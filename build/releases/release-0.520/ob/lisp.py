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
LISP_RLOC_PROBE_TTL = 64
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
  if 69 - 69: oO0o % OoooooooOO * iII111i
  if 58 - 58: oO0o / i11iIiiIii . OoOoOO00 % O0 / iIii1I11I1II1
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  I1io0 = self . rloc_name
  if ( cour ) : I1io0 = lisp_print_cour ( I1io0 )
  return ( 'rloc-name: {}' . format ( blue ( I1io0 , cour ) ) )
  if 91 - 91: i11iIiiIii . I1ii11iIi11i + I11i
  if 67 - 67: I1ii11iIi11i * I1Ii111 * I1IiiI / I11i - IiII + oO0o
 def print_record ( self , indent ) :
  o0oooOoOoOo = self . print_rloc_name ( )
  if ( o0oooOoOoOo != "" ) : o0oooOoOoOo = ", " + o0oooOoOoOo
  Iiii1II = ""
  if ( self . geo ) :
   Ooo0o0OoOO = ""
   if ( self . geo . geo_name ) : Ooo0o0OoOO = "'{}' " . format ( self . geo . geo_name )
   Iiii1II = ", geo: {}{}" . format ( Ooo0o0OoOO , self . geo . print_geo ( ) )
   if 15 - 15: o0oOOo0O0Ooo / IiII / ooOoO0o * OoOoOO00
  i11IiIii11i = ""
  if ( self . elp ) :
   Ooo0o0OoOO = ""
   if ( self . elp . elp_name ) : Ooo0o0OoOO = "'{}' " . format ( self . elp . elp_name )
   i11IiIii11i = ", elp: {}{}" . format ( Ooo0o0OoOO , self . elp . print_elp ( True ) )
   if 59 - 59: i1IIi + IiII . OOooOOo + I11i
  Oo00 = ""
  if ( self . rle ) :
   Ooo0o0OoOO = ""
   if ( self . rle . rle_name ) : Ooo0o0OoOO = "'{}' " . format ( self . rle . rle_name )
   Oo00 = ", rle: {}{}" . format ( Ooo0o0OoOO , self . rle . print_rle ( False ,
 True ) )
   if 91 - 91: iII111i % i11iIiiIii / I1Ii111
  i1ooo00Oo = ""
  if ( self . json ) :
   Ooo0o0OoOO = ""
   if ( self . json . json_name ) :
    Ooo0o0OoOO = "'{}' " . format ( self . json . json_name )
    if 53 - 53: OOooOOo / I1IiiI / oO0o * OOooOOo / i1IIi - I1Ii111
   i1ooo00Oo = ", json: {}" . format ( self . json . print_json ( False ) )
   if 71 - 71: O0 + Oo0Ooo % oO0o - o0oOOo0O0Ooo
   if 82 - 82: iIii1I11I1II1
  O00oO0 = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   O00oO0 = ", " + self . keys [ 1 ] . print_keys ( )
   if 26 - 26: I1IiiI . O0 % iII111i
   if 100 - 100: I1IiiI
  oOOo0ooO0 = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( oOOo0ooO0 . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , o0oooOoOoOo , Iiii1II ,
 i11IiIii11i , Oo00 , i1ooo00Oo , O00oO0 ) )
  if 55 - 55: i1IIi % IiII
  if 44 - 44: oO0o - iIii1I11I1II1 / ooOoO0o - iIii1I11I1II1 % i1IIi + ooOoO0o
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 74 - 74: I11i . OoOoOO00 + OoOoOO00
  if 87 - 87: IiII + o0oOOo0O0Ooo . i1IIi % I1Ii111
  if 44 - 44: Oo0Ooo - OOooOOo . Ii1I * OoooooooOO
 def store_rloc_entry ( self , rloc_entry ) :
  oOO = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 52 - 52: OOooOOo . oO0o / Oo0Ooo . OoooooooOO % I1ii11iIi11i
  self . rloc . copy_address ( oOO )
  if 65 - 65: ooOoO0o % II111iiii . iII111i - iIii1I11I1II1 - I1IiiI
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 63 - 63: I1IiiI . OoOoOO00 - II111iiii
   if 55 - 55: ooOoO0o - o0oOOo0O0Ooo
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   Ooo0o0OoOO = rloc_entry . geo_name
   if ( Ooo0o0OoOO and lisp_geo_list . has_key ( Ooo0o0OoOO ) ) :
    self . geo = lisp_geo_list [ Ooo0o0OoOO ]
    if 32 - 32: I1Ii111 * Ii1I / I1Ii111 . OoOoOO00 + I1ii11iIi11i - ooOoO0o
    if 14 - 14: IiII * O0 + O0 - ooOoO0o . i11iIiiIii - IiII
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   Ooo0o0OoOO = rloc_entry . elp_name
   if ( Ooo0o0OoOO and lisp_elp_list . has_key ( Ooo0o0OoOO ) ) :
    self . elp = lisp_elp_list [ Ooo0o0OoOO ]
    if 37 - 37: I11i
    if 19 - 19: OoooooooOO % I1Ii111
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   Ooo0o0OoOO = rloc_entry . rle_name
   if ( Ooo0o0OoOO and lisp_rle_list . has_key ( Ooo0o0OoOO ) ) :
    self . rle = lisp_rle_list [ Ooo0o0OoOO ]
    if 57 - 57: OoOoOO00 + i1IIi . iIii1I11I1II1 . iIii1I11I1II1 / iIii1I11I1II1 % oO0o
    if 7 - 7: i11iIiiIii * I1ii11iIi11i / OoO0O00 * oO0o
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   Ooo0o0OoOO = rloc_entry . json_name
   if ( Ooo0o0OoOO and lisp_json_list . has_key ( Ooo0o0OoOO ) ) :
    self . json = lisp_json_list [ Ooo0o0OoOO ]
    if 35 - 35: IiII . i1IIi + I1ii11iIi11i . IiII + ooOoO0o . oO0o
    if 2 - 2: II111iiii
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 18 - 18: iIii1I11I1II1 % I1ii11iIi11i % Oo0Ooo
  if 47 - 47: ooOoO0o - I1IiiI % OOooOOo * Ii1I % I1IiiI
 def encode_json ( self , json_string ) :
  iI1IIiI111iII = LISP_LCAF_JSON_TYPE
  OoOoO00OoOOo = socket . htons ( LISP_AFI_LCAF )
  OO0OoO = self . rloc . addr_length ( ) + 2
  if 91 - 91: I1IiiI + i1IIi * O0 / OoO0O00 + o0oOOo0O0Ooo
  oOOO0O000Oo = socket . htons ( len ( json_string ) + OO0OoO )
  if 54 - 54: IiII + I11i / OoooooooOO / I11i / i1IIi
  iiiii1I = socket . htons ( len ( json_string ) )
  IiiiIi1iiii11 = struct . pack ( "HBBBBHH" , OoOoO00OoOOo , 0 , 0 , iI1IIiI111iII , 0 , oOOO0O000Oo ,
 iiiii1I )
  IiiiIi1iiii11 += json_string
  if 94 - 94: OoO0O00 - OoO0O00 . OoOoOO00
  if 44 - 44: I1IiiI / IiII . iII111i
  if 48 - 48: o0oOOo0O0Ooo . i1IIi - OOooOOo % Ii1I
  if 62 - 62: II111iiii % i1IIi
  if ( lisp_is_json_telemetry ( json_string ) ) :
   IiiiIi1iiii11 += struct . pack ( "H" , socket . htons ( self . rloc . afi ) )
   IiiiIi1iiii11 += self . rloc . pack_address ( )
  else :
   IiiiIi1iiii11 += struct . pack ( "H" , 0 )
   if 98 - 98: I1IiiI - Oo0Ooo - Ii1I
  return ( IiiiIi1iiii11 )
  if 80 - 80: ooOoO0o . i11iIiiIii
  if 18 - 18: I11i + i11iIiiIii
 def encode_lcaf ( self ) :
  OoOoO00OoOOo = socket . htons ( LISP_AFI_LCAF )
  i11I1I1Ii1iI1 = ""
  if ( self . geo ) :
   i11I1I1Ii1iI1 = self . geo . encode_geo ( )
   if 67 - 67: I1ii11iIi11i . OoO0O00 . ooOoO0o + i11iIiiIii . OOooOOo . i11iIiiIii
   if 100 - 100: OoooooooOO
  o0oOo0 = ""
  if ( self . elp ) :
   oO00 = ""
   for IiiIIi1IiI in self . elp . elp_nodes :
    O0ooo0 = socket . htons ( IiiIIi1IiI . address . afi )
    II111Ii1I1I = 0
    if ( IiiIIi1IiI . eid ) : II111Ii1I1I |= 0x4
    if ( IiiIIi1IiI . probe ) : II111Ii1I1I |= 0x2
    if ( IiiIIi1IiI . strict ) : II111Ii1I1I |= 0x1
    II111Ii1I1I = socket . htons ( II111Ii1I1I )
    oO00 += struct . pack ( "HH" , II111Ii1I1I , O0ooo0 )
    oO00 += IiiIIi1IiI . address . pack_address ( )
    if 27 - 27: Oo0Ooo * OOooOOo / O0 . Oo0Ooo
    if 23 - 23: Oo0Ooo % II111iiii
   o000OOooO0O = socket . htons ( len ( oO00 ) )
   o0oOo0 = struct . pack ( "HBBBBH" , OoOoO00OoOOo , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , o000OOooO0O )
   o0oOo0 += oO00
   if 36 - 36: OoOoOO00 / Ii1I . OoooooooOO . OoO0O00 * OoooooooOO
   if 45 - 45: iIii1I11I1II1 * I1IiiI . OoOoOO00
  O00oo0ooo0O = ""
  if ( self . rle ) :
   iiIi1i1iI = ""
   for i1iiiIIi11 in self . rle . rle_nodes :
    O0ooo0 = socket . htons ( i1iiiIIi11 . address . afi )
    iiIi1i1iI += struct . pack ( "HBBH" , 0 , 0 , i1iiiIIi11 . level , O0ooo0 )
    iiIi1i1iI += i1iiiIIi11 . address . pack_address ( )
    if ( i1iiiIIi11 . rloc_name ) :
     iiIi1i1iI += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     iiIi1i1iI += i1iiiIIi11 . rloc_name + "\0"
     if 71 - 71: iII111i / ooOoO0o * i1IIi
     if 79 - 79: I1ii11iIi11i - I1IiiI * I1Ii111 + OOooOOo - O0
     if 37 - 37: Oo0Ooo + iIii1I11I1II1 * I11i / II111iiii . OoOoOO00
   oOo0ooo = socket . htons ( len ( iiIi1i1iI ) )
   O00oo0ooo0O = struct . pack ( "HBBBBH" , OoOoO00OoOOo , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , oOo0ooo )
   O00oo0ooo0O += iiIi1i1iI
   if 26 - 26: I11i - i1IIi - Oo0Ooo * O0 * OOooOOo . OoooooooOO
   if 99 - 99: oO0o . OoO0O00 / OOooOOo
  Ii1111i = ""
  if ( self . json ) :
   Ii1111i = self . encode_json ( self . json . json_string )
   if 17 - 17: OoO0O00
   if 69 - 69: O0
  ooOoOoooO = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   ooOoOoooO = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 78 - 78: i11iIiiIii
   if 14 - 14: i11iIiiIii + I1IiiI - oO0o - I11i
  iii1i = ""
  if ( self . rloc_name ) :
   iii1i += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   iii1i += self . rloc_name + "\0"
   if 78 - 78: i1IIi % oO0o + IiII
   if 75 - 75: O0 + I1ii11iIi11i
  oo0oO0 = len ( i11I1I1Ii1iI1 ) + len ( o0oOo0 ) + len ( O00oo0ooo0O ) + len ( ooOoOoooO ) + 2 + len ( Ii1111i ) + self . rloc . addr_length ( ) + len ( iii1i )
  if 21 - 21: OOooOOo % O0 / I11i
  oo0oO0 = socket . htons ( oo0oO0 )
  IiiiIiii = struct . pack ( "HBBBBHH" , OoOoO00OoOOo , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , oo0oO0 , socket . htons ( self . rloc . afi ) )
  IiiiIiii += self . rloc . pack_address ( )
  return ( IiiiIiii + iii1i + i11I1I1Ii1iI1 + o0oOo0 + O00oo0ooo0O + ooOoOoooO + Ii1111i )
  if 76 - 76: i1IIi
  if 38 - 38: I1IiiI
 def encode ( self ) :
  II111Ii1I1I = 0
  if ( self . local_bit ) : II111Ii1I1I |= 0x0004
  if ( self . probe_bit ) : II111Ii1I1I |= 0x0002
  if ( self . reach_bit ) : II111Ii1I1I |= 0x0001
  if 15 - 15: o0oOOo0O0Ooo
  IiiiIi1iiii11 = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( II111Ii1I1I ) ,
 socket . htons ( self . rloc . afi ) )
  if 55 - 55: i11iIiiIii / OoooooooOO - I11i
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 89 - 89: I11i - i1IIi - i1IIi * OOooOOo - O0
   IiiiIi1iiii11 = IiiiIi1iiii11 [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   IiiiIi1iiii11 += self . rloc . pack_address ( )
   if 94 - 94: Oo0Ooo / I11i . I1ii11iIi11i
  return ( IiiiIi1iiii11 )
  if 31 - 31: i11iIiiIii + iIii1I11I1II1 . II111iiii
  if 72 - 72: I1Ii111 * OoO0O00 + Oo0Ooo / Ii1I % OOooOOo
 def decode_lcaf ( self , packet , nonce ) :
  i1I1iii1I11II = "HBBBBH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 84 - 84: OoOoOO00 / o0oOOo0O0Ooo
  O0ooo0 , Ii1IiIIIi1i , II111Ii1I1I , iI1IIiI111iII , o00oo0oOo0o0 , oOOO0O000Oo = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 9 - 9: Ii1I
  if 76 - 76: I1IiiI % Oo0Ooo / iIii1I11I1II1 - Oo0Ooo
  oOOO0O000Oo = socket . ntohs ( oOOO0O000Oo )
  packet = packet [ Iiiii : : ]
  if ( oOOO0O000Oo > len ( packet ) ) : return ( None )
  if 34 - 34: OoOoOO00 - i1IIi + OOooOOo + Ii1I . o0oOOo0O0Ooo
  if 42 - 42: OoO0O00
  if 59 - 59: OoO0O00 . I1Ii111 % OoO0O00
  if 22 - 22: Oo0Ooo
  if ( iI1IIiI111iII == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( oOOO0O000Oo > 0 ) :
    i1I1iii1I11II = "H"
    Iiiii = struct . calcsize ( i1I1iii1I11II )
    if ( oOOO0O000Oo < Iiiii ) : return ( None )
    if 21 - 21: o0oOOo0O0Ooo
    iIi1Iii1 = len ( packet )
    O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
    O0ooo0 = socket . ntohs ( O0ooo0 )
    if 86 - 86: ooOoO0o / iIii1I11I1II1 . OOooOOo
    if ( O0ooo0 == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ Iiiii : : ]
     self . rloc_name = None
     if ( O0ooo0 == LISP_AFI_NAME ) :
      packet , I1io0 = lisp_decode_dist_name ( packet )
      self . rloc_name = I1io0
     else :
      self . rloc . afi = O0ooo0
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 93 - 93: Oo0Ooo / II111iiii . Oo0Ooo + i1IIi + i1IIi
      if 30 - 30: OoOoOO00 . OOooOOo % OOooOOo / II111iiii + i1IIi
      if 61 - 61: i1IIi % II111iiii * II111iiii . o0oOOo0O0Ooo / I1ii11iIi11i - I1Ii111
    oOOO0O000Oo -= iIi1Iii1 - len ( packet )
    if 93 - 93: Ii1I - i1IIi
    if 3 - 3: oO0o + OoO0O00 - iII111i / Ii1I
  elif ( iI1IIiI111iII == LISP_LCAF_GEO_COORD_TYPE ) :
   if 58 - 58: Ii1I * I11i
   if 95 - 95: oO0o
   if 49 - 49: I1IiiI
   if 23 - 23: I1Ii111
   IIiIiiIIiI = lisp_geo ( "" )
   packet = IIiIiiIIiI . decode_geo ( packet , oOOO0O000Oo , o00oo0oOo0o0 )
   if ( packet == None ) : return ( None )
   self . geo = IIiIiiIIiI
   if 45 - 45: OoO0O00 * iII111i . OoO0O00 + oO0o
  elif ( iI1IIiI111iII == LISP_LCAF_JSON_TYPE ) :
   if 80 - 80: iII111i - II111iiii + oO0o - OoooooooOO . IiII
   if 11 - 11: II111iiii
   if 86 - 86: Oo0Ooo * I1ii11iIi11i % iIii1I11I1II1 - ooOoO0o * OoO0O00
   if 50 - 50: ooOoO0o % OoO0O00 % ooOoO0o / i1IIi
   i1I1iii1I11II = "H"
   Iiiii = struct . calcsize ( i1I1iii1I11II )
   if ( oOOO0O000Oo < Iiiii ) : return ( None )
   if 10 - 10: Oo0Ooo * iII111i + Ii1I % iIii1I11I1II1
   iiiii1I = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
   iiiii1I = socket . ntohs ( iiiii1I )
   if ( oOOO0O000Oo < Iiiii + iiiii1I ) : return ( None )
   if 60 - 60: I1Ii111 / O0 - i1IIi * IiII
   packet = packet [ Iiiii : : ]
   self . json = lisp_json ( "" , packet [ 0 : iiiii1I ] )
   packet = packet [ iiiii1I : : ]
   if 72 - 72: O0 * I1Ii111 - iIii1I11I1II1 % i1IIi
   if 83 - 83: OoOoOO00 + OOooOOo / OoooooooOO
   if 39 - 39: OoO0O00 % iII111i . oO0o . II111iiii - i11iIiiIii
   if 85 - 85: O0 - OoOoOO00
   O0ooo0 = socket . ntohs ( struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ] )
   packet = packet [ 2 : : ]
   if 17 - 17: o0oOOo0O0Ooo / i1IIi / OOooOOo
   if ( O0ooo0 != 0 and lisp_is_json_telemetry ( self . json . json_string ) ) :
    self . rloc . afi = O0ooo0
    packet = self . rloc . unpack_address ( packet )
    if 91 - 91: I1ii11iIi11i / Ii1I - OoOoOO00 . I11i / oO0o
    if 16 - 16: IiII % iII111i . oO0o . I1IiiI % O0 * I11i
  elif ( iI1IIiI111iII == LISP_LCAF_ELP_TYPE ) :
   if 99 - 99: OoOoOO00 / OoooooooOO + iII111i * I11i * i11iIiiIii + OOooOOo
   if 40 - 40: II111iiii / I11i % I1IiiI - O0
   if 39 - 39: i11iIiiIii - OoOoOO00 % OOooOOo + ooOoO0o + i11iIiiIii
   if 59 - 59: IiII / OoOoOO00 - I1Ii111 - ooOoO0o . oO0o
   OO0o00O = lisp_elp ( None )
   OO0o00O . elp_nodes = [ ]
   while ( oOOO0O000Oo > 0 ) :
    II111Ii1I1I , O0ooo0 = struct . unpack ( "HH" , packet [ : 4 ] )
    if 51 - 51: i1IIi
    O0ooo0 = socket . ntohs ( O0ooo0 )
    if ( O0ooo0 == LISP_AFI_LCAF ) : return ( None )
    if 97 - 97: OoOoOO00 * iIii1I11I1II1 + OoOoOO00
    IiiIIi1IiI = lisp_elp_node ( )
    OO0o00O . elp_nodes . append ( IiiIIi1IiI )
    if 23 - 23: I1Ii111 . I1IiiI
    II111Ii1I1I = socket . ntohs ( II111Ii1I1I )
    IiiIIi1IiI . eid = ( II111Ii1I1I & 0x4 )
    IiiIIi1IiI . probe = ( II111Ii1I1I & 0x2 )
    IiiIIi1IiI . strict = ( II111Ii1I1I & 0x1 )
    IiiIIi1IiI . address . afi = O0ooo0
    IiiIIi1IiI . address . mask_len = IiiIIi1IiI . address . host_mask_len ( )
    packet = IiiIIi1IiI . address . unpack_address ( packet [ 4 : : ] )
    oOOO0O000Oo -= IiiIIi1IiI . address . addr_length ( ) + 4
    if 66 - 66: I1Ii111 % oO0o . iII111i * i1IIi
   OO0o00O . select_elp_node ( )
   self . elp = OO0o00O
   if 81 - 81: OoooooooOO * I1IiiI / I1Ii111
  elif ( iI1IIiI111iII == LISP_LCAF_RLE_TYPE ) :
   if 10 - 10: I1IiiI - II111iiii / IiII * II111iiii
   if 67 - 67: II111iiii . Ii1I % oO0o . Oo0Ooo + IiII
   if 10 - 10: OOooOOo - OoO0O00 * oO0o / iIii1I11I1II1 - OoOoOO00
   if 20 - 20: IiII % I1IiiI + iIii1I11I1II1 % iII111i
   iI1Ii11 = lisp_rle ( None )
   iI1Ii11 . rle_nodes = [ ]
   while ( oOOO0O000Oo > 0 ) :
    O0O , OO0Oo00oo , II1ioOO0Oo , O0ooo0 = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 17 - 17: Oo0Ooo / O0 - O0
    O0ooo0 = socket . ntohs ( O0ooo0 )
    if ( O0ooo0 == LISP_AFI_LCAF ) : return ( None )
    if 83 - 83: OOooOOo / Ii1I * I1IiiI % oO0o / iIii1I11I1II1
    i1iiiIIi11 = lisp_rle_node ( )
    iI1Ii11 . rle_nodes . append ( i1iiiIIi11 )
    if 1 - 1: I11i / OoooooooOO / iII111i
    i1iiiIIi11 . level = II1ioOO0Oo
    i1iiiIIi11 . address . afi = O0ooo0
    i1iiiIIi11 . address . mask_len = i1iiiIIi11 . address . host_mask_len ( )
    packet = i1iiiIIi11 . address . unpack_address ( packet [ 6 : : ] )
    if 68 - 68: i1IIi / Oo0Ooo / I11i * Oo0Ooo
    oOOO0O000Oo -= i1iiiIIi11 . address . addr_length ( ) + 6
    if ( oOOO0O000Oo >= 2 ) :
     O0ooo0 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( O0ooo0 ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , i1iiiIIi11 . rloc_name = lisp_decode_dist_name ( packet )
      if 91 - 91: OoO0O00 . iII111i
      if ( packet == None ) : return ( None )
      oOOO0O000Oo -= len ( i1iiiIIi11 . rloc_name ) + 1 + 2
      if 82 - 82: I1ii11iIi11i / Oo0Ooo
      if 63 - 63: I1IiiI
      if 3 - 3: iII111i + I1ii11iIi11i
   self . rle = iI1Ii11
   self . rle . build_forwarding_list ( )
   if 35 - 35: oO0o * iII111i * oO0o * I1Ii111 * IiII * i1IIi
  elif ( iI1IIiI111iII == LISP_LCAF_SECURITY_TYPE ) :
   if 43 - 43: OoO0O00 * I1IiiI / IiII . i11iIiiIii + iII111i + o0oOOo0O0Ooo
   if 1 - 1: I1IiiI % o0oOOo0O0Ooo . I1Ii111 + I11i * oO0o
   if 41 - 41: OoO0O00 * oO0o - II111iiii
   if 2 - 2: IiII + IiII - OoO0O00 * iII111i . oO0o
   if 91 - 91: ooOoO0o
   OoO = packet
   iI1IiI1 = lisp_keys ( 1 )
   packet = iI1IiI1 . decode_lcaf ( OoO , oOOO0O000Oo )
   if ( packet == None ) : return ( None )
   if 22 - 22: ooOoO0o % OoO0O00 * OoOoOO00 + Oo0Ooo
   if 44 - 44: O0 - I11i
   if 43 - 43: O0
   if 50 - 50: I11i - OoooooooOO
   iI111I = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( iI1IiI1 . cipher_suite in iI111I ) :
    if ( iI1IiI1 . cipher_suite == LISP_CS_25519_CBC ) :
     Oo000O000 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 29 - 29: oO0o * oO0o
    if ( iI1IiI1 . cipher_suite == LISP_CS_25519_CHACHA ) :
     Oo000O000 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 44 - 44: ooOoO0o . I1IiiI * oO0o * Ii1I
   else :
    Oo000O000 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
   packet = Oo000O000 . decode_lcaf ( OoO , oOOO0O000Oo )
   if ( packet == None ) : return ( None )
   if 8 - 8: OoooooooOO - OoO0O00 / i11iIiiIii / O0 . IiII
   if ( len ( packet ) < 2 ) : return ( None )
   O0ooo0 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( O0ooo0 )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 86 - 86: ooOoO0o * OoooooooOO + iII111i + o0oOOo0O0Ooo
   if 79 - 79: i1IIi % I1ii11iIi11i - OoO0O00 % I1ii11iIi11i
   if 6 - 6: Oo0Ooo / iII111i . i11iIiiIii
   if 8 - 8: I1ii11iIi11i + O0 - oO0o % II111iiii . I1Ii111
   if 86 - 86: IiII
   if 71 - 71: Ii1I - i1IIi . I1IiiI
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
   OoOi1IiiIiIII11 = self . rloc_name
   if ( OoOi1IiiIiIII11 ) : OoOi1IiiIiIII11 = blue ( self . rloc_name , False )
   if 39 - 39: I1IiiI + oO0o . I1Ii111 * iII111i - OoOoOO00 / Ii1I
   if 38 - 38: i1IIi / II111iiii
   if 51 - 51: iII111i - OoOoOO00 + II111iiii
   if 83 - 83: Ii1I
   if 25 - 25: OoOoOO00 + IiII . i11iIiiIii
   if 87 - 87: I1IiiI + OoooooooOO + O0
   oO0OooO0o0 = self . keys [ 1 ] if self . keys else None
   if ( oO0OooO0o0 == None ) :
    if ( Oo000O000 . remote_public_key == None ) :
     Iii11I111Ii11 = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( Iii11I111Ii11 , OoOi1IiiIiIII11 ) )
     Oo000O000 = None
    else :
     Iii11I111Ii11 = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( Iii11I111Ii11 , OoOi1IiiIiIII11 ) )
     Oo000O000 . compute_shared_key ( "encap" )
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
   if ( oO0OooO0o0 ) :
    if ( Oo000O000 . remote_public_key == None ) :
     Oo000O000 = None
     OOO0o0oo = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( OOO0o0oo , OoOi1IiiIiIII11 ) )
    elif ( oO0OooO0o0 . compare_keys ( Oo000O000 ) ) :
     Oo000O000 = oO0OooO0o0
     lprint ( "    Maintain stored encap-keys for {}" . format ( OoOi1IiiIiIII11 ) )
     if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
    else :
     if ( oO0OooO0o0 . remote_public_key == None ) :
      Iii11I111Ii11 = "New encap-keying for existing state"
     else :
      Iii11I111Ii11 = "Remote encap-rekeying"
      if 69 - 69: I1Ii111 + O0 . IiII . o0oOOo0O0Ooo
     lprint ( "    {} for {}" . format ( bold ( Iii11I111Ii11 , False ) ,
 OoOi1IiiIiIII11 ) )
     oO0OooO0o0 . remote_public_key = Oo000O000 . remote_public_key
     oO0OooO0o0 . compute_shared_key ( "encap" )
     Oo000O000 = oO0OooO0o0
     if 38 - 38: IiII / i1IIi
     if 60 - 60: OoOoOO00
   self . keys = [ None , Oo000O000 , None , None ]
   if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
  else :
   if 61 - 61: IiII . IiII
   if 17 - 17: OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
   if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
   if 95 - 95: iII111i / ooOoO0o + I1Ii111
   packet = packet [ oOOO0O000Oo : : ]
   if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
  return ( packet )
  if 81 - 81: I1ii11iIi11i
  if 31 - 31: O0 % ooOoO0o / I1IiiI * iII111i % iIii1I11I1II1 * OoOoOO00
 def decode ( self , packet , nonce ) :
  i1I1iii1I11II = "BBBBHH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 76 - 76: I1Ii111 - O0
  self . priority , self . weight , self . mpriority , self . mweight , II111Ii1I1I , O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
  if 7 - 7: II111iiii + I11i
  II111Ii1I1I = socket . ntohs ( II111Ii1I1I )
  O0ooo0 = socket . ntohs ( O0ooo0 )
  self . local_bit = True if ( II111Ii1I1I & 0x0004 ) else False
  self . probe_bit = True if ( II111Ii1I1I & 0x0002 ) else False
  self . reach_bit = True if ( II111Ii1I1I & 0x0001 ) else False
  if 99 - 99: iIii1I11I1II1 * oO0o
  if ( O0ooo0 == LISP_AFI_LCAF ) :
   packet = packet [ Iiiii - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce )
  else :
   self . rloc . afi = O0ooo0
   packet = packet [ Iiiii : : ]
   packet = self . rloc . unpack_address ( packet )
   if 37 - 37: ooOoO0o * iII111i * I11i
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 11 - 11: I1IiiI
  if 48 - 48: O0 . I11i
 def end_of_rlocs ( self , packet , rloc_count ) :
  for IiIIi1IiiIiI in range ( rloc_count ) :
   packet = self . decode ( packet , None )
   if ( packet == None ) : return ( None )
   if 9 - 9: oO0o / Oo0Ooo
  return ( packet )
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
  if 30 - 30: i11iIiiIii % OOooOOo
  if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
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
  if 67 - 67: OoooooooOO * I11i * Ii1I * iIii1I11I1II1
  if 22 - 22: OoO0O00 / o0oOOo0O0Ooo
  if 35 - 35: I1Ii111 / I1Ii111 + o0oOOo0O0Ooo - oO0o
  if 40 - 40: OoOoOO00 - II111iiii
  if 29 - 29: I1IiiI - O0
  if 36 - 36: I1IiiI * I1IiiI
class lisp_map_referral ( ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 79 - 79: I1Ii111 - I11i
  if 49 - 49: II111iiii + O0 * ooOoO0o - Oo0Ooo
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # OoO0O00 * iIii1I11I1II1 / iIii1I11I1II1 % OoOoOO00 - i1IIi / oO0o
 lisp_hex_string ( self . nonce ) ) )
  if 36 - 36: Ii1I % OoO0O00
  if 89 - 89: I1ii11iIi11i + I11i / i11iIiiIii * ooOoO0o
 def encode ( self ) :
  iII = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  IiiiIi1iiii11 = struct . pack ( "I" , socket . htonl ( iII ) )
  IiiiIi1iiii11 += struct . pack ( "Q" , self . nonce )
  return ( IiiiIi1iiii11 )
  if 36 - 36: iII111i / OoooooooOO + Ii1I . I1IiiI
  if 48 - 48: II111iiii / II111iiii . I11i - I1IiiI
 def decode ( self , packet ) :
  i1I1iii1I11II = "I"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 67 - 67: I1ii11iIi11i + I1ii11iIi11i
  iII = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  iII = socket . ntohl ( iII [ 0 ] )
  self . record_count = iII & 0xff
  packet = packet [ Iiiii : : ]
  if 52 - 52: i11iIiiIii - O0
  i1I1iii1I11II = "Q"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 64 - 64: i11iIiiIii . I1Ii111 / O0 - IiII
  self . nonce = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  return ( packet )
  if 88 - 88: Ii1I / OoO0O00 - I11i
  if 11 - 11: OoO0O00 / i1IIi . OoooooooOO
  if 40 - 40: IiII + iII111i * I11i + OoOoOO00
  if 5 - 5: I1Ii111 / IiII
  if 30 - 30: OOooOOo . iII111i % OoO0O00 + oO0o
  if 69 - 69: i11iIiiIii + IiII * ooOoO0o * iII111i % oO0o
  if 66 - 66: OOooOOo * IiII + O0 - OoooooooOO
  if 19 - 19: Oo0Ooo * OoOoOO00
class lisp_ddt_entry ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 52 - 52: OoO0O00 + oO0o
  if 84 - 84: O0 % I1ii11iIi11i % iIii1I11I1II1 - OoOoOO00 - Oo0Ooo
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 7 - 7: II111iiii % oO0o % i1IIi . iIii1I11I1II1
  if 92 - 92: Ii1I / o0oOOo0O0Ooo % OOooOOo - OoOoOO00
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 44 - 44: I1IiiI + OoOoOO00 * Oo0Ooo
  if 31 - 31: I11i - I1IiiI - OoO0O00 * OoOoOO00
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  iI111i = self . delegation_set [ 0 ]
  return ( iI111i . print_node_type ( ) )
  if 62 - 62: I1Ii111 + II111iiii % i1IIi . OoOoOO00 - OOooOOo * iIii1I11I1II1
  if 95 - 95: IiII + oO0o % OOooOOo / iII111i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 66 - 66: OoooooooOO + OoOoOO00 * OoO0O00 - I1IiiI . oO0o
  if 74 - 74: o0oOOo0O0Ooo . Oo0Ooo * i1IIi
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   oO0Oo0000OO0 = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( oO0Oo0000OO0 == None ) :
    oO0Oo0000OO0 = lisp_ddt_entry ( )
    oO0Oo0000OO0 . eid . copy_address ( self . group )
    oO0Oo0000OO0 . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , oO0Oo0000OO0 )
    if 37 - 37: OoO0O00 - IiII . I1Ii111 - oO0o
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( oO0Oo0000OO0 . group )
   oO0Oo0000OO0 . add_source_entry ( self )
   if 12 - 12: i1IIi / I11i
   if 79 - 79: I1IiiI + II111iiii + ooOoO0o % OoO0O00
   if 72 - 72: OOooOOo * OoOoOO00
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 81 - 81: II111iiii / I11i - ooOoO0o - i1IIi - I1Ii111
  if 38 - 38: OoOoOO00 . iII111i / O0 . OOooOOo + OOooOOo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 4 - 4: I11i
  if 95 - 95: II111iiii % o0oOOo0O0Ooo . I11i
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 18 - 18: O0 / OoooooooOO * Oo0Ooo % iII111i
  if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
  if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
class lisp_ddt_node ( ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 46 - 46: o0oOOo0O0Ooo
  if 28 - 28: i1IIi
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
  if 62 - 62: I1Ii111 * I11i / I11i
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 42 - 42: ooOoO0o * ooOoO0o / Ii1I / OOooOOo * OOooOOo
  if 92 - 92: Oo0Ooo / iII111i - OoooooooOO - o0oOOo0O0Ooo % ooOoO0o
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 35 - 35: i1IIi % iII111i % I11i * iIii1I11I1II1 % Ii1I - Oo0Ooo
  if 94 - 94: iII111i
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 68 - 68: OoooooooOO % OOooOOo / OoooooooOO / I1Ii111 + Ii1I - o0oOOo0O0Ooo
  if 81 - 81: I1IiiI
  if 62 - 62: Ii1I * OoOoOO00
  if 27 - 27: Oo0Ooo + Oo0Ooo / II111iiii % I1Ii111
  if 11 - 11: Ii1I
  if 54 - 54: I1IiiI * I1Ii111 / ooOoO0o / iIii1I11I1II1 % iII111i / oO0o
  if 11 - 11: ooOoO0o + I1IiiI + Ii1I . II111iiii
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
  if 50 - 50: Oo0Ooo
  if 14 - 14: O0
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # i1IIi / O0 / OoooooooOO . OoooooooOO
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 21 - 21: o0oOOo0O0Ooo / Oo0Ooo * II111iiii
  if 91 - 91: I1ii11iIi11i
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 100 - 100: iIii1I11I1II1 + Ii1I - I11i + Oo0Ooo
  if 49 - 49: O0 % ooOoO0o + i11iIiiIii + o0oOOo0O0Ooo
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( lisp_ddt_map_requestQ . has_key ( str ( self . nonce ) ) ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 85 - 85: II111iiii . iII111i - i1IIi
   if 23 - 23: iII111i . Ii1I - OoO0O00 / I1ii11iIi11i / O0
   if 4 - 4: i1IIi % Oo0Ooo % Ii1I * ooOoO0o - I11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 76 - 76: iIii1I11I1II1 / ooOoO0o % I1ii11iIi11i % OOooOOo
  if 13 - 13: IiII
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
  if 25 - 25: I1IiiI
  if 52 - 52: I1ii11iIi11i % i1IIi . IiII % OoOoOO00
  if 50 - 50: OOooOOo * I1IiiI / o0oOOo0O0Ooo
  if 91 - 91: iIii1I11I1II1 / OOooOOo * O0 . o0oOOo0O0Ooo + oO0o / I1ii11iIi11i
  if 33 - 33: II111iiii + Ii1I
  if 46 - 46: IiII + O0 + i1IIi + ooOoO0o / iII111i
  if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 59 - 59: I11i % Ii1I / OoOoOO00
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
if 80 - 80: Oo0Ooo
if 58 - 58: I1Ii111 + OOooOOo
if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
if 41 - 41: Ii1I . OoO0O00 + I1ii11iIi11i + OoOoOO00
if 76 - 76: iII111i - iIii1I11I1II1
if 23 - 23: I11i / OoO0O00 % OOooOOo
if 9 - 9: ooOoO0o % I1ii11iIi11i . OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
if 21 - 21: Ii1I % O0
if 15 - 15: II111iiii * Ii1I + IiII % iII111i
if 96 - 96: II111iiii * I1Ii111 / Oo0Ooo
if 35 - 35: I1IiiI
if 54 - 54: I1ii11iIi11i % o0oOOo0O0Ooo . i1IIi
if 72 - 72: Ii1I
if 87 - 87: iII111i - I1IiiI
if 54 - 54: iIii1I11I1II1 + oO0o * o0oOOo0O0Ooo % OoooooooOO . Oo0Ooo
if 32 - 32: iII111i
if 33 - 33: ooOoO0o + Oo0Ooo * OoOoOO00 % ooOoO0o * oO0o - OoO0O00
if 40 - 40: I11i . OoooooooOO * O0 / I1Ii111 + O0
if 97 - 97: ooOoO0o - ooOoO0o * OOooOOo % OoOoOO00 - OoOoOO00 - I1Ii111
if 52 - 52: O0 % iII111i
if 81 - 81: OoooooooOO % OoOoOO00 % Oo0Ooo - I1IiiI
if 43 - 43: o0oOOo0O0Ooo % o0oOOo0O0Ooo
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
if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
if 24 - 24: Ii1I + IiII + OoooooooOO / oO0o / I1IiiI + IiII
if 52 - 52: ooOoO0o
if 38 - 38: OoO0O00 + I1IiiI % IiII
if 87 - 87: oO0o * Ii1I - I1Ii111 / oO0o
if 65 - 65: OoOoOO00
if 87 - 87: I11i - i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
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
  if 84 - 84: OOooOOo * i1IIi . iIii1I11I1II1 * iII111i + I1Ii111 + II111iiii
  if 97 - 97: Ii1I - IiII
 def print_info ( self ) :
  if ( self . info_reply ) :
   OOoOo0oOO00OoOO0 = "Info-Reply"
   oOO = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # O0 % IiII + OoooooooOO . I1Ii111 + I11i
   # OoO0O00 % I11i . iIii1I11I1II1
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : oOO += "empty, "
   for OOO0O0OoOO in self . rtr_list :
    oOO += red ( OOO0O0OoOO . print_address_no_iid ( ) , False ) + ", "
    if 85 - 85: OOooOOo / I1Ii111 . i1IIi / OoOoOO00 + iIii1I11I1II1
   oOO = oOO [ 0 : - 2 ]
  else :
   OOoOo0oOO00OoOO0 = "Info-Request"
   o00oOOo = "<none>" if self . hostname == None else self . hostname
   oOO = ", hostname: {}" . format ( blue ( o00oOOo , False ) )
   if 24 - 24: II111iiii - I11i * IiII % Ii1I
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( OOoOo0oOO00OoOO0 , False ) ,
 lisp_hex_string ( self . nonce ) , oOO ) )
  if 69 - 69: OOooOOo + I1IiiI
  if 20 - 20: O0 % i11iIiiIii / II111iiii + IiII / OOooOOo
 def encode ( self ) :
  iII = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : iII |= ( 1 << 27 )
  if 6 - 6: iIii1I11I1II1 + II111iiii / II111iiii + o0oOOo0O0Ooo - iII111i / OoooooooOO
  if 25 - 25: O0 / i1IIi . iIii1I11I1II1
  if 10 - 10: I11i
  if 37 - 37: OoOoOO00 - ooOoO0o % II111iiii
  if 100 - 100: OoooooooOO
  IiiiIi1iiii11 = struct . pack ( "I" , socket . htonl ( iII ) )
  IiiiIi1iiii11 += struct . pack ( "Q" , self . nonce )
  IiiiIi1iiii11 += struct . pack ( "III" , 0 , 0 , 0 )
  if 90 - 90: I1Ii111 % O0 + OoooooooOO - IiII % iIii1I11I1II1
  if 24 - 24: OoOoOO00 . I1ii11iIi11i - iII111i * IiII % I1Ii111
  if 35 - 35: I1IiiI % I1Ii111 * oO0o * iIii1I11I1II1 * OOooOOo
  if 86 - 86: iIii1I11I1II1 + I1Ii111
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    IiiiIi1iiii11 += struct . pack ( "H" , 0 )
   else :
    IiiiIi1iiii11 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    IiiiIi1iiii11 += self . hostname + "\0"
    if 44 - 44: oO0o * iIii1I11I1II1
   return ( IiiiIi1iiii11 )
   if 28 - 28: OoO0O00 * I11i
   if 14 - 14: IiII % IiII - i1IIi % IiII . OoO0O00 . O0
   if 5 - 5: I1IiiI
   if 57 - 57: OOooOOo % OoO0O00 + IiII
   if 31 - 31: OoO0O00 % o0oOOo0O0Ooo * I1ii11iIi11i % O0 . II111iiii
  O0ooo0 = socket . htons ( LISP_AFI_LCAF )
  iI1IIiI111iII = LISP_LCAF_NAT_TYPE
  oOOO0O000Oo = socket . htons ( 16 )
  O0OOOOoOo00O = socket . htons ( self . ms_port )
  iII11i1I = socket . htons ( self . etr_port )
  IiiiIi1iiii11 += struct . pack ( "HHBBHHHH" , O0ooo0 , 0 , iI1IIiI111iII , 0 , oOOO0O000Oo ,
 O0OOOOoOo00O , iII11i1I , socket . htons ( self . global_etr_rloc . afi ) )
  IiiiIi1iiii11 += self . global_etr_rloc . pack_address ( )
  IiiiIi1iiii11 += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  IiiiIi1iiii11 += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : IiiiIi1iiii11 += struct . pack ( "H" , 0 )
  if 43 - 43: oO0o * Oo0Ooo - Ii1I * o0oOOo0O0Ooo
  if 17 - 17: i11iIiiIii - I11i * OoooooooOO
  if 1 - 1: OOooOOo - II111iiii * OoooooooOO . i1IIi
  if 42 - 42: o0oOOo0O0Ooo
  for OOO0O0OoOO in self . rtr_list :
   IiiiIi1iiii11 += struct . pack ( "H" , socket . htons ( OOO0O0OoOO . afi ) )
   IiiiIi1iiii11 += OOO0O0OoOO . pack_address ( )
   if 73 - 73: o0oOOo0O0Ooo . OoO0O00 . IiII + I1ii11iIi11i % ooOoO0o
  return ( IiiiIi1iiii11 )
  if 38 - 38: II111iiii + OoO0O00 - II111iiii * OoOoOO00
  if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo + I1IiiI * iIii1I11I1II1 + Oo0Ooo + i11iIiiIii
 def decode ( self , packet ) :
  OoO = packet
  i1I1iii1I11II = "I"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 67 - 67: i1IIi % I1Ii111 / i11iIiiIii . OoO0O00 - I1ii11iIi11i
  iII = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  iII = iII [ 0 ]
  packet = packet [ Iiiii : : ]
  if 15 - 15: o0oOOo0O0Ooo . OoO0O00 * i1IIi % I11i % OoOoOO00
  i1I1iii1I11II = "Q"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 25 - 25: OoOoOO00 . iIii1I11I1II1 - iII111i % II111iiii . OoOoOO00
  Iii11I = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 16 - 16: OOooOOo . Oo0Ooo . I1IiiI % O0 . I1ii11iIi11i + i11iIiiIii
  iII = socket . ntohl ( iII )
  self . nonce = Iii11I [ 0 ]
  self . info_reply = iII & 0x08000000
  self . hostname = None
  packet = packet [ Iiiii : : ]
  if 100 - 100: I1ii11iIi11i - i1IIi - OoO0O00 * o0oOOo0O0Ooo + OoOoOO00
  if 31 - 31: i1IIi
  if 21 - 21: o0oOOo0O0Ooo / O0 % O0 . OoooooooOO / I1IiiI
  if 94 - 94: ooOoO0o + OoO0O00 / ooOoO0o - ooOoO0o + Oo0Ooo + o0oOOo0O0Ooo
  if 50 - 50: oO0o . Oo0Ooo
  i1I1iii1I11II = "HH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 15 - 15: Ii1I
  if 64 - 64: OoooooooOO
  if 25 - 25: IiII
  if 29 - 29: OoOoOO00 % ooOoO0o * OoooooooOO
  if 8 - 8: i11iIiiIii - I1Ii111 / IiII
  I1I1I1 , II111iiI1Ii1 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if ( II111iiI1Ii1 != 0 ) : return ( None )
  if 17 - 17: i11iIiiIii * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO . OoOoOO00 - I1ii11iIi11i
  packet = packet [ Iiiii : : ]
  i1I1iii1I11II = "IBBH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 78 - 78: I1ii11iIi11i - OoooooooOO + O0
  oOoooOOO0o0 , i1o00Oo , iI11i , iiIiII1iIIi = struct . unpack ( i1I1iii1I11II ,
 packet [ : Iiiii ] )
  if 5 - 5: IiII * i11iIiiIii * OOooOOo . iII111i - Ii1I * oO0o
  if ( iiIiII1iIIi != 0 ) : return ( None )
  packet = packet [ Iiiii : : ]
  if 25 - 25: O0 . I1Ii111 / IiII % I1ii11iIi11i
  if 75 - 75: iII111i % I11i - Oo0Ooo * I1ii11iIi11i - IiII
  if 73 - 73: Ii1I - ooOoO0o / i1IIi
  if 8 - 8: Ii1I
  if ( self . info_reply == False ) :
   i1I1iii1I11II = "H"
   Iiiii = struct . calcsize ( i1I1iii1I11II )
   if ( len ( packet ) >= Iiiii ) :
    O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
    if ( socket . ntohs ( O0ooo0 ) == LISP_AFI_NAME ) :
     packet = packet [ Iiiii : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 52 - 52: IiII
     if 86 - 86: I1Ii111 / O0 + OoooooooOO % oO0o
   return ( OoO )
   if 45 - 45: I1IiiI . Oo0Ooo . I11i . Ii1I
   if 81 - 81: II111iiii + OoOoOO00 % i11iIiiIii / iII111i . I1Ii111 + II111iiii
   if 48 - 48: I1IiiI . I1ii11iIi11i * OoOoOO00 % i1IIi / I1Ii111 * II111iiii
   if 62 - 62: o0oOOo0O0Ooo * I1Ii111 . iIii1I11I1II1 / i1IIi
   if 75 - 75: OoooooooOO / ooOoO0o - iII111i . OoooooooOO . OoOoOO00 % i1IIi
  i1I1iii1I11II = "HHBBHHH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 7 - 7: OoOoOO00 . i1IIi * i11iIiiIii % i11iIiiIii
  O0ooo0 , O0O , iI1IIiI111iII , i1o00Oo , oOOO0O000Oo , O0OOOOoOo00O , iII11i1I = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 54 - 54: OoO0O00 / I1IiiI . Oo0Ooo
  if 39 - 39: OoO0O00 . ooOoO0o
  if ( socket . ntohs ( O0ooo0 ) != LISP_AFI_LCAF ) : return ( None )
  if 41 - 41: Oo0Ooo * I1ii11iIi11i - II111iiii - II111iiii
  self . ms_port = socket . ntohs ( O0OOOOoOo00O )
  self . etr_port = socket . ntohs ( iII11i1I )
  packet = packet [ Iiiii : : ]
  if 7 - 7: oO0o
  if 41 - 41: ooOoO0o
  if 93 - 93: Ii1I + I1Ii111 + Ii1I
  if 23 - 23: I1IiiI - i1IIi / ooOoO0o
  i1I1iii1I11II = "H"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 4 - 4: IiII . I1ii11iIi11i + iII111i % ooOoO0o
  if 28 - 28: I1Ii111
  if 27 - 27: iII111i * I1IiiI
  if 60 - 60: i1IIi / I1IiiI - I1ii11iIi11i
  O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  if ( O0ooo0 != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( O0ooo0 )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 41 - 41: I1Ii111 + ooOoO0o / OOooOOo + I11i % Oo0Ooo
   if 91 - 91: I1IiiI % I1ii11iIi11i % oO0o / i1IIi * iIii1I11I1II1 + I11i
   if 48 - 48: ooOoO0o / I1ii11iIi11i / OoO0O00 / II111iiii * OoOoOO00
   if 73 - 73: I11i / I1IiiI - IiII - i1IIi * IiII - OOooOOo
   if 39 - 39: I11i . ooOoO0o * II111iiii
   if 21 - 21: Ii1I
  if ( len ( packet ) < Iiiii ) : return ( OoO )
  if 92 - 92: OoO0O00 * I1ii11iIi11i + iIii1I11I1II1
  O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  if ( O0ooo0 != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( O0ooo0 )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( OoO )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 88 - 88: iIii1I11I1II1 + iIii1I11I1II1 * i11iIiiIii . I1ii11iIi11i % oO0o
   if 94 - 94: I1IiiI / I1ii11iIi11i / OOooOOo
   if 45 - 45: II111iiii
   if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
   if 84 - 84: o0oOOo0O0Ooo
  if ( len ( packet ) < Iiiii ) : return ( OoO )
  if 40 - 40: OoooooooOO - oO0o / O0 * I1Ii111 . O0 + i11iIiiIii
  O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  if ( O0ooo0 != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( O0ooo0 )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( OoO )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 9 - 9: OOooOOo % O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
   if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
   if 66 - 66: OOooOOo * Oo0Ooo
   if 58 - 58: OOooOOo
   if 96 - 96: IiII % OoooooooOO + O0 * II111iiii / OOooOOo . I1Ii111
   if 47 - 47: OoO0O00 - Oo0Ooo * OoO0O00 / oO0o
  while ( len ( packet ) >= Iiiii ) :
   O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
   packet = packet [ Iiiii : : ]
   if ( O0ooo0 == 0 ) : continue
   OOO0O0OoOO = lisp_address ( socket . ntohs ( O0ooo0 ) , "" , 0 , 0 )
   packet = OOO0O0OoOO . unpack_address ( packet )
   if ( packet == None ) : return ( OoO )
   OOO0O0OoOO . mask_len = OOO0O0OoOO . host_mask_len ( )
   self . rtr_list . append ( OOO0O0OoOO )
   if 13 - 13: ooOoO0o
  return ( OoO )
  if 55 - 55: i1IIi . I11i . II111iiii + O0 + ooOoO0o - i1IIi
  if 3 - 3: iIii1I11I1II1 / oO0o
  if 61 - 61: I1Ii111 / O0 - iII111i
class lisp_nat_info ( ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 44 - 44: i1IIi
  if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
 def timed_out ( self ) :
  oO000o0Oo00 = time . time ( ) - self . uptime
  return ( oO000o0Oo00 >= ( LISP_INFO_INTERVAL * 2 ) )
  if 89 - 89: OoOoOO00 + Oo0Ooo . OoOoOO00 - II111iiii
  if 85 - 85: OoooooooOO * OoooooooOO / Ii1I - II111iiii
  if 69 - 69: iII111i * I11i
class lisp_info_source ( ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 43 - 43: o0oOOo0O0Ooo - IiII * Ii1I . i11iIiiIii / II111iiii
  if 61 - 61: OoOoOO00 / I1IiiI . I1ii11iIi11i % OOooOOo
 def cache_address_for_info_source ( self ) :
  Oo000O000 = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ Oo000O000 ] = self
  if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
  if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
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
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 12 - 12: II111iiii - iIii1I11I1II1
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 43 - 43: i11iIiiIii % OoO0O00
  if 100 - 100: i1IIi
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  oooO = auth1 + auth2 + auth3
  if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
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
  if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
 return ( oooO )
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
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   Oo00O0OoooO = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 54 - 54: i1IIi
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   Oo00O0OoooO = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 26 - 26: o0oOOo0O0Ooo % i11iIiiIii % OoOoOO00 % OoO0O00 * iII111i % I1IiiI
  Oo00O0OoooO . bind ( ( local_addr , int ( port ) ) )
 else :
  Ooo0o0OoOO = port
  if ( os . path . exists ( Ooo0o0OoOO ) ) :
   os . system ( "rm " + Ooo0o0OoOO )
   time . sleep ( 1 )
   if 91 - 91: i1IIi * ooOoO0o
  Oo00O0OoooO = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  Oo00O0OoooO . bind ( Ooo0o0OoOO )
  if 33 - 33: I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
 return ( Oo00O0OoooO )
 if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
 if 26 - 26: O0 % o0oOOo0O0Ooo + iII111i * I1ii11iIi11i * I1Ii111
 if 4 - 4: OOooOOo * OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
 if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
 if 62 - 62: I1Ii111 % II111iiii
 if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
 if 91 - 91: i11iIiiIii + Ii1I
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   Oo00O0OoooO = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 85 - 85: I11i % IiII
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   Oo00O0OoooO = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  Oo00O0OoooO = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  Oo00O0OoooO . bind ( internal_name )
  if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
 return ( Oo00O0OoooO )
 if 24 - 24: ooOoO0o - I1Ii111 * II111iiii - II111iiii
 if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
 if 93 - 93: Ii1I / iII111i
 if 100 - 100: Oo0Ooo
 if 94 - 94: I1ii11iIi11i / i1IIi * I1IiiI - I11i - I1ii11iIi11i
 if 6 - 6: I1ii11iIi11i % o0oOOo0O0Ooo + o0oOOo0O0Ooo / OOooOOo / I1IiiI
 if 67 - 67: OoOoOO00 . iII111i / OOooOOo * ooOoO0o + i1IIi
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 100 - 100: OOooOOo . ooOoO0o + I1Ii111 . oO0o
 if 20 - 20: i11iIiiIii - i1IIi - iIii1I11I1II1 - OoooooooOO
 if 72 - 72: I1Ii111 . OoO0O00
 if 59 - 59: I1IiiI * I11i % i1IIi
 if 77 - 77: OOooOOo * OoooooooOO + I1IiiI + I1IiiI % oO0o . OoooooooOO
 if 60 - 60: iIii1I11I1II1
 if 13 - 13: II111iiii + Ii1I
 if 33 - 33: i1IIi
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 36 - 36: ooOoO0o % ooOoO0o . i11iIiiIii
 if 42 - 42: OoO0O00 . I1Ii111 / Ii1I
 if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / oO0o . OoOoOO00
 if 74 - 74: I1IiiI * OoO0O00 + OoooooooOO * ooOoO0o . oO0o
 if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
 if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
 if 81 - 81: i1IIi % iIii1I11I1II1
 if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
 if 82 - 82: ooOoO0o
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
 if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
 if 59 - 59: i11iIiiIii / OoO0O00
 if 48 - 48: iIii1I11I1II1
 if 19 - 19: oO0o
 if 69 - 69: I1ii11iIi11i % iII111i - OoooooooOO % Ii1I * oO0o
 if 12 - 12: OoOoOO00 / I1Ii111 . O0 . IiII - OOooOOo - OoO0O00
 if 28 - 28: II111iiii . OoOoOO00 - o0oOOo0O0Ooo
 if 89 - 89: I1Ii111 * OoooooooOO . OOooOOo . I11i % i11iIiiIii
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 8 - 8: I1ii11iIi11i + II111iiii . OoO0O00 + I1IiiI - II111iiii % OoO0O00
 if 85 - 85: i11iIiiIii % iII111i + II111iiii
 if 16 - 16: ooOoO0o * OoOoOO00 / OoOoOO00 + II111iiii
 if 50 - 50: OoO0O00 / OOooOOo % I1IiiI / Ii1I + OoO0O00 . iIii1I11I1II1
 if 62 - 62: I1Ii111 + OoooooooOO - Ii1I - iIii1I11I1II1
 if 80 - 80: OoO0O00
 if 72 - 72: II111iiii % i11iIiiIii + OoOoOO00 / I1Ii111 - i11iIiiIii
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 39 - 39: i11iIiiIii - OOooOOo / OoO0O00 * OoOoOO00 / IiII
 if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 / Ii1I / II111iiii
 if 56 - 56: OOooOOo * iII111i / Ii1I
 if 9 - 9: I1ii11iIi11i * i11iIiiIii / I1Ii111 + iIii1I11I1II1
 if 1 - 1: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / oO0o
 if 73 - 73: iII111i
 if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo
 if 45 - 45: oO0o % O0 / O0
 if 98 - 98: I1Ii111
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 58 - 58: OOooOOo
 if 6 - 6: I1ii11iIi11i
 if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
 if 18 - 18: ooOoO0o
 if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
 if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
 if 29 - 29: Ii1I . II111iiii / I1Ii111
 if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
 if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 81 - 81: i11iIiiIii - II111iiii + I11i
 if 52 - 52: II111iiii
 if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
 if 26 - 26: I1ii11iIi11i - OoO0O00
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
 if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
 if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
 if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
 if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
def lisp_ipc ( packet , send_socket , node ) :
 if 15 - 15: Ii1I
 if 29 - 29: I11i / I1IiiI / OoooooooOO . OoOoOO00 / I11i . I1Ii111
 if 69 - 69: O0 * OoOoOO00 + o0oOOo0O0Ooo + I1IiiI % iII111i . OoooooooOO
 if 45 - 45: I1Ii111 + oO0o - o0oOOo0O0Ooo - OoOoOO00 + I1IiiI / II111iiii
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 46 - 46: II111iiii . iIii1I11I1II1
  if 62 - 62: I1ii11iIi11i % i1IIi % I1Ii111 * ooOoO0o % OOooOOo + I1IiiI
 Oo0Oooo0 = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 29 - 29: OoO0O00 - Ii1I
 OoO00oo00 = 0
 IiiI1iii1iIiiI = len ( packet )
 i1I1ii11i1II = 0
 iiiiI = .001
 while ( IiiI1iii1iIiiI > 0 ) :
  iI11 = min ( IiiI1iii1iIiiI , Oo0Oooo0 )
  OoOOoO0O00oO = packet [ OoO00oo00 : iI11 + OoO00oo00 ]
  if 21 - 21: iII111i + OoOoOO00 - i11iIiiIii % O0 + OOooOOo
  try :
   send_socket . sendto ( OoOOoO0O00oO , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( OoOOoO0O00oO ) , len ( packet ) , node ) )
   if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
   i1I1ii11i1II = 0
   iiiiI = .001
   if 94 - 94: IiII
  except socket . error , oOo :
   if ( i1I1ii11i1II == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 69 - 69: I1Ii111 . I1Ii111
    if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( OoOOoO0O00oO ) , len ( packet ) , node , oOo ) )
   if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
   if 8 - 8: iII111i % o0oOOo0O0Ooo
   i1I1ii11i1II += 1
   time . sleep ( iiiiI )
   if 87 - 87: Ii1I % I11i / I1Ii111
   lprint ( "Retrying after {} ms ..." . format ( iiiiI * 1000 ) )
   iiiiI *= 2
   continue
   if 21 - 21: OoO0O00 + Ii1I / I1Ii111
   if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
  OoO00oo00 += iI11
  IiiI1iii1iIiiI -= iI11
  if 38 - 38: i1IIi
 return
 if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
 if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
 if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
 if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
 if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
 if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
 if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 OoO00oo00 = 0
 O0OOOo000 = ""
 IiiI1iii1iIiiI = len ( packet ) * 2
 while ( OoO00oo00 < IiiI1iii1iIiiI ) :
  O0OOOo000 += packet [ OoO00oo00 : OoO00oo00 + 8 ] + " "
  OoO00oo00 += 8
  IiiI1iii1iIiiI -= 4
  if 2 - 2: OOooOOo / I11i * I11i + I11i / O0 - OOooOOo
 return ( O0OOOo000 )
 if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
 if 68 - 68: iII111i / OOooOOo
 if 28 - 28: II111iiii
 if 49 - 49: I1ii11iIi11i
 if 33 - 33: iIii1I11I1II1
 if 72 - 72: I1ii11iIi11i * i11iIiiIii
 if 12 - 12: O0 - iIii1I11I1II1 % Oo0Ooo / O0 - IiII
def lisp_send ( lisp_sockets , dest , port , packet ) :
 O0oO0o = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 41 - 41: oO0o
 if 45 - 45: Ii1I
 if 8 - 8: oO0o + OOooOOo
 if 37 - 37: IiII - OoOoOO00 + oO0o - Oo0Ooo + IiII
 if 33 - 33: Oo0Ooo % oO0o - I1IiiI + Oo0Ooo
 if 90 - 90: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1 % IiII * I1Ii111 . I1Ii111
 if 90 - 90: o0oOOo0O0Ooo - O0 % O0 - oO0o . OoooooooOO
 if 30 - 30: I11i + O0 / Ii1I / OoOoOO00 - oO0o + II111iiii
 if 21 - 21: iIii1I11I1II1 % OoooooooOO * OOooOOo % i1IIi
 if 73 - 73: OoooooooOO
 if 100 - 100: I11i / i1IIi / i1IIi % Ii1I - II111iiii . OoooooooOO
 if 72 - 72: Oo0Ooo * OoooooooOO % I1IiiI + I11i - II111iiii
 ii1i1II11II1i = dest . print_address_no_iid ( )
 if ( ii1i1II11II1i . find ( "::ffff:" ) != - 1 and ii1i1II11II1i . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : O0oO0o = lisp_sockets [ 0 ]
  if ( O0oO0o == None ) :
   O0oO0o = lisp_sockets [ 0 ]
   ii1i1II11II1i = ii1i1II11II1i . split ( "::ffff:" ) [ - 1 ]
   if 82 - 82: iIii1I11I1II1 / i1IIi * I1IiiI . i11iIiiIii
   if 56 - 56: Ii1I * I1IiiI / ooOoO0o * II111iiii
   if 51 - 51: i1IIi . oO0o % OOooOOo
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + ii1i1II11II1i , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 90 - 90: OoooooooOO + iII111i / iIii1I11I1II1
 if 12 - 12: OoooooooOO
 if 9 - 9: O0 / O0 / I1IiiI - oO0o . ooOoO0o
 if 6 - 6: O0 - OoO0O00 + OoooooooOO % iIii1I11I1II1
 Ooo0oOO0oOo0 = ( LISP_RLOC_PROBE_TTL == 255 )
 if ( Ooo0oOO0oOo0 ) :
  O0000oO = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  Ooo0oOO0oOo0 = ( O0000oO in [ 0x12 , 0x28 ] )
  if ( Ooo0oOO0oOo0 ) : lisp_set_ttl ( O0oO0o , LISP_RLOC_PROBE_TTL )
  if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
  if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
 try : O0oO0o . sendto ( packet , ( ii1i1II11II1i , port ) )
 except socket . error , oOo :
  lprint ( "socket.sendto() failed: {}" . format ( oOo ) )
  if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
  if 86 - 86: iII111i / i1IIi % Oo0Ooo
  if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
  if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
  if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
 if ( Ooo0oOO0oOo0 ) : lisp_set_ttl ( O0oO0o , 64 )
 return
 if 14 - 14: OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
 if 92 - 92: OoO0O00 . i1IIi
 if 22 - 22: Ii1I . I1IiiI
 if 54 - 54: OOooOOo / I1ii11iIi11i % oO0o
 if 66 - 66: I11i + iII111i
 if 50 - 50: IiII
 if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
 if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 55 - 55: OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
 if 37 - 37: Ii1I + o0oOOo0O0Ooo
 if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
 if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
 if 8 - 8: I11i - I11i % IiII
 iI11 = total_length - len ( packet )
 if ( iI11 == 0 ) : return ( [ True , packet ] )
 if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
 if 25 - 25: iII111i / iII111i % OoOoOO00 / ooOoO0o
 if 81 - 81: OOooOOo * oO0o
 if 32 - 32: Oo0Ooo * OoO0O00 + ooOoO0o . O0 * oO0o * iIii1I11I1II1
 if 50 - 50: i1IIi
 IiiI1iii1iIiiI = iI11
 while ( IiiI1iii1iIiiI > 0 ) :
  try : OoOOoO0O00oO = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 53 - 53: II111iiii + O0 . ooOoO0o * IiII + i1IIi
  OoOOoO0O00oO = OoOOoO0O00oO [ 0 ]
  if 80 - 80: Ii1I + O0
  if 59 - 59: i11iIiiIii - OoooooooOO % I11i . OoO0O00 - Oo0Ooo * o0oOOo0O0Ooo
  if 7 - 7: II111iiii % Ii1I * i11iIiiIii
  if 28 - 28: II111iiii / ooOoO0o * i11iIiiIii % OOooOOo
  if 18 - 18: I11i - IiII - iIii1I11I1II1
  if ( OoOOoO0O00oO . find ( "packet@" ) == 0 ) :
   Oo0OooI11IIIiiiI = OoOOoO0O00oO . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( OoOOoO0O00oO ) ,
   # IiII * O0 % i1IIi * I1ii11iIi11i / OOooOOo % I1IiiI
 Oo0OooI11IIIiiiI [ 1 ] if len ( Oo0OooI11IIIiiiI ) > 2 else "?" )
   return ( [ False , OoOOoO0O00oO ] )
   if 19 - 19: OoO0O00 . i1IIi
   if 23 - 23: II111iiii
  IiiI1iii1iIiiI -= len ( OoOOoO0O00oO )
  packet += OoOOoO0O00oO
  if 74 - 74: OOooOOo % i11iIiiIii % i11iIiiIii . I1ii11iIi11i
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( OoOOoO0O00oO ) , total_length , source ) )
  if 95 - 95: I11i
  if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
 return ( [ True , packet ] )
 if 94 - 94: OOooOOo / IiII
 if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
 if 22 - 22: OoOoOO00 - Oo0Ooo
 if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
 if 33 - 33: I11i + O0
 if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
 if 68 - 68: O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
 if 12 - 12: II111iiii + I11i
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 IiiiIi1iiii11 = ""
 for OoOOoO0O00oO in payload : IiiiIi1iiii11 += OoOOoO0O00oO + "\x40"
 return ( IiiiIi1iiii11 [ : - 1 ] )
 if 9 - 9: I1ii11iIi11i
 if 51 - 51: I1ii11iIi11i
 if 37 - 37: I1IiiI % I1Ii111
 if 22 - 22: o0oOOo0O0Ooo % OOooOOo - I11i + ooOoO0o / OOooOOo
 if 98 - 98: I11i * O0 + IiII - oO0o
 if 35 - 35: OoooooooOO * Ii1I
 if 73 - 73: ooOoO0o . OoO0O00 % I1ii11iIi11i - oO0o
 if 67 - 67: o0oOOo0O0Ooo . I11i + i1IIi
 if 100 - 100: Oo0Ooo - I1IiiI . OOooOOo % iIii1I11I1II1 . I11i
 if 83 - 83: OoOoOO00 * iII111i
 if 75 - 75: i11iIiiIii . o0oOOo0O0Ooo / oO0o . OoO0O00 % Ii1I % Ii1I
 if 94 - 94: iII111i . Ii1I
 if 71 - 71: o0oOOo0O0Ooo * II111iiii / OOooOOo . OoO0O00
 if 73 - 73: I1Ii111 * OoO0O00 / OoOoOO00 . II111iiii
 if 87 - 87: OoO0O00 + Oo0Ooo + O0 % OoooooooOO - iIii1I11I1II1
 if 100 - 100: Oo0Ooo + IiII
 if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1
 if 19 - 19: ooOoO0o + i1IIi / Oo0Ooo * II111iiii * I1Ii111 / ooOoO0o
 if 23 - 23: I1Ii111
 if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 75 - 75: I11i . Ii1I / I1ii11iIi11i
  if 99 - 99: Ii1I
  if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
  if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
  try : i1111iIIii1 = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 4 - 4: OoooooooOO . Ii1I / oO0o % iII111i - i1IIi
  if 29 - 29: O0 % OoOoOO00 + o0oOOo0O0Ooo
  if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo
  if 72 - 72: OOooOOo % I1Ii111 . Oo0Ooo - i11iIiiIii
  if 98 - 98: iII111i / I1IiiI + iIii1I11I1II1 % Oo0Ooo
  if 67 - 67: oO0o / II111iiii . I11i / oO0o
  if ( internal == False ) :
   IiiiIi1iiii11 = i1111iIIii1 [ 0 ]
   i1IIi1ii1i1ii = lisp_convert_6to4 ( i1111iIIii1 [ 1 ] [ 0 ] )
   Oo0O00O = i1111iIIii1 [ 1 ] [ 1 ]
   if 46 - 46: oO0o * Oo0Ooo - I11i / iIii1I11I1II1
   if ( Oo0O00O == LISP_DATA_PORT ) :
    ooOOO00Ooo0 = lisp_data_plane_logging
    iII111111 = lisp_format_packet ( IiiiIi1iiii11 [ 0 : 60 ] ) + " ..."
   else :
    ooOOO00Ooo0 = True
    iII111111 = lisp_format_packet ( IiiiIi1iiii11 )
    if 13 - 13: OoO0O00
    if 88 - 88: oO0o - OoO0O00 % ooOoO0o + OoOoOO00 + IiII
   if ( ooOOO00Ooo0 ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( IiiiIi1iiii11 ) , bold ( "from " + i1IIi1ii1i1ii , False ) , Oo0O00O ,
 iII111111 ) )
    if 83 - 83: i1IIi - Oo0Ooo - IiII - i11iIiiIii
   return ( [ "packet" , i1IIi1ii1i1ii , Oo0O00O , IiiiIi1iiii11 ] )
   if 53 - 53: OoOoOO00 . OoooooooOO
   if 11 - 11: i1IIi % II111iiii % I1ii11iIi11i
   if 99 - 99: oO0o - I1Ii111
   if 29 - 29: I1IiiI - I11i
   if 42 - 42: Oo0Ooo - O0 . OoOoOO00
   if 4 - 4: IiII
  iIi1i1i1II1 = False
  i1I = i1111iIIii1 [ 0 ]
  ooOoo0OO0O = False
  if 4 - 4: o0oOOo0O0Ooo
  while ( iIi1i1i1II1 == False ) :
   i1I = i1I . split ( "@" )
   if 44 - 44: I11i % IiII / I1IiiI . OoO0O00 * Ii1I
   if ( len ( i1I ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( i1I [ 0 ] ) )
    if 89 - 89: OoOoOO00 / Oo0Ooo + O0 * ooOoO0o
    ooOoo0OO0O = True
    break
    if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
    if 95 - 95: II111iiii
   OO00oOo0oO = i1I [ 0 ]
   try :
    o00o0ooO0oo = int ( i1I [ 1 ] )
   except :
    OOO0OoOooo = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( OOO0OoOooo , i1111iIIii1 ) )
    ooOoo0OO0O = True
    break
    if 82 - 82: o0oOOo0O0Ooo - I11i + i1IIi . o0oOOo0O0Ooo
   i1IIi1ii1i1ii = i1I [ 2 ]
   Oo0O00O = i1I [ 3 ]
   if 58 - 58: II111iiii % ooOoO0o % I1Ii111 . II111iiii
   if 88 - 88: I1ii11iIi11i - iIii1I11I1II1 / iII111i
   if 69 - 69: o0oOOo0O0Ooo % o0oOOo0O0Ooo . i11iIiiIii
   if 34 - 34: Oo0Ooo - i11iIiiIii
   if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
   if 19 - 19: I1IiiI
   if 99 - 99: OOooOOo - OOooOOo
   if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
   if ( len ( i1I ) > 5 ) :
    IiiiIi1iiii11 = lisp_bit_stuff ( i1I [ 4 : : ] )
   else :
    IiiiIi1iiii11 = i1I [ 4 ]
    if 83 - 83: o0oOOo0O0Ooo
    if 23 - 23: o0oOOo0O0Ooo . I11i
    if 67 - 67: iII111i
    if 52 - 52: IiII . OoooooooOO
    if 34 - 34: o0oOOo0O0Ooo / IiII . OoooooooOO . Oo0Ooo / ooOoO0o + O0
    if 38 - 38: I11i
   iIi1i1i1II1 , IiiiIi1iiii11 = lisp_receive_segments ( lisp_socket , IiiiIi1iiii11 ,
 i1IIi1ii1i1ii , o00o0ooO0oo )
   if ( IiiiIi1iiii11 == None ) : return ( [ "" , "" , "" , "" ] )
   if 66 - 66: II111iiii
   if 57 - 57: OoO0O00 / Oo0Ooo % I1IiiI * I1ii11iIi11i
   if 68 - 68: iII111i - o0oOOo0O0Ooo - OoO0O00 . O0 - i11iIiiIii
   if 2 - 2: I1ii11iIi11i * i1IIi
   if 17 - 17: I1ii11iIi11i * Ii1I % Oo0Ooo * I1Ii111 + OoO0O00 . OoooooooOO
   if ( iIi1i1i1II1 == False ) :
    i1I = IiiiIi1iiii11
    continue
    if 60 - 60: Ii1I . II111iiii
    if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
   if ( Oo0O00O == "" ) : Oo0O00O = "no-port"
   if ( OO00oOo0oO == "command" and lisp_i_am_core == False ) :
    ooo = IiiiIi1iiii11 . find ( " {" )
    IiIIIi = IiiiIi1iiii11 if ooo == - 1 else IiiiIi1iiii11 [ : ooo ]
    IiIIIi = ": '" + IiIIIi + "'"
   else :
    IiIIIi = ""
    if 70 - 70: I1Ii111 * I11i % oO0o % ooOoO0o * iII111i - I1Ii111
    if 43 - 43: iIii1I11I1II1 . i11iIiiIii - oO0o
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( IiiiIi1iiii11 ) , bold ( "from " + i1IIi1ii1i1ii , False ) , Oo0O00O , OO00oOo0oO ,
 IiIIIi if ( OO00oOo0oO in [ "command" , "api" ] ) else ": ... " if ( OO00oOo0oO == "data-packet" ) else ": " + lisp_format_packet ( IiiiIi1iiii11 ) ) )
   if 55 - 55: iIii1I11I1II1 % oO0o % OOooOOo / I1Ii111 * OoooooooOO / Oo0Ooo
   if 88 - 88: I11i + OoO0O00 . iIii1I11I1II1 . II111iiii
   if 67 - 67: OOooOOo - ooOoO0o % iII111i % IiII
   if 71 - 71: OoO0O00 - ooOoO0o - I1IiiI + O0
   if 15 - 15: i1IIi
  if ( ooOoo0OO0O ) : continue
  return ( [ OO00oOo0oO , i1IIi1ii1i1ii , Oo0O00O , IiiiIi1iiii11 ] )
  if 43 - 43: II111iiii + OOooOOo . i11iIiiIii - II111iiii
  if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
  if 26 - 26: i1IIi - I1IiiI + IiII / OoO0O00 . I1ii11iIi11i
  if 82 - 82: I1Ii111 % iII111i . OoOoOO00 % OoO0O00 + I1ii11iIi11i
  if 69 - 69: I1IiiI * OoOoOO00 - ooOoO0o . O0
  if 15 - 15: oO0o . IiII + I1Ii111 - OoooooooOO
  if 85 - 85: II111iiii - Oo0Ooo + oO0o . i11iIiiIii + Oo0Ooo
  if 86 - 86: ooOoO0o . OoO0O00
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 i1i1i11i11 = False
 I1II1i = time . time ( )
 if 53 - 53: IiII * I1ii11iIi11i
 O0ooOoO0 = lisp_control_header ( )
 if ( O0ooOoO0 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( i1i1i11i11 )
  if 64 - 64: OOooOOo + Oo0Ooo . OoOoOO00 . OOooOOo + i11iIiiIii
  if 7 - 7: ooOoO0o * I11i / iIii1I11I1II1
  if 15 - 15: OoooooooOO / iII111i
  if 40 - 40: o0oOOo0O0Ooo
  if 75 - 75: oO0o - OoOoOO00 * ooOoO0o . O0
 o0ooo0 = source
 if ( source . find ( "lisp" ) == - 1 ) :
  IiII1iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  IiII1iiI . string_to_afi ( source )
  IiII1iiI . store_address ( source )
  source = IiII1iiI
  if 52 - 52: I1IiiI + oO0o * II111iiii
  if 15 - 15: I11i
 if ( O0ooOoO0 . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl , I1II1i )
  if 72 - 72: O0
 elif ( O0ooOoO0 . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl , I1II1i )
  if 15 - 15: II111iiii / I11i % II111iiii % Ii1I % i11iIiiIii / I1Ii111
 elif ( O0ooOoO0 . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 93 - 93: OOooOOo / OoooooooOO % iII111i
 elif ( O0ooOoO0 . type == LISP_MAP_NOTIFY ) :
  if ( o0ooo0 == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  else :
   if ( lisp_is_running ( "lisp-rtr" ) ) :
    lisp_process_multicast_map_notify ( packet , source )
    if 47 - 47: o0oOOo0O0Ooo - I1IiiI % O0 % I1Ii111 . O0 . OoOoOO00
   lisp_process_map_notify ( lisp_sockets , packet , source )
   if 95 - 95: o0oOOo0O0Ooo * OOooOOo - iII111i * OoooooooOO - ooOoO0o / I1IiiI
   if 47 - 47: OoO0O00 % I1IiiI / OoOoOO00 - I1Ii111 / I1IiiI
 elif ( O0ooOoO0 . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 13 - 13: o0oOOo0O0Ooo % ooOoO0o
 elif ( O0ooOoO0 . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 15 - 15: iII111i * I1IiiI . iIii1I11I1II1 % I1IiiI / O0
 elif ( O0ooOoO0 . type == LISP_NAT_INFO and O0ooOoO0 . is_info_reply ( ) ) :
  O0O , OO0Oo00oo , i1i1i11i11 = lisp_process_info_reply ( source , packet , True )
  if 47 - 47: OoooooooOO - i11iIiiIii . I1IiiI / i1IIi
 elif ( O0ooOoO0 . type == LISP_NAT_INFO and O0ooOoO0 . is_info_reply ( ) == False ) :
  oo0o00OO = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , oo0o00OO , udp_sport ,
 None )
  if 74 - 74: OoooooooOO * ooOoO0o
 elif ( O0ooOoO0 . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 45 - 45: Oo0Ooo + iIii1I11I1II1 . o0oOOo0O0Ooo
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( O0ooOoO0 . type ) )
  if 50 - 50: o0oOOo0O0Ooo % O0
 return ( i1i1i11i11 )
 if 67 - 67: OoOoOO00
 if 21 - 21: I11i % Oo0Ooo + Oo0Ooo / iIii1I11I1II1 % iIii1I11I1II1
 if 66 - 66: iII111i
 if 72 - 72: ooOoO0o / oO0o / iII111i . I1Ii111 . I1ii11iIi11i + IiII
 if 39 - 39: I1IiiI % I1Ii111
 if 22 - 22: OoOoOO00 - OOooOOo % i1IIi + i1IIi
 if 28 - 28: oO0o + OoOoOO00 * Ii1I . I11i
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp ) :
 if 80 - 80: I1ii11iIi11i / OoOoOO00
 oo00ooOOOo0O = bold ( "RLOC-probe" , False )
 if 74 - 74: I1ii11iIi11i + O0 + o0oOOo0O0Ooo - iII111i
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( oo00ooOOOo0O ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 48 - 48: ooOoO0o * iIii1I11I1II1 % Oo0Ooo
  if 60 - 60: OoOoOO00 / i1IIi * iIii1I11I1II1
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( oo00ooOOOo0O ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 91 - 91: I1Ii111 . OoooooooOO / IiII / I1IiiI
  if 56 - 56: II111iiii + iIii1I11I1II1 / I1Ii111 / I1Ii111 % Oo0Ooo / OoOoOO00
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( oo00ooOOOo0O ) )
 return
 if 46 - 46: i11iIiiIii + OoO0O00 . ooOoO0o + OoO0O00 % i11iIiiIii
 if 97 - 97: OoooooooOO % IiII * iIii1I11I1II1
 if 97 - 97: iIii1I11I1II1 - I1Ii111 - o0oOOo0O0Ooo * o0oOOo0O0Ooo * OoOoOO00
 if 80 - 80: II111iiii . I1ii11iIi11i % i11iIiiIii / Ii1I / oO0o
 if 100 - 100: Ii1I . OoO0O00 * ooOoO0o
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 4 - 4: i1IIi + OoooooooOO
 if 26 - 26: I1IiiI / II111iiii % I1ii11iIi11i * o0oOOo0O0Ooo . IiII / OoO0O00
 if 10 - 10: i11iIiiIii / i1IIi + O0 - i11iIiiIii % I11i - i1IIi
 if 38 - 38: O0 - I1IiiI + Oo0Ooo + ooOoO0o
 if 56 - 56: I1Ii111 + oO0o / Ii1I + I1Ii111
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 21 - 21: OOooOOo / OoOoOO00 + OoOoOO00 + OoOoOO00 - i1IIi + Ii1I
 if 43 - 43: O0 % II111iiii
 if 60 - 60: iII111i / ooOoO0o - Ii1I - OoooooooOO
 if 79 - 79: oO0o / iII111i . iIii1I11I1II1 * i11iIiiIii * i1IIi . iIii1I11I1II1
 if 31 - 31: OoooooooOO / ooOoO0o / OoooooooOO + ooOoO0o . O0 - IiII
 if 53 - 53: Oo0Ooo % iII111i % iII111i
 if 71 - 71: iII111i
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , map_request ,
 keys , enc , auth , mr_ttl = - 1 ) :
 if 99 - 99: O0 - OoOoOO00 * I1Ii111 - Oo0Ooo
 OoO0OOo = map_request . rloc_probe if ( map_request != None ) else False
 ii1i = map_request . json_telemetry if ( map_request != None ) else None
 if 51 - 51: ooOoO0o - I1Ii111 * oO0o
 if 47 - 47: Oo0Ooo % OoO0O00 * Ii1I / OoOoOO00
 i1i11i = lisp_map_reply ( )
 i1i11i . rloc_probe = OoO0OOo
 i1i11i . echo_nonce_capable = enc
 i1i11i . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 i1i11i . record_count = 1
 i1i11i . nonce = nonce
 IiiiIi1iiii11 = i1i11i . encode ( )
 i1i11i . print_map_reply ( )
 if 81 - 81: i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo + IiII % OOooOOo
 iI1I1I1I11I11 = lisp_eid_record ( )
 iI1I1I1I11I11 . rloc_count = len ( rloc_set )
 if ( ii1i != None ) : iI1I1I1I11I11 . rloc_count += 1
 iI1I1I1I11I11 . authoritative = auth
 iI1I1I1I11I11 . record_ttl = ttl
 iI1I1I1I11I11 . action = action
 iI1I1I1I11I11 . eid = eid
 iI1I1I1I11I11 . group = group
 if 92 - 92: II111iiii + OoooooooOO + OoOoOO00 / OOooOOo * Ii1I * Oo0Ooo
 IiiiIi1iiii11 += iI1I1I1I11I11 . encode ( )
 iI1I1I1I11I11 . print_record ( "  " , False )
 if 40 - 40: I1IiiI / I11i + II111iiii + II111iiii - O0 + Oo0Ooo
 OOooo = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 64 - 64: i1IIi % OoOoOO00
 o00OooOooO = None
 for oo0OOOoO0OoO in rloc_set :
  I1i11 = lisp_rloc_record ( )
  oo0o00OO = oo0OOOoO0OoO . rloc . print_address_no_iid ( )
  if ( oo0o00OO in OOooo ) :
   I1i11 . local_bit = True
   I1i11 . probe_bit = OoO0OOo
   I1i11 . keys = keys
   if ( oo0OOOoO0OoO . priority == 254 and lisp_i_am_rtr ) :
    I1i11 . rloc_name = "RTR"
    if 3 - 3: ooOoO0o / IiII
   if ( o00OooOooO == None ) : o00OooOooO = oo0OOOoO0OoO . rloc
   if 9 - 9: IiII
  I1i11 . store_rloc_entry ( oo0OOOoO0OoO )
  I1i11 . reach_bit = True
  I1i11 . print_record ( "    " )
  IiiiIi1iiii11 += I1i11 . encode ( )
  if 22 - 22: iII111i % i11iIiiIii / iIii1I11I1II1 % i1IIi + o0oOOo0O0Ooo
  if 64 - 64: II111iiii / II111iiii + OoO0O00
  if 70 - 70: Oo0Ooo * i11iIiiIii + IiII / OoOoOO00 . I1ii11iIi11i % OoOoOO00
  if 12 - 12: I11i % II111iiii % O0 % O0
  if 18 - 18: iII111i . IiII . I1IiiI
 if ( ii1i != None ) :
  I1i11 = lisp_rloc_record ( )
  if ( o00OooOooO ) : I1i11 . rloc . copy_address ( o00OooOooO )
  I1i11 . local_bit = True
  I1i11 . probe_bit = True
  I1i11 . reach_bit = True
  I1IIiiIiii1I1II1i = lisp_encode_telemetry ( ii1i , eo = str ( time . time ( ) ) )
  I1i11 . json = lisp_json ( "telemetry" , I1IIiiIiii1I1II1i )
  I1i11 . print_record ( "    " )
  IiiiIi1iiii11 += I1i11 . encode ( )
  if 81 - 81: oO0o % i11iIiiIii / Ii1I
 return ( IiiiIi1iiii11 )
 if 3 - 3: I1IiiI - O0 % O0
 if 85 - 85: iIii1I11I1II1 % OoooooooOO . Oo0Ooo * i1IIi . iIii1I11I1II1
 if 19 - 19: oO0o + II111iiii - OOooOOo
 if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
 if 81 - 81: iIii1I11I1II1 - OoO0O00 . i11iIiiIii
 if 4 - 4: o0oOOo0O0Ooo / OoO0O00 - I11i
 if 52 - 52: II111iiii . iII111i
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 iii111IIIIi1I = lisp_map_referral ( )
 iii111IIIIi1I . record_count = 1
 iii111IIIIi1I . nonce = nonce
 IiiiIi1iiii11 = iii111IIIIi1I . encode ( )
 iii111IIIIi1I . print_map_referral ( )
 if 82 - 82: Oo0Ooo - ooOoO0o
 iI1I1I1I11I11 = lisp_eid_record ( )
 if 25 - 25: I11i + oO0o / I1Ii111 % IiII * OOooOOo - I1Ii111
 O0oOo0OOOo0 = 0
 if ( ddt_entry == None ) :
  iI1I1I1I11I11 . eid = eid
  iI1I1I1I11I11 . group = group
 else :
  O0oOo0OOOo0 = len ( ddt_entry . delegation_set )
  iI1I1I1I11I11 . eid = ddt_entry . eid
  iI1I1I1I11I11 . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 16 - 16: IiII - I1ii11iIi11i - Oo0Ooo - ooOoO0o / OoooooooOO % i1IIi
 iI1I1I1I11I11 . rloc_count = O0oOo0OOOo0
 iI1I1I1I11I11 . authoritative = True
 if 85 - 85: i11iIiiIii / OoO0O00 / oO0o
 if 12 - 12: iII111i % OOooOOo % i1IIi
 if 17 - 17: IiII
 if 63 - 63: ooOoO0o . i11iIiiIii / iIii1I11I1II1
 if 8 - 8: i11iIiiIii . IiII * iIii1I11I1II1 * I1IiiI * Ii1I * i11iIiiIii
 O0II = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( O0oOo0OOOo0 == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   iI111i = ddt_entry . delegation_set [ 0 ]
   if ( iI111i . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 24 - 24: I1IiiI * I11i - o0oOOo0O0Ooo / iII111i + IiII - I1ii11iIi11i
   if ( iI111i . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 53 - 53: I11i / I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * OoOoOO00
    if 86 - 86: iIii1I11I1II1 - I1Ii111
    if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
    if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
    if 73 - 73: iII111i - o0oOOo0O0Ooo / OOooOOo + iII111i + o0oOOo0O0Ooo % II111iiii
    if 74 - 74: I11i * iIii1I11I1II1 - OoO0O00 / i1IIi / OoO0O00 / IiII
    if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0II = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  O0II = ( lisp_i_am_ms and iI111i . is_ms_peer ( ) == False )
  if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
  if 77 - 77: OoOoOO00 + IiII + Oo0Ooo
 iI1I1I1I11I11 . action = action
 iI1I1I1I11I11 . ddt_incomplete = O0II
 iI1I1I1I11I11 . record_ttl = ttl
 if 88 - 88: i1IIi
 IiiiIi1iiii11 += iI1I1I1I11I11 . encode ( )
 iI1I1I1I11I11 . print_record ( "  " , True )
 if 45 - 45: iII111i % I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
 if ( O0oOo0OOOo0 == 0 ) : return ( IiiiIi1iiii11 )
 if 55 - 55: OoO0O00 % IiII
 for iI111i in ddt_entry . delegation_set :
  I1i11 = lisp_rloc_record ( )
  I1i11 . rloc = iI111i . delegate_address
  I1i11 . priority = iI111i . priority
  I1i11 . weight = iI111i . weight
  I1i11 . mpriority = 255
  I1i11 . mweight = 0
  I1i11 . reach_bit = True
  IiiiIi1iiii11 += I1i11 . encode ( )
  I1i11 . print_record ( "    " )
  if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
 return ( IiiiIi1iiii11 )
 if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
 if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
 if 63 - 63: I1Ii111 + iII111i
 if 6 - 6: I1ii11iIi11i + Ii1I
 if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
 if 97 - 97: ooOoO0o + OOooOOo
 if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 6 - 6: Oo0Ooo + I1IiiI
 if ( map_request . target_group . is_null ( ) ) :
  iIIo00O000O = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  iIIo00O000O = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( iIIo00O000O ) : iIIo00O000O = iIIo00O000O . lookup_source_cache ( map_request . target_eid , False )
  if 53 - 53: ooOoO0o * oO0o - O0 . Ii1I + I1ii11iIi11i - O0
 I11i11i1 = map_request . print_prefix ( )
 if 37 - 37: OoO0O00 . i11iIiiIii
 if ( iIIo00O000O == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( I11i11i1 , False ) ) )
  if 62 - 62: i1IIi % i1IIi
  return
  if 58 - 58: OoooooooOO - i11iIiiIii
  if 67 - 67: OoO0O00 - OoooooooOO
 OOOo0O0O = iIIo00O000O . print_eid_tuple ( )
 if 46 - 46: II111iiii % iIii1I11I1II1 * i11iIiiIii
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( OOOo0O0O , False ) , green ( I11i11i1 , False ) ) )
 if 24 - 24: II111iiii . OoO0O00 % II111iiii / I11i
 if 42 - 42: OoOoOO00 . I1ii11iIi11i
 if 77 - 77: I1ii11iIi11i % i1IIi + OOooOOo - OOooOOo - o0oOOo0O0Ooo
 if 45 - 45: I1ii11iIi11i / o0oOOo0O0Ooo / I1IiiI - Oo0Ooo * ooOoO0o - I1ii11iIi11i
 if 71 - 71: I1IiiI % OoO0O00
 iiiI11111 = map_request . itr_rlocs [ 0 ]
 if ( iiiI11111 . is_private_address ( ) and lisp_nat_traversal ) :
  iiiI11111 = source
  if 27 - 27: OoO0O00 + o0oOOo0O0Ooo * iIii1I11I1II1 * OoooooooOO * Ii1I . iIii1I11I1II1
  if 67 - 67: oO0o * I1ii11iIi11i / I1Ii111 . i1IIi
 Iii11I = map_request . nonce
 ii11iIIi = lisp_nonce_echoing
 iIi11III = map_request . keys
 if 89 - 89: o0oOOo0O0Ooo / II111iiii . I1ii11iIi11i / OOooOOo
 if 92 - 92: OOooOOo % OOooOOo
 if 67 - 67: iII111i + I1ii11iIi11i - IiII . iII111i + iIii1I11I1II1
 if 40 - 40: II111iiii - oO0o / OoO0O00 / OoOoOO00 / Oo0Ooo
 if 11 - 11: IiII + OoooooooOO % OoooooooOO . o0oOOo0O0Ooo * OoOoOO00 + O0
 iIi1I = map_request . json_telemetry
 if ( iIi1I != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( iIi1I , ei = etr_in_ts )
  if 95 - 95: I1IiiI
  if 38 - 38: i1IIi
 iIIo00O000O . map_replies_sent += 1
 if 88 - 88: O0 . OoooooooOO / OoooooooOO / I1ii11iIi11i
 IiiiIi1iiii11 = lisp_build_map_reply ( iIIo00O000O . eid , iIIo00O000O . group , iIIo00O000O . rloc_set , Iii11I ,
 LISP_NO_ACTION , 1440 , map_request , iIi11III , ii11iIIi , True , ttl )
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
 if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
 if 36 - 36: OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
 if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  iiI1Iii = ( iiiI11111 . is_private_address ( ) == False )
  OOO0O0OoOO = iiiI11111 . print_address_no_iid ( )
  if ( ( iiI1Iii and lisp_rtr_list . has_key ( OOO0O0OoOO ) ) or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , iiiI11111 , None , IiiiIi1iiii11 )
   return
   if 23 - 23: oO0o / o0oOOo0O0Ooo + I11i % IiII * OoO0O00
   if 48 - 48: OoO0O00
   if 30 - 30: iIii1I11I1II1
   if 53 - 53: II111iiii
   if 40 - 40: Ii1I % oO0o
   if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
 lisp_send_map_reply ( lisp_sockets , IiiiIi1iiii11 , iiiI11111 , sport )
 return
 if 78 - 78: oO0o
 if 20 - 20: i1IIi + i1IIi * i1IIi
 if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
 if 27 - 27: oO0o + Ii1I . i11iIiiIii
 if 97 - 97: iII111i . I1IiiI
 if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
 if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 45 - 45: oO0o
 if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
 if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
 if 100 - 100: i11iIiiIii - iII111i - I11i
 iiiI11111 = map_request . itr_rlocs [ 0 ]
 if ( iiiI11111 . is_private_address ( ) ) : iiiI11111 = source
 Iii11I = map_request . nonce
 if 5 - 5: oO0o % IiII * iII111i
 ooOOoo0 = map_request . target_eid
 IIi1iiIII11 = map_request . target_group
 if 98 - 98: iII111i / OOooOOo + IiII
 Oo = [ ]
 for iIII1II1 in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( iIII1II1 == None ) : continue
  oOO = lisp_rloc ( )
  oOO . rloc . copy_address ( iIII1II1 )
  oOO . priority = 254
  Oo . append ( oOO )
  if 42 - 42: iII111i * Ii1I - O0 % o0oOOo0O0Ooo - IiII
  if 74 - 74: oO0o
 ii11iIIi = lisp_nonce_echoing
 iIi11III = map_request . keys
 if 94 - 94: I1ii11iIi11i * O0
 if 28 - 28: O0 % i11iIiiIii + iIii1I11I1II1 / OOooOOo
 if 67 - 67: iII111i + OOooOOo % iII111i + IiII
 if 79 - 79: OOooOOo
 if 47 - 47: IiII - I1ii11iIi11i . OOooOOo + I1Ii111 % I1IiiI
 iIi1I = map_request . json_telemetry
 if ( iIi1I != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( iIi1I , ei = etr_in_ts )
  if 3 - 3: I1IiiI / Oo0Ooo - Ii1I
  if 69 - 69: iIii1I11I1II1 % iII111i + ooOoO0o * i1IIi + iII111i * I1Ii111
 IiiiIi1iiii11 = lisp_build_map_reply ( ooOOoo0 , IIi1iiIII11 , Oo , Iii11I , LISP_NO_ACTION ,
 1440 , map_request , iIi11III , ii11iIIi , True , ttl )
 lisp_send_map_reply ( lisp_sockets , IiiiIi1iiii11 , iiiI11111 , sport )
 return
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
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 Oo = target_site_eid . registered_rlocs
 if 33 - 33: OoooooooOO + iIii1I11I1II1
 OoOoOO0OoOOOo = lisp_site_eid_lookup ( seid , group , False )
 if ( OoOoOO0OoOOOo == None ) : return ( Oo )
 if 13 - 13: oO0o . I1IiiI - Ii1I * I1ii11iIi11i
 if 28 - 28: Oo0Ooo * oO0o % ooOoO0o / OoOoOO00 % OoOoOO00
 if 85 - 85: I1IiiI
 if 8 - 8: I1IiiI
 iI1iiI = None
 ooOO0oO0OOO0o = [ ]
 for oo0OOOoO0OoO in Oo :
  if ( oo0OOOoO0OoO . is_rtr ( ) ) : continue
  if ( oo0OOOoO0OoO . rloc . is_private_address ( ) ) :
   i1111IiI = copy . deepcopy ( oo0OOOoO0OoO )
   ooOO0oO0OOO0o . append ( i1111IiI )
   continue
   if 76 - 76: oO0o * II111iiii
  iI1iiI = oo0OOOoO0OoO
  break
  if 81 - 81: I11i
 if ( iI1iiI == None ) : return ( Oo )
 iI1iiI = iI1iiI . rloc . print_address_no_iid ( )
 if 2 - 2: OoOoOO00
 if 75 - 75: I1IiiI - OoooooooOO * I1Ii111
 if 1 - 1: o0oOOo0O0Ooo % oO0o * I1Ii111 - i1IIi - iII111i . oO0o
 if 25 - 25: i1IIi * o0oOOo0O0Ooo / oO0o
 i1iIii1 = None
 for oo0OOOoO0OoO in OoOoOO0OoOOOo . registered_rlocs :
  if ( oo0OOOoO0OoO . is_rtr ( ) ) : continue
  if ( oo0OOOoO0OoO . rloc . is_private_address ( ) ) : continue
  i1iIii1 = oo0OOOoO0OoO
  break
  if 42 - 42: OoooooooOO * iII111i / I1IiiI + OoooooooOO + ooOoO0o * iII111i
 if ( i1iIii1 == None ) : return ( Oo )
 i1iIii1 = i1iIii1 . rloc . print_address_no_iid ( )
 if 35 - 35: I11i + OoooooooOO
 if 67 - 67: iII111i . OoO0O00 . i1IIi - Oo0Ooo
 if 92 - 92: I1Ii111 % II111iiii % I11i % O0 . I1Ii111 % o0oOOo0O0Ooo
 if 99 - 99: I1ii11iIi11i
 O0O0oOO = target_site_eid . site_id
 if ( O0O0oOO == 0 ) :
  if ( i1iIii1 == iI1iiI ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( iI1iiI ) )
   if 78 - 78: OoooooooOO
   return ( ooOO0oO0OOO0o )
   if 14 - 14: O0 % OoooooooOO
  return ( Oo )
  if 92 - 92: oO0o
  if 49 - 49: i11iIiiIii + OoO0O00 - OOooOOo
  if 9 - 9: II111iiii * OOooOOo / Oo0Ooo + iIii1I11I1II1 % I1IiiI
  if 95 - 95: I1Ii111 . IiII % OoO0O00 - OOooOOo - I11i
  if 55 - 55: OoooooooOO % I1ii11iIi11i % iII111i / IiII
  if 65 - 65: II111iiii
  if 58 - 58: iIii1I11I1II1 / i11iIiiIii . iII111i . OOooOOo * I1ii11iIi11i + OoooooooOO
 if ( O0O0oOO == OoOoOO0OoOOOo . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( O0O0oOO ) )
  return ( ooOO0oO0OOO0o )
  if 13 - 13: OoooooooOO + iII111i * i11iIiiIii % IiII + oO0o . o0oOOo0O0Ooo
 return ( Oo )
 if 31 - 31: o0oOOo0O0Ooo - ooOoO0o
 if 40 - 40: O0 / OoOoOO00 - I1Ii111
 if 60 - 60: IiII + I1IiiI
 if 61 - 61: OoO0O00
 if 96 - 96: ooOoO0o - OoooooooOO * iIii1I11I1II1 . IiII - O0
 if 7 - 7: iIii1I11I1II1 . OoO0O00
 if 88 - 88: i1IIi * II111iiii / i11iIiiIii % IiII . IiII
 if 93 - 93: OoOoOO00 * i1IIi . Ii1I
 if 2 - 2: i1IIi
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 OoO00 = [ ]
 Oo = [ ]
 if 48 - 48: Ii1I
 if 62 - 62: oO0o - I1ii11iIi11i - oO0o - OoO0O00 * Oo0Ooo
 if 47 - 47: o0oOOo0O0Ooo
 if 88 - 88: iIii1I11I1II1 + OOooOOo . II111iiii / i11iIiiIii % OOooOOo % IiII
 if 38 - 38: OOooOOo
 if 82 - 82: OoOoOO00 % II111iiii * ooOoO0o + OoooooooOO + I1IiiI
 o0Ooo0O000O = False
 iiI1IiIi = False
 for oo0OOOoO0OoO in registered_rloc_set :
  if ( oo0OOOoO0OoO . priority != 254 ) : continue
  iiI1IiIi |= True
  if ( oo0OOOoO0OoO . rloc . is_exact_match ( mr_source ) == False ) : continue
  o0Ooo0O000O = True
  break
  if 68 - 68: iII111i
  if 55 - 55: IiII . i11iIiiIii % OoooooooOO
  if 88 - 88: Ii1I * o0oOOo0O0Ooo / oO0o
  if 58 - 58: O0
  if 43 - 43: O0 / i1IIi / I11i % I1IiiI
  if 82 - 82: i11iIiiIii * i11iIiiIii + I1Ii111 - I1ii11iIi11i * oO0o - Ii1I
  if 40 - 40: o0oOOo0O0Ooo + OoO0O00 % i1IIi % iII111i * I1Ii111
 if ( iiI1IiIi == False ) : return ( registered_rloc_set )
 if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
 if 34 - 34: OoooooooOO * i11iIiiIii
 if 33 - 33: II111iiii
 if 59 - 59: iIii1I11I1II1 % I11i
 if 93 - 93: I1ii11iIi11i
 if 50 - 50: ooOoO0o % OoO0O00 % OoO0O00
 if 36 - 36: I1IiiI * O0 . IiII / I1Ii111
 if 15 - 15: I11i + iII111i
 if 79 - 79: i11iIiiIii * IiII % iII111i
 if 18 - 18: iIii1I11I1II1 - O0 . o0oOOo0O0Ooo % oO0o
 O0000o = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 14 - 14: OoooooooOO . I1Ii111 % Ii1I + iII111i + O0
 if 31 - 31: ooOoO0o / i11iIiiIii . OoO0O00 - O0 * Ii1I + Ii1I
 if 59 - 59: i11iIiiIii % iII111i
 if 54 - 54: I11i . ooOoO0o / OOooOOo % I1Ii111
 if 13 - 13: I11i / O0 . o0oOOo0O0Ooo . ooOoO0o
 for oo0OOOoO0OoO in registered_rloc_set :
  if ( O0000o and oo0OOOoO0OoO . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and oo0OOOoO0OoO . priority == 255 ) : continue
  if ( multicast and oo0OOOoO0OoO . mpriority == 255 ) : continue
  if ( oo0OOOoO0OoO . priority == 254 ) :
   OoO00 . append ( oo0OOOoO0OoO )
  else :
   Oo . append ( oo0OOOoO0OoO )
   if 7 - 7: OoO0O00 + OoooooooOO % II111iiii % oO0o
   if 48 - 48: OOooOOo . II111iiii * OOooOOo - I11i / iIii1I11I1II1 / i11iIiiIii
   if 37 - 37: II111iiii % O0 + iIii1I11I1II1 - I1IiiI . I11i + I1ii11iIi11i
   if 14 - 14: ooOoO0o % iIii1I11I1II1 % ooOoO0o / IiII + OOooOOo
   if 14 - 14: Oo0Ooo
   if 79 - 79: I1ii11iIi11i % I1Ii111 % I11i - iII111i * OoOoOO00
 if ( o0Ooo0O000O ) : return ( Oo )
 if 48 - 48: O0 + OoOoOO00 - O0
 if 79 - 79: ooOoO0o . OoOoOO00 / OoooooooOO - II111iiii
 if 48 - 48: Oo0Ooo
 if 59 - 59: OoO0O00 % o0oOOo0O0Ooo
 if 83 - 83: iII111i % iIii1I11I1II1 / OOooOOo - OoOoOO00
 if 98 - 98: I11i % oO0o . I1IiiI % OoOoOO00
 if 32 - 32: I1ii11iIi11i / Ii1I
 if 54 - 54: I11i - i11iIiiIii
 if 91 - 91: Ii1I - OoO0O00 - I1IiiI % OoO0O00 . o0oOOo0O0Ooo
 if 85 - 85: ooOoO0o . ooOoO0o % Oo0Ooo . OOooOOo + OOooOOo / I1IiiI
 Oo = [ ]
 for oo0OOOoO0OoO in registered_rloc_set :
  if ( oo0OOOoO0OoO . rloc . is_private_address ( ) ) : Oo . append ( oo0OOOoO0OoO )
  if 69 - 69: i1IIi + II111iiii / Ii1I
 Oo += OoO00
 return ( Oo )
 if 4 - 4: I11i * OoOoOO00 % o0oOOo0O0Ooo % ooOoO0o - I1ii11iIi11i
 if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 * I11i * OoOoOO00
 if 14 - 14: i11iIiiIii * I1IiiI % O0 % iIii1I11I1II1
 if 18 - 18: Oo0Ooo % OOooOOo + IiII
 if 28 - 28: OOooOOo . OoO0O00 / o0oOOo0O0Ooo + II111iiii / iIii1I11I1II1 * II111iiii
 if 83 - 83: II111iiii . OoOoOO00 - i11iIiiIii . OoOoOO00 . i1IIi % OoooooooOO
 if 47 - 47: II111iiii
 if 30 - 30: i1IIi . Oo0Ooo / o0oOOo0O0Ooo + IiII * OOooOOo
 if 26 - 26: Ii1I % O0 - i1IIi % iII111i * OoO0O00
 if 60 - 60: I1ii11iIi11i * iII111i / OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 oO0 = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 oO0 . add ( reply_eid )
 return
 if 25 - 25: I1Ii111 % OOooOOo
 if 82 - 82: Ii1I
 if 17 - 17: iII111i . i1IIi . i1IIi
 if 76 - 76: OoooooooOO % IiII
 if 81 - 81: iII111i . OOooOOo * i1IIi
 if 14 - 14: oO0o
 if 16 - 16: iII111i
 if 26 - 26: iII111i . oO0o * i11iIiiIii . iIii1I11I1II1
 if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
 if 65 - 65: OOooOOo * I11i * Oo0Ooo
 if 21 - 21: Ii1I . iIii1I11I1II1
 if 84 - 84: OOooOOo
 if 67 - 67: I1IiiI % OoO0O00 % o0oOOo0O0Ooo % IiII
 if 33 - 33: ooOoO0o % I1IiiI
 if 98 - 98: oO0o . o0oOOo0O0Ooo + II111iiii
def lisp_convert_reply_to_notify ( packet ) :
 if 62 - 62: ooOoO0o - OoooooooOO / I1ii11iIi11i / iII111i - o0oOOo0O0Ooo
 if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
 if 9 - 9: iII111i * Oo0Ooo % iII111i % Oo0Ooo * II111iiii
 if 71 - 71: II111iiii + I1ii11iIi11i * II111iiii
 o0ooO00 = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 o0ooO00 = socket . ntohl ( o0ooO00 ) & 0xff
 Iii11I = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 40 - 40: I11i . iII111i + OoOoOO00 % I1ii11iIi11i
 if 79 - 79: I1Ii111 - OOooOOo * I1ii11iIi11i + i11iIiiIii . iII111i
 if 3 - 3: Oo0Ooo
 if 81 - 81: OoO0O00 / OoO0O00 . I1ii11iIi11i
 iII = ( LISP_MAP_NOTIFY << 28 ) | o0ooO00
 O0ooOoO0 = struct . pack ( "I" , socket . htonl ( iII ) )
 o00O0o00oo = struct . pack ( "I" , 0 )
 if 100 - 100: iIii1I11I1II1 % II111iiii - I1ii11iIi11i . iIii1I11I1II1 + IiII % iIii1I11I1II1
 if 48 - 48: Ii1I % i1IIi
 if 38 - 38: OOooOOo / I1ii11iIi11i % oO0o / o0oOOo0O0Ooo
 if 54 - 54: OoOoOO00 * OoooooooOO - OoO0O00 * OoOoOO00 % I1ii11iIi11i * I11i
 packet = O0ooOoO0 + Iii11I + o00O0o00oo + packet
 return ( packet )
 if 34 - 34: I11i - oO0o + I11i * OoooooooOO * I11i
 if 73 - 73: OOooOOo * iII111i * OoO0O00
 if 11 - 11: I1Ii111 * II111iiii
 if 3 - 3: Oo0Ooo * OOooOOo
 if 13 - 13: I1Ii111 + i11iIiiIii / OOooOOo
 if 98 - 98: I1IiiI * Oo0Ooo
 if 9 - 9: O0 / i11iIiiIii . iIii1I11I1II1 . IiII
 if 14 - 14: OoOoOO00 . OOooOOo - Oo0Ooo + I1Ii111 % ooOoO0o
def lisp_notify_subscribers ( lisp_sockets , eid_record , eid , site ) :
 I11i11i1 = eid . print_prefix ( )
 if ( lisp_pubsub_cache . has_key ( I11i11i1 ) == False ) : return
 if 95 - 95: OoO0O00 * II111iiii + i1IIi
 for oO0 in lisp_pubsub_cache [ I11i11i1 ] . values ( ) :
  I11iiII1I1111 = oO0 . itr
  Oo0O00O = oO0 . port
  I111iI1IIIi1I = red ( I11iiII1I1111 . print_address_no_iid ( ) , False )
  I111 = bold ( "subscriber" , False )
  I1II = "0x" + lisp_hex_string ( oO0 . xtr_id )
  Iii11I = "0x" + lisp_hex_string ( oO0 . nonce )
  if 46 - 46: OoO0O00 . oO0o * I1ii11iIi11i % ooOoO0o . iIii1I11I1II1
  lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( I111 , I111iI1IIIi1I , Oo0O00O , I1II , green ( I11i11i1 , False ) , Iii11I ) )
  if 2 - 2: Ii1I + OoooooooOO . oO0o
  if 26 - 26: ooOoO0o - Ii1I - I1Ii111 * IiII + I1Ii111 . OoOoOO00
  lisp_build_map_notify ( lisp_sockets , eid_record , [ I11i11i1 ] , 1 , I11iiII1I1111 ,
 Oo0O00O , oO0 . nonce , 0 , 0 , 0 , site , False )
  oO0 . map_notify_count += 1
  if 12 - 12: OoooooooOO
 return
 if 57 - 57: OoOoOO00 . iII111i . O0 * oO0o
 if 85 - 85: I1Ii111 * iIii1I11I1II1 . OoOoOO00
 if 20 - 20: I11i * O0 - OoooooooOO * OOooOOo % oO0o * iII111i
 if 70 - 70: I11i + O0 . i11iIiiIii . OOooOOo
 if 48 - 48: iIii1I11I1II1 * Ii1I - OoooooooOO / oO0o - OoO0O00 / i11iIiiIii
 if 24 - 24: I1IiiI
 if 63 - 63: I11i - iIii1I11I1II1 * Ii1I + OoooooooOO . i11iIiiIii
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 94 - 94: OoO0O00 . oO0o . OoOoOO00 * i11iIiiIii
 if 96 - 96: i1IIi . OoO0O00 . OoO0O00 - o0oOOo0O0Ooo - Ii1I
 if 33 - 33: ooOoO0o + I1ii11iIi11i - I1IiiI . iII111i / OoO0O00
 if 91 - 91: OOooOOo - OoooooooOO . OoO0O00
 lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl , xtr_id )
 if 34 - 34: Ii1I . I1IiiI . i1IIi * I1ii11iIi11i
 ooOOoo0 = green ( reply_eid . print_prefix ( ) , False )
 I11iiII1I1111 = red ( itr_rloc . print_address_no_iid ( ) , False )
 o0i1i = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( o0i1i ,
 ooOOoo0 , I11iiII1I1111 , xtr_id ) )
 if 20 - 20: IiII * I1Ii111
 if 11 - 11: I11i * OoO0O00 * OoO0O00 * I1ii11iIi11i * IiII
 if 42 - 42: I1Ii111 * I1Ii111 * OoO0O00 - oO0o
 if 96 - 96: Oo0Ooo
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 return
 if 82 - 82: ooOoO0o - O0 / OoO0O00
 if 24 - 24: IiII - OoOoOO00 / OoooooooOO . I1ii11iIi11i
 if 88 - 88: I11i
 if 36 - 36: iIii1I11I1II1 - ooOoO0o * OoO0O00 * OoO0O00 . II111iiii
 if 49 - 49: O0 + OoO0O00 - I1ii11iIi11i + ooOoO0o
 if 90 - 90: O0 . Ii1I * OOooOOo * OoooooooOO * ooOoO0o * Ii1I
 if 12 - 12: ooOoO0o * OoooooooOO * i1IIi
 if 3 - 3: o0oOOo0O0Ooo + Ii1I - i1IIi . OoooooooOO % Ii1I
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 39 - 39: o0oOOo0O0Ooo
 if 73 - 73: IiII
 if 92 - 92: OOooOOo / ooOoO0o . I1Ii111 . iII111i / ooOoO0o
 if 83 - 83: iIii1I11I1II1 - OoO0O00 - I1Ii111
 if 27 - 27: IiII - iII111i * i11iIiiIii % i11iIiiIii + OoOoOO00 . I1Ii111
 if 10 - 10: IiII / i11iIiiIii
 ooOOoo0 = map_request . target_eid
 IIi1iiIII11 = map_request . target_group
 I11i11i1 = lisp_print_eid_tuple ( ooOOoo0 , IIi1iiIII11 )
 iiiI11111 = map_request . itr_rlocs [ 0 ]
 I1II = map_request . xtr_id
 Iii11I = map_request . nonce
 I11I1iI = LISP_NO_ACTION
 oO0 = map_request . subscribe_bit
 if 6 - 6: I11i - OOooOOo
 if 100 - 100: Oo0Ooo / OOooOOo + iII111i - o0oOOo0O0Ooo + OoO0O00 % IiII
 if 91 - 91: Ii1I % I11i % Oo0Ooo / OoO0O00 - II111iiii - o0oOOo0O0Ooo
 if 50 - 50: OoooooooOO
 if 51 - 51: II111iiii - oO0o % OoooooooOO - II111iiii / O0 - OoooooooOO
 i1I11iIiI1i1 = True
 o0o0O0OO0o = ( lisp_get_eid_hash ( ooOOoo0 ) != None )
 if ( o0o0O0OO0o ) :
  O0OO0OoO00oOo = map_request . map_request_signature
  if ( O0OO0OoO00oOo == None ) :
   i1I11iIiI1i1 = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 74 - 74: Oo0Ooo % OoO0O00 / I1ii11iIi11i
  else :
   Oo0o0ooOo0 = map_request . signature_eid
   i11 , I11I111 , i1I11iIiI1i1 = lisp_lookup_public_key ( Oo0o0ooOo0 )
   if ( i1I11iIiI1i1 ) :
    i1I11iIiI1i1 = map_request . verify_map_request_sig ( I11I111 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( Oo0o0ooOo0 . print_address ( ) , i11 . print_address ( ) ) )
    if 72 - 72: OoOoOO00 * I1ii11iIi11i + iIii1I11I1II1
    if 51 - 51: oO0o + I1IiiI - I1Ii111 * Oo0Ooo . II111iiii
   OOO0Oooo = bold ( "passed" , False ) if i1I11iIiI1i1 else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( OOO0Oooo ) )
   if 44 - 44: OOooOOo - oO0o + o0oOOo0O0Ooo - i1IIi % o0oOOo0O0Ooo
   if 79 - 79: iII111i . iIii1I11I1II1
   if 42 - 42: i11iIiiIii / IiII . O0 / OOooOOo . iII111i * i1IIi
 if ( oO0 and i1I11iIiI1i1 == False ) :
  oO0 = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 83 - 83: iIii1I11I1II1 . II111iiii * Oo0Ooo . I1IiiI - I1IiiI - iIii1I11I1II1
  if 29 - 29: Oo0Ooo
  if 35 - 35: OoOoOO00 + II111iiii
  if 46 - 46: O0 / I1ii11iIi11i + OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
  if 96 - 96: IiII + i1IIi - I11i * I11i - OoO0O00 % II111iiii
  if 47 - 47: I1Ii111 . i11iIiiIii + oO0o . I1ii11iIi11i
  if 12 - 12: iIii1I11I1II1 % I1Ii111 * OoOoOO00 / OoooooooOO % OoooooooOO
  if 81 - 81: iIii1I11I1II1 - Oo0Ooo - ooOoO0o . OoO0O00 + I1ii11iIi11i
  if 84 - 84: iII111i . OOooOOo . iII111i * oO0o % Ii1I . oO0o
  if 86 - 86: iII111i * ooOoO0o / iIii1I11I1II1 + Ii1I . iII111i
  if 64 - 64: IiII - Oo0Ooo % iII111i % I11i
  if 42 - 42: Oo0Ooo . OoO0O00
  if 22 - 22: ooOoO0o - o0oOOo0O0Ooo + I11i / I1IiiI + OOooOOo
  if 10 - 10: oO0o / I1IiiI
 Oo00o0Oo = iiiI11111 if ( iiiI11111 . afi == ecm_source . afi ) else ecm_source
 if 95 - 95: II111iiii
 I1iiiI1I1 = lisp_site_eid_lookup ( ooOOoo0 , IIi1iiIII11 , False )
 if 3 - 3: I1Ii111 . i1IIi
 if ( I1iiiI1I1 == None or I1iiiI1I1 . is_star_g ( ) ) :
  IiIii11 = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( IiIii11 ,
 green ( I11i11i1 , False ) ) )
  if 13 - 13: oO0o + Oo0Ooo + Oo0Ooo / OoO0O00 + i1IIi + I1IiiI
  if 56 - 56: OoOoOO00
  if 10 - 10: iIii1I11I1II1 + i1IIi * Ii1I / iIii1I11I1II1 % OoOoOO00 / O0
  if 14 - 14: O0
  lisp_send_negative_map_reply ( lisp_sockets , ooOOoo0 , IIi1iiIII11 , Iii11I , iiiI11111 ,
 mr_sport , 15 , I1II , oO0 )
  if 65 - 65: IiII / oO0o
  return ( [ ooOOoo0 , IIi1iiIII11 , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 57 - 57: IiII + oO0o - IiII
  if 51 - 51: OoOoOO00 % IiII / iII111i - oO0o - OoO0O00 . iIii1I11I1II1
 OOOo0O0O = I1iiiI1I1 . print_eid_tuple ( )
 oOO0o0o = I1iiiI1I1 . site . site_name
 if 29 - 29: O0 % I1Ii111
 if 19 - 19: I11i % IiII
 if 73 - 73: i11iIiiIii . II111iiii
 if 26 - 26: Oo0Ooo * i1IIi / OoooooooOO
 if 78 - 78: O0 + OOooOOo . I11i * OoOoOO00 - OoooooooOO
 if ( o0o0O0OO0o == False and I1iiiI1I1 . require_signature ) :
  O0OO0OoO00oOo = map_request . map_request_signature
  Oo0o0ooOo0 = map_request . signature_eid
  if ( O0OO0OoO00oOo == None or Oo0o0ooOo0 . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( oOO0o0o ) )
   i1I11iIiI1i1 = False
  else :
   Oo0o0ooOo0 = map_request . signature_eid
   i11 , I11I111 , i1I11iIiI1i1 = lisp_lookup_public_key ( Oo0o0ooOo0 )
   if ( i1I11iIiI1i1 ) :
    i1I11iIiI1i1 = map_request . verify_map_request_sig ( I11I111 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( Oo0o0ooOo0 . print_address ( ) , i11 . print_address ( ) ) )
    if 92 - 92: o0oOOo0O0Ooo + OoOoOO00 / oO0o . I1Ii111 * I1IiiI * OoOoOO00
    if 6 - 6: Ii1I / i11iIiiIii / IiII - i1IIi - I1IiiI * I11i
   OOO0Oooo = bold ( "passed" , False ) if i1I11iIiI1i1 else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( OOO0Oooo ) )
   if 43 - 43: IiII * Oo0Ooo / OoOoOO00 + I1IiiI - i11iIiiIii + II111iiii
   if 81 - 81: I11i / Oo0Ooo % Ii1I % OoO0O00
   if 87 - 87: O0 % II111iiii
   if 42 - 42: I1IiiI . i1IIi
   if 98 - 98: o0oOOo0O0Ooo % I11i . Oo0Ooo * Oo0Ooo % iII111i
   if 37 - 37: OoO0O00 / I1Ii111 . I1Ii111 * i1IIi
 if ( i1I11iIiI1i1 and I1iiiI1I1 . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( oOO0o0o , green ( OOOo0O0O , False ) , green ( I11i11i1 , False ) ) )
  if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
  if 13 - 13: II111iiii
  if 36 - 36: iII111i - oO0o / Oo0Ooo / O0 . OoO0O00 . i1IIi
  if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
  if 98 - 98: oO0o . Oo0Ooo
  if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
  if ( I1iiiI1I1 . accept_more_specifics == False ) :
   ooOOoo0 = I1iiiI1I1 . eid
   IIi1iiIII11 = I1iiiI1I1 . group
   if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
   if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
   if 64 - 64: OoooooooOO + OOooOOo
   if 36 - 36: I1IiiI - Ii1I / I1ii11iIi11i + Oo0Ooo % I1ii11iIi11i
   if 86 - 86: iIii1I11I1II1 * OoO0O00
  oOoooOOO0o0 = 1
  if ( I1iiiI1I1 . force_ttl != None ) :
   oOoooOOO0o0 = I1iiiI1I1 . force_ttl | 0x80000000
   if 82 - 82: I1IiiI - OoO0O00 % o0oOOo0O0Ooo
   if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
   if 98 - 98: Oo0Ooo . II111iiii * I11i
   if 39 - 39: IiII * o0oOOo0O0Ooo + Ii1I - I11i
   if 70 - 70: oO0o * ooOoO0o / ooOoO0o - Ii1I * Ii1I % OOooOOo
  lisp_send_negative_map_reply ( lisp_sockets , ooOOoo0 , IIi1iiIII11 , Iii11I , iiiI11111 ,
 mr_sport , oOoooOOO0o0 , I1II , oO0 )
  if 91 - 91: OoO0O00 - OoO0O00 % O0
  return ( [ ooOOoo0 , IIi1iiIII11 , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 67 - 67: ooOoO0o * i1IIi
  if 66 - 66: o0oOOo0O0Ooo - I1ii11iIi11i . OoOoOO00 / iII111i - Ii1I - i1IIi
  if 97 - 97: oO0o % iII111i - OOooOOo . OoooooooOO
  if 94 - 94: Oo0Ooo
  if 10 - 10: i11iIiiIii / I1ii11iIi11i . i1IIi + i1IIi * iII111i
 OooOoOooOO = False
 IIi1IIII1ii = ""
 I11II1i111Iii = False
 if ( I1iiiI1I1 . force_nat_proxy_reply ) :
  IIi1IIII1ii = ", nat-forced"
  OooOoOooOO = True
  I11II1i111Iii = True
 elif ( I1iiiI1I1 . force_proxy_reply ) :
  IIi1IIII1ii = ", forced"
  I11II1i111Iii = True
 elif ( I1iiiI1I1 . proxy_reply_requested ) :
  IIi1IIII1ii = ", requested"
  I11II1i111Iii = True
 elif ( map_request . pitr_bit and I1iiiI1I1 . pitr_proxy_reply_drop ) :
  IIi1IIII1ii = ", drop-to-pitr"
  I11I1iI = LISP_DROP_ACTION
 elif ( I1iiiI1I1 . proxy_reply_action != "" ) :
  I11I1iI = I1iiiI1I1 . proxy_reply_action
  IIi1IIII1ii = ", forced, action {}" . format ( I11I1iI )
  I11I1iI = LISP_DROP_ACTION if ( I11I1iI == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 87 - 87: Oo0Ooo + II111iiii . OoO0O00 + OoOoOO00 . IiII - OOooOOo
  if 46 - 46: iIii1I11I1II1
  if 97 - 97: O0 * OOooOOo - o0oOOo0O0Ooo % o0oOOo0O0Ooo * II111iiii % I11i
  if 65 - 65: iIii1I11I1II1 / OOooOOo
  if 2 - 2: I11i - OOooOOo / o0oOOo0O0Ooo
  if 14 - 14: I11i + Oo0Ooo + i11iIiiIii - i1IIi . O0
  if 47 - 47: o0oOOo0O0Ooo / i1IIi * IiII
 iiIi11I1I1 = False
 ooO00 = None
 if ( I11II1i111Iii and lisp_policies . has_key ( I1iiiI1I1 . policy ) ) :
  oo00ooOOOo0O = lisp_policies [ I1iiiI1I1 . policy ]
  if ( oo00ooOOOo0O . match_policy_map_request ( map_request , mr_source ) ) : ooO00 = oo00ooOOOo0O
  if 44 - 44: OoooooooOO . oO0o
  if ( ooO00 ) :
   O0oo0000o = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( O0oo0000o ,
 oo00ooOOOo0O . policy_name , oo00ooOOOo0O . set_action ) )
  else :
   O0oo0000o = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( O0oo0000o ,
 oo00ooOOOo0O . policy_name ) )
   iiIi11I1I1 = True
   if 30 - 30: I1Ii111 % IiII / II111iiii
   if 68 - 68: oO0o / O0 / OOooOOo
   if 3 - 3: o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if ( IIi1IIII1ii != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( I11i11i1 , False ) , oOO0o0o , green ( OOOo0O0O , False ) ,
  # II111iiii
 IIi1IIII1ii ) )
  if 93 - 93: OoOoOO00 / OoOoOO00 / OoOoOO00
  Oo = I1iiiI1I1 . registered_rlocs
  oOoooOOO0o0 = 1440
  if ( OooOoOooOO ) :
   if ( I1iiiI1I1 . site_id != 0 ) :
    O0OOO0OOo0 = map_request . source_eid
    Oo = lisp_get_private_rloc_set ( I1iiiI1I1 , O0OOO0OOo0 , IIi1iiIII11 )
    if 1 - 1: OoooooooOO . ooOoO0o - i1IIi
   if ( Oo == I1iiiI1I1 . registered_rlocs ) :
    Oo00oOoo = ( I1iiiI1I1 . group . is_null ( ) == False )
    ooOO0oO0OOO0o = lisp_get_partial_rloc_set ( Oo , Oo00o0Oo , Oo00oOoo )
    if ( ooOO0oO0OOO0o != Oo ) :
     oOoooOOO0o0 = 15
     Oo = ooOO0oO0OOO0o
     if 83 - 83: OoooooooOO + Oo0Ooo
     if 4 - 4: Oo0Ooo - i11iIiiIii / O0 / I11i + ooOoO0o / iII111i
     if 72 - 72: II111iiii % iII111i + OoO0O00
     if 44 - 44: OoooooooOO + OoooooooOO - Ii1I * iII111i
     if 45 - 45: oO0o . O0 - ooOoO0o / o0oOOo0O0Ooo
     if 58 - 58: Ii1I . iII111i * OoO0O00 + OoO0O00 % I1Ii111 + I1ii11iIi11i
     if 34 - 34: i11iIiiIii + OoOoOO00
     if 57 - 57: I1IiiI + IiII . OoOoOO00 * iIii1I11I1II1 % OoooooooOO
  if ( I1iiiI1I1 . force_ttl != None ) :
   oOoooOOO0o0 = I1iiiI1I1 . force_ttl | 0x80000000
   if 21 - 21: I11i
   if 36 - 36: IiII + OoO0O00
   if 66 - 66: iIii1I11I1II1 / oO0o
   if 36 - 36: o0oOOo0O0Ooo % I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo
   if 18 - 18: oO0o / i1IIi * I11i
   if 71 - 71: OoooooooOO - i11iIiiIii * i1IIi % OOooOOo - oO0o / o0oOOo0O0Ooo
  if ( ooO00 ) :
   if ( ooO00 . set_record_ttl ) :
    oOoooOOO0o0 = ooO00 . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( oOoooOOO0o0 ) )
    if 77 - 77: iIii1I11I1II1 / OoOoOO00
   if ( ooO00 . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    I11I1iI = LISP_POLICY_DENIED_ACTION
    Oo = [ ]
   else :
    oOO = ooO00 . set_policy_map_reply ( )
    if ( oOO ) : Oo = [ oOO ]
    if 59 - 59: Oo0Ooo % OOooOOo
    if 14 - 14: I11i . OoO0O00
    if 46 - 46: ooOoO0o
  if ( iiIi11I1I1 ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   I11I1iI = LISP_POLICY_DENIED_ACTION
   Oo = [ ]
   if 48 - 48: i1IIi * I1IiiI / i11iIiiIii
   if 40 - 40: IiII
  ii11iIIi = I1iiiI1I1 . echo_nonce_capable
  if 42 - 42: O0 / II111iiii
  if 88 - 88: Oo0Ooo
  if 20 - 20: OoooooooOO * i1IIi * IiII / OoooooooOO - Oo0Ooo / i11iIiiIii
  if 28 - 28: iIii1I11I1II1 % OOooOOo * I1IiiI
  if ( i1I11iIiI1i1 ) :
   iiIIIIi1 = I1iiiI1I1 . eid
   IiIiiiIii1 = I1iiiI1I1 . group
  else :
   iiIIIIi1 = ooOOoo0
   IiIiiiIii1 = IIi1iiIII11
   I11I1iI = LISP_AUTH_FAILURE_ACTION
   Oo = [ ]
   if 41 - 41: OoooooooOO - Oo0Ooo / I1ii11iIi11i / OoO0O00 - II111iiii
   if 73 - 73: oO0o - o0oOOo0O0Ooo
   if 50 - 50: iIii1I11I1II1 - i11iIiiIii / iII111i + ooOoO0o / OOooOOo
   if 80 - 80: IiII / OoooooooOO
   if 69 - 69: OoOoOO00 + IiII
   if 18 - 18: O0 / I11i
  packet = lisp_build_map_reply ( iiIIIIi1 , IiIiiiIii1 , Oo ,
 Iii11I , I11I1iI , oOoooOOO0o0 , map_request , None , ii11iIIi , False )
  if 10 - 10: I1Ii111 * i1IIi
  if ( oO0 ) :
   lisp_process_pubsub ( lisp_sockets , packet , iiIIIIi1 , iiiI11111 ,
 mr_sport , Iii11I , oOoooOOO0o0 , I1II )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , iiiI11111 , mr_sport )
   if 48 - 48: Oo0Ooo % i1IIi / iII111i . O0
   if 27 - 27: I11i + iIii1I11I1II1 - i11iIiiIii
  return ( [ I1iiiI1I1 . eid , I1iiiI1I1 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 81 - 81: I11i + oO0o * iIii1I11I1II1 * IiII
  if 7 - 7: I11i - I1IiiI . iII111i + O0 / iIii1I11I1II1 - I1Ii111
  if 32 - 32: ooOoO0o
  if 9 - 9: I1Ii111
  if 77 - 77: OoooooooOO * I1Ii111
 O0oOo0OOOo0 = len ( I1iiiI1I1 . registered_rlocs )
 if ( O0oOo0OOOo0 == 0 ) :
  lprint ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" . format ( green ( I11i11i1 , False ) , oOO0o0o ,
  # ooOoO0o + ooOoO0o * iIii1I11I1II1 - OoooooooOO
 green ( OOOo0O0O , False ) ) )
  return ( [ I1iiiI1I1 . eid , I1iiiI1I1 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 56 - 56: I11i / iIii1I11I1II1 - OoOoOO00 . Oo0Ooo + oO0o - ooOoO0o
  if 51 - 51: O0 . O0
  if 9 - 9: Oo0Ooo . i1IIi - i1IIi + I1Ii111 * ooOoO0o . I1ii11iIi11i
  if 17 - 17: I11i * I1ii11iIi11i % I1IiiI + OoO0O00 + IiII
  if 90 - 90: OoooooooOO - I1IiiI / I1ii11iIi11i + oO0o - o0oOOo0O0Ooo
 oO0oOoo = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 68 - 68: i11iIiiIii
 IIi1iiIIi1i = map_request . target_eid . hash_address ( oO0oOoo )
 IIi1iiIIi1i %= O0oOo0OOOo0
 I1I111I1 = I1iiiI1I1 . registered_rlocs [ IIi1iiIIi1i ]
 if 64 - 64: OoO0O00 * oO0o . I1IiiI / OoOoOO00
 if ( I1I111I1 . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( I11i11i1 , False ) ,
  # OoOoOO00 . Ii1I * O0 . Oo0Ooo / Oo0Ooo - iII111i
 oOO0o0o , green ( OOOo0O0O , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( I11i11i1 , False ) ,
  # i11iIiiIii . Ii1I
 red ( I1I111I1 . rloc . print_address ( ) , False ) , oOO0o0o ,
 green ( OOOo0O0O , False ) ) )
  if 86 - 86: o0oOOo0O0Ooo / oO0o * i1IIi
  if 41 - 41: II111iiii . i1IIi
  if 78 - 78: I1IiiI * I11i % OOooOOo + Ii1I + OoOoOO00
  if 23 - 23: iII111i / Oo0Ooo % OoooooooOO * OoooooooOO . iII111i / I1ii11iIi11i
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , I1I111I1 . rloc , to_etr = True )
  if 30 - 30: oO0o - OoOoOO00 . I1IiiI
 return ( [ I1iiiI1I1 . eid , I1iiiI1I1 . group , LISP_DDT_ACTION_MS_ACK ] )
 if 17 - 17: OoOoOO00
 if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
 if 57 - 57: O0
 if 23 - 23: OoO0O00 / II111iiii . I1ii11iIi11i . O0
 if 13 - 13: I1ii11iIi11i
 if 32 - 32: OOooOOo / I11i + I1Ii111 / Oo0Ooo * OoooooooOO / II111iiii
 if 8 - 8: OoO0O00
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 17 - 17: iIii1I11I1II1 - Oo0Ooo
 if 25 - 25: O0 + I1ii11iIi11i
 if 53 - 53: OoooooooOO . Oo0Ooo
 if 35 - 35: OOooOOo % i11iIiiIii % ooOoO0o . O0
 ooOOoo0 = map_request . target_eid
 IIi1iiIII11 = map_request . target_group
 I11i11i1 = lisp_print_eid_tuple ( ooOOoo0 , IIi1iiIII11 )
 Iii11I = map_request . nonce
 I11I1iI = LISP_DDT_ACTION_NULL
 if 9 - 9: ooOoO0o + iII111i / i1IIi % Oo0Ooo - o0oOOo0O0Ooo / I1IiiI
 if 42 - 42: OOooOOo + oO0o % O0 * I1ii11iIi11i + i11iIiiIii
 if 16 - 16: i1IIi . I11i + OoO0O00 % Ii1I * IiII + I1IiiI
 if 96 - 96: II111iiii + O0 - II111iiii
 if 97 - 97: I1IiiI
 o0o0oO = None
 if ( lisp_i_am_ms ) :
  I1iiiI1I1 = lisp_site_eid_lookup ( ooOOoo0 , IIi1iiIII11 , False )
  if ( I1iiiI1I1 == None ) : return
  if 58 - 58: i11iIiiIii / Ii1I - OoooooooOO
  if ( I1iiiI1I1 . registered ) :
   I11I1iI = LISP_DDT_ACTION_MS_ACK
   oOoooOOO0o0 = 1440
  else :
   ooOOoo0 , IIi1iiIII11 , I11I1iI = lisp_ms_compute_neg_prefix ( ooOOoo0 , IIi1iiIII11 )
   I11I1iI = LISP_DDT_ACTION_MS_NOT_REG
   oOoooOOO0o0 = 1
   if 25 - 25: i1IIi * ooOoO0o % OOooOOo / I1IiiI
 else :
  o0o0oO = lisp_ddt_cache_lookup ( ooOOoo0 , IIi1iiIII11 , False )
  if ( o0o0oO == None ) :
   I11I1iI = LISP_DDT_ACTION_NOT_AUTH
   oOoooOOO0o0 = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( I11i11i1 , False ) ) )
   if 75 - 75: i11iIiiIii
  elif ( o0o0oO . is_auth_prefix ( ) ) :
   if 38 - 38: iIii1I11I1II1
   if 80 - 80: OoO0O00
   if 72 - 72: I11i * II111iiii
   if 82 - 82: I1Ii111 . OoO0O00 * II111iiii
   I11I1iI = LISP_DDT_ACTION_DELEGATION_HOLE
   oOoooOOO0o0 = 15
   Oo00O = o0o0oO . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( Oo00O ,
   # II111iiii / OoO0O00
 green ( I11i11i1 , False ) ) )
   if 33 - 33: OoooooooOO / i1IIi . Ii1I
   if ( IIi1iiIII11 . is_null ( ) ) :
    ooOOoo0 = lisp_ddt_compute_neg_prefix ( ooOOoo0 , o0o0oO ,
 lisp_ddt_cache )
   else :
    IIi1iiIII11 = lisp_ddt_compute_neg_prefix ( IIi1iiIII11 , o0o0oO ,
 lisp_ddt_cache )
    ooOOoo0 = lisp_ddt_compute_neg_prefix ( ooOOoo0 , o0o0oO ,
 o0o0oO . source_cache )
    if 96 - 96: OoOoOO00 / Oo0Ooo . II111iiii / ooOoO0o
   o0o0oO = None
  else :
   Oo00O = o0o0oO . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( Oo00O , green ( I11i11i1 , False ) ) )
   if 56 - 56: IiII - ooOoO0o % oO0o / Oo0Ooo * oO0o % O0
   oOoooOOO0o0 = 1440
   if 71 - 71: iII111i / II111iiii - II111iiii / I1IiiI
   if 24 - 24: O0 . I1IiiI + IiII . IiII
   if 53 - 53: II111iiii + Ii1I * o0oOOo0O0Ooo
   if 47 - 47: Ii1I % OOooOOo . Oo0Ooo
   if 94 - 94: Ii1I - iIii1I11I1II1 + I1IiiI - iIii1I11I1II1 . o0oOOo0O0Ooo
   if 3 - 3: O0 / I11i + OoOoOO00 % IiII / i11iIiiIii
 IiiiIi1iiii11 = lisp_build_map_referral ( ooOOoo0 , IIi1iiIII11 , o0o0oO , I11I1iI , oOoooOOO0o0 , Iii11I )
 Iii11I = map_request . nonce >> 32
 if ( map_request . nonce != 0 and Iii11I != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , IiiiIi1iiii11 , ecm_source , port )
 return
 if 25 - 25: II111iiii / I1ii11iIi11i % iIii1I11I1II1
 if 69 - 69: IiII
 if 36 - 36: I1IiiI / oO0o
 if 72 - 72: i1IIi - I1ii11iIi11i . OOooOOo + I1Ii111 - ooOoO0o
 if 69 - 69: o0oOOo0O0Ooo * I1IiiI - I11i
 if 11 - 11: OOooOOo * O0
 if 43 - 43: I1IiiI - i1IIi . i1IIi * II111iiii
 if 64 - 64: I1IiiI * iIii1I11I1II1 % I1Ii111
 if 22 - 22: OoooooooOO + I1Ii111 . o0oOOo0O0Ooo * Oo0Ooo
 if 61 - 61: iIii1I11I1II1
 if 95 - 95: I1ii11iIi11i + IiII * Ii1I - IiII
 if 58 - 58: I1ii11iIi11i - oO0o % I11i * O0
 if 43 - 43: OoOoOO00 + O0
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 o0oOOooo0ooO = eid . hash_address ( entry_prefix )
 oooOOOO = eid . addr_length ( ) * 8
 OO00O = 0
 if 47 - 47: o0oOOo0O0Ooo . i1IIi % OoO0O00 + OoooooooOO . OoO0O00
 if 35 - 35: Oo0Ooo - Oo0Ooo + I11i
 if 17 - 17: O0 / IiII % I11i * i1IIi
 if 75 - 75: Ii1I . o0oOOo0O0Ooo / I11i
 for OO00O in range ( oooOOOO ) :
  I1i1iI = 1 << ( oooOOOO - OO00O - 1 )
  if ( o0oOOooo0ooO & I1i1iI ) : break
  if 42 - 42: o0oOOo0O0Ooo
  if 76 - 76: i1IIi
 if ( OO00O > neg_prefix . mask_len ) : neg_prefix . mask_len = OO00O
 return
 if 98 - 98: iII111i
 if 86 - 86: I1IiiI % OoO0O00 - O0 . I1Ii111 + ooOoO0o
 if 88 - 88: I1Ii111 . O0 - oO0o + i1IIi % Oo0Ooo
 if 39 - 39: I1Ii111 - I1IiiI
 if 18 - 18: i1IIi
 if 42 - 42: II111iiii - i1IIi . oO0o % OOooOOo % ooOoO0o - i11iIiiIii
 if 23 - 23: OOooOOo + iIii1I11I1II1 - i1IIi
 if 72 - 72: OOooOOo . I1IiiI * O0 + i11iIiiIii - iII111i
 if 79 - 79: o0oOOo0O0Ooo + I1ii11iIi11i
 if 46 - 46: I11i
def lisp_neg_prefix_walk ( entry , parms ) :
 ooOOoo0 , o0oOo , III111iiI = parms
 if 45 - 45: i1IIi - OoO0O00 % Oo0Ooo
 if ( o0oOo == None ) :
  if ( entry . eid . instance_id != ooOOoo0 . instance_id ) :
   return ( [ True , parms ] )
   if 42 - 42: ooOoO0o - I11i * iII111i
  if ( entry . eid . afi != ooOOoo0 . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( o0oOo ) == False ) :
   return ( [ True , parms ] )
   if 39 - 39: OOooOOo - I1ii11iIi11i % IiII % I1ii11iIi11i * II111iiii - Ii1I
   if 19 - 19: I11i % OoOoOO00 / OoO0O00 % I11i + o0oOOo0O0Ooo / iII111i
   if 35 - 35: ooOoO0o % I11i * I1ii11iIi11i
   if 10 - 10: OoO0O00 + OoooooooOO + I1Ii111
   if 57 - 57: Ii1I % Ii1I * Oo0Ooo % i11iIiiIii
   if 12 - 12: oO0o . Oo0Ooo . I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
 lisp_find_negative_mask_len ( ooOOoo0 , entry . eid , III111iiI )
 return ( [ True , parms ] )
 if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
 if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
 if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
 if 66 - 66: iII111i % iII111i
 if 59 - 59: II111iiii . i1IIi % i1IIi
 if 40 - 40: I1Ii111 . II111iiii * o0oOOo0O0Ooo + I11i - i1IIi
 if 67 - 67: o0oOOo0O0Ooo - O0 - i1IIi . ooOoO0o . iII111i
 if 43 - 43: II111iiii . o0oOOo0O0Ooo + i11iIiiIii . O0 / O0 . II111iiii
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 13 - 13: Ii1I % i11iIiiIii
 if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
 if 50 - 50: I1ii11iIi11i + iII111i
 if 64 - 64: oO0o
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 11 - 11: o0oOOo0O0Ooo
 III111iiI = lisp_address ( eid . afi , "" , 0 , 0 )
 III111iiI . copy_address ( eid )
 III111iiI . mask_len = 0
 if 95 - 95: i1IIi . ooOoO0o . Oo0Ooo
 II1Iii1Ii = ddt_entry . print_eid_tuple ( )
 o0oOo = ddt_entry . eid
 if 36 - 36: I1ii11iIi11i % OoooooooOO
 if 58 - 58: OoooooooOO
 if 57 - 57: I1ii11iIi11i % i1IIi % i1IIi % o0oOOo0O0Ooo
 if 45 - 45: IiII + oO0o . iII111i
 if 85 - 85: IiII * IiII * iII111i % i11iIiiIii
 eid , o0oOo , III111iiI = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , o0oOo , III111iiI ) )
 if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
 if 10 - 10: OOooOOo / I1ii11iIi11i
 if 21 - 21: OoO0O00 % Oo0Ooo . o0oOOo0O0Ooo + IiII
 if 48 - 48: O0 / i1IIi / iII111i
 III111iiI . mask_address ( III111iiI . mask_len )
 if 11 - 11: O0 - OoO0O00 + OoOoOO00 * ooOoO0o - Ii1I
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # oO0o - IiII % OoooooooOO . ooOoO0o * I1IiiI
 II1Iii1Ii , III111iiI . print_prefix ( ) ) )
 return ( III111iiI )
 if 44 - 44: o0oOOo0O0Ooo
 if 76 - 76: i11iIiiIii % OoO0O00
 if 38 - 38: I1ii11iIi11i + II111iiii - I1ii11iIi11i
 if 67 - 67: Ii1I / OoOoOO00
 if 19 - 19: OoO0O00 - OOooOOo * O0
 if 75 - 75: Ii1I + Oo0Ooo
 if 72 - 72: iII111i / o0oOOo0O0Ooo % I1IiiI * OOooOOo % I1ii11iIi11i * i11iIiiIii
 if 12 - 12: Ii1I * iIii1I11I1II1 . OoOoOO00 % i1IIi
def lisp_ms_compute_neg_prefix ( eid , group ) :
 III111iiI = lisp_address ( eid . afi , "" , 0 , 0 )
 III111iiI . copy_address ( eid )
 III111iiI . mask_len = 0
 II = lisp_address ( group . afi , "" , 0 , 0 )
 II . copy_address ( group )
 II . mask_len = 0
 o0oOo = None
 if 29 - 29: oO0o * OoO0O00 . IiII
 if 99 - 99: oO0o
 if 21 - 21: IiII * OoO0O00 / OoooooooOO % o0oOOo0O0Ooo + OoO0O00
 if 25 - 25: IiII % OOooOOo + Ii1I * I1ii11iIi11i
 if 25 - 25: iIii1I11I1II1 * OoOoOO00 % I1IiiI + IiII
 if ( group . is_null ( ) ) :
  o0o0oO = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( o0o0oO == None ) :
   III111iiI . mask_len = III111iiI . host_mask_len ( )
   II . mask_len = II . host_mask_len ( )
   return ( [ III111iiI , II , LISP_DDT_ACTION_NOT_AUTH ] )
   if 34 - 34: ooOoO0o - OoooooooOO . o0oOOo0O0Ooo
  oo0ooO = lisp_sites_by_eid
  if ( o0o0oO . is_auth_prefix ( ) ) : o0oOo = o0o0oO . eid
 else :
  o0o0oO = lisp_ddt_cache . lookup_cache ( group , False )
  if ( o0o0oO == None ) :
   III111iiI . mask_len = III111iiI . host_mask_len ( )
   II . mask_len = II . host_mask_len ( )
   return ( [ III111iiI , II , LISP_DDT_ACTION_NOT_AUTH ] )
   if 68 - 68: OOooOOo % Oo0Ooo * ooOoO0o * OoO0O00 / iII111i
  if ( o0o0oO . is_auth_prefix ( ) ) : o0oOo = o0o0oO . group
  if 96 - 96: i11iIiiIii - I1IiiI % OoOoOO00 * Ii1I % OoO0O00 % O0
  group , o0oOo , II = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , o0oOo , II ) )
  if 100 - 100: oO0o . OoooooooOO
  if 58 - 58: I11i % OoooooooOO
  II . mask_address ( II . mask_len )
  if 97 - 97: OOooOOo - IiII
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , o0oOo . print_prefix ( ) if ( o0oOo != None ) else "'not found'" ,
  # OoooooooOO * I1ii11iIi11i / O0 * II111iiii - Oo0Ooo
  # o0oOOo0O0Ooo
  # o0oOOo0O0Ooo
 II . print_prefix ( ) ) )
  if 53 - 53: II111iiii / IiII . i1IIi + I1Ii111 / OoO0O00 - OoooooooOO
  oo0ooO = o0o0oO . source_cache
  if 67 - 67: ooOoO0o . Ii1I - Oo0Ooo * iII111i . I11i - OOooOOo
  if 10 - 10: I11i
  if 37 - 37: o0oOOo0O0Ooo / I1IiiI * oO0o / II111iiii
  if 39 - 39: IiII - i1IIi - IiII - OoooooooOO - I1ii11iIi11i
  if 66 - 66: IiII + i1IIi
 I11I1iI = LISP_DDT_ACTION_DELEGATION_HOLE if ( o0oOo != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 21 - 21: IiII / i11iIiiIii / OoOoOO00
 if 75 - 75: Ii1I . i1IIi / I1IiiI * iII111i . IiII / OoOoOO00
 if 58 - 58: ooOoO0o + OOooOOo / ooOoO0o / i11iIiiIii
 if 95 - 95: ooOoO0o
 if 10 - 10: OoO0O00 % ooOoO0o * o0oOOo0O0Ooo
 if 37 - 37: Ii1I . o0oOOo0O0Ooo
 eid , o0oOo , III111iiI = oo0ooO . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , o0oOo , III111iiI ) )
 if 34 - 34: ooOoO0o * IiII . Ii1I + iIii1I11I1II1
 if 1 - 1: i11iIiiIii + I11i
 if 78 - 78: Ii1I % Oo0Ooo / OoO0O00 . iIii1I11I1II1 . II111iiii
 if 67 - 67: oO0o % I1Ii111
 III111iiI . mask_address ( III111iiI . mask_len )
 if 72 - 72: I1IiiI . i11iIiiIii . OoOoOO00 + I1IiiI - I1Ii111 + iII111i
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # O0
 # I1Ii111 * IiII / Ii1I
 o0oOo . print_prefix ( ) if ( o0oOo != None ) else "'not found'" , III111iiI . print_prefix ( ) ) )
 if 58 - 58: iII111i % O0 . O0
 if 93 - 93: oO0o % OoooooooOO + i11iIiiIii - I1Ii111 + i11iIiiIii
 return ( [ III111iiI , II , I11I1iI ] )
 if 43 - 43: I1IiiI / OOooOOo * Ii1I
 if 50 - 50: OoOoOO00
 if 77 - 77: O0 % Ii1I - I1ii11iIi11i
 if 17 - 17: OoooooooOO - OoooooooOO % I1Ii111 * Ii1I . OoooooooOO
 if 51 - 51: iIii1I11I1II1 % IiII * iIii1I11I1II1 - OoO0O00 % I1IiiI + i11iIiiIii
 if 33 - 33: I11i
 if 99 - 99: I11i
 if 61 - 61: i1IIi - i1IIi
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 97 - 97: I11i + II111iiii / OoooooooOO + I1ii11iIi11i * o0oOOo0O0Ooo
 ooOOoo0 = map_request . target_eid
 IIi1iiIII11 = map_request . target_group
 Iii11I = map_request . nonce
 if 29 - 29: I1Ii111
 if ( action == LISP_DDT_ACTION_MS_ACK ) : oOoooOOO0o0 = 1440
 if 95 - 95: OoOoOO00 * II111iiii + I1ii11iIi11i - I11i . I11i % i11iIiiIii
 if 23 - 23: OoO0O00
 if 26 - 26: I1ii11iIi11i
 if 66 - 66: i11iIiiIii - i11iIiiIii / Ii1I * OOooOOo / IiII
 iii111IIIIi1I = lisp_map_referral ( )
 iii111IIIIi1I . record_count = 1
 iii111IIIIi1I . nonce = Iii11I
 IiiiIi1iiii11 = iii111IIIIi1I . encode ( )
 iii111IIIIi1I . print_map_referral ( )
 if 67 - 67: I1IiiI . I1Ii111 - OoOoOO00
 O0II = False
 if 18 - 18: O0
 if 26 - 26: i1IIi - iIii1I11I1II1
 if 8 - 8: I1Ii111
 if 86 - 86: i1IIi
 if 26 - 26: o0oOOo0O0Ooo % I1Ii111 / Oo0Ooo
 if 68 - 68: II111iiii / Oo0Ooo / Oo0Ooo
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( ooOOoo0 ,
 IIi1iiIII11 )
  oOoooOOO0o0 = 15
  if 1 - 1: Oo0Ooo
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : oOoooOOO0o0 = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : oOoooOOO0o0 = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : oOoooOOO0o0 = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : oOoooOOO0o0 = 0
 if 73 - 73: Ii1I * iIii1I11I1II1 / o0oOOo0O0Ooo - o0oOOo0O0Ooo / i1IIi
 o00OooO0ooO0 = False
 O0oOo0OOOo0 = 0
 o0o0oO = lisp_ddt_cache_lookup ( ooOOoo0 , IIi1iiIII11 , False )
 if ( o0o0oO != None ) :
  O0oOo0OOOo0 = len ( o0o0oO . delegation_set )
  o00OooO0ooO0 = o0o0oO . is_ms_peer_entry ( )
  o0o0oO . map_referrals_sent += 1
  if 33 - 33: OOooOOo + I1ii11iIi11i + I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
  if 46 - 46: iII111i
  if 56 - 56: Oo0Ooo / II111iiii
  if 61 - 61: Ii1I - i1IIi / ooOoO0o - Oo0Ooo / IiII % Oo0Ooo
  if 53 - 53: OoooooooOO + iII111i % II111iiii * IiII
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0II = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  O0II = ( o00OooO0ooO0 == False )
  if 10 - 10: OoOoOO00 % I11i
  if 46 - 46: i1IIi % IiII
  if 45 - 45: I1ii11iIi11i / I1ii11iIi11i - OoO0O00
  if 54 - 54: Ii1I + I1IiiI * OoOoOO00 + oO0o
  if 10 - 10: Ii1I - I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
 iI1I1I1I11I11 = lisp_eid_record ( )
 iI1I1I1I11I11 . rloc_count = O0oOo0OOOo0
 iI1I1I1I11I11 . authoritative = True
 iI1I1I1I11I11 . action = action
 iI1I1I1I11I11 . ddt_incomplete = O0II
 iI1I1I1I11I11 . eid = eid_prefix
 iI1I1I1I11I11 . group = group_prefix
 iI1I1I1I11I11 . record_ttl = oOoooOOO0o0
 if 75 - 75: OOooOOo . ooOoO0o
 IiiiIi1iiii11 += iI1I1I1I11I11 . encode ( )
 iI1I1I1I11I11 . print_record ( "  " , True )
 if 32 - 32: i1IIi / I11i + iIii1I11I1II1 . OOooOOo
 if 67 - 67: iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
 if 51 - 51: I1IiiI + O0
 if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
 if ( O0oOo0OOOo0 != 0 ) :
  for iI111i in o0o0oO . delegation_set :
   I1i11 = lisp_rloc_record ( )
   I1i11 . rloc = iI111i . delegate_address
   I1i11 . priority = iI111i . priority
   I1i11 . weight = iI111i . weight
   I1i11 . mpriority = 255
   I1i11 . mweight = 0
   I1i11 . reach_bit = True
   IiiiIi1iiii11 += I1i11 . encode ( )
   I1i11 . print_record ( "    " )
   if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
   if 85 - 85: OoOoOO00
   if 57 - 57: Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
   if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
   if 72 - 72: Ii1I
   if 22 - 22: o0oOOo0O0Ooo / OoO0O00 + OoOoOO00 + Ii1I . II111iiii * I11i
   if 85 - 85: i11iIiiIii / I11i
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , IiiiIi1iiii11 , ecm_source , port )
 return
 if 28 - 28: i11iIiiIii + IiII / I11i . Ii1I / OoO0O00
 if 100 - 100: o0oOOo0O0Ooo - I11i . o0oOOo0O0Ooo
 if 90 - 90: OoOoOO00 / II111iiii / I11i * I11i - iIii1I11I1II1
 if 87 - 87: IiII
 if 92 - 92: OoO0O00 / IiII - ooOoO0o
 if 45 - 45: iII111i - I11i * ooOoO0o * OOooOOo / I1Ii111 * iII111i
 if 33 - 33: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo % iIii1I11I1II1 + I11i / i11iIiiIii
 if 64 - 64: I11i * ooOoO0o / OoooooooOO
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 38 - 38: iIii1I11I1II1 . OoO0O00 * OoOoOO00 + OoOoOO00 + ooOoO0o
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # IiII * I11i - OOooOOo
 red ( dest . print_address ( ) , False ) ) )
 if 11 - 11: I1IiiI % Ii1I + II111iiii
 I11I1iI = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
 if 63 - 63: OoOoOO00 % IiII . iII111i
 if 44 - 44: I1IiiI
 if 25 - 25: oO0o
 if 100 - 100: I1IiiI / IiII + OoO0O00 . iII111i
 if ( lisp_get_eid_hash ( eid ) != None ) :
  I11I1iI = LISP_SEND_MAP_REQUEST_ACTION
  if 39 - 39: OoooooooOO * OOooOOo - OoO0O00
  if 3 - 3: I11i . i11iIiiIii % Oo0Ooo % II111iiii . I11i
 IiiiIi1iiii11 = lisp_build_map_reply ( eid , group , [ ] , nonce , I11I1iI , ttl , None ,
 None , False , False )
 if 88 - 88: iIii1I11I1II1 . OOooOOo % iII111i
 if 72 - 72: ooOoO0o + i11iIiiIii / i1IIi
 if 64 - 64: OOooOOo - OOooOOo
 if 42 - 42: i1IIi / ooOoO0o . I1Ii111 % OoOoOO00
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , IiiiIi1iiii11 , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , IiiiIi1iiii11 , dest , port )
  if 67 - 67: i1IIi * i11iIiiIii * I1IiiI
 return
 if 23 - 23: Oo0Ooo
 if 81 - 81: I1Ii111 % II111iiii - Oo0Ooo / I1IiiI + i11iIiiIii . I11i
 if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
 if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
 if 60 - 60: OoO0O00 / oO0o . I1IiiI + OoOoOO00 + I1ii11iIi11i % Ii1I
 if 70 - 70: i1IIi * II111iiii * I1IiiI
 if 7 - 7: OoooooooOO + II111iiii % o0oOOo0O0Ooo * O0 . OoO0O00 * OoooooooOO
def lisp_retransmit_ddt_map_request ( mr ) :
 iI1ii111i1i = mr . mr_source . print_address ( )
 oO0O0oo0o0oO = mr . print_eid_tuple ( )
 Iii11I = mr . nonce
 if 28 - 28: IiII - i1IIi - I1Ii111 % Ii1I - IiII
 if 73 - 73: iIii1I11I1II1 . iIii1I11I1II1 + oO0o % i11iIiiIii . IiII
 if 33 - 33: IiII - OOooOOo / i11iIiiIii * iIii1I11I1II1
 if 2 - 2: i11iIiiIii % ooOoO0o
 if 56 - 56: IiII % ooOoO0o + I1IiiI % I11i - OOooOOo
 if ( mr . last_request_sent_to ) :
  OoiI = mr . last_request_sent_to . print_address ( )
  iiooOOOoOo00O0O = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( iiooOOOoOo00O0O and iiooOOOoOo00O0O . referral_set . has_key ( OoiI ) ) :
   iiooOOOoOo00O0O . referral_set [ OoiI ] . no_responses += 1
   if 16 - 16: oO0o % Ii1I % II111iiii
   if 91 - 91: iII111i - IiII + i1IIi . iII111i . I11i
   if 37 - 37: I11i + Ii1I * OoOoOO00 + o0oOOo0O0Ooo * i11iIiiIii . ooOoO0o
   if 63 - 63: I1Ii111 / Ii1I - iIii1I11I1II1 / i11iIiiIii / IiII + I11i
   if 57 - 57: iIii1I11I1II1 % iIii1I11I1II1
   if 23 - 23: II111iiii . ooOoO0o % I1Ii111
   if 39 - 39: OoooooooOO
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( oO0O0oo0o0oO , False ) , lisp_hex_string ( Iii11I ) ) )
  if 10 - 10: Oo0Ooo * iII111i
  mr . dequeue_map_request ( )
  return
  if 78 - 78: Oo0Ooo / i11iIiiIii - I1IiiI
  if 51 - 51: ooOoO0o / Oo0Ooo - I1Ii111 - iII111i
 mr . retry_count += 1
 if 68 - 68: I1ii11iIi11i - iIii1I11I1II1 * OoooooooOO
 IiII1iiI = green ( iI1ii111i1i , False )
 OooOOOoOoo0O0 = green ( oO0O0oo0o0oO , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # Oo0Ooo + Oo0Ooo / I1Ii111
 red ( mr . itr . print_address ( ) , False ) , IiII1iiI , OooOOOoOoo0O0 ,
 lisp_hex_string ( Iii11I ) ) )
 if 42 - 42: OoOoOO00
 if 69 - 69: OoO0O00
 if 24 - 24: i1IIi + o0oOOo0O0Ooo / oO0o - I1IiiI % I1IiiI
 if 100 - 100: Ii1I % I1Ii111 . iII111i % IiII * IiII . OoOoOO00
 lisp_send_ddt_map_request ( mr , False )
 if 68 - 68: iIii1I11I1II1
 if 30 - 30: I11i . I1ii11iIi11i - i1IIi / i1IIi + IiII . oO0o
 if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
 if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
 if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
 if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
 if 45 - 45: iIii1I11I1II1 . o0oOOo0O0Ooo % I1IiiI
 if 10 - 10: I1IiiI / i1IIi * o0oOOo0O0Ooo + Oo0Ooo - OoOoOO00 % iII111i
 if 88 - 88: Ii1I % Ii1I
 if 29 - 29: OOooOOo % I1ii11iIi11i
 if 57 - 57: I1ii11iIi11i - OoOoOO00 + IiII
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 58 - 58: OOooOOo % I1IiiI / oO0o . ooOoO0o . OoO0O00 / IiII
 if 72 - 72: ooOoO0o + ooOoO0o + o0oOOo0O0Ooo - o0oOOo0O0Ooo % Ii1I
 if 52 - 52: I11i % i1IIi . I1ii11iIi11i
 if 62 - 62: ooOoO0o - I1ii11iIi11i
 oOOoO0oOOO = [ ]
 for oO0O0o0000 in referral . referral_set . values ( ) :
  if ( oO0O0o0000 . updown == False ) : continue
  if ( len ( oOOoO0oOOO ) == 0 or oOOoO0oOOO [ 0 ] . priority == oO0O0o0000 . priority ) :
   oOOoO0oOOO . append ( oO0O0o0000 )
  elif ( oOOoO0oOOO [ 0 ] . priority > oO0O0o0000 . priority ) :
   oOOoO0oOOO = [ ]
   oOOoO0oOOO . append ( oO0O0o0000 )
   if 58 - 58: oO0o - Ii1I % I1ii11iIi11i . i11iIiiIii - i11iIiiIii
   if 75 - 75: OOooOOo % I1ii11iIi11i
   if 40 - 40: I1IiiI / I1IiiI
 Ii1II11iIii = len ( oOOoO0oOOO )
 if ( Ii1II11iIii == 0 ) : return ( None )
 if 95 - 95: OoooooooOO + OoooooooOO . IiII * II111iiii
 IIi1iiIIi1i = dest_eid . hash_address ( source_eid )
 IIi1iiIIi1i = IIi1iiIIi1i % Ii1II11iIii
 return ( oOOoO0oOOO [ IIi1iiIIi1i ] )
 if 98 - 98: OoO0O00 * iIii1I11I1II1 % o0oOOo0O0Ooo / I1Ii111 * I1IiiI
 if 46 - 46: I1IiiI . i1IIi / i1IIi * I1Ii111
 if 33 - 33: OOooOOo + OoOoOO00 % I1Ii111 / iIii1I11I1II1 % Ii1I % o0oOOo0O0Ooo
 if 49 - 49: OOooOOo
 if 1 - 1: I1ii11iIi11i - OoOoOO00 / oO0o + OoooooooOO % o0oOOo0O0Ooo
 if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
 if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 oOo0oo0 = mr . lisp_sockets
 Iii11I = mr . nonce
 I11iiII1I1111 = mr . itr
 IIiII11Iii111 = mr . mr_source
 I11i11i1 = mr . print_eid_tuple ( )
 if 67 - 67: OOooOOo % II111iiii
 if 47 - 47: OoO0O00 * I1Ii111 % OoooooooOO
 if 38 - 38: Ii1I % i1IIi
 if 41 - 41: I1ii11iIi11i . ooOoO0o / Oo0Ooo + i1IIi / i11iIiiIii * I1IiiI
 if 63 - 63: ooOoO0o + i11iIiiIii / i1IIi - I1Ii111 . O0 % OOooOOo
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( I11i11i1 , False ) , lisp_hex_string ( Iii11I ) ) )
  if 39 - 39: o0oOOo0O0Ooo
  mr . dequeue_map_request ( )
  return
  if 88 - 88: iII111i % I1IiiI . iIii1I11I1II1 * OOooOOo / IiII % OoooooooOO
  if 94 - 94: ooOoO0o % oO0o - OoooooooOO + IiII * Ii1I
  if 60 - 60: OoO0O00 - O0 + o0oOOo0O0Ooo + I1ii11iIi11i
  if 78 - 78: OOooOOo * Oo0Ooo * Ii1I
  if 94 - 94: OoooooooOO % iII111i
  if 48 - 48: iIii1I11I1II1
 if ( send_to_root ) :
  IiiIi1Iii11 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  i111IiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( I11i11i1 , False ) ) )
 else :
  IiiIi1Iii11 = mr . eid
  i111IiI = mr . group
  if 38 - 38: OoO0O00 + OoO0O00 . Oo0Ooo * OoooooooOO - i1IIi
  if 37 - 37: I1IiiI % i11iIiiIii + OoO0O00 * OOooOOo . o0oOOo0O0Ooo % IiII
  if 18 - 18: Oo0Ooo % IiII . OoOoOO00 - IiII + I1Ii111 + oO0o
  if 31 - 31: OOooOOo + OoOoOO00 * OOooOOo + OoOoOO00 / o0oOOo0O0Ooo . iIii1I11I1II1
  if 1 - 1: I1Ii111 * i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / Oo0Ooo
 IIiii1I1 = lisp_referral_cache_lookup ( IiiIi1Iii11 , i111IiI , False )
 if ( IIiii1I1 == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( oOo0oo0 , IiiIi1Iii11 , i111IiI ,
 Iii11I , I11iiII1I1111 , mr . sport , 15 , None , False )
  return
  if 43 - 43: II111iiii % O0 + o0oOOo0O0Ooo / Ii1I
  if 55 - 55: Oo0Ooo / Oo0Ooo - I1IiiI
 oO0Oo0O0o00 = IIiii1I1 . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( oO0Oo0O0o00 ,
 IIiii1I1 . print_referral_type ( ) ) )
 if 92 - 92: I1Ii111 . I1IiiI
 oO0O0o0000 = lisp_get_referral_node ( IIiii1I1 , IIiII11Iii111 , mr . eid )
 if ( oO0O0o0000 == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( oOo0oo0 , IIiii1I1 . eid ,
 IIiii1I1 . group , Iii11I , I11iiII1I1111 , mr . sport , 1 , None , False )
  return
  if 19 - 19: IiII / II111iiii + I1IiiI
  if 33 - 33: oO0o
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( oO0O0o0000 . referral_address . print_address ( ) ,
 # I1Ii111
 IIiii1I1 . print_referral_type ( ) , green ( I11i11i1 , False ) ,
 lisp_hex_string ( Iii11I ) ) )
 if 1 - 1: i11iIiiIii % I1Ii111 + I1ii11iIi11i
 if 17 - 17: Oo0Ooo
 if 59 - 59: OoO0O00 * o0oOOo0O0Ooo . I11i
 if 32 - 32: I1ii11iIi11i
 iiIiIIIIi11II = ( IIiii1I1 . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 IIiii1I1 . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( oOo0oo0 , mr . packet , IIiII11Iii111 , mr . sport , mr . eid ,
 oO0O0o0000 . referral_address , to_ms = iiIiIIIIi11II , ddt = True )
 if 37 - 37: iIii1I11I1II1
 if 64 - 64: II111iiii * oO0o % I1Ii111 + i1IIi
 if 57 - 57: OoOoOO00 + OoOoOO00
 if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
 mr . last_request_sent_to = oO0O0o0000 . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 oO0O0o0000 . map_requests_sent += 1
 return
 if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
 if 85 - 85: iII111i % i11iIiiIii
 if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
 if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
 if 41 - 41: Ii1I + IiII
 if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
 if 53 - 53: I1IiiI % OOooOOo + Ii1I - Ii1I
 if 99 - 99: i1IIi * OoOoOO00 - i1IIi
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 65 - 65: OoO0O00 / i11iIiiIii + I1ii11iIi11i + OoOoOO00
 ooOOoo0 = map_request . target_eid
 IIi1iiIII11 = map_request . target_group
 oO0O0oo0o0oO = map_request . print_eid_tuple ( )
 iI1ii111i1i = mr_source . print_address ( )
 Iii11I = map_request . nonce
 if 82 - 82: Ii1I * OOooOOo % ooOoO0o / OoO0O00 - Oo0Ooo . I1Ii111
 IiII1iiI = green ( iI1ii111i1i , False )
 OooOOOoOoo0O0 = green ( oO0O0oo0o0oO , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # ooOoO0o % OOooOOo % OoO0O00 . OoooooooOO / OoO0O00 * iIii1I11I1II1
 red ( ecm_source . print_address ( ) , False ) , IiII1iiI , OooOOOoOoo0O0 ,
 lisp_hex_string ( Iii11I ) ) )
 if 52 - 52: i11iIiiIii + OOooOOo - I11i
 if 43 - 43: OoOoOO00
 if 32 - 32: ooOoO0o * OoO0O00 * oO0o / I1ii11iIi11i
 if 72 - 72: I1ii11iIi11i * ooOoO0o % I1IiiI % OoOoOO00
 O0O0OOoO00 = lisp_ddt_map_request ( lisp_sockets , packet , ooOOoo0 , IIi1iiIII11 , Iii11I )
 O0O0OOoO00 . packet = packet
 O0O0OOoO00 . itr = ecm_source
 O0O0OOoO00 . mr_source = mr_source
 O0O0OOoO00 . sport = sport
 O0O0OOoO00 . from_pitr = map_request . pitr_bit
 O0O0OOoO00 . queue_map_request ( )
 if 4 - 4: i11iIiiIii % OoooooooOO . i11iIiiIii
 lisp_send_ddt_map_request ( O0O0OOoO00 , False )
 return
 if 61 - 61: iIii1I11I1II1 . Oo0Ooo . i1IIi
 if 45 - 45: I1Ii111
 if 49 - 49: i1IIi * iII111i - iIii1I11I1II1 % I11i * O0 / OoOoOO00
 if 48 - 48: IiII
 if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - o0oOOo0O0Ooo
 if 98 - 98: o0oOOo0O0Ooo * OoO0O00 . OoooooooOO
 if 40 - 40: I1Ii111 + Oo0Ooo + I1Ii111
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl , timestamp ) :
 if 57 - 57: I1Ii111 / II111iiii % iII111i
 OoO = packet
 I1IIIiii1 = lisp_map_request ( )
 packet = I1IIIiii1 . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 75 - 75: o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1IiiI / OoO0O00
  if 22 - 22: Oo0Ooo / iIii1I11I1II1 + o0oOOo0O0Ooo
 I1IIIiii1 . print_map_request ( )
 if 16 - 16: II111iiii . Ii1I + I1Ii111 % i1IIi / i11iIiiIii + OOooOOo
 if 43 - 43: I1IiiI . Oo0Ooo + i1IIi + I11i / OoO0O00
 if 66 - 66: i11iIiiIii
 if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
 if ( I1IIIiii1 . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , I1IIIiii1 , mr_source ,
 mr_port , ttl , timestamp )
  return
  if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
  if 83 - 83: i1IIi * i1IIi - II111iiii / OoooooooOO . Ii1I + I1Ii111
  if 10 - 10: I11i
  if 24 - 24: Ii1I
  if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
 if ( I1IIIiii1 . smr_bit ) :
  lisp_process_smr ( I1IIIiii1 )
  if 25 - 25: I11i % i1IIi / I11i * i11iIiiIii
  if 71 - 71: IiII % I11i - OoooooooOO + I1IiiI / Oo0Ooo % I11i
  if 6 - 6: i1IIi * i11iIiiIii + ooOoO0o - IiII
  if 97 - 97: iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - Oo0Ooo - iIii1I11I1II1
  if 26 - 26: ooOoO0o + Oo0Ooo
 if ( I1IIIiii1 . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( I1IIIiii1 )
  if 24 - 24: I1IiiI
  if 43 - 43: OoO0O00
  if 51 - 51: OoooooooOO % IiII % Oo0Ooo
  if 50 - 50: I1IiiI - i11iIiiIii / I1ii11iIi11i . Ii1I - iIii1I11I1II1
  if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , I1IIIiii1 , mr_source ,
 mr_port , ttl , timestamp )
  if 95 - 95: iII111i
  if 77 - 77: I1IiiI * II111iiii * iIii1I11I1II1
  if 19 - 19: OOooOOo * o0oOOo0O0Ooo
  if 64 - 64: I11i % ooOoO0o / OOooOOo / iII111i
  if 80 - 80: i1IIi
 if ( lisp_i_am_ms ) :
  packet = OoO
  ooOOoo0 , IIi1iiIII11 , oO = lisp_ms_process_map_request ( lisp_sockets ,
 OoO , I1IIIiii1 , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , I1IIIiii1 , ecm_source ,
 ecm_port , oO , ooOOoo0 , IIi1iiIII11 )
   if 49 - 49: OoooooooOO . OoooooooOO - i1IIi
  return
  if 40 - 40: IiII . iII111i
  if 68 - 68: iII111i
  if 29 - 29: II111iiii / II111iiii % OoO0O00 % Oo0Ooo . II111iiii
  if 33 - 33: OoooooooOO . OoO0O00 % OoooooooOO
  if 9 - 9: IiII * O0 + OOooOOo . II111iiii
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , OoO , I1IIIiii1 ,
 ecm_source , mr_port , mr_source )
  if 14 - 14: iIii1I11I1II1 + i11iIiiIii + o0oOOo0O0Ooo + o0oOOo0O0Ooo - IiII / I1Ii111
  if 70 - 70: OoooooooOO + I1IiiI / OOooOOo
  if 19 - 19: I1Ii111 + i1IIi % OoooooooOO + i1IIi
  if 16 - 16: I1Ii111 + II111iiii + IiII
  if 34 - 34: iIii1I11I1II1 - II111iiii - ooOoO0o + oO0o
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = OoO
  lisp_ddt_process_map_request ( lisp_sockets , I1IIIiii1 , ecm_source ,
 ecm_port )
  if 46 - 46: ooOoO0o % II111iiii
 return
 if 61 - 61: OoO0O00 . I1IiiI
 if 89 - 89: IiII
 if 73 - 73: II111iiii + ooOoO0o % OOooOOo . oO0o / oO0o * i1IIi
 if 19 - 19: I1Ii111 + I11i
 if 21 - 21: OoOoOO00
 if 2 - 2: i1IIi . OOooOOo
 if 23 - 23: Ii1I - OOooOOo
 if 89 - 89: i11iIiiIii
def lisp_store_mr_stats ( source , nonce ) :
 O0O0OOoO00 = lisp_get_map_resolver ( source , None )
 if ( O0O0OOoO00 == None ) : return
 if 40 - 40: OoooooooOO % OoO0O00
 if 54 - 54: i1IIi * OOooOOo - oO0o * OoooooooOO + II111iiii . IiII
 if 90 - 90: O0 - II111iiii + I1IiiI . iII111i
 if 3 - 3: o0oOOo0O0Ooo + i1IIi * Oo0Ooo
 O0O0OOoO00 . neg_map_replies_received += 1
 O0O0OOoO00 . last_reply = lisp_get_timestamp ( )
 if 6 - 6: OoO0O00 * OoooooooOO * iIii1I11I1II1
 if 87 - 87: iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1
 if 79 - 79: ooOoO0o . oO0o + Ii1I * ooOoO0o + O0 . II111iiii
 if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
 if ( ( O0O0OOoO00 . neg_map_replies_received % 100 ) == 0 ) : O0O0OOoO00 . total_rtt = 0
 if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
 if 5 - 5: OoooooooOO + ooOoO0o - II111iiii . i11iIiiIii / oO0o - ooOoO0o
 if 3 - 3: iII111i
 if 74 - 74: i11iIiiIii + OoooooooOO . OOooOOo
 if ( O0O0OOoO00 . last_nonce == nonce ) :
  O0O0OOoO00 . total_rtt += ( time . time ( ) - O0O0OOoO00 . last_used )
  O0O0OOoO00 . last_nonce = 0
  if 29 - 29: IiII % OoO0O00
 if ( ( O0O0OOoO00 . neg_map_replies_received % 10 ) == 0 ) : O0O0OOoO00 . last_nonce = 0
 return
 if 53 - 53: OoooooooOO - OoOoOO00 / IiII - I1Ii111
 if 16 - 16: iIii1I11I1II1 / OOooOOo + I1IiiI * II111iiii . OOooOOo
 if 68 - 68: IiII * IiII + oO0o / o0oOOo0O0Ooo
 if 41 - 41: OoOoOO00 - O0
 if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
 if 53 - 53: ooOoO0o + oO0o - II111iiii
 if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl , itr_in_ts ) :
 global lisp_map_cache
 if 6 - 6: iIii1I11I1II1 + oO0o
 i1i11i = lisp_map_reply ( )
 packet = i1i11i . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 8 - 8: I1ii11iIi11i + o0oOOo0O0Ooo
 i1i11i . print_map_reply ( )
 if 29 - 29: Ii1I . OOooOOo
 if 59 - 59: O0 . OoO0O00
 if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
 if 81 - 81: i1IIi % I11i * iIii1I11I1II1
 Iiii = None
 for IiIIi1IiiIiI in range ( i1i11i . record_count ) :
  iI1I1I1I11I11 = lisp_eid_record ( )
  packet = iI1I1I1I11I11 . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 55 - 55: iIii1I11I1II1
  iI1I1I1I11I11 . print_record ( "  " , False )
  if 7 - 7: OoO0O00
  if 61 - 61: I1Ii111 / I1IiiI / OOooOOo . I1ii11iIi11i
  if 3 - 3: IiII
  if 2 - 2: I1IiiI % Ii1I % Oo0Ooo / ooOoO0o % Oo0Ooo + OoOoOO00
  if 44 - 44: i1IIi / OoooooooOO * OoooooooOO
  if ( iI1I1I1I11I11 . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , i1i11i . nonce )
   if 93 - 93: OoOoOO00 % Oo0Ooo . OoO0O00 / OoooooooOO
   if 59 - 59: OoO0O00 + O0 + i11iIiiIii / OoOoOO00 + iIii1I11I1II1 / OoOoOO00
  OO00o0oO0O00 = ( iI1I1I1I11I11 . group . is_null ( ) == False )
  if 60 - 60: I11i + O0 * I1IiiI * O0 * II111iiii
  if 73 - 73: II111iiii
  if 81 - 81: I1IiiI + OoO0O00
  if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
  if 32 - 32: o0oOOo0O0Ooo - iII111i + i11iIiiIii / ooOoO0o . OoOoOO00 . IiII
  if ( lisp_decent_push_configured ) :
   I11I1iI = iI1I1I1I11I11 . action
   if ( OO00o0oO0O00 and I11I1iI == LISP_DROP_ACTION ) :
    if ( iI1I1I1I11I11 . eid . is_local ( ) ) : continue
    if 9 - 9: iIii1I11I1II1
    if 66 - 66: iIii1I11I1II1
    if 13 - 13: O0 / ooOoO0o
    if 64 - 64: i11iIiiIii + I1IiiI / Oo0Ooo - iII111i
    if 26 - 26: I1ii11iIi11i
    if 67 - 67: I1Ii111 * iIii1I11I1II1 / O0 + OoO0O00 * iIii1I11I1II1 % II111iiii
    if 13 - 13: Ii1I / ooOoO0o / iII111i % II111iiii * I1IiiI * II111iiii
  if ( iI1I1I1I11I11 . eid . is_null ( ) ) : continue
  if 40 - 40: Ii1I / i1IIi . iII111i
  if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
  if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
  if 85 - 85: I1IiiI + i1IIi % I1Ii111
  if 76 - 76: i11iIiiIii % i11iIiiIii
  if ( OO00o0oO0O00 ) :
   I1iOo0 = lisp_map_cache_lookup ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group )
  else :
   I1iOo0 = lisp_map_cache . lookup_cache ( iI1I1I1I11I11 . eid , True )
   if 65 - 65: oO0o % i11iIiiIii % I1ii11iIi11i + oO0o % o0oOOo0O0Ooo
  O0oO0 = ( I1iOo0 == None )
  if 23 - 23: iIii1I11I1II1
  if 68 - 68: oO0o * iII111i + II111iiii / i1IIi
  if 99 - 99: OoOoOO00 * oO0o + OOooOOo . Oo0Ooo - iII111i
  if 37 - 37: iII111i - OoOoOO00
  if 87 - 87: ooOoO0o
  if ( I1iOo0 == None ) :
   o0iIII1I , O0O , OO0Oo00oo = lisp_allow_gleaning ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group ,
 None )
   if ( o0iIII1I ) : continue
  else :
   if ( I1iOo0 . gleaned ) : continue
   if 57 - 57: I1Ii111 % i11iIiiIii
   if 36 - 36: O0 . I11i / o0oOOo0O0Ooo + i1IIi + oO0o * IiII
   if 29 - 29: O0 - II111iiii + iII111i
   if 73 - 73: I1Ii111 - I11i + IiII - o0oOOo0O0Ooo - I11i - OOooOOo
   if 40 - 40: iIii1I11I1II1 . iII111i * I1ii11iIi11i + IiII - iIii1I11I1II1
  Oo = [ ]
  for oooOi1II1II111 in range ( iI1I1I1I11I11 . rloc_count ) :
   I1i11 = lisp_rloc_record ( )
   I1i11 . keys = i1i11i . keys
   packet = I1i11 . decode ( packet , i1i11i . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 27 - 27: OoOoOO00 % I11i
   I1i11 . print_record ( "    " )
   if 19 - 19: i1IIi - OoOoOO00
   I11iI = None
   if ( I1iOo0 ) : I11iI = I1iOo0 . get_rloc ( I1i11 . rloc )
   if ( I11iI ) :
    oOO = I11iI
   else :
    oOO = lisp_rloc ( )
    if 90 - 90: o0oOOo0O0Ooo + O0
    if 71 - 71: ooOoO0o + OOooOOo
    if 100 - 100: ooOoO0o
    if 80 - 80: oO0o * I1Ii111
    if 87 - 87: iII111i + OoOoOO00 % ooOoO0o - oO0o
    if 40 - 40: i1IIi / OoOoOO00 - I11i / ooOoO0o . Ii1I
    if 8 - 8: I1IiiI . IiII . OOooOOo . O0
   Oo0O00O = oOO . store_rloc_from_record ( I1i11 , i1i11i . nonce ,
 source )
   oOO . echo_nonce_capable = i1i11i . echo_nonce_capable
   if 3 - 3: Ii1I + i11iIiiIii
   if ( oOO . echo_nonce_capable ) :
    oo0o00OO = oOO . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , oo0o00OO ) == None ) :
     lisp_echo_nonce ( oo0o00OO )
     if 87 - 87: ooOoO0o - iII111i % I11i
     if 88 - 88: I11i . OoooooooOO
     if 86 - 86: Ii1I - I1IiiI - iII111i % Ii1I . I1ii11iIi11i % i1IIi
     if 84 - 84: OoOoOO00
     if 99 - 99: OoO0O00 - OoOoOO00 - i1IIi / OoO0O00 * I1ii11iIi11i * iIii1I11I1II1
     if 65 - 65: iII111i - O0 / i1IIi . I1Ii111
   if ( oOO . json ) :
    if ( lisp_is_json_telemetry ( oOO . json . json_string ) ) :
     I1IIiiIiii1I1II1i = oOO . json . json_string
     I1IIiiIiii1I1II1i = lisp_encode_telemetry ( I1IIiiIiii1I1II1i , ii = itr_in_ts )
     oOO . json . json_string = I1IIiiIiii1I1II1i
     if 85 - 85: o0oOOo0O0Ooo % Ii1I
     if 81 - 81: oO0o / OoO0O00 * i1IIi % iIii1I11I1II1
     if 23 - 23: II111iiii . II111iiii
     if 17 - 17: i11iIiiIii / IiII * I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - iIii1I11I1II1
     if 21 - 21: OOooOOo % Ii1I
     if 3 - 3: OOooOOo / ooOoO0o / I1Ii111 . I11i
     if 54 - 54: I1ii11iIi11i - I1IiiI . OoOoOO00
     if 36 - 36: OoO0O00 * I1IiiI / iII111i
     if 95 - 95: Ii1I . Oo0Ooo
     if 42 - 42: IiII . i1IIi % O0 * ooOoO0o - OOooOOo % ooOoO0o
   if ( i1i11i . rloc_probe and I1i11 . probe_bit ) :
    if ( oOO . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( oOO , source , Oo0O00O ,
 i1i11i , ttl )
     if 99 - 99: i1IIi + OoOoOO00 - iII111i % II111iiii
     if 6 - 6: ooOoO0o - I1Ii111 . OoOoOO00
     if 64 - 64: iII111i + I1ii11iIi11i
     if 88 - 88: I1Ii111 / i11iIiiIii - O0 . II111iiii / II111iiii * II111iiii
     if 56 - 56: Oo0Ooo / I1IiiI % I1Ii111 % I1ii11iIi11i * I1IiiI - IiII
     if 39 - 39: oO0o + iII111i . I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + OOooOOo
   Oo . append ( oOO )
   if 61 - 61: ooOoO0o / I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * iII111i
   if 94 - 94: I1IiiI / I11i
   if 100 - 100: Ii1I % OoO0O00 % OoooooooOO / II111iiii * I1Ii111
   if 64 - 64: I1Ii111 * OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / Oo0Ooo
   if ( lisp_data_plane_security and oOO . rloc_recent_rekey ( ) ) :
    Iiii = oOO
    if 50 - 50: OOooOOo % i11iIiiIii
    if 99 - 99: IiII
    if 87 - 87: IiII
    if 35 - 35: oO0o . O0 . Ii1I / ooOoO0o
    if 36 - 36: i11iIiiIii . II111iiii . I11i . II111iiii
    if 36 - 36: Ii1I + ooOoO0o / Oo0Ooo % Oo0Ooo
    if 2 - 2: oO0o - Oo0Ooo * OoO0O00 . ooOoO0o . OOooOOo - oO0o
    if 74 - 74: o0oOOo0O0Ooo
    if 18 - 18: Oo0Ooo % OOooOOo / OOooOOo . I1IiiI + i1IIi . I1IiiI
    if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
    if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
  if ( i1i11i . rloc_probe == False and lisp_nat_traversal ) :
   ooOO0oO0OOO0o = [ ]
   iiI1iIi1II1ii = [ ]
   for oOO in Oo :
    if 95 - 95: IiII / O0 . i1IIi % OoO0O00
    if 13 - 13: II111iiii % I11i + OoooooooOO % I11i - I1ii11iIi11i / I11i
    if 27 - 27: I1Ii111 * I1IiiI - I1ii11iIi11i * I1IiiI / o0oOOo0O0Ooo % IiII
    if 24 - 24: oO0o - I11i / OoOoOO00 % ooOoO0o . OoOoOO00 % OOooOOo
    if 68 - 68: IiII % i1IIi + o0oOOo0O0Ooo
    if ( oOO . rloc . is_private_address ( ) ) :
     oOO . priority = 1
     oOO . state = LISP_RLOC_UNREACH_STATE
     ooOO0oO0OOO0o . append ( oOO )
     iiI1iIi1II1ii . append ( oOO . rloc . print_address_no_iid ( ) )
     continue
     if 33 - 33: iIii1I11I1II1 . O0
     if 54 - 54: iIii1I11I1II1
     if 54 - 54: iII111i + OOooOOo + OoO0O00
     if 6 - 6: oO0o - OoooooooOO * iIii1I11I1II1 * I1ii11iIi11i
     if 65 - 65: IiII + OoOoOO00
     if 93 - 93: Ii1I
    if ( oOO . priority == 254 and lisp_i_am_rtr == False ) :
     ooOO0oO0OOO0o . append ( oOO )
     iiI1iIi1II1ii . append ( oOO . rloc . print_address_no_iid ( ) )
     if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
    if ( oOO . priority != 254 and lisp_i_am_rtr ) :
     ooOO0oO0OOO0o . append ( oOO )
     iiI1iIi1II1ii . append ( oOO . rloc . print_address_no_iid ( ) )
     if 5 - 5: OoO0O00 / ooOoO0o
     if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
     if 97 - 97: oO0o / Ii1I
   if ( iiI1iIi1II1ii != [ ] ) :
    Oo = ooOO0oO0OOO0o
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( iiI1iIi1II1ii ) )
    if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
    if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
    if 91 - 91: IiII * Ii1I * OOooOOo
    if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
    if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
    if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
    if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
  ooOO0oO0OOO0o = [ ]
  for oOO in Oo :
   if ( oOO . json != None ) : continue
   ooOO0oO0OOO0o . append ( oOO )
   if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
  if ( ooOO0oO0OOO0o != [ ] ) :
   I1I1 = len ( Oo ) - len ( ooOO0oO0OOO0o )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( I1I1 ) )
   if 95 - 95: IiII + iII111i % I1IiiI
   Oo = ooOO0oO0OOO0o
   if 18 - 18: Oo0Ooo
   if 8 - 8: O0 + iIii1I11I1II1 - O0
   if 67 - 67: O0
   if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
   if 28 - 28: O0 - Oo0Ooo
   if 58 - 58: iIii1I11I1II1 - OoooooooOO - iII111i
   if 43 - 43: ooOoO0o / o0oOOo0O0Ooo
   if 56 - 56: II111iiii * I1ii11iIi11i * O0 . iII111i . I1ii11iIi11i % I1Ii111
  if ( i1i11i . rloc_probe and I1iOo0 != None ) : Oo = I1iOo0 . rloc_set
  if 99 - 99: Oo0Ooo - OoO0O00 + OoooooooOO - I1Ii111 - I1ii11iIi11i % i1IIi
  if 49 - 49: IiII % OoooooooOO / Oo0Ooo - OoOoOO00 + o0oOOo0O0Ooo / Ii1I
  if 6 - 6: I11i % IiII
  if 48 - 48: Ii1I
  if 100 - 100: OoO0O00 % I1Ii111 + OoooooooOO / OoO0O00
  oOo0O0o000O0 = O0oO0
  if ( I1iOo0 and Oo != I1iOo0 . rloc_set ) :
   I1iOo0 . delete_rlocs_from_rloc_probe_list ( )
   oOo0O0o000O0 = True
   if 74 - 74: iII111i - O0 * o0oOOo0O0Ooo / OoooooooOO + II111iiii + Ii1I
   if 39 - 39: i11iIiiIii . IiII + I1ii11iIi11i % IiII
   if 96 - 96: I11i / I1IiiI . i1IIi
   if 67 - 67: i11iIiiIii
   if 3 - 3: IiII
  iI = I1iOo0 . uptime if ( I1iOo0 ) else None
  if ( I1iOo0 == None ) :
   I1iOo0 = lisp_mapping ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group , Oo )
   I1iOo0 . mapping_source = source
   if 81 - 81: OoOoOO00 % ooOoO0o
   if 19 - 19: O0 - i1IIi - Oo0Ooo
   if 3 - 3: I1Ii111 + i11iIiiIii - I1IiiI . I1IiiI
   if 40 - 40: O0 * O0 / OOooOOo . OOooOOo . I1ii11iIi11i + O0
   if 96 - 96: iII111i * i11iIiiIii * I1Ii111
   if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
   if ( lisp_i_am_rtr and iI1I1I1I11I11 . group . is_null ( ) == False ) :
    I1iOo0 . map_cache_ttl = LISP_MCAST_TTL
   else :
    I1iOo0 . map_cache_ttl = iI1I1I1I11I11 . store_ttl ( )
    if 88 - 88: IiII
   I1iOo0 . action = iI1I1I1I11I11 . action
   I1iOo0 . add_cache ( oOo0O0o000O0 )
   if 29 - 29: iII111i . ooOoO0o
   if 62 - 62: IiII
  O0OoO = "Add"
  if ( iI ) :
   I1iOo0 . uptime = iI
   I1iOo0 . refresh_time = lisp_get_timestamp ( )
   O0OoO = "Replace"
   if 27 - 27: OoO0O00 + OOooOOo / ooOoO0o * I1IiiI / I11i
   if 84 - 84: iII111i . i11iIiiIii % ooOoO0o % O0 + I1IiiI
  lprint ( "{} {} map-cache with {} RLOCs" . format ( O0OoO ,
 green ( I1iOo0 . print_eid_tuple ( ) , False ) , len ( Oo ) ) )
  if 25 - 25: iIii1I11I1II1
  if 95 - 95: ooOoO0o * OoO0O00 % OoooooooOO % OoO0O00
  if 79 - 79: II111iiii % Ii1I * oO0o * iII111i + II111iiii
  if 51 - 51: I1IiiI + iII111i + I1IiiI / Ii1I * IiII + OOooOOo
  if 70 - 70: I11i . IiII + IiII
  if ( lisp_ipc_dp_socket and Iiii != None ) :
   lisp_write_ipc_keys ( Iiii )
   if 74 - 74: Ii1I
   if 11 - 11: I1ii11iIi11i
   if 83 - 83: O0
   if 97 - 97: O0
   if 50 - 50: I1Ii111 / OoooooooOO . o0oOOo0O0Ooo + I1IiiI * i11iIiiIii
   if 28 - 28: I1Ii111 * II111iiii
   if 14 - 14: iIii1I11I1II1 / Ii1I + o0oOOo0O0Ooo . iII111i % iII111i . i1IIi
  if ( O0oO0 ) :
   O0OoO0ooo0Ooo = bold ( "RLOC-probe" , False )
   for oOO in I1iOo0 . best_rloc_set :
    oo0o00OO = red ( oOO . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( O0OoO0ooo0Ooo , oo0o00OO ) )
    lisp_send_map_request ( lisp_sockets , 0 , I1iOo0 . eid , I1iOo0 . group , oOO )
    if 91 - 91: ooOoO0o
    if 66 - 66: OOooOOo
    if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
 return
 if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
 if 9 - 9: Ii1I
 if 44 - 44: iII111i
 if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
 if 37 - 37: OoO0O00 - Ii1I + OoO0O00
 if 49 - 49: OoooooooOO - I1ii11iIi11i % I1ii11iIi11i / i1IIi . ooOoO0o
 if 60 - 60: Oo0Ooo
 if 46 - 46: OoOoOO00 + i1IIi
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 43 - 43: II111iiii * IiII % iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
 packet = map_register . zero_auth ( packet )
 IIi1iiIIi1i = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 81 - 81: oO0o % I1ii11iIi11i % ooOoO0o * O0 - OOooOOo
 if 17 - 17: O0 % O0 / I1ii11iIi11i . Oo0Ooo . iII111i
 if 4 - 4: OoO0O00
 if 65 - 65: Oo0Ooo % O0 / I1Ii111 * IiII - oO0o
 map_register . auth_data = IIi1iiIIi1i
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 32 - 32: Ii1I * OoO0O00 + ooOoO0o
 if 41 - 41: IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
 if 38 - 38: iII111i * OoooooooOO - IiII
 if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
 if 91 - 91: O0 + I1Ii111 * II111iiii - O0 . i11iIiiIii . Oo0Ooo
 if 54 - 54: ooOoO0o * I11i / I1ii11iIi11i % ooOoO0o
 if 76 - 76: I11i . I1IiiI
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 66 - 66: oO0o % oO0o * IiII
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  IiI1iIIi1iIi = hashlib . sha1
  if 27 - 27: OoOoOO00
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  IiI1iIIi1iIi = hashlib . sha256
  if 53 - 53: iII111i
  if 43 - 43: i11iIiiIii * i11iIiiIii * I1Ii111
 if ( do_hex ) :
  IIi1iiIIi1i = hmac . new ( password , packet , IiI1iIIi1iIi ) . hexdigest ( )
 else :
  IIi1iiIIi1i = hmac . new ( password , packet , IiI1iIIi1iIi ) . digest ( )
  if 80 - 80: oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / o0oOOo0O0Ooo % OoooooooOO
 return ( IIi1iiIIi1i )
 if 31 - 31: o0oOOo0O0Ooo - OoO0O00 % I1IiiI
 if 23 - 23: OOooOOo
 if 97 - 97: Oo0Ooo / OoooooooOO . OoooooooOO
 if 47 - 47: OoO0O00
 if 52 - 52: I1IiiI * iIii1I11I1II1 % oO0o * IiII % oO0o
 if 9 - 9: I11i
 if 83 - 83: i11iIiiIii
 if 72 - 72: oO0o + II111iiii . O0 * oO0o + iII111i
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 22 - 22: I11i + Ii1I . IiII - OoO0O00 - o0oOOo0O0Ooo
 IIi1iiIIi1i = lisp_hash_me ( packet , alg_id , password , True )
 ooO0OOoO = ( IIi1iiIIi1i == auth_data )
 if 42 - 42: O0
 if 31 - 31: OoOoOO00 . II111iiii - oO0o . iII111i - I1ii11iIi11i
 if 90 - 90: OoooooooOO / ooOoO0o / I1IiiI
 if 70 - 70: I1IiiI
 if ( ooO0OOoO == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( IIi1iiIIi1i , auth_data ) )
  if 74 - 74: ooOoO0o * II111iiii
  if 96 - 96: i11iIiiIii . I1IiiI - II111iiii . I11i
 return ( ooO0OOoO )
 if 79 - 79: OoO0O00 . OoOoOO00 - i1IIi + Ii1I * i11iIiiIii . OoooooooOO
 if 83 - 83: o0oOOo0O0Ooo / oO0o
 if 24 - 24: Ii1I + oO0o / OoooooooOO % i11iIiiIii
 if 1 - 1: iII111i / I1Ii111 * I1IiiI + OoOoOO00 . OoooooooOO
 if 5 - 5: I1IiiI
 if 74 - 74: i1IIi * Oo0Ooo - OoOoOO00 * o0oOOo0O0Ooo
 if 85 - 85: iIii1I11I1II1 * IiII / i11iIiiIii - ooOoO0o - o0oOOo0O0Ooo
def lisp_retransmit_map_notify ( map_notify ) :
 oo0OoO = map_notify . etr
 Oo0O00O = map_notify . etr_port
 if 30 - 30: OoOoOO00 - OOooOOo . Oo0Ooo
 if 11 - 11: IiII - I1Ii111 - OoO0O00 * o0oOOo0O0Ooo
 if 99 - 99: O0 - OoO0O00
 if 95 - 95: Ii1I . IiII * o0oOOo0O0Ooo
 if 91 - 91: I1Ii111
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( oo0OoO . print_address ( ) , False ) ) )
  if 49 - 49: I11i
  if 17 - 17: Oo0Ooo % o0oOOo0O0Ooo
  Oo000O000 = map_notify . nonce_key
  if ( lisp_map_notify_queue . has_key ( Oo000O000 ) ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( Oo000O000 ) )
   if 3 - 3: OoO0O00 . oO0o . oO0o . Ii1I
   try :
    lisp_map_notify_queue . pop ( Oo000O000 )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
    if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
  return
  if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
  if 10 - 10: ooOoO0o
 oOo0oo0 = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 69 - 69: I11i + I1IiiI / oO0o
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # OOooOOo + i11iIiiIii / I1ii11iIi11i + i1IIi * I1Ii111 - oO0o
 red ( oo0OoO . print_address ( ) , False ) , map_notify . retry_count ) )
 if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
 lisp_send_map_notify ( oOo0oo0 , map_notify . packet , oo0OoO , Oo0O00O )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 96 - 96: oO0o
 if 44 - 44: OoooooooOO / iII111i * Oo0Ooo % OoOoOO00 . oO0o
 if 97 - 97: iIii1I11I1II1 / ooOoO0o
 if 16 - 16: Oo0Ooo % IiII
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 48 - 48: I1IiiI . I1Ii111 . o0oOOo0O0Ooo
 if 72 - 72: Ii1I * OoO0O00 / OoO0O00
 if 39 - 39: oO0o
 if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
 if 57 - 57: oO0o + O0 - OoOoOO00
 if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
 if 93 - 93: o0oOOo0O0Ooo + i1IIi
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 24 - 24: i1IIi
 if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
 if 99 - 99: Oo0Ooo
 if 38 - 38: I1ii11iIi11i - I1IiiI
 eid_record . rloc_count = len ( parent . registered_rlocs )
 I1IIIIiIii = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 83 - 83: Oo0Ooo / I1ii11iIi11i % OoO0O00
 if 29 - 29: IiII - I1ii11iIi11i . Oo0Ooo + IiII - I1IiiI
 if 95 - 95: O0 / o0oOOo0O0Ooo + OoO0O00 / IiII - IiII % OOooOOo
 if 16 - 16: I1IiiI * iIii1I11I1II1 % o0oOOo0O0Ooo - IiII - OOooOOo
 for ooo0O0O0oOO in parent . registered_rlocs :
  I1i11 = lisp_rloc_record ( )
  I1i11 . store_rloc_entry ( ooo0O0O0oOO )
  I1IIIIiIii += I1i11 . encode ( )
  I1i11 . print_record ( "  " )
  del ( I1i11 )
  if 68 - 68: IiII * O0 % OOooOOo
  if 26 - 26: ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
  if 26 - 26: I1IiiI - OOooOOo
  if 34 - 34: I1Ii111 % I1IiiI . OoOoOO00 / iII111i + ooOoO0o . i11iIiiIii
  if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
 for ooo0O0O0oOO in parent . registered_rlocs :
  oo0OoO = ooo0O0O0oOO . rloc
  iiiiIi1111ii1 = lisp_map_notify ( lisp_sockets )
  iiiiIi1111ii1 . record_count = 1
  I1I1I1 = map_register . key_id
  iiiiIi1111ii1 . key_id = I1I1I1
  iiiiIi1111ii1 . alg_id = map_register . alg_id
  iiiiIi1111ii1 . auth_len = map_register . auth_len
  iiiiIi1111ii1 . nonce = map_register . nonce
  iiiiIi1111ii1 . nonce_key = lisp_hex_string ( iiiiIi1111ii1 . nonce )
  iiiiIi1111ii1 . etr . copy_address ( oo0OoO )
  iiiiIi1111ii1 . etr_port = map_register . sport
  iiiiIi1111ii1 . site = parent . site
  IiiiIi1iiii11 = iiiiIi1111ii1 . encode ( I1IIIIiIii , parent . site . auth_key [ I1I1I1 ] )
  iiiiIi1111ii1 . print_notify ( )
  if 10 - 10: i1IIi / i1IIi * iIii1I11I1II1 * OoOoOO00 * oO0o / II111iiii
  if 23 - 23: I11i . OoOoOO00 + I1Ii111 + oO0o + II111iiii
  if 71 - 71: OoOoOO00 * OoOoOO00
  if 27 - 27: II111iiii + OoooooooOO - I11i * o0oOOo0O0Ooo
  Oo000O000 = iiiiIi1111ii1 . nonce_key
  if ( lisp_map_notify_queue . has_key ( Oo000O000 ) ) :
   ooO0OooO = lisp_map_notify_queue [ Oo000O000 ]
   ooO0OooO . retransmit_timer . cancel ( )
   del ( ooO0OooO )
   if 56 - 56: o0oOOo0O0Ooo / I1ii11iIi11i
  lisp_map_notify_queue [ Oo000O000 ] = iiiiIi1111ii1
  if 25 - 25: iIii1I11I1II1 / OoO0O00 - o0oOOo0O0Ooo
  if 97 - 97: ooOoO0o % OoooooooOO * o0oOOo0O0Ooo
  if 8 - 8: I1ii11iIi11i + Oo0Ooo - iII111i
  if 53 - 53: ooOoO0o / IiII
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( oo0OoO . print_address ( ) , False ) ) )
  if 36 - 36: iIii1I11I1II1
  lisp_send ( lisp_sockets , oo0OoO , LISP_CTRL_PORT , IiiiIi1iiii11 )
  if 78 - 78: II111iiii * I11i
  parent . site . map_notifies_sent += 1
  if 47 - 47: Ii1I
  if 42 - 42: I11i . oO0o - I1IiiI / OoO0O00
  if 75 - 75: I1IiiI / OoOoOO00 . I11i * iIii1I11I1II1
  if 53 - 53: iIii1I11I1II1
  iiiiIi1111ii1 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ iiiiIi1111ii1 ] )
  iiiiIi1111ii1 . retransmit_timer . start ( )
  if 8 - 8: O0 - O0 - II111iiii
 return
 if 77 - 77: i1IIi - ooOoO0o + O0 . OoO0O00 * I1Ii111 - I11i
 if 64 - 64: i1IIi + OoooooooOO + OOooOOo / ooOoO0o % I1IiiI . OoooooooOO
 if 96 - 96: II111iiii - OoOoOO00 + oO0o
 if 80 - 80: oO0o / OoOoOO00 - I11i / oO0o - iII111i - OoooooooOO
 if 57 - 57: o0oOOo0O0Ooo
 if 37 - 37: iII111i * o0oOOo0O0Ooo
 if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
 Oo000O000 = lisp_hex_string ( nonce ) + source . print_address ( )
 if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
 if 34 - 34: O0 * oO0o
 if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
 if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
 if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
 if 88 - 88: i11iIiiIii
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( lisp_map_notify_queue . has_key ( Oo000O000 ) ) :
  iiiiIi1111ii1 = lisp_map_notify_queue [ Oo000O000 ]
  IiII1iiI = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( iiiiIi1111ii1 . nonce ) , IiII1iiI ) )
  if 13 - 13: I1IiiI
  return
  if 52 - 52: Ii1I * oO0o / I1Ii111 . IiII
  if 84 - 84: OoooooooOO - oO0o - I1Ii111
 iiiiIi1111ii1 = lisp_map_notify ( lisp_sockets )
 iiiiIi1111ii1 . record_count = record_count
 key_id = key_id
 iiiiIi1111ii1 . key_id = key_id
 iiiiIi1111ii1 . alg_id = alg_id
 iiiiIi1111ii1 . auth_len = auth_len
 iiiiIi1111ii1 . nonce = nonce
 iiiiIi1111ii1 . nonce_key = lisp_hex_string ( nonce )
 iiiiIi1111ii1 . etr . copy_address ( source )
 iiiiIi1111ii1 . etr_port = port
 iiiiIi1111ii1 . site = site
 iiiiIi1111ii1 . eid_list = eid_list
 if 69 - 69: OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
 if 20 - 20: IiII
 if 17 - 17: o0oOOo0O0Ooo % iIii1I11I1II1
 if 66 - 66: OoooooooOO + IiII . II111iiii
 if ( map_register_ack == False ) :
  Oo000O000 = iiiiIi1111ii1 . nonce_key
  lisp_map_notify_queue [ Oo000O000 ] = iiiiIi1111ii1
  if 66 - 66: iIii1I11I1II1 % I11i
  if 38 - 38: I1ii11iIi11i * ooOoO0o
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 77 - 77: OOooOOo - i11iIiiIii - I1ii11iIi11i
  if 94 - 94: OoO0O00 % iII111i - I1Ii111 + OoO0O00 - I1IiiI
  if 65 - 65: OOooOOo
  if 90 - 90: O0
  if 91 - 91: O0 * OoOoOO00 - OoOoOO00 * II111iiii - iII111i
 IiiiIi1iiii11 = iiiiIi1111ii1 . encode ( eid_records , site . auth_key [ key_id ] )
 iiiiIi1111ii1 . print_notify ( )
 if 38 - 38: oO0o * I11i % OOooOOo
 if ( map_register_ack == False ) :
  iI1I1I1I11I11 = lisp_eid_record ( )
  iI1I1I1I11I11 . decode ( eid_records )
  iI1I1I1I11I11 . print_record ( "  " , False )
  if 80 - 80: O0 % II111iiii / O0 . Oo0Ooo * OoOoOO00 + OOooOOo
  if 47 - 47: Ii1I - Oo0Ooo * OoOoOO00
  if 20 - 20: oO0o
  if 48 - 48: I1IiiI % OoO0O00
  if 33 - 33: Ii1I
 lisp_send_map_notify ( lisp_sockets , IiiiIi1iiii11 , iiiiIi1111ii1 . etr , port )
 site . map_notifies_sent += 1
 if 73 - 73: Ii1I . IiII
 if ( map_register_ack ) : return
 if 43 - 43: I11i . IiII - iII111i * I1IiiI * iII111i
 if 90 - 90: i11iIiiIii * i1IIi
 if 88 - 88: i11iIiiIii - OoOoOO00
 if 53 - 53: iIii1I11I1II1 % I1Ii111 / Oo0Ooo % Oo0Ooo
 if 6 - 6: iII111i
 if 44 - 44: oO0o
 iiiiIi1111ii1 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ iiiiIi1111ii1 ] )
 iiiiIi1111ii1 . retransmit_timer . start ( )
 return
 if 23 - 23: I1IiiI + iIii1I11I1II1 . iII111i + OOooOOo - OoO0O00 + i1IIi
 if 60 - 60: i11iIiiIii + Oo0Ooo * OoOoOO00 . iII111i - iIii1I11I1II1 * IiII
 if 52 - 52: OOooOOo
 if 50 - 50: OoOoOO00 % o0oOOo0O0Ooo - II111iiii - i1IIi
 if 35 - 35: Oo0Ooo - ooOoO0o % OoO0O00
 if 26 - 26: i1IIi * I1Ii111 * OoO0O00 - IiII
 if 26 - 26: Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
 if 66 - 66: I1IiiI
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 45 - 45: II111iiii * I1Ii111 - II111iiii / I1IiiI % oO0o
 if 83 - 83: oO0o % OoO0O00 + I1ii11iIi11i / OoooooooOO % iII111i
 if 22 - 22: I1Ii111
 if 41 - 41: O0 * i1IIi
 IiiiIi1iiii11 = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 89 - 89: iIii1I11I1II1 . I11i % I1ii11iIi11i + II111iiii . OoO0O00
 if 5 - 5: I1ii11iIi11i / I1IiiI . iII111i
 if 7 - 7: Ii1I
 if 62 - 62: I1ii11iIi11i + IiII . O0 - OoooooooOO * o0oOOo0O0Ooo % O0
 oo0OoO = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( oo0OoO . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , oo0OoO , LISP_CTRL_PORT , IiiiIi1iiii11 )
 return
 if 63 - 63: OOooOOo + iII111i - IiII - I1IiiI % IiII . OoO0O00
 if 73 - 73: OoOoOO00
 if 47 - 47: oO0o
 if 17 - 17: IiII
 if 47 - 47: I11i . I1IiiI % ooOoO0o . i11iIiiIii
 if 63 - 63: I1ii11iIi11i % I11i % OoooooooOO
 if 100 - 100: O0
 if 9 - 9: Ii1I
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 87 - 87: I1IiiI
 iiiiIi1111ii1 = lisp_map_notify ( lisp_sockets )
 iiiiIi1111ii1 . record_count = 1
 iiiiIi1111ii1 . nonce = lisp_get_control_nonce ( )
 iiiiIi1111ii1 . nonce_key = lisp_hex_string ( iiiiIi1111ii1 . nonce )
 iiiiIi1111ii1 . etr . copy_address ( xtr )
 iiiiIi1111ii1 . etr_port = LISP_CTRL_PORT
 iiiiIi1111ii1 . eid_list = eid_list
 Oo000O000 = iiiiIi1111ii1 . nonce_key
 if 56 - 56: OOooOOo % oO0o - OoOoOO00
 if 27 - 27: I1ii11iIi11i - IiII * OoooooooOO * I1ii11iIi11i + i11iIiiIii . IiII
 if 81 - 81: oO0o / iIii1I11I1II1
 if 15 - 15: Ii1I + I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
 if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
 if 28 - 28: ooOoO0o
 lisp_remove_eid_from_map_notify_queue ( iiiiIi1111ii1 . eid_list )
 if ( lisp_map_notify_queue . has_key ( Oo000O000 ) ) :
  iiiiIi1111ii1 = lisp_map_notify_queue [ Oo000O000 ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( iiiiIi1111ii1 . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 88 - 88: oO0o
  return
  if 77 - 77: ooOoO0o + I1Ii111 . OoOoOO00
  if 2 - 2: i1IIi - IiII + iIii1I11I1II1 % i1IIi * II111iiii
  if 26 - 26: I11i
  if 57 - 57: I1ii11iIi11i + I1Ii111 + i11iIiiIii . i1IIi / i11iIiiIii
  if 43 - 43: Ii1I % I11i
 lisp_map_notify_queue [ Oo000O000 ] = iiiiIi1111ii1
 if 5 - 5: OoooooooOO % i11iIiiIii * o0oOOo0O0Ooo * OoooooooOO - o0oOOo0O0Ooo % I11i
 if 58 - 58: i11iIiiIii % Ii1I + Oo0Ooo - OoOoOO00 - i11iIiiIii / O0
 if 36 - 36: OOooOOo
 if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
 Oooo0o0OOO0O0 = site_eid . rtrs_in_rloc_set ( )
 if ( Oooo0o0OOO0O0 ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : Oooo0o0OOO0O0 = False
  if 22 - 22: OoO0O00 / o0oOOo0O0Ooo - i11iIiiIii
  if 4 - 4: I1IiiI * o0oOOo0O0Ooo - I11i - OoooooooOO . OoooooooOO
  if 79 - 79: oO0o - iII111i
  if 34 - 34: OoooooooOO + Ii1I - iII111i + OoooooooOO / I1IiiI
  if 39 - 39: o0oOOo0O0Ooo . i1IIi * OoO0O00 / II111iiii / I1ii11iIi11i * OOooOOo
 iI1I1I1I11I11 = lisp_eid_record ( )
 iI1I1I1I11I11 . record_ttl = 1440
 iI1I1I1I11I11 . eid . copy_address ( site_eid . eid )
 iI1I1I1I11I11 . group . copy_address ( site_eid . group )
 iI1I1I1I11I11 . rloc_count = 0
 for oo0OOOoO0OoO in site_eid . registered_rlocs :
  if ( Oooo0o0OOO0O0 ^ oo0OOOoO0OoO . is_rtr ( ) ) : continue
  iI1I1I1I11I11 . rloc_count += 1
  if 39 - 39: O0 . OOooOOo
 IiiiIi1iiii11 = iI1I1I1I11I11 . encode ( )
 if 95 - 95: I11i
 if 58 - 58: I1ii11iIi11i / i11iIiiIii + iII111i + I11i / oO0o
 if 8 - 8: I1ii11iIi11i
 if 100 - 100: OoooooooOO / I11i - Ii1I
 iiiiIi1111ii1 . print_notify ( )
 iI1I1I1I11I11 . print_record ( "  " , False )
 if 11 - 11: OoO0O00
 if 20 - 20: Oo0Ooo
 if 34 - 34: I1Ii111 % i11iIiiIii / oO0o - i1IIi . o0oOOo0O0Ooo / oO0o
 if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
 for oo0OOOoO0OoO in site_eid . registered_rlocs :
  if ( Oooo0o0OOO0O0 ^ oo0OOOoO0OoO . is_rtr ( ) ) : continue
  I1i11 = lisp_rloc_record ( )
  I1i11 . store_rloc_entry ( oo0OOOoO0OoO )
  IiiiIi1iiii11 += I1i11 . encode ( )
  I1i11 . print_record ( "    " )
  if 1 - 1: I1ii11iIi11i
  if 18 - 18: i11iIiiIii % OoO0O00 % OOooOOo . OOooOOo * Ii1I / II111iiii
  if 81 - 81: iII111i % IiII / I11i
  if 50 - 50: IiII + i1IIi % I1Ii111
  if 72 - 72: I1Ii111
 IiiiIi1iiii11 = iiiiIi1111ii1 . encode ( IiiiIi1iiii11 , "" )
 if ( IiiiIi1iiii11 == None ) : return
 if 6 - 6: II111iiii - i1IIi
 if 78 - 78: OoOoOO00 - Oo0Ooo * II111iiii % iIii1I11I1II1 . i11iIiiIii % iII111i
 if 85 - 85: I1ii11iIi11i + OOooOOo % i1IIi
 if 13 - 13: OOooOOo + i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
 lisp_send_map_notify ( lisp_sockets , IiiiIi1iiii11 , xtr , LISP_CTRL_PORT )
 if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
 if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
 if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
 if 8 - 8: OoooooooOO * OOooOOo * iII111i - iII111i
 iiiiIi1111ii1 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ iiiiIi1111ii1 ] )
 iiiiIi1111ii1 . retransmit_timer . start ( )
 return
 if 32 - 32: I1Ii111
 if 28 - 28: I11i . i11iIiiIii % iIii1I11I1II1 + OoOoOO00
 if 4 - 4: OOooOOo + I1ii11iIi11i - iII111i + OOooOOo / IiII
 if 23 - 23: iIii1I11I1II1 + OoooooooOO + ooOoO0o . iII111i . Oo0Ooo - iIii1I11I1II1
 if 25 - 25: O0 + I1IiiI % OOooOOo / Oo0Ooo . IiII / I1Ii111
 if 84 - 84: ooOoO0o . O0 + I1IiiI * OoO0O00 - I1IiiI
 if 24 - 24: Ii1I
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 IIiiiiI1iIiiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 37 - 37: I1IiiI
 for oOOooo000OoO in rle_list :
  OO00o = lisp_site_eid_lookup ( oOOooo000OoO [ 0 ] , oOOooo000OoO [ 1 ] , True )
  if ( OO00o == None ) : continue
  if 26 - 26: IiII * I11i + ooOoO0o % Oo0Ooo
  if 75 - 75: o0oOOo0O0Ooo . I1Ii111 % i1IIi . i11iIiiIii
  if 38 - 38: o0oOOo0O0Ooo - OoO0O00 - i11iIiiIii
  if 60 - 60: i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i * iII111i . oO0o + iII111i
  if 29 - 29: Oo0Ooo
  if 16 - 16: oO0o
  if 52 - 52: I11i * I1IiiI % I11i - iII111i - Ii1I - OoooooooOO
  i11iii1IiIii = OO00o . registered_rlocs
  if ( len ( i11iii1IiIii ) == 0 ) :
   O0o000OooO = { }
   for IiI111II1I1iI in OO00o . individual_registrations . values ( ) :
    for oo0OOOoO0OoO in IiI111II1I1iI . registered_rlocs :
     if ( oo0OOOoO0OoO . is_rtr ( ) == False ) : continue
     O0o000OooO [ oo0OOOoO0OoO . rloc . print_address ( ) ] = oo0OOOoO0OoO
     if 14 - 14: O0 + ooOoO0o
     if 62 - 62: II111iiii * o0oOOo0O0Ooo . OoO0O00 / II111iiii
   i11iii1IiIii = O0o000OooO . values ( )
   if 5 - 5: OoO0O00 + O0 . OoooooooOO + I1IiiI + i1IIi * OOooOOo
   if 19 - 19: OoooooooOO + i11iIiiIii / II111iiii - Oo0Ooo . OOooOOo
   if 10 - 10: oO0o * Oo0Ooo
   if 55 - 55: OoO0O00 - i1IIi - I11i * oO0o
   if 91 - 91: I1Ii111
   if 77 - 77: I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + Ii1I % II111iiii * II111iiii
  IiIIi1I = [ ]
  oO00o00OoO = False
  if ( OO00o . eid . address == 0 and OO00o . eid . mask_len == 0 ) :
   IIiiII1iI1iI = [ ]
   i1II1i1i11I1i = [ ]
   if ( len ( i11iii1IiIii ) != 0 and i11iii1IiIii [ 0 ] . rle != None ) :
    i1II1i1i11I1i = i11iii1IiIii [ 0 ] . rle . rle_nodes
    if 86 - 86: IiII % I1IiiI * OoO0O00 . i11iIiiIii / OOooOOo
   for i1iiiIIi11 in i1II1i1i11I1i :
    IiIIi1I . append ( i1iiiIIi11 . address )
    IIiiII1iI1iI . append ( i1iiiIIi11 . address . print_address_no_iid ( ) )
    if 23 - 23: I1ii11iIi11i
   lprint ( "Notify existing RLE-nodes {}" . format ( IIiiII1iI1iI ) )
  else :
   if 53 - 53: I11i
   if 64 - 64: iIii1I11I1II1 + O0 % IiII
   if 13 - 13: i11iIiiIii
   if 49 - 49: OoOoOO00
   if 61 - 61: I1Ii111 / I1Ii111 / iII111i / ooOoO0o - I1IiiI . o0oOOo0O0Ooo
   for oo0OOOoO0OoO in i11iii1IiIii :
    if ( oo0OOOoO0OoO . is_rtr ( ) ) : IiIIi1I . append ( oo0OOOoO0OoO . rloc )
    if 80 - 80: I1IiiI - OOooOOo . oO0o
    if 75 - 75: oO0o + OoOoOO00 - OoooooooOO
    if 38 - 38: I11i / ooOoO0o / OoOoOO00 * OOooOOo . oO0o
    if 8 - 8: OoO0O00 . OOooOOo % I1Ii111 * OOooOOo / I1IiiI
    if 3 - 3: IiII - I1ii11iIi11i . o0oOOo0O0Ooo
   oO00o00OoO = ( len ( IiIIi1I ) != 0 )
   if ( oO00o00OoO == False ) :
    I1iiiI1I1 = lisp_site_eid_lookup ( oOOooo000OoO [ 0 ] , IIiiiiI1iIiiI , False )
    if ( I1iiiI1I1 == None ) : continue
    if 39 - 39: oO0o . I1Ii111 + oO0o % OoOoOO00 - i11iIiiIii
    for oo0OOOoO0OoO in I1iiiI1I1 . registered_rlocs :
     if ( oo0OOOoO0OoO . rloc . is_null ( ) ) : continue
     IiIIi1I . append ( oo0OOOoO0OoO . rloc )
     if 69 - 69: I11i / OoO0O00
     if 73 - 73: i11iIiiIii / i1IIi
     if 8 - 8: O0 / OOooOOo + iII111i % iIii1I11I1II1 % iIii1I11I1II1 . ooOoO0o
     if 47 - 47: OoO0O00 / o0oOOo0O0Ooo / Ii1I * I1IiiI % ooOoO0o / I1Ii111
     if 80 - 80: I1Ii111 / O0 * O0
     if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
   if ( len ( IiIIi1I ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( OO00o . print_eid_tuple ( ) , False ) ) )
    if 89 - 89: i11iIiiIii - II111iiii
    continue
    if 67 - 67: IiII % I1Ii111 + i11iIiiIii
    if 53 - 53: OOooOOo
    if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
    if 21 - 21: I1Ii111 . i1IIi - iII111i % I1ii11iIi11i . OOooOOo
    if 52 - 52: Ii1I * I1ii11iIi11i
    if 21 - 21: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo * II111iiii % iIii1I11I1II1
  for ooo0O0O0oOO in IiIIi1I :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if oO00o00OoO else "x" , red ( ooo0O0O0oOO . print_address_no_iid ( ) , False ) ,
   # II111iiii
 green ( OO00o . print_eid_tuple ( ) , False ) ) )
   if 42 - 42: OoooooooOO % OoO0O00 % i1IIi % i1IIi
   OoO0OOO0Oo0O = [ OO00o . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , OO00o , OoO0OOO0Oo0O , ooo0O0O0oOO )
   time . sleep ( .001 )
   if 4 - 4: OoOoOO00 / OoO0O00
   if 66 - 66: I1Ii111 / OoOoOO00
 return
 if 53 - 53: OoOoOO00 . i11iIiiIii - OoooooooOO
 if 92 - 92: O0 - i11iIiiIii + OoO0O00 - OoooooooOO - o0oOOo0O0Ooo
 if 25 - 25: oO0o / oO0o / Ii1I / O0
 if 56 - 56: ooOoO0o
 if 19 - 19: O0 * I1IiiI + I1ii11iIi11i
 if 25 - 25: I11i - ooOoO0o / OoO0O00 / iII111i - OoO0O00
 if 86 - 86: OoO0O00
 if 89 - 89: OoooooooOO % iII111i * I1ii11iIi11i + I1ii11iIi11i . Oo0Ooo
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for IiIIi1IiiIiI in range ( rloc_count ) :
  I1i11 = lisp_rloc_record ( )
  packet = I1i11 . decode ( packet , None )
  iii1iii11i = I1i11 . json
  if ( iii1iii11i == None ) : continue
  if 57 - 57: o0oOOo0O0Ooo . I1IiiI / iII111i / ooOoO0o - OoO0O00
  try :
   iii1iii11i = json . loads ( iii1iii11i . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 8 - 8: iIii1I11I1II1 % ooOoO0o + OoO0O00 . oO0o % I1IiiI - O0
   if 25 - 25: i11iIiiIii * OoOoOO00 + OoO0O00 . o0oOOo0O0Ooo
  if ( iii1iii11i . has_key ( "signature" ) == False ) : continue
  return ( I1i11 )
  if 65 - 65: I1Ii111 + i1IIi / iII111i % O0 + II111iiii * i1IIi
 return ( None )
 if 49 - 49: o0oOOo0O0Ooo + OOooOOo - II111iiii
 if 34 - 34: ooOoO0o . I1Ii111
 if 52 - 52: I1IiiI + I1Ii111 * oO0o / i11iIiiIii * iIii1I11I1II1
 if 27 - 27: Oo0Ooo
 if 85 - 85: iIii1I11I1II1 . o0oOOo0O0Ooo + oO0o
 if 79 - 79: O0 - iIii1I11I1II1 + i1IIi . I11i
 if 21 - 21: II111iiii
 if 23 - 23: I11i * i1IIi . oO0o / IiII + o0oOOo0O0Ooo
 if 1 - 1: IiII / OoO0O00 . oO0o * I1Ii111 - i11iIiiIii
 if 50 - 50: oO0o - O0 / I1IiiI . OoOoOO00 . Oo0Ooo
 if 30 - 30: IiII . OoO0O00 + Oo0Ooo
 if 48 - 48: iIii1I11I1II1 / i11iIiiIii . OoOoOO00 * I11i
 if 1 - 1: IiII . OoOoOO00 * o0oOOo0O0Ooo
 if 63 - 63: O0 / Ii1I + I1Ii111 % OoO0O00 % OOooOOo * O0
 if 35 - 35: OoO0O00 + OoooooooOO % Oo0Ooo / I11i - O0 . i1IIi
 if 76 - 76: IiII % I1IiiI * Ii1I / Ii1I / OoooooooOO + Ii1I
 if 19 - 19: OoooooooOO
 if 88 - 88: I1IiiI % ooOoO0o % Oo0Ooo - O0
 if 71 - 71: OOooOOo % Ii1I - i11iIiiIii - oO0o . ooOoO0o / I1Ii111
def lisp_get_eid_hash ( eid ) :
 o0O = None
 for OO0o0O0O0o0o in lisp_eid_hashes :
  if 17 - 17: iII111i / iII111i / I1ii11iIi11i - OoOoOO00 * I1IiiI
  if 39 - 39: OoOoOO00 % O0 * I1Ii111 - IiII + OoO0O00 * O0
  if 69 - 69: Ii1I
  if 29 - 29: OoOoOO00 + Oo0Ooo
  o0OoO0000o = OO0o0O0O0o0o . instance_id
  if ( o0OoO0000o == - 1 ) : OO0o0O0O0o0o . instance_id = eid . instance_id
  if 49 - 49: OOooOOo - iIii1I11I1II1 / ooOoO0o
  IIIIiI1 = eid . is_more_specific ( OO0o0O0O0o0o )
  OO0o0O0O0o0o . instance_id = o0OoO0000o
  if ( IIIIiI1 ) :
   o0O = 128 - OO0o0O0O0o0o . mask_len
   break
   if 81 - 81: oO0o
   if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
 if ( o0O == None ) : return ( None )
 if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
 ii1i1II11II1i = eid . address
 o0O0OOOO = ""
 for IiIIi1IiiIiI in range ( 0 , o0O / 16 ) :
  IiiIIi1 = ii1i1II11II1i & 0xffff
  IiiIIi1 = hex ( IiiIIi1 ) [ 2 : - 1 ]
  o0O0OOOO = IiiIIi1 . zfill ( 4 ) + ":" + o0O0OOOO
  ii1i1II11II1i >>= 16
  if 8 - 8: OOooOOo . i11iIiiIii / oO0o % OOooOOo - II111iiii % II111iiii
 if ( o0O % 16 != 0 ) :
  IiiIIi1 = ii1i1II11II1i & 0xff
  IiiIIi1 = hex ( IiiIIi1 ) [ 2 : - 1 ]
  o0O0OOOO = IiiIIi1 . zfill ( 2 ) + ":" + o0O0OOOO
  if 46 - 46: II111iiii + OoOoOO00 % OoO0O00
 return ( o0O0OOOO [ 0 : - 1 ] )
 if 7 - 7: oO0o + II111iiii - O0
 if 32 - 32: oO0o
 if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
 if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
 if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
 if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
 if 94 - 94: Ii1I
 if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
 if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
 if 34 - 34: iIii1I11I1II1
def lisp_lookup_public_key ( eid ) :
 o0OoO0000o = eid . instance_id
 if 47 - 47: OOooOOo * iII111i
 if 71 - 71: IiII - OoooooooOO * i11iIiiIii . OoooooooOO % i1IIi . Oo0Ooo
 if 3 - 3: OoO0O00 + i11iIiiIii + oO0o * IiII
 if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
 if 70 - 70: OoO0O00
 IiI11I11i = lisp_get_eid_hash ( eid )
 if ( IiI11I11i == None ) : return ( [ None , None , False ] )
 if 83 - 83: I1IiiI * O0 . II111iiii
 IiI11I11i = "hash-" + IiI11I11i
 i11 = lisp_address ( LISP_AFI_NAME , IiI11I11i , len ( IiI11I11i ) , o0OoO0000o )
 IIi1iiIII11 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 if 80 - 80: O0 * I11i * I1Ii111
 if 89 - 89: Ii1I * OoO0O00 . i1IIi . O0 - IiII - OoOoOO00
 if 25 - 25: iII111i + i1IIi
 if 64 - 64: IiII % I11i / iIii1I11I1II1
 I1iiiI1I1 = lisp_site_eid_lookup ( i11 , IIi1iiIII11 , True )
 if ( I1iiiI1I1 == None ) : return ( [ i11 , None , False ] )
 if 66 - 66: Ii1I
 if 55 - 55: OOooOOo + I1IiiI + IiII . Ii1I * oO0o
 if 71 - 71: IiII - iII111i % I1IiiI * iII111i
 if 27 - 27: ooOoO0o - OoO0O00
 I11I111 = None
 for oOO in I1iiiI1I1 . registered_rlocs :
  O0OO0o000o00 = oOO . json
  if ( O0OO0o000o00 == None ) : continue
  try :
   O0OO0o000o00 = json . loads ( O0OO0o000o00 . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( IiI11I11i ) )
   if 85 - 85: Ii1I % OoOoOO00
   return ( [ i11 , None , False ] )
   if 28 - 28: IiII
  if ( O0OO0o000o00 . has_key ( "public-key" ) == False ) : continue
  I11I111 = O0OO0o000o00 [ "public-key" ]
  break
  if 32 - 32: IiII * II111iiii . Ii1I
 return ( [ i11 , I11I111 , True ] )
 if 68 - 68: I11i / O0
 if 6 - 6: oO0o - oO0o . I1IiiI % I1ii11iIi11i
 if 22 - 22: Ii1I / I1IiiI / II111iiii
 if 31 - 31: II111iiii - Ii1I * OOooOOo - i11iIiiIii / OoooooooOO - I1Ii111
 if 76 - 76: Oo0Ooo
 if 93 - 93: i1IIi - I1IiiI * i11iIiiIii / Ii1I . Ii1I - i1IIi
 if 19 - 19: iIii1I11I1II1 * OOooOOo * Oo0Ooo % I1IiiI
 if 93 - 93: IiII % OoOoOO00 / I1IiiI + o0oOOo0O0Ooo * ooOoO0o / i1IIi
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 25 - 25: O0 / Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo
 if 45 - 45: Ii1I * IiII - OOooOOo
 if 57 - 57: iII111i % OoO0O00 / OoooooooOO
 if 69 - 69: oO0o
 if 44 - 44: IiII - II111iiii % Ii1I
 O0OO0OoO00oOo = json . loads ( rloc_record . json . json_string )
 if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
 if ( lisp_get_eid_hash ( eid ) ) :
  Oo0o0ooOo0 = eid
 elif ( O0OO0OoO00oOo . has_key ( "signature-eid" ) ) :
  o0OOOo0OooO0O = O0OO0OoO00oOo [ "signature-eid" ]
  Oo0o0ooOo0 = lisp_address ( LISP_AFI_IPV6 , o0OOOo0OooO0O , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 13 - 13: I1ii11iIi11i % i11iIiiIii
  if 47 - 47: oO0o - iII111i
  if 92 - 92: OoooooooOO * OoooooooOO
  if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
  if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
 i11 , I11I111 , OOoO0 = lisp_lookup_public_key ( Oo0o0ooOo0 )
 if ( i11 == None ) :
  I11i11i1 = green ( Oo0o0ooOo0 . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( I11i11i1 ) )
  return ( False )
  if 78 - 78: II111iiii - i11iIiiIii . OOooOOo
  if 22 - 22: Oo0Ooo + ooOoO0o
 O00o0 = "found" if OOoO0 else bold ( "not found" , False )
 I11i11i1 = green ( i11 . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( I11i11i1 , O00o0 ) )
 if ( OOoO0 == False ) : return ( False )
 if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
 if ( I11I111 == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
  if 26 - 26: Oo0Ooo . Ii1I
 iIIIIiiii = I11I111 [ 0 : 8 ] + "..." + I11I111 [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( iIIIIiiii ) )
 if 17 - 17: II111iiii - I1Ii111 - i11iIiiIii - iIii1I11I1II1
 if 10 - 10: I1IiiI
 if 40 - 40: OoO0O00 * oO0o / OoOoOO00
 if 37 - 37: iII111i * oO0o / I1IiiI * I1ii11iIi11i
 if 73 - 73: oO0o + O0
 O0OO00OO0oo = O0OO0OoO00oOo [ "signature" ]
 if 5 - 5: I1IiiI
 try :
  O0OO0OoO00oOo = binascii . a2b_base64 ( O0OO00OO0oo )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 22 - 22: II111iiii / iII111i
  if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
 OoOOOo0o0oo = len ( O0OO0OoO00oOo )
 if ( OoOOOo0o0oo & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( OoOOOo0o0oo ) )
  return ( False )
  if 81 - 81: iII111i . Oo0Ooo / i1IIi / i11iIiiIii
  if 77 - 77: I1Ii111
  if 92 - 92: iII111i * i11iIiiIii * o0oOOo0O0Ooo * OoO0O00
  if 70 - 70: Ii1I
  if 51 - 51: i1IIi % Oo0Ooo
 IIIiiI1I = Oo0o0ooOo0 . print_address ( )
 if 32 - 32: OoOoOO00 + iIii1I11I1II1 . OoO0O00 . I1ii11iIi11i . IiII
 if 97 - 97: ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + iII111i + OoOoOO00
 if 8 - 8: Oo0Ooo . oO0o + II111iiii
 if 100 - 100: OoOoOO00 . IiII / OoO0O00 * OoooooooOO - OoOoOO00
 I11I111 = binascii . a2b_base64 ( I11I111 )
 try :
  Oo000O000 = ecdsa . VerifyingKey . from_pem ( I11I111 )
 except :
  oOOOO = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( oOOOO ) )
  return ( False )
  if 70 - 70: i1IIi % Oo0Ooo % I1Ii111 + I11i . ooOoO0o
  if 66 - 66: i11iIiiIii % I11i / Oo0Ooo * oO0o
  if 7 - 7: O0 - Ii1I - oO0o
  if 95 - 95: i1IIi - OOooOOo / OoOoOO00 + I1ii11iIi11i + O0
  if 10 - 10: ooOoO0o - OOooOOo + i1IIi * Ii1I
  if 78 - 78: iIii1I11I1II1
  if 76 - 76: ooOoO0o - i11iIiiIii * I11i / I1IiiI - OOooOOo
  if 41 - 41: iII111i
  if 91 - 91: I1Ii111
  if 54 - 54: o0oOOo0O0Ooo . i1IIi / iII111i
  if 21 - 21: O0 + ooOoO0o
 try :
  OO = Oo000O000 . verify ( O0OO0OoO00oOo , IIIiiI1I , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( IIIiiI1I ) )
  if 53 - 53: Ii1I - II111iiii * iIii1I11I1II1
  lprint ( "  Signature used '{}'" . format ( O0OO00OO0oo ) )
  return ( False )
  if 91 - 91: OoOoOO00 % iIii1I11I1II1
 return ( OO )
 if 81 - 81: i11iIiiIii / OoOoOO00 + iIii1I11I1II1
 if 65 - 65: o0oOOo0O0Ooo
 if 73 - 73: I11i . I1ii11iIi11i - OoO0O00 + OoooooooOO
 if 71 - 71: I1IiiI
 if 27 - 27: OoO0O00 + i1IIi * OoooooooOO * iIii1I11I1II1 - Ii1I
 if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
 if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
 if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
 if 33 - 33: oO0o . oO0o / IiII + II111iiii
 if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
 if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
 if 25 - 25: OoO0O00
 if 83 - 83: II111iiii . iIii1I11I1II1
 if 77 - 77: O0 . OoOoOO00 % oO0o / OOooOOo
 i1i1Ii11 = [ ]
 for ooOOooO in eid_list :
  for ooO0oO0o0oo0 in lisp_map_notify_queue :
   iiiiIi1111ii1 = lisp_map_notify_queue [ ooO0oO0o0oo0 ]
   if ( ooOOooO not in iiiiIi1111ii1 . eid_list ) : continue
   if 98 - 98: OoooooooOO - i11iIiiIii - iII111i + Ii1I - I1IiiI
   i1i1Ii11 . append ( ooO0oO0o0oo0 )
   ooOo0OO0O0 = iiiiIi1111ii1 . retransmit_timer
   if ( ooOo0OO0O0 ) : ooOo0OO0O0 . cancel ( )
   if 24 - 24: OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - o0oOOo0O0Ooo . I1ii11iIi11i
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( iiiiIi1111ii1 . nonce_key , green ( ooOOooO , False ) ) )
   if 2 - 2: I1IiiI . o0oOOo0O0Ooo / Oo0Ooo - OoOoOO00 - OoooooooOO
   if 73 - 73: I1Ii111 . i11iIiiIii * ooOoO0o . IiII - I11i + I1Ii111
   if 21 - 21: I1Ii111 + iIii1I11I1II1 + I1IiiI / O0 * I1ii11iIi11i
   if 57 - 57: OOooOOo * I11i . oO0o
   if 17 - 17: iII111i - OOooOOo * I1IiiI + i1IIi % I1ii11iIi11i
   if 71 - 71: Ii1I - o0oOOo0O0Ooo - oO0o
   if 27 - 27: O0 - iIii1I11I1II1
 for ooO0oO0o0oo0 in i1i1Ii11 : lisp_map_notify_queue . pop ( ooO0oO0o0oo0 )
 return
 if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
 if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
 if 97 - 97: i11iIiiIii + I1ii11iIi11i - I11i . oO0o
 if 76 - 76: IiII * II111iiii * I1ii11iIi11i + OoooooooOO - OoOoOO00 . Ii1I
 if 51 - 51: II111iiii % I1Ii111 * O0 . ooOoO0o * OoOoOO00
 if 17 - 17: I1IiiI % I11i
 if 28 - 28: I1ii11iIi11i * OoooooooOO
 if 19 - 19: Oo0Ooo - iII111i % OoOoOO00 * i11iIiiIii / oO0o . i11iIiiIii
def lisp_decrypt_map_register ( packet ) :
 if 46 - 46: I1ii11iIi11i
 if 50 - 50: OOooOOo * OoO0O00 * OOooOOo % I1IiiI - I1Ii111 * Ii1I
 if 88 - 88: OOooOOo . iII111i / I11i
 if 1 - 1: iIii1I11I1II1 - Oo0Ooo % OoooooooOO
 if 71 - 71: OOooOOo - Ii1I
 O0ooOoO0 = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 oOOo0Oo00o00O = ( O0ooOoO0 >> 13 ) & 0x1
 if ( oOOo0Oo00o00O == 0 ) : return ( packet )
 if 49 - 49: II111iiii
 i111Ii = ( O0ooOoO0 >> 14 ) & 0x7
 if 14 - 14: oO0o . OOooOOo * OOooOOo . OoO0O00
 if 27 - 27: OOooOOo - iII111i - IiII
 if 14 - 14: i11iIiiIii . I1ii11iIi11i % OoOoOO00 * Ii1I / OoO0O00
 if 56 - 56: o0oOOo0O0Ooo / I1IiiI + I11i + I1IiiI
 try :
  iIIi1oOoO0OoooOoOO = lisp_ms_encryption_keys [ i111Ii ]
  iIIi1oOoO0OoooOoOO = iIIi1oOoO0OoooOoOO . zfill ( 32 )
  iiI1iiIiiiI1I = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( i111Ii ) )
  return ( None )
  if 25 - 25: I1IiiI - I1ii11iIi11i
  if 64 - 64: OoOoOO00 / iIii1I11I1II1 / Oo0Ooo % I11i / OoooooooOO / i11iIiiIii
 OooOOOoOoo0O0 = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( OooOOOoOoo0O0 , i111Ii ) )
 if 61 - 61: O0 . Oo0Ooo . iIii1I11I1II1
 iiii1Ii1iii = chacha . ChaCha ( iIIi1oOoO0OoooOoOO , iiI1iiIiiiI1I ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + iiii1Ii1iii )
 if 54 - 54: OOooOOo * I1ii11iIi11i + OoooooooOO
 if 58 - 58: i1IIi - OoooooooOO * OOooOOo . ooOoO0o + O0 + o0oOOo0O0Ooo
 if 87 - 87: OOooOOo + I1Ii111 + O0 / oO0o / i11iIiiIii
 if 60 - 60: O0 . II111iiii
 if 69 - 69: II111iiii / ooOoO0o - OoOoOO00 / OOooOOo
 if 52 - 52: OoO0O00 % I11i + o0oOOo0O0Ooo % OoOoOO00
 if 46 - 46: o0oOOo0O0Ooo % O0
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 30 - 30: oO0o
 if 64 - 64: O0
 if 70 - 70: oO0o % I1IiiI . iIii1I11I1II1 - Oo0Ooo + OoOoOO00 % O0
 if 91 - 91: I1Ii111 - oO0o * ooOoO0o - I1ii11iIi11i + IiII + O0
 if 18 - 18: OoOoOO00 / IiII / o0oOOo0O0Ooo . OOooOOo
 if 35 - 35: I11i . ooOoO0o % I11i / iII111i / O0 % I11i
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 29 - 29: I1Ii111 + Ii1I
 O0o0oo0 = lisp_map_register ( )
 OoO , packet = O0o0oo0 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 21 - 21: i1IIi . oO0o + ooOoO0o
 O0o0oo0 . sport = sport
 if 13 - 13: Oo0Ooo . IiII % iII111i + i1IIi / OOooOOo
 O0o0oo0 . print_map_register ( )
 if 1 - 1: I11i * i1IIi * Oo0Ooo % O0
 if 41 - 41: OOooOOo % OoOoOO00
 if 82 - 82: I11i . IiII
 if 27 - 27: I1Ii111 % O0 * OoooooooOO . Oo0Ooo
 o0oOOO000O = True
 if ( O0o0oo0 . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  o0oOOO000O = True
  if 66 - 66: OoooooooOO
 if ( O0o0oo0 . alg_id == LISP_SHA_256_128_ALG_ID ) :
  o0oOOO000O = False
  if 4 - 4: Oo0Ooo % iII111i
  if 24 - 24: ooOoO0o * oO0o * Oo0Ooo . oO0o - OoOoOO00
  if 85 - 85: II111iiii
  if 51 - 51: Oo0Ooo
  if 57 - 57: i1IIi * ooOoO0o + o0oOOo0O0Ooo + O0 - I1ii11iIi11i % IiII
 O0Oo0o000oO0oOo0oo = [ ]
 if 89 - 89: iII111i . OoO0O00 . iII111i
 if 35 - 35: oO0o - ooOoO0o
 if 4 - 4: Oo0Ooo - IiII - I11i
 if 72 - 72: OoooooooOO
 iIO00O00o0Oo00 = None
 Oo0ooO000o0ooo = packet
 iiii11iii = [ ]
 o0ooO00 = O0o0oo0 . record_count
 for IiIIi1IiiIiI in range ( o0ooO00 ) :
  iI1I1I1I11I11 = lisp_eid_record ( )
  I1i11 = lisp_rloc_record ( )
  packet = iI1I1I1I11I11 . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 45 - 45: OOooOOo / OOooOOo . oO0o / I1ii11iIi11i * i1IIi % i1IIi
  iI1I1I1I11I11 . print_record ( "  " , False )
  if 17 - 17: oO0o + OoOoOO00
  if 42 - 42: OOooOOo * I11i / II111iiii % IiII
  if 54 - 54: IiII * I1Ii111 + O0 / I1ii11iIi11i / OoOoOO00 . I1ii11iIi11i
  if 40 - 40: O0 / OoooooooOO + ooOoO0o . iII111i + O0 . I11i
  I1iiiI1I1 = lisp_site_eid_lookup ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group ,
 False )
  if 92 - 92: iIii1I11I1II1 / I1IiiI
  OOOO00o = I1iiiI1I1 . print_eid_tuple ( ) if I1iiiI1I1 else None
  if 51 - 51: OoO0O00
  if 60 - 60: ooOoO0o
  if 95 - 95: I11i / o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
  if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
  if 8 - 8: OoooooooOO * ooOoO0o
  if 26 - 26: i11iIiiIii + oO0o - i1IIi
  if 71 - 71: I1IiiI % I1Ii111 / oO0o % oO0o / iIii1I11I1II1 + I1Ii111
  if ( I1iiiI1I1 and I1iiiI1I1 . accept_more_specifics == False ) :
   if ( I1iiiI1I1 . eid_record_matches ( iI1I1I1I11I11 ) == False ) :
    O00oOO0OO00 = I1iiiI1I1 . parent_for_more_specifics
    if ( O00oOO0OO00 ) : I1iiiI1I1 = O00oOO0OO00
    if 61 - 61: I1ii11iIi11i % I1IiiI % OoOoOO00
    if 58 - 58: OOooOOo
    if 19 - 19: i1IIi + OOooOOo % OoOoOO00 . IiII - O0
    if 44 - 44: II111iiii - II111iiii % Ii1I % oO0o / II111iiii
    if 25 - 25: IiII - oO0o . Oo0Ooo
    if 14 - 14: I1Ii111 + i11iIiiIii * iII111i / Oo0Ooo % OOooOOo % II111iiii
    if 63 - 63: O0 % Oo0Ooo % OoooooooOO % O0 / OoO0O00
    if 41 - 41: i11iIiiIii - I1ii11iIi11i - II111iiii
  iIiIi1o0oo = ( I1iiiI1I1 and I1iiiI1I1 . accept_more_specifics )
  if ( iIiIi1o0oo ) :
   OOooO = lisp_site_eid ( I1iiiI1I1 . site )
   OOooO . dynamic = True
   OOooO . eid . copy_address ( iI1I1I1I11I11 . eid )
   OOooO . group . copy_address ( iI1I1I1I11I11 . group )
   OOooO . parent_for_more_specifics = I1iiiI1I1
   OOooO . add_cache ( )
   OOooO . inherit_from_ams_parent ( )
   I1iiiI1I1 . more_specific_registrations . append ( OOooO )
   I1iiiI1I1 = OOooO
  else :
   I1iiiI1I1 = lisp_site_eid_lookup ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group ,
 True )
   if 90 - 90: OoOoOO00 % IiII + OoooooooOO % oO0o . I1IiiI
   if 85 - 85: I1Ii111 / IiII - Oo0Ooo
  I11i11i1 = iI1I1I1I11I11 . print_eid_tuple ( )
  if 73 - 73: OoooooooOO % OoooooooOO * OoO0O00 * II111iiii - O0 - OoO0O00
  if ( I1iiiI1I1 == None ) :
   IiIii11 = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( IiIii11 , green ( I11i11i1 , False ) ,
 ", matched non-ams {}" . format ( green ( OOOO00o , False ) if OOOO00o else "" ) ) )
   if 63 - 63: o0oOOo0O0Ooo / IiII - i11iIiiIii
   if 99 - 99: O0 + O0 . iIii1I11I1II1 . ooOoO0o * o0oOOo0O0Ooo
   if 1 - 1: I1Ii111 - I11i . OoOoOO00
   if 72 - 72: II111iiii . O0 . I11i * OoO0O00
   if 70 - 70: iII111i % OoooooooOO * I1ii11iIi11i . I11i / OoO0O00
   packet = I1i11 . end_of_rlocs ( packet , iI1I1I1I11I11 . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 6 - 6: O0 . i11iIiiIii
   continue
   if 85 - 85: i11iIiiIii / Ii1I + Oo0Ooo / OoOoOO00 - I1IiiI
   if 39 - 39: OoO0O00
  iIO00O00o0Oo00 = I1iiiI1I1 . site
  if 97 - 97: iIii1I11I1II1 . I1IiiI - O0
  if ( iIiIi1o0oo ) :
   oOo = I1iiiI1I1 . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( oOo , False ) , iIO00O00o0Oo00 . site_name , green ( I11i11i1 , False ) ) )
   if 41 - 41: I11i . OoOoOO00 * O0 % Ii1I
  else :
   oOo = green ( I1iiiI1I1 . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( oOo , iIO00O00o0Oo00 . site_name , green ( I11i11i1 , False ) ) )
   if 54 - 54: ooOoO0o
   if 13 - 13: I11i
   if 18 - 18: II111iiii * oO0o % i11iIiiIii / IiII . ooOoO0o
   if 2 - 2: OoOoOO00 % I1Ii111
   if 35 - 35: OOooOOo
   if 50 - 50: iIii1I11I1II1 . I1IiiI + i11iIiiIii
  if ( iIO00O00o0Oo00 . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( iIO00O00o0Oo00 . site_name ) )
   packet = I1i11 . end_of_rlocs ( packet , iI1I1I1I11I11 . rloc_count )
   continue
   if 65 - 65: I11i % I1IiiI
   if 3 - 3: i11iIiiIii % OOooOOo - Ii1I . i1IIi
   if 24 - 24: OOooOOo
   if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
   if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
   if 59 - 59: oO0o * OoO0O00 - I11i * I1IiiI
   if 60 - 60: iII111i - OoooooooOO / iII111i % OoO0O00 . OoOoOO00 - o0oOOo0O0Ooo
   if 71 - 71: iII111i * o0oOOo0O0Ooo * i11iIiiIii * O0
  I1I1I1 = O0o0oo0 . key_id
  if ( iIO00O00o0Oo00 . auth_key . has_key ( I1I1I1 ) ) :
   O0O0o0OOOO = iIO00O00o0Oo00 . auth_key [ I1I1I1 ]
  else :
   O0O0o0OOOO = ""
   if 46 - 46: i11iIiiIii . iIii1I11I1II1 % o0oOOo0O0Ooo * Ii1I
   if 64 - 64: OOooOOo
  o0OoO00O0Oo = lisp_verify_auth ( OoO , O0o0oo0 . alg_id ,
 O0o0oo0 . auth_data , O0O0o0OOOO )
  II111I1I1I11I = "dynamic " if I1iiiI1I1 . dynamic else ""
  if 12 - 12: ooOoO0o
  O0o = bold ( "passed" if o0OoO00O0Oo else "failed" , False )
  I1I1I1 = "key-id {}" . format ( I1I1I1 ) if I1I1I1 == O0o0oo0 . key_id else "bad key-id {}" . format ( O0o0oo0 . key_id )
  if 56 - 56: i1IIi
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( O0o , II111I1I1I11I , green ( I11i11i1 , False ) , I1I1I1 ) )
  if 3 - 3: OOooOOo - Oo0Ooo * Ii1I + i11iIiiIii
  if 53 - 53: i1IIi % I1ii11iIi11i
  if 65 - 65: I11i + OoOoOO00 - i11iIiiIii
  if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
  if 61 - 61: oO0o . i11iIiiIii / Ii1I % iII111i
  if 36 - 36: OoO0O00 + Ii1I / I11i - iII111i % OoO0O00 / Oo0Ooo
  I1I1IiiIi = True
  ooOooo0Oo000 = ( lisp_get_eid_hash ( iI1I1I1I11I11 . eid ) != None )
  if ( ooOooo0Oo000 or I1iiiI1I1 . require_signature ) :
   oo00o = "Required " if I1iiiI1I1 . require_signature else ""
   I11i11i1 = green ( I11i11i1 , False )
   oOO = lisp_find_sig_in_rloc_set ( packet , iI1I1I1I11I11 . rloc_count )
   if ( oOO == None ) :
    I1I1IiiIi = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( oo00o ,
    # oO0o + OoooooooOO
 bold ( "failed" , False ) , I11i11i1 ) )
   else :
    I1I1IiiIi = lisp_verify_cga_sig ( iI1I1I1I11I11 . eid , oOO )
    O0o = bold ( "passed" if I1I1IiiIi else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( oo00o , O0o , I11i11i1 ) )
    if 88 - 88: oO0o + OOooOOo
    if 14 - 14: I11i / i1IIi
    if 56 - 56: OoooooooOO
    if 59 - 59: I1ii11iIi11i + OoO0O00
  if ( o0OoO00O0Oo == False or I1I1IiiIi == False ) :
   packet = I1i11 . end_of_rlocs ( packet , iI1I1I1I11I11 . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 37 - 37: IiII * I1IiiI % O0
   continue
   if 32 - 32: ooOoO0o % II111iiii
   if 60 - 60: i11iIiiIii
   if 11 - 11: o0oOOo0O0Ooo
   if 77 - 77: o0oOOo0O0Ooo / iIii1I11I1II1 * iIii1I11I1II1 / o0oOOo0O0Ooo * iII111i
   if 26 - 26: Ii1I
   if 1 - 1: OoOoOO00 . o0oOOo0O0Ooo + Oo0Ooo % Oo0Ooo * I1ii11iIi11i
  if ( O0o0oo0 . merge_register_requested ) :
   O00oOO0OO00 = I1iiiI1I1
   O00oOO0OO00 . inconsistent_registration = False
   if 50 - 50: IiII / i1IIi . I1ii11iIi11i
   if 75 - 75: I11i * oO0o + OoooooooOO . iII111i + OoO0O00
   if 44 - 44: II111iiii
   if 65 - 65: I11i . iII111i . I1IiiI - Oo0Ooo % iIii1I11I1II1 / O0
   if 54 - 54: iII111i - I1Ii111
   if ( I1iiiI1I1 . group . is_null ( ) ) :
    if ( O00oOO0OO00 . site_id != O0o0oo0 . site_id ) :
     O00oOO0OO00 . site_id = O0o0oo0 . site_id
     O00oOO0OO00 . registered = False
     O00oOO0OO00 . individual_registrations = { }
     O00oOO0OO00 . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
     if 7 - 7: i1IIi
     if 30 - 30: oO0o . i1IIi / I11i
   Oo000O000 = source . address + O0o0oo0 . xtr_id
   if ( I1iiiI1I1 . individual_registrations . has_key ( Oo000O000 ) ) :
    I1iiiI1I1 = I1iiiI1I1 . individual_registrations [ Oo000O000 ]
   else :
    I1iiiI1I1 = lisp_site_eid ( iIO00O00o0Oo00 )
    I1iiiI1I1 . eid . copy_address ( O00oOO0OO00 . eid )
    I1iiiI1I1 . group . copy_address ( O00oOO0OO00 . group )
    O00oOO0OO00 . individual_registrations [ Oo000O000 ] = I1iiiI1I1
    if 23 - 23: i1IIi + oO0o % iII111i - OoO0O00 - i1IIi
  else :
   I1iiiI1I1 . inconsistent_registration = I1iiiI1I1 . merge_register_requested
   if 74 - 74: Ii1I + I11i . OoooooooOO - I1ii11iIi11i
   if 2 - 2: oO0o - o0oOOo0O0Ooo
   if 80 - 80: i1IIi
  I1iiiI1I1 . map_registers_received += 1
  if 40 - 40: O0 . ooOoO0o * iII111i . I11i + I1Ii111 % OoO0O00
  if 9 - 9: IiII * oO0o - o0oOOo0O0Ooo
  if 17 - 17: iII111i % Oo0Ooo
  if 14 - 14: I1IiiI - I1Ii111 % I1IiiI - II111iiii
  if 34 - 34: I1ii11iIi11i * IiII / II111iiii / ooOoO0o * oO0o
  oOOOO = ( I1iiiI1I1 . is_rloc_in_rloc_set ( source ) == False )
  if ( iI1I1I1I11I11 . record_ttl == 0 and oOOOO ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 3 - 3: II111iiii
   continue
   if 61 - 61: oO0o . I1IiiI + i1IIi
   if 69 - 69: O0 / i1IIi - OoOoOO00 + ooOoO0o - oO0o
   if 80 - 80: o0oOOo0O0Ooo % O0 * I11i . i1IIi - ooOoO0o
   if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
   if 61 - 61: II111iiii / i1IIi . I1ii11iIi11i % iIii1I11I1II1
   if 66 - 66: iIii1I11I1II1 % OoOoOO00 + i1IIi * i11iIiiIii * OoooooooOO
  I1IIIii1i = I1iiiI1I1 . registered_rlocs
  I1iiiI1I1 . registered_rlocs = [ ]
  if 75 - 75: oO0o * Oo0Ooo * O0
  if 22 - 22: ooOoO0o / OoooooooOO . II111iiii / Ii1I * OoO0O00 . i1IIi
  if 62 - 62: oO0o % Ii1I - Ii1I
  if 16 - 16: OoO0O00 - O0 - OOooOOo - I11i % OoOoOO00
  i1iIi = packet
  for oooOi1II1II111 in range ( iI1I1I1I11I11 . rloc_count ) :
   I1i11 = lisp_rloc_record ( )
   packet = I1i11 . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 9 - 9: I11i . I11i . OoooooooOO
   I1i11 . print_record ( "    " )
   if 42 - 42: iII111i / oO0o / iII111i * OoO0O00
   if 25 - 25: OoOoOO00 - II111iiii + II111iiii . Ii1I * II111iiii
   if 12 - 12: IiII / Ii1I
   if 54 - 54: Oo0Ooo + Ii1I % OoooooooOO * OOooOOo / OoOoOO00
   if ( len ( iIO00O00o0Oo00 . allowed_rlocs ) > 0 ) :
    oo0o00OO = I1i11 . rloc . print_address ( )
    if ( iIO00O00o0Oo00 . allowed_rlocs . has_key ( oo0o00OO ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( oo0o00OO , False ) ) )
     if 39 - 39: I1IiiI % i11iIiiIii % Ii1I
     if 59 - 59: ooOoO0o % OoO0O00 / I1IiiI - II111iiii + OoooooooOO * i11iIiiIii
     I1iiiI1I1 . registered = False
     packet = I1i11 . end_of_rlocs ( packet ,
 iI1I1I1I11I11 . rloc_count - oooOi1II1II111 - 1 )
     break
     if 58 - 58: IiII / Oo0Ooo + o0oOOo0O0Ooo
     if 71 - 71: Ii1I - IiII
     if 2 - 2: OoOoOO00 % IiII % OoO0O00 . i1IIi / I1Ii111 - iIii1I11I1II1
     if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
     if 65 - 65: iII111i . oO0o
     if 67 - 67: I1IiiI / iII111i / O0 % ooOoO0o - IiII / Ii1I
   oOO = lisp_rloc ( )
   oOO . store_rloc_from_record ( I1i11 , None , source )
   if 31 - 31: I11i - oO0o * ooOoO0o
   if 64 - 64: I11i
   if 41 - 41: I1Ii111 * OoooooooOO / OoOoOO00 + OoO0O00 . OoOoOO00 + I1Ii111
   if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
   if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
   if 43 - 43: Oo0Ooo % I11i
   if ( source . is_exact_match ( oOO . rloc ) ) :
    oOO . map_notify_requested = O0o0oo0 . map_notify_requested
    if 53 - 53: OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
    if 47 - 47: iIii1I11I1II1 - OOooOOo + I1ii11iIi11i * ooOoO0o + Oo0Ooo + OoO0O00
    if 64 - 64: OoOoOO00 - OoOoOO00 . OoooooooOO + ooOoO0o
    if 100 - 100: ooOoO0o . OoooooooOO % i1IIi % OoO0O00
    if 26 - 26: OoOoOO00 * IiII
   I1iiiI1I1 . registered_rlocs . append ( oOO )
   if 76 - 76: I1IiiI + IiII * I1ii11iIi11i * I1IiiI % Ii1I + ooOoO0o
   if 46 - 46: OoOoOO00
  O0oo00ooo = ( I1iiiI1I1 . do_rloc_sets_match ( I1IIIii1i ) == False )
  if 41 - 41: ooOoO0o + IiII
  if 97 - 97: I11i % I11i
  if 18 - 18: OoooooooOO . OOooOOo * Ii1I + II111iiii - I1ii11iIi11i
  if 61 - 61: Ii1I % i1IIi + OoOoOO00 % o0oOOo0O0Ooo + Oo0Ooo % OoooooooOO
  if 5 - 5: i1IIi % Oo0Ooo / OoooooooOO * OoOoOO00 + OOooOOo - ooOoO0o
  if 24 - 24: oO0o / ooOoO0o % I1IiiI / I1ii11iIi11i
  if ( O0o0oo0 . map_register_refresh and O0oo00ooo and
 I1iiiI1I1 . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   I1iiiI1I1 . registered_rlocs = I1IIIii1i
   continue
   if 88 - 88: OoO0O00
   if 96 - 96: IiII % I1ii11iIi11i % Oo0Ooo - i11iIiiIii % iIii1I11I1II1
   if 100 - 100: IiII - Ii1I
   if 9 - 9: II111iiii / Ii1I / O0 - OoOoOO00 - IiII
   if 6 - 6: OoOoOO00 / O0 * i1IIi * OoooooooOO
   if 60 - 60: iII111i - iII111i - Oo0Ooo . i11iIiiIii
  if ( I1iiiI1I1 . registered == False ) :
   I1iiiI1I1 . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 67 - 67: oO0o * OoOoOO00 * OoO0O00 + O0 * oO0o
  I1iiiI1I1 . last_registered = lisp_get_timestamp ( )
  I1iiiI1I1 . registered = ( iI1I1I1I11I11 . record_ttl != 0 )
  I1iiiI1I1 . last_registerer = source
  if 39 - 39: i1IIi
  if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
  if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
  if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
  I1iiiI1I1 . auth_sha1_or_sha2 = o0oOOO000O
  I1iiiI1I1 . proxy_reply_requested = O0o0oo0 . proxy_reply_requested
  I1iiiI1I1 . lisp_sec_present = O0o0oo0 . lisp_sec_present
  I1iiiI1I1 . map_notify_requested = O0o0oo0 . map_notify_requested
  I1iiiI1I1 . mobile_node_requested = O0o0oo0 . mobile_node
  I1iiiI1I1 . merge_register_requested = O0o0oo0 . merge_register_requested
  if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
  I1iiiI1I1 . use_register_ttl_requested = O0o0oo0 . use_ttl_for_timeout
  if ( I1iiiI1I1 . use_register_ttl_requested ) :
   I1iiiI1I1 . register_ttl = iI1I1I1I11I11 . store_ttl ( )
  else :
   I1iiiI1I1 . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
  I1iiiI1I1 . xtr_id_present = O0o0oo0 . xtr_id_present
  if ( I1iiiI1I1 . xtr_id_present ) :
   I1iiiI1I1 . xtr_id = O0o0oo0 . xtr_id
   I1iiiI1I1 . site_id = O0o0oo0 . site_id
   if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
   if 22 - 22: ooOoO0o - OOooOOo
   if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
   if 20 - 20: ooOoO0o - i11iIiiIii
   if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
  if ( O0o0oo0 . merge_register_requested ) :
   if ( O00oOO0OO00 . merge_in_site_eid ( I1iiiI1I1 ) ) :
    O0Oo0o000oO0oOo0oo . append ( [ iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group ] )
    if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
   if ( O0o0oo0 . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , O00oOO0OO00 , O0o0oo0 ,
 iI1I1I1I11I11 )
    if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
    if 29 - 29: oO0o
    if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
  if ( O0oo00ooo == False ) : continue
  if ( len ( O0Oo0o000oO0oOo0oo ) != 0 ) : continue
  if 78 - 78: Oo0Ooo
  iiii11iii . append ( I1iiiI1I1 . print_eid_tuple ( ) )
  if 77 - 77: oO0o % Oo0Ooo % O0
  if 51 - 51: IiII % IiII + OOooOOo . II111iiii / I1ii11iIi11i
  if 4 - 4: o0oOOo0O0Ooo % I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
  if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
  if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
  if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
  if 88 - 88: ooOoO0o
  iI1I1I1I11I11 = iI1I1I1I11I11 . encode ( )
  iI1I1I1I11I11 += i1iIi
  OoO0OOO0Oo0O = [ I1iiiI1I1 . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
  for oOO in I1IIIii1i :
   if ( oOO . map_notify_requested == False ) : continue
   if ( oOO . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , iI1I1I1I11I11 , OoO0OOO0Oo0O , 1 , oOO . rloc ,
 LISP_CTRL_PORT , O0o0oo0 . nonce , O0o0oo0 . key_id ,
 O0o0oo0 . alg_id , O0o0oo0 . auth_len , iIO00O00o0Oo00 , False )
   if 20 - 20: i11iIiiIii * I11i
   if 29 - 29: IiII / OOooOOo
   if 39 - 39: O0 + II111iiii
   if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
   if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
  lisp_notify_subscribers ( lisp_sockets , iI1I1I1I11I11 , I1iiiI1I1 . eid , iIO00O00o0Oo00 )
  if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
  if 42 - 42: O0 / oO0o % O0 . i1IIi % OOooOOo
  if 13 - 13: I1IiiI % ooOoO0o + OOooOOo
  if 91 - 91: oO0o - ooOoO0o
  if 20 - 20: i1IIi . IiII / o0oOOo0O0Ooo / I11i
 if ( len ( O0Oo0o000oO0oOo0oo ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , O0Oo0o000oO0oOo0oo )
  if 27 - 27: ooOoO0o . ooOoO0o - Ii1I % i11iIiiIii
  if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
  if 7 - 7: I1IiiI + OoooooooOO + o0oOOo0O0Ooo . OoooooooOO
  if 29 - 29: iII111i * O0 + I1IiiI * IiII + iII111i - IiII
  if 38 - 38: I1ii11iIi11i - Ii1I % OoooooooOO
  if 43 - 43: iIii1I11I1II1 / OoOoOO00
 if ( O0o0oo0 . merge_register_requested ) : return
 if 13 - 13: o0oOOo0O0Ooo / I1Ii111
 if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
 if 32 - 32: oO0o
 if 72 - 72: I1IiiI
 if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
 if ( O0o0oo0 . map_notify_requested and iIO00O00o0Oo00 != None ) :
  lisp_build_map_notify ( lisp_sockets , Oo0ooO000o0ooo , iiii11iii ,
 O0o0oo0 . record_count , source , sport , O0o0oo0 . nonce ,
 O0o0oo0 . key_id , O0o0oo0 . alg_id , O0o0oo0 . auth_len ,
 iIO00O00o0Oo00 , True )
  if 87 - 87: Oo0Ooo
 return
 if 7 - 7: iIii1I11I1II1
 if 85 - 85: iIii1I11I1II1 . O0
 if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
 if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
 if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
 if 8 - 8: OoO0O00 . OoO0O00
 if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
 if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
 if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
 if 24 - 24: IiII
def lisp_process_multicast_map_notify ( packet , source ) :
 iiiiIi1111ii1 = lisp_map_notify ( "" )
 packet = iiiiIi1111ii1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 95 - 95: IiII + OoOoOO00 * OOooOOo
  if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
 iiiiIi1111ii1 . print_notify ( )
 if ( iiiiIi1111ii1 . record_count == 0 ) : return
 if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
 ii11i = iiiiIi1111ii1 . eid_records
 if 80 - 80: I11i * IiII % iII111i + OoOoOO00
 for IiIIi1IiiIiI in range ( iiiiIi1111ii1 . record_count ) :
  iI1I1I1I11I11 = lisp_eid_record ( )
  ii11i = iI1I1I1I11I11 . decode ( ii11i )
  if ( packet == None ) : return
  iI1I1I1I11I11 . print_record ( "  " , False )
  if 56 - 56: OOooOOo . OOooOOo + oO0o
  if 7 - 7: o0oOOo0O0Ooo * II111iiii - I11i . Ii1I % OoooooooOO - I1IiiI
  if 24 - 24: Oo0Ooo / II111iiii * Oo0Ooo - ooOoO0o
  if 46 - 46: o0oOOo0O0Ooo
  I1iOo0 = lisp_map_cache_lookup ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group )
  if ( I1iOo0 == None ) :
   I1IiIiI11I , O0O , OO0Oo00oo = lisp_allow_gleaning ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group ,
 None )
   if ( I1IiIiI11I == False ) : continue
   if 13 - 13: i1IIi % iIii1I11I1II1 - iII111i - I1IiiI - IiII + iIii1I11I1II1
   I1iOo0 = lisp_mapping ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group , [ ] )
   I1iOo0 . add_cache ( )
   if 22 - 22: IiII - OOooOOo + I1ii11iIi11i
   if 64 - 64: OoOoOO00
   if 79 - 79: IiII
   if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
   if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
   if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
   if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
  if ( I1iOo0 . gleaned ) :
   lprint ( "Ignore Map-Notify for gleaned {}" . format ( green ( I1iOo0 . print_eid_tuple ( ) , False ) ) )
   if 41 - 41: OoooooooOO + iII111i . OOooOOo
   continue
   if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
   if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
  I1iOo0 . mapping_source = None if source == "lisp-etr" else source
  I1iOo0 . map_cache_ttl = iI1I1I1I11I11 . store_ttl ( )
  if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
  if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
  if 57 - 57: II111iiii % OoO0O00 * i1IIi
  if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
  if 9 - 9: II111iiii % OoooooooOO
  if ( len ( I1iOo0 . rloc_set ) != 0 and iI1I1I1I11I11 . rloc_count == 0 ) :
   I1iOo0 . rloc_set = [ ]
   I1iOo0 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , I1iOo0 )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( I1iOo0 . print_eid_tuple ( ) , False ) ) )
   if 4 - 4: i1IIi * i11iIiiIii % OoooooooOO + OoOoOO00 . oO0o
   continue
   if 95 - 95: I1ii11iIi11i * OoOoOO00 % o0oOOo0O0Ooo / O0 + ooOoO0o % OOooOOo
   if 48 - 48: i1IIi + IiII - iIii1I11I1II1 . i11iIiiIii % OOooOOo + I1ii11iIi11i
  O0oOOo = I1iOo0 . rtrs_in_rloc_set ( )
  if 80 - 80: i1IIi + II111iiii / Oo0Ooo % i11iIiiIii / iII111i
  if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
  if 6 - 6: IiII
  if 68 - 68: Oo0Ooo
  if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
  for oooOi1II1II111 in range ( iI1I1I1I11I11 . rloc_count ) :
   I1i11 = lisp_rloc_record ( )
   ii11i = I1i11 . decode ( ii11i , None )
   I1i11 . print_record ( "    " )
   if ( iI1I1I1I11I11 . group . is_null ( ) ) : continue
   if ( I1i11 . rle == None ) : continue
   if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
   if 93 - 93: i11iIiiIii
   if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
   if 40 - 40: IiII % IiII
   if 9 - 9: I1IiiI * i1IIi + OOooOOo * OoOoOO00
   iIiI11i1iI1 = I1iOo0 . rloc_set [ 0 ] . stats if len ( I1iOo0 . rloc_set ) != 0 else None
   if 77 - 77: iII111i
   if 15 - 15: O0 - Ii1I + OoOoOO00
   if 93 - 93: OoO0O00
   if 68 - 68: OOooOOo
   oOO = lisp_rloc ( )
   oOO . store_rloc_from_record ( I1i11 , None , I1iOo0 . mapping_source )
   if ( iIiI11i1iI1 != None ) : oOO . stats = copy . deepcopy ( iIiI11i1iI1 )
   if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
   if ( O0oOOo and oOO . is_rtr ( ) == False ) : continue
   if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
   I1iOo0 . rloc_set = [ oOO ]
   I1iOo0 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , I1iOo0 )
   if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( I1iOo0 . print_eid_tuple ( ) , False ) ,
   # ooOoO0o
 oOO . rle . print_rle ( False , True ) ) )
   if 2 - 2: iII111i + II111iiii
   if 88 - 88: i1IIi - iII111i / OOooOOo / i1IIi
 return
 if 48 - 48: iII111i / OoooooooOO / iIii1I11I1II1
 if 41 - 41: II111iiii - II111iiii - OoO0O00 + oO0o * I11i
 if 77 - 77: IiII % iIii1I11I1II1 - OOooOOo / I1Ii111 / ooOoO0o . iII111i
 if 62 - 62: I1Ii111
 if 42 - 42: o0oOOo0O0Ooo
 if 59 - 59: I1ii11iIi11i % O0 - i1IIi . Oo0Ooo
 if 18 - 18: II111iiii
 if 31 - 31: Oo0Ooo / Oo0Ooo / iIii1I11I1II1 / I11i % OoooooooOO
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 iiiiIi1111ii1 = lisp_map_notify ( "" )
 IiiiIi1iiii11 = iiiiIi1111ii1 . decode ( orig_packet )
 if ( IiiiIi1iiii11 == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 90 - 90: I1IiiI
  if 35 - 35: O0
 iiiiIi1111ii1 . print_notify ( )
 if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
 if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
 if 78 - 78: I1IiiI - iIii1I11I1II1
 if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
 if 85 - 85: I11i + OoOoOO00 * O0 * O0
 IiII1iiI = source . print_address ( )
 if ( iiiiIi1111ii1 . alg_id != 0 or iiiiIi1111ii1 . auth_len != 0 ) :
  IIIIiI1 = None
  for Oo000O000 in lisp_map_servers_list :
   if ( Oo000O000 . find ( IiII1iiI ) == - 1 ) : continue
   IIIIiI1 = lisp_map_servers_list [ Oo000O000 ]
   if 92 - 92: i11iIiiIii
  if ( IIIIiI1 == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( IiII1iiI ) )
   if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
   return
   if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
   if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
  IIIIiI1 . map_notifies_received += 1
  if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
  o0OoO00O0Oo = lisp_verify_auth ( IiiiIi1iiii11 , iiiiIi1111ii1 . alg_id ,
 iiiiIi1111ii1 . auth_data , IIIIiI1 . password )
  if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if o0OoO00O0Oo else "failed" ) )
  if 42 - 42: OoOoOO00 . I11i % II111iiii
  if ( o0OoO00O0Oo == False ) : return
 else :
  IIIIiI1 = lisp_ms ( IiII1iiI , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 19 - 19: OoooooooOO
  if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
  if 21 - 21: OOooOOo . Oo0Ooo - i1IIi
  if 56 - 56: I11i
  if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
  if 32 - 32: OOooOOo / i1IIi / OOooOOo
 ii11i = iiiiIi1111ii1 . eid_records
 if ( iiiiIi1111ii1 . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , ii11i , iiiiIi1111ii1 , IIIIiI1 )
  return
  if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
  if 45 - 45: Oo0Ooo
  if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
  if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
  if 52 - 52: OOooOOo + OoO0O00
  if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
  if 42 - 42: i1IIi
  if 52 - 52: OoO0O00 % iII111i % O0
 iI1I1I1I11I11 = lisp_eid_record ( )
 IiiiIi1iiii11 = iI1I1I1I11I11 . decode ( ii11i )
 if ( IiiiIi1iiii11 == None ) : return
 if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
 iI1I1I1I11I11 . print_record ( "  " , False )
 if 50 - 50: oO0o . I1Ii111
 for oooOi1II1II111 in range ( iI1I1I1I11I11 . rloc_count ) :
  I1i11 = lisp_rloc_record ( )
  IiiiIi1iiii11 = I1i11 . decode ( IiiiIi1iiii11 , None )
  if ( IiiiIi1iiii11 == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 38 - 38: iIii1I11I1II1 . Ii1I
  I1i11 . print_record ( "    " )
  if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
  if 15 - 15: O0
  if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
  if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
  if 25 - 25: ooOoO0o
 if ( iI1I1I1I11I11 . group . is_null ( ) == False ) :
  if 33 - 33: Oo0Ooo
  if 11 - 11: I11i
  if 55 - 55: i11iIiiIii * OoOoOO00 - OoOoOO00 * OoO0O00 / iII111i
  if 64 - 64: iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
  if 74 - 74: I1IiiI / o0oOOo0O0Ooo
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( iI1I1I1I11I11 . print_eid_tuple ( ) , False ) ) )
  if 53 - 53: iIii1I11I1II1 * oO0o
  if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
  iiiii1i1 = lisp_control_packet_ipc ( orig_packet , IiII1iiI , "lisp-itr" , 0 )
  lisp_ipc ( iiiii1i1 , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
  if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
  if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
  if 60 - 60: oO0o * I1Ii111
  if 81 - 81: oO0o - OOooOOo - oO0o
 lisp_send_map_notify_ack ( lisp_sockets , ii11i , iiiiIi1111ii1 , IIIIiI1 )
 return
 if 54 - 54: oO0o % I11i
 if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
 if 22 - 22: iIii1I11I1II1 - OoooooooOO
 if 8 - 8: ooOoO0o % i11iIiiIii
 if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
 if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
 if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
 if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
def lisp_process_map_notify_ack ( packet , source ) :
 iiiiIi1111ii1 = lisp_map_notify ( "" )
 packet = iiiiIi1111ii1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 73 - 73: O0 % i11iIiiIii
  if 16 - 16: O0
 iiiiIi1111ii1 . print_notify ( )
 if 15 - 15: i1IIi % i11iIiiIii
 if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
 if 35 - 35: OoOoOO00 . oO0o / II111iiii
 if 97 - 97: Ii1I + I1Ii111 / II111iiii
 if 14 - 14: iII111i / IiII / oO0o
 if ( iiiiIi1111ii1 . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 55 - 55: OoO0O00 % O0
  if 92 - 92: OoooooooOO / O0
 iI1I1I1I11I11 = lisp_eid_record ( )
 if 14 - 14: i11iIiiIii
 if ( iI1I1I1I11I11 . decode ( iiiiIi1111ii1 . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 43 - 43: OOooOOo
 iI1I1I1I11I11 . print_record ( "  " , False )
 if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
 I11i11i1 = iI1I1I1I11I11 . print_eid_tuple ( )
 if 93 - 93: OoOoOO00
 if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
 if 72 - 72: ooOoO0o
 if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
 if ( iiiiIi1111ii1 . alg_id != LISP_NONE_ALG_ID and iiiiIi1111ii1 . auth_len != 0 ) :
  I1iiiI1I1 = lisp_sites_by_eid . lookup_cache ( iI1I1I1I11I11 . eid , True )
  if ( I1iiiI1I1 == None ) :
   IiIii11 = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( IiIii11 , green ( I11i11i1 , False ) ) )
   if 53 - 53: OOooOOo * O0 . iII111i
   return
   if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
  iIO00O00o0Oo00 = I1iiiI1I1 . site
  if 78 - 78: iII111i
  if 80 - 80: i1IIi * I1IiiI + OOooOOo
  if 91 - 91: I1IiiI % OoOoOO00 * Oo0Ooo / I1ii11iIi11i
  if 57 - 57: i11iIiiIii / o0oOOo0O0Ooo . II111iiii
  iIO00O00o0Oo00 . map_notify_acks_received += 1
  if 63 - 63: O0
  I1I1I1 = iiiiIi1111ii1 . key_id
  if ( iIO00O00o0Oo00 . auth_key . has_key ( I1I1I1 ) ) :
   O0O0o0OOOO = iIO00O00o0Oo00 . auth_key [ I1I1I1 ]
  else :
   O0O0o0OOOO = ""
   if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
   if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
  o0OoO00O0Oo = lisp_verify_auth ( packet , iiiiIi1111ii1 . alg_id ,
 iiiiIi1111ii1 . auth_data , O0O0o0OOOO )
  if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
  I1I1I1 = "key-id {}" . format ( I1I1I1 ) if I1I1I1 == iiiiIi1111ii1 . key_id else "bad key-id {}" . format ( iiiiIi1111ii1 . key_id )
  if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
  if 74 - 74: i11iIiiIii
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if o0OoO00O0Oo else "failed" , I1I1I1 ) )
  if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
  if ( o0OoO00O0Oo == False ) : return
  if 6 - 6: I11i
  if 70 - 70: ooOoO0o + OoooooooOO % OoOoOO00 % oO0o / Ii1I . I11i
  if 63 - 63: I1ii11iIi11i - ooOoO0o . OOooOOo / O0 . iIii1I11I1II1 - Ii1I
  if 6 - 6: Ii1I
  if 60 - 60: iII111i + I1IiiI
 if ( iiiiIi1111ii1 . retransmit_timer ) : iiiiIi1111ii1 . retransmit_timer . cancel ( )
 if 36 - 36: i1IIi . O0 . OoO0O00 % OOooOOo * I11i / Ii1I
 I1I111I1 = source . print_address ( )
 Oo000O000 = iiiiIi1111ii1 . nonce_key
 if 16 - 16: Oo0Ooo
 if ( lisp_map_notify_queue . has_key ( Oo000O000 ) ) :
  iiiiIi1111ii1 = lisp_map_notify_queue . pop ( Oo000O000 )
  if ( iiiiIi1111ii1 . retransmit_timer ) : iiiiIi1111ii1 . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( Oo000O000 ) )
  if 44 - 44: iIii1I11I1II1 - II111iiii . IiII . i1IIi
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( iiiiIi1111ii1 . nonce_key , red ( I1I111I1 , False ) ) )
  if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
  if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
 return
 if 43 - 43: I1ii11iIi11i + I11i
 if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
 if 100 - 100: IiII - OoOoOO00 / I11i
 if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
 if 87 - 87: Oo0Ooo
 if 65 - 65: ooOoO0o . I1IiiI
 if 51 - 51: IiII
 if 43 - 43: oO0o - I11i . i11iIiiIii
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 30 - 30: I1IiiI % oO0o * OoooooooOO
 if 64 - 64: I1IiiI
 if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
 if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
 ooOoo0OO0O = False
 if ( group . is_null ( ) == False ) :
  ooOoo0OO0O = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
 if ( ooOoo0OO0O == False ) :
  ooOoo0OO0O = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 90 - 90: o0oOOo0O0Ooo / I1ii11iIi11i - oO0o - Ii1I - I1IiiI + I1Ii111
  if 93 - 93: I1IiiI - I11i . I1IiiI - iIii1I11I1II1
 if ( ooOoo0OO0O ) :
  OOOo0O0O = lisp_print_eid_tuple ( eid , group )
  IiO0ooOoO = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 3 - 3: I1Ii111 % OOooOOo . ooOoO0o / I1IiiI
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( OOOo0O0O , False ) , s ,
  # iIii1I11I1II1 - IiII - O0 * Oo0Ooo * OoOoOO00
 IiO0ooOoO ) )
  if 78 - 78: ooOoO0o * Oo0Ooo
 return ( ooOoo0OO0O )
 if 74 - 74: II111iiii . i11iIiiIii
 if 51 - 51: o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 93 - 93: i11iIiiIii / OoO0O00 + I1IiiI
 if 4 - 4: ooOoO0o . i11iIiiIii . i1IIi
 if 37 - 37: i11iIiiIii + OoO0O00 * Ii1I
 if 100 - 100: IiII . I1Ii111 + II111iiii + i1IIi
 if 37 - 37: iII111i
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 27 - 27: iII111i / Ii1I / iII111i + OoooooooOO - O0 + OoO0O00
 iii111IIIIi1I = lisp_map_referral ( )
 packet = iii111IIIIi1I . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 62 - 62: iIii1I11I1II1
 iii111IIIIi1I . print_map_referral ( )
 if 60 - 60: Oo0Ooo % IiII % OoO0O00 - i11iIiiIii
 IiII1iiI = source . print_address ( )
 Iii11I = iii111IIIIi1I . nonce
 if 53 - 53: i11iIiiIii + OoooooooOO
 if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
 if 79 - 79: II111iiii / OoooooooOO
 if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
 for IiIIi1IiiIiI in range ( iii111IIIIi1I . record_count ) :
  iI1I1I1I11I11 = lisp_eid_record ( )
  packet = iI1I1I1I11I11 . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
  iI1I1I1I11I11 . print_record ( "  " , True )
  if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
  if 17 - 17: I1Ii111
  if 2 - 2: O0 % OoOoOO00 + oO0o
  if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
  Oo000O000 = str ( Iii11I )
  if ( Oo000O000 not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( Iii11I ) , IiII1iiI ) )
   if 51 - 51: IiII
   if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
   continue
   if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
  O0O0OOoO00 = lisp_ddt_map_requestQ [ Oo000O000 ]
  if ( O0O0OOoO00 == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( Iii11I ) , IiII1iiI ) )
   if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
   continue
   if 95 - 95: O0 - OoOoOO00
   if 68 - 68: ooOoO0o . I1Ii111
   if 84 - 84: OoooooooOO + oO0o % i1IIi + o0oOOo0O0Ooo * i1IIi
   if 51 - 51: oO0o . OoooooooOO + OOooOOo * I1ii11iIi11i - ooOoO0o
   if 41 - 41: Oo0Ooo
   if 46 - 46: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii . iII111i
  if ( lisp_map_referral_loop ( O0O0OOoO00 , iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group ,
 iI1I1I1I11I11 . action , IiII1iiI ) ) :
   O0O0OOoO00 . dequeue_map_request ( )
   continue
   if 66 - 66: oO0o % i1IIi % OoooooooOO
   if 58 - 58: OOooOOo
  O0O0OOoO00 . last_cached_prefix [ 0 ] = iI1I1I1I11I11 . eid
  O0O0OOoO00 . last_cached_prefix [ 1 ] = iI1I1I1I11I11 . group
  if 89 - 89: iIii1I11I1II1 - i1IIi
  if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
  if 9 - 9: I1Ii111 / II111iiii * I1Ii111 / I11i - OoO0O00
  if 36 - 36: IiII . OoOoOO00 . Ii1I
  O0OoO = False
  IIiii1I1 = lisp_referral_cache_lookup ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group ,
 True )
  if ( IIiii1I1 == None ) :
   O0OoO = True
   IIiii1I1 = lisp_referral ( )
   IIiii1I1 . eid = iI1I1I1I11I11 . eid
   IIiii1I1 . group = iI1I1I1I11I11 . group
   if ( iI1I1I1I11I11 . ddt_incomplete == False ) : IIiii1I1 . add_cache ( )
  elif ( IIiii1I1 . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( IIiii1I1 . print_eid_tuple ( ) , False ) ) )
   if 31 - 31: iIii1I11I1II1
   O0O0OOoO00 . dequeue_map_request ( )
   continue
   if 84 - 84: I1ii11iIi11i - iII111i * I1IiiI
   if 88 - 88: OOooOOo / Oo0Ooo
  I11I1iI = iI1I1I1I11I11 . action
  IIiii1I1 . referral_source = source
  IIiii1I1 . referral_type = I11I1iI
  oOoooOOO0o0 = iI1I1I1I11I11 . store_ttl ( )
  IIiii1I1 . referral_ttl = oOoooOOO0o0
  IIiii1I1 . expires = lisp_set_timestamp ( oOoooOOO0o0 )
  if 31 - 31: II111iiii
  if 32 - 32: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 67 - 67: IiII + oO0o * IiII
  if 26 - 26: I1ii11iIi11i + i1IIi . i1IIi - oO0o + I1IiiI * o0oOOo0O0Ooo
  o00000o = IIiii1I1 . is_referral_negative ( )
  if ( IIiii1I1 . referral_set . has_key ( IiII1iiI ) ) :
   oO0O0o0000 = IIiii1I1 . referral_set [ IiII1iiI ]
   if 16 - 16: I1IiiI . Ii1I
   if ( oO0O0o0000 . updown == False and o00000o == False ) :
    oO0O0o0000 . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( IiII1iiI ) )
    if 80 - 80: OOooOOo * O0 / iIii1I11I1II1 / IiII / OoOoOO00
   elif ( oO0O0o0000 . updown == True and o00000o == True ) :
    oO0O0o0000 . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( IiII1iiI ) )
    if 15 - 15: I1ii11iIi11i * iII111i + i11iIiiIii
    if 68 - 68: i1IIi / oO0o * I1ii11iIi11i - OoOoOO00 + Oo0Ooo / O0
    if 1 - 1: ooOoO0o - Oo0Ooo + I1Ii111
    if 90 - 90: I1Ii111 * O0 . iII111i - Oo0Ooo % iIii1I11I1II1
    if 7 - 7: I1ii11iIi11i % o0oOOo0O0Ooo % O0 % iIii1I11I1II1
    if 10 - 10: OoooooooOO - iII111i . i1IIi % oO0o . OoooooooOO + OOooOOo
    if 59 - 59: I1IiiI * OoooooooOO % OOooOOo / I11i
    if 77 - 77: II111iiii - IiII % OOooOOo
  iiI11 = { }
  for Oo000O000 in IIiii1I1 . referral_set : iiI11 [ Oo000O000 ] = None
  if 87 - 87: I11i . i1IIi % i1IIi + II111iiii
  if 23 - 23: OOooOOo - OoooooooOO % o0oOOo0O0Ooo / iII111i
  if 74 - 74: iIii1I11I1II1 . OoooooooOO * iII111i + OoO0O00 * O0 - iIii1I11I1II1
  if 86 - 86: iII111i - Ii1I / II111iiii * oO0o
  for IiIIi1IiiIiI in range ( iI1I1I1I11I11 . rloc_count ) :
   I1i11 = lisp_rloc_record ( )
   packet = I1i11 . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 18 - 18: Oo0Ooo
   I1i11 . print_record ( "    " )
   if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
   if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
   if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
   if 39 - 39: OoOoOO00 - I1ii11iIi11i / I1Ii111
   oo0o00OO = I1i11 . rloc . print_address ( )
   if ( IIiii1I1 . referral_set . has_key ( oo0o00OO ) == False ) :
    oO0O0o0000 = lisp_referral_node ( )
    oO0O0o0000 . referral_address . copy_address ( I1i11 . rloc )
    IIiii1I1 . referral_set [ oo0o00OO ] = oO0O0o0000
    if ( IiII1iiI == oo0o00OO and o00000o ) : oO0O0o0000 . updown = False
   else :
    oO0O0o0000 = IIiii1I1 . referral_set [ oo0o00OO ]
    if ( iiI11 . has_key ( oo0o00OO ) ) : iiI11 . pop ( oo0o00OO )
    if 48 - 48: IiII - oO0o + I11i % o0oOOo0O0Ooo
   oO0O0o0000 . priority = I1i11 . priority
   oO0O0o0000 . weight = I1i11 . weight
   if 81 - 81: Oo0Ooo . I1Ii111 * iIii1I11I1II1
   if 60 - 60: OoooooooOO
   if 41 - 41: iIii1I11I1II1 + O0 % o0oOOo0O0Ooo - IiII . I11i * O0
   if 39 - 39: i11iIiiIii . Ii1I
   if 68 - 68: OOooOOo * ooOoO0o . I1IiiI - iII111i
  for Oo000O000 in iiI11 : IIiii1I1 . referral_set . pop ( Oo000O000 )
  if 81 - 81: I11i % Oo0Ooo / iII111i
  I11i11i1 = IIiii1I1 . print_eid_tuple ( )
  if 44 - 44: Oo0Ooo
  if ( O0OoO ) :
   if ( iI1I1I1I11I11 . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( I11i11i1 , False ) ) )
    if 90 - 90: Oo0Ooo . ooOoO0o / IiII * I1Ii111 . ooOoO0o + II111iiii
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( I11i11i1 , False ) , iI1I1I1I11I11 . rloc_count ) )
    if 43 - 43: iIii1I11I1II1 % OOooOOo + OoOoOO00 + I1ii11iIi11i - Oo0Ooo / Ii1I
    if 94 - 94: Ii1I / Oo0Ooo % II111iiii % Oo0Ooo * oO0o
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( I11i11i1 , False ) , iI1I1I1I11I11 . rloc_count ) )
   if 54 - 54: O0 / ooOoO0o * I1Ii111
   if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
   if 13 - 13: IiII + Oo0Ooo - I1Ii111
   if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
   if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
   if 95 - 95: oO0o / Ii1I + OoO0O00
  if ( I11I1iI == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( O0O0OOoO00 . lisp_sockets , IIiii1I1 . eid ,
 IIiii1I1 . group , O0O0OOoO00 . nonce , O0O0OOoO00 . itr , O0O0OOoO00 . sport , 15 , None , False )
   O0O0OOoO00 . dequeue_map_request ( )
   if 57 - 57: iIii1I11I1II1 + I1Ii111 % oO0o - Ii1I . I1IiiI
   if 39 - 39: OoO0O00 + II111iiii
  if ( I11I1iI == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( O0O0OOoO00 . tried_root ) :
    lisp_send_negative_map_reply ( O0O0OOoO00 . lisp_sockets , IIiii1I1 . eid ,
 IIiii1I1 . group , O0O0OOoO00 . nonce , O0O0OOoO00 . itr , O0O0OOoO00 . sport , 0 , None , False )
    O0O0OOoO00 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( O0O0OOoO00 , True )
    if 98 - 98: O0 - I1Ii111 % oO0o - iII111i + Ii1I * i1IIi
    if 76 - 76: o0oOOo0O0Ooo
    if 55 - 55: OOooOOo + I1ii11iIi11i * Oo0Ooo
  if ( I11I1iI == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( IIiii1I1 . referral_set . has_key ( IiII1iiI ) ) :
    oO0O0o0000 = IIiii1I1 . referral_set [ IiII1iiI ]
    oO0O0o0000 . updown = False
    if 11 - 11: i1IIi - OoooooooOO * OoOoOO00 / oO0o - OoooooooOO - I1IiiI
   if ( len ( IIiii1I1 . referral_set ) == 0 ) :
    O0O0OOoO00 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( O0O0OOoO00 , False )
    if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
    if 49 - 49: iII111i + I11i . Oo0Ooo
    if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
  if ( I11I1iI in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( O0O0OOoO00 . eid . is_exact_match ( iI1I1I1I11I11 . eid ) ) :
    if ( not O0O0OOoO00 . tried_root ) :
     lisp_send_ddt_map_request ( O0O0OOoO00 , True )
    else :
     lisp_send_negative_map_reply ( O0O0OOoO00 . lisp_sockets ,
 IIiii1I1 . eid , IIiii1I1 . group , O0O0OOoO00 . nonce , O0O0OOoO00 . itr ,
 O0O0OOoO00 . sport , 15 , None , False )
     O0O0OOoO00 . dequeue_map_request ( )
     if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
   else :
    lisp_send_ddt_map_request ( O0O0OOoO00 , False )
    if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
    if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
    if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
  if ( I11I1iI == LISP_DDT_ACTION_MS_ACK ) : O0O0OOoO00 . dequeue_map_request ( )
  if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
 return
 if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
 if 1 - 1: i11iIiiIii
 if 1 - 1: iIii1I11I1II1
 if 73 - 73: iII111i + IiII
 if 95 - 95: O0
 if 75 - 75: ooOoO0o
 if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
 if 85 - 85: ooOoO0o
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 I1iiiIII11ii1i1i1 = lisp_ecm ( 0 )
 packet = I1iiiIII11ii1i1i1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 29 - 29: iII111i . Ii1I
  if 43 - 43: I11i - I1ii11iIi11i + iIii1I11I1II1 / I1ii11iIi11i * oO0o / iIii1I11I1II1
 I1iiiIII11ii1i1i1 . print_ecm ( )
 if 45 - 45: IiII
 O0ooOoO0 = lisp_control_header ( )
 if ( O0ooOoO0 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 49 - 49: I1IiiI . Ii1I * I1IiiI - OoooooooOO . I11i / I1Ii111
  if 9 - 9: iIii1I11I1II1 * Ii1I / O0 - OOooOOo
 Oo0o0Ooo0ooOo = O0ooOoO0 . type
 del ( O0ooOoO0 )
 if 51 - 51: OOooOOo . i11iIiiIii / i11iIiiIii
 if ( Oo0o0Ooo0ooOo != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 10 - 10: iIii1I11I1II1 % i1IIi
  if 78 - 78: I11i + II111iiii % o0oOOo0O0Ooo
  if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
  if 44 - 44: I1ii11iIi11i
  if 39 - 39: iII111i + Oo0Ooo / oO0o
 O0oOo0o0O0o0 = I1iiiIII11ii1i1i1 . udp_sport
 I1II1i = time . time ( )
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 I1iiiIII11ii1i1i1 . source , O0oOo0o0O0o0 , I1iiiIII11ii1i1i1 . ddt , - 1 , I1II1i )
 return
 if 33 - 33: I1IiiI % o0oOOo0O0Ooo
 if 27 - 27: OoOoOO00 + I11i
 if 12 - 12: OoOoOO00 * II111iiii + I11i + iII111i / o0oOOo0O0Ooo
 if 85 - 85: Ii1I . OoOoOO00 / ooOoO0o + I11i / oO0o
 if 13 - 13: Ii1I % OoO0O00 / oO0o / OoooooooOO - I11i % OoooooooOO
 if 11 - 11: I1IiiI + IiII
 if 97 - 97: i1IIi * ooOoO0o
 if 18 - 18: i1IIi . I1IiiI % I1IiiI / iII111i + Ii1I * o0oOOo0O0Ooo
 if 97 - 97: Ii1I % I1IiiI % iIii1I11I1II1 * Ii1I . i1IIi
 if 70 - 70: i1IIi . oO0o - oO0o . I1Ii111
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 68 - 68: I1Ii111 . iIii1I11I1II1 * O0
 if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
 if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
 if 90 - 90: i11iIiiIii - iII111i * oO0o
 if 79 - 79: IiII
 if 38 - 38: I1Ii111
 if 56 - 56: i11iIiiIii
 oo0OoO = ms . map_server
 if ( lisp_decent_push_configured and oo0OoO . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  oo0OoO = copy . deepcopy ( oo0OoO )
  oo0OoO . address = 0x7f000001
  I11i1iIiiIiIi = bold ( "Bootstrap" , False )
  i11ii = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( I11i1iIiiIiIi , i11ii ) )
  if 58 - 58: i11iIiiIii / OoOoOO00
  if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
  if 39 - 39: Oo0Ooo . OoO0O00
  if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
  if 100 - 100: ooOoO0o / OoooooooOO
  if 73 - 73: i11iIiiIii - Oo0Ooo
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 100 - 100: iIii1I11I1II1 + I1Ii111
 if 51 - 51: o0oOOo0O0Ooo * I11i
 if 42 - 42: OOooOOo % I11i
 if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
 if 81 - 81: I1IiiI
 if ( ms . ekey != None ) :
  iIIi1oOoO0OoooOoOO = ms . ekey . zfill ( 32 )
  iiI1iiIiiiI1I = "0" * 8
  o0 = chacha . ChaCha ( iIIi1oOoO0OoooOoOO , iiI1iiIiiiI1I ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + o0
  oOo = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( oOo , ms . ekey_id ) )
  if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
  if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
 o0OO0oO0 = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  o0OO0oO0 = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 55 - 55: I11i . iII111i - i1IIi
  if 57 - 57: I11i * I11i . iIii1I11I1II1 - Oo0Ooo + OoooooooOO
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( oo0OoO . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , o0OO0oO0 ) )
 if 34 - 34: Oo0Ooo * OoOoOO00 % OOooOOo % i1IIi
 lisp_send ( lisp_sockets , oo0OoO , LISP_CTRL_PORT , packet )
 return
 if 18 - 18: o0oOOo0O0Ooo / iII111i * iIii1I11I1II1
 if 100 - 100: OoO0O00 . i1IIi . I1ii11iIi11i / IiII + iII111i
 if 64 - 64: O0
 if 43 - 43: OoOoOO00 / o0oOOo0O0Ooo
 if 7 - 7: ooOoO0o / i1IIi * OOooOOo * O0 % I1IiiI . iII111i
 if 54 - 54: I1IiiI * I1Ii111 . OoO0O00 / OOooOOo / i1IIi
 if 13 - 13: OoooooooOO
 if 65 - 65: OoO0O00 * I11i - II111iiii + OOooOOo
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 i1IIi1ii1i1ii = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 48 - 48: Oo0Ooo / OoO0O00
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 14 - 14: I1Ii111 + i11iIiiIii * oO0o + I1Ii111 . iIii1I11I1II1
 if 74 - 74: Oo0Ooo * I1IiiI
 packet = lisp_control_packet_ipc ( packet , i1IIi1ii1i1ii , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 87 - 87: iII111i + i1IIi
 if 10 - 10: Oo0Ooo . o0oOOo0O0Ooo - i11iIiiIii / iII111i + i11iIiiIii . I11i
 if 66 - 66: i1IIi
 if 98 - 98: Oo0Ooo / iIii1I11I1II1
 if 33 - 33: O0 - iII111i
 if 40 - 40: iII111i * I11i
 if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
 if 87 - 87: OoOoOO00
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 30 - 30: IiII % OoOoOO00 + I1Ii111
 if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
 if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
 if 87 - 87: I11i
 if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
 if 72 - 72: OoO0O00 * Oo0Ooo - IiII
 if 74 - 74: Ii1I
 if 26 - 26: I11i . O0
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 68 - 68: Ii1I
 if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
 if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
 if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
 if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
 if 44 - 44: I11i * iIii1I11I1II1 . I1ii11iIi11i
 if 9 - 9: o0oOOo0O0Ooo
 if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 21 - 21: Ii1I * OoOoOO00
 if 29 - 29: iIii1I11I1II1 / ooOoO0o
 if 75 - 75: OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
 if 88 - 88: OoO0O00 % Ii1I
 if 12 - 12: OoooooooOO . O0
 if 33 - 33: OoooooooOO / I11i . II111iiii * i1IIi
 if 34 - 34: i11iIiiIii / OoOoOO00
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 100 - 100: o0oOOo0O0Ooo - I1IiiI / I11i
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 43 - 43: o0oOOo0O0Ooo % iIii1I11I1II1
  if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
  if 4 - 4: Ii1I . i1IIi + Oo0Ooo % I11i . OoO0O00
  if 70 - 70: OOooOOo * OoOoOO00 / OoOoOO00 / OoOoOO00
  if 23 - 23: I1IiiI
  if 24 - 24: I1Ii111 * i1IIi % O0 * Ii1I + iII111i
 if ( lisp_nat_traversal ) :
  oo0O = lisp_get_any_translated_port ( )
  if ( oo0O != None ) : inner_sport = oo0O
  if 14 - 14: oO0o * iII111i + Ii1I + Ii1I * IiII
 I1iiiIII11ii1i1i1 = lisp_ecm ( inner_sport )
 if 82 - 82: IiII * ooOoO0o / OOooOOo + OoOoOO00
 I1iiiIII11ii1i1i1 . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 I1iiiIII11ii1i1i1 . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 I1iiiIII11ii1i1i1 . ddt = ddt
 i11iI111I1ii = I1iiiIII11ii1i1i1 . encode ( packet , inner_source , inner_dest )
 if ( i11iI111I1ii == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
 I1iiiIII11ii1i1i1 . print_ecm ( )
 if 96 - 96: O0
 packet = i11iI111I1ii + packet
 if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
 oo0o00OO = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( oo0o00OO ) )
 oo0OoO = lisp_convert_4to6 ( oo0o00OO )
 lisp_send ( lisp_sockets , oo0OoO , LISP_CTRL_PORT , packet )
 return
 if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
 if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
 if 61 - 61: IiII . O0
 if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
 if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
 if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
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
if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 32 - 32: OoO0O00 + OOooOOo . OoO0O00 - Oo0Ooo
if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
if 86 - 86: OOooOOo / OoooooooOO - IiII
if 56 - 56: I1ii11iIi11i - i1IIi * OoooooooOO * O0 * I1IiiI - I1Ii111
if 32 - 32: OoooooooOO . OOooOOo . OoO0O00 . IiII / I11i % i1IIi
if 21 - 21: O0 . OoO0O00 * I1ii11iIi11i % iII111i + OoooooooOO
if 8 - 8: oO0o * iII111i * I11i
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 30 - 30: I1Ii111
if 61 - 61: iII111i
if 50 - 50: Ii1I / I1IiiI . O0
if 49 - 49: I1Ii111 . OoO0O00 % O0
if 15 - 15: I11i - Oo0Ooo / I1Ii111 . ooOoO0o % I1IiiI
if 62 - 62: II111iiii + ooOoO0o + I1IiiI
def byte_swap_64 ( address ) :
 IiiIIi1 = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
 if 13 - 13: I1ii11iIi11i
 if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
 if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
 if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
 if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
 if 18 - 18: OoooooooOO - I1ii11iIi11i
 if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
 return ( IiiIIi1 )
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
 if 74 - 74: oO0o . I1Ii111 . II111iiii
 if 92 - 92: I1Ii111 % OoooooooOO * I1Ii111
class lisp_cache_entries ( ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 78 - 78: Oo0Ooo . I11i . oO0o + O0 / O0
  if 41 - 41: iII111i * OoO0O00 - OoO0O00
  if 72 - 72: o0oOOo0O0Ooo + oO0o . I1ii11iIi11i + OoO0O00 / I1Ii111
class lisp_cache ( ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 58 - 58: Oo0Ooo / II111iiii % OoooooooOO % II111iiii
  if 39 - 39: i1IIi
 def cache_size ( self ) :
  return ( self . cache_count )
  if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
  if 59 - 59: i1IIi
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   iI11i = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   iI11i = prefix . mask_len
  else :
   iI11i = prefix . mask_len + 48
   if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
   if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
  o0OoO0000o = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  O0ooo0 = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    IiiI1iii1iIiiI = prefix . addr_length ( ) * 2
    IiiIIi1 = lisp_hex_string ( prefix . address ) . zfill ( IiiI1iii1iIiiI )
   else :
    IiiIIi1 = prefix . address
    if 71 - 71: OOooOOo
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   O0ooo0 = "8003"
   IiiIIi1 = prefix . address . print_geo ( )
  else :
   O0ooo0 = ""
   IiiIIi1 = ""
   if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
   if 73 - 73: iII111i / I1IiiI * ooOoO0o
  Oo000O000 = o0OoO0000o + O0ooo0 + IiiIIi1
  return ( [ iI11i , Oo000O000 ] )
  if 85 - 85: I11i + I11i + oO0o - OoOoOO00
  if 15 - 15: OoO0O00
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  iI11i , Oo000O000 = self . build_key ( prefix )
  if ( self . cache . has_key ( iI11i ) == False ) :
   self . cache [ iI11i ] = lisp_cache_entries ( )
   self . cache [ iI11i ] . entries = { }
   self . cache [ iI11i ] . entries_sorted = [ ]
   self . cache_sorted = sorted ( self . cache )
   if 88 - 88: Ii1I % i1IIi / I1Ii111
  if ( self . cache [ iI11i ] . entries . has_key ( Oo000O000 ) == False ) :
   self . cache_count += 1
   if 2 - 2: Ii1I . IiII % OoOoOO00
  self . cache [ iI11i ] . entries [ Oo000O000 ] = entry
  self . cache [ iI11i ] . entries_sorted = sorted ( self . cache [ iI11i ] . entries )
  if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
  if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
 def lookup_cache ( self , prefix , exact ) :
  iIOO , Oo000O000 = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( iIOO ) == False ) : return ( None )
   if ( self . cache [ iIOO ] . entries . has_key ( Oo000O000 ) == False ) : return ( None )
   return ( self . cache [ iIOO ] . entries [ Oo000O000 ] )
   if 53 - 53: i1IIi * OOooOOo - IiII * Oo0Ooo / OoooooooOO + OoooooooOO
   if 10 - 10: oO0o - O0 / Ii1I - OOooOOo - I1Ii111
  O00o0 = None
  for iI11i in self . cache_sorted :
   if ( iIOO < iI11i ) : return ( O00o0 )
   for IiIi in self . cache [ iI11i ] . entries_sorted :
    OoOOo00o0 = self . cache [ iI11i ] . entries
    if ( IiIi in OoOOo00o0 ) :
     i1ii1i1Ii11 = OoOOo00o0 [ IiIi ]
     if ( i1ii1i1Ii11 == None ) : continue
     if ( prefix . is_more_specific ( i1ii1i1Ii11 . eid ) ) : O00o0 = i1ii1i1Ii11
     if 66 - 66: iIii1I11I1II1
     if 86 - 86: o0oOOo0O0Ooo % iIii1I11I1II1
     if 46 - 46: Oo0Ooo . Ii1I
  return ( O00o0 )
  if 23 - 23: I1IiiI . IiII - I1ii11iIi11i % Ii1I
  if 89 - 89: ooOoO0o - Ii1I / OoooooooOO
 def delete_cache ( self , prefix ) :
  iI11i , Oo000O000 = self . build_key ( prefix )
  if ( self . cache . has_key ( iI11i ) == False ) : return
  if ( self . cache [ iI11i ] . entries . has_key ( Oo000O000 ) == False ) : return
  self . cache [ iI11i ] . entries . pop ( Oo000O000 )
  self . cache [ iI11i ] . entries_sorted . remove ( Oo000O000 )
  self . cache_count -= 1
  if 29 - 29: Oo0Ooo . IiII / I1ii11iIi11i
  if 19 - 19: O0
 def walk_cache ( self , function , parms ) :
  for iI11i in self . cache_sorted :
   for Oo000O000 in self . cache [ iI11i ] . entries_sorted :
    i1ii1i1Ii11 = self . cache [ iI11i ] . entries [ Oo000O000 ]
    oO0OOo0o0o , parms = function ( i1ii1i1Ii11 , parms )
    if ( oO0OOo0o0o == False ) : return ( parms )
    if 2 - 2: I1Ii111 - ooOoO0o + oO0o + OoOoOO00 / O0 * ooOoO0o
    if 26 - 26: i11iIiiIii - OoooooooOO + i11iIiiIii
  return ( parms )
  if 79 - 79: Oo0Ooo * oO0o . oO0o / Oo0Ooo * IiII
  if 14 - 14: Ii1I % I1IiiI / oO0o + OoO0O00 * ooOoO0o . Oo0Ooo
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 99 - 99: IiII * OOooOOo - OoOoOO00 + IiII
  for iI11i in self . cache_sorted :
   for Oo000O000 in self . cache [ iI11i ] . entries_sorted :
    i1ii1i1Ii11 = self . cache [ iI11i ] . entries [ Oo000O000 ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( iI11i , Oo000O000 ,
 i1ii1i1Ii11 ) )
    if 22 - 22: ooOoO0o - I1Ii111 - II111iiii / IiII + iII111i
    if 5 - 5: O0 * Ii1I
    if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
    if 77 - 77: OOooOOo / OoooooooOO
    if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
    if 79 - 79: i11iIiiIii % o0oOOo0O0Ooo * II111iiii . i1IIi * Ii1I - i11iIiiIii
    if 31 - 31: IiII / o0oOOo0O0Ooo
    if 27 - 27: Oo0Ooo
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
if 35 - 35: o0oOOo0O0Ooo % iII111i / O0 * I1IiiI . o0oOOo0O0Ooo / OOooOOo
if 81 - 81: I1ii11iIi11i - i11iIiiIii
if 49 - 49: iII111i * I11i - II111iiii . o0oOOo0O0Ooo
if 52 - 52: Ii1I + Ii1I - II111iiii . O0 + I1ii11iIi11i
if 60 - 60: i11iIiiIii + IiII
if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
def lisp_map_cache_lookup ( source , dest ) :
 if 86 - 86: Ii1I / oO0o
 OO00o0oO0O00 = dest . is_multicast_address ( )
 if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
 if 60 - 60: II111iiii / Ii1I
 if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
 if 89 - 89: i1IIi / I1Ii111 + Ii1I - i1IIi
 I1iOo0 = lisp_map_cache . lookup_cache ( dest , False )
 if ( I1iOo0 == None ) :
  I11i11i1 = source . print_sg ( dest ) if OO00o0oO0O00 else dest . print_address ( )
  I11i11i1 = green ( I11i11i1 , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( I11i11i1 ) )
  return ( None )
  if 66 - 66: OoooooooOO
  if 68 - 68: iII111i + I1Ii111
  if 90 - 90: o0oOOo0O0Ooo
  if 48 - 48: iII111i + Ii1I
  if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
 if ( OO00o0oO0O00 == False ) :
  Oo00oOoo = green ( I1iOo0 . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , Oo00oOoo ) )
  if 89 - 89: OOooOOo - I1Ii111 - iII111i
  return ( I1iOo0 )
  if 67 - 67: oO0o
  if 76 - 76: I1IiiI % I1IiiI - IiII / OoOoOO00 / I1ii11iIi11i
  if 42 - 42: I1IiiI + I1ii11iIi11i + Oo0Ooo * i1IIi - II111iiii
  if 15 - 15: o0oOOo0O0Ooo
  if 60 - 60: I1ii11iIi11i / I1Ii111
 I1iOo0 = I1iOo0 . lookup_source_cache ( source , False )
 if ( I1iOo0 == None ) :
  I11i11i1 = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( I11i11i1 ) )
  return ( None )
  if 13 - 13: I1Ii111
  if 52 - 52: II111iiii / OoO0O00 . Ii1I
  if 68 - 68: iII111i
  if 67 - 67: I1IiiI * I1IiiI
  if 100 - 100: iII111i * iII111i . Oo0Ooo
 Oo00oOoo = green ( I1iOo0 . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , Oo00oOoo ) )
 if 10 - 10: Oo0Ooo % ooOoO0o * Oo0Ooo
 return ( I1iOo0 )
 if 48 - 48: ooOoO0o + II111iiii
 if 73 - 73: II111iiii
 if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
 if 35 - 35: II111iiii + IiII
 if 66 - 66: o0oOOo0O0Ooo % IiII
 if 39 - 39: IiII
 if 18 - 18: iII111i % o0oOOo0O0Ooo - i1IIi
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  iiooOOOoOo00O0O = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( iiooOOOoOo00O0O )
  if 53 - 53: o0oOOo0O0Ooo + IiII - ooOoO0o % i11iIiiIii - i11iIiiIii - I1Ii111
  if 79 - 79: II111iiii + i11iIiiIii . OOooOOo . I11i / iIii1I11I1II1
  if 62 - 62: O0
  if 52 - 52: OoooooooOO . oO0o
  if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 21 - 21: i11iIiiIii + II111iiii - i1IIi / OoooooooOO * OOooOOo % Oo0Ooo
 if 59 - 59: Ii1I
 if 77 - 77: I1ii11iIi11i * Ii1I * O0 * I1IiiI % OoO0O00 - iIii1I11I1II1
 if 6 - 6: i11iIiiIii . I11i - OoooooooOO
 if 26 - 26: I1IiiI
 if 26 - 26: IiII . Ii1I / IiII - OoO0O00 % OoO0O00
 iiooOOOoOo00O0O = lisp_referral_cache . lookup_cache ( group , exact )
 if ( iiooOOOoOo00O0O == None ) : return ( None )
 if 72 - 72: OoooooooOO * II111iiii + OoO0O00 % iIii1I11I1II1 . I1ii11iIi11i % OoooooooOO
 iI1iIi = iiooOOOoOo00O0O . lookup_source_cache ( eid , exact )
 if ( iI1iIi ) : return ( iI1iIi )
 if 58 - 58: I1ii11iIi11i * O0 . OoOoOO00
 if ( exact ) : iiooOOOoOo00O0O = None
 return ( iiooOOOoOo00O0O )
 if 87 - 87: oO0o - OoOoOO00
 if 40 - 40: iII111i . iII111i
 if 68 - 68: OoO0O00 / OoO0O00 - I1IiiI + OoOoOO00
 if 22 - 22: iIii1I11I1II1 . i1IIi . OOooOOo % Oo0Ooo - i1IIi
 if 78 - 78: I1IiiI / i1IIi % II111iiii % I1IiiI % Ii1I
 if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
 if 38 - 38: IiII . I1Ii111
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  oO0Oo0000OO0 = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( oO0Oo0000OO0 )
  if 69 - 69: ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + Ii1I . ooOoO0o
  if 73 - 73: I11i % I11i . ooOoO0o + OoOoOO00
  if 33 - 33: i11iIiiIii . i11iIiiIii * i11iIiiIii / iIii1I11I1II1 / I1ii11iIi11i . ooOoO0o
  if 11 - 11: iII111i
  if 60 - 60: I1ii11iIi11i / I1Ii111
 if ( eid . is_null ( ) ) : return ( None )
 if 10 - 10: OoO0O00 * iIii1I11I1II1 / I11i % II111iiii . OoOoOO00 / I1IiiI
 if 4 - 4: Oo0Ooo * o0oOOo0O0Ooo
 if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
 if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
 if 69 - 69: iII111i % I1ii11iIi11i
 if 19 - 19: IiII
 oO0Oo0000OO0 = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( oO0Oo0000OO0 == None ) : return ( None )
 if 35 - 35: OoOoOO00
 IiIIIIiI11i = oO0Oo0000OO0 . lookup_source_cache ( eid , exact )
 if ( IiIIIIiI11i ) : return ( IiIIIIiI11i )
 if 29 - 29: i11iIiiIii - oO0o - oO0o + I11i . OOooOOo . OoO0O00
 if ( exact ) : oO0Oo0000OO0 = None
 return ( oO0Oo0000OO0 )
 if 94 - 94: oO0o - o0oOOo0O0Ooo / I1ii11iIi11i . IiII - II111iiii - ooOoO0o
 if 92 - 92: OoooooooOO + O0 * OOooOOo
 if 1 - 1: O0
 if 34 - 34: o0oOOo0O0Ooo * i1IIi + I1Ii111
 if 46 - 46: IiII / i11iIiiIii
 if 51 - 51: OoO0O00 - OoO0O00 + o0oOOo0O0Ooo * iII111i % II111iiii
 if 7 - 7: O0 * OoO0O00 % IiII
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 76 - 76: iII111i - i1IIi
 if ( group . is_null ( ) ) :
  I1iiiI1I1 = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( I1iiiI1I1 )
  if 62 - 62: Ii1I + O0 % I1IiiI
  if 44 - 44: i11iIiiIii
  if 21 - 21: OOooOOo
  if 15 - 15: I1ii11iIi11i + oO0o
  if 99 - 99: oO0o - ooOoO0o - II111iiii * OoooooooOO / O0
 if ( eid . is_null ( ) ) : return ( None )
 if 57 - 57: iIii1I11I1II1 / IiII + OoO0O00 * oO0o + Ii1I
 if 76 - 76: i11iIiiIii . OOooOOo / I11i * oO0o % iIii1I11I1II1 . ooOoO0o
 if 75 - 75: O0 + I1IiiI
 if 67 - 67: OoOoOO00 % OoooooooOO / OoO0O00 - OoO0O00 / O0
 if 19 - 19: iIii1I11I1II1 / OOooOOo % I11i % I1IiiI / I1ii11iIi11i
 if 73 - 73: II111iiii
 I1iiiI1I1 = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( I1iiiI1I1 == None ) : return ( None )
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
 if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
 if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
 O0OOO0OOo0 = I1iiiI1I1 . lookup_source_cache ( eid , exact )
 if ( O0OOO0OOo0 ) : return ( O0OOO0OOo0 )
 if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
 if ( exact ) :
  I1iiiI1I1 = None
 else :
  O00oOO0OO00 = I1iiiI1I1 . parent_for_more_specifics
  if ( O00oOO0OO00 and O00oOO0OO00 . accept_more_specifics ) :
   if ( group . is_more_specific ( O00oOO0OO00 . group ) ) : I1iiiI1I1 = O00oOO0OO00
   if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
   if 65 - 65: I1IiiI . ooOoO0o
 return ( I1iiiI1I1 )
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
 if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
 if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
 if 56 - 56: Ii1I . iII111i
 if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
 if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
 if 52 - 52: i11iIiiIii
 if 1 - 1: i1IIi * iIii1I11I1II1
 if 29 - 29: I11i
class lisp_address ( ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
  if 6 - 6: IiII / OoO0O00
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
  if 77 - 77: Ii1I
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 9 - 9: OOooOOo / OoooooooOO + iII111i
  if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 20 - 20: I1Ii111
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
   if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
   if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 56 - 56: iII111i * II111iiii . OoooooooOO . I11i
  if 25 - 25: ooOoO0o % o0oOOo0O0Ooo - i11iIiiIii
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  IiiIIi1 = self . address
  if ( ( ( IiiIIi1 & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( IiiIIi1 & 0xff000000 ) >> 24 ) == 172 ) :
   O00OooOO = ( IiiIIi1 & 0x00ff0000 ) >> 16
   if ( O00OooOO >= 16 and O00OooOO <= 31 ) : return ( True )
   if 5 - 5: I1ii11iIi11i + IiII + I1ii11iIi11i
  if ( ( ( IiiIIi1 & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 28 - 28: Ii1I % o0oOOo0O0Ooo * IiII
  if 20 - 20: OoOoOO00 / I11i * O0 + Ii1I - OoOoOO00 % ooOoO0o
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 99 - 99: o0oOOo0O0Ooo / i1IIi * OOooOOo % iII111i
  if 18 - 18: iII111i * i1IIi / II111iiii / Oo0Ooo
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 47 - 47: Ii1I / i1IIi - iII111i - i11iIiiIii
  return ( 0 )
  if 3 - 3: OoOoOO00
  if 53 - 53: II111iiii / II111iiii . O0 - oO0o . i1IIi
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  IiiIIi1 = self . address >> 96
  return ( IiiIIi1 == 0x20010005 )
  if 45 - 45: OoOoOO00 + I1Ii111 + Oo0Ooo
  if 73 - 73: OoO0O00 / o0oOOo0O0Ooo % Ii1I * ooOoO0o
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
   if 94 - 94: I1IiiI . iII111i - iIii1I11I1II1 . Oo0Ooo
  return ( 0 )
  if 40 - 40: Ii1I
  if 26 - 26: OoO0O00 / IiII
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 31 - 31: Ii1I / OoO0O00 % ooOoO0o / I11i . I1ii11iIi11i
  if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
 def packet_format ( self ) :
  if 81 - 81: I1Ii111 % OoO0O00 / O0
  if 55 - 55: i1IIi - I1Ii111 + I11i
  if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
  if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
  if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
  if 34 - 34: I1IiiI + I1Ii111 % ooOoO0o
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
   i1IiiIiI11I = IiiIIi1 & 0xffff
   IiiiIi1iiii11 = struct . pack ( i1I1iii1I11II , ooOo0O0 , ooo0 , i1IiiIiI11I )
  elif ( self . is_e164 ( ) ) :
   IiiIIi1 = self . address
   ooOo0O0 = ( IiiIIi1 >> 32 ) & 0xffffffff
   ooo0 = ( IiiIIi1 & 0xffffffff )
   IiiiIi1iiii11 = struct . pack ( i1I1iii1I11II , ooOo0O0 , ooo0 )
  elif ( self . is_dist_name ( ) ) :
   IiiiIi1iiii11 += self . address + "\0"
   if 96 - 96: i1IIi % OoooooooOO * OOooOOo - Oo0Ooo + iIii1I11I1II1
  return ( IiiiIi1iiii11 )
  if 87 - 87: I11i . I1ii11iIi11i / i1IIi - II111iiii - i11iIiiIii
  if 49 - 49: I1ii11iIi11i + I1Ii111 * OOooOOo - IiII . i11iIiiIii
 def unpack_address ( self , packet ) :
  i1I1iii1I11II = self . packet_format ( )
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 34 - 34: iII111i . OoOoOO00
  IiiIIi1 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( IiiIIi1 [ 0 ] )
   if 20 - 20: I1ii11iIi11i . iIii1I11I1II1 - Ii1I % OoO0O00
  elif ( self . is_ipv6 ( ) ) :
   if 27 - 27: iIii1I11I1II1 / I1Ii111 - I11i . OoO0O00 + ooOoO0o
   if 89 - 89: I1IiiI % I11i - OOooOOo
   if 71 - 71: OOooOOo % Oo0Ooo - o0oOOo0O0Ooo / I1Ii111 - O0 - oO0o
   if 10 - 10: I1IiiI
   if 17 - 17: i11iIiiIii % o0oOOo0O0Ooo . ooOoO0o
   if 34 - 34: OoooooooOO / iII111i / O0
   if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
   if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
   if ( IiiIIi1 [ 0 ] <= 0xffff and ( IiiIIi1 [ 0 ] & 0xff ) == 0 ) :
    Oo00O0o0oOoO = ( IiiIIi1 [ 0 ] << 48 ) << 64
   else :
    Oo00O0o0oOoO = byte_swap_64 ( IiiIIi1 [ 0 ] ) << 64
    if 69 - 69: OoO0O00 + Ii1I
   IiiIii1 = byte_swap_64 ( IiiIIi1 [ 1 ] )
   self . address = Oo00O0o0oOoO | IiiIii1
   if 31 - 31: I1Ii111 / OoooooooOO * I11i . ooOoO0o
  elif ( self . is_mac ( ) ) :
   OOOoO = IiiIIi1 [ 0 ]
   oO0Oo0OO0O0 = IiiIIi1 [ 1 ]
   OoOooOo0o0O0o = IiiIIi1 [ 2 ]
   self . address = ( OOOoO << 32 ) + ( oO0Oo0OO0O0 << 16 ) + OoOooOo0o0O0o
   if 70 - 70: O0
  elif ( self . is_e164 ( ) ) :
   self . address = ( IiiIIi1 [ 0 ] << 32 ) + IiiIIi1 [ 1 ]
   if 100 - 100: o0oOOo0O0Ooo . Ii1I + ooOoO0o * I1IiiI
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   Iiiii = 0
   if 3 - 3: II111iiii % OoO0O00 . Ii1I * i11iIiiIii % I1Ii111
  packet = packet [ Iiiii : : ]
  return ( packet )
  if 73 - 73: OoO0O00 + I1Ii111 % OoooooooOO / o0oOOo0O0Ooo + I1Ii111 / i1IIi
  if 71 - 71: iIii1I11I1II1 + i1IIi
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 48 - 48: ooOoO0o % OoooooooOO - OOooOOo
  if 22 - 22: ooOoO0o / Ii1I / OoOoOO00 / I1Ii111 * OoOoOO00 + I1Ii111
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 94 - 94: i1IIi - iIii1I11I1II1 / Ii1I
  if 51 - 51: oO0o
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
  if 35 - 35: o0oOOo0O0Ooo % II111iiii + O0
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 70 - 70: I1ii11iIi11i . II111iiii
  if 54 - 54: OOooOOo
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 67 - 67: I1IiiI . o0oOOo0O0Ooo / i1IIi * I1ii11iIi11i . Oo0Ooo + II111iiii
  if 63 - 63: OoOoOO00 - OoOoOO00
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 31 - 31: I1ii11iIi11i % O0 - i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o * ooOoO0o
  if 18 - 18: OoO0O00 - OoO0O00 . o0oOOo0O0Ooo
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 80 - 80: I11i + I1Ii111 / I1IiiI * OOooOOo % iII111i
  if 48 - 48: iIii1I11I1II1 + i1IIi . I1IiiI % OoO0O00 - iIii1I11I1II1 / i1IIi
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 14 - 14: IiII . I11i
  if 13 - 13: OoOoOO00 - I11i . OOooOOo % OoO0O00
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
  if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
  if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 9 - 9: iIii1I11I1II1
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
  if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
  if 34 - 34: iIii1I11I1II1
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 65 - 65: II111iiii - iII111i / o0oOOo0O0Ooo
  if 35 - 35: i11iIiiIii - Oo0Ooo . I1ii11iIi11i % OoOoOO00
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 20 - 20: OoO0O00
  if 93 - 93: ooOoO0o + o0oOOo0O0Ooo - I1ii11iIi11i
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 56 - 56: Ii1I / Oo0Ooo
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 96 - 96: o0oOOo0O0Ooo . II111iiii
  return ( False )
  if 14 - 14: OoooooooOO - i1IIi / i11iIiiIii - OOooOOo - i11iIiiIii . ooOoO0o
  if 8 - 8: oO0o * O0 - II111iiii + I1IiiI
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 85 - 85: OoooooooOO % i11iIiiIii / IiII % OoOoOO00 + O0
  if 6 - 6: OoooooooOO
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 97 - 97: II111iiii + o0oOOo0O0Ooo * II111iiii
  if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
  if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
  if 14 - 14: OOooOOo * IiII
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
  if 33 - 33: OoO0O00
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 91 - 91: I11i % I11i % iII111i
  if 19 - 19: I11i / I11i + I1IiiI * OoO0O00 - iII111i . Oo0Ooo
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 76 - 76: iII111i % OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % i1IIi
  if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 38 - 38: OoOoOO00 % OoooooooOO . oO0o - OoooooooOO + I11i
  if 18 - 18: OoooooooOO + ooOoO0o * OoOoOO00 - OoO0O00
  if 42 - 42: oO0o % OoOoOO00 - oO0o + I11i / i11iIiiIii
  if 74 - 74: OoO0O00 - II111iiii - ooOoO0o % i1IIi
  IiIIi1IiiIiI = addr_str . find ( "[" )
  oooOi1II1II111 = addr_str . find ( "]" )
  if ( IiIIi1IiiIiI != - 1 and oooOi1II1II111 != - 1 ) :
   self . instance_id = int ( addr_str [ IiIIi1IiiIiI + 1 : oooOi1II1II111 ] )
   addr_str = addr_str [ oooOi1II1II111 + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 42 - 42: i11iIiiIii / O0
    if 8 - 8: I1Ii111
    if 51 - 51: i11iIiiIii
    if 1 - 1: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i
    if 58 - 58: i11iIiiIii * i11iIiiIii - OoO0O00
    if 8 - 8: i11iIiiIii * OoOoOO00 . o0oOOo0O0Ooo
  if ( self . is_ipv4 ( ) ) :
   iI111ii1III = addr_str . split ( "." )
   i11II = int ( iI111ii1III [ 0 ] ) << 24
   i11II += int ( iI111ii1III [ 1 ] ) << 16
   i11II += int ( iI111ii1III [ 2 ] ) << 8
   i11II += int ( iI111ii1III [ 3 ] )
   self . address = i11II
  elif ( self . is_ipv6 ( ) ) :
   if 47 - 47: OoOoOO00 . iIii1I11I1II1 * i11iIiiIii
   if 83 - 83: I1IiiI . i11iIiiIii * iII111i
   if 96 - 96: OoOoOO00
   if 84 - 84: OOooOOo
   if 68 - 68: I1Ii111
   if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
   if 54 - 54: oO0o + I11i - OoO0O00
   if 86 - 86: OoooooooOO
   if 51 - 51: i11iIiiIii
   if 91 - 91: OOooOOo
   if 22 - 22: OoooooooOO + OoOoOO00 - Ii1I . iII111i / OoooooooOO / I1IiiI
   if 73 - 73: i1IIi - Ii1I + oO0o * iIii1I11I1II1
   if 100 - 100: i11iIiiIii / iIii1I11I1II1 + Oo0Ooo + OoO0O00 - iII111i
   if 8 - 8: i11iIiiIii . O0 + o0oOOo0O0Ooo * oO0o + II111iiii
   if 61 - 61: ooOoO0o / ooOoO0o
   if 51 - 51: iIii1I11I1II1 / oO0o * I1Ii111 + i1IIi
   if 96 - 96: Oo0Ooo + oO0o - Oo0Ooo - OoOoOO00 % OOooOOo . iIii1I11I1II1
   oooo0ooOOo = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 67 - 67: o0oOOo0O0Ooo . I1Ii111 % iIii1I11I1II1 / I1Ii111
   addr_str = binascii . hexlify ( addr_str )
   if 18 - 18: I11i * ooOoO0o
   if ( oooo0ooOOo ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 46 - 46: IiII
   self . address = int ( addr_str , 16 )
   if 96 - 96: iII111i / i11iIiiIii + Oo0Ooo . I1IiiI + iII111i % OoOoOO00
  elif ( self . is_geo_prefix ( ) ) :
   IIiIiiIIiI = lisp_geo ( None )
   IIiIiiIIiI . name = "geo-prefix-{}" . format ( IIiIiiIIiI )
   IIiIiiIIiI . parse_geo_string ( addr_str )
   self . address = IIiIiiIIiI
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
   if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
  self . mask_len = self . host_mask_len ( )
  if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
  if 87 - 87: iII111i
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
   if 86 - 86: IiII - I11i
   if 99 - 99: i1IIi + I1ii11iIi11i
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( OO00O )
  if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
  if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  iiIIi = ( 2 ** self . mask_len ) - 1
  o0O0OO = self . addr_length ( ) * 8 - self . mask_len
  iiIIi <<= o0O0OO
  self . address &= iiIIi
  if 35 - 35: OoooooooOO . o0oOOo0O0Ooo % I11i - Oo0Ooo % oO0o
  if 96 - 96: O0 / IiII
 def is_geo_string ( self , addr_str ) :
  ooo = addr_str . find ( "]" )
  if ( ooo != - 1 ) : addr_str = addr_str [ ooo + 1 : : ]
  if 4 - 4: II111iiii * o0oOOo0O0Ooo - IiII * iII111i
  IIiIiiIIiI = addr_str . split ( "/" )
  if ( len ( IIiIiiIIiI ) == 2 ) :
   if ( IIiIiiIIiI [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 91 - 91: I1Ii111 * iII111i * OoO0O00
  IIiIiiIIiI = IIiIiiIIiI [ 0 ]
  IIiIiiIIiI = IIiIiiIIiI . split ( "-" )
  o0Oo0O0 = len ( IIiIiiIIiI )
  if ( o0Oo0O0 < 8 or o0Oo0O0 > 9 ) : return ( False )
  if 9 - 9: ooOoO0o . O0 + II111iiii . OoooooooOO
  for oooOoooOoo00o in range ( 0 , o0Oo0O0 ) :
   if ( oooOoooOoo00o == 3 ) :
    if ( IIiIiiIIiI [ oooOoooOoo00o ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 24 - 24: OoooooooOO % iII111i . II111iiii - O0 . i1IIi % Ii1I
   if ( oooOoooOoo00o == 7 ) :
    if ( IIiIiiIIiI [ oooOoooOoo00o ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 65 - 65: Oo0Ooo
   if ( IIiIiiIIiI [ oooOoooOoo00o ] . isdigit ( ) == False ) : return ( False )
   if 64 - 64: I1ii11iIi11i * OoOoOO00 + II111iiii . I11i - I1IiiI * O0
  return ( True )
  if 74 - 74: OoO0O00 * O0 - oO0o * OoooooooOO % I1Ii111
  if 95 - 95: OoOoOO00 + ooOoO0o . iIii1I11I1II1 * o0oOOo0O0Ooo
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 75 - 75: OOooOOo - i11iIiiIii - i1IIi - IiII * iII111i
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 38 - 38: o0oOOo0O0Ooo - I1ii11iIi11i % o0oOOo0O0Ooo
  if 8 - 8: oO0o + I11i . I1ii11iIi11i
 def print_address ( self ) :
  IiiIIi1 = self . print_address_no_iid ( )
  o0OoO0000o = "[" + str ( self . instance_id )
  for IiIIi1IiiIiI in self . iid_list : o0OoO0000o += "," + str ( IiIIi1IiiIiI )
  o0OoO0000o += "]"
  IiiIIi1 = "{}{}" . format ( o0OoO0000o , IiiIIi1 )
  return ( IiiIIi1 )
  if 57 - 57: I11i
  if 46 - 46: iII111i . OoO0O00 % Ii1I
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   IiiIIi1 = self . address
   I11III1I1II = IiiIIi1 >> 24
   Oo0o0OoOo = ( IiiIIi1 >> 16 ) & 0xff
   IiIiIII1 = ( IiiIIi1 >> 8 ) & 0xff
   iI1iI11i1 = IiiIIi1 & 0xff
   return ( "{}.{}.{}.{}" . format ( I11III1I1II , Oo0o0OoOo , IiIiIII1 , iI1iI11i1 ) )
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
   if 100 - 100: i1IIi . I1IiiI . OOooOOo % Ii1I - IiII - ooOoO0o
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 99 - 99: I1ii11iIi11i * I1IiiI % iII111i % Ii1I + O0
  if 53 - 53: i11iIiiIii % I1ii11iIi11i
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   oO0OoOo0oo = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , oO0OoOo0oo ) )
   if 63 - 63: IiII + oO0o + II111iiii * I11i
  IiiIIi1 = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( IiiIIi1 )
  if ( self . is_geo_prefix ( ) ) : return ( IiiIIi1 )
  if 49 - 49: OoO0O00
  ooo = IiiIIi1 . find ( "no-address" )
  if ( ooo == - 1 ) :
   IiiIIi1 = "{}/{}" . format ( IiiIIi1 , str ( self . mask_len ) )
  else :
   IiiIIi1 = IiiIIi1 [ 0 : ooo ]
   if 78 - 78: I1IiiI - I1ii11iIi11i
  return ( IiiIIi1 )
  if 24 - 24: Ii1I + I11i
  if 5 - 5: I1Ii111 . Ii1I - ooOoO0o % OoooooooOO
 def print_prefix_no_iid ( self ) :
  IiiIIi1 = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( IiiIIi1 )
  if ( self . is_geo_prefix ( ) ) : return ( IiiIIi1 )
  return ( "{}/{}" . format ( IiiIIi1 , str ( self . mask_len ) ) )
  if 2 - 2: OOooOOo . IiII . iII111i / Oo0Ooo
  if 86 - 86: OOooOOo . o0oOOo0O0Ooo - iIii1I11I1II1
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  IiiIIi1 = self . print_address ( )
  ooo = IiiIIi1 . find ( "]" )
  if ( ooo != - 1 ) : IiiIIi1 = IiiIIi1 [ ooo + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   IiiIIi1 = IiiIIi1 . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , IiiIIi1 ) )
   if 12 - 12: oO0o + iII111i
  return ( "{}-{}-{}" . format ( self . instance_id , IiiIIi1 , self . mask_len ) )
  if 16 - 16: O0 + oO0o - ooOoO0o * O0 . I1ii11iIi11i . oO0o
  if 4 - 4: I1Ii111
 def print_sg ( self , g ) :
  IiII1iiI = self . print_prefix ( )
  IIi1I11i1 = IiII1iiI . find ( "]" ) + 1
  g = g . print_prefix ( )
  i11OOO0oO = g . find ( "]" ) + 1
  II11I = "[{}]({}, {})" . format ( self . instance_id , IiII1iiI [ IIi1I11i1 : : ] , g [ i11OOO0oO : : ] )
  return ( II11I )
  if 35 - 35: OOooOOo / i1IIi + OoO0O00
  if 31 - 31: OoO0O00 . i1IIi / OoooooooOO
 def hash_address ( self , addr ) :
  ooOo0O0 = self . address
  ooo0 = addr . address
  if 81 - 81: ooOoO0o . Oo0Ooo . OoOoOO00 + OOooOOo % iII111i - oO0o
  if ( self . is_geo_prefix ( ) ) : ooOo0O0 = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : ooo0 = addr . address . print_geo ( )
  if 68 - 68: iII111i - O0 / Ii1I
  if ( type ( ooOo0O0 ) == str ) :
   ooOo0O0 = int ( binascii . hexlify ( ooOo0O0 [ 0 : 1 ] ) )
   if 15 - 15: I1Ii111 / I1ii11iIi11i / I1IiiI % i11iIiiIii + II111iiii . ooOoO0o
  if ( type ( ooo0 ) == str ) :
   ooo0 = int ( binascii . hexlify ( ooo0 [ 0 : 1 ] ) )
   if 74 - 74: o0oOOo0O0Ooo
  return ( ooOo0O0 ^ ooo0 )
  if 4 - 4: I1ii11iIi11i * II111iiii - Oo0Ooo % i1IIi % O0 * i11iIiiIii
  if 62 - 62: OoO0O00 * I1Ii111 * Ii1I / ooOoO0o
  if 27 - 27: oO0o . iII111i . oO0o
  if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
  if 14 - 14: I11i + ooOoO0o . oO0o * I11i
  if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
  OO00O = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   i1ii1ii1I = 2 ** ( 32 - OO00O )
   ii1111 = prefix . instance_id
   oO0OoOo0oo = ii1111 + i1ii1ii1I
   return ( self . instance_id in range ( ii1111 , oO0OoOo0oo ) )
   if 99 - 99: Ii1I - ooOoO0o % I1ii11iIi11i % Ii1I . OOooOOo
   if 10 - 10: o0oOOo0O0Ooo - OoooooooOO - iIii1I11I1II1 - o0oOOo0O0Ooo / iII111i
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 10 - 10: OoOoOO00 . i1IIi
   if 44 - 44: OOooOOo - OOooOOo * IiII - iIii1I11I1II1
   if 72 - 72: iIii1I11I1II1 . OoooooooOO
   if 44 - 44: I11i * I11i + OoooooooOO
   if 26 - 26: I1Ii111 * Ii1I
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   IiiIIi1 = self . address
   OOoO0Oo = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    IiiIIi1 = self . address . print_geo ( )
    OOoO0Oo = prefix . address . print_geo ( )
    if 28 - 28: I1IiiI
   if ( len ( IiiIIi1 ) < len ( OOoO0Oo ) ) : return ( False )
   return ( IiiIIi1 . find ( OOoO0Oo ) == 0 )
   if 59 - 59: OOooOOo . I1IiiI / i1IIi / II111iiii . II111iiii
   if 54 - 54: iIii1I11I1II1 % ooOoO0o
   if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
   if 92 - 92: I11i + OoO0O00 . OoooooooOO
   if 3 - 3: OoO0O00 % iIii1I11I1II1
  if ( self . mask_len < OO00O ) : return ( False )
  if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
  o0O0OO = ( prefix . addr_length ( ) * 8 ) - OO00O
  iiIIi = ( 2 ** OO00O - 1 ) << o0O0OO
  return ( ( self . address & iiIIi ) == prefix . address )
  if 59 - 59: iIii1I11I1II1
  if 18 - 18: ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
 def mask_address ( self , mask_len ) :
  o0O0OO = ( self . addr_length ( ) * 8 ) - mask_len
  iiIIi = ( 2 ** mask_len - 1 ) << o0O0OO
  self . address &= iiIIi
  if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
  if 63 - 63: I11i
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  OOoOI1i1Iii = self . print_prefix ( )
  III1 = prefix . print_prefix ( ) if prefix else ""
  return ( OOoOI1i1Iii == III1 )
  if 85 - 85: Ii1I - I1Ii111 % Ii1I / I11i % i1IIi / OoO0O00
  if 4 - 4: i11iIiiIii / i11iIiiIii
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   oooO0oO0OO0 = lisp_myrlocs [ 0 ]
   if ( oooO0oO0OO0 == None ) : return ( False )
   oooO0oO0OO0 = oooO0oO0OO0 . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == oooO0oO0OO0 )
   if 17 - 17: iIii1I11I1II1 - Ii1I + IiII . Oo0Ooo + i11iIiiIii
  if ( self . is_ipv6 ( ) ) :
   oooO0oO0OO0 = lisp_myrlocs [ 1 ]
   if ( oooO0oO0OO0 == None ) : return ( False )
   oooO0oO0OO0 = oooO0oO0OO0 . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == oooO0oO0OO0 )
   if 97 - 97: ooOoO0o % II111iiii / Ii1I . iIii1I11I1II1
  return ( False )
  if 100 - 100: II111iiii / I11i * iIii1I11I1II1 / OOooOOo + i11iIiiIii - iIii1I11I1II1
  if 32 - 32: o0oOOo0O0Ooo - Ii1I / ooOoO0o % I1Ii111
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid == 0 and mask_len == 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 69 - 69: oO0o - I1IiiI . OOooOOo * OoooooooOO
  self . instance_id = iid
  self . mask_len = mask_len
  if 83 - 83: IiII % I1Ii111 % IiII - O0 % I1ii11iIi11i
  if 44 - 44: i11iIiiIii + oO0o * oO0o . i11iIiiIii % i1IIi + iII111i
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
  if 91 - 91: I1Ii111 . II111iiii / Ii1I * O0
  if 33 - 33: oO0o * i1IIi + ooOoO0o * OOooOOo - O0 - iIii1I11I1II1
  if 35 - 35: I1Ii111
  if 12 - 12: Ii1I % I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
  if 12 - 12: Oo0Ooo + I1IiiI
  if 12 - 12: OoOoOO00 / II111iiii
  if 100 - 100: I1ii11iIi11i % iIii1I11I1II1 . IiII . OoooooooOO / II111iiii
  if 28 - 28: I1IiiI
  if 27 - 27: I1IiiI % oO0o - iIii1I11I1II1 - o0oOOo0O0Ooo - IiII - O0
  if 46 - 46: II111iiii
  if 24 - 24: i11iIiiIii * i1IIi - I11i + o0oOOo0O0Ooo
  if 60 - 60: ooOoO0o
  if 62 - 62: i11iIiiIii
  if 88 - 88: i11iIiiIii
  if 59 - 59: oO0o - OoooooooOO % ooOoO0o
  if 90 - 90: OoOoOO00
  if 96 - 96: II111iiii % Ii1I
 def lcaf_encode_iid ( self ) :
  iI1IIiI111iII = LISP_LCAF_INSTANCE_ID_TYPE
  Iii1i11 = socket . htons ( self . lcaf_length ( iI1IIiI111iII ) )
  o0OoO0000o = self . instance_id
  O0ooo0 = self . afi
  iI11i = 0
  if ( O0ooo0 < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    O0ooo0 = LISP_AFI_LCAF
    iI11i = 0
   else :
    O0ooo0 = 0
    iI11i = self . mask_len
    if 84 - 84: I1IiiI . I1IiiI
    if 82 - 82: OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1 + I1ii11iIi11i
    if 45 - 45: iII111i . oO0o * iII111i
  iIII = struct . pack ( "BBBBH" , 0 , 0 , iI1IIiI111iII , iI11i , Iii1i11 )
  iIII += struct . pack ( "IH" , socket . htonl ( o0OoO0000o ) , socket . htons ( O0ooo0 ) )
  if ( O0ooo0 == 0 ) : return ( iIII )
  if 36 - 36: O0 - iII111i + I11i + I1IiiI
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   iIII = iIII [ 0 : - 2 ]
   iIII += self . address . encode_geo ( )
   return ( iIII )
   if 89 - 89: OoOoOO00 / Ii1I - OoO0O00 % I11i - oO0o . Ii1I
   if 75 - 75: I11i * OoooooooOO % OoOoOO00 . i1IIi - Ii1I + iIii1I11I1II1
  iIII += self . pack_address ( )
  return ( iIII )
  if 74 - 74: ooOoO0o
  if 18 - 18: iIii1I11I1II1 - I11i - oO0o
 def lcaf_decode_iid ( self , packet ) :
  i1I1iii1I11II = "BBBBH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 12 - 12: O0 + O0 + ooOoO0o . I1IiiI * II111iiii
  O0O , OO0Oo00oo , iI1IIiI111iII , IiiIi1I1iiI , IiiI1iii1iIiiI = struct . unpack ( i1I1iii1I11II ,
 packet [ : Iiiii ] )
  packet = packet [ Iiiii : : ]
  if 30 - 30: ooOoO0o / ooOoO0o - Oo0Ooo
  if ( iI1IIiI111iII != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 60 - 60: I1ii11iIi11i
  i1I1iii1I11II = "IH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( None )
  if 91 - 91: iII111i
  o0OoO0000o , O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  packet = packet [ Iiiii : : ]
  if 99 - 99: OOooOOo / i11iIiiIii - oO0o / I1IiiI
  IiiI1iii1iIiiI = socket . ntohs ( IiiI1iii1iIiiI )
  self . instance_id = socket . ntohl ( o0OoO0000o )
  O0ooo0 = socket . ntohs ( O0ooo0 )
  self . afi = O0ooo0
  if ( IiiIi1I1iiI != 0 and O0ooo0 == 0 ) : self . mask_len = IiiIi1I1iiI
  if ( O0ooo0 == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if IiiIi1I1iiI else LISP_AFI_ULTIMATE_ROOT
   if 58 - 58: Oo0Ooo % iII111i
   if 43 - 43: oO0o * iII111i
   if 96 - 96: ooOoO0o % OOooOOo % OoO0O00 + OoOoOO00 % I11i
   if 85 - 85: ooOoO0o / iII111i / OoOoOO00 % I1ii11iIi11i
   if 1 - 1: I1ii11iIi11i + iIii1I11I1II1 . O0 + I1ii11iIi11i + I1IiiI + OOooOOo
  if ( O0ooo0 == 0 ) : return ( packet )
  if 63 - 63: iIii1I11I1II1 . iIii1I11I1II1 . Ii1I . i1IIi + I1Ii111
  if 65 - 65: i11iIiiIii * oO0o + OoO0O00
  if 86 - 86: iII111i - Ii1I / OoO0O00
  if 19 - 19: iIii1I11I1II1 / iII111i + OOooOOo . ooOoO0o
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 85 - 85: i1IIi
   if 78 - 78: oO0o
   if 6 - 6: IiII
   if 69 - 69: iII111i
   if 87 - 87: i11iIiiIii % o0oOOo0O0Ooo + Ii1I
  if ( O0ooo0 == LISP_AFI_LCAF ) :
   i1I1iii1I11II = "BBBBH"
   Iiiii = struct . calcsize ( i1I1iii1I11II )
   if ( len ( packet ) < Iiiii ) : return ( None )
   if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
   Ii1IiIIIi1i , II111Ii1I1I , iI1IIiI111iII , o00oo0oOo0o0 , oOOO0O000Oo = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
   if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
   if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
   if ( iI1IIiI111iII != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
   oOOO0O000Oo = socket . ntohs ( oOOO0O000Oo )
   packet = packet [ Iiiii : : ]
   if ( oOOO0O000Oo > len ( packet ) ) : return ( None )
   if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
   IIiIiiIIiI = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = IIiIiiIIiI
   packet = IIiIiiIIiI . decode_geo ( packet , oOOO0O000Oo , o00oo0oOo0o0 )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 90 - 90: II111iiii + OOooOOo % I1Ii111 * iIii1I11I1II1 % iIii1I11I1II1
   if 55 - 55: II111iiii % O0 * O0 - II111iiii * I1IiiI % Oo0Ooo
  Iii1i11 = self . addr_length ( )
  if ( len ( packet ) < Iii1i11 ) : return ( None )
  if 48 - 48: I1ii11iIi11i + OoooooooOO % i1IIi
  packet = self . unpack_address ( packet )
  return ( packet )
  if 46 - 46: OoOoOO00
  if 75 - 75: I1IiiI
  if 37 - 37: iIii1I11I1II1 % OoO0O00 * ooOoO0o + I11i % ooOoO0o / i11iIiiIii
  if 14 - 14: i1IIi / ooOoO0o
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
 def lcaf_encode_sg ( self , group ) :
  iI1IIiI111iII = LISP_LCAF_MCAST_INFO_TYPE
  o0OoO0000o = socket . htonl ( self . instance_id )
  Iii1i11 = socket . htons ( self . lcaf_length ( iI1IIiI111iII ) )
  iIII = struct . pack ( "BBBBHIHBB" , 0 , 0 , iI1IIiI111iII , 0 , Iii1i11 , o0OoO0000o ,
 0 , self . mask_len , group . mask_len )
  if 45 - 45: iIii1I11I1II1 - i1IIi % I1IiiI - I1Ii111 + oO0o
  iIII += struct . pack ( "H" , socket . htons ( self . afi ) )
  iIII += self . pack_address ( )
  iIII += struct . pack ( "H" , socket . htons ( group . afi ) )
  iIII += group . pack_address ( )
  return ( iIII )
  if 15 - 15: iIii1I11I1II1 - OoooooooOO / ooOoO0o
  if 83 - 83: IiII + I1Ii111 / OoOoOO00 * IiII . oO0o
 def lcaf_decode_sg ( self , packet ) :
  i1I1iii1I11II = "BBBBHIHBB"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( [ None , None ] )
  if 22 - 22: O0 + ooOoO0o + I1Ii111
  O0O , OO0Oo00oo , iI1IIiI111iII , i1o00Oo , IiiI1iii1iIiiI , o0OoO0000o , OOO , O0OI1iI , ooooOO0oo = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
  if 97 - 97: oO0o % OoOoOO00 . I1Ii111
  packet = packet [ Iiiii : : ]
  if 76 - 76: IiII % i1IIi / iIii1I11I1II1 - II111iiii * IiII + ooOoO0o
  if ( iI1IIiI111iII != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 9 - 9: oO0o / OOooOOo + II111iiii . i1IIi % I1IiiI / I1IiiI
  self . instance_id = socket . ntohl ( o0OoO0000o )
  IiiI1iii1iIiiI = socket . ntohs ( IiiI1iii1iIiiI ) - 8
  if 1 - 1: iIii1I11I1II1
  if 8 - 8: o0oOOo0O0Ooo % II111iiii * O0 . ooOoO0o
  if 96 - 96: I1ii11iIi11i / I11i - I1ii11iIi11i . I1Ii111 . i11iIiiIii . I11i
  if 93 - 93: OoO0O00 % I1ii11iIi11i * Ii1I . OoO0O00 % OOooOOo - OoooooooOO
  if 17 - 17: O0 + OOooOOo * ooOoO0o - i1IIi + OOooOOo
  i1I1iii1I11II = "H"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( [ None , None ] )
  if ( IiiI1iii1iIiiI < Iiiii ) : return ( [ None , None ] )
  if 30 - 30: OOooOOo / I1ii11iIi11i - iIii1I11I1II1 % i1IIi
  O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  IiiI1iii1iIiiI -= Iiiii
  self . afi = socket . ntohs ( O0ooo0 )
  self . mask_len = O0OI1iI
  Iii1i11 = self . addr_length ( )
  if ( IiiI1iii1iIiiI < Iii1i11 ) : return ( [ None , None ] )
  if 34 - 34: I1IiiI . II111iiii
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 100 - 100: OoO0O00 / O0 / OoOoOO00
  IiiI1iii1iIiiI -= Iii1i11
  if 33 - 33: i1IIi / o0oOOo0O0Ooo . OoooooooOO
  if 8 - 8: I1IiiI * OOooOOo * IiII / I1IiiI + i1IIi
  if 11 - 11: I11i * Ii1I * I1IiiI - I1IiiI % OoooooooOO
  if 83 - 83: i11iIiiIii % iII111i * O0 % OoooooooOO
  if 99 - 99: I1ii11iIi11i % I1ii11iIi11i * iII111i % oO0o
  i1I1iii1I11II = "H"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( [ None , None ] )
  if ( IiiI1iii1iIiiI < Iiiii ) : return ( [ None , None ] )
  if 56 - 56: Oo0Ooo + i11iIiiIii - oO0o . Ii1I + IiII
  O0ooo0 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  IiiI1iii1iIiiI -= Iiiii
  IIi1iiIII11 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  IIi1iiIII11 . afi = socket . ntohs ( O0ooo0 )
  IIi1iiIII11 . mask_len = ooooOO0oo
  IIi1iiIII11 . instance_id = self . instance_id
  Iii1i11 = self . addr_length ( )
  if ( IiiI1iii1iIiiI < Iii1i11 ) : return ( [ None , None ] )
  if 19 - 19: I11i * OoooooooOO . i1IIi
  packet = IIi1iiIII11 . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 100 - 100: II111iiii
  return ( [ packet , IIi1iiIII11 ] )
  if 95 - 95: iII111i
  if 94 - 94: OoOoOO00 + OoooooooOO
 def lcaf_decode_eid ( self , packet ) :
  i1I1iii1I11II = "BBB"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( [ None , None ] )
  if 92 - 92: i11iIiiIii * IiII * I1IiiI - oO0o / iII111i
  if 1 - 1: ooOoO0o - OoO0O00 - o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i - I1Ii111
  if 78 - 78: Oo0Ooo
  if 27 - 27: Ii1I / oO0o - Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo . Ii1I
  if 79 - 79: Ii1I % O0 * OOooOOo
  i1o00Oo , II111Ii1I1I , iI1IIiI111iII = struct . unpack ( i1I1iii1I11II ,
 packet [ : Iiiii ] )
  if 41 - 41: I1ii11iIi11i . OoooooooOO * I1ii11iIi11i - oO0o
  if ( iI1IIiI111iII == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( iI1IIiI111iII == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , IIi1iiIII11 = self . lcaf_decode_sg ( packet )
   return ( [ packet , IIi1iiIII11 ] )
  elif ( iI1IIiI111iII == LISP_LCAF_GEO_COORD_TYPE ) :
   i1I1iii1I11II = "BBBBH"
   Iiiii = struct . calcsize ( i1I1iii1I11II )
   if ( len ( packet ) < Iiiii ) : return ( None )
   if 40 - 40: I1IiiI % OoO0O00 + i11iIiiIii / oO0o
   Ii1IiIIIi1i , II111Ii1I1I , iI1IIiI111iII , o00oo0oOo0o0 , oOOO0O000Oo = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] )
   if 98 - 98: oO0o + iIii1I11I1II1 . ooOoO0o / I1ii11iIi11i
   if 77 - 77: OoOoOO00 / Oo0Ooo * OoOoOO00 % I1IiiI . II111iiii % OoO0O00
   if ( iI1IIiI111iII != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 38 - 38: iII111i - OoO0O00 / i1IIi + ooOoO0o . ooOoO0o . iII111i
   oOOO0O000Oo = socket . ntohs ( oOOO0O000Oo )
   packet = packet [ Iiiii : : ]
   if ( oOOO0O000Oo > len ( packet ) ) : return ( None )
   if 37 - 37: iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoooooooOO + OoO0O00
   IIiIiiIIiI = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = IIiIiiIIiI
   packet = IIiIiiIIiI . decode_geo ( packet , oOOO0O000Oo , o00oo0oOo0o0 )
   self . mask_len = self . host_mask_len ( )
   if 25 - 25: I1IiiI / IiII . OOooOOo . I1ii11iIi11i % i1IIi
  return ( [ packet , None ] )
  if 12 - 12: O0 % O0
  if 9 - 9: O0 . I1IiiI + I1ii11iIi11i / OOooOOo * I1ii11iIi11i
  if 10 - 10: IiII % o0oOOo0O0Ooo / O0 / II111iiii
  if 81 - 81: Ii1I / o0oOOo0O0Ooo % OoOoOO00 . I1ii11iIi11i
  if 47 - 47: II111iiii + OOooOOo / II111iiii . OOooOOo
  if 68 - 68: OoooooooOO
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 63 - 63: I1IiiI
  if 80 - 80: oO0o + iIii1I11I1II1
 def copy_elp_node ( self ) :
  IiiIIi1IiI = lisp_elp_node ( )
  IiiIIi1IiI . copy_address ( self . address )
  IiiIIi1IiI . probe = self . probe
  IiiIIi1IiI . strict = self . strict
  IiiIIi1IiI . eid = self . eid
  IiiIIi1IiI . we_are_last = self . we_are_last
  return ( IiiIIi1IiI )
  if 87 - 87: I1ii11iIi11i % Ii1I . Ii1I
  if 71 - 71: OoO0O00 - IiII . i1IIi * I1IiiI % I11i
  if 36 - 36: IiII * OoooooooOO . i11iIiiIii * i1IIi
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 52 - 52: IiII + ooOoO0o - II111iiii - OoooooooOO * OoO0O00 - iIii1I11I1II1
  if 38 - 38: II111iiii % iIii1I11I1II1 * IiII * OoOoOO00 % II111iiii . I1IiiI
 def copy_elp ( self ) :
  OO0o00O = lisp_elp ( self . elp_name )
  OO0o00O . use_elp_node = self . use_elp_node
  OO0o00O . we_are_last = self . we_are_last
  for IiiIIi1IiI in self . elp_nodes :
   OO0o00O . elp_nodes . append ( IiiIIi1IiI . copy_elp_node ( ) )
   if 35 - 35: OoooooooOO - i11iIiiIii * i11iIiiIii % Ii1I - OOooOOo . iIii1I11I1II1
  return ( OO0o00O )
  if 96 - 96: OOooOOo
  if 18 - 18: oO0o . I1ii11iIi11i % oO0o
 def print_elp ( self , want_marker ) :
  i11IiIii11i = ""
  for IiiIIi1IiI in self . elp_nodes :
   IIi1IIi = ""
   if ( want_marker ) :
    if ( IiiIIi1IiI == self . use_elp_node ) :
     IIi1IIi = "*"
    elif ( IiiIIi1IiI . we_are_last ) :
     IIi1IIi = "x"
     if 96 - 96: Ii1I % I11i * OoooooooOO . I1IiiI . iIii1I11I1II1
     if 8 - 8: O0 + o0oOOo0O0Ooo / O0 - I1ii11iIi11i % I1ii11iIi11i
   i11IiIii11i += "{}{}({}{}{}), " . format ( IIi1IIi ,
 IiiIIi1IiI . address . print_address_no_iid ( ) ,
 "r" if IiiIIi1IiI . eid else "R" , "P" if IiiIIi1IiI . probe else "p" ,
 "S" if IiiIIi1IiI . strict else "s" )
   if 55 - 55: OoooooooOO * OoooooooOO % I1Ii111 / Ii1I / ooOoO0o
  return ( i11IiIii11i [ 0 : - 2 ] if i11IiIii11i != "" else "" )
  if 12 - 12: i11iIiiIii + Ii1I % iIii1I11I1II1 + I1Ii111
  if 12 - 12: Ii1I + I1Ii111 / O0 * II111iiii
 def select_elp_node ( self ) :
  OoO00OO000ooO0OoOO , O0Ooo000 , OoO0o0OOOO = lisp_myrlocs
  ooo = None
  if 100 - 100: oO0o . i11iIiiIii - ooOoO0o
  for IiiIIi1IiI in self . elp_nodes :
   if ( OoO00OO000ooO0OoOO and IiiIIi1IiI . address . is_exact_match ( OoO00OO000ooO0OoOO ) ) :
    ooo = self . elp_nodes . index ( IiiIIi1IiI )
    break
    if 49 - 49: Oo0Ooo % ooOoO0o % o0oOOo0O0Ooo + ooOoO0o * I1Ii111 % I1IiiI
   if ( O0Ooo000 and IiiIIi1IiI . address . is_exact_match ( O0Ooo000 ) ) :
    ooo = self . elp_nodes . index ( IiiIIi1IiI )
    break
    if 85 - 85: i1IIi / i1IIi
    if 77 - 77: i1IIi . ooOoO0o % ooOoO0o - Ii1I
    if 6 - 6: OOooOOo % Ii1I + ooOoO0o
    if 17 - 17: iIii1I11I1II1 * I1Ii111 % oO0o + o0oOOo0O0Ooo . Ii1I * Oo0Ooo
    if 16 - 16: I1IiiI % OoO0O00 . ooOoO0o / OoooooooOO
    if 8 - 8: I1Ii111 % OoO0O00 . I1IiiI - OoOoOO00 + i1IIi / iIii1I11I1II1
    if 89 - 89: II111iiii / Ii1I % Ii1I
  if ( ooo == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   IiiIIi1IiI . we_are_last = False
   return
   if 57 - 57: I11i
   if 95 - 95: OoOoOO00 + I11i * i1IIi - ooOoO0o % ooOoO0o
   if 58 - 58: OOooOOo
   if 74 - 74: i1IIi . IiII / ooOoO0o + I11i % i11iIiiIii % iII111i
   if 62 - 62: i1IIi % I1Ii111
   if 94 - 94: i1IIi + iII111i
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ ooo ] ) :
   self . use_elp_node = None
   IiiIIi1IiI . we_are_last = True
   return
   if 25 - 25: I1Ii111 . Ii1I - Ii1I . o0oOOo0O0Ooo - IiII
   if 91 - 91: o0oOOo0O0Ooo % I1ii11iIi11i % OoOoOO00 * iIii1I11I1II1
   if 18 - 18: OoOoOO00 * I1ii11iIi11i . i1IIi * iII111i
   if 67 - 67: IiII + i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i11iIiiIii
   if 23 - 23: Oo0Ooo
  self . use_elp_node = self . elp_nodes [ ooo + 1 ]
  return
  if 7 - 7: Oo0Ooo / oO0o . I1Ii111 % I11i
  if 85 - 85: II111iiii / o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO / Ii1I
  if 18 - 18: i11iIiiIii + o0oOOo0O0Ooo . i11iIiiIii
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
  if 50 - 50: IiII / OoooooooOO . I11i
  if 93 - 93: OOooOOo / OoooooooOO % iII111i % Ii1I / I1Ii111 % OOooOOo
 def copy_geo ( self ) :
  IIiIiiIIiI = lisp_geo ( self . geo_name )
  IIiIiiIIiI . latitude = self . latitude
  IIiIiiIIiI . lat_mins = self . lat_mins
  IIiIiiIIiI . lat_secs = self . lat_secs
  IIiIiiIIiI . longitude = self . longitude
  IIiIiiIIiI . long_mins = self . long_mins
  IIiIiiIIiI . long_secs = self . long_secs
  IIiIiiIIiI . altitude = self . altitude
  IIiIiiIIiI . radius = self . radius
  return ( IIiIiiIIiI )
  if 25 - 25: i1IIi % Oo0Ooo . i1IIi * OoOoOO00 . Ii1I % OoO0O00
  if 47 - 47: o0oOOo0O0Ooo - i11iIiiIii / OoooooooOO
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 93 - 93: I1IiiI * II111iiii * O0 % o0oOOo0O0Ooo + oO0o / ooOoO0o
  if 79 - 79: OoO0O00 + ooOoO0o / oO0o % I1ii11iIi11i
 def parse_geo_string ( self , geo_str ) :
  ooo = geo_str . find ( "]" )
  if ( ooo != - 1 ) : geo_str = geo_str [ ooo + 1 : : ]
  if 77 - 77: Ii1I / Ii1I / I1ii11iIi11i
  if 92 - 92: O0 * i11iIiiIii . OoOoOO00 * IiII / o0oOOo0O0Ooo * ooOoO0o
  if 74 - 74: O0 - o0oOOo0O0Ooo
  if 68 - 68: I1Ii111
  if 19 - 19: o0oOOo0O0Ooo
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , oo0ooOOO00 = geo_str . split ( "/" )
   self . radius = int ( oo0ooOOO00 )
   if 92 - 92: I1Ii111 + iII111i % Ii1I / I11i % iII111i + OoOoOO00
   if 3 - 3: OoO0O00 - I11i % i11iIiiIii . iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 17 - 17: I1ii11iIi11i . I11i / IiII
  oOoo = geo_str [ 0 : 4 ]
  o00o000oOoo0o = geo_str [ 4 : 8 ]
  if 71 - 71: oO0o % OoO0O00 / Ii1I % II111iiii * OoOoOO00
  if 19 - 19: o0oOOo0O0Ooo * IiII . Oo0Ooo * OOooOOo
  if 6 - 6: I1ii11iIi11i / O0
  if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 98 - 98: II111iiii - i1IIi - ooOoO0o
  if 36 - 36: IiII + o0oOOo0O0Ooo
  if 81 - 81: OOooOOo / I11i % oO0o + ooOoO0o
  if 10 - 10: oO0o / i11iIiiIii
  self . latitude = int ( oOoo [ 0 ] )
  self . lat_mins = int ( oOoo [ 1 ] )
  self . lat_secs = int ( oOoo [ 2 ] )
  if ( oOoo [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 73 - 73: OoO0O00 - i1IIi
  if 52 - 52: I1ii11iIi11i
  if 4 - 4: Ii1I - iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
  if 18 - 18: oO0o % iIii1I11I1II1 + ooOoO0o
  self . longitude = int ( o00o000oOoo0o [ 0 ] )
  self . long_mins = int ( o00o000oOoo0o [ 1 ] )
  self . long_secs = int ( o00o000oOoo0o [ 2 ] )
  if ( o00o000oOoo0o [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 34 - 34: I1IiiI - OoooooooOO . IiII - OOooOOo % IiII
  if 19 - 19: IiII + I1ii11iIi11i % Oo0Ooo
 def print_geo ( self ) :
  iIiiiI1iII = "N" if self . latitude < 0 else "S"
  iIoOo0OoOO = "E" if self . longitude < 0 else "W"
  if 86 - 86: i1IIi
  Iiii1II = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , iIiiiI1iII , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , iIoOo0OoOO )
  if 73 - 73: iIii1I11I1II1 * Oo0Ooo
  if ( self . no_geo_altitude ( ) == False ) :
   Iiii1II += "-" + str ( self . altitude )
   if 54 - 54: oO0o . Ii1I
   if 31 - 31: I11i
   if 60 - 60: Oo0Ooo - iII111i . II111iiii % ooOoO0o / OoooooooOO / iIii1I11I1II1
   if 23 - 23: I11i + iIii1I11I1II1
   if 60 - 60: O0 * I1IiiI + o0oOOo0O0Ooo * OoO0O00 + o0oOOo0O0Ooo / i11iIiiIii
  if ( self . radius != 0 ) : Iiii1II += "/{}" . format ( self . radius )
  return ( Iiii1II )
  if 54 - 54: i11iIiiIii . iII111i * i1IIi
  if 68 - 68: Oo0Ooo
 def geo_url ( self ) :
  i11i1iI = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  i11i1iI = "10" if ( i11i1iI == "" or i11i1iI . isdigit ( ) == False ) else i11i1iI
  oOOO0OoOOO0O , II111IIII = self . dms_to_decimal ( )
  i1III1ii = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( oOOO0OoOOO0O , II111IIII , oOOO0OoOOO0O , II111IIII ,
  # o0oOOo0O0Ooo + I1IiiI / II111iiii
  # i11iIiiIii % Ii1I . Ii1I
 i11i1iI )
  return ( i1III1ii )
  if 74 - 74: OoooooooOO - Oo0Ooo - Ii1I + I11i
  if 93 - 93: I1IiiI % O0 * OoO0O00 % OoOoOO00 . I1Ii111 * I1IiiI
 def print_geo_url ( self ) :
  IIiIiiIIiI = self . print_geo ( )
  if ( self . radius == 0 ) :
   i1III1ii = self . geo_url ( )
   Iii11I111Ii11 = "<a href='{}'>{}</a>" . format ( i1III1ii , IIiIiiIIiI )
  else :
   i1III1ii = IIiIiiIIiI . replace ( "/" , "-" )
   Iii11I111Ii11 = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( i1III1ii , IIiIiiIIiI )
   if 95 - 95: IiII + o0oOOo0O0Ooo - o0oOOo0O0Ooo
  return ( Iii11I111Ii11 )
  if 83 - 83: ooOoO0o
  if 59 - 59: I1ii11iIi11i
 def dms_to_decimal ( self ) :
  i11O0 , i1iI1IIi1ii , OooOo0 = self . latitude , self . lat_mins , self . lat_secs
  o0iII1 = float ( abs ( i11O0 ) )
  o0iII1 += float ( i1iI1IIi1ii * 60 + OooOo0 ) / 3600
  if ( i11O0 > 0 ) : o0iII1 = - o0iII1
  I1 = o0iII1
  if 94 - 94: i11iIiiIii
  i11O0 , i1iI1IIi1ii , OooOo0 = self . longitude , self . long_mins , self . long_secs
  o0iII1 = float ( abs ( i11O0 ) )
  o0iII1 += float ( i1iI1IIi1ii * 60 + OooOo0 ) / 3600
  if ( i11O0 > 0 ) : o0iII1 = - o0iII1
  O0Oo00 = o0iII1
  return ( ( I1 , O0Oo00 ) )
  if 80 - 80: I11i - IiII
  if 40 - 40: OOooOOo * I1IiiI % I11i . I1Ii111 % O0 . O0
 def get_distance ( self , geo_point ) :
  I1IIiI1IIIiii1iI = self . dms_to_decimal ( )
  II1iI1iIIiI = geo_point . dms_to_decimal ( )
  IiI11ii = vincenty ( I1IIiI1IIIiii1iI , II1iI1iIIiI )
  return ( IiI11ii . km )
  if 21 - 21: I1IiiI
  if 69 - 69: OoooooooOO + iII111i
 def point_in_circle ( self , geo_point ) :
  I1iIiII11IIi = self . get_distance ( geo_point )
  return ( I1iIiII11IIi <= self . radius )
  if 96 - 96: IiII + oO0o / Oo0Ooo + OoooooooOO
  if 53 - 53: Ii1I * IiII + Oo0Ooo + i11iIiiIii - iIii1I11I1II1
 def encode_geo ( self ) :
  OoOoO00OoOOo = socket . htons ( LISP_AFI_LCAF )
  o0Oo0O0 = socket . htons ( 20 + 2 )
  II111Ii1I1I = 0
  if 66 - 66: O0 - I1ii11iIi11i * iIii1I11I1II1 - I1Ii111 / I1ii11iIi11i
  oOOO0OoOOO0O = abs ( self . latitude )
  iIi1i1Iii1I = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : II111Ii1I1I |= 0x40
  if 11 - 11: O0 % iIii1I11I1II1
  II111IIII = abs ( self . longitude )
  oOOo0Ooo = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : II111Ii1I1I |= 0x20
  if 14 - 14: I1Ii111
  oOOOo = 0
  if ( self . no_geo_altitude ( ) == False ) :
   oOOOo = socket . htonl ( self . altitude )
   II111Ii1I1I |= 0x10
   if 90 - 90: I1IiiI - OOooOOo / OoO0O00 / I11i
  oo0ooOOO00 = socket . htons ( self . radius )
  if ( oo0ooOOO00 != 0 ) : II111Ii1I1I |= 0x06
  if 39 - 39: OoooooooOO
  Ii1Ii = struct . pack ( "HBBBBH" , OoOoO00OoOOo , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , o0Oo0O0 )
  Ii1Ii += struct . pack ( "BBHBBHBBHIHHH" , II111Ii1I1I , 0 , 0 , oOOO0OoOOO0O , iIi1i1Iii1I >> 16 ,
 socket . htons ( iIi1i1Iii1I & 0x0ffff ) , II111IIII , oOOo0Ooo >> 16 ,
 socket . htons ( oOOo0Ooo & 0xffff ) , oOOOo , oo0ooOOO00 , 0 , 0 )
  if 97 - 97: I11i / OOooOOo - iII111i
  return ( Ii1Ii )
  if 42 - 42: ooOoO0o . II111iiii % OoOoOO00 - I11i
  if 34 - 34: Ii1I % I1Ii111 % I1ii11iIi11i - IiII
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  i1I1iii1I11II = "BBHBBHBBHIHHH"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( lcaf_len < Iiiii ) : return ( None )
  if 89 - 89: IiII
  II111Ii1I1I , ooooo0O , iIIIo0O0 , oOOO0OoOOO0O , o0ooo00 , iIi1i1Iii1I , II111IIII , ooo00ooOo , oOOo0Ooo , oOOOo , oo0ooOOO00 , I1iIii11 , O0ooo0 = struct . unpack ( i1I1iii1I11II ,
  # Ii1I
 packet [ : Iiiii ] )
  if 22 - 22: Ii1I
  if 59 - 59: I1ii11iIi11i
  if 90 - 90: OOooOOo / iII111i
  if 70 - 70: o0oOOo0O0Ooo
  O0ooo0 = socket . ntohs ( O0ooo0 )
  if ( O0ooo0 == LISP_AFI_LCAF ) : return ( None )
  if 49 - 49: OOooOOo - I1IiiI + OoooooooOO % iII111i + o0oOOo0O0Ooo + OoOoOO00
  if ( II111Ii1I1I & 0x40 ) : oOOO0OoOOO0O = - oOOO0OoOOO0O
  self . latitude = oOOO0OoOOO0O
  ii1IIIii1iI = ( ( o0ooo00 << 16 ) | socket . ntohs ( iIi1i1Iii1I ) ) / 1000
  self . lat_mins = ii1IIIii1iI / 60
  self . lat_secs = ii1IIIii1iI % 60
  if 45 - 45: OoooooooOO . O0 * oO0o + IiII
  if ( II111Ii1I1I & 0x20 ) : II111IIII = - II111IIII
  self . longitude = II111IIII
  IiIi11IIIIiii = ( ( ooo00ooOo << 16 ) | socket . ntohs ( oOOo0Ooo ) ) / 1000
  self . long_mins = IiIi11IIIIiii / 60
  self . long_secs = IiIi11IIIIiii % 60
  if 25 - 25: Oo0Ooo * ooOoO0o % I1Ii111
  self . altitude = socket . ntohl ( oOOOo ) if ( II111Ii1I1I & 0x10 ) else - 1
  oo0ooOOO00 = socket . ntohs ( oo0ooOOO00 )
  self . radius = oo0ooOOO00 if ( II111Ii1I1I & 0x02 ) else oo0ooOOO00 * 1000
  if 34 - 34: OoOoOO00 / I1Ii111 - ooOoO0o
  self . geo_name = None
  packet = packet [ Iiiii : : ]
  if 66 - 66: I11i * OoO0O00
  if ( O0ooo0 != 0 ) :
   self . rloc . afi = O0ooo0
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 98 - 98: IiII . Oo0Ooo + I1Ii111
  return ( packet )
  if 63 - 63: oO0o * I1IiiI * oO0o
  if 56 - 56: oO0o - Ii1I % I1Ii111
  if 100 - 100: OOooOOo * IiII % IiII / o0oOOo0O0Ooo * OoO0O00 % OoOoOO00
  if 12 - 12: I1IiiI
  if 32 - 32: I1Ii111
  if 35 - 35: O0 + II111iiii + o0oOOo0O0Ooo - OoO0O00 - Ii1I
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 88 - 88: I1ii11iIi11i . O0 - o0oOOo0O0Ooo . I1ii11iIi11i * iII111i * I11i
  if 89 - 89: Oo0Ooo - oO0o + O0 / i11iIiiIii
 def copy_rle_node ( self ) :
  i1iiiIIi11 = lisp_rle_node ( )
  i1iiiIIi11 . address . copy_address ( self . address )
  i1iiiIIi11 . level = self . level
  i1iiiIIi11 . translated_port = self . translated_port
  i1iiiIIi11 . rloc_name = self . rloc_name
  return ( i1iiiIIi11 )
  if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
  if 74 - 74: IiII - O0 % OOooOOo % OoooooooOO - I11i
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 4 - 4: i1IIi + OoOoOO00 + iIii1I11I1II1 - i1IIi * i11iIiiIii
  if 99 - 99: I1ii11iIi11i - O0 % II111iiii + ooOoO0o % OoO0O00 * Ii1I
 def get_encap_keys ( self ) :
  Oo0O00O = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 8 - 8: OOooOOo
  oo0o00OO = self . address . print_address_no_iid ( ) + ":" + Oo0O00O
  if 85 - 85: O0 % OOooOOo . Ii1I
  try :
   iIi11III = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ]
   if ( iIi11III [ 1 ] ) : return ( iIi11III [ 1 ] . encrypt_key , iIi11III [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 74 - 74: I1ii11iIi11i - I1Ii111 + i11iIiiIii / I1Ii111 / OoooooooOO + o0oOOo0O0Ooo
   if 23 - 23: Oo0Ooo
   if 91 - 91: I1Ii111
   if 59 - 59: i1IIi % OOooOOo
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 81 - 81: i11iIiiIii / OoO0O00 * OoOoOO00 % iII111i - iIii1I11I1II1 + I1ii11iIi11i
  if 20 - 20: O0 . I1Ii111 * Ii1I * II111iiii
 def copy_rle ( self ) :
  iI1Ii11 = lisp_rle ( self . rle_name )
  for i1iiiIIi11 in self . rle_nodes :
   iI1Ii11 . rle_nodes . append ( i1iiiIIi11 . copy_rle_node ( ) )
   if 66 - 66: Ii1I % OoO0O00 % II111iiii - OOooOOo * o0oOOo0O0Ooo
  iI1Ii11 . build_forwarding_list ( )
  return ( iI1Ii11 )
  if 33 - 33: OoooooooOO / I11i
  if 98 - 98: I1ii11iIi11i . Ii1I . iIii1I11I1II1 * I1ii11iIi11i / Ii1I
 def print_rle ( self , html , do_formatting ) :
  Oo00 = ""
  for i1iiiIIi11 in self . rle_nodes :
   Oo0O00O = i1iiiIIi11 . translated_port
   if 74 - 74: Oo0Ooo * I1Ii111
   OOOo00 = ""
   if ( i1iiiIIi11 . rloc_name != None ) :
    OOOo00 = i1iiiIIi11 . rloc_name
    if ( do_formatting ) : OOOo00 = blue ( OOOo00 , html )
    if 97 - 97: I11i + II111iiii
    if 84 - 84: OOooOOo . I1IiiI / IiII
   oo0o00OO = i1iiiIIi11 . address . print_address_no_iid ( )
   if ( i1iiiIIi11 . address . is_local ( ) ) : oo0o00OO = red ( oo0o00OO , html )
   Oo00 += "{}{}({}), " . format ( oo0o00OO , "" if Oo0O00O == 0 else ":" + str ( Oo0O00O ) , "" if i1iiiIIi11 . rloc_name == None else OOOo00 )
   if 100 - 100: i1IIi / I1IiiI * I1ii11iIi11i % ooOoO0o + OoO0O00 * oO0o
   if 51 - 51: I1Ii111 - OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00
   if 45 - 45: i11iIiiIii - II111iiii / i1IIi * OoOoOO00
  return ( Oo00 [ 0 : - 2 ] if Oo00 != "" else "" )
  if 1 - 1: OOooOOo + I1IiiI + Ii1I . iII111i
  if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
 def build_forwarding_list ( self ) :
  II1ioOO0Oo = - 1
  for i1iiiIIi11 in self . rle_nodes :
   if ( II1ioOO0Oo == - 1 ) :
    if ( i1iiiIIi11 . address . is_local ( ) ) : II1ioOO0Oo = i1iiiIIi11 . level
   else :
    if ( i1iiiIIi11 . level > II1ioOO0Oo ) : break
    if 5 - 5: OoOoOO00 % i1IIi
    if 31 - 31: Oo0Ooo * O0 . OOooOOo . o0oOOo0O0Ooo + OoO0O00 + II111iiii
  II1ioOO0Oo = 0 if II1ioOO0Oo == - 1 else i1iiiIIi11 . level
  if 76 - 76: Oo0Ooo + I1IiiI - O0
  self . rle_forwarding_list = [ ]
  for i1iiiIIi11 in self . rle_nodes :
   if ( i1iiiIIi11 . level == II1ioOO0Oo or ( II1ioOO0Oo == 0 and
 i1iiiIIi11 . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and i1iiiIIi11 . address . is_local ( ) ) :
     oo0o00OO = i1iiiIIi11 . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( oo0o00OO ) )
     continue
     if 58 - 58: IiII * i1IIi . I1IiiI - iII111i
    self . rle_forwarding_list . append ( i1iiiIIi11 )
    if 73 - 73: Oo0Ooo . OoOoOO00
    if 50 - 50: IiII / o0oOOo0O0Ooo
    if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
    if 52 - 52: O0
    if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
class lisp_json ( ) :
 def __init__ ( self , name , string ) :
  self . json_name = name
  self . json_string = string
  if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
  if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 83 - 83: oO0o / OoO0O00
  if 34 - 34: OoooooooOO - i1IIi * O0
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 83 - 83: I1IiiI + OoO0O00
   if 41 - 41: Ii1I + II111iiii . OOooOOo * I1Ii111 / II111iiii
   if 32 - 32: Oo0Ooo - Ii1I % o0oOOo0O0Ooo
 def print_json ( self , html ) :
  IiiI111IIIIi = self . json_string
  oOOOO = "***"
  if ( html ) : oOOOO = red ( oOOOO , html )
  oOO00o = oOOOO + self . json_string + oOOOO
  if ( self . valid_json ( ) ) : return ( IiiI111IIIIi )
  return ( oOO00o )
  if 82 - 82: o0oOOo0O0Ooo + iIii1I11I1II1 + o0oOOo0O0Ooo + ooOoO0o
  if 41 - 41: OOooOOo * ooOoO0o
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 40 - 40: OOooOOo * Ii1I - I11i % I1IiiI
  return ( True )
  if 73 - 73: ooOoO0o + Ii1I . O0 . iII111i
  if 77 - 77: OOooOOo % I1IiiI - iII111i % I1Ii111
  if 29 - 29: iIii1I11I1II1 / i11iIiiIii + Oo0Ooo
  if 99 - 99: I1IiiI - iII111i * Ii1I - OoOoOO00 / i11iIiiIii - i1IIi
  if 46 - 46: I1ii11iIi11i * ooOoO0o
  if 4 - 4: I1Ii111 * II111iiii
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 4 - 4: ooOoO0o * Oo0Ooo - I1ii11iIi11i % ooOoO0o % OoOoOO00
  if 18 - 18: OOooOOo / O0 . OoO0O00 - II111iiii * OOooOOo
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 13 - 13: OoO0O00 % i1IIi . i11iIiiIii / iII111i
  if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . last_increment
  return ( oO000o0Oo00 <= 1 )
  if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
  if 4 - 4: Ii1I - Oo0Ooo . i1IIi + iIii1I11I1II1
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . last_increment
  return ( oO000o0Oo00 <= 60 )
  if 28 - 28: O0 / ooOoO0o / IiII - I11i + IiII + OoO0O00
  if 84 - 84: Oo0Ooo + OoOoOO00 / iII111i . I1ii11iIi11i
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 26 - 26: Oo0Ooo
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 61 - 61: Ii1I * oO0o * i11iIiiIii + OoO0O00
  return ( c1 , c2 )
  if 43 - 43: OoO0O00 * OoO0O00 * oO0o
  if 24 - 24: oO0o
 def normalize ( self , count ) :
  count = str ( count )
  OoO00OoOo = len ( count )
  if ( OoO00OoOo > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 79 - 79: Oo0Ooo % Oo0Ooo . oO0o + ooOoO0o * iII111i * I11i
  if ( OoO00OoOo > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 87 - 87: o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo + I1IiiI
  if ( OoO00OoOo > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 89 - 89: II111iiii
  return ( count )
  if 41 - 41: iIii1I11I1II1
  if 26 - 26: Oo0Ooo / i1IIi + Oo0Ooo
 def get_stats ( self , summary , html ) :
  oO0oO000ooo0o = self . last_rate_check
  II11iII1i11ii = self . last_packet_count
  i111I1Iiii = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 84 - 84: IiII - i1IIi . II111iiii . IiII
  O0o0OoO0o = self . last_rate_check - oO0oO000ooo0o
  if ( O0o0OoO0o == 0 ) :
   i1Ii11I = 0
   I1iiiiII11 = 0
  else :
   i1Ii11I = int ( ( self . packet_count - II11iII1i11ii ) / O0o0OoO0o )
   I1iiiiII11 = ( self . byte_count - i111I1Iiii ) / O0o0OoO0o
   I1iiiiII11 = ( I1iiiiII11 * 8 ) / 1000000
   I1iiiiII11 = round ( I1iiiiII11 , 2 )
   if 95 - 95: I1Ii111 / OOooOOo / O0
   if 29 - 29: O0 * I1IiiI % iIii1I11I1II1
   if 12 - 12: Oo0Ooo
   if 96 - 96: OoooooooOO - Ii1I * I1Ii111 / O0
   if 63 - 63: I1Ii111 - OOooOOo + i1IIi * i11iIiiIii - I1Ii111
  IIiiii1I1 = self . normalize ( self . packet_count )
  O0O0o = self . normalize ( self . byte_count )
  if 90 - 90: o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 31 - 31: I1IiiI / iIii1I11I1II1 + I1IiiI - o0oOOo0O0Ooo % OoOoOO00 - OoOoOO00
  if 16 - 16: oO0o - oO0o . I1Ii111 + I1ii11iIi11i
  if 10 - 10: I1ii11iIi11i / Ii1I
  if 71 - 71: ooOoO0o * I1Ii111
  if ( summary ) :
   I1iIi11II = "<br>" if html else ""
   IIiiii1I1 , O0O0o = self . stat_colors ( IIiiii1I1 , O0O0o , html )
   i1II1II1 = "packet-count: {}{}byte-count: {}" . format ( IIiiii1I1 , I1iIi11II , O0O0o )
   iIiI11i1iI1 = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( i1Ii11I , I1iiiiII11 )
   if 93 - 93: OoooooooOO + iIii1I11I1II1 * I1IiiI * Ii1I
   if ( html != "" ) : iIiI11i1iI1 = lisp_span ( i1II1II1 , iIiI11i1iI1 )
  else :
   Ii111i1I = str ( i1Ii11I )
   oooOoOo00 = str ( I1iiiiII11 )
   if ( html ) :
    IIiiii1I1 = lisp_print_cour ( IIiiii1I1 )
    Ii111i1I = lisp_print_cour ( Ii111i1I )
    O0O0o = lisp_print_cour ( O0O0o )
    oooOoOo00 = lisp_print_cour ( oooOoOo00 )
    if 32 - 32: Ii1I
   I1iIi11II = "<br>" if html else ", "
   if 51 - 51: i11iIiiIii
   iIiI11i1iI1 = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( IIiiii1I1 , I1iIi11II , Ii111i1I , I1iIi11II , O0O0o , I1iIi11II ,
   # i11iIiiIii + OoO0O00 + iII111i . o0oOOo0O0Ooo
 oooOoOo00 )
   if 65 - 65: ooOoO0o + I1Ii111 + iIii1I11I1II1 * i11iIiiIii
  return ( iIiI11i1iI1 )
  if 29 - 29: o0oOOo0O0Ooo . OoO0O00
  if 55 - 55: Oo0Ooo * IiII . o0oOOo0O0Ooo
  if 26 - 26: i1IIi
  if 20 - 20: OoooooooOO . O0 * OoOoOO00 + i11iIiiIii
  if 24 - 24: OoooooooOO - iII111i
  if 87 - 87: OOooOOo + iII111i % Oo0Ooo
  if 90 - 90: IiII * OoooooooOO - IiII * Oo0Ooo / I1IiiI / II111iiii
  if 81 - 81: I11i * oO0o
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 51 - 51: I1IiiI
if 35 - 35: OOooOOo % oO0o
if 73 - 73: II111iiii / i11iIiiIii
if 91 - 91: OOooOOo
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
  if 92 - 92: o0oOOo0O0Ooo % o0oOOo0O0Ooo + I1IiiI
  if ( recurse == False ) : return
  if 35 - 35: oO0o + iII111i + I11i - I1ii11iIi11i - ooOoO0o - OOooOOo
  if 77 - 77: OoooooooOO + OoooooooOO / oO0o * o0oOOo0O0Ooo / I11i
  if 86 - 86: I1IiiI % IiII - IiII
  if 1 - 1: o0oOOo0O0Ooo + OoOoOO00 / OOooOOo % IiII
  if 16 - 16: IiII . I11i * O0 + OoooooooOO
  if 37 - 37: OoO0O00 . i11iIiiIii - i11iIiiIii % I1Ii111 + II111iiii * i11iIiiIii
  OOOoo0000Oo = lisp_get_default_route_next_hops ( )
  if ( OOOoo0000Oo == [ ] or len ( OOOoo0000Oo ) == 1 ) : return
  if 84 - 84: OoooooooOO + i1IIi + iII111i % IiII % I1IiiI
  self . rloc_next_hop = OOOoo0000Oo [ 0 ]
  iiI = self
  for I11Ii11IiiII11ii in OOOoo0000Oo [ 1 : : ] :
   iI1III1Iiiii = lisp_rloc ( False )
   iI1III1Iiiii = copy . deepcopy ( self )
   iI1III1Iiiii . rloc_next_hop = I11Ii11IiiII11ii
   iiI . next_rloc = iI1III1Iiiii
   iiI = iI1III1Iiiii
   if 57 - 57: OoooooooOO % OoooooooOO + I1ii11iIi11i - I11i * II111iiii
   if 39 - 39: II111iiii * II111iiii
   if 47 - 47: oO0o / Ii1I + IiII % oO0o
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 86 - 86: I1IiiI
  if 83 - 83: I11i % Ii1I + IiII % I11i / i1IIi . oO0o
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 56 - 56: I1Ii111 - OOooOOo % o0oOOo0O0Ooo
  if 30 - 30: I1Ii111 % i1IIi
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 98 - 98: oO0o . i11iIiiIii / Ii1I - Ii1I
  if 23 - 23: iIii1I11I1II1
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 30 - 30: I1ii11iIi11i + OoO0O00 - O0
  if 42 - 42: I11i - I1Ii111
  if 24 - 24: i1IIi
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
  if 93 - 93: OoOoOO00 - Oo0Ooo + iIii1I11I1II1 % iIii1I11I1II1 / I1ii11iIi11i - I1Ii111
  if 9 - 9: I1ii11iIi11i - o0oOOo0O0Ooo / i11iIiiIii * iII111i / OoOoOO00 . I1IiiI
 def print_rloc ( self , indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , i1 , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 23 - 23: I1IiiI . iII111i % i1IIi
  if 92 - 92: o0oOOo0O0Ooo % i1IIi / OoooooooOO * OoooooooOO / iIii1I11I1II1
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  I1io0 = self . rloc_name
  if ( cour ) : I1io0 = lisp_print_cour ( I1io0 )
  return ( 'rloc-name: {}' . format ( blue ( I1io0 , cour ) ) )
  if 7 - 7: IiII / OOooOOo + Oo0Ooo . I1IiiI
  if 33 - 33: I1Ii111 + OoooooooOO
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  Oo0O00O = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 73 - 73: O0 . Oo0Ooo
  if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
  if 48 - 48: II111iiii % I1ii11iIi11i - II111iiii
  if 29 - 29: I1Ii111 - I1Ii111 - I11i * iIii1I11I1II1 % OoO0O00 % IiII
  oOO = self . rloc
  if ( oOO . is_null ( ) == False ) :
   Ooo = lisp_get_nat_info ( oOO , self . rloc_name )
   if ( Ooo ) :
    Oo0O00O = Ooo . port
    Ii1i11I = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    oo0o00OO = oOO . print_address_no_iid ( )
    o0oooOoOoOo = red ( oo0o00OO , False )
    Ii1I1I1iIii1 = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 65 - 65: iII111i / iIii1I11I1II1 + I11i - iIii1I11I1II1 - Ii1I . I1Ii111
    if 77 - 77: OoOoOO00 / I1IiiI + IiII
    if 66 - 66: i11iIiiIii * OoooooooOO + iII111i / Ii1I
    if 42 - 42: Ii1I / iIii1I11I1II1 / Oo0Ooo . O0 . oO0o * I1IiiI
    if 21 - 21: OoooooooOO
    if 76 - 76: i1IIi * i11iIiiIii / OOooOOo + I1Ii111
    if ( Ooo . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( o0oooOoOoOo , Oo0O00O , Ii1I1I1iIii1 ) )
     if 50 - 50: oO0o % OoOoOO00 + I1IiiI
     if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
     Ooo = None if ( Ooo == Ii1i11I ) else Ii1i11I
     if ( Ooo and Ooo . timed_out ( ) ) :
      Oo0O00O = Ooo . port
      o0oooOoOoOo = red ( Ooo . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( o0oooOoOoOo , Oo0O00O ,
      # oO0o % OOooOOo % I1Ii111 / IiII - Oo0Ooo
 Ii1I1I1iIii1 ) )
      Ooo = None
      if 48 - 48: Oo0Ooo * iII111i - Oo0Ooo + I11i % II111iiii
      if 71 - 71: OoOoOO00 % o0oOOo0O0Ooo . oO0o
      if 65 - 65: OoO0O00
      if 48 - 48: OoO0O00
      if 59 - 59: OoooooooOO + I11i . oO0o
      if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
      if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
    if ( Ooo ) :
     if ( Ooo . address != oo0o00OO ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( o0oooOoOoOo , red ( Ooo . address , False ) ) )
      if 16 - 16: OoO0O00 / Ii1I * i11iIiiIii / o0oOOo0O0Ooo + I1Ii111
      self . rloc . store_address ( Ooo . address )
      if 21 - 21: I11i % I1ii11iIi11i
     o0oooOoOoOo = red ( Ooo . address , False )
     Oo0O00O = Ooo . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( o0oooOoOoOo , Oo0O00O , Ii1I1I1iIii1 ) )
     if 8 - 8: OOooOOo % OoO0O00 + O0 - o0oOOo0O0Ooo
     self . store_translated_rloc ( oOO , Oo0O00O )
     if 46 - 46: Oo0Ooo . ooOoO0o + OoOoOO00 - I11i / i11iIiiIii . iII111i
     if 80 - 80: II111iiii + OoO0O00 % ooOoO0o + i11iIiiIii
     if 30 - 30: Ii1I / I1ii11iIi11i % IiII - Oo0Ooo
     if 100 - 100: IiII . I1Ii111 * oO0o % OoO0O00 . iIii1I11I1II1 * Oo0Ooo
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 100 - 100: IiII - OoOoOO00 % iII111i
  if 24 - 24: Oo0Ooo / OoO0O00 + i11iIiiIii
  if 81 - 81: i11iIiiIii . iIii1I11I1II1 - OoooooooOO
  if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for i1iiiIIi11 in self . rle . rle_nodes :
    I1io0 = i1iiiIIi11 . rloc_name
    Ooo = lisp_get_nat_info ( i1iiiIIi11 . address , I1io0 )
    if ( Ooo == None ) : continue
    if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
    Oo0O00O = Ooo . port
    OoOi1IiiIiIII11 = I1io0
    if ( OoOi1IiiIiIII11 ) : OoOi1IiiIiIII11 = blue ( I1io0 , False )
    if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( Oo0O00O ,
    # OOooOOo . OoO0O00 + OoO0O00
 i1iiiIIi11 . address . print_address_no_iid ( ) , OoOi1IiiIiIII11 ) )
    i1iiiIIi11 . translated_port = Oo0O00O
    if 19 - 19: iII111i * i1IIi / iII111i
    if 21 - 21: ooOoO0o / o0oOOo0O0Ooo % I1ii11iIi11i . Ii1I . IiII
    if 8 - 8: I1ii11iIi11i / ooOoO0o + II111iiii
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 45 - 45: ooOoO0o - OOooOOo * IiII % iII111i . OoOoOO00 / i11iIiiIii
  if 63 - 63: Oo0Ooo * iIii1I11I1II1 / ooOoO0o
  if 46 - 46: OoOoOO00 / iII111i - OoO0O00 . o0oOOo0O0Ooo
  if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
  oooOoOoooo = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 26 - 26: OoooooooOO % iIii1I11I1II1 - IiII
  if ( rloc_record . keys != None and oooOoOoooo ) :
   Oo000O000 = rloc_record . keys [ 1 ]
   if ( Oo000O000 != None ) :
    oo0o00OO = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( Oo0O00O )
    if 3 - 3: oO0o * II111iiii . O0
    Oo000O000 . add_key_by_rloc ( oo0o00OO , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( oo0o00OO , False ) ) )
    if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
    if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
    if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
  return ( Oo0O00O )
  if 51 - 51: oO0o - I1ii11iIi11i + I1ii11iIi11i
  if 100 - 100: I11i - I1ii11iIi11i . i1IIi
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 85 - 85: II111iiii
  if 58 - 58: i1IIi - OoO0O00 + ooOoO0o
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 6 - 6: IiII % I1IiiI + OoooooooOO * oO0o . iII111i + oO0o
  if 4 - 4: I11i % I1IiiI
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 72 - 72: I1IiiI % II111iiii % iII111i / OoOoOO00
  return ( True )
  if 96 - 96: OoOoOO00 % Ii1I
  if 50 - 50: IiII - II111iiii
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 10 - 10: OoooooooOO % Ii1I * OOooOOo + IiII * oO0o
  if 13 - 13: II111iiii
  if 14 - 14: i11iIiiIii . IiII
 def print_state_change ( self , new_state ) :
  OOO000oOoo00o = self . print_state ( )
  Iii11I111Ii11 = "{} -> {}" . format ( OOO000oOoo00o , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   Iii11I111Ii11 = bold ( Iii11I111Ii11 , False )
   if 29 - 29: I1IiiI + i1IIi * O0 % oO0o
  return ( Iii11I111Ii11 )
  if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
  if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 49 - 49: iII111i + OoOoOO00
  if 33 - 33: ooOoO0o
 def print_recent_rloc_probe_rtts ( self ) :
  i1111111II = str ( self . recent_rloc_probe_rtts )
  i1111111II = i1111111II . replace ( "-1" , "?" )
  return ( i1111111II )
  if 58 - 58: o0oOOo0O0Ooo
  if 5 - 5: O0
 def compute_rloc_probe_rtt ( self ) :
  iiI = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  I1oO0OOoOOo = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ iiI ] + I1oO0OOoOOo [ 0 : - 1 ]
  if 28 - 28: I1ii11iIi11i
  if 83 - 83: ooOoO0o % I1IiiI - OoOoOO00 - I11i
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 12 - 12: I1Ii111 . OoO0O00 + I11i * OoO0O00 - IiII + I11i
  if 98 - 98: iII111i . I1Ii111 * IiII - Ii1I * OoooooooOO
 def print_recent_rloc_probe_hops ( self ) :
  i1iIiII11I1 = str ( self . recent_rloc_probe_hops )
  return ( i1iIiII11I1 )
  if 22 - 22: ooOoO0o
  if 83 - 83: OOooOOo - i11iIiiIii - i1IIi / oO0o
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < LISP_RLOC_PROBE_TTL / 2 ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 33 - 33: OoO0O00 + OOooOOo
  if ( from_ttl < LISP_RLOC_PROBE_TTL / 2 ) :
   IIII11111Iii1I = "!"
  else :
   IIII11111Iii1I = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 53 - 53: II111iiii - o0oOOo0O0Ooo - Ii1I * Oo0Ooo * Oo0Ooo . Ii1I
   if 4 - 4: i11iIiiIii - iIii1I11I1II1 % o0oOOo0O0Ooo * oO0o
  iiI = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + IIII11111Iii1I
  I1oO0OOoOOo = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ iiI ] + I1oO0OOoOOo [ 0 : - 1 ]
  if 19 - 19: Ii1I
  if 47 - 47: IiII - IiII
 def store_rloc_probe_latencies ( self , json_telemetry ) :
  iiiI1IIIIIIi1 = lisp_decode_telemetry ( json_telemetry )
  if 94 - 94: iIii1I11I1II1 - Oo0Ooo / iIii1I11I1II1 * Ii1I + o0oOOo0O0Ooo
  Ii1IIii1i111i = round ( float ( iiiI1IIIIIIi1 [ "etr-in" ] ) - float ( iiiI1IIIIIIi1 [ "itr-out" ] ) , 3 )
  IIiiIi1i = round ( float ( iiiI1IIIIIIi1 [ "itr-in" ] ) - float ( iiiI1IIIIIIi1 [ "etr-out" ] ) , 3 )
  if 84 - 84: i11iIiiIii
  iiI = self . rloc_probe_latency
  self . rloc_probe_latency = str ( Ii1IIii1i111i ) + "/" + str ( IIiiIi1i )
  I1oO0OOoOOo = self . recent_rloc_probe_latencies
  self . recent_rloc_probe_latencies = [ iiI ] + I1oO0OOoOOo [ 0 : - 1 ]
  if 11 - 11: I1ii11iIi11i + i1IIi % oO0o * O0 + I1Ii111 / Oo0Ooo
  if 45 - 45: I1IiiI / OoooooooOO / II111iiii % I1Ii111 / O0 . I1ii11iIi11i
 def print_rloc_probe_latency ( self ) :
  return ( self . rloc_probe_latency )
  if 96 - 96: IiII * OOooOOo / Oo0Ooo / Oo0Ooo / OoooooooOO . i11iIiiIii
  if 24 - 24: OoO0O00 - OoO0O00 * Oo0Ooo + oO0o + o0oOOo0O0Ooo % OOooOOo
 def print_recent_rloc_probe_latencies ( self ) :
  iii1I1i11IiI1 = str ( self . recent_rloc_probe_latencies )
  return ( iii1I1i11IiI1 )
  if 82 - 82: I1IiiI
  if 12 - 12: O0 * OoooooooOO - i1IIi % oO0o
 def process_rloc_probe_reply ( self , ts , nonce , eid , group , hc , ttl , jt ) :
  oOO = self
  while ( True ) :
   if ( oOO . last_rloc_probe_nonce == nonce ) : break
   oOO = oOO . next_rloc
   if ( oOO == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 27 - 27: i1IIi - OOooOOo / Oo0Ooo
    return
    if 16 - 16: o0oOOo0O0Ooo - iIii1I11I1II1 / OoooooooOO / I1ii11iIi11i + IiII
    if 73 - 73: OOooOOo % I1Ii111 + OoooooooOO / I1ii11iIi11i * oO0o % oO0o
    if 25 - 25: I1Ii111
    if 93 - 93: OoO0O00
    if 62 - 62: Oo0Ooo . iII111i
    if 15 - 15: i11iIiiIii * I11i + oO0o
  oOO . last_rloc_probe_reply = ts
  oOO . compute_rloc_probe_rtt ( )
  o0OoOO0oO0o0oOoO = oOO . print_state_change ( "up" )
  if ( oOO . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( oOO . rloc , True )
   oOO . state = LISP_RLOC_UP_STATE
   oOO . last_state_change = lisp_get_timestamp ( )
   I1iOo0 = lisp_map_cache . lookup_cache ( eid , True )
   if ( I1iOo0 ) : lisp_write_ipc_map_cache ( True , I1iOo0 )
   if 30 - 30: II111iiii / II111iiii
   if 70 - 70: OoO0O00 + O0 * OoO0O00
   if 25 - 25: OoooooooOO . Oo0Ooo + OOooOOo + Oo0Ooo * O0 % i1IIi
   if 71 - 71: II111iiii / Ii1I + i1IIi - OoOoOO00 + Ii1I
   if 31 - 31: OoooooooOO * Ii1I - iII111i . oO0o % Ii1I
  oOO . store_rloc_probe_hops ( hc , ttl )
  if 97 - 97: Ii1I
  if 51 - 51: II111iiii . oO0o % iII111i
  if 47 - 47: II111iiii - iII111i * I1IiiI . IiII
  if 41 - 41: OoOoOO00 / O0 + I1Ii111 . I1ii11iIi11i
  if ( jt ) : oOO . store_rloc_probe_latencies ( jt )
  if 48 - 48: Ii1I . o0oOOo0O0Ooo * O0 / OoooooooOO + I1Ii111 + Oo0Ooo
  O0OoO0ooo0Ooo = bold ( "RLOC-probe reply" , False )
  oo0o00OO = oOO . rloc . print_address_no_iid ( )
  O00OOo0oo = bold ( str ( oOO . print_rloc_probe_rtt ( ) ) , False )
  oo00ooOOOo0O = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 36 - 36: i11iIiiIii
  I11Ii11IiiII11ii = ""
  if ( oOO . rloc_next_hop != None ) :
   OooOOOoOoo0O0 , iIIi1Iii1Ii = oOO . rloc_next_hop
   I11Ii11IiiII11ii = ", nh {}({})" . format ( iIIi1Iii1Ii , OooOOOoOoo0O0 )
   if 13 - 13: Ii1I + O0 % o0oOOo0O0Ooo % Oo0Ooo / i1IIi . II111iiii
   if 23 - 23: I1ii11iIi11i . Oo0Ooo . iII111i % i1IIi
  oOOO0OoOOO0O = bold ( oOO . print_rloc_probe_latency ( ) , False )
  oOOO0OoOOO0O = ", latency {}" . format ( oOOO0OoOOO0O ) if jt else ""
  if 56 - 56: iIii1I11I1II1 * i11iIiiIii % O0 * Ii1I % I1Ii111 % I11i
  oOo = green ( lisp_print_eid_tuple ( eid , group ) , False )
  if 65 - 65: I1ii11iIi11i . I1IiiI . II111iiii . ooOoO0o - o0oOOo0O0Ooo
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}{}" ) . format ( O0OoO0ooo0Ooo , red ( oo0o00OO , False ) , oo00ooOOOo0O , oOo ,
  # o0oOOo0O0Ooo - I1Ii111 . iII111i
 o0OoOO0oO0o0oOoO , O00OOo0oo , I11Ii11IiiII11ii , str ( hc ) + "/" + str ( ttl ) , oOOO0OoOOO0O ) )
  if 6 - 6: OoO0O00
  if ( oOO . rloc_next_hop == None ) : return
  if 75 - 75: i11iIiiIii - oO0o % I1Ii111
  if 19 - 19: oO0o . I1Ii111 - IiII * IiII - OoOoOO00 % iIii1I11I1II1
  if 77 - 77: II111iiii + OOooOOo % iII111i * O0 % i1IIi / I1Ii111
  if 39 - 39: II111iiii % OoOoOO00 / O0 / II111iiii
  oOO = None
  I1iII11 = None
  while ( True ) :
   oOO = self if oOO == None else oOO . next_rloc
   if ( oOO == None ) : break
   if ( oOO . up_state ( ) == False ) : continue
   if ( oOO . rloc_probe_rtt == - 1 ) : continue
   if 11 - 11: I1ii11iIi11i + O0
   if ( I1iII11 == None ) : I1iII11 = oOO
   if ( oOO . rloc_probe_rtt < I1iII11 . rloc_probe_rtt ) : I1iII11 = oOO
   if 41 - 41: ooOoO0o
   if 31 - 31: OoO0O00
  if ( I1iII11 != None ) :
   OooOOOoOoo0O0 , iIIi1Iii1Ii = I1iII11 . rloc_next_hop
   I11Ii11IiiII11ii = bold ( "nh {}({})" . format ( iIIi1Iii1Ii , OooOOOoOoo0O0 ) , False )
   lprint ( "    Install host-route via best {}" . format ( I11Ii11IiiII11ii ) )
   lisp_install_host_route ( oo0o00OO , None , False )
   lisp_install_host_route ( oo0o00OO , iIIi1Iii1Ii , True )
   if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
   if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
   if 72 - 72: I1ii11iIi11i
 def add_to_rloc_probe_list ( self , eid , group ) :
  oo0o00OO = self . rloc . print_address_no_iid ( )
  Oo0O00O = self . translated_port
  if ( Oo0O00O != 0 ) : oo0o00OO += ":" + str ( Oo0O00O )
  if 74 - 74: I1Ii111 * iIii1I11I1II1 / oO0o - IiII - I1IiiI
  if ( lisp_rloc_probe_list . has_key ( oo0o00OO ) == False ) :
   lisp_rloc_probe_list [ oo0o00OO ] = [ ]
   if 84 - 84: iIii1I11I1II1 % Oo0Ooo / I1ii11iIi11i + o0oOOo0O0Ooo * II111iiii
   if 81 - 81: I1IiiI / I1ii11iIi11i / OOooOOo
  if ( group . is_null ( ) ) : group . instance_id = 0
  for O0OOOO0o0O , oOo , i11ii in lisp_rloc_probe_list [ oo0o00OO ] :
   if ( oOo . is_exact_match ( eid ) and i11ii . is_exact_match ( group ) ) :
    if ( O0OOOO0o0O == self ) :
     if ( lisp_rloc_probe_list [ oo0o00OO ] == [ ] ) :
      lisp_rloc_probe_list . pop ( oo0o00OO )
      if 89 - 89: Oo0Ooo % IiII
     return
     if 36 - 36: IiII % OoOoOO00 % I1ii11iIi11i
    lisp_rloc_probe_list [ oo0o00OO ] . remove ( [ O0OOOO0o0O , oOo , i11ii ] )
    break
    if 7 - 7: I1ii11iIi11i % OoOoOO00 - O0 . I1Ii111
    if 9 - 9: Ii1I . OoooooooOO / ooOoO0o + i1IIi
  lisp_rloc_probe_list [ oo0o00OO ] . append ( [ self , eid , group ] )
  if 90 - 90: oO0o - OoOoOO00 % ooOoO0o
  if 83 - 83: OOooOOo - I1ii11iIi11i + OoO0O00
  if 99 - 99: iII111i - OoOoOO00 % ooOoO0o
  if 27 - 27: oO0o . oO0o * iII111i % iIii1I11I1II1
  if 81 - 81: iII111i * II111iiii
  oOO = lisp_rloc_probe_list [ oo0o00OO ] [ 0 ] [ 0 ]
  if ( oOO . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 28 - 28: i11iIiiIii . Oo0Ooo . Ii1I
   if 19 - 19: OoO0O00 - Ii1I + ooOoO0o + OOooOOo
   if 84 - 84: iII111i / Oo0Ooo
 def delete_from_rloc_probe_list ( self , eid , group ) :
  oo0o00OO = self . rloc . print_address_no_iid ( )
  Oo0O00O = self . translated_port
  if ( Oo0O00O != 0 ) : oo0o00OO += ":" + str ( Oo0O00O )
  if ( lisp_rloc_probe_list . has_key ( oo0o00OO ) == False ) : return
  if 21 - 21: OoO0O00 . I1IiiI - OoO0O00
  ooOOO0 = [ ]
  for i1ii1i1Ii11 in lisp_rloc_probe_list [ oo0o00OO ] :
   if ( i1ii1i1Ii11 [ 0 ] != self ) : continue
   if ( i1ii1i1Ii11 [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( i1ii1i1Ii11 [ 2 ] . is_exact_match ( group ) == False ) : continue
   ooOOO0 = i1ii1i1Ii11
   break
   if 97 - 97: I11i - ooOoO0o + oO0o . I1Ii111
  if ( ooOOO0 == [ ] ) : return
  if 22 - 22: Ii1I - II111iiii % Oo0Ooo * OoOoOO00 + iIii1I11I1II1
  try :
   lisp_rloc_probe_list [ oo0o00OO ] . remove ( ooOOO0 )
   if ( lisp_rloc_probe_list [ oo0o00OO ] == [ ] ) :
    lisp_rloc_probe_list . pop ( oo0o00OO )
    if 5 - 5: Oo0Ooo % o0oOOo0O0Ooo * I1Ii111
  except :
   return
   if 6 - 6: OOooOOo + o0oOOo0O0Ooo
   if 41 - 41: OoooooooOO + iIii1I11I1II1 . O0 % I1Ii111 % OOooOOo + I1Ii111
   if 65 - 65: II111iiii . oO0o
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  Oo0Ooo0O0 = ""
  oOO = self
  while ( True ) :
   I1o0O0o0 = oOO . last_rloc_probe
   if ( I1o0O0o0 == None ) : I1o0O0o0 = 0
   III1111 = oOO . last_rloc_probe_reply
   if ( III1111 == None ) : III1111 = 0
   O00OOo0oo = oOO . print_rloc_probe_rtt ( )
   IiII1iiI = space ( 4 )
   if 56 - 56: iIii1I11I1II1 - OoO0O00 . i1IIi . OOooOOo / o0oOOo0O0Ooo
   if ( oOO . rloc_next_hop == None ) :
    Oo0Ooo0O0 += "RLOC-Probing:\n"
   else :
    OooOOOoOoo0O0 , iIIi1Iii1Ii = oOO . rloc_next_hop
    Oo0Ooo0O0 += "RLOC-Probing for nh {}({}):\n" . format ( iIIi1Iii1Ii , OooOOOoOoo0O0 )
    if 98 - 98: oO0o + I11i . oO0o
    if 10 - 10: iII111i + i1IIi . I11i % ooOoO0o / ooOoO0o
   Oo0Ooo0O0 += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( IiII1iiI , lisp_print_elapsed ( I1o0O0o0 ) ,
   # Oo0Ooo . i11iIiiIii . IiII . Oo0Ooo % I1Ii111 * iII111i
 IiII1iiI , lisp_print_elapsed ( III1111 ) , O00OOo0oo )
   if 61 - 61: IiII - o0oOOo0O0Ooo
   if ( trailing_linefeed ) : Oo0Ooo0O0 += "\n"
   if 8 - 8: OOooOOo . Ii1I
   oOO = oOO . next_rloc
   if ( oOO == None ) : break
   Oo0Ooo0O0 += "\n"
   if 15 - 15: ooOoO0o / OOooOOo + i1IIi / Ii1I / OOooOOo
  return ( Oo0Ooo0O0 )
  if 47 - 47: Oo0Ooo + oO0o % OoooooooOO
  if 23 - 23: I1Ii111 / i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1
 def get_encap_keys ( self ) :
  Oo0O00O = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 11 - 11: I11i % OoOoOO00 * Oo0Ooo
  oo0o00OO = self . rloc . print_address_no_iid ( ) + ":" + Oo0O00O
  if 48 - 48: OOooOOo
  try :
   iIi11III = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ]
   if ( iIi11III [ 1 ] ) : return ( iIi11III [ 1 ] . encrypt_key , iIi11III [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 66 - 66: iII111i - I1Ii111 - i11iIiiIii . o0oOOo0O0Ooo + Oo0Ooo
   if 90 - 90: O0 - i11iIiiIii * ooOoO0o . I1ii11iIi11i . Ii1I - OoooooooOO
   if 23 - 23: o0oOOo0O0Ooo
 def rloc_recent_rekey ( self ) :
  Oo0O00O = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 88 - 88: I1Ii111 + iIii1I11I1II1 / o0oOOo0O0Ooo
  oo0o00OO = self . rloc . print_address_no_iid ( ) + ":" + Oo0O00O
  if 93 - 93: ooOoO0o % iIii1I11I1II1 - OOooOOo . IiII + ooOoO0o
  try :
   Oo000O000 = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ] [ 1 ]
   if ( Oo000O000 == None ) : return ( False )
   if ( Oo000O000 . last_rekey == None ) : return ( True )
   return ( time . time ( ) - Oo000O000 . last_rekey < 1 )
  except :
   return ( False )
   if 63 - 63: I1ii11iIi11i / OOooOOo
   if 28 - 28: I11i / I1Ii111 + IiII * OoooooooOO - iIii1I11I1II1
   if 6 - 6: I11i % o0oOOo0O0Ooo / OoooooooOO . I1Ii111
   if 17 - 17: I1ii11iIi11i + OoooooooOO / iIii1I11I1II1 . II111iiii + Oo0Ooo
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
  if 7 - 7: O0 - I1ii11iIi11i - iIii1I11I1II1
  if 96 - 96: OoOoOO00 . I1IiiI . I11i * OoooooooOO + OoooooooOO * O0
 def print_mapping ( self , eid_indent , rloc_indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  IIi1iiIII11 = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 90 - 90: I11i + I1ii11iIi11i + OoooooooOO + OoOoOO00 + IiII / iII111i
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , IIi1iiIII11 , i1 ,
 len ( self . rloc_set ) ) )
  for oOO in self . rloc_set : oOO . print_rloc ( rloc_indent )
  if 75 - 75: i11iIiiIii
  if 27 - 27: I11i - IiII - I1Ii111
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 90 - 90: OoO0O00 . oO0o * O0 / I11i % O0 + I1Ii111
  if 48 - 48: iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
 def print_ttl ( self ) :
  oOoooOOO0o0 = self . map_cache_ttl
  if ( oOoooOOO0o0 == None ) : return ( "forever" )
  if 84 - 84: Ii1I
  if ( oOoooOOO0o0 >= 3600 ) :
   if ( ( oOoooOOO0o0 % 3600 ) == 0 ) :
    oOoooOOO0o0 = str ( oOoooOOO0o0 / 3600 ) + " hours"
   else :
    oOoooOOO0o0 = str ( oOoooOOO0o0 * 60 ) + " mins"
    if 92 - 92: I11i
  elif ( oOoooOOO0o0 >= 60 ) :
   if ( ( oOoooOOO0o0 % 60 ) == 0 ) :
    oOoooOOO0o0 = str ( oOoooOOO0o0 / 60 ) + " mins"
   else :
    oOoooOOO0o0 = str ( oOoooOOO0o0 ) + " secs"
    if 64 - 64: iII111i / iII111i * iII111i % O0 / IiII . I1ii11iIi11i
  else :
   oOoooOOO0o0 = str ( oOoooOOO0o0 ) + " secs"
   if 23 - 23: i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
  return ( oOoooOOO0o0 )
  if 82 - 82: O0 * ooOoO0o * iIii1I11I1II1 . i1IIi
  if 47 - 47: I11i * I11i . OoOoOO00
 def refresh ( self ) :
  if ( self . group . is_null ( ) ) : return ( self . refresh_unicast ( ) )
  return ( self . refresh_multicast ( ) )
  if 68 - 68: OoooooooOO + OoOoOO00 + i11iIiiIii
  if 89 - 89: Oo0Ooo + Ii1I * O0 - I1Ii111
 def refresh_unicast ( self ) :
  return ( self . is_active ( ) and self . has_ttl_elapsed ( ) and
 self . gleaned == False )
  if 33 - 33: iIii1I11I1II1 . I11i
  if 63 - 63: oO0o - iII111i
 def refresh_multicast ( self ) :
  if 13 - 13: I1Ii111 / i1IIi % OoooooooOO / I11i
  if 66 - 66: I1Ii111 % o0oOOo0O0Ooo . iII111i . ooOoO0o + OOooOOo * II111iiii
  if 33 - 33: oO0o
  if 64 - 64: OoO0O00 % Oo0Ooo % I11i . iII111i % I1IiiI
  if 50 - 50: i1IIi + ooOoO0o - iIii1I11I1II1
  oO000o0Oo00 = int ( ( time . time ( ) - self . uptime ) % self . map_cache_ttl )
  iiiIO0 = ( oO000o0Oo00 in [ 0 , 1 , 2 ] )
  if ( iiiIO0 == False ) : return ( False )
  if 94 - 94: ooOoO0o . IiII - Ii1I + I1ii11iIi11i / ooOoO0o
  if 10 - 10: ooOoO0o . OOooOOo * O0 % II111iiii
  if 12 - 12: oO0o + I1IiiI * Oo0Ooo - iII111i
  if 88 - 88: OOooOOo . OoO0O00
  OOI1iiiI1IIi111 = ( ( time . time ( ) - self . last_multicast_map_request ) <= 2 )
  if ( OOI1iiiI1IIi111 ) : return ( False )
  if 83 - 83: I1ii11iIi11i / OoOoOO00 % OoooooooOO
  self . last_multicast_map_request = lisp_get_timestamp ( )
  return ( True )
  if 54 - 54: I11i / I1IiiI * IiII - iII111i
  if 37 - 37: i1IIi * I1Ii111 / I11i * II111iiii + OoooooooOO . OoO0O00
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . last_refresh_time
  if ( oO000o0Oo00 >= self . map_cache_ttl ) : return ( True )
  if 22 - 22: OoOoOO00 + OoooooooOO - I1Ii111
  if 82 - 82: Ii1I % I1Ii111 / ooOoO0o
  if 86 - 86: II111iiii - iIii1I11I1II1 + oO0o + I1IiiI
  if 29 - 29: Ii1I % OoooooooOO * II111iiii
  if 88 - 88: I1Ii111 + I11i + I1Ii111 % OoO0O00 / I1ii11iIi11i - I11i
  iIi11ii1 = self . map_cache_ttl - ( self . map_cache_ttl / 10 )
  if ( oO000o0Oo00 >= iIi11ii1 ) : return ( True )
  return ( False )
  if 55 - 55: I1ii11iIi11i - I11i
  if 73 - 73: i11iIiiIii . OoO0O00 + OoO0O00 - OOooOOo % OOooOOo - OoO0O00
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . stats . last_increment
  return ( oO000o0Oo00 <= 60 )
  if 5 - 5: I1ii11iIi11i + i1IIi * I11i % iII111i
  if 96 - 96: ooOoO0o % I1ii11iIi11i % i11iIiiIii * I11i * iII111i . i11iIiiIii
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 65 - 65: i11iIiiIii / o0oOOo0O0Ooo % I1ii11iIi11i - O0 % OoooooooOO / o0oOOo0O0Ooo
  if 36 - 36: iII111i * OoO0O00 / OOooOOo * IiII * iIii1I11I1II1 / IiII
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 79 - 79: iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
  if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for oOO in self . best_rloc_set :
   oOO . delete_from_rloc_probe_list ( self . eid , self . group )
   if 65 - 65: OoOoOO00
   if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
   if 58 - 58: OoO0O00 * I1IiiI - II111iiii / Ii1I - I1IiiI % OoooooooOO
 def build_best_rloc_set ( self ) :
  i1Iiooo00ooOO0 = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 84 - 84: oO0o * iII111i % i11iIiiIii - O0 . iIii1I11I1II1 - OoOoOO00
  if 73 - 73: OoOoOO00
  if 66 - 66: Oo0Ooo
  if 42 - 42: i11iIiiIii / II111iiii . OOooOOo
  oOOoOoo0Ooo = 256
  for oOO in self . rloc_set :
   if ( oOO . up_state ( ) ) : oOOoOoo0Ooo = min ( oOO . priority , oOOoOoo0Ooo )
   if 54 - 54: I1Ii111 + O0 + Ii1I + I1ii11iIi11i * I1ii11iIi11i
   if 92 - 92: OoooooooOO
   if 11 - 11: Oo0Ooo - II111iiii
   if 55 - 55: I1Ii111 - I1IiiI . oO0o - OoO0O00 + Oo0Ooo - Oo0Ooo
   if 68 - 68: Oo0Ooo / I1ii11iIi11i % OoOoOO00 + Oo0Ooo
   if 92 - 92: II111iiii . O0 . iIii1I11I1II1 % IiII - i11iIiiIii
   if 9 - 9: OoO0O00
   if 60 - 60: O0 / OoOoOO00 % i11iIiiIii % II111iiii / OoooooooOO
   if 52 - 52: ooOoO0o
   if 100 - 100: Oo0Ooo - o0oOOo0O0Ooo + iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1
  for oOO in self . rloc_set :
   if ( oOO . priority <= oOOoOoo0Ooo ) :
    if ( oOO . unreach_state ( ) and oOO . last_rloc_probe == None ) :
     oOO . last_rloc_probe = lisp_get_timestamp ( )
     if 4 - 4: OoOoOO00 / Oo0Ooo - OoO0O00 . OoOoOO00 / I1Ii111
    self . best_rloc_set . append ( oOO )
    if 60 - 60: OOooOOo * I1Ii111
    if 17 - 17: iII111i * I11i / iIii1I11I1II1 - II111iiii
    if 97 - 97: II111iiii * o0oOOo0O0Ooo
    if 13 - 13: o0oOOo0O0Ooo . II111iiii
    if 76 - 76: II111iiii + I1Ii111 . OoooooooOO / IiII % i11iIiiIii
    if 87 - 87: Ii1I / OoOoOO00 / OOooOOo
    if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
    if 19 - 19: i1IIi + IiII . OoO0O00 / O0 - I1Ii111 - Oo0Ooo
  for oOO in i1Iiooo00ooOO0 :
   if ( oOO . priority < oOOoOoo0Ooo ) : continue
   oOO . delete_from_rloc_probe_list ( self . eid , self . group )
   if 24 - 24: iII111i + i1IIi
  for oOO in self . best_rloc_set :
   if ( oOO . rloc . is_null ( ) ) : continue
   oOO . add_to_rloc_probe_list ( self . eid , self . group )
   if 31 - 31: OoOoOO00
   if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
   if 43 - 43: II111iiii - OoooooooOO
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  IiiiIi1iiii11 = lisp_packet . packet
  i1II11 = lisp_packet . inner_version
  IiiI1iii1iIiiI = len ( self . best_rloc_set )
  if ( IiiI1iii1iIiiI == 0 ) :
   self . stats . increment ( len ( IiiiIi1iiii11 ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 29 - 29: Oo0Ooo
   if 91 - 91: oO0o / OoO0O00 + I1IiiI * iIii1I11I1II1
  iI11IiIiIi = 4 if lisp_load_split_pings else 0
  IIi1iiIIi1i = lisp_packet . hash_ports ( )
  if ( i1II11 == 4 ) :
   for IiIIi1IiiIiI in range ( 8 + iI11IiIiIi ) :
    IIi1iiIIi1i = IIi1iiIIi1i ^ struct . unpack ( "B" , IiiiIi1iiii11 [ IiIIi1IiiIiI + 12 ] ) [ 0 ]
    if 23 - 23: ooOoO0o
  elif ( i1II11 == 6 ) :
   for IiIIi1IiiIiI in range ( 0 , 32 + iI11IiIiIi , 4 ) :
    IIi1iiIIi1i = IIi1iiIIi1i ^ struct . unpack ( "I" , IiiiIi1iiii11 [ IiIIi1IiiIiI + 8 : IiIIi1IiiIiI + 12 ] ) [ 0 ]
    if 99 - 99: OOooOOo % I11i
   IIi1iiIIi1i = ( IIi1iiIIi1i >> 16 ) + ( IIi1iiIIi1i & 0xffff )
   IIi1iiIIi1i = ( IIi1iiIIi1i >> 8 ) + ( IIi1iiIIi1i & 0xff )
  else :
   for IiIIi1IiiIiI in range ( 0 , 12 + iI11IiIiIi , 4 ) :
    IIi1iiIIi1i = IIi1iiIIi1i ^ struct . unpack ( "I" , IiiiIi1iiii11 [ IiIIi1IiiIiI : IiIIi1IiiIiI + 4 ] ) [ 0 ]
    if 56 - 56: ooOoO0o
    if 5 - 5: I1Ii111 + I1Ii111 * i11iIiiIii . OoO0O00
    if 50 - 50: iII111i - I1ii11iIi11i . Ii1I + i11iIiiIii + IiII * I1Ii111
  if ( lisp_data_plane_logging ) :
   O00OoOoOOO0Oo = [ ]
   for O0OOOO0o0O in self . best_rloc_set :
    if ( O0OOOO0o0O . rloc . is_null ( ) ) : continue
    O00OoOoOOO0Oo . append ( [ O0OOOO0o0O . rloc . print_address_no_iid ( ) , O0OOOO0o0O . print_state ( ) ] )
    if 85 - 85: OoooooooOO + I1ii11iIi11i
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( IIi1iiIIi1i ) , IIi1iiIIi1i % IiiI1iii1iIiiI , red ( str ( O00OoOoOOO0Oo ) , False ) ) )
   if 28 - 28: o0oOOo0O0Ooo - i1IIi + i1IIi * i1IIi / ooOoO0o + I11i
   if 2 - 2: i1IIi + o0oOOo0O0Ooo * OoooooooOO - i1IIi . iII111i
   if 4 - 4: I1Ii111
   if 61 - 61: I1Ii111 - iII111i + OoOoOO00
   if 51 - 51: Oo0Ooo + I1IiiI
   if 63 - 63: I11i
  oOO = self . best_rloc_set [ IIi1iiIIi1i % IiiI1iii1iIiiI ]
  if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
  if 63 - 63: o0oOOo0O0Ooo . IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
  if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
  if 38 - 38: O0 % I1ii11iIi11i + O0
  if 37 - 37: Oo0Ooo / I1IiiI
  ii1 = lisp_get_echo_nonce ( oOO . rloc , None )
  if ( ii1 ) :
   ii1 . change_state ( oOO )
   if ( oOO . no_echoed_nonce_state ( ) ) :
    ii1 . request_nonce_sent = None
    if 23 - 23: II111iiii / iII111i
    if 55 - 55: i11iIiiIii - Ii1I % OoooooooOO * OoooooooOO
    if 92 - 92: iIii1I11I1II1
    if 47 - 47: Oo0Ooo + Oo0Ooo * ooOoO0o - OoOoOO00 + II111iiii
    if 10 - 10: II111iiii / ooOoO0o . Ii1I / I1Ii111 / oO0o
    if 8 - 8: OOooOOo / ooOoO0o * I11i + OOooOOo * i1IIi
  if ( oOO . up_state ( ) == False ) :
   iIiI1I1Ii = IIi1iiIIi1i % IiiI1iii1iIiiI
   ooo = ( iIiI1I1Ii + 1 ) % IiiI1iii1iIiiI
   while ( ooo != iIiI1I1Ii ) :
    oOO = self . best_rloc_set [ ooo ]
    if ( oOO . up_state ( ) ) : break
    ooo = ( ooo + 1 ) % IiiI1iii1iIiiI
    if 16 - 16: OOooOOo % IiII . I1IiiI / Ii1I - OoOoOO00 . IiII
   if ( ooo == iIiI1I1Ii ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 22 - 22: o0oOOo0O0Ooo - IiII . I11i - I1Ii111 * I11i - OoOoOO00
    if 30 - 30: II111iiii - I1Ii111 * Oo0Ooo
    if 21 - 21: OoOoOO00 + IiII - i1IIi - O0
    if 8 - 8: OoooooooOO . IiII . Oo0Ooo - Oo0Ooo % o0oOOo0O0Ooo
    if 8 - 8: I11i % o0oOOo0O0Ooo
    if 39 - 39: OoooooooOO - I1Ii111 . i1IIi . I1ii11iIi11i
  oOO . stats . increment ( len ( IiiiIi1iiii11 ) )
  if 72 - 72: I1ii11iIi11i % Ii1I
  if 37 - 37: O0
  if 41 - 41: iII111i . Ii1I . OoooooooOO / OoOoOO00
  if 85 - 85: II111iiii - II111iiii
  if ( oOO . rle_name and oOO . rle == None ) :
   if ( lisp_rle_list . has_key ( oOO . rle_name ) ) :
    oOO . rle = lisp_rle_list [ oOO . rle_name ]
    if 95 - 95: II111iiii + II111iiii + iII111i
    if 38 - 38: OoO0O00 * Ii1I * O0 / I1IiiI
  if ( oOO . rle ) : return ( [ None , None , None , None , oOO . rle , None ] )
  if 99 - 99: Oo0Ooo + ooOoO0o - I1ii11iIi11i + I1Ii111 + Ii1I * I1IiiI
  if 68 - 68: OoO0O00
  if 79 - 79: Ii1I . IiII + OoOoOO00
  if 10 - 10: OoooooooOO * iII111i * ooOoO0o . Ii1I % I1Ii111 / I1ii11iIi11i
  if ( oOO . elp and oOO . elp . use_elp_node ) :
   return ( [ oOO . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 71 - 71: Ii1I + IiII
   if 10 - 10: II111iiii % o0oOOo0O0Ooo . o0oOOo0O0Ooo % iII111i
   if 2 - 2: OoooooooOO / IiII % Oo0Ooo % iIii1I11I1II1
   if 62 - 62: oO0o
   if 47 - 47: I1IiiI - O0 - I1ii11iIi11i . OoOoOO00
  OOoOoO0O = None if ( oOO . rloc . is_null ( ) ) else oOO . rloc
  Oo0O00O = oOO . translated_port
  I11I1iI = self . action if ( OOoOoO0O == None ) else None
  if 49 - 49: OoOoOO00 / o0oOOo0O0Ooo % OoO0O00
  if 50 - 50: iIii1I11I1II1 - OoooooooOO + I1ii11iIi11i / Oo0Ooo * OOooOOo
  if 37 - 37: O0 % I1Ii111 * OOooOOo / OOooOOo
  if 95 - 95: I1ii11iIi11i % o0oOOo0O0Ooo . oO0o
  if 9 - 9: OoOoOO00 % OoOoOO00 * ooOoO0o / I1IiiI - OOooOOo
  Iii11I = None
  if ( ii1 and ii1 . request_nonce_timeout ( ) == False ) :
   Iii11I = ii1 . get_request_or_echo_nonce ( ipc_socket , OOoOoO0O )
   if 62 - 62: Oo0Ooo + OOooOOo - Oo0Ooo
   if 32 - 32: OoooooooOO
   if 99 - 99: II111iiii % Oo0Ooo / OOooOOo / I1ii11iIi11i % O0 + i1IIi
   if 90 - 90: OoOoOO00 % OoO0O00 . I1IiiI * oO0o
   if 17 - 17: O0 - i1IIi
  return ( [ OOoOoO0O , Oo0O00O , Iii11I , I11I1iI , None , oOO ] )
  if 77 - 77: OOooOOo - i1IIi / II111iiii . I1Ii111 + O0
  if 1 - 1: OoooooooOO % iIii1I11I1II1 * I1ii11iIi11i
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 17 - 17: Ii1I * i1IIi % OoO0O00
  if 12 - 12: I1ii11iIi11i
  if 86 - 86: iIii1I11I1II1 % iII111i
  if 80 - 80: Oo0Ooo
  if 37 - 37: i11iIiiIii - I1Ii111
  for oo0OOOoO0OoO in self . rloc_set :
   for oOO in rloc_address_set :
    if ( oOO . is_exact_match ( oo0OOOoO0OoO . rloc ) == False ) : continue
    oOO = None
    break
    if 50 - 50: I1IiiI / Ii1I / Ii1I + O0 % I11i - i1IIi
   if ( oOO == rloc_address_set [ - 1 ] ) : return ( False )
   if 72 - 72: II111iiii . OoO0O00 . II111iiii * I1ii11iIi11i
  return ( True )
  if 42 - 42: II111iiii
  if 45 - 45: I1ii11iIi11i . I1Ii111 . i1IIi * OOooOOo
 def get_rloc ( self , rloc ) :
  for oo0OOOoO0OoO in self . rloc_set :
   O0OOOO0o0O = oo0OOOoO0OoO . rloc
   if ( rloc . is_exact_match ( O0OOOO0o0O ) ) : return ( oo0OOOoO0OoO )
   if 53 - 53: Ii1I . i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
  return ( None )
  if 87 - 87: I1Ii111 % i11iIiiIii + O0
  if 67 - 67: OoooooooOO / i1IIi / ooOoO0o . i1IIi - i11iIiiIii . i1IIi
 def get_rloc_by_interface ( self , interface ) :
  for oo0OOOoO0OoO in self . rloc_set :
   if ( oo0OOOoO0OoO . interface == interface ) : return ( oo0OOOoO0OoO )
   if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
  return ( None )
  if 15 - 15: I1ii11iIi11i
  if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   iIIo00O000O = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( iIIo00O000O == None ) :
    iIIo00O000O = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , iIIo00O000O )
    if 56 - 56: I1IiiI . ooOoO0o
   iIIo00O000O . add_source_entry ( self )
   if 35 - 35: iIii1I11I1II1 % Oo0Ooo + o0oOOo0O0Ooo * o0oOOo0O0Ooo % ooOoO0o
   if 10 - 10: I1ii11iIi11i / II111iiii % II111iiii - OoooooooOO * o0oOOo0O0Ooo / ooOoO0o
   if 26 - 26: OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   I1iOo0 = lisp_map_cache . lookup_cache ( self . group , True )
   if ( I1iOo0 == None ) :
    I1iOo0 = lisp_mapping ( self . group , self . group , [ ] )
    I1iOo0 . eid . copy_address ( self . group )
    I1iOo0 . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , I1iOo0 )
    if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( I1iOo0 . group )
   I1iOo0 . add_source_entry ( self )
   if 8 - 8: OoooooooOO % I11i - iII111i * OOooOOo . O0
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 40 - 40: I1Ii111 . oO0o + OoO0O00 % Oo0Ooo / II111iiii
  if 19 - 19: i11iIiiIii
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 20 - 20: i11iIiiIii . II111iiii - I1ii11iIi11i / ooOoO0o % i11iIiiIii
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    iIiIIi1i = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( iIiIIi1i ) )
    if 28 - 28: Ii1I + OOooOOo % IiII . i11iIiiIii - I1IiiI * Oo0Ooo
  else :
   I1iOo0 = lisp_map_cache . lookup_cache ( self . group , True )
   if ( I1iOo0 == None ) : return
   if 2 - 2: I11i * I1ii11iIi11i + O0
   iiIi1 = I1iOo0 . lookup_source_cache ( self . eid , True )
   if ( iiIi1 == None ) : return
   if 10 - 10: OOooOOo
   I1iOo0 . source_cache . delete_cache ( self . eid )
   if ( I1iOo0 . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 78 - 78: OOooOOo * I1ii11iIi11i % i11iIiiIii % o0oOOo0O0Ooo . I1ii11iIi11i / OoooooooOO
    if 12 - 12: iIii1I11I1II1 % OoO0O00 + OOooOOo * iIii1I11I1II1 - iIii1I11I1II1
    if 70 - 70: OoO0O00 % i11iIiiIii * IiII . I11i * Oo0Ooo
    if 17 - 17: i1IIi
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 29 - 29: OOooOOo % OoO0O00 + oO0o + o0oOOo0O0Ooo . iII111i
  if 14 - 14: i1IIi + OoOoOO00 * oO0o - II111iiii + IiII + OoOoOO00
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 42 - 42: Oo0Ooo + iII111i * ooOoO0o
  if 72 - 72: iIii1I11I1II1 % I1Ii111
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 77 - 77: I1Ii111 * I1IiiI / iIii1I11I1II1 . II111iiii * Oo0Ooo
  if 71 - 71: ooOoO0o / iIii1I11I1II1 % O0 / I1ii11iIi11i . I1Ii111 / i11iIiiIii
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  o0OoO0000o = "," + str ( self . secondary_iid )
  return ( prefix . replace ( o0OoO0000o , o0OoO0000o + "*" ) )
  if 6 - 6: oO0o . OoO0O00 - II111iiii . I1IiiI - o0oOOo0O0Ooo - i1IIi
  if 42 - 42: Ii1I + i11iIiiIii
 def increment_decap_stats ( self , packet ) :
  Oo0O00O = packet . udp_dport
  if ( Oo0O00O == LISP_DATA_PORT ) :
   oOO = self . get_rloc ( packet . outer_dest )
  else :
   if 46 - 46: O0 % OoOoOO00 - I1Ii111 . I1IiiI
   if 66 - 66: II111iiii * iIii1I11I1II1 * ooOoO0o * I11i . II111iiii - ooOoO0o
   if 15 - 15: I1ii11iIi11i - i11iIiiIii - Ii1I / Ii1I . iII111i
   if 36 - 36: oO0o + Oo0Ooo * I1Ii111 % OOooOOo . Oo0Ooo . I1IiiI
   for oOO in self . rloc_set :
    if ( oOO . translated_port != 0 ) : break
    if 81 - 81: o0oOOo0O0Ooo . OoOoOO00 . i11iIiiIii
    if 13 - 13: i1IIi
  if ( oOO != None ) : oOO . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 70 - 70: O0 / II111iiii
  if 98 - 98: OoOoOO00 - O0 . O0 + ooOoO0o * iIii1I11I1II1
 def rtrs_in_rloc_set ( self ) :
  for oOO in self . rloc_set :
   if ( oOO . is_rtr ( ) ) : return ( True )
   if 7 - 7: IiII * OoOoOO00 + iIii1I11I1II1 / OoOoOO00 + Oo0Ooo / o0oOOo0O0Ooo
  return ( False )
  if 77 - 77: i1IIi . I1IiiI
  if 59 - 59: O0 + OoooooooOO - i1IIi
 def add_recent_source ( self , source ) :
  self . recent_sources [ source . print_address ( ) ] = lisp_get_timestamp ( )
  if 87 - 87: IiII * OoooooooOO / Oo0Ooo % iIii1I11I1II1 % oO0o
  if 97 - 97: ooOoO0o % i1IIi . IiII / Oo0Ooo . I1Ii111 . OoO0O00
  if 12 - 12: I1IiiI
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 99 - 99: II111iiii - OoOoOO00
  if 22 - 22: i11iIiiIii * II111iiii
 def get_timeout ( self , interface ) :
  try :
   iIi111i1II = lisp_myinterfaces [ interface ]
   self . timeout = iIi111i1II . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 68 - 68: Oo0Ooo + ooOoO0o . II111iiii
   if 74 - 74: ooOoO0o - iII111i * OoooooooOO . ooOoO0o
   if 35 - 35: I1Ii111 - iII111i . I11i . O0
   if 87 - 87: OOooOOo * ooOoO0o / OoO0O00 / OoO0O00
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 10 - 10: I11i % OOooOOo % i1IIi + I1IiiI - iIii1I11I1II1 + O0
  if 9 - 9: oO0o % Ii1I
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 20 - 20: OoooooooOO - OoooooooOO + Ii1I % I1Ii111
  if 54 - 54: IiII % oO0o + i11iIiiIii % O0
  if 56 - 56: OoOoOO00 / II111iiii . O0
  if 24 - 24: OoooooooOO * Ii1I * II111iiii
  if 75 - 75: I1IiiI / o0oOOo0O0Ooo . Ii1I / Ii1I / iII111i - Ii1I
  if 39 - 39: OoO0O00 . iIii1I11I1II1 - oO0o
  if 60 - 60: OOooOOo + OOooOOo - Ii1I / iII111i
  if 42 - 42: IiII % oO0o - o0oOOo0O0Ooo * iII111i - Oo0Ooo
  if 19 - 19: I1IiiI - iII111i - oO0o / II111iiii
  if 98 - 98: IiII * OoOoOO00
def lisp_is_group_more_specific ( group_str , group_mapping ) :
 o0OoO0000o = group_mapping . group_prefix . instance_id
 OO00O = group_mapping . group_prefix . mask_len
 IIi1iiIII11 = lisp_address ( LISP_AFI_IPV4 , group_str , 32 , o0OoO0000o )
 if ( IIi1iiIII11 . is_more_specific ( group_mapping . group_prefix ) ) : return ( OO00O )
 return ( - 1 )
 if 13 - 13: O0 + oO0o - iIii1I11I1II1 - Oo0Ooo % I1IiiI
 if 45 - 45: O0
 if 55 - 55: i11iIiiIii * Ii1I % OOooOOo + ooOoO0o - I1ii11iIi11i . Oo0Ooo
 if 48 - 48: o0oOOo0O0Ooo
 if 55 - 55: OOooOOo - OoooooooOO * iIii1I11I1II1 + iII111i % II111iiii
 if 33 - 33: I1Ii111 * oO0o * OoooooooOO + OOooOOo - I1IiiI + I1Ii111
 if 92 - 92: ooOoO0o * I11i % iIii1I11I1II1 + Ii1I - OoOoOO00
def lisp_lookup_group ( group ) :
 O00OoOoOOO0Oo = None
 for i11o0 in lisp_group_mapping_list . values ( ) :
  OO00O = lisp_is_group_more_specific ( group , i11o0 )
  if ( OO00O == - 1 ) : continue
  if ( O00OoOoOOO0Oo == None or OO00O > O00OoOoOOO0Oo . group_prefix . mask_len ) : O00OoOoOOO0Oo = i11o0
  if 19 - 19: I1Ii111 . IiII / iIii1I11I1II1 + Ii1I / oO0o
 return ( O00OoOoOOO0Oo )
 if 66 - 66: I1IiiI - IiII - ooOoO0o * I11i - II111iiii + Oo0Ooo
 if 51 - 51: Ii1I / Ii1I - I1ii11iIi11i
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 67 - 67: I1IiiI - OoooooooOO * OoooooooOO / OoO0O00
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
  if 79 - 79: Ii1I - II111iiii
  if 57 - 57: II111iiii / OoooooooOO
  if 4 - 4: I11i * OoOoOO00
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
  if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
  if 87 - 87: oO0o . I11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 15 - 15: oO0o
  if 45 - 45: Oo0Ooo * IiII * OoO0O00 + iIii1I11I1II1
 def print_flags ( self , html ) :
  if ( html == False ) :
   Oo0Ooo0O0 = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # iIii1I11I1II1 - iIii1I11I1II1 * OOooOOo * iII111i - I1ii11iIi11i / Oo0Ooo
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
   for IIiI1iII11II1ii in Ooo0OO0O0oO :
    OoooOO0O = lisp_site_flags [ IIiI1iII11II1ii . upper ( ) ]
    OoooOO0O = OoooOO0O . format ( "" if IIiI1iII11II1ii . isupper ( ) else "not " )
    Oo0Ooo0O0 += lisp_span ( IIiI1iII11II1ii , OoooOO0O )
    if ( IIiI1iII11II1ii . lower ( ) != "n" ) : Oo0Ooo0O0 += "-"
    if 47 - 47: i1IIi . i11iIiiIii / I1ii11iIi11i + OoooooooOO % i11iIiiIii - i1IIi
    if 9 - 9: I1ii11iIi11i
  return ( Oo0Ooo0O0 )
  if 68 - 68: I1IiiI + ooOoO0o * i11iIiiIii - OOooOOo / II111iiii
  if 81 - 81: O0 - I1IiiI / ooOoO0o % I1IiiI . iII111i
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 63 - 63: oO0o * Ii1I
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 95 - 95: OoooooooOO % I1ii11iIi11i . I1Ii111 . IiII
  if 98 - 98: OoooooooOO - OoO0O00 . oO0o - iIii1I11I1II1 * iIii1I11I1II1 % Ii1I
 def build_sort_key ( self ) :
  oo0Oo0Oo0o0 = lisp_cache ( )
  iI11i , Oo000O000 = oo0Oo0Oo0o0 . build_key ( self . eid )
  oOOo0O0 = ""
  if ( self . group . is_null ( ) == False ) :
   ooooOO0oo , oOOo0O0 = oo0Oo0Oo0o0 . build_key ( self . group )
   oOOo0O0 = "-" + oOOo0O0 [ 0 : 12 ] + "-" + str ( ooooOO0oo ) + "-" + oOOo0O0 [ 12 : : ]
   if 72 - 72: OoO0O00
  Oo000O000 = Oo000O000 [ 0 : 12 ] + "-" + str ( iI11i ) + "-" + Oo000O000 [ 12 : : ] + oOOo0O0
  del ( oo0Oo0Oo0o0 )
  return ( Oo000O000 )
  if 3 - 3: o0oOOo0O0Ooo
  if 18 - 18: OOooOOo . II111iiii . OoOoOO00 / i1IIi . o0oOOo0O0Ooo
 def merge_in_site_eid ( self , child ) :
  OoO0 = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   OoO0 = self . merge_rles_in_site_eid ( )
   if 87 - 87: OOooOOo + II111iiii . I11i
   if 7 - 7: IiII . iIii1I11I1II1 % o0oOOo0O0Ooo + iII111i . OOooOOo + I1IiiI
   if 64 - 64: iII111i - ooOoO0o % OoO0O00
   if 51 - 51: I1Ii111 . ooOoO0o
   if 100 - 100: o0oOOo0O0Ooo % iII111i
   if 44 - 44: IiII * OoOoOO00 - OoO0O00 - OoooooooOO - I1ii11iIi11i - II111iiii
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 26 - 26: ooOoO0o - i1IIi / OOooOOo + OoOoOO00 / iII111i
  return ( OoO0 )
  if 27 - 27: I11i % Ii1I / iII111i . OoOoOO00
  if 88 - 88: iII111i - i11iIiiIii * I1Ii111 * i11iIiiIii - O0
 def copy_rloc_records ( self ) :
  iIiI11 = [ ]
  for oo0OOOoO0OoO in self . registered_rlocs :
   iIiI11 . append ( copy . deepcopy ( oo0OOOoO0OoO ) )
   if 72 - 72: Ii1I % O0 + II111iiii . i11iIiiIii
  return ( iIiI11 )
  if 66 - 66: II111iiii % I1IiiI
  if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 + I1Ii111 * OOooOOo . I1IiiI
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for I1iiiI1I1 in self . individual_registrations . values ( ) :
   if ( self . site_id != I1iiiI1I1 . site_id ) : continue
   if ( I1iiiI1I1 . registered == False ) : continue
   self . registered_rlocs += I1iiiI1I1 . copy_rloc_records ( )
   if 96 - 96: I1ii11iIi11i
   if 37 - 37: OoO0O00 % o0oOOo0O0Ooo * O0 * O0 + iII111i
   if 18 - 18: i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % oO0o * Ii1I / I1IiiI
   if 46 - 46: o0oOOo0O0Ooo . ooOoO0o / Ii1I
   if 97 - 97: Ii1I . Oo0Ooo - O0 - I1Ii111 . i1IIi
   if 47 - 47: IiII * ooOoO0o - i1IIi % OoOoOO00 * i11iIiiIii . OoooooooOO
  iIiI11 = [ ]
  for oo0OOOoO0OoO in self . registered_rlocs :
   if ( oo0OOOoO0OoO . rloc . is_null ( ) or len ( iIiI11 ) == 0 ) :
    iIiI11 . append ( oo0OOOoO0OoO )
    continue
    if 84 - 84: OoOoOO00 / IiII - i1IIi - I1IiiI * OOooOOo
   for iiII1II1 in iIiI11 :
    if ( iiII1II1 . rloc . is_null ( ) ) : continue
    if ( oo0OOOoO0OoO . rloc . is_exact_match ( iiII1II1 . rloc ) ) : break
    if 82 - 82: ooOoO0o - ooOoO0o . Ii1I . i11iIiiIii % Ii1I + OOooOOo
   if ( iiII1II1 == iIiI11 [ - 1 ] ) : iIiI11 . append ( oo0OOOoO0OoO )
   if 33 - 33: Oo0Ooo - OOooOOo / OoOoOO00 % II111iiii % OOooOOo + I1Ii111
  self . registered_rlocs = iIiI11
  if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
  if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
  if 98 - 98: IiII
  if 75 - 75: OoooooooOO % IiII + Ii1I - i1IIi / OoooooooOO
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 57 - 57: iII111i
  if 18 - 18: II111iiii % i11iIiiIii + I11i - OOooOOo
 def merge_rles_in_site_eid ( self ) :
  if 100 - 100: o0oOOo0O0Ooo / Ii1I - iIii1I11I1II1 / oO0o
  if 68 - 68: I11i / II111iiii * oO0o . II111iiii * OOooOOo
  if 78 - 78: I11i * OoO0O00 / II111iiii
  if 86 - 86: I1Ii111 % II111iiii
  oOO0 = { }
  for oo0OOOoO0OoO in self . registered_rlocs :
   if ( oo0OOOoO0OoO . rle == None ) : continue
   for i1iiiIIi11 in oo0OOOoO0OoO . rle . rle_nodes :
    IiiIIi1 = i1iiiIIi11 . address . print_address_no_iid ( )
    oOO0 [ IiiIIi1 ] = i1iiiIIi11 . address
    if 39 - 39: OoOoOO00 * i1IIi . i11iIiiIii + IiII * II111iiii
   break
   if 13 - 13: I1Ii111
   if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
   if 59 - 59: IiII . OoO0O00 - OoooooooOO . O0
   if 33 - 33: Ii1I
   if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
  self . merge_rlocs_in_site_eid ( )
  if 40 - 40: I1IiiI / OOooOOo * Ii1I
  if 98 - 98: I1IiiI
  if 4 - 4: I1IiiI % O0 / Oo0Ooo / O0
  if 90 - 90: ooOoO0o - O0 . IiII - O0 . iIii1I11I1II1
  if 42 - 42: I1ii11iIi11i
  if 51 - 51: iII111i % i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
  if 14 - 14: I1ii11iIi11i . OoO0O00
  if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
  I1iI1iI1ii = [ ]
  for oo0OOOoO0OoO in self . registered_rlocs :
   if ( self . registered_rlocs . index ( oo0OOOoO0OoO ) == 0 ) :
    I1iI1iI1ii . append ( oo0OOOoO0OoO )
    continue
    if 29 - 29: iII111i . ooOoO0o . I1Ii111
   if ( oo0OOOoO0OoO . rle == None ) : I1iI1iI1ii . append ( oo0OOOoO0OoO )
   if 71 - 71: IiII % O0 % I11i - I1ii11iIi11i
  self . registered_rlocs = I1iI1iI1ii
  if 55 - 55: ooOoO0o * Ii1I
  if 30 - 30: O0
  if 8 - 8: O0 + OoOoOO00 / Ii1I
  if 21 - 21: O0 / OOooOOo . Oo0Ooo % O0
  if 95 - 95: O0 - I1IiiI / O0 % O0
  if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
  if 65 - 65: I1ii11iIi11i % ooOoO0o - OoOoOO00 + ooOoO0o + Oo0Ooo
  iI1Ii11 = lisp_rle ( "" )
  O0OoOooO0O00o = { }
  I1io0 = None
  for I1iiiI1I1 in self . individual_registrations . values ( ) :
   if ( I1iiiI1I1 . registered == False ) : continue
   IiiiI111I1 = I1iiiI1I1 . registered_rlocs [ 0 ] . rle
   if ( IiiiI111I1 == None ) : continue
   if 14 - 14: IiII / iII111i % OoooooooOO
   I1io0 = I1iiiI1I1 . registered_rlocs [ 0 ] . rloc_name
   for IiiIi1 in IiiiI111I1 . rle_nodes :
    IiiIIi1 = IiiIi1 . address . print_address_no_iid ( )
    if ( O0OoOooO0O00o . has_key ( IiiIIi1 ) ) : break
    if 86 - 86: I1Ii111 % i1IIi
    i1iiiIIi11 = lisp_rle_node ( )
    i1iiiIIi11 . address . copy_address ( IiiIi1 . address )
    i1iiiIIi11 . level = IiiIi1 . level
    i1iiiIIi11 . rloc_name = I1io0
    iI1Ii11 . rle_nodes . append ( i1iiiIIi11 )
    O0OoOooO0O00o [ IiiIIi1 ] = IiiIi1 . address
    if 35 - 35: IiII
    if 91 - 91: iIii1I11I1II1
    if 66 - 66: i1IIi . ooOoO0o
    if 84 - 84: O0 % ooOoO0o / I1Ii111
    if 75 - 75: I11i - iII111i . O0
    if 52 - 52: I1ii11iIi11i
  if ( len ( iI1Ii11 . rle_nodes ) == 0 ) : iI1Ii11 = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = iI1Ii11
   if ( I1io0 ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 22 - 22: I1ii11iIi11i - i1IIi / OOooOOo . o0oOOo0O0Ooo . oO0o
   if 9 - 9: ooOoO0o - I1Ii111 + IiII . iII111i
   if 52 - 52: I1Ii111 + oO0o % II111iiii - i1IIi
   if 32 - 32: I1Ii111 % ooOoO0o + I1Ii111 / I1ii11iIi11i - o0oOOo0O0Ooo + ooOoO0o
   if 46 - 46: OoO0O00 % OoO0O00 . O0 + II111iiii
  if ( oOO0 . keys ( ) == O0OoOooO0O00o . keys ( ) ) : return ( False )
  if 42 - 42: OOooOOo * I1Ii111
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # I11i * II111iiii / I1Ii111 % I1ii11iIi11i
 oOO0 . keys ( ) , O0OoOooO0O00o . keys ( ) ) )
  if 69 - 69: I1ii11iIi11i * I1Ii111 % II111iiii
  return ( True )
  if 15 - 15: IiII . I1ii11iIi11i / I1IiiI . I1ii11iIi11i + Ii1I
  if 82 - 82: OOooOOo / I1IiiI % Oo0Ooo - OoO0O00 - o0oOOo0O0Ooo
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   IiI111II1I1iI = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( IiI111II1I1iI == None ) :
    IiI111II1I1iI = lisp_site_eid ( self . site )
    IiI111II1I1iI . eid . copy_address ( self . group )
    IiI111II1I1iI . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , IiI111II1I1iI )
    if 95 - 95: iII111i % o0oOOo0O0Ooo
    if 26 - 26: i1IIi / iII111i + iII111i
    if 66 - 66: i1IIi + I1IiiI
    if 45 - 45: I1Ii111 . iII111i + OoO0O00 - O0
    if 71 - 71: Oo0Ooo + OOooOOo
    IiI111II1I1iI . parent_for_more_specifics = self . parent_for_more_specifics
    if 94 - 94: OOooOOo
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( IiI111II1I1iI . group )
   IiI111II1I1iI . add_source_entry ( self )
   if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
   if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
   if 31 - 31: I11i . o0oOOo0O0Ooo
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   IiI111II1I1iI = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( IiI111II1I1iI == None ) : return
   if 82 - 82: I11i - Oo0Ooo
   I1iiiI1I1 = IiI111II1I1iI . lookup_source_cache ( self . eid , True )
   if ( I1iiiI1I1 == None ) : return
   if 77 - 77: I1IiiI + OoO0O00 % iIii1I11I1II1 - OOooOOo
   if ( IiI111II1I1iI . source_cache == None ) : return
   if 80 - 80: oO0o % I1ii11iIi11i * I1Ii111 + i1IIi
   IiI111II1I1iI . source_cache . delete_cache ( self . eid )
   if ( IiI111II1I1iI . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 79 - 79: oO0o + IiII
    if 4 - 4: iII111i + OoooooooOO / I1Ii111
    if 57 - 57: I1IiiI . iIii1I11I1II1 % iII111i * iII111i / I1Ii111
    if 30 - 30: O0 / I11i % OoOoOO00 * I1Ii111 / O0 % ooOoO0o
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 36 - 36: iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
  if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 97 - 97: i11iIiiIii / O0 % OoO0O00
  if 88 - 88: i1IIi . I1IiiI
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
  if 51 - 51: oO0o + Ii1I * Ii1I * I1ii11iIi11i % I11i - I1ii11iIi11i
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 15 - 15: i1IIi / OoO0O00 - Oo0Ooo
  if 74 - 74: o0oOOo0O0Ooo % Ii1I - II111iiii / ooOoO0o
 def inherit_from_ams_parent ( self ) :
  O00oOO0OO00 = self . parent_for_more_specifics
  if ( O00oOO0OO00 == None ) : return
  self . force_proxy_reply = O00oOO0OO00 . force_proxy_reply
  self . force_nat_proxy_reply = O00oOO0OO00 . force_nat_proxy_reply
  self . force_ttl = O00oOO0OO00 . force_ttl
  self . pitr_proxy_reply_drop = O00oOO0OO00 . pitr_proxy_reply_drop
  self . proxy_reply_action = O00oOO0OO00 . proxy_reply_action
  self . echo_nonce_capable = O00oOO0OO00 . echo_nonce_capable
  self . policy = O00oOO0OO00 . policy
  self . require_signature = O00oOO0OO00 . require_signature
  if 84 - 84: I1IiiI + OOooOOo
  if 80 - 80: OOooOOo / OoOoOO00
 def rtrs_in_rloc_set ( self ) :
  for oo0OOOoO0OoO in self . registered_rlocs :
   if ( oo0OOOoO0OoO . is_rtr ( ) ) : return ( True )
   if 93 - 93: OOooOOo
  return ( False )
  if 82 - 82: iIii1I11I1II1 + OoO0O00 / iIii1I11I1II1 . iIii1I11I1II1
  if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for oo0OOOoO0OoO in self . registered_rlocs :
   if ( oo0OOOoO0OoO . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( oo0OOOoO0OoO . is_rtr ( ) ) : return ( True )
   if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
  return ( False )
  if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
  if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
 def is_rloc_in_rloc_set ( self , rloc ) :
  for oo0OOOoO0OoO in self . registered_rlocs :
   if ( oo0OOOoO0OoO . rle ) :
    for iI1Ii11 in oo0OOOoO0OoO . rle . rle_nodes :
     if ( iI1Ii11 . address . is_exact_match ( rloc ) ) : return ( True )
     if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
     if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
   if ( oo0OOOoO0OoO . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
  return ( False )
  if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
  if 91 - 91: II111iiii * o0oOOo0O0Ooo
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 20 - 20: iIii1I11I1II1 % Oo0Ooo * OoOoOO00 % IiII
  for oo0OOOoO0OoO in prev_rloc_set :
   I11iI = oo0OOOoO0OoO . rloc
   if ( self . is_rloc_in_rloc_set ( I11iI ) == False ) : return ( False )
   if 93 - 93: I11i * iIii1I11I1II1 * oO0o
  return ( True )
  if 74 - 74: I1IiiI
  if 39 - 39: iII111i * IiII / iII111i * IiII % I1ii11iIi11i
  if 27 - 27: iIii1I11I1II1 . ooOoO0o
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
   if 74 - 74: i1IIi % OoOoOO00
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 98 - 98: IiII * OOooOOo / O0 - I1Ii111 . I1Ii111 + OOooOOo
  if 61 - 61: iII111i * Ii1I % Ii1I + I1IiiI
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 23 - 23: oO0o + I1Ii111 / OoooooooOO / O0 + IiII
  try :
   IIiiI = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   OoOoooOoO = IIiiI [ 2 ]
  except :
   return
   if 100 - 100: Ii1I
   if 73 - 73: IiII - O0
   if 54 - 54: OOooOOo
   if 28 - 28: i1IIi - Oo0Ooo * OoO0O00 + OoooooooOO - Ii1I * i11iIiiIii
   if 71 - 71: iII111i - OOooOOo / iIii1I11I1II1 % i11iIiiIii
   if 39 - 39: o0oOOo0O0Ooo
  if ( len ( OoOoooOoO ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 32 - 32: iIii1I11I1II1 . II111iiii / IiII % O0 / iII111i
   if 97 - 97: iIii1I11I1II1
  IiiIIi1 = OoOoooOoO [ self . a_record_index ]
  if ( IiiIIi1 != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( IiiIIi1 )
   self . insert_mr ( )
   if 18 - 18: OOooOOo
   if 87 - 87: O0 - i1IIi . I11i / Ii1I % iIii1I11I1II1
   if 57 - 57: I11i . IiII / iIii1I11I1II1 - ooOoO0o
   if 50 - 50: O0 / II111iiii
   if 94 - 94: O0 + O0 % I1ii11iIi11i % i1IIi
   if 15 - 15: I1IiiI
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 48 - 48: Ii1I * IiII % O0 - II111iiii
  for IiiIIi1 in OoOoooOoO [ 1 : : ] :
   OO0o = lisp_address ( LISP_AFI_NONE , IiiIIi1 , 0 , 0 )
   O0O0OOoO00 = lisp_get_map_resolver ( OO0o , None )
   if ( O0O0OOoO00 != None and O0O0OOoO00 . a_record_index == OoOoooOoO . index ( IiiIIi1 ) ) :
    continue
    if 66 - 66: iIii1I11I1II1 / OOooOOo
   O0O0OOoO00 = lisp_mr ( IiiIIi1 , None , None )
   O0O0OOoO00 . a_record_index = OoOoooOoO . index ( IiiIIi1 )
   O0O0OOoO00 . dns_name = self . dns_name
   O0O0OOoO00 . last_dns_resolve = lisp_get_timestamp ( )
   if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
   if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
   if 67 - 67: I1Ii111
   if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
   if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
  i1i1iI1I1 = [ ]
  for O0O0OOoO00 in lisp_map_resolvers_list . values ( ) :
   if ( self . dns_name != O0O0OOoO00 . dns_name ) : continue
   OO0o = O0O0OOoO00 . map_resolver . print_address_no_iid ( )
   if ( OO0o in OoOoooOoO ) : continue
   i1i1iI1I1 . append ( O0O0OOoO00 )
   if 89 - 89: O0 * OoOoOO00 * iII111i
  for O0O0OOoO00 in i1i1iI1I1 : O0O0OOoO00 . delete_mr ( )
  if 90 - 90: i11iIiiIii / i1IIi
  if 35 - 35: Ii1I . I11i / oO0o / OoOoOO00
 def insert_mr ( self ) :
  Oo000O000 = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ Oo000O000 ] = self
  if 5 - 5: I1ii11iIi11i . o0oOOo0O0Ooo * iII111i * I1ii11iIi11i % I1Ii111
  if 83 - 83: iIii1I11I1II1 * o0oOOo0O0Ooo % i11iIiiIii + OoO0O00 . O0
 def delete_mr ( self ) :
  Oo000O000 = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( Oo000O000 ) == False ) : return
  lisp_map_resolvers_list . pop ( Oo000O000 )
  if 87 - 87: II111iiii - iIii1I11I1II1 % I11i % I1IiiI . o0oOOo0O0Ooo
  if 52 - 52: i11iIiiIii . oO0o / OoooooooOO - OoO0O00
  if 7 - 7: I1IiiI * I1IiiI % OOooOOo % iIii1I11I1II1 * OoO0O00 . o0oOOo0O0Ooo
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 32 - 32: ooOoO0o / i1IIi
  if 55 - 55: oO0o . OoOoOO00 + OoooooooOO - ooOoO0o . OoooooooOO
  if 77 - 77: I1IiiI
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
  if 16 - 16: I1IiiI + ooOoO0o - O0 / o0oOOo0O0Ooo
  if 36 - 36: Oo0Ooo - OoOoOO00 - II111iiii
 def print_referral ( self , eid_indent , referral_indent ) :
  Ii1i11 = lisp_print_elapsed ( self . uptime )
  O0000oOooO = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , Ii1i11 ,
  # O0 - O0
 O0000oOooO , len ( self . referral_set ) ) )
  if 46 - 46: I1Ii111 * I1Ii111 - OoooooooOO * iIii1I11I1II1 - oO0o
  for oO0O0o0000 in self . referral_set . values ( ) :
   oO0O0o0000 . print_ref_node ( referral_indent )
   if 34 - 34: IiII + ooOoO0o . IiII * iII111i
   if 42 - 42: oO0o * I1IiiI
   if 65 - 65: ooOoO0o
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 88 - 88: OOooOOo - O0 % o0oOOo0O0Ooo + o0oOOo0O0Ooo % i11iIiiIii * I11i
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 98 - 98: iII111i % IiII + OoO0O00
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 23 - 23: OOooOOo
  if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 99 - 99: II111iiii + O0
  if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
 def print_ttl ( self ) :
  oOoooOOO0o0 = self . referral_ttl
  if ( oOoooOOO0o0 < 60 ) : return ( str ( oOoooOOO0o0 ) + " secs" )
  if 88 - 88: Oo0Ooo . iII111i
  if ( ( oOoooOOO0o0 % 60 ) == 0 ) :
   oOoooOOO0o0 = str ( oOoooOOO0o0 / 60 ) + " mins"
  else :
   oOoooOOO0o0 = str ( oOoooOOO0o0 ) + " secs"
   if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
  return ( oOoooOOO0o0 )
  if 9 - 9: OoOoOO00 % i1IIi + IiII
  if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # II111iiii - II111iiii + i1IIi + OoO0O00 % iIii1I11I1II1 * ooOoO0o
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
  if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   iiooOOOoOo00O0O = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( iiooOOOoOo00O0O == None ) :
    iiooOOOoOo00O0O = lisp_referral ( )
    iiooOOOoOo00O0O . eid . copy_address ( self . group )
    iiooOOOoOo00O0O . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , iiooOOOoOo00O0O )
    if 32 - 32: OoOoOO00 % i11iIiiIii
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( iiooOOOoOo00O0O . group )
   iiooOOOoOo00O0O . add_source_entry ( self )
   if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
   if 44 - 44: I1Ii111 + ooOoO0o
   if 15 - 15: I11i + OoO0O00 + OoOoOO00
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   iiooOOOoOo00O0O = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( iiooOOOoOo00O0O == None ) : return
   if 100 - 100: I1Ii111
   iI1iIi = iiooOOOoOo00O0O . lookup_source_cache ( self . eid , True )
   if ( iI1iIi == None ) : return
   if 78 - 78: OoOoOO00
   iiooOOOoOo00O0O . source_cache . delete_cache ( self . eid )
   if ( iiooOOOoOo00O0O . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
    if 36 - 36: OoOoOO00 * II111iiii . OoooooooOO * I11i . I11i
    if 13 - 13: I1ii11iIi11i * II111iiii
    if 93 - 93: OOooOOo / O0 - o0oOOo0O0Ooo + OoO0O00 * I1IiiI
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 53 - 53: I1ii11iIi11i
  if 91 - 91: o0oOOo0O0Ooo - I1ii11iIi11i . i1IIi
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 64 - 64: ooOoO0o
  if 23 - 23: Oo0Ooo . OoO0O00
  if 49 - 49: oO0o % i11iIiiIii * Ii1I
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
  if 61 - 61: O0 - i11iIiiIii * o0oOOo0O0Ooo
 def print_ref_node ( self , indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , i1 ,
  # Oo0Ooo + I1ii11iIi11i + i11iIiiIii - iII111i / O0 % Oo0Ooo
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 40 - 40: O0 * Oo0Ooo % o0oOOo0O0Ooo / OoooooooOO
  if 94 - 94: iII111i
  if 79 - 79: o0oOOo0O0Ooo / I1ii11iIi11i . iII111i . II111iiii + I1ii11iIi11i * I11i
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
   if 49 - 49: Ii1I * OoooooooOO * i1IIi % OoOoOO00
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
   if 83 - 83: iIii1I11I1II1 - i1IIi - Ii1I % iII111i
   if 69 - 69: I1Ii111 * oO0o * I1IiiI
   if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
  try :
   IIiiI = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   OoOoooOoO = IIiiI [ 2 ]
  except :
   return
   if 52 - 52: OoooooooOO
   if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
   if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
   if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
   if 86 - 86: Oo0Ooo / OoO0O00
   if 78 - 78: I1IiiI * I1IiiI
  if ( len ( OoOoooOoO ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 13 - 13: oO0o
   if 43 - 43: oO0o / Ii1I % OOooOOo
  IiiIIi1 = OoOoooOoO [ self . a_record_index ]
  if ( IiiIIi1 != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( IiiIIi1 )
   self . insert_ms ( )
   if 45 - 45: II111iiii
   if 41 - 41: Ii1I / OOooOOo * Oo0Ooo . O0 - i11iIiiIii
   if 77 - 77: o0oOOo0O0Ooo + I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
   if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
   if 43 - 43: OOooOOo . O0
   if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
  for IiiIIi1 in OoOoooOoO [ 1 : : ] :
   OO0o = lisp_address ( LISP_AFI_NONE , IiiIIi1 , 0 , 0 )
   IIIIiI1 = lisp_get_map_server ( OO0o )
   if ( IIIIiI1 != None and IIIIiI1 . a_record_index == OoOoooOoO . index ( IiiIIi1 ) ) :
    continue
    if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
   IIIIiI1 = copy . deepcopy ( self )
   IIIIiI1 . map_server . store_address ( IiiIIi1 )
   IIIIiI1 . a_record_index = OoOoooOoO . index ( IiiIIi1 )
   IIIIiI1 . last_dns_resolve = lisp_get_timestamp ( )
   IIIIiI1 . insert_ms ( )
   if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
   if 24 - 24: ooOoO0o % I1Ii111 + OoO0O00 * o0oOOo0O0Ooo % O0 - i11iIiiIii
   if 49 - 49: o0oOOo0O0Ooo / OoOoOO00 + iII111i
   if 85 - 85: I1IiiI - o0oOOo0O0Ooo
   if 86 - 86: II111iiii + Ii1I * Ii1I
  i1i1iI1I1 = [ ]
  for IIIIiI1 in lisp_map_servers_list . values ( ) :
   if ( self . dns_name != IIIIiI1 . dns_name ) : continue
   OO0o = IIIIiI1 . map_server . print_address_no_iid ( )
   if ( OO0o in OoOoooOoO ) : continue
   i1i1iI1I1 . append ( IIIIiI1 )
   if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
  for IIIIiI1 in i1i1iI1I1 : IIIIiI1 . delete_ms ( )
  if 86 - 86: Ii1I
  if 69 - 69: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
 def insert_ms ( self ) :
  Oo000O000 = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ Oo000O000 ] = self
  if 1 - 1: Ii1I
  if 43 - 43: o0oOOo0O0Ooo
 def delete_ms ( self ) :
  Oo000O000 = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( Oo000O000 ) == False ) : return
  lisp_map_servers_list . pop ( Oo000O000 )
  if 78 - 78: I1Ii111 % i1IIi * I11i
  if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
  if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
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
  if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
  if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 32 - 32: OoooooooOO . I1Ii111 - I1ii11iIi11i
  if 29 - 29: OoO0O00
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 33 - 33: I1ii11iIi11i - O0
  if 72 - 72: Oo0Ooo * iII111i - I11i
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 81 - 81: I1Ii111
  if 85 - 85: O0 % OoOoOO00 . I1ii11iIi11i
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 46 - 46: OOooOOo * iIii1I11I1II1
  if 33 - 33: OoO0O00 * II111iiii / i1IIi
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 93 - 93: I1Ii111 % I11i
  if 64 - 64: I1IiiI % OoOoOO00 / Oo0Ooo
 def set_socket ( self , device ) :
  IiII1iiI = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  IiII1iiI . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   IiII1iiI . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   IiII1iiI . close ( )
   IiII1iiI = None
   if 40 - 40: Ii1I + iIii1I11I1II1 / oO0o . II111iiii % O0 - IiII
  self . raw_socket = IiII1iiI
  if 49 - 49: IiII - OOooOOo * OOooOOo . O0
  if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
 def set_bridge_socket ( self , device ) :
  IiII1iiI = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   IiII1iiI = IiII1iiI . bind ( ( device , 0 ) )
   self . bridge_socket = IiII1iiI
  except :
   return
   if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
   if 61 - 61: OoO0O00
   if 100 - 100: OoOoOO00
   if 97 - 97: OoooooooOO
class lisp_datetime ( ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
  if 35 - 35: iII111i % OoO0O00 * O0
 def valid_datetime ( self ) :
  i1I1Iii1II = self . datetime_name
  if ( i1I1Iii1II . find ( ":" ) == - 1 ) : return ( False )
  if ( i1I1Iii1II . find ( "-" ) == - 1 ) : return ( False )
  III1i1iii111 , oO0OO0O , oOo00Oo0o , time = i1I1Iii1II [ 0 : 4 ] , i1I1Iii1II [ 5 : 7 ] , i1I1Iii1II [ 8 : 10 ] , i1I1Iii1II [ 11 : : ]
  if 85 - 85: oO0o % I1Ii111
  if ( ( III1i1iii111 + oO0OO0O + oOo00Oo0o ) . isdigit ( ) == False ) : return ( False )
  if ( oO0OO0O < "01" and oO0OO0O > "12" ) : return ( False )
  if ( oOo00Oo0o < "01" and oOo00Oo0o > "31" ) : return ( False )
  if 18 - 18: OOooOOo * I1IiiI + Ii1I
  I1oooo000oo , O0OOooOo0 , iiIi1iI1I11 = time . split ( ":" )
  if 72 - 72: I1Ii111 . OoooooooOO . I1IiiI % o0oOOo0O0Ooo % i11iIiiIii
  if ( ( I1oooo000oo + O0OOooOo0 + iiIi1iI1I11 ) . isdigit ( ) == False ) : return ( False )
  if ( I1oooo000oo < "00" and I1oooo000oo > "23" ) : return ( False )
  if ( O0OOooOo0 < "00" and O0OOooOo0 > "59" ) : return ( False )
  if ( iiIi1iI1I11 < "00" and iiIi1iI1I11 > "59" ) : return ( False )
  return ( True )
  if 13 - 13: OoooooooOO
  if 29 - 29: I1Ii111 + OOooOOo . OoooooooOO . II111iiii + OoO0O00 / OoooooooOO
 def parse_datetime ( self ) :
  ooOOOOOO0oo0O = self . datetime_name
  ooOOOOOO0oo0O = ooOOOOOO0oo0O . replace ( "-" , "" )
  ooOOOOOO0oo0O = ooOOOOOO0oo0O . replace ( ":" , "" )
  self . datetime = int ( ooOOOOOO0oo0O )
  if 7 - 7: I1Ii111
  if 98 - 98: IiII * ooOoO0o + o0oOOo0O0Ooo / I11i - Ii1I * OoOoOO00
 def now ( self ) :
  i1 = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  i1 = lisp_datetime ( i1 )
  return ( i1 )
  if 26 - 26: iIii1I11I1II1 . oO0o
  if 8 - 8: I1ii11iIi11i * OOooOOo * iIii1I11I1II1 + I11i . iII111i
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 55 - 55: I1IiiI + Ii1I % I1ii11iIi11i + iIii1I11I1II1
  if 64 - 64: i1IIi / O0 - oO0o
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 7 - 7: IiII . IiII * Ii1I
  if 1 - 1: i11iIiiIii
 def past ( self ) :
  return ( self . future ( ) == False )
  if 91 - 91: I1ii11iIi11i . OoO0O00 / OoO0O00 / I1ii11iIi11i + iII111i
  if 20 - 20: o0oOOo0O0Ooo . I1Ii111 + O0
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 99 - 99: O0 / IiII . oO0o
  if 18 - 18: OoooooooOO * OoO0O00 * I1Ii111
 def this_year ( self ) :
  Iiii1 = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  i1 = str ( self . datetime ) [ 0 : 4 ]
  return ( i1 == Iiii1 )
  if 75 - 75: I11i * ooOoO0o * Oo0Ooo . i1IIi . ooOoO0o . ooOoO0o
  if 24 - 24: iIii1I11I1II1
 def this_month ( self ) :
  Iiii1 = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  i1 = str ( self . datetime ) [ 0 : 6 ]
  return ( i1 == Iiii1 )
  if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
  if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
 def today ( self ) :
  Iiii1 = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  i1 = str ( self . datetime ) [ 0 : 8 ]
  return ( i1 == Iiii1 )
  if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
  if 62 - 62: o0oOOo0O0Ooo
  if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
  if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
  if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
  if 84 - 84: OoOoOO00
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
  if 80 - 80: oO0o
  if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
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
  if 92 - 92: iII111i
  if 96 - 96: OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
 def match_policy_map_request ( self , mr , srloc ) :
  for Oo00oOoo in self . match_clauses :
   oo00ooOOOo0O = Oo00oOoo . source_eid
   iioOo0oo = mr . source_eid
   if ( oo00ooOOOo0O and iioOo0oo and iioOo0oo . is_more_specific ( oo00ooOOOo0O ) == False ) : continue
   if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
   oo00ooOOOo0O = Oo00oOoo . dest_eid
   iioOo0oo = mr . target_eid
   if ( oo00ooOOOo0O and iioOo0oo and iioOo0oo . is_more_specific ( oo00ooOOOo0O ) == False ) : continue
   if 92 - 92: I1Ii111 - IiII / IiII
   oo00ooOOOo0O = Oo00oOoo . source_rloc
   iioOo0oo = srloc
   if ( oo00ooOOOo0O and iioOo0oo and iioOo0oo . is_more_specific ( oo00ooOOOo0O ) == False ) : continue
   I11iIi1i1I1i1 = Oo00oOoo . datetime_lower
   iiiiI1I11iI1 = Oo00oOoo . datetime_upper
   if ( I11iIi1i1I1i1 and iiiiI1I11iI1 and I11iIi1i1I1i1 . now_in_range ( iiiiI1I11iI1 ) == False ) : continue
   return ( True )
   if 51 - 51: ooOoO0o / OoOoOO00 % OOooOOo * i11iIiiIii
  return ( False )
  if 21 - 21: I1ii11iIi11i / I1ii11iIi11i % iII111i . Oo0Ooo * Oo0Ooo . i11iIiiIii
  if 73 - 73: i1IIi - i11iIiiIii - Ii1I % oO0o
 def set_policy_map_reply ( self ) :
  o0ooOOOo0O0 = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( o0ooOOOo0O0 ) : return ( None )
  if 17 - 17: O0 * i11iIiiIii - I1ii11iIi11i * iIii1I11I1II1 + oO0o * i1IIi
  oOO = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   oOO . rloc . copy_address ( self . set_rloc_address )
   IiiIIi1 = oOO . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( IiiIIi1 ) )
   if 15 - 15: ooOoO0o + I1ii11iIi11i / I1IiiI - Oo0Ooo - Ii1I / I11i
  if ( self . set_rloc_record_name ) :
   oOO . rloc_name = self . set_rloc_record_name
   Ooo0o0OoOO = blue ( oOO . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( Ooo0o0OoOO ) )
   if 37 - 37: ooOoO0o / II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - Ii1I
  if ( self . set_geo_name ) :
   oOO . geo_name = self . set_geo_name
   Ooo0o0OoOO = oOO . geo_name
   iii1IIiI1 = "" if lisp_geo_list . has_key ( Ooo0o0OoOO ) else "(not configured)"
   if 100 - 100: I1Ii111 + ooOoO0o - o0oOOo0O0Ooo
   lprint ( "Policy set-geo-name '{}' {}" . format ( Ooo0o0OoOO , iii1IIiI1 ) )
   if 83 - 83: O0 % OOooOOo + OoOoOO00 + o0oOOo0O0Ooo
  if ( self . set_elp_name ) :
   oOO . elp_name = self . set_elp_name
   Ooo0o0OoOO = oOO . elp_name
   iii1IIiI1 = "" if lisp_elp_list . has_key ( Ooo0o0OoOO ) else "(not configured)"
   if 83 - 83: I1IiiI
   lprint ( "Policy set-elp-name '{}' {}" . format ( Ooo0o0OoOO , iii1IIiI1 ) )
   if 56 - 56: Ii1I
  if ( self . set_rle_name ) :
   oOO . rle_name = self . set_rle_name
   Ooo0o0OoOO = oOO . rle_name
   iii1IIiI1 = "" if lisp_rle_list . has_key ( Ooo0o0OoOO ) else "(not configured)"
   if 84 - 84: iII111i
   lprint ( "Policy set-rle-name '{}' {}" . format ( Ooo0o0OoOO , iii1IIiI1 ) )
   if 21 - 21: i11iIiiIii
  if ( self . set_json_name ) :
   oOO . json_name = self . set_json_name
   Ooo0o0OoOO = oOO . json_name
   iii1IIiI1 = "" if lisp_json_list . has_key ( Ooo0o0OoOO ) else "(not configured)"
   if 30 - 30: OoO0O00 + OoooooooOO
   lprint ( "Policy set-json-name '{}' {}" . format ( Ooo0o0OoOO , iii1IIiI1 ) )
   if 98 - 98: I1ii11iIi11i % I1IiiI
  return ( oOO )
  if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
  if 66 - 66: IiII
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 56 - 56: oO0o + OoooooooOO
  if 75 - 75: O0 % Ii1I
  if 47 - 47: OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  if 23 - 23: iII111i / iIii1I11I1II1
  if 5 - 5: O0
 def add ( self , eid_prefix ) :
  oOoooOOO0o0 = self . ttl
  ooOOoo0 = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( ooOOoo0 ) == False ) :
   lisp_pubsub_cache [ ooOOoo0 ] = { }
   if 64 - 64: i1IIi * i1IIi . iII111i - O0 - oO0o % OoooooooOO
  oO0 = lisp_pubsub_cache [ ooOOoo0 ]
  if 14 - 14: Ii1I % OoO0O00 % I1Ii111 * O0
  ii1iIiIIi = "Add"
  if ( oO0 . has_key ( self . xtr_id ) ) :
   ii1iIiIIi = "Replace"
   del ( oO0 [ self . xtr_id ] )
   if 63 - 63: i11iIiiIii / oO0o % O0
  oO0 [ self . xtr_id ] = self
  if 70 - 70: IiII * I11i . iII111i . I1IiiI % iIii1I11I1II1 * OoooooooOO
  ooOOoo0 = green ( ooOOoo0 , False )
  I11iiII1I1111 = red ( self . itr . print_address_no_iid ( ) , False )
  I1II = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( ii1iIiIIi , ooOOoo0 ,
 I11iiII1I1111 , I1II , oOoooOOO0o0 ) )
  if 51 - 51: O0 * Oo0Ooo - OoooooooOO % OoOoOO00 . I1ii11iIi11i
  if 44 - 44: ooOoO0o / IiII + O0 . II111iiii
 def delete ( self , eid_prefix ) :
  ooOOoo0 = eid_prefix . print_prefix ( )
  I11iiII1I1111 = red ( self . itr . print_address_no_iid ( ) , False )
  I1II = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( ooOOoo0 ) ) :
   oO0 = lisp_pubsub_cache [ ooOOoo0 ]
   if ( oO0 . has_key ( self . xtr_id ) ) :
    oO0 . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( ooOOoo0 ,
 I11iiII1I1111 , I1II ) )
    if 12 - 12: Oo0Ooo
    if 54 - 54: OoOoOO00 . O0 % I1ii11iIi11i - II111iiii % I11i
    if 34 - 34: OoOoOO00 % ooOoO0o * I1IiiI % IiII
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
    if 28 - 28: i11iIiiIii - IiII * I1ii11iIi11i + IiII * iII111i
    if 75 - 75: o0oOOo0O0Ooo * OoOoOO00 % I1ii11iIi11i + OOooOOo . II111iiii
    if 12 - 12: ooOoO0o
    if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
class lisp_trace ( ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
  if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
 def print_trace ( self ) :
  ooO0 = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( ooO0 ) )
  if 78 - 78: OoOoOO00 / IiII
  if 92 - 92: OoOoOO00 / I11i / I1Ii111
 def encode ( self ) :
  iII = socket . htonl ( 0x90000000 )
  IiiiIi1iiii11 = struct . pack ( "II" , iII , 0 )
  IiiiIi1iiii11 += struct . pack ( "Q" , self . nonce )
  IiiiIi1iiii11 += json . dumps ( self . packet_json )
  return ( IiiiIi1iiii11 )
  if 2 - 2: IiII - iIii1I11I1II1
  if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
 def decode ( self , packet ) :
  i1I1iii1I11II = "I"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( False )
  iII = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  iII = socket . ntohl ( iII )
  if ( ( iII & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
  if ( len ( packet ) < Iiiii ) : return ( False )
  IiiIIi1 = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  if 15 - 15: i11iIiiIii
  IiiIIi1 = socket . ntohl ( IiiIIi1 )
  o0O0OOO = IiiIIi1 >> 24
  IIii = ( IiiIIi1 >> 16 ) & 0xff
  OOII1i1 = ( IiiIIi1 >> 8 ) & 0xff
  OoO00OO000ooO0OoOO = IiiIIi1 & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( o0O0OOO , IIii , OOII1i1 , OoO00OO000ooO0OoOO )
  self . local_port = str ( iII & 0xffff )
  if 70 - 70: OoOoOO00 % o0oOOo0O0Ooo + o0oOOo0O0Ooo
  i1I1iii1I11II = "Q"
  Iiiii = struct . calcsize ( i1I1iii1I11II )
  if ( len ( packet ) < Iiiii ) : return ( False )
  self . nonce = struct . unpack ( i1I1iii1I11II , packet [ : Iiiii ] ) [ 0 ]
  packet = packet [ Iiiii : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 53 - 53: i1IIi % Oo0Ooo + O0 . I11i
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 8 - 8: O0 + o0oOOo0O0Ooo + oO0o - OoOoOO00 % iII111i - IiII
  return ( True )
  if 27 - 27: o0oOOo0O0Ooo
  if 20 - 20: i1IIi / IiII . OOooOOo - I1ii11iIi11i * O0 * OoOoOO00
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 11 - 11: I11i + i1IIi
  if 49 - 49: OoooooooOO
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  oOO , Oo0O00O = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( oOO == None ) :
   oOO , Oo0O00O = rts_rloc . split ( ":" )
   Oo0O00O = int ( Oo0O00O )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( oOO , Oo0O00O ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( oOO ,
 Oo0O00O ) )
   if 75 - 75: OoO0O00
   if 52 - 52: i11iIiiIii
  if ( lisp_socket == None ) :
   IiII1iiI = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   IiII1iiI . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   IiII1iiI . sendto ( packet , ( oOO , Oo0O00O ) )
   IiII1iiI . close ( )
  else :
   lisp_socket . sendto ( packet , ( oOO , Oo0O00O ) )
   if 97 - 97: Oo0Ooo % IiII
   if 24 - 24: iIii1I11I1II1
   if 97 - 97: o0oOOo0O0Ooo - iIii1I11I1II1 + I1Ii111 / ooOoO0o + Ii1I
 def packet_length ( self ) :
  o0oOo00 = 8 ; IIIii1I = 4 + 4 + 8
  return ( o0oOo00 + IIIii1I + len ( json . dumps ( self . packet_json ) ) )
  if 43 - 43: I1Ii111 / I1Ii111
  if 76 - 76: I1Ii111
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  Oo000O000 = self . local_rloc + ":" + self . local_port
  i11II = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ Oo000O000 ] = i11II
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( Oo000O000 , i11II ) )
  if 78 - 78: OoOoOO00 / OoO0O00 % II111iiii
  if 43 - 43: IiII + II111iiii + oO0o / I1ii11iIi11i % i1IIi - OoO0O00
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  Oo000O000 = local_rloc_and_port
  try : i11II = lisp_rtr_nat_trace_cache [ Oo000O000 ]
  except : i11II = ( None , None )
  return ( i11II )
  if 59 - 59: Oo0Ooo + O0 + iII111i
  if 71 - 71: IiII - OoO0O00
  if 90 - 90: Oo0Ooo
  if 83 - 83: iIii1I11I1II1 % ooOoO0o % OOooOOo * i1IIi - o0oOOo0O0Ooo * i1IIi
  if 60 - 60: Ii1I . I1ii11iIi11i - I11i + i11iIiiIii / iII111i
  if 9 - 9: I1Ii111 . oO0o . OoO0O00 / IiII - oO0o / oO0o
  if 50 - 50: II111iiii + OoOoOO00
  if 17 - 17: ooOoO0o + I1ii11iIi11i
  if 34 - 34: Ii1I / II111iiii + OoOoOO00 . II111iiii + OoooooooOO * o0oOOo0O0Ooo
  if 48 - 48: O0
  if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
def lisp_get_map_server ( address ) :
 for IIIIiI1 in lisp_map_servers_list . values ( ) :
  if ( IIIIiI1 . map_server . is_exact_match ( address ) ) : return ( IIIIiI1 )
  if 84 - 84: i11iIiiIii . OoooooooOO
 return ( None )
 if 69 - 69: I1Ii111 * II111iiii % I1Ii111 * i11iIiiIii . ooOoO0o / Oo0Ooo
 if 5 - 5: Ii1I
 if 19 - 19: oO0o
 if 61 - 61: OoOoOO00 + iIii1I11I1II1 / I1ii11iIi11i - i1IIi
 if 11 - 11: oO0o * o0oOOo0O0Ooo . I1IiiI
 if 12 - 12: I1IiiI % OoO0O00 / I1Ii111 / O0 % o0oOOo0O0Ooo
 if 1 - 1: OoOoOO00 / I11i
def lisp_get_any_map_server ( ) :
 for IIIIiI1 in lisp_map_servers_list . values ( ) : return ( IIIIiI1 )
 return ( None )
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
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  IiiIIi1 = address . print_address ( )
  O0O0OOoO00 = None
  for Oo000O000 in lisp_map_resolvers_list :
   if ( Oo000O000 . find ( IiiIIi1 ) == - 1 ) : continue
   O0O0OOoO00 = lisp_map_resolvers_list [ Oo000O000 ]
   if 64 - 64: OOooOOo * Oo0Ooo
  return ( O0O0OOoO00 )
  if 96 - 96: Oo0Ooo / I1ii11iIi11i * iIii1I11I1II1 / iII111i
  if 18 - 18: I1Ii111
  if 29 - 29: i1IIi - I1IiiI / i1IIi
  if 64 - 64: IiII
  if 69 - 69: OOooOOo . I1IiiI
  if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
  if 22 - 22: iII111i % I11i % O0 - I11i
 if ( eid == "" ) :
  O0Oo0i1Ii = ""
 elif ( eid == None ) :
  O0Oo0i1Ii = "all"
 else :
  iIIo00O000O = lisp_db_for_lookups . lookup_cache ( eid , False )
  O0Oo0i1Ii = "all" if iIIo00O000O == None else iIIo00O000O . use_mr_name
  if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
  if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
 O0o00 = None
 for O0O0OOoO00 in lisp_map_resolvers_list . values ( ) :
  if ( O0Oo0i1Ii == "" ) : return ( O0O0OOoO00 )
  if ( O0O0OOoO00 . mr_name != O0Oo0i1Ii ) : continue
  if ( O0o00 == None or O0O0OOoO00 . last_used < O0o00 . last_used ) : O0o00 = O0O0OOoO00
  if 47 - 47: I1ii11iIi11i . OoooooooOO
 return ( O0o00 )
 if 24 - 24: i1IIi / Oo0Ooo + OoO0O00 * iII111i - o0oOOo0O0Ooo / O0
 if 97 - 97: iIii1I11I1II1 * I1Ii111
 if 39 - 39: I1Ii111 . II111iiii
 if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
 if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
 if 34 - 34: I1IiiI
 if 56 - 56: Ii1I
 if 71 - 71: O0 / i1IIi
def lisp_get_decent_map_resolver ( eid ) :
 ooo = lisp_get_decent_index ( eid )
 IIo0 = str ( ooo ) + "." + lisp_decent_dns_suffix
 if 23 - 23: IiII * Ii1I - Ii1I . oO0o - IiII
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( IIo0 , False ) , eid . print_prefix ( ) ) )
 if 56 - 56: i1IIi + i11iIiiIii % OoO0O00 - ooOoO0o / OoO0O00
 if 23 - 23: IiII - OoO0O00 / I1ii11iIi11i * oO0o
 O0o00 = None
 for O0O0OOoO00 in lisp_map_resolvers_list . values ( ) :
  if ( IIo0 != O0O0OOoO00 . dns_name ) : continue
  if ( O0o00 == None or O0O0OOoO00 . last_used < O0o00 . last_used ) : O0o00 = O0O0OOoO00
  if 77 - 77: O0 * oO0o . I1ii11iIi11i - i1IIi
 return ( O0o00 )
 if 87 - 87: i1IIi % I1Ii111
 if 37 - 37: I11i
 if 61 - 61: OoooooooOO % iIii1I11I1II1 % O0 % I1Ii111 / Oo0Ooo . I1IiiI
 if 20 - 20: ooOoO0o - I1Ii111
 if 97 - 97: O0
 if 56 - 56: Ii1I * I1IiiI * ooOoO0o
 if 39 - 39: iII111i % Ii1I * iIii1I11I1II1 - Ii1I - I1Ii111
def lisp_ipv4_input ( packet ) :
 if 60 - 60: i11iIiiIii + i11iIiiIii - OoooooooOO + OoooooooOO
 if 5 - 5: o0oOOo0O0Ooo
 if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
 if 12 - 12: Oo0Ooo . o0oOOo0O0Ooo - i1IIi - oO0o % IiII . I11i
 if ( ord ( packet [ 9 ] ) == 2 ) : return ( [ True , packet ] )
 if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
 if 64 - 64: O0 - iII111i
 if 82 - 82: O0
 if 37 - 37: I1Ii111
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
   if 98 - 98: iII111i - OoOoOO00 / I1Ii111 . OOooOOo - OOooOOo - ooOoO0o
   if 84 - 84: OOooOOo * ooOoO0o / O0
   if 96 - 96: I11i . I11i % II111iiii
   if 14 - 14: iII111i / OoooooooOO
   if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
   if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
   if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
 oOoooOOO0o0 = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( oOoooOOO0o0 == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( oOoooOOO0o0 == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
  return ( [ False , None ] )
  if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
  if 11 - 11: I1IiiI
 oOoooOOO0o0 -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , oOoooOOO0o0 ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( [ False , packet ] )
 if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
 if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
 if 91 - 91: OoO0O00
 if 8 - 8: oO0o
 if 96 - 96: IiII
 if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
 if 26 - 26: o0oOOo0O0Ooo . i1IIi
def lisp_ipv6_input ( packet ) :
 oo0OoO = packet . inner_dest
 packet = packet . packet
 if 62 - 62: IiII * I1ii11iIi11i % iIii1I11I1II1 / II111iiii - OoO0O00
 if 52 - 52: iII111i . I11i - I11i + oO0o + iIii1I11I1II1
 if 83 - 83: I11i * iIii1I11I1II1 + OoOoOO00
 if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
 if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
 oOoooOOO0o0 = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( oOoooOOO0o0 == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( oOoooOOO0o0 == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 100 - 100: II111iiii / Oo0Ooo / iII111i / OOooOOo
  return ( None )
  if 100 - 100: iIii1I11I1II1
  if 50 - 50: I1Ii111 / ooOoO0o * I11i
  if 53 - 53: II111iiii . IiII
  if 5 - 5: i1IIi % IiII
  if 16 - 16: ooOoO0o - iII111i % Ii1I . OoOoOO00
 if ( oo0OoO . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 56 - 56: i11iIiiIii % i11iIiiIii % OoooooooOO . Ii1I . iII111i + I11i
  if 64 - 64: O0
 oOoooOOO0o0 -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , oOoooOOO0o0 ) + packet [ 8 : : ]
 return ( packet )
 if 37 - 37: o0oOOo0O0Ooo / O0
 if 58 - 58: I1Ii111 + OoooooooOO + iIii1I11I1II1
 if 13 - 13: o0oOOo0O0Ooo . I11i / O0
 if 39 - 39: I11i + oO0o + ooOoO0o % ooOoO0o - I1IiiI % Oo0Ooo
 if 9 - 9: IiII / iII111i * II111iiii + O0 % Oo0Ooo / i1IIi
 if 45 - 45: OoOoOO00 % i11iIiiIii . I1IiiI - O0 * i1IIi - I1IiiI
 if 48 - 48: IiII / iIii1I11I1II1
 if 20 - 20: oO0o / OoooooooOO
def lisp_mac_input ( packet ) :
 return ( packet )
 if 95 - 95: Oo0Ooo . i11iIiiIii
 if 50 - 50: iII111i . i11iIiiIii - i1IIi
 if 24 - 24: i11iIiiIii % iII111i . oO0o
 if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
 if 34 - 34: I1ii11iIi11i % ooOoO0o / II111iiii * O0 % OOooOOo
 if 9 - 9: I1ii11iIi11i / I1ii11iIi11i - OOooOOo . iIii1I11I1II1
 if 33 - 33: I1IiiI + oO0o % I1IiiI / iII111i - ooOoO0o - i11iIiiIii
 if 39 - 39: i11iIiiIii / oO0o
 if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
def lisp_rate_limit_map_request ( dest ) :
 Iiii1 = lisp_get_timestamp ( )
 if 87 - 87: I1IiiI / Ii1I
 if 54 - 54: OoooooooOO / Ii1I
 if 26 - 26: o0oOOo0O0Ooo + OoO0O00
 if 59 - 59: Ii1I * IiII
 oO000o0Oo00 = Iiii1 - lisp_no_map_request_rate_limit
 if ( oO000o0Oo00 < LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME ) :
  i1i = int ( LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME - oO000o0Oo00 )
  dprint ( "No Rate-Limit Mode for another {} secs" . format ( i1i ) )
  return ( False )
  if 64 - 64: ooOoO0o . Oo0Ooo - OoOoOO00
  if 66 - 66: OoOoOO00
  if 83 - 83: OOooOOo . IiII
  if 98 - 98: i11iIiiIii
  if 74 - 74: iIii1I11I1II1 * O0 + OOooOOo . o0oOOo0O0Ooo
 if ( lisp_last_map_request_sent == None ) : return ( False )
 oO000o0Oo00 = Iiii1 - lisp_last_map_request_sent
 OOI1iiiI1IIi111 = ( oO000o0Oo00 < LISP_MAP_REQUEST_RATE_LIMIT )
 if 17 - 17: I1Ii111
 if ( OOI1iiiI1IIi111 ) :
  dprint ( "Rate-limiting Map-Request for {}, sent {} secs ago" . format ( green ( dest . print_address ( ) , False ) , round ( oO000o0Oo00 , 3 ) ) )
  if 59 - 59: OoOoOO00 . OoOoOO00 * iII111i - Ii1I . i11iIiiIii
  if 68 - 68: iII111i
 return ( OOI1iiiI1IIi111 )
 if 68 - 68: I1Ii111 - OoO0O00 % OoO0O00 % OOooOOo - OoO0O00
 if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
 if 59 - 59: iII111i
 if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
 if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + OOooOOo
 if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ) :
 global lisp_last_map_request_sent
 if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
 if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
 if 77 - 77: ooOoO0o % I1IiiI
 if 26 - 26: o0oOOo0O0Ooo
 if 72 - 72: I1IiiI
 if 90 - 90: ooOoO0o
 Oo0o0o = i1II11iIII = None
 if ( rloc ) :
  Oo0o0o = rloc . rloc
  i1II11iIII = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 54 - 54: i1IIi - I11i % Oo0Ooo / i11iIiiIii
  if 83 - 83: I1IiiI * OoooooooOO % I1IiiI - oO0o
  if 93 - 93: I1ii11iIi11i - OOooOOo - II111iiii * OoO0O00 . O0 - ooOoO0o
  if 53 - 53: OoO0O00 / i11iIiiIii . OoooooooOO
  if 84 - 84: I1ii11iIi11i
 I11IiI1 , iIi1 , OoO0o0OOOO = lisp_myrlocs
 if ( I11IiI1 == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 55 - 55: IiII
 if ( iIi1 == None and Oo0o0o != None and Oo0o0o . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 25 - 25: iII111i - OoOoOO00
  if 37 - 37: OoOoOO00 % o0oOOo0O0Ooo . oO0o % i11iIiiIii
 I1IIIiii1 = lisp_map_request ( )
 I1IIIiii1 . record_count = 1
 I1IIIiii1 . nonce = lisp_get_control_nonce ( )
 I1IIIiii1 . rloc_probe = ( Oo0o0o != None )
 if 42 - 42: OOooOOo - IiII + ooOoO0o / O0 * OOooOOo . OoOoOO00
 if 42 - 42: OoO0O00 % oO0o / I1ii11iIi11i
 if 34 - 34: OOooOOo % OoO0O00 - o0oOOo0O0Ooo * iIii1I11I1II1 - I11i / OoooooooOO
 if 87 - 87: I1ii11iIi11i - I1Ii111 / OOooOOo * II111iiii
 if 15 - 15: Ii1I / OoOoOO00 - OoO0O00 - iIii1I11I1II1 + OoOoOO00 - I11i
 if 10 - 10: I1ii11iIi11i
 if 6 - 6: OoO0O00 + OoO0O00 * OOooOOo / IiII % ooOoO0o - I1IiiI
 if ( rloc ) : rloc . last_rloc_probe_nonce = I1IIIiii1 . nonce
 if 17 - 17: II111iiii
 oOOooo000OoO = deid . is_multicast_address ( )
 if ( oOOooo000OoO ) :
  I1IIIiii1 . target_eid = seid
  I1IIIiii1 . target_group = deid
 else :
  I1IIIiii1 . target_eid = deid
  if 66 - 66: O0 % OoOoOO00 + IiII % I1Ii111
  if 94 - 94: OoOoOO00 / OoooooooOO % Ii1I * i11iIiiIii
  if 95 - 95: iIii1I11I1II1 % OOooOOo % O0
  if 93 - 93: I1ii11iIi11i
  if 61 - 61: o0oOOo0O0Ooo * ooOoO0o
  if 82 - 82: O0 * O0 % I1IiiI / o0oOOo0O0Ooo
  if 46 - 46: IiII . O0 . I11i % I1ii11iIi11i * oO0o - oO0o
  if 92 - 92: I1IiiI - I1IiiI
  if 28 - 28: oO0o * iII111i + IiII
 if ( I1IIIiii1 . rloc_probe == False ) :
  iIIo00O000O = lisp_get_signature_eid ( )
  if ( iIIo00O000O ) :
   I1IIIiii1 . signature_eid . copy_address ( iIIo00O000O . eid )
   I1IIIiii1 . privkey_filename = "./lisp-sig.pem"
   if 73 - 73: OoooooooOO
   if 45 - 45: IiII + I1IiiI * I1Ii111
   if 82 - 82: OOooOOo / I11i % Ii1I * OoOoOO00
   if 88 - 88: o0oOOo0O0Ooo % OoO0O00
   if 30 - 30: II111iiii / Oo0Ooo % Oo0Ooo + O0 / iIii1I11I1II1 . OoO0O00
   if 43 - 43: I1IiiI % OoOoOO00 * O0 + o0oOOo0O0Ooo
 if ( seid == None or oOOooo000OoO ) :
  I1IIIiii1 . source_eid . afi = LISP_AFI_NONE
 else :
  I1IIIiii1 . source_eid = seid
  if 97 - 97: iIii1I11I1II1 + O0
  if 41 - 41: OoOoOO00 - II111iiii
  if 46 - 46: OOooOOo
  if 73 - 73: iII111i - IiII + II111iiii
  if 58 - 58: Oo0Ooo % I1IiiI
  if 78 - 78: iII111i / iIii1I11I1II1 * IiII . ooOoO0o / I1Ii111 % I11i
  if 14 - 14: II111iiii % iIii1I11I1II1 - I1IiiI % i11iIiiIii . OOooOOo * I1ii11iIi11i
  if 12 - 12: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . OoOoOO00
  if 73 - 73: I1ii11iIi11i * i1IIi * Oo0Ooo / O0
  if 1 - 1: iII111i * OOooOOo + II111iiii / Ii1I . I1ii11iIi11i
  if 61 - 61: oO0o % OoOoOO00 % ooOoO0o . I1Ii111 / OoO0O00
  if 21 - 21: IiII
 if ( Oo0o0o != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( Oo0o0o . is_private_address ( ) == False ) :
   I11IiI1 = lisp_get_any_translated_rloc ( )
   if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
  if ( I11IiI1 == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 52 - 52: II111iiii * o0oOOo0O0Ooo
   if 95 - 95: I1Ii111 - OoooooooOO
   if 99 - 99: OoooooooOO % IiII . I11i + OoooooooOO
   if 57 - 57: Ii1I / I1IiiI * i1IIi
   if 21 - 21: I11i . O0 * OoooooooOO + ooOoO0o * oO0o % i11iIiiIii
   if 30 - 30: ooOoO0o * I1Ii111 + OoO0O00
   if 30 - 30: Ii1I / iII111i * Ii1I
   if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
 if ( Oo0o0o == None or Oo0o0o . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and Oo0o0o == None ) :
   Ii1iIiI1 = lisp_get_any_translated_rloc ( )
   if ( Ii1iIiI1 != None ) : I11IiI1 = Ii1iIiI1
   if 50 - 50: I11i + Ii1I / ooOoO0o . i11iIiiIii / O0
  I1IIIiii1 . itr_rlocs . append ( I11IiI1 )
  if 88 - 88: OoooooooOO / Oo0Ooo / oO0o
 if ( Oo0o0o == None or Oo0o0o . is_ipv6 ( ) ) :
  if ( iIi1 == None or iIi1 . is_ipv6_link_local ( ) ) :
   iIi1 = None
  else :
   I1IIIiii1 . itr_rloc_count = 1 if ( Oo0o0o == None ) else 0
   I1IIIiii1 . itr_rlocs . append ( iIi1 )
   if 99 - 99: I1Ii111 % OoOoOO00 % IiII - Ii1I
   if 79 - 79: ooOoO0o + Oo0Ooo
   if 80 - 80: OoOoOO00 % OoO0O00 . OoO0O00 * OoO0O00 * O0
   if 18 - 18: II111iiii . o0oOOo0O0Ooo + OoO0O00
   if 69 - 69: OoO0O00 . ooOoO0o * ooOoO0o * iIii1I11I1II1
   if 8 - 8: iII111i . oO0o . OOooOOo + iII111i . Ii1I
   if 46 - 46: OoO0O00
   if 21 - 21: iIii1I11I1II1 - iII111i
   if 15 - 15: O0 + iII111i + i11iIiiIii
 if ( Oo0o0o != None and I1IIIiii1 . itr_rlocs != [ ] ) :
  iiiI11111 = I1IIIiii1 . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   iiiI11111 = I11IiI1
  elif ( deid . is_ipv6 ( ) ) :
   iiiI11111 = iIi1
  else :
   iiiI11111 = I11IiI1
   if 31 - 31: iIii1I11I1II1 * iIii1I11I1II1 . I11i
   if 52 - 52: i11iIiiIii / oO0o / IiII
   if 84 - 84: I11i . oO0o + ooOoO0o
   if 75 - 75: I1Ii111
   if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
   if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
 IiiiIi1iiii11 = I1IIIiii1 . encode ( Oo0o0o , i1II11iIII )
 I1IIIiii1 . print_map_request ( )
 if 73 - 73: ooOoO0o + O0 - I11i . I1IiiI + OOooOOo
 if 36 - 36: I11i % OoO0O00 * OoOoOO00 - I1Ii111
 if 16 - 16: ooOoO0o % OOooOOo . OoO0O00 % II111iiii . iIii1I11I1II1
 if 21 - 21: oO0o + II111iiii / OoOoOO00 * I11i
 if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
 if 70 - 70: I1IiiI . ooOoO0o / I11i / OoO0O00
 if ( Oo0o0o != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   Ooo = lisp_get_nat_info ( Oo0o0o , rloc . rloc_name )
   if 40 - 40: oO0o % iIii1I11I1II1 * iIii1I11I1II1 / Oo0Ooo * OoO0O00
   if 61 - 61: OOooOOo
   if 80 - 80: I1ii11iIi11i
   if 6 - 6: I1ii11iIi11i + OOooOOo % ooOoO0o
   if ( Ooo == None ) :
    O0OOOO0o0O = rloc . rloc . print_address_no_iid ( )
    i11ii = "gleaned-{}" . format ( O0OOOO0o0O )
    oo00ooOOOo0O = rloc . translated_port
    Ooo = lisp_nat_info ( O0OOOO0o0O , i11ii , oo00ooOOOo0O )
    if 65 - 65: iIii1I11I1II1 % i1IIi / I1IiiI / oO0o % ooOoO0o / I11i
   lisp_encapsulate_rloc_probe ( lisp_sockets , Oo0o0o , Ooo ,
 IiiiIi1iiii11 )
   return
   if 2 - 2: I1ii11iIi11i
   if 90 - 90: II111iiii * I1Ii111 . ooOoO0o - I1ii11iIi11i % I11i * o0oOOo0O0Ooo
  oo0o00OO = Oo0o0o . print_address_no_iid ( )
  oo0OoO = lisp_convert_4to6 ( oo0o00OO )
  lisp_send ( lisp_sockets , oo0OoO , LISP_CTRL_PORT , IiiiIi1iiii11 )
  return
  if 85 - 85: iIii1I11I1II1
  if 76 - 76: i11iIiiIii % I1IiiI / I11i
  if 42 - 42: o0oOOo0O0Ooo . I1IiiI + I11i . OoOoOO00 - O0 / Ii1I
  if 66 - 66: IiII + OoOoOO00 + I1IiiI + i1IIi + OoooooooOO % I1IiiI
  if 80 - 80: iII111i / O0 % OoooooooOO / Oo0Ooo
  if 75 - 75: ooOoO0o
 OOo00O0OOooo = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  O0O0OOoO00 = lisp_get_decent_map_resolver ( deid )
 else :
  O0O0OOoO00 = lisp_get_map_resolver ( None , OOo00O0OOooo )
  if 72 - 72: Ii1I * O0 * OOooOOo / oO0o . I1Ii111
 if ( O0O0OOoO00 == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 37 - 37: Oo0Ooo * oO0o / ooOoO0o - OOooOOo * iII111i
  return
  if 23 - 23: Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
 O0O0OOoO00 . last_used = lisp_get_timestamp ( )
 O0O0OOoO00 . map_requests_sent += 1
 if ( O0O0OOoO00 . last_nonce == 0 ) : O0O0OOoO00 . last_nonce = I1IIIiii1 . nonce
 if 26 - 26: O0 + Oo0Ooo
 if 30 - 30: IiII
 if 6 - 6: O0
 if 92 - 92: I11i
 if ( seid == None ) : seid = iiiI11111
 lisp_send_ecm ( lisp_sockets , IiiiIi1iiii11 , seid , lisp_ephem_port , deid ,
 O0O0OOoO00 . map_resolver )
 if 76 - 76: I11i / iIii1I11I1II1 - i11iIiiIii / O0 / O0
 if 19 - 19: Ii1I . I1IiiI - i1IIi * ooOoO0o . iIii1I11I1II1
 if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
 if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
 if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
 if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
 if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
 O0O0OOoO00 . resolve_dns_name ( )
 return
 if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
 if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
 if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
 if 83 - 83: OOooOOo . ooOoO0o / IiII
 if 80 - 80: I1Ii111 . I11i - I11i + I1ii11iIi11i
 if 42 - 42: I11i / IiII % O0 - Oo0Ooo
 if 33 - 33: I1Ii111
 if 1 - 1: IiII - iIii1I11I1II1 % OoooooooOO
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 1 - 1: o0oOOo0O0Ooo - i11iIiiIii + I11i
 if 47 - 47: O0 + IiII + ooOoO0o + OOooOOo / OoOoOO00
 if 31 - 31: oO0o * iII111i % OoOoOO00
 if 80 - 80: ooOoO0o % I1ii11iIi11i % I11i . I1Ii111
 i1Iiii111 = lisp_info ( )
 i1Iiii111 . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : i1Iiii111 . hostname += "-" + device_name
 if 14 - 14: O0 % IiII . OoOoOO00 . i1IIi . iII111i
 oo0o00OO = dest . print_address_no_iid ( )
 if 17 - 17: OoO0O00 * OoO0O00 - OOooOOo
 if 93 - 93: I1Ii111 . o0oOOo0O0Ooo . ooOoO0o
 if 63 - 63: OOooOOo . oO0o * OoooooooOO + ooOoO0o / iIii1I11I1II1 + iII111i
 if 45 - 45: ooOoO0o / O0 % O0 % i1IIi . I1IiiI - OoOoOO00
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
 I1I1iIii = False
 if ( device_name ) :
  o0oo0O = lisp_get_host_route_next_hop ( oo0o00OO )
  if 61 - 61: Oo0Ooo . i1IIi
  if 78 - 78: i11iIiiIii
  if 20 - 20: Ii1I
  if 100 - 100: OoooooooOO . I1Ii111
  if 32 - 32: iIii1I11I1II1 . iIii1I11I1II1 % II111iiii / Oo0Ooo . iIii1I11I1II1 . O0
  if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
  if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
  if 87 - 87: I1ii11iIi11i . i1IIi - I11i + OoOoOO00 . O0
  if 37 - 37: IiII
  if ( port == LISP_CTRL_PORT and o0oo0O != None ) :
   while ( True ) :
    time . sleep ( .01 )
    o0oo0O = lisp_get_host_route_next_hop ( oo0o00OO )
    if ( o0oo0O == None ) : break
    if 65 - 65: ooOoO0o * Ii1I / I1IiiI . i1IIi % ooOoO0o . OoooooooOO
    if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
    if 88 - 88: i1IIi - OoOoOO00
  Oo0oo0Ooo = lisp_get_default_route_next_hops ( )
  for OoO0o0OOOO , I11Ii11IiiII11ii in Oo0oo0Ooo :
   if ( OoO0o0OOOO != device_name ) : continue
   if 65 - 65: II111iiii . Ii1I / Oo0Ooo . OOooOOo / iIii1I11I1II1
   if 4 - 4: Oo0Ooo - o0oOOo0O0Ooo + I1IiiI
   if 58 - 58: I1Ii111
   if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
   if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
   if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
   if ( o0oo0O != I11Ii11IiiII11ii ) :
    if ( o0oo0O != None ) :
     lisp_install_host_route ( oo0o00OO , o0oo0O , False )
     if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
    lisp_install_host_route ( oo0o00OO , I11Ii11IiiII11ii , True )
    I1I1iIii = True
    if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
   break
   if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
   if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
   if 38 - 38: IiII
   if 78 - 78: Oo0Ooo * I1ii11iIi11i % OOooOOo / Oo0Ooo + I1ii11iIi11i * IiII
   if 2 - 2: Oo0Ooo - OoOoOO00
   if 22 - 22: OoO0O00 - oO0o - O0
 IiiiIi1iiii11 = i1Iiii111 . encode ( )
 i1Iiii111 . print_info ( )
 if 49 - 49: iIii1I11I1II1 + I1Ii111 / i11iIiiIii
 if 62 - 62: ooOoO0o . I1IiiI * i11iIiiIii
 if 2 - 2: i11iIiiIii
 if 86 - 86: I1Ii111 + o0oOOo0O0Ooo
 iiiO0OOOOo = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 iiiO0OOOOo = bold ( iiiO0OOOOo , False )
 oo00ooOOOo0O = bold ( "{}" . format ( port ) , False )
 OO0o = red ( oo0o00OO , False )
 OOO0O0OoOO = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( OOO0O0OoOO , OO0o , oo00ooOOOo0O , iiiO0OOOOo ) )
 if 100 - 100: OoOoOO00 + OOooOOo
 if 44 - 44: IiII % iII111i * iII111i + iII111i * i11iIiiIii - OoO0O00
 if 89 - 89: I1ii11iIi11i - OoO0O00 / i11iIiiIii + ooOoO0o / OoOoOO00
 if 15 - 15: II111iiii - IiII
 if 74 - 74: i1IIi * OoooooooOO . Oo0Ooo . I1IiiI / o0oOOo0O0Ooo . OoOoOO00
 if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , IiiiIi1iiii11 )
 else :
  O0ooOoO0 = lisp_data_header ( )
  O0ooOoO0 . instance_id ( 0xffffff )
  O0ooOoO0 = O0ooOoO0 . encode ( )
  if ( O0ooOoO0 ) :
   IiiiIi1iiii11 = O0ooOoO0 + IiiiIi1iiii11
   if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
   if 96 - 96: I1IiiI . oO0o % O0
   if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
   if 87 - 87: OoooooooOO
   if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
   if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
   if 23 - 23: o0oOOo0O0Ooo . o0oOOo0O0Ooo - iIii1I11I1II1 / o0oOOo0O0Ooo
   if 65 - 65: I1Ii111 + I1Ii111 . I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
   if 2 - 2: oO0o % iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , IiiiIi1iiii11 )
   if 45 - 45: II111iiii . iII111i
   if 55 - 55: ooOoO0o / iII111i / O0
   if 98 - 98: O0 % iII111i + II111iiii
   if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
   if 23 - 23: iIii1I11I1II1 + oO0o . oO0o / o0oOOo0O0Ooo
   if 77 - 77: i1IIi * o0oOOo0O0Ooo * IiII
   if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
 if ( I1I1iIii ) :
  lisp_install_host_route ( oo0o00OO , None , False )
  if ( o0oo0O != None ) : lisp_install_host_route ( oo0o00OO , o0oo0O , True )
  if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
 return
 if 36 - 36: O0
 if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
 if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
 if 21 - 21: i1IIi * iII111i + OoO0O00
 if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
 if 85 - 85: OoooooooOO
 if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 8 - 8: I1Ii111
 if 86 - 86: ooOoO0o + iII111i * O0 % OoO0O00 + OoOoOO00
 if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
 if 9 - 9: iIii1I11I1II1 + Ii1I + I11i
 i1Iiii111 = lisp_info ( )
 packet = i1Iiii111 . decode ( packet )
 if ( packet == None ) : return
 i1Iiii111 . print_info ( )
 if 96 - 96: OoO0O00 + i11iIiiIii + OoO0O00
 if 7 - 7: i1IIi . I1IiiI
 if 68 - 68: OoooooooOO
 if 91 - 91: IiII . ooOoO0o * I11i
 if 39 - 39: o0oOOo0O0Ooo + i11iIiiIii
 i1Iiii111 . info_reply = True
 i1Iiii111 . global_etr_rloc . store_address ( addr_str )
 i1Iiii111 . etr_port = sport
 if 69 - 69: iIii1I11I1II1 . II111iiii
 if 36 - 36: I1IiiI * i1IIi + OoOoOO00
 if 63 - 63: OoOoOO00 - iII111i
 if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
 if 82 - 82: iIii1I11I1II1 / OOooOOo
 if ( i1Iiii111 . hostname != None ) :
  i1Iiii111 . private_etr_rloc . afi = LISP_AFI_NAME
  i1Iiii111 . private_etr_rloc . store_address ( i1Iiii111 . hostname )
  if 7 - 7: OoooooooOO
  if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
 if ( rtr_list != None ) : i1Iiii111 . rtr_list = rtr_list
 packet = i1Iiii111 . encode ( )
 i1Iiii111 . print_info ( )
 if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
 if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
 if 1 - 1: Ii1I . Ii1I % II111iiii + I11i + OoOoOO00
 if 52 - 52: OoooooooOO - OoO0O00
 if 24 - 24: iII111i / Oo0Ooo - I1ii11iIi11i + o0oOOo0O0Ooo
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 oo0OoO = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , oo0OoO , sport , packet )
 if 44 - 44: OoOoOO00 + I1IiiI . I1ii11iIi11i / i1IIi + II111iiii . Oo0Ooo
 if 39 - 39: o0oOOo0O0Ooo
 if 64 - 64: oO0o - i11iIiiIii
 if 62 - 62: OoooooooOO - OoooooooOO / OoO0O00 - II111iiii . iIii1I11I1II1
 if 2 - 2: O0 + o0oOOo0O0Ooo % OOooOOo . ooOoO0o % i1IIi
 IIIiI = lisp_info_source ( i1Iiii111 . hostname , addr_str , sport )
 IIIiI . cache_address_for_info_source ( )
 return
 if 95 - 95: I1Ii111 - Oo0Ooo % iII111i + OoooooooOO - I1ii11iIi11i % Ii1I
 if 84 - 84: o0oOOo0O0Ooo
 if 78 - 78: II111iiii * Ii1I + II111iiii
 if 9 - 9: I1Ii111
 if 69 - 69: i1IIi + ooOoO0o + Ii1I
 if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
 if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
 if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
def lisp_get_signature_eid ( ) :
 for iIIo00O000O in lisp_db_list :
  if ( iIIo00O000O . signature_eid ) : return ( iIIo00O000O )
  if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
 return ( None )
 if 8 - 8: i1IIi
 if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
 if 97 - 97: OoooooooOO % ooOoO0o . I1Ii111 / iII111i
 if 59 - 59: II111iiii + O0 . I1ii11iIi11i . Oo0Ooo * OoO0O00
 if 35 - 35: oO0o / I1Ii111 * OOooOOo + OoooooooOO . IiII
 if 1 - 1: I1IiiI + I1Ii111 / OOooOOo . Ii1I . oO0o / I1ii11iIi11i
 if 54 - 54: OOooOOo
 if 86 - 86: oO0o * Oo0Ooo / OOooOOo
def lisp_get_any_translated_port ( ) :
 for iIIo00O000O in lisp_db_list :
  for oo0OOOoO0OoO in iIIo00O000O . rloc_set :
   if ( oo0OOOoO0OoO . translated_rloc . is_null ( ) ) : continue
   return ( oo0OOOoO0OoO . translated_port )
   if 18 - 18: II111iiii - I1Ii111
   if 13 - 13: i11iIiiIii - O0 % OoOoOO00 + OOooOOo * ooOoO0o
 return ( None )
 if 55 - 55: i1IIi - OOooOOo / I11i * Ii1I
 if 20 - 20: OoOoOO00 * iIii1I11I1II1 % O0 - i1IIi
 if 51 - 51: I1ii11iIi11i * Ii1I - oO0o / O0 * OoooooooOO
 if 12 - 12: i1IIi / iIii1I11I1II1 / O0 * OoO0O00
 if 15 - 15: i11iIiiIii / IiII + Ii1I % OOooOOo % I1ii11iIi11i * oO0o
 if 24 - 24: OOooOOo / OOooOOo + I11i / iII111i . oO0o - iII111i
 if 59 - 59: I1ii11iIi11i % II111iiii - i11iIiiIii - I1Ii111
 if 34 - 34: II111iiii + iII111i / IiII
 if 47 - 47: OoO0O00
def lisp_get_any_translated_rloc ( ) :
 for iIIo00O000O in lisp_db_list :
  for oo0OOOoO0OoO in iIIo00O000O . rloc_set :
   if ( oo0OOOoO0OoO . translated_rloc . is_null ( ) ) : continue
   return ( oo0OOOoO0OoO . translated_rloc )
   if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
   if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
 return ( None )
 if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
 if 100 - 100: II111iiii . IiII . I11i
 if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
 if 3 - 3: OoooooooOO
 if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
 if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
 if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
def lisp_get_all_translated_rlocs ( ) :
 IIIII1I1iI = [ ]
 for iIIo00O000O in lisp_db_list :
  for oo0OOOoO0OoO in iIIo00O000O . rloc_set :
   if ( oo0OOOoO0OoO . is_rloc_translated ( ) == False ) : continue
   IiiIIi1 = oo0OOOoO0OoO . translated_rloc . print_address_no_iid ( )
   IIIII1I1iI . append ( IiiIIi1 )
   if 30 - 30: IiII - iII111i - OOooOOo / O0 . I1ii11iIi11i % Ii1I
   if 24 - 24: IiII + i11iIiiIii - OoOoOO00
 return ( IIIII1I1iI )
 if 67 - 67: IiII % iII111i * I11i
 if 62 - 62: I11i
 if 60 - 60: IiII
 if 85 - 85: OoOoOO00 * IiII / OoOoOO00 + IiII
 if 17 - 17: OoO0O00
 if 91 - 91: iIii1I11I1II1 * iIii1I11I1II1 * OoooooooOO - iII111i * iIii1I11I1II1 + OoOoOO00
 if 10 - 10: oO0o . OoooooooOO / oO0o + I1IiiI / O0
 if 12 - 12: ooOoO0o / I1IiiI % Oo0Ooo - II111iiii / i11iIiiIii
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 O0000o = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 33 - 33: o0oOOo0O0Ooo + IiII / OoOoOO00 / ooOoO0o
 iIIiI1i = { }
 for oOO in rtr_list :
  if ( oOO == None ) : continue
  IiiIIi1 = rtr_list [ oOO ]
  if ( O0000o and IiiIIi1 . is_private_address ( ) ) : continue
  iIIiI1i [ oOO ] = IiiIIi1
  if 66 - 66: o0oOOo0O0Ooo . I1IiiI + OoooooooOO . iII111i / OoooooooOO - IiII
 rtr_list = iIIiI1i
 if 47 - 47: o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
 I11I = [ ]
 for O0ooo0 in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( O0ooo0 == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 90 - 90: IiII % O0 / OoooooooOO - II111iiii - Oo0Ooo
  if 22 - 22: I1ii11iIi11i
  if 74 - 74: OoOoOO00 . I1Ii111 - Oo0Ooo / I11i . OoOoOO00 * o0oOOo0O0Ooo
  if 43 - 43: I11i
  if 18 - 18: OoooooooOO + OoooooooOO - i11iIiiIii / II111iiii
  iIiIIi1i = lisp_address ( O0ooo0 , "" , 0 , iid )
  iIiIIi1i . make_default_route ( iIiIIi1i )
  I1iOo0 = lisp_map_cache . lookup_cache ( iIiIIi1i , True )
  if ( I1iOo0 ) :
   if ( I1iOo0 . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( I1iOo0 . print_eid_tuple ( ) , False ) ) )
    if 41 - 41: Oo0Ooo . OoOoOO00 . iII111i / i11iIiiIii
   elif ( I1iOo0 . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 65 - 65: iII111i * o0oOOo0O0Ooo * OoooooooOO + I11i + oO0o % OoO0O00
   I1iOo0 . delete_cache ( )
   if 1 - 1: I1ii11iIi11i . ooOoO0o
   if 54 - 54: OoOoOO00 % I1IiiI . ooOoO0o + IiII / i11iIiiIii / o0oOOo0O0Ooo
  I11I . append ( [ iIiIIi1i , "" ] )
  if 51 - 51: OoOoOO00 / Ii1I . I1IiiI / Ii1I . II111iiii - iIii1I11I1II1
  if 78 - 78: I11i
  if 42 - 42: Ii1I
  if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
  IIi1iiIII11 = lisp_address ( O0ooo0 , "" , 0 , iid )
  IIi1iiIII11 . make_default_multicast_route ( IIi1iiIII11 )
  iIIiiiiII11 = lisp_map_cache . lookup_cache ( IIi1iiIII11 , True )
  if ( iIIiiiiII11 ) : iIIiiiiII11 = iIIiiiiII11 . source_cache . lookup_cache ( iIiIIi1i , True )
  if ( iIIiiiiII11 ) : iIIiiiiII11 . delete_cache ( )
  if 36 - 36: i1IIi * i11iIiiIii
  I11I . append ( [ iIiIIi1i , IIi1iiIII11 ] )
  if 92 - 92: OoooooooOO / i11iIiiIii - oO0o * II111iiii / iIii1I11I1II1
 if ( len ( I11I ) == 0 ) : return
 if 49 - 49: Ii1I
 if 19 - 19: OoooooooOO . i1IIi % IiII % i1IIi . oO0o
 if 66 - 66: o0oOOo0O0Ooo
 if 54 - 54: OOooOOo % I11i * oO0o . OoO0O00 . Ii1I
 Oo = [ ]
 for OOO0O0OoOO in rtr_list :
  I11II = rtr_list [ OOO0O0OoOO ]
  oo0OOOoO0OoO = lisp_rloc ( )
  oo0OOOoO0OoO . rloc . copy_address ( I11II )
  oo0OOOoO0OoO . priority = 254
  oo0OOOoO0OoO . mpriority = 255
  oo0OOOoO0OoO . rloc_name = "RTR"
  Oo . append ( oo0OOOoO0OoO )
  if 66 - 66: OoOoOO00 % iIii1I11I1II1 / o0oOOo0O0Ooo
  if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
 for iIiIIi1i in I11I :
  I1iOo0 = lisp_mapping ( iIiIIi1i [ 0 ] , iIiIIi1i [ 1 ] , Oo )
  I1iOo0 . mapping_source = map_resolver
  I1iOo0 . map_cache_ttl = LISP_MR_TTL * 60
  I1iOo0 . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( I1iOo0 . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
  Oo = copy . deepcopy ( Oo )
  if 71 - 71: OoO0O00 - I11i
 return
 if 96 - 96: I1Ii111 / Ii1I
 if 65 - 65: I1ii11iIi11i * O0 . IiII
 if 11 - 11: I11i / Ii1I % oO0o
 if 50 - 50: i11iIiiIii
 if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
 if 25 - 25: I11i / ooOoO0o % ooOoO0o - OOooOOo
 if 59 - 59: I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1 - O0 - i11iIiiIii
 if 4 - 4: I1IiiI
 if 36 - 36: Ii1I
 if 76 - 76: i11iIiiIii + i1IIi
def lisp_process_info_reply ( source , packet , store ) :
 if 56 - 56: OoOoOO00 + II111iiii / i11iIiiIii * OoOoOO00 * OoooooooOO
 if 15 - 15: OoOoOO00 / OoooooooOO + OOooOOo
 if 76 - 76: Ii1I * iII111i . OoooooooOO
 if 92 - 92: iIii1I11I1II1 - Oo0Ooo - I1IiiI - OOooOOo * I1Ii111
 i1Iiii111 = lisp_info ( )
 packet = i1Iiii111 . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 44 - 44: I1Ii111 - II111iiii / OOooOOo
 i1Iiii111 . print_info ( )
 if 50 - 50: I11i / I1ii11iIi11i
 if 60 - 60: II111iiii / Ii1I + OoO0O00 % I1IiiI * i1IIi / II111iiii
 if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
 if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
 i11Ii = False
 for OOO0O0OoOO in i1Iiii111 . rtr_list :
  oo0o00OO = OOO0O0OoOO . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( oo0o00OO ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ oo0o00OO ] != None ) : continue
   if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
  i11Ii = True
  lisp_rtr_list [ oo0o00OO ] = OOO0O0OoOO
  if 48 - 48: O0
  if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
  if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
  if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
  if 96 - 96: ooOoO0o * Ii1I + I11i + II111iiii * I1IiiI / iII111i
 if ( lisp_i_am_itr and i11Ii ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for o0OoO0000o in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( o0OoO0000o ) , lisp_rtr_list )
    if 40 - 40: OoooooooOO - I11i % OOooOOo - I1IiiI . I1IiiI + Ii1I
    if 97 - 97: OOooOOo . OoooooooOO . OOooOOo . i11iIiiIii
    if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
    if 79 - 79: oO0o
    if 47 - 47: OoooooooOO - i1IIi * OOooOOo
    if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
    if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
 if ( store == False ) :
  return ( [ i1Iiii111 . global_etr_rloc , i1Iiii111 . etr_port , i11Ii ] )
  if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
  if 8 - 8: iII111i
  if 10 - 10: OoOoOO00 % I11i
  if 49 - 49: oO0o % ooOoO0o + II111iiii
  if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
  if 99 - 99: OoOoOO00
 for iIIo00O000O in lisp_db_list :
  for oo0OOOoO0OoO in iIIo00O000O . rloc_set :
   oOO = oo0OOOoO0OoO . rloc
   II1i = oo0OOOoO0OoO . interface
   if ( II1i == None ) :
    if ( oOO . is_null ( ) ) : continue
    if ( oOO . is_local ( ) == False ) : continue
    if ( i1Iiii111 . private_etr_rloc . is_null ( ) == False and
 oOO . is_exact_match ( i1Iiii111 . private_etr_rloc ) == False ) :
     continue
     if 46 - 46: I1ii11iIi11i / II111iiii / OoooooooOO / Ii1I
   elif ( i1Iiii111 . private_etr_rloc . is_dist_name ( ) ) :
    I1io0 = i1Iiii111 . private_etr_rloc . address
    if ( I1io0 != oo0OOOoO0OoO . rloc_name ) : continue
    if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
    if 8 - 8: oO0o
   I11i11i1 = green ( iIIo00O000O . eid . print_prefix ( ) , False )
   o0oooOoOoOo = red ( oOO . print_address_no_iid ( ) , False )
   if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
   OO0Ooo0ooOo = i1Iiii111 . global_etr_rloc . is_exact_match ( oOO )
   if ( oo0OOOoO0OoO . translated_port == 0 and OO0Ooo0ooOo ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( o0oooOoOoOo ,
 II1i , I11i11i1 ) )
    continue
    if 1 - 1: OoooooooOO . Ii1I
    if 68 - 68: Ii1I
    if 98 - 98: iII111i
    if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
    if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
   oOO00OOo = i1Iiii111 . global_etr_rloc
   iIi1IIiIIIII1 = oo0OOOoO0OoO . translated_rloc
   if ( iIi1IIiIIIII1 . is_exact_match ( oOO00OOo ) and
 i1Iiii111 . etr_port == oo0OOOoO0OoO . translated_port ) : continue
   if 57 - 57: i1IIi + I11i % Oo0Ooo - i11iIiiIii - I1IiiI * OOooOOo
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( i1Iiii111 . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # I1IiiI + Oo0Ooo . ooOoO0o * oO0o
 i1Iiii111 . etr_port , o0oooOoOoOo , II1i , I11i11i1 ) )
   if 31 - 31: Oo0Ooo * IiII / IiII
   oo0OOOoO0OoO . store_translated_rloc ( i1Iiii111 . global_etr_rloc ,
 i1Iiii111 . etr_port )
   if 3 - 3: I1Ii111
   if 65 - 65: iIii1I11I1II1 % Oo0Ooo % I11i / OoooooooOO
 return ( [ i1Iiii111 . global_etr_rloc , i1Iiii111 . etr_port , i11Ii ] )
 if 82 - 82: o0oOOo0O0Ooo
 if 33 - 33: OoOoOO00 / i11iIiiIii - I1IiiI - OoooooooOO + i1IIi * I1Ii111
 if 92 - 92: iII111i + OoO0O00
 if 70 - 70: iIii1I11I1II1
 if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
 if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
 if 14 - 14: I1Ii111 + Oo0Ooo
 if 35 - 35: i11iIiiIii * Ii1I
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 100 - 100: O0 . iII111i / iIii1I11I1II1
 ooOOoo0 = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 i1I1II = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 86 - 86: OOooOOo - ooOoO0o / i11iIiiIii * o0oOOo0O0Ooo % II111iiii / I1ii11iIi11i
 if 25 - 25: Ii1I
 if 88 - 88: OoooooooOO
 if 73 - 73: ooOoO0o % iII111i * IiII - iIii1I11I1II1 + i1IIi + o0oOOo0O0Ooo
 ooOOoo0 . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , ooOOoo0 , None )
 ooOOoo0 . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , ooOOoo0 , None )
 if 63 - 63: iIii1I11I1II1
 if 88 - 88: OoooooooOO
 if 23 - 23: iII111i - IiII % i11iIiiIii
 if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
 i1I1II . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , i1I1II , None )
 i1I1II . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , i1I1II , None )
 if 60 - 60: OOooOOo - I1Ii111 * Oo0Ooo
 if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
 if 39 - 39: iIii1I11I1II1 / i1IIi % I11i % I1ii11iIi11i * IiII
 if 11 - 11: II111iiii + i1IIi
 iiIIi1iiII = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 iiIIi1iiII . start ( )
 return
 if 83 - 83: OoooooooOO
 if 53 - 53: o0oOOo0O0Ooo - Oo0Ooo / IiII + O0
 if 88 - 88: Oo0Ooo % I1Ii111 * O0 - i1IIi * OoO0O00
 if 74 - 74: Oo0Ooo % iIii1I11I1II1 + OOooOOo
 if 50 - 50: OoO0O00 . OoooooooOO
 if 31 - 31: OoO0O00
 if 55 - 55: OoOoOO00 + I1Ii111 * o0oOOo0O0Ooo - I1ii11iIi11i + OoOoOO00
 if 6 - 6: II111iiii % iIii1I11I1II1 * I1Ii111
 if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
 if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
 if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
 if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
 if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
 IiiIIi1 = lisp_get_interface_address ( rloc . interface )
 if ( IiiIIi1 == None ) : return
 if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
 oo00ooO = rloc . rloc . print_address_no_iid ( )
 O0OOOo000 = IiiIIi1 . print_address_no_iid ( )
 if 63 - 63: IiII / I1IiiI + O0 * o0oOOo0O0Ooo
 if ( oo00ooO == O0OOOo000 ) : return
 if 43 - 43: I1Ii111 + Oo0Ooo . OoooooooOO % I1ii11iIi11i - I1ii11iIi11i
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , oo00ooO , O0OOOo000 ) )
 if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
 if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
 rloc . rloc . copy_address ( IiiIIi1 )
 lisp_myrlocs [ 0 ] = IiiIIi1
 return
 if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
 if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
 if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
 if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
 if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
 if 40 - 40: I1ii11iIi11i
 if 76 - 76: Oo0Ooo - I11i
 if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
def lisp_update_encap_port ( mc ) :
 for oOO in mc . rloc_set :
  Ooo = lisp_get_nat_info ( oOO . rloc , oOO . rloc_name )
  if ( Ooo == None ) : continue
  if ( oOO . translated_port == Ooo . port ) : continue
  if 39 - 39: I1IiiI
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( oOO . translated_port , Ooo . port ,
  # OOooOOo
 red ( oOO . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 90 - 90: i1IIi * i1IIi * OOooOOo . Oo0Ooo . i11iIiiIii + iII111i
  oOO . store_translated_rloc ( oOO . rloc , Ooo . port )
  if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
 return
 if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
 if 89 - 89: iII111i
 if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
 if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
 if 77 - 77: OoooooooOO - I11i / I1IiiI % OoOoOO00 - OOooOOo
 if 37 - 37: ooOoO0o
 if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
 if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
 if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
 if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
 if 82 - 82: iII111i - I1Ii111 - OoOoOO00
 if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
  if 44 - 44: O0
 Iiii1 = lisp_get_timestamp ( )
 if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
 if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
 if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
 if 14 - 14: iIii1I11I1II1 * I1ii11iIi11i + OOooOOo + O0
 if 79 - 79: II111iiii - iII111i
 if 89 - 89: O0 - OoO0O00
 if ( mc . last_refresh_time + mc . map_cache_ttl > Iiii1 ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
  if 32 - 32: O0 + IiII
  if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
  if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
  if 17 - 17: OOooOOo
 if ( lisp_nat_traversal and mc . eid . address == 0 and mc . eid . mask_len == 0 ) :
  return ( [ True , delete_list ] )
  if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
  if 46 - 46: II111iiii * OoO0O00
  if 77 - 77: ooOoO0o * I11i
  if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
  if 76 - 76: iII111i * OoooooooOO
 oO000o0Oo00 = lisp_print_elapsed ( mc . last_refresh_time )
 OOOo0O0O = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( OOOo0O0O , False ) , bold ( "timed out" , False ) , oO000o0Oo00 ) )
 if 49 - 49: II111iiii - OOooOOo + II111iiii + OoOoOO00
 if 51 - 51: i11iIiiIii
 if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
 if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
 if 63 - 63: II111iiii - Oo0Ooo
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
 if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
 if 78 - 78: IiII - I1IiiI
 if 59 - 59: oO0o + i1IIi - IiII % OOooOOo % iIii1I11I1II1
 if 71 - 71: OoO0O00
 if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
 if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
 if 54 - 54: Ii1I / I1IiiI
def lisp_timeout_map_cache_walk ( mc , parms ) :
 i1i1iI1I1 = parms [ 0 ]
 IiiI = parms [ 1 ]
 if 87 - 87: i1IIi + O0 % iII111i * iIii1I11I1II1 + II111iiii
 if 59 - 59: OoooooooOO . ooOoO0o / OOooOOo - OOooOOo / iIii1I11I1II1 / oO0o
 if 58 - 58: iIii1I11I1II1 - OoO0O00
 if 74 - 74: o0oOOo0O0Ooo . OOooOOo
 if ( mc . group . is_null ( ) ) :
  oO0OOo0o0o , i1i1iI1I1 = lisp_timeout_map_cache_entry ( mc , i1i1iI1I1 )
  if ( i1i1iI1I1 == [ ] or mc != i1i1iI1I1 [ - 1 ] ) :
   IiiI = lisp_write_checkpoint_entry ( IiiI , mc )
   if 96 - 96: OoooooooOO
  return ( [ oO0OOo0o0o , parms ] )
  if 19 - 19: Ii1I / OoooooooOO
  if 67 - 67: I1ii11iIi11i - OoooooooOO + OoooooooOO * o0oOOo0O0Ooo * iII111i
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 30 - 30: I1ii11iIi11i % Ii1I
 if 2 - 2: I1IiiI . IiII . iIii1I11I1II1 - OOooOOo
 if 56 - 56: OoooooooOO + I1IiiI / I11i % i11iIiiIii / o0oOOo0O0Ooo / Ii1I
 if 27 - 27: oO0o
 if 98 - 98: OoOoOO00 . oO0o + I1ii11iIi11i
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 14 - 14: OoooooooOO
 if 73 - 73: OoOoOO00 % o0oOOo0O0Ooo
 if 28 - 28: OoO0O00
 if 15 - 15: OoO0O00 . I11i
 if 64 - 64: OOooOOo + I1Ii111 - o0oOOo0O0Ooo . II111iiii * Ii1I
 if 88 - 88: I1ii11iIi11i + OoooooooOO % I1ii11iIi11i
 if 3 - 3: I1Ii111 . O0 * OOooOOo * I11i + Ii1I * I1IiiI
def lisp_timeout_map_cache ( lisp_map_cache ) :
 I1I1i = [ [ ] , [ ] ]
 I1I1i = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , I1I1i )
 if 18 - 18: iIii1I11I1II1 % ooOoO0o . o0oOOo0O0Ooo * iII111i % iII111i
 if 64 - 64: I1Ii111 . I11i
 if 32 - 32: I1ii11iIi11i + IiII % OoOoOO00 . O0
 if 70 - 70: IiII + iII111i . i11iIiiIii + OoO0O00
 if 45 - 45: o0oOOo0O0Ooo - ooOoO0o
 i1i1iI1I1 = I1I1i [ 0 ]
 for I1iOo0 in i1i1iI1I1 : I1iOo0 . delete_cache ( )
 if 2 - 2: OOooOOo + iII111i * ooOoO0o + II111iiii
 if 88 - 88: ooOoO0o * OoO0O00 * I1ii11iIi11i - I1IiiI * IiII * I11i
 if 37 - 37: iIii1I11I1II1
 if 50 - 50: o0oOOo0O0Ooo - OOooOOo * IiII % Oo0Ooo
 IiiI = I1I1i [ 1 ]
 lisp_checkpoint ( IiiI )
 return
 if 81 - 81: OoooooooOO - OoOoOO00 % I1ii11iIi11i % I1ii11iIi11i + OoOoOO00
 if 49 - 49: Ii1I + iIii1I11I1II1 . O0 * OOooOOo * OoooooooOO - OOooOOo
 if 23 - 23: iIii1I11I1II1 % I11i . OoO0O00 / i11iIiiIii % O0 * Ii1I
 if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
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
def lisp_store_nat_info ( hostname , rloc , port ) :
 oo0o00OO = rloc . print_address_no_iid ( )
 o0oOoOOoo0O = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( oo0o00OO , False ) , port )
 if 21 - 21: OoO0O00 - OOooOOo - i11iIiiIii . II111iiii
 oo0O0o000OO0 = lisp_nat_info ( oo0o00OO , hostname , port )
 if 1 - 1: I1Ii111 . I1IiiI + I1Ii111
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ oo0O0o000OO0 ]
  lprint ( o0oOoOOoo0O . format ( "Store initial" ) )
  return ( True )
  if 40 - 40: I1IiiI
  if 92 - 92: I1ii11iIi11i + iII111i
  if 55 - 55: ooOoO0o
  if 68 - 68: Oo0Ooo
  if 3 - 3: Ii1I % Ii1I + oO0o
  if 19 - 19: Ii1I . IiII % o0oOOo0O0Ooo
 Ooo = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( Ooo . address == oo0o00OO and Ooo . port == port ) :
  Ooo . uptime = lisp_get_timestamp ( )
  lprint ( o0oOoOOoo0O . format ( "Refresh existing" ) )
  return ( False )
  if 92 - 92: i1IIi + IiII - iIii1I11I1II1 + i1IIi * ooOoO0o - i11iIiiIii
  if 68 - 68: o0oOOo0O0Ooo + IiII / iII111i - i11iIiiIii / OOooOOo
  if 62 - 62: I1IiiI
  if 42 - 42: II111iiii
  if 49 - 49: OoooooooOO
  if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
  if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
 iIii = None
 for Ooo in lisp_nat_state_info [ hostname ] :
  if ( Ooo . address == oo0o00OO and Ooo . port == port ) :
   iIii = Ooo
   break
   if 36 - 36: i1IIi * oO0o / i1IIi % oO0o
   if 9 - 9: Ii1I / iIii1I11I1II1
   if 52 - 52: OOooOOo / oO0o / iIii1I11I1II1 / OoOoOO00
 if ( iIii == None ) :
  lprint ( o0oOoOOoo0O . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( iIii )
  lprint ( o0oOoOOoo0O . format ( "Use previous" ) )
  if 43 - 43: iII111i * OoOoOO00 % II111iiii - I1Ii111
  if 87 - 87: oO0o
 o0O0 = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ oo0O0o000OO0 ] + o0O0
 return ( True )
 if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
 if 64 - 64: OOooOOo / OoOoOO00
 if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
 if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
 if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
 if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
 if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
 if 49 - 49: IiII
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 1 - 1: oO0o / I11i
 oo0o00OO = rloc . print_address_no_iid ( )
 for Ooo in lisp_nat_state_info [ hostname ] :
  if ( Ooo . address == oo0o00OO ) : return ( Ooo )
  if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
 return ( None )
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
 if 55 - 55: II111iiii - IiII
 if 24 - 24: oO0o % Ii1I / i1IIi
 if 84 - 84: i1IIi
 if 53 - 53: OoooooooOO - i1IIi - Ii1I
 if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
 if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
 if 34 - 34: Ii1I
 if 5 - 5: II111iiii . I1ii11iIi11i
 if 85 - 85: I1Ii111 . IiII + II111iiii
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
 if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
 if 87 - 87: OOooOOo
 if 44 - 44: Oo0Ooo + iIii1I11I1II1
 if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
 I11I1 = [ ]
 oooooo0oo0o0 = [ ]
 if ( dest == None ) :
  for O0O0OOoO00 in lisp_map_resolvers_list . values ( ) :
   oooooo0oo0o0 . append ( O0O0OOoO00 . map_resolver )
   if 49 - 49: I11i
  I11I1 = oooooo0oo0o0
  if ( I11I1 == [ ] ) :
   for IIIIiI1 in lisp_map_servers_list . values ( ) :
    I11I1 . append ( IIIIiI1 . map_server )
    if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
    if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
  if ( I11I1 == [ ] ) : return
 else :
  I11I1 . append ( dest )
  if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
  if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
  if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
  if 32 - 32: O0
  if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
 IIIII1I1iI = { }
 for iIIo00O000O in lisp_db_list :
  for oo0OOOoO0OoO in iIIo00O000O . rloc_set :
   lisp_update_local_rloc ( oo0OOOoO0OoO )
   if ( oo0OOOoO0OoO . rloc . is_null ( ) ) : continue
   if ( oo0OOOoO0OoO . interface == None ) : continue
   if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
   IiiIIi1 = oo0OOOoO0OoO . rloc . print_address_no_iid ( )
   if ( IiiIIi1 in IIIII1I1iI ) : continue
   IIIII1I1iI [ IiiIIi1 ] = oo0OOOoO0OoO . interface
   if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
   if 70 - 70: iIii1I11I1II1 - I11i
 if ( IIIII1I1iI == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 2 - 2: oO0o / II111iiii * OoO0O00
  return
  if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
  if 40 - 40: OOooOOo
  if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
  if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
  if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
  if 26 - 26: OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
 for IiiIIi1 in IIIII1I1iI :
  II1i = IIIII1I1iI [ IiiIIi1 ]
  OO0o = red ( IiiIIi1 , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( OO0o ,
 II1i ) )
  OoO0o0OOOO = II1i if len ( IIIII1I1iI ) > 1 else None
  for dest in I11I1 :
   lisp_send_info_request ( lisp_sockets , dest , port , OoO0o0OOOO )
   if 39 - 39: I1ii11iIi11i * I1IiiI * II111iiii . Oo0Ooo % I1IiiI
   if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
   if 98 - 98: OoO0O00 + oO0o - II111iiii
   if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
   if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
   if 77 - 77: iIii1I11I1II1 * Oo0Ooo . IiII / oO0o + O0
 if ( oooooo0oo0o0 != [ ] ) :
  for O0O0OOoO00 in lisp_map_resolvers_list . values ( ) :
   O0O0OOoO00 . resolve_dns_name ( )
   if 76 - 76: iII111i + o0oOOo0O0Ooo - OoooooooOO * oO0o % OoooooooOO - O0
   if 18 - 18: Ii1I
 return
 if 82 - 82: OoOoOO00 + OoO0O00 - IiII / ooOoO0o
 if 70 - 70: OoO0O00
 if 43 - 43: ooOoO0o + OOooOOo + II111iiii - I1IiiI
 if 58 - 58: I11i
 if 94 - 94: Oo0Ooo
 if 39 - 39: I11i - oO0o % iII111i - ooOoO0o - OoOoOO00
 if 8 - 8: i1IIi % i1IIi % OoooooooOO % i1IIi . iIii1I11I1II1
 if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 58 - 58: II111iiii * oO0o - i1IIi . I11i
 if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
 if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
 if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
 if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 31 - 31: i1IIi * Ii1I
 if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
 if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
 if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
 if ( value . find ( "." ) != - 1 ) :
  IiiIIi1 = value . split ( "." )
  if ( len ( IiiIIi1 ) != 4 ) : return ( False )
  if 52 - 52: OOooOOo . OoOoOO00 - ooOoO0o % i1IIi
  for iiIiIIi1I in IiiIIi1 :
   if ( iiIiIIi1I . isdigit ( ) == False ) : return ( False )
   if ( int ( iiIiIIi1I ) > 255 ) : return ( False )
   if 89 - 89: ooOoO0o * II111iiii * oO0o - iII111i
  return ( True )
  if 22 - 22: I1Ii111 * oO0o - OoO0O00
  if 12 - 12: IiII . OoooooooOO - iIii1I11I1II1 % iII111i
  if 56 - 56: Oo0Ooo / I1IiiI + iIii1I11I1II1 + I1IiiI % iIii1I11I1II1
  if 64 - 64: O0
  if 55 - 55: OoO0O00 * oO0o . Ii1I + OoOoOO00 % I11i + IiII
 if ( value . find ( "-" ) != - 1 ) :
  IiiIIi1 = value . split ( "-" )
  for IiIIi1IiiIiI in [ "N" , "S" , "W" , "E" ] :
   if ( IiIIi1IiiIiI in IiiIIi1 ) :
    if ( len ( IiiIIi1 ) < 8 ) : return ( False )
    return ( True )
    if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
    if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
    if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
    if 7 - 7: I1Ii111 % i1IIi . I11i . O0 / i1IIi
    if 56 - 56: Oo0Ooo
    if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
    if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
 if ( value . find ( "-" ) != - 1 ) :
  IiiIIi1 = value . split ( "-" )
  if ( len ( IiiIIi1 ) != 3 ) : return ( False )
  if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
  for iIi1I11IIi in IiiIIi1 :
   try : int ( iIi1I11IIi , 16 )
   except : return ( False )
   if 73 - 73: Ii1I - II111iiii + I1IiiI % i11iIiiIii * I11i
  return ( True )
  if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
  if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
  if 64 - 64: OoooooooOO
  if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
  if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
 if ( value . find ( ":" ) != - 1 ) :
  IiiIIi1 = value . split ( ":" )
  if ( len ( IiiIIi1 ) < 2 ) : return ( False )
  if 71 - 71: O0 - OoooooooOO
  oo0o00Oo00o0 = False
  I1I1 = 0
  for iIi1I11IIi in IiiIIi1 :
   I1I1 += 1
   if ( iIi1I11IIi == "" ) :
    if ( oo0o00Oo00o0 ) :
     if ( len ( IiiIIi1 ) == I1I1 ) : break
     if ( I1I1 > 2 ) : return ( False )
     if 62 - 62: IiII - I1Ii111 % iII111i / oO0o
    oo0o00Oo00o0 = True
    continue
    if 27 - 27: o0oOOo0O0Ooo + iIii1I11I1II1 + OoooooooOO - iII111i
   try : int ( iIi1I11IIi , 16 )
   except : return ( False )
   if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
  return ( True )
  if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
  if 60 - 60: i1IIi / iII111i
  if 10 - 10: I1Ii111 / OoOoOO00 * Ii1I % o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i
  if 2 - 2: iIii1I11I1II1
  if 85 - 85: O0 - ooOoO0o
 if ( value [ 0 ] == "+" ) :
  IiiIIi1 = value [ 1 : : ]
  for iIiI11ii in IiiIIi1 :
   if ( iIiI11ii . isdigit ( ) == False ) : return ( False )
   if 82 - 82: iII111i + I1IiiI * Ii1I . i1IIi - Ii1I % i11iIiiIii
  return ( True )
  if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
 return ( False )
 if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
 if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
 if 88 - 88: iII111i
 if 94 - 94: OoooooooOO
 if 32 - 32: I1ii11iIi11i
 if 8 - 8: I11i * i11iIiiIii - ooOoO0o
 if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
 if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
 if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
 if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
 if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
 if 42 - 42: II111iiii . iII111i
def lisp_process_api ( process , lisp_socket , data_structure ) :
 Oooo00OO , I1I1i = data_structure . split ( "%" )
 if 25 - 25: IiII - IiII
 lprint ( "Process API request '{}', parameters: '{}'" . format ( Oooo00OO ,
 I1I1i ) )
 if 11 - 11: I1IiiI + o0oOOo0O0Ooo / O0 + Ii1I % I11i
 i1I = [ ]
 if ( Oooo00OO == "map-cache" ) :
  if ( I1I1i == "" ) :
   i1I = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , i1I )
  else :
   i1I = lisp_process_api_map_cache_entry ( json . loads ( I1I1i ) )
   if 50 - 50: iII111i * OoooooooOO . O0
   if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
 if ( Oooo00OO == "site-cache" ) :
  if ( I1I1i == "" ) :
   i1I = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 i1I )
  else :
   i1I = lisp_process_api_site_cache_entry ( json . loads ( I1I1i ) )
   if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
   if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
 if ( Oooo00OO == "map-server" ) :
  I1I1i = { } if ( I1I1i == "" ) else json . loads ( I1I1i )
  i1I = lisp_process_api_ms_or_mr ( True , I1I1i )
  if 12 - 12: I1IiiI . OOooOOo % Oo0Ooo
 if ( Oooo00OO == "map-resolver" ) :
  I1I1i = { } if ( I1I1i == "" ) else json . loads ( I1I1i )
  i1I = lisp_process_api_ms_or_mr ( False , I1I1i )
  if 86 - 86: i11iIiiIii
 if ( Oooo00OO == "database-mapping" ) :
  i1I = lisp_process_api_database_mapping ( )
  if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
  if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
  if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
  if 79 - 79: I11i - II111iiii
  if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
 i1I = json . dumps ( i1I )
 iiiii1i1 = lisp_api_ipc ( process , i1I )
 lisp_ipc ( iiiii1i1 , lisp_socket , "lisp-core" )
 return
 if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
 if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
 if 44 - 44: I1IiiI * IiII . OoooooooOO
 if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
 if 10 - 10: i1IIi + o0oOOo0O0Ooo
 if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
 if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
def lisp_process_api_map_cache ( mc , data ) :
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 if 2 - 2: I11i
 if 12 - 12: i1IIi . I1Ii111
 if 99 - 99: Oo0Ooo / i11iIiiIii
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 42 - 42: iII111i / Oo0Ooo
 if 14 - 14: O0 . Oo0Ooo
 if 8 - 8: i11iIiiIii
 if 80 - 80: I1ii11iIi11i + Ii1I
 if 16 - 16: i11iIiiIii * Oo0Ooo
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 76 - 76: iII111i . oO0o - i1IIi
 if 94 - 94: O0 % iII111i
 if 90 - 90: IiII
 if 1 - 1: I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % oO0o + Ii1I
 if 46 - 46: I1IiiI + OoO0O00 - Oo0Ooo
 if 13 - 13: OoOoOO00
 if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
def lisp_gather_map_cache_data ( mc , data ) :
 i1ii1i1Ii11 = { }
 i1ii1i1Ii11 [ "instance-id" ] = str ( mc . eid . instance_id )
 i1ii1i1Ii11 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  i1ii1i1Ii11 [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 90 - 90: oO0o * I1Ii111 / O0
 i1ii1i1Ii11 [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 i1ii1i1Ii11 [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 i1ii1i1Ii11 [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 i1ii1i1Ii11 [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 15 - 15: o0oOOo0O0Ooo * O0 . OOooOOo / Oo0Ooo
 if 28 - 28: OoooooooOO + OoooooooOO
 if 27 - 27: I11i . oO0o / OoooooooOO - OoO0O00 . I11i
 if 15 - 15: II111iiii * OoO0O00
 if 33 - 33: OoooooooOO . o0oOOo0O0Ooo . I1IiiI / I1ii11iIi11i . OoOoOO00
 Oo = [ ]
 for oOO in mc . rloc_set :
  O0OOOO0o0O = { }
  if ( oOO . rloc_exists ( ) ) :
   O0OOOO0o0O [ "address" ] = oOO . rloc . print_address_no_iid ( )
   if 58 - 58: Ii1I
   if 20 - 20: OOooOOo
  if ( oOO . translated_port != 0 ) :
   O0OOOO0o0O [ "encap-port" ] = str ( oOO . translated_port )
   if 93 - 93: i1IIi . IiII % O0 * iII111i
  O0OOOO0o0O [ "state" ] = oOO . print_state ( )
  if ( oOO . geo ) : O0OOOO0o0O [ "geo" ] = oOO . geo . print_geo ( )
  if ( oOO . elp ) : O0OOOO0o0O [ "elp" ] = oOO . elp . print_elp ( False )
  if ( oOO . rle ) : O0OOOO0o0O [ "rle" ] = oOO . rle . print_rle ( False , False )
  if ( oOO . json ) : O0OOOO0o0O [ "json" ] = oOO . json . print_json ( False )
  if ( oOO . rloc_name ) : O0OOOO0o0O [ "rloc-name" ] = oOO . rloc_name
  iIiI11i1iI1 = oOO . stats . get_stats ( False , False )
  if ( iIiI11i1iI1 ) : O0OOOO0o0O [ "stats" ] = iIiI11i1iI1
  O0OOOO0o0O [ "uptime" ] = lisp_print_elapsed ( oOO . uptime )
  O0OOOO0o0O [ "upriority" ] = str ( oOO . priority )
  O0OOOO0o0O [ "uweight" ] = str ( oOO . weight )
  O0OOOO0o0O [ "mpriority" ] = str ( oOO . mpriority )
  O0OOOO0o0O [ "mweight" ] = str ( oOO . mweight )
  o0oO0Oo0O0 = oOO . last_rloc_probe_reply
  if ( o0oO0Oo0O0 ) :
   O0OOOO0o0O [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( o0oO0Oo0O0 )
   O0OOOO0o0O [ "rloc-probe-rtt" ] = str ( oOO . rloc_probe_rtt )
   if 70 - 70: iIii1I11I1II1 . i1IIi / OOooOOo . oO0o / i11iIiiIii + II111iiii
  O0OOOO0o0O [ "rloc-hop-count" ] = oOO . rloc_probe_hops
  O0OOOO0o0O [ "recent-rloc-hop-counts" ] = oOO . recent_rloc_probe_hops
  if 89 - 89: I11i * O0 * Oo0Ooo % i1IIi
  O0OOOO0o0O [ "rloc-probe-latency" ] = oOO . rloc_probe_latency
  O0OOOO0o0O [ "recent-rloc-probe-latencies" ] = oOO . recent_rloc_probe_latencies
  if 41 - 41: OOooOOo + ooOoO0o - OoOoOO00 . iIii1I11I1II1
  OOOo0IiIII1 = [ ]
  for O00OOo0oo in oOO . recent_rloc_probe_rtts : OOOo0IiIII1 . append ( str ( O00OOo0oo ) )
  O0OOOO0o0O [ "recent-rloc-probe-rtts" ] = OOOo0IiIII1
  if 77 - 77: Oo0Ooo % OoOoOO00 - OoooooooOO % iII111i - O0
  Oo . append ( O0OOOO0o0O )
  if 62 - 62: iIii1I11I1II1
 i1ii1i1Ii11 [ "rloc-set" ] = Oo
 if 14 - 14: I1Ii111
 data . append ( i1ii1i1Ii11 )
 return ( [ True , data ] )
 if 95 - 95: II111iiii / o0oOOo0O0Ooo * OOooOOo
 if 81 - 81: i11iIiiIii / iIii1I11I1II1
 if 73 - 73: i11iIiiIii . I1ii11iIi11i * OoOoOO00
 if 95 - 95: i1IIi + iIii1I11I1II1 . I1Ii111 / I1Ii111
 if 84 - 84: Oo0Ooo . OoO0O00 * IiII
 if 95 - 95: OoO0O00
 if 100 - 100: II111iiii
def lisp_process_api_map_cache_entry ( parms ) :
 o0OoO0000o = parms [ "instance-id" ]
 o0OoO0000o = 0 if ( o0OoO0000o == "" ) else int ( o0OoO0000o )
 if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
 if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
 if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
 if 42 - 42: ooOoO0o + I1IiiI * iII111i / OoOoOO00 . i1IIi - OoooooooOO
 ooOOoo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 ooOOoo0 . store_prefix ( parms [ "eid-prefix" ] )
 oo0OoO = ooOOoo0
 i1IIi1ii1i1ii = ooOOoo0
 if 8 - 8: iIii1I11I1II1 - Oo0Ooo + iII111i
 if 40 - 40: o0oOOo0O0Ooo * I1IiiI
 if 75 - 75: O0 * OOooOOo / ooOoO0o + I11i
 if 56 - 56: I1IiiI % OoooooooOO % Oo0Ooo
 if 19 - 19: i11iIiiIii - iIii1I11I1II1 . i1IIi . I1Ii111 / I1IiiI * I1Ii111
 IIi1iiIII11 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 if ( parms . has_key ( "group-prefix" ) ) :
  IIi1iiIII11 . store_prefix ( parms [ "group-prefix" ] )
  oo0OoO = IIi1iiIII11
  if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i * OoOoOO00
  if 16 - 16: oO0o
 i1I = [ ]
 I1iOo0 = lisp_map_cache_lookup ( i1IIi1ii1i1ii , oo0OoO )
 if ( I1iOo0 ) : oO0OOo0o0o , i1I = lisp_process_api_map_cache ( I1iOo0 , i1I )
 return ( i1I )
 if 32 - 32: OoooooooOO
 if 77 - 77: Oo0Ooo . i1IIi - I11i
 if 98 - 98: O0
 if 87 - 87: OoO0O00 % I1Ii111 - OOooOOo - II111iiii + iII111i
 if 54 - 54: i1IIi % iII111i
 if 16 - 16: II111iiii - Oo0Ooo
 if 44 - 44: OOooOOo / Oo0Ooo - I1ii11iIi11i + I11i . oO0o
def lisp_process_api_site_cache ( se , data ) :
 if 85 - 85: iIii1I11I1II1 / Ii1I
 if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
 if 97 - 97: I1Ii111 + I1ii11iIi11i
 if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 80 - 80: I11i
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
 if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
 if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
 if 46 - 46: Oo0Ooo / Oo0Ooo * IiII
 if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 65 - 65: I11i
 if 92 - 92: iII111i . IiII + i1IIi % i1IIi
 if 11 - 11: I1ii11iIi11i + iIii1I11I1II1 - I1Ii111 * iIii1I11I1II1 * IiII + oO0o
 if 6 - 6: I1Ii111 * OOooOOo + i1IIi - Ii1I / oO0o
 if 81 - 81: I1Ii111 % oO0o * i1IIi * OoooooooOO / Oo0Ooo
 if 70 - 70: I1IiiI
 if 35 - 35: i11iIiiIii
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 ii1i1II11II1i = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 IIo0 = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  ii1i1II11II1i . store_address ( data [ "address" ] )
  if 59 - 59: ooOoO0o . iII111i - II111iiii
  if 30 - 30: o0oOOo0O0Ooo % iII111i - i11iIiiIii
 i11II = { }
 if ( ms_or_mr ) :
  for IIIIiI1 in lisp_map_servers_list . values ( ) :
   if ( IIo0 ) :
    if ( IIo0 != IIIIiI1 . dns_name ) : continue
   else :
    if ( ii1i1II11II1i . is_exact_match ( IIIIiI1 . map_server ) == False ) : continue
    if 25 - 25: i11iIiiIii + OoOoOO00 + oO0o / Ii1I * Oo0Ooo + Oo0Ooo
    if 26 - 26: I1IiiI % I1ii11iIi11i + o0oOOo0O0Ooo / I1ii11iIi11i - I1IiiI
   i11II [ "dns-name" ] = IIIIiI1 . dns_name
   i11II [ "address" ] = IIIIiI1 . map_server . print_address_no_iid ( )
   i11II [ "ms-name" ] = "" if IIIIiI1 . ms_name == None else IIIIiI1 . ms_name
   return ( [ i11II ] )
   if 55 - 55: OoooooooOO
 else :
  for O0O0OOoO00 in lisp_map_resolvers_list . values ( ) :
   if ( IIo0 ) :
    if ( IIo0 != O0O0OOoO00 . dns_name ) : continue
   else :
    if ( ii1i1II11II1i . is_exact_match ( O0O0OOoO00 . map_resolver ) == False ) : continue
    if 2 - 2: Oo0Ooo + I11i / OOooOOo + OOooOOo
    if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
   i11II [ "dns-name" ] = O0O0OOoO00 . dns_name
   i11II [ "address" ] = O0O0OOoO00 . map_resolver . print_address_no_iid ( )
   i11II [ "mr-name" ] = "" if O0O0OOoO00 . mr_name == None else O0O0OOoO00 . mr_name
   return ( [ i11II ] )
   if 90 - 90: OOooOOo
   if 29 - 29: OoOoOO00 - I1IiiI / oO0o + Oo0Ooo + I1Ii111 + O0
 return ( [ ] )
 if 65 - 65: oO0o
 if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
 if 13 - 13: Ii1I
 if 34 - 34: I1IiiI / iIii1I11I1II1
 if 35 - 35: oO0o / oO0o
 if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
 if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
 if 77 - 77: O0
def lisp_process_api_database_mapping ( ) :
 i1I = [ ]
 if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
 for iIIo00O000O in lisp_db_list :
  i1ii1i1Ii11 = { }
  i1ii1i1Ii11 [ "eid-prefix" ] = iIIo00O000O . eid . print_prefix ( )
  if ( iIIo00O000O . group . is_null ( ) == False ) :
   i1ii1i1Ii11 [ "group-prefix" ] = iIIo00O000O . group . print_prefix ( )
   if 36 - 36: II111iiii
   if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
  ooOOo = [ ]
  for O0OOOO0o0O in iIIo00O000O . rloc_set :
   oOO = { }
   if ( O0OOOO0o0O . rloc . is_null ( ) == False ) :
    oOO [ "rloc" ] = O0OOOO0o0O . rloc . print_address_no_iid ( )
    if 7 - 7: i11iIiiIii
   if ( O0OOOO0o0O . rloc_name != None ) : oOO [ "rloc-name" ] = O0OOOO0o0O . rloc_name
   if ( O0OOOO0o0O . interface != None ) : oOO [ "interface" ] = O0OOOO0o0O . interface
   Ii1Ii1ii = O0OOOO0o0O . translated_rloc
   if ( Ii1Ii1ii . is_null ( ) == False ) :
    oOO [ "translated-rloc" ] = Ii1Ii1ii . print_address_no_iid ( )
    if 26 - 26: OOooOOo / II111iiii * ooOoO0o
   if ( oOO != { } ) : ooOOo . append ( oOO )
   if 25 - 25: O0 * o0oOOo0O0Ooo - iII111i % OoO0O00
   if 6 - 6: ooOoO0o % Oo0Ooo / I1Ii111 % i11iIiiIii * OoooooooOO + I1ii11iIi11i
   if 21 - 21: o0oOOo0O0Ooo - iII111i / OoO0O00
   if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
   if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
  i1ii1i1Ii11 [ "rlocs" ] = ooOOo
  if 89 - 89: Ii1I * Oo0Ooo / I1Ii111 * I1ii11iIi11i + O0 * Oo0Ooo
  if 74 - 74: I11i . I11i
  if 74 - 74: OoOoOO00 * ooOoO0o * I1Ii111
  if 56 - 56: iIii1I11I1II1 * OoO0O00 - oO0o * Ii1I
  i1I . append ( i1ii1i1Ii11 )
  if 62 - 62: i1IIi + I11i / OOooOOo - OoooooooOO % i1IIi . I1IiiI
 return ( i1I )
 if 13 - 13: O0 * iII111i
 if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
 if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
 if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
 if 47 - 47: I1Ii111 * iII111i
 if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
 if 76 - 76: iIii1I11I1II1 . i11iIiiIii * II111iiii - iII111i
def lisp_gather_site_cache_data ( se , data ) :
 i1ii1i1Ii11 = { }
 i1ii1i1Ii11 [ "site-name" ] = se . site . site_name
 i1ii1i1Ii11 [ "instance-id" ] = str ( se . eid . instance_id )
 i1ii1i1Ii11 [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  i1ii1i1Ii11 [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 51 - 51: I1IiiI
 i1ii1i1Ii11 [ "registered" ] = "yes" if se . registered else "no"
 i1ii1i1Ii11 [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 i1ii1i1Ii11 [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 52 - 52: I1Ii111
 IiiIIi1 = se . last_registerer
 IiiIIi1 = "none" if IiiIIi1 . is_null ( ) else IiiIIi1 . print_address ( )
 i1ii1i1Ii11 [ "last-registerer" ] = IiiIIi1
 i1ii1i1Ii11 [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 i1ii1i1Ii11 [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 i1ii1i1Ii11 [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  i1ii1i1Ii11 [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 82 - 82: iII111i + II111iiii
  if 29 - 29: O0 % Ii1I * ooOoO0o % O0
  if 83 - 83: oO0o
  if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
  if 85 - 85: iIii1I11I1II1 / I11i
 Oo = [ ]
 for oOO in se . registered_rlocs :
  O0OOOO0o0O = { }
  O0OOOO0o0O [ "address" ] = oOO . rloc . print_address_no_iid ( ) if oOO . rloc_exists ( ) else "none"
  if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
  if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
  if ( oOO . geo ) : O0OOOO0o0O [ "geo" ] = oOO . geo . print_geo ( )
  if ( oOO . elp ) : O0OOOO0o0O [ "elp" ] = oOO . elp . print_elp ( False )
  if ( oOO . rle ) : O0OOOO0o0O [ "rle" ] = oOO . rle . print_rle ( False , True )
  if ( oOO . json ) : O0OOOO0o0O [ "json" ] = oOO . json . print_json ( False )
  if ( oOO . rloc_name ) : O0OOOO0o0O [ "rloc-name" ] = oOO . rloc_name
  O0OOOO0o0O [ "uptime" ] = lisp_print_elapsed ( oOO . uptime )
  O0OOOO0o0O [ "upriority" ] = str ( oOO . priority )
  O0OOOO0o0O [ "uweight" ] = str ( oOO . weight )
  O0OOOO0o0O [ "mpriority" ] = str ( oOO . mpriority )
  O0OOOO0o0O [ "mweight" ] = str ( oOO . mweight )
  if 20 - 20: OOooOOo % i1IIi * Ii1I / i11iIiiIii
  Oo . append ( O0OOOO0o0O )
  if 89 - 89: ooOoO0o
 i1ii1i1Ii11 [ "registered-rlocs" ] = Oo
 if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
 data . append ( i1ii1i1Ii11 )
 return ( [ True , data ] )
 if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
 if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
 if 20 - 20: I11i
 if 37 - 37: I1Ii111
 if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
 if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
 if 41 - 41: O0 / OoooooooOO - i1IIi
def lisp_process_api_site_cache_entry ( parms ) :
 o0OoO0000o = parms [ "instance-id" ]
 o0OoO0000o = 0 if ( o0OoO0000o == "" ) else int ( o0OoO0000o )
 if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
 if 32 - 32: oO0o / IiII - I11i . ooOoO0o
 if 69 - 69: i11iIiiIii * i11iIiiIii
 if 100 - 100: I1ii11iIi11i * I1ii11iIi11i + i1IIi
 ooOOoo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 ooOOoo0 . store_prefix ( parms [ "eid-prefix" ] )
 if 96 - 96: I1Ii111 / I1IiiI + ooOoO0o
 if 16 - 16: I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo % OoOoOO00 + ooOoO0o % I1ii11iIi11i
 if 85 - 85: oO0o * OoooooooOO * iIii1I11I1II1 + iII111i
 if 67 - 67: Ii1I / i11iIiiIii % OoOoOO00 % O0 / OoOoOO00
 if 54 - 54: I11i . OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
 IIi1iiIII11 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 if ( parms . has_key ( "group-prefix" ) ) :
  IIi1iiIII11 . store_prefix ( parms [ "group-prefix" ] )
  if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
  if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
 i1I = [ ]
 IiI111II1I1iI = lisp_site_eid_lookup ( ooOOoo0 , IIi1iiIII11 , False )
 if ( IiI111II1I1iI ) : lisp_gather_site_cache_data ( IiI111II1I1iI , i1I )
 return ( i1I )
 if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
 if 89 - 89: I1Ii111
 if 29 - 29: I11i * ooOoO0o - OoooooooOO
 if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
 if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
 if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
 if 73 - 73: OoooooooOO
def lisp_get_interface_instance_id ( device , source_eid ) :
 II1i = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  II1i = lisp_myinterfaces [ device ]
  if 25 - 25: i1IIi . II111iiii . I1Ii111
  if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
  if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
  if 61 - 61: I1ii11iIi11i
  if 12 - 12: OoO0O00
  if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
 if ( II1i == None or II1i . instance_id == None ) :
  return ( lisp_default_iid )
  if 7 - 7: Oo0Ooo
  if 38 - 38: Oo0Ooo - I1ii11iIi11i
  if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
  if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
  if 3 - 3: Ii1I
  if 71 - 71: iIii1I11I1II1 . OOooOOo / I11i / i1IIi
  if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
  if 86 - 86: Oo0Ooo
  if 97 - 97: I1IiiI
 o0OoO0000o = II1i . get_instance_id ( )
 if ( source_eid == None ) : return ( o0OoO0000o )
 if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
 IiIi1i = source_eid . instance_id
 O00OoOoOOO0Oo = None
 for II1i in lisp_multi_tenant_interfaces :
  if ( II1i . device != device ) : continue
  iIiIIi1i = II1i . multi_tenant_eid
  source_eid . instance_id = iIiIIi1i . instance_id
  if ( source_eid . is_more_specific ( iIiIIi1i ) == False ) : continue
  if ( O00OoOoOOO0Oo == None or O00OoOoOOO0Oo . multi_tenant_eid . mask_len < iIiIIi1i . mask_len ) :
   O00OoOoOOO0Oo = II1i
   if 96 - 96: OoOoOO00 . O0 - ooOoO0o
   if 83 - 83: Oo0Ooo % I1IiiI % I11i
 source_eid . instance_id = IiIi1i
 if 54 - 54: Oo0Ooo . oO0o * I11i . i1IIi / Oo0Ooo
 if ( O00OoOoOOO0Oo == None ) : return ( o0OoO0000o )
 return ( O00OoOoOOO0Oo . get_instance_id ( ) )
 if 28 - 28: I1IiiI - I1IiiI % I11i * OOooOOo
 if 97 - 97: iII111i
 if 27 - 27: ooOoO0o + OOooOOo / I1ii11iIi11i % I1Ii111
 if 68 - 68: OOooOOo % OOooOOo
 if 61 - 61: I1ii11iIi11i - i1IIi
 if 53 - 53: o0oOOo0O0Ooo - I11i . I11i + OoooooooOO
 if 6 - 6: II111iiii + I1Ii111
 if 17 - 17: iIii1I11I1II1 / I1ii11iIi11i
 if 85 - 85: o0oOOo0O0Ooo
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( lisp_myinterfaces . has_key ( device ) == False ) : return ( None )
 if 20 - 20: OoooooooOO . ooOoO0o + ooOoO0o
 II1i = lisp_myinterfaces [ device ]
 III1iIIiiIiIi1 = device if II1i . dynamic_eid_device == None else II1i . dynamic_eid_device
 if 28 - 28: ooOoO0o
 if 1 - 1: IiII / OoO0O00 * oO0o - I1Ii111 . OoOoOO00
 if ( II1i . does_dynamic_eid_match ( eid ) ) : return ( III1iIIiiIiIi1 )
 return ( None )
 if 85 - 85: i11iIiiIii + OoOoOO00
 if 4 - 4: OOooOOo . OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
 if 60 - 60: OOooOOo . Ii1I
 if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
 if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
 if 38 - 38: IiII / I11i / IiII * iII111i
 if 30 - 30: oO0o
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 30 - 30: IiII / OoO0O00
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 89 - 89: oO0o . OoOoOO00 . IiII / iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00
 Oooo0Oo0O = lisp_process_rloc_probe_timer
 ooOo0OO0O0 = threading . Timer ( interval , Oooo0Oo0O , [ lisp_sockets ] )
 lisp_rloc_probe_timer = ooOo0OO0O0
 ooOo0OO0O0 . start ( )
 return
 if 94 - 94: Ii1I - iIii1I11I1II1 % OoO0O00 - IiII % i11iIiiIii - o0oOOo0O0Ooo
 if 25 - 25: Oo0Ooo - OOooOOo . i1IIi * OoOoOO00 / I11i / o0oOOo0O0Ooo
 if 54 - 54: OoOoOO00 / i1IIi + OOooOOo - I1ii11iIi11i - I1IiiI * I1Ii111
 if 91 - 91: OoooooooOO * OoooooooOO
 if 27 - 27: ooOoO0o / I1IiiI * I1ii11iIi11i . o0oOOo0O0Ooo
 if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
 if 33 - 33: OOooOOo % OoooooooOO
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for Oo000O000 in lisp_rloc_probe_list :
  oO0O00000OO = lisp_rloc_probe_list [ Oo000O000 ]
  lprint ( "RLOC {}:" . format ( Oo000O000 ) )
  for O0OOOO0o0O , oOo , i11ii in oO0O00000OO :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( O0OOOO0o0O ) ) , oOo . print_prefix ( ) ,
 i11ii . print_prefix ( ) , O0OOOO0o0O . translated_port ) )
   if 40 - 40: I1IiiI + Ii1I . O0 . i1IIi - ooOoO0o . ooOoO0o
   if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 18 - 18: OoO0O00 * ooOoO0o
 if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
 if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
 if 67 - 67: I1IiiI
 if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
 if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
 if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
 if 59 - 59: i11iIiiIii
 if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 59 - 59: I1ii11iIi11i
 if 47 - 47: I1IiiI + Oo0Ooo
 if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
 if 10 - 10: i1IIi % ooOoO0o / iII111i
 oOO , oOo , i11ii = eid_list [ 0 ]
 O0OOoO0O00OoO = [ lisp_print_eid_tuple ( oOo , i11ii ) ]
 if 10 - 10: IiII
 for oOO , oOo , i11ii in eid_list [ 1 : : ] :
  oOO . state = LISP_RLOC_UNREACH_STATE
  oOO . last_state_change = lisp_get_timestamp ( )
  O0OOoO0O00OoO . append ( lisp_print_eid_tuple ( oOo , i11ii ) )
  if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
  if 34 - 34: I1ii11iIi11i . i1IIi * O0 / OoooooooOO
 i1IIiIIi1I1 = bold ( "unreachable" , False )
 o0oooOoOoOo = red ( oOO . rloc . print_address_no_iid ( ) , False )
 if 27 - 27: Oo0Ooo % i11iIiiIii
 for ooOOoo0 in O0OOoO0O00OoO :
  oOo = green ( ooOOoo0 , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( o0oooOoOoOo , i1IIiIIi1I1 , oOo ) )
  if 48 - 48: IiII
  if 74 - 74: Oo0Ooo
  if 75 - 75: IiII + OOooOOo
  if 92 - 92: OoOoOO00
  if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
  if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 for oOO , oOo , i11ii in eid_list :
  I1iOo0 = lisp_map_cache . lookup_cache ( oOo , True )
  if ( I1iOo0 ) : lisp_write_ipc_map_cache ( True , I1iOo0 )
  if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 return
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
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
 if 76 - 76: iII111i * OOooOOo
 if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
 if 40 - 40: iII111i
 if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
 if 33 - 33: OoooooooOO
 Ooooo00o0 = lisp_get_default_route_next_hops ( )
 if 11 - 11: i1IIi + I1ii11iIi11i * I1IiiI - IiII
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 61 - 61: OOooOOo . iII111i * I1Ii111
 if 94 - 94: I1ii11iIi11i % II111iiii . O0
 if 38 - 38: o0oOOo0O0Ooo % i11iIiiIii / I1Ii111 / I1ii11iIi11i % iII111i - oO0o
 if 76 - 76: iIii1I11I1II1 / I1ii11iIi11i + i1IIi % oO0o / iIii1I11I1II1
 if 33 - 33: OoooooooOO * i1IIi / O0 * I1ii11iIi11i
 I1I1 = 0
 O0OoO0ooo0Ooo = bold ( "RLOC-probe" , False )
 for oOoO0oOo0ooOo in lisp_rloc_probe_list . values ( ) :
  if 14 - 14: i1IIi - ooOoO0o + ooOoO0o
  if 93 - 93: oO0o - I1IiiI / I1ii11iIi11i % o0oOOo0O0Ooo / OoooooooOO + II111iiii
  if 10 - 10: o0oOOo0O0Ooo - iII111i . O0 + OoO0O00 - Oo0Ooo - i11iIiiIii
  if 37 - 37: iIii1I11I1II1
  if 37 - 37: II111iiii % OoOoOO00 . IiII * ooOoO0o . I1IiiI
  Iiiii1IIIii = None
  for IiI11I1i , ooOOoo0 , IIi1iiIII11 in oOoO0oOo0ooOo :
   oo0o00OO = IiI11I1i . rloc . print_address_no_iid ( )
   if 81 - 81: oO0o . OOooOOo - Ii1I . OoOoOO00
   if 100 - 100: Ii1I * i1IIi * i1IIi - iII111i + OoO0O00 + OoO0O00
   if 9 - 9: oO0o / OoO0O00 . I1IiiI
   if 24 - 24: IiII * i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o + ooOoO0o . II111iiii
   o0iIII1I , oooOo000Oo , OO0Oo00oo = lisp_allow_gleaning ( ooOOoo0 , None , IiI11I1i )
   if ( o0iIII1I and oooOo000Oo == False ) :
    oOo = green ( ooOOoo0 . print_address ( ) , False )
    oo0o00OO += ":{}" . format ( IiI11I1i . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( oo0o00OO , False ) , oOo ) )
    if 98 - 98: OoO0O00
    continue
    if 46 - 46: iII111i - I11i
    if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
    if 7 - 7: I1ii11iIi11i
    if 37 - 37: O0 . II111iiii
    if 70 - 70: o0oOOo0O0Ooo / iII111i + i1IIi + I11i % iIii1I11I1II1 % Oo0Ooo
    if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
    if 1 - 1: I1ii11iIi11i / i1IIi . I1IiiI / Ii1I
   if ( IiI11I1i . down_state ( ) ) : continue
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
   if ( Iiiii1IIIii ) :
    IiI11I1i . last_rloc_probe_nonce = Iiiii1IIIii . last_rloc_probe_nonce
    if 29 - 29: IiII + I1ii11iIi11i
    if ( Iiiii1IIIii . translated_port == IiI11I1i . translated_port and Iiiii1IIIii . rloc_name == IiI11I1i . rloc_name ) :
     if 8 - 8: IiII % I1IiiI
     oOo = green ( lisp_print_eid_tuple ( ooOOoo0 , IIi1iiIII11 ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( oo0o00OO , False ) , oOo ) )
     if 10 - 10: OoooooooOO / OoOoOO00
     if 77 - 77: OoOoOO00
     if 10 - 10: IiII / i11iIiiIii
     if 19 - 19: OoO0O00
     if 100 - 100: I1ii11iIi11i - I1ii11iIi11i
     if 38 - 38: I1Ii111
     IiI11I1i . last_rloc_probe = Iiiii1IIIii . last_rloc_probe
     continue
     if 23 - 23: Ii1I . I1ii11iIi11i + I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
     if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
     if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
   I11Ii11IiiII11ii = None
   oOO = None
   while ( True ) :
    oOO = IiI11I1i if oOO == None else oOO . next_rloc
    if ( oOO == None ) : break
    if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
    if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
    if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
    if 40 - 40: iII111i - I1IiiI + OoOoOO00
    if 2 - 2: I11i - II111iiii / I1Ii111
    if ( oOO . rloc_next_hop != None ) :
     if ( oOO . rloc_next_hop not in Ooooo00o0 ) :
      if ( oOO . up_state ( ) ) :
       OooOOOoOoo0O0 , iIIi1Iii1Ii = oOO . rloc_next_hop
       oOO . state = LISP_RLOC_UNREACH_STATE
       oOO . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( oOO . rloc , False )
       if 27 - 27: OoO0O00 - I1ii11iIi11i * i11iIiiIii + Oo0Ooo
      i1IIiIIi1I1 = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( iIIi1Iii1Ii , OooOOOoOoo0O0 ,
 red ( oo0o00OO , False ) , i1IIiIIi1I1 ) )
      continue
      if 29 - 29: I1ii11iIi11i / IiII . I1Ii111 + Ii1I + OoO0O00
      if 76 - 76: ooOoO0o . I11i * OoO0O00
      if 53 - 53: II111iiii / OoOoOO00 / IiII * oO0o
      if 52 - 52: O0 % iII111i * iIii1I11I1II1 / I11i / I1IiiI * ooOoO0o
      if 93 - 93: iIii1I11I1II1 . II111iiii * OOooOOo - iIii1I11I1II1 . oO0o % Oo0Ooo
      if 92 - 92: OoO0O00
    iiI = oOO . last_rloc_probe
    iI1i1iIi = 0 if iiI == None else time . time ( ) - iiI
    if ( oOO . unreach_state ( ) and iI1i1iIi < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( oo0o00OO , False ) ) )
     if 38 - 38: o0oOOo0O0Ooo * I1ii11iIi11i + OoooooooOO
     continue
     if 53 - 53: OOooOOo . I11i + O0 % o0oOOo0O0Ooo
     if 100 - 100: iIii1I11I1II1 . OoOoOO00 . OoooooooOO / I1ii11iIi11i - I1IiiI * I11i
     if 5 - 5: i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1IiiI - II111iiii
     if 15 - 15: I1Ii111
     if 38 - 38: O0
     if 50 - 50: i11iIiiIii * OoO0O00 + iII111i / O0 * oO0o % ooOoO0o
    ii1 = lisp_get_echo_nonce ( None , oo0o00OO )
    if ( ii1 and ii1 . request_nonce_timeout ( ) ) :
     oOO . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     oOO . last_state_change = lisp_get_timestamp ( )
     i1IIiIIi1I1 = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( oo0o00OO , False ) , i1IIiIIi1I1 ) )
     if 6 - 6: OoO0O00 . o0oOOo0O0Ooo / Ii1I + Ii1I
     lisp_update_rtr_updown ( oOO . rloc , False )
     continue
     if 59 - 59: II111iiii - o0oOOo0O0Ooo * OoooooooOO
     if 83 - 83: oO0o . iIii1I11I1II1 . iII111i % Oo0Ooo
     if 48 - 48: oO0o % OoO0O00 - OoooooooOO . IiII
     if 11 - 11: I1Ii111 % o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i
     if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
     if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
    if ( ii1 and ii1 . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( oo0o00OO , False ) ) )
     if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
     continue
     if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
     if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
     if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
     if 47 - 47: OOooOOo + IiII
     if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
     if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
    if ( oOO . last_rloc_probe != None ) :
     iiI = oOO . last_rloc_probe_reply
     if ( iiI == None ) : iiI = 0
     iI1i1iIi = time . time ( ) - iiI
     if ( oOO . up_state ( ) and iI1i1iIi >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 64 - 64: Ii1I
      oOO . state = LISP_RLOC_UNREACH_STATE
      oOO . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( oOO . rloc , False )
      i1IIiIIi1I1 = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( oo0o00OO , False ) , i1IIiIIi1I1 ) )
      if 4 - 4: OoOoOO00
      if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
      lisp_mark_rlocs_for_other_eids ( oOoO0oOo0ooOo )
      if 48 - 48: iII111i / II111iiii * I1Ii111 + I11i / ooOoO0o . OoOoOO00
      if 45 - 45: OOooOOo / Ii1I % O0
      if 7 - 7: oO0o * i11iIiiIii + OoooooooOO + I11i
    oOO . last_rloc_probe = lisp_get_timestamp ( )
    if 9 - 9: II111iiii * Oo0Ooo * I1Ii111 . IiII
    Ooii = "" if oOO . unreach_state ( ) == False else " unreachable"
    if 53 - 53: I1Ii111
    if 69 - 69: iIii1I11I1II1 * oO0o
    if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
    if 64 - 64: I1IiiI % i11iIiiIii / oO0o
    if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
    if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
    if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
    i1iiiIi = ""
    iIIi1Iii1Ii = None
    if ( oOO . rloc_next_hop != None ) :
     OooOOOoOoo0O0 , iIIi1Iii1Ii = oOO . rloc_next_hop
     lisp_install_host_route ( oo0o00OO , iIIi1Iii1Ii , True )
     i1iiiIi = ", send on nh {}({})" . format ( iIIi1Iii1Ii , OooOOOoOoo0O0 )
     if 66 - 66: IiII - O0 + oO0o - OoO0O00 % I11i
     if 50 - 50: OoooooooOO - iII111i
     if 40 - 40: Ii1I . I1Ii111 % i11iIiiIii / II111iiii . i11iIiiIii * II111iiii
     if 2 - 2: ooOoO0o
     if 65 - 65: O0 - o0oOOo0O0Ooo - OoO0O00
    O00OOo0oo = oOO . print_rloc_probe_rtt ( )
    iIIiiIiiI111 = oo0o00OO
    if ( oOO . translated_port != 0 ) :
     iIIiiIiiI111 += ":{}" . format ( oOO . translated_port )
     if 30 - 30: I1IiiI % iIii1I11I1II1
    iIIiiIiiI111 = red ( iIIiiIiiI111 , False )
    if ( oOO . rloc_name != None ) :
     iIIiiIiiI111 += " (" + blue ( oOO . rloc_name , False ) + ")"
     if 37 - 37: OoooooooOO - Oo0Ooo % oO0o
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( O0OoO0ooo0Ooo , Ooii ,
 iIIiiIiiI111 , O00OOo0oo , i1iiiIi ) )
    if 59 - 59: II111iiii - o0oOOo0O0Ooo / I1ii11iIi11i . oO0o / o0oOOo0O0Ooo - iII111i
    if 65 - 65: I1ii11iIi11i * OOooOOo * ooOoO0o + oO0o - OOooOOo
    if 100 - 100: iII111i
    if 12 - 12: OoooooooOO - I1ii11iIi11i * iII111i / ooOoO0o
    if 99 - 99: I1ii11iIi11i + I11i
    if 29 - 29: I1ii11iIi11i / oO0o
    if 2 - 2: Oo0Ooo / IiII - OoooooooOO
    if 65 - 65: OoO0O00 - Ii1I
    if ( oOO . rloc_next_hop != None ) :
     I11Ii11IiiII11ii = lisp_get_host_route_next_hop ( oo0o00OO )
     if ( I11Ii11IiiII11ii ) : lisp_install_host_route ( oo0o00OO , I11Ii11IiiII11ii , False )
     if 98 - 98: OoOoOO00 * I1Ii111 * iIii1I11I1II1 * OoOoOO00
     if 15 - 15: Oo0Ooo
     if 100 - 100: IiII + I1ii11iIi11i + iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
     if 84 - 84: o0oOOo0O0Ooo * I11i
     if 22 - 22: i1IIi + OOooOOo % OoooooooOO
     if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
    if ( oOO . rloc . is_null ( ) ) :
     oOO . rloc . copy_address ( IiI11I1i . rloc )
     if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
     if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
     if 66 - 66: OoooooooOO
     if 90 - 90: IiII - OoOoOO00
     if 98 - 98: Oo0Ooo / oO0o . Ii1I
    O0OOO0OOo0 = None if ( IIi1iiIII11 . is_null ( ) ) else ooOOoo0
    O00O0o00Oo = ooOOoo0 if ( IIi1iiIII11 . is_null ( ) ) else IIi1iiIII11
    lisp_send_map_request ( lisp_sockets , 0 , O0OOO0OOo0 , O00O0o00Oo , oOO )
    Iiiii1IIIii = IiI11I1i
    if 65 - 65: o0oOOo0O0Ooo + O0 % Ii1I
    if 63 - 63: OoooooooOO * i11iIiiIii * I1ii11iIi11i
    if 12 - 12: ooOoO0o + OOooOOo . i1IIi % i11iIiiIii
    if 61 - 61: o0oOOo0O0Ooo - Ii1I % o0oOOo0O0Ooo
    if ( iIIi1Iii1Ii ) : lisp_install_host_route ( oo0o00OO , iIIi1Iii1Ii , False )
    if 59 - 59: OoooooooOO . iIii1I11I1II1 * OoooooooOO + ooOoO0o
    if 56 - 56: OoOoOO00 . iII111i / OOooOOo
    if 39 - 39: iIii1I11I1II1 % ooOoO0o
    if 75 - 75: i1IIi * II111iiii * O0 * i11iIiiIii % iII111i / iII111i
    if 36 - 36: IiII / I1IiiI % iII111i / iII111i
   if ( I11Ii11IiiII11ii ) : lisp_install_host_route ( oo0o00OO , I11Ii11IiiII11ii , True )
   if 38 - 38: OOooOOo * I1ii11iIi11i * I1Ii111 + I11i
   if 65 - 65: O0 + O0 * I1Ii111
   if 66 - 66: OOooOOo / O0 + i1IIi . O0 % I1ii11iIi11i - OoooooooOO
   if 16 - 16: I11i % iII111i
   I1I1 += 1
   if ( ( I1I1 % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 29 - 29: I1IiiI - ooOoO0o * OoO0O00 . i11iIiiIii % OoOoOO00 * o0oOOo0O0Ooo
   if 43 - 43: OoO0O00 * OOooOOo / I1Ii111 % OoOoOO00 . oO0o / OOooOOo
   if 62 - 62: O0 * I1ii11iIi11i - O0 / I11i % ooOoO0o
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 1 - 1: O0 / iIii1I11I1II1
 if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
 if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
 if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
 if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
 if 16 - 16: o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii . I1ii11iIi11i
 if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 83 - 83: OoooooooOO % I1ii11iIi11i . IiII + OOooOOo . iII111i - ooOoO0o
 if 100 - 100: o0oOOo0O0Ooo
 if 95 - 95: iII111i * oO0o * i1IIi
 if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
 if ( lisp_i_am_itr == False ) : return
 if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
 if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
 if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
 if 76 - 76: OoO0O00
 if ( lisp_register_all_rtrs ) : return
 if 92 - 92: iIii1I11I1II1 * O0 % I11i
 oOO000 = rtr . print_address_no_iid ( )
 if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1
 if 2 - 2: Oo0Ooo + II111iiii * O0 / iIii1I11I1II1 / iIii1I11I1II1
 if 33 - 33: OOooOOo * OOooOOo . II111iiii % O0 % O0 % o0oOOo0O0Ooo
 if 45 - 45: OoooooooOO * oO0o
 if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
 if ( lisp_rtr_list . has_key ( oOO000 ) == False ) : return
 if 16 - 16: Oo0Ooo
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( oOO000 , False ) , bold ( updown , False ) ) )
 if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
 if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 if 67 - 67: I1IiiI
 if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
 iiiii1i1 = "rtr%{}%{}" . format ( oOO000 , updown )
 iiiii1i1 = lisp_command_ipc ( iiiii1i1 , "lisp-itr" )
 lisp_ipc ( iiiii1i1 , lisp_ipc_socket , "lisp-etr" )
 return
 if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
 if 33 - 33: OOooOOo - OoooooooOO . iII111i
 if 2 - 2: I11i + i1IIi
 if 52 - 52: I11i - OoO0O00 % I1Ii111 . OOooOOo
 if 90 - 90: O0 - Oo0Ooo / i1IIi * iIii1I11I1II1 % o0oOOo0O0Ooo / oO0o
 if 73 - 73: iII111i % iIii1I11I1II1 + o0oOOo0O0Ooo % Ii1I . II111iiii + IiII
 if 55 - 55: OoOoOO00 * II111iiii / iII111i + OOooOOo / OoooooooOO
def lisp_process_rloc_probe_reply ( rloc_entry , source , port , map_reply , ttl ) :
 oOO = rloc_entry . rloc
 Iii11I = map_reply . nonce
 IiIiIIiIIIii1 = map_reply . hop_count
 O0OoO0ooo0Ooo = bold ( "RLOC-probe reply" , False )
 O0oO = oOO . print_address_no_iid ( )
 iIIii = source . print_address_no_iid ( )
 i1iII1iII11i1 = lisp_rloc_probe_list
 iIi1I = rloc_entry . json . json_string if rloc_entry . json else None
 if 23 - 23: OOooOOo % Oo0Ooo . iII111i
 if 53 - 53: OoO0O00 - OoooooooOO
 if 81 - 81: i1IIi / I1ii11iIi11i - OoOoOO00 + I1Ii111
 if 21 - 21: OoooooooOO
 if 63 - 63: I1IiiI / o0oOOo0O0Ooo - I1Ii111
 if 49 - 49: iII111i . OoOoOO00
 IiiIIi1 = O0oO
 if ( i1iII1iII11i1 . has_key ( IiiIIi1 ) == False ) :
  IiiIIi1 += ":" + str ( port )
  if ( i1iII1iII11i1 . has_key ( IiiIIi1 ) == False ) :
   IiiIIi1 = iIIii
   if ( i1iII1iII11i1 . has_key ( IiiIIi1 ) == False ) :
    IiiIIi1 += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( O0OoO0ooo0Ooo , red ( O0oO , False ) , red ( iIIii ,
    # i1IIi - OoooooooOO % ooOoO0o % OOooOOo * i11iIiiIii % I11i
 False ) , port ) )
    return
    if 91 - 91: I11i
    if 24 - 24: ooOoO0o . i1IIi - O0 + I11i
    if 71 - 71: OoOoOO00
    if 29 - 29: O0 . i11iIiiIii
    if 51 - 51: IiII
    if 53 - 53: O0
    if 19 - 19: o0oOOo0O0Ooo / iII111i % OoOoOO00
    if 65 - 65: o0oOOo0O0Ooo
 i1 = lisp_get_timestamp ( )
 for oOO , ooOOoo0 , IIi1iiIII11 in lisp_rloc_probe_list [ IiiIIi1 ] :
  if ( lisp_i_am_rtr ) :
   if ( oOO . translated_port != 0 and oOO . translated_port != port ) :
    continue
    if 89 - 89: iIii1I11I1II1 + OoooooooOO + i1IIi + OoooooooOO % IiII * OoO0O00
    if 53 - 53: OOooOOo . IiII % I11i - OoO0O00 - Oo0Ooo
  oOO . process_rloc_probe_reply ( i1 , Iii11I , ooOOoo0 , IIi1iiIII11 , IiIiIIiIIIii1 , ttl , iIi1I )
  if 58 - 58: I1Ii111 / OoooooooOO . I11i % I1Ii111
 return
 if 8 - 8: Oo0Ooo % ooOoO0o / i11iIiiIii
 if 54 - 54: IiII
 if 85 - 85: OOooOOo - i1IIi
 if 10 - 10: I1ii11iIi11i
 if 3 - 3: ooOoO0o * O0 / o0oOOo0O0Ooo
 if 22 - 22: OoOoOO00 + OOooOOo . iII111i % iIii1I11I1II1 - I11i
 if 23 - 23: OoOoOO00 * I1Ii111
 if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
def lisp_db_list_length ( ) :
 I1I1 = 0
 for iIIo00O000O in lisp_db_list :
  I1I1 += len ( iIIo00O000O . dynamic_eids ) if iIIo00O000O . dynamic_eid_configured ( ) else 1
  I1I1 += len ( iIIo00O000O . eid . iid_list )
  if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
 return ( I1I1 )
 if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
 if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
 if 25 - 25: OoO0O00 * oO0o
 if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
 if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
 if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
 if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
 if 73 - 73: Oo0Ooo + II111iiii - IiII
def lisp_is_myeid ( eid ) :
 for iIIo00O000O in lisp_db_list :
  if ( eid . is_more_specific ( iIIo00O000O . eid ) ) : return ( True )
  if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
 return ( False )
 if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
 if 66 - 66: II111iiii * I1IiiI . Oo0Ooo * OoooooooOO % OoOoOO00 . II111iiii
 if 4 - 4: iII111i + I1Ii111 % OoOoOO00 / Ii1I
 if 94 - 94: OoO0O00
 if 35 - 35: I1ii11iIi11i % OoO0O00 + II111iiii % II111iiii / IiII - iII111i
 if 9 - 9: I1ii11iIi11i * o0oOOo0O0Ooo . oO0o
 if 48 - 48: IiII . I1Ii111 + OoooooooOO - I1Ii111 . Ii1I . I1Ii111
 if 24 - 24: ooOoO0o * iIii1I11I1II1
 if 1 - 1: I1ii11iIi11i . O0
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 3 - 3: iIii1I11I1II1 * ooOoO0o - OoOoOO00 * I1ii11iIi11i % OoOoOO00 - OoooooooOO
 if 42 - 42: I1Ii111 - i1IIi
 if 91 - 91: iII111i . OOooOOo / iIii1I11I1II1 . Oo0Ooo . II111iiii . OoOoOO00
 if 31 - 31: OoO0O00 . I1ii11iIi11i % I11i - II111iiii
 if 70 - 70: ooOoO0o - IiII - OoO0O00 / I11i
 if 59 - 59: IiII % ooOoO0o . iII111i / Ii1I * Ii1I
 if 73 - 73: I1ii11iIi11i . oO0o % I11i . I1ii11iIi11i / I1Ii111 / II111iiii
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 ii1 = None
 if ( lisp_nonce_echo_list . has_key ( rloc_str ) ) :
  ii1 = lisp_nonce_echo_list [ rloc_str ]
  if 76 - 76: I1Ii111
 return ( ii1 )
 if 91 - 91: iIii1I11I1II1 / Ii1I . I1IiiI
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 if 85 - 85: II111iiii + I1ii11iIi11i
 if 33 - 33: iII111i
 if 14 - 14: O0 * Oo0Ooo / i1IIi
 if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
 if 78 - 78: II111iiii % OOooOOo
 if 6 - 6: OOooOOo
def lisp_decode_dist_name ( packet ) :
 I1I1 = 0
 I1I11iII = ""
 if 48 - 48: OOooOOo - II111iiii - i11iIiiIii
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( I1I1 == 255 ) : return ( [ None , None ] )
  I1I11iII += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  I1I1 += 1
  if 82 - 82: i11iIiiIii % I11i . OoOoOO00 + Ii1I * iIii1I11I1II1 - OoOoOO00
  if 96 - 96: I1IiiI
 packet = packet [ 1 : : ]
 return ( packet , I1I11iII )
 if 3 - 3: OoooooooOO
 if 3 - 3: IiII / O0 * i11iIiiIii . iII111i - iIii1I11I1II1
 if 56 - 56: ooOoO0o
 if 82 - 82: ooOoO0o . IiII . I1Ii111 - iIii1I11I1II1 + II111iiii . OoOoOO00
 if 59 - 59: Oo0Ooo
 if 98 - 98: I1Ii111 * II111iiii / Oo0Ooo . Oo0Ooo % I1Ii111
 if 52 - 52: OoOoOO00
 if 59 - 59: ooOoO0o / OoooooooOO
def lisp_write_flow_log ( flow_log ) :
 OOO000 = open ( "./logs/lisp-flow.log" , "a" )
 if 71 - 71: OOooOOo + I11i * O0 / o0oOOo0O0Ooo + I1IiiI + Ii1I
 I1I1 = 0
 for III11i in flow_log :
  IiiiIi1iiii11 = III11i [ 3 ]
  i11IiIIIi11i = IiiiIi1iiii11 . print_flow ( III11i [ 0 ] , III11i [ 1 ] , III11i [ 2 ] )
  OOO000 . write ( i11IiIIIi11i )
  I1I1 += 1
  if 11 - 11: O0 % i11iIiiIii
 OOO000 . close ( )
 del ( flow_log )
 if 7 - 7: I11i - OoOoOO00 % I11i . i11iIiiIii
 I1I1 = bold ( str ( I1I1 ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( I1I1 ) )
 return
 if 28 - 28: oO0o * i11iIiiIii * i11iIiiIii % OoooooooOO / I1IiiI / II111iiii
 if 36 - 36: ooOoO0o % i1IIi . ooOoO0o % oO0o % O0 . II111iiii
 if 74 - 74: I1ii11iIi11i % I1IiiI
 if 47 - 47: I1ii11iIi11i % I1IiiI . iII111i * I11i . I1IiiI + iII111i
 if 53 - 53: iIii1I11I1II1
 if 56 - 56: OoooooooOO % II111iiii + oO0o
 if 67 - 67: ooOoO0o + I11i - I1ii11iIi11i - OoooooooOO
def lisp_policy_command ( kv_pair ) :
 oo00ooOOOo0O = lisp_policy ( "" )
 i1Ii1I1iii = None
 if 87 - 87: iII111i + IiII * I1ii11iIi11i . iII111i + Ii1I - II111iiii
 oOIII1IIii1 = [ ]
 for IiIIi1IiiIiI in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  oOIII1IIii1 . append ( lisp_policy_match ( ) )
  if 62 - 62: IiII % I1IiiI - OoooooooOO % I1ii11iIi11i % I1ii11iIi11i . Oo0Ooo
  if 17 - 17: I1IiiI * I1ii11iIi11i
 for Oo00o0oOooO in kv_pair . keys ( ) :
  i11II = kv_pair [ Oo00o0oOooO ]
  if 67 - 67: II111iiii . I1Ii111 % OoooooooOO - OoO0O00 * I1ii11iIi11i . OoO0O00
  if 69 - 69: OoOoOO00 / OoO0O00
  if 37 - 37: OOooOOo * I11i
  if 1 - 1: OOooOOo
  if ( Oo00o0oOooO == "instance-id" ) :
   for IiIIi1IiiIiI in range ( len ( oOIII1IIii1 ) ) :
    O0oOO0O00OOO0 = i11II [ IiIIi1IiiIiI ]
    if ( O0oOO0O00OOO0 == "" ) : continue
    I11iIii11Ii = oOIII1IIii1 [ IiIIi1IiiIiI ]
    if ( I11iIii11Ii . source_eid == None ) :
     I11iIii11Ii . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 84 - 84: OOooOOo
    if ( I11iIii11Ii . dest_eid == None ) :
     I11iIii11Ii . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 35 - 35: I1IiiI . ooOoO0o - O0
    I11iIii11Ii . source_eid . instance_id = int ( O0oOO0O00OOO0 )
    I11iIii11Ii . dest_eid . instance_id = int ( O0oOO0O00OOO0 )
    if 63 - 63: Ii1I
    if 9 - 9: iIii1I11I1II1 / OOooOOo * O0 . Oo0Ooo + OoO0O00
  if ( Oo00o0oOooO == "source-eid" ) :
   for IiIIi1IiiIiI in range ( len ( oOIII1IIii1 ) ) :
    O0oOO0O00OOO0 = i11II [ IiIIi1IiiIiI ]
    if ( O0oOO0O00OOO0 == "" ) : continue
    I11iIii11Ii = oOIII1IIii1 [ IiIIi1IiiIiI ]
    if ( I11iIii11Ii . source_eid == None ) :
     I11iIii11Ii . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 95 - 95: I11i . o0oOOo0O0Ooo + O0
    o0OoO0000o = I11iIii11Ii . source_eid . instance_id
    I11iIii11Ii . source_eid . store_prefix ( O0oOO0O00OOO0 )
    I11iIii11Ii . source_eid . instance_id = o0OoO0000o
    if 36 - 36: I1IiiI * ooOoO0o
    if 74 - 74: I1IiiI - ooOoO0o / I1ii11iIi11i
  if ( Oo00o0oOooO == "destination-eid" ) :
   for IiIIi1IiiIiI in range ( len ( oOIII1IIii1 ) ) :
    O0oOO0O00OOO0 = i11II [ IiIIi1IiiIiI ]
    if ( O0oOO0O00OOO0 == "" ) : continue
    I11iIii11Ii = oOIII1IIii1 [ IiIIi1IiiIiI ]
    if ( I11iIii11Ii . dest_eid == None ) :
     I11iIii11Ii . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 82 - 82: II111iiii % OoOoOO00
    o0OoO0000o = I11iIii11Ii . dest_eid . instance_id
    I11iIii11Ii . dest_eid . store_prefix ( O0oOO0O00OOO0 )
    I11iIii11Ii . dest_eid . instance_id = o0OoO0000o
    if 32 - 32: i11iIiiIii
    if 38 - 38: IiII + I1Ii111 % Ii1I / Ii1I
  if ( Oo00o0oOooO == "source-rloc" ) :
   for IiIIi1IiiIiI in range ( len ( oOIII1IIii1 ) ) :
    O0oOO0O00OOO0 = i11II [ IiIIi1IiiIiI ]
    if ( O0oOO0O00OOO0 == "" ) : continue
    I11iIii11Ii = oOIII1IIii1 [ IiIIi1IiiIiI ]
    I11iIii11Ii . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    I11iIii11Ii . source_rloc . store_prefix ( O0oOO0O00OOO0 )
    if 39 - 39: iII111i * i11iIiiIii
    if 31 - 31: IiII - Ii1I . i1IIi
  if ( Oo00o0oOooO == "destination-rloc" ) :
   for IiIIi1IiiIiI in range ( len ( oOIII1IIii1 ) ) :
    O0oOO0O00OOO0 = i11II [ IiIIi1IiiIiI ]
    if ( O0oOO0O00OOO0 == "" ) : continue
    I11iIii11Ii = oOIII1IIii1 [ IiIIi1IiiIiI ]
    I11iIii11Ii . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    I11iIii11Ii . dest_rloc . store_prefix ( O0oOO0O00OOO0 )
    if 1 - 1: o0oOOo0O0Ooo + OOooOOo % Ii1I - O0 / I1ii11iIi11i
    if 20 - 20: o0oOOo0O0Ooo + II111iiii * Ii1I . OoooooooOO
  if ( Oo00o0oOooO == "rloc-record-name" ) :
   for IiIIi1IiiIiI in range ( len ( oOIII1IIii1 ) ) :
    O0oOO0O00OOO0 = i11II [ IiIIi1IiiIiI ]
    if ( O0oOO0O00OOO0 == "" ) : continue
    I11iIii11Ii = oOIII1IIii1 [ IiIIi1IiiIiI ]
    I11iIii11Ii . rloc_record_name = O0oOO0O00OOO0
    if 88 - 88: O0 + iIii1I11I1II1 . o0oOOo0O0Ooo . iIii1I11I1II1 - Ii1I
    if 74 - 74: Ii1I . IiII
  if ( Oo00o0oOooO == "geo-name" ) :
   for IiIIi1IiiIiI in range ( len ( oOIII1IIii1 ) ) :
    O0oOO0O00OOO0 = i11II [ IiIIi1IiiIiI ]
    if ( O0oOO0O00OOO0 == "" ) : continue
    I11iIii11Ii = oOIII1IIii1 [ IiIIi1IiiIiI ]
    I11iIii11Ii . geo_name = O0oOO0O00OOO0
    if 67 - 67: oO0o
    if 12 - 12: I1IiiI + OoooooooOO
  if ( Oo00o0oOooO == "elp-name" ) :
   for IiIIi1IiiIiI in range ( len ( oOIII1IIii1 ) ) :
    O0oOO0O00OOO0 = i11II [ IiIIi1IiiIiI ]
    if ( O0oOO0O00OOO0 == "" ) : continue
    I11iIii11Ii = oOIII1IIii1 [ IiIIi1IiiIiI ]
    I11iIii11Ii . elp_name = O0oOO0O00OOO0
    if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
    if 19 - 19: OoooooooOO / IiII
  if ( Oo00o0oOooO == "rle-name" ) :
   for IiIIi1IiiIiI in range ( len ( oOIII1IIii1 ) ) :
    O0oOO0O00OOO0 = i11II [ IiIIi1IiiIiI ]
    if ( O0oOO0O00OOO0 == "" ) : continue
    I11iIii11Ii = oOIII1IIii1 [ IiIIi1IiiIiI ]
    I11iIii11Ii . rle_name = O0oOO0O00OOO0
    if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
    if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
  if ( Oo00o0oOooO == "json-name" ) :
   for IiIIi1IiiIiI in range ( len ( oOIII1IIii1 ) ) :
    O0oOO0O00OOO0 = i11II [ IiIIi1IiiIiI ]
    if ( O0oOO0O00OOO0 == "" ) : continue
    I11iIii11Ii = oOIII1IIii1 [ IiIIi1IiiIiI ]
    I11iIii11Ii . json_name = O0oOO0O00OOO0
    if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
    if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
  if ( Oo00o0oOooO == "datetime-range" ) :
   for IiIIi1IiiIiI in range ( len ( oOIII1IIii1 ) ) :
    O0oOO0O00OOO0 = i11II [ IiIIi1IiiIiI ]
    I11iIii11Ii = oOIII1IIii1 [ IiIIi1IiiIiI ]
    if ( O0oOO0O00OOO0 == "" ) : continue
    I11iIi1i1I1i1 = lisp_datetime ( O0oOO0O00OOO0 [ 0 : 19 ] )
    iiiiI1I11iI1 = lisp_datetime ( O0oOO0O00OOO0 [ 19 : : ] )
    if ( I11iIi1i1I1i1 . valid_datetime ( ) and iiiiI1I11iI1 . valid_datetime ( ) ) :
     I11iIii11Ii . datetime_lower = I11iIi1i1I1i1
     I11iIii11Ii . datetime_upper = iiiiI1I11iI1
     if 51 - 51: OoO0O00 - OoO0O00 * IiII
     if 24 - 24: OoooooooOO . II111iiii
     if 97 - 97: II111iiii . O0
     if 18 - 18: iII111i
     if 35 - 35: ooOoO0o / O0 / iIii1I11I1II1 - iIii1I11I1II1 + I11i
     if 8 - 8: I1Ii111 . oO0o % Oo0Ooo * OoooooooOO
     if 25 - 25: OoO0O00
  if ( Oo00o0oOooO == "set-action" ) :
   oo00ooOOOo0O . set_action = i11II
   if 54 - 54: O0
  if ( Oo00o0oOooO == "set-record-ttl" ) :
   oo00ooOOOo0O . set_record_ttl = int ( i11II )
   if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
  if ( Oo00o0oOooO == "set-instance-id" ) :
   if ( oo00ooOOOo0O . set_source_eid == None ) :
    oo00ooOOOo0O . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
   if ( oo00ooOOOo0O . set_dest_eid == None ) :
    oo00ooOOOo0O . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 92 - 92: ooOoO0o - iII111i
   i1Ii1I1iii = int ( i11II )
   oo00ooOOOo0O . set_source_eid . instance_id = i1Ii1I1iii
   oo00ooOOOo0O . set_dest_eid . instance_id = i1Ii1I1iii
   if 69 - 69: iII111i
  if ( Oo00o0oOooO == "set-source-eid" ) :
   if ( oo00ooOOOo0O . set_source_eid == None ) :
    oo00ooOOOo0O . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
   oo00ooOOOo0O . set_source_eid . store_prefix ( i11II )
   if ( i1Ii1I1iii != None ) : oo00ooOOOo0O . set_source_eid . instance_id = i1Ii1I1iii
   if 63 - 63: oO0o * OoO0O00 * oO0o
  if ( Oo00o0oOooO == "set-destination-eid" ) :
   if ( oo00ooOOOo0O . set_dest_eid == None ) :
    oo00ooOOOo0O . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 31 - 31: Oo0Ooo
   oo00ooOOOo0O . set_dest_eid . store_prefix ( i11II )
   if ( i1Ii1I1iii != None ) : oo00ooOOOo0O . set_dest_eid . instance_id = i1Ii1I1iii
   if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
  if ( Oo00o0oOooO == "set-rloc-address" ) :
   oo00ooOOOo0O . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   oo00ooOOOo0O . set_rloc_address . store_address ( i11II )
   if 67 - 67: I1Ii111 . I1ii11iIi11i
  if ( Oo00o0oOooO == "set-rloc-record-name" ) :
   oo00ooOOOo0O . set_rloc_record_name = i11II
   if 2 - 2: O0 + I1Ii111
  if ( Oo00o0oOooO == "set-elp-name" ) :
   oo00ooOOOo0O . set_elp_name = i11II
   if 82 - 82: Ii1I / iII111i
  if ( Oo00o0oOooO == "set-geo-name" ) :
   oo00ooOOOo0O . set_geo_name = i11II
   if 13 - 13: I11i + iII111i
  if ( Oo00o0oOooO == "set-rle-name" ) :
   oo00ooOOOo0O . set_rle_name = i11II
   if 54 - 54: I1ii11iIi11i - I1IiiI . Ii1I
  if ( Oo00o0oOooO == "set-json-name" ) :
   oo00ooOOOo0O . set_json_name = i11II
   if 59 - 59: Oo0Ooo + I1ii11iIi11i
  if ( Oo00o0oOooO == "policy-name" ) :
   oo00ooOOOo0O . policy_name = i11II
   if 87 - 87: ooOoO0o * OoooooooOO + OoO0O00 + oO0o - I1Ii111
   if 70 - 70: i1IIi . Ii1I / Ii1I
   if 9 - 9: iII111i + I1Ii111 + iII111i % ooOoO0o + i11iIiiIii + i11iIiiIii
   if 45 - 45: i1IIi + I1ii11iIi11i
   if 49 - 49: i11iIiiIii . I1ii11iIi11i
   if 91 - 91: ooOoO0o - OOooOOo - OOooOOo * o0oOOo0O0Ooo
 oo00ooOOOo0O . match_clauses = oOIII1IIii1
 oo00ooOOOo0O . save_policy ( )
 return
 if 33 - 33: II111iiii
 if 39 - 39: ooOoO0o + I11i
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
if 24 - 24: o0oOOo0O0Ooo
if 5 - 5: i11iIiiIii - oO0o + o0oOOo0O0Ooo % ooOoO0o
if 63 - 63: oO0o
if 7 - 7: IiII / i11iIiiIii - OOooOOo
if 9 - 9: II111iiii + i11iIiiIii % I1Ii111 - Oo0Ooo * OOooOOo
if 55 - 55: I1Ii111 + ooOoO0o
if 58 - 58: iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
 o0oOoOOooOo = command
 if ( interface != "" ) : o0oOoOOooOo = interface + ": " + o0oOoOOooOo
 lprint ( "Send CLI command '{}' to hardware" . format ( o0oOoOOooOo ) )
 if 67 - 67: oO0o % i11iIiiIii - I1IiiI % iIii1I11I1II1 . iIii1I11I1II1
 commands = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 73 - 73: OOooOOo % OoO0O00 + IiII . Ii1I * I1Ii111
 os . system ( "FastCli -c '{}'" . format ( commands ) )
 return
 if 26 - 26: iII111i - I11i
 if 5 - 5: OoO0O00 % iII111i + i1IIi - OoooooooOO
 if 16 - 16: i1IIi
 if 86 - 86: OoOoOO00 - iII111i - Oo0Ooo
 if 33 - 33: Ii1I - OoO0O00
 if 15 - 15: O0 . iIii1I11I1II1 - I1Ii111 + O0 + ooOoO0o / I1IiiI
 if 8 - 8: iII111i % O0 - OoOoOO00
def lisp_arista_is_alive ( prefix ) :
 ooO0ooooO = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 Oo0Ooo0O0 = commands . getoutput ( "FastCli -c '{}'" . format ( ooO0ooooO ) )
 if 49 - 49: oO0o - OOooOOo / Ii1I / I1Ii111 . o0oOOo0O0Ooo . iII111i
 if 58 - 58: IiII + Ii1I
 if 89 - 89: Ii1I / Oo0Ooo * o0oOOo0O0Ooo / OoO0O00 + I11i
 if 4 - 4: I11i
 Oo0Ooo0O0 = Oo0Ooo0O0 . split ( "\n" ) [ 1 ]
 OOoO0OOoOoO0 = Oo0Ooo0O0 . split ( " " )
 OOoO0OOoOoO0 = OOoO0OOoOoO0 [ - 1 ] . replace ( "\r" , "" )
 if 50 - 50: IiII - Ii1I % iIii1I11I1II1
 if 60 - 60: o0oOOo0O0Ooo - Oo0Ooo
 if 92 - 92: OoOoOO00 + IiII . OoO0O00 % iII111i / II111iiii / I11i
 if 62 - 62: I1ii11iIi11i
 return ( OOoO0OOoOoO0 == "Y" )
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
 if 47 - 47: II111iiii * I1ii11iIi11i
 if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
 if 71 - 71: I1ii11iIi11i * i1IIi
 if 67 - 67: I1ii11iIi11i % OoOoOO00 . iII111i / Ii1I . I1IiiI
 if 48 - 48: IiII + II111iiii . I1IiiI % o0oOOo0O0Ooo
 if 57 - 57: OOooOOo . I11i % OoOoOO00
 if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
 if 78 - 78: iII111i - OOooOOo / I1Ii111
 if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
def lisp_program_vxlan_hardware ( mc ) :
 if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
 if 17 - 17: OoooooooOO % OoooooooOO + Oo0Ooo + I1Ii111
 if 56 - 56: I11i % OoOoOO00 - OoO0O00
 if 31 - 31: iII111i % i11iIiiIii - Ii1I / OOooOOo - I1Ii111
 if 60 - 60: o0oOOo0O0Ooo + Oo0Ooo . O0
 if 51 - 51: i11iIiiIii / iIii1I11I1II1 . I1IiiI - Ii1I * I1Ii111 . iII111i
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 72 - 72: Ii1I . I11i / i1IIi % i1IIi + I1ii11iIi11i
 if 56 - 56: OoO0O00 - OoOoOO00 - II111iiii * o0oOOo0O0Ooo
 if 87 - 87: ooOoO0o * OoooooooOO % O0 * OoooooooOO . I1Ii111
 if 66 - 66: OoO0O00 * Ii1I . OoO0O00
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 90 - 90: II111iiii % Ii1I
 if 67 - 67: I1IiiI - I11i - i11iIiiIii
 if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
 if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
 OO0o0O0O0o0o = mc . eid . print_prefix_no_iid ( )
 oOO = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
 if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
 if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
 if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
 I1i1I1IIiI111 = commands . getoutput ( "ip route get {} | egrep vlan4094" . format ( OO0o0O0O0o0o ) )
 if 24 - 24: iII111i - Ii1I - I11i
 if ( I1i1I1IIiI111 != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( OO0o0O0O0o0o , False ) , I1i1I1IIiI111 ) )
  if 70 - 70: i11iIiiIii . II111iiii - IiII - O0 . O0 / IiII
  return
  if 3 - 3: Oo0Ooo
  if 10 - 10: IiII % OoO0O00 / OoO0O00 . ooOoO0o . IiII
  if 38 - 38: I11i / iII111i - iIii1I11I1II1 + ooOoO0o + o0oOOo0O0Ooo . I1IiiI
  if 96 - 96: IiII - I1IiiI . I1ii11iIi11i . O0
  if 82 - 82: Ii1I % o0oOOo0O0Ooo . Oo0Ooo * OoO0O00 - Oo0Ooo
  if 49 - 49: i11iIiiIii - I1IiiI * IiII
  if 92 - 92: Oo0Ooo % O0 * Oo0Ooo
 Ii1i111I11I1I = commands . getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( Ii1i111I11I1I . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 43 - 43: O0 % OoooooooOO + iIii1I11I1II1 % i11iIiiIii % iIii1I11I1II1
 if ( Ii1i111I11I1I . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 25 - 25: OoO0O00 % II111iiii % IiII - OoOoOO00
 ii1i1iIi1Ii1I1 = commands . getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( ii1i1iIi1Ii1I1 == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 100 - 100: I11i % i1IIi / OoooooooOO
 ii1i1iIi1Ii1I1 = ii1i1iIi1Ii1I1 . split ( "inet " ) [ 1 ]
 ii1i1iIi1Ii1I1 = ii1i1iIi1Ii1I1 . split ( "/" ) [ 0 ]
 if 12 - 12: Ii1I . Ii1I
 if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
 if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
 if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
 if 42 - 42: i1IIi . OoO0O00 % iII111i
 if 57 - 57: I1ii11iIi11i / I1IiiI
 if 69 - 69: iII111i - iII111i . OoO0O00 / oO0o - OoO0O00 + I1Ii111
 O0OooOoOo00oo = [ ]
 o0oo0oo0 = commands . getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for oOOo0ooO0 in o0oo0oo0 :
  if ( oOOo0ooO0 . find ( "vlan4094" ) == - 1 ) : continue
  if ( oOOo0ooO0 . find ( "(incomplete)" ) == - 1 ) : continue
  I11Ii11IiiII11ii = oOOo0ooO0 . split ( " " ) [ 0 ]
  O0OooOoOo00oo . append ( I11Ii11IiiII11ii )
  if 35 - 35: o0oOOo0O0Ooo . I1Ii111
  if 18 - 18: OoooooooOO - o0oOOo0O0Ooo % i1IIi
 I11Ii11IiiII11ii = None
 oooO0oO0OO0 = ii1i1iIi1Ii1I1
 ii1i1iIi1Ii1I1 = ii1i1iIi1Ii1I1 . split ( "." )
 for IiIIi1IiiIiI in range ( 1 , 255 ) :
  ii1i1iIi1Ii1I1 [ 3 ] = str ( IiIIi1IiiIiI )
  IiiIIi1 = "." . join ( ii1i1iIi1Ii1I1 )
  if ( IiiIIi1 in O0OooOoOo00oo ) : continue
  if ( IiiIIi1 == oooO0oO0OO0 ) : continue
  I11Ii11IiiII11ii = IiiIIi1
  break
  if 28 - 28: Oo0Ooo * OoooooooOO . I1Ii111 . iIii1I11I1II1 - Oo0Ooo / OOooOOo
 if ( I11Ii11IiiII11ii == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 69 - 69: OoooooooOO
  return
  if 51 - 51: OoO0O00 + i11iIiiIii / II111iiii
  if 52 - 52: o0oOOo0O0Ooo * I1ii11iIi11i % OoOoOO00 . Ii1I . OoO0O00 * I1Ii111
  if 26 - 26: ooOoO0o % OoO0O00 * OoO0O00 * O0 . i1IIi
  if 32 - 32: i11iIiiIii
  if 43 - 43: iIii1I11I1II1 + oO0o + OoooooooOO
  if 69 - 69: Oo0Ooo - o0oOOo0O0Ooo
  if 18 - 18: OoooooooOO
 Ooooooo0 = oOO . split ( "." )
 oOooo00Oo0oo = lisp_hex_string ( Ooooooo0 [ 1 ] ) . zfill ( 2 )
 oooo = lisp_hex_string ( Ooooooo0 [ 2 ] ) . zfill ( 2 )
 i1Iii = lisp_hex_string ( Ooooooo0 [ 3 ] ) . zfill ( 2 )
 Ii = "00:00:00:{}:{}:{}" . format ( oOooo00Oo0oo , oooo , i1Iii )
 I1O0OOOoOOOO0 = "0000.00{}.{}{}" . format ( oOooo00Oo0oo , oooo , i1Iii )
 IIiiiIII11 = "arp -i vlan4094 -s {} {}" . format ( I11Ii11IiiII11ii , Ii )
 os . system ( IIiiiIII11 )
 if 78 - 78: Oo0Ooo
 if 14 - 14: OOooOOo
 if 16 - 16: iII111i
 if 63 - 63: OoOoOO00
 oooI1IIiIIi1iII = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( I1O0OOOoOOOO0 , oOO )
 if 56 - 56: iIii1I11I1II1 . Oo0Ooo / II111iiii
 lisp_send_to_arista ( oooI1IIiIIi1iII , None )
 if 75 - 75: Oo0Ooo - I1Ii111 * IiII
 if 2 - 2: I1Ii111 - O0 % OoooooooOO + I1Ii111
 if 1 - 1: I1Ii111 % OoooooooOO + OoooooooOO - I1IiiI % I1IiiI
 if 51 - 51: iIii1I11I1II1 / I1IiiI
 if 27 - 27: O0 . o0oOOo0O0Ooo / ooOoO0o / OoooooooOO % Ii1I
 I1I1I = "ip route add {} via {}" . format ( OO0o0O0O0o0o , I11Ii11IiiII11ii )
 os . system ( I1I1I )
 if 45 - 45: I1Ii111 % I1Ii111 * O0 % i11iIiiIii - ooOoO0o
 lprint ( "Hardware programmed with commands:" )
 I1I1I = I1I1I . replace ( OO0o0O0O0o0o , green ( OO0o0O0O0o0o , False ) )
 lprint ( "  " + I1I1I )
 lprint ( "  " + IIiiiIII11 )
 oooI1IIiIIi1iII = oooI1IIiIIi1iII . replace ( oOO , red ( oOO , False ) )
 lprint ( "  " + oooI1IIiIIi1iII )
 return
 if 78 - 78: IiII - i1IIi - i11iIiiIii * o0oOOo0O0Ooo / I1IiiI
 if 98 - 98: i11iIiiIii / ooOoO0o * OOooOOo
 if 34 - 34: I1IiiI * oO0o + i1IIi * Oo0Ooo / ooOoO0o . Ii1I
 if 47 - 47: I11i * oO0o % I11i * i1IIi * II111iiii
 if 3 - 3: Ii1I % IiII + O0 % iIii1I11I1II1
 if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
 if 64 - 64: iII111i - Oo0Ooo
def lisp_clear_hardware_walk ( mc , parms ) :
 iIiIIi1i = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( iIiIIi1i ) )
 return ( [ True , None ] )
 if 73 - 73: iIii1I11I1II1 * I1Ii111 * OoO0O00
 if 68 - 68: ooOoO0o * Ii1I / I1ii11iIi11i * OoooooooOO + OoooooooOO . OoooooooOO
 if 50 - 50: I1IiiI % o0oOOo0O0Ooo
 if 1 - 1: II111iiii
 if 22 - 22: I1Ii111 + iII111i
 if 50 - 50: iII111i % OoOoOO00 - II111iiii + II111iiii / OoO0O00
 if 69 - 69: Ii1I * II111iiii
 if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list , lisp_gleaned_groups
 global lisp_no_map_request_rate_limit
 if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
 O00o000oOo0OO = bold ( "User cleared" , False )
 I1I1 = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( O00o000oOo0OO , I1I1 ) )
 if 22 - 22: OoooooooOO
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 86 - 86: II111iiii % Oo0Ooo % I1IiiI / IiII * Oo0Ooo
 lisp_map_cache = lisp_cache ( )
 if 67 - 67: i11iIiiIii % OoOoOO00 - oO0o
 if 28 - 28: I1Ii111 . I1ii11iIi11i % Ii1I . i1IIi + I11i
 if 84 - 84: Ii1I % oO0o / I1ii11iIi11i . OoooooooOO % I1IiiI
 if 28 - 28: I1Ii111 / IiII + oO0o + O0
 lisp_no_map_request_rate_limit = lisp_get_timestamp ( )
 if 52 - 52: I1IiiI - i11iIiiIii
 if 15 - 15: I11i / OOooOOo % OoO0O00 - O0 + Oo0Ooo
 if 32 - 32: IiII
 if 53 - 53: I1ii11iIi11i
 if 85 - 85: iIii1I11I1II1 - II111iiii + Ii1I
 lisp_rloc_probe_list = { }
 if 3 - 3: ooOoO0o - I1Ii111
 if 97 - 97: OOooOOo
 if 87 - 87: iII111i
 if 73 - 73: II111iiii
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 2 - 2: i1IIi % iII111i . oO0o / II111iiii * I1IiiI
 if 17 - 17: O0 + iII111i + oO0o / iIii1I11I1II1 % oO0o
 if 81 - 81: iII111i * i11iIiiIii % O0 / iIii1I11I1II1 . OoO0O00
 if 24 - 24: I1ii11iIi11i + OoOoOO00 % ooOoO0o % I1IiiI * I1Ii111 - o0oOOo0O0Ooo
 if 95 - 95: Oo0Ooo * IiII - I1IiiI
 lisp_rtr_list = { }
 if 37 - 37: Oo0Ooo - oO0o / I1ii11iIi11i . o0oOOo0O0Ooo * Ii1I
 if 95 - 95: i11iIiiIii - ooOoO0o / I11i / I1Ii111
 if 59 - 59: iII111i
 if 59 - 59: Oo0Ooo - IiII
 lisp_gleaned_groups = { }
 if 6 - 6: OOooOOo - I1IiiI . IiII
 if 40 - 40: II111iiii
 if 13 - 13: OoOoOO00
 if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
 lisp_process_data_plane_restart ( True )
 return
 if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
 if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
 if 46 - 46: OOooOOo
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
 OO0oOOOoO00 = lisp_myrlocs [ 0 ]
 if 43 - 43: II111iiii % II111iiii - OoooooooOO
 if 4 - 4: iIii1I11I1II1 / OoooooooOO * OoooooooOO
 if 88 - 88: Ii1I % OoOoOO00
 if 66 - 66: OoooooooOO . I1Ii111 + II111iiii / I1Ii111 / I1Ii111
 if 10 - 10: i1IIi / ooOoO0o * o0oOOo0O0Ooo % i11iIiiIii - oO0o % i11iIiiIii
 IiiI1iii1iIiiI = len ( packet ) + 28
 Ooo0oO = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( IiiI1iii1iIiiI ) , 0 , 64 ,
 17 , 0 , socket . htonl ( OO0oOOOoO00 . address ) , socket . htonl ( rloc . address ) )
 Ooo0oO = lisp_ip_checksum ( Ooo0oO )
 if 27 - 27: I1Ii111
 o0oOo00 = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( IiiI1iii1iIiiI - 20 ) , 0 )
 if 86 - 86: i1IIi % OoO0O00 - OoooooooOO
 if 63 - 63: o0oOOo0O0Ooo . iIii1I11I1II1 % IiII * i11iIiiIii
 if 70 - 70: iIii1I11I1II1
 if 12 - 12: OoOoOO00 / o0oOOo0O0Ooo - I1ii11iIi11i + oO0o + O0
 packet = lisp_packet ( Ooo0oO + o0oOo00 + packet )
 if 9 - 9: I1ii11iIi11i * OoooooooOO . O0 . ooOoO0o * i11iIiiIii / i1IIi
 if 38 - 38: OoOoOO00 . OoooooooOO % I1ii11iIi11i . oO0o % oO0o
 if 80 - 80: i11iIiiIii / OoOoOO00 . OOooOOo . iIii1I11I1II1
 if 81 - 81: I1ii11iIi11i * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( OO0oOOOoO00 )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( OO0oOOOoO00 )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 64 - 64: Oo0Ooo . I1ii11iIi11i / ooOoO0o % oO0o . iIii1I11I1II1
 o0oooOoOoOo = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  o00oOOo = " {}" . format ( blue ( nat_info . hostname , False ) )
  O0OoO0ooo0Ooo = bold ( "RLOC-probe request" , False )
 else :
  o00oOOo = ""
  O0OoO0ooo0Ooo = bold ( "RLOC-probe reply" , False )
  if 84 - 84: II111iiii . oO0o * O0 / iII111i + OoooooooOO
  if 99 - 99: I1ii11iIi11i . oO0o + Oo0Ooo + I1ii11iIi11i / I1Ii111 . I1ii11iIi11i
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( O0OoO0ooo0Ooo , o0oooOoOoOo , o00oOOo , packet . encap_port ) )
 if 95 - 95: OoOoOO00 * iIii1I11I1II1 / OoooooooOO % i1IIi
 if 91 - 91: OOooOOo - OoOoOO00
 if 58 - 58: II111iiii . OOooOOo % II111iiii * oO0o % OoO0O00 % I11i
 if 71 - 71: Ii1I * II111iiii * I1IiiI
 if 22 - 22: oO0o
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 96 - 96: ooOoO0o * iII111i . IiII
 oO00OO00 = lisp_sockets [ 3 ]
 packet . send_packet ( oO00OO00 , packet . outer_dest )
 del ( packet )
 return
 if 35 - 35: oO0o
 if 8 - 8: IiII / o0oOOo0O0Ooo
 if 75 - 75: I1IiiI + oO0o
 if 50 - 50: iIii1I11I1II1 / I1IiiI / O0 . I1IiiI
 if 35 - 35: I1Ii111
 if 80 - 80: I1Ii111 * I11i + O0 - OOooOOo . ooOoO0o - i11iIiiIii
 if 49 - 49: iIii1I11I1II1 + iIii1I11I1II1 - I1ii11iIi11i % o0oOOo0O0Ooo - i11iIiiIii
 if 52 - 52: I1Ii111 . o0oOOo0O0Ooo / iIii1I11I1II1 - I11i
def lisp_get_default_route_next_hops ( ) :
 if 23 - 23: i11iIiiIii / OoooooooOO + I1ii11iIi11i + O0 + I1ii11iIi11i / i11iIiiIii
 if 14 - 14: OoOoOO00 . II111iiii / iII111i / oO0o - oO0o
 if 12 - 12: O0
 if 77 - 77: oO0o % o0oOOo0O0Ooo % iII111i
 if ( lisp_is_macos ( ) ) :
  ooO0ooooO = "route -n get default"
  IIoooo0OoOo = commands . getoutput ( ooO0ooooO ) . split ( "\n" )
  O0OOOoooo0o = II1i = None
  for OOO000 in IIoooo0OoOo :
   if ( OOO000 . find ( "gateway: " ) != - 1 ) : O0OOOoooo0o = OOO000 . split ( ": " ) [ 1 ]
   if ( OOO000 . find ( "interface: " ) != - 1 ) : II1i = OOO000 . split ( ": " ) [ 1 ]
   if 10 - 10: OoO0O00 - I1IiiI . OOooOOo . I1IiiI . OoooooooOO * Ii1I
  return ( [ [ II1i , O0OOOoooo0o ] ] )
  if 97 - 97: i1IIi / i1IIi + I1IiiI % oO0o - iIii1I11I1II1
  if 55 - 55: OoooooooOO % II111iiii - o0oOOo0O0Ooo
  if 86 - 86: II111iiii - OOooOOo + o0oOOo0O0Ooo
  if 26 - 26: oO0o / I1ii11iIi11i - oO0o
  if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
 ooO0ooooO = "ip route | egrep 'default via'"
 Oo0oo0Ooo = commands . getoutput ( ooO0ooooO ) . split ( "\n" )
 if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
 OOOoo0000Oo = [ ]
 for I1i1I1IIiI111 in Oo0oo0Ooo :
  if ( I1i1I1IIiI111 . find ( " metric " ) != - 1 ) : continue
  O0OOOO0o0O = I1i1I1IIiI111 . split ( " " )
  try :
   o0oo00oo00o = O0OOOO0o0O . index ( "via" ) + 1
   if ( o0oo00oo00o >= len ( O0OOOO0o0O ) ) : continue
   Ii11iI1II1iI = O0OOOO0o0O . index ( "dev" ) + 1
   if ( Ii11iI1II1iI >= len ( O0OOOO0o0O ) ) : continue
  except :
   continue
   if 28 - 28: ooOoO0o . o0oOOo0O0Ooo . OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
   if 91 - 91: ooOoO0o
  OOOoo0000Oo . append ( [ O0OOOO0o0O [ Ii11iI1II1iI ] , O0OOOO0o0O [ o0oo00oo00o ] ] )
  if 47 - 47: II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
 return ( OOOoo0000Oo )
 if 9 - 9: O0 + IiII
 if 69 - 69: I1IiiI
 if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
 if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
 if 86 - 86: ooOoO0o * OoOoOO00 + oO0o / II111iiii % OOooOOo
 if 89 - 89: O0 * Ii1I / OoO0O00 / OoOoOO00 % iII111i * iIii1I11I1II1
 if 72 - 72: iIii1I11I1II1 / iIii1I11I1II1 * I11i
def lisp_get_host_route_next_hop ( rloc ) :
 ooO0ooooO = "ip route | egrep '{} via'" . format ( rloc )
 I1i1I1IIiI111 = commands . getoutput ( ooO0ooooO ) . split ( " " )
 if 19 - 19: I1ii11iIi11i
 try : ooo = I1i1I1IIiI111 . index ( "via" ) + 1
 except : return ( None )
 if 42 - 42: OoOoOO00 / IiII
 if ( ooo >= len ( I1i1I1IIiI111 ) ) : return ( None )
 return ( I1i1I1IIiI111 [ ooo ] )
 if 65 - 65: ooOoO0o - ooOoO0o * OoO0O00
 if 99 - 99: I11i % ooOoO0o . I1Ii111
 if 34 - 34: ooOoO0o + oO0o + II111iiii . I1Ii111 . i1IIi
 if 14 - 14: OoO0O00 . ooOoO0o - i1IIi * I1IiiI
 if 24 - 24: iIii1I11I1II1 / I1Ii111
 if 16 - 16: OoOoOO00 * I1Ii111 - I1IiiI / I1Ii111
 if 64 - 64: I1ii11iIi11i . i1IIi % II111iiii % Oo0Ooo + oO0o - I1IiiI
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 i1iiiIi = "none" if nh == None else nh
 if 24 - 24: IiII . II111iiii . II111iiii . OoOoOO00 . i11iIiiIii
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , i1iiiIi ) )
 if 11 - 11: Ii1I
 if ( nh == None ) :
  ii1iIiIIi = "ip route {} {}/32" . format ( install , dest )
 else :
  ii1iIiIIi = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
 os . system ( ii1iIiIIi )
 return
 if 44 - 44: iII111i
 if 56 - 56: II111iiii / Oo0Ooo % IiII * II111iiii - iIii1I11I1II1 + ooOoO0o
 if 33 - 33: o0oOOo0O0Ooo . I11i / I1IiiI
 if 29 - 29: o0oOOo0O0Ooo - ooOoO0o
 if 59 - 59: I11i / IiII * OoO0O00 / IiII . I1Ii111
 if 82 - 82: OOooOOo . iIii1I11I1II1 + I1Ii111
 if 14 - 14: IiII . i11iIiiIii
 if 17 - 17: ooOoO0o % ooOoO0o * oO0o
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 8 - 8: ooOoO0o + OoO0O00 . II111iiii / iIii1I11I1II1 - OOooOOo
 OOO000 = open ( lisp_checkpoint_filename , "w" )
 for i1ii1i1Ii11 in checkpoint_list :
  OOO000 . write ( i1ii1i1Ii11 + "\n" )
  if 87 - 87: iIii1I11I1II1 . IiII % I1IiiI . OoO0O00 - I1Ii111
 OOO000 . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 53 - 53: I1Ii111 % i11iIiiIii
 if 99 - 99: I1IiiI - i1IIi * i11iIiiIii + OoO0O00
 if 80 - 80: o0oOOo0O0Ooo . I11i % iIii1I11I1II1 + OoOoOO00
 if 87 - 87: I1Ii111 + II111iiii / I1ii11iIi11i + OoOoOO00
 if 71 - 71: I1IiiI + iIii1I11I1II1 + O0 * iII111i % IiII
 if 42 - 42: OOooOOo - I1ii11iIi11i
 if 93 - 93: I1Ii111 + OOooOOo % ooOoO0o / I1Ii111 % OOooOOo . IiII
 if 37 - 37: iII111i * oO0o / oO0o / Ii1I % I11i
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 12 - 12: i11iIiiIii
 OOO000 = open ( lisp_checkpoint_filename , "r" )
 if 62 - 62: oO0o + OOooOOo + oO0o + I1IiiI
 I1I1 = 0
 for i1ii1i1Ii11 in OOO000 :
  I1I1 += 1
  oOo = i1ii1i1Ii11 . split ( " rloc " )
  ooOOo = [ ] if ( oOo [ 1 ] in [ "native-forward\n" , "\n" ] ) else oOo [ 1 ] . split ( ", " )
  if 10 - 10: IiII - Oo0Ooo % ooOoO0o
  if 38 - 38: oO0o * o0oOOo0O0Ooo . I11i % II111iiii / I11i % Ii1I
  Oo = [ ]
  for oOO in ooOOo :
   oo0OOOoO0OoO = lisp_rloc ( False )
   O0OOOO0o0O = oOO . split ( " " )
   oo0OOOoO0OoO . rloc . store_address ( O0OOOO0o0O [ 0 ] )
   oo0OOOoO0OoO . priority = int ( O0OOOO0o0O [ 1 ] )
   oo0OOOoO0OoO . weight = int ( O0OOOO0o0O [ 2 ] )
   Oo . append ( oo0OOOoO0OoO )
   if 19 - 19: II111iiii / i11iIiiIii * II111iiii + OoOoOO00 - OoOoOO00
   if 7 - 7: OoOoOO00 - OoO0O00 % OoOoOO00 . I1ii11iIi11i % Oo0Ooo * iII111i
  I1iOo0 = lisp_mapping ( "" , "" , Oo )
  if ( I1iOo0 != None ) :
   I1iOo0 . eid . store_prefix ( oOo [ 0 ] )
   I1iOo0 . checkpoint_entry = True
   I1iOo0 . map_cache_ttl = LISP_NMR_TTL * 60
   if ( Oo == [ ] ) : I1iOo0 . action = LISP_NATIVE_FORWARD_ACTION
   I1iOo0 . add_cache ( )
   continue
   if 90 - 90: IiII - OOooOOo + iIii1I11I1II1
   if 88 - 88: ooOoO0o . o0oOOo0O0Ooo . OOooOOo - I11i
  I1I1 -= 1
  if 76 - 76: IiII % I1IiiI . iII111i
  if 5 - 5: ooOoO0o . oO0o - OoOoOO00 - OoooooooOO
 OOO000 . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , I1I1 , lisp_checkpoint_filename ) )
 return
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
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 91 - 91: O0
 i1ii1i1Ii11 = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 13 - 13: o0oOOo0O0Ooo
 for oo0OOOoO0OoO in mc . rloc_set :
  if ( oo0OOOoO0OoO . rloc . is_null ( ) ) : continue
  i1ii1i1Ii11 += "{} {} {}, " . format ( oo0OOOoO0OoO . rloc . print_address_no_iid ( ) ,
 oo0OOOoO0OoO . priority , oo0OOOoO0OoO . weight )
  if 15 - 15: iIii1I11I1II1 * Oo0Ooo . iIii1I11I1II1 . Ii1I % iII111i - i11iIiiIii
  if 77 - 77: ooOoO0o - o0oOOo0O0Ooo * OoOoOO00 % oO0o
 if ( mc . rloc_set != [ ] ) :
  i1ii1i1Ii11 = i1ii1i1Ii11 [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  i1ii1i1Ii11 += "native-forward"
  if 4 - 4: i11iIiiIii + OoOoOO00
  if 45 - 45: ooOoO0o / OoooooooOO . Oo0Ooo
 checkpoint_list . append ( i1ii1i1Ii11 )
 return
 if 35 - 35: i11iIiiIii / o0oOOo0O0Ooo / oO0o / I11i . O0
 if 53 - 53: i1IIi
 if 51 - 51: OoOoOO00 / iIii1I11I1II1 . oO0o - I1ii11iIi11i - OOooOOo
 if 90 - 90: i1IIi / oO0o * I1Ii111 + II111iiii % I11i
 if 41 - 41: o0oOOo0O0Ooo - II111iiii . ooOoO0o . iII111i - ooOoO0o / iII111i
 if 59 - 59: O0 / II111iiii * II111iiii - ooOoO0o
 if 63 - 63: I1ii11iIi11i * IiII % OoO0O00 . OoOoOO00 - II111iiii % IiII
def lisp_check_dp_socket ( ) :
 i1III1iiiII1II = lisp_ipc_dp_socket_name
 if ( os . path . exists ( i1III1iiiII1II ) == False ) :
  OO0OoOoo0 = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( i1III1iiiII1II , OO0OoOoo0 ) )
  return ( False )
  if 19 - 19: oO0o
 return ( True )
 if 97 - 97: IiII
 if 36 - 36: II111iiii
 if 83 - 83: I11i . ooOoO0o
 if 57 - 57: IiII
 if 34 - 34: I1ii11iIi11i + i11iIiiIii - I1ii11iIi11i / OoOoOO00 + i1IIi . i11iIiiIii
 if 48 - 48: I1ii11iIi11i % OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii / OoOoOO00
 if 73 - 73: OoOoOO00 + OOooOOo * II111iiii . OOooOOo % I1Ii111 % oO0o
def lisp_write_to_dp_socket ( entry ) :
 try :
  oO00O0oO0O = json . dumps ( entry )
  IiIiII1iI = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( IiIiII1iI , oO00O0oO0O ) )
  lisp_ipc_dp_socket . sendto ( oO00O0oO0O , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( oO00O0oO0O ) )
  if 89 - 89: Ii1I - OOooOOo / ooOoO0o - IiII + iIii1I11I1II1 + OoO0O00
 return
 if 40 - 40: OoO0O00
 if 69 - 69: iIii1I11I1II1 + OoOoOO00 * O0 - OoooooooOO / OOooOOo
 if 52 - 52: IiII % OOooOOo . II111iiii + IiII + i11iIiiIii * iIii1I11I1II1
 if 21 - 21: OoooooooOO + iIii1I11I1II1 + OoOoOO00 . II111iiii . Ii1I / iII111i
 if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
 if 70 - 70: oO0o - I1IiiI + Ii1I
 if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
 if 37 - 37: o0oOOo0O0Ooo
 if 57 - 57: iII111i / i1IIi / i1IIi + IiII
def lisp_write_ipc_keys ( rloc ) :
 oo0o00OO = rloc . rloc . print_address_no_iid ( )
 Oo0O00O = rloc . translated_port
 if ( Oo0O00O != 0 ) : oo0o00OO += ":" + str ( Oo0O00O )
 if ( lisp_rloc_probe_list . has_key ( oo0o00OO ) == False ) : return
 if 75 - 75: IiII / O0
 for O0OOOO0o0O , oOo , i11ii in lisp_rloc_probe_list [ oo0o00OO ] :
  I1iOo0 = lisp_map_cache . lookup_cache ( oOo , True )
  if ( I1iOo0 == None ) : continue
  lisp_write_ipc_map_cache ( True , I1iOo0 )
  if 72 - 72: I11i
 return
 if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
 if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
 if 23 - 23: OoOoOO00 . oO0o - iII111i
 if 27 - 27: Oo0Ooo * OOooOOo - OoOoOO00
 if 1 - 1: II111iiii * i11iIiiIii . OoooooooOO
 if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
 if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 88 - 88: I1Ii111
 if 16 - 16: Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . OoooooooOO * OoO0O00
 if 50 - 50: II111iiii + I11i . OoooooooOO . I1Ii111 - OOooOOo
 if 83 - 83: oO0o
 IiI1III = "add" if add_or_delete else "delete"
 i1ii1i1Ii11 = { "type" : "map-cache" , "opcode" : IiI1III }
 if 100 - 100: I1Ii111 + o0oOOo0O0Ooo * oO0o / oO0o . oO0o + iII111i
 OO00o0oO0O00 = ( mc . group . is_null ( ) == False )
 if ( OO00o0oO0O00 ) :
  i1ii1i1Ii11 [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  i1ii1i1Ii11 [ "rles" ] = [ ]
 else :
  i1ii1i1Ii11 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  i1ii1i1Ii11 [ "rlocs" ] = [ ]
  if 71 - 71: II111iiii + iII111i + O0 % Oo0Ooo / I1IiiI
 i1ii1i1Ii11 [ "instance-id" ] = str ( mc . eid . instance_id )
 if 52 - 52: Oo0Ooo . I1Ii111 * i1IIi / Oo0Ooo / OoO0O00
 if ( OO00o0oO0O00 ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for i1iiiIIi11 in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    IiiIIi1 = i1iiiIIi11 . address . print_address_no_iid ( )
    Oo0O00O = str ( 4341 ) if i1iiiIIi11 . translated_port == 0 else str ( i1iiiIIi11 . translated_port )
    if 29 - 29: iII111i
    O0OOOO0o0O = { "rle" : IiiIIi1 , "port" : Oo0O00O }
    iIIi1oOoO0OoooOoOO , oO0OOo0O0 = i1iiiIIi11 . get_encap_keys ( )
    O0OOOO0o0O = lisp_build_json_keys ( O0OOOO0o0O , iIIi1oOoO0OoooOoOO , oO0OOo0O0 , "encrypt-key" )
    i1ii1i1Ii11 [ "rles" ] . append ( O0OOOO0o0O )
    if 81 - 81: i11iIiiIii / I1ii11iIi11i + i1IIi / I11i * I1IiiI
    if 42 - 42: i1IIi . I1Ii111 - ooOoO0o + I11i / oO0o
 else :
  for oOO in mc . rloc_set :
   if ( oOO . rloc . is_ipv4 ( ) == False and oOO . rloc . is_ipv6 ( ) == False ) :
    continue
    if 60 - 60: i1IIi + OoooooooOO % i11iIiiIii / IiII % Oo0Ooo + I1IiiI
   if ( oOO . up_state ( ) == False ) : continue
   if 87 - 87: Ii1I % OoooooooOO % I1Ii111 * i11iIiiIii * OoOoOO00
   Oo0O00O = str ( 4341 ) if oOO . translated_port == 0 else str ( oOO . translated_port )
   if 78 - 78: I11i
   O0OOOO0o0O = { "rloc" : oOO . rloc . print_address_no_iid ( ) , "priority" :
 str ( oOO . priority ) , "weight" : str ( oOO . weight ) , "port" :
 Oo0O00O }
   iIIi1oOoO0OoooOoOO , oO0OOo0O0 = oOO . get_encap_keys ( )
   O0OOOO0o0O = lisp_build_json_keys ( O0OOOO0o0O , iIIi1oOoO0OoooOoOO , oO0OOo0O0 , "encrypt-key" )
   i1ii1i1Ii11 [ "rlocs" ] . append ( O0OOOO0o0O )
   if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
   if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
   if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
 if ( dont_send == False ) : lisp_write_to_dp_socket ( i1ii1i1Ii11 )
 return ( i1ii1i1Ii11 )
 if 53 - 53: I1IiiI % I1IiiI
 if 80 - 80: OoO0O00 - i11iIiiIii / iII111i * I1ii11iIi11i / I1IiiI - I1Ii111
 if 85 - 85: IiII
 if 72 - 72: iII111i * OoOoOO00
 if 65 - 65: iIii1I11I1II1 / iIii1I11I1II1 % O0 / II111iiii . OOooOOo . O0
 if 65 - 65: I11i
 if 35 - 35: o0oOOo0O0Ooo - i11iIiiIii
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 78 - 78: ooOoO0o - II111iiii - i1IIi
 if 18 - 18: OoooooooOO % OoOoOO00 - IiII / oO0o . OOooOOo . I1IiiI
 if 77 - 77: I1ii11iIi11i . OoO0O00 / OoOoOO00 / O0
 if 67 - 67: ooOoO0o % I11i % oO0o
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 74 - 74: II111iiii
 iIIi1oOoO0OoooOoOO = keys [ 1 ] . encrypt_key
 oO0OOo0O0 = keys [ 1 ] . icv_key
 if 44 - 44: Oo0Ooo + OoO0O00 + OoOoOO00 - I1IiiI
 if 68 - 68: i11iIiiIii / OOooOOo . i1IIi . i11iIiiIii . I11i
 if 56 - 56: iIii1I11I1II1 - II111iiii * i1IIi / Ii1I
 if 65 - 65: OOooOOo / I1IiiI . OoooooooOO + I1IiiI + OoooooooOO + i11iIiiIii
 IiI11i = rloc_addr . split ( ":" )
 if ( len ( IiI11i ) == 1 ) :
  i1ii1i1Ii11 = { "type" : "decap-keys" , "rloc" : IiI11i [ 0 ] }
 else :
  i1ii1i1Ii11 = { "type" : "decap-keys" , "rloc" : IiI11i [ 0 ] , "port" : IiI11i [ 1 ] }
  if 10 - 10: oO0o - I11i
 i1ii1i1Ii11 = lisp_build_json_keys ( i1ii1i1Ii11 , iIIi1oOoO0OoooOoOO , oO0OOo0O0 , "decrypt-key" )
 if 1 - 1: OoOoOO00 . I1IiiI * ooOoO0o . iII111i * Oo0Ooo
 lisp_write_to_dp_socket ( i1ii1i1Ii11 )
 return
 if 16 - 16: OoooooooOO % OoO0O00 - oO0o + ooOoO0o
 if 36 - 36: OoO0O00 + ooOoO0o
 if 67 - 67: OoooooooOO * IiII - OoOoOO00 % i1IIi
 if 71 - 71: I1IiiI
 if 44 - 44: IiII + I1IiiI . Ii1I % Oo0Ooo
 if 97 - 97: O0
 if 95 - 95: OoO0O00 % iII111i / I1IiiI * OoooooooOO
 if 31 - 31: iIii1I11I1II1
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 62 - 62: o0oOOo0O0Ooo - iII111i / II111iiii . o0oOOo0O0Ooo
 entry [ "keys" ] = [ ]
 Oo000O000 = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( Oo000O000 )
 return ( entry )
 if 20 - 20: iIii1I11I1II1 % OOooOOo
 if 91 - 91: ooOoO0o
 if 96 - 96: I1IiiI . OOooOOo
 if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
 if 34 - 34: IiII % oO0o
 if 54 - 54: I1IiiI
 if 80 - 80: OoOoOO00 . I1IiiI / I1ii11iIi11i . iII111i
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 31 - 31: I11i * o0oOOo0O0Ooo
 if 17 - 17: Ii1I * iIii1I11I1II1
 if 9 - 9: o0oOOo0O0Ooo - IiII
 if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
 i1ii1i1Ii11 = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
 if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
 if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
 if 23 - 23: Ii1I % i1IIi - I1Ii111
 for iIIo00O000O in lisp_db_list :
  if ( iIIo00O000O . eid . is_ipv4 ( ) == False and iIIo00O000O . eid . is_ipv6 ( ) == False ) : continue
  OOo0oooO = { "instance-id" : str ( iIIo00O000O . eid . instance_id ) ,
 "eid-prefix" : iIIo00O000O . eid . print_prefix_no_iid ( ) }
  i1ii1i1Ii11 [ "database-mappings" ] . append ( OOo0oooO )
  if 78 - 78: I1ii11iIi11i + i11iIiiIii - Oo0Ooo
 lisp_write_to_dp_socket ( i1ii1i1Ii11 )
 if 64 - 64: i1IIi
 if 11 - 11: IiII / I1IiiI . I1IiiI
 if 87 - 87: OoooooooOO * OoO0O00 * iIii1I11I1II1
 if 16 - 16: o0oOOo0O0Ooo * I11i + OoooooooOO + O0 / iIii1I11I1II1
 if 60 - 60: Ii1I % IiII * OoooooooOO * ooOoO0o * Ii1I
 i1ii1i1Ii11 = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( i1ii1i1Ii11 )
 return
 if 8 - 8: I1Ii111 - o0oOOo0O0Ooo
 if 52 - 52: OoOoOO00 % O0 + I1ii11iIi11i . i11iIiiIii
 if 59 - 59: Ii1I - I1Ii111 . ooOoO0o - OoOoOO00 + oO0o . OoO0O00
 if 88 - 88: OOooOOo - ooOoO0o * o0oOOo0O0Ooo . OoooooooOO
 if 3 - 3: I1Ii111
 if 24 - 24: Ii1I + i11iIiiIii * I1Ii111 - OoOoOO00 / Ii1I - OoOoOO00
 if 69 - 69: I11i - I1IiiI . oO0o - OoooooooOO
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 33 - 33: o0oOOo0O0Ooo - o0oOOo0O0Ooo
 if 55 - 55: OoooooooOO / IiII + i1IIi
 if 54 - 54: ooOoO0o * Ii1I / Ii1I
 if 15 - 15: oO0o * I1Ii111
 i1ii1i1Ii11 = { "type" : "interfaces" , "interfaces" : [ ] }
 if 11 - 11: Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
 for II1i in lisp_myinterfaces . values ( ) :
  if ( II1i . instance_id == None ) : continue
  OOo0oooO = { "interface" : II1i . device ,
 "instance-id" : str ( II1i . instance_id ) }
  i1ii1i1Ii11 [ "interfaces" ] . append ( OOo0oooO )
  if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
  if 46 - 46: oO0o + OoOoOO00
 lisp_write_to_dp_socket ( i1ii1i1Ii11 )
 return
 if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
 if 59 - 59: O0
 if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
 if 17 - 17: Ii1I % I1ii11iIi11i + I11i
 if 80 - 80: i1IIi . OoooooooOO % OoooooooOO . oO0o / OOooOOo
 if 85 - 85: OOooOOo
 if 80 - 80: ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
 if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
 if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
 if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
 if 72 - 72: IiII / II111iiii
 if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
 if 21 - 21: I1ii11iIi11i
 if 60 - 60: i1IIi / OoO0O00 . Ii1I
def lisp_parse_auth_key ( value ) :
 oOoO0oOo0ooOo = value . split ( "[" )
 Ii1III1 = { }
 if ( len ( oOoO0oOo0ooOo ) == 1 ) :
  Ii1III1 [ 0 ] = value
  return ( Ii1III1 )
  if 56 - 56: I1Ii111 % II111iiii
  if 11 - 11: i11iIiiIii / OoO0O00 * OoO0O00 . I1Ii111 - OOooOOo
 for O0oOO0O00OOO0 in oOoO0oOo0ooOo :
  if ( O0oOO0O00OOO0 == "" ) : continue
  ooo = O0oOO0O00OOO0 . find ( "]" )
  I1I1I1 = O0oOO0O00OOO0 [ 0 : ooo ]
  try : I1I1I1 = int ( I1I1I1 )
  except : return
  if 12 - 12: OOooOOo . OoOoOO00 % ooOoO0o
  Ii1III1 [ I1I1I1 ] = O0oOO0O00OOO0 [ ooo + 1 : : ]
  if 100 - 100: OoOoOO00 . iII111i
 return ( Ii1III1 )
 if 50 - 50: iIii1I11I1II1 * OOooOOo . I1IiiI . OoOoOO00 - O0 + Oo0Ooo
 if 89 - 89: IiII - iII111i + IiII
 if 39 - 39: oO0o % I11i . oO0o * I11i
 if 36 - 36: i1IIi / I1ii11iIi11i * iIii1I11I1II1
 if 44 - 44: Ii1I / I1Ii111
 if 81 - 81: OoooooooOO * I1IiiI * II111iiii . Oo0Ooo
 if 28 - 28: iII111i * I1IiiI + Oo0Ooo % I1ii11iIi11i / OoooooooOO * ooOoO0o
 if 45 - 45: OoO0O00 + iIii1I11I1II1 + ooOoO0o - OoO0O00
 if 22 - 22: I1IiiI
 if 28 - 28: OoO0O00 / ooOoO0o % OoOoOO00 - Ii1I * i11iIiiIii + I1ii11iIi11i
 if 90 - 90: ooOoO0o * o0oOOo0O0Ooo + Ii1I / I11i % II111iiii
 if 59 - 59: I11i + iII111i + I11i
 if 84 - 84: I1IiiI * Ii1I . I1IiiI % OOooOOo * Ii1I % OoO0O00
 if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
 if 42 - 42: oO0o / i1IIi . IiII
 if 12 - 12: i11iIiiIii . ooOoO0o
def lisp_reassemble ( packet ) :
 oo00o00O0 = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
 if 88 - 88: OoooooooOO . I1IiiI
 if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
 if 7 - 7: i1IIi
 if ( oo00o00O0 == 0 or oo00o00O0 == 0x4000 ) : return ( packet )
 if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
 if 34 - 34: iII111i + i11iIiiIii . IiII
 if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
 if 29 - 29: II111iiii % i11iIiiIii % O0
 i11iiI = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 Ii1IIii1i111i = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 38 - 38: o0oOOo0O0Ooo * IiII
 OoOoOo00OoO = ( oo00o00O0 & 0x2000 == 0 and ( oo00o00O0 & 0x1fff ) != 0 )
 i1ii1i1Ii11 = [ ( oo00o00O0 & 0x1fff ) * 8 , Ii1IIii1i111i - 20 , packet , OoOoOo00OoO ]
 if 57 - 57: ooOoO0o
 if 35 - 35: iIii1I11I1II1 / I1IiiI / I1IiiI
 if 14 - 14: o0oOOo0O0Ooo - OoOoOO00 + oO0o
 if 88 - 88: iII111i * I11i
 if 57 - 57: o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
 if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
 if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
 if 80 - 80: II111iiii . i11iIiiIii
 if ( oo00o00O0 == 0x2000 ) :
  oo0O , O0o0o0ooO0ooo = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  oo0O = socket . ntohs ( oo0O )
  O0o0o0ooO0ooo = socket . ntohs ( O0o0o0ooO0ooo )
  if ( O0o0o0ooO0ooo not in [ 4341 , 8472 , 4789 ] and oo0O != 4341 ) :
   lisp_reassembly_queue [ i11iiI ] = [ ]
   i1ii1i1Ii11 [ 2 ] = None
   if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
   if 33 - 33: iIii1I11I1II1
   if 52 - 52: iIii1I11I1II1 + O0
   if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
   if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
   if 29 - 29: iII111i % I1Ii111
 if ( lisp_reassembly_queue . has_key ( i11iiI ) == False ) :
  lisp_reassembly_queue [ i11iiI ] = [ ]
  if 95 - 95: OOooOOo - ooOoO0o % i1IIi / O0 % I11i . IiII
  if 63 - 63: ooOoO0o
  if 22 - 22: OOooOOo . i11iIiiIii + II111iiii - Oo0Ooo % i1IIi / o0oOOo0O0Ooo
  if 90 - 90: IiII
  if 38 - 38: i1IIi / ooOoO0o / I11i * I1ii11iIi11i / II111iiii . iIii1I11I1II1
 OO0000O0o0 = lisp_reassembly_queue [ i11iiI ]
 if 2 - 2: I1Ii111 % iII111i . OoooooooOO - o0oOOo0O0Ooo
 if 30 - 30: i1IIi / I1Ii111 * oO0o - oO0o / oO0o
 if 9 - 9: IiII / o0oOOo0O0Ooo . IiII * O0 % i11iIiiIii % OoOoOO00
 if 29 - 29: I1ii11iIi11i % ooOoO0o . OOooOOo . Ii1I . IiII
 if 69 - 69: o0oOOo0O0Ooo . i11iIiiIii * I11i + IiII / I11i
 if ( len ( OO0000O0o0 ) == 1 and OO0000O0o0 [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( i11iiI ) . zfill ( 4 ) ) )
  if 66 - 66: I1ii11iIi11i % I1Ii111 - i11iIiiIii % I11i
  return ( None )
  if 62 - 62: i11iIiiIii % iIii1I11I1II1 / IiII . I1IiiI * O0
  if 17 - 17: I1ii11iIi11i - I1Ii111 % II111iiii + OOooOOo
  if 45 - 45: I1Ii111 + iII111i - iIii1I11I1II1 / Oo0Ooo
  if 92 - 92: iIii1I11I1II1 . OoO0O00 - I11i % I1ii11iIi11i / i11iIiiIii
  if 4 - 4: Oo0Ooo / I1IiiI * i1IIi . II111iiii
 OO0000O0o0 . append ( i1ii1i1Ii11 )
 OO0000O0o0 = sorted ( OO0000O0o0 )
 if 13 - 13: i1IIi
 if 39 - 39: OOooOOo
 if 73 - 73: OoO0O00 . ooOoO0o
 if 13 - 13: o0oOOo0O0Ooo - OoOoOO00
 IiiIIi1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 IiiIIi1 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 oo00o0o = IiiIIi1 . print_address_no_iid ( )
 IiiIIi1 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 o0O0OoO = IiiIIi1 . print_address_no_iid ( )
 IiiIIi1 = red ( "{} -> {}" . format ( oo00o0o , o0O0OoO ) , False )
 if 4 - 4: I1ii11iIi11i . oO0o . IiII + iIii1I11I1II1 - i1IIi
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if i1ii1i1Ii11 [ 2 ] == None else "" , IiiIIi1 , lisp_hex_string ( i11iiI ) . zfill ( 4 ) ,
 # iII111i * OoooooooOO . II111iiii
 # iII111i . OoO0O00 . i11iIiiIii / I1ii11iIi11i * Oo0Ooo
 lisp_hex_string ( oo00o00O0 ) . zfill ( 4 ) ) )
 if 38 - 38: IiII + II111iiii
 if 20 - 20: iII111i * I1IiiI * iII111i - o0oOOo0O0Ooo + i1IIi + ooOoO0o
 if 49 - 49: II111iiii * I1IiiI / oO0o
 if 50 - 50: Ii1I + O0 . I1IiiI * Oo0Ooo
 if 15 - 15: Oo0Ooo
 if ( OO0000O0o0 [ 0 ] [ 0 ] != 0 or OO0000O0o0 [ - 1 ] [ 3 ] == False ) : return ( None )
 Oooo0000O0O00 = OO0000O0o0 [ 0 ]
 for ii11I in OO0000O0o0 [ 1 : : ] :
  oo00o00O0 = ii11I [ 0 ]
  OO0 , O0o0ooo0000 = Oooo0000O0O00 [ 0 ] , Oooo0000O0O00 [ 1 ]
  if ( OO0 + O0o0ooo0000 != oo00o00O0 ) : return ( None )
  Oooo0000O0O00 = ii11I
  if 62 - 62: O0 . I11i - OoooooooOO * IiII . II111iiii
 lisp_reassembly_queue . pop ( i11iiI )
 if 38 - 38: I1IiiI + OoO0O00
 if 11 - 11: iIii1I11I1II1 + i1IIi * IiII - Oo0Ooo
 if 66 - 66: I1Ii111 . Ii1I / I1ii11iIi11i / iIii1I11I1II1 + O0 / i1IIi
 if 72 - 72: ooOoO0o . II111iiii
 if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
 packet = OO0000O0o0 [ 0 ] [ 2 ]
 for ii11I in OO0000O0o0 [ 1 : : ] : packet += ii11I [ 2 ] [ 20 : : ]
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( i11iiI ) . zfill ( 4 ) , len ( packet ) ) )
 if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
 if 18 - 18: o0oOOo0O0Ooo / OOooOOo
 if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
 if 100 - 100: O0
 if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
 IiiI1iii1iIiiI = socket . htons ( len ( packet ) )
 O0ooOoO0 = packet [ 0 : 2 ] + struct . pack ( "H" , IiiI1iii1iIiiI ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
 if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
 O0ooOoO0 = lisp_ip_checksum ( O0ooOoO0 )
 return ( O0ooOoO0 + packet [ 20 : : ] )
 if 38 - 38: Ii1I
 if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
 if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
 if 36 - 36: I1Ii111 - OoO0O00 . I1ii11iIi11i * I1ii11iIi11i
 if 9 - 9: OOooOOo - oO0o - iIii1I11I1II1 * i11iIiiIii / I11i
 if 2 - 2: i1IIi % iII111i * ooOoO0o / OoOoOO00 + Oo0Ooo
 if 59 - 59: i11iIiiIii / I1IiiI * iII111i
 if 16 - 16: i11iIiiIii * II111iiii - ooOoO0o
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 oo0o00OO = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( oo0o00OO ) ) : return ( oo0o00OO )
 if 80 - 80: iIii1I11I1II1 + iIii1I11I1II1 + I1Ii111 - IiII * iII111i - Ii1I
 oo0o00OO = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( oo0o00OO ) ) : return ( oo0o00OO )
 if 89 - 89: O0 * ooOoO0o
 if 36 - 36: I1ii11iIi11i * II111iiii * iII111i + I1IiiI + OoO0O00 + oO0o
 if 28 - 28: Ii1I - i11iIiiIii . oO0o / II111iiii
 if 82 - 82: iII111i * iII111i . IiII * II111iiii
 if 17 - 17: OoooooooOO % I1Ii111 * I1Ii111 / II111iiii . OoOoOO00 * iII111i
 for o0oo0OoOo0O in lisp_crypto_keys_by_rloc_decap :
  OO0o = o0oo0OoOo0O . split ( ":" )
  if ( len ( OO0o ) == 1 ) : continue
  OO0o = OO0o [ 0 ] if len ( OO0o ) == 2 else ":" . join ( OO0o [ 0 : - 1 ] )
  if ( OO0o == oo0o00OO ) :
   iIi11III = lisp_crypto_keys_by_rloc_decap [ o0oo0OoOo0O ]
   lisp_crypto_keys_by_rloc_decap [ oo0o00OO ] = iIi11III
   return ( oo0o00OO )
   if 50 - 50: OoOoOO00 + iII111i . Oo0Ooo / OoO0O00 + II111iiii
   if 91 - 91: iIii1I11I1II1
 return ( None )
 if 32 - 32: OoOoOO00 * oO0o / O0 . o0oOOo0O0Ooo
 if 47 - 47: i1IIi
 if 61 - 61: OOooOOo * I1ii11iIi11i - ooOoO0o - Oo0Ooo + o0oOOo0O0Ooo . ooOoO0o
 if 98 - 98: II111iiii
 if 56 - 56: i1IIi % IiII / I1Ii111
 if 1 - 1: I1IiiI / OoOoOO00 - oO0o + OoooooooOO
 if 51 - 51: ooOoO0o + Ii1I * o0oOOo0O0Ooo * I1IiiI / oO0o + OoO0O00
 if 92 - 92: oO0o * o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * OoooooooOO * Oo0Ooo
 if 86 - 86: iII111i / OoooooooOO * I1Ii111 % I1IiiI + Ii1I
 if 16 - 16: OoO0O00
 if 41 - 41: i1IIi
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 OoOoo = addr + ":" + str ( port )
 if 8 - 8: iII111i + IiII + IiII
 if ( lisp_i_am_rtr ) :
  if ( lisp_rloc_probe_list . has_key ( addr ) ) : return ( addr )
  if 63 - 63: OoO0O00 . IiII - OoO0O00 - I1ii11iIi11i % I1IiiI
  if 45 - 45: I1Ii111 + I1ii11iIi11i + Ii1I % Ii1I
  if 94 - 94: OoO0O00
  if 78 - 78: iIii1I11I1II1 / I1IiiI + iIii1I11I1II1 . I1ii11iIi11i / I1ii11iIi11i + IiII
  if 92 - 92: i11iIiiIii * iII111i
  if 9 - 9: O0 * IiII / Ii1I + OoO0O00
  for Ooo in lisp_nat_state_info . values ( ) :
   for OooOoOooOO in Ooo :
    if ( addr == OooOoOooOO . address ) : return ( OoOoo )
    if 75 - 75: OOooOOo * OoOoOO00
    if 82 - 82: Ii1I
  return ( addr )
  if 83 - 83: I1IiiI
 return ( OoOoo )
 if 22 - 22: IiII / Ii1I + I1Ii111 % iIii1I11I1II1
 if 75 - 75: OoOoOO00 % OoOoOO00 % o0oOOo0O0Ooo % I1ii11iIi11i + IiII
 if 45 - 45: I11i - iIii1I11I1II1
 if 20 - 20: OoOoOO00
 if 84 - 84: OoOoOO00
 if 59 - 59: Ii1I / I1Ii111 + i11iIiiIii
 if 20 - 20: O0 / I1Ii111 - OOooOOo % iIii1I11I1II1
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 89 - 89: O0 * OoOoOO00 . ooOoO0o
 return
 if 11 - 11: iIii1I11I1II1 * OoO0O00 . I1IiiI * OoOoOO00 / II111iiii
 if 72 - 72: I11i
 if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
 if 62 - 62: OoOoOO00 * oO0o - I1IiiI / Ii1I
 if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
 if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
 if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
 if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
 if 9 - 9: i1IIi % iII111i / Ii1I
 if 83 - 83: oO0o
 if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
 if 29 - 29: OoooooooOO
 if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 83 - 83: iIii1I11I1II1
 if 92 - 92: OoO0O00 - iII111i
 if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
 if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
 if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
 if 70 - 70: I1Ii111 % iIii1I11I1II1
 if 74 - 74: i1IIi % i11iIiiIii + oO0o
 if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
 if 34 - 34: Oo0Ooo . i1IIi
 if 97 - 97: I11i
 if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
 if 20 - 20: oO0o % OoOoOO00
 if 93 - 93: I1ii11iIi11i - Ii1I % i1IIi / i1IIi
 if 82 - 82: OOooOOo
 if 27 - 27: I1Ii111 / IiII - i1IIi * Ii1I
 if 90 - 90: ooOoO0o
 if 100 - 100: iII111i * i1IIi . iII111i / O0 / OoO0O00 - oO0o
 if 65 - 65: OoOoOO00 + ooOoO0o * OoO0O00 % OoooooooOO + OoooooooOO * OoooooooOO
 if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
def lisp_is_rloc_probe ( packet , rr ) :
 o0oOo00 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( o0oOo00 == False ) : return ( [ packet , None , None , None ] )
 if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
 oo0O = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 O0o0o0ooO0ooo = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 Oo00oO0OOOOO0 = ( socket . htons ( LISP_CTRL_PORT ) in [ oo0O , O0o0o0ooO0ooo ] )
 if ( Oo00oO0OOOOO0 == False ) : return ( [ packet , None , None , None ] )
 if 10 - 10: o0oOOo0O0Ooo / OOooOOo + i11iIiiIii
 if ( rr == 0 ) :
  O0OoO0ooo0Ooo = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( O0OoO0ooo0Ooo == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  O0OoO0ooo0Ooo = lisp_is_rloc_probe_reply ( packet [ 28 ] )
  if ( O0OoO0ooo0Ooo == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  O0OoO0ooo0Ooo = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( O0OoO0ooo0Ooo == False ) :
   O0OoO0ooo0Ooo = lisp_is_rloc_probe_reply ( packet [ 28 ] )
   if ( O0OoO0ooo0Ooo == False ) : return ( [ packet , None , None , None ] )
   if 74 - 74: IiII * OoO0O00 % iIii1I11I1II1 * oO0o . I1IiiI
   if 7 - 7: IiII . IiII
   if 72 - 72: iII111i . iIii1I11I1II1 % IiII
   if 72 - 72: ooOoO0o + O0 . II111iiii . iIii1I11I1II1
   if 22 - 22: i11iIiiIii
   if 67 - 67: IiII / o0oOOo0O0Ooo . i1IIi / Ii1I . I1IiiI % ooOoO0o
 i1IIi1ii1i1ii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 i1IIi1ii1i1ii . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 78 - 78: Oo0Ooo . II111iiii - OoO0O00 - I1Ii111 + Oo0Ooo
 if 71 - 71: O0 + OOooOOo % OoooooooOO
 if 51 - 51: I1ii11iIi11i * o0oOOo0O0Ooo * I11i
 if 27 - 27: OoOoOO00 % OoO0O00 * oO0o . II111iiii - i11iIiiIii
 if ( i1IIi1ii1i1ii . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 56 - 56: OOooOOo . IiII - OOooOOo / i11iIiiIii * I1ii11iIi11i
 if 66 - 66: oO0o + ooOoO0o
 if 1 - 1: ooOoO0o
 if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
 i1IIi1ii1i1ii = i1IIi1ii1i1ii . print_address_no_iid ( )
 Oo0O00O = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 oOoooOOO0o0 = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 75 - 75: Ii1I
 O0OOOO0o0O = bold ( "Receive(pcap)" , False )
 OOO000 = bold ( "from " + i1IIi1ii1i1ii , False )
 oo00ooOOOo0O = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( O0OOOO0o0O , len ( packet ) , OOO000 , Oo0O00O , oo00ooOOOo0O ) )
 if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
 return ( [ packet , i1IIi1ii1i1ii , Oo0O00O , oOoooOOO0o0 ] )
 if 99 - 99: oO0o + I11i % i1IIi . iII111i
 if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
 if 65 - 65: OoO0O00
 if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
 if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
 if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
 if 74 - 74: OoOoOO00 + I1ii11iIi11i
 if 82 - 82: II111iiii
 if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
 if 48 - 48: ooOoO0o + Oo0Ooo / Oo0Ooo
 if 15 - 15: iIii1I11I1II1 . I1Ii111 * OoooooooOO * O0 % OOooOOo
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 53 - 53: Ii1I
 iiiii1i1 = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 63 - 63: I11i % OoOoOO00
 lisp_write_to_dp_socket ( iiiii1i1 )
 return
 if 46 - 46: iIii1I11I1II1 . II111iiii / OoooooooOO - ooOoO0o * iII111i
 if 52 - 52: I11i + iII111i
 if 9 - 9: OoOoOO00 % II111iiii . I11i * Oo0Ooo
 if 53 - 53: II111iiii / i1IIi + OoooooooOO * O0
 if 62 - 62: IiII . O0
 if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
 if 91 - 91: OOooOOo % oO0o . OoOoOO00 . I1IiiI - OoOoOO00
 if 18 - 18: O0 - I1IiiI + i1IIi % i11iIiiIii
def lisp_external_data_plane ( ) :
 ooO0ooooO = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( commands . getoutput ( ooO0ooooO ) != "" ) : return ( True )
 if 97 - 97: iII111i * OoooooooOO + I1Ii111 + ooOoO0o - ooOoO0o
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 63 - 63: o0oOOo0O0Ooo * OOooOOo + iIii1I11I1II1 + Oo0Ooo
 if 25 - 25: oO0o + IiII % o0oOOo0O0Ooo
 if 24 - 24: OoOoOO00
 if 87 - 87: I1ii11iIi11i / ooOoO0o * i1IIi
 if 71 - 71: OoOoOO00 - I11i
 if 83 - 83: oO0o + oO0o - Oo0Ooo . Oo0Ooo - iII111i . OOooOOo
 if 56 - 56: OoOoOO00 * IiII + i1IIi
 if 40 - 40: I1ii11iIi11i / O0
 if 87 - 87: ooOoO0o
 if 100 - 100: iII111i + II111iiii * Oo0Ooo * OOooOOo
 if 6 - 6: IiII % OOooOOo
 if 3 - 3: OoOoOO00 / OoOoOO00 - II111iiii
 if 41 - 41: oO0o
 if 12 - 12: I1IiiI + I1Ii111
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
 Oo0OoOOOO0 = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 24 - 24: IiII % Ii1I / ooOoO0o
 if ( do_clear == False ) :
  OoOOo00o0 = Oo0OoOOOO0 [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , OoOOo00o0 )
  if 52 - 52: iII111i % iIii1I11I1II1 - Oo0Ooo - iIii1I11I1II1 * I1ii11iIi11i - OoO0O00
  if 26 - 26: i11iIiiIii % I11i % o0oOOo0O0Ooo % OoOoOO00 / iII111i - OOooOOo
 lisp_write_to_dp_socket ( Oo0OoOOOO0 )
 return
 if 17 - 17: i1IIi - Ii1I . ooOoO0o % I1Ii111 . OoooooooOO / oO0o
 if 91 - 91: ooOoO0o % I1ii11iIi11i
 if 60 - 60: O0 * Oo0Ooo * IiII % OoOoOO00 . OoOoOO00
 if 4 - 4: I1Ii111 % I1Ii111 * O0
 if 54 - 54: I1ii11iIi11i - IiII . OoO0O00 + I1ii11iIi11i / I1IiiI
 if 91 - 91: OOooOOo % Oo0Ooo
 if 44 - 44: iIii1I11I1II1 . OOooOOo
 if 57 - 57: II111iiii + I1Ii111
 if 42 - 42: OoOoOO00 % O0
 if 70 - 70: iIii1I11I1II1 * Oo0Ooo - I1IiiI / OoO0O00 + OoOoOO00
 if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
 if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
 if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
 if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 26 - 26: Ii1I * I11i / I11i
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 79 - 79: ooOoO0o / oO0o - oO0o / OoooooooOO
  if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
  I11i11i1 = msg [ "eid-prefix" ]
  if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
  o0OoO0000o = int ( msg [ "instance-id" ] )
  if 16 - 16: I11i
  if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
  if 61 - 61: O0 % iII111i
  if 41 - 41: I1Ii111 * OoooooooOO
  ooOOoo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
  ooOOoo0 . store_prefix ( I11i11i1 )
  I1iOo0 = lisp_map_cache_lookup ( None , ooOOoo0 )
  if ( I1iOo0 == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( I11i11i1 ) )
   if 76 - 76: OoooooooOO * II111iiii . II111iiii / o0oOOo0O0Ooo - iII111i
   continue
   if 49 - 49: O0 . I1ii11iIi11i . OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
   if 19 - 19: iIii1I11I1II1
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( I11i11i1 ) )
   if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
   continue
   if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
  Oo0IiiiII = msg [ "rlocs" ]
  if 60 - 60: OOooOOo - OoOoOO00 - I1ii11iIi11i % i1IIi . I1IiiI + OoooooooOO
  if 72 - 72: II111iiii . II111iiii / iII111i % i1IIi / OoO0O00
  if 83 - 83: I11i % iIii1I11I1II1 * OoO0O00 - I1IiiI
  if 80 - 80: ooOoO0o - OoO0O00 . I1IiiI - I1IiiI
  for ooOoOO00 in Oo0IiiiII :
   if ( ooOoOO00 . has_key ( "rloc" ) == False ) : continue
   if 82 - 82: I1IiiI + OoOoOO00 . II111iiii / OoOoOO00 % OoOoOO00 . I1ii11iIi11i
   o0oooOoOoOo = ooOoOO00 [ "rloc" ]
   if ( o0oooOoOoOo == "no-address" ) : continue
   if 19 - 19: iIii1I11I1II1 . iIii1I11I1II1 + OOooOOo - I1ii11iIi11i
   oOO = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   oOO . store_address ( o0oooOoOoOo )
   if 59 - 59: i11iIiiIii / oO0o * IiII . o0oOOo0O0Ooo % Ii1I
   oo0OOOoO0OoO = I1iOo0 . get_rloc ( oOO )
   if ( oo0OOOoO0OoO == None ) : continue
   if 95 - 95: OoooooooOO - I1IiiI * I1ii11iIi11i
   if 52 - 52: oO0o % iII111i - I1IiiI - o0oOOo0O0Ooo
   if 66 - 66: o0oOOo0O0Ooo - Oo0Ooo - OoooooooOO * o0oOOo0O0Ooo + I1Ii111
   if 82 - 82: I11i * i1IIi / Ii1I + O0
   oooO0O0 = 0 if ooOoOO00 . has_key ( "packet-count" ) == False else ooOoOO00 [ "packet-count" ]
   if 17 - 17: Oo0Ooo . i1IIi / IiII . O0
   O0O0o = 0 if ooOoOO00 . has_key ( "byte-count" ) == False else ooOoOO00 [ "byte-count" ]
   if 72 - 72: OOooOOo
   i1 = 0 if ooOoOO00 . has_key ( "seconds-last-packet" ) == False else ooOoOO00 [ "seconds-last-packet" ]
   if 20 - 20: i11iIiiIii + Oo0Ooo * Oo0Ooo % OOooOOo
   if 66 - 66: I1ii11iIi11i + iII111i / Ii1I / I1IiiI * i11iIiiIii
   oo0OOOoO0OoO . stats . packet_count += oooO0O0
   oo0OOOoO0OoO . stats . byte_count += O0O0o
   oo0OOOoO0OoO . stats . last_increment = lisp_get_timestamp ( ) - i1
   if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( oooO0O0 , O0O0o ,
 i1 , I11i11i1 , o0oooOoOoOo ) )
   if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
   if 71 - 71: oO0o
   if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
   if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
   if 16 - 16: I1Ii111 + O0 - O0 * iIii1I11I1II1 / iII111i
  if ( I1iOo0 . group . is_null ( ) and I1iOo0 . has_ttl_elapsed ( ) ) :
   I11i11i1 = green ( I1iOo0 . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( I11i11i1 ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , I1iOo0 . eid , None )
   if 4 - 4: iII111i
   if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
 return
 if 32 - 32: iII111i
 if 59 - 59: OoOoOO00 - I1Ii111
 if 34 - 34: ooOoO0o . OoooooooOO / ooOoO0o + OoooooooOO
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
 if 21 - 21: IiII
 if 43 - 43: IiII
 if 9 - 9: OOooOOo * ooOoO0o + ooOoO0o . I1Ii111
 if 8 - 8: IiII * iIii1I11I1II1
 if 7 - 7: I1Ii111 / OoooooooOO % O0 - I1ii11iIi11i
 if 49 - 49: OoooooooOO . I1ii11iIi11i / OoooooooOO * oO0o
 if 81 - 81: I1ii11iIi11i . ooOoO0o + I1ii11iIi11i
 if 84 - 84: OoooooooOO
 if 95 - 95: o0oOOo0O0Ooo
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 22 - 22: ooOoO0o / o0oOOo0O0Ooo - OoooooooOO / Oo0Ooo - I1Ii111 / OOooOOo
 if 41 - 41: oO0o . II111iiii
 if 47 - 47: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 23 - 23: i11iIiiIii / I11i + i1IIi % I1Ii111
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  iiiii1i1 = "stats%{}" . format ( json . dumps ( msg ) )
  iiiii1i1 = lisp_command_ipc ( iiiii1i1 , "lisp-itr" )
  lisp_ipc ( iiiii1i1 , lisp_ipc_socket , "lisp-etr" )
  return
  if 100 - 100: Oo0Ooo
  if 13 - 13: I1IiiI + ooOoO0o * II111iiii
  if 32 - 32: iIii1I11I1II1 + O0 + i1IIi
  if 28 - 28: IiII + I11i
  if 1 - 1: OoooooooOO - i11iIiiIii . OoooooooOO - o0oOOo0O0Ooo - OOooOOo * I1Ii111
  if 56 - 56: Ii1I . OoO0O00
  if 43 - 43: iII111i * iII111i
  if 31 - 31: O0 - iIii1I11I1II1 . I11i . oO0o
 iiiii1i1 = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( iiiii1i1 , msg ) )
 if 96 - 96: OoooooooOO * iIii1I11I1II1 * Oo0Ooo
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 76 - 76: OoO0O00 / i11iIiiIii % ooOoO0o % I11i * O0
 Ooo0o00oo = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 25 - 25: ooOoO0o . OoooooooOO . OoO0O00 . I1IiiI
 for I11IIi1IIIi in Ooo0o00oo :
  oooO0O0 = 0 if msg . has_key ( I11IIi1IIIi ) == False else msg [ I11IIi1IIIi ] [ "packet-count" ]
  if 91 - 91: i11iIiiIii / iIii1I11I1II1
  lisp_decap_stats [ I11IIi1IIIi ] . packet_count += oooO0O0
  if 86 - 86: o0oOOo0O0Ooo + OoOoOO00 % I11i - iIii1I11I1II1 % OoOoOO00 + ooOoO0o
  O0O0o = 0 if msg . has_key ( I11IIi1IIIi ) == False else msg [ I11IIi1IIIi ] [ "byte-count" ]
  if 30 - 30: II111iiii / OoOoOO00 * o0oOOo0O0Ooo + OoooooooOO
  lisp_decap_stats [ I11IIi1IIIi ] . byte_count += O0O0o
  if 32 - 32: Ii1I - Ii1I / i11iIiiIii
  i1 = 0 if msg . has_key ( I11IIi1IIIi ) == False else msg [ I11IIi1IIIi ] [ "seconds-last-packet" ]
  if 48 - 48: iIii1I11I1II1 % OoooooooOO * Ii1I . i1IIi . oO0o % iIii1I11I1II1
  lisp_decap_stats [ I11IIi1IIIi ] . last_increment = lisp_get_timestamp ( ) - i1
  if 89 - 89: I11i + I11i * OoooooooOO + IiII % iIii1I11I1II1
 return
 if 52 - 52: i1IIi
 if 85 - 85: I1Ii111 - iII111i
 if 44 - 44: I11i - I11i - IiII . I11i
 if 34 - 34: iIii1I11I1II1 - oO0o * i11iIiiIii * o0oOOo0O0Ooo
 if 15 - 15: I1Ii111
 if 25 - 25: I1ii11iIi11i * O0
 if 8 - 8: i11iIiiIii
 if 95 - 95: ooOoO0o + i1IIi / OOooOOo . i11iIiiIii
 if 31 - 31: iII111i - iII111i - oO0o
 if 62 - 62: Oo0Ooo % Oo0Ooo / OoooooooOO * o0oOOo0O0Ooo . Ii1I
 if 1 - 1: I1ii11iIi11i / II111iiii / II111iiii + o0oOOo0O0Ooo + OoooooooOO
 if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
 if 87 - 87: OOooOOo * OoO0O00
 if 61 - 61: iII111i - II111iiii . I1Ii111 % II111iiii / I11i
 if 86 - 86: II111iiii
 if 94 - 94: o0oOOo0O0Ooo % Ii1I * Ii1I % Oo0Ooo / I1ii11iIi11i
 if 40 - 40: Oo0Ooo . II111iiii / II111iiii - i1IIi
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 oOoOOO0oOoo , i1IIi1ii1i1ii = punt_socket . recvfrom ( 4000 )
 if 24 - 24: o0oOOo0O0Ooo % iII111i
 o0oOoOOoo0O = json . loads ( oOoOOO0oOoo )
 if ( type ( o0oOoOOoo0O ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( i1IIi1ii1i1ii ) )
  if 47 - 47: OoooooooOO
  return
  if 65 - 65: I1ii11iIi11i . o0oOOo0O0Ooo * I1Ii111
 O0o0O00O = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( O0o0O00O , i1IIi1ii1i1ii , o0oOoOOoo0O ) )
 if 29 - 29: I1Ii111
 if ( o0oOoOOoo0O . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 61 - 61: I1ii11iIi11i % oO0o + OoooooooOO - ooOoO0o . OOooOOo + OoOoOO00
  if 53 - 53: o0oOOo0O0Ooo
  if 55 - 55: ooOoO0o . i1IIi - ooOoO0o + O0 + I1IiiI
  if 31 - 31: OoO0O00 % I1Ii111
  if 62 - 62: oO0o / O0 - I1Ii111 . IiII
 if ( o0oOoOOoo0O [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( o0oOoOOoo0O , lisp_send_sockets , lisp_ephem_port )
  return
  if 81 - 81: i11iIiiIii
 if ( o0oOoOOoo0O [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( o0oOoOOoo0O , punt_socket )
  return
  if 57 - 57: O0
  if 85 - 85: i11iIiiIii - i11iIiiIii - OoOoOO00 / II111iiii - II111iiii
  if 4 - 4: I1ii11iIi11i * O0 / OoO0O00 * II111iiii . iIii1I11I1II1 / OOooOOo
  if 97 - 97: i1IIi - OoOoOO00 . OoooooooOO
  if 24 - 24: iIii1I11I1II1 + OOooOOo * iII111i % IiII % OOooOOo
 if ( o0oOoOOoo0O [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 64 - 64: IiII . I1ii11iIi11i - o0oOOo0O0Ooo - ooOoO0o + OoooooooOO
  if 95 - 95: iII111i . I1ii11iIi11i + ooOoO0o + o0oOOo0O0Ooo % OoO0O00
  if 50 - 50: iII111i * O0 % II111iiii
  if 80 - 80: OOooOOo - II111iiii - OoO0O00
  if 62 - 62: Ii1I . i11iIiiIii % OOooOOo
 if ( o0oOoOOoo0O [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 44 - 44: i1IIi * I1ii11iIi11i % Ii1I . Ii1I * I11i + II111iiii
 if ( o0oOoOOoo0O . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( i1IIi1ii1i1ii ) )
  if 15 - 15: i1IIi - I11i - I1Ii111 / OoO0O00 + Oo0Ooo + I1IiiI
  return
  if 81 - 81: IiII
  if 54 - 54: I1IiiI % OoO0O00 % OoOoOO00
  if 12 - 12: II111iiii . O0 * i11iIiiIii . I11i
  if 98 - 98: II111iiii + i1IIi * oO0o % I1IiiI
  if 53 - 53: i11iIiiIii . I1ii11iIi11i - OOooOOo - OOooOOo
 OoO0o0OOOO = o0oOoOOoo0O [ "interface" ]
 if ( OoO0o0OOOO == "" ) :
  o0OoO0000o = int ( o0oOoOOoo0O [ "instance-id" ] )
  if ( o0OoO0000o == - 1 ) : return
 else :
  o0OoO0000o = lisp_get_interface_instance_id ( OoO0o0OOOO , None )
  if 97 - 97: I1IiiI % iII111i % OoooooooOO / ooOoO0o / i11iIiiIii
  if 7 - 7: O0 % IiII / o0oOOo0O0Ooo
  if 79 - 79: IiII + I1Ii111
  if 59 - 59: iII111i - oO0o . ooOoO0o / IiII * i11iIiiIii
  if 61 - 61: I11i - Oo0Ooo * II111iiii + iIii1I11I1II1
 O0OOO0OOo0 = None
 if ( o0oOoOOoo0O . has_key ( "source-eid" ) ) :
  OoOoo0ooO0000 = o0oOoOOoo0O [ "source-eid" ]
  O0OOO0OOo0 = lisp_address ( LISP_AFI_NONE , OoOoo0ooO0000 , 0 , o0OoO0000o )
  if ( O0OOO0OOo0 . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( OoOoo0ooO0000 ) )
   return
   if 37 - 37: OoooooooOO % II111iiii / o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i . iIii1I11I1II1
   if 73 - 73: OoOoOO00
 O00O0o00Oo = None
 if ( o0oOoOOoo0O . has_key ( "dest-eid" ) ) :
  iIIi = o0oOoOOoo0O [ "dest-eid" ]
  O00O0o00Oo = lisp_address ( LISP_AFI_NONE , iIIi , 0 , o0OoO0000o )
  if ( O00O0o00Oo . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( iIIi ) )
   return
   if 88 - 88: Oo0Ooo / ooOoO0o + II111iiii + OoooooooOO * iIii1I11I1II1
   if 82 - 82: i1IIi - I11i % ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo
   if 20 - 20: i11iIiiIii - O0 / i11iIiiIii
   if 51 - 51: iII111i . ooOoO0o
   if 70 - 70: I11i / O0 - I11i + o0oOOo0O0Ooo . ooOoO0o . o0oOOo0O0Ooo
   if 6 - 6: I11i + II111iiii - I1Ii111
   if 45 - 45: i1IIi / iII111i + i11iIiiIii * I11i + ooOoO0o / OoooooooOO
   if 56 - 56: I11i + I1Ii111
 if ( O0OOO0OOo0 ) :
  oOo = green ( O0OOO0OOo0 . print_address ( ) , False )
  iIIo00O000O = lisp_db_for_lookups . lookup_cache ( O0OOO0OOo0 , False )
  if ( iIIo00O000O != None ) :
   if 80 - 80: II111iiii . Ii1I + o0oOOo0O0Ooo / II111iiii / OoO0O00 + iIii1I11I1II1
   if 29 - 29: o0oOOo0O0Ooo + OoOoOO00 + ooOoO0o - I1ii11iIi11i
   if 64 - 64: O0 / OoooooooOO
   if 28 - 28: I1ii11iIi11i + oO0o . Oo0Ooo % iIii1I11I1II1 / I1Ii111
   if 8 - 8: O0 . I1IiiI * o0oOOo0O0Ooo + I1IiiI
   if ( iIIo00O000O . dynamic_eid_configured ( ) ) :
    II1i = lisp_allow_dynamic_eid ( OoO0o0OOOO , O0OOO0OOo0 )
    if ( II1i != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( iIIo00O000O , O0OOO0OOo0 , OoO0o0OOOO , II1i )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( oOo , OoO0o0OOOO ) )
     if 44 - 44: i1IIi % iII111i . i11iIiiIii / I11i + OoooooooOO
     if 21 - 21: OoOoOO00 . OoO0O00 . OoOoOO00 + OoOoOO00
     if 30 - 30: I1IiiI - iII111i - OOooOOo + oO0o
  else :
   lprint ( "Punt from non-EID source {}" . format ( oOo ) )
   if 51 - 51: Ii1I % O0 / II111iiii . Oo0Ooo
   if 90 - 90: i11iIiiIii * II111iiii % iIii1I11I1II1 . I1ii11iIi11i / Oo0Ooo . OOooOOo
   if 77 - 77: OoO0O00
   if 95 - 95: II111iiii
   if 59 - 59: iIii1I11I1II1 % OOooOOo / OoOoOO00 * I1Ii111 * OoooooooOO * O0
   if 43 - 43: OoO0O00 * I1IiiI * OOooOOo * O0 - O0 / o0oOOo0O0Ooo
 if ( O00O0o00Oo ) :
  I1iOo0 = lisp_map_cache_lookup ( O0OOO0OOo0 , O00O0o00Oo )
  if ( I1iOo0 == None or I1iOo0 . action == LISP_SEND_MAP_REQUEST_ACTION ) :
   if 77 - 77: I11i % I1Ii111 . IiII % OoooooooOO * o0oOOo0O0Ooo
   if 87 - 87: iII111i + IiII / ooOoO0o * ooOoO0o * OOooOOo
   if 97 - 97: I1Ii111
   if 47 - 47: iII111i / I1ii11iIi11i - Ii1I . II111iiii
   if 56 - 56: O0 - i1IIi % o0oOOo0O0Ooo + IiII
   if ( lisp_rate_limit_map_request ( O00O0o00Oo ) ) : return
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 O0OOO0OOo0 , O00O0o00Oo , None )
  else :
   oOo = green ( O00O0o00Oo . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( oOo ) )
   if 42 - 42: o0oOOo0O0Ooo . OOooOOo % I11i - OoOoOO00
   if 38 - 38: OoooooooOO
 return
 if 27 - 27: O0 + I1ii11iIi11i % Ii1I . i1IIi + OoO0O00 + OoOoOO00
 if 22 - 22: II111iiii / I1IiiI + o0oOOo0O0Ooo * I1IiiI . OoooooooOO * OOooOOo
 if 49 - 49: I1ii11iIi11i * I1IiiI + OOooOOo + i11iIiiIii * I1ii11iIi11i . o0oOOo0O0Ooo
 if 36 - 36: o0oOOo0O0Ooo - i11iIiiIii
 if 37 - 37: O0 + IiII + I1IiiI
 if 50 - 50: OoooooooOO . I1Ii111
 if 100 - 100: ooOoO0o * ooOoO0o - Ii1I
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 i1ii1i1Ii11 = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( i1ii1i1Ii11 )
 return ( [ True , jdata ] )
 if 13 - 13: iII111i . I11i * OoO0O00 . i1IIi . iIii1I11I1II1 - o0oOOo0O0Ooo
 if 68 - 68: Ii1I % o0oOOo0O0Ooo / OoooooooOO + Ii1I - Ii1I
 if 79 - 79: II111iiii / IiII
 if 4 - 4: O0 - i11iIiiIii % ooOoO0o * O0 - ooOoO0o
 if 96 - 96: oO0o % II111iiii . Ii1I % OoO0O00 . iIii1I11I1II1 / IiII
 if 96 - 96: o0oOOo0O0Ooo / O0 . iIii1I11I1II1 . Ii1I % OOooOOo % II111iiii
 if 5 - 5: OoooooooOO / I1Ii111 % I1Ii111 / I1IiiI
 if 19 - 19: I1IiiI - ooOoO0o % IiII - o0oOOo0O0Ooo * OOooOOo + I1ii11iIi11i
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 44 - 44: i1IIi
 if 85 - 85: I1ii11iIi11i / IiII + oO0o
 if 95 - 95: IiII . OoO0O00
 if 36 - 36: IiII % Ii1I - OoOoOO00 + OoO0O00 + IiII * Ii1I
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 15 - 15: I1IiiI / O0 % I1ii11iIi11i % OoOoOO00 . OoOoOO00 + iII111i
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 79 - 79: OOooOOo + Ii1I . I1Ii111 / Oo0Ooo / i11iIiiIii / O0
 if 28 - 28: i1IIi % OoO0O00 / i1IIi - o0oOOo0O0Ooo
 if 97 - 97: II111iiii + O0 . Ii1I + OoooooooOO
 if 39 - 39: i11iIiiIii + OoO0O00 + I11i * oO0o + iIii1I11I1II1 % o0oOOo0O0Ooo
 if 25 - 25: OoooooooOO
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 78 - 78: oO0o / i11iIiiIii * O0 / OOooOOo % i11iIiiIii % O0
 if 86 - 86: IiII
 if 26 - 26: IiII - I1Ii111 + i11iIiiIii % ooOoO0o * i11iIiiIii + Oo0Ooo
 if 39 - 39: Ii1I - i1IIi + i11iIiiIii
 if 21 - 21: IiII
 if 76 - 76: o0oOOo0O0Ooo % Oo0Ooo + OoO0O00
 if 36 - 36: OOooOOo . oO0o
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 I11i11i1 = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( I11i11i1 ) ) :
  db . dynamic_eids [ I11i11i1 ] . last_packet = lisp_get_timestamp ( )
  return
  if 15 - 15: I1IiiI + ooOoO0o - o0oOOo0O0Ooo
  if 62 - 62: Ii1I - OOooOOo
  if 88 - 88: iIii1I11I1II1 * Oo0Ooo / II111iiii / IiII / OoO0O00 % ooOoO0o
  if 19 - 19: I11i * iII111i . O0 * iII111i % I1ii11iIi11i - OoOoOO00
  if 68 - 68: I1Ii111 - OoO0O00 % Ii1I + i1IIi . ooOoO0o
 I1iIi1IiI1i = lisp_dynamic_eid ( )
 I1iIi1IiI1i . dynamic_eid . copy_address ( eid )
 I1iIi1IiI1i . interface = routed_interface
 I1iIi1IiI1i . last_packet = lisp_get_timestamp ( )
 I1iIi1IiI1i . get_timeout ( routed_interface )
 db . dynamic_eids [ I11i11i1 ] = I1iIi1IiI1i
 if 36 - 36: oO0o * iIii1I11I1II1 - O0 - IiII * O0 + i11iIiiIii
 OOooO0OoO0 = ""
 if ( input_interface != routed_interface ) :
  OOooO0OoO0 = ", routed-interface " + routed_interface
  if 32 - 32: IiII
  if 52 - 52: O0
 Ooooooo0Oo = green ( I11i11i1 , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( Ooooooo0Oo , input_interface , OOooO0OoO0 , I1iIi1IiI1i . timeout ) )
 if 54 - 54: ooOoO0o
 if 47 - 47: I11i * I1IiiI / oO0o
 if 98 - 98: Ii1I / oO0o * O0 + I1Ii111 - I1Ii111 + iII111i
 if 4 - 4: i1IIi
 if 43 - 43: oO0o * ooOoO0o - I11i
 iiiii1i1 = "learn%{}%{}" . format ( I11i11i1 , routed_interface )
 iiiii1i1 = lisp_command_ipc ( iiiii1i1 , "lisp-itr" )
 lisp_ipc ( iiiii1i1 , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 70 - 70: oO0o / Ii1I
 if 15 - 15: iIii1I11I1II1 % ooOoO0o % i11iIiiIii
 if 16 - 16: iII111i
 if 50 - 50: iIii1I11I1II1 - II111iiii % i1IIi
 if 48 - 48: O0
 if 60 - 60: ooOoO0o - IiII % i1IIi
 if 5 - 5: oO0o
 if 29 - 29: i1IIi . OoOoOO00 . i1IIi + oO0o . I1Ii111 + O0
 if 62 - 62: I1ii11iIi11i . IiII + OoO0O00 - OoOoOO00 * O0 + I1Ii111
 if 58 - 58: oO0o . OoO0O00 / ooOoO0o
 if 61 - 61: I11i + I1Ii111
 if 27 - 27: ooOoO0o / i1IIi . oO0o - OoooooooOO
 if 48 - 48: ooOoO0o % ooOoO0o / OoooooooOO + i1IIi * oO0o + ooOoO0o
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 69 - 69: iII111i . iII111i
 if 46 - 46: IiII * Oo0Ooo + I1Ii111
 if 79 - 79: IiII
 if 89 - 89: IiII * I11i + I1ii11iIi11i * oO0o - II111iiii
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 58 - 58: ooOoO0o . I1Ii111 / i1IIi % I1ii11iIi11i + o0oOOo0O0Ooo
 O00oOO0OO00 = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 94 - 94: i11iIiiIii + I1Ii111 . iII111i - ooOoO0o % I1Ii111
 for Oo000O000 in lisp_crypto_keys_by_rloc_decap :
  if 94 - 94: i11iIiiIii - OOooOOo - O0 * OoooooooOO - ooOoO0o
  if 35 - 35: iII111i . i11iIiiIii - OOooOOo % Oo0Ooo + Ii1I . iIii1I11I1II1
  if 91 - 91: o0oOOo0O0Ooo / OoO0O00 + I1IiiI % i11iIiiIii % i1IIi
  if 22 - 22: I1Ii111 * O0 % OoO0O00 * I1ii11iIi11i
  if ( Oo000O000 . find ( addr_str ) == - 1 ) : continue
  if 47 - 47: OoO0O00 / OOooOOo / OoOoOO00 % i11iIiiIii / OoOoOO00
  if 52 - 52: ooOoO0o / I11i % i11iIiiIii - I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
  if 67 - 67: OoOoOO00 / I1Ii111 + i11iIiiIii - IiII
  if 79 - 79: I11i . I11i - OoOoOO00
  if ( Oo000O000 == addr_str ) : continue
  if 86 - 86: OoO0O00 * Oo0Ooo . iIii1I11I1II1 * O0
  if 52 - 52: iII111i - i11iIiiIii + o0oOOo0O0Ooo + i1IIi
  if 58 - 58: OOooOOo - Ii1I * I1Ii111 - O0 . oO0o
  if 72 - 72: i1IIi * iII111i * Ii1I / o0oOOo0O0Ooo . I1Ii111 + i11iIiiIii
  i1ii1i1Ii11 = lisp_crypto_keys_by_rloc_decap [ Oo000O000 ]
  if ( i1ii1i1Ii11 == O00oOO0OO00 ) : continue
  if 33 - 33: I11i / OoO0O00 * ooOoO0o + iIii1I11I1II1
  if 54 - 54: Oo0Ooo / IiII + i11iIiiIii . O0
  if 94 - 94: OoooooooOO + iII111i * OoooooooOO / o0oOOo0O0Ooo
  if 12 - 12: iIii1I11I1II1 / iIii1I11I1II1 / II111iiii
  oO00OoooO = i1ii1i1Ii11 [ 1 ]
  if ( packet_icv != oO00OoooO . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( Oo000O000 , False ) ) )
   continue
   if 97 - 97: Ii1I * Ii1I * iIii1I11I1II1
   if 47 - 47: o0oOOo0O0Ooo + I1Ii111 * I1Ii111
  lprint ( "Changing decap crypto key to {}" . format ( red ( Oo000O000 , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = i1ii1i1Ii11
  if 38 - 38: Ii1I . IiII
 return
 if 11 - 11: O0 . II111iiii % ooOoO0o % o0oOOo0O0Ooo
 if 45 - 45: o0oOOo0O0Ooo + iII111i / II111iiii + iII111i
 if 1 - 1: i1IIi * Oo0Ooo * oO0o
 if 85 - 85: OoooooooOO . IiII / IiII . ooOoO0o . IiII % II111iiii
 if 65 - 65: oO0o - OoO0O00 / iII111i + ooOoO0o
 if 80 - 80: o0oOOo0O0Ooo + II111iiii * Ii1I % OoOoOO00 % I1IiiI + I1ii11iIi11i
 if 46 - 46: Oo0Ooo / Oo0Ooo % iII111i % I1IiiI
 if 85 - 85: OoO0O00 - Ii1I / O0
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 45 - 45: IiII + I1Ii111 / I11i
 if 84 - 84: iII111i % II111iiii
 if 86 - 86: IiII % II111iiii / i1IIi * I1ii11iIi11i - O0 * OOooOOo
 if 53 - 53: OOooOOo * oO0o + i1IIi % Oo0Ooo + II111iiii
 if 34 - 34: oO0o % iII111i / IiII . IiII + i11iIiiIii
 if 68 - 68: O0 % oO0o * IiII % O0
 if 55 - 55: O0 % I1IiiI % O0
 if 27 - 27: I1IiiI + I1ii11iIi11i * I1Ii111 % Ii1I - Oo0Ooo
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 Ooo0o0OoOO = dns_name . split ( "." )
 Ooo0o0OoOO = "." . join ( Ooo0o0OoOO [ 1 : : ] )
 return ( Ooo0o0OoOO == lisp_decent_dns_suffix )
 if 87 - 87: i11iIiiIii % OOooOOo - OoOoOO00 * ooOoO0o / Oo0Ooo
 if 74 - 74: OoooooooOO * ooOoO0o - I11i / I1ii11iIi11i % iIii1I11I1II1
 if 94 - 94: Ii1I * I1Ii111 + OoOoOO00 . iIii1I11I1II1
 if 44 - 44: Oo0Ooo . Oo0Ooo * Oo0Ooo
 if 23 - 23: I1Ii111 / iII111i . O0 % II111iiii
 if 67 - 67: I11i / iIii1I11I1II1 / ooOoO0o
 if 90 - 90: II111iiii % I1Ii111 - IiII . Oo0Ooo % OOooOOo - OoOoOO00
def lisp_get_decent_index ( eid ) :
 I11i11i1 = eid . print_prefix ( )
 oOoO0O00 = hashlib . sha256 ( I11i11i1 ) . hexdigest ( )
 ooo = int ( oOoO0O00 , 16 ) % lisp_decent_modulus
 return ( ooo )
 if 100 - 100: iII111i % i11iIiiIii % I1Ii111
 if 77 - 77: OoOoOO00 . IiII
 if 86 - 86: I1Ii111 + iII111i . Ii1I
 if 65 - 65: i11iIiiIii % i11iIiiIii
 if 82 - 82: I1ii11iIi11i - OoooooooOO . OoooooooOO - OoO0O00 / iII111i
 if 32 - 32: Ii1I / o0oOOo0O0Ooo * I1Ii111 * i11iIiiIii * I11i
 if 14 - 14: oO0o
def lisp_get_decent_dns_name ( eid ) :
 ooo = lisp_get_decent_index ( eid )
 return ( str ( ooo ) + "." + lisp_decent_dns_suffix )
 if 27 - 27: Ii1I + Ii1I
 if 32 - 32: OOooOOo % OOooOOo + I1ii11iIi11i / Ii1I - i11iIiiIii
 if 28 - 28: iIii1I11I1II1 - II111iiii
 if 36 - 36: ooOoO0o . II111iiii - OoOoOO00 % I1ii11iIi11i * O0
 if 91 - 91: iII111i + Oo0Ooo / OoooooooOO * iIii1I11I1II1 - OoO0O00
 if 73 - 73: iIii1I11I1II1 % I1Ii111 % II111iiii * Oo0Ooo * OoO0O00
 if 48 - 48: OOooOOo * i11iIiiIii - i11iIiiIii + iIii1I11I1II1 + I1IiiI % OoooooooOO
 if 61 - 61: i1IIi
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 ooOOoo0 = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 ooo = lisp_get_decent_index ( ooOOoo0 )
 return ( str ( ooo ) + "." + lisp_decent_dns_suffix )
 if 56 - 56: iIii1I11I1II1 / I11i * iII111i * I11i * OoooooooOO
 if 44 - 44: I1ii11iIi11i - OOooOOo % I11i - I1Ii111 / iIii1I11I1II1 - OOooOOo
 if 38 - 38: iIii1I11I1II1 - OoooooooOO * II111iiii . OoooooooOO + OOooOOo
 if 59 - 59: OoooooooOO
 if 22 - 22: II111iiii
 if 85 - 85: I1Ii111 + I1ii11iIi11i * I11i % o0oOOo0O0Ooo + Ii1I
 if 23 - 23: IiII * OoO0O00
 if 42 - 42: IiII
 if 83 - 83: i1IIi * o0oOOo0O0Ooo / OoO0O00 / o0oOOo0O0Ooo
 if 55 - 55: Oo0Ooo % O0 - OoO0O00
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 42 - 42: OoooooooOO * OOooOOo
 OoO00oo00 = 28 if packet . inner_version == 4 else 48
 O0oo0O = packet . packet [ OoO00oo00 : : ]
 IIIii1I = lisp_trace ( )
 if ( IIIii1I . decode ( O0oo0O ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 55 - 55: O0 + ooOoO0o * oO0o
  if 87 - 87: o0oOOo0O0Ooo + OoOoOO00 * iIii1I11I1II1
 II1IIiI1 = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 55 - 55: OoO0O00
 if 11 - 11: OoooooooOO - I1IiiI . I1IiiI % o0oOOo0O0Ooo
 if 56 - 56: I1Ii111
 if 23 - 23: ooOoO0o . I11i - OOooOOo
 if 40 - 40: OoOoOO00
 if 44 - 44: O0 + Oo0Ooo - iII111i + iIii1I11I1II1 / i11iIiiIii * IiII
 if ( II1IIiI1 != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : II1IIiI1 += ":{}" . format ( packet . encap_port )
  if 49 - 49: Oo0Ooo
  if 87 - 87: I1Ii111 + iII111i / IiII / ooOoO0o * OoooooooOO / OOooOOo
  if 44 - 44: IiII . I1Ii111
  if 46 - 46: O0 - ooOoO0o . I1ii11iIi11i % oO0o / OoOoOO00
  if 93 - 93: I1ii11iIi11i * o0oOOo0O0Ooo . I11i . I1ii11iIi11i % i1IIi + Ii1I
 i1ii1i1Ii11 = { }
 i1ii1i1Ii11 [ "node" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 63 - 63: I1IiiI / OoooooooOO
 iIiii1I = packet . outer_source
 if ( iIiii1I . is_null ( ) ) : iIiii1I = lisp_myrlocs [ 0 ]
 i1ii1i1Ii11 [ "srloc" ] = iIiii1I . print_address_no_iid ( )
 if 85 - 85: ooOoO0o + I1Ii111 - O0 * I11i / i1IIi
 if 66 - 66: ooOoO0o % I1Ii111 - O0 + I1Ii111 - i1IIi % OoOoOO00
 if 13 - 13: O0 + iIii1I11I1II1 % I1IiiI * O0 + ooOoO0o
 if 60 - 60: iIii1I11I1II1 + OoooooooOO - OoO0O00
 if 44 - 44: O0 . OOooOOo . o0oOOo0O0Ooo . I1ii11iIi11i - II111iiii
 if ( i1ii1i1Ii11 [ "node" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  i1ii1i1Ii11 [ "srloc" ] += ":{}" . format ( packet . inner_sport )
  if 71 - 71: I1ii11iIi11i + o0oOOo0O0Ooo . i11iIiiIii * oO0o . i1IIi
  if 40 - 40: OoO0O00 - IiII
 i1ii1i1Ii11 [ "hn" ] = lisp_hostname
 Oo000O000 = ed + "-ts"
 i1ii1i1Ii11 [ Oo000O000 ] = lisp_get_timestamp ( )
 if 43 - 43: I1Ii111 + i11iIiiIii % iII111i % I1Ii111 - ooOoO0o
 if 85 - 85: IiII % iIii1I11I1II1 . I1Ii111
 if 38 - 38: iII111i - I1IiiI / ooOoO0o
 if 46 - 46: OOooOOo . O0 / i11iIiiIii . OOooOOo
 if 19 - 19: I11i / Oo0Ooo + I1Ii111
 if 43 - 43: I1ii11iIi11i
 if ( II1IIiI1 == "?" and i1ii1i1Ii11 [ "node" ] == "ETR" ) :
  iIIo00O000O = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( iIIo00O000O != None and len ( iIIo00O000O . rloc_set ) >= 1 ) :
   II1IIiI1 = iIIo00O000O . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 18 - 18: I11i / OOooOOo % I11i - o0oOOo0O0Ooo
   if 22 - 22: iII111i
 i1ii1i1Ii11 [ "drloc" ] = II1IIiI1
 if 88 - 88: I11i + OoOoOO00 % IiII % OoO0O00 * O0 / OoooooooOO
 if 83 - 83: IiII + I1Ii111 . I1ii11iIi11i * iIii1I11I1II1
 if 9 - 9: ooOoO0o % IiII - OoOoOO00
 if 66 - 66: oO0o % Oo0Ooo
 if ( II1IIiI1 == "?" and reason != None ) :
  i1ii1i1Ii11 [ "drloc" ] += " ({})" . format ( reason )
  if 40 - 40: i11iIiiIii . O0 * I11i - oO0o / OOooOOo . oO0o
  if 86 - 86: OOooOOo - I1Ii111 * IiII - i1IIi + ooOoO0o + I11i
  if 32 - 32: IiII
  if 99 - 99: II111iiii
  if 34 - 34: OOooOOo + OoOoOO00 * o0oOOo0O0Ooo + I1ii11iIi11i + IiII * i1IIi
 if ( rloc_entry != None ) :
  i1ii1i1Ii11 [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  i1ii1i1Ii11 [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  i1ii1i1Ii11 [ "latencies" ] = rloc_entry . recent_rloc_probe_latencies
  if 73 - 73: I1ii11iIi11i - IiII - O0 . oO0o + Oo0Ooo % iII111i
  if 68 - 68: I1ii11iIi11i - OoooooooOO
  if 5 - 5: I1ii11iIi11i * I1IiiI + OoooooooOO / Oo0Ooo
  if 18 - 18: OoO0O00 * iII111i % I1IiiI . OOooOOo * o0oOOo0O0Ooo
  if 58 - 58: iII111i . IiII + iIii1I11I1II1
  if 13 - 13: oO0o * I1Ii111 / I1Ii111 . I1IiiI
 O0OOO0OOo0 = packet . inner_source . print_address ( )
 O00O0o00Oo = packet . inner_dest . print_address ( )
 if ( IIIii1I . packet_json == [ ] ) :
  oO00O0oO0O = { }
  oO00O0oO0O [ "seid" ] = O0OOO0OOo0
  oO00O0oO0O [ "deid" ] = O00O0o00Oo
  oO00O0oO0O [ "paths" ] = [ ]
  IIIii1I . packet_json . append ( oO00O0oO0O )
  if 93 - 93: I11i % OoOoOO00 - OOooOOo + iIii1I11I1II1 / OoooooooOO % i11iIiiIii
  if 90 - 90: oO0o % iIii1I11I1II1 + o0oOOo0O0Ooo - I11i / i11iIiiIii
  if 57 - 57: I1IiiI . Oo0Ooo / I1IiiI / II111iiii - I1Ii111
  if 68 - 68: I1IiiI
  if 97 - 97: Ii1I + o0oOOo0O0Ooo / OoO0O00
  if 97 - 97: i11iIiiIii % iIii1I11I1II1 + II111iiii
 for oO00O0oO0O in IIIii1I . packet_json :
  if ( oO00O0oO0O [ "deid" ] != O00O0o00Oo ) : continue
  oO00O0oO0O [ "paths" ] . append ( i1ii1i1Ii11 )
  break
  if 90 - 90: OOooOOo / I1IiiI
  if 28 - 28: OoooooooOO + i1IIi
  if 29 - 29: Oo0Ooo
  if 98 - 98: OOooOOo / Oo0Ooo % Ii1I * OoooooooOO - oO0o
  if 64 - 64: I1IiiI - I1IiiI
  if 90 - 90: iII111i - I1IiiI - II111iiii / OOooOOo + Ii1I
  if 34 - 34: i11iIiiIii + I1Ii111 / O0 / iIii1I11I1II1 * OoooooooOO % Ii1I
  if 32 - 32: i11iIiiIii - OoOoOO00 / iIii1I11I1II1 * o0oOOo0O0Ooo % I1IiiI + O0
 II1I11 = False
 if ( len ( IIIii1I . packet_json ) == 1 and i1ii1i1Ii11 [ "node" ] == "ETR" and
 IIIii1I . myeid ( packet . inner_dest ) ) :
  oO00O0oO0O = { }
  oO00O0oO0O [ "seid" ] = O00O0o00Oo
  oO00O0oO0O [ "deid" ] = O0OOO0OOo0
  oO00O0oO0O [ "paths" ] = [ ]
  IIIii1I . packet_json . append ( oO00O0oO0O )
  II1I11 = True
  if 95 - 95: o0oOOo0O0Ooo + I1ii11iIi11i % Ii1I + iIii1I11I1II1 + i1IIi % I1ii11iIi11i
  if 31 - 31: oO0o * OOooOOo % OoooooooOO . OOooOOo * Ii1I
  if 38 - 38: I1IiiI - Oo0Ooo + I1Ii111 % II111iiii
  if 90 - 90: iIii1I11I1II1
  if 91 - 91: I1IiiI / iIii1I11I1II1 * OoO0O00 + iII111i * IiII + OoooooooOO
  if 63 - 63: I1IiiI / Ii1I
 IIIii1I . print_trace ( )
 O0oo0O = IIIii1I . encode ( )
 if 31 - 31: i1IIi - oO0o
 if 99 - 99: iII111i - i11iIiiIii + oO0o
 if 66 - 66: Oo0Ooo * I11i . iIii1I11I1II1 - OoO0O00
 if 11 - 11: I1Ii111 + iIii1I11I1II1 * O0 * Oo0Ooo
 if 66 - 66: OoooooooOO % OoO0O00 + i11iIiiIii + I1Ii111 % OoO0O00
 if 80 - 80: Oo0Ooo - Ii1I
 if 54 - 54: O0 - iIii1I11I1II1 . OoO0O00 . IiII % OoO0O00
 if 28 - 28: O0 % i1IIi % OoO0O00 / o0oOOo0O0Ooo . iIii1I11I1II1 - iII111i
 IIi11ii = IIIii1I . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "srloc" ]
 if ( II1IIiI1 == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( IIi11ii ) )
  IIIii1I . return_to_sender ( lisp_socket , IIi11ii , O0oo0O )
  return ( False )
  if 61 - 61: IiII
  if 5 - 5: OOooOOo % iIii1I11I1II1 % O0 * i11iIiiIii / I1Ii111
  if 48 - 48: IiII * oO0o
  if 53 - 53: i1IIi * iIii1I11I1II1 . OOooOOo
  if 68 - 68: IiII % IiII - iII111i . IiII + OoooooooOO
  if 82 - 82: Ii1I . II111iiii / i1IIi * OoO0O00
 O0OOOOo0 = IIIii1I . packet_length ( )
 if 80 - 80: I11i
 if 96 - 96: i1IIi - I1ii11iIi11i * iII111i . OOooOOo . OoO0O00
 if 93 - 93: oO0o * Oo0Ooo * IiII
 if 26 - 26: o0oOOo0O0Ooo + O0 % i11iIiiIii . ooOoO0o . I1IiiI + Oo0Ooo
 if 90 - 90: IiII * OoooooooOO + II111iiii / iII111i + i11iIiiIii / ooOoO0o
 if 20 - 20: II111iiii % I1ii11iIi11i - OoooooooOO * Ii1I / I11i - OoooooooOO
 IiI11iI = packet . packet [ 0 : OoO00oo00 ]
 oo00ooOOOo0O = struct . pack ( "HH" , socket . htons ( O0OOOOo0 ) , 0 )
 IiI11iI = IiI11iI [ 0 : OoO00oo00 - 4 ] + oo00ooOOOo0O
 if ( packet . inner_version == 6 and i1ii1i1Ii11 [ "node" ] == "ETR" and
 len ( IIIii1I . packet_json ) == 2 ) :
  o0oOo00 = IiI11iI [ OoO00oo00 - 8 : : ] + O0oo0O
  o0oOo00 = lisp_udp_checksum ( O0OOO0OOo0 , O00O0o00Oo , o0oOo00 )
  IiI11iI = IiI11iI [ 0 : OoO00oo00 - 8 ] + o0oOo00 [ 0 : 8 ]
  if 56 - 56: i1IIi + OoooooooOO - i11iIiiIii + o0oOOo0O0Ooo
  if 10 - 10: OOooOOo - o0oOOo0O0Ooo
  if 80 - 80: II111iiii
  if 79 - 79: I1ii11iIi11i % iII111i % O0 + o0oOOo0O0Ooo - oO0o - I1Ii111
  if 60 - 60: oO0o * I1IiiI / ooOoO0o - i11iIiiIii
  if 57 - 57: I1IiiI * I1IiiI % O0 + OOooOOo
 if ( II1I11 ) :
  if ( packet . inner_version == 4 ) :
   IiI11iI = IiI11iI [ 0 : 12 ] + IiI11iI [ 16 : 20 ] + IiI11iI [ 12 : 16 ] + IiI11iI [ 22 : 24 ] + IiI11iI [ 20 : 22 ] + IiI11iI [ 24 : : ]
   if 58 - 58: Oo0Ooo . I1IiiI + I1Ii111 - ooOoO0o . o0oOOo0O0Ooo
  else :
   IiI11iI = IiI11iI [ 0 : 8 ] + IiI11iI [ 24 : 40 ] + IiI11iI [ 8 : 24 ] + IiI11iI [ 42 : 44 ] + IiI11iI [ 40 : 42 ] + IiI11iI [ 44 : : ]
   if 52 - 52: o0oOOo0O0Ooo % I11i * I11i / iIii1I11I1II1
   if 77 - 77: OoOoOO00
  OooOOOoOoo0O0 = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = OooOOOoOoo0O0
  if 67 - 67: OoooooooOO / OoooooooOO + IiII - ooOoO0o
  if 72 - 72: Ii1I
  if 21 - 21: ooOoO0o + iII111i
  if 39 - 39: o0oOOo0O0Ooo % I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo
  if 78 - 78: OoO0O00 / o0oOOo0O0Ooo / O0 % OOooOOo % i1IIi
 OoO00oo00 = 2 if packet . inner_version == 4 else 4
 oOoOoO0O0 = 20 + O0OOOOo0 if packet . inner_version == 4 else O0OOOOo0
 I1iIi11II = struct . pack ( "H" , socket . htons ( oOoOoO0O0 ) )
 IiI11iI = IiI11iI [ 0 : OoO00oo00 ] + I1iIi11II + IiI11iI [ OoO00oo00 + 2 : : ]
 if 56 - 56: OoO0O00 . OOooOOo * OoO0O00 . ooOoO0o * OoooooooOO
 if 75 - 75: i1IIi - I11i
 if 5 - 5: OoO0O00 - oO0o - OOooOOo + II111iiii
 if 19 - 19: iIii1I11I1II1 * OoooooooOO - i11iIiiIii . I1Ii111 * OoO0O00
 if ( packet . inner_version == 4 ) :
  oOOoooo0o0 = struct . pack ( "H" , 0 )
  IiI11iI = IiI11iI [ 0 : 10 ] + oOOoooo0o0 + IiI11iI [ 12 : : ]
  I1iIi11II = lisp_ip_checksum ( IiI11iI [ 0 : 20 ] )
  IiI11iI = I1iIi11II + IiI11iI [ 20 : : ]
  if 30 - 30: iII111i + I1IiiI * ooOoO0o
  if 53 - 53: iII111i + IiII
  if 52 - 52: II111iiii * i11iIiiIii - IiII * IiII / OoooooooOO
  if 18 - 18: IiII / O0 / I1ii11iIi11i
  if 47 - 47: oO0o / iIii1I11I1II1
 packet . packet = IiI11iI + O0oo0O
 return ( True )
 if 45 - 45: OoOoOO00 * o0oOOo0O0Ooo / I1ii11iIi11i * iII111i - I1ii11iIi11i
 if 48 - 48: Ii1I / OoO0O00
 if 45 - 45: O0 * OoO0O00 / I11i . II111iiii
 if 20 - 20: I11i - IiII
 if 75 - 75: i11iIiiIii + I11i % I11i . I1Ii111
 if 58 - 58: o0oOOo0O0Ooo * II111iiii + o0oOOo0O0Ooo . I1IiiI
 if 25 - 25: o0oOOo0O0Ooo * I11i
 if 70 - 70: OOooOOo
 if 11 - 11: I11i * II111iiii * Oo0Ooo + OOooOOo % i1IIi
 if 73 - 73: OoO0O00 + O0 / Ii1I . OoooooooOO % iIii1I11I1II1 * i1IIi
def lisp_allow_gleaning ( eid , group , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False , False )
 if 84 - 84: o0oOOo0O0Ooo . iII111i / o0oOOo0O0Ooo + I1ii11iIi11i % OoO0O00
 for i1ii1i1Ii11 in lisp_glean_mappings :
  if ( i1ii1i1Ii11 . has_key ( "instance-id" ) ) :
   o0OoO0000o = eid . instance_id
   IiiIii1 , Oo00O0o0oOoO = i1ii1i1Ii11 [ "instance-id" ]
   if ( o0OoO0000o < IiiIii1 or o0OoO0000o > Oo00O0o0oOoO ) : continue
   if 52 - 52: OoOoOO00 / Ii1I % OoOoOO00 % i11iIiiIii + I1IiiI / o0oOOo0O0Ooo
  if ( i1ii1i1Ii11 . has_key ( "eid-prefix" ) ) :
   oOo = copy . deepcopy ( i1ii1i1Ii11 [ "eid-prefix" ] )
   oOo . instance_id = eid . instance_id
   if ( eid . is_more_specific ( oOo ) == False ) : continue
   if 63 - 63: I1IiiI
  if ( i1ii1i1Ii11 . has_key ( "group-prefix" ) ) :
   if ( group == None ) : continue
   i11ii = copy . deepcopy ( i1ii1i1Ii11 [ "group-prefix" ] )
   i11ii . instance_id = group . instance_id
   if ( group . is_more_specific ( i11ii ) == False ) : continue
   if 20 - 20: oO0o + OoOoOO00
  if ( i1ii1i1Ii11 . has_key ( "rloc-prefix" ) ) :
   if ( rloc != None and rloc . is_more_specific ( i1ii1i1Ii11 [ "rloc-prefix" ] )
 == False ) : continue
   if 32 - 32: o0oOOo0O0Ooo % oO0o % I1IiiI * OoooooooOO
  return ( True , i1ii1i1Ii11 [ "rloc-probe" ] , i1ii1i1Ii11 [ "igmp-query" ] )
  if 4 - 4: OOooOOo % oO0o
 return ( False , False , False )
 if 18 - 18: Ii1I * I11i
 if 14 - 14: ooOoO0o . ooOoO0o * OoOoOO00 * o0oOOo0O0Ooo - iII111i - I1Ii111
 if 53 - 53: Oo0Ooo * OoOoOO00 * II111iiii % IiII - I1ii11iIi11i
 if 56 - 56: Oo0Ooo . I1ii11iIi11i - i11iIiiIii / iIii1I11I1II1 . ooOoO0o
 if 28 - 28: OoooooooOO + I1IiiI / oO0o . iIii1I11I1II1 - oO0o
 if 64 - 64: I1Ii111 + Oo0Ooo / iII111i
 if 61 - 61: Ii1I * Ii1I . OoOoOO00 + OoO0O00 * i11iIiiIii * OoO0O00
def lisp_build_gleaned_multicast ( seid , geid , rloc , port , igmp ) :
 iI1i1iIi1iiII = geid . print_address ( )
 Ii111I11iI = seid . print_address_no_iid ( )
 IiII1iiI = green ( "{}" . format ( Ii111I11iI ) , False )
 oOo = green ( "(*, {})" . format ( iI1i1iIi1iiII ) , False )
 O0OOOO0o0O = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 if 52 - 52: iIii1I11I1II1 + o0oOOo0O0Ooo + oO0o + o0oOOo0O0Ooo
 if 55 - 55: OoOoOO00 - Ii1I
 if 35 - 35: OOooOOo / I1ii11iIi11i + OoOoOO00 / I1Ii111
 if 46 - 46: I1Ii111 + I1Ii111 / i11iIiiIii * OOooOOo
 I1iOo0 = lisp_map_cache_lookup ( seid , geid )
 if ( I1iOo0 == None ) :
  I1iOo0 = lisp_mapping ( "" , "" , [ ] )
  I1iOo0 . group . copy_address ( geid )
  I1iOo0 . eid . copy_address ( geid )
  I1iOo0 . eid . address = 0
  I1iOo0 . eid . mask_len = 0
  I1iOo0 . mapping_source . copy_address ( rloc )
  I1iOo0 . map_cache_ttl = LISP_IGMP_TTL
  I1iOo0 . gleaned = True
  I1iOo0 . add_cache ( )
  lprint ( "Add gleaned EID {} to map-cache" . format ( oOo ) )
  if 39 - 39: oO0o + I1IiiI * iII111i + OOooOOo
  if 84 - 84: i1IIi * I11i / o0oOOo0O0Ooo
  if 23 - 23: O0 % Ii1I / I11i / I1Ii111 . i1IIi
  if 99 - 99: ooOoO0o / II111iiii * I1ii11iIi11i
  if 61 - 61: I11i . II111iiii
  if 59 - 59: i11iIiiIii . I1ii11iIi11i * I1IiiI . O0 - I1Ii111 - OoO0O00
 oo0OOOoO0OoO = IiI1iiII = i1iiiIIi11 = None
 if ( I1iOo0 . rloc_set != [ ] ) :
  oo0OOOoO0OoO = I1iOo0 . rloc_set [ 0 ]
  if ( oo0OOOoO0OoO . rle ) :
   IiI1iiII = oo0OOOoO0OoO . rle
   for Oo00oo0O00O in IiI1iiII . rle_nodes :
    if ( Oo00oo0O00O . rloc_name != Ii111I11iI ) : continue
    i1iiiIIi11 = Oo00oo0O00O
    break
    if 83 - 83: OoooooooOO . Ii1I * i11iIiiIii / o0oOOo0O0Ooo / I1Ii111 - OOooOOo
    if 69 - 69: I1IiiI - I1IiiI / I1IiiI - iIii1I11I1II1 * Ii1I . Ii1I
    if 28 - 28: ooOoO0o % IiII
    if 3 - 3: I1ii11iIi11i / ooOoO0o * OoOoOO00 * o0oOOo0O0Ooo / oO0o + O0
    if 8 - 8: o0oOOo0O0Ooo * OoOoOO00 / i1IIi
    if 87 - 87: i1IIi * OoooooooOO / O0 - II111iiii - i1IIi + OoO0O00
    if 11 - 11: OOooOOo / I1ii11iIi11i . OOooOOo + i1IIi - OoooooooOO * II111iiii
 if ( oo0OOOoO0OoO == None ) :
  oo0OOOoO0OoO = lisp_rloc ( )
  I1iOo0 . rloc_set = [ oo0OOOoO0OoO ]
  oo0OOOoO0OoO . priority = 253
  oo0OOOoO0OoO . mpriority = 255
  I1iOo0 . build_best_rloc_set ( )
  if 80 - 80: I11i % Oo0Ooo % I1Ii111 / OoO0O00 + II111iiii
 if ( IiI1iiII == None ) :
  IiI1iiII = lisp_rle ( geid . print_address ( ) )
  oo0OOOoO0OoO . rle = IiI1iiII
  if 40 - 40: Ii1I + O0 . i11iIiiIii % I11i / Oo0Ooo
 if ( i1iiiIIi11 == None ) :
  i1iiiIIi11 = lisp_rle_node ( )
  i1iiiIIi11 . rloc_name = Ii111I11iI
  IiI1iiII . rle_nodes . append ( i1iiiIIi11 )
  IiI1iiII . build_forwarding_list ( )
  lprint ( "Add RLE {} from {} for gleaned EID {}" . format ( O0OOOO0o0O , IiII1iiI , oOo ) )
 elif ( rloc . is_exact_match ( i1iiiIIi11 . address ) == False or
 port != i1iiiIIi11 . translated_port ) :
  lprint ( "Changed RLE {} from {} for gleaned EID {}" . format ( O0OOOO0o0O , IiII1iiI , oOo ) )
  if 25 - 25: IiII * IiII
  if 54 - 54: I1Ii111
  if 90 - 90: Oo0Ooo / Ii1I
  if 66 - 66: i11iIiiIii - I11i + oO0o . OoooooooOO
  if 77 - 77: OoO0O00 / OOooOOo
 i1iiiIIi11 . store_translated_rloc ( rloc , port )
 if 97 - 97: OoOoOO00 / Ii1I * I1IiiI - Oo0Ooo % O0
 if 66 - 66: O0 + I1IiiI % iIii1I11I1II1 . i1IIi % II111iiii - i1IIi
 if 93 - 93: O0 + OoooooooOO % IiII % oO0o % I1ii11iIi11i
 if 36 - 36: I1IiiI - oO0o * Oo0Ooo + oO0o % iII111i - i11iIiiIii
 if 93 - 93: O0
 if ( igmp ) :
  iI1ii111i1i = seid . print_address ( )
  if ( lisp_gleaned_groups . has_key ( iI1ii111i1i ) == False ) :
   lisp_gleaned_groups [ iI1ii111i1i ] = { }
   if 11 - 11: OoooooooOO . I1ii11iIi11i + I1ii11iIi11i
  lisp_gleaned_groups [ iI1ii111i1i ] [ iI1i1iIi1iiII ] = lisp_get_timestamp ( )
  if 73 - 73: OoooooooOO
  if 2 - 2: o0oOOo0O0Ooo % IiII + I1ii11iIi11i - i11iIiiIii
  if 100 - 100: II111iiii + oO0o
  if 85 - 85: I1ii11iIi11i % I1ii11iIi11i . Ii1I
  if 42 - 42: oO0o + OoO0O00
  if 16 - 16: Ii1I
  if 67 - 67: I1ii11iIi11i . OoooooooOO * I1Ii111 + Ii1I * OOooOOo
  if 84 - 84: OOooOOo
def lisp_remove_gleaned_multicast ( seid , geid ) :
 if 78 - 78: O0 % O0
 if 72 - 72: o0oOOo0O0Ooo * IiII / II111iiii / iIii1I11I1II1
 if 41 - 41: iII111i / Ii1I
 if 11 - 11: Oo0Ooo % OOooOOo . ooOoO0o
 I1iOo0 = lisp_map_cache_lookup ( seid , geid )
 if ( I1iOo0 == None ) : return
 if 24 - 24: IiII / Oo0Ooo
 iI1Ii11 = I1iOo0 . rloc_set [ 0 ] . rle
 if ( iI1Ii11 == None ) : return
 if 90 - 90: ooOoO0o . OOooOOo - Ii1I
 I1io0 = seid . print_address_no_iid ( )
 O00o0 = False
 for i1iiiIIi11 in iI1Ii11 . rle_nodes :
  if ( i1iiiIIi11 . rloc_name == I1io0 ) :
   O00o0 = True
   break
   if 60 - 60: i11iIiiIii % iII111i . I1IiiI * I1ii11iIi11i
   if 30 - 30: Ii1I + i11iIiiIii . I11i + o0oOOo0O0Ooo - OoO0O00
 if ( O00o0 == False ) : return
 if 55 - 55: ooOoO0o - II111iiii . ooOoO0o . iII111i / OoooooooOO
 if 51 - 51: I1IiiI * I1Ii111 - ooOoO0o + IiII
 if 22 - 22: OoOoOO00 % Ii1I + iII111i
 if 64 - 64: ooOoO0o
 iI1Ii11 . rle_nodes . remove ( i1iiiIIi11 )
 iI1Ii11 . build_forwarding_list ( )
 if 87 - 87: IiII - Ii1I / Oo0Ooo / I1ii11iIi11i . iII111i
 iI1i1iIi1iiII = geid . print_address ( )
 iI1ii111i1i = seid . print_address ( )
 IiII1iiI = green ( "{}" . format ( iI1ii111i1i ) , False )
 oOo = green ( "(*, {})" . format ( iI1i1iIi1iiII ) , False )
 lprint ( "Gleaned EID {} RLE removed for {}" . format ( oOo , IiII1iiI ) )
 if 49 - 49: IiII * OoooooooOO * iIii1I11I1II1 * Oo0Ooo / iII111i % oO0o
 if 88 - 88: I1Ii111 * OOooOOo
 if 38 - 38: Oo0Ooo - OoooooooOO - OoooooooOO / II111iiii
 if 10 - 10: II111iiii - OoO0O00 / II111iiii % Ii1I - OoOoOO00
 if ( lisp_gleaned_groups . has_key ( iI1ii111i1i ) ) :
  if ( lisp_gleaned_groups [ iI1ii111i1i ] . has_key ( iI1i1iIi1iiII ) ) :
   lisp_gleaned_groups [ iI1ii111i1i ] . pop ( iI1i1iIi1iiII )
   if 90 - 90: I11i + II111iiii - oO0o - ooOoO0o / ooOoO0o / i11iIiiIii
   if 80 - 80: I1ii11iIi11i % O0 / II111iiii + iII111i
   if 22 - 22: Oo0Ooo + ooOoO0o . OOooOOo % Oo0Ooo . IiII
   if 34 - 34: Ii1I . OoOoOO00 - OOooOOo * Oo0Ooo - ooOoO0o . oO0o
   if 42 - 42: O0 + OoO0O00
   if 47 - 47: O0 % OoOoOO00 + Ii1I * iIii1I11I1II1
 if ( iI1Ii11 . rle_nodes == [ ] ) :
  I1iOo0 . delete_cache ( )
  lprint ( "Gleaned EID {} remove, no more RLEs" . format ( oOo ) )
  if 55 - 55: Ii1I
  if 93 - 93: iII111i + OOooOOo . OoooooooOO . I1Ii111 . O0
  if 46 - 46: i11iIiiIii
  if 26 - 26: I11i * Oo0Ooo % OoO0O00 + Oo0Ooo - I1ii11iIi11i
  if 74 - 74: i1IIi + OoO0O00 . II111iiii + I1Ii111
  if 59 - 59: Ii1I . i11iIiiIii . o0oOOo0O0Ooo * iIii1I11I1II1 . OoOoOO00 . II111iiii
  if 67 - 67: OoO0O00 - Oo0Ooo + OOooOOo / OoOoOO00 + OOooOOo
  if 18 - 18: Oo0Ooo % OoOoOO00 % i1IIi
def lisp_change_gleaned_multicast ( seid , rloc , port ) :
 iI1ii111i1i = seid . print_address ( )
 if ( lisp_gleaned_groups . has_key ( iI1ii111i1i ) == False ) : return
 if 66 - 66: OoOoOO00 % II111iiii
 for IIi1iiIII11 in lisp_gleaned_groups [ iI1ii111i1i ] :
  lisp_geid . store_address ( IIi1iiIII11 )
  lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , port , False )
  if 16 - 16: i11iIiiIii - I1IiiI + ooOoO0o * oO0o
  if 30 - 30: II111iiii / o0oOOo0O0Ooo
  if 57 - 57: I11i / I1ii11iIi11i . I11i
  if 68 - 68: OoOoOO00 + O0 . I1IiiI
  if 26 - 26: I1ii11iIi11i
  if 98 - 98: Oo0Ooo
  if 72 - 72: oO0o + OoooooooOO . O0 + IiII
  if 49 - 49: i1IIi - i11iIiiIii + II111iiii + Ii1I / OoO0O00
  if 34 - 34: I1ii11iIi11i * i11iIiiIii
  if 6 - 6: I1ii11iIi11i + I1IiiI / OoooooooOO % I11i * Oo0Ooo
  if 20 - 20: Oo0Ooo
  if 85 - 85: I1Ii111
  if 98 - 98: OoO0O00 - IiII % iIii1I11I1II1 . OoOoOO00 + i1IIi + OoooooooOO
  if 29 - 29: I1ii11iIi11i * I1Ii111 - i1IIi * i11iIiiIii * iIii1I11I1II1 % I11i
  if 73 - 73: OoO0O00 . I1IiiI / o0oOOo0O0Ooo
  if 12 - 12: I11i * i11iIiiIii - O0 * o0oOOo0O0Ooo - IiII + I1IiiI
  if 7 - 7: oO0o + I1Ii111 . o0oOOo0O0Ooo / IiII + iIii1I11I1II1 % I1Ii111
  if 24 - 24: i11iIiiIii + iIii1I11I1II1
  if 22 - 22: i11iIiiIii . II111iiii / o0oOOo0O0Ooo / Ii1I . O0 . OoOoOO00
  if 89 - 89: O0 * Oo0Ooo + I1Ii111 + ooOoO0o * OoOoOO00
  if 20 - 20: OoO0O00 - OoOoOO00
  if 84 - 84: iIii1I11I1II1 + ooOoO0o . o0oOOo0O0Ooo % iII111i
  if 35 - 35: I11i - oO0o * oO0o / OoooooooOO + iII111i + OoOoOO00
  if 48 - 48: I1Ii111 / o0oOOo0O0Ooo - OOooOOo / o0oOOo0O0Ooo % O0
  if 38 - 38: OoO0O00 + o0oOOo0O0Ooo / OoO0O00
  if 74 - 74: oO0o - i1IIi . Oo0Ooo / I1IiiI + o0oOOo0O0Ooo . OoOoOO00
  if 35 - 35: iII111i / Ii1I
  if 57 - 57: ooOoO0o . I1IiiI * OOooOOo
  if 87 - 87: I11i - I11i % iII111i - Ii1I
  if 29 - 29: oO0o - ooOoO0o * iIii1I11I1II1 / OoOoOO00
  if 34 - 34: I1IiiI . Oo0Ooo
  if 4 - 4: Ii1I - II111iiii * iII111i / oO0o - I1IiiI
  if 32 - 32: iIii1I11I1II1 - I11i
  if 49 - 49: I11i * I1Ii111 - iIii1I11I1II1 * O0
  if 72 - 72: I1IiiI * iII111i
  if 61 - 61: Ii1I * Oo0Ooo * I1Ii111 % I11i + iII111i % oO0o
  if 67 - 67: IiII
  if 90 - 90: o0oOOo0O0Ooo
  if 5 - 5: i1IIi
  if 55 - 55: Ii1I
  if 46 - 46: OOooOOo / iII111i . i1IIi . i11iIiiIii . iIii1I11I1II1 % I11i
  if 62 - 62: I11i % II111iiii % OoooooooOO * ooOoO0o / oO0o
  if 29 - 29: o0oOOo0O0Ooo / O0 / OoO0O00
  if 23 - 23: Ii1I + i11iIiiIii % IiII
  if 64 - 64: i11iIiiIii + OoooooooOO . oO0o * Ii1I
  if 49 - 49: O0
  if 72 - 72: I1Ii111
  if 96 - 96: II111iiii / OOooOOo % i1IIi / Oo0Ooo
  if 22 - 22: I1IiiI % iIii1I11I1II1 % I1ii11iIi11i
  if 68 - 68: iII111i + I11i
  if 61 - 61: oO0o . I1Ii111
  if 74 - 74: O0 . Ii1I - iII111i % IiII + II111iiii
  if 71 - 71: oO0o + Ii1I % oO0o
  if 17 - 17: I1Ii111 % I1Ii111 * o0oOOo0O0Ooo
  if 84 - 84: I1Ii111 + iII111i . i1IIi / O0 / I1Ii111 + o0oOOo0O0Ooo
  if 70 - 70: O0 % ooOoO0o - iII111i + oO0o
  if 12 - 12: I1Ii111 - OoO0O00 % II111iiii % ooOoO0o / II111iiii % OoOoOO00
  if 74 - 74: iII111i . OOooOOo * Ii1I / Oo0Ooo . OoO0O00 . I11i
  if 65 - 65: i11iIiiIii - OoO0O00 / OoooooooOO * I1IiiI % iII111i
  if 15 - 15: OOooOOo * Ii1I / ooOoO0o
  if 70 - 70: i11iIiiIii * oO0o . I11i - OoooooooOO / I1ii11iIi11i
  if 10 - 10: IiII * OoOoOO00 . II111iiii . II111iiii * Oo0Ooo
  if 23 - 23: I1ii11iIi11i + I11i
  if 74 - 74: i1IIi % I1IiiI
  if 44 - 44: Oo0Ooo - OoooooooOO % ooOoO0o + II111iiii
  if 60 - 60: o0oOOo0O0Ooo - ooOoO0o + i11iIiiIii % I1ii11iIi11i % II111iiii
  if 62 - 62: Ii1I
  if 30 - 30: iII111i % O0 + II111iiii * I1IiiI
  if 91 - 91: i11iIiiIii
  if 35 - 35: OoOoOO00 * I1Ii111 / Oo0Ooo - i1IIi - IiII + OOooOOo
  if 96 - 96: Oo0Ooo + I1ii11iIi11i . O0
  if 62 - 62: i1IIi % OoooooooOO % OoooooooOO
  if 53 - 53: O0 * oO0o
  if 22 - 22: OOooOOo % Oo0Ooo % ooOoO0o - O0 + i1IIi
  if 67 - 67: OoO0O00 / I1IiiI - IiII + iII111i - iII111i
  if 4 - 4: IiII . Ii1I . IiII % OoO0O00
  if 12 - 12: OoOoOO00 + O0 / O0 . i1IIi
  if 58 - 58: IiII . iII111i % O0 . Ii1I * Oo0Ooo
  if 54 - 54: OoO0O00 % OOooOOo - OoO0O00 . Oo0Ooo % i1IIi
  if 95 - 95: iII111i . OoooooooOO . o0oOOo0O0Ooo / II111iiii - OoooooooOO / I1Ii111
  if 11 - 11: II111iiii / iII111i . oO0o / ooOoO0o / OOooOOo + OoO0O00
  if 37 - 37: iIii1I11I1II1 * O0
  if 64 - 64: I1Ii111 - II111iiii + oO0o % ooOoO0o * oO0o
  if 27 - 27: iIii1I11I1II1 - Ii1I . i11iIiiIii / IiII . I1Ii111 / i11iIiiIii
  if 27 - 27: OoOoOO00 . I11i / OoOoOO00
  if 96 - 96: OoO0O00 - I1IiiI
  if 73 - 73: I1IiiI - o0oOOo0O0Ooo - I1Ii111
  if 34 - 34: iIii1I11I1II1 - i1IIi + OoO0O00 % Oo0Ooo + i1IIi
  if 46 - 46: I1IiiI
  if 82 - 82: iII111i . i1IIi
  if 38 - 38: Ii1I . I1IiiI . I1ii11iIi11i
  if 26 - 26: O0 - II111iiii * I1Ii111 - OoOoOO00
igmp_types = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 96 - 96: I11i * Oo0Ooo / OOooOOo - IiII
lisp_igmp_record_types = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 75 - 75: OoooooooOO - O0
def lisp_process_igmp_packet ( packet ) :
 i1IIi1ii1i1ii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 i1IIi1ii1i1ii . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 i1IIi1ii1i1ii = bold ( "from {}" . format ( i1IIi1ii1i1ii . print_address_no_iid ( ) ) , False )
 if 39 - 39: i11iIiiIii / Ii1I / ooOoO0o
 O0OOOO0o0O = bold ( "Receive" , False )
 lprint ( "{} {}-byte {}, IGMP packet: {}" . format ( O0OOOO0o0O , len ( packet ) , i1IIi1ii1i1ii ,
 lisp_format_packet ( packet ) ) )
 if 93 - 93: o0oOOo0O0Ooo - Oo0Ooo / oO0o / OoOoOO00
 if 75 - 75: o0oOOo0O0Ooo * ooOoO0o % Ii1I
 if 94 - 94: OoooooooOO + II111iiii / iIii1I11I1II1 * ooOoO0o
 if 85 - 85: ooOoO0o / IiII
 iiIiii1ii = ( struct . unpack ( "B" , packet [ 0 ] ) [ 0 ] & 0x0f ) * 4
 if 59 - 59: I1Ii111 + I1ii11iIi11i + OoO0O00 % oO0o . i1IIi % O0
 if 22 - 22: i1IIi * OoOoOO00 + Ii1I
 if 48 - 48: Ii1I % IiII + OoO0O00 . IiII
 if 42 - 42: Ii1I
 o0ooOOooOo = packet [ iiIiii1ii : : ]
 ooOOooooOO00 = struct . unpack ( "B" , o0ooOOooOo [ 0 ] ) [ 0 ]
 if 65 - 65: i1IIi % i1IIi + O0 . O0 . I11i / o0oOOo0O0Ooo
 if 59 - 59: iIii1I11I1II1 . iII111i
 if 33 - 33: I1Ii111 - Ii1I / I11i
 if 17 - 17: OoO0O00
 if 85 - 85: IiII
 IIi1iiIII11 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 IIi1iiIII11 . address = socket . ntohl ( struct . unpack ( "II" , o0ooOOooOo [ : 8 ] ) [ 1 ] )
 iI1i1iIi1iiII = IIi1iiIII11 . print_address_no_iid ( )
 if 3 - 3: I11i % OOooOOo % OoO0O00
 if ( ooOOooooOO00 == 17 ) :
  lprint ( "IGMP Query for group {}" . format ( iI1i1iIi1iiII ) )
  return ( True )
  if 93 - 93: i11iIiiIii % I1IiiI
  if 81 - 81: iIii1I11I1II1 / Oo0Ooo - i11iIiiIii / I1IiiI * iII111i
 iiIIIII1 = ( ooOOooooOO00 in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( iiIIIII1 == False ) :
  O0oOO = "{} ({})" . format ( ooOOooooOO00 , igmp_types [ ooOOooooOO00 ] ) if igmp_types . has_key ( ooOOooooOO00 ) else ooOOooooOO00
  if 10 - 10: I1IiiI * oO0o + I1IiiI
  lprint ( "IGMP type {} not supported" . format ( O0oOO ) )
  return ( [ ] )
  if 17 - 17: o0oOOo0O0Ooo . Oo0Ooo % I11i
  if 43 - 43: IiII - O0 + I1Ii111 % OoooooooOO % OoO0O00 / I1Ii111
 if ( len ( o0ooOOooOo ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 48 - 48: I1ii11iIi11i . i1IIi % i1IIi - iII111i * o0oOOo0O0Ooo + IiII
  if 45 - 45: II111iiii . II111iiii + I1IiiI / I1Ii111 . OoO0O00 - o0oOOo0O0Ooo
  if 20 - 20: ooOoO0o % oO0o
  if 28 - 28: i1IIi . II111iiii + O0 / O0 % OoOoOO00 + OOooOOo
  if 24 - 24: OoooooooOO
 if ( ooOOooooOO00 == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( iI1i1iIi1iiII , False ) ) )
  return ( [ [ None , iI1i1iIi1iiII , False ] ] )
  if 11 - 11: i11iIiiIii / iIii1I11I1II1 % ooOoO0o + OOooOOo
 if ( ooOOooooOO00 in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( ooOOooooOO00 == 0x12 ) else 2 , bold ( iI1i1iIi1iiII , False ) ) )
  if 73 - 73: OoOoOO00 + OoooooooOO + iIii1I11I1II1 + II111iiii * iIii1I11I1II1 - OoOoOO00
  if 71 - 71: O0 * OOooOOo . I1IiiI . I1Ii111 * I11i
  if 45 - 45: O0 . O0 . II111iiii * ooOoO0o
  if 2 - 2: OoO0O00 . o0oOOo0O0Ooo
  if 48 - 48: Ii1I
  if ( iI1i1iIi1iiII . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
  else :
   return ( [ [ None , iI1i1iIi1iiII , True ] ] )
   if 45 - 45: I1ii11iIi11i - I11i + Ii1I
   if 82 - 82: iII111i
   if 81 - 81: i1IIi % OOooOOo - OoO0O00 - Oo0Ooo
   if 19 - 19: i1IIi
   if 97 - 97: OoO0O00 + i11iIiiIii % I1IiiI * Ii1I
  return ( [ ] )
  if 89 - 89: IiII % i11iIiiIii + OoO0O00 . oO0o / I1IiiI . Ii1I
  if 11 - 11: ooOoO0o - I1Ii111 - I11i + OoOoOO00
  if 20 - 20: I11i + O0
  if 27 - 27: Oo0Ooo
  if 12 - 12: I1ii11iIi11i . iII111i - iII111i - OOooOOo - iIii1I11I1II1
 o0ooO00 = IIi1iiIII11 . address
 o0ooOOooOo = o0ooOOooOo [ 8 : : ]
 if 50 - 50: I1IiiI - iIii1I11I1II1 . iII111i - Ii1I / I1Ii111 + iII111i
 I1111I = "BBHI"
 Oo0o0OoOoOO0O = struct . calcsize ( I1111I )
 OoO0ooo = "I"
 oOoo0 = struct . calcsize ( OoO0ooo )
 i1IIi1ii1i1ii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 9 - 9: o0oOOo0O0Ooo . o0oOOo0O0Ooo % OOooOOo - O0 * OoO0O00 . IiII
 if 41 - 41: O0 / Ii1I / OoO0O00 + iII111i
 if 14 - 14: I1IiiI * I1ii11iIi11i - Oo0Ooo * i1IIi / I1ii11iIi11i / OoO0O00
 if 12 - 12: OOooOOo + iIii1I11I1II1 % I1Ii111 + OOooOOo
 IIIII = [ ]
 for IiIIi1IiiIiI in range ( o0ooO00 ) :
  if ( len ( o0ooOOooOo ) < Oo0o0OoOoOO0O ) : return
  o0Oo , O0O , o0I111II , ii1i1II11II1i = struct . unpack ( I1111I ,
 o0ooOOooOo [ : Oo0o0OoOoOO0O ] )
  if 42 - 42: II111iiii . I1Ii111 * IiII . OoO0O00 * OoooooooOO
  o0ooOOooOo = o0ooOOooOo [ Oo0o0OoOoOO0O : : ]
  if 53 - 53: i11iIiiIii * OoO0O00
  if ( lisp_igmp_record_types . has_key ( o0Oo ) == False ) :
   lprint ( "Invalid record type {}" . format ( o0Oo ) )
   continue
   if 73 - 73: OOooOOo * i11iIiiIii - OoO0O00
   if 94 - 94: O0
  Oo000oOo = lisp_igmp_record_types [ o0Oo ]
  o0I111II = socket . ntohs ( o0I111II )
  IIi1iiIII11 . address = socket . ntohl ( ii1i1II11II1i )
  iI1i1iIi1iiII = IIi1iiIII11 . print_address_no_iid ( )
  if 92 - 92: Ii1I . o0oOOo0O0Ooo - i1IIi + i11iIiiIii + Ii1I
  lprint ( "Record type: {}, group: {}, source-count: {}" . format ( Oo000oOo , iI1i1iIi1iiII , o0I111II ) )
  if 21 - 21: IiII . i1IIi
  if 48 - 48: i1IIi
  if 56 - 56: II111iiii + i1IIi - oO0o * I1ii11iIi11i % i1IIi
  if 48 - 48: ooOoO0o + I1IiiI - o0oOOo0O0Ooo + Ii1I
  if 99 - 99: OOooOOo / II111iiii + II111iiii + I11i
  if 9 - 9: i11iIiiIii
  if 27 - 27: I1Ii111 * O0
  IiIIiiiii = False
  if ( o0Oo in ( 1 , 5 ) ) : IiIIiiiii = True
  if ( o0Oo in ( 2 , 4 ) and o0I111II == 0 ) : IiIIiiiii = True
  I1Iii1 = "join" if ( IiIIiiiii ) else "leave"
  if 31 - 31: I11i % iII111i + i11iIiiIii * I1Ii111
  if 47 - 47: OoooooooOO + II111iiii / iIii1I11I1II1 * i1IIi * Ii1I . I11i
  if 87 - 87: Oo0Ooo / IiII * OOooOOo + I1ii11iIi11i . I11i
  if 56 - 56: oO0o + oO0o % o0oOOo0O0Ooo + OOooOOo . II111iiii + i11iIiiIii
  if ( iI1i1iIi1iiII . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   continue
   if 45 - 45: iIii1I11I1II1 / o0oOOo0O0Ooo * OoooooooOO - Oo0Ooo
   if 77 - 77: II111iiii
   if 8 - 8: I1IiiI * II111iiii % I1ii11iIi11i
   if 88 - 88: Oo0Ooo . oO0o + OoOoOO00 % OoooooooOO
   if 81 - 81: OoooooooOO . I1Ii111 + OoO0O00 % I1Ii111
   if 49 - 49: oO0o . oO0o % oO0o / Oo0Ooo
   if 62 - 62: ooOoO0o . i1IIi % OoO0O00 - I1ii11iIi11i - IiII
   if 57 - 57: i1IIi - II111iiii - O0 . iII111i + OoO0O00
  if ( o0I111II == 0 ) :
   IIIII . append ( [ None , iI1i1iIi1iiII , IiIIiiiii ] )
   lprint ( "IGMPv3 {} (*, {})" . format ( bold ( I1Iii1 , False ) ,
 bold ( iI1i1iIi1iiII , False ) ) )
   if 67 - 67: OOooOOo * iII111i / iIii1I11I1II1 / I1ii11iIi11i
   if 10 - 10: OoooooooOO % I1ii11iIi11i * i1IIi . iII111i
   if 96 - 96: II111iiii % i11iIiiIii - Oo0Ooo
   if 70 - 70: O0 * iIii1I11I1II1 - IiII * I11i / Ii1I + i11iIiiIii
   if 26 - 26: II111iiii - I11i % I11i / ooOoO0o + Oo0Ooo
  for oooOi1II1II111 in range ( o0I111II ) :
   if ( len ( o0ooOOooOo ) < oOoo0 ) : return
   ii1i1II11II1i = struct . unpack ( OoO0ooo , o0ooOOooOo [ : oOoo0 ] ) [ 0 ]
   i1IIi1ii1i1ii . address = socket . ntohl ( ii1i1II11II1i )
   OoO0O0oOooO = i1IIi1ii1i1ii . print_address_no_iid ( )
   IIIII . append ( [ OoO0O0oOooO , iI1i1iIi1iiII , IiIIiiiii ] )
   lprint ( "{} ({}, {})" . format ( I1Iii1 ,
 green ( OoO0O0oOooO , False ) , bold ( iI1i1iIi1iiII , False ) ) )
   o0ooOOooOo = o0ooOOooOo [ oOoo0 : : ]
   if 40 - 40: OoooooooOO
   if 71 - 71: OOooOOo
   if 88 - 88: O0
   if 44 - 44: II111iiii - IiII / I1IiiI + ooOoO0o % iII111i - iII111i
   if 53 - 53: OoooooooOO
   if 41 - 41: i1IIi - oO0o
   if 41 - 41: I11i
   if 92 - 92: i11iIiiIii
 return ( IIIII )
 if 62 - 62: i1IIi / I1IiiI - o0oOOo0O0Ooo
 if 3 - 3: O0 * OoOoOO00 * I11i / OoOoOO00
 if 77 - 77: i1IIi
 if 3 - 3: iII111i * OoO0O00 - oO0o + iII111i . o0oOOo0O0Ooo + I1IiiI
 if 65 - 65: O0 / OoOoOO00
 if 77 - 77: OoO0O00
 if 17 - 17: i1IIi
 if 35 - 35: OoOoOO00
lisp_geid = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
if 61 - 61: I1Ii111
def lisp_glean_map_cache ( seid , rloc , encap_port , igmp ) :
 if 78 - 78: I1Ii111 * Ii1I % Ii1I + I1IiiI
 if 83 - 83: iIii1I11I1II1 + O0 / IiII . iIii1I11I1II1
 if 74 - 74: Oo0Ooo
 if 60 - 60: OoooooooOO
 if 16 - 16: iIii1I11I1II1 - OoOoOO00 / I1ii11iIi11i % O0 % o0oOOo0O0Ooo
 if 99 - 99: ooOoO0o . o0oOOo0O0Ooo - O0 * I1Ii111 . i11iIiiIii / iIii1I11I1II1
 IiiIIi = True
 I1iOo0 = lisp_map_cache . lookup_cache ( seid , True )
 if ( I1iOo0 and len ( I1iOo0 . rloc_set ) != 0 ) :
  I1iOo0 . last_refresh_time = lisp_get_timestamp ( )
  if 69 - 69: i1IIi + O0
  OOooOo0000OOo = I1iOo0 . rloc_set [ 0 ]
  i11II1IIII1i = OOooOo0000OOo . rloc
  i1ioooOoO = OOooOo0000OOo . translated_port
  IiiIIi = ( i11II1IIII1i . is_exact_match ( rloc ) == False or
 i1ioooOoO != encap_port )
  if 41 - 41: II111iiii - I1ii11iIi11i - I1Ii111
  if ( IiiIIi ) :
   oOo = green ( seid . print_address ( ) , False )
   O0OOOO0o0O = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
   lprint ( "Change gleaned EID {} to RLOC {}" . format ( oOo , O0OOOO0o0O ) )
   OOooOo0000OOo . delete_from_rloc_probe_list ( I1iOo0 . eid , I1iOo0 . group )
   lisp_change_gleaned_multicast ( seid , rloc , encap_port )
   if 82 - 82: I1IiiI * I1IiiI / iIii1I11I1II1
 else :
  I1iOo0 = lisp_mapping ( "" , "" , [ ] )
  I1iOo0 . eid . copy_address ( seid )
  I1iOo0 . mapping_source . copy_address ( rloc )
  I1iOo0 . map_cache_ttl = LISP_GLEAN_TTL
  I1iOo0 . gleaned = True
  oOo = green ( seid . print_address ( ) , False )
  O0OOOO0o0O = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( oOo , O0OOOO0o0O ) )
  I1iOo0 . add_cache ( )
  if 14 - 14: I11i + Ii1I - OOooOOo % Ii1I / Ii1I
  if 86 - 86: I1Ii111 - i11iIiiIii + Ii1I + I11i
  if 96 - 96: Ii1I
  if 28 - 28: i1IIi . oO0o . IiII + Oo0Ooo . Oo0Ooo . i1IIi
  if 34 - 34: Oo0Ooo + IiII / i1IIi
 if ( IiiIIi ) :
  oo0OOOoO0OoO = lisp_rloc ( )
  oo0OOOoO0OoO . store_translated_rloc ( rloc , encap_port )
  oo0OOOoO0OoO . add_to_rloc_probe_list ( I1iOo0 . eid , I1iOo0 . group )
  oo0OOOoO0OoO . priority = 253
  oo0OOOoO0OoO . mpriority = 255
  Oo = [ oo0OOOoO0OoO ]
  I1iOo0 . rloc_set = Oo
  I1iOo0 . build_best_rloc_set ( )
  if 33 - 33: i1IIi
  if 26 - 26: ooOoO0o - Oo0Ooo * II111iiii - Oo0Ooo
  if 15 - 15: OoO0O00 - oO0o . OoOoOO00 / O0 * oO0o
  if 45 - 45: O0
  if 89 - 89: IiII - IiII % o0oOOo0O0Ooo * Oo0Ooo % ooOoO0o
 if ( igmp == None ) : return
 if 4 - 4: OoO0O00 % II111iiii / I11i
 if 95 - 95: I1Ii111 - I1Ii111 - iII111i + IiII . OoO0O00
 if 5 - 5: i11iIiiIii - O0 % ooOoO0o
 if 55 - 55: II111iiii
 if 7 - 7: I1Ii111 % o0oOOo0O0Ooo . oO0o . ooOoO0o % i1IIi / I1IiiI
 lisp_geid . instance_id = seid . instance_id
 if 88 - 88: i11iIiiIii / oO0o - i1IIi / I1IiiI
 if 57 - 57: oO0o + O0 * I11i
 if 87 - 87: o0oOOo0O0Ooo % Oo0Ooo * I1ii11iIi11i / OoooooooOO / o0oOOo0O0Ooo
 if 78 - 78: Ii1I
 if 5 - 5: i1IIi * ooOoO0o / OoOoOO00 % i11iIiiIii
 OoOOo00o0 = lisp_process_igmp_packet ( igmp )
 if ( type ( OoOOo00o0 ) == bool ) : return
 if 57 - 57: IiII
 for i1IIi1ii1i1ii , IIi1iiIII11 , IiIIiiiii in OoOOo00o0 :
  if ( i1IIi1ii1i1ii != None ) : continue
  if 89 - 89: I1ii11iIi11i - I1Ii111 + o0oOOo0O0Ooo
  if 62 - 62: I1ii11iIi11i + OoooooooOO * OOooOOo
  if 49 - 49: i1IIi - I11i * II111iiii
  if 4 - 4: o0oOOo0O0Ooo + o0oOOo0O0Ooo
  lisp_geid . store_address ( IIi1iiIII11 )
  I1IiIiI11I , O0O , OO0Oo00oo = lisp_allow_gleaning ( seid , lisp_geid , rloc )
  if ( I1IiIiI11I == False ) : continue
  if 57 - 57: I1IiiI * OOooOOo . i11iIiiIii * oO0o - OoOoOO00
  if ( IiIIiiiii ) :
   lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port ,
 True )
  else :
   lisp_remove_gleaned_multicast ( seid , lisp_geid )
   if 35 - 35: O0
   if 65 - 65: Oo0Ooo
   if 100 - 100: I1Ii111 . o0oOOo0O0Ooo * OoooooooOO . o0oOOo0O0Ooo
   if 90 - 90: i11iIiiIii . I1IiiI + ooOoO0o * OoooooooOO * OoooooooOO + oO0o
   if 77 - 77: OOooOOo * OoOoOO00
   if 75 - 75: Oo0Ooo * Oo0Ooo - IiII - OoOoOO00 / i11iIiiIii + I1Ii111
   if 57 - 57: i11iIiiIii / oO0o
   if 37 - 37: o0oOOo0O0Ooo + OoOoOO00 - i1IIi . Oo0Ooo
   if 3 - 3: ooOoO0o % OoooooooOO / I1Ii111 + oO0o - O0
   if 72 - 72: oO0o * OoO0O00
   if 89 - 89: OoooooooOO . OOooOOo
   if 96 - 96: o0oOOo0O0Ooo + OoOoOO00 / i11iIiiIii - o0oOOo0O0Ooo * i11iIiiIii + OOooOOo
def lisp_is_json_telemetry ( json_string ) :
 try :
  iiiI1IIIIIIi1 = json . loads ( json_string )
  if ( type ( iiiI1IIIIIIi1 ) != dict ) : return ( None )
 except :
  lprint ( "Could not decode telemetry json: {}" . format ( json_string ) )
  return ( None )
  if 16 - 16: IiII / I1Ii111 . II111iiii * I11i
  if 33 - 33: I1ii11iIi11i / Oo0Ooo % i11iIiiIii
 if ( iiiI1IIIIIIi1 . has_key ( "type" ) == False ) : return ( None )
 if ( iiiI1IIIIIIi1 . has_key ( "sub-type" ) == False ) : return ( None )
 if ( iiiI1IIIIIIi1 [ "type" ] != "telemetry" ) : return ( None )
 if ( iiiI1IIIIIIi1 [ "sub-type" ] != "timestamps" ) : return ( None )
 return ( iiiI1IIIIIIi1 )
 if 37 - 37: Oo0Ooo - I1Ii111 - IiII / oO0o % I1IiiI / I1Ii111
 if 80 - 80: iII111i - oO0o % i1IIi * iIii1I11I1II1 . oO0o
 if 86 - 86: Ii1I
 if 36 - 36: i11iIiiIii % i11iIiiIii
 if 91 - 91: Oo0Ooo + I1Ii111 % iII111i
 if 7 - 7: I1Ii111 + II111iiii
 if 63 - 63: OoO0O00 - o0oOOo0O0Ooo / iII111i % II111iiii * IiII
 if 71 - 71: IiII
 if 34 - 34: II111iiii
 if 7 - 7: IiII / I1ii11iIi11i
 if 88 - 88: iIii1I11I1II1 / o0oOOo0O0Ooo
 if 68 - 68: OoooooooOO % Ii1I + ooOoO0o / oO0o
def lisp_encode_telemetry ( json_string , ii = "?" , io = "?" , ei = "?" , eo = "?" ) :
 iiiI1IIIIIIi1 = lisp_is_json_telemetry ( json_string )
 if ( iiiI1IIIIIIi1 == None ) : return ( json_string )
 if 60 - 60: i11iIiiIii / O0 / I1IiiI
 if ( iiiI1IIIIIIi1 [ "itr-in" ] == "?" ) : iiiI1IIIIIIi1 [ "itr-in" ] = ii
 if ( iiiI1IIIIIIi1 [ "itr-out" ] == "?" ) : iiiI1IIIIIIi1 [ "itr-out" ] = io
 if ( iiiI1IIIIIIi1 [ "etr-in" ] == "?" ) : iiiI1IIIIIIi1 [ "etr-in" ] = ei
 if ( iiiI1IIIIIIi1 [ "etr-out" ] == "?" ) : iiiI1IIIIIIi1 [ "etr-out" ] = eo
 json_string = json . dumps ( iiiI1IIIIIIi1 )
 return ( json_string )
 if 99 - 99: I1IiiI / oO0o . OoO0O00 / ooOoO0o + IiII
 if 3 - 3: II111iiii . OOooOOo * i11iIiiIii / I11i
 if 16 - 16: I1ii11iIi11i - ooOoO0o + OoO0O00 . I11i / O0
 if 56 - 56: I1IiiI + Oo0Ooo * II111iiii + iIii1I11I1II1
 if 56 - 56: o0oOOo0O0Ooo * I1IiiI - I11i * I1Ii111 - I11i
 if 92 - 92: oO0o % iIii1I11I1II1 * o0oOOo0O0Ooo * OoooooooOO - iIii1I11I1II1
 if 51 - 51: Ii1I - OoO0O00 + i1IIi
 if 11 - 11: II111iiii - iII111i + oO0o % Oo0Ooo
 if 56 - 56: IiII
 if 72 - 72: Oo0Ooo
 if 37 - 37: i11iIiiIii * I1IiiI % ooOoO0o
 if 23 - 23: OoO0O00 + o0oOOo0O0Ooo * I1IiiI
def lisp_decode_telemetry ( json_string ) :
 iiiI1IIIIIIi1 = lisp_is_json_telemetry ( json_string )
 if ( iiiI1IIIIIIi1 == None ) : return ( { } )
 return ( iiiI1IIIIIIi1 )
 if 76 - 76: i1IIi . OOooOOo
 if 78 - 78: OoooooooOO % OoOoOO00 * oO0o . I1ii11iIi11i
 if 79 - 79: OoooooooOO
 if 6 - 6: i11iIiiIii / II111iiii + II111iiii + I1ii11iIi11i % IiII - I1ii11iIi11i
 if 92 - 92: IiII
 if 49 - 49: O0 . OoOoOO00
 if 7 - 7: i1IIi + II111iiii
 if 96 - 96: I1Ii111 / OoO0O00
 if 27 - 27: Ii1I
def lisp_telemetry_configured ( ) :
 if ( lisp_json_list . has_key ( "telemetry" ) == False ) : return ( None )
 if 90 - 90: I1ii11iIi11i
 II11iii = lisp_json_list [ "telemetry" ] . json_string
 if ( lisp_is_json_telemetry ( II11iii ) == None ) : return ( None )
 if 43 - 43: OoO0O00 . I1IiiI . oO0o + Ii1I
 return ( II11iii )
 if 7 - 7: iII111i / Oo0Ooo - OoO0O00 + I1Ii111 * II111iiii * ooOoO0o
 if 80 - 80: oO0o - i1IIi / I11i . II111iiii % O0 % I11i
 if 70 - 70: iIii1I11I1II1 * i1IIi * OOooOOo - Oo0Ooo % i1IIi
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
