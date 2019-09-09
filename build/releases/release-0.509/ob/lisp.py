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
lisp_last_map_request_sent = None
if 61 - 61: II111iiii
if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
if 42 - 42: OoO0O00
lisp_last_icmp_too_big_sent = 0
if 67 - 67: I1Ii111 . iII111i . O0
if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
LISP_FLOW_LOG_SIZE = 100
lisp_flow_log = [ ]
if 83 - 83: I11i / I1IiiI
if 34 - 34: IiII
if 57 - 57: oO0o . I11i . i1IIi
if 42 - 42: I11i + I1ii11iIi11i % O0
lisp_policies = { }
if 6 - 6: oO0o
if 68 - 68: OoOoOO00 - OoO0O00
if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
if 1 - 1: iIii1I11I1II1 / II111iiii
if 33 - 33: I11i
lisp_load_split_pings = False
if 18 - 18: o0oOOo0O0Ooo % iII111i * O0
if 87 - 87: i11iIiiIii
if 93 - 93: I1ii11iIi11i - OoO0O00 % i11iIiiIii . iII111i / iII111i - I1Ii111
if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
lisp_eid_hashes = [ ]
if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
if 51 - 51: O0 + iII111i
if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
if 48 - 48: O0
if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
if 41 - 41: Ii1I - O0 - O0
if 68 - 68: OOooOOo % I1Ii111
if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
lisp_reassembly_queue = { }
if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
if 23 - 23: O0
if 85 - 85: Ii1I
if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
lisp_pubsub_cache = { }
if 53 - 53: iII111i % II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
if 77 - 77: iIii1I11I1II1 * OoO0O00
if 95 - 95: I1IiiI + i11iIiiIii
if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
if 80 - 80: II111iiii
if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
lisp_decent_push_configured = False
if 53 - 53: II111iiii
if 31 - 31: OoO0O00
if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
if 25 - 25: OoO0O00
if 62 - 62: OOooOOo + O0
if 98 - 98: o0oOOo0O0Ooo
lisp_decent_modulus = 0
lisp_decent_dns_suffix = None
if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
if 82 - 82: Ii1I
if 46 - 46: OoooooooOO . i11iIiiIii
if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
if 87 - 87: Oo0Ooo . IiII
lisp_ipc_socket = None
if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
if 55 - 55: OOooOOo . I1IiiI
if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
if 100 - 100: I1Ii111 * O0
lisp_ms_encryption_keys = { }
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
if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
lisp_rtr_nat_trace_cache = { }
if 63 - 63: OoOoOO00 * iII111i
if 69 - 69: O0 . OoO0O00
if 49 - 49: I1IiiI - I11i
if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
if 62 - 62: OoooooooOO * I1IiiI
if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
if 97 - 97: O0 + OoOoOO00
if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
lisp_glean_mappings = [ ]
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
lisp_gleaned_groups = { }
if 11 - 11: ooOoO0o / OoOoOO00 - IiII * OoooooooOO + OoooooooOO . OoOoOO00
if 26 - 26: Ii1I % I1ii11iIi11i
if 76 - 76: IiII * iII111i
if 52 - 52: OOooOOo
if 19 - 19: I1IiiI
lisp_icmp_raw_socket = None
if ( os . getenv ( "LISP_SEND_ICMP_TOO_BIG" ) != None ) :
 lisp_icmp_raw_socket = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_ICMP )
 lisp_icmp_raw_socket . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 if 25 - 25: Ii1I / ooOoO0o
 if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
lisp_ignore_df_bit = ( os . getenv ( "LISP_IGNORE_DF_BIT" ) != None )
if 71 - 71: I1Ii111 . II111iiii
if 62 - 62: OoooooooOO . I11i
if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
if 58 - 58: I1IiiI
if 53 - 53: i1IIi
LISP_DATA_PORT = 4341
LISP_CTRL_PORT = 4342
LISP_L2_DATA_PORT = 8472
LISP_VXLAN_DATA_PORT = 4789
LISP_VXLAN_GPE_PORT = 4790
LISP_TRACE_PORT = 2434
if 59 - 59: o0oOOo0O0Ooo
if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
if 73 - 73: I11i % i11iIiiIii - I1IiiI
if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
LISP_MAP_REQUEST = 1
LISP_MAP_REPLY = 2
LISP_MAP_REGISTER = 3
LISP_MAP_NOTIFY = 4
LISP_MAP_NOTIFY_ACK = 5
LISP_MAP_REFERRAL = 6
LISP_NAT_INFO = 7
LISP_ECM = 8
LISP_TRACE = 9
if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
if 23 - 23: i11iIiiIii
if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
if 81 - 81: IiII % i1IIi . iIii1I11I1II1
LISP_NO_ACTION = 0
LISP_NATIVE_FORWARD_ACTION = 1
LISP_SEND_MAP_REQUEST_ACTION = 2
LISP_DROP_ACTION = 3
LISP_POLICY_DENIED_ACTION = 4
LISP_AUTH_FAILURE_ACTION = 5
if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
lisp_map_reply_action_string = [ "no-action" , "native-forward" ,
 "send-map-request" , "drop-action" , "policy-denied" , "auth-failure" ]
if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
if 31 - 31: OOooOOo
if 23 - 23: I1Ii111 . IiII
if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
LISP_NONE_ALG_ID = 0
LISP_SHA_1_96_ALG_ID = 1
LISP_SHA_256_128_ALG_ID = 2
LISP_MD5_AUTH_DATA_LEN = 16
LISP_SHA1_160_AUTH_DATA_LEN = 20
LISP_SHA2_256_AUTH_DATA_LEN = 32
if 42 - 42: Oo0Ooo
if 76 - 76: I1IiiI * iII111i % I1Ii111
if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
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
if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
if 42 - 42: I1IiiI
LISP_MR_TTL = ( 24 * 60 )
LISP_REGISTER_TTL = 3
LISP_SHORT_TTL = 1
LISP_NMR_TTL = 15
LISP_GLEAN_TTL = 15
LISP_IGMP_TTL = 240
if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
LISP_SITE_TIMEOUT_CHECK_INTERVAL = 60
LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL = 60
LISP_REFERRAL_TIMEOUT_CHECK_INTERVAL = 60
LISP_TEST_MR_INTERVAL = 60
LISP_MAP_NOTIFY_INTERVAL = 2
LISP_DDT_MAP_REQUEST_INTERVAL = 2
LISP_MAX_MAP_NOTIFY_RETRIES = 3
LISP_INFO_INTERVAL = 15
LISP_MAP_REQUEST_RATE_LIMIT = 5
LISP_ICMP_TOO_BIG_RATE_LIMIT = 1
if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
LISP_RLOC_PROBE_TTL = 64
LISP_RLOC_PROBE_INTERVAL = 10
LISP_RLOC_PROBE_REPLY_WAIT = 15
if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
LISP_DEFAULT_DYN_EID_TIMEOUT = 15
LISP_NONCE_ECHO_INTERVAL = 10
LISP_IGMP_TIMEOUT_INTERVAL = 180
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
LISP_CS_1024 = 0
LISP_CS_1024_G = 2
LISP_CS_1024_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 54 - 54: i1IIi + II111iiii
LISP_CS_2048_CBC = 1
LISP_CS_2048_CBC_G = 2
LISP_CS_2048_CBC_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
LISP_CS_25519_CBC = 2
LISP_CS_2048_GCM = 3
if 5 - 5: Ii1I
LISP_CS_3072 = 4
LISP_CS_3072_G = 2
LISP_CS_3072_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
if 46 - 46: IiII
LISP_CS_25519_GCM = 5
LISP_CS_25519_CHACHA = 6
if 45 - 45: ooOoO0o
LISP_4_32_MASK = 0xFFFFFFFF
LISP_8_64_MASK = 0xFFFFFFFFFFFFFFFF
LISP_16_128_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
if 17 - 17: OOooOOo / OOooOOo / I11i
if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
if 9 - 9: Ii1I
if 59 - 59: I1IiiI * II111iiii . O0
if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
def lisp_record_traceback ( * args ) :
 if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
 Oo0OO0000oooo = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
 IIII1iII = open ( "./logs/lisp-traceback.log" , "a" )
 IIII1iII . write ( "---------- Exception occurred: {} ----------\n" . format ( Oo0OO0000oooo ) )
 try :
  traceback . print_last ( file = IIII1iII )
 except :
  IIII1iII . write ( "traceback.print_last(file=fd) failed" )
  if 28 - 28: i1IIi - iII111i
 try :
  traceback . print_last ( )
 except :
  print ( "traceback.print_last() failed" )
  if 54 - 54: iII111i - O0 % OOooOOo
 IIII1iII . close ( )
 return
 if 73 - 73: O0 . OoOoOO00 + I1IiiI - I11i % I11i . I11i
 if 17 - 17: Ii1I - OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
 if 28 - 28: I11i
 if 58 - 58: OoOoOO00
 if 37 - 37: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i
 if 73 - 73: i11iIiiIii - IiII
 if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
def lisp_set_exception ( ) :
 sys . excepthook = lisp_record_traceback
 return
 if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
 if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
 if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
 if 91 - 91: i11iIiiIii / i1IIi + iII111i + ooOoO0o * i11iIiiIii
 if 66 - 66: iIii1I11I1II1 % i1IIi - O0 + I11i * I1Ii111 . IiII
 if 52 - 52: ooOoO0o + O0 . iII111i . I1ii11iIi11i . OoO0O00
 if 97 - 97: I1IiiI / iII111i
def lisp_is_raspbian ( ) :
 if ( platform . dist ( ) [ 0 ] != "debian" ) : return ( False )
 return ( platform . machine ( ) in [ "armv6l" , "armv7l" ] )
 if 71 - 71: II111iiii / i1IIi . I1ii11iIi11i % OoooooooOO . OoOoOO00
 if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
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
 return ( oOoOOo0oo0 . lower ( ) . find ( "amazon" ) != - 1 )
 if 60 - 60: ooOoO0o * I1Ii111 + Oo0Ooo
 if 19 - 19: OoO0O00 * I11i / I11i . OoooooooOO - OOooOOo + i11iIiiIii
 if 88 - 88: i11iIiiIii - ooOoO0o
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
 if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
 if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
 if 30 - 30: OoOoOO00
def lisp_on_gcp ( ) :
 oOoOOo0oo0 = commands . getoutput ( "sudo dmidecode -s bios-version" )
 return ( oOoOOo0oo0 . lower ( ) . find ( "google" ) != - 1 )
 if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
 if 26 - 26: II111iiii * OoOoOO00
 if 10 - 10: II111iiii . iII111i
 if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
 if 88 - 88: iII111i
 if 19 - 19: II111iiii * IiII + Ii1I
 if 65 - 65: OOooOOo . I1Ii111 . OoO0O00 . iII111i - OOooOOo
 if 19 - 19: i11iIiiIii + iII111i % ooOoO0o
def lisp_process_logfile ( ) :
 IIi = "./logs/lisp-{}.log" . format ( lisp_log_id )
 if ( os . path . exists ( IIi ) ) : return
 if 27 - 27: OOooOOo % Ii1I
 sys . stdout . close ( )
 sys . stdout = open ( IIi , "a" )
 if 58 - 58: OOooOOo * o0oOOo0O0Ooo + O0 % OOooOOo
 lisp_print_banner ( bold ( "logfile rotation" , False ) )
 return
 if 25 - 25: Oo0Ooo % I1ii11iIi11i * ooOoO0o
 if 6 - 6: iII111i . IiII * OoOoOO00 . i1IIi
 if 98 - 98: i1IIi
 if 65 - 65: OoOoOO00 / OoO0O00 % IiII
 if 45 - 45: OoOoOO00
 if 66 - 66: OoO0O00
 if 56 - 56: O0
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
def lisp_i_am ( name ) :
 global lisp_log_id , lisp_i_am_itr , lisp_i_am_etr , lisp_i_am_rtr
 global lisp_i_am_mr , lisp_i_am_ms , lisp_i_am_ddt , lisp_i_am_core
 global lisp_hostname
 if 23 - 23: oO0o - OOooOOo + I11i
 lisp_log_id = name
 if ( name == "itr" ) : lisp_i_am_itr = True
 if ( name == "etr" ) : lisp_i_am_etr = True
 if ( name == "rtr" ) : lisp_i_am_rtr = True
 if ( name == "mr" ) : lisp_i_am_mr = True
 if ( name == "ms" ) : lisp_i_am_ms = True
 if ( name == "ddt" ) : lisp_i_am_ddt = True
 if ( name == "core" ) : lisp_i_am_core = True
 if 12 - 12: I1IiiI / ooOoO0o % o0oOOo0O0Ooo / i11iIiiIii % OoooooooOO
 if 15 - 15: iIii1I11I1II1 % OoooooooOO - Oo0Ooo * Ii1I + I11i
 if 11 - 11: iII111i * Ii1I - OoOoOO00
 if 66 - 66: OoOoOO00 . i11iIiiIii - iII111i * o0oOOo0O0Ooo + OoooooooOO * I1ii11iIi11i
 if 74 - 74: Oo0Ooo
 lisp_hostname = socket . gethostname ( )
 OO000o00 = lisp_hostname . find ( "." )
 if ( OO000o00 != - 1 ) : lisp_hostname = lisp_hostname [ 0 : OO000o00 ]
 return
 if 46 - 46: OoO0O00
 if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
 if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
 if 68 - 68: OoooooooOO % II111iiii
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if 2 - 2: Ii1I - IiII
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
def lprint ( * args ) :
 IIIiIi = ( "force" in args )
 if ( lisp_debug_logging == False and IIIiIi == False ) : return
 if 34 - 34: OoooooooOO . O0 / oO0o * OoOoOO00 - I1ii11iIi11i
 lisp_process_logfile ( )
 Oo0OO0000oooo = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 Oo0OO0000oooo = Oo0OO0000oooo [ : - 3 ]
 print "{}: {}:" . format ( Oo0OO0000oooo , lisp_log_id ) ,
 if 36 - 36: i1IIi / O0 / OoO0O00 - O0 - i1IIi
 for ii1I11 in args :
  if ( ii1I11 == "force" ) : continue
  print ii1I11 ,
  if 99 - 99: OOooOOo
 print ""
 if 45 - 45: oO0o - OOooOOo * I1Ii111 / Oo0Ooo * II111iiii - I1Ii111
 try : sys . stdout . flush ( )
 except : pass
 return
 if 83 - 83: OoO0O00 % IiII . OoooooooOO
 if 52 - 52: ooOoO0o / i11iIiiIii - OOooOOo . IiII % iIii1I11I1II1 + o0oOOo0O0Ooo
 if 71 - 71: oO0o % I11i * OoOoOO00 . O0 / Ii1I . I1ii11iIi11i
 if 58 - 58: Oo0Ooo / oO0o
 if 44 - 44: OOooOOo
 if 54 - 54: Ii1I - I11i - I1Ii111 . iIii1I11I1II1
 if 79 - 79: Ii1I . OoO0O00
 if 40 - 40: o0oOOo0O0Ooo + Oo0Ooo . o0oOOo0O0Ooo % ooOoO0o
def dprint ( * args ) :
 if ( lisp_data_plane_logging ) : lprint ( * args )
 return
 if 15 - 15: Ii1I * Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - i11iIiiIii
 if 60 - 60: I1IiiI * I1Ii111 % OoO0O00 + oO0o
 if 52 - 52: i1IIi
 if 84 - 84: Ii1I / IiII
 if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
 if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
 if 37 - 37: i11iIiiIii + i1IIi
 if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
def debug ( * args ) :
 lisp_process_logfile ( )
 if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
 Oo0OO0000oooo = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 Oo0OO0000oooo = Oo0OO0000oooo [ : - 3 ]
 if 8 - 8: o0oOOo0O0Ooo
 print red ( ">>>" , False ) ,
 print "{}:" . format ( Oo0OO0000oooo ) ,
 for ii1I11 in args : print ii1I11 ,
 print red ( "<<<\n" , False )
 try : sys . stdout . flush ( )
 except : pass
 return
 if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
 if 78 - 78: Ii1I / II111iiii % OoOoOO00
 if 52 - 52: OOooOOo - iII111i * oO0o
 if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
 if 36 - 36: O0 + Oo0Ooo
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
def lisp_print_banner ( string ) :
 global lisp_version , lisp_hostname
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if ( lisp_version == "" ) :
  lisp_version = commands . getoutput ( "cat lisp-version.txt" )
  if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 Ooo = bold ( lisp_hostname , False )
 lprint ( "lispers.net LISP {} {}, version {}, hostname {}" . format ( string ,
 datetime . datetime . now ( ) , lisp_version , Ooo ) )
 return
 if 65 - 65: Oo0Ooo / I11i
 if 12 - 12: I11i % OoOoOO00
 if 48 - 48: iII111i . i11iIiiIii
 if 5 - 5: oO0o . I1ii11iIi11i . II111iiii . OoooooooOO
 if 96 - 96: i11iIiiIii - OOooOOo % O0 / OoO0O00
 if 100 - 100: iII111i / Ii1I - OoooooooOO % II111iiii - I1IiiI % OoOoOO00
 if 60 - 60: iIii1I11I1II1 + i1IIi
def green ( string , html ) :
 if ( html ) : return ( '<font color="green"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[92m" + string + "\033[0m" , html ) )
 if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if 53 - 53: Ii1I % Oo0Ooo
 if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
 if 41 - 41: Ii1I % I1ii11iIi11i
 if 12 - 12: OOooOOo
def green_last_sec ( string ) :
 return ( green ( string , True ) )
 if 69 - 69: OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 if 31 - 31: I11i % OOooOOo * I11i
 if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
 if 1 - 1: iIii1I11I1II1
 if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
def green_last_min ( string ) :
 return ( '<font color="#58D68D"><b>{}</b></font>' . format ( string ) )
 if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
 if 4 - 4: OoooooooOO . ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if 10 - 10: I1Ii111 % I1IiiI
 if 97 - 97: OoooooooOO - I1Ii111
 if 58 - 58: iIii1I11I1II1 + O0
 if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
def red ( string , html ) :
 if ( html ) : return ( '<font color="red"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[91m" + string + "\033[0m" , html ) )
 if 46 - 46: i11iIiiIii - O0 . oO0o
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 if 83 - 83: I1Ii111
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 if 50 - 50: IiII % i1IIi
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
def blue ( string , html ) :
 if ( html ) : return ( '<font color="blue"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[94m" + string + "\033[0m" , html ) )
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
 if 62 - 62: i1IIi - OoOoOO00
 if 62 - 62: i1IIi + Oo0Ooo % IiII
 if 28 - 28: I1ii11iIi11i . i1IIi
 if 10 - 10: OoO0O00 / Oo0Ooo
 if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
def bold ( string , html ) :
 if ( html ) : return ( "<b>{}</b>" . format ( string ) )
 return ( "\033[1m" + string + "\033[0m" )
 if 57 - 57: O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
def convert_font ( string ) :
 iI11iiii1I = [ [ "[91m" , red ] , [ "[92m" , green ] , [ "[94m" , blue ] , [ "[1m" , bold ] ]
 iiiiI1iiiIi = "[0m"
 if 84 - 84: OOooOOo
 for o0OoO00 in iI11iiii1I :
  IIIIIiII1 = o0OoO00 [ 0 ]
  iii11 = o0OoO00 [ 1 ]
  i1 = len ( IIIIIiII1 )
  OO000o00 = string . find ( IIIIIiII1 )
  if ( OO000o00 != - 1 ) : break
  if 95 - 95: OoO0O00 . i1IIi / i11iIiiIii
  if 38 - 38: Oo0Ooo - I11i . Oo0Ooo
 while ( OO000o00 != - 1 ) :
  ii1111i = string [ OO000o00 : : ] . find ( iiiiI1iiiIi )
  O0ooOO = string [ OO000o00 + i1 : OO000o00 + ii1111i ]
  string = string [ : OO000o00 ] + iii11 ( O0ooOO , True ) + string [ OO000o00 + ii1111i + i1 : : ]
  if 28 - 28: i11iIiiIii / o0oOOo0O0Ooo . iIii1I11I1II1 / II111iiii
  OO000o00 = string . find ( IIIIIiII1 )
  if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
  if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
  if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
  if 32 - 32: i11iIiiIii - I1Ii111
  if 53 - 53: OoooooooOO - IiII
 if ( string . find ( "[1m" ) != - 1 ) : string = convert_font ( string )
 return ( string )
 if 87 - 87: oO0o . I1IiiI
 if 17 - 17: Ii1I . i11iIiiIii
 if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
 if 63 - 63: oO0o
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 if 36 - 36: IiII
 if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
def lisp_space ( num ) :
 o0OooooOoOO = ""
 for i1i1IIIIIIIi in range ( num ) : o0OooooOoOO += "&#160;"
 return ( o0OooooOoOO )
 if 65 - 65: o0oOOo0O0Ooo
 if 7 - 7: IiII . OoOoOO00 / I1ii11iIi11i . OOooOOo * I11i - II111iiii
 if 37 - 37: I1Ii111 . OoOoOO00 / O0 * iII111i
 if 7 - 7: OoO0O00 * I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
 if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
def lisp_button ( string , url ) :
 iIIi1iI1I1IIi = '<button style="background-color:transparent;border-radius:10px; ' + 'type="button">'
 if 77 - 77: ooOoO0o / Oo0Ooo + ooOoO0o % o0oOOo0O0Ooo - I1IiiI * I1IiiI
 if 23 - 23: iII111i . II111iiii % I1ii11iIi11i - OoooooooOO * Oo0Ooo . iIii1I11I1II1
 if ( url == None ) :
  I1iI = iIIi1iI1I1IIi + string + "</button>"
 else :
  O0o00O0Oo0 = '<a href="{}">' . format ( url )
  o0 = lisp_space ( 2 )
  I1iI = o0 + O0o00O0Oo0 + iIIi1iI1I1IIi + string + "</button></a>" + o0
  if 35 - 35: IiII + i1IIi * oO0o - Ii1I . Oo0Ooo
 return ( I1iI )
 if 31 - 31: o0oOOo0O0Ooo
 if 15 - 15: O0 / Oo0Ooo % I1ii11iIi11i + o0oOOo0O0Ooo
 if 23 - 23: iIii1I11I1II1 + O0
 if 58 - 58: Oo0Ooo
 if 9 - 9: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo + OoooooooOO
 if 62 - 62: O0 / I1IiiI % O0 * OoO0O00 % I1IiiI
 if 33 - 33: I1IiiI . oO0o * OoO0O00 * iIii1I11I1II1
def lisp_print_cour ( string ) :
 o0OooooOoOO = '<font face="Courier New">{}</font>' . format ( string )
 return ( o0OooooOoOO )
 if 5 - 5: Oo0Ooo / IiII % O0 . I1Ii111 * IiII
 if 83 - 83: OOooOOo
 if 12 - 12: i1IIi . i1IIi - o0oOOo0O0Ooo
 if 26 - 26: iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
def lisp_print_sans ( string ) :
 o0OooooOoOO = '<font face="Sans-Serif">{}</font>' . format ( string )
 return ( o0OooooOoOO )
 if 93 - 93: i1IIi
 if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
 if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
 if 66 - 66: Oo0Ooo
 if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
 if 55 - 55: o0oOOo0O0Ooo . iII111i
 if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
def lisp_span ( string , hover_string ) :
 o0OooooOoOO = '<span title="{}">{}</span>' . format ( hover_string , string )
 return ( o0OooooOoOO )
 if 100 - 100: I1Ii111 . I1IiiI * I1Ii111 - I1IiiI . I11i * Ii1I
 if 89 - 89: OoO0O00 + IiII * I1Ii111
 if 28 - 28: OoooooooOO . oO0o % I1ii11iIi11i / i1IIi / OOooOOo
 if 36 - 36: o0oOOo0O0Ooo + I11i - IiII + iIii1I11I1II1 + OoooooooOO
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
def lisp_eid_help_hover ( output ) :
 OO0o0OO0 = '''Unicast EID format:
  For longest match lookups: 
    <address> or [<iid>]<address>
  For exact match lookups: 
    <prefix> or [<iid>]<prefix>
Multicast EID format:
  For longest match lookups:
    <address>-><group> or
    [<iid>]<address>->[<iid>]<group>'''
 if 56 - 56: i11iIiiIii - Oo0Ooo / iII111i / OoOoOO00
 if 43 - 43: o0oOOo0O0Ooo . iII111i . I11i + iIii1I11I1II1
 OoOOoO0oOo = lisp_span ( output , OO0o0OO0 )
 return ( OoOOoO0oOo )
 if 70 - 70: I11i % iIii1I11I1II1 . Oo0Ooo + Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 if 87 - 87: OoO0O00 % I1IiiI
 if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
def lisp_geo_help_hover ( output ) :
 OO0o0OO0 = '''EID format:
    <address> or [<iid>]<address>
    '<name>' or [<iid>]'<name>'
Geo-Point format:
    d-m-s-<N|S>-d-m-s-<W|E> or 
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>
Geo-Prefix format:
    d-m-s-<N|S>-d-m-s-<W|E>/<km> or
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>/<km>'''
 if 84 - 84: i11iIiiIii * OoO0O00
 if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
 OoOOoO0oOo = lisp_span ( output , OO0o0OO0 )
 return ( OoOOoO0oOo )
 if 30 - 30: O0 + I1ii11iIi11i + II111iiii
 if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
 if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
 if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
 if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
 if 64 - 64: i1IIi
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
def space ( num ) :
 o0OooooOoOO = ""
 for i1i1IIIIIIIi in range ( num ) : o0OooooOoOO += "&#160;"
 return ( o0OooooOoOO )
 if 18 - 18: OOooOOo + I1Ii111
 if 80 - 80: oO0o + o0oOOo0O0Ooo * Ii1I + OoO0O00
 if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 if 50 - 50: ooOoO0o + i1IIi
 if 31 - 31: Ii1I
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
def lisp_get_ephemeral_port ( ) :
 return ( random . randrange ( 32768 , 65535 ) )
 if 47 - 47: o0oOOo0O0Ooo
 if 66 - 66: I1IiiI - IiII
 if 33 - 33: I1IiiI / OoO0O00
 if 12 - 12: II111iiii
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
def lisp_get_data_nonce ( ) :
 return ( random . randint ( 0 , 0xffffff ) )
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if 47 - 47: iII111i
 if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 if 47 - 47: oO0o % iIii1I11I1II1
 if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
def lisp_get_control_nonce ( ) :
 return ( random . randint ( 0 , ( 2 ** 64 ) - 1 ) )
 if 98 - 98: iII111i + Ii1I - OoO0O00
 if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
 if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
 if 38 - 38: O0 - IiII % I1Ii111
 if 64 - 64: iIii1I11I1II1
 if 15 - 15: I1ii11iIi11i + OOooOOo / I1ii11iIi11i / I1Ii111
 if 31 - 31: ooOoO0o + O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / o0oOOo0O0Ooo
 if 6 - 6: Oo0Ooo % IiII * I11i / I1IiiI + Oo0Ooo
 if 39 - 39: OoOoOO00 - Oo0Ooo / iII111i * OoooooooOO
def lisp_hex_string ( integer_value ) :
 Oooo0oOOO0 = hex ( integer_value ) [ 2 : : ]
 if ( Oooo0oOOO0 [ - 1 ] == "L" ) : Oooo0oOOO0 = Oooo0oOOO0 [ 0 : - 1 ]
 return ( Oooo0oOOO0 )
 if 61 - 61: o0oOOo0O0Ooo / OoOoOO00 - Oo0Ooo
 if 19 - 19: iII111i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + Oo0Ooo
 if 98 - 98: iIii1I11I1II1 % OOooOOo + I11i . ooOoO0o
 if 99 - 99: O0 + O0 * I11i + O0 * oO0o
 if 80 - 80: I1IiiI . Ii1I
 if 47 - 47: I11i + ooOoO0o + II111iiii % i11iIiiIii
 if 93 - 93: I1ii11iIi11i % OoOoOO00 . O0 / iII111i * oO0o
def lisp_get_timestamp ( ) :
 return ( time . time ( ) )
 if 29 - 29: o0oOOo0O0Ooo
 if 86 - 86: II111iiii . IiII
 if 2 - 2: OoooooooOO
 if 60 - 60: OoO0O00
 if 81 - 81: OoOoOO00 % Ii1I
 if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
def lisp_set_timestamp ( seconds ) :
 return ( time . time ( ) + seconds )
 if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 if 29 - 29: O0 . I1Ii111
 if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
def lisp_print_elapsed ( ts ) :
 if ( ts == 0 or ts == None ) : return ( "never" )
 o0O0oO0 = time . time ( ) - ts
 o0O0oO0 = round ( o0O0oO0 , 0 )
 return ( str ( datetime . timedelta ( seconds = o0O0oO0 ) ) )
 if 77 - 77: O0 . Ii1I
 if 39 - 39: ooOoO0o . II111iiii
 if 45 - 45: oO0o * OoOoOO00 / iIii1I11I1II1
 if 77 - 77: I1Ii111 - I11i
 if 11 - 11: I1ii11iIi11i
 if 26 - 26: iIii1I11I1II1 * I1Ii111 - OOooOOo
 if 27 - 27: I1ii11iIi11i * I1Ii111 - OoO0O00 + Ii1I * Ii1I
def lisp_print_future ( ts ) :
 if ( ts == 0 ) : return ( "never" )
 o0OO0O0OO0oO0 = ts - time . time ( )
 if ( o0OO0O0OO0oO0 < 0 ) : return ( "expired" )
 o0OO0O0OO0oO0 = round ( o0OO0O0OO0oO0 , 0 )
 return ( str ( datetime . timedelta ( seconds = o0OO0O0OO0oO0 ) ) )
 if 9 - 9: oO0o % i11iIiiIii / Oo0Ooo
 if 20 - 20: oO0o * O0 + I11i - OoooooooOO . I11i
 if 60 - 60: o0oOOo0O0Ooo . o0oOOo0O0Ooo / iII111i
 if 45 - 45: O0 . i11iIiiIii % iII111i . OoOoOO00 % IiII % iIii1I11I1II1
 if 58 - 58: iIii1I11I1II1 . OoOoOO00 - i11iIiiIii * iIii1I11I1II1 % i11iIiiIii / I1IiiI
 if 80 - 80: I1ii11iIi11i / iIii1I11I1II1 % OoOoOO00
 if 80 - 80: OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if 13 - 13: OoO0O00
 if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
 if 2 - 2: OoooooooOO . OOooOOo . IiII
 if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 if 19 - 19: oO0o * I1IiiI % i11iIiiIii
def lisp_print_eid_tuple ( eid , group ) :
 iiI1Ii1I = eid . print_prefix ( )
 if ( group . is_null ( ) ) : return ( iiI1Ii1I )
 if 28 - 28: OOooOOo % ooOoO0o
 iiIiII11i1 = group . print_prefix ( )
 oOo00Ooo0o0 = group . instance_id
 if 33 - 33: I11i
 if ( eid . is_null ( ) or eid . is_exact_match ( group ) ) :
  OO000o00 = iiIiII11i1 . find ( "]" ) + 1
  return ( "[{}](*, {})" . format ( oOo00Ooo0o0 , iiIiII11i1 [ OO000o00 : : ] ) )
  if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
  if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 iii1IiI1I1 = eid . print_sg ( group )
 return ( iii1IiI1I1 )
 if 64 - 64: ooOoO0o / O0 * OoOoOO00 * ooOoO0o
 if 60 - 60: I11i / i1IIi % I1ii11iIi11i / I1ii11iIi11i * I1ii11iIi11i . i11iIiiIii
 if 99 - 99: OoOoOO00
 if 77 - 77: o0oOOo0O0Ooo
 if 48 - 48: OoOoOO00 % I1ii11iIi11i / I11i . iIii1I11I1II1 * II111iiii
 if 65 - 65: OoOoOO00
 if 31 - 31: I11i * OoOoOO00 . IiII % Ii1I + Oo0Ooo
 if 47 - 47: O0 * I1IiiI * OoO0O00 . II111iiii
def lisp_convert_6to4 ( addr_str ) :
 if ( addr_str . find ( "::ffff:" ) == - 1 ) : return ( addr_str )
 O0o00o000oO = addr_str . split ( ":" )
 return ( O0o00o000oO [ - 1 ] )
 if 62 - 62: I1ii11iIi11i / I11i . i1IIi
 if 99 - 99: OoOoOO00 . I1Ii111
 if 59 - 59: I11i / Oo0Ooo / OOooOOo / O0 / OoOoOO00 + o0oOOo0O0Ooo
 if 13 - 13: o0oOOo0O0Ooo % oO0o / I1Ii111 % I1Ii111 % O0
 if 90 - 90: IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 if 79 - 79: OoOoOO00 / ooOoO0o
 if 77 - 77: Oo0Ooo
 if 46 - 46: I1Ii111
def lisp_convert_4to6 ( addr_str ) :
 O0o00o000oO = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 if ( O0o00o000oO . is_ipv4_string ( addr_str ) ) : addr_str = "::ffff:" + addr_str
 O0o00o000oO . store_address ( addr_str )
 return ( O0o00o000oO )
 if 72 - 72: iII111i * OOooOOo
 if 67 - 67: i1IIi
 if 5 - 5: II111iiii . OoooooooOO
 if 57 - 57: I1IiiI
 if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
 if 50 - 50: OoOoOO00
 if 33 - 33: I11i
 if 98 - 98: OoOoOO00 % II111iiii
 if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
def lisp_gethostbyname ( string ) :
 IiiIIi1 = string . split ( "." )
 iI1iIiiI = string . split ( ":" )
 Oo0OOo = string . split ( "-" )
 if 36 - 36: O0 * OoO0O00 % iII111i * iII111i / OoO0O00 * IiII
 if ( len ( IiiIIi1 ) > 1 ) :
  if ( IiiIIi1 [ 0 ] . isdigit ( ) ) : return ( string )
  if 14 - 14: i1IIi . IiII + O0 * ooOoO0o
 if ( len ( iI1iIiiI ) > 1 ) :
  try :
   int ( iI1iIiiI [ 0 ] , 16 )
   return ( string )
  except :
   pass
   if 76 - 76: OoO0O00
   if 92 - 92: I11i - iIii1I11I1II1 % OoooooooOO
   if 39 - 39: iII111i . I1IiiI * OoOoOO00 - i11iIiiIii
   if 1 - 1: iII111i * OoOoOO00
   if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
   if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
   if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if ( len ( Oo0OOo ) == 3 ) :
  for i1i1IIIIIIIi in range ( 3 ) :
   try : int ( Oo0OOo [ i1i1IIIIIIIi ] , 16 )
   except : break
   if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
   if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
   if 69 - 69: I1ii11iIi11i
 try :
  O0o00o000oO = socket . gethostbyname ( string )
  return ( O0o00o000oO )
 except :
  if ( lisp_is_alpine ( ) == False ) : return ( "" )
  if 83 - 83: o0oOOo0O0Ooo
  if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
  if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
  if 48 - 48: iII111i + IiII
  if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
 try :
  O0o00o000oO = socket . getaddrinfo ( string , 0 ) [ 0 ]
  if ( O0o00o000oO [ 3 ] != string ) : return ( "" )
  O0o00o000oO = O0o00o000oO [ 4 ] [ 0 ]
 except :
  O0o00o000oO = ""
  if 14 - 14: OOooOOo
 return ( O0o00o000oO )
 if 79 - 79: Ii1I
 if 76 - 76: iIii1I11I1II1
 if 80 - 80: iIii1I11I1II1 . O0 / Ii1I % Ii1I
 if 93 - 93: OoooooooOO * Oo0Ooo
 if 10 - 10: I1Ii111 * OoooooooOO + I11i - I1ii11iIi11i / I1ii11iIi11i . i11iIiiIii
 if 22 - 22: I1Ii111 / o0oOOo0O0Ooo
 if 98 - 98: i1IIi
 if 51 - 51: I1ii11iIi11i + ooOoO0o + Oo0Ooo / i1IIi + i1IIi
def lisp_ip_checksum ( data , hdrlen = 20 ) :
 if ( len ( data ) < hdrlen ) :
  lprint ( "IPv4 packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 12 - 12: iIii1I11I1II1 . Ii1I . I1ii11iIi11i % I1IiiI . II111iiii . oO0o
  if 32 - 32: I1ii11iIi11i + IiII / O0 / OoOoOO00 * OoooooooOO % ooOoO0o
 iIiiIIi = binascii . hexlify ( data )
 if 93 - 93: ooOoO0o . I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / I1ii11iIi11i
 if 28 - 28: OoO0O00 - oO0o + OoOoOO00 + Ii1I / iIii1I11I1II1
 if 26 - 26: iIii1I11I1II1 - O0 . O0
 if 68 - 68: OOooOOo + oO0o . O0 . Ii1I % i1IIi % OOooOOo
 i1I1iI = 0
 for i1i1IIIIIIIi in range ( 0 , hdrlen * 2 , 4 ) :
  i1I1iI += int ( iIiiIIi [ i1i1IIIIIIIi : i1i1IIIIIIIi + 4 ] , 16 )
  if 92 - 92: Oo0Ooo / i11iIiiIii + I1ii11iIi11i
  if 87 - 87: OoOoOO00 % iIii1I11I1II1
  if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
  if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
  if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 i1I1iI = ( i1I1iI >> 16 ) + ( i1I1iI & 0xffff )
 i1I1iI += i1I1iI >> 16
 i1I1iI = socket . htons ( ~ i1I1iI & 0xffff )
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 i1I1iI = struct . pack ( "H" , i1I1iI )
 iIiiIIi = data [ 0 : 10 ] + i1I1iI + data [ 12 : : ]
 return ( iIiiIIi )
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
 if 84 - 84: i1IIi
 if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
 if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
def lisp_icmp_checksum ( data ) :
 if ( len ( data ) < 36 ) :
  lprint ( "ICMP packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 81 - 81: IiII / OoOoOO00 * IiII . O0
  if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
 O0o0oo0oOO0oO = binascii . hexlify ( data )
 if 15 - 15: OoO0O00 * II111iiii
 if 59 - 59: I1Ii111 + OoO0O00 / OOooOOo
 if 97 - 97: Oo0Ooo * iII111i % ooOoO0o . iII111i - I1Ii111 - OOooOOo
 if 79 - 79: I1IiiI - ooOoO0o
 i1I1iI = 0
 for i1i1IIIIIIIi in range ( 0 , 36 , 4 ) :
  i1I1iI += int ( O0o0oo0oOO0oO [ i1i1IIIIIIIi : i1i1IIIIIIIi + 4 ] , 16 )
  if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
  if 83 - 83: IiII / I1Ii111
  if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
  if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
  if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 i1I1iI = ( i1I1iI >> 16 ) + ( i1I1iI & 0xffff )
 i1I1iI += i1I1iI >> 16
 i1I1iI = socket . htons ( ~ i1I1iI & 0xffff )
 if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
 if 80 - 80: OoooooooOO + IiII
 if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 if 43 - 43: Oo0Ooo . I1Ii111
 i1I1iI = struct . pack ( "H" , i1I1iI )
 O0o0oo0oOO0oO = data [ 0 : 2 ] + i1I1iI + data [ 4 : : ]
 return ( O0o0oo0oOO0oO )
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
 if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
 if 5 - 5: IiII
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
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
def lisp_udp_checksum ( source , dest , data ) :
 if 3 - 3: OoooooooOO
 if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
 if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 o0 = lisp_address ( LISP_AFI_IPV6 , source , LISP_IPV6_HOST_MASK_LEN , 0 )
 Ii = lisp_address ( LISP_AFI_IPV6 , dest , LISP_IPV6_HOST_MASK_LEN , 0 )
 ii1I = socket . htonl ( len ( data ) )
 Ooo000000 = socket . htonl ( LISP_UDP_PROTOCOL )
 Oo00ooOoO = o0 . pack_address ( )
 Oo00ooOoO += Ii . pack_address ( )
 Oo00ooOoO += struct . pack ( "II" , ii1I , Ooo000000 )
 if 100 - 100: i11iIiiIii / i11iIiiIii
 if 89 - 89: iII111i . i11iIiiIii * O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 if 27 - 27: OOooOOo
 O0OO0ooO00 = binascii . hexlify ( Oo00ooOoO + data )
 oO0 = len ( O0OO0ooO00 ) % 4
 for i1i1IIIIIIIi in range ( 0 , oO0 ) : O0OO0ooO00 += "0"
 if 92 - 92: II111iiii
 if 45 - 45: O0 % I1IiiI - iII111i . OoO0O00
 if 42 - 42: iII111i / o0oOOo0O0Ooo + Oo0Ooo . Oo0Ooo % OOooOOo
 if 16 - 16: i1IIi + OoO0O00 % OoOoOO00 + Ii1I * Oo0Ooo
 i1I1iI = 0
 for i1i1IIIIIIIi in range ( 0 , len ( O0OO0ooO00 ) , 4 ) :
  i1I1iI += int ( O0OO0ooO00 [ i1i1IIIIIIIi : i1i1IIIIIIIi + 4 ] , 16 )
  if 3 - 3: i11iIiiIii
  if 81 - 81: I1IiiI . OoooooooOO * Ii1I . oO0o - O0 * oO0o
  if 72 - 72: II111iiii - OOooOOo + I1IiiI - I11i
  if 91 - 91: II111iiii
  if 53 - 53: OoO0O00 % o0oOOo0O0Ooo / OOooOOo % IiII % OoO0O00 % OoooooooOO
 i1I1iI = ( i1I1iI >> 16 ) + ( i1I1iI & 0xffff )
 i1I1iI += i1I1iI >> 16
 i1I1iI = socket . htons ( ~ i1I1iI & 0xffff )
 if 31 - 31: I1IiiI
 if 73 - 73: ooOoO0o . O0 / o0oOOo0O0Ooo - OoooooooOO % i11iIiiIii
 if 80 - 80: Ii1I / ooOoO0o % O0 . Oo0Ooo
 if 63 - 63: OOooOOo . II111iiii . I11i
 i1I1iI = struct . pack ( "H" , i1I1iI )
 O0OO0ooO00 = data [ 0 : 6 ] + i1I1iI + data [ 8 : : ]
 return ( O0OO0ooO00 )
 if 46 - 46: ooOoO0o % IiII - o0oOOo0O0Ooo - Oo0Ooo - Ii1I / I11i
 if 68 - 68: i1IIi - I1ii11iIi11i / Oo0Ooo % I11i . iII111i
 if 9 - 9: IiII
 if 48 - 48: o0oOOo0O0Ooo + o0oOOo0O0Ooo - Oo0Ooo
 if 27 - 27: OoO0O00 + OoOoOO00 * ooOoO0o
 if 83 - 83: iIii1I11I1II1
 if 72 - 72: I11i
 if 87 - 87: i1IIi
def lisp_igmp_checksum ( igmp ) :
 II1IIiIiiI1iI = binascii . hexlify ( igmp )
 if 80 - 80: I1ii11iIi11i
 if 5 - 5: i1IIi * OoOoOO00 % I1IiiI . OoO0O00 * I1ii11iIi11i - I1Ii111
 if 79 - 79: oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
 i1I1iI = 0
 for i1i1IIIIIIIi in range ( 0 , 24 , 4 ) :
  i1I1iI += int ( II1IIiIiiI1iI [ i1i1IIIIIIIi : i1i1IIIIIIIi + 4 ] , 16 )
  if 24 - 24: ooOoO0o - I11i * oO0o
  if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
  if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
  if 79 - 79: IiII % OoO0O00
  if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 i1I1iI = ( i1I1iI >> 16 ) + ( i1I1iI & 0xffff )
 i1I1iI += i1I1iI >> 16
 i1I1iI = socket . htons ( ~ i1I1iI & 0xffff )
 if 32 - 32: O0 . OoooooooOO
 if 15 - 15: I1IiiI . OoO0O00
 if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 i1I1iI = struct . pack ( "H" , i1I1iI )
 igmp = igmp [ 0 : 2 ] + i1I1iI + igmp [ 4 : : ]
 return ( igmp )
 if 47 - 47: OoO0O00 + IiII / II111iiii
 if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
def lisp_get_interface_address ( device ) :
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if ( device not in netifaces . interfaces ( ) ) : return ( None )
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 I1i1II1 = netifaces . ifaddresses ( device )
 if ( I1i1II1 . has_key ( netifaces . AF_INET ) == False ) : return ( None )
 if 89 - 89: OoO0O00 / OoO0O00
 if 1 - 1: I1ii11iIi11i . i11iIiiIii
 if 74 - 74: O0 + OoooooooOO / oO0o / OoOoOO00 . I1ii11iIi11i % oO0o
 if 34 - 34: i1IIi . I1IiiI
 i11I1IIiiii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 85 - 85: iIii1I11I1II1
 for O0o00o000oO in I1i1II1 [ netifaces . AF_INET ] :
  oOo0O = O0o00o000oO [ "addr" ]
  i11I1IIiiii . store_address ( oOo0O )
  return ( i11I1IIiiii )
  if 30 - 30: Ii1I . I1ii11iIi11i / OOooOOo
 return ( None )
 if 2 - 2: IiII % I1IiiI - I1Ii111
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
 if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
 if 89 - 89: I1IiiI . Oo0Ooo + I1ii11iIi11i . O0 % o0oOOo0O0Ooo
 if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
 if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
 if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
 if 12 - 12: I1ii11iIi11i / Ii1I
 if 5 - 5: OoooooooOO
 if 18 - 18: I1IiiI % OoooooooOO - iII111i . i11iIiiIii * Oo0Ooo % Ii1I
 if 12 - 12: i1IIi / OOooOOo % ooOoO0o * IiII * O0 * iIii1I11I1II1
def lisp_get_input_interface ( packet ) :
 OOOO = lisp_format_packet ( packet [ 0 : 12 ] ) . replace ( " " , "" )
 oO = OOOO [ 0 : 12 ]
 Iii11111iiI = OOOO [ 12 : : ]
 if 67 - 67: o0oOOo0O0Ooo
 try : OOOoO00O = lisp_mymacs . has_key ( Iii11111iiI )
 except : OOOoO00O = False
 if 27 - 27: I1ii11iIi11i * i1IIi . i1IIi
 if ( lisp_mymacs . has_key ( oO ) ) : return ( lisp_mymacs [ oO ] , Iii11111iiI , oO , OOOoO00O )
 if ( OOOoO00O ) : return ( lisp_mymacs [ Iii11111iiI ] , Iii11111iiI , oO , OOOoO00O )
 return ( [ "?" ] , Iii11111iiI , oO , OOOoO00O )
 if 87 - 87: IiII / I1Ii111 - Oo0Ooo
 if 56 - 56: O0
 if 45 - 45: OoOoOO00 - OoO0O00 - OoOoOO00
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
 if 69 - 69: ooOoO0o % ooOoO0o
 if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
 if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
def lisp_get_local_interfaces ( ) :
 for OO0oo00oOO in netifaces . interfaces ( ) :
  I1i = lisp_interface ( OO0oo00oOO )
  I1i . add_interface ( )
  if 82 - 82: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo % i11iIiiIii / I1Ii111 % OoooooooOO
 return
 if 96 - 96: oO0o - oO0o
 if 87 - 87: Oo0Ooo / OoooooooOO - I1ii11iIi11i . IiII + iIii1I11I1II1 . I1ii11iIi11i
 if 4 - 4: OoooooooOO + ooOoO0o . i1IIi / O0 - O0
 if 52 - 52: OoO0O00 * OoooooooOO
 if 12 - 12: O0 + IiII * i1IIi . OoO0O00
 if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
 if 28 - 28: iIii1I11I1II1
def lisp_get_loopback_address ( ) :
 for O0o00o000oO in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( O0o00o000oO [ "peer" ] == "127.0.0.1" ) : continue
  return ( O0o00o000oO [ "peer" ] )
  if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 return ( None )
 if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
 if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
 if 46 - 46: OoOoOO00 - O0
 if 70 - 70: I11i + Oo0Ooo * iIii1I11I1II1 . I1IiiI * I11i
 if 49 - 49: o0oOOo0O0Ooo
 if 25 - 25: iII111i . OoooooooOO * iIii1I11I1II1 . o0oOOo0O0Ooo / O0 + Ii1I
 if 68 - 68: Oo0Ooo
def lisp_is_mac_string ( mac_str ) :
 Oo0OOo = mac_str . split ( "/" )
 if ( len ( Oo0OOo ) == 2 ) : mac_str = Oo0OOo [ 0 ]
 return ( len ( mac_str ) == 14 and mac_str . count ( "-" ) == 2 )
 if 22 - 22: OOooOOo
 if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
 if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
 if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
 if 94 - 94: i1IIi
 if 36 - 36: I1IiiI + Oo0Ooo
 if 46 - 46: iII111i
 if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
def lisp_get_local_macs ( ) :
 for OO0oo00oOO in netifaces . interfaces ( ) :
  if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
  if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
  if 65 - 65: ooOoO0o - i1IIi
  if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
  if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
  Ii = OO0oo00oOO . replace ( ":" , "" )
  Ii = OO0oo00oOO . replace ( "-" , "" )
  if ( Ii . isalnum ( ) == False ) : continue
  if 34 - 34: I1Ii111 - OOooOOo
  if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
  if 64 - 64: i1IIi
  if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
  if 25 - 25: II111iiii / OoO0O00
  try :
   oo0OoOO0000 = netifaces . ifaddresses ( OO0oo00oOO )
  except :
   continue
   if 2 - 2: Ii1I * I1ii11iIi11i * OoooooooOO
  if ( oo0OoOO0000 . has_key ( netifaces . AF_LINK ) == False ) : continue
  Oo0OOo = oo0OoOO0000 [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  Oo0OOo = Oo0OOo . replace ( ":" , "" )
  if 73 - 73: OoOoOO00 + Oo0Ooo
  if 61 - 61: iIii1I11I1II1
  if 47 - 47: OoooooooOO
  if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
  if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
  if ( len ( Oo0OOo ) < 12 ) : continue
  if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
  if ( lisp_mymacs . has_key ( Oo0OOo ) == False ) : lisp_mymacs [ Oo0OOo ] = [ ]
  lisp_mymacs [ Oo0OOo ] . append ( OO0oo00oOO )
  if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
  if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 26 - 26: OOooOOo * Oo0Ooo
 if 31 - 31: I11i * oO0o . Ii1I
 if 35 - 35: I11i
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
 if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
 if 68 - 68: O0
def lisp_get_local_rloc ( ) :
 o0oOoO00 = commands . getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( o0oOoO00 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 94 - 94: OoO0O00 + IiII + ooOoO0o
 if 82 - 82: Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + IiII % iIii1I11I1II1
 if 61 - 61: OOooOOo / Oo0Ooo % OOooOOo - OoO0O00 + ooOoO0o / ooOoO0o
 if 82 - 82: Oo0Ooo
 o0oOoO00 = o0oOoO00 . split ( "\n" ) [ 0 ]
 OO0oo00oOO = o0oOoO00 . split ( ) [ - 1 ]
 if 5 - 5: OoO0O00 / OoO0O00 - O0 - I1Ii111 + I1Ii111
 O0o00o000oO = ""
 O0oooOO0Oo0o = lisp_is_macos ( )
 if ( O0oooOO0Oo0o ) :
  o0oOoO00 = commands . getoutput ( "ifconfig {} | egrep 'inet '" . format ( OO0oo00oOO ) )
  if ( o0oOoO00 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  OoOoOoo0OoO0 = 'ip addr show | egrep "inet " | egrep "{}"' . format ( OO0oo00oOO )
  o0oOoO00 = commands . getoutput ( OoOoOoo0OoO0 )
  if ( o0oOoO00 == "" ) :
   OoOoOoo0OoO0 = 'ip addr show | egrep "inet " | egrep "global lo"'
   o0oOoO00 = commands . getoutput ( OoOoOoo0OoO0 )
   if 17 - 17: Ii1I * II111iiii / IiII + iIii1I11I1II1 . I11i - O0
  if ( o0oOoO00 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 70 - 70: Ii1I * oO0o - I11i + Oo0Ooo % I1ii11iIi11i - IiII
  if 81 - 81: O0 . O0
  if 75 - 75: iIii1I11I1II1 % IiII + I1ii11iIi11i * O0 . iII111i - ooOoO0o
  if 32 - 32: Ii1I % oO0o - i1IIi
  if 40 - 40: iIii1I11I1II1 + iII111i * OoOoOO00 + oO0o
  if 15 - 15: I11i % I1IiiI - iIii1I11I1II1 * ooOoO0o
 O0o00o000oO = ""
 o0oOoO00 = o0oOoO00 . split ( "\n" )
 if 71 - 71: OoOoOO00 % Oo0Ooo % ooOoO0o
 for I111 in o0oOoO00 :
  O0o00O0Oo0 = I111 . split ( ) [ 1 ]
  if ( O0oooOO0Oo0o == False ) : O0o00O0Oo0 = O0o00O0Oo0 . split ( "/" ) [ 0 ]
  III1 = lisp_address ( LISP_AFI_IPV4 , O0o00O0Oo0 , 32 , 0 )
  return ( III1 )
  if 66 - 66: o0oOOo0O0Ooo * OOooOOo + Ii1I * o0oOOo0O0Ooo + OOooOOo / OoooooooOO
 return ( lisp_address ( LISP_AFI_IPV4 , O0o00o000oO , 32 , 0 ) )
 if 86 - 86: Ii1I . iII111i - iII111i
 if 71 - 71: iIii1I11I1II1 . II111iiii % iIii1I11I1II1
 if 22 - 22: i11iIiiIii % I1ii11iIi11i % ooOoO0o % ooOoO0o . OoO0O00
 if 85 - 85: ooOoO0o . O0 / OOooOOo * ooOoO0o - OoO0O00 - i11iIiiIii
 if 25 - 25: ooOoO0o % Oo0Ooo - OOooOOo
 if 80 - 80: IiII % II111iiii - Oo0Ooo - iIii1I11I1II1
 if 9 - 9: o0oOOo0O0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 28 - 28: OoooooooOO % oO0o + I1ii11iIi11i + O0 . I1Ii111
 if 80 - 80: i11iIiiIii % I1ii11iIi11i
 if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
 if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
 if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
 if 21 - 21: iII111i
 if 24 - 24: iII111i / ooOoO0o
 if 61 - 61: iIii1I11I1II1 + oO0o
 if 8 - 8: I1Ii111 + OoO0O00
 if 9 - 9: OOooOOo + o0oOOo0O0Ooo
 if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
 if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
 if 55 - 55: oO0o
 i1iiI = None
 OO000o00 = 1
 o0o = os . getenv ( "LISP_ADDR_SELECT" )
 if ( o0o != None and o0o != "" ) :
  o0o = o0o . split ( ":" )
  if ( len ( o0o ) == 2 ) :
   i1iiI = o0o [ 0 ]
   OO000o00 = o0o [ 1 ]
  else :
   if ( o0o [ 0 ] . isdigit ( ) ) :
    OO000o00 = o0o [ 0 ]
   else :
    i1iiI = o0o [ 0 ]
    if 73 - 73: OoOoOO00 % o0oOOo0O0Ooo
    if 71 - 71: oO0o - OoooooooOO * Oo0Ooo * I11i + o0oOOo0O0Ooo * I1ii11iIi11i
  OO000o00 = 1 if ( OO000o00 == "" ) else int ( OO000o00 )
  if 85 - 85: i11iIiiIii . OoooooooOO - iIii1I11I1II1
  if 38 - 38: I11i . I11i * oO0o / OoooooooOO % ooOoO0o
 OO000 = [ None , None , None ]
 IIiii11ii1II1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 o0OO000O = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 O000o0000O = None
 if 61 - 61: OOooOOo * o0oOOo0O0Ooo * O0 / iII111i
 for OO0oo00oOO in netifaces . interfaces ( ) :
  if ( i1iiI != None and i1iiI != OO0oo00oOO ) : continue
  I1i1II1 = netifaces . ifaddresses ( OO0oo00oOO )
  if ( I1i1II1 == { } ) : continue
  if 52 - 52: Oo0Ooo + iIii1I11I1II1 + i1IIi * Ii1I - II111iiii . II111iiii
  if 22 - 22: i1IIi - I1Ii111 / iII111i - OoOoOO00 . oO0o
  if 49 - 49: I1IiiI - i11iIiiIii + IiII
  if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
  O000o0000O = lisp_get_interface_instance_id ( OO0oo00oOO , None )
  if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
  if 43 - 43: iIii1I11I1II1 % OoO0O00
  if 84 - 84: Oo0Ooo
  if 44 - 44: OoooooooOO * i11iIiiIii / Oo0Ooo
  if ( I1i1II1 . has_key ( netifaces . AF_INET ) ) :
   IiiIIi1 = I1i1II1 [ netifaces . AF_INET ]
   OoO = 0
   for O0o00o000oO in IiiIIi1 :
    IIiii11ii1II1 . store_address ( O0o00o000oO [ "addr" ] )
    if ( IIiii11ii1II1 . is_ipv4_loopback ( ) ) : continue
    if ( IIiii11ii1II1 . is_ipv4_link_local ( ) ) : continue
    if ( IIiii11ii1II1 . address == 0 ) : continue
    OoO += 1
    IIiii11ii1II1 . instance_id = O000o0000O
    if ( i1iiI == None and
 lisp_db_for_lookups . lookup_cache ( IIiii11ii1II1 , False ) ) : continue
    OO000 [ 0 ] = IIiii11ii1II1
    if ( OoO == OO000o00 ) : break
    if 67 - 67: I1ii11iIi11i + Ii1I
    if 72 - 72: IiII % o0oOOo0O0Ooo
  if ( I1i1II1 . has_key ( netifaces . AF_INET6 ) ) :
   iI1iIiiI = I1i1II1 [ netifaces . AF_INET6 ]
   OoO = 0
   for O0o00o000oO in iI1iIiiI :
    oOo0O = O0o00o000oO [ "addr" ]
    o0OO000O . store_address ( oOo0O )
    if ( o0OO000O . is_ipv6_string_link_local ( oOo0O ) ) : continue
    if ( o0OO000O . is_ipv6_loopback ( ) ) : continue
    OoO += 1
    o0OO000O . instance_id = O000o0000O
    if ( i1iiI == None and
 lisp_db_for_lookups . lookup_cache ( o0OO000O , False ) ) : continue
    OO000 [ 1 ] = o0OO000O
    if ( OoO == OO000o00 ) : break
    if 93 - 93: iIii1I11I1II1 + i11iIiiIii . o0oOOo0O0Ooo . i1IIi % I1IiiI % ooOoO0o
    if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
    if 52 - 52: IiII % ooOoO0o
    if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
    if 23 - 23: i11iIiiIii
    if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
  if ( OO000 [ 0 ] == None ) : continue
  if 65 - 65: II111iiii / Oo0Ooo
  OO000 [ 2 ] = OO0oo00oOO
  break
  if 42 - 42: i11iIiiIii . O0
  if 75 - 75: I1Ii111 + iIii1I11I1II1
 IiiiI1 = OO000 [ 0 ] . print_address_no_iid ( ) if OO000 [ 0 ] else "none"
 I1IIIi = OO000 [ 1 ] . print_address_no_iid ( ) if OO000 [ 1 ] else "none"
 OO0oo00oOO = OO000 [ 2 ] if OO000 [ 2 ] else "none"
 if 39 - 39: I11i . I1ii11iIi11i . OOooOOo * I11i / O0 * o0oOOo0O0Ooo
 i1iiI = " (user selected)" if i1iiI != None else ""
 if 35 - 35: i1IIi * i11iIiiIii % I1ii11iIi11i / IiII / IiII
 IiiiI1 = red ( IiiiI1 , False )
 I1IIIi = red ( I1IIIi , False )
 OO0oo00oOO = bold ( OO0oo00oOO , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( IiiiI1 , I1IIIi , OO0oo00oOO , i1iiI , O000o0000O ) )
 if 91 - 91: OoO0O00 * I1Ii111 % OoO0O00 . o0oOOo0O0Ooo * I1ii11iIi11i . OOooOOo
 if 13 - 13: I1ii11iIi11i
 lisp_myrlocs = OO000
 return ( ( OO000 [ 0 ] != None ) )
 if 80 - 80: Oo0Ooo % IiII % OoooooooOO * Oo0Ooo % Ii1I
 if 41 - 41: OoooooooOO / i1IIi
 if 70 - 70: OoOoOO00 % o0oOOo0O0Ooo % i1IIi / I1ii11iIi11i % i11iIiiIii / i1IIi
 if 4 - 4: IiII
 if 93 - 93: oO0o % i1IIi
 if 83 - 83: I1IiiI . Oo0Ooo - I11i . o0oOOo0O0Ooo
 if 73 - 73: I1IiiI - iII111i . iII111i
 if 22 - 22: ooOoO0o / ooOoO0o - Ii1I % I11i . OOooOOo + IiII
 if 64 - 64: i1IIi % I1ii11iIi11i / Ii1I % OoooooooOO
def lisp_get_all_addresses ( ) :
 I1iii1 = [ ]
 for I1i in netifaces . interfaces ( ) :
  try : iIiiiIIiii = netifaces . ifaddresses ( I1i )
  except : continue
  if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
  if ( iIiiiIIiii . has_key ( netifaces . AF_INET ) ) :
   for O0o00o000oO in iIiiiIIiii [ netifaces . AF_INET ] :
    O0o00O0Oo0 = O0o00o000oO [ "addr" ]
    if ( O0o00O0Oo0 . find ( "127.0.0.1" ) != - 1 ) : continue
    I1iii1 . append ( O0o00O0Oo0 )
    if 25 - 25: iIii1I11I1II1
    if 63 - 63: ooOoO0o
  if ( iIiiiIIiii . has_key ( netifaces . AF_INET6 ) ) :
   for O0o00o000oO in iIiiiIIiii [ netifaces . AF_INET6 ] :
    O0o00O0Oo0 = O0o00o000oO [ "addr" ]
    if ( O0o00O0Oo0 == "::1" ) : continue
    if ( O0o00O0Oo0 [ 0 : 5 ] == "fe80:" ) : continue
    I1iii1 . append ( O0o00O0Oo0 )
    if 96 - 96: I11i
    if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
    if 63 - 63: iII111i
 return ( I1iii1 )
 if 11 - 11: iII111i - iIii1I11I1II1
 if 92 - 92: OoO0O00
 if 15 - 15: IiII / IiII + iIii1I11I1II1 % OoooooooOO
 if 12 - 12: ooOoO0o
 if 36 - 36: I1Ii111 . IiII * OoooooooOO - o0oOOo0O0Ooo
 if 60 - 60: OOooOOo . iII111i / iIii1I11I1II1 + OOooOOo * I1Ii111
 if 82 - 82: i11iIiiIii . iIii1I11I1II1 * I1IiiI - I11i + Ii1I
 if 48 - 48: I1ii11iIi11i
def lisp_get_all_multicast_rles ( ) :
 o0oi1I1I1I = [ ]
 o0oOoO00 = commands . getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( o0oOoO00 == "" ) : return ( o0oi1I1I1I )
 if 25 - 25: o0oOOo0O0Ooo + iII111i - Oo0Ooo
 o000oo0o = o0oOoO00 . split ( "\n" )
 for I111 in o000oo0o :
  if ( I111 [ 0 ] == "#" ) : continue
  OoO000oo000o0 = I111 . split ( "rle-address = " ) [ 1 ]
  i1Ii1I1Ii11iI = int ( OoO000oo000o0 . split ( "." ) [ 0 ] )
  if ( i1Ii1I1Ii11iI >= 224 and i1Ii1I1Ii11iI < 240 ) : o0oi1I1I1I . append ( OoO000oo000o0 )
  if 8 - 8: I1ii11iIi11i
 return ( o0oi1I1I1I )
 if 82 - 82: OoooooooOO
 if 75 - 75: II111iiii % I1IiiI + OOooOOo % OoooooooOO / IiII
 if 4 - 4: i11iIiiIii - OOooOOo % I1ii11iIi11i * I1Ii111 % o0oOOo0O0Ooo
 if 71 - 71: ooOoO0o . ooOoO0o - iIii1I11I1II1
 if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
 if 32 - 32: OoooooooOO % oO0o % iIii1I11I1II1 / O0
 if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
 if 98 - 98: Ii1I - I1IiiI . i11iIiiIii * Oo0Ooo
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
  if 29 - 29: Ii1I / ooOoO0o % I11i
  if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
 def encode ( self , nonce ) :
  if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
  if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
  if 79 - 79: IiII + IiII + Ii1I
  if 39 - 39: O0 - OoooooooOO
  if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 79 - 79: O0
  if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
  if 15 - 15: I1ii11iIi11i
  if 4 - 4: IiII + iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % II111iiii
  if 88 - 88: oO0o - i1IIi % i11iIiiIii % II111iiii * OoooooooOO
  if 40 - 40: Oo0Ooo
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 47 - 47: OoOoOO00
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
  if 71 - 71: i11iIiiIii / OoOoOO00 . oO0o
  if 33 - 33: oO0o
  if 39 - 39: OoO0O00 + O0 + ooOoO0o * II111iiii % O0 - O0
  if 41 - 41: IiII % o0oOOo0O0Ooo
  if 67 - 67: O0 % I1Ii111
  self . lisp_header . key_id ( 0 )
  III = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and III == False ) :
   oOo0O = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 48 - 48: OOooOOo . OOooOOo + i11iIiiIii + I1ii11iIi11i % O0
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( oOo0O ) ) :
    O0000 = lisp_crypto_keys_by_rloc_encap [ oOo0O ]
    if ( O0000 [ 1 ] ) :
     O0000 [ 1 ] . use_count += 1
     ii1i1II , iiI1ii1IIiI = self . encrypt ( O0000 [ 1 ] , oOo0O )
     if ( iiI1ii1IIiI ) : self . packet = ii1i1II
     if 35 - 35: I1ii11iIi11i * iII111i . IiII . IiII - oO0o % OoOoOO00
     if 42 - 42: o0oOOo0O0Ooo - iIii1I11I1II1 % OoooooooOO
     if 43 - 43: o0oOOo0O0Ooo - Oo0Ooo
     if 85 - 85: II111iiii + I1Ii111 - ooOoO0o * iIii1I11I1II1 % oO0o
     if 62 - 62: Ii1I + O0 * OoO0O00
     if 59 - 59: II111iiii
     if 43 - 43: Oo0Ooo + OoooooooOO
     if 47 - 47: ooOoO0o
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    if ( self . gleaned_dest ) :
     self . udp_sport = LISP_DATA_PORT
    else :
     self . hash_packet ( )
     if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 23 - 23: II111iiii * iII111i
  else :
   self . udp_sport = LISP_DATA_PORT
   if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
  if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
  if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
  if 21 - 21: OoO0O00
  if ( self . outer_version == 4 ) :
   O0o0oOOO = socket . htons ( self . udp_sport )
   IIi11 = socket . htons ( self . udp_dport )
  else :
   O0o0oOOO = self . udp_sport
   IIi11 = self . udp_dport
   if 78 - 78: I1Ii111 / oO0o - iIii1I11I1II1 - OoOoOO00
   if 60 - 60: II111iiii
  IIi11 = socket . htons ( self . udp_dport ) if self . outer_version == 4 else self . udp_dport
  if 90 - 90: OoOoOO00
  if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
  O0OO0ooO00 = struct . pack ( "HHHH" , O0o0oOOO , IIi11 , socket . htons ( self . udp_length ) ,
 self . udp_checksum )
  if 18 - 18: OoooooooOO
  if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
  if 75 - 75: i11iIiiIii / o0oOOo0O0Ooo . IiII . i1IIi . i1IIi / I11i
  if 94 - 94: ooOoO0o + I1IiiI
  oOOOoo00oO = self . lisp_header . encode ( )
  if 59 - 59: Ii1I / OoOoOO00 * OoO0O00 * iII111i % oO0o
  if 61 - 61: Oo0Ooo - O0 - OoooooooOO
  if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
  if 18 - 18: Oo0Ooo % O0
  if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
  if ( self . outer_version == 4 ) :
   IIIIIiiI11i1 = socket . htons ( self . udp_length + 20 )
   Iii1I = socket . htons ( 0x4000 )
   ooo = struct . pack ( "BBHHHBBH" , 0x45 , self . outer_tos , IIIIIiiI11i1 , 0xdfdf ,
 Iii1I , self . outer_ttl , 17 , 0 )
   ooo += self . outer_source . pack_address ( )
   ooo += self . outer_dest . pack_address ( )
   ooo = lisp_ip_checksum ( ooo )
  elif ( self . outer_version == 6 ) :
   ooo = ""
   if 39 - 39: oO0o / ooOoO0o * II111iiii * iII111i
   if 41 - 41: i11iIiiIii * O0 - iII111i . II111iiii % OoO0O00 % I1ii11iIi11i
   if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
   if 62 - 62: i11iIiiIii
   if 2 - 2: I1IiiI
   if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
   if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
  else :
   return ( None )
   if 14 - 14: IiII . IiII % ooOoO0o
   if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
  self . packet = ooo + O0OO0ooO00 + oOOOoo00oO + self . packet
  return ( self )
  if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
  if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
 def cipher_pad ( self , packet ) :
  iI1 = len ( packet )
  if ( ( iI1 % 16 ) != 0 ) :
   i1I1iiii1Ii11 = ( ( iI1 / 16 ) + 1 ) * 16
   packet = packet . ljust ( i1I1iiii1Ii11 )
   if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  return ( packet )
  if 6 - 6: oO0o . I11i
  if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
 def encrypt ( self , key , addr_str ) :
  if ( key == None or key . shared_key == None ) :
   return ( [ self . packet , False ] )
   if 50 - 50: oO0o % i1IIi * O0
   if 4 - 4: iIii1I11I1II1 . i1IIi
   if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
   if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
   if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
  ii1i1II = self . cipher_pad ( self . packet )
  oo0O = key . get_iv ( )
  if 100 - 100: OoooooooOO - O0 . I11i / I11i + II111iiii * OoOoOO00
  Oo0OO0000oooo = lisp_get_timestamp ( )
  i11111 = None
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   o0o00OoOo0 = chacha . ChaCha ( key . encrypt_key , oo0O ) . encrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   oo0O0000O0 = binascii . unhexlify ( key . encrypt_key )
   try :
    o0OO0ooOOO = AES . new ( oo0O0000O0 , AES . MODE_GCM , oo0O )
    o0o00OoOo0 = o0OO0ooOOO . encrypt
    i11111 = o0OO0ooOOO . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 44 - 44: Ii1I * ooOoO0o / OoOoOO00
  else :
   oo0O0000O0 = binascii . unhexlify ( key . encrypt_key )
   o0o00OoOo0 = AES . new ( oo0O0000O0 , AES . MODE_CBC , oo0O ) . encrypt
   if 69 - 69: ooOoO0o . OOooOOo - I1IiiI
   if 29 - 29: i11iIiiIii . I1ii11iIi11i / I1IiiI . OOooOOo + i11iIiiIii
  i1I1i = o0o00OoOo0 ( ii1i1II )
  if 9 - 9: OoooooooOO * I1ii11iIi11i
  if ( i1I1i == None ) : return ( [ self . packet , False ] )
  Oo0OO0000oooo = int ( str ( time . time ( ) - Oo0OO0000oooo ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 9 - 9: Oo0Ooo + iII111i
  if 64 - 64: O0 * I1IiiI / I1IiiI
  if 57 - 57: I1ii11iIi11i / OoooooooOO % I1ii11iIi11i . O0 / I1ii11iIi11i
  if 63 - 63: IiII + iIii1I11I1II1 + I1IiiI + I1Ii111
  if 72 - 72: OoO0O00 + i11iIiiIii + I1ii11iIi11i
  if 96 - 96: oO0o % i1IIi / o0oOOo0O0Ooo
  if ( i11111 != None ) : i1I1i += i11111 ( )
  if 13 - 13: II111iiii - Oo0Ooo % i11iIiiIii + iII111i
  if 88 - 88: O0 . oO0o % I1IiiI
  if 10 - 10: I1IiiI + O0
  if 75 - 75: O0 % iIii1I11I1II1 / OoOoOO00 % OOooOOo / IiII
  if 31 - 31: i11iIiiIii * OoOoOO00
  self . lisp_header . key_id ( key . key_id )
  oOOOoo00oO = self . lisp_header . encode ( )
  if 69 - 69: i11iIiiIii
  ooO = key . do_icv ( oOOOoo00oO + oo0O + i1I1i , oo0O )
  if 84 - 84: iIii1I11I1II1 . ooOoO0o + iII111i
  O00OOOo0Oo0 = 4 if ( key . do_poly ) else 8
  if 55 - 55: OOooOOo / OoOoOO00 * OOooOOo
  IIIiiiI1Ii1 = bold ( "Encrypt" , False )
  oo0O0OO0Oo = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  oO00o0oO0O = "poly" if key . do_poly else "sha256"
  oO00o0oO0O = bold ( oO00o0oO0O , False )
  iI11Iii1I = "ICV({}): 0x{}...{}" . format ( oO00o0oO0O , ooO [ 0 : O00OOOo0Oo0 ] , ooO [ - O00OOOo0Oo0 : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( IIIiiiI1Ii1 , key . key_id , addr_str , iI11Iii1I , oo0O0OO0Oo , Oo0OO0000oooo ) )
  if 62 - 62: IiII . O0 . iIii1I11I1II1
  if 94 - 94: ooOoO0o % I11i % i1IIi
  ooO = int ( ooO , 16 )
  if ( key . do_poly ) :
   o0OoOo0o0O00 = byte_swap_64 ( ( ooO >> 64 ) & LISP_8_64_MASK )
   I1IiiIi11 = byte_swap_64 ( ooO & LISP_8_64_MASK )
   ooO = struct . pack ( "QQ" , o0OoOo0o0O00 , I1IiiIi11 )
  else :
   o0OoOo0o0O00 = byte_swap_64 ( ( ooO >> 96 ) & LISP_8_64_MASK )
   I1IiiIi11 = byte_swap_64 ( ( ooO >> 32 ) & LISP_8_64_MASK )
   I1i11IIIi = socket . htonl ( ooO & 0xffffffff )
   ooO = struct . pack ( "QQI" , o0OoOo0o0O00 , I1IiiIi11 , I1i11IIIi )
   if 19 - 19: oO0o * iII111i + OoOoOO00 - oO0o + I1ii11iIi11i
   if 14 - 14: OoO0O00
  return ( [ oo0O + i1I1i + ooO , True ] )
  if 38 - 38: O0
  if 79 - 79: i1IIi . oO0o
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 34 - 34: I1Ii111 * II111iiii
  if 71 - 71: IiII
  if 97 - 97: I1ii11iIi11i
  if 86 - 86: Oo0Ooo - OOooOOo . OoOoOO00 . II111iiii * I1IiiI . II111iiii
  if 34 - 34: o0oOOo0O0Ooo . I1Ii111 % IiII - O0 / I1Ii111
  if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
  if ( key . do_poly ) :
   o0OoOo0o0O00 , I1IiiIi11 = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   iI = byte_swap_64 ( o0OoOo0o0O00 ) << 64
   iI |= byte_swap_64 ( I1IiiIi11 )
   iI = lisp_hex_string ( iI ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   O00OOOo0Oo0 = 4
   o00oo = bold ( "poly" , False )
  else :
   o0OoOo0o0O00 , I1IiiIi11 , I1i11IIIi = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   iI = byte_swap_64 ( o0OoOo0o0O00 ) << 96
   iI |= byte_swap_64 ( I1IiiIi11 ) << 32
   iI |= socket . htonl ( I1i11IIIi )
   iI = lisp_hex_string ( iI ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   O00OOOo0Oo0 = 8
   o00oo = bold ( "sha" , False )
   if 78 - 78: IiII - I11i % O0 - OOooOOo % OoO0O00
  oOOOoo00oO = self . lisp_header . encode ( )
  if 43 - 43: OoO0O00
  if 90 - 90: OoooooooOO + O0 + I1ii11iIi11i / I11i / Ii1I * I1ii11iIi11i
  if 100 - 100: I11i
  if 82 - 82: iIii1I11I1II1
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   iIiiII = 8
   oo0O0OO0Oo = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   iIiiII = 12
   oo0O0OO0Oo = bold ( "aes-gcm" , False )
  else :
   iIiiII = 16
   oo0O0OO0Oo = bold ( "aes-cbc" , False )
   if 13 - 13: II111iiii
  oo0O = packet [ 0 : iIiiII ]
  if 55 - 55: Oo0Ooo % i1IIi * I11i
  if 95 - 95: OOooOOo / II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
  if 63 - 63: iIii1I11I1II1 / ooOoO0o
  if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
  iI1ii = key . do_icv ( oOOOoo00oO + packet , oo0O )
  if 61 - 61: Oo0Ooo * i1IIi . OoooooooOO
  iIIiI = "0x{}...{}" . format ( iI [ 0 : O00OOOo0Oo0 ] , iI [ - O00OOOo0Oo0 : : ] )
  O0O0O0OO00oo = "0x{}...{}" . format ( iI1ii [ 0 : O00OOOo0Oo0 ] , iI1ii [ - O00OOOo0Oo0 : : ] )
  if 39 - 39: IiII % OoOoOO00 * I1ii11iIi11i - OoooooooOO - Oo0Ooo
  if ( iI1ii != iI ) :
   self . packet_error = "ICV-error"
   Oo0 = oo0O0OO0Oo + "/" + o00oo
   oOOO = bold ( "ICV failed ({})" . format ( Oo0 ) , False )
   iI11Iii1I = "packet-ICV {} != computed-ICV {}" . format ( iIIiI , O0O0O0OO00oo )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( oOOO , red ( addr_str , False ) ,
   # OOooOOo + iII111i % iIii1I11I1II1 - I1ii11iIi11i
 self . udp_sport , key . key_id , iI11Iii1I ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 33 - 33: OoOoOO00 / OoO0O00
   if 47 - 47: iII111i + O0 / II111iiii * I1IiiI - OoooooooOO . Ii1I
   if 28 - 28: oO0o . oO0o . iIii1I11I1II1 . OOooOOo . I1ii11iIi11i * i11iIiiIii
   if 72 - 72: I11i
   if 26 - 26: IiII % Oo0Ooo
   if 72 - 72: O0 + o0oOOo0O0Ooo + I1IiiI / Oo0Ooo
   lisp_retry_decap_keys ( addr_str , oOOOoo00oO + packet , oo0O , iI )
   return ( [ None , False ] )
   if 83 - 83: IiII - I1IiiI . Ii1I
   if 34 - 34: OoOoOO00 - oO0o * OoooooooOO
   if 5 - 5: i11iIiiIii * iII111i - Ii1I - I1ii11iIi11i - i1IIi + iII111i
   if 4 - 4: ooOoO0o + O0 . i1IIi * I1ii11iIi11i - o0oOOo0O0Ooo
   if 42 - 42: o0oOOo0O0Ooo * OoOoOO00 . OoO0O00 - iII111i / II111iiii
  packet = packet [ iIiiII : : ]
  if 25 - 25: Oo0Ooo % OoOoOO00
  if 75 - 75: i1IIi
  if 74 - 74: Oo0Ooo + I1Ii111 - oO0o - OoO0O00 + iII111i - iIii1I11I1II1
  if 54 - 54: I1ii11iIi11i + II111iiii . I1IiiI / OoO0O00 . ooOoO0o
  Oo0OO0000oooo = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   O00oooO00oo = chacha . ChaCha ( key . encrypt_key , oo0O ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   oo0O0000O0 = binascii . unhexlify ( key . encrypt_key )
   try :
    O00oooO00oo = AES . new ( oo0O0000O0 , AES . MODE_GCM , oo0O ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 44 - 44: iIii1I11I1II1 * I1Ii111 * Oo0Ooo * I1ii11iIi11i + I11i
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 12 - 12: I1ii11iIi11i * ooOoO0o - I11i . OoO0O00 + OoO0O00 + iII111i
   oo0O0000O0 = binascii . unhexlify ( key . encrypt_key )
   O00oooO00oo = AES . new ( oo0O0000O0 , AES . MODE_CBC , oo0O ) . decrypt
   if 29 - 29: OoooooooOO . I1Ii111 % I1Ii111
   if 9 - 9: Oo0Ooo - Oo0Ooo - o0oOOo0O0Ooo + I1Ii111 - II111iiii . I1IiiI
  O0Ooooo0 = O00oooO00oo ( packet )
  Oo0OO0000oooo = int ( str ( time . time ( ) - Oo0OO0000oooo ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 74 - 74: o0oOOo0O0Ooo / oO0o - II111iiii . II111iiii . IiII + II111iiii
  if 92 - 92: I1Ii111 % iIii1I11I1II1 - iII111i / i11iIiiIii % ooOoO0o * o0oOOo0O0Ooo
  if 80 - 80: iII111i
  if 3 - 3: I1ii11iIi11i * I11i
  IIIiiiI1Ii1 = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  oO00o0oO0O = "poly" if key . do_poly else "sha256"
  oO00o0oO0O = bold ( oO00o0oO0O , False )
  iI11Iii1I = "ICV({}): {}" . format ( oO00o0oO0O , iIIiI )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( IIIiiiI1Ii1 , key . key_id , addr_str , iI11Iii1I , oo0O0OO0Oo , Oo0OO0000oooo ) )
  if 53 - 53: iIii1I11I1II1 / iII111i % OoO0O00 + IiII / ooOoO0o
  if 74 - 74: Oo0Ooo
  if 8 - 8: I1IiiI % II111iiii - o0oOOo0O0Ooo - I11i % I1IiiI
  if 93 - 93: Ii1I * iII111i / OOooOOo
  if 88 - 88: oO0o
  if 1 - 1: Oo0Ooo
  if 95 - 95: OoooooooOO / I11i % OoooooooOO / ooOoO0o * IiII
  self . packet = self . packet [ 0 : header_length ]
  return ( [ O0Ooooo0 , True ] )
  if 75 - 75: O0
  if 56 - 56: OoO0O00 / II111iiii
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  IIIiiiiI1 = 1000
  if 40 - 40: O0 + IiII . Ii1I
  if 29 - 29: OOooOOo / OoOoOO00 . iIii1I11I1II1 / I11i % OoOoOO00 % iII111i
  if 49 - 49: II111iiii / IiII - Ii1I
  if 7 - 7: I1IiiI / OoO0O00 + I1Ii111 + I11i / I1IiiI
  if 82 - 82: I1ii11iIi11i + OoooooooOO
  IIiIi11i111II = [ ]
  i1 = 0
  iI1 = len ( inner_packet )
  while ( i1 < iI1 ) :
   Iii1I = inner_packet [ i1 : : ]
   if ( len ( Iii1I ) > IIIiiiiI1 ) : Iii1I = Iii1I [ 0 : IIIiiiiI1 ]
   IIiIi11i111II . append ( Iii1I )
   i1 += len ( Iii1I )
   if 52 - 52: OoooooooOO / IiII - i1IIi
   if 81 - 81: i1IIi / I1Ii111 % i11iIiiIii . iIii1I11I1II1 * OoOoOO00 + OoooooooOO
   if 31 - 31: i1IIi % II111iiii
   if 13 - 13: iIii1I11I1II1 - II111iiii % O0 . Ii1I % OoO0O00
   if 2 - 2: OoooooooOO - Ii1I % oO0o / I1IiiI / o0oOOo0O0Ooo
   if 3 - 3: II111iiii / OOooOOo
  i1I = [ ]
  i1 = 0
  for Iii1I in IIiIi11i111II :
   if 49 - 49: i1IIi - OoOoOO00 . Oo0Ooo + iIii1I11I1II1 - ooOoO0o / Oo0Ooo
   if 24 - 24: oO0o - iII111i / ooOoO0o
   if 10 - 10: OoOoOO00 * i1IIi
   if 15 - 15: I11i + i1IIi - II111iiii % I1IiiI
   iIIi1 = i1 if ( Iii1I == IIiIi11i111II [ - 1 ] ) else 0x2000 + i1
   iIIi1 = socket . htons ( iIIi1 )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , iIIi1 ) + outer_hdr [ 8 : : ]
   if 76 - 76: I1IiiI - I1IiiI - o0oOOo0O0Ooo % ooOoO0o * O0
   if 11 - 11: Ii1I + I11i . OoO0O00 . i11iIiiIii * OoO0O00
   if 18 - 18: I11i + Oo0Ooo - OoO0O00 / I1Ii111 / OOooOOo
   if 53 - 53: OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
   o0000oO = socket . htons ( len ( Iii1I ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , o0000oO ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   i1I . append ( outer_hdr + Iii1I )
   i1 += len ( Iii1I ) / 8
   if 83 - 83: OoO0O00
  return ( i1I )
  if 16 - 16: ooOoO0o
  if 32 - 32: o0oOOo0O0Ooo % I1IiiI
 def send_icmp_too_big ( self , inner_packet ) :
  global lisp_last_icmp_too_big_sent
  global lisp_icmp_raw_socket
  if 7 - 7: Oo0Ooo . i1IIi - oO0o
  o0O0oO0 = time . time ( ) - lisp_last_icmp_too_big_sent
  if ( o0O0oO0 < LISP_ICMP_TOO_BIG_RATE_LIMIT ) :
   lprint ( "Rate limit sending ICMP Too-Big to {}" . format ( self . inner_source . print_address_no_iid ( ) ) )
   if 93 - 93: IiII % I1ii11iIi11i
   return ( False )
   if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
   if 28 - 28: Ii1I . I1ii11iIi11i
   if 77 - 77: I1ii11iIi11i % II111iiii
   if 81 - 81: OoOoOO00 % Ii1I / O0 * iIii1I11I1II1 % IiII . I1IiiI
   if 90 - 90: o0oOOo0O0Ooo
   if 44 - 44: o0oOOo0O0Ooo / I1ii11iIi11i . Oo0Ooo + OoOoOO00
   if 32 - 32: IiII - ooOoO0o * iII111i * I11i
   if 84 - 84: Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
   if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
   if 94 - 94: I11i / OoO0O00 . o0oOOo0O0Ooo
   if 1 - 1: Oo0Ooo . II111iiii
   if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
   if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
   if 4 - 4: IiII
   if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
  oo00o00O0 = socket . htons ( 1400 )
  O0o0oo0oOO0oO = struct . pack ( "BBHHH" , 3 , 4 , 0 , 0 , oo00o00O0 )
  O0o0oo0oOO0oO += inner_packet [ 0 : 20 + 8 ]
  O0o0oo0oOO0oO = lisp_icmp_checksum ( O0o0oo0oOO0oO )
  if 52 - 52: iII111i + O0 % o0oOOo0O0Ooo % O0 % II111iiii + OoooooooOO
  if 51 - 51: iII111i % i11iIiiIii
  if 28 - 28: I1ii11iIi11i + I1ii11iIi11i % OoOoOO00
  if 12 - 12: I11i
  if 19 - 19: Ii1I * i1IIi % O0 + I11i
  if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
  if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
  IIi1I1 = inner_packet [ 12 : 16 ]
  oO00o0oOoo = self . inner_source . print_address_no_iid ( )
  oOO = self . outer_source . pack_address ( )
  if 38 - 38: I11i . IiII - OoO0O00 . I1IiiI
  if 65 - 65: I1Ii111
  if 31 - 31: i11iIiiIii / OoOoOO00 % I1ii11iIi11i
  if 44 - 44: II111iiii * I1IiiI + OOooOOo
  if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
  if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
  if 46 - 46: i11iIiiIii
  if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
  IIIIIiiI11i1 = socket . htons ( 20 + 36 )
  iIiiIIi = struct . pack ( "BBHHHBBH" , 0x45 , 0 , IIIIIiiI11i1 , 0 , 0 , 32 , 1 , 0 ) + oOO + IIi1I1
  iIiiIIi = lisp_ip_checksum ( iIiiIIi )
  iIiiIIi = self . fix_outer_header ( iIiiIIi )
  iIiiIIi += O0o0oo0oOO0oO
  I11111ii1i = bold ( "Too-Big" , False )
  lprint ( "Send ICMP {} to {}, mtu 1400: {}" . format ( I11111ii1i , oO00o0oOoo ,
 lisp_format_packet ( iIiiIIi ) ) )
  if 78 - 78: I11i % Oo0Ooo + OoOoOO00 . I1ii11iIi11i % oO0o / Ii1I
  try :
   lisp_icmp_raw_socket . sendto ( iIiiIIi , ( oO00o0oOoo , 0 ) )
  except socket . error , o0OoO00 :
   lprint ( "lisp_icmp_raw_socket.sendto() failed: {}" . format ( o0OoO00 ) )
   return ( False )
   if 37 - 37: oO0o % I1Ii111 % oO0o
   if 14 - 14: OoO0O00 / I1IiiI
   if 66 - 66: Oo0Ooo / i11iIiiIii % ooOoO0o
   if 43 - 43: OOooOOo
   if 84 - 84: OOooOOo . IiII . iII111i
   if 2 - 2: Oo0Ooo - OoOoOO00
  lisp_last_icmp_too_big_sent = lisp_get_timestamp ( )
  return ( True )
  if 49 - 49: Ii1I + II111iiii / oO0o - OoOoOO00 % OoOoOO00 + I1IiiI
 def fragment ( self ) :
  global lisp_icmp_raw_socket
  global lisp_ignore_df_bit
  if 54 - 54: ooOoO0o % Oo0Ooo - OOooOOo
  ii1i1II = self . fix_outer_header ( self . packet )
  if 16 - 16: I1ii11iIi11i * iII111i / I11i
  if 46 - 46: II111iiii
  if 13 - 13: IiII + II111iiii % I1IiiI
  if 30 - 30: OoooooooOO - i11iIiiIii + oO0o / Oo0Ooo - i11iIiiIii
  if 74 - 74: O0 . I11i
  if 64 - 64: ooOoO0o / i1IIi % iII111i
  iI1 = len ( ii1i1II )
  if ( iI1 <= 1500 ) : return ( [ ii1i1II ] , "Fragment-None" )
  if 84 - 84: OoOoOO00 - Oo0Ooo . ooOoO0o . IiII - Oo0Ooo
  ii1i1II = self . packet
  if 99 - 99: I1Ii111
  if 75 - 75: ooOoO0o . OOooOOo / IiII
  if 84 - 84: OoooooooOO . I1IiiI / o0oOOo0O0Ooo
  if 86 - 86: Oo0Ooo % OoOoOO00
  if 77 - 77: Ii1I % OOooOOo / oO0o
  if ( self . inner_version != 4 ) :
   OOoOo = random . randint ( 0 , 0xffff )
   Iiiiiii11IIiI = ii1i1II [ 0 : 4 ] + struct . pack ( "H" , OOoOo ) + ii1i1II [ 6 : 20 ]
   oOOO0o = ii1i1II [ 20 : : ]
   i1I = self . fragment_outer ( Iiiiiii11IIiI , oOOO0o )
   return ( i1I , "Fragment-Outer" )
   if 70 - 70: i11iIiiIii / ooOoO0o * I1ii11iIi11i - i1IIi + ooOoO0o
   if 37 - 37: OOooOOo / i11iIiiIii
   if 63 - 63: OoO0O00 + ooOoO0o
   if 3 - 3: OoOoOO00 - I1Ii111 / oO0o . O0 * ooOoO0o / I1ii11iIi11i
   if 18 - 18: Ii1I
  o0OOoO = 56 if ( self . outer_version == 6 ) else 36
  Iiiiiii11IIiI = ii1i1II [ 0 : o0OOoO ]
  I1iII1II1I1ii = ii1i1II [ o0OOoO : o0OOoO + 20 ]
  oOOO0o = ii1i1II [ o0OOoO + 20 : : ]
  if 54 - 54: OoooooooOO + Oo0Ooo * OOooOOo
  if 98 - 98: oO0o - oO0o . ooOoO0o
  if 60 - 60: I1IiiI * I1ii11iIi11i / O0 + I11i + IiII
  if 66 - 66: IiII * Oo0Ooo . OoooooooOO * I1Ii111
  if 93 - 93: IiII / i1IIi
  i111IiIi1 = struct . unpack ( "H" , I1iII1II1I1ii [ 6 : 8 ] ) [ 0 ]
  i111IiIi1 = socket . ntohs ( i111IiIi1 )
  if ( i111IiIi1 & 0x4000 ) :
   if ( lisp_icmp_raw_socket != None ) :
    iii1111iIi1i1 = ii1i1II [ o0OOoO : : ]
    if ( self . send_icmp_too_big ( iii1111iIi1i1 ) ) : return ( [ ] , None )
    if 65 - 65: OoOoOO00 . II111iiii % iII111i + Ii1I
   if ( lisp_ignore_df_bit ) :
    i111IiIi1 &= ~ 0x4000
   else :
    IIIiii11 = bold ( "DF-bit set" , False )
    dprint ( "{} in inner header, packet discarded" . format ( IIIiii11 ) )
    return ( [ ] , "Fragment-None-DF-bit" )
    if 12 - 12: I1IiiI + I1Ii111
    if 80 - 80: oO0o . O0
    if 90 - 90: II111iiii / OoO0O00 / Ii1I
  i1 = 0
  iI1 = len ( oOOO0o )
  i1I = [ ]
  while ( i1 < iI1 ) :
   i1I . append ( oOOO0o [ i1 : i1 + 1400 ] )
   i1 += 1400
   if 70 - 70: Ii1I - II111iiii . Oo0Ooo / Oo0Ooo
   if 30 - 30: oO0o . OoO0O00 + I11i / iIii1I11I1II1 % Oo0Ooo / oO0o
   if 3 - 3: I1ii11iIi11i / II111iiii
   if 73 - 73: OoO0O00 * OoooooooOO - OoooooooOO + I1IiiI * Oo0Ooo
   if 87 - 87: o0oOOo0O0Ooo / IiII / i11iIiiIii
  IIiIi11i111II = i1I
  i1I = [ ]
  ooo00 = True if i111IiIi1 & 0x2000 else False
  i111IiIi1 = ( i111IiIi1 & 0x1fff ) * 8
  for Iii1I in IIiIi11i111II :
   if 65 - 65: I1Ii111 + iII111i * iII111i
   if 79 - 79: i1IIi / Oo0Ooo - I1IiiI . O0
   if 56 - 56: IiII % O0 * i1IIi - II111iiii
   if 74 - 74: i1IIi - OoOoOO00 % oO0o . O0 - OoooooooOO
   oOooOOOO0oOo = i111IiIi1 / 8
   if ( ooo00 ) :
    oOooOOOO0oOo |= 0x2000
   elif ( Iii1I != IIiIi11i111II [ - 1 ] ) :
    oOooOOOO0oOo |= 0x2000
    if 12 - 12: OoooooooOO
   oOooOOOO0oOo = socket . htons ( oOooOOOO0oOo )
   I1iII1II1I1ii = I1iII1II1I1ii [ 0 : 6 ] + struct . pack ( "H" , oOooOOOO0oOo ) + I1iII1II1I1ii [ 8 : : ]
   if 55 - 55: I1ii11iIi11i + I1ii11iIi11i
   if 87 - 87: IiII
   if 78 - 78: oO0o % OoOoOO00
   if 1 - 1: OoOoOO00 - o0oOOo0O0Ooo / ooOoO0o - IiII / i1IIi
   if 28 - 28: OoO0O00 / I1Ii111 * I1IiiI + ooOoO0o
   if 48 - 48: O0
   iI1 = len ( Iii1I )
   i111IiIi1 += iI1
   o0000oO = socket . htons ( iI1 + 20 )
   I1iII1II1I1ii = I1iII1II1I1ii [ 0 : 2 ] + struct . pack ( "H" , o0000oO ) + I1iII1II1I1ii [ 4 : 10 ] + struct . pack ( "H" , 0 ) + I1iII1II1I1ii [ 12 : : ]
   if 44 - 44: OoO0O00 * oO0o
   I1iII1II1I1ii = lisp_ip_checksum ( I1iII1II1I1ii )
   o0oOoOooOOo = I1iII1II1I1ii + Iii1I
   if 16 - 16: IiII % OoooooooOO - ooOoO0o * Ii1I - Ii1I
   if 27 - 27: IiII + iIii1I11I1II1 / Oo0Ooo + OoO0O00 % Oo0Ooo + OoO0O00
   if 77 - 77: Oo0Ooo * ooOoO0o % Ii1I
   if 2 - 2: I11i / Oo0Ooo / Ii1I / I1ii11iIi11i / OoooooooOO
   if 22 - 22: iIii1I11I1II1 * I1IiiI / I11i + OoOoOO00
   iI1 = len ( o0oOoOooOOo )
   if ( self . outer_version == 4 ) :
    o0000oO = iI1 + o0OOoO
    iI1 += 16
    Iiiiiii11IIiI = Iiiiiii11IIiI [ 0 : 2 ] + struct . pack ( "H" , o0000oO ) + Iiiiiii11IIiI [ 4 : : ]
    if 98 - 98: OOooOOo
    Iiiiiii11IIiI = lisp_ip_checksum ( Iiiiiii11IIiI )
    o0oOoOooOOo = Iiiiiii11IIiI + o0oOoOooOOo
    o0oOoOooOOo = self . fix_outer_header ( o0oOoOooOOo )
    if 69 - 69: II111iiii + Oo0Ooo - oO0o . Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1
    if 75 - 75: OoO0O00 % OoooooooOO
    if 16 - 16: O0 / i1IIi
    if 58 - 58: o0oOOo0O0Ooo / i11iIiiIii / O0 % I11i % I1IiiI
    if 86 - 86: IiII + OoOoOO00 / I1IiiI + I11i % I11i / i11iIiiIii
   iIiI1I = o0OOoO - 12
   o0000oO = socket . htons ( iI1 )
   o0oOoOooOOo = o0oOoOooOOo [ 0 : iIiI1I ] + struct . pack ( "H" , o0000oO ) + o0oOoOooOOo [ iIiI1I + 2 : : ]
   if 2 - 2: o0oOOo0O0Ooo . Ii1I % OoOoOO00
   i1I . append ( o0oOoOooOOo )
   if 58 - 58: I1ii11iIi11i % Ii1I * Ii1I - iII111i
  return ( i1I , "Fragment-Inner" )
  if 9 - 9: ooOoO0o - Ii1I % II111iiii + IiII + OOooOOo % O0
  if 65 - 65: OOooOOo - OoO0O00 % i11iIiiIii
 def fix_outer_header ( self , packet ) :
  if 58 - 58: iII111i
  if 2 - 2: II111iiii + i1IIi
  if 68 - 68: OOooOOo + Ii1I
  if 58 - 58: IiII * Ii1I . i1IIi
  if 19 - 19: oO0o
  if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
  if 94 - 94: iIii1I11I1II1 + IiII
  if 44 - 44: OoO0O00 + I11i % OoO0O00 + i1IIi + iII111i + O0
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : 6 ] + packet [ 7 ] + packet [ 6 ] + packet [ 8 : : ]
    if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : : ]
    if 36 - 36: OoOoOO00 . i11iIiiIii
    if 81 - 81: Oo0Ooo * iII111i * OoO0O00
  return ( packet )
  if 85 - 85: O0 * oO0o
  if 39 - 39: II111iiii * I1IiiI - iIii1I11I1II1
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 25 - 25: OoooooooOO . Ii1I % iII111i . IiII
  dest = dest . print_address_no_iid ( )
  i1I , ooo000 = self . fragment ( )
  if 82 - 82: iIii1I11I1II1 * OoooooooOO
  for o0oOoOooOOo in i1I :
   if ( len ( i1I ) != 1 ) :
    self . packet = o0oOoOooOOo
    self . print_packet ( ooo000 , True )
    if 50 - 50: I1Ii111 - II111iiii
    if 33 - 33: IiII / IiII . i11iIiiIii * I1ii11iIi11i + o0oOOo0O0Ooo
   try : lisp_raw_socket . sendto ( o0oOoOooOOo , ( dest , 0 ) )
   except socket . error , o0OoO00 :
    lprint ( "socket.sendto() failed: {}" . format ( o0OoO00 ) )
    if 16 - 16: IiII
    if 10 - 10: OoOoOO00 . IiII * iIii1I11I1II1 - oO0o - OoOoOO00 / I1Ii111
    if 13 - 13: oO0o + OoOoOO00 % IiII % OoooooooOO
    if 22 - 22: I1Ii111
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 23 - 23: O0
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 41 - 41: i1IIi . OOooOOo / ooOoO0o / o0oOOo0O0Ooo % IiII - Ii1I
   if 14 - 14: I1ii11iIi11i - i11iIiiIii * I1Ii111
  ii1i1II = mac_header + self . packet
  if 39 - 39: OoooooooOO
  if 19 - 19: i11iIiiIii
  if 80 - 80: I1IiiI
  if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
  if 22 - 22: iIii1I11I1II1 - Ii1I / I1IiiI * IiII
  if 26 - 26: o0oOOo0O0Ooo + OOooOOo - o0oOOo0O0Ooo + Oo0Ooo . oO0o
  if 97 - 97: i1IIi
  if 46 - 46: I1ii11iIi11i
  if 30 - 30: OoO0O00 / O0 * o0oOOo0O0Ooo * I1Ii111 + OoooooooOO * iII111i
  if 23 - 23: I11i
  if 36 - 36: IiII . iII111i - i1IIi + I1Ii111
  l2_socket . write ( ii1i1II )
  return
  if 54 - 54: OoooooooOO . oO0o - iII111i
  if 76 - 76: I1Ii111
 def bridge_l2_packet ( self , eid , db ) :
  try : O00o0 = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : I1i = lisp_myinterfaces [ O00o0 . interface ]
  except : return
  try :
   socket = I1i . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 98 - 98: iIii1I11I1II1 + i11iIiiIii * I1ii11iIi11i / I1Ii111 / ooOoO0o - O0
  try : socket . send ( self . packet )
  except socket . error , o0OoO00 :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( o0OoO00 ) )
   if 42 - 42: iII111i
   if 77 - 77: i1IIi * oO0o % OoooooooOO + O0 * ooOoO0o
   if 28 - 28: I11i . OoooooooOO * OOooOOo + i11iIiiIii % I1IiiI . iIii1I11I1II1
 def is_lisp_packet ( self , packet ) :
  O0OO0ooO00 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == LISP_UDP_PROTOCOL )
  if ( O0OO0ooO00 == False ) : return ( False )
  if 63 - 63: II111iiii - I11i . OoOoOO00
  IIi1I1iII111 = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
  if ( socket . ntohs ( IIi1I1iII111 ) == LISP_DATA_PORT ) : return ( True )
  IIi1I1iII111 = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
  if ( socket . ntohs ( IIi1I1iII111 ) == LISP_DATA_PORT ) : return ( True )
  return ( False )
  if 76 - 76: ooOoO0o . oO0o
  if 60 - 60: OOooOOo * ooOoO0o * OoO0O00
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  ii1i1II = self . packet
  O0ooO = len ( ii1i1II )
  Iii1iIIIi11I1 = IIII11Ii1I11I = True
  if 40 - 40: Ii1I + I1ii11iIi11i * I1Ii111 - oO0o % Ii1I
  if 67 - 67: I1ii11iIi11i
  if 3 - 3: I1Ii111 . I11i % II111iiii * I1IiiI % i1IIi * OoO0O00
  if 5 - 5: II111iiii * i1IIi % Ii1I
  oO000O = 0
  oOo00Ooo0o0 = 0
  if ( is_lisp_packet ) :
   oOo00Ooo0o0 = self . lisp_header . get_instance_id ( )
   Oo0o0OoOoOo0 = struct . unpack ( "B" , ii1i1II [ 0 : 1 ] ) [ 0 ]
   self . outer_version = Oo0o0OoOoOo0 >> 4
   if ( self . outer_version == 4 ) :
    if 36 - 36: Ii1I * I1IiiI * I1ii11iIi11i . I11i * I1ii11iIi11i
    if 76 - 76: OOooOOo + O0 / IiII - OoO0O00
    if 27 - 27: Oo0Ooo - iIii1I11I1II1 * iII111i * II111iiii * I1ii11iIi11i
    if 9 - 9: i11iIiiIii + OOooOOo - OoOoOO00 / ooOoO0o % i1IIi / oO0o
    if 22 - 22: i1IIi
    IIIII1II1111 = struct . unpack ( "H" , ii1i1II [ 10 : 12 ] ) [ 0 ]
    ii1i1II = lisp_ip_checksum ( ii1i1II )
    i1I1iI = struct . unpack ( "H" , ii1i1II [ 10 : 12 ] ) [ 0 ]
    if ( i1I1iI != 0 ) :
     if ( IIIII1II1111 != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( O0ooO )
       if 99 - 99: Oo0Ooo / I1Ii111 * Oo0Ooo / iIii1I11I1II1 * IiII
       if 99 - 99: iIii1I11I1II1 - ooOoO0o
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 79 - 79: I1IiiI + oO0o % I11i % oO0o
      if 56 - 56: I1ii11iIi11i + oO0o . OoO0O00 + OoooooooOO * I1ii11iIi11i - O0
      if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
    oO0oO00 = LISP_AFI_IPV4
    i1 = 12
    self . outer_tos = struct . unpack ( "B" , ii1i1II [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , ii1i1II [ 8 : 9 ] ) [ 0 ]
    oO000O = 20
   elif ( self . outer_version == 6 ) :
    oO0oO00 = LISP_AFI_IPV6
    i1 = 8
    IiiI1Ii1II = struct . unpack ( "H" , ii1i1II [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( IiiI1Ii1II ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , ii1i1II [ 7 : 8 ] ) [ 0 ]
    oO000O = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( O0ooO )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 74 - 74: oO0o / OoooooooOO % oO0o / iIii1I11I1II1 + O0
    if 95 - 95: Oo0Ooo * OOooOOo + I1IiiI . O0
   self . outer_source . afi = oO0oO00
   self . outer_dest . afi = oO0oO00
   IIiIi1II1IiI = self . outer_source . addr_length ( )
   if 99 - 99: Oo0Ooo
   self . outer_source . unpack_address ( ii1i1II [ i1 : i1 + IIiIi1II1IiI ] )
   i1 += IIiIi1II1IiI
   self . outer_dest . unpack_address ( ii1i1II [ i1 : i1 + IIiIi1II1IiI ] )
   ii1i1II = ii1i1II [ oO000O : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 17 - 17: i11iIiiIii - i11iIiiIii + I1ii11iIi11i * ooOoO0o * oO0o / OoooooooOO
   if 22 - 22: I1Ii111 * I1ii11iIi11i - IiII
   if 71 - 71: iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * I1IiiI % II111iiii
   if 35 - 35: I1Ii111 - OoOoOO00
   O00OOOoOOOo0o = struct . unpack ( "H" , ii1i1II [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( O00OOOoOOOo0o )
   O00OOOoOOOo0o = struct . unpack ( "H" , ii1i1II [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( O00OOOoOOOo0o )
   O00OOOoOOOo0o = struct . unpack ( "H" , ii1i1II [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( O00OOOoOOOo0o )
   O00OOOoOOOo0o = struct . unpack ( "H" , ii1i1II [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( O00OOOoOOOo0o )
   ii1i1II = ii1i1II [ 8 : : ]
   if 41 - 41: I1Ii111 * I1Ii111 % I11i
   if 84 - 84: o0oOOo0O0Ooo
   if 67 - 67: I1ii11iIi11i - o0oOOo0O0Ooo
   if 40 - 40: I1IiiI / OoooooooOO + OoO0O00 * OoO0O00
   Iii1iIIIi11I1 = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   IIII11Ii1I11I = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 9 - 9: iIii1I11I1II1
   if 57 - 57: ooOoO0o / Ii1I % o0oOOo0O0Ooo % i11iIiiIii
   if 95 - 95: I1Ii111 - o0oOOo0O0Ooo
   if 65 - 65: i11iIiiIii - OoooooooOO / O0 * IiII % I11i
   if ( self . lisp_header . decode ( ii1i1II ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( O0ooO )
    if 53 - 53: OOooOOo + I1Ii111
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 10 - 10: I11i * i1IIi . oO0o / I1Ii111 . OOooOOo / I1Ii111
   ii1i1II = ii1i1II [ 8 : : ]
   oOo00Ooo0o0 = self . lisp_header . get_instance_id ( )
   oO000O += 16
   if 1 - 1: iII111i % ooOoO0o
  if ( oOo00Ooo0o0 == 0xffffff ) : oOo00Ooo0o0 = 0
  if 99 - 99: iII111i + iIii1I11I1II1 . OOooOOo / OoO0O00 * I1ii11iIi11i
  if 87 - 87: IiII / II111iiii % OoO0O00 % OoO0O00
  if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
  if 91 - 91: I1IiiI / II111iiii * OOooOOo
  ooOoo000 = False
  o0O = self . lisp_header . k_bits
  if ( o0O ) :
   oOo0O = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( oOo0O == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( O0ooO )
    if 11 - 11: OoooooooOO % Ii1I
    self . print_packet ( "Receive" , is_lisp_packet )
    oOoOo00oo = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( oOoOo00oo , o0O ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 32 - 32: I1IiiI * I1Ii111 * i1IIi + oO0o
    if 40 - 40: II111iiii
   iII1 = lisp_crypto_keys_by_rloc_decap [ oOo0O ] [ o0O ]
   if ( iII1 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( O0ooO )
    if 7 - 7: I1ii11iIi11i - iIii1I11I1II1
    self . print_packet ( "Receive" , is_lisp_packet )
    oOoOo00oo = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( oOoOo00oo ,
 red ( oOo0O , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 97 - 97: OOooOOo
    if 41 - 41: OoooooooOO - Oo0Ooo * iIii1I11I1II1 . i1IIi
    if 39 - 39: Ii1I % i1IIi . I1ii11iIi11i - O0
    if 65 - 65: oO0o * oO0o / I11i + oO0o % ooOoO0o + OoOoOO00
    if 92 - 92: o0oOOo0O0Ooo
   iII1 . use_count += 1
   ii1i1II , ooOoo000 = self . decrypt ( ii1i1II , oO000O , iII1 ,
 oOo0O )
   if ( ooOoo000 == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( O0ooO )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 37 - 37: oO0o
    if 18 - 18: IiII * i11iIiiIii + iIii1I11I1II1 % I11i + i1IIi - OoO0O00
    if 85 - 85: OoO0O00 * I11i + OoO0O00
    if 39 - 39: Oo0Ooo / i1IIi % i1IIi
    if 20 - 20: OOooOOo * oO0o
    if 91 - 91: OoO0O00 % i1IIi - iIii1I11I1II1 . OOooOOo
  Oo0o0OoOoOo0 = struct . unpack ( "B" , ii1i1II [ 0 : 1 ] ) [ 0 ]
  self . inner_version = Oo0o0OoOoOo0 >> 4
  if ( Iii1iIIIi11I1 and self . inner_version == 4 and Oo0o0OoOoOo0 >= 0x45 ) :
   IIiiIiIIiI1 = socket . ntohs ( struct . unpack ( "H" , ii1i1II [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , ii1i1II [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , ii1i1II [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , ii1i1II [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( ii1i1II [ 12 : 16 ] )
   self . inner_dest . unpack_address ( ii1i1II [ 16 : 20 ] )
   i111IiIi1 = socket . ntohs ( struct . unpack ( "H" , ii1i1II [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( i111IiIi1 & 0x2000 or i111IiIi1 != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , ii1i1II [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , ii1i1II [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 39 - 39: I11i / OoooooooOO - Ii1I + OoO0O00 / OoOoOO00
  elif ( Iii1iIIIi11I1 and self . inner_version == 6 and Oo0o0OoOoOo0 >= 0x60 ) :
   IIiiIiIIiI1 = socket . ntohs ( struct . unpack ( "H" , ii1i1II [ 4 : 6 ] ) [ 0 ] ) + 40
   IiiI1Ii1II = struct . unpack ( "H" , ii1i1II [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( IiiI1Ii1II ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , ii1i1II [ 7 : 8 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , ii1i1II [ 6 : 7 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( ii1i1II [ 8 : 24 ] )
   self . inner_dest . unpack_address ( ii1i1II [ 24 : 40 ] )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , ii1i1II [ 40 : 42 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , ii1i1II [ 42 : 44 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 87 - 87: I1Ii111
  elif ( IIII11Ii1I11I ) :
   IIiiIiIIiI1 = len ( ii1i1II )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_protocol = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( ii1i1II [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( ii1i1II [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( O0ooO )
   if 32 - 32: I11i - OOooOOo * O0 % IiII . IiII . I1IiiI
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( Oo0o0OoOoOo0 ) ) )
   if 91 - 91: i1IIi . iII111i
   ii1i1II = lisp_format_packet ( ii1i1II [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( ii1i1II ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 37 - 37: iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoO0O00 . o0oOOo0O0Ooo
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = oOo00Ooo0o0
  self . inner_dest . instance_id = oOo00Ooo0o0
  if 62 - 62: I1ii11iIi11i
  if 47 - 47: I1Ii111 % OOooOOo * OoO0O00 . iIii1I11I1II1 % Oo0Ooo + OoooooooOO
  if 2 - 2: I1Ii111 % OoooooooOO - ooOoO0o * I1ii11iIi11i * IiII
  if 99 - 99: iIii1I11I1II1 . Oo0Ooo / ooOoO0o . OOooOOo % I1IiiI * I11i
  if 95 - 95: oO0o
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   oOo0ooO0O0oo = lisp_get_echo_nonce ( self . outer_source , None )
   if ( oOo0ooO0O0oo == None ) :
    ii11IiI = self . outer_source . print_address_no_iid ( )
    oOo0ooO0O0oo = lisp_echo_nonce ( ii11IiI )
    if 14 - 14: I11i - Oo0Ooo . Oo0Ooo * OOooOOo . I1IiiI % iII111i
   OO00OO = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    oOo0ooO0O0oo . receive_request ( lisp_ipc_socket , OO00OO )
   elif ( oOo0ooO0O0oo . request_nonce_sent ) :
    oOo0ooO0O0oo . receive_echo ( lisp_ipc_socket , OO00OO )
    if 27 - 27: O0 * I1IiiI - iIii1I11I1II1 - iII111i % O0 . Oo0Ooo
    if 16 - 16: IiII % i11iIiiIii . IiII % OoooooooOO - oO0o
    if 88 - 88: Ii1I * iIii1I11I1II1 . I11i
    if 20 - 20: O0 . i11iIiiIii * i1IIi % O0 . I1IiiI
    if 53 - 53: ooOoO0o / OoooooooOO - II111iiii
    if 68 - 68: OoooooooOO . OoooooooOO . iIii1I11I1II1 / ooOoO0o - I11i % O0
    if 19 - 19: OoooooooOO * oO0o
  if ( ooOoo000 ) : self . packet += ii1i1II [ : IIiiIiIIiI1 ]
  if 60 - 60: II111iiii - iII111i + o0oOOo0O0Ooo % OOooOOo
  if 97 - 97: O0 % O0
  if 35 - 35: iII111i - Ii1I . i11iIiiIii % O0 % I1ii11iIi11i
  if 92 - 92: OOooOOo % II111iiii . iII111i
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 46 - 46: OoOoOO00 + I1IiiI % OoooooooOO * i11iIiiIii - Oo0Ooo
  if 47 - 47: iII111i * OoOoOO00 * IiII
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 46 - 46: Ii1I
  if 42 - 42: iIii1I11I1II1
 def strip_outer_headers ( self ) :
  i1 = 16
  i1 += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ i1 : : ]
  return ( self )
  if 32 - 32: Oo0Ooo - Ii1I . OoooooooOO - OoooooooOO - Oo0Ooo . iIii1I11I1II1
  if 34 - 34: Oo0Ooo
 def hash_ports ( self ) :
  ii1i1II = self . packet
  Oo0o0OoOoOo0 = self . inner_version
  IiI1I1i1 = 0
  if ( Oo0o0OoOoOo0 == 4 ) :
   Iii11I = struct . unpack ( "B" , ii1i1II [ 9 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( Iii11I )
   if ( Iii11I in [ 6 , 17 ] ) :
    IiI1I1i1 = Iii11I
    IiI1I1i1 += struct . unpack ( "I" , ii1i1II [ 20 : 24 ] ) [ 0 ]
    IiI1I1i1 = ( IiI1I1i1 >> 16 ) ^ ( IiI1I1i1 & 0xffff )
    if 2 - 2: oO0o . OOooOOo
    if 43 - 43: iIii1I11I1II1
  if ( Oo0o0OoOoOo0 == 6 ) :
   Iii11I = struct . unpack ( "B" , ii1i1II [ 6 ] ) [ 0 ]
   if ( Iii11I in [ 6 , 17 ] ) :
    IiI1I1i1 = Iii11I
    IiI1I1i1 += struct . unpack ( "I" , ii1i1II [ 40 : 44 ] ) [ 0 ]
    IiI1I1i1 = ( IiI1I1i1 >> 16 ) ^ ( IiI1I1i1 & 0xffff )
    if 29 - 29: IiII % ooOoO0o + OoO0O00 . i1IIi + I1IiiI
    if 24 - 24: I1Ii111 / Ii1I * I1ii11iIi11i - OoooooooOO / I1IiiI . oO0o
  return ( IiI1I1i1 )
  if 98 - 98: i1IIi - iII111i
  if 49 - 49: o0oOOo0O0Ooo . Ii1I . oO0o
 def hash_packet ( self ) :
  IiI1I1i1 = self . inner_source . address ^ self . inner_dest . address
  IiI1I1i1 += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   IiI1I1i1 = ( IiI1I1i1 >> 16 ) ^ ( IiI1I1i1 & 0xffff )
  elif ( self . inner_version == 6 ) :
   IiI1I1i1 = ( IiI1I1i1 >> 64 ) ^ ( IiI1I1i1 & 0xffffffffffffffff )
   IiI1I1i1 = ( IiI1I1i1 >> 32 ) ^ ( IiI1I1i1 & 0xffffffff )
   IiI1I1i1 = ( IiI1I1i1 >> 16 ) ^ ( IiI1I1i1 & 0xffff )
   if 9 - 9: IiII - II111iiii * OoO0O00
  self . udp_sport = 0xf000 | ( IiI1I1i1 & 0xfff )
  if 78 - 78: iIii1I11I1II1 / O0 * oO0o / iII111i / OoOoOO00
  if 15 - 15: ooOoO0o / oO0o
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   O0Oo00o0o = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # iII111i + II111iiii . i11iIiiIii . Ii1I - O0
 green ( O0Oo00o0o , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 47 - 47: oO0o . I1ii11iIi11i - iIii1I11I1II1 % II111iiii / OoOoOO00 % OoooooooOO
   if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   oOO0o = "decap"
   oOO0o += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   oOO0o = s_or_r
   if ( oOO0o in [ "Send" , "Replicate" ] or oOO0o . find ( "Fragment" ) != - 1 ) :
    oOO0o = "encap"
    if 72 - 72: O0
    if 7 - 7: o0oOOo0O0Ooo
  o0OO0OOOOOo = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 83 - 83: iIii1I11I1II1 + II111iiii * oO0o / O0 - iII111i
  if 23 - 23: i1IIi
  if 24 - 24: IiII
  if 51 - 51: OOooOOo % i11iIiiIii
  if 77 - 77: OOooOOo % i11iIiiIii - I1ii11iIi11i
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   I111 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 21 - 21: I11i . Oo0Ooo - OoooooooOO * i1IIi
   I111 += bold ( "control-packet" , False ) + ": {} ..."
   if 54 - 54: II111iiii % o0oOOo0O0Ooo - i1IIi . I1IiiI - II111iiii / iIii1I11I1II1
   dprint ( I111 . format ( bold ( s_or_r , False ) , red ( o0OO0OOOOOo , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   I111 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 29 - 29: oO0o
   if 66 - 66: OoooooooOO + iII111i . IiII % i1IIi
   if 58 - 58: OOooOOo % iII111i * O0 + I1ii11iIi11i - IiII
   if 26 - 26: i1IIi / I1IiiI / I11i + I11i
  if ( self . lisp_header . k_bits ) :
   if ( oOO0o == "encap" ) : oOO0o = "encrypt/encap"
   if ( oOO0o == "decap" ) : oOO0o = "decap/decrypt"
   if 46 - 46: I1Ii111 % I1ii11iIi11i + Ii1I
   if 67 - 67: iIii1I11I1II1 . i11iIiiIii . i11iIiiIii . i11iIiiIii / I11i + ooOoO0o
  O0Oo00o0o = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 10 - 10: ooOoO0o - Oo0Ooo % II111iiii
  dprint ( I111 . format ( bold ( s_or_r , False ) , red ( o0OO0OOOOOo , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( O0Oo00o0o , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( oOO0o ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 66 - 66: iIii1I11I1II1 . iIii1I11I1II1
  if 46 - 46: I1Ii111 * oO0o . Ii1I * I1Ii111 * iIii1I11I1II1 / I11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 46 - 46: II111iiii % I1ii11iIi11i . OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
  if 47 - 47: IiII . OOooOOo
 def get_raw_socket ( self ) :
  oOo00Ooo0o0 = str ( self . lisp_header . get_instance_id ( ) )
  if ( oOo00Ooo0o0 == "0" ) : return ( None )
  if ( lisp_iid_to_interface . has_key ( oOo00Ooo0o0 ) == False ) : return ( None )
  if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
  I1i = lisp_iid_to_interface [ oOo00Ooo0o0 ]
  o0 = I1i . get_socket ( )
  if ( o0 == None ) :
   IIIiiiI1Ii1 = bold ( "SO_BINDTODEVICE" , False )
   O0000ooO = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( IIIiiiI1Ii1 , "drop" if O0000ooO else "forward" ) )
   if 83 - 83: I1Ii111 + o0oOOo0O0Ooo % oO0o / OoO0O00
   if ( O0000ooO ) : return ( None )
   if 59 - 59: Ii1I * OOooOOo . IiII
   if 68 - 68: O0 * iIii1I11I1II1 / I1Ii111
  oOo00Ooo0o0 = bold ( oOo00Ooo0o0 , False )
  Ii = bold ( I1i . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( oOo00Ooo0o0 , Ii ) )
  return ( o0 )
  if 65 - 65: OOooOOo - I1IiiI * I1Ii111
  if 99 - 99: I1IiiI
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 64 - 64: I1ii11iIi11i * Ii1I * Oo0Ooo % IiII % ooOoO0o
  OoO0000O = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or OoO0000O ) :
   I1I1iI = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = I1I1iI ) . start ( )
   if ( OoO0000O ) : os . system ( "rm ./log-flows" )
   return
   if 41 - 41: oO0o . iII111i + OoooooooOO * Ii1I . o0oOOo0O0Ooo
   if 11 - 11: O0
  Oo0OO0000oooo = datetime . datetime . now ( )
  lisp_flow_log . append ( [ Oo0OO0000oooo , encap , self . packet , self ] )
  if 96 - 96: iII111i + o0oOOo0O0Ooo
  if 10 - 10: i11iIiiIii . OoooooooOO . O0 % ooOoO0o / OoO0O00
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  iiIiIIIIiI = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 4 - 4: I11i . IiII
  I1I = red ( self . outer_source . print_address_no_iid ( ) , False )
  IiiI1II = red ( self . outer_dest . print_address_no_iid ( ) , False )
  I1I1i1ii11 = green ( self . inner_source . print_address ( ) , False )
  ii = green ( self . inner_dest . print_address ( ) , False )
  if 87 - 87: OoO0O00 * OoOoOO00 - Oo0Ooo % OOooOOo * i11iIiiIii
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   iiIiIIIIiI += " {}:{} -> {}:{}, LISP control message type {}\n"
   iiIiIIIIiI = iiIiIIIIiI . format ( I1I , self . udp_sport , IiiI1II , self . udp_dport ,
 self . inner_version )
   return ( iiIiIIIIiI )
   if 59 - 59: I1Ii111 + OoooooooOO / I1IiiI / OoooooooOO . iII111i
   if 20 - 20: Ii1I . I1Ii111 % Ii1I
  if ( self . outer_dest . is_null ( ) == False ) :
   iiIiIIIIiI += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   iiIiIIIIiI = iiIiIIIIiI . format ( I1I , self . udp_sport , IiiI1II , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 5 - 5: OOooOOo + iII111i
   if 23 - 23: I1Ii111 % iIii1I11I1II1 . I11i
   if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
   if 11 - 11: I1ii11iIi11i / O0 + II111iiii
   if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
  if ( self . lisp_header . k_bits != 0 ) :
   II1Iii1iI = "\n"
   if ( self . packet_error != "" ) :
    II1Iii1iI = " ({})" . format ( self . packet_error ) + II1Iii1iI
    if 56 - 56: iIii1I11I1II1 . I11i
   iiIiIIIIiI += ", encrypted" + II1Iii1iI
   return ( iiIiIIIIiI )
   if 2 - 2: Ii1I
   if 12 - 12: i11iIiiIii - iIii1I11I1II1 * IiII * iII111i
   if 19 - 19: O0 + oO0o + o0oOOo0O0Ooo
   if 81 - 81: iIii1I11I1II1
   if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
   if 89 - 89: OoooooooOO % II111iiii - OoO0O00 % i11iIiiIii
  Iii11I = packet [ 9 ] if self . inner_version == 4 else packet [ 6 ]
  Iii11I = struct . unpack ( "B" , Iii11I ) [ 0 ]
  if 7 - 7: IiII
  iiIiIIIIiI += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  iiIiIIIIiI = iiIiIIIIiI . format ( I1I1i1ii11 , ii , len ( packet ) , self . inner_tos ,
 self . inner_ttl , Iii11I )
  if 15 - 15: Oo0Ooo + iII111i + I1IiiI * o0oOOo0O0Ooo
  if 33 - 33: o0oOOo0O0Ooo * Oo0Ooo
  if 88 - 88: I1Ii111 % OOooOOo - OoOoOO00 - OoOoOO00 . I1IiiI
  if 52 - 52: II111iiii / II111iiii / I1IiiI - I1Ii111
  if ( Iii11I in [ 6 , 17 ] ) :
   Oo0OOoI1i1i1IIi1I = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( Oo0OOoI1i1i1IIi1I ) == 4 ) :
    Oo0OOoI1i1i1IIi1I = socket . ntohl ( struct . unpack ( "I" , Oo0OOoI1i1i1IIi1I ) [ 0 ] )
    iiIiIIIIiI += ", ports {} -> {}" . format ( Oo0OOoI1i1i1IIi1I >> 16 , Oo0OOoI1i1i1IIi1I & 0xffff )
    if 18 - 18: oO0o * Ii1I / OoooooooOO % OoOoOO00 - i1IIi
  elif ( Iii11I == 1 ) :
   iIiIi111 = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( iIiIi111 ) == 2 ) :
    iIiIi111 = socket . ntohs ( struct . unpack ( "H" , iIiIi111 ) [ 0 ] )
    iiIiIIIIiI += ", icmp-seq {}" . format ( iIiIi111 )
    if 1 - 1: I1Ii111 * OoOoOO00
    if 100 - 100: I1ii11iIi11i / O0 / ooOoO0o + I1ii11iIi11i
  if ( self . packet_error != "" ) :
   iiIiIIIIiI += " ({})" . format ( self . packet_error )
   if 48 - 48: OoooooooOO . iII111i + O0
  iiIiIIIIiI += "\n"
  return ( iiIiIIIIiI )
  if 85 - 85: II111iiii - Ii1I
  if 93 - 93: IiII / i11iIiiIii - oO0o + OoO0O00 / i1IIi
 def is_trace ( self ) :
  Oo0OOoI1i1i1IIi1I = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in Oo0OOoI1i1i1IIi1I )
  if 62 - 62: I1ii11iIi11i / OoooooooOO * I1IiiI - i1IIi
  if 81 - 81: oO0o / O0 * ooOoO0o % OoOoOO00 / O0
  if 85 - 85: OoooooooOO + OoooooooOO
  if 23 - 23: i1IIi
  if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
  if 74 - 74: Oo0Ooo - II111iiii - IiII
  if 50 - 50: I1IiiI - oO0o + oO0o * I11i + oO0o
  if 70 - 70: i1IIi % OoO0O00 / i1IIi
  if 30 - 30: OoOoOO00 - i11iIiiIii
  if 94 - 94: OoOoOO00 % iII111i
  if 39 - 39: OoOoOO00 + I1Ii111 % O0
  if 26 - 26: ooOoO0o + OoOoOO00
  if 17 - 17: I1ii11iIi11i - iII111i % Oo0Ooo * O0 % O0 * OOooOOo
  if 6 - 6: I1Ii111
  if 46 - 46: II111iiii * I1Ii111
  if 23 - 23: i1IIi - O0
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 6 - 6: ooOoO0o % OoooooooOO * I1Ii111 - IiII
class lisp_data_header ( ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 24 - 24: I11i / iIii1I11I1II1 . OoooooooOO % OoOoOO00 . Ii1I
  if 73 - 73: I1Ii111
 def print_header ( self , e_or_d ) :
  i1IiIiiiii11 = lisp_hex_string ( self . first_long & 0xffffff )
  oooo = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 65 - 65: Oo0Ooo . OoOoOO00 . OOooOOo % o0oOOo0O0Ooo + OoO0O00
  I111 = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 53 - 53: Oo0Ooo * I11i - Ii1I % OoO0O00 - OoOoOO00 - iII111i
  return ( I111 . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 i1IiIiiiii11 , oooo ) )
  if 21 - 21: II111iiii + OoO0O00 - Oo0Ooo + I1IiiI
  if 20 - 20: OoO0O00
 def encode ( self ) :
  o00OooooOOOO = "II"
  i1IiIiiiii11 = socket . htonl ( self . first_long )
  oooo = socket . htonl ( self . second_long )
  if 89 - 89: O0 + IiII * I1Ii111
  iIIIIII = struct . pack ( o00OooooOOOO , i1IiIiiiii11 , oooo )
  return ( iIIIIII )
  if 48 - 48: OoOoOO00 * OoooooooOO + OoooooooOO * iIii1I11I1II1 * II111iiii % i11iIiiIii
  if 22 - 22: OoO0O00 . OoOoOO00 % II111iiii - O0
 def decode ( self , packet ) :
  o00OooooOOOO = "II"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( False )
  if 7 - 7: Oo0Ooo * OoO0O00 - II111iiii % I1Ii111 . Oo0Ooo . Oo0Ooo
  i1IiIiiiii11 , oooo = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  if 5 - 5: OoooooooOO * I1ii11iIi11i
  if 42 - 42: o0oOOo0O0Ooo . I1Ii111 / O0 . II111iiii * OoOoOO00
  self . first_long = socket . ntohl ( i1IiIiiiii11 )
  self . second_long = socket . ntohl ( oooo )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 7 - 7: I1Ii111 * O0 + OoOoOO00
  if 90 - 90: IiII * II111iiii * IiII - iII111i
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 34 - 34: OOooOOo - I1ii11iIi11i * iII111i % Ii1I
  if 25 - 25: II111iiii + I1IiiI * ooOoO0o * I1ii11iIi11i . iII111i
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 26 - 26: iII111i - ooOoO0o / OoooooooOO + o0oOOo0O0Ooo . Oo0Ooo
  if 75 - 75: O0 / OoOoOO00 . I1Ii111
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 7 - 7: OoO0O00 * iII111i
  if 16 - 16: I1Ii111 . i1IIi . IiII
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 50 - 50: OoO0O00 - II111iiii * OoooooooOO - I1IiiI . O0 + O0
  if 80 - 80: o0oOOo0O0Ooo
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 50 - 50: ooOoO0o
  if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
  if 59 - 59: iII111i - OoooooooOO / ooOoO0o + I1ii11iIi11i . o0oOOo0O0Ooo - iII111i
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 29 - 29: oO0o
  if 26 - 26: O0 % OOooOOo - IiII . OOooOOo
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 70 - 70: o0oOOo0O0Ooo + I11i / iII111i + ooOoO0o / I1IiiI
  if 33 - 33: OoooooooOO . O0
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 59 - 59: iIii1I11I1II1
  if 45 - 45: O0
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 78 - 78: I11i - iIii1I11I1II1 + I1Ii111 - I1ii11iIi11i - I1Ii111
  if 21 - 21: OoooooooOO . O0 / i11iIiiIii
  if 86 - 86: OoOoOO00 / OOooOOo
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
  if 40 - 40: iIii1I11I1II1 / ooOoO0o / I1IiiI + I1ii11iIi11i * OOooOOo
  if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
 def send_ipc ( self , ipc_socket , ipc ) :
  O0O00Oo = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  oO00o0oOoo = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , O0O00Oo )
  lisp_ipc ( ipc , ipc_socket , oO00o0oOoo )
  if 49 - 49: i1IIi - OOooOOo / o0oOOo0O0Ooo % IiII - ooOoO0o
  if 62 - 62: I1Ii111 + OoOoOO00 % o0oOOo0O0Ooo % o0oOOo0O0Ooo
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  oOO0O = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , oOO0O )
  if 88 - 88: oO0o * I1IiiI / OoO0O00 - OOooOOo / i1IIi . I1Ii111
  if 26 - 26: i11iIiiIii - ooOoO0o
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  oOO0O = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , oOO0O )
  if 45 - 45: ooOoO0o + II111iiii % iII111i
  if 55 - 55: ooOoO0o - oO0o % I1IiiI
 def receive_request ( self , ipc_socket , nonce ) :
  ooOooo0OoOo0o = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( ooOooo0OoOo0o != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 65 - 65: iIii1I11I1II1 . II111iiii % OOooOOo - I1Ii111 + OoooooooOO / O0
  if 94 - 94: o0oOOo0O0Ooo - O0
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 99 - 99: i11iIiiIii * Ii1I / I1Ii111 % iIii1I11I1II1 * iIii1I11I1II1 + Ii1I
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 78 - 78: OOooOOo . O0 / Ii1I
  if 36 - 36: I1Ii111 / I1Ii111 % oO0o
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 97 - 97: OoooooooOO * o0oOOo0O0Ooo + OoooooooOO % Ii1I * Oo0Ooo
  if 35 - 35: iIii1I11I1II1 % iII111i - i1IIi
  if 20 - 20: I11i % ooOoO0o . OOooOOo / I1Ii111
  if 50 - 50: oO0o + i11iIiiIii / i11iIiiIii + ooOoO0o + I1Ii111
  if 65 - 65: ooOoO0o * O0 * iII111i
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   OoOOOo0oo = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 83 - 83: O0 * I1IiiI
   if 97 - 97: II111iiii
   if ( remote_rloc . address > OoOOOo0oo . address ) :
    O0o00O0Oo0 = "exit"
    self . request_nonce_sent = None
   else :
    O0o00O0Oo0 = "stay in"
    self . echo_nonce_sent = None
    if 38 - 38: I1IiiI
    if 42 - 42: o0oOOo0O0Ooo
   ii1i1 = bold ( "collision" , False )
   o0000oO = red ( OoOOOo0oo . print_address_no_iid ( ) , False )
   O0OooO0oo = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( ii1i1 ,
 o0000oO , O0OooO0oo , O0o00O0Oo0 ) )
   if 81 - 81: iII111i / I1ii11iIi11i
   if 55 - 55: o0oOOo0O0Ooo % OOooOOo - I1ii11iIi11i / IiII / i11iIiiIii % I1Ii111
   if 43 - 43: O0 / I1Ii111 . iIii1I11I1II1 - OoOoOO00
   if 47 - 47: II111iiii - I1ii11iIi11i - Ii1I
   if 9 - 9: I1ii11iIi11i - IiII
  if ( self . echo_nonce_sent != None ) :
   OO00OO = self . echo_nonce_sent
   o0OoO00 = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( o0OoO00 ,
 lisp_hex_string ( OO00OO ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( OO00OO )
   if 64 - 64: i1IIi
   if 71 - 71: IiII * o0oOOo0O0Ooo
   if 99 - 99: o0oOOo0O0Ooo
   if 28 - 28: OoooooooOO % O0 - OOooOOo / o0oOOo0O0Ooo / I1IiiI
   if 41 - 41: II111iiii * IiII / OoO0O00 . oO0o
   if 50 - 50: OoooooooOO + iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii . ooOoO0o
   if 75 - 75: iIii1I11I1II1 % ooOoO0o / OOooOOo - iII111i % i11iIiiIii
  OO00OO = self . request_nonce_sent
  i11 = self . last_request_nonce_sent
  if ( OO00OO and i11 != None ) :
   if ( time . time ( ) - i11 >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( OO00OO ) ) )
    if 87 - 87: OOooOOo + OOooOOo
    return ( None )
    if 45 - 45: i1IIi - Oo0Ooo
    if 87 - 87: OoOoOO00 - OoO0O00 * OoO0O00 / Ii1I . I11i * o0oOOo0O0Ooo
    if 21 - 21: II111iiii
    if 29 - 29: OoOoOO00 % Ii1I
    if 7 - 7: i1IIi / IiII / iII111i
    if 97 - 97: OoO0O00 + iIii1I11I1II1
    if 79 - 79: ooOoO0o + oO0o - II111iiii . Oo0Ooo
    if 26 - 26: IiII
    if 52 - 52: O0 + ooOoO0o
  if ( OO00OO == None ) :
   OO00OO = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( OO00OO )
   if 11 - 11: i1IIi / I1Ii111 * I1ii11iIi11i * I1Ii111 * ooOoO0o - i11iIiiIii
   self . request_nonce_sent = OO00OO
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( OO00OO ) ) )
   if 96 - 96: I1ii11iIi11i % I1ii11iIi11i
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 1 - 1: I1IiiI . Ii1I
   if 26 - 26: oO0o - ooOoO0o % Oo0Ooo - oO0o + IiII
   if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
   if 21 - 21: O0 * ooOoO0o % OoO0O00
   if 14 - 14: O0 / I1Ii111 / ooOoO0o + IiII - IiII
   if ( lisp_i_am_itr == False ) : return ( OO00OO | 0x80000000 )
   self . send_request_ipc ( ipc_socket , OO00OO )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( OO00OO ) ) )
   if 10 - 10: O0 - I1ii11iIi11i / I1Ii111 % OoOoOO00 / OoooooooOO / Ii1I
   if 73 - 73: ooOoO0o + IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . I1Ii111
   if 76 - 76: I11i . I1ii11iIi11i * OoooooooOO % iII111i
   if 24 - 24: OoooooooOO
   if 83 - 83: O0 / OoO0O00
   if 62 - 62: I11i
   if 73 - 73: Ii1I % OoO0O00 * OOooOOo
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( OO00OO | 0x80000000 )
  if 84 - 84: Oo0Ooo
  if 18 - 18: OoooooooOO
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 85 - 85: OoooooooOO . OoO0O00 . OoO0O00
  o0O0oO0 = time . time ( ) - self . last_request_nonce_sent
  o00O0O0OoO = self . last_echo_nonce_rcvd
  return ( o0O0oO0 >= LISP_NONCE_ECHO_INTERVAL and o00O0O0OoO == None )
  if 83 - 83: i1IIi - OoooooooOO + OoO0O00 * I1IiiI
  if 61 - 61: iII111i % II111iiii / OoOoOO00 % I1ii11iIi11i . iIii1I11I1II1 % O0
 def recently_requested ( self ) :
  o00O0O0OoO = self . last_request_nonce_sent
  if ( o00O0O0OoO == None ) : return ( False )
  if 74 - 74: I1ii11iIi11i * oO0o + iII111i % O0
  o0O0oO0 = time . time ( ) - o00O0O0OoO
  return ( o0O0oO0 <= LISP_NONCE_ECHO_INTERVAL )
  if 18 - 18: i1IIi % IiII . O0 - O0 - O0 - II111iiii
  if 55 - 55: OoOoOO00 . iIii1I11I1II1 * OOooOOo % iIii1I11I1II1 . OoO0O00
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 43 - 43: Ii1I . OOooOOo + I1IiiI * i11iIiiIii
  if 2 - 2: OOooOOo
  if 3 - 3: I1IiiI . iII111i % O0 - ooOoO0o / O0
  if 79 - 79: Ii1I + oO0o % ooOoO0o % I1IiiI
  o00O0O0OoO = self . last_good_echo_nonce_rcvd
  if ( o00O0O0OoO == None ) : o00O0O0OoO = 0
  o0O0oO0 = time . time ( ) - o00O0O0OoO
  if ( o0O0oO0 <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 68 - 68: II111iiii - OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo % II111iiii
  if 53 - 53: iII111i . oO0o / Oo0Ooo . OoO0O00 . i11iIiiIii
  if 60 - 60: II111iiii
  if 25 - 25: Oo0Ooo + o0oOOo0O0Ooo - OoO0O00
  if 57 - 57: II111iiii . i1IIi
  if 33 - 33: iII111i + Oo0Ooo % I11i . oO0o
  o00O0O0OoO = self . last_new_request_nonce_sent
  if ( o00O0O0OoO == None ) : o00O0O0OoO = 0
  o0O0oO0 = time . time ( ) - o00O0O0OoO
  return ( o0O0oO0 <= LISP_NONCE_ECHO_INTERVAL )
  if 6 - 6: IiII + I1ii11iIi11i
  if 62 - 62: oO0o . I1Ii111 - OoooooooOO * II111iiii . i11iIiiIii
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   iiIIiIi1i1I1 = bold ( "down" , False )
   oOoooo0OooO = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , iiIIiIi1i1I1 , oOoooo0OooO ) )
   if 67 - 67: OoooooooOO + OoO0O00 / Oo0Ooo % o0oOOo0O0Ooo % i1IIi
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 31 - 31: IiII . II111iiii % Oo0Ooo * Ii1I + Ii1I
   if 87 - 87: OoO0O00
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 23 - 23: OOooOOo + ooOoO0o / i11iIiiIii * Oo0Ooo . OoO0O00
  if ( self . recently_requested ( ) == False ) :
   i1I111II = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , i1I111II ) )
   if 51 - 51: I1IiiI * ooOoO0o
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 47 - 47: OOooOOo . OOooOOo . IiII . I1Ii111 / i1IIi
   if 77 - 77: II111iiii % I11i / Oo0Ooo
   if 23 - 23: iIii1I11I1II1
 def print_echo_nonce ( self ) :
  I11IIiII = lisp_print_elapsed ( self . last_request_nonce_sent )
  iii111 = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 96 - 96: o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + OoO0O00 - IiII - IiII
  i1ii1iiI1iI = lisp_print_elapsed ( self . last_echo_nonce_sent )
  Ii1i1 = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  o0 = space ( 4 )
  if 42 - 42: oO0o
  o0OooooOoOO = "Nonce-Echoing:\n"
  o0OooooOoOO += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( o0 , I11IIiII , o0 , iii111 )
  if 22 - 22: iIii1I11I1II1 % I1IiiI . O0
  o0OooooOoOO += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( o0 , Ii1i1 , o0 , i1ii1iiI1iI )
  if 13 - 13: II111iiii % i1IIi - OoOoOO00 + iII111i
  if 59 - 59: OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
  return ( o0OooooOoOO )
  if 42 - 42: I1Ii111
  if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
  if 80 - 80: OOooOOo
  if 12 - 12: Ii1I
  if 2 - 2: OoooooooOO
  if 100 - 100: Oo0Ooo / O0 * i11iIiiIii * OoooooooOO
  if 46 - 46: O0 % OoooooooOO
  if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
  if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
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
    if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   iII1 = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( iII1 )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 2 - 2: ooOoO0o - O0 - I1ii11iIi11i / I11i * OoOoOO00
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 26 - 26: I1ii11iIi11i + I1Ii111 - oO0o + IiII % OOooOOo
  if 84 - 84: I11i % Ii1I % O0 * o0oOOo0O0Ooo
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
  if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
  oo0O = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   oo0O = struct . pack ( "Q" , oo0O & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   oO0oo0O0OOOo0 = struct . pack ( "I" , ( oo0O >> 64 ) & LISP_4_32_MASK )
   iII11I = struct . pack ( "Q" , oo0O & LISP_8_64_MASK )
   oo0O = oO0oo0O0OOOo0 + iII11I
  else :
   oo0O = struct . pack ( "QQ" , oo0O >> 64 , oo0O & LISP_8_64_MASK )
  return ( oo0O )
  if 44 - 44: iII111i
  if 79 - 79: o0oOOo0O0Ooo % OOooOOo . O0
 def key_length ( self , key ) :
  if ( type ( key ) != str ) : key = self . normalize_pub_key ( key )
  return ( len ( key ) / 2 )
  if 56 - 56: oO0o + i1IIi * iII111i - O0
  if 84 - 84: iII111i % I1IiiI / iIii1I11I1II1 * Ii1I * iIii1I11I1II1 + I1ii11iIi11i
 def print_key ( self , key ) :
  oo0O0000O0 = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( oo0O0000O0 [ 0 : 4 ] , oo0O0000O0 [ - 4 : : ] , self . key_length ( oo0O0000O0 ) ) )
  if 78 - 78: IiII / iII111i * Ii1I . OOooOOo . oO0o - I1Ii111
  if 39 - 39: ooOoO0o . i1IIi + OoooooooOO . iII111i - i11iIiiIii % I1Ii111
 def normalize_pub_key ( self , key ) :
  if ( type ( key ) == str ) :
   if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
   return ( key )
   if 38 - 38: oO0o
  key = lisp_hex_string ( key ) . zfill ( 256 )
  return ( key )
  if 9 - 9: I11i . OoO0O00 . oO0o / OoooooooOO
  if 59 - 59: iIii1I11I1II1 + i1IIi % II111iiii
 def print_keys ( self , do_bold = True ) :
  o0000oO = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   o0000oO += "none"
  else :
   o0000oO += self . print_key ( self . local_public_key )
   if 2 - 2: II111iiii + I11i . OoO0O00
  O0OooO0oo = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   O0OooO0oo += "none"
  else :
   O0OooO0oo += self . print_key ( self . remote_public_key )
   if 14 - 14: OOooOOo * I1IiiI - I1ii11iIi11i
  I1111I1i1i = "ECDH" if ( self . curve25519 ) else "DH"
  O0oOo = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( I1111I1i1i , O0oOo , o0000oO , O0OooO0oo ) )
  if 14 - 14: I1Ii111 + I1Ii111 / OoOoOO00 + OoOoOO00 * ooOoO0o / I1Ii111
  if 68 - 68: OoooooooOO
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 38 - 38: iII111i + ooOoO0o
  if 32 - 32: ooOoO0o - OoooooooOO + OoO0O00
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 90 - 90: I1ii11iIi11i / OoooooooOO % i11iIiiIii - IiII
  iII1 = self . local_private_key
  II1IIiIiiI1iI = self . dh_g_value
  iIiiI11II11 = self . dh_p_value
  return ( int ( ( II1IIiIiiI1iI ** iII1 ) % iIiiI11II11 ) )
  if 75 - 75: I1Ii111 - iII111i . oO0o
  if 88 - 88: iII111i - OoooooooOO . ooOoO0o - o0oOOo0O0Ooo / OoOoOO00 % I11i
 def compute_shared_key ( self , ed , print_shared = False ) :
  iII1 = self . local_private_key
  o00O00o = self . remote_public_key
  if 69 - 69: i1IIi . Ii1I
  oO0O00O0O0o = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( oO0O00O0O0o , self . print_keys ( ) ) )
  if 41 - 41: Ii1I . i11iIiiIii + O0 - OoooooooOO * oO0o
  if ( self . curve25519 ) :
   i1IiI111IiiI1 = curve25519 . Public ( o00O00o )
   self . shared_key = self . curve25519 . get_shared_key ( i1IiI111IiiI1 )
  else :
   iIiiI11II11 = self . dh_p_value
   self . shared_key = ( o00O00o ** iII1 ) % iIiiI11II11
   if 8 - 8: Oo0Ooo / I1ii11iIi11i + I1ii11iIi11i . Ii1I
   if 27 - 27: II111iiii - i11iIiiIii - OoooooooOO
   if 90 - 90: I1IiiI
   if 4 - 4: OOooOOo % ooOoO0o - OOooOOo - o0oOOo0O0Ooo
   if 30 - 30: IiII
   if 34 - 34: oO0o - II111iiii - o0oOOo0O0Ooo + iII111i + I1Ii111
   if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
  if ( print_shared ) :
   oo0O0000O0 = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( oo0O0000O0 ) )
   if 20 - 20: i11iIiiIii - II111iiii - ooOoO0o % oO0o . ooOoO0o
   if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
   if 84 - 84: OoOoOO00 - I11i
   if 80 - 80: i11iIiiIii % OOooOOo - Oo0Ooo % OOooOOo
   if 89 - 89: Ii1I * I11i + OoOoOO00 / i11iIiiIii
  self . compute_encrypt_icv_keys ( )
  if 68 - 68: OoooooooOO * I11i
  if 86 - 86: o0oOOo0O0Ooo / OoOoOO00
  if 40 - 40: iII111i
  if 62 - 62: ooOoO0o / OOooOOo
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 74 - 74: iII111i % I1Ii111 / I1Ii111 - iIii1I11I1II1 - II111iiii + OOooOOo
  if 92 - 92: I11i % I1Ii111
 def compute_encrypt_icv_keys ( self ) :
  I1i1i1 = hashlib . sha256
  if ( self . curve25519 ) :
   Ii11i1IiII = self . shared_key
  else :
   Ii11i1IiII = lisp_hex_string ( self . shared_key )
   if 96 - 96: i11iIiiIii - OoOoOO00 / iII111i % OoooooooOO / iIii1I11I1II1 - OOooOOo
   if 52 - 52: iIii1I11I1II1 * OoOoOO00 + o0oOOo0O0Ooo . I11i
   if 59 - 59: iII111i . i1IIi
   if 31 - 31: I1IiiI + I1IiiI
   if 11 - 11: IiII + OoOoOO00 % o0oOOo0O0Ooo * OoO0O00 / IiII
  o0000oO = self . local_public_key
  if ( type ( o0000oO ) != long ) : o0000oO = int ( binascii . hexlify ( o0000oO ) , 16 )
  O0OooO0oo = self . remote_public_key
  if ( type ( O0OooO0oo ) != long ) : O0OooO0oo = int ( binascii . hexlify ( O0OooO0oo ) , 16 )
  I11Ii = "0001" + "lisp-crypto" + lisp_hex_string ( o0000oO ^ O0OooO0oo ) + "0100"
  if 96 - 96: Oo0Ooo . oO0o + iIii1I11I1II1 * OoOoOO00 - O0
  ooo0O0O = hmac . new ( I11Ii , Ii11i1IiII , I1i1i1 ) . hexdigest ( )
  ooo0O0O = int ( ooo0O0O , 16 )
  if 17 - 17: I1IiiI
  if 81 - 81: O0 + Ii1I / Ii1I - OoO0O00 + II111iiii
  if 17 - 17: I1IiiI + OOooOOo % o0oOOo0O0Ooo
  if 34 - 34: Ii1I * I11i / OoooooooOO - iIii1I11I1II1
  O0Ooo00o0OoOo = ( ooo0O0O >> 128 ) & LISP_16_128_MASK
  o0000ooOooOO = ooo0O0O & LISP_16_128_MASK
  self . encrypt_key = lisp_hex_string ( O0Ooo00o0OoOo ) . zfill ( 32 )
  i1III = 32 if self . do_poly else 40
  self . icv_key = lisp_hex_string ( o0000ooOooOO ) . zfill ( i1III )
  if 100 - 100: IiII + i1IIi * OoO0O00
  if 64 - 64: oO0o * i11iIiiIii . Oo0Ooo
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   OOo0 = self . icv . poly1305aes
   OO00 = self . icv . binascii . hexlify
   nonce = OO00 ( nonce )
   ii1i = OOo0 ( self . encrypt_key , self . icv_key , nonce , packet )
   ii1i = OO00 ( ii1i )
  else :
   iII1 = binascii . unhexlify ( self . icv_key )
   ii1i = hmac . new ( iII1 , packet , self . icv ) . hexdigest ( )
   ii1i = ii1i [ 0 : 40 ]
   if 31 - 31: Oo0Ooo
  return ( ii1i )
  if 1 - 1: i1IIi
  if 27 - 27: I11i
 def add_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 47 - 47: OoooooooOO
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 48 - 48: OoOoOO00 . IiII % I1IiiI + I11i
  if 37 - 37: Oo0Ooo + I1Ii111 * oO0o / o0oOOo0O0Ooo
 def delete_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 78 - 78: IiII + I11i - o0oOOo0O0Ooo + OoO0O00 / iIii1I11I1II1
  if 47 - 47: OOooOOo
 def add_key_by_rloc ( self , addr_str , encap ) :
  I1I111iiII = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 62 - 62: ooOoO0o * Ii1I % I1ii11iIi11i - i1IIi - I1ii11iIi11i
  if 24 - 24: OOooOOo
  if ( I1I111iiII . has_key ( addr_str ) == False ) :
   I1I111iiII [ addr_str ] = [ None , None , None , None ]
   if 71 - 71: IiII - i1IIi
  I1I111iiII [ addr_str ] [ self . key_id ] = self
  if 56 - 56: OoOoOO00 + oO0o
  if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
  if 19 - 19: IiII % OoooooooOO + OoooooooOO
  if 7 - 7: i1IIi
  if 91 - 91: OoOoOO00 - OoOoOO00 . IiII
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , I1I111iiII [ addr_str ] )
   if 33 - 33: I1Ii111 - iIii1I11I1II1 / Ii1I % O0
   if 80 - 80: IiII % OoooooooOO - IiII
   if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
 def encode_lcaf ( self , rloc_addr ) :
  IIIiIIi111 = self . normalize_pub_key ( self . local_public_key )
  oo0O0 = self . key_length ( IIIiIIi111 )
  Oo0i11iiI11II = ( 6 + oo0O0 + 2 )
  if ( rloc_addr != None ) : Oo0i11iiI11II += rloc_addr . addr_length ( )
  if 3 - 3: OOooOOo + I11i
  ii1i1II = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( Oo0i11iiI11II ) , 1 , 0 )
  if 20 - 20: i11iIiiIii / OoOoOO00 + I1ii11iIi11i / O0
  if 97 - 97: i11iIiiIii
  if 16 - 16: i1IIi
  if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
  if 41 - 41: OoooooooOO
  if 13 - 13: I11i + I1Ii111 - I1Ii111 % oO0o / I11i
  O0oOo = self . cipher_suite
  ii1i1II += struct . pack ( "BBH" , O0oOo , 0 , socket . htons ( oo0O0 ) )
  if 4 - 4: I1IiiI + OOooOOo - IiII + iII111i
  if 78 - 78: Ii1I
  if 29 - 29: II111iiii
  if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
  for i1i1IIIIIIIi in range ( 0 , oo0O0 * 2 , 16 ) :
   iII1 = int ( IIIiIIi111 [ i1i1IIIIIIIi : i1i1IIIIIIIi + 16 ] , 16 )
   ii1i1II += struct . pack ( "Q" , byte_swap_64 ( iII1 ) )
   if 84 - 84: Oo0Ooo % I11i * O0 * I11i
   if 66 - 66: OOooOOo / iIii1I11I1II1 - OoOoOO00 % O0 . ooOoO0o
   if 12 - 12: Oo0Ooo + I1IiiI
   if 37 - 37: i1IIi * i11iIiiIii
   if 95 - 95: i11iIiiIii % I1Ii111 * Oo0Ooo + i1IIi . O0 + I1ii11iIi11i
  if ( rloc_addr ) :
   ii1i1II += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   ii1i1II += rloc_addr . pack_address ( )
   if 7 - 7: OoO0O00 * i11iIiiIii * iIii1I11I1II1 / OOooOOo / I1Ii111
  return ( ii1i1II )
  if 35 - 35: iII111i * OOooOOo
  if 65 - 65: II111iiii % i1IIi
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 13 - 13: OoO0O00 * I1Ii111 + Oo0Ooo - IiII
  if 31 - 31: OoO0O00
  if 68 - 68: OoO0O00 + i1IIi / iIii1I11I1II1 + II111iiii * iIii1I11I1II1 + I1ii11iIi11i
  if 77 - 77: i11iIiiIii - I1Ii111 . I1ii11iIi11i % Oo0Ooo . Ii1I
  if ( lcaf_len == 0 ) :
   o00OooooOOOO = "HHBBH"
   oO0o00O = struct . calcsize ( o00OooooOOOO )
   if ( len ( packet ) < oO0o00O ) : return ( None )
   if 9 - 9: o0oOOo0O0Ooo
   oO0oO00 , O0Ooo000Ooo , iiii1II , O0Ooo000Ooo , lcaf_len = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
   if 28 - 28: OoooooooOO % I11i
   if 3 - 3: o0oOOo0O0Ooo / Oo0Ooo - OoO0O00 + II111iiii
   if ( iiii1II != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 3 - 3: i11iIiiIii
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ oO0o00O : : ]
   if 20 - 20: i1IIi * iII111i + OoO0O00 * OoO0O00 / Oo0Ooo
   if 83 - 83: I1ii11iIi11i
   if 53 - 53: OoOoOO00 % ooOoO0o . OoO0O00 + I1IiiI / I1ii11iIi11i
   if 76 - 76: I1ii11iIi11i . iIii1I11I1II1 - i11iIiiIii / I1ii11iIi11i - o0oOOo0O0Ooo
   if 95 - 95: I11i
   if 76 - 76: II111iiii - i1IIi . O0 * i11iIiiIii % o0oOOo0O0Ooo - iII111i
  iiii1II = LISP_LCAF_SECURITY_TYPE
  o00OooooOOOO = "BBBBH"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 30 - 30: I1Ii111 % oO0o + oO0o * OoooooooOO - I1ii11iIi11i
  OOoOOo , O0Ooo000Ooo , O0oOo , O0Ooo000Ooo , oo0O0 = struct . unpack ( o00OooooOOOO ,
 packet [ : oO0o00O ] )
  if 22 - 22: OoOoOO00 . II111iiii
  if 24 - 24: OoooooooOO / I11i
  if 97 - 97: I1ii11iIi11i - ooOoO0o * i11iIiiIii + I1Ii111 % OoooooooOO
  if 44 - 44: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo % O0 / OoooooooOO . OOooOOo
  if 3 - 3: O0 - I1Ii111 * Ii1I * OOooOOo / Ii1I
  if 58 - 58: Ii1I * iIii1I11I1II1 + ooOoO0o . ooOoO0o
  packet = packet [ oO0o00O : : ]
  oo0O0 = socket . ntohs ( oo0O0 )
  if ( len ( packet ) < oo0O0 ) : return ( None )
  if 74 - 74: ooOoO0o - o0oOOo0O0Ooo * IiII % ooOoO0o
  if 93 - 93: iIii1I11I1II1 / OoOoOO00 % Oo0Ooo * I1Ii111 - OoO0O00 - o0oOOo0O0Ooo
  if 44 - 44: OoooooooOO
  if 82 - 82: OoOoOO00 . OoOoOO00
  IIiIiIii11I1 = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( O0oOo not in IIiIiIii11I1 ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( IIiIiIii11I1 ,
 O0oOo ) )
   packet = packet [ oo0O0 : : ]
   return ( packet )
   if 60 - 60: OoooooooOO * Oo0Ooo % I1Ii111
   if 68 - 68: O0 - Oo0Ooo . II111iiii % Ii1I % Oo0Ooo + i11iIiiIii
  self . cipher_suite = O0oOo
  if 90 - 90: II111iiii / OOooOOo * I1IiiI - Oo0Ooo
  if 11 - 11: IiII - oO0o - oO0o / I1Ii111 * II111iiii % oO0o
  if 39 - 39: oO0o / i11iIiiIii
  if 46 - 46: i11iIiiIii . I1ii11iIi11i
  if 11 - 11: ooOoO0o
  IIIiIIi111 = 0
  for i1i1IIIIIIIi in range ( 0 , oo0O0 , 8 ) :
   iII1 = byte_swap_64 ( struct . unpack ( "Q" , packet [ i1i1IIIIIIIi : i1i1IIIIIIIi + 8 ] ) [ 0 ] )
   IIIiIIi111 <<= 64
   IIIiIIi111 |= iII1
   if 36 - 36: OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
  self . remote_public_key = IIIiIIi111
  if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
  if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
  if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
  if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
  if 28 - 28: iIii1I11I1II1 . O0
  if ( self . curve25519 ) :
   iII1 = lisp_hex_string ( self . remote_public_key )
   iII1 = iII1 . zfill ( 64 )
   iiiI = ""
   for i1i1IIIIIIIi in range ( 0 , len ( iII1 ) , 2 ) :
    iiiI += chr ( int ( iII1 [ i1i1IIIIIIIi : i1i1IIIIIIIi + 2 ] , 16 ) )
    if 41 - 41: Ii1I
   self . remote_public_key = iiiI
   if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
   if 47 - 47: O0 . o0oOOo0O0Ooo / Ii1I * iII111i
  packet = packet [ oo0O0 : : ]
  return ( packet )
  if 63 - 63: I1Ii111 - oO0o - iII111i - ooOoO0o / oO0o + OoO0O00
  if 94 - 94: IiII / I1IiiI . II111iiii
  if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
  if 37 - 37: OOooOOo + O0 + OOooOOo . iII111i . o0oOOo0O0Ooo
  if 78 - 78: I1IiiI / I11i + o0oOOo0O0Ooo . Oo0Ooo / O0
  if 49 - 49: I1ii11iIi11i
  if 66 - 66: o0oOOo0O0Ooo . I1ii11iIi11i
  if 18 - 18: Oo0Ooo + IiII
class lisp_thread ( ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = Queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
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
  if 20 - 20: I1Ii111 . I11i . Ii1I + I11i - OOooOOo * oO0o
  if 82 - 82: OoO0O00
 def decode ( self , packet ) :
  o00OooooOOOO = "BBBBQ"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( False )
  if 78 - 78: II111iiii / I11i - i11iIiiIii + I1ii11iIi11i * Oo0Ooo
  i1Ii1II , iIiI1 , IiIi11i1 , self . record_count , self . nonce = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  if 87 - 87: o0oOOo0O0Ooo % Oo0Ooo % II111iiii + iII111i * I1IiiI
  if 18 - 18: ooOoO0o * II111iiii
  self . type = i1Ii1II >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( i1Ii1II & 0x01 ) else False
   self . rloc_probe = True if ( i1Ii1II & 0x02 ) else False
   self . smr_invoked_bit = True if ( iIiI1 & 0x40 ) else False
   if 43 - 43: o0oOOo0O0Ooo / O0 + i1IIi - I1ii11iIi11i % i11iIiiIii
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( i1Ii1II & 0x04 ) else False
   self . to_etr = True if ( i1Ii1II & 0x02 ) else False
   self . to_ms = True if ( i1Ii1II & 0x01 ) else False
   if 69 - 69: OOooOOo % I1ii11iIi11i / OoOoOO00 . OOooOOo - IiII
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( i1Ii1II & 0x08 ) else False
   if 74 - 74: OoO0O00 - o0oOOo0O0Ooo - IiII . O0 % ooOoO0o
  return ( True )
  if 32 - 32: OoOoOO00 . OoO0O00 / Oo0Ooo . i11iIiiIii
  if 9 - 9: I11i - II111iiii + I1Ii111 / oO0o % I1ii11iIi11i
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 17 - 17: iIii1I11I1II1 - ooOoO0o
  if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 52 - 52: I1ii11iIi11i
  if 93 - 93: iII111i . i11iIiiIii
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
  if 49 - 49: O0 . Oo0Ooo / Ii1I
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
  if 86 - 86: I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 20 - 20: iII111i . OoooooooOO + iII111i + ooOoO0o * I1ii11iIi11i
  if 44 - 44: i11iIiiIii
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 69 - 69: OOooOOo * O0 + i11iIiiIii
  if 65 - 65: O0 / iII111i . i1IIi * iII111i / iIii1I11I1II1 - oO0o
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 93 - 93: OoOoOO00 % i11iIiiIii - Ii1I % OoO0O00
  if 55 - 55: o0oOOo0O0Ooo . I1ii11iIi11i
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
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
  if 69 - 69: OOooOOo * II111iiii - ooOoO0o - i1IIi + i11iIiiIii
  if 50 - 50: OoooooooOO * i1IIi / oO0o
 def print_map_register ( self ) :
  oOo0 = lisp_hex_string ( self . xtr_id )
  if 19 - 19: o0oOOo0O0Ooo
  I111 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 19 - 19: OoooooooOO
  lprint ( I111 . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # iIii1I11I1II1 % I1IiiI % O0 * i11iIiiIii % IiII . OoO0O00
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , oOo0 , self . site_id ) )
  if 68 - 68: Ii1I . I1Ii111 - o0oOOo0O0Ooo
  if 25 - 25: I1Ii111
  if 9 - 9: iIii1I11I1II1 / II111iiii * OOooOOo
  if 96 - 96: Ii1I + I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
 def encode ( self ) :
  i1IiIiiiii11 = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : i1IiIiiiii11 |= 0x08000000
  if ( self . lisp_sec_present ) : i1IiIiiiii11 |= 0x04000000
  if ( self . xtr_id_present ) : i1IiIiiiii11 |= 0x02000000
  if ( self . map_register_refresh ) : i1IiIiiiii11 |= 0x1000
  if ( self . use_ttl_for_timeout ) : i1IiIiiiii11 |= 0x800
  if ( self . merge_register_requested ) : i1IiIiiiii11 |= 0x400
  if ( self . mobile_node ) : i1IiIiiiii11 |= 0x200
  if ( self . map_notify_requested ) : i1IiIiiiii11 |= 0x100
  if ( self . encryption_key_id != None ) :
   i1IiIiiiii11 |= 0x2000
   i1IiIiiiii11 |= self . encryption_key_id << 14
   if 43 - 43: ooOoO0o . i1IIi
   if 68 - 68: IiII % Oo0Ooo . O0 - OoOoOO00 + I1ii11iIi11i . i11iIiiIii
   if 45 - 45: I1IiiI
   if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
   if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
    if 61 - 61: Oo0Ooo - I1Ii111
    if 51 - 51: iII111i * ooOoO0o / O0 / O0
  ii1i1II = struct . pack ( "I" , socket . htonl ( i1IiIiiiii11 ) )
  ii1i1II += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 52 - 52: OoooooooOO % O0
  ii1i1II = self . zero_auth ( ii1i1II )
  return ( ii1i1II )
  if 56 - 56: oO0o - i1IIi * OoooooooOO - II111iiii
  if 28 - 28: i1IIi / I11i . o0oOOo0O0Ooo
 def zero_auth ( self , packet ) :
  i1 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  iIIiiiIiiii11 = ""
  iI1i1i1i1i = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   iIIiiiIiiii11 = struct . pack ( "QQI" , 0 , 0 , 0 )
   iI1i1i1i1i = struct . calcsize ( "QQI" )
   if 10 - 10: II111iiii . OOooOOo / iII111i
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   iIIiiiIiiii11 = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   iI1i1i1i1i = struct . calcsize ( "QQQQ" )
   if 35 - 35: iII111i / Oo0Ooo + O0 * iIii1I11I1II1 - O0
  packet = packet [ 0 : i1 ] + iIIiiiIiiii11 + packet [ i1 + iI1i1i1i1i : : ]
  return ( packet )
  if 3 - 3: I1ii11iIi11i
  if 42 - 42: I11i % Oo0Ooo + IiII - I11i . iIii1I11I1II1 - Ii1I
 def encode_auth ( self , packet ) :
  i1 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  iI1i1i1i1i = self . auth_len
  iIIiiiIiiii11 = self . auth_data
  packet = packet [ 0 : i1 ] + iIIiiiIiiii11 + packet [ i1 + iI1i1i1i1i : : ]
  return ( packet )
  if 27 - 27: iII111i % Oo0Ooo . I1ii11iIi11i . i1IIi % OoOoOO00 . o0oOOo0O0Ooo
  if 37 - 37: iII111i + I1Ii111 * Ii1I + IiII
 def decode ( self , packet ) :
  IiIIIii1iIII1 = packet
  o00OooooOOOO = "I"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( [ None , None ] )
  if 69 - 69: i1IIi / i11iIiiIii + Oo0Ooo - OoOoOO00
  i1IiIiiiii11 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  i1IiIiiiii11 = socket . ntohl ( i1IiIiiiii11 [ 0 ] )
  packet = packet [ oO0o00O : : ]
  if 13 - 13: IiII . iIii1I11I1II1
  o00OooooOOOO = "QBBH"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( [ None , None ] )
  if 30 - 30: i1IIi
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  if 42 - 42: iII111i
  if 35 - 35: II111iiii % OOooOOo . oO0o * ooOoO0o
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( i1IiIiiiii11 & 0x08000000 ) else False
  if 54 - 54: ooOoO0o * I11i - I1Ii111
  self . lisp_sec_present = True if ( i1IiIiiiii11 & 0x04000000 ) else False
  self . xtr_id_present = True if ( i1IiIiiiii11 & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( i1IiIiiiii11 & 0x800 ) else False
  self . map_register_refresh = True if ( i1IiIiiiii11 & 0x1000 ) else False
  self . merge_register_requested = True if ( i1IiIiiiii11 & 0x400 ) else False
  self . mobile_node = True if ( i1IiIiiiii11 & 0x200 ) else False
  self . map_notify_requested = True if ( i1IiIiiiii11 & 0x100 ) else False
  self . record_count = i1IiIiiiii11 & 0xff
  if 15 - 15: iII111i / O0
  if 61 - 61: i1IIi / i1IIi + ooOoO0o . I1Ii111 * ooOoO0o
  if 19 - 19: o0oOOo0O0Ooo . II111iiii / i1IIi
  if 82 - 82: O0 / iII111i * OoO0O00 - I11i + Oo0Ooo
  self . encrypt_bit = True if i1IiIiiiii11 & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( i1IiIiiiii11 >> 14 ) & 0x7
   if 47 - 47: I1ii11iIi11i * I1IiiI / I1ii11iIi11i + Ii1I * II111iiii
   if 78 - 78: I1Ii111 - i1IIi + OoOoOO00 + Oo0Ooo * I1ii11iIi11i * o0oOOo0O0Ooo
   if 97 - 97: i1IIi
   if 29 - 29: I1IiiI
   if 37 - 37: I1ii11iIi11i * I1Ii111 * I1IiiI * O0
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( IiIIIii1iIII1 ) == False ) : return ( [ None , None ] )
   if 35 - 35: I1IiiI - I1ii11iIi11i * iII111i + IiII / i1IIi
   if 46 - 46: Oo0Ooo . ooOoO0o % Oo0Ooo / II111iiii * ooOoO0o * OOooOOo
  packet = packet [ oO0o00O : : ]
  if 59 - 59: I1Ii111 * iII111i
  if 31 - 31: I11i / O0
  if 57 - 57: i1IIi % ooOoO0o
  if 69 - 69: o0oOOo0O0Ooo
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 69 - 69: I1Ii111
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 83 - 83: iIii1I11I1II1 . o0oOOo0O0Ooo + I1Ii111 . OoooooooOO / ooOoO0o + II111iiii
    if 90 - 90: Ii1I * iII111i / OOooOOo
   iI1i1i1i1i = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    oO0o00O = struct . calcsize ( "QQI" )
    if ( iI1i1i1i1i < oO0o00O ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 68 - 68: OoOoOO00
    o0oO000oO , IiiIi1 , o0000o0OOOo = struct . unpack ( "QQI" , packet [ : iI1i1i1i1i ] )
    iiiiiI1iii11 = ""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    oO0o00O = struct . calcsize ( "QQQQ" )
    if ( iI1i1i1i1i < oO0o00O ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 13 - 13: o0oOOo0O0Ooo % O0 - I1Ii111 * OoooooooOO / Oo0Ooo - OoooooooOO
    o0oO000oO , IiiIi1 , o0000o0OOOo , iiiiiI1iii11 = struct . unpack ( "QQQQ" ,
 packet [ : iI1i1i1i1i ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 78 - 78: oO0o % OoooooooOO
    return ( [ None , None ] )
    if 73 - 73: I1IiiI % ooOoO0o % IiII + i1IIi - OoooooooOO / oO0o
   self . auth_data = lisp_concat_auth_data ( self . alg_id , o0oO000oO , IiiIi1 ,
 o0000o0OOOo , iiiiiI1iii11 )
   IiIIIii1iIII1 = self . zero_auth ( IiIIIii1iIII1 )
   packet = packet [ self . auth_len : : ]
   if 78 - 78: OoooooooOO % oO0o - i11iIiiIii
  return ( [ IiIIIii1iIII1 , packet ] )
  if 37 - 37: IiII % Ii1I % i1IIi
  if 23 - 23: ooOoO0o - O0 + i11iIiiIii
 def encode_xtr_id ( self , packet ) :
  oO0ooOoOooO00o00 = self . xtr_id >> 64
  o0Ooo00Oo0oo0 = self . xtr_id & 0xffffffffffffffff
  oO0ooOoOooO00o00 = byte_swap_64 ( oO0ooOoOooO00o00 )
  o0Ooo00Oo0oo0 = byte_swap_64 ( o0Ooo00Oo0oo0 )
  I11 = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , oO0ooOoOooO00o00 , o0Ooo00Oo0oo0 , I11 )
  return ( packet )
  if 51 - 51: II111iiii % I1IiiI * IiII * I1ii11iIi11i
  if 72 - 72: IiII % ooOoO0o / Oo0Ooo + iII111i
 def decode_xtr_id ( self , packet ) :
  oO0o00O = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < oO0o00O ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - oO0o00O : : ]
  oO0ooOoOooO00o00 , o0Ooo00Oo0oo0 , I11 = struct . unpack ( "QQQ" ,
 packet [ : oO0o00O ] )
  oO0ooOoOooO00o00 = byte_swap_64 ( oO0ooOoOooO00o00 )
  o0Ooo00Oo0oo0 = byte_swap_64 ( o0Ooo00Oo0oo0 )
  self . xtr_id = ( oO0ooOoOooO00o00 << 64 ) | o0Ooo00Oo0oo0
  self . site_id = byte_swap_64 ( I11 )
  return ( True )
  if 62 - 62: OOooOOo / i1IIi * Ii1I * Ii1I + oO0o . o0oOOo0O0Ooo
  if 28 - 28: iIii1I11I1II1 + OoOoOO00 / IiII / Ii1I * OOooOOo
  if 33 - 33: OOooOOo
  if 22 - 22: O0 + OOooOOo % i1IIi
  if 83 - 83: O0 + Ii1I % i11iIiiIii
  if 32 - 32: I1Ii111 % Oo0Ooo - I11i + O0
  if 57 - 57: OoO0O00 + I1Ii111 . I11i . i1IIi - o0oOOo0O0Ooo / Oo0Ooo
  if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
  if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
  if 76 - 76: OoO0O00 * oO0o - OoO0O00
  if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
  if 14 - 14: i11iIiiIii % OOooOOo * o0oOOo0O0Ooo * OoOoOO00
  if 55 - 55: I1Ii111 * OOooOOo * I1Ii111
  if 70 - 70: O0 . Ii1I
  if 33 - 33: OOooOOo * Ii1I
  if 64 - 64: i11iIiiIii . iIii1I11I1II1
  if 7 - 7: OoOoOO00 % ooOoO0o + OoOoOO00 - OoOoOO00 * i11iIiiIii % OoO0O00
  if 57 - 57: OOooOOo / OoO0O00 + I1ii11iIi11i
  if 60 - 60: O0 * Oo0Ooo % OOooOOo + IiII . OoO0O00 . Oo0Ooo
  if 70 - 70: I11i . I1ii11iIi11i * oO0o
  if 97 - 97: oO0o . iIii1I11I1II1 - OOooOOo
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
  if 86 - 86: I1ii11iIi11i - I1ii11iIi11i / iII111i - I1ii11iIi11i * iII111i + I1Ii111
  if 61 - 61: Oo0Ooo / II111iiii / Oo0Ooo / i1IIi . Oo0Ooo - IiII
 def print_notify ( self ) :
  iIIiiiIiiii11 = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( iIIiiiIiiii11 ) != 40 ) :
   iIIiiiIiiii11 = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( iIIiiiIiiii11 ) != 64 ) :
   iIIiiiIiiii11 = self . auth_data
   if 30 - 30: OoooooooOO % OOooOOo
  I111 = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( I111 . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # IiII
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , iIIiiiIiiii11 ) )
  if 20 - 20: OoO0O00 / i11iIiiIii - i1IIi
  if 46 - 46: OOooOOo - Oo0Ooo % iII111i % i11iIiiIii
  if 80 - 80: I11i - I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
  if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   iIIiiiIiiii11 = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 82 - 82: Oo0Ooo / Ii1I / Ii1I % Ii1I
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   iIIiiiIiiii11 = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 20 - 20: ooOoO0o
  packet += iIIiiiIiiii11
  return ( packet )
  if 63 - 63: iIii1I11I1II1 . OoO0O00
  if 100 - 100: i1IIi * i1IIi
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   i1IiIiiiii11 = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   i1IiIiiiii11 = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 26 - 26: OOooOOo . OoO0O00 % OoOoOO00
  ii1i1II = struct . pack ( "I" , socket . htonl ( i1IiIiiiii11 ) )
  ii1i1II += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 94 - 94: IiII
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = ii1i1II + eid_records
   return ( self . packet )
   if 15 - 15: Ii1I - IiII / O0
   if 28 - 28: I1Ii111 . i1IIi / I1ii11iIi11i
   if 77 - 77: i11iIiiIii / I1Ii111 / i11iIiiIii % OoOoOO00 - I1Ii111
   if 80 - 80: I1Ii111 % OoOoOO00 . OoooooooOO . II111iiii % IiII
   if 6 - 6: I1Ii111 % IiII / Ii1I + I1Ii111 . oO0o
  ii1i1II = self . zero_auth ( ii1i1II )
  ii1i1II += eid_records
  if 70 - 70: iIii1I11I1II1 / Ii1I
  IiI1I1i1 = lisp_hash_me ( ii1i1II , self . alg_id , password , False )
  if 61 - 61: O0 * o0oOOo0O0Ooo + I1Ii111 - OOooOOo . I1IiiI - IiII
  i1 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  iI1i1i1i1i = self . auth_len
  self . auth_data = IiI1I1i1
  ii1i1II = ii1i1II [ 0 : i1 ] + IiI1I1i1 + ii1i1II [ i1 + iI1i1i1i1i : : ]
  self . packet = ii1i1II
  return ( ii1i1II )
  if 7 - 7: I1ii11iIi11i
  if 81 - 81: Oo0Ooo % II111iiii % o0oOOo0O0Ooo / I11i
 def decode ( self , packet ) :
  IiIIIii1iIII1 = packet
  o00OooooOOOO = "I"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 95 - 95: OoOoOO00 - O0 % OoooooooOO
  i1IiIiiiii11 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  i1IiIiiiii11 = socket . ntohl ( i1IiIiiiii11 [ 0 ] )
  self . map_notify_ack = ( ( i1IiIiiiii11 >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = i1IiIiiiii11 & 0xff
  packet = packet [ oO0o00O : : ]
  if 13 - 13: i11iIiiIii
  o00OooooOOOO = "QBBH"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ oO0o00O : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
  if 69 - 69: Oo0Ooo * ooOoO0o
  if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
  if 52 - 52: I1IiiI - i11iIiiIii / IiII . oO0o
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 38 - 38: oO0o + OoooooooOO * OoOoOO00 % oO0o
  iI1i1i1i1i = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   o0oO000oO , IiiIi1 , o0000o0OOOo = struct . unpack ( "QQI" , packet [ : iI1i1i1i1i ] )
   iiiiiI1iii11 = ""
   if 91 - 91: i1IIi - I1ii11iIi11i * I1IiiI
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   o0oO000oO , IiiIi1 , o0000o0OOOo , iiiiiI1iii11 = struct . unpack ( "QQQQ" ,
 packet [ : iI1i1i1i1i ] )
   if 24 - 24: OoOoOO00 * Ii1I
  self . auth_data = lisp_concat_auth_data ( self . alg_id , o0oO000oO , IiiIi1 ,
 o0000o0OOOo , iiiiiI1iii11 )
  if 17 - 17: OoO0O00 . I1IiiI * O0
  oO0o00O = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( IiIIIii1iIII1 [ : oO0o00O ] )
  oO0o00O += iI1i1i1i1i
  packet += IiIIIii1iIII1 [ oO0o00O : : ]
  return ( packet )
  if 81 - 81: OOooOOo
  if 58 - 58: II111iiii . I1Ii111 . Ii1I * OoooooooOO / Ii1I / I11i
  if 41 - 41: I11i + OoO0O00 . iII111i
  if 73 - 73: i11iIiiIii * I1IiiI + o0oOOo0O0Ooo / oO0o
  if 56 - 56: i1IIi
  if 11 - 11: i11iIiiIii % o0oOOo0O0Ooo / I11i * OoooooooOO
  if 82 - 82: IiII
  if 10 - 10: Oo0Ooo % OOooOOo / I11i * IiII - o0oOOo0O0Ooo
  if 54 - 54: i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i / I1IiiI . iIii1I11I1II1 / iII111i
  if 1 - 1: I1Ii111 / OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % Ii1I
  if 96 - 96: IiII / Ii1I % OoO0O00 . iIii1I11I1II1
  if 30 - 30: I11i - OoO0O00
  if 15 - 15: OoooooooOO
  if 31 - 31: II111iiii
  if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
  if 87 - 87: IiII
  if 45 - 45: oO0o + II111iiii * O0 % OOooOOo . iIii1I11I1II1
  if 55 - 55: IiII
  if 43 - 43: OOooOOo
  if 17 - 17: i11iIiiIii
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
  if 30 - 30: OoooooooOO % o0oOOo0O0Ooo + ooOoO0o * OoO0O00
  if 57 - 57: I11i + iIii1I11I1II1 . OoO0O00 + oO0o
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 4 - 4: Ii1I
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 43 - 43: i1IIi . I1IiiI * iIii1I11I1II1 * i11iIiiIii - OOooOOo + ooOoO0o
  if 56 - 56: Oo0Ooo % i11iIiiIii / Ii1I . I1Ii111 . OoO0O00 - OoOoOO00
 def print_map_request ( self ) :
  oOo0 = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   oOo0 = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 32 - 32: I1Ii111 / oO0o / I1IiiI
   if 22 - 22: OoO0O00 - OoOoOO00 . Oo0Ooo + o0oOOo0O0Ooo
   if 69 - 69: oO0o - I1IiiI
  I111 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 10 - 10: i1IIi / iII111i . II111iiii * i1IIi % OoooooooOO
  lprint ( I111 . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # O0 * Oo0Ooo % I1Ii111 - O0 * I11i
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , oOo0 ) )
  if 48 - 48: oO0o - OoooooooOO + o0oOOo0O0Ooo % i1IIi - I1IiiI + OOooOOo
  O0000 = self . keys
  for oo0O0oO0o in self . itr_rlocs :
   lprint ( "  itr-rloc: afi {} {}{}" . format ( oo0O0oO0o . afi ,
 red ( oo0O0oO0o . print_address_no_iid ( ) , False ) ,
 "" if ( O0000 == None ) else ", " + O0000 [ 1 ] . print_keys ( ) ) )
   O0000 = None
   if 37 - 37: O0
   if 34 - 34: IiII
   if 5 - 5: OoO0O00 . I1IiiI
 def sign_map_request ( self , privkey ) :
  IIiII11i1 = self . signature_eid . print_address ( )
  i1Iii = self . source_eid . print_address ( )
  oOOooo = self . target_eid . print_address ( )
  IiI11IiIIi = lisp_hex_string ( self . nonce ) + i1Iii + oOOooo
  self . map_request_signature = privkey . sign ( IiI11IiIIi )
  oOOo0OoooOo = binascii . b2a_base64 ( self . map_request_signature )
  oOOo0OoooOo = { "source-eid" : i1Iii , "signature-eid" : IIiII11i1 ,
 "signature" : oOOo0OoooOo }
  return ( json . dumps ( oOOo0OoooOo ) )
  if 33 - 33: I11i * iII111i + iIii1I11I1II1 - I1ii11iIi11i
  if 11 - 11: II111iiii + OoOoOO00 * I11i
 def verify_map_request_sig ( self , pubkey ) :
  i1IiIII = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( i1IiIII ) )
   return ( False )
   if 89 - 89: ooOoO0o + oO0o + Ii1I - OOooOOo
   if 12 - 12: OoOoOO00 - o0oOOo0O0Ooo - I1Ii111 / I11i
  i1Iii = self . source_eid . print_address ( )
  oOOooo = self . target_eid . print_address ( )
  IiI11IiIIi = lisp_hex_string ( self . nonce ) + i1Iii + oOOooo
  pubkey = binascii . a2b_base64 ( pubkey )
  if 17 - 17: OoO0O00 - I1Ii111 - II111iiii / I1Ii111 / Ii1I
  I11III111i1I = True
  try :
   iII1 = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 52 - 52: iII111i % iIii1I11I1II1 . I1ii11iIi11i + oO0o % iII111i * iII111i
   I11III111i1I = False
   if 83 - 83: oO0o - I1Ii111
   if 46 - 46: i11iIiiIii
  if ( I11III111i1I ) :
   try :
    I11III111i1I = iII1 . verify ( self . map_request_signature , IiI11IiIIi )
   except :
    I11III111i1I = False
    if 33 - 33: ooOoO0o / iII111i * Ii1I % i1IIi
    if 50 - 50: Oo0Ooo - O0 - oO0o % o0oOOo0O0Ooo / iII111i % iIii1I11I1II1
    if 9 - 9: OoOoOO00 * o0oOOo0O0Ooo
  I1i1I11I = bold ( "passed" if I11III111i1I else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( I1i1I11I , i1IiIII ) )
  return ( I11III111i1I )
  if 85 - 85: I1ii11iIi11i + iIii1I11I1II1 + I1Ii111 * i1IIi - O0 % iII111i
  if 32 - 32: Ii1I % I11i + OOooOOo % OoooooooOO
 def encode ( self , probe_dest , probe_port ) :
  i1IiIiiiii11 = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  i1IiIiiiii11 = i1IiIiiiii11 | ( self . itr_rloc_count << 8 )
  if ( self . auth_bit ) : i1IiIiiiii11 |= 0x08000000
  if ( self . map_data_present ) : i1IiIiiiii11 |= 0x04000000
  if ( self . rloc_probe ) : i1IiIiiiii11 |= 0x02000000
  if ( self . smr_bit ) : i1IiIiiiii11 |= 0x01000000
  if ( self . pitr_bit ) : i1IiIiiiii11 |= 0x00800000
  if ( self . smr_invoked_bit ) : i1IiIiiiii11 |= 0x00400000
  if ( self . mobile_node ) : i1IiIiiiii11 |= 0x00200000
  if ( self . xtr_id_present ) : i1IiIiiiii11 |= 0x00100000
  if ( self . local_xtr ) : i1IiIiiiii11 |= 0x00004000
  if ( self . dont_reply_bit ) : i1IiIiiiii11 |= 0x00002000
  if 68 - 68: I11i
  ii1i1II = struct . pack ( "I" , socket . htonl ( i1IiIiiiii11 ) )
  ii1i1II += struct . pack ( "Q" , self . nonce )
  if 13 - 13: i11iIiiIii - ooOoO0o
  if 54 - 54: I1IiiI * I1IiiI - I11i . O0 . iII111i - Ii1I
  if 86 - 86: I1IiiI . II111iiii * i1IIi % I1IiiI . OOooOOo
  if 79 - 79: OoO0O00 + O0 * OOooOOo
  if 51 - 51: i1IIi - oO0o / oO0o % o0oOOo0O0Ooo
  if 98 - 98: OoO0O00 * ooOoO0o + i1IIi + IiII - i1IIi % OoOoOO00
  iiiI1iiIiII1 = False
  oOo0oOOoo0O = self . privkey_filename
  if ( oOo0oOOoo0O != None and os . path . exists ( oOo0oOOoo0O ) ) :
   iI1IiI11Ii11i = open ( oOo0oOOoo0O , "r" ) ; iII1 = iI1IiI11Ii11i . read ( ) ; iI1IiI11Ii11i . close ( )
   try :
    iII1 = ecdsa . SigningKey . from_pem ( iII1 )
   except :
    return ( None )
    if 67 - 67: ooOoO0o . iIii1I11I1II1 . OoO0O00 + I1Ii111
   o0OOOO00O = self . sign_map_request ( iII1 )
   iiiI1iiIiII1 = True
  elif ( self . map_request_signature != None ) :
   oOOo0OoooOo = binascii . b2a_base64 ( self . map_request_signature )
   o0OOOO00O = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : oOOo0OoooOo }
   o0OOOO00O = json . dumps ( o0OOOO00O )
   iiiI1iiIiII1 = True
   if 58 - 58: OoOoOO00
  if ( iiiI1iiIiII1 ) :
   iiii1II = LISP_LCAF_JSON_TYPE
   I1I1iiI1iIIii = socket . htons ( LISP_AFI_LCAF )
   o00O0oOO0o = socket . htons ( len ( o0OOOO00O ) + 2 )
   O0000000oooOO = socket . htons ( len ( o0OOOO00O ) )
   ii1i1II += struct . pack ( "HBBBBHH" , I1I1iiI1iIIii , 0 , 0 , iiii1II , 0 ,
 o00O0oOO0o , O0000000oooOO )
   ii1i1II += o0OOOO00O
   ii1i1II += struct . pack ( "H" , 0 )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    ii1i1II += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    ii1i1II += self . source_eid . lcaf_encode_iid ( )
   else :
    ii1i1II += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    ii1i1II += self . source_eid . pack_address ( )
    if 7 - 7: OoO0O00 - ooOoO0o % i1IIi
    if 24 - 24: OoO0O00 % O0 % I11i
    if 61 - 61: ooOoO0o . iII111i / ooOoO0o * OoooooooOO
    if 13 - 13: II111iiii
    if 17 - 17: II111iiii
    if 66 - 66: IiII * oO0o
    if 73 - 73: i11iIiiIii + O0 % O0
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   oOo0O = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 70 - 70: II111iiii * OoooooooOO - Ii1I + oO0o * O0
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( oOo0O ) ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ oOo0O ]
    if 49 - 49: oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
    if 74 - 74: ooOoO0o % I1ii11iIi11i * i1IIi
    if 18 - 18: OoOoOO00
    if 30 - 30: II111iiii
    if 27 - 27: i1IIi - iIii1I11I1II1 + O0 % Oo0Ooo / OOooOOo + i1IIi
    if 48 - 48: Oo0Ooo
    if 70 - 70: OoooooooOO * i11iIiiIii
  for oo0O0oO0o in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( oo0O0oO0o ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     O0000 = lisp_keys ( 1 )
     self . keys = [ None , O0000 , None , None ]
     if 60 - 60: IiII / iIii1I11I1II1 + OoooooooOO - I1ii11iIi11i * i11iIiiIii
    O0000 = self . keys [ 1 ]
    O0000 . add_key_by_nonce ( self . nonce )
    ii1i1II += O0000 . encode_lcaf ( oo0O0oO0o )
   else :
    ii1i1II += struct . pack ( "H" , socket . htons ( oo0O0oO0o . afi ) )
    ii1i1II += oo0O0oO0o . pack_address ( )
    if 47 - 47: O0 . I1IiiI / ooOoO0o % i11iIiiIii
    if 47 - 47: Ii1I . OoOoOO00 . iIii1I11I1II1 . o0oOOo0O0Ooo
    if 39 - 39: o0oOOo0O0Ooo
  Ooo0o00 = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 75 - 75: iIii1I11I1II1 * iII111i / OoOoOO00 * II111iiii . i1IIi
  if 6 - 6: Ii1I % Ii1I / OoooooooOO * oO0o . I1IiiI . i1IIi
  O00 = 0
  if ( self . subscribe_bit ) :
   O00 = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 74 - 74: iII111i / OoOoOO00 % oO0o / i1IIi
    if 19 - 19: O0 + OoOoOO00 * OoOoOO00 . iII111i
    if 73 - 73: ooOoO0o
  o00OooooOOOO = "BB"
  ii1i1II += struct . pack ( o00OooooOOOO , O00 , Ooo0o00 )
  if 14 - 14: Oo0Ooo % iIii1I11I1II1 - iIii1I11I1II1 . iIii1I11I1II1 - o0oOOo0O0Ooo * I1Ii111
  if ( self . target_group . is_null ( ) == False ) :
   ii1i1II += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   ii1i1II += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   ii1i1II += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   ii1i1II += self . target_eid . lcaf_encode_iid ( )
  else :
   ii1i1II += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   ii1i1II += self . target_eid . pack_address ( )
   if 10 - 10: OoO0O00 - II111iiii % o0oOOo0O0Ooo - OoOoOO00 + OoO0O00
   if 88 - 88: iIii1I11I1II1 % ooOoO0o + o0oOOo0O0Ooo * OoOoOO00 / I11i . OoO0O00
   if 66 - 66: iIii1I11I1II1 * II111iiii . iIii1I11I1II1 * i11iIiiIii + I11i + Ii1I
   if 94 - 94: i1IIi * I11i - OoooooooOO . i1IIi / o0oOOo0O0Ooo
   if 51 - 51: i11iIiiIii * OoooooooOO
  if ( self . subscribe_bit ) : ii1i1II = self . encode_xtr_id ( ii1i1II )
  return ( ii1i1II )
  if 23 - 23: II111iiii + I11i / O0 . I11i . I1Ii111 + iIii1I11I1II1
  if 2 - 2: i1IIi . O0 / o0oOOo0O0Ooo . II111iiii / OoO0O00 % i1IIi
 def lcaf_decode_json ( self , packet ) :
  o00OooooOOOO = "BBBBHH"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 12 - 12: o0oOOo0O0Ooo
  Ooo0o00O0O0oO , OO000OOO , iiii1II , o000OOooo000O , o00O0oOO0o , O0000000oooOO = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  if 69 - 69: O0 . iII111i
  if 96 - 96: O0
  if ( iiii1II != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 89 - 89: I1ii11iIi11i - Oo0Ooo
  if 26 - 26: ooOoO0o % ooOoO0o / II111iiii / iII111i
  if 2 - 2: i1IIi / i11iIiiIii + I1IiiI
  if 95 - 95: I1ii11iIi11i / IiII % iIii1I11I1II1 + O0
  o00O0oOO0o = socket . ntohs ( o00O0oOO0o )
  O0000000oooOO = socket . ntohs ( O0000000oooOO )
  packet = packet [ oO0o00O : : ]
  if ( len ( packet ) < o00O0oOO0o ) : return ( None )
  if ( o00O0oOO0o != O0000000oooOO + 2 ) : return ( None )
  if 6 - 6: IiII
  if 73 - 73: o0oOOo0O0Ooo % o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i - Ii1I
  if 97 - 97: IiII
  if 15 - 15: O0 - I1IiiI / i1IIi . I1Ii111
  try :
   o0OOOO00O = json . loads ( packet [ 0 : O0000000oooOO ] )
  except :
   return ( None )
   if 64 - 64: ooOoO0o / i1IIi
  packet = packet [ O0000000oooOO : : ]
  if 100 - 100: II111iiii
  if 16 - 16: Ii1I
  if 96 - 96: o0oOOo0O0Ooo / I1Ii111 % Ii1I - ooOoO0o
  if 35 - 35: OOooOOo
  o00OooooOOOO = "H"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  oO0oO00 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] ) [ 0 ]
  packet = packet [ oO0o00O : : ]
  if ( oO0oO00 != 0 ) : return ( packet )
  if 90 - 90: i11iIiiIii
  if 47 - 47: OoO0O00 . i11iIiiIii
  if 9 - 9: OoOoOO00 - I11i . OoooooooOO % ooOoO0o
  if 13 - 13: OoO0O00 * iIii1I11I1II1 + II111iiii - Oo0Ooo - OoOoOO00
  if ( o0OOOO00O . has_key ( "source-eid" ) == False ) : return ( packet )
  I111o0oooO00o0 = o0OOOO00O [ "source-eid" ]
  oO0oO00 = LISP_AFI_IPV4 if I111o0oooO00o0 . count ( "." ) == 3 else LISP_AFI_IPV6 if I111o0oooO00o0 . count ( ":" ) == 7 else None
  if 3 - 3: i11iIiiIii / I11i + i1IIi - I11i
  if ( oO0oO00 == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( I111o0oooO00o0 ) )
   return ( None )
   if 50 - 50: i1IIi
   if 56 - 56: OoO0O00 + I1Ii111 / Ii1I
  self . source_eid . afi = oO0oO00
  self . source_eid . store_address ( I111o0oooO00o0 )
  if 75 - 75: OoOoOO00
  if ( o0OOOO00O . has_key ( "signature-eid" ) == False ) : return ( packet )
  I111o0oooO00o0 = o0OOOO00O [ "signature-eid" ]
  if ( I111o0oooO00o0 . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( I111o0oooO00o0 ) )
   return ( None )
   if 96 - 96: o0oOOo0O0Ooo * I11i * Oo0Ooo
   if 36 - 36: OoooooooOO + ooOoO0o . oO0o * ooOoO0o + IiII
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( I111o0oooO00o0 )
  if 45 - 45: oO0o / iII111i + I1ii11iIi11i - Oo0Ooo - ooOoO0o . iIii1I11I1II1
  if ( o0OOOO00O . has_key ( "signature" ) == False ) : return ( packet )
  oOOo0OoooOo = binascii . a2b_base64 ( o0OOOO00O [ "signature" ] )
  self . map_request_signature = oOOo0OoooOo
  return ( packet )
  if 52 - 52: I1IiiI + i1IIi . iII111i * I1IiiI
  if 31 - 31: Oo0Ooo % iIii1I11I1II1 . O0
 def decode ( self , packet , source , port ) :
  o00OooooOOOO = "I"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 80 - 80: I11i / Oo0Ooo + I1ii11iIi11i
  i1IiIiiiii11 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  i1IiIiiiii11 = i1IiIiiiii11 [ 0 ]
  packet = packet [ oO0o00O : : ]
  if 18 - 18: II111iiii - iII111i / iIii1I11I1II1 % OoOoOO00 % I1ii11iIi11i / o0oOOo0O0Ooo
  o00OooooOOOO = "Q"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 47 - 47: OOooOOo
  OO00OO = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  packet = packet [ oO0o00O : : ]
  if 24 - 24: Ii1I % o0oOOo0O0Ooo
  i1IiIiiiii11 = socket . ntohl ( i1IiIiiiii11 )
  self . auth_bit = True if ( i1IiIiiiii11 & 0x08000000 ) else False
  self . map_data_present = True if ( i1IiIiiiii11 & 0x04000000 ) else False
  self . rloc_probe = True if ( i1IiIiiiii11 & 0x02000000 ) else False
  self . smr_bit = True if ( i1IiIiiiii11 & 0x01000000 ) else False
  self . pitr_bit = True if ( i1IiIiiiii11 & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( i1IiIiiiii11 & 0x00400000 ) else False
  self . mobile_node = True if ( i1IiIiiiii11 & 0x00200000 ) else False
  self . xtr_id_present = True if ( i1IiIiiiii11 & 0x00100000 ) else False
  self . local_xtr = True if ( i1IiIiiiii11 & 0x00004000 ) else False
  self . dont_reply_bit = True if ( i1IiIiiiii11 & 0x00002000 ) else False
  self . itr_rloc_count = ( ( i1IiIiiiii11 >> 8 ) & 0x1f ) + 1
  self . record_count = i1IiIiiiii11 & 0xff
  self . nonce = OO00OO [ 0 ]
  if 87 - 87: o0oOOo0O0Ooo % iII111i / ooOoO0o - IiII + i11iIiiIii
  if 85 - 85: OoooooooOO * IiII . OOooOOo / iII111i / OoooooooOO
  if 87 - 87: OoO0O00
  if 32 - 32: i11iIiiIii - OoOoOO00 * I11i . Oo0Ooo * ooOoO0o
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 21 - 21: OOooOOo
   if 11 - 11: oO0o % i11iIiiIii * O0
  oO0o00O = struct . calcsize ( "H" )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 28 - 28: I1Ii111 / iIii1I11I1II1 + OOooOOo . I1ii11iIi11i % OOooOOo + OoO0O00
  oO0oO00 = struct . unpack ( "H" , packet [ : oO0o00O ] )
  self . source_eid . afi = socket . ntohs ( oO0oO00 [ 0 ] )
  packet = packet [ oO0o00O : : ]
  if 79 - 79: oO0o
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   I11I1iIiI1I = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( I11I1iIiI1I )
    if ( packet == None ) : return ( None )
    if 83 - 83: i11iIiiIii + iIii1I11I1II1
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 21 - 21: o0oOOo0O0Ooo / i11iIiiIii % I1Ii111
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 56 - 56: o0oOOo0O0Ooo * iIii1I11I1II1 . Ii1I + OoOoOO00 % I1Ii111
  iiI1i111I1 = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  while ( self . itr_rloc_count != 0 ) :
   oO0o00O = struct . calcsize ( "H" )
   if ( len ( packet ) < oO0o00O ) : return ( None )
   if 26 - 26: OoooooooOO . i1IIi + OoO0O00
   oO0oO00 = struct . unpack ( "H" , packet [ : oO0o00O ] ) [ 0 ]
   if 42 - 42: i11iIiiIii * o0oOOo0O0Ooo % I11i % Oo0Ooo + o0oOOo0O0Ooo * i11iIiiIii
   oo0O0oO0o = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   oo0O0oO0o . afi = socket . ntohs ( oO0oO00 )
   if 66 - 66: Ii1I / IiII . OoooooooOO * Oo0Ooo % i11iIiiIii
   if 100 - 100: I1ii11iIi11i % II111iiii * i11iIiiIii - iII111i
   if 69 - 69: OOooOOo + iII111i / I1Ii111
   if 37 - 37: iIii1I11I1II1 * I11i / IiII * Oo0Ooo % i11iIiiIii
   if 93 - 93: ooOoO0o + ooOoO0o
   if ( oo0O0oO0o . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < oo0O0oO0o . addr_length ( ) ) : return ( None )
    packet = oo0O0oO0o . unpack_address ( packet [ oO0o00O : : ] )
    if ( packet == None ) : return ( None )
    if 65 - 65: OoooooooOO * I11i * oO0o % I1ii11iIi11i * II111iiii
    if ( iiI1i111I1 ) :
     self . itr_rlocs . append ( oo0O0oO0o )
     self . itr_rloc_count -= 1
     continue
     if 86 - 86: i11iIiiIii / I11i * iII111i - iII111i
     if 32 - 32: Oo0Ooo . O0
    oOo0O = lisp_build_crypto_decap_lookup_key ( oo0O0oO0o , port )
    if 48 - 48: I1ii11iIi11i % II111iiii + I11i
    if 25 - 25: IiII * o0oOOo0O0Ooo / I1IiiI . IiII % II111iiii
    if 50 - 50: OoOoOO00 * iII111i
    if 59 - 59: I1IiiI * I1IiiI / I11i
    if 92 - 92: o0oOOo0O0Ooo
    if ( lisp_nat_traversal and oo0O0oO0o . is_private_address ( ) and source ) : oo0O0oO0o = source
    if 8 - 8: iII111i + I1ii11iIi11i . Ii1I
    ii1I11ii1I11 = lisp_crypto_keys_by_rloc_decap
    if ( ii1I11ii1I11 . has_key ( oOo0O ) ) : ii1I11ii1I11 . pop ( oOo0O )
    if 78 - 78: iIii1I11I1II1 + OoO0O00 + i11iIiiIii
    if 21 - 21: Oo0Ooo + Ii1I % ooOoO0o + OoOoOO00 % I11i
    if 22 - 22: i1IIi / OoooooooOO . OoO0O00
    if 83 - 83: I1IiiI - OoooooooOO + I1ii11iIi11i . Ii1I / o0oOOo0O0Ooo + ooOoO0o
    if 90 - 90: I1IiiI - i11iIiiIii
    if 42 - 42: OOooOOo . Oo0Ooo
    lisp_write_ipc_decap_key ( oOo0O , None )
   else :
    IiIIIii1iIII1 = packet
    i1i1IIiIiI11 = lisp_keys ( 1 )
    packet = i1i1IIiIiI11 . decode_lcaf ( IiIIIii1iIII1 , 0 )
    if ( packet == None ) : return ( None )
    if 61 - 61: i11iIiiIii % I1Ii111 / o0oOOo0O0Ooo
    if 40 - 40: OOooOOo / Ii1I % I1IiiI / o0oOOo0O0Ooo . iII111i
    if 78 - 78: I11i - I1IiiI * IiII
    if 43 - 43: OoooooooOO . OOooOOo
    IIiIiIii11I1 = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( i1i1IIiIiI11 . cipher_suite in IIiIiIii11I1 ) :
     if ( i1i1IIiIiI11 . cipher_suite == LISP_CS_25519_CBC or
 i1i1IIiIiI11 . cipher_suite == LISP_CS_25519_GCM ) :
      iII1 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 33 - 33: o0oOOo0O0Ooo % OoOoOO00 * I1IiiI
     if ( i1i1IIiIiI11 . cipher_suite == LISP_CS_25519_CHACHA ) :
      iII1 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 26 - 26: I11i . iII111i . o0oOOo0O0Ooo
    else :
     iII1 = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 15 - 15: OoO0O00 / iII111i
    packet = iII1 . decode_lcaf ( IiIIIii1iIII1 , 0 )
    if ( packet == None ) : return ( None )
    if 46 - 46: OoooooooOO . I1Ii111
    if ( len ( packet ) < oO0o00O ) : return ( None )
    oO0oO00 = struct . unpack ( "H" , packet [ : oO0o00O ] ) [ 0 ]
    oo0O0oO0o . afi = socket . ntohs ( oO0oO00 )
    if ( len ( packet ) < oo0O0oO0o . addr_length ( ) ) : return ( None )
    if 15 - 15: Ii1I
    packet = oo0O0oO0o . unpack_address ( packet [ oO0o00O : : ] )
    if ( packet == None ) : return ( None )
    if 84 - 84: OoOoOO00 - ooOoO0o - OoooooooOO . OoooooooOO % IiII
    if ( iiI1i111I1 ) :
     self . itr_rlocs . append ( oo0O0oO0o )
     self . itr_rloc_count -= 1
     continue
     if 38 - 38: OoO0O00 * I1ii11iIi11i
     if 4 - 4: OoO0O00 . I1ii11iIi11i
    oOo0O = lisp_build_crypto_decap_lookup_key ( oo0O0oO0o , port )
    if 21 - 21: i11iIiiIii / OoO0O00 / I1ii11iIi11i * O0 - II111iiii * OOooOOo
    II = None
    if ( lisp_nat_traversal and oo0O0oO0o . is_private_address ( ) and source ) : oo0O0oO0o = source
    if 87 - 87: Ii1I * iII111i * O0
    if 93 - 93: IiII % I1Ii111 % II111iiii
    if ( lisp_crypto_keys_by_rloc_decap . has_key ( oOo0O ) ) :
     O0000 = lisp_crypto_keys_by_rloc_decap [ oOo0O ]
     II = O0000 [ 1 ] if O0000 and O0000 [ 1 ] else None
     if 20 - 20: OoooooooOO * I1Ii111
     if 38 - 38: iII111i . OoooooooOO
    i1iiI11ii1II1 = True
    if ( II ) :
     if ( II . compare_keys ( iII1 ) ) :
      self . keys = [ None , II , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( oOo0O , False ) ) )
      if 33 - 33: oO0o / I11i . OoOoOO00 * O0 - IiII
     else :
      i1iiI11ii1II1 = False
      ii1IIi = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( ii1IIi , red ( oOo0O ,
 False ) ) )
      iII1 . copy_keypair ( II )
      iII1 . uptime = II . uptime
      II = None
      if 44 - 44: I1IiiI + IiII / I1ii11iIi11i
      if 31 - 31: II111iiii - I1ii11iIi11i % I11i . o0oOOo0O0Ooo - i11iIiiIii / I11i
      if 100 - 100: i11iIiiIii * i11iIiiIii . iIii1I11I1II1 % iII111i * I1ii11iIi11i
    if ( II == None ) :
     self . keys = [ None , iII1 , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      iII1 . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( oOo0O , False ) ) )
     elif ( iII1 . remote_public_key != None ) :
      if ( i1iiI11ii1II1 ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # Ii1I
 red ( oOo0O , False ) ) )
       if 91 - 91: IiII * i11iIiiIii / I1ii11iIi11i / i1IIi . IiII
      iII1 . compute_shared_key ( "decap" )
      iII1 . add_key_by_rloc ( oOo0O , False )
      if 35 - 35: i11iIiiIii / OoooooooOO
      if 36 - 36: iII111i
      if 91 - 91: ooOoO0o + IiII . I1IiiI / I11i / IiII
      if 23 - 23: I1ii11iIi11i - OOooOOo - i1IIi
   self . itr_rlocs . append ( oo0O0oO0o )
   self . itr_rloc_count -= 1
   if 20 - 20: OoooooooOO / Oo0Ooo * OoO0O00 . o0oOOo0O0Ooo . I1IiiI
   if 75 - 75: iIii1I11I1II1 - Ii1I % O0 % IiII
  oO0o00O = struct . calcsize ( "BBH" )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 6 - 6: Oo0Ooo % oO0o * ooOoO0o - i1IIi . OoOoOO00
  O00 , Ooo0o00 , oO0oO00 = struct . unpack ( "BBH" , packet [ : oO0o00O ] )
  self . subscribe_bit = ( O00 & 0x80 )
  self . target_eid . afi = socket . ntohs ( oO0oO00 )
  packet = packet [ oO0o00O : : ]
  if 20 - 20: Oo0Ooo / I1Ii111 . Oo0Ooo
  self . target_eid . mask_len = Ooo0o00
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , OO0O0ooOo = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( OO0O0ooOo ) : self . target_group = OO0O0ooOo
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ oO0o00O : : ]
   if 23 - 23: OoO0O00 / IiII * II111iiii
  return ( packet )
  if 32 - 32: I1Ii111 - iIii1I11I1II1 / I11i * OoO0O00 * OoO0O00
  if 77 - 77: I1ii11iIi11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 16 - 16: II111iiii - II111iiii * I11i / OOooOOo . IiII
  if 36 - 36: I11i / iIii1I11I1II1
 def encode_xtr_id ( self , packet ) :
  oO0ooOoOooO00o00 = self . xtr_id >> 64
  o0Ooo00Oo0oo0 = self . xtr_id & 0xffffffffffffffff
  oO0ooOoOooO00o00 = byte_swap_64 ( oO0ooOoOooO00o00 )
  o0Ooo00Oo0oo0 = byte_swap_64 ( o0Ooo00Oo0oo0 )
  packet += struct . pack ( "QQ" , oO0ooOoOooO00o00 , o0Ooo00Oo0oo0 )
  return ( packet )
  if 59 - 59: i1IIi
  if 85 - 85: I1Ii111 + iIii1I11I1II1 + ooOoO0o + Oo0Ooo
 def decode_xtr_id ( self , packet ) :
  oO0o00O = struct . calcsize ( "QQ" )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  packet = packet [ len ( packet ) - oO0o00O : : ]
  oO0ooOoOooO00o00 , o0Ooo00Oo0oo0 = struct . unpack ( "QQ" , packet [ : oO0o00O ] )
  oO0ooOoOooO00o00 = byte_swap_64 ( oO0ooOoOooO00o00 )
  o0Ooo00Oo0oo0 = byte_swap_64 ( o0Ooo00Oo0oo0 )
  self . xtr_id = ( oO0ooOoOooO00o00 << 64 ) | o0Ooo00Oo0oo0
  return ( True )
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
  if 88 - 88: i1IIi + iIii1I11I1II1 * i11iIiiIii - OoooooooOO % o0oOOo0O0Ooo
  if 74 - 74: ooOoO0o - i11iIiiIii
  if 34 - 34: IiII + I1Ii111 + Oo0Ooo / II111iiii
  if 33 - 33: Ii1I . i1IIi - II111iiii - OoO0O00
  if 31 - 31: I11i - OoOoOO00 / o0oOOo0O0Ooo * OoOoOO00 / Oo0Ooo + o0oOOo0O0Ooo
  if 46 - 46: IiII * OoO0O00 / OOooOOo + Oo0Ooo
  if 24 - 24: ooOoO0o % OOooOOo . O0 * Oo0Ooo
class lisp_map_reply ( ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 52 - 52: O0 . I1Ii111 + iII111i / i11iIiiIii
  if 52 - 52: oO0o % Oo0Ooo * II111iiii
 def print_map_reply ( self ) :
  I111 = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 24 - 24: i11iIiiIii * i1IIi * i1IIi
  lprint ( I111 . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # o0oOOo0O0Ooo + i1IIi
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 40 - 40: i11iIiiIii - I11i + iIii1I11I1II1 * I1Ii111
  if 19 - 19: IiII + I1Ii111
 def encode ( self ) :
  i1IiIiiiii11 = ( LISP_MAP_REPLY << 28 ) | self . record_count
  i1IiIiiiii11 |= self . hop_count << 8
  if ( self . rloc_probe ) : i1IiIiiiii11 |= 0x08000000
  if ( self . echo_nonce_capable ) : i1IiIiiiii11 |= 0x04000000
  if ( self . security ) : i1IiIiiiii11 |= 0x02000000
  if 65 - 65: Ii1I - oO0o + i1IIi + OOooOOo % iII111i
  ii1i1II = struct . pack ( "I" , socket . htonl ( i1IiIiiiii11 ) )
  ii1i1II += struct . pack ( "Q" , self . nonce )
  return ( ii1i1II )
  if 5 - 5: OoO0O00 / iII111i / OOooOOo
  if 70 - 70: OoOoOO00 - I11i + ooOoO0o / i11iIiiIii / I1IiiI % iIii1I11I1II1
 def decode ( self , packet ) :
  o00OooooOOOO = "I"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 83 - 83: oO0o . Ii1I - o0oOOo0O0Ooo % I11i + i11iIiiIii
  i1IiIiiiii11 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  i1IiIiiiii11 = i1IiIiiiii11 [ 0 ]
  packet = packet [ oO0o00O : : ]
  if 40 - 40: O0 . Ii1I
  o00OooooOOOO = "Q"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 58 - 58: i11iIiiIii * iII111i / Ii1I - oO0o - I1ii11iIi11i % o0oOOo0O0Ooo
  OO00OO = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  packet = packet [ oO0o00O : : ]
  if 16 - 16: OoooooooOO
  i1IiIiiiii11 = socket . ntohl ( i1IiIiiiii11 )
  self . rloc_probe = True if ( i1IiIiiiii11 & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( i1IiIiiiii11 & 0x04000000 ) else False
  self . security = True if ( i1IiIiiiii11 & 0x02000000 ) else False
  self . hop_count = ( i1IiIiiiii11 >> 8 ) & 0xff
  self . record_count = i1IiIiiiii11 & 0xff
  self . nonce = OO00OO [ 0 ]
  if 71 - 71: Ii1I % O0 / I1Ii111 % iII111i - II111iiii / OoO0O00
  if ( lisp_crypto_keys_by_nonce . has_key ( self . nonce ) ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 30 - 30: I11i
  return ( packet )
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
  if 22 - 22: i1IIi
  if 82 - 82: oO0o . iIii1I11I1II1 - I1ii11iIi11i
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 55 - 55: Oo0Ooo % Ii1I . iIii1I11I1II1 * I1Ii111
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 33 - 33: O0 - I1IiiI / I1ii11iIi11i / OoO0O00 + iII111i - oO0o
  if 27 - 27: I1Ii111 + ooOoO0o - I1Ii111 % i11iIiiIii * Oo0Ooo * o0oOOo0O0Ooo
 def print_ttl ( self ) :
  oo0OOoOO0 = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   oo0OOoOO0 = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( oo0OOoOO0 % 60 ) == 0 ) :
   oo0OOoOO0 = str ( oo0OOoOO0 / 60 ) + " hours"
  else :
   oo0OOoOO0 = str ( oo0OOoOO0 ) + " mins"
   if 16 - 16: oO0o * iII111i % i1IIi . OoOoOO00 * iIii1I11I1II1
  return ( oo0OOoOO0 )
  if 17 - 17: OoooooooOO . OOooOOo
  if 32 - 32: OoOoOO00 . oO0o + O0
 def store_ttl ( self ) :
  oo0OOoOO0 = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : oo0OOoOO0 = self . record_ttl & 0x7fffffff
  return ( oo0OOoOO0 )
  if 100 - 100: O0 / OOooOOo - ooOoO0o
  if 15 - 15: iII111i - O0 - OoooooooOO
 def print_record ( self , indent , ddt ) :
  iiiiIIiiII1Iii1 = ""
  OOo0O0O000 = ""
  o0oOOoO0o0 = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    o0oOOoO0o0 = lisp_map_referral_action_string [ self . action ]
    o0oOOoO0o0 = bold ( o0oOOoO0o0 , False )
    iiiiIIiiII1Iii1 = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 56 - 56: I1IiiI . I11i % iII111i
    OOo0O0O000 = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 33 - 33: I11i / OOooOOo - OOooOOo / i11iIiiIii * OoOoOO00 + O0
    if 2 - 2: i11iIiiIii % I1IiiI
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    o0oOOoO0o0 = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     o0oOOoO0o0 = bold ( o0oOOoO0o0 , False )
     if 90 - 90: II111iiii
     if 2 - 2: Ii1I - OoooooooOO - i11iIiiIii % Oo0Ooo / Ii1I
     if 77 - 77: o0oOOo0O0Ooo . o0oOOo0O0Ooo * I1Ii111 + OOooOOo - i11iIiiIii
     if 45 - 45: I1IiiI . I1IiiI - Oo0Ooo * OOooOOo
  oO0oO00 = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  I111 = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 71 - 71: i1IIi / I11i
  lprint ( I111 . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 o0oOOoO0o0 , "auth" if ( self . authoritative is True ) else "non-auth" ,
 iiiiIIiiII1Iii1 , OOo0O0O000 , self . map_version , oO0oO00 ,
 green ( self . print_prefix ( ) , False ) ) )
  if 14 - 14: OoooooooOO
  if 99 - 99: o0oOOo0O0Ooo * o0oOOo0O0Ooo
 def encode ( self ) :
  Ii1II1I = self . action << 13
  if ( self . authoritative ) : Ii1II1I |= 0x1000
  if ( self . ddt_incomplete ) : Ii1II1I |= 0x800
  if 5 - 5: OOooOOo . iII111i . oO0o % IiII * O0
  if 20 - 20: Oo0Ooo . I1IiiI . I1IiiI / OoooooooOO . OoooooooOO + iIii1I11I1II1
  if 60 - 60: OoOoOO00 / ooOoO0o % iIii1I11I1II1
  if 32 - 32: i11iIiiIii + II111iiii + II111iiii % I11i
  oO0oO00 = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( oO0oO00 < 0 ) : oO0oO00 = LISP_AFI_LCAF
  o0000o0o = ( self . group . is_null ( ) == False )
  if ( o0000o0o ) : oO0oO00 = LISP_AFI_LCAF
  if 75 - 75: I11i - OoO0O00 - iII111i % iIii1I11I1II1 * OoO0O00
  I1I1iI1i = ( self . signature_count << 12 ) | self . map_version
  Ooo0o00 = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 13 - 13: OoO0O00 - Oo0Ooo / OoO0O00
  ii1i1II = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , Ooo0o00 , socket . htons ( Ii1II1I ) ,
 socket . htons ( I1I1iI1i ) , socket . htons ( oO0oO00 ) )
  if 34 - 34: i11iIiiIii + OoO0O00 + i11iIiiIii . IiII % O0
  if 64 - 64: o0oOOo0O0Ooo . iIii1I11I1II1
  if 86 - 86: ooOoO0o - I11i . iIii1I11I1II1 - iIii1I11I1II1
  if 61 - 61: Ii1I % Oo0Ooo + OoOoOO00
  if ( o0000o0o ) :
   ii1i1II += self . eid . lcaf_encode_sg ( self . group )
   return ( ii1i1II )
   if 60 - 60: oO0o . OoooooooOO
   if 40 - 40: I11i
   if 44 - 44: ooOoO0o
   if 35 - 35: II111iiii + iII111i / I1ii11iIi11i * I1IiiI . I11i
   if 97 - 97: I1IiiI / o0oOOo0O0Ooo
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   ii1i1II = ii1i1II [ 0 : - 2 ]
   ii1i1II += self . eid . address . encode_geo ( )
   return ( ii1i1II )
   if 13 - 13: I1ii11iIi11i
   if 72 - 72: Oo0Ooo + IiII / Ii1I * Oo0Ooo
   if 41 - 41: OOooOOo - OoOoOO00 . I1IiiI + i11iIiiIii + OoO0O00 * iII111i
   if 85 - 85: OoO0O00 + II111iiii
   if 87 - 87: OoO0O00
  if ( oO0oO00 == LISP_AFI_LCAF ) :
   ii1i1II += self . eid . lcaf_encode_iid ( )
   return ( ii1i1II )
   if 93 - 93: OoooooooOO
   if 80 - 80: o0oOOo0O0Ooo
   if 3 - 3: i11iIiiIii / OOooOOo + oO0o
   if 10 - 10: OoO0O00 . OoO0O00 + O0
   if 13 - 13: i1IIi . I1IiiI
  ii1i1II += self . eid . pack_address ( )
  return ( ii1i1II )
  if 45 - 45: ooOoO0o % I11i
  if 37 - 37: iII111i
 def decode ( self , packet ) :
  o00OooooOOOO = "IBBHHH"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 70 - 70: O0 + iIii1I11I1II1 % O0 * o0oOOo0O0Ooo - Oo0Ooo - ooOoO0o
  self . record_ttl , self . rloc_count , self . eid . mask_len , Ii1II1I , self . map_version , self . eid . afi = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  if 94 - 94: i1IIi + IiII / OoooooooOO - oO0o / OOooOOo / OoOoOO00
  if 55 - 55: OOooOOo
  if 5 - 5: I11i / OoOoOO00
  self . record_ttl = socket . ntohl ( self . record_ttl )
  Ii1II1I = socket . ntohs ( Ii1II1I )
  self . action = ( Ii1II1I >> 13 ) & 0x7
  self . authoritative = True if ( ( Ii1II1I >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( Ii1II1I >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ oO0o00O : : ]
  if 48 - 48: i1IIi - oO0o . OoooooooOO - OoO0O00 - i1IIi
  if 19 - 19: oO0o % Ii1I + I1ii11iIi11i . II111iiii * i11iIiiIii
  if 87 - 87: Ii1I / I1Ii111 % OoOoOO00 * I1ii11iIi11i - OoooooooOO / OoOoOO00
  if 24 - 24: I11i . OOooOOo * i1IIi . I1ii11iIi11i / ooOoO0o / O0
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , oOoooOOO0o0 = self . eid . lcaf_decode_eid ( packet )
   if ( oOoooOOO0o0 ) : self . group = oOoooOOO0o0
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 34 - 34: iII111i . OOooOOo
   if 13 - 13: OoO0O00 * OOooOOo + oO0o
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 21 - 21: i11iIiiIii . Ii1I % i1IIi * Ii1I . oO0o + Ii1I
  if 92 - 92: i1IIi + OoO0O00 * I11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
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
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 27 - 27: II111iiii + i11iIiiIii
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
  if 32 - 32: i1IIi
  if 76 - 76: II111iiii % ooOoO0o - I1ii11iIi11i
 def print_ecm ( self ) :
  I111 = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 50 - 50: II111iiii / I1IiiI . Ii1I % i11iIiiIii
  lprint ( I111 . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 66 - 66: oO0o / OOooOOo / iII111i
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 5 - 5: I1Ii111 . oO0o
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 77 - 77: iII111i / i11iIiiIii
   if 20 - 20: O0 . I11i
   if 67 - 67: OoOoOO00 - ooOoO0o - iIii1I11I1II1
   if 31 - 31: II111iiii + o0oOOo0O0Ooo * i11iIiiIii . o0oOOo0O0Ooo
   if 73 - 73: oO0o / OOooOOo * II111iiii % OoooooooOO - i1IIi - ooOoO0o
   if 43 - 43: o0oOOo0O0Ooo + Ii1I % OoO0O00 . I1Ii111 + i1IIi
  i1IiIiiiii11 = ( LISP_ECM << 28 )
  if ( self . security ) : i1IiIiiiii11 |= 0x08000000
  if ( self . ddt ) : i1IiIiiiii11 |= 0x04000000
  if ( self . to_etr ) : i1IiIiiiii11 |= 0x02000000
  if ( self . to_ms ) : i1IiIiiiii11 |= 0x01000000
  if 85 - 85: Oo0Ooo % I1ii11iIi11i / OOooOOo
  O0O00O = struct . pack ( "I" , socket . htonl ( i1IiIiiiii11 ) )
  if 51 - 51: Oo0Ooo . Oo0Ooo
  iIiiIIi = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   iIiiIIi = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   iIiiIIi += self . source . pack_address ( )
   iIiiIIi += self . dest . pack_address ( )
   iIiiIIi = lisp_ip_checksum ( iIiiIIi )
   if 34 - 34: I1ii11iIi11i - i11iIiiIii
  if ( self . afi == LISP_AFI_IPV6 ) :
   iIiiIIi = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   iIiiIIi += self . source . pack_address ( )
   iIiiIIi += self . dest . pack_address ( )
   if 43 - 43: iIii1I11I1II1
   if 73 - 73: OoOoOO00 + o0oOOo0O0Ooo
  o0 = socket . htons ( self . udp_sport )
  Ii = socket . htons ( self . udp_dport )
  o0000oO = socket . htons ( self . udp_length )
  ii1i1 = socket . htons ( self . udp_checksum )
  O0OO0ooO00 = struct . pack ( "HHHH" , o0 , Ii , o0000oO , ii1i1 )
  return ( O0O00O + iIiiIIi + O0OO0ooO00 )
  if 58 - 58: i1IIi * I1ii11iIi11i % iII111i . OoO0O00 % IiII % I11i
  if 63 - 63: I1ii11iIi11i % ooOoO0o % I1ii11iIi11i
 def decode ( self , packet ) :
  if 71 - 71: Ii1I
  if 43 - 43: o0oOOo0O0Ooo / ooOoO0o
  if 88 - 88: i11iIiiIii - i1IIi + Oo0Ooo - O0
  if 50 - 50: I1ii11iIi11i
  o00OooooOOOO = "I"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 37 - 37: oO0o % iII111i / II111iiii / OoO0O00 - IiII - ooOoO0o
  i1IiIiiiii11 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  if 69 - 69: I1ii11iIi11i . OoooooooOO % I1Ii111
  i1IiIiiiii11 = socket . ntohl ( i1IiIiiiii11 [ 0 ] )
  self . security = True if ( i1IiIiiiii11 & 0x08000000 ) else False
  self . ddt = True if ( i1IiIiiiii11 & 0x04000000 ) else False
  self . to_etr = True if ( i1IiIiiiii11 & 0x02000000 ) else False
  self . to_ms = True if ( i1IiIiiiii11 & 0x01000000 ) else False
  packet = packet [ oO0o00O : : ]
  if 79 - 79: I1IiiI - IiII . OoooooooOO - I1ii11iIi11i
  if 79 - 79: OOooOOo + o0oOOo0O0Ooo % iII111i . oO0o
  if 49 - 49: Ii1I + i11iIiiIii * OoOoOO00 . OoOoOO00 . I1ii11iIi11i . Oo0Ooo
  if 61 - 61: I11i / OOooOOo
  if ( len ( packet ) < 1 ) : return ( None )
  Oo0o0OoOoOo0 = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  Oo0o0OoOoOo0 = Oo0o0OoOoOo0 >> 4
  if 85 - 85: OoOoOO00 - I11i . OoOoOO00 . OoOoOO00
  if ( Oo0o0OoOoOo0 == 4 ) :
   oO0o00O = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < oO0o00O ) : return ( None )
   if 62 - 62: IiII % OoooooooOO * OoO0O00 + OoO0O00 % Ii1I % iII111i
   OoOO0OOOO0 , o0000oO , OoOO0OOOO0 , OooOOo0ooO , iIiiI11II11 , ii1i1 = struct . unpack ( "HHIBBH" , packet [ : oO0o00O ] )
   self . length = socket . ntohs ( o0000oO )
   self . ttl = OooOOo0ooO
   self . protocol = iIiiI11II11
   self . ip_checksum = socket . ntohs ( ii1i1 )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 6 - 6: OoooooooOO . oO0o / i11iIiiIii / ooOoO0o + oO0o . Oo0Ooo
   if 94 - 94: i11iIiiIii . IiII - OoO0O00 + O0
   if 89 - 89: iII111i * oO0o
   if 36 - 36: ooOoO0o / II111iiii - ooOoO0o * iII111i
   iIiiI11II11 = struct . pack ( "H" , 0 )
   I1iiiiiII1I1I = struct . calcsize ( "HHIBB" )
   o0OoO00ooOoO = struct . calcsize ( "H" )
   packet = packet [ : I1iiiiiII1I1I ] + iIiiI11II11 + packet [ I1iiiiiII1I1I + o0OoO00ooOoO : ]
   if 93 - 93: ooOoO0o - OoooooooOO / IiII . I11i
   packet = packet [ oO0o00O : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 7 - 7: o0oOOo0O0Ooo % Ii1I - i11iIiiIii
   if 47 - 47: Oo0Ooo / OoOoOO00
  if ( Oo0o0OoOoOo0 == 6 ) :
   oO0o00O = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < oO0o00O ) : return ( None )
   if 26 - 26: I11i . I1ii11iIi11i
   OoOO0OOOO0 , o0000oO , iIiiI11II11 , OooOOo0ooO = struct . unpack ( "IHBB" , packet [ : oO0o00O ] )
   self . length = socket . ntohs ( o0000oO )
   self . protocol = iIiiI11II11
   self . ttl = OooOOo0ooO
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 55 - 55: OoOoOO00 * I1Ii111 % OoO0O00 - OoO0O00
   packet = packet [ oO0o00O : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 34 - 34: O0 * OoO0O00 - oO0o - IiII * Ii1I . II111iiii
   if 28 - 28: O0 % iII111i - i1IIi
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 49 - 49: ooOoO0o . I11i - iIii1I11I1II1
  oO0o00O = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 41 - 41: ooOoO0o * i11iIiiIii % ooOoO0o . oO0o
  o0 , Ii , o0000oO , ii1i1 = struct . unpack ( "HHHH" , packet [ : oO0o00O ] )
  self . udp_sport = socket . ntohs ( o0 )
  self . udp_dport = socket . ntohs ( Ii )
  self . udp_length = socket . ntohs ( o0000oO )
  self . udp_checksum = socket . ntohs ( ii1i1 )
  packet = packet [ oO0o00O : : ]
  return ( packet )
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
  if 86 - 86: I1IiiI % I11i * O0 + i1IIi % I1Ii111
  if 97 - 97: II111iiii * OoOoOO00 - I1Ii111 / i11iIiiIii / OoOoOO00
  if 25 - 25: Oo0Ooo / Oo0Ooo
  if 74 - 74: OOooOOo
  if 30 - 30: O0 . Ii1I / o0oOOo0O0Ooo + I1IiiI - O0
  if 88 - 88: i11iIiiIii
  if 33 - 33: OoO0O00 + O0
  if 20 - 20: o0oOOo0O0Ooo % I11i . ooOoO0o - i1IIi . O0
  if 10 - 10: i1IIi
  if 49 - 49: I1Ii111 - Ii1I . O0
  if 46 - 46: OOooOOo
  if 64 - 64: I1IiiI / OoOoOO00
  if 6 - 6: i11iIiiIii - iII111i * i1IIi - iII111i
  if 8 - 8: I11i / i11iIiiIii . O0 / OoO0O00 * oO0o + I1Ii111
  if 91 - 91: I1IiiI
  if 84 - 84: O0 % Ii1I
  if 3 - 3: I1IiiI . I11i / I1ii11iIi11i
  if 2 - 2: IiII + I11i / iIii1I11I1II1 . i11iIiiIii . i1IIi * ooOoO0o
  if 14 - 14: Oo0Ooo . O0 - oO0o - i11iIiiIii
  if 8 - 8: I1IiiI / iIii1I11I1II1 / OoooooooOO / Oo0Ooo / ooOoO0o
  if 80 - 80: I11i
  if 26 - 26: II111iiii + I1IiiI . II111iiii - oO0o % OoO0O00
  if 1 - 1: OoO0O00 - II111iiii
  if 75 - 75: Oo0Ooo - OoOoOO00 + oO0o % i1IIi * OOooOOo
  if 56 - 56: OoOoOO00 / OoO0O00 / I1IiiI % OoooooooOO
  if 39 - 39: I1IiiI + II111iiii * Oo0Ooo % Ii1I . o0oOOo0O0Ooo * oO0o
  if 42 - 42: Ii1I / Oo0Ooo
  if 25 - 25: OoooooooOO % Ii1I * I1Ii111 * I11i + I1IiiI % I1ii11iIi11i
  if 70 - 70: Ii1I + I1ii11iIi11i * I11i * i1IIi . I1Ii111
  if 76 - 76: OoooooooOO * OoOoOO00 . OoooooooOO
  if 46 - 46: ooOoO0o * o0oOOo0O0Ooo % II111iiii / I1Ii111
  if 29 - 29: OoO0O00 - i11iIiiIii % Oo0Ooo % o0oOOo0O0Ooo
  if 30 - 30: oO0o - Ii1I % Ii1I
  if 8 - 8: IiII
  if 68 - 68: IiII . OoooooooOO - i11iIiiIii + i11iIiiIii
  if 81 - 81: OoOoOO00 + iII111i . i11iIiiIii
  if 10 - 10: OoOoOO00 + I11i - iIii1I11I1II1 - I11i
  if 58 - 58: ooOoO0o
  if 98 - 98: Ii1I / OoO0O00 % OoooooooOO
  if 65 - 65: ooOoO0o % Oo0Ooo - I1IiiI % I1Ii111 + iIii1I11I1II1 / iIii1I11I1II1
  if 94 - 94: IiII - Oo0Ooo . o0oOOo0O0Ooo - ooOoO0o - oO0o . I11i
  if 39 - 39: oO0o + OoOoOO00
  if 68 - 68: i1IIi * oO0o / i11iIiiIii
  if 96 - 96: I1IiiI
  if 78 - 78: OoO0O00
  if 72 - 72: I1ii11iIi11i / O0 % II111iiii / II111iiii
  if 48 - 48: OOooOOo % OOooOOo / iIii1I11I1II1 - i11iIiiIii
  if 57 - 57: I11i / IiII * i1IIi + II111iiii . o0oOOo0O0Ooo
  if 11 - 11: II111iiii
  if 66 - 66: Ii1I - I1IiiI . OoooooooOO * I1Ii111
  if 16 - 16: IiII * OoO0O00 * i11iIiiIii - ooOoO0o
  if 88 - 88: iIii1I11I1II1 / Ii1I * IiII / I1Ii111
  if 31 - 31: O0 . I1IiiI
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
  if 59 - 59: iIii1I11I1II1 . Oo0Ooo * I11i
  if 29 - 29: Oo0Ooo - I1IiiI * I11i
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  Ooo000oo0OO0 = self . rloc_name
  if ( cour ) : Ooo000oo0OO0 = lisp_print_cour ( Ooo000oo0OO0 )
  return ( 'rloc-name: {}' . format ( blue ( Ooo000oo0OO0 , cour ) ) )
  if 54 - 54: I1IiiI
  if 29 - 29: OoO0O00 * iIii1I11I1II1 % Ii1I / oO0o / I1Ii111
 def print_record ( self , indent ) :
  ii11IiI = self . print_rloc_name ( )
  if ( ii11IiI != "" ) : ii11IiI = ", " + ii11IiI
  OOOOooO0Oo0oo = ""
  if ( self . geo ) :
   oOo0oooo = ""
   if ( self . geo . geo_name ) : oOo0oooo = "'{}' " . format ( self . geo . geo_name )
   OOOOooO0Oo0oo = ", geo: {}{}" . format ( oOo0oooo , self . geo . print_geo ( ) )
   if 48 - 48: i11iIiiIii * OoOoOO00 - I1IiiI + iIii1I11I1II1
  iIii1IiI = ""
  if ( self . elp ) :
   oOo0oooo = ""
   if ( self . elp . elp_name ) : oOo0oooo = "'{}' " . format ( self . elp . elp_name )
   iIii1IiI = ", elp: {}{}" . format ( oOo0oooo , self . elp . print_elp ( True ) )
   if 42 - 42: II111iiii . I1IiiI . i11iIiiIii . OoOoOO00 % I1Ii111 + I1ii11iIi11i
  Oo0iIIIIi = ""
  if ( self . rle ) :
   oOo0oooo = ""
   if ( self . rle . rle_name ) : oOo0oooo = "'{}' " . format ( self . rle . rle_name )
   Oo0iIIIIi = ", rle: {}{}" . format ( oOo0oooo , self . rle . print_rle ( False ) )
   if 48 - 48: iIii1I11I1II1 % i1IIi - OoO0O00 % IiII - i1IIi + o0oOOo0O0Ooo
  i111i = ""
  if ( self . json ) :
   oOo0oooo = ""
   if ( self . json . json_name ) :
    oOo0oooo = "'{}' " . format ( self . json . json_name )
    if 43 - 43: IiII + IiII
   i111i = ", json: {}" . format ( self . json . print_json ( False ) )
   if 88 - 88: OoOoOO00 % I1IiiI * I1IiiI
   if 97 - 97: iII111i + I1IiiI % oO0o % II111iiii * II111iiii + OoO0O00
  I11iIiiI = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   I11iIiiI = ", " + self . keys [ 1 ] . print_keys ( )
   if 13 - 13: o0oOOo0O0Ooo / iIii1I11I1II1 + O0 % OoO0O00
   if 13 - 13: OoOoOO00 + i1IIi - I1IiiI
  I111 = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( I111 . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , ii11IiI , OOOOooO0Oo0oo ,
 iIii1IiI , Oo0iIIIIi , i111i , I11iIiiI ) )
  if 3 - 3: II111iiii % IiII * O0
  if 58 - 58: OOooOOo * I1Ii111
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 19 - 19: OoOoOO00 / IiII - OOooOOo * i11iIiiIii % I1Ii111
  if 98 - 98: IiII + IiII + OOooOOo / i1IIi + oO0o
  if 53 - 53: OoOoOO00
 def store_rloc_entry ( self , rloc_entry ) :
  OooO0ooO0o0OO = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 73 - 73: OoooooooOO
  self . rloc . copy_address ( OooO0ooO0o0OO )
  if 64 - 64: Ii1I * OoO0O00 % O0 . Ii1I . OoooooooOO
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 83 - 83: I11i * o0oOOo0O0Ooo - Oo0Ooo / ooOoO0o / i1IIi - Ii1I
   if 43 - 43: i11iIiiIii - OoooooooOO % ooOoO0o
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   oOo0oooo = rloc_entry . geo_name
   if ( oOo0oooo and lisp_geo_list . has_key ( oOo0oooo ) ) :
    self . geo = lisp_geo_list [ oOo0oooo ]
    if 55 - 55: oO0o % Oo0Ooo % IiII
    if 65 - 65: IiII * IiII
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   oOo0oooo = rloc_entry . elp_name
   if ( oOo0oooo and lisp_elp_list . has_key ( oOo0oooo ) ) :
    self . elp = lisp_elp_list [ oOo0oooo ]
    if 60 - 60: ooOoO0o
    if 92 - 92: O0 % IiII
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   oOo0oooo = rloc_entry . rle_name
   if ( oOo0oooo and lisp_rle_list . has_key ( oOo0oooo ) ) :
    self . rle = lisp_rle_list [ oOo0oooo ]
    if 15 - 15: O0 % i1IIi - OOooOOo . IiII
    if 1 - 1: I1IiiI
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   oOo0oooo = rloc_entry . json_name
   if ( oOo0oooo and lisp_json_list . has_key ( oOo0oooo ) ) :
    self . json = lisp_json_list [ oOo0oooo ]
    if 40 - 40: o0oOOo0O0Ooo % I11i % O0
    if 88 - 88: o0oOOo0O0Ooo - oO0o
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 73 - 73: II111iiii
  if 7 - 7: O0 / OoO0O00
 def encode_lcaf ( self ) :
  I1I1iiI1iIIii = socket . htons ( LISP_AFI_LCAF )
  o0oOoOoooO = ""
  if ( self . geo ) :
   o0oOoOoooO = self . geo . encode_geo ( )
   if 20 - 20: I1Ii111 . I1IiiI - iIii1I11I1II1 / iII111i
   if 46 - 46: I1Ii111 . i11iIiiIii
  OOO0Oo0Oo = ""
  if ( self . elp ) :
   oOOoO0OO0OOoo = ""
   for Oo0ooOOOOOoO in self . elp . elp_nodes :
    oO0oO00 = socket . htons ( Oo0ooOOOOOoO . address . afi )
    OO000OOO = 0
    if ( Oo0ooOOOOOoO . eid ) : OO000OOO |= 0x4
    if ( Oo0ooOOOOOoO . probe ) : OO000OOO |= 0x2
    if ( Oo0ooOOOOOoO . strict ) : OO000OOO |= 0x1
    OO000OOO = socket . htons ( OO000OOO )
    oOOoO0OO0OOoo += struct . pack ( "HH" , OO000OOO , oO0oO00 )
    oOOoO0OO0OOoo += Oo0ooOOOOOoO . address . pack_address ( )
    if 37 - 37: OOooOOo / Ii1I
    if 51 - 51: OOooOOo + O0
   Oo0OoO = socket . htons ( len ( oOOoO0OO0OOoo ) )
   OOO0Oo0Oo = struct . pack ( "HBBBBH" , I1I1iiI1iIIii , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , Oo0OoO )
   OOO0Oo0Oo += oOOoO0OO0OOoo
   if 55 - 55: iII111i / i11iIiiIii % I1IiiI % OoooooooOO
   if 83 - 83: OoO0O00 % I1ii11iIi11i
  oOo0Ooo = ""
  if ( self . rle ) :
   Ii1III1 = ""
   for Oo0000O00o0 in self . rle . rle_nodes :
    oO0oO00 = socket . htons ( Oo0000O00o0 . address . afi )
    Ii1III1 += struct . pack ( "HBBH" , 0 , 0 , Oo0000O00o0 . level , oO0oO00 )
    Ii1III1 += Oo0000O00o0 . address . pack_address ( )
    if ( Oo0000O00o0 . rloc_name ) :
     Ii1III1 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     Ii1III1 += Oo0000O00o0 . rloc_name + "\0"
     if 51 - 51: iIii1I11I1II1
     if 74 - 74: OoooooooOO * O0 % O0 + O0
     if 83 - 83: OoooooooOO / OoOoOO00 % ooOoO0o * OOooOOo + iII111i
   o000000 = socket . htons ( len ( Ii1III1 ) )
   oOo0Ooo = struct . pack ( "HBBBBH" , I1I1iiI1iIIii , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , o000000 )
   oOo0Ooo += Ii1III1
   if 59 - 59: I11i + Ii1I + OoO0O00
   if 46 - 46: I11i - Oo0Ooo
  ooOOo0oo00O = ""
  if ( self . json ) :
   o00O0oOO0o = socket . htons ( len ( self . json . json_string ) + 2 )
   O0000000oooOO = socket . htons ( len ( self . json . json_string ) )
   ooOOo0oo00O = struct . pack ( "HBBBBHH" , I1I1iiI1iIIii , 0 , 0 , LISP_LCAF_JSON_TYPE ,
 0 , o00O0oOO0o , O0000000oooOO )
   ooOOo0oo00O += self . json . json_string
   ooOOo0oo00O += struct . pack ( "H" , 0 )
   if 79 - 79: OoooooooOO * I1ii11iIi11i * i1IIi % oO0o
   if 2 - 2: OOooOOo
  iiI1i = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   iiI1i = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 75 - 75: O0
   if 71 - 71: i11iIiiIii + OoO0O00 . I11i - iII111i % I1ii11iIi11i * IiII
  oO0O0 = ""
  if ( self . rloc_name ) :
   oO0O0 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   oO0O0 += self . rloc_name + "\0"
   if 61 - 61: I1ii11iIi11i
   if 48 - 48: II111iiii
  III11ii1 = len ( o0oOoOoooO ) + len ( OOO0Oo0Oo ) + len ( oOo0Ooo ) + len ( iiI1i ) + 2 + len ( ooOOo0oo00O ) + self . rloc . addr_length ( ) + len ( oO0O0 )
  if 10 - 10: iIii1I11I1II1 + OoO0O00 - o0oOOo0O0Ooo . o0oOOo0O0Ooo / IiII / I1Ii111
  III11ii1 = socket . htons ( III11ii1 )
  oo0 = struct . pack ( "HBBBBHH" , I1I1iiI1iIIii , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , III11ii1 , socket . htons ( self . rloc . afi ) )
  oo0 += self . rloc . pack_address ( )
  return ( oo0 + oO0O0 + o0oOoOoooO + OOO0Oo0Oo + oOo0Ooo + iiI1i + ooOOo0oo00O )
  if 69 - 69: i11iIiiIii - i11iIiiIii + I11i / I1IiiI % I1ii11iIi11i
  if 56 - 56: iIii1I11I1II1 / OoO0O00 * OOooOOo
 def encode ( self ) :
  OO000OOO = 0
  if ( self . local_bit ) : OO000OOO |= 0x0004
  if ( self . probe_bit ) : OO000OOO |= 0x0002
  if ( self . reach_bit ) : OO000OOO |= 0x0001
  if 73 - 73: OoooooooOO % IiII / I1Ii111 * I11i + i1IIi % i11iIiiIii
  ii1i1II = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( OO000OOO ) ,
 socket . htons ( self . rloc . afi ) )
  if 91 - 91: i11iIiiIii
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 6 - 6: O0 - iIii1I11I1II1 + I1Ii111 . o0oOOo0O0Ooo * i11iIiiIii
   ii1i1II = ii1i1II [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   ii1i1II += self . rloc . pack_address ( )
   if 53 - 53: OOooOOo / I1IiiI / oO0o * OOooOOo / i1IIi - I1Ii111
  return ( ii1i1II )
  if 71 - 71: O0 + Oo0Ooo % oO0o - o0oOOo0O0Ooo
  if 82 - 82: iIii1I11I1II1
 def decode_lcaf ( self , packet , nonce ) :
  o00OooooOOOO = "HBBBBH"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 64 - 64: ooOoO0o + I1IiiI % OOooOOo + II111iiii
  oO0oO00 , Ooo0o00O0O0oO , OO000OOO , iiii1II , o000OOooo000O , o00O0oOO0o = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  if 46 - 46: I1IiiI
  if 72 - 72: iII111i
  o00O0oOO0o = socket . ntohs ( o00O0oOO0o )
  packet = packet [ oO0o00O : : ]
  if ( o00O0oOO0o > len ( packet ) ) : return ( None )
  if 100 - 100: I1IiiI
  if 55 - 55: i1IIi % IiII
  if 44 - 44: oO0o - iIii1I11I1II1 / ooOoO0o - iIii1I11I1II1 % i1IIi + ooOoO0o
  if 74 - 74: I11i . OoOoOO00 + OoOoOO00
  if ( iiii1II == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( o00O0oOO0o > 0 ) :
    o00OooooOOOO = "H"
    oO0o00O = struct . calcsize ( o00OooooOOOO )
    if ( o00O0oOO0o < oO0o00O ) : return ( None )
    if 87 - 87: IiII + o0oOOo0O0Ooo . i1IIi % I1Ii111
    IIiiIiIIiI1 = len ( packet )
    oO0oO00 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] ) [ 0 ]
    oO0oO00 = socket . ntohs ( oO0oO00 )
    if 44 - 44: Oo0Ooo - OOooOOo . Ii1I * OoooooooOO
    if ( oO0oO00 == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ oO0o00O : : ]
     self . rloc_name = None
     if ( oO0oO00 == LISP_AFI_NAME ) :
      packet , Ooo000oo0OO0 = lisp_decode_dist_name ( packet )
      self . rloc_name = Ooo000oo0OO0
     else :
      self . rloc . afi = oO0oO00
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 93 - 93: OoO0O00 . OoO0O00
      if 52 - 52: OOooOOo . oO0o / Oo0Ooo . OoooooooOO % I1ii11iIi11i
      if 65 - 65: ooOoO0o % II111iiii . iII111i - iIii1I11I1II1 - I1IiiI
    o00O0oOO0o -= IIiiIiIIiI1 - len ( packet )
    if 63 - 63: I1IiiI . OoOoOO00 - II111iiii
    if 55 - 55: ooOoO0o - o0oOOo0O0Ooo
  elif ( iiii1II == LISP_LCAF_GEO_COORD_TYPE ) :
   if 32 - 32: I1Ii111 * Ii1I / I1Ii111 . OoOoOO00 + I1ii11iIi11i - ooOoO0o
   if 14 - 14: IiII * O0 + O0 - ooOoO0o . i11iIiiIii - IiII
   if 37 - 37: I11i
   if 19 - 19: OoooooooOO % I1Ii111
   OOoooo = lisp_geo ( "" )
   packet = OOoooo . decode_geo ( packet , o00O0oOO0o , o000OOooo000O )
   if ( packet == None ) : return ( None )
   self . geo = OOoooo
   if 20 - 20: I11i
  elif ( iiii1II == LISP_LCAF_JSON_TYPE ) :
   if 15 - 15: o0oOOo0O0Ooo . i11iIiiIii * I1ii11iIi11i / ooOoO0o
   if 41 - 41: ooOoO0o + IiII . i1IIi + iIii1I11I1II1
   if 57 - 57: i11iIiiIii * oO0o * i11iIiiIii
   if 14 - 14: Oo0Ooo / I11i
   o00OooooOOOO = "H"
   oO0o00O = struct . calcsize ( o00OooooOOOO )
   if ( o00O0oOO0o < oO0o00O ) : return ( None )
   if 14 - 14: Oo0Ooo - Ii1I + ooOoO0o - I1IiiI % IiII
   O0000000oooOO = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] ) [ 0 ]
   O0000000oooOO = socket . ntohs ( O0000000oooOO )
   if ( o00O0oOO0o < oO0o00O + O0000000oooOO ) : return ( None )
   if 70 - 70: I1IiiI % ooOoO0o * OoO0O00 + OoOoOO00 % i11iIiiIii
   packet = packet [ oO0o00O : : ]
   self . json = lisp_json ( "" , packet [ 0 : O0000000oooOO ] )
   packet = packet [ O0000000oooOO : : ]
   if 39 - 39: Oo0Ooo % I1Ii111 / I1IiiI / Oo0Ooo . o0oOOo0O0Ooo + o0oOOo0O0Ooo
  elif ( iiii1II == LISP_LCAF_ELP_TYPE ) :
   if 83 - 83: OoooooooOO * II111iiii % OoooooooOO
   if 30 - 30: I1Ii111 / o0oOOo0O0Ooo + OoooooooOO + OoOoOO00 + OoO0O00
   if 40 - 40: OoooooooOO / IiII
   if 82 - 82: i11iIiiIii - oO0o - i1IIi
   OOo0oo0OOOO = lisp_elp ( None )
   OOo0oo0OOOO . elp_nodes = [ ]
   while ( o00O0oOO0o > 0 ) :
    OO000OOO , oO0oO00 = struct . unpack ( "HH" , packet [ : 4 ] )
    if 36 - 36: I1IiiI % ooOoO0o . OoooooooOO . OoOoOO00 / I11i
    oO0oO00 = socket . ntohs ( oO0oO00 )
    if ( oO0oO00 == LISP_AFI_LCAF ) : return ( None )
    if 1 - 1: I1Ii111 / Ii1I % I1ii11iIi11i
    Oo0ooOOOOOoO = lisp_elp_node ( )
    OOo0oo0OOOO . elp_nodes . append ( Oo0ooOOOOOoO )
    if 70 - 70: OoOoOO00 * ooOoO0o . I1IiiI
    OO000OOO = socket . ntohs ( OO000OOO )
    Oo0ooOOOOOoO . eid = ( OO000OOO & 0x4 )
    Oo0ooOOOOOoO . probe = ( OO000OOO & 0x2 )
    Oo0ooOOOOOoO . strict = ( OO000OOO & 0x1 )
    Oo0ooOOOOOoO . address . afi = oO0oO00
    Oo0ooOOOOOoO . address . mask_len = Oo0ooOOOOOoO . address . host_mask_len ( )
    packet = Oo0ooOOOOOoO . address . unpack_address ( packet [ 4 : : ] )
    o00O0oOO0o -= Oo0ooOOOOOoO . address . addr_length ( ) + 4
    if 64 - 64: ooOoO0o % I1ii11iIi11i . OoO0O00 . ooOoO0o + i11iIiiIii . iIii1I11I1II1
   OOo0oo0OOOO . select_elp_node ( )
   self . elp = OOo0oo0OOOO
   if 70 - 70: ooOoO0o
  elif ( iiii1II == LISP_LCAF_RLE_TYPE ) :
   if 3 - 3: I1IiiI - I1IiiI
   if 89 - 89: OoOoOO00
   if 27 - 27: i1IIi % OoOoOO00 / Ii1I * Ii1I / I11i
   if 11 - 11: OOooOOo
   OoO000oo000o0 = lisp_rle ( None )
   OoO000oo000o0 . rle_nodes = [ ]
   while ( o00O0oOO0o > 0 ) :
    OoOO0OOOO0 , oOoOoO0Oo0oo , i1Ii , oO0oO00 = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 96 - 96: ooOoO0o % Ii1I
    oO0oO00 = socket . ntohs ( oO0oO00 )
    if ( oO0oO00 == LISP_AFI_LCAF ) : return ( None )
    if 83 - 83: I1IiiI - OOooOOo . I1IiiI * Oo0Ooo
    Oo0000O00o0 = lisp_rle_node ( )
    OoO000oo000o0 . rle_nodes . append ( Oo0000O00o0 )
    if 76 - 76: i11iIiiIii + Ii1I
    Oo0000O00o0 . level = i1Ii
    Oo0000O00o0 . address . afi = oO0oO00
    Oo0000O00o0 . address . mask_len = Oo0000O00o0 . address . host_mask_len ( )
    packet = Oo0000O00o0 . address . unpack_address ( packet [ 6 : : ] )
    if 14 - 14: OoO0O00 * OoooooooOO
    o00O0oOO0o -= Oo0000O00o0 . address . addr_length ( ) + 6
    if ( o00O0oOO0o >= 2 ) :
     oO0oO00 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( oO0oO00 ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , Oo0000O00o0 . rloc_name = lisp_decode_dist_name ( packet )
      if 45 - 45: iIii1I11I1II1 * I1IiiI . OoOoOO00
      if ( packet == None ) : return ( None )
      o00O0oOO0o -= len ( Oo0000O00o0 . rloc_name ) + 1 + 2
      if 97 - 97: I11i % II111iiii % Ii1I . II111iiii . iIii1I11I1II1
      if 98 - 98: i11iIiiIii + O0 - O0 - iII111i
      if 25 - 25: oO0o / O0 + I1Ii111 % i11iIiiIii / I1IiiI
   self . rle = OoO000oo000o0
   self . rle . build_forwarding_list ( )
   if 62 - 62: iII111i . I11i * i1IIi + iII111i
  elif ( iiii1II == LISP_LCAF_SECURITY_TYPE ) :
   if 95 - 95: Ii1I / o0oOOo0O0Ooo % ooOoO0o - I1IiiI / OOooOOo * OOooOOo
   if 6 - 6: OoO0O00 % IiII + iIii1I11I1II1
   if 18 - 18: II111iiii . Ii1I + OoOoOO00 + O0 - I11i
   if 30 - 30: II111iiii
   if 26 - 26: I11i - i1IIi - Oo0Ooo * O0 * OOooOOo . OoooooooOO
   IiIIIii1iIII1 = packet
   i1i1IIiIiI11 = lisp_keys ( 1 )
   packet = i1i1IIiIiI11 . decode_lcaf ( IiIIIii1iIII1 , o00O0oOO0o )
   if ( packet == None ) : return ( None )
   if 99 - 99: oO0o . OoO0O00 / OOooOOo
   if 12 - 12: iIii1I11I1II1 + ooOoO0o * I1Ii111 % OoooooooOO / iIii1I11I1II1
   if 43 - 43: O0 . i1IIi - OoooooooOO - i1IIi - I1ii11iIi11i
   if 8 - 8: OoOoOO00 / Ii1I
   IIiIiIii11I1 = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( i1i1IIiIiI11 . cipher_suite in IIiIiIii11I1 ) :
    if ( i1i1IIiIiI11 . cipher_suite == LISP_CS_25519_CBC ) :
     iII1 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 12 - 12: iIii1I11I1II1
    if ( i1i1IIiIiI11 . cipher_suite == LISP_CS_25519_CHACHA ) :
     iII1 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 52 - 52: oO0o . I1ii11iIi11i + oO0o
   else :
    iII1 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 73 - 73: II111iiii / i11iIiiIii / ooOoO0o
   packet = iII1 . decode_lcaf ( IiIIIii1iIII1 , o00O0oOO0o )
   if ( packet == None ) : return ( None )
   if 1 - 1: iII111i + OoOoOO00 / IiII - I1IiiI % I1IiiI
   if ( len ( packet ) < 2 ) : return ( None )
   oO0oO00 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( oO0oO00 )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 6 - 6: OoOoOO00 - i1IIi + II111iiii % oO0o
   if 72 - 72: OOooOOo + OOooOOo
   if 30 - 30: I11i
   if 15 - 15: O0 - i1IIi . iIii1I11I1II1 - i11iIiiIii / Ii1I
   if 11 - 11: iIii1I11I1II1 + I1IiiI
   if 15 - 15: o0oOOo0O0Ooo
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 55 - 55: i11iIiiIii / OoooooooOO - I11i
   O0Oo0oO0 = self . rloc_name
   if ( O0Oo0oO0 ) : O0Oo0oO0 = blue ( self . rloc_name , False )
   if 9 - 9: i1IIi + i11iIiiIii + I1ii11iIi11i % OoOoOO00 / i11iIiiIii + i11iIiiIii
   if 13 - 13: Ii1I % ooOoO0o
   if 92 - 92: II111iiii + Ii1I + Ii1I
   if 68 - 68: OoooooooOO / o0oOOo0O0Ooo + iIii1I11I1II1 . Ii1I % Ii1I - I1IiiI
   if 26 - 26: iIii1I11I1II1 - I1IiiI + iII111i
   if 61 - 61: i1IIi + OOooOOo + iIii1I11I1II1
   II = self . keys [ 1 ] if self . keys else None
   if ( II == None ) :
    if ( iII1 . remote_public_key == None ) :
     IIIiiiI1Ii1 = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( IIIiiiI1Ii1 , O0Oo0oO0 ) )
     iII1 = None
    else :
     IIIiiiI1Ii1 = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( IIIiiiI1Ii1 , O0Oo0oO0 ) )
     iII1 . compute_shared_key ( "encap" )
     if 76 - 76: iIii1I11I1II1 + I1ii11iIi11i + iIii1I11I1II1 + OoO0O00
     if 83 - 83: i1IIi + Oo0Ooo . O0 / IiII - II111iiii + ooOoO0o
     if 17 - 17: OOooOOo
     if 93 - 93: Oo0Ooo / II111iiii . Oo0Ooo + i1IIi + i1IIi
     if 30 - 30: OoOoOO00 . OOooOOo % OOooOOo / II111iiii + i1IIi
     if 61 - 61: i1IIi % II111iiii * II111iiii . o0oOOo0O0Ooo / I1ii11iIi11i - I1Ii111
     if 93 - 93: Ii1I - i1IIi
     if 3 - 3: oO0o + OoO0O00 - iII111i / Ii1I
     if 58 - 58: Ii1I * I11i
     if 95 - 95: oO0o
   if ( II ) :
    if ( iII1 . remote_public_key == None ) :
     iII1 = None
     ii1IIi = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( ii1IIi , O0Oo0oO0 ) )
    elif ( II . compare_keys ( iII1 ) ) :
     iII1 = II
     lprint ( "    Maintain stored encap-keys for {}" . format ( O0Oo0oO0 ) )
     if 49 - 49: I1IiiI
    else :
     if ( II . remote_public_key == None ) :
      IIIiiiI1Ii1 = "New encap-keying for existing state"
     else :
      IIIiiiI1Ii1 = "Remote encap-rekeying"
      if 23 - 23: I1Ii111
     lprint ( "    {} for {}" . format ( bold ( IIIiiiI1Ii1 , False ) ,
 O0Oo0oO0 ) )
     II . remote_public_key = iII1 . remote_public_key
     II . compute_shared_key ( "encap" )
     iII1 = II
     if 5 - 5: I1ii11iIi11i % OoOoOO00 . OoooooooOO . o0oOOo0O0Ooo + i11iIiiIii
     if 54 - 54: ooOoO0o - O0 + iII111i
   self . keys = [ None , iII1 , None , None ]
   if 34 - 34: Ii1I - OOooOOo % iII111i
  else :
   if 48 - 48: oO0o - O0
   if 17 - 17: iIii1I11I1II1 . IiII / ooOoO0o % I11i + o0oOOo0O0Ooo - iIii1I11I1II1
   if 95 - 95: OoOoOO00 + OOooOOo - I11i * i1IIi + i1IIi * O0
   if 60 - 60: Oo0Ooo + I11i % iIii1I11I1II1 % oO0o - I1Ii111 / o0oOOo0O0Ooo
   packet = packet [ o00O0oOO0o : : ]
   if 9 - 9: IiII / oO0o % O0 * I1Ii111 - iIii1I11I1II1 % i1IIi
  return ( packet )
  if 83 - 83: OoOoOO00 + OOooOOo / OoooooooOO
  if 39 - 39: OoO0O00 % iII111i . oO0o . II111iiii - i11iIiiIii
 def decode ( self , packet , nonce ) :
  o00OooooOOOO = "BBBBHH"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 85 - 85: O0 - OoOoOO00
  self . priority , self . weight , self . mpriority , self . mweight , OO000OOO , oO0oO00 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  if 17 - 17: o0oOOo0O0Ooo / i1IIi / OOooOOo
  if 91 - 91: I1ii11iIi11i / Ii1I - OoOoOO00 . I11i / oO0o
  OO000OOO = socket . ntohs ( OO000OOO )
  oO0oO00 = socket . ntohs ( oO0oO00 )
  self . local_bit = True if ( OO000OOO & 0x0004 ) else False
  self . probe_bit = True if ( OO000OOO & 0x0002 ) else False
  self . reach_bit = True if ( OO000OOO & 0x0001 ) else False
  if 16 - 16: IiII % iII111i . oO0o . I1IiiI % O0 * I11i
  if ( oO0oO00 == LISP_AFI_LCAF ) :
   packet = packet [ oO0o00O - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce )
  else :
   self . rloc . afi = oO0oO00
   packet = packet [ oO0o00O : : ]
   packet = self . rloc . unpack_address ( packet )
   if 99 - 99: OoOoOO00 / OoooooooOO + iII111i * I11i * i11iIiiIii + OOooOOo
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 40 - 40: II111iiii / I11i % I1IiiI - O0
  if 39 - 39: i11iIiiIii - OoOoOO00 % OOooOOo + ooOoO0o + i11iIiiIii
 def end_of_rlocs ( self , packet , rloc_count ) :
  for i1i1IIIIIIIi in range ( rloc_count ) :
   packet = self . decode ( packet , None )
   if ( packet == None ) : return ( None )
   if 59 - 59: IiII / OoOoOO00 - I1Ii111 - ooOoO0o . oO0o
  return ( packet )
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
class lisp_map_referral ( ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 44 - 44: ooOoO0o . I1IiiI * oO0o * Ii1I
  if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # iII111i
 lisp_hex_string ( self . nonce ) ) )
  if 54 - 54: OoO0O00 / I1IiiI
  if 4 - 4: O0
 def encode ( self ) :
  i1IiIiiiii11 = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  ii1i1II = struct . pack ( "I" , socket . htonl ( i1IiIiiiii11 ) )
  ii1i1II += struct . pack ( "Q" , self . nonce )
  return ( ii1i1II )
  if 87 - 87: IiII - OoO0O00 * Oo0Ooo / o0oOOo0O0Ooo % oO0o % Ii1I
  if 25 - 25: Ii1I - I1ii11iIi11i + Oo0Ooo . I1IiiI
 def decode ( self , packet ) :
  o00OooooOOOO = "I"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 36 - 36: iII111i
  i1IiIiiiii11 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  i1IiIiiiii11 = socket . ntohl ( i1IiIiiiii11 [ 0 ] )
  self . record_count = i1IiIiiiii11 & 0xff
  packet = packet [ oO0o00O : : ]
  if 3 - 3: Ii1I
  o00OooooOOOO = "Q"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 44 - 44: O0 - oO0o % II111iiii . I1Ii111
  self . nonce = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] ) [ 0 ]
  packet = packet [ oO0o00O : : ]
  return ( packet )
  if 86 - 86: IiII
  if 71 - 71: Ii1I - i1IIi . I1IiiI
  if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
  if 54 - 54: i1IIi . OoO0O00 + iII111i + OoO0O00 * i1IIi
  if 13 - 13: Oo0Ooo / OoO0O00 + OOooOOo
  if 90 - 90: OoO0O00 * i11iIiiIii / oO0o
  if 91 - 91: iII111i - OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
  if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
class lisp_ddt_entry ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 25 - 25: OoOoOO00 + IiII . i11iIiiIii
  if 87 - 87: I1IiiI + OoooooooOO + O0
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
  if 65 - 65: IiII
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 74 - 74: Oo0Ooo + i1IIi - II111iiii / ooOoO0o / iII111i
  if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  I11i1ii11 = self . delegation_set [ 0 ]
  return ( I11i1ii11 . print_node_type ( ) )
  if 8 - 8: I1ii11iIi11i % Oo0Ooo % O0 + I1ii11iIi11i % I1ii11iIi11i
  if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
  if 29 - 29: Oo0Ooo - Ii1I - Oo0Ooo
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   OO = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( OO == None ) :
    OO = lisp_ddt_entry ( )
    OO . eid . copy_address ( self . group )
    OO . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , OO )
    if 14 - 14: I1ii11iIi11i * oO0o . O0
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OO . group )
   OO . add_source_entry ( self )
   if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
   if 69 - 69: I1Ii111 + O0 . IiII . o0oOOo0O0Ooo
   if 38 - 38: IiII / i1IIi
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 60 - 60: OoOoOO00
  if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 61 - 61: IiII . IiII
  if 17 - 17: OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
  if 95 - 95: iII111i / ooOoO0o + I1Ii111
  if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
class lisp_ddt_node ( ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 81 - 81: I1ii11iIi11i
  if 31 - 31: O0 % ooOoO0o / I1IiiI * iII111i % iIii1I11I1II1 * OoOoOO00
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 76 - 76: I1Ii111 - O0
  if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 7 - 7: II111iiii + I11i
  if 99 - 99: iIii1I11I1II1 * oO0o
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 37 - 37: ooOoO0o * iII111i * I11i
  if 11 - 11: I1IiiI
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 48 - 48: O0 . I11i
  if 9 - 9: oO0o / Oo0Ooo
  if 85 - 85: i11iIiiIii / I1IiiI . OoO0O00 . I11i . oO0o * IiII
  if 41 - 41: Ii1I / OoO0O00 / OoO0O00 * I11i
  if 31 - 31: Ii1I / OoooooooOO % iIii1I11I1II1 - IiII * I1IiiI - O0
  if 31 - 31: oO0o
  if 74 - 74: OoO0O00
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
  if 11 - 11: oO0o + O0 % Ii1I . I11i * o0oOOo0O0Ooo
  if 14 - 14: I11i . iIii1I11I1II1 + I1Ii111 % OoooooooOO
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # iII111i
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 36 - 36: Ii1I / I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo
  if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
  if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( lisp_ddt_map_requestQ . has_key ( str ( self . nonce ) ) ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 30 - 30: i11iIiiIii % OOooOOo
   if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
   if 27 - 27: I1IiiI + OoOoOO00 + iII111i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
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
  if 79 - 79: I1Ii111 - I11i
  if 49 - 49: II111iiii + O0 * ooOoO0o - Oo0Ooo
  if 89 - 89: I1IiiI + I11i . oO0o . II111iiii + oO0o / Oo0Ooo
  if 32 - 32: OoO0O00 % oO0o * I1ii11iIi11i + I11i / I1Ii111
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 5 - 5: o0oOOo0O0Ooo + iII111i / OoooooooOO + Ii1I . OoOoOO00 / oO0o
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
if 46 - 46: o0oOOo0O0Ooo
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
if 27 - 27: Oo0Ooo + Oo0Ooo / II111iiii % I1Ii111
if 11 - 11: Ii1I
if 54 - 54: I1IiiI * I1Ii111 / ooOoO0o / iIii1I11I1II1 % iII111i / oO0o
if 11 - 11: ooOoO0o + I1IiiI + Ii1I . II111iiii
if 50 - 50: Oo0Ooo
if 14 - 14: O0
if 67 - 67: II111iiii / O0
if 10 - 10: i1IIi / Oo0Ooo
if 20 - 20: Oo0Ooo * I1Ii111 / I1ii11iIi11i . ooOoO0o
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
  if 67 - 67: o0oOOo0O0Ooo . Oo0Ooo % I11i
  if 38 - 38: OOooOOo - OoO0O00 . ooOoO0o
 def print_info ( self ) :
  if ( self . info_reply ) :
   i1IiiI1i = "Info-Reply"
   OooO0ooO0o0OO = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # OoooooooOO % iII111i
   # II111iiii % II111iiii + O0 - i11iIiiIii
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : OooO0ooO0o0OO += "empty, "
   for O0O0 in self . rtr_list :
    OooO0ooO0o0OO += red ( O0O0 . print_address_no_iid ( ) , False ) + ", "
    if 80 - 80: I11i * oO0o % iIii1I11I1II1 / iII111i
   OooO0ooO0o0OO = OooO0ooO0o0OO [ 0 : - 2 ]
  else :
   i1IiiI1i = "Info-Request"
   O0oo0OoOO = "<none>" if self . hostname == None else self . hostname
   OooO0ooO0o0OO = ", hostname: {}" . format ( blue ( O0oo0OoOO , False ) )
   if 58 - 58: II111iiii . I1IiiI . i1IIi
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( i1IiiI1i , False ) ,
 lisp_hex_string ( self . nonce ) , OooO0ooO0o0OO ) )
  if 60 - 60: iIii1I11I1II1 + ooOoO0o * i11iIiiIii + OoooooooOO
  if 43 - 43: I1ii11iIi11i % Oo0Ooo - i11iIiiIii / I1Ii111 * i1IIi
 def encode ( self ) :
  i1IiIiiiii11 = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : i1IiIiiiii11 |= ( 1 << 27 )
  if 78 - 78: o0oOOo0O0Ooo / OOooOOo / oO0o
  if 9 - 9: IiII + O0 / I1IiiI
  if 92 - 92: OOooOOo / i11iIiiIii + OoooooooOO
  if 9 - 9: iII111i
  if 9 - 9: O0 / o0oOOo0O0Ooo / I11i - i11iIiiIii - iII111i / IiII
  ii1i1II = struct . pack ( "I" , socket . htonl ( i1IiIiiiii11 ) )
  ii1i1II += struct . pack ( "Q" , self . nonce )
  ii1i1II += struct . pack ( "III" , 0 , 0 , 0 )
  if 46 - 46: IiII + OoooooooOO % I1IiiI
  if 51 - 51: I1IiiI * I1Ii111 . i11iIiiIii % Oo0Ooo . i1IIi - oO0o
  if 56 - 56: Oo0Ooo / II111iiii
  if 76 - 76: OoOoOO00 % OoO0O00 * O0
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    ii1i1II += struct . pack ( "H" , 0 )
   else :
    ii1i1II += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    ii1i1II += self . hostname + "\0"
    if 39 - 39: ooOoO0o / iII111i
   return ( ii1i1II )
   if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
   if 59 - 59: I11i % Ii1I / OoOoOO00
   if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
   if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
   if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
  oO0oO00 = socket . htons ( LISP_AFI_LCAF )
  iiii1II = LISP_LCAF_NAT_TYPE
  o00O0oOO0o = socket . htons ( 16 )
  i1IIIoOoO00 = socket . htons ( self . ms_port )
  Oo0OOO0OO = socket . htons ( self . etr_port )
  ii1i1II += struct . pack ( "HHBBHHHH" , oO0oO00 , 0 , iiii1II , 0 , o00O0oOO0o ,
 i1IIIoOoO00 , Oo0OOO0OO , socket . htons ( self . global_etr_rloc . afi ) )
  ii1i1II += self . global_etr_rloc . pack_address ( )
  ii1i1II += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  ii1i1II += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : ii1i1II += struct . pack ( "H" , 0 )
  if 60 - 60: I11i * i1IIi + OoO0O00 . i11iIiiIii - OoO0O00 % OoO0O00
  if 46 - 46: Ii1I + I1ii11iIi11i / iIii1I11I1II1 % i1IIi
  if 47 - 47: Ii1I % OoO0O00
  if 68 - 68: I1Ii111
  for O0O0 in self . rtr_list :
   ii1i1II += struct . pack ( "H" , socket . htons ( O0O0 . afi ) )
   ii1i1II += O0O0 . pack_address ( )
   if 76 - 76: I1ii11iIi11i . OoooooooOO + OoO0O00 % OOooOOo * i1IIi / i1IIi
  return ( ii1i1II )
  if 69 - 69: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / iII111i % IiII
  if 84 - 84: ooOoO0o + i1IIi / Oo0Ooo * iIii1I11I1II1 + o0oOOo0O0Ooo + Oo0Ooo
 def decode ( self , packet ) :
  IiIIIii1iIII1 = packet
  o00OooooOOOO = "I"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 78 - 78: o0oOOo0O0Ooo . I11i / Ii1I . IiII
  i1IiIiiiii11 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  i1IiIiiiii11 = i1IiIiiiii11 [ 0 ]
  packet = packet [ oO0o00O : : ]
  if 27 - 27: I1IiiI % Ii1I - iIii1I11I1II1 + ooOoO0o
  o00OooooOOOO = "Q"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 64 - 64: i11iIiiIii - Oo0Ooo / iIii1I11I1II1 / I1IiiI % ooOoO0o
  OO00OO = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  if 42 - 42: Oo0Ooo * OoOoOO00 % ooOoO0o * oO0o - Oo0Ooo + OOooOOo
  i1IiIiiiii11 = socket . ntohl ( i1IiIiiiii11 )
  self . nonce = OO00OO [ 0 ]
  self . info_reply = i1IiIiiiii11 & 0x08000000
  self . hostname = None
  packet = packet [ oO0o00O : : ]
  if 5 - 5: OoooooooOO * O0 / I1Ii111 + ooOoO0o . I1Ii111
  if 57 - 57: ooOoO0o * OOooOOo % OoOoOO00 - OoOoOO00 - o0oOOo0O0Ooo * i1IIi
  if 80 - 80: iII111i
  if 81 - 81: OoooooooOO % OoOoOO00 % Oo0Ooo - I1IiiI
  if 43 - 43: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  o00OooooOOOO = "HH"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 48 - 48: O0
  if 5 - 5: OOooOOo / i11iIiiIii . I11i % OOooOOo
  if 1 - 1: II111iiii + O0 * OoOoOO00 / IiII . O0
  if 87 - 87: IiII + I1IiiI
  if 74 - 74: OoO0O00 + OoO0O00 % iII111i / I11i / O0
  o0O , iI1i1i1i1i = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  if ( iI1i1i1i1i != 0 ) : return ( None )
  if 54 - 54: o0oOOo0O0Ooo / OoooooooOO * ooOoO0o . OoOoOO00 - I1Ii111
  packet = packet [ oO0o00O : : ]
  o00OooooOOOO = "IBBH"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 69 - 69: oO0o - OoO0O00
  oo0OOoOO0 , O0Ooo000Ooo , O0ooOo , oOOoooOO0O = struct . unpack ( o00OooooOOOO ,
 packet [ : oO0o00O ] )
  if 14 - 14: I1ii11iIi11i + iII111i . I11i . Oo0Ooo
  if ( oOOoooOO0O != 0 ) : return ( None )
  packet = packet [ oO0o00O : : ]
  if 24 - 24: OoO0O00 * II111iiii . OoooooooOO - I1IiiI + OoooooooOO
  if 91 - 91: oO0o * I1IiiI + iIii1I11I1II1
  if 43 - 43: OoO0O00 - II111iiii
  if 17 - 17: Ii1I
  if ( self . info_reply == False ) :
   o00OooooOOOO = "H"
   oO0o00O = struct . calcsize ( o00OooooOOOO )
   if ( len ( packet ) >= oO0o00O ) :
    oO0oO00 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] ) [ 0 ]
    if ( socket . ntohs ( oO0oO00 ) == LISP_AFI_NAME ) :
     packet = packet [ oO0o00O : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 34 - 34: IiII / ooOoO0o * II111iiii * iII111i % OoooooooOO - iIii1I11I1II1
     if 61 - 61: OOooOOo - OOooOOo / ooOoO0o * I1Ii111
   return ( IiIIIii1iIII1 )
   if 73 - 73: OoO0O00 * Ii1I
   if 49 - 49: OoooooooOO / oO0o / I1IiiI + o0oOOo0O0Ooo * ooOoO0o . Oo0Ooo
   if 48 - 48: I11i + IiII / IiII
   if 65 - 65: I1ii11iIi11i - i1IIi % oO0o * iIii1I11I1II1 - IiII + ooOoO0o
   if 63 - 63: i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
  o00OooooOOOO = "HHBBHHH"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
  oO0oO00 , OoOO0OOOO0 , iiii1II , O0Ooo000Ooo , o00O0oOO0o , i1IIIoOoO00 , Oo0OOO0OO = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  if 84 - 84: OOooOOo * i1IIi . iIii1I11I1II1 * iII111i + I1Ii111 + II111iiii
  if 97 - 97: Ii1I - IiII
  if ( socket . ntohs ( oO0oO00 ) != LISP_AFI_LCAF ) : return ( None )
  if 64 - 64: oO0o . ooOoO0o / ooOoO0o - II111iiii
  self . ms_port = socket . ntohs ( i1IIIoOoO00 )
  self . etr_port = socket . ntohs ( Oo0OOO0OO )
  packet = packet [ oO0o00O : : ]
  if 81 - 81: I1ii11iIi11i
  if 64 - 64: oO0o * OoO0O00 / OOooOOo + Ii1I % Oo0Ooo . IiII
  if 2 - 2: I1Ii111 + I11i
  if 47 - 47: i11iIiiIii + iIii1I11I1II1 % I1ii11iIi11i - oO0o % OoO0O00
  o00OooooOOOO = "H"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 85 - 85: oO0o * OoOoOO00 / OoOoOO00
  if 85 - 85: OOooOOo / I1Ii111 . i1IIi / OoOoOO00 + iIii1I11I1II1
  if 71 - 71: OoO0O00
  if 96 - 96: I1ii11iIi11i / I1IiiI - I1ii11iIi11i / II111iiii - IiII
  oO0oO00 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] ) [ 0 ]
  packet = packet [ oO0o00O : : ]
  if ( oO0oO00 != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( oO0oO00 )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 74 - 74: Ii1I * OoooooooOO % OOooOOo + OoooooooOO + iII111i
   if 83 - 83: i1IIi
   if 2 - 2: i1IIi / OOooOOo * O0
   if 99 - 99: OoooooooOO . OoOoOO00 / II111iiii
   if 64 - 64: iII111i / i1IIi . I1IiiI + O0
   if 5 - 5: O0 . i11iIiiIii
  if ( len ( packet ) < oO0o00O ) : return ( IiIIIii1iIII1 )
  if 71 - 71: o0oOOo0O0Ooo + iII111i + ooOoO0o
  oO0oO00 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] ) [ 0 ]
  packet = packet [ oO0o00O : : ]
  if ( oO0oO00 != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( oO0oO00 )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( IiIIIii1iIII1 )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 27 - 27: OoooooooOO . iII111i * I1Ii111 % O0 + OoooooooOO - iII111i
   if 86 - 86: i1IIi
   if 81 - 81: OoOoOO00
   if 52 - 52: iII111i * IiII % I1IiiI * I11i
   if 73 - 73: I1Ii111 * ooOoO0o
  if ( len ( packet ) < oO0o00O ) : return ( IiIIIii1iIII1 )
  if 62 - 62: OOooOOo . I1IiiI * iIii1I11I1II1 + OoO0O00 * ooOoO0o / oO0o
  oO0oO00 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] ) [ 0 ]
  packet = packet [ oO0o00O : : ]
  if ( oO0oO00 != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( oO0oO00 )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( IiIIIii1iIII1 )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 14 - 14: iII111i / OoO0O00
   if 75 - 75: IiII
   if 68 - 68: IiII - i1IIi % IiII . OoO0O00 . i11iIiiIii . OoooooooOO
   if 32 - 32: iII111i + OoO0O00 % IiII + I1IiiI
   if 69 - 69: I1Ii111 + I11i - iIii1I11I1II1 - II111iiii . Ii1I
   if 74 - 74: I1ii11iIi11i % o0oOOo0O0Ooo + O0 - i11iIiiIii - IiII % OOooOOo
  while ( len ( packet ) >= oO0o00O ) :
   oO0oO00 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] ) [ 0 ]
   packet = packet [ oO0o00O : : ]
   if ( oO0oO00 == 0 ) : continue
   O0O0 = lisp_address ( socket . ntohs ( oO0oO00 ) , "" , 0 , 0 )
   packet = O0O0 . unpack_address ( packet )
   if ( packet == None ) : return ( IiIIIii1iIII1 )
   O0O0 . mask_len = O0O0 . host_mask_len ( )
   self . rtr_list . append ( O0O0 )
   if 39 - 39: OoO0O00 - o0oOOo0O0Ooo
  return ( IiIIIii1iIII1 )
  if 71 - 71: iII111i . OoO0O00 + ooOoO0o - OOooOOo - Oo0Ooo
  if 100 - 100: OoooooooOO - o0oOOo0O0Ooo + I1Ii111 . OoooooooOO % i11iIiiIii
  if 64 - 64: I1Ii111 % OoooooooOO / i1IIi / OoO0O00
class lisp_nat_info ( ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 2 - 2: I11i % o0oOOo0O0Ooo . OoO0O00 . OoO0O00
  if 89 - 89: ooOoO0o - oO0o + II111iiii + OoO0O00 - IiII
 def timed_out ( self ) :
  o0O0oO0 = time . time ( ) - self . uptime
  return ( o0O0oO0 >= ( LISP_INFO_INTERVAL * 2 ) )
  if 27 - 27: I1Ii111 - o0oOOo0O0Ooo + OoO0O00
  if 38 - 38: OoOoOO00 + OoO0O00 . i11iIiiIii + Ii1I % i1IIi % I1IiiI
  if 93 - 93: i11iIiiIii
class lisp_info_source ( ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 63 - 63: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo
  if 97 - 97: i1IIi % I11i % OoOoOO00
 def cache_address_for_info_source ( self ) :
  iII1 = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ iII1 ] = self
  if 25 - 25: OoOoOO00 . iIii1I11I1II1 - iII111i % II111iiii . OoOoOO00
  if 16 - 16: OOooOOo . Oo0Ooo . I1IiiI % O0 . I1ii11iIi11i + i11iIiiIii
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
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
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 78 - 78: I1ii11iIi11i - OoooooooOO + O0
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 15 - 15: I1ii11iIi11i / IiII % I1IiiI
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 16 - 16: Ii1I
  if 26 - 26: o0oOOo0O0Ooo / I11i + OoOoOO00 / OoOoOO00
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  iIIiiiIiiii11 = auth1 + auth2 + auth3
  if 31 - 31: I1Ii111
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  iIIiiiIiiii11 = auth1 + auth2 + auth3 + auth4
  if 84 - 84: i11iIiiIii * OOooOOo . iII111i - Ii1I * i1IIi - I1ii11iIi11i
 return ( iIIiiiIiiii11 )
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
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   OoO0o = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 84 - 84: OoooooooOO
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   OoO0o = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 76 - 76: O0 / i11iIiiIii - OoOoOO00
  OoO0o . bind ( ( local_addr , int ( port ) ) )
 else :
  oOo0oooo = port
  if ( os . path . exists ( oOo0oooo ) ) :
   os . system ( "rm " + oOo0oooo )
   time . sleep ( 1 )
   if 95 - 95: i11iIiiIii % i11iIiiIii
  OoO0o = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  OoO0o . bind ( oOo0oooo )
  if 54 - 54: OoO0O00 / I1IiiI . Oo0Ooo
 return ( OoO0o )
 if 39 - 39: OoO0O00 . ooOoO0o
 if 41 - 41: Oo0Ooo * I1ii11iIi11i - II111iiii - II111iiii
 if 7 - 7: oO0o
 if 41 - 41: ooOoO0o
 if 93 - 93: Ii1I + I1Ii111 + Ii1I
 if 23 - 23: I1IiiI - i1IIi / ooOoO0o
 if 4 - 4: IiII . I1ii11iIi11i + iII111i % ooOoO0o
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   OoO0o = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 28 - 28: I1Ii111
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   OoO0o = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 27 - 27: iII111i * I1IiiI
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  OoO0o = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  OoO0o . bind ( internal_name )
  if 60 - 60: i1IIi / I1IiiI - I1ii11iIi11i
 return ( OoO0o )
 if 41 - 41: I1Ii111 + ooOoO0o / OOooOOo + I11i % Oo0Ooo
 if 91 - 91: I1IiiI % I1ii11iIi11i % oO0o / i1IIi * iIii1I11I1II1 + I11i
 if 48 - 48: ooOoO0o / I1ii11iIi11i / OoO0O00 / II111iiii * OoOoOO00
 if 73 - 73: I11i / I1IiiI - IiII - i1IIi * IiII - OOooOOo
 if 39 - 39: I11i . ooOoO0o * II111iiii
 if 21 - 21: Ii1I
 if 92 - 92: OoO0O00 * I1ii11iIi11i + iIii1I11I1II1
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 88 - 88: iIii1I11I1II1 + iIii1I11I1II1 * i11iIiiIii . I1ii11iIi11i % oO0o
 if 94 - 94: I1IiiI / I1ii11iIi11i / OOooOOo
 if 45 - 45: II111iiii
 if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
 if 84 - 84: o0oOOo0O0Ooo
 if 40 - 40: OoooooooOO - oO0o / O0 * I1Ii111 . O0 + i11iIiiIii
 if 9 - 9: OOooOOo % O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
 if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 66 - 66: OOooOOo * Oo0Ooo
 if 58 - 58: OOooOOo
 if 96 - 96: IiII % OoooooooOO + O0 * II111iiii / OOooOOo . I1Ii111
 if 47 - 47: OoO0O00 - Oo0Ooo * OoO0O00 / oO0o
 if 13 - 13: ooOoO0o
 if 55 - 55: i1IIi . I11i . II111iiii + O0 + ooOoO0o - i1IIi
 if 3 - 3: iIii1I11I1II1 / oO0o
 if 61 - 61: I1Ii111 / O0 - iII111i
 if 44 - 44: i1IIi
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
 if 89 - 89: OoOoOO00 + Oo0Ooo . OoOoOO00 - II111iiii
 if 85 - 85: OoooooooOO * OoooooooOO / Ii1I - II111iiii
 if 69 - 69: iII111i * I11i
 if 43 - 43: o0oOOo0O0Ooo - IiII * Ii1I . i11iIiiIii / II111iiii
 if 61 - 61: OoOoOO00 / I1IiiI . I1ii11iIi11i % OOooOOo
 if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
 if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
 if 15 - 15: o0oOOo0O0Ooo / i11iIiiIii
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 63 - 63: I1ii11iIi11i - Ii1I + I11i
 if 98 - 98: iII111i / IiII * I1IiiI / oO0o - iIii1I11I1II1
 if 72 - 72: O0 . OOooOOo
 if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
 if 74 - 74: i1IIi
 if 80 - 80: ooOoO0o + I1Ii111 . I1ii11iIi11i % OoooooooOO
 if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
 if 35 - 35: i11iIiiIii + oO0o
 if 85 - 85: OoOoOO00 . O0 % OoooooooOO % oO0o
 if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
 if 12 - 12: II111iiii - iIii1I11I1II1
 if 43 - 43: i11iIiiIii % OoO0O00
 if 100 - 100: i1IIi
 if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
 if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 71 - 71: IiII + OoO0O00
 if 39 - 39: I1IiiI % IiII / II111iiii / II111iiii
 if 95 - 95: II111iiii + i11iIiiIii + o0oOOo0O0Ooo
 if 30 - 30: O0 - O0 % iIii1I11I1II1 + iII111i * OoooooooOO
 if 1 - 1: O0
 if 36 - 36: oO0o . iII111i
 if 62 - 62: I11i + iIii1I11I1II1 % I11i * OOooOOo + iIii1I11I1II1 % Ii1I
 if 56 - 56: o0oOOo0O0Ooo
 if 55 - 55: oO0o - I1Ii111 / ooOoO0o % I1IiiI * OoooooooOO * I1IiiI
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 88 - 88: Ii1I + O0
 if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
 if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
 if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
 if 85 - 85: OoooooooOO * ooOoO0o
 if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
 if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
 if 26 - 26: O0 % o0oOOo0O0Ooo + iII111i * I1ii11iIi11i * I1Ii111
 if 4 - 4: OOooOOo * OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
def lisp_ipc ( packet , send_socket , node ) :
 if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
 if 62 - 62: I1Ii111 % II111iiii
 if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
 if 91 - 91: i11iIiiIii + Ii1I
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 85 - 85: I11i % IiII
  if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
 o00o = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 1 - 1: oO0o - ooOoO0o
 i1 = 0
 iI1 = len ( packet )
 OooO0O0oo = 0
 o00oO0oo = .001
 while ( iI1 > 0 ) :
  OoO00oO0oOoO0 = min ( iI1 , o00o )
  o0OOOoOo0oO = packet [ i1 : OoO00oO0oOoO0 + i1 ]
  if 80 - 80: OoOoOO00
  try :
   send_socket . sendto ( o0OOOoOo0oO , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( o0OOOoOo0oO ) , len ( packet ) , node ) )
   if 31 - 31: OOooOOo * ooOoO0o + ooOoO0o / O0 - OOooOOo
   OooO0O0oo = 0
   o00oO0oo = .001
   if 47 - 47: I1Ii111 . OoooooooOO - oO0o - o0oOOo0O0Ooo . I1ii11iIi11i / iIii1I11I1II1
  except socket . error , o0OoO00 :
   if ( OooO0O0oo == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 20 - 20: i11iIiiIii / OoO0O00 * I1IiiI - I1IiiI * Ii1I
    if 73 - 73: ooOoO0o % I1Ii111
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( o0OOOoOo0oO ) , len ( packet ) , node , o0OoO00 ) )
   if 69 - 69: OoOoOO00 / OOooOOo / I1IiiI
   if 12 - 12: I1ii11iIi11i . iIii1I11I1II1 . II111iiii . OoOoOO00
   OooO0O0oo += 1
   time . sleep ( o00oO0oo )
   if 30 - 30: i11iIiiIii / Oo0Ooo / OOooOOo + i11iIiiIii * ooOoO0o
   lprint ( "Retrying after {} ms ..." . format ( o00oO0oo * 1000 ) )
   o00oO0oo *= 2
   continue
   if 4 - 4: O0 + I1IiiI + I1Ii111
   if 80 - 80: Ii1I % OoooooooOO . i1IIi - OOooOOo
  i1 += OoO00oO0oOoO0
  iI1 -= OoO00oO0oOoO0
  if 10 - 10: I11i + iII111i % OoO0O00 / OoO0O00
 return
 if 91 - 91: ooOoO0o . oO0o
 if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
 if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
 if 81 - 81: i1IIi % iIii1I11I1II1
 if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
 if 82 - 82: ooOoO0o
 if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 i1 = 0
 i1iiI11ii1II1 = ""
 iI1 = len ( packet ) * 2
 while ( i1 < iI1 ) :
  i1iiI11ii1II1 += packet [ i1 : i1 + 8 ] + " "
  i1 += 8
  iI1 -= 4
  if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
 return ( i1iiI11ii1II1 )
 if 59 - 59: i11iIiiIii / OoO0O00
 if 48 - 48: iIii1I11I1II1
 if 19 - 19: oO0o
 if 69 - 69: I1ii11iIi11i % iII111i - OoooooooOO % Ii1I * oO0o
 if 12 - 12: OoOoOO00 / I1Ii111 . O0 . IiII - OOooOOo - OoO0O00
 if 28 - 28: II111iiii . OoOoOO00 - o0oOOo0O0Ooo
 if 89 - 89: I1Ii111 * OoooooooOO . OOooOOo . I11i % i11iIiiIii
def lisp_send ( lisp_sockets , dest , port , packet ) :
 IIiiIII = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 33 - 33: OoO0O00 / OoO0O00 * i11iIiiIii % iII111i + II111iiii
 if 16 - 16: ooOoO0o * OoOoOO00 / OoOoOO00 + II111iiii
 if 50 - 50: OoO0O00 / OOooOOo % I1IiiI / Ii1I + OoO0O00 . iIii1I11I1II1
 if 62 - 62: I1Ii111 + OoooooooOO - Ii1I - iIii1I11I1II1
 if 80 - 80: OoO0O00
 if 72 - 72: II111iiii % i11iIiiIii + OoOoOO00 / I1Ii111 - i11iIiiIii
 if 39 - 39: i11iIiiIii - OOooOOo / OoO0O00 * OoOoOO00 / IiII
 if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 / Ii1I / II111iiii
 if 56 - 56: OOooOOo * iII111i / Ii1I
 if 9 - 9: I1ii11iIi11i * i11iIiiIii / I1Ii111 + iIii1I11I1II1
 if 1 - 1: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / oO0o
 if 73 - 73: iII111i
 III1 = dest . print_address_no_iid ( )
 if ( III1 . find ( "::ffff:" ) != - 1 and III1 . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : IIiiIII = lisp_sockets [ 0 ]
  if ( IIiiIII == None ) :
   IIiiIII = lisp_sockets [ 0 ]
   III1 = III1 . split ( "::ffff:" ) [ - 1 ]
   if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo
   if 45 - 45: oO0o % O0 / O0
   if 98 - 98: I1Ii111
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + III1 , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 58 - 58: OOooOOo
 if 6 - 6: I1ii11iIi11i
 if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
 if 18 - 18: ooOoO0o
 I11II1I = ( LISP_RLOC_PROBE_TTL == 255 )
 if ( I11II1I ) :
  oOo0O0OO0 = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  I11II1I = ( oOo0O0OO0 in [ 0x12 , 0x28 ] )
  if ( I11II1I ) : lisp_set_ttl ( IIiiIII , LISP_RLOC_PROBE_TTL )
  if 62 - 62: OoooooooOO % OoO0O00 / Ii1I . II111iiii / I1Ii111
  if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
 try : IIiiIII . sendto ( packet , ( III1 , port ) )
 except socket . error , o0OoO00 :
  lprint ( "socket.sendto() failed: {}" . format ( o0OoO00 ) )
  if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
  if 81 - 81: i11iIiiIii - II111iiii + I11i
  if 52 - 52: II111iiii
  if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
  if 26 - 26: I1ii11iIi11i - OoO0O00
 if ( I11II1I ) : lisp_set_ttl ( IIiiIII , 64 )
 return
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
 if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
 if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
 if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
 if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
 if 15 - 15: Ii1I
 if 29 - 29: I11i / I1IiiI / OoooooooOO . OoOoOO00 / I11i . I1Ii111
 if 69 - 69: O0 * OoOoOO00 + o0oOOo0O0Ooo + I1IiiI % iII111i . OoooooooOO
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 45 - 45: I1Ii111 + oO0o - o0oOOo0O0Ooo - OoOoOO00 + I1IiiI / II111iiii
 if 46 - 46: II111iiii . iIii1I11I1II1
 if 62 - 62: I1ii11iIi11i % i1IIi % I1Ii111 * ooOoO0o % OOooOOo + I1IiiI
 if 100 - 100: II111iiii - o0oOOo0O0Ooo * OoooooooOO . ooOoO0o / II111iiii / oO0o
 if 43 - 43: iIii1I11I1II1 + ooOoO0o * iII111i + iIii1I11I1II1 . I1Ii111
 OoO00oO0oOoO0 = total_length - len ( packet )
 if ( OoO00oO0oOoO0 == 0 ) : return ( [ True , packet ] )
 if 87 - 87: I1Ii111
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 47 - 47: II111iiii + I1IiiI . Oo0Ooo / iIii1I11I1II1
 if 14 - 14: i1IIi / OoO0O00 / iII111i % I1Ii111
 if 72 - 72: OoO0O00 . II111iiii - IiII + IiII + iIii1I11I1II1 % oO0o
 if 21 - 21: iII111i + OoOoOO00 - i11iIiiIii % O0 + OOooOOo
 if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
 iI1 = OoO00oO0oOoO0
 while ( iI1 > 0 ) :
  try : o0OOOoOo0oO = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 94 - 94: IiII
  o0OOOoOo0oO = o0OOOoOo0oO [ 0 ]
  if 69 - 69: I1Ii111 . I1Ii111
  if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
  if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
  if 8 - 8: iII111i % o0oOOo0O0Ooo
  if 87 - 87: Ii1I % I11i / I1Ii111
  if ( o0OOOoOo0oO . find ( "packet@" ) == 0 ) :
   iIi111 = o0OOOoOo0oO . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( o0OOOoOo0oO ) ,
   # I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
 iIi111 [ 1 ] if len ( iIi111 ) > 2 else "?" )
   return ( [ False , o0OOOoOo0oO ] )
   if 38 - 38: i1IIi
   if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
  iI1 -= len ( o0OOOoOo0oO )
  packet += o0OOOoOo0oO
  if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( o0OOOoOo0oO ) , total_length , source ) )
  if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
  if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
 return ( [ True , packet ] )
 if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
 if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
 if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
 if 2 - 2: OOooOOo / I11i * I11i + I11i / O0 - OOooOOo
 if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
 if 68 - 68: iII111i / OOooOOo
 if 28 - 28: II111iiii
 if 49 - 49: I1ii11iIi11i
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 ii1i1II = ""
 for o0OOOoOo0oO in payload : ii1i1II += o0OOOoOo0oO + "\x40"
 return ( ii1i1II [ : - 1 ] )
 if 33 - 33: iIii1I11I1II1
 if 72 - 72: I1ii11iIi11i * i11iIiiIii
 if 12 - 12: O0 - iIii1I11I1II1 % Oo0Ooo / O0 - IiII
 if 55 - 55: OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * i11iIiiIii + oO0o
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
 if 82 - 82: iIii1I11I1II1 / i1IIi * I1IiiI . i11iIiiIii
 if 56 - 56: Ii1I * I1IiiI / ooOoO0o * II111iiii
 if 51 - 51: i1IIi . oO0o % OOooOOo
 if 90 - 90: OoooooooOO + iII111i / iIii1I11I1II1
 if 12 - 12: OoooooooOO
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 9 - 9: O0 / O0 / I1IiiI - oO0o . ooOoO0o
  if 6 - 6: O0 - OoO0O00 + OoooooooOO % iIii1I11I1II1
  if 58 - 58: i11iIiiIii * OOooOOo . Oo0Ooo / iII111i - i1IIi
  if 45 - 45: Ii1I
  try : O0000oO = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
  if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
  if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
  if 86 - 86: iII111i / i1IIi % Oo0Ooo
  if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
  if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
  if ( internal == False ) :
   ii1i1II = O0000oO [ 0 ]
   O0O00Oo = lisp_convert_6to4 ( O0000oO [ 1 ] [ 0 ] )
   IIi1I1iII111 = O0000oO [ 1 ] [ 1 ]
   if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
   if ( IIi1I1iII111 == LISP_DATA_PORT ) :
    IIii = lisp_data_plane_logging
    Oo = lisp_format_packet ( ii1i1II [ 0 : 60 ] ) + " ..."
   else :
    IIii = True
    Oo = lisp_format_packet ( ii1i1II )
    if 50 - 50: i11iIiiIii / i1IIi + i1IIi / Ii1I . o0oOOo0O0Ooo + OoOoOO00
    if 29 - 29: I1ii11iIi11i % OOooOOo - I1IiiI / iII111i % OoOoOO00
   if ( IIii ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( ii1i1II ) , bold ( "from " + O0O00Oo , False ) , IIi1I1iII111 ,
 Oo ) )
    if 15 - 15: o0oOOo0O0Ooo / OOooOOo % I1IiiI - I1IiiI / i1IIi * Ii1I
   return ( [ "packet" , O0O00Oo , IIi1I1iII111 , ii1i1II ] )
   if 90 - 90: ooOoO0o % o0oOOo0O0Ooo * Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo * OoOoOO00
   if 40 - 40: iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
   if 37 - 37: Ii1I + o0oOOo0O0Ooo
   if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
   if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
   if 8 - 8: I11i - I11i % IiII
  Ii1 = False
  Ii11i1IiII = O0000oO [ 0 ]
  OOIi = False
  if 34 - 34: Oo0Ooo + I11i / i1IIi - o0oOOo0O0Ooo
  while ( Ii1 == False ) :
   Ii11i1IiII = Ii11i1IiII . split ( "@" )
   if 26 - 26: iII111i % OoOoOO00 / iII111i * IiII / oO0o % I1IiiI
   if ( len ( Ii11i1IiII ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( Ii11i1IiII [ 0 ] ) )
    if 100 - 100: OoO0O00 + i11iIiiIii + IiII * ooOoO0o . iIii1I11I1II1 - OoOoOO00
    OOIi = True
    break
    if 15 - 15: Ii1I - OoOoOO00
    if 27 - 27: O0
   O0o0oO0 = Ii11i1IiII [ 0 ]
   try :
    IIi1ii1II1II = int ( Ii11i1IiII [ 1 ] )
   except :
    ii11iiIii1 = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( ii11iiIii1 , O0000oO ) )
    OOIi = True
    break
    if 97 - 97: OOooOOo . OoOoOO00 / I11i - IiII - iIii1I11I1II1
   O0O00Oo = Ii11i1IiII [ 2 ]
   IIi1I1iII111 = Ii11i1IiII [ 3 ]
   if 82 - 82: II111iiii + OoO0O00 % iIii1I11I1II1 / O0
   if 75 - 75: OOooOOo * OoO0O00 + OoooooooOO + i11iIiiIii . OoO0O00
   if 94 - 94: I11i * ooOoO0o . I1IiiI / Ii1I - I1IiiI % OoooooooOO
   if 32 - 32: OoO0O00
   if 22 - 22: II111iiii . I11i
   if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
   if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
   if 94 - 94: OOooOOo / IiII
   if ( len ( Ii11i1IiII ) > 5 ) :
    ii1i1II = lisp_bit_stuff ( Ii11i1IiII [ 4 : : ] )
   else :
    ii1i1II = Ii11i1IiII [ 4 ]
    if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
    if 22 - 22: OoOoOO00 - Oo0Ooo
    if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
    if 33 - 33: I11i + O0
    if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
    if 68 - 68: O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
   Ii1 , ii1i1II = lisp_receive_segments ( lisp_socket , ii1i1II ,
 O0O00Oo , IIi1ii1II1II )
   if ( ii1i1II == None ) : return ( [ "" , "" , "" , "" ] )
   if 12 - 12: II111iiii + I11i
   if 9 - 9: I1ii11iIi11i
   if 51 - 51: I1ii11iIi11i
   if 37 - 37: I1IiiI % I1Ii111
   if 22 - 22: o0oOOo0O0Ooo % OOooOOo - I11i + ooOoO0o / OOooOOo
   if ( Ii1 == False ) :
    Ii11i1IiII = ii1i1II
    continue
    if 98 - 98: I11i * O0 + IiII - oO0o
    if 35 - 35: OoooooooOO * Ii1I
   if ( IIi1I1iII111 == "" ) : IIi1I1iII111 = "no-port"
   if ( O0o0oO0 == "command" and lisp_i_am_core == False ) :
    OO000o00 = ii1i1II . find ( " {" )
    O0oOOOOoOO = ii1i1II if OO000o00 == - 1 else ii1i1II [ : OO000o00 ]
    O0oOOOOoOO = ": '" + O0oOOOOoOO + "'"
   else :
    O0oOOOOoOO = ""
    if 72 - 72: iII111i * oO0o
    if 37 - 37: I1IiiI
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( ii1i1II ) , bold ( "from " + O0O00Oo , False ) , IIi1I1iII111 , O0o0oO0 ,
 O0oOOOOoOO if ( O0o0oO0 in [ "command" , "api" ] ) else ": ... " if ( O0o0oO0 == "data-packet" ) else ": " + lisp_format_packet ( ii1i1II ) ) )
   if 76 - 76: iIii1I11I1II1 . iII111i % ooOoO0o / iII111i + I11i
   if 85 - 85: i11iIiiIii
   if 25 - 25: oO0o . OoO0O00 % Ii1I % Ii1I
   if 94 - 94: iII111i . Ii1I
   if 71 - 71: o0oOOo0O0Ooo * II111iiii / OOooOOo . OoO0O00
  if ( OOIi ) : continue
  return ( [ O0o0oO0 , O0O00Oo , IIi1I1iII111 , ii1i1II ] )
  if 73 - 73: I1Ii111 * OoO0O00 / OoOoOO00 . II111iiii
  if 87 - 87: OoO0O00 + Oo0Ooo + O0 % OoooooooOO - iIii1I11I1II1
  if 100 - 100: Oo0Ooo + IiII
  if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1
  if 19 - 19: ooOoO0o + i1IIi / Oo0Ooo * II111iiii * I1Ii111 / ooOoO0o
  if 23 - 23: I1Ii111
  if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
  if 75 - 75: I11i . Ii1I / I1ii11iIi11i
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 o00O0O0oOo0 = False
 if 13 - 13: OoO0O00 + Ii1I % iIii1I11I1II1 / Ii1I
 iIIIIII = lisp_control_header ( )
 if ( iIIIIII . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( o00O0O0oOo0 )
  if 86 - 86: OoooooooOO % Ii1I
  if 21 - 21: iII111i
  if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
  if 75 - 75: OoooooooOO
  if 24 - 24: oO0o % iII111i - II111iiii / Ii1I + O0
 i1iiiI1I = source
 if ( source . find ( "lisp" ) == - 1 ) :
  o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  o0 . string_to_afi ( source )
  o0 . store_address ( source )
  source = o0
  if 76 - 76: I1Ii111 . Oo0Ooo - ooOoO0o . II111iiii - iII111i
  if 36 - 36: iIii1I11I1II1 % Oo0Ooo
 if ( iIIIIII . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl )
  if 67 - 67: oO0o / II111iiii . I11i / oO0o
 elif ( iIIIIII . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl )
  if 46 - 46: oO0o * Oo0Ooo - I11i / iIii1I11I1II1
 elif ( iIIIIII . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 100 - 100: i11iIiiIii % oO0o
 elif ( iIIIIII . type == LISP_MAP_NOTIFY ) :
  if ( i1iiiI1I == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  else :
   if ( lisp_is_running ( "lisp-rtr" ) ) :
    lisp_process_multicast_map_notify ( packet , source )
    if 62 - 62: OOooOOo * i1IIi - OOooOOo / i11iIiiIii
   lisp_process_map_notify ( lisp_sockets , packet , source )
   if 17 - 17: I1ii11iIi11i + ooOoO0o % Ii1I % OOooOOo
   if 73 - 73: i11iIiiIii
 elif ( iIIIIII . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 44 - 44: o0oOOo0O0Ooo % Ii1I - OoOoOO00 + OoOoOO00 * IiII + iII111i
 elif ( iIIIIII . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 58 - 58: I1ii11iIi11i / oO0o + i11iIiiIii * o0oOOo0O0Ooo
 elif ( iIIIIII . type == LISP_NAT_INFO and iIIIIII . is_info_reply ( ) ) :
  OoOO0OOOO0 , oOoOoO0Oo0oo , o00O0O0oOo0 = lisp_process_info_reply ( source , packet , True )
  if 19 - 19: OoOoOO00
 elif ( iIIIIII . type == LISP_NAT_INFO and iIIIIII . is_info_reply ( ) == False ) :
  oOo0O = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , oOo0O , udp_sport ,
 None )
  if 17 - 17: Oo0Ooo
 elif ( iIIIIII . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 76 - 76: II111iiii % I1ii11iIi11i
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( iIIIIII . type ) )
  if 99 - 99: oO0o - I1Ii111
 return ( o00O0O0oOo0 )
 if 29 - 29: I1IiiI - I11i
 if 42 - 42: Oo0Ooo - O0 . OoOoOO00
 if 4 - 4: IiII
 if 2 - 2: iII111i
 if 47 - 47: i1IIi % I11i
 if 17 - 17: OoOoOO00 - iII111i % I11i / o0oOOo0O0Ooo / II111iiii
 if 22 - 22: Oo0Ooo + I1ii11iIi11i % i11iIiiIii . OoO0O00 - I11i % I11i
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl ) :
 if 21 - 21: I1IiiI . OoO0O00 * IiII % OoooooooOO - Oo0Ooo + Oo0Ooo
 iIiiI11II11 = bold ( "RLOC-probe" , False )
 if 94 - 94: ooOoO0o
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( iIiiI11II11 ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
  if 95 - 95: II111iiii
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( iIiiI11II11 ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 76 - 76: OoO0O00 % iII111i * OoOoOO00 / ooOoO0o / i1IIi
  if 45 - 45: Ii1I . I11i * I1Ii111 . i11iIiiIii
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( iIiiI11II11 ) )
 return
 if 34 - 34: O0 * o0oOOo0O0Ooo / IiII
 if 75 - 75: I1Ii111 - i1IIi - OoO0O00
 if 25 - 25: iII111i . o0oOOo0O0Ooo
 if 62 - 62: I11i + i1IIi . I1ii11iIi11i - I1ii11iIi11i
 if 68 - 68: ooOoO0o % OoooooooOO
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 94 - 94: Oo0Ooo * o0oOOo0O0Ooo
 if 60 - 60: iII111i . OOooOOo
 if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
 if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
 if 19 - 19: I1IiiI
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 99 - 99: OOooOOo - OOooOOo
 if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
 if 83 - 83: o0oOOo0O0Ooo
 if 23 - 23: o0oOOo0O0Ooo . I11i
 if 67 - 67: iII111i
 if 52 - 52: IiII . OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / IiII . OoooooooOO . Oo0Ooo / ooOoO0o + O0
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , rloc_probe ,
 keys , enc , auth , mr_ttl = - 1 ) :
 iIiiIIiI1I = lisp_map_reply ( )
 iIiiIIiI1I . rloc_probe = rloc_probe
 iIiiIIiI1I . echo_nonce_capable = enc
 iIiiIIiI1I . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 iIiiIIiI1I . record_count = 1
 iIiiIIiI1I . nonce = nonce
 ii1i1II = iIiiIIiI1I . encode ( )
 iIiiIIiI1I . print_map_reply ( )
 if 88 - 88: OOooOOo - I1ii11iIi11i % iII111i
 OOoo = lisp_eid_record ( )
 OOoo . rloc_count = len ( rloc_set )
 OOoo . authoritative = auth
 OOoo . record_ttl = ttl
 OOoo . action = action
 OOoo . eid = eid
 OOoo . group = group
 if 32 - 32: i1IIi - iII111i . I1ii11iIi11i * Ii1I % Oo0Ooo * OoOoOO00
 ii1i1II += OOoo . encode ( )
 OOoo . print_record ( "  " , False )
 if 92 - 92: OoO0O00
 Ii1i = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
 for IiIIIi in rloc_set :
  O0000O00O00OO = lisp_rloc_record ( )
  oOo0O = IiIIIi . rloc . print_address_no_iid ( )
  if ( oOo0O in Ii1i ) :
   O0000O00O00OO . local_bit = True
   O0000O00O00OO . probe_bit = rloc_probe
   O0000O00O00OO . keys = keys
   if ( IiIIIi . priority == 254 and lisp_i_am_rtr ) :
    O0000O00O00OO . rloc_name = "RTR"
    if 10 - 10: I1ii11iIi11i
    if 5 - 5: IiII - iIii1I11I1II1 % oO0o % i1IIi
  O0000O00O00OO . store_rloc_entry ( IiIIIi )
  O0000O00O00OO . reach_bit = True
  O0000O00O00OO . print_record ( "    " )
  ii1i1II += O0000O00O00OO . encode ( )
  if 68 - 68: OoooooooOO * Oo0Ooo / o0oOOo0O0Ooo * I11i + OoO0O00 . OoooooooOO
 return ( ii1i1II )
 if 12 - 12: oO0o - I1ii11iIi11i
 if 69 - 69: iII111i * IiII * oO0o % OoO0O00 - o0oOOo0O0Ooo
 if 97 - 97: O0 + i11iIiiIii . i1IIi
 if 43 - 43: II111iiii + OOooOOo . i11iIiiIii - II111iiii
 if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
 if 26 - 26: i1IIi - I1IiiI + IiII / OoO0O00 . I1ii11iIi11i
 if 82 - 82: I1Ii111 % iII111i . OoOoOO00 % OoO0O00 + I1ii11iIi11i
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 OOOOo0ooOoOO = lisp_map_referral ( )
 OOOOo0ooOoOO . record_count = 1
 OOOOo0ooOoOO . nonce = nonce
 ii1i1II = OOOOo0ooOoOO . encode ( )
 OOOOo0ooOoOO . print_map_referral ( )
 if 86 - 86: OoooooooOO * OOooOOo * II111iiii - OoO0O00
 OOoo = lisp_eid_record ( )
 if 40 - 40: oO0o
 i1ii1I = 0
 if ( ddt_entry == None ) :
  OOoo . eid = eid
  OOoo . group = group
 else :
  i1ii1I = len ( ddt_entry . delegation_set )
  OOoo . eid = ddt_entry . eid
  OOoo . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 47 - 47: IiII % I1IiiI
 OOoo . rloc_count = i1ii1I
 OOoo . authoritative = True
 if 91 - 91: Ii1I
 if 69 - 69: iII111i
 if 96 - 96: Ii1I
 if 39 - 39: OoO0O00 - I1IiiI % II111iiii - IiII * I1ii11iIi11i
 if 64 - 64: OOooOOo + Oo0Ooo . OoOoOO00 . OOooOOo + i11iIiiIii
 iiiiIIiiII1Iii1 = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( i1ii1I == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   I11i1ii11 = ddt_entry . delegation_set [ 0 ]
   if ( I11i1ii11 . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 7 - 7: ooOoO0o * I11i / iIii1I11I1II1
   if ( I11i1ii11 . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 15 - 15: OoooooooOO / iII111i
    if 40 - 40: o0oOOo0O0Ooo
    if 75 - 75: oO0o - OoOoOO00 * ooOoO0o . O0
    if 78 - 78: Oo0Ooo
    if 74 - 74: O0 / I11i
    if 52 - 52: I1IiiI + oO0o * II111iiii
    if 15 - 15: I11i
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : iiiiIIiiII1Iii1 = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  iiiiIIiiII1Iii1 = ( lisp_i_am_ms and I11i1ii11 . is_ms_peer ( ) == False )
  if 72 - 72: O0
  if 15 - 15: II111iiii / I11i % II111iiii % Ii1I % i11iIiiIii / I1Ii111
 OOoo . action = action
 OOoo . ddt_incomplete = iiiiIIiiII1Iii1
 OOoo . record_ttl = ttl
 if 93 - 93: OOooOOo / OoooooooOO % iII111i
 ii1i1II += OOoo . encode ( )
 OOoo . print_record ( "  " , True )
 if 47 - 47: o0oOOo0O0Ooo - I1IiiI % O0 % I1Ii111 . O0 . OoOoOO00
 if ( i1ii1I == 0 ) : return ( ii1i1II )
 if 95 - 95: o0oOOo0O0Ooo * OOooOOo - iII111i * OoooooooOO - ooOoO0o / I1IiiI
 for I11i1ii11 in ddt_entry . delegation_set :
  O0000O00O00OO = lisp_rloc_record ( )
  O0000O00O00OO . rloc = I11i1ii11 . delegate_address
  O0000O00O00OO . priority = I11i1ii11 . priority
  O0000O00O00OO . weight = I11i1ii11 . weight
  O0000O00O00OO . mpriority = 255
  O0000O00O00OO . mweight = 0
  O0000O00O00OO . reach_bit = True
  ii1i1II += O0000O00O00OO . encode ( )
  O0000O00O00OO . print_record ( "    " )
  if 47 - 47: OoO0O00 % I1IiiI / OoOoOO00 - I1Ii111 / I1IiiI
 return ( ii1i1II )
 if 13 - 13: o0oOOo0O0Ooo % ooOoO0o
 if 15 - 15: iII111i * I1IiiI . iIii1I11I1II1 % I1IiiI / O0
 if 47 - 47: OoooooooOO - i11iIiiIii . I1IiiI / i1IIi
 if 74 - 74: OoooooooOO * ooOoO0o
 if 45 - 45: Oo0Ooo + iIii1I11I1II1 . o0oOOo0O0Ooo
 if 50 - 50: o0oOOo0O0Ooo % O0
 if 67 - 67: OoOoOO00
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 21 - 21: I11i % Oo0Ooo + Oo0Ooo / iIii1I11I1II1 % iIii1I11I1II1
 if ( map_request . target_group . is_null ( ) ) :
  o00o0oOo0o0O = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  o00o0oOo0o0O = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( o00o0oOo0o0O ) : o00o0oOo0o0O = o00o0oOo0o0O . lookup_source_cache ( map_request . target_eid , False )
  if 60 - 60: I1IiiI + I1IiiI % i1IIi * oO0o - iII111i + OOooOOo
 iiI1Ii1I = map_request . print_prefix ( )
 if 37 - 37: II111iiii / I1ii11iIi11i
 if ( o00o0oOo0o0O == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( iiI1Ii1I , False ) ) )
  if 46 - 46: OoOoOO00 * Ii1I . Ii1I % I1IiiI
  return
  if 30 - 30: I11i + Oo0Ooo - OoO0O00 - O0
  if 54 - 54: OoOoOO00 * I1Ii111 + iII111i * iIii1I11I1II1
 IiI1ii1 = o00o0oOo0o0O . print_eid_tuple ( )
 if 59 - 59: I1Ii111
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( IiI1ii1 , False ) , green ( iiI1Ii1I , False ) ) )
 if 22 - 22: OoooooooOO
 if 88 - 88: I1Ii111 - OoO0O00
 if 29 - 29: I1IiiI . I1Ii111
 if 74 - 74: Oo0Ooo / OoOoOO00 + OoOoOO00 % i11iIiiIii . OoO0O00 + ooOoO0o
 if 77 - 77: ooOoO0o . I11i + OoooooooOO
 O00o00O0OO0 = map_request . itr_rlocs [ 0 ]
 if ( O00o00O0OO0 . is_private_address ( ) and lisp_nat_traversal ) :
  O00o00O0OO0 = source
  if 77 - 77: II111iiii
  if 80 - 80: i11iIiiIii / Ii1I / ooOoO0o - OoO0O00
 OO00OO = map_request . nonce
 II1iiIiii1iI = lisp_nonce_echoing
 O0000 = map_request . keys
 if 82 - 82: I1ii11iIi11i * iIii1I11I1II1
 o00o0oOo0o0O . map_replies_sent += 1
 if 53 - 53: OoO0O00 * O0
 ii1i1II = lisp_build_map_reply ( o00o0oOo0o0O . eid , o00o0oOo0o0O . group , o00o0oOo0o0O . rloc_set , OO00OO ,
 LISP_NO_ACTION , 1440 , map_request . rloc_probe , O0000 , II1iiIiii1iI , True , ttl )
 if 97 - 97: Oo0Ooo . i1IIi
 if 56 - 56: Ii1I
 if 2 - 2: i1IIi % oO0o + O0 - OoO0O00
 if 34 - 34: ooOoO0o + oO0o - Oo0Ooo
 if 94 - 94: OoOoOO00 - Ii1I
 if 93 - 93: OoooooooOO * OOooOOo
 if 34 - 34: OoOoOO00 + OoOoOO00 - Oo0Ooo
 if 21 - 21: i1IIi + O0 % I1ii11iIi11i / i1IIi - iII111i
 if 56 - 56: Ii1I - Ii1I / OoooooooOO * i11iIiiIii - iII111i % iIii1I11I1II1
 if 87 - 87: O0
 if 23 - 23: I1IiiI
 if 97 - 97: OoooooooOO / ooOoO0o
 if 50 - 50: O0
 if 100 - 100: IiII . Oo0Ooo - Oo0Ooo % iII111i
 if 83 - 83: i11iIiiIii % ooOoO0o * I1ii11iIi11i - ooOoO0o . OoOoOO00
 if 54 - 54: oO0o + OoOoOO00 - OoOoOO00 / I1ii11iIi11i * i11iIiiIii + OoooooooOO
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  i1IiI111IiiI1 = ( O00o00O0OO0 . is_private_address ( ) == False )
  O0O0 = O00o00O0OO0 . print_address_no_iid ( )
  if ( ( i1IiI111IiiI1 and lisp_rtr_list . has_key ( O0O0 ) ) or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , O00o00O0OO0 , None , ii1i1II )
   return
   if 20 - 20: OOooOOo / O0
   if 51 - 51: ooOoO0o - I1Ii111 * oO0o
   if 47 - 47: Oo0Ooo % OoO0O00 * Ii1I / OoOoOO00
   if 1 - 1: I1IiiI
   if 68 - 68: ooOoO0o
   if 68 - 68: I11i % IiII
 lisp_send_map_reply ( lisp_sockets , ii1i1II , O00o00O0OO0 , sport )
 return
 if 1 - 1: I1IiiI + OOooOOo - OOooOOo * O0 + o0oOOo0O0Ooo * OOooOOo
 if 48 - 48: ooOoO0o - iII111i + I1ii11iIi11i * I1Ii111 % ooOoO0o * OoO0O00
 if 28 - 28: i1IIi / iII111i + OOooOOo
 if 89 - 89: Oo0Ooo + II111iiii * OoO0O00 + Oo0Ooo % II111iiii
 if 59 - 59: O0 + Oo0Ooo
 if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
 if 50 - 50: I11i . I11i % I1IiiI - i1IIi
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 63 - 63: OoO0O00 . iII111i
 if 28 - 28: ooOoO0o . Oo0Ooo - OoooooooOO - I1Ii111 - OoooooooOO - oO0o
 if 25 - 25: I11i / I1Ii111 . i11iIiiIii % i1IIi
 if 21 - 21: O0 * IiII . iII111i / iII111i % i11iIiiIii / I11i
 O00o00O0OO0 = map_request . itr_rlocs [ 0 ]
 if ( O00o00O0OO0 . is_private_address ( ) ) : O00o00O0OO0 = source
 OO00OO = map_request . nonce
 if 15 - 15: o0oOOo0O0Ooo / OoO0O00 - i1IIi
 I111o0oooO00o0 = map_request . target_eid
 oOoooOOO0o0 = map_request . target_group
 if 30 - 30: OoO0O00 / ooOoO0o % ooOoO0o
 iio0OOoO0 = [ ]
 for O0ooo in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( O0ooo == None ) : continue
  OooO0ooO0o0OO = lisp_rloc ( )
  OooO0ooO0o0OO . rloc . copy_address ( O0ooo )
  OooO0ooO0o0OO . priority = 254
  iio0OOoO0 . append ( OooO0ooO0o0OO )
  if 49 - 49: iII111i
  if 12 - 12: Oo0Ooo / II111iiii * OoOoOO00 * i1IIi - i1IIi / iII111i
 II1iiIiii1iI = lisp_nonce_echoing
 O0000 = map_request . keys
 if 43 - 43: I1IiiI / IiII
 ii1i1II = lisp_build_map_reply ( I111o0oooO00o0 , oOoooOOO0o0 , iio0OOoO0 , OO00OO , LISP_NO_ACTION ,
 1440 , True , O0000 , II1iiIiii1iI , True , ttl )
 lisp_send_map_reply ( lisp_sockets , ii1i1II , O00o00O0OO0 , sport )
 return
 if 38 - 38: I1ii11iIi11i + i11iIiiIii * I1IiiI % oO0o % OoooooooOO
 if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
 if 69 - 69: OoooooooOO
 if 19 - 19: O0 + iIii1I11I1II1 / OoOoOO00 / oO0o + II111iiii - OOooOOo
 if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
 if 81 - 81: iIii1I11I1II1 - OoO0O00 . i11iIiiIii
 if 4 - 4: o0oOOo0O0Ooo / OoO0O00 - I11i
 if 52 - 52: II111iiii . iII111i
 if 36 - 36: I1IiiI * II111iiii
 if 68 - 68: oO0o * o0oOOo0O0Ooo + OoooooooOO - I1ii11iIi11i * i1IIi % OOooOOo
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 iio0OOoO0 = target_site_eid . registered_rlocs
 if 39 - 39: I1Ii111 / I11i + oO0o / I1Ii111 % IiII * I1ii11iIi11i
 OOo00oOOo0OOO = lisp_site_eid_lookup ( seid , group , False )
 if ( OOo00oOOo0OOO == None ) : return ( iio0OOoO0 )
 if 6 - 6: iII111i . IiII - I1ii11iIi11i - Oo0Ooo - i1IIi
 if 96 - 96: i1IIi . Oo0Ooo * i11iIiiIii / OoO0O00 / oO0o
 if 12 - 12: iII111i % OOooOOo % i1IIi
 if 17 - 17: IiII
 o0oi1 = None
 i11i1i11ii11I = [ ]
 for IiIIIi in iio0OOoO0 :
  if ( IiIIIi . is_rtr ( ) ) : continue
  if ( IiIIIi . rloc . is_private_address ( ) ) :
   OOO0 = copy . deepcopy ( IiIIIi )
   i11i1i11ii11I . append ( OOO0 )
   continue
   if 61 - 61: o0oOOo0O0Ooo - II111iiii % oO0o % o0oOOo0O0Ooo / IiII . o0oOOo0O0Ooo
  o0oi1 = IiIIIi
  break
  if 49 - 49: o0oOOo0O0Ooo / I1Ii111 . I1ii11iIi11i * O0 * IiII + Oo0Ooo
 if ( o0oi1 == None ) : return ( iio0OOoO0 )
 o0oi1 = o0oi1 . rloc . print_address_no_iid ( )
 if 47 - 47: o0oOOo0O0Ooo - I1IiiI % I1IiiI
 if 5 - 5: o0oOOo0O0Ooo
 if 58 - 58: oO0o * II111iiii * Oo0Ooo - I1IiiI % iII111i
 if 77 - 77: I11i / iII111i * o0oOOo0O0Ooo % iIii1I11I1II1
 iiiI1 = None
 for IiIIIi in OOo00oOOo0OOO . registered_rlocs :
  if ( IiIIIi . is_rtr ( ) ) : continue
  if ( IiIIIi . rloc . is_private_address ( ) ) : continue
  iiiI1 = IiIIIi
  break
  if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
 if ( iiiI1 == None ) : return ( iio0OOoO0 )
 iiiI1 = iiiI1 . rloc . print_address_no_iid ( )
 if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
 if 77 - 77: OoOoOO00 + IiII + Oo0Ooo
 if 88 - 88: i1IIi
 if 45 - 45: iII111i % I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
 I11 = target_site_eid . site_id
 if ( I11 == 0 ) :
  if ( iiiI1 == o0oi1 ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( o0oi1 ) )
   if 55 - 55: OoO0O00 % IiII
   return ( i11i1i11ii11I )
   if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
  return ( iio0OOoO0 )
  if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
  if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
  if 63 - 63: I1Ii111 + iII111i
  if 6 - 6: I1ii11iIi11i + Ii1I
  if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
  if 97 - 97: ooOoO0o + OOooOOo
  if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
 if ( I11 == OOo00oOOo0OOO . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( I11 ) )
  return ( i11i1i11ii11I )
  if 6 - 6: Oo0Ooo + I1IiiI
 return ( iio0OOoO0 )
 if 48 - 48: oO0o . I1ii11iIi11i
 if 59 - 59: IiII - Ii1I
 if 62 - 62: OOooOOo * o0oOOo0O0Ooo + IiII * o0oOOo0O0Ooo * i11iIiiIii - O0
 if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
 if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
 if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
 if 53 - 53: o0oOOo0O0Ooo * Ii1I
 if 42 - 42: I11i + iII111i / iIii1I11I1II1
 if 1 - 1: O0 - II111iiii
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 oo0Oo = [ ]
 iio0OOoO0 = [ ]
 if 3 - 3: Ii1I - Ii1I % I1ii11iIi11i
 if 44 - 44: OOooOOo - o0oOOo0O0Ooo
 if 69 - 69: IiII + I1ii11iIi11i / o0oOOo0O0Ooo / OOooOOo
 if 31 - 31: oO0o + I1ii11iIi11i * i1IIi % I1IiiI % I1IiiI + iIii1I11I1II1
 if 62 - 62: OoooooooOO
 if 38 - 38: iII111i % iII111i * ooOoO0o / OoO0O00 + ooOoO0o
 O0o = False
 IIIOOo0o = False
 for IiIIIi in registered_rloc_set :
  if ( IiIIIi . priority != 254 ) : continue
  IIIOOo0o |= True
  if ( IiIIIi . rloc . is_exact_match ( mr_source ) == False ) : continue
  O0o = True
  break
  if 21 - 21: II111iiii - OOooOOo * O0
  if 52 - 52: IiII / I1IiiI - o0oOOo0O0Ooo
  if 6 - 6: I1ii11iIi11i / OOooOOo
  if 92 - 92: OOooOOo % OOooOOo
  if 67 - 67: iII111i + I1ii11iIi11i - IiII . iII111i + iIii1I11I1II1
  if 40 - 40: II111iiii - oO0o / OoO0O00 / OoOoOO00 / Oo0Ooo
  if 11 - 11: IiII + OoooooooOO % OoooooooOO . o0oOOo0O0Ooo * OoOoOO00 + O0
 if ( IIIOOo0o == False ) : return ( registered_rloc_set )
 if 37 - 37: I1IiiI
 if 64 - 64: ooOoO0o
 if 35 - 35: I1IiiI . iIii1I11I1II1 + IiII / i11iIiiIii - II111iiii . OoooooooOO
 if 19 - 19: IiII - OoOoOO00
 if 43 - 43: IiII / OOooOOo % II111iiii . o0oOOo0O0Ooo / i11iIiiIii
 if 5 - 5: oO0o % iII111i . Oo0Ooo . O0 . OoOoOO00 / iII111i
 if 78 - 78: Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . OoO0O00 - ooOoO0o
 if 81 - 81: o0oOOo0O0Ooo * OoooooooOO
 if 32 - 32: OoOoOO00 - I11i * i11iIiiIii . I1ii11iIi11i . IiII . iIii1I11I1II1
 if 41 - 41: iII111i / OoOoOO00 / OoO0O00 / ooOoO0o
 iiIII1 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 18 - 18: OoO0O00 . Oo0Ooo
 if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
 if 14 - 14: i1IIi
 if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
 if 36 - 36: OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
 for IiIIIi in registered_rloc_set :
  if ( iiIII1 and IiIIIi . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and IiIIIi . priority == 255 ) : continue
  if ( multicast and IiIIIi . mpriority == 255 ) : continue
  if ( IiIIIi . priority == 254 ) :
   oo0Oo . append ( IiIIIi )
  else :
   iio0OOoO0 . append ( IiIIIi )
   if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
   if 23 - 23: oO0o / o0oOOo0O0Ooo + I11i % IiII * OoO0O00
   if 48 - 48: OoO0O00
   if 30 - 30: iIii1I11I1II1
   if 53 - 53: II111iiii
   if 40 - 40: Ii1I % oO0o
 if ( O0o ) : return ( iio0OOoO0 )
 if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
 if 78 - 78: oO0o
 if 20 - 20: i1IIi + i1IIi * i1IIi
 if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
 if 27 - 27: oO0o + Ii1I . i11iIiiIii
 if 97 - 97: iII111i . I1IiiI
 if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
 if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
 if 45 - 45: oO0o
 if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
 iio0OOoO0 = [ ]
 for IiIIIi in registered_rloc_set :
  if ( IiIIIi . rloc . is_private_address ( ) ) : iio0OOoO0 . append ( IiIIIi )
  if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
 iio0OOoO0 += oo0Oo
 return ( iio0OOoO0 )
 if 100 - 100: i11iIiiIii - iII111i - I11i
 if 5 - 5: oO0o % IiII * iII111i
 if 98 - 98: iII111i / OOooOOo + IiII
 if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
 if 82 - 82: ooOoO0o % OOooOOo % Ii1I
 if 82 - 82: I1ii11iIi11i
 if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
 if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
 if 53 - 53: OOooOOo * OoOoOO00 % iII111i
 if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 OooOooOO0000 = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 OooOooOO0000 . add ( reply_eid )
 return
 if 15 - 15: iII111i % Oo0Ooo * i1IIi
 if 93 - 93: OOooOOo * I11i % oO0o % i11iIiiIii + OoO0O00 + I11i
 if 88 - 88: OoOoOO00 + iIii1I11I1II1 + iIii1I11I1II1 . II111iiii % OoO0O00
 if 99 - 99: Oo0Ooo - I1Ii111 * OOooOOo
 if 95 - 95: o0oOOo0O0Ooo / oO0o + Ii1I - OoooooooOO
 if 15 - 15: O0
 if 21 - 21: OoO0O00 * iIii1I11I1II1 - iIii1I11I1II1 % OoO0O00 . I1ii11iIi11i
 if 19 - 19: i1IIi % Ii1I . OoOoOO00
 if 22 - 22: iIii1I11I1II1 + Ii1I
 if 73 - 73: I1IiiI / OoO0O00 / OoooooooOO
 if 14 - 14: ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i . IiII + I1ii11iIi11i
 if 30 - 30: I1ii11iIi11i + iIii1I11I1II1 . I1ii11iIi11i
 if 9 - 9: I1IiiI - Ii1I * II111iiii - I11i
 if 85 - 85: oO0o % ooOoO0o / OOooOOo
 if 50 - 50: O0 * O0 / iIii1I11I1II1
def lisp_convert_reply_to_notify ( packet ) :
 if 31 - 31: I1IiiI / o0oOOo0O0Ooo
 if 70 - 70: I1IiiI
 if 36 - 36: ooOoO0o . oO0o . I11i - I1ii11iIi11i / OoOoOO00 * Oo0Ooo
 if 42 - 42: OoooooooOO / o0oOOo0O0Ooo . Ii1I * iII111i * I1IiiI - Oo0Ooo
 oOo0o0ooO0OOO = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 oOo0o0ooO0OOO = socket . ntohl ( oOo0o0ooO0OOO ) & 0xff
 OO00OO = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 85 - 85: I1Ii111
 if 1 - 1: o0oOOo0O0Ooo % oO0o * I1Ii111 - i1IIi - iII111i . oO0o
 if 25 - 25: i1IIi * o0oOOo0O0Ooo / oO0o
 if 11 - 11: IiII + II111iiii
 i1IiIiiiii11 = ( LISP_MAP_NOTIFY << 28 ) | oOo0o0ooO0OOO
 iIIIIII = struct . pack ( "I" , socket . htonl ( i1IiIiiiii11 ) )
 oO00o0oO0O = struct . pack ( "I" , 0 )
 if 37 - 37: O0
 if 98 - 98: IiII * OoooooooOO . iII111i
 if 34 - 34: OoooooooOO + I1Ii111
 if 97 - 97: II111iiii + I11i + OOooOOo / i11iIiiIii - iII111i
 packet = iIIIIII + OO00OO + oO00o0oO0O + packet
 return ( packet )
 if 9 - 9: i1IIi - I1Ii111 + I1Ii111
 if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
 if 58 - 58: OoooooooOO . II111iiii . O0 % I1Ii111 / OoooooooOO
 if 64 - 64: Oo0Ooo + oO0o . OoO0O00
 if 67 - 67: I11i
 if 91 - 91: OOooOOo / OoO0O00
 if 36 - 36: I1IiiI . iII111i * I1Ii111 . IiII % I1ii11iIi11i
 if 44 - 44: I11i % I1ii11iIi11i - OoooooooOO % iII111i
def lisp_notify_subscribers ( lisp_sockets , eid_record , eid , site ) :
 iiI1Ii1I = eid . print_prefix ( )
 if ( lisp_pubsub_cache . has_key ( iiI1Ii1I ) == False ) : return
 if 60 - 60: IiII % oO0o
 for OooOooOO0000 in lisp_pubsub_cache [ iiI1Ii1I ] . values ( ) :
  oo0O0oO0o = OooOooOO0000 . itr
  IIi1I1iII111 = OooOooOO0000 . port
  i1iiiii1 = red ( oo0O0oO0o . print_address_no_iid ( ) , False )
  OOoo0O = bold ( "subscriber" , False )
  oOo0 = "0x" + lisp_hex_string ( OooOooOO0000 . xtr_id )
  OO00OO = "0x" + lisp_hex_string ( OooOooOO0000 . nonce )
  if 16 - 16: iII111i % OoOoOO00 . OoooooooOO * o0oOOo0O0Ooo - I1IiiI / oO0o
  lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( OOoo0O , i1iiiii1 , IIi1I1iII111 , oOo0 , green ( iiI1Ii1I , False ) , OO00OO ) )
  if 51 - 51: Oo0Ooo + O0 / OoOoOO00 - I1ii11iIi11i * Oo0Ooo / IiII
  if 33 - 33: OoO0O00 . OOooOOo * ooOoO0o - ooOoO0o
  lisp_build_map_notify ( lisp_sockets , eid_record , [ iiI1Ii1I ] , 1 , oo0O0oO0o ,
 IIi1I1iII111 , OooOooOO0000 . nonce , 0 , 0 , 0 , site , False )
  OooOooOO0000 . map_notify_count += 1
  if 20 - 20: iIii1I11I1II1
 return
 if 66 - 66: O0 . iIii1I11I1II1 / OoO0O00 . Ii1I * i1IIi * OoooooooOO
 if 26 - 26: iIii1I11I1II1 . IiII * Oo0Ooo * OoOoOO00 * O0
 if 25 - 25: iIii1I11I1II1 . iII111i / II111iiii % OoO0O00 / Ii1I
 if 82 - 82: Ii1I . I11i - OOooOOo
 if 64 - 64: o0oOOo0O0Ooo - I1Ii111 - Oo0Ooo + OoOoOO00
 if 6 - 6: IiII * iIii1I11I1II1 + OOooOOo . OoooooooOO
 if 30 - 30: iII111i . IiII % O0 + iII111i % Ii1I
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 72 - 72: II111iiii * ooOoO0o + I1IiiI
 if 19 - 19: OoO0O00 * ooOoO0o % I1ii11iIi11i
 if 21 - 21: OoO0O00 * I11i
 if 76 - 76: I1IiiI - I1ii11iIi11i / I1ii11iIi11i . o0oOOo0O0Ooo % OoooooooOO
 lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl , xtr_id )
 if 39 - 39: OoooooooOO % iII111i
 I111o0oooO00o0 = green ( reply_eid . print_prefix ( ) , False )
 oo0O0oO0o = red ( itr_rloc . print_address_no_iid ( ) , False )
 o0o0O0 = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( o0o0O0 ,
 I111o0oooO00o0 , oo0O0oO0o , xtr_id ) )
 if 78 - 78: oO0o - I1ii11iIi11i
 if 8 - 8: OoO0O00
 if 58 - 58: OoooooooOO . i1IIi
 if 71 - 71: iII111i + ooOoO0o * OoOoOO00 . I1ii11iIi11i . I1Ii111
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 return
 if 91 - 91: oO0o - Oo0Ooo % OoOoOO00 % o0oOOo0O0Ooo
 if 71 - 71: i1IIi % iII111i * I1Ii111
 if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
 if 34 - 34: OoooooooOO * i11iIiiIii
 if 33 - 33: II111iiii
 if 59 - 59: iIii1I11I1II1 % I11i
 if 93 - 93: I1ii11iIi11i
 if 50 - 50: ooOoO0o % OoO0O00 % OoO0O00
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 36 - 36: I1IiiI * O0 . IiII / I1Ii111
 if 15 - 15: I11i + iII111i
 if 79 - 79: i11iIiiIii * IiII % iII111i
 if 18 - 18: iIii1I11I1II1 - O0 . o0oOOo0O0Ooo % oO0o
 if 73 - 73: IiII + I11i % I1IiiI * iII111i . O0
 if 17 - 17: OoO0O00 * OoOoOO00 % O0 % iII111i / i1IIi
 I111o0oooO00o0 = map_request . target_eid
 oOoooOOO0o0 = map_request . target_group
 iiI1Ii1I = lisp_print_eid_tuple ( I111o0oooO00o0 , oOoooOOO0o0 )
 O00o00O0OO0 = map_request . itr_rlocs [ 0 ]
 oOo0 = map_request . xtr_id
 OO00OO = map_request . nonce
 Ii1II1I = LISP_NO_ACTION
 OooOooOO0000 = map_request . subscribe_bit
 if 100 - 100: i11iIiiIii
 if 54 - 54: O0 * Ii1I + Ii1I
 if 59 - 59: i11iIiiIii % iII111i
 if 54 - 54: I11i . ooOoO0o / OOooOOo % I1Ii111
 if 13 - 13: I11i / O0 . o0oOOo0O0Ooo . ooOoO0o
 II1i1iI = True
 IIoOo0oooO0 = ( lisp_get_eid_hash ( I111o0oooO00o0 ) != None )
 if ( IIoOo0oooO0 ) :
  oOOo0OoooOo = map_request . map_request_signature
  if ( oOOo0OoooOo == None ) :
   II1i1iI = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 81 - 81: O0 + oO0o
  else :
   IIiII11i1 = map_request . signature_eid
   iI1Ii1 , Ooo0O00ooO , II1i1iI = lisp_lookup_public_key ( IIiII11i1 )
   if ( II1i1iI ) :
    II1i1iI = map_request . verify_map_request_sig ( Ooo0O00ooO )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( IIiII11i1 . print_address ( ) , iI1Ii1 . print_address ( ) ) )
    if 79 - 79: I1ii11iIi11i % I1Ii111 % I11i - iII111i * OoOoOO00
    if 48 - 48: O0 + OoOoOO00 - O0
   O0oIiI = bold ( "passed" , False ) if II1i1iI else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( O0oIiI ) )
   if 4 - 4: I1IiiI - OoO0O00 % o0oOOo0O0Ooo
   if 83 - 83: iII111i % iIii1I11I1II1 / OOooOOo - OoOoOO00
   if 98 - 98: I11i % oO0o . I1IiiI % OoOoOO00
 if ( OooOooOO0000 and II1i1iI == False ) :
  OooOooOO0000 = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 32 - 32: I1ii11iIi11i / Ii1I
  if 54 - 54: I11i - i11iIiiIii
  if 91 - 91: Ii1I - OoO0O00 - I1IiiI % OoO0O00 . o0oOOo0O0Ooo
  if 85 - 85: ooOoO0o . ooOoO0o % Oo0Ooo . OOooOOo + OOooOOo / I1IiiI
  if 69 - 69: i1IIi + II111iiii / Ii1I
  if 4 - 4: I11i * OoOoOO00 % o0oOOo0O0Ooo % ooOoO0o - I1ii11iIi11i
  if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 * I11i * OoOoOO00
  if 14 - 14: i11iIiiIii * I1IiiI % O0 % iIii1I11I1II1
  if 18 - 18: Oo0Ooo % OOooOOo + IiII
  if 28 - 28: OOooOOo . OoO0O00 / o0oOOo0O0Ooo + II111iiii / iIii1I11I1II1 * II111iiii
  if 83 - 83: II111iiii . OoOoOO00 - i11iIiiIii . OoOoOO00 . i1IIi % OoooooooOO
  if 47 - 47: II111iiii
  if 30 - 30: i1IIi . Oo0Ooo / o0oOOo0O0Ooo + IiII * OOooOOo
  if 26 - 26: Ii1I % O0 - i1IIi % iII111i * OoO0O00
 OOo0oOoOo0ooO = O00o00O0OO0 if ( O00o00O0OO0 . afi == ecm_source . afi ) else ecm_source
 if 98 - 98: iII111i / I1Ii111
 O0oiiii1i1i11I = lisp_site_eid_lookup ( I111o0oooO00o0 , oOoooOOO0o0 , False )
 if 3 - 3: OOooOOo * iIii1I11I1II1 / oO0o . iIii1I11I1II1 . iII111i
 if ( O0oiiii1i1i11I == None or O0oiiii1i1i11I . is_star_g ( ) ) :
  I11oo = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( I11oo ,
 green ( iiI1Ii1I , False ) ) )
  if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
  if 65 - 65: OOooOOo * I11i * Oo0Ooo
  if 21 - 21: Ii1I . iIii1I11I1II1
  if 84 - 84: OOooOOo
  lisp_send_negative_map_reply ( lisp_sockets , I111o0oooO00o0 , oOoooOOO0o0 , OO00OO , O00o00O0OO0 ,
 mr_sport , 15 , oOo0 , OooOooOO0000 )
  if 67 - 67: I1IiiI % OoO0O00 % o0oOOo0O0Ooo % IiII
  return ( [ I111o0oooO00o0 , oOoooOOO0o0 , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 33 - 33: ooOoO0o % I1IiiI
  if 98 - 98: oO0o . o0oOOo0O0Ooo + II111iiii
 IiI1ii1 = O0oiiii1i1i11I . print_eid_tuple ( )
 O0oooOO0O = O0oiiii1i1i11I . site . site_name
 if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
 if 9 - 9: iII111i * Oo0Ooo % iII111i % Oo0Ooo * II111iiii
 if 71 - 71: II111iiii + I1ii11iIi11i * II111iiii
 if 59 - 59: OoO0O00
 if 81 - 81: i11iIiiIii
 if ( IIoOo0oooO0 == False and O0oiiii1i1i11I . require_signature ) :
  oOOo0OoooOo = map_request . map_request_signature
  IIiII11i1 = map_request . signature_eid
  if ( oOOo0OoooOo == None or IIiII11i1 . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( O0oooOO0O ) )
   II1i1iI = False
  else :
   IIiII11i1 = map_request . signature_eid
   iI1Ii1 , Ooo0O00ooO , II1i1iI = lisp_lookup_public_key ( IIiII11i1 )
   if ( II1i1iI ) :
    II1i1iI = map_request . verify_map_request_sig ( Ooo0O00ooO )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( IIiII11i1 . print_address ( ) , iI1Ii1 . print_address ( ) ) )
    if 57 - 57: Oo0Ooo * iIii1I11I1II1 - OoOoOO00 % iII111i % I1ii11iIi11i + Ii1I
    if 82 - 82: IiII * Oo0Ooo - iIii1I11I1II1 - i11iIiiIii
   O0oIiI = bold ( "passed" , False ) if II1i1iI else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( O0oIiI ) )
   if 85 - 85: OoooooooOO
   if 37 - 37: OoooooooOO + O0 + I1ii11iIi11i + IiII * iII111i
   if 15 - 15: i11iIiiIii / Oo0Ooo - OOooOOo . IiII
   if 11 - 11: OOooOOo / i1IIi % Oo0Ooo
   if 65 - 65: OOooOOo % I1ii11iIi11i
   if 25 - 25: o0oOOo0O0Ooo - I1Ii111 * I1ii11iIi11i + OoooooooOO
 if ( II1i1iI and O0oiiii1i1i11I . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( O0oooOO0O , green ( IiI1ii1 , False ) , green ( iiI1Ii1I , False ) ) )
  if 93 - 93: OoOoOO00 % I1ii11iIi11i * I11i
  if 34 - 34: I11i - oO0o + I11i * OoooooooOO * I11i
  if 73 - 73: OOooOOo * iII111i * OoO0O00
  if 11 - 11: I1Ii111 * II111iiii
  if 3 - 3: Oo0Ooo * OOooOOo
  if 13 - 13: I1Ii111 + i11iIiiIii / OOooOOo
  if ( O0oiiii1i1i11I . accept_more_specifics == False ) :
   I111o0oooO00o0 = O0oiiii1i1i11I . eid
   oOoooOOO0o0 = O0oiiii1i1i11I . group
   if 98 - 98: I1IiiI * Oo0Ooo
   if 9 - 9: O0 / i11iIiiIii . iIii1I11I1II1 . IiII
   if 14 - 14: OoOoOO00 . OOooOOo - Oo0Ooo + I1Ii111 % ooOoO0o
   if 95 - 95: OoO0O00 * II111iiii + i1IIi
   if 22 - 22: Ii1I / ooOoO0o % I11i + OoO0O00 . ooOoO0o
  oo0OOoOO0 = 1
  if ( O0oiiii1i1i11I . force_ttl != None ) :
   oo0OOoOO0 = O0oiiii1i1i11I . force_ttl | 0x80000000
   if 61 - 61: O0 - iIii1I11I1II1 * Oo0Ooo . Ii1I + O0
   if 20 - 20: ooOoO0o / ooOoO0o - Ii1I - ooOoO0o
   if 93 - 93: O0 * OoOoOO00 * iIii1I11I1II1
   if 3 - 3: I1ii11iIi11i - O0
   if 46 - 46: iII111i
  lisp_send_negative_map_reply ( lisp_sockets , I111o0oooO00o0 , oOoooOOO0o0 , OO00OO , O00o00O0OO0 ,
 mr_sport , oo0OOoOO0 , oOo0 , OooOooOO0000 )
  if 99 - 99: oO0o
  return ( [ I111o0oooO00o0 , oOoooOOO0o0 , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 85 - 85: I1Ii111 * iIii1I11I1II1 . OoOoOO00
  if 20 - 20: I11i * O0 - OoooooooOO * OOooOOo % oO0o * iII111i
  if 70 - 70: I11i + O0 . i11iIiiIii . OOooOOo
  if 48 - 48: iIii1I11I1II1 * Ii1I - OoooooooOO / oO0o - OoO0O00 / i11iIiiIii
  if 24 - 24: I1IiiI
 O00oO0ooo = False
 OOIIi11iiiIIIII = ""
 oO0OOoOo0O = False
 if ( O0oiiii1i1i11I . force_nat_proxy_reply ) :
  OOIIi11iiiIIIII = ", nat-forced"
  O00oO0ooo = True
  oO0OOoOo0O = True
 elif ( O0oiiii1i1i11I . force_proxy_reply ) :
  OOIIi11iiiIIIII = ", forced"
  oO0OOoOo0O = True
 elif ( O0oiiii1i1i11I . proxy_reply_requested ) :
  OOIIi11iiiIIIII = ", requested"
  oO0OOoOo0O = True
 elif ( map_request . pitr_bit and O0oiiii1i1i11I . pitr_proxy_reply_drop ) :
  OOIIi11iiiIIIII = ", drop-to-pitr"
  Ii1II1I = LISP_DROP_ACTION
 elif ( O0oiiii1i1i11I . proxy_reply_action != "" ) :
  Ii1II1I = O0oiiii1i1i11I . proxy_reply_action
  OOIIi11iiiIIIII = ", forced, action {}" . format ( Ii1II1I )
  Ii1II1I = LISP_DROP_ACTION if ( Ii1II1I == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 91 - 91: OOooOOo - OoooooooOO . OoO0O00
  if 34 - 34: Ii1I . I1IiiI . i1IIi * I1ii11iIi11i
  if 77 - 77: ooOoO0o . II111iiii
  if 41 - 41: IiII
  if 27 - 27: IiII / IiII
  if 91 - 91: Ii1I
  if 93 - 93: OoO0O00 * OoO0O00 * I1ii11iIi11i * OoO0O00 * o0oOOo0O0Ooo
 O0OOO0oO0OO0 = False
 iiII1iI = None
 if ( oO0OOoOo0O and lisp_policies . has_key ( O0oiiii1i1i11I . policy ) ) :
  iIiiI11II11 = lisp_policies [ O0oiiii1i1i11I . policy ]
  if ( iIiiI11II11 . match_policy_map_request ( map_request , mr_source ) ) : iiII1iI = iIiiI11II11
  if 8 - 8: I1ii11iIi11i
  if ( iiII1iI ) :
   O00OOOo0Oo0 = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( O00OOOo0Oo0 ,
 iIiiI11II11 . policy_name , iIiiI11II11 . set_action ) )
  else :
   O00OOOo0Oo0 = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( O00OOOo0Oo0 ,
 iIiiI11II11 . policy_name ) )
   O0OOO0oO0OO0 = True
   if 88 - 88: I11i
   if 36 - 36: iIii1I11I1II1 - ooOoO0o * OoO0O00 * OoO0O00 . II111iiii
   if 49 - 49: O0 + OoO0O00 - I1ii11iIi11i + ooOoO0o
 if ( OOIIi11iiiIIIII != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( iiI1Ii1I , False ) , O0oooOO0O , green ( IiI1ii1 , False ) ,
  # iIii1I11I1II1 * ooOoO0o . ooOoO0o % I1Ii111 % ooOoO0o . ooOoO0o
 OOIIi11iiiIIIII ) )
  if 78 - 78: Oo0Ooo
  iio0OOoO0 = O0oiiii1i1i11I . registered_rlocs
  oo0OOoOO0 = 1440
  if ( O00oO0ooo ) :
   if ( O0oiiii1i1i11I . site_id != 0 ) :
    Oooo0OOO0oo0o = map_request . source_eid
    iio0OOoO0 = lisp_get_private_rloc_set ( O0oiiii1i1i11I , Oooo0OOO0oo0o , oOoooOOO0o0 )
    if 78 - 78: o0oOOo0O0Ooo . i11iIiiIii % IiII
   if ( iio0OOoO0 == O0oiiii1i1i11I . registered_rlocs ) :
    OOo0I111I = ( O0oiiii1i1i11I . group . is_null ( ) == False )
    i11i1i11ii11I = lisp_get_partial_rloc_set ( iio0OOoO0 , OOo0oOoOo0ooO , OOo0I111I )
    if ( i11i1i11ii11I != iio0OOoO0 ) :
     oo0OOoOO0 = 15
     iio0OOoO0 = i11i1i11ii11I
     if 66 - 66: o0oOOo0O0Ooo
     if 44 - 44: IiII / IiII - iII111i * i11iIiiIii % i11iIiiIii + i11iIiiIii
     if 50 - 50: II111iiii . IiII / O0 . I1ii11iIi11i / OOooOOo % ooOoO0o
     if 90 - 90: OoO0O00 + OOooOOo
     if 64 - 64: o0oOOo0O0Ooo + OoO0O00 % I1Ii111 * I11i * iII111i % I11i
     if 26 - 26: OoO0O00 - II111iiii - o0oOOo0O0Ooo
     if 50 - 50: OoooooooOO
     if 51 - 51: II111iiii - oO0o % OoooooooOO - II111iiii / O0 - OoooooooOO
  if ( O0oiiii1i1i11I . force_ttl != None ) :
   oo0OOoOO0 = O0oiiii1i1i11I . force_ttl | 0x80000000
   if 21 - 21: iII111i * o0oOOo0O0Ooo
   if 85 - 85: I1ii11iIi11i . OoOoOO00 . i1IIi % OOooOOo * I11i . I1Ii111
   if 26 - 26: I1Ii111 + Oo0Ooo + II111iiii % OoOoOO00 % OOooOOo
   if 40 - 40: I1ii11iIi11i + i1IIi
   if 9 - 9: OOooOOo
   if 74 - 74: OoOoOO00 - OOooOOo % OoOoOO00
  if ( iiII1iI ) :
   if ( iiII1iI . set_record_ttl ) :
    oo0OOoOO0 = iiII1iI . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( oo0OOoOO0 ) )
    if 82 - 82: I11i % IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
   if ( iiII1iI . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    Ii1II1I = LISP_POLICY_DENIED_ACTION
    iio0OOoO0 = [ ]
   else :
    OooO0ooO0o0OO = iiII1iI . set_policy_map_reply ( )
    if ( OooO0ooO0o0OO ) : iio0OOoO0 = [ OooO0ooO0o0OO ]
    if 65 - 65: IiII / O0 * II111iiii + oO0o
    if 52 - 52: o0oOOo0O0Ooo - OoOoOO00 * II111iiii / OoooooooOO
    if 44 - 44: OOooOOo - oO0o + o0oOOo0O0Ooo - i1IIi % o0oOOo0O0Ooo
  if ( O0OOO0oO0OO0 ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   Ii1II1I = LISP_POLICY_DENIED_ACTION
   iio0OOoO0 = [ ]
   if 79 - 79: iII111i . iIii1I11I1II1
   if 42 - 42: i11iIiiIii / IiII . O0 / OOooOOo . iII111i * i1IIi
  II1iiIiii1iI = O0oiiii1i1i11I . echo_nonce_capable
  if 83 - 83: iIii1I11I1II1 . II111iiii * Oo0Ooo . I1IiiI - I1IiiI - iIii1I11I1II1
  if 29 - 29: Oo0Ooo
  if 35 - 35: OoOoOO00 + II111iiii
  if 46 - 46: O0 / I1ii11iIi11i + OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
  if ( II1i1iI ) :
   O0Oo00O = O0oiiii1i1i11I . eid
   OoOOo0O = O0oiiii1i1i11I . group
  else :
   O0Oo00O = I111o0oooO00o0
   OoOOo0O = oOoooOOO0o0
   Ii1II1I = LISP_AUTH_FAILURE_ACTION
   iio0OOoO0 = [ ]
   if 5 - 5: oO0o
   if 59 - 59: iII111i
   if 74 - 74: IiII
   if 94 - 94: I11i + OoooooooOO
   if 20 - 20: o0oOOo0O0Ooo % o0oOOo0O0Ooo . iIii1I11I1II1 + OoOoOO00 * OoO0O00
   if 57 - 57: i11iIiiIii * i11iIiiIii % I1Ii111 - iII111i * O0 - Ii1I
  packet = lisp_build_map_reply ( O0Oo00O , OoOOo0O , iio0OOoO0 ,
 OO00OO , Ii1II1I , oo0OOoOO0 , False , None , II1iiIiii1iI , False )
  if 63 - 63: IiII % OoooooooOO * OoOoOO00 * iIii1I11I1II1 . iII111i % oO0o
  if ( OooOooOO0000 ) :
   lisp_process_pubsub ( lisp_sockets , packet , O0Oo00O , O00o00O0OO0 ,
 mr_sport , OO00OO , oo0OOoOO0 , oOo0 )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , O00o00O0OO0 , mr_sport )
   if 58 - 58: I11i * iII111i + I11i % OoO0O00
   if 19 - 19: Oo0Ooo
  return ( [ O0oiiii1i1i11I . eid , O0oiiii1i1i11I . group , LISP_DDT_ACTION_MS_ACK ] )
  if 43 - 43: oO0o % ooOoO0o
  if 36 - 36: I11i / I1IiiI + O0 % II111iiii
  if 24 - 24: I1Ii111 / o0oOOo0O0Ooo - OOooOOo / IiII
  if 7 - 7: OoooooooOO - i11iIiiIii * i11iIiiIii / oO0o * i1IIi % OoooooooOO
  if 6 - 6: I1ii11iIi11i * i11iIiiIii % i11iIiiIii / I1Ii111
 i1ii1I = len ( O0oiiii1i1i11I . registered_rlocs )
 if ( i1ii1I == 0 ) :
  lprint ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" . format ( green ( iiI1Ii1I , False ) , O0oooOO0O ,
  # oO0o . OoOoOO00
 green ( IiI1ii1 , False ) ) )
  return ( [ O0oiiii1i1i11I . eid , O0oiiii1i1i11I . group , LISP_DDT_ACTION_MS_ACK ] )
  if 10 - 10: I1IiiI / I1Ii111 % IiII . OoOoOO00
  if 65 - 65: II111iiii + OoO0O00 + OoO0O00
  if 48 - 48: I1ii11iIi11i / iIii1I11I1II1
  if 47 - 47: I1Ii111
  if 41 - 41: IiII
 i1iiIiiiiIi = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 26 - 26: I1ii11iIi11i - OoOoOO00 + o0oOOo0O0Ooo * IiII - IiII - iII111i
 IiI1I1i1 = map_request . target_eid . hash_address ( i1iiIiiiiIi )
 IiI1I1i1 %= i1ii1I
 iI1IIiIiIiII = O0oiiii1i1i11I . registered_rlocs [ IiI1I1i1 ]
 if 57 - 57: OOooOOo / II111iiii . Ii1I / I1Ii111 . OoooooooOO
 if ( iI1IIiIiIiII . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( iiI1Ii1I , False ) ,
  # I11i % IiII
 O0oooOO0O , green ( IiI1ii1 , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( iiI1Ii1I , False ) ,
  # O0 / II111iiii . Oo0Ooo / Oo0Ooo * II111iiii
 red ( iI1IIiIiIiII . rloc . print_address ( ) , False ) , O0oooOO0O ,
 green ( IiI1ii1 , False ) ) )
  if 22 - 22: Ii1I
  if 81 - 81: iIii1I11I1II1 . ooOoO0o % I11i
  if 64 - 64: I1Ii111 . Oo0Ooo * o0oOOo0O0Ooo
  if 32 - 32: oO0o . I1Ii111 * I1Ii111
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , iI1IIiIiIiII . rloc , to_etr = True )
  if 32 - 32: I1Ii111 . Ii1I / i1IIi
 return ( [ O0oiiii1i1i11I . eid , O0oiiii1i1i11I . group , LISP_DDT_ACTION_MS_ACK ] )
 if 2 - 2: OOooOOo * ooOoO0o / I11i + OoO0O00
 if 96 - 96: II111iiii * OoO0O00 + I1ii11iIi11i + OoOoOO00 / II111iiii . iII111i
 if 64 - 64: iII111i % Oo0Ooo
 if 79 - 79: IiII + iII111i / II111iiii . i1IIi + iIii1I11I1II1
 if 32 - 32: Ii1I * iII111i
 if 52 - 52: I11i
 if 100 - 100: Oo0Ooo % Oo0Ooo % I1ii11iIi11i
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 33 - 33: I1Ii111 . I1Ii111 * i1IIi
 if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
 if 13 - 13: II111iiii
 if 36 - 36: iII111i - oO0o / Oo0Ooo / O0 . OoO0O00 . i1IIi
 I111o0oooO00o0 = map_request . target_eid
 oOoooOOO0o0 = map_request . target_group
 iiI1Ii1I = lisp_print_eid_tuple ( I111o0oooO00o0 , oOoooOOO0o0 )
 OO00OO = map_request . nonce
 Ii1II1I = LISP_DDT_ACTION_NULL
 if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
 if 98 - 98: oO0o . Oo0Ooo
 if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
 if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
 if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
 oo0O0O = None
 if ( lisp_i_am_ms ) :
  O0oiiii1i1i11I = lisp_site_eid_lookup ( I111o0oooO00o0 , oOoooOOO0o0 , False )
  if ( O0oiiii1i1i11I == None ) : return
  if 34 - 34: OoO0O00 % I1ii11iIi11i
  if ( O0oiiii1i1i11I . registered ) :
   Ii1II1I = LISP_DDT_ACTION_MS_ACK
   oo0OOoOO0 = 1440
  else :
   I111o0oooO00o0 , oOoooOOO0o0 , Ii1II1I = lisp_ms_compute_neg_prefix ( I111o0oooO00o0 , oOoooOOO0o0 )
   Ii1II1I = LISP_DDT_ACTION_MS_NOT_REG
   oo0OOoOO0 = 1
   if 80 - 80: IiII - I1Ii111 / iIii1I11I1II1
 else :
  oo0O0O = lisp_ddt_cache_lookup ( I111o0oooO00o0 , oOoooOOO0o0 , False )
  if ( oo0O0O == None ) :
   Ii1II1I = LISP_DDT_ACTION_NOT_AUTH
   oo0OOoOO0 = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( iiI1Ii1I , False ) ) )
   if 45 - 45: oO0o + iII111i / o0oOOo0O0Ooo + I11i % OoOoOO00
  elif ( oo0O0O . is_auth_prefix ( ) ) :
   if 6 - 6: OoooooooOO + i1IIi % IiII - OoO0O00 * iIii1I11I1II1
   if 36 - 36: I11i / o0oOOo0O0Ooo + IiII * o0oOOo0O0Ooo + Ii1I - I11i
   if 70 - 70: oO0o * ooOoO0o / ooOoO0o - Ii1I * Ii1I % OOooOOo
   if 91 - 91: OoO0O00 - OoO0O00 % O0
   Ii1II1I = LISP_DDT_ACTION_DELEGATION_HOLE
   oo0OOoOO0 = 15
   o0oO0OOoOoOO = oo0O0O . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( o0oO0OOoOoOO ,
   # Ii1I - ooOoO0o / Ii1I - oO0o - iII111i
 green ( iiI1Ii1I , False ) ) )
   if 10 - 10: I1Ii111 . Oo0Ooo . Ii1I . i11iIiiIii / OoooooooOO
   if ( oOoooOOO0o0 . is_null ( ) ) :
    I111o0oooO00o0 = lisp_ddt_compute_neg_prefix ( I111o0oooO00o0 , oo0O0O ,
 lisp_ddt_cache )
   else :
    oOoooOOO0o0 = lisp_ddt_compute_neg_prefix ( oOoooOOO0o0 , oo0O0O ,
 lisp_ddt_cache )
    I111o0oooO00o0 = lisp_ddt_compute_neg_prefix ( I111o0oooO00o0 , oo0O0O ,
 oo0O0O . source_cache )
    if 58 - 58: I1Ii111 / iII111i / oO0o
   oo0O0O = None
  else :
   o0oO0OOoOoOO = oo0O0O . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( o0oO0OOoOoOO , green ( iiI1Ii1I , False ) ) )
   if 69 - 69: i11iIiiIii / O0 - OoooooooOO + I1ii11iIi11i . OoO0O00
   oo0OOoOO0 = 1440
   if 19 - 19: I1IiiI / iII111i . OOooOOo / oO0o + I1ii11iIi11i + OOooOOo
   if 1 - 1: iIii1I11I1II1
   if 59 - 59: ooOoO0o % I1IiiI + i1IIi * I1Ii111 % o0oOOo0O0Ooo * II111iiii
   if 22 - 22: OoOoOO00 * O0 + OoOoOO00 / iIii1I11I1II1 + oO0o + IiII
   if 69 - 69: iIii1I11I1II1 . I1Ii111 * iII111i
   if 6 - 6: I11i - IiII - I11i - II111iiii
 ii1i1II = lisp_build_map_referral ( I111o0oooO00o0 , oOoooOOO0o0 , oo0O0O , Ii1II1I , oo0OOoOO0 , OO00OO )
 OO00OO = map_request . nonce >> 32
 if ( map_request . nonce != 0 and OO00OO != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , ii1i1II , ecm_source , port )
 return
 if 72 - 72: i1IIi / OOooOOo . Oo0Ooo . oO0o
 if 72 - 72: o0oOOo0O0Ooo % iIii1I11I1II1
 if 74 - 74: Oo0Ooo % OOooOOo + i11iIiiIii
 if 17 - 17: OoOoOO00 . I1IiiI
 if 30 - 30: i1IIi * OoOoOO00 * I11i . O0
 if 45 - 45: iII111i
 if 99 - 99: o0oOOo0O0Ooo % ooOoO0o % i11iIiiIii
 if 32 - 32: IiII - Ii1I
 if 44 - 44: OoooooooOO . oO0o
 if 30 - 30: I1Ii111 % IiII / II111iiii
 if 68 - 68: oO0o / O0 / OOooOOo
 if 3 - 3: o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if 17 - 17: OoO0O00 * i1IIi
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 iI1I11I = eid . hash_address ( entry_prefix )
 IIIi1iIiiI1 = eid . addr_length ( ) * 8
 Ooo0o00 = 0
 if 25 - 25: I1ii11iIi11i - OOooOOo . iIii1I11I1II1 * O0 + OoooooooOO
 if 83 - 83: OoooooooOO + Oo0Ooo
 if 4 - 4: Oo0Ooo - i11iIiiIii / O0 / I11i + ooOoO0o / iII111i
 if 72 - 72: II111iiii % iII111i + OoO0O00
 for Ooo0o00 in range ( IIIi1iIiiI1 ) :
  IiIi11 = 1 << ( IIIi1iIiiI1 - Ooo0o00 - 1 )
  if ( iI1I11I & IiIi11 ) : break
  if 83 - 83: i11iIiiIii - o0oOOo0O0Ooo - O0
  if 25 - 25: I1ii11iIi11i - O0 * iII111i % I1IiiI % Ii1I + OoO0O00
 if ( Ooo0o00 > neg_prefix . mask_len ) : neg_prefix . mask_len = Ooo0o00
 return
 if 44 - 44: I1IiiI - Oo0Ooo / OoOoOO00 . Ii1I - I1IiiI + O0
 if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
 if 45 - 45: OoooooooOO / oO0o . I1ii11iIi11i + OOooOOo
 if 54 - 54: Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
 if 61 - 61: I11i / IiII % OoooooooOO - i11iIiiIii * i1IIi % o0oOOo0O0Ooo
 if 67 - 67: o0oOOo0O0Ooo - Ii1I
 if 29 - 29: OoOoOO00 . I1ii11iIi11i
 if 24 - 24: OOooOOo + i1IIi . I11i . OoOoOO00 + OoooooooOO
 if 98 - 98: ooOoO0o + i1IIi / I1IiiI
 if 1 - 1: IiII . OoooooooOO + II111iiii
def lisp_neg_prefix_walk ( entry , parms ) :
 I111o0oooO00o0 , iiIi11i1ii1I , iiiI1i = parms
 if 91 - 91: II111iiii / iIii1I11I1II1 / OoOoOO00 . II111iiii
 if ( iiIi11i1ii1I == None ) :
  if ( entry . eid . instance_id != I111o0oooO00o0 . instance_id ) :
   return ( [ True , parms ] )
   if 58 - 58: OoOoOO00 - II111iiii
  if ( entry . eid . afi != I111o0oooO00o0 . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( iiIi11i1ii1I ) == False ) :
   return ( [ True , parms ] )
   if 77 - 77: I1ii11iIi11i
   if 72 - 72: I1IiiI - i1IIi
   if 11 - 11: iIii1I11I1II1 . OoO0O00 * Ii1I
   if 65 - 65: Oo0Ooo / OoooooooOO
   if 60 - 60: II111iiii + I1IiiI % oO0o - o0oOOo0O0Ooo
   if 50 - 50: iIii1I11I1II1 - i11iIiiIii / iII111i + ooOoO0o / OOooOOo
 lisp_find_negative_mask_len ( I111o0oooO00o0 , entry . eid , iiiI1i )
 return ( [ True , parms ] )
 if 80 - 80: IiII / OoooooooOO
 if 69 - 69: OoOoOO00 + IiII
 if 18 - 18: O0 / I11i
 if 10 - 10: I1Ii111 * i1IIi
 if 48 - 48: Oo0Ooo % i1IIi / iII111i . O0
 if 27 - 27: I11i + iIii1I11I1II1 - i11iIiiIii
 if 81 - 81: I11i + oO0o * iIii1I11I1II1 * IiII
 if 7 - 7: I11i - I1IiiI . iII111i + O0 / iIii1I11I1II1 - I1Ii111
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 32 - 32: ooOoO0o
 if 9 - 9: I1Ii111
 if 77 - 77: OoooooooOO * I1Ii111
 if 63 - 63: IiII * oO0o * iIii1I11I1II1
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 18 - 18: II111iiii * o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
 iiiI1i = lisp_address ( eid . afi , "" , 0 , 0 )
 iiiI1i . copy_address ( eid )
 iiiI1i . mask_len = 0
 if 40 - 40: oO0o - o0oOOo0O0Ooo * II111iiii
 iioOoOo0 = ddt_entry . print_eid_tuple ( )
 iiIi11i1ii1I = ddt_entry . eid
 if 92 - 92: ooOoO0o
 if 58 - 58: iII111i % I11i
 if 71 - 71: I1IiiI + OoO0O00 + IiII * I11i
 if 61 - 61: I1IiiI / OoOoOO00
 if 58 - 58: o0oOOo0O0Ooo - Oo0Ooo % OoOoOO00 + I11i
 eid , iiIi11i1ii1I , iiiI1i = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , iiIi11i1ii1I , iiiI1i ) )
 if 10 - 10: II111iiii / iIii1I11I1II1 % i11iIiiIii
 if 29 - 29: ooOoO0o - iII111i + IiII % Ii1I - oO0o - ooOoO0o
 if 43 - 43: oO0o
 if 22 - 22: I1Ii111 + i11iIiiIii
 iiiI1i . mask_address ( iiiI1i . mask_len )
 if 49 - 49: O0 % II111iiii . OOooOOo + iII111i + iIii1I11I1II1 / i11iIiiIii
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # I1IiiI * o0oOOo0O0Ooo / oO0o * OoO0O00 / i1IIi
 iioOoOo0 , iiiI1i . print_prefix ( ) ) )
 return ( iiiI1i )
 if 16 - 16: Ii1I / Ii1I
 if 95 - 95: I11i % OoO0O00
 if 69 - 69: OoOoOO00 % IiII / II111iiii
 if 82 - 82: I1Ii111 + O0 . I1IiiI / I1ii11iIi11i % II111iiii
 if 46 - 46: O0 - I1IiiI + OoooooooOO / OoOoOO00
 if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
 if 57 - 57: O0
 if 23 - 23: OoO0O00 / II111iiii . I1ii11iIi11i . O0
def lisp_ms_compute_neg_prefix ( eid , group ) :
 iiiI1i = lisp_address ( eid . afi , "" , 0 , 0 )
 iiiI1i . copy_address ( eid )
 iiiI1i . mask_len = 0
 ii1i1I1i = lisp_address ( group . afi , "" , 0 , 0 )
 ii1i1I1i . copy_address ( group )
 ii1i1I1i . mask_len = 0
 iiIi11i1ii1I = None
 if 95 - 95: i1IIi + II111iiii . iIii1I11I1II1 . OoooooooOO + o0oOOo0O0Ooo / iIii1I11I1II1
 if 40 - 40: OoO0O00 / O0
 if 60 - 60: iIii1I11I1II1 / Oo0Ooo / oO0o + iII111i
 if 66 - 66: iIii1I11I1II1 . O0 * IiII . ooOoO0o + i1IIi
 if 83 - 83: o0oOOo0O0Ooo / II111iiii + I1IiiI - iII111i + OoO0O00
 if ( group . is_null ( ) ) :
  oo0O0O = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( oo0O0O == None ) :
   iiiI1i . mask_len = iiiI1i . host_mask_len ( )
   ii1i1I1i . mask_len = ii1i1I1i . host_mask_len ( )
   return ( [ iiiI1i , ii1i1I1i , LISP_DDT_ACTION_NOT_AUTH ] )
   if 67 - 67: I1Ii111 - OoOoOO00 . i11iIiiIii - I1Ii111 . i11iIiiIii
  i1I11I1I1I = lisp_sites_by_eid
  if ( oo0O0O . is_auth_prefix ( ) ) : iiIi11i1ii1I = oo0O0O . eid
 else :
  oo0O0O = lisp_ddt_cache . lookup_cache ( group , False )
  if ( oo0O0O == None ) :
   iiiI1i . mask_len = iiiI1i . host_mask_len ( )
   ii1i1I1i . mask_len = ii1i1I1i . host_mask_len ( )
   return ( [ iiiI1i , ii1i1I1i , LISP_DDT_ACTION_NOT_AUTH ] )
   if 36 - 36: O0 - II111iiii
  if ( oo0O0O . is_auth_prefix ( ) ) : iiIi11i1ii1I = oo0O0O . group
  if 97 - 97: I1IiiI
  group , iiIi11i1ii1I , ii1i1I1i = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , iiIi11i1ii1I , ii1i1I1i ) )
  if 87 - 87: I11i + iIii1I11I1II1
  if 91 - 91: oO0o
  ii1i1I1i . mask_address ( ii1i1I1i . mask_len )
  if 58 - 58: i11iIiiIii / Ii1I - OoooooooOO
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , iiIi11i1ii1I . print_prefix ( ) if ( iiIi11i1ii1I != None ) else "'not found'" ,
  # IiII - i1IIi
  # I1IiiI * I1IiiI - i11iIiiIii % Oo0Ooo . i11iIiiIii
  # Ii1I
 ii1i1I1i . print_prefix ( ) ) )
  if 2 - 2: I1IiiI % I11i * II111iiii
  i1I11I1I1I = oo0O0O . source_cache
  if 82 - 82: I1Ii111 . OoO0O00 * II111iiii
  if 99 - 99: iIii1I11I1II1 / iII111i % i1IIi - II111iiii / OoO0O00
  if 33 - 33: OoooooooOO / i1IIi . Ii1I
  if 96 - 96: OoOoOO00 / Oo0Ooo . II111iiii / ooOoO0o
  if 56 - 56: IiII - ooOoO0o % oO0o / Oo0Ooo * oO0o % O0
 Ii1II1I = LISP_DDT_ACTION_DELEGATION_HOLE if ( iiIi11i1ii1I != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 71 - 71: iII111i / II111iiii - II111iiii / I1IiiI
 if 24 - 24: O0 . I1IiiI + IiII . IiII
 if 53 - 53: II111iiii + Ii1I * o0oOOo0O0Ooo
 if 47 - 47: Ii1I % OOooOOo . Oo0Ooo
 if 94 - 94: Ii1I - iIii1I11I1II1 + I1IiiI - iIii1I11I1II1 . o0oOOo0O0Ooo
 if 3 - 3: O0 / I11i + OoOoOO00 % IiII / i11iIiiIii
 eid , iiIi11i1ii1I , iiiI1i = i1I11I1I1I . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , iiIi11i1ii1I , iiiI1i ) )
 if 25 - 25: II111iiii / I1ii11iIi11i % iIii1I11I1II1
 if 69 - 69: IiII
 if 36 - 36: I1IiiI / oO0o
 if 72 - 72: i1IIi - I1ii11iIi11i . OOooOOo + I1Ii111 - ooOoO0o
 iiiI1i . mask_address ( iiiI1i . mask_len )
 if 69 - 69: o0oOOo0O0Ooo * I1IiiI - I11i
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # I1IiiI
 # O0 % I1ii11iIi11i + I1IiiI - i1IIi . i1IIi * II111iiii
 iiIi11i1ii1I . print_prefix ( ) if ( iiIi11i1ii1I != None ) else "'not found'" , iiiI1i . print_prefix ( ) ) )
 if 64 - 64: I1IiiI * iIii1I11I1II1 % I1Ii111
 if 22 - 22: OoooooooOO + I1Ii111 . o0oOOo0O0Ooo * Oo0Ooo
 return ( [ iiiI1i , ii1i1I1i , Ii1II1I ] )
 if 61 - 61: iIii1I11I1II1
 if 95 - 95: I1ii11iIi11i + IiII * Ii1I - IiII
 if 58 - 58: I1ii11iIi11i - oO0o % I11i * O0
 if 43 - 43: OoOoOO00 + O0
 if 71 - 71: ooOoO0o * I1IiiI / I1ii11iIi11i
 if 8 - 8: I1Ii111 / iIii1I11I1II1
 if 29 - 29: i11iIiiIii % i1IIi + oO0o . I1ii11iIi11i
 if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
 I111o0oooO00o0 = map_request . target_eid
 oOoooOOO0o0 = map_request . target_group
 OO00OO = map_request . nonce
 if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
 if ( action == LISP_DDT_ACTION_MS_ACK ) : oo0OOoOO0 = 1440
 if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
 if 53 - 53: OOooOOo / I11i + OOooOOo / I1IiiI / OoO0O00
 if 12 - 12: i11iIiiIii % ooOoO0o / iII111i . IiII
 if 68 - 68: OOooOOo / iIii1I11I1II1 + I1IiiI . ooOoO0o * IiII
 OOOOo0ooOoOO = lisp_map_referral ( )
 OOOOo0ooOoOO . record_count = 1
 OOOOo0ooOoOO . nonce = OO00OO
 ii1i1II = OOOOo0ooOoOO . encode ( )
 OOOOo0ooOoOO . print_map_referral ( )
 if 72 - 72: I1Ii111
 iiiiIIiiII1Iii1 = False
 if 51 - 51: OoOoOO00
 if 61 - 61: Oo0Ooo / i1IIi + I1Ii111 - OoooooooOO / O0
 if 25 - 25: I1ii11iIi11i * i11iIiiIii / i1IIi
 if 69 - 69: OOooOOo % ooOoO0o - i1IIi . Oo0Ooo
 if 35 - 35: iIii1I11I1II1 - I11i / iIii1I11I1II1 % ooOoO0o % I1IiiI
 if 46 - 46: oO0o
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( I111o0oooO00o0 ,
 oOoooOOO0o0 )
  oo0OOoOO0 = 15
  if 5 - 5: i1IIi % o0oOOo0O0Ooo + OoOoOO00 - I11i . Ii1I
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : oo0OOoOO0 = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : oo0OOoOO0 = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : oo0OOoOO0 = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : oo0OOoOO0 = 0
 if 33 - 33: II111iiii * o0oOOo0O0Ooo
 iIII111iiII = False
 i1ii1I = 0
 oo0O0O = lisp_ddt_cache_lookup ( I111o0oooO00o0 , oOoooOOO0o0 , False )
 if ( oo0O0O != None ) :
  i1ii1I = len ( oo0O0O . delegation_set )
  iIII111iiII = oo0O0O . is_ms_peer_entry ( )
  oo0O0O . map_referrals_sent += 1
  if 42 - 42: I11i / Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
  if 100 - 100: iII111i % iII111i + OOooOOo - I1ii11iIi11i % IiII % ooOoO0o
  if 57 - 57: Ii1I / IiII / I11i % I1IiiI
  if 49 - 49: Oo0Ooo + i1IIi % iII111i - I1IiiI + Ii1I
  if 96 - 96: I1ii11iIi11i % Oo0Ooo . OoO0O00 + OoooooooOO + I1ii11iIi11i * OOooOOo
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : iiiiIIiiII1Iii1 = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  iiiiIIiiII1Iii1 = ( iIII111iiII == False )
  if 75 - 75: Ii1I * Oo0Ooo % iIii1I11I1II1 . O0 % oO0o
  if 4 - 4: I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
  if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
  if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
  if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
 OOoo = lisp_eid_record ( )
 OOoo . rloc_count = i1ii1I
 OOoo . authoritative = True
 OOoo . action = action
 OOoo . ddt_incomplete = iiiiIIiiII1Iii1
 OOoo . eid = eid_prefix
 OOoo . group = group_prefix
 OOoo . record_ttl = oo0OOoOO0
 if 66 - 66: iII111i % iII111i
 ii1i1II += OOoo . encode ( )
 OOoo . print_record ( "  " , True )
 if 59 - 59: II111iiii . i1IIi % i1IIi
 if 40 - 40: I1Ii111 . II111iiii * o0oOOo0O0Ooo + I11i - i1IIi
 if 67 - 67: o0oOOo0O0Ooo - O0 - i1IIi . ooOoO0o . iII111i
 if 43 - 43: II111iiii . o0oOOo0O0Ooo + i11iIiiIii . O0 / O0 . II111iiii
 if ( i1ii1I != 0 ) :
  for I11i1ii11 in oo0O0O . delegation_set :
   O0000O00O00OO = lisp_rloc_record ( )
   O0000O00O00OO . rloc = I11i1ii11 . delegate_address
   O0000O00O00OO . priority = I11i1ii11 . priority
   O0000O00O00OO . weight = I11i1ii11 . weight
   O0000O00O00OO . mpriority = 255
   O0000O00O00OO . mweight = 0
   O0000O00O00OO . reach_bit = True
   ii1i1II += O0000O00O00OO . encode ( )
   O0000O00O00OO . print_record ( "    " )
   if 13 - 13: Ii1I % i11iIiiIii
   if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
   if 50 - 50: I1ii11iIi11i + iII111i
   if 64 - 64: oO0o
   if 11 - 11: o0oOOo0O0Ooo
   if 95 - 95: i1IIi . ooOoO0o . Oo0Ooo
   if 13 - 13: OOooOOo - Oo0Ooo % O0 . I1Ii111
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , ii1i1II , ecm_source , port )
 return
 if 66 - 66: I1IiiI + I11i
 if 58 - 58: I1ii11iIi11i
 if 7 - 7: oO0o - I11i
 if 59 - 59: Ii1I / o0oOOo0O0Ooo / OoO0O00 + IiII + i11iIiiIii
 if 64 - 64: o0oOOo0O0Ooo * IiII * IiII * iII111i % i11iIiiIii
 if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
 if 10 - 10: OOooOOo / I1ii11iIi11i
 if 21 - 21: OoO0O00 % Oo0Ooo . o0oOOo0O0Ooo + IiII
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 48 - 48: O0 / i1IIi / iII111i
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # iII111i
 red ( dest . print_address ( ) , False ) ) )
 if 51 - 51: OoO0O00
 Ii1II1I = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 45 - 45: I1ii11iIi11i + Ii1I * I1ii11iIi11i % Ii1I - O0 * OoooooooOO
 if 98 - 98: OoO0O00 / o0oOOo0O0Ooo . OoooooooOO % i11iIiiIii % Oo0Ooo + OoOoOO00
 if 49 - 49: II111iiii - OOooOOo - I1IiiI / Ii1I
 if 47 - 47: I1ii11iIi11i + OoO0O00
 if 95 - 95: I11i . OoOoOO00 / Oo0Ooo % ooOoO0o % II111iiii
 if ( lisp_get_eid_hash ( eid ) != None ) :
  Ii1II1I = LISP_SEND_MAP_REQUEST_ACTION
  if 82 - 82: ooOoO0o - I11i / I1Ii111 - i11iIiiIii - iIii1I11I1II1
  if 53 - 53: iIii1I11I1II1 % I11i . i1IIi + IiII / OoOoOO00 . II111iiii
 ii1i1II = lisp_build_map_reply ( eid , group , [ ] , nonce , Ii1II1I , ttl , False ,
 None , False , False )
 if 43 - 43: O0 - IiII + i11iIiiIii * i1IIi - ooOoO0o % IiII
 if 23 - 23: OoooooooOO % o0oOOo0O0Ooo + OoO0O00
 if 25 - 25: IiII % OOooOOo + Ii1I * I1ii11iIi11i
 if 25 - 25: iIii1I11I1II1 * OoOoOO00 % I1IiiI + IiII
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , ii1i1II , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , ii1i1II , dest , port )
  if 34 - 34: ooOoO0o - OoooooooOO . o0oOOo0O0Ooo
 return
 if 83 - 83: II111iiii . OOooOOo
 if 88 - 88: O0
 if 12 - 12: Ii1I % OOooOOo % Oo0Ooo * I1Ii111
 if 96 - 96: iII111i + ooOoO0o
 if 100 - 100: OOooOOo . ooOoO0o + Ii1I + Ii1I
 if 70 - 70: ooOoO0o . iIii1I11I1II1 / oO0o
 if 18 - 18: Ii1I / OoooooooOO % i1IIi * o0oOOo0O0Ooo
def lisp_retransmit_ddt_map_request ( mr ) :
 O0ooO0oOoOo = mr . mr_source . print_address ( )
 oO0ooo0O = mr . print_eid_tuple ( )
 OO00OO = mr . nonce
 if 23 - 23: o0oOOo0O0Ooo * OoO0O00
 if 20 - 20: i11iIiiIii * I1ii11iIi11i * ooOoO0o % iIii1I11I1II1 + iII111i
 if 51 - 51: O0 - I11i . o0oOOo0O0Ooo + o0oOOo0O0Ooo / I1Ii111
 if 32 - 32: II111iiii - Oo0Ooo
 if 69 - 69: o0oOOo0O0Ooo * I1ii11iIi11i / o0oOOo0O0Ooo * OoooooooOO
 if ( mr . last_request_sent_to ) :
  OO0oo = mr . last_request_sent_to . print_address ( )
  iiiI11i1ii1i = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( iiiI11i1ii1i and iiiI11i1ii1i . referral_set . has_key ( OO0oo ) ) :
   iiiI11i1ii1i . referral_set [ OO0oo ] . no_responses += 1
   if 5 - 5: IiII / I1ii11iIi11i + OoO0O00 - II111iiii * OOooOOo
   if 23 - 23: I1Ii111 . ooOoO0o . OoO0O00 . OoO0O00 % ooOoO0o * o0oOOo0O0Ooo
   if 37 - 37: Ii1I . o0oOOo0O0Ooo
   if 34 - 34: ooOoO0o * IiII . Ii1I + iIii1I11I1II1
   if 1 - 1: i11iIiiIii + I11i
   if 78 - 78: Ii1I % Oo0Ooo / OoO0O00 . iIii1I11I1II1 . II111iiii
   if 67 - 67: oO0o % I1Ii111
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( oO0ooo0O , False ) , lisp_hex_string ( OO00OO ) ) )
  if 72 - 72: I1IiiI . i11iIiiIii . OoOoOO00 + I1IiiI - I1Ii111 + iII111i
  mr . dequeue_map_request ( )
  return
  if 15 - 15: I1IiiI
  if 88 - 88: IiII / I1ii11iIi11i % I11i + i11iIiiIii * O0 . I1Ii111
 mr . retry_count += 1
 if 69 - 69: Oo0Ooo - OOooOOo / I1IiiI . i11iIiiIii * OoO0O00
 o0 = green ( O0ooO0oOoOo , False )
 Ii = green ( oO0ooo0O , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # I1IiiI / OOooOOo * Ii1I
 red ( mr . itr . print_address ( ) , False ) , o0 , Ii ,
 lisp_hex_string ( OO00OO ) ) )
 if 50 - 50: OoOoOO00
 if 77 - 77: O0 % Ii1I - I1ii11iIi11i
 if 17 - 17: OoooooooOO - OoooooooOO % I1Ii111 * Ii1I . OoooooooOO
 if 51 - 51: iIii1I11I1II1 % IiII * iIii1I11I1II1 - OoO0O00 % I1IiiI + i11iIiiIii
 lisp_send_ddt_map_request ( mr , False )
 if 33 - 33: I11i
 if 99 - 99: I11i
 if 61 - 61: i1IIi - i1IIi
 if 97 - 97: I11i + II111iiii / OoooooooOO + I1ii11iIi11i * o0oOOo0O0Ooo
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 29 - 29: I1Ii111
 if 95 - 95: OoOoOO00 * II111iiii + I1ii11iIi11i - I11i . I11i % i11iIiiIii
 if 23 - 23: OoO0O00
 if 26 - 26: I1ii11iIi11i
 if 66 - 66: i11iIiiIii - i11iIiiIii / Ii1I * OOooOOo / IiII
 if 67 - 67: I1IiiI . I1Ii111 - OoOoOO00
 if 18 - 18: O0
 if 26 - 26: i1IIi - iIii1I11I1II1
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 8 - 8: I1Ii111
 if 86 - 86: i1IIi
 if 26 - 26: o0oOOo0O0Ooo % I1Ii111 / Oo0Ooo
 if 68 - 68: II111iiii / Oo0Ooo / Oo0Ooo
 i1111i = [ ]
 for IiIiII11 in referral . referral_set . values ( ) :
  if ( IiIiII11 . updown == False ) : continue
  if ( len ( i1111i ) == 0 or i1111i [ 0 ] . priority == IiIiII11 . priority ) :
   i1111i . append ( IiIiII11 )
  elif ( i1111i [ 0 ] . priority > IiIiII11 . priority ) :
   i1111i = [ ]
   i1111i . append ( IiIiII11 )
   if 68 - 68: I1IiiI / Ii1I - i11iIiiIii . Oo0Ooo
   if 78 - 78: Oo0Ooo * OOooOOo
   if 44 - 44: I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
 iIiiIiI1I1ii = len ( i1111i )
 if ( iIiiIiI1I1ii == 0 ) : return ( None )
 if 63 - 63: Oo0Ooo / IiII % o0oOOo0O0Ooo + I1IiiI - iII111i / iII111i
 IiI1I1i1 = dest_eid . hash_address ( source_eid )
 IiI1I1i1 = IiI1I1i1 % iIiiIiI1I1ii
 return ( i1111i [ IiI1I1i1 ] )
 if 88 - 88: O0 * II111iiii
 if 81 - 81: OoOoOO00 % I11i / i1IIi
 if 87 - 87: II111iiii + oO0o - I1ii11iIi11i
 if 42 - 42: Oo0Ooo - ooOoO0o % OoOoOO00 + OoOoOO00
 if 61 - 61: I1Ii111
 if 67 - 67: I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
 if 75 - 75: OOooOOo . ooOoO0o
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 IiI1i = mr . lisp_sockets
 OO00OO = mr . nonce
 oo0O0oO0o = mr . itr
 III11I1II = mr . mr_source
 iiI1Ii1I = mr . print_eid_tuple ( )
 if 51 - 51: I1IiiI + O0
 if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
 if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
 if 85 - 85: OoOoOO00
 if 57 - 57: Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( iiI1Ii1I , False ) , lisp_hex_string ( OO00OO ) ) )
  if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
  mr . dequeue_map_request ( )
  return
  if 72 - 72: Ii1I
  if 22 - 22: o0oOOo0O0Ooo / OoO0O00 + OoOoOO00 + Ii1I . II111iiii * I11i
  if 85 - 85: i11iIiiIii / I11i
  if 28 - 28: i11iIiiIii + IiII / I11i . Ii1I / OoO0O00
  if 100 - 100: o0oOOo0O0Ooo - I11i . o0oOOo0O0Ooo
  if 90 - 90: OoOoOO00 / II111iiii / I11i * I11i - iIii1I11I1II1
 if ( send_to_root ) :
  o0OoOO00O0O0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  O0o0000o00oOO = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( iiI1Ii1I , False ) ) )
 else :
  o0OoOO00O0O0 = mr . eid
  O0o0000o00oOO = mr . group
  if 80 - 80: iIii1I11I1II1 + I11i / oO0o . I1Ii111 + I11i
  if 26 - 26: Oo0Ooo . i11iIiiIii % I1Ii111 . Oo0Ooo + Oo0Ooo + OoOoOO00
  if 100 - 100: IiII * I11i - OOooOOo
  if 11 - 11: I1IiiI % Ii1I + II111iiii
  if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
 oOo00OoOoo = lisp_referral_cache_lookup ( o0OoOO00O0O0 , O0o0000o00oOO , False )
 if ( oOo00OoOoo == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( IiI1i , o0OoOO00O0O0 , O0o0000o00oOO ,
 OO00OO , oo0O0oO0o , mr . sport , 15 , None , False )
  return
  if 65 - 65: I1IiiI - OoO0O00 / iIii1I11I1II1 * iII111i + OoOoOO00 + IiII
  if 16 - 16: OoO0O00 % OOooOOo . I11i . I11i
 Iii11Ii111II1iiiI = oOo00OoOoo . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( Iii11Ii111II1iiiI ,
 oOo00OoOoo . print_referral_type ( ) ) )
 if 28 - 28: OOooOOo - I1ii11iIi11i + i1IIi / OoooooooOO
 IiIiII11 = lisp_get_referral_node ( oOo00OoOoo , III11I1II , mr . eid )
 if ( IiIiII11 == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( IiI1i , oOo00OoOoo . eid ,
 oOo00OoOoo . group , OO00OO , oo0O0oO0o , mr . sport , 1 , None , False )
  return
  if 97 - 97: OoOoOO00 * Oo0Ooo - i1IIi * i11iIiiIii * I1IiiI
  if 23 - 23: Oo0Ooo
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( IiIiII11 . referral_address . print_address ( ) ,
 # Ii1I * I1ii11iIi11i * I1IiiI / OoO0O00 + I1IiiI
 oOo00OoOoo . print_referral_type ( ) , green ( iiI1Ii1I , False ) ,
 lisp_hex_string ( OO00OO ) ) )
 if 4 - 4: I11i
 if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
 if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
 if 60 - 60: OoO0O00 / oO0o . I1IiiI + OoOoOO00 + I1ii11iIi11i % Ii1I
 oo0oOo0Oo0o0 = ( oOo00OoOoo . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 oOo00OoOoo . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( IiI1i , mr . packet , III11I1II , mr . sport , mr . eid ,
 IiIiII11 . referral_address , to_ms = oo0oOo0Oo0o0 , ddt = True )
 if 53 - 53: O0
 if 100 - 100: OoooooooOO . Ii1I / Oo0Ooo
 if 69 - 69: iIii1I11I1II1
 if 70 - 70: i1IIi % iIii1I11I1II1 % II111iiii % OoO0O00 * o0oOOo0O0Ooo % ooOoO0o
 mr . last_request_sent_to = IiIiII11 . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 IiIiII11 . map_requests_sent += 1
 return
 if 1 - 1: OoooooooOO % I11i
 if 8 - 8: Ii1I / IiII - i1IIi - Ii1I
 if 95 - 95: IiII % I11i % iIii1I11I1II1 . OoO0O00
 if 11 - 11: i11iIiiIii - IiII . o0oOOo0O0Ooo / IiII - I1IiiI
 if 66 - 66: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i * OOooOOo % IiII
 if 34 - 34: I1IiiI % I11i - iII111i - i11iIiiIii - iIii1I11I1II1 / i1IIi
 if 7 - 7: I1IiiI + iIii1I11I1II1 . oO0o
 if 17 - 17: OoO0O00 / OoO0O00 + o0oOOo0O0Ooo / OOooOOo . I1ii11iIi11i % IiII
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 40 - 40: OoOoOO00
 I111o0oooO00o0 = map_request . target_eid
 oOoooOOO0o0 = map_request . target_group
 oO0ooo0O = map_request . print_eid_tuple ( )
 O0ooO0oOoOo = mr_source . print_address ( )
 OO00OO = map_request . nonce
 if 81 - 81: Ii1I % I1Ii111 / I1ii11iIi11i % iII111i
 o0 = green ( O0ooO0oOoOo , False )
 Ii = green ( oO0ooo0O , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # iIii1I11I1II1 * O0 / iII111i
 red ( ecm_source . print_address ( ) , False ) , o0 , Ii ,
 lisp_hex_string ( OO00OO ) ) )
 if 75 - 75: Oo0Ooo * IiII % Ii1I
 if 40 - 40: o0oOOo0O0Ooo * i11iIiiIii . ooOoO0o
 if 63 - 63: I1Ii111 / Ii1I - iIii1I11I1II1 / i11iIiiIii / IiII + I11i
 if 57 - 57: iIii1I11I1II1 % iIii1I11I1II1
 ii1 = lisp_ddt_map_request ( lisp_sockets , packet , I111o0oooO00o0 , oOoooOOO0o0 , OO00OO )
 ii1 . packet = packet
 ii1 . itr = ecm_source
 ii1 . mr_source = mr_source
 ii1 . sport = sport
 ii1 . from_pitr = map_request . pitr_bit
 ii1 . queue_map_request ( )
 if 99 - 99: O0 + O0 / IiII / iII111i + OoOoOO00 % I1IiiI
 lisp_send_ddt_map_request ( ii1 , False )
 return
 if 40 - 40: I1IiiI . I1ii11iIi11i - ooOoO0o / o0oOOo0O0Ooo
 if 37 - 37: iII111i * OoOoOO00 % I1ii11iIi11i - I1Ii111
 if 13 - 13: Oo0Ooo + Oo0Ooo
 if 20 - 20: OoO0O00 * OoOoOO00 . OOooOOo
 if 14 - 14: iII111i / i1IIi + II111iiii
 if 54 - 54: Ii1I - I1IiiI + iII111i * iII111i
 if 78 - 78: I1Ii111
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl ) :
 if 79 - 79: IiII * IiII . OOooOOo + iIii1I11I1II1 . II111iiii
 IiIIIii1iIII1 = packet
 oOOooOoo0O = lisp_map_request ( )
 packet = oOOooOoo0O . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
  if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
 oOOooOoo0O . print_map_request ( )
 if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
 if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
 if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
 if 45 - 45: iIii1I11I1II1 . o0oOOo0O0Ooo % I1IiiI
 if ( oOOooOoo0O . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , oOOooOoo0O ,
 mr_source , mr_port , ttl )
  return
  if 10 - 10: I1IiiI / i1IIi * o0oOOo0O0Ooo + Oo0Ooo - OoOoOO00 % iII111i
  if 88 - 88: Ii1I % Ii1I
  if 29 - 29: OOooOOo % I1ii11iIi11i
  if 57 - 57: I1ii11iIi11i - OoOoOO00 + IiII
  if 58 - 58: OOooOOo % I1IiiI / oO0o . ooOoO0o . OoO0O00 / IiII
 if ( oOOooOoo0O . smr_bit ) :
  lisp_process_smr ( oOOooOoo0O )
  if 72 - 72: ooOoO0o + ooOoO0o + o0oOOo0O0Ooo - o0oOOo0O0Ooo % Ii1I
  if 52 - 52: I11i % i1IIi . I1ii11iIi11i
  if 62 - 62: ooOoO0o - I1ii11iIi11i
  if 71 - 71: I11i
  if 34 - 34: oO0o / O0 * oO0o
 if ( oOOooOoo0O . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( oOOooOoo0O )
  if 47 - 47: iIii1I11I1II1 - o0oOOo0O0Ooo % Ii1I
  if 38 - 38: ooOoO0o / IiII * I1ii11iIi11i % I1ii11iIi11i % oO0o
  if 82 - 82: I1ii11iIi11i . i11iIiiIii - I11i . iII111i / OOooOOo
  if 60 - 60: I1IiiI / I1IiiI / II111iiii
  if 59 - 59: OOooOOo . oO0o + ooOoO0o % o0oOOo0O0Ooo . i11iIiiIii
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , oOOooOoo0O , mr_source ,
 mr_port , ttl )
  if 27 - 27: OoOoOO00 - OoooooooOO / IiII / II111iiii * OOooOOo * ooOoO0o
  if 43 - 43: II111iiii . IiII - I1IiiI * I1ii11iIi11i + OoooooooOO
  if 34 - 34: I1Ii111 / i1IIi
  if 95 - 95: OoOoOO00 * OOooOOo
  if 68 - 68: I1Ii111 / iIii1I11I1II1 % Ii1I
 if ( lisp_i_am_ms ) :
  packet = IiIIIii1iIII1
  I111o0oooO00o0 , oOoooOOO0o0 , OoOo0OO = lisp_ms_process_map_request ( lisp_sockets ,
 IiIIIii1iIII1 , oOOooOoo0O , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , oOOooOoo0O , ecm_source ,
 ecm_port , OoOo0OO , I111o0oooO00o0 , oOoooOOO0o0 )
   if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
  return
  if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
  if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
  if 77 - 77: OOooOOo + ooOoO0o / O0
  if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
  if 49 - 49: ooOoO0o . Ii1I
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , IiIIIii1iIII1 , oOOooOoo0O ,
 ecm_source , mr_port , mr_source )
  if 75 - 75: OOooOOo / II111iiii - Oo0Ooo + I1Ii111
  if 42 - 42: OoooooooOO * II111iiii + Ii1I % OoO0O00 / I1Ii111
  if 11 - 11: ooOoO0o / Oo0Ooo + i1IIi / IiII
  if 4 - 4: iII111i - Oo0Ooo
  if 100 - 100: OOooOOo . i1IIi
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = IiIIIii1iIII1
  lisp_ddt_process_map_request ( lisp_sockets , oOOooOoo0O , ecm_source ,
 ecm_port )
  if 15 - 15: O0 % Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o * iII111i % O0
 return
 if 31 - 31: i1IIi . Ii1I - OoooooooOO * I11i * ooOoO0o % oO0o
 if 61 - 61: I1Ii111 . Ii1I * I1ii11iIi11i
 if 59 - 59: OoOoOO00 + Oo0Ooo . I1ii11iIi11i - Ii1I
 if 48 - 48: I1Ii111 % Ii1I + I1IiiI * OoooooooOO % OoOoOO00 % i11iIiiIii
 if 13 - 13: iII111i % i1IIi
 if 13 - 13: iII111i / OoooooooOO + Ii1I / iII111i
 if 29 - 29: OOooOOo + ooOoO0o % o0oOOo0O0Ooo
 if 18 - 18: I11i + OoO0O00 + OoO0O00 . ooOoO0o
def lisp_store_mr_stats ( source , nonce ) :
 ii1 = lisp_get_map_resolver ( source , None )
 if ( ii1 == None ) : return
 if 37 - 37: i1IIi . IiII + I1IiiI % OoOoOO00
 if 3 - 3: i11iIiiIii + Ii1I % IiII - I1Ii111 / Oo0Ooo % iIii1I11I1II1
 if 86 - 86: Oo0Ooo + Oo0Ooo * oO0o * I1IiiI
 if 95 - 95: IiII - OoO0O00 + OOooOOo
 ii1 . neg_map_replies_received += 1
 ii1 . last_reply = lisp_get_timestamp ( )
 if 33 - 33: o0oOOo0O0Ooo . i11iIiiIii . ooOoO0o
 if 100 - 100: i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / i11iIiiIii + OOooOOo
 if 55 - 55: i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
 if 60 - 60: OoOoOO00 / i1IIi . Ii1I - OoO0O00 - OoooooooOO
 if ( ( ii1 . neg_map_replies_received % 100 ) == 0 ) : ii1 . total_rtt = 0
 if 39 - 39: I1IiiI + i1IIi * OoO0O00 % I11i
 if 41 - 41: I1ii11iIi11i * IiII
 if 16 - 16: I1Ii111 % iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / OoOoOO00
 if 29 - 29: OoooooooOO / oO0o
 if ( ii1 . last_nonce == nonce ) :
  ii1 . total_rtt += ( time . time ( ) - ii1 . last_used )
  ii1 . last_nonce = 0
  if 1 - 1: OoOoOO00 . i11iIiiIii % I1Ii111 + OoooooooOO - Oo0Ooo . I1ii11iIi11i
 if ( ( ii1 . neg_map_replies_received % 10 ) == 0 ) : ii1 . last_nonce = 0
 return
 if 46 - 46: i11iIiiIii + I11i - iIii1I11I1II1 / OoO0O00 - ooOoO0o / i1IIi
 if 44 - 44: o0oOOo0O0Ooo + Oo0Ooo
 if 46 - 46: OOooOOo % I1IiiI
 if 66 - 66: iIii1I11I1II1 . o0oOOo0O0Ooo - ooOoO0o
 if 27 - 27: Oo0Ooo - i1IIi * OoooooooOO - OoOoOO00 + OoOoOO00
 if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
 if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl ) :
 global lisp_map_cache
 if 85 - 85: iII111i % i11iIiiIii
 iIiiIIiI1I = lisp_map_reply ( )
 packet = iIiiIIiI1I . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
 iIiiIIiI1I . print_map_reply ( )
 if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
 if 41 - 41: Ii1I + IiII
 if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
 if 53 - 53: I1IiiI % OOooOOo + Ii1I - Ii1I
 ooOOoOOoOOoOO = None
 for i1i1IIIIIIIi in range ( iIiiIIiI1I . record_count ) :
  OOoo = lisp_eid_record ( )
  packet = OOoo . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 50 - 50: ooOoO0o * Ii1I % II111iiii % OOooOOo * OoO0O00
  OOoo . print_record ( "  " , False )
  if 15 - 15: IiII * ooOoO0o % I11i
  if 69 - 69: OoO0O00
  if 24 - 24: OoO0O00 * iIii1I11I1II1
  if 52 - 52: i11iIiiIii + OOooOOo - I11i
  if 43 - 43: OoOoOO00
  if ( OOoo . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , iIiiIIiI1I . nonce )
   if 32 - 32: ooOoO0o * OoO0O00 * oO0o / I1ii11iIi11i
   if 72 - 72: I1ii11iIi11i * ooOoO0o % I1IiiI % OoOoOO00
  O0O0OOoO00 = ( OOoo . group . is_null ( ) == False )
  if 4 - 4: i11iIiiIii % OoooooooOO . i11iIiiIii
  if 61 - 61: iIii1I11I1II1 . Oo0Ooo . i1IIi
  if 45 - 45: I1Ii111
  if 49 - 49: i1IIi * iII111i - iIii1I11I1II1 % I11i * O0 / OoOoOO00
  if 48 - 48: IiII
  if ( lisp_decent_push_configured ) :
   Ii1II1I = OOoo . action
   if ( O0O0OOoO00 and Ii1II1I == LISP_DROP_ACTION ) :
    if ( OOoo . eid . is_local ( ) ) : continue
    if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - o0oOOo0O0Ooo
    if 98 - 98: o0oOOo0O0Ooo * OoO0O00 . OoooooooOO
    if 40 - 40: I1Ii111 + Oo0Ooo + I1Ii111
    if 57 - 57: I1Ii111 / II111iiii % iII111i
    if 32 - 32: IiII - OOooOOo + i11iIiiIii + I1IiiI . iII111i
    if 75 - 75: o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1IiiI / OoO0O00
    if 22 - 22: Oo0Ooo / iIii1I11I1II1 + o0oOOo0O0Ooo
  if ( OOoo . eid . is_null ( ) ) : continue
  if 16 - 16: II111iiii . Ii1I + I1Ii111 % i1IIi / i11iIiiIii + OOooOOo
  if 43 - 43: I1IiiI . Oo0Ooo + i1IIi + I11i / OoO0O00
  if 66 - 66: i11iIiiIii
  if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
  if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
  if ( O0O0OOoO00 ) :
   OoOoooooO00oo = lisp_map_cache_lookup ( OOoo . eid , OOoo . group )
  else :
   OoOoooooO00oo = lisp_map_cache . lookup_cache ( OOoo . eid , True )
   if 73 - 73: Ii1I . II111iiii
  oO0O0i11ii11i1 = ( OoOoooooO00oo == None )
  if 88 - 88: o0oOOo0O0Ooo * OoOoOO00 % I1IiiI . OOooOOo / Oo0Ooo
  if 74 - 74: I1ii11iIi11i
  if 95 - 95: i11iIiiIii + I1ii11iIi11i
  if 97 - 97: ooOoO0o * iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - o0oOOo0O0Ooo
  if 37 - 37: II111iiii
  if ( OoOoooooO00oo == None ) :
   iIiiIIiIII1i1 , OoOO0OOOO0 , oOoOoO0Oo0oo = lisp_allow_gleaning ( OOoo . eid , OOoo . group ,
 None )
   if ( iIiiIIiIII1i1 ) : continue
  else :
   if ( OoOoooooO00oo . gleaned ) : continue
   if 89 - 89: I11i + I1IiiI - II111iiii
   if 4 - 4: I1ii11iIi11i
   if 51 - 51: I1Ii111 . O0 - OoOoOO00 + i11iIiiIii * II111iiii
   if 39 - 39: iII111i . OoO0O00 % I1IiiI * II111iiii * OoooooooOO . II111iiii
   if 97 - 97: oO0o - Ii1I - II111iiii % II111iiii * OOooOOo
  iio0OOoO0 = [ ]
  for Oo0iIIiiIiiI in range ( OOoo . rloc_count ) :
   O0000O00O00OO = lisp_rloc_record ( )
   O0000O00O00OO . keys = iIiiIIiI1I . keys
   packet = O0000O00O00OO . decode ( packet , iIiiIIiI1I . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 33 - 33: IiII
   O0000O00O00OO . print_record ( "    " )
   if 82 - 82: iII111i . OOooOOo / II111iiii / II111iiii % Ii1I
   iiiIii = None
   if ( OoOoooooO00oo ) : iiiIii = OoOoooooO00oo . get_rloc ( O0000O00O00OO . rloc )
   if ( iiiIii ) :
    OooO0ooO0o0OO = iiiIii
   else :
    OooO0ooO0o0OO = lisp_rloc ( )
    if 82 - 82: O0 . I1Ii111 - IiII
    if 37 - 37: i11iIiiIii
    if 67 - 67: ooOoO0o . Oo0Ooo
    if 15 - 15: OoO0O00 . oO0o - o0oOOo0O0Ooo
    if 28 - 28: OOooOOo * OoOoOO00 + OoooooooOO . OOooOOo / oO0o / OoOoOO00
    if 94 - 94: OoO0O00 / i1IIi . OoO0O00 . I1Ii111 + OoO0O00
    if 30 - 30: o0oOOo0O0Ooo + iIii1I11I1II1 - II111iiii - ooOoO0o + OoOoOO00 - II111iiii
   IIi1I1iII111 = OooO0ooO0o0OO . store_rloc_from_record ( O0000O00O00OO , iIiiIIiI1I . nonce ,
 source )
   OooO0ooO0o0OO . echo_nonce_capable = iIiiIIiI1I . echo_nonce_capable
   if 69 - 69: oO0o / O0 / I1IiiI + OoooooooOO * I11i * IiII
   if ( OooO0ooO0o0OO . echo_nonce_capable ) :
    oOo0O = OooO0ooO0o0OO . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , oOo0O ) == None ) :
     lisp_echo_nonce ( oOo0O )
     if 41 - 41: ooOoO0o % i11iIiiIii
     if 69 - 69: IiII - oO0o
     if 21 - 21: Oo0Ooo / I1Ii111
     if 72 - 72: OoOoOO00 . i11iIiiIii
     if 25 - 25: i1IIi
     if 69 - 69: OOooOOo / Ii1I
     if 67 - 67: i11iIiiIii . II111iiii + OoooooooOO % o0oOOo0O0Ooo + IiII * i1IIi
     if 53 - 53: oO0o * OoooooooOO + II111iiii . IiII * I1ii11iIi11i
     if 55 - 55: OoOoOO00
     if 27 - 27: I1IiiI
   if ( iIiiIIiI1I . rloc_probe and O0000O00O00OO . probe_bit ) :
    if ( OooO0ooO0o0OO . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( OooO0ooO0o0OO . rloc , source , IIi1I1iII111 ,
 iIiiIIiI1I . nonce , iIiiIIiI1I . hop_count , ttl )
     if 81 - 81: Oo0Ooo
     if 43 - 43: i1IIi * O0 + ooOoO0o + OoO0O00
     if 99 - 99: IiII . OoOoOO00
     if 64 - 64: I1Ii111
     if 96 - 96: Ii1I
     if 100 - 100: ooOoO0o
   iio0OOoO0 . append ( OooO0ooO0o0OO )
   if 43 - 43: Ii1I * ooOoO0o + O0 . II111iiii
   if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
   if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
   if 5 - 5: OoooooooOO + ooOoO0o - II111iiii . i11iIiiIii / oO0o - ooOoO0o
   if ( lisp_data_plane_security and OooO0ooO0o0OO . rloc_recent_rekey ( ) ) :
    ooOOoOOoOOoOO = OooO0ooO0o0OO
    if 3 - 3: iII111i
    if 74 - 74: i11iIiiIii + OoooooooOO . OOooOOo
    if 29 - 29: IiII % OoO0O00
    if 53 - 53: OoooooooOO - OoOoOO00 / IiII - I1Ii111
    if 16 - 16: iIii1I11I1II1 / OOooOOo + I1IiiI * II111iiii . OOooOOo
    if 68 - 68: IiII * IiII + oO0o / o0oOOo0O0Ooo
    if 41 - 41: OoOoOO00 - O0
    if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
    if 53 - 53: ooOoO0o + oO0o - II111iiii
    if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
    if 6 - 6: iIii1I11I1II1 + oO0o
  if ( iIiiIIiI1I . rloc_probe == False and lisp_nat_traversal ) :
   i11i1i11ii11I = [ ]
   iIIiii = [ ]
   for OooO0ooO0o0OO in iio0OOoO0 :
    if 76 - 76: II111iiii - O0 . O0 + OoooooooOO - I1Ii111
    if 21 - 21: OoO0O00 * ooOoO0o
    if 81 - 81: i1IIi % I11i * iIii1I11I1II1
    if 39 - 39: iIii1I11I1II1 / O0 . OoooooooOO - O0 . OoO0O00 . oO0o
    if 59 - 59: II111iiii * I1IiiI
    if ( OooO0ooO0o0OO . rloc . is_private_address ( ) ) :
     OooO0ooO0o0OO . priority = 1
     OooO0ooO0o0OO . state = LISP_RLOC_UNREACH_STATE
     i11i1i11ii11I . append ( OooO0ooO0o0OO )
     iIIiii . append ( OooO0ooO0o0OO . rloc . print_address_no_iid ( ) )
     continue
     if 12 - 12: i11iIiiIii - IiII . iII111i . Ii1I
     if 34 - 34: i1IIi % iII111i + Oo0Ooo * OoOoOO00 + OoO0O00
     if 37 - 37: I1Ii111 / OoooooooOO
     if 19 - 19: Ii1I - O0 + I1IiiI + OoooooooOO + ooOoO0o - Oo0Ooo
     if 45 - 45: I1IiiI . OoOoOO00 . OoOoOO00
     if 20 - 20: OoOoOO00
    if ( OooO0ooO0o0OO . priority == 254 and lisp_i_am_rtr == False ) :
     i11i1i11ii11I . append ( OooO0ooO0o0OO )
     iIIiii . append ( OooO0ooO0o0OO . rloc . print_address_no_iid ( ) )
     if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
    if ( OooO0ooO0o0OO . priority != 254 and lisp_i_am_rtr ) :
     i11i1i11ii11I . append ( OooO0ooO0o0OO )
     iIIiii . append ( OooO0ooO0o0OO . rloc . print_address_no_iid ( ) )
     if 93 - 93: OoO0O00 % IiII % ooOoO0o . I1IiiI
     if 96 - 96: II111iiii
     if 73 - 73: II111iiii
   if ( iIIiii != [ ] ) :
    iio0OOoO0 = i11i1i11ii11I
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( iIIiii ) )
    if 81 - 81: I1IiiI + OoO0O00
    if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
    if 32 - 32: o0oOOo0O0Ooo - iII111i + i11iIiiIii / ooOoO0o . OoOoOO00 . IiII
    if 9 - 9: iIii1I11I1II1
    if 66 - 66: iIii1I11I1II1
    if 13 - 13: O0 / ooOoO0o
    if 64 - 64: i11iIiiIii + I1IiiI / Oo0Ooo - iII111i
  i11i1i11ii11I = [ ]
  for OooO0ooO0o0OO in iio0OOoO0 :
   if ( OooO0ooO0o0OO . json != None ) : continue
   i11i1i11ii11I . append ( OooO0ooO0o0OO )
   if 26 - 26: I1ii11iIi11i
  if ( i11i1i11ii11I != [ ] ) :
   OoO = len ( iio0OOoO0 ) - len ( i11i1i11ii11I )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( OoO ) )
   if 67 - 67: I1Ii111 * iIii1I11I1II1 / O0 + OoO0O00 * iIii1I11I1II1 % II111iiii
   iio0OOoO0 = i11i1i11ii11I
   if 13 - 13: Ii1I / ooOoO0o / iII111i % II111iiii * I1IiiI * II111iiii
   if 40 - 40: Ii1I / i1IIi . iII111i
   if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
   if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
   if 85 - 85: I1IiiI + i1IIi % I1Ii111
   if 76 - 76: i11iIiiIii % i11iIiiIii
   if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
   if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
  if ( iIiiIIiI1I . rloc_probe and OoOoooooO00oo != None ) : iio0OOoO0 = OoOoooooO00oo . rloc_set
  if 69 - 69: O0 % I1ii11iIi11i
  if 77 - 77: iIii1I11I1II1 . OOooOOo
  if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
  if 61 - 61: OOooOOo
  if 51 - 51: Oo0Ooo * OOooOOo / iII111i
  I1 = oO0O0i11ii11i1
  if ( OoOoooooO00oo and iio0OOoO0 != OoOoooooO00oo . rloc_set ) :
   OoOoooooO00oo . delete_rlocs_from_rloc_probe_list ( )
   I1 = True
   if 80 - 80: I1Ii111 . iIii1I11I1II1
   if 33 - 33: OoO0O00 - I11i - Oo0Ooo
   if 57 - 57: I1Ii111 % i11iIiiIii
   if 36 - 36: O0 . I11i / o0oOOo0O0Ooo + i1IIi + oO0o * IiII
   if 29 - 29: O0 - II111iiii + iII111i
  O0O0O0OOO = OoOoooooO00oo . uptime if ( OoOoooooO00oo ) else None
  if ( OoOoooooO00oo == None ) :
   OoOoooooO00oo = lisp_mapping ( OOoo . eid , OOoo . group , iio0OOoO0 )
   OoOoooooO00oo . mapping_source = source
   OoOoooooO00oo . map_cache_ttl = OOoo . store_ttl ( )
   OoOoooooO00oo . action = OOoo . action
   OoOoooooO00oo . add_cache ( I1 )
   if 74 - 74: Ii1I + iIii1I11I1II1 . iII111i * OoOoOO00
   if 59 - 59: iIii1I11I1II1 * OoooooooOO % O0 / I1IiiI
  i1O0OO00 = "Add"
  if ( O0O0O0OOO ) :
   OoOoooooO00oo . uptime = O0O0O0OOO
   OoOoooooO00oo . refresh_time = lisp_get_timestamp ( )
   i1O0OO00 = "Replace"
   if 96 - 96: Ii1I / OoOoOO00
   if 71 - 71: OOooOOo / i1IIi
  lprint ( "{} {} map-cache with {} RLOCs" . format ( i1O0OO00 ,
 green ( OoOoooooO00oo . print_eid_tuple ( ) , False ) , len ( iio0OOoO0 ) ) )
  if 50 - 50: iIii1I11I1II1 * IiII
  if 73 - 73: II111iiii
  if 4 - 4: II111iiii * o0oOOo0O0Ooo + I11i . II111iiii
  if 35 - 35: ooOoO0o - ooOoO0o . i1IIi % oO0o * IiII * I1ii11iIi11i
  if 36 - 36: OoOoOO00 % ooOoO0o - Oo0Ooo - OoooooooOO % I1ii11iIi11i / OoOoOO00
  if ( lisp_ipc_dp_socket and ooOOoOOoOOoOO != None ) :
   lisp_write_ipc_keys ( ooOOoOOoOOoOO )
   if 23 - 23: ooOoO0o . O0 % O0 - iIii1I11I1II1 / IiII
   if 8 - 8: i11iIiiIii . Oo0Ooo / i11iIiiIii % IiII
   if 41 - 41: iII111i * I11i % OoooooooOO * iIii1I11I1II1
   if 73 - 73: I1Ii111 * I1ii11iIi11i
   if 79 - 79: I11i / O0 % Ii1I % I1ii11iIi11i
   if 21 - 21: OoOoOO00 . ooOoO0o * OoO0O00 - OoOoOO00 - OoooooooOO
   if 23 - 23: I1Ii111 + iIii1I11I1II1 - o0oOOo0O0Ooo - iII111i - O0 / iIii1I11I1II1
  if ( oO0O0i11ii11i1 ) :
   Ii1I11IiI1I1 = bold ( "RLOC-probe" , False )
   for OooO0ooO0o0OO in OoOoooooO00oo . best_rloc_set :
    oOo0O = red ( OooO0ooO0o0OO . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( Ii1I11IiI1I1 , oOo0O ) )
    lisp_send_map_request ( lisp_sockets , 0 , OoOoooooO00oo . eid , OoOoooooO00oo . group , OooO0ooO0o0OO )
    if 24 - 24: i1IIi
    if 21 - 21: II111iiii
    if 27 - 27: I1IiiI * i11iIiiIii
 return
 if 86 - 86: I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - i1IIi . I11i / OOooOOo
 if 78 - 78: I1ii11iIi11i
 if 18 - 18: ooOoO0o / I1Ii111 . o0oOOo0O0Ooo % OoOoOO00
 if 60 - 60: I1IiiI . Oo0Ooo + ooOoO0o + OoO0O00
 if 30 - 30: I1Ii111 * i1IIi
 if 4 - 4: OoO0O00 + O0 * OOooOOo * I1Ii111 / O0
 if 58 - 58: OOooOOo % ooOoO0o * I1IiiI - I1ii11iIi11i / I11i + iII111i
 if 26 - 26: OoOoOO00
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 63 - 63: I1Ii111 . oO0o + OoO0O00 / I1ii11iIi11i % IiII * II111iiii
 packet = map_register . zero_auth ( packet )
 IiI1I1i1 = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 92 - 92: iIii1I11I1II1 . OoooooooOO . ooOoO0o / II111iiii
 if 30 - 30: i1IIi * Ii1I + Ii1I / I1Ii111
 if 84 - 84: I1IiiI - Oo0Ooo * OoO0O00 * oO0o
 if 13 - 13: I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + oO0o - iII111i
 map_register . auth_data = IiI1I1i1
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 32 - 32: I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * I1Ii111 % II111iiii
 if 33 - 33: ooOoO0o % I11i
 if 72 - 72: OoO0O00 % OoooooooOO / II111iiii * oO0o * I1Ii111
 if 98 - 98: OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / OoOoOO00 + I1IiiI
 if 74 - 74: ooOoO0o . IiII . O0 * I1IiiI * oO0o
 if 6 - 6: O0 . Ii1I / Oo0Ooo * o0oOOo0O0Ooo
 if 1 - 1: i11iIiiIii
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 30 - 30: I11i
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  iI1i11IIi = hashlib . sha1
  if 100 - 100: IiII - iIii1I11I1II1 + O0 + ooOoO0o
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  iI1i11IIi = hashlib . sha256
  if 54 - 54: I11i - o0oOOo0O0Ooo . IiII / Oo0Ooo % OoooooooOO
  if 66 - 66: OOooOOo
 if ( do_hex ) :
  IiI1I1i1 = hmac . new ( password , packet , iI1i11IIi ) . hexdigest ( )
 else :
  IiI1I1i1 = hmac . new ( password , packet , iI1i11IIi ) . digest ( )
  if 37 - 37: i1IIi . I1IiiI
 return ( IiI1I1i1 )
 if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
 if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
 if 6 - 6: O0 * I1Ii111 - II111iiii
 if 60 - 60: oO0o % oO0o
 if 76 - 76: I1Ii111 / o0oOOo0O0Ooo
 if 19 - 19: O0 . i1IIi % iIii1I11I1II1 + OOooOOo * OoOoOO00 / I11i
 if 82 - 82: I1ii11iIi11i
 if 75 - 75: I11i - II111iiii
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 84 - 84: I1ii11iIi11i * IiII / I1IiiI - Ii1I + IiII - i1IIi
 IiI1I1i1 = lisp_hash_me ( packet , alg_id , password , True )
 Oo00Oo00O = ( IiI1I1i1 == auth_data )
 if 67 - 67: iII111i + OoOoOO00 * o0oOOo0O0Ooo / II111iiii / iIii1I11I1II1
 if 12 - 12: o0oOOo0O0Ooo
 if 13 - 13: o0oOOo0O0Ooo
 if 45 - 45: OoO0O00 % OoO0O00 % O0
 if ( Oo00Oo00O == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( IiI1I1i1 , auth_data ) )
  if 62 - 62: IiII - iII111i . I1ii11iIi11i . oO0o
  if 22 - 22: OoOoOO00 * i11iIiiIii * Ii1I
 return ( Oo00Oo00O )
 if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
 if 5 - 5: OoO0O00 / ooOoO0o
 if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
 if 97 - 97: oO0o / Ii1I
 if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
 if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
 if 91 - 91: IiII * Ii1I * OOooOOo
def lisp_retransmit_map_notify ( map_notify ) :
 oO00o0oOoo = map_notify . etr
 IIi1I1iII111 = map_notify . etr_port
 if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
 if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
 if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
 if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
 if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( oO00o0oOoo . print_address ( ) , False ) ) )
  if 95 - 95: IiII + iII111i % I1IiiI
  if 18 - 18: Oo0Ooo
  iII1 = map_notify . nonce_key
  if ( lisp_map_notify_queue . has_key ( iII1 ) ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( iII1 ) )
   if 8 - 8: O0 + iIii1I11I1II1 - O0
   try :
    lisp_map_notify_queue . pop ( iII1 )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 67 - 67: O0
    if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
  return
  if 28 - 28: O0 - Oo0Ooo
  if 58 - 58: iIii1I11I1II1 - OoooooooOO - iII111i
 IiI1i = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 43 - 43: ooOoO0o / o0oOOo0O0Ooo
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # I1Ii111 * I1Ii111 / O0 - O0
 red ( oO00o0oOoo . print_address ( ) , False ) , map_notify . retry_count ) )
 if 15 - 15: I1ii11iIi11i % ooOoO0o * oO0o * OoO0O00 + OoO0O00
 lisp_send_map_notify ( IiI1i , map_notify . packet , oO00o0oOoo , IIi1I1iII111 )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 58 - 58: I1ii11iIi11i
 if 93 - 93: i1IIi - IiII + IiII % OoooooooOO / o0oOOo0O0Ooo
 if 39 - 39: I1IiiI + Ii1I - O0
 if 25 - 25: IiII % iIii1I11I1II1 + ooOoO0o % iII111i - OoO0O00
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 36 - 36: OoooooooOO / oO0o + IiII . I1IiiI - o0oOOo0O0Ooo % OOooOOo
 if 15 - 15: Ii1I % IiII + IiII % iII111i - O0 * OoooooooOO
 if 53 - 53: OoOoOO00 . Ii1I / Oo0Ooo
 if 62 - 62: i11iIiiIii
 if 38 - 38: I1ii11iIi11i % ooOoO0o * OoooooooOO + iIii1I11I1II1 % i1IIi / OOooOOo
 if 6 - 6: i11iIiiIii
 if 8 - 8: iIii1I11I1II1 + I1ii11iIi11i . i1IIi % OoOoOO00 % OoooooooOO * Oo0Ooo
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 53 - 53: oO0o
 if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
 if 4 - 4: I1IiiI
 if 31 - 31: ooOoO0o * i1IIi . O0
 eid_record . rloc_count = len ( parent . registered_rlocs )
 III1I = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 96 - 96: i11iIiiIii * I11i * ooOoO0o % i1IIi * i1IIi
 if 84 - 84: i11iIiiIii - IiII * O0
 if 89 - 89: OoooooooOO / iII111i
 if 98 - 98: IiII . OOooOOo * ooOoO0o / OoO0O00
 for i1IIiOoO000o00o00O in parent . registered_rlocs :
  O0000O00O00OO = lisp_rloc_record ( )
  O0000O00O00OO . store_rloc_entry ( i1IIiOoO000o00o00O )
  III1I += O0000O00O00OO . encode ( )
  O0000O00O00OO . print_record ( "  " )
  del ( O0000O00O00OO )
  if 9 - 9: O0 / iIii1I11I1II1
  if 95 - 95: ooOoO0o * OoO0O00 % OoooooooOO % OoO0O00
  if 79 - 79: II111iiii % Ii1I * oO0o * iII111i + II111iiii
  if 51 - 51: I1IiiI + iII111i + I1IiiI / Ii1I * IiII + OOooOOo
  if 70 - 70: I11i . IiII + IiII
 for i1IIiOoO000o00o00O in parent . registered_rlocs :
  oO00o0oOoo = i1IIiOoO000o00o00O . rloc
  oooO0oo0ooO = lisp_map_notify ( lisp_sockets )
  oooO0oo0ooO . record_count = 1
  o0O = map_register . key_id
  oooO0oo0ooO . key_id = o0O
  oooO0oo0ooO . alg_id = map_register . alg_id
  oooO0oo0ooO . auth_len = map_register . auth_len
  oooO0oo0ooO . nonce = map_register . nonce
  oooO0oo0ooO . nonce_key = lisp_hex_string ( oooO0oo0ooO . nonce )
  oooO0oo0ooO . etr . copy_address ( oO00o0oOoo )
  oooO0oo0ooO . etr_port = map_register . sport
  oooO0oo0ooO . site = parent . site
  ii1i1II = oooO0oo0ooO . encode ( III1I , parent . site . auth_key [ o0O ] )
  oooO0oo0ooO . print_notify ( )
  if 79 - 79: i11iIiiIii * OoooooooOO
  if 50 - 50: I1IiiI * II111iiii . I1Ii111 / I1Ii111
  if 28 - 28: ooOoO0o
  if 27 - 27: OoO0O00
  iII1 = oooO0oo0ooO . nonce_key
  if ( lisp_map_notify_queue . has_key ( iII1 ) ) :
   o00o0o0O = lisp_map_notify_queue [ iII1 ]
   o00o0o0O . retransmit_timer . cancel ( )
   del ( o00o0o0O )
   if 98 - 98: II111iiii + ooOoO0o - iIii1I11I1II1 . I11i . iIii1I11I1II1 - iIii1I11I1II1
  lisp_map_notify_queue [ iII1 ] = oooO0oo0ooO
  if 91 - 91: ooOoO0o
  if 66 - 66: OOooOOo
  if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
  if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( oO00o0oOoo . print_address ( ) , False ) ) )
  if 9 - 9: Ii1I
  lisp_send ( lisp_sockets , oO00o0oOoo , LISP_CTRL_PORT , ii1i1II )
  if 44 - 44: iII111i
  parent . site . map_notifies_sent += 1
  if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
  if 37 - 37: OoO0O00 - Ii1I + OoO0O00
  if 49 - 49: OoooooooOO - I1ii11iIi11i % I1ii11iIi11i / i1IIi . ooOoO0o
  if 60 - 60: Oo0Ooo
  oooO0oo0ooO . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ oooO0oo0ooO ] )
  oooO0oo0ooO . retransmit_timer . start ( )
  if 46 - 46: OoOoOO00 + i1IIi
 return
 if 43 - 43: II111iiii * IiII % iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
 if 81 - 81: oO0o % I1ii11iIi11i % ooOoO0o * O0 - OOooOOo
 if 17 - 17: O0 % O0 / I1ii11iIi11i . Oo0Ooo . iII111i
 if 4 - 4: OoO0O00
 if 65 - 65: Oo0Ooo % O0 / I1Ii111 * IiII - oO0o
 if 32 - 32: Ii1I * OoO0O00 + ooOoO0o
 if 41 - 41: IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 38 - 38: iII111i * OoooooooOO - IiII
 iII1 = lisp_hex_string ( nonce ) + source . print_address ( )
 if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
 if 91 - 91: O0 + I1Ii111 * II111iiii - O0 . i11iIiiIii . Oo0Ooo
 if 54 - 54: ooOoO0o * I11i / I1ii11iIi11i % ooOoO0o
 if 76 - 76: I11i . I1IiiI
 if 66 - 66: oO0o % oO0o * IiII
 if 39 - 39: i1IIi * Ii1I + OoOoOO00 / oO0o
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( lisp_map_notify_queue . has_key ( iII1 ) ) :
  oooO0oo0ooO = lisp_map_notify_queue [ iII1 ]
  o0 = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( oooO0oo0ooO . nonce ) , o0 ) )
  if 6 - 6: I1ii11iIi11i / II111iiii / OoOoOO00 . i11iIiiIii - iII111i
  return
  if 43 - 43: i11iIiiIii * i11iIiiIii * I1Ii111
  if 80 - 80: oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / o0oOOo0O0Ooo % OoooooooOO
 oooO0oo0ooO = lisp_map_notify ( lisp_sockets )
 oooO0oo0ooO . record_count = record_count
 key_id = key_id
 oooO0oo0ooO . key_id = key_id
 oooO0oo0ooO . alg_id = alg_id
 oooO0oo0ooO . auth_len = auth_len
 oooO0oo0ooO . nonce = nonce
 oooO0oo0ooO . nonce_key = lisp_hex_string ( nonce )
 oooO0oo0ooO . etr . copy_address ( source )
 oooO0oo0ooO . etr_port = port
 oooO0oo0ooO . site = site
 oooO0oo0ooO . eid_list = eid_list
 if 31 - 31: o0oOOo0O0Ooo - OoO0O00 % I1IiiI
 if 23 - 23: OOooOOo
 if 97 - 97: Oo0Ooo / OoooooooOO . OoooooooOO
 if 47 - 47: OoO0O00
 if ( map_register_ack == False ) :
  iII1 = oooO0oo0ooO . nonce_key
  lisp_map_notify_queue [ iII1 ] = oooO0oo0ooO
  if 52 - 52: I1IiiI * iIii1I11I1II1 % oO0o * IiII % oO0o
  if 9 - 9: I11i
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 83 - 83: i11iIiiIii
  if 72 - 72: oO0o + II111iiii . O0 * oO0o + iII111i
  if 22 - 22: I11i + Ii1I . IiII - OoO0O00 - o0oOOo0O0Ooo
  if 84 - 84: OoooooooOO - Oo0Ooo
  if 86 - 86: O0 + OoO0O00 + O0 . I1IiiI
 ii1i1II = oooO0oo0ooO . encode ( eid_records , site . auth_key [ key_id ] )
 oooO0oo0ooO . print_notify ( )
 if 82 - 82: OoOoOO00
 if ( map_register_ack == False ) :
  OOoo = lisp_eid_record ( )
  OOoo . decode ( eid_records )
  OOoo . print_record ( "  " , False )
  if 61 - 61: oO0o . o0oOOo0O0Ooo
  if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
  if 70 - 70: I1IiiI
  if 74 - 74: ooOoO0o * II111iiii
  if 96 - 96: i11iIiiIii . I1IiiI - II111iiii . I11i
 lisp_send_map_notify ( lisp_sockets , ii1i1II , oooO0oo0ooO . etr , port )
 site . map_notifies_sent += 1
 if 79 - 79: OoO0O00 . OoOoOO00 - i1IIi + Ii1I * i11iIiiIii . OoooooooOO
 if ( map_register_ack ) : return
 if 83 - 83: o0oOOo0O0Ooo / oO0o
 if 24 - 24: Ii1I + oO0o / OoooooooOO % i11iIiiIii
 if 1 - 1: iII111i / I1Ii111 * I1IiiI + OoOoOO00 . OoooooooOO
 if 5 - 5: I1IiiI
 if 74 - 74: i1IIi * Oo0Ooo - OoOoOO00 * o0oOOo0O0Ooo
 if 85 - 85: iIii1I11I1II1 * IiII / i11iIiiIii - ooOoO0o - o0oOOo0O0Ooo
 oooO0oo0ooO . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ oooO0oo0ooO ] )
 oooO0oo0ooO . retransmit_timer . start ( )
 return
 if 30 - 30: OoOoOO00 - OOooOOo . Oo0Ooo
 if 11 - 11: IiII - I1Ii111 - OoO0O00 * o0oOOo0O0Ooo
 if 99 - 99: O0 - OoO0O00
 if 95 - 95: Ii1I . IiII * o0oOOo0O0Ooo
 if 91 - 91: I1Ii111
 if 49 - 49: I11i
 if 17 - 17: Oo0Ooo % o0oOOo0O0Ooo
 if 3 - 3: OoO0O00 . oO0o . oO0o . Ii1I
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
 if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
 if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
 if 10 - 10: ooOoO0o
 ii1i1II = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 69 - 69: I11i + I1IiiI / oO0o
 if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
 if 85 - 85: I1Ii111 - oO0o
 if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
 oO00o0oOoo = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( oO00o0oOoo . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , oO00o0oOoo , LISP_CTRL_PORT , ii1i1II )
 return
 if 96 - 96: oO0o
 if 44 - 44: OoooooooOO / iII111i * Oo0Ooo % OoOoOO00 . oO0o
 if 97 - 97: iIii1I11I1II1 / ooOoO0o
 if 16 - 16: Oo0Ooo % IiII
 if 48 - 48: I1IiiI . I1Ii111 . o0oOOo0O0Ooo
 if 72 - 72: Ii1I * OoO0O00 / OoO0O00
 if 39 - 39: oO0o
 if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 57 - 57: oO0o + O0 - OoOoOO00
 oooO0oo0ooO = lisp_map_notify ( lisp_sockets )
 oooO0oo0ooO . record_count = 1
 oooO0oo0ooO . nonce = lisp_get_control_nonce ( )
 oooO0oo0ooO . nonce_key = lisp_hex_string ( oooO0oo0ooO . nonce )
 oooO0oo0ooO . etr . copy_address ( xtr )
 oooO0oo0ooO . etr_port = LISP_CTRL_PORT
 oooO0oo0ooO . eid_list = eid_list
 iII1 = oooO0oo0ooO . nonce_key
 if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
 if 93 - 93: o0oOOo0O0Ooo + i1IIi
 if 24 - 24: i1IIi
 if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
 if 99 - 99: Oo0Ooo
 if 38 - 38: I1ii11iIi11i - I1IiiI
 lisp_remove_eid_from_map_notify_queue ( oooO0oo0ooO . eid_list )
 if ( lisp_map_notify_queue . has_key ( iII1 ) ) :
  oooO0oo0ooO = lisp_map_notify_queue [ iII1 ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( oooO0oo0ooO . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 50 - 50: iII111i % OoO0O00 - oO0o + Oo0Ooo . O0 . iII111i
  return
  if 42 - 42: iII111i + I1ii11iIi11i
  if 44 - 44: I1ii11iIi11i % IiII
  if 1 - 1: Oo0Ooo + IiII - I1Ii111 / I1Ii111
  if 25 - 25: OoOoOO00
  if 52 - 52: OOooOOo + IiII
 lisp_map_notify_queue [ iII1 ] = oooO0oo0ooO
 if 73 - 73: OoooooooOO - I1Ii111 % iII111i / OOooOOo . o0oOOo0O0Ooo - IiII
 if 69 - 69: Ii1I . iIii1I11I1II1 / Oo0Ooo * Oo0Ooo % IiII
 if 5 - 5: OOooOOo - I1Ii111 + IiII
 if 82 - 82: OOooOOo
 I1Ii11 = site_eid . rtrs_in_rloc_set ( )
 if ( I1Ii11 ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : I1Ii11 = False
  if 91 - 91: I1ii11iIi11i / I1IiiI
  if 68 - 68: OOooOOo * O0 * I1IiiI
  if 20 - 20: iII111i + ooOoO0o . i11iIiiIii
  if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
  if 50 - 50: OoooooooOO * II111iiii
 OOoo = lisp_eid_record ( )
 OOoo . record_ttl = 1440
 OOoo . eid . copy_address ( site_eid . eid )
 OOoo . group . copy_address ( site_eid . group )
 OOoo . rloc_count = 0
 for IiIIIi in site_eid . registered_rlocs :
  if ( I1Ii11 ^ IiIIIi . is_rtr ( ) ) : continue
  OOoo . rloc_count += 1
  if 7 - 7: ooOoO0o / I11i * iII111i
 ii1i1II = OOoo . encode ( )
 if 17 - 17: O0 % I1Ii111
 if 28 - 28: i1IIi * ooOoO0o
 if 14 - 14: II111iiii + II111iiii - I11i / I11i . OoOoOO00 + OoO0O00
 if 92 - 92: II111iiii - II111iiii % IiII
 oooO0oo0ooO . print_notify ( )
 OOoo . print_record ( "  " , False )
 if 48 - 48: oO0o / II111iiii + oO0o
 if 16 - 16: o0oOOo0O0Ooo % II111iiii - i11iIiiIii - IiII + O0 - i11iIiiIii
 if 58 - 58: OoooooooOO / I1ii11iIi11i - Oo0Ooo / II111iiii
 if 13 - 13: o0oOOo0O0Ooo + OoOoOO00 * ooOoO0o % IiII
 for IiIIIi in site_eid . registered_rlocs :
  if ( I1Ii11 ^ IiIIIi . is_rtr ( ) ) : continue
  O0000O00O00OO = lisp_rloc_record ( )
  O0000O00O00OO . store_rloc_entry ( IiIIIi )
  ii1i1II += O0000O00O00OO . encode ( )
  O0000O00O00OO . print_record ( "    " )
  if 18 - 18: I1IiiI . I1ii11iIi11i + Oo0Ooo - iII111i
  if 53 - 53: ooOoO0o / IiII
  if 36 - 36: iIii1I11I1II1
  if 78 - 78: II111iiii * I11i
  if 47 - 47: Ii1I
 ii1i1II = oooO0oo0ooO . encode ( ii1i1II , "" )
 if ( ii1i1II == None ) : return
 if 42 - 42: I11i . oO0o - I1IiiI / OoO0O00
 if 75 - 75: I1IiiI / OoOoOO00 . I11i * iIii1I11I1II1
 if 53 - 53: iIii1I11I1II1
 if 8 - 8: O0 - O0 - II111iiii
 lisp_send_map_notify ( lisp_sockets , ii1i1II , xtr , LISP_CTRL_PORT )
 if 77 - 77: i1IIi - ooOoO0o + O0 . OoO0O00 * I1Ii111 - I11i
 if 64 - 64: i1IIi + OoooooooOO + OOooOOo / ooOoO0o % I1IiiI . OoooooooOO
 if 96 - 96: II111iiii - OoOoOO00 + oO0o
 if 80 - 80: oO0o / OoOoOO00 - I11i / oO0o - iII111i - OoooooooOO
 oooO0oo0ooO . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ oooO0oo0ooO ] )
 oooO0oo0ooO . retransmit_timer . start ( )
 return
 if 57 - 57: o0oOOo0O0Ooo
 if 37 - 37: iII111i * o0oOOo0O0Ooo
 if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
 if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
 if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
 if 34 - 34: O0 * oO0o
 if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 oo000oOoO = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 57 - 57: OOooOOo % IiII % i11iIiiIii . iIii1I11I1II1 . o0oOOo0O0Ooo / OOooOOo
 for o0000o0o in rle_list :
  OOo0OOoOO0 = lisp_site_eid_lookup ( o0000o0o [ 0 ] , o0000o0o [ 1 ] , True )
  if ( OOo0OOoOO0 == None ) : continue
  if 69 - 69: OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
  if 20 - 20: IiII
  if 17 - 17: o0oOOo0O0Ooo % iIii1I11I1II1
  if 66 - 66: OoooooooOO + IiII . II111iiii
  if 66 - 66: iIii1I11I1II1 % I11i
  if 38 - 38: I1ii11iIi11i * ooOoO0o
  if 77 - 77: OOooOOo - i11iIiiIii - I1ii11iIi11i
  OOO0O0OOoOo = OOo0OOoOO0 . registered_rlocs
  if ( len ( OOO0O0OOoOo ) == 0 ) :
   Oo0OOO = { }
   for oo0OO0O0 in OOo0OOoOO0 . individual_registrations . values ( ) :
    for IiIIIi in oo0OO0O0 . registered_rlocs :
     if ( IiIIIi . is_rtr ( ) == False ) : continue
     Oo0OOO [ IiIIIi . rloc . print_address ( ) ] = IiIIIi
     if 73 - 73: ooOoO0o % O0 % II111iiii / O0 . ooOoO0o
     if 40 - 40: OOooOOo + OoO0O00 + oO0o
   OOO0O0OOoOo = Oo0OOO . values ( )
   if 77 - 77: OoOoOO00 + iIii1I11I1II1 / OoOoOO00 - Ii1I / OoO0O00 + I1IiiI
   if 3 - 3: i1IIi % Ii1I . OoO0O00 * iIii1I11I1II1 % I11i
   if 64 - 64: iII111i * I1IiiI * IiII * iII111i / i1IIi . IiII
   if 30 - 30: OoOoOO00 . oO0o - iIii1I11I1II1 % i1IIi
   if 94 - 94: Oo0Ooo + iIii1I11I1II1 . OoO0O00 * oO0o . i1IIi
   if 85 - 85: O0 / OoOoOO00 . iII111i
  OOoO0Oo = [ ]
  oOOo0Oo0OO0OOO = False
  if ( OOo0OOoOO0 . eid . address == 0 and OOo0OOoOO0 . eid . mask_len == 0 ) :
   oOOOIIiI1i11II1i1 = [ ]
   o00 = [ ] if len ( OOO0O0OOoOo ) == 0 else OOO0O0OOoOo [ 0 ] . rle . rle_nodes
   if 81 - 81: OoooooooOO + OOooOOo
   for Oo0000O00o0 in o00 :
    OOoO0Oo . append ( Oo0000O00o0 . address )
    oOOOIIiI1i11II1i1 . append ( Oo0000O00o0 . address . print_address_no_iid ( ) )
    if 7 - 7: I11i + ooOoO0o
   lprint ( "Notify existing RLE-nodes {}" . format ( oOOOIIiI1i11II1i1 ) )
  else :
   if 28 - 28: OoooooooOO * iII111i / oO0o / iII111i
   if 80 - 80: OoO0O00 - I1IiiI + OOooOOo - iII111i / i1IIi
   if 11 - 11: i1IIi + O0 * IiII / O0 % I11i . I11i
   if 39 - 39: II111iiii . i11iIiiIii + I1IiiI + I1ii11iIi11i
   if 6 - 6: O0 % Ii1I . oO0o
   for IiIIIi in OOO0O0OOoOo :
    if ( IiIIIi . is_rtr ( ) ) : OOoO0Oo . append ( IiIIIi . rloc )
    if 91 - 91: O0 - oO0o * O0
    if 98 - 98: Ii1I
    if 54 - 54: oO0o
    if 85 - 85: oO0o % o0oOOo0O0Ooo % IiII
    if 84 - 84: IiII . OoO0O00
   oOOo0Oo0OO0OOO = ( len ( OOoO0Oo ) != 0 )
   if ( oOOo0Oo0OO0OOO == False ) :
    O0oiiii1i1i11I = lisp_site_eid_lookup ( o0000o0o [ 0 ] , oo000oOoO , False )
    if ( O0oiiii1i1i11I == None ) : continue
    if 73 - 73: OoOoOO00
    for IiIIIi in O0oiiii1i1i11I . registered_rlocs :
     if ( IiIIIi . rloc . is_null ( ) ) : continue
     OOoO0Oo . append ( IiIIIi . rloc )
     if 47 - 47: oO0o
     if 17 - 17: IiII
     if 47 - 47: I11i . I1IiiI % ooOoO0o . i11iIiiIii
     if 63 - 63: I1ii11iIi11i % I11i % OoooooooOO
     if 100 - 100: O0
     if 9 - 9: Ii1I
   if ( len ( OOoO0Oo ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( OOo0OOoOO0 . print_eid_tuple ( ) , False ) ) )
    if 87 - 87: I1IiiI
    continue
    if 56 - 56: OOooOOo % oO0o - OoOoOO00
    if 27 - 27: I1ii11iIi11i - IiII * OoooooooOO * I1ii11iIi11i + i11iIiiIii . IiII
    if 81 - 81: oO0o / iIii1I11I1II1
    if 15 - 15: Ii1I + I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
    if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
    if 28 - 28: ooOoO0o
  for i1IIiOoO000o00o00O in OOoO0Oo :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if oOOo0Oo0OO0OOO else "x" , red ( i1IIiOoO000o00o00O . print_address_no_iid ( ) , False ) ,
   # oO0o . Oo0Ooo % ooOoO0o + I1Ii111 . i11iIiiIii + Ii1I
 green ( OOo0OOoOO0 . print_eid_tuple ( ) , False ) ) )
   if 61 - 61: IiII + iII111i
   Iiii = [ OOo0OOoOO0 . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , OOo0OOoOO0 , Iiii , i1IIiOoO000o00o00O )
   time . sleep ( .001 )
   if 74 - 74: OoOoOO00 % OoO0O00 - OoooooooOO * i11iIiiIii
   if 20 - 20: OoO0O00 . II111iiii
 return
 if 70 - 70: i11iIiiIii % Ii1I * IiII / IiII . o0oOOo0O0Ooo
 if 52 - 52: o0oOOo0O0Ooo % I11i
 if 58 - 58: i11iIiiIii % Ii1I + Oo0Ooo - OoOoOO00 - i11iIiiIii / O0
 if 36 - 36: OOooOOo
 if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
 if 95 - 95: i1IIi * O0 / II111iiii * OoOoOO00 * I1IiiI
 if 38 - 38: OOooOOo - OoOoOO00 / OoO0O00 / o0oOOo0O0Ooo - i11iIiiIii
 if 4 - 4: I1IiiI * o0oOOo0O0Ooo - I11i - OoooooooOO . OoooooooOO
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for i1i1IIIIIIIi in range ( rloc_count ) :
  O0000O00O00OO = lisp_rloc_record ( )
  packet = O0000O00O00OO . decode ( packet , None )
  oO0o0OoO0 = O0000O00O00OO . json
  if ( oO0o0OoO0 == None ) : continue
  if 39 - 39: OoooooooOO / Oo0Ooo / OoooooooOO * IiII - i1IIi
  try :
   oO0o0OoO0 = json . loads ( oO0o0OoO0 . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 29 - 29: II111iiii / I1ii11iIi11i * OOooOOo
   if 39 - 39: O0 . OOooOOo
  if ( oO0o0OoO0 . has_key ( "signature" ) == False ) : continue
  return ( O0000O00O00OO )
  if 95 - 95: I11i
 return ( None )
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
 if 72 - 72: I1Ii111
 if 6 - 6: II111iiii - i1IIi
 if 78 - 78: OoOoOO00 - Oo0Ooo * II111iiii % iIii1I11I1II1 . i11iIiiIii % iII111i
 if 85 - 85: I1ii11iIi11i + OOooOOo % i1IIi
 if 13 - 13: OOooOOo + i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
 if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
 if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
 if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
def lisp_get_eid_hash ( eid ) :
 Ii1II11ii1iIi = None
 for OOi1 in lisp_eid_hashes :
  if 37 - 37: I1ii11iIi11i - iII111i + OOooOOo / i1IIi * ooOoO0o
  if 37 - 37: OoO0O00
  if 19 - 19: ooOoO0o
  if 4 - 4: Oo0Ooo - i1IIi . Oo0Ooo * I11i . i1IIi + OOooOOo
  oOo00Ooo0o0 = OOi1 . instance_id
  if ( oOo00Ooo0o0 == - 1 ) : OOi1 . instance_id = eid . instance_id
  if 3 - 3: IiII / iII111i * iII111i
  Ii1IIII = eid . is_more_specific ( OOi1 )
  OOi1 . instance_id = oOo00Ooo0o0
  if ( Ii1IIII ) :
   Ii1II11ii1iIi = 128 - OOi1 . mask_len
   break
   if 24 - 24: Ii1I
   if 23 - 23: Oo0Ooo * i1IIi / I1IiiI . I11i - I1ii11iIi11i . iIii1I11I1II1
 if ( Ii1II11ii1iIi == None ) : return ( None )
 if 15 - 15: O0 + o0oOOo0O0Ooo / oO0o
 III1 = eid . address
 i1iiI11I111I1 = ""
 for i1i1IIIIIIIi in range ( 0 , Ii1II11ii1iIi / 16 ) :
  O0o00o000oO = III1 & 0xffff
  O0o00o000oO = hex ( O0o00o000oO ) [ 2 : - 1 ]
  i1iiI11I111I1 = O0o00o000oO . zfill ( 4 ) + ":" + i1iiI11I111I1
  III1 >>= 16
  if 65 - 65: o0oOOo0O0Ooo
 if ( Ii1II11ii1iIi % 16 != 0 ) :
  O0o00o000oO = III1 & 0xff
  O0o00o000oO = hex ( O0o00o000oO ) [ 2 : - 1 ]
  i1iiI11I111I1 = O0o00o000oO . zfill ( 2 ) + ":" + i1iiI11I111I1
  if 77 - 77: i1IIi . Oo0Ooo . oO0o + oO0o - i11iIiiIii + I1ii11iIi11i
 return ( i1iiI11I111I1 [ 0 : - 1 ] )
 if 86 - 86: ooOoO0o . ooOoO0o . OoooooooOO - OoOoOO00 % oO0o
 if 81 - 81: Oo0Ooo . OoooooooOO
 if 15 - 15: I1Ii111 - I11i * I1IiiI % o0oOOo0O0Ooo
 if 75 - 75: oO0o % OoooooooOO % i11iIiiIii . iII111i
 if 95 - 95: i11iIiiIii . Ii1I / II111iiii + II111iiii + Ii1I / I11i
 if 72 - 72: I1Ii111 . I1Ii111 * O0 + I1ii11iIi11i / Oo0Ooo
 if 96 - 96: oO0o . ooOoO0o * Oo0Ooo % ooOoO0o + I1Ii111 + iIii1I11I1II1
 if 45 - 45: II111iiii
 if 42 - 42: ooOoO0o
 if 62 - 62: II111iiii * o0oOOo0O0Ooo . OoO0O00 / II111iiii
 if 5 - 5: OoO0O00 + O0 . OoooooooOO + I1IiiI + i1IIi * OOooOOo
def lisp_lookup_public_key ( eid ) :
 oOo00Ooo0o0 = eid . instance_id
 if 19 - 19: OoooooooOO + i11iIiiIii / II111iiii - Oo0Ooo . OOooOOo
 if 10 - 10: oO0o * Oo0Ooo
 if 55 - 55: OoO0O00 - i1IIi - I11i * oO0o
 if 91 - 91: I1Ii111
 if 77 - 77: I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + Ii1I % II111iiii * II111iiii
 IiIIi1I = lisp_get_eid_hash ( eid )
 if ( IiIIi1I == None ) : return ( [ None , None , False ] )
 if 93 - 93: OOooOOo
 IiIIi1I = "hash-" + IiIIi1I
 iI1Ii1 = lisp_address ( LISP_AFI_NAME , IiIIi1I , len ( IiIIi1I ) , oOo00Ooo0o0 )
 oOoooOOO0o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , oOo00Ooo0o0 )
 if 65 - 65: i1IIi * ooOoO0o * OoooooooOO - i11iIiiIii + IiII - o0oOOo0O0Ooo
 if 12 - 12: I1IiiI
 if 34 - 34: o0oOOo0O0Ooo / I1IiiI * i11iIiiIii + I1Ii111 / IiII
 if 55 - 55: iIii1I11I1II1 % iIii1I11I1II1 % iII111i
 O0oiiii1i1i11I = lisp_site_eid_lookup ( iI1Ii1 , oOoooOOO0o0 , True )
 if ( O0oiiii1i1i11I == None ) : return ( [ iI1Ii1 , None , False ] )
 if 80 - 80: OoooooooOO % iII111i * IiII % IiII
 if 34 - 34: OoO0O00
 if 22 - 22: OOooOOo
 if 23 - 23: I1ii11iIi11i
 Ooo0O00ooO = None
 for OooO0ooO0o0OO in O0oiiii1i1i11I . registered_rlocs :
  oOOOo0o0oo = OooO0ooO0o0OO . json
  if ( oOOOo0o0oo == None ) : continue
  try :
   oOOOo0o0oo = json . loads ( oOOOo0o0oo . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( IiIIi1I ) )
   if 2 - 2: OoOoOO00 . ooOoO0o - II111iiii
   return ( [ iI1Ii1 , None , False ] )
   if 92 - 92: II111iiii * iII111i
  if ( oOOOo0o0oo . has_key ( "public-key" ) == False ) : continue
  Ooo0O00ooO = oOOOo0o0oo [ "public-key" ]
  break
  if 60 - 60: I1IiiI . Ii1I - I1ii11iIi11i + iIii1I11I1II1 / oO0o % I11i
 return ( [ iI1Ii1 , Ooo0O00ooO , True ] )
 if 38 - 38: I1ii11iIi11i - OoooooooOO + Oo0Ooo
 if 74 - 74: i1IIi % ooOoO0o
 if 95 - 95: OOooOOo . O0 - OOooOOo
 if 5 - 5: OOooOOo % I1Ii111 * II111iiii
 if 69 - 69: OoO0O00 . o0oOOo0O0Ooo
 if 86 - 86: I1ii11iIi11i
 if 51 - 51: O0 % OoO0O00 - I1Ii111
 if 82 - 82: OoOoOO00 - OOooOOo . i1IIi / I11i
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 45 - 45: i1IIi / i1IIi . ooOoO0o . O0 / I1IiiI
 if 68 - 68: I11i % iIii1I11I1II1 . ooOoO0o . I1Ii111 + OoooooooOO
 if 45 - 45: IiII - Ii1I
 if 74 - 74: ooOoO0o / I1Ii111
 if 80 - 80: I1Ii111 / O0 * O0
 oOOo0OoooOo = json . loads ( rloc_record . json . json_string )
 if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
 if ( lisp_get_eid_hash ( eid ) ) :
  IIiII11i1 = eid
 elif ( oOOo0OoooOo . has_key ( "signature-eid" ) ) :
  ooo0O00O = oOOo0OoooOo [ "signature-eid" ]
  IIiII11i1 = lisp_address ( LISP_AFI_IPV6 , ooo0O00O , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 91 - 91: o0oOOo0O0Ooo
  if 5 - 5: IiII * oO0o - OOooOOo % I1Ii111 / iII111i
  if 19 - 19: O0 / OOooOOo / I1Ii111 . o0oOOo0O0Ooo
  if 22 - 22: O0 * OOooOOo - OoooooooOO - Ii1I * I1ii11iIi11i
  if 21 - 21: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo * II111iiii % iIii1I11I1II1
 iI1Ii1 , Ooo0O00ooO , iI1i1I = lisp_lookup_public_key ( IIiII11i1 )
 if ( iI1Ii1 == None ) :
  iiI1Ii1I = green ( IIiII11i1 . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( iiI1Ii1I ) )
  return ( False )
  if 81 - 81: I11i / oO0o
  if 89 - 89: OoOoOO00
 OO0Oo0Oo = "found" if iI1i1I else bold ( "not found" , False )
 iiI1Ii1I = green ( iI1Ii1 . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( iiI1Ii1I , OO0Oo0Oo ) )
 if ( iI1i1I == False ) : return ( False )
 if 18 - 18: OoO0O00 + OOooOOo
 if ( Ooo0O00ooO == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 25 - 25: OoOoOO00 * o0oOOo0O0Ooo
  if 41 - 41: OoOoOO00
 o00ooOOOo = Ooo0O00ooO [ 0 : 8 ] + "..." + Ooo0O00ooO [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( o00ooOOOo ) )
 if 52 - 52: i1IIi - oO0o
 if 33 - 33: Ii1I / I1ii11iIi11i . ooOoO0o . OoooooooOO
 if 45 - 45: OoO0O00 . I1ii11iIi11i + Ii1I / I11i - ooOoO0o / OoooooooOO
 if 44 - 44: OoO0O00 % O0 * IiII + iII111i
 if 79 - 79: ooOoO0o
 ooOOoo0o = oOOo0OoooOo [ "signature" ]
 if 16 - 16: II111iiii . ooOoO0o . i11iIiiIii * Ii1I - o0oOOo0O0Ooo . I1IiiI
 try :
  oOOo0OoooOo = binascii . a2b_base64 ( ooOOoo0o )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 33 - 33: o0oOOo0O0Ooo % ooOoO0o
  if 43 - 43: I1Ii111
 o0oO0OO = len ( oOOo0OoooOo )
 if ( o0oO0OO & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( o0oO0OO ) )
  return ( False )
  if 34 - 34: i1IIi
  if 56 - 56: Oo0Ooo . O0 + o0oOOo0O0Ooo + ooOoO0o - I1Ii111 + i1IIi
  if 25 - 25: OoO0O00 % IiII . i1IIi / OoOoOO00 + OoOoOO00
  if 53 - 53: II111iiii % i1IIi + ooOoO0o . I1Ii111
  if 52 - 52: I1IiiI + I1Ii111 * oO0o / i11iIiiIii * iIii1I11I1II1
 IiI11IiIIi = IIiII11i1 . print_address ( )
 if 27 - 27: Oo0Ooo
 if 85 - 85: iIii1I11I1II1 . o0oOOo0O0Ooo + oO0o
 if 79 - 79: O0 - iIii1I11I1II1 + i1IIi . I11i
 if 21 - 21: II111iiii
 Ooo0O00ooO = binascii . a2b_base64 ( Ooo0O00ooO )
 try :
  iII1 = ecdsa . VerifyingKey . from_pem ( Ooo0O00ooO )
 except :
  I1iiiII1Ii1i1 = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( I1iiiII1Ii1i1 ) )
  return ( False )
  if 2 - 2: oO0o * I1Ii111 - i11iIiiIii
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
 try :
  I11III111i1I = iII1 . verify ( oOOo0OoooOo , IiI11IiIIi , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( IiI11IiIIi ) )
  if 53 - 53: iII111i . Oo0Ooo
  lprint ( "  Signature used '{}'" . format ( ooOOoo0o ) )
  return ( False )
  if 91 - 91: oO0o * OoooooooOO * oO0o % oO0o * II111iiii % I1Ii111
 return ( I11III111i1I )
 if 8 - 8: Ii1I
 if 28 - 28: iII111i / I1ii11iIi11i - OoOoOO00 * Oo0Ooo + Ii1I * OoOoOO00
 if 94 - 94: oO0o
 if 95 - 95: ooOoO0o * O0 + OOooOOo
 if 11 - 11: i1IIi / OoOoOO00 + OoOoOO00 + I1ii11iIi11i + OOooOOo
 if 21 - 21: ooOoO0o
 if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
 if 81 - 81: oO0o
 if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
 if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
 if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
 if 33 - 33: I11i
 if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
 if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
 iI1IiIiI1 = [ ]
 for iIi1IIIIi1IiI in eid_list :
  for oO0O0000O00 in lisp_map_notify_queue :
   oooO0oo0ooO = lisp_map_notify_queue [ oO0O0000O00 ]
   if ( iIi1IIIIi1IiI not in oooO0oo0ooO . eid_list ) : continue
   if 81 - 81: ooOoO0o . O0 % OoO0O00 + I11i % IiII
   iI1IiIiI1 . append ( oO0O0000O00 )
   iiIi = oooO0oo0ooO . retransmit_timer
   if ( iiIi ) : iiIi . cancel ( )
   if 54 - 54: iIii1I11I1II1 * Ii1I
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( oooO0oo0ooO . nonce_key , green ( iIi1IIIIi1IiI , False ) ) )
   if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
   if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
   if 34 - 34: iIii1I11I1II1
   if 47 - 47: OOooOOo * iII111i
   if 71 - 71: IiII - OoooooooOO * i11iIiiIii . OoooooooOO % i1IIi . Oo0Ooo
   if 3 - 3: OoO0O00 + i11iIiiIii + oO0o * IiII
   if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
 for oO0O0000O00 in iI1IiIiI1 : lisp_map_notify_queue . pop ( oO0O0000O00 )
 return
 if 70 - 70: OoO0O00
 if 42 - 42: OoooooooOO - I1Ii111 + I1ii11iIi11i * iII111i * iII111i / OoO0O00
 if 85 - 85: O0 . II111iiii
 if 80 - 80: O0 * I11i * I1Ii111
 if 89 - 89: Ii1I * OoO0O00 . i1IIi . O0 - IiII - OoOoOO00
 if 25 - 25: iII111i + i1IIi
 if 64 - 64: IiII % I11i / iIii1I11I1II1
 if 66 - 66: Ii1I
def lisp_decrypt_map_register ( packet ) :
 if 55 - 55: OOooOOo + I1IiiI + IiII . Ii1I * oO0o
 if 71 - 71: IiII - iII111i % I1IiiI * iII111i
 if 27 - 27: ooOoO0o - OoO0O00
 if 83 - 83: iII111i * OoOoOO00 - O0 * Ii1I
 if 79 - 79: I11i / iII111i % Ii1I / OoOoOO00 % O0 / IiII
 iIIIIII = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 i1ii11ii1iiI = ( iIIIIII >> 13 ) & 0x1
 if ( i1ii11ii1iiI == 0 ) : return ( packet )
 if 67 - 67: oO0o . I1IiiI % i1IIi - OoO0O00
 IiiiO00O0 = ( iIIIIII >> 14 ) & 0x7
 if 26 - 26: I1ii11iIi11i
 if 17 - 17: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i * IiII / OoooooooOO + i11iIiiIii
 if 4 - 4: Ii1I - OoooooooOO / IiII - IiII . OOooOOo
 if 77 - 77: I1Ii111 + iII111i * IiII
 try :
  iI1Ii1iiiII1II = lisp_ms_encryption_keys [ IiiiO00O0 ]
  iI1Ii1iiiII1II = iI1Ii1iiiII1II . zfill ( 32 )
  oo0O = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( IiiiO00O0 ) )
  return ( None )
  if 45 - 45: Ii1I * IiII - OOooOOo
  if 57 - 57: iII111i % OoO0O00 / OoooooooOO
 Ii = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( Ii , IiiiO00O0 ) )
 if 69 - 69: oO0o
 O0Ooooo0 = chacha . ChaCha ( iI1Ii1iiiII1II , oo0O ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + O0Ooooo0 )
 if 44 - 44: IiII - II111iiii % Ii1I
 if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
 if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
 if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
 if 59 - 59: OoOoOO00
 if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
 if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
 if 62 - 62: Oo0Ooo . II111iiii % OoO0O00 . Ii1I * OOooOOo + II111iiii
 if 7 - 7: OOooOOo
 if 22 - 22: Oo0Ooo + ooOoO0o
 if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
 if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
 iI1iIIIIiiii = lisp_map_register ( )
 IiIIIii1iIII1 , packet = iI1iIIIIiiii . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 17 - 17: II111iiii - I1Ii111 - i11iIiiIii - iIii1I11I1II1
 iI1iIIIIiiii . sport = sport
 if 10 - 10: I1IiiI
 iI1iIIIIiiii . print_map_register ( )
 if 40 - 40: OoO0O00 * oO0o / OoOoOO00
 if 37 - 37: iII111i * oO0o / I1IiiI * I1ii11iIi11i
 if 73 - 73: oO0o + O0
 if 98 - 98: I11i % oO0o - I1Ii111 % o0oOOo0O0Ooo - IiII
 iiiii1i = True
 if ( iI1iIIIIiiii . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  iiiii1i = True
  if 79 - 79: OoooooooOO . OoOoOO00 * OoO0O00 + I11i / iII111i - Ii1I
 if ( iI1iIIIIiiii . alg_id == LISP_SHA_256_128_ALG_ID ) :
  iiiii1i = False
  if 9 - 9: I1IiiI - IiII . iIii1I11I1II1
  if 99 - 99: iII111i / o0oOOo0O0Ooo
  if 9 - 9: Oo0Ooo / i1IIi / Ii1I . I1Ii111 . I1Ii111
  if 56 - 56: ooOoO0o % IiII . OoO0O00 - iIii1I11I1II1 % o0oOOo0O0Ooo % I1IiiI
  if 71 - 71: I1IiiI + iII111i
 iii = [ ]
 if 41 - 41: I1ii11iIi11i
 if 90 - 90: IiII * I1Ii111 * I1Ii111 * I1IiiI . OoOoOO00 * iII111i
 if 46 - 46: OoOoOO00
 if 1 - 1: oO0o + ooOoO0o / iII111i
 i11I = None
 o0OoOOO = packet
 O0o0OO0o00 = [ ]
 oOo0o0ooO0OOO = iI1iIIIIiiii . record_count
 for i1i1IIIIIIIi in range ( oOo0o0ooO0OOO ) :
  OOoo = lisp_eid_record ( )
  O0000O00O00OO = lisp_rloc_record ( )
  packet = OOoo . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 66 - 66: i11iIiiIii % I11i / Oo0Ooo * oO0o
  OOoo . print_record ( "  " , False )
  if 7 - 7: O0 - Ii1I - oO0o
  if 95 - 95: i1IIi - OOooOOo / OoOoOO00 + I1ii11iIi11i + O0
  if 10 - 10: ooOoO0o - OOooOOo + i1IIi * Ii1I
  if 78 - 78: iIii1I11I1II1
  O0oiiii1i1i11I = lisp_site_eid_lookup ( OOoo . eid , OOoo . group ,
 False )
  if 76 - 76: ooOoO0o - i11iIiiIii * I11i / I1IiiI - OOooOOo
  i1i1IIiIii1 = O0oiiii1i1i11I . print_eid_tuple ( ) if O0oiiii1i1i11I else None
  if 21 - 21: O0 + ooOoO0o
  if 53 - 53: Ii1I - II111iiii * iIii1I11I1II1
  if 91 - 91: OoOoOO00 % iIii1I11I1II1
  if 81 - 81: i11iIiiIii / OoOoOO00 + iIii1I11I1II1
  if 65 - 65: o0oOOo0O0Ooo
  if 73 - 73: I11i . I1ii11iIi11i - OoO0O00 + OoooooooOO
  if 71 - 71: I1IiiI
  if ( O0oiiii1i1i11I and O0oiiii1i1i11I . accept_more_specifics == False ) :
   if ( O0oiiii1i1i11I . eid_record_matches ( OOoo ) == False ) :
    II1i1i = O0oiiii1i1i11I . parent_for_more_specifics
    if ( II1i1i ) : O0oiiii1i1i11I = II1i1i
    if 53 - 53: Ii1I
    if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
    if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
    if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
    if 33 - 33: oO0o . oO0o / IiII + II111iiii
    if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
    if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
    if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
  i1iiii1 = ( O0oiiii1i1i11I and O0oiiii1i1i11I . accept_more_specifics )
  if ( i1iiii1 ) :
   o0OIiiI1i1Ii1 = lisp_site_eid ( O0oiiii1i1i11I . site )
   o0OIiiI1i1Ii1 . dynamic = True
   o0OIiiI1i1Ii1 . eid . copy_address ( OOoo . eid )
   o0OIiiI1i1Ii1 . group . copy_address ( OOoo . group )
   o0OIiiI1i1Ii1 . parent_for_more_specifics = O0oiiii1i1i11I
   o0OIiiI1i1Ii1 . add_cache ( )
   o0OIiiI1i1Ii1 . inherit_from_ams_parent ( )
   O0oiiii1i1i11I . more_specific_registrations . append ( o0OIiiI1i1Ii1 )
   O0oiiii1i1i11I = o0OIiiI1i1Ii1
  else :
   O0oiiii1i1i11I = lisp_site_eid_lookup ( OOoo . eid , OOoo . group ,
 True )
   if 72 - 72: OoOoOO00 . OoO0O00 . iIii1I11I1II1 + oO0o / ooOoO0o
   if 20 - 20: I1ii11iIi11i . II111iiii % I1Ii111 + I1Ii111 / OoooooooOO . Ii1I
  iiI1Ii1I = OOoo . print_eid_tuple ( )
  if 98 - 98: OoooooooOO - i11iIiiIii - iII111i + Ii1I - I1IiiI
  if ( O0oiiii1i1i11I == None ) :
   I11oo = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( I11oo , green ( iiI1Ii1I , False ) ,
 ", matched non-ams {}" . format ( green ( i1i1IIiIii1 , False ) if i1i1IIiIii1 else "" ) ) )
   if 75 - 75: OOooOOo
   if 25 - 25: iII111i / I1ii11iIi11i - ooOoO0o
   if 53 - 53: IiII / OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - iIii1I11I1II1
   if 53 - 53: OOooOOo . I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
   if 40 - 40: OoooooooOO + iII111i % I1Ii111 . ooOoO0o
   packet = O0000O00O00OO . end_of_rlocs ( packet , OOoo . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 2 - 2: ooOoO0o
   continue
   if 55 - 55: I11i + i1IIi * OoOoOO00 % Oo0Ooo * II111iiii . I1IiiI
   if 98 - 98: I1ii11iIi11i
  i11I = O0oiiii1i1i11I . site
  if 57 - 57: OOooOOo * I11i . oO0o
  if ( i1iiii1 ) :
   o0OoO00 = O0oiiii1i1i11I . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( o0OoO00 , False ) , i11I . site_name , green ( iiI1Ii1I , False ) ) )
   if 17 - 17: iII111i - OOooOOo * I1IiiI + i1IIi % I1ii11iIi11i
  else :
   o0OoO00 = green ( O0oiiii1i1i11I . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( o0OoO00 , i11I . site_name , green ( iiI1Ii1I , False ) ) )
   if 71 - 71: Ii1I - o0oOOo0O0Ooo - oO0o
   if 27 - 27: O0 - iIii1I11I1II1
   if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
   if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
   if 97 - 97: i11iIiiIii + I1ii11iIi11i - I11i . oO0o
   if 76 - 76: IiII * II111iiii * I1ii11iIi11i + OoooooooOO - OoOoOO00 . Ii1I
  if ( i11I . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( i11I . site_name ) )
   packet = O0000O00O00OO . end_of_rlocs ( packet , OOoo . rloc_count )
   continue
   if 51 - 51: II111iiii % I1Ii111 * O0 . ooOoO0o * OoOoOO00
   if 17 - 17: I1IiiI % I11i
   if 28 - 28: I1ii11iIi11i * OoooooooOO
   if 19 - 19: Oo0Ooo - iII111i % OoOoOO00 * i11iIiiIii / oO0o . i11iIiiIii
   if 46 - 46: I1ii11iIi11i
   if 50 - 50: OOooOOo * OoO0O00 * OOooOOo % I1IiiI - I1Ii111 * Ii1I
   if 88 - 88: OOooOOo . iII111i / I11i
   if 1 - 1: iIii1I11I1II1 - Oo0Ooo % OoooooooOO
  o0O = iI1iIIIIiiii . key_id
  if ( i11I . auth_key . has_key ( o0O ) == False ) : o0O = 0
  o000o0OOo = i11I . auth_key [ o0O ]
  if 90 - 90: OOooOOo . O0 % I1Ii111
  oooOoO0 = lisp_verify_auth ( IiIIIii1iIII1 , iI1iIIIIiiii . alg_id ,
 iI1iIIIIiiii . auth_data , o000o0OOo )
  OooOoO00 = "dynamic " if O0oiiii1i1i11I . dynamic else ""
  if 4 - 4: II111iiii + oO0o + o0oOOo0O0Ooo % IiII % iIii1I11I1II1
  I1i1I11I = bold ( "passed" if oooOoO0 else "failed" , False )
  o0O = "key-id {}" . format ( o0O ) if o0O == iI1iIIIIiiii . key_id else "bad key-id {}" . format ( iI1iIIIIiiii . key_id )
  if 68 - 68: i11iIiiIii
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( I1i1I11I , OooOoO00 , green ( iiI1Ii1I , False ) , o0O ) )
  if 79 - 79: OoOoOO00 * Ii1I / I1ii11iIi11i + OOooOOo
  if 19 - 19: I1IiiI + I11i + I1IiiI + OoO0O00
  if 33 - 33: i11iIiiIii - Ii1I * II111iiii
  if 97 - 97: OoO0O00 / o0oOOo0O0Ooo * iIii1I11I1II1
  if 5 - 5: I1IiiI
  if 27 - 27: i1IIi + oO0o / I1ii11iIi11i + oO0o
  ooo0Oo0 = True
  iIii = ( lisp_get_eid_hash ( OOoo . eid ) != None )
  if ( iIii or O0oiiii1i1i11I . require_signature ) :
   iI1IIIiI = "Required " if O0oiiii1i1i11I . require_signature else ""
   iiI1Ii1I = green ( iiI1Ii1I , False )
   OooO0ooO0o0OO = lisp_find_sig_in_rloc_set ( packet , OOoo . rloc_count )
   if ( OooO0ooO0o0OO == None ) :
    ooo0Oo0 = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( iI1IIIiI ,
    # i1IIi - OoooooooOO * OOooOOo . ooOoO0o + O0 + o0oOOo0O0Ooo
 bold ( "failed" , False ) , iiI1Ii1I ) )
   else :
    ooo0Oo0 = lisp_verify_cga_sig ( OOoo . eid , OooO0ooO0o0OO )
    I1i1I11I = bold ( "passed" if ooo0Oo0 else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( iI1IIIiI , I1i1I11I , iiI1Ii1I ) )
    if 87 - 87: OOooOOo + I1Ii111 + O0 / oO0o / i11iIiiIii
    if 60 - 60: O0 . II111iiii
    if 69 - 69: II111iiii / ooOoO0o - OoOoOO00 / OOooOOo
    if 52 - 52: OoO0O00 % I11i + o0oOOo0O0Ooo % OoOoOO00
  if ( oooOoO0 == False or ooo0Oo0 == False ) :
   packet = O0000O00O00OO . end_of_rlocs ( packet , OOoo . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 46 - 46: o0oOOo0O0Ooo % O0
   continue
   if 30 - 30: oO0o
   if 64 - 64: O0
   if 70 - 70: oO0o % I1IiiI . iIii1I11I1II1 - Oo0Ooo + OoOoOO00 % O0
   if 91 - 91: I1Ii111 - oO0o * ooOoO0o - I1ii11iIi11i + IiII + O0
   if 18 - 18: OoOoOO00 / IiII / o0oOOo0O0Ooo . OOooOOo
   if 35 - 35: I11i . ooOoO0o % I11i / iII111i / O0 % I11i
  if ( iI1iIIIIiiii . merge_register_requested ) :
   II1i1i = O0oiiii1i1i11I
   II1i1i . inconsistent_registration = False
   if 29 - 29: I1Ii111 + Ii1I
   if 100 - 100: Ii1I + I1Ii111 / iIii1I11I1II1 / i1IIi % OoOoOO00
   if 6 - 6: oO0o + ooOoO0o
   if 13 - 13: Oo0Ooo . IiII % iII111i + i1IIi / OOooOOo
   if 1 - 1: I11i * i1IIi * Oo0Ooo % O0
   if ( O0oiiii1i1i11I . group . is_null ( ) ) :
    if ( II1i1i . site_id != iI1iIIIIiiii . site_id ) :
     II1i1i . site_id = iI1iIIIIiiii . site_id
     II1i1i . registered = False
     II1i1i . individual_registrations = { }
     II1i1i . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 41 - 41: OOooOOo % OoOoOO00
     if 82 - 82: I11i . IiII
     if 27 - 27: I1Ii111 % O0 * OoooooooOO . Oo0Ooo
   iII1 = source . address + iI1iIIIIiiii . xtr_id
   if ( O0oiiii1i1i11I . individual_registrations . has_key ( iII1 ) ) :
    O0oiiii1i1i11I = O0oiiii1i1i11I . individual_registrations [ iII1 ]
   else :
    O0oiiii1i1i11I = lisp_site_eid ( i11I )
    O0oiiii1i1i11I . eid . copy_address ( II1i1i . eid )
    O0oiiii1i1i11I . group . copy_address ( II1i1i . group )
    II1i1i . individual_registrations [ iII1 ] = O0oiiii1i1i11I
    if 51 - 51: I11i
  else :
   O0oiiii1i1i11I . inconsistent_registration = O0oiiii1i1i11I . merge_register_requested
   if 80 - 80: Oo0Ooo + oO0o
   if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
   if 82 - 82: IiII % ooOoO0o
  O0oiiii1i1i11I . map_registers_received += 1
  if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
  if 27 - 27: Oo0Ooo . I1Ii111 - i1IIi * I1IiiI
  if 96 - 96: I1ii11iIi11i - Ii1I . I1ii11iIi11i
  if 89 - 89: II111iiii % I1ii11iIi11i % IiII . I11i
  if 49 - 49: iII111i % i11iIiiIii * I11i - oO0o . OOooOOo . i11iIiiIii
  I1iiiII1Ii1i1 = ( O0oiiii1i1i11I . is_rloc_in_rloc_set ( source ) == False )
  if ( OOoo . record_ttl == 0 and I1iiiII1Ii1i1 ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 26 - 26: iIii1I11I1II1 + i11iIiiIii % iII111i + I1IiiI + oO0o - ooOoO0o
   continue
   if 4 - 4: Oo0Ooo - IiII - I11i
   if 72 - 72: OoooooooOO
   if 19 - 19: Oo0Ooo . OOooOOo
   if 58 - 58: IiII % iII111i + i1IIi % I1IiiI % OOooOOo . iII111i
   if 85 - 85: i11iIiiIii . o0oOOo0O0Ooo * iII111i . I1ii11iIi11i / I1Ii111 % Ii1I
   if 27 - 27: II111iiii . iIii1I11I1II1 / I1ii11iIi11i / i1IIi / iIii1I11I1II1
  OoiiIiIiI1I1iii = O0oiiii1i1i11I . registered_rlocs
  O0oiiii1i1i11I . registered_rlocs = [ ]
  if 33 - 33: OoOoOO00 - I1ii11iIi11i + IiII
  if 70 - 70: Ii1I % II111iiii
  if 90 - 90: IiII * OoOoOO00 * i1IIi * O0
  if 28 - 28: OoOoOO00 . Oo0Ooo - i1IIi * O0
  i1Io0 = packet
  for Oo0iIIiiIiiI in range ( OOoo . rloc_count ) :
   O0000O00O00OO = lisp_rloc_record ( )
   packet = O0000O00O00OO . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 92 - 92: iIii1I11I1II1 / I1IiiI
   O0000O00O00OO . print_record ( "    " )
   if 60 - 60: OoOoOO00 + o0oOOo0O0Ooo + OOooOOo % OoooooooOO
   if 51 - 51: OoO0O00
   if 60 - 60: ooOoO0o
   if 95 - 95: I11i / o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
   if ( len ( i11I . allowed_rlocs ) > 0 ) :
    oOo0O = O0000O00O00OO . rloc . print_address ( )
    if ( i11I . allowed_rlocs . has_key ( oOo0O ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( oOo0O , False ) ) )
     if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
     if 8 - 8: OoooooooOO * ooOoO0o
     O0oiiii1i1i11I . registered = False
     packet = O0000O00O00OO . end_of_rlocs ( packet ,
 OOoo . rloc_count - Oo0iIIiiIiiI - 1 )
     break
     if 26 - 26: i11iIiiIii + oO0o - i1IIi
     if 71 - 71: I1IiiI % I1Ii111 / oO0o % oO0o / iIii1I11I1II1 + I1Ii111
     if 86 - 86: IiII % i1IIi * o0oOOo0O0Ooo - I1Ii111
     if 37 - 37: iII111i % I1IiiI - I1ii11iIi11i % I11i
     if 35 - 35: O0 - OoooooooOO % iII111i
     if 48 - 48: OOooOOo % i11iIiiIii
   OooO0ooO0o0OO = lisp_rloc ( )
   OooO0ooO0o0OO . store_rloc_from_record ( O0000O00O00OO , None , source )
   if 49 - 49: O0 * iII111i + II111iiii - OOooOOo
   if 29 - 29: OoooooooOO % II111iiii - Oo0Ooo / IiII - i11iIiiIii
   if 64 - 64: iII111i . I1Ii111 + I1Ii111
   if 1 - 1: OOooOOo % Oo0Ooo
   if 81 - 81: oO0o / I11i % Ii1I . I11i + OoooooooOO
   if 31 - 31: OoO0O00
   if ( source . is_exact_match ( OooO0ooO0o0OO . rloc ) ) :
    OooO0ooO0o0OO . map_notify_requested = iI1iIIIIiiii . map_notify_requested
    if 41 - 41: i11iIiiIii - I1ii11iIi11i - II111iiii
    if 5 - 5: OoOoOO00 + i1IIi
    if 43 - 43: iII111i * I1IiiI
    if 20 - 20: I1IiiI . I11i * OoO0O00 . ooOoO0o . II111iiii
    if 6 - 6: Ii1I * OoOoOO00 % IiII + I11i
   O0oiiii1i1i11I . registered_rlocs . append ( OooO0ooO0o0OO )
   if 20 - 20: oO0o
   if 34 - 34: i1IIi + oO0o * Oo0Ooo * I1Ii111 % OoooooooOO % ooOoO0o
  IIiIiI = ( O0oiiii1i1i11I . do_rloc_sets_match ( OoiiIiIiI1I1iii ) == False )
  if 63 - 63: o0oOOo0O0Ooo / IiII - i11iIiiIii
  if 99 - 99: O0 + O0 . iIii1I11I1II1 . ooOoO0o * o0oOOo0O0Ooo
  if 1 - 1: I1Ii111 - I11i . OoOoOO00
  if 72 - 72: II111iiii . O0 . I11i * OoO0O00
  if 70 - 70: iII111i % OoooooooOO * I1ii11iIi11i . I11i / OoO0O00
  if 6 - 6: O0 . i11iIiiIii
  if ( iI1iIIIIiiii . map_register_refresh and IIiIiI and
 O0oiiii1i1i11I . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   O0oiiii1i1i11I . registered_rlocs = OoiiIiIiI1I1iii
   continue
   if 85 - 85: i11iIiiIii / Ii1I + Oo0Ooo / OoOoOO00 - I1IiiI
   if 39 - 39: OoO0O00
   if 97 - 97: iIii1I11I1II1 . I1IiiI - O0
   if 41 - 41: I11i . OoOoOO00 * O0 % Ii1I
   if 54 - 54: ooOoO0o
   if 13 - 13: I11i
  if ( O0oiiii1i1i11I . registered == False ) :
   O0oiiii1i1i11I . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 18 - 18: II111iiii * oO0o % i11iIiiIii / IiII . ooOoO0o
  O0oiiii1i1i11I . last_registered = lisp_get_timestamp ( )
  O0oiiii1i1i11I . registered = ( OOoo . record_ttl != 0 )
  O0oiiii1i1i11I . last_registerer = source
  if 2 - 2: OoOoOO00 % I1Ii111
  if 35 - 35: OOooOOo
  if 50 - 50: iIii1I11I1II1 . I1IiiI + i11iIiiIii
  if 65 - 65: I11i % I1IiiI
  O0oiiii1i1i11I . auth_sha1_or_sha2 = iiiii1i
  O0oiiii1i1i11I . proxy_reply_requested = iI1iIIIIiiii . proxy_reply_requested
  O0oiiii1i1i11I . lisp_sec_present = iI1iIIIIiiii . lisp_sec_present
  O0oiiii1i1i11I . map_notify_requested = iI1iIIIIiiii . map_notify_requested
  O0oiiii1i1i11I . mobile_node_requested = iI1iIIIIiiii . mobile_node
  O0oiiii1i1i11I . merge_register_requested = iI1iIIIIiiii . merge_register_requested
  if 3 - 3: i11iIiiIii % OOooOOo - Ii1I . i1IIi
  O0oiiii1i1i11I . use_register_ttl_requested = iI1iIIIIiiii . use_ttl_for_timeout
  if ( O0oiiii1i1i11I . use_register_ttl_requested ) :
   O0oiiii1i1i11I . register_ttl = OOoo . store_ttl ( )
  else :
   O0oiiii1i1i11I . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 24 - 24: OOooOOo
  O0oiiii1i1i11I . xtr_id_present = iI1iIIIIiiii . xtr_id_present
  if ( O0oiiii1i1i11I . xtr_id_present ) :
   O0oiiii1i1i11I . xtr_id = iI1iIIIIiiii . xtr_id
   O0oiiii1i1i11I . site_id = iI1iIIIIiiii . site_id
   if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
   if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
   if 59 - 59: oO0o * OoO0O00 - I11i * I1IiiI
   if 60 - 60: iII111i - OoooooooOO / iII111i % OoO0O00 . OoOoOO00 - o0oOOo0O0Ooo
   if 71 - 71: iII111i * o0oOOo0O0Ooo * i11iIiiIii * O0
  if ( iI1iIIIIiiii . merge_register_requested ) :
   if ( II1i1i . merge_in_site_eid ( O0oiiii1i1i11I ) ) :
    iii . append ( [ OOoo . eid , OOoo . group ] )
    if 77 - 77: OOooOOo % iII111i + I11i / OoOoOO00
   if ( iI1iIIIIiiii . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , II1i1i , iI1iIIIIiiii ,
 OOoo )
    if 50 - 50: OoOoOO00 - i11iIiiIii - OOooOOo . iIii1I11I1II1
    if 97 - 97: oO0o % OOooOOo . OoooooooOO * Ii1I
    if 100 - 100: I1ii11iIi11i / Ii1I % Oo0Ooo
  if ( IIiIiI == False ) : continue
  if ( len ( iii ) != 0 ) : continue
  if 83 - 83: O0 . I1Ii111 % I1ii11iIi11i
  O0o0OO0o00 . append ( O0oiiii1i1i11I . print_eid_tuple ( ) )
  if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
  if 12 - 12: ooOoO0o
  if 56 - 56: i1IIi
  if 3 - 3: OOooOOo - Oo0Ooo * Ii1I + i11iIiiIii
  if 53 - 53: i1IIi % I1ii11iIi11i
  if 65 - 65: I11i + OoOoOO00 - i11iIiiIii
  if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
  OOoo = OOoo . encode ( )
  OOoo += i1Io0
  Iiii = [ O0oiiii1i1i11I . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 61 - 61: oO0o . i11iIiiIii / Ii1I % iII111i
  for OooO0ooO0o0OO in OoiiIiIiI1I1iii :
   if ( OooO0ooO0o0OO . map_notify_requested == False ) : continue
   if ( OooO0ooO0o0OO . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , OOoo , Iiii , 1 , OooO0ooO0o0OO . rloc ,
 LISP_CTRL_PORT , iI1iIIIIiiii . nonce , iI1iIIIIiiii . key_id ,
 iI1iIIIIiiii . alg_id , iI1iIIIIiiii . auth_len , i11I , False )
   if 36 - 36: OoO0O00 + Ii1I / I11i - iII111i % OoO0O00 / Oo0Ooo
   if 38 - 38: Ii1I - ooOoO0o - O0 + oO0o . iIii1I11I1II1
   if 90 - 90: i1IIi * OoOoOO00
   if 27 - 27: iIii1I11I1II1
   if 95 - 95: iII111i / ooOoO0o % Ii1I
  lisp_notify_subscribers ( lisp_sockets , OOoo , O0oiiii1i1i11I . eid , i11I )
  if 44 - 44: OOooOOo . OOooOOo
  if 5 - 5: oO0o + OoooooooOO
  if 88 - 88: oO0o + OOooOOo
  if 14 - 14: I11i / i1IIi
  if 56 - 56: OoooooooOO
 if ( len ( iii ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , iii )
  if 59 - 59: I1ii11iIi11i + OoO0O00
  if 37 - 37: IiII * I1IiiI % O0
  if 32 - 32: ooOoO0o % II111iiii
  if 60 - 60: i11iIiiIii
  if 11 - 11: o0oOOo0O0Ooo
  if 77 - 77: o0oOOo0O0Ooo / iIii1I11I1II1 * iIii1I11I1II1 / o0oOOo0O0Ooo * iII111i
 if ( iI1iIIIIiiii . merge_register_requested ) : return
 if 26 - 26: Ii1I
 if 1 - 1: OoOoOO00 . o0oOOo0O0Ooo + Oo0Ooo % Oo0Ooo * I1ii11iIi11i
 if 50 - 50: IiII / i1IIi . I1ii11iIi11i
 if 75 - 75: I11i * oO0o + OoooooooOO . iII111i + OoO0O00
 if 44 - 44: II111iiii
 if ( iI1iIIIIiiii . map_notify_requested and i11I != None ) :
  lisp_build_map_notify ( lisp_sockets , o0OoOOO , O0o0OO0o00 ,
 iI1iIIIIiiii . record_count , source , sport , iI1iIIIIiiii . nonce ,
 iI1iIIIIiiii . key_id , iI1iIIIIiiii . alg_id , iI1iIIIIiiii . auth_len ,
 i11I , True )
  if 65 - 65: I11i . iII111i . I1IiiI - Oo0Ooo % iIii1I11I1II1 / O0
 return
 if 54 - 54: iII111i - I1Ii111
 if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
 if 7 - 7: i1IIi
 if 30 - 30: oO0o . i1IIi / I11i
 if 23 - 23: i1IIi + oO0o % iII111i - OoO0O00 - i1IIi
 if 74 - 74: Ii1I + I11i . OoooooooOO - I1ii11iIi11i
 if 2 - 2: oO0o - o0oOOo0O0Ooo
 if 80 - 80: i1IIi
 if 40 - 40: O0 . ooOoO0o * iII111i . I11i + I1Ii111 % OoO0O00
 if 9 - 9: IiII * oO0o - o0oOOo0O0Ooo
def lisp_process_multicast_map_notify ( packet , source ) :
 oooO0oo0ooO = lisp_map_notify ( "" )
 packet = oooO0oo0ooO . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 17 - 17: iII111i % Oo0Ooo
  if 14 - 14: I1IiiI - I1Ii111 % I1IiiI - II111iiii
 oooO0oo0ooO . print_notify ( )
 if ( oooO0oo0ooO . record_count == 0 ) : return
 if 34 - 34: I1ii11iIi11i * IiII / II111iiii / ooOoO0o * oO0o
 iIIiIi11i = oooO0oo0ooO . eid_records
 if 8 - 8: OoOoOO00 / oO0o + oO0o * Ii1I
 for i1i1IIIIIIIi in range ( oooO0oo0ooO . record_count ) :
  OOoo = lisp_eid_record ( )
  iIIiIi11i = OOoo . decode ( iIIiIi11i )
  if ( packet == None ) : return
  OOoo . print_record ( "  " , False )
  if 71 - 71: I1Ii111 - O0 . oO0o % ooOoO0o / I1Ii111
  if 28 - 28: o0oOOo0O0Ooo / oO0o
  if 65 - 65: O0 / i1IIi
  if 78 - 78: OOooOOo . I11i % Oo0Ooo . OoOoOO00
  OoOoooooO00oo = lisp_map_cache_lookup ( OOoo . eid , OOoo . group )
  if ( OoOoooooO00oo == None ) :
   oooO0O0OOOoo , OoOO0OOOO0 , oOoOoO0Oo0oo = lisp_allow_gleaning ( OOoo . eid , OOoo . group ,
 None )
   if ( oooO0O0OOOoo == False ) : continue
   if 78 - 78: OoOoOO00 % I1Ii111
   OoOoooooO00oo = lisp_mapping ( OOoo . eid , OOoo . group , [ ] )
   OoOoooooO00oo . add_cache ( )
   if 64 - 64: O0 + IiII / ooOoO0o / OoooooooOO . II111iiii / ooOoO0o
   if 77 - 77: OoO0O00
   if 23 - 23: I11i + o0oOOo0O0Ooo - Ii1I % OoooooooOO
   if 70 - 70: o0oOOo0O0Ooo + o0oOOo0O0Ooo . OOooOOo % I11i
   if 48 - 48: Oo0Ooo
   if 27 - 27: OoOoOO00 . O0 / i11iIiiIii + O0 % OoooooooOO % OoO0O00
   if 52 - 52: I1IiiI * oO0o
  if ( OoOoooooO00oo . gleaned ) :
   lprint ( "Ignore Map-Notify for gleaned {}" . format ( green ( OoOoooooO00oo . print_eid_tuple ( ) , False ) ) )
   if 93 - 93: i1IIi + I1ii11iIi11i % Oo0Ooo + iIii1I11I1II1 / II111iiii
   continue
   if 100 - 100: iIii1I11I1II1 / II111iiii / Ii1I * Ii1I - OoO0O00
   if 36 - 36: ooOoO0o % i1IIi / OoOoOO00 % OoOoOO00 + Ii1I
  OoOoooooO00oo . mapping_source = None if source == "lisp-etr" else source
  OoOoooooO00oo . map_cache_ttl = OOoo . store_ttl ( )
  if 35 - 35: Ii1I . ooOoO0o - ooOoO0o % OoO0O00 / oO0o
  if 33 - 33: I1Ii111 / i11iIiiIii / I1ii11iIi11i
  if 44 - 44: OoOoOO00 * Oo0Ooo
  if 51 - 51: OOooOOo / IiII % I1Ii111 . OoOoOO00 % Ii1I
  if 88 - 88: OoO0O00
  if ( len ( OoOoooooO00oo . rloc_set ) != 0 and OOoo . rloc_count == 0 ) :
   OoOoooooO00oo . rloc_set = [ ]
   OoOoooooO00oo . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , OoOoooooO00oo )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( OoOoooooO00oo . print_eid_tuple ( ) , False ) ) )
   if 28 - 28: I1Ii111 - iIii1I11I1II1
   continue
   if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
   if 65 - 65: iII111i . oO0o
  Ooo0 = OoOoooooO00oo . rtrs_in_rloc_set ( )
  if 81 - 81: oO0o
  if 100 - 100: Ii1I * I1IiiI
  if 43 - 43: IiII % ooOoO0o - i11iIiiIii - I11i
  if 41 - 41: I1Ii111 * OoooooooOO / OoOoOO00 + OoO0O00 . OoOoOO00 + I1Ii111
  if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
  for Oo0iIIiiIiiI in range ( OOoo . rloc_count ) :
   O0000O00O00OO = lisp_rloc_record ( )
   iIIiIi11i = O0000O00O00OO . decode ( iIIiIi11i , None )
   O0000O00O00OO . print_record ( "    " )
   if ( OOoo . group . is_null ( ) ) : continue
   if ( O0000O00O00OO . rle == None ) : continue
   if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
   if 43 - 43: Oo0Ooo % I11i
   if 53 - 53: OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
   if 47 - 47: iIii1I11I1II1 - OOooOOo + I1ii11iIi11i * ooOoO0o + Oo0Ooo + OoO0O00
   if 64 - 64: OoOoOO00 - OoOoOO00 . OoooooooOO + ooOoO0o
   O0ooOoo0O000O = OoOoooooO00oo . rloc_set [ 0 ] . stats if len ( OoOoooooO00oo . rloc_set ) != 0 else None
   if 32 - 32: I1Ii111 * iII111i - OoO0O00 / ooOoO0o % i11iIiiIii + OoOoOO00
   if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
   if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
   if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
   OooO0ooO0o0OO = lisp_rloc ( )
   OooO0ooO0o0OO . store_rloc_from_record ( O0000O00O00OO , None , OoOoooooO00oo . mapping_source )
   if ( O0ooOoo0O000O != None ) : OooO0ooO0o0OO . stats = copy . deepcopy ( O0ooOoo0O000O )
   if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
   if ( Ooo0 and OooO0ooO0o0OO . is_rtr ( ) == False ) : continue
   if 20 - 20: IiII
   OoOoooooO00oo . rloc_set = [ OooO0ooO0o0OO ]
   OoOoooooO00oo . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , OoOoooooO00oo )
   if 81 - 81: Oo0Ooo / I1Ii111
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( OoOoooooO00oo . print_eid_tuple ( ) , False ) , OooO0ooO0o0OO . rle . print_rle ( False ) ) )
   if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
   if 51 - 51: iII111i - ooOoO0o
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
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 oooO0oo0ooO = lisp_map_notify ( "" )
 ii1i1II = oooO0oo0ooO . decode ( orig_packet )
 if ( ii1i1II == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
  if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
 oooO0oo0ooO . print_notify ( )
 if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
 if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
 if 22 - 22: ooOoO0o - OOooOOo
 if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
 if 20 - 20: ooOoO0o - i11iIiiIii
 o0 = source . print_address ( )
 if ( oooO0oo0ooO . alg_id != 0 or oooO0oo0ooO . auth_len != 0 ) :
  Ii1IIII = None
  for iII1 in lisp_map_servers_list :
   if ( iII1 . find ( o0 ) == - 1 ) : continue
   Ii1IIII = lisp_map_servers_list [ iII1 ]
   if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
  if ( Ii1IIII == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( o0 ) )
   if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
   return
   if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
   if 29 - 29: oO0o
  Ii1IIII . map_notifies_received += 1
  if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
  oooOoO0 = lisp_verify_auth ( ii1i1II , oooO0oo0ooO . alg_id ,
 oooO0oo0ooO . auth_data , Ii1IIII . password )
  if 78 - 78: Oo0Ooo
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if oooOoO0 else "failed" ) )
  if 77 - 77: oO0o % Oo0Ooo % O0
  if ( oooOoO0 == False ) : return
 else :
  Ii1IIII = lisp_ms ( o0 , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 51 - 51: IiII % IiII + OOooOOo . II111iiii / I1ii11iIi11i
  if 4 - 4: o0oOOo0O0Ooo % I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
  if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
  if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
  if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
  if 88 - 88: ooOoO0o
 iIIiIi11i = oooO0oo0ooO . eid_records
 if ( oooO0oo0ooO . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , iIIiIi11i , oooO0oo0ooO , Ii1IIII )
  return
  if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
  if 20 - 20: i11iIiiIii * I11i
  if 29 - 29: IiII / OOooOOo
  if 39 - 39: O0 + II111iiii
  if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
  if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
  if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
  if 42 - 42: O0 / oO0o % O0 . i1IIi % OOooOOo
 OOoo = lisp_eid_record ( )
 ii1i1II = OOoo . decode ( iIIiIi11i )
 if ( ii1i1II == None ) : return
 if 13 - 13: I1IiiI % ooOoO0o + OOooOOo
 OOoo . print_record ( "  " , False )
 if 91 - 91: oO0o - ooOoO0o
 for Oo0iIIiiIiiI in range ( OOoo . rloc_count ) :
  O0000O00O00OO = lisp_rloc_record ( )
  ii1i1II = O0000O00O00OO . decode ( ii1i1II , None )
  if ( ii1i1II == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 20 - 20: i1IIi . IiII / o0oOOo0O0Ooo / I11i
  O0000O00O00OO . print_record ( "    " )
  if 27 - 27: ooOoO0o . ooOoO0o - Ii1I % i11iIiiIii
  if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
  if 7 - 7: I1IiiI + OoooooooOO + o0oOOo0O0Ooo . OoooooooOO
  if 29 - 29: iII111i * O0 + I1IiiI * IiII + iII111i - IiII
  if 38 - 38: I1ii11iIi11i - Ii1I % OoooooooOO
 if ( OOoo . group . is_null ( ) == False ) :
  if 43 - 43: iIii1I11I1II1 / OoOoOO00
  if 13 - 13: o0oOOo0O0Ooo / I1Ii111
  if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
  if 32 - 32: oO0o
  if 72 - 72: I1IiiI
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( OOoo . print_eid_tuple ( ) , False ) ) )
  if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
  if 87 - 87: Oo0Ooo
  oOO0O = lisp_control_packet_ipc ( orig_packet , o0 , "lisp-itr" , 0 )
  lisp_ipc ( oOO0O , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 7 - 7: iIii1I11I1II1
  if 85 - 85: iIii1I11I1II1 . O0
  if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
  if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
  if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
 lisp_send_map_notify_ack ( lisp_sockets , iIIiIi11i , oooO0oo0ooO , Ii1IIII )
 return
 if 8 - 8: OoO0O00 . OoO0O00
 if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
 if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
 if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
 if 24 - 24: IiII
 if 95 - 95: IiII + OoOoOO00 * OOooOOo
 if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
 if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
def lisp_process_map_notify_ack ( packet , source ) :
 oooO0oo0ooO = lisp_map_notify ( "" )
 packet = oooO0oo0ooO . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 41 - 41: i1IIi / IiII
  if 73 - 73: o0oOOo0O0Ooo % ooOoO0o
 oooO0oo0ooO . print_notify ( )
 if 72 - 72: OoO0O00 * OoOoOO00 % I1IiiI - OOooOOo . Oo0Ooo
 if 70 - 70: ooOoO0o . o0oOOo0O0Ooo * II111iiii - O0
 if 74 - 74: oO0o % I1IiiI / oO0o / Oo0Ooo / ooOoO0o
 if 29 - 29: ooOoO0o + iIii1I11I1II1 + OoO0O00 - o0oOOo0O0Ooo
 if 74 - 74: II111iiii - II111iiii + ooOoO0o + Oo0Ooo % iIii1I11I1II1
 if ( oooO0oo0ooO . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 90 - 90: oO0o / o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoOoOO00 / IiII
  if 13 - 13: oO0o + IiII
 OOoo = lisp_eid_record ( )
 if 36 - 36: oO0o - OoOoOO00 . O0 % IiII
 if ( OOoo . decode ( oooO0oo0ooO . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
 OOoo . print_record ( "  " , False )
 if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
 iiI1Ii1I = OOoo . print_eid_tuple ( )
 if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
 if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
 if 41 - 41: OoooooooOO + iII111i . OOooOOo
 if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
 if ( oooO0oo0ooO . alg_id != LISP_NONE_ALG_ID and oooO0oo0ooO . auth_len != 0 ) :
  O0oiiii1i1i11I = lisp_sites_by_eid . lookup_cache ( OOoo . eid , True )
  if ( O0oiiii1i1i11I == None ) :
   I11oo = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( I11oo , green ( iiI1Ii1I , False ) ) )
   if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
   return
   if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
  i11I = O0oiiii1i1i11I . site
  if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
  if 57 - 57: II111iiii % OoO0O00 * i1IIi
  if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
  if 9 - 9: II111iiii % OoooooooOO
  i11I . map_notify_acks_received += 1
  if 4 - 4: i1IIi * i11iIiiIii % OoooooooOO + OoOoOO00 . oO0o
  o0O = oooO0oo0ooO . key_id
  if ( i11I . auth_key . has_key ( o0O ) == False ) : o0O = 0
  o000o0OOo = i11I . auth_key [ o0O ]
  if 95 - 95: I1ii11iIi11i * OoOoOO00 % o0oOOo0O0Ooo / O0 + ooOoO0o % OOooOOo
  oooOoO0 = lisp_verify_auth ( packet , oooO0oo0ooO . alg_id ,
 oooO0oo0ooO . auth_data , o000o0OOo )
  if 48 - 48: i1IIi + IiII - iIii1I11I1II1 . i11iIiiIii % OOooOOo + I1ii11iIi11i
  o0O = "key-id {}" . format ( o0O ) if o0O == oooO0oo0ooO . key_id else "bad key-id {}" . format ( oooO0oo0ooO . key_id )
  if 95 - 95: ooOoO0o + OoOoOO00 . II111iiii + Ii1I
  if 81 - 81: OoooooooOO / OOooOOo / Oo0Ooo
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if oooOoO0 else "failed" , o0O ) )
  if 26 - 26: iII111i
  if ( oooOoO0 == False ) : return
  if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
  if 6 - 6: IiII
  if 68 - 68: Oo0Ooo
  if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
  if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
 if ( oooO0oo0ooO . retransmit_timer ) : oooO0oo0ooO . retransmit_timer . cancel ( )
 if 93 - 93: i11iIiiIii
 iI1IIiIiIiII = source . print_address ( )
 iII1 = oooO0oo0ooO . nonce_key
 if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
 if ( lisp_map_notify_queue . has_key ( iII1 ) ) :
  oooO0oo0ooO = lisp_map_notify_queue . pop ( iII1 )
  if ( oooO0oo0ooO . retransmit_timer ) : oooO0oo0ooO . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( iII1 ) )
  if 40 - 40: IiII % IiII
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( oooO0oo0ooO . nonce_key , red ( iI1IIiIiIiII , False ) ) )
  if 9 - 9: I1IiiI * i1IIi + OOooOOo * OoOoOO00
  if 8 - 8: iII111i
 return
 if 51 - 51: I1IiiI
 if 72 - 72: ooOoO0o / I1ii11iIi11i . Ii1I * iII111i . iIii1I11I1II1
 if 35 - 35: OoO0O00 . OoOoOO00 % O0 * OoO0O00
 if 68 - 68: OOooOOo
 if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
 if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
 if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
 if 15 - 15: i1IIi . iII111i + IiII / I1ii11iIi11i - i1IIi / iII111i
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 27 - 27: OoOoOO00 / OoooooooOO + i1IIi % iIii1I11I1II1 / OoO0O00
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 73 - 73: I1ii11iIi11i / OoOoOO00 / IiII + oO0o
 if 73 - 73: I11i * o0oOOo0O0Ooo * I1IiiI . OoooooooOO % I1Ii111
 if 9 - 9: oO0o % I1Ii111 . O0 + I1ii11iIi11i - Ii1I - I1ii11iIi11i
 if 57 - 57: i11iIiiIii
 OOIi = False
 if ( group . is_null ( ) == False ) :
  OOIi = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 21 - 21: iIii1I11I1II1 / I1IiiI / iII111i
 if ( OOIi == False ) :
  OOIi = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 19 - 19: Oo0Ooo / iIii1I11I1II1 / I11i
  if 71 - 71: iIii1I11I1II1 * I1IiiI
 if ( OOIi ) :
  IiI1ii1 = lisp_print_eid_tuple ( eid , group )
  iiOo0OOoOO00o = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 1 - 1: II111iiii % I1IiiI - iIii1I11I1II1
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( IiI1ii1 , False ) , s ,
  # iII111i + i11iIiiIii
 iiOo0OOoOO00o ) )
  if 74 - 74: iII111i + OoO0O00 - I11i
 return ( OOIi )
 if 91 - 91: O0 * I1Ii111 . iIii1I11I1II1
 if 1 - 1: I11i
 if 12 - 12: ooOoO0o - Oo0Ooo / OoO0O00 . I1ii11iIi11i / OOooOOo
 if 51 - 51: ooOoO0o % I11i + IiII + oO0o + O0 % ooOoO0o
 if 38 - 38: OoO0O00 - iIii1I11I1II1 % ooOoO0o + I1ii11iIi11i - Ii1I
 if 69 - 69: OOooOOo / OoooooooOO % ooOoO0o % iIii1I11I1II1 / OoO0O00 + iIii1I11I1II1
 if 47 - 47: II111iiii % O0 / I1IiiI / iIii1I11I1II1 * I11i
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 60 - 60: O0 * iII111i % I1ii11iIi11i
 OOOOo0ooOoOO = lisp_map_referral ( )
 packet = OOOOo0ooOoOO . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 92 - 92: OoOoOO00 / iIii1I11I1II1
 OOOOo0ooOoOO . print_map_referral ( )
 if 67 - 67: i1IIi + i11iIiiIii - i1IIi % OoOoOO00
 o0 = source . print_address ( )
 OO00OO = OOOOo0ooOoOO . nonce
 if 3 - 3: I1IiiI % ooOoO0o
 if 32 - 32: OOooOOo / i1IIi / OOooOOo
 if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
 if 45 - 45: Oo0Ooo
 for i1i1IIIIIIIi in range ( OOOOo0ooOoOO . record_count ) :
  OOoo = lisp_eid_record ( )
  packet = OOoo . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
  OOoo . print_record ( "  " , True )
  if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
  if 52 - 52: OOooOOo + OoO0O00
  if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
  if 42 - 42: i1IIi
  iII1 = str ( OO00OO )
  if ( iII1 not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( OO00OO ) , o0 ) )
   if 52 - 52: OoO0O00 % iII111i % O0
   if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
   continue
   if 50 - 50: oO0o . I1Ii111
  ii1 = lisp_ddt_map_requestQ [ iII1 ]
  if ( ii1 == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( OO00OO ) , o0 ) )
   if 38 - 38: iIii1I11I1II1 . Ii1I
   continue
   if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
   if 15 - 15: O0
   if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
   if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
   if 25 - 25: ooOoO0o
   if 33 - 33: Oo0Ooo
  if ( lisp_map_referral_loop ( ii1 , OOoo . eid , OOoo . group ,
 OOoo . action , o0 ) ) :
   ii1 . dequeue_map_request ( )
   continue
   if 11 - 11: I11i
   if 55 - 55: i11iIiiIii * OoOoOO00 - OoOoOO00 * OoO0O00 / iII111i
  ii1 . last_cached_prefix [ 0 ] = OOoo . eid
  ii1 . last_cached_prefix [ 1 ] = OOoo . group
  if 64 - 64: iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
  if 74 - 74: I1IiiI / o0oOOo0O0Ooo
  if 53 - 53: iIii1I11I1II1 * oO0o
  if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
  i1O0OO00 = False
  oOo00OoOoo = lisp_referral_cache_lookup ( OOoo . eid , OOoo . group ,
 True )
  if ( oOo00OoOoo == None ) :
   i1O0OO00 = True
   oOo00OoOoo = lisp_referral ( )
   oOo00OoOoo . eid = OOoo . eid
   oOo00OoOoo . group = OOoo . group
   if ( OOoo . ddt_incomplete == False ) : oOo00OoOoo . add_cache ( )
  elif ( oOo00OoOoo . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( oOo00OoOoo . print_eid_tuple ( ) , False ) ) )
   if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
   ii1 . dequeue_map_request ( )
   continue
   if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
   if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
  Ii1II1I = OOoo . action
  oOo00OoOoo . referral_source = source
  oOo00OoOoo . referral_type = Ii1II1I
  oo0OOoOO0 = OOoo . store_ttl ( )
  oOo00OoOoo . referral_ttl = oo0OOoOO0
  oOo00OoOoo . expires = lisp_set_timestamp ( oo0OOoOO0 )
  if 60 - 60: oO0o * I1Ii111
  if 81 - 81: oO0o - OOooOOo - oO0o
  if 54 - 54: oO0o % I11i
  if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
  iiiii11i = oOo00OoOoo . is_referral_negative ( )
  if ( oOo00OoOoo . referral_set . has_key ( o0 ) ) :
   IiIiII11 = oOo00OoOoo . referral_set [ o0 ]
   if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
   if ( IiIiII11 . updown == False and iiiii11i == False ) :
    IiIiII11 . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( o0 ) )
    if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
   elif ( IiIiII11 . updown == True and iiiii11i == True ) :
    IiIiII11 . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( o0 ) )
    if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
    if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
    if 73 - 73: O0 % i11iIiiIii
    if 16 - 16: O0
    if 15 - 15: i1IIi % i11iIiiIii
    if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
    if 35 - 35: OoOoOO00 . oO0o / II111iiii
    if 97 - 97: Ii1I + I1Ii111 / II111iiii
  i1i1 = { }
  for iII1 in oOo00OoOoo . referral_set : i1i1 [ iII1 ] = None
  if 64 - 64: I11i / O0 + i1IIi * II111iiii
  if 20 - 20: iIii1I11I1II1
  if 9 - 9: OoO0O00
  if 5 - 5: OOooOOo % iII111i % Oo0Ooo . I11i
  for i1i1IIIIIIIi in range ( OOoo . rloc_count ) :
   O0000O00O00OO = lisp_rloc_record ( )
   packet = O0000O00O00OO . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 25 - 25: iIii1I11I1II1 * OoOoOO00 + ooOoO0o * I11i / I1Ii111 - I11i
   O0000O00O00OO . print_record ( "    " )
   if 5 - 5: I1Ii111 * I11i . ooOoO0o . o0oOOo0O0Ooo - O0
   if 39 - 39: OoO0O00
   if 19 - 19: i1IIi
   if 53 - 53: OOooOOo * O0 . iII111i
   oOo0O = O0000O00O00OO . rloc . print_address ( )
   if ( oOo00OoOoo . referral_set . has_key ( oOo0O ) == False ) :
    IiIiII11 = lisp_referral_node ( )
    IiIiII11 . referral_address . copy_address ( O0000O00O00OO . rloc )
    oOo00OoOoo . referral_set [ oOo0O ] = IiIiII11
    if ( o0 == oOo0O and iiiii11i ) : IiIiII11 . updown = False
   else :
    IiIiII11 = oOo00OoOoo . referral_set [ oOo0O ]
    if ( i1i1 . has_key ( oOo0O ) ) : i1i1 . pop ( oOo0O )
    if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
   IiIiII11 . priority = O0000O00O00OO . priority
   IiIiII11 . weight = O0000O00O00OO . weight
   if 78 - 78: iII111i
   if 80 - 80: i1IIi * I1IiiI + OOooOOo
   if 91 - 91: I1IiiI % OoOoOO00 * Oo0Ooo / I1ii11iIi11i
   if 57 - 57: i11iIiiIii / o0oOOo0O0Ooo . II111iiii
   if 63 - 63: O0
  for iII1 in i1i1 : oOo00OoOoo . referral_set . pop ( iII1 )
  if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
  iiI1Ii1I = oOo00OoOoo . print_eid_tuple ( )
  if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
  if ( i1O0OO00 ) :
   if ( OOoo . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( iiI1Ii1I , False ) ) )
    if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( iiI1Ii1I , False ) , OOoo . rloc_count ) )
    if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
    if 74 - 74: i11iIiiIii
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( iiI1Ii1I , False ) , OOoo . rloc_count ) )
   if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
   if 6 - 6: I11i
   if 70 - 70: ooOoO0o + OoooooooOO % OoOoOO00 % oO0o / Ii1I . I11i
   if 63 - 63: I1ii11iIi11i - ooOoO0o . OOooOOo / O0 . iIii1I11I1II1 - Ii1I
   if 6 - 6: Ii1I
   if 60 - 60: iII111i + I1IiiI
  if ( Ii1II1I == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( ii1 . lisp_sockets , oOo00OoOoo . eid ,
 oOo00OoOoo . group , ii1 . nonce , ii1 . itr , ii1 . sport , 15 , None , False )
   ii1 . dequeue_map_request ( )
   if 36 - 36: i1IIi . O0 . OoO0O00 % OOooOOo * I11i / Ii1I
   if 16 - 16: Oo0Ooo
  if ( Ii1II1I == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( ii1 . tried_root ) :
    lisp_send_negative_map_reply ( ii1 . lisp_sockets , oOo00OoOoo . eid ,
 oOo00OoOoo . group , ii1 . nonce , ii1 . itr , ii1 . sport , 0 , None , False )
    ii1 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( ii1 , True )
    if 44 - 44: iIii1I11I1II1 - II111iiii . IiII . i1IIi
    if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
    if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
  if ( Ii1II1I == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( oOo00OoOoo . referral_set . has_key ( o0 ) ) :
    IiIiII11 = oOo00OoOoo . referral_set [ o0 ]
    IiIiII11 . updown = False
    if 43 - 43: I1ii11iIi11i + I11i
   if ( len ( oOo00OoOoo . referral_set ) == 0 ) :
    ii1 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( ii1 , False )
    if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
    if 100 - 100: IiII - OoOoOO00 / I11i
    if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
  if ( Ii1II1I in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( ii1 . eid . is_exact_match ( OOoo . eid ) ) :
    if ( not ii1 . tried_root ) :
     lisp_send_ddt_map_request ( ii1 , True )
    else :
     lisp_send_negative_map_reply ( ii1 . lisp_sockets ,
 oOo00OoOoo . eid , oOo00OoOoo . group , ii1 . nonce , ii1 . itr ,
 ii1 . sport , 15 , None , False )
     ii1 . dequeue_map_request ( )
     if 87 - 87: Oo0Ooo
   else :
    lisp_send_ddt_map_request ( ii1 , False )
    if 65 - 65: ooOoO0o . I1IiiI
    if 51 - 51: IiII
    if 43 - 43: oO0o - I11i . i11iIiiIii
  if ( Ii1II1I == LISP_DDT_ACTION_MS_ACK ) : ii1 . dequeue_map_request ( )
  if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
 return
 if 30 - 30: I1IiiI % oO0o * OoooooooOO
 if 64 - 64: I1IiiI
 if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
 if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
 if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
 if 90 - 90: o0oOOo0O0Ooo / I1ii11iIi11i - oO0o - Ii1I - I1IiiI + I1Ii111
 if 93 - 93: I1IiiI - I11i . I1IiiI - iIii1I11I1II1
 if 1 - 1: O0 . Ii1I % Ii1I + II111iiii . oO0o
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 O0O00O = lisp_ecm ( 0 )
 packet = O0O00O . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 24 - 24: o0oOOo0O0Ooo . I1Ii111 % O0
  if 67 - 67: I1IiiI * Ii1I
 O0O00O . print_ecm ( )
 if 64 - 64: OOooOOo
 iIIIIII = lisp_control_header ( )
 if ( iIIIIII . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 90 - 90: iII111i . OoOoOO00 + i1IIi % ooOoO0o * I11i + OoooooooOO
  if 2 - 2: o0oOOo0O0Ooo . II111iiii
 I1IiiIIi = iIIIIII . type
 del ( iIIIIII )
 if 4 - 4: ooOoO0o . i11iIiiIii . i1IIi
 if ( I1IiiIIi != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 37 - 37: i11iIiiIii + OoO0O00 * Ii1I
  if 100 - 100: IiII . I1Ii111 + II111iiii + i1IIi
  if 37 - 37: iII111i
  if 27 - 27: iII111i / Ii1I / iII111i + OoooooooOO - O0 + OoO0O00
  if 62 - 62: iIii1I11I1II1
 OO00OOoOoOo = O0O00O . udp_sport
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 O0O00O . source , OO00OOoOoOo , O0O00O . ddt , - 1 )
 return
 if 17 - 17: OOooOOo % i11iIiiIii
 if 63 - 63: I1ii11iIi11i + I1ii11iIi11i % Ii1I + II111iiii / OoooooooOO / I1IiiI
 if 64 - 64: Oo0Ooo / OOooOOo * II111iiii
 if 70 - 70: OoOoOO00 - I11i
 if 50 - 50: I1ii11iIi11i
 if 9 - 9: I11i % I11i . OoOoOO00 / OOooOOo / OoooooooOO
 if 21 - 21: O0 . I1Ii111
 if 2 - 2: O0 % OoOoOO00 + oO0o
 if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
 if 51 - 51: IiII
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
 if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
 if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
 if 95 - 95: O0 - OoOoOO00
 if 68 - 68: ooOoO0o . I1Ii111
 if 84 - 84: OoooooooOO + oO0o % i1IIi + o0oOOo0O0Ooo * i1IIi
 if 51 - 51: oO0o . OoooooooOO + OOooOOo * I1ii11iIi11i - ooOoO0o
 oO00o0oOoo = ms . map_server
 if ( lisp_decent_push_configured and oO00o0oOoo . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  oO00o0oOoo = copy . deepcopy ( oO00o0oOoo )
  oO00o0oOoo . address = 0x7f000001
  iIIi1iI1I1IIi = bold ( "Bootstrap" , False )
  II1IIiIiiI1iI = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( iIIi1iI1I1IIi , II1IIiIiiI1iI ) )
  if 41 - 41: Oo0Ooo
  if 46 - 46: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii . iII111i
  if 66 - 66: oO0o % i1IIi % OoooooooOO
  if 58 - 58: OOooOOo
  if 89 - 89: iIii1I11I1II1 - i1IIi
  if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 9 - 9: I1Ii111 / II111iiii * I1Ii111 / I11i - OoO0O00
 if 36 - 36: IiII . OoOoOO00 . Ii1I
 if 31 - 31: iIii1I11I1II1
 if 84 - 84: I1ii11iIi11i - iII111i * I1IiiI
 if 88 - 88: OOooOOo / Oo0Ooo
 if ( ms . ekey != None ) :
  iI1Ii1iiiII1II = ms . ekey . zfill ( 32 )
  oo0O = "0" * 8
  i1I1i = chacha . ChaCha ( iI1Ii1iiiII1II , oo0O ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + i1I1i
  o0OoO00 = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( o0OoO00 , ms . ekey_id ) )
  if 31 - 31: II111iiii
  if 32 - 32: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 o00O0o = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  o00O0o = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 99 - 99: OoooooooOO - I1ii11iIi11i / i1IIi
  if 44 - 44: I1IiiI * oO0o - OoOoOO00 + ooOoO0o
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( oO00o0oOoo . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , o00O0o ) )
 if 75 - 75: ooOoO0o % OoooooooOO / OoooooooOO / Ii1I / I11i % IiII
 lisp_send ( lisp_sockets , oO00o0oOoo , LISP_CTRL_PORT , packet )
 return
 if 68 - 68: II111iiii . iIii1I11I1II1
 if 23 - 23: iIii1I11I1II1 + I1Ii111 + I1IiiI - i11iIiiIii % IiII % i1IIi
 if 24 - 24: OOooOOo - OoOoOO00 - i1IIi + O0 + I1IiiI . o0oOOo0O0Ooo
 if 97 - 97: I1Ii111 + Ii1I * ooOoO0o
 if 95 - 95: O0
 if 61 - 61: Oo0Ooo % O0 . Ii1I - OOooOOo - o0oOOo0O0Ooo
 if 71 - 71: iIii1I11I1II1
 if 10 - 10: OoooooooOO - iII111i . i1IIi % oO0o . OoooooooOO + OOooOOo
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 O0O00Oo = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 59 - 59: I1IiiI * OoooooooOO % OOooOOo / I11i
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 77 - 77: II111iiii - IiII % OOooOOo
 if 22 - 22: OoooooooOO / oO0o
 packet = lisp_control_packet_ipc ( packet , O0O00Oo , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
 if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
 if 12 - 12: I1Ii111
 if 17 - 17: I1Ii111 % oO0o + O0
 if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
 if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
 if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
 if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 39 - 39: OoOoOO00 - I1ii11iIi11i / I1Ii111
 if 48 - 48: IiII - oO0o + I11i % o0oOOo0O0Ooo
 if 81 - 81: Oo0Ooo . I1Ii111 * iIii1I11I1II1
 if 60 - 60: OoooooooOO
 if 41 - 41: iIii1I11I1II1 + O0 % o0oOOo0O0Ooo - IiII . I11i * O0
 if 39 - 39: i11iIiiIii . Ii1I
 if 68 - 68: OOooOOo * ooOoO0o . I1IiiI - iII111i
 if 81 - 81: I11i % Oo0Ooo / iII111i
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 44 - 44: Oo0Ooo
 if 90 - 90: Oo0Ooo . ooOoO0o / IiII * I1Ii111 . ooOoO0o + II111iiii
 if 43 - 43: iIii1I11I1II1 % OOooOOo + OoOoOO00 + I1ii11iIi11i - Oo0Ooo / Ii1I
 if 94 - 94: Ii1I / Oo0Ooo % II111iiii % Oo0Ooo * oO0o
 if 54 - 54: O0 / ooOoO0o * I1Ii111
 if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
 if 13 - 13: IiII + Oo0Ooo - I1Ii111
 if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
 if 95 - 95: oO0o / Ii1I + OoO0O00
 if 57 - 57: iIii1I11I1II1 + I1Ii111 % oO0o - Ii1I . I1IiiI
 if 39 - 39: OoO0O00 + II111iiii
 if 98 - 98: O0 - I1Ii111 % oO0o - iII111i + Ii1I * i1IIi
 if 76 - 76: o0oOOo0O0Ooo
 if 55 - 55: OOooOOo + I1ii11iIi11i * Oo0Ooo
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 11 - 11: i1IIi - OoooooooOO * OoOoOO00 / oO0o - OoooooooOO - I1IiiI
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
  if 49 - 49: iII111i + I11i . Oo0Ooo
  if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
  if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
  if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
  if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
 if ( lisp_nat_traversal ) :
  O0o0oOOO = lisp_get_any_translated_port ( )
  if ( O0o0oOOO != None ) : inner_sport = O0o0oOOO
  if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
 O0O00O = lisp_ecm ( inner_sport )
 if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
 O0O00O . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 O0O00O . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 O0O00O . ddt = ddt
 O0oooO = O0O00O . encode ( packet , inner_source , inner_dest )
 if ( O0oooO == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 34 - 34: i11iIiiIii + O0
 O0O00O . print_ecm ( )
 if 3 - 3: iIii1I11I1II1
 packet = O0oooO + packet
 if 15 - 15: Oo0Ooo / IiII % i11iIiiIii * I11i . iIii1I11I1II1
 oOo0O = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( oOo0O ) )
 oO00o0oOoo = lisp_convert_4to6 ( oOo0O )
 lisp_send ( lisp_sockets , oO00o0oOoo , LISP_CTRL_PORT , packet )
 return
 if 97 - 97: I1Ii111
 if 55 - 55: Oo0Ooo
 if 20 - 20: i11iIiiIii - Oo0Ooo
 if 47 - 47: iII111i * ooOoO0o . I1IiiI / O0
 if 81 - 81: iII111i + I11i - I1ii11iIi11i + iIii1I11I1II1 / ooOoO0o
 if 60 - 60: iIii1I11I1II1 - OoO0O00
 if 11 - 11: IiII + I1IiiI . Ii1I * I1IiiI - OoooooooOO . II111iiii
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
if 74 - 74: o0oOOo0O0Ooo . iIii1I11I1II1 * Ii1I / O0 - I1Ii111 % oO0o
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 98 - 98: IiII
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 30 - 30: iIii1I11I1II1 - ooOoO0o / iIii1I11I1II1 / I1IiiI + OoOoOO00 - iIii1I11I1II1
if 69 - 69: i11iIiiIii . O0
if 21 - 21: i1IIi . OoO0O00 % I11i + II111iiii % o0oOOo0O0Ooo
if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
if 44 - 44: I1ii11iIi11i
if 39 - 39: iII111i + Oo0Ooo / oO0o
if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 99 - 99: I1IiiI * II111iiii
if 84 - 84: II111iiii - I1IiiI
if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
if 35 - 35: I11i + i1IIi
if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
if 97 - 97: oO0o % iIii1I11I1II1
def byte_swap_64 ( address ) :
 O0o00o000oO = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
 if 16 - 16: I1IiiI
 if 39 - 39: ooOoO0o * II111iiii
 if 90 - 90: OoooooooOO * ooOoO0o
 if 14 - 14: I1IiiI % i1IIi
 if 35 - 35: ooOoO0o % o0oOOo0O0Ooo % ooOoO0o
 if 77 - 77: OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
 if 55 - 55: i1IIi
 return ( O0o00o000oO )
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
class lisp_cache_entries ( ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 51 - 51: o0oOOo0O0Ooo * I11i
  if 42 - 42: OOooOOo % I11i
  if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
class lisp_cache ( ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 81 - 81: I1IiiI
  if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
 def cache_size ( self ) :
  return ( self . cache_count )
  if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
  if 83 - 83: iII111i - I1ii11iIi11i + iII111i
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   O0ooOo = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   O0ooOo = prefix . mask_len
  else :
   O0ooOo = prefix . mask_len + 48
   if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
   if 60 - 60: I1ii11iIi11i / I1Ii111 % i11iIiiIii % oO0o % I1IiiI . Oo0Ooo
  oOo00Ooo0o0 = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  oO0oO00 = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 20 - 20: IiII - OOooOOo + OoOoOO00
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    iI1 = prefix . addr_length ( ) * 2
    O0o00o000oO = lisp_hex_string ( prefix . address ) . zfill ( iI1 )
   else :
    O0o00o000oO = prefix . address
    if 83 - 83: OoooooooOO / I1IiiI + iII111i - iIii1I11I1II1 % ooOoO0o
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   oO0oO00 = "8003"
   O0o00o000oO = prefix . address . print_geo ( )
  else :
   oO0oO00 = ""
   O0o00o000oO = ""
   if 74 - 74: OoO0O00
   if 13 - 13: I1ii11iIi11i / OoO0O00
  iII1 = oOo00Ooo0o0 + oO0oO00 + O0o00o000oO
  return ( [ O0ooOo , iII1 ] )
  if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
  if 94 - 94: IiII * i1IIi
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  O0ooOo , iII1 = self . build_key ( prefix )
  if ( self . cache . has_key ( O0ooOo ) == False ) :
   self . cache [ O0ooOo ] = lisp_cache_entries ( )
   self . cache [ O0ooOo ] . entries = { }
   self . cache [ O0ooOo ] . entries_sorted = [ ]
   self . cache_sorted = sorted ( self . cache )
   if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  if ( self . cache [ O0ooOo ] . entries . has_key ( iII1 ) == False ) :
   self . cache_count += 1
   if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
  self . cache [ O0ooOo ] . entries [ iII1 ] = entry
  self . cache [ O0ooOo ] . entries_sorted = sorted ( self . cache [ O0ooOo ] . entries )
  if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
  if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
 def lookup_cache ( self , prefix , exact ) :
  ii1i1i1Ii , iII1 = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( ii1i1i1Ii ) == False ) : return ( None )
   if ( self . cache [ ii1i1i1Ii ] . entries . has_key ( iII1 ) == False ) : return ( None )
   return ( self . cache [ ii1i1i1Ii ] . entries [ iII1 ] )
   if 87 - 87: iII111i + i1IIi
   if 10 - 10: Oo0Ooo . o0oOOo0O0Ooo - i11iIiiIii / iII111i + i11iIiiIii . I11i
  OO0Oo0Oo = None
  for O0ooOo in self . cache_sorted :
   if ( ii1i1i1Ii < O0ooOo ) : return ( OO0Oo0Oo )
   for o0oo in self . cache [ O0ooOo ] . entries_sorted :
    iiIi1 = self . cache [ O0ooOo ] . entries
    if ( o0oo in iiIi1 ) :
     iIiiiIIiii = iiIi1 [ o0oo ]
     if ( iIiiiIIiii == None ) : continue
     if ( prefix . is_more_specific ( iIiiiIIiii . eid ) ) : OO0Oo0Oo = iIiiiIIiii
     if 40 - 40: iII111i * I11i
     if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
     if 87 - 87: OoOoOO00
  return ( OO0Oo0Oo )
  if 30 - 30: IiII % OoOoOO00 + I1Ii111
  if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
 def delete_cache ( self , prefix ) :
  O0ooOo , iII1 = self . build_key ( prefix )
  if ( self . cache . has_key ( O0ooOo ) == False ) : return
  if ( self . cache [ O0ooOo ] . entries . has_key ( iII1 ) == False ) : return
  self . cache [ O0ooOo ] . entries . pop ( iII1 )
  self . cache [ O0ooOo ] . entries_sorted . remove ( iII1 )
  self . cache_count -= 1
  if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
  if 87 - 87: I11i
 def walk_cache ( self , function , parms ) :
  for O0ooOo in self . cache_sorted :
   for iII1 in self . cache [ O0ooOo ] . entries_sorted :
    iIiiiIIiii = self . cache [ O0ooOo ] . entries [ iII1 ]
    iI1i11I1III11 , parms = function ( iIiiiIIiii , parms )
    if ( iI1i11I1III11 == False ) : return ( parms )
    if 14 - 14: II111iiii / I11i . OOooOOo . Ii1I . II111iiii
    if 57 - 57: i1IIi - Ii1I - i11iIiiIii . O0
  return ( parms )
  if 67 - 67: I1Ii111
  if 49 - 49: IiII / i1IIi . OOooOOo
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 64 - 64: O0
  for O0ooOo in self . cache_sorted :
   for iII1 in self . cache [ O0ooOo ] . entries_sorted :
    iIiiiIIiii = self . cache [ O0ooOo ] . entries [ iII1 ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( O0ooOo , iII1 ,
 iIiiiIIiii ) )
    if 10 - 10: I1ii11iIi11i % ooOoO0o * IiII - iIii1I11I1II1
    if 42 - 42: iII111i
    if 96 - 96: OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
    if 44 - 44: I11i * iIii1I11I1II1 . I1ii11iIi11i
    if 9 - 9: o0oOOo0O0Ooo
    if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
    if 21 - 21: Ii1I * OoOoOO00
    if 29 - 29: iIii1I11I1II1 / ooOoO0o
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 75 - 75: OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
if 88 - 88: OoO0O00 % Ii1I
if 12 - 12: OoooooooOO . O0
if 33 - 33: OoooooooOO / I11i . II111iiii * i1IIi
if 34 - 34: i11iIiiIii / OoOoOO00
if 100 - 100: o0oOOo0O0Ooo - I1IiiI / I11i
if 43 - 43: o0oOOo0O0Ooo % iIii1I11I1II1
def lisp_map_cache_lookup ( source , dest ) :
 if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
 O0O0OOoO00 = dest . is_multicast_address ( )
 if 4 - 4: Ii1I . i1IIi + Oo0Ooo % I11i . OoO0O00
 if 70 - 70: OOooOOo * OoOoOO00 / OoOoOO00 / OoOoOO00
 if 23 - 23: I1IiiI
 if 24 - 24: I1Ii111 * i1IIi % O0 * Ii1I + iII111i
 OoOoooooO00oo = lisp_map_cache . lookup_cache ( dest , False )
 if ( OoOoooooO00oo == None ) :
  iiI1Ii1I = source . print_sg ( dest ) if O0O0OOoO00 else dest . print_address ( )
  iiI1Ii1I = green ( iiI1Ii1I , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( iiI1Ii1I ) )
  return ( None )
  if 14 - 14: oO0o * iII111i + Ii1I + Ii1I * IiII
  if 82 - 82: IiII * ooOoO0o / OOooOOo + OoOoOO00
  if 32 - 32: IiII
  if 90 - 90: I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
  if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
 if ( O0O0OOoO00 == False ) :
  OOo0I111I = green ( OoOoooooO00oo . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , OOo0I111I ) )
  if 96 - 96: O0
  return ( OoOoooooO00oo )
  if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
  if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
  if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
  if 61 - 61: IiII . O0
  if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
 OoOoooooO00oo = OoOoooooO00oo . lookup_source_cache ( source , False )
 if ( OoOoooooO00oo == None ) :
  iiI1Ii1I = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( iiI1Ii1I ) )
  return ( None )
  if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
  if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
  if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
  if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
  if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
 OOo0I111I = green ( OoOoooooO00oo . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , OOo0I111I ) )
 if 32 - 32: OoO0O00 + OOooOOo . OoO0O00 - Oo0Ooo
 return ( OoOoooooO00oo )
 if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
 if 86 - 86: OOooOOo / OoooooooOO - IiII
 if 56 - 56: I1ii11iIi11i - i1IIi * OoooooooOO * O0 * I1IiiI - I1Ii111
 if 32 - 32: OoooooooOO . OOooOOo . OoO0O00 . IiII / I11i % i1IIi
 if 21 - 21: O0 . OoO0O00 * I1ii11iIi11i % iII111i + OoooooooOO
 if 8 - 8: oO0o * iII111i * I11i
 if 30 - 30: I1Ii111
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  iiiI11i1ii1i = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( iiiI11i1ii1i )
  if 61 - 61: iII111i
  if 50 - 50: Ii1I / I1IiiI . O0
  if 49 - 49: I1Ii111 . OoO0O00 % O0
  if 15 - 15: I11i - Oo0Ooo / I1Ii111 . ooOoO0o % I1IiiI
  if 62 - 62: II111iiii + ooOoO0o + I1IiiI
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
 if 13 - 13: I1ii11iIi11i
 if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
 if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
 if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
 if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
 iiiI11i1ii1i = lisp_referral_cache . lookup_cache ( group , exact )
 if ( iiiI11i1ii1i == None ) : return ( None )
 if 18 - 18: OoooooooOO - I1ii11iIi11i
 O0i1I1iI1Iiii1I = iiiI11i1ii1i . lookup_source_cache ( eid , exact )
 if ( O0i1I1iI1Iiii1I ) : return ( O0i1I1iI1Iiii1I )
 if 21 - 21: iIii1I11I1II1 . ooOoO0o / II111iiii + OoO0O00 . i1IIi / Ii1I
 if ( exact ) : iiiI11i1ii1i = None
 return ( iiiI11i1ii1i )
 if 74 - 74: II111iiii
 if 91 - 91: oO0o % II111iiii / I1ii11iIi11i
 if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
 if 99 - 99: OOooOOo
 if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
 if 53 - 53: oO0o / i1IIi - Oo0Ooo - i1IIi + IiII
 if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  OO = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( OO )
  if 56 - 56: Oo0Ooo % I1ii11iIi11i
  if 53 - 53: OoO0O00 . I11i - ooOoO0o
  if 11 - 11: I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
  if 74 - 74: oO0o . I1Ii111 . II111iiii
  if 92 - 92: I1Ii111 % OoooooooOO * I1Ii111
 if ( eid . is_null ( ) ) : return ( None )
 if 78 - 78: Oo0Ooo . I11i . oO0o + O0 / O0
 if 41 - 41: iII111i * OoO0O00 - OoO0O00
 if 72 - 72: o0oOOo0O0Ooo + oO0o . I1ii11iIi11i + OoO0O00 / I1Ii111
 if 58 - 58: Oo0Ooo / II111iiii % OoooooooOO % II111iiii
 if 39 - 39: i1IIi
 if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
 OO = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( OO == None ) : return ( None )
 if 59 - 59: i1IIi
 iIiII = OO . lookup_source_cache ( eid , exact )
 if ( iIiII ) : return ( iIiII )
 if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
 if ( exact ) : OO = None
 return ( OO )
 if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
 if 71 - 71: OOooOOo
 if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
 if 73 - 73: iII111i / I1IiiI * ooOoO0o
 if 85 - 85: I11i + I11i + oO0o - OoOoOO00
 if 15 - 15: OoO0O00
 if 88 - 88: Ii1I % i1IIi / I1Ii111
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 2 - 2: Ii1I . IiII % OoOoOO00
 if ( group . is_null ( ) ) :
  O0oiiii1i1i11I = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( O0oiiii1i1i11I )
  if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
  if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
  if 35 - 35: i11iIiiIii
  if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
  if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
 if ( eid . is_null ( ) ) : return ( None )
 if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
 if 59 - 59: i11iIiiIii . OOooOOo % Oo0Ooo + O0
 if 84 - 84: I1Ii111 / O0 - IiII . I11i / o0oOOo0O0Ooo
 if 12 - 12: i11iIiiIii / Ii1I + i1IIi
 if 54 - 54: I1IiiI
 if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
 O0oiiii1i1i11I = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( O0oiiii1i1i11I == None ) : return ( None )
 if 37 - 37: Oo0Ooo
 if 33 - 33: OoooooooOO - O0 . O0 - o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoO0O00
 if 27 - 27: ooOoO0o . i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 * OoOoOO00 * oO0o
 if 19 - 19: O0 * II111iiii * OoOoOO00
 if 53 - 53: Oo0Ooo
 if 16 - 16: Ii1I
 if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
 if 78 - 78: OoO0O00 + oO0o
 if 86 - 86: ooOoO0o . ooOoO0o + oO0o
 if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
 if 31 - 31: IiII + iII111i
 if 5 - 5: O0 * Ii1I
 if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
 if 77 - 77: OOooOOo / OoooooooOO
 if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
 if 79 - 79: i11iIiiIii % o0oOOo0O0Ooo * II111iiii . i1IIi * Ii1I - i11iIiiIii
 if 31 - 31: IiII / o0oOOo0O0Ooo
 if 27 - 27: Oo0Ooo
 Oooo0OOO0oo0o = O0oiiii1i1i11I . lookup_source_cache ( eid , exact )
 if ( Oooo0OOO0oo0o ) : return ( Oooo0OOO0oo0o )
 if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
 if ( exact ) :
  O0oiiii1i1i11I = None
 else :
  II1i1i = O0oiiii1i1i11I . parent_for_more_specifics
  if ( II1i1i and II1i1i . accept_more_specifics ) :
   if ( group . is_more_specific ( II1i1i . group ) ) : O0oiiii1i1i11I = II1i1i
   if 35 - 35: o0oOOo0O0Ooo % iII111i / O0 * I1IiiI . o0oOOo0O0Ooo / OOooOOo
   if 81 - 81: I1ii11iIi11i - i11iIiiIii
 return ( O0oiiii1i1i11I )
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
 if 48 - 48: iII111i + Ii1I
 if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
 if 89 - 89: OOooOOo - I1Ii111 - iII111i
 if 67 - 67: oO0o
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
class lisp_address ( ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 48 - 48: ooOoO0o + II111iiii
  if 73 - 73: II111iiii
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
  if 35 - 35: II111iiii + IiII
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 66 - 66: o0oOOo0O0Ooo % IiII
  if 39 - 39: IiII
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 18 - 18: iII111i % o0oOOo0O0Ooo - i1IIi
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 53 - 53: o0oOOo0O0Ooo + IiII - ooOoO0o % i11iIiiIii - i11iIiiIii - I1Ii111
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 79 - 79: II111iiii + i11iIiiIii . OOooOOo . I11i / iIii1I11I1II1
   if 62 - 62: O0
   if 52 - 52: OoooooooOO . oO0o
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
  if 21 - 21: i11iIiiIii + II111iiii - i1IIi / OoooooooOO * OOooOOo % Oo0Ooo
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  O0o00o000oO = self . address
  if ( ( ( O0o00o000oO & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( O0o00o000oO & 0xff000000 ) >> 24 ) == 172 ) :
   o000O000o0O = ( O0o00o000oO & 0x00ff0000 ) >> 16
   if ( o000O000o0O >= 16 and o000O000o0O <= 31 ) : return ( True )
   if 62 - 62: O0 . O0 + i11iIiiIii
  if ( ( ( O0o00o000oO & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 57 - 57: II111iiii . I1IiiI . OOooOOo / IiII . II111iiii
  if 80 - 80: I11i * OoO0O00 + ooOoO0o % ooOoO0o
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 16 - 16: iII111i / i11iIiiIii + iIii1I11I1II1
  if 76 - 76: OoooooooOO / Oo0Ooo / I1Ii111 + OoooooooOO
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 65 - 65: Oo0Ooo - I1Ii111
  return ( 0 )
  if 57 - 57: O0
  if 49 - 49: I1ii11iIi11i / OoOoOO00 - I1IiiI + iII111i . OOooOOo % oO0o
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  O0o00o000oO = self . address >> 96
  return ( O0o00o000oO == 0x20010005 )
  if 34 - 34: OoO0O00 - I1IiiI + OoOoOO00
  if 22 - 22: iIii1I11I1II1 . i1IIi . OOooOOo % Oo0Ooo - i1IIi
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
   if 78 - 78: I1IiiI / i1IIi % II111iiii % I1IiiI % Ii1I
  return ( 0 )
  if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
  if 38 - 38: IiII . I1Ii111
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 69 - 69: ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + Ii1I . ooOoO0o
  if 73 - 73: I11i % I11i . ooOoO0o + OoOoOO00
 def packet_format ( self ) :
  if 33 - 33: i11iIiiIii . i11iIiiIii * i11iIiiIii / iIii1I11I1II1 / I1ii11iIi11i . ooOoO0o
  if 11 - 11: iII111i
  if 60 - 60: I1ii11iIi11i / I1Ii111
  if 10 - 10: OoO0O00 * iIii1I11I1II1 / I11i % II111iiii . OoOoOO00 / I1IiiI
  if 4 - 4: Oo0Ooo * o0oOOo0O0Ooo
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
  if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
 def pack_address ( self ) :
  o00OooooOOOO = self . packet_format ( )
  ii1i1II = ""
  if ( self . is_ipv4 ( ) ) :
   ii1i1II = struct . pack ( o00OooooOOOO , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   IiiiI1 = byte_swap_64 ( self . address >> 64 )
   I1IIIi = byte_swap_64 ( self . address & 0xffffffffffffffff )
   ii1i1II = struct . pack ( o00OooooOOOO , IiiiI1 , I1IIIi )
  elif ( self . is_mac ( ) ) :
   O0o00o000oO = self . address
   IiiiI1 = ( O0o00o000oO >> 32 ) & 0xffff
   I1IIIi = ( O0o00o000oO >> 16 ) & 0xffff
   o0Ooo0OoOo = O0o00o000oO & 0xffff
   ii1i1II = struct . pack ( o00OooooOOOO , IiiiI1 , I1IIIi , o0Ooo0OoOo )
  elif ( self . is_e164 ( ) ) :
   O0o00o000oO = self . address
   IiiiI1 = ( O0o00o000oO >> 32 ) & 0xffffffff
   I1IIIi = ( O0o00o000oO & 0xffffffff )
   ii1i1II = struct . pack ( o00OooooOOOO , IiiiI1 , I1IIIi )
  elif ( self . is_dist_name ( ) ) :
   ii1i1II += self . address + "\0"
   if 71 - 71: II111iiii
  return ( ii1i1II )
  if 34 - 34: I1ii11iIi11i * oO0o + OoooooooOO
  if 39 - 39: I1IiiI * ooOoO0o / i11iIiiIii - oO0o - oO0o + O0
 def unpack_address ( self , packet ) :
  o00OooooOOOO = self . packet_format ( )
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 73 - 73: OOooOOo
  O0o00o000oO = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  if 44 - 44: I1ii11iIi11i * i1IIi - iIii1I11I1II1 - oO0o - oO0o * II111iiii
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( O0o00o000oO [ 0 ] )
   if 98 - 98: Oo0Ooo + ooOoO0o / OOooOOo . iIii1I11I1II1 . I1IiiI . OoOoOO00
  elif ( self . is_ipv6 ( ) ) :
   if 92 - 92: i1IIi + OoOoOO00 * i1IIi / IiII
   if 4 - 4: oO0o % OoO0O00 + IiII + o0oOOo0O0Ooo
   if 82 - 82: O0 / I1Ii111 + OOooOOo . IiII + Ii1I
   if 31 - 31: i1IIi * OoO0O00 - Ii1I + I11i
   if 8 - 8: O0 + i1IIi . O0
   if 67 - 67: I1IiiI
   if 42 - 42: ooOoO0o - o0oOOo0O0Ooo % oO0o - ooOoO0o
   if 87 - 87: OoooooooOO / O0
   if ( O0o00o000oO [ 0 ] <= 0xffff and ( O0o00o000oO [ 0 ] & 0xff ) == 0 ) :
    OoO0 = ( O0o00o000oO [ 0 ] << 48 ) << 64
   else :
    OoO0 = byte_swap_64 ( O0o00o000oO [ 0 ] ) << 64
    if 94 - 94: oO0o + Ii1I % IiII
   iI111 = byte_swap_64 ( O0o00o000oO [ 1 ] )
   self . address = OoO0 | iI111
   if 62 - 62: iIii1I11I1II1
  elif ( self . is_mac ( ) ) :
   OOoOO = O0o00o000oO [ 0 ]
   OooOOoO = O0o00o000oO [ 1 ]
   iii1111iII1 = O0o00o000oO [ 2 ]
   self . address = ( OOoOO << 32 ) + ( OooOOoO << 16 ) + iii1111iII1
   if 2 - 2: o0oOOo0O0Ooo / O0
  elif ( self . is_e164 ( ) ) :
   self . address = ( O0o00o000oO [ 0 ] << 32 ) + O0o00o000oO [ 1 ]
   if 29 - 29: OOooOOo . OOooOOo * iII111i % OoO0O00
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   oO0o00O = 0
   if 66 - 66: Ii1I / OoO0O00 * i11iIiiIii * oO0o . iIii1I11I1II1
  packet = packet [ oO0o00O : : ]
  return ( packet )
  if 16 - 16: Oo0Ooo % IiII * o0oOOo0O0Ooo % OoOoOO00 - OoooooooOO
  if 61 - 61: i11iIiiIii - i1IIi + iIii1I11I1II1 * I1IiiI % OoOoOO00 . oO0o
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 24 - 24: iII111i . i1IIi * I1ii11iIi11i
  if 1 - 1: oO0o / OoOoOO00 + I1IiiI
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 47 - 47: O0 / OOooOOo . i1IIi / OoooooooOO . IiII
  if 34 - 34: OoO0O00 * II111iiii + I1Ii111
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 20 - 20: iIii1I11I1II1 . OoO0O00 . II111iiii / Ii1I - iIii1I11I1II1 / OOooOOo
  if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
  if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
  if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
  if 65 - 65: I1IiiI . ooOoO0o
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 51 - 51: I1Ii111
  if 89 - 89: Oo0Ooo
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 15 - 15: OOooOOo * II111iiii - OOooOOo * iIii1I11I1II1
  if 95 - 95: I1Ii111 / OoooooooOO * I11i * OoooooooOO
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 88 - 88: I1IiiI / Oo0Ooo / oO0o + oO0o % OOooOOo + Oo0Ooo
  if 63 - 63: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo % iIii1I11I1II1 / I1ii11iIi11i - iII111i
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 72 - 72: iII111i % oO0o . IiII + I1ii11iIi11i . IiII . II111iiii
  if 10 - 10: I11i . ooOoO0o + I11i * Ii1I
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 55 - 55: OOooOOo / iII111i + OoooooooOO - OoooooooOO
  if 51 - 51: O0 % Ii1I % Oo0Ooo - O0
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 94 - 94: OoooooooOO - ooOoO0o % I1ii11iIi11i + I1Ii111
  if 51 - 51: I1ii11iIi11i . iII111i / i1IIi * ooOoO0o % I11i
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 82 - 82: O0 % OoOoOO00 . iII111i . i1IIi . iII111i - Oo0Ooo
  if 58 - 58: O0 * OOooOOo
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 60 - 60: ooOoO0o
  if 47 - 47: i11iIiiIii
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 21 - 21: i1IIi - oO0o - Oo0Ooo
  if 11 - 11: i1IIi
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
  return ( False )
  if 56 - 56: Ii1I . iII111i
  if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
  if 52 - 52: i11iIiiIii
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 1 - 1: i1IIi * iIii1I11I1II1
  if 29 - 29: I11i
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
  if 6 - 6: IiII / OoO0O00
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
  if 77 - 77: Ii1I
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 9 - 9: OOooOOo / OoooooooOO + iII111i
  if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 20 - 20: I1Ii111
  if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
  if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
  if 56 - 56: iII111i * II111iiii . OoooooooOO . I11i
  if 25 - 25: ooOoO0o % o0oOOo0O0Ooo - i11iIiiIii
  if 79 - 79: iII111i - I1IiiI % O0 / Oo0Ooo + OoOoOO00 . Oo0Ooo
  i1i1IIIIIIIi = addr_str . find ( "[" )
  Oo0iIIiiIiiI = addr_str . find ( "]" )
  if ( i1i1IIIIIIIi != - 1 and Oo0iIIiiIiiI != - 1 ) :
   self . instance_id = int ( addr_str [ i1i1IIIIIIIi + 1 : Oo0iIIiiIiiI ] )
   addr_str = addr_str [ Oo0iIIiiIiiI + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 59 - 59: I1ii11iIi11i * OoOoOO00 / Ii1I
    if 80 - 80: IiII - ooOoO0o / OoOoOO00 / I11i * O0 + oO0o
    if 77 - 77: ooOoO0o + I1ii11iIi11i * o0oOOo0O0Ooo / i1IIi * I11i
    if 70 - 70: oO0o / iII111i * i1IIi / II111iiii / OoOoOO00 + oO0o
    if 30 - 30: i1IIi - iII111i - i11iIiiIii . OoOoOO00 . o0oOOo0O0Ooo
    if 74 - 74: i11iIiiIii / II111iiii
  if ( self . is_ipv4 ( ) ) :
   oOo = addr_str . split ( "." )
   Oooo0oOOO0 = int ( oOo [ 0 ] ) << 24
   Oooo0oOOO0 += int ( oOo [ 1 ] ) << 16
   Oooo0oOOO0 += int ( oOo [ 2 ] ) << 8
   Oooo0oOOO0 += int ( oOo [ 3 ] )
   self . address = Oooo0oOOO0
  elif ( self . is_ipv6 ( ) ) :
   if 45 - 45: OoOoOO00 + I1Ii111 + Oo0Ooo
   if 73 - 73: OoO0O00 / o0oOOo0O0Ooo % Ii1I * ooOoO0o
   if 94 - 94: I1IiiI . iII111i - iIii1I11I1II1 . Oo0Ooo
   if 40 - 40: Ii1I
   if 26 - 26: OoO0O00 / IiII
   if 31 - 31: Ii1I / OoO0O00 % ooOoO0o / I11i . I1ii11iIi11i
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
   i11IIIi = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 57 - 57: OoOoOO00 . iII111i
   addr_str = binascii . hexlify ( addr_str )
   if 43 - 43: I1Ii111 * OOooOOo - IiII . i11iIiiIii
   if ( i11IIIi ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 34 - 34: iII111i . OoOoOO00
   self . address = int ( addr_str , 16 )
   if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
  elif ( self . is_geo_prefix ( ) ) :
   OOoooo = lisp_geo ( None )
   OOoooo . name = "geo-prefix-{}" . format ( OOoooo )
   OOoooo . parse_geo_string ( addr_str )
   self . address = OOoooo
  elif ( self . is_mac ( ) ) :
   addr_str = addr_str . replace ( "-" , "" )
   Oooo0oOOO0 = int ( addr_str , 16 )
   self . address = Oooo0oOOO0
  elif ( self . is_e164 ( ) ) :
   addr_str = addr_str [ 1 : : ]
   Oooo0oOOO0 = int ( addr_str , 16 )
   self . address = Oooo0oOOO0 << 4
  elif ( self . is_dist_name ( ) ) :
   self . address = addr_str . replace ( "'" , "" )
   if 20 - 20: I1ii11iIi11i . iIii1I11I1II1 - Ii1I % OoO0O00
  self . mask_len = self . host_mask_len ( )
  if 27 - 27: iIii1I11I1II1 / I1Ii111 - I11i . OoO0O00 + ooOoO0o
  if 89 - 89: I1IiiI % I11i - OOooOOo
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   OO000o00 = prefix_str . find ( "]" )
   Ooo0o00 = len ( prefix_str [ OO000o00 + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , Ooo0o00 = prefix_str . split ( "/" )
  else :
   IIIIIiII1 = prefix_str . find ( "'" )
   if ( IIIIIiII1 == - 1 ) : return
   iiiiI1iiiIi = prefix_str . find ( "'" , IIIIIiII1 + 1 )
   if ( iiiiI1iiiIi == - 1 ) : return
   Ooo0o00 = len ( prefix_str [ IIIIIiII1 + 1 : iiiiI1iiiIi ] ) * 8
   if 71 - 71: OOooOOo % Oo0Ooo - o0oOOo0O0Ooo / I1Ii111 - O0 - oO0o
   if 10 - 10: I1IiiI
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( Ooo0o00 )
  if 17 - 17: i11iIiiIii % o0oOOo0O0Ooo . ooOoO0o
  if 34 - 34: OoooooooOO / iII111i / O0
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  O0OO0O000o = ( 2 ** self . mask_len ) - 1
  oOo00o0o = self . addr_length ( ) * 8 - self . mask_len
  O0OO0O000o <<= oOo00o0o
  self . address &= O0OO0O000o
  if 25 - 25: Ii1I % i1IIi * I11i * Ii1I - IiII . i11iIiiIii
  if 40 - 40: OOooOOo - OoooooooOO
 def is_geo_string ( self , addr_str ) :
  OO000o00 = addr_str . find ( "]" )
  if ( OO000o00 != - 1 ) : addr_str = addr_str [ OO000o00 + 1 : : ]
  if 36 - 36: i1IIi % OoOoOO00 - i1IIi
  OOoooo = addr_str . split ( "/" )
  if ( len ( OOoooo ) == 2 ) :
   if ( OOoooo [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
  OOoooo = OOoooo [ 0 ]
  OOoooo = OOoooo . split ( "-" )
  o0OoOOoO0o0 = len ( OOoooo )
  if ( o0OoOOoO0o0 < 8 or o0OoOOoO0o0 > 9 ) : return ( False )
  if 48 - 48: O0 - I1ii11iIi11i * ooOoO0o - iII111i - Ii1I - I1Ii111
  for iioo0O0o0oo0O in range ( 0 , o0OoOOoO0o0 ) :
   if ( iioo0O0o0oo0O == 3 ) :
    if ( OOoooo [ iioo0O0o0oo0O ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 4 - 4: Ii1I + ooOoO0o * i11iIiiIii + iII111i
   if ( iioo0O0o0oo0O == 7 ) :
    if ( OOoooo [ iioo0O0o0oo0O ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 77 - 77: OoO0O00 . iII111i
   if ( OOoooo [ iioo0O0o0oo0O ] . isdigit ( ) == False ) : return ( False )
   if 77 - 77: I1Ii111 . IiII % OoO0O00 + I1Ii111 % OoooooooOO
  return ( True )
  if 17 - 17: OoooooooOO - i1IIi * I11i
  if 33 - 33: i1IIi . Oo0Ooo + I11i
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 78 - 78: I1Ii111 + I1Ii111
  if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
 def print_address ( self ) :
  O0o00o000oO = self . print_address_no_iid ( )
  oOo00Ooo0o0 = "[" + str ( self . instance_id )
  for i1i1IIIIIIIi in self . iid_list : oOo00Ooo0o0 += "," + str ( i1i1IIIIIIIi )
  oOo00Ooo0o0 += "]"
  O0o00o000oO = "{}{}" . format ( oOo00Ooo0o0 , O0o00o000oO )
  return ( O0o00o000oO )
  if 19 - 19: Ii1I
  if 51 - 51: oO0o
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   O0o00o000oO = self . address
   OoOO00OO = O0o00o000oO >> 24
   IIii1iiI = ( O0o00o000oO >> 16 ) & 0xff
   II1 = ( O0o00o000oO >> 8 ) & 0xff
   ooO0oo = O0o00o000oO & 0xff
   return ( "{}.{}.{}.{}" . format ( OoOO00OO , IIii1iiI , II1 , ooO0oo ) )
  elif ( self . is_ipv6 ( ) ) :
   oOo0O = lisp_hex_string ( self . address ) . zfill ( 32 )
   oOo0O = binascii . unhexlify ( oOo0O )
   oOo0O = socket . inet_ntop ( socket . AF_INET6 , oOo0O )
   return ( "{}" . format ( oOo0O ) )
  elif ( self . is_geo_prefix ( ) ) :
   return ( "{}" . format ( self . address . print_geo ( ) ) )
  elif ( self . is_mac ( ) ) :
   oOo0O = lisp_hex_string ( self . address ) . zfill ( 12 )
   oOo0O = "{}-{}-{}" . format ( oOo0O [ 0 : 4 ] , oOo0O [ 4 : 8 ] ,
 oOo0O [ 8 : 12 ] )
   return ( "{}" . format ( oOo0O ) )
  elif ( self . is_e164 ( ) ) :
   oOo0O = lisp_hex_string ( self . address ) . zfill ( 15 )
   return ( "+{}" . format ( oOo0O ) )
  elif ( self . is_dist_name ( ) ) :
   return ( "'{}'" . format ( self . address ) )
  elif ( self . is_null ( ) ) :
   return ( "no-address" )
   if 56 - 56: II111iiii + II111iiii - I1ii11iIi11i
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 48 - 48: I1Ii111 / I1ii11iIi11i % OOooOOo
  if 8 - 8: O0 . IiII - ooOoO0o * OoOoOO00 / OoO0O00 - O0
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   I1I1i11i1I1 = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , I1I1i11i1I1 ) )
   if 48 - 48: iIii1I11I1II1 + i1IIi . I1IiiI % OoO0O00 - iIii1I11I1II1 / i1IIi
  O0o00o000oO = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( O0o00o000oO )
  if ( self . is_geo_prefix ( ) ) : return ( O0o00o000oO )
  if 14 - 14: IiII . I11i
  OO000o00 = O0o00o000oO . find ( "no-address" )
  if ( OO000o00 == - 1 ) :
   O0o00o000oO = "{}/{}" . format ( O0o00o000oO , str ( self . mask_len ) )
  else :
   O0o00o000oO = O0o00o000oO [ 0 : OO000o00 ]
   if 13 - 13: OoOoOO00 - I11i . OOooOOo % OoO0O00
  return ( O0o00o000oO )
  if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
  if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
 def print_prefix_no_iid ( self ) :
  O0o00o000oO = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( O0o00o000oO )
  if ( self . is_geo_prefix ( ) ) : return ( O0o00o000oO )
  return ( "{}/{}" . format ( O0o00o000oO , str ( self . mask_len ) ) )
  if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
  if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  O0o00o000oO = self . print_address ( )
  OO000o00 = O0o00o000oO . find ( "]" )
  if ( OO000o00 != - 1 ) : O0o00o000oO = O0o00o000oO [ OO000o00 + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   O0o00o000oO = O0o00o000oO . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , O0o00o000oO ) )
   if 9 - 9: iIii1I11I1II1
  return ( "{}-{}-{}" . format ( self . instance_id , O0o00o000oO , self . mask_len ) )
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
 def print_sg ( self , g ) :
  o0 = self . print_prefix ( )
  III1iIIIi = o0 . find ( "]" ) + 1
  g = g . print_prefix ( )
  IIi1IiiIiiI = g . find ( "]" ) + 1
  iii1IiI1I1 = "[{}]({}, {})" . format ( self . instance_id , o0 [ III1iIIIi : : ] , g [ IIi1IiiIiiI : : ] )
  return ( iii1IiI1I1 )
  if 47 - 47: II111iiii / o0oOOo0O0Ooo * o0oOOo0O0Ooo + oO0o
  if 3 - 3: Oo0Ooo
 def hash_address ( self , addr ) :
  IiiiI1 = self . address
  I1IIIi = addr . address
  if 82 - 82: OoooooooOO + OoO0O00 . OoO0O00 * OoO0O00
  if ( self . is_geo_prefix ( ) ) : IiiiI1 = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : I1IIIi = addr . address . print_geo ( )
  if 99 - 99: I1ii11iIi11i - OoooooooOO - Ii1I / Oo0Ooo
  if ( type ( IiiiI1 ) == str ) :
   IiiiI1 = int ( binascii . hexlify ( IiiiI1 [ 0 : 1 ] ) )
   if 96 - 96: o0oOOo0O0Ooo . II111iiii
  if ( type ( I1IIIi ) == str ) :
   I1IIIi = int ( binascii . hexlify ( I1IIIi [ 0 : 1 ] ) )
   if 14 - 14: OoooooooOO - i1IIi / i11iIiiIii - OOooOOo - i11iIiiIii . ooOoO0o
  return ( IiiiI1 ^ I1IIIi )
  if 8 - 8: oO0o * O0 - II111iiii + I1IiiI
  if 85 - 85: OoooooooOO % i11iIiiIii / IiII % OoOoOO00 + O0
  if 6 - 6: OoooooooOO
  if 97 - 97: II111iiii + o0oOOo0O0Ooo * II111iiii
  if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
  if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  Ooo0o00 = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   i1IIIii111 = 2 ** ( 32 - Ooo0o00 )
   IIIiI1 = prefix . instance_id
   I1I1i11i1I1 = IIIiI1 + i1IIIii111
   return ( self . instance_id in range ( IIIiI1 , I1I1i11i1I1 ) )
   if 3 - 3: iIii1I11I1II1 / I1IiiI % OoO0O00 . I1Ii111
   if 46 - 46: I11i % iII111i % iII111i / I11i / I1IiiI
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 74 - 74: oO0o / iIii1I11I1II1 + Oo0Ooo * ooOoO0o % iII111i % i1IIi
   if 68 - 68: OoooooooOO
   if 81 - 81: OoO0O00 % i1IIi
   if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
   if 38 - 38: OoOoOO00 % OoooooooOO . oO0o - OoooooooOO + I11i
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   O0o00o000oO = self . address
   Ii11III = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    O0o00o000oO = self . address . print_geo ( )
    Ii11III = prefix . address . print_geo ( )
    if 42 - 42: oO0o % OoOoOO00 - oO0o + I11i / i11iIiiIii
   if ( len ( O0o00o000oO ) < len ( Ii11III ) ) : return ( False )
   return ( O0o00o000oO . find ( Ii11III ) == 0 )
   if 74 - 74: OoO0O00 - II111iiii - ooOoO0o % i1IIi
   if 42 - 42: i11iIiiIii / O0
   if 8 - 8: I1Ii111
   if 51 - 51: i11iIiiIii
   if 1 - 1: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i
  if ( self . mask_len < Ooo0o00 ) : return ( False )
  if 58 - 58: i11iIiiIii * i11iIiiIii - OoO0O00
  oOo00o0o = ( prefix . addr_length ( ) * 8 ) - Ooo0o00
  O0OO0O000o = ( 2 ** Ooo0o00 - 1 ) << oOo00o0o
  return ( ( self . address & O0OO0O000o ) == prefix . address )
  if 8 - 8: i11iIiiIii * OoOoOO00 . o0oOOo0O0Ooo
  if 27 - 27: I1ii11iIi11i + Ii1I % I1Ii111
 def mask_address ( self , mask_len ) :
  oOo00o0o = ( self . addr_length ( ) * 8 ) - mask_len
  O0OO0O000o = ( 2 ** mask_len - 1 ) << oOo00o0o
  self . address &= O0OO0O000o
  if 20 - 20: Oo0Ooo
  if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  Iii1i1 = self . print_prefix ( )
  o0o00o0 = prefix . print_prefix ( ) if prefix else ""
  return ( Iii1i1 == o0o00o0 )
  if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
  if 54 - 54: oO0o + I11i - OoO0O00
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   oOoI1 = lisp_myrlocs [ 0 ]
   if ( oOoI1 == None ) : return ( False )
   oOoI1 = oOoI1 . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == oOoI1 )
   if 22 - 22: OoooooooOO + OoOoOO00 - Ii1I . iII111i / OoooooooOO / I1IiiI
  if ( self . is_ipv6 ( ) ) :
   oOoI1 = lisp_myrlocs [ 1 ]
   if ( oOoI1 == None ) : return ( False )
   oOoI1 = oOoI1 . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == oOoI1 )
   if 73 - 73: i1IIi - Ii1I + oO0o * iIii1I11I1II1
  return ( False )
  if 100 - 100: i11iIiiIii / iIii1I11I1II1 + Oo0Ooo + OoO0O00 - iII111i
  if 8 - 8: i11iIiiIii . O0 + o0oOOo0O0Ooo * oO0o + II111iiii
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid is 0 and mask_len is 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 61 - 61: ooOoO0o / ooOoO0o
  self . instance_id = iid
  self . mask_len = mask_len
  if 51 - 51: iIii1I11I1II1 / oO0o * I1Ii111 + i1IIi
  if 96 - 96: Oo0Ooo + oO0o - Oo0Ooo - OoOoOO00 % OOooOOo . iIii1I11I1II1
 def lcaf_length ( self , lcaf_type ) :
  iI1 = self . addr_length ( ) + 2
  if ( lcaf_type == LISP_LCAF_AFI_LIST_TYPE ) : iI1 += 4
  if ( lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE ) : iI1 += 4
  if ( lcaf_type == LISP_LCAF_ASN_TYPE ) : iI1 += 4
  if ( lcaf_type == LISP_LCAF_APP_DATA_TYPE ) : iI1 += 8
  if ( lcaf_type == LISP_LCAF_GEO_COORD_TYPE ) : iI1 += 12
  if ( lcaf_type == LISP_LCAF_OPAQUE_TYPE ) : iI1 += 0
  if ( lcaf_type == LISP_LCAF_NAT_TYPE ) : iI1 += 4
  if ( lcaf_type == LISP_LCAF_NONCE_LOC_TYPE ) : iI1 += 4
  if ( lcaf_type == LISP_LCAF_MCAST_INFO_TYPE ) : iI1 = iI1 * 2 + 8
  if ( lcaf_type == LISP_LCAF_ELP_TYPE ) : iI1 += 0
  if ( lcaf_type == LISP_LCAF_SECURITY_TYPE ) : iI1 += 6
  if ( lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE ) : iI1 += 4
  if ( lcaf_type == LISP_LCAF_RLE_TYPE ) : iI1 += 4
  return ( iI1 )
  if 93 - 93: iIii1I11I1II1 % OoooooooOO
  if 6 - 6: II111iiii / oO0o - OOooOOo . O0 - o0oOOo0O0Ooo
  if 72 - 72: iIii1I11I1II1 / OoooooooOO * ooOoO0o / ooOoO0o % O0 + IiII
  if 96 - 96: iII111i / i11iIiiIii + Oo0Ooo . I1IiiI + iII111i % OoOoOO00
  if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
  if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
  if 87 - 87: iII111i
  if 86 - 86: IiII - I11i
  if 99 - 99: i1IIi + I1ii11iIi11i
  if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
  if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
  if 44 - 44: II111iiii / I1ii11iIi11i
  if 39 - 39: OoooooooOO % OoO0O00
  if 83 - 83: OOooOOo % I1IiiI + O0 % OoooooooOO
  if 84 - 84: I11i - Oo0Ooo % ooOoO0o - II111iiii
  if 29 - 29: IiII
  if 4 - 4: II111iiii * o0oOOo0O0Ooo - IiII * iII111i
 def lcaf_encode_iid ( self ) :
  iiii1II = LISP_LCAF_INSTANCE_ID_TYPE
  IIiIi1II1IiI = socket . htons ( self . lcaf_length ( iiii1II ) )
  oOo00Ooo0o0 = self . instance_id
  oO0oO00 = self . afi
  O0ooOo = 0
  if ( oO0oO00 < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    oO0oO00 = LISP_AFI_LCAF
    O0ooOo = 0
   else :
    oO0oO00 = 0
    O0ooOo = self . mask_len
    if 91 - 91: I1Ii111 * iII111i * OoO0O00
    if 79 - 79: iII111i + oO0o
    if 19 - 19: I1Ii111 - OOooOOo . ooOoO0o . O0 + II111iiii . OoooooooOO
  oooO = struct . pack ( "BBBBH" , 0 , 0 , iiii1II , O0ooOo , IIiIi1II1IiI )
  oooO += struct . pack ( "IH" , socket . htonl ( oOo00Ooo0o0 ) , socket . htons ( oO0oO00 ) )
  if ( oO0oO00 == 0 ) : return ( oooO )
  if 100 - 100: oO0o
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   oooO = oooO [ 0 : - 2 ]
   oooO += self . address . encode_geo ( )
   return ( oooO )
   if 7 - 7: i11iIiiIii - O0
   if 76 - 76: i1IIi . OOooOOo * iIii1I11I1II1 / I1ii11iIi11i % i11iIiiIii / O0
  oooO += self . pack_address ( )
  return ( oooO )
  if 83 - 83: oO0o % OoooooooOO
  if 36 - 36: IiII * OoOoOO00 - iIii1I11I1II1 + II111iiii
 def lcaf_decode_iid ( self , packet ) :
  o00OooooOOOO = "BBBBH"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 65 - 65: I1IiiI * I11i . I1Ii111 % I1ii11iIi11i + O0
  OoOO0OOOO0 , oOoOoO0Oo0oo , iiii1II , Oo00OOOo00 , iI1 = struct . unpack ( o00OooooOOOO ,
 packet [ : oO0o00O ] )
  packet = packet [ oO0o00O : : ]
  if 11 - 11: OOooOOo % OOooOOo - i11iIiiIii - o0oOOo0O0Ooo
  if ( iiii1II != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 23 - 23: iII111i * OoO0O00 + o0oOOo0O0Ooo - I1ii11iIi11i % O0 - Oo0Ooo
  o00OooooOOOO = "IH"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( None )
  if 42 - 42: I11i . I1ii11iIi11i - I11i . OoOoOO00
  oOo00Ooo0o0 , oO0oO00 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  packet = packet [ oO0o00O : : ]
  if 46 - 46: iII111i
  iI1 = socket . ntohs ( iI1 )
  self . instance_id = socket . ntohl ( oOo00Ooo0o0 )
  oO0oO00 = socket . ntohs ( oO0oO00 )
  self . afi = oO0oO00
  if ( Oo00OOOo00 != 0 and oO0oO00 == 0 ) : self . mask_len = Oo00OOOo00
  if ( oO0oO00 == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if Oo00OOOo00 else LISP_AFI_ULTIMATE_ROOT
   if 82 - 82: Oo0Ooo % Ii1I * I1Ii111
   if 74 - 74: OoO0O00 - oO0o * I1Ii111
   if 50 - 50: Ii1I % i11iIiiIii - I1Ii111
   if 32 - 32: iIii1I11I1II1 + i1IIi - iII111i + i1IIi / OoOoOO00
   if 29 - 29: OOooOOo
  if ( oO0oO00 == 0 ) : return ( packet )
  if 18 - 18: iII111i - OoO0O00 + oO0o
  if 55 - 55: OoO0O00 / Ii1I % ooOoO0o . I1Ii111 * i1IIi . i11iIiiIii
  if 34 - 34: I1ii11iIi11i % o0oOOo0O0Ooo % ooOoO0o * Ii1I * I1Ii111
  if 59 - 59: Ii1I + Oo0Ooo % O0 % i1IIi - iII111i
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 4 - 4: O0 - oO0o % OoO0O00 % OoooooooOO
   if 67 - 67: I11i
   if 23 - 23: I1ii11iIi11i - OoOoOO00
   if 90 - 90: ooOoO0o - I11i / OoOoOO00
   if 12 - 12: II111iiii % I1IiiI - I1ii11iIi11i
  if ( oO0oO00 == LISP_AFI_LCAF ) :
   o00OooooOOOO = "BBBBH"
   oO0o00O = struct . calcsize ( o00OooooOOOO )
   if ( len ( packet ) < oO0o00O ) : return ( None )
   if 24 - 24: Ii1I + I11i
   Ooo0o00O0O0oO , OO000OOO , iiii1II , o000OOooo000O , o00O0oOO0o = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
   if 5 - 5: I1Ii111 . Ii1I - ooOoO0o % OoooooooOO
   if 2 - 2: OOooOOo . IiII . iII111i / Oo0Ooo
   if ( iiii1II != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 86 - 86: OOooOOo . o0oOOo0O0Ooo - iIii1I11I1II1
   o00O0oOO0o = socket . ntohs ( o00O0oOO0o )
   packet = packet [ oO0o00O : : ]
   if ( o00O0oOO0o > len ( packet ) ) : return ( None )
   if 12 - 12: oO0o + iII111i
   OOoooo = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = OOoooo
   packet = OOoooo . decode_geo ( packet , o00O0oOO0o , o000OOooo000O )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 16 - 16: O0 + oO0o - ooOoO0o * O0 . I1ii11iIi11i . oO0o
   if 4 - 4: I1Ii111
  IIiIi1II1IiI = self . addr_length ( )
  if ( len ( packet ) < IIiIi1II1IiI ) : return ( None )
  if 39 - 39: OoOoOO00 - I1Ii111 / I11i + II111iiii * I1IiiI * I1IiiI
  packet = self . unpack_address ( packet )
  return ( packet )
  if 9 - 9: IiII * I1IiiI * OoO0O00 - I1IiiI * I1IiiI - OoO0O00
  if 20 - 20: i1IIi + I1IiiI + i11iIiiIii + II111iiii + i1IIi
  if 18 - 18: i11iIiiIii * O0 * Oo0Ooo + iII111i + OOooOOo
  if 62 - 62: OOooOOo - oO0o + i1IIi % Ii1I . I1Ii111 . II111iiii
  if 94 - 94: OOooOOo - I1IiiI
  if 35 - 35: i11iIiiIii
  if 27 - 27: O0 % i11iIiiIii - I1Ii111 * oO0o - I11i / Oo0Ooo
  if 78 - 78: O0 * i11iIiiIii
  if 62 - 62: OoO0O00 * I1Ii111 * Ii1I / ooOoO0o
  if 27 - 27: oO0o . iII111i . oO0o
  if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
  if 14 - 14: I11i + ooOoO0o . oO0o * I11i
  if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
  if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
  if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
  if 33 - 33: I11i
  if 37 - 37: Oo0Ooo
  if 36 - 36: IiII % I11i
  if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
  if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
  if 82 - 82: OoooooooOO
 def lcaf_encode_sg ( self , group ) :
  iiii1II = LISP_LCAF_MCAST_INFO_TYPE
  oOo00Ooo0o0 = socket . htonl ( self . instance_id )
  IIiIi1II1IiI = socket . htons ( self . lcaf_length ( iiii1II ) )
  oooO = struct . pack ( "BBBBHIHBB" , 0 , 0 , iiii1II , 0 , IIiIi1II1IiI , oOo00Ooo0o0 ,
 0 , self . mask_len , group . mask_len )
  if 14 - 14: OoO0O00 / oO0o - OOooOOo
  oooO += struct . pack ( "H" , socket . htons ( self . afi ) )
  oooO += self . pack_address ( )
  oooO += struct . pack ( "H" , socket . htons ( group . afi ) )
  oooO += group . pack_address ( )
  return ( oooO )
  if 100 - 100: IiII - I11i . iIii1I11I1II1 / iIii1I11I1II1
  if 16 - 16: IiII + Oo0Ooo % I11i
 def lcaf_decode_sg ( self , packet ) :
  o00OooooOOOO = "BBBBHIHBB"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( [ None , None ] )
  if 16 - 16: ooOoO0o / I1Ii111
  OoOO0OOOO0 , oOoOoO0Oo0oo , iiii1II , O0Ooo000Ooo , iI1 , oOo00Ooo0o0 , OOOoO0Oo , iI1i1i , iiii = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
  if 54 - 54: iIii1I11I1II1 % ooOoO0o
  packet = packet [ oO0o00O : : ]
  if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
  if ( iiii1II != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 92 - 92: I11i + OoO0O00 . OoooooooOO
  self . instance_id = socket . ntohl ( oOo00Ooo0o0 )
  iI1 = socket . ntohs ( iI1 ) - 8
  if 3 - 3: OoO0O00 % iIii1I11I1II1
  if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
  if 59 - 59: iIii1I11I1II1
  if 18 - 18: ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
  if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
  o00OooooOOOO = "H"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( [ None , None ] )
  if ( iI1 < oO0o00O ) : return ( [ None , None ] )
  if 63 - 63: I11i
  oO0oO00 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] ) [ 0 ]
  packet = packet [ oO0o00O : : ]
  iI1 -= oO0o00O
  self . afi = socket . ntohs ( oO0oO00 )
  self . mask_len = iI1i1i
  IIiIi1II1IiI = self . addr_length ( )
  if ( iI1 < IIiIi1II1IiI ) : return ( [ None , None ] )
  if 60 - 60: I1IiiI / I1ii11iIi11i / I11i / Ii1I + iIii1I11I1II1
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 85 - 85: O0 / OOooOOo . OoOoOO00 / I1ii11iIi11i
  iI1 -= IIiIi1II1IiI
  if 80 - 80: I1ii11iIi11i * iII111i % i1IIi * OOooOOo % II111iiii % i1IIi
  if 44 - 44: OoooooooOO
  if 18 - 18: i11iIiiIii
  if 65 - 65: i1IIi . iIii1I11I1II1 % iIii1I11I1II1
  if 35 - 35: iIii1I11I1II1 - o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - OOooOOo . o0oOOo0O0Ooo
  o00OooooOOOO = "H"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( [ None , None ] )
  if ( iI1 < oO0o00O ) : return ( [ None , None ] )
  if 12 - 12: iIii1I11I1II1 % OoO0O00 * Oo0Ooo
  oO0oO00 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] ) [ 0 ]
  packet = packet [ oO0o00O : : ]
  iI1 -= oO0o00O
  oOoooOOO0o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  oOoooOOO0o0 . afi = socket . ntohs ( oO0oO00 )
  oOoooOOO0o0 . mask_len = iiii
  oOoooOOO0o0 . instance_id = self . instance_id
  IIiIi1II1IiI = self . addr_length ( )
  if ( iI1 < IIiIi1II1IiI ) : return ( [ None , None ] )
  if 5 - 5: I11i - II111iiii * iIii1I11I1II1 / iIii1I11I1II1 % IiII * i1IIi
  packet = oOoooOOO0o0 . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 30 - 30: i1IIi % I1IiiI . OOooOOo % iIii1I11I1II1 . I1ii11iIi11i / o0oOOo0O0Ooo
  return ( [ packet , oOoooOOO0o0 ] )
  if 53 - 53: OOooOOo % ooOoO0o
  if 94 - 94: OOooOOo - O0 - I1Ii111 / OoooooooOO - iII111i
 def lcaf_decode_eid ( self , packet ) :
  o00OooooOOOO = "BBB"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( [ None , None ] )
  if 83 - 83: OOooOOo * I1ii11iIi11i * iII111i * I1ii11iIi11i . OoO0O00
  if 87 - 87: ooOoO0o . O0 - oO0o
  if 75 - 75: Oo0Ooo
  if 22 - 22: oO0o * I1Ii111 . II111iiii / Ii1I * O0
  if 33 - 33: oO0o * i1IIi + ooOoO0o * OOooOOo - O0 - iIii1I11I1II1
  O0Ooo000Ooo , OO000OOO , iiii1II = struct . unpack ( o00OooooOOOO ,
 packet [ : oO0o00O ] )
  if 35 - 35: I1Ii111
  if ( iiii1II == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( iiii1II == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , oOoooOOO0o0 = self . lcaf_decode_sg ( packet )
   return ( [ packet , oOoooOOO0o0 ] )
  elif ( iiii1II == LISP_LCAF_GEO_COORD_TYPE ) :
   o00OooooOOOO = "BBBBH"
   oO0o00O = struct . calcsize ( o00OooooOOOO )
   if ( len ( packet ) < oO0o00O ) : return ( None )
   if 12 - 12: Ii1I % I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
   Ooo0o00O0O0oO , OO000OOO , iiii1II , o000OOooo000O , o00O0oOO0o = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] )
   if 12 - 12: Oo0Ooo + I1IiiI
   if 12 - 12: OoOoOO00 / II111iiii
   if ( iiii1II != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 100 - 100: I1ii11iIi11i % iIii1I11I1II1 . IiII . OoooooooOO / II111iiii
   o00O0oOO0o = socket . ntohs ( o00O0oOO0o )
   packet = packet [ oO0o00O : : ]
   if ( o00O0oOO0o > len ( packet ) ) : return ( None )
   if 28 - 28: I1IiiI
   OOoooo = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = OOoooo
   packet = OOoooo . decode_geo ( packet , o00O0oOO0o , o000OOooo000O )
   self . mask_len = self . host_mask_len ( )
   if 27 - 27: I1IiiI % oO0o - iIii1I11I1II1 - o0oOOo0O0Ooo - IiII - O0
  return ( [ packet , None ] )
  if 46 - 46: II111iiii
  if 24 - 24: i11iIiiIii * i1IIi - I11i + o0oOOo0O0Ooo
  if 60 - 60: ooOoO0o
  if 62 - 62: i11iIiiIii
  if 88 - 88: i11iIiiIii
  if 59 - 59: oO0o - OoooooooOO % ooOoO0o
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 90 - 90: OoOoOO00
  if 96 - 96: II111iiii % Ii1I
 def copy_elp_node ( self ) :
  Oo0ooOOOOOoO = lisp_elp_node ( )
  Oo0ooOOOOOoO . copy_address ( self . address )
  Oo0ooOOOOOoO . probe = self . probe
  Oo0ooOOOOOoO . strict = self . strict
  Oo0ooOOOOOoO . eid = self . eid
  Oo0ooOOOOOoO . we_are_last = self . we_are_last
  return ( Oo0ooOOOOOoO )
  if 84 - 84: I1IiiI . I1IiiI
  if 82 - 82: OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1 + I1ii11iIi11i
  if 45 - 45: iII111i . oO0o * iII111i
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 3 - 3: OoOoOO00 / Oo0Ooo - Oo0Ooo
  if 54 - 54: Oo0Ooo . OoO0O00 * I1IiiI % IiII
 def copy_elp ( self ) :
  OOo0oo0OOOO = lisp_elp ( self . elp_name )
  OOo0oo0OOOO . use_elp_node = self . use_elp_node
  OOo0oo0OOOO . we_are_last = self . we_are_last
  for Oo0ooOOOOOoO in self . elp_nodes :
   OOo0oo0OOOO . elp_nodes . append ( Oo0ooOOOOOoO . copy_elp_node ( ) )
   if 97 - 97: o0oOOo0O0Ooo + Ii1I
  return ( OOo0oo0OOOO )
  if 77 - 77: I11i - oO0o . Ii1I
  if 75 - 75: I11i * OoooooooOO % OoOoOO00 . i1IIi - Ii1I + iIii1I11I1II1
 def print_elp ( self , want_marker ) :
  iIii1IiI = ""
  for Oo0ooOOOOOoO in self . elp_nodes :
   ooOOoO0Oo0OoO = ""
   if ( want_marker ) :
    if ( Oo0ooOOOOOoO == self . use_elp_node ) :
     ooOOoO0Oo0OoO = "*"
    elif ( Oo0ooOOOOOoO . we_are_last ) :
     ooOOoO0Oo0OoO = "x"
     if 10 - 10: ooOoO0o
     if 86 - 86: OoOoOO00 / Ii1I
   iIii1IiI += "{}{}({}{}{}), " . format ( ooOOoO0Oo0OoO ,
 Oo0ooOOOOOoO . address . print_address_no_iid ( ) ,
 "r" if Oo0ooOOOOOoO . eid else "R" , "P" if Oo0ooOOOOOoO . probe else "p" ,
 "S" if Oo0ooOOOOOoO . strict else "s" )
   if 80 - 80: II111iiii
  return ( iIii1IiI [ 0 : - 2 ] if iIii1IiI != "" else "" )
  if 66 - 66: ooOoO0o
  if 61 - 61: O0 / II111iiii + I1IiiI + I1ii11iIi11i * Oo0Ooo * I1ii11iIi11i
 def select_elp_node ( self ) :
  Ii11Ii1IiiIi , oO0Oo0O000 , OO0oo00oOO = lisp_myrlocs
  OO000o00 = None
  if 80 - 80: OOooOOo % OoO0O00 + OoOoOO00 % iII111i % OoooooooOO - ooOoO0o
  for Oo0ooOOOOOoO in self . elp_nodes :
   if ( Ii11Ii1IiiIi and Oo0ooOOOOOoO . address . is_exact_match ( Ii11Ii1IiiIi ) ) :
    OO000o00 = self . elp_nodes . index ( Oo0ooOOOOOoO )
    break
    if 25 - 25: OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - Oo0Ooo . O0
   if ( oO0Oo0O000 and Oo0ooOOOOOoO . address . is_exact_match ( oO0Oo0O000 ) ) :
    OO000o00 = self . elp_nodes . index ( Oo0ooOOOOOoO )
    break
    if 48 - 48: I1IiiI + oO0o % i11iIiiIii % iIii1I11I1II1
    if 14 - 14: iIii1I11I1II1
    if 78 - 78: I1Ii111 / Oo0Ooo - I1Ii111
    if 1 - 1: OoO0O00 - I1IiiI * o0oOOo0O0Ooo
    if 84 - 84: OoO0O00 % OoooooooOO
    if 66 - 66: OoOoOO00 . iII111i
    if 1 - 1: iII111i * i1IIi . iIii1I11I1II1 % O0 - OoooooooOO
  if ( OO000o00 == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   Oo0ooOOOOOoO . we_are_last = False
   return
   if 87 - 87: iII111i . Oo0Ooo * i11iIiiIii % o0oOOo0O0Ooo + Ii1I
   if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
   if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
   if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
   if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
   if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ OO000o00 ] ) :
   self . use_elp_node = None
   Oo0ooOOOOOoO . we_are_last = True
   return
   if 90 - 90: II111iiii + OOooOOo % I1Ii111 * iIii1I11I1II1 % iIii1I11I1II1
   if 55 - 55: II111iiii % O0 * O0 - II111iiii * I1IiiI % Oo0Ooo
   if 48 - 48: I1ii11iIi11i + OoooooooOO % i1IIi
   if 46 - 46: OoOoOO00
   if 75 - 75: I1IiiI
  self . use_elp_node = self . elp_nodes [ OO000o00 + 1 ]
  return
  if 37 - 37: iIii1I11I1II1 % OoO0O00 * ooOoO0o + I11i % ooOoO0o / i11iIiiIii
  if 14 - 14: i1IIi / ooOoO0o
  if 10 - 10: ooOoO0o / OoooooooOO - ooOoO0o % O0 + oO0o - oO0o
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
  if 16 - 16: O0
  if 14 - 14: Ii1I . Ii1I . OOooOOo - O0 / OoO0O00 % II111iiii
 def copy_geo ( self ) :
  OOoooo = lisp_geo ( self . geo_name )
  OOoooo . latitude = self . latitude
  OOoooo . lat_mins = self . lat_mins
  OOoooo . lat_secs = self . lat_secs
  OOoooo . longitude = self . longitude
  OOoooo . long_mins = self . long_mins
  OOoooo . long_secs = self . long_secs
  OOoooo . altitude = self . altitude
  OOoooo . radius = self . radius
  return ( OOoooo )
  if 5 - 5: iIii1I11I1II1 % OoOoOO00 % OOooOOo % O0 * oO0o . iIii1I11I1II1
  if 96 - 96: i11iIiiIii + oO0o / I1ii11iIi11i . IiII % o0oOOo0O0Ooo
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 41 - 41: o0oOOo0O0Ooo . i1IIi - OOooOOo
  if 19 - 19: o0oOOo0O0Ooo % I1Ii111 % I11i
 def parse_geo_string ( self , geo_str ) :
  OO000o00 = geo_str . find ( "]" )
  if ( OO000o00 != - 1 ) : geo_str = geo_str [ OO000o00 + 1 : : ]
  if 1 - 1: I1IiiI / o0oOOo0O0Ooo - I1Ii111
  if 50 - 50: I11i - OoOoOO00 + I1IiiI % Oo0Ooo / OoooooooOO - I1ii11iIi11i
  if 26 - 26: IiII . Ii1I
  if 35 - 35: I1ii11iIi11i + OOooOOo
  if 88 - 88: O0
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , II1iiiIiiI = geo_str . split ( "/" )
   self . radius = int ( II1iiiIiiI )
   if 29 - 29: Ii1I % o0oOOo0O0Ooo - Ii1I
   if 40 - 40: I1IiiI * O0 * iIii1I11I1II1 / Oo0Ooo
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 15 - 15: iIii1I11I1II1 . OoOoOO00 % Ii1I / i1IIi . o0oOOo0O0Ooo
  Ii1iIiI1I = geo_str [ 0 : 4 ]
  iiii111I = geo_str [ 4 : 8 ]
  if 87 - 87: ooOoO0o * OoOoOO00
  if 3 - 3: i1IIi - Oo0Ooo + OoOoOO00 . I1Ii111 * iII111i - O0
  if 66 - 66: o0oOOo0O0Ooo * I1Ii111 . O0 - iII111i
  if 22 - 22: OoO0O00 / I1IiiI - I1IiiI - i11iIiiIii . I1IiiI - OOooOOo
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 27 - 27: ooOoO0o
  if 34 - 34: OoooooooOO - I1Ii111 + I1Ii111 % IiII % OoooooooOO
  if 24 - 24: I1Ii111 . Oo0Ooo / ooOoO0o * O0
  if 85 - 85: I1IiiI - OOooOOo
  self . latitude = int ( Ii1iIiI1I [ 0 ] )
  self . lat_mins = int ( Ii1iIiI1I [ 1 ] )
  self . lat_secs = int ( Ii1iIiI1I [ 2 ] )
  if ( Ii1iIiI1I [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 7 - 7: i1IIi % II111iiii
  if 33 - 33: iIii1I11I1II1 . O0 . oO0o
  if 69 - 69: II111iiii * O0 . ooOoO0o * IiII
  if 25 - 25: I11i - I1ii11iIi11i . I1Ii111 . OoooooooOO
  self . longitude = int ( iiii111I [ 0 ] )
  self . long_mins = int ( iiii111I [ 1 ] )
  self . long_secs = int ( iiii111I [ 2 ] )
  if ( iiii111I [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 4 - 4: IiII * OoO0O00 % I1ii11iIi11i * Ii1I . iII111i
  if 41 - 41: OoooooooOO % I11i . O0 + I1Ii111
 def print_geo ( self ) :
  OOo0oOoOOO0oo = "N" if self . latitude < 0 else "S"
  iIi = "E" if self . longitude < 0 else "W"
  if 100 - 100: OoO0O00 / O0 / OoOoOO00
  OOOOooO0Oo0oo = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , OOo0oOoOOO0oo , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , iIi )
  if 33 - 33: i1IIi / o0oOOo0O0Ooo . OoooooooOO
  if ( self . no_geo_altitude ( ) == False ) :
   OOOOooO0Oo0oo += "-" + str ( self . altitude )
   if 8 - 8: I1IiiI * OOooOOo * IiII / I1IiiI + i1IIi
   if 11 - 11: I11i * Ii1I * I1IiiI - I1IiiI % OoooooooOO
   if 83 - 83: i11iIiiIii % iII111i * O0 % OoooooooOO
   if 99 - 99: I1ii11iIi11i % I1ii11iIi11i * iII111i % oO0o
   if 56 - 56: Oo0Ooo + i11iIiiIii - oO0o . Ii1I + IiII
  if ( self . radius != 0 ) : OOOOooO0Oo0oo += "/{}" . format ( self . radius )
  return ( OOOOooO0Oo0oo )
  if 19 - 19: I11i * OoooooooOO . i1IIi
  if 100 - 100: II111iiii
 def geo_url ( self ) :
  o0oOOo000o0 = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  o0oOOo000o0 = "10" if ( o0oOOo000o0 == "" or o0oOOo000o0 . isdigit ( ) == False ) else o0oOOo000o0
  OoO0o0 , OO0Oo0OO0 = self . dms_to_decimal ( )
  oo0o0O = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( OoO0o0 , OO0Oo0OO0 , OoO0o0 , OO0Oo0OO0 ,
  # Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo . Ii1I
  # iII111i + iII111i % OOooOOo . I1ii11iIi11i + OoooooooOO
 o0oOOo000o0 )
  return ( oo0o0O )
  if 60 - 60: oO0o / oO0o - o0oOOo0O0Ooo + I1IiiI % OoO0O00 + i1IIi
  if 2 - 2: I1ii11iIi11i * oO0o + iIii1I11I1II1 . I1IiiI
 def print_geo_url ( self ) :
  OOoooo = self . print_geo ( )
  if ( self . radius == 0 ) :
   oo0o0O = self . geo_url ( )
   IIIiiiI1Ii1 = "<a href='{}'>{}</a>" . format ( oo0o0O , OOoooo )
  else :
   oo0o0O = OOoooo . replace ( "/" , "-" )
   IIIiiiI1Ii1 = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( oo0o0O , OOoooo )
   if 100 - 100: IiII % OoOoOO00 / Oo0Ooo * iII111i
  return ( IIIiiiI1Ii1 )
  if 46 - 46: I1IiiI
  if 78 - 78: Oo0Ooo + ooOoO0o
 def dms_to_decimal ( self ) :
  OOOo , I11IiiIIIIiIi1ii , IIOoo0 = self . latitude , self . lat_mins , self . lat_secs
  i1i = float ( abs ( OOOo ) )
  i1i += float ( I11IiiIIIIiIi1ii * 60 + IIOoo0 ) / 3600
  if ( OOOo > 0 ) : i1i = - i1i
  iiI11 = i1i
  if 57 - 57: I1ii11iIi11i
  OOOo , I11IiiIIIIiIi1ii , IIOoo0 = self . longitude , self . long_mins , self . long_secs
  i1i = float ( abs ( OOOo ) )
  i1i += float ( I11IiiIIIIiIi1ii * 60 + IIOoo0 ) / 3600
  if ( OOOo > 0 ) : i1i = - i1i
  OOooIi11IiII = i1i
  return ( ( iiI11 , OOooIi11IiII ) )
  if 47 - 47: II111iiii + OOooOOo / II111iiii . OOooOOo
  if 68 - 68: OoooooooOO
 def get_distance ( self , geo_point ) :
  o0oOO = self . dms_to_decimal ( )
  I1Ii111Oo00o0o = geo_point . dms_to_decimal ( )
  o00oo0oo = vincenty ( o0oOO , I1Ii111Oo00o0o )
  return ( o00oo0oo . km )
  if 52 - 52: IiII + ooOoO0o - II111iiii - OoooooooOO * OoO0O00 - iIii1I11I1II1
  if 38 - 38: II111iiii % iIii1I11I1II1 * IiII * OoOoOO00 % II111iiii . I1IiiI
 def point_in_circle ( self , geo_point ) :
  Ii1i1iI1i = self . get_distance ( geo_point )
  return ( Ii1i1iI1i <= self . radius )
  if 69 - 69: ooOoO0o
  if 2 - 2: OoOoOO00 / oO0o . I1ii11iIi11i % OoO0O00 - oO0o
 def encode_geo ( self ) :
  I1I1iiI1iIIii = socket . htons ( LISP_AFI_LCAF )
  o0OoOOoO0o0 = socket . htons ( 20 + 2 )
  OO000OOO = 0
  if 21 - 21: ooOoO0o . o0oOOo0O0Ooo . oO0o . i1IIi
  OoO0o0 = abs ( self . latitude )
  O000oooooo0 = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : OO000OOO |= 0x40
  if 40 - 40: i1IIi
  OO0Oo0OO0 = abs ( self . longitude )
  O0O00o0oo0 = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : OO000OOO |= 0x20
  if 31 - 31: iIii1I11I1II1 * OoO0O00 - I11i . OoO0O00 % iIii1I11I1II1
  oO0o00ooO = 0
  if ( self . no_geo_altitude ( ) == False ) :
   oO0o00ooO = socket . htonl ( self . altitude )
   OO000OOO |= 0x10
   if 83 - 83: OoOoOO00 . I11i
  II1iiiIiiI = socket . htons ( self . radius )
  if ( II1iiiIiiI != 0 ) : OO000OOO |= 0x06
  if 88 - 88: I1Ii111 * ooOoO0o - Ii1I % OoooooooOO . OOooOOo + OoOoOO00
  i1II1Iii = struct . pack ( "HBBBBH" , I1I1iiI1iIIii , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , o0OoOOoO0o0 )
  i1II1Iii += struct . pack ( "BBHBBHBBHIHHH" , OO000OOO , 0 , 0 , OoO0o0 , O000oooooo0 >> 16 ,
 socket . htons ( O000oooooo0 & 0x0ffff ) , OO0Oo0OO0 , O0O00o0oo0 >> 16 ,
 socket . htons ( O0O00o0oo0 & 0xffff ) , oO0o00ooO , II1iiiIiiI , 0 , 0 )
  if 74 - 74: ooOoO0o * i11iIiiIii + I1ii11iIi11i - ooOoO0o . OoOoOO00
  return ( i1II1Iii )
  if 96 - 96: Ii1I + Oo0Ooo * I1Ii111 - I11i * I1Ii111
  if 32 - 32: I1IiiI / i1IIi / I1ii11iIi11i % i1IIi . ooOoO0o % I1ii11iIi11i
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  o00OooooOOOO = "BBHBBHBBHIHHH"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( lcaf_len < oO0o00O ) : return ( None )
  if 97 - 97: OoO0O00 . OOooOOo % Ii1I + OoooooooOO * I1Ii111
  OO000OOO , o0OOoO00Oo , OoOo0 , OoO0o0 , i11iIIiIIiii , O000oooooo0 , OO0Oo0OO0 , oo000 , O0O00o0oo0 , oO0o00ooO , II1iiiIiiI , o00OO00Oo0 , oO0oO00 = struct . unpack ( o00OooooOOOO ,
  # I1ii11iIi11i * OOooOOo . ooOoO0o % i1IIi . IiII / OoOoOO00
 packet [ : oO0o00O ] )
  if 98 - 98: Ii1I % iII111i . OoooooooOO - i1IIi % I1Ii111
  if 94 - 94: i1IIi + iII111i
  if 25 - 25: I1Ii111 . Ii1I - Ii1I . o0oOOo0O0Ooo - IiII
  if 91 - 91: o0oOOo0O0Ooo % I1ii11iIi11i % OoOoOO00 * iIii1I11I1II1
  oO0oO00 = socket . ntohs ( oO0oO00 )
  if ( oO0oO00 == LISP_AFI_LCAF ) : return ( None )
  if 18 - 18: OoOoOO00 * I1ii11iIi11i . i1IIi * iII111i
  if ( OO000OOO & 0x40 ) : OoO0o0 = - OoO0o0
  self . latitude = OoO0o0
  O0oooo = ( ( i11iIIiIIiii << 16 ) | socket . ntohs ( O000oooooo0 ) ) / 1000
  self . lat_mins = O0oooo / 60
  self . lat_secs = O0oooo % 60
  if 43 - 43: OoooooooOO + i1IIi . O0
  if ( OO000OOO & 0x20 ) : OO0Oo0OO0 = - OO0Oo0OO0
  self . longitude = OO0Oo0OO0
  iiIiI111 = ( ( oo000 << 16 ) | socket . ntohs ( O0O00o0oo0 ) ) / 1000
  self . long_mins = iiIiI111 / 60
  self . long_secs = iiIiI111 % 60
  if 85 - 85: II111iiii / o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO / Ii1I
  self . altitude = socket . ntohl ( oO0o00ooO ) if ( OO000OOO & 0x10 ) else - 1
  II1iiiIiiI = socket . ntohs ( II1iiiIiiI )
  self . radius = II1iiiIiiI if ( OO000OOO & 0x02 ) else II1iiiIiiI * 1000
  if 18 - 18: i11iIiiIii + o0oOOo0O0Ooo . i11iIiiIii
  self . geo_name = None
  packet = packet [ oO0o00O : : ]
  if 50 - 50: IiII / OoooooooOO . I11i
  if ( oO0oO00 != 0 ) :
   self . rloc . afi = oO0oO00
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 93 - 93: OOooOOo / OoooooooOO % iII111i % Ii1I / I1Ii111 % OOooOOo
  return ( packet )
  if 25 - 25: i1IIi % Oo0Ooo . i1IIi * OoOoOO00 . Ii1I % OoO0O00
  if 47 - 47: o0oOOo0O0Ooo - i11iIiiIii / OoooooooOO
  if 93 - 93: I1IiiI * II111iiii * O0 % o0oOOo0O0Ooo + oO0o / ooOoO0o
  if 79 - 79: OoO0O00 + ooOoO0o / oO0o % I1ii11iIi11i
  if 77 - 77: Ii1I / Ii1I / I1ii11iIi11i
  if 92 - 92: O0 * i11iIiiIii . OoOoOO00 * IiII / o0oOOo0O0Ooo * ooOoO0o
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 74 - 74: O0 - o0oOOo0O0Ooo
  if 68 - 68: I1Ii111
 def copy_rle_node ( self ) :
  Oo0000O00o0 = lisp_rle_node ( )
  Oo0000O00o0 . address . copy_address ( self . address )
  Oo0000O00o0 . level = self . level
  Oo0000O00o0 . translated_port = self . translated_port
  Oo0000O00o0 . rloc_name = self . rloc_name
  return ( Oo0000O00o0 )
  if 19 - 19: o0oOOo0O0Ooo
  if 63 - 63: OoooooooOO % ooOoO0o
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 26 - 26: OOooOOo + Oo0Ooo
  if 97 - 97: I1Ii111 * I1Ii111 + iII111i % Ii1I / iII111i
 def get_encap_keys ( self ) :
  IIi1I1iII111 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 73 - 73: OoOoOO00 % I1Ii111 . I1ii11iIi11i
  oOo0O = self . address . print_address_no_iid ( ) + ":" + IIi1I1iII111
  if 45 - 45: iIii1I11I1II1 % Ii1I . OoOoOO00 . o0oOOo0O0Ooo - OoooooooOO
  try :
   O0000 = lisp_crypto_keys_by_rloc_encap [ oOo0O ]
   if ( O0000 [ 1 ] ) : return ( O0000 [ 1 ] . encrypt_key , O0000 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 46 - 46: I1ii11iIi11i
   if 32 - 32: iII111i * i11iIiiIii / IiII + i11iIiiIii + O0
   if 51 - 51: I1Ii111
   if 95 - 95: Ii1I / Ii1I * OoO0O00 . OoooooooOO . OoooooooOO * I11i
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 76 - 76: OoooooooOO - Ii1I + IiII % OoOoOO00 / OoooooooOO
  if 55 - 55: i11iIiiIii - IiII * OOooOOo + II111iiii . I1ii11iIi11i / O0
 def copy_rle ( self ) :
  OoO000oo000o0 = lisp_rle ( self . rle_name )
  for Oo0000O00o0 in self . rle_nodes :
   OoO000oo000o0 . rle_nodes . append ( Oo0000O00o0 . copy_rle_node ( ) )
   if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
  OoO000oo000o0 . build_forwarding_list ( )
  return ( OoO000oo000o0 )
  if 98 - 98: II111iiii - i1IIi - ooOoO0o
  if 36 - 36: IiII + o0oOOo0O0Ooo
 def print_rle ( self , html ) :
  Oo0iIIIIi = ""
  for Oo0000O00o0 in self . rle_nodes :
   IIi1I1iII111 = Oo0000O00o0 . translated_port
   OO00O = blue ( Oo0000O00o0 . rloc_name , html ) if Oo0000O00o0 . rloc_name != None else ""
   if 62 - 62: II111iiii . oO0o / I11i . oO0o / i1IIi + o0oOOo0O0Ooo
   oOo0O = Oo0000O00o0 . address . print_address_no_iid ( )
   if ( Oo0000O00o0 . address . is_local ( ) ) : oOo0O = red ( oOo0O , html )
   Oo0iIIIIi += "{}{}(L{}){}, " . format ( oOo0O , "" if IIi1I1iII111 == 0 else ":" + str ( IIi1I1iII111 ) , Oo0000O00o0 . level ,
   # I1ii11iIi11i
 "" if Oo0000O00o0 . rloc_name == None else OO00O )
   if 4 - 4: Ii1I - iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
  return ( Oo0iIIIIi [ 0 : - 2 ] if Oo0iIIIIi != "" else "" )
  if 18 - 18: oO0o % iIii1I11I1II1 + ooOoO0o
  if 34 - 34: I1IiiI - OoooooooOO . IiII - OOooOOo % IiII
 def build_forwarding_list ( self ) :
  i1Ii = - 1
  for Oo0000O00o0 in self . rle_nodes :
   if ( i1Ii == - 1 ) :
    if ( Oo0000O00o0 . address . is_local ( ) ) : i1Ii = Oo0000O00o0 . level
   else :
    if ( Oo0000O00o0 . level > i1Ii ) : break
    if 19 - 19: IiII + I1ii11iIi11i % Oo0Ooo
    if 32 - 32: OOooOOo
  i1Ii = 0 if i1Ii == - 1 else Oo0000O00o0 . level
  if 46 - 46: II111iiii . OoO0O00
  self . rle_forwarding_list = [ ]
  for Oo0000O00o0 in self . rle_nodes :
   if ( Oo0000O00o0 . level == i1Ii or ( i1Ii == 0 and
 Oo0000O00o0 . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and Oo0000O00o0 . address . is_local ( ) ) :
     oOo0O = Oo0000O00o0 . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( oOo0O ) )
     continue
     if 97 - 97: oO0o
    self . rle_forwarding_list . append ( Oo0000O00o0 )
    if 45 - 45: i11iIiiIii / IiII + OoO0O00
    if 55 - 55: Ii1I / II111iiii - oO0o
    if 58 - 58: i1IIi . OoooooooOO % iIii1I11I1II1 * o0oOOo0O0Ooo + O0 / oO0o
    if 77 - 77: I11i . I1ii11iIi11i
    if 92 - 92: i11iIiiIii + I11i % I1IiiI / ooOoO0o
class lisp_json ( ) :
 def __init__ ( self , name , string ) :
  self . json_name = name
  self . json_string = string
  if 28 - 28: i1IIi . I1IiiI
  if 41 - 41: I1ii11iIi11i . I1Ii111 * OoOoOO00 . I1Ii111 / o0oOOo0O0Ooo
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 41 - 41: o0oOOo0O0Ooo / o0oOOo0O0Ooo . Oo0Ooo
  if 4 - 4: I1Ii111
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 85 - 85: iIii1I11I1II1 % Oo0Ooo
   if 20 - 20: IiII + i11iIiiIii * OOooOOo
   if 27 - 27: O0 * OoO0O00 * I1ii11iIi11i
 def print_json ( self , html ) :
  IiIII1I = self . json_string
  I1iiiII1Ii1i1 = "***"
  if ( html ) : I1iiiII1Ii1i1 = red ( I1iiiII1Ii1i1 , html )
  II111IIII = I1iiiII1Ii1i1 + self . json_string + I1iiiII1Ii1i1
  if ( self . valid_json ( ) ) : return ( IiIII1I )
  return ( II111IIII )
  if 34 - 34: o0oOOo0O0Ooo
  if 76 - 76: oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 51 - 51: II111iiii / OoOoOO00
  return ( True )
  if 69 - 69: i11iIiiIii
  if 77 - 77: I1ii11iIi11i % OoooooooOO - Oo0Ooo - Ii1I + I11i
  if 93 - 93: I1IiiI % O0 * OoO0O00 % OoOoOO00 . I1Ii111 * I1IiiI
  if 95 - 95: IiII + o0oOOo0O0Ooo - o0oOOo0O0Ooo
  if 83 - 83: ooOoO0o
  if 59 - 59: I1ii11iIi11i
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 26 - 26: I11i . Ii1I
  if 94 - 94: ooOoO0o . I1IiiI + IiII % I1IiiI / o0oOOo0O0Ooo % o0oOOo0O0Ooo
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 21 - 21: O0 / OOooOOo - II111iiii + I1ii11iIi11i / OoooooooOO
  if 81 - 81: i11iIiiIii / Oo0Ooo * i1IIi + OoO0O00 + O0 % I1ii11iIi11i
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  o0O0oO0 = time . time ( ) - self . last_increment
  return ( o0O0oO0 <= 1 )
  if 3 - 3: i11iIiiIii * IiII . Oo0Ooo % OoOoOO00 * I11i . iII111i
  if 80 - 80: I11i - IiII
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  o0O0oO0 = time . time ( ) - self . last_increment
  return ( o0O0oO0 <= 60 )
  if 40 - 40: OOooOOo * I1IiiI % I11i . I1Ii111 % O0 . O0
  if 14 - 14: ooOoO0o . OoOoOO00 + ooOoO0o * OoOoOO00 . OoOoOO00 * Oo0Ooo
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 40 - 40: OoooooooOO
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 14 - 14: o0oOOo0O0Ooo / OOooOOo . OoOoOO00 % iIii1I11I1II1 % OoOoOO00
  return ( c1 , c2 )
  if 92 - 92: o0oOOo0O0Ooo + II111iiii
  if 56 - 56: OoOoOO00 - OoOoOO00 / Ii1I
 def normalize ( self , count ) :
  count = str ( count )
  oooIIi1i = len ( count )
  if ( oooIIi1i > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 64 - 64: i1IIi * II111iiii + I1ii11iIi11i + OOooOOo % I1ii11iIi11i - OoooooooOO
  if ( oooIIi1i > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 96 - 96: IiII + oO0o / Oo0Ooo + OoooooooOO
  if ( oooIIi1i > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 53 - 53: Ii1I * IiII + Oo0Ooo + i11iIiiIii - iIii1I11I1II1
  return ( count )
  if 66 - 66: O0 - I1ii11iIi11i * iIii1I11I1II1 - I1Ii111 / I1ii11iIi11i
  if 24 - 24: Ii1I
 def get_stats ( self , summary , html ) :
  ii1Iii1Iii = self . last_rate_check
  oOooo0Ooooo0 = self . last_packet_count
  oOOOo = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 90 - 90: I1IiiI - OOooOOo / OoO0O00 / I11i
  ii1iIi1Ii1I11I = self . last_rate_check - ii1Iii1Iii
  if ( ii1iIi1Ii1I11I == 0 ) :
   o0oOO0OO0000O = 0
   Oo0OoOoooo0O = 0
  else :
   o0oOO0OO0000O = int ( ( self . packet_count - oOooo0Ooooo0 ) / ii1iIi1Ii1I11I )
   Oo0OoOoooo0O = ( self . byte_count - oOOOo ) / ii1iIi1Ii1I11I
   Oo0OoOoooo0O = ( Oo0OoOoooo0O * 8 ) / 1000000
   Oo0OoOoooo0O = round ( Oo0OoOoooo0O , 2 )
   if 47 - 47: I1IiiI / o0oOOo0O0Ooo
   if 47 - 47: i1IIi / Oo0Ooo % IiII % OoO0O00 + Ii1I
   if 31 - 31: I11i / I11i
   if 90 - 90: II111iiii . I1Ii111
   if 26 - 26: I1Ii111 * O0 / oO0o
  iI1iIii11i1i = self . normalize ( self . packet_count )
  IiI1iiI11 = self . normalize ( self . byte_count )
  if 6 - 6: ooOoO0o + OOooOOo - I1IiiI + OOooOOo
  if 16 - 16: OoO0O00 * OoOoOO00 - Oo0Ooo
  if 44 - 44: ooOoO0o / OoOoOO00 - O0 + iII111i / iIii1I11I1II1
  if 41 - 41: iIii1I11I1II1 - iII111i / O0
  if 39 - 39: OoooooooOO * iIii1I11I1II1 - o0oOOo0O0Ooo / O0
  if ( summary ) :
   I1IIIIiiii = "<br>" if html else ""
   iI1iIii11i1i , IiI1iiI11 = self . stat_colors ( iI1iIii11i1i , IiI1iiI11 , html )
   I111II = "packet-count: {}{}byte-count: {}" . format ( iI1iIii11i1i , I1IIIIiiii , IiI1iiI11 )
   O0ooOoo0O000O = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( o0oOO0OO0000O , Oo0OoOoooo0O )
   if 22 - 22: I1Ii111 - OOooOOo * i1IIi
   if ( html != "" ) : O0ooOoo0O000O = lisp_span ( I111II , O0ooOoo0O000O )
  else :
   O0Oo0OO = str ( o0oOO0OO0000O )
   O0O0OO = str ( Oo0OoOoooo0O )
   if ( html ) :
    iI1iIii11i1i = lisp_print_cour ( iI1iIii11i1i )
    O0Oo0OO = lisp_print_cour ( O0Oo0OO )
    IiI1iiI11 = lisp_print_cour ( IiI1iiI11 )
    O0O0OO = lisp_print_cour ( O0O0OO )
    if 56 - 56: oO0o - Ii1I % I1Ii111
   I1IIIIiiii = "<br>" if html else ", "
   if 100 - 100: OOooOOo * IiII % IiII / o0oOOo0O0Ooo * OoO0O00 % OoOoOO00
   O0ooOoo0O000O = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( iI1iIii11i1i , I1IIIIiiii , O0Oo0OO , I1IIIIiiii , IiI1iiI11 , I1IIIIiiii ,
   # i11iIiiIii
 O0O0OO )
   if 32 - 32: I1Ii111 . I1IiiI
  return ( O0ooOoo0O000O )
  if 78 - 78: OoOoOO00 . I1ii11iIi11i / o0oOOo0O0Ooo
  if 57 - 57: IiII % O0 * I1ii11iIi11i
  if 61 - 61: O0
  if 51 - 51: I1Ii111 - I11i % o0oOOo0O0Ooo * Oo0Ooo - oO0o + II111iiii
  if 7 - 7: oO0o
  if 98 - 98: Ii1I + oO0o + i1IIi + IiII % IiII
  if 79 - 79: oO0o % I11i * I11i . OOooOOo % OoooooooOO
  if 71 - 71: iII111i
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 48 - 48: OoOoOO00 + oO0o
if 15 - 15: i11iIiiIii / IiII * I1ii11iIi11i - O0 % II111iiii + Ii1I
if 100 - 100: Ii1I + O0 . iII111i - Ii1I + O0 . OOooOOo
if 77 - 77: OOooOOo * OoOoOO00 - i1IIi * I1IiiI . I1Ii111
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
  if 37 - 37: i1IIi - O0
  if ( recurse == False ) : return
  if 36 - 36: I1Ii111 . OoooooooOO - i1IIi % iII111i - II111iiii * i11iIiiIii
  if 90 - 90: OoOoOO00 % iII111i - Oo0Ooo
  if 13 - 13: o0oOOo0O0Ooo / O0 . I1Ii111 * I1Ii111
  if 76 - 76: Ii1I - iII111i
  if 79 - 79: o0oOOo0O0Ooo + IiII / o0oOOo0O0Ooo - I1IiiI / OoooooooOO
  if 17 - 17: OOooOOo * I1ii11iIi11i . Ii1I . iIii1I11I1II1 * OoooooooOO
  Oo0O00OOOO = lisp_get_default_route_next_hops ( )
  if ( Oo0O00OOOO == [ ] or len ( Oo0O00OOOO ) == 1 ) : return
  if 7 - 7: ooOoO0o * OoO0O00 / II111iiii % OoOoOO00 * OOooOOo . II111iiii
  self . rloc_next_hop = Oo0O00OOOO [ 0 ]
  i11 = self
  for I1ii1I1II11II in Oo0O00OOOO [ 1 : : ] :
   O0ooo00Oo = lisp_rloc ( False )
   O0ooo00Oo = copy . deepcopy ( self )
   O0ooo00Oo . rloc_next_hop = I1ii1I1II11II
   i11 . next_rloc = O0ooo00Oo
   i11 = O0ooo00Oo
   if 98 - 98: OOooOOo + i11iIiiIii - i1IIi
   if 26 - 26: OoOoOO00 / o0oOOo0O0Ooo . OOooOOo + I1IiiI + Ii1I . iII111i
   if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 5 - 5: OoOoOO00 % i1IIi
  if 31 - 31: Oo0Ooo * O0 . OOooOOo . o0oOOo0O0Ooo + OoO0O00 + II111iiii
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 76 - 76: Oo0Ooo + I1IiiI - O0
  if 58 - 58: IiII * i1IIi . I1IiiI - iII111i
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 73 - 73: Oo0Ooo . OoOoOO00
  if 50 - 50: IiII / o0oOOo0O0Ooo
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
  if 52 - 52: O0
  if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
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
  if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
  if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
 def print_rloc ( self , indent ) :
  Oo0OO0000oooo = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , Oo0OO0000oooo , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 83 - 83: oO0o / OoO0O00
  if 34 - 34: OoooooooOO - i1IIi * O0
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  Ooo000oo0OO0 = self . rloc_name
  if ( cour ) : Ooo000oo0OO0 = lisp_print_cour ( Ooo000oo0OO0 )
  return ( 'rloc-name: {}' . format ( blue ( Ooo000oo0OO0 , cour ) ) )
  if 83 - 83: I1IiiI + OoO0O00
  if 41 - 41: Ii1I + II111iiii . OOooOOo * I1Ii111 / II111iiii
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  IIi1I1iII111 = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 32 - 32: Oo0Ooo - Ii1I % o0oOOo0O0Ooo
  if 15 - 15: iIii1I11I1II1 * I1ii11iIi11i / ooOoO0o * oO0o % OOooOOo
  if 62 - 62: Ii1I / Oo0Ooo . OoO0O00 - OOooOOo
  if 89 - 89: o0oOOo0O0Ooo % OoO0O00
  OooO0ooO0o0OO = self . rloc
  if ( OooO0ooO0o0OO . is_null ( ) == False ) :
   oOOo0O0O = lisp_get_nat_info ( OooO0ooO0o0OO , self . rloc_name )
   if ( oOOo0O0O ) :
    IIi1I1iII111 = oOOo0O0O . port
    OO000O0OO0 = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    oOo0O = OooO0ooO0o0OO . print_address_no_iid ( )
    ii11IiI = red ( oOo0O , False )
    IiO00Oo000 = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 29 - 29: iIii1I11I1II1 / i11iIiiIii + Oo0Ooo
    if 99 - 99: I1IiiI - iII111i * Ii1I - OoOoOO00 / i11iIiiIii - i1IIi
    if 46 - 46: I1ii11iIi11i * ooOoO0o
    if 4 - 4: I1Ii111 * II111iiii
    if 4 - 4: ooOoO0o * Oo0Ooo - I1ii11iIi11i % ooOoO0o % OoOoOO00
    if 18 - 18: OOooOOo / O0 . OoO0O00 - II111iiii * OOooOOo
    if ( oOOo0O0O . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( ii11IiI , IIi1I1iII111 , IiO00Oo000 ) )
     if 13 - 13: OoO0O00 % i1IIi . i11iIiiIii / iII111i
     if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
     oOOo0O0O = None if ( oOOo0O0O == OO000O0OO0 ) else OO000O0OO0
     if ( oOOo0O0O and oOOo0O0O . timed_out ( ) ) :
      IIi1I1iII111 = oOOo0O0O . port
      ii11IiI = red ( oOOo0O0O . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( ii11IiI , IIi1I1iII111 ,
      # I11i
 IiO00Oo000 ) )
      oOOo0O0O = None
      if 42 - 42: OOooOOo * ooOoO0o / i1IIi . i11iIiiIii - oO0o - Ii1I
      if 5 - 5: i1IIi + II111iiii . ooOoO0o
      if 21 - 21: i1IIi
      if 96 - 96: OoOoOO00 * OoOoOO00 % OoO0O00 * iII111i
      if 51 - 51: I1IiiI + i11iIiiIii + iII111i
      if 57 - 57: Oo0Ooo . oO0o
      if 52 - 52: IiII % OoO0O00 - OoO0O00 . I1IiiI + OoO0O00 * ooOoO0o
    if ( oOOo0O0O ) :
     if ( oOOo0O0O . address != oOo0O ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( ii11IiI , red ( oOOo0O0O . address , False ) ) )
      if 44 - 44: iIii1I11I1II1 / Ii1I - oO0o % i11iIiiIii
      self . rloc . store_address ( oOOo0O0O . address )
      if 65 - 65: I1ii11iIi11i * Oo0Ooo / Ii1I . OOooOOo * iIii1I11I1II1 + Oo0Ooo
     ii11IiI = red ( oOOo0O0O . address , False )
     IIi1I1iII111 = oOOo0O0O . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( ii11IiI , IIi1I1iII111 , IiO00Oo000 ) )
     if 44 - 44: ooOoO0o * iII111i * IiII % o0oOOo0O0Ooo
     self . store_translated_rloc ( OooO0ooO0o0OO , IIi1I1iII111 )
     if 45 - 45: OoOoOO00 % o0oOOo0O0Ooo + IiII / i11iIiiIii
     if 29 - 29: iIii1I11I1II1 . OoO0O00 / I1IiiI
     if 38 - 38: Oo0Ooo / Oo0Ooo % ooOoO0o
     if 56 - 56: oO0o / iII111i % i1IIi * II111iiii . Ii1I
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 10 - 10: ooOoO0o - I1ii11iIi11i
  if 82 - 82: o0oOOo0O0Ooo / I11i - I11i / O0 * I1IiiI / OoO0O00
  if 71 - 71: I11i % I11i - i11iIiiIii + iIii1I11I1II1 / iII111i
  if 63 - 63: O0 * i11iIiiIii / IiII / IiII
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for Oo0000O00o0 in self . rle . rle_nodes :
    Ooo000oo0OO0 = Oo0000O00o0 . rloc_name
    oOOo0O0O = lisp_get_nat_info ( Oo0000O00o0 . address , Ooo000oo0OO0 )
    if ( oOOo0O0O == None ) : continue
    if 72 - 72: i11iIiiIii * OoOoOO00 % oO0o / I1Ii111
    IIi1I1iII111 = oOOo0O0O . port
    O0Oo0oO0 = Ooo000oo0OO0
    if ( O0Oo0oO0 ) : O0Oo0oO0 = blue ( Ooo000oo0OO0 , False )
    if 9 - 9: iIii1I11I1II1 . IiII
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( IIi1I1iII111 ,
    # I1IiiI + iII111i / Ii1I
 Oo0000O00o0 . address . print_address_no_iid ( ) , O0Oo0oO0 ) )
    Oo0000O00o0 . translated_port = IIi1I1iII111
    if 57 - 57: o0oOOo0O0Ooo
    if 69 - 69: i1IIi / i1IIi / OoOoOO00 + ooOoO0o % I1Ii111
    if 41 - 41: II111iiii * OOooOOo
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 8 - 8: I1Ii111 + O0
  if 67 - 67: iIii1I11I1II1 . O0
  if 40 - 40: OOooOOo - ooOoO0o . OoooooooOO % O0 * I11i - I1ii11iIi11i
  if 92 - 92: ooOoO0o % oO0o / i11iIiiIii
  oOOoooo0O0 = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
  if ( rloc_record . keys != None and oOOoooo0O0 ) :
   iII1 = rloc_record . keys [ 1 ]
   if ( iII1 != None ) :
    oOo0O = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( IIi1I1iII111 )
    if 54 - 54: II111iiii * I1IiiI
    iII1 . add_key_by_rloc ( oOo0O , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( oOo0O , False ) ) )
    if 49 - 49: I1ii11iIi11i
    if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
    if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
  return ( IIi1I1iII111 )
  if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
  if 15 - 15: oO0o
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 40 - 40: I1Ii111
  if 77 - 77: II111iiii - o0oOOo0O0Ooo . Ii1I
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 47 - 47: o0oOOo0O0Ooo % OOooOOo + I1Ii111
  if 64 - 64: ooOoO0o / IiII . I1IiiI
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 77 - 77: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
  return ( True )
  if 90 - 90: I11i
  if 53 - 53: I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoooooooOO + IiII * I1IiiI
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 16 - 16: i11iIiiIii - oO0o . i11iIiiIii + OoO0O00 + i11iIiiIii
  if 85 - 85: I1ii11iIi11i - ooOoO0o + I1Ii111 + I1Ii111
  if 13 - 13: II111iiii
 def print_state_change ( self , new_state ) :
  iIII1Ii1 = self . print_state ( )
  IIIiiiI1Ii1 = "{} -> {}" . format ( iIII1Ii1 , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   IIIiiiI1Ii1 = bold ( IIIiiiI1Ii1 , False )
   if 53 - 53: i1IIi . OoooooooOO
  return ( IIIiiiI1Ii1 )
  if 56 - 56: OoooooooOO
  if 93 - 93: OoOoOO00
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 48 - 48: i1IIi
  if 22 - 22: iII111i / OoO0O00 * OOooOOo + I11i
 def print_recent_rloc_probe_rtts ( self ) :
  o000Oo00oOoO = str ( self . recent_rloc_probe_rtts )
  o000Oo00oOoO = o000Oo00oOoO . replace ( "-1" , "?" )
  return ( o000Oo00oOoO )
  if 28 - 28: I1Ii111 / oO0o % OoooooooOO - I1IiiI / I1IiiI
  if 73 - 73: I11i - i1IIi / i11iIiiIii / I1Ii111
 def compute_rloc_probe_rtt ( self ) :
  i11 = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  II1IIIII1III1 = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ i11 ] + II1IIIII1III1 [ 0 : - 1 ]
  if 67 - 67: I1ii11iIi11i - ooOoO0o - Ii1I - OoO0O00 % OoooooooOO
  if 22 - 22: oO0o * i1IIi
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 54 - 54: I1IiiI * I1IiiI % IiII - i11iIiiIii * o0oOOo0O0Ooo
  if 38 - 38: OoOoOO00 / OOooOOo % OoooooooOO * I1ii11iIi11i
 def print_recent_rloc_probe_hops ( self ) :
  I1IiiI1iIIi1i = str ( self . recent_rloc_probe_hops )
  return ( I1IiiI1iIIi1i )
  if 46 - 46: II111iiii * iII111i . iII111i % oO0o - i11iIiiIii . I11i
  if 74 - 74: OoO0O00 * iII111i / OoO0O00 % Oo0Ooo / i1IIi
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < LISP_RLOC_PROBE_TTL / 2 ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 77 - 77: IiII % iIii1I11I1II1 / iIii1I11I1II1 * iII111i * Ii1I + I1Ii111
  if ( from_ttl < LISP_RLOC_PROBE_TTL / 2 ) :
   IIiiII11iiii = "!"
  else :
   IIiiII11iiii = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 15 - 15: i11iIiiIii % I1ii11iIi11i % Oo0Ooo
   if 65 - 65: II111iiii - i1IIi . I1ii11iIi11i . I11i % OoO0O00 . OoooooooOO
  i11 = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + IIiiII11iiii
  II1IIIII1III1 = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ i11 ] + II1IIIII1III1 [ 0 : - 1 ]
  if 64 - 64: I11i * Oo0Ooo / IiII / II111iiii
  if 29 - 29: OoooooooOO - OoO0O00 - Ii1I
 def process_rloc_probe_reply ( self , nonce , eid , group , hop_count , ttl ) :
  OooO0ooO0o0OO = self
  while ( True ) :
   if ( OooO0ooO0o0OO . last_rloc_probe_nonce == nonce ) : break
   OooO0ooO0o0OO = OooO0ooO0o0OO . next_rloc
   if ( OooO0ooO0o0OO == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 82 - 82: IiII - I1IiiI . iII111i % I11i % Ii1I + iII111i
    return
    if 87 - 87: i11iIiiIii % i1IIi
    if 63 - 63: I1ii11iIi11i + iII111i * o0oOOo0O0Ooo % II111iiii
    if 23 - 23: i1IIi * oO0o * oO0o . i11iIiiIii / o0oOOo0O0Ooo
  OooO0ooO0o0OO . last_rloc_probe_reply = lisp_get_timestamp ( )
  OooO0ooO0o0OO . compute_rloc_probe_rtt ( )
  Oooo = OooO0ooO0o0OO . print_state_change ( "up" )
  if ( OooO0ooO0o0OO . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( OooO0ooO0o0OO . rloc , True )
   OooO0ooO0o0OO . state = LISP_RLOC_UP_STATE
   OooO0ooO0o0OO . last_state_change = lisp_get_timestamp ( )
   OoOoooooO00oo = lisp_map_cache . lookup_cache ( eid , True )
   if ( OoOoooooO00oo ) : lisp_write_ipc_map_cache ( True , OoOoooooO00oo )
   if 50 - 50: o0oOOo0O0Ooo - O0 + OoO0O00
   if 22 - 22: I1Ii111 % O0 / I1Ii111 / I1Ii111
  OooO0ooO0o0OO . store_rloc_probe_hops ( hop_count , ttl )
  if 64 - 64: Oo0Ooo + iIii1I11I1II1 % i1IIi
  Ii1I11IiI1I1 = bold ( "RLOC-probe reply" , False )
  oOo0O = OooO0ooO0o0OO . rloc . print_address_no_iid ( )
  I1i1IIiI = bold ( str ( OooO0ooO0o0OO . print_rloc_probe_rtt ( ) ) , False )
  iIiiI11II11 = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 86 - 86: i1IIi
  I1ii1I1II11II = ""
  if ( OooO0ooO0o0OO . rloc_next_hop != None ) :
   Ii , oooOoo0 = OooO0ooO0o0OO . rloc_next_hop
   I1ii1I1II11II = ", nh {}({})" . format ( oooOoo0 , Ii )
   if 82 - 82: I11i * Ii1I
   if 55 - 55: IiII / OoooooooOO
  o0OoO00 = green ( lisp_print_eid_tuple ( eid , group ) , False )
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}" ) . format ( Ii1I11IiI1I1 , red ( oOo0O , False ) , iIiiI11II11 , o0OoO00 ,
  # iIii1I11I1II1 . O0
 Oooo , I1i1IIiI , I1ii1I1II11II , str ( hop_count ) + "/" + str ( ttl ) ) )
  if 61 - 61: OoOoOO00 * OOooOOo
  if ( OooO0ooO0o0OO . rloc_next_hop == None ) : return
  if 3 - 3: I1IiiI + Oo0Ooo / I1Ii111
  if 17 - 17: i11iIiiIii / Oo0Ooo . o0oOOo0O0Ooo / I1IiiI . OOooOOo
  if 10 - 10: I11i - OoOoOO00
  if 49 - 49: I1ii11iIi11i / II111iiii - ooOoO0o / I1Ii111 - oO0o
  OooO0ooO0o0OO = None
  O0o0O000oo = None
  while ( True ) :
   OooO0ooO0o0OO = self if OooO0ooO0o0OO == None else OooO0ooO0o0OO . next_rloc
   if ( OooO0ooO0o0OO == None ) : break
   if ( OooO0ooO0o0OO . up_state ( ) == False ) : continue
   if ( OooO0ooO0o0OO . rloc_probe_rtt == - 1 ) : continue
   if 27 - 27: OoOoOO00 % OoooooooOO
   if ( O0o0O000oo == None ) : O0o0O000oo = OooO0ooO0o0OO
   if ( OooO0ooO0o0OO . rloc_probe_rtt < O0o0O000oo . rloc_probe_rtt ) : O0o0O000oo = OooO0ooO0o0OO
   if 77 - 77: Ii1I % Oo0Ooo
   if 30 - 30: iIii1I11I1II1 * Oo0Ooo * OOooOOo * ooOoO0o
  if ( O0o0O000oo != None ) :
   Ii , oooOoo0 = O0o0O000oo . rloc_next_hop
   I1ii1I1II11II = bold ( "nh {}({})" . format ( oooOoo0 , Ii ) , False )
   lprint ( "    Install host-route via best {}" . format ( I1ii1I1II11II ) )
   lisp_install_host_route ( oOo0O , None , False )
   lisp_install_host_route ( oOo0O , oooOoo0 , True )
   if 6 - 6: iIii1I11I1II1 / oO0o % ooOoO0o
   if 19 - 19: iIii1I11I1II1 + I11i - iIii1I11I1II1 - Ii1I . Ii1I * OoO0O00
   if 32 - 32: I1IiiI + OOooOOo * oO0o
 def add_to_rloc_probe_list ( self , eid , group ) :
  oOo0O = self . rloc . print_address_no_iid ( )
  IIi1I1iII111 = self . translated_port
  if ( IIi1I1iII111 != 0 ) : oOo0O += ":" + str ( IIi1I1iII111 )
  if 100 - 100: OoO0O00
  if ( lisp_rloc_probe_list . has_key ( oOo0O ) == False ) :
   lisp_rloc_probe_list [ oOo0O ] = [ ]
   if 20 - 20: Ii1I % OoO0O00
   if 85 - 85: i1IIi % iIii1I11I1II1
  if ( group . is_null ( ) ) : group . instance_id = 0
  for O0OooO0oo , o0OoO00 , II1IIiIiiI1iI in lisp_rloc_probe_list [ oOo0O ] :
   if ( o0OoO00 . is_exact_match ( eid ) and II1IIiIiiI1iI . is_exact_match ( group ) ) :
    if ( O0OooO0oo == self ) :
     if ( lisp_rloc_probe_list [ oOo0O ] == [ ] ) :
      lisp_rloc_probe_list . pop ( oOo0O )
      if 10 - 10: O0 . oO0o * I1IiiI
     return
     if 21 - 21: OoooooooOO
    lisp_rloc_probe_list [ oOo0O ] . remove ( [ O0OooO0oo , o0OoO00 , II1IIiIiiI1iI ] )
    break
    if 76 - 76: i1IIi * i11iIiiIii / OOooOOo + I1Ii111
    if 50 - 50: oO0o % OoOoOO00 + I1IiiI
  lisp_rloc_probe_list [ oOo0O ] . append ( [ self , eid , group ] )
  if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
  if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
  if 79 - 79: oO0o + I1IiiI % iII111i + II111iiii % OoO0O00 % iII111i
  if 46 - 46: o0oOOo0O0Ooo
  if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
  OooO0ooO0o0OO = lisp_rloc_probe_list [ oOo0O ] [ 0 ] [ 0 ]
  if ( OooO0ooO0o0OO . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 44 - 44: I11i . oO0o
   if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
   if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
 def delete_from_rloc_probe_list ( self , eid , group ) :
  oOo0O = self . rloc . print_address_no_iid ( )
  IIi1I1iII111 = self . translated_port
  if ( IIi1I1iII111 != 0 ) : oOo0O += ":" + str ( IIi1I1iII111 )
  if ( lisp_rloc_probe_list . has_key ( oOo0O ) == False ) : return
  if 16 - 16: OoO0O00 / Ii1I * i11iIiiIii / o0oOOo0O0Ooo + I1Ii111
  i1IiI1IIIIi = [ ]
  for iIiiiIIiii in lisp_rloc_probe_list [ oOo0O ] :
   if ( iIiiiIIiii [ 0 ] != self ) : continue
   if ( iIiiiIIiii [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( iIiiiIIiii [ 2 ] . is_exact_match ( group ) == False ) : continue
   i1IiI1IIIIi = iIiiiIIiii
   break
   if 51 - 51: iIii1I11I1II1 * Oo0Ooo + ooOoO0o
  if ( i1IiI1IIIIi == [ ] ) : return
  if 58 - 58: I11i / i11iIiiIii . iII111i
  try :
   lisp_rloc_probe_list [ oOo0O ] . remove ( i1IiI1IIIIi )
   if ( lisp_rloc_probe_list [ oOo0O ] == [ ] ) :
    lisp_rloc_probe_list . pop ( oOo0O )
    if 80 - 80: II111iiii + OoO0O00 % ooOoO0o + i11iIiiIii
  except :
   return
   if 30 - 30: Ii1I / I1ii11iIi11i % IiII - Oo0Ooo
   if 100 - 100: IiII . I1Ii111 * oO0o % OoO0O00 . iIii1I11I1II1 * Oo0Ooo
   if 100 - 100: IiII - OoOoOO00 % iII111i
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  o0OooooOoOO = ""
  OooO0ooO0o0OO = self
  while ( True ) :
   iIII = OooO0ooO0o0OO . last_rloc_probe
   if ( iIII == None ) : iIII = 0
   IiiIii = OooO0ooO0o0OO . last_rloc_probe_reply
   if ( IiiIii == None ) : IiiIii = 0
   I1i1IIiI = OooO0ooO0o0OO . print_rloc_probe_rtt ( )
   o0 = space ( 4 )
   if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
   if ( OooO0ooO0o0OO . rloc_next_hop == None ) :
    o0OooooOoOO += "RLOC-Probing:\n"
   else :
    Ii , oooOoo0 = OooO0ooO0o0OO . rloc_next_hop
    o0OooooOoOO += "RLOC-Probing for nh {}({}):\n" . format ( oooOoo0 , Ii )
    if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
    if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
   o0OooooOoOO += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( o0 , lisp_print_elapsed ( iIII ) ,
   # OOooOOo . OoO0O00 + OoO0O00
 o0 , lisp_print_elapsed ( IiiIii ) , I1i1IIiI )
   if 19 - 19: iII111i * i1IIi / iII111i
   if ( trailing_linefeed ) : o0OooooOoOO += "\n"
   if 21 - 21: ooOoO0o / o0oOOo0O0Ooo % I1ii11iIi11i . Ii1I . IiII
   OooO0ooO0o0OO = OooO0ooO0o0OO . next_rloc
   if ( OooO0ooO0o0OO == None ) : break
   o0OooooOoOO += "\n"
   if 8 - 8: I1ii11iIi11i / ooOoO0o + II111iiii
  return ( o0OooooOoOO )
  if 45 - 45: ooOoO0o - OOooOOo * IiII % iII111i . OoOoOO00 / i11iIiiIii
  if 63 - 63: Oo0Ooo * iIii1I11I1II1 / ooOoO0o
 def get_encap_keys ( self ) :
  IIi1I1iII111 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 46 - 46: OoOoOO00 / iII111i - OoO0O00 . o0oOOo0O0Ooo
  oOo0O = self . rloc . print_address_no_iid ( ) + ":" + IIi1I1iII111
  if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
  try :
   O0000 = lisp_crypto_keys_by_rloc_encap [ oOo0O ]
   if ( O0000 [ 1 ] ) : return ( O0000 [ 1 ] . encrypt_key , O0000 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 65 - 65: I1IiiI % iIii1I11I1II1
   if 52 - 52: I1IiiI
   if 19 - 19: I1IiiI
 def rloc_recent_rekey ( self ) :
  IIi1I1iII111 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 17 - 17: I11i + OoooooooOO
  oOo0O = self . rloc . print_address_no_iid ( ) + ":" + IIi1I1iII111
  if 63 - 63: IiII
  try :
   iII1 = lisp_crypto_keys_by_rloc_encap [ oOo0O ] [ 1 ]
   if ( iII1 == None ) : return ( False )
   if ( iII1 . last_rekey == None ) : return ( True )
   return ( time . time ( ) - iII1 . last_rekey < 1 )
  except :
   return ( False )
   if 3 - 3: oO0o * II111iiii . O0
   if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
   if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
   if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
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
  if 51 - 51: oO0o - I1ii11iIi11i + I1ii11iIi11i
  if 100 - 100: I11i - I1ii11iIi11i . i1IIi
 def print_mapping ( self , eid_indent , rloc_indent ) :
  Oo0OO0000oooo = lisp_print_elapsed ( self . uptime )
  oOoooOOO0o0 = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 85 - 85: II111iiii
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , oOoooOOO0o0 , Oo0OO0000oooo ,
 len ( self . rloc_set ) ) )
  for OooO0ooO0o0OO in self . rloc_set : OooO0ooO0o0OO . print_rloc ( rloc_indent )
  if 58 - 58: i1IIi - OoO0O00 + ooOoO0o
  if 6 - 6: IiII % I1IiiI + OoooooooOO * oO0o . iII111i + oO0o
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 4 - 4: I11i % I1IiiI
  if 72 - 72: I1IiiI % II111iiii % iII111i / OoOoOO00
 def print_ttl ( self ) :
  oo0OOoOO0 = self . map_cache_ttl
  if ( oo0OOoOO0 == None ) : return ( "forever" )
  if 96 - 96: OoOoOO00 % Ii1I
  if ( oo0OOoOO0 >= 3600 ) :
   if ( ( oo0OOoOO0 % 3600 ) == 0 ) :
    oo0OOoOO0 = str ( oo0OOoOO0 / 3600 ) + " hours"
   else :
    oo0OOoOO0 = str ( oo0OOoOO0 * 60 ) + " mins"
    if 50 - 50: IiII - II111iiii
  elif ( oo0OOoOO0 >= 60 ) :
   if ( ( oo0OOoOO0 % 60 ) == 0 ) :
    oo0OOoOO0 = str ( oo0OOoOO0 / 60 ) + " mins"
   else :
    oo0OOoOO0 = str ( oo0OOoOO0 ) + " secs"
    if 10 - 10: OoooooooOO % Ii1I * OOooOOo + IiII * oO0o
  else :
   oo0OOoOO0 = str ( oo0OOoOO0 ) + " secs"
   if 13 - 13: II111iiii
  return ( oo0OOoOO0 )
  if 14 - 14: i11iIiiIii . IiII
  if 70 - 70: Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  o0O0oO0 = time . time ( ) - self . last_refresh_time
  if ( o0O0oO0 >= self . map_cache_ttl ) : return ( True )
  if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
  if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
  if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
  if 49 - 49: iII111i + OoOoOO00
  if 33 - 33: ooOoO0o
  i1111111II = self . map_cache_ttl - ( self . map_cache_ttl / 10 )
  if ( o0O0oO0 >= i1111111II ) : return ( True )
  return ( False )
  if 58 - 58: o0oOOo0O0Ooo
  if 5 - 5: O0
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  o0O0oO0 = time . time ( ) - self . stats . last_increment
  return ( o0O0oO0 <= 60 )
  if 23 - 23: OOooOOo . i11iIiiIii % o0oOOo0O0Ooo - OoOoOO00 * OoooooooOO - OoO0O00
  if 51 - 51: iIii1I11I1II1 / I1ii11iIi11i
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 83 - 83: ooOoO0o % I1IiiI - OoOoOO00 - I11i
  if 12 - 12: I1Ii111 . OoO0O00 + I11i * OoO0O00 - IiII + I11i
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 98 - 98: iII111i . I1Ii111 * IiII - Ii1I * OoooooooOO
  if 13 - 13: iII111i
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for OooO0ooO0o0OO in self . best_rloc_set :
   OooO0ooO0o0OO . delete_from_rloc_probe_list ( self . eid , self . group )
   if 76 - 76: iIii1I11I1II1 + Oo0Ooo
   if 40 - 40: oO0o % i1IIi % ooOoO0o . oO0o % oO0o
   if 69 - 69: OoooooooOO . oO0o / OoooooooOO / OoOoOO00
 def build_best_rloc_set ( self ) :
  I1iIiI = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 89 - 89: ooOoO0o * Ii1I * Oo0Ooo * O0
  if 25 - 25: o0oOOo0O0Ooo + I1ii11iIi11i * oO0o / IiII - Ii1I
  if 85 - 85: Oo0Ooo . i11iIiiIii % oO0o
  if 60 - 60: OOooOOo
  IIii1IiI = 256
  for OooO0ooO0o0OO in self . rloc_set :
   if ( OooO0ooO0o0OO . up_state ( ) ) : IIii1IiI = min ( OooO0ooO0o0OO . priority , IIii1IiI )
   if 90 - 90: i11iIiiIii / i1IIi * Oo0Ooo / OoO0O00 * I1ii11iIi11i + I1ii11iIi11i
   if 36 - 36: Ii1I . OOooOOo * iIii1I11I1II1 - i1IIi
   if 38 - 38: Oo0Ooo . o0oOOo0O0Ooo % oO0o / i11iIiiIii * OoO0O00 % OoOoOO00
   if 18 - 18: OOooOOo
   if 12 - 12: I1Ii111 % II111iiii / o0oOOo0O0Ooo - iIii1I11I1II1 + II111iiii
   if 41 - 41: OOooOOo
   if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
   if 64 - 64: I1IiiI . Oo0Ooo * OoO0O00
   if 87 - 87: i1IIi / OoooooooOO
   if 68 - 68: I1Ii111 / iIii1I11I1II1
  for OooO0ooO0o0OO in self . rloc_set :
   if ( OooO0ooO0o0OO . priority <= IIii1IiI ) :
    if ( OooO0ooO0o0OO . unreach_state ( ) and OooO0ooO0o0OO . last_rloc_probe == None ) :
     OooO0ooO0o0OO . last_rloc_probe = lisp_get_timestamp ( )
     if 8 - 8: ooOoO0o * IiII * OOooOOo / I1IiiI
    self . best_rloc_set . append ( OooO0ooO0o0OO )
    if 40 - 40: i11iIiiIii + OoooooooOO
    if 2 - 2: o0oOOo0O0Ooo * OoO0O00
    if 88 - 88: Oo0Ooo + oO0o + iII111i
    if 51 - 51: i1IIi + i11iIiiIii * I11i / iII111i + OoooooooOO
    if 89 - 89: i11iIiiIii - I1Ii111 - O0 % iIii1I11I1II1 / IiII - O0
    if 63 - 63: OOooOOo
    if 23 - 23: Oo0Ooo / i1IIi - OOooOOo / Oo0Ooo
    if 16 - 16: o0oOOo0O0Ooo - iIii1I11I1II1 / OoooooooOO / I1ii11iIi11i + IiII
  for OooO0ooO0o0OO in I1iIiI :
   if ( OooO0ooO0o0OO . priority < IIii1IiI ) : continue
   OooO0ooO0o0OO . delete_from_rloc_probe_list ( self . eid , self . group )
   if 73 - 73: OOooOOo % I1Ii111 + OoooooooOO / I1ii11iIi11i * oO0o % oO0o
  for OooO0ooO0o0OO in self . best_rloc_set :
   if ( OooO0ooO0o0OO . rloc . is_null ( ) ) : continue
   OooO0ooO0o0OO . add_to_rloc_probe_list ( self . eid , self . group )
   if 25 - 25: I1Ii111
   if 93 - 93: OoO0O00
   if 62 - 62: Oo0Ooo . iII111i
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  ii1i1II = lisp_packet . packet
  iiI1IIii1IIi1 = lisp_packet . inner_version
  iI1 = len ( self . best_rloc_set )
  if ( iI1 is 0 ) :
   self . stats . increment ( len ( ii1i1II ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 63 - 63: OoooooooOO % I1Ii111 + IiII / OoooooooOO
   if 60 - 60: II111iiii + II111iiii
  i1IIIoo0ooO = 4 if lisp_load_split_pings else 0
  IiI1I1i1 = lisp_packet . hash_ports ( )
  if ( iiI1IIii1IIi1 == 4 ) :
   for i1i1IIIIIIIi in range ( 8 + i1IIIoo0ooO ) :
    IiI1I1i1 = IiI1I1i1 ^ struct . unpack ( "B" , ii1i1II [ i1i1IIIIIIIi + 12 ] ) [ 0 ]
    if 40 - 40: ooOoO0o % I11i + O0
  elif ( iiI1IIii1IIi1 == 6 ) :
   for i1i1IIIIIIIi in range ( 0 , 32 + i1IIIoo0ooO , 4 ) :
    IiI1I1i1 = IiI1I1i1 ^ struct . unpack ( "I" , ii1i1II [ i1i1IIIIIIIi + 8 : i1i1IIIIIIIi + 12 ] ) [ 0 ]
    if 22 - 22: i1IIi % Oo0Ooo / oO0o % OoOoOO00 / OoOoOO00
   IiI1I1i1 = ( IiI1I1i1 >> 16 ) + ( IiI1I1i1 & 0xffff )
   IiI1I1i1 = ( IiI1I1i1 >> 8 ) + ( IiI1I1i1 & 0xff )
  else :
   for i1i1IIIIIIIi in range ( 0 , 12 + i1IIIoo0ooO , 4 ) :
    IiI1I1i1 = IiI1I1i1 ^ struct . unpack ( "I" , ii1i1II [ i1i1IIIIIIIi : i1i1IIIIIIIi + 4 ] ) [ 0 ]
    if 79 - 79: IiII % OoooooooOO
    if 51 - 51: iII111i . oO0o % ooOoO0o % Ii1I . o0oOOo0O0Ooo
    if 43 - 43: II111iiii
  if ( lisp_data_plane_logging ) :
   OOOOo00oo0OO = [ ]
   for O0OooO0oo in self . best_rloc_set :
    if ( O0OooO0oo . rloc . is_null ( ) ) : continue
    OOOOo00oo0OO . append ( [ O0OooO0oo . rloc . print_address_no_iid ( ) , O0OooO0oo . print_state ( ) ] )
    if 18 - 18: O0 + I1Ii111 . I1ii11iIi11i
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( IiI1I1i1 ) , IiI1I1i1 % iI1 , red ( str ( OOOOo00oo0OO ) , False ) ) )
   if 48 - 48: Ii1I . o0oOOo0O0Ooo * O0 / OoooooooOO + I1Ii111 + Oo0Ooo
   if 92 - 92: Ii1I - o0oOOo0O0Ooo % I1IiiI + I1Ii111
   if 3 - 3: iIii1I11I1II1 + i11iIiiIii
   if 49 - 49: OoOoOO00 % iIii1I11I1II1 + I1Ii111
   if 38 - 38: i11iIiiIii
   if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
  OooO0ooO0o0OO = self . best_rloc_set [ IiI1I1i1 % iI1 ]
  if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
  if 7 - 7: Oo0Ooo . iII111i % I1ii11iIi11i / iII111i
  if 93 - 93: iII111i
  if 5 - 5: iII111i . I11i % I11i * Ii1I - I1ii11iIi11i . i11iIiiIii
  if 32 - 32: II111iiii
  oOo0ooO0O0oo = lisp_get_echo_nonce ( OooO0ooO0o0OO . rloc , None )
  if ( oOo0ooO0O0oo ) :
   oOo0ooO0O0oo . change_state ( OooO0ooO0o0OO )
   if ( OooO0ooO0o0OO . no_echoed_nonce_state ( ) ) :
    oOo0ooO0O0oo . request_nonce_sent = None
    if 58 - 58: I1IiiI - o0oOOo0O0Ooo - I1Ii111 . O0 % OoO0O00 . I11i
    if 41 - 41: iII111i . I1Ii111 - IiII / O0
    if 62 - 62: IiII * I1ii11iIi11i * iII111i * OoOoOO00
    if 12 - 12: Oo0Ooo * Ii1I / ooOoO0o % I11i % O0
    if 25 - 25: Oo0Ooo * oO0o
    if 78 - 78: OoOoOO00 / II111iiii
  if ( OooO0ooO0o0OO . up_state ( ) == False ) :
   i1IoO00oo = IiI1I1i1 % iI1
   OO000o00 = ( i1IoO00oo + 1 ) % iI1
   while ( OO000o00 != i1IoO00oo ) :
    OooO0ooO0o0OO = self . best_rloc_set [ OO000o00 ]
    if ( OooO0ooO0o0OO . up_state ( ) ) : break
    OO000o00 = ( OO000o00 + 1 ) % iI1
    if 36 - 36: OoO0O00 . ooOoO0o . O0 / OoO0O00
   if ( OO000o00 == i1IoO00oo ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
    if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
    if 72 - 72: I1ii11iIi11i
    if 74 - 74: I1Ii111 * iIii1I11I1II1 / oO0o - IiII - I1IiiI
    if 84 - 84: iIii1I11I1II1 % Oo0Ooo / I1ii11iIi11i + o0oOOo0O0Ooo * II111iiii
    if 81 - 81: I1IiiI / I1ii11iIi11i / OOooOOo
  OooO0ooO0o0OO . stats . increment ( len ( ii1i1II ) )
  if 89 - 89: Oo0Ooo % IiII
  if 36 - 36: IiII % OoOoOO00 % I1ii11iIi11i
  if 7 - 7: I1ii11iIi11i % OoOoOO00 - O0 . I1Ii111
  if 9 - 9: Ii1I . OoooooooOO / ooOoO0o + i1IIi
  if ( OooO0ooO0o0OO . rle_name and OooO0ooO0o0OO . rle == None ) :
   if ( lisp_rle_list . has_key ( OooO0ooO0o0OO . rle_name ) ) :
    OooO0ooO0o0OO . rle = lisp_rle_list [ OooO0ooO0o0OO . rle_name ]
    if 90 - 90: oO0o - OoOoOO00 % ooOoO0o
    if 83 - 83: OOooOOo - I1ii11iIi11i + OoO0O00
  if ( OooO0ooO0o0OO . rle ) : return ( [ None , None , None , None , OooO0ooO0o0OO . rle , None ] )
  if 99 - 99: iII111i - OoOoOO00 % ooOoO0o
  if 27 - 27: oO0o . oO0o * iII111i % iIii1I11I1II1
  if 81 - 81: iII111i * II111iiii
  if 28 - 28: i11iIiiIii . Oo0Ooo . Ii1I
  if ( OooO0ooO0o0OO . elp and OooO0ooO0o0OO . elp . use_elp_node ) :
   return ( [ OooO0ooO0o0OO . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 19 - 19: OoO0O00 - Ii1I + ooOoO0o + OOooOOo
   if 84 - 84: iII111i / Oo0Ooo
   if 21 - 21: OoO0O00 . I1IiiI - OoO0O00
   if 51 - 51: iIii1I11I1II1
   if 5 - 5: oO0o - OoOoOO00 . ooOoO0o
  O0O0oO0o0 = None if ( OooO0ooO0o0OO . rloc . is_null ( ) ) else OooO0ooO0o0OO . rloc
  IIi1I1iII111 = OooO0ooO0o0OO . translated_port
  Ii1II1I = self . action if ( O0O0oO0o0 == None ) else None
  if 59 - 59: II111iiii % Oo0Ooo * OoOoOO00 + i11iIiiIii . OoO0O00
  if 70 - 70: o0oOOo0O0Ooo * O0 * II111iiii
  if 38 - 38: OoO0O00 - I1IiiI * OoooooooOO / I11i . O0
  if 77 - 77: OOooOOo + oO0o * iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii
  if 92 - 92: Oo0Ooo . o0oOOo0O0Ooo % OoooooooOO * i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo
  OO00OO = None
  if ( oOo0ooO0O0oo and oOo0ooO0O0oo . request_nonce_timeout ( ) == False ) :
   OO00OO = oOo0ooO0O0oo . get_request_or_echo_nonce ( ipc_socket , O0O0oO0o0 )
   if 48 - 48: iII111i * I1ii11iIi11i * oO0o % O0 . OoO0O00
   if 11 - 11: OOooOOo / o0oOOo0O0Ooo
   if 98 - 98: oO0o + I11i . oO0o
   if 10 - 10: iII111i + i1IIi . I11i % ooOoO0o / ooOoO0o
   if 86 - 86: Oo0Ooo
  return ( [ O0O0oO0o0 , IIi1I1iII111 , OO00OO , Ii1II1I , None , OooO0ooO0o0OO ] )
  if 7 - 7: iIii1I11I1II1
  if 86 - 86: IiII + iII111i * II111iiii - IiII - o0oOOo0O0Ooo
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 8 - 8: OOooOOo . Ii1I
  if 15 - 15: ooOoO0o / OOooOOo + i1IIi / Ii1I / OOooOOo
  if 47 - 47: Oo0Ooo + oO0o % OoooooooOO
  if 23 - 23: I1Ii111 / i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1
  if 11 - 11: I11i % OoOoOO00 * Oo0Ooo
  for IiIIIi in self . rloc_set :
   for OooO0ooO0o0OO in rloc_address_set :
    if ( OooO0ooO0o0OO . is_exact_match ( IiIIIi . rloc ) == False ) : continue
    OooO0ooO0o0OO = None
    break
    if 48 - 48: OOooOOo
   if ( OooO0ooO0o0OO == rloc_address_set [ - 1 ] ) : return ( False )
   if 66 - 66: iII111i - I1Ii111 - i11iIiiIii . o0oOOo0O0Ooo + Oo0Ooo
  return ( True )
  if 90 - 90: O0 - i11iIiiIii * ooOoO0o . I1ii11iIi11i . Ii1I - OoooooooOO
  if 23 - 23: o0oOOo0O0Ooo
 def get_rloc ( self , rloc ) :
  for IiIIIi in self . rloc_set :
   O0OooO0oo = IiIIIi . rloc
   if ( rloc . is_exact_match ( O0OooO0oo ) ) : return ( IiIIIi )
   if 88 - 88: I1Ii111 + iIii1I11I1II1 / o0oOOo0O0Ooo
  return ( None )
  if 93 - 93: ooOoO0o % iIii1I11I1II1 - OOooOOo . IiII + ooOoO0o
  if 63 - 63: I1ii11iIi11i / OOooOOo
 def get_rloc_by_interface ( self , interface ) :
  for IiIIIi in self . rloc_set :
   if ( IiIIIi . interface == interface ) : return ( IiIIIi )
   if 28 - 28: I11i / I1Ii111 + IiII * OoooooooOO - iIii1I11I1II1
  return ( None )
  if 6 - 6: I11i % o0oOOo0O0Ooo / OoooooooOO . I1Ii111
  if 17 - 17: I1ii11iIi11i + OoooooooOO / iIii1I11I1II1 . II111iiii + Oo0Ooo
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   o00o0oOo0o0O = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( o00o0oOo0o0O == None ) :
    o00o0oOo0o0O = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , o00o0oOo0o0O )
    if 7 - 7: O0 - I1ii11iIi11i - iIii1I11I1II1
   o00o0oOo0o0O . add_source_entry ( self )
   if 96 - 96: OoOoOO00 . I1IiiI . I11i * OoooooooOO + OoooooooOO * O0
   if 90 - 90: I11i + I1ii11iIi11i + OoooooooOO + OoOoOO00 + IiII / iII111i
   if 75 - 75: i11iIiiIii
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   OoOoooooO00oo = lisp_map_cache . lookup_cache ( self . group , True )
   if ( OoOoooooO00oo == None ) :
    OoOoooooO00oo = lisp_mapping ( self . group , self . group , [ ] )
    OoOoooooO00oo . eid . copy_address ( self . group )
    OoOoooooO00oo . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , OoOoooooO00oo )
    if 27 - 27: I11i - IiII - I1Ii111
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OoOoooooO00oo . group )
   OoOoooooO00oo . add_source_entry ( self )
   if 90 - 90: OoO0O00 . oO0o * O0 / I11i % O0 + I1Ii111
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 48 - 48: iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
  if 84 - 84: Ii1I
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 92 - 92: I11i
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    O000 = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( O000 ) )
    if 79 - 79: O0 / IiII . i1IIi - i1IIi + i1IIi
  else :
   OoOoooooO00oo = lisp_map_cache . lookup_cache ( self . group , True )
   if ( OoOoooooO00oo == None ) : return
   if 47 - 47: iII111i - I1Ii111 - I1Ii111 . ooOoO0o
   iII1oO0OOoOOo0 = OoOoooooO00oo . lookup_source_cache ( self . eid , True )
   if ( iII1oO0OOoOOo0 == None ) : return
   if 53 - 53: iII111i + oO0o % O0
   OoOoooooO00oo . source_cache . delete_cache ( self . eid )
   if ( OoOoooooO00oo . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 92 - 92: O0 / iIii1I11I1II1
    if 72 - 72: o0oOOo0O0Ooo / iII111i - I1ii11iIi11i . II111iiii
    if 95 - 95: II111iiii / I11i / ooOoO0o - I1Ii111 % i11iIiiIii
    if 53 - 53: iII111i
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 45 - 45: OOooOOo * I1IiiI / oO0o . Ii1I - OoO0O00 % OOooOOo
  if 40 - 40: I11i
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 69 - 69: OoOoOO00 + OoOoOO00 + o0oOOo0O0Ooo / iIii1I11I1II1 * OoO0O00
  if 44 - 44: II111iiii / o0oOOo0O0Ooo
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 81 - 81: I1Ii111 . Ii1I * ooOoO0o . IiII - OoOoOO00
  if 79 - 79: ooOoO0o - O0
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  oOo00Ooo0o0 = "," + str ( self . secondary_iid )
  return ( prefix . replace ( oOo00Ooo0o0 , oOo00Ooo0o0 + "*" ) )
  if 56 - 56: ooOoO0o
  if 89 - 89: O0 % iIii1I11I1II1 / OoOoOO00 - I1Ii111 - I1IiiI
 def increment_decap_stats ( self , packet ) :
  IIi1I1iII111 = packet . udp_dport
  if ( IIi1I1iII111 == LISP_DATA_PORT ) :
   OooO0ooO0o0OO = self . get_rloc ( packet . outer_dest )
  else :
   if 60 - 60: IiII % i11iIiiIii / OOooOOo
   if 43 - 43: i11iIiiIii * II111iiii + ooOoO0o - OoooooooOO * II111iiii / OoO0O00
   if 92 - 92: O0 - ooOoO0o % iII111i
   if 83 - 83: I1ii11iIi11i / OoOoOO00 % OoooooooOO
   for OooO0ooO0o0OO in self . rloc_set :
    if ( OooO0ooO0o0OO . translated_port != 0 ) : break
    if 54 - 54: I11i / I1IiiI * IiII - iII111i
    if 37 - 37: i1IIi * I1Ii111 / I11i * II111iiii + OoooooooOO . OoO0O00
  if ( OooO0ooO0o0OO != None ) : OooO0ooO0o0OO . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 22 - 22: OoOoOO00 + OoooooooOO - I1Ii111
  if 82 - 82: Ii1I % I1Ii111 / ooOoO0o
 def rtrs_in_rloc_set ( self ) :
  for OooO0ooO0o0OO in self . rloc_set :
   if ( OooO0ooO0o0OO . is_rtr ( ) ) : return ( True )
   if 86 - 86: II111iiii - iIii1I11I1II1 + oO0o + I1IiiI
  return ( False )
  if 29 - 29: Ii1I % OoooooooOO * II111iiii
  if 88 - 88: I1Ii111 + I11i + I1Ii111 % OoO0O00 / I1ii11iIi11i - I11i
  if 15 - 15: Oo0Ooo - i1IIi
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 87 - 87: O0 . o0oOOo0O0Ooo % OOooOOo / I11i - I1Ii111 % i11iIiiIii
  if 3 - 3: oO0o + iII111i + OOooOOo
 def get_timeout ( self , interface ) :
  try :
   OoOOO0 = lisp_myinterfaces [ interface ]
   self . timeout = OoOOO0 . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 25 - 25: iII111i % iII111i * ooOoO0o % I1ii11iIi11i % I1Ii111
   if 4 - 4: O0 % i11iIiiIii % I1Ii111 - i11iIiiIii / o0oOOo0O0Ooo % o0oOOo0O0Ooo
   if 59 - 59: i1IIi . o0oOOo0O0Ooo . IiII + iII111i * i1IIi
   if 41 - 41: ooOoO0o - i1IIi * IiII . OoOoOO00 % iIii1I11I1II1 - IiII
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 12 - 12: I1ii11iIi11i * iII111i / i11iIiiIii / OoOoOO00
  if 62 - 62: O0 - IiII + I1ii11iIi11i
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 67 - 67: i1IIi + i11iIiiIii * I1ii11iIi11i / ooOoO0o * OoO0O00
  if 52 - 52: II111iiii / Ii1I - iII111i
  if 33 - 33: I1IiiI
  if 41 - 41: OoOoOO00 * i1IIi
  if 94 - 94: I11i
  if 28 - 28: OOooOOo
  if 82 - 82: II111iiii
  if 66 - 66: iII111i % I1Ii111 * oO0o
  if 81 - 81: i11iIiiIii - O0 . iIii1I11I1II1 - I11i + iIii1I11I1II1
  if 50 - 50: Oo0Ooo . OoO0O00 + i11iIiiIii / i11iIiiIii
def lisp_is_group_more_specific ( group_str , group_mapping ) :
 oOo00Ooo0o0 = group_mapping . group_prefix . instance_id
 Ooo0o00 = group_mapping . group_prefix . mask_len
 oOoooOOO0o0 = lisp_address ( LISP_AFI_IPV4 , group_str , 32 , oOo00Ooo0o0 )
 if ( oOoooOOO0o0 . is_more_specific ( group_mapping . group_prefix ) ) : return ( Ooo0o00 )
 return ( - 1 )
 if 27 - 27: OoOoOO00 - OoOoOO00 % II111iiii + i1IIi + I1IiiI
 if 75 - 75: OoooooooOO . I11i - OoOoOO00
 if 93 - 93: OoOoOO00 . I1Ii111 % I1ii11iIi11i
 if 58 - 58: OoooooooOO . i1IIi . Oo0Ooo - o0oOOo0O0Ooo / oO0o * I1Ii111
 if 6 - 6: oO0o - OoO0O00
 if 44 - 44: Oo0Ooo + I1ii11iIi11i % Oo0Ooo / I11i
 if 57 - 57: Oo0Ooo + Ii1I * OoooooooOO
def lisp_lookup_group ( group ) :
 OOOOo00oo0OO = None
 for i1IiiiII1ii1I1 in lisp_group_mapping_list . values ( ) :
  Ooo0o00 = lisp_is_group_more_specific ( group , i1IiiiII1ii1I1 )
  if ( Ooo0o00 == - 1 ) : continue
  if ( OOOOo00oo0OO == None or Ooo0o00 > OOOOo00oo0OO . group_prefix . mask_len ) : OOOOo00oo0OO = i1IiiiII1ii1I1
  if 5 - 5: OoooooooOO / o0oOOo0O0Ooo
 return ( OOOOo00oo0OO )
 if 14 - 14: OOooOOo * Oo0Ooo - o0oOOo0O0Ooo + iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1
 if 4 - 4: OoOoOO00 / Oo0Ooo - OoO0O00 . OoOoOO00 / I1Ii111
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 60 - 60: OOooOOo * I1Ii111
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
  if 17 - 17: iII111i * I11i / iIii1I11I1II1 - II111iiii
  if 97 - 97: II111iiii * o0oOOo0O0Ooo
  if 13 - 13: o0oOOo0O0Ooo . II111iiii
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
  if 76 - 76: II111iiii + I1Ii111 . OoooooooOO / IiII % i11iIiiIii
  if 87 - 87: Ii1I / OoOoOO00 / OOooOOo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
  if 19 - 19: i1IIi + IiII . OoO0O00 / O0 - I1Ii111 - Oo0Ooo
 def print_flags ( self , html ) :
  if ( html == False ) :
   o0OooooOoOO = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # Oo0Ooo / iII111i
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   iIiI1 = self . print_flags ( False )
   iIiI1 = iIiI1 . split ( "-" )
   o0OooooOoOO = ""
   for iIIii1IiIIiI in iIiI1 :
    iiI = lisp_site_flags [ iIIii1IiIIiI . upper ( ) ]
    iiI = iiI . format ( "" if iIIii1IiIIiI . isupper ( ) else "not " )
    o0OooooOoOO += lisp_span ( iIIii1IiIIiI , iiI )
    if ( iIIii1IiIIiI . lower ( ) != "n" ) : o0OooooOoOO += "-"
    if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
    if 64 - 64: OoO0O00 - OoO0O00
  return ( o0OooooOoOO )
  if 93 - 93: Oo0Ooo . O0
  if 75 - 75: iII111i * II111iiii - I1IiiI
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 30 - 30: i1IIi / ooOoO0o . ooOoO0o
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
  if 97 - 97: i11iIiiIii . OoOoOO00 + oO0o * O0 % OoO0O00 - Ii1I
 def build_sort_key ( self ) :
  i11II111IiIiI = lisp_cache ( )
  O0ooOo , iII1 = i11II111IiIiI . build_key ( self . eid )
  oOo0oOoOo0O = ""
  if ( self . group . is_null ( ) == False ) :
   iiii , oOo0oOoOo0O = i11II111IiIiI . build_key ( self . group )
   oOo0oOoOo0O = "-" + oOo0oOoOo0O [ 0 : 12 ] + "-" + str ( iiii ) + "-" + oOo0oOoOo0O [ 12 : : ]
   if 53 - 53: IiII / I1IiiI / i1IIi
  iII1 = iII1 [ 0 : 12 ] + "-" + str ( O0ooOo ) + "-" + iII1 [ 12 : : ] + oOo0oOoOo0O
  del ( i11II111IiIiI )
  return ( iII1 )
  if 49 - 49: i11iIiiIii % I1IiiI % I1Ii111 / I1ii11iIi11i - i11iIiiIii . i1IIi
  if 84 - 84: i11iIiiIii
 def merge_in_site_eid ( self , child ) :
  OO0O0O = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   OO0O0O = self . merge_rles_in_site_eid ( )
   if 51 - 51: Oo0Ooo + I1IiiI
   if 63 - 63: I11i
   if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
   if 63 - 63: o0oOOo0O0Ooo . IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
   if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
   if 38 - 38: O0 % I1ii11iIi11i + O0
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 37 - 37: Oo0Ooo / I1IiiI
  return ( OO0O0O )
  if 23 - 23: II111iiii / iII111i
  if 55 - 55: i11iIiiIii - Ii1I % OoooooooOO * OoooooooOO
 def copy_rloc_records ( self ) :
  oO0iII1IIii1iii = [ ]
  for IiIIIi in self . registered_rlocs :
   oO0iII1IIii1iii . append ( copy . deepcopy ( IiIIIi ) )
   if 98 - 98: II111iiii % I1Ii111
  return ( oO0iII1IIii1iii )
  if 64 - 64: I11i
  if 26 - 26: ooOoO0o * I11i + OOooOOo * i1IIi
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for O0oiiii1i1i11I in self . individual_registrations . values ( ) :
   if ( self . site_id != O0oiiii1i1i11I . site_id ) : continue
   if ( O0oiiii1i1i11I . registered == False ) : continue
   self . registered_rlocs += O0oiiii1i1i11I . copy_rloc_records ( )
   if 48 - 48: o0oOOo0O0Ooo - I1ii11iIi11i / iII111i
   if 63 - 63: O0 - IiII . OOooOOo % IiII . I1IiiI / oO0o
   if 79 - 79: OoOoOO00
   if 88 - 88: oO0o * o0oOOo0O0Ooo
   if 5 - 5: I11i - I1Ii111 * I11i - II111iiii + OOooOOo + II111iiii
   if 91 - 91: i1IIi + Oo0Ooo - I1ii11iIi11i + I1ii11iIi11i * O0 / O0
  oO0iII1IIii1iii = [ ]
  for IiIIIi in self . registered_rlocs :
   if ( IiIIIi . rloc . is_null ( ) or len ( oO0iII1IIii1iii ) == 0 ) :
    oO0iII1IIii1iii . append ( IiIIIi )
    continue
    if 78 - 78: OoooooooOO
   for II1IIii1 in oO0iII1IIii1iii :
    if ( II1IIii1 . rloc . is_null ( ) ) : continue
    if ( IiIIIi . rloc . is_exact_match ( II1IIii1 . rloc ) ) : break
    if 73 - 73: o0oOOo0O0Ooo + OoooooooOO - I1Ii111 . iIii1I11I1II1
   if ( II1IIii1 == oO0iII1IIii1iii [ - 1 ] ) : oO0iII1IIii1iii . append ( IiIIIi )
   if 25 - 25: OoooooooOO % I1ii11iIi11i % Oo0Ooo % i11iIiiIii
  self . registered_rlocs = oO0iII1IIii1iii
  if 8 - 8: O0 - O0 % Ii1I
  if 22 - 22: OoOoOO00
  if 85 - 85: II111iiii - II111iiii
  if 95 - 95: II111iiii + II111iiii + iII111i
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 38 - 38: OoO0O00 * Ii1I * O0 / I1IiiI
  if 99 - 99: Oo0Ooo + ooOoO0o - I1ii11iIi11i + I1Ii111 + Ii1I * I1IiiI
 def merge_rles_in_site_eid ( self ) :
  if 68 - 68: OoO0O00
  if 79 - 79: Ii1I . IiII + OoOoOO00
  if 10 - 10: OoooooooOO * iII111i * ooOoO0o . Ii1I % I1Ii111 / I1ii11iIi11i
  if 71 - 71: Ii1I + IiII
  IiiI1I1iIii = { }
  for IiIIIi in self . registered_rlocs :
   if ( IiIIIi . rle == None ) : continue
   for Oo0000O00o0 in IiIIIi . rle . rle_nodes :
    O0o00o000oO = Oo0000O00o0 . address . print_address_no_iid ( )
    IiiI1I1iIii [ O0o00o000oO ] = Oo0000O00o0 . address
    if 79 - 79: Oo0Ooo % oO0o . oO0o . o0oOOo0O0Ooo + I1IiiI - I1ii11iIi11i
   break
   if 8 - 8: I1ii11iIi11i
   if 50 - 50: o0oOOo0O0Ooo - O0 - II111iiii + OOooOOo - OoOoOO00 + OoO0O00
   if 33 - 33: o0oOOo0O0Ooo % OoOoOO00 + iII111i
   if 54 - 54: OoO0O00
   if 18 - 18: I1Ii111 - Oo0Ooo
  self . merge_rlocs_in_site_eid ( )
  if 66 - 66: iII111i - IiII . I1Ii111
  if 29 - 29: I1Ii111 - Ii1I + O0 - oO0o - O0
  if 68 - 68: iII111i + II111iiii + I1ii11iIi11i * OOooOOo / oO0o
  if 41 - 41: OOooOOo + Oo0Ooo % I1IiiI
  if 3 - 3: ooOoO0o * Ii1I
  if 29 - 29: OoooooooOO + OOooOOo
  if 68 - 68: O0 + IiII / iII111i - OoOoOO00
  if 5 - 5: I1IiiI * OoooooooOO - II111iiii
  o00O = [ ]
  for IiIIIi in self . registered_rlocs :
   if ( self . registered_rlocs . index ( IiIIIi ) == 0 ) :
    o00O . append ( IiIIIi )
    continue
    if 68 - 68: iIii1I11I1II1 / II111iiii
   if ( IiIIIi . rle == None ) : o00O . append ( IiIIIi )
   if 47 - 47: i11iIiiIii . OOooOOo + I1Ii111 / I1ii11iIi11i . I1IiiI . I1Ii111
  self . registered_rlocs = o00O
  if 79 - 79: OoO0O00 / i11iIiiIii . IiII - I11i / iIii1I11I1II1
  if 81 - 81: Oo0Ooo . II111iiii + i11iIiiIii - OoOoOO00 * ooOoO0o
  if 25 - 25: Ii1I / Oo0Ooo
  if 79 - 79: o0oOOo0O0Ooo . i1IIi % I1ii11iIi11i % II111iiii . iIii1I11I1II1
  if 45 - 45: I1ii11iIi11i / iIii1I11I1II1 + OoO0O00 / O0 - O0 - I1Ii111
  if 88 - 88: o0oOOo0O0Ooo % I1Ii111
  if 4 - 4: i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
  OoO000oo000o0 = lisp_rle ( "" )
  o0Ooo00oooo = { }
  Ooo000oo0OO0 = None
  for O0oiiii1i1i11I in self . individual_registrations . values ( ) :
   if ( O0oiiii1i1i11I . registered == False ) : continue
   IiiiiIIii = O0oiiii1i1i11I . registered_rlocs [ 0 ] . rle
   if ( IiiiiIIii == None ) : continue
   if 59 - 59: Ii1I + iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / iIii1I11I1II1 - o0oOOo0O0Ooo
   Ooo000oo0OO0 = O0oiiii1i1i11I . registered_rlocs [ 0 ] . rloc_name
   for iIIiii1I11 in IiiiiIIii . rle_nodes :
    O0o00o000oO = iIIiii1I11 . address . print_address_no_iid ( )
    if ( o0Ooo00oooo . has_key ( O0o00o000oO ) ) : break
    if 14 - 14: IiII + I11i - o0oOOo0O0Ooo
    Oo0000O00o0 = lisp_rle_node ( )
    Oo0000O00o0 . address . copy_address ( iIIiii1I11 . address )
    Oo0000O00o0 . level = iIIiii1I11 . level
    Oo0000O00o0 . rloc_name = Ooo000oo0OO0
    OoO000oo000o0 . rle_nodes . append ( Oo0000O00o0 )
    o0Ooo00oooo [ O0o00o000oO ] = iIIiii1I11 . address
    if 100 - 100: ooOoO0o
    if 29 - 29: II111iiii % II111iiii - OoooooooOO * OoooooooOO
    if 54 - 54: iII111i / OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
    if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
    if 8 - 8: OoooooooOO % I11i - iII111i * OOooOOo . O0
    if 40 - 40: I1Ii111 . oO0o + OoO0O00 % Oo0Ooo / II111iiii
  if ( len ( OoO000oo000o0 . rle_nodes ) == 0 ) : OoO000oo000o0 = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = OoO000oo000o0
   if ( Ooo000oo0OO0 ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 19 - 19: i11iIiiIii
   if 20 - 20: i11iIiiIii . II111iiii - I1ii11iIi11i / ooOoO0o % i11iIiiIii
   if 35 - 35: Oo0Ooo - I1ii11iIi11i . Oo0Ooo
   if 13 - 13: II111iiii / OoOoOO00 * iII111i % O0 % I1ii11iIi11i * i11iIiiIii
   if 92 - 92: i11iIiiIii + OoO0O00
  if ( IiiI1I1iIii . keys ( ) == o0Ooo00oooo . keys ( ) ) : return ( False )
  if 94 - 94: I1ii11iIi11i + OoO0O00 . II111iiii + oO0o . II111iiii
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # i11iIiiIii . Ii1I - ooOoO0o * iII111i - iII111i - i11iIiiIii
 IiiI1I1iIii . keys ( ) , o0Ooo00oooo . keys ( ) ) )
  if 6 - 6: I1ii11iIi11i / iIii1I11I1II1 / I11i % iIii1I11I1II1
  return ( True )
  if 49 - 49: OOooOOo * iIii1I11I1II1 - iIii1I11I1II1
  if 70 - 70: OoO0O00 % i11iIiiIii * IiII . I11i * Oo0Ooo
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   oo0OO0O0 = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( oo0OO0O0 == None ) :
    oo0OO0O0 = lisp_site_eid ( self . site )
    oo0OO0O0 . eid . copy_address ( self . group )
    oo0OO0O0 . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , oo0OO0O0 )
    if 17 - 17: i1IIi
    if 29 - 29: OOooOOo % OoO0O00 + oO0o + o0oOOo0O0Ooo . iII111i
    if 14 - 14: i1IIi + OoOoOO00 * oO0o - II111iiii + IiII + OoOoOO00
    if 42 - 42: Oo0Ooo + iII111i * ooOoO0o
    if 72 - 72: iIii1I11I1II1 % I1Ii111
    oo0OO0O0 . parent_for_more_specifics = self . parent_for_more_specifics
    if 77 - 77: I1Ii111 * I1IiiI / iIii1I11I1II1 . II111iiii * Oo0Ooo
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( oo0OO0O0 . group )
   oo0OO0O0 . add_source_entry ( self )
   if 71 - 71: ooOoO0o / iIii1I11I1II1 % O0 / I1ii11iIi11i . I1Ii111 / i11iIiiIii
   if 6 - 6: oO0o . OoO0O00 - II111iiii . I1IiiI - o0oOOo0O0Ooo - i1IIi
   if 42 - 42: Ii1I + i11iIiiIii
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   oo0OO0O0 = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( oo0OO0O0 == None ) : return
   if 46 - 46: O0 % OoOoOO00 - I1Ii111 . I1IiiI
   O0oiiii1i1i11I = oo0OO0O0 . lookup_source_cache ( self . eid , True )
   if ( O0oiiii1i1i11I == None ) : return
   if 66 - 66: II111iiii * iIii1I11I1II1 * ooOoO0o * I11i . II111iiii - ooOoO0o
   if ( oo0OO0O0 . source_cache == None ) : return
   if 15 - 15: I1ii11iIi11i - i11iIiiIii - Ii1I / Ii1I . iII111i
   oo0OO0O0 . source_cache . delete_cache ( self . eid )
   if ( oo0OO0O0 . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 36 - 36: oO0o + Oo0Ooo * I1Ii111 % OOooOOo . Oo0Ooo . I1IiiI
    if 81 - 81: o0oOOo0O0Ooo . OoOoOO00 . i11iIiiIii
    if 13 - 13: i1IIi
    if 70 - 70: O0 / II111iiii
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 98 - 98: OoOoOO00 - O0 . O0 + ooOoO0o * iIii1I11I1II1
  if 7 - 7: IiII * OoOoOO00 + iIii1I11I1II1 / OoOoOO00 + Oo0Ooo / o0oOOo0O0Ooo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 77 - 77: i1IIi . I1IiiI
  if 59 - 59: O0 + OoooooooOO - i1IIi
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 87 - 87: IiII * OoooooooOO / Oo0Ooo % iIii1I11I1II1 % oO0o
  if 97 - 97: ooOoO0o % i1IIi . IiII / Oo0Ooo . I1Ii111 . OoO0O00
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 12 - 12: I1IiiI
  if 99 - 99: II111iiii - OoOoOO00
 def inherit_from_ams_parent ( self ) :
  II1i1i = self . parent_for_more_specifics
  if ( II1i1i == None ) : return
  self . force_proxy_reply = II1i1i . force_proxy_reply
  self . force_nat_proxy_reply = II1i1i . force_nat_proxy_reply
  self . force_ttl = II1i1i . force_ttl
  self . pitr_proxy_reply_drop = II1i1i . pitr_proxy_reply_drop
  self . proxy_reply_action = II1i1i . proxy_reply_action
  self . echo_nonce_capable = II1i1i . echo_nonce_capable
  self . policy = II1i1i . policy
  self . require_signature = II1i1i . require_signature
  if 22 - 22: i11iIiiIii * II111iiii
  if 11 - 11: Oo0Ooo % i1IIi
 def rtrs_in_rloc_set ( self ) :
  for IiIIIi in self . registered_rlocs :
   if ( IiIIIi . is_rtr ( ) ) : return ( True )
   if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
  return ( False )
  if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
  if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for IiIIIi in self . registered_rlocs :
   if ( IiIIIi . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( IiIIIi . is_rtr ( ) ) : return ( True )
   if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
  return ( False )
  if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
  if 8 - 8: OoooooooOO
 def is_rloc_in_rloc_set ( self , rloc ) :
  for IiIIIi in self . registered_rlocs :
   if ( IiIIIi . rle ) :
    for OoO000oo000o0 in IiIIIi . rle . rle_nodes :
     if ( OoO000oo000o0 . address . is_exact_match ( rloc ) ) : return ( True )
     if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
     if 83 - 83: o0oOOo0O0Ooo * Ii1I - Oo0Ooo * iII111i - i11iIiiIii
   if ( IiIIIi . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 6 - 6: I1IiiI + i11iIiiIii + O0 / i1IIi
  return ( False )
  if 50 - 50: iII111i . II111iiii % I1Ii111 % I1IiiI / o0oOOo0O0Ooo . I1IiiI
  if 76 - 76: OOooOOo % iII111i
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 80 - 80: iIii1I11I1II1 + o0oOOo0O0Ooo + iIii1I11I1II1
  for IiIIIi in prev_rloc_set :
   iiiIii = IiIIIi . rloc
   if ( self . is_rloc_in_rloc_set ( iiiIii ) == False ) : return ( False )
   if 63 - 63: OoOoOO00 - o0oOOo0O0Ooo % II111iiii - Ii1I
  return ( True )
  if 81 - 81: iII111i % OOooOOo * oO0o
  if 84 - 84: iII111i - OoooooooOO + I1ii11iIi11i - I1IiiI
  if 52 - 52: oO0o / ooOoO0o / iII111i / OoOoOO00 * iIii1I11I1II1
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
   if 74 - 74: oO0o . I1ii11iIi11i - iIii1I11I1II1
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 73 - 73: OoO0O00 / O0 . o0oOOo0O0Ooo
  if 100 - 100: Ii1I . OoO0O00 % I1ii11iIi11i % O0 * Oo0Ooo - OoOoOO00
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 15 - 15: OOooOOo - OOooOOo - OoooooooOO * OoO0O00
  try :
   I1i1II1 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   Iii1111IIiI1 = I1i1II1 [ 2 ]
  except :
   return
   if 48 - 48: I1Ii111 * iII111i
   if 93 - 93: I11i % iIii1I11I1II1 + Ii1I - I1IiiI + OoooooooOO . IiII
   if 77 - 77: i11iIiiIii . OoooooooOO % iIii1I11I1II1 % I1Ii111
   if 22 - 22: iIii1I11I1II1 + Ii1I / OOooOOo - oO0o * oO0o / IiII
   if 91 - 91: I11i - II111iiii + o0oOOo0O0Ooo + i1IIi + I1ii11iIi11i % Ii1I
   if 57 - 57: o0oOOo0O0Ooo - I1Ii111 / OoooooooOO . OoooooooOO
  if ( len ( Iii1111IIiI1 ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 44 - 44: oO0o / II111iiii % I1IiiI - II111iiii / OoooooooOO
   if 4 - 4: I11i * OoOoOO00
  O0o00o000oO = Iii1111IIiI1 [ self . a_record_index ]
  if ( O0o00o000oO != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( O0o00o000oO )
   self . insert_mr ( )
   if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
   if 87 - 87: oO0o . I11i
   if 15 - 15: oO0o
   if 45 - 45: Oo0Ooo * IiII * OoO0O00 + iIii1I11I1II1
   if 89 - 89: IiII . IiII . oO0o % iII111i
   if 27 - 27: OoOoOO00 + O0 % i1IIi - Oo0Ooo
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 96 - 96: O0 % o0oOOo0O0Ooo + OOooOOo % I1IiiI
  for O0o00o000oO in Iii1111IIiI1 [ 1 : : ] :
   O0o00O0Oo0 = lisp_address ( LISP_AFI_NONE , O0o00o000oO , 0 , 0 )
   ii1 = lisp_get_map_resolver ( O0o00O0Oo0 , None )
   if ( ii1 != None and ii1 . a_record_index == Iii1111IIiI1 . index ( O0o00o000oO ) ) :
    continue
    if 51 - 51: i1IIi . o0oOOo0O0Ooo % I1IiiI - OoooooooOO / OoOoOO00 - I11i
   ii1 = lisp_mr ( O0o00o000oO , None , None )
   ii1 . a_record_index = Iii1111IIiI1 . index ( O0o00o000oO )
   ii1 . dns_name = self . dns_name
   ii1 . last_dns_resolve = lisp_get_timestamp ( )
   if 45 - 45: O0 * II111iiii / i11iIiiIii
   if 38 - 38: OoooooooOO % i11iIiiIii - O0 / O0
   if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
   if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
   if 85 - 85: IiII / Ii1I - I1ii11iIi11i * OOooOOo
  ii1111Ii = [ ]
  for ii1 in lisp_map_resolvers_list . values ( ) :
   if ( self . dns_name != ii1 . dns_name ) : continue
   O0o00O0Oo0 = ii1 . map_resolver . print_address_no_iid ( )
   if ( O0o00O0Oo0 in Iii1111IIiI1 ) : continue
   ii1111Ii . append ( ii1 )
   if 8 - 8: oO0o - iIii1I11I1II1 * iII111i
  for ii1 in ii1111Ii : ii1 . delete_mr ( )
  if 15 - 15: II111iiii * O0 % I1ii11iIi11i % Ii1I . OoOoOO00
  if 8 - 8: IiII / Oo0Ooo % OOooOOo + O0 - Ii1I
 def insert_mr ( self ) :
  iII1 = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ iII1 ] = self
  if 43 - 43: O0 % i11iIiiIii + o0oOOo0O0Ooo . I11i / OOooOOo . O0
  if 30 - 30: i11iIiiIii + i1IIi
 def delete_mr ( self ) :
  iII1 = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( iII1 ) == False ) : return
  lisp_map_resolvers_list . pop ( iII1 )
  if 52 - 52: OoooooooOO % OoOoOO00 / IiII % OoO0O00
  if 36 - 36: II111iiii . O0 % O0 * iII111i * iIii1I11I1II1
  if 42 - 42: iII111i . OOooOOo + oO0o / OoOoOO00
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 54 - 54: ooOoO0o % o0oOOo0O0Ooo + i11iIiiIii / ooOoO0o * II111iiii * Ii1I
  if 52 - 52: ooOoO0o + IiII * OoOoOO00 - OoO0O00 - OoooooooOO - oO0o
  if 60 - 60: iII111i / oO0o
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
  if 98 - 98: OoOoOO00 / OOooOOo
  if 31 - 31: II111iiii % I11i - I11i
 def print_referral ( self , eid_indent , referral_indent ) :
  I1II11i11Iiii = lisp_print_elapsed ( self . uptime )
  iiI111I11 = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , I1II11i11Iiii ,
  # iIii1I11I1II1 . i11iIiiIii / OOooOOo
 iiI111I11 , len ( self . referral_set ) ) )
  if 27 - 27: I1IiiI / Ii1I * iIii1I11I1II1 * iIii1I11I1II1 + ooOoO0o
  for IiIiII11 in self . referral_set . values ( ) :
   IiIiII11 . print_ref_node ( referral_indent )
   if 92 - 92: OOooOOo
   if 34 - 34: I1ii11iIi11i . OOooOOo + OoO0O00 % o0oOOo0O0Ooo * O0 * I1IiiI
   if 9 - 9: IiII / i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % I1Ii111
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 65 - 65: I1IiiI % OoOoOO00
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 45 - 45: o0oOOo0O0Ooo
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 33 - 33: ooOoO0o % O0 % I1ii11iIi11i % o0oOOo0O0Ooo + i11iIiiIii . I1Ii111
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 21 - 21: I1Ii111 * I1ii11iIi11i * ooOoO0o
  if 73 - 73: OoOoOO00 * O0
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 1 - 1: OOooOOo * OoooooooOO
  if 46 - 46: I1ii11iIi11i * I1Ii111 / OOooOOo / I1IiiI
 def print_ttl ( self ) :
  oo0OOoOO0 = self . referral_ttl
  if ( oo0OOoOO0 < 60 ) : return ( str ( oo0OOoOO0 ) + " secs" )
  if 7 - 7: OOooOOo / OoOoOO00
  if ( ( oo0OOoOO0 % 60 ) == 0 ) :
   oo0OOoOO0 = str ( oo0OOoOO0 / 60 ) + " mins"
  else :
   oo0OOoOO0 = str ( oo0OOoOO0 ) + " secs"
   if 93 - 93: iIii1I11I1II1 * Ii1I - iII111i
  return ( oo0OOoOO0 )
  if 94 - 94: iIii1I11I1II1 * iIii1I11I1II1 * I11i % i11iIiiIii
  if 38 - 38: I1IiiI % I1ii11iIi11i * I1IiiI + OOooOOo - OoOoOO00
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # Oo0Ooo / I1Ii111 % I11i + I11i + iIii1I11I1II1
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 38 - 38: i11iIiiIii + iII111i
  if 49 - 49: o0oOOo0O0Ooo
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   iiiI11i1ii1i = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( iiiI11i1ii1i == None ) :
    iiiI11i1ii1i = lisp_referral ( )
    iiiI11i1ii1i . eid . copy_address ( self . group )
    iiiI11i1ii1i . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , iiiI11i1ii1i )
    if 47 - 47: iII111i % i11iIiiIii / ooOoO0o + IiII . iII111i % iII111i
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( iiiI11i1ii1i . group )
   iiiI11i1ii1i . add_source_entry ( self )
   if 18 - 18: o0oOOo0O0Ooo * OoooooooOO % i1IIi
   if 17 - 17: iII111i . o0oOOo0O0Ooo / II111iiii % Oo0Ooo
   if 1 - 1: OOooOOo % o0oOOo0O0Ooo * o0oOOo0O0Ooo / oO0o
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   iiiI11i1ii1i = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( iiiI11i1ii1i == None ) : return
   if 79 - 79: oO0o . OOooOOo
   O0i1I1iI1Iiii1I = iiiI11i1ii1i . lookup_source_cache ( self . eid , True )
   if ( O0i1I1iI1Iiii1I == None ) : return
   if 82 - 82: I1Ii111 % II111iiii
   iiiI11i1ii1i . source_cache . delete_cache ( self . eid )
   if ( iiiI11i1ii1i . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 10 - 10: II111iiii * Ii1I % IiII + I11i
    if 29 - 29: IiII / Ii1I / I1Ii111
    if 30 - 30: i1IIi + OOooOOo + Oo0Ooo % iII111i % O0 + i1IIi
    if 45 - 45: ooOoO0o
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 89 - 89: iIii1I11I1II1 . I1Ii111
  if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 59 - 59: IiII . OoO0O00 - OoooooooOO . O0
  if 33 - 33: Ii1I
  if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 40 - 40: I1IiiI / OOooOOo * Ii1I
  if 98 - 98: I1IiiI
 def print_ref_node ( self , indent ) :
  Oo0OO0000oooo = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , Oo0OO0000oooo ,
  # o0oOOo0O0Ooo
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 79 - 79: O0 / II111iiii
  if 39 - 39: IiII
  if 79 - 79: iIii1I11I1II1 * oO0o . iIii1I11I1II1 * O0
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
   if 13 - 13: I1ii11iIi11i . IiII - I11i
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
   if 81 - 81: i11iIiiIii
   if 7 - 7: IiII - OoOoOO00 * i1IIi
   if 14 - 14: I1ii11iIi11i . OoO0O00
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
  try :
   I1i1II1 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   Iii1111IIiI1 = I1i1II1 [ 2 ]
  except :
   return
   if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
   if 29 - 29: O0 + iII111i
   if 4 - 4: I11i * I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
   if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
   if 76 - 76: OoooooooOO - O0
   if 17 - 17: Oo0Ooo % I1Ii111 . oO0o - O0
  if ( len ( Iii1111IIiI1 ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 32 - 32: O0 % O0
   if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
  O0o00o000oO = Iii1111IIiI1 [ self . a_record_index ]
  if ( O0o00o000oO != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( O0o00o000oO )
   self . insert_ms ( )
   if 65 - 65: I1ii11iIi11i % ooOoO0o - OoOoOO00 + ooOoO0o + Oo0Ooo
   if 95 - 95: I1Ii111 * i11iIiiIii - I1IiiI - OoOoOO00 . ooOoO0o
   if 34 - 34: OoooooooOO % I1ii11iIi11i + OoooooooOO % i11iIiiIii / IiII - ooOoO0o
   if 74 - 74: iIii1I11I1II1 % II111iiii + IiII
   if 71 - 71: I1IiiI / O0 * i1IIi . i1IIi + Oo0Ooo
   if 32 - 32: i1IIi * I1Ii111 % I1IiiI / IiII . I1Ii111
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 11 - 11: OOooOOo
  for O0o00o000oO in Iii1111IIiI1 [ 1 : : ] :
   O0o00O0Oo0 = lisp_address ( LISP_AFI_NONE , O0o00o000oO , 0 , 0 )
   Ii1IIII = lisp_get_map_server ( O0o00O0Oo0 )
   if ( Ii1IIII != None and Ii1IIII . a_record_index == Iii1111IIiI1 . index ( O0o00o000oO ) ) :
    continue
    if 25 - 25: i1IIi
   Ii1IIII = copy . deepcopy ( self )
   Ii1IIII . map_server . store_address ( O0o00o000oO )
   Ii1IIII . a_record_index = Iii1111IIiI1 . index ( O0o00o000oO )
   Ii1IIII . last_dns_resolve = lisp_get_timestamp ( )
   Ii1IIII . insert_ms ( )
   if 99 - 99: OOooOOo + OoooooooOO . I1Ii111 * Oo0Ooo % oO0o
   if 75 - 75: iII111i
   if 8 - 8: I1ii11iIi11i . I11i / I1ii11iIi11i - i1IIi
   if 22 - 22: OOooOOo
   if 7 - 7: O0 - I1ii11iIi11i - OoO0O00 * I1Ii111
  ii1111Ii = [ ]
  for Ii1IIII in lisp_map_servers_list . values ( ) :
   if ( self . dns_name != Ii1IIII . dns_name ) : continue
   O0o00O0Oo0 = Ii1IIII . map_server . print_address_no_iid ( )
   if ( O0o00O0Oo0 in Iii1111IIiI1 ) : continue
   ii1111Ii . append ( Ii1IIII )
   if 17 - 17: o0oOOo0O0Ooo % OoO0O00 - I11i * o0oOOo0O0Ooo - i1IIi / I1IiiI
  for Ii1IIII in ii1111Ii : Ii1IIII . delete_ms ( )
  if 100 - 100: OoO0O00 * i1IIi * o0oOOo0O0Ooo * Oo0Ooo - o0oOOo0O0Ooo
  if 100 - 100: iII111i - i11iIiiIii + OoO0O00
 def insert_ms ( self ) :
  iII1 = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ iII1 ] = self
  if 50 - 50: II111iiii
  if 42 - 42: OOooOOo * I1Ii111
 def delete_ms ( self ) :
  iII1 = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( iII1 ) == False ) : return
  lisp_map_servers_list . pop ( iII1 )
  if 53 - 53: II111iiii % OOooOOo / I1ii11iIi11i * OoOoOO00 % I1ii11iIi11i * iII111i
  if 91 - 91: iII111i . OoooooooOO
  if 90 - 90: i11iIiiIii - I1IiiI
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
  if 39 - 39: iII111i % OoooooooOO % Ii1I % I1IiiI
  if 63 - 63: OoO0O00 - I1Ii111 - II111iiii
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 79 - 79: II111iiii - II111iiii + OoOoOO00 / iII111i % OoooooooOO - OoO0O00
  if 22 - 22: o0oOOo0O0Ooo + I1Ii111 . Oo0Ooo
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 84 - 84: O0 + I1IiiI % Oo0Ooo + OOooOOo
  if 94 - 94: OOooOOo
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
  if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 31 - 31: I11i . o0oOOo0O0Ooo
  if 82 - 82: I11i - Oo0Ooo
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 77 - 77: I1IiiI + OoO0O00 % iIii1I11I1II1 - OOooOOo
  if 80 - 80: oO0o % I1ii11iIi11i * I1Ii111 + i1IIi
 def set_socket ( self , device ) :
  o0 = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  o0 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   o0 . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   o0 . close ( )
   o0 = None
   if 79 - 79: oO0o + IiII
  self . raw_socket = o0
  if 4 - 4: iII111i + OoooooooOO / I1Ii111
  if 57 - 57: I1IiiI . iIii1I11I1II1 % iII111i * iII111i / I1Ii111
 def set_bridge_socket ( self , device ) :
  o0 = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   o0 = o0 . bind ( ( device , 0 ) )
   self . bridge_socket = o0
  except :
   return
   if 30 - 30: O0 / I11i % OoOoOO00 * I1Ii111 / O0 % ooOoO0o
   if 36 - 36: iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
   if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
   if 97 - 97: i11iIiiIii / O0 % OoO0O00
class lisp_datetime ( ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 88 - 88: i1IIi . I1IiiI
  if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
 def valid_datetime ( self ) :
  OO00000 = self . datetime_name
  if ( OO00000 . find ( ":" ) == - 1 ) : return ( False )
  if ( OO00000 . find ( "-" ) == - 1 ) : return ( False )
  OOoOooOOO0 , OO0oo00o , i1ii1I1i11 , time = OO00000 [ 0 : 4 ] , OO00000 [ 5 : 7 ] , OO00000 [ 8 : 10 ] , OO00000 [ 11 : : ]
  if 54 - 54: OoooooooOO . iIii1I11I1II1 + iIii1I11I1II1
  if ( ( OOoOooOOO0 + OO0oo00o + i1ii1I1i11 ) . isdigit ( ) == False ) : return ( False )
  if ( OO0oo00o < "01" and OO0oo00o > "12" ) : return ( False )
  if ( i1ii1I1i11 < "01" and i1ii1I1i11 > "31" ) : return ( False )
  if 11 - 11: Ii1I * OoO0O00 % I1ii11iIi11i
  oo0o00O0oO , i11IiII1 , Oooo000O = time . split ( ":" )
  if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
  if ( ( oo0o00O0oO + i11IiII1 + Oooo000O ) . isdigit ( ) == False ) : return ( False )
  if ( oo0o00O0oO < "00" and oo0o00O0oO > "23" ) : return ( False )
  if ( i11IiII1 < "00" and i11IiII1 > "59" ) : return ( False )
  if ( Oooo000O < "00" and Oooo000O > "59" ) : return ( False )
  return ( True )
  if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
  if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
 def parse_datetime ( self ) :
  IIi1iii1i1 = self . datetime_name
  IIi1iii1i1 = IIi1iii1i1 . replace ( "-" , "" )
  IIi1iii1i1 = IIi1iii1i1 . replace ( ":" , "" )
  self . datetime = int ( IIi1iii1i1 )
  if 29 - 29: oO0o / iIii1I11I1II1 % Oo0Ooo * Ii1I
  if 49 - 49: OoO0O00 * I11i * iIii1I11I1II1 * I11i - I1IiiI . Oo0Ooo
 def now ( self ) :
  Oo0OO0000oooo = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  Oo0OO0000oooo = lisp_datetime ( Oo0OO0000oooo )
  return ( Oo0OO0000oooo )
  if 74 - 74: II111iiii % iII111i * Ii1I % I1ii11iIi11i * II111iiii / i11iIiiIii
  if 13 - 13: i1IIi % i1IIi % ooOoO0o + IiII * II111iiii * OOooOOo
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 66 - 66: iIii1I11I1II1
  if 92 - 92: OOooOOo * o0oOOo0O0Ooo - IiII
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 83 - 83: OoO0O00 % I1IiiI % OOooOOo / oO0o + I1IiiI
  if 94 - 94: OoOoOO00 . O0
 def past ( self ) :
  return ( self . future ( ) == False )
  if 86 - 86: oO0o % Oo0Ooo . OoooooooOO / OOooOOo / i1IIi
  if 65 - 65: Ii1I . OoooooooOO % IiII - o0oOOo0O0Ooo . OOooOOo . II111iiii
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 100 - 100: ooOoO0o / Oo0Ooo + I1ii11iIi11i + OoooooooOO
  if 100 - 100: I11i . OOooOOo - II111iiii % I11i % iIii1I11I1II1
 def this_year ( self ) :
  iIiooo = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  Oo0OO0000oooo = str ( self . datetime ) [ 0 : 4 ]
  return ( Oo0OO0000oooo == iIiooo )
  if 81 - 81: O0 / ooOoO0o * iIii1I11I1II1 . iIii1I11I1II1 / IiII % I11i
  if 58 - 58: i11iIiiIii
 def this_month ( self ) :
  iIiooo = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  Oo0OO0000oooo = str ( self . datetime ) [ 0 : 6 ]
  return ( Oo0OO0000oooo == iIiooo )
  if 25 - 25: I11i % Ii1I
  if 13 - 13: iIii1I11I1II1 - I1IiiI % o0oOOo0O0Ooo * iIii1I11I1II1
 def today ( self ) :
  iIiooo = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  Oo0OO0000oooo = str ( self . datetime ) [ 0 : 8 ]
  return ( Oo0OO0000oooo == iIiooo )
  if 99 - 99: OoooooooOO / II111iiii . I1Ii111
  if 62 - 62: OOooOOo . iII111i . I1ii11iIi11i
  if 23 - 23: O0
  if 33 - 33: ooOoO0o - iII111i % IiII
  if 67 - 67: II111iiii
  if 66 - 66: iIii1I11I1II1 / OOooOOo
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
  if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
  if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
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
  if 67 - 67: I1Ii111
  if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
 def match_policy_map_request ( self , mr , srloc ) :
  for OOo0I111I in self . match_clauses :
   iIiiI11II11 = OOo0I111I . source_eid
   OooOOo0ooO = mr . source_eid
   if ( iIiiI11II11 and OooOOo0ooO and OooOOo0ooO . is_more_specific ( iIiiI11II11 ) == False ) : continue
   if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
   iIiiI11II11 = OOo0I111I . dest_eid
   OooOOo0ooO = mr . target_eid
   if ( iIiiI11II11 and OooOOo0ooO and OooOOo0ooO . is_more_specific ( iIiiI11II11 ) == False ) : continue
   if 46 - 46: I11i - ooOoO0o . I1IiiI
   iIiiI11II11 = OOo0I111I . source_rloc
   OooOOo0ooO = srloc
   if ( iIiiI11II11 and OooOOo0ooO and OooOOo0ooO . is_more_specific ( iIiiI11II11 ) == False ) : continue
   o0000oO = OOo0I111I . datetime_lower
   I11I1i1 = OOo0I111I . datetime_upper
   if ( o0000oO and I11I1i1 and o0000oO . now_in_range ( I11I1i1 ) == False ) : continue
   return ( True )
   if 47 - 47: I1IiiI * i11iIiiIii / I1IiiI / iIii1I11I1II1 - Ii1I
  return ( False )
  if 25 - 25: oO0o / i11iIiiIii + i11iIiiIii % IiII - o0oOOo0O0Ooo
  if 97 - 97: I1ii11iIi11i % iII111i * ooOoO0o % OOooOOo . I1IiiI - i11iIiiIii
 def set_policy_map_reply ( self ) :
  i11oo00oOOOOo = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( i11oo00oOOOOo ) : return ( None )
  if 2 - 2: oO0o - OoooooooOO
  OooO0ooO0o0OO = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   OooO0ooO0o0OO . rloc . copy_address ( self . set_rloc_address )
   O0o00o000oO = OooO0ooO0o0OO . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( O0o00o000oO ) )
   if 44 - 44: I1Ii111
  if ( self . set_rloc_record_name ) :
   OooO0ooO0o0OO . rloc_name = self . set_rloc_record_name
   oOo0oooo = blue ( OooO0ooO0o0OO . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( oOo0oooo ) )
   if 98 - 98: I1IiiI % OOooOOo % iII111i
  if ( self . set_geo_name ) :
   OooO0ooO0o0OO . geo_name = self . set_geo_name
   oOo0oooo = OooO0ooO0o0OO . geo_name
   iIiii1 = "" if lisp_geo_list . has_key ( oOo0oooo ) else "(not configured)"
   if 23 - 23: i11iIiiIii % OoO0O00 - o0oOOo0O0Ooo + OoooooooOO
   lprint ( "Policy set-geo-name '{}' {}" . format ( oOo0oooo , iIiii1 ) )
   if 12 - 12: Ii1I / I1IiiI . oO0o . I1IiiI + ooOoO0o - II111iiii
  if ( self . set_elp_name ) :
   OooO0ooO0o0OO . elp_name = self . set_elp_name
   oOo0oooo = OooO0ooO0o0OO . elp_name
   iIiii1 = "" if lisp_elp_list . has_key ( oOo0oooo ) else "(not configured)"
   if 6 - 6: Oo0Ooo + Oo0Ooo - OoOoOO00 - II111iiii
   lprint ( "Policy set-elp-name '{}' {}" . format ( oOo0oooo , iIiii1 ) )
   if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
  if ( self . set_rle_name ) :
   OooO0ooO0o0OO . rle_name = self . set_rle_name
   oOo0oooo = OooO0ooO0o0OO . rle_name
   iIiii1 = "" if lisp_rle_list . has_key ( oOo0oooo ) else "(not configured)"
   if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
   lprint ( "Policy set-rle-name '{}' {}" . format ( oOo0oooo , iIiii1 ) )
   if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
  if ( self . set_json_name ) :
   OooO0ooO0o0OO . json_name = self . set_json_name
   oOo0oooo = OooO0ooO0o0OO . json_name
   iIiii1 = "" if lisp_json_list . has_key ( oOo0oooo ) else "(not configured)"
   if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
   lprint ( "Policy set-json-name '{}' {}" . format ( oOo0oooo , iIiii1 ) )
   if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
  return ( OooO0ooO0o0OO )
  if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
  if 92 - 92: I11i
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
  if 98 - 98: iII111i % IiII + OoO0O00
  if 23 - 23: OOooOOo
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
  if 99 - 99: II111iiii + O0
 def add ( self , eid_prefix ) :
  oo0OOoOO0 = self . ttl
  I111o0oooO00o0 = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( I111o0oooO00o0 ) == False ) :
   lisp_pubsub_cache [ I111o0oooO00o0 ] = { }
   if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
  OooOooOO0000 = lisp_pubsub_cache [ I111o0oooO00o0 ]
  if 88 - 88: Oo0Ooo . iII111i
  O000Oo = "Add"
  if ( OooOooOO0000 . has_key ( self . xtr_id ) ) :
   O000Oo = "Replace"
   del ( OooOooOO0000 [ self . xtr_id ] )
   if 22 - 22: Oo0Ooo + O0 + OoO0O00
  OooOooOO0000 [ self . xtr_id ] = self
  if 83 - 83: i1IIi + OoooooooOO * IiII
  I111o0oooO00o0 = green ( I111o0oooO00o0 , False )
  oo0O0oO0o = red ( self . itr . print_address_no_iid ( ) , False )
  oOo0 = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( O000Oo , I111o0oooO00o0 ,
 oo0O0oO0o , oOo0 , oo0OOoOO0 ) )
  if 65 - 65: II111iiii / I1Ii111 + I1IiiI - OoooooooOO + ooOoO0o - I1ii11iIi11i
  if 29 - 29: OoOoOO00 / OOooOOo / OoO0O00
 def delete ( self , eid_prefix ) :
  I111o0oooO00o0 = eid_prefix . print_prefix ( )
  oo0O0oO0o = red ( self . itr . print_address_no_iid ( ) , False )
  oOo0 = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( I111o0oooO00o0 ) ) :
   OooOooOO0000 = lisp_pubsub_cache [ I111o0oooO00o0 ]
   if ( OooOooOO0000 . has_key ( self . xtr_id ) ) :
    OooOooOO0000 . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( I111o0oooO00o0 ,
 oo0O0oO0o , oOo0 ) )
    if 95 - 95: ooOoO0o
    if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
    if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
    if 32 - 32: OoOoOO00 % i11iIiiIii
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
    if 23 - 23: Oo0Ooo . OoO0O00
    if 49 - 49: oO0o % i11iIiiIii * Ii1I
    if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
    if 61 - 61: O0 - i11iIiiIii * o0oOOo0O0Ooo
    if 92 - 92: Oo0Ooo + OOooOOo - i11iIiiIii
    if 26 - 26: O0 % Oo0Ooo + ooOoO0o - Ii1I . Oo0Ooo
class lisp_trace ( ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 33 - 33: I1Ii111 / iII111i . I1Ii111 % II111iiii
  if 52 - 52: I1ii11iIi11i
 def print_trace ( self ) :
  Ii1I1II = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( Ii1I1II ) )
  if 100 - 100: OoooooooOO * i1IIi % iII111i + I1ii11iIi11i - iIii1I11I1II1
  if 57 - 57: Ii1I % iII111i
 def encode ( self ) :
  i1IiIiiiii11 = socket . htonl ( 0x90000000 )
  ii1i1II = struct . pack ( "II" , i1IiIiiiii11 , 0 )
  ii1i1II += struct . pack ( "Q" , self . nonce )
  ii1i1II += json . dumps ( self . packet_json )
  return ( ii1i1II )
  if 69 - 69: I1Ii111 * oO0o * I1IiiI
  if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
 def decode ( self , packet ) :
  o00OooooOOOO = "I"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( False )
  i1IiIiiiii11 = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] ) [ 0 ]
  packet = packet [ oO0o00O : : ]
  i1IiIiiiii11 = socket . ntohl ( i1IiIiiiii11 )
  if ( ( i1IiIiiiii11 & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
  if ( len ( packet ) < oO0o00O ) : return ( False )
  O0o00o000oO = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] ) [ 0 ]
  packet = packet [ oO0o00O : : ]
  if 52 - 52: OoooooooOO
  O0o00o000oO = socket . ntohl ( O0o00o000oO )
  IiIi = O0o00o000oO >> 24
  OOOoOOO0 = ( O0o00o000oO >> 16 ) & 0xff
  o00iIIiii1iiII1i = ( O0o00o000oO >> 8 ) & 0xff
  Ii11Ii1IiiIi = O0o00o000oO & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( IiIi , OOOoOOO0 , o00iIIiii1iiII1i , Ii11Ii1IiiIi )
  self . local_port = str ( i1IiIiiiii11 & 0xffff )
  if 89 - 89: iIii1I11I1II1 / O0
  o00OooooOOOO = "Q"
  oO0o00O = struct . calcsize ( o00OooooOOOO )
  if ( len ( packet ) < oO0o00O ) : return ( False )
  self . nonce = struct . unpack ( o00OooooOOOO , packet [ : oO0o00O ] ) [ 0 ]
  packet = packet [ oO0o00O : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 64 - 64: OoooooooOO + Ii1I - Ii1I
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 67 - 67: II111iiii . Ii1I + I1IiiI
  return ( True )
  if 77 - 77: O0 % I1ii11iIi11i + i11iIiiIii . OOooOOo % o0oOOo0O0Ooo + OoO0O00
  if 31 - 31: ooOoO0o * I1ii11iIi11i
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 23 - 23: OoOoOO00 - I11i . iIii1I11I1II1
  if 87 - 87: OoO0O00 - i11iIiiIii / O0 % OOooOOo % OOooOOo * i1IIi
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  OooO0ooO0o0OO , IIi1I1iII111 = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( OooO0ooO0o0OO == None ) :
   OooO0ooO0o0OO , IIi1I1iII111 = rts_rloc . split ( ":" )
   IIi1I1iII111 = int ( IIi1I1iII111 )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( OooO0ooO0o0OO , IIi1I1iII111 ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( OooO0ooO0o0OO ,
 IIi1I1iII111 ) )
   if 18 - 18: IiII
   if 50 - 50: i1IIi / o0oOOo0O0Ooo * OoO0O00
  if ( lisp_socket == None ) :
   o0 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   o0 . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   o0 . sendto ( packet , ( OooO0ooO0o0OO , IIi1I1iII111 ) )
   o0 . close ( )
  else :
   lisp_socket . sendto ( packet , ( OooO0ooO0o0OO , IIi1I1iII111 ) )
   if 98 - 98: I11i . II111iiii
   if 13 - 13: oO0o - I11i % II111iiii
   if 30 - 30: ooOoO0o / O0 . I11i + I1ii11iIi11i % O0 . I1IiiI
 def packet_length ( self ) :
  O0OO0ooO00 = 8 ; iIi111I1 = 4 + 4 + 8
  return ( O0OO0ooO00 + iIi111I1 + len ( json . dumps ( self . packet_json ) ) )
  if 98 - 98: o0oOOo0O0Ooo % O0 - i11iIiiIii
  if 49 - 49: o0oOOo0O0Ooo / OoOoOO00 + iII111i
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  iII1 = self . local_rloc + ":" + self . local_port
  Oooo0oOOO0 = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ iII1 ] = Oooo0oOOO0
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( iII1 , Oooo0oOOO0 ) )
  if 85 - 85: I1IiiI - o0oOOo0O0Ooo
  if 86 - 86: II111iiii + Ii1I * Ii1I
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  iII1 = local_rloc_and_port
  try : Oooo0oOOO0 = lisp_rtr_nat_trace_cache [ iII1 ]
  except : Oooo0oOOO0 = ( None , None )
  return ( Oooo0oOOO0 )
  if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
  if 86 - 86: Ii1I
  if 69 - 69: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
  if 1 - 1: Ii1I
  if 43 - 43: o0oOOo0O0Ooo
  if 78 - 78: I1Ii111 % i1IIi * I11i
  if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
  if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
  if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
  if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
  if 32 - 32: OoooooooOO . I1Ii111 - I1ii11iIi11i
def lisp_get_map_server ( address ) :
 for Ii1IIII in lisp_map_servers_list . values ( ) :
  if ( Ii1IIII . map_server . is_exact_match ( address ) ) : return ( Ii1IIII )
  if 29 - 29: OoO0O00
 return ( None )
 if 33 - 33: I1ii11iIi11i - O0
 if 72 - 72: Oo0Ooo * iII111i - I11i
 if 81 - 81: I1Ii111
 if 85 - 85: O0 % OoOoOO00 . I1ii11iIi11i
 if 46 - 46: OOooOOo * iIii1I11I1II1
 if 33 - 33: OoO0O00 * II111iiii / i1IIi
 if 93 - 93: I1Ii111 % I11i
def lisp_get_any_map_server ( ) :
 for Ii1IIII in lisp_map_servers_list . values ( ) : return ( Ii1IIII )
 return ( None )
 if 64 - 64: I1IiiI % OoOoOO00 / Oo0Ooo
 if 40 - 40: Ii1I + iIii1I11I1II1 / oO0o . II111iiii % O0 - IiII
 if 49 - 49: IiII - OOooOOo * OOooOOo . O0
 if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
 if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
 if 61 - 61: OoO0O00
 if 100 - 100: OoOoOO00
 if 97 - 97: OoooooooOO
 if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
 if 35 - 35: iII111i % OoO0O00 * O0
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  O0o00o000oO = address . print_address ( )
  ii1 = None
  for iII1 in lisp_map_resolvers_list :
   if ( iII1 . find ( O0o00o000oO ) == - 1 ) : continue
   ii1 = lisp_map_resolvers_list [ iII1 ]
   if 37 - 37: OOooOOo
  return ( ii1 )
  if 100 - 100: Oo0Ooo * I1IiiI . ooOoO0o
  if 53 - 53: OOooOOo + o0oOOo0O0Ooo * Ii1I + O0
  if 75 - 75: OoooooooOO
  if 24 - 24: I1Ii111 % i11iIiiIii % oO0o . OOooOOo % IiII
  if 23 - 23: o0oOOo0O0Ooo * II111iiii - Oo0Ooo - I1IiiI
  if 86 - 86: I1IiiI - II111iiii * II111iiii * oO0o % OoooooooOO * OoOoOO00
  if 93 - 93: I1IiiI + OoO0O00 % O0 - ooOoO0o * i1IIi
 if ( eid == "" ) :
  oo000i1I1IIiiIi1 = ""
 elif ( eid == None ) :
  oo000i1I1IIiiIi1 = "all"
 else :
  o00o0oOo0o0O = lisp_db_for_lookups . lookup_cache ( eid , False )
  oo000i1I1IIiiIi1 = "all" if o00o0oOo0o0O == None else o00o0oOo0o0O . use_mr_name
  if 3 - 3: i1IIi % oO0o
  if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
 I1Iii = None
 for ii1 in lisp_map_resolvers_list . values ( ) :
  if ( oo000i1I1IIiiIi1 == "" ) : return ( ii1 )
  if ( ii1 . mr_name != oo000i1I1IIiiIi1 ) : continue
  if ( I1Iii == None or ii1 . last_used < I1Iii . last_used ) : I1Iii = ii1
  if 5 - 5: II111iiii
 return ( I1Iii )
 if 100 - 100: O0 * iIii1I11I1II1 - OoooooooOO
 if 41 - 41: OoO0O00 / OoooooooOO
 if 61 - 61: ooOoO0o
 if 4 - 4: Oo0Ooo + oO0o + oO0o
 if 79 - 79: OoooooooOO
 if 98 - 98: O0 . ooOoO0o * I1Ii111
 if 98 - 98: ooOoO0o + o0oOOo0O0Ooo / I11i - Ii1I * II111iiii + i1IIi
 if 10 - 10: oO0o
def lisp_get_decent_map_resolver ( eid ) :
 OO000o00 = lisp_get_decent_index ( eid )
 II11Iii11III = str ( OO000o00 ) + "." + lisp_decent_dns_suffix
 if 33 - 33: Oo0Ooo % iIii1I11I1II1 - OoO0O00 - i1IIi / o0oOOo0O0Ooo
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( II11Iii11III , False ) , eid . print_prefix ( ) ) )
 if 6 - 6: Oo0Ooo . IiII . IiII * Ii1I
 if 1 - 1: i11iIiiIii
 I1Iii = None
 for ii1 in lisp_map_resolvers_list . values ( ) :
  if ( II11Iii11III != ii1 . dns_name ) : continue
  if ( I1Iii == None or ii1 . last_used < I1Iii . last_used ) : I1Iii = ii1
  if 91 - 91: I1ii11iIi11i . OoO0O00 / OoO0O00 / I1ii11iIi11i + iII111i
 return ( I1Iii )
 if 20 - 20: o0oOOo0O0Ooo . I1Ii111 + O0
 if 99 - 99: O0 / IiII . oO0o
 if 18 - 18: OoooooooOO * OoO0O00 * I1Ii111
 if 12 - 12: i11iIiiIii / iIii1I11I1II1 . I11i % I1Ii111 * ooOoO0o % ooOoO0o
 if 13 - 13: i1IIi . ooOoO0o . ooOoO0o
 if 24 - 24: iIii1I11I1II1
 if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
def lisp_ipv4_input ( packet ) :
 if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
 if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
 if 62 - 62: o0oOOo0O0Ooo
 if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
 if ( ord ( packet [ 9 ] ) == 2 ) : return ( [ True , packet ] )
 if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
 if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
 if 84 - 84: OoOoOO00
 if 80 - 80: oO0o
 i1I1iI = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
 if ( i1I1iI == 0 ) :
  dprint ( "Packet arrived with checksum of 0!" )
 else :
  packet = lisp_ip_checksum ( packet )
  i1I1iI = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
  if ( i1I1iI != 0 ) :
   dprint ( "IPv4 header checksum failed for inner header" )
   packet = lisp_format_packet ( packet [ 0 : 20 ] )
   dprint ( "Packet header: {}" . format ( packet ) )
   return ( [ False , None ] )
   if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
   if 92 - 92: iII111i
   if 96 - 96: OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
   if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
   if 92 - 92: I1Ii111 - IiII / IiII
   if 42 - 42: IiII
   if 7 - 7: iIii1I11I1II1
 oo0OOoOO0 = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( oo0OOoOO0 == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( oo0OOoOO0 == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 35 - 35: IiII + O0 % I1Ii111 - I1ii11iIi11i - i1IIi
  return ( [ False , None ] )
  if 100 - 100: I1Ii111 + i11iIiiIii - IiII / I1ii11iIi11i / iII111i
  if 56 - 56: iII111i
 oo0OOoOO0 -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , oo0OOoOO0 ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( [ False , packet ] )
 if 91 - 91: Oo0Ooo . I11i . I1ii11iIi11i
 if 60 - 60: i11iIiiIii - OOooOOo
 if 78 - 78: I1IiiI * ooOoO0o % iIii1I11I1II1 / I1ii11iIi11i
 if 61 - 61: I1Ii111 . Ii1I + OoooooooOO
 if 98 - 98: OOooOOo . ooOoO0o . OoOoOO00 - I1Ii111 . i1IIi - iIii1I11I1II1
 if 89 - 89: II111iiii * I1ii11iIi11i - I1IiiI
 if 58 - 58: Ii1I / Oo0Ooo % IiII
def lisp_ipv6_input ( packet ) :
 oO00o0oOoo = packet . inner_dest
 packet = packet . packet
 if 33 - 33: II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % i11iIiiIii
 if 60 - 60: iII111i . o0oOOo0O0Ooo
 if 56 - 56: I1ii11iIi11i
 if 89 - 89: Oo0Ooo + I1ii11iIi11i * o0oOOo0O0Ooo * oO0o % O0 % OoO0O00
 if 70 - 70: o0oOOo0O0Ooo + O0 % I1IiiI
 oo0OOoOO0 = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( oo0OOoOO0 == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( oo0OOoOO0 == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 56 - 56: Ii1I
  return ( None )
  if 84 - 84: iII111i
  if 21 - 21: i11iIiiIii
  if 30 - 30: OoO0O00 + OoooooooOO
  if 98 - 98: I1ii11iIi11i % I1IiiI
  if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
 if ( oO00o0oOoo . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 66 - 66: IiII
  if 56 - 56: oO0o + OoooooooOO
 oo0OOoOO0 -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , oo0OOoOO0 ) + packet [ 8 : : ]
 return ( packet )
 if 75 - 75: O0 % Ii1I
 if 47 - 47: OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
 if 23 - 23: iII111i / iIii1I11I1II1
 if 5 - 5: O0
 if 64 - 64: i1IIi * i1IIi . iII111i - O0 - oO0o % OoooooooOO
 if 14 - 14: Ii1I % OoO0O00 % I1Ii111 * O0
 if 8 - 8: I1IiiI - i11iIiiIii * I1IiiI
 if 6 - 6: O0 - OoOoOO00 - i11iIiiIii / iII111i
def lisp_mac_input ( packet ) :
 return ( packet )
 if 63 - 63: OOooOOo
 if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
 if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
 if 96 - 96: iIii1I11I1II1 * II111iiii . iIii1I11I1II1
 if 13 - 13: Ii1I - OoOoOO00 . Ii1I
 if 7 - 7: Ii1I - I11i / I1ii11iIi11i + iII111i
 if 47 - 47: I11i * IiII / oO0o - OoooooooOO . OoooooooOO / I11i
 if 73 - 73: Ii1I . IiII % IiII
 if 56 - 56: I1Ii111 + iII111i + iII111i
def lisp_rate_limit_map_request ( source , dest ) :
 if ( lisp_last_map_request_sent == None ) : return ( False )
 iIiooo = lisp_get_timestamp ( )
 o0O0oO0 = iIiooo - lisp_last_map_request_sent
 OOoOoOOo0O = ( o0O0oO0 < LISP_MAP_REQUEST_RATE_LIMIT )
 if 46 - 46: OoO0O00 * I1Ii111 . O0
 if ( OOoOoOOo0O ) :
  if ( source != None ) : source = source . print_address ( )
  dest = dest . print_address ( )
  dprint ( "Rate-limiting Map-Request for {} -> {}" . format ( source , dest ) )
  if 86 - 86: i11iIiiIii . Ii1I / OoOoOO00 / I11i * i1IIi
 return ( OOoOoOOo0O )
 if 40 - 40: o0oOOo0O0Ooo
 if 33 - 33: i11iIiiIii + I1Ii111 % I1ii11iIi11i - I1Ii111 * OoO0O00
 if 1 - 1: II111iiii / I1IiiI + II111iiii % II111iiii - I1Ii111
 if 24 - 24: I11i / Oo0Ooo / i1IIi + IiII
 if 10 - 10: I11i - IiII / II111iiii / oO0o % O0 / I1Ii111
 if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
 if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ) :
 global lisp_last_map_request_sent
 if 45 - 45: OOooOOo - OOooOOo % iII111i - IiII . O0
 if 6 - 6: iIii1I11I1II1 * II111iiii / O0 % IiII - I1Ii111
 if 64 - 64: ooOoO0o
 if 28 - 28: i11iIiiIii - IiII * I1ii11iIi11i + IiII * iII111i
 if 75 - 75: o0oOOo0O0Ooo * OoOoOO00 % I1ii11iIi11i + OOooOOo . II111iiii
 if 12 - 12: ooOoO0o
 o0O0oOO0o0 = i1iIi1IIIiI1 = None
 if ( rloc ) :
  o0O0oOO0o0 = rloc . rloc
  i1iIi1IIIiI1 = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 5 - 5: OoO0O00 / I1Ii111
  if 78 - 78: OoOoOO00 / IiII
  if 92 - 92: OoOoOO00 / I11i / I1Ii111
  if 2 - 2: IiII - iIii1I11I1II1
  if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
 I1I1I1i1II1 , i1iI1IIIi1iIii1 , OO0oo00oOO = lisp_myrlocs
 if ( I1I1I1i1II1 == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 64 - 64: OoOoOO00
 if ( i1iI1IIIi1iIii1 == None and o0O0oOO0o0 != None and o0O0oOO0o0 . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
  if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
 oOOooOoo0O = lisp_map_request ( )
 oOOooOoo0O . record_count = 1
 oOOooOoo0O . nonce = lisp_get_control_nonce ( )
 oOOooOoo0O . rloc_probe = ( o0O0oOO0o0 != None )
 if 71 - 71: ooOoO0o
 if 35 - 35: OoOoOO00
 if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
 if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
 if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
 if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
 if 89 - 89: iIii1I11I1II1 . ooOoO0o
 if ( rloc ) : rloc . last_rloc_probe_nonce = oOOooOoo0O . nonce
 if 82 - 82: OoOoOO00 - II111iiii . OoO0O00 * ooOoO0o
 o0000o0o = deid . is_multicast_address ( )
 if ( o0000o0o ) :
  oOOooOoo0O . target_eid = seid
  oOOooOoo0O . target_group = deid
 else :
  oOOooOoo0O . target_eid = deid
  if 78 - 78: OoOoOO00 % oO0o
  if 39 - 39: iIii1I11I1II1
  if 72 - 72: II111iiii + I1Ii111 / Ii1I * iIii1I11I1II1
  if 95 - 95: OoooooooOO + OOooOOo + II111iiii + IiII + OoO0O00
  if 86 - 86: II111iiii / iII111i - I1ii11iIi11i
  if 65 - 65: I1ii11iIi11i + OoOoOO00
  if 43 - 43: O0 + I11i % II111iiii
  if 56 - 56: IiII + Oo0Ooo . IiII % iIii1I11I1II1 % ooOoO0o % ooOoO0o
  if 70 - 70: ooOoO0o / i1IIi - I11i - i11iIiiIii
 if ( oOOooOoo0O . rloc_probe == False ) :
  o00o0oOo0o0O = lisp_get_signature_eid ( )
  if ( o00o0oOo0o0O ) :
   oOOooOoo0O . signature_eid . copy_address ( o00o0oOo0o0O . eid )
   oOOooOoo0O . privkey_filename = "./lisp-sig.pem"
   if 79 - 79: OoO0O00 - OoooooooOO % iII111i . O0
   if 93 - 93: I1Ii111
   if 3 - 3: OoO0O00 / IiII - oO0o / oO0o
   if 50 - 50: II111iiii + OoOoOO00
   if 17 - 17: ooOoO0o + I1ii11iIi11i
   if 34 - 34: Ii1I / II111iiii + OoOoOO00 . II111iiii + OoooooooOO * o0oOOo0O0Ooo
 if ( seid == None or o0000o0o ) :
  oOOooOoo0O . source_eid . afi = LISP_AFI_NONE
 else :
  oOOooOoo0O . source_eid = seid
  if 48 - 48: O0
  if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
  if 84 - 84: i11iIiiIii . OoooooooOO
  if 69 - 69: I1Ii111 * II111iiii % I1Ii111 * i11iIiiIii . ooOoO0o / Oo0Ooo
  if 5 - 5: Ii1I
  if 19 - 19: oO0o
  if 61 - 61: OoOoOO00 + iIii1I11I1II1 / I1ii11iIi11i - i1IIi
  if 11 - 11: oO0o * o0oOOo0O0Ooo . I1IiiI
  if 12 - 12: I1IiiI % OoO0O00 / I1Ii111 / O0 % o0oOOo0O0Ooo
  if 1 - 1: OoOoOO00 / I11i
  if 43 - 43: o0oOOo0O0Ooo - i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
  if 69 - 69: i11iIiiIii - iIii1I11I1II1
 if ( o0O0oOO0o0 != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( o0O0oOO0o0 . is_private_address ( ) == False ) :
   I1I1I1i1II1 = lisp_get_any_translated_rloc ( )
   if 40 - 40: I1IiiI / oO0o + ooOoO0o
  if ( I1I1I1i1II1 == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
   if 37 - 37: I1ii11iIi11i
   if 24 - 24: O0 . I1Ii111 * i11iIiiIii
   if 84 - 84: ooOoO0o / I1ii11iIi11i - o0oOOo0O0Ooo . OoooooooOO * iIii1I11I1II1
   if 16 - 16: I11i % O0
   if 56 - 56: Ii1I * OoOoOO00 . i1IIi
   if 15 - 15: I1Ii111
   if 64 - 64: OOooOOo * Oo0Ooo
 if ( o0O0oOO0o0 == None or o0O0oOO0o0 . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and o0O0oOO0o0 == None ) :
   OO0O = lisp_get_any_translated_rloc ( )
   if ( OO0O != None ) : I1I1I1i1II1 = OO0O
   if 28 - 28: iII111i
  oOOooOoo0O . itr_rlocs . append ( I1I1I1i1II1 )
  if 18 - 18: I1Ii111
 if ( o0O0oOO0o0 == None or o0O0oOO0o0 . is_ipv6 ( ) ) :
  if ( i1iI1IIIi1iIii1 == None or i1iI1IIIi1iIii1 . is_ipv6_link_local ( ) ) :
   i1iI1IIIi1iIii1 = None
  else :
   oOOooOoo0O . itr_rloc_count = 1 if ( o0O0oOO0o0 == None ) else 0
   oOOooOoo0O . itr_rlocs . append ( i1iI1IIIi1iIii1 )
   if 29 - 29: i1IIi - I1IiiI / i1IIi
   if 64 - 64: IiII
   if 69 - 69: OOooOOo . I1IiiI
   if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
   if 22 - 22: iII111i % I11i % O0 - I11i
   if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
   if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
   if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
   if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
 if ( o0O0oOO0o0 != None and oOOooOoo0O . itr_rlocs != [ ] ) :
  O00o00O0OO0 = oOOooOoo0O . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   O00o00O0OO0 = I1I1I1i1II1
  elif ( deid . is_ipv6 ( ) ) :
   O00o00O0OO0 = i1iI1IIIi1iIii1
  else :
   O00o00O0OO0 = I1I1I1i1II1
   if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
   if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
   if 97 - 97: iIii1I11I1II1 * I1Ii111
   if 39 - 39: I1Ii111 . II111iiii
   if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
   if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
 ii1i1II = oOOooOoo0O . encode ( o0O0oOO0o0 , i1iIi1IIIiI1 )
 oOOooOoo0O . print_map_request ( )
 if 34 - 34: I1IiiI
 if 56 - 56: Ii1I
 if 71 - 71: O0 / i1IIi
 if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
 if 82 - 82: oO0o * i11iIiiIii % o0oOOo0O0Ooo % IiII - I11i - OoO0O00
 if 24 - 24: oO0o . II111iiii + OoO0O00 * I1ii11iIi11i / oO0o
 if ( o0O0oOO0o0 != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   oOOo0O0O = lisp_get_nat_info ( o0O0oOO0o0 , rloc . rloc_name )
   if 86 - 86: I1Ii111 + I1ii11iIi11i
   if 63 - 63: ooOoO0o - i11iIiiIii . o0oOOo0O0Ooo - i1IIi - IiII
   if 32 - 32: I1Ii111 / iIii1I11I1II1 + oO0o % I11i * OoooooooOO
   if 69 - 69: OOooOOo
   if ( oOOo0O0O == None ) :
    O0OooO0oo = rloc . rloc . print_address_no_iid ( )
    II1IIiIiiI1iI = "gleaned-{}" . format ( O0OooO0oo )
    iIiiI11II11 = rloc . translated_port
    oOOo0O0O = lisp_nat_info ( O0OooO0oo , II1IIiIiiI1iI , iIiiI11II11 )
    if 9 - 9: i11iIiiIii * Oo0Ooo
   lisp_encapsulate_rloc_probe ( lisp_sockets , o0O0oOO0o0 , oOOo0O0O ,
 ii1i1II )
   return
   if 33 - 33: oO0o / ooOoO0o
   if 92 - 92: O0 . Oo0Ooo - Ii1I * I1IiiI * Oo0Ooo * iII111i
  oOo0O = o0O0oOO0o0 . print_address_no_iid ( )
  oO00o0oOoo = lisp_convert_4to6 ( oOo0O )
  lisp_send ( lisp_sockets , oO00o0oOoo , LISP_CTRL_PORT , ii1i1II )
  return
  if 78 - 78: Ii1I * iIii1I11I1II1 - Ii1I - I1ii11iIi11i * I1ii11iIi11i
  if 44 - 44: o0oOOo0O0Ooo
  if 1 - 1: OoooooooOO / i11iIiiIii . o0oOOo0O0Ooo
  if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
  if 12 - 12: Oo0Ooo . o0oOOo0O0Ooo - i1IIi - oO0o % IiII . I11i
  if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
 oo00ooOo = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  ii1 = lisp_get_decent_map_resolver ( deid )
 else :
  ii1 = lisp_get_map_resolver ( None , oo00ooOo )
  if 92 - 92: I1ii11iIi11i * I1IiiI % i11iIiiIii + oO0o * I1ii11iIi11i % OOooOOo
 if ( ii1 == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 96 - 96: I1Ii111 + i1IIi % O0 * I1IiiI * I11i . Ii1I
  return
  if 71 - 71: i1IIi . I1IiiI
 ii1 . last_used = lisp_get_timestamp ( )
 ii1 . map_requests_sent += 1
 if ( ii1 . last_nonce == 0 ) : ii1 . last_nonce = oOOooOoo0O . nonce
 if 81 - 81: O0
 if 89 - 89: oO0o % OoOoOO00 + Oo0Ooo
 if 16 - 16: Ii1I . I1Ii111
 if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
 if ( seid == None ) : seid = O00o00O0OO0
 lisp_send_ecm ( lisp_sockets , ii1i1II , seid , lisp_ephem_port , deid ,
 ii1 . map_resolver )
 if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
 if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
 if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
 if 11 - 11: I1IiiI
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
 if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
 if 91 - 91: OoO0O00
 if 8 - 8: oO0o
 ii1 . resolve_dns_name ( )
 return
 if 96 - 96: IiII
 if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
 if 26 - 26: o0oOOo0O0Ooo . i1IIi
 if 62 - 62: IiII * I1ii11iIi11i % iIii1I11I1II1 / II111iiii - OoO0O00
 if 52 - 52: iII111i . I11i - I11i + oO0o + iIii1I11I1II1
 if 83 - 83: I11i * iIii1I11I1II1 + OoOoOO00
 if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
 if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 100 - 100: II111iiii / Oo0Ooo / iII111i / OOooOOo
 if 100 - 100: iIii1I11I1II1
 if 50 - 50: I1Ii111 / ooOoO0o * I11i
 if 53 - 53: II111iiii . IiII
 ii1iII111i = lisp_info ( )
 ii1iII111i . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : ii1iII111i . hostname += "-" + device_name
 if 80 - 80: IiII - i11iIiiIii % I11i
 oOo0O = dest . print_address_no_iid ( )
 if 5 - 5: OoooooooOO
 if 5 - 5: iII111i + oO0o % O0 . OoooooooOO + i1IIi
 if 55 - 55: I1ii11iIi11i
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
 iiIIiI11I = False
 if ( device_name ) :
  Ii1iIiIiIIIiI = lisp_get_host_route_next_hop ( oOo0O )
  if 14 - 14: OoO0O00 * I1IiiI
  if 78 - 78: I1IiiI / iII111i - ooOoO0o - i11iIiiIii
  if 39 - 39: i11iIiiIii / oO0o
  if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
  if 87 - 87: I1IiiI / Ii1I
  if 54 - 54: OoooooooOO / Ii1I
  if 26 - 26: o0oOOo0O0Ooo + OoO0O00
  if 59 - 59: Ii1I * IiII
  if 64 - 64: ooOoO0o . Oo0Ooo - OoOoOO00
  if ( port == LISP_CTRL_PORT and Ii1iIiIiIIIiI != None ) :
   while ( True ) :
    time . sleep ( .01 )
    Ii1iIiIiIIIiI = lisp_get_host_route_next_hop ( oOo0O )
    if ( Ii1iIiIiIIIiI == None ) : break
    if 66 - 66: OoOoOO00
    if 83 - 83: OOooOOo . IiII
    if 98 - 98: i11iIiiIii
  OoOoo0Ooo0O0o = lisp_get_default_route_next_hops ( )
  for OO0oo00oOO , I1ii1I1II11II in OoOoo0Ooo0O0o :
   if ( OO0oo00oOO != device_name ) : continue
   if 48 - 48: oO0o + i11iIiiIii % i11iIiiIii % i11iIiiIii % OOooOOo * I11i
   if 63 - 63: OoO0O00 % OoO0O00 % OOooOOo - i11iIiiIii + Oo0Ooo + iIii1I11I1II1
   if 44 - 44: OoO0O00
   if 59 - 59: iII111i
   if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
   if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
   if ( Ii1iIiIiIIIiI != I1ii1I1II11II ) :
    if ( Ii1iIiIiIIIiI != None ) :
     lisp_install_host_route ( oOo0O , Ii1iIiIiIIIiI , False )
     if 65 - 65: I1Ii111 + OOooOOo
    lisp_install_host_route ( oOo0O , I1ii1I1II11II , True )
    iiIIiI11I = True
    if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
   break
   if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
   if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
   if 77 - 77: ooOoO0o % I1IiiI
   if 26 - 26: o0oOOo0O0Ooo
   if 72 - 72: I1IiiI
   if 90 - 90: ooOoO0o
 ii1i1II = ii1iII111i . encode ( )
 ii1iII111i . print_info ( )
 if 67 - 67: iIii1I11I1II1 + i1IIi * I1IiiI * OoooooooOO
 if 23 - 23: IiII
 if 32 - 32: OoOoOO00 - iII111i % oO0o / I1ii11iIi11i - o0oOOo0O0Ooo
 if 52 - 52: Ii1I / OoooooooOO % i11iIiiIii + iII111i
 O0oOO = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 O0oOO = bold ( O0oOO , False )
 iIiiI11II11 = bold ( "{}" . format ( port ) , False )
 O0o00O0Oo0 = red ( oOo0O , False )
 O0O0 = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( O0O0 , O0o00O0Oo0 , iIiiI11II11 , O0oOO ) )
 if 65 - 65: OOooOOo * o0oOOo0O0Ooo - I1Ii111 % O0 / I1ii11iIi11i + O0
 if 97 - 97: II111iiii + i11iIiiIii + OoooooooOO . iII111i
 if 11 - 11: IiII + iII111i + o0oOOo0O0Ooo % iIii1I11I1II1
 if 58 - 58: iIii1I11I1II1 . o0oOOo0O0Ooo / Ii1I . i11iIiiIii - IiII
 if 25 - 25: iII111i - OoOoOO00
 if 37 - 37: OoOoOO00 % o0oOOo0O0Ooo . oO0o % i11iIiiIii
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , ii1i1II )
 else :
  iIIIIII = lisp_data_header ( )
  iIIIIII . instance_id ( 0xffffff )
  iIIIIII = iIIIIII . encode ( )
  if ( iIIIIII ) :
   ii1i1II = iIIIIII + ii1i1II
   if 42 - 42: OOooOOo - IiII + ooOoO0o / O0 * OOooOOo . OoOoOO00
   if 42 - 42: OoO0O00 % oO0o / I1ii11iIi11i
   if 34 - 34: OOooOOo % OoO0O00 - o0oOOo0O0Ooo * iIii1I11I1II1 - I11i / OoooooooOO
   if 87 - 87: I1ii11iIi11i - I1Ii111 / OOooOOo * II111iiii
   if 15 - 15: Ii1I / OoOoOO00 - OoO0O00 - iIii1I11I1II1 + OoOoOO00 - I11i
   if 10 - 10: I1ii11iIi11i
   if 6 - 6: OoO0O00 + OoO0O00 * OOooOOo / IiII % ooOoO0o - I1IiiI
   if 17 - 17: II111iiii
   if 66 - 66: O0 % OoOoOO00 + IiII % I1Ii111
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , ii1i1II )
   if 94 - 94: OoOoOO00 / OoooooooOO % Ii1I * i11iIiiIii
   if 95 - 95: iIii1I11I1II1 % OOooOOo % O0
   if 93 - 93: I1ii11iIi11i
   if 61 - 61: o0oOOo0O0Ooo * ooOoO0o
   if 82 - 82: O0 * O0 % I1IiiI / o0oOOo0O0Ooo
   if 46 - 46: IiII . O0 . I11i % I1ii11iIi11i * oO0o - oO0o
   if 92 - 92: I1IiiI - I1IiiI
 if ( iiIIiI11I ) :
  lisp_install_host_route ( oOo0O , None , False )
  if ( Ii1iIiIiIIIiI != None ) : lisp_install_host_route ( oOo0O , Ii1iIiIiIIIiI , True )
  if 28 - 28: oO0o * iII111i + IiII
 return
 if 73 - 73: OoooooooOO
 if 45 - 45: IiII + I1IiiI * I1Ii111
 if 82 - 82: OOooOOo / I11i % Ii1I * OoOoOO00
 if 88 - 88: o0oOOo0O0Ooo % OoO0O00
 if 30 - 30: II111iiii / Oo0Ooo % Oo0Ooo + O0 / iIii1I11I1II1 . OoO0O00
 if 43 - 43: I1IiiI % OoOoOO00 * O0 + o0oOOo0O0Ooo
 if 97 - 97: iIii1I11I1II1 + O0
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 41 - 41: OoOoOO00 - II111iiii
 if 46 - 46: OOooOOo
 if 73 - 73: iII111i - IiII + II111iiii
 if 58 - 58: Oo0Ooo % I1IiiI
 ii1iII111i = lisp_info ( )
 packet = ii1iII111i . decode ( packet )
 if ( packet == None ) : return
 ii1iII111i . print_info ( )
 if 78 - 78: iII111i / iIii1I11I1II1 * IiII . ooOoO0o / I1Ii111 % I11i
 if 14 - 14: II111iiii % iIii1I11I1II1 - I1IiiI % i11iIiiIii . OOooOOo * I1ii11iIi11i
 if 12 - 12: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . OoOoOO00
 if 73 - 73: I1ii11iIi11i * i1IIi * Oo0Ooo / O0
 if 1 - 1: iII111i * OOooOOo + II111iiii / Ii1I . I1ii11iIi11i
 ii1iII111i . info_reply = True
 ii1iII111i . global_etr_rloc . store_address ( addr_str )
 ii1iII111i . etr_port = sport
 if 61 - 61: oO0o % OoOoOO00 % ooOoO0o . I1Ii111 / OoO0O00
 if 21 - 21: IiII
 if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
 if 52 - 52: II111iiii * o0oOOo0O0Ooo
 if 95 - 95: I1Ii111 - OoooooooOO
 if ( ii1iII111i . hostname != None ) :
  ii1iII111i . private_etr_rloc . afi = LISP_AFI_NAME
  ii1iII111i . private_etr_rloc . store_address ( ii1iII111i . hostname )
  if 99 - 99: OoooooooOO % IiII . I11i + OoooooooOO
  if 57 - 57: Ii1I / I1IiiI * i1IIi
 if ( rtr_list != None ) : ii1iII111i . rtr_list = rtr_list
 packet = ii1iII111i . encode ( )
 ii1iII111i . print_info ( )
 if 21 - 21: I11i . O0 * OoooooooOO + ooOoO0o * oO0o % i11iIiiIii
 if 30 - 30: ooOoO0o * I1Ii111 + OoO0O00
 if 30 - 30: Ii1I / iII111i * Ii1I
 if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
 if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 oO00o0oOoo = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , oO00o0oOoo , sport , packet )
 if 71 - 71: i1IIi % O0 % ooOoO0o
 if 24 - 24: O0
 if 88 - 88: OoooooooOO / Oo0Ooo / oO0o
 if 99 - 99: I1Ii111 % OoOoOO00 % IiII - Ii1I
 if 79 - 79: ooOoO0o + Oo0Ooo
 OOoO0O0Ooo = lisp_info_source ( ii1iII111i . hostname , addr_str , sport )
 OOoO0O0Ooo . cache_address_for_info_source ( )
 return
 if 38 - 38: II111iiii
 if 44 - 44: OOooOOo + i11iIiiIii - I1Ii111 + ooOoO0o
 if 92 - 92: O0 . iIii1I11I1II1 % iIii1I11I1II1 % OoO0O00 - i11iIiiIii - iII111i
 if 76 - 76: OoO0O00 . II111iiii / I1ii11iIi11i
 if 15 - 15: OoOoOO00 . O0 + iII111i + I1IiiI . ooOoO0o + iIii1I11I1II1
 if 2 - 2: I11i
 if 52 - 52: i11iIiiIii / oO0o / IiII
 if 84 - 84: I11i . oO0o + ooOoO0o
def lisp_get_signature_eid ( ) :
 for o00o0oOo0o0O in lisp_db_list :
  if ( o00o0oOo0o0O . signature_eid ) : return ( o00o0oOo0o0O )
  if 75 - 75: I1Ii111
 return ( None )
 if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
 if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
 if 73 - 73: ooOoO0o + O0 - I11i . I1IiiI + OOooOOo
 if 36 - 36: I11i % OoO0O00 * OoOoOO00 - I1Ii111
 if 16 - 16: ooOoO0o % OOooOOo . OoO0O00 % II111iiii . iIii1I11I1II1
 if 21 - 21: oO0o + II111iiii / OoOoOO00 * I11i
 if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
 if 70 - 70: I1IiiI . ooOoO0o / I11i / OoO0O00
def lisp_get_any_translated_port ( ) :
 for o00o0oOo0o0O in lisp_db_list :
  for IiIIIi in o00o0oOo0o0O . rloc_set :
   if ( IiIIIi . translated_rloc . is_null ( ) ) : continue
   return ( IiIIIi . translated_port )
   if 40 - 40: oO0o % iIii1I11I1II1 * iIii1I11I1II1 / Oo0Ooo * OoO0O00
   if 61 - 61: OOooOOo
 return ( None )
 if 80 - 80: I1ii11iIi11i
 if 6 - 6: I1ii11iIi11i + OOooOOo % ooOoO0o
 if 65 - 65: iIii1I11I1II1 % i1IIi / I1IiiI / oO0o % ooOoO0o / I11i
 if 2 - 2: I1ii11iIi11i
 if 90 - 90: II111iiii * I1Ii111 . ooOoO0o - I1ii11iIi11i % I11i * o0oOOo0O0Ooo
 if 85 - 85: iIii1I11I1II1
 if 76 - 76: i11iIiiIii % I1IiiI / I11i
 if 42 - 42: o0oOOo0O0Ooo . I1IiiI + I11i . OoOoOO00 - O0 / Ii1I
 if 66 - 66: IiII + OoOoOO00 + I1IiiI + i1IIi + OoooooooOO % I1IiiI
def lisp_get_any_translated_rloc ( ) :
 for o00o0oOo0o0O in lisp_db_list :
  for IiIIIi in o00o0oOo0o0O . rloc_set :
   if ( IiIIIi . translated_rloc . is_null ( ) ) : continue
   return ( IiIIIi . translated_rloc )
   if 80 - 80: iII111i / O0 % OoooooooOO / Oo0Ooo
   if 75 - 75: ooOoO0o
 return ( None )
 if 72 - 72: oO0o . OoooooooOO % ooOoO0o % OoO0O00 * oO0o * OoO0O00
 if 14 - 14: I11i / I11i
 if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
 if 93 - 93: oO0o / ooOoO0o - I1Ii111
 if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
 if 26 - 26: O0 + Oo0Ooo
 if 30 - 30: IiII
def lisp_get_all_translated_rlocs ( ) :
 i1I1i1Iiiiiii = [ ]
 for o00o0oOo0o0O in lisp_db_list :
  for IiIIIi in o00o0oOo0o0O . rloc_set :
   if ( IiIIIi . is_rloc_translated ( ) == False ) : continue
   O0o00o000oO = IiIIIi . translated_rloc . print_address_no_iid ( )
   i1I1i1Iiiiiii . append ( O0o00o000oO )
   if 19 - 19: Ii1I . I1IiiI - i1IIi * ooOoO0o . iIii1I11I1II1
   if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
 return ( i1I1i1Iiiiiii )
 if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
 if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
 if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
 if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
 if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
 if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
 if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
 if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 iiIII1 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 83 - 83: OOooOOo . ooOoO0o / IiII
 O0O0OOOo0 = { }
 for OooO0ooO0o0OO in rtr_list :
  if ( OooO0ooO0o0OO == None ) : continue
  O0o00o000oO = rtr_list [ OooO0ooO0o0OO ]
  if ( iiIII1 and O0o00o000oO . is_private_address ( ) ) : continue
  O0O0OOOo0 [ OooO0ooO0o0OO ] = O0o00o000oO
  if 73 - 73: O0 - I1IiiI + I1Ii111 . OoOoOO00 . IiII - OOooOOo
 rtr_list = O0O0OOOo0
 if 13 - 13: i11iIiiIii
 IIi1I1Ii = [ ]
 for oO0oO00 in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( oO0oO00 == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 37 - 37: ooOoO0o + OOooOOo / I1IiiI + ooOoO0o + I11i - iII111i
  if 46 - 46: OOooOOo - I11i * iIii1I11I1II1 - I1Ii111 % i11iIiiIii
  if 32 - 32: Oo0Ooo * i1IIi . iII111i . iII111i
  if 77 - 77: OOooOOo
  if 74 - 74: O0
  O000 = lisp_address ( oO0oO00 , "" , 0 , iid )
  O000 . make_default_route ( O000 )
  OoOoooooO00oo = lisp_map_cache . lookup_cache ( O000 , True )
  if ( OoOoooooO00oo ) :
   if ( OoOoooooO00oo . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( OoOoooooO00oo . print_eid_tuple ( ) , False ) ) )
    if 86 - 86: OoOoOO00
   elif ( OoOoooooO00oo . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 4 - 4: OoooooooOO * OoO0O00
   OoOoooooO00oo . delete_cache ( )
   if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
   if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
  IIi1I1Ii . append ( [ O000 , "" ] )
  if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
  if 6 - 6: I1IiiI - OoOoOO00
  if 63 - 63: OOooOOo - oO0o * I1IiiI
  if 60 - 60: II111iiii - Oo0Ooo
  oOoooOOO0o0 = lisp_address ( oO0oO00 , "" , 0 , iid )
  oOoooOOO0o0 . make_default_multicast_route ( oOoooOOO0o0 )
  iII11iIi = lisp_map_cache . lookup_cache ( oOoooOOO0o0 , True )
  if ( iII11iIi ) : iII11iIi = iII11iIi . source_cache . lookup_cache ( O000 , True )
  if ( iII11iIi ) : iII11iIi . delete_cache ( )
  if 94 - 94: i1IIi * O0 * Oo0Ooo . Oo0Ooo
  IIi1I1Ii . append ( [ O000 , oOoooOOO0o0 ] )
  if 27 - 27: Oo0Ooo
 if ( len ( IIi1I1Ii ) == 0 ) : return
 if 94 - 94: i1IIi * ooOoO0o / I1IiiI
 if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
 if 99 - 99: i11iIiiIii - I1ii11iIi11i
 if 64 - 64: IiII . OoOoOO00 . Oo0Ooo . I1Ii111 / I11i / Ii1I
 iio0OOoO0 = [ ]
 for O0O0 in rtr_list :
  Oo0O000OOOO0 = rtr_list [ O0O0 ]
  IiIIIi = lisp_rloc ( )
  IiIIIi . rloc . copy_address ( Oo0O000OOOO0 )
  IiIIIi . priority = 254
  IiIIIi . mpriority = 255
  IiIIIi . rloc_name = "RTR"
  iio0OOoO0 . append ( IiIIIi )
  if 63 - 63: i11iIiiIii / iII111i / o0oOOo0O0Ooo
  if 77 - 77: OoooooooOO % iIii1I11I1II1 - OOooOOo / OoOoOO00
 for O000 in IIi1I1Ii :
  OoOoooooO00oo = lisp_mapping ( O000 [ 0 ] , O000 [ 1 ] , iio0OOoO0 )
  OoOoooooO00oo . mapping_source = map_resolver
  OoOoooooO00oo . map_cache_ttl = LISP_MR_TTL * 60
  OoOoooooO00oo . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( OoOoooooO00oo . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 36 - 36: i1IIi / OoOoOO00 * II111iiii - Oo0Ooo . i1IIi
  iio0OOoO0 = copy . deepcopy ( iio0OOoO0 )
  if 78 - 78: i11iIiiIii
 return
 if 20 - 20: Ii1I
 if 100 - 100: OoooooooOO . I1Ii111
 if 32 - 32: iIii1I11I1II1 . iIii1I11I1II1 % II111iiii / Oo0Ooo . iIii1I11I1II1 . O0
 if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
 if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
 if 87 - 87: I1ii11iIi11i . i1IIi - I11i + OoOoOO00 . O0
 if 37 - 37: IiII
 if 65 - 65: ooOoO0o * Ii1I / I1IiiI . i1IIi % ooOoO0o . OoooooooOO
 if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
 if 88 - 88: i1IIi - OoOoOO00
def lisp_process_info_reply ( source , packet , store ) :
 if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
 if 7 - 7: Ii1I / iIii1I11I1II1
 if 36 - 36: iIii1I11I1II1 % i11iIiiIii
 if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
 ii1iII111i = lisp_info ( )
 packet = ii1iII111i . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
 ii1iII111i . print_info ( )
 if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
 if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
 if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
 if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
 IIIII1IIi11 = False
 for O0O0 in ii1iII111i . rtr_list :
  oOo0O = O0O0 . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( oOo0O ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ oOo0O ] != None ) : continue
   if 81 - 81: I1Ii111 . I1IiiI + O0 * oO0o * Oo0Ooo * iIii1I11I1II1
  IIIII1IIi11 = True
  lisp_rtr_list [ oOo0O ] = O0O0
  if 88 - 88: ooOoO0o * Ii1I + II111iiii - OoO0O00 % Oo0Ooo
  if 94 - 94: i11iIiiIii * I1ii11iIi11i / OoOoOO00 + i1IIi
  if 37 - 37: OOooOOo + O0 - OoOoOO00 + OoO0O00
  if 13 - 13: i11iIiiIii * oO0o
  if 41 - 41: ooOoO0o
 if ( lisp_i_am_itr and IIIII1IIi11 ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for oOo00Ooo0o0 in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( oOo00Ooo0o0 ) , lisp_rtr_list )
    if 89 - 89: i11iIiiIii . i11iIiiIii . IiII
    if 29 - 29: o0oOOo0O0Ooo * iIii1I11I1II1 . iIii1I11I1II1
    if 32 - 32: IiII - OoOoOO00
    if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
    if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
    if 83 - 83: OoO0O00 . I11i * I1ii11iIi11i - II111iiii
    if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
 if ( store == False ) :
  return ( [ ii1iII111i . global_etr_rloc , ii1iII111i . etr_port , IIIII1IIi11 ] )
  if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
  if 16 - 16: Oo0Ooo
  if 24 - 24: o0oOOo0O0Ooo . OoOoOO00
  if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
  if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
  if 96 - 96: I1IiiI . oO0o % O0
 for o00o0oOo0o0O in lisp_db_list :
  for IiIIIi in o00o0oOo0o0O . rloc_set :
   OooO0ooO0o0OO = IiIIIi . rloc
   I1i = IiIIIi . interface
   if ( I1i == None ) :
    if ( OooO0ooO0o0OO . is_null ( ) ) : continue
    if ( OooO0ooO0o0OO . is_local ( ) == False ) : continue
    if ( ii1iII111i . private_etr_rloc . is_null ( ) == False and
 OooO0ooO0o0OO . is_exact_match ( ii1iII111i . private_etr_rloc ) == False ) :
     continue
     if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
   elif ( ii1iII111i . private_etr_rloc . is_dist_name ( ) ) :
    Ooo000oo0OO0 = ii1iII111i . private_etr_rloc . address
    if ( Ooo000oo0OO0 != IiIIIi . rloc_name ) : continue
    if 87 - 87: OoooooooOO
    if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
   iiI1Ii1I = green ( o00o0oOo0o0O . eid . print_prefix ( ) , False )
   ii11IiI = red ( OooO0ooO0o0OO . print_address_no_iid ( ) , False )
   if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
   IIOoOO = ii1iII111i . global_etr_rloc . is_exact_match ( OooO0ooO0o0OO )
   if ( IiIIIi . translated_port == 0 and IIOoOO ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( ii11IiI ,
 I1i , iiI1Ii1I ) )
    continue
    if 94 - 94: i11iIiiIii * i11iIiiIii * I1ii11iIi11i
    if 72 - 72: o0oOOo0O0Ooo * i11iIiiIii - OOooOOo
    if 68 - 68: iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
    if 45 - 45: II111iiii . iII111i
    if 55 - 55: ooOoO0o / iII111i / O0
   ooO0ooO0oO = ii1iII111i . global_etr_rloc
   OOOoIII1I = IiIIIi . translated_rloc
   if ( OOOoIII1I . is_exact_match ( ooO0ooO0oO ) and
 ii1iII111i . etr_port == IiIIIi . translated_port ) : continue
   if 85 - 85: o0oOOo0O0Ooo * IiII
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( ii1iII111i . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # OoooooooOO + i11iIiiIii
 ii1iII111i . etr_port , ii11IiI , I1i , iiI1Ii1I ) )
   if 24 - 24: iII111i
   IiIIIi . store_translated_rloc ( ii1iII111i . global_etr_rloc ,
 ii1iII111i . etr_port )
   if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
   if 36 - 36: O0
 return ( [ ii1iII111i . global_etr_rloc , ii1iII111i . etr_port , IIIII1IIi11 ] )
 if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
 if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
 if 21 - 21: i1IIi * iII111i + OoO0O00
 if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
 if 85 - 85: OoooooooOO
 if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
 if 8 - 8: I1Ii111
 if 86 - 86: ooOoO0o + iII111i * O0 % OoO0O00 + OoOoOO00
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
 I111o0oooO00o0 = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 iiI111I = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 37 - 37: i11iIiiIii + O0 + II111iiii
 if 13 - 13: OOooOOo / O0
 if 19 - 19: iIii1I11I1II1 + IiII * I11i * II111iiii + o0oOOo0O0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 . II111iiii
 I111o0oooO00o0 . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , I111o0oooO00o0 , None )
 I111o0oooO00o0 . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , I111o0oooO00o0 , None )
 if 36 - 36: I1IiiI * i1IIi + OoOoOO00
 if 63 - 63: OoOoOO00 - iII111i
 if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
 if 82 - 82: iIii1I11I1II1 / OOooOOo
 iiI111I . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , iiI111I , None )
 iiI111I . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , iiI111I , None )
 if 7 - 7: OoooooooOO
 if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
 if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
 if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
 I1OoO0OO = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 I1OoO0OO . start ( )
 return
 if 20 - 20: OoO0O00 / I1ii11iIi11i / iII111i / o0oOOo0O0Ooo
 if 37 - 37: o0oOOo0O0Ooo - ooOoO0o + OoOoOO00
 if 50 - 50: I1IiiI
 if 30 - 30: i1IIi + II111iiii . Oo0Ooo + iIii1I11I1II1
 if 54 - 54: o0oOOo0O0Ooo / i11iIiiIii - I11i - oO0o
 if 16 - 16: I1ii11iIi11i / OoO0O00
 if 2 - 2: i11iIiiIii . iII111i
 if 35 - 35: Ii1I
 if 54 - 54: OOooOOo
 if 83 - 83: i1IIi / II111iiii - I1IiiI + I1ii11iIi11i . IiII * oO0o
 if 92 - 92: OoOoOO00 + oO0o % Ii1I / Ii1I - iII111i
 if 11 - 11: Oo0Ooo % II111iiii * Ii1I + II111iiii
 if 9 - 9: I1Ii111
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 69 - 69: i1IIi + ooOoO0o + Ii1I
 O0o00o000oO = lisp_get_interface_address ( rloc . interface )
 if ( O0o00o000oO == None ) : return
 if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
 O0o00o000 = rloc . rloc . print_address_no_iid ( )
 i1iiI11ii1II1 = O0o00o000oO . print_address_no_iid ( )
 if 70 - 70: o0oOOo0O0Ooo - O0 % I1ii11iIi11i
 if ( O0o00o000 == i1iiI11ii1II1 ) : return
 if 28 - 28: I1Ii111 % iII111i
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , O0o00o000 , i1iiI11ii1II1 ) )
 if 18 - 18: OoOoOO00
 if 42 - 42: Ii1I . OOooOOo / O0 / i1IIi . i11iIiiIii
 rloc . rloc . copy_address ( O0o00o000oO )
 lisp_myrlocs [ 0 ] = O0o00o000oO
 return
 if 62 - 62: OoOoOO00
 if 6 - 6: OoO0O00 * ooOoO0o . oO0o
 if 77 - 77: iIii1I11I1II1
 if 96 - 96: iII111i * I1ii11iIi11i
 if 77 - 77: i11iIiiIii / iIii1I11I1II1 . I1ii11iIi11i
 if 90 - 90: I1IiiI + I1IiiI % oO0o
 if 95 - 95: OOooOOo + OoooooooOO . i11iIiiIii * OoO0O00 * I1IiiI / I1Ii111
 if 5 - 5: Ii1I . oO0o / o0oOOo0O0Ooo - OoooooooOO
def lisp_update_encap_port ( mc ) :
 for OooO0ooO0o0OO in mc . rloc_set :
  oOOo0O0O = lisp_get_nat_info ( OooO0ooO0o0OO . rloc , OooO0ooO0o0OO . rloc_name )
  if ( oOOo0O0O == None ) : continue
  if ( OooO0ooO0o0OO . translated_port == oOOo0O0O . port ) : continue
  if 67 - 67: I1Ii111 + i1IIi - OOooOOo + OoooooooOO / II111iiii - I1Ii111
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( OooO0ooO0o0OO . translated_port , oOOo0O0O . port ,
  # OOooOOo
 red ( OooO0ooO0o0OO . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 55 - 55: I11i
  OooO0ooO0o0OO . store_translated_rloc ( OooO0ooO0o0OO . rloc , oOOo0O0O . port )
  if 7 - 7: I1Ii111 + ooOoO0o % o0oOOo0O0Ooo
 return
 if 53 - 53: i1IIi / iII111i % Ii1I % OoooooooOO
 if 63 - 63: OOooOOo + I1ii11iIi11i . i1IIi . Ii1I - I1ii11iIi11i * o0oOOo0O0Ooo
 if 79 - 79: ooOoO0o - O0
 if 20 - 20: OOooOOo
 if 22 - 22: iIii1I11I1II1 / I1Ii111
 if 6 - 6: iII111i . i11iIiiIii / Oo0Ooo
 if 86 - 86: I11i % I1Ii111 % oO0o - ooOoO0o / i1IIi
 if 68 - 68: i1IIi % O0 % iII111i
 if 55 - 55: I1ii11iIi11i % OOooOOo - o0oOOo0O0Ooo - II111iiii
 if 52 - 52: I1Ii111
 if 34 - 34: II111iiii + iII111i / IiII
 if 47 - 47: OoO0O00
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
  if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
 iIiooo = lisp_get_timestamp ( )
 if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
 if 100 - 100: II111iiii . IiII . I11i
 if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
 if 3 - 3: OoooooooOO
 if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
 if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
 if ( mc . last_refresh_time + mc . map_cache_ttl > iIiooo ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
  if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
  if 37 - 37: I1ii11iIi11i * IiII
  if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
  if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
 o0O0oO0 = lisp_print_elapsed ( mc . last_refresh_time )
 IiI1ii1 = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( IiI1ii1 , False ) , bold ( "timed out" , False ) , o0O0oO0 ) )
 if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
 if 46 - 46: OoooooooOO * OoO0O00 . I1Ii111
 if 95 - 95: ooOoO0o . I1ii11iIi11i . ooOoO0o / I1IiiI * OoOoOO00 . O0
 if 78 - 78: oO0o
 if 33 - 33: oO0o + i1IIi
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 32 - 32: iIii1I11I1II1
 if 71 - 71: Ii1I * I1IiiI
 if 62 - 62: II111iiii / I1IiiI . I1ii11iIi11i
 if 49 - 49: IiII / OoOoOO00 / O0 * i11iIiiIii
 if 47 - 47: i11iIiiIii + iII111i + i11iIiiIii
 if 66 - 66: o0oOOo0O0Ooo . I1IiiI + OoooooooOO . iII111i / OoooooooOO - IiII
 if 47 - 47: o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
 if 34 - 34: I11i / o0oOOo0O0Ooo * OOooOOo * OOooOOo
def lisp_timeout_map_cache_walk ( mc , parms ) :
 ii1111Ii = parms [ 0 ]
 oOIIiiI = parms [ 1 ]
 if 74 - 74: OoOoOO00 . I1Ii111 - Oo0Ooo / I11i . OoOoOO00 * o0oOOo0O0Ooo
 if 43 - 43: I11i
 if 18 - 18: OoooooooOO + OoooooooOO - i11iIiiIii / II111iiii
 if 41 - 41: Oo0Ooo . OoOoOO00 . iII111i / i11iIiiIii
 if ( mc . group . is_null ( ) ) :
  iI1i11I1III11 , ii1111Ii = lisp_timeout_map_cache_entry ( mc , ii1111Ii )
  if ( ii1111Ii == [ ] or mc != ii1111Ii [ - 1 ] ) :
   oOIIiiI = lisp_write_checkpoint_entry ( oOIIiiI , mc )
   if 65 - 65: iII111i * o0oOOo0O0Ooo * OoooooooOO + I11i + oO0o % OoO0O00
  return ( [ iI1i11I1III11 , parms ] )
  if 1 - 1: I1ii11iIi11i . ooOoO0o
  if 54 - 54: OoOoOO00 % I1IiiI . ooOoO0o + IiII / i11iIiiIii / o0oOOo0O0Ooo
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 51 - 51: OoOoOO00 / Ii1I . I1IiiI / Ii1I . II111iiii - iIii1I11I1II1
 if 78 - 78: I11i
 if 42 - 42: Ii1I
 if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
 if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 21 - 21: I1ii11iIi11i - ooOoO0o
 if 81 - 81: iII111i / i11iIiiIii / I1Ii111
 if 70 - 70: I1ii11iIi11i / i11iIiiIii
 if 90 - 90: II111iiii / OoOoOO00 . Ii1I . OoooooooOO
 if 76 - 76: OoooooooOO
 if 78 - 78: IiII % i11iIiiIii
 if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
def lisp_timeout_map_cache ( lisp_map_cache ) :
 oo0OoOO0000 = [ [ ] , [ ] ]
 oo0OoOO0000 = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , oo0OoOO0000 )
 if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
 if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
 if 19 - 19: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
 if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
 ii1111Ii = oo0OoOO0000 [ 0 ]
 for OoOoooooO00oo in ii1111Ii : OoOoooooO00oo . delete_cache ( )
 if 71 - 71: OoO0O00 - I11i
 if 96 - 96: I1Ii111 / Ii1I
 if 65 - 65: I1ii11iIi11i * O0 . IiII
 if 11 - 11: I11i / Ii1I % oO0o
 oOIIiiI = oo0OoOO0000 [ 1 ]
 lisp_checkpoint ( oOIIiiI )
 return
 if 50 - 50: i11iIiiIii
 if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
 if 25 - 25: I11i / ooOoO0o % ooOoO0o - OOooOOo
 if 59 - 59: I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1 - O0 - i11iIiiIii
 if 4 - 4: I1IiiI
 if 36 - 36: Ii1I
 if 76 - 76: i11iIiiIii + i1IIi
 if 56 - 56: OoOoOO00 + II111iiii / i11iIiiIii * OoOoOO00 * OoooooooOO
 if 15 - 15: OoOoOO00 / OoooooooOO + OOooOOo
 if 76 - 76: Ii1I * iII111i . OoooooooOO
 if 92 - 92: iIii1I11I1II1 - Oo0Ooo - I1IiiI - OOooOOo * I1Ii111
 if 44 - 44: I1Ii111 - II111iiii / OOooOOo
 if 50 - 50: I11i / I1ii11iIi11i
 if 60 - 60: II111iiii / Ii1I + OoO0O00 % I1IiiI * i1IIi / II111iiii
 if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
 if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
def lisp_store_nat_info ( hostname , rloc , port ) :
 oOo0O = rloc . print_address_no_iid ( )
 i11Ii = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( oOo0O , False ) , port )
 if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 i1Oo = lisp_nat_info ( oOo0O , hostname , port )
 if 45 - 45: OoO0O00 + OoOoOO00 + o0oOOo0O0Ooo
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ i1Oo ]
  lprint ( i11Ii . format ( "Store initial" ) )
  return ( True )
  if 70 - 70: OOooOOo % OoOoOO00
  if 86 - 86: OoooooooOO + OOooOOo + OOooOOo + I1Ii111 + OoooooooOO + ooOoO0o
  if 84 - 84: OoOoOO00 * OoOoOO00 % ooOoO0o % II111iiii / iII111i + Oo0Ooo
  if 95 - 95: iII111i . oO0o % iIii1I11I1II1 - I1IiiI
  if 38 - 38: ooOoO0o % iIii1I11I1II1 - OOooOOo
  if 13 - 13: OOooOOo . i11iIiiIii
 oOOo0O0O = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( oOOo0O0O . address == oOo0O and oOOo0O0O . port == port ) :
  oOOo0O0O . uptime = lisp_get_timestamp ( )
  lprint ( i11Ii . format ( "Refresh existing" ) )
  return ( False )
  if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
  if 79 - 79: oO0o
  if 47 - 47: OoooooooOO - i1IIi * OOooOOo
  if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
  if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
  if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
  if 8 - 8: iII111i
 iI1II1II1i = None
 for oOOo0O0O in lisp_nat_state_info [ hostname ] :
  if ( oOOo0O0O . address == oOo0O and oOOo0O0O . port == port ) :
   iI1II1II1i = oOOo0O0O
   break
   if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
   if 99 - 99: OoOoOO00
   if 46 - 46: I1ii11iIi11i / II111iiii / OoooooooOO / Ii1I
 if ( iI1II1II1i == None ) :
  lprint ( i11Ii . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( iI1II1II1i )
  lprint ( i11Ii . format ( "Use previous" ) )
  if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
  if 8 - 8: oO0o
 I1I1ii = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ i1Oo ] + I1I1ii
 return ( True )
 if 36 - 36: ooOoO0o . Ii1I * ooOoO0o - OoOoOO00
 if 20 - 20: ooOoO0o
 if 13 - 13: i11iIiiIii + i11iIiiIii
 if 21 - 21: OoooooooOO
 if 76 - 76: Ii1I . i11iIiiIii * I1IiiI % o0oOOo0O0Ooo * OoO0O00
 if 79 - 79: O0 % iIii1I11I1II1 * iII111i - II111iiii % Oo0Ooo + i11iIiiIii
 if 36 - 36: OOooOOo / o0oOOo0O0Ooo . OoOoOO00 - I11i
 if 89 - 89: i1IIi - iIii1I11I1II1 / II111iiii
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 61 - 61: I1Ii111
 oOo0O = rloc . print_address_no_iid ( )
 for oOOo0O0O in lisp_nat_state_info [ hostname ] :
  if ( oOOo0O0O . address == oOo0O ) : return ( oOOo0O0O )
  if 56 - 56: I1ii11iIi11i - OoooooooOO
 return ( None )
 if 52 - 52: Oo0Ooo - I11i - IiII - OoOoOO00
 if 21 - 21: oO0o % o0oOOo0O0Ooo + I1Ii111 . OOooOOo / OOooOOo
 if 41 - 41: Oo0Ooo . ooOoO0o * oO0o
 if 31 - 31: Oo0Ooo * IiII / IiII
 if 3 - 3: I1Ii111
 if 65 - 65: iIii1I11I1II1 % Oo0Ooo % I11i / OoooooooOO
 if 82 - 82: o0oOOo0O0Ooo
 if 33 - 33: OoOoOO00 / i11iIiiIii - I1IiiI - OoooooooOO + i1IIi * I1Ii111
 if 92 - 92: iII111i + OoO0O00
 if 70 - 70: iIii1I11I1II1
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
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 60 - 60: iIii1I11I1II1 + i1IIi + oO0o - iIii1I11I1II1 . i11iIiiIii * OoooooooOO
 if 23 - 23: iII111i - IiII % i11iIiiIii
 if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
 if 60 - 60: OOooOOo - I1Ii111 * Oo0Ooo
 if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
 if 39 - 39: iIii1I11I1II1 / i1IIi % I11i % I1ii11iIi11i * IiII
 iiiii1 = [ ]
 Ii1iiI = [ ]
 if ( dest == None ) :
  for ii1 in lisp_map_resolvers_list . values ( ) :
   Ii1iiI . append ( ii1 . map_resolver )
   if 37 - 37: OoooooooOO . o0oOOo0O0Ooo - o0oOOo0O0Ooo - Oo0Ooo / I1IiiI
  iiiii1 = Ii1iiI
  if ( iiiii1 == [ ] ) :
   for Ii1IIII in lisp_map_servers_list . values ( ) :
    iiiii1 . append ( Ii1IIII . map_server )
    if 87 - 87: IiII
    if 68 - 68: I1Ii111 + I1ii11iIi11i * IiII . OoO0O00 / I11i
  if ( iiiii1 == [ ] ) : return
 else :
  iiiii1 . append ( dest )
  if 39 - 39: Oo0Ooo + OOooOOo . I1IiiI + OoO0O00 . OoooooooOO
  if 31 - 31: OoO0O00
  if 55 - 55: OoOoOO00 + I1Ii111 * o0oOOo0O0Ooo - I1ii11iIi11i + OoOoOO00
  if 6 - 6: II111iiii % iIii1I11I1II1 * I1Ii111
  if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
 i1I1i1Iiiiiii = { }
 for o00o0oOo0o0O in lisp_db_list :
  for IiIIIi in o00o0oOo0o0O . rloc_set :
   lisp_update_local_rloc ( IiIIIi )
   if ( IiIIIi . rloc . is_null ( ) ) : continue
   if ( IiIIIi . interface == None ) : continue
   if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
   O0o00o000oO = IiIIIi . rloc . print_address_no_iid ( )
   if ( O0o00o000oO in i1I1i1Iiiiiii ) : continue
   i1I1i1Iiiiiii [ O0o00o000oO ] = IiIIIi . interface
   if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
   if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
 if ( i1I1i1Iiiiiii == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
  return
  if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
  if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
  if 74 - 74: OoooooooOO + Ii1I
  if 100 - 100: I1IiiI
  if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
  if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
 for O0o00o000oO in i1I1i1Iiiiiii :
  I1i = i1I1i1Iiiiiii [ O0o00o000oO ]
  O0o00O0Oo0 = red ( O0o00o000oO , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( O0o00O0Oo0 ,
 I1i ) )
  OO0oo00oOO = I1i if len ( i1I1i1Iiiiiii ) > 1 else None
  for dest in iiiii1 :
   lisp_send_info_request ( lisp_sockets , dest , port , OO0oo00oOO )
   if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
   if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
   if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
   if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
   if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
   if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
 if ( Ii1iiI != [ ] ) :
  for ii1 in lisp_map_resolvers_list . values ( ) :
   ii1 . resolve_dns_name ( )
   if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
   if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
 return
 if 40 - 40: I1ii11iIi11i
 if 76 - 76: Oo0Ooo - I11i
 if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
 if 39 - 39: I1IiiI
 if 8 - 8: IiII * i1IIi * i1IIi * O0
 if 69 - 69: Oo0Ooo
 if 48 - 48: iII111i
 if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
 if 89 - 89: iII111i
 if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
 if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
 if 77 - 77: OoooooooOO - I11i / I1IiiI % OoOoOO00 - OOooOOo
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 37 - 37: ooOoO0o
 if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
 if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
 if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
 if ( value . find ( "." ) != - 1 ) :
  O0o00o000oO = value . split ( "." )
  if ( len ( O0o00o000oO ) != 4 ) : return ( False )
  if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
  for o0O0O00oO in O0o00o000oO :
   if ( o0O0O00oO . isdigit ( ) == False ) : return ( False )
   if ( int ( o0O0O00oO ) > 255 ) : return ( False )
   if 67 - 67: o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
  return ( True )
  if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
  if 44 - 44: O0
  if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
  if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
  if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
 if ( value . find ( "-" ) != - 1 ) :
  O0o00o000oO = value . split ( "-" )
  for i1i1IIIIIIIi in [ "N" , "S" , "W" , "E" ] :
   if ( i1i1IIIIIIIi in O0o00o000oO ) :
    if ( len ( O0o00o000oO ) < 8 ) : return ( False )
    return ( True )
    if 14 - 14: iIii1I11I1II1 * I1ii11iIi11i + OOooOOo + O0
    if 79 - 79: II111iiii - iII111i
    if 89 - 89: O0 - OoO0O00
    if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
    if 32 - 32: O0 + IiII
    if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
    if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
 if ( value . find ( "-" ) != - 1 ) :
  O0o00o000oO = value . split ( "-" )
  if ( len ( O0o00o000oO ) != 3 ) : return ( False )
  if 17 - 17: OOooOOo
  for O00o in O0o00o000oO :
   try : int ( O00o , 16 )
   except : return ( False )
   if 2 - 2: OoOoOO00 % ooOoO0o / OoO0O00 / Ii1I
  return ( True )
  if 26 - 26: I11i * ooOoO0o * OoO0O00 * I1Ii111 - OoooooooOO / o0oOOo0O0Ooo
  if 14 - 14: Ii1I / II111iiii % IiII
  if 81 - 81: oO0o + oO0o
  if 27 - 27: OoOoOO00 % OoOoOO00 / o0oOOo0O0Ooo
  if 9 - 9: Oo0Ooo
 if ( value . find ( ":" ) != - 1 ) :
  O0o00o000oO = value . split ( ":" )
  if ( len ( O0o00o000oO ) < 2 ) : return ( False )
  if 84 - 84: iII111i - oO0o * OoO0O00 / i11iIiiIii / oO0o
  O0O0oOOo = False
  OoO = 0
  for O00o in O0o00o000oO :
   OoO += 1
   if ( O00o == "" ) :
    if ( O0O0oOOo ) :
     if ( len ( O0o00o000oO ) == OoO ) : break
     if ( OoO > 2 ) : return ( False )
     if 54 - 54: o0oOOo0O0Ooo + OOooOOo
    O0O0oOOo = True
    continue
    if 24 - 24: ooOoO0o
   try : int ( O00o , 16 )
   except : return ( False )
   if 7 - 7: ooOoO0o . OoooooooOO . iII111i * II111iiii . II111iiii / OOooOOo
  return ( True )
  if 46 - 46: Ii1I - Oo0Ooo / i1IIi % IiII - I1ii11iIi11i + OOooOOo
  if 42 - 42: i1IIi - IiII % OOooOOo % iIii1I11I1II1
  if 71 - 71: OoO0O00
  if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
  if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
 if ( value [ 0 ] == "+" ) :
  O0o00o000oO = value [ 1 : : ]
  for o0oooOo in O0o00o000oO :
   if ( o0oooOo . isdigit ( ) == False ) : return ( False )
   if 6 - 6: Ii1I * i1IIi + O0 % I1Ii111
  return ( True )
  if 82 - 82: II111iiii . IiII - O0
 return ( False )
 if 18 - 18: oO0o * OOooOOo
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
 if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
 if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
 if 96 - 96: II111iiii % I11i / Ii1I - i11iIiiIii
 if 63 - 63: I1IiiI
 if 15 - 15: iIii1I11I1II1 - I1ii11iIi11i % OoO0O00 * II111iiii / I11i + I11i
 if 23 - 23: I1IiiI
 if 51 - 51: i11iIiiIii / ooOoO0o - OoooooooOO + OoOoOO00 + oO0o
 if 57 - 57: iIii1I11I1II1
 if 19 - 19: Ii1I / o0oOOo0O0Ooo + O0 / iIii1I11I1II1 + II111iiii
 if 3 - 3: oO0o % OoO0O00 % OOooOOo
def lisp_process_api ( process , lisp_socket , data_structure ) :
 OO0 , oo0OoOO0000 = data_structure . split ( "%" )
 if 30 - 30: OoO0O00 * I1ii11iIi11i + OoooooooOO % i11iIiiIii - ooOoO0o
 lprint ( "Process API request '{}', parameters: '{}'" . format ( OO0 ,
 oo0OoOO0000 ) )
 if 15 - 15: O0 * OOooOOo * I11i + Ii1I * OoooooooOO + OOooOOo
 Ii11i1IiII = [ ]
 if ( OO0 == "map-cache" ) :
  if ( oo0OoOO0000 == "" ) :
   Ii11i1IiII = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , Ii11i1IiII )
  else :
   Ii11i1IiII = lisp_process_api_map_cache_entry ( json . loads ( oo0OoOO0000 ) )
   if 77 - 77: O0
   if 98 - 98: iII111i - iII111i % i1IIi - I1Ii111 . I1IiiI % o0oOOo0O0Ooo
 if ( OO0 == "site-cache" ) :
  if ( oo0OoOO0000 == "" ) :
   Ii11i1IiII = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 Ii11i1IiII )
  else :
   Ii11i1IiII = lisp_process_api_site_cache_entry ( json . loads ( oo0OoOO0000 ) )
   if 38 - 38: IiII % OoOoOO00 . OOooOOo . I1ii11iIi11i
   if 34 - 34: iII111i . i11iIiiIii + OoO0O00 + o0oOOo0O0Ooo / ooOoO0o - i11iIiiIii
 if ( OO0 == "map-server" ) :
  oo0OoOO0000 = { } if ( oo0OoOO0000 == "" ) else json . loads ( oo0OoOO0000 )
  Ii11i1IiII = lisp_process_api_ms_or_mr ( True , oo0OoOO0000 )
  if 63 - 63: ooOoO0o % OoO0O00 % ooOoO0o
 if ( OO0 == "map-resolver" ) :
  oo0OoOO0000 = { } if ( oo0OoOO0000 == "" ) else json . loads ( oo0OoOO0000 )
  Ii11i1IiII = lisp_process_api_ms_or_mr ( False , oo0OoOO0000 )
  if 28 - 28: IiII * I1Ii111 * o0oOOo0O0Ooo + ooOoO0o - IiII / IiII
 if ( OO0 == "database-mapping" ) :
  Ii11i1IiII = lisp_process_api_database_mapping ( )
  if 73 - 73: iIii1I11I1II1 . I1ii11iIi11i + OOooOOo
  if 51 - 51: I11i % Oo0Ooo * OOooOOo % OoooooooOO - OoOoOO00 % Ii1I
  if 60 - 60: OoOoOO00 - IiII + OoO0O00
  if 77 - 77: iIii1I11I1II1
  if 92 - 92: IiII
 Ii11i1IiII = json . dumps ( Ii11i1IiII )
 oOO0O = lisp_api_ipc ( process , Ii11i1IiII )
 lisp_ipc ( oOO0O , lisp_socket , "lisp-core" )
 return
 if 68 - 68: OOooOOo . IiII / iIii1I11I1II1 % i11iIiiIii
 if 74 - 74: iII111i + i11iIiiIii
 if 95 - 95: Ii1I
 if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
 if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
 if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
 if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
def lisp_process_api_map_cache ( mc , data ) :
 if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
 if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
 if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
 if 49 - 49: iII111i / iII111i - OoOoOO00
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 89 - 89: ooOoO0o
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
 if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
 if 11 - 11: iII111i
 if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
 if 89 - 89: I11i % II111iiii
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 35 - 35: oO0o
 if 65 - 65: II111iiii
 if 87 - 87: oO0o / OoO0O00 - oO0o
 if 69 - 69: i11iIiiIii
 if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
 if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
 if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
def lisp_gather_map_cache_data ( mc , data ) :
 iIiiiIIiii = { }
 iIiiiIIiii [ "instance-id" ] = str ( mc . eid . instance_id )
 iIiiiIIiii [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  iIiiiIIiii [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
 iIiiiIIiii [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 iIiiiIIiii [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 iIiiiIIiii [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 iIiiiIIiii [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
 if 14 - 14: I1ii11iIi11i / i11iIiiIii * I11i % o0oOOo0O0Ooo + IiII / I1ii11iIi11i
 if 82 - 82: OOooOOo . oO0o
 if 12 - 12: i11iIiiIii + II111iiii
 if 49 - 49: OoooooooOO
 iio0OOoO0 = [ ]
 for OooO0ooO0o0OO in mc . rloc_set :
  O0OooO0oo = { }
  if ( OooO0ooO0o0OO . rloc_exists ( ) ) :
   O0OooO0oo [ "address" ] = OooO0ooO0o0OO . rloc . print_address_no_iid ( )
   if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
   if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
  if ( OooO0ooO0o0OO . translated_port != 0 ) :
   O0OooO0oo [ "encap-port" ] = str ( OooO0ooO0o0OO . translated_port )
   if 6 - 6: oO0o / II111iiii
  O0OooO0oo [ "state" ] = OooO0ooO0o0OO . print_state ( )
  if ( OooO0ooO0o0OO . geo ) : O0OooO0oo [ "geo" ] = OooO0ooO0o0OO . geo . print_geo ( )
  if ( OooO0ooO0o0OO . elp ) : O0OooO0oo [ "elp" ] = OooO0ooO0o0OO . elp . print_elp ( False )
  if ( OooO0ooO0o0OO . rle ) : O0OooO0oo [ "rle" ] = OooO0ooO0o0OO . rle . print_rle ( False )
  if ( OooO0ooO0o0OO . json ) : O0OooO0oo [ "json" ] = OooO0ooO0o0OO . json . print_json ( False )
  if ( OooO0ooO0o0OO . rloc_name ) : O0OooO0oo [ "rloc-name" ] = OooO0ooO0o0OO . rloc_name
  O0ooOoo0O000O = OooO0ooO0o0OO . stats . get_stats ( False , False )
  if ( O0ooOoo0O000O ) : O0OooO0oo [ "stats" ] = O0ooOoo0O000O
  O0OooO0oo [ "uptime" ] = lisp_print_elapsed ( OooO0ooO0o0OO . uptime )
  O0OooO0oo [ "upriority" ] = str ( OooO0ooO0o0OO . priority )
  O0OooO0oo [ "uweight" ] = str ( OooO0ooO0o0OO . weight )
  O0OooO0oo [ "mpriority" ] = str ( OooO0ooO0o0OO . mpriority )
  O0OooO0oo [ "mweight" ] = str ( OooO0ooO0o0OO . mweight )
  i1iiI1iIi = OooO0ooO0o0OO . last_rloc_probe_reply
  if ( i1iiI1iIi ) :
   O0OooO0oo [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( i1iiI1iIi )
   O0OooO0oo [ "rloc-probe-rtt" ] = str ( OooO0ooO0o0OO . rloc_probe_rtt )
   if 18 - 18: iIii1I11I1II1 % o0oOOo0O0Ooo
  O0OooO0oo [ "rloc-hop-count" ] = OooO0ooO0o0OO . rloc_probe_hops
  O0OooO0oo [ "recent-rloc-hop-counts" ] = OooO0ooO0o0OO . recent_rloc_probe_hops
  if 64 - 64: i1IIi % oO0o
  iII111I = [ ]
  for I1i1IIiI in OooO0ooO0o0OO . recent_rloc_probe_rtts : iII111I . append ( str ( I1i1IIiI ) )
  O0OooO0oo [ "recent-rloc-probe-rtts" ] = iII111I
  if 66 - 66: IiII * i11iIiiIii
  iio0OOoO0 . append ( O0OooO0oo )
  if 64 - 64: i11iIiiIii . I1Ii111 % i11iIiiIii % I11i
 iIiiiIIiii [ "rloc-set" ] = iio0OOoO0
 if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
 data . append ( iIiiiIIiii )
 return ( [ True , data ] )
 if 64 - 64: OOooOOo / OoOoOO00
 if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
 if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
 if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
 if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
 if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
 if 49 - 49: IiII
def lisp_process_api_map_cache_entry ( parms ) :
 oOo00Ooo0o0 = parms [ "instance-id" ]
 oOo00Ooo0o0 = 0 if ( oOo00Ooo0o0 == "" ) else int ( oOo00Ooo0o0 )
 if 1 - 1: oO0o / I11i
 if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
 if 28 - 28: OOooOOo - O0 - O0 % i11iIiiIii * OoooooooOO
 if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
 I111o0oooO00o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , oOo00Ooo0o0 )
 I111o0oooO00o0 . store_prefix ( parms [ "eid-prefix" ] )
 oO00o0oOoo = I111o0oooO00o0
 O0O00Oo = I111o0oooO00o0
 if 24 - 24: O0
 if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
 if 65 - 65: i11iIiiIii
 if 46 - 46: i11iIiiIii
 if 70 - 70: i1IIi + o0oOOo0O0Ooo
 oOoooOOO0o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , oOo00Ooo0o0 )
 if ( parms . has_key ( "group-prefix" ) ) :
  oOoooOOO0o0 . store_prefix ( parms [ "group-prefix" ] )
  oO00o0oOoo = oOoooOOO0o0
  if 44 - 44: iII111i . II111iiii % o0oOOo0O0Ooo
  if 29 - 29: i11iIiiIii * i1IIi
 Ii11i1IiII = [ ]
 OoOoooooO00oo = lisp_map_cache_lookup ( O0O00Oo , oO00o0oOoo )
 if ( OoOoooooO00oo ) : iI1i11I1III11 , Ii11i1IiII = lisp_process_api_map_cache ( OoOoooooO00oo , Ii11i1IiII )
 return ( Ii11i1IiII )
 if 36 - 36: OoO0O00 * I11i . ooOoO0o
 if 50 - 50: oO0o * OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
 if 55 - 55: II111iiii - IiII
 if 24 - 24: oO0o % Ii1I / i1IIi
 if 84 - 84: i1IIi
 if 53 - 53: OoooooooOO - i1IIi - Ii1I
 if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
def lisp_process_api_site_cache ( se , data ) :
 if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
 if 34 - 34: Ii1I
 if 5 - 5: II111iiii . I1ii11iIi11i
 if 85 - 85: I1Ii111 . IiII + II111iiii
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
 if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
 if 87 - 87: OOooOOo
 if 44 - 44: Oo0Ooo + iIii1I11I1II1
 if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
 if 10 - 10: O0 / I11i
 if 29 - 29: i11iIiiIii % I11i
 if 49 - 49: I11i
 if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
 if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
 if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 III1 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 II11Iii11III = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  III1 . store_address ( data [ "address" ] )
  if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
  if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
 Oooo0oOOO0 = { }
 if ( ms_or_mr ) :
  for Ii1IIII in lisp_map_servers_list . values ( ) :
   if ( II11Iii11III ) :
    if ( II11Iii11III != Ii1IIII . dns_name ) : continue
   else :
    if ( III1 . is_exact_match ( Ii1IIII . map_server ) == False ) : continue
    if 32 - 32: O0
    if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
   Oooo0oOOO0 [ "dns-name" ] = Ii1IIII . dns_name
   Oooo0oOOO0 [ "address" ] = Ii1IIII . map_server . print_address_no_iid ( )
   Oooo0oOOO0 [ "ms-name" ] = "" if Ii1IIII . ms_name == None else Ii1IIII . ms_name
   return ( [ Oooo0oOOO0 ] )
   if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
 else :
  for ii1 in lisp_map_resolvers_list . values ( ) :
   if ( II11Iii11III ) :
    if ( II11Iii11III != ii1 . dns_name ) : continue
   else :
    if ( III1 . is_exact_match ( ii1 . map_resolver ) == False ) : continue
    if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
    if 70 - 70: iIii1I11I1II1 - I11i
   Oooo0oOOO0 [ "dns-name" ] = ii1 . dns_name
   Oooo0oOOO0 [ "address" ] = ii1 . map_resolver . print_address_no_iid ( )
   Oooo0oOOO0 [ "mr-name" ] = "" if ii1 . mr_name == None else ii1 . mr_name
   return ( [ Oooo0oOOO0 ] )
   if 2 - 2: oO0o / II111iiii * OoO0O00
   if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
 return ( [ ] )
 if 40 - 40: OOooOOo
 if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
 if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
 if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
 if 26 - 26: OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
 if 39 - 39: I1ii11iIi11i * I1IiiI * II111iiii . Oo0Ooo % I1IiiI
 if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
 if 98 - 98: OoO0O00 + oO0o - II111iiii
def lisp_process_api_database_mapping ( ) :
 Ii11i1IiII = [ ]
 if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
 for o00o0oOo0o0O in lisp_db_list :
  iIiiiIIiii = { }
  iIiiiIIiii [ "eid-prefix" ] = o00o0oOo0o0O . eid . print_prefix ( )
  if ( o00o0oOo0o0O . group . is_null ( ) == False ) :
   iIiiiIIiii [ "group-prefix" ] = o00o0oOo0o0O . group . print_prefix ( )
   if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
   if 77 - 77: iIii1I11I1II1 * Oo0Ooo . IiII / oO0o + O0
  OO000 = [ ]
  for O0OooO0oo in o00o0oOo0o0O . rloc_set :
   OooO0ooO0o0OO = { }
   if ( O0OooO0oo . rloc . is_null ( ) == False ) :
    OooO0ooO0o0OO [ "rloc" ] = O0OooO0oo . rloc . print_address_no_iid ( )
    if 76 - 76: iII111i + o0oOOo0O0Ooo - OoooooooOO * oO0o % OoooooooOO - O0
   if ( O0OooO0oo . rloc_name != None ) : OooO0ooO0o0OO [ "rloc-name" ] = O0OooO0oo . rloc_name
   if ( O0OooO0oo . interface != None ) : OooO0ooO0o0OO [ "interface" ] = O0OooO0oo . interface
   i1IIIIIi111 = O0OooO0oo . translated_rloc
   if ( i1IIIIIi111 . is_null ( ) == False ) :
    OooO0ooO0o0OO [ "translated-rloc" ] = i1IIIIIi111 . print_address_no_iid ( )
    if 10 - 10: o0oOOo0O0Ooo + ooOoO0o + Oo0Ooo
   if ( OooO0ooO0o0OO != { } ) : OO000 . append ( OooO0ooO0o0OO )
   if 67 - 67: I1IiiI / i11iIiiIii - I1Ii111 % OoooooooOO
   if 36 - 36: oO0o % iII111i % oO0o
   if 56 - 56: ooOoO0o - O0 + iII111i % I11i / i1IIi
   if 78 - 78: i1IIi . iIii1I11I1II1
   if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
  iIiiiIIiii [ "rlocs" ] = OO000
  if 58 - 58: II111iiii * oO0o - i1IIi . I11i
  if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
  if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
  if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
  Ii11i1IiII . append ( iIiiiIIiii )
  if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
 return ( Ii11i1IiII )
 if 31 - 31: i1IIi * Ii1I
 if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
 if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
 if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
 if 52 - 52: OOooOOo . OoOoOO00 - ooOoO0o % i1IIi
 if 15 - 15: oO0o
 if 6 - 6: oO0o . iIii1I11I1II1 - I1ii11iIi11i % IiII
def lisp_gather_site_cache_data ( se , data ) :
 iIiiiIIiii = { }
 iIiiiIIiii [ "site-name" ] = se . site . site_name
 iIiiiIIiii [ "instance-id" ] = str ( se . eid . instance_id )
 iIiiiIIiii [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  iIiiiIIiii [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 58 - 58: iII111i * oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o
 iIiiiIIiii [ "registered" ] = "yes" if se . registered else "no"
 iIiiiIIiii [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 iIiiiIIiii [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 63 - 63: oO0o . IiII . o0oOOo0O0Ooo
 O0o00o000oO = se . last_registerer
 O0o00o000oO = "none" if O0o00o000oO . is_null ( ) else O0o00o000oO . print_address ( )
 iIiiiIIiii [ "last-registerer" ] = O0o00o000oO
 iIiiiIIiii [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 iIiiiIIiii [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 iIiiiIIiii [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  iIiiiIIiii [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 16 - 16: iII111i . I11i - Oo0Ooo / I1IiiI + OoOoOO00
  if 14 - 14: iIii1I11I1II1 / i11iIiiIii - o0oOOo0O0Ooo . iII111i * OoO0O00
  if 5 - 5: Ii1I + OoOoOO00 % I11i + IiII
  if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
  if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
 iio0OOoO0 = [ ]
 for OooO0ooO0o0OO in se . registered_rlocs :
  O0OooO0oo = { }
  O0OooO0oo [ "address" ] = OooO0ooO0o0OO . rloc . print_address_no_iid ( ) if OooO0ooO0o0OO . rloc_exists ( ) else "none"
  if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
  if 7 - 7: I1Ii111 % i1IIi . I11i . O0 / i1IIi
  if ( OooO0ooO0o0OO . geo ) : O0OooO0oo [ "geo" ] = OooO0ooO0o0OO . geo . print_geo ( )
  if ( OooO0ooO0o0OO . elp ) : O0OooO0oo [ "elp" ] = OooO0ooO0o0OO . elp . print_elp ( False )
  if ( OooO0ooO0o0OO . rle ) : O0OooO0oo [ "rle" ] = OooO0ooO0o0OO . rle . print_rle ( False )
  if ( OooO0ooO0o0OO . json ) : O0OooO0oo [ "json" ] = OooO0ooO0o0OO . json . print_json ( False )
  if ( OooO0ooO0o0OO . rloc_name ) : O0OooO0oo [ "rloc-name" ] = OooO0ooO0o0OO . rloc_name
  O0OooO0oo [ "uptime" ] = lisp_print_elapsed ( OooO0ooO0o0OO . uptime )
  O0OooO0oo [ "upriority" ] = str ( OooO0ooO0o0OO . priority )
  O0OooO0oo [ "uweight" ] = str ( OooO0ooO0o0OO . weight )
  O0OooO0oo [ "mpriority" ] = str ( OooO0ooO0o0OO . mpriority )
  O0OooO0oo [ "mweight" ] = str ( OooO0ooO0o0OO . mweight )
  if 56 - 56: Oo0Ooo
  iio0OOoO0 . append ( O0OooO0oo )
  if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
 iIiiiIIiii [ "registered-rlocs" ] = iio0OOoO0
 if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
 data . append ( iIiiiIIiii )
 return ( [ True , data ] )
 if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
 if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
 if 70 - 70: Oo0Ooo - I11i / I1ii11iIi11i % OoO0O00 % II111iiii
 if 72 - 72: i11iIiiIii * I11i
 if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
 if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
 if 64 - 64: OoooooooOO
def lisp_process_api_site_cache_entry ( parms ) :
 oOo00Ooo0o0 = parms [ "instance-id" ]
 oOo00Ooo0o0 = 0 if ( oOo00Ooo0o0 == "" ) else int ( oOo00Ooo0o0 )
 if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
 if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
 if 71 - 71: O0 - OoooooooOO
 if 82 - 82: i11iIiiIii * II111iiii % IiII
 I111o0oooO00o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , oOo00Ooo0o0 )
 I111o0oooO00o0 . store_prefix ( parms [ "eid-prefix" ] )
 if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
 if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
 if 67 - 67: iII111i
 if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
 if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
 oOoooOOO0o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , oOo00Ooo0o0 )
 if ( parms . has_key ( "group-prefix" ) ) :
  oOoooOOO0o0 . store_prefix ( parms [ "group-prefix" ] )
  if 60 - 60: i1IIi / iII111i
  if 10 - 10: I1Ii111 / OoOoOO00 * Ii1I % o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i
 Ii11i1IiII = [ ]
 oo0OO0O0 = lisp_site_eid_lookup ( I111o0oooO00o0 , oOoooOOO0o0 , False )
 if ( oo0OO0O0 ) : lisp_gather_site_cache_data ( oo0OO0O0 , Ii11i1IiII )
 return ( Ii11i1IiII )
 if 2 - 2: iIii1I11I1II1
 if 85 - 85: O0 - ooOoO0o
 if 35 - 35: o0oOOo0O0Ooo - I1IiiI
 if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
 if 65 - 65: Ii1I % i11iIiiIii
 if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
 if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
def lisp_get_interface_instance_id ( device , source_eid ) :
 I1i = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  I1i = lisp_myinterfaces [ device ]
  if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
  if 88 - 88: iII111i
  if 94 - 94: OoooooooOO
  if 32 - 32: I1ii11iIi11i
  if 8 - 8: I11i * i11iIiiIii - ooOoO0o
  if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
 if ( I1i == None or I1i . instance_id == None ) :
  return ( lisp_default_iid )
  if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
  if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
  if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
  if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
  if 42 - 42: II111iiii . iII111i
  if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
  if 64 - 64: oO0o / IiII
  if 86 - 86: I11i
  if 36 - 36: o0oOOo0O0Ooo / OoO0O00
 oOo00Ooo0o0 = I1i . get_instance_id ( )
 if ( source_eid == None ) : return ( oOo00Ooo0o0 )
 if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
 O000iI1ii1I = source_eid . instance_id
 OOOOo00oo0OO = None
 for I1i in lisp_multi_tenant_interfaces :
  if ( I1i . device != device ) : continue
  O000 = I1i . multi_tenant_eid
  source_eid . instance_id = O000 . instance_id
  if ( source_eid . is_more_specific ( O000 ) == False ) : continue
  if ( OOOOo00oo0OO == None or OOOOo00oo0OO . multi_tenant_eid . mask_len < O000 . mask_len ) :
   OOOOo00oo0OO = I1i
   if 34 - 34: iIii1I11I1II1
   if 26 - 26: iII111i / IiII * iII111i
 source_eid . instance_id = O000iI1ii1I
 if 91 - 91: Oo0Ooo
 if ( OOOOo00oo0OO == None ) : return ( oOo00Ooo0o0 )
 return ( OOOOo00oo0OO . get_instance_id ( ) )
 if 98 - 98: iIii1I11I1II1 . OoO0O00
 if 1 - 1: OOooOOo % Oo0Ooo
 if 86 - 86: i11iIiiIii
 if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
 if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
 if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
 if 79 - 79: I11i - II111iiii
 if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
 if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( lisp_myinterfaces . has_key ( device ) == False ) : return ( None )
 if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
 I1i = lisp_myinterfaces [ device ]
 iii1iI1I1i11 = device if I1i . dynamic_eid_device == None else I1i . dynamic_eid_device
 if 3 - 3: OoOoOO00 / o0oOOo0O0Ooo * O0
 if 32 - 32: o0oOOo0O0Ooo / I1Ii111 + I1Ii111
 if ( I1i . does_dynamic_eid_match ( eid ) ) : return ( iii1iI1I1i11 )
 return ( None )
 if 69 - 69: iIii1I11I1II1 * o0oOOo0O0Ooo * II111iiii + OoooooooOO . Ii1I
 if 99 - 99: Ii1I % iIii1I11I1II1 . I1Ii111 / iIii1I11I1II1 / oO0o
 if 76 - 76: I1Ii111
 if 27 - 27: I1ii11iIi11i
 if 72 - 72: OoooooooOO - IiII
 if 8 - 8: i11iIiiIii + I11i . II111iiii . O0
 if 21 - 21: i1IIi * Oo0Ooo / iII111i . iIii1I11I1II1 % OOooOOo % i1IIi
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 8 - 8: OoO0O00 % OoO0O00 * i1IIi / Oo0Ooo * i1IIi . i11iIiiIii
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 10 - 10: O0 . Ii1I . i1IIi
 Iii1iI1Ii1I = lisp_process_rloc_probe_timer
 iiIi = threading . Timer ( interval , Iii1iI1Ii1I , [ lisp_sockets ] )
 lisp_rloc_probe_timer = iiIi
 iiIi . start ( )
 return
 if 63 - 63: OoooooooOO * iII111i
 if 8 - 8: OoooooooOO * i11iIiiIii * iII111i * O0 - OoOoOO00
 if 3 - 3: OoooooooOO % oO0o + OoOoOO00 % I1IiiI
 if 50 - 50: OoO0O00 - Oo0Ooo
 if 13 - 13: OoOoOO00
 if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
 if 90 - 90: oO0o * I1Ii111 / O0
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for iII1 in lisp_rloc_probe_list :
  IIiii1IiiIiii = lisp_rloc_probe_list [ iII1 ]
  lprint ( "RLOC {}:" . format ( iII1 ) )
  for O0OooO0oo , o0OoO00 , II1IIiIiiI1iI in IIiii1IiiIiii :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( O0OooO0oo ) ) , o0OoO00 . print_prefix ( ) ,
 II1IIiIiiI1iI . print_prefix ( ) , O0OooO0oo . translated_port ) )
   if 81 - 81: I11i
   if 31 - 31: OoooooooOO - OoO0O00 . iIii1I11I1II1 % I1IiiI
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 98 - 98: I1IiiI + Ii1I
 if 7 - 7: o0oOOo0O0Ooo . OoooooooOO
 if 32 - 32: I1ii11iIi11i
 if 46 - 46: Ii1I . i11iIiiIii / I1Ii111 - I1ii11iIi11i
 if 13 - 13: IiII % I1Ii111
 if 9 - 9: OoooooooOO * ooOoO0o % I1ii11iIi11i . I1IiiI % O0
 if 91 - 91: OOooOOo * OoooooooOO * I1IiiI . i1IIi
 if 9 - 9: oO0o / i11iIiiIii + IiII / IiII - I11i
 if 87 - 87: iII111i
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 37 - 37: oO0o + OoO0O00
 if 66 - 66: iIii1I11I1II1 * iIii1I11I1II1 + IiII % I1IiiI
 if 60 - 60: I1Ii111 . IiII / Oo0Ooo
 if 32 - 32: OoOoOO00 + Ii1I * iII111i % Oo0Ooo
 OooO0ooO0o0OO , o0OoO00 , II1IIiIiiI1iI = eid_list [ 0 ]
 ooO0oOoooo = [ lisp_print_eid_tuple ( o0OoO00 , II1IIiIiiI1iI ) ]
 if 91 - 91: I1IiiI + IiII / OOooOOo - i1IIi % i11iIiiIii / iIii1I11I1II1
 for OooO0ooO0o0OO , o0OoO00 , II1IIiIiiI1iI in eid_list [ 1 : : ] :
  OooO0ooO0o0OO . state = LISP_RLOC_UNREACH_STATE
  OooO0ooO0o0OO . last_state_change = lisp_get_timestamp ( )
  ooO0oOoooo . append ( lisp_print_eid_tuple ( o0OoO00 , II1IIiIiiI1iI ) )
  if 73 - 73: i11iIiiIii . I1ii11iIi11i * OoOoOO00
  if 95 - 95: i1IIi + iIii1I11I1II1 . I1Ii111 / I1Ii111
 oO0IiI1iiII11II1 = bold ( "unreachable" , False )
 ii11IiI = red ( OooO0ooO0o0OO . rloc . print_address_no_iid ( ) , False )
 if 81 - 81: I1IiiI . I1Ii111
 for I111o0oooO00o0 in ooO0oOoooo :
  o0OoO00 = green ( I111o0oooO00o0 , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( ii11IiI , oO0IiI1iiII11II1 , o0OoO00 ) )
  if 74 - 74: II111iiii - o0oOOo0O0Ooo + ooOoO0o - iIii1I11I1II1 / OoO0O00
  if 89 - 89: I1Ii111 + ooOoO0o + I1Ii111
  if 35 - 35: O0 * OoOoOO00
  if 54 - 54: O0 / Oo0Ooo
  if 54 - 54: OoO0O00
  if 38 - 38: II111iiii + o0oOOo0O0Ooo * I11i + I1Ii111 - II111iiii . OOooOOo
 for OooO0ooO0o0OO , o0OoO00 , II1IIiIiiI1iI in eid_list :
  OoOoooooO00oo = lisp_map_cache . lookup_cache ( o0OoO00 , True )
  if ( OoOoooooO00oo ) : lisp_write_ipc_map_cache ( True , OoOoooooO00oo )
  if 38 - 38: I1ii11iIi11i % OOooOOo + iII111i / Oo0Ooo / IiII / oO0o
 return
 if 2 - 2: iIii1I11I1II1
 if 9 - 9: I1Ii111 / IiII
 if 33 - 33: o0oOOo0O0Ooo + oO0o . o0oOOo0O0Ooo . I11i * OoooooooOO + iIii1I11I1II1
 if 64 - 64: OoooooooOO . Ii1I
 if 38 - 38: Oo0Ooo
 if 64 - 64: ooOoO0o % i11iIiiIii
 if 10 - 10: Ii1I % oO0o + oO0o * OoOoOO00 % iII111i / o0oOOo0O0Ooo
 if 17 - 17: iII111i / I1IiiI . II111iiii - OoO0O00 + iII111i
 if 22 - 22: Oo0Ooo - I1ii11iIi11i + I11i . oO0o
 if 85 - 85: iIii1I11I1II1 / Ii1I
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 97 - 97: I1Ii111 + I1ii11iIi11i
 if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
 if 80 - 80: I11i
 if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
 if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
 if 46 - 46: Oo0Ooo / Oo0Ooo * IiII
 if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
 o0Oo0O00oo = lisp_get_default_route_next_hops ( )
 if 11 - 11: I1ii11iIi11i + iIii1I11I1II1 - I1Ii111 * iIii1I11I1II1 * IiII + oO0o
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 6 - 6: I1Ii111 * OOooOOo + i1IIi - Ii1I / oO0o
 if 81 - 81: I1Ii111 % oO0o * i1IIi * OoooooooOO / Oo0Ooo
 if 70 - 70: I1IiiI
 if 35 - 35: i11iIiiIii
 if 59 - 59: ooOoO0o . iII111i - II111iiii
 OoO = 0
 Ii1I11IiI1I1 = bold ( "RLOC-probe" , False )
 for iII1ii1IiII in lisp_rloc_probe_list . values ( ) :
  if 26 - 26: Ii1I * Oo0Ooo + II111iiii + Ii1I
  if 70 - 70: I1ii11iIi11i + i1IIi
  if 54 - 54: I1IiiI - i11iIiiIii - i11iIiiIii / oO0o
  if 43 - 43: I11i / OOooOOo + OOooOOo
  if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
  oo0OOoOOOO = None
  for iiIiII1iiI1i1 , I111o0oooO00o0 , oOoooOOO0o0 in iII1ii1IiII :
   oOo0O = iiIiII1iiI1i1 . rloc . print_address_no_iid ( )
   if 63 - 63: iIii1I11I1II1 . OoooooooOO
   if 78 - 78: I1IiiI / iIii1I11I1II1 / I1IiiI
   if 21 - 21: oO0o - IiII
   if 61 - 61: o0oOOo0O0Ooo
   OoOO0OOOO0 , o0oO , oOoOoO0Oo0oo = lisp_allow_gleaning ( I111o0oooO00o0 , None , iiIiII1iiI1i1 )
   if ( o0oO == False ) :
    o0OoO00 = green ( I111o0oooO00o0 . print_address ( ) , False )
    oOo0O += ":{}" . format ( iiIiII1iiI1i1 . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( oOo0O , False ) , o0OoO00 ) )
    if 72 - 72: Oo0Ooo - OoOoOO00 . II111iiii - Ii1I
    continue
    if 22 - 22: O0 . OoooooooOO + o0oOOo0O0Ooo / Oo0Ooo . iIii1I11I1II1
    if 30 - 30: OoOoOO00 + ooOoO0o + i1IIi . OoooooooOO . i11iIiiIii
    if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
    if 41 - 41: IiII % II111iiii
    if 99 - 99: IiII - O0
    if 59 - 59: iII111i % O0 + OOooOOo * ooOoO0o
    if 27 - 27: I1Ii111 % i11iIiiIii * I1IiiI
   if ( iiIiII1iiI1i1 . down_state ( ) ) : continue
   if 19 - 19: OoOoOO00 / o0oOOo0O0Ooo - iII111i / OoO0O00
   if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
   if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
   if 89 - 89: Ii1I * Oo0Ooo / I1Ii111 * I1ii11iIi11i + O0 * Oo0Ooo
   if 74 - 74: I11i . I11i
   if 74 - 74: OoOoOO00 * ooOoO0o * I1Ii111
   if 56 - 56: iIii1I11I1II1 * OoO0O00 - oO0o * Ii1I
   if 62 - 62: i1IIi + I11i / OOooOOo - OoooooooOO % i1IIi . I1IiiI
   if 13 - 13: O0 * iII111i
   if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
   if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
   if ( oo0OOoOOOO ) :
    iiIiII1iiI1i1 . last_rloc_probe_nonce = oo0OOoOOOO . last_rloc_probe_nonce
    if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
    if ( oo0OOoOOOO . translated_port == iiIiII1iiI1i1 . translated_port and oo0OOoOOOO . rloc_name == iiIiII1iiI1i1 . rloc_name ) :
     if 47 - 47: I1Ii111 * iII111i
     o0OoO00 = green ( lisp_print_eid_tuple ( I111o0oooO00o0 , oOoooOOO0o0 ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( oOo0O , False ) , o0OoO00 ) )
     if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
     continue
     if 76 - 76: iIii1I11I1II1 . i11iIiiIii * II111iiii - iII111i
     if 51 - 51: I1IiiI
     if 52 - 52: I1Ii111
   I1ii1I1II11II = None
   OooO0ooO0o0OO = None
   while ( True ) :
    OooO0ooO0o0OO = iiIiII1iiI1i1 if OooO0ooO0o0OO == None else OooO0ooO0o0OO . next_rloc
    if ( OooO0ooO0o0OO == None ) : break
    if 82 - 82: iII111i + II111iiii
    if 29 - 29: O0 % Ii1I * ooOoO0o % O0
    if 83 - 83: oO0o
    if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
    if 85 - 85: iIii1I11I1II1 / I11i
    if ( OooO0ooO0o0OO . rloc_next_hop != None ) :
     if ( OooO0ooO0o0OO . rloc_next_hop not in o0Oo0O00oo ) :
      if ( OooO0ooO0o0OO . up_state ( ) ) :
       Ii , oooOoo0 = OooO0ooO0o0OO . rloc_next_hop
       OooO0ooO0o0OO . state = LISP_RLOC_UNREACH_STATE
       OooO0ooO0o0OO . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( OooO0ooO0o0OO . rloc , False )
       if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
      oO0IiI1iiII11II1 = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( oooOoo0 , Ii ,
 red ( oOo0O , False ) , oO0IiI1iiII11II1 ) )
      continue
      if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
      if 20 - 20: OOooOOo % i1IIi * Ii1I / i11iIiiIii
      if 89 - 89: ooOoO0o
      if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
      if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
      if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
    i11 = OooO0ooO0o0OO . last_rloc_probe
    iIi1i1iIi1 = 0 if i11 == None else time . time ( ) - i11
    if ( OooO0ooO0o0OO . unreach_state ( ) and iIi1i1iIi1 < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( oOo0O , False ) ) )
     if 23 - 23: ooOoO0o + Oo0Ooo
     continue
     if 43 - 43: Ii1I
     if 87 - 87: OoO0O00
     if 32 - 32: I11i
     if 78 - 78: ooOoO0o * iII111i
     if 31 - 31: I1IiiI + OOooOOo . OoooooooOO
     if 24 - 24: ooOoO0o
    oOo0ooO0O0oo = lisp_get_echo_nonce ( None , oOo0O )
    if ( oOo0ooO0O0oo and oOo0ooO0O0oo . request_nonce_timeout ( ) ) :
     OooO0ooO0o0OO . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     OooO0ooO0o0OO . last_state_change = lisp_get_timestamp ( )
     oO0IiI1iiII11II1 = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( oOo0O , False ) , oO0IiI1iiII11II1 ) )
     if 53 - 53: I1ii11iIi11i % OOooOOo
     lisp_update_rtr_updown ( OooO0ooO0o0OO . rloc , False )
     continue
     if 92 - 92: I1IiiI / ooOoO0o
     if 5 - 5: OoooooooOO - oO0o
     if 52 - 52: I11i . OOooOOo * ooOoO0o / i11iIiiIii . OoO0O00 * ooOoO0o
     if 58 - 58: i1IIi - OoO0O00 * II111iiii
     if 92 - 92: ooOoO0o / I1Ii111 . iII111i
     if 59 - 59: Ii1I - OoO0O00 % iII111i + I1ii11iIi11i * iII111i
    if ( oOo0ooO0O0oo and oOo0ooO0O0oo . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( oOo0O , False ) ) )
     if 51 - 51: ooOoO0o - Oo0Ooo / iII111i . I11i - Ii1I / OOooOOo
     continue
     if 4 - 4: II111iiii + OoOoOO00 . ooOoO0o - I11i . I1IiiI
     if 46 - 46: II111iiii
     if 38 - 38: OOooOOo % II111iiii
     if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
     if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
     if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
    if ( OooO0ooO0o0OO . last_rloc_probe != None ) :
     i11 = OooO0ooO0o0OO . last_rloc_probe_reply
     if ( i11 == None ) : i11 = 0
     iIi1i1iIi1 = time . time ( ) - i11
     if ( OooO0ooO0o0OO . up_state ( ) and iIi1i1iIi1 >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 89 - 89: I1Ii111
      OooO0ooO0o0OO . state = LISP_RLOC_UNREACH_STATE
      OooO0ooO0o0OO . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( OooO0ooO0o0OO . rloc , False )
      oO0IiI1iiII11II1 = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( oOo0O , False ) , oO0IiI1iiII11II1 ) )
      if 29 - 29: I11i * ooOoO0o - OoooooooOO
      if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
      lisp_mark_rlocs_for_other_eids ( iII1ii1IiII )
      if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
      if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
      if 73 - 73: OoooooooOO
    OooO0ooO0o0OO . last_rloc_probe = lisp_get_timestamp ( )
    if 25 - 25: i1IIi . II111iiii . I1Ii111
    Oo0OooO = "" if OooO0ooO0o0OO . unreach_state ( ) == False else " unreachable"
    if 12 - 12: oO0o + iII111i - ooOoO0o % O0 + I1Ii111
    if 15 - 15: I1Ii111 * iIii1I11I1II1 - iIii1I11I1II1 - O0
    if 41 - 41: O0 - i11iIiiIii - I1Ii111 + i1IIi - iIii1I11I1II1 . Oo0Ooo
    if 38 - 38: Oo0Ooo - I1ii11iIi11i
    if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
    if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
    if 3 - 3: Ii1I
    OoI1i1 = ""
    oooOoo0 = None
    if ( OooO0ooO0o0OO . rloc_next_hop != None ) :
     Ii , oooOoo0 = OooO0ooO0o0OO . rloc_next_hop
     lisp_install_host_route ( oOo0O , oooOoo0 , True )
     OoI1i1 = ", send on nh {}({})" . format ( oooOoo0 , Ii )
     if 73 - 73: OoO0O00 / iII111i
     if 40 - 40: I11i + IiII * Oo0Ooo . OoooooooOO * I1IiiI
     if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
     if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
     if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
    I1i1IIiI = OooO0ooO0o0OO . print_rloc_probe_rtt ( )
    O0oiIIi1 = oOo0O
    if ( OooO0ooO0o0OO . translated_port != 0 ) :
     O0oiIIi1 += ":{}" . format ( OooO0ooO0o0OO . translated_port )
     if 32 - 32: OOooOOo % O0 * II111iiii % OoO0O00 - I1IiiI * OOooOOo
    O0oiIIi1 = red ( O0oiIIi1 , False )
    if ( OooO0ooO0o0OO . rloc_name != None ) :
     O0oiIIi1 += " (" + blue ( OooO0ooO0o0OO . rloc_name , False ) + ")"
     if 80 - 80: OOooOOo * I11i / OOooOOo - oO0o
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( Ii1I11IiI1I1 , Oo0OooO ,
 O0oiIIi1 , I1i1IIiI , OoI1i1 ) )
    if 18 - 18: i1IIi - OOooOOo - o0oOOo0O0Ooo - iIii1I11I1II1
    if 72 - 72: OoooooooOO % I1IiiI . OoO0O00
    if 28 - 28: II111iiii / iIii1I11I1II1 / iII111i - o0oOOo0O0Ooo . I1IiiI / O0
    if 16 - 16: ooOoO0o * oO0o . OoooooooOO
    if 44 - 44: iIii1I11I1II1 * OOooOOo + OoO0O00 - OoooooooOO
    if 13 - 13: Oo0Ooo . I11i . II111iiii
    if 6 - 6: OOooOOo . IiII / OoO0O00 * oO0o - I1Ii111 . OoOoOO00
    if 85 - 85: i11iIiiIii + OoOoOO00
    if ( OooO0ooO0o0OO . rloc_next_hop != None ) :
     I1ii1I1II11II = lisp_get_host_route_next_hop ( oOo0O )
     if ( I1ii1I1II11II ) : lisp_install_host_route ( oOo0O , I1ii1I1II11II , False )
     if 4 - 4: OOooOOo . OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
     if 60 - 60: OOooOOo . Ii1I
     if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
     if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
     if 38 - 38: IiII / I11i / IiII * iII111i
     if 30 - 30: oO0o
    if ( OooO0ooO0o0OO . rloc . is_null ( ) ) :
     OooO0ooO0o0OO . rloc . copy_address ( iiIiII1iiI1i1 . rloc )
     if 30 - 30: IiII / OoO0O00
     if 89 - 89: oO0o . OoOoOO00 . IiII / iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00
     if 86 - 86: OoooooooOO - iIii1I11I1II1 . OoO0O00 * Ii1I / I1Ii111 + I1Ii111
     if 52 - 52: iIii1I11I1II1 % OoO0O00 - IiII % i11iIiiIii - o0oOOo0O0Ooo
     if 25 - 25: Oo0Ooo - OOooOOo . i1IIi * OoOoOO00 / I11i / o0oOOo0O0Ooo
    Oooo0OOO0oo0o = None if ( oOoooOOO0o0 . is_null ( ) ) else I111o0oooO00o0
    OOOoOO0o00o0o = I111o0oooO00o0 if ( oOoooOOO0o0 . is_null ( ) ) else oOoooOOO0o0
    lisp_send_map_request ( lisp_sockets , 0 , Oooo0OOO0oo0o , OOOoOO0o00o0o , OooO0ooO0o0OO )
    oo0OOoOOOO = iiIiII1iiI1i1
    if 17 - 17: i1IIi - ooOoO0o
    if 86 - 86: I1ii11iIi11i . o0oOOo0O0Ooo
    if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
    if 33 - 33: OOooOOo % OoooooooOO
    if ( oooOoo0 ) : lisp_install_host_route ( oOo0O , oooOoo0 , False )
    if 98 - 98: Ii1I
    if 38 - 38: ooOoO0o - iII111i * OOooOOo % I1ii11iIi11i + Oo0Ooo
    if 95 - 95: iIii1I11I1II1 / O0 % O0
    if 53 - 53: ooOoO0o . ooOoO0o
    if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
   if ( I1ii1I1II11II ) : lisp_install_host_route ( oOo0O , I1ii1I1II11II , True )
   if 18 - 18: OoO0O00 * ooOoO0o
   if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
   if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
   if 67 - 67: I1IiiI
   OoO += 1
   if ( ( OoO % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
   if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
   if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 59 - 59: i11iIiiIii
 if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
 if 59 - 59: I1ii11iIi11i
 if 47 - 47: I1IiiI + Oo0Ooo
 if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
 if 10 - 10: i1IIi % ooOoO0o / iII111i
 if 98 - 98: IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
 if 65 - 65: Ii1I + OoOoOO00 * Oo0Ooo . O0 . IiII
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
 if 34 - 34: I1ii11iIi11i . i1IIi * O0 / OoooooooOO
 if 22 - 22: OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
 if 58 - 58: IiII . Ii1I + II111iiii
 if ( lisp_i_am_itr == False ) : return
 if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
 if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
 if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 if ( lisp_register_all_rtrs ) : return
 if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
 OOoOOo0o0oo0Ooo = rtr . print_address_no_iid ( )
 if 16 - 16: I11i - ooOoO0o
 if 54 - 54: oO0o * II111iiii
 if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
 if 98 - 98: ooOoO0o
 if 73 - 73: I1Ii111
 if ( lisp_rtr_list . has_key ( OOoOOo0o0oo0Ooo ) == False ) : return
 if 97 - 97: OoO0O00 * Ii1I + Oo0Ooo
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( OOoOOo0o0oo0Ooo , False ) , bold ( updown , False ) ) )
 if 83 - 83: II111iiii - Oo0Ooo % II111iiii * o0oOOo0O0Ooo
 if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
 if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
 if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
 oOO0O = "rtr%{}%{}" . format ( OOoOOo0o0oo0Ooo , updown )
 oOO0O = lisp_command_ipc ( oOO0O , "lisp-itr" )
 lisp_ipc ( oOO0O , lisp_ipc_socket , "lisp-etr" )
 return
 if 76 - 76: iII111i * OOooOOo
 if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
 if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
 if 40 - 40: iII111i
 if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
 if 33 - 33: OoooooooOO
def lisp_process_rloc_probe_reply ( rloc , source , port , nonce , hop_count , ttl ) :
 Ii1I11IiI1I1 = bold ( "RLOC-probe reply" , False )
 Ooooo00o0 = rloc . print_address_no_iid ( )
 Ii1IIi1 = source . print_address_no_iid ( )
 oOO0O0OoooO00O = lisp_rloc_probe_list
 if 17 - 17: II111iiii
 if 91 - 91: oO0o - oO0o % Ii1I % iIii1I11I1II1 / OoOoOO00
 if 60 - 60: I1IiiI / iIii1I11I1II1 - o0oOOo0O0Ooo / OoooooooOO * OoooooooOO
 if 22 - 22: I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo . i1IIi * OoO0O00
 if 7 - 7: O0 / I1IiiI + OoO0O00 . i1IIi - ooOoO0o + ooOoO0o
 if 93 - 93: oO0o - I1IiiI / I1ii11iIi11i % o0oOOo0O0Ooo / OoooooooOO + II111iiii
 O0o00o000oO = Ooooo00o0
 if ( oOO0O0OoooO00O . has_key ( O0o00o000oO ) == False ) :
  O0o00o000oO += ":" + str ( port )
  if ( oOO0O0OoooO00O . has_key ( O0o00o000oO ) == False ) :
   O0o00o000oO = Ii1IIi1
   if ( oOO0O0OoooO00O . has_key ( O0o00o000oO ) == False ) :
    O0o00o000oO += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( Ii1I11IiI1I1 , red ( Ooooo00o0 , False ) , red ( Ii1IIi1 ,
    # I1Ii111
 False ) , port ) )
    return
    if 56 - 56: iII111i . O0 + OoO0O00 - I1ii11iIi11i
    if 37 - 37: Oo0Ooo
    if 3 - 3: Oo0Ooo
    if 73 - 73: i11iIiiIii / iII111i + O0 * I1IiiI * i1IIi
    if 75 - 75: iIii1I11I1II1 / II111iiii / I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
    if 16 - 16: I11i
    if 55 - 55: OoO0O00
    if 87 - 87: Ii1I - iII111i / O0 - o0oOOo0O0Ooo - iIii1I11I1II1 % Ii1I
 for rloc , I111o0oooO00o0 , oOoooOOO0o0 in lisp_rloc_probe_list [ O0o00o000oO ] :
  if ( lisp_i_am_rtr and rloc . translated_port != 0 and
 rloc . translated_port != port ) : continue
  if 47 - 47: iII111i * I1Ii111 % o0oOOo0O0Ooo / OoOoOO00 / OoO0O00 % OoO0O00
  rloc . process_rloc_probe_reply ( nonce , I111o0oooO00o0 , oOoooOOO0o0 , hop_count , ttl )
  if 43 - 43: Oo0Ooo
 return
 if 34 - 34: OoO0O00 . i1IIi + IiII * IiII
 if 76 - 76: OOooOOo
 if 54 - 54: O0 * II111iiii * OOooOOo
 if 44 - 44: I1IiiI
 if 66 - 66: o0oOOo0O0Ooo
 if 40 - 40: OOooOOo * Ii1I
 if 38 - 38: ooOoO0o
 if 5 - 5: OoooooooOO + iII111i - I11i
def lisp_db_list_length ( ) :
 OoO = 0
 for o00o0oOo0o0O in lisp_db_list :
  OoO += len ( o00o0oOo0o0O . dynamic_eids ) if o00o0oOo0o0O . dynamic_eid_configured ( ) else 1
  OoO += len ( o00o0oOo0o0O . eid . iid_list )
  if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
 return ( OoO )
 if 7 - 7: I1ii11iIi11i
 if 37 - 37: O0 . II111iiii
 if 70 - 70: o0oOOo0O0Ooo / iII111i + i1IIi + I11i % iIii1I11I1II1 % Oo0Ooo
 if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
 if 1 - 1: I1ii11iIi11i / i1IIi . I1IiiI / Ii1I
 if 19 - 19: iIii1I11I1II1 / Oo0Ooo . O0 - Oo0Ooo
 if 74 - 74: I1ii11iIi11i * OoooooooOO . iII111i
 if 45 - 45: I1IiiI - IiII % ooOoO0o - IiII . Oo0Ooo - o0oOOo0O0Ooo
def lisp_is_myeid ( eid ) :
 for o00o0oOo0o0O in lisp_db_list :
  if ( eid . is_more_specific ( o00o0oOo0o0O . eid ) ) : return ( True )
  if 27 - 27: iII111i
 return ( False )
 if 64 - 64: iIii1I11I1II1 - OOooOOo . iII111i % o0oOOo0O0Ooo / II111iiii % OoooooooOO
 if 87 - 87: OoooooooOO
 if 70 - 70: o0oOOo0O0Ooo % OoooooooOO % I1IiiI . OoOoOO00 * I1IiiI - ooOoO0o
 if 92 - 92: I1IiiI . I11i
 if 66 - 66: I1Ii111 / I11i / OoooooooOO % OoOoOO00 . oO0o * iII111i
 if 34 - 34: I1ii11iIi11i * I1ii11iIi11i % I11i / OOooOOo % oO0o . OoOoOO00
 if 25 - 25: I1ii11iIi11i / I11i + i1IIi . I1IiiI + ooOoO0o
 if 29 - 29: IiII + I1ii11iIi11i
 if 8 - 8: IiII % I1IiiI
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 10 - 10: OoooooooOO / OoOoOO00
 if 77 - 77: OoOoOO00
 if 10 - 10: IiII / i11iIiiIii
 if 19 - 19: OoO0O00
 if 100 - 100: I1ii11iIi11i - I1ii11iIi11i
 if 38 - 38: I1Ii111
 if 23 - 23: Ii1I . I1ii11iIi11i + I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 oOo0ooO0O0oo = None
 if ( lisp_nonce_echo_list . has_key ( rloc_str ) ) :
  oOo0ooO0O0oo = lisp_nonce_echo_list [ rloc_str ]
  if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
 return ( oOo0ooO0O0oo )
 if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
 if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
 if 40 - 40: iII111i - I1IiiI + OoOoOO00
 if 2 - 2: I11i - II111iiii / I1Ii111
 if 27 - 27: OoO0O00 - I1ii11iIi11i * i11iIiiIii + Oo0Ooo
 if 29 - 29: I1ii11iIi11i / IiII . I1Ii111 + Ii1I + OoO0O00
 if 76 - 76: ooOoO0o . I11i * OoO0O00
def lisp_decode_dist_name ( packet ) :
 OoO = 0
 OooO = ""
 if 89 - 89: o0oOOo0O0Ooo - OOooOOo * I1Ii111 . i1IIi % I1IiiI . I11i
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( OoO == 255 ) : return ( [ None , None ] )
  OooO += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  OoO += 1
  if 99 - 99: I1Ii111 * ooOoO0o
  if 9 - 9: I1Ii111
 packet = packet [ 1 : : ]
 return ( packet , OooO )
 if 26 - 26: iIii1I11I1II1 - I11i . Oo0Ooo - I1Ii111
 if 3 - 3: I1IiiI + I1ii11iIi11i - I11i
 if 15 - 15: OoOoOO00 . Oo0Ooo / ooOoO0o + Oo0Ooo - OoooooooOO - o0oOOo0O0Ooo
 if 64 - 64: OOooOOo
 if 44 - 44: O0 % ooOoO0o - iIii1I11I1II1 * i11iIiiIii . OoOoOO00
 if 32 - 32: I1ii11iIi11i - iII111i
 if 34 - 34: OOooOOo . i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1ii11iIi11i
 if 32 - 32: i11iIiiIii . I1Ii111
def lisp_write_flow_log ( flow_log ) :
 iI1IiI11Ii11i = open ( "./logs/lisp-flow.log" , "a" )
 if 38 - 38: O0
 OoO = 0
 for iiIiIIIIiI in flow_log :
  ii1i1II = iiIiIIIIiI [ 3 ]
  IiIIi11i1I1iI = ii1i1II . print_flow ( iiIiIIIIiI [ 0 ] , iiIiIIIIiI [ 1 ] , iiIiIIIIiI [ 2 ] )
  iI1IiI11Ii11i . write ( IiIIi11i1I1iI )
  OoO += 1
  if 15 - 15: o0oOOo0O0Ooo / Ii1I + Ii1I
 iI1IiI11Ii11i . close ( )
 del ( flow_log )
 if 59 - 59: II111iiii - o0oOOo0O0Ooo * OoooooooOO
 OoO = bold ( str ( OoO ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( OoO ) )
 return
 if 83 - 83: oO0o . iIii1I11I1II1 . iII111i % Oo0Ooo
 if 48 - 48: oO0o % OoO0O00 - OoooooooOO . IiII
 if 11 - 11: I1Ii111 % o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i
 if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
 if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
def lisp_policy_command ( kv_pair ) :
 iIiiI11II11 = lisp_policy ( "" )
 O000i11II11I = None
 if 43 - 43: iIii1I11I1II1
 i1iI11i = [ ]
 for i1i1IIIIIIIi in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  i1iI11i . append ( lisp_policy_match ( ) )
  if 89 - 89: I11i + iII111i / i11iIiiIii
  if 46 - 46: ooOoO0o + ooOoO0o / IiII
 for oOO0ooo in kv_pair . keys ( ) :
  Oooo0oOOO0 = kv_pair [ oOO0ooo ]
  if 7 - 7: i11iIiiIii - i11iIiiIii % OoOoOO00 . I11i % i1IIi - Oo0Ooo
  if 84 - 84: I11i . o0oOOo0O0Ooo / ooOoO0o + OoooooooOO
  if 83 - 83: Oo0Ooo / i1IIi * O0 % OoOoOO00 * OoOoOO00 + i1IIi
  if 66 - 66: O0 % o0oOOo0O0Ooo . oO0o * i11iIiiIii + Oo0Ooo
  if ( oOO0ooo == "instance-id" ) :
   for i1i1IIIIIIIi in range ( len ( i1iI11i ) ) :
    IIoOo0000oooooo = Oooo0oOOO0 [ i1i1IIIIIIIi ]
    if ( IIoOo0000oooooo == "" ) : continue
    o0o0oO00O00OO = i1iI11i [ i1i1IIIIIIIi ]
    if ( o0o0oO00O00OO . source_eid == None ) :
     o0o0oO00O00OO . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 80 - 80: iIii1I11I1II1
    if ( o0o0oO00O00OO . dest_eid == None ) :
     o0o0oO00O00OO . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 41 - 41: I11i + I1IiiI + oO0o . Ii1I
    o0o0oO00O00OO . source_eid . instance_id = int ( IIoOo0000oooooo )
    o0o0oO00O00OO . dest_eid . instance_id = int ( IIoOo0000oooooo )
    if 71 - 71: iIii1I11I1II1 / I1ii11iIi11i + OoooooooOO . ooOoO0o
    if 63 - 63: i11iIiiIii % I1Ii111 % IiII * i1IIi + I1Ii111 + I1Ii111
  if ( oOO0ooo == "source-eid" ) :
   for i1i1IIIIIIIi in range ( len ( i1iI11i ) ) :
    IIoOo0000oooooo = Oooo0oOOO0 [ i1i1IIIIIIIi ]
    if ( IIoOo0000oooooo == "" ) : continue
    o0o0oO00O00OO = i1iI11i [ i1i1IIIIIIIi ]
    if ( o0o0oO00O00OO . source_eid == None ) :
     o0o0oO00O00OO . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 51 - 51: iII111i / Ii1I . iII111i + O0 / IiII + OoooooooOO
    oOo00Ooo0o0 = o0o0oO00O00OO . source_eid . instance_id
    o0o0oO00O00OO . source_eid . store_prefix ( IIoOo0000oooooo )
    o0o0oO00O00OO . source_eid . instance_id = oOo00Ooo0o0
    if 29 - 29: I1IiiI - OOooOOo
    if 83 - 83: OoOoOO00 * oO0o . OOooOOo - OoO0O00
  if ( oOO0ooo == "destination-eid" ) :
   for i1i1IIIIIIIi in range ( len ( i1iI11i ) ) :
    IIoOo0000oooooo = Oooo0oOOO0 [ i1i1IIIIIIIi ]
    if ( IIoOo0000oooooo == "" ) : continue
    o0o0oO00O00OO = i1iI11i [ i1i1IIIIIIIi ]
    if ( o0o0oO00O00OO . dest_eid == None ) :
     o0o0oO00O00OO . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 73 - 73: I1ii11iIi11i / iII111i / Oo0Ooo
    oOo00Ooo0o0 = o0o0oO00O00OO . dest_eid . instance_id
    o0o0oO00O00OO . dest_eid . store_prefix ( IIoOo0000oooooo )
    o0o0oO00O00OO . dest_eid . instance_id = oOo00Ooo0o0
    if 85 - 85: Ii1I
    if 67 - 67: i11iIiiIii / II111iiii . i11iIiiIii * i11iIiiIii / ooOoO0o . oO0o
  if ( oOO0ooo == "source-rloc" ) :
   for i1i1IIIIIIIi in range ( len ( i1iI11i ) ) :
    IIoOo0000oooooo = Oooo0oOOO0 [ i1i1IIIIIIIi ]
    if ( IIoOo0000oooooo == "" ) : continue
    o0o0oO00O00OO = i1iI11i [ i1i1IIIIIIIi ]
    o0o0oO00O00OO . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    o0o0oO00O00OO . source_rloc . store_prefix ( IIoOo0000oooooo )
    if 46 - 46: oO0o . OoO0O00 - iIii1I11I1II1 . IiII
    if 52 - 52: i11iIiiIii / O0 + oO0o . I11i
  if ( oOO0ooo == "destination-rloc" ) :
   for i1i1IIIIIIIi in range ( len ( i1iI11i ) ) :
    IIoOo0000oooooo = Oooo0oOOO0 [ i1i1IIIIIIIi ]
    if ( IIoOo0000oooooo == "" ) : continue
    o0o0oO00O00OO = i1iI11i [ i1i1IIIIIIIi ]
    o0o0oO00O00OO . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    o0o0oO00O00OO . dest_rloc . store_prefix ( IIoOo0000oooooo )
    if 73 - 73: OoooooooOO / I1IiiI % Oo0Ooo . oO0o + OoooooooOO
    if 84 - 84: I1ii11iIi11i - OOooOOo * II111iiii
  if ( oOO0ooo == "rloc-record-name" ) :
   for i1i1IIIIIIIi in range ( len ( i1iI11i ) ) :
    IIoOo0000oooooo = Oooo0oOOO0 [ i1i1IIIIIIIi ]
    if ( IIoOo0000oooooo == "" ) : continue
    o0o0oO00O00OO = i1iI11i [ i1i1IIIIIIIi ]
    o0o0oO00O00OO . rloc_record_name = IIoOo0000oooooo
    if 28 - 28: I1ii11iIi11i . oO0o / o0oOOo0O0Ooo - iII111i
    if 65 - 65: I1ii11iIi11i * OOooOOo * ooOoO0o + oO0o - OOooOOo
  if ( oOO0ooo == "geo-name" ) :
   for i1i1IIIIIIIi in range ( len ( i1iI11i ) ) :
    IIoOo0000oooooo = Oooo0oOOO0 [ i1i1IIIIIIIi ]
    if ( IIoOo0000oooooo == "" ) : continue
    o0o0oO00O00OO = i1iI11i [ i1i1IIIIIIIi ]
    o0o0oO00O00OO . geo_name = IIoOo0000oooooo
    if 100 - 100: iII111i
    if 12 - 12: OoooooooOO - I1ii11iIi11i * iII111i / ooOoO0o
  if ( oOO0ooo == "elp-name" ) :
   for i1i1IIIIIIIi in range ( len ( i1iI11i ) ) :
    IIoOo0000oooooo = Oooo0oOOO0 [ i1i1IIIIIIIi ]
    if ( IIoOo0000oooooo == "" ) : continue
    o0o0oO00O00OO = i1iI11i [ i1i1IIIIIIIi ]
    o0o0oO00O00OO . elp_name = IIoOo0000oooooo
    if 99 - 99: I1ii11iIi11i + I11i
    if 29 - 29: I1ii11iIi11i / oO0o
  if ( oOO0ooo == "rle-name" ) :
   for i1i1IIIIIIIi in range ( len ( i1iI11i ) ) :
    IIoOo0000oooooo = Oooo0oOOO0 [ i1i1IIIIIIIi ]
    if ( IIoOo0000oooooo == "" ) : continue
    o0o0oO00O00OO = i1iI11i [ i1i1IIIIIIIi ]
    o0o0oO00O00OO . rle_name = IIoOo0000oooooo
    if 2 - 2: Oo0Ooo / IiII - OoooooooOO
    if 65 - 65: OoO0O00 - Ii1I
  if ( oOO0ooo == "json-name" ) :
   for i1i1IIIIIIIi in range ( len ( i1iI11i ) ) :
    IIoOo0000oooooo = Oooo0oOOO0 [ i1i1IIIIIIIi ]
    if ( IIoOo0000oooooo == "" ) : continue
    o0o0oO00O00OO = i1iI11i [ i1i1IIIIIIIi ]
    o0o0oO00O00OO . json_name = IIoOo0000oooooo
    if 98 - 98: OoOoOO00 * I1Ii111 * iIii1I11I1II1 * OoOoOO00
    if 15 - 15: Oo0Ooo
  if ( oOO0ooo == "datetime-range" ) :
   for i1i1IIIIIIIi in range ( len ( i1iI11i ) ) :
    IIoOo0000oooooo = Oooo0oOOO0 [ i1i1IIIIIIIi ]
    o0o0oO00O00OO = i1iI11i [ i1i1IIIIIIIi ]
    if ( IIoOo0000oooooo == "" ) : continue
    o0000oO = lisp_datetime ( IIoOo0000oooooo [ 0 : 19 ] )
    I11I1i1 = lisp_datetime ( IIoOo0000oooooo [ 19 : : ] )
    if ( o0000oO . valid_datetime ( ) and I11I1i1 . valid_datetime ( ) ) :
     o0o0oO00O00OO . datetime_lower = o0000oO
     o0o0oO00O00OO . datetime_upper = I11I1i1
     if 100 - 100: IiII + I1ii11iIi11i + iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
     if 84 - 84: o0oOOo0O0Ooo * I11i
     if 22 - 22: i1IIi + OOooOOo % OoooooooOO
     if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
     if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
     if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
     if 66 - 66: OoooooooOO
  if ( oOO0ooo == "set-action" ) :
   iIiiI11II11 . set_action = Oooo0oOOO0
   if 90 - 90: IiII - OoOoOO00
  if ( oOO0ooo == "set-record-ttl" ) :
   iIiiI11II11 . set_record_ttl = int ( Oooo0oOOO0 )
   if 98 - 98: Oo0Ooo / oO0o . Ii1I
  if ( oOO0ooo == "set-instance-id" ) :
   if ( iIiiI11II11 . set_source_eid == None ) :
    iIiiI11II11 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
   if ( iIiiI11II11 . set_dest_eid == None ) :
    iIiiI11II11 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 37 - 37: iII111i - Ii1I . oO0o
   O000i11II11I = int ( Oooo0oOOO0 )
   iIiiI11II11 . set_source_eid . instance_id = O000i11II11I
   iIiiI11II11 . set_dest_eid . instance_id = O000i11II11I
   if 47 - 47: IiII / I1ii11iIi11i . o0oOOo0O0Ooo . ooOoO0o + OOooOOo . OOooOOo
  if ( oOO0ooo == "set-source-eid" ) :
   if ( iIiiI11II11 . set_source_eid == None ) :
    iIiiI11II11 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 25 - 25: oO0o
   iIiiI11II11 . set_source_eid . store_prefix ( Oooo0oOOO0 )
   if ( O000i11II11I != None ) : iIiiI11II11 . set_source_eid . instance_id = O000i11II11I
   if 43 - 43: Ii1I - o0oOOo0O0Ooo % oO0o - O0
  if ( oOO0ooo == "set-destination-eid" ) :
   if ( iIiiI11II11 . set_dest_eid == None ) :
    iIiiI11II11 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 20 - 20: OoO0O00 . ooOoO0o / OoOoOO00 - OoOoOO00 . iII111i / OOooOOo
   iIiiI11II11 . set_dest_eid . store_prefix ( Oooo0oOOO0 )
   if ( O000i11II11I != None ) : iIiiI11II11 . set_dest_eid . instance_id = O000i11II11I
   if 39 - 39: iIii1I11I1II1 % ooOoO0o
  if ( oOO0ooo == "set-rloc-address" ) :
   iIiiI11II11 . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   iIiiI11II11 . set_rloc_address . store_address ( Oooo0oOOO0 )
   if 75 - 75: i1IIi * II111iiii * O0 * i11iIiiIii % iII111i / iII111i
  if ( oOO0ooo == "set-rloc-record-name" ) :
   iIiiI11II11 . set_rloc_record_name = Oooo0oOOO0
   if 36 - 36: IiII / I1IiiI % iII111i / iII111i
  if ( oOO0ooo == "set-elp-name" ) :
   iIiiI11II11 . set_elp_name = Oooo0oOOO0
   if 38 - 38: OOooOOo * I1ii11iIi11i * I1Ii111 + I11i
  if ( oOO0ooo == "set-geo-name" ) :
   iIiiI11II11 . set_geo_name = Oooo0oOOO0
   if 65 - 65: O0 + O0 * I1Ii111
  if ( oOO0ooo == "set-rle-name" ) :
   iIiiI11II11 . set_rle_name = Oooo0oOOO0
   if 66 - 66: OOooOOo / O0 + i1IIi . O0 % I1ii11iIi11i - OoooooooOO
  if ( oOO0ooo == "set-json-name" ) :
   iIiiI11II11 . set_json_name = Oooo0oOOO0
   if 16 - 16: I11i % iII111i
  if ( oOO0ooo == "policy-name" ) :
   iIiiI11II11 . policy_name = Oooo0oOOO0
   if 29 - 29: I1IiiI - ooOoO0o * OoO0O00 . i11iIiiIii % OoOoOO00 * o0oOOo0O0Ooo
   if 43 - 43: OoO0O00 * OOooOOo / I1Ii111 % OoOoOO00 . oO0o / OOooOOo
   if 62 - 62: O0 * I1ii11iIi11i - O0 / I11i % ooOoO0o
   if 1 - 1: O0 / iIii1I11I1II1
   if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
   if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
 iIiiI11II11 . match_clauses = i1iI11i
 iIiiI11II11 . save_policy ( )
 return
 if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
 if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
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
if 16 - 16: o0oOOo0O0Ooo
if 3 - 3: i11iIiiIii . I1ii11iIi11i
if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
if 83 - 83: OoooooooOO % I1ii11iIi11i . IiII + OOooOOo . iII111i - ooOoO0o
if 100 - 100: o0oOOo0O0Ooo
if 95 - 95: iII111i * oO0o * i1IIi
if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 oOoOOOo00oOOoO0 = command
 if ( interface != "" ) : oOoOOOo00oOOoO0 = interface + ": " + oOoOOOo00oOOoO0
 lprint ( "Send CLI command '{}' to hardware" . format ( oOoOOOo00oOOoO0 ) )
 if 85 - 85: i11iIiiIii + O0 % I1Ii111 + I1Ii111 + iIii1I11I1II1
 commands = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 74 - 74: I11i
 os . system ( "FastCli -c '{}'" . format ( commands ) )
 return
 if 92 - 92: OoOoOO00 + oO0o
 if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
 if 28 - 28: I1IiiI . iIii1I11I1II1
 if 12 - 12: I1Ii111 * OOooOOo
 if 11 - 11: II111iiii % O0 % O0 % o0oOOo0O0Ooo
 if 45 - 45: OoooooooOO * oO0o
 if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
def lisp_arista_is_alive ( prefix ) :
 OoOoOoo0OoO0 = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 o0OooooOoOO = commands . getoutput ( "FastCli -c '{}'" . format ( OoOoOoo0OoO0 ) )
 if 16 - 16: Oo0Ooo
 if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
 if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 if 67 - 67: I1IiiI
 o0OooooOoOO = o0OooooOoOO . split ( "\n" ) [ 1 ]
 O0I11I = o0OooooOoOO . split ( " " )
 O0I11I = O0I11I [ - 1 ] . replace ( "\r" , "" )
 if 71 - 71: Ii1I % iIii1I11I1II1 + OoOoOO00
 if 19 - 19: I1IiiI % I1IiiI / I1ii11iIi11i + iIii1I11I1II1 % iII111i / i11iIiiIii
 if 30 - 30: i1IIi % o0oOOo0O0Ooo - I1ii11iIi11i
 if 72 - 72: iIii1I11I1II1 + OOooOOo * ooOoO0o * O0 - I1IiiI
 return ( O0I11I == "Y" )
 if 36 - 36: I11i / II111iiii . oO0o - ooOoO0o % iII111i % OoOoOO00
 if 13 - 13: iIii1I11I1II1 - Oo0Ooo % IiII / iII111i - I1Ii111
 if 46 - 46: OoO0O00 / iII111i
 if 21 - 21: iIii1I11I1II1 / I1Ii111 * I1ii11iIi11i / Oo0Ooo . Oo0Ooo
 if 2 - 2: Oo0Ooo + i11iIiiIii . I1ii11iIi11i * I1Ii111
 if 22 - 22: I1ii11iIi11i . i1IIi + I1ii11iIi11i / OoooooooOO - i11iIiiIii / iIii1I11I1II1
 if 96 - 96: o0oOOo0O0Ooo . I1Ii111 + Oo0Ooo . I11i + ooOoO0o
 if 33 - 33: OoO0O00 / OOooOOo % Oo0Ooo . o0oOOo0O0Ooo % II111iiii
 if 62 - 62: iII111i . OoooooooOO - i1IIi
 if 59 - 59: OoOoOO00 + i1IIi * OoooooooOO . oO0o
 if 38 - 38: I1ii11iIi11i / o0oOOo0O0Ooo
 if 95 - 95: iIii1I11I1II1 / OoOoOO00 % I1Ii111
 if 54 - 54: OoooooooOO % Ii1I
 if 100 - 100: OOooOOo - I11i . O0 * i1IIi % OoooooooOO - ooOoO0o
 if 54 - 54: O0 + I11i
 if 71 - 71: OoOoOO00
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
 if 23 - 23: OoOoOO00 * I1Ii111
 if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
 if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
 if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
 if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
 if 25 - 25: OoO0O00 * oO0o
 if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
 if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
 if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
 if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
 if 73 - 73: Oo0Ooo + II111iiii - IiII
 if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
 if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
 if 66 - 66: II111iiii * I1IiiI . Oo0Ooo * OoooooooOO % OoOoOO00 . II111iiii
def lisp_program_vxlan_hardware ( mc ) :
 if 4 - 4: iII111i + I1Ii111 % OoOoOO00 / Ii1I
 if 94 - 94: OoO0O00
 if 35 - 35: I1ii11iIi11i % OoO0O00 + II111iiii % II111iiii / IiII - iII111i
 if 9 - 9: I1ii11iIi11i * o0oOOo0O0Ooo . oO0o
 if 48 - 48: IiII . I1Ii111 + OoooooooOO - I1Ii111 . Ii1I . I1Ii111
 if 24 - 24: ooOoO0o * iIii1I11I1II1
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 1 - 1: I1ii11iIi11i . O0
 if 3 - 3: iIii1I11I1II1 * ooOoO0o - OoOoOO00 * I1ii11iIi11i % OoOoOO00 - OoooooooOO
 if 42 - 42: I1Ii111 - i1IIi
 if 91 - 91: iII111i . OOooOOo / iIii1I11I1II1 . Oo0Ooo . II111iiii . OoOoOO00
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 31 - 31: OoO0O00 . I1ii11iIi11i % I11i - II111iiii
 if 70 - 70: ooOoO0o - IiII - OoO0O00 / I11i
 if 59 - 59: IiII % ooOoO0o . iII111i / Ii1I * Ii1I
 if 73 - 73: I1ii11iIi11i . oO0o % I11i . I1ii11iIi11i / I1Ii111 / II111iiii
 OOi1 = mc . eid . print_prefix_no_iid ( )
 OooO0ooO0o0OO = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
 if 76 - 76: I1Ii111
 if 91 - 91: iIii1I11I1II1 / Ii1I . I1IiiI
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 ooOoo0o = commands . getoutput ( "ip route get {} | egrep vlan4094" . format ( OOi1 ) )
 if 44 - 44: OoooooooOO . i1IIi + Ii1I * O0 % i1IIi % I11i
 if ( ooOoo0o != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( OOi1 , False ) , ooOoo0o ) )
  if 98 - 98: I1IiiI - II111iiii % II111iiii % OOooOOo
  return
  if 6 - 6: OOooOOo
  if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
  if 55 - 55: OOooOOo + oO0o - II111iiii
  if 5 - 5: iII111i * OoooooooOO . OoO0O00 % ooOoO0o + Ii1I
  if 59 - 59: OoOoOO00
  if 96 - 96: I1IiiI
  if 3 - 3: OoooooooOO
 I11ii1iIi111i = commands . getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( I11ii1iIi111i . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 96 - 96: IiII
 if ( I11ii1iIi111i . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 55 - 55: iIii1I11I1II1 + II111iiii . I1ii11iIi11i + Oo0Ooo . Ii1I * IiII
 ooO0O = commands . getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( ooO0O == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 92 - 92: OoOoOO00 . I1IiiI - ooOoO0o / OoooooooOO
 ooO0O = ooO0O . split ( "inet " ) [ 1 ]
 ooO0O = ooO0O . split ( "/" ) [ 0 ]
 if 71 - 71: OOooOOo + I11i * O0 / o0oOOo0O0Ooo + I1IiiI + Ii1I
 if 41 - 41: ooOoO0o * I1Ii111
 if 40 - 40: OoOoOO00
 if 60 - 60: IiII . i11iIiiIii * II111iiii . Ii1I
 if 10 - 10: O0
 if 65 - 65: I11i % i11iIiiIii + i11iIiiIii % II111iiii
 if 95 - 95: I1Ii111 - I11i . II111iiii . i1IIi / II111iiii + Oo0Ooo
 Ooo000Oooo0o0 = [ ]
 o00OoO0 = commands . getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for I111 in o00OoO0 :
  if ( I111 . find ( "vlan4094" ) == - 1 ) : continue
  if ( I111 . find ( "(incomplete)" ) == - 1 ) : continue
  I1ii1I1II11II = I111 . split ( " " ) [ 0 ]
  Ooo000Oooo0o0 . append ( I1ii1I1II11II )
  if 83 - 83: I11i
  if 39 - 39: o0oOOo0O0Ooo * iIii1I11I1II1
 I1ii1I1II11II = None
 oOoI1 = ooO0O
 ooO0O = ooO0O . split ( "." )
 for i1i1IIIIIIIi in range ( 1 , 255 ) :
  ooO0O [ 3 ] = str ( i1i1IIIIIIIi )
  O0o00o000oO = "." . join ( ooO0O )
  if ( O0o00o000oO in Ooo000Oooo0o0 ) : continue
  if ( O0o00o000oO == oOoI1 ) : continue
  I1ii1I1II11II = O0o00o000oO
  break
  if 13 - 13: iII111i + Oo0Ooo / oO0o / OOooOOo
 if ( I1ii1I1II11II == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 58 - 58: oO0o * I1ii11iIi11i % I1ii11iIi11i
  return
  if 16 - 16: I11i / I1IiiI % I1IiiI
  if 78 - 78: O0 % i11iIiiIii / IiII
  if 87 - 87: IiII % iIii1I11I1II1 * I1ii11iIi11i
  if 43 - 43: Ii1I - IiII / i11iIiiIii + OoOoOO00 + I1ii11iIi11i - o0oOOo0O0Ooo
  if 39 - 39: OoOoOO00 - i1IIi / oO0o % I11i * o0oOOo0O0Ooo * I1IiiI
  if 79 - 79: Ii1I
  if 56 - 56: I1ii11iIi11i
 i1iI = OooO0ooO0o0OO . split ( "." )
 Oo00o0oOooO = lisp_hex_string ( i1iI [ 1 ] ) . zfill ( 2 )
 OoOo0OoOO0o = lisp_hex_string ( i1iI [ 2 ] ) . zfill ( 2 )
 iIi1I1i = lisp_hex_string ( i1iI [ 3 ] ) . zfill ( 2 )
 Oo0OOo = "00:00:00:{}:{}:{}" . format ( Oo00o0oOooO , OoOo0OoOO0o , iIi1I1i )
 I111iII1I11II = "0000.00{}.{}{}" . format ( Oo00o0oOooO , OoOo0OoOO0o , iIi1I1i )
 O00OO = "arp -i vlan4094 -s {} {}" . format ( I1ii1I1II11II , Oo0OOo )
 os . system ( O00OO )
 if 33 - 33: IiII
 if 76 - 76: iII111i . OOooOOo . OoOoOO00 + O0
 if 32 - 32: O0 * iIii1I11I1II1 - O0 % Ii1I
 if 31 - 31: ooOoO0o
 oOiIi1IIiIi1I11 = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( I111iII1I11II , OooO0ooO0o0OO )
 if 40 - 40: I1IiiI + I1ii11iIi11i * I1IiiI % Ii1I
 lisp_send_to_arista ( oOiIi1IIiIi1I11 , None )
 if 27 - 27: O0 / Oo0Ooo . oO0o
 if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
 if 36 - 36: i11iIiiIii * i1IIi % iII111i . Oo0Ooo
 if 54 - 54: o0oOOo0O0Ooo % i1IIi % I1ii11iIi11i . o0oOOo0O0Ooo / OoOoOO00
 if 55 - 55: O0 / OoooooooOO % Ii1I * O0 + iIii1I11I1II1 . iIii1I11I1II1
 O00i1IiIiiIiii = "ip route add {} via {}" . format ( OOi1 , I1ii1I1II11II )
 os . system ( O00i1IiIiiIiii )
 if 59 - 59: iIii1I11I1II1 . OoOoOO00 + ooOoO0o . OoooooooOO
 lprint ( "Hardware programmed with commands:" )
 O00i1IiIiiIiii = O00i1IiIiiIiii . replace ( OOi1 , green ( OOi1 , False ) )
 lprint ( "  " + O00i1IiIiiIiii )
 lprint ( "  " + O00OO )
 oOiIi1IIiIi1I11 = oOiIi1IIiIi1I11 . replace ( OooO0ooO0o0OO , red ( OooO0ooO0o0OO , False ) )
 lprint ( "  " + oOiIi1IIiIi1I11 )
 return
 if 27 - 27: IiII . Oo0Ooo
 if 70 - 70: ooOoO0o + OoooooooOO
 if 17 - 17: iIii1I11I1II1
 if 25 - 25: I1ii11iIi11i * I11i
 if 33 - 33: oO0o / II111iiii
 if 90 - 90: o0oOOo0O0Ooo - iIii1I11I1II1 + i1IIi - OoO0O00 + IiII
 if 40 - 40: i11iIiiIii . i11iIiiIii - OoOoOO00 - oO0o
def lisp_clear_hardware_walk ( mc , parms ) :
 O000 = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( O000 ) )
 return ( [ True , None ] )
 if 42 - 42: IiII + OoooooooOO / OoooooooOO . ooOoO0o / i11iIiiIii / II111iiii
 if 10 - 10: iII111i . I1IiiI
 if 74 - 74: II111iiii * O0
 if 57 - 57: OoO0O00
 if 12 - 12: o0oOOo0O0Ooo . I1Ii111 . oO0o % Oo0Ooo * OoooooooOO
 if 25 - 25: OoO0O00
 if 54 - 54: O0
 if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list , lisp_gleaned_groups
 if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
 o000o0O0O = bold ( "User cleared" , False )
 OoO = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( o000o0O0O , OoO ) )
 if 8 - 8: o0oOOo0O0Ooo
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 52 - 52: IiII * OoooooooOO . oO0o + Oo0Ooo
 lisp_map_cache = lisp_cache ( )
 if 95 - 95: OoO0O00 * I1IiiI - Oo0Ooo . IiII
 if 82 - 82: I11i
 if 89 - 89: iIii1I11I1II1 . I11i + OOooOOo / i11iIiiIii / I1ii11iIi11i * i11iIiiIii
 if 20 - 20: I1Ii111 . II111iiii % II111iiii
 if 79 - 79: II111iiii . I11i + o0oOOo0O0Ooo % I1ii11iIi11i + I1ii11iIi11i
 lisp_rloc_probe_list = { }
 if 4 - 4: I1ii11iIi11i % OoooooooOO
 if 43 - 43: IiII - I1Ii111 % ooOoO0o
 if 49 - 49: OoOoOO00
 if 43 - 43: I1Ii111 - Oo0Ooo % i1IIi . II111iiii
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 80 - 80: IiII . iII111i + I1Ii111 + iII111i % Oo0Ooo
 if 98 - 98: i11iIiiIii . II111iiii + OoOoOO00
 if 25 - 25: I1IiiI + i11iIiiIii . I1Ii111 - I1ii11iIi11i
 if 67 - 67: OOooOOo - OOooOOo * I1IiiI - II111iiii . i1IIi + Oo0Ooo
 if 97 - 97: O0 / i11iIiiIii - o0oOOo0O0Ooo - OoOoOO00 . oO0o
 lisp_rtr_list = { }
 if 77 - 77: oO0o * oO0o . OoOoOO00 . i1IIi
 if 90 - 90: OOooOOo . Ii1I . II111iiii + Ii1I
 if 2 - 2: I1Ii111 * OOooOOo + II111iiii - OoOoOO00
 if 94 - 94: Ii1I - iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
 lisp_gleaned_groups = { }
 if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
 if 96 - 96: OOooOOo % o0oOOo0O0Ooo / iIii1I11I1II1
 if 60 - 60: i1IIi / iIii1I11I1II1 + I11i % iII111i
 if 64 - 64: I11i . i11iIiiIii / iIii1I11I1II1 . I11i
 lisp_process_data_plane_restart ( True )
 return
 if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
 if 20 - 20: I11i % I1ii11iIi11i . OoO0O00 % OoOoOO00
 if 84 - 84: OoooooooOO / i11iIiiIii . IiII / I1IiiI
 if 62 - 62: iII111i - I1IiiI + OoooooooOO
 if 59 - 59: iIii1I11I1II1 + i11iIiiIii * oO0o . Oo0Ooo . I1Ii111
 if 49 - 49: II111iiii
 if 99 - 99: Oo0Ooo . OOooOOo
 if 85 - 85: OoOoOO00 . IiII + oO0o - II111iiii
 if 70 - 70: O0 % I1Ii111
 if 13 - 13: I1ii11iIi11i % OoO0O00 / Ii1I * IiII
 if 82 - 82: ooOoO0o % Oo0Ooo
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 26 - 26: OoO0O00 + i11iIiiIii % I11i . I1ii11iIi11i
 OoO0OOo = lisp_myrlocs [ 0 ]
 if 48 - 48: I1ii11iIi11i
 if 69 - 69: oO0o + I11i * Ii1I
 if 13 - 13: I1ii11iIi11i / Oo0Ooo - I1Ii111 * OoOoOO00
 if 47 - 47: IiII
 if 76 - 76: iII111i / II111iiii / I11i
 iI1 = len ( packet ) + 28
 iIiiIIi = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( iI1 ) , 0 , 64 ,
 17 , 0 , socket . htonl ( OoO0OOo . address ) , socket . htonl ( rloc . address ) )
 iIiiIIi = lisp_ip_checksum ( iIiiIIi )
 if 62 - 62: I1ii11iIi11i
 O0OO0ooO00 = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( iI1 - 20 ) , 0 )
 if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
 if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
 if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
 if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
 packet = lisp_packet ( iIiiIIi + O0OO0ooO00 + packet )
 if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
 if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
 if 71 - 71: i1IIi
 if 79 - 79: iII111i * O0 / Ii1I / O0 % i1IIi
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( OoO0OOo )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( OoO0OOo )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
 ii11IiI = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  O0oo0OoOO = " {}" . format ( blue ( nat_info . hostname , False ) )
  Ii1I11IiI1I1 = bold ( "RLOC-probe request" , False )
 else :
  O0oo0OoOO = ""
  Ii1I11IiI1I1 = bold ( "RLOC-probe reply" , False )
  if 62 - 62: Ii1I . I1ii11iIi11i . iII111i + I11i * o0oOOo0O0Ooo
  if 56 - 56: oO0o * iIii1I11I1II1 . II111iiii - II111iiii + II111iiii - i11iIiiIii
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( Ii1I11IiI1I1 , ii11IiI , O0oo0OoOO , packet . encap_port ) )
 if 79 - 79: iII111i
 if 29 - 29: Ii1I * I1Ii111 / OoO0O00 - O0 - i11iIiiIii * I1IiiI
 if 2 - 2: OoOoOO00 . I1ii11iIi11i * I1ii11iIi11i
 if 42 - 42: OoO0O00 . OoO0O00 + II111iiii - IiII - OOooOOo * Oo0Ooo
 if 47 - 47: oO0o - OoooooooOO + iII111i
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 69 - 69: I1ii11iIi11i - I1IiiI % oO0o + OOooOOo - I1Ii111
 i1i1o0oO = lisp_sockets [ 3 ]
 packet . send_packet ( i1i1o0oO , packet . outer_dest )
 del ( packet )
 return
 if 81 - 81: OoO0O00
 if 66 - 66: OoooooooOO * OoOoOO00 . iII111i + iIii1I11I1II1 * O0 % OOooOOo
 if 72 - 72: iII111i * Oo0Ooo - i11iIiiIii . OoooooooOO
 if 85 - 85: O0 * i1IIi
 if 29 - 29: i11iIiiIii
 if 34 - 34: OoOoOO00
 if 17 - 17: oO0o * OoOoOO00 % OoO0O00 % I1IiiI * I11i
 if 78 - 78: OoooooooOO . I1Ii111 + Ii1I - II111iiii - IiII / iIii1I11I1II1
def lisp_get_default_route_next_hops ( ) :
 if 92 - 92: Ii1I
 if 34 - 34: OOooOOo * OoooooooOO / I1ii11iIi11i
 if 41 - 41: i1IIi
 if 75 - 75: o0oOOo0O0Ooo . I1Ii111 - I1Ii111 % Ii1I * OoooooooOO
 if ( lisp_is_macos ( ) ) :
  OoOoOoo0OoO0 = "route -n get default"
  O0OOo0o = commands . getoutput ( OoOoOoo0OoO0 ) . split ( "\n" )
  O0OOOoOoO00 = I1i = None
  for iI1IiI11Ii11i in O0OOo0o :
   if ( iI1IiI11Ii11i . find ( "gateway: " ) != - 1 ) : O0OOOoOoO00 = iI1IiI11Ii11i . split ( ": " ) [ 1 ]
   if ( iI1IiI11Ii11i . find ( "interface: " ) != - 1 ) : I1i = iI1IiI11Ii11i . split ( ": " ) [ 1 ]
   if 100 - 100: OoO0O00 . Oo0Ooo
  return ( [ [ I1i , O0OOOoOoO00 ] ] )
  if 29 - 29: OoO0O00
  if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
  if 63 - 63: O0 % iIii1I11I1II1 . o0oOOo0O0Ooo . I1IiiI * Ii1I % i1IIi
  if 47 - 47: II111iiii * I1ii11iIi11i
  if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
 OoOoOoo0OoO0 = "ip route | egrep 'default via'"
 OoOoo0Ooo0O0o = commands . getoutput ( OoOoOoo0OoO0 ) . split ( "\n" )
 if 71 - 71: I1ii11iIi11i * i1IIi
 Oo0O00OOOO = [ ]
 for ooOoo0o in OoOoo0Ooo0O0o :
  if ( ooOoo0o . find ( " metric " ) != - 1 ) : continue
  O0OooO0oo = ooOoo0o . split ( " " )
  try :
   OOoOo0o0oO = O0OooO0oo . index ( "via" ) + 1
   if ( OOoOo0o0oO >= len ( O0OooO0oo ) ) : continue
   ooo0OOOOo000 = O0OooO0oo . index ( "dev" ) + 1
   if ( ooo0OOOOo000 >= len ( O0OooO0oo ) ) : continue
  except :
   continue
   if 49 - 49: iII111i % iII111i . II111iiii - I1IiiI / O0
   if 82 - 82: o0oOOo0O0Ooo + I1IiiI % I1Ii111 % iII111i + iII111i
  Oo0O00OOOO . append ( [ O0OooO0oo [ ooo0OOOOo000 ] , O0OooO0oo [ OOoOo0o0oO ] ] )
  if 71 - 71: Oo0Ooo / OoOoOO00 - I1ii11iIi11i
 return ( Oo0O00OOOO )
 if 32 - 32: iII111i
 if 99 - 99: o0oOOo0O0Ooo . oO0o
 if 9 - 9: oO0o % OoooooooOO
 if 62 - 62: OoO0O00 / OoOoOO00 / I1Ii111 + Oo0Ooo - Ii1I
 if 72 - 72: OoO0O00 + I11i / iII111i % OOooOOo
 if 5 - 5: oO0o % OOooOOo
 if 95 - 95: OoOoOO00 + OoooooooOO - O0 + o0oOOo0O0Ooo
def lisp_get_host_route_next_hop ( rloc ) :
 OoOoOoo0OoO0 = "ip route | egrep '{} via'" . format ( rloc )
 ooOoo0o = commands . getoutput ( OoOoOoo0OoO0 ) . split ( " " )
 if 88 - 88: i11iIiiIii . iIii1I11I1II1
 try : OO000o00 = ooOoo0o . index ( "via" ) + 1
 except : return ( None )
 if 57 - 57: Ii1I * iIii1I11I1II1
 if ( OO000o00 >= len ( ooOoo0o ) ) : return ( None )
 return ( ooOoo0o [ OO000o00 ] )
 if 92 - 92: Ii1I % Ii1I . I11i / i1IIi % Oo0Ooo
 if 25 - 25: o0oOOo0O0Ooo - OoO0O00 - OoOoOO00 - ooOoO0o
 if 28 - 28: OOooOOo * ooOoO0o * OoooooooOO % IiII
 if 9 - 9: OoooooooOO
 if 92 - 92: I1Ii111 + O0 + OoO0O00 % IiII
 if 31 - 31: Ii1I / Oo0Ooo - I1IiiI - I11i - i11iIiiIii
 if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 OoI1i1 = "none" if nh == None else nh
 if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , OoI1i1 ) )
 if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
 if ( nh == None ) :
  O000Oo = "ip route {} {}/32" . format ( install , dest )
 else :
  O000Oo = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
 os . system ( O000Oo )
 return
 if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
 if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
 if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
 if 57 - 57: I1Ii111 - IiII
 if 89 - 89: oO0o + iII111i
 if 52 - 52: OOooOOo % O0 * I1ii11iIi11i . I1ii11iIi11i / IiII
 if 7 - 7: II111iiii
 if 7 - 7: iIii1I11I1II1 . O0 + Ii1I % I1IiiI * O0 + OoO0O00
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 3 - 3: Oo0Ooo * OoooooooOO * oO0o % OoOoOO00 * OoOoOO00 . ooOoO0o
 iI1IiI11Ii11i = open ( lisp_checkpoint_filename , "w" )
 for iIiiiIIiii in checkpoint_list :
  iI1IiI11Ii11i . write ( iIiiiIIiii + "\n" )
  if 16 - 16: ooOoO0o / o0oOOo0O0Ooo - O0 * I1IiiI
 iI1IiI11Ii11i . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 13 - 13: iII111i . iII111i % O0 % o0oOOo0O0Ooo
 if 99 - 99: OoO0O00 - OoOoOO00 + OoO0O00
 if 67 - 67: I1Ii111
 if 31 - 31: OoO0O00 * Oo0Ooo % O0 * II111iiii + ooOoO0o * I1IiiI
 if 77 - 77: ooOoO0o
 if 98 - 98: I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
 if 6 - 6: iII111i / iII111i . i11iIiiIii
 if 12 - 12: I11i - OoO0O00
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 68 - 68: IiII - OoOoOO00
 iI1IiI11Ii11i = open ( lisp_checkpoint_filename , "r" )
 if 22 - 22: i1IIi . IiII
 OoO = 0
 for iIiiiIIiii in iI1IiI11Ii11i :
  OoO += 1
  o0OoO00 = iIiiiIIiii . split ( " rloc " )
  OO000 = [ ] if ( o0OoO00 [ 1 ] in [ "native-forward\n" , "\n" ] ) else o0OoO00 [ 1 ] . split ( ", " )
  if 8 - 8: IiII % o0oOOo0O0Ooo . i11iIiiIii
  if 69 - 69: I1Ii111 / Ii1I - ooOoO0o
  iio0OOoO0 = [ ]
  for OooO0ooO0o0OO in OO000 :
   IiIIIi = lisp_rloc ( False )
   O0OooO0oo = OooO0ooO0o0OO . split ( " " )
   IiIIIi . rloc . store_address ( O0OooO0oo [ 0 ] )
   IiIIIi . priority = int ( O0OooO0oo [ 1 ] )
   IiIIIi . weight = int ( O0OooO0oo [ 2 ] )
   iio0OOoO0 . append ( IiIIIi )
   if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
   if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
  OoOoooooO00oo = lisp_mapping ( "" , "" , iio0OOoO0 )
  if ( OoOoooooO00oo != None ) :
   OoOoooooO00oo . eid . store_prefix ( o0OoO00 [ 0 ] )
   OoOoooooO00oo . checkpoint_entry = True
   OoOoooooO00oo . map_cache_ttl = LISP_NMR_TTL * 60
   if ( iio0OOoO0 == [ ] ) : OoOoooooO00oo . action = LISP_NATIVE_FORWARD_ACTION
   OoOoooooO00oo . add_cache ( )
   continue
   if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
   if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
  OoO -= 1
  if 42 - 42: i1IIi . OoO0O00 % iII111i
  if 57 - 57: I1ii11iIi11i / I1IiiI
 iI1IiI11Ii11i . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , OoO , lisp_checkpoint_filename ) )
 return
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
 if 53 - 53: II111iiii / iIii1I11I1II1
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 25 - 25: I1Ii111
 iIiiiIIiii = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 58 - 58: OoOoOO00 * i1IIi
 for IiIIIi in mc . rloc_set :
  if ( IiIIIi . rloc . is_null ( ) ) : continue
  iIiiiIIiii += "{} {} {}, " . format ( IiIIIi . rloc . print_address_no_iid ( ) ,
 IiIIIi . priority , IiIIIi . weight )
  if 20 - 20: IiII
  if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
 if ( mc . rloc_set != [ ] ) :
  iIiiiIIiii = iIiiiIIiii [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  iIiiiIIiii += "native-forward"
  if 30 - 30: i11iIiiIii . I1IiiI
  if 5 - 5: Ii1I / O0 + iIii1I11I1II1
 checkpoint_list . append ( iIiiiIIiii )
 return
 if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
 if 79 - 79: iII111i
 if 71 - 71: i1IIi / OoO0O00 / OOooOOo + I1Ii111
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
 if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
def lisp_check_dp_socket ( ) :
 IIIiiiIi = lisp_ipc_dp_socket_name
 if ( os . path . exists ( IIIiiiIi ) == False ) :
  oO000oOO0 = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( IIIiiiIi , oO000oOO0 ) )
  return ( False )
  if 81 - 81: OoOoOO00
 return ( True )
 if 18 - 18: Ii1I . I1Ii111 % OoooooooOO + OoooooooOO - I1IiiI % I1IiiI
 if 51 - 51: iIii1I11I1II1 / I1IiiI
 if 27 - 27: O0 . o0oOOo0O0Ooo / ooOoO0o / OoooooooOO % Ii1I
 if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
 if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
 if 87 - 87: II111iiii
 if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
def lisp_write_to_dp_socket ( entry ) :
 try :
  O00oOO = json . dumps ( entry )
  oOo0o000O000oo = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( oOo0o000O000oo , O00oOO ) )
  lisp_ipc_dp_socket . sendto ( O00oOO , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( O00oOO ) )
  if 3 - 3: Ii1I % IiII + O0 % iIii1I11I1II1
 return
 if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
 if 64 - 64: iII111i - Oo0Ooo
 if 73 - 73: iIii1I11I1II1 * I1Ii111 * OoO0O00
 if 68 - 68: ooOoO0o * Ii1I / I1ii11iIi11i * OoooooooOO + OoooooooOO . OoooooooOO
 if 50 - 50: I1IiiI % o0oOOo0O0Ooo
 if 1 - 1: II111iiii
 if 22 - 22: I1Ii111 + iII111i
 if 50 - 50: iII111i % OoOoOO00 - II111iiii + II111iiii / OoO0O00
 if 69 - 69: Ii1I * II111iiii
def lisp_write_ipc_keys ( rloc ) :
 oOo0O = rloc . rloc . print_address_no_iid ( )
 IIi1I1iII111 = rloc . translated_port
 if ( IIi1I1iII111 != 0 ) : oOo0O += ":" + str ( IIi1I1iII111 )
 if ( lisp_rloc_probe_list . has_key ( oOo0O ) == False ) : return
 if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
 for O0OooO0oo , o0OoO00 , II1IIiIiiI1iI in lisp_rloc_probe_list [ oOo0O ] :
  OoOoooooO00oo = lisp_map_cache . lookup_cache ( o0OoO00 , True )
  if ( OoOoooooO00oo == None ) : continue
  lisp_write_ipc_map_cache ( True , OoOoooooO00oo )
  if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
 return
 if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
 if 10 - 10: Ii1I / Oo0Ooo - i1IIi
 if 11 - 11: I11i * iII111i
 if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
 if 2 - 2: oO0o + I11i / I1Ii111 . I11i
 if 59 - 59: Ii1I
 if 47 - 47: iII111i % iII111i
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
 if 23 - 23: IiII + oO0o + o0oOOo0O0Ooo . I1ii11iIi11i / i11iIiiIii + iIii1I11I1II1
 if 74 - 74: I11i % OOooOOo
 if 57 - 57: O0 + I1IiiI + i11iIiiIii
 oO0 = "add" if add_or_delete else "delete"
 iIiiiIIiii = { "type" : "map-cache" , "opcode" : oO0 }
 if 90 - 90: I1ii11iIi11i . OoO0O00 * iIii1I11I1II1 - Oo0Ooo
 O0O0OOoO00 = ( mc . group . is_null ( ) == False )
 if ( O0O0OOoO00 ) :
  iIiiiIIiii [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  iIiiiIIiii [ "rles" ] = [ ]
 else :
  iIiiiIIiii [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  iIiiiIIiii [ "rlocs" ] = [ ]
  if 28 - 28: I1IiiI . ooOoO0o - ooOoO0o * OOooOOo . IiII
 iIiiiIIiii [ "instance-id" ] = str ( mc . eid . instance_id )
 if 16 - 16: iIii1I11I1II1 % i11iIiiIii / Ii1I % iIii1I11I1II1 / iII111i
 if ( O0O0OOoO00 ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for Oo0000O00o0 in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    O0o00o000oO = Oo0000O00o0 . address . print_address_no_iid ( )
    IIi1I1iII111 = str ( 4341 ) if Oo0000O00o0 . translated_port == 0 else str ( Oo0000O00o0 . translated_port )
    if 27 - 27: II111iiii * OoooooooOO / Oo0Ooo % O0
    O0OooO0oo = { "rle" : O0o00o000oO , "port" : IIi1I1iII111 }
    iI1Ii1iiiII1II , II1iI = Oo0000O00o0 . get_encap_keys ( )
    O0OooO0oo = lisp_build_json_keys ( O0OooO0oo , iI1Ii1iiiII1II , II1iI , "encrypt-key" )
    iIiiiIIiii [ "rles" ] . append ( O0OooO0oo )
    if 81 - 81: iII111i * i11iIiiIii % O0 / iIii1I11I1II1 . OoO0O00
    if 24 - 24: I1ii11iIi11i + OoOoOO00 % ooOoO0o % I1IiiI * I1Ii111 - o0oOOo0O0Ooo
 else :
  for OooO0ooO0o0OO in mc . rloc_set :
   if ( OooO0ooO0o0OO . rloc . is_ipv4 ( ) == False and OooO0ooO0o0OO . rloc . is_ipv6 ( ) == False ) :
    continue
    if 95 - 95: Oo0Ooo * IiII - I1IiiI
   if ( OooO0ooO0o0OO . up_state ( ) == False ) : continue
   if 37 - 37: Oo0Ooo - oO0o / I1ii11iIi11i . o0oOOo0O0Ooo * Ii1I
   IIi1I1iII111 = str ( 4341 ) if OooO0ooO0o0OO . translated_port == 0 else str ( OooO0ooO0o0OO . translated_port )
   if 95 - 95: i11iIiiIii - ooOoO0o / I11i / I1Ii111
   O0OooO0oo = { "rloc" : OooO0ooO0o0OO . rloc . print_address_no_iid ( ) , "priority" :
 str ( OooO0ooO0o0OO . priority ) , "weight" : str ( OooO0ooO0o0OO . weight ) , "port" :
 IIi1I1iII111 }
   iI1Ii1iiiII1II , II1iI = OooO0ooO0o0OO . get_encap_keys ( )
   O0OooO0oo = lisp_build_json_keys ( O0OooO0oo , iI1Ii1iiiII1II , II1iI , "encrypt-key" )
   iIiiiIIiii [ "rlocs" ] . append ( O0OooO0oo )
   if 59 - 59: iII111i
   if 59 - 59: Oo0Ooo - IiII
   if 6 - 6: OOooOOo - I1IiiI . IiII
 if ( dont_send == False ) : lisp_write_to_dp_socket ( iIiiiIIiii )
 return ( iIiiiIIiii )
 if 40 - 40: II111iiii
 if 13 - 13: OoOoOO00
 if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
 if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
 if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
 iI1Ii1iiiII1II = keys [ 1 ] . encrypt_key
 II1iI = keys [ 1 ] . icv_key
 if 46 - 46: OOooOOo
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
 if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
 i1II1iIiiiIi = rloc_addr . split ( ":" )
 if ( len ( i1II1iIiiiIi ) == 1 ) :
  iIiiiIIiii = { "type" : "decap-keys" , "rloc" : i1II1iIiiiIi [ 0 ] }
 else :
  iIiiiIIiii = { "type" : "decap-keys" , "rloc" : i1II1iIiiiIi [ 0 ] , "port" : i1II1iIiiiIi [ 1 ] }
  if 12 - 12: OoooooooOO / OoooooooOO * Ii1I % OOooOOo + i11iIiiIii % OoooooooOO
 iIiiiIIiii = lisp_build_json_keys ( iIiiiIIiii , iI1Ii1iiiII1II , II1iI , "decrypt-key" )
 if 46 - 46: II111iiii / I1Ii111 / O0 * OoooooooOO * ooOoO0o / ooOoO0o
 lisp_write_to_dp_socket ( iIiiiIIiii )
 return
 if 74 - 74: i11iIiiIii - oO0o % II111iiii . iIii1I11I1II1
 if 94 - 94: OOooOOo + oO0o / OoooooooOO + o0oOOo0O0Ooo - o0oOOo0O0Ooo . OOooOOo
 if 15 - 15: i11iIiiIii * O0 % iIii1I11I1II1 . OoooooooOO % oO0o + o0oOOo0O0Ooo
 if 37 - 37: oO0o + O0 . IiII * I1ii11iIi11i
 if 2 - 2: O0 . ooOoO0o
 if 97 - 97: i1IIi . Oo0Ooo
 if 81 - 81: OoOoOO00
 if 81 - 81: O0
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 57 - 57: oO0o - o0oOOo0O0Ooo % i11iIiiIii / OoOoOO00 . iIii1I11I1II1
 entry [ "keys" ] = [ ]
 iII1 = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( iII1 )
 return ( entry )
 if 68 - 68: iII111i
 if 59 - 59: O0 - i11iIiiIii + OoooooooOO - iII111i - Oo0Ooo . OoooooooOO
 if 60 - 60: O0 * iIii1I11I1II1 - Ii1I * II111iiii . ooOoO0o
 if 61 - 61: I1IiiI . iII111i
 if 19 - 19: iIii1I11I1II1 * Oo0Ooo - I1IiiI - I1IiiI + O0 - I1Ii111
 if 56 - 56: I1Ii111 - i1IIi + I11i . i1IIi / II111iiii * oO0o
 if 70 - 70: ooOoO0o - II111iiii . I11i
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 70 - 70: OOooOOo / iII111i - I11i + OoOoOO00 % Ii1I * IiII
 if 26 - 26: O0 / oO0o
 if 96 - 96: ooOoO0o * iII111i . IiII
 if 77 - 77: OOooOOo - I11i % o0oOOo0O0Ooo
 iIiiiIIiii = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 46 - 46: I1IiiI % oO0o . OoooooooOO . IiII / I11i - i1IIi
 if 43 - 43: OoOoOO00 - o0oOOo0O0Ooo
 if 22 - 22: i1IIi
 if 33 - 33: O0
 for o00o0oOo0o0O in lisp_db_list :
  if ( o00o0oOo0o0O . eid . is_ipv4 ( ) == False and o00o0oOo0o0O . eid . is_ipv6 ( ) == False ) : continue
  i11OO0Ooo0O0oO0O = { "instance-id" : str ( o00o0oOo0o0O . eid . instance_id ) ,
 "eid-prefix" : o00o0oOo0o0O . eid . print_prefix_no_iid ( ) }
  iIiiiIIiii [ "database-mappings" ] . append ( i11OO0Ooo0O0oO0O )
  if 13 - 13: I11i . I1ii11iIi11i - i11iIiiIii - o0oOOo0O0Ooo
 lisp_write_to_dp_socket ( iIiiiIIiii )
 if 56 - 56: I1Ii111
 if 23 - 23: iIii1I11I1II1 - i1IIi % i1IIi * i11iIiiIii
 if 40 - 40: I1ii11iIi11i + OoO0O00
 if 8 - 8: i11iIiiIii - iIii1I11I1II1
 if 73 - 73: OoOoOO00
 iIiiiIIiii = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( iIiiiIIiii )
 return
 if 25 - 25: iII111i / oO0o
 if 61 - 61: OoooooooOO . Ii1I . I11i + oO0o
 if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
 if 61 - 61: I1IiiI / OOooOOo
 if 67 - 67: OoOoOO00
 if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
 if 30 - 30: O0 / oO0o * i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 95 - 95: ooOoO0o % OOooOOo
 if 17 - 17: i1IIi + Ii1I
 if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
 if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
 iIiiiIIiii = { "type" : "interfaces" , "interfaces" : [ ] }
 if 26 - 26: oO0o / I1ii11iIi11i - oO0o
 for I1i in lisp_myinterfaces . values ( ) :
  if ( I1i . instance_id == None ) : continue
  i11OO0Ooo0O0oO0O = { "interface" : I1i . device ,
 "instance-id" : str ( I1i . instance_id ) }
  iIiiiIIiii [ "interfaces" ] . append ( i11OO0Ooo0O0oO0O )
  if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
  if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
 lisp_write_to_dp_socket ( iIiiiIIiii )
 return
 if 96 - 96: Ii1I
 if 90 - 90: II111iiii
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
def lisp_parse_auth_key ( value ) :
 iII1ii1IiII = value . split ( "[" )
 oo0o0 = { }
 if ( len ( iII1ii1IiII ) == 1 ) :
  oo0o0 [ 0 ] = value
  return ( oo0o0 )
  if 19 - 19: I1ii11iIi11i
  if 42 - 42: OoOoOO00 / IiII
 for IIoOo0000oooooo in iII1ii1IiII :
  if ( IIoOo0000oooooo == "" ) : continue
  OO000o00 = IIoOo0000oooooo . find ( "]" )
  o0O = IIoOo0000oooooo [ 0 : OO000o00 ]
  try : o0O = int ( o0O )
  except : return
  if 65 - 65: ooOoO0o - ooOoO0o * OoO0O00
  oo0o0 [ o0O ] = IIoOo0000oooooo [ OO000o00 + 1 : : ]
  if 99 - 99: I11i % ooOoO0o . I1Ii111
 return ( oo0o0 )
 if 34 - 34: ooOoO0o + oO0o + II111iiii . I1Ii111 . i1IIi
 if 14 - 14: OoO0O00 . ooOoO0o - i1IIi * I1IiiI
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
 if 17 - 17: ooOoO0o % ooOoO0o * oO0o
def lisp_reassemble ( packet ) :
 iIIi1 = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 8 - 8: ooOoO0o + OoO0O00 . II111iiii / iIii1I11I1II1 - OOooOOo
 if 87 - 87: iIii1I11I1II1 . IiII % I1IiiI . OoO0O00 - I1Ii111
 if 53 - 53: I1Ii111 % i11iIiiIii
 if 99 - 99: I1IiiI - i1IIi * i11iIiiIii + OoO0O00
 if ( iIIi1 == 0 or iIIi1 == 0x4000 ) : return ( packet )
 if 80 - 80: o0oOOo0O0Ooo . I11i % iIii1I11I1II1 + OoOoOO00
 if 87 - 87: I1Ii111 + II111iiii / I1ii11iIi11i + OoOoOO00
 if 71 - 71: I1IiiI + iIii1I11I1II1 + O0 * iII111i % IiII
 if 42 - 42: OOooOOo - I1ii11iIi11i
 OOoOo = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 O000o0 = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 82 - 82: OOooOOo . Oo0Ooo * ooOoO0o % II111iiii % II111iiii - oO0o
 OoooOOOOO0 = ( iIIi1 & 0x2000 == 0 and ( iIIi1 & 0x1fff ) != 0 )
 iIiiiIIiii = [ ( iIIi1 & 0x1fff ) * 8 , O000o0 - 20 , packet , OoooOOOOO0 ]
 if 36 - 36: O0 / I1ii11iIi11i + iII111i * Oo0Ooo
 if 97 - 97: IiII * O0 - o0oOOo0O0Ooo
 if 77 - 77: II111iiii / I11i % OoooooooOO % I1IiiI % II111iiii
 if 99 - 99: Oo0Ooo
 if 30 - 30: OoOoOO00 + I1Ii111 . OoOoOO00 - I11i
 if 42 - 42: OoOoOO00
 if 77 - 77: Oo0Ooo * IiII * I1ii11iIi11i + IiII
 if 37 - 37: IiII . OoooooooOO - i11iIiiIii * I1ii11iIi11i - OOooOOo
 if ( iIIi1 == 0x2000 ) :
  O0o0oOOO , IIi11 = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  O0o0oOOO = socket . ntohs ( O0o0oOOO )
  IIi11 = socket . ntohs ( IIi11 )
  if ( IIi11 not in [ 4341 , 8472 , 4789 ] and O0o0oOOO != 4341 ) :
   lisp_reassembly_queue [ OOoOo ] = [ ]
   iIiiiIIiii [ 2 ] = None
   if 74 - 74: Ii1I + i11iIiiIii * iII111i / o0oOOo0O0Ooo . i11iIiiIii
   if 99 - 99: OOooOOo - OoooooooOO + OoooooooOO . OOooOOo
   if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
   if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
   if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
   if 78 - 78: OoO0O00 - i1IIi % I1Ii111
 if ( lisp_reassembly_queue . has_key ( OOoOo ) == False ) :
  lisp_reassembly_queue [ OOoOo ] = [ ]
  if 87 - 87: I11i
  if 37 - 37: iII111i . I1Ii111 - iII111i - I11i - iIii1I11I1II1 - II111iiii
  if 80 - 80: I1Ii111 % O0 - IiII / II111iiii + i1IIi
  if 4 - 4: OOooOOo + II111iiii
  if 1 - 1: OoooooooOO * I1Ii111 - I11i / IiII
 iiiI1IIi111i = lisp_reassembly_queue [ OOoOo ]
 if 60 - 60: iIii1I11I1II1 . o0oOOo0O0Ooo . IiII
 if 66 - 66: OoooooooOO - I11i % i11iIiiIii / OoO0O00
 if 34 - 34: O0 * iIii1I11I1II1 . o0oOOo0O0Ooo . I1Ii111 . iIii1I11I1II1 * iIii1I11I1II1
 if 38 - 38: iIii1I11I1II1
 if 83 - 83: iII111i - Ii1I . oO0o - I1Ii111 * o0oOOo0O0Ooo
 if ( len ( iiiI1IIi111i ) == 1 and iiiI1IIi111i [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( OOoOo ) . zfill ( 4 ) ) )
  if 70 - 70: i11iIiiIii - OoO0O00 / i11iIiiIii
  return ( None )
  if 46 - 46: II111iiii + O0 * OoooooooOO
  if 39 - 39: OoooooooOO % II111iiii . o0oOOo0O0Ooo
  if 29 - 29: I11i . o0oOOo0O0Ooo . i1IIi . o0oOOo0O0Ooo
  if 77 - 77: iIii1I11I1II1 + iIii1I11I1II1
  if 52 - 52: I1ii11iIi11i - IiII % I1IiiI % i1IIi
 iiiI1IIi111i . append ( iIiiiIIiii )
 iiiI1IIi111i = sorted ( iiiI1IIi111i )
 if 98 - 98: I1Ii111 + II111iiii % OoO0O00 % iII111i
 if 54 - 54: II111iiii . ooOoO0o . iII111i - I1IiiI
 if 97 - 97: oO0o - O0 / II111iiii * II111iiii - oO0o * IiII
 if 97 - 97: IiII % OoO0O00 . OoOoOO00 - Ii1I
 O0o00o000oO = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 O0o00o000oO . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 IiIiI1I1iii = O0o00o000oO . print_address_no_iid ( )
 O0o00o000oO . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 IIIIIII1IiIii = O0o00o000oO . print_address_no_iid ( )
 O0o00o000oO = red ( "{} -> {}" . format ( IiIiI1I1iii , IIIIIII1IiIii ) , False )
 if 100 - 100: oO0o . ooOoO0o
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if iIiiiIIiii [ 2 ] == None else "" , O0o00o000oO , lisp_hex_string ( OOoOo ) . zfill ( 4 ) ,
 # IiII
 # II111iiii . I1IiiI % iIii1I11I1II1
 lisp_hex_string ( iIIi1 ) . zfill ( 4 ) ) )
 if 72 - 72: iIii1I11I1II1 - I1IiiI * OoO0O00 * o0oOOo0O0Ooo - I1IiiI . I1ii11iIi11i
 if 46 - 46: i1IIi . OoOoOO00 . I1Ii111
 if 84 - 84: OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii
 if 28 - 28: ooOoO0o % OoOoOO00 + ooOoO0o
 if 68 - 68: II111iiii
 if ( iiiI1IIi111i [ 0 ] [ 0 ] != 0 or iiiI1IIi111i [ - 1 ] [ 3 ] == False ) : return ( None )
 O0O0o0O00O = iiiI1IIi111i [ 0 ]
 for Iii1I in iiiI1IIi111i [ 1 : : ] :
  iIIi1 = Iii1I [ 0 ]
  o0Oo0O , III1i = O0O0o0O00O [ 0 ] , O0O0o0O00O [ 1 ]
  if ( o0Oo0O + III1i != iIIi1 ) : return ( None )
  O0O0o0O00O = Iii1I
  if 64 - 64: I1ii11iIi11i * II111iiii % oO0o % Oo0Ooo * OoOoOO00 * iIii1I11I1II1
 lisp_reassembly_queue . pop ( OOoOo )
 if 41 - 41: OoO0O00 . I11i % OoO0O00
 if 13 - 13: I1ii11iIi11i + II111iiii . OOooOOo . ooOoO0o - IiII % O0
 if 69 - 69: Oo0Ooo / ooOoO0o * i11iIiiIii
 if 11 - 11: OoOoOO00 * OoooooooOO
 if 40 - 40: iIii1I11I1II1
 packet = iiiI1IIi111i [ 0 ] [ 2 ]
 for Iii1I in iiiI1IIi111i [ 1 : : ] : packet += Iii1I [ 2 ] [ 20 : : ]
 if 46 - 46: II111iiii
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( OOoOo ) . zfill ( 4 ) , len ( packet ) ) )
 if 24 - 24: OOooOOo % OOooOOo * iII111i . Oo0Ooo * OOooOOo
 if 52 - 52: I11i
 if 46 - 46: Oo0Ooo % oO0o - I1IiiI + Ii1I
 if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
 if 37 - 37: o0oOOo0O0Ooo
 iI1 = socket . htons ( len ( packet ) )
 iIIIIII = packet [ 0 : 2 ] + struct . pack ( "H" , iI1 ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 57 - 57: iII111i / i1IIi / i1IIi + IiII
 if 75 - 75: IiII / O0
 iIIIIII = lisp_ip_checksum ( iIIIIII )
 return ( iIIIIII + packet [ 20 : : ] )
 if 72 - 72: I11i
 if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
 if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
 if 23 - 23: OoOoOO00 . oO0o - iII111i
 if 27 - 27: Oo0Ooo * OOooOOo - OoOoOO00
 if 1 - 1: II111iiii * i11iIiiIii . OoooooooOO
 if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
 if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 oOo0O = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( oOo0O ) ) : return ( oOo0O )
 if 88 - 88: I1Ii111
 oOo0O = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( oOo0O ) ) : return ( oOo0O )
 if 16 - 16: Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . OoooooooOO * OoO0O00
 if 50 - 50: II111iiii + I11i . OoooooooOO . I1Ii111 - OOooOOo
 if 83 - 83: oO0o
 if 100 - 100: I1Ii111 + o0oOOo0O0Ooo * oO0o / oO0o . oO0o + iII111i
 if 71 - 71: II111iiii + iII111i + O0 % Oo0Ooo / I1IiiI
 for OOOooOO in lisp_crypto_keys_by_rloc_decap :
  O0o00O0Oo0 = OOOooOO . split ( ":" )
  if ( len ( O0o00O0Oo0 ) == 1 ) : continue
  O0o00O0Oo0 = O0o00O0Oo0 [ 0 ] if len ( O0o00O0Oo0 ) == 2 else ":" . join ( O0o00O0Oo0 [ 0 : - 1 ] )
  if ( O0o00O0Oo0 == oOo0O ) :
   O0000 = lisp_crypto_keys_by_rloc_decap [ OOOooOO ]
   lisp_crypto_keys_by_rloc_decap [ oOo0O ] = O0000
   return ( oOo0O )
   if 29 - 29: iII111i
   if 91 - 91: Oo0Ooo - IiII
 return ( None )
 if 47 - 47: iII111i / OOooOOo + iII111i
 if 69 - 69: I1IiiI . I1ii11iIi11i
 if 18 - 18: I11i * I1IiiI
 if 42 - 42: i1IIi . I1Ii111 - ooOoO0o + I11i / oO0o
 if 60 - 60: i1IIi + OoooooooOO % i11iIiiIii / IiII % Oo0Ooo + I1IiiI
 if 87 - 87: Ii1I % OoooooooOO % I1Ii111 * i11iIiiIii * OoOoOO00
 if 78 - 78: I11i
 if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
 if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
 if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
 if 53 - 53: I1IiiI % I1IiiI
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 OOoo00oOO = addr + ":" + str ( port )
 if 33 - 33: O0 * I11i * ooOoO0o / OoOoOO00 % IiII - I1IiiI
 if ( lisp_i_am_rtr ) :
  if ( lisp_rloc_probe_list . has_key ( addr ) ) : return ( addr )
  if 15 - 15: II111iiii . O0 . iIii1I11I1II1 / O0 - oO0o
  if 9 - 9: i1IIi + o0oOOo0O0Ooo - Ii1I . oO0o + ooOoO0o
  if 65 - 65: OoooooooOO / IiII
  if 81 - 81: OoOoOO00 - I1IiiI
  if 90 - 90: oO0o
  if 9 - 9: Ii1I / O0 - II111iiii - i1IIi + OoOoOO00
  for oOOo0O0O in lisp_nat_state_info . values ( ) :
   for O00oO0ooo in oOOo0O0O :
    if ( addr == O00oO0ooo . address ) : return ( OOoo00oOO )
    if 8 - 8: Ii1I + I11i * oO0o % I11i
    if 17 - 17: o0oOOo0O0Ooo + Oo0Ooo
  return ( addr )
  if 38 - 38: oO0o + I1IiiI + OOooOOo
 return ( OOoo00oOO )
 if 82 - 82: iIii1I11I1II1 . OOooOOo
 if 7 - 7: i11iIiiIii . I11i
 if 56 - 56: iIii1I11I1II1 - II111iiii * i1IIi / Ii1I
 if 65 - 65: OOooOOo / I1IiiI . OoooooooOO + I1IiiI + OoooooooOO + i11iIiiIii
 if 20 - 20: I1IiiI + iII111i + O0 * O0
 if 18 - 18: I11i - I11i . OoOoOO00 . ooOoO0o
 if 31 - 31: ooOoO0o
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 87 - 87: OoooooooOO + OOooOOo - I1ii11iIi11i / I1IiiI + ooOoO0o - Oo0Ooo
 return
 if 19 - 19: ooOoO0o + I1ii11iIi11i - ooOoO0o
 if 17 - 17: I11i * i1IIi + iIii1I11I1II1 % I1IiiI
 if 44 - 44: IiII + I1IiiI . Ii1I % Oo0Ooo
 if 97 - 97: O0
 if 95 - 95: OoO0O00 % iII111i / I1IiiI * OoooooooOO
 if 31 - 31: iIii1I11I1II1
 if 62 - 62: o0oOOo0O0Ooo - iII111i / II111iiii . o0oOOo0O0Ooo
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 20 - 20: iIii1I11I1II1 % OOooOOo
 if 91 - 91: ooOoO0o
 if 96 - 96: I1IiiI . OOooOOo
 if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
 if 34 - 34: IiII % oO0o
 if 54 - 54: I1IiiI
 if 80 - 80: OoOoOO00 . I1IiiI / I1ii11iIi11i . iII111i
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 31 - 31: I11i * o0oOOo0O0Ooo
 if 17 - 17: Ii1I * iIii1I11I1II1
 if 9 - 9: o0oOOo0O0Ooo - IiII
 if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
 if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
 if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
 if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
 if 23 - 23: Ii1I % i1IIi - I1Ii111
 if 95 - 95: OoOoOO00 - ooOoO0o . i1IIi . OoooooooOO
 if 38 - 38: I1IiiI + I1ii11iIi11i - Oo0Ooo . i11iIiiIii - i1IIi
 if 11 - 11: IiII / I1IiiI . I1IiiI
 if 87 - 87: OoooooooOO * OoO0O00 * iIii1I11I1II1
 if 16 - 16: o0oOOo0O0Ooo * I11i + OoooooooOO + O0 / iIii1I11I1II1
 if 60 - 60: Ii1I % IiII * OoooooooOO * ooOoO0o * Ii1I
 if 8 - 8: I1Ii111 - o0oOOo0O0Ooo
 if 52 - 52: OoOoOO00 % O0 + I1ii11iIi11i . i11iIiiIii
 if 59 - 59: Ii1I - I1Ii111 . ooOoO0o - OoOoOO00 + oO0o . OoO0O00
 if 88 - 88: OOooOOo - ooOoO0o * o0oOOo0O0Ooo . OoooooooOO
 if 3 - 3: I1Ii111
def lisp_is_rloc_probe ( packet , rr ) :
 O0OO0ooO00 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( O0OO0ooO00 == False ) : return ( [ packet , None , None , None ] )
 if 24 - 24: Ii1I + i11iIiiIii * I1Ii111 - OoOoOO00 / Ii1I - OoOoOO00
 O0o0oOOO = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 IIi11 = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 O0oOOOooo = ( socket . htons ( LISP_CTRL_PORT ) in [ O0o0oOOO , IIi11 ] )
 if ( O0oOOOooo == False ) : return ( [ packet , None , None , None ] )
 if 52 - 52: o0oOOo0O0Ooo - i1IIi + OoOoOO00 / IiII
 if ( rr == 0 ) :
  Ii1I11IiI1I1 = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( Ii1I11IiI1I1 == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  Ii1I11IiI1I1 = lisp_is_rloc_probe_reply ( packet [ 28 ] )
  if ( Ii1I11IiI1I1 == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  Ii1I11IiI1I1 = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( Ii1I11IiI1I1 == False ) :
   Ii1I11IiI1I1 = lisp_is_rloc_probe_reply ( packet [ 28 ] )
   if ( Ii1I11IiI1I1 == False ) : return ( [ packet , None , None , None ] )
   if 24 - 24: IiII + OoooooooOO * Ii1I % iIii1I11I1II1
   if 22 - 22: I1Ii111 - I1ii11iIi11i . Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
   if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
   if 46 - 46: oO0o + OoOoOO00
   if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
   if 59 - 59: O0
 O0O00Oo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 O0O00Oo . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
 if 17 - 17: Ii1I % I1ii11iIi11i + I11i
 if 80 - 80: i1IIi . OoooooooOO % OoooooooOO . oO0o / OOooOOo
 if 85 - 85: OOooOOo
 if ( O0O00Oo . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 80 - 80: ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
 if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
 if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
 if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
 O0O00Oo = O0O00Oo . print_address_no_iid ( )
 IIi1I1iII111 = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 oo0OOoOO0 = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 72 - 72: IiII / II111iiii
 O0OooO0oo = bold ( "Receive(pcap)" , False )
 iI1IiI11Ii11i = bold ( "from " + O0O00Oo , False )
 iIiiI11II11 = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( O0OooO0oo , len ( packet ) , iI1IiI11Ii11i , IIi1I1iII111 , iIiiI11II11 ) )
 if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
 return ( [ packet , O0O00Oo , IIi1I1iII111 , oo0OOoOO0 ] )
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
 if 62 - 62: I11i
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 86 - 86: Oo0Ooo % II111iiii + I1Ii111 / I1ii11iIi11i
 oOO0O = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 15 - 15: I1IiiI / I1Ii111 % iII111i
 lisp_write_to_dp_socket ( oOO0O )
 return
 if 57 - 57: I1Ii111 . iIii1I11I1II1 / Oo0Ooo / IiII / iII111i * OoOoOO00
 if 35 - 35: i1IIi + I1Ii111 - ooOoO0o . I1ii11iIi11i + Oo0Ooo
 if 43 - 43: oO0o . OoO0O00 * i1IIi
 if 1 - 1: ooOoO0o / i1IIi
 if 42 - 42: I1ii11iIi11i * ooOoO0o + OoOoOO00 % I1ii11iIi11i . IiII
 if 75 - 75: OoO0O00 * i1IIi - OOooOOo % II111iiii % OoO0O00 - OoOoOO00
 if 75 - 75: I11i * IiII * ooOoO0o
 if 31 - 31: Ii1I
def lisp_external_data_plane ( ) :
 OoOoOoo0OoO0 = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( commands . getoutput ( OoOoOoo0OoO0 ) != "" ) : return ( True )
 if 72 - 72: OOooOOo * Ii1I % OoO0O00
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
 if 42 - 42: oO0o / i1IIi . IiII
 if 12 - 12: i11iIiiIii . ooOoO0o
 if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
 if 88 - 88: OoooooooOO . I1IiiI
 if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
 if 7 - 7: i1IIi
 if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
 if 34 - 34: iII111i + i11iIiiIii . IiII
 if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
 if 29 - 29: II111iiii % i11iIiiIii % O0
 if 38 - 38: o0oOOo0O0Ooo * IiII
 if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
 if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 19 - 19: OoooooooOO
 iII = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 53 - 53: oO0o + OoooooooOO * ooOoO0o
 if ( do_clear == False ) :
  iiIi1 = iII [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , iiIi1 )
  if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
  if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
 lisp_write_to_dp_socket ( iII )
 return
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
 if 22 - 22: OOooOOo . i11iIiiIii + II111iiii - Oo0Ooo % i1IIi / o0oOOo0O0Ooo
 if 90 - 90: IiII
 if 38 - 38: i1IIi / ooOoO0o / I11i * I1ii11iIi11i / II111iiii . iIii1I11I1II1
 if 52 - 52: I1ii11iIi11i % ooOoO0o * Ii1I * IiII + IiII / i11iIiiIii
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 51 - 51: iIii1I11I1II1 * o0oOOo0O0Ooo % o0oOOo0O0Ooo . Ii1I / OoooooooOO
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 23 - 23: oO0o * I1IiiI - oO0o - ooOoO0o . IiII / i11iIiiIii
  if 53 - 53: Ii1I * Ii1I . OoOoOO00 . OOooOOo / I1ii11iIi11i % O0
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 98 - 98: OOooOOo
  iiI1Ii1I = msg [ "eid-prefix" ]
  if 11 - 11: OOooOOo * iIii1I11I1II1 % IiII - I1IiiI . I11i
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 29 - 29: OOooOOo % I11i - OOooOOo - OOooOOo * I11i . oO0o
  oOo00Ooo0o0 = int ( msg [ "instance-id" ] )
  if 75 - 75: II111iiii . O0 . I1Ii111 * O0 / OoooooooOO
  if 60 - 60: OOooOOo - Oo0Ooo * OOooOOo / OoO0O00
  if 55 - 55: I1ii11iIi11i * II111iiii * iIii1I11I1II1
  if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i . Ii1I + I1IiiI % i11iIiiIii - i11iIiiIii
  I111o0oooO00o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , oOo00Ooo0o0 )
  I111o0oooO00o0 . store_prefix ( iiI1Ii1I )
  OoOoooooO00oo = lisp_map_cache_lookup ( None , I111o0oooO00o0 )
  if ( OoOoooooO00oo == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( iiI1Ii1I ) )
   if 62 - 62: I1Ii111 + I1IiiI
   continue
   if 9 - 9: iIii1I11I1II1 / iIii1I11I1II1
   if 24 - 24: OOooOOo . I1IiiI % i11iIiiIii
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( iiI1Ii1I ) )
   if 43 - 43: OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i + OoO0O00 . I1Ii111 . iII111i
   continue
   if 1 - 1: iII111i / OoO0O00 / OoOoOO00 * Oo0Ooo * OoooooooOO
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 59 - 59: iII111i
  IIIiiI11ii = msg [ "rlocs" ]
  if 30 - 30: iII111i . OoO0O00 . i11iIiiIii / I1ii11iIi11i * Oo0Ooo
  if 38 - 38: IiII + II111iiii
  if 20 - 20: iII111i * I1IiiI * iII111i - o0oOOo0O0Ooo + i1IIi + ooOoO0o
  if 49 - 49: II111iiii * I1IiiI / oO0o
  for I1ii1II in IIIiiI11ii :
   if ( I1ii1II . has_key ( "rloc" ) == False ) : continue
   if 15 - 15: Oo0Ooo
   ii11IiI = I1ii1II [ "rloc" ]
   if ( ii11IiI == "no-address" ) : continue
   if 53 - 53: OoooooooOO * O0 / iII111i * ooOoO0o % I1Ii111 + OOooOOo
   OooO0ooO0o0OO = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   OooO0ooO0o0OO . store_address ( ii11IiI )
   if 95 - 95: I1Ii111 % OoOoOO00 . IiII * iII111i % Ii1I
   IiIIIi = OoOoooooO00oo . get_rloc ( OooO0ooO0o0OO )
   if ( IiIIIi == None ) : continue
   if 18 - 18: iIii1I11I1II1 / ooOoO0o / I1Ii111 % oO0o * Ii1I
   if 14 - 14: oO0o
   if 72 - 72: iIii1I11I1II1 / II111iiii * II111iiii + I1IiiI + iIii1I11I1II1 + oO0o
   if 46 - 46: I1Ii111
   III1i1i1iIIi = 0 if I1ii1II . has_key ( "packet-count" ) == False else I1ii1II [ "packet-count" ]
   if 20 - 20: i1IIi
   IiI1iiI11 = 0 if I1ii1II . has_key ( "byte-count" ) == False else I1ii1II [ "byte-count" ]
   if 72 - 72: ooOoO0o . II111iiii
   Oo0OO0000oooo = 0 if I1ii1II . has_key ( "seconds-last-packet" ) == False else I1ii1II [ "seconds-last-packet" ]
   if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
   if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
   IiIIIi . stats . packet_count += III1i1i1iIIi
   IiIIIi . stats . byte_count += IiI1iiI11
   IiIIIi . stats . last_increment = lisp_get_timestamp ( ) - Oo0OO0000oooo
   if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( III1i1i1iIIi , IiI1iiI11 ,
 Oo0OO0000oooo , iiI1Ii1I , ii11IiI ) )
   if 18 - 18: o0oOOo0O0Ooo / OOooOOo
   if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
   if 100 - 100: O0
   if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
   if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
  if ( OoOoooooO00oo . group . is_null ( ) and OoOoooooO00oo . has_ttl_elapsed ( ) ) :
   iiI1Ii1I = green ( OoOoooooO00oo . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( iiI1Ii1I ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , OoOoooooO00oo . eid , None )
   if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
   if 38 - 38: Ii1I
 return
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
 if 31 - 31: OoO0O00 + I1Ii111 / iIii1I11I1II1
 if 11 - 11: ooOoO0o - OoOoOO00
 if 19 - 19: O0 . OoOoOO00 - i1IIi . oO0o
 if 96 - 96: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoO0O00 * iIii1I11I1II1 + ooOoO0o - ooOoO0o
 if 4 - 4: OoO0O00 - OOooOOo
 if 21 - 21: I1Ii111 * i11iIiiIii
 if 63 - 63: oO0o + OoOoOO00
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 50 - 50: o0oOOo0O0Ooo / Oo0Ooo * ooOoO0o * Ii1I
 if 97 - 97: I1IiiI / oO0o + I1Ii111 + I1Ii111
 if 86 - 86: o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * ooOoO0o
 if 20 - 20: Ii1I * iII111i / ooOoO0o
 if 18 - 18: Oo0Ooo * Ii1I / i11iIiiIii . OoO0O00 + OoooooooOO
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  oOO0O = "stats%{}" . format ( json . dumps ( msg ) )
  oOO0O = lisp_command_ipc ( oOO0O , "lisp-itr" )
  lisp_ipc ( oOO0O , lisp_ipc_socket , "lisp-etr" )
  return
  if 23 - 23: I1IiiI - I1ii11iIi11i . O0 . OoOoOO00 . OoO0O00
  if 81 - 81: IiII * I11i - iIii1I11I1II1
  if 41 - 41: oO0o * I11i + I1IiiI - OoO0O00
  if 63 - 63: Oo0Ooo * Ii1I - Ii1I
  if 76 - 76: OoO0O00 . IiII % iIii1I11I1II1 / I1IiiI + iIii1I11I1II1 . I1IiiI
  if 57 - 57: IiII - i1IIi * ooOoO0o
  if 5 - 5: oO0o . O0 * IiII / Ii1I + OoO0O00
  if 75 - 75: OOooOOo * OoOoOO00
 oOO0O = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( oOO0O , msg ) )
 if 82 - 82: Ii1I
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 83 - 83: I1IiiI
 I1I1 = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 67 - 67: I11i . I11i % I11i + Ii1I + Oo0Ooo - I1ii11iIi11i
 for oO0oi1iIIIi in I1I1 :
  III1i1i1iIIi = 0 if msg . has_key ( oO0oi1iIIIi ) == False else msg [ oO0oi1iIIIi ] [ "packet-count" ]
  if 76 - 76: i11iIiiIii * oO0o / I1IiiI
  lisp_decap_stats [ oO0oi1iIIIi ] . packet_count += III1i1i1iIIi
  if 10 - 10: iII111i * iIii1I11I1II1 % OoO0O00 * ooOoO0o
  IiI1iiI11 = 0 if msg . has_key ( oO0oi1iIIIi ) == False else msg [ oO0oi1iIIIi ] [ "byte-count" ]
  if 10 - 10: OoOoOO00
  lisp_decap_stats [ oO0oi1iIIIi ] . byte_count += IiI1iiI11
  if 97 - 97: OOooOOo
  Oo0OO0000oooo = 0 if msg . has_key ( oO0oi1iIIIi ) == False else msg [ oO0oi1iIIIi ] [ "seconds-last-packet" ]
  if 86 - 86: i11iIiiIii
  lisp_decap_stats [ oO0oi1iIIIi ] . last_increment = lisp_get_timestamp ( ) - Oo0OO0000oooo
  if 45 - 45: OoooooooOO + II111iiii + iIii1I11I1II1 % O0 % OOooOOo + i1IIi
 return
 if 51 - 51: oO0o / ooOoO0o - OOooOOo + oO0o
 if 28 - 28: OoOoOO00 % I11i + o0oOOo0O0Ooo
 if 51 - 51: iIii1I11I1II1 + I1ii11iIi11i % OoooooooOO + Ii1I
 if 20 - 20: O0 * I1ii11iIi11i + OoOoOO00 * OOooOOo . i1IIi . o0oOOo0O0Ooo
 if 26 - 26: OOooOOo - OoOoOO00 + I1ii11iIi11i + OoO0O00 - OoOoOO00 / o0oOOo0O0Ooo
 if 76 - 76: I1ii11iIi11i / oO0o + Ii1I - O0
 if 95 - 95: OoOoOO00
 if 69 - 69: iII111i / Ii1I
 if 83 - 83: oO0o
 if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
 if 29 - 29: OoooooooOO
 if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
 if 83 - 83: iIii1I11I1II1
 if 92 - 92: OoO0O00 - iII111i
 if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
 if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
 if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 o0o0O0oOoO , O0O00Oo = punt_socket . recvfrom ( 4000 )
 if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
 i11Ii = json . loads ( o0o0O0oOoO )
 if ( type ( i11Ii ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( O0O00Oo ) )
  if 34 - 34: Oo0Ooo . i1IIi
  return
  if 97 - 97: I11i
 o0oOOoo0OO0 = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( o0oOOoo0OO0 , O0O00Oo , i11Ii ) )
 if 52 - 52: iII111i - II111iiii % i1IIi / iII111i
 if ( i11Ii . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 14 - 14: oO0o / I1Ii111 / IiII - i1IIi * Ii1I
  if 90 - 90: ooOoO0o
  if 100 - 100: iII111i * i1IIi . iII111i / O0 / OoO0O00 - oO0o
  if 65 - 65: OoOoOO00 + ooOoO0o * OoO0O00 % OoooooooOO + OoooooooOO * OoooooooOO
  if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
 if ( i11Ii [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( i11Ii , lisp_send_sockets , lisp_ephem_port )
  return
  if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
 if ( i11Ii [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( i11Ii , punt_socket )
  return
  if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
  if 55 - 55: Oo0Ooo - OOooOOo - O0
  if 40 - 40: OoOoOO00 - OOooOOo
  if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
  if 35 - 35: II111iiii
 if ( i11Ii [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
  if 96 - 96: O0
  if 15 - 15: i1IIi . iIii1I11I1II1
  if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
  if 11 - 11: I1IiiI % Ii1I * i11iIiiIii % OOooOOo + II111iiii
 if ( i11Ii [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 61 - 61: I1Ii111 + I11i + I1IiiI
 if ( i11Ii . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( O0O00Oo ) )
  if 48 - 48: I11i
  return
  if 67 - 67: o0oOOo0O0Ooo
  if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
  if 61 - 61: i11iIiiIii / Ii1I - OOooOOo . I1ii11iIi11i
  if 89 - 89: ooOoO0o % i11iIiiIii
  if 57 - 57: Oo0Ooo / ooOoO0o - O0 . ooOoO0o
 OO0oo00oOO = i11Ii [ "interface" ]
 if ( OO0oo00oOO == "" ) :
  oOo00Ooo0o0 = int ( i11Ii [ "instance-id" ] )
  if ( oOo00Ooo0o0 == - 1 ) : return
 else :
  oOo00Ooo0o0 = lisp_get_interface_instance_id ( OO0oo00oOO , None )
  if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
  if 75 - 75: Ii1I
  if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
  if 99 - 99: oO0o + I11i % i1IIi . iII111i
  if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
 Oooo0OOO0oo0o = None
 if ( i11Ii . has_key ( "source-eid" ) ) :
  i1Iii = i11Ii [ "source-eid" ]
  Oooo0OOO0oo0o = lisp_address ( LISP_AFI_NONE , i1Iii , 0 , oOo00Ooo0o0 )
  if ( Oooo0OOO0oo0o . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( i1Iii ) )
   return
   if 65 - 65: OoO0O00
   if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
 OOOoOO0o00o0o = None
 if ( i11Ii . has_key ( "dest-eid" ) ) :
  I1II1i = i11Ii [ "dest-eid" ]
  OOOoOO0o00o0o = lisp_address ( LISP_AFI_NONE , I1II1i , 0 , oOo00Ooo0o0 )
  if ( OOOoOO0o00o0o . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( I1II1i ) )
   return
   if 16 - 16: iIii1I11I1II1 . I1Ii111 * OoO0O00
   if 78 - 78: iIii1I11I1II1 + I11i - OoOoOO00 / I1ii11iIi11i + iIii1I11I1II1 % II111iiii
   if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
   if 48 - 48: ooOoO0o + Oo0Ooo / Oo0Ooo
   if 15 - 15: iIii1I11I1II1 . I1Ii111 * OoooooooOO * O0 % OOooOOo
   if 53 - 53: Ii1I
   if 63 - 63: I11i % OoOoOO00
   if 46 - 46: iIii1I11I1II1 . II111iiii / OoooooooOO - ooOoO0o * iII111i
 if ( Oooo0OOO0oo0o ) :
  o0OoO00 = green ( Oooo0OOO0oo0o . print_address ( ) , False )
  o00o0oOo0o0O = lisp_db_for_lookups . lookup_cache ( Oooo0OOO0oo0o , False )
  if ( o00o0oOo0o0O != None ) :
   if 52 - 52: I11i + iII111i
   if 9 - 9: OoOoOO00 % II111iiii . I11i * Oo0Ooo
   if 53 - 53: II111iiii / i1IIi + OoooooooOO * O0
   if 62 - 62: IiII . O0
   if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
   if ( o00o0oOo0o0O . dynamic_eid_configured ( ) ) :
    I1i = lisp_allow_dynamic_eid ( OO0oo00oOO , Oooo0OOO0oo0o )
    if ( I1i != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( o00o0oOo0o0O , Oooo0OOO0oo0o , OO0oo00oOO , I1i )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( o0OoO00 , OO0oo00oOO ) )
     if 91 - 91: OOooOOo % oO0o . OoOoOO00 . I1IiiI - OoOoOO00
     if 18 - 18: O0 - I1IiiI + i1IIi % i11iIiiIii
     if 97 - 97: iII111i * OoooooooOO + I1Ii111 + ooOoO0o - ooOoO0o
  else :
   lprint ( "Punt from non-EID source {}" . format ( o0OoO00 ) )
   if 63 - 63: o0oOOo0O0Ooo * OOooOOo + iIii1I11I1II1 + Oo0Ooo
   if 25 - 25: oO0o + IiII % o0oOOo0O0Ooo
   if 24 - 24: OoOoOO00
   if 87 - 87: I1ii11iIi11i / ooOoO0o * i1IIi
   if 71 - 71: OoOoOO00 - I11i
   if 83 - 83: oO0o + oO0o - Oo0Ooo . Oo0Ooo - iII111i . OOooOOo
 if ( OOOoOO0o00o0o ) :
  OoOoooooO00oo = lisp_map_cache_lookup ( Oooo0OOO0oo0o , OOOoOO0o00o0o )
  if ( OoOoooooO00oo == None or OoOoooooO00oo . action == LISP_SEND_MAP_REQUEST_ACTION ) :
   if 56 - 56: OoOoOO00 * IiII + i1IIi
   if 40 - 40: I1ii11iIi11i / O0
   if 87 - 87: ooOoO0o
   if 100 - 100: iII111i + II111iiii * Oo0Ooo * OOooOOo
   if 6 - 6: IiII % OOooOOo
   if ( lisp_rate_limit_map_request ( Oooo0OOO0oo0o , OOOoOO0o00o0o ) ) : return
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 Oooo0OOO0oo0o , OOOoOO0o00o0o , None )
  else :
   o0OoO00 = green ( OOOoOO0o00o0o . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( o0OoO00 ) )
   if 3 - 3: OoOoOO00 / OoOoOO00 - II111iiii
   if 41 - 41: oO0o
 return
 if 12 - 12: I1IiiI + I1Ii111
 if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
 if 74 - 74: O0 % OOooOOo * OoOoOO00 / oO0o - Oo0Ooo
 if 79 - 79: Ii1I + IiII
 if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
 if 98 - 98: I1ii11iIi11i
 if 58 - 58: IiII / i11iIiiIii % I11i
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 iIiiiIIiii = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( iIiiiIIiii )
 return ( [ True , jdata ] )
 if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
 if 21 - 21: Ii1I
 if 72 - 72: I1Ii111 . OoooooooOO / I1Ii111 - Ii1I / I1ii11iIi11i * I1ii11iIi11i
 if 72 - 72: IiII . Ii1I + OoooooooOO * OoOoOO00 + Oo0Ooo . iII111i
 if 92 - 92: O0 * Ii1I - I1ii11iIi11i - IiII . OoO0O00 + I1IiiI
 if 59 - 59: i1IIi * OOooOOo % Oo0Ooo
 if 44 - 44: iIii1I11I1II1 . OOooOOo
 if 57 - 57: II111iiii + I1Ii111
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 42 - 42: OoOoOO00 % O0
 if 70 - 70: iIii1I11I1II1 * Oo0Ooo - I1IiiI / OoO0O00 + OoOoOO00
 if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
 if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
 if 26 - 26: Ii1I * I11i / I11i
 if 79 - 79: ooOoO0o / oO0o - oO0o / OoooooooOO
 if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
 if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
 if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
 if 16 - 16: I11i
 if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
 if 61 - 61: O0 % iII111i
 if 41 - 41: I1Ii111 * OoooooooOO
 if 76 - 76: OoooooooOO * II111iiii . II111iiii / o0oOOo0O0Ooo - iII111i
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 iiI1Ii1I = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( iiI1Ii1I ) ) :
  db . dynamic_eids [ iiI1Ii1I ] . last_packet = lisp_get_timestamp ( )
  return
  if 49 - 49: O0 . I1ii11iIi11i . OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
  if 19 - 19: iIii1I11I1II1
  if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
  if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
  if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
 O00o0 = lisp_dynamic_eid ( )
 O00o0 . dynamic_eid . copy_address ( eid )
 O00o0 . interface = routed_interface
 O00o0 . last_packet = lisp_get_timestamp ( )
 O00o0 . get_timeout ( routed_interface )
 db . dynamic_eids [ iiI1Ii1I ] = O00o0
 if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
 O0O0OO0Oo = ""
 if ( input_interface != routed_interface ) :
  O0O0OO0Oo = ", routed-interface " + routed_interface
  if 22 - 22: OoooooooOO / Ii1I % i11iIiiIii
  if 27 - 27: iII111i / iII111i
 i1I111i = green ( iiI1Ii1I , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( i1I111i , input_interface , O0O0OO0Oo , O00o0 . timeout ) )
 if 66 - 66: Ii1I / oO0o - ooOoO0o
 if 6 - 6: I1IiiI - oO0o + OoO0O00
 if 58 - 58: iIii1I11I1II1 + OoOoOO00
 if 65 - 65: iII111i % Oo0Ooo * iIii1I11I1II1 + I1IiiI + II111iiii
 if 72 - 72: OoOoOO00 . OoooooooOO - OOooOOo
 oOO0O = "learn%{}%{}" . format ( iiI1Ii1I , routed_interface )
 oOO0O = lisp_command_ipc ( oOO0O , "lisp-itr" )
 lisp_ipc ( oOO0O , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 15 - 15: OoOoOO00
 if 13 - 13: I1ii11iIi11i - OOooOOo - i11iIiiIii / IiII
 if 65 - 65: IiII
 if 76 - 76: I1Ii111 % I1ii11iIi11i + ooOoO0o / I1IiiI
 if 59 - 59: OOooOOo - o0oOOo0O0Ooo - o0oOOo0O0Ooo % I1IiiI
 if 55 - 55: o0oOOo0O0Ooo % I1ii11iIi11i - IiII + OoooooooOO
 if 44 - 44: iII111i * I1Ii111 - I1IiiI % i1IIi
 if 35 - 35: iII111i . OoOoOO00 + i1IIi . I1Ii111 - oO0o
 if 92 - 92: o0oOOo0O0Ooo
 if 8 - 8: i1IIi / IiII . O0
 if 72 - 72: OOooOOo
 if 20 - 20: i11iIiiIii + Oo0Ooo * Oo0Ooo % OOooOOo
 if 66 - 66: I1ii11iIi11i + iII111i / Ii1I / I1IiiI * i11iIiiIii
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
 if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
 if 71 - 71: oO0o
 if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
 II1i1i = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 16 - 16: I1Ii111 + O0 - O0 * iIii1I11I1II1 / iII111i
 for iII1 in lisp_crypto_keys_by_rloc_decap :
  if 4 - 4: iII111i
  if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
  if 32 - 32: iII111i
  if 59 - 59: OoOoOO00 - I1Ii111
  if ( iII1 . find ( addr_str ) == - 1 ) : continue
  if 34 - 34: ooOoO0o . OoooooooOO / ooOoO0o + OoooooooOO
  if 24 - 24: OoooooooOO * I1ii11iIi11i / O0 / Oo0Ooo * I1IiiI / ooOoO0o
  if 33 - 33: Ii1I
  if 20 - 20: Ii1I + I11i
  if ( iII1 == addr_str ) : continue
  if 98 - 98: OOooOOo
  if 58 - 58: i11iIiiIii / OoOoOO00
  if 18 - 18: ooOoO0o + O0 - OOooOOo + iIii1I11I1II1 . OOooOOo * iIii1I11I1II1
  if 83 - 83: OoO0O00 - Oo0Ooo * I1IiiI % Oo0Ooo % oO0o
  iIiiiIIiii = lisp_crypto_keys_by_rloc_decap [ iII1 ]
  if ( iIiiiIIiii == II1i1i ) : continue
  if 64 - 64: OoOoOO00 + oO0o / OoooooooOO . i11iIiiIii / II111iiii
  if 55 - 55: ooOoO0o . i11iIiiIii . o0oOOo0O0Ooo
  if 52 - 52: IiII . oO0o + i11iIiiIii % IiII
  if 45 - 45: i1IIi - I1IiiI / IiII - I1IiiI
  iIi1iI11I1i1 = iIiiiIIiii [ 1 ]
  if ( packet_icv != iIi1iI11I1i1 . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( iII1 , False ) ) )
   continue
   if 93 - 93: II111iiii
   if 85 - 85: O0 . II111iiii - Ii1I * I1ii11iIi11i / I1ii11iIi11i . OoOoOO00
  lprint ( "Changing decap crypto key to {}" . format ( red ( iII1 , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = iIiiiIIiii
  if 55 - 55: OoooooooOO
 return
 if 26 - 26: OoooooooOO * iII111i - iIii1I11I1II1 + I1ii11iIi11i
 if 37 - 37: iII111i - OoooooooOO . i11iIiiIii * i1IIi - II111iiii * ooOoO0o
 if 54 - 54: OoooooooOO / Oo0Ooo - I1Ii111 / OOooOOo
 if 41 - 41: oO0o . II111iiii
 if 47 - 47: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 23 - 23: i11iIiiIii / I11i + i1IIi % I1Ii111
 if 100 - 100: Oo0Ooo
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 13 - 13: I1IiiI + ooOoO0o * II111iiii
 if 32 - 32: iIii1I11I1II1 + O0 + i1IIi
 if 28 - 28: IiII + I11i
 if 1 - 1: OoooooooOO - i11iIiiIii . OoooooooOO - o0oOOo0O0Ooo - OOooOOo * I1Ii111
 if 56 - 56: Ii1I . OoO0O00
 if 43 - 43: iII111i * iII111i
 if 31 - 31: O0 - iIii1I11I1II1 . I11i . oO0o
 if 96 - 96: OoooooooOO * iIii1I11I1II1 * Oo0Ooo
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 oOo0oooo = dns_name . split ( "." )
 oOo0oooo = "." . join ( oOo0oooo [ 1 : : ] )
 return ( oOo0oooo == lisp_decent_dns_suffix )
 if 76 - 76: OoO0O00 / i11iIiiIii % ooOoO0o % I11i * O0
 if 84 - 84: II111iiii - iII111i / IiII . O0 % i1IIi / I1ii11iIi11i
 if 2 - 2: OoooooooOO . OoO0O00 . II111iiii / Ii1I - OOooOOo % Oo0Ooo
 if 47 - 47: OOooOOo * oO0o
 if 41 - 41: OoooooooOO * I1IiiI
 if 3 - 3: IiII
 if 96 - 96: I11i - OOooOOo + I11i
def lisp_get_decent_index ( eid ) :
 iiI1Ii1I = eid . print_prefix ( )
 oO0oOo = hashlib . sha256 ( iiI1Ii1I ) . hexdigest ( )
 OO000o00 = int ( oO0oOo , 16 ) % lisp_decent_modulus
 return ( OO000o00 )
 if 30 - 30: OoOoOO00 + OoooooooOO - OoOoOO00 / Ii1I - Ii1I / i11iIiiIii
 if 48 - 48: iIii1I11I1II1 % OoooooooOO * Ii1I . i1IIi . oO0o % iIii1I11I1II1
 if 89 - 89: I11i + I11i * OoooooooOO + IiII % iIii1I11I1II1
 if 52 - 52: i1IIi
 if 85 - 85: I1Ii111 - iII111i
 if 44 - 44: I11i - I11i - IiII . I11i
 if 34 - 34: iIii1I11I1II1 - oO0o * i11iIiiIii * o0oOOo0O0Ooo
def lisp_get_decent_dns_name ( eid ) :
 OO000o00 = lisp_get_decent_index ( eid )
 return ( str ( OO000o00 ) + "." + lisp_decent_dns_suffix )
 if 15 - 15: I1Ii111
 if 25 - 25: I1ii11iIi11i * O0
 if 8 - 8: i11iIiiIii
 if 95 - 95: ooOoO0o + i1IIi / OOooOOo . i11iIiiIii
 if 31 - 31: iII111i - iII111i - oO0o
 if 62 - 62: Oo0Ooo % Oo0Ooo / OoooooooOO * o0oOOo0O0Ooo . Ii1I
 if 1 - 1: I1ii11iIi11i / II111iiii / II111iiii + o0oOOo0O0Ooo + OoooooooOO
 if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 I111o0oooO00o0 = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 OO000o00 = lisp_get_decent_index ( I111o0oooO00o0 )
 return ( str ( OO000o00 ) + "." + lisp_decent_dns_suffix )
 if 87 - 87: OOooOOo * OoO0O00
 if 61 - 61: iII111i - II111iiii . I1Ii111 % II111iiii / I11i
 if 86 - 86: II111iiii
 if 94 - 94: o0oOOo0O0Ooo % Ii1I * Ii1I % Oo0Ooo / I1ii11iIi11i
 if 40 - 40: Oo0Ooo . II111iiii / II111iiii - i1IIi
 if 91 - 91: Ii1I
 if 45 - 45: I1ii11iIi11i + Oo0Ooo
 if 72 - 72: I1ii11iIi11i
 if 5 - 5: i1IIi
 if 31 - 31: iII111i - OoooooooOO + oO0o / OoooooooOO + I1ii11iIi11i
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 93 - 93: o0oOOo0O0Ooo * I1ii11iIi11i % I1IiiI * ooOoO0o
 i1 = 28 if packet . inner_version == 4 else 48
 IIii1I11IIII = packet . packet [ i1 : : ]
 iIi111I1 = lisp_trace ( )
 if ( iIi111I1 . decode ( IIii1I11IIII ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 16 - 16: ooOoO0o
  if 49 - 49: o0oOOo0O0Ooo + o0oOOo0O0Ooo . OOooOOo - OoooooooOO
 OO0Oii1I1 = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 62 - 62: oO0o / O0 - I1Ii111 . IiII
 if 81 - 81: i11iIiiIii
 if 57 - 57: O0
 if 85 - 85: i11iIiiIii - i11iIiiIii - OoOoOO00 / II111iiii - II111iiii
 if 4 - 4: I1ii11iIi11i * O0 / OoO0O00 * II111iiii . iIii1I11I1II1 / OOooOOo
 if 97 - 97: i1IIi - OoOoOO00 . OoooooooOO
 if ( OO0Oii1I1 != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : OO0Oii1I1 += ":{}" . format ( packet . encap_port )
  if 24 - 24: iIii1I11I1II1 + OOooOOo * iII111i % IiII % OOooOOo
  if 64 - 64: IiII . I1ii11iIi11i - o0oOOo0O0Ooo - ooOoO0o + OoooooooOO
  if 95 - 95: iII111i . I1ii11iIi11i + ooOoO0o + o0oOOo0O0Ooo % OoO0O00
  if 50 - 50: iII111i * O0 % II111iiii
  if 80 - 80: OOooOOo - II111iiii - OoO0O00
 iIiiiIIiii = { }
 iIiiiIIiii [ "node" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 62 - 62: Ii1I . i11iIiiIii % OOooOOo
 Ii1Ii111I1ii1 = packet . outer_source
 if ( Ii1Ii111I1ii1 . is_null ( ) ) : Ii1Ii111I1ii1 = lisp_myrlocs [ 0 ]
 iIiiiIIiii [ "srloc" ] = Ii1Ii111I1ii1 . print_address_no_iid ( )
 if 59 - 59: I11i - I1IiiI
 if 95 - 95: OoOoOO00 + I1IiiI + iII111i
 if 15 - 15: Oo0Ooo - I1IiiI % OoO0O00 % iIii1I11I1II1 + O0 - II111iiii
 if 96 - 96: OoooooooOO
 if 1 - 1: oO0o * II111iiii + i1IIi * oO0o % I1IiiI
 if ( iIiiiIIiii [ "node" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  iIiiiIIiii [ "srloc" ] += ":{}" . format ( packet . inner_sport )
  if 53 - 53: i11iIiiIii . I1ii11iIi11i - OOooOOo - OOooOOo
  if 97 - 97: I1IiiI % iII111i % OoooooooOO / ooOoO0o / i11iIiiIii
 iIiiiIIiii [ "hn" ] = lisp_hostname
 iII1 = ed + "-ts"
 iIiiiIIiii [ iII1 ] = lisp_get_timestamp ( )
 if 7 - 7: O0 % IiII / o0oOOo0O0Ooo
 if 79 - 79: IiII + I1Ii111
 if 59 - 59: iII111i - oO0o . ooOoO0o / IiII * i11iIiiIii
 if 61 - 61: I11i - Oo0Ooo * II111iiii + iIii1I11I1II1
 if 37 - 37: OoooooooOO % II111iiii / o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i . iIii1I11I1II1
 if 73 - 73: OoOoOO00
 if ( OO0Oii1I1 == "?" and iIiiiIIiii [ "node" ] == "ETR" ) :
  o00o0oOo0o0O = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( o00o0oOo0o0O != None and len ( o00o0oOo0o0O . rloc_set ) >= 1 ) :
   OO0Oii1I1 = o00o0oOo0o0O . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 44 - 44: Oo0Ooo / oO0o
   if 9 - 9: i1IIi % I1IiiI + OoO0O00 * ooOoO0o / iIii1I11I1II1 / iII111i
 iIiiiIIiii [ "drloc" ] = OO0Oii1I1
 if 80 - 80: OOooOOo / O0 % IiII * OoOoOO00
 if 53 - 53: OOooOOo + i11iIiiIii
 if 25 - 25: i11iIiiIii
 if 51 - 51: iII111i . ooOoO0o
 if ( OO0Oii1I1 == "?" and reason != None ) :
  iIiiiIIiii [ "drloc" ] += " ({})" . format ( reason )
  if 70 - 70: I11i / O0 - I11i + o0oOOo0O0Ooo . ooOoO0o . o0oOOo0O0Ooo
  if 6 - 6: I11i + II111iiii - I1Ii111
  if 45 - 45: i1IIi / iII111i + i11iIiiIii * I11i + ooOoO0o / OoooooooOO
  if 56 - 56: I11i + I1Ii111
  if 80 - 80: II111iiii . Ii1I + o0oOOo0O0Ooo / II111iiii / OoO0O00 + iIii1I11I1II1
 if ( rloc_entry != None ) :
  iIiiiIIiii [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  iIiiiIIiii [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  if 29 - 29: o0oOOo0O0Ooo + OoOoOO00 + ooOoO0o - I1ii11iIi11i
  if 64 - 64: O0 / OoooooooOO
  if 28 - 28: I1ii11iIi11i + oO0o . Oo0Ooo % iIii1I11I1II1 / I1Ii111
  if 8 - 8: O0 . I1IiiI * o0oOOo0O0Ooo + I1IiiI
  if 44 - 44: i1IIi % iII111i . i11iIiiIii / I11i + OoooooooOO
  if 21 - 21: OoOoOO00 . OoO0O00 . OoOoOO00 + OoOoOO00
 Oooo0OOO0oo0o = packet . inner_source . print_address ( )
 OOOoOO0o00o0o = packet . inner_dest . print_address ( )
 if ( iIi111I1 . packet_json == [ ] ) :
  O00oOO = { }
  O00oOO [ "seid" ] = Oooo0OOO0oo0o
  O00oOO [ "deid" ] = OOOoOO0o00o0o
  O00oOO [ "paths" ] = [ ]
  iIi111I1 . packet_json . append ( O00oOO )
  if 30 - 30: I1IiiI - iII111i - OOooOOo + oO0o
  if 51 - 51: Ii1I % O0 / II111iiii . Oo0Ooo
  if 90 - 90: i11iIiiIii * II111iiii % iIii1I11I1II1 . I1ii11iIi11i / Oo0Ooo . OOooOOo
  if 77 - 77: OoO0O00
  if 95 - 95: II111iiii
  if 59 - 59: iIii1I11I1II1 % OOooOOo / OoOoOO00 * I1Ii111 * OoooooooOO * O0
 for O00oOO in iIi111I1 . packet_json :
  if ( O00oOO [ "deid" ] != OOOoOO0o00o0o ) : continue
  O00oOO [ "paths" ] . append ( iIiiiIIiii )
  break
  if 43 - 43: OoO0O00 * I1IiiI * OOooOOo * O0 - O0 / o0oOOo0O0Ooo
  if 77 - 77: I11i % I1Ii111 . IiII % OoooooooOO * o0oOOo0O0Ooo
  if 87 - 87: iII111i + IiII / ooOoO0o * ooOoO0o * OOooOOo
  if 97 - 97: I1Ii111
  if 47 - 47: iII111i / I1ii11iIi11i - Ii1I . II111iiii
  if 56 - 56: O0 - i1IIi % o0oOOo0O0Ooo + IiII
  if 42 - 42: o0oOOo0O0Ooo . OOooOOo % I11i - OoOoOO00
  if 38 - 38: OoooooooOO
 Ii1Ii1I = False
 if ( len ( iIi111I1 . packet_json ) == 1 and iIiiiIIiii [ "node" ] == "ETR" and
 iIi111I1 . myeid ( packet . inner_dest ) ) :
  O00oOO = { }
  O00oOO [ "seid" ] = OOOoOO0o00o0o
  O00oOO [ "deid" ] = Oooo0OOO0oo0o
  O00oOO [ "paths" ] = [ ]
  iIi111I1 . packet_json . append ( O00oOO )
  Ii1Ii1I = True
  if 21 - 21: OoOoOO00 + IiII / I1IiiI
  if 29 - 29: ooOoO0o / iIii1I11I1II1 - I1IiiI
  if 93 - 93: OOooOOo
  if 49 - 49: I1ii11iIi11i * I1IiiI + OOooOOo + i11iIiiIii * I1ii11iIi11i . o0oOOo0O0Ooo
  if 36 - 36: o0oOOo0O0Ooo - i11iIiiIii
  if 37 - 37: O0 + IiII + I1IiiI
 iIi111I1 . print_trace ( )
 IIii1I11IIII = iIi111I1 . encode ( )
 if 50 - 50: OoooooooOO . I1Ii111
 if 100 - 100: ooOoO0o * ooOoO0o - Ii1I
 if 13 - 13: iII111i . I11i * OoO0O00 . i1IIi . iIii1I11I1II1 - o0oOOo0O0Ooo
 if 68 - 68: Ii1I % o0oOOo0O0Ooo / OoooooooOO + Ii1I - Ii1I
 if 79 - 79: II111iiii / IiII
 if 4 - 4: O0 - i11iIiiIii % ooOoO0o * O0 - ooOoO0o
 if 96 - 96: oO0o % II111iiii . Ii1I % OoO0O00 . iIii1I11I1II1 / IiII
 if 96 - 96: o0oOOo0O0Ooo / O0 . iIii1I11I1II1 . Ii1I % OOooOOo % II111iiii
 Ii11i = iIi111I1 . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "srloc" ]
 if ( OO0Oii1I1 == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( Ii11i ) )
  iIi111I1 . return_to_sender ( lisp_socket , Ii11i , IIii1I11IIII )
  return ( False )
  if 93 - 93: I1Ii111 / o0oOOo0O0Ooo
  if 33 - 33: OOooOOo * IiII * OoO0O00 - I1ii11iIi11i % OoO0O00
  if 16 - 16: OoO0O00 * I1IiiI
  if 58 - 58: oO0o * II111iiii * O0
  if 89 - 89: I1Ii111 + IiII % I1ii11iIi11i
  if 80 - 80: Oo0Ooo + ooOoO0o + IiII
 ii1I = iIi111I1 . packet_length ( )
 if 76 - 76: I1Ii111
 if 23 - 23: O0 % I1ii11iIi11i % iIii1I11I1II1
 if 49 - 49: iII111i + I1Ii111 % OoOoOO00
 if 67 - 67: Ii1I
 if 27 - 27: Oo0Ooo / i11iIiiIii / II111iiii . Ii1I - II111iiii / OoO0O00
 if 61 - 61: ooOoO0o - OOooOOo
 iiIo0OoOO = packet . packet [ 0 : i1 ]
 iIiiI11II11 = struct . pack ( "HH" , socket . htons ( ii1I ) , 0 )
 iiIo0OoOO = iiIo0OoOO [ 0 : i1 - 4 ] + iIiiI11II11
 if ( packet . inner_version == 6 and iIiiiIIiii [ "node" ] == "ETR" and
 len ( iIi111I1 . packet_json ) == 2 ) :
  O0OO0ooO00 = iiIo0OoOO [ i1 - 8 : : ] + IIii1I11IIII
  O0OO0ooO00 = lisp_udp_checksum ( Oooo0OOO0oo0o , OOOoOO0o00o0o , O0OO0ooO00 )
  iiIo0OoOO = iiIo0OoOO [ 0 : i1 - 8 ] + O0OO0ooO00 [ 0 : 8 ]
  if 90 - 90: oO0o + iIii1I11I1II1 % i1IIi - OoooooooOO . Ii1I
  if 91 - 91: iII111i - i11iIiiIii
  if 27 - 27: iII111i
  if 66 - 66: O0 . iIii1I11I1II1 * II111iiii * OOooOOo * IiII
  if 44 - 44: i11iIiiIii % ooOoO0o * i11iIiiIii + Oo0Ooo + I1ii11iIi11i + Ii1I
  if 43 - 43: i1IIi . iIii1I11I1II1
 if ( Ii1Ii1I ) :
  if ( packet . inner_version == 4 ) :
   iiIo0OoOO = iiIo0OoOO [ 0 : 12 ] + iiIo0OoOO [ 16 : 20 ] + iiIo0OoOO [ 12 : 16 ] + iiIo0OoOO [ 22 : 24 ] + iiIo0OoOO [ 20 : 22 ] + iiIo0OoOO [ 24 : : ]
   if 86 - 86: OOooOOo + OoOoOO00 - OoO0O00 + i1IIi + iIii1I11I1II1
  else :
   iiIo0OoOO = iiIo0OoOO [ 0 : 8 ] + iiIo0OoOO [ 24 : 40 ] + iiIo0OoOO [ 8 : 24 ] + iiIo0OoOO [ 42 : 44 ] + iiIo0OoOO [ 40 : 42 ] + iiIo0OoOO [ 44 : : ]
   if 68 - 68: OoOoOO00 . I1IiiI + ooOoO0o - o0oOOo0O0Ooo
   if 62 - 62: Ii1I - OOooOOo
  Ii = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = Ii
  if 88 - 88: iIii1I11I1II1 * Oo0Ooo / II111iiii / IiII / OoO0O00 % ooOoO0o
  if 19 - 19: I11i * iII111i . O0 * iII111i % I1ii11iIi11i - OoOoOO00
  if 68 - 68: I1Ii111 - OoO0O00 % Ii1I + i1IIi . ooOoO0o
  if 36 - 36: oO0o * iIii1I11I1II1 - O0 - IiII * O0 + i11iIiiIii
  if 76 - 76: OoO0O00 % O0 / Ii1I + I1IiiI
 i1 = 2 if packet . inner_version == 4 else 4
 iii1IiiII1i = 20 + ii1I if packet . inner_version == 4 else ii1I
 I1IIIIiiii = struct . pack ( "H" , socket . htons ( iii1IiiII1i ) )
 iiIo0OoOO = iiIo0OoOO [ 0 : i1 ] + I1IIIIiiii + iiIo0OoOO [ i1 + 2 : : ]
 if 13 - 13: II111iiii / iIii1I11I1II1
 if 82 - 82: o0oOOo0O0Ooo / ooOoO0o . I1IiiI + ooOoO0o
 if 71 - 71: oO0o + ooOoO0o
 if 87 - 87: ooOoO0o % oO0o
 if ( packet . inner_version == 4 ) :
  ii1i1 = struct . pack ( "H" , 0 )
  iiIo0OoOO = iiIo0OoOO [ 0 : 10 ] + ii1i1 + iiIo0OoOO [ 12 : : ]
  I1IIIIiiii = lisp_ip_checksum ( iiIo0OoOO [ 0 : 20 ] )
  iiIo0OoOO = I1IIIIiiii + iiIo0OoOO [ 20 : : ]
  if 45 - 45: oO0o
  if 95 - 95: iII111i * iIii1I11I1II1 . i1IIi
  if 43 - 43: oO0o * ooOoO0o - I11i
  if 70 - 70: oO0o / Ii1I
  if 15 - 15: iIii1I11I1II1 % ooOoO0o % i11iIiiIii
 packet . packet = iiIo0OoOO + IIii1I11IIII
 return ( True )
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
def lisp_allow_gleaning ( eid , group , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False , False )
 if 48 - 48: ooOoO0o % ooOoO0o / OoooooooOO + i1IIi * oO0o + ooOoO0o
 for iIiiiIIiii in lisp_glean_mappings :
  if ( iIiiiIIiii . has_key ( "instance-id" ) ) :
   oOo00Ooo0o0 = eid . instance_id
   iI111 , OoO0 = iIiiiIIiii [ "instance-id" ]
   if ( oOo00Ooo0o0 < iI111 or oOo00Ooo0o0 > OoO0 ) : continue
   if 69 - 69: iII111i . iII111i
  if ( iIiiiIIiii . has_key ( "eid-prefix" ) ) :
   o0OoO00 = copy . deepcopy ( iIiiiIIiii [ "eid-prefix" ] )
   o0OoO00 . instance_id = eid . instance_id
   if ( eid . is_more_specific ( o0OoO00 ) == False ) : continue
   if 46 - 46: IiII * Oo0Ooo + I1Ii111
  if ( iIiiiIIiii . has_key ( "group-prefix" ) ) :
   if ( group == None ) : continue
   II1IIiIiiI1iI = copy . deepcopy ( iIiiiIIiii [ "group-prefix" ] )
   II1IIiIiiI1iI . instance_id = group . instance_id
   if ( group . is_more_specific ( II1IIiIiiI1iI ) == False ) : continue
   if 79 - 79: IiII
  if ( iIiiiIIiii . has_key ( "rloc-prefix" ) ) :
   if ( rloc != None and rloc . is_more_specific ( iIiiiIIiii [ "rloc-prefix" ] )
 == False ) : continue
   if 89 - 89: IiII * I11i + I1ii11iIi11i * oO0o - II111iiii
  return ( True , iIiiiIIiii [ "rloc-probe" ] , iIiiiIIiii [ "igmp-query" ] )
  if 58 - 58: ooOoO0o . I1Ii111 / i1IIi % I1ii11iIi11i + o0oOOo0O0Ooo
 return ( False , False , False )
 if 94 - 94: i11iIiiIii + I1Ii111 . iII111i - ooOoO0o % I1Ii111
 if 94 - 94: i11iIiiIii - OOooOOo - O0 * OoooooooOO - ooOoO0o
 if 35 - 35: iII111i . i11iIiiIii - OOooOOo % Oo0Ooo + Ii1I . iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo / OoO0O00 + I1IiiI % i11iIiiIii % i1IIi
 if 22 - 22: I1Ii111 * O0 % OoO0O00 * I1ii11iIi11i
 if 47 - 47: OoO0O00 / OOooOOo / OoOoOO00 % i11iIiiIii / OoOoOO00
 if 52 - 52: ooOoO0o / I11i % i11iIiiIii - I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
def lisp_build_gleaned_multicast ( seid , geid , rloc , port , igmp ) :
 iiIiII11i1 = geid . print_address ( )
 OOO0o0Oo0O0O0O0O = seid . print_address_no_iid ( )
 o0 = green ( "{}" . format ( OOO0o0Oo0O0O0O0O ) , False )
 o0OoO00 = green ( "(*, {})" . format ( iiIiII11i1 ) , False )
 O0OooO0oo = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 if 7 - 7: iIii1I11I1II1 * o0oOOo0O0Ooo . oO0o
 if 62 - 62: i11iIiiIii + o0oOOo0O0Ooo + I1ii11iIi11i / OOooOOo % OOooOOo
 if 99 - 99: I1Ii111 - O0 . I11i - IiII * i1IIi
 if 98 - 98: Ii1I / o0oOOo0O0Ooo . I1Ii111 + I1IiiI . i1IIi - I11i
 OoOoooooO00oo = lisp_map_cache_lookup ( seid , geid )
 if ( OoOoooooO00oo == None ) :
  OoOoooooO00oo = lisp_mapping ( "" , "" , [ ] )
  OoOoooooO00oo . group . copy_address ( geid )
  OoOoooooO00oo . eid . copy_address ( geid )
  OoOoooooO00oo . eid . address = 0
  OoOoooooO00oo . eid . mask_len = 0
  OoOoooooO00oo . mapping_source . copy_address ( rloc )
  OoOoooooO00oo . map_cache_ttl = LISP_IGMP_TTL
  OoOoooooO00oo . gleaned = True
  OoOoooooO00oo . add_cache ( )
  lprint ( "Add gleaned EID {} to map-cache" . format ( o0OoO00 ) )
  if 92 - 92: ooOoO0o + o0oOOo0O0Ooo . I1ii11iIi11i
  if 25 - 25: IiII + i11iIiiIii . O0
  if 94 - 94: OoooooooOO + iII111i * OoooooooOO / o0oOOo0O0Ooo
  if 12 - 12: iIii1I11I1II1 / iIii1I11I1II1 / II111iiii
  if 93 - 93: oO0o
  if 53 - 53: OoO0O00 * i1IIi / Oo0Ooo / OoO0O00 * ooOoO0o
 IiIIIi = OoOOOO000Oo = Oo0000O00o0 = None
 if ( OoOoooooO00oo . rloc_set != [ ] ) :
  IiIIIi = OoOoooooO00oo . rloc_set [ 0 ]
  if ( IiIIIi . rle ) :
   OoOOOO000Oo = IiIIIi . rle
   for IiIii1i11III in OoOOOO000Oo . rle_nodes :
    if ( IiIii1i11III . rloc_name != OOO0o0Oo0O0O0O0O ) : continue
    Oo0000O00o0 = IiIii1i11III
    break
    if 49 - 49: iII111i / II111iiii + i11iIiiIii * Oo0Ooo
    if 100 - 100: Oo0Ooo * oO0o
    if 85 - 85: OoooooooOO . IiII / IiII . ooOoO0o . IiII % II111iiii
    if 65 - 65: oO0o - OoO0O00 / iII111i + ooOoO0o
    if 80 - 80: o0oOOo0O0Ooo + II111iiii * Ii1I % OoOoOO00 % I1IiiI + I1ii11iIi11i
    if 46 - 46: Oo0Ooo / Oo0Ooo % iII111i % I1IiiI
    if 85 - 85: OoO0O00 - Ii1I / O0
 if ( IiIIIi == None ) :
  IiIIIi = lisp_rloc ( )
  OoOoooooO00oo . rloc_set = [ IiIIIi ]
  IiIIIi . priority = 253
  IiIIIi . mpriority = 255
  OoOoooooO00oo . build_best_rloc_set ( )
  if 45 - 45: IiII + I1Ii111 / I11i
 if ( OoOOOO000Oo == None ) :
  OoOOOO000Oo = lisp_rle ( geid . print_address ( ) )
  IiIIIi . rle = OoOOOO000Oo
  if 84 - 84: iII111i % II111iiii
 if ( Oo0000O00o0 == None ) :
  Oo0000O00o0 = lisp_rle_node ( )
  Oo0000O00o0 . rloc_name = OOO0o0Oo0O0O0O0O
  OoOOOO000Oo . rle_nodes . append ( Oo0000O00o0 )
  OoOOOO000Oo . build_forwarding_list ( )
  lprint ( "Add RLE {} from {} for gleaned EID {}" . format ( O0OooO0oo , o0 , o0OoO00 ) )
 elif ( rloc . is_exact_match ( Oo0000O00o0 . address ) == False or
 port != Oo0000O00o0 . translated_port ) :
  lprint ( "Changed RLE {} from {} for gleaned EID {}" . format ( O0OooO0oo , o0 , o0OoO00 ) )
  if 86 - 86: IiII % II111iiii / i1IIi * I1ii11iIi11i - O0 * OOooOOo
  if 53 - 53: OOooOOo * oO0o + i1IIi % Oo0Ooo + II111iiii
  if 34 - 34: oO0o % iII111i / IiII . IiII + i11iIiiIii
  if 68 - 68: O0 % oO0o * IiII % O0
  if 55 - 55: O0 % I1IiiI % O0
 Oo0000O00o0 . store_translated_rloc ( rloc , port )
 if 27 - 27: I1IiiI + I1ii11iIi11i * I1Ii111 % Ii1I - Oo0Ooo
 if 87 - 87: i11iIiiIii % OOooOOo - OoOoOO00 * ooOoO0o / Oo0Ooo
 if 74 - 74: OoooooooOO * ooOoO0o - I11i / I1ii11iIi11i % iIii1I11I1II1
 if 94 - 94: Ii1I * I1Ii111 + OoOoOO00 . iIii1I11I1II1
 if 44 - 44: Oo0Ooo . Oo0Ooo * Oo0Ooo
 if ( igmp ) :
  O0ooO0oOoOo = seid . print_address ( )
  if ( lisp_gleaned_groups . has_key ( O0ooO0oOoOo ) == False ) :
   lisp_gleaned_groups [ O0ooO0oOoOo ] = { }
   if 23 - 23: I1Ii111 / iII111i . O0 % II111iiii
  lisp_gleaned_groups [ O0ooO0oOoOo ] [ iiIiII11i1 ] = lisp_get_timestamp ( )
  if 67 - 67: I11i / iIii1I11I1II1 / ooOoO0o
  if 90 - 90: II111iiii % I1Ii111 - IiII . Oo0Ooo % OOooOOo - OoOoOO00
  if 89 - 89: Oo0Ooo - I1ii11iIi11i . I1Ii111
  if 65 - 65: ooOoO0o % OOooOOo + OOooOOo % I1Ii111 . I1IiiI % O0
  if 46 - 46: OoO0O00 * I1Ii111 + iII111i . oO0o % OOooOOo / i11iIiiIii
  if 1 - 1: I1ii11iIi11i % O0 - I1ii11iIi11i / OoooooooOO / OoO0O00
  if 82 - 82: i1IIi % Ii1I
  if 85 - 85: I1Ii111 * i11iIiiIii * iIii1I11I1II1 % iIii1I11I1II1
def lisp_remove_gleaned_multicast ( seid , geid ) :
 if 64 - 64: OoO0O00 / Ii1I
 if 79 - 79: Ii1I % OOooOOo
 if 39 - 39: I1ii11iIi11i / Ii1I - II111iiii . i1IIi
 if 59 - 59: II111iiii
 OoOoooooO00oo = lisp_map_cache_lookup ( seid , geid )
 if ( OoOoooooO00oo == None ) : return
 if 36 - 36: ooOoO0o . II111iiii - OoOoOO00 % I1ii11iIi11i * O0
 OoO000oo000o0 = OoOoooooO00oo . rloc_set [ 0 ] . rle
 if ( OoO000oo000o0 == None ) : return
 if 91 - 91: iII111i + Oo0Ooo / OoooooooOO * iIii1I11I1II1 - OoO0O00
 Ooo000oo0OO0 = seid . print_address_no_iid ( )
 OO0Oo0Oo = False
 for Oo0000O00o0 in OoO000oo000o0 . rle_nodes :
  if ( Oo0000O00o0 . rloc_name == Ooo000oo0OO0 ) :
   OO0Oo0Oo = True
   break
   if 73 - 73: iIii1I11I1II1 % I1Ii111 % II111iiii * Oo0Ooo * OoO0O00
   if 48 - 48: OOooOOo * i11iIiiIii - i11iIiiIii + iIii1I11I1II1 + I1IiiI % OoooooooOO
 if ( OO0Oo0Oo == False ) : return
 if 61 - 61: i1IIi
 if 56 - 56: iIii1I11I1II1 / I11i * iII111i * I11i * OoooooooOO
 if 44 - 44: I1ii11iIi11i - OOooOOo % I11i - I1Ii111 / iIii1I11I1II1 - OOooOOo
 if 38 - 38: iIii1I11I1II1 - OoooooooOO * II111iiii . OoooooooOO + OOooOOo
 OoO000oo000o0 . rle_nodes . remove ( Oo0000O00o0 )
 OoO000oo000o0 . build_forwarding_list ( )
 if 59 - 59: OoooooooOO
 iiIiII11i1 = geid . print_address ( )
 O0ooO0oOoOo = seid . print_address ( )
 o0 = green ( "{}" . format ( O0ooO0oOoOo ) , False )
 o0OoO00 = green ( "(*, {})" . format ( iiIiII11i1 ) , False )
 lprint ( "Gleaned EID {} RLE removed for {}" . format ( o0OoO00 , o0 ) )
 if 22 - 22: II111iiii
 if 85 - 85: I1Ii111 + I1ii11iIi11i * I11i % o0oOOo0O0Ooo + Ii1I
 if 23 - 23: IiII * OoO0O00
 if 42 - 42: IiII
 if ( lisp_gleaned_groups . has_key ( O0ooO0oOoOo ) ) :
  if ( lisp_gleaned_groups [ O0ooO0oOoOo ] . has_key ( iiIiII11i1 ) ) :
   lisp_gleaned_groups [ O0ooO0oOoOo ] . pop ( iiIiII11i1 )
   if 83 - 83: i1IIi * o0oOOo0O0Ooo / OoO0O00 / o0oOOo0O0Ooo
   if 55 - 55: Oo0Ooo % O0 - OoO0O00
   if 42 - 42: OoooooooOO * OOooOOo
   if 93 - 93: OOooOOo + II111iiii . oO0o * Oo0Ooo - O0 + I1Ii111
   if 99 - 99: OoO0O00 * o0oOOo0O0Ooo + OoOoOO00 * iIii1I11I1II1
   if 38 - 38: I1ii11iIi11i - OOooOOo * O0 - I1ii11iIi11i
 if ( OoO000oo000o0 . rle_nodes == [ ] ) :
  OoOoooooO00oo . delete_cache ( )
  lprint ( "Gleaned EID {} remove, no more RLEs" . format ( o0OoO00 ) )
  if 95 - 95: OoO0O00 . oO0o . OoooooooOO - iIii1I11I1II1
  if 35 - 35: o0oOOo0O0Ooo / OoooooooOO - i1IIi * iIii1I11I1II1 + ooOoO0o
  if 66 - 66: Oo0Ooo - OoOoOO00 . I1Ii111 + O0 + o0oOOo0O0Ooo
  if 36 - 36: II111iiii % IiII . i11iIiiIii
  if 88 - 88: Oo0Ooo . IiII * Oo0Ooo
  if 92 - 92: I1IiiI % IiII
  if 95 - 95: OoooooooOO / OoO0O00 % O0 / I1Ii111 * Ii1I + I1ii11iIi11i
  if 7 - 7: ooOoO0o
def lisp_change_gleaned_multicast ( seid , rloc , port ) :
 O0ooO0oOoOo = seid . print_address ( )
 if ( lisp_gleaned_groups . has_key ( O0ooO0oOoOo ) == False ) : return
 if 83 - 83: oO0o / I1Ii111 + I1Ii111 * I1ii11iIi11i
 for oOoooOOO0o0 in lisp_gleaned_groups [ O0ooO0oOoOo ] :
  lisp_geid . store_address ( oOoooOOO0o0 )
  lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , port , False )
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
  if 43 - 43: I1Ii111 + i11iIiiIii % iII111i % I1Ii111 - ooOoO0o
  if 85 - 85: IiII % iIii1I11I1II1 . I1Ii111
  if 38 - 38: iII111i - I1IiiI / ooOoO0o
  if 46 - 46: OOooOOo . O0 / i11iIiiIii . OOooOOo
  if 19 - 19: I11i / Oo0Ooo + I1Ii111
  if 43 - 43: I1ii11iIi11i
  if 18 - 18: I11i / OOooOOo % I11i - o0oOOo0O0Ooo
  if 22 - 22: iII111i
  if 88 - 88: I11i + OoOoOO00 % IiII % OoO0O00 * O0 / OoooooooOO
  if 83 - 83: IiII + I1Ii111 . I1ii11iIi11i * iIii1I11I1II1
  if 9 - 9: ooOoO0o % IiII - OoOoOO00
  if 66 - 66: oO0o % Oo0Ooo
  if 40 - 40: i11iIiiIii . O0 * I11i - oO0o / OOooOOo . oO0o
  if 86 - 86: OOooOOo - I1Ii111 * IiII - i1IIi + ooOoO0o + I11i
  if 32 - 32: IiII
  if 99 - 99: II111iiii
  if 34 - 34: OOooOOo + OoOoOO00 * o0oOOo0O0Ooo + I1ii11iIi11i + IiII * i1IIi
  if 73 - 73: I1ii11iIi11i - IiII - O0 . oO0o + Oo0Ooo % iII111i
  if 68 - 68: I1ii11iIi11i - OoooooooOO
  if 5 - 5: I1ii11iIi11i * I1IiiI + OoooooooOO / Oo0Ooo
  if 18 - 18: OoO0O00 * iII111i % I1IiiI . OOooOOo * o0oOOo0O0Ooo
  if 58 - 58: iII111i . IiII + iIii1I11I1II1
  if 13 - 13: oO0o * I1Ii111 / I1Ii111 . I1IiiI
  if 93 - 93: I11i % OoOoOO00 - OOooOOo + iIii1I11I1II1 / OoooooooOO % i11iIiiIii
  if 90 - 90: oO0o % iIii1I11I1II1 + o0oOOo0O0Ooo - I11i / i11iIiiIii
  if 57 - 57: I1IiiI . Oo0Ooo / I1IiiI / II111iiii - I1Ii111
  if 68 - 68: I1IiiI
  if 97 - 97: Ii1I + o0oOOo0O0Ooo / OoO0O00
  if 97 - 97: i11iIiiIii % iIii1I11I1II1 + II111iiii
  if 90 - 90: OOooOOo / I1IiiI
  if 28 - 28: OoooooooOO + i1IIi
  if 29 - 29: Oo0Ooo
  if 98 - 98: OOooOOo / Oo0Ooo % Ii1I * OoooooooOO - oO0o
  if 64 - 64: I1IiiI - I1IiiI
  if 90 - 90: iII111i - I1IiiI - II111iiii / OOooOOo + Ii1I
  if 34 - 34: i11iIiiIii + I1Ii111 / O0 / iIii1I11I1II1 * OoooooooOO % Ii1I
  if 32 - 32: i11iIiiIii - OoOoOO00 / iIii1I11I1II1 * o0oOOo0O0Ooo % I1IiiI + O0
  if 36 - 36: I1ii11iIi11i + I1ii11iIi11i % I1Ii111 * ooOoO0o * OoOoOO00
  if 54 - 54: Oo0Ooo - I1IiiI % OOooOOo . I1ii11iIi11i / I1IiiI
  if 75 - 75: OOooOOo - O0 % iII111i . Ii1I % I1ii11iIi11i + I1ii11iIi11i
  if 32 - 32: Ii1I + II111iiii * IiII
  if 9 - 9: I1Ii111
  if 96 - 96: I1Ii111 / iIii1I11I1II1
  if 48 - 48: iII111i * IiII + OoooooooOO
  if 63 - 63: I1IiiI / Ii1I
  if 31 - 31: i1IIi - oO0o
  if 99 - 99: iII111i - i11iIiiIii + oO0o
  if 66 - 66: Oo0Ooo * I11i . iIii1I11I1II1 - OoO0O00
  if 11 - 11: I1Ii111 + iIii1I11I1II1 * O0 * Oo0Ooo
  if 66 - 66: OoooooooOO % OoO0O00 + i11iIiiIii + I1Ii111 % OoO0O00
  if 80 - 80: Oo0Ooo - Ii1I
  if 54 - 54: O0 - iIii1I11I1II1 . OoO0O00 . IiII % OoO0O00
  if 28 - 28: O0 % i1IIi % OoO0O00 / o0oOOo0O0Ooo . iIii1I11I1II1 - iII111i
  if 50 - 50: o0oOOo0O0Ooo + iII111i / i1IIi % II111iiii
  if 61 - 61: IiII
  if 5 - 5: OOooOOo % iIii1I11I1II1 % O0 * i11iIiiIii / I1Ii111
  if 48 - 48: IiII * oO0o
  if 53 - 53: i1IIi * iIii1I11I1II1 . OOooOOo
  if 68 - 68: IiII % IiII - iII111i . IiII + OoooooooOO
  if 82 - 82: Ii1I . II111iiii / i1IIi * OoO0O00
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
  if 64 - 64: I1ii11iIi11i * ooOoO0o - OoooooooOO - I1IiiI
  if 59 - 59: I1ii11iIi11i . I1Ii111 - OOooOOo / Oo0Ooo + OOooOOo . I1ii11iIi11i
  if 69 - 69: Oo0Ooo
  if 34 - 34: I1Ii111 - ooOoO0o . o0oOOo0O0Ooo
  if 52 - 52: o0oOOo0O0Ooo % I11i * I11i / iIii1I11I1II1
  if 77 - 77: OoOoOO00
  if 67 - 67: OoooooooOO / OoooooooOO + IiII - ooOoO0o
  if 72 - 72: Ii1I
  if 21 - 21: ooOoO0o + iII111i
  if 39 - 39: o0oOOo0O0Ooo % I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo
igmp_types = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 78 - 78: OoO0O00 / o0oOOo0O0Ooo / O0 % OOooOOo % i1IIi
lisp_igmp_record_types = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 78 - 78: o0oOOo0O0Ooo - oO0o . II111iiii
def lisp_process_igmp_packet ( packet ) :
 O0O00Oo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 O0O00Oo . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 O0O00Oo = bold ( "from {}" . format ( O0O00Oo . print_address_no_iid ( ) ) , False )
 if 67 - 67: iII111i + I11i - OoO0O00 . OOooOOo * iIii1I11I1II1
 O0OooO0oo = bold ( "Receive" , False )
 lprint ( "{} {}-byte {}, IGMP packet: {}" . format ( O0OooO0oo , len ( packet ) , O0O00Oo ,
 lisp_format_packet ( packet ) ) )
 if 44 - 44: OoooooooOO * i1IIi % i1IIi - i11iIiiIii % OOooOOo - OoO0O00
 if 62 - 62: OOooOOo + OoooooooOO / I1Ii111 % iIii1I11I1II1
 if 59 - 59: i11iIiiIii . IiII
 if 91 - 91: Oo0Ooo / iII111i + I1Ii111
 IiI11I11 = ( struct . unpack ( "B" , packet [ 0 ] ) [ 0 ] & 0x0f ) * 4
 if 30 - 30: I1Ii111 . i1IIi * OoooooooOO * OoooooooOO
 if 43 - 43: OoooooooOO * O0
 if 56 - 56: i1IIi / iIii1I11I1II1 - OoO0O00
 if 77 - 77: I1IiiI + IiII - oO0o - I1ii11iIi11i * II111iiii + i1IIi
 oO0ooOo = packet [ IiI11I11 : : ]
 ooO0 = struct . unpack ( "B" , oO0ooOo [ 0 ] ) [ 0 ]
 if 88 - 88: OoOoOO00 - Ii1I . O0 % I1Ii111 % I1ii11iIi11i
 if 56 - 56: OoOoOO00 - iIii1I11I1II1 / I1IiiI - i1IIi / o0oOOo0O0Ooo * I11i
 if 70 - 70: OOooOOo
 if 11 - 11: I11i * II111iiii * Oo0Ooo + OOooOOo % i1IIi
 if 73 - 73: OoO0O00 + O0 / Ii1I . OoooooooOO % iIii1I11I1II1 * i1IIi
 oOoooOOO0o0 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 oOoooOOO0o0 . address = socket . ntohl ( struct . unpack ( "II" , oO0ooOo [ : 8 ] ) [ 1 ] )
 iiIiII11i1 = oOoooOOO0o0 . print_address_no_iid ( )
 if 84 - 84: o0oOOo0O0Ooo . iII111i / o0oOOo0O0Ooo + I1ii11iIi11i % OoO0O00
 if ( ooO0 == 17 ) :
  lprint ( "IGMP Query for group {}" . format ( iiIiII11i1 ) )
  return ( True )
  if 52 - 52: OoOoOO00 / Ii1I % OoOoOO00 % i11iIiiIii + I1IiiI / o0oOOo0O0Ooo
  if 63 - 63: I1IiiI
 iIIiI1I = ( ooO0 in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( iIIiI1I == False ) :
  Ooooo0OOoo00 = "{} ({})" . format ( ooO0 , igmp_types [ ooO0 ] ) if igmp_types . has_key ( ooO0 ) else ooO0
  if 71 - 71: I1Ii111
  lprint ( "IGMP type {} not supported" . format ( Ooooo0OOoo00 ) )
  return ( [ ] )
  if 4 - 4: ooOoO0o * OoOoOO00 * o0oOOo0O0Ooo - iII111i - o0oOOo0O0Ooo * OOooOOo
  if 91 - 91: OoOoOO00 * II111iiii % I1ii11iIi11i
 if ( len ( oO0ooOo ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 89 - 89: OOooOOo - Oo0Ooo . I1ii11iIi11i - I1IiiI
  if 1 - 1: iIii1I11I1II1
  if 100 - 100: Oo0Ooo % OoooooooOO
  if 28 - 28: oO0o . o0oOOo0O0Ooo
  if 14 - 14: Oo0Ooo - I1Ii111 + Oo0Ooo / iII111i
 if ( ooO0 == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( iiIiII11i1 , False ) ) )
  return ( [ [ None , iiIiII11i1 , False ] ] )
  if 61 - 61: Ii1I * Ii1I . OoOoOO00 + OoO0O00 * i11iIiiIii * OoO0O00
 if ( ooO0 in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( ooO0 == 0x12 ) else 2 , bold ( iiIiII11i1 , False ) ) )
  if 4 - 4: OoooooooOO % iII111i % Oo0Ooo * IiII % o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 66 - 66: I1IiiI . Oo0Ooo - oO0o
  if 53 - 53: oO0o / Ii1I + oO0o + II111iiii
  if 70 - 70: OoooooooOO - I1Ii111 + OoOoOO00
  if 61 - 61: I1IiiI * I1Ii111 * i11iIiiIii
  if ( iiIiII11i1 . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
  else :
   return ( [ [ None , iiIiII11i1 , True ] ] )
   if 68 - 68: OoOoOO00 - iII111i - I1IiiI
   if 37 - 37: iII111i - I1Ii111 + i1IIi / o0oOOo0O0Ooo % iII111i / iII111i
   if 8 - 8: i1IIi % I11i
   if 12 - 12: ooOoO0o / II111iiii + ooOoO0o * I1ii11iIi11i / i1IIi - iIii1I11I1II1
   if 71 - 71: IiII - i11iIiiIii
  return ( [ ] )
  if 3 - 3: i11iIiiIii - o0oOOo0O0Ooo / oO0o . OoO0O00 * I11i + o0oOOo0O0Ooo
  if 18 - 18: OoooooooOO % oO0o / IiII - ooOoO0o
  if 80 - 80: I11i
  if 98 - 98: iII111i / I1ii11iIi11i
  if 87 - 87: iII111i - O0 * ooOoO0o / II111iiii % OoooooooOO . o0oOOo0O0Ooo
 oOo0o0ooO0OOO = oOoooOOO0o0 . address
 oO0ooOo = oO0ooOo [ 8 : : ]
 if 55 - 55: OOooOOo - o0oOOo0O0Ooo * I1IiiI / o0oOOo0O0Ooo + I1Ii111 + iIii1I11I1II1
 Iii111i1iI1 = "BBHI"
 OoOOOoo = struct . calcsize ( Iii111i1iI1 )
 IiIi111i = "I"
 iiIiIiIi1 = struct . calcsize ( IiIi111i )
 O0O00Oo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 33 - 33: I1ii11iIi11i . OOooOOo + i1IIi - OoooooooOO * II111iiii
 if 80 - 80: I11i % Oo0Ooo % I1Ii111 / OoO0O00 + II111iiii
 if 40 - 40: Ii1I + O0 . i11iIiiIii % I11i / Oo0Ooo
 if 25 - 25: IiII * IiII
 o0ooO0OOOoO0o = [ ]
 for i1i1IIIIIIIi in range ( oOo0o0ooO0OOO ) :
  if ( len ( oO0ooOo ) < OoOOOoo ) : return
  oooO000oO00 , OoOO0OOOO0 , oOoO0Oo0Oo , III1 = struct . unpack ( Iii111i1iI1 ,
 oO0ooOo [ : OoOOOoo ] )
  if 11 - 11: o0oOOo0O0Ooo / i1IIi / I11i * O0 + iII111i
  oO0ooOo = oO0ooOo [ OoOOOoo : : ]
  if 20 - 20: Ii1I * I1ii11iIi11i - I1Ii111 + I1IiiI - ooOoO0o
  if ( lisp_igmp_record_types . has_key ( oooO000oO00 ) == False ) :
   lprint ( "Invalid record type {}" . format ( oooO000oO00 ) )
   continue
   if 63 - 63: Ii1I + o0oOOo0O0Ooo - iII111i
   if 1 - 1: O0 . I1IiiI . OoooooooOO . I1ii11iIi11i + I11i - i11iIiiIii
  i1II1IIi = lisp_igmp_record_types [ oooO000oO00 ]
  oOoO0Oo0Oo = socket . ntohs ( oOoO0Oo0Oo )
  oOoooOOO0o0 . address = socket . ntohl ( III1 )
  iiIiII11i1 = oOoooOOO0o0 . print_address_no_iid ( )
  if 100 - 100: II111iiii + oO0o
  lprint ( "Record type: {}, group: {}, source-count: {}" . format ( i1II1IIi , iiIiII11i1 , oOoO0Oo0Oo ) )
  if 85 - 85: I1ii11iIi11i % I1ii11iIi11i . Ii1I
  if 42 - 42: oO0o + OoO0O00
  if 16 - 16: Ii1I
  if 67 - 67: I1ii11iIi11i . OoooooooOO * I1Ii111 + Ii1I * OOooOOo
  if 84 - 84: OOooOOo
  if 78 - 78: O0 % O0
  if 72 - 72: o0oOOo0O0Ooo * IiII / II111iiii / iIii1I11I1II1
  i11iI = False
  if ( oooO000oO00 in ( 1 , 5 ) ) : i11iI = True
  if ( oooO000oO00 in ( 2 , 4 ) and oOoO0Oo0Oo == 0 ) : i11iI = True
  o00i1I1 = "join" if ( i11iI ) else "leave"
  if 45 - 45: ooOoO0o
  if 52 - 52: I1ii11iIi11i % Ii1I - iIii1I11I1II1 . ooOoO0o % I1IiiI
  if 57 - 57: OoO0O00 % Ii1I
  if 11 - 11: OoO0O00
  if ( iiIiII11i1 . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   continue
   if 74 - 74: OoO0O00 - OOooOOo - ooOoO0o - iIii1I11I1II1
   if 29 - 29: ooOoO0o
   if 31 - 31: o0oOOo0O0Ooo / IiII - oO0o / OoOoOO00 * IiII * i1IIi
   if 45 - 45: OoOoOO00 + iII111i % iIii1I11I1II1 - IiII * OOooOOo
   if 62 - 62: Ii1I / Oo0Ooo / I1ii11iIi11i . OoOoOO00 % ooOoO0o * IiII
   if 97 - 97: ooOoO0o
   if 14 - 14: iII111i + iII111i
   if 62 - 62: ooOoO0o / OOooOOo * I1ii11iIi11i + Oo0Ooo - OoooooooOO - OoooooooOO
  if ( oOoO0Oo0Oo == 0 ) :
   o0ooO0OOOoO0o . append ( [ None , iiIiII11i1 , i11iI ] )
   lprint ( "IGMPv3 {} (*, {})" . format ( bold ( o00i1I1 , False ) ,
 bold ( iiIiII11i1 , False ) ) )
   if 19 - 19: Ii1I . oO0o
   if 26 - 26: OOooOOo + II111iiii
   if 67 - 67: IiII + OoOoOO00 * I1ii11iIi11i % o0oOOo0O0Ooo / oO0o
   if 31 - 31: ooOoO0o / Ii1I . Ii1I - I1IiiI - Oo0Ooo . II111iiii
   if 82 - 82: Oo0Ooo % Oo0Ooo
  for Oo0iIIiiIiiI in range ( oOoO0Oo0Oo ) :
   if ( len ( oO0ooOo ) < iiIiIiIi1 ) : return
   III1 = struct . unpack ( IiIi111i , oO0ooOo [ : iiIiIiIi1 ] ) [ 0 ]
   O0O00Oo . address = socket . ntohl ( III1 )
   I1iI1I1i1II = O0O00Oo . print_address_no_iid ( )
   o0ooO0OOOoO0o . append ( [ I1iI1I1i1II , iiIiII11i1 , i11iI ] )
   lprint ( "{} ({}, {})" . format ( o00i1I1 ,
 green ( I1iI1I1i1II , False ) , bold ( iiIiII11i1 , False ) ) )
   oO0ooOo = oO0ooOo [ iiIiIiIi1 : : ]
   if 99 - 99: Oo0Ooo - ooOoO0o . OoO0O00 - Oo0Ooo / O0
   if 42 - 42: Ii1I - OoOoOO00 . OoOoOO00
   if 88 - 88: o0oOOo0O0Ooo . Ii1I . iII111i * iII111i + i11iIiiIii
   if 68 - 68: OoooooooOO
   if 5 - 5: OoOoOO00 . i11iIiiIii . OOooOOo / I11i * Oo0Ooo % Oo0Ooo
   if 44 - 44: I1ii11iIi11i + oO0o % i1IIi + OoooooooOO
   if 42 - 42: I1Ii111 / I1Ii111 - O0
   if 79 - 79: i11iIiiIii
 return ( o0ooO0OOOoO0o )
 if 96 - 96: iIii1I11I1II1 . OoOoOO00 . OOooOOo / iII111i
 if 59 - 59: Oo0Ooo + OOooOOo / Oo0Ooo
 if 49 - 49: OoO0O00 / Oo0Ooo % OoOoOO00 % i1IIi
 if 66 - 66: OoOoOO00 % II111iiii
 if 16 - 16: i11iIiiIii - I1IiiI + ooOoO0o * oO0o
 if 30 - 30: II111iiii / o0oOOo0O0Ooo
 if 57 - 57: I11i / I1ii11iIi11i . I11i
 if 68 - 68: OoOoOO00 + O0 . I1IiiI
lisp_geid = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
if 26 - 26: I1ii11iIi11i
def lisp_glean_map_cache ( seid , rloc , encap_port , igmp ) :
 if 98 - 98: Oo0Ooo
 if 72 - 72: oO0o + OoooooooOO . O0 + IiII
 if 49 - 49: i1IIi - i11iIiiIii + II111iiii + Ii1I / OoO0O00
 if 34 - 34: I1ii11iIi11i * i11iIiiIii
 if 6 - 6: I1ii11iIi11i + I1IiiI / OoooooooOO % I11i * Oo0Ooo
 if 20 - 20: Oo0Ooo
 o00OO00ooOOO = True
 OoOoooooO00oo = lisp_map_cache . lookup_cache ( seid , True )
 if ( OoOoooooO00oo and len ( OoOoooooO00oo . rloc_set ) != 0 ) :
  OoOoooooO00oo . last_refresh_time = lisp_get_timestamp ( )
  if 24 - 24: ooOoO0o / I1Ii111
  O0o0o0o00OoOo = OoOoooooO00oo . rloc_set [ 0 ]
  I11O0 = O0o0o0o00OoOo . rloc
  II1Ii1II = O0o0o0o00OoOo . translated_port
  o00OO00ooOOO = ( I11O0 . is_exact_match ( rloc ) == False or
 II1Ii1II != encap_port )
  if 8 - 8: o0oOOo0O0Ooo / IiII + iIii1I11I1II1 % i1IIi * OoOoOO00 / i11iIiiIii
  if ( o00OO00ooOOO ) :
   o0OoO00 = green ( seid . print_address ( ) , False )
   O0OooO0oo = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
   lprint ( "Change gleaned EID {} to RLOC {}" . format ( o0OoO00 , O0OooO0oo ) )
   O0o0o0o00OoOo . delete_from_rloc_probe_list ( OoOoooooO00oo . eid , OoOoooooO00oo . group )
   lisp_change_gleaned_multicast ( seid , rloc , encap_port )
   if 11 - 11: OoooooooOO * i11iIiiIii
 else :
  OoOoooooO00oo = lisp_mapping ( "" , "" , [ ] )
  OoOoooooO00oo . eid . copy_address ( seid )
  OoOoooooO00oo . mapping_source . copy_address ( rloc )
  OoOoooooO00oo . map_cache_ttl = LISP_GLEAN_TTL
  OoOoooooO00oo . gleaned = True
  o0OoO00 = green ( seid . print_address ( ) , False )
  O0OooO0oo = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( o0OoO00 , O0OooO0oo ) )
  OoOoooooO00oo . add_cache ( )
  if 31 - 31: o0oOOo0O0Ooo / iIii1I11I1II1
  if 79 - 79: O0
  if 50 - 50: IiII % OoOoOO00 . OoOoOO00 + ooOoO0o * OoOoOO00 * OoooooooOO
  if 22 - 22: OoOoOO00 + I1ii11iIi11i * iIii1I11I1II1 + iIii1I11I1II1
  if 100 - 100: iII111i - ooOoO0o + I11i - oO0o * i1IIi
 if ( o00OO00ooOOO ) :
  IiIIIi = lisp_rloc ( )
  IiIIIi . store_translated_rloc ( rloc , encap_port )
  IiIIIi . add_to_rloc_probe_list ( OoOoooooO00oo . eid , OoOoooooO00oo . group )
  IiIIIi . priority = 253
  IiIIIi . mpriority = 255
  iio0OOoO0 = [ IiIIIi ]
  OoOoooooO00oo . rloc_set = iio0OOoO0
  OoOoooooO00oo . build_best_rloc_set ( )
  if 62 - 62: OoO0O00 / OoOoOO00 * OoOoOO00
  if 83 - 83: oO0o * o0oOOo0O0Ooo
  if 25 - 25: o0oOOo0O0Ooo % Oo0Ooo . Oo0Ooo + OoO0O00
  if 23 - 23: I11i + I1ii11iIi11i * iIii1I11I1II1 - i1IIi
  if 33 - 33: I1IiiI + o0oOOo0O0Ooo . OoOoOO00
 if ( igmp == None ) : return
 if 35 - 35: iII111i / Ii1I
 if 57 - 57: ooOoO0o . I1IiiI * OOooOOo
 if 87 - 87: I11i - I11i % iII111i - Ii1I
 if 29 - 29: oO0o - ooOoO0o * iIii1I11I1II1 / OoOoOO00
 if 34 - 34: I1IiiI . Oo0Ooo
 lisp_geid . instance_id = seid . instance_id
 if 4 - 4: Ii1I - II111iiii * iII111i / oO0o - I1IiiI
 if 32 - 32: iIii1I11I1II1 - I11i
 if 49 - 49: I11i * I1Ii111 - iIii1I11I1II1 * O0
 if 72 - 72: I1IiiI * iII111i
 if 61 - 61: Ii1I * Oo0Ooo * I1Ii111 % I11i + iII111i % oO0o
 iiIi1 = lisp_process_igmp_packet ( igmp )
 if ( type ( iiIi1 ) == bool ) : return
 if 67 - 67: IiII
 for O0O00Oo , oOoooOOO0o0 , i11iI in iiIi1 :
  if ( O0O00Oo != None ) : continue
  if 90 - 90: o0oOOo0O0Ooo
  if 5 - 5: i1IIi
  if 55 - 55: Ii1I
  if 46 - 46: OOooOOo / iII111i . i1IIi . i11iIiiIii . iIii1I11I1II1 % I11i
  lisp_geid . store_address ( oOoooOOO0o0 )
  oooO0O0OOOoo , OoOO0OOOO0 , oOoOoO0Oo0oo = lisp_allow_gleaning ( seid , lisp_geid , rloc )
  if ( oooO0O0OOOoo == False ) : continue
  if 62 - 62: I11i % II111iiii % OoooooooOO * ooOoO0o / oO0o
  if ( i11iI ) :
   lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port ,
 True )
  else :
   lisp_remove_gleaned_multicast ( seid , lisp_geid )
   if 29 - 29: o0oOOo0O0Ooo / O0 / OoO0O00
   if 23 - 23: Ii1I + i11iIiiIii % IiII
   if 64 - 64: i11iIiiIii + OoooooooOO . oO0o * Ii1I
   if 49 - 49: O0
   if 72 - 72: I1Ii111
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
