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
LISP_MCAST_TTL = 15
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
 Oo0OO0000oooo = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 Oo0OO0000oooo = Oo0OO0000oooo [ : - 3 ]
 print "{}: {}:" . format ( Oo0OO0000oooo , lisp_log_id ) ,
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
 Oo0OO0000oooo = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 Oo0OO0000oooo = Oo0OO0000oooo [ : - 3 ]
 if 6 - 6: ooOoO0o / I1ii11iIi11i
 print red ( ">>>" , False ) ,
 print "{}:" . format ( Oo0OO0000oooo ) ,
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
 i1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 iii1IiiiI1i1 = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 IIIiI1i1 = None
 if 13 - 13: OOooOOo * I11i / O0 * o0oOOo0O0Ooo
 for OoO0o0OOOO in netifaces . interfaces ( ) :
  if ( O0O0 != None and O0O0 != OoO0o0OOOO ) : continue
  IIiiI = netifaces . ifaddresses ( OoO0o0OOOO )
  if ( IIiiI == { } ) : continue
  if 35 - 35: i1IIi * i11iIiiIii % I1ii11iIi11i / IiII / IiII
  if 91 - 91: OoO0O00 * I1Ii111 % OoO0O00 . o0oOOo0O0Ooo * I1ii11iIi11i . OOooOOo
  if 13 - 13: I1ii11iIi11i
  if 80 - 80: Oo0Ooo % IiII % OoooooooOO * Oo0Ooo % Ii1I
  IIIiI1i1 = lisp_get_interface_instance_id ( OoO0o0OOOO , None )
  if 41 - 41: OoooooooOO / i1IIi
  if 70 - 70: OoOoOO00 % o0oOOo0O0Ooo % i1IIi / I1ii11iIi11i % i11iIiiIii / i1IIi
  if 4 - 4: IiII
  if 93 - 93: oO0o % i1IIi
  if ( IIiiI . has_key ( netifaces . AF_INET ) ) :
   IIi1 = IIiiI [ netifaces . AF_INET ]
   OO = 0
   for IiiIIi1 in IIi1 :
    i1 . store_address ( IiiIIi1 [ "addr" ] )
    if ( i1 . is_ipv4_loopback ( ) ) : continue
    if ( i1 . is_ipv4_link_local ( ) ) : continue
    if ( i1 . address == 0 ) : continue
    OO += 1
    i1 . instance_id = IIIiI1i1
    if ( O0O0 == None and
 lisp_db_for_lookups . lookup_cache ( i1 , False ) ) : continue
    ooOOo [ 0 ] = i1
    if ( OO == ooo ) : break
    if 61 - 61: I11i . I11i - OoO0O00
    if 62 - 62: iII111i . iII111i
  if ( IIiiI . has_key ( netifaces . AF_INET6 ) ) :
   OoO0oO = IIiiI [ netifaces . AF_INET6 ]
   OO = 0
   for IiiIIi1 in OoO0oO :
    oo0o00OO = IiiIIi1 [ "addr" ]
    iii1IiiiI1i1 . store_address ( oo0o00OO )
    if ( iii1IiiiI1i1 . is_ipv6_string_link_local ( oo0o00OO ) ) : continue
    if ( iii1IiiiI1i1 . is_ipv6_loopback ( ) ) : continue
    OO += 1
    iii1IiiiI1i1 . instance_id = IIIiI1i1
    if ( O0O0 == None and
 lisp_db_for_lookups . lookup_cache ( iii1IiiiI1i1 , False ) ) : continue
    ooOOo [ 1 ] = iii1IiiiI1i1
    if ( OO == ooo ) : break
    if 22 - 22: ooOoO0o / ooOoO0o - Ii1I % I11i . OOooOOo + IiII
    if 64 - 64: i1IIi % I1ii11iIi11i / Ii1I % OoooooooOO
    if 24 - 24: I1Ii111 + OoooooooOO . IiII / OoOoOO00 / I11i
    if 65 - 65: OoooooooOO
    if 18 - 18: O0 - i1IIi . I1Ii111
    if 98 - 98: o0oOOo0O0Ooo
  if ( ooOOo [ 0 ] == None ) : continue
  if 73 - 73: Oo0Ooo - iII111i . oO0o % i1IIi . O0
  ooOOo [ 2 ] = OoO0o0OOOO
  break
  if 15 - 15: ooOoO0o . iIii1I11I1II1 * I1IiiI % I11i
  if 21 - 21: OoO0O00 - I1IiiI . OoooooooOO
 Ii1iiI1i1 = ooOOo [ 0 ] . print_address_no_iid ( ) if ooOOo [ 0 ] else "none"
 iIi = ooOOo [ 1 ] . print_address_no_iid ( ) if ooOOo [ 1 ] else "none"
 OoO0o0OOOO = ooOOo [ 2 ] if ooOOo [ 2 ] else "none"
 if 88 - 88: iII111i * OoooooooOO . iIii1I11I1II1
 O0O0 = " (user selected)" if O0O0 != None else ""
 if 11 - 11: oO0o + I1Ii111 . IiII * OoooooooOO - I1ii11iIi11i - OOooOOo
 Ii1iiI1i1 = red ( Ii1iiI1i1 , False )
 iIi = red ( iIi , False )
 OoO0o0OOOO = bold ( OoO0o0OOOO , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( Ii1iiI1i1 , iIi , OoO0o0OOOO , O0O0 , IIIiI1i1 ) )
 if 16 - 16: iII111i / iIii1I11I1II1 + OOooOOo * iII111i * I11i
 if 8 - 8: I1Ii111
 lisp_myrlocs = ooOOo
 return ( ( ooOOo [ 0 ] != None ) )
 if 15 - 15: Oo0Ooo / Ii1I % O0 + I1ii11iIi11i
 if 96 - 96: ooOoO0o . OoooooooOO
 if 39 - 39: OOooOOo + OoO0O00
 if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
 if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
 if 71 - 71: ooOoO0o . i11iIiiIii
 if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
 if 25 - 25: iIii1I11I1II1 . I11i * i11iIiiIii + Oo0Ooo * I11i
 if 67 - 67: iII111i
def lisp_get_all_addresses ( ) :
 oooO0o = [ ]
 for II1i in netifaces . interfaces ( ) :
  try : I1iII11ii1 = netifaces . ifaddresses ( II1i )
  except : continue
  if 4 - 4: i11iIiiIii - OOooOOo % I1ii11iIi11i * I1Ii111 % o0oOOo0O0Ooo
  if ( I1iII11ii1 . has_key ( netifaces . AF_INET ) ) :
   for IiiIIi1 in I1iII11ii1 [ netifaces . AF_INET ] :
    OO0o = IiiIIi1 [ "addr" ]
    if ( OO0o . find ( "127.0.0.1" ) != - 1 ) : continue
    oooO0o . append ( OO0o )
    if 71 - 71: ooOoO0o . ooOoO0o - iIii1I11I1II1
    if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
  if ( I1iII11ii1 . has_key ( netifaces . AF_INET6 ) ) :
   for IiiIIi1 in I1iII11ii1 [ netifaces . AF_INET6 ] :
    OO0o = IiiIIi1 [ "addr" ]
    if ( OO0o == "::1" ) : continue
    if ( OO0o [ 0 : 5 ] == "fe80:" ) : continue
    oooO0o . append ( OO0o )
    if 32 - 32: OoooooooOO % oO0o % iIii1I11I1II1 / O0
    if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
    if 98 - 98: Ii1I - I1IiiI . i11iIiiIii * Oo0Ooo
 return ( oooO0o )
 if 29 - 29: Ii1I / ooOoO0o % I11i
 if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
 if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
 if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
 if 79 - 79: IiII + IiII + Ii1I
 if 39 - 39: O0 - OoooooooOO
 if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
 if 79 - 79: O0
def lisp_get_all_multicast_rles ( ) :
 IiI = [ ]
 II1IIiiI1 = commands . getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( II1IIiiI1 == "" ) : return ( IiI )
 if 9 - 9: II111iiii % OoOoOO00
 IiiIi1I11 = II1IIiiI1 . split ( "\n" )
 for oOOo0ooO0 in IiiIi1I11 :
  if ( oOOo0ooO0 [ 0 ] == "#" ) : continue
  i1I1Ii11II1i = oOOo0ooO0 . split ( "rle-address = " ) [ 1 ]
  oooOoOOoOO0O = int ( i1I1Ii11II1i . split ( "." ) [ 0 ] )
  if ( oooOoOOoOO0O >= 224 and oooOoOOoOO0O < 240 ) : IiI . append ( i1I1Ii11II1i )
  if 9 - 9: I1Ii111 * OoooooooOO % I1IiiI / OoOoOO00 * I11i
 return ( IiI )
 if 48 - 48: OoooooooOO . OoOoOO00
 if 65 - 65: oO0o . Oo0Ooo
 if 94 - 94: OoOoOO00 + IiII . ooOoO0o
 if 69 - 69: O0 - O0
 if 41 - 41: IiII % o0oOOo0O0Ooo
 if 67 - 67: O0 % I1Ii111
 if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
 if 39 - 39: Ii1I
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
  if 60 - 60: OOooOOo
  if 62 - 62: I1Ii111 * I11i
 def encode ( self , nonce ) :
  if 74 - 74: OoOoOO00 . iIii1I11I1II1
  if 87 - 87: ooOoO0o
  if 41 - 41: OoOoOO00 . iIii1I11I1II1 % ooOoO0o + O0
  if 22 - 22: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o + I1ii11iIi11i * iII111i . i11iIiiIii
  if 90 - 90: OOooOOo * OoOoOO00 - Oo0Ooo + o0oOOo0O0Ooo
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
  if 44 - 44: I1Ii111 - IiII
  if 100 - 100: oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
  if 59 - 59: II111iiii
  if 43 - 43: Oo0Ooo + OoooooooOO
  if 47 - 47: ooOoO0o
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 23 - 23: II111iiii * iII111i
  if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
  if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
  if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
  if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
  if 21 - 21: OoO0O00
  self . lisp_header . key_id ( 0 )
  O0o0oOOO = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and O0o0oOOO == False ) :
   oo0o00OO = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 24 - 24: o0oOOo0O0Ooo / Ii1I / Ii1I % II111iiii - oO0o * oO0o
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( oo0o00OO ) ) :
    oOoo0oO = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ]
    if ( oOoo0oO [ 1 ] ) :
     oOoo0oO [ 1 ] . use_count += 1
     IIii1i , o00oo = self . encrypt ( oOoo0oO [ 1 ] , oo0o00OO )
     if ( o00oo ) : self . packet = IIii1i
     if 18 - 18: i11iIiiIii - ooOoO0o * oO0o + o0oOOo0O0Ooo
     if 16 - 16: OoooooooOO * i11iIiiIii . OoooooooOO - iIii1I11I1II1 * i1IIi
     if 33 - 33: I1Ii111 % II111iiii
     if 49 - 49: I1ii11iIi11i + I11i / o0oOOo0O0Ooo + OoooooooOO + OOooOOo / IiII
     if 29 - 29: Ii1I - Ii1I / ooOoO0o
     if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
     if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
     if 18 - 18: Oo0Ooo % O0
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    if ( self . gleaned_dest ) :
     self . udp_sport = LISP_DATA_PORT
    else :
     self . hash_packet ( )
     if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
  else :
   self . udp_sport = LISP_DATA_PORT
   if 86 - 86: IiII
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
  if 33 - 33: II111iiii - IiII - ooOoO0o
  if 92 - 92: OoO0O00 * IiII
  if 92 - 92: oO0o
  if ( self . outer_version == 4 ) :
   i1i1IIiII1I = socket . htons ( self . udp_sport )
   OOO = socket . htons ( self . udp_dport )
  else :
   i1i1IIiII1I = self . udp_sport
   OOO = self . udp_dport
   if 3 - 3: i11iIiiIii
   if 11 - 11: OoO0O00 % OoooooooOO
  OOO = socket . htons ( self . udp_dport ) if self . outer_version == 4 else self . udp_dport
  if 20 - 20: I1Ii111 + I1Ii111 * II111iiii * iIii1I11I1II1 % O0 * I1IiiI
  if 62 - 62: OoooooooOO / OoOoOO00 . IiII . IiII % ooOoO0o
  o0oOo00 = struct . pack ( "HHHH" , i1i1IIiII1I , OOO , socket . htons ( self . udp_length ) ,
 self . udp_checksum )
  if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
  if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
  if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
  if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
  O0oooo0O = self . lisp_header . encode ( )
  if 15 - 15: i1IIi % OoooooooOO * OOooOOo . II111iiii + O0 * OoO0O00
  if 16 - 16: O0 - O0 / I11i - OoO0O00
  if 30 - 30: o0oOOo0O0Ooo - OoO0O00 + OOooOOo
  if 65 - 65: O0 / II111iiii . iIii1I11I1II1 . oO0o / Oo0Ooo % iIii1I11I1II1
  if 74 - 74: i1IIi / I1IiiI % I1ii11iIi11i / O0 % I11i - OoOoOO00
  if ( self . outer_version == 4 ) :
   Iiii = socket . htons ( self . udp_length + 20 )
   oO = socket . htons ( 0x4000 )
   ii11I = struct . pack ( "BBHHHBBH" , 0x45 , self . outer_tos , Iiii , 0xdfdf ,
 oO , self . outer_ttl , 17 , 0 )
   ii11I += self . outer_source . pack_address ( )
   ii11I += self . outer_dest . pack_address ( )
   ii11I = lisp_ip_checksum ( ii11I )
  elif ( self . outer_version == 6 ) :
   ii11I = ""
   if 97 - 97: i1IIi + iII111i . ooOoO0o - iII111i
   if 53 - 53: O0 . I1IiiI
   if 74 - 74: ooOoO0o % OoOoOO00 / Oo0Ooo
   if 2 - 2: IiII % IiII % I1Ii111
   if 60 - 60: OOooOOo
   if 73 - 73: ooOoO0o
   if 86 - 86: OoOoOO00 . I11i / Oo0Ooo * I11i
  else :
   return ( None )
   if 20 - 20: ooOoO0o - OOooOOo * OoO0O00 * o0oOOo0O0Ooo * OOooOOo / IiII
   if 40 - 40: I1IiiI * o0oOOo0O0Ooo . I1IiiI
  self . packet = ii11I + o0oOo00 + O0oooo0O + self . packet
  return ( self )
  if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
  if 50 - 50: OoooooooOO + oO0o * I1IiiI - Ii1I / i11iIiiIii
 def cipher_pad ( self , packet ) :
  iiiIIiiIi = len ( packet )
  if ( ( iiiIIiiIi % 16 ) != 0 ) :
   Oooo0oOooOO = ( ( iiiIIiiIi / 16 ) + 1 ) * 16
   packet = packet . ljust ( Oooo0oOooOO )
   if 82 - 82: ooOoO0o + II111iiii . I1IiiI / I1ii11iIi11i
  return ( packet )
  if 68 - 68: OOooOOo - OoooooooOO
  if 14 - 14: O0 / oO0o - Oo0Ooo - IiII
 def encrypt ( self , key , addr_str ) :
  if ( key == None or key . shared_key == None ) :
   return ( [ self . packet , False ] )
   if 44 - 44: OoO0O00
   if 32 - 32: OoOoOO00 % OoO0O00 + i11iIiiIii + ooOoO0o - Ii1I + oO0o
   if 31 - 31: iIii1I11I1II1 - o0oOOo0O0Ooo
   if 57 - 57: Oo0Ooo % OoO0O00
   if 1 - 1: OoOoOO00 * O0 . oO0o % O0 + II111iiii
  IIii1i = self . cipher_pad ( self . packet )
  i1Oo = key . get_iv ( )
  if 15 - 15: i1IIi + IiII % I1IiiI / i11iIiiIii * OoOoOO00
  Oo0OO0000oooo = lisp_get_timestamp ( )
  oOiI1I = None
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   i111I1 = chacha . ChaCha ( key . encrypt_key , i1Oo ) . encrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   OOOo0Oo0O = binascii . unhexlify ( key . encrypt_key )
   try :
    i1I1I1iIIi = AES . new ( OOOo0Oo0O , AES . MODE_GCM , i1Oo )
    i111I1 = i1I1I1iIIi . encrypt
    oOiI1I = i1I1I1iIIi . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 46 - 46: I1IiiI . IiII - i11iIiiIii - I1Ii111
  else :
   OOOo0Oo0O = binascii . unhexlify ( key . encrypt_key )
   i111I1 = AES . new ( OOOo0Oo0O , AES . MODE_CBC , i1Oo ) . encrypt
   if 97 - 97: II111iiii % Oo0Ooo * IiII
   if 51 - 51: Oo0Ooo % OOooOOo . Oo0Ooo
  o0o0oO0OOO = i111I1 ( IIii1i )
  if 66 - 66: Ii1I * iIii1I11I1II1 - ooOoO0o / I1IiiI
  if ( o0o0oO0OOO == None ) : return ( [ self . packet , False ] )
  Oo0OO0000oooo = int ( str ( time . time ( ) - Oo0OO0000oooo ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 62 - 62: IiII . O0 . iIii1I11I1II1
  if 94 - 94: ooOoO0o % I11i % i1IIi
  if 90 - 90: Ii1I * OoO0O00
  if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
  if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
  if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
  if ( oOiI1I != None ) : o0o0oO0OOO += oOiI1I ( )
  if 55 - 55: OoooooooOO
  if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
  if 38 - 38: O0
  if 79 - 79: i1IIi . oO0o
  if 34 - 34: I1Ii111 * II111iiii
  self . lisp_header . key_id ( key . key_id )
  O0oooo0O = self . lisp_header . encode ( )
  if 71 - 71: IiII
  o00OOo0o = key . do_icv ( O0oooo0O + i1Oo + o0o0oO0OOO , i1Oo )
  if 48 - 48: i11iIiiIii / II111iiii + Ii1I + o0oOOo0O0Ooo . I1Ii111 % OOooOOo
  o0 = 4 if ( key . do_poly ) else 8
  if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
  iI = bold ( "Encrypt" , False )
  o00ooO000Oo00 = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  iI1 = "poly" if key . do_poly else "sha256"
  iI1 = bold ( iI1 , False )
  oOoo = "ICV({}): 0x{}...{}" . format ( iI1 , o00OOo0o [ 0 : o0 ] , o00OOo0o [ - o0 : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( iI , key . key_id , addr_str , oOoo , o00ooO000Oo00 , Oo0OO0000oooo ) )
  if 59 - 59: IiII % Ii1I
  if 57 - 57: I11i . O0 % OoooooooOO . I1IiiI . i1IIi - II111iiii
  o00OOo0o = int ( o00OOo0o , 16 )
  if ( key . do_poly ) :
   ooooO0o000oOO = byte_swap_64 ( ( o00OOo0o >> 64 ) & LISP_8_64_MASK )
   Ii11Iiii = byte_swap_64 ( o00OOo0o & LISP_8_64_MASK )
   o00OOo0o = struct . pack ( "QQ" , ooooO0o000oOO , Ii11Iiii )
  else :
   ooooO0o000oOO = byte_swap_64 ( ( o00OOo0o >> 96 ) & LISP_8_64_MASK )
   Ii11Iiii = byte_swap_64 ( ( o00OOo0o >> 32 ) & LISP_8_64_MASK )
   ooO0o00OOo = socket . htonl ( o00OOo0o & 0xffffffff )
   o00OOo0o = struct . pack ( "QQI" , ooooO0o000oOO , Ii11Iiii , ooO0o00OOo )
   if 50 - 50: II111iiii
   if 39 - 39: II111iiii . OoOoOO00 - Oo0Ooo * i1IIi . OoooooooOO
  return ( [ i1Oo + o0o0oO0OOO + o00OOo0o , True ] )
  if 44 - 44: I1IiiI
  if 55 - 55: oO0o . I1Ii111 * I1Ii111
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 82 - 82: I1IiiI % OoO0O00 % I11i + I11i
  if 6 - 6: Oo0Ooo
  if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
  if 93 - 93: i11iIiiIii
  if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
  if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
  if ( key . do_poly ) :
   ooooO0o000oOO , Ii11Iiii = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   Ii1i = byte_swap_64 ( ooooO0o000oOO ) << 64
   Ii1i |= byte_swap_64 ( Ii11Iiii )
   Ii1i = lisp_hex_string ( Ii1i ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   o0 = 4
   ooooOoOooo00Oo = bold ( "poly" , False )
  else :
   ooooO0o000oOO , Ii11Iiii , ooO0o00OOo = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   Ii1i = byte_swap_64 ( ooooO0o000oOO ) << 96
   Ii1i |= byte_swap_64 ( Ii11Iiii ) << 32
   Ii1i |= socket . htonl ( ooO0o00OOo )
   Ii1i = lisp_hex_string ( Ii1i ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   o0 = 8
   ooooOoOooo00Oo = bold ( "sha" , False )
   if 72 - 72: I11i
  O0oooo0O = self . lisp_header . encode ( )
  if 26 - 26: IiII % Oo0Ooo
  if 72 - 72: O0 + o0oOOo0O0Ooo + I1IiiI / Oo0Ooo
  if 83 - 83: IiII - I1IiiI . Ii1I
  if 34 - 34: OoOoOO00 - oO0o * OoooooooOO
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   IiI1I1IIIi1i = 8
   o00ooO000Oo00 = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   IiI1I1IIIi1i = 12
   o00ooO000Oo00 = bold ( "aes-gcm" , False )
  else :
   IiI1I1IIIi1i = 16
   o00ooO000Oo00 = bold ( "aes-cbc" , False )
   if 73 - 73: O0 * I1Ii111 . i1IIi
  i1Oo = packet [ 0 : IiI1I1IIIi1i ]
  if 51 - 51: OoO0O00 - iII111i % O0 - OoOoOO00
  if 53 - 53: iII111i / i1IIi / i1IIi
  if 77 - 77: I11i + i1IIi . I11i
  if 89 - 89: o0oOOo0O0Ooo + OOooOOo * oO0o
  i1iI1IIi = key . do_icv ( O0oooo0O + packet , i1Oo )
  if 27 - 27: O0 / OoO0O00
  O000oooO0 = "0x{}...{}" . format ( Ii1i [ 0 : o0 ] , Ii1i [ - o0 : : ] )
  oOO00 = "0x{}...{}" . format ( i1iI1IIi [ 0 : o0 ] , i1iI1IIi [ - o0 : : ] )
  if 91 - 91: I1ii11iIi11i + iIii1I11I1II1 % IiII
  if ( i1iI1IIi != Ii1i ) :
   self . packet_error = "ICV-error"
   O0o0OOOO0 = o00ooO000Oo00 + "/" + ooooOoOooo00Oo
   ii1 = bold ( "ICV failed ({})" . format ( O0o0OOOO0 ) , False )
   oOoo = "packet-ICV {} != computed-ICV {}" . format ( O000oooO0 , oOO00 )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( ii1 , red ( addr_str , False ) ,
   # O0 * I1ii11iIi11i * oO0o + OoO0O00 + I1ii11iIi11i - I1Ii111
 self . udp_sport , key . key_id , oOoo ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 10 - 10: I1ii11iIi11i + IiII
   if 58 - 58: I1IiiI + OoooooooOO / iII111i . ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i
   if 62 - 62: II111iiii
   if 12 - 12: IiII + II111iiii
   if 92 - 92: I1Ii111 % iIii1I11I1II1 - iII111i / i11iIiiIii % ooOoO0o * o0oOOo0O0Ooo
   if 80 - 80: iII111i
   lisp_retry_decap_keys ( addr_str , O0oooo0O + packet , i1Oo , Ii1i )
   return ( [ None , False ] )
   if 3 - 3: I1ii11iIi11i * I11i
   if 53 - 53: iIii1I11I1II1 / iII111i % OoO0O00 + IiII / ooOoO0o
   if 74 - 74: Oo0Ooo
   if 8 - 8: I1IiiI % II111iiii - o0oOOo0O0Ooo - I11i % I1IiiI
   if 93 - 93: Ii1I * iII111i / OOooOOo
  packet = packet [ IiI1I1IIIi1i : : ]
  if 88 - 88: oO0o
  if 1 - 1: Oo0Ooo
  if 95 - 95: OoooooooOO / I11i % OoooooooOO / ooOoO0o * IiII
  if 75 - 75: O0
  Oo0OO0000oooo = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   oOoO = chacha . ChaCha ( key . encrypt_key , i1Oo ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   OOOo0Oo0O = binascii . unhexlify ( key . encrypt_key )
   try :
    oOoO = AES . new ( OOOo0Oo0O , AES . MODE_GCM , i1Oo ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 59 - 59: OOooOOo + I1IiiI / II111iiii / OoOoOO00
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 80 - 80: OoOoOO00 + iIii1I11I1II1 . IiII
   OOOo0Oo0O = binascii . unhexlify ( key . encrypt_key )
   oOoO = AES . new ( OOOo0Oo0O , AES . MODE_CBC , i1Oo ) . decrypt
   if 76 - 76: I1IiiI * OOooOOo
   if 12 - 12: iIii1I11I1II1 / I11i % Ii1I
  IIiiI11 = oOoO ( packet )
  Oo0OO0000oooo = int ( str ( time . time ( ) - Oo0OO0000oooo ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 7 - 7: I1IiiI / OoO0O00 + I1Ii111 + I11i / I1IiiI
  if 82 - 82: I1ii11iIi11i + OoooooooOO
  if 21 - 21: oO0o * oO0o / I11i . iII111i
  if 10 - 10: Ii1I * OOooOOo - Oo0Ooo - OoooooooOO / o0oOOo0O0Ooo
  iI = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  iI1 = "poly" if key . do_poly else "sha256"
  iI1 = bold ( iI1 , False )
  oOoo = "ICV({}): {}" . format ( iI1 , O000oooO0 )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( iI , key . key_id , addr_str , oOoo , o00ooO000Oo00 , Oo0OO0000oooo ) )
  if 86 - 86: I1Ii111 % I1IiiI
  if 22 - 22: i11iIiiIii * I1Ii111 . Oo0Ooo . OoooooooOO + I1IiiI
  if 24 - 24: II111iiii / Ii1I . iIii1I11I1II1 - II111iiii % O0
  if 8 - 8: OoO0O00 % iII111i . OoooooooOO - Ii1I % OoooooooOO
  if 61 - 61: o0oOOo0O0Ooo / i11iIiiIii
  if 28 - 28: OOooOOo / OoOoOO00
  if 30 - 30: ooOoO0o
  self . packet = self . packet [ 0 : header_length ]
  return ( [ IIiiI11 , True ] )
  if 57 - 57: o0oOOo0O0Ooo * i11iIiiIii / OoOoOO00
  if 40 - 40: iIii1I11I1II1 - ooOoO0o / Oo0Ooo
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  iIi11ii1 = 1000
  if 49 - 49: oO0o . OoOoOO00
  if 73 - 73: Ii1I / I1IiiI / OoooooooOO + I1IiiI
  if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
  if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
  if 70 - 70: OoooooooOO % OoooooooOO % OoO0O00
  oo0O0OO = [ ]
  OoO00oo00 = 0
  iiiIIiiIi = len ( inner_packet )
  while ( OoO00oo00 < iiiIIiiIi ) :
   oO = inner_packet [ OoO00oo00 : : ]
   if ( len ( oO ) > iIi11ii1 ) : oO = oO [ 0 : iIi11ii1 ]
   oo0O0OO . append ( oO )
   OoO00oo00 += len ( oO )
   if 30 - 30: I1Ii111 / o0oOOo0O0Ooo % oO0o
   if 38 - 38: o0oOOo0O0Ooo . oO0o / o0oOOo0O0Ooo % II111iiii
   if 47 - 47: I11i * iIii1I11I1II1 * iII111i - OoO0O00 . O0 . ooOoO0o
   if 32 - 32: o0oOOo0O0Ooo % I1IiiI
   if 7 - 7: Oo0Ooo . i1IIi - oO0o
   if 93 - 93: IiII % I1ii11iIi11i
  IiIIii = [ ]
  OoO00oo00 = 0
  for oO in oo0O0OO :
   if 74 - 74: iIii1I11I1II1 / Ii1I
   if 59 - 59: Ii1I / II111iiii - IiII % OoOoOO00 % OoooooooOO
   if 79 - 79: iII111i . OoooooooOO . I1IiiI * O0 * OoO0O00 - OOooOOo
   if 33 - 33: I1ii11iIi11i . Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
   O00000OO00OO = OoO00oo00 if ( oO == oo0O0OO [ - 1 ] ) else 0x2000 + OoO00oo00
   O00000OO00OO = socket . htons ( O00000OO00OO )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , O00000OO00OO ) + outer_hdr [ 8 : : ]
   if 35 - 35: Oo0Ooo
   if 47 - 47: i1IIi % ooOoO0o - Oo0Ooo * I11i / i11iIiiIii
   if 45 - 45: I1IiiI . Oo0Ooo . I1Ii111 / oO0o
   if 4 - 4: i11iIiiIii + OOooOOo
   I1111III111ii = socket . htons ( len ( oO ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , I1111III111ii ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   IiIIii . append ( outer_hdr + oO )
   OoO00oo00 += len ( oO ) / 8
   if 90 - 90: I11i
  return ( IiIIii )
  if 88 - 88: OoO0O00
  if 85 - 85: oO0o
 def send_icmp_too_big ( self , inner_packet ) :
  global lisp_last_icmp_too_big_sent
  global lisp_icmp_raw_socket
  if 7 - 7: o0oOOo0O0Ooo
  oO000o0Oo00 = time . time ( ) - lisp_last_icmp_too_big_sent
  if ( oO000o0Oo00 < LISP_ICMP_TOO_BIG_RATE_LIMIT ) :
   lprint ( "Rate limit sending ICMP Too-Big to {}" . format ( self . inner_source . print_address_no_iid ( ) ) )
   if 99 - 99: i11iIiiIii - iII111i
   return ( False )
   if 85 - 85: I1Ii111 % I1ii11iIi11i
   if 95 - 95: OoO0O00 * OOooOOo * iII111i . o0oOOo0O0Ooo
   if 73 - 73: OoO0O00
   if 28 - 28: OoooooooOO - I11i
   if 84 - 84: II111iiii
   if 36 - 36: OOooOOo - OoOoOO00 - iIii1I11I1II1
   if 10 - 10: I1ii11iIi11i / Ii1I * i1IIi % O0 + I11i
   if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
   if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
   if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
   if 80 - 80: Ii1I
   if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
   if 59 - 59: I1ii11iIi11i + I11i . oO0o
   if 87 - 87: OoO0O00
   if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
  II1iII1 = socket . htons ( 1400 )
  O00ooooo00 = struct . pack ( "BBHHH" , 3 , 4 , 0 , 0 , II1iII1 )
  O00ooooo00 += inner_packet [ 0 : 20 + 8 ]
  O00ooooo00 = lisp_icmp_checksum ( O00ooooo00 )
  if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
  if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
  if 46 - 46: i11iIiiIii
  if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
  if 48 - 48: I1Ii111 % iII111i % Ii1I % iIii1I11I1II1 . Ii1I
  if 14 - 14: iII111i * OoO0O00 % O0 + I11i + I1ii11iIi11i
  if 23 - 23: Oo0Ooo % iII111i + Ii1I - I1Ii111
  ooOO = inner_packet [ 12 : 16 ]
  oO0o0 = self . inner_source . print_address_no_iid ( )
  i1Ii1i11ii = self . outer_source . pack_address ( )
  if 58 - 58: OoOoOO00 + OoO0O00 * Ii1I
  if 31 - 31: oO0o - iII111i
  if 46 - 46: I1IiiI + Oo0Ooo - Ii1I
  if 99 - 99: OOooOOo + I1IiiI . I1ii11iIi11i * OoooooooOO
  if 82 - 82: i11iIiiIii + iIii1I11I1II1 / Oo0Ooo + OOooOOo * II111iiii
  if 34 - 34: o0oOOo0O0Ooo % OoooooooOO
  if 36 - 36: I1IiiI
  if 64 - 64: i11iIiiIii + i1IIi % O0 . I11i
  Iiii = socket . htons ( 20 + 36 )
  Ooo0oO = struct . pack ( "BBHHHBBH" , 0x45 , 0 , Iiii , 0 , 0 , 32 , 1 , 0 ) + i1Ii1i11ii + ooOO
  Ooo0oO = lisp_ip_checksum ( Ooo0oO )
  Ooo0oO = self . fix_outer_header ( Ooo0oO )
  Ooo0oO += O00ooooo00
  o00o0 = bold ( "Too-Big" , False )
  lprint ( "Send ICMP {} to {}, mtu 1400: {}" . format ( o00o0 , oO0o0 ,
 lisp_format_packet ( Ooo0oO ) ) )
  if 84 - 84: OoOoOO00 - Oo0Ooo . ooOoO0o . IiII - Oo0Ooo
  try :
   lisp_icmp_raw_socket . sendto ( Ooo0oO , ( oO0o0 , 0 ) )
  except socket . error , oOo :
   lprint ( "lisp_icmp_raw_socket.sendto() failed: {}" . format ( oOo ) )
   return ( False )
   if 99 - 99: I1Ii111
   if 75 - 75: ooOoO0o . OOooOOo / IiII
   if 84 - 84: OoooooooOO . I1IiiI / o0oOOo0O0Ooo
   if 86 - 86: Oo0Ooo % OoOoOO00
   if 77 - 77: Ii1I % OOooOOo / oO0o
   if 91 - 91: OoO0O00 / OoO0O00 . II111iiii . ooOoO0o - I1IiiI
  lisp_last_icmp_too_big_sent = lisp_get_timestamp ( )
  return ( True )
  if 23 - 23: I1IiiI
 def fragment ( self ) :
  global lisp_icmp_raw_socket
  global lisp_ignore_df_bit
  if 7 - 7: iII111i % I1ii11iIi11i
  IIii1i = self . fix_outer_header ( self . packet )
  if 64 - 64: I1Ii111 + i11iIiiIii
  if 35 - 35: OoOoOO00 + i1IIi % OOooOOo
  if 68 - 68: IiII . ooOoO0o
  if 64 - 64: i1IIi + Oo0Ooo * I1IiiI / OOooOOo
  if 3 - 3: Oo0Ooo / ooOoO0o + ooOoO0o . I1ii11iIi11i
  if 50 - 50: iIii1I11I1II1 * oO0o
  iiiIIiiIi = len ( IIii1i )
  if ( iiiIIiiIi <= 1500 ) : return ( [ IIii1i ] , "Fragment-None" )
  if 85 - 85: i1IIi
  IIii1i = self . packet
  if 100 - 100: OoooooooOO / I11i % OoO0O00 + Ii1I
  if 42 - 42: Oo0Ooo / IiII . Ii1I * I1IiiI
  if 54 - 54: OoOoOO00 * iII111i + OoO0O00
  if 93 - 93: o0oOOo0O0Ooo / I1IiiI
  if 47 - 47: Oo0Ooo * OOooOOo
  if ( self . inner_version != 4 ) :
   oOoO0O00o = random . randint ( 0 , 0xffff )
   IiI11II = IIii1i [ 0 : 4 ] + struct . pack ( "H" , oOoO0O00o ) + IIii1i [ 6 : 20 ]
   OO0 = IIii1i [ 20 : : ]
   IiIIii = self . fragment_outer ( IiI11II , OO0 )
   return ( IiIIii , "Fragment-Outer" )
   if 18 - 18: I1IiiI * IiII / OoOoOO00 / oO0o / Ii1I * ooOoO0o
   if 51 - 51: oO0o
   if 34 - 34: OoOoOO00 . i11iIiiIii * OOooOOo . ooOoO0o * O0 * OoO0O00
   if 27 - 27: Ii1I . o0oOOo0O0Ooo - OoOoOO00 . II111iiii % Oo0Ooo
   if 83 - 83: I11i + oO0o - iIii1I11I1II1 + II111iiii . iII111i
  oOO0 = 56 if ( self . outer_version == 6 ) else 36
  IiI11II = IIii1i [ 0 : oOO0 ]
  oOooooO = IIii1i [ oOO0 : oOO0 + 20 ]
  OO0 = IIii1i [ oOO0 + 20 : : ]
  if 79 - 79: I1ii11iIi11i - iIii1I11I1II1 % i1IIi / Oo0Ooo + II111iiii
  if 95 - 95: oO0o
  if 48 - 48: I11i / iIii1I11I1II1 % II111iiii
  if 39 - 39: i1IIi . I1ii11iIi11i / I11i / I11i
  if 100 - 100: OoooooooOO - OoooooooOO + IiII
  iIiIi1i1Iiii = struct . unpack ( "H" , oOooooO [ 6 : 8 ] ) [ 0 ]
  iIiIi1i1Iiii = socket . ntohs ( iIiIi1i1Iiii )
  if ( iIiIi1i1Iiii & 0x4000 ) :
   if ( lisp_icmp_raw_socket != None ) :
    OOO00000O = IIii1i [ oOO0 : : ]
    if ( self . send_icmp_too_big ( OOO00000O ) ) : return ( [ ] , None )
    if 23 - 23: Oo0Ooo - O0
   if ( lisp_ignore_df_bit ) :
    iIiIi1i1Iiii &= ~ 0x4000
   else :
    iI111iIi = bold ( "DF-bit set" , False )
    dprint ( "{} in inner header, packet discarded" . format ( iI111iIi ) )
    return ( [ ] , "Fragment-None-DF-bit" )
    if 26 - 26: OOooOOo % OOooOOo / i11iIiiIii + I1ii11iIi11i - O0
    if 20 - 20: I1Ii111 . O0 - I1ii11iIi11i / OoOoOO00 - o0oOOo0O0Ooo
    if 79 - 79: OoooooooOO - iIii1I11I1II1
  OoO00oo00 = 0
  iiiIIiiIi = len ( OO0 )
  IiIIii = [ ]
  while ( OoO00oo00 < iiiIIiiIi ) :
   IiIIii . append ( OO0 [ OoO00oo00 : OoO00oo00 + 1400 ] )
   OoO00oo00 += 1400
   if 9 - 9: i1IIi - OoOoOO00
   if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
   if 46 - 46: Ii1I
   if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
   if 87 - 87: I1ii11iIi11i / I1IiiI
  oo0O0OO = IiIIii
  IiIIii = [ ]
  IIi1IiiIi1III = True if iIiIi1i1Iiii & 0x2000 else False
  iIiIi1i1Iiii = ( iIiIi1i1Iiii & 0x1fff ) * 8
  for oO in oo0O0OO :
   if 19 - 19: i1IIi % I1IiiI - iIii1I11I1II1 - oO0o / I1ii11iIi11i
   if 16 - 16: Ii1I
   if 79 - 79: OoooooooOO - ooOoO0o * Ii1I - II111iiii % OoOoOO00 * IiII
   if 31 - 31: I1IiiI
   IIII1I1 = iIiIi1i1Iiii / 8
   if ( IIi1IiiIi1III ) :
    IIII1I1 |= 0x2000
   elif ( oO != oo0O0OO [ - 1 ] ) :
    IIII1I1 |= 0x2000
    if 36 - 36: Ii1I * I11i . I11i / Oo0Ooo / I1IiiI
   IIII1I1 = socket . htons ( IIII1I1 )
   oOooooO = oOooooO [ 0 : 6 ] + struct . pack ( "H" , IIII1I1 ) + oOooooO [ 8 : : ]
   if 80 - 80: OoooooooOO - i1IIi
   if 51 - 51: i1IIi . OoOoOO00 / OoOoOO00 % i11iIiiIii * OOooOOo - I1Ii111
   if 49 - 49: Oo0Ooo - iIii1I11I1II1
   if 64 - 64: I1Ii111 + iIii1I11I1II1
   if 14 - 14: Ii1I / OoooooooOO + II111iiii . O0 / i1IIi
   if 58 - 58: o0oOOo0O0Ooo / i11iIiiIii / O0 % I11i % I1IiiI
   iiiIIiiIi = len ( oO )
   iIiIi1i1Iiii += iiiIIiiIi
   I1111III111ii = socket . htons ( iiiIIiiIi + 20 )
   oOooooO = oOooooO [ 0 : 2 ] + struct . pack ( "H" , I1111III111ii ) + oOooooO [ 4 : 10 ] + struct . pack ( "H" , 0 ) + oOooooO [ 12 : : ]
   if 86 - 86: IiII + OoOoOO00 / I1IiiI + I11i % I11i / i11iIiiIii
   oOooooO = lisp_ip_checksum ( oOooooO )
   iIiI1I = oOooooO + oO
   if 2 - 2: o0oOOo0O0Ooo . Ii1I % OoOoOO00
   if 58 - 58: I1ii11iIi11i % Ii1I * Ii1I - iII111i
   if 9 - 9: ooOoO0o - Ii1I % II111iiii + IiII + OOooOOo % O0
   if 65 - 65: OOooOOo - OoO0O00 % i11iIiiIii
   if 58 - 58: iII111i
   iiiIIiiIi = len ( iIiI1I )
   if ( self . outer_version == 4 ) :
    I1111III111ii = iiiIIiiIi + oOO0
    iiiIIiiIi += 16
    IiI11II = IiI11II [ 0 : 2 ] + struct . pack ( "H" , I1111III111ii ) + IiI11II [ 4 : : ]
    if 2 - 2: II111iiii + i1IIi
    IiI11II = lisp_ip_checksum ( IiI11II )
    iIiI1I = IiI11II + iIiI1I
    iIiI1I = self . fix_outer_header ( iIiI1I )
    if 68 - 68: OOooOOo + Ii1I
    if 58 - 58: IiII * Ii1I . i1IIi
    if 19 - 19: oO0o
    if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
    if 94 - 94: iIii1I11I1II1 + IiII
   II11II = oOO0 - 12
   I1111III111ii = socket . htons ( iiiIIiiIi )
   iIiI1I = iIiI1I [ 0 : II11II ] + struct . pack ( "H" , I1111III111ii ) + iIiI1I [ II11II + 2 : : ]
   if 40 - 40: iII111i + O0
   IiIIii . append ( iIiI1I )
   if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
  return ( IiIIii , "Fragment-Inner" )
  if 36 - 36: OoOoOO00 . i11iIiiIii
  if 81 - 81: Oo0Ooo * iII111i * OoO0O00
 def fix_outer_header ( self , packet ) :
  if 85 - 85: O0 * oO0o
  if 39 - 39: II111iiii * I1IiiI - iIii1I11I1II1
  if 25 - 25: OoooooooOO . Ii1I % iII111i . IiII
  if 67 - 67: OoooooooOO + I1Ii111 / ooOoO0o
  if 75 - 75: IiII / OoooooooOO . I1IiiI + I1Ii111 - II111iiii
  if 33 - 33: IiII / IiII . i11iIiiIii * I1ii11iIi11i + o0oOOo0O0Ooo
  if 16 - 16: IiII
  if 10 - 10: OoOoOO00 . IiII * iIii1I11I1II1 - oO0o - OoOoOO00 / I1Ii111
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : 6 ] + packet [ 7 ] + packet [ 6 ] + packet [ 8 : : ]
    if 13 - 13: oO0o + OoOoOO00 % IiII % OoooooooOO
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : : ]
    if 22 - 22: I1Ii111
    if 23 - 23: O0
  return ( packet )
  if 41 - 41: i1IIi . OOooOOo / ooOoO0o / o0oOOo0O0Ooo % IiII - Ii1I
  if 14 - 14: I1ii11iIi11i - i11iIiiIii * I1Ii111
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 39 - 39: OoooooooOO
  dest = dest . print_address_no_iid ( )
  IiIIii , i1iIII1IIi = self . fragment ( )
  if 63 - 63: II111iiii . I1Ii111 % IiII + II111iiii
  for iIiI1I in IiIIii :
   if ( len ( IiIIii ) != 1 ) :
    self . packet = iIiI1I
    self . print_packet ( i1iIII1IIi , True )
    if 81 - 81: OOooOOo - I1IiiI % o0oOOo0O0Ooo
    if 7 - 7: ooOoO0o - i1IIi . OoOoOO00
   try : lisp_raw_socket . sendto ( iIiI1I , ( dest , 0 ) )
   except socket . error , oOo :
    lprint ( "socket.sendto() failed: {}" . format ( oOo ) )
    if 12 - 12: IiII / OoO0O00 / O0 * IiII
    if 51 - 51: ooOoO0o * iII111i / i1IIi
    if 2 - 2: oO0o + IiII . iII111i - i1IIi + I1Ii111
    if 54 - 54: OoooooooOO . oO0o - iII111i
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 76 - 76: I1Ii111
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 61 - 61: ooOoO0o / II111iiii * ooOoO0o * OoOoOO00 * I1Ii111 . i11iIiiIii
   if 26 - 26: I1Ii111 / ooOoO0o - OoO0O00 . iIii1I11I1II1
  IIii1i = mac_header + self . packet
  if 83 - 83: ooOoO0o % Ii1I / Oo0Ooo - iII111i / O0
  if 97 - 97: iIii1I11I1II1 * I11i
  if 95 - 95: OoO0O00
  if 68 - 68: iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00 - II111iiii - iIii1I11I1II1
  if 75 - 75: ooOoO0o . I1IiiI * II111iiii
  if 99 - 99: iIii1I11I1II1 * I1ii11iIi11i + IiII
  if 70 - 70: i1IIi % ooOoO0o . I1ii11iIi11i - IiII + OOooOOo
  if 84 - 84: oO0o + II111iiii * II111iiii % o0oOOo0O0Ooo / iII111i + ooOoO0o
  if 9 - 9: iII111i
  if 25 - 25: OOooOOo - Ii1I . I11i
  if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
  l2_socket . write ( IIii1i )
  return
  if 37 - 37: OoO0O00 * I11i + Ii1I + I1ii11iIi11i * o0oOOo0O0Ooo
  if 95 - 95: Ii1I - i11iIiiIii % i11iIiiIii - O0 * I1Ii111
 def bridge_l2_packet ( self , eid , db ) :
  try : Oo0O0oOoO0o0 = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : II1i = lisp_myinterfaces [ Oo0O0oOoO0o0 . interface ]
  except : return
  try :
   socket = II1i . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 21 - 21: I1IiiI - I1IiiI + iII111i % I1IiiI * oO0o
  try : socket . send ( self . packet )
  except socket . error , oOo :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( oOo ) )
   if 74 - 74: iII111i / I11i . I1IiiI - OoooooooOO + II111iiii + I11i
   if 36 - 36: Ii1I * I1IiiI * I1ii11iIi11i . I11i * I1ii11iIi11i
   if 76 - 76: OOooOOo + O0 / IiII - OoO0O00
 def is_lisp_packet ( self , packet ) :
  o0oOo00 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == LISP_UDP_PROTOCOL )
  if ( o0oOo00 == False ) : return ( False )
  if 27 - 27: Oo0Ooo - iIii1I11I1II1 * iII111i * II111iiii * I1ii11iIi11i
  IiI1iI1 = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
  if ( socket . ntohs ( IiI1iI1 ) == LISP_DATA_PORT ) : return ( True )
  IiI1iI1 = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
  if ( socket . ntohs ( IiI1iI1 ) == LISP_DATA_PORT ) : return ( True )
  return ( False )
  if 99 - 99: oO0o / i1IIi
  if 2 - 2: oO0o . iII111i
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  IIii1i = self . packet
  II1II111 = len ( IIii1i )
  OoO00oO0o00 = I11 = True
  if 51 - 51: iII111i / I11i - I11i
  if 65 - 65: OoOoOO00 * O0 - OoOoOO00 - OoO0O00
  if 96 - 96: I1ii11iIi11i - O0
  if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
  oO0oO00 = 0
  o0OoO0000o = 0
  if ( is_lisp_packet ) :
   o0OoO0000o = self . lisp_header . get_instance_id ( )
   IiiI1Ii1II = struct . unpack ( "B" , IIii1i [ 0 : 1 ] ) [ 0 ]
   self . outer_version = IiiI1Ii1II >> 4
   if ( self . outer_version == 4 ) :
    if 74 - 74: oO0o / OoooooooOO % oO0o / iIii1I11I1II1 + O0
    if 95 - 95: Oo0Ooo * OOooOOo + I1IiiI . O0
    if 36 - 36: OoOoOO00 * OoO0O00 / ooOoO0o / I1IiiI - Ii1I
    if 53 - 53: oO0o
    if 99 - 99: Oo0Ooo
    IiIi1I11 = struct . unpack ( "H" , IIii1i [ 10 : 12 ] ) [ 0 ]
    IIii1i = lisp_ip_checksum ( IIii1i )
    Oo0 = struct . unpack ( "H" , IIii1i [ 10 : 12 ] ) [ 0 ]
    if ( Oo0 != 0 ) :
     if ( IiIi1I11 != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( II1II111 )
       if 19 - 19: i1IIi / IiII + I1ii11iIi11i * I1ii11iIi11i
       if 90 - 90: OoooooooOO * iII111i . i11iIiiIii . ooOoO0o - I1Ii111
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 81 - 81: I1IiiI / OoooooooOO
      if 52 - 52: oO0o + I1Ii111 * I1Ii111 * Oo0Ooo - iIii1I11I1II1 + I1ii11iIi11i
      if 34 - 34: iII111i / OoO0O00 / Oo0Ooo
    O000oOOoOOO = LISP_AFI_IPV4
    OoO00oo00 = 12
    self . outer_tos = struct . unpack ( "B" , IIii1i [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , IIii1i [ 8 : 9 ] ) [ 0 ]
    oO0oO00 = 20
   elif ( self . outer_version == 6 ) :
    O000oOOoOOO = LISP_AFI_IPV6
    OoO00oo00 = 8
    IiIi = struct . unpack ( "H" , IIii1i [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( IiIi ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , IIii1i [ 7 : 8 ] ) [ 0 ]
    oO0oO00 = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( II1II111 )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 95 - 95: O0 + iIii1I11I1II1 . I1ii11iIi11i
    if 61 - 61: Ii1I * Ii1I
   self . outer_source . afi = O000oOOoOOO
   self . outer_dest . afi = O000oOOoOOO
   O0III1Iiii1i11 = self . outer_source . addr_length ( )
   if 74 - 74: Oo0Ooo / I1Ii111 % I1Ii111 . IiII
   self . outer_source . unpack_address ( IIii1i [ OoO00oo00 : OoO00oo00 + O0III1Iiii1i11 ] )
   OoO00oo00 += O0III1Iiii1i11
   self . outer_dest . unpack_address ( IIii1i [ OoO00oo00 : OoO00oo00 + O0III1Iiii1i11 ] )
   IIii1i = IIii1i [ oO0oO00 : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 72 - 72: i1IIi
   if 21 - 21: I1Ii111 . OOooOOo / i11iIiiIii * i1IIi
   if 82 - 82: ooOoO0o * Oo0Ooo % i11iIiiIii * i1IIi . OOooOOo
   if 89 - 89: IiII - i1IIi - IiII
   oOOo00OOOO = struct . unpack ( "H" , IIii1i [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( oOOo00OOOO )
   oOOo00OOOO = struct . unpack ( "H" , IIii1i [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( oOOo00OOOO )
   oOOo00OOOO = struct . unpack ( "H" , IIii1i [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( oOOo00OOOO )
   oOOo00OOOO = struct . unpack ( "H" , IIii1i [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( oOOo00OOOO )
   IIii1i = IIii1i [ 8 : : ]
   if 70 - 70: i1IIi - iIii1I11I1II1 - I1Ii111
   if 49 - 49: I1Ii111 / II111iiii
   if 69 - 69: o0oOOo0O0Ooo + I1ii11iIi11i / iIii1I11I1II1 . IiII % I1ii11iIi11i * OoOoOO00
   if 13 - 13: iIii1I11I1II1 + iII111i / Ii1I / i1IIi % OoO0O00 - iIii1I11I1II1
   OoO00oO0o00 = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   I11 = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 60 - 60: I1Ii111
   if 77 - 77: I1IiiI / I1ii11iIi11i
   if 95 - 95: I1Ii111 * i1IIi + oO0o
   if 40 - 40: II111iiii
   if ( self . lisp_header . decode ( IIii1i ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( II1II111 )
    if 7 - 7: OOooOOo / OoO0O00
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 88 - 88: i1IIi
   IIii1i = IIii1i [ 8 : : ]
   o0OoO0000o = self . lisp_header . get_instance_id ( )
   oO0oO00 += 16
   if 53 - 53: ooOoO0o . OOooOOo . o0oOOo0O0Ooo + oO0o
  if ( o0OoO0000o == 0xffffff ) : o0OoO0000o = 0
  if 17 - 17: iIii1I11I1II1 + i1IIi . I1ii11iIi11i + Ii1I % i1IIi . oO0o
  if 57 - 57: oO0o
  if 92 - 92: II111iiii - OoO0O00 - OOooOOo % I1IiiI - OoOoOO00 * I1Ii111
  if 16 - 16: iIii1I11I1II1 + OoooooooOO - ooOoO0o * IiII
  iiI1IiI1I1I = False
  IIIiI1i = self . lisp_header . k_bits
  if ( IIIiI1i ) :
   oo0o00OO = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( oo0o00OO == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( II1II111 )
    if 22 - 22: IiII / OOooOOo
    self . print_packet ( "Receive" , is_lisp_packet )
    O0OOoooO = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( O0OOoooO , IIIiI1i ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
    if 45 - 45: OOooOOo + I11i / OoooooooOO - Ii1I + OoooooooOO
   ii1i1I1111ii = lisp_crypto_keys_by_rloc_decap [ oo0o00OO ] [ IIIiI1i ]
   if ( ii1i1I1111ii == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( II1II111 )
    if 87 - 87: IiII
    self . print_packet ( "Receive" , is_lisp_packet )
    O0OOoooO = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( O0OOoooO ,
 red ( oo0o00OO , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 32 - 32: OoooooooOO / iII111i / I1Ii111 + iII111i - I11i + II111iiii
    if 11 - 11: OoooooooOO * o0oOOo0O0Ooo + OoooooooOO - I1ii11iIi11i
    if 47 - 47: I1Ii111 % OOooOOo * OoO0O00 . iIii1I11I1II1 % Oo0Ooo + OoooooooOO
    if 2 - 2: I1Ii111 % OoooooooOO - ooOoO0o * I1ii11iIi11i * IiII
    if 99 - 99: iIii1I11I1II1 . Oo0Ooo / ooOoO0o . OOooOOo % I1IiiI * I11i
   ii1i1I1111ii . use_count += 1
   IIii1i , iiI1IiI1I1I = self . decrypt ( IIii1i , oO0oO00 , ii1i1I1111ii ,
 oo0o00OO )
   if ( iiI1IiI1I1I == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( II1II111 )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 95 - 95: oO0o
    if 80 - 80: IiII
    if 42 - 42: OoooooooOO * II111iiii
    if 53 - 53: I1Ii111 + i1IIi . OoO0O00 / i11iIiiIii + Ii1I % OoOoOO00
    if 9 - 9: ooOoO0o . I11i - Oo0Ooo . I1Ii111
    if 39 - 39: OOooOOo
  IiiI1Ii1II = struct . unpack ( "B" , IIii1i [ 0 : 1 ] ) [ 0 ]
  self . inner_version = IiiI1Ii1II >> 4
  if ( OoO00oO0o00 and self . inner_version == 4 and IiiI1Ii1II >= 0x45 ) :
   o00OO00OOo0 = socket . ntohs ( struct . unpack ( "H" , IIii1i [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , IIii1i [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , IIii1i [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , IIii1i [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( IIii1i [ 12 : 16 ] )
   self . inner_dest . unpack_address ( IIii1i [ 16 : 20 ] )
   iIiIi1i1Iiii = socket . ntohs ( struct . unpack ( "H" , IIii1i [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( iIiIi1i1Iiii & 0x2000 or iIiIi1i1Iiii != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , IIii1i [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , IIii1i [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 92 - 92: OOooOOo
  elif ( OoO00oO0o00 and self . inner_version == 6 and IiiI1Ii1II >= 0x60 ) :
   o00OO00OOo0 = socket . ntohs ( struct . unpack ( "H" , IIii1i [ 4 : 6 ] ) [ 0 ] ) + 40
   IiIi = struct . unpack ( "H" , IIii1i [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( IiIi ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , IIii1i [ 7 : 8 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , IIii1i [ 6 : 7 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( IIii1i [ 8 : 24 ] )
   self . inner_dest . unpack_address ( IIii1i [ 24 : 40 ] )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , IIii1i [ 40 : 42 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , IIii1i [ 42 : 44 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 32 - 32: iII111i . iIii1I11I1II1 % Oo0Ooo . OoooooooOO
  elif ( I11 ) :
   o00OO00OOo0 = len ( IIii1i )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_protocol = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( IIii1i [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( IIii1i [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( II1II111 )
   if 81 - 81: i11iIiiIii * iII111i . oO0o * oO0o . IiII
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( IiiI1Ii1II ) ) )
   if 47 - 47: iIii1I11I1II1 % I11i . I11i / O0 . i11iIiiIii * Ii1I
   IIii1i = lisp_format_packet ( IIii1i [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( IIii1i ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 24 - 24: O0
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = o0OoO0000o
  self . inner_dest . instance_id = o0OoO0000o
  if 33 - 33: OoooooooOO + oO0o * II111iiii / OOooOOo
  if 87 - 87: OoooooooOO
  if 1 - 1: iIii1I11I1II1 / o0oOOo0O0Ooo
  if 98 - 98: O0 % I1IiiI / OoooooooOO * I1ii11iIi11i - oO0o
  if 51 - 51: iII111i + I11i
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   Oo0ooO0O0o00o = lisp_get_echo_nonce ( self . outer_source , None )
   if ( Oo0ooO0O0o00o == None ) :
    o0O00oo0O = self . outer_source . print_address_no_iid ( )
    Oo0ooO0O0o00o = lisp_echo_nonce ( o0O00oo0O )
    if 75 - 75: Ii1I + ooOoO0o / OoooooooOO
   oOO000 = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    Oo0ooO0O0o00o . receive_request ( lisp_ipc_socket , oOO000 )
   elif ( Oo0ooO0O0o00o . request_nonce_sent ) :
    Oo0ooO0O0o00o . receive_echo ( lisp_ipc_socket , oOO000 )
    if 47 - 47: iIii1I11I1II1 + OoO0O00 % iIii1I11I1II1 . ooOoO0o / Oo0Ooo - i11iIiiIii
    if 80 - 80: I1ii11iIi11i / O0 / iIii1I11I1II1 + I1IiiI
    if 3 - 3: ooOoO0o / i1IIi - OoOoOO00
    if 73 - 73: OoooooooOO * O0 * ooOoO0o
    if 7 - 7: II111iiii + i1IIi
    if 95 - 95: i11iIiiIii + OoooooooOO / OOooOOo - iIii1I11I1II1 + iIii1I11I1II1
    if 29 - 29: IiII % ooOoO0o + OoO0O00 . i1IIi + I1IiiI
  if ( iiI1IiI1I1I ) : self . packet += IIii1i [ : o00OO00OOo0 ]
  if 24 - 24: I1Ii111 / Ii1I * I1ii11iIi11i - OoooooooOO / I1IiiI . oO0o
  if 98 - 98: i1IIi - iII111i
  if 49 - 49: o0oOOo0O0Ooo . Ii1I . oO0o
  if 9 - 9: IiII - II111iiii * OoO0O00
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 78 - 78: iIii1I11I1II1 / O0 * oO0o / iII111i / OoOoOO00
  if 15 - 15: ooOoO0o / oO0o
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 54 - 54: ooOoO0o - iIii1I11I1II1 - I11i % Ii1I / II111iiii
  if 80 - 80: i11iIiiIii % iIii1I11I1II1 / i11iIiiIii
 def strip_outer_headers ( self ) :
  OoO00oo00 = 16
  OoO00oo00 += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ OoO00oo00 : : ]
  return ( self )
  if 66 - 66: OoOoOO00 . iIii1I11I1II1 * I1ii11iIi11i - Ii1I - iIii1I11I1II1
  if 28 - 28: OoOoOO00 % OoooooooOO
 def hash_ports ( self ) :
  IIii1i = self . packet
  IiiI1Ii1II = self . inner_version
  I1I = 0
  if ( IiiI1Ii1II == 4 ) :
   iIIIIi1iiI = struct . unpack ( "B" , IIii1i [ 9 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( iIIIIi1iiI )
   if ( iIIIIi1iiI in [ 6 , 17 ] ) :
    I1I = iIIIIi1iiI
    I1I += struct . unpack ( "I" , IIii1i [ 20 : 24 ] ) [ 0 ]
    I1I = ( I1I >> 16 ) ^ ( I1I & 0xffff )
    if 57 - 57: I11i . O0 . OoooooooOO . I1Ii111 - Ii1I / ooOoO0o
    if 34 - 34: OoOoOO00 % o0oOOo0O0Ooo - oO0o
  if ( IiiI1Ii1II == 6 ) :
   iIIIIi1iiI = struct . unpack ( "B" , IIii1i [ 6 ] ) [ 0 ]
   if ( iIIIIi1iiI in [ 6 , 17 ] ) :
    I1I = iIIIIi1iiI
    I1I += struct . unpack ( "I" , IIii1i [ 40 : 44 ] ) [ 0 ]
    I1I = ( I1I >> 16 ) ^ ( I1I & 0xffff )
    if 40 - 40: iII111i
    if 82 - 82: I1Ii111 . i1IIi / oO0o
  return ( I1I )
  if 56 - 56: iII111i
  if 23 - 23: i1IIi
 def hash_packet ( self ) :
  I1I = self . inner_source . address ^ self . inner_dest . address
  I1I += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   I1I = ( I1I >> 16 ) ^ ( I1I & 0xffff )
  elif ( self . inner_version == 6 ) :
   I1I = ( I1I >> 64 ) ^ ( I1I & 0xffffffffffffffff )
   I1I = ( I1I >> 32 ) ^ ( I1I & 0xffffffff )
   I1I = ( I1I >> 16 ) ^ ( I1I & 0xffff )
   if 24 - 24: IiII
  self . udp_sport = 0xf000 | ( I1I & 0xfff )
  if 51 - 51: OOooOOo % i11iIiiIii
  if 77 - 77: OOooOOo % i11iIiiIii - I1ii11iIi11i
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   I1 = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # IiII + i1IIi . I1Ii111 - I11i
 green ( I1 , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 29 - 29: OoooooooOO - oO0o / I1IiiI + II111iiii
   if 12 - 12: oO0o . OOooOOo
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   oo00 = "decap"
   oo00 += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   oo00 = s_or_r
   if ( oo00 in [ "Send" , "Replicate" ] or oo00 . find ( "Fragment" ) != - 1 ) :
    oo00 = "encap"
    if 88 - 88: I11i - iII111i
    if 68 - 68: Oo0Ooo % oO0o . IiII - o0oOOo0O0Ooo / i1IIi / OoooooooOO
  i1II11II11 = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 94 - 94: iIii1I11I1II1
  if 1 - 1: O0
  if 2 - 2: OoO0O00 . I11i
  if 97 - 97: Oo0Ooo
  if 65 - 65: Oo0Ooo % OOooOOo / i11iIiiIii / iIii1I11I1II1 . I1Ii111 + ooOoO0o
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   oOOo0ooO0 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 92 - 92: oO0o
   oOOo0ooO0 += bold ( "control-packet" , False ) + ": {} ..."
   if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
   dprint ( oOOo0ooO0 . format ( bold ( s_or_r , False ) , red ( i1II11II11 , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   oOOo0ooO0 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 3 - 3: OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
   if 47 - 47: IiII . OOooOOo
   if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
   if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
  if ( self . lisp_header . k_bits ) :
   if ( oo00 == "encap" ) : oo00 = "encrypt/encap"
   if ( oo00 == "decap" ) : oo00 = "decap/decrypt"
   if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
   if 68 - 68: OoO0O00 % O0 * iIii1I11I1II1 / oO0o * o0oOOo0O0Ooo + OOooOOo
  I1 = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 89 - 89: ooOoO0o * I1IiiI . oO0o
  dprint ( oOOo0ooO0 . format ( bold ( s_or_r , False ) , red ( i1II11II11 , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( I1 , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( oo00 ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 75 - 75: ooOoO0o - iII111i % iII111i + ooOoO0o * o0oOOo0O0Ooo - I1ii11iIi11i
  if 26 - 26: I11i * Ii1I % I1IiiI + iII111i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 38 - 38: iII111i - Oo0Ooo / Ii1I + oO0o . iII111i + IiII
  if 19 - 19: Ii1I
 def get_raw_socket ( self ) :
  o0OoO0000o = str ( self . lisp_header . get_instance_id ( ) )
  if ( o0OoO0000o == "0" ) : return ( None )
  if ( lisp_iid_to_interface . has_key ( o0OoO0000o ) == False ) : return ( None )
  if 51 - 51: iIii1I11I1II1
  II1i = lisp_iid_to_interface [ o0OoO0000o ]
  IiII1iiI = II1i . get_socket ( )
  if ( IiII1iiI == None ) :
   iI = bold ( "SO_BINDTODEVICE" , False )
   II1I = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( iI , "drop" if II1I else "forward" ) )
   if 10 - 10: i11iIiiIii . OoooooooOO . O0 % ooOoO0o / OoO0O00
   if ( II1I ) : return ( None )
   if 36 - 36: I1IiiI % i1IIi + OoO0O00
   if 59 - 59: i11iIiiIii - i11iIiiIii + I1IiiI
  o0OoO0000o = bold ( o0OoO0000o , False )
  OooOOOoOoo0O0 = bold ( II1i . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( o0OoO0000o , OooOOOoOoo0O0 ) )
  return ( IiII1iiI )
  if 4 - 4: Oo0Ooo * O0 - oO0o % ooOoO0o + OoOoOO00
  if 3 - 3: OoOoOO00
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 91 - 91: O0 - I11i % I1Ii111
  I1ii = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or I1ii ) :
   OOoo = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = OOoo ) . start ( )
   if ( I1ii ) : os . system ( "rm ./log-flows" )
   return
   if 87 - 87: OoO0O00 * OoOoOO00 - Oo0Ooo % OOooOOo * i11iIiiIii
   if 59 - 59: I1Ii111 + OoooooooOO / I1IiiI / OoooooooOO . iII111i
  Oo0OO0000oooo = datetime . datetime . now ( )
  lisp_flow_log . append ( [ Oo0OO0000oooo , encap , self . packet , self ] )
  if 20 - 20: Ii1I . I1Ii111 % Ii1I
  if 5 - 5: OOooOOo + iII111i
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  i1ii11III1 = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 3 - 3: oO0o % OoOoOO00 . I1ii11iIi11i / OoO0O00
  iII111iiIII1I = red ( self . outer_source . print_address_no_iid ( ) , False )
  iiIIiii1ii1 = red ( self . outer_dest . print_address_no_iid ( ) , False )
  Ii1i111iI = green ( self . inner_source . print_address ( ) , False )
  iII1ii = green ( self . inner_dest . print_address ( ) , False )
  if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   i1ii11III1 += " {}:{} -> {}:{}, LISP control message type {}\n"
   i1ii11III1 = i1ii11III1 . format ( iII111iiIII1I , self . udp_sport , iiIIiii1ii1 , self . udp_dport ,
 self . inner_version )
   return ( i1ii11III1 )
   if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
   if 89 - 89: OoooooooOO % II111iiii - OoO0O00 % i11iIiiIii
  if ( self . outer_dest . is_null ( ) == False ) :
   i1ii11III1 += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   i1ii11III1 = i1ii11III1 . format ( iII111iiIII1I , self . udp_sport , iiIIiii1ii1 , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 7 - 7: IiII
   if 15 - 15: Oo0Ooo + iII111i + I1IiiI * o0oOOo0O0Ooo
   if 33 - 33: o0oOOo0O0Ooo * Oo0Ooo
   if 88 - 88: I1Ii111 % OOooOOo - OoOoOO00 - OoOoOO00 . I1IiiI
   if 52 - 52: II111iiii / II111iiii / I1IiiI - I1Ii111
  if ( self . lisp_header . k_bits != 0 ) :
   Oo0OOo = "\n"
   if ( self . packet_error != "" ) :
    Oo0OOo = " ({})" . format ( self . packet_error ) + Oo0OOo
    if 43 - 43: IiII % Ii1I . OOooOOo / Oo0Ooo
   i1ii11III1 += ", encrypted" + Oo0OOo
   return ( i1ii11III1 )
   if 55 - 55: I1ii11iIi11i % OoooooooOO
   if 73 - 73: i1IIi - iII111i % oO0o / i1IIi + II111iiii + I1ii11iIi11i
   if 54 - 54: oO0o
   if 26 - 26: ooOoO0o % OoooooooOO . I1Ii111 * ooOoO0o + II111iiii - I1ii11iIi11i
   if 20 - 20: OoO0O00
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 99 - 99: Oo0Ooo + OoooooooOO . iII111i + O0
   if 85 - 85: II111iiii - Ii1I
  iIIIIi1iiI = packet [ 9 ] if self . inner_version == 4 else packet [ 6 ]
  iIIIIi1iiI = struct . unpack ( "B" , iIIIIi1iiI ) [ 0 ]
  if 93 - 93: IiII / i11iIiiIii - oO0o + OoO0O00 / i1IIi
  i1ii11III1 += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  i1ii11III1 = i1ii11III1 . format ( Ii1i111iI , iII1ii , len ( packet ) , self . inner_tos ,
 self . inner_ttl , iIIIIi1iiI )
  if 62 - 62: I1ii11iIi11i / OoooooooOO * I1IiiI - i1IIi
  if 81 - 81: oO0o / O0 * ooOoO0o % OoOoOO00 / O0
  if 85 - 85: OoooooooOO + OoooooooOO
  if 23 - 23: i1IIi
  if ( iIIIIi1iiI in [ 6 , 17 ] ) :
   IIiii1I1I = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( IIiii1I1I ) == 4 ) :
    IIiii1I1I = socket . ntohl ( struct . unpack ( "I" , IIiii1I1I ) [ 0 ] )
    i1ii11III1 += ", ports {} -> {}" . format ( IIiii1I1I >> 16 , IIiii1I1I & 0xffff )
    if 62 - 62: II111iiii - OoOoOO00 * Ii1I
  elif ( iIIIIi1iiI == 1 ) :
   oO0OO0O = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( oO0OO0O ) == 2 ) :
    oO0OO0O = socket . ntohs ( struct . unpack ( "H" , oO0OO0O ) [ 0 ] )
    i1ii11III1 += ", icmp-seq {}" . format ( oO0OO0O )
    if 70 - 70: i1IIi % OoO0O00 / i1IIi
    if 30 - 30: OoOoOO00 - i11iIiiIii
  if ( self . packet_error != "" ) :
   i1ii11III1 += " ({})" . format ( self . packet_error )
   if 94 - 94: OoOoOO00 % iII111i
  i1ii11III1 += "\n"
  return ( i1ii11III1 )
  if 39 - 39: OoOoOO00 + I1Ii111 % O0
  if 26 - 26: ooOoO0o + OoOoOO00
 def is_trace ( self ) :
  IIiii1I1I = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in IIiii1I1I )
  if 17 - 17: I1ii11iIi11i - iII111i % Oo0Ooo * O0 % O0 * OOooOOo
  if 6 - 6: I1Ii111
  if 46 - 46: II111iiii * I1Ii111
  if 23 - 23: i1IIi - O0
  if 6 - 6: ooOoO0o % OoooooooOO * I1Ii111 - IiII
  if 24 - 24: I11i / iIii1I11I1II1 . OoooooooOO % OoOoOO00 . Ii1I
  if 73 - 73: I1Ii111
  if 25 - 25: IiII
  if 77 - 77: o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO . iIii1I11I1II1
  if 87 - 87: II111iiii - OoooooooOO / i1IIi . Ii1I - Oo0Ooo . i11iIiiIii
  if 47 - 47: Oo0Ooo % OoO0O00 - ooOoO0o - Oo0Ooo * oO0o
  if 72 - 72: o0oOOo0O0Ooo % o0oOOo0O0Ooo + iII111i + I1ii11iIi11i / Oo0Ooo
  if 30 - 30: Oo0Ooo + I1IiiI + i11iIiiIii / OoO0O00
  if 64 - 64: IiII
  if 80 - 80: I1IiiI - i11iIiiIii / OoO0O00 / OoOoOO00 + OoOoOO00
  if 89 - 89: O0 + IiII * I1Ii111
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 30 - 30: OoOoOO00
class lisp_data_header ( ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 39 - 39: I1ii11iIi11i + o0oOOo0O0Ooo + I1Ii111 + IiII
  if 48 - 48: I1Ii111 / ooOoO0o . iIii1I11I1II1
 def print_header ( self , e_or_d ) :
  ooo0OOoo = lisp_hex_string ( self . first_long & 0xffffff )
  oO0o00O = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 7 - 7: Oo0Ooo * OoO0O00 - II111iiii % I1Ii111 . Oo0Ooo . Oo0Ooo
  oOOo0ooO0 = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 5 - 5: OoooooooOO * I1ii11iIi11i
  return ( oOOo0ooO0 . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 ooo0OOoo , oO0o00O ) )
  if 42 - 42: o0oOOo0O0Ooo . I1Ii111 / O0 . II111iiii * OoOoOO00
  if 7 - 7: I1Ii111 * O0 + OoOoOO00
 def encode ( self ) :
  O00oO00oOO00O = "II"
  ooo0OOoo = socket . htonl ( self . first_long )
  oO0o00O = socket . htonl ( self . second_long )
  if 69 - 69: i1IIi % OoO0O00 % I1Ii111 / ooOoO0o / ooOoO0o
  Ii1I1i1IiiI = struct . pack ( O00oO00oOO00O , ooo0OOoo , oO0o00O )
  return ( Ii1I1i1IiiI )
  if 37 - 37: I1IiiI + OoooooooOO . I1Ii111 + I1IiiI . IiII
  if 44 - 44: OoOoOO00 . I1Ii111 . i1IIi . OoOoOO00 * ooOoO0o
 def decode ( self , packet ) :
  O00oO00oOO00O = "II"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( False )
  if 50 - 50: ooOoO0o
  ooo0OOoo , oO0o00O = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
  if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
  self . first_long = socket . ntohl ( ooo0OOoo )
  self . second_long = socket . ntohl ( oO0o00O )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 59 - 59: iII111i - OoooooooOO / ooOoO0o + I1ii11iIi11i . o0oOOo0O0Ooo - iII111i
  if 29 - 29: oO0o
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 26 - 26: O0 % OOooOOo - IiII . OOooOOo
  if 70 - 70: o0oOOo0O0Ooo + I11i / iII111i + ooOoO0o / I1IiiI
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 33 - 33: OoooooooOO . O0
  if 59 - 59: iIii1I11I1II1
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 45 - 45: O0
  if 78 - 78: I11i - iIii1I11I1II1 + I1Ii111 - I1ii11iIi11i - I1Ii111
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 21 - 21: OoooooooOO . O0 / i11iIiiIii
  if 86 - 86: OoOoOO00 / OOooOOo
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 40 - 40: iIii1I11I1II1 / ooOoO0o / I1IiiI + I1ii11iIi11i * OOooOOo
  if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 91 - 91: Ii1I + I11i - Oo0Ooo % OoOoOO00 . iII111i
  if 51 - 51: OOooOOo / I11i
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 51 - 51: ooOoO0o * oO0o - I1Ii111 + iII111i
  if 46 - 46: o0oOOo0O0Ooo - i11iIiiIii % OoO0O00 / Ii1I - OoOoOO00
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 88 - 88: oO0o * I1IiiI / OoO0O00 - OOooOOo / i1IIi . I1Ii111
  if 26 - 26: i11iIiiIii - ooOoO0o
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 45 - 45: ooOoO0o + II111iiii % iII111i
  if 55 - 55: ooOoO0o - oO0o % I1IiiI
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 61 - 61: ooOoO0o
  if 22 - 22: iIii1I11I1II1 / ooOoO0o / I1IiiI - o0oOOo0O0Ooo
  if 21 - 21: oO0o . i11iIiiIii * I11i . OOooOOo / OOooOOo
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
  if 42 - 42: OoooooooOO / I1Ii111 . o0oOOo0O0Ooo / O0 - IiII * IiII
  if 1 - 1: Ii1I % I1Ii111
 def send_ipc ( self , ipc_socket , ipc ) :
  oo00Oo0 = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  oO0o0 = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , oo00Oo0 )
  lisp_ipc ( ipc , ipc_socket , oO0o0 )
  if 28 - 28: Ii1I
  if 36 - 36: I1Ii111 / I1Ii111 % oO0o
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  OoOO0o00OOO0o = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , OoOO0o00OOO0o )
  if 52 - 52: OoooooooOO / Ii1I - O0 % i1IIi * OOooOOo
  if 92 - 92: Oo0Ooo % OoooooooOO - i11iIiiIii
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  OoOO0o00OOO0o = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , OoOO0o00OOO0o )
  if 46 - 46: Oo0Ooo
  if 99 - 99: OoO0O00 - ooOoO0o * O0 * I1ii11iIi11i * iIii1I11I1II1 - iIii1I11I1II1
 def receive_request ( self , ipc_socket , nonce ) :
  IIIi1ii1i1 = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( IIIi1ii1i1 != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 6 - 6: iIii1I11I1II1 * II111iiii
  if 38 - 38: I1IiiI
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 42 - 42: o0oOOo0O0Ooo
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 8 - 8: i11iIiiIii / ooOoO0o
  if 33 - 33: I1Ii111 * IiII - O0 + I1IiiI / IiII
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 19 - 19: i1IIi % II111iiii
  if 85 - 85: IiII - o0oOOo0O0Ooo % OOooOOo - II111iiii
  if 56 - 56: Ii1I * i11iIiiIii
  if 92 - 92: II111iiii - O0 . I1Ii111
  if 59 - 59: OoOoOO00
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   iiII1iiI = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 57 - 57: i11iIiiIii - I11i / ooOoO0o / o0oOOo0O0Ooo * i11iIiiIii * o0oOOo0O0Ooo
   if 28 - 28: OoooooooOO % O0 - OOooOOo / o0oOOo0O0Ooo / I1IiiI
   if ( remote_rloc . address > iiII1iiI . address ) :
    OO0o = "exit"
    self . request_nonce_sent = None
   else :
    OO0o = "stay in"
    self . echo_nonce_sent = None
    if 41 - 41: II111iiii * IiII / OoO0O00 . oO0o
    if 50 - 50: OoooooooOO + iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii . ooOoO0o
   Ooo0OO00oo = bold ( "collision" , False )
   I1111III111ii = red ( iiII1iiI . print_address_no_iid ( ) , False )
   i11iII1IiI = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( Ooo0OO00oo ,
 I1111III111ii , i11iII1IiI , OO0o ) )
   if 21 - 21: IiII * OoOoOO00 - I1Ii111
   if 44 - 44: OoooooooOO + Ii1I
   if 84 - 84: i1IIi - II111iiii . OoooooooOO / OoOoOO00 % Ii1I
   if 7 - 7: i1IIi / IiII / iII111i
   if 97 - 97: OoO0O00 + iIii1I11I1II1
  if ( self . echo_nonce_sent != None ) :
   oOO000 = self . echo_nonce_sent
   oOo = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( oOo ,
 lisp_hex_string ( oOO000 ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( oOO000 )
   if 79 - 79: ooOoO0o + oO0o - II111iiii . Oo0Ooo
   if 26 - 26: IiII
   if 52 - 52: O0 + ooOoO0o
   if 11 - 11: i1IIi / I1Ii111 * I1ii11iIi11i * I1Ii111 * ooOoO0o - i11iIiiIii
   if 96 - 96: I1ii11iIi11i % I1ii11iIi11i
   if 1 - 1: I1IiiI . Ii1I
   if 26 - 26: oO0o - ooOoO0o % Oo0Ooo - oO0o + IiII
  oOO000 = self . request_nonce_sent
  I1IIII = self . last_request_nonce_sent
  if ( oOO000 and I1IIII != None ) :
   if ( time . time ( ) - I1IIII >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( oOO000 ) ) )
    if 69 - 69: IiII
    return ( None )
    if 24 - 24: OoO0O00 / O0 * ooOoO0o % iIii1I11I1II1 + i1IIi % O0
    if 26 - 26: ooOoO0o + IiII - O0 * oO0o * II111iiii . I1ii11iIi11i
    if 75 - 75: OoOoOO00 / OoooooooOO / I11i % OoOoOO00 * Ii1I * IiII
    if 11 - 11: I1ii11iIi11i / OOooOOo . Ii1I * I1ii11iIi11i
    if 17 - 17: I1ii11iIi11i * OoooooooOO % i1IIi % OoooooooOO . iII111i
    if 20 - 20: OoO0O00 . oO0o
    if 4 - 4: Oo0Ooo % Ii1I % OoO0O00 * iII111i % OoooooooOO
    if 38 - 38: OoooooooOO . iII111i
    if 43 - 43: OoooooooOO
  if ( oOO000 == None ) :
   oOO000 = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( oOO000 )
   if 8 - 8: OOooOOo + I11i . I11i
   self . request_nonce_sent = oOO000
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( oOO000 ) ) )
   if 89 - 89: I1ii11iIi11i * I1ii11iIi11i * OoOoOO00 / iII111i
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 60 - 60: OoO0O00 / iII111i / I1IiiI + oO0o
   if 93 - 93: OoooooooOO * Ii1I / O0 + Ii1I - iIii1I11I1II1
   if 6 - 6: IiII - Oo0Ooo - I11i - O0 % OoooooooOO
   if 88 - 88: O0 / o0oOOo0O0Ooo * o0oOOo0O0Ooo . o0oOOo0O0Ooo . O0
   if 27 - 27: i11iIiiIii % iII111i + Ii1I . OOooOOo
   if ( lisp_i_am_itr == False ) : return ( oOO000 | 0x80000000 )
   self . send_request_ipc ( ipc_socket , oOO000 )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( oOO000 ) ) )
   if 9 - 9: OoO0O00
   if 43 - 43: Ii1I . OOooOOo + I1IiiI * i11iIiiIii
   if 2 - 2: OOooOOo
   if 3 - 3: I1IiiI . iII111i % O0 - ooOoO0o / O0
   if 79 - 79: Ii1I + oO0o % ooOoO0o % I1IiiI
   if 68 - 68: II111iiii - OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo % II111iiii
   if 53 - 53: iII111i . oO0o / Oo0Ooo . OoO0O00 . i11iIiiIii
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( oOO000 | 0x80000000 )
  if 60 - 60: II111iiii
  if 25 - 25: Oo0Ooo + o0oOOo0O0Ooo - OoO0O00
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 57 - 57: II111iiii . i1IIi
  oO000o0Oo00 = time . time ( ) - self . last_request_nonce_sent
  I11Ii1 = self . last_echo_nonce_rcvd
  return ( oO000o0Oo00 >= LISP_NONCE_ECHO_INTERVAL and I11Ii1 == None )
  if 63 - 63: i1IIi
  if 42 - 42: oO0o - i11iIiiIii % oO0o - I1Ii111 * O0 / II111iiii
 def recently_requested ( self ) :
  I11Ii1 = self . last_request_nonce_sent
  if ( I11Ii1 == None ) : return ( False )
  if 5 - 5: Oo0Ooo
  oO000o0Oo00 = time . time ( ) - I11Ii1
  return ( oO000o0Oo00 <= LISP_NONCE_ECHO_INTERVAL )
  if 84 - 84: I1ii11iIi11i
  if 53 - 53: oO0o
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 26 - 26: I1Ii111 / I1Ii111 + Oo0Ooo - o0oOOo0O0Ooo % II111iiii . OoooooooOO
  if 7 - 7: II111iiii - I1ii11iIi11i / I11i % OoooooooOO + i1IIi
  if 42 - 42: I11i + i1IIi - Ii1I / IiII . iII111i
  if 30 - 30: Oo0Ooo + Ii1I % i11iIiiIii * i1IIi + I1IiiI % OOooOOo
  I11Ii1 = self . last_good_echo_nonce_rcvd
  if ( I11Ii1 == None ) : I11Ii1 = 0
  oO000o0Oo00 = time . time ( ) - I11Ii1
  if ( oO000o0Oo00 <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 30 - 30: i11iIiiIii * Oo0Ooo . II111iiii + I1ii11iIi11i / o0oOOo0O0Ooo % I1Ii111
  if 78 - 78: I1ii11iIi11i + OoooooooOO - I1IiiI * OoOoOO00 * iII111i
  if 7 - 7: OOooOOo . IiII . I1Ii111 / Ii1I / Oo0Ooo
  if 83 - 83: I11i / Oo0Ooo
  if 23 - 23: iIii1I11I1II1
  if 10 - 10: I11i - o0oOOo0O0Ooo % OoooooooOO - I1ii11iIi11i
  I11Ii1 = self . last_new_request_nonce_sent
  if ( I11Ii1 == None ) : I11Ii1 = 0
  oO000o0Oo00 = time . time ( ) - I11Ii1
  return ( oO000o0Oo00 <= LISP_NONCE_ECHO_INTERVAL )
  if 64 - 64: OoO0O00 / I1IiiI
  if 23 - 23: I11i * I1Ii111 * o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + o0oOOo0O0Ooo
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   I1ii11ii1iiI = bold ( "down" , False )
   oO0oo0 = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , I1ii11ii1iiI , oO0oo0 ) )
   if 12 - 12: i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 8 - 8: o0oOOo0O0Ooo
   if 78 - 78: i1IIi - Oo0Ooo
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
  if ( self . recently_requested ( ) == False ) :
   i11iII11I1III = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , i11iII11I1III ) )
   if 44 - 44: OOooOOo . iIii1I11I1II1 . i11iIiiIii % OoooooooOO . ooOoO0o
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 53 - 53: IiII + O0
   if 88 - 88: OoooooooOO
   if 46 - 46: O0 % OoooooooOO
 def print_echo_nonce ( self ) :
  I1IiII = lisp_print_elapsed ( self . last_request_nonce_sent )
  o0O00o0o = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 31 - 31: ooOoO0o % I1IiiI % IiII / I1Ii111
  OoOOoo = lisp_print_elapsed ( self . last_echo_nonce_sent )
  I1OooO00Oo = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  IiII1iiI = space ( 4 )
  if 81 - 81: I1ii11iIi11i - OoO0O00 * oO0o
  Oo0Ooo0O0 = "Nonce-Echoing:\n"
  Oo0Ooo0O0 += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( IiII1iiI , I1IiII , IiII1iiI , o0O00o0o )
  if 81 - 81: iII111i - Ii1I - OOooOOo % IiII % o0oOOo0O0Ooo . iIii1I11I1II1
  Oo0Ooo0O0 += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( IiII1iiI , I1OooO00Oo , IiII1iiI , OoOOoo )
  if 79 - 79: I1ii11iIi11i - I1ii11iIi11i . Ii1I / IiII
  if 57 - 57: ooOoO0o * iIii1I11I1II1 * iII111i * Ii1I / Ii1I
  return ( Oo0Ooo0O0 )
  if 43 - 43: O0 * i11iIiiIii - OoooooooOO - oO0o
  if 46 - 46: oO0o * i1IIi / I1ii11iIi11i
  if 100 - 100: I1IiiI - OOooOOo
  if 91 - 91: o0oOOo0O0Ooo * I1ii11iIi11i - iII111i . II111iiii
  if 1 - 1: OOooOOo + I1Ii111 * I1ii11iIi11i
  if 44 - 44: iII111i
  if 79 - 79: o0oOOo0O0Ooo % OOooOOo . O0
  if 56 - 56: oO0o + i1IIi * iII111i - O0
  if 84 - 84: iII111i % I1IiiI / iIii1I11I1II1 * Ii1I * iIii1I11I1II1 + I1ii11iIi11i
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
    if 78 - 78: IiII / iII111i * Ii1I . OOooOOo . oO0o - I1Ii111
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   ii1i1I1111ii = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( ii1i1I1111ii )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 39 - 39: ooOoO0o . i1IIi + OoooooooOO . iII111i - i11iIiiIii % I1Ii111
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 38 - 38: oO0o
  if 9 - 9: I11i . OoO0O00 . oO0o / OoooooooOO
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 59 - 59: iIii1I11I1II1 + i1IIi % II111iiii
  if 2 - 2: II111iiii + I11i . OoO0O00
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 14 - 14: OOooOOo * I1IiiI - I1ii11iIi11i
  i1Oo = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   i1Oo = struct . pack ( "Q" , i1Oo & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   I1111I1i1i = struct . pack ( "I" , ( i1Oo >> 64 ) & LISP_4_32_MASK )
   O0oOo = struct . pack ( "Q" , i1Oo & LISP_8_64_MASK )
   i1Oo = I1111I1i1i + O0oOo
  else :
   i1Oo = struct . pack ( "QQ" , i1Oo >> 64 , i1Oo & LISP_8_64_MASK )
  return ( i1Oo )
  if 14 - 14: I1Ii111 + I1Ii111 / OoOoOO00 + OoOoOO00 * ooOoO0o / I1Ii111
  if 68 - 68: OoooooooOO
 def key_length ( self , key ) :
  if ( type ( key ) != str ) : key = self . normalize_pub_key ( key )
  return ( len ( key ) / 2 )
  if 38 - 38: iII111i + ooOoO0o
  if 32 - 32: ooOoO0o - OoooooooOO + OoO0O00
 def print_key ( self , key ) :
  OOOo0Oo0O = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( OOOo0Oo0O [ 0 : 4 ] , OOOo0Oo0O [ - 4 : : ] , self . key_length ( OOOo0Oo0O ) ) )
  if 90 - 90: I1ii11iIi11i / OoooooooOO % i11iIiiIii - IiII
  if 30 - 30: iII111i
 def normalize_pub_key ( self , key ) :
  if ( type ( key ) == str ) :
   if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
   return ( key )
   if 44 - 44: OoOoOO00 . OOooOOo
  key = lisp_hex_string ( key ) . zfill ( 256 )
  return ( key )
  if 84 - 84: I1Ii111 - I11i * OoOoOO00
  if 52 - 52: iII111i . IiII - I1ii11iIi11i * iIii1I11I1II1 % o0oOOo0O0Ooo / ooOoO0o
 def print_keys ( self , do_bold = True ) :
  I1111III111ii = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   I1111III111ii += "none"
  else :
   I1111III111ii += self . print_key ( self . local_public_key )
   if 18 - 18: OoOoOO00 % oO0o % OoO0O00 / iII111i
  i11iII1IiI = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   i11iII1IiI += "none"
  else :
   i11iII1IiI += self . print_key ( self . remote_public_key )
   if 88 - 88: iII111i * OOooOOo / i11iIiiIii / i1IIi
  O0O00O0O0 = "ECDH" if ( self . curve25519 ) else "DH"
  ii1IiIi1iIi = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( O0O00O0O0 , ii1IiIi1iIi , I1111III111ii , i11iII1IiI ) )
  if 16 - 16: OOooOOo % I1IiiI . I1Ii111 * OoO0O00 % O0 . OOooOOo
  if 94 - 94: I1ii11iIi11i
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 33 - 33: I1ii11iIi11i + I1ii11iIi11i . Ii1I
  if 27 - 27: II111iiii - i11iIiiIii - OoooooooOO
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 90 - 90: I1IiiI
  ii1i1I1111ii = self . local_private_key
  i11ii = self . dh_g_value
  III1I1Iii1 = self . dh_p_value
  return ( int ( ( i11ii ** ii1i1I1111ii ) % III1I1Iii1 ) )
  if 34 - 34: oO0o - II111iiii - o0oOOo0O0Ooo + iII111i + I1Ii111
  if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
 def compute_shared_key ( self , ed , print_shared = False ) :
  ii1i1I1111ii = self . local_private_key
  IiIi11iI1 = self . remote_public_key
  if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
  oO00O0oO = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( oO00O0oO , self . print_keys ( ) ) )
  if 69 - 69: OOooOOo + OOooOOo * Ii1I * I11i + I1IiiI
  if ( self . curve25519 ) :
   ii1i11iiII = curve25519 . Public ( IiIi11iI1 )
   self . shared_key = self . curve25519 . get_shared_key ( ii1i11iiII )
  else :
   III1I1Iii1 = self . dh_p_value
   self . shared_key = ( IiIi11iI1 ** ii1i1I1111ii ) % III1I1Iii1
   if 40 - 40: iII111i
   if 62 - 62: ooOoO0o / OOooOOo
   if 74 - 74: iII111i % I1Ii111 / I1Ii111 - iIii1I11I1II1 - II111iiii + OOooOOo
   if 92 - 92: I11i % I1Ii111
   if 18 - 18: ooOoO0o + I1Ii111 / OOooOOo / oO0o + iIii1I11I1II1 % IiII
   if 94 - 94: I11i
   if 37 - 37: oO0o
  if ( print_shared ) :
   OOOo0Oo0O = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( OOOo0Oo0O ) )
   if 52 - 52: I1ii11iIi11i * I1IiiI . OOooOOo + i1IIi % oO0o / iIii1I11I1II1
   if 68 - 68: I1Ii111 - OoOoOO00 . i11iIiiIii + o0oOOo0O0Ooo
   if 71 - 71: i11iIiiIii / i1IIi * I1IiiI / OoOoOO00
   if 33 - 33: I11i . Oo0Ooo
   if 89 - 89: iII111i + i1IIi - IiII + ooOoO0o . II111iiii
  self . compute_encrypt_icv_keys ( )
  if 85 - 85: iIii1I11I1II1 - Ii1I * Oo0Ooo . oO0o + I1Ii111
  if 13 - 13: O0 + iIii1I11I1II1 % II111iiii + iIii1I11I1II1
  if 85 - 85: I1IiiI * iIii1I11I1II1 . iII111i / iII111i
  if 43 - 43: I1IiiI
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 78 - 78: OoO0O00 % II111iiii + OoOoOO00 / I1IiiI
  if 34 - 34: o0oOOo0O0Ooo % I1ii11iIi11i + Ii1I * I11i / oO0o
 def compute_encrypt_icv_keys ( self ) :
  i111Iii11i1Ii = hashlib . sha256
  if ( self . curve25519 ) :
   oo00000ooOooO = self . shared_key
  else :
   oo00000ooOooO = lisp_hex_string ( self . shared_key )
   if 56 - 56: I1IiiI . IiII
   if 53 - 53: ooOoO0o - OoOoOO00 + IiII
   if 100 - 100: oO0o + OoO0O00
   if 95 - 95: i11iIiiIii . o0oOOo0O0Ooo + OoooooooOO % Oo0Ooo
   if 21 - 21: iII111i - o0oOOo0O0Ooo / I11i % O0 / iIii1I11I1II1 / iII111i
  I1111III111ii = self . local_public_key
  if ( type ( I1111III111ii ) != long ) : I1111III111ii = int ( binascii . hexlify ( I1111III111ii ) , 16 )
  i11iII1IiI = self . remote_public_key
  if ( type ( i11iII1IiI ) != long ) : i11iII1IiI = int ( binascii . hexlify ( i11iII1IiI ) , 16 )
  iIiii1Ii = "0001" + "lisp-crypto" + lisp_hex_string ( I1111III111ii ^ i11iII1IiI ) + "0100"
  if 17 - 17: O0 - Ii1I + IiII
  iIIII11iII = hmac . new ( iIiii1Ii , oo00000ooOooO , i111Iii11i1Ii ) . hexdigest ( )
  iIIII11iII = int ( iIIII11iII , 16 )
  if 78 - 78: IiII + I11i - o0oOOo0O0Ooo + OoO0O00 / iIii1I11I1II1
  if 47 - 47: OOooOOo
  if 20 - 20: I1Ii111 % ooOoO0o - I1Ii111 * OoooooooOO / I1ii11iIi11i
  if 57 - 57: IiII % I11i * OOooOOo % I1ii11iIi11i
  oooO0oO0 = ( iIIII11iII >> 128 ) & LISP_16_128_MASK
  IIII1 = iIIII11iII & LISP_16_128_MASK
  self . encrypt_key = lisp_hex_string ( oooO0oO0 ) . zfill ( 32 )
  oo0Ooo00O0o = 32 if self . do_poly else 40
  self . icv_key = lisp_hex_string ( IIII1 ) . zfill ( oo0Ooo00O0o )
  if 45 - 45: OoO0O00 * OoooooooOO / O0 . I1Ii111 / OoOoOO00
  if 53 - 53: OoOoOO00 . I1IiiI * I1ii11iIi11i
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   Oo00 = self . icv . poly1305aes
   I11Ii1I11IIIIi1 = self . icv . binascii . hexlify
   nonce = I11Ii1I11IIIIi1 ( nonce )
   ooOOo000 = Oo00 ( self . encrypt_key , self . icv_key , nonce , packet )
   ooOOo000 = I11Ii1I11IIIIi1 ( ooOOo000 )
  else :
   ii1i1I1111ii = binascii . unhexlify ( self . icv_key )
   ooOOo000 = hmac . new ( ii1i1I1111ii , packet , self . icv ) . hexdigest ( )
   ooOOo000 = ooOOo000 [ 0 : 40 ]
   if 77 - 77: I1IiiI / I1Ii111
  return ( ooOOo000 )
  if 65 - 65: I1ii11iIi11i * O0 . OoooooooOO * I11i / IiII
  if 87 - 87: iIii1I11I1II1
 def add_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 58 - 58: I1ii11iIi11i % i11iIiiIii + OoOoOO00 / I11i - OoooooooOO
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 62 - 62: OoO0O00 . OoOoOO00
  if 22 - 22: ooOoO0o . i11iIiiIii . OoooooooOO . i1IIi
 def delete_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
  if 41 - 41: OoooooooOO
 def add_key_by_rloc ( self , addr_str , encap ) :
  I1I111i = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 63 - 63: I1ii11iIi11i . I1IiiI + OOooOOo - IiII + iII111i
  if 78 - 78: Ii1I
  if ( I1I111i . has_key ( addr_str ) == False ) :
   I1I111i [ addr_str ] = [ None , None , None , None ]
   if 29 - 29: II111iiii
  I1I111i [ addr_str ] [ self . key_id ] = self
  if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
  if 84 - 84: Oo0Ooo % I11i * O0 * I11i
  if 66 - 66: OOooOOo / iIii1I11I1II1 - OoOoOO00 % O0 . ooOoO0o
  if 12 - 12: Oo0Ooo + I1IiiI
  if 37 - 37: i1IIi * i11iIiiIii
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , I1I111i [ addr_str ] )
   if 95 - 95: i11iIiiIii % I1Ii111 * Oo0Ooo + i1IIi . O0 + I1ii11iIi11i
   if 7 - 7: OoO0O00 * i11iIiiIii * iIii1I11I1II1 / OOooOOo / I1Ii111
   if 35 - 35: iII111i * OOooOOo
 def encode_lcaf ( self , rloc_addr ) :
  ooooO0OO0O = self . normalize_pub_key ( self . local_public_key )
  IiI11 = self . key_length ( ooooO0OO0O )
  iiIi = ( 6 + IiI11 + 2 )
  if ( rloc_addr != None ) : iiIi += rloc_addr . addr_length ( )
  if 84 - 84: iIii1I11I1II1 + I1ii11iIi11i
  IIii1i = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( iiIi ) , 1 , 0 )
  if 77 - 77: i11iIiiIii - I1Ii111 . I1ii11iIi11i % Oo0Ooo . Ii1I
  if 9 - 9: o0oOOo0O0Ooo
  if 55 - 55: OOooOOo % iIii1I11I1II1 + I11i . ooOoO0o
  if 71 - 71: i11iIiiIii / i1IIi + OoOoOO00
  if 23 - 23: i11iIiiIii
  if 88 - 88: II111iiii - iII111i / OoooooooOO
  ii1IiIi1iIi = self . cipher_suite
  IIii1i += struct . pack ( "BBH" , ii1IiIi1iIi , 0 , socket . htons ( IiI11 ) )
  if 71 - 71: I1ii11iIi11i
  if 19 - 19: Oo0Ooo - OoO0O00 + i11iIiiIii / iIii1I11I1II1
  if 1 - 1: IiII % i1IIi
  if 41 - 41: OoO0O00 * OoO0O00 / iII111i + I1ii11iIi11i . o0oOOo0O0Ooo
  for IiIIi1IiiIiI in range ( 0 , IiI11 * 2 , 16 ) :
   ii1i1I1111ii = int ( ooooO0OO0O [ IiIIi1IiiIiI : IiIIi1IiiIiI + 16 ] , 16 )
   IIii1i += struct . pack ( "Q" , byte_swap_64 ( ii1i1I1111ii ) )
   if 84 - 84: i11iIiiIii + OoO0O00 * I1IiiI + I1ii11iIi11i / Ii1I
   if 80 - 80: I1ii11iIi11i
   if 67 - 67: II111iiii
   if 2 - 2: o0oOOo0O0Ooo - O0 * Ii1I % IiII
   if 64 - 64: i1IIi . ooOoO0o
  if ( rloc_addr ) :
   IIii1i += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   IIii1i += rloc_addr . pack_address ( )
   if 7 - 7: oO0o . iII111i - iII111i / I1Ii111 % Oo0Ooo
  return ( IIii1i )
  if 61 - 61: oO0o - I1ii11iIi11i / iII111i % I1ii11iIi11i + OoO0O00 / Oo0Ooo
  if 10 - 10: i11iIiiIii / OoOoOO00
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 27 - 27: I1IiiI / OoooooooOO
  if 74 - 74: I1ii11iIi11i % I1Ii111 - OoO0O00 * I11i . OoooooooOO * OoO0O00
  if 99 - 99: OoOoOO00 . iII111i - OoooooooOO - O0
  if 6 - 6: OOooOOo
  if ( lcaf_len == 0 ) :
   O00oO00oOO00O = "HHBBH"
   ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
   if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
   if 3 - 3: O0 - I1Ii111 * Ii1I * OOooOOo / Ii1I
   O000oOOoOOO , O0Ooo000OO00 , O000oo0O0OO0 , O0Ooo000OO00 , lcaf_len = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
   if 58 - 58: OoO0O00 - OoooooooOO . iII111i
   if 26 - 26: OoOoOO00
   if ( O000oo0O0OO0 != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 48 - 48: iII111i
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ ooOoooOoo0oO : : ]
   if 85 - 85: I1ii11iIi11i . oO0o . O0
   if 16 - 16: I1ii11iIi11i % I1ii11iIi11i % I1Ii111 + I11i . I1Ii111 + OOooOOo
   if 85 - 85: i11iIiiIii . I11i + Ii1I / Ii1I
   if 43 - 43: IiII . OoooooooOO - II111iiii
   if 90 - 90: I1IiiI - iIii1I11I1II1 + I1ii11iIi11i * OOooOOo * oO0o
   if 19 - 19: I1Ii111 * II111iiii % Oo0Ooo - i1IIi
  O000oo0O0OO0 = LISP_LCAF_SECURITY_TYPE
  O00oO00oOO00O = "BBBBH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 27 - 27: OoOoOO00 . O0 / I1ii11iIi11i . iIii1I11I1II1
  I11IIi , O0Ooo000OO00 , ii1IiIi1iIi , O0Ooo000OO00 , IiI11 = struct . unpack ( O00oO00oOO00O ,
 packet [ : ooOoooOoo0oO ] )
  if 51 - 51: i1IIi % o0oOOo0O0Ooo - oO0o - IiII
  if 14 - 14: ooOoO0o + Ii1I
  if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
  if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
  if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
  if 28 - 28: iIii1I11I1II1 . O0
  packet = packet [ ooOoooOoo0oO : : ]
  IiI11 = socket . ntohs ( IiI11 )
  if ( len ( packet ) < IiI11 ) : return ( None )
  if 32 - 32: OoooooooOO
  if 29 - 29: I1ii11iIi11i
  if 41 - 41: Ii1I
  if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
  Iii = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( ii1IiIi1iIi not in Iii ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( Iii ,
 ii1IiIi1iIi ) )
   packet = packet [ IiI11 : : ]
   return ( packet )
   if 52 - 52: iII111i % I1Ii111 - I1Ii111 - oO0o - iII111i - i1IIi
   if 98 - 98: OoO0O00 - Oo0Ooo * I1IiiI
  self . cipher_suite = ii1IiIi1iIi
  if 90 - 90: I1IiiI
  if 27 - 27: iIii1I11I1II1 - oO0o
  if 73 - 73: OOooOOo . Oo0Ooo + Oo0Ooo % Oo0Ooo % O0
  if 8 - 8: iII111i . Ii1I - i1IIi % OoO0O00 / I11i
  if 13 - 13: Oo0Ooo / OoOoOO00 . I1ii11iIi11i . OOooOOo
  ooooO0OO0O = 0
  for IiIIi1IiiIiI in range ( 0 , IiI11 , 8 ) :
   ii1i1I1111ii = byte_swap_64 ( struct . unpack ( "Q" , packet [ IiIIi1IiiIiI : IiIIi1IiiIiI + 8 ] ) [ 0 ] )
   ooooO0OO0O <<= 64
   ooooO0OO0O |= ii1i1I1111ii
   if 31 - 31: o0oOOo0O0Ooo
  self . remote_public_key = ooooO0OO0O
  if 59 - 59: Oo0Ooo / Oo0Ooo
  if 87 - 87: I1ii11iIi11i % OoOoOO00 + Ii1I . i11iIiiIii / Ii1I
  if 32 - 32: Ii1I + IiII + I1ii11iIi11i
  if 79 - 79: i1IIi / Ii1I
  if 81 - 81: iIii1I11I1II1
  if ( self . curve25519 ) :
   ii1i1I1111ii = lisp_hex_string ( self . remote_public_key )
   ii1i1I1111ii = ii1i1I1111ii . zfill ( 64 )
   o000oO0oOOO = ""
   for IiIIi1IiiIiI in range ( 0 , len ( ii1i1I1111ii ) , 2 ) :
    o000oO0oOOO += chr ( int ( ii1i1I1111ii [ IiIIi1IiiIiI : IiIIi1IiiIiI + 2 ] , 16 ) )
    if 23 - 23: OOooOOo
   self . remote_public_key = o000oO0oOOO
   if 68 - 68: OoooooooOO
   if 18 - 18: Ii1I * OoO0O00
  packet = packet [ IiI11 : : ]
  return ( packet )
  if 89 - 89: OoO0O00 + oO0o % iIii1I11I1II1 + I11i / O0
  if 38 - 38: ooOoO0o - o0oOOo0O0Ooo - O0 + ooOoO0o % OoOoOO00 . o0oOOo0O0Ooo
  if 40 - 40: iIii1I11I1II1 * OoooooooOO * I1Ii111 - Ii1I + i11iIiiIii
  if 81 - 81: OoO0O00 * OoooooooOO / iII111i
  if 8 - 8: O0 * i1IIi - OoOoOO00 % I1IiiI / I1ii11iIi11i
  if 39 - 39: I1ii11iIi11i . oO0o * II111iiii + I1IiiI - iIii1I11I1II1
  if 56 - 56: IiII - Ii1I + i11iIiiIii * OoO0O00 % I1IiiI
  if 37 - 37: iIii1I11I1II1 + IiII / I1Ii111 . OoooooooOO
class lisp_thread ( ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = Queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
  if 72 - 72: oO0o % ooOoO0o % OOooOOo
  if 63 - 63: OoO0O00 . Ii1I % II111iiii / I11i - OoOoOO00
  if 4 - 4: Oo0Ooo - O0 / I11i + O0 - oO0o * Oo0Ooo
  if 25 - 25: I1IiiI
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
  if 93 - 93: iII111i . i11iIiiIii
  if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
 def decode ( self , packet ) :
  O00oO00oOO00O = "BBBBQ"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( False )
  if 49 - 49: O0 . Oo0Ooo / Ii1I
  II1IooOO00Oo , I11ii1i1I , i11IIii1I11 , self . record_count , self . nonce = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 43 - 43: i11iIiiIii
  if 65 - 65: O0 / iII111i . i1IIi * iII111i / iIii1I11I1II1 - oO0o
  self . type = II1IooOO00Oo >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( II1IooOO00Oo & 0x01 ) else False
   self . rloc_probe = True if ( II1IooOO00Oo & 0x02 ) else False
   self . smr_invoked_bit = True if ( I11ii1i1I & 0x40 ) else False
   if 93 - 93: OoOoOO00 % i11iIiiIii - Ii1I % OoO0O00
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( II1IooOO00Oo & 0x04 ) else False
   self . to_etr = True if ( II1IooOO00Oo & 0x02 ) else False
   self . to_ms = True if ( II1IooOO00Oo & 0x01 ) else False
   if 55 - 55: o0oOOo0O0Ooo . I1ii11iIi11i
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( II1IooOO00Oo & 0x08 ) else False
   if 63 - 63: oO0o
  return ( True )
  if 79 - 79: I1ii11iIi11i - oO0o - o0oOOo0O0Ooo . OOooOOo
  if 65 - 65: i11iIiiIii . OoO0O00 % iII111i + IiII - i11iIiiIii
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 60 - 60: I1Ii111
  if 14 - 14: Oo0Ooo % oO0o * iII111i - i11iIiiIii / I1ii11iIi11i * i11iIiiIii
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 95 - 95: iIii1I11I1II1 + OoOoOO00 . I1IiiI + OoOoOO00 * I11i + OOooOOo
  if 14 - 14: Ii1I - O0
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 68 - 68: II111iiii - I1ii11iIi11i - OoO0O00 * iIii1I11I1II1 / I1IiiI * I1ii11iIi11i
  if 45 - 45: I1Ii111 * I11i / iIii1I11I1II1 / I1IiiI % II111iiii
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 49 - 49: Ii1I / iII111i . iII111i . iII111i + i11iIiiIii % I11i
  if 7 - 7: IiII * ooOoO0o + OoOoOO00
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 22 - 22: iII111i
  if 48 - 48: I1ii11iIi11i . I1IiiI
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 73 - 73: O0 . I1Ii111 - OoooooooOO % I11i % i1IIi
  if 14 - 14: I1Ii111 + Ii1I * Oo0Ooo
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 49 - 49: Oo0Ooo
  if 57 - 57: O0 * ooOoO0o - iII111i - iIii1I11I1II1 * iII111i
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
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
  if 68 - 68: IiII % Oo0Ooo . O0 - OoOoOO00 + I1ii11iIi11i . i11iIiiIii
  if 45 - 45: I1IiiI
  if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
  if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
  if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
  if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
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
  if 61 - 61: Oo0Ooo - I1Ii111
  if 51 - 51: iII111i * ooOoO0o / O0 / O0
 def print_map_register ( self ) :
  oooOOOO0oOo = lisp_hex_string ( self . xtr_id )
  if 26 - 26: II111iiii + i1IIi
  oOOo0ooO0 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 14 - 14: iIii1I11I1II1 - ooOoO0o + oO0o + i11iIiiIii / iIii1I11I1II1
  lprint ( oOOo0ooO0 . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # i11iIiiIii . O0 / OOooOOo * i1IIi
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , oooOOOO0oOo , self . site_id ) )
  if 14 - 14: IiII + IiII . I11i / Ii1I . iIii1I11I1II1
  if 10 - 10: II111iiii . OOooOOo / iII111i
  if 35 - 35: iII111i / Oo0Ooo + O0 * iIii1I11I1II1 - O0
  if 3 - 3: I1ii11iIi11i
 def encode ( self ) :
  ooo0OOoo = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : ooo0OOoo |= 0x08000000
  if ( self . lisp_sec_present ) : ooo0OOoo |= 0x04000000
  if ( self . xtr_id_present ) : ooo0OOoo |= 0x02000000
  if ( self . map_register_refresh ) : ooo0OOoo |= 0x1000
  if ( self . use_ttl_for_timeout ) : ooo0OOoo |= 0x800
  if ( self . merge_register_requested ) : ooo0OOoo |= 0x400
  if ( self . mobile_node ) : ooo0OOoo |= 0x200
  if ( self . map_notify_requested ) : ooo0OOoo |= 0x100
  if ( self . encryption_key_id != None ) :
   ooo0OOoo |= 0x2000
   ooo0OOoo |= self . encryption_key_id << 14
   if 42 - 42: I11i % Oo0Ooo + IiII - I11i . iIii1I11I1II1 - Ii1I
   if 27 - 27: iII111i % Oo0Ooo . I1ii11iIi11i . i1IIi % OoOoOO00 . o0oOOo0O0Ooo
   if 37 - 37: iII111i + I1Ii111 * Ii1I + IiII
   if 39 - 39: O0 * Oo0Ooo - I1IiiI + Ii1I / II111iiii
   if 66 - 66: ooOoO0o + oO0o % OoooooooOO
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 23 - 23: oO0o . OoOoOO00 + iIii1I11I1II1
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 17 - 17: IiII
    if 12 - 12: i1IIi . OoO0O00
    if 14 - 14: OOooOOo + II111iiii % OOooOOo . oO0o * ooOoO0o
  IIii1i = struct . pack ( "I" , socket . htonl ( ooo0OOoo ) )
  IIii1i += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 54 - 54: ooOoO0o * I11i - I1Ii111
  IIii1i = self . zero_auth ( IIii1i )
  return ( IIii1i )
  if 15 - 15: iII111i / O0
  if 61 - 61: i1IIi / i1IIi + ooOoO0o . I1Ii111 * ooOoO0o
 def zero_auth ( self , packet ) :
  OoO00oo00 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  iIi11i = ""
  IIII1II11Iii = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   iIi11i = struct . pack ( "QQI" , 0 , 0 , 0 )
   IIII1II11Iii = struct . calcsize ( "QQI" )
   if 46 - 46: Ii1I * Ii1I / oO0o * I1Ii111
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   iIi11i = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   IIII1II11Iii = struct . calcsize ( "QQQQ" )
   if 37 - 37: OoOoOO00 + IiII
  packet = packet [ 0 : OoO00oo00 ] + iIi11i + packet [ OoO00oo00 + IIII1II11Iii : : ]
  return ( packet )
  if 40 - 40: o0oOOo0O0Ooo - O0 * II111iiii / I1IiiI . o0oOOo0O0Ooo + I1Ii111
  if 58 - 58: I1Ii111 * O0 / Ii1I + I1IiiI - I1ii11iIi11i * Oo0Ooo
 def encode_auth ( self , packet ) :
  OoO00oo00 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  IIII1II11Iii = self . auth_len
  iIi11i = self . auth_data
  packet = packet [ 0 : OoO00oo00 ] + iIi11i + packet [ OoO00oo00 + IIII1II11Iii : : ]
  return ( packet )
  if 85 - 85: i1IIi * OoOoOO00
  if 99 - 99: Oo0Ooo
 def decode ( self , packet ) :
  OO0o0 = packet
  O00oO00oOO00O = "I"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( [ None , None ] )
  if 96 - 96: i1IIi - I1Ii111 * I1IiiI % I1IiiI
  ooo0OOoo = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  ooo0OOoo = socket . ntohl ( ooo0OOoo [ 0 ] )
  packet = packet [ ooOoooOoo0oO : : ]
  if 31 - 31: I1ii11iIi11i . Ii1I / ooOoO0o / i11iIiiIii % o0oOOo0O0Ooo
  O00oO00oOO00O = "QBBH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( [ None , None ] )
  if 69 - 69: I1Ii111
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 83 - 83: iIii1I11I1II1 . o0oOOo0O0Ooo + I1Ii111 . OoooooooOO / ooOoO0o + II111iiii
  if 90 - 90: Ii1I * iII111i / OOooOOo
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( ooo0OOoo & 0x08000000 ) else False
  if 68 - 68: OoOoOO00
  self . lisp_sec_present = True if ( ooo0OOoo & 0x04000000 ) else False
  self . xtr_id_present = True if ( ooo0OOoo & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( ooo0OOoo & 0x800 ) else False
  self . map_register_refresh = True if ( ooo0OOoo & 0x1000 ) else False
  self . merge_register_requested = True if ( ooo0OOoo & 0x400 ) else False
  self . mobile_node = True if ( ooo0OOoo & 0x200 ) else False
  self . map_notify_requested = True if ( ooo0OOoo & 0x100 ) else False
  self . record_count = ooo0OOoo & 0xff
  if 65 - 65: oO0o
  if 82 - 82: o0oOOo0O0Ooo
  if 80 - 80: i1IIi % OoOoOO00 + OoO0O00 - OoooooooOO / iIii1I11I1II1 + I1Ii111
  if 65 - 65: Ii1I
  self . encrypt_bit = True if ooo0OOoo & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( ooo0OOoo >> 14 ) & 0x7
   if 71 - 71: I1Ii111 % I1Ii111 . oO0o + i11iIiiIii - i11iIiiIii
   if 16 - 16: iIii1I11I1II1 / I1IiiI / I1Ii111 - i11iIiiIii . ooOoO0o / OOooOOo
   if 13 - 13: o0oOOo0O0Ooo % O0 - I1Ii111 * OoooooooOO / Oo0Ooo - OoooooooOO
   if 78 - 78: oO0o % OoooooooOO
   if 73 - 73: I1IiiI % ooOoO0o % IiII + i1IIi - OoooooooOO / oO0o
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( OO0o0 ) == False ) : return ( [ None , None ] )
   if 78 - 78: OoooooooOO % oO0o - i11iIiiIii
   if 37 - 37: IiII % Ii1I % i1IIi
  packet = packet [ ooOoooOoo0oO : : ]
  if 23 - 23: ooOoO0o - O0 + i11iIiiIii
  if 98 - 98: OoooooooOO
  if 61 - 61: o0oOOo0O0Ooo . IiII . O0 + OoooooooOO + O0
  if 65 - 65: i1IIi * OOooOOo * OoooooooOO - IiII . iII111i - OoO0O00
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 71 - 71: Ii1I * OoOoOO00
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 33 - 33: i1IIi . i1IIi * OoooooooOO % I1Ii111 * o0oOOo0O0Ooo
    if 64 - 64: ooOoO0o / ooOoO0o + I1ii11iIi11i * OOooOOo % OOooOOo
   IIII1II11Iii = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    ooOoooOoo0oO = struct . calcsize ( "QQI" )
    if ( IIII1II11Iii < ooOoooOoo0oO ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 87 - 87: OoO0O00 * Oo0Ooo
    OoO0o00O0oOOo , ooO , I1IiiIiIIi1Ii = struct . unpack ( "QQI" , packet [ : IIII1II11Iii ] )
    oo00oo = ""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    ooOoooOoo0oO = struct . calcsize ( "QQQQ" )
    if ( IIII1II11Iii < ooOoooOoo0oO ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 57 - 57: OOooOOo * OoO0O00 + O0 % I1Ii111 - I1IiiI
    OoO0o00O0oOOo , ooO , I1IiiIiIIi1Ii , oo00oo = struct . unpack ( "QQQQ" ,
 packet [ : IIII1II11Iii ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 43 - 43: I1Ii111
    return ( [ None , None ] )
    if 10 - 10: i1IIi - o0oOOo0O0Ooo / OoooooooOO + i11iIiiIii + iIii1I11I1II1
   self . auth_data = lisp_concat_auth_data ( self . alg_id , OoO0o00O0oOOo , ooO ,
 I1IiiIiIIi1Ii , oo00oo )
   OO0o0 = self . zero_auth ( OO0o0 )
   packet = packet [ self . auth_len : : ]
   if 26 - 26: i11iIiiIii . OOooOOo - O0
  return ( [ OO0o0 , packet ] )
  if 73 - 73: I1IiiI
  if 95 - 95: OoO0O00 % OoO0O00 * oO0o - OoO0O00
 def encode_xtr_id ( self , packet ) :
  OoOO = self . xtr_id >> 64
  IiI1i111III = self . xtr_id & 0xffffffffffffffff
  OoOO = byte_swap_64 ( OoOO )
  IiI1i111III = byte_swap_64 ( IiI1i111III )
  I1111iii1ii11 = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , OoOO , IiI1i111III , I1111iii1ii11 )
  return ( packet )
  if 79 - 79: iIii1I11I1II1 / iIii1I11I1II1 . iII111i . Ii1I
  if 49 - 49: I1ii11iIi11i * I1Ii111 + OoOoOO00
 def decode_xtr_id ( self , packet ) :
  ooOoooOoo0oO = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - ooOoooOoo0oO : : ]
  OoOO , IiI1i111III , I1111iii1ii11 = struct . unpack ( "QQQ" ,
 packet [ : ooOoooOoo0oO ] )
  OoOO = byte_swap_64 ( OoOO )
  IiI1i111III = byte_swap_64 ( IiI1i111III )
  self . xtr_id = ( OoOO << 64 ) | IiI1i111III
  self . site_id = byte_swap_64 ( I1111iii1ii11 )
  return ( True )
  if 72 - 72: OoO0O00
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
  if 80 - 80: I1Ii111 % OoOoOO00 . OoooooooOO . II111iiii % IiII
  if 6 - 6: I1Ii111 % IiII / Ii1I + I1Ii111 . oO0o
 def print_notify ( self ) :
  iIi11i = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( iIi11i ) != 40 ) :
   iIi11i = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( iIi11i ) != 64 ) :
   iIi11i = self . auth_data
   if 70 - 70: iIii1I11I1II1 / Ii1I
  oOOo0ooO0 = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( oOOo0ooO0 . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # I1Ii111 * Oo0Ooo . o0oOOo0O0Ooo - I1Ii111
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , iIi11i ) )
  if 16 - 16: I1IiiI - O0 * I1ii11iIi11i . I1ii11iIi11i % OOooOOo
  if 39 - 39: II111iiii / I11i - OoOoOO00 * OoOoOO00 - Ii1I
  if 8 - 8: O0 . i11iIiiIii
  if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   iIi11i = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   iIi11i = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
  packet += iIi11i
  return ( packet )
  if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
  if 69 - 69: Oo0Ooo * ooOoO0o
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   ooo0OOoo = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   ooo0OOoo = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
  IIii1i = struct . pack ( "I" , socket . htonl ( ooo0OOoo ) )
  IIii1i += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 52 - 52: I1IiiI - i11iIiiIii / IiII . oO0o
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = IIii1i + eid_records
   return ( self . packet )
   if 38 - 38: oO0o + OoooooooOO * OoOoOO00 % oO0o
   if 91 - 91: i1IIi - I1ii11iIi11i * I1IiiI
   if 24 - 24: OoOoOO00 * Ii1I
   if 17 - 17: OoO0O00 . I1IiiI * O0
   if 81 - 81: OOooOOo
  IIii1i = self . zero_auth ( IIii1i )
  IIii1i += eid_records
  if 58 - 58: II111iiii . I1Ii111 . Ii1I * OoooooooOO / Ii1I / I11i
  I1I = lisp_hash_me ( IIii1i , self . alg_id , password , False )
  if 41 - 41: I11i + OoO0O00 . iII111i
  OoO00oo00 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  IIII1II11Iii = self . auth_len
  self . auth_data = I1I
  IIii1i = IIii1i [ 0 : OoO00oo00 ] + I1I + IIii1i [ OoO00oo00 + IIII1II11Iii : : ]
  self . packet = IIii1i
  return ( IIii1i )
  if 73 - 73: i11iIiiIii * I1IiiI + o0oOOo0O0Ooo / oO0o
  if 56 - 56: i1IIi
 def decode ( self , packet ) :
  OO0o0 = packet
  O00oO00oOO00O = "I"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 11 - 11: i11iIiiIii % o0oOOo0O0Ooo / I11i * OoooooooOO
  ooo0OOoo = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  ooo0OOoo = socket . ntohl ( ooo0OOoo [ 0 ] )
  self . map_notify_ack = ( ( ooo0OOoo >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = ooo0OOoo & 0xff
  packet = packet [ ooOoooOoo0oO : : ]
  if 82 - 82: IiII
  O00oO00oOO00O = "QBBH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 10 - 10: Oo0Ooo % OOooOOo / I11i * IiII - o0oOOo0O0Ooo
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 54 - 54: i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i / I1IiiI . iIii1I11I1II1 / iII111i
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ ooOoooOoo0oO : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 1 - 1: I1Ii111 / OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % Ii1I
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 96 - 96: IiII / Ii1I % OoO0O00 . iIii1I11I1II1
  if 30 - 30: I11i - OoO0O00
  if 15 - 15: OoooooooOO
  if 31 - 31: II111iiii
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
  IIII1II11Iii = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   OoO0o00O0oOOo , ooO , I1IiiIiIIi1Ii = struct . unpack ( "QQI" , packet [ : IIII1II11Iii ] )
   oo00oo = ""
   if 87 - 87: IiII
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   OoO0o00O0oOOo , ooO , I1IiiIiIIi1Ii , oo00oo = struct . unpack ( "QQQQ" ,
 packet [ : IIII1II11Iii ] )
   if 45 - 45: oO0o + II111iiii * O0 % OOooOOo . iIii1I11I1II1
  self . auth_data = lisp_concat_auth_data ( self . alg_id , OoO0o00O0oOOo , ooO ,
 I1IiiIiIIi1Ii , oo00oo )
  if 55 - 55: IiII
  ooOoooOoo0oO = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( OO0o0 [ : ooOoooOoo0oO ] )
  ooOoooOoo0oO += IIII1II11Iii
  packet += OO0o0 [ ooOoooOoo0oO : : ]
  return ( packet )
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
  if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
  if 23 - 23: i1IIi
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 9 - 9: i1IIi % I1Ii111 - OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 18 - 18: Ii1I . OoOoOO00 + iII111i . I1IiiI + OoooooooOO . OoO0O00
  if 31 - 31: I1Ii111 - I11i
 def print_map_request ( self ) :
  oooOOOO0oOo = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   oooOOOO0oOo = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 49 - 49: iIii1I11I1II1 - iIii1I11I1II1 - OoOoOO00 + IiII / OoOoOO00
   if 74 - 74: OoooooooOO + I1ii11iIi11i % O0
   if 32 - 32: I1ii11iIi11i + I1ii11iIi11i
  oOOo0ooO0 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 89 - 89: ooOoO0o + oO0o + Ii1I - OOooOOo
  lprint ( oOOo0ooO0 . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # o0oOOo0O0Ooo
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , oooOOOO0oOo ) )
  if 56 - 56: o0oOOo0O0Ooo - I1Ii111 / I11i
  oOoo0oO = self . keys
  for III1iii1 in self . itr_rlocs :
   lprint ( "  itr-rloc: afi {} {}{}" . format ( III1iii1 . afi ,
 red ( III1iii1 . print_address_no_iid ( ) , False ) ,
 "" if ( oOoo0oO == None ) else ", " + oOoo0oO [ 1 ] . print_keys ( ) ) )
   oOoo0oO = None
   if 78 - 78: I1Ii111 % OOooOOo
   if 73 - 73: I1ii11iIi11i + iII111i * I1IiiI * I11i
   if 35 - 35: I11i * O0 * OoO0O00 . I1ii11iIi11i
 def sign_map_request ( self , privkey ) :
  O000oOO0Oooo = self . signature_eid . print_address ( )
  o0000oO0OOOo0 = self . source_eid . print_address ( )
  o00ooo0O = self . target_eid . print_address ( )
  oO0o0O00O00O = lisp_hex_string ( self . nonce ) + o0000oO0OOOo0 + o00ooo0O
  self . map_request_signature = privkey . sign ( oO0o0O00O00O )
  o00 = binascii . b2a_base64 ( self . map_request_signature )
  o00 = { "source-eid" : o0000oO0OOOo0 , "signature-eid" : O000oOO0Oooo ,
 "signature" : o00 }
  return ( json . dumps ( o00 ) )
  if 59 - 59: O0 % iII111i
  if 32 - 32: Ii1I % I11i + OOooOOo % OoooooooOO
 def verify_map_request_sig ( self , pubkey ) :
  oooOo0O00o = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( oooOo0O00o ) )
   return ( False )
   if 65 - 65: I11i . i11iIiiIii
   if 6 - 6: Ii1I % I11i * I1IiiI . IiII
  o0000oO0OOOo0 = self . source_eid . print_address ( )
  o00ooo0O = self . target_eid . print_address ( )
  oO0o0O00O00O = lisp_hex_string ( self . nonce ) + o0000oO0OOOo0 + o00ooo0O
  pubkey = binascii . a2b_base64 ( pubkey )
  if 30 - 30: O0 / OOooOOo + OoOoOO00 % OoO0O00 + I1Ii111
  IIIiiI1I = True
  try :
   ii1i1I1111ii = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 55 - 55: iII111i * Oo0Ooo + OoOoOO00 * OOooOOo / iII111i * i1IIi
   IIIiiI1I = False
   if 49 - 49: IiII + iIii1I11I1II1
   if 30 - 30: i11iIiiIii % o0oOOo0O0Ooo . i1IIi
  if ( IIIiiI1I ) :
   try :
    IIIiiI1I = ii1i1I1111ii . verify ( self . map_request_signature , oO0o0O00O00O )
   except :
    IIIiiI1I = False
    if 49 - 49: o0oOOo0O0Ooo * Ii1I + Oo0Ooo
    if 1 - 1: o0oOOo0O0Ooo / II111iiii + I11i . i11iIiiIii + ooOoO0o . OoOoOO00
    if 95 - 95: o0oOOo0O0Ooo / I1Ii111 % II111iiii + ooOoO0o
  oOo0ooOO0O = bold ( "passed" if IIIiiI1I else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( oOo0ooOO0O , oooOo0O00o ) )
  return ( IIIiiI1I )
  if 11 - 11: OoOoOO00 % I1ii11iIi11i - Ii1I - I1Ii111
  if 58 - 58: OoOoOO00 . Ii1I / IiII * oO0o
 def encode ( self , probe_dest , probe_port ) :
  ooo0OOoo = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  ooo0OOoo = ooo0OOoo | ( self . itr_rloc_count << 8 )
  if ( self . auth_bit ) : ooo0OOoo |= 0x08000000
  if ( self . map_data_present ) : ooo0OOoo |= 0x04000000
  if ( self . rloc_probe ) : ooo0OOoo |= 0x02000000
  if ( self . smr_bit ) : ooo0OOoo |= 0x01000000
  if ( self . pitr_bit ) : ooo0OOoo |= 0x00800000
  if ( self . smr_invoked_bit ) : ooo0OOoo |= 0x00400000
  if ( self . mobile_node ) : ooo0OOoo |= 0x00200000
  if ( self . xtr_id_present ) : ooo0OOoo |= 0x00100000
  if ( self . local_xtr ) : ooo0OOoo |= 0x00004000
  if ( self . dont_reply_bit ) : ooo0OOoo |= 0x00002000
  if 70 - 70: OoooooooOO
  IIii1i = struct . pack ( "I" , socket . htonl ( ooo0OOoo ) )
  IIii1i += struct . pack ( "Q" , self . nonce )
  if 51 - 51: oO0o / II111iiii + ooOoO0o / I11i . iII111i
  if 77 - 77: iIii1I11I1II1 * OoOoOO00 + i11iIiiIii * ooOoO0o
  if 81 - 81: Ii1I * iII111i % Ii1I % i11iIiiIii % i1IIi / o0oOOo0O0Ooo
  if 53 - 53: OoOoOO00
  if 55 - 55: ooOoO0o % i1IIi / OoO0O00
  if 77 - 77: O0 % oO0o % oO0o
  I111 = False
  iii = self . privkey_filename
  if ( iii != None and os . path . exists ( iii ) ) :
   ii11I1IIi = open ( iii , "r" ) ; ii1i1I1111ii = ii11I1IIi . read ( ) ; ii11I1IIi . close ( )
   try :
    ii1i1I1111ii = ecdsa . SigningKey . from_pem ( ii1i1I1111ii )
   except :
    return ( None )
    if 76 - 76: O0
   OoOoO00OoOOo = self . sign_map_request ( ii1i1I1111ii )
   I111 = True
  elif ( self . map_request_signature != None ) :
   o00 = binascii . b2a_base64 ( self . map_request_signature )
   OoOoO00OoOOo = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : o00 }
   OoOoO00OoOOo = json . dumps ( OoOoO00OoOOo )
   I111 = True
   if 64 - 64: Ii1I
  if ( I111 ) :
   O000oo0O0OO0 = LISP_LCAF_JSON_TYPE
   o0O000Ooo = socket . htons ( LISP_AFI_LCAF )
   iiii1 = socket . htons ( len ( OoOoO00OoOOo ) + 2 )
   oo0ooOO = socket . htons ( len ( OoOoO00OoOOo ) )
   IIii1i += struct . pack ( "HBBBBHH" , o0O000Ooo , 0 , 0 , O000oo0O0OO0 , 0 ,
 iiii1 , oo0ooOO )
   IIii1i += OoOoO00OoOOo
   IIii1i += struct . pack ( "H" , 0 )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    IIii1i += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    IIii1i += self . source_eid . lcaf_encode_iid ( )
   else :
    IIii1i += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    IIii1i += self . source_eid . pack_address ( )
    if 69 - 69: iIii1I11I1II1 + Oo0Ooo
    if 70 - 70: OoooooooOO * i11iIiiIii
    if 60 - 60: IiII / iIii1I11I1II1 + OoooooooOO - I1ii11iIi11i * i11iIiiIii
    if 47 - 47: O0 . I1IiiI / ooOoO0o % i11iIiiIii
    if 47 - 47: Ii1I . OoOoOO00 . iIii1I11I1II1 . o0oOOo0O0Ooo
    if 39 - 39: o0oOOo0O0Ooo
    if 89 - 89: OoooooooOO + iII111i . I1Ii111 / Ii1I
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   oo0o00OO = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 75 - 75: iIii1I11I1II1 * iII111i / OoOoOO00 * II111iiii . i1IIi
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( oo0o00OO ) ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ]
    if 6 - 6: Ii1I % Ii1I / OoooooooOO * oO0o . I1IiiI . i1IIi
    if 59 - 59: I11i . I11i * I1IiiI - Ii1I % OoOoOO00
    if 19 - 19: OoooooooOO / Oo0Ooo - I1Ii111 . OoOoOO00
    if 8 - 8: I11i % ooOoO0o . iIii1I11I1II1
    if 95 - 95: o0oOOo0O0Ooo + i11iIiiIii . I1ii11iIi11i . ooOoO0o . o0oOOo0O0Ooo
    if 93 - 93: iII111i
    if 55 - 55: II111iiii % o0oOOo0O0Ooo - OoO0O00
  for III1iii1 in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( III1iii1 ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     oOoo0oO = lisp_keys ( 1 )
     self . keys = [ None , oOoo0oO , None , None ]
     if 48 - 48: ooOoO0o * iIii1I11I1II1 % OoOoOO00
    oOoo0oO = self . keys [ 1 ]
    oOoo0oO . add_key_by_nonce ( self . nonce )
    IIii1i += oOoo0oO . encode_lcaf ( III1iii1 )
   else :
    IIii1i += struct . pack ( "H" , socket . htons ( III1iii1 . afi ) )
    IIii1i += III1iii1 . pack_address ( )
    if 100 - 100: II111iiii - i11iIiiIii + OoO0O00 % ooOoO0o - iIii1I11I1II1 * i11iIiiIii
    if 30 - 30: OoO0O00 . OoO0O00 . Ii1I % Ii1I * i1IIi * oO0o
    if 74 - 74: OoooooooOO
  iIi1iii1 = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 42 - 42: I11i / i11iIiiIii
  if 7 - 7: I11i
  Ii1 = 0
  if ( self . subscribe_bit ) :
   Ii1 = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 1 - 1: O0 / i11iIiiIii
    if 52 - 52: I11i / OoO0O00
    if 24 - 24: i11iIiiIii
  O00oO00oOO00O = "BB"
  IIii1i += struct . pack ( O00oO00oOO00O , Ii1 , iIi1iii1 )
  if 52 - 52: ooOoO0o % iIii1I11I1II1 . i11iIiiIii % ooOoO0o
  if ( self . target_group . is_null ( ) == False ) :
   IIii1i += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   IIii1i += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   IIii1i += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   IIii1i += self . target_eid . lcaf_encode_iid ( )
  else :
   IIii1i += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   IIii1i += self . target_eid . pack_address ( )
   if 86 - 86: oO0o % iIii1I11I1II1 % OoOoOO00
   if 94 - 94: o0oOOo0O0Ooo - I11i % oO0o % o0oOOo0O0Ooo + I11i
   if 31 - 31: I1Ii111 * o0oOOo0O0Ooo * II111iiii + O0 / iII111i * ooOoO0o
   if 52 - 52: iIii1I11I1II1 / iII111i . O0 * IiII . I1IiiI
   if 67 - 67: II111iiii + Ii1I - I1IiiI * ooOoO0o
  if ( self . subscribe_bit ) : IIii1i = self . encode_xtr_id ( IIii1i )
  return ( IIii1i )
  if 19 - 19: i11iIiiIii * Oo0Ooo
  if 33 - 33: i11iIiiIii + I1IiiI
 def lcaf_decode_json ( self , packet ) :
  O00oO00oOO00O = "BBBBHH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 95 - 95: I1ii11iIi11i / IiII % iIii1I11I1II1 + O0
  i111IiI1III1 , ooOOooooo0Oo , O000oo0O0OO0 , I1iii1IiI11I11I , iiii1 , oo0ooOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 2 - 2: iIii1I11I1II1 * OoOoOO00 . O0 / OoO0O00
  if 3 - 3: I1ii11iIi11i
  if ( O000oo0O0OO0 != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 53 - 53: I11i . OoooooooOO % ooOoO0o
  if 13 - 13: OoO0O00 * iIii1I11I1II1 + II111iiii - Oo0Ooo - OoOoOO00
  if 43 - 43: iII111i / I1Ii111 * I1IiiI % ooOoO0o % I1IiiI
  if 18 - 18: OoO0O00
  iiii1 = socket . ntohs ( iiii1 )
  oo0ooOO = socket . ntohs ( oo0ooOO )
  packet = packet [ ooOoooOoo0oO : : ]
  if ( len ( packet ) < iiii1 ) : return ( None )
  if ( iiii1 != oo0ooOO + 2 ) : return ( None )
  if 99 - 99: iII111i / oO0o . i11iIiiIii / I11i + i1IIi - I11i
  if 50 - 50: i1IIi
  if 56 - 56: OoO0O00 + I1Ii111 / Ii1I
  if 75 - 75: OoOoOO00
  try :
   OoOoO00OoOOo = json . loads ( packet [ 0 : oo0ooOO ] )
  except :
   return ( None )
   if 96 - 96: o0oOOo0O0Ooo * I11i * Oo0Ooo
  packet = packet [ oo0ooOO : : ]
  if 36 - 36: OoooooooOO + ooOoO0o . oO0o * ooOoO0o + IiII
  if 45 - 45: oO0o / iII111i + I1ii11iIi11i - Oo0Ooo - ooOoO0o . iIii1I11I1II1
  if 52 - 52: I1IiiI + i1IIi . iII111i * I1IiiI
  if 31 - 31: Oo0Ooo % iIii1I11I1II1 . O0
  O00oO00oOO00O = "H"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if ( O000oOOoOOO != 0 ) : return ( packet )
  if 80 - 80: I11i / Oo0Ooo + I1ii11iIi11i
  if 18 - 18: II111iiii - iII111i / iIii1I11I1II1 % OoOoOO00 % I1ii11iIi11i / o0oOOo0O0Ooo
  if 47 - 47: OOooOOo
  if 24 - 24: Ii1I % o0oOOo0O0Ooo
  if ( OoOoO00OoOOo . has_key ( "source-eid" ) == False ) : return ( packet )
  OOo0O0O0o0 = OoOoO00OoOOo [ "source-eid" ]
  O000oOOoOOO = LISP_AFI_IPV4 if OOo0O0O0o0 . count ( "." ) == 3 else LISP_AFI_IPV6 if OOo0O0O0o0 . count ( ":" ) == 7 else None
  if 82 - 82: OoooooooOO / I1IiiI * II111iiii - OoooooooOO % iIii1I11I1II1 * OoO0O00
  if ( O000oOOoOOO == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( OOo0O0O0o0 ) )
   return ( None )
   if 32 - 32: i11iIiiIii - OoOoOO00 * I11i . Oo0Ooo * ooOoO0o
   if 21 - 21: OOooOOo
  self . source_eid . afi = O000oOOoOOO
  self . source_eid . store_address ( OOo0O0O0o0 )
  if 11 - 11: oO0o % i11iIiiIii * O0
  if ( OoOoO00OoOOo . has_key ( "signature-eid" ) == False ) : return ( packet )
  OOo0O0O0o0 = OoOoO00OoOOo [ "signature-eid" ]
  if ( OOo0O0O0o0 . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( OOo0O0O0o0 ) )
   return ( None )
   if 28 - 28: I1Ii111 / iIii1I11I1II1 + OOooOOo . I1ii11iIi11i % OOooOOo + OoO0O00
   if 79 - 79: oO0o
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( OOo0O0O0o0 )
  if 39 - 39: I1Ii111 % oO0o % O0 % O0 - iII111i - oO0o
  if ( OoOoO00OoOOo . has_key ( "signature" ) == False ) : return ( packet )
  o00 = binascii . a2b_base64 ( OoOoO00OoOOo [ "signature" ] )
  self . map_request_signature = o00
  return ( packet )
  if 83 - 83: i11iIiiIii + iIii1I11I1II1
  if 21 - 21: o0oOOo0O0Ooo / i11iIiiIii % I1Ii111
 def decode ( self , packet , source , port ) :
  O00oO00oOO00O = "I"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 56 - 56: o0oOOo0O0Ooo * iIii1I11I1II1 . Ii1I + OoOoOO00 % I1Ii111
  ooo0OOoo = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  ooo0OOoo = ooo0OOoo [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if 11 - 11: OOooOOo
  O00oO00oOO00O = "Q"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 12 - 12: OoooooooOO * OOooOOo * I1ii11iIi11i * ooOoO0o
  oOO000 = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  packet = packet [ ooOoooOoo0oO : : ]
  if 26 - 26: OoooooooOO . i1IIi + OoO0O00
  ooo0OOoo = socket . ntohl ( ooo0OOoo )
  self . auth_bit = True if ( ooo0OOoo & 0x08000000 ) else False
  self . map_data_present = True if ( ooo0OOoo & 0x04000000 ) else False
  self . rloc_probe = True if ( ooo0OOoo & 0x02000000 ) else False
  self . smr_bit = True if ( ooo0OOoo & 0x01000000 ) else False
  self . pitr_bit = True if ( ooo0OOoo & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( ooo0OOoo & 0x00400000 ) else False
  self . mobile_node = True if ( ooo0OOoo & 0x00200000 ) else False
  self . xtr_id_present = True if ( ooo0OOoo & 0x00100000 ) else False
  self . local_xtr = True if ( ooo0OOoo & 0x00004000 ) else False
  self . dont_reply_bit = True if ( ooo0OOoo & 0x00002000 ) else False
  self . itr_rloc_count = ( ( ooo0OOoo >> 8 ) & 0x1f ) + 1
  self . record_count = ooo0OOoo & 0xff
  self . nonce = oOO000 [ 0 ]
  if 42 - 42: i11iIiiIii * o0oOOo0O0Ooo % I11i % Oo0Ooo + o0oOOo0O0Ooo * i11iIiiIii
  if 66 - 66: Ii1I / IiII . OoooooooOO * Oo0Ooo % i11iIiiIii
  if 100 - 100: I1ii11iIi11i % II111iiii * i11iIiiIii - iII111i
  if 69 - 69: OOooOOo + iII111i / I1Ii111
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 37 - 37: iIii1I11I1II1 * I11i / IiII * Oo0Ooo % i11iIiiIii
   if 93 - 93: ooOoO0o + ooOoO0o
  ooOoooOoo0oO = struct . calcsize ( "H" )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 65 - 65: OoooooooOO * I11i * oO0o % I1ii11iIi11i * II111iiii
  O000oOOoOOO = struct . unpack ( "H" , packet [ : ooOoooOoo0oO ] )
  self . source_eid . afi = socket . ntohs ( O000oOOoOOO [ 0 ] )
  packet = packet [ ooOoooOoo0oO : : ]
  if 86 - 86: i11iIiiIii / I11i * iII111i - iII111i
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   iIiiIIi1i111iI = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( iIiiIIi1i111iI )
    if ( packet == None ) : return ( None )
    if 10 - 10: IiII % II111iiii
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 50 - 50: OoOoOO00 * iII111i
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 59 - 59: I1IiiI * I1IiiI / I11i
  ooOO0oO0 = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  while ( self . itr_rloc_count != 0 ) :
   ooOoooOoo0oO = struct . calcsize ( "H" )
   if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
   if 50 - 50: Oo0Ooo
   O000oOOoOOO = struct . unpack ( "H" , packet [ : ooOoooOoo0oO ] ) [ 0 ]
   if 16 - 16: Ii1I - OoOoOO00 % Oo0Ooo / Ii1I . I11i + ooOoO0o
   III1iii1 = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   III1iii1 . afi = socket . ntohs ( O000oOOoOOO )
   if 78 - 78: iIii1I11I1II1 + OoO0O00 + i11iIiiIii
   if 21 - 21: Oo0Ooo + Ii1I % ooOoO0o + OoOoOO00 % I11i
   if 22 - 22: i1IIi / OoooooooOO . OoO0O00
   if 83 - 83: I1IiiI - OoooooooOO + I1ii11iIi11i . Ii1I / o0oOOo0O0Ooo + ooOoO0o
   if 90 - 90: I1IiiI - i11iIiiIii
   if ( III1iii1 . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < III1iii1 . addr_length ( ) ) : return ( None )
    packet = III1iii1 . unpack_address ( packet [ ooOoooOoo0oO : : ] )
    if ( packet == None ) : return ( None )
    if 42 - 42: OOooOOo . Oo0Ooo
    if ( ooOO0oO0 ) :
     self . itr_rlocs . append ( III1iii1 )
     self . itr_rloc_count -= 1
     continue
     if 21 - 21: iII111i . I1IiiI / I11i
     if 97 - 97: iIii1I11I1II1 + i1IIi - o0oOOo0O0Ooo
    oo0o00OO = lisp_build_crypto_decap_lookup_key ( III1iii1 , port )
    if 73 - 73: OoO0O00 - i11iIiiIii % I1Ii111 / Oo0Ooo - OoooooooOO % OOooOOo
    if 79 - 79: I1IiiI / o0oOOo0O0Ooo . Ii1I * I1ii11iIi11i + I11i
    if 96 - 96: OoO0O00 * II111iiii
    if 1 - 1: I1IiiI - OoOoOO00
    if 74 - 74: OoOoOO00 * II111iiii + O0 + I11i
    if ( lisp_nat_traversal and III1iii1 . is_private_address ( ) and source ) : III1iii1 = source
    if 3 - 3: iIii1I11I1II1 - i1IIi / iII111i + i1IIi + O0
    Ii1OOO0oo0o0 = lisp_crypto_keys_by_rloc_decap
    if ( Ii1OOO0oo0o0 . has_key ( oo0o00OO ) ) : Ii1OOO0oo0o0 . pop ( oo0o00OO )
    if 38 - 38: OoO0O00 * I1ii11iIi11i
    if 4 - 4: OoO0O00 . I1ii11iIi11i
    if 21 - 21: i11iIiiIii / OoO0O00 / I1ii11iIi11i * O0 - II111iiii * OOooOOo
    if 27 - 27: o0oOOo0O0Ooo . OoOoOO00 * Ii1I * iII111i * O0
    if 93 - 93: IiII % I1Ii111 % II111iiii
    if 20 - 20: OoooooooOO * I1Ii111
    lisp_write_ipc_decap_key ( oo0o00OO , None )
   else :
    OO0o0 = packet
    i1ii1iiI11ii1II1 = lisp_keys ( 1 )
    packet = i1ii1iiI11ii1II1 . decode_lcaf ( OO0o0 , 0 )
    if ( packet == None ) : return ( None )
    if 33 - 33: oO0o / I11i . OoOoOO00 * O0 - IiII
    if 12 - 12: i11iIiiIii + I1ii11iIi11i * OoO0O00
    if 13 - 13: Oo0Ooo + OoooooooOO / IiII
    if 56 - 56: I1ii11iIi11i * II111iiii
    Iii = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( i1ii1iiI11ii1II1 . cipher_suite in Iii ) :
     if ( i1ii1iiI11ii1II1 . cipher_suite == LISP_CS_25519_CBC or
 i1ii1iiI11ii1II1 . cipher_suite == LISP_CS_25519_GCM ) :
      ii1i1I1111ii = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 75 - 75: I11i . o0oOOo0O0Ooo - i11iIiiIii / I11i
     if ( i1ii1iiI11ii1II1 . cipher_suite == LISP_CS_25519_CHACHA ) :
      ii1i1I1111ii = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 100 - 100: i11iIiiIii * i11iIiiIii . iIii1I11I1II1 % iII111i * I1ii11iIi11i
    else :
     ii1i1I1111ii = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 17 - 17: Ii1I * IiII * i11iIiiIii / I1ii11iIi11i / i11iIiiIii
    packet = ii1i1I1111ii . decode_lcaf ( OO0o0 , 0 )
    if ( packet == None ) : return ( None )
    if 23 - 23: OoooooooOO + i11iIiiIii / Oo0Ooo / iII111i . iII111i * I1IiiI
    if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
    O000oOOoOOO = struct . unpack ( "H" , packet [ : ooOoooOoo0oO ] ) [ 0 ]
    III1iii1 . afi = socket . ntohs ( O000oOOoOOO )
    if ( len ( packet ) < III1iii1 . addr_length ( ) ) : return ( None )
    if 98 - 98: IiII
    packet = III1iii1 . unpack_address ( packet [ ooOoooOoo0oO : : ] )
    if ( packet == None ) : return ( None )
    if 23 - 23: I11i / i1IIi * OoO0O00
    if ( ooOO0oO0 ) :
     self . itr_rlocs . append ( III1iii1 )
     self . itr_rloc_count -= 1
     continue
     if 51 - 51: OOooOOo - OoooooooOO / OoooooooOO % OoooooooOO
     if 85 - 85: OoO0O00 . o0oOOo0O0Ooo . I1IiiI
    oo0o00OO = lisp_build_crypto_decap_lookup_key ( III1iii1 , port )
    if 75 - 75: iIii1I11I1II1 - Ii1I % O0 % IiII
    II1II1iiIiI = None
    if ( lisp_nat_traversal and III1iii1 . is_private_address ( ) and source ) : III1iii1 = source
    if 31 - 31: I1Ii111 . I1ii11iIi11i + IiII
    if 65 - 65: I1IiiI * O0 * Oo0Ooo . O0
    if ( lisp_crypto_keys_by_rloc_decap . has_key ( oo0o00OO ) ) :
     oOoo0oO = lisp_crypto_keys_by_rloc_decap [ oo0o00OO ]
     II1II1iiIiI = oOoo0oO [ 1 ] if oOoo0oO and oOoo0oO [ 1 ] else None
     if 23 - 23: OoO0O00 / IiII * II111iiii
     if 32 - 32: I1Ii111 - iIii1I11I1II1 / I11i * OoO0O00 * OoO0O00
    oo0Oo0oo = True
    if ( II1II1iiIiI ) :
     if ( II1II1iiIiI . compare_keys ( ii1i1I1111ii ) ) :
      self . keys = [ None , II1II1iiIiI , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( oo0o00OO , False ) ) )
      if 71 - 71: OOooOOo
     else :
      oo0Oo0oo = False
      oo0oO = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( oo0oO , red ( oo0o00OO ,
 False ) ) )
      ii1i1I1111ii . copy_keypair ( II1II1iiIiI )
      ii1i1I1111ii . uptime = II1II1iiIiI . uptime
      II1II1iiIiI = None
      if 11 - 11: o0oOOo0O0Ooo * OoO0O00
      if 92 - 92: OoOoOO00 . Oo0Ooo * I11i
      if 86 - 86: O0
    if ( II1II1iiIiI == None ) :
     self . keys = [ None , ii1i1I1111ii , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      ii1i1I1111ii . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( oo0o00OO , False ) ) )
     elif ( ii1i1I1111ii . remote_public_key != None ) :
      if ( oo0Oo0oo ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # II111iiii % I1IiiI % Ii1I * I1ii11iIi11i
 red ( oo0o00OO , False ) ) )
       if 74 - 74: o0oOOo0O0Ooo / OoO0O00 + iII111i - i1IIi / OoooooooOO / I1ii11iIi11i
      ii1i1I1111ii . compute_shared_key ( "decap" )
      ii1i1I1111ii . add_key_by_rloc ( oo0o00OO , False )
      if 56 - 56: oO0o + I1IiiI . I11i
      if 67 - 67: IiII / o0oOOo0O0Ooo + I11i % iII111i - ooOoO0o - I1IiiI
      if 44 - 44: Ii1I . o0oOOo0O0Ooo . iIii1I11I1II1 + OoooooooOO - I1IiiI
      if 22 - 22: I11i * I1ii11iIi11i . OoooooooOO / Oo0Ooo / Ii1I
   self . itr_rlocs . append ( III1iii1 )
   self . itr_rloc_count -= 1
   if 54 - 54: I1Ii111 % Ii1I + ooOoO0o
   if 45 - 45: Ii1I / oO0o * I1Ii111 . Ii1I
  ooOoooOoo0oO = struct . calcsize ( "BBH" )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 25 - 25: I1ii11iIi11i / I1ii11iIi11i
  Ii1 , iIi1iii1 , O000oOOoOOO = struct . unpack ( "BBH" , packet [ : ooOoooOoo0oO ] )
  self . subscribe_bit = ( Ii1 & 0x80 )
  self . target_eid . afi = socket . ntohs ( O000oOOoOOO )
  packet = packet [ ooOoooOoo0oO : : ]
  if 79 - 79: Oo0Ooo - OoO0O00 % Oo0Ooo . II111iiii
  self . target_eid . mask_len = iIi1iii1
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , o0Ooo0Oooo0o = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( o0Ooo0Oooo0o ) : self . target_group = o0Ooo0Oooo0o
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ ooOoooOoo0oO : : ]
   if 22 - 22: oO0o / II111iiii . OoOoOO00
  return ( packet )
  if 9 - 9: i11iIiiIii + ooOoO0o . iIii1I11I1II1 * OoOoOO00
  if 4 - 4: I1Ii111 + iII111i % O0
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 98 - 98: i1IIi + I1Ii111 - I1ii11iIi11i . OoooooooOO / O0 / iII111i
  if 66 - 66: i1IIi % OoooooooOO * i11iIiiIii + oO0o * O0 / OoO0O00
 def encode_xtr_id ( self , packet ) :
  OoOO = self . xtr_id >> 64
  IiI1i111III = self . xtr_id & 0xffffffffffffffff
  OoOO = byte_swap_64 ( OoOO )
  IiI1i111III = byte_swap_64 ( IiI1i111III )
  packet += struct . pack ( "QQ" , OoOO , IiI1i111III )
  return ( packet )
  if 14 - 14: I1IiiI . IiII
  if 29 - 29: OoooooooOO / IiII + OoOoOO00 - I1Ii111 + IiII . i1IIi
 def decode_xtr_id ( self , packet ) :
  ooOoooOoo0oO = struct . calcsize ( "QQ" )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  packet = packet [ len ( packet ) - ooOoooOoo0oO : : ]
  OoOO , IiI1i111III = struct . unpack ( "QQ" , packet [ : ooOoooOoo0oO ] )
  OoOO = byte_swap_64 ( OoOO )
  IiI1i111III = byte_swap_64 ( IiI1i111III )
  self . xtr_id = ( OoOO << 64 ) | IiI1i111III
  return ( True )
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
class lisp_map_reply ( ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 64 - 64: i1IIi / IiII . IiII - I1Ii111 % OOooOOo . II111iiii
  if 78 - 78: I1Ii111 - O0 - I1Ii111 . iIii1I11I1II1 % I1ii11iIi11i . OoooooooOO
 def print_map_reply ( self ) :
  oOOo0ooO0 = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 64 - 64: IiII
  lprint ( oOOo0ooO0 . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # o0oOOo0O0Ooo - o0oOOo0O0Ooo
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 90 - 90: OoooooooOO . OoooooooOO . I1ii11iIi11i * Ii1I - iII111i % I1IiiI
  if 95 - 95: iIii1I11I1II1 . I1ii11iIi11i - I1ii11iIi11i + oO0o
 def encode ( self ) :
  ooo0OOoo = ( LISP_MAP_REPLY << 28 ) | self . record_count
  ooo0OOoo |= self . hop_count << 8
  if ( self . rloc_probe ) : ooo0OOoo |= 0x08000000
  if ( self . echo_nonce_capable ) : ooo0OOoo |= 0x04000000
  if ( self . security ) : ooo0OOoo |= 0x02000000
  if 47 - 47: o0oOOo0O0Ooo . OoO0O00
  IIii1i = struct . pack ( "I" , socket . htonl ( ooo0OOoo ) )
  IIii1i += struct . pack ( "Q" , self . nonce )
  return ( IIii1i )
  if 60 - 60: I1ii11iIi11i
  if 90 - 90: OoOoOO00 / i11iIiiIii + iIii1I11I1II1 . oO0o . oO0o + iII111i
 def decode ( self , packet ) :
  O00oO00oOO00O = "I"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 100 - 100: IiII % i1IIi / iII111i
  ooo0OOoo = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  ooo0OOoo = ooo0OOoo [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if 39 - 39: I1IiiI - iII111i - i11iIiiIii + OoooooooOO
  O00oO00oOO00O = "Q"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 74 - 74: OOooOOo - II111iiii
  oOO000 = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  packet = packet [ ooOoooOoo0oO : : ]
  if 66 - 66: i11iIiiIii + I1Ii111 . ooOoO0o
  ooo0OOoo = socket . ntohl ( ooo0OOoo )
  self . rloc_probe = True if ( ooo0OOoo & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( ooo0OOoo & 0x04000000 ) else False
  self . security = True if ( ooo0OOoo & 0x02000000 ) else False
  self . hop_count = ( ooo0OOoo >> 8 ) & 0xff
  self . record_count = ooo0OOoo & 0xff
  self . nonce = oOO000 [ 0 ]
  if 46 - 46: I1Ii111 / I1ii11iIi11i
  if ( lisp_crypto_keys_by_nonce . has_key ( self . nonce ) ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 41 - 41: i1IIi % Ii1I + I1Ii111 . Oo0Ooo / iIii1I11I1II1
  return ( packet )
  if 77 - 77: Oo0Ooo . OoO0O00 % O0 - OoO0O00 - Oo0Ooo
  if 95 - 95: IiII * II111iiii % o0oOOo0O0Ooo * Oo0Ooo . I11i
  if 46 - 46: II111iiii - OoO0O00 % ooOoO0o
  if 97 - 97: OoO0O00 . OoOoOO00
  if 78 - 78: I1ii11iIi11i + I1ii11iIi11i . OoOoOO00 - IiII * iIii1I11I1II1 * O0
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
  if 2 - 2: i11iIiiIii % I1IiiI
  if 90 - 90: II111iiii
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 2 - 2: Ii1I - OoooooooOO - i11iIiiIii % Oo0Ooo / Ii1I
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 77 - 77: o0oOOo0O0Ooo . o0oOOo0O0Ooo * I1Ii111 + OOooOOo - i11iIiiIii
  if 45 - 45: I1IiiI . I1IiiI - Oo0Ooo * OOooOOo
 def print_ttl ( self ) :
  oo0o = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   oo0o = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( oo0o % 60 ) == 0 ) :
   oo0o = str ( oo0o / 60 ) + " hours"
  else :
   oo0o = str ( oo0o ) + " mins"
   if 6 - 6: II111iiii * IiII
  return ( oo0o )
  if 51 - 51: Ii1I . i11iIiiIii + oO0o % OoOoOO00
  if 97 - 97: OOooOOo . OOooOOo . iII111i . iII111i
 def store_ttl ( self ) :
  oo0o = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : oo0o = self . record_ttl & 0x7fffffff
  return ( oo0o )
  if 63 - 63: O0 * IiII / Oo0Ooo . I1IiiI . I1IiiI / i11iIiiIii
  if 17 - 17: iIii1I11I1II1 / OoO0O00 - II111iiii
 def print_record ( self , indent , ddt ) :
  IiiIIiIi1i11i = ""
  O00o0o00O0O = ""
  I1iIi1I1I1i = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    I1iIi1I1I1i = lisp_map_referral_action_string [ self . action ]
    I1iIi1I1I1i = bold ( I1iIi1I1I1i , False )
    IiiIIiIi1i11i = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 39 - 39: iIii1I11I1II1 / I1ii11iIi11i + i1IIi + OoO0O00 + I1IiiI
    O00o0o00O0O = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 82 - 82: Oo0Ooo . i11iIiiIii + i11iIiiIii
    if 74 - 74: oO0o . i11iIiiIii / iIii1I11I1II1 - I1ii11iIi11i * ooOoO0o - O0
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    I1iIi1I1I1i = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     I1iIi1I1I1i = bold ( I1iIi1I1I1i , False )
     if 75 - 75: iIii1I11I1II1 . I1IiiI - Ii1I % OoOoOO00
     if 38 - 38: i1IIi - oO0o . OoooooooOO
     if 40 - 40: I11i
     if 44 - 44: ooOoO0o
  O000oOOoOOO = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  oOOo0ooO0 = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 35 - 35: II111iiii + iII111i / I1ii11iIi11i * I1IiiI . I11i
  lprint ( oOOo0ooO0 . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 I1iIi1I1I1i , "auth" if ( self . authoritative is True ) else "non-auth" ,
 IiiIIiIi1i11i , O00o0o00O0O , self . map_version , O000oOOoOOO ,
 green ( self . print_prefix ( ) , False ) ) )
  if 97 - 97: I1IiiI / o0oOOo0O0Ooo
  if 13 - 13: I1ii11iIi11i
 def encode ( self ) :
  OOo000 = self . action << 13
  if ( self . authoritative ) : OOo000 |= 0x1000
  if ( self . ddt_incomplete ) : OOo000 |= 0x800
  if 40 - 40: I1ii11iIi11i * iIii1I11I1II1 % OoOoOO00
  if 50 - 50: i11iIiiIii + ooOoO0o
  if 41 - 41: I1IiiI * OoO0O00 + IiII / OoO0O00 . I1Ii111
  if 2 - 2: O0 % o0oOOo0O0Ooo
  O000oOOoOOO = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( O000oOOoOOO < 0 ) : O000oOOoOOO = LISP_AFI_LCAF
  iiI1 = ( self . group . is_null ( ) == False )
  if ( iiI1 ) : O000oOOoOOO = LISP_AFI_LCAF
  if 64 - 64: OoOoOO00
  iIiiii = ( self . signature_count << 12 ) | self . map_version
  iIi1iii1 = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 25 - 25: II111iiii + I11i
  IIii1i = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , iIi1iii1 , socket . htons ( OOo000 ) ,
 socket . htons ( iIiiii ) , socket . htons ( O000oOOoOOO ) )
  if 97 - 97: O0 + OOooOOo % OoOoOO00 * I11i . iIii1I11I1II1
  if 94 - 94: oO0o
  if 53 - 53: ooOoO0o + iII111i * i1IIi + I1IiiI
  if 89 - 89: I1IiiI / II111iiii - OoOoOO00 % o0oOOo0O0Ooo
  if ( iiI1 ) :
   IIii1i += self . eid . lcaf_encode_sg ( self . group )
   return ( IIii1i )
   if 1 - 1: OoooooooOO . I11i / OoOoOO00 + o0oOOo0O0Ooo % i1IIi
   if 1 - 1: OoooooooOO - OoO0O00 - OoooooooOO / iII111i
   if 70 - 70: Ii1I + I1ii11iIi11i . II111iiii * i11iIiiIii
   if 87 - 87: Ii1I / I1Ii111 % OoOoOO00 * I1ii11iIi11i - OoooooooOO / OoOoOO00
   if 24 - 24: I11i . OOooOOo * i1IIi . I1ii11iIi11i / ooOoO0o / O0
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   IIii1i = IIii1i [ 0 : - 2 ]
   IIii1i += self . eid . address . encode_geo ( )
   return ( IIii1i )
   if 62 - 62: o0oOOo0O0Ooo % II111iiii
   if 22 - 22: oO0o - o0oOOo0O0Ooo
   if 89 - 89: OOooOOo
   if 34 - 34: iII111i . OOooOOo
   if 13 - 13: OoO0O00 * OOooOOo + oO0o
  if ( O000oOOoOOO == LISP_AFI_LCAF ) :
   IIii1i += self . eid . lcaf_encode_iid ( )
   return ( IIii1i )
   if 21 - 21: i11iIiiIii . Ii1I % i1IIi * Ii1I . oO0o + Ii1I
   if 92 - 92: i1IIi + OoO0O00 * I11i
   if 70 - 70: Oo0Ooo
   if 93 - 93: iII111i . I1ii11iIi11i . Oo0Ooo . oO0o . OoooooooOO
   if 51 - 51: O0 - iII111i
  IIii1i += self . eid . pack_address ( )
  return ( IIii1i )
  if 65 - 65: O0 / II111iiii * IiII % Ii1I + o0oOOo0O0Ooo
  if 43 - 43: I1Ii111 + OoO0O00 * OoooooooOO
 def decode ( self , packet ) :
  O00oO00oOO00O = "IBBHHH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 85 - 85: iII111i + OOooOOo
  self . record_ttl , self . rloc_count , self . eid . mask_len , OOo000 , self . map_version , self . eid . afi = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 36 - 36: OoO0O00 % II111iiii * O0 + II111iiii - oO0o - i1IIi
  if 53 - 53: Ii1I - OOooOOo
  if 75 - 75: iII111i % O0 - I11i - I1ii11iIi11i + I1IiiI - I1IiiI
  self . record_ttl = socket . ntohl ( self . record_ttl )
  OOo000 = socket . ntohs ( OOo000 )
  self . action = ( OOo000 >> 13 ) & 0x7
  self . authoritative = True if ( ( OOo000 >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( OOo000 >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ ooOoooOoo0oO : : ]
  if 87 - 87: i1IIi % Ii1I % i1IIi + iIii1I11I1II1
  if 23 - 23: iIii1I11I1II1 * I11i . I1Ii111 - o0oOOo0O0Ooo
  if 66 - 66: I1IiiI * I1Ii111 / i11iIiiIii / OOooOOo
  if 19 - 19: ooOoO0o % iIii1I11I1II1 * OoooooooOO
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , O0o00oOOOO00 = self . eid . lcaf_decode_eid ( packet )
   if ( O0o00oOOOO00 ) : self . group = O0o00oOOOO00
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 53 - 53: OoOoOO00 . oO0o - OOooOOo . II111iiii * i11iIiiIii + OOooOOo
   if 99 - 99: I1ii11iIi11i % Oo0Ooo
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 31 - 31: o0oOOo0O0Ooo - II111iiii * OOooOOo . OOooOOo - oO0o
  if 57 - 57: OOooOOo / i11iIiiIii / I1Ii111 - Oo0Ooo . iIii1I11I1II1
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
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
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 71 - 71: Ii1I
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
  if 43 - 43: o0oOOo0O0Ooo / ooOoO0o
  if 88 - 88: i11iIiiIii - i1IIi + Oo0Ooo - O0
 def print_ecm ( self ) :
  oOOo0ooO0 = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 50 - 50: I1ii11iIi11i
  lprint ( oOOo0ooO0 . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 37 - 37: oO0o % iII111i / II111iiii / OoO0O00 - IiII - ooOoO0o
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 69 - 69: I1ii11iIi11i . OoooooooOO % I1Ii111
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 79 - 79: I1IiiI - IiII . OoooooooOO - I1ii11iIi11i
   if 79 - 79: OOooOOo + o0oOOo0O0Ooo % iII111i . oO0o
   if 49 - 49: Ii1I + i11iIiiIii * OoOoOO00 . OoOoOO00 . I1ii11iIi11i . Oo0Ooo
   if 61 - 61: I11i / OOooOOo
   if 85 - 85: OoOoOO00 - I11i . OoOoOO00 . OoOoOO00
   if 62 - 62: IiII % OoooooooOO * OoO0O00 + OoO0O00 % Ii1I % iII111i
  ooo0OOoo = ( LISP_ECM << 28 )
  if ( self . security ) : ooo0OOoo |= 0x08000000
  if ( self . ddt ) : ooo0OOoo |= 0x04000000
  if ( self . to_etr ) : ooo0OOoo |= 0x02000000
  if ( self . to_ms ) : ooo0OOoo |= 0x01000000
  if 66 - 66: I1IiiI . OOooOOo - OoO0O00 % Oo0Ooo * o0oOOo0O0Ooo - oO0o
  O0ooOOo0 = struct . pack ( "I" , socket . htonl ( ooo0OOoo ) )
  if 32 - 32: O0 + I1Ii111
  Ooo0oO = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   Ooo0oO = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   Ooo0oO += self . source . pack_address ( )
   Ooo0oO += self . dest . pack_address ( )
   Ooo0oO = lisp_ip_checksum ( Ooo0oO )
   if 11 - 11: i1IIi
  if ( self . afi == LISP_AFI_IPV6 ) :
   Ooo0oO = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   Ooo0oO += self . source . pack_address ( )
   Ooo0oO += self . dest . pack_address ( )
   if 65 - 65: OoO0O00 . ooOoO0o
   if 12 - 12: I1Ii111 + O0 - oO0o . IiII
  IiII1iiI = socket . htons ( self . udp_sport )
  OooOOOoOoo0O0 = socket . htons ( self . udp_dport )
  I1111III111ii = socket . htons ( self . udp_length )
  Ooo0OO00oo = socket . htons ( self . udp_checksum )
  o0oOo00 = struct . pack ( "HHHH" , IiII1iiI , OooOOOoOoo0O0 , I1111III111ii , Ooo0OO00oo )
  return ( O0ooOOo0 + Ooo0oO + o0oOo00 )
  if 46 - 46: IiII . ooOoO0o / iII111i
  if 63 - 63: II111iiii - I1ii11iIi11i * II111iiii
 def decode ( self , packet ) :
  if 92 - 92: OoO0O00 % ooOoO0o * O0 % iIii1I11I1II1 / i1IIi / OoOoOO00
  if 67 - 67: I1Ii111 + I11i + I1Ii111 . OOooOOo % o0oOOo0O0Ooo / ooOoO0o
  if 78 - 78: I1ii11iIi11i . O0
  if 56 - 56: oO0o - i1IIi * O0 / I11i * I1IiiI . I11i
  O00oO00oOO00O = "I"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 54 - 54: i11iIiiIii % i1IIi + Oo0Ooo / OoOoOO00
  ooo0OOoo = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 26 - 26: I11i . I1ii11iIi11i
  ooo0OOoo = socket . ntohl ( ooo0OOoo [ 0 ] )
  self . security = True if ( ooo0OOoo & 0x08000000 ) else False
  self . ddt = True if ( ooo0OOoo & 0x04000000 ) else False
  self . to_etr = True if ( ooo0OOoo & 0x02000000 ) else False
  self . to_ms = True if ( ooo0OOoo & 0x01000000 ) else False
  packet = packet [ ooOoooOoo0oO : : ]
  if 55 - 55: OoOoOO00 * I1Ii111 % OoO0O00 - OoO0O00
  if 34 - 34: O0 * OoO0O00 - oO0o - IiII * Ii1I . II111iiii
  if 28 - 28: O0 % iII111i - i1IIi
  if 49 - 49: ooOoO0o . I11i - iIii1I11I1II1
  if ( len ( packet ) < 1 ) : return ( None )
  IiiI1Ii1II = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  IiiI1Ii1II = IiiI1Ii1II >> 4
  if 41 - 41: ooOoO0o * i11iIiiIii % ooOoO0o . oO0o
  if ( IiiI1Ii1II == 4 ) :
   ooOoooOoo0oO = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
   if 97 - 97: oO0o - iII111i + IiII . OoOoOO00 + iIii1I11I1II1
   O0o000 , I1111III111ii , O0o000 , Ii1i11iIi1iII , III1I1Iii1 , Ooo0OO00oo = struct . unpack ( "HHIBBH" , packet [ : ooOoooOoo0oO ] )
   self . length = socket . ntohs ( I1111III111ii )
   self . ttl = Ii1i11iIi1iII
   self . protocol = III1I1Iii1
   self . ip_checksum = socket . ntohs ( Ooo0OO00oo )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 23 - 23: I11i + IiII . oO0o
   if 33 - 33: OoO0O00 / i11iIiiIii / i1IIi . IiII
   if 7 - 7: Oo0Ooo + IiII
   if 15 - 15: iIii1I11I1II1 % OoOoOO00 + i1IIi . Ii1I - Oo0Ooo
   III1I1Iii1 = struct . pack ( "H" , 0 )
   oOOoo0O00 = struct . calcsize ( "HHIBB" )
   i111 = struct . calcsize ( "H" )
   packet = packet [ : oOOoo0O00 ] + III1I1Iii1 + packet [ oOOoo0O00 + i111 : ]
   if 33 - 33: I1IiiI % I11i . I1Ii111 / Ii1I * II111iiii * o0oOOo0O0Ooo
   packet = packet [ ooOoooOoo0oO : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 49 - 49: i1IIi * i11iIiiIii
   if 47 - 47: II111iiii / Oo0Ooo
  if ( IiiI1Ii1II == 6 ) :
   ooOoooOoo0oO = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
   if 38 - 38: OOooOOo . iII111i / O0 . Ii1I / OoOoOO00
   O0o000 , I1111III111ii , III1I1Iii1 , Ii1i11iIi1iII = struct . unpack ( "IHBB" , packet [ : ooOoooOoo0oO ] )
   self . length = socket . ntohs ( I1111III111ii )
   self . protocol = III1I1Iii1
   self . ttl = Ii1i11iIi1iII
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 52 - 52: O0 / i11iIiiIii * I1IiiI . i1IIi
   packet = packet [ ooOoooOoo0oO : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 50 - 50: OoooooooOO . iII111i % o0oOOo0O0Ooo
   if 6 - 6: ooOoO0o - i1IIi . O0 . i1IIi . OoOoOO00
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 42 - 42: i11iIiiIii * O0 % i11iIiiIii + OOooOOo
  ooOoooOoo0oO = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 64 - 64: I1IiiI / OoOoOO00
  IiII1iiI , OooOOOoOoo0O0 , I1111III111ii , Ooo0OO00oo = struct . unpack ( "HHHH" , packet [ : ooOoooOoo0oO ] )
  self . udp_sport = socket . ntohs ( IiII1iiI )
  self . udp_dport = socket . ntohs ( OooOOOoOoo0O0 )
  self . udp_length = socket . ntohs ( I1111III111ii )
  self . udp_checksum = socket . ntohs ( Ooo0OO00oo )
  packet = packet [ ooOoooOoo0oO : : ]
  return ( packet )
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
  if 6 - 6: OoO0O00 . OoOoOO00 + I1ii11iIi11i
  if 24 - 24: OoO0O00 . Ii1I
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  IiIi1I1i1iII = self . rloc_name
  if ( cour ) : IiIi1I1i1iII = lisp_print_cour ( IiIi1I1i1iII )
  return ( 'rloc-name: {}' . format ( blue ( IiIi1I1i1iII , cour ) ) )
  if 86 - 86: I11i % I1Ii111 . I11i * IiII + IiII + II111iiii
  if 66 - 66: oO0o / O0 - OoOoOO00
 def print_record ( self , indent ) :
  o0O00oo0O = self . print_rloc_name ( )
  if ( o0O00oo0O != "" ) : o0O00oo0O = ", " + o0O00oo0O
  OooO0ooO0o0OO = ""
  if ( self . geo ) :
   oO00 = ""
   if ( self . geo . geo_name ) : oO00 = "'{}' " . format ( self . geo . geo_name )
   OooO0ooO0o0OO = ", geo: {}{}" . format ( oO00 , self . geo . print_geo ( ) )
   if 79 - 79: i11iIiiIii + iIii1I11I1II1 . OoooooooOO % iII111i % IiII
  OoOo0Oo0 = ""
  if ( self . elp ) :
   oO00 = ""
   if ( self . elp . elp_name ) : oO00 = "'{}' " . format ( self . elp . elp_name )
   OoOo0Oo0 = ", elp: {}{}" . format ( oO00 , self . elp . print_elp ( True ) )
   if 43 - 43: i11iIiiIii - OoooooooOO % ooOoO0o
  oO0O0Oo000 = ""
  if ( self . rle ) :
   oO00 = ""
   if ( self . rle . rle_name ) : oO00 = "'{}' " . format ( self . rle . rle_name )
   oO0O0Oo000 = ", rle: {}{}" . format ( oO00 , self . rle . print_rle ( False , True ) )
   if 60 - 60: ooOoO0o
  oo0oO0oOoo = ""
  if ( self . json ) :
   oO00 = ""
   if ( self . json . json_name ) :
    oO00 = "'{}' " . format ( self . json . json_name )
    if 66 - 66: iIii1I11I1II1 . Oo0Ooo / Ii1I + OOooOOo - O0 % IiII
   oo0oO0oOoo = ", json: {}" . format ( self . json . print_json ( False ) )
   if 22 - 22: oO0o - i11iIiiIii % O0 / II111iiii
   if 28 - 28: OoO0O00
  o0oOoOoooO = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   o0oOoOoooO = ", " + self . keys [ 1 ] . print_keys ( )
   if 20 - 20: I1Ii111 . I1IiiI - iIii1I11I1II1 / iII111i
   if 46 - 46: I1Ii111 . i11iIiiIii
  oOOo0ooO0 = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( oOOo0ooO0 . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , o0O00oo0O , OooO0ooO0o0OO ,
 OoOo0Oo0 , oO0O0Oo000 , oo0oO0oOoo , o0oOoOoooO ) )
  if 89 - 89: OoO0O00 - OOooOOo - i1IIi - OoO0O00 % iIii1I11I1II1
  if 52 - 52: o0oOOo0O0Ooo * O0 + I1ii11iIi11i
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 83 - 83: I11i + OOooOOo - OoooooooOO
  if 7 - 7: IiII % ooOoO0o / OoooooooOO / o0oOOo0O0Ooo + OoO0O00 - OoO0O00
  if 15 - 15: i1IIi + OOooOOo / Ii1I
 def store_rloc_entry ( self , rloc_entry ) :
  oOo00O = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 5 - 5: II111iiii - o0oOOo0O0Ooo + i1IIi - Ii1I % i11iIiiIii
  self . rloc . copy_address ( oOo00O )
  if 79 - 79: iII111i . Ii1I / OoO0O00
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 57 - 57: O0 / I11i + I1IiiI . IiII
   if 38 - 38: i1IIi . iII111i
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   oO00 = rloc_entry . geo_name
   if ( oO00 and lisp_geo_list . has_key ( oO00 ) ) :
    self . geo = lisp_geo_list [ oO00 ]
    if 47 - 47: o0oOOo0O0Ooo * I1ii11iIi11i
    if 48 - 48: oO0o * i1IIi % iII111i * Ii1I * I1Ii111 + ooOoO0o
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   oO00 = rloc_entry . elp_name
   if ( oO00 and lisp_elp_list . has_key ( oO00 ) ) :
    self . elp = lisp_elp_list [ oO00 ]
    if 12 - 12: iIii1I11I1II1 - I11i . I1Ii111 - Ii1I / OoO0O00 . O0
    if 8 - 8: II111iiii % OOooOOo / IiII + I1IiiI * OOooOOo
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   oO00 = rloc_entry . rle_name
   if ( oO00 and lisp_rle_list . has_key ( oO00 ) ) :
    self . rle = lisp_rle_list [ oO00 ]
    if 85 - 85: OoOoOO00 + iII111i % I1Ii111 % OOooOOo * I1ii11iIi11i
    if 48 - 48: OoO0O00 % OoO0O00 % OoOoOO00
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   oO00 = rloc_entry . json_name
   if ( oO00 and lisp_json_list . has_key ( oO00 ) ) :
    self . json = lisp_json_list [ oO00 ]
    if 30 - 30: Oo0Ooo % OoooooooOO * i11iIiiIii % oO0o
    if 37 - 37: iII111i
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 29 - 29: OOooOOo
  if 69 - 69: oO0o % OoooooooOO * iII111i
 def encode_lcaf ( self ) :
  o0O000Ooo = socket . htons ( LISP_AFI_LCAF )
  OOoooooO = ""
  if ( self . geo ) :
   OOoooooO = self . geo . encode_geo ( )
   if 65 - 65: I1Ii111
   if 33 - 33: O0 . I1Ii111 % i11iIiiIii + OoO0O00 . I1ii11iIi11i
  O0O00ooO0O0O = ""
  if ( self . elp ) :
   Iiii1II = ""
   for Ooo0o0OoOO in self . elp . elp_nodes :
    O000oOOoOOO = socket . htons ( Ooo0o0OoOO . address . afi )
    ooOOooooo0Oo = 0
    if ( Ooo0o0OoOO . eid ) : ooOOooooo0Oo |= 0x4
    if ( Ooo0o0OoOO . probe ) : ooOOooooo0Oo |= 0x2
    if ( Ooo0o0OoOO . strict ) : ooOOooooo0Oo |= 0x1
    ooOOooooo0Oo = socket . htons ( ooOOooooo0Oo )
    Iiii1II += struct . pack ( "HH" , ooOOooooo0Oo , O000oOOoOOO )
    Iiii1II += Ooo0o0OoOO . address . pack_address ( )
    if 15 - 15: o0oOOo0O0Ooo / IiII / ooOoO0o * OoOoOO00
    if 13 - 13: iII111i
   OoOoo00oO = socket . htons ( len ( Iiii1II ) )
   O0O00ooO0O0O = struct . pack ( "HBBBBH" , o0O000Ooo , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , OoOoo00oO )
   O0O00ooO0O0O += Iiii1II
   if 56 - 56: iIii1I11I1II1 / OoO0O00 * OOooOOo
   if 73 - 73: OoooooooOO % IiII / I1Ii111 * I11i + i1IIi % i11iIiiIii
  ooOOi1IiI1i1iI1Ii = ""
  if ( self . rle ) :
   O00O = ""
   for iIIII1iiIII in self . rle . rle_nodes :
    O000oOOoOOO = socket . htons ( iIIII1iiIII . address . afi )
    O00O += struct . pack ( "HBBH" , 0 , 0 , iIIII1iiIII . level , O000oOOoOOO )
    O00O += iIIII1iiIII . address . pack_address ( )
    if ( iIIII1iiIII . rloc_name ) :
     O00O += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     O00O += iIIII1iiIII . rloc_name + "\0"
     if 99 - 99: OoOoOO00 / II111iiii % i11iIiiIii + I11i + O0
     if 83 - 83: I1IiiI . i1IIi - i1IIi % OoO0O00 * oO0o * oO0o
     if 30 - 30: I1ii11iIi11i
   OOo = socket . htons ( len ( O00O ) )
   ooOOi1IiI1i1iI1Ii = struct . pack ( "HBBBBH" , o0O000Ooo , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , OOo )
   ooOOi1IiI1i1iI1Ii += O00O
   if 100 - 100: i11iIiiIii + OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo * OoOoOO00
   if 87 - 87: o0oOOo0O0Ooo
  oOOOOoO00o0oo = ""
  if ( self . json ) :
   iiii1 = socket . htons ( len ( self . json . json_string ) + 2 )
   oo0ooOO = socket . htons ( len ( self . json . json_string ) )
   oOOOOoO00o0oo = struct . pack ( "HBBBBHH" , o0O000Ooo , 0 , 0 , LISP_LCAF_JSON_TYPE ,
 0 , iiii1 , oo0ooOO )
   oOOOOoO00o0oo += self . json . json_string
   oOOOOoO00o0oo += struct . pack ( "H" , 0 )
   if 43 - 43: OOooOOo - OOooOOo . OoooooooOO
   if 65 - 65: Oo0Ooo
  oO000ooO = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   oO000ooO = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 81 - 81: I1IiiI . OoOoOO00 - I1IiiI . oO0o
   if 50 - 50: OoooooooOO - I1ii11iIi11i
  O000o = ""
  if ( self . rloc_name ) :
   O000o += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   O000o += self . rloc_name + "\0"
   if 78 - 78: I1Ii111
   if 39 - 39: I1ii11iIi11i - iIii1I11I1II1 * ooOoO0o
  OoOoo0 = len ( OOoooooO ) + len ( O0O00ooO0O0O ) + len ( ooOOi1IiI1i1iI1Ii ) + len ( oO000ooO ) + 2 + len ( oOOOOoO00o0oo ) + self . rloc . addr_length ( ) + len ( O000o )
  if 53 - 53: IiII
  OoOoo0 = socket . htons ( OoOoo0 )
  iii1i1I1II = struct . pack ( "HBBBBHH" , o0O000Ooo , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , OoOoo0 , socket . htons ( self . rloc . afi ) )
  iii1i1I1II += self . rloc . pack_address ( )
  return ( iii1i1I1II + O000o + OOoooooO + O0O00ooO0O0O + ooOOi1IiI1i1iI1Ii + oO000ooO + oOOOOoO00o0oo )
  if 5 - 5: iIii1I11I1II1 . OoooooooOO
  if 13 - 13: oO0o . o0oOOo0O0Ooo . i11iIiiIii * I1ii11iIi11i / ooOoO0o
 def encode ( self ) :
  ooOOooooo0Oo = 0
  if ( self . local_bit ) : ooOOooooo0Oo |= 0x0004
  if ( self . probe_bit ) : ooOOooooo0Oo |= 0x0002
  if ( self . reach_bit ) : ooOOooooo0Oo |= 0x0001
  if 41 - 41: ooOoO0o + IiII . i1IIi + iIii1I11I1II1
  IIii1i = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( ooOOooooo0Oo ) ,
 socket . htons ( self . rloc . afi ) )
  if 57 - 57: i11iIiiIii * oO0o * i11iIiiIii
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 14 - 14: Oo0Ooo / I11i
   IIii1i = IIii1i [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   IIii1i += self . rloc . pack_address ( )
   if 14 - 14: Oo0Ooo - Ii1I + ooOoO0o - I1IiiI % IiII
  return ( IIii1i )
  if 70 - 70: I1IiiI % ooOoO0o * OoO0O00 + OoOoOO00 % i11iIiiIii
  if 39 - 39: Oo0Ooo % I1Ii111 / I1IiiI / Oo0Ooo . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 def decode_lcaf ( self , packet , nonce ) :
  O00oO00oOO00O = "HBBBBH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 83 - 83: OoooooooOO * II111iiii % OoooooooOO
  O000oOOoOOO , i111IiI1III1 , ooOOooooo0Oo , O000oo0O0OO0 , I1iii1IiI11I11I , iiii1 = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 30 - 30: I1Ii111 / o0oOOo0O0Ooo + OoooooooOO + OoOoOO00 + OoO0O00
  if 40 - 40: OoooooooOO / IiII
  iiii1 = socket . ntohs ( iiii1 )
  packet = packet [ ooOoooOoo0oO : : ]
  if ( iiii1 > len ( packet ) ) : return ( None )
  if 82 - 82: i11iIiiIii - oO0o - i1IIi
  if 78 - 78: oO0o % iII111i / i1IIi / ooOoO0o
  if 44 - 44: o0oOOo0O0Ooo + Ii1I + I1IiiI % O0
  if 100 - 100: OoooooooOO
  if ( O000oo0O0OO0 == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( iiii1 > 0 ) :
    O00oO00oOO00O = "H"
    ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
    if ( iiii1 < ooOoooOoo0oO ) : return ( None )
    if 27 - 27: i11iIiiIii % II111iiii + I1Ii111
    o00OO00OOo0 = len ( packet )
    O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
    O000oOOoOOO = socket . ntohs ( O000oOOoOOO )
    if 76 - 76: OOooOOo - I1Ii111 + iIii1I11I1II1 + I1IiiI * oO0o
    if ( O000oOOoOOO == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ ooOoooOoo0oO : : ]
     self . rloc_name = None
     if ( O000oOOoOOO == LISP_AFI_NAME ) :
      packet , IiIi1I1i1iII = lisp_decode_dist_name ( packet )
      self . rloc_name = IiIi1I1i1iII
     else :
      self . rloc . afi = O000oOOoOOO
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 93 - 93: i11iIiiIii * i11iIiiIii - I1IiiI + iIii1I11I1II1 * i11iIiiIii
      if 14 - 14: ooOoO0o . OoooooooOO . I1IiiI - IiII + iIii1I11I1II1
      if 47 - 47: OOooOOo % i1IIi
    iiii1 -= o00OO00OOo0 - len ( packet )
    if 23 - 23: Ii1I * Ii1I / I11i
    if 11 - 11: OOooOOo
  elif ( O000oo0O0OO0 == LISP_LCAF_GEO_COORD_TYPE ) :
   if 58 - 58: OoO0O00 * OoooooooOO
   if 47 - 47: iII111i - Oo0Ooo
   if 19 - 19: O0 . i1IIi + I11i / II111iiii + ooOoO0o
   if 26 - 26: Ii1I * oO0o % I1IiiI - OOooOOo . I1Ii111
   iiIi1ii1IiI = lisp_geo ( "" )
   packet = iiIi1ii1IiI . decode_geo ( packet , iiii1 , I1iii1IiI11I11I )
   if ( packet == None ) : return ( None )
   self . geo = iiIi1ii1IiI
   if 39 - 39: O0 . OoOoOO00 / I11i * I11i % II111iiii % iIii1I11I1II1
  elif ( O000oo0O0OO0 == LISP_LCAF_JSON_TYPE ) :
   if 76 - 76: II111iiii
   if 12 - 12: Oo0Ooo - oO0o . I1ii11iIi11i . iII111i . Ii1I / i1IIi
   if 62 - 62: I11i . I1IiiI * i11iIiiIii
   if 33 - 33: iIii1I11I1II1 - I1Ii111 % OoO0O00 % i1IIi
   O00oO00oOO00O = "H"
   ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
   if ( iiii1 < ooOoooOoo0oO ) : return ( None )
   if 81 - 81: i1IIi * iII111i % I1ii11iIi11i - I1IiiI * I1Ii111 + OOooOOo
   oo0ooOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
   oo0ooOO = socket . ntohs ( oo0ooOO )
   if ( iiii1 < ooOoooOoo0oO + oo0ooOO ) : return ( None )
   if 66 - 66: Oo0Ooo
   packet = packet [ ooOoooOoo0oO : : ]
   self . json = lisp_json ( "" , packet [ 0 : oo0ooOO ] )
   packet = packet [ oo0ooOO : : ]
   if 82 - 82: IiII + OoooooooOO . I11i
  elif ( O000oo0O0OO0 == LISP_LCAF_ELP_TYPE ) :
   if 11 - 11: Ii1I + OoO0O00
   if 47 - 47: I11i . i11iIiiIii / II111iiii / IiII
   if 53 - 53: i1IIi - Oo0Ooo * O0 * OOooOOo . OoooooooOO
   if 99 - 99: oO0o . OoO0O00 / OOooOOo
   Ii1111i = lisp_elp ( None )
   Ii1111i . elp_nodes = [ ]
   while ( iiii1 > 0 ) :
    ooOOooooo0Oo , O000oOOoOOO = struct . unpack ( "HH" , packet [ : 4 ] )
    if 17 - 17: OoO0O00
    O000oOOoOOO = socket . ntohs ( O000oOOoOOO )
    if ( O000oOOoOOO == LISP_AFI_LCAF ) : return ( None )
    if 69 - 69: O0
    Ooo0o0OoOO = lisp_elp_node ( )
    Ii1111i . elp_nodes . append ( Ooo0o0OoOO )
    if 51 - 51: OoooooooOO - I1ii11iIi11i
    ooOOooooo0Oo = socket . ntohs ( ooOOooooo0Oo )
    Ooo0o0OoOO . eid = ( ooOOooooo0Oo & 0x4 )
    Ooo0o0OoOO . probe = ( ooOOooooo0Oo & 0x2 )
    Ooo0o0OoOO . strict = ( ooOOooooo0Oo & 0x1 )
    Ooo0o0OoOO . address . afi = O000oOOoOOO
    Ooo0o0OoOO . address . mask_len = Ooo0o0OoOO . address . host_mask_len ( )
    packet = Ooo0o0OoOO . address . unpack_address ( packet [ 4 : : ] )
    iiii1 -= Ooo0o0OoOO . address . addr_length ( ) + 4
    if 25 - 25: I1IiiI . OoOoOO00 / iIii1I11I1II1 % i11iIiiIii
   Ii1111i . select_elp_node ( )
   self . elp = Ii1111i
   if 14 - 14: i11iIiiIii + I1IiiI - oO0o - I11i
  elif ( O000oo0O0OO0 == LISP_LCAF_RLE_TYPE ) :
   if 38 - 38: I1IiiI / i11iIiiIii
   if 99 - 99: Ii1I
   if 38 - 38: OoOoOO00 / IiII - I1IiiI % O0 + I1ii11iIi11i
   if 51 - 51: i1IIi + II111iiii % oO0o
   i1I1Ii11II1i = lisp_rle ( None )
   i1I1Ii11II1i . rle_nodes = [ ]
   while ( iiii1 > 0 ) :
    O0o000 , o00oo0 , IiiiIiii , O000oOOoOOO = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 76 - 76: i1IIi
    O000oOOoOOO = socket . ntohs ( O000oOOoOOO )
    if ( O000oOOoOOO == LISP_AFI_LCAF ) : return ( None )
    if 38 - 38: I1IiiI
    iIIII1iiIII = lisp_rle_node ( )
    i1I1Ii11II1i . rle_nodes . append ( iIIII1iiIII )
    if 15 - 15: o0oOOo0O0Ooo
    iIIII1iiIII . level = IiiiIiii
    iIIII1iiIII . address . afi = O000oOOoOOO
    iIIII1iiIII . address . mask_len = iIIII1iiIII . address . host_mask_len ( )
    packet = iIIII1iiIII . address . unpack_address ( packet [ 6 : : ] )
    if 55 - 55: i11iIiiIii / OoooooooOO - I11i
    iiii1 -= iIIII1iiIII . address . addr_length ( ) + 6
    if ( iiii1 >= 2 ) :
     O000oOOoOOO = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( O000oOOoOOO ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , iIIII1iiIII . rloc_name = lisp_decode_dist_name ( packet )
      if 89 - 89: I11i - i1IIi - i1IIi * OOooOOo - O0
      if ( packet == None ) : return ( None )
      iiii1 -= len ( iIIII1iiIII . rloc_name ) + 1 + 2
      if 94 - 94: Oo0Ooo / I11i . I1ii11iIi11i
      if 31 - 31: i11iIiiIii + iIii1I11I1II1 . II111iiii
      if 72 - 72: I1Ii111 * OoO0O00 + Oo0Ooo / Ii1I % OOooOOo
   self . rle = i1I1Ii11II1i
   self . rle . build_forwarding_list ( )
   if 84 - 84: OoOoOO00 / o0oOOo0O0Ooo
  elif ( O000oo0O0OO0 == LISP_LCAF_SECURITY_TYPE ) :
   if 9 - 9: Ii1I
   if 76 - 76: I1IiiI % Oo0Ooo / iIii1I11I1II1 - Oo0Ooo
   if 34 - 34: OoOoOO00 - i1IIi + OOooOOo + Ii1I . o0oOOo0O0Ooo
   if 42 - 42: OoO0O00
   if 59 - 59: OoO0O00 . I1Ii111 % OoO0O00
   OO0o0 = packet
   i1ii1iiI11ii1II1 = lisp_keys ( 1 )
   packet = i1ii1iiI11ii1II1 . decode_lcaf ( OO0o0 , iiii1 )
   if ( packet == None ) : return ( None )
   if 22 - 22: Oo0Ooo
   if 21 - 21: o0oOOo0O0Ooo
   if 86 - 86: ooOoO0o / iIii1I11I1II1 . OOooOOo
   if 93 - 93: Oo0Ooo / II111iiii . Oo0Ooo + i1IIi + i1IIi
   Iii = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( i1ii1iiI11ii1II1 . cipher_suite in Iii ) :
    if ( i1ii1iiI11ii1II1 . cipher_suite == LISP_CS_25519_CBC ) :
     ii1i1I1111ii = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 30 - 30: OoOoOO00 . OOooOOo % OOooOOo / II111iiii + i1IIi
    if ( i1ii1iiI11ii1II1 . cipher_suite == LISP_CS_25519_CHACHA ) :
     ii1i1I1111ii = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 61 - 61: i1IIi % II111iiii * II111iiii . o0oOOo0O0Ooo / I1ii11iIi11i - I1Ii111
   else :
    ii1i1I1111ii = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 93 - 93: Ii1I - i1IIi
   packet = ii1i1I1111ii . decode_lcaf ( OO0o0 , iiii1 )
   if ( packet == None ) : return ( None )
   if 3 - 3: oO0o + OoO0O00 - iII111i / Ii1I
   if ( len ( packet ) < 2 ) : return ( None )
   O000oOOoOOO = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( O000oOOoOOO )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 58 - 58: Ii1I * I11i
   if 95 - 95: oO0o
   if 49 - 49: I1IiiI
   if 23 - 23: I1Ii111
   if 5 - 5: I1ii11iIi11i % OoOoOO00 . OoooooooOO . o0oOOo0O0Ooo + i11iIiiIii
   if 54 - 54: ooOoO0o - O0 + iII111i
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 34 - 34: Ii1I - OOooOOo % iII111i
   iIii1iii1 = self . rloc_name
   if ( iIii1iii1 ) : iIii1iii1 = blue ( self . rloc_name , False )
   if 80 - 80: I11i + o0oOOo0O0Ooo - I1Ii111 . OoO0O00 * oO0o + OOooOOo
   if 96 - 96: i1IIi + i1IIi * I1ii11iIi11i . Oo0Ooo * Oo0Ooo
   if 82 - 82: iIii1I11I1II1 % oO0o - I1Ii111 / O0 - iII111i
   if 22 - 22: oO0o % O0 * I1Ii111 - iIii1I11I1II1 % iII111i / OoOoOO00
   if 43 - 43: OOooOOo / Oo0Ooo / iII111i
   if 70 - 70: iII111i . oO0o . o0oOOo0O0Ooo
   II1II1iiIiI = self . keys [ 1 ] if self . keys else None
   if ( II1II1iiIiI == None ) :
    if ( ii1i1I1111ii . remote_public_key == None ) :
     iI = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( iI , iIii1iii1 ) )
     ii1i1I1111ii = None
    else :
     iI = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( iI , iIii1iii1 ) )
     ii1i1I1111ii . compute_shared_key ( "encap" )
     if 27 - 27: iII111i
     if 32 - 32: OoOoOO00 . Oo0Ooo . o0oOOo0O0Ooo / I1IiiI
     if 23 - 23: iII111i * I1ii11iIi11i / Ii1I - OoOoOO00 . II111iiii
     if 74 - 74: I1Ii111 . IiII % iII111i . O0
     if 61 - 61: IiII / I11i . I1Ii111 * OoOoOO00 / OoO0O00
     if 18 - 18: ooOoO0o % OoO0O00 % OOooOOo . I1ii11iIi11i + II111iiii / iII111i
     if 73 - 73: O0 / Ii1I + i11iIiiIii - Ii1I
     if 48 - 48: I1IiiI - i11iIiiIii * I1ii11iIi11i
     if 70 - 70: I1ii11iIi11i * OoOoOO00
     if 63 - 63: ooOoO0o . IiII - OoOoOO00 % IiII - I1Ii111 / I1Ii111
   if ( II1II1iiIiI ) :
    if ( ii1i1I1111ii . remote_public_key == None ) :
     ii1i1I1111ii = None
     oo0oO = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( oo0oO , iIii1iii1 ) )
    elif ( II1II1iiIiI . compare_keys ( ii1i1I1111ii ) ) :
     ii1i1I1111ii = II1II1iiIiI
     lprint ( "    Maintain stored encap-keys for {}" . format ( iIii1iii1 ) )
     if 42 - 42: i1IIi . OoOoOO00 * OoOoOO00 * OoOoOO00
    else :
     if ( II1II1iiIiI . remote_public_key == None ) :
      iI = "New encap-keying for existing state"
     else :
      iI = "Remote encap-rekeying"
      if 14 - 14: II111iiii / I1Ii111 . I1IiiI
     lprint ( "    {} for {}" . format ( bold ( iI , False ) ,
 iIii1iii1 ) )
     II1II1iiIiI . remote_public_key = ii1i1I1111ii . remote_public_key
     II1II1iiIiI . compute_shared_key ( "encap" )
     ii1i1I1111ii = II1II1iiIiI
     if 66 - 66: I1Ii111 % oO0o . iII111i * i1IIi
     if 81 - 81: OoooooooOO * I1IiiI / I1Ii111
   self . keys = [ None , ii1i1I1111ii , None , None ]
   if 10 - 10: I1IiiI - II111iiii / IiII * II111iiii
  else :
   if 67 - 67: II111iiii . Ii1I % oO0o . Oo0Ooo + IiII
   if 10 - 10: OOooOOo - OoO0O00 * oO0o / iIii1I11I1II1 - OoOoOO00
   if 20 - 20: IiII % I1IiiI + iIii1I11I1II1 % iII111i
   if 100 - 100: o0oOOo0O0Ooo - Oo0Ooo % I1Ii111 . i11iIiiIii % OoooooooOO
   packet = packet [ iiii1 : : ]
   if 39 - 39: I1ii11iIi11i / i11iIiiIii * i1IIi * Oo0Ooo
  return ( packet )
  if 39 - 39: OoO0O00 * OoooooooOO / i1IIi + Oo0Ooo
  if 57 - 57: O0
 def decode ( self , packet , nonce ) :
  O00oO00oOO00O = "BBBBHH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 83 - 83: OOooOOo / Ii1I * I1IiiI % oO0o / iIii1I11I1II1
  self . priority , self . weight , self . mpriority , self . mweight , ooOOooooo0Oo , O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 1 - 1: I11i / OoooooooOO / iII111i
  if 68 - 68: i1IIi / Oo0Ooo / I11i * Oo0Ooo
  ooOOooooo0Oo = socket . ntohs ( ooOOooooo0Oo )
  O000oOOoOOO = socket . ntohs ( O000oOOoOOO )
  self . local_bit = True if ( ooOOooooo0Oo & 0x0004 ) else False
  self . probe_bit = True if ( ooOOooooo0Oo & 0x0002 ) else False
  self . reach_bit = True if ( ooOOooooo0Oo & 0x0001 ) else False
  if 91 - 91: OoO0O00 . iII111i
  if ( O000oOOoOOO == LISP_AFI_LCAF ) :
   packet = packet [ ooOoooOoo0oO - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce )
  else :
   self . rloc . afi = O000oOOoOOO
   packet = packet [ ooOoooOoo0oO : : ]
   packet = self . rloc . unpack_address ( packet )
   if 82 - 82: I1ii11iIi11i / Oo0Ooo
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 63 - 63: I1IiiI
  if 3 - 3: iII111i + I1ii11iIi11i
 def end_of_rlocs ( self , packet , rloc_count ) :
  for IiIIi1IiiIiI in range ( rloc_count ) :
   packet = self . decode ( packet , None )
   if ( packet == None ) : return ( None )
   if 35 - 35: oO0o * iII111i * oO0o * I1Ii111 * IiII * i1IIi
  return ( packet )
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
class lisp_map_referral ( ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
  if 42 - 42: I1Ii111 - i11iIiiIii % II111iiii * ooOoO0o . O0 % I11i
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # Ii1I - OoO0O00 + OOooOOo . I1ii11iIi11i - I11i
 lisp_hex_string ( self . nonce ) ) )
  if 84 - 84: iIii1I11I1II1 . o0oOOo0O0Ooo * OoO0O00 % OoO0O00 * I11i . OoOoOO00
  if 43 - 43: oO0o
 def encode ( self ) :
  ooo0OOoo = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  IIii1i = struct . pack ( "I" , socket . htonl ( ooo0OOoo ) )
  IIii1i += struct . pack ( "Q" , self . nonce )
  return ( IIii1i )
  if 65 - 65: II111iiii % I1ii11iIi11i + OOooOOo + Ii1I
  if 39 - 39: i11iIiiIii % iIii1I11I1II1 + ooOoO0o + i11iIiiIii - O0 - I11i
 def decode ( self , packet ) :
  O00oO00oOO00O = "I"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 71 - 71: OoooooooOO . OoOoOO00 % IiII * iII111i / OOooOOo
  ooo0OOoo = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  ooo0OOoo = socket . ntohl ( ooo0OOoo [ 0 ] )
  self . record_count = ooo0OOoo & 0xff
  packet = packet [ ooOoooOoo0oO : : ]
  if 63 - 63: O0 * O0 . IiII
  O00oO00oOO00O = "Q"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 54 - 54: I1IiiI / i1IIi * I1ii11iIi11i
  self . nonce = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  return ( packet )
  if 10 - 10: I1IiiI % II111iiii / I1IiiI
  if 13 - 13: II111iiii - i11iIiiIii
  if 90 - 90: I11i . OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
  if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
  if 95 - 95: iII111i / ooOoO0o + I1Ii111
  if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
  if 81 - 81: I1ii11iIi11i
  if 31 - 31: O0 % ooOoO0o / I1IiiI * iII111i % iIii1I11I1II1 * OoOoOO00
class lisp_ddt_entry ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 76 - 76: I1Ii111 - O0
  if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 7 - 7: II111iiii + I11i
  if 99 - 99: iIii1I11I1II1 * oO0o
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 37 - 37: ooOoO0o * iII111i * I11i
  if 11 - 11: I1IiiI
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  ii1iII11 = self . delegation_set [ 0 ]
  return ( ii1iII11 . print_node_type ( ) )
  if 33 - 33: O0
  if 31 - 31: OoO0O00
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 9 - 9: oO0o * OoO0O00 * I1IiiI - I1IiiI % OoO0O00
  if 84 - 84: I1IiiI % I1IiiI * Ii1I
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   oo00OOooo = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( oo00OOooo == None ) :
    oo00OOooo = lisp_ddt_entry ( )
    oo00OOooo . eid . copy_address ( self . group )
    oo00OOooo . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , oo00OOooo )
    if 62 - 62: OoO0O00 . OOooOOo . oO0o + O0 % O0
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( oo00OOooo . group )
   oo00OOooo . add_source_entry ( self )
   if 76 - 76: o0oOOo0O0Ooo % OOooOOo . I11i . iIii1I11I1II1 + I1Ii111 % OoooooooOO
   if 9 - 9: oO0o + Ii1I / I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo
   if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
  if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 30 - 30: i11iIiiIii % OOooOOo
  if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 27 - 27: I1IiiI + OoOoOO00 + iII111i
  if 70 - 70: I11i + IiII . ooOoO0o - I1ii11iIi11i
  if 34 - 34: i1IIi % Oo0Ooo . oO0o
class lisp_ddt_node ( ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 36 - 36: I1ii11iIi11i / I1Ii111 - IiII + OOooOOo + I1Ii111
  if 62 - 62: Oo0Ooo . OoO0O00 * I1Ii111 . i11iIiiIii * O0
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 10 - 10: Oo0Ooo / OoOoOO00 * OOooOOo - IiII + Ii1I
  if 62 - 62: I1IiiI . Ii1I
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 74 - 74: Ii1I - I11i % ooOoO0o - I1IiiI - Ii1I - II111iiii
  if 81 - 81: i1IIi * I1ii11iIi11i + IiII - OoO0O00 * i1IIi
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 6 - 6: iIii1I11I1II1 % OoOoOO00 % II111iiii % o0oOOo0O0Ooo
  if 52 - 52: Ii1I - I1IiiI * iIii1I11I1II1 % Oo0Ooo * OOooOOo
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 67 - 67: OoooooooOO * I11i * Ii1I * iIii1I11I1II1
  if 22 - 22: OoO0O00 / o0oOOo0O0Ooo
  if 35 - 35: I1Ii111 / I1Ii111 + o0oOOo0O0Ooo - oO0o
  if 40 - 40: OoOoOO00 - II111iiii
  if 29 - 29: I1IiiI - O0
  if 36 - 36: I1IiiI * I1IiiI
  if 79 - 79: I1Ii111 - I11i
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
  if 49 - 49: II111iiii + O0 * ooOoO0o - Oo0Ooo
  if 89 - 89: I1IiiI + I11i . oO0o . II111iiii + oO0o / Oo0Ooo
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # Ii1I % OoO0O00
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 89 - 89: I1ii11iIi11i + I11i / i11iIiiIii * ooOoO0o
  if 36 - 36: iII111i / OoooooooOO + Ii1I . I1IiiI
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 48 - 48: II111iiii / II111iiii . I11i - I1IiiI
  if 67 - 67: I1ii11iIi11i + I1ii11iIi11i
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( lisp_ddt_map_requestQ . has_key ( str ( self . nonce ) ) ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 52 - 52: i11iIiiIii - O0
   if 64 - 64: i11iIiiIii . I1Ii111 / O0 - IiII
   if 88 - 88: Ii1I / OoO0O00 - I11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 11 - 11: OoO0O00 / i1IIi . OoooooooOO
  if 40 - 40: IiII + iII111i * I11i + OoOoOO00
  if 5 - 5: I1Ii111 / IiII
  if 30 - 30: OOooOOo . iII111i % OoO0O00 + oO0o
  if 69 - 69: i11iIiiIii + IiII * ooOoO0o * iII111i % oO0o
  if 66 - 66: OOooOOo * IiII + O0 - OoooooooOO
  if 19 - 19: Oo0Ooo * OoOoOO00
  if 52 - 52: OoO0O00 + oO0o
  if 84 - 84: O0 % I1ii11iIi11i % iIii1I11I1II1 - OoOoOO00 - Oo0Ooo
  if 7 - 7: II111iiii % oO0o % i1IIi . iIii1I11I1II1
  if 92 - 92: Ii1I / o0oOOo0O0Ooo % OOooOOo - OoOoOO00
  if 44 - 44: I1IiiI + OoOoOO00 * Oo0Ooo
  if 31 - 31: I11i - I1IiiI - OoO0O00 * OoOoOO00
  if 50 - 50: I1ii11iIi11i + I11i * iII111i
  if 27 - 27: OoOoOO00 * OOooOOo * iIii1I11I1II1 / i1IIi
  if 60 - 60: OOooOOo * I1Ii111 . oO0o
  if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
  if 51 - 51: I1IiiI . I11i - OoOoOO00
  if 10 - 10: Oo0Ooo * OOooOOo / IiII . o0oOOo0O0Ooo
  if 97 - 97: Ii1I . Ii1I % iII111i
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 49 - 49: Oo0Ooo % OOooOOo - OoooooooOO + IiII
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
if 67 - 67: o0oOOo0O0Ooo . Oo0Ooo % I11i
if 38 - 38: OOooOOo - OoO0O00 . ooOoO0o
if 50 - 50: o0oOOo0O0Ooo
if 85 - 85: II111iiii . iII111i - i1IIi
if 23 - 23: iII111i . Ii1I - OoO0O00 / I1ii11iIi11i / O0
if 4 - 4: i1IIi % Oo0Ooo % Ii1I * ooOoO0o - I11i
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
  if 46 - 46: IiII + O0 + i1IIi + ooOoO0o / iII111i
  if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
 def print_info ( self ) :
  if ( self . info_reply ) :
   o0o0O00O0oo = "Info-Reply"
   oOo00O = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # I1IiiI . OoO0O00 * iII111i % o0oOOo0O0Ooo
   # IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : oOo00O += "empty, "
   for ooOoOo0O in self . rtr_list :
    oOo00O += red ( ooOoOo0O . print_address_no_iid ( ) , False ) + ", "
    if 47 - 47: OoooooooOO % I1ii11iIi11i + I1IiiI / I1Ii111
   oOo00O = oOo00O [ 0 : - 2 ]
  else :
   o0o0O00O0oo = "Info-Request"
   OOo0OOO0 = "<none>" if self . hostname == None else self . hostname
   oOo00O = ", hostname: {}" . format ( blue ( OOo0OOO0 , False ) )
   if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( o0o0O00O0oo , False ) ,
 lisp_hex_string ( self . nonce ) , oOo00O ) )
  if 41 - 41: Ii1I . OoO0O00 + I1ii11iIi11i + OoOoOO00
  if 76 - 76: iII111i - iIii1I11I1II1
 def encode ( self ) :
  ooo0OOoo = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : ooo0OOoo |= ( 1 << 27 )
  if 23 - 23: I11i / OoO0O00 % OOooOOo
  if 9 - 9: ooOoO0o % I1ii11iIi11i . OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
  if 21 - 21: Ii1I % O0
  if 15 - 15: II111iiii * Ii1I + IiII % iII111i
  if 96 - 96: II111iiii * I1Ii111 / Oo0Ooo
  IIii1i = struct . pack ( "I" , socket . htonl ( ooo0OOoo ) )
  IIii1i += struct . pack ( "Q" , self . nonce )
  IIii1i += struct . pack ( "III" , 0 , 0 , 0 )
  if 35 - 35: I1IiiI
  if 54 - 54: I1ii11iIi11i % o0oOOo0O0Ooo . i1IIi
  if 72 - 72: Ii1I
  if 87 - 87: iII111i - I1IiiI
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    IIii1i += struct . pack ( "H" , 0 )
   else :
    IIii1i += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    IIii1i += self . hostname + "\0"
    if 54 - 54: iIii1I11I1II1 + oO0o * o0oOOo0O0Ooo % OoooooooOO . Oo0Ooo
   return ( IIii1i )
   if 32 - 32: iII111i
   if 33 - 33: ooOoO0o + Oo0Ooo * OoOoOO00 % ooOoO0o * oO0o - OoO0O00
   if 40 - 40: I11i . OoooooooOO * O0 / I1Ii111 + O0
   if 97 - 97: ooOoO0o - ooOoO0o * OOooOOo % OoOoOO00 - OoOoOO00 - I1Ii111
   if 52 - 52: O0 % iII111i
  O000oOOoOOO = socket . htons ( LISP_AFI_LCAF )
  O000oo0O0OO0 = LISP_LCAF_NAT_TYPE
  iiii1 = socket . htons ( 16 )
  Oo0OOOoOo0O = socket . htons ( self . ms_port )
  ooI1ii1 = socket . htons ( self . etr_port )
  IIii1i += struct . pack ( "HHBBHHHH" , O000oOOoOOO , 0 , O000oo0O0OO0 , 0 , iiii1 ,
 Oo0OOOoOo0O , ooI1ii1 , socket . htons ( self . global_etr_rloc . afi ) )
  IIii1i += self . global_etr_rloc . pack_address ( )
  IIii1i += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  IIii1i += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : IIii1i += struct . pack ( "H" , 0 )
  if 74 - 74: I11i . II111iiii + O0 * II111iiii
  if 50 - 50: IiII
  if 7 - 7: OoO0O00 / I1IiiI * Ii1I % OoO0O00 + OoO0O00 % II111iiii
  if 83 - 83: O0 % o0oOOo0O0Ooo
  for ooOoOo0O in self . rtr_list :
   IIii1i += struct . pack ( "H" , socket . htons ( ooOoOo0O . afi ) )
   IIii1i += ooOoOo0O . pack_address ( )
   if 77 - 77: I1Ii111 - OoooooooOO
  return ( IIii1i )
  if 2 - 2: OoOoOO00 - OOooOOo * o0oOOo0O0Ooo / OoO0O00 - IiII % I1IiiI
  if 98 - 98: iIii1I11I1II1
 def decode ( self , packet ) :
  OO0o0 = packet
  O00oO00oOO00O = "I"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 49 - 49: I1IiiI - I11i
  ooo0OOoo = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  ooo0OOoo = ooo0OOoo [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if 63 - 63: i11iIiiIii . OoO0O00 . oO0o
  O00oO00oOO00O = "Q"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 85 - 85: oO0o . I1ii11iIi11i + i11iIiiIii
  oOO000 = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 85 - 85: I11i
  ooo0OOoo = socket . ntohl ( ooo0OOoo )
  self . nonce = oOO000 [ 0 ]
  self . info_reply = ooo0OOoo & 0x08000000
  self . hostname = None
  packet = packet [ ooOoooOoo0oO : : ]
  if 36 - 36: ooOoO0o % OoO0O00
  if 1 - 1: OoooooooOO - OoOoOO00
  if 35 - 35: I1Ii111
  if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
  if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
  O00oO00oOO00O = "HH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 92 - 92: iII111i % I1ii11iIi11i
  if 16 - 16: oO0o
  if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
  if 24 - 24: Ii1I + IiII + OoooooooOO / oO0o / I1IiiI + IiII
  if 52 - 52: ooOoO0o
  IIIiI1i , IIII1II11Iii = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if ( IIII1II11Iii != 0 ) : return ( None )
  if 38 - 38: OoO0O00 + I1IiiI % IiII
  packet = packet [ ooOoooOoo0oO : : ]
  O00oO00oOO00O = "IBBH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 87 - 87: oO0o * Ii1I - I1Ii111 / oO0o
  oo0o , O0Ooo000OO00 , o00O0Oo , IIi1I11 = struct . unpack ( O00oO00oOO00O ,
 packet [ : ooOoooOoo0oO ] )
  if 84 - 84: II111iiii
  if ( IIi1I11 != 0 ) : return ( None )
  packet = packet [ ooOoooOoo0oO : : ]
  if 16 - 16: OoO0O00
  if 60 - 60: Ii1I
  if 72 - 72: ooOoO0o % I1Ii111
  if 68 - 68: i1IIi
  if ( self . info_reply == False ) :
   O00oO00oOO00O = "H"
   ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
   if ( len ( packet ) >= ooOoooOoo0oO ) :
    O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
    if ( socket . ntohs ( O000oOOoOOO ) == LISP_AFI_NAME ) :
     packet = packet [ ooOoooOoo0oO : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 95 - 95: OoOoOO00
     if 82 - 82: II111iiii * I1IiiI * I1ii11iIi11i
   return ( OO0o0 )
   if 79 - 79: o0oOOo0O0Ooo - oO0o . ooOoO0o / ooOoO0o - iII111i / OoooooooOO
   if 58 - 58: ooOoO0o * I1IiiI - OoO0O00 + OOooOOo
   if 79 - 79: Oo0Ooo . i11iIiiIii * OoO0O00 / I11i * OoOoOO00
   if 78 - 78: I11i . I1ii11iIi11i . I1ii11iIi11i
   if 71 - 71: iII111i + IiII + I1IiiI - OoOoOO00
  O00oO00oOO00O = "HHBBHHH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 49 - 49: I1IiiI % O0 - OoooooooOO * OoO0O00 / iIii1I11I1II1 + I11i
  O000oOOoOOO , O0o000 , O000oo0O0OO0 , O0Ooo000OO00 , iiii1 , Oo0OOOoOo0O , ooI1ii1 = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 7 - 7: iII111i * I1ii11iIi11i / oO0o
  if 31 - 31: I1ii11iIi11i - II111iiii
  if ( socket . ntohs ( O000oOOoOOO ) != LISP_AFI_LCAF ) : return ( None )
  if 86 - 86: IiII % OOooOOo % OoOoOO00 / I1IiiI % OoooooooOO
  self . ms_port = socket . ntohs ( Oo0OOOoOo0O )
  self . etr_port = socket . ntohs ( ooI1ii1 )
  packet = packet [ ooOoooOoo0oO : : ]
  if 83 - 83: i1IIi . OoOoOO00 . i1IIi / OOooOOo * O0
  if 99 - 99: OoooooooOO . OoOoOO00 / II111iiii
  if 64 - 64: iII111i / i1IIi . I1IiiI + O0
  if 5 - 5: O0 . i11iIiiIii
  O00oO00oOO00O = "H"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 71 - 71: o0oOOo0O0Ooo + iII111i + ooOoO0o
  if 27 - 27: OoooooooOO . iII111i * I1Ii111 % O0 + OoooooooOO - iII111i
  if 86 - 86: i1IIi
  if 81 - 81: OoOoOO00
  O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if ( O000oOOoOOO != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( O000oOOoOOO )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 52 - 52: iII111i * IiII % I1IiiI * I11i
   if 73 - 73: I1Ii111 * ooOoO0o
   if 62 - 62: OOooOOo . I1IiiI * iIii1I11I1II1 + OoO0O00 * ooOoO0o / oO0o
   if 14 - 14: iII111i / OoO0O00
   if 75 - 75: IiII
   if 68 - 68: IiII - i1IIi % IiII . OoO0O00 . i11iIiiIii . OoooooooOO
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( OO0o0 )
  if 32 - 32: iII111i + OoO0O00 % IiII + I1IiiI
  O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if ( O000oOOoOOO != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( O000oOOoOOO )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( OO0o0 )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 69 - 69: I1Ii111 + I11i - iIii1I11I1II1 - II111iiii . Ii1I
   if 74 - 74: I1ii11iIi11i % o0oOOo0O0Ooo + O0 - i11iIiiIii - IiII % OOooOOo
   if 39 - 39: OoO0O00 - o0oOOo0O0Ooo
   if 71 - 71: iII111i . OoO0O00 + ooOoO0o - OOooOOo - Oo0Ooo
   if 100 - 100: OoooooooOO - o0oOOo0O0Ooo + I1Ii111 . OoooooooOO % i11iIiiIii
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( OO0o0 )
  if 64 - 64: I1Ii111 % OoooooooOO / i1IIi / OoO0O00
  O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if ( O000oOOoOOO != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( O000oOOoOOO )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( OO0o0 )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 2 - 2: I11i % o0oOOo0O0Ooo . OoO0O00 . OoO0O00
   if 89 - 89: ooOoO0o - oO0o + II111iiii + OoO0O00 - IiII
   if 27 - 27: I1Ii111 - o0oOOo0O0Ooo + OoO0O00
   if 38 - 38: OoOoOO00 + OoO0O00 . i11iIiiIii + Ii1I % i1IIi % I1IiiI
   if 93 - 93: i11iIiiIii
   if 63 - 63: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo
  while ( len ( packet ) >= ooOoooOoo0oO ) :
   O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
   packet = packet [ ooOoooOoo0oO : : ]
   if ( O000oOOoOOO == 0 ) : continue
   ooOoOo0O = lisp_address ( socket . ntohs ( O000oOOoOOO ) , "" , 0 , 0 )
   packet = ooOoOo0O . unpack_address ( packet )
   if ( packet == None ) : return ( OO0o0 )
   ooOoOo0O . mask_len = ooOoOo0O . host_mask_len ( )
   self . rtr_list . append ( ooOoOo0O )
   if 97 - 97: i1IIi % I11i % OoOoOO00
  return ( OO0o0 )
  if 25 - 25: OoOoOO00 . iIii1I11I1II1 - iII111i % II111iiii . OoOoOO00
  if 16 - 16: OOooOOo . Oo0Ooo . I1IiiI % O0 . I1ii11iIi11i + i11iIiiIii
  if 100 - 100: I1ii11iIi11i - i1IIi - OoO0O00 * o0oOOo0O0Ooo + OoOoOO00
class lisp_nat_info ( ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 31 - 31: i1IIi
  if 21 - 21: o0oOOo0O0Ooo / O0 % O0 . OoooooooOO / I1IiiI
 def timed_out ( self ) :
  oO000o0Oo00 = time . time ( ) - self . uptime
  return ( oO000o0Oo00 >= ( LISP_INFO_INTERVAL * 2 ) )
  if 94 - 94: ooOoO0o + OoO0O00 / ooOoO0o - ooOoO0o + Oo0Ooo + o0oOOo0O0Ooo
  if 50 - 50: oO0o . Oo0Ooo
  if 15 - 15: Ii1I
class lisp_info_source ( ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 64 - 64: OoooooooOO
  if 25 - 25: IiII
 def cache_address_for_info_source ( self ) :
  ii1i1I1111ii = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ ii1i1I1111ii ] = self
  if 29 - 29: OoOoOO00 % ooOoO0o * OoooooooOO
  if 8 - 8: i11iIiiIii - I1Ii111 / IiII
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
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
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 52 - 52: IiII
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 86 - 86: I1Ii111 / O0 + OoooooooOO % oO0o
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 45 - 45: I1IiiI . Oo0Ooo . I11i . Ii1I
  if 81 - 81: II111iiii + OoOoOO00 % i11iIiiIii / iII111i . I1Ii111 + II111iiii
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  iIi11i = auth1 + auth2 + auth3
  if 48 - 48: I1IiiI . I1ii11iIi11i * OoOoOO00 % i1IIi / I1Ii111 * II111iiii
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  iIi11i = auth1 + auth2 + auth3 + auth4
  if 62 - 62: o0oOOo0O0Ooo * I1Ii111 . iIii1I11I1II1 / i1IIi
 return ( iIi11i )
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
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   iii11IIIiiIiI = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 41 - 41: I1Ii111 + ooOoO0o / OOooOOo + I11i % Oo0Ooo
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   iii11IIIiiIiI = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 91 - 91: I1IiiI % I1ii11iIi11i % oO0o / i1IIi * iIii1I11I1II1 + I11i
  iii11IIIiiIiI . bind ( ( local_addr , int ( port ) ) )
 else :
  oO00 = port
  if ( os . path . exists ( oO00 ) ) :
   os . system ( "rm " + oO00 )
   time . sleep ( 1 )
   if 48 - 48: ooOoO0o / I1ii11iIi11i / OoO0O00 / II111iiii * OoOoOO00
  iii11IIIiiIiI = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  iii11IIIiiIiI . bind ( oO00 )
  if 73 - 73: I11i / I1IiiI - IiII - i1IIi * IiII - OOooOOo
 return ( iii11IIIiiIiI )
 if 39 - 39: I11i . ooOoO0o * II111iiii
 if 21 - 21: Ii1I
 if 92 - 92: OoO0O00 * I1ii11iIi11i + iIii1I11I1II1
 if 88 - 88: iIii1I11I1II1 + iIii1I11I1II1 * i11iIiiIii . I1ii11iIi11i % oO0o
 if 94 - 94: I1IiiI / I1ii11iIi11i / OOooOOo
 if 45 - 45: II111iiii
 if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   iii11IIIiiIiI = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 84 - 84: o0oOOo0O0Ooo
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   iii11IIIiiIiI = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 40 - 40: OoooooooOO - oO0o / O0 * I1Ii111 . O0 + i11iIiiIii
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  iii11IIIiiIiI = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  iii11IIIiiIiI . bind ( internal_name )
  if 9 - 9: OOooOOo % O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
 return ( iii11IIIiiIiI )
 if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
 if 66 - 66: OOooOOo * Oo0Ooo
 if 58 - 58: OOooOOo
 if 96 - 96: IiII % OoooooooOO + O0 * II111iiii / OOooOOo . I1Ii111
 if 47 - 47: OoO0O00 - Oo0Ooo * OoO0O00 / oO0o
 if 13 - 13: ooOoO0o
 if 55 - 55: i1IIi . I11i . II111iiii + O0 + ooOoO0o - i1IIi
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 3 - 3: iIii1I11I1II1 / oO0o
 if 61 - 61: I1Ii111 / O0 - iII111i
 if 44 - 44: i1IIi
 if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
 if 89 - 89: OoOoOO00 + Oo0Ooo . OoOoOO00 - II111iiii
 if 85 - 85: OoooooooOO * OoooooooOO / Ii1I - II111iiii
 if 69 - 69: iII111i * I11i
 if 43 - 43: o0oOOo0O0Ooo - IiII * Ii1I . i11iIiiIii / II111iiii
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 61 - 61: OoOoOO00 / I1IiiI . I1ii11iIi11i % OOooOOo
 if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
 if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
 if 15 - 15: o0oOOo0O0Ooo / i11iIiiIii
 if 63 - 63: I1ii11iIi11i - Ii1I + I11i
 if 98 - 98: iII111i / IiII * I1IiiI / oO0o - iIii1I11I1II1
 if 72 - 72: O0 . OOooOOo
 if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
 if 74 - 74: i1IIi
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 80 - 80: ooOoO0o + I1Ii111 . I1ii11iIi11i % OoooooooOO
 if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
 if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
 if 35 - 35: i11iIiiIii + oO0o
 if 85 - 85: OoOoOO00 . O0 % OoooooooOO % oO0o
 if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
 if 12 - 12: II111iiii - iIii1I11I1II1
 if 43 - 43: i11iIiiIii % OoO0O00
 if 100 - 100: i1IIi
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
 if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
 if 71 - 71: IiII + OoO0O00
 if 39 - 39: I1IiiI % IiII / II111iiii / II111iiii
 if 95 - 95: II111iiii + i11iIiiIii + o0oOOo0O0Ooo
 if 30 - 30: O0 - O0 % iIii1I11I1II1 + iII111i * OoooooooOO
 if 1 - 1: O0
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 36 - 36: oO0o . iII111i
 if 62 - 62: I11i + iIii1I11I1II1 % I11i * OOooOOo + iIii1I11I1II1 % Ii1I
 if 56 - 56: o0oOOo0O0Ooo
 if 55 - 55: oO0o - I1Ii111 / ooOoO0o % I1IiiI * OoooooooOO * I1IiiI
 if 88 - 88: Ii1I + O0
 if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
 if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
 if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
 if 85 - 85: OoooooooOO * ooOoO0o
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
 if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
 if 26 - 26: O0 % o0oOOo0O0Ooo + iII111i * I1ii11iIi11i * I1Ii111
 if 4 - 4: OOooOOo * OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
 if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
 if 62 - 62: I1Ii111 % II111iiii
 if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
 if 91 - 91: i11iIiiIii + Ii1I
 if 85 - 85: I11i % IiII
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
 if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
 if 24 - 24: ooOoO0o - I1Ii111 * II111iiii - II111iiii
 if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
 if 93 - 93: Ii1I / iII111i
 if 100 - 100: Oo0Ooo
 if 94 - 94: I1ii11iIi11i / i1IIi * I1IiiI - I11i - I1ii11iIi11i
 if 6 - 6: I1ii11iIi11i % o0oOOo0O0Ooo + o0oOOo0O0Ooo / OOooOOo / I1IiiI
 if 67 - 67: OoOoOO00 . iII111i / OOooOOo * ooOoO0o + i1IIi
def lisp_ipc ( packet , send_socket , node ) :
 if 100 - 100: OOooOOo . ooOoO0o + I1Ii111 . oO0o
 if 20 - 20: i11iIiiIii - i1IIi - iIii1I11I1II1 - OoooooooOO
 if 72 - 72: I1Ii111 . OoO0O00
 if 59 - 59: I1IiiI * I11i % i1IIi
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 77 - 77: OOooOOo * OoooooooOO + I1IiiI + I1IiiI % oO0o . OoooooooOO
  if 60 - 60: iIii1I11I1II1
 ii1iiiI = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 37 - 37: i11iIiiIii * i11iIiiIii * OoOoOO00 + OoO0O00 . I1IiiI
 OoO00oo00 = 0
 iiiIIiiIi = len ( packet )
 O00ooOoO = 0
 I111iII = .001
 while ( iiiIIiiIi > 0 ) :
  o0O = min ( iiiIIiiIi , ii1iiiI )
  OoO0oo = packet [ OoO00oo00 : o0O + OoO00oo00 ]
  if 26 - 26: I1IiiI % iIii1I11I1II1 / OoO0O00
  try :
   send_socket . sendto ( OoO0oo , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( OoO0oo ) , len ( packet ) , node ) )
   if 71 - 71: OoOoOO00 + iII111i - I1IiiI
   O00ooOoO = 0
   I111iII = .001
   if 80 - 80: OoO0O00 . ooOoO0o
  except socket . error , oOo :
   if ( O00ooOoO == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 58 - 58: iII111i / o0oOOo0O0Ooo . iII111i % OoO0O00
    if 38 - 38: iIii1I11I1II1 % IiII * OoooooooOO - OOooOOo
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( OoO0oo ) , len ( packet ) , node , oOo ) )
   if 15 - 15: I1IiiI + iIii1I11I1II1 . i11iIiiIii % oO0o
   if 92 - 92: I11i
   O00ooOoO += 1
   time . sleep ( I111iII )
   if 96 - 96: O0 / i1IIi - i11iIiiIii / OoOoOO00 + OoooooooOO
   lprint ( "Retrying after {} ms ..." . format ( I111iII * 1000 ) )
   I111iII *= 2
   continue
   if 12 - 12: oO0o . OOooOOo
   if 76 - 76: oO0o - I11i * I1Ii111 . oO0o % iIii1I11I1II1
  OoO00oo00 += o0O
  iiiIIiiIi -= o0O
  if 86 - 86: OoooooooOO + I1Ii111
 return
 if 5 - 5: I1ii11iIi11i
 if 89 - 89: OoO0O00 - OoOoOO00 / II111iiii . I1ii11iIi11i
 if 50 - 50: Ii1I * I1Ii111 * OoooooooOO . OoooooooOO
 if 67 - 67: i11iIiiIii % ooOoO0o . I1ii11iIi11i + II111iiii . OoO0O00
 if 42 - 42: I11i / OoO0O00 / OoO0O00 * OOooOOo
 if 2 - 2: II111iiii % oO0o . I1Ii111
 if 100 - 100: OoOoOO00 + OoOoOO00
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 OoO00oo00 = 0
 oo0Oo0oo = ""
 iiiIIiiIi = len ( packet ) * 2
 while ( OoO00oo00 < iiiIIiiIi ) :
  oo0Oo0oo += packet [ OoO00oo00 : OoO00oo00 + 8 ] + " "
  OoO00oo00 += 8
  iiiIIiiIi -= 4
  if 26 - 26: II111iiii * iII111i + OOooOOo
 return ( oo0Oo0oo )
 if 28 - 28: Ii1I + O0
 if 44 - 44: oO0o
 if 51 - 51: o0oOOo0O0Ooo * o0oOOo0O0Ooo . Ii1I
 if 14 - 14: OoO0O00 . I11i % II111iiii % i11iIiiIii + OoooooooOO
 if 50 - 50: i11iIiiIii * I11i + i11iIiiIii - i1IIi
 if 69 - 69: I1IiiI + IiII + oO0o * I1ii11iIi11i . iIii1I11I1II1 / OoooooooOO
 if 77 - 77: Oo0Ooo - ooOoO0o
def lisp_send ( lisp_sockets , dest , port , packet ) :
 o0oO0OooO0oo = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 52 - 52: IiII + OoooooooOO . oO0o + O0 % iII111i
 if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo
 if 45 - 45: oO0o % O0 / O0
 if 98 - 98: I1Ii111
 if 58 - 58: OOooOOo
 if 6 - 6: I1ii11iIi11i
 if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
 if 18 - 18: ooOoO0o
 if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
 if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
 if 29 - 29: Ii1I . II111iiii / I1Ii111
 if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
 ii1i1II11II1i = dest . print_address_no_iid ( )
 if ( ii1i1II11II1i . find ( "::ffff:" ) != - 1 and ii1i1II11II1i . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : o0oO0OooO0oo = lisp_sockets [ 0 ]
  if ( o0oO0OooO0oo == None ) :
   o0oO0OooO0oo = lisp_sockets [ 0 ]
   ii1i1II11II1i = ii1i1II11II1i . split ( "::ffff:" ) [ - 1 ]
   if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
   if 81 - 81: i11iIiiIii - II111iiii + I11i
   if 52 - 52: II111iiii
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + ii1i1II11II1i , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
 if 26 - 26: I1ii11iIi11i - OoO0O00
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
 if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
 Oooo0 = ( LISP_RLOC_PROBE_TTL == 255 )
 if ( Oooo0 ) :
  I1I1 = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  Oooo0 = ( I1I1 in [ 0x12 , 0x28 ] )
  if ( Oooo0 ) : lisp_set_ttl ( o0oO0OooO0oo , LISP_RLOC_PROBE_TTL )
  if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
  if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
 try : o0oO0OooO0oo . sendto ( packet , ( ii1i1II11II1i , port ) )
 except socket . error , oOo :
  lprint ( "socket.sendto() failed: {}" . format ( oOo ) )
  if 15 - 15: Ii1I
  if 29 - 29: I11i / I1IiiI / OoooooooOO . OoOoOO00 / I11i . I1Ii111
  if 69 - 69: O0 * OoOoOO00 + o0oOOo0O0Ooo + I1IiiI % iII111i . OoooooooOO
  if 45 - 45: I1Ii111 + oO0o - o0oOOo0O0Ooo - OoOoOO00 + I1IiiI / II111iiii
  if 46 - 46: II111iiii . iIii1I11I1II1
 if ( Oooo0 ) : lisp_set_ttl ( o0oO0OooO0oo , 64 )
 return
 if 62 - 62: I1ii11iIi11i % i1IIi % I1Ii111 * ooOoO0o % OOooOOo + I1IiiI
 if 100 - 100: II111iiii - o0oOOo0O0Ooo * OoooooooOO . ooOoO0o / II111iiii / oO0o
 if 43 - 43: iIii1I11I1II1 + ooOoO0o * iII111i + iIii1I11I1II1 . I1Ii111
 if 87 - 87: I1Ii111
 if 47 - 47: II111iiii + I1IiiI . Oo0Ooo / iIii1I11I1II1
 if 14 - 14: i1IIi / OoO0O00 / iII111i % I1Ii111
 if 72 - 72: OoO0O00 . II111iiii - IiII + IiII + iIii1I11I1II1 % oO0o
 if 21 - 21: iII111i + OoOoOO00 - i11iIiiIii % O0 + OOooOOo
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
 if 94 - 94: IiII
 if 69 - 69: I1Ii111 . I1Ii111
 if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
 o0O = total_length - len ( packet )
 if ( o0O == 0 ) : return ( [ True , packet ] )
 if 8 - 8: iII111i % o0oOOo0O0Ooo
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 87 - 87: Ii1I % I11i / I1Ii111
 if 21 - 21: OoO0O00 + Ii1I / I1Ii111
 if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
 if 38 - 38: i1IIi
 if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
 iiiIIiiIi = o0O
 while ( iiiIIiiIi > 0 ) :
  try : OoO0oo = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
  OoO0oo = OoO0oo [ 0 ]
  if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
  if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
  if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
  if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
  if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
  if ( OoO0oo . find ( "packet@" ) == 0 ) :
   I111I = OoO0oo . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( OoO0oo ) ,
   # I11i / O0 - II111iiii % Oo0Ooo - OoOoOO00
 I111I [ 1 ] if len ( I111I ) > 2 else "?" )
   return ( [ False , OoO0oo ] )
   if 69 - 69: OOooOOo
   if 43 - 43: OOooOOo
  iiiIIiiIi -= len ( OoO0oo )
  packet += OoO0oo
  if 27 - 27: OOooOOo * II111iiii
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( OoO0oo ) , total_length , source ) )
  if 16 - 16: i11iIiiIii + I1ii11iIi11i
  if 33 - 33: iIii1I11I1II1
 return ( [ True , packet ] )
 if 72 - 72: I1ii11iIi11i * i11iIiiIii
 if 12 - 12: O0 - iIii1I11I1II1 % Oo0Ooo / O0 - IiII
 if 55 - 55: OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * i11iIiiIii + oO0o
 if 45 - 45: Ii1I
 if 8 - 8: oO0o + OOooOOo
 if 37 - 37: IiII - OoOoOO00 + oO0o - Oo0Ooo + IiII
 if 33 - 33: Oo0Ooo % oO0o - I1IiiI + Oo0Ooo
 if 90 - 90: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1 % IiII * I1Ii111 . I1Ii111
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 IIii1i = ""
 for OoO0oo in payload : IIii1i += OoO0oo + "\x40"
 return ( IIii1i [ : - 1 ] )
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
 if 9 - 9: O0 / O0 / I1IiiI - oO0o . ooOoO0o
 if 6 - 6: O0 - OoO0O00 + OoooooooOO % iIii1I11I1II1
 if 58 - 58: i11iIiiIii * OOooOOo . Oo0Ooo / iII111i - i1IIi
 if 45 - 45: Ii1I
 if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
 if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
 if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
 if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
 if 86 - 86: iII111i / i1IIi % Oo0Ooo
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
  if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
  if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
  if 14 - 14: OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
  try : oOii1I = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 54 - 54: OOooOOo / I1ii11iIi11i % oO0o
  if 66 - 66: I11i + iII111i
  if 50 - 50: IiII
  if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
  if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
  if 55 - 55: OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
  if ( internal == False ) :
   IIii1i = oOii1I [ 0 ]
   oo00Oo0 = lisp_convert_6to4 ( oOii1I [ 1 ] [ 0 ] )
   IiI1iI1 = oOii1I [ 1 ] [ 1 ]
   if 37 - 37: Ii1I + o0oOOo0O0Ooo
   if ( IiI1iI1 == LISP_DATA_PORT ) :
    OOOoo = lisp_data_plane_logging
    iiIIiI = lisp_format_packet ( IIii1i [ 0 : 60 ] ) + " ..."
   else :
    OOOoo = True
    iiIIiI = lisp_format_packet ( IIii1i )
    if 31 - 31: Ii1I . O0 / o0oOOo0O0Ooo + I11i
    if 72 - 72: O0 * iIii1I11I1II1 - I1Ii111 / IiII * O0
   if ( OOOoo ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( IIii1i ) , bold ( "from " + oo00Oo0 , False ) , IiI1iI1 ,
 iiIIiI ) )
    if 52 - 52: I11i
   return ( [ "packet" , oo00Oo0 , IiI1iI1 , IIii1i ] )
   if 3 - 3: oO0o + Oo0Ooo
   if 36 - 36: o0oOOo0O0Ooo % i1IIi
   if 51 - 51: Ii1I * iII111i
   if 24 - 24: iII111i * IiII / OOooOOo
   if 64 - 64: iII111i * Oo0Ooo
   if 42 - 42: ooOoO0o . O0 * ooOoO0o
  oooO0Oo = False
  oo00000ooOooO = oOii1I [ 0 ]
  i1I1i1iI1iI1 = False
  if 64 - 64: Ii1I
  while ( oooO0Oo == False ) :
   oo00000ooOooO = oo00000ooOooO . split ( "@" )
   if 20 - 20: I11i
   if ( len ( oo00000ooOooO ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( oo00000ooOooO [ 0 ] ) )
    if 58 - 58: Oo0Ooo * O0 - OoO0O00
    i1I1i1iI1iI1 = True
    break
    if 70 - 70: Ii1I * i11iIiiIii
    if 28 - 28: II111iiii / ooOoO0o * i11iIiiIii % OOooOOo
   i1I1i1II = oo00000ooOooO [ 0 ]
   try :
    Iiii111 = int ( oo00000ooOooO [ 1 ] )
   except :
    oOoooO0 = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( oOoooO0 , oOii1I ) )
    i1I1i1iI1iI1 = True
    break
    if 89 - 89: O0 % i1IIi * I1ii11iIi11i / OOooOOo % OoooooooOO / I1IiiI
   oo00Oo0 = oo00000ooOooO [ 2 ]
   IiI1iI1 = oo00000ooOooO [ 3 ]
   if 12 - 12: i1IIi / II111iiii . I11i
   if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
   if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
   if 94 - 94: OOooOOo / IiII
   if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
   if 22 - 22: OoOoOO00 - Oo0Ooo
   if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
   if 33 - 33: I11i + O0
   if ( len ( oo00000ooOooO ) > 5 ) :
    IIii1i = lisp_bit_stuff ( oo00000ooOooO [ 4 : : ] )
   else :
    IIii1i = oo00000ooOooO [ 4 ]
    if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
    if 68 - 68: O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
    if 12 - 12: II111iiii + I11i
    if 9 - 9: I1ii11iIi11i
    if 51 - 51: I1ii11iIi11i
    if 37 - 37: I1IiiI % I1Ii111
   oooO0Oo , IIii1i = lisp_receive_segments ( lisp_socket , IIii1i ,
 oo00Oo0 , Iiii111 )
   if ( IIii1i == None ) : return ( [ "" , "" , "" , "" ] )
   if 22 - 22: o0oOOo0O0Ooo % OOooOOo - I11i + ooOoO0o / OOooOOo
   if 98 - 98: I11i * O0 + IiII - oO0o
   if 35 - 35: OoooooooOO * Ii1I
   if 73 - 73: ooOoO0o . OoO0O00 % I1ii11iIi11i - oO0o
   if 67 - 67: o0oOOo0O0Ooo . I11i + i1IIi
   if ( oooO0Oo == False ) :
    oo00000ooOooO = IIii1i
    continue
    if 100 - 100: Oo0Ooo - I1IiiI . OOooOOo % iIii1I11I1II1 . I11i
    if 83 - 83: OoOoOO00 * iII111i
   if ( IiI1iI1 == "" ) : IiI1iI1 = "no-port"
   if ( i1I1i1II == "command" and lisp_i_am_core == False ) :
    ooo = IIii1i . find ( " {" )
    Oo = IIii1i if ooo == - 1 else IIii1i [ : ooo ]
    Oo = ": '" + Oo + "'"
   else :
    Oo = ""
    if 25 - 25: oO0o . OoO0O00 % Ii1I % Ii1I
    if 94 - 94: iII111i . Ii1I
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( IIii1i ) , bold ( "from " + oo00Oo0 , False ) , IiI1iI1 , i1I1i1II ,
 Oo if ( i1I1i1II in [ "command" , "api" ] ) else ": ... " if ( i1I1i1II == "data-packet" ) else ": " + lisp_format_packet ( IIii1i ) ) )
   if 71 - 71: o0oOOo0O0Ooo * II111iiii / OOooOOo . OoO0O00
   if 73 - 73: I1Ii111 * OoO0O00 / OoOoOO00 . II111iiii
   if 87 - 87: OoO0O00 + Oo0Ooo + O0 % OoooooooOO - iIii1I11I1II1
   if 100 - 100: Oo0Ooo + IiII
   if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1
  if ( i1I1i1iI1iI1 ) : continue
  return ( [ i1I1i1II , oo00Oo0 , IiI1iI1 , IIii1i ] )
  if 19 - 19: ooOoO0o + i1IIi / Oo0Ooo * II111iiii * I1Ii111 / ooOoO0o
  if 23 - 23: I1Ii111
  if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
  if 75 - 75: I11i . Ii1I / I1ii11iIi11i
  if 99 - 99: Ii1I
  if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
  if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
  if 21 - 21: iII111i
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 O0oOOoo0o0 = False
 if 2 - 2: Ii1I / OOooOOo
 Ii1I1i1IiiI = lisp_control_header ( )
 if ( Ii1I1i1IiiI . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( O0oOOoo0o0 )
  if 64 - 64: i1IIi % Oo0Ooo / O0 % Oo0Ooo
  if 49 - 49: II111iiii * iIii1I11I1II1 / I11i - oO0o
  if 76 - 76: I1Ii111 . Oo0Ooo - ooOoO0o . II111iiii - iII111i
  if 36 - 36: iIii1I11I1II1 % Oo0Ooo
  if 67 - 67: oO0o / II111iiii . I11i / oO0o
 IIIIi1i1i1iII = source
 if ( source . find ( "lisp" ) == - 1 ) :
  IiII1iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  IiII1iiI . string_to_afi ( source )
  IiII1iiI . store_address ( source )
  source = IiII1iiI
  if 61 - 61: o0oOOo0O0Ooo % i1IIi / i11iIiiIii % I1ii11iIi11i . I1ii11iIi11i + OOooOOo
  if 97 - 97: OOooOOo % iIii1I11I1II1 % OoO0O00 . I11i * o0oOOo0O0Ooo
 if ( Ii1I1i1IiiI . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl )
  if 64 - 64: OoOoOO00 + OoOoOO00 * IiII + I1ii11iIi11i % o0oOOo0O0Ooo
 elif ( Ii1I1i1IiiI . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl )
  if 25 - 25: oO0o + i11iIiiIii * OoooooooOO - iIii1I11I1II1
 elif ( Ii1I1i1IiiI . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 47 - 47: Oo0Ooo . Ii1I
 elif ( Ii1I1i1IiiI . type == LISP_MAP_NOTIFY ) :
  if ( IIIIi1i1i1iII == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  else :
   if ( lisp_is_running ( "lisp-rtr" ) ) :
    lisp_process_multicast_map_notify ( packet , source )
    if 25 - 25: I1ii11iIi11i / i1IIi * oO0o - II111iiii * i1IIi
   lisp_process_map_notify ( lisp_sockets , packet , source )
   if 57 - 57: OoO0O00 % OoO0O00
   if 67 - 67: O0 . i11iIiiIii + iIii1I11I1II1
 elif ( Ii1I1i1IiiI . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 86 - 86: iIii1I11I1II1
 elif ( Ii1I1i1IiiI . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 81 - 81: OOooOOo / I11i / OoooooooOO
 elif ( Ii1I1i1IiiI . type == LISP_NAT_INFO and Ii1I1i1IiiI . is_info_reply ( ) ) :
  O0o000 , o00oo0 , O0oOOoo0o0 = lisp_process_info_reply ( source , packet , True )
  if 74 - 74: I11i + OoooooooOO % II111iiii % o0oOOo0O0Ooo
 elif ( Ii1I1i1IiiI . type == LISP_NAT_INFO and Ii1I1i1IiiI . is_info_reply ( ) == False ) :
  oo0o00OO = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , oo0o00OO , udp_sport ,
 None )
  if 27 - 27: OoO0O00 * Oo0Ooo
 elif ( Ii1I1i1IiiI . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 80 - 80: i11iIiiIii . OoO0O00 - I11i % I11i
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( Ii1I1i1IiiI . type ) )
  if 21 - 21: I1IiiI . OoO0O00 * IiII % OoooooooOO - Oo0Ooo + Oo0Ooo
 return ( O0oOOoo0o0 )
 if 94 - 94: ooOoO0o
 if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
 if 95 - 95: II111iiii
 if 76 - 76: OoO0O00 % iII111i * OoOoOO00 / ooOoO0o / i1IIi
 if 45 - 45: Ii1I . I11i * I1Ii111 . i11iIiiIii
 if 34 - 34: O0 * o0oOOo0O0Ooo / IiII
 if 75 - 75: I1Ii111 - i1IIi - OoO0O00
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl ) :
 if 25 - 25: iII111i . o0oOOo0O0Ooo
 III1I1Iii1 = bold ( "RLOC-probe" , False )
 if 62 - 62: I11i + i1IIi . I1ii11iIi11i - I1ii11iIi11i
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( III1I1Iii1 ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 68 - 68: ooOoO0o % OoooooooOO
  if 94 - 94: Oo0Ooo * o0oOOo0O0Ooo
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( III1I1Iii1 ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl )
  return
  if 60 - 60: iII111i . OOooOOo
  if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( III1I1Iii1 ) )
 return
 if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
 if 19 - 19: I1IiiI
 if 99 - 99: OOooOOo - OOooOOo
 if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
 if 83 - 83: o0oOOo0O0Ooo
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 23 - 23: o0oOOo0O0Ooo . I11i
 if 67 - 67: iII111i
 if 52 - 52: IiII . OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / IiII . OoooooooOO . Oo0Ooo / ooOoO0o + O0
 if 38 - 38: I11i
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 66 - 66: II111iiii
 if 57 - 57: OoO0O00 / Oo0Ooo % I1IiiI * I1ii11iIi11i
 if 68 - 68: iII111i - o0oOOo0O0Ooo - OoO0O00 . O0 - i11iIiiIii
 if 2 - 2: I1ii11iIi11i * i1IIi
 if 17 - 17: I1ii11iIi11i * Ii1I % Oo0Ooo * I1Ii111 + OoO0O00 . OoooooooOO
 if 60 - 60: Ii1I . II111iiii
 if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , rloc_probe ,
 keys , enc , auth , mr_ttl = - 1 ) :
 IiIIIi = lisp_map_reply ( )
 IiIIIi . rloc_probe = rloc_probe
 IiIIIi . echo_nonce_capable = enc
 IiIIIi . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 IiIIIi . record_count = 1
 IiIIIi . nonce = nonce
 IIii1i = IiIIIi . encode ( )
 IiIIIi . print_map_reply ( )
 if 70 - 70: I1Ii111 * I11i % oO0o % ooOoO0o * iII111i - I1Ii111
 iiI = lisp_eid_record ( )
 iiI . rloc_count = len ( rloc_set )
 iiI . authoritative = auth
 iiI . record_ttl = ttl
 iiI . action = action
 iiI . eid = eid
 iiI . group = group
 if 5 - 5: IiII - iIii1I11I1II1 % oO0o % i1IIi
 IIii1i += iiI . encode ( )
 iiI . print_record ( "  " , False )
 if 68 - 68: OoooooooOO * Oo0Ooo / o0oOOo0O0Ooo * I11i + OoO0O00 . OoooooooOO
 iII111111 = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 71 - 71: OoO0O00 - ooOoO0o - I1IiiI + O0
 for iIII in rloc_set :
  iIii1IiIiI = lisp_rloc_record ( )
  oo0o00OO = iIII . rloc . print_address_no_iid ( )
  if ( oo0o00OO in iII111111 ) :
   iIii1IiIiI . local_bit = True
   iIii1IiIiI . probe_bit = rloc_probe
   iIii1IiIiI . keys = keys
   if ( iIII . priority == 254 and lisp_i_am_rtr ) :
    iIii1IiIiI . rloc_name = "RTR"
    if 91 - 91: I1ii11iIi11i % i1IIi
    if 43 - 43: IiII / i11iIiiIii
  iIii1IiIiI . store_rloc_entry ( iIII )
  iIii1IiIiI . reach_bit = True
  iIii1IiIiI . print_record ( "    " )
  IIii1i += iIii1IiIiI . encode ( )
  if 41 - 41: I11i % I1Ii111 % iII111i . OOooOOo
 return ( IIii1i )
 if 46 - 46: I1ii11iIi11i + oO0o % I1Ii111
 if 35 - 35: iIii1I11I1II1 + O0 * oO0o . i11iIiiIii
 if 63 - 63: OOooOOo * OoooooooOO * iII111i
 if 68 - 68: OoO0O00 / O0 + I1IiiI - i11iIiiIii
 if 40 - 40: iIii1I11I1II1 / OoO0O00 * II111iiii + IiII % I1Ii111 / iIii1I11I1II1
 if 79 - 79: iII111i . O0 * Oo0Ooo % o0oOOo0O0Ooo % OoO0O00
 if 77 - 77: II111iiii - I1Ii111
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 O0OOoOoOO = lisp_map_referral ( )
 O0OOoOoOO . record_count = 1
 O0OOoOoOO . nonce = nonce
 IIii1i = O0OOoOoOO . encode ( )
 O0OOoOoOO . print_map_referral ( )
 if 69 - 69: O0
 iiI = lisp_eid_record ( )
 if 37 - 37: i1IIi * iIii1I11I1II1 % OoooooooOO . OoooooooOO / Oo0Ooo % i11iIiiIii
 OOO0Oo0o = 0
 if ( ddt_entry == None ) :
  iiI . eid = eid
  iiI . group = group
 else :
  OOO0Oo0o = len ( ddt_entry . delegation_set )
  iiI . eid = ddt_entry . eid
  iiI . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 78 - 78: Oo0Ooo
 iiI . rloc_count = OOO0Oo0o
 iiI . authoritative = True
 if 74 - 74: O0 / I11i
 if 52 - 52: I1IiiI + oO0o * II111iiii
 if 15 - 15: I11i
 if 72 - 72: O0
 if 15 - 15: II111iiii / I11i % II111iiii % Ii1I % i11iIiiIii / I1Ii111
 IiiIIiIi1i11i = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( OOO0Oo0o == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   ii1iII11 = ddt_entry . delegation_set [ 0 ]
   if ( ii1iII11 . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 93 - 93: OOooOOo / OoooooooOO % iII111i
   if ( ii1iII11 . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 47 - 47: o0oOOo0O0Ooo - I1IiiI % O0 % I1Ii111 . O0 . OoOoOO00
    if 95 - 95: o0oOOo0O0Ooo * OOooOOo - iII111i * OoooooooOO - ooOoO0o / I1IiiI
    if 47 - 47: OoO0O00 % I1IiiI / OoOoOO00 - I1Ii111 / I1IiiI
    if 13 - 13: o0oOOo0O0Ooo % ooOoO0o
    if 15 - 15: iII111i * I1IiiI . iIii1I11I1II1 % I1IiiI / O0
    if 47 - 47: OoooooooOO - i11iIiiIii . I1IiiI / i1IIi
    if 74 - 74: OoooooooOO * ooOoO0o
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : IiiIIiIi1i11i = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  IiiIIiIi1i11i = ( lisp_i_am_ms and ii1iII11 . is_ms_peer ( ) == False )
  if 45 - 45: Oo0Ooo + iIii1I11I1II1 . o0oOOo0O0Ooo
  if 50 - 50: o0oOOo0O0Ooo % O0
 iiI . action = action
 iiI . ddt_incomplete = IiiIIiIi1i11i
 iiI . record_ttl = ttl
 if 67 - 67: OoOoOO00
 IIii1i += iiI . encode ( )
 iiI . print_record ( "  " , True )
 if 21 - 21: I11i % Oo0Ooo + Oo0Ooo / iIii1I11I1II1 % iIii1I11I1II1
 if ( OOO0Oo0o == 0 ) : return ( IIii1i )
 if 66 - 66: iII111i
 for ii1iII11 in ddt_entry . delegation_set :
  iIii1IiIiI = lisp_rloc_record ( )
  iIii1IiIiI . rloc = ii1iII11 . delegate_address
  iIii1IiIiI . priority = ii1iII11 . priority
  iIii1IiIiI . weight = ii1iII11 . weight
  iIii1IiIiI . mpriority = 255
  iIii1IiIiI . mweight = 0
  iIii1IiIiI . reach_bit = True
  IIii1i += iIii1IiIiI . encode ( )
  iIii1IiIiI . print_record ( "    " )
  if 72 - 72: ooOoO0o / oO0o / iII111i . I1Ii111 . I1ii11iIi11i + IiII
 return ( IIii1i )
 if 39 - 39: I1IiiI % I1Ii111
 if 22 - 22: OoOoOO00 - OOooOOo % i1IIi + i1IIi
 if 28 - 28: oO0o + OoOoOO00 * Ii1I . I11i
 if 80 - 80: I1ii11iIi11i / OoOoOO00
 if 74 - 74: I1ii11iIi11i + O0 + o0oOOo0O0Ooo - iII111i
 if 48 - 48: ooOoO0o * iIii1I11I1II1 % Oo0Ooo
 if 60 - 60: OoOoOO00 / i1IIi * iIii1I11I1II1
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 91 - 91: I1Ii111 . OoooooooOO / IiII / I1IiiI
 if ( map_request . target_group . is_null ( ) ) :
  Ooooo00 = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  Ooooo00 = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( Ooooo00 ) : Ooooo00 = Ooooo00 . lookup_source_cache ( map_request . target_eid , False )
  if 91 - 91: OoOoOO00 + OoOoOO00
 I11i11i1 = map_request . print_prefix ( )
 if 73 - 73: i11iIiiIii . OoO0O00 + ooOoO0o
 if ( Ooooo00 == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( I11i11i1 , False ) ) )
  if 77 - 77: ooOoO0o . I11i + OoooooooOO
  return
  if 100 - 100: ooOoO0o . oO0o % I1ii11iIi11i . IiII * IiII - o0oOOo0O0Ooo
  if 49 - 49: iIii1I11I1II1 % Ii1I / OoooooooOO - II111iiii . Ii1I
 Oo00O0o = Ooooo00 . print_eid_tuple ( )
 if 28 - 28: OoooooooOO / I1Ii111 / i1IIi
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( Oo00O0o , False ) , green ( I11i11i1 , False ) ) )
 if 35 - 35: IiII / iIii1I11I1II1 - I1IiiI - OoO0O00 * O0
 if 97 - 97: Oo0Ooo . i1IIi
 if 56 - 56: Ii1I
 if 2 - 2: i1IIi % oO0o + O0 - OoO0O00
 if 34 - 34: ooOoO0o + oO0o - Oo0Ooo
 oO00o0o0O = map_request . itr_rlocs [ 0 ]
 if ( oO00o0o0O . is_private_address ( ) and lisp_nat_traversal ) :
  oO00o0o0O = source
  if 50 - 50: o0oOOo0O0Ooo + Oo0Ooo + i1IIi
  if 79 - 79: Ii1I / II111iiii . I1ii11iIi11i
 oOO000 = map_request . nonce
 oO0O0o00oOo = lisp_nonce_echoing
 oOoo0oO = map_request . keys
 if 82 - 82: IiII . O0 . iIii1I11I1II1 / ooOoO0o / OoooooooOO / OoooooooOO
 Ooooo00 . map_replies_sent += 1
 if 98 - 98: O0 . oO0o * O0
 IIii1i = lisp_build_map_reply ( Ooooo00 . eid , Ooooo00 . group , Ooooo00 . rloc_set , oOO000 ,
 LISP_NO_ACTION , 1440 , map_request . rloc_probe , oOoo0oO , oO0O0o00oOo , True , ttl )
 if 87 - 87: iII111i + iII111i + iII111i % I11i
 if 2 - 2: OOooOOo * O0 - OoOoOO00 * I1Ii111 - oO0o + I1ii11iIi11i
 if 47 - 47: ooOoO0o + I1ii11iIi11i
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
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  ii1i11iiII = ( oO00o0o0O . is_private_address ( ) == False )
  ooOoOo0O = oO00o0o0O . print_address_no_iid ( )
  if ( ( ii1i11iiII and lisp_rtr_list . has_key ( ooOoOo0O ) ) or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , oO00o0o0O , None , IIii1i )
   return
   if 50 - 50: I11i . I11i % I1IiiI - i1IIi
   if 63 - 63: OoO0O00 . iII111i
   if 28 - 28: ooOoO0o . Oo0Ooo - OoooooooOO - I1Ii111 - OoooooooOO - oO0o
   if 25 - 25: I11i / I1Ii111 . i11iIiiIii % i1IIi
   if 21 - 21: O0 * IiII . iII111i / iII111i % i11iIiiIii / I11i
   if 15 - 15: o0oOOo0O0Ooo / OoO0O00 - i1IIi
 lisp_send_map_reply ( lisp_sockets , IIii1i , oO00o0o0O , sport )
 return
 if 30 - 30: OoO0O00 / ooOoO0o % ooOoO0o
 if 40 - 40: i1IIi . iIii1I11I1II1 * OoOoOO00
 if 83 - 83: iIii1I11I1II1 + Ii1I - Ii1I % II111iiii
 if 82 - 82: O0
 if 18 - 18: iII111i . IiII . I1IiiI
 if 40 - 40: IiII / oO0o + OoooooooOO / iII111i / II111iiii + i1IIi
 if 33 - 33: I11i + I1ii11iIi11i + i11iIiiIii * I1IiiI % oO0o % OoooooooOO
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl ) :
 if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
 if 69 - 69: OoooooooOO
 if 19 - 19: O0 + iIii1I11I1II1 / OoOoOO00 / oO0o + II111iiii - OOooOOo
 if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
 oO00o0o0O = map_request . itr_rlocs [ 0 ]
 if ( oO00o0o0O . is_private_address ( ) ) : oO00o0o0O = source
 oOO000 = map_request . nonce
 if 81 - 81: iIii1I11I1II1 - OoO0O00 . i11iIiiIii
 OOo0O0O0o0 = map_request . target_eid
 O0o00oOOOO00 = map_request . target_group
 if 4 - 4: o0oOOo0O0Ooo / OoO0O00 - I11i
 ooo0oo = [ ]
 for OOOOOo0O0oOO in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( OOOOOo0O0oOO == None ) : continue
  oOo00O = lisp_rloc ( )
  oOo00O . rloc . copy_address ( OOOOOo0O0oOO )
  oOo00O . priority = 254
  ooo0oo . append ( oOo00O )
  if 99 - 99: OoO0O00 * I11i
  if 33 - 33: I1Ii111 % IiII * OOooOOo - I1Ii111
 oO0O0o00oOo = lisp_nonce_echoing
 oOoo0oO = map_request . keys
 if 100 - 100: ooOoO0o . i11iIiiIii * Oo0Ooo - i11iIiiIii
 IIii1i = lisp_build_map_reply ( OOo0O0O0o0 , O0o00oOOOO00 , ooo0oo , oOO000 , LISP_NO_ACTION ,
 1440 , True , oOoo0oO , oO0O0o00oOo , True , ttl )
 lisp_send_map_reply ( lisp_sockets , IIii1i , oO00o0o0O , sport )
 return
 if 72 - 72: oO0o + I11i . OoooooooOO
 if 84 - 84: oO0o * oO0o - i1IIi + ooOoO0o
 if 83 - 83: i1IIi
 if 85 - 85: i11iIiiIii / OoO0O00 / oO0o
 if 12 - 12: iII111i % OOooOOo % i1IIi
 if 17 - 17: IiII
 if 63 - 63: ooOoO0o . i11iIiiIii / iIii1I11I1II1
 if 8 - 8: i11iIiiIii . IiII * iIii1I11I1II1 * I1IiiI * Ii1I * i11iIiiIii
 if 24 - 24: I1IiiI * I11i - o0oOOo0O0Ooo / iII111i + IiII - I1ii11iIi11i
 if 53 - 53: I11i / I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * OoOoOO00
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 ooo0oo = target_site_eid . registered_rlocs
 if 86 - 86: iIii1I11I1II1 - I1Ii111
 OoO0OOOOO0OO = lisp_site_eid_lookup ( seid , group , False )
 if ( OoO0OOOOO0OO == None ) : return ( ooo0oo )
 if 5 - 5: o0oOOo0O0Ooo
 if 58 - 58: oO0o * II111iiii * Oo0Ooo - I1IiiI % iII111i
 if 77 - 77: I11i / iII111i * o0oOOo0O0Ooo % iIii1I11I1II1
 if 26 - 26: i1IIi / OoO0O00 / IiII
 oO00OoO0O0O = None
 I1III = [ ]
 for iIII in ooo0oo :
  if ( iIII . is_rtr ( ) ) : continue
  if ( iIII . rloc . is_private_address ( ) ) :
   I1iiI1 = copy . deepcopy ( iIII )
   I1III . append ( I1iiI1 )
   continue
   if 74 - 74: I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
  oO00OoO0O0O = iIII
  break
  if 55 - 55: OoO0O00 % IiII
 if ( oO00OoO0O0O == None ) : return ( ooo0oo )
 oO00OoO0O0O = oO00OoO0O0O . rloc . print_address_no_iid ( )
 if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
 if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
 if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
 if 63 - 63: I1Ii111 + iII111i
 iI1III = None
 for iIII in OoO0OOOOO0OO . registered_rlocs :
  if ( iIII . is_rtr ( ) ) : continue
  if ( iIII . rloc . is_private_address ( ) ) : continue
  iI1III = iIII
  break
  if 84 - 84: ooOoO0o % I1ii11iIi11i + i1IIi * ooOoO0o + OOooOOo - IiII
 if ( iI1III == None ) : return ( ooo0oo )
 iI1III = iI1III . rloc . print_address_no_iid ( )
 if 42 - 42: Ii1I - i11iIiiIii + I11i * O0
 if 51 - 51: i1IIi . Oo0Ooo + OoOoOO00 / OoooooooOO / oO0o
 if 58 - 58: I1ii11iIi11i / Ii1I * ooOoO0o - IiII
 if 67 - 67: ooOoO0o - ooOoO0o * o0oOOo0O0Ooo
 I1111iii1ii11 = target_site_eid . site_id
 if ( I1111iii1ii11 == 0 ) :
  if ( iI1III == oO00OoO0O0O ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( oO00OoO0O0O ) )
   if 65 - 65: O0
   return ( I1III )
   if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
  return ( ooo0oo )
  if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
  if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
  if 53 - 53: o0oOOo0O0Ooo * Ii1I
  if 42 - 42: I11i + iII111i / iIii1I11I1II1
  if 1 - 1: O0 - II111iiii
  if 75 - 75: II111iiii / OoO0O00 % II111iiii
  if 3 - 3: Ii1I - Ii1I % I1ii11iIi11i
 if ( I1111iii1ii11 == OoO0OOOOO0OO . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( I1111iii1ii11 ) )
  return ( I1III )
  if 44 - 44: OOooOOo - o0oOOo0O0Ooo
 return ( ooo0oo )
 if 69 - 69: IiII + I1ii11iIi11i / o0oOOo0O0Ooo / OOooOOo
 if 31 - 31: oO0o + I1ii11iIi11i * i1IIi % I1IiiI % I1IiiI + iIii1I11I1II1
 if 62 - 62: OoooooooOO
 if 38 - 38: iII111i % iII111i * ooOoO0o / OoO0O00 + ooOoO0o
 if 52 - 52: ooOoO0o . iIii1I11I1II1 / iIii1I11I1II1 % oO0o - oO0o * II111iiii
 if 57 - 57: I1Ii111
 if 23 - 23: I1ii11iIi11i + II111iiii
 if 99 - 99: o0oOOo0O0Ooo . I1IiiI + o0oOOo0O0Ooo * o0oOOo0O0Ooo / O0
 if 27 - 27: OOooOOo - I1Ii111
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 III1I1IIi = [ ]
 ooo0oo = [ ]
 if 89 - 89: iIii1I11I1II1 * I11i + OOooOOo
 if 27 - 27: i1IIi - OoO0O00
 if 23 - 23: iIii1I11I1II1 + Oo0Ooo * IiII
 if 80 - 80: OoooooooOO . ooOoO0o
 if 52 - 52: O0 + O0 + I1IiiI
 if 64 - 64: ooOoO0o
 II = False
 i1Ii = False
 for iIII in registered_rloc_set :
  if ( iIII . priority != 254 ) : continue
  i1Ii |= True
  if ( iIII . rloc . is_exact_match ( mr_source ) == False ) : continue
  II = True
  break
  if 9 - 9: OoooooooOO / OoooooooOO
  if 57 - 57: OoO0O00 + i1IIi % OOooOOo * i11iIiiIii % i1IIi / o0oOOo0O0Ooo
  if 1 - 1: ooOoO0o
  if 81 - 81: iII111i . Oo0Ooo . O0 . II111iiii
  if 46 - 46: I1Ii111 % Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . oO0o
  if 43 - 43: i1IIi % o0oOOo0O0Ooo * I1IiiI / oO0o * IiII + I11i
  if 13 - 13: O0
 if ( i1Ii == False ) : return ( registered_rloc_set )
 if 60 - 60: IiII
 if 14 - 14: II111iiii - i1IIi % OoOoOO00
 if 29 - 29: OoooooooOO * O0 / iIii1I11I1II1
 if 29 - 29: OoO0O00 / IiII + i1IIi / OoO0O00 . Oo0Ooo
 if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
 if 14 - 14: i1IIi
 if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
 if 36 - 36: OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
 if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
 if 23 - 23: oO0o / o0oOOo0O0Ooo + I11i % IiII * OoO0O00
 iiiiIii = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 40 - 40: Ii1I % oO0o
 if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
 if 78 - 78: oO0o
 if 20 - 20: i1IIi + i1IIi * i1IIi
 if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
 for iIII in registered_rloc_set :
  if ( iiiiIii and iIII . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and iIII . priority == 255 ) : continue
  if ( multicast and iIII . mpriority == 255 ) : continue
  if ( iIII . priority == 254 ) :
   III1I1IIi . append ( iIII )
  else :
   ooo0oo . append ( iIII )
   if 27 - 27: oO0o + Ii1I . i11iIiiIii
   if 97 - 97: iII111i . I1IiiI
   if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
   if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
   if 45 - 45: oO0o
   if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
 if ( II ) : return ( ooo0oo )
 if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
 if 100 - 100: i11iIiiIii - iII111i - I11i
 if 5 - 5: oO0o % IiII * iII111i
 if 98 - 98: iII111i / OOooOOo + IiII
 if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
 if 82 - 82: ooOoO0o % OOooOOo % Ii1I
 if 82 - 82: I1ii11iIi11i
 if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
 if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
 if 53 - 53: OOooOOo * OoOoOO00 % iII111i
 ooo0oo = [ ]
 for iIII in registered_rloc_set :
  if ( iIII . rloc . is_private_address ( ) ) : ooo0oo . append ( iIII )
  if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
 ooo0oo += III1I1IIi
 return ( ooo0oo )
 if 66 - 66: I1IiiI * OoOoOO00 . I1IiiI / Oo0Ooo - Ii1I
 if 69 - 69: iIii1I11I1II1 % iII111i + ooOoO0o * i1IIi + iII111i * I1Ii111
 if 67 - 67: Ii1I % Oo0Ooo - Oo0Ooo . I11i + IiII
 if 73 - 73: Oo0Ooo + iIii1I11I1II1 . iIii1I11I1II1
 if 73 - 73: ooOoO0o + OoOoOO00
 if 61 - 61: I1Ii111 * I1Ii111 % OOooOOo
 if 31 - 31: oO0o + Ii1I - iIii1I11I1II1 / i11iIiiIii
 if 9 - 9: IiII % OoO0O00
 if 58 - 58: iII111i
 if 12 - 12: OoO0O00
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 o0oo0O = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 o0oo0O . add ( reply_eid )
 return
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
def lisp_convert_reply_to_notify ( packet ) :
 if 1 - 1: o0oOOo0O0Ooo % oO0o * I1Ii111 - i1IIi - iII111i . oO0o
 if 25 - 25: i1IIi * o0oOOo0O0Ooo / oO0o
 if 11 - 11: IiII + II111iiii
 if 37 - 37: O0
 o0oo0OoOo000 = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 o0oo0OoOo000 = socket . ntohl ( o0oo0OoOo000 ) & 0xff
 oOO000 = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 35 - 35: I11i + OoooooooOO
 if 67 - 67: iII111i . OoO0O00 . i1IIi - Oo0Ooo
 if 92 - 92: I1Ii111 % II111iiii % I11i % O0 . I1Ii111 % o0oOOo0O0Ooo
 if 99 - 99: I1ii11iIi11i
 ooo0OOoo = ( LISP_MAP_NOTIFY << 28 ) | o0oo0OoOo000
 Ii1I1i1IiiI = struct . pack ( "I" , socket . htonl ( ooo0OOoo ) )
 iI1 = struct . pack ( "I" , 0 )
 if 78 - 78: OoooooooOO
 if 14 - 14: O0 % OoooooooOO
 if 92 - 92: oO0o
 if 49 - 49: i11iIiiIii + OoO0O00 - OOooOOo
 packet = Ii1I1i1IiiI + oOO000 + iI1 + packet
 return ( packet )
 if 9 - 9: II111iiii * OOooOOo / Oo0Ooo + iIii1I11I1II1 % I1IiiI
 if 95 - 95: I1Ii111 . IiII % OoO0O00 - OOooOOo - I11i
 if 55 - 55: OoooooooOO % I1ii11iIi11i % iII111i / IiII
 if 65 - 65: II111iiii
 if 58 - 58: iIii1I11I1II1 / i11iIiiIii . iII111i . OOooOOo * I1ii11iIi11i + OoooooooOO
 if 13 - 13: OoooooooOO + iII111i * i11iIiiIii % IiII + oO0o . o0oOOo0O0Ooo
 if 31 - 31: o0oOOo0O0Ooo - ooOoO0o
 if 40 - 40: O0 / OoOoOO00 - I1Ii111
def lisp_notify_subscribers ( lisp_sockets , eid_record , eid , site ) :
 I11i11i1 = eid . print_prefix ( )
 if ( lisp_pubsub_cache . has_key ( I11i11i1 ) == False ) : return
 if 60 - 60: IiII + I1IiiI
 for o0oo0O in lisp_pubsub_cache [ I11i11i1 ] . values ( ) :
  III1iii1 = o0oo0O . itr
  IiI1iI1 = o0oo0O . port
  o00O00 = red ( III1iii1 . print_address_no_iid ( ) , False )
  iI1iiiI1 = bold ( "subscriber" , False )
  oooOOOO0oOo = "0x" + lisp_hex_string ( o0oo0O . xtr_id )
  oOO000 = "0x" + lisp_hex_string ( o0oo0O . nonce )
  if 77 - 77: OoooooooOO / I11i / iIii1I11I1II1 . IiII * Oo0Ooo * I1Ii111
  lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( iI1iiiI1 , o00O00 , IiI1iI1 , oooOOOO0oOo , green ( I11i11i1 , False ) , oOO000 ) )
  if 48 - 48: i1IIi
  if 79 - 79: iIii1I11I1II1
  lisp_build_map_notify ( lisp_sockets , eid_record , [ I11i11i1 ] , 1 , III1iii1 ,
 IiI1iI1 , o0oo0O . nonce , 0 , 0 , 0 , site , False )
  o0oo0O . map_notify_count += 1
  if 25 - 25: II111iiii % OoO0O00 / iII111i % i11iIiiIii + oO0o % I11i
 return
 if 66 - 66: I1ii11iIi11i - oO0o - OoO0O00 * Oo0Ooo
 if 47 - 47: o0oOOo0O0Ooo
 if 88 - 88: iIii1I11I1II1 + OOooOOo . II111iiii / i11iIiiIii % OOooOOo % IiII
 if 38 - 38: OOooOOo
 if 82 - 82: OoOoOO00 % II111iiii * ooOoO0o + OoooooooOO + I1IiiI
 if 89 - 89: ooOoO0o % i1IIi - OoooooooOO
 if 100 - 100: Ii1I % I1ii11iIi11i % I1IiiI
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 19 - 19: I1ii11iIi11i . o0oOOo0O0Ooo % Oo0Ooo / OoooooooOO
 if 68 - 68: iII111i
 if 55 - 55: IiII . i11iIiiIii % OoooooooOO
 if 88 - 88: Ii1I * o0oOOo0O0Ooo / oO0o
 lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl , xtr_id )
 if 58 - 58: O0
 OOo0O0O0o0 = green ( reply_eid . print_prefix ( ) , False )
 III1iii1 = red ( itr_rloc . print_address_no_iid ( ) , False )
 IiiiO000oO = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( IiiiO000oO ,
 OOo0O0O0o0 , III1iii1 , xtr_id ) )
 if 1 - 1: I1Ii111 * OOooOOo - Ii1I - Oo0Ooo
 if 79 - 79: I11i - Ii1I + i1IIi
 if 94 - 94: Oo0Ooo * iII111i - I11i - OoooooooOO / I1Ii111
 if 59 - 59: iII111i / i11iIiiIii / I1IiiI
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 return
 if 7 - 7: i1IIi - OOooOOo
 if 11 - 11: O0 * OoOoOO00 - OOooOOo + iII111i * OoO0O00
 if 41 - 41: I1Ii111 - i11iIiiIii + O0
 if 24 - 24: iIii1I11I1II1 * OoO0O00 / iII111i % OoOoOO00 % i11iIiiIii * I11i
 if 89 - 89: oO0o / iIii1I11I1II1 - O0 . o0oOOo0O0Ooo % oO0o
 if 73 - 73: IiII + I11i % I1IiiI * iII111i . O0
 if 17 - 17: OoO0O00 * OoOoOO00 % O0 % iII111i / i1IIi
 if 100 - 100: i11iIiiIii
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 54 - 54: O0 * Ii1I + Ii1I
 if 59 - 59: i11iIiiIii % iII111i
 if 54 - 54: I11i . ooOoO0o / OOooOOo % I1Ii111
 if 13 - 13: I11i / O0 . o0oOOo0O0Ooo . ooOoO0o
 if 7 - 7: OoO0O00 + OoooooooOO % II111iiii % oO0o
 if 48 - 48: OOooOOo . II111iiii * OOooOOo - I11i / iIii1I11I1II1 / i11iIiiIii
 OOo0O0O0o0 = map_request . target_eid
 O0o00oOOOO00 = map_request . target_group
 I11i11i1 = lisp_print_eid_tuple ( OOo0O0O0o0 , O0o00oOOOO00 )
 oO00o0o0O = map_request . itr_rlocs [ 0 ]
 oooOOOO0oOo = map_request . xtr_id
 oOO000 = map_request . nonce
 OOo000 = LISP_NO_ACTION
 o0oo0O = map_request . subscribe_bit
 if 37 - 37: II111iiii % O0 + iIii1I11I1II1 - I1IiiI . I11i + I1ii11iIi11i
 if 14 - 14: ooOoO0o % iIii1I11I1II1 % ooOoO0o / IiII + OOooOOo
 if 14 - 14: Oo0Ooo
 if 79 - 79: I1ii11iIi11i % I1Ii111 % I11i - iII111i * OoOoOO00
 if 48 - 48: O0 + OoOoOO00 - O0
 O0o = True
 IiIii1II1I11 = ( lisp_get_eid_hash ( OOo0O0O0o0 ) != None )
 if ( IiIii1II1I11 ) :
  o00 = map_request . map_request_signature
  if ( o00 == None ) :
   O0o = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 23 - 23: I1ii11iIi11i
  else :
   O000oOO0Oooo = map_request . signature_eid
   oO00oO0OOoooO , OO0o0OOO0ooOO00o , O0o = lisp_lookup_public_key ( O000oOO0Oooo )
   if ( O0o ) :
    O0o = map_request . verify_map_request_sig ( OO0o0OOO0ooOO00o )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( O000oOO0Oooo . print_address ( ) , oO00oO0OOoooO . print_address ( ) ) )
    if 98 - 98: O0 * OoOoOO00 + OoooooooOO - I1IiiI % OOooOOo
    if 35 - 35: I1IiiI / Ii1I / i11iIiiIii
   O0O0OO0O0O = bold ( "passed" , False ) if O0o else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( O0O0OO0O0O ) )
   if 90 - 90: ooOoO0o
   if 11 - 11: OoOoOO00 % OOooOOo . i11iIiiIii * I1IiiI % O0 % iIii1I11I1II1
   if 18 - 18: Oo0Ooo % OOooOOo + IiII
 if ( o0oo0O and O0o == False ) :
  o0oo0O = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 28 - 28: OOooOOo . OoO0O00 / o0oOOo0O0Ooo + II111iiii / iIii1I11I1II1 * II111iiii
  if 83 - 83: II111iiii . OoOoOO00 - i11iIiiIii . OoOoOO00 . i1IIi % OoooooooOO
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
  if 14 - 14: oO0o
  if 16 - 16: iII111i
 I11oo = oO00o0o0O if ( oO00o0o0O . afi == ecm_source . afi ) else ecm_source
 if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
 oO00Oooo0o0o0 = lisp_site_eid_lookup ( OOo0O0O0o0 , O0o00oOOOO00 , False )
 if 67 - 67: I1IiiI % OoO0O00 % o0oOOo0O0Ooo % IiII
 if ( oO00Oooo0o0o0 == None or oO00Oooo0o0o0 . is_star_g ( ) ) :
  i1i1IiIIIiI = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( i1i1IiIIIiI ,
 green ( I11i11i1 , False ) ) )
  if 82 - 82: OoooooooOO * OoooooooOO / I1ii11iIi11i - iII111i
  if 52 - 52: I11i * IiII - o0oOOo0O0Ooo / I1Ii111 + OoOoOO00
  if 5 - 5: O0 - IiII % iII111i
  if 81 - 81: iII111i % Oo0Ooo * II111iiii
  lisp_send_negative_map_reply ( lisp_sockets , OOo0O0O0o0 , O0o00oOOOO00 , oOO000 , oO00o0o0O ,
 mr_sport , 15 , oooOOOO0oOo , o0oo0O )
  if 71 - 71: II111iiii + I1ii11iIi11i * II111iiii
  return ( [ OOo0O0O0o0 , O0o00oOOOO00 , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 59 - 59: OoO0O00
  if 81 - 81: i11iIiiIii
 Oo00O0o = oO00Oooo0o0o0 . print_eid_tuple ( )
 OOOo0O00OO00O = oO00Oooo0o0o0 . site . site_name
 if 91 - 91: Oo0Ooo - iIii1I11I1II1 - iII111i . OoooooooOO . iII111i + Oo0Ooo
 if 20 - 20: OoO0O00 . ooOoO0o - IiII
 if 82 - 82: oO0o
 if 26 - 26: I1ii11iIi11i
 if 40 - 40: OOooOOo
 if ( IiIii1II1I11 == False and oO00Oooo0o0o0 . require_signature ) :
  o00 = map_request . map_request_signature
  O000oOO0Oooo = map_request . signature_eid
  if ( o00 == None or O000oOO0Oooo . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( OOOo0O00OO00O ) )
   O0o = False
  else :
   O000oOO0Oooo = map_request . signature_eid
   oO00oO0OOoooO , OO0o0OOO0ooOO00o , O0o = lisp_lookup_public_key ( O000oOO0Oooo )
   if ( O0o ) :
    O0o = map_request . verify_map_request_sig ( OO0o0OOO0ooOO00o )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( O000oOO0Oooo . print_address ( ) , oO00oO0OOoooO . print_address ( ) ) )
    if 90 - 90: OoOoOO00
    if 21 - 21: i1IIi % oO0o + OOooOOo / I1ii11iIi11i % i1IIi
   O0O0OO0O0O = bold ( "passed" , False ) if O0o else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( O0O0OO0O0O ) )
   if 64 - 64: I1Ii111 - OoOoOO00 * OoooooooOO - I1Ii111
   if 43 - 43: I1Ii111 + I11i - Ii1I + I11i - Oo0Ooo
   if 63 - 63: IiII % I11i / OoOoOO00 % OOooOOo * iII111i * OoO0O00
   if 11 - 11: I1Ii111 * II111iiii
   if 3 - 3: Oo0Ooo * OOooOOo
   if 13 - 13: I1Ii111 + i11iIiiIii / OOooOOo
 if ( O0o and oO00Oooo0o0o0 . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( OOOo0O00OO00O , green ( Oo00O0o , False ) , green ( I11i11i1 , False ) ) )
  if 98 - 98: I1IiiI * Oo0Ooo
  if 9 - 9: O0 / i11iIiiIii . iIii1I11I1II1 . IiII
  if 14 - 14: OoOoOO00 . OOooOOo - Oo0Ooo + I1Ii111 % ooOoO0o
  if 95 - 95: OoO0O00 * II111iiii + i1IIi
  if 22 - 22: Ii1I / ooOoO0o % I11i + OoO0O00 . ooOoO0o
  if 61 - 61: O0 - iIii1I11I1II1 * Oo0Ooo . Ii1I + O0
  if ( oO00Oooo0o0o0 . accept_more_specifics == False ) :
   OOo0O0O0o0 = oO00Oooo0o0o0 . eid
   O0o00oOOOO00 = oO00Oooo0o0o0 . group
   if 20 - 20: ooOoO0o / ooOoO0o - Ii1I - ooOoO0o
   if 93 - 93: O0 * OoOoOO00 * iIii1I11I1II1
   if 3 - 3: I1ii11iIi11i - O0
   if 46 - 46: iII111i
   if 99 - 99: oO0o
  oo0o = 1
  if ( oO00Oooo0o0o0 . force_ttl != None ) :
   oo0o = oO00Oooo0o0o0 . force_ttl | 0x80000000
   if 85 - 85: I1Ii111 * iIii1I11I1II1 . OoOoOO00
   if 20 - 20: I11i * O0 - OoooooooOO * OOooOOo % oO0o * iII111i
   if 70 - 70: I11i + O0 . i11iIiiIii . OOooOOo
   if 48 - 48: iIii1I11I1II1 * Ii1I - OoooooooOO / oO0o - OoO0O00 / i11iIiiIii
   if 24 - 24: I1IiiI
  lisp_send_negative_map_reply ( lisp_sockets , OOo0O0O0o0 , O0o00oOOOO00 , oOO000 , oO00o0o0O ,
 mr_sport , oo0o , oooOOOO0oOo , o0oo0O )
  if 63 - 63: I11i - iIii1I11I1II1 * Ii1I + OoooooooOO . i11iIiiIii
  return ( [ OOo0O0O0o0 , O0o00oOOOO00 , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 94 - 94: OoO0O00 . oO0o . OoOoOO00 * i11iIiiIii
  if 96 - 96: i1IIi . OoO0O00 . OoO0O00 - o0oOOo0O0Ooo - Ii1I
  if 33 - 33: ooOoO0o + I1ii11iIi11i - I1IiiI . iII111i / OoO0O00
  if 91 - 91: OOooOOo - OoooooooOO . OoO0O00
  if 34 - 34: Ii1I . I1IiiI . i1IIi * I1ii11iIi11i
 o0i1i = False
 i11i1111I1I1 = ""
 OO0000O = False
 if ( oO00Oooo0o0o0 . force_nat_proxy_reply ) :
  i11i1111I1I1 = ", nat-forced"
  o0i1i = True
  OO0000O = True
 elif ( oO00Oooo0o0o0 . force_proxy_reply ) :
  i11i1111I1I1 = ", forced"
  OO0000O = True
 elif ( oO00Oooo0o0o0 . proxy_reply_requested ) :
  i11i1111I1I1 = ", requested"
  OO0000O = True
 elif ( map_request . pitr_bit and oO00Oooo0o0o0 . pitr_proxy_reply_drop ) :
  i11i1111I1I1 = ", drop-to-pitr"
  OOo000 = LISP_DROP_ACTION
 elif ( oO00Oooo0o0o0 . proxy_reply_action != "" ) :
  OOo000 = oO00Oooo0o0o0 . proxy_reply_action
  i11i1111I1I1 = ", forced, action {}" . format ( OOo000 )
  OOo000 = LISP_DROP_ACTION if ( OOo000 == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 45 - 45: O0 * iII111i + oO0o + ooOoO0o
  if 29 - 29: OoO0O00
  if 24 - 24: IiII - OoOoOO00 / OoooooooOO . I1ii11iIi11i
  if 88 - 88: I11i
  if 36 - 36: iIii1I11I1II1 - ooOoO0o * OoO0O00 * OoO0O00 . II111iiii
  if 49 - 49: O0 + OoO0O00 - I1ii11iIi11i + ooOoO0o
  if 90 - 90: O0 . Ii1I * OOooOOo * OoooooooOO * ooOoO0o * Ii1I
 i11iii1III1i = False
 I1Ii = None
 if ( OO0000O and lisp_policies . has_key ( oO00Oooo0o0o0 . policy ) ) :
  III1I1Iii1 = lisp_policies [ oO00Oooo0o0o0 . policy ]
  if ( III1I1Iii1 . match_policy_map_request ( map_request , mr_source ) ) : I1Ii = III1I1Iii1
  if 54 - 54: IiII . iII111i * OOooOOo / ooOoO0o . i11iIiiIii
  if ( I1Ii ) :
   o0 = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( o0 ,
 III1I1Iii1 . policy_name , III1I1Iii1 . set_action ) )
  else :
   o0 = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( o0 ,
 III1I1Iii1 . policy_name ) )
   i11iii1III1i = True
   if 91 - 91: ooOoO0o % iII111i
   if 41 - 41: o0oOOo0O0Ooo . I1Ii111 + IiII / oO0o
   if 86 - 86: iII111i % OoOoOO00 . i11iIiiIii . I1Ii111 + II111iiii . i1IIi
 if ( i11i1111I1I1 != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( I11i11i1 , False ) , OOOo0O00OO00O , green ( Oo00O0o , False ) ,
  # O0 . I1ii11iIi11i / OOooOOo % IiII * Oo0Ooo / OoO0O00
 i11i1111I1I1 ) )
  if 67 - 67: Oo0Ooo * I11i - IiII + I1Ii111
  ooo0oo = oO00Oooo0o0o0 . registered_rlocs
  oo0o = 1440
  if ( o0i1i ) :
   if ( oO00Oooo0o0o0 . site_id != 0 ) :
    O00oOOOOoOO = map_request . source_eid
    ooo0oo = lisp_get_private_rloc_set ( oO00Oooo0o0o0 , O00oOOOOoOO , O0o00oOOOO00 )
    if 7 - 7: IiII - oO0o
   if ( ooo0oo == oO00Oooo0o0o0 . registered_rlocs ) :
    IIiiiIiii = ( oO00Oooo0o0o0 . group . is_null ( ) == False )
    I1III = lisp_get_partial_rloc_set ( ooo0oo , I11oo , IIiiiIiii )
    if ( I1III != ooo0oo ) :
     oo0o = 15
     ooo0oo = I1III
     if 22 - 22: o0oOOo0O0Ooo * I1Ii111 * I1ii11iIi11i . OoOoOO00 . i1IIi % ooOoO0o
     if 67 - 67: I11i
     if 95 - 95: OoO0O00 % I1Ii111
     if 49 - 49: II111iiii % OoOoOO00 % OOooOOo
     if 40 - 40: I1ii11iIi11i + i1IIi
     if 9 - 9: OOooOOo
     if 74 - 74: OoOoOO00 - OOooOOo % OoOoOO00
     if 82 - 82: I11i % IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
  if ( oO00Oooo0o0o0 . force_ttl != None ) :
   oo0o = oO00Oooo0o0o0 . force_ttl | 0x80000000
   if 65 - 65: IiII / O0 * II111iiii + oO0o
   if 52 - 52: o0oOOo0O0Ooo - OoOoOO00 * II111iiii / OoooooooOO
   if 44 - 44: OOooOOo - oO0o + o0oOOo0O0Ooo - i1IIi % o0oOOo0O0Ooo
   if 79 - 79: iII111i . iIii1I11I1II1
   if 42 - 42: i11iIiiIii / IiII . O0 / OOooOOo . iII111i * i1IIi
   if 83 - 83: iIii1I11I1II1 . II111iiii * Oo0Ooo . I1IiiI - I1IiiI - iIii1I11I1II1
  if ( I1Ii ) :
   if ( I1Ii . set_record_ttl ) :
    oo0o = I1Ii . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( oo0o ) )
    if 29 - 29: Oo0Ooo
   if ( I1Ii . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    OOo000 = LISP_POLICY_DENIED_ACTION
    ooo0oo = [ ]
   else :
    oOo00O = I1Ii . set_policy_map_reply ( )
    if ( oOo00O ) : ooo0oo = [ oOo00O ]
    if 35 - 35: OoOoOO00 + II111iiii
    if 46 - 46: O0 / I1ii11iIi11i + OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
    if 96 - 96: IiII + i1IIi - I11i * I11i - OoO0O00 % II111iiii
  if ( i11iii1III1i ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   OOo000 = LISP_POLICY_DENIED_ACTION
   ooo0oo = [ ]
   if 47 - 47: I1Ii111 . i11iIiiIii + oO0o . I1ii11iIi11i
   if 12 - 12: iIii1I11I1II1 % I1Ii111 * OoOoOO00 / OoooooooOO % OoooooooOO
  oO0O0o00oOo = oO00Oooo0o0o0 . echo_nonce_capable
  if 81 - 81: iIii1I11I1II1 - Oo0Ooo - ooOoO0o . OoO0O00 + I1ii11iIi11i
  if 84 - 84: iII111i . OOooOOo . iII111i * oO0o % Ii1I . oO0o
  if 86 - 86: iII111i * ooOoO0o / iIii1I11I1II1 + Ii1I . iII111i
  if 64 - 64: IiII - Oo0Ooo % iII111i % I11i
  if ( O0o ) :
   iIiI1IIi1Ii1i = oO00Oooo0o0o0 . eid
   ii1IIi11i = oO00Oooo0o0o0 . group
  else :
   iIiI1IIi1Ii1i = OOo0O0O0o0
   ii1IIi11i = O0o00oOOOO00
   OOo000 = LISP_AUTH_FAILURE_ACTION
   ooo0oo = [ ]
   if 89 - 89: I1Ii111 / II111iiii . ooOoO0o . oO0o
   if 74 - 74: O0 / I1ii11iIi11i
   if 95 - 95: i11iIiiIii % i11iIiiIii / i1IIi * i11iIiiIii
   if 62 - 62: I1ii11iIi11i . I1IiiI / OOooOOo
   if 94 - 94: IiII
   if 48 - 48: Oo0Ooo + Oo0Ooo / OoO0O00 + OoOoOO00
  packet = lisp_build_map_reply ( iIiI1IIi1Ii1i , ii1IIi11i , ooo0oo ,
 oOO000 , OOo000 , oo0o , False , None , oO0O0o00oOo , False )
  if 23 - 23: iIii1I11I1II1 - OoOoOO00
  if ( o0oo0O ) :
   lisp_process_pubsub ( lisp_sockets , packet , iIiI1IIi1Ii1i , oO00o0o0O ,
 mr_sport , oOO000 , oo0o , oooOOOO0oOo )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , oO00o0o0O , mr_sport )
   if 10 - 10: iIii1I11I1II1 + i1IIi * Ii1I / iIii1I11I1II1 % OoOoOO00 / O0
   if 14 - 14: O0
  return ( [ oO00Oooo0o0o0 . eid , oO00Oooo0o0o0 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 65 - 65: IiII / oO0o
  if 57 - 57: IiII + oO0o - IiII
  if 51 - 51: OoOoOO00 % IiII / iII111i - oO0o - OoO0O00 . iIii1I11I1II1
  if 61 - 61: OoO0O00
  if 60 - 60: I1IiiI % O0 % OoooooooOO / Ii1I
 OOO0Oo0o = len ( oO00Oooo0o0o0 . registered_rlocs )
 if ( OOO0Oo0o == 0 ) :
  lprint ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" . format ( green ( I11i11i1 , False ) , OOOo0O00OO00O ,
  # I1Ii111
 green ( Oo00O0o , False ) ) )
  return ( [ oO00Oooo0o0o0 . eid , oO00Oooo0o0o0 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 19 - 19: I11i % IiII
  if 73 - 73: i11iIiiIii . II111iiii
  if 26 - 26: Oo0Ooo * i1IIi / OoooooooOO
  if 78 - 78: O0 + OOooOOo . I11i * OoOoOO00 - OoooooooOO
  if 92 - 92: o0oOOo0O0Ooo + OoOoOO00 / oO0o . I1Ii111 * I1IiiI * OoOoOO00
 I1iiOo0O0O000 = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 29 - 29: OoOoOO00 + I1IiiI - OoOoOO00
 I1I = map_request . target_eid . hash_address ( I1iiOo0O0O000 )
 I1I %= OOO0Oo0o
 iIi11I11I1i = oO00Oooo0o0o0 . registered_rlocs [ I1I ]
 if 83 - 83: II111iiii
 if ( iIi11I11I1i . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( I11i11i1 , False ) ,
  # iIii1I11I1II1 / i1IIi / ooOoO0o
 OOOo0O00OO00O , green ( Oo00O0o , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( I11i11i1 , False ) ,
  # o0oOOo0O0Ooo % I11i . Oo0Ooo * Oo0Ooo % iII111i
 red ( iIi11I11I1i . rloc . print_address ( ) , False ) , OOOo0O00OO00O ,
 green ( Oo00O0o , False ) ) )
  if 37 - 37: OoO0O00 / I1Ii111 . I1Ii111 * i1IIi
  if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
  if 13 - 13: II111iiii
  if 36 - 36: iII111i - oO0o / Oo0Ooo / O0 . OoO0O00 . i1IIi
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , iIi11I11I1i . rloc , to_etr = True )
  if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
 return ( [ oO00Oooo0o0o0 . eid , oO00Oooo0o0o0 . group , LISP_DDT_ACTION_MS_ACK ] )
 if 98 - 98: oO0o . Oo0Ooo
 if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
 if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
 if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
 if 64 - 64: OoooooooOO + OOooOOo
 if 36 - 36: I1IiiI - Ii1I / I1ii11iIi11i + Oo0Ooo % I1ii11iIi11i
 if 86 - 86: iIii1I11I1II1 * OoO0O00
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 82 - 82: I1IiiI - OoO0O00 % o0oOOo0O0Ooo
 if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
 if 98 - 98: Oo0Ooo . II111iiii * I11i
 if 39 - 39: IiII * o0oOOo0O0Ooo + Ii1I - I11i
 OOo0O0O0o0 = map_request . target_eid
 O0o00oOOOO00 = map_request . target_group
 I11i11i1 = lisp_print_eid_tuple ( OOo0O0O0o0 , O0o00oOOOO00 )
 oOO000 = map_request . nonce
 OOo000 = LISP_DDT_ACTION_NULL
 if 70 - 70: oO0o * ooOoO0o / ooOoO0o - Ii1I * Ii1I % OOooOOo
 if 91 - 91: OoO0O00 - OoO0O00 % O0
 if 67 - 67: ooOoO0o * i1IIi
 if 66 - 66: o0oOOo0O0Ooo - I1ii11iIi11i . OoOoOO00 / iII111i - Ii1I - i1IIi
 if 97 - 97: oO0o % iII111i - OOooOOo . OoooooooOO
 oo0ooo = None
 if ( lisp_i_am_ms ) :
  oO00Oooo0o0o0 = lisp_site_eid_lookup ( OOo0O0O0o0 , O0o00oOOOO00 , False )
  if ( oO00Oooo0o0o0 == None ) : return
  if 58 - 58: I1Ii111 / iII111i / oO0o
  if ( oO00Oooo0o0o0 . registered ) :
   OOo000 = LISP_DDT_ACTION_MS_ACK
   oo0o = 1440
  else :
   OOo0O0O0o0 , O0o00oOOOO00 , OOo000 = lisp_ms_compute_neg_prefix ( OOo0O0O0o0 , O0o00oOOOO00 )
   OOo000 = LISP_DDT_ACTION_MS_NOT_REG
   oo0o = 1
   if 69 - 69: i11iIiiIii / O0 - OoooooooOO + I1ii11iIi11i . OoO0O00
 else :
  oo0ooo = lisp_ddt_cache_lookup ( OOo0O0O0o0 , O0o00oOOOO00 , False )
  if ( oo0ooo == None ) :
   OOo000 = LISP_DDT_ACTION_NOT_AUTH
   oo0o = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( I11i11i1 , False ) ) )
   if 19 - 19: I1IiiI / iII111i . OOooOOo / oO0o + I1ii11iIi11i + OOooOOo
  elif ( oo0ooo . is_auth_prefix ( ) ) :
   if 1 - 1: iIii1I11I1II1
   if 59 - 59: ooOoO0o % I1IiiI + i1IIi * I1Ii111 % o0oOOo0O0Ooo * II111iiii
   if 22 - 22: OoOoOO00 * O0 + OoOoOO00 / iIii1I11I1II1 + oO0o + IiII
   if 69 - 69: iIii1I11I1II1 . I1Ii111 * iII111i
   OOo000 = LISP_DDT_ACTION_DELEGATION_HOLE
   oo0o = 15
   I1I1I1i1I = oo0ooo . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( I1I1I1i1I ,
   # iIii1I11I1II1 / OOooOOo
 green ( I11i11i1 , False ) ) )
   if 2 - 2: I11i - OOooOOo / o0oOOo0O0Ooo
   if ( O0o00oOOOO00 . is_null ( ) ) :
    OOo0O0O0o0 = lisp_ddt_compute_neg_prefix ( OOo0O0O0o0 , oo0ooo ,
 lisp_ddt_cache )
   else :
    O0o00oOOOO00 = lisp_ddt_compute_neg_prefix ( O0o00oOOOO00 , oo0ooo ,
 lisp_ddt_cache )
    OOo0O0O0o0 = lisp_ddt_compute_neg_prefix ( OOo0O0O0o0 , oo0ooo ,
 oo0ooo . source_cache )
    if 14 - 14: I11i + Oo0Ooo + i11iIiiIii - i1IIi . O0
   oo0ooo = None
  else :
   I1I1I1i1I = oo0ooo . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( I1I1I1i1I , green ( I11i11i1 , False ) ) )
   if 47 - 47: o0oOOo0O0Ooo / i1IIi * IiII
   oo0o = 1440
   if 50 - 50: I11i
   if 9 - 9: iII111i . OoOoOO00 * iII111i
   if 54 - 54: i11iIiiIii * I1IiiI / IiII - OoO0O00 % i1IIi
   if 2 - 2: II111iiii - OoOoOO00
   if 81 - 81: IiII / OOooOOo / OoooooooOO + II111iiii - OOooOOo . i11iIiiIii
   if 33 - 33: o0oOOo0O0Ooo - OoooooooOO
 IIii1i = lisp_build_map_referral ( OOo0O0O0o0 , O0o00oOOOO00 , oo0ooo , OOo000 , oo0o , oOO000 )
 oOO000 = map_request . nonce >> 32
 if ( map_request . nonce != 0 and oOO000 != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , IIii1i , ecm_source , port )
 return
 if 30 - 30: i1IIi + II111iiii + OoOoOO00 + I1ii11iIi11i % ooOoO0o % OOooOOo
 if 40 - 40: I1IiiI % I1IiiI - i11iIiiIii % OoOoOO00
 if 17 - 17: ooOoO0o - i1IIi
 if 73 - 73: iIii1I11I1II1 - I1Ii111 % Oo0Ooo . O0
 if 16 - 16: OoO0O00 / Oo0Ooo / IiII . Oo0Ooo - OoooooooOO
 if 5 - 5: OoOoOO00 . I11i
 if 28 - 28: I11i % OOooOOo + Oo0Ooo / OoO0O00 % o0oOOo0O0Ooo + OoO0O00
 if 20 - 20: ooOoO0o . iII111i % OOooOOo + i11iIiiIii
 if 64 - 64: i1IIi . o0oOOo0O0Ooo * I1Ii111 - O0
 if 76 - 76: I1IiiI % Ii1I + OoO0O00 + I1ii11iIi11i * II111iiii + Oo0Ooo
 if 3 - 3: Ii1I - I1IiiI + O0
 if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
 if 45 - 45: OoooooooOO / oO0o . I1ii11iIi11i + OOooOOo
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 O0OOoOoO = eid . hash_address ( entry_prefix )
 o00Oo0o0oO = eid . addr_length ( ) * 8
 iIi1iii1 = 0
 if 67 - 67: o0oOOo0O0Ooo - Ii1I
 if 29 - 29: OoOoOO00 . I1ii11iIi11i
 if 24 - 24: OOooOOo + i1IIi . I11i . OoOoOO00 + OoooooooOO
 if 98 - 98: ooOoO0o + i1IIi / I1IiiI
 for iIi1iii1 in range ( o00Oo0o0oO ) :
  i1I = 1 << ( o00Oo0o0oO - iIi1iii1 - 1 )
  if ( O0OOoOoO & i1I ) : break
  if 20 - 20: II111iiii . IiII
  if 10 - 10: IiII / OoooooooOO * IiII
 if ( iIi1iii1 > neg_prefix . mask_len ) : neg_prefix . mask_len = iIi1iii1
 return
 if 22 - 22: I1ii11iIi11i * OoooooooOO
 if 22 - 22: II111iiii . Ii1I + iIii1I11I1II1
 if 91 - 91: II111iiii / iIii1I11I1II1 / OoOoOO00 . II111iiii
 if 58 - 58: OoOoOO00 - II111iiii
 if 77 - 77: I1ii11iIi11i
 if 72 - 72: I1IiiI - i1IIi
 if 11 - 11: iIii1I11I1II1 . OoO0O00 * Ii1I
 if 65 - 65: Oo0Ooo / OoooooooOO
 if 60 - 60: II111iiii + I1IiiI % oO0o - o0oOOo0O0Ooo
 if 50 - 50: iIii1I11I1II1 - i11iIiiIii / iII111i + ooOoO0o / OOooOOo
def lisp_neg_prefix_walk ( entry , parms ) :
 OOo0O0O0o0 , o0o0o , iiiii1ii11iI = parms
 if 64 - 64: OoooooooOO + i11iIiiIii / O0 % OoO0O00 / OoO0O00
 if ( o0o0o == None ) :
  if ( entry . eid . instance_id != OOo0O0O0o0 . instance_id ) :
   return ( [ True , parms ] )
   if 74 - 74: i11iIiiIii . I1ii11iIi11i % I11i + I1Ii111
  if ( entry . eid . afi != OOo0O0O0o0 . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( o0o0o ) == False ) :
   return ( [ True , parms ] )
   if 61 - 61: IiII . I1Ii111 . I11i - I1IiiI . iII111i + II111iiii
   if 9 - 9: I1Ii111 . iIii1I11I1II1 / O0 * i11iIiiIii
   if 91 - 91: ooOoO0o / I1Ii111 . OoO0O00 - IiII * ooOoO0o
   if 64 - 64: OoooooooOO
   if 56 - 56: I11i / iIii1I11I1II1 - OoOoOO00 . Oo0Ooo + oO0o - ooOoO0o
   if 51 - 51: O0 . O0
 lisp_find_negative_mask_len ( OOo0O0O0o0 , entry . eid , iiiii1ii11iI )
 return ( [ True , parms ] )
 if 9 - 9: Oo0Ooo . i1IIi - i1IIi + I1Ii111 * ooOoO0o . I1ii11iIi11i
 if 17 - 17: I11i * I1ii11iIi11i % I1IiiI + OoO0O00 + IiII
 if 90 - 90: OoooooooOO - I1IiiI / I1ii11iIi11i + oO0o - o0oOOo0O0Ooo
 if 84 - 84: OoOoOO00 + O0 % Oo0Ooo
 if 22 - 22: iIii1I11I1II1 % i11iIiiIii
 if 29 - 29: ooOoO0o - iII111i + IiII % Ii1I - oO0o - ooOoO0o
 if 43 - 43: oO0o
 if 22 - 22: I1Ii111 + i11iIiiIii
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 49 - 49: O0 % II111iiii . OOooOOo + iII111i + iIii1I11I1II1 / i11iIiiIii
 if 79 - 79: II111iiii + ooOoO0o - i1IIi - i1IIi + II111iiii . i1IIi
 if 78 - 78: I1IiiI * I11i % OOooOOo + Ii1I + OoOoOO00
 if 23 - 23: iII111i / Oo0Ooo % OoooooooOO * OoooooooOO . iII111i / I1ii11iIi11i
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 30 - 30: oO0o - OoOoOO00 . I1IiiI
 iiiii1ii11iI = lisp_address ( eid . afi , "" , 0 , 0 )
 iiiii1ii11iI . copy_address ( eid )
 iiiii1ii11iI . mask_len = 0
 if 17 - 17: OoOoOO00
 OO00oo0Oo = ddt_entry . print_eid_tuple ( )
 o0o0o = ddt_entry . eid
 if 88 - 88: O0 - i1IIi . II111iiii - O0 + O0 / I1ii11iIi11i
 if 9 - 9: iIii1I11I1II1
 if 57 - 57: i1IIi * OOooOOo
 if 35 - 35: I1Ii111 / Oo0Ooo * OoooooooOO / O0 / iIii1I11I1II1
 if 44 - 44: o0oOOo0O0Ooo / iIii1I11I1II1
 eid , o0o0o , iiiii1ii11iI = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , o0o0o , iiiii1ii11iI ) )
 if 40 - 40: OoO0O00 / O0
 if 60 - 60: iIii1I11I1II1 / Oo0Ooo / oO0o + iII111i
 if 66 - 66: iIii1I11I1II1 . O0 * IiII . ooOoO0o + i1IIi
 if 83 - 83: o0oOOo0O0Ooo / II111iiii + I1IiiI - iII111i + OoO0O00
 iiiii1ii11iI . mask_address ( iiiii1ii11iI . mask_len )
 if 67 - 67: I1Ii111 - OoOoOO00 . i11iIiiIii - I1Ii111 . i11iIiiIii
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # I11i + I11i
 OO00oo0Oo , iiiii1ii11iI . print_prefix ( ) ) )
 return ( iiiii1ii11iI )
 if 42 - 42: OoOoOO00 % I1IiiI * Oo0Ooo * II111iiii + O0 - II111iiii
 if 97 - 97: I1IiiI
 if 87 - 87: I11i + iIii1I11I1II1
 if 91 - 91: oO0o
 if 58 - 58: i11iIiiIii / Ii1I - OoooooooOO
 if 25 - 25: i1IIi * ooOoO0o % OOooOOo / I1IiiI
 if 75 - 75: i11iIiiIii
 if 38 - 38: iIii1I11I1II1
def lisp_ms_compute_neg_prefix ( eid , group ) :
 iiiii1ii11iI = lisp_address ( eid . afi , "" , 0 , 0 )
 iiiii1ii11iI . copy_address ( eid )
 iiiii1ii11iI . mask_len = 0
 o0o00o0 = lisp_address ( group . afi , "" , 0 , 0 )
 o0o00o0 . copy_address ( group )
 o0o00o0 . mask_len = 0
 o0o0o = None
 if 48 - 48: I1Ii111
 if 91 - 91: ooOoO0o / II111iiii % iIii1I11I1II1
 if 70 - 70: i1IIi - II111iiii / I1IiiI + OoooooooOO + i11iIiiIii / i1IIi
 if 80 - 80: i1IIi - iIii1I11I1II1 + OoooooooOO + ooOoO0o / IiII - I1ii11iIi11i
 if 90 - 90: I1IiiI * ooOoO0o - I11i + O0 - I11i
 if ( group . is_null ( ) ) :
  oo0ooo = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( oo0ooo == None ) :
   iiiii1ii11iI . mask_len = iiiii1ii11iI . host_mask_len ( )
   o0o00o0 . mask_len = o0o00o0 . host_mask_len ( )
   return ( [ iiiii1ii11iI , o0o00o0 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 59 - 59: OOooOOo % II111iiii
  iiIii = lisp_sites_by_eid
  if ( oo0ooo . is_auth_prefix ( ) ) : o0o0o = oo0ooo . eid
 else :
  oo0ooo = lisp_ddt_cache . lookup_cache ( group , False )
  if ( oo0ooo == None ) :
   iiiii1ii11iI . mask_len = iiiii1ii11iI . host_mask_len ( )
   o0o00o0 . mask_len = o0o00o0 . host_mask_len ( )
   return ( [ iiiii1ii11iI , o0o00o0 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 38 - 38: IiII . IiII
  if ( oo0ooo . is_auth_prefix ( ) ) : o0o0o = oo0ooo . group
  if 53 - 53: II111iiii + Ii1I * o0oOOo0O0Ooo
  group , o0o0o , o0o00o0 = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , o0o0o , o0o00o0 ) )
  if 47 - 47: Ii1I % OOooOOo . Oo0Ooo
  if 94 - 94: Ii1I - iIii1I11I1II1 + I1IiiI - iIii1I11I1II1 . o0oOOo0O0Ooo
  o0o00o0 . mask_address ( o0o00o0 . mask_len )
  if 3 - 3: O0 / I11i + OoOoOO00 % IiII / i11iIiiIii
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , o0o0o . print_prefix ( ) if ( o0o0o != None ) else "'not found'" ,
  # i1IIi + II111iiii
  # iIii1I11I1II1 - O0 % Oo0Ooo * OoooooooOO / I1IiiI
  # I11i % i1IIi - I1ii11iIi11i . Oo0Ooo
 o0o00o0 . print_prefix ( ) ) )
  if 69 - 69: ooOoO0o * OoO0O00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
  iiIii = oo0ooo . source_cache
  if 35 - 35: I1IiiI . OOooOOo * OoO0O00 . I1ii11iIi11i - I1IiiI
  if 5 - 5: i1IIi * II111iiii
  if 64 - 64: I1IiiI * iIii1I11I1II1 % I1Ii111
  if 22 - 22: OoooooooOO + I1Ii111 . o0oOOo0O0Ooo * Oo0Ooo
  if 61 - 61: iIii1I11I1II1
 OOo000 = LISP_DDT_ACTION_DELEGATION_HOLE if ( o0o0o != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 95 - 95: I1ii11iIi11i + IiII * Ii1I - IiII
 if 58 - 58: I1ii11iIi11i - oO0o % I11i * O0
 if 43 - 43: OoOoOO00 + O0
 if 71 - 71: ooOoO0o * I1IiiI / I1ii11iIi11i
 if 8 - 8: I1Ii111 / iIii1I11I1II1
 if 29 - 29: i11iIiiIii % i1IIi + oO0o . I1ii11iIi11i
 eid , o0o0o , iiiii1ii11iI = iiIii . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , o0o0o , iiiii1ii11iI ) )
 if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
 if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
 if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
 if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
 iiiii1ii11iI . mask_address ( iiiii1ii11iI . mask_len )
 if 53 - 53: OOooOOo / I11i + OOooOOo / I1IiiI / OoO0O00
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # o0oOOo0O0Ooo
 # i1IIi . i11iIiiIii * IiII * I11i % I1IiiI
 o0o0o . print_prefix ( ) if ( o0o0o != None ) else "'not found'" , iiiii1ii11iI . print_prefix ( ) ) )
 if 67 - 67: O0 . I1Ii111 + ooOoO0o
 if 88 - 88: I1Ii111 . O0 - oO0o + i1IIi % Oo0Ooo
 return ( [ iiiii1ii11iI , o0o00o0 , OOo000 ] )
 if 39 - 39: I1Ii111 - I1IiiI
 if 18 - 18: i1IIi
 if 42 - 42: II111iiii - i1IIi . oO0o % OOooOOo % ooOoO0o - i11iIiiIii
 if 23 - 23: OOooOOo + iIii1I11I1II1 - i1IIi
 if 72 - 72: OOooOOo . I1IiiI * O0 + i11iIiiIii - iII111i
 if 79 - 79: o0oOOo0O0Ooo + I1ii11iIi11i
 if 46 - 46: I11i
 if 78 - 78: IiII / II111iiii
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 55 - 55: Oo0Ooo
 OOo0O0O0o0 = map_request . target_eid
 O0o00oOOOO00 = map_request . target_group
 oOO000 = map_request . nonce
 if 80 - 80: o0oOOo0O0Ooo - I1Ii111 * O0 * iIii1I11I1II1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : oo0o = 1440
 if 59 - 59: I1ii11iIi11i + I11i / OoO0O00
 if 36 - 36: o0oOOo0O0Ooo + ooOoO0o * I11i
 if 81 - 81: OOooOOo * I11i - I1ii11iIi11i
 if 82 - 82: I1ii11iIi11i * II111iiii - OoooooooOO % iII111i * I1IiiI % OoOoOO00
 O0OOoOoOO = lisp_map_referral ( )
 O0OOoOoOO . record_count = 1
 O0OOoOoOO . nonce = oOO000
 IIii1i = O0OOoOoOO . encode ( )
 O0OOoOoOO . print_map_referral ( )
 if 81 - 81: I11i + o0oOOo0O0Ooo / iII111i
 IiiIIiIi1i11i = False
 if 35 - 35: ooOoO0o % I11i * I1ii11iIi11i
 if 10 - 10: OoO0O00 + OoooooooOO + I1Ii111
 if 57 - 57: Ii1I % Ii1I * Oo0Ooo % i11iIiiIii
 if 12 - 12: oO0o . Oo0Ooo . I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
 if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
 if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( OOo0O0O0o0 ,
 O0o00oOOOO00 )
  oo0o = 15
  if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : oo0o = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : oo0o = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : oo0o = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : oo0o = 0
 if 66 - 66: iII111i % iII111i
 oooO0oOOOO0 = False
 OOO0Oo0o = 0
 oo0ooo = lisp_ddt_cache_lookup ( OOo0O0O0o0 , O0o00oOOOO00 , False )
 if ( oo0ooo != None ) :
  OOO0Oo0o = len ( oo0ooo . delegation_set )
  oooO0oOOOO0 = oo0ooo . is_ms_peer_entry ( )
  oo0ooo . map_referrals_sent += 1
  if 25 - 25: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoooooooOO . i1IIi
  if 10 - 10: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / i11iIiiIii - I1IiiI . O0
  if 2 - 2: II111iiii
  if 13 - 13: Ii1I % i11iIiiIii
  if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : IiiIIiIi1i11i = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  IiiIIiIi1i11i = ( oooO0oOOOO0 == False )
  if 50 - 50: I1ii11iIi11i + iII111i
  if 64 - 64: oO0o
  if 11 - 11: o0oOOo0O0Ooo
  if 95 - 95: i1IIi . ooOoO0o . Oo0Ooo
  if 13 - 13: OOooOOo - Oo0Ooo % O0 . I1Ii111
 iiI = lisp_eid_record ( )
 iiI . rloc_count = OOO0Oo0o
 iiI . authoritative = True
 iiI . action = action
 iiI . ddt_incomplete = IiiIIiIi1i11i
 iiI . eid = eid_prefix
 iiI . group = group_prefix
 iiI . record_ttl = oo0o
 if 66 - 66: I1IiiI + I11i
 IIii1i += iiI . encode ( )
 iiI . print_record ( "  " , True )
 if 58 - 58: I1ii11iIi11i
 if 7 - 7: oO0o - I11i
 if 59 - 59: Ii1I / o0oOOo0O0Ooo / OoO0O00 + IiII + i11iIiiIii
 if 64 - 64: o0oOOo0O0Ooo * IiII * IiII * iII111i % i11iIiiIii
 if ( OOO0Oo0o != 0 ) :
  for ii1iII11 in oo0ooo . delegation_set :
   iIii1IiIiI = lisp_rloc_record ( )
   iIii1IiIiI . rloc = ii1iII11 . delegate_address
   iIii1IiIiI . priority = ii1iII11 . priority
   iIii1IiIiI . weight = ii1iII11 . weight
   iIii1IiIiI . mpriority = 255
   iIii1IiIiI . mweight = 0
   iIii1IiIiI . reach_bit = True
   IIii1i += iIii1IiIiI . encode ( )
   iIii1IiIiI . print_record ( "    " )
   if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
   if 10 - 10: OOooOOo / I1ii11iIi11i
   if 21 - 21: OoO0O00 % Oo0Ooo . o0oOOo0O0Ooo + IiII
   if 48 - 48: O0 / i1IIi / iII111i
   if 11 - 11: O0 - OoO0O00 + OoOoOO00 * ooOoO0o - Ii1I
   if 82 - 82: Ii1I - O0 * ooOoO0o . ooOoO0o
   if 32 - 32: o0oOOo0O0Ooo . OoooooooOO % OOooOOo
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , IIii1i , ecm_source , port )
 return
 if 2 - 2: OoOoOO00 + I1ii11iIi11i + oO0o
 if 27 - 27: OoooooooOO - Ii1I / OoooooooOO + OoO0O00
 if 58 - 58: OOooOOo * I11i . I1IiiI
 if 46 - 46: I11i + II111iiii * iII111i % ooOoO0o - I1IiiI
 if 73 - 73: I1ii11iIi11i * iIii1I11I1II1 . I1Ii111 - Ii1I
 if 11 - 11: I11i
 if 48 - 48: IiII / O0
 if 46 - 46: ooOoO0o + oO0o
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 7 - 7: ooOoO0o * oO0o . i1IIi
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # IiII * OoO0O00 / OoooooooOO % o0oOOo0O0Ooo + OoO0O00
 red ( dest . print_address ( ) , False ) ) )
 if 25 - 25: IiII % OOooOOo + Ii1I * I1ii11iIi11i
 OOo000 = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 25 - 25: iIii1I11I1II1 * OoOoOO00 % I1IiiI + IiII
 if 34 - 34: ooOoO0o - OoooooooOO . o0oOOo0O0Ooo
 if 83 - 83: II111iiii . OOooOOo
 if 88 - 88: O0
 if 12 - 12: Ii1I % OOooOOo % Oo0Ooo * I1Ii111
 if ( lisp_get_eid_hash ( eid ) != None ) :
  OOo000 = LISP_SEND_MAP_REQUEST_ACTION
  if 96 - 96: iII111i + ooOoO0o
  if 100 - 100: OOooOOo . ooOoO0o + Ii1I + Ii1I
 IIii1i = lisp_build_map_reply ( eid , group , [ ] , nonce , OOo000 , ttl , False ,
 None , False , False )
 if 70 - 70: ooOoO0o . iIii1I11I1II1 / oO0o
 if 18 - 18: Ii1I / OoooooooOO % i1IIi * o0oOOo0O0Ooo
 if 70 - 70: IiII % i1IIi / IiII - o0oOOo0O0Ooo . Oo0Ooo / O0
 if 54 - 54: o0oOOo0O0Ooo
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , IIii1i , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , IIii1i , dest , port )
  if 53 - 53: II111iiii / IiII . i1IIi + I1Ii111 / OoO0O00 - OoooooooOO
 return
 if 67 - 67: ooOoO0o . Ii1I - Oo0Ooo * iII111i . I11i - OOooOOo
 if 10 - 10: I11i
 if 37 - 37: o0oOOo0O0Ooo / I1IiiI * oO0o / II111iiii
 if 39 - 39: IiII - i1IIi - IiII - OoooooooOO - I1ii11iIi11i
 if 66 - 66: IiII + i1IIi
 if 21 - 21: IiII / i11iIiiIii / OoOoOO00
 if 75 - 75: Ii1I . i1IIi / I1IiiI * iII111i . IiII / OoOoOO00
def lisp_retransmit_ddt_map_request ( mr ) :
 O0oOo0o = mr . mr_source . print_address ( )
 ooO0O00OOoo0O = mr . print_eid_tuple ( )
 oOO000 = mr . nonce
 if 34 - 34: ooOoO0o * IiII . Ii1I + iIii1I11I1II1
 if 1 - 1: i11iIiiIii + I11i
 if 78 - 78: Ii1I % Oo0Ooo / OoO0O00 . iIii1I11I1II1 . II111iiii
 if 67 - 67: oO0o % I1Ii111
 if 72 - 72: I1IiiI . i11iIiiIii . OoOoOO00 + I1IiiI - I1Ii111 + iII111i
 if ( mr . last_request_sent_to ) :
  i11i11 = mr . last_request_sent_to . print_address ( )
  o0ooo000OO = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( o0ooo000OO and o0ooo000OO . referral_set . has_key ( i11i11 ) ) :
   o0ooo000OO . referral_set [ i11i11 ] . no_responses += 1
   if 17 - 17: I1IiiI . i11iIiiIii * OoO0O00 + II111iiii
   if 34 - 34: Ii1I - O0 + Ii1I + I11i + I1ii11iIi11i . Ii1I
   if 56 - 56: Ii1I
   if 58 - 58: iII111i
   if 18 - 18: O0 * OoooooooOO % IiII - iIii1I11I1II1 % IiII * o0oOOo0O0Ooo
   if 13 - 13: OoO0O00 + i11iIiiIii + O0 / ooOoO0o % iIii1I11I1II1
   if 75 - 75: oO0o / i1IIi / Ii1I * Oo0Ooo
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( ooO0O00OOoo0O , False ) , lisp_hex_string ( oOO000 ) ) )
  if 75 - 75: Oo0Ooo / OoooooooOO
  mr . dequeue_map_request ( )
  return
  if 98 - 98: II111iiii - I1Ii111 . ooOoO0o * iII111i
  if 49 - 49: I1ii11iIi11i / OoooooooOO - I11i
 mr . retry_count += 1
 if 76 - 76: i1IIi . OoO0O00 . O0 / OOooOOo - iII111i
 IiII1iiI = green ( O0oOo0o , False )
 OooOOOoOoo0O0 = green ( ooO0O00OOoo0O , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # I1IiiI . ooOoO0o . II111iiii % OOooOOo
 red ( mr . itr . print_address ( ) , False ) , IiII1iiI , OooOOOoOoo0O0 ,
 lisp_hex_string ( oOO000 ) ) )
 if 86 - 86: i11iIiiIii + I1ii11iIi11i / OoOoOO00 * OoooooooOO
 if 6 - 6: II111iiii
 if 26 - 26: iIii1I11I1II1 / iIii1I11I1II1 . IiII * i11iIiiIii
 if 21 - 21: OOooOOo + o0oOOo0O0Ooo
 lisp_send_ddt_map_request ( mr , False )
 if 28 - 28: OOooOOo + i1IIi + II111iiii / Oo0Ooo + iIii1I11I1II1 . Oo0Ooo
 if 73 - 73: Ii1I * iIii1I11I1II1 / o0oOOo0O0Ooo - o0oOOo0O0Ooo / i1IIi
 if 64 - 64: Ii1I * I1ii11iIi11i % II111iiii
 if 31 - 31: iIii1I11I1II1 % Oo0Ooo . I1IiiI % ooOoO0o
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 38 - 38: I1ii11iIi11i + I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
 if 46 - 46: iII111i
 if 56 - 56: Oo0Ooo / II111iiii
 if 61 - 61: Ii1I - i1IIi / ooOoO0o - Oo0Ooo / IiII % Oo0Ooo
 if 53 - 53: OoooooooOO + iII111i % II111iiii * IiII
 if 10 - 10: OoOoOO00 % I11i
 if 46 - 46: i1IIi % IiII
 if 45 - 45: I1ii11iIi11i / I1ii11iIi11i - OoO0O00
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 54 - 54: Ii1I + I1IiiI * OoOoOO00 + oO0o
 if 10 - 10: Ii1I - I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
 if 75 - 75: OOooOOo . ooOoO0o
 if 32 - 32: i1IIi / I11i + iIii1I11I1II1 . OOooOOo
 O00O0OOOo = [ ]
 for ii in referral . referral_set . values ( ) :
  if ( ii . updown == False ) : continue
  if ( len ( O00O0OOOo ) == 0 or O00O0OOOo [ 0 ] . priority == ii . priority ) :
   O00O0OOOo . append ( ii )
  elif ( O00O0OOOo [ 0 ] . priority > ii . priority ) :
   O00O0OOOo = [ ]
   O00O0OOOo . append ( ii )
   if 54 - 54: I1Ii111 * OoO0O00
   if 94 - 94: iIii1I11I1II1
   if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
 oOOOOOo = len ( O00O0OOOo )
 if ( oOOOOOo == 0 ) : return ( None )
 if 96 - 96: OoO0O00 - II111iiii - I1IiiI % ooOoO0o
 I1I = dest_eid . hash_address ( source_eid )
 I1I = I1I % oOOOOOo
 return ( O00O0OOOo [ I1I ] )
 if 78 - 78: I11i / Ii1I . IiII / o0oOOo0O0Ooo / OoO0O00 + OoOoOO00
 if 50 - 50: Ii1I
 if 84 - 84: iII111i % II111iiii
 if 31 - 31: I11i
 if 28 - 28: i11iIiiIii + IiII / I11i . Ii1I / OoO0O00
 if 100 - 100: o0oOOo0O0Ooo - I11i . o0oOOo0O0Ooo
 if 90 - 90: OoOoOO00 / II111iiii / I11i * I11i - iIii1I11I1II1
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 o0OoOO00O0O0 = mr . lisp_sockets
 oOO000 = mr . nonce
 III1iii1 = mr . itr
 O0o0000o00oOO = mr . mr_source
 I11i11i1 = mr . print_eid_tuple ( )
 if 80 - 80: iIii1I11I1II1 + I11i / oO0o . I1Ii111 + I11i
 if 26 - 26: Oo0Ooo . i11iIiiIii % I1Ii111 . Oo0Ooo + Oo0Ooo + OoOoOO00
 if 100 - 100: IiII * I11i - OOooOOo
 if 11 - 11: I1IiiI % Ii1I + II111iiii
 if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( I11i11i1 , False ) , lisp_hex_string ( oOO000 ) ) )
  if 63 - 63: OoOoOO00 % IiII . iII111i
  mr . dequeue_map_request ( )
  return
  if 44 - 44: I1IiiI
  if 25 - 25: oO0o
  if 100 - 100: I1IiiI / IiII + OoO0O00 . iII111i
  if 39 - 39: OoooooooOO * OOooOOo - OoO0O00
  if 3 - 3: I11i . i11iIiiIii % Oo0Ooo % II111iiii . I11i
  if 88 - 88: iIii1I11I1II1 . OOooOOo % iII111i
 if ( send_to_root ) :
  o0oooOo = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  OOOooo000O = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( I11i11i1 , False ) ) )
 else :
  o0oooOo = mr . eid
  OOOooo000O = mr . group
  if 67 - 67: i1IIi * i11iIiiIii * I1IiiI
  if 23 - 23: Oo0Ooo
  if 81 - 81: I1Ii111 % II111iiii - Oo0Ooo / I1IiiI + i11iIiiIii . I11i
  if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
  if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
 OOoO = lisp_referral_cache_lookup ( o0oooOo , OOOooo000O , False )
 if ( OOoO == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( o0OoOO00O0O0 , o0oooOo , OOOooo000O ,
 oOO000 , III1iii1 , mr . sport , 15 , None , False )
  return
  if 34 - 34: OoOoOO00 + I1ii11iIi11i % Ii1I
  if 70 - 70: i1IIi * II111iiii * I1IiiI
 Ii1i1Ii = OOoO . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( Ii1i1Ii ,
 OOoO . print_referral_type ( ) ) )
 if 7 - 7: OoooooooOO + II111iiii / Oo0Ooo % O0 % OOooOOo . I1Ii111
 ii = lisp_get_referral_node ( OOoO , O0o0000o00oOO , mr . eid )
 if ( ii == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( o0OoOO00O0O0 , OOoO . eid ,
 OOoO . group , oOO000 , III1iii1 , mr . sport , 1 , None , False )
  return
  if 78 - 78: iIii1I11I1II1 % OOooOOo
  if 27 - 27: I11i + ooOoO0o - II111iiii . OoooooooOO % O0 % I1ii11iIi11i
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( ii . referral_address . print_address ( ) ,
 # I1ii11iIi11i % IiII
 OOoO . print_referral_type ( ) , green ( I11i11i1 , False ) ,
 lisp_hex_string ( oOO000 ) ) )
 if 66 - 66: I1Ii111 % I1ii11iIi11i
 if 77 - 77: I11i % iIii1I11I1II1 . iIii1I11I1II1 + oO0o % i11iIiiIii . IiII
 if 33 - 33: IiII - OOooOOo / i11iIiiIii * iIii1I11I1II1
 if 2 - 2: i11iIiiIii % ooOoO0o
 O0O00OO0O0 = ( OOoO . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 OOoO . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( o0OoOO00O0O0 , mr . packet , O0o0000o00oOO , mr . sport , mr . eid ,
 ii . referral_address , to_ms = O0O00OO0O0 , ddt = True )
 if 60 - 60: OoooooooOO
 if 11 - 11: OoO0O00 . OoO0O00
 if 31 - 31: iIii1I11I1II1
 if 64 - 64: ooOoO0o
 mr . last_request_sent_to = ii . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 ii . map_requests_sent += 1
 return
 if 30 - 30: OoO0O00 + o0oOOo0O0Ooo / iIii1I11I1II1
 if 69 - 69: IiII - OoooooooOO + iII111i + iII111i - Ii1I
 if 27 - 27: I1ii11iIi11i % Oo0Ooo * iIii1I11I1II1 * O0 / I11i * Oo0Ooo
 if 97 - 97: IiII % Oo0Ooo % OoOoOO00
 if 87 - 87: i11iIiiIii . oO0o * I1IiiI * I1Ii111
 if 57 - 57: iIii1I11I1II1 / i11iIiiIii / IiII + I1ii11iIi11i % I1IiiI
 if 80 - 80: iIii1I11I1II1
 if 23 - 23: II111iiii . ooOoO0o % I1Ii111
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 39 - 39: OoooooooOO
 OOo0O0O0o0 = map_request . target_eid
 O0o00oOOOO00 = map_request . target_group
 ooO0O00OOoo0O = map_request . print_eid_tuple ( )
 O0oOo0o = mr_source . print_address ( )
 oOO000 = map_request . nonce
 if 10 - 10: Oo0Ooo * iII111i
 IiII1iiI = green ( O0oOo0o , False )
 OooOOOoOoo0O0 = green ( ooO0O00OOoo0O , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # I1IiiI + o0oOOo0O0Ooo + I1IiiI . I1ii11iIi11i - I1IiiI
 red ( ecm_source . print_address ( ) , False ) , IiII1iiI , OooOOOoOoo0O0 ,
 lisp_hex_string ( oOO000 ) ) )
 if 97 - 97: oO0o + iII111i * OoOoOO00 % o0oOOo0O0Ooo
 if 57 - 57: OoooooooOO . Oo0Ooo + OoooooooOO + I1Ii111 + iIii1I11I1II1 + OoOoOO00
 if 69 - 69: OoO0O00
 if 24 - 24: i1IIi + o0oOOo0O0Ooo / oO0o - I1IiiI % I1IiiI
 O0o00000o0O = lisp_ddt_map_request ( lisp_sockets , packet , OOo0O0O0o0 , O0o00oOOOO00 , oOO000 )
 O0o00000o0O . packet = packet
 O0o00000o0O . itr = ecm_source
 O0o00000o0O . mr_source = mr_source
 O0o00000o0O . sport = sport
 O0o00000o0O . from_pitr = map_request . pitr_bit
 O0o00000o0O . queue_map_request ( )
 if 68 - 68: iIii1I11I1II1
 lisp_send_ddt_map_request ( O0o00000o0O , False )
 return
 if 30 - 30: I11i . I1ii11iIi11i - i1IIi / i1IIi + IiII . oO0o
 if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
 if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
 if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
 if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
 if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
 if 45 - 45: iIii1I11I1II1 . o0oOOo0O0Ooo % I1IiiI
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl ) :
 if 10 - 10: I1IiiI / i1IIi * o0oOOo0O0Ooo + Oo0Ooo - OoOoOO00 % iII111i
 OO0o0 = packet
 o00oo00OOOO = lisp_map_request ( )
 packet = o00oo00OOOO . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 60 - 60: IiII + ooOoO0o - iII111i
  if 69 - 69: iIii1I11I1II1 + oO0o
 o00oo00OOOO . print_map_request ( )
 if 16 - 16: OoO0O00 / I11i * OoOoOO00 % OoO0O00 * oO0o * o0oOOo0O0Ooo
 if 80 - 80: o0oOOo0O0Ooo % I11i + O0 % i1IIi
 if 58 - 58: oO0o / I1ii11iIi11i * O0 % I11i
 if 34 - 34: oO0o / O0 * oO0o
 if ( o00oo00OOOO . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , o00oo00OOOO ,
 mr_source , mr_port , ttl )
  return
  if 47 - 47: iIii1I11I1II1 - o0oOOo0O0Ooo % Ii1I
  if 38 - 38: ooOoO0o / IiII * I1ii11iIi11i % I1ii11iIi11i % oO0o
  if 82 - 82: I1ii11iIi11i . i11iIiiIii - I11i . iII111i / OOooOOo
  if 60 - 60: I1IiiI / I1IiiI / II111iiii
  if 59 - 59: OOooOOo . oO0o + ooOoO0o % o0oOOo0O0Ooo . i11iIiiIii
 if ( o00oo00OOOO . smr_bit ) :
  lisp_process_smr ( o00oo00OOOO )
  if 27 - 27: OoOoOO00 - OoooooooOO / IiII / II111iiii * OOooOOo * ooOoO0o
  if 43 - 43: II111iiii . IiII - I1IiiI * I1ii11iIi11i + OoooooooOO
  if 34 - 34: I1Ii111 / i1IIi
  if 95 - 95: OoOoOO00 * OOooOOo
  if 68 - 68: I1Ii111 / iIii1I11I1II1 % Ii1I
 if ( o00oo00OOOO . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( o00oo00OOOO )
  if 77 - 77: i11iIiiIii + i11iIiiIii - I1ii11iIi11i % I1ii11iIi11i
  if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
  if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
  if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
  if 77 - 77: OOooOOo + ooOoO0o / O0
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , o00oo00OOOO , mr_source ,
 mr_port , ttl )
  if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
  if 49 - 49: ooOoO0o . Ii1I
  if 75 - 75: OOooOOo / II111iiii - Oo0Ooo + I1Ii111
  if 42 - 42: OoooooooOO * II111iiii + Ii1I % OoO0O00 / I1Ii111
  if 11 - 11: ooOoO0o / Oo0Ooo + i1IIi / IiII
 if ( lisp_i_am_ms ) :
  packet = OO0o0
  OOo0O0O0o0 , O0o00oOOOO00 , i1I1iiIii = lisp_ms_process_map_request ( lisp_sockets ,
 OO0o0 , o00oo00OOOO , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , o00oo00OOOO , ecm_source ,
 ecm_port , i1I1iiIii , OOo0O0O0o0 , O0o00oOOOO00 )
   if 93 - 93: OOooOOo . O0 + IiII - iII111i * iII111i
  return
  if 6 - 6: iIii1I11I1II1 * i1IIi
  if 66 - 66: OoooooooOO * I11i * ooOoO0o % oO0o - Oo0Ooo
  if 17 - 17: Ii1I * I1ii11iIi11i - OoO0O00 - O0 + o0oOOo0O0Ooo + I1ii11iIi11i
  if 78 - 78: OOooOOo * Oo0Ooo * Ii1I
  if 94 - 94: OoooooooOO % iII111i
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , OO0o0 , o00oo00OOOO ,
 ecm_source , mr_port , mr_source )
  if 48 - 48: iIii1I11I1II1
  if 25 - 25: i1IIi % o0oOOo0O0Ooo . iII111i / OoooooooOO + i1IIi
  if 76 - 76: Oo0Ooo / OOooOOo + ooOoO0o % OoooooooOO - Oo0Ooo - I11i
  if 36 - 36: OoO0O00 . Oo0Ooo * I1ii11iIi11i
  if 16 - 16: IiII + OOooOOo
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = OO0o0
  lisp_ddt_process_map_request ( lisp_sockets , o00oo00OOOO , ecm_source ,
 ecm_port )
  if 33 - 33: ooOoO0o . i11iIiiIii + OOooOOo
 return
 if 77 - 77: OoooooooOO * Ii1I * iIii1I11I1II1 + IiII
 if 53 - 53: IiII + I1Ii111 + oO0o
 if 31 - 31: OOooOOo + OoOoOO00 * OOooOOo + OoOoOO00 / o0oOOo0O0Ooo . iIii1I11I1II1
 if 1 - 1: I1Ii111 * i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / Oo0Ooo
 if 3 - 3: OOooOOo - i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
 if 60 - 60: OoOoOO00 / i1IIi . Ii1I - OoO0O00 - OoooooooOO
 if 39 - 39: I1IiiI + i1IIi * OoO0O00 % I11i
 if 41 - 41: I1ii11iIi11i * IiII
def lisp_store_mr_stats ( source , nonce ) :
 O0o00000o0O = lisp_get_map_resolver ( source , None )
 if ( O0o00000o0O == None ) : return
 if 16 - 16: I1Ii111 % iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / OoOoOO00
 if 29 - 29: OoooooooOO / oO0o
 if 1 - 1: OoOoOO00 . i11iIiiIii % I1Ii111 + OoooooooOO - Oo0Ooo . I1ii11iIi11i
 if 46 - 46: i11iIiiIii + I11i - iIii1I11I1II1 / OoO0O00 - ooOoO0o / i1IIi
 O0o00000o0O . neg_map_replies_received += 1
 O0o00000o0O . last_reply = lisp_get_timestamp ( )
 if 44 - 44: o0oOOo0O0Ooo + Oo0Ooo
 if 46 - 46: OOooOOo % I1IiiI
 if 66 - 66: iIii1I11I1II1 . o0oOOo0O0Ooo - ooOoO0o
 if 27 - 27: Oo0Ooo - i1IIi * OoooooooOO - OoOoOO00 + OoOoOO00
 if ( ( O0o00000o0O . neg_map_replies_received % 100 ) == 0 ) : O0o00000o0O . total_rtt = 0
 if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
 if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
 if 85 - 85: iII111i % i11iIiiIii
 if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
 if ( O0o00000o0O . last_nonce == nonce ) :
  O0o00000o0O . total_rtt += ( time . time ( ) - O0o00000o0O . last_used )
  O0o00000o0O . last_nonce = 0
  if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
 if ( ( O0o00000o0O . neg_map_replies_received % 10 ) == 0 ) : O0o00000o0O . last_nonce = 0
 return
 if 41 - 41: Ii1I + IiII
 if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
 if 53 - 53: I1IiiI % OOooOOo + Ii1I - Ii1I
 if 99 - 99: i1IIi * OoOoOO00 - i1IIi
 if 65 - 65: OoO0O00 / i11iIiiIii + I1ii11iIi11i + OoOoOO00
 if 82 - 82: Ii1I * OOooOOo % ooOoO0o / OoO0O00 - Oo0Ooo . I1Ii111
 if 90 - 90: I11i * i11iIiiIii % i1IIi + I1Ii111 / OoO0O00
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl ) :
 global lisp_map_cache
 if 15 - 15: Oo0Ooo + oO0o . I11i % OoO0O00
 IiIIIi = lisp_map_reply ( )
 packet = IiIIIi . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 13 - 13: I1ii11iIi11i / ooOoO0o * I1Ii111
 IiIIIi . print_map_reply ( )
 if 45 - 45: I1ii11iIi11i - I11i
 if 60 - 60: OOooOOo - OOooOOo * OoOoOO00 / Ii1I % iII111i % Oo0Ooo
 if 75 - 75: iIii1I11I1II1 - IiII - I1Ii111
 if 4 - 4: i11iIiiIii % OoooooooOO . i11iIiiIii
 ooiIi1 = None
 for IiIIi1IiiIiI in range ( IiIIIi . record_count ) :
  iiI = lisp_eid_record ( )
  packet = iiI . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 49 - 49: i1IIi * iII111i - iIii1I11I1II1 % I11i * O0 / OoOoOO00
  iiI . print_record ( "  " , False )
  if 48 - 48: IiII
  if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - o0oOOo0O0Ooo
  if 98 - 98: o0oOOo0O0Ooo * OoO0O00 . OoooooooOO
  if 40 - 40: I1Ii111 + Oo0Ooo + I1Ii111
  if 57 - 57: I1Ii111 / II111iiii % iII111i
  if ( iiI . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , IiIIIi . nonce )
   if 32 - 32: IiII - OOooOOo + i11iIiiIii + I1IiiI . iII111i
   if 75 - 75: o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1IiiI / OoO0O00
  iIIiI = ( iiI . group . is_null ( ) == False )
  if 16 - 16: II111iiii . Ii1I + I1Ii111 % i1IIi / i11iIiiIii + OOooOOo
  if 43 - 43: I1IiiI . Oo0Ooo + i1IIi + I11i / OoO0O00
  if 66 - 66: i11iIiiIii
  if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
  if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
  if ( lisp_decent_push_configured ) :
   OOo000 = iiI . action
   if ( iIIiI and OOo000 == LISP_DROP_ACTION ) :
    if ( iiI . eid . is_local ( ) ) : continue
    if 83 - 83: i1IIi * i1IIi - II111iiii / OoooooooOO . Ii1I + I1Ii111
    if 10 - 10: I11i
    if 24 - 24: Ii1I
    if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
    if 25 - 25: I11i % i1IIi / I11i * i11iIiiIii
    if 71 - 71: IiII % I11i - OoooooooOO + I1IiiI / Oo0Ooo % I11i
    if 6 - 6: i1IIi * i11iIiiIii + ooOoO0o - IiII
  if ( iiI . eid . is_null ( ) ) : continue
  if 97 - 97: iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - Oo0Ooo - iIii1I11I1II1
  if 26 - 26: ooOoO0o + Oo0Ooo
  if 24 - 24: I1IiiI
  if 43 - 43: OoO0O00
  if 51 - 51: OoooooooOO % IiII % Oo0Ooo
  if ( iIIiI ) :
   IiiiiII1i = lisp_map_cache_lookup ( iiI . eid , iiI . group )
  else :
   IiiiiII1i = lisp_map_cache . lookup_cache ( iiI . eid , True )
   if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
  o0O0o0oooo00 = ( IiiiiII1i == None )
  if 51 - 51: Ii1I - II111iiii % II111iiii * OOooOOo
  if 84 - 84: i1IIi . OoOoOO00 % I1ii11iIi11i . OoO0O00 + i11iIiiIii
  if 19 - 19: i1IIi / I1IiiI + IiII . iII111i
  if 68 - 68: iII111i
  if 29 - 29: II111iiii / II111iiii % OoO0O00 % Oo0Ooo . II111iiii
  if ( IiiiiII1i == None ) :
   ii1iI1 , O0o000 , o00oo0 = lisp_allow_gleaning ( iiI . eid , iiI . group ,
 None )
   if ( ii1iI1 ) : continue
  else :
   if ( IiiiiII1i . gleaned ) : continue
   if 87 - 87: i11iIiiIii . II111iiii % iIii1I11I1II1
   if 97 - 97: OoOoOO00 . OoO0O00 . o0oOOo0O0Ooo
   if 64 - 64: IiII / OOooOOo * OoOoOO00 + OoooooooOO
   if 19 - 19: OoooooooOO % oO0o
   if 49 - 49: i1IIi % OoooooooOO + OoooooooOO / OoO0O00 + OoO0O00 * II111iiii
  ooo0oo = [ ]
  for oOoOoO0O in range ( iiI . rloc_count ) :
   iIii1IiIiI = lisp_rloc_record ( )
   iIii1IiIiI . keys = IiIIIi . keys
   packet = iIii1IiIiI . decode ( packet , IiIIIi . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 46 - 46: ooOoO0o % II111iiii
   iIii1IiIiI . print_record ( "    " )
   if 61 - 61: OoO0O00 . I1IiiI
   o00Oo00o0oO0 = None
   if ( IiiiiII1i ) : o00Oo00o0oO0 = IiiiiII1i . get_rloc ( iIii1IiIiI . rloc )
   if ( o00Oo00o0oO0 ) :
    oOo00O = o00Oo00o0oO0
   else :
    oOo00O = lisp_rloc ( )
    if 65 - 65: OoooooooOO / Oo0Ooo
    if 91 - 91: iIii1I11I1II1 / i11iIiiIii + i11iIiiIii / OOooOOo / i1IIi
    if 20 - 20: OOooOOo % O0 * Oo0Ooo . II111iiii
    if 82 - 82: OoO0O00
    if 54 - 54: i1IIi * OOooOOo - oO0o * OoooooooOO + II111iiii . IiII
    if 90 - 90: O0 - II111iiii + I1IiiI . iII111i
    if 3 - 3: o0oOOo0O0Ooo + i1IIi * Oo0Ooo
   IiI1iI1 = oOo00O . store_rloc_from_record ( iIii1IiIiI , IiIIIi . nonce ,
 source )
   oOo00O . echo_nonce_capable = IiIIIi . echo_nonce_capable
   if 6 - 6: OoO0O00 * OoooooooOO * iIii1I11I1II1
   if ( oOo00O . echo_nonce_capable ) :
    oo0o00OO = oOo00O . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , oo0o00OO ) == None ) :
     lisp_echo_nonce ( oo0o00OO )
     if 87 - 87: iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1
     if 79 - 79: ooOoO0o . oO0o + Ii1I * ooOoO0o + O0 . II111iiii
     if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
     if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
     if 5 - 5: OoooooooOO + ooOoO0o - II111iiii . i11iIiiIii / oO0o - ooOoO0o
     if 3 - 3: iII111i
     if 74 - 74: i11iIiiIii + OoooooooOO . OOooOOo
     if 29 - 29: IiII % OoO0O00
     if 53 - 53: OoooooooOO - OoOoOO00 / IiII - I1Ii111
     if 16 - 16: iIii1I11I1II1 / OOooOOo + I1IiiI * II111iiii . OOooOOo
   if ( IiIIIi . rloc_probe and iIii1IiIiI . probe_bit ) :
    if ( oOo00O . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( oOo00O . rloc , source , IiI1iI1 ,
 IiIIIi . nonce , IiIIIi . hop_count , ttl )
     if 68 - 68: IiII * IiII + oO0o / o0oOOo0O0Ooo
     if 41 - 41: OoOoOO00 - O0
     if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
     if 53 - 53: ooOoO0o + oO0o - II111iiii
     if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
     if 6 - 6: iIii1I11I1II1 + oO0o
   ooo0oo . append ( oOo00O )
   if 8 - 8: I1ii11iIi11i + o0oOOo0O0Ooo
   if 29 - 29: Ii1I . OOooOOo
   if 59 - 59: O0 . OoO0O00
   if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
   if ( lisp_data_plane_security and oOo00O . rloc_recent_rekey ( ) ) :
    ooiIi1 = oOo00O
    if 81 - 81: i1IIi % I11i * iIii1I11I1II1
    if 39 - 39: iIii1I11I1II1 / O0 . OoooooooOO - O0 . OoO0O00 . oO0o
    if 59 - 59: II111iiii * I1IiiI
    if 12 - 12: i11iIiiIii - IiII . iII111i . Ii1I
    if 34 - 34: i1IIi % iII111i + Oo0Ooo * OoOoOO00 + OoO0O00
    if 37 - 37: I1Ii111 / OoooooooOO
    if 19 - 19: Ii1I - O0 + I1IiiI + OoooooooOO + ooOoO0o - Oo0Ooo
    if 45 - 45: I1IiiI . OoOoOO00 . OoOoOO00
    if 20 - 20: OoOoOO00
    if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
    if 93 - 93: OoO0O00 % IiII % ooOoO0o . I1IiiI
  if ( IiIIIi . rloc_probe == False and lisp_nat_traversal ) :
   I1III = [ ]
   o0oo0 = [ ]
   for oOo00O in ooo0oo :
    if 32 - 32: OoO0O00 / I1Ii111 / I1Ii111
    if 45 - 45: iII111i + O0 % i11iIiiIii * I1ii11iIi11i + I1Ii111 / OOooOOo
    if 55 - 55: OoooooooOO % iIii1I11I1II1 . ooOoO0o
    if 10 - 10: O0 * iIii1I11I1II1 . OOooOOo
    if 4 - 4: iIii1I11I1II1
    if ( oOo00O . rloc . is_private_address ( ) ) :
     oOo00O . priority = 1
     oOo00O . state = LISP_RLOC_UNREACH_STATE
     I1III . append ( oOo00O )
     o0oo0 . append ( oOo00O . rloc . print_address_no_iid ( ) )
     continue
     if 22 - 22: ooOoO0o . oO0o
     if 65 - 65: i1IIi . I1ii11iIi11i / Oo0Ooo
     if 84 - 84: I1ii11iIi11i . OOooOOo
     if 86 - 86: II111iiii * Oo0Ooo . IiII . iII111i + II111iiii . iIii1I11I1II1
     if 88 - 88: OoooooooOO % ooOoO0o
     if 71 - 71: II111iiii * I1IiiI * Oo0Ooo / II111iiii + iIii1I11I1II1 % i1IIi
    if ( oOo00O . priority == 254 and lisp_i_am_rtr == False ) :
     I1III . append ( oOo00O )
     o0oo0 . append ( oOo00O . rloc . print_address_no_iid ( ) )
     if 85 - 85: IiII * O0 . I1Ii111 . II111iiii
    if ( oOo00O . priority != 254 and lisp_i_am_rtr ) :
     I1III . append ( oOo00O )
     o0oo0 . append ( oOo00O . rloc . print_address_no_iid ( ) )
     if 6 - 6: I1ii11iIi11i * oO0o + iIii1I11I1II1 + II111iiii
     if 69 - 69: iII111i . OoO0O00 + I1IiiI
     if 77 - 77: Ii1I * II111iiii
   if ( o0oo0 != [ ] ) :
    ooo0oo = I1III
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( o0oo0 ) )
    if 80 - 80: i11iIiiIii
    if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
    if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
    if 69 - 69: O0 % I1ii11iIi11i
    if 77 - 77: iIii1I11I1II1 . OOooOOo
    if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
    if 61 - 61: OOooOOo
  I1III = [ ]
  for oOo00O in ooo0oo :
   if ( oOo00O . json != None ) : continue
   I1III . append ( oOo00O )
   if 51 - 51: Oo0Ooo * OOooOOo / iII111i
  if ( I1III != [ ] ) :
   OO = len ( ooo0oo ) - len ( I1III )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( OO ) )
   if 49 - 49: ooOoO0o . i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + OoO0O00
   ooo0oo = I1III
   if 65 - 65: I1ii11iIi11i + Ii1I / i11iIiiIii * I1Ii111 + OoooooooOO
   if 7 - 7: Oo0Ooo % o0oOOo0O0Ooo
   if 40 - 40: oO0o * IiII
   if 29 - 29: O0 - II111iiii + iII111i
   if 73 - 73: I1Ii111 - I11i + IiII - o0oOOo0O0Ooo - I11i - OOooOOo
   if 40 - 40: iIii1I11I1II1 . iII111i * I1ii11iIi11i + IiII - iIii1I11I1II1
   if 83 - 83: i1IIi
   if 9 - 9: iIii1I11I1II1 + i11iIiiIii
  if ( IiIIIi . rloc_probe and IiiiiII1i != None ) : ooo0oo = IiiiiII1i . rloc_set
  if 70 - 70: I1IiiI - OoO0O00 % OOooOOo + ooOoO0o % II111iiii
  if 19 - 19: I11i + i1IIi / i1IIi - II111iiii + I1Ii111
  if 11 - 11: i11iIiiIii % i11iIiiIii / IiII - Oo0Ooo / O0 - I11i
  if 29 - 29: OOooOOo * iIii1I11I1II1 * ooOoO0o
  if 80 - 80: oO0o * I1Ii111
  O00OO0 = o0O0o0oooo00
  if ( IiiiiII1i and ooo0oo != IiiiiII1i . rloc_set ) :
   IiiiiII1i . delete_rlocs_from_rloc_probe_list ( )
   O00OO0 = True
   if 61 - 61: OoooooooOO % I1ii11iIi11i / OoOoOO00
   if 23 - 23: ooOoO0o . O0 % O0 - iIii1I11I1II1 / IiII
   if 8 - 8: i11iIiiIii . Oo0Ooo / i11iIiiIii % IiII
   if 41 - 41: iII111i * I11i % OoooooooOO * iIii1I11I1II1
   if 73 - 73: I1Ii111 * I1ii11iIi11i
  O00o0 = IiiiiII1i . uptime if ( IiiiiII1i ) else None
  if ( IiiiiII1i == None ) :
   IiiiiII1i = lisp_mapping ( iiI . eid , iiI . group , ooo0oo )
   IiiiiII1i . mapping_source = source
   if 77 - 77: iII111i / OoOoOO00 . ooOoO0o * I1ii11iIi11i
   if 44 - 44: OoooooooOO + ooOoO0o / I1Ii111 + I1ii11iIi11i
   if 15 - 15: oO0o - i1IIi % iIii1I11I1II1 . i1IIi
   if 93 - 93: I11i / Ii1I - o0oOOo0O0Ooo % oO0o / OoO0O00 * I11i
   if 24 - 24: i1IIi
   if 21 - 21: II111iiii
   if ( lisp_i_am_rtr and iiI . group . is_null ( ) == False ) :
    IiiiiII1i . map_cache_ttl = LISP_MCAST_TTL
   else :
    IiiiiII1i . map_cache_ttl = iiI . store_ttl ( )
    if 27 - 27: I1IiiI * i11iIiiIii
   IiiiiII1i . action = iiI . action
   IiiiiII1i . add_cache ( O00OO0 )
   if 86 - 86: I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - i1IIi . I11i / OOooOOo
   if 78 - 78: I1ii11iIi11i
  I1i1 = "Add"
  if ( O00o0 ) :
   IiiiiII1i . uptime = O00o0
   IiiiiII1i . refresh_time = lisp_get_timestamp ( )
   I1i1 = "Replace"
   if 73 - 73: I1ii11iIi11i + OoooooooOO - OoOoOO00 + Oo0Ooo
   if 47 - 47: II111iiii + iII111i / i1IIi * Ii1I . OoO0O00 + IiII
  lprint ( "{} {} map-cache with {} RLOCs" . format ( I1i1 ,
 green ( IiiiiII1i . print_eid_tuple ( ) , False ) , len ( ooo0oo ) ) )
  if 7 - 7: i1IIi % O0 * ooOoO0o - OOooOOo % ooOoO0o * I1ii11iIi11i
  if 34 - 34: OoOoOO00 - I11i
  if 85 - 85: OoOoOO00 . oO0o
  if 98 - 98: I1Ii111
  if 49 - 49: OoO0O00 / I1ii11iIi11i % IiII * II111iiii
  if ( lisp_ipc_dp_socket and ooiIi1 != None ) :
   lisp_write_ipc_keys ( ooiIi1 )
   if 92 - 92: iIii1I11I1II1 . OoooooooOO . ooOoO0o / II111iiii
   if 30 - 30: i1IIi * Ii1I + Ii1I / I1Ii111
   if 84 - 84: I1IiiI - Oo0Ooo * OoO0O00 * oO0o
   if 13 - 13: I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + oO0o - iII111i
   if 32 - 32: I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * I1Ii111 % II111iiii
   if 33 - 33: ooOoO0o % I11i
   if 72 - 72: OoO0O00 % OoooooooOO / II111iiii * oO0o * I1Ii111
  if ( o0O0o0oooo00 ) :
   OOO0oOooOOo00 = bold ( "RLOC-probe" , False )
   for oOo00O in IiiiiII1i . best_rloc_set :
    oo0o00OO = red ( oOo00O . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( OOO0oOooOOo00 , oo0o00OO ) )
    lisp_send_map_request ( lisp_sockets , 0 , IiiiiII1i . eid , IiiiiII1i . group , oOo00O )
    if 4 - 4: IiII . O0 * I1IiiI * O0 - i11iIiiIii - O0
    if 26 - 26: Oo0Ooo * i11iIiiIii - i11iIiiIii . i11iIiiIii / I11i
    if 26 - 26: Oo0Ooo - II111iiii % ooOoO0o
 return
 if 81 - 81: i11iIiiIii + I1ii11iIi11i * oO0o
 if 86 - 86: OoO0O00 . ooOoO0o . o0oOOo0O0Ooo
 if 70 - 70: O0 % OoooooooOO - Ii1I * Oo0Ooo
 if 18 - 18: OOooOOo . I1IiiI + i1IIi . I1IiiI
 if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
 if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
 if 6 - 6: O0 * I1Ii111 - II111iiii
 if 60 - 60: oO0o % oO0o
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 76 - 76: I1Ii111 / o0oOOo0O0Ooo
 packet = map_register . zero_auth ( packet )
 I1I = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 19 - 19: O0 . i1IIi % iIii1I11I1II1 + OOooOOo * OoOoOO00 / I11i
 if 82 - 82: I1ii11iIi11i
 if 75 - 75: I11i - II111iiii
 if 84 - 84: I1ii11iIi11i * IiII / I1IiiI - Ii1I + IiII - i1IIi
 map_register . auth_data = I1I
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 98 - 98: II111iiii - iII111i % i11iIiiIii + ooOoO0o
 if 76 - 76: OOooOOo - iII111i + IiII
 if 48 - 48: I1IiiI - II111iiii
 if 15 - 15: O0
 if 54 - 54: iIii1I11I1II1
 if 54 - 54: iII111i + OOooOOo + OoO0O00
 if 6 - 6: oO0o - OoooooooOO * iIii1I11I1II1 * I1ii11iIi11i
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 65 - 65: IiII + OoOoOO00
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  oO0ooO0O000 = hashlib . sha1
  if 66 - 66: i11iIiiIii + II111iiii / ooOoO0o + ooOoO0o * II111iiii
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  oO0ooO0O000 = hashlib . sha256
  if 36 - 36: I1Ii111 * ooOoO0o . ooOoO0o
  if 75 - 75: ooOoO0o + II111iiii / Ii1I - IiII % I1IiiI
 if ( do_hex ) :
  I1I = hmac . new ( password , packet , oO0ooO0O000 ) . hexdigest ( )
 else :
  I1I = hmac . new ( password , packet , oO0ooO0O000 ) . digest ( )
  if 82 - 82: Oo0Ooo
 return ( I1I )
 if 63 - 63: II111iiii * II111iiii % I1IiiI
 if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
 if 91 - 91: IiII * Ii1I * OOooOOo
 if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
 if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
 if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
 if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
 if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 95 - 95: IiII + iII111i % I1IiiI
 I1I = lisp_hash_me ( packet , alg_id , password , True )
 iiIIiIiiii1i1ii1 = ( I1I == auth_data )
 if 30 - 30: I1ii11iIi11i * I11i
 if 76 - 76: I1ii11iIi11i / O0
 if 38 - 38: oO0o + oO0o . iII111i / OoO0O00
 if 27 - 27: o0oOOo0O0Ooo * I1ii11iIi11i
 if ( iiIIiIiiii1i1ii1 == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( I1I , auth_data ) )
  if 100 - 100: I1Ii111 / O0 - iIii1I11I1II1 . iII111i % I1Ii111 - ooOoO0o
  if 100 - 100: OoO0O00 + I1ii11iIi11i + I1ii11iIi11i . I1Ii111
 return ( iiIIiIiiii1i1ii1 )
 if 83 - 83: OoOoOO00 / OOooOOo * II111iiii * OoooooooOO
 if 51 - 51: OoOoOO00 + o0oOOo0O0Ooo / Ii1I
 if 6 - 6: I11i % IiII
 if 48 - 48: Ii1I
 if 100 - 100: OoO0O00 % I1Ii111 + OoooooooOO / OoO0O00
 if 62 - 62: IiII
 if 66 - 66: o0oOOo0O0Ooo % OOooOOo
def lisp_retransmit_map_notify ( map_notify ) :
 oO0o0 = map_notify . etr
 IiI1iI1 = map_notify . etr_port
 if 15 - 15: Ii1I % IiII + IiII % iII111i - O0 * OoooooooOO
 if 53 - 53: OoOoOO00 . Ii1I / Oo0Ooo
 if 62 - 62: i11iIiiIii
 if 38 - 38: I1ii11iIi11i % ooOoO0o * OoooooooOO + iIii1I11I1II1 % i1IIi / OOooOOo
 if 6 - 6: i11iIiiIii
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( oO0o0 . print_address ( ) , False ) ) )
  if 8 - 8: iIii1I11I1II1 + I1ii11iIi11i . i1IIi % OoOoOO00 % OoooooooOO * Oo0Ooo
  if 53 - 53: oO0o
  ii1i1I1111ii = map_notify . nonce_key
  if ( lisp_map_notify_queue . has_key ( ii1i1I1111ii ) ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( ii1i1I1111ii ) )
   if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
   try :
    lisp_map_notify_queue . pop ( ii1i1I1111ii )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 4 - 4: I1IiiI
    if 31 - 31: ooOoO0o * i1IIi . O0
  return
  if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
  if 100 - 100: I1Ii111
 o0OoOO00O0O0 = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # IiII . OoooooooOO / iII111i . oO0o * IiII . I1Ii111
 red ( oO0o0 . print_address ( ) , False ) , map_notify . retry_count ) )
 if 68 - 68: OoO0O00 * i1IIi
 lisp_send_map_notify ( o0OoOO00O0O0 , map_notify . packet , oO0o0 , IiI1iI1 )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 39 - 39: OoO0O00 % OoO0O00
 if 18 - 18: ooOoO0o * I1IiiI / iII111i % iII111i
 if 9 - 9: i11iIiiIii % ooOoO0o % O0 + i1IIi / O0
 if 12 - 12: I1Ii111 - iII111i * iII111i + OoO0O00 . Ii1I % I11i
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 28 - 28: ooOoO0o % OoO0O00 - II111iiii * IiII - I1IiiI + I1IiiI
 if 84 - 84: IiII / Ii1I
 if 39 - 39: OOooOOo - iIii1I11I1II1 + OoOoOO00 % IiII * OoooooooOO % Ii1I
 if 11 - 11: I1ii11iIi11i
 if 83 - 83: O0
 if 97 - 97: O0
 if 50 - 50: I1Ii111 / OoooooooOO . o0oOOo0O0Ooo + I1IiiI * i11iIiiIii
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 28 - 28: I1Ii111 * II111iiii
 if 14 - 14: iIii1I11I1II1 / Ii1I + o0oOOo0O0Ooo . iII111i % iII111i . i1IIi
 if 67 - 67: IiII * II111iiii + ooOoO0o - i11iIiiIii
 if 15 - 15: I11i
 eid_record . rloc_count = len ( parent . registered_rlocs )
 o0o = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 98 - 98: OOooOOo . o0oOOo0O0Ooo . i1IIi * Oo0Ooo
 if 48 - 48: I11i / Oo0Ooo % OOooOOo % iIii1I11I1II1 / OoOoOO00
 if 9 - 9: Ii1I
 if 44 - 44: iII111i
 for I11iiI1III in parent . registered_rlocs :
  iIii1IiIiI = lisp_rloc_record ( )
  iIii1IiIiI . store_rloc_entry ( I11iiI1III )
  o0o += iIii1IiIiI . encode ( )
  iIii1IiIiI . print_record ( "  " )
  del ( iIii1IiIiI )
  if 43 - 43: OoO0O00 % OOooOOo + oO0o
  if 16 - 16: i1IIi - iIii1I11I1II1 - ooOoO0o / OoooooooOO - Oo0Ooo
  if 46 - 46: OoOoOO00 + i1IIi
  if 43 - 43: II111iiii * IiII % iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
  if 81 - 81: oO0o % I1ii11iIi11i % ooOoO0o * O0 - OOooOOo
 for I11iiI1III in parent . registered_rlocs :
  oO0o0 = I11iiI1III . rloc
  IiiiiIiI1ii = lisp_map_notify ( lisp_sockets )
  IiiiiIiI1ii . record_count = 1
  IIIiI1i = map_register . key_id
  IiiiiIiI1ii . key_id = IIIiI1i
  IiiiiIiI1ii . alg_id = map_register . alg_id
  IiiiiIiI1ii . auth_len = map_register . auth_len
  IiiiiIiI1ii . nonce = map_register . nonce
  IiiiiIiI1ii . nonce_key = lisp_hex_string ( IiiiiIiI1ii . nonce )
  IiiiiIiI1ii . etr . copy_address ( oO0o0 )
  IiiiiIiI1ii . etr_port = map_register . sport
  IiiiiIiI1ii . site = parent . site
  IIii1i = IiiiiIiI1ii . encode ( o0o , parent . site . auth_key [ IIIiI1i ] )
  IiiiiIiI1ii . print_notify ( )
  if 41 - 41: I11i % i1IIi + I1Ii111 . I1Ii111
  if 62 - 62: I1IiiI - IiII + OoO0O00 % ooOoO0o + iII111i + I1IiiI
  if 86 - 86: Oo0Ooo % iIii1I11I1II1 * ooOoO0o + OoOoOO00 + iII111i * oO0o
  if 18 - 18: iII111i + I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
  ii1i1I1111ii = IiiiiIiI1ii . nonce_key
  if ( lisp_map_notify_queue . has_key ( ii1i1I1111ii ) ) :
   Oo00Ooo = lisp_map_notify_queue [ ii1i1I1111ii ]
   Oo00Ooo . retransmit_timer . cancel ( )
   del ( Oo00Ooo )
   if 6 - 6: i11iIiiIii
  lisp_map_notify_queue [ ii1i1I1111ii ] = IiiiiIiI1ii
  if 39 - 39: ooOoO0o - i1IIi * iII111i % I1ii11iIi11i
  if 96 - 96: O0 / I1IiiI % OoO0O00 - oO0o % IiII
  if 63 - 63: I1ii11iIi11i + i1IIi * Ii1I + OoOoOO00 / O0 - iII111i
  if 32 - 32: II111iiii / OoOoOO00 . i11iIiiIii - iII111i
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( oO0o0 . print_address ( ) , False ) ) )
  if 43 - 43: i11iIiiIii * i11iIiiIii * I1Ii111
  lisp_send ( lisp_sockets , oO0o0 , LISP_CTRL_PORT , IIii1i )
  if 80 - 80: oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / o0oOOo0O0Ooo % OoooooooOO
  parent . site . map_notifies_sent += 1
  if 31 - 31: o0oOOo0O0Ooo - OoO0O00 % I1IiiI
  if 23 - 23: OOooOOo
  if 97 - 97: Oo0Ooo / OoooooooOO . OoooooooOO
  if 47 - 47: OoO0O00
  IiiiiIiI1ii . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ IiiiiIiI1ii ] )
  IiiiiIiI1ii . retransmit_timer . start ( )
  if 52 - 52: I1IiiI * iIii1I11I1II1 % oO0o * IiII % oO0o
 return
 if 9 - 9: I11i
 if 83 - 83: i11iIiiIii
 if 72 - 72: oO0o + II111iiii . O0 * oO0o + iII111i
 if 22 - 22: I11i + Ii1I . IiII - OoO0O00 - o0oOOo0O0Ooo
 if 84 - 84: OoooooooOO - Oo0Ooo
 if 86 - 86: O0 + OoO0O00 + O0 . I1IiiI
 if 82 - 82: OoOoOO00
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 61 - 61: oO0o . o0oOOo0O0Ooo
 ii1i1I1111ii = lisp_hex_string ( nonce ) + source . print_address ( )
 if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
 if 70 - 70: I1IiiI
 if 74 - 74: ooOoO0o * II111iiii
 if 96 - 96: i11iIiiIii . I1IiiI - II111iiii . I11i
 if 79 - 79: OoO0O00 . OoOoOO00 - i1IIi + Ii1I * i11iIiiIii . OoooooooOO
 if 83 - 83: o0oOOo0O0Ooo / oO0o
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( lisp_map_notify_queue . has_key ( ii1i1I1111ii ) ) :
  IiiiiIiI1ii = lisp_map_notify_queue [ ii1i1I1111ii ]
  IiII1iiI = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( IiiiiIiI1ii . nonce ) , IiII1iiI ) )
  if 24 - 24: Ii1I + oO0o / OoooooooOO % i11iIiiIii
  return
  if 1 - 1: iII111i / I1Ii111 * I1IiiI + OoOoOO00 . OoooooooOO
  if 5 - 5: I1IiiI
 IiiiiIiI1ii = lisp_map_notify ( lisp_sockets )
 IiiiiIiI1ii . record_count = record_count
 key_id = key_id
 IiiiiIiI1ii . key_id = key_id
 IiiiiIiI1ii . alg_id = alg_id
 IiiiiIiI1ii . auth_len = auth_len
 IiiiiIiI1ii . nonce = nonce
 IiiiiIiI1ii . nonce_key = lisp_hex_string ( nonce )
 IiiiiIiI1ii . etr . copy_address ( source )
 IiiiiIiI1ii . etr_port = port
 IiiiiIiI1ii . site = site
 IiiiiIiI1ii . eid_list = eid_list
 if 74 - 74: i1IIi * Oo0Ooo - OoOoOO00 * o0oOOo0O0Ooo
 if 85 - 85: iIii1I11I1II1 * IiII / i11iIiiIii - ooOoO0o - o0oOOo0O0Ooo
 if 30 - 30: OoOoOO00 - OOooOOo . Oo0Ooo
 if 11 - 11: IiII - I1Ii111 - OoO0O00 * o0oOOo0O0Ooo
 if ( map_register_ack == False ) :
  ii1i1I1111ii = IiiiiIiI1ii . nonce_key
  lisp_map_notify_queue [ ii1i1I1111ii ] = IiiiiIiI1ii
  if 99 - 99: O0 - OoO0O00
  if 95 - 95: Ii1I . IiII * o0oOOo0O0Ooo
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 91 - 91: I1Ii111
  if 49 - 49: I11i
  if 17 - 17: Oo0Ooo % o0oOOo0O0Ooo
  if 3 - 3: OoO0O00 . oO0o . oO0o . Ii1I
  if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
 IIii1i = IiiiiIiI1ii . encode ( eid_records , site . auth_key [ key_id ] )
 IiiiiIiI1ii . print_notify ( )
 if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
 if ( map_register_ack == False ) :
  iiI = lisp_eid_record ( )
  iiI . decode ( eid_records )
  iiI . print_record ( "  " , False )
  if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
  if 10 - 10: ooOoO0o
  if 69 - 69: I11i + I1IiiI / oO0o
  if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
  if 85 - 85: I1Ii111 - oO0o
 lisp_send_map_notify ( lisp_sockets , IIii1i , IiiiiIiI1ii . etr , port )
 site . map_notifies_sent += 1
 if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
 if ( map_register_ack ) : return
 if 96 - 96: oO0o
 if 44 - 44: OoooooooOO / iII111i * Oo0Ooo % OoOoOO00 . oO0o
 if 97 - 97: iIii1I11I1II1 / ooOoO0o
 if 16 - 16: Oo0Ooo % IiII
 if 48 - 48: I1IiiI . I1Ii111 . o0oOOo0O0Ooo
 if 72 - 72: Ii1I * OoO0O00 / OoO0O00
 IiiiiIiI1ii . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ IiiiiIiI1ii ] )
 IiiiiIiI1ii . retransmit_timer . start ( )
 return
 if 39 - 39: oO0o
 if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
 if 57 - 57: oO0o + O0 - OoOoOO00
 if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
 if 93 - 93: o0oOOo0O0Ooo + i1IIi
 if 24 - 24: i1IIi
 if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
 if 99 - 99: Oo0Ooo
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 38 - 38: I1ii11iIi11i - I1IiiI
 if 50 - 50: iII111i % OoO0O00 - oO0o + Oo0Ooo . O0 . iII111i
 if 42 - 42: iII111i + I1ii11iIi11i
 if 44 - 44: I1ii11iIi11i % IiII
 IIii1i = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 1 - 1: Oo0Ooo + IiII - I1Ii111 / I1Ii111
 if 25 - 25: OoOoOO00
 if 52 - 52: OOooOOo + IiII
 if 73 - 73: OoooooooOO - I1Ii111 % iII111i / OOooOOo . o0oOOo0O0Ooo - IiII
 oO0o0 = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( oO0o0 . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , oO0o0 , LISP_CTRL_PORT , IIii1i )
 return
 if 69 - 69: Ii1I . iIii1I11I1II1 / Oo0Ooo * Oo0Ooo % IiII
 if 5 - 5: OOooOOo - I1Ii111 + IiII
 if 82 - 82: OOooOOo
 if 26 - 26: ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
 if 26 - 26: I1IiiI - OOooOOo
 if 34 - 34: I1Ii111 % I1IiiI . OoOoOO00 / iII111i + ooOoO0o . i11iIiiIii
 if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
 if 50 - 50: OoooooooOO * II111iiii
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 7 - 7: ooOoO0o / I11i * iII111i
 IiiiiIiI1ii = lisp_map_notify ( lisp_sockets )
 IiiiiIiI1ii . record_count = 1
 IiiiiIiI1ii . nonce = lisp_get_control_nonce ( )
 IiiiiIiI1ii . nonce_key = lisp_hex_string ( IiiiiIiI1ii . nonce )
 IiiiiIiI1ii . etr . copy_address ( xtr )
 IiiiiIiI1ii . etr_port = LISP_CTRL_PORT
 IiiiiIiI1ii . eid_list = eid_list
 ii1i1I1111ii = IiiiiIiI1ii . nonce_key
 if 17 - 17: O0 % I1Ii111
 if 28 - 28: i1IIi * ooOoO0o
 if 14 - 14: II111iiii + II111iiii - I11i / I11i . OoOoOO00 + OoO0O00
 if 92 - 92: II111iiii - II111iiii % IiII
 if 48 - 48: oO0o / II111iiii + oO0o
 if 16 - 16: o0oOOo0O0Ooo % II111iiii - i11iIiiIii - IiII + O0 - i11iIiiIii
 lisp_remove_eid_from_map_notify_queue ( IiiiiIiI1ii . eid_list )
 if ( lisp_map_notify_queue . has_key ( ii1i1I1111ii ) ) :
  IiiiiIiI1ii = lisp_map_notify_queue [ ii1i1I1111ii ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( IiiiiIiI1ii . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 58 - 58: OoooooooOO / I1ii11iIi11i - Oo0Ooo / II111iiii
  return
  if 13 - 13: o0oOOo0O0Ooo + OoOoOO00 * ooOoO0o % IiII
  if 18 - 18: I1IiiI . I1ii11iIi11i + Oo0Ooo - iII111i
  if 53 - 53: ooOoO0o / IiII
  if 36 - 36: iIii1I11I1II1
  if 78 - 78: II111iiii * I11i
 lisp_map_notify_queue [ ii1i1I1111ii ] = IiiiiIiI1ii
 if 47 - 47: Ii1I
 if 42 - 42: I11i . oO0o - I1IiiI / OoO0O00
 if 75 - 75: I1IiiI / OoOoOO00 . I11i * iIii1I11I1II1
 if 53 - 53: iIii1I11I1II1
 iiIii11Ii = site_eid . rtrs_in_rloc_set ( )
 if ( iiIii11Ii ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : iiIii11Ii = False
  if 47 - 47: O0 . OoO0O00 * I1Ii111 - oO0o % Oo0Ooo * i1IIi
  if 45 - 45: OOooOOo / Ii1I
  if 99 - 99: I1IiiI
  if 16 - 16: o0oOOo0O0Ooo + OoOoOO00 / oO0o + iII111i % oO0o / o0oOOo0O0Ooo
  if 50 - 50: OOooOOo % oO0o
 iiI = lisp_eid_record ( )
 iiI . record_ttl = 1440
 iiI . eid . copy_address ( site_eid . eid )
 iiI . group . copy_address ( site_eid . group )
 iiI . rloc_count = 0
 for iIII in site_eid . registered_rlocs :
  if ( iiIii11Ii ^ iIII . is_rtr ( ) ) : continue
  iiI . rloc_count += 1
  if 63 - 63: I1ii11iIi11i / o0oOOo0O0Ooo . II111iiii + iII111i * i1IIi - o0oOOo0O0Ooo
 IIii1i = iiI . encode ( )
 if 37 - 37: OoooooooOO * iII111i . i11iIiiIii % I1Ii111 + oO0o . I1ii11iIi11i
 if 17 - 17: iII111i + ooOoO0o % Oo0Ooo * i1IIi / O0 * oO0o
 if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
 if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
 IiiiiIiI1ii . print_notify ( )
 iiI . print_record ( "  " , False )
 if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
 if 88 - 88: i11iIiiIii
 if 13 - 13: I1IiiI
 if 52 - 52: Ii1I * oO0o / I1Ii111 . IiII
 for iIII in site_eid . registered_rlocs :
  if ( iiIii11Ii ^ iIII . is_rtr ( ) ) : continue
  iIii1IiIiI = lisp_rloc_record ( )
  iIii1IiIiI . store_rloc_entry ( iIII )
  IIii1i += iIii1IiIiI . encode ( )
  iIii1IiIiI . print_record ( "    " )
  if 84 - 84: OoooooooOO - oO0o - I1Ii111
  if 69 - 69: OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
  if 20 - 20: IiII
  if 17 - 17: o0oOOo0O0Ooo % iIii1I11I1II1
  if 66 - 66: OoooooooOO + IiII . II111iiii
 IIii1i = IiiiiIiI1ii . encode ( IIii1i , "" )
 if ( IIii1i == None ) : return
 if 66 - 66: iIii1I11I1II1 % I11i
 if 38 - 38: I1ii11iIi11i * ooOoO0o
 if 77 - 77: OOooOOo - i11iIiiIii - I1ii11iIi11i
 if 94 - 94: OoO0O00 % iII111i - I1Ii111 + OoO0O00 - I1IiiI
 lisp_send_map_notify ( lisp_sockets , IIii1i , xtr , LISP_CTRL_PORT )
 if 65 - 65: OOooOOo
 if 90 - 90: O0
 if 91 - 91: O0 * OoOoOO00 - OoOoOO00 * II111iiii - iII111i
 if 38 - 38: oO0o * I11i % OOooOOo
 IiiiiIiI1ii . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ IiiiiIiI1ii ] )
 IiiiiIiI1ii . retransmit_timer . start ( )
 return
 if 80 - 80: O0 % II111iiii / O0 . Oo0Ooo * OoOoOO00 + OOooOOo
 if 47 - 47: Ii1I - Oo0Ooo * OoOoOO00
 if 20 - 20: oO0o
 if 48 - 48: I1IiiI % OoO0O00
 if 33 - 33: Ii1I
 if 73 - 73: Ii1I . IiII
 if 43 - 43: I11i . IiII - iII111i * I1IiiI * iII111i
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 ooo0oOoOOO0o = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 21 - 21: Oo0Ooo % O0 + iII111i . iIii1I11I1II1 + i1IIi - iII111i
 for iiI1 in rle_list :
  iiI1IIiI1Ii = lisp_site_eid_lookup ( iiI1 [ 0 ] , iiI1 [ 1 ] , True )
  if ( iiI1IIiI1Ii == None ) : continue
  if 94 - 94: OoOoOO00 . iII111i - IiII
  if 15 - 15: i11iIiiIii - OoOoOO00 % I11i - I1ii11iIi11i + o0oOOo0O0Ooo - II111iiii
  if 22 - 22: o0oOOo0O0Ooo + OOooOOo + ooOoO0o
  if 45 - 45: I1Ii111 - i1IIi
  if 88 - 88: OoO0O00 - II111iiii * I1ii11iIi11i % iIii1I11I1II1 + IiII * iII111i
  if 22 - 22: OOooOOo . I1IiiI . OoO0O00
  if 74 - 74: o0oOOo0O0Ooo / OoooooooOO * iII111i / oO0o / Ii1I % iII111i
  ooO0o0o = iiI1IIiI1Ii . registered_rlocs
  if ( len ( ooO0o0o ) == 0 ) :
   Ii1ii1 = { }
   for o00Ii in iiI1IIiI1Ii . individual_registrations . values ( ) :
    for iIII in o00Ii . registered_rlocs :
     if ( iIII . is_rtr ( ) == False ) : continue
     Ii1ii1 [ iIII . rloc . print_address ( ) ] = iIII
     if 45 - 45: OoO0O00
     if 31 - 31: I1IiiI . O0 % Ii1I . oO0o
   ooO0o0o = Ii1ii1 . values ( )
   if 91 - 91: O0 - oO0o * O0
   if 98 - 98: Ii1I
   if 54 - 54: oO0o
   if 85 - 85: oO0o % o0oOOo0O0Ooo % IiII
   if 84 - 84: IiII . OoO0O00
   if 73 - 73: OoOoOO00
  iii1IIi11 = [ ]
  iiII1I11i1iii = False
  if ( iiI1IIiI1Ii . eid . address == 0 and iiI1IIiI1Ii . eid . mask_len == 0 ) :
   IiIII11IIIi1 = [ ]
   O00oOOoo00oo = [ ]
   if ( len ( ooO0o0o ) != 0 and ooO0o0o [ 0 ] . rle != None ) :
    O00oOOoo00oo = ooO0o0o [ 0 ] . rle . rle_nodes
    if 63 - 63: iIii1I11I1II1
   for iIIII1iiIII in O00oOOoo00oo :
    iii1IIi11 . append ( iIIII1iiIII . address )
    IiIII11IIIi1 . append ( iIIII1iiIII . address . print_address_no_iid ( ) )
    if 92 - 92: O0 % I1IiiI / OOooOOo
   lprint ( "Notify existing RLE-nodes {}" . format ( IiIII11IIIi1 ) )
  else :
   if 43 - 43: I11i - I11i
   if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
   if 28 - 28: ooOoO0o
   if 88 - 88: oO0o
   if 77 - 77: ooOoO0o + I1Ii111 . OoOoOO00
   for iIII in ooO0o0o :
    if ( iIII . is_rtr ( ) ) : iii1IIi11 . append ( iIII . rloc )
    if 2 - 2: i1IIi - IiII + iIii1I11I1II1 % i1IIi * II111iiii
    if 26 - 26: I11i
    if 57 - 57: I1ii11iIi11i + I1Ii111 + i11iIiiIii . i1IIi / i11iIiiIii
    if 43 - 43: Ii1I % I11i
    if 5 - 5: OoooooooOO % i11iIiiIii * o0oOOo0O0Ooo * OoooooooOO - o0oOOo0O0Ooo % I11i
   iiII1I11i1iii = ( len ( iii1IIi11 ) != 0 )
   if ( iiII1I11i1iii == False ) :
    oO00Oooo0o0o0 = lisp_site_eid_lookup ( iiI1 [ 0 ] , ooo0oOoOOO0o , False )
    if ( oO00Oooo0o0o0 == None ) : continue
    if 58 - 58: i11iIiiIii % Ii1I + Oo0Ooo - OoOoOO00 - i11iIiiIii / O0
    for iIII in oO00Oooo0o0o0 . registered_rlocs :
     if ( iIII . rloc . is_null ( ) ) : continue
     iii1IIi11 . append ( iIII . rloc )
     if 36 - 36: OOooOOo
     if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
     if 95 - 95: i1IIi * O0 / II111iiii * OoOoOO00 * I1IiiI
     if 38 - 38: OOooOOo - OoOoOO00 / OoO0O00 / o0oOOo0O0Ooo - i11iIiiIii
     if 4 - 4: I1IiiI * o0oOOo0O0Ooo - I11i - OoooooooOO . OoooooooOO
     if 79 - 79: oO0o - iII111i
   if ( len ( iii1IIi11 ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( iiI1IIiI1Ii . print_eid_tuple ( ) , False ) ) )
    if 34 - 34: OoooooooOO + Ii1I - iII111i + OoooooooOO / I1IiiI
    continue
    if 39 - 39: o0oOOo0O0Ooo . i1IIi * OoO0O00 / II111iiii / I1ii11iIi11i * OOooOOo
    if 39 - 39: O0 . OOooOOo
    if 95 - 95: I11i
    if 58 - 58: I1ii11iIi11i / i11iIiiIii + iII111i + I11i / oO0o
    if 8 - 8: I1ii11iIi11i
    if 100 - 100: OoooooooOO / I11i - Ii1I
  for I11iiI1III in iii1IIi11 :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if iiII1I11i1iii else "x" , red ( I11iiI1III . print_address_no_iid ( ) , False ) ,
   # O0
 green ( iiI1IIiI1Ii . print_eid_tuple ( ) , False ) ) )
   if 43 - 43: Oo0Ooo . I1IiiI
   OooOOoooOO00 = [ iiI1IIiI1Ii . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , iiI1IIiI1Ii , OooOOoooOO00 , I11iiI1III )
   time . sleep ( .001 )
   if 68 - 68: Ii1I * Oo0Ooo - O0 . i11iIiiIii * I1ii11iIi11i . OoooooooOO
   if 96 - 96: Ii1I . i11iIiiIii + ooOoO0o - II111iiii - Ii1I
 return
 if 28 - 28: Ii1I + OoooooooOO * I11i * OoOoOO00 + OoO0O00
 if 87 - 87: I1Ii111 / O0 % O0 * o0oOOo0O0Ooo / II111iiii
 if 25 - 25: I1ii11iIi11i * ooOoO0o + I11i + iIii1I11I1II1 / iIii1I11I1II1
 if 76 - 76: iII111i
 if 85 - 85: I1ii11iIi11i + OOooOOo % i1IIi
 if 13 - 13: OOooOOo + i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
 if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
 if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for IiIIi1IiiIiI in range ( rloc_count ) :
  iIii1IiIiI = lisp_rloc_record ( )
  packet = iIii1IiIiI . decode ( packet , None )
  OOooo0o = iIii1IiIiI . json
  if ( OOooo0o == None ) : continue
  if 20 - 20: OOooOOo . OoooooooOO * OOooOOo * I1ii11iIi11i
  try :
   OOooo0o = json . loads ( OOooo0o . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 85 - 85: O0 / II111iiii * O0 - iII111i % i11iIiiIii
   if 47 - 47: OoOoOO00
  if ( OOooo0o . has_key ( "signature" ) == False ) : continue
  return ( iIii1IiIiI )
  if 4 - 4: OOooOOo + I1ii11iIi11i - iII111i + OOooOOo / IiII
 return ( None )
 if 23 - 23: iIii1I11I1II1 + OoooooooOO + ooOoO0o . iII111i . Oo0Ooo - iIii1I11I1II1
 if 25 - 25: O0 + I1IiiI % OOooOOo / Oo0Ooo . IiII / I1Ii111
 if 84 - 84: ooOoO0o . O0 + I1IiiI * OoO0O00 - I1IiiI
 if 24 - 24: Ii1I
 if 23 - 23: Oo0Ooo * i1IIi / I1IiiI . I11i - I1ii11iIi11i . iIii1I11I1II1
 if 15 - 15: O0 + o0oOOo0O0Ooo / oO0o
 if 27 - 27: Ii1I * II111iiii / oO0o
 if 99 - 99: I11i + ooOoO0o % I11i + O0 - Ii1I - I1Ii111
 if 3 - 3: Oo0Ooo . I1IiiI
 if 61 - 61: OoO0O00 - I1ii11iIi11i . Ii1I * i11iIiiIii
 if 97 - 97: ooOoO0o
 if 58 - 58: iII111i
 if 47 - 47: II111iiii % Oo0Ooo . iIii1I11I1II1 . oO0o
 if 52 - 52: I11i * I1IiiI % I11i - iII111i - Ii1I - OoooooooOO
 if 15 - 15: iII111i
 if 95 - 95: i11iIiiIii . Ii1I / II111iiii + II111iiii + Ii1I / I11i
 if 72 - 72: I1Ii111 . I1Ii111 * O0 + I1ii11iIi11i / Oo0Ooo
 if 96 - 96: oO0o . ooOoO0o * Oo0Ooo % ooOoO0o + I1Ii111 + iIii1I11I1II1
 if 45 - 45: II111iiii
def lisp_get_eid_hash ( eid ) :
 iII1iiIiIii1I = None
 for iIi1iIi1 in lisp_eid_hashes :
  if 46 - 46: i11iIiiIii / I1ii11iIi11i
  if 30 - 30: Oo0Ooo
  if 68 - 68: i1IIi
  if 98 - 98: o0oOOo0O0Ooo + I1ii11iIi11i - oO0o + i1IIi
  o0OoO0000o = iIi1iIi1 . instance_id
  if ( o0OoO0000o == - 1 ) : iIi1iIi1 . instance_id = eid . instance_id
  if 85 - 85: I1Ii111 - I1Ii111 . ooOoO0o % I1ii11iIi11i . OOooOOo
  o00oO0Oo = eid . is_more_specific ( iIi1iIi1 )
  iIi1iIi1 . instance_id = o0OoO0000o
  if ( o00oO0Oo ) :
   iII1iiIiIii1I = 128 - iIi1iIi1 . mask_len
   break
   if 56 - 56: IiII / I1Ii111 - O0
   if 69 - 69: I1Ii111 * ooOoO0o / I1ii11iIi11i * OoooooooOO
 if ( iII1iiIiIii1I == None ) : return ( None )
 if 47 - 47: I1ii11iIi11i
 ii1i1II11II1i = eid . address
 OoO = ""
 for IiIIi1IiiIiI in range ( 0 , iII1iiIiIii1I / 16 ) :
  IiiIIi1 = ii1i1II11II1i & 0xffff
  IiiIIi1 = hex ( IiiIIi1 ) [ 2 : - 1 ]
  OoO = IiiIIi1 . zfill ( 4 ) + ":" + OoO
  ii1i1II11II1i >>= 16
  if 34 - 34: o0oOOo0O0Ooo / I1IiiI * i11iIiiIii + I1Ii111 / IiII
 if ( iII1iiIiIii1I % 16 != 0 ) :
  IiiIIi1 = ii1i1II11II1i & 0xff
  IiiIIi1 = hex ( IiiIIi1 ) [ 2 : - 1 ]
  OoO = IiiIIi1 . zfill ( 2 ) + ":" + OoO
  if 55 - 55: iIii1I11I1II1 % iIii1I11I1II1 % iII111i
 return ( OoO [ 0 : - 1 ] )
 if 80 - 80: OoooooooOO % iII111i * IiII % IiII
 if 34 - 34: OoO0O00
 if 22 - 22: OOooOOo
 if 23 - 23: I1ii11iIi11i
 if 53 - 53: I11i
 if 64 - 64: iIii1I11I1II1 + O0 % IiII
 if 13 - 13: i11iIiiIii
 if 49 - 49: OoOoOO00
 if 61 - 61: I1Ii111 / I1Ii111 / iII111i / ooOoO0o - I1IiiI . o0oOOo0O0Ooo
 if 80 - 80: I1IiiI - OOooOOo . oO0o
 if 75 - 75: oO0o + OoOoOO00 - OoooooooOO
def lisp_lookup_public_key ( eid ) :
 o0OoO0000o = eid . instance_id
 if 38 - 38: I11i / ooOoO0o / OoOoOO00 * OOooOOo . oO0o
 if 8 - 8: OoO0O00 . OOooOOo % I1Ii111 * OOooOOo / I1IiiI
 if 3 - 3: IiII - I1ii11iIi11i . o0oOOo0O0Ooo
 if 39 - 39: oO0o . I1Ii111 + oO0o % OoOoOO00 - i11iIiiIii
 if 69 - 69: I11i / OoO0O00
 oooo = lisp_get_eid_hash ( eid )
 if ( oooo == None ) : return ( [ None , None , False ] )
 if 100 - 100: I1IiiI . OOooOOo
 oooo = "hash-" + oooo
 oO00oO0OOoooO = lisp_address ( LISP_AFI_NAME , oooo , len ( oooo ) , o0OoO0000o )
 O0o00oOOOO00 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 if 72 - 72: iIii1I11I1II1 % iIii1I11I1II1 . OoOoOO00 * OoooooooOO * OoO0O00
 if 26 - 26: Ii1I * I1IiiI % ooOoO0o / I1Ii111
 if 80 - 80: I1Ii111 / O0 * O0
 if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
 oO00Oooo0o0o0 = lisp_site_eid_lookup ( oO00oO0OOoooO , O0o00oOOOO00 , True )
 if ( oO00Oooo0o0o0 == None ) : return ( [ oO00oO0OOoooO , None , False ] )
 if 89 - 89: i11iIiiIii - II111iiii
 if 67 - 67: IiII % I1Ii111 + i11iIiiIii
 if 53 - 53: OOooOOo
 if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
 OO0o0OOO0ooOO00o = None
 for oOo00O in oO00Oooo0o0o0 . registered_rlocs :
  I1o0oO0Oo00Oo = oOo00O . json
  if ( I1o0oO0Oo00Oo == None ) : continue
  try :
   I1o0oO0Oo00Oo = json . loads ( I1o0oO0Oo00Oo . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( oooo ) )
   if 75 - 75: I1IiiI
   return ( [ oO00oO0OOoooO , None , False ] )
   if 65 - 65: IiII
  if ( I1o0oO0Oo00Oo . has_key ( "public-key" ) == False ) : continue
  OO0o0OOO0ooOO00o = I1o0oO0Oo00Oo [ "public-key" ]
  break
  if 53 - 53: iIii1I11I1II1 / II111iiii . I1ii11iIi11i + OoooooooOO % OOooOOo
 return ( [ oO00oO0OOoooO , OO0o0OOO0ooOO00o , True ] )
 if 41 - 41: i1IIi / oO0o % OoooooooOO * OOooOOo + I1ii11iIi11i
 if 56 - 56: OOooOOo * OOooOOo / o0oOOo0O0Ooo
 if 4 - 4: OoOoOO00 / OoO0O00
 if 66 - 66: I1Ii111 / OoOoOO00
 if 53 - 53: OoOoOO00 . i11iIiiIii - OoooooooOO
 if 92 - 92: O0 - i11iIiiIii + OoO0O00 - OoooooooOO - o0oOOo0O0Ooo
 if 25 - 25: oO0o / oO0o / Ii1I / O0
 if 56 - 56: ooOoO0o
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 19 - 19: O0 * I1IiiI + I1ii11iIi11i
 if 25 - 25: I11i - ooOoO0o / OoO0O00 / iII111i - OoO0O00
 if 86 - 86: OoO0O00
 if 89 - 89: OoooooooOO % iII111i * I1ii11iIi11i + I1ii11iIi11i . Oo0Ooo
 if 4 - 4: I11i
 o00 = json . loads ( rloc_record . json . json_string )
 if 8 - 8: IiII
 if ( lisp_get_eid_hash ( eid ) ) :
  O000oOO0Oooo = eid
 elif ( o00 . has_key ( "signature-eid" ) ) :
  i11 = o00 [ "signature-eid" ]
  O000oOO0Oooo = lisp_address ( LISP_AFI_IPV6 , i11 , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 4 - 4: iIii1I11I1II1 % I1IiiI - OoooooooOO / iII111i
  if 55 - 55: O0 + iII111i * OoOoOO00 . i11iIiiIii * Ii1I + oO0o
  if 66 - 66: i1IIi . I1ii11iIi11i
  if 86 - 86: Oo0Ooo
  if 48 - 48: OoO0O00
 oO00oO0OOoooO , OO0o0OOO0ooOO00o , OO0oo00Oo0ooO = lisp_lookup_public_key ( O000oOO0Oooo )
 if ( oO00oO0OOoooO == None ) :
  I11i11i1 = green ( O000oOO0Oooo . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( I11i11i1 ) )
  return ( False )
  if 49 - 49: I1ii11iIi11i - II111iiii % I1IiiI
  if 24 - 24: ooOoO0o
 OOo00oO0oo = "found" if OO0oo00Oo0ooO else bold ( "not found" , False )
 I11i11i1 = green ( oO00oO0OOoooO . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( I11i11i1 , OOo00oO0oo ) )
 if ( OO0oo00Oo0ooO == False ) : return ( False )
 if 27 - 27: Oo0Ooo
 if ( OO0o0OOO0ooOO00o == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 85 - 85: iIii1I11I1II1 . o0oOOo0O0Ooo + oO0o
  if 79 - 79: O0 - iIii1I11I1II1 + i1IIi . I11i
 ii111 = OO0o0OOO0ooOO00o [ 0 : 8 ] + "..." + OO0o0OOO0ooOO00o [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( ii111 ) )
 if 4 - 4: oO0o / OoO0O00
 if 90 - 90: I11i . IiII / OoO0O00 . IiII
 if 62 - 62: i11iIiiIii * I11i + oO0o - i1IIi
 if 9 - 9: I1IiiI
 if 17 - 17: II111iiii + i11iIiiIii + IiII
 iIIiii = o00 [ "signature" ]
 if 2 - 2: I11i + I1IiiI . IiII . OoOoOO00 * oO0o - ooOoO0o
 try :
  o00 = binascii . a2b_base64 ( iIIiii )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 29 - 29: OoO0O00
  if 78 - 78: iII111i * ooOoO0o + O0 % ooOoO0o + OoO0O00
 IiIOoo = len ( o00 )
 if ( IiIOoo & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( IiIOoo ) )
  return ( False )
  if 76 - 76: IiII % I1IiiI * Ii1I / Ii1I / OoooooooOO + Ii1I
  if 19 - 19: OoooooooOO
  if 88 - 88: I1IiiI % ooOoO0o % Oo0Ooo - O0
  if 71 - 71: OOooOOo % Ii1I - i11iIiiIii - oO0o . ooOoO0o / I1Ii111
  if 53 - 53: iII111i . Oo0Ooo
 oO0o0O00O00O = O000oOO0Oooo . print_address ( )
 if 91 - 91: oO0o * OoooooooOO * oO0o % oO0o * II111iiii % I1Ii111
 if 8 - 8: Ii1I
 if 28 - 28: iII111i / I1ii11iIi11i - OoOoOO00 * Oo0Ooo + Ii1I * OoOoOO00
 if 94 - 94: oO0o
 OO0o0OOO0ooOO00o = binascii . a2b_base64 ( OO0o0OOO0ooOO00o )
 try :
  ii1i1I1111ii = ecdsa . VerifyingKey . from_pem ( OO0o0OOO0ooOO00o )
 except :
  o0Oo0o0ooOOO = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( o0Oo0o0ooOOO ) )
  return ( False )
  if 49 - 49: OOooOOo - iIii1I11I1II1 / ooOoO0o
  if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
  if 81 - 81: oO0o
  if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
  if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
  if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
  if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
  if 33 - 33: I11i
  if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
  if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
  if 32 - 32: oO0o
 try :
  IIIiiI1I = ii1i1I1111ii . verify ( o00 , oO0o0O00O00O , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( oO0o0O00O00O ) )
  if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
  lprint ( "  Signature used '{}'" . format ( iIIiii ) )
  return ( False )
  if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
 return ( IIIiiI1I )
 if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
 if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
 if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
 if 94 - 94: Ii1I
 if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
 if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
 if 34 - 34: iIii1I11I1II1
 if 47 - 47: OOooOOo * iII111i
 if 71 - 71: IiII - OoooooooOO * i11iIiiIii . OoooooooOO % i1IIi . Oo0Ooo
 if 3 - 3: OoO0O00 + i11iIiiIii + oO0o * IiII
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
 if 70 - 70: OoO0O00
 if 42 - 42: OoooooooOO - I1Ii111 + I1ii11iIi11i * iII111i * iII111i / OoO0O00
 if 85 - 85: O0 . II111iiii
 if 80 - 80: O0 * I11i * I1Ii111
 O0oOooOoO0Oo = [ ]
 for iiII11i1iIi in eid_list :
  for OO0Ooo000O in lisp_map_notify_queue :
   IiiiiIiI1ii = lisp_map_notify_queue [ OO0Ooo000O ]
   if ( iiII11i1iIi not in IiiiiIiI1ii . eid_list ) : continue
   if 71 - 71: IiII - iII111i % I1IiiI * iII111i
   O0oOooOoO0Oo . append ( OO0Ooo000O )
   i1I1I11II = IiiiiIiI1ii . retransmit_timer
   if ( i1I1I11II ) : i1I1I11II . cancel ( )
   if 99 - 99: Ii1I
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( IiiiiIiI1ii . nonce_key , green ( iiII11i1iIi , False ) ) )
   if 79 - 79: I11i / iII111i % Ii1I / OoOoOO00 % O0 / IiII
   if 32 - 32: IiII * II111iiii . Ii1I
   if 68 - 68: I11i / O0
   if 6 - 6: oO0o - oO0o . I1IiiI % I1ii11iIi11i
   if 22 - 22: Ii1I / I1IiiI / II111iiii
   if 31 - 31: II111iiii - Ii1I * OOooOOo - i11iIiiIii / OoooooooOO - I1Ii111
   if 76 - 76: Oo0Ooo
 for OO0Ooo000O in O0oOooOoO0Oo : lisp_map_notify_queue . pop ( OO0Ooo000O )
 return
 if 93 - 93: i1IIi - I1IiiI * i11iIiiIii / Ii1I . Ii1I - i1IIi
 if 19 - 19: iIii1I11I1II1 * OOooOOo * Oo0Ooo % I1IiiI
 if 93 - 93: IiII % OoOoOO00 / I1IiiI + o0oOOo0O0Ooo * ooOoO0o / i1IIi
 if 25 - 25: O0 / Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo
 if 45 - 45: Ii1I * IiII - OOooOOo
 if 57 - 57: iII111i % OoO0O00 / OoooooooOO
 if 69 - 69: oO0o
 if 44 - 44: IiII - II111iiii % Ii1I
def lisp_decrypt_map_register ( packet ) :
 if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
 if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
 if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
 if 59 - 59: OoOoOO00
 if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
 Ii1I1i1IiiI = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 I1i1i = ( Ii1I1i1IiiI >> 13 ) & 0x1
 if ( I1i1i == 0 ) : return ( packet )
 if 11 - 11: OOooOOo * i11iIiiIii % O0
 i1I1iI = ( Ii1I1i1IiiI >> 14 ) & 0x7
 if 81 - 81: OoO0O00 . ooOoO0o
 if 78 - 78: II111iiii - i11iIiiIii . OOooOOo
 if 22 - 22: Oo0Ooo + ooOoO0o
 if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
 try :
  IiiI = lisp_ms_encryption_keys [ i1I1iI ]
  IiiI = IiiI . zfill ( 32 )
  i1Oo = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( i1I1iI ) )
  return ( None )
  if 5 - 5: O0 + IiII % II111iiii % o0oOOo0O0Ooo * II111iiii . I1ii11iIi11i
  if 67 - 67: OoOoOO00
 OooOOOoOoo0O0 = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( OooOOOoOoo0O0 , i1I1iI ) )
 if 22 - 22: iII111i / II111iiii / Oo0Ooo . O0 % oO0o + OoOoOO00
 IIiiI11 = chacha . ChaCha ( IiiI , i1Oo ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + IIiiI11 )
 if 46 - 46: O0 - iIii1I11I1II1 . OoooooooOO . oO0o
 if 51 - 51: I1Ii111 - o0oOOo0O0Ooo
 if 5 - 5: O0
 if 7 - 7: OoOoOO00 + OoO0O00 * I1IiiI
 if 63 - 63: I1ii11iIi11i + iII111i * i1IIi
 if 63 - 63: I1ii11iIi11i / II111iiii % oO0o + ooOoO0o . Ii1I % I11i
 if 59 - 59: I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 5 - 5: I1IiiI
 if 22 - 22: II111iiii / iII111i
 if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
 if 62 - 62: O0 % o0oOOo0O0Ooo + iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
 if 21 - 21: o0oOOo0O0Ooo % O0
 if 81 - 81: i1IIi + i1IIi
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 3 - 3: I1Ii111 . I1ii11iIi11i * iII111i * i11iIiiIii * IiII
 oo0Oo0oOo0 = lisp_map_register ( )
 OO0o0 , packet = oo0Oo0oOo0 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 47 - 47: iIii1I11I1II1 . OoO0O00 . iIii1I11I1II1
 oo0Oo0oOo0 . sport = sport
 if 57 - 57: IiII * ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + OoOoOO00
 oo0Oo0oOo0 . print_map_register ( )
 if 83 - 83: OoOoOO00 . Oo0Ooo . OoO0O00
 if 65 - 65: iII111i * iIii1I11I1II1
 if 48 - 48: iII111i * OoO0O00
 if 57 - 57: ooOoO0o + I1IiiI
 iII111 = True
 if ( oo0Oo0oOo0 . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  iII111 = True
  if 23 - 23: Oo0Ooo + i11iIiiIii * ooOoO0o % OOooOOo - I11i
 if ( oo0Oo0oOo0 . alg_id == LISP_SHA_256_128_ALG_ID ) :
  iII111 = False
  if 4 - 4: IiII % Oo0Ooo
  if 65 - 65: OoO0O00
  if 65 - 65: oO0o
  if 77 - 77: I11i * i1IIi - OOooOOo / OoOoOO00
  if 50 - 50: O0 - oO0o . oO0o
 o0o00oo00O = [ ]
 if 98 - 98: OoooooooOO . o0oOOo0O0Ooo % OOooOOo / O0 + I1Ii111 % i11iIiiIii
 if 94 - 94: O0 + II111iiii - iII111i / i1IIi
 if 25 - 25: ooOoO0o . OoO0O00 - oO0o
 if 76 - 76: iIii1I11I1II1 / II111iiii * OoOoOO00 % iII111i . II111iiii + i11iIiiIii
 iIiOo0OOOOo = None
 oo0OO = packet
 ooOo000OOooo = [ ]
 o0oo0OoOo000 = oo0Oo0oOo0 . record_count
 for IiIIi1IiiIiI in range ( o0oo0OoOo000 ) :
  iiI = lisp_eid_record ( )
  iIii1IiIiI = lisp_rloc_record ( )
  packet = iiI . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 45 - 45: I1Ii111 / I1IiiI + Ii1I / iII111i / Ii1I + I1Ii111
  iiI . print_record ( "  " , False )
  if 12 - 12: Oo0Ooo . i1IIi + iIii1I11I1II1 % I1ii11iIi11i
  if 33 - 33: oO0o . oO0o / IiII + II111iiii
  if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
  if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
  oO00Oooo0o0o0 = lisp_site_eid_lookup ( iiI . eid , iiI . group ,
 False )
  if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
  i1iiii1 = oO00Oooo0o0o0 . print_eid_tuple ( ) if oO00Oooo0o0o0 else None
  if 66 - 66: O0
  if 68 - 68: oO0o / O0 % OoooooooOO
  if 58 - 58: iII111i / II111iiii - I11i * iIii1I11I1II1 % OoOoOO00
  if 14 - 14: iIii1I11I1II1 + oO0o / ooOoO0o
  if 20 - 20: I1ii11iIi11i . II111iiii % I1Ii111 + I1Ii111 / OoooooooOO . Ii1I
  if 98 - 98: OoooooooOO - i11iIiiIii - iII111i + Ii1I - I1IiiI
  if 75 - 75: OOooOOo
  if ( oO00Oooo0o0o0 and oO00Oooo0o0o0 . accept_more_specifics == False ) :
   if ( oO00Oooo0o0o0 . eid_record_matches ( iiI ) == False ) :
    i1II1 = oO00Oooo0o0o0 . parent_for_more_specifics
    if ( i1II1 ) : oO00Oooo0o0o0 = i1II1
    if 53 - 53: IiII / OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - iIii1I11I1II1
    if 53 - 53: OOooOOo . I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
    if 40 - 40: OoooooooOO + iII111i % I1Ii111 . ooOoO0o
    if 2 - 2: ooOoO0o
    if 55 - 55: I11i + i1IIi * OoOoOO00 % Oo0Ooo * II111iiii . I1IiiI
    if 98 - 98: I1ii11iIi11i
    if 57 - 57: OOooOOo * I11i . oO0o
    if 17 - 17: iII111i - OOooOOo * I1IiiI + i1IIi % I1ii11iIi11i
  o0OOOooO = ( oO00Oooo0o0o0 and oO00Oooo0o0o0 . accept_more_specifics )
  if ( o0OOOooO ) :
   iiiIII1iIiI = lisp_site_eid ( oO00Oooo0o0o0 . site )
   iiiIII1iIiI . dynamic = True
   iiiIII1iIiI . eid . copy_address ( iiI . eid )
   iiiIII1iIiI . group . copy_address ( iiI . group )
   iiiIII1iIiI . parent_for_more_specifics = oO00Oooo0o0o0
   iiiIII1iIiI . add_cache ( )
   iiiIII1iIiI . inherit_from_ams_parent ( )
   oO00Oooo0o0o0 . more_specific_registrations . append ( iiiIII1iIiI )
   oO00Oooo0o0o0 = iiiIII1iIiI
  else :
   oO00Oooo0o0o0 = lisp_site_eid_lookup ( iiI . eid , iiI . group ,
 True )
   if 22 - 22: IiII - I1ii11iIi11i . ooOoO0o + I1ii11iIi11i
   if 37 - 37: oO0o
  I11i11i1 = iiI . print_eid_tuple ( )
  if 59 - 59: I11i
  if ( oO00Oooo0o0o0 == None ) :
   i1i1IiIIIiI = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( i1i1IiIIIiI , green ( I11i11i1 , False ) ,
 ", matched non-ams {}" . format ( green ( i1iiii1 , False ) if i1iiii1 else "" ) ) )
   if 61 - 61: IiII * I1Ii111 * OoO0O00 / oO0o - OoooooooOO
   if 5 - 5: o0oOOo0O0Ooo % OOooOOo % II111iiii
   if 86 - 86: O0 . ooOoO0o * OoooooooOO + Ii1I / I11i / II111iiii
   if 26 - 26: OoooooooOO - I1Ii111 / Oo0Ooo - iII111i % OoOoOO00 * OoooooooOO
   if 3 - 3: oO0o
   packet = iIii1IiIiI . end_of_rlocs ( packet , iiI . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 3 - 3: I1ii11iIi11i . IiII + ooOoO0o
   continue
   if 66 - 66: OOooOOo + oO0o - ooOoO0o / Ii1I * OoO0O00 * i11iIiiIii
   if 69 - 69: I11i % i11iIiiIii
  iIiOo0OOOOo = oO00Oooo0o0o0 . site
  if 34 - 34: Ii1I . OoooooooOO + II111iiii % oO0o
  if ( o0OOOooO ) :
   oOo = oO00Oooo0o0o0 . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( oOo , False ) , iIiOo0OOOOo . site_name , green ( I11i11i1 , False ) ) )
   if 69 - 69: i11iIiiIii % I1IiiI * i11iIiiIii - OoO0O00 * iIii1I11I1II1
  else :
   oOo = green ( oO00Oooo0o0o0 . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( oOo , iIiOo0OOOOo . site_name , green ( I11i11i1 , False ) ) )
   if 70 - 70: I1Ii111 . OoOoOO00 % OoooooooOO + OoOoOO00 / II111iiii
   if 39 - 39: I1Ii111 * I1IiiI - o0oOOo0O0Ooo . oO0o . OOooOOo * i11iIiiIii
   if 70 - 70: OoOoOO00 / OOooOOo - o0oOOo0O0Ooo
   if 82 - 82: OOooOOo . i11iIiiIii . I1ii11iIi11i % OoOoOO00 * Ii1I / OoO0O00
   if 56 - 56: o0oOOo0O0Ooo / I1IiiI + I11i + I1IiiI
   if 34 - 34: Oo0Ooo / i11iIiiIii - ooOoO0o
  if ( iIiOo0OOOOo . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( iIiOo0OOOOo . site_name ) )
   packet = iIii1IiIiI . end_of_rlocs ( packet , iiI . rloc_count )
   continue
   if 77 - 77: OoOoOO00 * OoooooooOO
   if 41 - 41: iIii1I11I1II1 - O0 . II111iiii + I1IiiI - II111iiii / oO0o
   if 35 - 35: ooOoO0o - OoOoOO00 / iIii1I11I1II1 / OOooOOo
   if 38 - 38: i1IIi % OoooooooOO
   if 5 - 5: iIii1I11I1II1 + iIii1I11I1II1 . iIii1I11I1II1 + o0oOOo0O0Ooo
   if 45 - 45: I1IiiI - OoooooooOO - I1Ii111 - i1IIi - OoooooooOO * O0
   if 67 - 67: OoOoOO00 * o0oOOo0O0Ooo . IiII
   if 72 - 72: OoOoOO00 % OoooooooOO * O0
  IIIiI1i = oo0Oo0oOo0 . key_id
  if ( iIiOo0OOOOo . auth_key . has_key ( IIIiI1i ) ) :
   IIii1 = iIiOo0OOOOo . auth_key [ IIIiI1i ]
  else :
   IIii1 = ""
   if 58 - 58: oO0o / ooOoO0o
   if 31 - 31: o0oOOo0O0Ooo % I11i - OoO0O00
  IIIIi1Iiii = lisp_verify_auth ( OO0o0 , oo0Oo0oOo0 . alg_id ,
 oo0Oo0oOo0 . auth_data , IIii1 )
  Oo0OooOoOO0O = "dynamic " if oO00Oooo0o0o0 . dynamic else ""
  if 7 - 7: o0oOOo0O0Ooo * I1Ii111 * o0oOOo0O0Ooo - OoO0O00 * Oo0Ooo - IiII
  oOo0ooOO0O = bold ( "passed" if IIIIi1Iiii else "failed" , False )
  IIIiI1i = "key-id {}" . format ( IIIiI1i ) if IIIiI1i == oo0Oo0oOo0 . key_id else "bad key-id {}" . format ( oo0Oo0oOo0 . key_id )
  if 10 - 10: i1IIi - OoOoOO00
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( oOo0ooOO0O , Oo0OooOoOO0O , green ( I11i11i1 , False ) , IIIiI1i ) )
  if 25 - 25: o0oOOo0O0Ooo . I1IiiI % iIii1I11I1II1 * Ii1I % I1IiiI * I11i
  if 21 - 21: O0 % II111iiii % OoOoOO00 / Ii1I * ooOoO0o
  if 82 - 82: I1IiiI % II111iiii * iIii1I11I1II1
  if 83 - 83: O0 + i1IIi
  if 47 - 47: iIii1I11I1II1 * i11iIiiIii % Ii1I + IiII
  if 39 - 39: i1IIi / i11iIiiIii % ooOoO0o - ooOoO0o % i1IIi
  oOII1ii11iI = True
  OoooOOo00oOO = ( lisp_get_eid_hash ( iiI . eid ) != None )
  if ( OoooOOo00oOO or oO00Oooo0o0o0 . require_signature ) :
   O0OOoooo0O0 = "Required " if oO00Oooo0o0o0 . require_signature else ""
   I11i11i1 = green ( I11i11i1 , False )
   oOo00O = lisp_find_sig_in_rloc_set ( packet , iiI . rloc_count )
   if ( oOo00O == None ) :
    oOII1ii11iI = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( O0OOoooo0O0 ,
    # IiII % ooOoO0o
 bold ( "failed" , False ) , I11i11i1 ) )
   else :
    oOII1ii11iI = lisp_verify_cga_sig ( iiI . eid , oOo00O )
    oOo0ooOO0O = bold ( "passed" if oOII1ii11iI else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( O0OOoooo0O0 , oOo0ooOO0O , I11i11i1 ) )
    if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
    if 27 - 27: Oo0Ooo . I1Ii111 - i1IIi * I1IiiI
    if 96 - 96: I1ii11iIi11i - Ii1I . I1ii11iIi11i
    if 89 - 89: II111iiii % I1ii11iIi11i % IiII . I11i
  if ( IIIIi1Iiii == False or oOII1ii11iI == False ) :
   packet = iIii1IiIiI . end_of_rlocs ( packet , iiI . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 49 - 49: iII111i % i11iIiiIii * I11i - oO0o . OOooOOo . i11iIiiIii
   continue
   if 26 - 26: iIii1I11I1II1 + i11iIiiIii % iII111i + I1IiiI + oO0o - ooOoO0o
   if 4 - 4: Oo0Ooo - IiII - I11i
   if 72 - 72: OoooooooOO
   if 19 - 19: Oo0Ooo . OOooOOo
   if 58 - 58: IiII % iII111i + i1IIi % I1IiiI % OOooOOo . iII111i
   if 85 - 85: i11iIiiIii . o0oOOo0O0Ooo * iII111i . I1ii11iIi11i / I1Ii111 % Ii1I
  if ( oo0Oo0oOo0 . merge_register_requested ) :
   i1II1 = oO00Oooo0o0o0
   i1II1 . inconsistent_registration = False
   if 27 - 27: II111iiii . iIii1I11I1II1 / I1ii11iIi11i / i1IIi / iIii1I11I1II1
   if 70 - 70: i11iIiiIii . OoO0O00 / OoooooooOO * OoooooooOO - OOooOOo
   if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
   if 39 - 39: OoO0O00 + IiII - II111iiii % I11i
   if 80 - 80: o0oOOo0O0Ooo * ooOoO0o
   if ( oO00Oooo0o0o0 . group . is_null ( ) ) :
    if ( i1II1 . site_id != oo0Oo0oOo0 . site_id ) :
     i1II1 . site_id = oo0Oo0oOo0 . site_id
     i1II1 . registered = False
     i1II1 . individual_registrations = { }
     i1II1 . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 87 - 87: I1Ii111 + O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - IiII
     if 24 - 24: OoOoOO00
     if 19 - 19: ooOoO0o
   ii1i1I1111ii = source . address + oo0Oo0oOo0 . xtr_id
   if ( oO00Oooo0o0o0 . individual_registrations . has_key ( ii1i1I1111ii ) ) :
    oO00Oooo0o0o0 = oO00Oooo0o0o0 . individual_registrations [ ii1i1I1111ii ]
   else :
    oO00Oooo0o0o0 = lisp_site_eid ( iIiOo0OOOOo )
    oO00Oooo0o0o0 . eid . copy_address ( i1II1 . eid )
    oO00Oooo0o0o0 . group . copy_address ( i1II1 . group )
    i1II1 . individual_registrations [ ii1i1I1111ii ] = oO00Oooo0o0o0
    if 43 - 43: O0 . I1Ii111 % OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00
  else :
   oO00Oooo0o0o0 . inconsistent_registration = oO00Oooo0o0o0 . merge_register_requested
   if 46 - 46: I11i - OoooooooOO % o0oOOo0O0Ooo
   if 7 - 7: OoooooooOO - I1Ii111 * IiII
   if 20 - 20: o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
  oO00Oooo0o0o0 . map_registers_received += 1
  if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
  if 8 - 8: OoooooooOO * ooOoO0o
  if 26 - 26: i11iIiiIii + oO0o - i1IIi
  if 71 - 71: I1IiiI % I1Ii111 / oO0o % oO0o / iIii1I11I1II1 + I1Ii111
  if 86 - 86: IiII % i1IIi * o0oOOo0O0Ooo - I1Ii111
  o0Oo0o0ooOOO = ( oO00Oooo0o0o0 . is_rloc_in_rloc_set ( source ) == False )
  if ( iiI . record_ttl == 0 and o0Oo0o0ooOOO ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 37 - 37: iII111i % I1IiiI - I1ii11iIi11i % I11i
   continue
   if 35 - 35: O0 - OoooooooOO % iII111i
   if 48 - 48: OOooOOo % i11iIiiIii
   if 49 - 49: O0 * iII111i + II111iiii - OOooOOo
   if 29 - 29: OoooooooOO % II111iiii - Oo0Ooo / IiII - i11iIiiIii
   if 64 - 64: iII111i . I1Ii111 + I1Ii111
   if 1 - 1: OOooOOo % Oo0Ooo
  OO00o = oO00Oooo0o0o0 . registered_rlocs
  oO00Oooo0o0o0 . registered_rlocs = [ ]
  if 76 - 76: OoooooooOO % O0 / OoO0O00
  if 41 - 41: i11iIiiIii - I1ii11iIi11i - II111iiii
  if 5 - 5: OoOoOO00 + i1IIi
  if 43 - 43: iII111i * I1IiiI
  IiOOo = packet
  for oOoOoO0O in range ( iiI . rloc_count ) :
   iIii1IiIiI = lisp_rloc_record ( )
   packet = iIii1IiIiI . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 99 - 99: OOooOOo . IiII
   iIii1IiIiI . print_record ( "    " )
   if 77 - 77: I1IiiI + I11i * iIii1I11I1II1 / I1IiiI - iII111i
   if 42 - 42: oO0o * IiII
   if 37 - 37: I11i * ooOoO0o / IiII . I1ii11iIi11i + II111iiii
   if 55 - 55: OoO0O00
   if ( len ( iIiOo0OOOOo . allowed_rlocs ) > 0 ) :
    oo0o00OO = iIii1IiIiI . rloc . print_address ( )
    if ( iIiOo0OOOOo . allowed_rlocs . has_key ( oo0o00OO ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( oo0o00OO , False ) ) )
     if 63 - 63: o0oOOo0O0Ooo / IiII - i11iIiiIii
     if 99 - 99: O0 + O0 . iIii1I11I1II1 . ooOoO0o * o0oOOo0O0Ooo
     oO00Oooo0o0o0 . registered = False
     packet = iIii1IiIiI . end_of_rlocs ( packet ,
 iiI . rloc_count - oOoOoO0O - 1 )
     break
     if 1 - 1: I1Ii111 - I11i . OoOoOO00
     if 72 - 72: II111iiii . O0 . I11i * OoO0O00
     if 70 - 70: iII111i % OoooooooOO * I1ii11iIi11i . I11i / OoO0O00
     if 6 - 6: O0 . i11iIiiIii
     if 85 - 85: i11iIiiIii / Ii1I + Oo0Ooo / OoOoOO00 - I1IiiI
     if 39 - 39: OoO0O00
   oOo00O = lisp_rloc ( )
   oOo00O . store_rloc_from_record ( iIii1IiIiI , None , source )
   if 97 - 97: iIii1I11I1II1 . I1IiiI - O0
   if 41 - 41: I11i . OoOoOO00 * O0 % Ii1I
   if 54 - 54: ooOoO0o
   if 13 - 13: I11i
   if 18 - 18: II111iiii * oO0o % i11iIiiIii / IiII . ooOoO0o
   if 2 - 2: OoOoOO00 % I1Ii111
   if ( source . is_exact_match ( oOo00O . rloc ) ) :
    oOo00O . map_notify_requested = oo0Oo0oOo0 . map_notify_requested
    if 35 - 35: OOooOOo
    if 50 - 50: iIii1I11I1II1 . I1IiiI + i11iIiiIii
    if 65 - 65: I11i % I1IiiI
    if 3 - 3: i11iIiiIii % OOooOOo - Ii1I . i1IIi
    if 24 - 24: OOooOOo
   oO00Oooo0o0o0 . registered_rlocs . append ( oOo00O )
   if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
   if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
  OOOO00OO0O0o = ( oO00Oooo0o0o0 . do_rloc_sets_match ( OO00o ) == False )
  if 20 - 20: iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo + oO0o % IiII
  if 84 - 84: IiII - O0 . I1ii11iIi11i % OOooOOo % iII111i + OoooooooOO
  if 74 - 74: o0oOOo0O0Ooo + OoOoOO00 - o0oOOo0O0Ooo
  if 2 - 2: OOooOOo
  if 14 - 14: Ii1I - O0 - IiII % Ii1I / OoOoOO00 * OoooooooOO
  if 57 - 57: Oo0Ooo % Oo0Ooo % O0 . I1Ii111 % I1ii11iIi11i
  if ( oo0Oo0oOo0 . map_register_refresh and OOOO00OO0O0o and
 oO00Oooo0o0o0 . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   oO00Oooo0o0o0 . registered_rlocs = OO00o
   continue
   if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
   if 12 - 12: ooOoO0o
   if 56 - 56: i1IIi
   if 3 - 3: OOooOOo - Oo0Ooo * Ii1I + i11iIiiIii
   if 53 - 53: i1IIi % I1ii11iIi11i
   if 65 - 65: I11i + OoOoOO00 - i11iIiiIii
  if ( oO00Oooo0o0o0 . registered == False ) :
   oO00Oooo0o0o0 . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
  oO00Oooo0o0o0 . last_registered = lisp_get_timestamp ( )
  oO00Oooo0o0o0 . registered = ( iiI . record_ttl != 0 )
  oO00Oooo0o0o0 . last_registerer = source
  if 61 - 61: oO0o . i11iIiiIii / Ii1I % iII111i
  if 36 - 36: OoO0O00 + Ii1I / I11i - iII111i % OoO0O00 / Oo0Ooo
  if 38 - 38: Ii1I - ooOoO0o - O0 + oO0o . iIii1I11I1II1
  if 90 - 90: i1IIi * OoOoOO00
  oO00Oooo0o0o0 . auth_sha1_or_sha2 = iII111
  oO00Oooo0o0o0 . proxy_reply_requested = oo0Oo0oOo0 . proxy_reply_requested
  oO00Oooo0o0o0 . lisp_sec_present = oo0Oo0oOo0 . lisp_sec_present
  oO00Oooo0o0o0 . map_notify_requested = oo0Oo0oOo0 . map_notify_requested
  oO00Oooo0o0o0 . mobile_node_requested = oo0Oo0oOo0 . mobile_node
  oO00Oooo0o0o0 . merge_register_requested = oo0Oo0oOo0 . merge_register_requested
  if 27 - 27: iIii1I11I1II1
  oO00Oooo0o0o0 . use_register_ttl_requested = oo0Oo0oOo0 . use_ttl_for_timeout
  if ( oO00Oooo0o0o0 . use_register_ttl_requested ) :
   oO00Oooo0o0o0 . register_ttl = iiI . store_ttl ( )
  else :
   oO00Oooo0o0o0 . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 95 - 95: iII111i / ooOoO0o % Ii1I
  oO00Oooo0o0o0 . xtr_id_present = oo0Oo0oOo0 . xtr_id_present
  if ( oO00Oooo0o0o0 . xtr_id_present ) :
   oO00Oooo0o0o0 . xtr_id = oo0Oo0oOo0 . xtr_id
   oO00Oooo0o0o0 . site_id = oo0Oo0oOo0 . site_id
   if 44 - 44: OOooOOo . OOooOOo
   if 5 - 5: oO0o + OoooooooOO
   if 88 - 88: oO0o + OOooOOo
   if 14 - 14: I11i / i1IIi
   if 56 - 56: OoooooooOO
  if ( oo0Oo0oOo0 . merge_register_requested ) :
   if ( i1II1 . merge_in_site_eid ( oO00Oooo0o0o0 ) ) :
    o0o00oo00O . append ( [ iiI . eid , iiI . group ] )
    if 59 - 59: I1ii11iIi11i + OoO0O00
   if ( oo0Oo0oOo0 . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , i1II1 , oo0Oo0oOo0 ,
 iiI )
    if 37 - 37: IiII * I1IiiI % O0
    if 32 - 32: ooOoO0o % II111iiii
    if 60 - 60: i11iIiiIii
  if ( OOOO00OO0O0o == False ) : continue
  if ( len ( o0o00oo00O ) != 0 ) : continue
  if 11 - 11: o0oOOo0O0Ooo
  ooOo000OOooo . append ( oO00Oooo0o0o0 . print_eid_tuple ( ) )
  if 77 - 77: o0oOOo0O0Ooo / iIii1I11I1II1 * iIii1I11I1II1 / o0oOOo0O0Ooo * iII111i
  if 26 - 26: Ii1I
  if 1 - 1: OoOoOO00 . o0oOOo0O0Ooo + Oo0Ooo % Oo0Ooo * I1ii11iIi11i
  if 50 - 50: IiII / i1IIi . I1ii11iIi11i
  if 75 - 75: I11i * oO0o + OoooooooOO . iII111i + OoO0O00
  if 44 - 44: II111iiii
  if 65 - 65: I11i . iII111i . I1IiiI - Oo0Ooo % iIii1I11I1II1 / O0
  iiI = iiI . encode ( )
  iiI += IiOOo
  OooOOoooOO00 = [ oO00Oooo0o0o0 . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 54 - 54: iII111i - I1Ii111
  for oOo00O in OO00o :
   if ( oOo00O . map_notify_requested == False ) : continue
   if ( oOo00O . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , iiI , OooOOoooOO00 , 1 , oOo00O . rloc ,
 LISP_CTRL_PORT , oo0Oo0oOo0 . nonce , oo0Oo0oOo0 . key_id ,
 oo0Oo0oOo0 . alg_id , oo0Oo0oOo0 . auth_len , iIiOo0OOOOo , False )
   if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
   if 7 - 7: i1IIi
   if 30 - 30: oO0o . i1IIi / I11i
   if 23 - 23: i1IIi + oO0o % iII111i - OoO0O00 - i1IIi
   if 74 - 74: Ii1I + I11i . OoooooooOO - I1ii11iIi11i
  lisp_notify_subscribers ( lisp_sockets , iiI , oO00Oooo0o0o0 . eid , iIiOo0OOOOo )
  if 2 - 2: oO0o - o0oOOo0O0Ooo
  if 80 - 80: i1IIi
  if 40 - 40: O0 . ooOoO0o * iII111i . I11i + I1Ii111 % OoO0O00
  if 9 - 9: IiII * oO0o - o0oOOo0O0Ooo
  if 17 - 17: iII111i % Oo0Ooo
 if ( len ( o0o00oo00O ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , o0o00oo00O )
  if 14 - 14: I1IiiI - I1Ii111 % I1IiiI - II111iiii
  if 34 - 34: I1ii11iIi11i * IiII / II111iiii / ooOoO0o * oO0o
  if 3 - 3: II111iiii
  if 61 - 61: oO0o . I1IiiI + i1IIi
  if 69 - 69: O0 / i1IIi - OoOoOO00 + ooOoO0o - oO0o
  if 80 - 80: o0oOOo0O0Ooo % O0 * I11i . i1IIi - ooOoO0o
 if ( oo0Oo0oOo0 . merge_register_requested ) : return
 if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
 if 61 - 61: II111iiii / i1IIi . I1ii11iIi11i % iIii1I11I1II1
 if 66 - 66: iIii1I11I1II1 % OoOoOO00 + i1IIi * i11iIiiIii * OoooooooOO
 if 36 - 36: iII111i - OoO0O00 + I1IiiI + Ii1I . OoooooooOO
 if 75 - 75: oO0o * Oo0Ooo * O0
 if ( oo0Oo0oOo0 . map_notify_requested and iIiOo0OOOOo != None ) :
  lisp_build_map_notify ( lisp_sockets , oo0OO , ooOo000OOooo ,
 oo0Oo0oOo0 . record_count , source , sport , oo0Oo0oOo0 . nonce ,
 oo0Oo0oOo0 . key_id , oo0Oo0oOo0 . alg_id , oo0Oo0oOo0 . auth_len ,
 iIiOo0OOOOo , True )
  if 22 - 22: ooOoO0o / OoooooooOO . II111iiii / Ii1I * OoO0O00 . i1IIi
 return
 if 62 - 62: oO0o % Ii1I - Ii1I
 if 16 - 16: OoO0O00 - O0 - OOooOOo - I11i % OoOoOO00
 if 7 - 7: I1Ii111 / OoOoOO00 . II111iiii
 if 9 - 9: I11i . I11i . OoooooooOO
 if 42 - 42: iII111i / oO0o / iII111i * OoO0O00
 if 25 - 25: OoOoOO00 - II111iiii + II111iiii . Ii1I * II111iiii
 if 12 - 12: IiII / Ii1I
 if 54 - 54: Oo0Ooo + Ii1I % OoooooooOO * OOooOOo / OoOoOO00
 if 39 - 39: I1IiiI % i11iIiiIii % Ii1I
 if 59 - 59: ooOoO0o % OoO0O00 / I1IiiI - II111iiii + OoooooooOO * i11iIiiIii
def lisp_process_multicast_map_notify ( packet , source ) :
 IiiiiIiI1ii = lisp_map_notify ( "" )
 packet = IiiiiIiI1ii . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 58 - 58: IiII / Oo0Ooo + o0oOOo0O0Ooo
  if 71 - 71: Ii1I - IiII
 IiiiiIiI1ii . print_notify ( )
 if ( IiiiiIiI1ii . record_count == 0 ) : return
 if 2 - 2: OoOoOO00 % IiII % OoO0O00 . i1IIi / I1Ii111 - iIii1I11I1II1
 oO0oOOoo0OO0 = IiiiiIiI1ii . eid_records
 if 25 - 25: iII111i / iII111i
 for IiIIi1IiiIiI in range ( IiiiiIiI1ii . record_count ) :
  iiI = lisp_eid_record ( )
  oO0oOOoo0OO0 = iiI . decode ( oO0oOOoo0OO0 )
  if ( packet == None ) : return
  iiI . print_record ( "  " , False )
  if 7 - 7: II111iiii * Ii1I * OoO0O00 / o0oOOo0O0Ooo
  if 71 - 71: ooOoO0o - i11iIiiIii - OoO0O00 % iII111i * OoooooooOO * OoooooooOO
  if 44 - 44: OoO0O00 . OoOoOO00 + I1Ii111
  if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
  IiiiiII1i = lisp_map_cache_lookup ( iiI . eid , iiI . group )
  if ( IiiiiII1i == None ) :
   Ii1iIIi1I1II1I , O0o000 , o00oo0 = lisp_allow_gleaning ( iiI . eid , iiI . group ,
 None )
   if ( Ii1iIIi1I1II1I == False ) : continue
   if 93 - 93: o0oOOo0O0Ooo % OoooooooOO
   IiiiiII1i = lisp_mapping ( iiI . eid , iiI . group , [ ] )
   IiiiiII1i . add_cache ( )
   if 47 - 47: iIii1I11I1II1 - OOooOOo + I1ii11iIi11i * ooOoO0o + Oo0Ooo + OoO0O00
   if 64 - 64: OoOoOO00 - OoOoOO00 . OoooooooOO + ooOoO0o
   if 100 - 100: ooOoO0o . OoooooooOO % i1IIi % OoO0O00
   if 26 - 26: OoOoOO00 * IiII
   if 76 - 76: I1IiiI + IiII * I1ii11iIi11i * I1IiiI % Ii1I + ooOoO0o
   if 46 - 46: OoOoOO00
   if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
  if ( IiiiiII1i . gleaned ) :
   lprint ( "Ignore Map-Notify for gleaned {}" . format ( green ( IiiiiII1i . print_eid_tuple ( ) , False ) ) )
   if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
   continue
   if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
   if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
  IiiiiII1i . mapping_source = None if source == "lisp-etr" else source
  IiiiiII1i . map_cache_ttl = iiI . store_ttl ( )
  if 20 - 20: IiII
  if 81 - 81: Oo0Ooo / I1Ii111
  if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
  if 51 - 51: iII111i - ooOoO0o
  if 32 - 32: IiII - i11iIiiIii
  if ( len ( IiiiiII1i . rloc_set ) != 0 and iiI . rloc_count == 0 ) :
   IiiiiII1i . rloc_set = [ ]
   IiiiiII1i . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , IiiiiII1i )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( IiiiiII1i . print_eid_tuple ( ) , False ) ) )
   if 41 - 41: Ii1I % Ii1I * oO0o - I11i + iIii1I11I1II1 . ooOoO0o
   continue
   if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
   if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
  I1i = IiiiiII1i . rtrs_in_rloc_set ( )
  if 16 - 16: I1ii11iIi11i - I1ii11iIi11i % i11iIiiIii * Oo0Ooo
  if 1 - 1: ooOoO0o % I1Ii111 - OoO0O00 + OoO0O00
  if 99 - 99: oO0o
  if 39 - 39: i1IIi
  if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
  for oOoOoO0O in range ( iiI . rloc_count ) :
   iIii1IiIiI = lisp_rloc_record ( )
   oO0oOOoo0OO0 = iIii1IiIiI . decode ( oO0oOOoo0OO0 , None )
   iIii1IiIiI . print_record ( "    " )
   if ( iiI . group . is_null ( ) ) : continue
   if ( iIii1IiIiI . rle == None ) : continue
   if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
   if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
   if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
   if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
   if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
   i1I1IiiIi = IiiiiII1i . rloc_set [ 0 ] . stats if len ( IiiiiII1i . rloc_set ) != 0 else None
   if 12 - 12: oO0o / ooOoO0o
   if 3 - 3: I1IiiI % OoO0O00
   if 18 - 18: I1ii11iIi11i * I11i
   if 57 - 57: o0oOOo0O0Ooo % I1IiiI * i11iIiiIii - I1ii11iIi11i + I1IiiI % ooOoO0o
   oOo00O = lisp_rloc ( )
   oOo00O . store_rloc_from_record ( iIii1IiIiI , None , IiiiiII1i . mapping_source )
   if ( i1I1IiiIi != None ) : oOo00O . stats = copy . deepcopy ( i1I1IiiIi )
   if 10 - 10: OoooooooOO % iII111i / IiII
   if ( I1i and oOo00O . is_rtr ( ) == False ) : continue
   if 64 - 64: ooOoO0o % O0 / oO0o
   IiiiiII1i . rloc_set = [ oOo00O ]
   IiiiiII1i . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , IiiiiII1i )
   if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( IiiiiII1i . print_eid_tuple ( ) , False ) ,
   # Oo0Ooo . OoOoOO00 % oO0o % Oo0Ooo % O0
 oOo00O . rle . print_rle ( False , True ) ) )
   if 51 - 51: IiII % IiII + OOooOOo . II111iiii / I1ii11iIi11i
   if 4 - 4: o0oOOo0O0Ooo % I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
 return
 if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
 if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
 if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
 if 88 - 88: ooOoO0o
 if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
 if 20 - 20: i11iIiiIii * I11i
 if 29 - 29: IiII / OOooOOo
 if 39 - 39: O0 + II111iiii
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 IiiiiIiI1ii = lisp_map_notify ( "" )
 IIii1i = IiiiiIiI1ii . decode ( orig_packet )
 if ( IIii1i == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
  if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
 IiiiiIiI1ii . print_notify ( )
 if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
 if 42 - 42: O0 / oO0o % O0 . i1IIi % OOooOOo
 if 13 - 13: I1IiiI % ooOoO0o + OOooOOo
 if 91 - 91: oO0o - ooOoO0o
 if 20 - 20: i1IIi . IiII / o0oOOo0O0Ooo / I11i
 IiII1iiI = source . print_address ( )
 if ( IiiiiIiI1ii . alg_id != 0 or IiiiiIiI1ii . auth_len != 0 ) :
  o00oO0Oo = None
  for ii1i1I1111ii in lisp_map_servers_list :
   if ( ii1i1I1111ii . find ( IiII1iiI ) == - 1 ) : continue
   o00oO0Oo = lisp_map_servers_list [ ii1i1I1111ii ]
   if 27 - 27: ooOoO0o . ooOoO0o - Ii1I % i11iIiiIii
  if ( o00oO0Oo == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( IiII1iiI ) )
   if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
   return
   if 7 - 7: I1IiiI + OoooooooOO + o0oOOo0O0Ooo . OoooooooOO
   if 29 - 29: iII111i * O0 + I1IiiI * IiII + iII111i - IiII
  o00oO0Oo . map_notifies_received += 1
  if 38 - 38: I1ii11iIi11i - Ii1I % OoooooooOO
  IIIIi1Iiii = lisp_verify_auth ( IIii1i , IiiiiIiI1ii . alg_id ,
 IiiiiIiI1ii . auth_data , o00oO0Oo . password )
  if 43 - 43: iIii1I11I1II1 / OoOoOO00
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if IIIIi1Iiii else "failed" ) )
  if 13 - 13: o0oOOo0O0Ooo / I1Ii111
  if ( IIIIi1Iiii == False ) : return
 else :
  o00oO0Oo = lisp_ms ( IiII1iiI , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
  if 32 - 32: oO0o
  if 72 - 72: I1IiiI
  if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
  if 87 - 87: Oo0Ooo
  if 7 - 7: iIii1I11I1II1
 oO0oOOoo0OO0 = IiiiiIiI1ii . eid_records
 if ( IiiiiIiI1ii . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , oO0oOOoo0OO0 , IiiiiIiI1ii , o00oO0Oo )
  return
  if 85 - 85: iIii1I11I1II1 . O0
  if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
  if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
  if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
  if 8 - 8: OoO0O00 . OoO0O00
  if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
  if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
  if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
 iiI = lisp_eid_record ( )
 IIii1i = iiI . decode ( oO0oOOoo0OO0 )
 if ( IIii1i == None ) : return
 if 24 - 24: IiII
 iiI . print_record ( "  " , False )
 if 95 - 95: IiII + OoOoOO00 * OOooOOo
 for oOoOoO0O in range ( iiI . rloc_count ) :
  iIii1IiIiI = lisp_rloc_record ( )
  IIii1i = iIii1IiIiI . decode ( IIii1i , None )
  if ( IIii1i == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
  iIii1IiIiI . print_record ( "    " )
  if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
  if 41 - 41: i1IIi / IiII
  if 73 - 73: o0oOOo0O0Ooo % ooOoO0o
  if 72 - 72: OoO0O00 * OoOoOO00 % I1IiiI - OOooOOo . Oo0Ooo
  if 70 - 70: ooOoO0o . o0oOOo0O0Ooo * II111iiii - O0
 if ( iiI . group . is_null ( ) == False ) :
  if 74 - 74: oO0o % I1IiiI / oO0o / Oo0Ooo / ooOoO0o
  if 29 - 29: ooOoO0o + iIii1I11I1II1 + OoO0O00 - o0oOOo0O0Ooo
  if 74 - 74: II111iiii - II111iiii + ooOoO0o + Oo0Ooo % iIii1I11I1II1
  if 90 - 90: oO0o / o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoOoOO00 / IiII
  if 13 - 13: oO0o + IiII
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( iiI . print_eid_tuple ( ) , False ) ) )
  if 36 - 36: oO0o - OoOoOO00 . O0 % IiII
  if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
  OoOO0o00OOO0o = lisp_control_packet_ipc ( orig_packet , IiII1iiI , "lisp-itr" , 0 )
  lisp_ipc ( OoOO0o00OOO0o , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
  if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
  if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
  if 41 - 41: OoooooooOO + iII111i . OOooOOo
  if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
 lisp_send_map_notify_ack ( lisp_sockets , oO0oOOoo0OO0 , IiiiiIiI1ii , o00oO0Oo )
 return
 if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
 if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
 if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
 if 57 - 57: II111iiii % OoO0O00 * i1IIi
 if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
 if 9 - 9: II111iiii % OoooooooOO
 if 4 - 4: i1IIi * i11iIiiIii % OoooooooOO + OoOoOO00 . oO0o
 if 95 - 95: I1ii11iIi11i * OoOoOO00 % o0oOOo0O0Ooo / O0 + ooOoO0o % OOooOOo
def lisp_process_map_notify_ack ( packet , source ) :
 IiiiiIiI1ii = lisp_map_notify ( "" )
 packet = IiiiiIiI1ii . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 48 - 48: i1IIi + IiII - iIii1I11I1II1 . i11iIiiIii % OOooOOo + I1ii11iIi11i
  if 95 - 95: ooOoO0o + OoOoOO00 . II111iiii + Ii1I
 IiiiiIiI1ii . print_notify ( )
 if 81 - 81: OoooooooOO / OOooOOo / Oo0Ooo
 if 26 - 26: iII111i
 if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
 if 6 - 6: IiII
 if 68 - 68: Oo0Ooo
 if ( IiiiiIiI1ii . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
  if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
 iiI = lisp_eid_record ( )
 if 93 - 93: i11iIiiIii
 if ( iiI . decode ( IiiiiIiI1ii . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
 iiI . print_record ( "  " , False )
 if 40 - 40: IiII % IiII
 I11i11i1 = iiI . print_eid_tuple ( )
 if 9 - 9: I1IiiI * i1IIi + OOooOOo * OoOoOO00
 if 8 - 8: iII111i
 if 51 - 51: I1IiiI
 if 72 - 72: ooOoO0o / I1ii11iIi11i . Ii1I * iII111i . iIii1I11I1II1
 if ( IiiiiIiI1ii . alg_id != LISP_NONE_ALG_ID and IiiiiIiI1ii . auth_len != 0 ) :
  oO00Oooo0o0o0 = lisp_sites_by_eid . lookup_cache ( iiI . eid , True )
  if ( oO00Oooo0o0o0 == None ) :
   i1i1IiIIIiI = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( i1i1IiIIIiI , green ( I11i11i1 , False ) ) )
   if 35 - 35: OoO0O00 . OoOoOO00 % O0 * OoO0O00
   return
   if 68 - 68: OOooOOo
  iIiOo0OOOOo = oO00Oooo0o0o0 . site
  if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
  if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
  if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
  if 15 - 15: i1IIi . iII111i + IiII / I1ii11iIi11i - i1IIi / iII111i
  iIiOo0OOOOo . map_notify_acks_received += 1
  if 27 - 27: OoOoOO00 / OoooooooOO + i1IIi % iIii1I11I1II1 / OoO0O00
  IIIiI1i = IiiiiIiI1ii . key_id
  if ( iIiOo0OOOOo . auth_key . has_key ( IIIiI1i ) ) :
   IIii1 = iIiOo0OOOOo . auth_key [ IIIiI1i ]
  else :
   IIii1 = ""
   if 73 - 73: I1ii11iIi11i / OoOoOO00 / IiII + oO0o
   if 73 - 73: I11i * o0oOOo0O0Ooo * I1IiiI . OoooooooOO % I1Ii111
  IIIIi1Iiii = lisp_verify_auth ( packet , IiiiiIiI1ii . alg_id ,
 IiiiiIiI1ii . auth_data , IIii1 )
  if 9 - 9: oO0o % I1Ii111 . O0 + I1ii11iIi11i - Ii1I - I1ii11iIi11i
  IIIiI1i = "key-id {}" . format ( IIIiI1i ) if IIIiI1i == IiiiiIiI1ii . key_id else "bad key-id {}" . format ( IiiiiIiI1ii . key_id )
  if 57 - 57: i11iIiiIii
  if 21 - 21: iIii1I11I1II1 / I1IiiI / iII111i
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if IIIIi1Iiii else "failed" , IIIiI1i ) )
  if 19 - 19: Oo0Ooo / iIii1I11I1II1 / I11i
  if ( IIIIi1Iiii == False ) : return
  if 71 - 71: iIii1I11I1II1 * I1IiiI
  if 35 - 35: O0
  if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
  if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
  if 78 - 78: I1IiiI - iIii1I11I1II1
 if ( IiiiiIiI1ii . retransmit_timer ) : IiiiiIiI1ii . retransmit_timer . cancel ( )
 if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
 iIi11I11I1i = source . print_address ( )
 ii1i1I1111ii = IiiiiIiI1ii . nonce_key
 if 85 - 85: I11i + OoOoOO00 * O0 * O0
 if ( lisp_map_notify_queue . has_key ( ii1i1I1111ii ) ) :
  IiiiiIiI1ii = lisp_map_notify_queue . pop ( ii1i1I1111ii )
  if ( IiiiiIiI1ii . retransmit_timer ) : IiiiiIiI1ii . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( ii1i1I1111ii ) )
  if 92 - 92: i11iIiiIii
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( IiiiiIiI1ii . nonce_key , red ( iIi11I11I1i , False ) ) )
  if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
  if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
 return
 if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
 if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
 if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
 if 42 - 42: OoOoOO00 . I11i % II111iiii
 if 19 - 19: OoooooooOO
 if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
 if 21 - 21: OOooOOo . Oo0Ooo - i1IIi
 if 56 - 56: I11i
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 32 - 32: OOooOOo / i1IIi / OOooOOo
 if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
 if 45 - 45: Oo0Ooo
 if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
 i1I1i1iI1iI1 = False
 if ( group . is_null ( ) == False ) :
  i1I1i1iI1iI1 = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
 if ( i1I1i1iI1iI1 == False ) :
  i1I1i1iI1iI1 = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 52 - 52: OOooOOo + OoO0O00
  if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
 if ( i1I1i1iI1iI1 ) :
  Oo00O0o = lisp_print_eid_tuple ( eid , group )
  iII1 = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 42 - 42: O0 * iII111i . i1IIi / i11iIiiIii + Ii1I
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( Oo00O0o , False ) , s ,
  # Oo0Ooo % OoOoOO00 . i11iIiiIii / I1Ii111 - Oo0Ooo
 iII1 ) )
  if 24 - 24: iIii1I11I1II1
 return ( i1I1i1iI1iI1 )
 if 79 - 79: IiII - Oo0Ooo - iIii1I11I1II1 % OoO0O00 - iIii1I11I1II1
 if 6 - 6: OoO0O00
 if 62 - 62: Ii1I
 if 11 - 11: I1Ii111 + I1IiiI - OOooOOo
 if 56 - 56: II111iiii + IiII * iIii1I11I1II1 - i1IIi + iIii1I11I1II1
 if 98 - 98: Oo0Ooo . iIii1I11I1II1
 if 12 - 12: I11i - i11iIiiIii * OoOoOO00 - OoOoOO00 * II111iiii
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 45 - 45: I1ii11iIi11i - iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
 O0OOoOoOO = lisp_map_referral ( )
 packet = O0OOoOoOO . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 74 - 74: I1IiiI / o0oOOo0O0Ooo
 O0OOoOoOO . print_map_referral ( )
 if 53 - 53: iIii1I11I1II1 * oO0o
 IiII1iiI = source . print_address ( )
 oOO000 = O0OOoOoOO . nonce
 if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
 if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
 if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
 if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
 for IiIIi1IiiIiI in range ( O0OOoOoOO . record_count ) :
  iiI = lisp_eid_record ( )
  packet = iiI . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 60 - 60: oO0o * I1Ii111
  iiI . print_record ( "  " , True )
  if 81 - 81: oO0o - OOooOOo - oO0o
  if 54 - 54: oO0o % I11i
  if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
  if 22 - 22: iIii1I11I1II1 - OoooooooOO
  ii1i1I1111ii = str ( oOO000 )
  if ( ii1i1I1111ii not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( oOO000 ) , IiII1iiI ) )
   if 8 - 8: ooOoO0o % i11iIiiIii
   if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
   continue
   if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
  O0o00000o0O = lisp_ddt_map_requestQ [ ii1i1I1111ii ]
  if ( O0o00000o0O == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( oOO000 ) , IiII1iiI ) )
   if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
   continue
   if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
   if 73 - 73: O0 % i11iIiiIii
   if 16 - 16: O0
   if 15 - 15: i1IIi % i11iIiiIii
   if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
   if 35 - 35: OoOoOO00 . oO0o / II111iiii
  if ( lisp_map_referral_loop ( O0o00000o0O , iiI . eid , iiI . group ,
 iiI . action , IiII1iiI ) ) :
   O0o00000o0O . dequeue_map_request ( )
   continue
   if 97 - 97: Ii1I + I1Ii111 / II111iiii
   if 14 - 14: iII111i / IiII / oO0o
  O0o00000o0O . last_cached_prefix [ 0 ] = iiI . eid
  O0o00000o0O . last_cached_prefix [ 1 ] = iiI . group
  if 55 - 55: OoO0O00 % O0
  if 92 - 92: OoooooooOO / O0
  if 14 - 14: i11iIiiIii
  if 43 - 43: OOooOOo
  I1i1 = False
  OOoO = lisp_referral_cache_lookup ( iiI . eid , iiI . group ,
 True )
  if ( OOoO == None ) :
   I1i1 = True
   OOoO = lisp_referral ( )
   OOoO . eid = iiI . eid
   OOoO . group = iiI . group
   if ( iiI . ddt_incomplete == False ) : OOoO . add_cache ( )
  elif ( OOoO . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( OOoO . print_eid_tuple ( ) , False ) ) )
   if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
   O0o00000o0O . dequeue_map_request ( )
   continue
   if 93 - 93: OoOoOO00
   if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
  OOo000 = iiI . action
  OOoO . referral_source = source
  OOoO . referral_type = OOo000
  oo0o = iiI . store_ttl ( )
  OOoO . referral_ttl = oo0o
  OOoO . expires = lisp_set_timestamp ( oo0o )
  if 72 - 72: ooOoO0o
  if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
  if 53 - 53: OOooOOo * O0 . iII111i
  if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
  o0O0oOoO0O0O = OOoO . is_referral_negative ( )
  if ( OOoO . referral_set . has_key ( IiII1iiI ) ) :
   ii = OOoO . referral_set [ IiII1iiI ]
   if 91 - 91: Oo0Ooo / I1ii11iIi11i - Oo0Ooo
   if ( ii . updown == False and o0O0oOoO0O0O == False ) :
    ii . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( IiII1iiI ) )
    if 31 - 31: OoooooooOO
   elif ( ii . updown == True and o0O0oOoO0O0O == True ) :
    ii . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( IiII1iiI ) )
    if 51 - 51: O0 - O0
    if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
    if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
    if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
    if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
    if 74 - 74: i11iIiiIii
    if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
    if 6 - 6: I11i
  O00o0Oo = { }
  for ii1i1I1111ii in OOoO . referral_set : O00o0Oo [ ii1i1I1111ii ] = None
  if 62 - 62: Ii1I
  if 75 - 75: o0oOOo0O0Ooo * i11iIiiIii - OoooooooOO * OOooOOo
  if 11 - 11: oO0o
  if 14 - 14: OoooooooOO . I1ii11iIi11i % I1IiiI / I1IiiI % Oo0Ooo
  for IiIIi1IiiIiI in range ( iiI . rloc_count ) :
   iIii1IiIiI = lisp_rloc_record ( )
   packet = iIii1IiIiI . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 97 - 97: i1IIi
   iIii1IiIiI . print_record ( "    " )
   if 6 - 6: Ii1I
   if 43 - 43: i1IIi - Ii1I % iIii1I11I1II1 . OoO0O00 + oO0o - iIii1I11I1II1
   if 17 - 17: IiII . i1IIi
   if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
   oo0o00OO = iIii1IiIiI . rloc . print_address ( )
   if ( OOoO . referral_set . has_key ( oo0o00OO ) == False ) :
    ii = lisp_referral_node ( )
    ii . referral_address . copy_address ( iIii1IiIiI . rloc )
    OOoO . referral_set [ oo0o00OO ] = ii
    if ( IiII1iiI == oo0o00OO and o0O0oOoO0O0O ) : ii . updown = False
   else :
    ii = OOoO . referral_set [ oo0o00OO ]
    if ( O00o0Oo . has_key ( oo0o00OO ) ) : O00o0Oo . pop ( oo0o00OO )
    if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
   ii . priority = iIii1IiIiI . priority
   ii . weight = iIii1IiIiI . weight
   if 43 - 43: I1ii11iIi11i + I11i
   if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
   if 100 - 100: IiII - OoOoOO00 / I11i
   if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
   if 87 - 87: Oo0Ooo
  for ii1i1I1111ii in O00o0Oo : OOoO . referral_set . pop ( ii1i1I1111ii )
  if 65 - 65: ooOoO0o . I1IiiI
  I11i11i1 = OOoO . print_eid_tuple ( )
  if 51 - 51: IiII
  if ( I1i1 ) :
   if ( iiI . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( I11i11i1 , False ) ) )
    if 43 - 43: oO0o - I11i . i11iIiiIii
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( I11i11i1 , False ) , iiI . rloc_count ) )
    if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
    if 30 - 30: I1IiiI % oO0o * OoooooooOO
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( I11i11i1 , False ) , iiI . rloc_count ) )
   if 64 - 64: I1IiiI
   if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
   if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
   if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
   if 90 - 90: o0oOOo0O0Ooo / I1ii11iIi11i - oO0o - Ii1I - I1IiiI + I1Ii111
   if 93 - 93: I1IiiI - I11i . I1IiiI - iIii1I11I1II1
  if ( OOo000 == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( O0o00000o0O . lisp_sockets , OOoO . eid ,
 OOoO . group , O0o00000o0O . nonce , O0o00000o0O . itr , O0o00000o0O . sport , 15 , None , False )
   O0o00000o0O . dequeue_map_request ( )
   if 1 - 1: O0 . Ii1I % Ii1I + II111iiii . oO0o
   if 24 - 24: o0oOOo0O0Ooo . I1Ii111 % O0
  if ( OOo000 == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( O0o00000o0O . tried_root ) :
    lisp_send_negative_map_reply ( O0o00000o0O . lisp_sockets , OOoO . eid ,
 OOoO . group , O0o00000o0O . nonce , O0o00000o0O . itr , O0o00000o0O . sport , 0 , None , False )
    O0o00000o0O . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( O0o00000o0O , True )
    if 67 - 67: I1IiiI * Ii1I
    if 64 - 64: OOooOOo
    if 90 - 90: iII111i . OoOoOO00 + i1IIi % ooOoO0o * I11i + OoooooooOO
  if ( OOo000 == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( OOoO . referral_set . has_key ( IiII1iiI ) ) :
    ii = OOoO . referral_set [ IiII1iiI ]
    ii . updown = False
    if 2 - 2: o0oOOo0O0Ooo . II111iiii
   if ( len ( OOoO . referral_set ) == 0 ) :
    O0o00000o0O . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( O0o00000o0O , False )
    if 9 - 9: I1Ii111 - II111iiii + OoOoOO00 . OoO0O00
    if 33 - 33: Oo0Ooo
    if 12 - 12: i11iIiiIii . Oo0Ooo / OoOoOO00 + iII111i . Ii1I + ooOoO0o
  if ( OOo000 in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( O0o00000o0O . eid . is_exact_match ( iiI . eid ) ) :
    if ( not O0o00000o0O . tried_root ) :
     lisp_send_ddt_map_request ( O0o00000o0O , True )
    else :
     lisp_send_negative_map_reply ( O0o00000o0O . lisp_sockets ,
 OOoO . eid , OOoO . group , O0o00000o0O . nonce , O0o00000o0O . itr ,
 O0o00000o0O . sport , 15 , None , False )
     O0o00000o0O . dequeue_map_request ( )
     if 66 - 66: IiII
   else :
    lisp_send_ddt_map_request ( O0o00000o0O , False )
    if 41 - 41: II111iiii + Oo0Ooo / iII111i . IiII / iII111i / I1IiiI
    if 78 - 78: o0oOOo0O0Ooo % OoOoOO00 . O0
    if 41 - 41: iIii1I11I1II1 . OOooOOo - Oo0Ooo % OOooOOo
  if ( OOo000 == LISP_DDT_ACTION_MS_ACK ) : O0o00000o0O . dequeue_map_request ( )
  if 90 - 90: i11iIiiIii + OoooooooOO - i11iIiiIii + OoooooooOO
 return
 if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
 if 79 - 79: II111iiii / OoooooooOO
 if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
 if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
 if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
 if 17 - 17: I1Ii111
 if 2 - 2: O0 % OoOoOO00 + oO0o
 if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 O0ooOOo0 = lisp_ecm ( 0 )
 packet = O0ooOOo0 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 51 - 51: IiII
  if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
 O0ooOOo0 . print_ecm ( )
 if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
 Ii1I1i1IiiI = lisp_control_header ( )
 if ( Ii1I1i1IiiI . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
  if 95 - 95: O0 - OoOoOO00
 o0OOo0OOo0Oo = Ii1I1i1IiiI . type
 del ( Ii1I1i1IiiI )
 if 51 - 51: oO0o . OoooooooOO + OOooOOo * I1ii11iIi11i - ooOoO0o
 if ( o0OOo0OOo0Oo != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 41 - 41: Oo0Ooo
  if 46 - 46: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii . iII111i
  if 66 - 66: oO0o % i1IIi % OoooooooOO
  if 58 - 58: OOooOOo
  if 89 - 89: iIii1I11I1II1 - i1IIi
 I111iI1i = O0ooOOo0 . udp_sport
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 O0ooOOo0 . source , I111iI1i , O0ooOOo0 . ddt , - 1 )
 return
 if 83 - 83: I1Ii111 * II111iiii
 if 28 - 28: I11i - Oo0Ooo + iIii1I11I1II1 + O0 * Ii1I + I1IiiI
 if 13 - 13: iII111i
 if 42 - 42: I1Ii111 - I1IiiI % I1IiiI * I1IiiI
 if 70 - 70: O0 / I1IiiI / I1IiiI
 if 71 - 71: OOooOOo - Oo0Ooo + IiII * oO0o
 if 90 - 90: OoOoOO00 * I1ii11iIi11i
 if 16 - 16: i1IIi - OoO0O00
 if 61 - 61: o0oOOo0O0Ooo + OoOoOO00 - ooOoO0o + ooOoO0o % ooOoO0o % II111iiii
 if 16 - 16: I1IiiI . Ii1I
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 80 - 80: OOooOOo * O0 / iIii1I11I1II1 / IiII / OoOoOO00
 if 15 - 15: I1ii11iIi11i * iII111i + i11iIiiIii
 if 68 - 68: i1IIi / oO0o * I1ii11iIi11i - OoOoOO00 + Oo0Ooo / O0
 if 1 - 1: ooOoO0o - Oo0Ooo + I1Ii111
 if 90 - 90: I1Ii111 * O0 . iII111i - Oo0Ooo % iIii1I11I1II1
 if 7 - 7: I1ii11iIi11i % o0oOOo0O0Ooo % O0 % iIii1I11I1II1
 if 10 - 10: OoooooooOO - iII111i . i1IIi % oO0o . OoooooooOO + OOooOOo
 oO0o0 = ms . map_server
 if ( lisp_decent_push_configured and oO0o0 . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  oO0o0 = copy . deepcopy ( oO0o0 )
  oO0o0 . address = 0x7f000001
  I11i1iIiiIiIi = bold ( "Bootstrap" , False )
  i11ii = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( I11i1iIiiIiIi , i11ii ) )
  if 59 - 59: I1IiiI * OoooooooOO % OOooOOo / I11i
  if 77 - 77: II111iiii - IiII % OOooOOo
  if 22 - 22: OoooooooOO / oO0o
  if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
  if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
  if 12 - 12: I1Ii111
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 17 - 17: I1Ii111 % oO0o + O0
 if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
 if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
 if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
 if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
 if ( ms . ekey != None ) :
  IiiI = ms . ekey . zfill ( 32 )
  i1Oo = "0" * 8
  o0o0oO0OOO = chacha . ChaCha ( IiiI , i1Oo ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + o0o0oO0OOO
  oOo = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( oOo , ms . ekey_id ) )
  if 39 - 39: OoOoOO00 - I1ii11iIi11i / I1Ii111
  if 48 - 48: IiII - oO0o + I11i % o0oOOo0O0Ooo
 oOOOo = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  oOOOo = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 16 - 16: OoOoOO00 * iII111i . O0
  if 60 - 60: IiII . I11i * Oo0Ooo . i1IIi
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( oO0o0 . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , oOOOo ) )
 if 3 - 3: Ii1I
 lisp_send ( lisp_sockets , oO0o0 , LISP_CTRL_PORT , packet )
 return
 if 68 - 68: OOooOOo * ooOoO0o . I1IiiI - iII111i
 if 81 - 81: I11i % Oo0Ooo / iII111i
 if 44 - 44: Oo0Ooo
 if 90 - 90: Oo0Ooo . ooOoO0o / IiII * I1Ii111 . ooOoO0o + II111iiii
 if 43 - 43: iIii1I11I1II1 % OOooOOo + OoOoOO00 + I1ii11iIi11i - Oo0Ooo / Ii1I
 if 94 - 94: Ii1I / Oo0Ooo % II111iiii % Oo0Ooo * oO0o
 if 54 - 54: O0 / ooOoO0o * I1Ii111
 if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 oo00Oo0 = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 13 - 13: IiII + Oo0Ooo - I1Ii111
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
 if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
 packet = lisp_control_packet_ipc ( packet , oo00Oo0 , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 95 - 95: oO0o / Ii1I + OoO0O00
 if 57 - 57: iIii1I11I1II1 + I1Ii111 % oO0o - Ii1I . I1IiiI
 if 39 - 39: OoO0O00 + II111iiii
 if 98 - 98: O0 - I1Ii111 % oO0o - iII111i + Ii1I * i1IIi
 if 76 - 76: o0oOOo0O0Ooo
 if 55 - 55: OOooOOo + I1ii11iIi11i * Oo0Ooo
 if 11 - 11: i1IIi - OoooooooOO * OoOoOO00 / oO0o - OoooooooOO - I1IiiI
 if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 49 - 49: iII111i + I11i . Oo0Ooo
 if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
 if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
 if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
 if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
 if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
 if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
 if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 1 - 1: i11iIiiIii
 if 1 - 1: iIii1I11I1II1
 if 73 - 73: iII111i + IiII
 if 95 - 95: O0
 if 75 - 75: ooOoO0o
 if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
 if 85 - 85: ooOoO0o
 if 29 - 29: iII111i . Ii1I
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 43 - 43: I11i - I1ii11iIi11i + iIii1I11I1II1 / I1ii11iIi11i * oO0o / iIii1I11I1II1
 if 45 - 45: IiII
 if 49 - 49: I1IiiI . Ii1I * I1IiiI - OoooooooOO . I11i / I1Ii111
 if 9 - 9: iIii1I11I1II1 * Ii1I / O0 - OOooOOo
 if 95 - 95: i11iIiiIii * II111iiii * OOooOOo * iIii1I11I1II1
 if 22 - 22: iIii1I11I1II1 / I1IiiI + OoOoOO00 - OOooOOo . i11iIiiIii / i11iIiiIii
 if 10 - 10: iIii1I11I1II1 % i1IIi
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 78 - 78: I11i + II111iiii % o0oOOo0O0Ooo
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
  if 44 - 44: I1ii11iIi11i
  if 39 - 39: iII111i + Oo0Ooo / oO0o
  if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
  if 99 - 99: I1IiiI * II111iiii
  if 84 - 84: II111iiii - I1IiiI
 if ( lisp_nat_traversal ) :
  i1i1IIiII1I = lisp_get_any_translated_port ( )
  if ( i1i1IIiII1I != None ) : inner_sport = i1i1IIiII1I
  if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
 O0ooOOo0 = lisp_ecm ( inner_sport )
 if 35 - 35: I11i + i1IIi
 O0ooOOo0 . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 O0ooOOo0 . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 O0ooOOo0 . ddt = ddt
 O0o0oOO0o0Oo = O0ooOOo0 . encode ( packet , inner_source , inner_dest )
 if ( O0o0oOO0o0Oo == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
 O0ooOOo0 . print_ecm ( )
 if 16 - 16: I1IiiI
 packet = O0o0oOO0o0Oo + packet
 if 39 - 39: ooOoO0o * II111iiii
 oo0o00OO = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( oo0o00OO ) )
 oO0o0 = lisp_convert_4to6 ( oo0o00OO )
 lisp_send ( lisp_sockets , oO0o0 , LISP_CTRL_PORT , packet )
 return
 if 90 - 90: OoooooooOO * ooOoO0o
 if 14 - 14: I1IiiI % i1IIi
 if 35 - 35: ooOoO0o % o0oOOo0O0Ooo % ooOoO0o
 if 77 - 77: OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
 if 55 - 55: i1IIi
 if 64 - 64: oO0o . OOooOOo * i11iIiiIii + I1Ii111
 if 88 - 88: O0
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
if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 90 - 90: i11iIiiIii - iII111i * oO0o
if 79 - 79: IiII
if 38 - 38: I1Ii111
if 56 - 56: i11iIiiIii
if 58 - 58: i11iIiiIii / OoOoOO00
if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
if 39 - 39: Oo0Ooo . OoO0O00
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
if 100 - 100: ooOoO0o / OoooooooOO
if 73 - 73: i11iIiiIii - Oo0Ooo
if 100 - 100: iIii1I11I1II1 + I1Ii111
if 51 - 51: o0oOOo0O0Ooo * I11i
if 42 - 42: OOooOOo % I11i
def byte_swap_64 ( address ) :
 IiiIIi1 = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
 if 81 - 81: I1IiiI
 if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
 if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
 if 83 - 83: iII111i - I1ii11iIi11i + iII111i
 if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
 if 60 - 60: I1ii11iIi11i / I1Ii111 % i11iIiiIii % oO0o % I1IiiI . Oo0Ooo
 if 20 - 20: IiII - OOooOOo + OoOoOO00
 return ( IiiIIi1 )
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
 if 33 - 33: O0 - iII111i
class lisp_cache_entries ( ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 40 - 40: iII111i * I11i
  if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  if 87 - 87: OoOoOO00
class lisp_cache ( ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 30 - 30: IiII % OoOoOO00 + I1Ii111
  if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
 def cache_size ( self ) :
  return ( self . cache_count )
  if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
  if 87 - 87: I11i
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   o00O0Oo = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   o00O0Oo = prefix . mask_len
  else :
   o00O0Oo = prefix . mask_len + 48
   if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
   if 72 - 72: OoO0O00 * Oo0Ooo - IiII
  o0OoO0000o = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  O000oOOoOOO = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 74 - 74: Ii1I
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    iiiIIiiIi = prefix . addr_length ( ) * 2
    IiiIIi1 = lisp_hex_string ( prefix . address ) . zfill ( iiiIIiiIi )
   else :
    IiiIIi1 = prefix . address
    if 26 - 26: I11i . O0
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   O000oOOoOOO = "8003"
   IiiIIi1 = prefix . address . print_geo ( )
  else :
   O000oOOoOOO = ""
   IiiIIi1 = ""
   if 68 - 68: Ii1I
   if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
  ii1i1I1111ii = o0OoO0000o + O000oOOoOOO + IiiIIi1
  return ( [ o00O0Oo , ii1i1I1111ii ] )
  if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
  if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  o00O0Oo , ii1i1I1111ii = self . build_key ( prefix )
  if ( self . cache . has_key ( o00O0Oo ) == False ) :
   self . cache [ o00O0Oo ] = lisp_cache_entries ( )
   self . cache [ o00O0Oo ] . entries = { }
   self . cache [ o00O0Oo ] . entries_sorted = [ ]
   self . cache_sorted = sorted ( self . cache )
   if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
  if ( self . cache [ o00O0Oo ] . entries . has_key ( ii1i1I1111ii ) == False ) :
   self . cache_count += 1
   if 44 - 44: I11i * iIii1I11I1II1 . I1ii11iIi11i
  self . cache [ o00O0Oo ] . entries [ ii1i1I1111ii ] = entry
  self . cache [ o00O0Oo ] . entries_sorted = sorted ( self . cache [ o00O0Oo ] . entries )
  if 9 - 9: o0oOOo0O0Ooo
  if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
 def lookup_cache ( self , prefix , exact ) :
  i1Iiiii111Ii , ii1i1I1111ii = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( i1Iiiii111Ii ) == False ) : return ( None )
   if ( self . cache [ i1Iiiii111Ii ] . entries . has_key ( ii1i1I1111ii ) == False ) : return ( None )
   return ( self . cache [ i1Iiiii111Ii ] . entries [ ii1i1I1111ii ] )
   if 81 - 81: OoOoOO00 / O0 - IiII
   if 88 - 88: OoO0O00 % Ii1I
  OOo00oO0oo = None
  for o00O0Oo in self . cache_sorted :
   if ( i1Iiiii111Ii < o00O0Oo ) : return ( OOo00oO0oo )
   for iiiIii1 in self . cache [ o00O0Oo ] . entries_sorted :
    oOooiIIIii1Ii1Ii1 = self . cache [ o00O0Oo ] . entries
    if ( iiiIii1 in oOooiIIIii1Ii1Ii1 ) :
     I1iII11ii1 = oOooiIIIii1Ii1Ii1 [ iiiIii1 ]
     if ( I1iII11ii1 == None ) : continue
     if ( prefix . is_more_specific ( I1iII11ii1 . eid ) ) : OOo00oO0oo = I1iII11ii1
     if 86 - 86: I1ii11iIi11i - Ii1I / IiII
     if 91 - 91: ooOoO0o * i11iIiiIii / O0 % Ii1I
     if 35 - 35: Oo0Ooo % O0
  return ( OOo00oO0oo )
  if 71 - 71: oO0o % OOooOOo * i1IIi
  if 50 - 50: OoOoOO00 + i1IIi
 def delete_cache ( self , prefix ) :
  o00O0Oo , ii1i1I1111ii = self . build_key ( prefix )
  if ( self . cache . has_key ( o00O0Oo ) == False ) : return
  if ( self . cache [ o00O0Oo ] . entries . has_key ( ii1i1I1111ii ) == False ) : return
  self . cache [ o00O0Oo ] . entries . pop ( ii1i1I1111ii )
  self . cache [ o00O0Oo ] . entries_sorted . remove ( ii1i1I1111ii )
  self . cache_count -= 1
  if 9 - 9: iII111i / I1Ii111 * Ii1I
  if 25 - 25: OoO0O00 . iII111i % I11i . oO0o * iII111i + Oo0Ooo
 def walk_cache ( self , function , parms ) :
  for o00O0Oo in self . cache_sorted :
   for ii1i1I1111ii in self . cache [ o00O0Oo ] . entries_sorted :
    I1iII11ii1 = self . cache [ o00O0Oo ] . entries [ ii1i1I1111ii ]
    O00O00o0O0O , parms = function ( I1iII11ii1 , parms )
    if ( O00O00o0O0O == False ) : return ( parms )
    if 32 - 32: IiII
    if 90 - 90: I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
  return ( parms )
  if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
  if 96 - 96: O0
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
  for o00O0Oo in self . cache_sorted :
   for ii1i1I1111ii in self . cache [ o00O0Oo ] . entries_sorted :
    I1iII11ii1 = self . cache [ o00O0Oo ] . entries [ ii1i1I1111ii ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( o00O0Oo , ii1i1I1111ii ,
 I1iII11ii1 ) )
    if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
    if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
    if 61 - 61: IiII . O0
    if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
    if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
    if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
    if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
    if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
if 32 - 32: OoO0O00 + OOooOOo . OoO0O00 - Oo0Ooo
if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
if 86 - 86: OOooOOo / OoooooooOO - IiII
if 56 - 56: I1ii11iIi11i - i1IIi * OoooooooOO * O0 * I1IiiI - I1Ii111
if 32 - 32: OoooooooOO . OOooOOo . OoO0O00 . IiII / I11i % i1IIi
if 21 - 21: O0 . OoO0O00 * I1ii11iIi11i % iII111i + OoooooooOO
def lisp_map_cache_lookup ( source , dest ) :
 if 8 - 8: oO0o * iII111i * I11i
 iIIiI = dest . is_multicast_address ( )
 if 30 - 30: I1Ii111
 if 61 - 61: iII111i
 if 50 - 50: Ii1I / I1IiiI . O0
 if 49 - 49: I1Ii111 . OoO0O00 % O0
 IiiiiII1i = lisp_map_cache . lookup_cache ( dest , False )
 if ( IiiiiII1i == None ) :
  I11i11i1 = source . print_sg ( dest ) if iIIiI else dest . print_address ( )
  I11i11i1 = green ( I11i11i1 , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( I11i11i1 ) )
  return ( None )
  if 15 - 15: I11i - Oo0Ooo / I1Ii111 . ooOoO0o % I1IiiI
  if 62 - 62: II111iiii + ooOoO0o + I1IiiI
  if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
  if 13 - 13: I1ii11iIi11i
  if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
 if ( iIIiI == False ) :
  IIiiiIiii = green ( IiiiiII1i . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , IIiiiIiii ) )
  if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
  return ( IiiiiII1i )
  if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
  if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
  if 18 - 18: OoooooooOO - I1ii11iIi11i
  if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
  if 79 - 79: OOooOOo + Oo0Ooo
 IiiiiII1i = IiiiiII1i . lookup_source_cache ( source , False )
 if ( IiiiiII1i == None ) :
  I11i11i1 = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( I11i11i1 ) )
  return ( None )
  if 33 - 33: iIii1I11I1II1
  if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
  if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
  if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
  if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
 IIiiiIiii = green ( IiiiiII1i . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , IIiiiIiii ) )
 if 99 - 99: OOooOOo
 return ( IiiiiII1i )
 if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
 if 53 - 53: oO0o / i1IIi - Oo0Ooo - i1IIi + IiII
 if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
 if 56 - 56: Oo0Ooo % I1ii11iIi11i
 if 53 - 53: OoO0O00 . I11i - ooOoO0o
 if 11 - 11: I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
 if 74 - 74: oO0o . I1Ii111 . II111iiii
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  o0ooo000OO = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( o0ooo000OO )
  if 92 - 92: I1Ii111 % OoooooooOO * I1Ii111
  if 78 - 78: Oo0Ooo . I11i . oO0o + O0 / O0
  if 41 - 41: iII111i * OoO0O00 - OoO0O00
  if 72 - 72: o0oOOo0O0Ooo + oO0o . I1ii11iIi11i + OoO0O00 / I1Ii111
  if 58 - 58: Oo0Ooo / II111iiii % OoooooooOO % II111iiii
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 39 - 39: i1IIi
 if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
 if 59 - 59: i1IIi
 if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
 if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
 if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
 o0ooo000OO = lisp_referral_cache . lookup_cache ( group , exact )
 if ( o0ooo000OO == None ) : return ( None )
 if 71 - 71: OOooOOo
 I11iiiIIi1Ii1 = o0ooo000OO . lookup_source_cache ( eid , exact )
 if ( I11iiiIIi1Ii1 ) : return ( I11iiiIIi1Ii1 )
 if 96 - 96: iII111i * oO0o
 if ( exact ) : o0ooo000OO = None
 return ( o0ooo000OO )
 if 40 - 40: I11i + oO0o - iIii1I11I1II1 + OoO0O00 . IiII
 if 38 - 38: I1IiiI % I1Ii111 / OoOoOO00 . Ii1I . I11i
 if 86 - 86: IiII + OoOoOO00 * IiII
 if 44 - 44: OOooOOo * iIii1I11I1II1 * IiII + Oo0Ooo
 if 60 - 60: I1Ii111
 if 52 - 52: ooOoO0o . I1IiiI . i11iIiiIii . Ii1I - O0 - I1IiiI
 if 53 - 53: i1IIi * OOooOOo - IiII * Oo0Ooo / OoooooooOO + OoooooooOO
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  oo00OOooo = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( oo00OOooo )
  if 10 - 10: oO0o - O0 / Ii1I - OOooOOo - I1Ii111
  if 41 - 41: O0 / I1IiiI - I1ii11iIi11i - i11iIiiIii
  if 2 - 2: OoO0O00 % O0 + iII111i * I1Ii111 / OOooOOo
  if 7 - 7: IiII
  if 30 - 30: iIii1I11I1II1 - OoooooooOO + Oo0Ooo . i1IIi % o0oOOo0O0Ooo
 if ( eid . is_null ( ) ) : return ( None )
 if 7 - 7: IiII - iII111i
 if 59 - 59: Oo0Ooo * ooOoO0o - Ii1I / II111iiii / Oo0Ooo
 if 8 - 8: IiII / OoooooooOO - iIii1I11I1II1
 if 10 - 10: I11i . I11i - OoO0O00 - II111iiii
 if 94 - 94: ooOoO0o
 if 28 - 28: IiII
 oo00OOooo = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( oo00OOooo == None ) : return ( None )
 if 55 - 55: ooOoO0o + oO0o + OoOoOO00 / O0 * II111iiii * OoOoOO00
 ooo000 = oo00OOooo . lookup_source_cache ( eid , exact )
 if ( ooo000 ) : return ( ooo000 )
 if 40 - 40: oO0o
 if ( exact ) : oo00OOooo = None
 return ( oo00OOooo )
 if 31 - 31: Oo0Ooo * iIii1I11I1II1 * Ii1I * Ii1I
 if 23 - 23: oO0o + OoO0O00 * O0
 if 99 - 99: oO0o * IiII * oO0o
 if 70 - 70: IiII + iII111i / I1ii11iIi11i
 if 97 - 97: I1IiiI * OoOoOO00 / iII111i * i11iIiiIii
 if 20 - 20: Ii1I . I11i % iII111i * iIii1I11I1II1 . OoO0O00 . Ii1I
 if 50 - 50: I1IiiI % OOooOOo / iIii1I11I1II1 / I1ii11iIi11i % oO0o . Ii1I
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 14 - 14: oO0o / Ii1I - I1Ii111
 if ( group . is_null ( ) ) :
  oO00Oooo0o0o0 = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( oO00Oooo0o0o0 )
  if 79 - 79: I1Ii111
  if 54 - 54: II111iiii
  if 98 - 98: Ii1I - i11iIiiIii
  if 31 - 31: IiII / o0oOOo0O0Ooo
  if 27 - 27: Oo0Ooo
 if ( eid . is_null ( ) ) : return ( None )
 if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
 if 35 - 35: o0oOOo0O0Ooo % iII111i / O0 * I1IiiI . o0oOOo0O0Ooo / OOooOOo
 if 81 - 81: I1ii11iIi11i - i11iIiiIii
 if 49 - 49: iII111i * I11i - II111iiii . o0oOOo0O0Ooo
 if 52 - 52: Ii1I + Ii1I - II111iiii . O0 + I1ii11iIi11i
 if 60 - 60: i11iIiiIii + IiII
 oO00Oooo0o0o0 = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( oO00Oooo0o0o0 == None ) : return ( None )
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
 O00oOOOOoOO = oO00Oooo0o0o0 . lookup_source_cache ( eid , exact )
 if ( O00oOOOOoOO ) : return ( O00oOOOOoOO )
 if 52 - 52: II111iiii / OoO0O00 . Ii1I
 if ( exact ) :
  oO00Oooo0o0o0 = None
 else :
  i1II1 = oO00Oooo0o0o0 . parent_for_more_specifics
  if ( i1II1 and i1II1 . accept_more_specifics ) :
   if ( group . is_more_specific ( i1II1 . group ) ) : oO00Oooo0o0o0 = i1II1
   if 68 - 68: iII111i
   if 67 - 67: I1IiiI * I1IiiI
 return ( oO00Oooo0o0o0 )
 if 100 - 100: iII111i * iII111i . Oo0Ooo
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
 if 26 - 26: I1IiiI
 if 26 - 26: IiII . Ii1I / IiII - OoO0O00 % OoO0O00
 if 72 - 72: OoooooooOO * II111iiii + OoO0O00 % iIii1I11I1II1 . I1ii11iIi11i % OoooooooOO
 if 19 - 19: OoOoOO00 + I1Ii111
 if 19 - 19: I1ii11iIi11i / I1Ii111 + OoooooooOO - O0
 if 49 - 49: I1ii11iIi11i / OoOoOO00 - I1IiiI + iII111i . OOooOOo % oO0o
 if 34 - 34: OoO0O00 - I1IiiI + OoOoOO00
 if 22 - 22: iIii1I11I1II1 . i1IIi . OOooOOo % Oo0Ooo - i1IIi
class lisp_address ( ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 78 - 78: I1IiiI / i1IIi % II111iiii % I1IiiI % Ii1I
  if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 38 - 38: IiII . I1Ii111
  if 69 - 69: ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + Ii1I . ooOoO0o
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 73 - 73: I11i % I11i . ooOoO0o + OoOoOO00
  if 33 - 33: i11iIiiIii . i11iIiiIii * i11iIiiIii / iIii1I11I1II1 / I1ii11iIi11i . ooOoO0o
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 11 - 11: iII111i
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 60 - 60: I1ii11iIi11i / I1Ii111
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 10 - 10: OoO0O00 * iIii1I11I1II1 / I11i % II111iiii . OoOoOO00 / I1IiiI
   if 4 - 4: Oo0Ooo * o0oOOo0O0Ooo
   if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
  if 69 - 69: iII111i % I1ii11iIi11i
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  IiiIIi1 = self . address
  if ( ( ( IiiIIi1 & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( IiiIIi1 & 0xff000000 ) >> 24 ) == 172 ) :
   iIiIi1iiII1I = ( IiiIIi1 & 0x00ff0000 ) >> 16
   if ( iIiIi1iiII1I >= 16 and iIiIi1iiII1I <= 31 ) : return ( True )
   if 47 - 47: Oo0Ooo . IiII * II111iiii / ooOoO0o
  if ( ( ( IiiIIi1 & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 59 - 59: oO0o
  if 62 - 62: O0 - i11iIiiIii % OOooOOo
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 44 - 44: I1ii11iIi11i * i1IIi - iIii1I11I1II1 - oO0o - oO0o * II111iiii
  if 98 - 98: Oo0Ooo + ooOoO0o / OOooOOo . iIii1I11I1II1 . I1IiiI . OoOoOO00
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 92 - 92: i1IIi + OoOoOO00 * i1IIi / IiII
  return ( 0 )
  if 4 - 4: oO0o % OoO0O00 + IiII + o0oOOo0O0Ooo
  if 82 - 82: O0 / I1Ii111 + OOooOOo . IiII + Ii1I
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  IiiIIi1 = self . address >> 96
  return ( IiiIIi1 == 0x20010005 )
  if 31 - 31: i1IIi * OoO0O00 - Ii1I + I11i
  if 8 - 8: O0 + i1IIi . O0
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
   if 67 - 67: I1IiiI
  return ( 0 )
  if 42 - 42: ooOoO0o - o0oOOo0O0Ooo % oO0o - ooOoO0o
  if 87 - 87: OoooooooOO / O0
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 57 - 57: iIii1I11I1II1 / IiII + OoO0O00 * oO0o + Ii1I
  if 76 - 76: i11iIiiIii . OOooOOo / I11i * oO0o % iIii1I11I1II1 . ooOoO0o
 def packet_format ( self ) :
  if 75 - 75: O0 + I1IiiI
  if 67 - 67: OoOoOO00 % OoooooooOO / OoO0O00 - OoO0O00 / O0
  if 19 - 19: iIii1I11I1II1 / OOooOOo % I11i % I1IiiI / I1ii11iIi11i
  if 73 - 73: II111iiii
  if 26 - 26: II111iiii . iIii1I11I1II1 - I1Ii111 % OOooOOo
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 83 - 83: OOooOOo + OoooooooOO % I1Ii111 % IiII + i11iIiiIii
  if 10 - 10: OoooooooOO . Ii1I % I1Ii111 + IiII
 def pack_address ( self ) :
  O00oO00oOO00O = self . packet_format ( )
  IIii1i = ""
  if ( self . is_ipv4 ( ) ) :
   IIii1i = struct . pack ( O00oO00oOO00O , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   Ii1iiI1i1 = byte_swap_64 ( self . address >> 64 )
   iIi = byte_swap_64 ( self . address & 0xffffffffffffffff )
   IIii1i = struct . pack ( O00oO00oOO00O , Ii1iiI1i1 , iIi )
  elif ( self . is_mac ( ) ) :
   IiiIIi1 = self . address
   Ii1iiI1i1 = ( IiiIIi1 >> 32 ) & 0xffff
   iIi = ( IiiIIi1 >> 16 ) & 0xffff
   OOoO0OoOo = IiiIIi1 & 0xffff
   IIii1i = struct . pack ( O00oO00oOO00O , Ii1iiI1i1 , iIi , OOoO0OoOo )
  elif ( self . is_e164 ( ) ) :
   IiiIIi1 = self . address
   Ii1iiI1i1 = ( IiiIIi1 >> 32 ) & 0xffffffff
   iIi = ( IiiIIi1 & 0xffffffff )
   IIii1i = struct . pack ( O00oO00oOO00O , Ii1iiI1i1 , iIi )
  elif ( self . is_dist_name ( ) ) :
   IIii1i += self . address + "\0"
   if 87 - 87: iII111i
  return ( IIii1i )
  if 32 - 32: OoOoOO00
  if 65 - 65: iIii1I11I1II1 + iII111i
 def unpack_address ( self , packet ) :
  O00oO00oOO00O = self . packet_format ( )
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 90 - 90: i11iIiiIii - Oo0Ooo
  IiiIIi1 = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 31 - 31: OoOoOO00 + OoOoOO00 + OoooooooOO % O0
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( IiiIIi1 [ 0 ] )
   if 14 - 14: i1IIi / OoooooooOO . I1IiiI * I1Ii111 + OoO0O00
  elif ( self . is_ipv6 ( ) ) :
   if 45 - 45: OoooooooOO * I1Ii111
   if 7 - 7: O0
   if 42 - 42: o0oOOo0O0Ooo / Ii1I
   if 31 - 31: OOooOOo
   if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
   if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
   if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
   if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
   if ( IiiIIi1 [ 0 ] <= 0xffff and ( IiiIIi1 [ 0 ] & 0xff ) == 0 ) :
    O0OO0OO0 = ( IiiIIi1 [ 0 ] << 48 ) << 64
   else :
    O0OO0OO0 = byte_swap_64 ( IiiIIi1 [ 0 ] ) << 64
    if 23 - 23: OoOoOO00 % ooOoO0o
   iii11Ii = byte_swap_64 ( IiiIIi1 [ 1 ] )
   self . address = O0OO0OO0 | iii11Ii
   if 5 - 5: o0oOOo0O0Ooo * i11iIiiIii
  elif ( self . is_mac ( ) ) :
   OOIIIi11i1Ii11i = IiiIIi1 [ 0 ]
   O00o = IiiIIi1 [ 1 ]
   iII1II = IiiIIi1 [ 2 ]
   self . address = ( OOIIIi11i1Ii11i << 32 ) + ( O00o << 16 ) + iII1II
   if 66 - 66: I1Ii111 - o0oOOo0O0Ooo + I11i
  elif ( self . is_e164 ( ) ) :
   self . address = ( IiiIIi1 [ 0 ] << 32 ) + IiiIIi1 [ 1 ]
   if 1 - 1: i1IIi % oO0o . iII111i - I1Ii111 % iII111i
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   ooOoooOoo0oO = 0
   if 83 - 83: oO0o
  packet = packet [ ooOoooOoo0oO : : ]
  return ( packet )
  if 42 - 42: I1ii11iIi11i . IiII . O0 / iIii1I11I1II1 - Oo0Ooo % ooOoO0o
  if 98 - 98: o0oOOo0O0Ooo % I1IiiI - Oo0Ooo % o0oOOo0O0Ooo % OoooooooOO
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 16 - 16: I11i - Ii1I . I1ii11iIi11i % Oo0Ooo
  if 7 - 7: oO0o - I11i / OoOoOO00 * I1Ii111 - Ii1I - i11iIiiIii
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 57 - 57: IiII % i1IIi
  if 74 - 74: iII111i % I11i * i11iIiiIii . i11iIiiIii + iIii1I11I1II1 * i1IIi
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 53 - 53: I1ii11iIi11i + IiII / OOooOOo . OoooooooOO - ooOoO0o
  if 47 - 47: i11iIiiIii
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 21 - 21: i1IIi - oO0o - Oo0Ooo
  if 11 - 11: i1IIi
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
  if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 56 - 56: Ii1I . iII111i
  if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
  if 52 - 52: i11iIiiIii
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 1 - 1: i1IIi * iIii1I11I1II1
  if 29 - 29: I11i
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
  if 6 - 6: IiII / OoO0O00
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
  if 77 - 77: Ii1I
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 9 - 9: OOooOOo / OoooooooOO + iII111i
  if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 20 - 20: I1Ii111
  if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
  if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
  if 56 - 56: iII111i * II111iiii . OoooooooOO . I11i
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 25 - 25: ooOoO0o % o0oOOo0O0Ooo - i11iIiiIii
  if 79 - 79: iII111i - I1IiiI % O0 / Oo0Ooo + OoOoOO00 . Oo0Ooo
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 59 - 59: I1ii11iIi11i * OoOoOO00 / Ii1I
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 80 - 80: IiII - ooOoO0o / OoOoOO00 / I11i * O0 + oO0o
  return ( False )
  if 77 - 77: ooOoO0o + I1ii11iIi11i * o0oOOo0O0Ooo / i1IIi * I11i
  if 70 - 70: oO0o / iII111i * i1IIi / II111iiii / OoOoOO00 + oO0o
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 30 - 30: i1IIi - iII111i - i11iIiiIii . OoOoOO00 . o0oOOo0O0Ooo
  if 74 - 74: i11iIiiIii / II111iiii
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 62 - 62: O0
  if 63 - 63: Oo0Ooo + Oo0Ooo
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 48 - 48: Oo0Ooo * I1ii11iIi11i % II111iiii
  if 42 - 42: I1Ii111 - ooOoO0o % o0oOOo0O0Ooo * I1IiiI . o0oOOo0O0Ooo
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 84 - 84: iIii1I11I1II1
  if 39 - 39: Ii1I . II111iiii / I1IiiI
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 44 - 44: Ii1I / Ii1I / OoO0O00 % ooOoO0o / I11i . I1ii11iIi11i
  if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 81 - 81: I1Ii111 % OoO0O00 / O0
  if 55 - 55: i1IIi - I1Ii111 + I11i
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
  if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
  if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
  if 34 - 34: I1IiiI + I1Ii111 % ooOoO0o
  if 24 - 24: Ii1I % II111iiii - i11iIiiIii
  IiIIi1IiiIiI = addr_str . find ( "[" )
  oOoOoO0O = addr_str . find ( "]" )
  if ( IiIIi1IiiIiI != - 1 and oOoOoO0O != - 1 ) :
   self . instance_id = int ( addr_str [ IiIIi1IiiIiI + 1 : oOoOoO0O ] )
   addr_str = addr_str [ oOoOoO0O + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 52 - 52: OoO0O00
    if 76 - 76: ooOoO0o - iII111i % ooOoO0o / oO0o . OOooOOo
    if 50 - 50: IiII . i11iIiiIii % I11i
    if 22 - 22: i1IIi - II111iiii - OoOoOO00 . iII111i
    if 43 - 43: I1Ii111 * OOooOOo - IiII . i11iIiiIii
    if 34 - 34: iII111i . OoOoOO00
  if ( self . is_ipv4 ( ) ) :
   IIIIi11IiiI = addr_str . split ( "." )
   i11II = int ( IIIIi11IiiI [ 0 ] ) << 24
   i11II += int ( IIIIi11IiiI [ 1 ] ) << 16
   i11II += int ( IIIIi11IiiI [ 2 ] ) << 8
   i11II += int ( IIIIi11IiiI [ 3 ] )
   self . address = i11II
  elif ( self . is_ipv6 ( ) ) :
   if 7 - 7: iIii1I11I1II1 - Ii1I % II111iiii + Ii1I
   if 19 - 19: I1ii11iIi11i
   if 95 - 95: I11i
   if 39 - 39: IiII * I11i + I1IiiI
   if 60 - 60: I11i % Ii1I * oO0o % II111iiii + o0oOOo0O0Ooo
   if 62 - 62: O0 - O0 - I1IiiI . OoO0O00 . i11iIiiIii % i11iIiiIii
   if 54 - 54: I1IiiI + OoooooooOO / iII111i / I11i . I11i % I11i
   if 54 - 54: OoO0O00 * I11i * iIii1I11I1II1 * IiII
   if 12 - 12: O0 - iII111i * IiII . i11iIiiIii
   if 25 - 25: Ii1I % i1IIi * I11i * Ii1I - IiII . i11iIiiIii
   if 40 - 40: OOooOOo - OoooooooOO
   if 36 - 36: i1IIi % OoOoOO00 - i1IIi
   if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
   if 97 - 97: I11i . ooOoO0o
   if 87 - 87: oO0o / iIii1I11I1II1 - I11i + OoooooooOO
   if 79 - 79: I1ii11iIi11i * IiII . I1ii11iIi11i
   if 65 - 65: iII111i - Ii1I - II111iiii * O0 + I1ii11iIi11i . iIii1I11I1II1
   oO0o0oo0OoOO = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 76 - 76: I1IiiI * iII111i . II111iiii % OoO0O00 . Ii1I * OOooOOo
   addr_str = binascii . hexlify ( addr_str )
   if 5 - 5: IiII % OoO0O00 + I1Ii111 % OoooooooOO / o0oOOo0O0Ooo + OoooooooOO
   if ( oO0o0oo0OoOO ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 93 - 93: I1IiiI % OoOoOO00
   self . address = int ( addr_str , 16 )
   if 12 - 12: Oo0Ooo + I11i
  elif ( self . is_geo_prefix ( ) ) :
   iiIi1ii1IiI = lisp_geo ( None )
   iiIi1ii1IiI . name = "geo-prefix-{}" . format ( iiIi1ii1IiI )
   iiIi1ii1IiI . parse_geo_string ( addr_str )
   self . address = iiIi1ii1IiI
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
   if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
  self . mask_len = self . host_mask_len ( )
  if 78 - 78: I1Ii111 + I1Ii111
  if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   ooo = prefix_str . find ( "]" )
   iIi1iii1 = len ( prefix_str [ ooo + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , iIi1iii1 = prefix_str . split ( "/" )
  else :
   i1i = prefix_str . find ( "'" )
   if ( i1i == - 1 ) : return
   O0ooOo0 = prefix_str . find ( "'" , i1i + 1 )
   if ( O0ooOo0 == - 1 ) : return
   iIi1iii1 = len ( prefix_str [ i1i + 1 : O0ooOo0 ] ) * 8
   if 19 - 19: Ii1I
   if 51 - 51: oO0o
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( iIi1iii1 )
  if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
  if 35 - 35: o0oOOo0O0Ooo % II111iiii + O0
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  oOoo00oOoO0o = ( 2 ** self . mask_len ) - 1
  IIiIiII = self . addr_length ( ) * 8 - self . mask_len
  oOoo00oOoO0o <<= IIiIiII
  self . address &= oOoo00oOoO0o
  if 49 - 49: Ii1I * I1ii11iIi11i
  if 66 - 66: ooOoO0o
 def is_geo_string ( self , addr_str ) :
  ooo = addr_str . find ( "]" )
  if ( ooo != - 1 ) : addr_str = addr_str [ ooo + 1 : : ]
  if 2 - 2: o0oOOo0O0Ooo
  iiIi1ii1IiI = addr_str . split ( "/" )
  if ( len ( iiIi1ii1IiI ) == 2 ) :
   if ( iiIi1ii1IiI [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 86 - 86: OoooooooOO * I1ii11iIi11i + O0 + o0oOOo0O0Ooo + OOooOOo % OoO0O00
  iiIi1ii1IiI = iiIi1ii1IiI [ 0 ]
  iiIi1ii1IiI = iiIi1ii1IiI . split ( "-" )
  o0o0O0O0Oooo0 = len ( iiIi1ii1IiI )
  if ( o0o0O0O0Oooo0 < 8 or o0o0O0O0Oooo0 > 9 ) : return ( False )
  if 34 - 34: I1IiiI + i1IIi . II111iiii . O0
  for OOOi1II11i111 in range ( 0 , o0o0O0O0Oooo0 ) :
   if ( OOOi1II11i111 == 3 ) :
    if ( iiIi1ii1IiI [ OOOi1II11i111 ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 11 - 11: Ii1I
   if ( OOOi1II11i111 == 7 ) :
    if ( iiIi1ii1IiI [ OOOi1II11i111 ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 35 - 35: i11iIiiIii + ooOoO0o
   if ( iiIi1ii1IiI [ OOOi1II11i111 ] . isdigit ( ) == False ) : return ( False )
   if 82 - 82: OoooooooOO % O0 + iIii1I11I1II1
  return ( True )
  if 100 - 100: OoooooooOO + I11i - OoOoOO00 + Ii1I + I1Ii111 * iIii1I11I1II1
  if 55 - 55: I1Ii111
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 18 - 18: iIii1I11I1II1 + O0 / iIii1I11I1II1 . oO0o % O0
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 72 - 72: ooOoO0o / IiII / OOooOOo + OOooOOo / I1ii11iIi11i / i1IIi
  if 61 - 61: I11i * O0
 def print_address ( self ) :
  IiiIIi1 = self . print_address_no_iid ( )
  o0OoO0000o = "[" + str ( self . instance_id )
  for IiIIi1IiiIiI in self . iid_list : o0OoO0000o += "," + str ( IiIIi1IiiIiI )
  o0OoO0000o += "]"
  IiiIIi1 = "{}{}" . format ( o0OoO0000o , IiiIIi1 )
  return ( IiiIIi1 )
  if 80 - 80: I1ii11iIi11i + II111iiii % Oo0Ooo - o0oOOo0O0Ooo
  if 1 - 1: iII111i - OoOoOO00
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   IiiIIi1 = self . address
   IiiIiiI = IiiIIi1 >> 24
   Ii1II = ( IiiIIi1 >> 16 ) & 0xff
   OoIIiiI1II = ( IiiIIi1 >> 8 ) & 0xff
   OOOoo0O0 = IiiIIi1 & 0xff
   return ( "{}.{}.{}.{}" . format ( IiiIiiI , Ii1II , OoIIiiI1II , OOOoo0O0 ) )
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
   if 25 - 25: o0oOOo0O0Ooo
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 29 - 29: I1Ii111
  if 58 - 58: i1IIi / I1ii11iIi11i
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   Iii1iI1IIi = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , Iii1iI1IIi ) )
   if 39 - 39: iII111i / I11i
  IiiIIi1 = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( IiiIIi1 )
  if ( self . is_geo_prefix ( ) ) : return ( IiiIIi1 )
  if 67 - 67: i1IIi
  ooo = IiiIIi1 . find ( "no-address" )
  if ( ooo == - 1 ) :
   IiiIIi1 = "{}/{}" . format ( IiiIIi1 , str ( self . mask_len ) )
  else :
   IiiIIi1 = IiiIIi1 [ 0 : ooo ]
   if 1 - 1: OoOoOO00 * O0 + i11iIiiIii . ooOoO0o / OoO0O00
  return ( IiiIIi1 )
  if 48 - 48: o0oOOo0O0Ooo * II111iiii
  if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
 def print_prefix_no_iid ( self ) :
  IiiIIi1 = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( IiiIIi1 )
  if ( self . is_geo_prefix ( ) ) : return ( IiiIIi1 )
  return ( "{}/{}" . format ( IiiIIi1 , str ( self . mask_len ) ) )
  if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
  if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  IiiIIi1 = self . print_address ( )
  ooo = IiiIIi1 . find ( "]" )
  if ( ooo != - 1 ) : IiiIIi1 = IiiIIi1 [ ooo + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   IiiIIi1 = IiiIIi1 . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , IiiIIi1 ) )
   if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
  return ( "{}-{}-{}" . format ( self . instance_id , IiiIIi1 , self . mask_len ) )
  if 14 - 14: OOooOOo * IiII
  if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
 def print_sg ( self , g ) :
  IiII1iiI = self . print_prefix ( )
  i1I111 = IiII1iiI . find ( "]" ) + 1
  g = g . print_prefix ( )
  O0o0 = g . find ( "]" ) + 1
  II11I = "[{}]({}, {})" . format ( self . instance_id , IiII1iiI [ i1I111 : : ] , g [ O0o0 : : ] )
  return ( II11I )
  if 35 - 35: I1IiiI * OoO0O00 - iII111i . Ii1I + ooOoO0o
  if 81 - 81: OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % I1Ii111 / ooOoO0o
 def hash_address ( self , addr ) :
  Ii1iiI1i1 = self . address
  iIi = addr . address
  if 53 - 53: O0 / I1ii11iIi11i . OoooooooOO
  if ( self . is_geo_prefix ( ) ) : Ii1iiI1i1 = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : iIi = addr . address . print_geo ( )
  if 35 - 35: OoOoOO00 - OOooOOo + OoOoOO00 % OoooooooOO . oO0o
  if ( type ( Ii1iiI1i1 ) == str ) :
   Ii1iiI1i1 = int ( binascii . hexlify ( Ii1iiI1i1 [ 0 : 1 ] ) )
   if 61 - 61: I11i / o0oOOo0O0Ooo / OoO0O00
  if ( type ( iIi ) == str ) :
   iIi = int ( binascii . hexlify ( iIi [ 0 : 1 ] ) )
   if 17 - 17: o0oOOo0O0Ooo * OoO0O00 + I11i + oO0o % OoOoOO00 - Oo0Ooo
  return ( Ii1iiI1i1 ^ iIi )
  if 63 - 63: i11iIiiIii % I11i
  if 64 - 64: oO0o + I11i / i1IIi * OoO0O00
  if 19 - 19: O0 . O0
  if 13 - 13: i11iIiiIii - i11iIiiIii . iIii1I11I1II1 - O0 . I11i / i11iIiiIii
  if 59 - 59: ooOoO0o + I1ii11iIi11i . OoO0O00 . O0
  if 45 - 45: O0 . o0oOOo0O0Ooo + OoOoOO00 / I1ii11iIi11i + Ii1I % I1Ii111
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 20 - 20: Oo0Ooo
  iIi1iii1 = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   IIIIIiI1 = 2 ** ( 32 - iIi1iii1 )
   iIii1i11iI1 = prefix . instance_id
   Iii1iI1IIi = iIii1i11iI1 + IIIIIiI1
   return ( self . instance_id in range ( iIii1i11iI1 , Iii1iI1IIi ) )
   if 7 - 7: OoooooooOO % I1Ii111 * I1Ii111 - II111iiii - Ii1I
   if 75 - 75: o0oOOo0O0Ooo / Oo0Ooo + oO0o
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 67 - 67: IiII + OoooooooOO . i11iIiiIii - I1Ii111 . i11iIiiIii
   if 70 - 70: OoO0O00 * OoooooooOO
   if 52 - 52: Ii1I . iII111i / OoooooooOO
   if 19 - 19: OOooOOo % o0oOOo0O0Ooo
   if 23 - 23: I1Ii111 % iIii1I11I1II1 - ooOoO0o
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   IiiIIi1 = self . address
   oOiII1i1 = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    IiiIIi1 = self . address . print_geo ( )
    oOiII1i1 = prefix . address . print_geo ( )
    if 6 - 6: Oo0Ooo
   if ( len ( IiiIIi1 ) < len ( oOiII1i1 ) ) : return ( False )
   return ( IiiIIi1 . find ( oOiII1i1 ) == 0 )
   if 9 - 9: Oo0Ooo - II111iiii - i1IIi - ooOoO0o / o0oOOo0O0Ooo * I1ii11iIi11i
   if 29 - 29: ooOoO0o
   if 65 - 65: i1IIi * ooOoO0o * I1IiiI
   if 36 - 36: o0oOOo0O0Ooo - Ii1I + O0 + OOooOOo
   if 11 - 11: I11i / OoooooooOO . I11i . II111iiii / oO0o - i11iIiiIii
  if ( self . mask_len < iIi1iii1 ) : return ( False )
  if 67 - 67: o0oOOo0O0Ooo . I1Ii111 % iIii1I11I1II1 / I1Ii111
  IIiIiII = ( prefix . addr_length ( ) * 8 ) - iIi1iii1
  oOoo00oOoO0o = ( 2 ** iIi1iii1 - 1 ) << IIiIiII
  return ( ( self . address & oOoo00oOoO0o ) == prefix . address )
  if 18 - 18: I11i * ooOoO0o
  if 46 - 46: IiII
 def mask_address ( self , mask_len ) :
  IIiIiII = ( self . addr_length ( ) * 8 ) - mask_len
  oOoo00oOoO0o = ( 2 ** mask_len - 1 ) << IIiIiII
  self . address &= oOoo00oOoO0o
  if 96 - 96: iII111i / i11iIiiIii + Oo0Ooo . I1IiiI + iII111i % OoOoOO00
  if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  O00OooO0o = self . print_prefix ( )
  oo00oO000oOo = prefix . print_prefix ( ) if prefix else ""
  return ( O00OooO0o == oo00oO000oOo )
  if 57 - 57: I1IiiI - ooOoO0o
  if 70 - 70: I1ii11iIi11i * ooOoO0o
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   IIIIIi = lisp_myrlocs [ 0 ]
   if ( IIIIIi == None ) : return ( False )
   IIIIIi = IIIIIi . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == IIIIIi )
   if 40 - 40: I1IiiI / I1ii11iIi11i / Oo0Ooo
  if ( self . is_ipv6 ( ) ) :
   IIIIIi = lisp_myrlocs [ 1 ]
   if ( IIIIIi == None ) : return ( False )
   IIIIIi = IIIIIi . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == IIIIIi )
   if 28 - 28: OoO0O00 / I1ii11iIi11i % OOooOOo % I1IiiI + Ii1I
  return ( False )
  if 6 - 6: o0oOOo0O0Ooo % OOooOOo
  if 71 - 71: oO0o + II111iiii * O0 / i11iIiiIii * o0oOOo0O0Ooo
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid == 0 and mask_len == 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 85 - 85: o0oOOo0O0Ooo - I1Ii111
  self . instance_id = iid
  self . mask_len = mask_len
  if 90 - 90: OoO0O00 * I1Ii111 * iII111i * Ii1I + OoOoOO00 / iII111i
  if 63 - 63: o0oOOo0O0Ooo * I1Ii111
 def lcaf_length ( self , lcaf_type ) :
  iiiIIiiIi = self . addr_length ( ) + 2
  if ( lcaf_type == LISP_LCAF_AFI_LIST_TYPE ) : iiiIIiiIi += 4
  if ( lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE ) : iiiIIiiIi += 4
  if ( lcaf_type == LISP_LCAF_ASN_TYPE ) : iiiIIiiIi += 4
  if ( lcaf_type == LISP_LCAF_APP_DATA_TYPE ) : iiiIIiiIi += 8
  if ( lcaf_type == LISP_LCAF_GEO_COORD_TYPE ) : iiiIIiiIi += 12
  if ( lcaf_type == LISP_LCAF_OPAQUE_TYPE ) : iiiIIiiIi += 0
  if ( lcaf_type == LISP_LCAF_NAT_TYPE ) : iiiIIiiIi += 4
  if ( lcaf_type == LISP_LCAF_NONCE_LOC_TYPE ) : iiiIIiiIi += 4
  if ( lcaf_type == LISP_LCAF_MCAST_INFO_TYPE ) : iiiIIiiIi = iiiIIiiIi * 2 + 8
  if ( lcaf_type == LISP_LCAF_ELP_TYPE ) : iiiIIiiIi += 0
  if ( lcaf_type == LISP_LCAF_SECURITY_TYPE ) : iiiIIiiIi += 6
  if ( lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE ) : iiiIIiiIi += 4
  if ( lcaf_type == LISP_LCAF_RLE_TYPE ) : iiiIIiiIi += 4
  return ( iiiIIiiIi )
  if 9 - 9: ooOoO0o . O0 + II111iiii . OoooooooOO
  if 97 - 97: O0 / OoOoOO00 / ooOoO0o
  if 11 - 11: II111iiii . i11iIiiIii - Ii1I . IiII
  if 10 - 10: OOooOOo * OoooooooOO
  if 12 - 12: II111iiii - O0 . i1IIi % oO0o % OoooooooOO
  if 36 - 36: IiII * OoOoOO00 - iIii1I11I1II1 + II111iiii
  if 65 - 65: I1IiiI * I11i . I1Ii111 % I1ii11iIi11i + O0
  if 91 - 91: OoooooooOO % I1Ii111 * OoO0O00 - OoOoOO00
  if 5 - 5: iIii1I11I1II1 * I11i - oO0o % oO0o % o0oOOo0O0Ooo . i1IIi
  if 95 - 95: Oo0Ooo * I1ii11iIi11i + iII111i - o0oOOo0O0Ooo - Oo0Ooo . OoO0O00
  if 62 - 62: I11i
  if 58 - 58: I11i . OoOoOO00 + iII111i . iII111i
  if 43 - 43: I1Ii111 + I1Ii111 % Oo0Ooo % OoO0O00 - ooOoO0o
  if 61 - 61: OoOoOO00 + Ii1I % i11iIiiIii - I1IiiI * OoO0O00 % iIii1I11I1II1
  if 66 - 66: iII111i + i1IIi
  if 24 - 24: O0 / OoooooooOO - OoOoOO00
  if 51 - 51: OoO0O00 + o0oOOo0O0Ooo - II111iiii * I11i + Ii1I
 def lcaf_encode_iid ( self ) :
  O000oo0O0OO0 = LISP_LCAF_INSTANCE_ID_TYPE
  O0III1Iiii1i11 = socket . htons ( self . lcaf_length ( O000oo0O0OO0 ) )
  o0OoO0000o = self . instance_id
  O000oOOoOOO = self . afi
  o00O0Oo = 0
  if ( O000oOOoOOO < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    O000oOOoOOO = LISP_AFI_LCAF
    o00O0Oo = 0
   else :
    O000oOOoOOO = 0
    o00O0Oo = self . mask_len
    if 16 - 16: I1Ii111 * i1IIi . I1IiiI . OOooOOo % Ii1I - o0oOOo0O0Ooo
    if 89 - 89: Ii1I * I1ii11iIi11i * I1IiiI % iII111i % Ii1I + O0
    if 53 - 53: i11iIiiIii % I1ii11iIi11i
  oO0OoOo0oo = struct . pack ( "BBBBH" , 0 , 0 , O000oo0O0OO0 , o00O0Oo , O0III1Iiii1i11 )
  oO0OoOo0oo += struct . pack ( "IH" , socket . htonl ( o0OoO0000o ) , socket . htons ( O000oOOoOOO ) )
  if ( O000oOOoOOO == 0 ) : return ( oO0OoOo0oo )
  if 63 - 63: IiII + oO0o + II111iiii * I11i
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   oO0OoOo0oo = oO0OoOo0oo [ 0 : - 2 ]
   oO0OoOo0oo += self . address . encode_geo ( )
   return ( oO0OoOo0oo )
   if 49 - 49: OoO0O00
   if 78 - 78: I1IiiI - I1ii11iIi11i
  oO0OoOo0oo += self . pack_address ( )
  return ( oO0OoOo0oo )
  if 24 - 24: Ii1I + I11i
  if 5 - 5: I1Ii111 . Ii1I - ooOoO0o % OoooooooOO
 def lcaf_decode_iid ( self , packet ) :
  O00oO00oOO00O = "BBBBH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 2 - 2: OOooOOo . IiII . iII111i / Oo0Ooo
  O0o000 , o00oo0 , O000oo0O0OO0 , o0Ooo , iiiIIiiIi = struct . unpack ( O00oO00oOO00O ,
 packet [ : ooOoooOoo0oO ] )
  packet = packet [ ooOoooOoo0oO : : ]
  if 34 - 34: OoooooooOO % OoOoOO00 * o0oOOo0O0Ooo . oO0o
  if ( O000oo0O0OO0 != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 94 - 94: O0 . I1ii11iIi11i . i11iIiiIii - I1Ii111 . IiII + oO0o
  O00oO00oOO00O = "IH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 48 - 48: OoOoOO00 * I11i
  o0OoO0000o , O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  packet = packet [ ooOoooOoo0oO : : ]
  if 92 - 92: I1IiiI * I1IiiI
  iiiIIiiIi = socket . ntohs ( iiiIIiiIi )
  self . instance_id = socket . ntohl ( o0OoO0000o )
  O000oOOoOOO = socket . ntohs ( O000oOOoOOO )
  self . afi = O000oOOoOOO
  if ( o0Ooo != 0 and O000oOOoOOO == 0 ) : self . mask_len = o0Ooo
  if ( O000oOOoOOO == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if o0Ooo else LISP_AFI_ULTIMATE_ROOT
   if 9 - 9: IiII * I1IiiI * OoO0O00 - I1IiiI * I1IiiI - OoO0O00
   if 20 - 20: i1IIi + I1IiiI + i11iIiiIii + II111iiii + i1IIi
   if 18 - 18: i11iIiiIii * O0 * Oo0Ooo + iII111i + OOooOOo
   if 62 - 62: OOooOOo - oO0o + i1IIi % Ii1I . I1Ii111 . II111iiii
   if 94 - 94: OOooOOo - I1IiiI
  if ( O000oOOoOOO == 0 ) : return ( packet )
  if 35 - 35: i11iIiiIii
  if 27 - 27: O0 % i11iIiiIii - I1Ii111 * oO0o - I11i / Oo0Ooo
  if 78 - 78: O0 * i11iIiiIii
  if 62 - 62: OoO0O00 * I1Ii111 * Ii1I / ooOoO0o
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 27 - 27: oO0o . iII111i . oO0o
   if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
   if 14 - 14: I11i + ooOoO0o . oO0o * I11i
   if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
   if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
  if ( O000oOOoOOO == LISP_AFI_LCAF ) :
   O00oO00oOO00O = "BBBBH"
   ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
   if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
   if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
   i111IiI1III1 , ooOOooooo0Oo , O000oo0O0OO0 , I1iii1IiI11I11I , iiii1 = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
   if 33 - 33: I11i
   if 37 - 37: Oo0Ooo
   if ( O000oo0O0OO0 != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 36 - 36: IiII % I11i
   iiii1 = socket . ntohs ( iiii1 )
   packet = packet [ ooOoooOoo0oO : : ]
   if ( iiii1 > len ( packet ) ) : return ( None )
   if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
   iiIi1ii1IiI = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = iiIi1ii1IiI
   packet = iiIi1ii1IiI . decode_geo ( packet , iiii1 , I1iii1IiI11I11I )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
   if 82 - 82: OoooooooOO
  O0III1Iiii1i11 = self . addr_length ( )
  if ( len ( packet ) < O0III1Iiii1i11 ) : return ( None )
  if 14 - 14: OoO0O00 / oO0o - OOooOOo
  packet = self . unpack_address ( packet )
  return ( packet )
  if 100 - 100: IiII - I11i . iIii1I11I1II1 / iIii1I11I1II1
  if 16 - 16: IiII + Oo0Ooo % I11i
  if 16 - 16: ooOoO0o / I1Ii111
  if 78 - 78: OoOoOO00 - II111iiii - OOooOOo + I1IiiI + O0 / I1IiiI
  if 59 - 59: OOooOOo . I1IiiI / i1IIi / II111iiii . II111iiii
  if 54 - 54: iIii1I11I1II1 % ooOoO0o
  if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
  if 92 - 92: I11i + OoO0O00 . OoooooooOO
  if 3 - 3: OoO0O00 % iIii1I11I1II1
  if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
  if 59 - 59: iIii1I11I1II1
  if 18 - 18: ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
  if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
  if 63 - 63: I11i
  if 60 - 60: I1IiiI / I1ii11iIi11i / I11i / Ii1I + iIii1I11I1II1
  if 85 - 85: O0 / OOooOOo . OoOoOO00 / I1ii11iIi11i
  if 80 - 80: I1ii11iIi11i * iII111i % i1IIi * OOooOOo % II111iiii % i1IIi
  if 44 - 44: OoooooooOO
  if 18 - 18: i11iIiiIii
  if 65 - 65: i1IIi . iIii1I11I1II1 % iIii1I11I1II1
  if 35 - 35: iIii1I11I1II1 - o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - OOooOOo . o0oOOo0O0Ooo
 def lcaf_encode_sg ( self , group ) :
  O000oo0O0OO0 = LISP_LCAF_MCAST_INFO_TYPE
  o0OoO0000o = socket . htonl ( self . instance_id )
  O0III1Iiii1i11 = socket . htons ( self . lcaf_length ( O000oo0O0OO0 ) )
  oO0OoOo0oo = struct . pack ( "BBBBHIHBB" , 0 , 0 , O000oo0O0OO0 , 0 , O0III1Iiii1i11 , o0OoO0000o ,
 0 , self . mask_len , group . mask_len )
  if 12 - 12: iIii1I11I1II1 % OoO0O00 * Oo0Ooo
  oO0OoOo0oo += struct . pack ( "H" , socket . htons ( self . afi ) )
  oO0OoOo0oo += self . pack_address ( )
  oO0OoOo0oo += struct . pack ( "H" , socket . htons ( group . afi ) )
  oO0OoOo0oo += group . pack_address ( )
  return ( oO0OoOo0oo )
  if 5 - 5: I11i - II111iiii * iIii1I11I1II1 / iIii1I11I1II1 % IiII * i1IIi
  if 30 - 30: i1IIi % I1IiiI . OOooOOo % iIii1I11I1II1 . I1ii11iIi11i / o0oOOo0O0Ooo
 def lcaf_decode_sg ( self , packet ) :
  O00oO00oOO00O = "BBBBHIHBB"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( [ None , None ] )
  if 53 - 53: OOooOOo % ooOoO0o
  O0o000 , o00oo0 , O000oo0O0OO0 , O0Ooo000OO00 , iiiIIiiIi , o0OoO0000o , OOOoo0Oo , O000O00oOO , o0o0oOo00Oo = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 94 - 94: ooOoO0o / Ii1I
  packet = packet [ ooOoooOoo0oO : : ]
  if 9 - 9: I1Ii111 * oO0o
  if ( O000oo0O0OO0 != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 44 - 44: ooOoO0o * oO0o
  self . instance_id = socket . ntohl ( o0OoO0000o )
  iiiIIiiIi = socket . ntohs ( iiiIIiiIi ) - 8
  if 67 - 67: iIii1I11I1II1 . iIii1I11I1II1 + iIii1I11I1II1 * iII111i
  if 70 - 70: I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
  if 12 - 12: Oo0Ooo + I1IiiI
  if 12 - 12: OoOoOO00 / II111iiii
  if 100 - 100: I1ii11iIi11i % iIii1I11I1II1 . IiII . OoooooooOO / II111iiii
  O00oO00oOO00O = "H"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( [ None , None ] )
  if ( iiiIIiiIi < ooOoooOoo0oO ) : return ( [ None , None ] )
  if 28 - 28: I1IiiI
  O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  iiiIIiiIi -= ooOoooOoo0oO
  self . afi = socket . ntohs ( O000oOOoOOO )
  self . mask_len = O000O00oOO
  O0III1Iiii1i11 = self . addr_length ( )
  if ( iiiIIiiIi < O0III1Iiii1i11 ) : return ( [ None , None ] )
  if 27 - 27: I1IiiI % oO0o - iIii1I11I1II1 - o0oOOo0O0Ooo - IiII - O0
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 46 - 46: II111iiii
  iiiIIiiIi -= O0III1Iiii1i11
  if 24 - 24: i11iIiiIii * i1IIi - I11i + o0oOOo0O0Ooo
  if 60 - 60: ooOoO0o
  if 62 - 62: i11iIiiIii
  if 88 - 88: i11iIiiIii
  if 59 - 59: oO0o - OoooooooOO % ooOoO0o
  O00oO00oOO00O = "H"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( [ None , None ] )
  if ( iiiIIiiIi < ooOoooOoo0oO ) : return ( [ None , None ] )
  if 90 - 90: OoOoOO00
  O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  iiiIIiiIi -= ooOoooOoo0oO
  O0o00oOOOO00 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  O0o00oOOOO00 . afi = socket . ntohs ( O000oOOoOOO )
  O0o00oOOOO00 . mask_len = o0o0oOo00Oo
  O0o00oOOOO00 . instance_id = self . instance_id
  O0III1Iiii1i11 = self . addr_length ( )
  if ( iiiIIiiIi < O0III1Iiii1i11 ) : return ( [ None , None ] )
  if 96 - 96: II111iiii % Ii1I
  packet = O0o00oOOOO00 . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 84 - 84: I1IiiI . I1IiiI
  return ( [ packet , O0o00oOOOO00 ] )
  if 82 - 82: OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1 + I1ii11iIi11i
  if 45 - 45: iII111i . oO0o * iII111i
 def lcaf_decode_eid ( self , packet ) :
  O00oO00oOO00O = "BBB"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( [ None , None ] )
  if 3 - 3: OoOoOO00 / Oo0Ooo - Oo0Ooo
  if 54 - 54: Oo0Ooo . OoO0O00 * I1IiiI % IiII
  if 97 - 97: o0oOOo0O0Ooo + Ii1I
  if 77 - 77: I11i - oO0o . Ii1I
  if 75 - 75: I11i * OoooooooOO % OoOoOO00 . i1IIi - Ii1I + iIii1I11I1II1
  O0Ooo000OO00 , ooOOooooo0Oo , O000oo0O0OO0 = struct . unpack ( O00oO00oOO00O ,
 packet [ : ooOoooOoo0oO ] )
  if 74 - 74: ooOoO0o
  if ( O000oo0O0OO0 == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( O000oo0O0OO0 == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , O0o00oOOOO00 = self . lcaf_decode_sg ( packet )
   return ( [ packet , O0o00oOOOO00 ] )
  elif ( O000oo0O0OO0 == LISP_LCAF_GEO_COORD_TYPE ) :
   O00oO00oOO00O = "BBBBH"
   ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
   if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
   if 18 - 18: iIii1I11I1II1 - I11i - oO0o
   i111IiI1III1 , ooOOooooo0Oo , O000oo0O0OO0 , I1iii1IiI11I11I , iiii1 = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
   if 12 - 12: O0 + O0 + ooOoO0o . I1IiiI * II111iiii
   if 47 - 47: i11iIiiIii % OOooOOo / ooOoO0o . IiII - I1IiiI
   if ( O000oo0O0OO0 != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 10 - 10: Oo0Ooo / ooOoO0o / I1ii11iIi11i
   iiii1 = socket . ntohs ( iiii1 )
   packet = packet [ ooOoooOoo0oO : : ]
   if ( iiii1 > len ( packet ) ) : return ( None )
   if 98 - 98: O0 - I1Ii111 - i11iIiiIii
   iiIi1ii1IiI = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = iiIi1ii1IiI
   packet = iiIi1ii1IiI . decode_geo ( packet , iiii1 , I1iii1IiI11I11I )
   self . mask_len = self . host_mask_len ( )
   if 85 - 85: II111iiii - I1ii11iIi11i % I1IiiI . I1IiiI - OoooooooOO - I11i
  return ( [ packet , None ] )
  if 38 - 38: i1IIi + oO0o * ooOoO0o % Ii1I % ooOoO0o
  if 80 - 80: OoO0O00 + OoOoOO00 % iII111i % OoooooooOO - ooOoO0o
  if 25 - 25: OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - Oo0Ooo . O0
  if 48 - 48: I1IiiI + oO0o % i11iIiiIii % iIii1I11I1II1
  if 14 - 14: iIii1I11I1II1
  if 78 - 78: I1Ii111 / Oo0Ooo - I1Ii111
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 1 - 1: OoO0O00 - I1IiiI * o0oOOo0O0Ooo
  if 84 - 84: OoO0O00 % OoooooooOO
 def copy_elp_node ( self ) :
  Ooo0o0OoOO = lisp_elp_node ( )
  Ooo0o0OoOO . copy_address ( self . address )
  Ooo0o0OoOO . probe = self . probe
  Ooo0o0OoOO . strict = self . strict
  Ooo0o0OoOO . eid = self . eid
  Ooo0o0OoOO . we_are_last = self . we_are_last
  return ( Ooo0o0OoOO )
  if 66 - 66: OoOoOO00 . iII111i
  if 1 - 1: iII111i * i1IIi . iIii1I11I1II1 % O0 - OoooooooOO
  if 87 - 87: iII111i . Oo0Ooo * i11iIiiIii % o0oOOo0O0Ooo + Ii1I
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
  if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
 def copy_elp ( self ) :
  Ii1111i = lisp_elp ( self . elp_name )
  Ii1111i . use_elp_node = self . use_elp_node
  Ii1111i . we_are_last = self . we_are_last
  for Ooo0o0OoOO in self . elp_nodes :
   Ii1111i . elp_nodes . append ( Ooo0o0OoOO . copy_elp_node ( ) )
   if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
  return ( Ii1111i )
  if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
  if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
 def print_elp ( self , want_marker ) :
  OoOo0Oo0 = ""
  for Ooo0o0OoOO in self . elp_nodes :
   Oo0000 = ""
   if ( want_marker ) :
    if ( Ooo0o0OoOO == self . use_elp_node ) :
     Oo0000 = "*"
    elif ( Ooo0o0OoOO . we_are_last ) :
     Oo0000 = "x"
     if 76 - 76: iIii1I11I1II1
     if 55 - 55: II111iiii % O0 * O0 - II111iiii * I1IiiI % Oo0Ooo
   OoOo0Oo0 += "{}{}({}{}{}), " . format ( Oo0000 ,
 Ooo0o0OoOO . address . print_address_no_iid ( ) ,
 "r" if Ooo0o0OoOO . eid else "R" , "P" if Ooo0o0OoOO . probe else "p" ,
 "S" if Ooo0o0OoOO . strict else "s" )
   if 48 - 48: I1ii11iIi11i + OoooooooOO % i1IIi
  return ( OoOo0Oo0 [ 0 : - 2 ] if OoOo0Oo0 != "" else "" )
  if 46 - 46: OoOoOO00
  if 75 - 75: I1IiiI
 def select_elp_node ( self ) :
  Ii1II111i1 , iii1i , OoO0o0OOOO = lisp_myrlocs
  ooo = None
  if 100 - 100: OOooOOo * OoooooooOO
  for Ooo0o0OoOO in self . elp_nodes :
   if ( Ii1II111i1 and Ooo0o0OoOO . address . is_exact_match ( Ii1II111i1 ) ) :
    ooo = self . elp_nodes . index ( Ooo0o0OoOO )
    break
    if 80 - 80: O0 + oO0o - OoooooooOO - O0 . ooOoO0o . OoooooooOO
   if ( iii1i and Ooo0o0OoOO . address . is_exact_match ( iii1i ) ) :
    ooo = self . elp_nodes . index ( Ooo0o0OoOO )
    break
    if 76 - 76: Ii1I
    if 62 - 62: O0 / OoO0O00 % i11iIiiIii / OOooOOo * iIii1I11I1II1
    if 78 - 78: OOooOOo % O0 * O0
    if 62 - 62: ooOoO0o
    if 77 - 77: I1IiiI . i11iIiiIii - I1ii11iIi11i
    if 83 - 83: OoO0O00 - i11iIiiIii + I1ii11iIi11i - OOooOOo / OoOoOO00 / I11i
    if 53 - 53: I11i * I1IiiI . I1IiiI / o0oOOo0O0Ooo - I1Ii111
  if ( ooo == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   Ooo0o0OoOO . we_are_last = False
   return
   if 50 - 50: I11i - OoOoOO00 + I1IiiI % Oo0Ooo / OoooooooOO - I1ii11iIi11i
   if 26 - 26: IiII . Ii1I
   if 35 - 35: I1ii11iIi11i + OOooOOo
   if 88 - 88: O0
   if 4 - 4: OoOoOO00 % iIii1I11I1II1 % OoooooooOO . oO0o
   if 27 - 27: II111iiii - OoOoOO00
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ ooo ] ) :
   self . use_elp_node = None
   Ooo0o0OoOO . we_are_last = True
   return
   if 81 - 81: o0oOOo0O0Ooo - Oo0Ooo % IiII - ooOoO0o / O0
   if 27 - 27: Oo0Ooo
   if 15 - 15: iIii1I11I1II1 . OoOoOO00 % Ii1I / i1IIi . o0oOOo0O0Ooo
   if 45 - 45: iIii1I11I1II1 - i1IIi % I1IiiI - I1Ii111 + oO0o
   if 15 - 15: iIii1I11I1II1 - OoooooooOO / ooOoO0o
  self . use_elp_node = self . elp_nodes [ ooo + 1 ]
  return
  if 83 - 83: IiII + I1Ii111 / OoOoOO00 * IiII . oO0o
  if 22 - 22: O0 + ooOoO0o + I1Ii111
  if 57 - 57: OOooOOo . ooOoO0o - OoooooooOO - I1ii11iIi11i * O0
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
  if 85 - 85: I1IiiI * OoO0O00
  if 63 - 63: I1IiiI - i11iIiiIii
 def copy_geo ( self ) :
  iiIi1ii1IiI = lisp_geo ( self . geo_name )
  iiIi1ii1IiI . latitude = self . latitude
  iiIi1ii1IiI . lat_mins = self . lat_mins
  iiIi1ii1IiI . lat_secs = self . lat_secs
  iiIi1ii1IiI . longitude = self . longitude
  iiIi1ii1IiI . long_mins = self . long_mins
  iiIi1ii1IiI . long_secs = self . long_secs
  iiIi1ii1IiI . altitude = self . altitude
  iiIi1ii1IiI . radius = self . radius
  return ( iiIi1ii1IiI )
  if 4 - 4: OOooOOo + iIii1I11I1II1 / I1IiiI * Ii1I
  if 64 - 64: OoOoOO00
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 94 - 94: OOooOOo * OoooooooOO * o0oOOo0O0Ooo / I1Ii111 . II111iiii
  if 37 - 37: O0 * II111iiii * I1IiiI - O0 - I11i / i1IIi
 def parse_geo_string ( self , geo_str ) :
  ooo = geo_str . find ( "]" )
  if ( ooo != - 1 ) : geo_str = geo_str [ ooo + 1 : : ]
  if 27 - 27: i11iIiiIii + iIii1I11I1II1
  if 15 - 15: oO0o
  if 69 - 69: II111iiii * O0 . ooOoO0o * IiII
  if 25 - 25: I11i - I1ii11iIi11i . I1Ii111 . OoooooooOO
  if 4 - 4: IiII * OoO0O00 % I1ii11iIi11i * Ii1I . iII111i
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , Iii1Ii1II1 = geo_str . split ( "/" )
   self . radius = int ( Iii1Ii1II1 )
   if 49 - 49: II111iiii % OOooOOo
   if 19 - 19: I1ii11iIi11i - iIii1I11I1II1 % I1IiiI / OoooooooOO
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 12 - 12: ooOoO0o / II111iiii + OoO0O00
  iiIiiiI = geo_str [ 0 : 4 ]
  i1i11i1Iii = geo_str [ 4 : 8 ]
  if 11 - 11: I11i * Ii1I * I1IiiI - I1IiiI % OoooooooOO
  if 83 - 83: i11iIiiIii % iII111i * O0 % OoooooooOO
  if 99 - 99: I1ii11iIi11i % I1ii11iIi11i * iII111i % oO0o
  if 56 - 56: Oo0Ooo + i11iIiiIii - oO0o . Ii1I + IiII
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 19 - 19: I11i * OoooooooOO . i1IIi
  if 100 - 100: II111iiii
  if 95 - 95: iII111i
  if 94 - 94: OoOoOO00 + OoooooooOO
  self . latitude = int ( iiIiiiI [ 0 ] )
  self . lat_mins = int ( iiIiiiI [ 1 ] )
  self . lat_secs = int ( iiIiiiI [ 2 ] )
  if ( iiIiiiI [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 92 - 92: i11iIiiIii * IiII * I1IiiI - oO0o / iII111i
  if 1 - 1: ooOoO0o - OoO0O00 - o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i - I1Ii111
  if 78 - 78: Oo0Ooo
  if 27 - 27: Ii1I / oO0o - Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo . Ii1I
  self . longitude = int ( i1i11i1Iii [ 0 ] )
  self . long_mins = int ( i1i11i1Iii [ 1 ] )
  self . long_secs = int ( i1i11i1Iii [ 2 ] )
  if ( i1i11i1Iii [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 79 - 79: Ii1I % O0 * OOooOOo
  if 41 - 41: I1ii11iIi11i . OoooooooOO * I1ii11iIi11i - oO0o
 def print_geo ( self ) :
  IiIIiiI1II = "N" if self . latitude < 0 else "S"
  oo0 = "E" if self . longitude < 0 else "W"
  if 58 - 58: I1IiiI * I1Ii111 + iII111i + iIii1I11I1II1 + I1IiiI
  OooO0ooO0o0OO = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , IiIIiiI1II , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , oo0 )
  if 78 - 78: Oo0Ooo + ooOoO0o
  if ( self . no_geo_altitude ( ) == False ) :
   OooO0ooO0o0OO += "-" + str ( self . altitude )
   if 56 - 56: OoO0O00 / i1IIi + ooOoO0o . ooOoO0o . iII111i
   if 37 - 37: iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoooooooOO + OoO0O00
   if 25 - 25: I1IiiI / IiII . OOooOOo . I1ii11iIi11i % i1IIi
   if 12 - 12: O0 % O0
   if 9 - 9: O0 . I1IiiI + I1ii11iIi11i / OOooOOo * I1ii11iIi11i
  if ( self . radius != 0 ) : OooO0ooO0o0OO += "/{}" . format ( self . radius )
  return ( OooO0ooO0o0OO )
  if 10 - 10: IiII % o0oOOo0O0Ooo / O0 / II111iiii
  if 81 - 81: Ii1I / o0oOOo0O0Ooo % OoOoOO00 . I1ii11iIi11i
 def geo_url ( self ) :
  Iii1ii = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  Iii1ii = "10" if ( Iii1ii == "" or Iii1ii . isdigit ( ) == False ) else Iii1ii
  Ooo0oOO , I1Ii111Oo00o0o = self . dms_to_decimal ( )
  o00oo0oo = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( Ooo0oOO , I1Ii111Oo00o0o , Ooo0oOO , I1Ii111Oo00o0o ,
  # Oo0Ooo * o0oOOo0O0Ooo * I1ii11iIi11i * II111iiii
  # o0oOOo0O0Ooo . iIii1I11I1II1 + ooOoO0o + II111iiii % iIii1I11I1II1 * IiII
 Iii1ii )
  return ( o00oo0oo )
  if 89 - 89: O0 + I1IiiI / IiII + OoooooooOO - IiII
  if 2 - 2: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1 % i11iIiiIii * OOooOOo
 def print_geo_url ( self ) :
  iiIi1ii1IiI = self . print_geo ( )
  if ( self . radius == 0 ) :
   o00oo0oo = self . geo_url ( )
   iI = "<a href='{}'>{}</a>" . format ( o00oo0oo , iiIi1ii1IiI )
  else :
   o00oo0oo = iiIi1ii1IiI . replace ( "/" , "-" )
   iI = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( o00oo0oo , iiIi1ii1IiI )
   if 18 - 18: oO0o . I1ii11iIi11i % oO0o
  return ( iI )
  if 43 - 43: oO0o / ooOoO0o . o0oOOo0O0Ooo . iIii1I11I1II1
  if 63 - 63: iII111i * iII111i
 def dms_to_decimal ( self ) :
  Ooooooo0Oo , Ii1III11i , o0o0 = self . latitude , self . lat_mins , self . lat_secs
  oOo00Oo0o = float ( abs ( Ooooooo0Oo ) )
  oOo00Oo0o += float ( Ii1III11i * 60 + o0o0 ) / 3600
  if ( Ooooooo0Oo > 0 ) : oOo00Oo0o = - oOo00Oo0o
  oo00ooO0ooO = oOo00Oo0o
  if 72 - 72: I1Ii111 * oO0o * iII111i * OoooooooOO % I1IiiI / OOooOOo
  Ooooooo0Oo , Ii1III11i , o0o0 = self . longitude , self . long_mins , self . long_secs
  oOo00Oo0o = float ( abs ( Ooooooo0Oo ) )
  oOo00Oo0o += float ( Ii1III11i * 60 + o0o0 ) / 3600
  if ( Ooooooo0Oo > 0 ) : oOo00Oo0o = - oOo00Oo0o
  iI1II1I = oOo00Oo0o
  return ( ( oo00ooO0ooO , iI1II1I ) )
  if 27 - 27: Ii1I % IiII
  if 100 - 100: oO0o . i11iIiiIii - ooOoO0o
 def get_distance ( self , geo_point ) :
  II11II1111 = self . dms_to_decimal ( )
  IiiiOo = geo_point . dms_to_decimal ( )
  O00oO00O0 = vincenty ( II11II1111 , IiiiOo )
  return ( O00oO00O0 . km )
  if 96 - 96: IiII * iIii1I11I1II1
  if 75 - 75: oO0o + o0oOOo0O0Ooo . Ii1I * OoooooooOO + Ii1I - I1IiiI
 def point_in_circle ( self , geo_point ) :
  i1ii = self . get_distance ( geo_point )
  return ( i1ii <= self . radius )
  if 86 - 86: O0 * oO0o + Oo0Ooo / II111iiii + i1IIi
  if 12 - 12: I1IiiI + OOooOOo / Ii1I % i11iIiiIii - I1Ii111 % I11i
 def encode_geo ( self ) :
  o0O000Ooo = socket . htons ( LISP_AFI_LCAF )
  o0o0O0O0Oooo0 = socket . htons ( 20 + 2 )
  ooOOooooo0Oo = 0
  if 49 - 49: I11i * i1IIi - iII111i
  Ooo0oOO = abs ( self . latitude )
  Oo000ooo = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : ooOOooooo0Oo |= 0x40
  if 90 - 90: Ii1I * Ii1I % i11iIiiIii
  I1Ii111Oo00o0o = abs ( self . longitude )
  O0o0oo0o0o = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : ooOOooooo0Oo |= 0x20
  if 94 - 94: i11iIiiIii % I1ii11iIi11i % IiII - I1Ii111
  O0O0OooO = 0
  if ( self . no_geo_altitude ( ) == False ) :
   O0O0OooO = socket . htonl ( self . altitude )
   ooOOooooo0Oo |= 0x10
   if 88 - 88: I1ii11iIi11i . i1IIi * iII111i
  Iii1Ii1II1 = socket . htons ( self . radius )
  if ( Iii1Ii1II1 != 0 ) : ooOOooooo0Oo |= 0x06
  if 67 - 67: IiII + i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i11iIiiIii
  iiIiIi = struct . pack ( "HBBBBH" , o0O000Ooo , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , o0o0O0O0Oooo0 )
  iiIiIi += struct . pack ( "BBHBBHBBHIHHH" , ooOOooooo0Oo , 0 , 0 , Ooo0oOO , Oo000ooo >> 16 ,
 socket . htons ( Oo000ooo & 0x0ffff ) , I1Ii111Oo00o0o , O0o0oo0o0o >> 16 ,
 socket . htons ( O0o0oo0o0o & 0xffff ) , O0O0OooO , Iii1Ii1II1 , 0 , 0 )
  if 65 - 65: I11i * iII111i * II111iiii / o0oOOo0O0Ooo . O0
  return ( iiIiIi )
  if 11 - 11: Ii1I . OoooooooOO
  if 34 - 34: iIii1I11I1II1 . i11iIiiIii - OoOoOO00
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  O00oO00oOO00O = "BBHBBHBBHIHHH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( lcaf_len < ooOoooOoo0oO ) : return ( None )
  if 34 - 34: i11iIiiIii * OoooooooOO
  ooOOooooo0Oo , Oo00o00o0000o , OoO0 , Ooo0oOO , i11IIII , Oo000ooo , I1Ii111Oo00o0o , ooOo0o0oOOoO00O , O0o0oo0o0o , O0O0OooO , Iii1Ii1II1 , i11IIo0o0 , O000oOOoOOO = struct . unpack ( O00oO00oOO00O ,
  # ooOoO0o * O0 * i11iIiiIii . iII111i
 packet [ : ooOoooOoo0oO ] )
  if 48 - 48: ooOoO0o * o0oOOo0O0Ooo
  if 99 - 99: oO0o / o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO * O0
  if 52 - 52: OOooOOo / ooOoO0o . II111iiii / Oo0Ooo
  if 66 - 66: Ii1I * I1Ii111 * OoO0O00
  O000oOOoOOO = socket . ntohs ( O000oOOoOOO )
  if ( O000oOOoOOO == LISP_AFI_LCAF ) : return ( None )
  if 92 - 92: II111iiii * iII111i % OoOoOO00 % OoOoOO00 % i11iIiiIii
  if ( ooOOooooo0Oo & 0x40 ) : Ooo0oOO = - Ooo0oOO
  self . latitude = Ooo0oOO
  O00oo0o = ( ( i11IIII << 16 ) | socket . ntohs ( Oo000ooo ) ) / 1000
  self . lat_mins = O00oo0o / 60
  self . lat_secs = O00oo0o % 60
  if 48 - 48: OoooooooOO - O0 + I1IiiI - I11i
  if ( ooOOooooo0Oo & 0x20 ) : I1Ii111Oo00o0o = - I1Ii111Oo00o0o
  self . longitude = I1Ii111Oo00o0o
  OoO0iI = ( ( ooOo0o0oOOoO00O << 16 ) | socket . ntohs ( O0o0oo0o0o ) ) / 1000
  self . long_mins = OoO0iI / 60
  self . long_secs = OoO0iI % 60
  if 8 - 8: IiII * Ii1I / Ii1I * OoO0O00 . OoooooooOO . I1Ii111
  self . altitude = socket . ntohl ( O0O0OooO ) if ( ooOOooooo0Oo & 0x10 ) else - 1
  Iii1Ii1II1 = socket . ntohs ( Iii1Ii1II1 )
  self . radius = Iii1Ii1II1 if ( ooOOooooo0Oo & 0x02 ) else Iii1Ii1II1 * 1000
  if 18 - 18: I11i % OoooooooOO - Ii1I + IiII % II111iiii
  self . geo_name = None
  packet = packet [ ooOoooOoo0oO : : ]
  if 49 - 49: IiII - o0oOOo0O0Ooo
  if ( O000oOOoOOO != 0 ) :
   self . rloc . afi = O000oOOoOOO
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 3 - 3: Oo0Ooo * O0 % OoooooooOO / O0 - Ii1I . iIii1I11I1II1
  return ( packet )
  if 30 - 30: OoO0O00 + OOooOOo * i11iIiiIii - OoOoOO00 * II111iiii - oO0o
  if 22 - 22: i1IIi + IiII + iII111i - I1IiiI - I11i - I11i
  if 50 - 50: O0 * I1IiiI / i11iIiiIii - I11i
  if 28 - 28: i1IIi + O0 - i11iIiiIii - I1Ii111
  if 54 - 54: iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
  if 18 - 18: oO0o % iIii1I11I1II1 + ooOoO0o
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 34 - 34: I1IiiI - OoooooooOO . IiII - OOooOOo % IiII
  if 19 - 19: IiII + I1ii11iIi11i % Oo0Ooo
 def copy_rle_node ( self ) :
  iIIII1iiIII = lisp_rle_node ( )
  iIIII1iiIII . address . copy_address ( self . address )
  iIIII1iiIII . level = self . level
  iIIII1iiIII . translated_port = self . translated_port
  iIIII1iiIII . rloc_name = self . rloc_name
  return ( iIIII1iiIII )
  if 32 - 32: OOooOOo
  if 46 - 46: II111iiii . OoO0O00
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 97 - 97: oO0o
  if 45 - 45: i11iIiiIii / IiII + OoO0O00
 def get_encap_keys ( self ) :
  IiI1iI1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 55 - 55: Ii1I / II111iiii - oO0o
  oo0o00OO = self . address . print_address_no_iid ( ) + ":" + IiI1iI1
  if 58 - 58: i1IIi . OoooooooOO % iIii1I11I1II1 * o0oOOo0O0Ooo + O0 / oO0o
  try :
   oOoo0oO = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ]
   if ( oOoo0oO [ 1 ] ) : return ( oOoo0oO [ 1 ] . encrypt_key , oOoo0oO [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 77 - 77: I11i . I1ii11iIi11i
   if 92 - 92: i11iIiiIii + I11i % I1IiiI / ooOoO0o
   if 28 - 28: i1IIi . I1IiiI
   if 41 - 41: I1ii11iIi11i . I1Ii111 * OoOoOO00 . I1Ii111 / o0oOOo0O0Ooo
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 41 - 41: o0oOOo0O0Ooo / o0oOOo0O0Ooo . Oo0Ooo
  if 4 - 4: I1Ii111
 def copy_rle ( self ) :
  i1I1Ii11II1i = lisp_rle ( self . rle_name )
  for iIIII1iiIII in self . rle_nodes :
   i1I1Ii11II1i . rle_nodes . append ( iIIII1iiIII . copy_rle_node ( ) )
   if 85 - 85: iIii1I11I1II1 % Oo0Ooo
  i1I1Ii11II1i . build_forwarding_list ( )
  return ( i1I1Ii11II1i )
  if 20 - 20: IiII + i11iIiiIii * OOooOOo
  if 27 - 27: O0 * OoO0O00 * I1ii11iIi11i
 def print_rle ( self , html , do_formatting ) :
  oO0O0Oo000 = ""
  for iIIII1iiIII in self . rle_nodes :
   IiI1iI1 = iIIII1iiIII . translated_port
   if 40 - 40: O0 + oO0o - ooOoO0o + I1IiiI - IiII
   O00OOOOooO0OO = ""
   if ( iIIII1iiIII . rloc_name != None ) :
    O00OOOOooO0OO = iIIII1iiIII . rloc_name
    if ( do_formatting ) : O00OOOOooO0OO = blue ( O00OOOOooO0OO , html )
    if 65 - 65: OoooooooOO / OoOoOO00 + I1IiiI - II111iiii / OoOoOO00
    if 69 - 69: i11iIiiIii
   oo0o00OO = iIIII1iiIII . address . print_address_no_iid ( )
   if ( iIIII1iiIII . address . is_local ( ) ) : oo0o00OO = red ( oo0o00OO , html )
   oO0O0Oo000 += "{}{}(L{}){}, " . format ( oo0o00OO , "" if IiI1iI1 == 0 else ":" + str ( IiI1iI1 ) , iIIII1iiIII . level ,
   # I11i % o0oOOo0O0Ooo - o0oOOo0O0Ooo / OoO0O00 + Ii1I
 "" if iIIII1iiIII . rloc_name == None else O00OOOOooO0OO )
   if 72 - 72: I11i * ooOoO0o / iII111i . OoooooooOO + I1Ii111 + I1Ii111
  return ( oO0O0Oo000 [ 0 : - 2 ] if oO0O0Oo000 != "" else "" )
  if 35 - 35: Oo0Ooo + oO0o * o0oOOo0O0Ooo - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii
  if 56 - 56: iIii1I11I1II1 / I11i
 def build_forwarding_list ( self ) :
  IiiiIiii = - 1
  for iIIII1iiIII in self . rle_nodes :
   if ( IiiiIiii == - 1 ) :
    if ( iIIII1iiIII . address . is_local ( ) ) : IiiiIiii = iIIII1iiIII . level
   else :
    if ( iIIII1iiIII . level > IiiiIiii ) : break
    if 78 - 78: i11iIiiIii * OoO0O00 * Ii1I / i1IIi * OOooOOo + o0oOOo0O0Ooo
    if 52 - 52: i1IIi % O0
  IiiiIiii = 0 if IiiiIiii == - 1 else iIIII1iiIII . level
  if 59 - 59: II111iiii + I1ii11iIi11i / iII111i . ooOoO0o
  self . rle_forwarding_list = [ ]
  for iIIII1iiIII in self . rle_nodes :
   if ( iIIII1iiIII . level == IiiiIiii or ( IiiiIiii == 0 and
 iIIII1iiIII . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and iIIII1iiIII . address . is_local ( ) ) :
     oo0o00OO = iIIII1iiIII . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( oo0o00OO ) )
     continue
     if 18 - 18: I1Ii111
    self . rle_forwarding_list . append ( iIIII1iiIII )
    if 40 - 40: OoOoOO00 / OOooOOo + O0
    if 57 - 57: iII111i
    if 94 - 94: i11iIiiIii
    if 90 - 90: iII111i + i11iIiiIii + iII111i % I1IiiI % oO0o
    if 71 - 71: ooOoO0o + OOooOOo * I1IiiI % I11i . I1Ii111 % OoooooooOO
class lisp_json ( ) :
 def __init__ ( self , name , string ) :
  self . json_name = name
  self . json_string = string
  if 7 - 7: iIii1I11I1II1
  if 88 - 88: ooOoO0o
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 37 - 37: ooOoO0o * OoOoOO00 . ooOoO0o
  if 47 - 47: iIii1I11I1II1 + iIii1I11I1II1 / Ii1I
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 19 - 19: OOooOOo . OoOoOO00 % iIii1I11I1II1 % OoOoOO00
   if 92 - 92: o0oOOo0O0Ooo + II111iiii
   if 56 - 56: OoOoOO00 - OoOoOO00 / Ii1I
 def print_json ( self , html ) :
  oooIIi1i = self . json_string
  o0Oo0o0ooOOO = "***"
  if ( html ) : o0Oo0o0ooOOO = red ( o0Oo0o0ooOOO , html )
  OoOoOO00OOo0O = o0Oo0o0ooOOO + self . json_string + o0Oo0o0ooOOO
  if ( self . valid_json ( ) ) : return ( oooIIi1i )
  return ( OoOoOO00OOo0O )
  if 46 - 46: oO0o / Oo0Ooo + o0oOOo0O0Ooo . I1Ii111 % OoO0O00 % IiII
  if 37 - 37: i11iIiiIii - OOooOOo . OOooOOo
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 57 - 57: I1Ii111
  return ( True )
  if 60 - 60: OoooooooOO . I1ii11iIi11i * i11iIiiIii / Ii1I
  if 39 - 39: O0 % Ii1I
  if 63 - 63: OOooOOo / I1ii11iIi11i
  if 11 - 11: O0 % iIii1I11I1II1
  if 64 - 64: OoOoOO00 - oO0o
  if 8 - 8: i11iIiiIii - iIii1I11I1II1 / I1Ii111 . i11iIiiIii % o0oOOo0O0Ooo / oO0o
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 36 - 36: IiII
  if 53 - 53: OoooooooOO / I1IiiI % I11i + Oo0Ooo
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 15 - 15: O0
  if 75 - 75: iII111i / OoOoOO00
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . last_increment
  return ( oO000o0Oo00 <= 1 )
  if 2 - 2: i1IIi + oO0o % iII111i % I1ii11iIi11i + ooOoO0o . iII111i
  if 26 - 26: I11i + o0oOOo0O0Ooo + Ii1I % I11i
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . last_increment
  return ( oO000o0Oo00 <= 60 )
  if 95 - 95: IiII - O0 * oO0o * O0
  if 47 - 47: I1IiiI
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 20 - 20: I1Ii111
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 40 - 40: OoooooooOO / o0oOOo0O0Ooo + OoOoOO00
  return ( c1 , c2 )
  if 73 - 73: OOooOOo / Oo0Ooo
  if 80 - 80: OoO0O00 + I1IiiI % i1IIi / I11i % i1IIi * i11iIiiIii
 def normalize ( self , count ) :
  count = str ( count )
  II11i = len ( count )
  if ( II11i > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 6 - 6: II111iiii / o0oOOo0O0Ooo * O0 % I1ii11iIi11i
  if ( II11i > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 11 - 11: I1Ii111
  if ( II11i > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 70 - 70: Ii1I
  return ( count )
  if 22 - 22: Ii1I
  if 59 - 59: I1ii11iIi11i
 def get_stats ( self , summary , html ) :
  oO00o = self . last_rate_check
  oO0Oo0oO0OOOO = self . last_packet_count
  I1IIIiiIIIii1iII = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 90 - 90: iIii1I11I1II1 - II111iiii
  o000O = self . last_rate_check - oO00o
  if ( o000O == 0 ) :
   iiiiiI1I1 = 0
   OOoOO0 = 0
  else :
   iiiiiI1I1 = int ( ( self . packet_count - oO0Oo0oO0OOOO ) / o000O )
   OOoOO0 = ( self . byte_count - I1IIIiiIIIii1iII ) / o000O
   OOoOO0 = ( OOoOO0 * 8 ) / 1000000
   OOoOO0 = round ( OOoOO0 , 2 )
   if 99 - 99: IiII / OoO0O00 % Oo0Ooo * iIii1I11I1II1
   if 89 - 89: I1Ii111 + Oo0Ooo - ooOoO0o
   if 63 - 63: oO0o + OoOoOO00 - oO0o - Ii1I % ooOoO0o * I1Ii111
   if 92 - 92: IiII % IiII / o0oOOo0O0Ooo * OoO0O00 % OoOoOO00
   if 12 - 12: I1IiiI
  iI1IiIiIIII11 = self . normalize ( self . packet_count )
  oOooO0O0 = self . normalize ( self . byte_count )
  if 83 - 83: o0oOOo0O0Ooo * Oo0Ooo - oO0o + O0 / i11iIiiIii
  if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
  if 74 - 74: IiII - O0 % OOooOOo % OoooooooOO - I11i
  if 4 - 4: i1IIi + OoOoOO00 + iIii1I11I1II1 - i1IIi * i11iIiiIii
  if 99 - 99: I1ii11iIi11i - O0 % II111iiii + ooOoO0o % OoO0O00 * Ii1I
  if ( summary ) :
   i1I1ii111 = "<br>" if html else ""
   iI1IiIiIIII11 , oOooO0O0 = self . stat_colors ( iI1IiIiIIII11 , oOooO0O0 , html )
   OO0ooo0O = "packet-count: {}{}byte-count: {}" . format ( iI1IiIiIIII11 , i1I1ii111 , oOooO0O0 )
   i1I1IiiIi = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( iiiiiI1I1 , OOoOO0 )
   if 19 - 19: O0 / I1Ii111 + I1Ii111 . I1ii11iIi11i
   if ( html != "" ) : i1I1IiiIi = lisp_span ( OO0ooo0O , i1I1IiiIi )
  else :
   II11 = str ( iiiiiI1I1 )
   iI1II1IiIiIi = str ( OOoOO0 )
   if ( html ) :
    iI1IiIiIIII11 = lisp_print_cour ( iI1IiIiIIII11 )
    II11 = lisp_print_cour ( II11 )
    oOooO0O0 = lisp_print_cour ( oOooO0O0 )
    iI1II1IiIiIi = lisp_print_cour ( iI1II1IiIiIi )
    if 9 - 9: I1Ii111 * II111iiii % Ii1I - Ii1I % OoO0O00 % o0oOOo0O0Ooo
   i1I1ii111 = "<br>" if html else ", "
   if 26 - 26: o0oOOo0O0Ooo - I1IiiI / OoooooooOO / ooOoO0o % iIii1I11I1II1 % I1ii11iIi11i
   i1I1IiiIi = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( iI1IiIiIIII11 , i1I1ii111 , II11 , i1I1ii111 , oOooO0O0 , i1I1ii111 ,
   # Ii1I
 iI1II1IiIiIi )
   if 88 - 88: OoooooooOO
  return ( i1I1IiiIi )
  if 60 - 60: II111iiii % Oo0Ooo * I11i * OoO0O00 - OoOoOO00
  if 65 - 65: iII111i
  if 86 - 86: OoO0O00 / II111iiii % OoOoOO00 * OOooOOo . I1IiiI / IiII
  if 100 - 100: i1IIi / I1IiiI * I1ii11iIi11i % ooOoO0o + OoO0O00 * oO0o
  if 51 - 51: I1Ii111 - OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00
  if 45 - 45: i11iIiiIii - II111iiii / i1IIi * OoOoOO00
  if 1 - 1: OOooOOo + I1IiiI + Ii1I . iII111i
  if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 5 - 5: OoOoOO00 % i1IIi
if 31 - 31: Oo0Ooo * O0 . OOooOOo . o0oOOo0O0Ooo + OoO0O00 + II111iiii
if 76 - 76: Oo0Ooo + I1IiiI - O0
if 58 - 58: IiII * i1IIi . I1IiiI - iII111i
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
  if 73 - 73: Oo0Ooo . OoOoOO00
  if ( recurse == False ) : return
  if 50 - 50: IiII / o0oOOo0O0Ooo
  if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
  if 52 - 52: O0
  if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
  if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
  if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
  oOOoO = lisp_get_default_route_next_hops ( )
  if ( oOOoO == [ ] or len ( oOOoO ) == 1 ) : return
  if 54 - 54: ooOoO0o
  self . rloc_next_hop = oOOoO [ 0 ]
  I1IIII = self
  for iiIIII1I1ii in oOOoO [ 1 : : ] :
   O0oo = lisp_rloc ( False )
   O0oo = copy . deepcopy ( self )
   O0oo . rloc_next_hop = iiIIII1I1ii
   I1IIII . next_rloc = O0oo
   I1IIII = O0oo
   if 49 - 49: I11i + o0oOOo0O0Ooo % OOooOOo . iII111i
   if 11 - 11: I1Ii111 - ooOoO0o
   if 76 - 76: oO0o - i1IIi - O0 % Oo0Ooo
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 66 - 66: IiII % iII111i / o0oOOo0O0Ooo
  if 44 - 44: iIii1I11I1II1 + o0oOOo0O0Ooo + OoO0O00 * II111iiii
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 84 - 84: Oo0Ooo * I1Ii111 - o0oOOo0O0Ooo % Ii1I
  if 69 - 69: I11i + OoOoOO00 - i11iIiiIii * O0 % O0
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 81 - 81: I11i - o0oOOo0O0Ooo % Ii1I / I1Ii111 * II111iiii
  if 40 - 40: OoO0O00 . i11iIiiIii
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 36 - 36: o0oOOo0O0Ooo * iII111i / I1ii11iIi11i % i1IIi % I1ii11iIi11i + i11iIiiIii
  if 24 - 24: I1Ii111 / ooOoO0o - i11iIiiIii
  if 32 - 32: II111iiii * Ii1I . ooOoO0o * Oo0Ooo - I1ii11iIi11i % I11i
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
  if 96 - 96: Ii1I / OOooOOo / O0
  if 8 - 8: iII111i + OOooOOo / I1ii11iIi11i . iII111i
 def print_rloc ( self , indent ) :
  Oo0OO0000oooo = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , Oo0OO0000oooo , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 45 - 45: i1IIi
  if 28 - 28: iII111i
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  IiIi1I1i1iII = self . rloc_name
  if ( cour ) : IiIi1I1i1iII = lisp_print_cour ( IiIi1I1i1iII )
  return ( 'rloc-name: {}' . format ( blue ( IiIi1I1i1iII , cour ) ) )
  if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
  if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  IiI1iI1 = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 4 - 4: Ii1I - Oo0Ooo . i1IIi + iIii1I11I1II1
  if 28 - 28: O0 / ooOoO0o / IiII - I11i + IiII + OoO0O00
  if 84 - 84: Oo0Ooo + OoOoOO00 / iII111i . I1ii11iIi11i
  if 26 - 26: Oo0Ooo
  oOo00O = self . rloc
  if ( oOo00O . is_null ( ) == False ) :
   O00OOoOOO0O0O = lisp_get_nat_info ( oOo00O , self . rloc_name )
   if ( O00OOoOOO0O0O ) :
    IiI1iI1 = O00OOoOOO0O0O . port
    oO0 = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    oo0o00OO = oOo00O . print_address_no_iid ( )
    o0O00oo0O = red ( oo0o00OO , False )
    OOOoOo000O = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 12 - 12: oO0o + ooOoO0o * IiII
    if 84 - 84: o0oOOo0O0Ooo * o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo + I1IiiI
    if 89 - 89: II111iiii
    if 41 - 41: iIii1I11I1II1
    if 26 - 26: Oo0Ooo / i1IIi + Oo0Ooo
    if 76 - 76: I1ii11iIi11i * i1IIi % oO0o
    if ( O00OOoOOO0O0O . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( o0O00oo0O , IiI1iI1 , OOOoOo000O ) )
     if 80 - 80: i1IIi * II111iiii . O0 % I1ii11iIi11i / ooOoO0o
     if 58 - 58: I1IiiI * I1ii11iIi11i - i1IIi % I1Ii111 % O0
     O00OOoOOO0O0O = None if ( O00OOoOOO0O0O == oO0 ) else oO0
     if ( O00OOoOOO0O0O and O00OOoOOO0O0O . timed_out ( ) ) :
      IiI1iI1 = O00OOoOOO0O0O . port
      o0O00oo0O = red ( O00OOoOOO0O0O . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( o0O00oo0O , IiI1iI1 ,
      # OoO0O00 + I11i
 OOOoOo000O ) )
      O00OOoOOO0O0O = None
      if 82 - 82: oO0o % I1IiiI % OoooooooOO . iII111i . oO0o
      if 62 - 62: i1IIi . II111iiii . IiII * OOooOOo % i11iIiiIii * I11i
      if 48 - 48: I1Ii111 - O0
      if 23 - 23: iIii1I11I1II1
      if 88 - 88: I1IiiI + iII111i / Ii1I
      if 57 - 57: o0oOOo0O0Ooo
      if 69 - 69: i1IIi / i1IIi / OoOoOO00 + ooOoO0o % I1Ii111
    if ( O00OOoOOO0O0O ) :
     if ( O00OOoOOO0O0O . address != oo0o00OO ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( o0O00oo0O , red ( O00OOoOOO0O0O . address , False ) ) )
      if 41 - 41: II111iiii * OOooOOo
      self . rloc . store_address ( O00OOoOOO0O0O . address )
      if 8 - 8: I1Ii111 + O0
     o0O00oo0O = red ( O00OOoOOO0O0O . address , False )
     IiI1iI1 = O00OOoOOO0O0O . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( o0O00oo0O , IiI1iI1 , OOOoOo000O ) )
     if 67 - 67: iIii1I11I1II1 . O0
     self . store_translated_rloc ( oOo00O , IiI1iI1 )
     if 40 - 40: OOooOOo - ooOoO0o . OoooooooOO % O0 * I11i - I1ii11iIi11i
     if 92 - 92: ooOoO0o % oO0o / i11iIiiIii
     if 91 - 91: OOooOOo
     if 60 - 60: i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
  if 54 - 54: II111iiii * I1IiiI
  if 49 - 49: I1ii11iIi11i
  if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for iIIII1iiIII in self . rle . rle_nodes :
    IiIi1I1i1iII = iIIII1iiIII . rloc_name
    O00OOoOOO0O0O = lisp_get_nat_info ( iIIII1iiIII . address , IiIi1I1i1iII )
    if ( O00OOoOOO0O0O == None ) : continue
    if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
    IiI1iI1 = O00OOoOOO0O0O . port
    iIii1iii1 = IiIi1I1i1iII
    if ( iIii1iii1 ) : iIii1iii1 = blue ( IiIi1I1i1iII , False )
    if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( IiI1iI1 ,
    # i11iIiiIii
 iIIII1iiIII . address . print_address_no_iid ( ) , iIii1iii1 ) )
    iIIII1iiIII . translated_port = IiI1iI1
    if 61 - 61: I1Ii111 . OoO0O00 % I1ii11iIi11i
    if 29 - 29: o0oOOo0O0Ooo
    if 80 - 80: OOooOOo + OoO0O00 - OOooOOo
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 93 - 93: OoooooooOO + iIii1I11I1II1 * I1IiiI * Ii1I
  if 50 - 50: O0 - OOooOOo * O0 * o0oOOo0O0Ooo % I1Ii111
  if 35 - 35: i11iIiiIii / iIii1I11I1II1 + OoooooooOO + iII111i
  if 90 - 90: Ii1I . o0oOOo0O0Ooo
  iIiIIi1II = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 59 - 59: OoOoOO00 * I1Ii111 * iIii1I11I1II1
  if ( rloc_record . keys != None and iIiIIi1II ) :
   ii1i1I1111ii = rloc_record . keys [ 1 ]
   if ( ii1i1I1111ii != None ) :
    oo0o00OO = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( IiI1iI1 )
    if 5 - 5: i11iIiiIii / o0oOOo0O0Ooo
    ii1i1I1111ii . add_key_by_rloc ( oo0o00OO , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( oo0o00OO , False ) ) )
    if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
    if 12 - 12: I1ii11iIi11i / O0
    if 18 - 18: OoOoOO00 . i11iIiiIii + i1IIi / OoooooooOO - IiII % OoO0O00
  return ( IiI1iI1 )
  if 47 - 47: iII111i % IiII + I1Ii111 * o0oOOo0O0Ooo * OoooooooOO
  if 100 - 100: Oo0Ooo / I1IiiI / iII111i / I1Ii111 / oO0o % o0oOOo0O0Ooo
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 16 - 16: I1IiiI + I11i
  if 66 - 66: OoooooooOO % II111iiii / I1Ii111 . i11iIiiIii
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 67 - 67: Ii1I + Oo0Ooo - I1IiiI - IiII + oO0o + Oo0Ooo
  if 84 - 84: I1ii11iIi11i % oO0o - OOooOOo * Ii1I
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 78 - 78: i1IIi / ooOoO0o / oO0o
  return ( True )
  if 21 - 21: IiII % Ii1I + OOooOOo + IiII
  if 90 - 90: o0oOOo0O0Ooo
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 38 - 38: OoOoOO00 / OOooOOo % OoooooooOO * I1ii11iIi11i
  if 7 - 7: I11i * O0 + Oo0Ooo / O0 * oO0o + i11iIiiIii
  if 74 - 74: OoOoOO00
 def print_state_change ( self , new_state ) :
  Oo000 = self . print_state ( )
  iI = "{} -> {}" . format ( Oo000 , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   iI = bold ( iI , False )
   if 66 - 66: i11iIiiIii . I11i % IiII % OoO0O00
  return ( iI )
  if 25 - 25: OoO0O00 % Oo0Ooo / Ii1I / Ii1I * IiII
  if 33 - 33: ooOoO0o
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 14 - 14: Oo0Ooo % I1Ii111 % ooOoO0o . oO0o * iIii1I11I1II1 . I1ii11iIi11i
  if 50 - 50: O0 * i11iIiiIii / iIii1I11I1II1 . I11i + i11iIiiIii
 def print_recent_rloc_probe_rtts ( self ) :
  OO0Ooo = str ( self . recent_rloc_probe_rtts )
  OO0Ooo = OO0Ooo . replace ( "-1" , "?" )
  return ( OO0Ooo )
  if 23 - 23: I1ii11iIi11i
  if 68 - 68: OoO0O00 . oO0o / IiII - II111iiii % Oo0Ooo
 def compute_rloc_probe_rtt ( self ) :
  I1IIII = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  IiIIi = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ I1IIII ] + IiIIi [ 0 : - 1 ]
  if 65 - 65: iII111i % oO0o * IiII
  if 16 - 16: iII111i % I11i % OoOoOO00
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 80 - 80: OoooooooOO * i11iIiiIii % oO0o / Oo0Ooo - I1ii11iIi11i
  if 92 - 92: o0oOOo0O0Ooo % i1IIi / I1Ii111 % ooOoO0o / oO0o
 def print_recent_rloc_probe_hops ( self ) :
  IiI1 = str ( self . recent_rloc_probe_hops )
  return ( IiI1 )
  if 80 - 80: iIii1I11I1II1 . II111iiii
  if 50 - 50: o0oOOo0O0Ooo - O0 + OoO0O00
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < LISP_RLOC_PROBE_TTL / 2 ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 22 - 22: I1Ii111 % O0 / I1Ii111 / I1Ii111
  if ( from_ttl < LISP_RLOC_PROBE_TTL / 2 ) :
   oO0ooo = "!"
  else :
   oO0ooo = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 64 - 64: O0 * OOooOOo * I1IiiI - o0oOOo0O0Ooo
   if 86 - 86: i1IIi
  I1IIII = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + oO0ooo
  IiIIi = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ I1IIII ] + IiIIi [ 0 : - 1 ]
  if 84 - 84: OoOoOO00
  if 31 - 31: iIii1I11I1II1 + I1IiiI
 def process_rloc_probe_reply ( self , nonce , eid , group , hop_count , ttl ) :
  oOo00O = self
  while ( True ) :
   if ( oOo00O . last_rloc_probe_nonce == nonce ) : break
   oOo00O = oOo00O . next_rloc
   if ( oOo00O == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 82 - 82: I1Ii111 / Ii1I % OoooooooOO - IiII / OoooooooOO
    return
    if 23 - 23: iIii1I11I1II1
    if 7 - 7: IiII / OOooOOo + Oo0Ooo . I1IiiI
    if 33 - 33: I1Ii111 + OoooooooOO
  oOo00O . last_rloc_probe_reply = lisp_get_timestamp ( )
  oOo00O . compute_rloc_probe_rtt ( )
  ooiii1iiI1 = oOo00O . print_state_change ( "up" )
  if ( oOo00O . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( oOo00O . rloc , True )
   oOo00O . state = LISP_RLOC_UP_STATE
   oOo00O . last_state_change = lisp_get_timestamp ( )
   IiiiiII1i = lisp_map_cache . lookup_cache ( eid , True )
   if ( IiiiiII1i ) : lisp_write_ipc_map_cache ( True , IiiiiII1i )
   if 48 - 48: II111iiii % I1ii11iIi11i - II111iiii
   if 29 - 29: I1Ii111 - I1Ii111 - I11i * iIii1I11I1II1 % OoO0O00 % IiII
  oOo00O . store_rloc_probe_hops ( hop_count , ttl )
  if 73 - 73: i1IIi . OoooooooOO / OoOoOO00 % Ii1I / Ii1I / Ii1I
  OOO0oOooOOo00 = bold ( "RLOC-probe reply" , False )
  oo0o00OO = oOo00O . rloc . print_address_no_iid ( )
  i1i1I1I1 = bold ( str ( oOo00O . print_rloc_probe_rtt ( ) ) , False )
  III1I1Iii1 = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 6 - 6: iIii1I11I1II1 / oO0o % ooOoO0o
  iiIIII1I1ii = ""
  if ( oOo00O . rloc_next_hop != None ) :
   OooOOOoOoo0O0 , IiI1Ii = oOo00O . rloc_next_hop
   iiIIII1I1ii = ", nh {}({})" . format ( IiI1Ii , OooOOOoOoo0O0 )
   if 1 - 1: Ii1I * I1IiiI + Oo0Ooo + IiII + OOooOOo
   if 61 - 61: OoO0O00 . i1IIi / Ii1I % iII111i + Ii1I / i1IIi
  oOo = green ( lisp_print_eid_tuple ( eid , group ) , False )
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}" ) . format ( OOO0oOooOOo00 , red ( oo0o00OO , False ) , III1I1Iii1 , oOo ,
  # O0
 ooiii1iiI1 , i1i1I1I1 , iiIIII1I1ii , str ( hop_count ) + "/" + str ( ttl ) ) )
  if 40 - 40: O0
  if ( oOo00O . rloc_next_hop == None ) : return
  if 87 - 87: i1IIi / OoooooooOO . o0oOOo0O0Ooo % IiII
  if 22 - 22: OoO0O00 . OOooOOo
  if 95 - 95: OOooOOo + Oo0Ooo - OoOoOO00
  if 33 - 33: OoO0O00
  oOo00O = None
  o0O0 = None
  while ( True ) :
   oOo00O = self if oOo00O == None else oOo00O . next_rloc
   if ( oOo00O == None ) : break
   if ( oOo00O . up_state ( ) == False ) : continue
   if ( oOo00O . rloc_probe_rtt == - 1 ) : continue
   if 79 - 79: OOooOOo % I1Ii111 / IiII - Oo0Ooo
   if ( o0O0 == None ) : o0O0 = oOo00O
   if ( oOo00O . rloc_probe_rtt < o0O0 . rloc_probe_rtt ) : o0O0 = oOo00O
   if 48 - 48: Oo0Ooo * iII111i - Oo0Ooo + I11i % II111iiii
   if 71 - 71: OoOoOO00 % o0oOOo0O0Ooo . oO0o
  if ( o0O0 != None ) :
   OooOOOoOoo0O0 , IiI1Ii = o0O0 . rloc_next_hop
   iiIIII1I1ii = bold ( "nh {}({})" . format ( IiI1Ii , OooOOOoOoo0O0 ) , False )
   lprint ( "    Install host-route via best {}" . format ( iiIIII1I1ii ) )
   lisp_install_host_route ( oo0o00OO , None , False )
   lisp_install_host_route ( oo0o00OO , IiI1Ii , True )
   if 65 - 65: OoO0O00
   if 48 - 48: OoO0O00
   if 59 - 59: OoooooooOO + I11i . oO0o
 def add_to_rloc_probe_list ( self , eid , group ) :
  oo0o00OO = self . rloc . print_address_no_iid ( )
  IiI1iI1 = self . translated_port
  if ( IiI1iI1 != 0 ) : oo0o00OO += ":" + str ( IiI1iI1 )
  if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
  if ( lisp_rloc_probe_list . has_key ( oo0o00OO ) == False ) :
   lisp_rloc_probe_list [ oo0o00OO ] = [ ]
   if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
   if 16 - 16: OoO0O00 / Ii1I * i11iIiiIii / o0oOOo0O0Ooo + I1Ii111
  if ( group . is_null ( ) ) : group . instance_id = 0
  for i11iII1IiI , oOo , i11ii in lisp_rloc_probe_list [ oo0o00OO ] :
   if ( oOo . is_exact_match ( eid ) and i11ii . is_exact_match ( group ) ) :
    if ( i11iII1IiI == self ) :
     if ( lisp_rloc_probe_list [ oo0o00OO ] == [ ] ) :
      lisp_rloc_probe_list . pop ( oo0o00OO )
      if 21 - 21: I11i % I1ii11iIi11i
     return
     if 8 - 8: OOooOOo % OoO0O00 + O0 - o0oOOo0O0Ooo
    lisp_rloc_probe_list [ oo0o00OO ] . remove ( [ i11iII1IiI , oOo , i11ii ] )
    break
    if 46 - 46: Oo0Ooo . ooOoO0o + OoOoOO00 - I11i / i11iIiiIii . iII111i
    if 80 - 80: II111iiii + OoO0O00 % ooOoO0o + i11iIiiIii
  lisp_rloc_probe_list [ oo0o00OO ] . append ( [ self , eid , group ] )
  if 30 - 30: Ii1I / I1ii11iIi11i % IiII - Oo0Ooo
  if 100 - 100: IiII . I1Ii111 * oO0o % OoO0O00 . iIii1I11I1II1 * Oo0Ooo
  if 100 - 100: IiII - OoOoOO00 % iII111i
  if 24 - 24: Oo0Ooo / OoO0O00 + i11iIiiIii
  if 81 - 81: i11iIiiIii . iIii1I11I1II1 - OoooooooOO
  oOo00O = lisp_rloc_probe_list [ oo0o00OO ] [ 0 ] [ 0 ]
  if ( oOo00O . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
   if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
   if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
 def delete_from_rloc_probe_list ( self , eid , group ) :
  oo0o00OO = self . rloc . print_address_no_iid ( )
  IiI1iI1 = self . translated_port
  if ( IiI1iI1 != 0 ) : oo0o00OO += ":" + str ( IiI1iI1 )
  if ( lisp_rloc_probe_list . has_key ( oo0o00OO ) == False ) : return
  if 42 - 42: OOooOOo
  iiI11i = [ ]
  for I1iII11ii1 in lisp_rloc_probe_list [ oo0o00OO ] :
   if ( I1iII11ii1 [ 0 ] != self ) : continue
   if ( I1iII11ii1 [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( I1iII11ii1 [ 2 ] . is_exact_match ( group ) == False ) : continue
   iiI11i = I1iII11ii1
   break
   if 22 - 22: Ii1I / ooOoO0o / o0oOOo0O0Ooo % I1ii11iIi11i . iIii1I11I1II1
  if ( iiI11i == [ ] ) : return
  if 78 - 78: OoO0O00 . I1ii11iIi11i / ooOoO0o + OoO0O00 / I1ii11iIi11i * ooOoO0o
  try :
   lisp_rloc_probe_list [ oo0o00OO ] . remove ( iiI11i )
   if ( lisp_rloc_probe_list [ oo0o00OO ] == [ ] ) :
    lisp_rloc_probe_list . pop ( oo0o00OO )
    if 96 - 96: IiII % iII111i . OoOoOO00 / oO0o . OoO0O00
  except :
   return
   if 85 - 85: iIii1I11I1II1 / OoOoOO00 * I1ii11iIi11i
   if 26 - 26: iII111i - OoO0O00 . o0oOOo0O0Ooo
   if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  Oo0Ooo0O0 = ""
  oOo00O = self
  while ( True ) :
   oooOoOoooo = oOo00O . last_rloc_probe
   if ( oooOoOoooo == None ) : oooOoOoooo = 0
   iiIi1iI1Ii = oOo00O . last_rloc_probe_reply
   if ( iiIi1iI1Ii == None ) : iiIi1iI1Ii = 0
   i1i1I1I1 = oOo00O . print_rloc_probe_rtt ( )
   IiII1iiI = space ( 4 )
   if 26 - 26: OoooooooOO
   if ( oOo00O . rloc_next_hop == None ) :
    Oo0Ooo0O0 += "RLOC-Probing:\n"
   else :
    OooOOOoOoo0O0 , IiI1Ii = oOo00O . rloc_next_hop
    Oo0Ooo0O0 += "RLOC-Probing for nh {}({}):\n" . format ( IiI1Ii , OooOOOoOoo0O0 )
    if 79 - 79: I1IiiI + I1IiiI
    if 45 - 45: oO0o + I1IiiI / oO0o
   Oo0Ooo0O0 += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( IiII1iiI , lisp_print_elapsed ( oooOoOoooo ) ,
   # OOooOOo % OoooooooOO
 IiII1iiI , lisp_print_elapsed ( iiIi1iI1Ii ) , i1i1I1I1 )
   if 15 - 15: Oo0Ooo % OoooooooOO * OOooOOo * IiII / OoooooooOO / i11iIiiIii
   if ( trailing_linefeed ) : Oo0Ooo0O0 += "\n"
   if 11 - 11: o0oOOo0O0Ooo / Oo0Ooo
   oOo00O = oOo00O . next_rloc
   if ( oOo00O == None ) : break
   Oo0Ooo0O0 += "\n"
   if 53 - 53: I1ii11iIi11i + ooOoO0o - I1ii11iIi11i + I11i
  return ( Oo0Ooo0O0 )
  if 12 - 12: iII111i / II111iiii . OoOoOO00 - OOooOOo
  if 23 - 23: ooOoO0o + ooOoO0o . I11i
 def get_encap_keys ( self ) :
  IiI1iI1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 90 - 90: I1Ii111 / iIii1I11I1II1 / oO0o
  oo0o00OO = self . rloc . print_address_no_iid ( ) + ":" + IiI1iI1
  if 47 - 47: i11iIiiIii - OOooOOo / I1IiiI % o0oOOo0O0Ooo % I1IiiI % I11i
  try :
   oOoo0oO = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ]
   if ( oOoo0oO [ 1 ] ) : return ( oOoo0oO [ 1 ] . encrypt_key , oOoo0oO [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 26 - 26: OoOoOO00 * ooOoO0o
   if 23 - 23: Ii1I + i1IIi + IiII - O0 / OOooOOo
   if 82 - 82: I1Ii111
 def rloc_recent_rekey ( self ) :
  IiI1iI1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 78 - 78: I1Ii111 % oO0o * iIii1I11I1II1
  oo0o00OO = self . rloc . print_address_no_iid ( ) + ":" + IiI1iI1
  if 1 - 1: i1IIi . iIii1I11I1II1
  try :
   ii1i1I1111ii = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ] [ 1 ]
   if ( ii1i1I1111ii == None ) : return ( False )
   if ( ii1i1I1111ii . last_rekey == None ) : return ( True )
   return ( time . time ( ) - ii1i1I1111ii . last_rekey < 1 )
  except :
   return ( False )
   if 2 - 2: OOooOOo % Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
   if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
   if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
   if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
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
  if 49 - 49: iII111i + OoOoOO00
  if 33 - 33: ooOoO0o
 def print_mapping ( self , eid_indent , rloc_indent ) :
  Oo0OO0000oooo = lisp_print_elapsed ( self . uptime )
  O0o00oOOOO00 = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 19 - 19: I1Ii111 % IiII
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , O0o00oOOOO00 , Oo0OO0000oooo ,
 len ( self . rloc_set ) ) )
  for oOo00O in self . rloc_set : oOo00O . print_rloc ( rloc_indent )
  if 94 - 94: I1Ii111 * I1ii11iIi11i * I1ii11iIi11i - o0oOOo0O0Ooo . i11iIiiIii
  if 16 - 16: i1IIi
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 88 - 88: OOooOOo
  if 79 - 79: oO0o
 def print_ttl ( self ) :
  oo0o = self . map_cache_ttl
  if ( oo0o == None ) : return ( "forever" )
  if 52 - 52: oO0o + OoO0O00 / OoooooooOO - iIii1I11I1II1 / iII111i - oO0o
  if ( oo0o >= 3600 ) :
   if ( ( oo0o % 3600 ) == 0 ) :
    oo0o = str ( oo0o / 3600 ) + " hours"
   else :
    oo0o = str ( oo0o * 60 ) + " mins"
    if 68 - 68: I1IiiI - OoOoOO00 - iIii1I11I1II1 % i11iIiiIii * OoOoOO00 * OoO0O00
  elif ( oo0o >= 60 ) :
   if ( ( oo0o % 60 ) == 0 ) :
    oo0o = str ( oo0o / 60 ) + " mins"
   else :
    oo0o = str ( oo0o ) + " secs"
    if 97 - 97: OoO0O00 - IiII + ooOoO0o % iIii1I11I1II1 % iII111i
  else :
   oo0o = str ( oo0o ) + " secs"
   if 100 - 100: IiII - Ii1I * iIii1I11I1II1 . iII111i . i1IIi % Oo0Ooo
  return ( oo0o )
  if 11 - 11: I11i + oO0o % Ii1I
  if 22 - 22: ooOoO0o
 def refresh ( self ) :
  if ( self . group . is_null ( ) ) : return ( self . refresh_unicast ( ) )
  return ( self . refresh_multicast ( ) )
  if 83 - 83: OOooOOo - i11iIiiIii - i1IIi / oO0o
  if 33 - 33: OoO0O00 + OOooOOo
 def refresh_unicast ( self ) :
  return ( self . is_active ( ) and self . has_ttl_elapsed ( ) and
 self . gleaned == False )
  if 36 - 36: o0oOOo0O0Ooo . o0oOOo0O0Ooo / oO0o * ooOoO0o * Ii1I * IiII
  if 39 - 39: i1IIi
 def refresh_multicast ( self ) :
  if 79 - 79: ooOoO0o - II111iiii - oO0o
  if 55 - 55: iII111i % iIii1I11I1II1 + Ii1I + oO0o . i11iIiiIii - OOooOOo
  if 14 - 14: oO0o - i11iIiiIii / OoOoOO00 % o0oOOo0O0Ooo / IiII * I1IiiI
  if 2 - 2: i1IIi / I1Ii111 + I1IiiI + I1ii11iIi11i - o0oOOo0O0Ooo + iIii1I11I1II1
  if 78 - 78: I1ii11iIi11i % i1IIi . I1Ii111 + Oo0Ooo . o0oOOo0O0Ooo % II111iiii
  oO000o0Oo00 = int ( ( time . time ( ) - self . uptime ) % self . map_cache_ttl )
  O0ii1i = ( oO000o0Oo00 in [ 0 , 1 , 2 ] )
  if ( O0ii1i == False ) : return ( False )
  if 75 - 75: I1IiiI * oO0o / Oo0Ooo - II111iiii . OoO0O00
  if 8 - 8: iII111i . i11iIiiIii . IiII . I1ii11iIi11i + I11i
  if 24 - 24: I1IiiI - I1IiiI . Oo0Ooo * IiII + I1IiiI / i1IIi
  if 18 - 18: II111iiii / iIii1I11I1II1 * I1ii11iIi11i . ooOoO0o * ooOoO0o
  ooOoOoooo = ( ( time . time ( ) - self . last_multicast_map_request ) <= 2 )
  if ( ooOoOoooo ) : return ( False )
  if 92 - 92: IiII + OoO0O00 + Oo0Ooo + oO0o
  self . last_multicast_map_request = lisp_get_timestamp ( )
  return ( True )
  if 81 - 81: Oo0Ooo % ooOoO0o / II111iiii . I11i
  if 41 - 41: IiII / OOooOOo * o0oOOo0O0Ooo . iII111i * I1IiiI . iIii1I11I1II1
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . last_refresh_time
  if ( oO000o0Oo00 >= self . map_cache_ttl ) : return ( True )
  if 52 - 52: oO0o . OOooOOo . oO0o / Oo0Ooo / i1IIi - I1IiiI
  if 69 - 69: Ii1I . o0oOOo0O0Ooo - OoooooooOO
  if 15 - 15: OoO0O00 / I1ii11iIi11i
  if 86 - 86: OOooOOo * OoOoOO00 % i1IIi * IiII . I1ii11iIi11i
  if 72 - 72: i1IIi - I1Ii111 . O0 * OoO0O00
  oOo0oO0OO = self . map_cache_ttl - ( self . map_cache_ttl / 10 )
  if ( oO000o0Oo00 >= oOo0oO0OO ) : return ( True )
  return ( False )
  if 17 - 17: IiII
  if 43 - 43: ooOoO0o / o0oOOo0O0Ooo - OoooooooOO % I1IiiI
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . stats . last_increment
  return ( oO000o0Oo00 <= 60 )
  if 94 - 94: OoooooooOO * I1ii11iIi11i
  if 28 - 28: II111iiii / II111iiii / II111iiii
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 70 - 70: OoO0O00 + O0 * OoO0O00
  if 25 - 25: OoooooooOO . Oo0Ooo + OOooOOo + Oo0Ooo * O0 % i1IIi
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 71 - 71: II111iiii / Ii1I + i1IIi - OoOoOO00 + Ii1I
  if 31 - 31: OoooooooOO * Ii1I - iII111i . oO0o % Ii1I
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for oOo00O in self . best_rloc_set :
   oOo00O . delete_from_rloc_probe_list ( self . eid , self . group )
   if 97 - 97: Ii1I
   if 51 - 51: II111iiii . oO0o % iII111i
   if 47 - 47: II111iiii - iII111i * I1IiiI . IiII
 def build_best_rloc_set ( self ) :
  IIIi = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 2 - 2: OoOoOO00 - iIii1I11I1II1 * I1Ii111 % II111iiii - Oo0Ooo . OoooooooOO
  if 47 - 47: I1Ii111 + oO0o - Ii1I % OoO0O00 - I1Ii111 / i11iIiiIii
  if 27 - 27: i11iIiiIii . OoO0O00 + Ii1I
  if 47 - 47: I1Ii111 . iIii1I11I1II1 + i11iIiiIii
  Oo0O = 256
  for oOo00O in self . rloc_set :
   if ( oOo00O . up_state ( ) ) : Oo0O = min ( oOo00O . priority , Oo0O )
   if 77 - 77: iII111i . I1IiiI - iIii1I11I1II1 + II111iiii / i1IIi
   if 65 - 65: I1ii11iIi11i
   if 2 - 2: iII111i % I1ii11iIi11i / iII111i
   if 93 - 93: iII111i
   if 5 - 5: iII111i . I11i % I11i * Ii1I - I1ii11iIi11i . i11iIiiIii
   if 32 - 32: II111iiii
   if 58 - 58: I1IiiI - o0oOOo0O0Ooo - I1Ii111 . O0 % OoO0O00 . I11i
   if 41 - 41: iII111i . I1Ii111 - IiII / O0
   if 62 - 62: IiII * I1ii11iIi11i * iII111i * OoOoOO00
   if 12 - 12: Oo0Ooo * Ii1I / ooOoO0o % I11i % O0
  for oOo00O in self . rloc_set :
   if ( oOo00O . priority <= Oo0O ) :
    if ( oOo00O . unreach_state ( ) and oOo00O . last_rloc_probe == None ) :
     oOo00O . last_rloc_probe = lisp_get_timestamp ( )
     if 25 - 25: Oo0Ooo * oO0o
    self . best_rloc_set . append ( oOo00O )
    if 78 - 78: OoOoOO00 / II111iiii
    if 6 - 6: I1Ii111 . OoOoOO00
    if 75 - 75: Oo0Ooo + I11i
    if 87 - 87: I1IiiI
    if 36 - 36: OoO0O00 . ooOoO0o . O0 / OoO0O00
    if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
    if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
    if 72 - 72: I1ii11iIi11i
  for oOo00O in IIIi :
   if ( oOo00O . priority < Oo0O ) : continue
   oOo00O . delete_from_rloc_probe_list ( self . eid , self . group )
   if 74 - 74: I1Ii111 * iIii1I11I1II1 / oO0o - IiII - I1IiiI
  for oOo00O in self . best_rloc_set :
   if ( oOo00O . rloc . is_null ( ) ) : continue
   oOo00O . add_to_rloc_probe_list ( self . eid , self . group )
   if 84 - 84: iIii1I11I1II1 % Oo0Ooo / I1ii11iIi11i + o0oOOo0O0Ooo * II111iiii
   if 81 - 81: I1IiiI / I1ii11iIi11i / OOooOOo
   if 89 - 89: Oo0Ooo % IiII
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  IIii1i = lisp_packet . packet
  i11IIiI1II = lisp_packet . inner_version
  iiiIIiiIi = len ( self . best_rloc_set )
  if ( iiiIIiiIi == 0 ) :
   self . stats . increment ( len ( IIii1i ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 47 - 47: O0
   if 93 - 93: oO0o
  IiI1III1I1 = 4 if lisp_load_split_pings else 0
  I1I = lisp_packet . hash_ports ( )
  if ( i11IIiI1II == 4 ) :
   for IiIIi1IiiIiI in range ( 8 + IiI1III1I1 ) :
    I1I = I1I ^ struct . unpack ( "B" , IIii1i [ IiIIi1IiiIiI + 12 ] ) [ 0 ]
    if 83 - 83: OOooOOo - I1ii11iIi11i + OoO0O00
  elif ( i11IIiI1II == 6 ) :
   for IiIIi1IiiIiI in range ( 0 , 32 + IiI1III1I1 , 4 ) :
    I1I = I1I ^ struct . unpack ( "I" , IIii1i [ IiIIi1IiiIiI + 8 : IiIIi1IiiIiI + 12 ] ) [ 0 ]
    if 99 - 99: iII111i - OoOoOO00 % ooOoO0o
   I1I = ( I1I >> 16 ) + ( I1I & 0xffff )
   I1I = ( I1I >> 8 ) + ( I1I & 0xff )
  else :
   for IiIIi1IiiIiI in range ( 0 , 12 + IiI1III1I1 , 4 ) :
    I1I = I1I ^ struct . unpack ( "I" , IIii1i [ IiIIi1IiiIiI : IiIIi1IiiIiI + 4 ] ) [ 0 ]
    if 27 - 27: oO0o . oO0o * iII111i % iIii1I11I1II1
    if 81 - 81: iII111i * II111iiii
    if 28 - 28: i11iIiiIii . Oo0Ooo . Ii1I
  if ( lisp_data_plane_logging ) :
   III1I111i = [ ]
   for i11iII1IiI in self . best_rloc_set :
    if ( i11iII1IiI . rloc . is_null ( ) ) : continue
    III1I111i . append ( [ i11iII1IiI . rloc . print_address_no_iid ( ) , i11iII1IiI . print_state ( ) ] )
    if 18 - 18: i1IIi + O0 + o0oOOo0O0Ooo + OoO0O00 / o0oOOo0O0Ooo
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( I1I ) , I1I % iiiIIiiIi , red ( str ( III1I111i ) , False ) ) )
   if 8 - 8: i11iIiiIii
   if 44 - 44: OoooooooOO - ooOoO0o + I1ii11iIi11i * oO0o
   if 73 - 73: O0 * I1Ii111 - i1IIi
   if 68 - 68: OOooOOo % IiII / Oo0Ooo + OoOoOO00
   if 11 - 11: OoO0O00
   if 70 - 70: o0oOOo0O0Ooo * O0 * II111iiii
  oOo00O = self . best_rloc_set [ I1I % iiiIIiiIi ]
  if 38 - 38: OoO0O00 - I1IiiI * OoooooooOO / I11i . O0
  if 77 - 77: OOooOOo + oO0o * iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii
  if 92 - 92: Oo0Ooo . o0oOOo0O0Ooo % OoooooooOO * i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo
  if 48 - 48: iII111i * I1ii11iIi11i * oO0o % O0 . OoO0O00
  if 11 - 11: OOooOOo / o0oOOo0O0Ooo
  Oo0ooO0O0o00o = lisp_get_echo_nonce ( oOo00O . rloc , None )
  if ( Oo0ooO0O0o00o ) :
   Oo0ooO0O0o00o . change_state ( oOo00O )
   if ( oOo00O . no_echoed_nonce_state ( ) ) :
    Oo0ooO0O0o00o . request_nonce_sent = None
    if 98 - 98: oO0o + I11i . oO0o
    if 10 - 10: iII111i + i1IIi . I11i % ooOoO0o / ooOoO0o
    if 86 - 86: Oo0Ooo
    if 7 - 7: iIii1I11I1II1
    if 86 - 86: IiII + iII111i * II111iiii - IiII - o0oOOo0O0Ooo
    if 8 - 8: OOooOOo . Ii1I
  if ( oOo00O . up_state ( ) == False ) :
   I1I1ii1IIII1Iii1 = I1I % iiiIIiiIi
   ooo = ( I1I1ii1IIII1Iii1 + 1 ) % iiiIIiiIi
   while ( ooo != I1I1ii1IIII1Iii1 ) :
    oOo00O = self . best_rloc_set [ ooo ]
    if ( oOo00O . up_state ( ) ) : break
    ooo = ( ooo + 1 ) % iiiIIiiIi
    if 24 - 24: i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1 . I1IiiI
   if ( ooo == I1I1ii1IIII1Iii1 ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 81 - 81: OoOoOO00 * OoOoOO00 + OOooOOo . I11i - oO0o
    if 85 - 85: O0 * I1IiiI . Oo0Ooo - IiII
    if 84 - 84: I1Ii111 . iIii1I11I1II1 . O0 * I1ii11iIi11i
    if 59 - 59: i1IIi . o0oOOo0O0Ooo . Oo0Ooo * I1Ii111 + OoooooooOO
    if 11 - 11: I11i * ooOoO0o % iIii1I11I1II1 - O0
    if 68 - 68: ooOoO0o * OoooooooOO - OoooooooOO
  oOo00O . stats . increment ( len ( IIii1i ) )
  if 59 - 59: Ii1I / I11i / I1Ii111 + IiII * I1ii11iIi11i
  if 18 - 18: O0
  if 60 - 60: II111iiii % O0 - I1Ii111 / iII111i / I1IiiI
  if 59 - 59: O0 / iIii1I11I1II1
  if ( oOo00O . rle_name and oOo00O . rle == None ) :
   if ( lisp_rle_list . has_key ( oOo00O . rle_name ) ) :
    oOo00O . rle = lisp_rle_list [ oOo00O . rle_name ]
    if 49 - 49: O0 + I1IiiI
    if 52 - 52: oO0o
  if ( oOo00O . rle ) : return ( [ None , None , None , None , oOo00O . rle , None ] )
  if 56 - 56: ooOoO0o
  if 94 - 94: OoOoOO00
  if 12 - 12: I11i * OoooooooOO + ooOoO0o
  if 16 - 16: IiII
  if ( oOo00O . elp and oOo00O . elp . use_elp_node ) :
   return ( [ oOo00O . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 100 - 100: OoO0O00 % Oo0Ooo - OoooooooOO
   if 48 - 48: IiII / I11i * OoooooooOO
   if 1 - 1: I1ii11iIi11i + I11i
   if 54 - 54: IiII * O0 * I1Ii111 + i1IIi - I11i . I11i
   if 39 - 39: I1Ii111
  Iiiii = None if ( oOo00O . rloc . is_null ( ) ) else oOo00O . rloc
  IiI1iI1 = oOo00O . translated_port
  OOo000 = self . action if ( Iiiii == None ) else None
  if 21 - 21: i11iIiiIii * I1Ii111 % I11i . oO0o
  if 84 - 84: IiII % iII111i
  if 79 - 79: O0 / IiII . i1IIi - i1IIi + i1IIi
  if 47 - 47: iII111i - I1Ii111 - I1Ii111 . ooOoO0o
  if 5 - 5: i1IIi
  oOO000 = None
  if ( Oo0ooO0O0o00o and Oo0ooO0O0o00o . request_nonce_timeout ( ) == False ) :
   oOO000 = Oo0ooO0O0o00o . get_request_or_echo_nonce ( ipc_socket , Iiiii )
   if 47 - 47: I11i * I11i . OoOoOO00
   if 68 - 68: OoooooooOO + OoOoOO00 + i11iIiiIii
   if 89 - 89: Oo0Ooo + Ii1I * O0 - I1Ii111
   if 33 - 33: iIii1I11I1II1 . I11i
   if 63 - 63: oO0o - iII111i
  return ( [ Iiiii , IiI1iI1 , oOO000 , OOo000 , None , oOo00O ] )
  if 13 - 13: I1Ii111 / i1IIi % OoooooooOO / I11i
  if 66 - 66: I1Ii111 % o0oOOo0O0Ooo . iII111i . ooOoO0o + OOooOOo * II111iiii
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 33 - 33: oO0o
  if 64 - 64: OoO0O00 % Oo0Ooo % I11i . iII111i % I1IiiI
  if 50 - 50: i1IIi + ooOoO0o - iIii1I11I1II1
  if 45 - 45: OoooooooOO / o0oOOo0O0Ooo / iII111i
  if 72 - 72: I1Ii111
  for iIII in self . rloc_set :
   for oOo00O in rloc_address_set :
    if ( oOo00O . is_exact_match ( iIII . rloc ) == False ) : continue
    oOo00O = None
    break
    if 94 - 94: ooOoO0o . IiII - Ii1I + I1ii11iIi11i / ooOoO0o
   if ( oOo00O == rloc_address_set [ - 1 ] ) : return ( False )
   if 10 - 10: ooOoO0o . OOooOOo * O0 % II111iiii
  return ( True )
  if 12 - 12: oO0o + I1IiiI * Oo0Ooo - iII111i
  if 88 - 88: OOooOOo . OoO0O00
 def get_rloc ( self , rloc ) :
  for iIII in self . rloc_set :
   i11iII1IiI = iIII . rloc
   if ( rloc . is_exact_match ( i11iII1IiI ) ) : return ( iIII )
   if 86 - 86: OoOoOO00 . o0oOOo0O0Ooo / ooOoO0o * I1IiiI . OoO0O00 / I1Ii111
  return ( None )
  if 47 - 47: I11i . iII111i * OoOoOO00 % OoooooooOO
  if 59 - 59: OoooooooOO + I1ii11iIi11i - I11i / I1IiiI * oO0o
 def get_rloc_by_interface ( self , interface ) :
  for iIII in self . rloc_set :
   if ( iIII . interface == interface ) : return ( iIII )
   if 90 - 90: I1Ii111 + i1IIi * I1Ii111 / I11i * Oo0Ooo
  return ( None )
  if 27 - 27: OoooooooOO
  if 42 - 42: OoO0O00 + OoOoOO00
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   Ooooo00 = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( Ooooo00 == None ) :
    Ooooo00 = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , Ooooo00 )
    if 52 - 52: iII111i * OoOoOO00
   Ooooo00 . add_source_entry ( self )
   if 80 - 80: I1Ii111 / IiII * o0oOOo0O0Ooo - OoOoOO00 / iIii1I11I1II1
   if 38 - 38: II111iiii / I11i + IiII % OoooooooOO
   if 27 - 27: OoOoOO00 * OoO0O00 * OOooOOo % I1IiiI * o0oOOo0O0Ooo + I1ii11iIi11i
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   IiiiiII1i = lisp_map_cache . lookup_cache ( self . group , True )
   if ( IiiiiII1i == None ) :
    IiiiiII1i = lisp_mapping ( self . group , self . group , [ ] )
    IiiiiII1i . eid . copy_address ( self . group )
    IiiiiII1i . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , IiiiiII1i )
    if 73 - 73: i1IIi
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( IiiiiII1i . group )
   IiiiiII1i . add_source_entry ( self )
   if 52 - 52: IiII / i11iIiiIii * O0
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 67 - 67: OOooOOo / I11i - I1Ii111 % i11iIiiIii
  if 3 - 3: oO0o + iII111i + OOooOOo
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 54 - 54: i11iIiiIii + OoO0O00 - IiII - iII111i / I11i
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    O000O0o00o0o = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( O000O0o00o0o ) )
    if 65 - 65: i11iIiiIii / o0oOOo0O0Ooo % I1ii11iIi11i - O0 % OoooooooOO / o0oOOo0O0Ooo
  else :
   IiiiiII1i = lisp_map_cache . lookup_cache ( self . group , True )
   if ( IiiiiII1i == None ) : return
   if 36 - 36: iII111i * OoO0O00 / OOooOOo * IiII * iIii1I11I1II1 / IiII
   oo0oO0Oo = IiiiiII1i . lookup_source_cache ( self . eid , True )
   if ( oo0oO0Oo == None ) : return
   if 82 - 82: OoOoOO00 . oO0o
   IiiiiII1i . source_cache . delete_cache ( self . eid )
   if ( IiiiiII1i . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 36 - 36: OoOoOO00 . I1ii11iIi11i * I11i % Oo0Ooo
    if 25 - 25: II111iiii . I1Ii111 - OoO0O00 * I1IiiI - II111iiii / oO0o
    if 80 - 80: OoooooooOO / OoO0O00 / IiII / i1IIi + I1Ii111
    if 5 - 5: O0 / iII111i % II111iiii . Oo0Ooo - I11i
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 84 - 84: oO0o * iII111i % i11iIiiIii - O0 . iIii1I11I1II1 - OoOoOO00
  if 73 - 73: OoOoOO00
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 66 - 66: Oo0Ooo
  if 42 - 42: i11iIiiIii / II111iiii . OOooOOo
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 65 - 65: OoOoOO00 % II111iiii + Oo0Ooo
  if 24 - 24: OoO0O00 % OoooooooOO
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  o0OoO0000o = "," + str ( self . secondary_iid )
  return ( prefix . replace ( o0OoO0000o , o0OoO0000o + "*" ) )
  if 16 - 16: OoOoOO00 % Oo0Ooo * OoOoOO00 . Ii1I
  if 91 - 91: I1Ii111 - OoooooooOO . i1IIi . I1ii11iIi11i
 def increment_decap_stats ( self , packet ) :
  IiI1iI1 = packet . udp_dport
  if ( IiI1iI1 == LISP_DATA_PORT ) :
   oOo00O = self . get_rloc ( packet . outer_dest )
  else :
   if 37 - 37: IiII - oO0o
   if 92 - 92: I1IiiI
   if 51 - 51: OoO0O00 + Oo0Ooo - OOooOOo + I1ii11iIi11i
   if 32 - 32: I1ii11iIi11i % OoOoOO00 + Oo0Ooo
   for oOo00O in self . rloc_set :
    if ( oOo00O . translated_port != 0 ) : break
    if 92 - 92: II111iiii . O0 . iIii1I11I1II1 % IiII - i11iIiiIii
    if 9 - 9: OoO0O00
  if ( oOo00O != None ) : oOo00O . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 60 - 60: O0 / OoOoOO00 % i11iIiiIii % II111iiii / OoooooooOO
  if 52 - 52: ooOoO0o
 def rtrs_in_rloc_set ( self ) :
  for oOo00O in self . rloc_set :
   if ( oOo00O . is_rtr ( ) ) : return ( True )
   if 100 - 100: Oo0Ooo - o0oOOo0O0Ooo + iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1
  return ( False )
  if 4 - 4: OoOoOO00 / Oo0Ooo - OoO0O00 . OoOoOO00 / I1Ii111
  if 60 - 60: OOooOOo * I1Ii111
 def add_recent_source ( self , source ) :
  self . recent_sources [ source . print_address ( ) ] = lisp_get_timestamp ( )
  if 17 - 17: iII111i * I11i / iIii1I11I1II1 - II111iiii
  if 97 - 97: II111iiii * o0oOOo0O0Ooo
  if 13 - 13: o0oOOo0O0Ooo . II111iiii
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 76 - 76: II111iiii + I1Ii111 . OoooooooOO / IiII % i11iIiiIii
  if 87 - 87: Ii1I / OoOoOO00 / OOooOOo
 def get_timeout ( self , interface ) :
  try :
   IIiIIIiII1Ii1 = lisp_myinterfaces [ interface ]
   self . timeout = IIiIIIiII1Ii1 . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 39 - 39: IiII . II111iiii
   if 42 - 42: I1ii11iIi11i . Oo0Ooo * I1IiiI / Oo0Ooo
   if 83 - 83: i11iIiiIii / OoOoOO00
   if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 43 - 43: II111iiii - OoooooooOO
  if 11 - 11: I1IiiI
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
  if 64 - 64: OoO0O00 - OoO0O00
  if 93 - 93: Oo0Ooo . O0
  if 75 - 75: iII111i * II111iiii - I1IiiI
  if 30 - 30: i1IIi / ooOoO0o . ooOoO0o
  if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
  if 97 - 97: i11iIiiIii . OoOoOO00 + oO0o * O0 % OoO0O00 - Ii1I
  if 46 - 46: I1Ii111
  if 87 - 87: o0oOOo0O0Ooo - iII111i * OoO0O00 * o0oOOo0O0Ooo . o0oOOo0O0Ooo / OOooOOo
  if 50 - 50: i11iIiiIii - II111iiii * OoooooooOO + II111iiii - ooOoO0o
def lisp_is_group_more_specific ( group_str , group_mapping ) :
 o0OoO0000o = group_mapping . group_prefix . instance_id
 iIi1iii1 = group_mapping . group_prefix . mask_len
 O0o00oOOOO00 = lisp_address ( LISP_AFI_IPV4 , group_str , 32 , o0OoO0000o )
 if ( O0o00oOOOO00 . is_more_specific ( group_mapping . group_prefix ) ) : return ( iIi1iii1 )
 return ( - 1 )
 if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
 if 98 - 98: iII111i . i1IIi + o0oOOo0O0Ooo * OoooooooOO - i11iIiiIii
 if 21 - 21: i11iIiiIii . oO0o * o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
 if 33 - 33: I1IiiI + O0 - I11i
 if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
 if 63 - 63: o0oOOo0O0Ooo . IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
 if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
def lisp_lookup_group ( group ) :
 III1I111i = None
 for iiIIiIiiII in lisp_group_mapping_list . values ( ) :
  iIi1iii1 = lisp_is_group_more_specific ( group , iiIIiIiiII )
  if ( iIi1iii1 == - 1 ) : continue
  if ( III1I111i == None or iIi1iii1 > III1I111i . group_prefix . mask_len ) : III1I111i = iiIIiIiiII
  if 23 - 23: II111iiii / iII111i
 return ( III1I111i )
 if 55 - 55: i11iIiiIii - Ii1I % OoooooooOO * OoooooooOO
 if 92 - 92: iIii1I11I1II1
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 47 - 47: Oo0Ooo + Oo0Ooo * ooOoO0o - OoOoOO00 + II111iiii
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
  if 10 - 10: II111iiii / ooOoO0o . Ii1I / I1Ii111 / oO0o
  if 8 - 8: OOooOOo / ooOoO0o * I11i + OOooOOo * i1IIi
  if 48 - 48: o0oOOo0O0Ooo - I1ii11iIi11i / iII111i
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
  if 63 - 63: O0 - IiII . OOooOOo % IiII . I1IiiI / oO0o
  if 79 - 79: OoOoOO00
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 88 - 88: oO0o * o0oOOo0O0Ooo
  if 5 - 5: I11i - I1Ii111 * I11i - II111iiii + OOooOOo + II111iiii
 def print_flags ( self , html ) :
  if ( html == False ) :
   Oo0Ooo0O0 = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # Oo0Ooo * OOooOOo / OoOoOO00 + IiII - i1IIi - O0
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   I11ii1i1I = self . print_flags ( False )
   I11ii1i1I = I11ii1i1I . split ( "-" )
   Oo0Ooo0O0 = ""
   for IiiO0OOoo in I11ii1i1I :
    OOOOoo0o = lisp_site_flags [ IiiO0OOoo . upper ( ) ]
    OOOOoo0o = OOOOoo0o . format ( "" if IiiO0OOoo . isupper ( ) else "not " )
    Oo0Ooo0O0 += lisp_span ( IiiO0OOoo , OOOOoo0o )
    if ( IiiO0OOoo . lower ( ) != "n" ) : Oo0Ooo0O0 += "-"
    if 25 - 25: OoooooooOO % I1ii11iIi11i % Oo0Ooo % i11iIiiIii
    if 8 - 8: O0 - O0 % Ii1I
  return ( Oo0Ooo0O0 )
  if 22 - 22: OoOoOO00
  if 85 - 85: II111iiii - II111iiii
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 95 - 95: II111iiii + II111iiii + iII111i
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 38 - 38: OoO0O00 * Ii1I * O0 / I1IiiI
  if 99 - 99: Oo0Ooo + ooOoO0o - I1ii11iIi11i + I1Ii111 + Ii1I * I1IiiI
 def build_sort_key ( self ) :
  o0Oo0O0 = lisp_cache ( )
  o00O0Oo , ii1i1I1111ii = o0Oo0O0 . build_key ( self . eid )
  i1i11i111i1I1 = ""
  if ( self . group . is_null ( ) == False ) :
   o0o0oOo00Oo , i1i11i111i1I1 = o0Oo0O0 . build_key ( self . group )
   i1i11i111i1I1 = "-" + i1i11i111i1I1 [ 0 : 12 ] + "-" + str ( o0o0oOo00Oo ) + "-" + i1i11i111i1I1 [ 12 : : ]
   if 32 - 32: IiII % OOooOOo . Ii1I
  ii1i1I1111ii = ii1i1I1111ii [ 0 : 12 ] + "-" + str ( o00O0Oo ) + "-" + ii1i1I1111ii [ 12 : : ] + i1i11i111i1I1
  del ( o0Oo0O0 )
  return ( ii1i1I1111ii )
  if 27 - 27: o0oOOo0O0Ooo
  if 73 - 73: i11iIiiIii % II111iiii - Ii1I . IiII
 def merge_in_site_eid ( self , child ) :
  oOooOoOooOO = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   oOooOoOooOO = self . merge_rles_in_site_eid ( )
   if 98 - 98: o0oOOo0O0Ooo - OoO0O00 . I1ii11iIi11i / OOooOOo
   if 43 - 43: I1IiiI + OOooOOo + o0oOOo0O0Ooo
   if 44 - 44: o0oOOo0O0Ooo % OoO0O00 . OoooooooOO
   if 21 - 21: Oo0Ooo * Oo0Ooo - iII111i - O0
   if 87 - 87: OOooOOo / I1Ii111 - Ii1I + O0 - oO0o - O0
   if 68 - 68: iII111i + II111iiii + I1ii11iIi11i * OOooOOo / oO0o
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 41 - 41: OOooOOo + Oo0Ooo % I1IiiI
  return ( oOooOoOooOO )
  if 3 - 3: ooOoO0o * Ii1I
  if 29 - 29: OoooooooOO + OOooOOo
 def copy_rloc_records ( self ) :
  Ooo0O0 = [ ]
  for iIII in self . registered_rlocs :
   Ooo0O0 . append ( copy . deepcopy ( iIII ) )
   if 47 - 47: OoO0O00
  return ( Ooo0O0 )
  if 98 - 98: OoooooooOO - oO0o / O0
  if 23 - 23: o0oOOo0O0Ooo % OoooooooOO % iIii1I11I1II1 / OoOoOO00 / I1Ii111
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for oO00Oooo0o0o0 in self . individual_registrations . values ( ) :
   if ( self . site_id != oO00Oooo0o0o0 . site_id ) : continue
   if ( oO00Oooo0o0o0 . registered == False ) : continue
   self . registered_rlocs += oO00Oooo0o0o0 . copy_rloc_records ( )
   if 6 - 6: Oo0Ooo
   if 70 - 70: iIii1I11I1II1 * I1ii11iIi11i
   if 17 - 17: Ii1I * i1IIi % OoO0O00
   if 12 - 12: I1ii11iIi11i
   if 86 - 86: iIii1I11I1II1 % iII111i
   if 80 - 80: Oo0Ooo
  Ooo0O0 = [ ]
  for iIII in self . registered_rlocs :
   if ( iIII . rloc . is_null ( ) or len ( Ooo0O0 ) == 0 ) :
    Ooo0O0 . append ( iIII )
    continue
    if 37 - 37: i11iIiiIii - I1Ii111
   for Iii1 in Ooo0O0 :
    if ( Iii1 . rloc . is_null ( ) ) : continue
    if ( iIII . rloc . is_exact_match ( Iii1 . rloc ) ) : break
    if 38 - 38: O0 % I11i - I11i / iIii1I11I1II1 - II111iiii
   if ( Iii1 == Ooo0O0 [ - 1 ] ) : Ooo0O0 . append ( iIII )
   if 13 - 13: II111iiii * OoO0O00 - iIii1I11I1II1
  self . registered_rlocs = Ooo0O0
  if 30 - 30: O0 - O0 - I1Ii111
  if 88 - 88: o0oOOo0O0Ooo % I1Ii111
  if 4 - 4: i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
  if 87 - 87: I1Ii111 % i11iIiiIii + O0
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 67 - 67: OoooooooOO / i1IIi / ooOoO0o . i1IIi - i11iIiiIii . i1IIi
  if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
 def merge_rles_in_site_eid ( self ) :
  if 15 - 15: I1ii11iIi11i
  if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
  if 56 - 56: I1IiiI . ooOoO0o
  if 35 - 35: iIii1I11I1II1 % Oo0Ooo + o0oOOo0O0Ooo * o0oOOo0O0Ooo % ooOoO0o
  II1iI = { }
  for iIII in self . registered_rlocs :
   if ( iIII . rle == None ) : continue
   for iIIII1iiIII in iIII . rle . rle_nodes :
    IiiIIi1 = iIIII1iiIII . address . print_address_no_iid ( )
    II1iI [ IiiIIi1 ] = iIIII1iiIII . address
    if 26 - 26: OoooooooOO / ooOoO0o - iII111i / OoO0O00 . O0 * OOooOOo
   break
   if 85 - 85: iIii1I11I1II1 + iII111i + iII111i - ooOoO0o * OoO0O00
   if 80 - 80: i11iIiiIii / OOooOOo . OoooooooOO % I11i - iII111i * iIii1I11I1II1
   if 70 - 70: Oo0Ooo
   if 75 - 75: I1Ii111
   if 40 - 40: OoO0O00 % Oo0Ooo / OoooooooOO / i11iIiiIii
  self . merge_rlocs_in_site_eid ( )
  if 5 - 5: O0 % i11iIiiIii
  if 60 - 60: I1ii11iIi11i / I11i
  if 100 - 100: I1IiiI
  if 44 - 44: iIii1I11I1II1 + Oo0Ooo - I1Ii111 . OoooooooOO
  if 28 - 28: Ii1I + OOooOOo % IiII . i11iIiiIii - I1IiiI * Oo0Ooo
  if 2 - 2: I11i * I1ii11iIi11i + O0
  if 44 - 44: iIii1I11I1II1 / II111iiii - ooOoO0o
  if 10 - 10: OOooOOo
  OO0O0ooOoOoo0 = [ ]
  for iIII in self . registered_rlocs :
   if ( self . registered_rlocs . index ( iIII ) == 0 ) :
    OO0O0ooOoOoo0 . append ( iIII )
    continue
    if 73 - 73: OoOoOO00
   if ( iIII . rle == None ) : OO0O0ooOoOoo0 . append ( iIII )
   if 42 - 42: I1ii11iIi11i - iIii1I11I1II1 . Ii1I % OoO0O00 % i11iIiiIii * i11iIiiIii
  self . registered_rlocs = OO0O0ooOoOoo0
  if 86 - 86: Oo0Ooo % iIii1I11I1II1 . II111iiii / I11i % OoO0O00 % OoO0O00
  if 40 - 40: o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo * i1IIi
  if 94 - 94: oO0o - II111iiii + OoOoOO00
  if 90 - 90: Oo0Ooo + Oo0Ooo + I1Ii111
  if 81 - 81: i1IIi % iIii1I11I1II1 % Ii1I * ooOoO0o % i1IIi * I1IiiI
  if 15 - 15: ooOoO0o
  if 26 - 26: IiII % ooOoO0o / OOooOOo
  i1I1Ii11II1i = lisp_rle ( "" )
  iiIIi = { }
  IiIi1I1i1iII = None
  for oO00Oooo0o0o0 in self . individual_registrations . values ( ) :
   if ( oO00Oooo0o0o0 . registered == False ) : continue
   oOOooOoOO = oO00Oooo0o0o0 . registered_rlocs [ 0 ] . rle
   if ( oOOooOoOO == None ) : continue
   if 23 - 23: OoOoOO00 / i11iIiiIii % OoOoOO00
   IiIi1I1i1iII = oO00Oooo0o0o0 . registered_rlocs [ 0 ] . rloc_name
   for OOOII11i in oOOooOoOO . rle_nodes :
    IiiIIi1 = OOOII11i . address . print_address_no_iid ( )
    if ( iiIIi . has_key ( IiiIIi1 ) ) : break
    if 97 - 97: I1Ii111
    iIIII1iiIII = lisp_rle_node ( )
    iIIII1iiIII . address . copy_address ( OOOII11i . address )
    iIIII1iiIII . level = OOOII11i . level
    iIIII1iiIII . rloc_name = IiIi1I1i1iII
    i1I1Ii11II1i . rle_nodes . append ( iIIII1iiIII )
    iiIIi [ IiiIIi1 ] = OOOII11i . address
    if 98 - 98: I11i
    if 61 - 61: iIii1I11I1II1 * iII111i
    if 67 - 67: i11iIiiIii - Ii1I / Ii1I . iII111i
    if 36 - 36: oO0o + Oo0Ooo * I1Ii111 % OOooOOo . Oo0Ooo . I1IiiI
    if 81 - 81: o0oOOo0O0Ooo . OoOoOO00 . i11iIiiIii
    if 13 - 13: i1IIi
  if ( len ( i1I1Ii11II1i . rle_nodes ) == 0 ) : i1I1Ii11II1i = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = i1I1Ii11II1i
   if ( IiIi1I1i1iII ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 70 - 70: O0 / II111iiii
   if 98 - 98: OoOoOO00 - O0 . O0 + ooOoO0o * iIii1I11I1II1
   if 7 - 7: IiII * OoOoOO00 + iIii1I11I1II1 / OoOoOO00 + Oo0Ooo / o0oOOo0O0Ooo
   if 77 - 77: i1IIi . I1IiiI
   if 59 - 59: O0 + OoooooooOO - i1IIi
  if ( II1iI . keys ( ) == iiIIi . keys ( ) ) : return ( False )
  if 87 - 87: IiII * OoooooooOO / Oo0Ooo % iIii1I11I1II1 % oO0o
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # iII111i * O0 * II111iiii / i11iIiiIii * O0 + I1Ii111
 II1iI . keys ( ) , iiIIi . keys ( ) ) )
  if 42 - 42: iIii1I11I1II1
  return ( True )
  if 35 - 35: I1ii11iIi11i / OoOoOO00 / i1IIi / i11iIiiIii * iIii1I11I1II1 / i1IIi
  if 69 - 69: OOooOOo / I1Ii111 * II111iiii
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   o00Ii = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( o00Ii == None ) :
    o00Ii = lisp_site_eid ( self . site )
    o00Ii . eid . copy_address ( self . group )
    o00Ii . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , o00Ii )
    if 88 - 88: OOooOOo - I1IiiI + Oo0Ooo
    if 15 - 15: I11i / I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
    if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
    if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
    if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
    o00Ii . parent_for_more_specifics = self . parent_for_more_specifics
    if 8 - 8: OoooooooOO
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( o00Ii . group )
   o00Ii . add_source_entry ( self )
   if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
   if 83 - 83: o0oOOo0O0Ooo * Ii1I - Oo0Ooo * iII111i - i11iIiiIii
   if 6 - 6: I1IiiI + i11iIiiIii + O0 / i1IIi
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   o00Ii = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( o00Ii == None ) : return
   if 50 - 50: iII111i . II111iiii % I1Ii111 % I1IiiI / o0oOOo0O0Ooo . I1IiiI
   oO00Oooo0o0o0 = o00Ii . lookup_source_cache ( self . eid , True )
   if ( oO00Oooo0o0o0 == None ) : return
   if 76 - 76: OOooOOo % iII111i
   if ( o00Ii . source_cache == None ) : return
   if 80 - 80: iIii1I11I1II1 + o0oOOo0O0Ooo + iIii1I11I1II1
   o00Ii . source_cache . delete_cache ( self . eid )
   if ( o00Ii . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 63 - 63: OoOoOO00 - o0oOOo0O0Ooo % II111iiii - Ii1I
    if 81 - 81: iII111i % OOooOOo * oO0o
    if 84 - 84: iII111i - OoooooooOO + I1ii11iIi11i - I1IiiI
    if 52 - 52: oO0o / ooOoO0o / iII111i / OoOoOO00 * iIii1I11I1II1
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 74 - 74: oO0o . I1ii11iIi11i - iIii1I11I1II1
  if 73 - 73: OoO0O00 / O0 . o0oOOo0O0Ooo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 100 - 100: Ii1I . OoO0O00 % I1ii11iIi11i % O0 * Oo0Ooo - OoOoOO00
  if 15 - 15: OOooOOo - OOooOOo - OoooooooOO * OoO0O00
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 12 - 12: II111iiii * I1Ii111 / I1Ii111 * oO0o * Oo0Ooo
  if 17 - 17: OoOoOO00 % I1Ii111 / iII111i * I1Ii111
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 96 - 96: Oo0Ooo % o0oOOo0O0Ooo . OoOoOO00 % i11iIiiIii / OoooooooOO
  if 87 - 87: OoooooooOO - Ii1I . I11i / I1Ii111 . i1IIi
 def inherit_from_ams_parent ( self ) :
  i1II1 = self . parent_for_more_specifics
  if ( i1II1 == None ) : return
  self . force_proxy_reply = i1II1 . force_proxy_reply
  self . force_nat_proxy_reply = i1II1 . force_nat_proxy_reply
  self . force_ttl = i1II1 . force_ttl
  self . pitr_proxy_reply_drop = i1II1 . pitr_proxy_reply_drop
  self . proxy_reply_action = i1II1 . proxy_reply_action
  self . echo_nonce_capable = i1II1 . echo_nonce_capable
  self . policy = i1II1 . policy
  self . require_signature = i1II1 . require_signature
  if 86 - 86: i1IIi . oO0o % OOooOOo
  if 99 - 99: oO0o / I1Ii111 * oO0o * I11i
 def rtrs_in_rloc_set ( self ) :
  for iIII in self . registered_rlocs :
   if ( iIII . is_rtr ( ) ) : return ( True )
   if 38 - 38: o0oOOo0O0Ooo + OoOoOO00
  return ( False )
  if 24 - 24: Ii1I - OOooOOo - o0oOOo0O0Ooo - I1Ii111 / OoooooooOO
  if 17 - 17: OoO0O00
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for iIII in self . registered_rlocs :
   if ( iIII . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( iIII . is_rtr ( ) ) : return ( True )
   if 79 - 79: Ii1I - II111iiii
  return ( False )
  if 57 - 57: II111iiii / OoooooooOO
  if 4 - 4: I11i * OoOoOO00
 def is_rloc_in_rloc_set ( self , rloc ) :
  for iIII in self . registered_rlocs :
   if ( iIII . rle ) :
    for i1I1Ii11II1i in iIII . rle . rle_nodes :
     if ( i1I1Ii11II1i . address . is_exact_match ( rloc ) ) : return ( True )
     if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
     if 87 - 87: oO0o . I11i
   if ( iIII . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 15 - 15: oO0o
  return ( False )
  if 45 - 45: Oo0Ooo * IiII * OoO0O00 + iIii1I11I1II1
  if 89 - 89: IiII . IiII . oO0o % iII111i
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 27 - 27: OoOoOO00 + O0 % i1IIi - Oo0Ooo
  for iIII in prev_rloc_set :
   o00Oo00o0oO0 = iIII . rloc
   if ( self . is_rloc_in_rloc_set ( o00Oo00o0oO0 ) == False ) : return ( False )
   if 96 - 96: O0 % o0oOOo0O0Ooo + OOooOOo % I1IiiI
  return ( True )
  if 51 - 51: i1IIi . o0oOOo0O0Ooo % I1IiiI - OoooooooOO / OoOoOO00 - I11i
  if 45 - 45: O0 * II111iiii / i11iIiiIii
  if 38 - 38: OoooooooOO % i11iIiiIii - O0 / O0
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
   if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
  if 85 - 85: IiII / Ii1I - I1ii11iIi11i * OOooOOo
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 19 - 19: I1ii11iIi11i
  try :
   IIiiI = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   I11IiiIII1i1 = IIiiI [ 2 ]
  except :
   return
   if 15 - 15: II111iiii * O0 % I1ii11iIi11i % Ii1I . OoOoOO00
   if 8 - 8: IiII / Oo0Ooo % OOooOOo + O0 - Ii1I
   if 43 - 43: O0 % i11iIiiIii + o0oOOo0O0Ooo . I11i / OOooOOo . O0
   if 30 - 30: i11iIiiIii + i1IIi
   if 52 - 52: OoooooooOO % OoOoOO00 / IiII % OoO0O00
   if 36 - 36: II111iiii . O0 % O0 * iII111i * iIii1I11I1II1
  if ( len ( I11IiiIII1i1 ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 42 - 42: iII111i . OOooOOo + oO0o / OoOoOO00
   if 54 - 54: ooOoO0o % o0oOOo0O0Ooo + i11iIiiIii / ooOoO0o * II111iiii * Ii1I
  IiiIIi1 = I11IiiIII1i1 [ self . a_record_index ]
  if ( IiiIIi1 != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( IiiIIi1 )
   self . insert_mr ( )
   if 52 - 52: ooOoO0o + IiII * OoOoOO00 - OoO0O00 - OoooooooOO - oO0o
   if 60 - 60: iII111i / oO0o
   if 98 - 98: OoOoOO00 / OOooOOo
   if 31 - 31: II111iiii % I11i - I11i
   if 17 - 17: iII111i . IiII + OOooOOo % I1Ii111 % i11iIiiIii
   if 100 - 100: i11iIiiIii - O0 . OoO0O00 / O0 - Ii1I - IiII
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 72 - 72: Ii1I % O0 + II111iiii . i11iIiiIii
  for IiiIIi1 in I11IiiIII1i1 [ 1 : : ] :
   OO0o = lisp_address ( LISP_AFI_NONE , IiiIIi1 , 0 , 0 )
   O0o00000o0O = lisp_get_map_resolver ( OO0o , None )
   if ( O0o00000o0O != None and O0o00000o0O . a_record_index == I11IiiIII1i1 . index ( IiiIIi1 ) ) :
    continue
    if 66 - 66: II111iiii % I1IiiI
   O0o00000o0O = lisp_mr ( IiiIIi1 , None , None )
   O0o00000o0O . a_record_index = I11IiiIII1i1 . index ( IiiIIi1 )
   O0o00000o0O . dns_name = self . dns_name
   O0o00000o0O . last_dns_resolve = lisp_get_timestamp ( )
   if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 + I1Ii111 * OOooOOo . I1IiiI
   if 96 - 96: I1ii11iIi11i
   if 37 - 37: OoO0O00 % o0oOOo0O0Ooo * O0 * O0 + iII111i
   if 18 - 18: i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % oO0o * Ii1I / I1IiiI
   if 46 - 46: o0oOOo0O0Ooo . ooOoO0o / Ii1I
  O0ooo0oO00 = [ ]
  for O0o00000o0O in lisp_map_resolvers_list . values ( ) :
   if ( self . dns_name != O0o00000o0O . dns_name ) : continue
   OO0o = O0o00000o0O . map_resolver . print_address_no_iid ( )
   if ( OO0o in I11IiiIII1i1 ) : continue
   O0ooo0oO00 . append ( O0o00000o0O )
   if 86 - 86: I11i * ooOoO0o / O0 + i11iIiiIii
  for O0o00000o0O in O0ooo0oO00 : O0o00000o0O . delete_mr ( )
  if 18 - 18: OoooooooOO % OOooOOo + I1ii11iIi11i * I1Ii111 / OOooOOo / I1IiiI
  if 7 - 7: OOooOOo / OoOoOO00
 def insert_mr ( self ) :
  ii1i1I1111ii = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ ii1i1I1111ii ] = self
  if 93 - 93: iIii1I11I1II1 * Ii1I - iII111i
  if 94 - 94: iIii1I11I1II1 * iIii1I11I1II1 * I11i % i11iIiiIii
 def delete_mr ( self ) :
  ii1i1I1111ii = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( ii1i1I1111ii ) == False ) : return
  lisp_map_resolvers_list . pop ( ii1i1I1111ii )
  if 38 - 38: I1IiiI % I1ii11iIi11i * I1IiiI + OOooOOo - OoOoOO00
  if 78 - 78: OOooOOo + I1Ii111
  if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
  if 98 - 98: IiII
  if 75 - 75: OoooooooOO % IiII + Ii1I - i1IIi / OoooooooOO
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
  if 57 - 57: iII111i
  if 18 - 18: II111iiii % i11iIiiIii + I11i - OOooOOo
 def print_referral ( self , eid_indent , referral_indent ) :
  OOO0o = lisp_print_elapsed ( self . uptime )
  I1i11iiI1i = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , OOO0o ,
  # OoO0O00 % I11i * OoO0O00 / IiII / I1IiiI
 I1i11iiI1i , len ( self . referral_set ) ) )
  if 77 - 77: IiII / i1IIi + OOooOOo + Oo0Ooo % iII111i % OoOoOO00
  for ii in self . referral_set . values ( ) :
   ii . print_ref_node ( referral_indent )
   if 6 - 6: i11iIiiIii + ooOoO0o
   if 89 - 89: iIii1I11I1II1 . I1Ii111
   if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 59 - 59: IiII . OoO0O00 - OoooooooOO . O0
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 33 - 33: Ii1I
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 40 - 40: I1IiiI / OOooOOo * Ii1I
  if 98 - 98: I1IiiI
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 4 - 4: I1IiiI % O0 / Oo0Ooo / O0
  if 90 - 90: ooOoO0o - O0 . IiII - O0 . iIii1I11I1II1
 def print_ttl ( self ) :
  oo0o = self . referral_ttl
  if ( oo0o < 60 ) : return ( str ( oo0o ) + " secs" )
  if 42 - 42: I1ii11iIi11i
  if ( ( oo0o % 60 ) == 0 ) :
   oo0o = str ( oo0o / 60 ) + " mins"
  else :
   oo0o = str ( oo0o ) + " secs"
   if 51 - 51: iII111i % i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
  return ( oo0o )
  if 14 - 14: I1ii11iIi11i . OoO0O00
  if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # I11i % IiII
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 24 - 24: O0 % OOooOOo - OoooooooOO
  if 29 - 29: O0 + iII111i
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   o0ooo000OO = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( o0ooo000OO == None ) :
    o0ooo000OO = lisp_referral ( )
    o0ooo000OO . eid . copy_address ( self . group )
    o0ooo000OO . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , o0ooo000OO )
    if 4 - 4: I11i * I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( o0ooo000OO . group )
   o0ooo000OO . add_source_entry ( self )
   if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
   if 76 - 76: OoooooooOO - O0
   if 17 - 17: Oo0Ooo % I1Ii111 . oO0o - O0
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   o0ooo000OO = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( o0ooo000OO == None ) : return
   if 32 - 32: O0 % O0
   I11iiiIIi1Ii1 = o0ooo000OO . lookup_source_cache ( self . eid , True )
   if ( I11iiiIIi1Ii1 == None ) : return
   if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
   o0ooo000OO . source_cache . delete_cache ( self . eid )
   if ( o0ooo000OO . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 65 - 65: I1ii11iIi11i % ooOoO0o - OoOoOO00 + ooOoO0o + Oo0Ooo
    if 95 - 95: I1Ii111 * i11iIiiIii - I1IiiI - OoOoOO00 . ooOoO0o
    if 34 - 34: OoooooooOO % I1ii11iIi11i + OoooooooOO % i11iIiiIii / IiII - ooOoO0o
    if 74 - 74: iIii1I11I1II1 % II111iiii + IiII
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 71 - 71: I1IiiI / O0 * i1IIi . i1IIi + Oo0Ooo
  if 32 - 32: i1IIi * I1Ii111 % I1IiiI / IiII . I1Ii111
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 11 - 11: OOooOOo
  if 25 - 25: i1IIi
  if 99 - 99: OOooOOo + OoooooooOO . I1Ii111 * Oo0Ooo % oO0o
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 75 - 75: iII111i
  if 8 - 8: I1ii11iIi11i . I11i / I1ii11iIi11i - i1IIi
 def print_ref_node ( self , indent ) :
  Oo0OO0000oooo = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , Oo0OO0000oooo ,
  # OOooOOo . O0
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 52 - 52: oO0o . ooOoO0o - I1Ii111 + OoooooooOO
  if 86 - 86: I1ii11iIi11i - I1Ii111 + oO0o % II111iiii - i1IIi
  if 32 - 32: I1Ii111 % ooOoO0o + I1Ii111 / I1ii11iIi11i - o0oOOo0O0Ooo + ooOoO0o
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
   if 46 - 46: OoO0O00 % OoO0O00 . O0 + II111iiii
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
   if 42 - 42: OOooOOo * I1Ii111
   if 53 - 53: II111iiii % OOooOOo / I1ii11iIi11i * OoOoOO00 % I1ii11iIi11i * iII111i
   if 91 - 91: iII111i . OoooooooOO
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 90 - 90: i11iIiiIii - I1IiiI
  try :
   IIiiI = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   I11IiiIII1i1 = IIiiI [ 2 ]
  except :
   return
   if 39 - 39: iII111i % OoooooooOO % Ii1I % I1IiiI
   if 63 - 63: OoO0O00 - I1Ii111 - II111iiii
   if 79 - 79: II111iiii - II111iiii + OoOoOO00 / iII111i % OoooooooOO - OoO0O00
   if 22 - 22: o0oOOo0O0Ooo + I1Ii111 . Oo0Ooo
   if 84 - 84: O0 + I1IiiI % Oo0Ooo + OOooOOo
   if 94 - 94: OOooOOo
  if ( len ( I11IiiIII1i1 ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
   if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
  IiiIIi1 = I11IiiIII1i1 [ self . a_record_index ]
  if ( IiiIIi1 != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( IiiIIi1 )
   self . insert_ms ( )
   if 31 - 31: I11i . o0oOOo0O0Ooo
   if 82 - 82: I11i - Oo0Ooo
   if 77 - 77: I1IiiI + OoO0O00 % iIii1I11I1II1 - OOooOOo
   if 80 - 80: oO0o % I1ii11iIi11i * I1Ii111 + i1IIi
   if 79 - 79: oO0o + IiII
   if 4 - 4: iII111i + OoooooooOO / I1Ii111
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 57 - 57: I1IiiI . iIii1I11I1II1 % iII111i * iII111i / I1Ii111
  for IiiIIi1 in I11IiiIII1i1 [ 1 : : ] :
   OO0o = lisp_address ( LISP_AFI_NONE , IiiIIi1 , 0 , 0 )
   o00oO0Oo = lisp_get_map_server ( OO0o )
   if ( o00oO0Oo != None and o00oO0Oo . a_record_index == I11IiiIII1i1 . index ( IiiIIi1 ) ) :
    continue
    if 30 - 30: O0 / I11i % OoOoOO00 * I1Ii111 / O0 % ooOoO0o
   o00oO0Oo = copy . deepcopy ( self )
   o00oO0Oo . map_server . store_address ( IiiIIi1 )
   o00oO0Oo . a_record_index = I11IiiIII1i1 . index ( IiiIIi1 )
   o00oO0Oo . last_dns_resolve = lisp_get_timestamp ( )
   o00oO0Oo . insert_ms ( )
   if 36 - 36: iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
   if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
   if 97 - 97: i11iIiiIii / O0 % OoO0O00
   if 88 - 88: i1IIi . I1IiiI
   if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
  O0ooo0oO00 = [ ]
  for o00oO0Oo in lisp_map_servers_list . values ( ) :
   if ( self . dns_name != o00oO0Oo . dns_name ) : continue
   OO0o = o00oO0Oo . map_server . print_address_no_iid ( )
   if ( OO0o in I11IiiIII1i1 ) : continue
   O0ooo0oO00 . append ( o00oO0Oo )
   if 51 - 51: oO0o + Ii1I * Ii1I * I1ii11iIi11i % I11i - I1ii11iIi11i
  for o00oO0Oo in O0ooo0oO00 : o00oO0Oo . delete_ms ( )
  if 15 - 15: i1IIi / OoO0O00 - Oo0Ooo
  if 74 - 74: o0oOOo0O0Ooo % Ii1I - II111iiii / ooOoO0o
 def insert_ms ( self ) :
  ii1i1I1111ii = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ ii1i1I1111ii ] = self
  if 84 - 84: I1IiiI + OOooOOo
  if 80 - 80: OOooOOo / OoOoOO00
 def delete_ms ( self ) :
  ii1i1I1111ii = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( ii1i1I1111ii ) == False ) : return
  lisp_map_servers_list . pop ( ii1i1I1111ii )
  if 93 - 93: OOooOOo
  if 82 - 82: iIii1I11I1II1 + OoO0O00 / iIii1I11I1II1 . iIii1I11I1II1
  if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
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
  if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
  if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
  if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
  if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
  if 91 - 91: II111iiii * o0oOOo0O0Ooo
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 20 - 20: iIii1I11I1II1 % Oo0Ooo * OoOoOO00 % IiII
  if 93 - 93: I11i * iIii1I11I1II1 * oO0o
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 74 - 74: I1IiiI
  if 39 - 39: iII111i * IiII / iII111i * IiII % I1ii11iIi11i
 def set_socket ( self , device ) :
  IiII1iiI = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  IiII1iiI . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   IiII1iiI . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   IiII1iiI . close ( )
   IiII1iiI = None
   if 27 - 27: iIii1I11I1II1 . ooOoO0o
  self . raw_socket = IiII1iiI
  if 74 - 74: i1IIi % OoOoOO00
  if 98 - 98: IiII * OOooOOo / O0 - I1Ii111 . I1Ii111 + OOooOOo
 def set_bridge_socket ( self , device ) :
  IiII1iiI = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   IiII1iiI = IiII1iiI . bind ( ( device , 0 ) )
   self . bridge_socket = IiII1iiI
  except :
   return
   if 61 - 61: iII111i * Ii1I % Ii1I + I1IiiI
   if 23 - 23: oO0o + I1Ii111 / OoooooooOO / O0 + IiII
   if 80 - 80: i11iIiiIii - OoooooooOO + II111iiii / i1IIi - oO0o
   if 100 - 100: Ii1I
class lisp_datetime ( ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 73 - 73: IiII - O0
  if 54 - 54: OOooOOo
 def valid_datetime ( self ) :
  Ii1IIIIi = self . datetime_name
  if ( Ii1IIIIi . find ( ":" ) == - 1 ) : return ( False )
  if ( Ii1IIIIi . find ( "-" ) == - 1 ) : return ( False )
  O0Oo00ooOoOo0 , ii11 , i1iiii111Iii , time = Ii1IIIIi [ 0 : 4 ] , Ii1IIIIi [ 5 : 7 ] , Ii1IIIIi [ 8 : 10 ] , Ii1IIIIi [ 11 : : ]
  if 25 - 25: I11i % Ii1I
  if ( ( O0Oo00ooOoOo0 + ii11 + i1iiii111Iii ) . isdigit ( ) == False ) : return ( False )
  if ( ii11 < "01" and ii11 > "12" ) : return ( False )
  if ( i1iiii111Iii < "01" and i1iiii111Iii > "31" ) : return ( False )
  if 13 - 13: iIii1I11I1II1 - I1IiiI % o0oOOo0O0Ooo * iIii1I11I1II1
  oooo0 , o0oOooo , I111IiiIiiiII = time . split ( ":" )
  if 69 - 69: IiII
  if ( ( oooo0 + o0oOooo + I111IiiIiiiII ) . isdigit ( ) == False ) : return ( False )
  if ( oooo0 < "00" and oooo0 > "23" ) : return ( False )
  if ( o0oOooo < "00" and o0oOooo > "59" ) : return ( False )
  if ( I111IiiIiiiII < "00" and I111IiiIiiiII > "59" ) : return ( False )
  return ( True )
  if 47 - 47: O0 - i11iIiiIii + iII111i . I11i
  if 84 - 84: I1IiiI
 def parse_datetime ( self ) :
  oOO = self . datetime_name
  oOO = oOO . replace ( "-" , "" )
  oOO = oOO . replace ( ":" , "" )
  self . datetime = int ( oOO )
  if 6 - 6: I1Ii111 . ooOoO0o * I1Ii111 % iIii1I11I1II1 - i11iIiiIii
  if 27 - 27: oO0o * i11iIiiIii . o0oOOo0O0Ooo
 def now ( self ) :
  Oo0OO0000oooo = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  Oo0OO0000oooo = lisp_datetime ( Oo0OO0000oooo )
  return ( Oo0OO0000oooo )
  if 64 - 64: Ii1I / OOooOOo . i1IIi - Oo0Ooo + oO0o
  if 71 - 71: ooOoO0o
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 32 - 32: OoOoOO00 % IiII % OoO0O00
  if 95 - 95: ooOoO0o
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 47 - 47: I1IiiI * i11iIiiIii / I1IiiI / iIii1I11I1II1 - Ii1I
  if 25 - 25: oO0o / i11iIiiIii + i11iIiiIii % IiII - o0oOOo0O0Ooo
 def past ( self ) :
  return ( self . future ( ) == False )
  if 97 - 97: I1ii11iIi11i % iII111i * ooOoO0o % OOooOOo . I1IiiI - i11iIiiIii
  if 2 - 2: IiII . o0oOOo0O0Ooo % II111iiii
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 69 - 69: Ii1I
  if 75 - 75: I1IiiI
 def this_year ( self ) :
  OoooOOoOo = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  Oo0OO0000oooo = str ( self . datetime ) [ 0 : 4 ]
  return ( Oo0OO0000oooo == OoooOOoOo )
  if 91 - 91: I11i + Ii1I / iII111i % iIii1I11I1II1 . o0oOOo0O0Ooo + I1IiiI
  if 25 - 25: i1IIi * o0oOOo0O0Ooo
 def this_month ( self ) :
  OoooOOoOo = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  Oo0OO0000oooo = str ( self . datetime ) [ 0 : 6 ]
  return ( Oo0OO0000oooo == OoooOOoOo )
  if 82 - 82: oO0o
  if 42 - 42: OoooooooOO - ooOoO0o . OoooooooOO
 def today ( self ) :
  OoooOOoOo = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  Oo0OO0000oooo = str ( self . datetime ) [ 0 : 8 ]
  return ( Oo0OO0000oooo == OoooOOoOo )
  if 77 - 77: I1IiiI
  if 16 - 16: I1IiiI + ooOoO0o - O0 / o0oOOo0O0Ooo
  if 36 - 36: Oo0Ooo - OoOoOO00 - II111iiii
  if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
  if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
  if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
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
  if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
  if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
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
  if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
  if 92 - 92: I11i
 def match_policy_map_request ( self , mr , srloc ) :
  for IIiiiIiii in self . match_clauses :
   III1I1Iii1 = IIiiiIiii . source_eid
   Ii1i11iIi1iII = mr . source_eid
   if ( III1I1Iii1 and Ii1i11iIi1iII and Ii1i11iIi1iII . is_more_specific ( III1I1Iii1 ) == False ) : continue
   if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
   III1I1Iii1 = IIiiiIiii . dest_eid
   Ii1i11iIi1iII = mr . target_eid
   if ( III1I1Iii1 and Ii1i11iIi1iII and Ii1i11iIi1iII . is_more_specific ( III1I1Iii1 ) == False ) : continue
   if 98 - 98: iII111i % IiII + OoO0O00
   III1I1Iii1 = IIiiiIiii . source_rloc
   Ii1i11iIi1iII = srloc
   if ( III1I1Iii1 and Ii1i11iIi1iII and Ii1i11iIi1iII . is_more_specific ( III1I1Iii1 ) == False ) : continue
   I1111III111ii = IIiiiIiii . datetime_lower
   i11iI1iIiI = IIiiiIiii . datetime_upper
   if ( I1111III111ii and i11iI1iIiI and I1111III111ii . now_in_range ( i11iI1iIiI ) == False ) : continue
   return ( True )
   if 90 - 90: I1IiiI * II111iiii + O0
  return ( False )
  if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
  if 88 - 88: Oo0Ooo . iII111i
 def set_policy_map_reply ( self ) :
  O000Oo = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( O000Oo ) : return ( None )
  if 22 - 22: Oo0Ooo + O0 + OoO0O00
  oOo00O = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   oOo00O . rloc . copy_address ( self . set_rloc_address )
   IiiIIi1 = oOo00O . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( IiiIIi1 ) )
   if 83 - 83: i1IIi + OoooooooOO * IiII
  if ( self . set_rloc_record_name ) :
   oOo00O . rloc_name = self . set_rloc_record_name
   oO00 = blue ( oOo00O . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( oO00 ) )
   if 65 - 65: II111iiii / I1Ii111 + I1IiiI - OoooooooOO + ooOoO0o - I1ii11iIi11i
  if ( self . set_geo_name ) :
   oOo00O . geo_name = self . set_geo_name
   oO00 = oOo00O . geo_name
   iIi1I = "" if lisp_geo_list . has_key ( oO00 ) else "(not configured)"
   if 95 - 95: ooOoO0o
   lprint ( "Policy set-geo-name '{}' {}" . format ( oO00 , iIi1I ) )
   if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
  if ( self . set_elp_name ) :
   oOo00O . elp_name = self . set_elp_name
   oO00 = oOo00O . elp_name
   iIi1I = "" if lisp_elp_list . has_key ( oO00 ) else "(not configured)"
   if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
   lprint ( "Policy set-elp-name '{}' {}" . format ( oO00 , iIi1I ) )
   if 32 - 32: OoOoOO00 % i11iIiiIii
  if ( self . set_rle_name ) :
   oOo00O . rle_name = self . set_rle_name
   oO00 = oOo00O . rle_name
   iIi1I = "" if lisp_rle_list . has_key ( oO00 ) else "(not configured)"
   if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
   lprint ( "Policy set-rle-name '{}' {}" . format ( oO00 , iIi1I ) )
   if 44 - 44: I1Ii111 + ooOoO0o
  if ( self . set_json_name ) :
   oOo00O . json_name = self . set_json_name
   oO00 = oOo00O . json_name
   iIi1I = "" if lisp_json_list . has_key ( oO00 ) else "(not configured)"
   if 15 - 15: I11i + OoO0O00 + OoOoOO00
   lprint ( "Policy set-json-name '{}' {}" . format ( oO00 , iIi1I ) )
   if 100 - 100: I1Ii111
  return ( oOo00O )
  if 78 - 78: OoOoOO00
  if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 36 - 36: OoOoOO00 * II111iiii . OoooooooOO * I11i . I11i
  if 13 - 13: I1ii11iIi11i * II111iiii
  if 93 - 93: OOooOOo / O0 - o0oOOo0O0Ooo + OoO0O00 * I1IiiI
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  if 53 - 53: I1ii11iIi11i
  if 91 - 91: o0oOOo0O0Ooo - I1ii11iIi11i . i1IIi
 def add ( self , eid_prefix ) :
  oo0o = self . ttl
  OOo0O0O0o0 = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( OOo0O0O0o0 ) == False ) :
   lisp_pubsub_cache [ OOo0O0O0o0 ] = { }
   if 64 - 64: ooOoO0o
  o0oo0O = lisp_pubsub_cache [ OOo0O0O0o0 ]
  if 23 - 23: Oo0Ooo . OoO0O00
  iI1i1iIIIII = "Add"
  if ( o0oo0O . has_key ( self . xtr_id ) ) :
   iI1i1iIIIII = "Replace"
   del ( o0oo0O [ self . xtr_id ] )
   if 19 - 19: oO0o - I1ii11iIi11i + iII111i . o0oOOo0O0Ooo . OoO0O00 * Oo0Ooo
  o0oo0O [ self . xtr_id ] = self
  if 39 - 39: i11iIiiIii - iII111i / O0 % Oo0Ooo
  OOo0O0O0o0 = green ( OOo0O0O0o0 , False )
  III1iii1 = red ( self . itr . print_address_no_iid ( ) , False )
  oooOOOO0oOo = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( iI1i1iIIIII , OOo0O0O0o0 ,
 III1iii1 , oooOOOO0oOo , oo0o ) )
  if 40 - 40: O0 * Oo0Ooo % o0oOOo0O0Ooo / OoooooooOO
  if 94 - 94: iII111i
 def delete ( self , eid_prefix ) :
  OOo0O0O0o0 = eid_prefix . print_prefix ( )
  III1iii1 = red ( self . itr . print_address_no_iid ( ) , False )
  oooOOOO0oOo = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( OOo0O0O0o0 ) ) :
   o0oo0O = lisp_pubsub_cache [ OOo0O0O0o0 ]
   if ( o0oo0O . has_key ( self . xtr_id ) ) :
    o0oo0O . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( OOo0O0O0o0 ,
 III1iii1 , oooOOOO0oOo ) )
    if 79 - 79: o0oOOo0O0Ooo / I1ii11iIi11i . iII111i . II111iiii + I1ii11iIi11i * I11i
    if 49 - 49: Ii1I * OoooooooOO * i1IIi % OoOoOO00
    if 83 - 83: iIii1I11I1II1 - i1IIi - Ii1I % iII111i
    if 69 - 69: I1Ii111 * oO0o * I1IiiI
    if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
    if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
    if 52 - 52: OoooooooOO
    if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
    if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
    if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
    if 86 - 86: Oo0Ooo / OoO0O00
    if 78 - 78: I1IiiI * I1IiiI
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
class lisp_trace ( ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
  if 24 - 24: ooOoO0o % I1Ii111 + OoO0O00 * o0oOOo0O0Ooo % O0 - i11iIiiIii
 def print_trace ( self ) :
  iIIIOOOO0 = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( iIIIOOOO0 ) )
  if 38 - 38: IiII / Ii1I % II111iiii
  if 56 - 56: ooOoO0o - OoooooooOO - i11iIiiIii
 def encode ( self ) :
  ooo0OOoo = socket . htonl ( 0x90000000 )
  IIii1i = struct . pack ( "II" , ooo0OOoo , 0 )
  IIii1i += struct . pack ( "Q" , self . nonce )
  IIii1i += json . dumps ( self . packet_json )
  return ( IIii1i )
  if 27 - 27: Ii1I . OoOoOO00 % oO0o % o0oOOo0O0Ooo / i11iIiiIii - iIii1I11I1II1
  if 77 - 77: o0oOOo0O0Ooo . OoOoOO00 % Ii1I
 def decode ( self , packet ) :
  O00oO00oOO00O = "I"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( False )
  ooo0OOoo = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  ooo0OOoo = socket . ntohl ( ooo0OOoo )
  if ( ( ooo0OOoo & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 94 - 94: I11i / IiII - OoOoOO00 % OoO0O00 % i11iIiiIii . Ii1I
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( False )
  IiiIIi1 = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if 26 - 26: i1IIi - Ii1I * I1IiiI
  IiiIIi1 = socket . ntohl ( IiiIIi1 )
  OO0O0o0Oo0o0 = IiiIIi1 >> 24
  ii1IIi11II1i = ( IiiIIi1 >> 16 ) & 0xff
  OOooO = ( IiiIIi1 >> 8 ) & 0xff
  Ii1II111i1 = IiiIIi1 & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( OO0O0o0Oo0o0 , ii1IIi11II1i , OOooO , Ii1II111i1 )
  self . local_port = str ( ooo0OOoo & 0xffff )
  if 95 - 95: i11iIiiIii / I1IiiI + OOooOOo / I1ii11iIi11i
  O00oO00oOO00O = "Q"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( False )
  self . nonce = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 10 - 10: IiII + o0oOOo0O0Ooo + I11i % O0 % I1Ii111
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 85 - 85: O0 % OoOoOO00 . I1ii11iIi11i
  return ( True )
  if 46 - 46: OOooOOo * iIii1I11I1II1
  if 33 - 33: OoO0O00 * II111iiii / i1IIi
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 93 - 93: I1Ii111 % I11i
  if 64 - 64: I1IiiI % OoOoOO00 / Oo0Ooo
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  oOo00O , IiI1iI1 = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( oOo00O == None ) :
   oOo00O , IiI1iI1 = rts_rloc . split ( ":" )
   IiI1iI1 = int ( IiI1iI1 )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( oOo00O , IiI1iI1 ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( oOo00O ,
 IiI1iI1 ) )
   if 40 - 40: Ii1I + iIii1I11I1II1 / oO0o . II111iiii % O0 - IiII
   if 49 - 49: IiII - OOooOOo * OOooOOo . O0
  if ( lisp_socket == None ) :
   IiII1iiI = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   IiII1iiI . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   IiII1iiI . sendto ( packet , ( oOo00O , IiI1iI1 ) )
   IiII1iiI . close ( )
  else :
   lisp_socket . sendto ( packet , ( oOo00O , IiI1iI1 ) )
   if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
   if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
   if 61 - 61: OoO0O00
 def packet_length ( self ) :
  o0oOo00 = 8 ; o0oo0Oo = 4 + 4 + 8
  return ( o0oOo00 + o0oo0Oo + len ( json . dumps ( self . packet_json ) ) )
  if 55 - 55: OoO0O00 . Oo0Ooo + iII111i % OoO0O00 * O0
  if 37 - 37: OOooOOo
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  ii1i1I1111ii = self . local_rloc + ":" + self . local_port
  i11II = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ ii1i1I1111ii ] = i11II
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( ii1i1I1111ii , i11II ) )
  if 100 - 100: Oo0Ooo * I1IiiI . ooOoO0o
  if 53 - 53: OOooOOo + o0oOOo0O0Ooo * Ii1I + O0
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  ii1i1I1111ii = local_rloc_and_port
  try : i11II = lisp_rtr_nat_trace_cache [ ii1i1I1111ii ]
  except : i11II = ( None , None )
  return ( i11II )
  if 75 - 75: OoooooooOO
  if 24 - 24: I1Ii111 % i11iIiiIii % oO0o . OOooOOo % IiII
  if 23 - 23: o0oOOo0O0Ooo * II111iiii - Oo0Ooo - I1IiiI
  if 86 - 86: I1IiiI - II111iiii * II111iiii * oO0o % OoooooooOO * OoOoOO00
  if 93 - 93: I1IiiI + OoO0O00 % O0 - ooOoO0o * i1IIi
  if 60 - 60: I1IiiI
  if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
  if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
  if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
  if 17 - 17: OOooOOo / i11iIiiIii - i11iIiiIii . II111iiii . ooOoO0o
  if 38 - 38: OOooOOo . OoooooooOO . II111iiii + OoO0O00 / oO0o . OoooooooOO
def lisp_get_map_server ( address ) :
 for o00oO0Oo in lisp_map_servers_list . values ( ) :
  if ( o00oO0Oo . map_server . is_exact_match ( address ) ) : return ( o00oO0Oo )
  if 100 - 100: OoO0O00
 return ( None )
 if 36 - 36: oO0o + Ii1I - O0
 if 19 - 19: O0 + I1Ii111 . I1Ii111 * IiII * ooOoO0o + i1IIi
 if 51 - 51: ooOoO0o % OoOoOO00 % i1IIi / O0
 if 11 - 11: OOooOOo . I1ii11iIi11i * OOooOOo * OoO0O00
 if 11 - 11: I11i
 if 85 - 85: OoOoOO00 - Ii1I / Oo0Ooo % I1ii11iIi11i
 if 12 - 12: i1IIi + o0oOOo0O0Ooo / oO0o . O0
def lisp_get_any_map_server ( ) :
 for o00oO0Oo in lisp_map_servers_list . values ( ) : return ( o00oO0Oo )
 return ( None )
 if 37 - 37: IiII
 if 99 - 99: i11iIiiIii % i11iIiiIii . I11i * I1ii11iIi11i . OoO0O00 / I1IiiI
 if 44 - 44: iII111i - OoO0O00 / i11iIiiIii
 if 55 - 55: O0 * OoO0O00 * i1IIi
 if 9 - 9: IiII
 if 64 - 64: ooOoO0o + OoooooooOO
 if 99 - 99: iIii1I11I1II1 * II111iiii * i11iIiiIii
 if 10 - 10: OOooOOo
 if 75 - 75: I11i * ooOoO0o * Oo0Ooo . i1IIi . ooOoO0o . ooOoO0o
 if 24 - 24: iIii1I11I1II1
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  IiiIIi1 = address . print_address ( )
  O0o00000o0O = None
  for ii1i1I1111ii in lisp_map_resolvers_list :
   if ( ii1i1I1111ii . find ( IiiIIi1 ) == - 1 ) : continue
   O0o00000o0O = lisp_map_resolvers_list [ ii1i1I1111ii ]
   if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
  return ( O0o00000o0O )
  if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
  if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
  if 62 - 62: o0oOOo0O0Ooo
  if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
  if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
  if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
  if 84 - 84: OoOoOO00
 if ( eid == "" ) :
  oO0oo00OO = ""
 elif ( eid == None ) :
  oO0oo00OO = "all"
 else :
  Ooooo00 = lisp_db_for_lookups . lookup_cache ( eid , False )
  oO0oo00OO = "all" if Ooooo00 == None else Ooooo00 . use_mr_name
  if 52 - 52: I11i % I1Ii111 % i11iIiiIii
  if 84 - 84: I1IiiI % II111iiii + Oo0Ooo + OoOoOO00 + Oo0Ooo . I1Ii111
 ooo00o0 = None
 for O0o00000o0O in lisp_map_resolvers_list . values ( ) :
  if ( oO0oo00OO == "" ) : return ( O0o00000o0O )
  if ( O0o00000o0O . mr_name != oO0oo00OO ) : continue
  if ( ooo00o0 == None or O0o00000o0O . last_used < ooo00o0 . last_used ) : ooo00o0 = O0o00000o0O
  if 38 - 38: II111iiii * IiII * OoooooooOO + IiII
 return ( ooo00o0 )
 if 7 - 7: iIii1I11I1II1
 if 35 - 35: IiII + O0 % I1Ii111 - I1ii11iIi11i - i1IIi
 if 100 - 100: I1Ii111 + i11iIiiIii - IiII / I1ii11iIi11i / iII111i
 if 56 - 56: iII111i
 if 91 - 91: Oo0Ooo . I11i . I1ii11iIi11i
 if 60 - 60: i11iIiiIii - OOooOOo
 if 78 - 78: I1IiiI * ooOoO0o % iIii1I11I1II1 / I1ii11iIi11i
 if 61 - 61: I1Ii111 . Ii1I + OoooooooOO
def lisp_get_decent_map_resolver ( eid ) :
 ooo = lisp_get_decent_index ( eid )
 OOIIi1Iii1I = str ( ooo ) + "." + lisp_decent_dns_suffix
 if 100 - 100: I1ii11iIi11i - I1IiiI
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( OOIIi1Iii1I , False ) , eid . print_prefix ( ) ) )
 if 58 - 58: Ii1I / Oo0Ooo % IiII
 if 33 - 33: II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % i11iIiiIii
 ooo00o0 = None
 for O0o00000o0O in lisp_map_resolvers_list . values ( ) :
  if ( OOIIi1Iii1I != O0o00000o0O . dns_name ) : continue
  if ( ooo00o0 == None or O0o00000o0O . last_used < ooo00o0 . last_used ) : ooo00o0 = O0o00000o0O
  if 60 - 60: iII111i . o0oOOo0O0Ooo
 return ( ooo00o0 )
 if 56 - 56: I1ii11iIi11i
 if 89 - 89: Oo0Ooo + I1ii11iIi11i * o0oOOo0O0Ooo * oO0o % O0 % OoO0O00
 if 70 - 70: o0oOOo0O0Ooo + O0 % I1IiiI
 if 56 - 56: Ii1I
 if 84 - 84: iII111i
 if 21 - 21: i11iIiiIii
 if 30 - 30: OoO0O00 + OoooooooOO
def lisp_ipv4_input ( packet ) :
 if 98 - 98: I1ii11iIi11i % I1IiiI
 if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
 if 66 - 66: IiII
 if 56 - 56: oO0o + OoooooooOO
 if ( ord ( packet [ 9 ] ) == 2 ) : return ( [ True , packet ] )
 if 75 - 75: O0 % Ii1I
 if 47 - 47: OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
 if 23 - 23: iII111i / iIii1I11I1II1
 if 5 - 5: O0
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
   if 64 - 64: i1IIi * i1IIi . iII111i - O0 - oO0o % OoooooooOO
   if 14 - 14: Ii1I % OoO0O00 % I1Ii111 * O0
   if 8 - 8: I1IiiI - i11iIiiIii * I1IiiI
   if 6 - 6: O0 - OoOoOO00 - i11iIiiIii / iII111i
   if 63 - 63: OOooOOo
   if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
   if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
 oo0o = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( oo0o == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( oo0o == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 96 - 96: iIii1I11I1II1 * II111iiii . iIii1I11I1II1
  return ( [ False , None ] )
  if 13 - 13: Ii1I - OoOoOO00 . Ii1I
  if 7 - 7: Ii1I - I11i / I1ii11iIi11i + iII111i
 oo0o -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , oo0o ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( [ False , packet ] )
 if 47 - 47: I11i * IiII / oO0o - OoooooooOO . OoooooooOO / I11i
 if 73 - 73: Ii1I . IiII % IiII
 if 56 - 56: I1Ii111 + iII111i + iII111i
 if 99 - 99: o0oOOo0O0Ooo % I1ii11iIi11i / Oo0Ooo . O0 + OoO0O00 * OoOoOO00
 if 48 - 48: iIii1I11I1II1 + O0 * I11i * i11iIiiIii . Ii1I / i1IIi
 if 48 - 48: i1IIi % iIii1I11I1II1 + I1IiiI - OoOoOO00 % I11i . I1Ii111
 if 66 - 66: I1Ii111 * i11iIiiIii + I1IiiI % II111iiii
def lisp_ipv6_input ( packet ) :
 oO0o0 = packet . inner_dest
 packet = packet . packet
 if 47 - 47: II111iiii % o0oOOo0O0Ooo
 if 26 - 26: I1ii11iIi11i / I11i / Oo0Ooo / i1IIi + O0 * ooOoO0o
 if 53 - 53: IiII / II111iiii / oO0o % O0 / I1Ii111
 if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
 if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
 oo0o = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( oo0o == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( oo0o == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 45 - 45: OOooOOo - OOooOOo % iII111i - IiII . O0
  return ( None )
  if 6 - 6: iIii1I11I1II1 * II111iiii / O0 % IiII - I1Ii111
  if 64 - 64: ooOoO0o
  if 28 - 28: i11iIiiIii - IiII * I1ii11iIi11i + IiII * iII111i
  if 75 - 75: o0oOOo0O0Ooo * OoOoOO00 % I1ii11iIi11i + OOooOOo . II111iiii
  if 12 - 12: ooOoO0o
 if ( oO0o0 . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
  if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
 oo0o -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , oo0o ) + packet [ 8 : : ]
 return ( packet )
 if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
 if 78 - 78: i1IIi
 if 25 - 25: Ii1I * II111iiii / OoOoOO00
 if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
 if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
 if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
 if 15 - 15: i11iIiiIii
 if 85 - 85: I1Ii111 + iII111i - oO0o
def lisp_mac_input ( packet ) :
 return ( packet )
 if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
 if 64 - 64: OoOoOO00
 if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
 if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
 if 71 - 71: ooOoO0o
 if 35 - 35: OoOoOO00
 if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
 if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
 if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
def lisp_rate_limit_map_request ( source , dest ) :
 if ( lisp_last_map_request_sent == None ) : return ( False )
 OoooOOoOo = lisp_get_timestamp ( )
 oO000o0Oo00 = OoooOOoOo - lisp_last_map_request_sent
 ooOoOoooo = ( oO000o0Oo00 < LISP_MAP_REQUEST_RATE_LIMIT )
 if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
 if ( ooOoOoooo ) :
  if ( source != None ) : source = source . print_address ( )
  dest = dest . print_address ( )
  dprint ( "Rate-limiting Map-Request for {} -> {}" . format ( source , dest ) )
  if 89 - 89: iIii1I11I1II1 . ooOoO0o
 return ( ooOoOoooo )
 if 82 - 82: OoOoOO00 - II111iiii . OoO0O00 * ooOoO0o
 if 78 - 78: OoOoOO00 % oO0o
 if 39 - 39: iIii1I11I1II1
 if 72 - 72: II111iiii + I1Ii111 / Ii1I * iIii1I11I1II1
 if 95 - 95: OoooooooOO + OOooOOo + II111iiii + IiII + OoO0O00
 if 86 - 86: II111iiii / iII111i - I1ii11iIi11i
 if 65 - 65: I1ii11iIi11i + OoOoOO00
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ) :
 global lisp_last_map_request_sent
 if 43 - 43: O0 + I11i % II111iiii
 if 56 - 56: IiII + Oo0Ooo . IiII % iIii1I11I1II1 % ooOoO0o % ooOoO0o
 if 70 - 70: ooOoO0o / i1IIi - I11i - i11iIiiIii
 if 79 - 79: OoO0O00 - OoooooooOO % iII111i . O0
 if 93 - 93: I1Ii111
 if 3 - 3: OoO0O00 / IiII - oO0o / oO0o
 iiIiiI1 = oo0OooOOo0oO = None
 if ( rloc ) :
  iiIiiI1 = rloc . rloc
  oo0OooOOo0oO = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 48 - 48: O0
  if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
  if 84 - 84: i11iIiiIii . OoooooooOO
  if 69 - 69: I1Ii111 * II111iiii % I1Ii111 * i11iIiiIii . ooOoO0o / Oo0Ooo
  if 5 - 5: Ii1I
 iIIIIiiII , i1IiIii , OoO0o0OOOO = lisp_myrlocs
 if ( iIIIIiiII == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 77 - 77: OoooooooOO / II111iiii + Ii1I * o0oOOo0O0Ooo . i11iIiiIii
 if ( i1IiIii == None and iiIiiI1 != None and iiIiiI1 . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 24 - 24: I11i + OoO0O00
  if 76 - 76: II111iiii - O0 / Oo0Ooo % OoOoOO00
 o00oo00OOOO = lisp_map_request ( )
 o00oo00OOOO . record_count = 1
 o00oo00OOOO . nonce = lisp_get_control_nonce ( )
 o00oo00OOOO . rloc_probe = ( iiIiiI1 != None )
 if 1 - 1: I1ii11iIi11i / iIii1I11I1II1 . Oo0Ooo + I1IiiI / Oo0Ooo
 if 62 - 62: oO0o * OoOoOO00 % iII111i * ooOoO0o . Oo0Ooo . i11iIiiIii
 if 60 - 60: iIii1I11I1II1 + O0
 if 96 - 96: iII111i . i1IIi % o0oOOo0O0Ooo * iIii1I11I1II1 - iII111i - OoooooooOO
 if 13 - 13: i1IIi
 if 68 - 68: I1ii11iIi11i . IiII + O0 % i1IIi + iIii1I11I1II1
 if 17 - 17: i1IIi - OOooOOo * ooOoO0o + i1IIi - ooOoO0o + I1ii11iIi11i
 if ( rloc ) : rloc . last_rloc_probe_nonce = o00oo00OOOO . nonce
 if 28 - 28: iII111i
 iiI1 = deid . is_multicast_address ( )
 if ( iiI1 ) :
  o00oo00OOOO . target_eid = seid
  o00oo00OOOO . target_group = deid
 else :
  o00oo00OOOO . target_eid = deid
  if 18 - 18: I1Ii111
  if 29 - 29: i1IIi - I1IiiI / i1IIi
  if 64 - 64: IiII
  if 69 - 69: OOooOOo . I1IiiI
  if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
  if 22 - 22: iII111i % I11i % O0 - I11i
  if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
  if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
  if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
 if ( o00oo00OOOO . rloc_probe == False ) :
  Ooooo00 = lisp_get_signature_eid ( )
  if ( Ooooo00 ) :
   o00oo00OOOO . signature_eid . copy_address ( Ooooo00 . eid )
   o00oo00OOOO . privkey_filename = "./lisp-sig.pem"
   if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
   if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
   if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
   if 97 - 97: iIii1I11I1II1 * I1Ii111
   if 39 - 39: I1Ii111 . II111iiii
   if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
 if ( seid == None or iiI1 ) :
  o00oo00OOOO . source_eid . afi = LISP_AFI_NONE
 else :
  o00oo00OOOO . source_eid = seid
  if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
  if 34 - 34: I1IiiI
  if 56 - 56: Ii1I
  if 71 - 71: O0 / i1IIi
  if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
  if 82 - 82: oO0o * i11iIiiIii % o0oOOo0O0Ooo % IiII - I11i - OoO0O00
  if 24 - 24: oO0o . II111iiii + OoO0O00 * I1ii11iIi11i / oO0o
  if 86 - 86: I1Ii111 + I1ii11iIi11i
  if 63 - 63: ooOoO0o - i11iIiiIii . o0oOOo0O0Ooo - i1IIi - IiII
  if 32 - 32: I1Ii111 / iIii1I11I1II1 + oO0o % I11i * OoooooooOO
  if 69 - 69: OOooOOo
  if 9 - 9: i11iIiiIii * Oo0Ooo
 if ( iiIiiI1 != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( iiIiiI1 . is_private_address ( ) == False ) :
   iIIIIiiII = lisp_get_any_translated_rloc ( )
   if 33 - 33: oO0o / ooOoO0o
  if ( iIIIIiiII == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 92 - 92: O0 . Oo0Ooo - Ii1I * I1IiiI * Oo0Ooo * iII111i
   if 78 - 78: Ii1I * iIii1I11I1II1 - Ii1I - I1ii11iIi11i * I1ii11iIi11i
   if 44 - 44: o0oOOo0O0Ooo
   if 1 - 1: OoooooooOO / i11iIiiIii . o0oOOo0O0Ooo
   if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
   if 12 - 12: Oo0Ooo . o0oOOo0O0Ooo - i1IIi - oO0o % IiII . I11i
   if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
   if 64 - 64: O0 - iII111i
 if ( iiIiiI1 == None or iiIiiI1 . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and iiIiiI1 == None ) :
   oOoOO0oOo0O0O00 = lisp_get_any_translated_rloc ( )
   if ( oOoOO0oOo0O0O00 != None ) : iIIIIiiII = oOoOO0oOo0O0O00
   if 84 - 84: OOooOOo * ooOoO0o / O0
  o00oo00OOOO . itr_rlocs . append ( iIIIIiiII )
  if 96 - 96: I11i . I11i % II111iiii
 if ( iiIiiI1 == None or iiIiiI1 . is_ipv6 ( ) ) :
  if ( i1IiIii == None or i1IiIii . is_ipv6_link_local ( ) ) :
   i1IiIii = None
  else :
   o00oo00OOOO . itr_rloc_count = 1 if ( iiIiiI1 == None ) else 0
   o00oo00OOOO . itr_rlocs . append ( i1IiIii )
   if 14 - 14: iII111i / OoooooooOO
   if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
   if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
   if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
   if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
   if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
   if 11 - 11: I1IiiI
   if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
   if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
 if ( iiIiiI1 != None and o00oo00OOOO . itr_rlocs != [ ] ) :
  oO00o0o0O = o00oo00OOOO . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   oO00o0o0O = iIIIIiiII
  elif ( deid . is_ipv6 ( ) ) :
   oO00o0o0O = i1IiIii
  else :
   oO00o0o0O = iIIIIiiII
   if 91 - 91: OoO0O00
   if 8 - 8: oO0o
   if 96 - 96: IiII
   if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
   if 26 - 26: o0oOOo0O0Ooo . i1IIi
   if 62 - 62: IiII * I1ii11iIi11i % iIii1I11I1II1 / II111iiii - OoO0O00
 IIii1i = o00oo00OOOO . encode ( iiIiiI1 , oo0OooOOo0oO )
 o00oo00OOOO . print_map_request ( )
 if 52 - 52: iII111i . I11i - I11i + oO0o + iIii1I11I1II1
 if 83 - 83: I11i * iIii1I11I1II1 + OoOoOO00
 if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
 if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
 if 100 - 100: II111iiii / Oo0Ooo / iII111i / OOooOOo
 if 100 - 100: iIii1I11I1II1
 if ( iiIiiI1 != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   O00OOoOOO0O0O = lisp_get_nat_info ( iiIiiI1 , rloc . rloc_name )
   if 50 - 50: I1Ii111 / ooOoO0o * I11i
   if 53 - 53: II111iiii . IiII
   if 5 - 5: i1IIi % IiII
   if 16 - 16: ooOoO0o - iII111i % Ii1I . OoOoOO00
   if ( O00OOoOOO0O0O == None ) :
    i11iII1IiI = rloc . rloc . print_address_no_iid ( )
    i11ii = "gleaned-{}" . format ( i11iII1IiI )
    III1I1Iii1 = rloc . translated_port
    O00OOoOOO0O0O = lisp_nat_info ( i11iII1IiI , i11ii , III1I1Iii1 )
    if 56 - 56: i11iIiiIii % i11iIiiIii % OoooooooOO . Ii1I . iII111i + I11i
   lisp_encapsulate_rloc_probe ( lisp_sockets , iiIiiI1 , O00OOoOOO0O0O ,
 IIii1i )
   return
   if 64 - 64: O0
   if 37 - 37: o0oOOo0O0Ooo / O0
  oo0o00OO = iiIiiI1 . print_address_no_iid ( )
  oO0o0 = lisp_convert_4to6 ( oo0o00OO )
  lisp_send ( lisp_sockets , oO0o0 , LISP_CTRL_PORT , IIii1i )
  return
  if 58 - 58: I1Ii111 + OoooooooOO + iIii1I11I1II1
  if 13 - 13: o0oOOo0O0Ooo . I11i / O0
  if 39 - 39: I11i + oO0o + ooOoO0o % ooOoO0o - I1IiiI % Oo0Ooo
  if 9 - 9: IiII / iII111i * II111iiii + O0 % Oo0Ooo / i1IIi
  if 45 - 45: OoOoOO00 % i11iIiiIii . I1IiiI - O0 * i1IIi - I1IiiI
  if 48 - 48: IiII / iIii1I11I1II1
 iIi1i = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  O0o00000o0O = lisp_get_decent_map_resolver ( deid )
 else :
  O0o00000o0O = lisp_get_map_resolver ( None , iIi1i )
  if 5 - 5: OoOoOO00 . iIii1I11I1II1 + iII111i
 if ( O0o00000o0O == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 63 - 63: i1IIi
  return
  if 24 - 24: i11iIiiIii % iII111i . oO0o
 O0o00000o0O . last_used = lisp_get_timestamp ( )
 O0o00000o0O . map_requests_sent += 1
 if ( O0o00000o0O . last_nonce == 0 ) : O0o00000o0O . last_nonce = o00oo00OOOO . nonce
 if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
 if 34 - 34: I1ii11iIi11i % ooOoO0o / II111iiii * O0 % OOooOOo
 if 9 - 9: I1ii11iIi11i / I1ii11iIi11i - OOooOOo . iIii1I11I1II1
 if 33 - 33: I1IiiI + oO0o % I1IiiI / iII111i - ooOoO0o - i11iIiiIii
 if ( seid == None ) : seid = oO00o0o0O
 lisp_send_ecm ( lisp_sockets , IIii1i , seid , lisp_ephem_port , deid ,
 O0o00000o0O . map_resolver )
 if 39 - 39: i11iIiiIii / oO0o
 if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
 if 87 - 87: I1IiiI / Ii1I
 if 54 - 54: OoooooooOO / Ii1I
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 26 - 26: o0oOOo0O0Ooo + OoO0O00
 if 59 - 59: Ii1I * IiII
 if 64 - 64: ooOoO0o . Oo0Ooo - OoOoOO00
 if 66 - 66: OoOoOO00
 O0o00000o0O . resolve_dns_name ( )
 return
 if 83 - 83: OOooOOo . IiII
 if 98 - 98: i11iIiiIii
 if 74 - 74: iIii1I11I1II1 * O0 + OOooOOo . o0oOOo0O0Ooo
 if 17 - 17: I1Ii111
 if 59 - 59: OoOoOO00 . OoOoOO00 * iII111i - Ii1I . i11iIiiIii
 if 68 - 68: iII111i
 if 68 - 68: I1Ii111 - OoO0O00 % OoO0O00 % OOooOOo - OoO0O00
 if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 59 - 59: iII111i
 if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
 if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + OOooOOo
 OO0O0OOooo = lisp_info ( )
 OO0O0OOooo . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : OO0O0OOooo . hostname += "-" + device_name
 if 19 - 19: ooOoO0o
 oo0o00OO = dest . print_address_no_iid ( )
 if 53 - 53: O0 - ooOoO0o * I11i - oO0o / i1IIi % Ii1I
 if 100 - 100: i11iIiiIii / o0oOOo0O0Ooo
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
 if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
 if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
 if 67 - 67: i1IIi * I1Ii111 * O0
 if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
 OOO0OOoo0o = False
 if ( device_name ) :
  OOo000oo = lisp_get_host_route_next_hop ( oo0o00OO )
  if 91 - 91: I1ii11iIi11i % OoOoOO00
  if 63 - 63: iIii1I11I1II1 + OoOoOO00 - I11i
  if 10 - 10: I1ii11iIi11i
  if 6 - 6: OoO0O00 + OoO0O00 * OOooOOo / IiII % ooOoO0o - I1IiiI
  if 17 - 17: II111iiii
  if 66 - 66: O0 % OoOoOO00 + IiII % I1Ii111
  if 94 - 94: OoOoOO00 / OoooooooOO % Ii1I * i11iIiiIii
  if 95 - 95: iIii1I11I1II1 % OOooOOo % O0
  if 93 - 93: I1ii11iIi11i
  if ( port == LISP_CTRL_PORT and OOo000oo != None ) :
   while ( True ) :
    time . sleep ( .01 )
    OOo000oo = lisp_get_host_route_next_hop ( oo0o00OO )
    if ( OOo000oo == None ) : break
    if 61 - 61: o0oOOo0O0Ooo * ooOoO0o
    if 82 - 82: O0 * O0 % I1IiiI / o0oOOo0O0Ooo
    if 46 - 46: IiII . O0 . I11i % I1ii11iIi11i * oO0o - oO0o
  ooooO0OO0 = lisp_get_default_route_next_hops ( )
  for OoO0o0OOOO , iiIIII1I1ii in ooooO0OO0 :
   if ( OoO0o0OOOO != device_name ) : continue
   if 90 - 90: OoooooooOO . Oo0Ooo + IiII + I1IiiI * I1Ii111
   if 82 - 82: OOooOOo / I11i % Ii1I * OoOoOO00
   if 88 - 88: o0oOOo0O0Ooo % OoO0O00
   if 30 - 30: II111iiii / Oo0Ooo % Oo0Ooo + O0 / iIii1I11I1II1 . OoO0O00
   if 43 - 43: I1IiiI % OoOoOO00 * O0 + o0oOOo0O0Ooo
   if 97 - 97: iIii1I11I1II1 + O0
   if ( OOo000oo != iiIIII1I1ii ) :
    if ( OOo000oo != None ) :
     lisp_install_host_route ( oo0o00OO , OOo000oo , False )
     if 41 - 41: OoOoOO00 - II111iiii
    lisp_install_host_route ( oo0o00OO , iiIIII1I1ii , True )
    OOO0OOoo0o = True
    if 46 - 46: OOooOOo
   break
   if 73 - 73: iII111i - IiII + II111iiii
   if 58 - 58: Oo0Ooo % I1IiiI
   if 78 - 78: iII111i / iIii1I11I1II1 * IiII . ooOoO0o / I1Ii111 % I11i
   if 14 - 14: II111iiii % iIii1I11I1II1 - I1IiiI % i11iIiiIii . OOooOOo * I1ii11iIi11i
   if 12 - 12: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . OoOoOO00
   if 73 - 73: I1ii11iIi11i * i1IIi * Oo0Ooo / O0
 IIii1i = OO0O0OOooo . encode ( )
 OO0O0OOooo . print_info ( )
 if 1 - 1: iII111i * OOooOOo + II111iiii / Ii1I . I1ii11iIi11i
 if 61 - 61: oO0o % OoOoOO00 % ooOoO0o . I1Ii111 / OoO0O00
 if 21 - 21: IiII
 if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
 ooO0oO0o0O0o = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 ooO0oO0o0O0o = bold ( ooO0oO0o0O0o , False )
 III1I1Iii1 = bold ( "{}" . format ( port ) , False )
 OO0o = red ( oo0o00OO , False )
 ooOoOo0O = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( ooOoOo0O , OO0o , III1I1Iii1 , ooO0oO0o0O0o ) )
 if 9 - 9: I11i + I1ii11iIi11i / I1IiiI + I1Ii111 % i1IIi / i1IIi
 if 91 - 91: I11i
 if 94 - 94: OoO0O00
 if 19 - 19: I11i * i11iIiiIii - OoO0O00 / ooOoO0o * I1Ii111 + OoO0O00
 if 30 - 30: Ii1I / iII111i * Ii1I
 if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , IIii1i )
 else :
  Ii1I1i1IiiI = lisp_data_header ( )
  Ii1I1i1IiiI . instance_id ( 0xffffff )
  Ii1I1i1IiiI = Ii1I1i1IiiI . encode ( )
  if ( Ii1I1i1IiiI ) :
   IIii1i = Ii1I1i1IiiI + IIii1i
   if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
   if 71 - 71: i1IIi % O0 % ooOoO0o
   if 24 - 24: O0
   if 88 - 88: OoooooooOO / Oo0Ooo / oO0o
   if 99 - 99: I1Ii111 % OoOoOO00 % IiII - Ii1I
   if 79 - 79: ooOoO0o + Oo0Ooo
   if 80 - 80: OoOoOO00 % OoO0O00 . OoO0O00 * OoO0O00 * O0
   if 18 - 18: II111iiii . o0oOOo0O0Ooo + OoO0O00
   if 69 - 69: OoO0O00 . ooOoO0o * ooOoO0o * iIii1I11I1II1
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , IIii1i )
   if 8 - 8: iII111i . oO0o . OOooOOo + iII111i . Ii1I
   if 46 - 46: OoO0O00
   if 21 - 21: iIii1I11I1II1 - iII111i
   if 15 - 15: O0 + iII111i + i11iIiiIii
   if 31 - 31: iIii1I11I1II1 * iIii1I11I1II1 . I11i
   if 52 - 52: i11iIiiIii / oO0o / IiII
   if 84 - 84: I11i . oO0o + ooOoO0o
 if ( OOO0OOoo0o ) :
  lisp_install_host_route ( oo0o00OO , None , False )
  if ( OOo000oo != None ) : lisp_install_host_route ( oo0o00OO , OOo000oo , True )
  if 75 - 75: I1Ii111
 return
 if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
 if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
 if 73 - 73: ooOoO0o + O0 - I11i . I1IiiI + OOooOOo
 if 36 - 36: I11i % OoO0O00 * OoOoOO00 - I1Ii111
 if 16 - 16: ooOoO0o % OOooOOo . OoO0O00 % II111iiii . iIii1I11I1II1
 if 21 - 21: oO0o + II111iiii / OoOoOO00 * I11i
 if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 70 - 70: I1IiiI . ooOoO0o / I11i / OoO0O00
 if 40 - 40: oO0o % iIii1I11I1II1 * iIii1I11I1II1 / Oo0Ooo * OoO0O00
 if 61 - 61: OOooOOo
 if 80 - 80: I1ii11iIi11i
 OO0O0OOooo = lisp_info ( )
 packet = OO0O0OOooo . decode ( packet )
 if ( packet == None ) : return
 OO0O0OOooo . print_info ( )
 if 6 - 6: I1ii11iIi11i + OOooOOo % ooOoO0o
 if 65 - 65: iIii1I11I1II1 % i1IIi / I1IiiI / oO0o % ooOoO0o / I11i
 if 2 - 2: I1ii11iIi11i
 if 90 - 90: II111iiii * I1Ii111 . ooOoO0o - I1ii11iIi11i % I11i * o0oOOo0O0Ooo
 if 85 - 85: iIii1I11I1II1
 OO0O0OOooo . info_reply = True
 OO0O0OOooo . global_etr_rloc . store_address ( addr_str )
 OO0O0OOooo . etr_port = sport
 if 76 - 76: i11iIiiIii % I1IiiI / I11i
 if 42 - 42: o0oOOo0O0Ooo . I1IiiI + I11i . OoOoOO00 - O0 / Ii1I
 if 66 - 66: IiII + OoOoOO00 + I1IiiI + i1IIi + OoooooooOO % I1IiiI
 if 80 - 80: iII111i / O0 % OoooooooOO / Oo0Ooo
 if 75 - 75: ooOoO0o
 if ( OO0O0OOooo . hostname != None ) :
  OO0O0OOooo . private_etr_rloc . afi = LISP_AFI_NAME
  OO0O0OOooo . private_etr_rloc . store_address ( OO0O0OOooo . hostname )
  if 72 - 72: oO0o . OoooooooOO % ooOoO0o % OoO0O00 * oO0o * OoO0O00
  if 14 - 14: I11i / I11i
 if ( rtr_list != None ) : OO0O0OOooo . rtr_list = rtr_list
 packet = OO0O0OOooo . encode ( )
 OO0O0OOooo . print_info ( )
 if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
 if 93 - 93: oO0o / ooOoO0o - I1Ii111
 if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
 if 26 - 26: O0 + Oo0Ooo
 if 30 - 30: IiII
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 oO0o0 = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , oO0o0 , sport , packet )
 if 6 - 6: O0
 if 92 - 92: I11i
 if 76 - 76: I11i / iIii1I11I1II1 - i11iIiiIii / O0 / O0
 if 19 - 19: Ii1I . I1IiiI - i1IIi * ooOoO0o . iIii1I11I1II1
 if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
 I11iiI1i11I = lisp_info_source ( OO0O0OOooo . hostname , addr_str , sport )
 I11iiI1i11I . cache_address_for_info_source ( )
 return
 if 3 - 3: Oo0Ooo . IiII . Oo0Ooo
 if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
 if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
 if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
 if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
 if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
 if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
 if 83 - 83: OOooOOo . ooOoO0o / IiII
def lisp_get_signature_eid ( ) :
 for Ooooo00 in lisp_db_list :
  if ( Ooooo00 . signature_eid ) : return ( Ooooo00 )
  if 80 - 80: I1Ii111 . I11i - I11i + I1ii11iIi11i
 return ( None )
 if 42 - 42: I11i / IiII % O0 - Oo0Ooo
 if 33 - 33: I1Ii111
 if 1 - 1: IiII - iIii1I11I1II1 % OoooooooOO
 if 1 - 1: o0oOOo0O0Ooo - i11iIiiIii + I11i
 if 47 - 47: O0 + IiII + ooOoO0o + OOooOOo / OoOoOO00
 if 31 - 31: oO0o * iII111i % OoOoOO00
 if 80 - 80: ooOoO0o % I1ii11iIi11i % I11i . I1Ii111
 if 3 - 3: ooOoO0o - Oo0Ooo
def lisp_get_any_translated_port ( ) :
 for Ooooo00 in lisp_db_list :
  for iIII in Ooooo00 . rloc_set :
   if ( iIII . translated_rloc . is_null ( ) ) : continue
   return ( iIII . translated_port )
   if 2 - 2: iII111i . iII111i
   if 77 - 77: OOooOOo
 return ( None )
 if 74 - 74: O0
 if 86 - 86: OoOoOO00
 if 4 - 4: OoooooooOO * OoO0O00
 if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
 if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
 if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
 if 6 - 6: I1IiiI - OoOoOO00
 if 63 - 63: OOooOOo - oO0o * I1IiiI
 if 60 - 60: II111iiii - Oo0Ooo
def lisp_get_any_translated_rloc ( ) :
 for Ooooo00 in lisp_db_list :
  for iIII in Ooooo00 . rloc_set :
   if ( iIII . translated_rloc . is_null ( ) ) : continue
   return ( iIII . translated_rloc )
   if 43 - 43: I1IiiI - IiII - OOooOOo
   if 19 - 19: I1Ii111 / I1Ii111 - i1IIi
 return ( None )
 if 99 - 99: O0
 if 37 - 37: iIii1I11I1II1 / I1Ii111 + OoO0O00
 if 85 - 85: ooOoO0o / I1IiiI
 if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
 if 99 - 99: i11iIiiIii - I1ii11iIi11i
 if 64 - 64: IiII . OoOoOO00 . Oo0Ooo . I1Ii111 / I11i / Ii1I
 if 95 - 95: iIii1I11I1II1 . Ii1I % oO0o - I11i % IiII
def lisp_get_all_translated_rlocs ( ) :
 II1IIii = [ ]
 for Ooooo00 in lisp_db_list :
  for iIII in Ooooo00 . rloc_set :
   if ( iIII . is_rloc_translated ( ) == False ) : continue
   IiiIIi1 = iIII . translated_rloc . print_address_no_iid ( )
   II1IIii . append ( IiiIIi1 )
   if 25 - 25: Ii1I - Ii1I - I1ii11iIi11i / i1IIi . OoOoOO00 % Oo0Ooo
   if 76 - 76: I1Ii111 / OoOoOO00
 return ( II1IIii )
 if 61 - 61: Oo0Ooo . i1IIi
 if 78 - 78: i11iIiiIii
 if 20 - 20: Ii1I
 if 100 - 100: OoooooooOO . I1Ii111
 if 32 - 32: iIii1I11I1II1 . iIii1I11I1II1 % II111iiii / Oo0Ooo . iIii1I11I1II1 . O0
 if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
 if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
 if 87 - 87: I1ii11iIi11i . i1IIi - I11i + OoOoOO00 . O0
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 iiiiIii = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 37 - 37: IiII
 O0o0oo0oo0oo0 = { }
 for oOo00O in rtr_list :
  if ( oOo00O == None ) : continue
  IiiIIi1 = rtr_list [ oOo00O ]
  if ( iiiiIii and IiiIIi1 . is_private_address ( ) ) : continue
  O0o0oo0oo0oo0 [ oOo00O ] = IiiIIi1
  if 30 - 30: OoO0O00 / I1IiiI / OOooOOo % IiII * I1ii11iIi11i / i1IIi
 rtr_list = O0o0oo0oo0oo0
 if 49 - 49: I1ii11iIi11i * IiII / I1IiiI . I11i
 iI1i = [ ]
 for O000oOOoOOO in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( O000oOOoOOO == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 29 - 29: iIii1I11I1II1 % Oo0Ooo
  if 29 - 29: i11iIiiIii . o0oOOo0O0Ooo + Oo0Ooo + I1IiiI - I1ii11iIi11i
  if 10 - 10: I1ii11iIi11i - i1IIi * OoOoOO00 / II111iiii * I1IiiI - IiII
  if 56 - 56: Ii1I - iIii1I11I1II1
  if 76 - 76: IiII . iII111i % iII111i . OoooooooOO . IiII
  O000O0o00o0o = lisp_address ( O000oOOoOOO , "" , 0 , iid )
  O000O0o00o0o . make_default_route ( O000O0o00o0o )
  IiiiiII1i = lisp_map_cache . lookup_cache ( O000O0o00o0o , True )
  if ( IiiiiII1i ) :
   if ( IiiiiII1i . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( IiiiiII1i . print_eid_tuple ( ) , False ) ) )
    if 77 - 77: I1Ii111
   elif ( IiiiiII1i . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 77 - 77: OoO0O00 * O0 + OoOoOO00 % O0 * Ii1I . OOooOOo
   IiiiiII1i . delete_cache ( )
   if 52 - 52: O0 / I1Ii111 + o0oOOo0O0Ooo . O0 . OoO0O00
   if 81 - 81: o0oOOo0O0Ooo - OoOoOO00 - Oo0Ooo * i11iIiiIii - Ii1I
  iI1i . append ( [ O000O0o00o0o , "" ] )
  if 88 - 88: O0 * OoO0O00 * ooOoO0o / iII111i . oO0o
  if 96 - 96: IiII . I1Ii111 % ooOoO0o
  if 39 - 39: II111iiii - OoO0O00 % I1Ii111 + IiII - i11iIiiIii
  if 31 - 31: OoOoOO00 + Oo0Ooo / OoO0O00 - OOooOOo
  O0o00oOOOO00 = lisp_address ( O000oOOoOOO , "" , 0 , iid )
  O0o00oOOOO00 . make_default_multicast_route ( O0o00oOOOO00 )
  oOOoo0o = lisp_map_cache . lookup_cache ( O0o00oOOOO00 , True )
  if ( oOOoo0o ) : oOOoo0o = oOOoo0o . source_cache . lookup_cache ( O000O0o00o0o , True )
  if ( oOOoo0o ) : oOOoo0o . delete_cache ( )
  if 62 - 62: ooOoO0o . I1IiiI * i11iIiiIii
  iI1i . append ( [ O000O0o00o0o , O0o00oOOOO00 ] )
  if 2 - 2: i11iIiiIii
 if ( len ( iI1i ) == 0 ) : return
 if 86 - 86: I1Ii111 + o0oOOo0O0Ooo
 if 17 - 17: iIii1I11I1II1
 if 32 - 32: IiII - OoOoOO00
 if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
 ooo0oo = [ ]
 for ooOoOo0O in rtr_list :
  I11111I = rtr_list [ ooOoOo0O ]
  iIII = lisp_rloc ( )
  iIII . rloc . copy_address ( I11111I )
  iIII . priority = 254
  iIII . mpriority = 255
  iIII . rloc_name = "RTR"
  ooo0oo . append ( iIII )
  if 82 - 82: I1ii11iIi11i % OoO0O00 . I11i * I1ii11iIi11i - OoO0O00 / Oo0Ooo
  if 4 - 4: OoOoOO00 * iIii1I11I1II1
 for O000O0o00o0o in iI1i :
  IiiiiII1i = lisp_mapping ( O000O0o00o0o [ 0 ] , O000O0o00o0o [ 1 ] , ooo0oo )
  IiiiiII1i . mapping_source = map_resolver
  IiiiiII1i . map_cache_ttl = LISP_MR_TTL * 60
  IiiiiII1i . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( IiiiiII1i . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
  ooo0oo = copy . deepcopy ( ooo0oo )
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
 if 23 - 23: o0oOOo0O0Ooo . o0oOOo0O0Ooo - iIii1I11I1II1 / o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + I1Ii111 . I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
def lisp_process_info_reply ( source , packet , store ) :
 if 2 - 2: oO0o % iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
 if 45 - 45: II111iiii . iII111i
 if 55 - 55: ooOoO0o / iII111i / O0
 if 98 - 98: O0 % iII111i + II111iiii
 OO0O0OOooo = lisp_info ( )
 packet = OO0O0OOooo . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
 OO0O0OOooo . print_info ( )
 if 23 - 23: iIii1I11I1II1 + oO0o . oO0o / o0oOOo0O0Ooo
 if 77 - 77: i1IIi * o0oOOo0O0Ooo * IiII
 if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
 if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
 iiIiI11I11i11 = False
 for ooOoOo0O in OO0O0OOooo . rtr_list :
  oo0o00OO = ooOoOo0O . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( oo0o00OO ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ oo0o00OO ] != None ) : continue
   if 16 - 16: I1Ii111 % i1IIi
  iiIiI11I11i11 = True
  lisp_rtr_list [ oo0o00OO ] = ooOoOo0O
  if 50 - 50: OoOoOO00 / OoO0O00 * I11i / I11i / oO0o . Oo0Ooo
  if 81 - 81: OOooOOo - OoooooooOO * iII111i / OOooOOo
  if 98 - 98: I11i . OOooOOo - OoO0O00 % O0 * O0
  if 91 - 91: I1IiiI % ooOoO0o * iII111i % OoOoOO00 . OoOoOO00 + OoOoOO00
  if 95 - 95: o0oOOo0O0Ooo % i1IIi
 if ( lisp_i_am_itr and iiIiI11I11i11 ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for o0OoO0000o in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( o0OoO0000o ) , lisp_rtr_list )
    if 14 - 14: iIii1I11I1II1 + iIii1I11I1II1
    if 74 - 74: OoOoOO00 . iIii1I11I1II1 + Ii1I + ooOoO0o % OoOoOO00
    if 37 - 37: i11iIiiIii + O0 + II111iiii
    if 13 - 13: OOooOOo / O0
    if 19 - 19: iIii1I11I1II1 + IiII * I11i * II111iiii + o0oOOo0O0Ooo + i11iIiiIii
    if 69 - 69: iIii1I11I1II1 . II111iiii
    if 36 - 36: I1IiiI * i1IIi + OoOoOO00
 if ( store == False ) :
  return ( [ OO0O0OOooo . global_etr_rloc , OO0O0OOooo . etr_port , iiIiI11I11i11 ] )
  if 63 - 63: OoOoOO00 - iII111i
  if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
  if 82 - 82: iIii1I11I1II1 / OOooOOo
  if 7 - 7: OoooooooOO
  if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
  if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
 for Ooooo00 in lisp_db_list :
  for iIII in Ooooo00 . rloc_set :
   oOo00O = iIII . rloc
   II1i = iIII . interface
   if ( II1i == None ) :
    if ( oOo00O . is_null ( ) ) : continue
    if ( oOo00O . is_local ( ) == False ) : continue
    if ( OO0O0OOooo . private_etr_rloc . is_null ( ) == False and
 oOo00O . is_exact_match ( OO0O0OOooo . private_etr_rloc ) == False ) :
     continue
     if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
   elif ( OO0O0OOooo . private_etr_rloc . is_dist_name ( ) ) :
    IiIi1I1i1iII = OO0O0OOooo . private_etr_rloc . address
    if ( IiIi1I1i1iII != iIII . rloc_name ) : continue
    if 1 - 1: Ii1I . Ii1I % II111iiii + I11i + OoOoOO00
    if 52 - 52: OoooooooOO - OoO0O00
   I11i11i1 = green ( Ooooo00 . eid . print_prefix ( ) , False )
   o0O00oo0O = red ( oOo00O . print_address_no_iid ( ) , False )
   if 24 - 24: iII111i / Oo0Ooo - I1ii11iIi11i + o0oOOo0O0Ooo
   IIiIiIIiIIiI = OO0O0OOooo . global_etr_rloc . is_exact_match ( oOo00O )
   if ( iIII . translated_port == 0 and IIiIiIIiIIiI ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( o0O00oo0O ,
 II1i , I11i11i1 ) )
    continue
    if 64 - 64: oO0o - i11iIiiIii
    if 62 - 62: OoooooooOO - OoooooooOO / OoO0O00 - II111iiii . iIii1I11I1II1
    if 2 - 2: O0 + o0oOOo0O0Ooo % OOooOOo . ooOoO0o % i1IIi
    if 21 - 21: OoOoOO00 / OoooooooOO + I1Ii111 - IiII
    if 62 - 62: Oo0Ooo % iII111i + OoooooooOO - I1ii11iIi11i % iII111i % iIii1I11I1II1
   O0oO0o = OO0O0OOooo . global_etr_rloc
   i1IIiI1111II1 = iIII . translated_rloc
   if ( i1IIiI1111II1 . is_exact_match ( O0oO0o ) and
 OO0O0OOooo . etr_port == iIII . translated_port ) : continue
   if 82 - 82: I1IiiI . II111iiii % OoooooooOO
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( OO0O0OOooo . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # oO0o * ooOoO0o . Oo0Ooo % OoOoOO00
 OO0O0OOooo . etr_port , o0O00oo0O , II1i , I11i11i1 ) )
   if 88 - 88: IiII . I11i * OoO0O00 % o0oOOo0O0Ooo - Ii1I
   iIII . store_translated_rloc ( OO0O0OOooo . global_etr_rloc ,
 OO0O0OOooo . etr_port )
   if 6 - 6: I1IiiI / I1Ii111 % OoooooooOO * iIii1I11I1II1
   if 47 - 47: OoooooooOO % II111iiii % OOooOOo
 return ( [ OO0O0OOooo . global_etr_rloc , OO0O0OOooo . etr_port , iiIiI11I11i11 ] )
 if 26 - 26: O0
 if 23 - 23: oO0o
 if 15 - 15: OoO0O00 . OoO0O00 * O0
 if 97 - 97: OoooooooOO % ooOoO0o . I1Ii111 / iII111i
 if 59 - 59: II111iiii + O0 . I1ii11iIi11i . Oo0Ooo * OoO0O00
 if 35 - 35: oO0o / I1Ii111 * OOooOOo + OoooooooOO . IiII
 if 1 - 1: I1IiiI + I1Ii111 / OOooOOo . Ii1I . oO0o / I1ii11iIi11i
 if 54 - 54: OOooOOo
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 86 - 86: oO0o * Oo0Ooo / OOooOOo
 OOo0O0O0o0 = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 ii1i1Ii1 = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 7 - 7: I1Ii111 + ooOoO0o % o0oOOo0O0Ooo
 if 53 - 53: i1IIi / iII111i % Ii1I % OoooooooOO
 if 63 - 63: OOooOOo + I1ii11iIi11i . i1IIi . Ii1I - I1ii11iIi11i * o0oOOo0O0Ooo
 if 79 - 79: ooOoO0o - O0
 OOo0O0O0o0 . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , OOo0O0O0o0 , None )
 OOo0O0O0o0 . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , OOo0O0O0o0 , None )
 if 20 - 20: OOooOOo
 if 22 - 22: iIii1I11I1II1 / I1Ii111
 if 6 - 6: iII111i . i11iIiiIii / Oo0Ooo
 if 86 - 86: I11i % I1Ii111 % oO0o - ooOoO0o / i1IIi
 ii1i1Ii1 . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , ii1i1Ii1 , None )
 ii1i1Ii1 . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , ii1i1Ii1 , None )
 if 68 - 68: i1IIi % O0 % iII111i
 if 55 - 55: I1ii11iIi11i % OOooOOo - o0oOOo0O0Ooo - II111iiii
 if 52 - 52: I1Ii111
 if 34 - 34: II111iiii + iII111i / IiII
 iIIiIi = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 iIIiIi . start ( )
 return
 if 84 - 84: ooOoO0o - o0oOOo0O0Ooo * iIii1I11I1II1 * iIii1I11I1II1
 if 30 - 30: i1IIi + OoOoOO00 - I1ii11iIi11i % i1IIi
 if 2 - 2: i11iIiiIii + i1IIi
 if 1 - 1: i11iIiiIii + iIii1I11I1II1 / I11i * OoOoOO00 - OoOoOO00 % IiII
 if 68 - 68: O0 . OoooooooOO
 if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
 if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
 if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
 if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
 if 37 - 37: I1ii11iIi11i * IiII
 if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
 if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
 if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 46 - 46: OoooooooOO * OoO0O00 . I1Ii111
 IiiIIi1 = lisp_get_interface_address ( rloc . interface )
 if ( IiiIIi1 == None ) : return
 if 95 - 95: ooOoO0o . I1ii11iIi11i . ooOoO0o / I1IiiI * OoOoOO00 . O0
 oooOOoooo = rloc . rloc . print_address_no_iid ( )
 oo0Oo0oo = IiiIIi1 . print_address_no_iid ( )
 if 71 - 71: Ii1I * I1IiiI
 if ( oooOOoooo == oo0Oo0oo ) : return
 if 62 - 62: II111iiii / I1IiiI . I1ii11iIi11i
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , oooOOoooo , oo0Oo0oo ) )
 if 49 - 49: IiII / OoOoOO00 / O0 * i11iIiiIii
 if 47 - 47: i11iIiiIii + iII111i + i11iIiiIii
 rloc . rloc . copy_address ( IiiIIi1 )
 lisp_myrlocs [ 0 ] = IiiIIi1
 return
 if 66 - 66: o0oOOo0O0Ooo . I1IiiI + OoooooooOO . iII111i / OoooooooOO - IiII
 if 47 - 47: o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
 if 34 - 34: I11i / o0oOOo0O0Ooo * OOooOOo * OOooOOo
 if 89 - 89: I1ii11iIi11i . OoooooooOO
 if 61 - 61: i1IIi + i11iIiiIii
 if 59 - 59: i11iIiiIii * OOooOOo + i1IIi * iIii1I11I1II1 + I11i
 if 97 - 97: OoO0O00 - I11i . OoooooooOO
 if 58 - 58: I1ii11iIi11i / II111iiii / i11iIiiIii
def lisp_update_encap_port ( mc ) :
 for oOo00O in mc . rloc_set :
  O00OOoOOO0O0O = lisp_get_nat_info ( oOo00O . rloc , oOo00O . rloc_name )
  if ( O00OOoOOO0O0O == None ) : continue
  if ( oOo00O . translated_port == O00OOoOOO0O0O . port ) : continue
  if 27 - 27: iIii1I11I1II1 - O0 + OoOoOO00
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( oOo00O . translated_port , O00OOoOOO0O0O . port ,
  # i11iIiiIii * oO0o
 red ( oOo00O . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 100 - 100: iII111i % Oo0Ooo - OoO0O00 / OOooOOo % OoO0O00 - i11iIiiIii
  oOo00O . store_translated_rloc ( oOo00O . rloc , O00OOoOOO0O0O . port )
  if 18 - 18: I1ii11iIi11i
 return
 if 97 - 97: I11i * O0 + OoO0O00 / ooOoO0o
 if 34 - 34: i11iIiiIii / o0oOOo0O0Ooo - OoooooooOO * O0 + i1IIi % I1IiiI
 if 10 - 10: II111iiii - Ii1I . I11i . O0 + Ii1I
 if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
 if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
 if 21 - 21: I1ii11iIi11i - ooOoO0o
 if 81 - 81: iII111i / i11iIiiIii / I1Ii111
 if 70 - 70: I1ii11iIi11i / i11iIiiIii
 if 90 - 90: II111iiii / OoOoOO00 . Ii1I . OoooooooOO
 if 76 - 76: OoooooooOO
 if 78 - 78: IiII % i11iIiiIii
 if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
  if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
 OoooOOoOo = lisp_get_timestamp ( )
 if 19 - 19: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
 if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
 if 71 - 71: OoO0O00 - I11i
 if 96 - 96: I1Ii111 / Ii1I
 if 65 - 65: I1ii11iIi11i * O0 . IiII
 if ( mc . last_refresh_time + mc . map_cache_ttl > OoooOOoOo ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 11 - 11: I11i / Ii1I % oO0o
  if 50 - 50: i11iIiiIii
  if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
  if 25 - 25: I11i / ooOoO0o % ooOoO0o - OOooOOo
  if 59 - 59: I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1 - O0 - i11iIiiIii
 if ( lisp_nat_traversal and mc . eid . address == 0 and mc . eid . mask_len == 0 ) :
  return ( [ True , delete_list ] )
  if 4 - 4: I1IiiI
  if 36 - 36: Ii1I
  if 76 - 76: i11iIiiIii + i1IIi
  if 56 - 56: OoOoOO00 + II111iiii / i11iIiiIii * OoOoOO00 * OoooooooOO
  if 15 - 15: OoOoOO00 / OoooooooOO + OOooOOo
 oO000o0Oo00 = lisp_print_elapsed ( mc . last_refresh_time )
 Oo00O0o = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( Oo00O0o , False ) , bold ( "timed out" , False ) , oO000o0Oo00 ) )
 if 76 - 76: Ii1I * iII111i . OoooooooOO
 if 92 - 92: iIii1I11I1II1 - Oo0Ooo - I1IiiI - OOooOOo * I1Ii111
 if 44 - 44: I1Ii111 - II111iiii / OOooOOo
 if 50 - 50: I11i / I1ii11iIi11i
 if 60 - 60: II111iiii / Ii1I + OoO0O00 % I1IiiI * i1IIi / II111iiii
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
 if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
 if 3 - 3: OOooOOo / OoOoOO00 % iIii1I11I1II1
 if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 if 48 - 48: O0
 if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
 if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
 if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
def lisp_timeout_map_cache_walk ( mc , parms ) :
 O0ooo0oO00 = parms [ 0 ]
 O0O0O00ooO0O0 = parms [ 1 ]
 if 65 - 65: iII111i
 if 75 - 75: iIii1I11I1II1 - Oo0Ooo + Ii1I + ooOoO0o
 if 62 - 62: OOooOOo
 if 13 - 13: OOooOOo . i11iIiiIii
 if ( mc . group . is_null ( ) ) :
  O00O00o0O0O , O0ooo0oO00 = lisp_timeout_map_cache_entry ( mc , O0ooo0oO00 )
  if ( O0ooo0oO00 == [ ] or mc != O0ooo0oO00 [ - 1 ] ) :
   O0O0O00ooO0O0 = lisp_write_checkpoint_entry ( O0O0O00ooO0O0 , mc )
   if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
  return ( [ O00O00o0O0O , parms ] )
  if 79 - 79: oO0o
  if 47 - 47: OoooooooOO - i1IIi * OOooOOo
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
 if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
 if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
 if 8 - 8: iII111i
 if 10 - 10: OoOoOO00 % I11i
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 49 - 49: oO0o % ooOoO0o + II111iiii
 if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
 if 99 - 99: OoOoOO00
 if 46 - 46: I1ii11iIi11i / II111iiii / OoooooooOO / Ii1I
 if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
 if 8 - 8: oO0o
 if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
def lisp_timeout_map_cache ( lisp_map_cache ) :
 I1I1i = [ [ ] , [ ] ]
 I1I1i = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , I1I1i )
 if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
 if 1 - 1: OoooooooOO . Ii1I
 if 68 - 68: Ii1I
 if 98 - 98: iII111i
 if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
 O0ooo0oO00 = I1I1i [ 0 ]
 for IiiiiII1i in O0ooo0oO00 : IiiiiII1i . delete_cache ( )
 if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
 if 67 - 67: o0oOOo0O0Ooo
 if 58 - 58: IiII % o0oOOo0O0Ooo + i1IIi
 if 33 - 33: II111iiii
 O0O0O00ooO0O0 = I1I1i [ 1 ]
 lisp_checkpoint ( O0O0O00ooO0O0 )
 return
 if 61 - 61: I1Ii111
 if 56 - 56: I1ii11iIi11i - OoooooooOO
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
def lisp_store_nat_info ( hostname , rloc , port ) :
 oo0o00OO = rloc . print_address_no_iid ( )
 oooooO0O0O = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( oo0o00OO , False ) , port )
 if 62 - 62: I1ii11iIi11i * i1IIi - I1Ii111 * I11i . i1IIi - II111iiii
 o00i11111I1Ii = lisp_nat_info ( oo0o00OO , hostname , port )
 if 39 - 39: oO0o - O0
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ o00i11111I1Ii ]
  lprint ( oooooO0O0O . format ( "Store initial" ) )
  return ( True )
  if 15 - 15: OoooooooOO . OoOoOO00 / iII111i - IiII % iII111i . ooOoO0o
  if 78 - 78: OoOoOO00 / i1IIi
  if 87 - 87: I1ii11iIi11i . O0 / I1ii11iIi11i
  if 35 - 35: IiII % Oo0Ooo * Ii1I . IiII
  if 16 - 16: I1ii11iIi11i % I1IiiI + Ii1I * I11i + i1IIi
  if 14 - 14: iII111i / ooOoO0o % IiII - I1IiiI . Oo0Ooo
 O00OOoOOO0O0O = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( O00OOoOOO0O0O . address == oo0o00OO and O00OOoOOO0O0O . port == port ) :
  O00OOoOOO0O0O . uptime = lisp_get_timestamp ( )
  lprint ( oooooO0O0O . format ( "Refresh existing" ) )
  return ( False )
  if 30 - 30: O0 . OOooOOo
  if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
  if 83 - 83: OoooooooOO
  if 53 - 53: o0oOOo0O0Ooo - Oo0Ooo / IiII + O0
  if 88 - 88: Oo0Ooo % I1Ii111 * O0 - i1IIi * OoO0O00
  if 74 - 74: Oo0Ooo % iIii1I11I1II1 + OOooOOo
  if 50 - 50: OoO0O00 . OoooooooOO
 iI1II11 = None
 for O00OOoOOO0O0O in lisp_nat_state_info [ hostname ] :
  if ( O00OOoOOO0O0O . address == oo0o00OO and O00OOoOOO0O0O . port == port ) :
   iI1II11 = O00OOoOOO0O0O
   break
   if 65 - 65: I1ii11iIi11i + O0 + iII111i + II111iiii
   if 100 - 100: I1Ii111
   if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
 if ( iI1II11 == None ) :
  lprint ( oooooO0O0O . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( iI1II11 )
  lprint ( oooooO0O0O . format ( "Use previous" ) )
  if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
  if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
 O00OO00Oooo = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ o00i11111I1Ii ] + O00OO00Oooo
 return ( True )
 if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
 if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
 if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
 if 74 - 74: OoooooooOO + Ii1I
 if 100 - 100: I1IiiI
 if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
 if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
 if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
 oo0o00OO = rloc . print_address_no_iid ( )
 for O00OOoOOO0O0O in lisp_nat_state_info [ hostname ] :
  if ( O00OOoOOO0O0O . address == oo0o00OO ) : return ( O00OOoOOO0O0O )
  if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
 return ( None )
 if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
 if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
 if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
 if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
 if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
 if 40 - 40: I1ii11iIi11i
 if 76 - 76: Oo0Ooo - I11i
 if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
 if 39 - 39: I1IiiI
 if 8 - 8: IiII * i1IIi * i1IIi * O0
 if 69 - 69: Oo0Ooo
 if 48 - 48: iII111i
 if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
 if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
 if 89 - 89: iII111i
 if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
 if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
 if 77 - 77: OoooooooOO - I11i / I1IiiI % OoOoOO00 - OOooOOo
 if 37 - 37: ooOoO0o
 if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
 if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
 if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
 if 82 - 82: iII111i - I1Ii111 - OoOoOO00
 if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
 if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
 i1iI1I1I1iI1 = [ ]
 oOo0o0o = [ ]
 if ( dest == None ) :
  for O0o00000o0O in lisp_map_resolvers_list . values ( ) :
   oOo0o0o . append ( O0o00000o0O . map_resolver )
   if 39 - 39: IiII / iIii1I11I1II1 * iII111i - OoOoOO00 . I1ii11iIi11i
  i1iI1I1I1iI1 = oOo0o0o
  if ( i1iI1I1I1iI1 == [ ] ) :
   for o00oO0Oo in lisp_map_servers_list . values ( ) :
    i1iI1I1I1iI1 . append ( o00oO0Oo . map_server )
    if 49 - 49: Ii1I . o0oOOo0O0Ooo / iII111i / i1IIi * OOooOOo
    if 10 - 10: ooOoO0o . I1ii11iIi11i / oO0o
  if ( i1iI1I1I1iI1 == [ ] ) : return
 else :
  i1iI1I1I1iI1 . append ( dest )
  if 61 - 61: OoO0O00 . Ii1I * o0oOOo0O0Ooo
  if 2 - 2: OoOoOO00 / O0
  if 87 - 87: I1ii11iIi11i * i1IIi + oO0o % OoO0O00 % iII111i . I11i
  if 65 - 65: II111iiii + Ii1I
  if 46 - 46: o0oOOo0O0Ooo
 II1IIii = { }
 for Ooooo00 in lisp_db_list :
  for iIII in Ooooo00 . rloc_set :
   lisp_update_local_rloc ( iIII )
   if ( iIII . rloc . is_null ( ) ) : continue
   if ( iIII . interface == None ) : continue
   if 17 - 17: OOooOOo
   IiiIIi1 = iIII . rloc . print_address_no_iid ( )
   if ( IiiIIi1 in II1IIii ) : continue
   II1IIii [ IiiIIi1 ] = iIII . interface
   if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
   if 46 - 46: II111iiii * OoO0O00
 if ( II1IIii == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 77 - 77: ooOoO0o * I11i
  return
  if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
  if 76 - 76: iII111i * OoooooooOO
  if 49 - 49: II111iiii - OOooOOo + II111iiii + OoOoOO00
  if 51 - 51: i11iIiiIii
  if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
  if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
 for IiiIIi1 in II1IIii :
  II1i = II1IIii [ IiiIIi1 ]
  OO0o = red ( IiiIIi1 , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( OO0o ,
 II1i ) )
  OoO0o0OOOO = II1i if len ( II1IIii ) > 1 else None
  for dest in i1iI1I1I1iI1 :
   lisp_send_info_request ( lisp_sockets , dest , port , OoO0o0OOOO )
   if 63 - 63: II111iiii - Oo0Ooo
   if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
   if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
   if 78 - 78: IiII - I1IiiI
   if 59 - 59: oO0o + i1IIi - IiII % OOooOOo % iIii1I11I1II1
   if 71 - 71: OoO0O00
 if ( oOo0o0o != [ ] ) :
  for O0o00000o0O in lisp_map_resolvers_list . values ( ) :
   O0o00000o0O . resolve_dns_name ( )
   if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
   if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
 return
 if 54 - 54: Ii1I / I1IiiI
 if 7 - 7: iIii1I11I1II1 . O0 + OOooOOo . Ii1I * Oo0Ooo
 if 25 - 25: I1Ii111 . Oo0Ooo % II111iiii . IiII - O0
 if 18 - 18: oO0o * OOooOOo
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
 if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
 if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
 if 96 - 96: II111iiii % I11i / Ii1I - i11iIiiIii
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 63 - 63: I1IiiI
 if 15 - 15: iIii1I11I1II1 - I1ii11iIi11i % OoO0O00 * II111iiii / I11i + I11i
 if 23 - 23: I1IiiI
 if 51 - 51: i11iIiiIii / ooOoO0o - OoooooooOO + OoOoOO00 + oO0o
 if 57 - 57: iIii1I11I1II1
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 19 - 19: Ii1I / o0oOOo0O0Ooo + O0 / iIii1I11I1II1 + II111iiii
 if 3 - 3: oO0o % OoO0O00 % OOooOOo
 if 64 - 64: o0oOOo0O0Ooo . II111iiii * IiII % Oo0Ooo + I11i - OoooooooOO
 if 58 - 58: ooOoO0o
 if ( value . find ( "." ) != - 1 ) :
  IiiIIi1 = value . split ( "." )
  if ( len ( IiiIIi1 ) != 4 ) : return ( False )
  if 15 - 15: O0 * OOooOOo * I11i + Ii1I * OoooooooOO + OOooOOo
  for o0O00Ooo00oOO in IiiIIi1 :
   if ( o0O00Ooo00oOO . isdigit ( ) == False ) : return ( False )
   if ( int ( o0O00Ooo00oOO ) > 255 ) : return ( False )
   if 60 - 60: i11iIiiIii * O0 + I1ii11iIi11i % IiII + iIii1I11I1II1
  return ( True )
  if 82 - 82: OoO0O00 . I1IiiI + o0oOOo0O0Ooo
  if 52 - 52: oO0o . OOooOOo + iII111i * ooOoO0o + IiII / I1Ii111
  if 88 - 88: OoO0O00 * I1ii11iIi11i - I1IiiI * IiII * Oo0Ooo % OoooooooOO
  if 15 - 15: OOooOOo - I1Ii111 - OOooOOo
  if 73 - 73: iII111i + o0oOOo0O0Ooo % iII111i . Ii1I + OoO0O00 - I1ii11iIi11i
 if ( value . find ( "-" ) != - 1 ) :
  IiiIIi1 = value . split ( "-" )
  for IiIIi1IiiIiI in [ "N" , "S" , "W" , "E" ] :
   if ( IiIIi1IiiIiI in IiiIIi1 ) :
    if ( len ( IiiIIi1 ) < 8 ) : return ( False )
    return ( True )
    if 47 - 47: OoO0O00 * O0 % iIii1I11I1II1
    if 92 - 92: IiII
    if 68 - 68: OOooOOo . IiII / iIii1I11I1II1 % i11iIiiIii
    if 74 - 74: iII111i + i11iIiiIii
    if 95 - 95: Ii1I
    if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
    if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
 if ( value . find ( "-" ) != - 1 ) :
  IiiIIi1 = value . split ( "-" )
  if ( len ( IiiIIi1 ) != 3 ) : return ( False )
  if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
  for I1iiI1Iii1I in IiiIIi1 :
   try : int ( I1iiI1Iii1I , 16 )
   except : return ( False )
   if 57 - 57: IiII % OoooooooOO . II111iiii % o0oOOo0O0Ooo
  return ( True )
  if 7 - 7: OoooooooOO / Oo0Ooo / oO0o
  if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
  if 49 - 49: iII111i / iII111i - OoOoOO00
  if 89 - 89: ooOoO0o
  if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
 if ( value . find ( ":" ) != - 1 ) :
  IiiIIi1 = value . split ( ":" )
  if ( len ( IiiIIi1 ) < 2 ) : return ( False )
  if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
  i1Iiii1I1i1 = False
  OO = 0
  for I1iiI1Iii1I in IiiIIi1 :
   OO += 1
   if ( I1iiI1Iii1I == "" ) :
    if ( i1Iiii1I1i1 ) :
     if ( len ( IiiIIi1 ) == OO ) : break
     if ( OO > 2 ) : return ( False )
     if 71 - 71: OoooooooOO + oO0o
    i1Iiii1I1i1 = True
    continue
    if 65 - 65: II111iiii
   try : int ( I1iiI1Iii1I , 16 )
   except : return ( False )
   if 87 - 87: oO0o / OoO0O00 - oO0o
  return ( True )
  if 69 - 69: i11iIiiIii
  if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
  if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
  if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
  if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
 if ( value [ 0 ] == "+" ) :
  IiiIIi1 = value [ 1 : : ]
  for O0OoO0Oo0oO0o in IiiIIi1 :
   if ( O0OoO0Oo0oO0o . isdigit ( ) == False ) : return ( False )
   if 68 - 68: o0oOOo0O0Ooo + IiII / iII111i - i11iIiiIii / OOooOOo
  return ( True )
  if 62 - 62: I1IiiI
 return ( False )
 if 42 - 42: II111iiii
 if 49 - 49: OoooooooOO
 if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
 if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
 if 6 - 6: oO0o / II111iiii
 if 23 - 23: IiII - OoooooooOO / oO0o
 if 69 - 69: O0 - OoooooooOO
 if 31 - 31: o0oOOo0O0Ooo . i1IIi - i1IIi % i1IIi - iIii1I11I1II1
 if 50 - 50: IiII - OOooOOo % OoOoOO00
 if 66 - 66: IiII * i11iIiiIii
 if 64 - 64: i11iIiiIii . I1Ii111 % i11iIiiIii % I11i
 if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
def lisp_process_api ( process , lisp_socket , data_structure ) :
 o0Oo , I1I1i = data_structure . split ( "%" )
 if 46 - 46: o0oOOo0O0Ooo % i11iIiiIii * ooOoO0o / i1IIi * i1IIi
 lprint ( "Process API request '{}', parameters: '{}'" . format ( o0Oo ,
 I1I1i ) )
 if 71 - 71: I1IiiI + i1IIi
 oo00000ooOooO = [ ]
 if ( o0Oo == "map-cache" ) :
  if ( I1I1i == "" ) :
   oo00000ooOooO = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , oo00000ooOooO )
  else :
   oo00000ooOooO = lisp_process_api_map_cache_entry ( json . loads ( I1I1i ) )
   if 96 - 96: I1Ii111 . Oo0Ooo % I11i % I1ii11iIi11i % II111iiii * IiII
   if 69 - 69: OoO0O00 * Oo0Ooo * iII111i
 if ( o0Oo == "site-cache" ) :
  if ( I1I1i == "" ) :
   oo00000ooOooO = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 oo00000ooOooO )
  else :
   oo00000ooOooO = lisp_process_api_site_cache_entry ( json . loads ( I1I1i ) )
   if 2 - 2: iII111i - Ii1I
   if 1 - 1: I1Ii111 / oO0o + iIii1I11I1II1
 if ( o0Oo == "map-server" ) :
  I1I1i = { } if ( I1I1i == "" ) else json . loads ( I1I1i )
  oo00000ooOooO = lisp_process_api_ms_or_mr ( True , I1I1i )
  if 88 - 88: o0oOOo0O0Ooo
 if ( o0Oo == "map-resolver" ) :
  I1I1i = { } if ( I1I1i == "" ) else json . loads ( I1I1i )
  oo00000ooOooO = lisp_process_api_ms_or_mr ( False , I1I1i )
  if 3 - 3: i11iIiiIii / I1ii11iIi11i
 if ( o0Oo == "database-mapping" ) :
  oo00000ooOooO = lisp_process_api_database_mapping ( )
  if 49 - 49: IiII
  if 1 - 1: oO0o / I11i
  if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
  if 28 - 28: OOooOOo - O0 - O0 % i11iIiiIii * OoooooooOO
  if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
 oo00000ooOooO = json . dumps ( oo00000ooOooO )
 OoOO0o00OOO0o = lisp_api_ipc ( process , oo00000ooOooO )
 lisp_ipc ( OoOO0o00OOO0o , lisp_socket , "lisp-core" )
 return
 if 24 - 24: O0
 if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
 if 65 - 65: i11iIiiIii
 if 46 - 46: i11iIiiIii
 if 70 - 70: i1IIi + o0oOOo0O0Ooo
 if 44 - 44: iII111i . II111iiii % o0oOOo0O0Ooo
 if 29 - 29: i11iIiiIii * i1IIi
def lisp_process_api_map_cache ( mc , data ) :
 if 36 - 36: OoO0O00 * I11i . ooOoO0o
 if 50 - 50: oO0o * OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
 if 55 - 55: II111iiii - IiII
 if 24 - 24: oO0o % Ii1I / i1IIi
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 84 - 84: i1IIi
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 53 - 53: OoooooooOO - i1IIi - Ii1I
 if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
 if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
 if 34 - 34: Ii1I
 if 5 - 5: II111iiii . I1ii11iIi11i
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 85 - 85: I1Ii111 . IiII + II111iiii
 if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
 if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
 if 87 - 87: OOooOOo
 if 44 - 44: Oo0Ooo + iIii1I11I1II1
 if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
def lisp_gather_map_cache_data ( mc , data ) :
 I1iII11ii1 = { }
 I1iII11ii1 [ "instance-id" ] = str ( mc . eid . instance_id )
 I1iII11ii1 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  I1iII11ii1 [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
 I1iII11ii1 [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 I1iII11ii1 [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 I1iII11ii1 [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 I1iII11ii1 [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 10 - 10: O0 / I11i
 if 29 - 29: i11iIiiIii % I11i
 if 49 - 49: I11i
 if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
 if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
 ooo0oo = [ ]
 for oOo00O in mc . rloc_set :
  i11iII1IiI = { }
  if ( oOo00O . rloc_exists ( ) ) :
   i11iII1IiI [ "address" ] = oOo00O . rloc . print_address_no_iid ( )
   if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
   if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
  if ( oOo00O . translated_port != 0 ) :
   i11iII1IiI [ "encap-port" ] = str ( oOo00O . translated_port )
   if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
  i11iII1IiI [ "state" ] = oOo00O . print_state ( )
  if ( oOo00O . geo ) : i11iII1IiI [ "geo" ] = oOo00O . geo . print_geo ( )
  if ( oOo00O . elp ) : i11iII1IiI [ "elp" ] = oOo00O . elp . print_elp ( False )
  if ( oOo00O . rle ) : i11iII1IiI [ "rle" ] = oOo00O . rle . print_rle ( False , False )
  if ( oOo00O . json ) : i11iII1IiI [ "json" ] = oOo00O . json . print_json ( False )
  if ( oOo00O . rloc_name ) : i11iII1IiI [ "rloc-name" ] = oOo00O . rloc_name
  i1I1IiiIi = oOo00O . stats . get_stats ( False , False )
  if ( i1I1IiiIi ) : i11iII1IiI [ "stats" ] = i1I1IiiIi
  i11iII1IiI [ "uptime" ] = lisp_print_elapsed ( oOo00O . uptime )
  i11iII1IiI [ "upriority" ] = str ( oOo00O . priority )
  i11iII1IiI [ "uweight" ] = str ( oOo00O . weight )
  i11iII1IiI [ "mpriority" ] = str ( oOo00O . mpriority )
  i11iII1IiI [ "mweight" ] = str ( oOo00O . mweight )
  iII1IIiI1IiI1III = oOo00O . last_rloc_probe_reply
  if ( iII1IIiI1IiI1III ) :
   i11iII1IiI [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( iII1IIiI1IiI1III )
   i11iII1IiI [ "rloc-probe-rtt" ] = str ( oOo00O . rloc_probe_rtt )
   if 45 - 45: iII111i
  i11iII1IiI [ "rloc-hop-count" ] = oOo00O . rloc_probe_hops
  i11iII1IiI [ "recent-rloc-hop-counts" ] = oOo00O . recent_rloc_probe_hops
  if 9 - 9: OOooOOo * o0oOOo0O0Ooo / I11i . i11iIiiIii
  i1iI11Ii1 = [ ]
  for i1i1I1I1 in oOo00O . recent_rloc_probe_rtts : i1iI11Ii1 . append ( str ( i1i1I1I1 ) )
  i11iII1IiI [ "recent-rloc-probe-rtts" ] = i1iI11Ii1
  if 75 - 75: OoO0O00
  ooo0oo . append ( i11iII1IiI )
  if 34 - 34: Oo0Ooo - OOooOOo . OOooOOo . oO0o
 I1iII11ii1 [ "rloc-set" ] = ooo0oo
 if 18 - 18: iII111i . I1IiiI . ooOoO0o * oO0o / OoooooooOO
 data . append ( I1iII11ii1 )
 return ( [ True , data ] )
 if 85 - 85: i1IIi
 if 79 - 79: I11i - I11i
 if 25 - 25: OOooOOo / O0 / iIii1I11I1II1 + II111iiii * Ii1I
 if 74 - 74: i1IIi . I1Ii111 / O0 + Oo0Ooo * OOooOOo
 if 90 - 90: I1IiiI * II111iiii . Oo0Ooo % I1IiiI
 if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
 if 98 - 98: OoO0O00 + oO0o - II111iiii
def lisp_process_api_map_cache_entry ( parms ) :
 o0OoO0000o = parms [ "instance-id" ]
 o0OoO0000o = 0 if ( o0OoO0000o == "" ) else int ( o0OoO0000o )
 if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
 if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
 if 77 - 77: iIii1I11I1II1 * Oo0Ooo . IiII / oO0o + O0
 if 76 - 76: iII111i + o0oOOo0O0Ooo - OoooooooOO * oO0o % OoooooooOO - O0
 OOo0O0O0o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 OOo0O0O0o0 . store_prefix ( parms [ "eid-prefix" ] )
 oO0o0 = OOo0O0O0o0
 oo00Oo0 = OOo0O0O0o0
 if 18 - 18: Ii1I
 if 82 - 82: OoOoOO00 + OoO0O00 - IiII / ooOoO0o
 if 70 - 70: OoO0O00
 if 43 - 43: ooOoO0o + OOooOOo + II111iiii - I1IiiI
 if 58 - 58: I11i
 O0o00oOOOO00 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 if ( parms . has_key ( "group-prefix" ) ) :
  O0o00oOOOO00 . store_prefix ( parms [ "group-prefix" ] )
  oO0o0 = O0o00oOOOO00
  if 94 - 94: Oo0Ooo
  if 39 - 39: I11i - oO0o % iII111i - ooOoO0o - OoOoOO00
 oo00000ooOooO = [ ]
 IiiiiII1i = lisp_map_cache_lookup ( oo00Oo0 , oO0o0 )
 if ( IiiiiII1i ) : O00O00o0O0O , oo00000ooOooO = lisp_process_api_map_cache ( IiiiiII1i , oo00000ooOooO )
 return ( oo00000ooOooO )
 if 8 - 8: i1IIi % i1IIi % OoooooooOO % i1IIi . iIii1I11I1II1
 if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
 if 58 - 58: II111iiii * oO0o - i1IIi . I11i
 if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
 if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
 if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
 if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
def lisp_process_api_site_cache ( se , data ) :
 if 31 - 31: i1IIi * Ii1I
 if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
 if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
 if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 52 - 52: OOooOOo . OoOoOO00 - ooOoO0o % i1IIi
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 15 - 15: oO0o
 if 6 - 6: oO0o . iIii1I11I1II1 - I1ii11iIi11i % IiII
 if 58 - 58: iII111i * oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o
 if 63 - 63: oO0o . IiII . o0oOOo0O0Ooo
 if 16 - 16: iII111i . I11i - Oo0Ooo / I1IiiI + OoOoOO00
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 14 - 14: iIii1I11I1II1 / i11iIiiIii - o0oOOo0O0Ooo . iII111i * OoO0O00
 if 5 - 5: Ii1I + OoOoOO00 % I11i + IiII
 if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
 if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
 if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
 if 7 - 7: I1Ii111 % i1IIi . I11i . O0 / i1IIi
 if 56 - 56: Oo0Ooo
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 ii1i1II11II1i = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 OOIIi1Iii1I = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  ii1i1II11II1i . store_address ( data [ "address" ] )
  if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
  if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
 i11II = { }
 if ( ms_or_mr ) :
  for o00oO0Oo in lisp_map_servers_list . values ( ) :
   if ( OOIIi1Iii1I ) :
    if ( OOIIi1Iii1I != o00oO0Oo . dns_name ) : continue
   else :
    if ( ii1i1II11II1i . is_exact_match ( o00oO0Oo . map_server ) == False ) : continue
    if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
    if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
   i11II [ "dns-name" ] = o00oO0Oo . dns_name
   i11II [ "address" ] = o00oO0Oo . map_server . print_address_no_iid ( )
   i11II [ "ms-name" ] = "" if o00oO0Oo . ms_name == None else o00oO0Oo . ms_name
   return ( [ i11II ] )
   if 70 - 70: Oo0Ooo - I11i / I1ii11iIi11i % OoO0O00 % II111iiii
 else :
  for O0o00000o0O in lisp_map_resolvers_list . values ( ) :
   if ( OOIIi1Iii1I ) :
    if ( OOIIi1Iii1I != O0o00000o0O . dns_name ) : continue
   else :
    if ( ii1i1II11II1i . is_exact_match ( O0o00000o0O . map_resolver ) == False ) : continue
    if 72 - 72: i11iIiiIii * I11i
    if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
   i11II [ "dns-name" ] = O0o00000o0O . dns_name
   i11II [ "address" ] = O0o00000o0O . map_resolver . print_address_no_iid ( )
   i11II [ "mr-name" ] = "" if O0o00000o0O . mr_name == None else O0o00000o0O . mr_name
   return ( [ i11II ] )
   if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
   if 64 - 64: OoooooooOO
 return ( [ ] )
 if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
 if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
 if 71 - 71: O0 - OoooooooOO
 if 82 - 82: i11iIiiIii * II111iiii % IiII
 if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
 if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
 if 67 - 67: iII111i
 if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
def lisp_process_api_database_mapping ( ) :
 oo00000ooOooO = [ ]
 if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
 for Ooooo00 in lisp_db_list :
  I1iII11ii1 = { }
  I1iII11ii1 [ "eid-prefix" ] = Ooooo00 . eid . print_prefix ( )
  if ( Ooooo00 . group . is_null ( ) == False ) :
   I1iII11ii1 [ "group-prefix" ] = Ooooo00 . group . print_prefix ( )
   if 60 - 60: i1IIi / iII111i
   if 10 - 10: I1Ii111 / OoOoOO00 * Ii1I % o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i
  ooOOo = [ ]
  for i11iII1IiI in Ooooo00 . rloc_set :
   oOo00O = { }
   if ( i11iII1IiI . rloc . is_null ( ) == False ) :
    oOo00O [ "rloc" ] = i11iII1IiI . rloc . print_address_no_iid ( )
    if 2 - 2: iIii1I11I1II1
   if ( i11iII1IiI . rloc_name != None ) : oOo00O [ "rloc-name" ] = i11iII1IiI . rloc_name
   if ( i11iII1IiI . interface != None ) : oOo00O [ "interface" ] = i11iII1IiI . interface
   oo0OoOOo = i11iII1IiI . translated_rloc
   if ( oo0OoOOo . is_null ( ) == False ) :
    oOo00O [ "translated-rloc" ] = oo0OoOOo . print_address_no_iid ( )
    if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
   if ( oOo00O != { } ) : ooOOo . append ( oOo00O )
   if 65 - 65: Ii1I % i11iIiiIii
   if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
   if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
   if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
   if 88 - 88: iII111i
  I1iII11ii1 [ "rlocs" ] = ooOOo
  if 94 - 94: OoooooooOO
  if 32 - 32: I1ii11iIi11i
  if 8 - 8: I11i * i11iIiiIii - ooOoO0o
  if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
  oo00000ooOooO . append ( I1iII11ii1 )
  if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
 return ( oo00000ooOooO )
 if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
 if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
 if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
 if 42 - 42: II111iiii . iII111i
 if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
 if 64 - 64: oO0o / IiII
 if 86 - 86: I11i
def lisp_gather_site_cache_data ( se , data ) :
 I1iII11ii1 = { }
 I1iII11ii1 [ "site-name" ] = se . site . site_name
 I1iII11ii1 [ "instance-id" ] = str ( se . eid . instance_id )
 I1iII11ii1 [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  I1iII11ii1 [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 36 - 36: o0oOOo0O0Ooo / OoO0O00
 I1iII11ii1 [ "registered" ] = "yes" if se . registered else "no"
 I1iII11ii1 [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 I1iII11ii1 [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
 IiiIIi1 = se . last_registerer
 IiiIIi1 = "none" if IiiIIi1 . is_null ( ) else IiiIIi1 . print_address ( )
 I1iII11ii1 [ "last-registerer" ] = IiiIIi1
 I1iII11ii1 [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 I1iII11ii1 [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 I1iII11ii1 [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  I1iII11ii1 [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
  if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
  if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
  if 12 - 12: I1IiiI . OOooOOo % Oo0Ooo
  if 86 - 86: i11iIiiIii
 ooo0oo = [ ]
 for oOo00O in se . registered_rlocs :
  i11iII1IiI = { }
  i11iII1IiI [ "address" ] = oOo00O . rloc . print_address_no_iid ( ) if oOo00O . rloc_exists ( ) else "none"
  if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
  if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
  if ( oOo00O . geo ) : i11iII1IiI [ "geo" ] = oOo00O . geo . print_geo ( )
  if ( oOo00O . elp ) : i11iII1IiI [ "elp" ] = oOo00O . elp . print_elp ( False )
  if ( oOo00O . rle ) : i11iII1IiI [ "rle" ] = oOo00O . rle . print_rle ( False , True )
  if ( oOo00O . json ) : i11iII1IiI [ "json" ] = oOo00O . json . print_json ( False )
  if ( oOo00O . rloc_name ) : i11iII1IiI [ "rloc-name" ] = oOo00O . rloc_name
  i11iII1IiI [ "uptime" ] = lisp_print_elapsed ( oOo00O . uptime )
  i11iII1IiI [ "upriority" ] = str ( oOo00O . priority )
  i11iII1IiI [ "uweight" ] = str ( oOo00O . weight )
  i11iII1IiI [ "mpriority" ] = str ( oOo00O . mpriority )
  i11iII1IiI [ "mweight" ] = str ( oOo00O . mweight )
  if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
  ooo0oo . append ( i11iII1IiI )
  if 79 - 79: I11i - II111iiii
 I1iII11ii1 [ "registered-rlocs" ] = ooo0oo
 if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
 data . append ( I1iII11ii1 )
 return ( [ True , data ] )
 if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
 if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
 if 44 - 44: I1IiiI * IiII . OoooooooOO
 if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
 if 10 - 10: i1IIi + o0oOOo0O0Ooo
 if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
 if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
def lisp_process_api_site_cache_entry ( parms ) :
 o0OoO0000o = parms [ "instance-id" ]
 o0OoO0000o = 0 if ( o0OoO0000o == "" ) else int ( o0OoO0000o )
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 if 2 - 2: I11i
 if 12 - 12: i1IIi . I1Ii111
 if 99 - 99: Oo0Ooo / i11iIiiIii
 OOo0O0O0o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 OOo0O0O0o0 . store_prefix ( parms [ "eid-prefix" ] )
 if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
 if 42 - 42: iII111i / Oo0Ooo
 if 14 - 14: O0 . Oo0Ooo
 if 8 - 8: i11iIiiIii
 if 80 - 80: I1ii11iIi11i + Ii1I
 O0o00oOOOO00 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 if ( parms . has_key ( "group-prefix" ) ) :
  O0o00oOOOO00 . store_prefix ( parms [ "group-prefix" ] )
  if 16 - 16: i11iIiiIii * Oo0Ooo
  if 76 - 76: iII111i . oO0o - i1IIi
 oo00000ooOooO = [ ]
 o00Ii = lisp_site_eid_lookup ( OOo0O0O0o0 , O0o00oOOOO00 , False )
 if ( o00Ii ) : lisp_gather_site_cache_data ( o00Ii , oo00000ooOooO )
 return ( oo00000ooOooO )
 if 94 - 94: O0 % iII111i
 if 90 - 90: IiII
 if 1 - 1: I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % oO0o + Ii1I
 if 46 - 46: I1IiiI + OoO0O00 - Oo0Ooo
 if 13 - 13: OoOoOO00
 if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
 if 90 - 90: oO0o * I1Ii111 / O0
def lisp_get_interface_instance_id ( device , source_eid ) :
 II1i = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  II1i = lisp_myinterfaces [ device ]
  if 15 - 15: o0oOOo0O0Ooo * O0 . OOooOOo / Oo0Ooo
  if 28 - 28: OoooooooOO + OoooooooOO
  if 27 - 27: I11i . oO0o / OoooooooOO - OoO0O00 . I11i
  if 15 - 15: II111iiii * OoO0O00
  if 33 - 33: OoooooooOO . o0oOOo0O0Ooo . I1IiiI / I1ii11iIi11i . OoOoOO00
  if 58 - 58: Ii1I
 if ( II1i == None or II1i . instance_id == None ) :
  return ( lisp_default_iid )
  if 20 - 20: OOooOOo
  if 93 - 93: i1IIi . IiII % O0 * iII111i
  if 84 - 84: I11i
  if 99 - 99: I1ii11iIi11i
  if 78 - 78: I1Ii111 . IiII - OOooOOo
  if 93 - 93: iIii1I11I1II1
  if 33 - 33: OOooOOo . i1IIi
  if 63 - 63: II111iiii . oO0o * IiII
  if 73 - 73: iII111i . i1IIi + oO0o + OOooOOo + ooOoO0o - iIii1I11I1II1
 o0OoO0000o = II1i . get_instance_id ( )
 if ( source_eid == None ) : return ( o0OoO0000o )
 if 47 - 47: I11i
 oOo0o0OoO = source_eid . instance_id
 III1I111i = None
 for II1i in lisp_multi_tenant_interfaces :
  if ( II1i . device != device ) : continue
  O000O0o00o0o = II1i . multi_tenant_eid
  source_eid . instance_id = O000O0o00o0o . instance_id
  if ( source_eid . is_more_specific ( O000O0o00o0o ) == False ) : continue
  if ( III1I111i == None or III1I111i . multi_tenant_eid . mask_len < O000O0o00o0o . mask_len ) :
   III1I111i = II1i
   if 41 - 41: Ii1I * iII111i % Oo0Ooo
   if 61 - 61: OoooooooOO % iII111i - O0
 source_eid . instance_id = oOo0o0OoO
 if 62 - 62: iIii1I11I1II1
 if ( III1I111i == None ) : return ( o0OoO0000o )
 return ( III1I111i . get_instance_id ( ) )
 if 14 - 14: I1Ii111
 if 95 - 95: II111iiii / o0oOOo0O0Ooo * OOooOOo
 if 81 - 81: i11iIiiIii / iIii1I11I1II1
 if 73 - 73: i11iIiiIii . I1ii11iIi11i * OoOoOO00
 if 95 - 95: i1IIi + iIii1I11I1II1 . I1Ii111 / I1Ii111
 if 84 - 84: Oo0Ooo . OoO0O00 * IiII
 if 95 - 95: OoO0O00
 if 100 - 100: II111iiii
 if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( lisp_myinterfaces . has_key ( device ) == False ) : return ( None )
 if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
 II1i = lisp_myinterfaces [ device ]
 I1iiI1II = device if II1i . dynamic_eid_device == None else II1i . dynamic_eid_device
 if 95 - 95: I1Ii111 * OoooooooOO + iII111i
 if 10 - 10: i1IIi - O0 / Oo0Ooo
 if ( II1i . does_dynamic_eid_match ( eid ) ) : return ( I1iiI1II )
 return ( None )
 if 54 - 54: OoO0O00
 if 38 - 38: II111iiii + o0oOOo0O0Ooo * I11i + I1Ii111 - II111iiii . OOooOOo
 if 38 - 38: I1ii11iIi11i % OOooOOo + iII111i / Oo0Ooo / IiII / oO0o
 if 2 - 2: iIii1I11I1II1
 if 9 - 9: I1Ii111 / IiII
 if 33 - 33: o0oOOo0O0Ooo + oO0o . o0oOOo0O0Ooo . I11i * OoooooooOO + iIii1I11I1II1
 if 64 - 64: OoooooooOO . Ii1I
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 38 - 38: Oo0Ooo
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 64 - 64: ooOoO0o % i11iIiiIii
 I1II1I1Ii1 = lisp_process_rloc_probe_timer
 i1I1I11II = threading . Timer ( interval , I1II1I1Ii1 , [ lisp_sockets ] )
 lisp_rloc_probe_timer = i1I1I11II
 i1I1I11II . start ( )
 return
 if 54 - 54: i1IIi % iII111i
 if 16 - 16: II111iiii - Oo0Ooo
 if 44 - 44: OOooOOo / Oo0Ooo - I1ii11iIi11i + I11i . oO0o
 if 85 - 85: iIii1I11I1II1 / Ii1I
 if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
 if 97 - 97: I1Ii111 + I1ii11iIi11i
 if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for ii1i1I1111ii in lisp_rloc_probe_list :
  ooO0O0oo0O = lisp_rloc_probe_list [ ii1i1I1111ii ]
  lprint ( "RLOC {}:" . format ( ii1i1I1111ii ) )
  for i11iII1IiI , oOo , i11ii in ooO0O0oo0O :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( i11iII1IiI ) ) , oOo . print_prefix ( ) ,
 i11ii . print_prefix ( ) , i11iII1IiI . translated_port ) )
   if 46 - 46: ooOoO0o / OOooOOo * I1Ii111 % OoOoOO00 . ooOoO0o - i1IIi
   if 11 - 11: OoOoOO00 - II111iiii + I1Ii111 + IiII + OOooOOo - ooOoO0o
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 12 - 12: Ii1I - oO0o % I1ii11iIi11i / oO0o
 if 14 - 14: OOooOOo * iII111i . IiII + i1IIi % i1IIi
 if 11 - 11: I1ii11iIi11i + iIii1I11I1II1 - I1Ii111 * iIii1I11I1II1 * IiII + oO0o
 if 6 - 6: I1Ii111 * OOooOOo + i1IIi - Ii1I / oO0o
 if 81 - 81: I1Ii111 % oO0o * i1IIi * OoooooooOO / Oo0Ooo
 if 70 - 70: I1IiiI
 if 35 - 35: i11iIiiIii
 if 59 - 59: ooOoO0o . iII111i - II111iiii
 if 30 - 30: o0oOOo0O0Ooo % iII111i - i11iIiiIii
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 25 - 25: i11iIiiIii + OoOoOO00 + oO0o / Ii1I * Oo0Ooo + Oo0Ooo
 if 26 - 26: I1IiiI % I1ii11iIi11i + o0oOOo0O0Ooo / I1ii11iIi11i - I1IiiI
 if 55 - 55: OoooooooOO
 if 2 - 2: Oo0Ooo + I11i / OOooOOo + OOooOOo
 oOo00O , oOo , i11ii = eid_list [ 0 ]
 O0O = [ lisp_print_eid_tuple ( oOo , i11ii ) ]
 if 13 - 13: OOooOOo / IiII
 for oOo00O , oOo , i11ii in eid_list [ 1 : : ] :
  oOo00O . state = LISP_RLOC_UNREACH_STATE
  oOo00O . last_state_change = lisp_get_timestamp ( )
  O0O . append ( lisp_print_eid_tuple ( oOo , i11ii ) )
  if 16 - 16: I1Ii111 / OoOoOO00 - I1IiiI / oO0o + OoO0O00
  if 38 - 38: O0 * iIii1I11I1II1 - oO0o
 IiI1Iiiii1Iii = bold ( "unreachable" , False )
 o0O00oo0O = red ( oOo00O . rloc . print_address_no_iid ( ) , False )
 if 31 - 31: I1IiiI
 for OOo0O0O0o0 in O0O :
  oOo = green ( OOo0O0O0o0 , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( o0O00oo0O , IiI1Iiiii1Iii , oOo ) )
  if 21 - 21: oO0o - IiII
  if 61 - 61: o0oOOo0O0Ooo
  if 53 - 53: Ii1I / oO0o . I11i
  if 62 - 62: O0 + I1ii11iIi11i + Ii1I / i1IIi
  if 77 - 77: O0
  if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
 for oOo00O , oOo , i11ii in eid_list :
  IiiiiII1i = lisp_map_cache . lookup_cache ( oOo , True )
  if ( IiiiiII1i ) : lisp_write_ipc_map_cache ( True , IiiiiII1i )
  if 36 - 36: II111iiii
 return
 if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
 if 7 - 7: i11iIiiIii
 if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
 if 41 - 41: IiII % II111iiii
 if 99 - 99: IiII - O0
 if 59 - 59: iII111i % O0 + OOooOOo * ooOoO0o
 if 27 - 27: I1Ii111 % i11iIiiIii * I1IiiI
 if 19 - 19: OoOoOO00 / o0oOOo0O0Ooo - iII111i / OoO0O00
 if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
 if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 89 - 89: Ii1I * Oo0Ooo / I1Ii111 * I1ii11iIi11i + O0 * Oo0Ooo
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 74 - 74: I11i . I11i
 if 74 - 74: OoOoOO00 * ooOoO0o * I1Ii111
 if 56 - 56: iIii1I11I1II1 * OoO0O00 - oO0o * Ii1I
 if 62 - 62: i1IIi + I11i / OOooOOo - OoooooooOO % i1IIi . I1IiiI
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 13 - 13: O0 * iII111i
 if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
 if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
 if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
 i11111ii11I11 = lisp_get_default_route_next_hops ( )
 if 3 - 3: Ii1I % iIii1I11I1II1 - I1Ii111 . oO0o . iII111i / o0oOOo0O0Ooo
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 8 - 8: O0 - I1Ii111
 if 82 - 82: iII111i + II111iiii
 if 29 - 29: O0 % Ii1I * ooOoO0o % O0
 if 83 - 83: oO0o
 if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
 OO = 0
 OOO0oOooOOo00 = bold ( "RLOC-probe" , False )
 for oo0O in lisp_rloc_probe_list . values ( ) :
  if 78 - 78: iII111i % i1IIi
  if 90 - 90: Ii1I * I11i + iII111i
  if 11 - 11: I1ii11iIi11i % IiII + OOooOOo . I1Ii111
  if 45 - 45: o0oOOo0O0Ooo / OOooOOo % i1IIi * Ii1I / i11iIiiIii
  if 89 - 89: ooOoO0o
  O0O00OOoo00 = None
  for i1iI1Iii , OOo0O0O0o0 , O0o00oOOOO00 in oo0O :
   oo0o00OO = i1iI1Iii . rloc . print_address_no_iid ( )
   if 20 - 20: I11i
   if 37 - 37: I1Ii111
   if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
   if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
   ii1iI1 , iiIiiIi1II1ii , o00oo0 = lisp_allow_gleaning ( OOo0O0O0o0 , None , i1iI1Iii )
   if ( ii1iI1 and iiIiiIi1II1ii == False ) :
    oOo = green ( OOo0O0O0o0 . print_address ( ) , False )
    oo0o00OO += ":{}" . format ( i1iI1Iii . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( oo0o00OO , False ) , oOo ) )
    if 33 - 33: I1IiiI . OoooooooOO - o0oOOo0O0Ooo - i11iIiiIii * ooOoO0o % OOooOOo
    continue
    if 27 - 27: i11iIiiIii . OoO0O00 * I1ii11iIi11i * I1ii11iIi11i + ooOoO0o / OoO0O00
    if 26 - 26: I1IiiI + OoooooooOO * iII111i * iII111i - Ii1I - OOooOOo
    if 44 - 44: ooOoO0o % iII111i - o0oOOo0O0Ooo
    if 94 - 94: OoooooooOO * iIii1I11I1II1 + OOooOOo % I11i
    if 32 - 32: i11iIiiIii % OoOoOO00 % O0 / o0oOOo0O0Ooo + ooOoO0o
    if 4 - 4: OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
    if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
   if ( i1iI1Iii . down_state ( ) ) : continue
   if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
   if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
   if 89 - 89: I1Ii111
   if 29 - 29: I11i * ooOoO0o - OoooooooOO
   if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
   if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
   if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
   if 73 - 73: OoooooooOO
   if 25 - 25: i1IIi . II111iiii . I1Ii111
   if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
   if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
   if ( O0O00OOoo00 ) :
    i1iI1Iii . last_rloc_probe_nonce = O0O00OOoo00 . last_rloc_probe_nonce
    if 61 - 61: I1ii11iIi11i
    if ( O0O00OOoo00 . translated_port == i1iI1Iii . translated_port and O0O00OOoo00 . rloc_name == i1iI1Iii . rloc_name ) :
     if 12 - 12: OoO0O00
     oOo = green ( lisp_print_eid_tuple ( OOo0O0O0o0 , O0o00oOOOO00 ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( oo0o00OO , False ) , oOo ) )
     if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
     continue
     if 7 - 7: Oo0Ooo
     if 38 - 38: Oo0Ooo - I1ii11iIi11i
     if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
   iiIIII1I1ii = None
   oOo00O = None
   while ( True ) :
    oOo00O = i1iI1Iii if oOo00O == None else oOo00O . next_rloc
    if ( oOo00O == None ) : break
    if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
    if 3 - 3: Ii1I
    if 71 - 71: iIii1I11I1II1 . OOooOOo / I11i / i1IIi
    if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
    if 86 - 86: Oo0Ooo
    if ( oOo00O . rloc_next_hop != None ) :
     if ( oOo00O . rloc_next_hop not in i11111ii11I11 ) :
      if ( oOo00O . up_state ( ) ) :
       OooOOOoOoo0O0 , IiI1Ii = oOo00O . rloc_next_hop
       oOo00O . state = LISP_RLOC_UNREACH_STATE
       oOo00O . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( oOo00O . rloc , False )
       if 97 - 97: I1IiiI
      IiI1Iiiii1Iii = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( IiI1Ii , OooOOOoOoo0O0 ,
 red ( oo0o00OO , False ) , IiI1Iiiii1Iii ) )
      continue
      if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
      if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
      if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
      if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
      if 64 - 64: I1IiiI % ooOoO0o
      if 72 - 72: O0 * II111iiii % OoO0O00 - I1IiiI * OOooOOo
    I1IIII = oOo00O . last_rloc_probe
    O0o0O0OoOOoO = 0 if I1IIII == None else time . time ( ) - I1IIII
    if ( oOo00O . unreach_state ( ) and O0o0O0OoOOoO < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( oo0o00OO , False ) ) )
     if 66 - 66: iIii1I11I1II1 - Oo0Ooo % OoooooooOO % O0
     continue
     if 33 - 33: I1Ii111 / II111iiii / II111iiii
     if 15 - 15: O0 * OoooooooOO - O0 + OoooooooOO
     if 40 - 40: O0 * OoooooooOO - oO0o + iIii1I11I1II1 * OOooOOo + I1ii11iIi11i
     if 43 - 43: OoO0O00 . O0
     if 36 - 36: I11i
     if 28 - 28: ooOoO0o
    Oo0ooO0O0o00o = lisp_get_echo_nonce ( None , oo0o00OO )
    if ( Oo0ooO0O0o00o and Oo0ooO0O0o00o . request_nonce_timeout ( ) ) :
     oOo00O . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     oOo00O . last_state_change = lisp_get_timestamp ( )
     IiI1Iiiii1Iii = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( oo0o00OO , False ) , IiI1Iiiii1Iii ) )
     if 1 - 1: IiII / OoO0O00 * oO0o - I1Ii111 . OoOoOO00
     lisp_update_rtr_updown ( oOo00O . rloc , False )
     continue
     if 85 - 85: i11iIiiIii + OoOoOO00
     if 4 - 4: OOooOOo . OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
     if 60 - 60: OOooOOo . Ii1I
     if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
     if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
     if 38 - 38: IiII / I11i / IiII * iII111i
    if ( Oo0ooO0O0o00o and Oo0ooO0O0o00o . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( oo0o00OO , False ) ) )
     if 30 - 30: oO0o
     continue
     if 30 - 30: IiII / OoO0O00
     if 89 - 89: oO0o . OoOoOO00 . IiII / iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00
     if 86 - 86: OoooooooOO - iIii1I11I1II1 . OoO0O00 * Ii1I / I1Ii111 + I1Ii111
     if 52 - 52: iIii1I11I1II1 % OoO0O00 - IiII % i11iIiiIii - o0oOOo0O0Ooo
     if 25 - 25: Oo0Ooo - OOooOOo . i1IIi * OoOoOO00 / I11i / o0oOOo0O0Ooo
     if 54 - 54: OoOoOO00 / i1IIi + OOooOOo - I1ii11iIi11i - I1IiiI * I1Ii111
    if ( oOo00O . last_rloc_probe != None ) :
     I1IIII = oOo00O . last_rloc_probe_reply
     if ( I1IIII == None ) : I1IIII = 0
     O0o0O0OoOOoO = time . time ( ) - I1IIII
     if ( oOo00O . up_state ( ) and O0o0O0OoOOoO >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 91 - 91: OoooooooOO * OoooooooOO
      oOo00O . state = LISP_RLOC_UNREACH_STATE
      oOo00O . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( oOo00O . rloc , False )
      IiI1Iiiii1Iii = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( oo0o00OO , False ) , IiI1Iiiii1Iii ) )
      if 27 - 27: ooOoO0o / I1IiiI * I1ii11iIi11i . o0oOOo0O0Ooo
      if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
      lisp_mark_rlocs_for_other_eids ( oo0O )
      if 33 - 33: OOooOOo % OoooooooOO
      if 98 - 98: Ii1I
      if 38 - 38: ooOoO0o - iII111i * OOooOOo % I1ii11iIi11i + Oo0Ooo
    oOo00O . last_rloc_probe = lisp_get_timestamp ( )
    if 95 - 95: iIii1I11I1II1 / O0 % O0
    o0O0o00ooOOOO0 = "" if oOo00O . unreach_state ( ) == False else " unreachable"
    if 18 - 18: OoO0O00 * ooOoO0o
    if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
    if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
    if 67 - 67: I1IiiI
    if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
    if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
    if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
    ooooOOO0OoO = ""
    IiI1Ii = None
    if ( oOo00O . rloc_next_hop != None ) :
     OooOOOoOoo0O0 , IiI1Ii = oOo00O . rloc_next_hop
     lisp_install_host_route ( oo0o00OO , IiI1Ii , True )
     ooooOOO0OoO = ", send on nh {}({})" . format ( IiI1Ii , OooOOOoOoo0O0 )
     if 47 - 47: I1IiiI + Oo0Ooo
     if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
     if 10 - 10: i1IIi % ooOoO0o / iII111i
     if 98 - 98: IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
     if 65 - 65: Ii1I + OoOoOO00 * Oo0Ooo . O0 . IiII
    i1i1I1I1 = oOo00O . print_rloc_probe_rtt ( )
    IiiIII1IIiI1iii = oo0o00OO
    if ( oOo00O . translated_port != 0 ) :
     IiiIII1IIiI1iii += ":{}" . format ( oOo00O . translated_port )
     if 19 - 19: iII111i + OOooOOo
    IiiIII1IIiI1iii = red ( IiiIII1IIiI1iii , False )
    if ( oOo00O . rloc_name != None ) :
     IiiIII1IIiI1iii += " (" + blue ( oOo00O . rloc_name , False ) + ")"
     if 65 - 65: I1ii11iIi11i . OoooooooOO + Oo0Ooo * Ii1I
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( OOO0oOooOOo00 , o0O0o00ooOOOO0 ,
 IiiIII1IIiI1iii , i1i1I1I1 , ooooOOO0OoO ) )
    if 27 - 27: Oo0Ooo % i11iIiiIii
    if 48 - 48: IiII
    if 74 - 74: Oo0Ooo
    if 75 - 75: IiII + OOooOOo
    if 92 - 92: OoOoOO00
    if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
    if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
    if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
    if ( oOo00O . rloc_next_hop != None ) :
     iiIIII1I1ii = lisp_get_host_route_next_hop ( oo0o00OO )
     if ( iiIIII1I1ii ) : lisp_install_host_route ( oo0o00OO , iiIIII1I1ii , False )
     if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
     if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
     if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
     if 54 - 54: oO0o * II111iiii
     if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
     if 98 - 98: ooOoO0o
    if ( oOo00O . rloc . is_null ( ) ) :
     oOo00O . rloc . copy_address ( i1iI1Iii . rloc )
     if 73 - 73: I1Ii111
     if 97 - 97: OoO0O00 * Ii1I + Oo0Ooo
     if 83 - 83: II111iiii - Oo0Ooo % II111iiii * o0oOOo0O0Ooo
     if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
     if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
    O00oOOOOoOO = None if ( O0o00oOOOO00 . is_null ( ) ) else OOo0O0O0o0
    I11iIii1i11 = OOo0O0O0o0 if ( O0o00oOOOO00 . is_null ( ) ) else O0o00oOOOO00
    lisp_send_map_request ( lisp_sockets , 0 , O00oOOOOoOO , I11iIii1i11 , oOo00O )
    O0O00OOoo00 = i1iI1Iii
    if 67 - 67: OoO0O00
    if 37 - 37: o0oOOo0O0Ooo + I11i - Ii1I - Ii1I * OoO0O00 % i11iIiiIii
    if 98 - 98: I1Ii111 % IiII % i1IIi * OOooOOo . iIii1I11I1II1
    if 60 - 60: iII111i . Ii1I / I1IiiI
    if ( IiI1Ii ) : lisp_install_host_route ( oo0o00OO , IiI1Ii , False )
    if 92 - 92: OoooooooOO % II111iiii + I1ii11iIi11i
    if 93 - 93: OoooooooOO . I1ii11iIi11i
    if 100 - 100: iIii1I11I1II1 . i1IIi / OOooOOo * i11iIiiIii
    if 93 - 93: I1ii11iIi11i
    if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
   if ( iiIIII1I1ii ) : lisp_install_host_route ( oo0o00OO , iiIIII1I1ii , True )
   if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
   if 5 - 5: Oo0Ooo . I1Ii111
   if 77 - 77: i11iIiiIii / I1Ii111 / I1ii11iIi11i % oO0o
   if 83 - 83: Ii1I % iIii1I11I1II1 / I1ii11iIi11i + I11i
   OO += 1
   if ( ( OO % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 23 - 23: iIii1I11I1II1 - I1IiiI
   if 51 - 51: OoooooooOO / IiII / I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * OoooooooOO
   if 40 - 40: OoO0O00 / IiII . O0 / I1IiiI + OoO0O00 . o0oOOo0O0Ooo
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 25 - 25: ooOoO0o * I1Ii111 * oO0o
 if 64 - 64: Ii1I / I1ii11iIi11i
 if 30 - 30: OoooooooOO + O0 / I1ii11iIi11i * o0oOOo0O0Ooo
 if 11 - 11: O0 + OoO0O00 - Oo0Ooo - Oo0Ooo . i11iIiiIii
 if 15 - 15: Ii1I % i11iIiiIii / OoOoOO00
 if 85 - 85: ooOoO0o . i1IIi / iII111i % iIii1I11I1II1 / II111iiii / I1Ii111
 if 60 - 60: iIii1I11I1II1 - iIii1I11I1II1 . I11i
 if 55 - 55: OoO0O00
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 87 - 87: Ii1I - iII111i / O0 - o0oOOo0O0Ooo - iIii1I11I1II1 % Ii1I
 if 47 - 47: iII111i * I1Ii111 % o0oOOo0O0Ooo / OoOoOO00 / OoO0O00 % OoO0O00
 if 43 - 43: Oo0Ooo
 if 34 - 34: OoO0O00 . i1IIi + IiII * IiII
 if ( lisp_i_am_itr == False ) : return
 if 76 - 76: OOooOOo
 if 54 - 54: O0 * II111iiii * OOooOOo
 if 44 - 44: I1IiiI
 if 66 - 66: o0oOOo0O0Ooo
 if 40 - 40: OOooOOo * Ii1I
 if ( lisp_register_all_rtrs ) : return
 if 38 - 38: ooOoO0o
 iiI111I = rtr . print_address_no_iid ( )
 if 22 - 22: i11iIiiIii - Ii1I + O0 - I1ii11iIi11i . Oo0Ooo
 if 33 - 33: O0
 if 30 - 30: II111iiii * OoOoOO00 - OoO0O00 * OOooOOo / I11i
 if 77 - 77: Oo0Ooo
 if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
 if ( lisp_rtr_list . has_key ( iiI111I ) == False ) : return
 if 1 - 1: I1ii11iIi11i / i1IIi . I1IiiI / Ii1I
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( iiI111I , False ) , bold ( updown , False ) ) )
 if 19 - 19: iIii1I11I1II1 / Oo0Ooo . O0 - Oo0Ooo
 if 74 - 74: I1ii11iIi11i * OoooooooOO . iII111i
 if 45 - 45: I1IiiI - IiII % ooOoO0o - IiII . Oo0Ooo - o0oOOo0O0Ooo
 if 27 - 27: iII111i
 OoOO0o00OOO0o = "rtr%{}%{}" . format ( iiI111I , updown )
 OoOO0o00OOO0o = lisp_command_ipc ( OoOO0o00OOO0o , "lisp-itr" )
 lisp_ipc ( OoOO0o00OOO0o , lisp_ipc_socket , "lisp-etr" )
 return
 if 64 - 64: iIii1I11I1II1 - OOooOOo . iII111i % o0oOOo0O0Ooo / II111iiii % OoooooooOO
 if 87 - 87: OoooooooOO
 if 70 - 70: o0oOOo0O0Ooo % OoooooooOO % I1IiiI . OoOoOO00 * I1IiiI - ooOoO0o
 if 92 - 92: I1IiiI . I11i
 if 66 - 66: I1Ii111 / I11i / OoooooooOO % OoOoOO00 . oO0o * iII111i
 if 34 - 34: I1ii11iIi11i * I1ii11iIi11i % I11i / OOooOOo % oO0o . OoOoOO00
 if 25 - 25: I1ii11iIi11i / I11i + i1IIi . I1IiiI + ooOoO0o
def lisp_process_rloc_probe_reply ( rloc , source , port , nonce , hop_count , ttl ) :
 OOO0oOooOOo00 = bold ( "RLOC-probe reply" , False )
 i1Iii11 = rloc . print_address_no_iid ( )
 iiiI1 = source . print_address_no_iid ( )
 iiiooO0 = lisp_rloc_probe_list
 if 18 - 18: I1ii11iIi11i - iIii1I11I1II1 + i1IIi * I1Ii111
 if 12 - 12: I1ii11iIi11i + I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
 if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
 if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
 if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
 if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 IiiIIi1 = i1Iii11
 if ( iiiooO0 . has_key ( IiiIIi1 ) == False ) :
  IiiIIi1 += ":" + str ( port )
  if ( iiiooO0 . has_key ( IiiIIi1 ) == False ) :
   IiiIIi1 = iiiI1
   if ( iiiooO0 . has_key ( IiiIIi1 ) == False ) :
    IiiIIi1 += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( OOO0oOooOOo00 , red ( i1Iii11 , False ) , red ( iiiI1 ,
    # I1IiiI * I11i % i11iIiiIii * I1IiiI % Oo0Ooo
 False ) , port ) )
    return
    if 90 - 90: Oo0Ooo % I1ii11iIi11i + OoOoOO00 % OoOoOO00 / OoOoOO00 . oO0o
    if 73 - 73: I1Ii111 / II111iiii
    if 61 - 61: IiII + Oo0Ooo - Oo0Ooo . II111iiii
    if 70 - 70: i11iIiiIii - IiII
    if 35 - 35: Ii1I + Ii1I + iIii1I11I1II1 + I1Ii111 * OoO0O00 % o0oOOo0O0Ooo
    if 64 - 64: I1IiiI / OoOoOO00
    if 89 - 89: o0oOOo0O0Ooo - OOooOOo * I1Ii111 . i1IIi % I1IiiI . I11i
    if 99 - 99: I1Ii111 * ooOoO0o
 for rloc , OOo0O0O0o0 , O0o00oOOOO00 in lisp_rloc_probe_list [ IiiIIi1 ] :
  if ( lisp_i_am_rtr and rloc . translated_port != 0 and
 rloc . translated_port != port ) : continue
  if 9 - 9: I1Ii111
  rloc . process_rloc_probe_reply ( nonce , OOo0O0O0o0 , O0o00oOOOO00 , hop_count , ttl )
  if 26 - 26: iIii1I11I1II1 - I11i . Oo0Ooo - I1Ii111
 return
 if 3 - 3: I1IiiI + I1ii11iIi11i - I11i
 if 15 - 15: OoOoOO00 . Oo0Ooo / ooOoO0o + Oo0Ooo - OoooooooOO - o0oOOo0O0Ooo
 if 64 - 64: OOooOOo
 if 44 - 44: O0 % ooOoO0o - iIii1I11I1II1 * i11iIiiIii . OoOoOO00
 if 32 - 32: I1ii11iIi11i - iII111i
 if 34 - 34: OOooOOo . i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1ii11iIi11i
 if 32 - 32: i11iIiiIii . I1Ii111
 if 38 - 38: O0
def lisp_db_list_length ( ) :
 OO = 0
 for Ooooo00 in lisp_db_list :
  OO += len ( Ooooo00 . dynamic_eids ) if Ooooo00 . dynamic_eid_configured ( ) else 1
  OO += len ( Ooooo00 . eid . iid_list )
  if 50 - 50: i11iIiiIii * OoO0O00 + iII111i / O0 * oO0o % ooOoO0o
 return ( OO )
 if 6 - 6: OoO0O00 . o0oOOo0O0Ooo / Ii1I + Ii1I
 if 59 - 59: II111iiii - o0oOOo0O0Ooo * OoooooooOO
 if 83 - 83: oO0o . iIii1I11I1II1 . iII111i % Oo0Ooo
 if 48 - 48: oO0o % OoO0O00 - OoooooooOO . IiII
 if 11 - 11: I1Ii111 % o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i
 if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
def lisp_is_myeid ( eid ) :
 for Ooooo00 in lisp_db_list :
  if ( eid . is_more_specific ( Ooooo00 . eid ) ) : return ( True )
  if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
 return ( False )
 if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
 if 47 - 47: OOooOOo + IiII
 if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
 if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
 if 64 - 64: Ii1I
 if 4 - 4: OoOoOO00
 if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
 if 48 - 48: iII111i / II111iiii * I1Ii111 + I11i / ooOoO0o . OoOoOO00
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 45 - 45: OOooOOo / Ii1I % O0
 if 7 - 7: oO0o * i11iIiiIii + OoooooooOO + I11i
 if 9 - 9: II111iiii * Oo0Ooo * I1Ii111 . IiII
 if 80 - 80: i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - OOooOOo * OoooooooOO
 if 96 - 96: oO0o
 if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
 if 64 - 64: I1IiiI % i11iIiiIii / oO0o
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 Oo0ooO0O0o00o = None
 if ( lisp_nonce_echo_list . has_key ( rloc_str ) ) :
  Oo0ooO0O0o00o = lisp_nonce_echo_list [ rloc_str ]
  if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
 return ( Oo0ooO0O0o00o )
 if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
 if 31 - 31: OoO0O00
 if 89 - 89: II111iiii
 if 33 - 33: OOooOOo / oO0o % OoOoOO00 * O0
 if 65 - 65: OoO0O00 % OoOoOO00 % I1ii11iIi11i / OoooooooOO
 if 85 - 85: O0 * OOooOOo % I1Ii111
 if 33 - 33: O0
 if 30 - 30: II111iiii . O0 . oO0o * I1ii11iIi11i + oO0o . o0oOOo0O0Ooo
def lisp_decode_dist_name ( packet ) :
 OO = 0
 i1IoO = ""
 if 10 - 10: oO0o
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( OO == 255 ) : return ( [ None , None ] )
  i1IoO += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  OO += 1
  if 75 - 75: II111iiii % OOooOOo / iIii1I11I1II1 / OoO0O00 + oO0o
  if 16 - 16: oO0o + I1Ii111 - II111iiii - o0oOOo0O0Ooo / i11iIiiIii
 packet = packet [ 1 : : ]
 return ( packet , i1IoO )
 if 59 - 59: OOooOOo - o0oOOo0O0Ooo
 if 82 - 82: IiII % ooOoO0o - OoO0O00 % ooOoO0o
 if 51 - 51: ooOoO0o % iII111i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 20 - 20: i1IIi - ooOoO0o % OoooooooOO * I1ii11iIi11i + II111iiii % i1IIi
 if 30 - 30: i11iIiiIii - I1IiiI + o0oOOo0O0Ooo + IiII
 if 16 - 16: I1ii11iIi11i / Ii1I + I1ii11iIi11i * I1Ii111
 if 49 - 49: ooOoO0o * OoOoOO00 . OoooooooOO . ooOoO0o + Oo0Ooo * IiII
 if 47 - 47: iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
def lisp_write_flow_log ( flow_log ) :
 ii11I1IIi = open ( "./logs/lisp-flow.log" , "a" )
 if 84 - 84: o0oOOo0O0Ooo * I11i
 OO = 0
 for i1ii11III1 in flow_log :
  IIii1i = i1ii11III1 [ 3 ]
  ii1Iii1 = IIii1i . print_flow ( i1ii11III1 [ 0 ] , i1ii11III1 [ 1 ] , i1ii11III1 [ 2 ] )
  ii11I1IIi . write ( ii1Iii1 )
  OO += 1
  if 29 - 29: O0 - II111iiii % Oo0Ooo + I11i
 ii11I1IIi . close ( )
 del ( flow_log )
 if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
 OO = bold ( str ( OO ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( OO ) )
 return
 if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
 if 66 - 66: OoooooooOO
 if 90 - 90: IiII - OoOoOO00
 if 98 - 98: Oo0Ooo / oO0o . Ii1I
 if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
 if 37 - 37: iII111i - Ii1I . oO0o
 if 47 - 47: IiII / I1ii11iIi11i . o0oOOo0O0Ooo . ooOoO0o + OOooOOo . OOooOOo
def lisp_policy_command ( kv_pair ) :
 III1I1Iii1 = lisp_policy ( "" )
 iIII11III = None
 if 9 - 9: iIii1I11I1II1 * OoO0O00
 IIiIi11I = [ ]
 for IiIIi1IiiIiI in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  IIiIi11I . append ( lisp_policy_match ( ) )
  if 22 - 22: ooOoO0o . ooOoO0o % i1IIi * II111iiii * IiII
  if 6 - 6: II111iiii . iII111i % I1ii11iIi11i + IiII / I11i
 for i1II1I1II11I in kv_pair . keys ( ) :
  i11II = kv_pair [ i1II1I1II11I ]
  if 43 - 43: iII111i . I1Ii111 . OOooOOo
  if 89 - 89: OoOoOO00 % O0
  if 7 - 7: O0 % oO0o
  if 57 - 57: i1IIi . OOooOOo
  if ( i1II1I1II11I == "instance-id" ) :
   for IiIIi1IiiIiI in range ( len ( IIiIi11I ) ) :
    O0Oo0 = i11II [ IiIIi1IiiIiI ]
    if ( O0Oo0 == "" ) : continue
    o0o0OOO = IIiIi11I [ IiIIi1IiiIiI ]
    if ( o0o0OOO . source_eid == None ) :
     o0o0OOO . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 95 - 95: II111iiii + Ii1I % i11iIiiIii * i1IIi + OOooOOo - oO0o
    if ( o0o0OOO . dest_eid == None ) :
     o0o0OOO . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 73 - 73: o0oOOo0O0Ooo . I1IiiI - I11i . ooOoO0o % II111iiii . OoooooooOO
    o0o0OOO . source_eid . instance_id = int ( O0Oo0 )
    o0o0OOO . dest_eid . instance_id = int ( O0Oo0 )
    if 8 - 8: OoooooooOO
    if 92 - 92: ooOoO0o + IiII * II111iiii
  if ( i1II1I1II11I == "source-eid" ) :
   for IiIIi1IiiIiI in range ( len ( IIiIi11I ) ) :
    O0Oo0 = i11II [ IiIIi1IiiIiI ]
    if ( O0Oo0 == "" ) : continue
    o0o0OOO = IIiIi11I [ IiIIi1IiiIiI ]
    if ( o0o0OOO . source_eid == None ) :
     o0o0OOO . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 41 - 41: I1IiiI + OoOoOO00 . OOooOOo
    o0OoO0000o = o0o0OOO . source_eid . instance_id
    o0o0OOO . source_eid . store_prefix ( O0Oo0 )
    o0o0OOO . source_eid . instance_id = o0OoO0000o
    if 57 - 57: II111iiii . iIii1I11I1II1
    if 32 - 32: o0oOOo0O0Ooo
  if ( i1II1I1II11I == "destination-eid" ) :
   for IiIIi1IiiIiI in range ( len ( IIiIi11I ) ) :
    O0Oo0 = i11II [ IiIIi1IiiIiI ]
    if ( O0Oo0 == "" ) : continue
    o0o0OOO = IIiIi11I [ IiIIi1IiiIiI ]
    if ( o0o0OOO . dest_eid == None ) :
     o0o0OOO . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 75 - 75: I1IiiI . II111iiii - iII111i % IiII * OoO0O00 % ooOoO0o
    o0OoO0000o = o0o0OOO . dest_eid . instance_id
    o0o0OOO . dest_eid . store_prefix ( O0Oo0 )
    o0o0OOO . dest_eid . instance_id = o0OoO0000o
    if 38 - 38: I1IiiI / OoooooooOO
    if 16 - 16: i1IIi . i11iIiiIii . oO0o - I11i
  if ( i1II1I1II11I == "source-rloc" ) :
   for IiIIi1IiiIiI in range ( len ( IIiIi11I ) ) :
    O0Oo0 = i11II [ IiIIi1IiiIiI ]
    if ( O0Oo0 == "" ) : continue
    o0o0OOO = IIiIi11I [ IiIIi1IiiIiI ]
    o0o0OOO . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    o0o0OOO . source_rloc . store_prefix ( O0Oo0 )
    if 96 - 96: iII111i - OoOoOO00
    if 43 - 43: OoO0O00 - I1Ii111 % OoooooooOO % I1ii11iIi11i . OoOoOO00
  if ( i1II1I1II11I == "destination-rloc" ) :
   for IiIIi1IiiIiI in range ( len ( IIiIi11I ) ) :
    O0Oo0 = i11II [ IiIIi1IiiIiI ]
    if ( O0Oo0 == "" ) : continue
    o0o0OOO = IIiIi11I [ IiIIi1IiiIiI ]
    o0o0OOO . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    o0o0OOO . dest_rloc . store_prefix ( O0Oo0 )
    if 87 - 87: OOooOOo
    if 60 - 60: ooOoO0o * o0oOOo0O0Ooo . OoO0O00 * iII111i * oO0o * i1IIi
  if ( i1II1I1II11I == "rloc-record-name" ) :
   for IiIIi1IiiIiI in range ( len ( IIiIi11I ) ) :
    O0Oo0 = i11II [ IiIIi1IiiIiI ]
    if ( O0Oo0 == "" ) : continue
    o0o0OOO = IIiIi11I [ IiIIi1IiiIiI ]
    o0o0OOO . rloc_record_name = O0Oo0
    if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
    if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
  if ( i1II1I1II11I == "geo-name" ) :
   for IiIIi1IiiIiI in range ( len ( IIiIi11I ) ) :
    O0Oo0 = i11II [ IiIIi1IiiIiI ]
    if ( O0Oo0 == "" ) : continue
    o0o0OOO = IIiIi11I [ IiIIi1IiiIiI ]
    o0o0OOO . geo_name = O0Oo0
    if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
    if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
  if ( i1II1I1II11I == "elp-name" ) :
   for IiIIi1IiiIiI in range ( len ( IIiIi11I ) ) :
    O0Oo0 = i11II [ IiIIi1IiiIiI ]
    if ( O0Oo0 == "" ) : continue
    o0o0OOO = IIiIi11I [ IiIIi1IiiIiI ]
    o0o0OOO . elp_name = O0Oo0
    if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
    if 76 - 76: OoO0O00
  if ( i1II1I1II11I == "rle-name" ) :
   for IiIIi1IiiIiI in range ( len ( IIiIi11I ) ) :
    O0Oo0 = i11II [ IiIIi1IiiIiI ]
    if ( O0Oo0 == "" ) : continue
    o0o0OOO = IIiIi11I [ IiIIi1IiiIiI ]
    o0o0OOO . rle_name = O0Oo0
    if 92 - 92: iIii1I11I1II1 * O0 % I11i
    if 92 - 92: OoOoOO00 + oO0o
  if ( i1II1I1II11I == "json-name" ) :
   for IiIIi1IiiIiI in range ( len ( IIiIi11I ) ) :
    O0Oo0 = i11II [ IiIIi1IiiIiI ]
    if ( O0Oo0 == "" ) : continue
    o0o0OOO = IIiIi11I [ IiIIi1IiiIiI ]
    o0o0OOO . json_name = O0Oo0
    if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
    if 28 - 28: I1IiiI . iIii1I11I1II1
  if ( i1II1I1II11I == "datetime-range" ) :
   for IiIIi1IiiIiI in range ( len ( IIiIi11I ) ) :
    O0Oo0 = i11II [ IiIIi1IiiIiI ]
    o0o0OOO = IIiIi11I [ IiIIi1IiiIiI ]
    if ( O0Oo0 == "" ) : continue
    I1111III111ii = lisp_datetime ( O0Oo0 [ 0 : 19 ] )
    i11iI1iIiI = lisp_datetime ( O0Oo0 [ 19 : : ] )
    if ( I1111III111ii . valid_datetime ( ) and i11iI1iIiI . valid_datetime ( ) ) :
     o0o0OOO . datetime_lower = I1111III111ii
     o0o0OOO . datetime_upper = i11iI1iIiI
     if 12 - 12: I1Ii111 * OOooOOo
     if 11 - 11: II111iiii % O0 % O0 % o0oOOo0O0Ooo
     if 45 - 45: OoooooooOO * oO0o
     if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
     if 16 - 16: Oo0Ooo
     if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
     if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
  if ( i1II1I1II11I == "set-action" ) :
   III1I1Iii1 . set_action = i11II
   if 67 - 67: I1IiiI
  if ( i1II1I1II11I == "set-record-ttl" ) :
   III1I1Iii1 . set_record_ttl = int ( i11II )
   if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
  if ( i1II1I1II11I == "set-instance-id" ) :
   if ( III1I1Iii1 . set_source_eid == None ) :
    III1I1Iii1 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
   if ( III1I1Iii1 . set_dest_eid == None ) :
    III1I1Iii1 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 33 - 33: OOooOOo - OoooooooOO . iII111i
   iIII11III = int ( i11II )
   III1I1Iii1 . set_source_eid . instance_id = iIII11III
   III1I1Iii1 . set_dest_eid . instance_id = iIII11III
   if 2 - 2: I11i + i1IIi
  if ( i1II1I1II11I == "set-source-eid" ) :
   if ( III1I1Iii1 . set_source_eid == None ) :
    III1I1Iii1 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 52 - 52: I11i - OoO0O00 % I1Ii111 . OOooOOo
   III1I1Iii1 . set_source_eid . store_prefix ( i11II )
   if ( iIII11III != None ) : III1I1Iii1 . set_source_eid . instance_id = iIII11III
   if 90 - 90: O0 - Oo0Ooo / i1IIi * iIii1I11I1II1 % o0oOOo0O0Ooo / oO0o
  if ( i1II1I1II11I == "set-destination-eid" ) :
   if ( III1I1Iii1 . set_dest_eid == None ) :
    III1I1Iii1 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 73 - 73: iII111i % iIii1I11I1II1 + o0oOOo0O0Ooo % Ii1I . II111iiii + IiII
   III1I1Iii1 . set_dest_eid . store_prefix ( i11II )
   if ( iIII11III != None ) : III1I1Iii1 . set_dest_eid . instance_id = iIII11III
   if 55 - 55: OoOoOO00 * II111iiii / iII111i + OOooOOo / OoooooooOO
  if ( i1II1I1II11I == "set-rloc-address" ) :
   III1I1Iii1 . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   III1I1Iii1 . set_rloc_address . store_address ( i11II )
   if 12 - 12: II111iiii * O0 - Oo0Ooo + o0oOOo0O0Ooo . Oo0Ooo + iIii1I11I1II1
  if ( i1II1I1II11I == "set-rloc-record-name" ) :
   III1I1Iii1 . set_rloc_record_name = i11II
   if 4 - 4: I1Ii111 - I1Ii111 / I1ii11iIi11i . i1IIi + I1ii11iIi11i / oO0o
  if ( i1II1I1II11I == "set-elp-name" ) :
   III1I1Iii1 . set_elp_name = i11II
   if 18 - 18: iIii1I11I1II1 . ooOoO0o
  if ( i1II1I1II11I == "set-geo-name" ) :
   III1I1Iii1 . set_geo_name = i11II
   if 68 - 68: o0oOOo0O0Ooo
  if ( i1II1I1II11I == "set-rle-name" ) :
   III1I1Iii1 . set_rle_name = i11II
   if 36 - 36: Oo0Ooo . I11i + I1IiiI * i1IIi % Ii1I + OOooOOo
  if ( i1II1I1II11I == "set-json-name" ) :
   III1I1Iii1 . set_json_name = i11II
   if 5 - 5: o0oOOo0O0Ooo % oO0o / OoO0O00
  if ( i1II1I1II11I == "policy-name" ) :
   III1I1Iii1 . policy_name = i11II
   if 17 - 17: OoooooooOO - I1ii11iIi11i / OoO0O00 - I1Ii111 + i1IIi
   if 6 - 6: Oo0Ooo - II111iiii
   if 33 - 33: I1Ii111 - I1IiiI + iII111i . OoOoOO00
   if 91 - 91: OOooOOo / Ii1I / IiII * OOooOOo
   if 68 - 68: I11i
   if 91 - 91: I11i
 III1I1Iii1 . match_clauses = IIiIi11I
 III1I1Iii1 . save_policy ( )
 return
 if 24 - 24: ooOoO0o . i1IIi - O0 + I11i
 if 71 - 71: OoOoOO00
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
if 29 - 29: O0 . i11iIiiIii
if 51 - 51: IiII
if 53 - 53: O0
if 19 - 19: o0oOOo0O0Ooo / iII111i % OoOoOO00
if 65 - 65: o0oOOo0O0Ooo
if 89 - 89: iIii1I11I1II1 + OoooooooOO + i1IIi + OoooooooOO % IiII * OoO0O00
if 53 - 53: OOooOOo . IiII % I11i - OoO0O00 - Oo0Ooo
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 58 - 58: I1Ii111 / OoooooooOO . I11i % I1Ii111
 iIi1iIi11i = command
 if ( interface != "" ) : iIi1iIi11i = interface + ": " + iIi1iIi11i
 lprint ( "Send CLI command '{}' to hardware" . format ( iIi1iIi11i ) )
 if 66 - 66: O0 / I1ii11iIi11i . OoO0O00 . ooOoO0o * OoooooooOO
 commands = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 10 - 10: iII111i / OoOoOO00 + OOooOOo . OOooOOo
 os . system ( "FastCli -c '{}'" . format ( commands ) )
 return
 if 81 - 81: I11i . II111iiii / OoOoOO00 * I1Ii111
 if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
 if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
 if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
 if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
 if 25 - 25: OoO0O00 * oO0o
 if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
def lisp_arista_is_alive ( prefix ) :
 ooO0ooooO = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 Oo0Ooo0O0 = commands . getoutput ( "FastCli -c '{}'" . format ( ooO0ooooO ) )
 if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
 if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
 if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
 if 73 - 73: Oo0Ooo + II111iiii - IiII
 Oo0Ooo0O0 = Oo0Ooo0O0 . split ( "\n" ) [ 1 ]
 Ooii1 = Oo0Ooo0O0 . split ( " " )
 Ooii1 = Ooii1 [ - 1 ] . replace ( "\r" , "" )
 if 72 - 72: ooOoO0o + oO0o + IiII * I1Ii111 % oO0o
 if 55 - 55: IiII . ooOoO0o - II111iiii * I1IiiI . I1Ii111
 if 39 - 39: iIii1I11I1II1 . II111iiii + oO0o . iII111i + Ii1I
 if 91 - 91: Ii1I + I1Ii111
 return ( Ooii1 == "Y" )
 if 7 - 7: ooOoO0o + I1ii11iIi11i % OoO0O00
 if 45 - 45: i1IIi / o0oOOo0O0Ooo / iII111i * OoOoOO00 . IiII
 if 60 - 60: o0oOOo0O0Ooo
 if 63 - 63: i11iIiiIii * Oo0Ooo * I1Ii111
 if 56 - 56: I1Ii111 . i11iIiiIii
 if 76 - 76: II111iiii / ooOoO0o * i11iIiiIii . O0 / O0 - i11iIiiIii
 if 89 - 89: o0oOOo0O0Ooo . I1Ii111 * I11i + oO0o - OoooooooOO + OoO0O00
 if 25 - 25: i1IIi * I1Ii111 * iII111i . OoooooooOO
 if 70 - 70: iIii1I11I1II1
 if 1 - 1: II111iiii . I1IiiI + o0oOOo0O0Ooo
 if 5 - 5: I1ii11iIi11i % I11i - II111iiii
 if 70 - 70: ooOoO0o - IiII - OoO0O00 / I11i
 if 59 - 59: IiII % ooOoO0o . iII111i / Ii1I * Ii1I
 if 73 - 73: I1ii11iIi11i . oO0o % I11i . I1ii11iIi11i / I1Ii111 / II111iiii
 if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
 if 76 - 76: I1Ii111
 if 91 - 91: iIii1I11I1II1 / Ii1I . I1IiiI
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 if 85 - 85: II111iiii + I1ii11iIi11i
 if 33 - 33: iII111i
 if 14 - 14: O0 * Oo0Ooo / i1IIi
 if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
 if 78 - 78: II111iiii % OOooOOo
 if 6 - 6: OOooOOo
 if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
 if 55 - 55: OOooOOo + oO0o - II111iiii
 if 5 - 5: iII111i * OoooooooOO . OoO0O00 % ooOoO0o + Ii1I
 if 59 - 59: OoOoOO00
 if 96 - 96: I1IiiI
 if 3 - 3: OoooooooOO
 if 3 - 3: IiII / O0 * i11iIiiIii . iII111i - iIii1I11I1II1
 if 56 - 56: ooOoO0o
 if 82 - 82: ooOoO0o . IiII . I1Ii111 - iIii1I11I1II1 + II111iiii . OoOoOO00
 if 59 - 59: Oo0Ooo
 if 98 - 98: I1Ii111 * II111iiii / Oo0Ooo . Oo0Ooo % I1Ii111
 if 52 - 52: OoOoOO00
 if 59 - 59: ooOoO0o / OoooooooOO
 if 71 - 71: OOooOOo + I11i * O0 / o0oOOo0O0Ooo + I1IiiI + Ii1I
 if 41 - 41: ooOoO0o * I1Ii111
 if 40 - 40: OoOoOO00
 if 60 - 60: IiII . i11iIiiIii * II111iiii . Ii1I
 if 10 - 10: O0
 if 65 - 65: I11i % i11iIiiIii + i11iIiiIii % II111iiii
 if 95 - 95: I1Ii111 - I11i . II111iiii . i1IIi / II111iiii + Oo0Ooo
def lisp_program_vxlan_hardware ( mc ) :
 if 96 - 96: iIii1I11I1II1 * iII111i / OOooOOo * iIii1I11I1II1 - O0
 if 28 - 28: I11i / I1IiiI - I1Ii111 + I1ii11iIi11i % iIii1I11I1II1
 if 35 - 35: iIii1I11I1II1 % Oo0Ooo % iII111i / iIii1I11I1II1 - I1ii11iIi11i . Oo0Ooo
 if 81 - 81: II111iiii + oO0o
 if 67 - 67: ooOoO0o + I11i - I1ii11iIi11i - OoooooooOO
 if 37 - 37: I11i % I1IiiI
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 32 - 32: OOooOOo + OoooooooOO . IiII . Oo0Ooo * iII111i
 if 86 - 86: I1ii11iIi11i . iII111i + Ii1I - IiII / i11iIiiIii + OoOoOO00
 if 50 - 50: o0oOOo0O0Ooo - IiII + OoOoOO00 - II111iiii
 if 24 - 24: I1Ii111 - IiII % I1IiiI - OoooooooOO % Ii1I
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 56 - 56: I1ii11iIi11i
 if 40 - 40: OoooooooOO
 if 100 - 100: IiII - I11i
 if 79 - 79: iII111i % O0
 iIi1iIi1 = mc . eid . print_prefix_no_iid ( )
 oOo00O = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 73 - 73: Oo0Ooo
 if 13 - 13: OOooOOo - ooOoO0o
 if 8 - 8: I1Ii111 % oO0o
 if 19 - 19: O0 + OoO0O00 - i1IIi % OoOoOO00 / Oo0Ooo + OoooooooOO
 Ooo00000oO = commands . getoutput ( "ip route get {} | egrep vlan4094" . format ( iIi1iIi1 ) )
 if 54 - 54: OOooOOo + Oo0Ooo * o0oOOo0O0Ooo - iIii1I11I1II1 * ooOoO0o
 if ( Ooo00000oO != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( iIi1iIi1 , False ) , Ooo00000oO ) )
  if 76 - 76: i11iIiiIii * I1IiiI - IiII . o0oOOo0O0Ooo % iII111i . i11iIiiIii
  return
  if 69 - 69: O0 + o0oOOo0O0Ooo / ooOoO0o
  if 7 - 7: Ii1I . Ii1I . iIii1I11I1II1 / ooOoO0o
  if 70 - 70: O0
  if 42 - 42: I1Ii111 + OoooooooOO + I11i
  if 48 - 48: Oo0Ooo . IiII / ooOoO0o + I11i
  if 40 - 40: I1IiiI + I1ii11iIi11i * I1IiiI % Ii1I
  if 27 - 27: O0 / Oo0Ooo . oO0o
 I1i11Ii11i = commands . getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( I1i11Ii11i . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 31 - 31: IiII - Ii1I . i1IIi
 if ( I1i11Ii11i . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 1 - 1: o0oOOo0O0Ooo + OOooOOo % Ii1I - O0 / I1ii11iIi11i
 II1ii1i = commands . getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( II1ii1i == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 88 - 88: O0 + iIii1I11I1II1 . o0oOOo0O0Ooo . iIii1I11I1II1 - Ii1I
 II1ii1i = II1ii1i . split ( "inet " ) [ 1 ]
 II1ii1i = II1ii1i . split ( "/" ) [ 0 ]
 if 74 - 74: Ii1I . IiII
 if 67 - 67: oO0o
 if 12 - 12: I1IiiI + OoooooooOO
 if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
 if 19 - 19: OoooooooOO / IiII
 if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
 if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
 OOoOoOO0 = [ ]
 IioOOO0O0o = commands . getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for oOOo0ooO0 in IioOOO0O0o :
  if ( oOOo0ooO0 . find ( "vlan4094" ) == - 1 ) : continue
  if ( oOOo0ooO0 . find ( "(incomplete)" ) == - 1 ) : continue
  iiIIII1I1ii = oOOo0ooO0 . split ( " " ) [ 0 ]
  OOoOoOO0 . append ( iiIIII1I1ii )
  if 19 - 19: OoooooooOO
  if 28 - 28: i11iIiiIii / O0 / iIii1I11I1II1 / I1IiiI % OoooooooOO % ooOoO0o
 iiIIII1I1ii = None
 IIIIIi = II1ii1i
 II1ii1i = II1ii1i . split ( "." )
 for IiIIi1IiiIiI in range ( 1 , 255 ) :
  II1ii1i [ 3 ] = str ( IiIIi1IiiIiI )
  IiiIIi1 = "." . join ( II1ii1i )
  if ( IiiIIi1 in OOoOoOO0 ) : continue
  if ( IiiIIi1 == IIIIIi ) : continue
  iiIIII1I1ii = IiiIIi1
  break
  if 29 - 29: I1ii11iIi11i
 if ( iiIIII1I1ii == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 12 - 12: I11i . o0oOOo0O0Ooo . iIii1I11I1II1
  return
  if 93 - 93: ooOoO0o - OoooooooOO + iIii1I11I1II1 / o0oOOo0O0Ooo + iIii1I11I1II1
  if 9 - 9: OoOoOO00 + ooOoO0o
  if 61 - 61: i11iIiiIii + OOooOOo - i1IIi
  if 2 - 2: I1ii11iIi11i / I1Ii111 / I1ii11iIi11i / iII111i * i11iIiiIii % iII111i
  if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
  if 63 - 63: oO0o * OoO0O00 * oO0o
  if 31 - 31: Oo0Ooo
 O0OoO = oOo00O . split ( "." )
 ooo0OooOo = lisp_hex_string ( O0OoO [ 1 ] ) . zfill ( 2 )
 Oo00o = lisp_hex_string ( O0OoO [ 2 ] ) . zfill ( 2 )
 i1IIIIii1I = lisp_hex_string ( O0OoO [ 3 ] ) . zfill ( 2 )
 Ii = "00:00:00:{}:{}:{}" . format ( ooo0OooOo , Oo00o , i1IIIIii1I )
 iI1111 = "0000.00{}.{}{}" . format ( ooo0OooOo , Oo00o , i1IIIIii1I )
 iIII11I = "arp -i vlan4094 -s {} {}" . format ( iiIIII1I1ii , Ii )
 os . system ( iIII11I )
 if 6 - 6: Ii1I / Ii1I
 if 9 - 9: iII111i + I1Ii111 + iII111i % ooOoO0o + i11iIiiIii + i11iIiiIii
 if 45 - 45: i1IIi + I1ii11iIi11i
 if 49 - 49: i11iIiiIii . I1ii11iIi11i
 O0O000Ooo = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( iI1111 , oOo00O )
 if 26 - 26: Oo0Ooo / I11i * i1IIi
 lisp_send_to_arista ( O0O000Ooo , None )
 if 7 - 7: I1ii11iIi11i . i11iIiiIii - oO0o + Ii1I
 if 52 - 52: iIii1I11I1II1 - O0 - i1IIi + o0oOOo0O0Ooo * OOooOOo . O0
 if 76 - 76: Ii1I / oO0o . I1Ii111
 if 94 - 94: o0oOOo0O0Ooo - OoOoOO00 / I1Ii111
 if 99 - 99: O0 % oO0o % OOooOOo - Oo0Ooo
 II1iIi1ii1IIi = "ip route add {} via {}" . format ( iIi1iIi1 , iiIIII1I1ii )
 os . system ( II1iIi1ii1IIi )
 if 82 - 82: iII111i + OoooooooOO % iIii1I11I1II1 - o0oOOo0O0Ooo - i1IIi / Oo0Ooo
 lprint ( "Hardware programmed with commands:" )
 II1iIi1ii1IIi = II1iIi1ii1IIi . replace ( iIi1iIi1 , green ( iIi1iIi1 , False ) )
 lprint ( "  " + II1iIi1ii1IIi )
 lprint ( "  " + iIII11I )
 O0O000Ooo = O0O000Ooo . replace ( oOo00O , red ( oOo00O , False ) )
 lprint ( "  " + O0O000Ooo )
 return
 if 13 - 13: iII111i % oO0o - I11i . i11iIiiIii / iIii1I11I1II1
 if 11 - 11: iII111i % OoO0O00 % iIii1I11I1II1 + IiII * Ii1I
 if 93 - 93: OOooOOo / iII111i
 if 74 - 74: I1ii11iIi11i
 if 83 - 83: iII111i + i1IIi - OoooooooOO
 if 16 - 16: i1IIi
 if 86 - 86: OoOoOO00 - iII111i - Oo0Ooo
def lisp_clear_hardware_walk ( mc , parms ) :
 O000O0o00o0o = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( O000O0o00o0o ) )
 return ( [ True , None ] )
 if 33 - 33: Ii1I - OoO0O00
 if 15 - 15: O0 . iIii1I11I1II1 - I1Ii111 + O0 + ooOoO0o / I1IiiI
 if 8 - 8: iII111i % O0 - OoOoOO00
 if 49 - 49: oO0o - OOooOOo / Ii1I / I1Ii111 . o0oOOo0O0Ooo . iII111i
 if 58 - 58: IiII + Ii1I
 if 89 - 89: Ii1I / Oo0Ooo * o0oOOo0O0Ooo / OoO0O00 + I11i
 if 4 - 4: I11i
 if 59 - 59: OoOoOO00 * I1ii11iIi11i / I1IiiI * II111iiii + OoOoOO00
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list , lisp_gleaned_groups
 if 6 - 6: OoOoOO00 % oO0o + I11i * Ii1I
 IIII = bold ( "User cleared" , False )
 OO = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( IIII , OO ) )
 if 92 - 92: OoOoOO00 + IiII . OoO0O00 % iII111i / II111iiii / I11i
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 62 - 62: I1ii11iIi11i
 lisp_map_cache = lisp_cache ( )
 if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
 if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
 if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
 if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
 if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
 lisp_rloc_probe_list = { }
 if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
 if 71 - 71: i1IIi
 if 79 - 79: iII111i * O0 / Ii1I / O0 % i1IIi
 if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 62 - 62: Ii1I . I1ii11iIi11i . iII111i + I11i * o0oOOo0O0Ooo
 if 56 - 56: oO0o * iIii1I11I1II1 . II111iiii - II111iiii + II111iiii - i11iIiiIii
 if 79 - 79: iII111i
 if 29 - 29: Ii1I * I1Ii111 / OoO0O00 - O0 - i11iIiiIii * I1IiiI
 if 2 - 2: OoOoOO00 . I1ii11iIi11i * I1ii11iIi11i
 lisp_rtr_list = { }
 if 42 - 42: OoO0O00 . OoO0O00 + II111iiii - IiII - OOooOOo * Oo0Ooo
 if 47 - 47: oO0o - OoooooooOO + iII111i
 if 69 - 69: I1ii11iIi11i - I1IiiI % oO0o + OOooOOo - I1Ii111
 if 5 - 5: ooOoO0o . OoO0O00
 lisp_gleaned_groups = { }
 if 40 - 40: iII111i
 if 87 - 87: IiII / II111iiii
 if 44 - 44: OoO0O00 . I1Ii111 - OoooooooOO * OoOoOO00 . OoO0O00
 if 84 - 84: OOooOOo . OOooOOo . oO0o % iII111i * Oo0Ooo - iIii1I11I1II1
 lisp_process_data_plane_restart ( True )
 return
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
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
 OooooO0o00 = lisp_myrlocs [ 0 ]
 if 24 - 24: IiII / I1ii11iIi11i / OOooOOo
 if 23 - 23: o0oOOo0O0Ooo - OoooooooOO % I1ii11iIi11i * i1IIi
 if 67 - 67: I1ii11iIi11i % OoOoOO00 . iII111i / Ii1I . I1IiiI
 if 48 - 48: IiII + II111iiii . I1IiiI % o0oOOo0O0Ooo
 if 57 - 57: OOooOOo . I11i % OoOoOO00
 iiiIIiiIi = len ( packet ) + 28
 Ooo0oO = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( iiiIIiiIi ) , 0 , 64 ,
 17 , 0 , socket . htonl ( OooooO0o00 . address ) , socket . htonl ( rloc . address ) )
 Ooo0oO = lisp_ip_checksum ( Ooo0oO )
 if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
 o0oOo00 = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( iiiIIiiIi - 20 ) , 0 )
 if 78 - 78: iII111i - OOooOOo / I1Ii111
 if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
 if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
 if 17 - 17: OoooooooOO % OoooooooOO + Oo0Ooo + I1Ii111
 packet = lisp_packet ( Ooo0oO + o0oOo00 + packet )
 if 56 - 56: I11i % OoOoOO00 - OoO0O00
 if 31 - 31: iII111i % i11iIiiIii - Ii1I / OOooOOo - I1Ii111
 if 60 - 60: o0oOOo0O0Ooo + Oo0Ooo . O0
 if 51 - 51: i11iIiiIii / iIii1I11I1II1 . I1IiiI - Ii1I * I1Ii111 . iII111i
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( OooooO0o00 )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( OooooO0o00 )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 72 - 72: Ii1I . I11i / i1IIi % i1IIi + I1ii11iIi11i
 o0O00oo0O = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  OOo0OOO0 = " {}" . format ( blue ( nat_info . hostname , False ) )
  OOO0oOooOOo00 = bold ( "RLOC-probe request" , False )
 else :
  OOo0OOO0 = ""
  OOO0oOooOOo00 = bold ( "RLOC-probe reply" , False )
  if 56 - 56: OoO0O00 - OoOoOO00 - II111iiii * o0oOOo0O0Ooo
  if 87 - 87: ooOoO0o * OoooooooOO % O0 * OoooooooOO . I1Ii111
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( OOO0oOooOOo00 , o0O00oo0O , OOo0OOO0 , packet . encap_port ) )
 if 66 - 66: OoO0O00 * Ii1I . OoO0O00
 if 90 - 90: II111iiii % Ii1I
 if 67 - 67: I1IiiI - I11i - i11iIiiIii
 if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
 if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
 O00OOOoo = lisp_sockets [ 3 ]
 packet . send_packet ( O00OOOoo , packet . outer_dest )
 del ( packet )
 return
 if 95 - 95: i1IIi . I11i - OoO0O00 * Ii1I + OOooOOo + iII111i
 if 96 - 96: I1IiiI
 if 62 - 62: I1Ii111
 if 96 - 96: ooOoO0o % I11i + o0oOOo0O0Ooo / I1Ii111 * I1Ii111 . OoO0O00
 if 84 - 84: i1IIi - I1Ii111 - IiII * i1IIi
 if 36 - 36: o0oOOo0O0Ooo % I11i % iII111i % O0
 if 3 - 3: I1ii11iIi11i / O0 * II111iiii . O0
 if 86 - 86: iIii1I11I1II1
def lisp_get_default_route_next_hops ( ) :
 if 39 - 39: I11i
 if 77 - 77: OoO0O00 / OoO0O00 . ooOoO0o . Oo0Ooo * OoooooooOO * I11i
 if 63 - 63: iIii1I11I1II1 + ooOoO0o + o0oOOo0O0Ooo . ooOoO0o / o0oOOo0O0Ooo - IiII
 if 7 - 7: I1ii11iIi11i . iII111i . OOooOOo
 if ( lisp_is_macos ( ) ) :
  ooO0ooooO = "route -n get default"
  OOoOOOOOo0o = commands . getoutput ( ooO0ooooO ) . split ( "\n" )
  O0O0oOo = II1i = None
  for ii11I1IIi in OOoOOOOOo0o :
   if ( ii11I1IIi . find ( "gateway: " ) != - 1 ) : O0O0oOo = ii11I1IIi . split ( ": " ) [ 1 ]
   if ( ii11I1IIi . find ( "interface: " ) != - 1 ) : II1i = ii11I1IIi . split ( ": " ) [ 1 ]
   if 97 - 97: Ii1I / ooOoO0o . Ii1I * I1Ii111 + I1ii11iIi11i % IiII
  return ( [ [ II1i , O0O0oOo ] ] )
  if 42 - 42: iII111i % OoOoOO00 . OoooooooOO
  if 81 - 81: iII111i
  if 2 - 2: i1IIi
  if 60 - 60: OOooOOo + I1ii11iIi11i / OoOoOO00 * i1IIi / O0
  if 24 - 24: Oo0Ooo . IiII % o0oOOo0O0Ooo . OOooOOo . I1IiiI + I1Ii111
 ooO0ooooO = "ip route | egrep 'default via'"
 ooooO0OO0 = commands . getoutput ( ooO0ooooO ) . split ( "\n" )
 if 51 - 51: Oo0Ooo * I11i % i1IIi / iIii1I11I1II1 . OoooooooOO
 oOOoO = [ ]
 for Ooo00000oO in ooooO0OO0 :
  if ( Ooo00000oO . find ( " metric " ) != - 1 ) : continue
  i11iII1IiI = Ooo00000oO . split ( " " )
  try :
   IiIIIiiIiiI = i11iII1IiI . index ( "via" ) + 1
   if ( IiIIIiiIiiI >= len ( i11iII1IiI ) ) : continue
   oOoO0oO0O00o00O = i11iII1IiI . index ( "dev" ) + 1
   if ( oOoO0oO0O00o00O >= len ( i11iII1IiI ) ) : continue
  except :
   continue
   if 68 - 68: ooOoO0o + OoOoOO00 + iIii1I11I1II1
   if 21 - 21: iII111i + II111iiii - I1ii11iIi11i / OOooOOo + iII111i
  oOOoO . append ( [ i11iII1IiI [ oOoO0oO0O00o00O ] , i11iII1IiI [ IiIIIiiIiiI ] ] )
  if 60 - 60: iII111i . OoO0O00 / oO0o - OoO0O00 + ooOoO0o * I1Ii111
 return ( oOOoO )
 if 8 - 8: oO0o - O0 % I1IiiI . I1ii11iIi11i / I11i / I1Ii111
 if 18 - 18: Oo0Ooo % I1ii11iIi11i
 if 90 - 90: iII111i . O0
 if 6 - 6: I1IiiI + o0oOOo0O0Ooo . OoooooooOO * oO0o + OoooooooOO
 if 77 - 77: II111iiii / I1Ii111 * i11iIiiIii + OoooooooOO
 if 4 - 4: iIii1I11I1II1 - Oo0Ooo / OOooOOo % OoooooooOO . Oo0Ooo - Oo0Ooo
 if 41 - 41: II111iiii . o0oOOo0O0Ooo
def lisp_get_host_route_next_hop ( rloc ) :
 ooO0ooooO = "ip route | egrep '{} via'" . format ( rloc )
 Ooo00000oO = commands . getoutput ( ooO0ooooO ) . split ( " " )
 if 92 - 92: Ii1I - O0 - i11iIiiIii + IiII % I1Ii111 + II111iiii
 try : ooo = Ooo00000oO . index ( "via" ) + 1
 except : return ( None )
 if 71 - 71: ooOoO0o * I1Ii111 + i11iIiiIii + i1IIi . I1IiiI
 if ( ooo >= len ( Ooo00000oO ) ) : return ( None )
 return ( Ooo00000oO [ ooo ] )
 if 15 - 15: OoO0O00
 if 37 - 37: OoO0O00 . OoooooooOO - OOooOOo
 if 34 - 34: o0oOOo0O0Ooo + iIii1I11I1II1 / o0oOOo0O0Ooo / ooOoO0o
 if 53 - 53: II111iiii / iIii1I11I1II1
 if 25 - 25: I1Ii111
 if 58 - 58: OoOoOO00 * i1IIi
 if 20 - 20: IiII
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 ooooOOO0OoO = "none" if nh == None else nh
 if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , ooooOOO0OoO ) )
 if 30 - 30: i11iIiiIii . I1IiiI
 if ( nh == None ) :
  iI1i1iIIIII = "ip route {} {}/32" . format ( install , dest )
 else :
  iI1i1iIIIII = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 5 - 5: Ii1I / O0 + iIii1I11I1II1
 os . system ( iI1i1iIIIII )
 return
 if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
 if 79 - 79: iII111i
 if 71 - 71: i1IIi / OoO0O00 / OOooOOo + I1Ii111
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
 if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
 if 12 - 12: I1ii11iIi11i - i11iIiiIii + I1IiiI . Oo0Ooo
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 26 - 26: oO0o + I1Ii111 + IiII * o0oOOo0O0Ooo . oO0o
 ii11I1IIi = open ( lisp_checkpoint_filename , "w" )
 for I1iII11ii1 in checkpoint_list :
  ii11I1IIi . write ( I1iII11ii1 + "\n" )
  if 95 - 95: OoOoOO00 . I1Ii111 / Ii1I . I1Ii111 % OoO0O00
 ii11I1IIi . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 16 - 16: Ii1I / I1IiiI / I1IiiI - OoooooooOO
 if 13 - 13: OOooOOo / OoooooooOO
 if 7 - 7: II111iiii - ooOoO0o
 if 72 - 72: Ii1I
 if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
 if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
 if 87 - 87: II111iiii
 if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
 ii11I1IIi = open ( lisp_checkpoint_filename , "r" )
 if 24 - 24: i11iIiiIii + ooOoO0o
 OO = 0
 for I1iII11ii1 in ii11I1IIi :
  OO += 1
  oOo = I1iII11ii1 . split ( " rloc " )
  ooOOo = [ ] if ( oOo [ 1 ] in [ "native-forward\n" , "\n" ] ) else oOo [ 1 ] . split ( ", " )
  if 80 - 80: IiII % I11i % oO0o
  if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
  ooo0oo = [ ]
  for oOo00O in ooOOo :
   iIII = lisp_rloc ( False )
   i11iII1IiI = oOo00O . split ( " " )
   iIII . rloc . store_address ( i11iII1IiI [ 0 ] )
   iIII . priority = int ( i11iII1IiI [ 1 ] )
   iIII . weight = int ( i11iII1IiI [ 2 ] )
   ooo0oo . append ( iIII )
   if 70 - 70: iIii1I11I1II1
   if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
  IiiiiII1i = lisp_mapping ( "" , "" , ooo0oo )
  if ( IiiiiII1i != None ) :
   IiiiiII1i . eid . store_prefix ( oOo [ 0 ] )
   IiiiiII1i . checkpoint_entry = True
   IiiiiII1i . map_cache_ttl = LISP_NMR_TTL * 60
   if ( ooo0oo == [ ] ) : IiiiiII1i . action = LISP_NATIVE_FORWARD_ACTION
   IiiiiII1i . add_cache ( )
   continue
   if 64 - 64: iII111i - Oo0Ooo
   if 73 - 73: iIii1I11I1II1 * I1Ii111 * OoO0O00
  OO -= 1
  if 68 - 68: ooOoO0o * Ii1I / I1ii11iIi11i * OoooooooOO + OoooooooOO . OoooooooOO
  if 50 - 50: I1IiiI % o0oOOo0O0Ooo
 ii11I1IIi . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , OO , lisp_checkpoint_filename ) )
 return
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
 if 47 - 47: iII111i % iII111i
 if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 23 - 23: IiII + oO0o + o0oOOo0O0Ooo . I1ii11iIi11i / i11iIiiIii + iIii1I11I1II1
 I1iII11ii1 = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 74 - 74: I11i % OOooOOo
 for iIII in mc . rloc_set :
  if ( iIII . rloc . is_null ( ) ) : continue
  I1iII11ii1 += "{} {} {}, " . format ( iIII . rloc . print_address_no_iid ( ) ,
 iIII . priority , iIII . weight )
  if 57 - 57: O0 + I1IiiI + i11iIiiIii
  if 90 - 90: I1ii11iIi11i . OoO0O00 * iIii1I11I1II1 - Oo0Ooo
 if ( mc . rloc_set != [ ] ) :
  I1iII11ii1 = I1iII11ii1 [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  I1iII11ii1 += "native-forward"
  if 28 - 28: I1IiiI . ooOoO0o - ooOoO0o * OOooOOo . IiII
  if 16 - 16: iIii1I11I1II1 % i11iIiiIii / Ii1I % iIii1I11I1II1 / iII111i
 checkpoint_list . append ( I1iII11ii1 )
 return
 if 27 - 27: II111iiii * OoooooooOO / Oo0Ooo % O0
 if 41 - 41: oO0o / iIii1I11I1II1 % iII111i - I1Ii111 % I11i * i11iIiiIii
 if 21 - 21: O0
 if 14 - 14: IiII / I1ii11iIi11i + Ii1I
 if 48 - 48: I1Ii111 * oO0o / o0oOOo0O0Ooo * OoOoOO00 * ooOoO0o
 if 38 - 38: I1IiiI * Ii1I + Oo0Ooo - OoooooooOO
 if 63 - 63: I1ii11iIi11i
def lisp_check_dp_socket ( ) :
 O0OOoo0o00O = lisp_ipc_dp_socket_name
 if ( os . path . exists ( O0OOoo0o00O ) == False ) :
  IiII1iII1 = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( O0OOoo0o00O , IiII1iII1 ) )
  return ( False )
  if 1 - 1: Oo0Ooo * iIii1I11I1II1
 return ( True )
 if 28 - 28: iIii1I11I1II1
 if 49 - 49: II111iiii * Oo0Ooo
 if 74 - 74: OOooOOo % I1ii11iIi11i
 if 83 - 83: OoO0O00 + O0
 if 95 - 95: i1IIi % I11i
 if 75 - 75: I11i * Oo0Ooo
 if 73 - 73: O0
def lisp_write_to_dp_socket ( entry ) :
 try :
  OOOiii = json . dumps ( entry )
  O00oOoOoO0ooO = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( O00oOoOoO0ooO , OOOiii ) )
  lisp_ipc_dp_socket . sendto ( OOOiii , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( OOOiii ) )
  if 33 - 33: O0
 return
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
 if 46 - 46: OOooOOo
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
 if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
def lisp_write_ipc_keys ( rloc ) :
 oo0o00OO = rloc . rloc . print_address_no_iid ( )
 IiI1iI1 = rloc . translated_port
 if ( IiI1iI1 != 0 ) : oo0o00OO += ":" + str ( IiI1iI1 )
 if ( lisp_rloc_probe_list . has_key ( oo0o00OO ) == False ) : return
 if 32 - 32: I1Ii111 * I1IiiI + Ii1I
 for i11iII1IiI , oOo , i11ii in lisp_rloc_probe_list [ oo0o00OO ] :
  IiiiiII1i = lisp_map_cache . lookup_cache ( oOo , True )
  if ( IiiiiII1i == None ) : continue
  lisp_write_ipc_map_cache ( True , IiiiiII1i )
  if 30 - 30: OoooooooOO / I1IiiI . iIii1I11I1II1 / ooOoO0o
 return
 if 20 - 20: OoooooooOO * OOooOOo
 if 77 - 77: Ii1I - OoooooooOO . OoOoOO00
 if 93 - 93: OoooooooOO / I1Ii111
 if 91 - 91: I1Ii111
 if 18 - 18: ooOoO0o * I11i
 if 53 - 53: I11i . i11iIiiIii - iIii1I11I1II1 / I1Ii111
 if 86 - 86: i1IIi % OoO0O00 - OoooooooOO
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 63 - 63: o0oOOo0O0Ooo . iIii1I11I1II1 % IiII * i11iIiiIii
 if 70 - 70: iIii1I11I1II1
 if 12 - 12: OoOoOO00 / o0oOOo0O0Ooo - I1ii11iIi11i + oO0o + O0
 if 9 - 9: I1ii11iIi11i * OoooooooOO . O0 . ooOoO0o * i11iIiiIii / i1IIi
 IiI1III = "add" if add_or_delete else "delete"
 I1iII11ii1 = { "type" : "map-cache" , "opcode" : IiI1III }
 if 38 - 38: OoOoOO00 . OoooooooOO % I1ii11iIi11i . oO0o % oO0o
 iIIiI = ( mc . group . is_null ( ) == False )
 if ( iIIiI ) :
  I1iII11ii1 [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  I1iII11ii1 [ "rles" ] = [ ]
 else :
  I1iII11ii1 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  I1iII11ii1 [ "rlocs" ] = [ ]
  if 80 - 80: i11iIiiIii / OoOoOO00 . OOooOOo . iIii1I11I1II1
 I1iII11ii1 [ "instance-id" ] = str ( mc . eid . instance_id )
 if 81 - 81: I1ii11iIi11i * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO
 if ( iIIiI ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for iIIII1iiIII in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    IiiIIi1 = iIIII1iiIII . address . print_address_no_iid ( )
    IiI1iI1 = str ( 4341 ) if iIIII1iiIII . translated_port == 0 else str ( iIIII1iiIII . translated_port )
    if 64 - 64: Oo0Ooo . I1ii11iIi11i / ooOoO0o % oO0o . iIii1I11I1II1
    i11iII1IiI = { "rle" : IiiIIi1 , "port" : IiI1iI1 }
    IiiI , Oo0oO = iIIII1iiIII . get_encap_keys ( )
    i11iII1IiI = lisp_build_json_keys ( i11iII1IiI , IiiI , Oo0oO , "encrypt-key" )
    I1iII11ii1 [ "rles" ] . append ( i11iII1IiI )
    if 82 - 82: IiII * iIii1I11I1II1
    if 60 - 60: I1IiiI - I1IiiI + I1ii11iIi11i
 else :
  for oOo00O in mc . rloc_set :
   if ( oOo00O . rloc . is_ipv4 ( ) == False and oOo00O . rloc . is_ipv6 ( ) == False ) :
    continue
    if 8 - 8: I1Ii111 - I1Ii111 - i1IIi + I11i . i1IIi / I1Ii111
   if ( oOo00O . up_state ( ) == False ) : continue
   if 27 - 27: OoOoOO00 % ooOoO0o - II111iiii . I11i
   IiI1iI1 = str ( 4341 ) if oOo00O . translated_port == 0 else str ( oOo00O . translated_port )
   if 70 - 70: OOooOOo / iII111i - I11i + OoOoOO00 % Ii1I * IiII
   i11iII1IiI = { "rloc" : oOo00O . rloc . print_address_no_iid ( ) , "priority" :
 str ( oOo00O . priority ) , "weight" : str ( oOo00O . weight ) , "port" :
 IiI1iI1 }
   IiiI , Oo0oO = oOo00O . get_encap_keys ( )
   i11iII1IiI = lisp_build_json_keys ( i11iII1IiI , IiiI , Oo0oO , "encrypt-key" )
   I1iII11ii1 [ "rlocs" ] . append ( i11iII1IiI )
   if 26 - 26: O0 / oO0o
   if 96 - 96: ooOoO0o * iII111i . IiII
   if 77 - 77: OOooOOo - I11i % o0oOOo0O0Ooo
 if ( dont_send == False ) : lisp_write_to_dp_socket ( I1iII11ii1 )
 return ( I1iII11ii1 )
 if 46 - 46: I1IiiI % oO0o . OoooooooOO . IiII / I11i - i1IIi
 if 43 - 43: OoOoOO00 - o0oOOo0O0Ooo
 if 22 - 22: i1IIi
 if 33 - 33: O0
 if 34 - 34: I1Ii111 . IiII % iII111i
 if 94 - 94: OOooOOo % i11iIiiIii . OOooOOo
 if 55 - 55: OoOoOO00 . OoOoOO00 % o0oOOo0O0Ooo . I11i . I1ii11iIi11i - o0oOOo0O0Ooo
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 1 - 1: i11iIiiIii - i1IIi * oO0o - iIii1I11I1II1
 if 75 - 75: i1IIi * i11iIiiIii
 if 40 - 40: I1ii11iIi11i + OoO0O00
 if 8 - 8: i11iIiiIii - iIii1I11I1II1
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 73 - 73: OoOoOO00
 IiiI = keys [ 1 ] . encrypt_key
 Oo0oO = keys [ 1 ] . icv_key
 if 25 - 25: iII111i / oO0o
 if 61 - 61: OoooooooOO . Ii1I . I11i + oO0o
 if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
 if 61 - 61: I1IiiI / OOooOOo
 oo0000O = rloc_addr . split ( ":" )
 if ( len ( oo0000O ) == 1 ) :
  I1iII11ii1 = { "type" : "decap-keys" , "rloc" : oo0000O [ 0 ] }
 else :
  I1iII11ii1 = { "type" : "decap-keys" , "rloc" : oo0000O [ 0 ] , "port" : oo0000O [ 1 ] }
  if 57 - 57: I1IiiI . II111iiii . i1IIi * O0
 I1iII11ii1 = lisp_build_json_keys ( I1iII11ii1 , IiiI , Oo0oO , "decrypt-key" )
 if 90 - 90: i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
 lisp_write_to_dp_socket ( I1iII11ii1 )
 return
 if 95 - 95: ooOoO0o % OOooOOo
 if 17 - 17: i1IIi + Ii1I
 if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
 if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
 if 26 - 26: oO0o / I1ii11iIi11i - oO0o
 if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
 if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
 if 96 - 96: Ii1I
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 90 - 90: II111iiii
 entry [ "keys" ] = [ ]
 ii1i1I1111ii = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( ii1i1I1111ii )
 return ( entry )
 if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
 if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
 if 52 - 52: i11iIiiIii * ooOoO0o
 if 15 - 15: OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
 if 91 - 91: ooOoO0o
 if 47 - 47: II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
 if 9 - 9: O0 + IiII
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 69 - 69: I1IiiI
 if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
 if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
 if 86 - 86: ooOoO0o * OoOoOO00 + oO0o / II111iiii % OOooOOo
 I1iII11ii1 = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 89 - 89: O0 * Ii1I / OoO0O00 / OoOoOO00 % iII111i * iIii1I11I1II1
 if 72 - 72: iIii1I11I1II1 / iIii1I11I1II1 * I11i
 if 19 - 19: I1ii11iIi11i
 if 42 - 42: OoOoOO00 / IiII
 for Ooooo00 in lisp_db_list :
  if ( Ooooo00 . eid . is_ipv4 ( ) == False and Ooooo00 . eid . is_ipv6 ( ) == False ) : continue
  o000O0O0 = { "instance-id" : str ( Ooooo00 . eid . instance_id ) ,
 "eid-prefix" : Ooooo00 . eid . print_prefix_no_iid ( ) }
  I1iII11ii1 [ "database-mappings" ] . append ( o000O0O0 )
  if 74 - 74: ooOoO0o
 lisp_write_to_dp_socket ( I1iII11ii1 )
 if 93 - 93: Oo0Ooo % ooOoO0o
 if 38 - 38: II111iiii . I1Ii111 . iIii1I11I1II1 / o0oOOo0O0Ooo
 if 6 - 6: ooOoO0o - i1IIi * I1IiiI
 if 24 - 24: iIii1I11I1II1 / I1Ii111
 if 16 - 16: OoOoOO00 * I1Ii111 - I1IiiI / I1Ii111
 I1iII11ii1 = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( I1iII11ii1 )
 return
 if 64 - 64: I1ii11iIi11i . i1IIi % II111iiii % Oo0Ooo + oO0o - I1IiiI
 if 24 - 24: IiII . II111iiii . II111iiii . OoOoOO00 . i11iIiiIii
 if 11 - 11: Ii1I
 if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
 if 44 - 44: iII111i
 if 56 - 56: II111iiii / Oo0Ooo % IiII * II111iiii - iIii1I11I1II1 + ooOoO0o
 if 33 - 33: o0oOOo0O0Ooo . I11i / I1IiiI
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 29 - 29: o0oOOo0O0Ooo - ooOoO0o
 if 59 - 59: I11i / IiII * OoO0O00 / IiII . I1Ii111
 if 82 - 82: OOooOOo . iIii1I11I1II1 + I1Ii111
 if 14 - 14: IiII . i11iIiiIii
 I1iII11ii1 = { "type" : "interfaces" , "interfaces" : [ ] }
 if 17 - 17: ooOoO0o % ooOoO0o * oO0o
 for II1i in lisp_myinterfaces . values ( ) :
  if ( II1i . instance_id == None ) : continue
  o000O0O0 = { "interface" : II1i . device ,
 "instance-id" : str ( II1i . instance_id ) }
  I1iII11ii1 [ "interfaces" ] . append ( o000O0O0 )
  if 8 - 8: ooOoO0o + OoO0O00 . II111iiii / iIii1I11I1II1 - OOooOOo
  if 87 - 87: iIii1I11I1II1 . IiII % I1IiiI . OoO0O00 - I1Ii111
 lisp_write_to_dp_socket ( I1iII11ii1 )
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
 if 7 - 7: OoOoOO00 - OoO0O00 % OoOoOO00 . I1ii11iIi11i % Oo0Ooo * iII111i
def lisp_parse_auth_key ( value ) :
 oo0O = value . split ( "[" )
 o0O0o0Oo = { }
 if ( len ( oo0O ) == 1 ) :
  o0O0o0Oo [ 0 ] = value
  return ( o0O0o0Oo )
  if 98 - 98: o0oOOo0O0Ooo
  if 56 - 56: Ii1I % Ii1I + i11iIiiIii * iII111i / i11iIiiIii
 for O0Oo0 in oo0O :
  if ( O0Oo0 == "" ) : continue
  ooo = O0Oo0 . find ( "]" )
  IIIiI1i = O0Oo0 [ 0 : ooo ]
  try : IIIiI1i = int ( IIIiI1i )
  except : return
  if 53 - 53: ooOoO0o
  o0O0o0Oo [ IIIiI1i ] = O0Oo0 [ ooo + 1 : : ]
  if 58 - 58: OoOoOO00 - i11iIiiIii / OOooOOo . Oo0Ooo
 return ( o0O0o0Oo )
 if 54 - 54: IiII * i11iIiiIii . ooOoO0o . Ii1I
 if 60 - 60: Oo0Ooo % I11i - OoOoOO00 % II111iiii
 if 82 - 82: OoooooooOO % IiII / i11iIiiIii
 if 100 - 100: Ii1I / I1ii11iIi11i + OOooOOo + I1Ii111 / IiII
 if 13 - 13: IiII + iII111i . I1Ii111 - iII111i - o0oOOo0O0Ooo
 if 72 - 72: II111iiii . I11i % I1Ii111 % I1ii11iIi11i
 if 9 - 9: OoOoOO00 * II111iiii
 if 21 - 21: OoooooooOO
 if 34 - 34: i11iIiiIii / I1Ii111 - o0oOOo0O0Ooo / i1IIi * I11i
 if 87 - 87: IiII / I1IiiI . OoOoOO00
 if 80 - 80: i1IIi + OOooOOo % i11iIiiIii * I1ii11iIi11i
 if 49 - 49: iIii1I11I1II1
 if 2 - 2: OOooOOo * o0oOOo0O0Ooo - OOooOOo . I11i
 if 32 - 32: OoO0O00
 if 34 - 34: O0 * iIii1I11I1II1 . o0oOOo0O0Ooo . I1Ii111 . iIii1I11I1II1 * iIii1I11I1II1
 if 38 - 38: iIii1I11I1II1
def lisp_reassemble ( packet ) :
 O00000OO00OO = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 83 - 83: iII111i - Ii1I . oO0o - I1Ii111 * o0oOOo0O0Ooo
 if 70 - 70: i11iIiiIii - OoO0O00 / i11iIiiIii
 if 46 - 46: II111iiii + O0 * OoooooooOO
 if 39 - 39: OoooooooOO % II111iiii . o0oOOo0O0Ooo
 if ( O00000OO00OO == 0 or O00000OO00OO == 0x4000 ) : return ( packet )
 if 29 - 29: I11i . o0oOOo0O0Ooo . i1IIi . o0oOOo0O0Ooo
 if 77 - 77: iIii1I11I1II1 + iIii1I11I1II1
 if 52 - 52: I1ii11iIi11i - IiII % I1IiiI % i1IIi
 if 98 - 98: I1Ii111 + II111iiii % OoO0O00 % iII111i
 oOoO0O00o = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 OoI1i11IIii = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 88 - 88: II111iiii - ooOoO0o
 OO00oOOO0o0oo = ( O00000OO00OO & 0x2000 == 0 and ( O00000OO00OO & 0x1fff ) != 0 )
 I1iII11ii1 = [ ( O00000OO00OO & 0x1fff ) * 8 , OoI1i11IIii - 20 , packet , OO00oOOO0o0oo ]
 if 13 - 13: I1IiiI - Ii1I - iII111i - iIii1I11I1II1 . II111iiii
 if 40 - 40: I1ii11iIi11i * o0oOOo0O0Ooo + oO0o - OoOoOO00
 if 80 - 80: I1ii11iIi11i . OoooooooOO / ooOoO0o
 if 19 - 19: oO0o
 if 97 - 97: IiII
 if 36 - 36: II111iiii
 if 83 - 83: I11i . ooOoO0o
 if 57 - 57: IiII
 if ( O00000OO00OO == 0x2000 ) :
  i1i1IIiII1I , OOO = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  i1i1IIiII1I = socket . ntohs ( i1i1IIiII1I )
  OOO = socket . ntohs ( OOO )
  if ( OOO not in [ 4341 , 8472 , 4789 ] and i1i1IIiII1I != 4341 ) :
   lisp_reassembly_queue [ oOoO0O00o ] = [ ]
   I1iII11ii1 [ 2 ] = None
   if 34 - 34: I1ii11iIi11i + i11iIiiIii - I1ii11iIi11i / OoOoOO00 + i1IIi . i11iIiiIii
   if 48 - 48: I1ii11iIi11i % OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii / OoOoOO00
   if 73 - 73: OoOoOO00 + OOooOOo * II111iiii . OOooOOo % I1Ii111 % oO0o
   if 79 - 79: I1ii11iIi11i % I11i
   if 78 - 78: i11iIiiIii % I1Ii111 + iIii1I11I1II1 + iII111i
   if 66 - 66: I1IiiI - o0oOOo0O0Ooo
 if ( lisp_reassembly_queue . has_key ( oOoO0O00o ) == False ) :
  lisp_reassembly_queue [ oOoO0O00o ] = [ ]
  if 67 - 67: oO0o . iII111i * Ii1I - OOooOOo / oO0o
  if 98 - 98: OoOoOO00 * OoO0O00 . Oo0Ooo
  if 6 - 6: I11i % iIii1I11I1II1 + I1Ii111
  if 48 - 48: II111iiii . OOooOOo . ooOoO0o - iII111i
  if 90 - 90: OOooOOo
 i11iii = lisp_reassembly_queue [ oOoO0O00o ]
 if 89 - 89: Oo0Ooo / iIii1I11I1II1 . OoOoOO00
 if 6 - 6: Ii1I / iII111i
 if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
 if 70 - 70: oO0o - I1IiiI + Ii1I
 if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
 if ( len ( i11iii ) == 1 and i11iii [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( oOoO0O00o ) . zfill ( 4 ) ) )
  if 37 - 37: o0oOOo0O0Ooo
  return ( None )
  if 57 - 57: iII111i / i1IIi / i1IIi + IiII
  if 75 - 75: IiII / O0
  if 72 - 72: I11i
  if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
  if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
 i11iii . append ( I1iII11ii1 )
 i11iii = sorted ( i11iii )
 if 23 - 23: OoOoOO00 . oO0o - iII111i
 if 27 - 27: Oo0Ooo * OOooOOo - OoOoOO00
 if 1 - 1: II111iiii * i11iIiiIii . OoooooooOO
 if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
 IiiIIi1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 IiiIIi1 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 O0OooooOo0o0o0oO = IiiIIi1 . print_address_no_iid ( )
 IiiIIi1 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 IIiI = IiiIIi1 . print_address_no_iid ( )
 IiiIIi1 = red ( "{} -> {}" . format ( O0OooooOo0o0o0oO , IIiI ) , False )
 if 93 - 93: OoOoOO00 + iII111i
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if I1iII11ii1 [ 2 ] == None else "" , IiiIIi1 , lisp_hex_string ( oOoO0O00o ) . zfill ( 4 ) ,
 # i11iIiiIii / i11iIiiIii % OoooooooOO
 # OOooOOo * O0 % ooOoO0o - ooOoO0o
 lisp_hex_string ( O00000OO00OO ) . zfill ( 4 ) ) )
 if 46 - 46: o0oOOo0O0Ooo * oO0o / oO0o . oO0o + I11i * OOooOOo
 if 48 - 48: iII111i + Ii1I
 if 10 - 10: I1IiiI + o0oOOo0O0Ooo
 if 75 - 75: Oo0Ooo
 if 100 - 100: i1IIi / Oo0Ooo / II111iiii + iII111i . II111iiii * oO0o
 if ( i11iii [ 0 ] [ 0 ] != 0 or i11iii [ - 1 ] [ 3 ] == False ) : return ( None )
 IIi1I11oO = i11iii [ 0 ]
 for oO in i11iii [ 1 : : ] :
  O00000OO00OO = oO [ 0 ]
  o00o , IiIoo0OO0Oo0ooo0 = IIi1I11oO [ 0 ] , IIi1I11oO [ 1 ]
  if ( o00o + IiIoo0OO0Oo0ooo0 != O00000OO00OO ) : return ( None )
  IIi1I11oO = oO
  if 87 - 87: I1IiiI + Ii1I * I11i
 lisp_reassembly_queue . pop ( oOoO0O00o )
 if 77 - 77: IiII / I1Ii111 * OoOoOO00 . O0 % I11i
 if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
 if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
 if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
 if 53 - 53: I1IiiI % I1IiiI
 packet = i11iii [ 0 ] [ 2 ]
 for oO in i11iii [ 1 : : ] : packet += oO [ 2 ] [ 20 : : ]
 if 80 - 80: OoO0O00 - i11iIiiIii / iII111i * I1ii11iIi11i / I1IiiI - I1Ii111
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( oOoO0O00o ) . zfill ( 4 ) , len ( packet ) ) )
 if 85 - 85: IiII
 if 72 - 72: iII111i * OoOoOO00
 if 65 - 65: iIii1I11I1II1 / iIii1I11I1II1 % O0 / II111iiii . OOooOOo . O0
 if 65 - 65: I11i
 if 35 - 35: o0oOOo0O0Ooo - i11iIiiIii
 iiiIIiiIi = socket . htons ( len ( packet ) )
 Ii1I1i1IiiI = packet [ 0 : 2 ] + struct . pack ( "H" , iiiIIiiIi ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 78 - 78: ooOoO0o - II111iiii - i1IIi
 if 18 - 18: OoooooooOO % OoOoOO00 - IiII / oO0o . OOooOOo . I1IiiI
 Ii1I1i1IiiI = lisp_ip_checksum ( Ii1I1i1IiiI )
 return ( Ii1I1i1IiiI + packet [ 20 : : ] )
 if 77 - 77: I1ii11iIi11i . OoO0O00 / OoOoOO00 / O0
 if 67 - 67: ooOoO0o % I11i % oO0o
 if 74 - 74: II111iiii
 if 44 - 44: Oo0Ooo + OoO0O00 + OoOoOO00 - I1IiiI
 if 68 - 68: i11iIiiIii / OOooOOo . i1IIi . i11iIiiIii . I11i
 if 56 - 56: iIii1I11I1II1 - II111iiii * i1IIi / Ii1I
 if 65 - 65: OOooOOo / I1IiiI . OoooooooOO + I1IiiI + OoooooooOO + i11iIiiIii
 if 20 - 20: I1IiiI + iII111i + O0 * O0
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 oo0o00OO = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( oo0o00OO ) ) : return ( oo0o00OO )
 if 18 - 18: I11i - I11i . OoOoOO00 . ooOoO0o
 oo0o00OO = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( oo0o00OO ) ) : return ( oo0o00OO )
 if 31 - 31: ooOoO0o
 if 87 - 87: OoooooooOO + OOooOOo - I1ii11iIi11i / I1IiiI + ooOoO0o - Oo0Ooo
 if 19 - 19: ooOoO0o + I1ii11iIi11i - ooOoO0o
 if 17 - 17: I11i * i1IIi + iIii1I11I1II1 % I1IiiI
 if 44 - 44: IiII + I1IiiI . Ii1I % Oo0Ooo
 for o0Oo00Ooo in lisp_crypto_keys_by_rloc_decap :
  OO0o = o0Oo00Ooo . split ( ":" )
  if ( len ( OO0o ) == 1 ) : continue
  OO0o = OO0o [ 0 ] if len ( OO0o ) == 2 else ":" . join ( OO0o [ 0 : - 1 ] )
  if ( OO0o == oo0o00OO ) :
   oOoo0oO = lisp_crypto_keys_by_rloc_decap [ o0Oo00Ooo ]
   lisp_crypto_keys_by_rloc_decap [ oo0o00OO ] = oOoo0oO
   return ( oo0o00OO )
   if 10 - 10: oO0o
   if 53 - 53: i1IIi - iIii1I11I1II1 * o0oOOo0O0Ooo / OoooooooOO
 return ( None )
 if 30 - 30: OOooOOo . iIii1I11I1II1 * ooOoO0o * OoooooooOO / I1IiiI
 if 67 - 67: OoOoOO00 % iII111i . o0oOOo0O0Ooo / II111iiii * O0 / I1IiiI
 if 20 - 20: oO0o * O0 - Ii1I + i11iIiiIii - OoOoOO00
 if 18 - 18: I1ii11iIi11i . iII111i
 if 31 - 31: I11i * o0oOOo0O0Ooo
 if 17 - 17: Ii1I * iIii1I11I1II1
 if 9 - 9: o0oOOo0O0Ooo - IiII
 if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
 if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
 if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
 if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 i1Ii11IIIi = addr + ":" + str ( port )
 if 98 - 98: i1IIi
 if ( lisp_i_am_rtr ) :
  if ( lisp_rloc_probe_list . has_key ( addr ) ) : return ( addr )
  if 19 - 19: OoO0O00 % I1ii11iIi11i + I1ii11iIi11i
  if 3 - 3: i11iIiiIii - iIii1I11I1II1 / OoOoOO00
  if 34 - 34: I1IiiI . IiII / ooOoO0o + I1Ii111 / iIii1I11I1II1 + OoooooooOO
  if 80 - 80: OoO0O00 - OoOoOO00 % i1IIi / iIii1I11I1II1 . I11i - I11i
  if 76 - 76: ooOoO0o * iII111i / Ii1I * i1IIi . I1Ii111 - o0oOOo0O0Ooo
  if 52 - 52: OoOoOO00 % O0 + I1ii11iIi11i . i11iIiiIii
  for O00OOoOOO0O0O in lisp_nat_state_info . values ( ) :
   for o0i1i in O00OOoOOO0O0O :
    if ( addr == o0i1i . address ) : return ( i1Ii11IIIi )
    if 59 - 59: Ii1I - I1Ii111 . ooOoO0o - OoOoOO00 + oO0o . OoO0O00
    if 88 - 88: OOooOOo - ooOoO0o * o0oOOo0O0Ooo . OoooooooOO
  return ( addr )
  if 3 - 3: I1Ii111
 return ( i1Ii11IIIi )
 if 24 - 24: Ii1I + i11iIiiIii * I1Ii111 - OoOoOO00 / Ii1I - OoOoOO00
 if 69 - 69: I11i - I1IiiI . oO0o - OoooooooOO
 if 33 - 33: o0oOOo0O0Ooo - o0oOOo0O0Ooo
 if 55 - 55: OoooooooOO / IiII + i1IIi
 if 54 - 54: ooOoO0o * Ii1I / Ii1I
 if 15 - 15: oO0o * I1Ii111
 if 11 - 11: Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
 return
 if 46 - 46: oO0o + OoOoOO00
 if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
 if 59 - 59: O0
 if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
 if 17 - 17: Ii1I % I1ii11iIi11i + I11i
 if 80 - 80: i1IIi . OoooooooOO % OoooooooOO . oO0o / OOooOOo
 if 85 - 85: OOooOOo
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 80 - 80: ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
 if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
 if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
 if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
 if 72 - 72: IiII / II111iiii
 if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
 if 21 - 21: I1ii11iIi11i
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
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
 if 86 - 86: Oo0Ooo % II111iiii + I1Ii111 / I1ii11iIi11i
 if 15 - 15: I1IiiI / I1Ii111 % iII111i
 if 57 - 57: I1Ii111 . iIii1I11I1II1 / Oo0Ooo / IiII / iII111i * OoOoOO00
 if 35 - 35: i1IIi + I1Ii111 - ooOoO0o . I1ii11iIi11i + Oo0Ooo
 if 43 - 43: oO0o . OoO0O00 * i1IIi
 if 1 - 1: ooOoO0o / i1IIi
 if 42 - 42: I1ii11iIi11i * ooOoO0o + OoOoOO00 % I1ii11iIi11i . IiII
 if 75 - 75: OoO0O00 * i1IIi - OOooOOo % II111iiii % OoO0O00 - OoOoOO00
 if 75 - 75: I11i * IiII * ooOoO0o
def lisp_is_rloc_probe ( packet , rr ) :
 o0oOo00 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( o0oOo00 == False ) : return ( [ packet , None , None , None ] )
 if 31 - 31: Ii1I
 i1i1IIiII1I = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 OOO = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 o000O00OOOOOo = ( socket . htons ( LISP_CTRL_PORT ) in [ i1i1IIiII1I , OOO ] )
 if ( o000O00OOOOOo == False ) : return ( [ packet , None , None , None ] )
 if 84 - 84: OoO0O00 + OoooooooOO + oO0o
 if ( rr == 0 ) :
  OOO0oOooOOo00 = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( OOO0oOooOOo00 == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  OOO0oOooOOo00 = lisp_is_rloc_probe_reply ( packet [ 28 ] )
  if ( OOO0oOooOOo00 == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  OOO0oOooOOo00 = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( OOO0oOooOOo00 == False ) :
   OOO0oOooOOo00 = lisp_is_rloc_probe_reply ( packet [ 28 ] )
   if ( OOO0oOooOOo00 == False ) : return ( [ packet , None , None , None ] )
   if 3 - 3: iIii1I11I1II1 * i1IIi
   if 5 - 5: ooOoO0o
   if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
   if 88 - 88: OoooooooOO . I1IiiI
   if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
   if 7 - 7: i1IIi
 oo00Oo0 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 oo00Oo0 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
 if 34 - 34: iII111i + i11iIiiIii . IiII
 if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
 if 29 - 29: II111iiii % i11iIiiIii % O0
 if ( oo00Oo0 . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 38 - 38: o0oOOo0O0Ooo * IiII
 if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
 if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
 if 19 - 19: OoooooooOO
 oo00Oo0 = oo00Oo0 . print_address_no_iid ( )
 IiI1iI1 = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 oo0o = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 34 - 34: OoOoOO00 . oO0o
 i11iII1IiI = bold ( "Receive(pcap)" , False )
 ii11I1IIi = bold ( "from " + oo00Oo0 , False )
 III1I1Iii1 = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( i11iII1IiI , len ( packet ) , ii11I1IIi , IiI1iI1 , III1I1Iii1 ) )
 if 53 - 53: oO0o + OoooooooOO * ooOoO0o
 return ( [ packet , oo00Oo0 , IiI1iI1 , oo0o ] )
 if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
 if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
 if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
 if 80 - 80: II111iiii . i11iIiiIii
 if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
 if 33 - 33: iIii1I11I1II1
 if 52 - 52: iIii1I11I1II1 + O0
 if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
 if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
 if 29 - 29: iII111i % I1Ii111
 if 95 - 95: OOooOOo - ooOoO0o % i1IIi / O0 % I11i . IiII
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 63 - 63: ooOoO0o
 OoOO0o00OOO0o = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 22 - 22: OOooOOo . i11iIiiIii + II111iiii - Oo0Ooo % i1IIi / o0oOOo0O0Ooo
 lisp_write_to_dp_socket ( OoOO0o00OOO0o )
 return
 if 90 - 90: IiII
 if 38 - 38: i1IIi / ooOoO0o / I11i * I1ii11iIi11i / II111iiii . iIii1I11I1II1
 if 52 - 52: I1ii11iIi11i % ooOoO0o * Ii1I * IiII + IiII / i11iIiiIii
 if 51 - 51: iIii1I11I1II1 * o0oOOo0O0Ooo % o0oOOo0O0Ooo . Ii1I / OoooooooOO
 if 23 - 23: oO0o * I1IiiI - oO0o - ooOoO0o . IiII / i11iIiiIii
 if 53 - 53: Ii1I * Ii1I . OoOoOO00 . OOooOOo / I1ii11iIi11i % O0
 if 98 - 98: OOooOOo
 if 11 - 11: OOooOOo * iIii1I11I1II1 % IiII - I1IiiI . I11i
def lisp_external_data_plane ( ) :
 ooO0ooooO = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( commands . getoutput ( ooO0ooooO ) != "" ) : return ( True )
 if 29 - 29: OOooOOo % I11i - OOooOOo - OOooOOo * I11i . oO0o
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 75 - 75: II111iiii . O0 . I1Ii111 * O0 / OoooooooOO
 if 60 - 60: OOooOOo - Oo0Ooo * OOooOOo / OoO0O00
 if 55 - 55: I1ii11iIi11i * II111iiii * iIii1I11I1II1
 if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i . Ii1I + I1IiiI % i11iIiiIii - i11iIiiIii
 if 62 - 62: I1Ii111 + I1IiiI
 if 9 - 9: iIii1I11I1II1 / iIii1I11I1II1
 if 24 - 24: OOooOOo . I1IiiI % i11iIiiIii
 if 43 - 43: OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i + OoO0O00 . I1Ii111 . iII111i
 if 1 - 1: iII111i / OoO0O00 / OoOoOO00 * Oo0Ooo * OoooooooOO
 if 59 - 59: iII111i
 if 14 - 14: oO0o . IiII + iIii1I11I1II1 - i1IIi
 if 46 - 46: i11iIiiIii * II111iiii / i11iIiiIii % i11iIiiIii * II111iiii + i11iIiiIii
 if 87 - 87: Oo0Ooo + OoO0O00 / II111iiii * OoooooooOO
 if 95 - 95: I1Ii111 * o0oOOo0O0Ooo + OoO0O00 % OoOoOO00 - ooOoO0o / OoOoOO00
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 45 - 45: OoooooooOO / oO0o / o0oOOo0O0Ooo + Ii1I + O0 . iII111i
 iiIOooo0000O0O00 = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 79 - 79: OoOoOO00 . IiII * iII111i % OoooooooOO % i1IIi % iIii1I11I1II1
 if ( do_clear == False ) :
  oOooiIIIii1Ii1Ii1 = iiIOooo0000O0O00 [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , oOooiIIIii1Ii1Ii1 )
  if 20 - 20: I1Ii111 % oO0o * iIii1I11I1II1 % oO0o . IiII % OoooooooOO
  if 11 - 11: Oo0Ooo / Oo0Ooo / OoO0O00 / oO0o . iIii1I11I1II1 + I1Ii111
 lisp_write_to_dp_socket ( iiIOooo0000O0O00 )
 return
 if 23 - 23: Oo0Ooo * IiII - I1Ii111 . OoooooooOO
 if 78 - 78: OoOoOO00 - iIii1I11I1II1
 if 20 - 20: i1IIi
 if 72 - 72: ooOoO0o . II111iiii
 if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
 if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
 if 18 - 18: o0oOOo0O0Ooo / OOooOOo
 if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
 if 100 - 100: O0
 if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
 if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
 if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
 if 38 - 38: Ii1I
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
  if 36 - 36: I1Ii111 - OoO0O00 . I1ii11iIi11i * I1ii11iIi11i
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 9 - 9: OOooOOo - oO0o - iIii1I11I1II1 * i11iIiiIii / I11i
  I11i11i1 = msg [ "eid-prefix" ]
  if 2 - 2: i1IIi % iII111i * ooOoO0o / OoOoOO00 + Oo0Ooo
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 59 - 59: i11iIiiIii / I1IiiI * iII111i
  o0OoO0000o = int ( msg [ "instance-id" ] )
  if 16 - 16: i11iIiiIii * II111iiii - ooOoO0o
  if 80 - 80: iIii1I11I1II1 + iIii1I11I1II1 + I1Ii111 - IiII * iII111i - Ii1I
  if 89 - 89: O0 * ooOoO0o
  if 36 - 36: I1ii11iIi11i * II111iiii * iII111i + I1IiiI + OoO0O00 + oO0o
  OOo0O0O0o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
  OOo0O0O0o0 . store_prefix ( I11i11i1 )
  IiiiiII1i = lisp_map_cache_lookup ( None , OOo0O0O0o0 )
  if ( IiiiiII1i == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( I11i11i1 ) )
   if 28 - 28: Ii1I - i11iIiiIii . oO0o / II111iiii
   continue
   if 82 - 82: iII111i * iII111i . IiII * II111iiii
   if 17 - 17: OoooooooOO % I1Ii111 * I1Ii111 / II111iiii . OoOoOO00 * iII111i
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( I11i11i1 ) )
   if 80 - 80: IiII % i11iIiiIii
   continue
   if 6 - 6: II111iiii + i11iIiiIii - Oo0Ooo % OOooOOo + Oo0Ooo
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 46 - 46: iII111i
  iIi1iii = msg [ "rlocs" ]
  if 60 - 60: OoooooooOO + i11iIiiIii - o0oOOo0O0Ooo . OoooooooOO + oO0o / ooOoO0o
  if 93 - 93: I1ii11iIi11i - ooOoO0o - Oo0Ooo + o0oOOo0O0Ooo . ooOoO0o
  if 98 - 98: II111iiii
  if 56 - 56: i1IIi % IiII / I1Ii111
  for IIIIII1I in iIi1iii :
   if ( IIIIII1I . has_key ( "rloc" ) == False ) : continue
   if 100 - 100: ooOoO0o % II111iiii - Oo0Ooo / OoO0O00 - I1Ii111 * IiII
   o0O00oo0O = IIIIII1I [ "rloc" ]
   if ( o0O00oo0O == "no-address" ) : continue
   if 61 - 61: OoOoOO00 - I1Ii111 * ooOoO0o + Oo0Ooo / IiII
   oOo00O = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   oOo00O . store_address ( o0O00oo0O )
   if 79 - 79: ooOoO0o % OoooooooOO
   iIII = IiiiiII1i . get_rloc ( oOo00O )
   if ( iIII == None ) : continue
   if 67 - 67: I1IiiI + OoooooooOO % OoO0O00 . OoooooooOO + I11i / oO0o
   if 33 - 33: I1ii11iIi11i
   if 5 - 5: O0
   if 50 - 50: Oo0Ooo % IiII * oO0o
   oO0OO0 = 0 if IIIIII1I . has_key ( "packet-count" ) == False else IIIIII1I [ "packet-count" ]
   if 58 - 58: oO0o + I1Ii111 + Oo0Ooo
   oOooO0O0 = 0 if IIIIII1I . has_key ( "byte-count" ) == False else IIIIII1I [ "byte-count" ]
   if 57 - 57: Ii1I % i11iIiiIii * Ii1I + i1IIi * iIii1I11I1II1
   Oo0OO0000oooo = 0 if IIIIII1I . has_key ( "seconds-last-packet" ) == False else IIIIII1I [ "seconds-last-packet" ]
   if 42 - 42: iIii1I11I1II1 . I1IiiI
   if 57 - 57: IiII - i1IIi * ooOoO0o
   iIII . stats . packet_count += oO0OO0
   iIII . stats . byte_count += oOooO0O0
   iIII . stats . last_increment = lisp_get_timestamp ( ) - Oo0OO0000oooo
   if 5 - 5: oO0o . O0 * IiII / Ii1I + OoO0O00
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( oO0OO0 , oOooO0O0 ,
 Oo0OO0000oooo , I11i11i1 , o0O00oo0O ) )
   if 75 - 75: OOooOOo * OoOoOO00
   if 82 - 82: Ii1I
   if 83 - 83: I1IiiI
   if 22 - 22: IiII / Ii1I + I1Ii111 % iIii1I11I1II1
   if 75 - 75: OoOoOO00 % OoOoOO00 % o0oOOo0O0Ooo % I1ii11iIi11i + IiII
  if ( IiiiiII1i . group . is_null ( ) and IiiiiII1i . has_ttl_elapsed ( ) ) :
   I11i11i1 = green ( IiiiiII1i . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( I11i11i1 ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , IiiiiII1i . eid , None )
   if 45 - 45: I11i - iIii1I11I1II1
   if 20 - 20: OoOoOO00
 return
 if 84 - 84: OoOoOO00
 if 59 - 59: Ii1I / I1Ii111 + i11iIiiIii
 if 20 - 20: O0 / I1Ii111 - OOooOOo % iIii1I11I1II1
 if 89 - 89: O0 * OoOoOO00 . ooOoO0o
 if 11 - 11: iIii1I11I1II1 * OoO0O00 . I1IiiI * OoOoOO00 / II111iiii
 if 72 - 72: I11i
 if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
 if 62 - 62: OoOoOO00 * oO0o - I1IiiI / Ii1I
 if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
 if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
 if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
 if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
 if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
 if 9 - 9: i1IIi % iII111i / Ii1I
 if 83 - 83: oO0o
 if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
 if 29 - 29: OoooooooOO
 if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
 if 83 - 83: iIii1I11I1II1
 if 92 - 92: OoO0O00 - iII111i
 if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
 if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
 if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 70 - 70: I1Ii111 % iIii1I11I1II1
 if 74 - 74: i1IIi % i11iIiiIii + oO0o
 if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
 if 34 - 34: Oo0Ooo . i1IIi
 if 97 - 97: I11i
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  OoOO0o00OOO0o = "stats%{}" . format ( json . dumps ( msg ) )
  OoOO0o00OOO0o = lisp_command_ipc ( OoOO0o00OOO0o , "lisp-itr" )
  lisp_ipc ( OoOO0o00OOO0o , lisp_ipc_socket , "lisp-etr" )
  return
  if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
  if 20 - 20: oO0o % OoOoOO00
  if 93 - 93: I1ii11iIi11i - Ii1I % i1IIi / i1IIi
  if 82 - 82: OOooOOo
  if 27 - 27: I1Ii111 / IiII - i1IIi * Ii1I
  if 90 - 90: ooOoO0o
  if 100 - 100: iII111i * i1IIi . iII111i / O0 / OoO0O00 - oO0o
  if 65 - 65: OoOoOO00 + ooOoO0o * OoO0O00 % OoooooooOO + OoooooooOO * OoooooooOO
 OoOO0o00OOO0o = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( OoOO0o00OOO0o , msg ) )
 if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
 Oo00oO0OOOOO0 = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 10 - 10: o0oOOo0O0Ooo / OOooOOo + i11iIiiIii
 for O00O0ooOOooo in Oo00oO0OOOOO0 :
  oO0OO0 = 0 if msg . has_key ( O00O0ooOOooo ) == False else msg [ O00O0ooOOooo ] [ "packet-count" ]
  if 89 - 89: Oo0Ooo % iII111i . iIii1I11I1II1 % I11i * Oo0Ooo - ooOoO0o
  lisp_decap_stats [ O00O0ooOOooo ] . packet_count += oO0OO0
  if 14 - 14: iIii1I11I1II1
  oOooO0O0 = 0 if msg . has_key ( O00O0ooOOooo ) == False else msg [ O00O0ooOOooo ] [ "byte-count" ]
  if 29 - 29: i1IIi
  lisp_decap_stats [ O00O0ooOOooo ] . byte_count += oOooO0O0
  if 12 - 12: OOooOOo
  Oo0OO0000oooo = 0 if msg . has_key ( O00O0ooOOooo ) == False else msg [ O00O0ooOOooo ] [ "seconds-last-packet" ]
  if 84 - 84: i11iIiiIii * o0oOOo0O0Ooo
  lisp_decap_stats [ O00O0ooOOooo ] . last_increment = lisp_get_timestamp ( ) - Oo0OO0000oooo
  if 24 - 24: Ii1I . OOooOOo
 return
 if 34 - 34: I11i % Oo0Ooo . II111iiii - OoO0O00 - I1Ii111 + Oo0Ooo
 if 71 - 71: O0 + OOooOOo % OoooooooOO
 if 51 - 51: I1ii11iIi11i * o0oOOo0O0Ooo * I11i
 if 27 - 27: OoOoOO00 % OoO0O00 * oO0o . II111iiii - i11iIiiIii
 if 56 - 56: OOooOOo . IiII - OOooOOo / i11iIiiIii * I1ii11iIi11i
 if 66 - 66: oO0o + ooOoO0o
 if 1 - 1: ooOoO0o
 if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
 if 75 - 75: Ii1I
 if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
 if 99 - 99: oO0o + I11i % i1IIi . iII111i
 if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
 if 65 - 65: OoO0O00
 if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
 if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
 if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
 if 74 - 74: OoOoOO00 + I1ii11iIi11i
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 oO0o0i11I1IiI , oo00Oo0 = punt_socket . recvfrom ( 4000 )
 if 43 - 43: i1IIi * Oo0Ooo + iIii1I11I1II1
 oooooO0O0O = json . loads ( oO0o0i11I1IiI )
 if ( type ( oooooO0O0O ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( oo00Oo0 ) )
  if 70 - 70: iIii1I11I1II1
  return
  if 85 - 85: OoooooooOO * O0 % o0oOOo0O0Ooo % Ii1I . OoooooooOO - I11i
 o0ooooO = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( o0ooooO , oo00Oo0 , oooooO0O0O ) )
 if 19 - 19: iII111i * i1IIi - I11i + O0 % Ii1I - OoOoOO00
 if ( oooooO0O0O . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 1 - 1: I11i * Oo0Ooo
  if 53 - 53: II111iiii / i1IIi + OoooooooOO * O0
  if 62 - 62: IiII . O0
  if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
  if 91 - 91: OOooOOo % oO0o . OoOoOO00 . I1IiiI - OoOoOO00
 if ( oooooO0O0O [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( oooooO0O0O , lisp_send_sockets , lisp_ephem_port )
  return
  if 18 - 18: O0 - I1IiiI + i1IIi % i11iIiiIii
 if ( oooooO0O0O [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( oooooO0O0O , punt_socket )
  return
  if 97 - 97: iII111i * OoooooooOO + I1Ii111 + ooOoO0o - ooOoO0o
  if 63 - 63: o0oOOo0O0Ooo * OOooOOo + iIii1I11I1II1 + Oo0Ooo
  if 25 - 25: oO0o + IiII % o0oOOo0O0Ooo
  if 24 - 24: OoOoOO00
  if 87 - 87: I1ii11iIi11i / ooOoO0o * i1IIi
 if ( oooooO0O0O [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 71 - 71: OoOoOO00 - I11i
  if 83 - 83: oO0o + oO0o - Oo0Ooo . Oo0Ooo - iII111i . OOooOOo
  if 56 - 56: OoOoOO00 * IiII + i1IIi
  if 40 - 40: I1ii11iIi11i / O0
  if 87 - 87: ooOoO0o
 if ( oooooO0O0O [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 100 - 100: iII111i + II111iiii * Oo0Ooo * OOooOOo
 if ( oooooO0O0O . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( oo00Oo0 ) )
  if 6 - 6: IiII % OOooOOo
  return
  if 3 - 3: OoOoOO00 / OoOoOO00 - II111iiii
  if 41 - 41: oO0o
  if 12 - 12: I1IiiI + I1Ii111
  if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
  if 74 - 74: O0 % OOooOOo * OoOoOO00 / oO0o - Oo0Ooo
 OoO0o0OOOO = oooooO0O0O [ "interface" ]
 if ( OoO0o0OOOO == "" ) :
  o0OoO0000o = int ( oooooO0O0O [ "instance-id" ] )
  if ( o0OoO0000o == - 1 ) : return
 else :
  o0OoO0000o = lisp_get_interface_instance_id ( OoO0o0OOOO , None )
  if 79 - 79: Ii1I + IiII
  if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
  if 98 - 98: I1ii11iIi11i
  if 58 - 58: IiII / i11iIiiIii % I11i
  if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
 O00oOOOOoOO = None
 if ( oooooO0O0O . has_key ( "source-eid" ) ) :
  o0000oO0OOOo0 = oooooO0O0O [ "source-eid" ]
  O00oOOOOoOO = lisp_address ( LISP_AFI_NONE , o0000oO0OOOo0 , 0 , o0OoO0000o )
  if ( O00oOOOOoOO . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( o0000oO0OOOo0 ) )
   return
   if 21 - 21: Ii1I
   if 72 - 72: I1Ii111 . OoooooooOO / I1Ii111 - Ii1I / I1ii11iIi11i * I1ii11iIi11i
 I11iIii1i11 = None
 if ( oooooO0O0O . has_key ( "dest-eid" ) ) :
  O0IiIIiI1111iI = oooooO0O0O [ "dest-eid" ]
  I11iIii1i11 = lisp_address ( LISP_AFI_NONE , O0IiIIiI1111iI , 0 , o0OoO0000o )
  if ( I11iIii1i11 . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( O0IiIIiI1111iI ) )
   return
   if 78 - 78: iIii1I11I1II1 - OoOoOO00 * I1IiiI + I1ii11iIi11i
   if 34 - 34: Ii1I / Oo0Ooo - II111iiii + iIii1I11I1II1 . I1ii11iIi11i % II111iiii
   if 37 - 37: OoO0O00 * i1IIi
   if 84 - 84: OOooOOo . ooOoO0o % iIii1I11I1II1
   if 52 - 52: I1IiiI / OoO0O00 + OoOoOO00
   if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
   if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
   if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
 if ( O00oOOOOoOO ) :
  oOo = green ( O00oOOOOoOO . print_address ( ) , False )
  Ooooo00 = lisp_db_for_lookups . lookup_cache ( O00oOOOOoOO , False )
  if ( Ooooo00 != None ) :
   if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
   if 26 - 26: Ii1I * I11i / I11i
   if 79 - 79: ooOoO0o / oO0o - oO0o / OoooooooOO
   if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
   if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
   if ( Ooooo00 . dynamic_eid_configured ( ) ) :
    II1i = lisp_allow_dynamic_eid ( OoO0o0OOOO , O00oOOOOoOO )
    if ( II1i != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( Ooooo00 , O00oOOOOoOO , OoO0o0OOOO , II1i )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( oOo , OoO0o0OOOO ) )
     if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
     if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
     if 16 - 16: I11i
  else :
   lprint ( "Punt from non-EID source {}" . format ( oOo ) )
   if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
   if 61 - 61: O0 % iII111i
   if 41 - 41: I1Ii111 * OoooooooOO
   if 76 - 76: OoooooooOO * II111iiii . II111iiii / o0oOOo0O0Ooo - iII111i
   if 49 - 49: O0 . I1ii11iIi11i . OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
   if 19 - 19: iIii1I11I1II1
 if ( I11iIii1i11 ) :
  IiiiiII1i = lisp_map_cache_lookup ( O00oOOOOoOO , I11iIii1i11 )
  if ( IiiiiII1i == None or IiiiiII1i . action == LISP_SEND_MAP_REQUEST_ACTION ) :
   if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
   if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
   if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
   if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
   if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
   if ( lisp_rate_limit_map_request ( O00oOOOOoOO , I11iIii1i11 ) ) : return
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 O00oOOOOoOO , I11iIii1i11 , None )
  else :
   oOo = green ( I11iIii1i11 . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( oOo ) )
   if 57 - 57: i1IIi
   if 41 - 41: I11i / Ii1I
 return
 if 1 - 1: II111iiii / iII111i
 if 83 - 83: OoO0O00 / iII111i
 if 59 - 59: I1Ii111 % OOooOOo . I1IiiI + I1ii11iIi11i % oO0o
 if 96 - 96: OoO0O00
 if 53 - 53: oO0o + OoO0O00
 if 58 - 58: iIii1I11I1II1 + OoOoOO00
 if 65 - 65: iII111i % Oo0Ooo * iIii1I11I1II1 + I1IiiI + II111iiii
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 I1iII11ii1 = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( I1iII11ii1 )
 return ( [ True , jdata ] )
 if 72 - 72: OoOoOO00 . OoooooooOO - OOooOOo
 if 15 - 15: OoOoOO00
 if 13 - 13: I1ii11iIi11i - OOooOOo - i11iIiiIii / IiII
 if 65 - 65: IiII
 if 76 - 76: I1Ii111 % I1ii11iIi11i + ooOoO0o / I1IiiI
 if 59 - 59: OOooOOo - o0oOOo0O0Ooo - o0oOOo0O0Ooo % I1IiiI
 if 55 - 55: o0oOOo0O0Ooo % I1ii11iIi11i - IiII + OoooooooOO
 if 44 - 44: iII111i * I1Ii111 - I1IiiI % i1IIi
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 35 - 35: iII111i . OoOoOO00 + i1IIi . I1Ii111 - oO0o
 if 92 - 92: o0oOOo0O0Ooo
 if 8 - 8: i1IIi / IiII . O0
 if 72 - 72: OOooOOo
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 20 - 20: i11iIiiIii + Oo0Ooo * Oo0Ooo % OOooOOo
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 66 - 66: I1ii11iIi11i + iII111i / Ii1I / I1IiiI * i11iIiiIii
 if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
 if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
 if 71 - 71: oO0o
 if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
 if 16 - 16: I1Ii111 + O0 - O0 * iIii1I11I1II1 / iII111i
 if 4 - 4: iII111i
 if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
 if 32 - 32: iII111i
 if 59 - 59: OoOoOO00 - I1Ii111
 if 34 - 34: ooOoO0o . OoooooooOO / ooOoO0o + OoooooooOO
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 I11i11i1 = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( I11i11i1 ) ) :
  db . dynamic_eids [ I11i11i1 ] . last_packet = lisp_get_timestamp ( )
  return
  if 24 - 24: OoooooooOO * I1ii11iIi11i / O0 / Oo0Ooo * I1IiiI / ooOoO0o
  if 33 - 33: Ii1I
  if 20 - 20: Ii1I + I11i
  if 98 - 98: OOooOOo
  if 58 - 58: i11iIiiIii / OoOoOO00
 Oo0O0oOoO0o0 = lisp_dynamic_eid ( )
 Oo0O0oOoO0o0 . dynamic_eid . copy_address ( eid )
 Oo0O0oOoO0o0 . interface = routed_interface
 Oo0O0oOoO0o0 . last_packet = lisp_get_timestamp ( )
 Oo0O0oOoO0o0 . get_timeout ( routed_interface )
 db . dynamic_eids [ I11i11i1 ] = Oo0O0oOoO0o0
 if 18 - 18: ooOoO0o + O0 - OOooOOo + iIii1I11I1II1 . OOooOOo * iIii1I11I1II1
 OO0O0O0OO = ""
 if ( input_interface != routed_interface ) :
  OO0O0O0OO = ", routed-interface " + routed_interface
  if 64 - 64: OoOoOO00 + oO0o / OoooooooOO . i11iIiiIii / II111iiii
  if 55 - 55: ooOoO0o . i11iIiiIii . o0oOOo0O0Ooo
 O0OO0 = green ( I11i11i1 , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( O0OO0 , input_interface , OO0O0O0OO , Oo0O0oOoO0o0 . timeout ) )
 if 45 - 45: i1IIi - I1IiiI / IiII - I1IiiI
 if 21 - 21: IiII
 if 43 - 43: IiII
 if 9 - 9: OOooOOo * ooOoO0o + ooOoO0o . I1Ii111
 if 8 - 8: IiII * iIii1I11I1II1
 OoOO0o00OOO0o = "learn%{}%{}" . format ( I11i11i1 , routed_interface )
 OoOO0o00OOO0o = lisp_command_ipc ( OoOO0o00OOO0o , "lisp-itr" )
 lisp_ipc ( OoOO0o00OOO0o , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 7 - 7: I1Ii111 / OoooooooOO % O0 - I1ii11iIi11i
 if 49 - 49: OoooooooOO . I1ii11iIi11i / OoooooooOO * oO0o
 if 81 - 81: I1ii11iIi11i . ooOoO0o + I1ii11iIi11i
 if 84 - 84: OoooooooOO
 if 95 - 95: o0oOOo0O0Ooo
 if 22 - 22: ooOoO0o / o0oOOo0O0Ooo - OoooooooOO / Oo0Ooo - I1Ii111 / OOooOOo
 if 41 - 41: oO0o . II111iiii
 if 47 - 47: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 23 - 23: i11iIiiIii / I11i + i1IIi % I1Ii111
 if 100 - 100: Oo0Ooo
 if 13 - 13: I1IiiI + ooOoO0o * II111iiii
 if 32 - 32: iIii1I11I1II1 + O0 + i1IIi
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 28 - 28: IiII + I11i
 if 1 - 1: OoooooooOO - i11iIiiIii . OoooooooOO - o0oOOo0O0Ooo - OOooOOo * I1Ii111
 if 56 - 56: Ii1I . OoO0O00
 if 43 - 43: iII111i * iII111i
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 31 - 31: O0 - iIii1I11I1II1 . I11i . oO0o
 i1II1 = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 96 - 96: OoooooooOO * iIii1I11I1II1 * Oo0Ooo
 for ii1i1I1111ii in lisp_crypto_keys_by_rloc_decap :
  if 76 - 76: OoO0O00 / i11iIiiIii % ooOoO0o % I11i * O0
  if 84 - 84: II111iiii - iII111i / IiII . O0 % i1IIi / I1ii11iIi11i
  if 2 - 2: OoooooooOO . OoO0O00 . II111iiii / Ii1I - OOooOOo % Oo0Ooo
  if 47 - 47: OOooOOo * oO0o
  if ( ii1i1I1111ii . find ( addr_str ) == - 1 ) : continue
  if 41 - 41: OoooooooOO * I1IiiI
  if 3 - 3: IiII
  if 96 - 96: I11i - OOooOOo + I11i
  if 71 - 71: Oo0Ooo
  if ( ii1i1I1111ii == addr_str ) : continue
  if 48 - 48: o0oOOo0O0Ooo / II111iiii / OoOoOO00 * o0oOOo0O0Ooo + I1IiiI . OoOoOO00
  if 52 - 52: Ii1I / OoOoOO00 . OOooOOo * IiII . OoooooooOO
  if 6 - 6: i1IIi . oO0o % IiII . Oo0Ooo % I11i
  if 86 - 86: OoooooooOO + IiII % o0oOOo0O0Ooo . i1IIi . iII111i
  I1iII11ii1 = lisp_crypto_keys_by_rloc_decap [ ii1i1I1111ii ]
  if ( I1iII11ii1 == i1II1 ) : continue
  if 25 - 25: iII111i * I1ii11iIi11i + I11i - I1ii11iIi11i
  if 75 - 75: IiII
  if 74 - 74: o0oOOo0O0Ooo - iIii1I11I1II1
  if 92 - 92: i11iIiiIii * iIii1I11I1II1 - I1Ii111 . i1IIi
  Iiiii1II = I1iII11ii1 [ 1 ]
  if ( packet_icv != Iiiii1II . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( ii1i1I1111ii , False ) ) )
   continue
   if 100 - 100: O0 / OOooOOo
   if 1 - 1: I1ii11iIi11i + iII111i
  lprint ( "Changing decap crypto key to {}" . format ( red ( ii1i1I1111ii , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = I1iII11ii1
  if 61 - 61: oO0o - OOooOOo % II111iiii + IiII + O0 / o0oOOo0O0Ooo
 return
 if 78 - 78: I11i
 if 32 - 32: II111iiii / II111iiii + o0oOOo0O0Ooo + OoooooooOO
 if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
 if 87 - 87: OOooOOo * OoO0O00
 if 61 - 61: iII111i - II111iiii . I1Ii111 % II111iiii / I11i
 if 86 - 86: II111iiii
 if 94 - 94: o0oOOo0O0Ooo % Ii1I * Ii1I % Oo0Ooo / I1ii11iIi11i
 if 40 - 40: Oo0Ooo . II111iiii / II111iiii - i1IIi
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 91 - 91: Ii1I
 if 45 - 45: I1ii11iIi11i + Oo0Ooo
 if 72 - 72: I1ii11iIi11i
 if 5 - 5: i1IIi
 if 31 - 31: iII111i - OoooooooOO + oO0o / OoooooooOO + I1ii11iIi11i
 if 93 - 93: o0oOOo0O0Ooo * I1ii11iIi11i % I1IiiI * ooOoO0o
 if 37 - 37: OoO0O00 * OoooooooOO / oO0o * I11i * I1ii11iIi11i
 if 42 - 42: OoooooooOO - ooOoO0o . OOooOOo + OoOoOO00
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 oO00 = dns_name . split ( "." )
 oO00 = "." . join ( oO00 [ 1 : : ] )
 return ( oO00 == lisp_decent_dns_suffix )
 if 53 - 53: o0oOOo0O0Ooo
 if 55 - 55: ooOoO0o . i1IIi - ooOoO0o + O0 + I1IiiI
 if 31 - 31: OoO0O00 % I1Ii111
 if 62 - 62: oO0o / O0 - I1Ii111 . IiII
 if 81 - 81: i11iIiiIii
 if 57 - 57: O0
 if 85 - 85: i11iIiiIii - i11iIiiIii - OoOoOO00 / II111iiii - II111iiii
def lisp_get_decent_index ( eid ) :
 I11i11i1 = eid . print_prefix ( )
 IIii1IiiiiI1I = hashlib . sha256 ( I11i11i1 ) . hexdigest ( )
 ooo = int ( IIii1IiiiiI1I , 16 ) % lisp_decent_modulus
 return ( ooo )
 if 66 - 66: OoOoOO00 . OoooooooOO
 if 24 - 24: iIii1I11I1II1 + OOooOOo * iII111i % IiII % OOooOOo
 if 64 - 64: IiII . I1ii11iIi11i - o0oOOo0O0Ooo - ooOoO0o + OoooooooOO
 if 95 - 95: iII111i . I1ii11iIi11i + ooOoO0o + o0oOOo0O0Ooo % OoO0O00
 if 50 - 50: iII111i * O0 % II111iiii
 if 80 - 80: OOooOOo - II111iiii - OoO0O00
 if 62 - 62: Ii1I . i11iIiiIii % OOooOOo
def lisp_get_decent_dns_name ( eid ) :
 ooo = lisp_get_decent_index ( eid )
 return ( str ( ooo ) + "." + lisp_decent_dns_suffix )
 if 44 - 44: i1IIi * I1ii11iIi11i % Ii1I . Ii1I * I11i + II111iiii
 if 15 - 15: i1IIi - I11i - I1Ii111 / OoO0O00 + Oo0Ooo + I1IiiI
 if 81 - 81: IiII
 if 54 - 54: I1IiiI % OoO0O00 % OoOoOO00
 if 12 - 12: II111iiii . O0 * i11iIiiIii . I11i
 if 98 - 98: II111iiii + i1IIi * oO0o % I1IiiI
 if 53 - 53: i11iIiiIii . I1ii11iIi11i - OOooOOo - OOooOOo
 if 97 - 97: I1IiiI % iII111i % OoooooooOO / ooOoO0o / i11iIiiIii
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 OOo0O0O0o0 = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 ooo = lisp_get_decent_index ( OOo0O0O0o0 )
 return ( str ( ooo ) + "." + lisp_decent_dns_suffix )
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
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 25 - 25: i11iIiiIii
 OoO00oo00 = 28 if packet . inner_version == 4 else 48
 o00O0OoIIi = packet . packet [ OoO00oo00 : : ]
 o0oo0Oo = lisp_trace ( )
 if ( o0oo0Oo . decode ( o00O0OoIIi ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 96 - 96: Oo0Ooo . I11i + II111iiii - I1Ii111
  if 45 - 45: i1IIi / iII111i + i11iIiiIii * I11i + ooOoO0o / OoooooooOO
 o0000o = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 29 - 29: i1IIi % i1IIi - II111iiii
 if 44 - 44: II111iiii . Oo0Ooo - o0oOOo0O0Ooo
 if 45 - 45: ooOoO0o - oO0o - I1IiiI
 if 21 - 21: OoooooooOO
 if 28 - 28: I1ii11iIi11i + oO0o . Oo0Ooo % iIii1I11I1II1 / I1Ii111
 if 8 - 8: O0 . I1IiiI * o0oOOo0O0Ooo + I1IiiI
 if ( o0000o != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : o0000o += ":{}" . format ( packet . encap_port )
  if 44 - 44: i1IIi % iII111i . i11iIiiIii / I11i + OoooooooOO
  if 21 - 21: OoOoOO00 . OoO0O00 . OoOoOO00 + OoOoOO00
  if 30 - 30: I1IiiI - iII111i - OOooOOo + oO0o
  if 51 - 51: Ii1I % O0 / II111iiii . Oo0Ooo
  if 90 - 90: i11iIiiIii * II111iiii % iIii1I11I1II1 . I1ii11iIi11i / Oo0Ooo . OOooOOo
 I1iII11ii1 = { }
 I1iII11ii1 [ "node" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 77 - 77: OoO0O00
 oO00oII111iiI11I1i = packet . outer_source
 if ( oO00oII111iiI11I1i . is_null ( ) ) : oO00oII111iiI11I1i = lisp_myrlocs [ 0 ]
 I1iII11ii1 [ "srloc" ] = oO00oII111iiI11I1i . print_address_no_iid ( )
 if 88 - 88: O0 - O0 / Ii1I - OOooOOo % I11i
 if 13 - 13: IiII % OoooooooOO * IiII - OoO0O00 % OoooooooOO * IiII
 if 91 - 91: ooOoO0o * ooOoO0o % I1Ii111 . I1ii11iIi11i + iII111i / oO0o
 if 60 - 60: Ii1I
 if 27 - 27: I1ii11iIi11i - I11i . OoO0O00 / o0oOOo0O0Ooo
 if ( I1iII11ii1 [ "node" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  I1iII11ii1 [ "srloc" ] += ":{}" . format ( packet . inner_sport )
  if 87 - 87: iIii1I11I1II1 - OOooOOo - OOooOOo
  if 55 - 55: Oo0Ooo + OoooooooOO . IiII / O0 + I11i
 I1iII11ii1 [ "hn" ] = lisp_hostname
 ii1i1I1111ii = ed + "-ts"
 I1iII11ii1 [ ii1i1I1111ii ] = lisp_get_timestamp ( )
 if 58 - 58: Ii1I
 if 35 - 35: OoO0O00 + OoOoOO00
 if 22 - 22: II111iiii / I1IiiI + o0oOOo0O0Ooo * I1IiiI . OoooooooOO * OOooOOo
 if 49 - 49: I1ii11iIi11i * I1IiiI + OOooOOo + i11iIiiIii * I1ii11iIi11i . o0oOOo0O0Ooo
 if 36 - 36: o0oOOo0O0Ooo - i11iIiiIii
 if 37 - 37: O0 + IiII + I1IiiI
 if ( o0000o == "?" and I1iII11ii1 [ "node" ] == "ETR" ) :
  Ooooo00 = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( Ooooo00 != None and len ( Ooooo00 . rloc_set ) >= 1 ) :
   o0000o = Ooooo00 . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 50 - 50: OoooooooOO . I1Ii111
   if 100 - 100: ooOoO0o * ooOoO0o - Ii1I
 I1iII11ii1 [ "drloc" ] = o0000o
 if 13 - 13: iII111i . I11i * OoO0O00 . i1IIi . iIii1I11I1II1 - o0oOOo0O0Ooo
 if 68 - 68: Ii1I % o0oOOo0O0Ooo / OoooooooOO + Ii1I - Ii1I
 if 79 - 79: II111iiii / IiII
 if 4 - 4: O0 - i11iIiiIii % ooOoO0o * O0 - ooOoO0o
 if ( o0000o == "?" and reason != None ) :
  I1iII11ii1 [ "drloc" ] += " ({})" . format ( reason )
  if 96 - 96: oO0o % II111iiii . Ii1I % OoO0O00 . iIii1I11I1II1 / IiII
  if 96 - 96: o0oOOo0O0Ooo / O0 . iIii1I11I1II1 . Ii1I % OOooOOo % II111iiii
  if 5 - 5: OoooooooOO / I1Ii111 % I1Ii111 / I1IiiI
  if 19 - 19: I1IiiI - ooOoO0o % IiII - o0oOOo0O0Ooo * OOooOOo + I1ii11iIi11i
  if 44 - 44: i1IIi
 if ( rloc_entry != None ) :
  I1iII11ii1 [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  I1iII11ii1 [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  if 85 - 85: I1ii11iIi11i / IiII + oO0o
  if 95 - 95: IiII . OoO0O00
  if 36 - 36: IiII % Ii1I - OoOoOO00 + OoO0O00 + IiII * Ii1I
  if 15 - 15: I1IiiI / O0 % I1ii11iIi11i % OoOoOO00 . OoOoOO00 + iII111i
  if 79 - 79: OOooOOo + Ii1I . I1Ii111 / Oo0Ooo / i11iIiiIii / O0
  if 28 - 28: i1IIi % OoO0O00 / i1IIi - o0oOOo0O0Ooo
 O00oOOOOoOO = packet . inner_source . print_address ( )
 I11iIii1i11 = packet . inner_dest . print_address ( )
 if ( o0oo0Oo . packet_json == [ ] ) :
  OOOiii = { }
  OOOiii [ "seid" ] = O00oOOOOoOO
  OOOiii [ "deid" ] = I11iIii1i11
  OOOiii [ "paths" ] = [ ]
  o0oo0Oo . packet_json . append ( OOOiii )
  if 97 - 97: II111iiii + O0 . Ii1I + OoooooooOO
  if 39 - 39: i11iIiiIii + OoO0O00 + I11i * oO0o + iIii1I11I1II1 % o0oOOo0O0Ooo
  if 25 - 25: OoooooooOO
  if 78 - 78: oO0o / i11iIiiIii * O0 / OOooOOo % i11iIiiIii % O0
  if 86 - 86: IiII
  if 26 - 26: IiII - I1Ii111 + i11iIiiIii % ooOoO0o * i11iIiiIii + Oo0Ooo
 for OOOiii in o0oo0Oo . packet_json :
  if ( OOOiii [ "deid" ] != I11iIii1i11 ) : continue
  OOOiii [ "paths" ] . append ( I1iII11ii1 )
  break
  if 39 - 39: Ii1I - i1IIi + i11iIiiIii
  if 21 - 21: IiII
  if 76 - 76: o0oOOo0O0Ooo % Oo0Ooo + OoO0O00
  if 36 - 36: OOooOOo . oO0o
  if 15 - 15: I1IiiI + ooOoO0o - o0oOOo0O0Ooo
  if 62 - 62: Ii1I - OOooOOo
  if 88 - 88: iIii1I11I1II1 * Oo0Ooo / II111iiii / IiII / OoO0O00 % ooOoO0o
  if 19 - 19: I11i * iII111i . O0 * iII111i % I1ii11iIi11i - OoOoOO00
 O00OO0oo = False
 if ( len ( o0oo0Oo . packet_json ) == 1 and I1iII11ii1 [ "node" ] == "ETR" and
 o0oo0Oo . myeid ( packet . inner_dest ) ) :
  OOOiii = { }
  OOOiii [ "seid" ] = I11iIii1i11
  OOOiii [ "deid" ] = O00oOOOOoOO
  OOOiii [ "paths" ] = [ ]
  o0oo0Oo . packet_json . append ( OOOiii )
  O00OO0oo = True
  if 99 - 99: I1Ii111 * oO0o - iIii1I11I1II1
  if 51 - 51: I1Ii111
  if 87 - 87: i11iIiiIii . I1ii11iIi11i % I11i
  if 41 - 41: OoO0O00 . Ii1I
  if 35 - 35: Ii1I + I1IiiI
  if 10 - 10: i11iIiiIii - I1ii11iIi11i . OOooOOo - iIii1I11I1II1 / II111iiii / II111iiii
 o0oo0Oo . print_trace ( )
 o00O0OoIIi = o0oo0Oo . encode ( )
 if 13 - 13: i1IIi - OoooooooOO - OoOoOO00 * ooOoO0o + I11i
 if 32 - 32: ooOoO0o - II111iiii * Ii1I
 if 99 - 99: O0 + I1Ii111 - I1Ii111 + iII111i
 if 4 - 4: i1IIi
 if 43 - 43: oO0o * ooOoO0o - I11i
 if 70 - 70: oO0o / Ii1I
 if 15 - 15: iIii1I11I1II1 % ooOoO0o % i11iIiiIii
 if 16 - 16: iII111i
 ii1iiIiiI = o0oo0Oo . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "srloc" ]
 if ( o0000o == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( ii1iiIiiI ) )
  o0oo0Oo . return_to_sender ( lisp_socket , ii1iiIiiI , o00O0OoIIi )
  return ( False )
  if 40 - 40: iII111i * i1IIi * O0 . oO0o
  if 29 - 29: i1IIi . OoOoOO00 . i1IIi + oO0o . I1Ii111 + O0
  if 62 - 62: I1ii11iIi11i . IiII + OoO0O00 - OoOoOO00 * O0 + I1Ii111
  if 58 - 58: oO0o . OoO0O00 / ooOoO0o
  if 61 - 61: I11i + I1Ii111
  if 27 - 27: ooOoO0o / i1IIi . oO0o - OoooooooOO
 O0OOOOo0 = o0oo0Oo . packet_length ( )
 if 48 - 48: ooOoO0o % ooOoO0o / OoooooooOO + i1IIi * oO0o + ooOoO0o
 if 69 - 69: iII111i . iII111i
 if 46 - 46: IiII * Oo0Ooo + I1Ii111
 if 79 - 79: IiII
 if 89 - 89: IiII * I11i + I1ii11iIi11i * oO0o - II111iiii
 if 58 - 58: ooOoO0o . I1Ii111 / i1IIi % I1ii11iIi11i + o0oOOo0O0Ooo
 Ooo0O00 = packet . packet [ 0 : OoO00oo00 ]
 III1I1Iii1 = struct . pack ( "HH" , socket . htons ( O0OOOOo0 ) , 0 )
 Ooo0O00 = Ooo0O00 [ 0 : OoO00oo00 - 4 ] + III1I1Iii1
 if ( packet . inner_version == 6 and I1iII11ii1 [ "node" ] == "ETR" and
 len ( o0oo0Oo . packet_json ) == 2 ) :
  o0oOo00 = Ooo0O00 [ OoO00oo00 - 8 : : ] + o00O0OoIIi
  o0oOo00 = lisp_udp_checksum ( O00oOOOOoOO , I11iIii1i11 , o0oOo00 )
  Ooo0O00 = Ooo0O00 [ 0 : OoO00oo00 - 8 ] + o0oOo00 [ 0 : 8 ]
  if 96 - 96: Ii1I * i11iIiiIii - OOooOOo - O0 * OoooooooOO - ooOoO0o
  if 35 - 35: iII111i . i11iIiiIii - OOooOOo % Oo0Ooo + Ii1I . iIii1I11I1II1
  if 91 - 91: o0oOOo0O0Ooo / OoO0O00 + I1IiiI % i11iIiiIii % i1IIi
  if 22 - 22: I1Ii111 * O0 % OoO0O00 * I1ii11iIi11i
  if 47 - 47: OoO0O00 / OOooOOo / OoOoOO00 % i11iIiiIii / OoOoOO00
  if 52 - 52: ooOoO0o / I11i % i11iIiiIii - I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
 if ( O00OO0oo ) :
  if ( packet . inner_version == 4 ) :
   Ooo0O00 = Ooo0O00 [ 0 : 12 ] + Ooo0O00 [ 16 : 20 ] + Ooo0O00 [ 12 : 16 ] + Ooo0O00 [ 22 : 24 ] + Ooo0O00 [ 20 : 22 ] + Ooo0O00 [ 24 : : ]
   if 67 - 67: OoOoOO00 / I1Ii111 + i11iIiiIii - IiII
  else :
   Ooo0O00 = Ooo0O00 [ 0 : 8 ] + Ooo0O00 [ 24 : 40 ] + Ooo0O00 [ 8 : 24 ] + Ooo0O00 [ 42 : 44 ] + Ooo0O00 [ 40 : 42 ] + Ooo0O00 [ 44 : : ]
   if 79 - 79: I11i . I11i - OoOoOO00
   if 86 - 86: OoO0O00 * Oo0Ooo . iIii1I11I1II1 * O0
  OooOOOoOoo0O0 = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = OooOOOoOoo0O0
  if 52 - 52: iII111i - i11iIiiIii + o0oOOo0O0Ooo + i1IIi
  if 58 - 58: OOooOOo - Ii1I * I1Ii111 - O0 . oO0o
  if 72 - 72: i1IIi * iII111i * Ii1I / o0oOOo0O0Ooo . I1Ii111 + i11iIiiIii
  if 33 - 33: I11i / OoO0O00 * ooOoO0o + iIii1I11I1II1
  if 54 - 54: Oo0Ooo / IiII + i11iIiiIii . O0
 OoO00oo00 = 2 if packet . inner_version == 4 else 4
 Oo00oo = 20 + O0OOOOo0 if packet . inner_version == 4 else O0OOOOo0
 i1I1ii111 = struct . pack ( "H" , socket . htons ( Oo00oo ) )
 Ooo0O00 = Ooo0O00 [ 0 : OoO00oo00 ] + i1I1ii111 + Ooo0O00 [ OoO00oo00 + 2 : : ]
 if 54 - 54: Oo0Ooo
 if 26 - 26: II111iiii
 if 15 - 15: OoooooooOO * oO0o
 if 53 - 53: OoO0O00 * i1IIi / Oo0Ooo / OoO0O00 * ooOoO0o
 if ( packet . inner_version == 4 ) :
  Ooo0OO00oo = struct . pack ( "H" , 0 )
  Ooo0O00 = Ooo0O00 [ 0 : 10 ] + Ooo0OO00oo + Ooo0O00 [ 12 : : ]
  i1I1ii111 = lisp_ip_checksum ( Ooo0O00 [ 0 : 20 ] )
  Ooo0O00 = i1I1ii111 + Ooo0O00 [ 20 : : ]
  if 77 - 77: iIii1I11I1II1 % I1IiiI + o0oOOo0O0Ooo + I1Ii111 * Oo0Ooo * i1IIi
  if 14 - 14: iIii1I11I1II1 * iIii1I11I1II1 - OOooOOo . iII111i / ooOoO0o
  if 54 - 54: OoOoOO00 - I1IiiI - iII111i
  if 49 - 49: i11iIiiIii * Oo0Ooo
  if 100 - 100: Oo0Ooo * oO0o
 packet . packet = Ooo0O00 + o00O0OoIIi
 return ( True )
 if 85 - 85: OoooooooOO . IiII / IiII . ooOoO0o . IiII % II111iiii
 if 65 - 65: oO0o - OoO0O00 / iII111i + ooOoO0o
 if 80 - 80: o0oOOo0O0Ooo + II111iiii * Ii1I % OoOoOO00 % I1IiiI + I1ii11iIi11i
 if 46 - 46: Oo0Ooo / Oo0Ooo % iII111i % I1IiiI
 if 85 - 85: OoO0O00 - Ii1I / O0
 if 45 - 45: IiII + I1Ii111 / I11i
 if 84 - 84: iII111i % II111iiii
 if 86 - 86: IiII % II111iiii / i1IIi * I1ii11iIi11i - O0 * OOooOOo
 if 53 - 53: OOooOOo * oO0o + i1IIi % Oo0Ooo + II111iiii
 if 34 - 34: oO0o % iII111i / IiII . IiII + i11iIiiIii
def lisp_allow_gleaning ( eid , group , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False , False )
 if 68 - 68: O0 % oO0o * IiII % O0
 for I1iII11ii1 in lisp_glean_mappings :
  if ( I1iII11ii1 . has_key ( "instance-id" ) ) :
   o0OoO0000o = eid . instance_id
   iii11Ii , O0OO0OO0 = I1iII11ii1 [ "instance-id" ]
   if ( o0OoO0000o < iii11Ii or o0OoO0000o > O0OO0OO0 ) : continue
   if 55 - 55: O0 % I1IiiI % O0
  if ( I1iII11ii1 . has_key ( "eid-prefix" ) ) :
   oOo = copy . deepcopy ( I1iII11ii1 [ "eid-prefix" ] )
   oOo . instance_id = eid . instance_id
   if ( eid . is_more_specific ( oOo ) == False ) : continue
   if 27 - 27: I1IiiI + I1ii11iIi11i * I1Ii111 % Ii1I - Oo0Ooo
  if ( I1iII11ii1 . has_key ( "group-prefix" ) ) :
   if ( group == None ) : continue
   i11ii = copy . deepcopy ( I1iII11ii1 [ "group-prefix" ] )
   i11ii . instance_id = group . instance_id
   if ( group . is_more_specific ( i11ii ) == False ) : continue
   if 87 - 87: i11iIiiIii % OOooOOo - OoOoOO00 * ooOoO0o / Oo0Ooo
  if ( I1iII11ii1 . has_key ( "rloc-prefix" ) ) :
   if ( rloc != None and rloc . is_more_specific ( I1iII11ii1 [ "rloc-prefix" ] )
 == False ) : continue
   if 74 - 74: OoooooooOO * ooOoO0o - I11i / I1ii11iIi11i % iIii1I11I1II1
  return ( True , I1iII11ii1 [ "rloc-probe" ] , I1iII11ii1 [ "igmp-query" ] )
  if 94 - 94: Ii1I * I1Ii111 + OoOoOO00 . iIii1I11I1II1
 return ( False , False , False )
 if 44 - 44: Oo0Ooo . Oo0Ooo * Oo0Ooo
 if 23 - 23: I1Ii111 / iII111i . O0 % II111iiii
 if 67 - 67: I11i / iIii1I11I1II1 / ooOoO0o
 if 90 - 90: II111iiii % I1Ii111 - IiII . Oo0Ooo % OOooOOo - OoOoOO00
 if 89 - 89: Oo0Ooo - I1ii11iIi11i . I1Ii111
 if 65 - 65: ooOoO0o % OOooOOo + OOooOOo % I1Ii111 . I1IiiI % O0
 if 46 - 46: OoO0O00 * I1Ii111 + iII111i . oO0o % OOooOOo / i11iIiiIii
def lisp_build_gleaned_multicast ( seid , geid , rloc , port , igmp ) :
 iI1i1iIi1iiII = geid . print_address ( )
 IIIiiIiiI1i = seid . print_address_no_iid ( )
 IiII1iiI = green ( "{}" . format ( IIIiiIiiI1i ) , False )
 oOo = green ( "(*, {})" . format ( iI1i1iIi1iiII ) , False )
 i11iII1IiI = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 if 71 - 71: iII111i % o0oOOo0O0Ooo
 if 91 - 91: i11iIiiIii * iIii1I11I1II1 % oO0o . II111iiii / Ii1I + Ii1I
 if 32 - 32: OOooOOo % OOooOOo + I1ii11iIi11i / Ii1I - i11iIiiIii
 if 28 - 28: iIii1I11I1II1 - II111iiii
 IiiiiII1i = lisp_map_cache_lookup ( seid , geid )
 if ( IiiiiII1i == None ) :
  IiiiiII1i = lisp_mapping ( "" , "" , [ ] )
  IiiiiII1i . group . copy_address ( geid )
  IiiiiII1i . eid . copy_address ( geid )
  IiiiiII1i . eid . address = 0
  IiiiiII1i . eid . mask_len = 0
  IiiiiII1i . mapping_source . copy_address ( rloc )
  IiiiiII1i . map_cache_ttl = LISP_IGMP_TTL
  IiiiiII1i . gleaned = True
  IiiiiII1i . add_cache ( )
  lprint ( "Add gleaned EID {} to map-cache" . format ( oOo ) )
  if 36 - 36: ooOoO0o . II111iiii - OoOoOO00 % I1ii11iIi11i * O0
  if 91 - 91: iII111i + Oo0Ooo / OoooooooOO * iIii1I11I1II1 - OoO0O00
  if 73 - 73: iIii1I11I1II1 % I1Ii111 % II111iiii * Oo0Ooo * OoO0O00
  if 48 - 48: OOooOOo * i11iIiiIii - i11iIiiIii + iIii1I11I1II1 + I1IiiI % OoooooooOO
  if 61 - 61: i1IIi
  if 56 - 56: iIii1I11I1II1 / I11i * iII111i * I11i * OoooooooOO
 iIII = II1II1i1 = iIIII1iiIII = None
 if ( IiiiiII1i . rloc_set != [ ] ) :
  iIII = IiiiiII1i . rloc_set [ 0 ]
  if ( iIII . rle ) :
   II1II1i1 = iIII . rle
   for oO0Oo0oooO in II1II1i1 . rle_nodes :
    if ( oO0Oo0oooO . rloc_name != IIIiiIiiI1i ) : continue
    iIIII1iiIII = oO0Oo0oooO
    break
    if 20 - 20: i11iIiiIii - i1IIi . II111iiii . OOooOOo * I1IiiI
    if 91 - 91: Ii1I - OoO0O00 % Ii1I - II111iiii / IiII * OoO0O00
    if 42 - 42: IiII
    if 83 - 83: i1IIi * o0oOOo0O0Ooo / OoO0O00 / o0oOOo0O0Ooo
    if 55 - 55: Oo0Ooo % O0 - OoO0O00
    if 42 - 42: OoooooooOO * OOooOOo
    if 93 - 93: OOooOOo + II111iiii . oO0o * Oo0Ooo - O0 + I1Ii111
 if ( iIII == None ) :
  iIII = lisp_rloc ( )
  IiiiiII1i . rloc_set = [ iIII ]
  iIII . priority = 253
  iIII . mpriority = 255
  IiiiiII1i . build_best_rloc_set ( )
  if 99 - 99: OoO0O00 * o0oOOo0O0Ooo + OoOoOO00 * iIii1I11I1II1
 if ( II1II1i1 == None ) :
  II1II1i1 = lisp_rle ( geid . print_address ( ) )
  iIII . rle = II1II1i1
  if 38 - 38: I1ii11iIi11i - OOooOOo * O0 - I1ii11iIi11i
 if ( iIIII1iiIII == None ) :
  iIIII1iiIII = lisp_rle_node ( )
  iIIII1iiIII . rloc_name = IIIiiIiiI1i
  II1II1i1 . rle_nodes . append ( iIIII1iiIII )
  II1II1i1 . build_forwarding_list ( )
  lprint ( "Add RLE {} from {} for gleaned EID {}" . format ( i11iII1IiI , IiII1iiI , oOo ) )
 elif ( rloc . is_exact_match ( iIIII1iiIII . address ) == False or
 port != iIIII1iiIII . translated_port ) :
  lprint ( "Changed RLE {} from {} for gleaned EID {}" . format ( i11iII1IiI , IiII1iiI , oOo ) )
  if 95 - 95: OoO0O00 . oO0o . OoooooooOO - iIii1I11I1II1
  if 35 - 35: o0oOOo0O0Ooo / OoooooooOO - i1IIi * iIii1I11I1II1 + ooOoO0o
  if 66 - 66: Oo0Ooo - OoOoOO00 . I1Ii111 + O0 + o0oOOo0O0Ooo
  if 36 - 36: II111iiii % IiII . i11iIiiIii
  if 88 - 88: Oo0Ooo . IiII * Oo0Ooo
 iIIII1iiIII . store_translated_rloc ( rloc , port )
 if 92 - 92: I1IiiI % IiII
 if 95 - 95: OoooooooOO / OoO0O00 % O0 / I1Ii111 * Ii1I + I1ii11iIi11i
 if 7 - 7: ooOoO0o
 if 83 - 83: oO0o / I1Ii111 + I1Ii111 * I1ii11iIi11i
 if 8 - 8: I11i . I1ii11iIi11i % i1IIi + Ii1I
 if ( igmp ) :
  O0oOo0o = seid . print_address ( )
  if ( lisp_gleaned_groups . has_key ( O0oOo0o ) == False ) :
   lisp_gleaned_groups [ O0oOo0o ] = { }
   if 63 - 63: I1IiiI / OoooooooOO
  lisp_gleaned_groups [ O0oOo0o ] [ iI1i1iIi1iiII ] = lisp_get_timestamp ( )
  if 16 - 16: OoOoOO00
  if 67 - 67: O0 . I1Ii111
  if 42 - 42: OoOoOO00 % I1ii11iIi11i * I1Ii111 * i1IIi . i1IIi % OOooOOo
  if 90 - 90: oO0o * Oo0Ooo * oO0o . Ii1I * i1IIi
  if 47 - 47: OOooOOo
  if 38 - 38: I11i
  if 15 - 15: OoO0O00 / ooOoO0o . OoO0O00 - iIii1I11I1II1 + OoooooooOO - OoO0O00
  if 44 - 44: O0 . OOooOOo . o0oOOo0O0Ooo . I1ii11iIi11i - II111iiii
def lisp_remove_gleaned_multicast ( seid , geid ) :
 if 71 - 71: I1ii11iIi11i + o0oOOo0O0Ooo . i11iIiiIii * oO0o . i1IIi
 if 40 - 40: OoO0O00 - IiII
 if 43 - 43: I1Ii111 + i11iIiiIii % iII111i % I1Ii111 - ooOoO0o
 if 85 - 85: IiII % iIii1I11I1II1 . I1Ii111
 IiiiiII1i = lisp_map_cache_lookup ( seid , geid )
 if ( IiiiiII1i == None ) : return
 if 38 - 38: iII111i - I1IiiI / ooOoO0o
 i1I1Ii11II1i = IiiiiII1i . rloc_set [ 0 ] . rle
 if ( i1I1Ii11II1i == None ) : return
 if 46 - 46: OOooOOo . O0 / i11iIiiIii . OOooOOo
 IiIi1I1i1iII = seid . print_address_no_iid ( )
 OOo00oO0oo = False
 for iIIII1iiIII in i1I1Ii11II1i . rle_nodes :
  if ( iIIII1iiIII . rloc_name == IiIi1I1i1iII ) :
   OOo00oO0oo = True
   break
   if 19 - 19: I11i / Oo0Ooo + I1Ii111
   if 43 - 43: I1ii11iIi11i
 if ( OOo00oO0oo == False ) : return
 if 18 - 18: I11i / OOooOOo % I11i - o0oOOo0O0Ooo
 if 22 - 22: iII111i
 if 88 - 88: I11i + OoOoOO00 % IiII % OoO0O00 * O0 / OoooooooOO
 if 83 - 83: IiII + I1Ii111 . I1ii11iIi11i * iIii1I11I1II1
 i1I1Ii11II1i . rle_nodes . remove ( iIIII1iiIII )
 i1I1Ii11II1i . build_forwarding_list ( )
 if 9 - 9: ooOoO0o % IiII - OoOoOO00
 iI1i1iIi1iiII = geid . print_address ( )
 O0oOo0o = seid . print_address ( )
 IiII1iiI = green ( "{}" . format ( O0oOo0o ) , False )
 oOo = green ( "(*, {})" . format ( iI1i1iIi1iiII ) , False )
 lprint ( "Gleaned EID {} RLE removed for {}" . format ( oOo , IiII1iiI ) )
 if 66 - 66: oO0o % Oo0Ooo
 if 40 - 40: i11iIiiIii . O0 * I11i - oO0o / OOooOOo . oO0o
 if 86 - 86: OOooOOo - I1Ii111 * IiII - i1IIi + ooOoO0o + I11i
 if 32 - 32: IiII
 if ( lisp_gleaned_groups . has_key ( O0oOo0o ) ) :
  if ( lisp_gleaned_groups [ O0oOo0o ] . has_key ( iI1i1iIi1iiII ) ) :
   lisp_gleaned_groups [ O0oOo0o ] . pop ( iI1i1iIi1iiII )
   if 99 - 99: II111iiii
   if 34 - 34: OOooOOo + OoOoOO00 * o0oOOo0O0Ooo + I1ii11iIi11i + IiII * i1IIi
   if 73 - 73: I1ii11iIi11i - IiII - O0 . oO0o + Oo0Ooo % iII111i
   if 68 - 68: I1ii11iIi11i - OoooooooOO
   if 5 - 5: I1ii11iIi11i * I1IiiI + OoooooooOO / Oo0Ooo
   if 18 - 18: OoO0O00 * iII111i % I1IiiI . OOooOOo * o0oOOo0O0Ooo
 if ( i1I1Ii11II1i . rle_nodes == [ ] ) :
  IiiiiII1i . delete_cache ( )
  lprint ( "Gleaned EID {} remove, no more RLEs" . format ( oOo ) )
  if 58 - 58: iII111i . IiII + iIii1I11I1II1
  if 13 - 13: oO0o * I1Ii111 / I1Ii111 . I1IiiI
  if 93 - 93: I11i % OoOoOO00 - OOooOOo + iIii1I11I1II1 / OoooooooOO % i11iIiiIii
  if 90 - 90: oO0o % iIii1I11I1II1 + o0oOOo0O0Ooo - I11i / i11iIiiIii
  if 57 - 57: I1IiiI . Oo0Ooo / I1IiiI / II111iiii - I1Ii111
  if 68 - 68: I1IiiI
  if 97 - 97: Ii1I + o0oOOo0O0Ooo / OoO0O00
  if 97 - 97: i11iIiiIii % iIii1I11I1II1 + II111iiii
def lisp_change_gleaned_multicast ( seid , rloc , port ) :
 O0oOo0o = seid . print_address ( )
 if ( lisp_gleaned_groups . has_key ( O0oOo0o ) == False ) : return
 if 90 - 90: OOooOOo / I1IiiI
 for O0o00oOOOO00 in lisp_gleaned_groups [ O0oOo0o ] :
  lisp_geid . store_address ( O0o00oOOOO00 )
  lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , port , False )
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
  if 78 - 78: OoO0O00 / o0oOOo0O0Ooo / O0 % OOooOOo % i1IIi
  if 78 - 78: o0oOOo0O0Ooo - oO0o . II111iiii
  if 67 - 67: iII111i + I11i - OoO0O00 . OOooOOo * iIii1I11I1II1
  if 44 - 44: OoooooooOO * i1IIi % i1IIi - i11iIiiIii % OOooOOo - OoO0O00
  if 62 - 62: OOooOOo + OoooooooOO / I1Ii111 % iIii1I11I1II1
  if 59 - 59: i11iIiiIii . IiII
  if 91 - 91: Oo0Ooo / iII111i + I1Ii111
  if 32 - 32: i1IIi - iII111i + o0oOOo0O0Ooo * I1Ii111 % I1ii11iIi11i / i11iIiiIii
  if 91 - 91: IiII / OoooooooOO . OoooooooOO + OoooooooOO * I1ii11iIi11i . OoOoOO00
  if 22 - 22: iIii1I11I1II1 - OoO0O00
  if 77 - 77: I1IiiI + IiII - oO0o - I1ii11iIi11i * II111iiii + i1IIi
  if 79 - 79: I1ii11iIi11i + O0 * OoooooooOO
  if 43 - 43: I11i
  if 29 - 29: o0oOOo0O0Ooo / I11i
  if 88 - 88: OoOoOO00 - Ii1I . O0 % I1Ii111 % I1ii11iIi11i
  if 56 - 56: OoOoOO00 - iIii1I11I1II1 / I1IiiI - i1IIi / o0oOOo0O0Ooo * I11i
  if 70 - 70: OOooOOo
  if 11 - 11: I11i * II111iiii * Oo0Ooo + OOooOOo % i1IIi
  if 73 - 73: OoO0O00 + O0 / Ii1I . OoooooooOO % iIii1I11I1II1 * i1IIi
  if 84 - 84: o0oOOo0O0Ooo . iII111i / o0oOOo0O0Ooo + I1ii11iIi11i % OoO0O00
  if 52 - 52: OoOoOO00 / Ii1I % OoOoOO00 % i11iIiiIii + I1IiiI / o0oOOo0O0Ooo
  if 63 - 63: I1IiiI
  if 20 - 20: oO0o + OoOoOO00
  if 32 - 32: o0oOOo0O0Ooo % oO0o % I1IiiI * OoooooooOO
  if 4 - 4: OOooOOo % oO0o
  if 18 - 18: Ii1I * I11i
  if 14 - 14: ooOoO0o . ooOoO0o * OoOoOO00 * o0oOOo0O0Ooo - iII111i - I1Ii111
  if 53 - 53: Oo0Ooo * OoOoOO00 * II111iiii % IiII - I1ii11iIi11i
  if 56 - 56: Oo0Ooo . I1ii11iIi11i - i11iIiiIii / iIii1I11I1II1 . ooOoO0o
  if 28 - 28: OoooooooOO + I1IiiI / oO0o . iIii1I11I1II1 - oO0o
  if 64 - 64: I1Ii111 + Oo0Ooo / iII111i
  if 61 - 61: Ii1I * Ii1I . OoOoOO00 + OoO0O00 * i11iIiiIii * OoO0O00
  if 4 - 4: OoooooooOO % iII111i % Oo0Ooo * IiII % o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 66 - 66: I1IiiI . Oo0Ooo - oO0o
  if 53 - 53: oO0o / Ii1I + oO0o + II111iiii
  if 70 - 70: OoooooooOO - I1Ii111 + OoOoOO00
  if 61 - 61: I1IiiI * I1Ii111 * i11iIiiIii
  if 68 - 68: OoOoOO00 - iII111i - I1IiiI
  if 37 - 37: iII111i - I1Ii111 + i1IIi / o0oOOo0O0Ooo % iII111i / iII111i
  if 8 - 8: i1IIi % I11i
  if 12 - 12: ooOoO0o / II111iiii + ooOoO0o * I1ii11iIi11i / i1IIi - iIii1I11I1II1
  if 71 - 71: IiII - i11iIiiIii
igmp_types = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 3 - 3: i11iIiiIii - o0oOOo0O0Ooo / oO0o . OoO0O00 * I11i + o0oOOo0O0Ooo
lisp_igmp_record_types = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 18 - 18: OoooooooOO % oO0o / IiII - ooOoO0o
def lisp_process_igmp_packet ( packet ) :
 oo00Oo0 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 oo00Oo0 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 oo00Oo0 = bold ( "from {}" . format ( oo00Oo0 . print_address_no_iid ( ) ) , False )
 if 80 - 80: I11i
 i11iII1IiI = bold ( "Receive" , False )
 lprint ( "{} {}-byte {}, IGMP packet: {}" . format ( i11iII1IiI , len ( packet ) , oo00Oo0 ,
 lisp_format_packet ( packet ) ) )
 if 98 - 98: iII111i / I1ii11iIi11i
 if 87 - 87: iII111i - O0 * ooOoO0o / II111iiii % OoooooooOO . o0oOOo0O0Ooo
 if 55 - 55: OOooOOo - o0oOOo0O0Ooo * I1IiiI / o0oOOo0O0Ooo + I1Ii111 + iIii1I11I1II1
 if 3 - 3: II111iiii % iII111i / IiII * ooOoO0o . OoooooooOO
 O0OoOOOooO0Oo = ( struct . unpack ( "B" , packet [ 0 ] ) [ 0 ] & 0x0f ) * 4
 if 47 - 47: IiII * ooOoO0o
 if 22 - 22: oO0o / O0
 if 63 - 63: i1IIi + OoO0O00
 if 11 - 11: OOooOOo / I1ii11iIi11i . OOooOOo + i1IIi - OoooooooOO * II111iiii
 O00Oo0OOoO = packet [ O0OoOOOooO0Oo : : ]
 ooo0oo0Ooo0 = struct . unpack ( "B" , O00Oo0OOoO [ 0 ] ) [ 0 ]
 if 90 - 90: O0 - IiII * i1IIi / Ii1I + oO0o - OOooOOo
 if 5 - 5: i11iIiiIii % OoooooooOO - Ii1I
 if 31 - 31: OOooOOo + ooOoO0o
 if 76 - 76: IiII + Ii1I
 if 64 - 64: Oo0Ooo % O0
 O0o00oOOOO00 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 O0o00oOOOO00 . address = socket . ntohl ( struct . unpack ( "II" , O00Oo0OOoO [ : 8 ] ) [ 1 ] )
 iI1i1iIi1iiII = O0o00oOOOO00 . print_address_no_iid ( )
 if 66 - 66: O0 + I1IiiI % iIii1I11I1II1 . i1IIi % II111iiii - i1IIi
 if ( ooo0oo0Ooo0 == 17 ) :
  lprint ( "IGMP Query for group {}" . format ( iI1i1iIi1iiII ) )
  return ( True )
  if 93 - 93: O0 + OoooooooOO % IiII % oO0o % I1ii11iIi11i
  if 36 - 36: I1IiiI - oO0o * Oo0Ooo + oO0o % iII111i - i11iIiiIii
 ooiIII = ( ooo0oo0Ooo0 in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( ooiIII == False ) :
  ooOO0OOo0o = "{} ({})" . format ( ooo0oo0Ooo0 , igmp_types [ ooo0oo0Ooo0 ] ) if igmp_types . has_key ( ooo0oo0Ooo0 ) else ooo0oo0Ooo0
  if 41 - 41: iII111i - OoO0O00
  lprint ( "IGMP type {} not supported" . format ( ooOO0OOo0o ) )
  return ( [ ] )
  if 74 - 74: I1ii11iIi11i . OoO0O00 % Oo0Ooo / oO0o
  if 43 - 43: iIii1I11I1II1
 if ( len ( O00Oo0OOoO ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 79 - 79: O0 % ooOoO0o - OoOoOO00 / I1Ii111
  if 85 - 85: iII111i % OOooOOo . OoooooooOO % O0 % O0
  if 72 - 72: o0oOOo0O0Ooo * IiII / II111iiii / iIii1I11I1II1
  if 41 - 41: iII111i / Ii1I
  if 11 - 11: Oo0Ooo % OOooOOo . ooOoO0o
 if ( ooo0oo0Ooo0 == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( iI1i1iIi1iiII , False ) ) )
  return ( [ [ None , iI1i1iIi1iiII , False ] ] )
  if 24 - 24: IiII / Oo0Ooo
 if ( ooo0oo0Ooo0 in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( ooo0oo0Ooo0 == 0x12 ) else 2 , bold ( iI1i1iIi1iiII , False ) ) )
  if 90 - 90: ooOoO0o . OOooOOo - Ii1I
  if 60 - 60: i11iIiiIii % iII111i . I1IiiI * I1ii11iIi11i
  if 30 - 30: Ii1I + i11iIiiIii . I11i + o0oOOo0O0Ooo - OoO0O00
  if 55 - 55: ooOoO0o - II111iiii . ooOoO0o . iII111i / OoooooooOO
  if 51 - 51: I1IiiI * I1Ii111 - ooOoO0o + IiII
  if ( iI1i1iIi1iiII . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
  else :
   return ( [ [ None , iI1i1iIi1iiII , True ] ] )
   if 22 - 22: OoOoOO00 % Ii1I + iII111i
   if 64 - 64: ooOoO0o
   if 87 - 87: IiII - Ii1I / Oo0Ooo / I1ii11iIi11i . iII111i
   if 49 - 49: IiII * OoooooooOO * iIii1I11I1II1 * Oo0Ooo / iII111i % oO0o
   if 88 - 88: I1Ii111 * OOooOOo
  return ( [ ] )
  if 38 - 38: Oo0Ooo - OoooooooOO - OoooooooOO / II111iiii
  if 10 - 10: II111iiii - OoO0O00 / II111iiii % Ii1I - OoOoOO00
  if 90 - 90: I11i + II111iiii - oO0o - ooOoO0o / ooOoO0o / i11iIiiIii
  if 80 - 80: I1ii11iIi11i % O0 / II111iiii + iII111i
  if 22 - 22: Oo0Ooo + ooOoO0o . OOooOOo % Oo0Ooo . IiII
 o0oo0OoOo000 = O0o00oOOOO00 . address
 O00Oo0OOoO = O00Oo0OOoO [ 8 : : ]
 if 34 - 34: Ii1I . OoOoOO00 - OOooOOo * Oo0Ooo - ooOoO0o . oO0o
 iiIII1 = "BBHI"
 i11iIi1 = struct . calcsize ( iiIII1 )
 O0o0oo = "I"
 IIi1111 = struct . calcsize ( O0o0oo )
 oo00Oo0 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 36 - 36: I1ii11iIi11i + I1ii11iIi11i + I11i
 if 61 - 61: OoooooooOO / Oo0Ooo + II111iiii
 if 93 - 93: O0 * iIii1I11I1II1 % ooOoO0o . o0oOOo0O0Ooo
 if 13 - 13: iIii1I11I1II1
 i1IIIIi1I = [ ]
 for IiIIi1IiiIiI in range ( o0oo0OoOo000 ) :
  if ( len ( O00Oo0OOoO ) < i11iIi1 ) : return
  II1IoOo0 , O0o000 , iII , ii1i1II11II1i = struct . unpack ( iiIII1 ,
 O00Oo0OOoO [ : i11iIi1 ] )
  if 3 - 3: iII111i / oO0o * II111iiii
  O00Oo0OOoO = O00Oo0OOoO [ i11iIi1 : : ]
  if 21 - 21: o0oOOo0O0Ooo / I1ii11iIi11i
  if ( lisp_igmp_record_types . has_key ( II1IoOo0 ) == False ) :
   lprint ( "Invalid record type {}" . format ( II1IoOo0 ) )
   continue
   if 48 - 48: i11iIiiIii % I1ii11iIi11i
   if 73 - 73: OoOoOO00 + O0 + I1IiiI . iIii1I11I1II1 / I1ii11iIi11i
  o0OOOo = lisp_igmp_record_types [ II1IoOo0 ]
  iII = socket . ntohs ( iII )
  O0o00oOOOO00 . address = socket . ntohl ( ii1i1II11II1i )
  iI1i1iIi1iiII = O0o00oOOOO00 . print_address_no_iid ( )
  if 19 - 19: IiII . I11i + oO0o
  lprint ( "Record type: {}, group: {}, source-count: {}" . format ( o0OOOo , iI1i1iIi1iiII , iII ) )
  if 24 - 24: OoOoOO00 . I1IiiI / Ii1I
  if 42 - 42: I1Ii111 / I1ii11iIi11i
  if 1 - 1: OOooOOo
  if 48 - 48: I1IiiI / OoooooooOO % I11i * Oo0Ooo
  if 20 - 20: Oo0Ooo
  if 85 - 85: I1Ii111
  if 98 - 98: OoO0O00 - IiII % iIii1I11I1II1 . OoOoOO00 + i1IIi + OoooooooOO
  III11i1i1i11 = False
  if ( II1IoOo0 in ( 1 , 5 ) ) : III11i1i1i11 = True
  if ( II1IoOo0 in ( 2 , 4 ) and iII == 0 ) : III11i1i1i11 = True
  iiiIi1 = "join" if ( III11i1i1i11 ) else "leave"
  if 97 - 97: i11iIiiIii - O0 * o0oOOo0O0Ooo - IiII + I1IiiI
  if 7 - 7: oO0o + I1Ii111 . o0oOOo0O0Ooo / IiII + iIii1I11I1II1 % I1Ii111
  if 24 - 24: i11iIiiIii + iIii1I11I1II1
  if 22 - 22: i11iIiiIii . II111iiii / o0oOOo0O0Ooo / Ii1I . O0 . OoOoOO00
  if ( iI1i1iIi1iiII . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   continue
   if 89 - 89: O0 * Oo0Ooo + I1Ii111 + ooOoO0o * OoOoOO00
   if 20 - 20: OoO0O00 - OoOoOO00
   if 84 - 84: iIii1I11I1II1 + ooOoO0o . o0oOOo0O0Ooo % iII111i
   if 35 - 35: I11i - oO0o * oO0o / OoooooooOO + iII111i + OoOoOO00
   if 48 - 48: I1Ii111 / o0oOOo0O0Ooo - OOooOOo / o0oOOo0O0Ooo % O0
   if 38 - 38: OoO0O00 + o0oOOo0O0Ooo / OoO0O00
   if 74 - 74: oO0o - i1IIi . Oo0Ooo / I1IiiI + o0oOOo0O0Ooo . OoOoOO00
   if 35 - 35: iII111i / Ii1I
  if ( iII == 0 ) :
   i1IIIIi1I . append ( [ None , iI1i1iIi1iiII , III11i1i1i11 ] )
   lprint ( "IGMPv3 {} (*, {})" . format ( bold ( iiiIi1 , False ) ,
 bold ( iI1i1iIi1iiII , False ) ) )
   if 57 - 57: ooOoO0o . I1IiiI * OOooOOo
   if 87 - 87: I11i - I11i % iII111i - Ii1I
   if 29 - 29: oO0o - ooOoO0o * iIii1I11I1II1 / OoOoOO00
   if 34 - 34: I1IiiI . Oo0Ooo
   if 4 - 4: Ii1I - II111iiii * iII111i / oO0o - I1IiiI
  for oOoOoO0O in range ( iII ) :
   if ( len ( O00Oo0OOoO ) < IIi1111 ) : return
   ii1i1II11II1i = struct . unpack ( O0o0oo , O00Oo0OOoO [ : IIi1111 ] ) [ 0 ]
   oo00Oo0 . address = socket . ntohl ( ii1i1II11II1i )
   ii1II11I = oo00Oo0 . print_address_no_iid ( )
   i1IIIIi1I . append ( [ ii1II11I , iI1i1iIi1iiII , III11i1i1i11 ] )
   lprint ( "{} ({}, {})" . format ( iiiIi1 ,
 green ( ii1II11I , False ) , bold ( iI1i1iIi1iiII , False ) ) )
   O00Oo0OOoO = O00Oo0OOoO [ IIi1111 : : ]
   if 93 - 93: O0 . I1IiiI % I1IiiI * oO0o % I1Ii111 * Ii1I
   if 85 - 85: I1Ii111 % I11i + iII111i
   if 83 - 83: iIii1I11I1II1 - IiII * o0oOOo0O0Ooo . i11iIiiIii
   if 4 - 4: iIii1I11I1II1 - Ii1I
   if 46 - 46: OOooOOo / iII111i . i1IIi . i11iIiiIii . iIii1I11I1II1 % I11i
   if 62 - 62: I11i % II111iiii % OoooooooOO * ooOoO0o / oO0o
   if 29 - 29: o0oOOo0O0Ooo / O0 / OoO0O00
   if 23 - 23: Ii1I + i11iIiiIii % IiII
 return ( i1IIIIi1I )
 if 64 - 64: i11iIiiIii + OoooooooOO . oO0o * Ii1I
 if 49 - 49: O0
 if 72 - 72: I1Ii111
 if 96 - 96: II111iiii / OOooOOo % i1IIi / Oo0Ooo
 if 22 - 22: I1IiiI % iIii1I11I1II1 % I1ii11iIi11i
 if 68 - 68: iII111i + I11i
 if 61 - 61: oO0o . I1Ii111
 if 74 - 74: O0 . Ii1I - iII111i % IiII + II111iiii
lisp_geid = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
if 71 - 71: oO0o + Ii1I % oO0o
def lisp_glean_map_cache ( seid , rloc , encap_port , igmp ) :
 if 17 - 17: I1Ii111 % I1Ii111 * o0oOOo0O0Ooo
 if 84 - 84: I1Ii111 + iII111i . i1IIi / O0 / I1Ii111 + o0oOOo0O0Ooo
 if 70 - 70: O0 % ooOoO0o - iII111i + oO0o
 if 12 - 12: I1Ii111 - OoO0O00 % II111iiii % ooOoO0o / II111iiii % OoOoOO00
 if 74 - 74: iII111i . OOooOOo * Ii1I / Oo0Ooo . OoO0O00 . I11i
 if 65 - 65: i11iIiiIii - OoO0O00 / OoooooooOO * I1IiiI % iII111i
 i1i11111iiII1 = True
 IiiiiII1i = lisp_map_cache . lookup_cache ( seid , True )
 if ( IiiiiII1i and len ( IiiiiII1i . rloc_set ) != 0 ) :
  IiiiiII1i . last_refresh_time = lisp_get_timestamp ( )
  if 30 - 30: O0 - I11i
  OOiiIiiII11i1ii = IiiiiII1i . rloc_set [ 0 ]
  II1iI1iI = OOiiIiiII11i1ii . rloc
  OO00o0Oo = OOiiIiiII11i1ii . translated_port
  i1i11111iiII1 = ( II1iI1iI . is_exact_match ( rloc ) == False or
 OO00o0Oo != encap_port )
  if 62 - 62: Ii1I
  if ( i1i11111iiII1 ) :
   oOo = green ( seid . print_address ( ) , False )
   i11iII1IiI = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
   lprint ( "Change gleaned EID {} to RLOC {}" . format ( oOo , i11iII1IiI ) )
   OOiiIiiII11i1ii . delete_from_rloc_probe_list ( IiiiiII1i . eid , IiiiiII1i . group )
   lisp_change_gleaned_multicast ( seid , rloc , encap_port )
   if 30 - 30: iII111i % O0 + II111iiii * I1IiiI
 else :
  IiiiiII1i = lisp_mapping ( "" , "" , [ ] )
  IiiiiII1i . eid . copy_address ( seid )
  IiiiiII1i . mapping_source . copy_address ( rloc )
  IiiiiII1i . map_cache_ttl = LISP_GLEAN_TTL
  IiiiiII1i . gleaned = True
  oOo = green ( seid . print_address ( ) , False )
  i11iII1IiI = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( oOo , i11iII1IiI ) )
  IiiiiII1i . add_cache ( )
  if 91 - 91: i11iIiiIii
  if 35 - 35: OoOoOO00 * I1Ii111 / Oo0Ooo - i1IIi - IiII + OOooOOo
  if 96 - 96: Oo0Ooo + I1ii11iIi11i . O0
  if 62 - 62: i1IIi % OoooooooOO % OoooooooOO
  if 53 - 53: O0 * oO0o
 if ( i1i11111iiII1 ) :
  iIII = lisp_rloc ( )
  iIII . store_translated_rloc ( rloc , encap_port )
  iIII . add_to_rloc_probe_list ( IiiiiII1i . eid , IiiiiII1i . group )
  iIII . priority = 253
  iIII . mpriority = 255
  ooo0oo = [ iIII ]
  IiiiiII1i . rloc_set = ooo0oo
  IiiiiII1i . build_best_rloc_set ( )
  if 22 - 22: OOooOOo % Oo0Ooo % ooOoO0o - O0 + i1IIi
  if 67 - 67: OoO0O00 / I1IiiI - IiII + iII111i - iII111i
  if 4 - 4: IiII . Ii1I . IiII % OoO0O00
  if 12 - 12: OoOoOO00 + O0 / O0 . i1IIi
  if 58 - 58: IiII . iII111i % O0 . Ii1I * Oo0Ooo
 if ( igmp == None ) : return
 if 54 - 54: OoO0O00 % OOooOOo - OoO0O00 . Oo0Ooo % i1IIi
 if 95 - 95: iII111i . OoooooooOO . o0oOOo0O0Ooo / II111iiii - OoooooooOO / I1Ii111
 if 11 - 11: II111iiii / iII111i . oO0o / ooOoO0o / OOooOOo + OoO0O00
 if 37 - 37: iIii1I11I1II1 * O0
 if 64 - 64: I1Ii111 - II111iiii + oO0o % ooOoO0o * oO0o
 lisp_geid . instance_id = seid . instance_id
 if 27 - 27: iIii1I11I1II1 - Ii1I . i11iIiiIii / IiII . I1Ii111 / i11iIiiIii
 if 27 - 27: OoOoOO00 . I11i / OoOoOO00
 if 96 - 96: OoO0O00 - I1IiiI
 if 73 - 73: I1IiiI - o0oOOo0O0Ooo - I1Ii111
 if 34 - 34: iIii1I11I1II1 - i1IIi + OoO0O00 % Oo0Ooo + i1IIi
 oOooiIIIii1Ii1Ii1 = lisp_process_igmp_packet ( igmp )
 if ( type ( oOooiIIIii1Ii1Ii1 ) == bool ) : return
 if 46 - 46: I1IiiI
 for oo00Oo0 , O0o00oOOOO00 , III11i1i1i11 in oOooiIIIii1Ii1Ii1 :
  if ( oo00Oo0 != None ) : continue
  if 82 - 82: iII111i . i1IIi
  if 38 - 38: Ii1I . I1IiiI . I1ii11iIi11i
  if 26 - 26: O0 - II111iiii * I1Ii111 - OoOoOO00
  if 96 - 96: I11i * Oo0Ooo / OOooOOo - IiII
  lisp_geid . store_address ( O0o00oOOOO00 )
  Ii1iIIi1I1II1I , O0o000 , o00oo0 = lisp_allow_gleaning ( seid , lisp_geid , rloc )
  if ( Ii1iIIi1I1II1I == False ) : continue
  if 75 - 75: OoooooooOO - O0
  if ( III11i1i1i11 ) :
   lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port ,
 True )
  else :
   lisp_remove_gleaned_multicast ( seid , lisp_geid )
   if 39 - 39: i11iIiiIii / Ii1I / ooOoO0o
   if 93 - 93: o0oOOo0O0Ooo - Oo0Ooo / oO0o / OoOoOO00
   if 75 - 75: o0oOOo0O0Ooo * ooOoO0o % Ii1I
   if 94 - 94: OoooooooOO + II111iiii / iIii1I11I1II1 * ooOoO0o
   if 85 - 85: ooOoO0o / IiII
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
