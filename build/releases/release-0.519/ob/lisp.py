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
  self . json_telemetry = None
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
   if ( III1iii1 . afi == LISP_AFI_LCAF and self . json_telemetry != None ) :
    continue
    if 78 - 78: I1Ii111 % OOooOOo
   OO000o0 = red ( III1iii1 . print_address_no_iid ( ) , False )
   lprint ( "  itr-rloc: afi {} {}{}" . format ( III1iii1 . afi , OO000o0 ,
 "" if ( oOoo0oO == None ) else ", " + oOoo0oO [ 1 ] . print_keys ( ) ) )
   oOoo0oO = None
   if 35 - 35: I11i * O0 * OoO0O00 . I1ii11iIi11i
  if ( self . json_telemetry != None ) :
   lprint ( "  itr-rloc: afi {} telemetry: {}" . format ( LISP_AFI_LCAF ,
 self . json_telemetry ) )
   if 74 - 74: iII111i * iII111i * o0oOOo0O0Ooo / oO0o
   if 91 - 91: i11iIiiIii . I1ii11iIi11i / II111iiii
   if 97 - 97: Ii1I % i1IIi % IiII + Oo0Ooo - O0 - I11i
 def sign_map_request ( self , privkey ) :
  o00ooo0O = self . signature_eid . print_address ( )
  oO0o0O00O00O = self . source_eid . print_address ( )
  o00 = self . target_eid . print_address ( )
  oo0oO00O000 = lisp_hex_string ( self . nonce ) + oO0o0O00O00O + o00
  self . map_request_signature = privkey . sign ( oo0oO00O000 )
  I1ii1I11iIi = binascii . b2a_base64 ( self . map_request_signature )
  I1ii1I11iIi = { "source-eid" : oO0o0O00O00O , "signature-eid" : o00ooo0O ,
 "signature" : I1ii1I11iIi }
  return ( json . dumps ( I1ii1I11iIi ) )
  if 13 - 13: O0 . iII111i - IiII % i11iIiiIii % I1IiiI
  if 88 - 88: i1IIi % O0
 def verify_map_request_sig ( self , pubkey ) :
  IIII1i1IIIi = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( IIII1i1IIIi ) )
   return ( False )
   if 25 - 25: oO0o % ooOoO0o - iII111i * OoO0O00
   if 37 - 37: i1IIi + IiII - i1IIi % OoooooooOO + IiII + iIii1I11I1II1
  oO0o0O00O00O = self . source_eid . print_address ( )
  o00 = self . target_eid . print_address ( )
  oo0oO00O000 = lisp_hex_string ( self . nonce ) + oO0o0O00O00O + o00
  pubkey = binascii . a2b_base64 ( pubkey )
  if 30 - 30: i11iIiiIii % o0oOOo0O0Ooo . i1IIi
  iII1Ii1iIIii = True
  try :
   ii1i1I1111ii = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 71 - 71: iIii1I11I1II1 . OoOoOO00 * I1Ii111
   iII1Ii1iIIii = False
   if 64 - 64: iII111i - I1Ii111
   if 41 - 41: ooOoO0o * i11iIiiIii
  if ( iII1Ii1iIIii ) :
   try :
    iII1Ii1iIIii = ii1i1I1111ii . verify ( self . map_request_signature , oo0oO00O000 )
   except :
    iII1Ii1iIIii = False
    if 67 - 67: ooOoO0o . iIii1I11I1II1 . OoO0O00 + I1Ii111
    if 51 - 51: oO0o
    if 68 - 68: I1ii11iIi11i - Ii1I - I1Ii111
  OOI1I1iiI1iIIii = bold ( "passed" if iII1Ii1iIIii else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( OOI1I1iiI1iIIii , IIII1i1IIIi ) )
  return ( iII1Ii1iIIii )
  if 97 - 97: I11i
  if 84 - 84: IiII - OoOoOO00 . IiII + ooOoO0o . iII111i
 def encode_json ( self , json_string ) :
  O000oo0O0OO0 = LISP_LCAF_JSON_TYPE
  O00000oooOO = socket . htons ( LISP_AFI_LCAF )
  iI11iiI1 = socket . htons ( len ( json_string ) + 2 )
  I1Ioo000oooooooO = socket . htons ( len ( json_string ) )
  IIii1i = struct . pack ( "HBBBBHH" , O00000oooOO , 0 , 0 , O000oo0O0OO0 , 0 , iI11iiI1 ,
 I1Ioo000oooooooO )
  IIii1i += json_string
  IIii1i += struct . pack ( "H" , 0 )
  return ( IIii1i )
  if 18 - 18: oO0o * Oo0Ooo % i11iIiiIii + O0 % OOooOOo . OOooOOo
  if 84 - 84: OoooooooOO - Oo0Ooo
 def encode ( self , probe_dest , probe_port ) :
  ooo0OOoo = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  if 79 - 79: O0 - oO0o + oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
  o00OoooOoo = lisp_telemetry_configured ( ) if ( self . rloc_probe ) else None
  if ( o00OoooOoo != None ) : self . itr_rloc_count += 1
  ooo0OOoo = ooo0OOoo | ( self . itr_rloc_count << 8 )
  if 29 - 29: oO0o * i1IIi
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
  if 42 - 42: iII111i
  IIii1i = struct . pack ( "I" , socket . htonl ( ooo0OOoo ) )
  IIii1i += struct . pack ( "Q" , self . nonce )
  if 6 - 6: OoO0O00 + OOooOOo
  if 22 - 22: Oo0Ooo . OoooooooOO % I1Ii111
  if 16 - 16: I1ii11iIi11i
  if 78 - 78: OoO0O00 * iIii1I11I1II1
  if 58 - 58: I1ii11iIi11i * i11iIiiIii
  if 47 - 47: O0 . I1IiiI / ooOoO0o % i11iIiiIii
  I1i = False
  iII = self . privkey_filename
  if ( iII != None and os . path . exists ( iII ) ) :
   IIIii1i11111 = open ( iII , "r" ) ; ii1i1I1111ii = IIIii1i11111 . read ( ) ; IIIii1i11111 . close ( )
   try :
    ii1i1I1111ii = ecdsa . SigningKey . from_pem ( ii1i1I1111ii )
   except :
    return ( None )
    if 12 - 12: ooOoO0o % OoOoOO00
   ii11 = self . sign_map_request ( ii1i1I1111ii )
   I1i = True
  elif ( self . map_request_signature != None ) :
   I1ii1I11iIi = binascii . b2a_base64 ( self . map_request_signature )
   ii11 = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : I1ii1I11iIi }
   ii11 = json . dumps ( ii11 )
   I1i = True
   if 76 - 76: I1Ii111 % OoooooooOO
  if ( I1i ) :
   IIii1i += self . encode_json ( ii11 )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    IIii1i += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    IIii1i += self . source_eid . lcaf_encode_iid ( )
   else :
    IIii1i += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    IIii1i += self . source_eid . pack_address ( )
    if 15 - 15: I1IiiI . I1ii11iIi11i / iIii1I11I1II1 % I11i
    if 94 - 94: I1IiiI - Ii1I % OoooooooOO + i1IIi - OoooooooOO
    if 65 - 65: I1Ii111 . O0 + OoOoOO00
    if 82 - 82: ooOoO0o . I1Ii111 . Oo0Ooo % iIii1I11I1II1 - i11iIiiIii
    if 11 - 11: ooOoO0o . I1Ii111 - iII111i . o0oOOo0O0Ooo
    if 41 - 41: oO0o / OoO0O00 - OoO0O00 + ooOoO0o * OOooOOo
    if 13 - 13: I1Ii111 * II111iiii - OoOoOO00
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   oo0o00OO = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 3 - 3: OOooOOo + ooOoO0o * i11iIiiIii . iII111i / iIii1I11I1II1
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( oo0o00OO ) ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ]
    if 44 - 44: OoO0O00
    if 74 - 74: Ii1I * i1IIi * I11i - OoooooooOO . I1IiiI
    if 24 - 24: II111iiii - i11iIiiIii * i1IIi . ooOoO0o
    if 42 - 42: I11i / i11iIiiIii
    if 7 - 7: I11i
    if 50 - 50: i11iIiiIii . i11iIiiIii * i1IIi / i11iIiiIii . i1IIi - II111iiii
    if 72 - 72: iIii1I11I1II1 / o0oOOo0O0Ooo . I1ii11iIi11i
  for III1iii1 in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( III1iii1 ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     oOoo0oO = lisp_keys ( 1 )
     self . keys = [ None , oOoo0oO , None , None ]
     if 78 - 78: iIii1I11I1II1 . i11iIiiIii % IiII * Ii1I + iII111i - iIii1I11I1II1
    oOoo0oO = self . keys [ 1 ]
    oOoo0oO . add_key_by_nonce ( self . nonce )
    IIii1i += oOoo0oO . encode_lcaf ( III1iii1 )
   else :
    IIii1i += struct . pack ( "H" , socket . htons ( III1iii1 . afi ) )
    IIii1i += III1iii1 . pack_address ( )
    if 50 - 50: I1ii11iIi11i % Ii1I - I11i % Oo0Ooo - I11i - I1IiiI
    if 99 - 99: IiII * OoOoOO00 - i1IIi / I1Ii111 . ooOoO0o % o0oOOo0O0Ooo
    if 69 - 69: O0 . iII111i
    if 96 - 96: O0
    if 89 - 89: I1ii11iIi11i - Oo0Ooo
    if 26 - 26: ooOoO0o % ooOoO0o / II111iiii / iII111i
  if ( o00OoooOoo != None ) :
   Oo0OO0000oooo = str ( time . time ( ) )
   o00OoooOoo = lisp_encode_telemetry ( o00OoooOoo , io = Oo0OO0000oooo )
   self . json_telemetry = o00OoooOoo
   IIii1i += self . encode_json ( o00OoooOoo )
   if 2 - 2: i1IIi / i11iIiiIii + I1IiiI
   if 95 - 95: I1ii11iIi11i / IiII % iIii1I11I1II1 + O0
  i111IiI1III1 = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 97 - 97: IiII
  if 15 - 15: O0 - I1IiiI / i1IIi . I1Ii111
  o0o0o = 0
  if ( self . subscribe_bit ) :
   o0o0o = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 30 - 30: O0
    if 78 - 78: I1IiiI - OOooOOo - oO0o * ooOoO0o % i11iIiiIii + OOooOOo
    if 90 - 90: i11iIiiIii
  O00oO00oOO00O = "BB"
  IIii1i += struct . pack ( O00oO00oOO00O , o0o0o , i111IiI1III1 )
  if 47 - 47: OoO0O00 . i11iIiiIii
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
   if 9 - 9: OoOoOO00 - I11i . OoooooooOO % ooOoO0o
   if 13 - 13: OoO0O00 * iIii1I11I1II1 + II111iiii - Oo0Ooo - OoOoOO00
   if 43 - 43: iII111i / I1Ii111 * I1IiiI % ooOoO0o % I1IiiI
   if 18 - 18: OoO0O00
   if 99 - 99: iII111i / oO0o . i11iIiiIii / I11i + i1IIi - I11i
  if ( self . subscribe_bit ) : IIii1i = self . encode_xtr_id ( IIii1i )
  return ( IIii1i )
  if 50 - 50: i1IIi
  if 56 - 56: OoO0O00 + I1Ii111 / Ii1I
 def lcaf_decode_json ( self , packet ) :
  O00oO00oOO00O = "BBBBHH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 75 - 75: OoOoOO00
  oO00OO0Ooo00O , II1iII1IIIIi , O000oo0O0OO0 , oOOooo00 , iI11iiI1 , I1Ioo000oooooooO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 31 - 31: I11i + Oo0Ooo
  if 16 - 16: O0
  if ( O000oo0O0OO0 != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 80 - 80: I11i / Oo0Ooo + I1ii11iIi11i
  if 18 - 18: II111iiii - iII111i / iIii1I11I1II1 % OoOoOO00 % I1ii11iIi11i / o0oOOo0O0Ooo
  if 47 - 47: OOooOOo
  if 24 - 24: Ii1I % o0oOOo0O0Ooo
  iI11iiI1 = socket . ntohs ( iI11iiI1 )
  I1Ioo000oooooooO = socket . ntohs ( I1Ioo000oooooooO )
  packet = packet [ ooOoooOoo0oO : : ]
  if ( len ( packet ) < iI11iiI1 ) : return ( None )
  if ( iI11iiI1 != I1Ioo000oooooooO + 2 ) : return ( None )
  if 87 - 87: o0oOOo0O0Ooo % iII111i / ooOoO0o - IiII + i11iIiiIii
  if 85 - 85: OoooooooOO * IiII . OOooOOo / iII111i / OoooooooOO
  if 87 - 87: OoO0O00
  if 32 - 32: i11iIiiIii - OoOoOO00 * I11i . Oo0Ooo * ooOoO0o
  ii11 = packet [ 0 : I1Ioo000oooooooO ]
  packet = packet [ I1Ioo000oooooooO : : ]
  if 21 - 21: OOooOOo
  if 11 - 11: oO0o % i11iIiiIii * O0
  if 28 - 28: I1Ii111 / iIii1I11I1II1 + OOooOOo . I1ii11iIi11i % OOooOOo + OoO0O00
  if 79 - 79: oO0o
  if ( lisp_is_json_telemetry ( ii11 ) != None ) :
   self . json_telemetry = ii11
   if 39 - 39: I1Ii111 % oO0o % O0 % O0 - iII111i - oO0o
   if 83 - 83: i11iIiiIii + iIii1I11I1II1
   if 21 - 21: o0oOOo0O0Ooo / i11iIiiIii % I1Ii111
   if 56 - 56: o0oOOo0O0Ooo * iIii1I11I1II1 . Ii1I + OoOoOO00 % I1Ii111
   if 11 - 11: OOooOOo
  O00oO00oOO00O = "H"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if ( O000oOOoOOO != 0 ) : return ( packet )
  if 12 - 12: OoooooooOO * OOooOOo * I1ii11iIi11i * ooOoO0o
  if ( self . json_telemetry != None ) : return ( packet )
  if 26 - 26: OoooooooOO . i1IIi + OoO0O00
  if 42 - 42: i11iIiiIii * o0oOOo0O0Ooo % I11i % Oo0Ooo + o0oOOo0O0Ooo * i11iIiiIii
  if 66 - 66: Ii1I / IiII . OoooooooOO * Oo0Ooo % i11iIiiIii
  if 100 - 100: I1ii11iIi11i % II111iiii * i11iIiiIii - iII111i
  try :
   ii11 = json . loads ( ii11 )
  except :
   return ( None )
   if 69 - 69: OOooOOo + iII111i / I1Ii111
   if 37 - 37: iIii1I11I1II1 * I11i / IiII * Oo0Ooo % i11iIiiIii
   if 93 - 93: ooOoO0o + ooOoO0o
   if 65 - 65: OoooooooOO * I11i * oO0o % I1ii11iIi11i * II111iiii
   if 86 - 86: i11iIiiIii / I11i * iII111i - iII111i
  if ( ii11 . has_key ( "source-eid" ) == False ) : return ( packet )
  iIiiIIi1i111iI = ii11 [ "source-eid" ]
  O000oOOoOOO = LISP_AFI_IPV4 if iIiiIIi1i111iI . count ( "." ) == 3 else LISP_AFI_IPV6 if iIiiIIi1i111iI . count ( ":" ) == 7 else None
  if 10 - 10: IiII % II111iiii
  if ( O000oOOoOOO == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( iIiiIIi1i111iI ) )
   return ( None )
   if 50 - 50: OoOoOO00 * iII111i
   if 59 - 59: I1IiiI * I1IiiI / I11i
  self . source_eid . afi = O000oOOoOOO
  self . source_eid . store_address ( iIiiIIi1i111iI )
  if 92 - 92: o0oOOo0O0Ooo
  if ( ii11 . has_key ( "signature-eid" ) == False ) : return ( packet )
  iIiiIIi1i111iI = ii11 [ "signature-eid" ]
  if ( iIiiIIi1i111iI . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( iIiiIIi1i111iI ) )
   return ( None )
   if 8 - 8: iII111i + I1ii11iIi11i . Ii1I
   if 50 - 50: Oo0Ooo
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( iIiiIIi1i111iI )
  if 16 - 16: Ii1I - OoOoOO00 % Oo0Ooo / Ii1I . I11i + ooOoO0o
  if ( ii11 . has_key ( "signature" ) == False ) : return ( packet )
  I1ii1I11iIi = binascii . a2b_base64 ( ii11 [ "signature" ] )
  self . map_request_signature = I1ii1I11iIi
  return ( packet )
  if 78 - 78: iIii1I11I1II1 + OoO0O00 + i11iIiiIii
  if 21 - 21: Oo0Ooo + Ii1I % ooOoO0o + OoOoOO00 % I11i
 def decode ( self , packet , source , port ) :
  O00oO00oOO00O = "I"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 22 - 22: i1IIi / OoooooooOO . OoO0O00
  ooo0OOoo = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  ooo0OOoo = ooo0OOoo [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if 83 - 83: I1IiiI - OoooooooOO + I1ii11iIi11i . Ii1I / o0oOOo0O0Ooo + ooOoO0o
  O00oO00oOO00O = "Q"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 90 - 90: I1IiiI - i11iIiiIii
  oOO000 = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  packet = packet [ ooOoooOoo0oO : : ]
  if 42 - 42: OOooOOo . Oo0Ooo
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
  self . itr_rloc_count = ( ( ooo0OOoo >> 8 ) & 0x1f )
  self . record_count = ooo0OOoo & 0xff
  self . nonce = oOO000 [ 0 ]
  if 21 - 21: iII111i . I1IiiI / I11i
  if 97 - 97: iIii1I11I1II1 + i1IIi - o0oOOo0O0Ooo
  if 73 - 73: OoO0O00 - i11iIiiIii % I1Ii111 / Oo0Ooo - OoooooooOO % OOooOOo
  if 79 - 79: I1IiiI / o0oOOo0O0Ooo . Ii1I * I1ii11iIi11i + I11i
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 96 - 96: OoO0O00 * II111iiii
   if 1 - 1: I1IiiI - OoOoOO00
  ooOoooOoo0oO = struct . calcsize ( "H" )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 74 - 74: OoOoOO00 * II111iiii + O0 + I11i
  O000oOOoOOO = struct . unpack ( "H" , packet [ : ooOoooOoo0oO ] )
  self . source_eid . afi = socket . ntohs ( O000oOOoOOO [ 0 ] )
  packet = packet [ ooOoooOoo0oO : : ]
  if 3 - 3: iIii1I11I1II1 - i1IIi / iII111i + i1IIi + O0
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   Ii1 = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( Ii1 )
    if ( packet == None ) : return ( None )
    if 84 - 84: OoOoOO00 - ooOoO0o - OoooooooOO . OoooooooOO % IiII
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 38 - 38: OoO0O00 * I1ii11iIi11i
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 4 - 4: OoO0O00 . I1ii11iIi11i
  IiiI = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  Oo0o0o0o = self . itr_rloc_count + 1
  if 55 - 55: IiII + I1Ii111 % O0 % OoO0O00 * IiII % OOooOOo
  while ( Oo0o0o0o != 0 ) :
   ooOoooOoo0oO = struct . calcsize ( "H" )
   if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
   if 95 - 95: OoooooooOO / iII111i
   O000oOOoOOO = socket . ntohs ( struct . unpack ( "H" , packet [ : ooOoooOoo0oO ] ) [ 0 ] )
   III1iii1 = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   III1iii1 . afi = O000oOOoOOO
   if 19 - 19: i1IIi + iII111i . II111iiii . ooOoO0o + i11iIiiIii * i1IIi
   if 57 - 57: I1IiiI % IiII . oO0o - I1IiiI * OOooOOo
   if 22 - 22: I11i . OoOoOO00 * O0 - IiII
   if 12 - 12: i11iIiiIii + I1ii11iIi11i * OoO0O00
   if 13 - 13: Oo0Ooo + OoooooooOO / IiII
   if ( III1iii1 . afi == LISP_AFI_LCAF ) :
    OO0o0 = packet
    oOo0Oo0OOoo00 = packet [ ooOoooOoo0oO : : ]
    packet = self . lcaf_decode_json ( oOo0Oo0OOoo00 )
    if ( packet == oOo0Oo0OOoo00 ) : packet = OO0o0
    if 76 - 76: i11iIiiIii . I11i . ooOoO0o . I1ii11iIi11i * Ii1I . I1Ii111
    if 78 - 78: i1IIi * II111iiii . i11iIiiIii - IiII / OoooooooOO + i1IIi
    if 1 - 1: i11iIiiIii + iII111i
    if 91 - 91: ooOoO0o + IiII . I1IiiI / I11i / IiII
    if 23 - 23: I1ii11iIi11i - OOooOOo - i1IIi
    if 20 - 20: OoooooooOO / Oo0Ooo * OoO0O00 . o0oOOo0O0Ooo . I1IiiI
   if ( III1iii1 . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < III1iii1 . addr_length ( ) ) : return ( None )
    packet = III1iii1 . unpack_address ( packet [ ooOoooOoo0oO : : ] )
    if ( packet == None ) : return ( None )
    if 75 - 75: iIii1I11I1II1 - Ii1I % O0 % IiII
    if ( IiiI ) :
     self . itr_rlocs . append ( III1iii1 )
     Oo0o0o0o -= 1
     continue
     if 6 - 6: Oo0Ooo % oO0o * ooOoO0o - i1IIi . OoOoOO00
     if 20 - 20: Oo0Ooo / I1Ii111 . Oo0Ooo
    oo0o00OO = lisp_build_crypto_decap_lookup_key ( III1iii1 , port )
    if 60 - 60: I1ii11iIi11i - I1IiiI * O0 * Oo0Ooo . i1IIi . OoOoOO00
    if 24 - 24: IiII * I1IiiI / OOooOOo
    if 51 - 51: iIii1I11I1II1 / I11i * OoO0O00 * Ii1I + I1ii11iIi11i . OoooooooOO
    if 75 - 75: IiII / OoooooooOO / O0 % OOooOOo
    if 87 - 87: II111iiii / iIii1I11I1II1 % I1ii11iIi11i
    if ( lisp_nat_traversal and III1iii1 . is_private_address ( ) and source ) : III1iii1 = source
    if 11 - 11: o0oOOo0O0Ooo * OoO0O00
    oO0 = lisp_crypto_keys_by_rloc_decap
    if ( oO0 . has_key ( oo0o00OO ) ) : oO0 . pop ( oo0o00OO )
    if 38 - 38: OoooooooOO * o0oOOo0O0Ooo . II111iiii % I1IiiI % I1Ii111
    if 80 - 80: ooOoO0o % o0oOOo0O0Ooo / OoO0O00 + oO0o
    if 83 - 83: i1IIi / OoooooooOO
    if 59 - 59: Oo0Ooo + O0 - I11i + OOooOOo
    if 97 - 97: I1IiiI * o0oOOo0O0Ooo
    if 79 - 79: iII111i - ooOoO0o - OoO0O00 / iIii1I11I1II1 % Ii1I
    lisp_write_ipc_decap_key ( oo0o00OO , None )
    if 2 - 2: iIii1I11I1II1 + OoooooooOO - i1IIi / Ii1I
   elif ( self . json_telemetry == None ) :
    if 88 - 88: I1ii11iIi11i . OoooooooOO / Oo0Ooo / o0oOOo0O0Ooo % Oo0Ooo
    if 80 - 80: Ii1I + OoO0O00 * OoooooooOO - IiII % O0 - I1Ii111
    if 80 - 80: II111iiii / I1ii11iIi11i
    if 60 - 60: OOooOOo - iII111i + iIii1I11I1II1 + II111iiii + iII111i
    OO0o0 = packet
    IIii1Iiii1iiI = lisp_keys ( 1 )
    packet = IIii1Iiii1iiI . decode_lcaf ( OO0o0 , 0 )
    if 21 - 21: II111iiii . O0 + Oo0Ooo - i11iIiiIii
    if ( packet == None ) : return ( None )
    if 5 - 5: iIii1I11I1II1 * i11iIiiIii + OoO0O00 + I11i * O0 % ooOoO0o
    if 88 - 88: o0oOOo0O0Ooo / i11iIiiIii * I1ii11iIi11i
    if 23 - 23: O0 / iII111i
    if 66 - 66: i1IIi % OoooooooOO * i11iIiiIii + oO0o * O0 / OoO0O00
    Iii = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( IIii1Iiii1iiI . cipher_suite in Iii ) :
     if ( IIii1Iiii1iiI . cipher_suite == LISP_CS_25519_CBC or
 IIii1Iiii1iiI . cipher_suite == LISP_CS_25519_GCM ) :
      ii1i1I1111ii = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 14 - 14: I1IiiI . IiII
     if ( IIii1Iiii1iiI . cipher_suite == LISP_CS_25519_CHACHA ) :
      ii1i1I1111ii = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 29 - 29: OoooooooOO / IiII + OoOoOO00 - I1Ii111 + IiII . i1IIi
    else :
     ii1i1I1111ii = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 26 - 26: i11iIiiIii - II111iiii
    packet = ii1i1I1111ii . decode_lcaf ( OO0o0 , 0 )
    if ( packet == None ) : return ( None )
    if 43 - 43: I1IiiI
    if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
    O000oOOoOOO = struct . unpack ( "H" , packet [ : ooOoooOoo0oO ] ) [ 0 ]
    III1iii1 . afi = socket . ntohs ( O000oOOoOOO )
    if ( len ( packet ) < III1iii1 . addr_length ( ) ) : return ( None )
    if 35 - 35: ooOoO0o + OoOoOO00 * OoooooooOO - II111iiii
    packet = III1iii1 . unpack_address ( packet [ ooOoooOoo0oO : : ] )
    if ( packet == None ) : return ( None )
    if 19 - 19: i1IIi / Ii1I / OoOoOO00 . I1IiiI / Ii1I % o0oOOo0O0Ooo
    if ( IiiI ) :
     self . itr_rlocs . append ( III1iii1 )
     Oo0o0o0o -= 1
     continue
     if 39 - 39: ooOoO0o - OoooooooOO
     if 88 - 88: i1IIi + iIii1I11I1II1 * i11iIiiIii - OoooooooOO % o0oOOo0O0Ooo
    oo0o00OO = lisp_build_crypto_decap_lookup_key ( III1iii1 , port )
    if 74 - 74: ooOoO0o - i11iIiiIii
    I1I1iI = None
    if ( lisp_nat_traversal and III1iii1 . is_private_address ( ) and source ) : III1iii1 = source
    if 28 - 28: i11iIiiIii - Ii1I
    if 59 - 59: II111iiii - OoO0O00
    if ( lisp_crypto_keys_by_rloc_decap . has_key ( oo0o00OO ) ) :
     oOoo0oO = lisp_crypto_keys_by_rloc_decap [ oo0o00OO ]
     I1I1iI = oOoo0oO [ 1 ] if oOoo0oO and oOoo0oO [ 1 ] else None
     if 31 - 31: I11i - OoOoOO00 / o0oOOo0O0Ooo * OoOoOO00 / Oo0Ooo + o0oOOo0O0Ooo
     if 46 - 46: IiII * OoO0O00 / OOooOOo + Oo0Ooo
    I1iI1iIIIii = True
    if ( I1I1iI ) :
     if ( I1I1iI . compare_keys ( ii1i1I1111ii ) ) :
      self . keys = [ None , I1I1iI , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( oo0o00OO , False ) ) )
      if 46 - 46: iII111i / o0oOOo0O0Ooo . OOooOOo + iII111i - II111iiii + i1IIi
     else :
      I1iI1iIIIii = False
      I1iIIiI = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( I1iIIiI , red ( oo0o00OO ,
 False ) ) )
      ii1i1I1111ii . copy_keypair ( I1I1iI )
      ii1i1I1111ii . uptime = I1I1iI . uptime
      I1I1iI = None
      if 65 - 65: OoO0O00 . IiII % I1Ii111 . OoooooooOO
      if 19 - 19: I1Ii111 * Ii1I - oO0o
      if 78 - 78: OoO0O00 - Ii1I / OOooOOo
    if ( I1I1iI == None ) :
     self . keys = [ None , ii1i1I1111ii , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      ii1i1I1111ii . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( oo0o00OO , False ) ) )
     elif ( ii1i1I1111ii . remote_public_key != None ) :
      if ( I1iI1iIIIii ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # OoOoOO00 . OoO0O00 / iII111i / OOooOOo % IiII
 red ( oo0o00OO , False ) ) )
       if 51 - 51: I11i + ooOoO0o / I1IiiI
      ii1i1I1111ii . compute_shared_key ( "decap" )
      ii1i1I1111ii . add_key_by_rloc ( oo0o00OO , False )
      if 3 - 3: iIii1I11I1II1 / OOooOOo % oO0o . Ii1I - Ii1I
      if 55 - 55: i11iIiiIii % OoooooooOO + O0
      if 7 - 7: ooOoO0o - i11iIiiIii * iII111i / Ii1I - o0oOOo0O0Ooo
      if 62 - 62: o0oOOo0O0Ooo - iIii1I11I1II1 . I11i . Ii1I * Ii1I
   self . itr_rlocs . append ( III1iii1 )
   Oo0o0o0o -= 1
   if 24 - 24: I11i
   if 93 - 93: I1IiiI % OoO0O00 / i11iIiiIii / I11i
  ooOoooOoo0oO = struct . calcsize ( "BBH" )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 60 - 60: ooOoO0o - Ii1I . I1IiiI * oO0o * i11iIiiIii
  o0o0o , i111IiI1III1 , O000oOOoOOO = struct . unpack ( "BBH" , packet [ : ooOoooOoo0oO ] )
  self . subscribe_bit = ( o0o0o & 0x80 )
  self . target_eid . afi = socket . ntohs ( O000oOOoOOO )
  packet = packet [ ooOoooOoo0oO : : ]
  if 29 - 29: OoO0O00 - Oo0Ooo . oO0o / OoO0O00 % i11iIiiIii
  self . target_eid . mask_len = i111IiI1III1
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , I1iO0000 = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( I1iO0000 ) : self . target_group = I1iO0000
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ ooOoooOoo0oO : : ]
   if 70 - 70: I11i . OoOoOO00 . i11iIiiIii * ooOoO0o - II111iiii
  return ( packet )
  if 23 - 23: IiII
  if 53 - 53: I1Ii111 % OOooOOo . Ii1I / OOooOOo * OOooOOo * O0
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 1 - 1: iIii1I11I1II1 % I1ii11iIi11i . oO0o . IiII . o0oOOo0O0Ooo / o0oOOo0O0Ooo
  if 52 - 52: O0 * OoooooooOO . I1Ii111 . OOooOOo - iII111i % iII111i
 def encode_xtr_id ( self , packet ) :
  OoOO = self . xtr_id >> 64
  IiI1i111III = self . xtr_id & 0xffffffffffffffff
  OoOO = byte_swap_64 ( OoOO )
  IiI1i111III = byte_swap_64 ( IiI1i111III )
  packet += struct . pack ( "QQ" , OoOO , IiI1i111III )
  return ( packet )
  if 33 - 33: i11iIiiIii - o0oOOo0O0Ooo . I1IiiI - oO0o - II111iiii + O0
  if 54 - 54: iIii1I11I1II1 - IiII - IiII
 def decode_xtr_id ( self , packet ) :
  ooOoooOoo0oO = struct . calcsize ( "QQ" )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  packet = packet [ len ( packet ) - ooOoooOoo0oO : : ]
  OoOO , IiI1i111III = struct . unpack ( "QQ" , packet [ : ooOoooOoo0oO ] )
  OoOO = byte_swap_64 ( OoOO )
  IiI1i111III = byte_swap_64 ( IiI1i111III )
  self . xtr_id = ( OoOO << 64 ) | IiI1i111III
  return ( True )
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
class lisp_map_reply ( ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 97 - 97: I1IiiI
  if 63 - 63: O0 - OoOoOO00 / i11iIiiIii / OoooooooOO / ooOoO0o / II111iiii
 def print_map_reply ( self ) :
  oOOo0ooO0 = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 45 - 45: II111iiii . OoO0O00 + OoO0O00 * iIii1I11I1II1
  lprint ( oOOo0ooO0 . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # I1Ii111 * IiII
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 70 - 70: Ii1I / Ii1I - oO0o
  if 98 - 98: ooOoO0o * OOooOOo . OoooooooOO * I1IiiI - II111iiii
 def encode ( self ) :
  ooo0OOoo = ( LISP_MAP_REPLY << 28 ) | self . record_count
  ooo0OOoo |= self . hop_count << 8
  if ( self . rloc_probe ) : ooo0OOoo |= 0x08000000
  if ( self . echo_nonce_capable ) : ooo0OOoo |= 0x04000000
  if ( self . security ) : ooo0OOoo |= 0x02000000
  if 39 - 39: iII111i . Oo0Ooo - I1IiiI . I11i % I1IiiI % iII111i
  IIii1i = struct . pack ( "I" , socket . htonl ( ooo0OOoo ) )
  IIii1i += struct . pack ( "Q" , self . nonce )
  return ( IIii1i )
  if 27 - 27: OOooOOo - OOooOOo / i11iIiiIii * OoOoOO00 + O0
  if 2 - 2: i11iIiiIii % I1IiiI
 def decode ( self , packet ) :
  O00oO00oOO00O = "I"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 90 - 90: II111iiii
  ooo0OOoo = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  ooo0OOoo = ooo0OOoo [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if 2 - 2: Ii1I - OoooooooOO - i11iIiiIii % Oo0Ooo / Ii1I
  O00oO00oOO00O = "Q"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 77 - 77: o0oOOo0O0Ooo . o0oOOo0O0Ooo * I1Ii111 + OOooOOo - i11iIiiIii
  oOO000 = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  packet = packet [ ooOoooOoo0oO : : ]
  if 45 - 45: I1IiiI . I1IiiI - Oo0Ooo * OOooOOo
  ooo0OOoo = socket . ntohl ( ooo0OOoo )
  self . rloc_probe = True if ( ooo0OOoo & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( ooo0OOoo & 0x04000000 ) else False
  self . security = True if ( ooo0OOoo & 0x02000000 ) else False
  self . hop_count = ( ooo0OOoo >> 8 ) & 0xff
  self . record_count = ooo0OOoo & 0xff
  self . nonce = oOO000 [ 0 ]
  if 71 - 71: i1IIi / I11i
  if ( lisp_crypto_keys_by_nonce . has_key ( self . nonce ) ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 14 - 14: OoooooooOO
  return ( packet )
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
  if 94 - 94: i1IIi + IiII / OoooooooOO - oO0o / OOooOOo / OoOoOO00
  if 55 - 55: OOooOOo
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 5 - 5: I11i / OoOoOO00
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 48 - 48: i1IIi - oO0o . OoooooooOO - OoO0O00 - i1IIi
  if 19 - 19: oO0o % Ii1I + I1ii11iIi11i . II111iiii * i11iIiiIii
 def print_ttl ( self ) :
  O0000 = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   O0000 = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( O0000 % 60 ) == 0 ) :
   O0000 = str ( O0000 / 60 ) + " hours"
  else :
   O0000 = str ( O0000 ) + " mins"
   if 47 - 47: OoooooooOO - OoOoOO00 . I1Ii111 / OoooooooOO
  return ( O0000 )
  if 73 - 73: i11iIiiIii - OoooooooOO / II111iiii - O0 * i1IIi - Ii1I
  if 52 - 52: II111iiii / OOooOOo
 def store_ttl ( self ) :
  O0000 = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : O0000 = self . record_ttl & 0x7fffffff
  return ( O0000 )
  if 61 - 61: i11iIiiIii * I1IiiI % O0 / iII111i
  if 70 - 70: Oo0Ooo
 def print_record ( self , indent , ddt ) :
  o0Oo0oo = ""
  Ooo0OO00OOo0O = ""
  OOO0 = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    OOO0 = lisp_map_referral_action_string [ self . action ]
    OOO0 = bold ( OOO0 , False )
    o0Oo0oo = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 1 - 1: Oo0Ooo . oO0o . o0oOOo0O0Ooo / I1IiiI
    Ooo0OO00OOo0O = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 64 - 64: iII111i
    if 65 - 65: O0 / II111iiii * IiII % Ii1I + o0oOOo0O0Ooo
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    OOO0 = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     OOO0 = bold ( OOO0 , False )
     if 43 - 43: I1Ii111 + OoO0O00 * OoooooooOO
     if 85 - 85: iII111i + OOooOOo
     if 36 - 36: OoO0O00 % II111iiii * O0 + II111iiii - oO0o - i1IIi
     if 53 - 53: Ii1I - OOooOOo
  O000oOOoOOO = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  oOOo0ooO0 = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 75 - 75: iII111i % O0 - I11i - I1ii11iIi11i + I1IiiI - I1IiiI
  lprint ( oOOo0ooO0 . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 OOO0 , "auth" if ( self . authoritative is True ) else "non-auth" ,
 o0Oo0oo , Ooo0OO00OOo0O , self . map_version , O000oOOoOOO ,
 green ( self . print_prefix ( ) , False ) ) )
  if 87 - 87: i1IIi % Ii1I % i1IIi + iIii1I11I1II1
  if 23 - 23: iIii1I11I1II1 * I11i . I1Ii111 - o0oOOo0O0Ooo
 def encode ( self ) :
  Ooo0oo0oO000 = self . action << 13
  if ( self . authoritative ) : Ooo0oo0oO000 |= 0x1000
  if ( self . ddt_incomplete ) : Ooo0oo0oO000 |= 0x800
  if 14 - 14: o0oOOo0O0Ooo - I1Ii111
  if 94 - 94: I1Ii111 % OoooooooOO
  if 40 - 40: OoOoOO00 - Ii1I * o0oOOo0O0Ooo
  if 91 - 91: OoOoOO00
  O000oOOoOOO = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( O000oOOoOOO < 0 ) : O000oOOoOOO = LISP_AFI_LCAF
  OOoo00o0 = ( self . group . is_null ( ) == False )
  if ( OOoo00o0 ) : O000oOOoOOO = LISP_AFI_LCAF
  if 58 - 58: I11i / o0oOOo0O0Ooo - IiII
  iI1II1i1ii = ( self . signature_count << 12 ) | self . map_version
  i111IiI1III1 = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 63 - 63: Oo0Ooo . iII111i . IiII . Oo0Ooo + O0 . I1IiiI
  IIii1i = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , i111IiI1III1 , socket . htons ( Ooo0oo0oO000 ) ,
 socket . htons ( iI1II1i1ii ) , socket . htons ( O000oOOoOOO ) )
  if 91 - 91: OoO0O00 % OoOoOO00 / I1Ii111 * Ii1I / Oo0Ooo
  if 50 - 50: ooOoO0o
  if 26 - 26: O0 . I1IiiI - Ii1I
  if 42 - 42: OOooOOo . OoO0O00 + I1IiiI + OoooooooOO
  if ( OOoo00o0 ) :
   IIii1i += self . eid . lcaf_encode_sg ( self . group )
   return ( IIii1i )
   if 90 - 90: Ii1I / OoOoOO00 - iIii1I11I1II1 / i1IIi * I1Ii111 - ooOoO0o
   if 2 - 2: iII111i * I11i * ooOoO0o + i11iIiiIii + oO0o
   if 81 - 81: o0oOOo0O0Ooo * OoO0O00
   if 18 - 18: i11iIiiIii / o0oOOo0O0Ooo - oO0o . I11i * i1IIi
   if 67 - 67: Ii1I
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   IIii1i = IIii1i [ 0 : - 2 ]
   IIii1i += self . eid . address . encode_geo ( )
   return ( IIii1i )
   if 64 - 64: OoOoOO00 + iII111i * OoOoOO00 - I1IiiI * OoooooooOO
   if 27 - 27: II111iiii + i11iIiiIii
   if 32 - 32: i1IIi
   if 76 - 76: II111iiii % ooOoO0o - I1ii11iIi11i
   if 50 - 50: II111iiii / I1IiiI . Ii1I % i11iIiiIii
  if ( O000oOOoOOO == LISP_AFI_LCAF ) :
   IIii1i += self . eid . lcaf_encode_iid ( )
   return ( IIii1i )
   if 66 - 66: oO0o / OOooOOo / iII111i
   if 5 - 5: I1Ii111 . oO0o
   if 77 - 77: iII111i / i11iIiiIii
   if 20 - 20: O0 . I11i
   if 67 - 67: OoOoOO00 - ooOoO0o - iIii1I11I1II1
  IIii1i += self . eid . pack_address ( )
  return ( IIii1i )
  if 31 - 31: II111iiii + o0oOOo0O0Ooo * i11iIiiIii . o0oOOo0O0Ooo
  if 73 - 73: oO0o / OOooOOo * II111iiii % OoooooooOO - i1IIi - ooOoO0o
 def decode ( self , packet ) :
  O00oO00oOO00O = "IBBHHH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 43 - 43: o0oOOo0O0Ooo + Ii1I % OoO0O00 . I1Ii111 + i1IIi
  self . record_ttl , self . rloc_count , self . eid . mask_len , Ooo0oo0oO000 , self . map_version , self . eid . afi = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 85 - 85: Oo0Ooo % I1ii11iIi11i / OOooOOo
  if 65 - 65: ooOoO0o + IiII - OoOoOO00 % II111iiii - iIii1I11I1II1
  if 39 - 39: I1IiiI + I1ii11iIi11i - i11iIiiIii
  self . record_ttl = socket . ntohl ( self . record_ttl )
  Ooo0oo0oO000 = socket . ntohs ( Ooo0oo0oO000 )
  self . action = ( Ooo0oo0oO000 >> 13 ) & 0x7
  self . authoritative = True if ( ( Ooo0oo0oO000 >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( Ooo0oo0oO000 >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ ooOoooOoo0oO : : ]
  if 43 - 43: iIii1I11I1II1
  if 73 - 73: OoOoOO00 + o0oOOo0O0Ooo
  if 58 - 58: i1IIi * I1ii11iIi11i % iII111i . OoO0O00 % IiII % I11i
  if 63 - 63: I1ii11iIi11i % ooOoO0o % I1ii11iIi11i
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , oOooO00OOoO = self . eid . lcaf_decode_eid ( packet )
   if ( oOooO00OOoO ) : self . group = oOooO00OOoO
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 22 - 22: O0 + O0 + Oo0Ooo - ooOoO0o
   if 77 - 77: iII111i / II111iiii / OoO0O00 - o0oOOo0O0Ooo
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 87 - 87: Oo0Ooo % I1ii11iIi11i . OoooooooOO % Ii1I * oO0o - I1IiiI
  if 9 - 9: OoooooooOO - Ii1I - Oo0Ooo - Ii1I - iIii1I11I1II1 - iII111i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 65 - 65: Oo0Ooo * ooOoO0o % i11iIiiIii
  if 12 - 12: OoOoOO00 . I1ii11iIi11i . Oo0Ooo
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
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 91 - 91: I1IiiI - OoooooooOO - OoooooooOO
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
  if 69 - 69: iII111i * i11iIiiIii / i1IIi
  if 86 - 86: I1IiiI % I11i * O0 + i1IIi % I1Ii111
 def print_ecm ( self ) :
  oOOo0ooO0 = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 97 - 97: II111iiii * OoOoOO00 - I1Ii111 / i11iIiiIii / OoOoOO00
  lprint ( oOOo0ooO0 . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 25 - 25: Oo0Ooo / Oo0Ooo
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 74 - 74: OOooOOo
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 30 - 30: O0 . Ii1I / o0oOOo0O0Ooo + I1IiiI - O0
   if 88 - 88: i11iIiiIii
   if 33 - 33: OoO0O00 + O0
   if 20 - 20: o0oOOo0O0Ooo % I11i . ooOoO0o - i1IIi . O0
   if 10 - 10: i1IIi
   if 49 - 49: I1Ii111 - Ii1I . O0
  ooo0OOoo = ( LISP_ECM << 28 )
  if ( self . security ) : ooo0OOoo |= 0x08000000
  if ( self . ddt ) : ooo0OOoo |= 0x04000000
  if ( self . to_etr ) : ooo0OOoo |= 0x02000000
  if ( self . to_ms ) : ooo0OOoo |= 0x01000000
  if 46 - 46: OOooOOo
  ooOoO = struct . pack ( "I" , socket . htonl ( ooo0OOoo ) )
  if 66 - 66: IiII
  Ooo0oO = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   Ooo0oO = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   Ooo0oO += self . source . pack_address ( )
   Ooo0oO += self . dest . pack_address ( )
   Ooo0oO = lisp_ip_checksum ( Ooo0oO )
   if 83 - 83: iII111i / I1Ii111 . I11i / i11iIiiIii
  if ( self . afi == LISP_AFI_IPV6 ) :
   Ooo0oO = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   Ooo0oO += self . source . pack_address ( )
   Ooo0oO += self . dest . pack_address ( )
   if 4 - 4: ooOoO0o . OoO0O00
   if 34 - 34: I1Ii111 * I1IiiI . OoooooooOO % I11i
  IiII1iiI = socket . htons ( self . udp_sport )
  OooOOOoOoo0O0 = socket . htons ( self . udp_dport )
  I1111III111ii = socket . htons ( self . udp_length )
  Ooo0OO00oo = socket . htons ( self . udp_checksum )
  o0oOo00 = struct . pack ( "HHHH" , IiII1iiI , OooOOOoOoo0O0 , I1111III111ii , Ooo0OO00oo )
  return ( ooOoO + Ooo0oO + o0oOo00 )
  if 10 - 10: OoO0O00 . I1IiiI . I11i / i11iIiiIii - ooOoO0o
  if 41 - 41: I11i / iIii1I11I1II1 . i11iIiiIii . i1IIi * iIii1I11I1II1 * OOooOOo
 def decode ( self , packet ) :
  if 5 - 5: O0 - oO0o - i11iIiiIii
  if 8 - 8: I1IiiI / iIii1I11I1II1 / OoooooooOO / Oo0Ooo / ooOoO0o
  if 80 - 80: I11i
  if 26 - 26: II111iiii + I1IiiI . II111iiii - oO0o % OoO0O00
  O00oO00oOO00O = "I"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 1 - 1: OoO0O00 - II111iiii
  ooo0OOoo = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 75 - 75: Oo0Ooo - OoOoOO00 + oO0o % i1IIi * OOooOOo
  ooo0OOoo = socket . ntohl ( ooo0OOoo [ 0 ] )
  self . security = True if ( ooo0OOoo & 0x08000000 ) else False
  self . ddt = True if ( ooo0OOoo & 0x04000000 ) else False
  self . to_etr = True if ( ooo0OOoo & 0x02000000 ) else False
  self . to_ms = True if ( ooo0OOoo & 0x01000000 ) else False
  packet = packet [ ooOoooOoo0oO : : ]
  if 56 - 56: OoOoOO00 / OoO0O00 / I1IiiI % OoooooooOO
  if 39 - 39: I1IiiI + II111iiii * Oo0Ooo % Ii1I . o0oOOo0O0Ooo * oO0o
  if 42 - 42: Ii1I / Oo0Ooo
  if 25 - 25: OoooooooOO % Ii1I * I1Ii111 * I11i + I1IiiI % I1ii11iIi11i
  if ( len ( packet ) < 1 ) : return ( None )
  IiiI1Ii1II = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  IiiI1Ii1II = IiiI1Ii1II >> 4
  if 70 - 70: Ii1I + I1ii11iIi11i * I11i * i1IIi . I1Ii111
  if ( IiiI1Ii1II == 4 ) :
   ooOoooOoo0oO = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
   if 76 - 76: OoooooooOO * OoOoOO00 . OoooooooOO
   I11Iii1iIII1i , I1111III111ii , I11Iii1iIII1i , ooOOO000 , III1I1Iii1 , Ooo0OO00oo = struct . unpack ( "HHIBBH" , packet [ : ooOoooOoo0oO ] )
   self . length = socket . ntohs ( I1111III111ii )
   self . ttl = ooOOO000
   self . protocol = III1I1Iii1
   self . ip_checksum = socket . ntohs ( Ooo0OO00oo )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 8 - 8: IiII
   if 68 - 68: IiII . OoooooooOO - i11iIiiIii + i11iIiiIii
   if 81 - 81: OoOoOO00 + iII111i . i11iIiiIii
   if 10 - 10: OoOoOO00 + I11i - iIii1I11I1II1 - I11i
   III1I1Iii1 = struct . pack ( "H" , 0 )
   o0Oo00OoO000O = struct . calcsize ( "HHIBB" )
   II1iii = struct . calcsize ( "H" )
   packet = packet [ : o0Oo00OoO000O ] + III1I1Iii1 + packet [ o0Oo00OoO000O + II1iii : ]
   if 94 - 94: IiII - Oo0Ooo . o0oOOo0O0Ooo - ooOoO0o - oO0o . I11i
   packet = packet [ ooOoooOoo0oO : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 39 - 39: oO0o + OoOoOO00
   if 68 - 68: i1IIi * oO0o / i11iIiiIii
  if ( IiiI1Ii1II == 6 ) :
   ooOoooOoo0oO = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
   if 96 - 96: I1IiiI
   I11Iii1iIII1i , I1111III111ii , III1I1Iii1 , ooOOO000 = struct . unpack ( "IHBB" , packet [ : ooOoooOoo0oO ] )
   self . length = socket . ntohs ( I1111III111ii )
   self . protocol = III1I1Iii1
   self . ttl = ooOOO000
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 78 - 78: OoO0O00
   packet = packet [ ooOoooOoo0oO : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 72 - 72: I1ii11iIi11i / O0 % II111iiii / II111iiii
   if 48 - 48: OOooOOo % OOooOOo / iIii1I11I1II1 - i11iIiiIii
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 57 - 57: I11i / IiII * i1IIi + II111iiii . o0oOOo0O0Ooo
  ooOoooOoo0oO = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 11 - 11: II111iiii
  IiII1iiI , OooOOOoOoo0O0 , I1111III111ii , Ooo0OO00oo = struct . unpack ( "HHHH" , packet [ : ooOoooOoo0oO ] )
  self . udp_sport = socket . ntohs ( IiII1iiI )
  self . udp_dport = socket . ntohs ( OooOOOoOoo0O0 )
  self . udp_length = socket . ntohs ( I1111III111ii )
  self . udp_checksum = socket . ntohs ( Ooo0OO00oo )
  packet = packet [ ooOoooOoo0oO : : ]
  return ( packet )
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
  if 49 - 49: I1IiiI * iII111i - OoO0O00 % Ii1I + Ii1I * I1Ii111
  if 94 - 94: OoOoOO00 - I11i + Ii1I + OoOoOO00 + II111iiii
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  O0o0oO = self . rloc_name
  if ( cour ) : O0o0oO = lisp_print_cour ( O0o0oO )
  return ( 'rloc-name: {}' . format ( blue ( O0o0oO , cour ) ) )
  if 37 - 37: iII111i
  if 29 - 29: OOooOOo
 def print_record ( self , indent ) :
  o0O00oo0O = self . print_rloc_name ( )
  if ( o0O00oo0O != "" ) : o0O00oo0O = ", " + o0O00oo0O
  oO0o0O0oOoo = ""
  if ( self . geo ) :
   oooO = ""
   if ( self . geo . geo_name ) : oooO = "'{}' " . format ( self . geo . geo_name )
   oO0o0O0oOoo = ", geo: {}{}" . format ( oooO , self . geo . print_geo ( ) )
   if 65 - 65: I1Ii111
  Ii1oo = ""
  if ( self . elp ) :
   oooO = ""
   if ( self . elp . elp_name ) : oooO = "'{}' " . format ( self . elp . elp_name )
   Ii1oo = ", elp: {}{}" . format ( oooO , self . elp . print_elp ( True ) )
   if 41 - 41: OOooOOo % I1Ii111 * IiII - I1Ii111
  i1I1IiII = ""
  if ( self . rle ) :
   oooO = ""
   if ( self . rle . rle_name ) : oooO = "'{}' " . format ( self . rle . rle_name )
   i1I1IiII = ", rle: {}{}" . format ( oooO , self . rle . print_rle ( False ,
 True ) )
   if 10 - 10: IiII / o0oOOo0O0Ooo
  I1ii1i1IiIIi = ""
  if ( self . json ) :
   oooO = ""
   if ( self . json . json_name ) :
    oooO = "'{}' " . format ( self . json . json_name )
    if 52 - 52: II111iiii - IiII
   I1ii1i1IiIIi = ", json: {}" . format ( self . json . print_json ( False ) )
   if 91 - 91: iIii1I11I1II1 + iII111i . I11i % i11iIiiIii - i11iIiiIii + I1IiiI
   if 75 - 75: I1ii11iIi11i / I1IiiI - iIii1I11I1II1 / OoO0O00 * OOooOOo
  Ooo000O00o = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   Ooo000O00o = ", " + self . keys [ 1 ] . print_keys ( )
   if 2 - 2: i11iIiiIii . iII111i . O0 - iIii1I11I1II1 + I1Ii111 . IiII
   if 54 - 54: o0oOOo0O0Ooo
  oOOo0ooO0 = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( oOOo0ooO0 . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , o0O00oo0O , oO0o0O0oOoo ,
 Ii1oo , i1I1IiII , I1ii1i1IiIIi , Ooo000O00o ) )
  if 99 - 99: II111iiii % I1IiiI
  if 89 - 89: OOooOOo / i1IIi - I11i * oO0o
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 42 - 42: Ii1I
  if 40 - 40: o0oOOo0O0Ooo - iIii1I11I1II1 % oO0o . o0oOOo0O0Ooo
  if 35 - 35: I1IiiI % OOooOOo + OoOoOO00 / I1IiiI . O0 % iII111i
 def store_rloc_entry ( self , rloc_entry ) :
  oOo0o0 = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 44 - 44: oO0o - iIii1I11I1II1 / ooOoO0o - iIii1I11I1II1 % i1IIi + ooOoO0o
  self . rloc . copy_address ( oOo0o0 )
  if 74 - 74: I11i . OoOoOO00 + OoOoOO00
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 87 - 87: IiII + o0oOOo0O0Ooo . i1IIi % I1Ii111
   if 44 - 44: Oo0Ooo - OOooOOo . Ii1I * OoooooooOO
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   oooO = rloc_entry . geo_name
   if ( oooO and lisp_geo_list . has_key ( oooO ) ) :
    self . geo = lisp_geo_list [ oooO ]
    if 93 - 93: OoO0O00 . OoO0O00
    if 52 - 52: OOooOOo . oO0o / Oo0Ooo . OoooooooOO % I1ii11iIi11i
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   oooO = rloc_entry . elp_name
   if ( oooO and lisp_elp_list . has_key ( oooO ) ) :
    self . elp = lisp_elp_list [ oooO ]
    if 65 - 65: ooOoO0o % II111iiii . iII111i - iIii1I11I1II1 - I1IiiI
    if 63 - 63: I1IiiI . OoOoOO00 - II111iiii
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   oooO = rloc_entry . rle_name
   if ( oooO and lisp_rle_list . has_key ( oooO ) ) :
    self . rle = lisp_rle_list [ oooO ]
    if 55 - 55: ooOoO0o - o0oOOo0O0Ooo
    if 32 - 32: I1Ii111 * Ii1I / I1Ii111 . OoOoOO00 + I1ii11iIi11i - ooOoO0o
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   oooO = rloc_entry . json_name
   if ( oooO and lisp_json_list . has_key ( oooO ) ) :
    self . json = lisp_json_list [ oooO ]
    if 14 - 14: IiII * O0 + O0 - ooOoO0o . i11iIiiIii - IiII
    if 37 - 37: I11i
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 19 - 19: OoooooooOO % I1Ii111
  if 57 - 57: OoOoOO00 + i1IIi . iIii1I11I1II1 . iIii1I11I1II1 / iIii1I11I1II1 % oO0o
 def encode_json ( self , json_string ) :
  O000oo0O0OO0 = LISP_LCAF_JSON_TYPE
  O00000oooOO = socket . htons ( LISP_AFI_LCAF )
  IiiI1III1i1I = self . rloc . addr_length ( ) + 2
  if 22 - 22: I1ii11iIi11i
  iI11iiI1 = socket . htons ( len ( json_string ) + IiiI1III1i1I )
  if 39 - 39: ooOoO0o . i11iIiiIii - II111iiii . Oo0Ooo / iIii1I11I1II1 % I11i
  I1Ioo000oooooooO = socket . htons ( len ( json_string ) )
  IIii1i = struct . pack ( "HBBBBHH" , O00000oooOO , 0 , 0 , O000oo0O0OO0 , 0 , iI11iiI1 ,
 I1Ioo000oooooooO )
  IIii1i += json_string
  if 58 - 58: Ii1I + ooOoO0o - OOooOOo
  if 33 - 33: iII111i % I1IiiI % ooOoO0o * OoO0O00 + OoOoOO00 % i11iIiiIii
  if 39 - 39: Oo0Ooo % I1Ii111 / I1IiiI / Oo0Ooo . o0oOOo0O0Ooo + o0oOOo0O0Ooo
  if 83 - 83: OoooooooOO * II111iiii % OoooooooOO
  if ( lisp_is_json_telemetry ( json_string ) ) :
   IIii1i += struct . pack ( "H" , socket . htons ( self . rloc . afi ) )
   IIii1i += self . rloc . pack_address ( )
  else :
   IIii1i += struct . pack ( "H" , 0 )
   if 30 - 30: I1Ii111 / o0oOOo0O0Ooo + OoooooooOO + OoOoOO00 + OoO0O00
  return ( IIii1i )
  if 40 - 40: OoooooooOO / IiII
  if 82 - 82: i11iIiiIii - oO0o - i1IIi
 def encode_lcaf ( self ) :
  O00000oooOO = socket . htons ( LISP_AFI_LCAF )
  OOo0oo0OOOO = ""
  if ( self . geo ) :
   OOo0oo0OOOO = self . geo . encode_geo ( )
   if 36 - 36: I1IiiI % ooOoO0o . OoooooooOO . OoOoOO00 / I11i
   if 1 - 1: I1Ii111 / Ii1I % I1ii11iIi11i
  oOo0oO000oOo = ""
  if ( self . elp ) :
   iiii1i1iiIiI1 = ""
   for i11iiIi11iiIIi1I in self . elp . elp_nodes :
    O000oOOoOOO = socket . htons ( i11iiIi11iiIIi1I . address . afi )
    II1iII1IIIIi = 0
    if ( i11iiIi11iiIIi1I . eid ) : II1iII1IIIIi |= 0x4
    if ( i11iiIi11iiIIi1I . probe ) : II1iII1IIIIi |= 0x2
    if ( i11iiIi11iiIIi1I . strict ) : II1iII1IIIIi |= 0x1
    II1iII1IIIIi = socket . htons ( II1iII1IIIIi )
    iiii1i1iiIiI1 += struct . pack ( "HH" , II1iII1IIIIi , O000oOOoOOO )
    iiii1i1iiIiI1 += i11iiIi11iiIIi1I . address . pack_address ( )
    if 19 - 19: I1ii11iIi11i / Oo0Ooo * OoooooooOO
    if 67 - 67: O0
   i1Ii = socket . htons ( len ( iiii1i1iiIiI1 ) )
   oOo0oO000oOo = struct . pack ( "HBBBBH" , O00000oooOO , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , i1Ii )
   oOo0oO000oOo += iiii1i1iiIiI1
   if 96 - 96: ooOoO0o % Ii1I
   if 83 - 83: I1IiiI - OOooOOo . I1IiiI * Oo0Ooo
  oo0oo0O = ""
  if ( self . rle ) :
   i1iiiI = ""
   for O00oo0ooo0O in self . rle . rle_nodes :
    O000oOOoOOO = socket . htons ( O00oo0ooo0O . address . afi )
    i1iiiI += struct . pack ( "HBBH" , 0 , 0 , O00oo0ooo0O . level , O000oOOoOOO )
    i1iiiI += O00oo0ooo0O . address . pack_address ( )
    if ( O00oo0ooo0O . rloc_name ) :
     i1iiiI += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     i1iiiI += O00oo0ooo0O . rloc_name + "\0"
     if 40 - 40: oO0o
     if 6 - 6: iII111i . Ii1I / oO0o / I1IiiI
     if 8 - 8: I1IiiI * I1IiiI . I1ii11iIi11i - iII111i . I1Ii111
   o000 = socket . htons ( len ( i1iiiI ) )
   oo0oo0O = struct . pack ( "HBBBBH" , O00000oooOO , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , o000 )
   oo0oo0O += i1iiiI
   if 22 - 22: o0oOOo0O0Ooo % ooOoO0o - I1IiiI / OOooOOo * OOooOOo
   if 6 - 6: OoO0O00 % IiII + iIii1I11I1II1
  IiIoOo0ooo = ""
  if ( self . json ) :
   IiIoOo0ooo = self . encode_json ( self . json . json_string )
   if 26 - 26: I11i - i1IIi - Oo0Ooo * O0 * OOooOOo . OoooooooOO
   if 99 - 99: oO0o . OoO0O00 / OOooOOo
  Ii1111i = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   Ii1111i = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 17 - 17: OoO0O00
   if 69 - 69: O0
  ooOoOoooO = ""
  if ( self . rloc_name ) :
   ooOoOoooO += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   ooOoOoooO += self . rloc_name + "\0"
   if 78 - 78: i11iIiiIii
   if 14 - 14: i11iIiiIii + I1IiiI - oO0o - I11i
  iii1i = len ( OOo0oo0OOOO ) + len ( oOo0oO000oOo ) + len ( oo0oo0O ) + len ( Ii1111i ) + 2 + len ( IiIoOo0ooo ) + self . rloc . addr_length ( ) + len ( ooOoOoooO )
  if 78 - 78: i1IIi % oO0o + IiII
  iii1i = socket . htons ( iii1i )
  ooOOOO = struct . pack ( "HBBBBHH" , O00000oooOO , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , iii1i , socket . htons ( self . rloc . afi ) )
  ooOOOO += self . rloc . pack_address ( )
  return ( ooOOOO + ooOoOoooO + OOo0oo0OOOO + oOo0oO000oOo + oo0oo0O + Ii1111i + IiIoOo0ooo )
  if 24 - 24: oO0o / i1IIi % OOooOOo + II111iiii % O0
  if 72 - 72: Ii1I
 def encode ( self ) :
  II1iII1IIIIi = 0
  if ( self . local_bit ) : II1iII1IIIIi |= 0x0004
  if ( self . probe_bit ) : II1iII1IIIIi |= 0x0002
  if ( self . reach_bit ) : II1iII1IIIIi |= 0x0001
  if 55 - 55: O0
  IIii1i = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( II1iII1IIIIi ) ,
 socket . htons ( self . rloc . afi ) )
  if 25 - 25: OoooooooOO . Ii1I . i1IIi . Oo0Ooo
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 11 - 11: O0 . o0oOOo0O0Ooo
   IIii1i = IIii1i [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   IIii1i += self . rloc . pack_address ( )
   if 55 - 55: i11iIiiIii / OoooooooOO - I11i
  return ( IIii1i )
  if 89 - 89: I11i - i1IIi - i1IIi * OOooOOo - O0
  if 94 - 94: Oo0Ooo / I11i . I1ii11iIi11i
 def decode_lcaf ( self , packet , nonce ) :
  O00oO00oOO00O = "HBBBBH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 31 - 31: i11iIiiIii + iIii1I11I1II1 . II111iiii
  O000oOOoOOO , oO00OO0Ooo00O , II1iII1IIIIi , O000oo0O0OO0 , oOOooo00 , iI11iiI1 = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 72 - 72: I1Ii111 * OoO0O00 + Oo0Ooo / Ii1I % OOooOOo
  if 84 - 84: OoOoOO00 / o0oOOo0O0Ooo
  iI11iiI1 = socket . ntohs ( iI11iiI1 )
  packet = packet [ ooOoooOoo0oO : : ]
  if ( iI11iiI1 > len ( packet ) ) : return ( None )
  if 9 - 9: Ii1I
  if 76 - 76: I1IiiI % Oo0Ooo / iIii1I11I1II1 - Oo0Ooo
  if 34 - 34: OoOoOO00 - i1IIi + OOooOOo + Ii1I . o0oOOo0O0Ooo
  if 42 - 42: OoO0O00
  if ( O000oo0O0OO0 == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( iI11iiI1 > 0 ) :
    O00oO00oOO00O = "H"
    ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
    if ( iI11iiI1 < ooOoooOoo0oO ) : return ( None )
    if 59 - 59: OoO0O00 . I1Ii111 % OoO0O00
    o00OO00OOo0 = len ( packet )
    O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
    O000oOOoOOO = socket . ntohs ( O000oOOoOOO )
    if 22 - 22: Oo0Ooo
    if ( O000oOOoOOO == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ ooOoooOoo0oO : : ]
     self . rloc_name = None
     if ( O000oOOoOOO == LISP_AFI_NAME ) :
      packet , O0o0oO = lisp_decode_dist_name ( packet )
      self . rloc_name = O0o0oO
     else :
      self . rloc . afi = O000oOOoOOO
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 21 - 21: o0oOOo0O0Ooo
      if 86 - 86: ooOoO0o / iIii1I11I1II1 . OOooOOo
      if 93 - 93: Oo0Ooo / II111iiii . Oo0Ooo + i1IIi + i1IIi
    iI11iiI1 -= o00OO00OOo0 - len ( packet )
    if 30 - 30: OoOoOO00 . OOooOOo % OOooOOo / II111iiii + i1IIi
    if 61 - 61: i1IIi % II111iiii * II111iiii . o0oOOo0O0Ooo / I1ii11iIi11i - I1Ii111
  elif ( O000oo0O0OO0 == LISP_LCAF_GEO_COORD_TYPE ) :
   if 93 - 93: Ii1I - i1IIi
   if 3 - 3: oO0o + OoO0O00 - iII111i / Ii1I
   if 58 - 58: Ii1I * I11i
   if 95 - 95: oO0o
   iii1iOoOooOOo = lisp_geo ( "" )
   packet = iii1iOoOooOOo . decode_geo ( packet , iI11iiI1 , oOOooo00 )
   if ( packet == None ) : return ( None )
   self . geo = iii1iOoOooOOo
   if 54 - 54: ooOoO0o - O0 + iII111i
  elif ( O000oo0O0OO0 == LISP_LCAF_JSON_TYPE ) :
   if 34 - 34: Ii1I - OOooOOo % iII111i
   if 48 - 48: oO0o - O0
   if 17 - 17: iIii1I11I1II1 . IiII / ooOoO0o % I11i + o0oOOo0O0Ooo - iIii1I11I1II1
   if 95 - 95: OoOoOO00 + OOooOOo - I11i * i1IIi + i1IIi * O0
   O00oO00oOO00O = "H"
   ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
   if ( iI11iiI1 < ooOoooOoo0oO ) : return ( None )
   if 60 - 60: Oo0Ooo + I11i % iIii1I11I1II1 % oO0o - I1Ii111 / o0oOOo0O0Ooo
   I1Ioo000oooooooO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
   I1Ioo000oooooooO = socket . ntohs ( I1Ioo000oooooooO )
   if ( iI11iiI1 < ooOoooOoo0oO + I1Ioo000oooooooO ) : return ( None )
   if 9 - 9: IiII / oO0o % O0 * I1Ii111 - iIii1I11I1II1 % i1IIi
   packet = packet [ ooOoooOoo0oO : : ]
   self . json = lisp_json ( "" , packet [ 0 : I1Ioo000oooooooO ] )
   packet = packet [ I1Ioo000oooooooO : : ]
   if 83 - 83: OoOoOO00 + OOooOOo / OoooooooOO
   if 39 - 39: OoO0O00 % iII111i . oO0o . II111iiii - i11iIiiIii
   if 85 - 85: O0 - OoOoOO00
   if 17 - 17: o0oOOo0O0Ooo / i1IIi / OOooOOo
   O000oOOoOOO = socket . ntohs ( struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ] )
   packet = packet [ 2 : : ]
   if 91 - 91: I1ii11iIi11i / Ii1I - OoOoOO00 . I11i / oO0o
   if ( O000oOOoOOO != 0 and lisp_is_json_telemetry ( self . json . json_string ) ) :
    self . rloc . afi = O000oOOoOOO
    packet = self . rloc . unpack_address ( packet )
    if 16 - 16: IiII % iII111i . oO0o . I1IiiI % O0 * I11i
    if 99 - 99: OoOoOO00 / OoooooooOO + iII111i * I11i * i11iIiiIii + OOooOOo
  elif ( O000oo0O0OO0 == LISP_LCAF_ELP_TYPE ) :
   if 40 - 40: II111iiii / I11i % I1IiiI - O0
   if 39 - 39: i11iIiiIii - OoOoOO00 % OOooOOo + ooOoO0o + i11iIiiIii
   if 59 - 59: IiII / OoOoOO00 - I1Ii111 - ooOoO0o . oO0o
   if 87 - 87: oO0o + I1IiiI * I1Ii111 * o0oOOo0O0Ooo + O0
   I1IIiIi = lisp_elp ( None )
   I1IIiIi . elp_nodes = [ ]
   while ( iI11iiI1 > 0 ) :
    II1iII1IIIIi , O000oOOoOOO = struct . unpack ( "HH" , packet [ : 4 ] )
    if 30 - 30: I1Ii111
    O000oOOoOOO = socket . ntohs ( O000oOOoOOO )
    if ( O000oOOoOOO == LISP_AFI_LCAF ) : return ( None )
    if 31 - 31: I11i - O0 * IiII - iII111i
    i11iiIi11iiIIi1I = lisp_elp_node ( )
    I1IIiIi . elp_nodes . append ( i11iiIi11iiIIi1I )
    if 23 - 23: I1Ii111 + i1IIi / I1Ii111 / o0oOOo0O0Ooo . oO0o
    II1iII1IIIIi = socket . ntohs ( II1iII1IIIIi )
    i11iiIi11iiIIi1I . eid = ( II1iII1IIIIi & 0x4 )
    i11iiIi11iiIIi1I . probe = ( II1iII1IIIIi & 0x2 )
    i11iiIi11iiIIi1I . strict = ( II1iII1IIIIi & 0x1 )
    i11iiIi11iiIIi1I . address . afi = O000oOOoOOO
    i11iiIi11iiIIi1I . address . mask_len = i11iiIi11iiIIi1I . address . host_mask_len ( )
    packet = i11iiIi11iiIIi1I . address . unpack_address ( packet [ 4 : : ] )
    iI11iiI1 -= i11iiIi11iiIIi1I . address . addr_length ( ) + 4
    if 32 - 32: ooOoO0o / IiII
   I1IIiIi . select_elp_node ( )
   self . elp = I1IIiIi
   if 28 - 28: OoooooooOO % iII111i / i11iIiiIii % OoO0O00 - Oo0Ooo
  elif ( O000oo0O0OO0 == LISP_LCAF_RLE_TYPE ) :
   if 90 - 90: OOooOOo
   if 52 - 52: OoO0O00 * oO0o / iIii1I11I1II1 - OoOoOO00
   if 20 - 20: IiII % I1IiiI + iIii1I11I1II1 % iII111i
   if 100 - 100: o0oOOo0O0Ooo - Oo0Ooo % I1Ii111 . i11iIiiIii % OoooooooOO
   i1I1Ii11II1i = lisp_rle ( None )
   i1I1Ii11II1i . rle_nodes = [ ]
   while ( iI11iiI1 > 0 ) :
    I11Iii1iIII1i , II1ioOO0Oo , iIIi , O000oOOoOOO = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 7 - 7: OoooooooOO % iII111i % Ii1I % II111iiii / oO0o
    O000oOOoOOO = socket . ntohs ( O000oOOoOOO )
    if ( O000oOOoOOO == LISP_AFI_LCAF ) : return ( None )
    if 15 - 15: OoO0O00
    O00oo0ooo0O = lisp_rle_node ( )
    i1I1Ii11II1i . rle_nodes . append ( O00oo0ooo0O )
    if 18 - 18: OoooooooOO / OOooOOo % i1IIi - i1IIi / Oo0Ooo
    O00oo0ooo0O . level = iIIi
    O00oo0ooo0O . address . afi = O000oOOoOOO
    O00oo0ooo0O . address . mask_len = O00oo0ooo0O . address . host_mask_len ( )
    packet = O00oo0ooo0O . address . unpack_address ( packet [ 6 : : ] )
    if 94 - 94: I1Ii111 + i11iIiiIii / iII111i + OoooooooOO % i1IIi
    iI11iiI1 -= O00oo0ooo0O . address . addr_length ( ) + 6
    if ( iI11iiI1 >= 2 ) :
     O000oOOoOOO = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( O000oOOoOOO ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , O00oo0ooo0O . rloc_name = lisp_decode_dist_name ( packet )
      if 57 - 57: iIii1I11I1II1 - i11iIiiIii / II111iiii
      if ( packet == None ) : return ( None )
      iI11iiI1 -= len ( O00oo0ooo0O . rloc_name ) + 1 + 2
      if 35 - 35: I1IiiI - IiII * I1Ii111 - ooOoO0o % oO0o
      if 88 - 88: IiII * OoO0O00 / IiII * I1IiiI + O0 / IiII
      if 41 - 41: OoOoOO00
   self . rle = i1I1Ii11II1i
   self . rle . build_forwarding_list ( )
   if 81 - 81: Ii1I . I1IiiI % o0oOOo0O0Ooo . OoOoOO00
  elif ( O000oo0O0OO0 == LISP_LCAF_SECURITY_TYPE ) :
   if 94 - 94: oO0o % Oo0Ooo + OoO0O00 * oO0o - i11iIiiIii / I11i
   if 46 - 46: IiII - OoO0O00 * iII111i . I1Ii111 - ooOoO0o . i1IIi
   if 53 - 53: I1Ii111 * I1IiiI + Oo0Ooo + I1IiiI + OOooOOo
   if 8 - 8: i11iIiiIii + OoOoOO00 . I1ii11iIi11i / OoooooooOO % II111iiii
   if 21 - 21: oO0o - o0oOOo0O0Ooo + ooOoO0o . I1IiiI * oO0o * Ii1I
   OO0o0 = packet
   IIii1Iiii1iiI = lisp_keys ( 1 )
   packet = IIii1Iiii1iiI . decode_lcaf ( OO0o0 , iI11iiI1 )
   if ( packet == None ) : return ( None )
   if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
   if 8 - 8: OoooooooOO - OoO0O00 / i11iIiiIii / O0 . IiII
   if 86 - 86: ooOoO0o * OoooooooOO + iII111i + o0oOOo0O0Ooo
   if 79 - 79: i1IIi % I1ii11iIi11i - OoO0O00 % I1ii11iIi11i
   Iii = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( IIii1Iiii1iiI . cipher_suite in Iii ) :
    if ( IIii1Iiii1iiI . cipher_suite == LISP_CS_25519_CBC ) :
     ii1i1I1111ii = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 6 - 6: Oo0Ooo / iII111i . i11iIiiIii
    if ( IIii1Iiii1iiI . cipher_suite == LISP_CS_25519_CHACHA ) :
     ii1i1I1111ii = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 8 - 8: I1ii11iIi11i + O0 - oO0o % II111iiii . I1Ii111
   else :
    ii1i1I1111ii = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 86 - 86: IiII
   packet = ii1i1I1111ii . decode_lcaf ( OO0o0 , iI11iiI1 )
   if ( packet == None ) : return ( None )
   if 71 - 71: Ii1I - i1IIi . I1IiiI
   if ( len ( packet ) < 2 ) : return ( None )
   O000oOOoOOO = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( O000oOOoOOO )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
   if 54 - 54: i1IIi . OoO0O00 + iII111i + OoO0O00 * i1IIi
   if 13 - 13: Oo0Ooo / OoO0O00 + OOooOOo
   if 90 - 90: OoO0O00 * i11iIiiIii / oO0o
   if 91 - 91: iII111i - OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
   if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 25 - 25: OoOoOO00 + IiII . i11iIiiIii
   ooOooo = self . rloc_name
   if ( ooOooo ) : ooOooo = blue ( self . rloc_name , False )
   if 48 - 48: O0 % I1ii11iIi11i
   if 79 - 79: IiII . Ii1I % Oo0Ooo + o0oOOo0O0Ooo
   if 25 - 25: i1IIi / ooOoO0o
   if 81 - 81: i1IIi + I1Ii111 * iIii1I11I1II1 * OoO0O00
   if 99 - 99: OOooOOo * ooOoO0o . i11iIiiIii / ooOoO0o
   if 74 - 74: I11i
   I1I1iI = self . keys [ 1 ] if self . keys else None
   if ( I1I1iI == None ) :
    if ( ii1i1I1111ii . remote_public_key == None ) :
     iI = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( iI , ooOooo ) )
     ii1i1I1111ii = None
    else :
     iI = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( iI , ooOooo ) )
     ii1i1I1111ii . compute_shared_key ( "encap" )
     if 82 - 82: Oo0Ooo % O0 + I1ii11iIi11i % I1ii11iIi11i
     if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
     if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
     if 29 - 29: Oo0Ooo - Ii1I - Oo0Ooo
     if 89 - 89: Oo0Ooo . OoO0O00 . I1ii11iIi11i * oO0o . O0
     if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
     if 69 - 69: I1Ii111 + O0 . IiII . o0oOOo0O0Ooo
     if 38 - 38: IiII / i1IIi
     if 60 - 60: OoOoOO00
     if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
   if ( I1I1iI ) :
    if ( ii1i1I1111ii . remote_public_key == None ) :
     ii1i1I1111ii = None
     I1iIIiI = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( I1iIIiI , ooOooo ) )
    elif ( I1I1iI . compare_keys ( ii1i1I1111ii ) ) :
     ii1i1I1111ii = I1I1iI
     lprint ( "    Maintain stored encap-keys for {}" . format ( ooOooo ) )
     if 61 - 61: IiII . IiII
    else :
     if ( I1I1iI . remote_public_key == None ) :
      iI = "New encap-keying for existing state"
     else :
      iI = "Remote encap-rekeying"
      if 17 - 17: OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
     lprint ( "    {} for {}" . format ( bold ( iI , False ) ,
 ooOooo ) )
     I1I1iI . remote_public_key = ii1i1I1111ii . remote_public_key
     I1I1iI . compute_shared_key ( "encap" )
     ii1i1I1111ii = I1I1iI
     if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
     if 95 - 95: iII111i / ooOoO0o + I1Ii111
   self . keys = [ None , ii1i1I1111ii , None , None ]
   if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
  else :
   if 81 - 81: I1ii11iIi11i
   if 31 - 31: O0 % ooOoO0o / I1IiiI * iII111i % iIii1I11I1II1 * OoOoOO00
   if 76 - 76: I1Ii111 - O0
   if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
   packet = packet [ iI11iiI1 : : ]
   if 7 - 7: II111iiii + I11i
  return ( packet )
  if 99 - 99: iIii1I11I1II1 * oO0o
  if 37 - 37: ooOoO0o * iII111i * I11i
 def decode ( self , packet , nonce ) :
  O00oO00oOO00O = "BBBBHH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 11 - 11: I1IiiI
  self . priority , self . weight , self . mpriority , self . mweight , II1iII1IIIIi , O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 48 - 48: O0 . I11i
  if 9 - 9: oO0o / Oo0Ooo
  II1iII1IIIIi = socket . ntohs ( II1iII1IIIIi )
  O000oOOoOOO = socket . ntohs ( O000oOOoOOO )
  self . local_bit = True if ( II1iII1IIIIi & 0x0004 ) else False
  self . probe_bit = True if ( II1iII1IIIIi & 0x0002 ) else False
  self . reach_bit = True if ( II1iII1IIIIi & 0x0001 ) else False
  if 85 - 85: i11iIiiIii / I1IiiI . OoO0O00 . I11i . oO0o * IiII
  if ( O000oOOoOOO == LISP_AFI_LCAF ) :
   packet = packet [ ooOoooOoo0oO - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce )
  else :
   self . rloc . afi = O000oOOoOOO
   packet = packet [ ooOoooOoo0oO : : ]
   packet = self . rloc . unpack_address ( packet )
   if 41 - 41: Ii1I / OoO0O00 / OoO0O00 * I11i
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 31 - 31: Ii1I / OoooooooOO % iIii1I11I1II1 - IiII * I1IiiI - O0
  if 31 - 31: oO0o
 def end_of_rlocs ( self , packet , rloc_count ) :
  for IiIIi1IiiIiI in range ( rloc_count ) :
   packet = self . decode ( packet , None )
   if ( packet == None ) : return ( None )
   if 74 - 74: OoO0O00
  return ( packet )
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
  if 79 - 79: I1Ii111 - I11i
  if 49 - 49: II111iiii + O0 * ooOoO0o - Oo0Ooo
  if 89 - 89: I1IiiI + I11i . oO0o . II111iiii + oO0o / Oo0Ooo
  if 32 - 32: OoO0O00 % oO0o * I1ii11iIi11i + I11i / I1Ii111
  if 5 - 5: o0oOOo0O0Ooo + iII111i / OoooooooOO + Ii1I . OoOoOO00 / oO0o
class lisp_map_referral ( ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 18 - 18: II111iiii . o0oOOo0O0Ooo
  if 75 - 75: OoooooooOO - Oo0Ooo
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # o0oOOo0O0Ooo - OOooOOo / O0 . oO0o
 lisp_hex_string ( self . nonce ) ) )
  if 51 - 51: i11iIiiIii
  if 21 - 21: O0 - IiII * i1IIi + o0oOOo0O0Ooo % I11i + iIii1I11I1II1
 def encode ( self ) :
  ooo0OOoo = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  IIii1i = struct . pack ( "I" , socket . htonl ( ooo0OOoo ) )
  IIii1i += struct . pack ( "Q" , self . nonce )
  return ( IIii1i )
  if 35 - 35: i11iIiiIii + i1IIi
  if 16 - 16: OoO0O00 - I1Ii111 * iII111i
 def decode ( self , packet ) :
  O00oO00oOO00O = "I"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 41 - 41: i11iIiiIii + i1IIi / IiII * I1ii11iIi11i / iIii1I11I1II1
  ooo0OOoo = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  ooo0OOoo = socket . ntohl ( ooo0OOoo [ 0 ] )
  self . record_count = ooo0OOoo & 0xff
  packet = packet [ ooOoooOoo0oO : : ]
  if 70 - 70: I1IiiI % oO0o + iII111i % i11iIiiIii + ooOoO0o
  O00oO00oOO00O = "Q"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 88 - 88: I11i * oO0o * I1ii11iIi11i - OOooOOo * IiII + o0oOOo0O0Ooo
  self . nonce = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  return ( packet )
  if 9 - 9: OoooooooOO
  if 26 - 26: OoOoOO00 + II111iiii - OoO0O00 + iII111i - iII111i % O0
  if 79 - 79: iIii1I11I1II1 - OoOoOO00 - O0 + I1ii11iIi11i
  if 69 - 69: oO0o % OoooooooOO
  if 21 - 21: I1Ii111
  if 62 - 62: Ii1I % o0oOOo0O0Ooo
  if 65 - 65: OoO0O00 + Oo0Ooo + IiII / OoOoOO00
  if 37 - 37: oO0o - I11i
class lisp_ddt_entry ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 64 - 64: OoO0O00 * OoOoOO00
  if 50 - 50: I1ii11iIi11i + I11i * iII111i
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 27 - 27: OoOoOO00 * OOooOOo * iIii1I11I1II1 / i1IIi
  if 60 - 60: OOooOOo * I1Ii111 . oO0o
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
  if 51 - 51: I1IiiI . I11i - OoOoOO00
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  IIiIi1I1Ii11 = self . delegation_set [ 0 ]
  return ( IIiIi1I1Ii11 . print_node_type ( ) )
  if 79 - 79: I1ii11iIi11i + Oo0Ooo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo * I1Ii111
  if 63 - 63: OoooooooOO
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 17 - 17: Ii1I % oO0o
  if 45 - 45: II111iiii + iII111i
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   oo00O00ooO = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( oo00O00ooO == None ) :
    oo00O00ooO = lisp_ddt_entry ( )
    oo00O00ooO . eid . copy_address ( self . group )
    oo00O00ooO . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , oo00O00ooO )
    if 72 - 72: o0oOOo0O0Ooo * I1Ii111 / Ii1I + i11iIiiIii
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( oo00O00ooO . group )
   oo00O00ooO . add_source_entry ( self )
   if 47 - 47: iIii1I11I1II1 % O0
   if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
   if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
  if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 46 - 46: o0oOOo0O0Ooo
  if 28 - 28: i1IIi
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
  if 62 - 62: I1Ii111 * I11i / I11i
  if 42 - 42: ooOoO0o * ooOoO0o / Ii1I / OOooOOo * OOooOOo
class lisp_ddt_node ( ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 92 - 92: Oo0Ooo / iII111i - OoooooooOO - o0oOOo0O0Ooo % ooOoO0o
  if 35 - 35: i1IIi % iII111i % I11i * iIii1I11I1II1 % Ii1I - Oo0Ooo
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 94 - 94: iII111i
  if 68 - 68: OoooooooOO % OOooOOo / OoooooooOO / I1Ii111 + Ii1I - o0oOOo0O0Ooo
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 81 - 81: I1IiiI
  if 62 - 62: Ii1I * OoOoOO00
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 27 - 27: Oo0Ooo + Oo0Ooo / II111iiii % I1Ii111
  if 11 - 11: Ii1I
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 54 - 54: I1IiiI * I1Ii111 / ooOoO0o / iIii1I11I1II1 % iII111i / oO0o
  if 11 - 11: ooOoO0o + I1IiiI + Ii1I . II111iiii
  if 50 - 50: Oo0Ooo
  if 14 - 14: O0
  if 67 - 67: II111iiii / O0
  if 10 - 10: i1IIi / Oo0Ooo
  if 20 - 20: Oo0Ooo * I1Ii111 / I1ii11iIi11i . ooOoO0o
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
  if 67 - 67: o0oOOo0O0Ooo . Oo0Ooo % I11i
  if 38 - 38: OOooOOo - OoO0O00 . ooOoO0o
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # o0oOOo0O0Ooo . Oo0Ooo * i11iIiiIii
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 30 - 30: i1IIi % iII111i / iII111i . OOooOOo
  if 80 - 80: II111iiii + I1ii11iIi11i
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 9 - 9: I11i
  if 69 - 69: Oo0Ooo % I1Ii111
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( lisp_ddt_map_requestQ . has_key ( str ( self . nonce ) ) ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 80 - 80: I11i * oO0o % iIii1I11I1II1 / iII111i
   if 100 - 100: OOooOOo - O0 . I1ii11iIi11i * Oo0Ooo . o0oOOo0O0Ooo
   if 58 - 58: II111iiii . I1IiiI . i1IIi
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 60 - 60: iIii1I11I1II1 + ooOoO0o * i11iIiiIii + OoooooooOO
  if 43 - 43: I1ii11iIi11i % Oo0Ooo - i11iIiiIii / I1Ii111 * i1IIi
  if 78 - 78: o0oOOo0O0Ooo / OOooOOo / oO0o
  if 9 - 9: IiII + O0 / I1IiiI
  if 92 - 92: OOooOOo / i11iIiiIii + OoooooooOO
  if 9 - 9: iII111i
  if 9 - 9: O0 / o0oOOo0O0Ooo / I11i - i11iIiiIii - iII111i / IiII
  if 46 - 46: IiII + OoooooooOO % I1IiiI
  if 51 - 51: I1IiiI * I1Ii111 . i11iIiiIii % Oo0Ooo . i1IIi - oO0o
  if 56 - 56: Oo0Ooo / II111iiii
  if 76 - 76: OoOoOO00 % OoO0O00 * O0
  if 39 - 39: ooOoO0o / iII111i
  if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
  if 59 - 59: I11i % Ii1I / OoOoOO00
  if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
  if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
  if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
  if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
  if 80 - 80: Oo0Ooo
  if 58 - 58: I1Ii111 + OOooOOo
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
if 84 - 84: OOooOOo * i1IIi . iIii1I11I1II1 * iII111i + I1Ii111 + II111iiii
if 97 - 97: Ii1I - IiII
if 64 - 64: oO0o . ooOoO0o / ooOoO0o - II111iiii
if 81 - 81: I1ii11iIi11i
if 64 - 64: oO0o * OoO0O00 / OOooOOo + Ii1I % Oo0Ooo . IiII
if 2 - 2: I1Ii111 + I11i
if 47 - 47: i11iIiiIii + iIii1I11I1II1 % I1ii11iIi11i - oO0o % OoO0O00
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
  if 85 - 85: oO0o * OoOoOO00 / OoOoOO00
  if 85 - 85: OOooOOo / I1Ii111 . i1IIi / OoOoOO00 + iIii1I11I1II1
 def print_info ( self ) :
  if ( self . info_reply ) :
   o00oOOo = "Info-Reply"
   oOo0o0 = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # I1ii11iIi11i - II111iiii
   # OOooOOo % Ii1I * OoooooooOO % OOooOOo + OoooooooOO + iII111i
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : oOo0o0 += "empty, "
   for ooOo in self . rtr_list :
    oOo0o0 += red ( ooOo . print_address_no_iid ( ) , False ) + ", "
    if 25 - 25: O0 % OoO0O00 * OoooooooOO . OoOoOO00 / oO0o / o0oOOo0O0Ooo
   oOo0o0 = oOo0o0 [ 0 : - 2 ]
  else :
   o00oOOo = "Info-Request"
   IiIii = "<none>" if self . hostname == None else self . hostname
   oOo0o0 = ", hostname: {}" . format ( blue ( IiIii , False ) )
   if 14 - 14: i11iIiiIii
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( o00oOOo , False ) ,
 lisp_hex_string ( self . nonce ) , oOo0o0 ) )
  if 71 - 71: o0oOOo0O0Ooo + iII111i + ooOoO0o
  if 27 - 27: OoooooooOO . iII111i * I1Ii111 % O0 + OoooooooOO - iII111i
 def encode ( self ) :
  ooo0OOoo = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : ooo0OOoo |= ( 1 << 27 )
  if 86 - 86: i1IIi
  if 81 - 81: OoOoOO00
  if 52 - 52: iII111i * IiII % I1IiiI * I11i
  if 73 - 73: I1Ii111 * ooOoO0o
  if 62 - 62: OOooOOo . I1IiiI * iIii1I11I1II1 + OoO0O00 * ooOoO0o / oO0o
  IIii1i = struct . pack ( "I" , socket . htonl ( ooo0OOoo ) )
  IIii1i += struct . pack ( "Q" , self . nonce )
  IIii1i += struct . pack ( "III" , 0 , 0 , 0 )
  if 14 - 14: iII111i / OoO0O00
  if 75 - 75: IiII
  if 68 - 68: IiII - i1IIi % IiII . OoO0O00 . i11iIiiIii . OoooooooOO
  if 32 - 32: iII111i + OoO0O00 % IiII + I1IiiI
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    IIii1i += struct . pack ( "H" , 0 )
   else :
    IIii1i += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    IIii1i += self . hostname + "\0"
    if 69 - 69: I1Ii111 + I11i - iIii1I11I1II1 - II111iiii . Ii1I
   return ( IIii1i )
   if 74 - 74: I1ii11iIi11i % o0oOOo0O0Ooo + O0 - i11iIiiIii - IiII % OOooOOo
   if 39 - 39: OoO0O00 - o0oOOo0O0Ooo
   if 71 - 71: iII111i . OoO0O00 + ooOoO0o - OOooOOo - Oo0Ooo
   if 100 - 100: OoooooooOO - o0oOOo0O0Ooo + I1Ii111 . OoooooooOO % i11iIiiIii
   if 64 - 64: I1Ii111 % OoooooooOO / i1IIi / OoO0O00
  O000oOOoOOO = socket . htons ( LISP_AFI_LCAF )
  O000oo0O0OO0 = LISP_LCAF_NAT_TYPE
  iI11iiI1 = socket . htons ( 16 )
  I1iIiII11I = socket . htons ( self . ms_port )
  oOoOO0oOO = socket . htons ( self . etr_port )
  IIii1i += struct . pack ( "HHBBHHHH" , O000oOOoOOO , 0 , O000oo0O0OO0 , 0 , iI11iiI1 ,
 I1iIiII11I , oOoOO0oOO , socket . htons ( self . global_etr_rloc . afi ) )
  IIii1i += self . global_etr_rloc . pack_address ( )
  IIii1i += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  IIii1i += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : IIii1i += struct . pack ( "H" , 0 )
  if 95 - 95: OoO0O00 - IiII + I1IiiI
  if 50 - 50: OoO0O00
  if 36 - 36: OOooOOo
  if 80 - 80: I1IiiI / O0 * oO0o . I1ii11iIi11i + iIii1I11I1II1
  for ooOo in self . rtr_list :
   IIii1i += struct . pack ( "H" , socket . htons ( ooOo . afi ) )
   IIii1i += ooOo . pack_address ( )
   if 72 - 72: o0oOOo0O0Ooo
  return ( IIii1i )
  if 97 - 97: i1IIi % I11i % OoOoOO00
  if 25 - 25: OoOoOO00 . iIii1I11I1II1 - iII111i % II111iiii . OoOoOO00
 def decode ( self , packet ) :
  OO0o0 = packet
  O00oO00oOO00O = "I"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 16 - 16: OOooOOo . Oo0Ooo . I1IiiI % O0 . I1ii11iIi11i + i11iIiiIii
  ooo0OOoo = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  ooo0OOoo = ooo0OOoo [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if 100 - 100: I1ii11iIi11i - i1IIi - OoO0O00 * o0oOOo0O0Ooo + OoOoOO00
  O00oO00oOO00O = "Q"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 31 - 31: i1IIi
  oOO000 = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 21 - 21: o0oOOo0O0Ooo / O0 % O0 . OoooooooOO / I1IiiI
  ooo0OOoo = socket . ntohl ( ooo0OOoo )
  self . nonce = oOO000 [ 0 ]
  self . info_reply = ooo0OOoo & 0x08000000
  self . hostname = None
  packet = packet [ ooOoooOoo0oO : : ]
  if 94 - 94: ooOoO0o + OoO0O00 / ooOoO0o - ooOoO0o + Oo0Ooo + o0oOOo0O0Ooo
  if 50 - 50: oO0o . Oo0Ooo
  if 15 - 15: Ii1I
  if 64 - 64: OoooooooOO
  if 25 - 25: IiII
  O00oO00oOO00O = "HH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 29 - 29: OoOoOO00 % ooOoO0o * OoooooooOO
  if 8 - 8: i11iIiiIii - I1Ii111 / IiII
  if 17 - 17: i11iIiiIii * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO . OoOoOO00 - I1ii11iIi11i
  if 78 - 78: I1ii11iIi11i - OoooooooOO + O0
  if 15 - 15: I1ii11iIi11i / IiII % I1IiiI
  IIIiI1i , IIII1II11Iii = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if ( IIII1II11Iii != 0 ) : return ( None )
  if 16 - 16: Ii1I
  packet = packet [ ooOoooOoo0oO : : ]
  O00oO00oOO00O = "IBBH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 26 - 26: o0oOOo0O0Ooo / I11i + OoOoOO00 / OoOoOO00
  O0000 , O0Ooo000OO00 , i111ii1I111Ii , oo0 = struct . unpack ( O00oO00oOO00O ,
 packet [ : ooOoooOoo0oO ] )
  if 79 - 79: I11i - iII111i % oO0o % iII111i % OOooOOo + I1ii11iIi11i
  if ( oo0 != 0 ) : return ( None )
  packet = packet [ ooOoooOoo0oO : : ]
  if 89 - 89: I1ii11iIi11i + II111iiii % i1IIi * O0 . Ii1I
  if 52 - 52: IiII
  if 86 - 86: I1Ii111 / O0 + OoooooooOO % oO0o
  if 45 - 45: I1IiiI . Oo0Ooo . I11i . Ii1I
  if ( self . info_reply == False ) :
   O00oO00oOO00O = "H"
   ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
   if ( len ( packet ) >= ooOoooOoo0oO ) :
    O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
    if ( socket . ntohs ( O000oOOoOOO ) == LISP_AFI_NAME ) :
     packet = packet [ ooOoooOoo0oO : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 81 - 81: II111iiii + OoOoOO00 % i11iIiiIii / iII111i . I1Ii111 + II111iiii
     if 48 - 48: I1IiiI . I1ii11iIi11i * OoOoOO00 % i1IIi / I1Ii111 * II111iiii
   return ( OO0o0 )
   if 62 - 62: o0oOOo0O0Ooo * I1Ii111 . iIii1I11I1II1 / i1IIi
   if 75 - 75: OoooooooOO / ooOoO0o - iII111i . OoooooooOO . OoOoOO00 % i1IIi
   if 7 - 7: OoOoOO00 . i1IIi * i11iIiiIii % i11iIiiIii
   if 54 - 54: OoO0O00 / I1IiiI . Oo0Ooo
   if 39 - 39: OoO0O00 . ooOoO0o
  O00oO00oOO00O = "HHBBHHH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 41 - 41: Oo0Ooo * I1ii11iIi11i - II111iiii - II111iiii
  O000oOOoOOO , I11Iii1iIII1i , O000oo0O0OO0 , O0Ooo000OO00 , iI11iiI1 , I1iIiII11I , oOoOO0oOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 7 - 7: oO0o
  if 41 - 41: ooOoO0o
  if ( socket . ntohs ( O000oOOoOOO ) != LISP_AFI_LCAF ) : return ( None )
  if 93 - 93: Ii1I + I1Ii111 + Ii1I
  self . ms_port = socket . ntohs ( I1iIiII11I )
  self . etr_port = socket . ntohs ( oOoOO0oOO )
  packet = packet [ ooOoooOoo0oO : : ]
  if 23 - 23: I1IiiI - i1IIi / ooOoO0o
  if 4 - 4: IiII . I1ii11iIi11i + iII111i % ooOoO0o
  if 28 - 28: I1Ii111
  if 27 - 27: iII111i * I1IiiI
  O00oO00oOO00O = "H"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 60 - 60: i1IIi / I1IiiI - I1ii11iIi11i
  if 41 - 41: I1Ii111 + ooOoO0o / OOooOOo + I11i % Oo0Ooo
  if 91 - 91: I1IiiI % I1ii11iIi11i % oO0o / i1IIi * iIii1I11I1II1 + I11i
  if 48 - 48: ooOoO0o / I1ii11iIi11i / OoO0O00 / II111iiii * OoOoOO00
  O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if ( O000oOOoOOO != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( O000oOOoOOO )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 73 - 73: I11i / I1IiiI - IiII - i1IIi * IiII - OOooOOo
   if 39 - 39: I11i . ooOoO0o * II111iiii
   if 21 - 21: Ii1I
   if 92 - 92: OoO0O00 * I1ii11iIi11i + iIii1I11I1II1
   if 88 - 88: iIii1I11I1II1 + iIii1I11I1II1 * i11iIiiIii . I1ii11iIi11i % oO0o
   if 94 - 94: I1IiiI / I1ii11iIi11i / OOooOOo
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( OO0o0 )
  if 45 - 45: II111iiii
  O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if ( O000oOOoOOO != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( O000oOOoOOO )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( OO0o0 )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
   if 84 - 84: o0oOOo0O0Ooo
   if 40 - 40: OoooooooOO - oO0o / O0 * I1Ii111 . O0 + i11iIiiIii
   if 9 - 9: OOooOOo % O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
   if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( OO0o0 )
  if 66 - 66: OOooOOo * Oo0Ooo
  O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if ( O000oOOoOOO != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( O000oOOoOOO )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( OO0o0 )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 58 - 58: OOooOOo
   if 96 - 96: IiII % OoooooooOO + O0 * II111iiii / OOooOOo . I1Ii111
   if 47 - 47: OoO0O00 - Oo0Ooo * OoO0O00 / oO0o
   if 13 - 13: ooOoO0o
   if 55 - 55: i1IIi . I11i . II111iiii + O0 + ooOoO0o - i1IIi
   if 3 - 3: iIii1I11I1II1 / oO0o
  while ( len ( packet ) >= ooOoooOoo0oO ) :
   O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
   packet = packet [ ooOoooOoo0oO : : ]
   if ( O000oOOoOOO == 0 ) : continue
   ooOo = lisp_address ( socket . ntohs ( O000oOOoOOO ) , "" , 0 , 0 )
   packet = ooOo . unpack_address ( packet )
   if ( packet == None ) : return ( OO0o0 )
   ooOo . mask_len = ooOo . host_mask_len ( )
   self . rtr_list . append ( ooOo )
   if 61 - 61: I1Ii111 / O0 - iII111i
  return ( OO0o0 )
  if 44 - 44: i1IIi
  if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
  if 89 - 89: OoOoOO00 + Oo0Ooo . OoOoOO00 - II111iiii
class lisp_nat_info ( ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 85 - 85: OoooooooOO * OoooooooOO / Ii1I - II111iiii
  if 69 - 69: iII111i * I11i
 def timed_out ( self ) :
  oO000o0Oo00 = time . time ( ) - self . uptime
  return ( oO000o0Oo00 >= ( LISP_INFO_INTERVAL * 2 ) )
  if 43 - 43: o0oOOo0O0Ooo - IiII * Ii1I . i11iIiiIii / II111iiii
  if 61 - 61: OoOoOO00 / I1IiiI . I1ii11iIi11i % OOooOOo
  if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
class lisp_info_source ( ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
  if 15 - 15: o0oOOo0O0Ooo / i11iIiiIii
 def cache_address_for_info_source ( self ) :
  ii1i1I1111ii = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ ii1i1I1111ii ] = self
  if 63 - 63: I1ii11iIi11i - Ii1I + I11i
  if 98 - 98: iII111i / IiII * I1IiiI / oO0o - iIii1I11I1II1
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
  if 72 - 72: O0 . OOooOOo
  if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
  if 74 - 74: i1IIi
  if 80 - 80: ooOoO0o + I1Ii111 . I1ii11iIi11i % OoooooooOO
  if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
  if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
  if 35 - 35: i11iIiiIii + oO0o
  if 85 - 85: OoOoOO00 . O0 % OoooooooOO % oO0o
  if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
  if 12 - 12: II111iiii - iIii1I11I1II1
  if 43 - 43: i11iIiiIii % OoO0O00
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 100 - 100: i1IIi
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
  if 71 - 71: IiII + OoO0O00
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  iIi11i = auth1 + auth2 + auth3
  if 39 - 39: I1IiiI % IiII / II111iiii / II111iiii
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
  if 95 - 95: II111iiii + i11iIiiIii + o0oOOo0O0Ooo
 return ( iIi11i )
 if 30 - 30: O0 - O0 % iIii1I11I1II1 + iII111i * OoooooooOO
 if 1 - 1: O0
 if 36 - 36: oO0o . iII111i
 if 62 - 62: I11i + iIii1I11I1II1 % I11i * OOooOOo + iIii1I11I1II1 % Ii1I
 if 56 - 56: o0oOOo0O0Ooo
 if 55 - 55: oO0o - I1Ii111 / ooOoO0o % I1IiiI * OoooooooOO * I1IiiI
 if 88 - 88: Ii1I + O0
 if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
 if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
 if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   oo0o0o0o0Ooo = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 80 - 80: OoO0O00 + ooOoO0o - OOooOOo . Ii1I
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   oo0o0o0o0Ooo = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 99 - 99: I11i / OoOoOO00 % OoO0O00 * Ii1I / OOooOOo
  oo0o0o0o0Ooo . bind ( ( local_addr , int ( port ) ) )
 else :
  oooO = port
  if ( os . path . exists ( oooO ) ) :
   os . system ( "rm " + oooO )
   time . sleep ( 1 )
   if 9 - 9: ooOoO0o - ooOoO0o * I1ii11iIi11i
  oo0o0o0o0Ooo = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  oo0o0o0o0Ooo . bind ( oooO )
  if 92 - 92: Ii1I
 return ( oo0o0o0o0Ooo )
 if 88 - 88: OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
 if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
 if 62 - 62: I1Ii111 % II111iiii
 if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
 if 91 - 91: i11iIiiIii + Ii1I
 if 85 - 85: I11i % IiII
 if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   oo0o0o0o0Ooo = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   oo0o0o0o0Ooo = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 24 - 24: ooOoO0o - I1Ii111 * II111iiii - II111iiii
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  oo0o0o0o0Ooo = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  oo0o0o0o0Ooo . bind ( internal_name )
  if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
 return ( oo0o0o0o0Ooo )
 if 93 - 93: Ii1I / iII111i
 if 100 - 100: Oo0Ooo
 if 94 - 94: I1ii11iIi11i / i1IIi * I1IiiI - I11i - I1ii11iIi11i
 if 6 - 6: I1ii11iIi11i % o0oOOo0O0Ooo + o0oOOo0O0Ooo / OOooOOo / I1IiiI
 if 67 - 67: OoOoOO00 . iII111i / OOooOOo * ooOoO0o + i1IIi
 if 100 - 100: OOooOOo . ooOoO0o + I1Ii111 . oO0o
 if 20 - 20: i11iIiiIii - i1IIi - iIii1I11I1II1 - OoooooooOO
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 72 - 72: I1Ii111 . OoO0O00
 if 59 - 59: I1IiiI * I11i % i1IIi
 if 77 - 77: OOooOOo * OoooooooOO + I1IiiI + I1IiiI % oO0o . OoooooooOO
 if 60 - 60: iIii1I11I1II1
 if 13 - 13: II111iiii + Ii1I
 if 33 - 33: i1IIi
 if 36 - 36: ooOoO0o % ooOoO0o . i11iIiiIii
 if 42 - 42: OoO0O00 . I1Ii111 / Ii1I
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / oO0o . OoOoOO00
 if 74 - 74: I1IiiI * OoO0O00 + OoooooooOO * ooOoO0o . oO0o
 if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
 if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
 if 81 - 81: i1IIi % iIii1I11I1II1
 if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
 if 82 - 82: ooOoO0o
 if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
 if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 59 - 59: i11iIiiIii / OoO0O00
 if 48 - 48: iIii1I11I1II1
 if 19 - 19: oO0o
 if 69 - 69: I1ii11iIi11i % iII111i - OoooooooOO % Ii1I * oO0o
 if 12 - 12: OoOoOO00 / I1Ii111 . O0 . IiII - OOooOOo - OoO0O00
 if 28 - 28: II111iiii . OoOoOO00 - o0oOOo0O0Ooo
 if 89 - 89: I1Ii111 * OoooooooOO . OOooOOo . I11i % i11iIiiIii
 if 8 - 8: I1ii11iIi11i + II111iiii . OoO0O00 + I1IiiI - II111iiii % OoO0O00
 if 85 - 85: i11iIiiIii % iII111i + II111iiii
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 16 - 16: ooOoO0o * OoOoOO00 / OoOoOO00 + II111iiii
 if 50 - 50: OoO0O00 / OOooOOo % I1IiiI / Ii1I + OoO0O00 . iIii1I11I1II1
 if 62 - 62: I1Ii111 + OoooooooOO - Ii1I - iIii1I11I1II1
 if 80 - 80: OoO0O00
 if 72 - 72: II111iiii % i11iIiiIii + OoOoOO00 / I1Ii111 - i11iIiiIii
 if 39 - 39: i11iIiiIii - OOooOOo / OoO0O00 * OoOoOO00 / IiII
 if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 / Ii1I / II111iiii
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 56 - 56: OOooOOo * iII111i / Ii1I
 if 9 - 9: I1ii11iIi11i * i11iIiiIii / I1Ii111 + iIii1I11I1II1
 if 1 - 1: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / oO0o
 if 73 - 73: iII111i
 if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo
 if 45 - 45: oO0o % O0 / O0
 if 98 - 98: I1Ii111
 if 58 - 58: OOooOOo
 if 6 - 6: I1ii11iIi11i
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
 if 18 - 18: ooOoO0o
 if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
 if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
 if 29 - 29: Ii1I . II111iiii / I1Ii111
 if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
 if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
 if 81 - 81: i11iIiiIii - II111iiii + I11i
 if 52 - 52: II111iiii
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
 if 26 - 26: I1ii11iIi11i - OoO0O00
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
 if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
 if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
 if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
 if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
 if 15 - 15: Ii1I
 if 29 - 29: I11i / I1IiiI / OoooooooOO . OoOoOO00 / I11i . I1Ii111
def lisp_ipc ( packet , send_socket , node ) :
 if 69 - 69: O0 * OoOoOO00 + o0oOOo0O0Ooo + I1IiiI % iII111i . OoooooooOO
 if 45 - 45: I1Ii111 + oO0o - o0oOOo0O0Ooo - OoOoOO00 + I1IiiI / II111iiii
 if 46 - 46: II111iiii . iIii1I11I1II1
 if 62 - 62: I1ii11iIi11i % i1IIi % I1Ii111 * ooOoO0o % OOooOOo + I1IiiI
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 100 - 100: II111iiii - o0oOOo0O0Ooo * OoooooooOO . ooOoO0o / II111iiii / oO0o
  if 43 - 43: iIii1I11I1II1 + ooOoO0o * iII111i + iIii1I11I1II1 . I1Ii111
 oOOOooooOooOo = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 25 - 25: OOooOOo + iII111i
 OoO00oo00 = 0
 iiiIIiiIi = len ( packet )
 OoOOoO0O00oO = 0
 I1II1iI = .001
 while ( iiiIIiiIi > 0 ) :
  IIIII = min ( iiiIIiiIi , oOOOooooOooOo )
  ii1i11ii11II = packet [ OoO00oo00 : IIIII + OoO00oo00 ]
  if 44 - 44: I1Ii111
  try :
   send_socket . sendto ( ii1i11ii11II , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( ii1i11ii11II ) , len ( packet ) , node ) )
   if 84 - 84: I1Ii111 + Ii1I - o0oOOo0O0Ooo / OoooooooOO
   OoOOoO0O00oO = 0
   I1II1iI = .001
   if 70 - 70: IiII / i11iIiiIii / i1IIi . OOooOOo
  except socket . error , oOo :
   if ( OoOOoO0O00oO == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 82 - 82: OoOoOO00 * Ii1I % I11i / I1Ii111
    if 21 - 21: OoO0O00 + Ii1I / I1Ii111
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( ii1i11ii11II ) , len ( packet ) , node , oOo ) )
   if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
   if 38 - 38: i1IIi
   OoOOoO0O00oO += 1
   time . sleep ( I1II1iI )
   if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
   lprint ( "Retrying after {} ms ..." . format ( I1II1iI * 1000 ) )
   I1II1iI *= 2
   continue
   if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
   if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
  OoO00oo00 += IIIII
  iiiIIiiIi -= IIIII
  if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
 return
 if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
 if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
 if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
 if 2 - 2: OOooOOo / I11i * I11i + I11i / O0 - OOooOOo
 if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
 if 68 - 68: iII111i / OOooOOo
 if 28 - 28: II111iiii
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 OoO00oo00 = 0
 I1iI1iIIIii = ""
 iiiIIiiIi = len ( packet ) * 2
 while ( OoO00oo00 < iiiIIiiIi ) :
  I1iI1iIIIii += packet [ OoO00oo00 : OoO00oo00 + 8 ] + " "
  OoO00oo00 += 8
  iiiIIiiIi -= 4
  if 49 - 49: I1ii11iIi11i
 return ( I1iI1iIIIii )
 if 33 - 33: iIii1I11I1II1
 if 72 - 72: I1ii11iIi11i * i11iIiiIii
 if 12 - 12: O0 - iIii1I11I1II1 % Oo0Ooo / O0 - IiII
 if 55 - 55: OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * i11iIiiIii + oO0o
 if 45 - 45: Ii1I
 if 8 - 8: oO0o + OOooOOo
 if 37 - 37: IiII - OoOoOO00 + oO0o - Oo0Ooo + IiII
def lisp_send ( lisp_sockets , dest , port , packet ) :
 IIIIIiI111 = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 56 - 56: OOooOOo * IiII . iIii1I11I1II1 * I1Ii111
 if 95 - 95: oO0o % Ii1I - OOooOOo . O0 . OoooooooOO - II111iiii
 if 91 - 91: I1IiiI % i1IIi . Ii1I
 if 67 - 67: oO0o + i1IIi / o0oOOo0O0Ooo
 if 78 - 78: ooOoO0o
 if 19 - 19: i1IIi % O0 % ooOoO0o / II111iiii * I11i
 if 18 - 18: i1IIi % oO0o
 if 80 - 80: II111iiii
 if 18 - 18: I1Ii111 % iII111i + OoOoOO00 . I1ii11iIi11i / I11i
 if 29 - 29: II111iiii - I1Ii111 . OoooooooOO / i11iIiiIii / I1ii11iIi11i
 if 60 - 60: i1IIi % ooOoO0o / II111iiii * Oo0Ooo - i1IIi . Ii1I
 if 63 - 63: OoO0O00 * OoooooooOO + iII111i / iIii1I11I1II1 . i11iIiiIii
 ii1i1II11II1i = dest . print_address_no_iid ( )
 if ( ii1i1II11II1i . find ( "::ffff:" ) != - 1 and ii1i1II11II1i . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : IIIIIiI111 = lisp_sockets [ 0 ]
  if ( IIIIIiI111 == None ) :
   IIIIIiI111 = lisp_sockets [ 0 ]
   ii1i1II11II1i = ii1i1II11II1i . split ( "::ffff:" ) [ - 1 ]
   if 17 - 17: OOooOOo
   if 21 - 21: i1IIi
   if 10 - 10: i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo . o0oOOo0O0Ooo
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + ii1i1II11II1i , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 8 - 8: iII111i + iIii1I11I1II1 . I1ii11iIi11i
 if 68 - 68: OoooooooOO . OoooooooOO % I1ii11iIi11i + i1IIi % OoooooooOO + Ii1I
 if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
 if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
 I11I1iI = ( LISP_RLOC_PROBE_TTL == 255 )
 if ( I11I1iI ) :
  iI1I1 = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  I11I1iI = ( iI1I1 in [ 0x12 , 0x28 ] )
  if ( I11I1iI ) : lisp_set_ttl ( IIIIIiI111 , LISP_RLOC_PROBE_TTL )
  if 50 - 50: Oo0Ooo % OoOoOO00 * i1IIi
  if 83 - 83: Oo0Ooo / OOooOOo * o0oOOo0O0Ooo * OOooOOo . IiII
 try : IIIIIiI111 . sendto ( packet , ( ii1i1II11II1i , port ) )
 except socket . error , oOo :
  lprint ( "socket.sendto() failed: {}" . format ( oOo ) )
  if 75 - 75: IiII / ooOoO0o % ooOoO0o * I1ii11iIi11i % Oo0Ooo
  if 78 - 78: Oo0Ooo
  if 47 - 47: I1ii11iIi11i
  if 29 - 29: ooOoO0o * oO0o + iIii1I11I1II1 * i1IIi % i11iIiiIii + iIii1I11I1II1
  if 69 - 69: i11iIiiIii . I1Ii111 + i11iIiiIii / OoO0O00
 if ( I11I1iI ) : lisp_set_ttl ( IIIIIiI111 , 64 )
 return
 if 25 - 25: i11iIiiIii / Ii1I
 if 34 - 34: II111iiii + OOooOOo % oO0o - OOooOOo
 if 25 - 25: iII111i % iIii1I11I1II1 + IiII
 if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
 if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
 if 55 - 55: OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
 if 37 - 37: Ii1I + o0oOOo0O0Ooo
 if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
 if 8 - 8: I11i - I11i % IiII
 if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
 if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
 if 25 - 25: iII111i / iII111i % OoOoOO00 / ooOoO0o
 IIIII = total_length - len ( packet )
 if ( IIIII == 0 ) : return ( [ True , packet ] )
 if 81 - 81: OOooOOo * oO0o
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 32 - 32: Oo0Ooo * OoO0O00 + ooOoO0o . O0 * oO0o * iIii1I11I1II1
 if 50 - 50: i1IIi
 if 53 - 53: II111iiii + O0 . ooOoO0o * IiII + i1IIi
 if 80 - 80: Ii1I + O0
 if 59 - 59: i11iIiiIii - OoooooooOO % I11i . OoO0O00 - Oo0Ooo * o0oOOo0O0Ooo
 iiiIIiiIi = IIIII
 while ( iiiIIiiIi > 0 ) :
  try : ii1i11ii11II = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 7 - 7: II111iiii % Ii1I * i11iIiiIii
  ii1i11ii11II = ii1i11ii11II [ 0 ]
  if 28 - 28: II111iiii / ooOoO0o * i11iIiiIii % OOooOOo
  if 18 - 18: I11i - IiII - iIii1I11I1II1
  if 82 - 82: II111iiii + OoO0O00 % iIii1I11I1II1 / O0
  if 75 - 75: OOooOOo * OoO0O00 + OoooooooOO + i11iIiiIii . OoO0O00
  if 94 - 94: I11i * ooOoO0o . I1IiiI / Ii1I - I1IiiI % OoooooooOO
  if ( ii1i11ii11II . find ( "packet@" ) == 0 ) :
   iiiii1 = ii1i11ii11II . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( ii1i11ii11II ) ,
   # OOooOOo % i11iIiiIii % i11iIiiIii . I1ii11iIi11i
 iiiii1 [ 1 ] if len ( iiiii1 ) > 2 else "?" )
   return ( [ False , ii1i11ii11II ] )
   if 95 - 95: I11i
   if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
  iiiIIiiIi -= len ( ii1i11ii11II )
  packet += ii1i11ii11II
  if 94 - 94: OOooOOo / IiII
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( ii1i11ii11II ) , total_length , source ) )
  if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
  if 22 - 22: OoOoOO00 - Oo0Ooo
 return ( [ True , packet ] )
 if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
 if 33 - 33: I11i + O0
 if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
 if 68 - 68: O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
 if 12 - 12: II111iiii + I11i
 if 9 - 9: I1ii11iIi11i
 if 51 - 51: I1ii11iIi11i
 if 37 - 37: I1IiiI % I1Ii111
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 IIii1i = ""
 for ii1i11ii11II in payload : IIii1i += ii1i11ii11II + "\x40"
 return ( IIii1i [ : - 1 ] )
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
 if 75 - 75: I11i . Ii1I / I1ii11iIi11i
 if 99 - 99: Ii1I
 if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
  if 21 - 21: iII111i
  if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
  if 75 - 75: OoooooooOO
  try : III1iiI1iI = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 49 - 49: II111iiii * iIii1I11I1II1 / I11i - oO0o
  if 76 - 76: I1Ii111 . Oo0Ooo - ooOoO0o . II111iiii - iII111i
  if 36 - 36: iIii1I11I1II1 % Oo0Ooo
  if 67 - 67: oO0o / II111iiii . I11i / oO0o
  if 46 - 46: oO0o * Oo0Ooo - I11i / iIii1I11I1II1
  if 100 - 100: i11iIiiIii % oO0o
  if ( internal == False ) :
   IIii1i = III1iiI1iI [ 0 ]
   oo00Oo0 = lisp_convert_6to4 ( III1iiI1iI [ 1 ] [ 0 ] )
   IiI1iI1 = III1iiI1iI [ 1 ] [ 1 ]
   if 62 - 62: OOooOOo * i1IIi - OOooOOo / i11iIiiIii
   if ( IiI1iI1 == LISP_DATA_PORT ) :
    II1111 = lisp_data_plane_logging
    OoO = lisp_format_packet ( IIii1i [ 0 : 60 ] ) + " ..."
   else :
    II1111 = True
    OoO = lisp_format_packet ( IIii1i )
    if 88 - 88: oO0o - OoO0O00 % ooOoO0o + OoOoOO00 + IiII
    if 83 - 83: i1IIi - Oo0Ooo - IiII - i11iIiiIii
   if ( II1111 ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( IIii1i ) , bold ( "from " + oo00Oo0 , False ) , IiI1iI1 ,
 OoO ) )
    if 53 - 53: OoOoOO00 . OoooooooOO
   return ( [ "packet" , oo00Oo0 , IiI1iI1 , IIii1i ] )
   if 11 - 11: i1IIi % II111iiii % I1ii11iIi11i
   if 99 - 99: oO0o - I1Ii111
   if 29 - 29: I1IiiI - I11i
   if 42 - 42: Oo0Ooo - O0 . OoOoOO00
   if 4 - 4: IiII
   if 2 - 2: iII111i
  ii1i1II11i = False
  oo00000ooOooO = III1iiI1iI [ 0 ]
  ooo0OO0O = False
  if 4 - 4: o0oOOo0O0Ooo
  while ( ii1i1II11i == False ) :
   oo00000ooOooO = oo00000ooOooO . split ( "@" )
   if 44 - 44: I11i % IiII / I1IiiI . OoO0O00 * Ii1I
   if ( len ( oo00000ooOooO ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( oo00000ooOooO [ 0 ] ) )
    if 89 - 89: OoOoOO00 / Oo0Ooo + O0 * ooOoO0o
    ooo0OO0O = True
    break
    if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
    if 95 - 95: II111iiii
   OO00oOo0oO = oo00000ooOooO [ 0 ]
   try :
    o00o0ooO0oo = int ( oo00000ooOooO [ 1 ] )
   except :
    OOO0OoOooo = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( OOO0OoOooo , III1iiI1iI ) )
    ooo0OO0O = True
    break
    if 82 - 82: o0oOOo0O0Ooo - I11i + i1IIi . o0oOOo0O0Ooo
   oo00Oo0 = oo00000ooOooO [ 2 ]
   IiI1iI1 = oo00000ooOooO [ 3 ]
   if 58 - 58: II111iiii % ooOoO0o % I1Ii111 . II111iiii
   if 88 - 88: I1ii11iIi11i - iIii1I11I1II1 / iII111i
   if 69 - 69: o0oOOo0O0Ooo % o0oOOo0O0Ooo . i11iIiiIii
   if 34 - 34: Oo0Ooo - i11iIiiIii
   if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
   if 19 - 19: I1IiiI
   if 99 - 99: OOooOOo - OOooOOo
   if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
   if ( len ( oo00000ooOooO ) > 5 ) :
    IIii1i = lisp_bit_stuff ( oo00000ooOooO [ 4 : : ] )
   else :
    IIii1i = oo00000ooOooO [ 4 ]
    if 83 - 83: o0oOOo0O0Ooo
    if 23 - 23: o0oOOo0O0Ooo . I11i
    if 67 - 67: iII111i
    if 52 - 52: IiII . OoooooooOO
    if 34 - 34: o0oOOo0O0Ooo / IiII . OoooooooOO . Oo0Ooo / ooOoO0o + O0
    if 38 - 38: I11i
   ii1i1II11i , IIii1i = lisp_receive_segments ( lisp_socket , IIii1i ,
 oo00Oo0 , o00o0ooO0oo )
   if ( IIii1i == None ) : return ( [ "" , "" , "" , "" ] )
   if 66 - 66: II111iiii
   if 57 - 57: OoO0O00 / Oo0Ooo % I1IiiI * I1ii11iIi11i
   if 68 - 68: iII111i - o0oOOo0O0Ooo - OoO0O00 . O0 - i11iIiiIii
   if 2 - 2: I1ii11iIi11i * i1IIi
   if 17 - 17: I1ii11iIi11i * Ii1I % Oo0Ooo * I1Ii111 + OoO0O00 . OoooooooOO
   if ( ii1i1II11i == False ) :
    oo00000ooOooO = IIii1i
    continue
    if 60 - 60: Ii1I . II111iiii
    if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
   if ( IiI1iI1 == "" ) : IiI1iI1 = "no-port"
   if ( OO00oOo0oO == "command" and lisp_i_am_core == False ) :
    ooo = IIii1i . find ( " {" )
    IiIIIi = IIii1i if ooo == - 1 else IIii1i [ : ooo ]
    IiIIIi = ": '" + IiIIIi + "'"
   else :
    IiIIIi = ""
    if 70 - 70: I1Ii111 * I11i % oO0o % ooOoO0o * iII111i - I1Ii111
    if 43 - 43: iIii1I11I1II1 . i11iIiiIii - oO0o
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( IIii1i ) , bold ( "from " + oo00Oo0 , False ) , IiI1iI1 , OO00oOo0oO ,
 IiIIIi if ( OO00oOo0oO in [ "command" , "api" ] ) else ": ... " if ( OO00oOo0oO == "data-packet" ) else ": " + lisp_format_packet ( IIii1i ) ) )
   if 55 - 55: iIii1I11I1II1 % oO0o % OOooOOo / I1Ii111 * OoooooooOO / Oo0Ooo
   if 88 - 88: I11i + OoO0O00 . iIii1I11I1II1 . II111iiii
   if 67 - 67: OOooOOo - ooOoO0o % iII111i % IiII
   if 71 - 71: OoO0O00 - ooOoO0o - I1IiiI + O0
   if 15 - 15: i1IIi
  if ( ooo0OO0O ) : continue
  return ( [ OO00oOo0oO , oo00Oo0 , IiI1iI1 , IIii1i ] )
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
 Ii1I1i1IiiI = lisp_control_header ( )
 if ( Ii1I1i1IiiI . decode ( packet ) == None ) :
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
 if ( Ii1I1i1IiiI . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl , I1II1i )
  if 72 - 72: O0
 elif ( Ii1I1i1IiiI . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl , I1II1i )
  if 15 - 15: II111iiii / I11i % II111iiii % Ii1I % i11iIiiIii / I1Ii111
 elif ( Ii1I1i1IiiI . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 93 - 93: OOooOOo / OoooooooOO % iII111i
 elif ( Ii1I1i1IiiI . type == LISP_MAP_NOTIFY ) :
  if ( o0ooo0 == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  else :
   if ( lisp_is_running ( "lisp-rtr" ) ) :
    lisp_process_multicast_map_notify ( packet , source )
    if 47 - 47: o0oOOo0O0Ooo - I1IiiI % O0 % I1Ii111 . O0 . OoOoOO00
   lisp_process_map_notify ( lisp_sockets , packet , source )
   if 95 - 95: o0oOOo0O0Ooo * OOooOOo - iII111i * OoooooooOO - ooOoO0o / I1IiiI
   if 47 - 47: OoO0O00 % I1IiiI / OoOoOO00 - I1Ii111 / I1IiiI
 elif ( Ii1I1i1IiiI . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 13 - 13: o0oOOo0O0Ooo % ooOoO0o
 elif ( Ii1I1i1IiiI . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 15 - 15: iII111i * I1IiiI . iIii1I11I1II1 % I1IiiI / O0
 elif ( Ii1I1i1IiiI . type == LISP_NAT_INFO and Ii1I1i1IiiI . is_info_reply ( ) ) :
  I11Iii1iIII1i , II1ioOO0Oo , i1i1i11i11 = lisp_process_info_reply ( source , packet , True )
  if 47 - 47: OoooooooOO - i11iIiiIii . I1IiiI / i1IIi
 elif ( Ii1I1i1IiiI . type == LISP_NAT_INFO and Ii1I1i1IiiI . is_info_reply ( ) == False ) :
  oo0o00OO = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , oo0o00OO , udp_sport ,
 None )
  if 74 - 74: OoooooooOO * ooOoO0o
 elif ( Ii1I1i1IiiI . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 45 - 45: Oo0Ooo + iIii1I11I1II1 . o0oOOo0O0Ooo
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( Ii1I1i1IiiI . type ) )
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
 III1I1Iii1 = bold ( "RLOC-probe" , False )
 if 74 - 74: I1ii11iIi11i + O0 + o0oOOo0O0Ooo - iII111i
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( III1I1Iii1 ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 48 - 48: ooOoO0o * iIii1I11I1II1 % Oo0Ooo
  if 60 - 60: OoOoOO00 / i1IIi * iIii1I11I1II1
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( III1I1Iii1 ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 91 - 91: I1Ii111 . OoooooooOO / IiII / I1IiiI
  if 56 - 56: II111iiii + iIii1I11I1II1 / I1Ii111 / I1Ii111 % Oo0Ooo / OoOoOO00
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( III1I1Iii1 ) )
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
 IIii1i = i1i11i . encode ( )
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
 IIii1i += iI1I1I1I11I11 . encode ( )
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
  IIii1i += I1i11 . encode ( )
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
  I1IIi = lisp_encode_telemetry ( ii1i , eo = str ( time . time ( ) ) )
  I1i11 . json = lisp_json ( "telemetry" , I1IIi )
  I1i11 . print_record ( "    " )
  IIii1i += I1i11 . encode ( )
  if 20 - 20: OoO0O00 * II111iiii
 return ( IIii1i )
 if 22 - 22: Oo0Ooo * I11i
 if 48 - 48: i11iIiiIii * I1IiiI % oO0o % OoooooooOO
 if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
 if 69 - 69: OoooooooOO
 if 19 - 19: O0 + iIii1I11I1II1 / OoOoOO00 / oO0o + II111iiii - OOooOOo
 if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
 if 81 - 81: iIii1I11I1II1 - OoO0O00 . i11iIiiIii
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 iIII = lisp_map_referral ( )
 iIII . record_count = 1
 iIII . nonce = nonce
 IIii1i = iIII . encode ( )
 iIII . print_map_referral ( )
 if 74 - 74: i11iIiiIii / iII111i / i1IIi + I1Ii111
 iI1I1I1I11I11 = lisp_eid_record ( )
 if 33 - 33: IiII % IiII
 oOo0O0oO = 0
 if ( ddt_entry == None ) :
  iI1I1I1I11I11 . eid = eid
  iI1I1I1I11I11 . group = group
 else :
  oOo0O0oO = len ( ddt_entry . delegation_set )
  iI1I1I1I11I11 . eid = ddt_entry . eid
  iI1I1I1I11I11 . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 39 - 39: I1Ii111 / I11i + oO0o / I1Ii111 % IiII * I1ii11iIi11i
 iI1I1I1I11I11 . rloc_count = oOo0O0oO
 iI1I1I1I11I11 . authoritative = True
 if 66 - 66: I1ii11iIi11i * ooOoO0o . i11iIiiIii * Oo0Ooo - I11i . I1IiiI
 if 43 - 43: I11i . iII111i . IiII - oO0o
 if 60 - 60: i1IIi + iII111i * i1IIi . iII111i
 if 40 - 40: i1IIi . OoO0O00
 if 65 - 65: Oo0Ooo
 o0Oo0oo = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( oOo0O0oO == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   IIiIi1I1Ii11 = ddt_entry . delegation_set [ 0 ]
   if ( IIiIi1I1Ii11 . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 81 - 81: OOooOOo % OoooooooOO / IiII . Oo0Ooo - ooOoO0o . I1IiiI
   if ( IIiIi1I1Ii11 . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 3 - 3: O0
    if 95 - 95: i11iIiiIii
    if 100 - 100: iIii1I11I1II1 * I1IiiI * Ii1I * i1IIi . I1Ii111 * I1IiiI
    if 54 - 54: o0oOOo0O0Ooo / iII111i + IiII - o0oOOo0O0Ooo - I11i
    if 28 - 28: I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * IiII + OoooooooOO
    if 52 - 52: I1Ii111
    if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : o0Oo0oo = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  o0Oo0oo = ( lisp_i_am_ms and IIiIi1I1Ii11 . is_ms_peer ( ) == False )
  if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
  if 73 - 73: iII111i - o0oOOo0O0Ooo / OOooOOo + iII111i + o0oOOo0O0Ooo % II111iiii
 iI1I1I1I11I11 . action = action
 iI1I1I1I11I11 . ddt_incomplete = o0Oo0oo
 iI1I1I1I11I11 . record_ttl = ttl
 if 74 - 74: I11i * iIii1I11I1II1 - OoO0O00 / i1IIi / OoO0O00 / IiII
 IIii1i += iI1I1I1I11I11 . encode ( )
 iI1I1I1I11I11 . print_record ( "  " , True )
 if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
 if ( oOo0O0oO == 0 ) : return ( IIii1i )
 if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
 for IIiIi1I1Ii11 in ddt_entry . delegation_set :
  I1i11 = lisp_rloc_record ( )
  I1i11 . rloc = IIiIi1I1Ii11 . delegate_address
  I1i11 . priority = IIiIi1I1Ii11 . priority
  I1i11 . weight = IIiIi1I1Ii11 . weight
  I1i11 . mpriority = 255
  I1i11 . mweight = 0
  I1i11 . reach_bit = True
  IIii1i += I1i11 . encode ( )
  I1i11 . print_record ( "    " )
  if 77 - 77: OoOoOO00 + IiII + Oo0Ooo
 return ( IIii1i )
 if 88 - 88: i1IIi
 if 45 - 45: iII111i % I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
 if 55 - 55: OoO0O00 % IiII
 if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
 if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
 if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
 if 63 - 63: I1Ii111 + iII111i
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 6 - 6: I1ii11iIi11i + Ii1I
 if ( map_request . target_group . is_null ( ) ) :
  I1111I = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  I1111I = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( I1111I ) : I1111I = I1111I . lookup_source_cache ( map_request . target_eid , False )
  if 56 - 56: Oo0Ooo / OOooOOo * IiII % o0oOOo0O0Ooo + Ii1I - Oo0Ooo
 I11i11i1 = map_request . print_prefix ( )
 if 1 - 1: O0 % Ii1I - i1IIi . Oo0Ooo + OoOoOO00 / I1IiiI
 if ( I1111I == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( I11i11i1 , False ) ) )
  if 16 - 16: I1ii11iIi11i - I1ii11iIi11i / Ii1I * oO0o
  return
  if 97 - 97: OoO0O00 % ooOoO0o - ooOoO0o * oO0o - O0 . Oo0Ooo
  if 80 - 80: O0 - i1IIi + OoO0O00 . i11iIiiIii
 oooOoOoo0o = I1111I . print_eid_tuple ( )
 if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( oooOoOoo0o , False ) , green ( I11i11i1 , False ) ) )
 if 53 - 53: o0oOOo0O0Ooo * Ii1I
 if 42 - 42: I11i + iII111i / iIii1I11I1II1
 if 1 - 1: O0 - II111iiii
 if 75 - 75: II111iiii / OoO0O00 % II111iiii
 if 3 - 3: Ii1I - Ii1I % I1ii11iIi11i
 iII1II1iI = map_request . itr_rlocs [ 0 ]
 if ( iII1II1iI . is_private_address ( ) and lisp_nat_traversal ) :
  iII1II1iI = source
  if 32 - 32: I1IiiI - Oo0Ooo * ooOoO0o - I1ii11iIi11i
  if 71 - 71: I1IiiI % OoO0O00
 oOO000 = map_request . nonce
 iiiI11111 = lisp_nonce_echoing
 oOoo0oO = map_request . keys
 if 27 - 27: OoO0O00 + o0oOOo0O0Ooo * iIii1I11I1II1 * OoooooooOO * Ii1I . iIii1I11I1II1
 if 67 - 67: oO0o * I1ii11iIi11i / I1Ii111 . i1IIi
 if 21 - 21: II111iiii - OOooOOo * O0
 if 52 - 52: IiII / I1IiiI - o0oOOo0O0Ooo
 if 6 - 6: I1ii11iIi11i / OOooOOo
 oOOO0O0OOo0 = map_request . json_telemetry
 if ( oOOO0O0OOo0 != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( oOOO0O0OOo0 , ei = etr_in_ts )
  if 34 - 34: Oo0Ooo . OOooOOo % II111iiii / i1IIi - i1IIi + OoOoOO00
  if 37 - 37: ooOoO0o
 I1111I . map_replies_sent += 1
 if 36 - 36: OoooooooOO % OoooooooOO . o0oOOo0O0Ooo * OoOoOO00 + Oo0Ooo . O0
 IIii1i = lisp_build_map_reply ( I1111I . eid , I1111I . group , I1111I . rloc_set , oOO000 ,
 LISP_NO_ACTION , 1440 , map_request , oOoo0oO , iiiI11111 , True , ttl )
 if 33 - 33: ooOoO0o . I1Ii111 + I1IiiI . Oo0Ooo
 if 11 - 11: o0oOOo0O0Ooo * i11iIiiIii
 if 9 - 9: OoooooooOO / OoooooooOO
 if 57 - 57: OoO0O00 + i1IIi % OOooOOo * i11iIiiIii % i1IIi / o0oOOo0O0Ooo
 if 1 - 1: ooOoO0o
 if 81 - 81: iII111i . Oo0Ooo . O0 . II111iiii
 if 46 - 46: I1Ii111 % Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . oO0o
 if 43 - 43: i1IIi % o0oOOo0O0Ooo * I1IiiI / oO0o * IiII + I11i
 if 13 - 13: O0
 if 60 - 60: IiII
 if 14 - 14: II111iiii - i1IIi % OoOoOO00
 if 29 - 29: OoooooooOO * O0 / iIii1I11I1II1
 if 29 - 29: OoO0O00 / IiII + i1IIi / OoO0O00 . Oo0Ooo
 if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
 if 14 - 14: i1IIi
 if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  ii1i11iiII = ( iII1II1iI . is_private_address ( ) == False )
  ooOo = iII1II1iI . print_address_no_iid ( )
  if ( ( ii1i11iiII and lisp_rtr_list . has_key ( ooOo ) ) or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , iII1II1iI , None , IIii1i )
   return
   if 36 - 36: OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
   if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
   if 23 - 23: oO0o / o0oOOo0O0Ooo + I11i % IiII * OoO0O00
   if 48 - 48: OoO0O00
   if 30 - 30: iIii1I11I1II1
   if 53 - 53: II111iiii
 lisp_send_map_reply ( lisp_sockets , IIii1i , iII1II1iI , sport )
 return
 if 40 - 40: Ii1I % oO0o
 if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
 if 78 - 78: oO0o
 if 20 - 20: i1IIi + i1IIi * i1IIi
 if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
 if 27 - 27: oO0o + Ii1I . i11iIiiIii
 if 97 - 97: iII111i . I1IiiI
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
 if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
 if 45 - 45: oO0o
 if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
 iII1II1iI = map_request . itr_rlocs [ 0 ]
 if ( iII1II1iI . is_private_address ( ) ) : iII1II1iI = source
 oOO000 = map_request . nonce
 if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
 iIiiIIi1i111iI = map_request . target_eid
 oOooO00OOoO = map_request . target_group
 if 100 - 100: i11iIiiIii - iII111i - I11i
 iI1111Ii1I = [ ]
 for O0ooooOOOO0OO in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( O0ooooOOOO0OO == None ) : continue
  oOo0o0 = lisp_rloc ( )
  oOo0o0 . rloc . copy_address ( O0ooooOOOO0OO )
  oOo0o0 . priority = 254
  iI1111Ii1I . append ( oOo0o0 )
  if 82 - 82: ooOoO0o % OOooOOo % Ii1I
  if 82 - 82: I1ii11iIi11i
 iiiI11111 = lisp_nonce_echoing
 oOoo0oO = map_request . keys
 if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
 if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
 if 53 - 53: OOooOOo * OoOoOO00 % iII111i
 if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
 if 66 - 66: I1IiiI * OoOoOO00 . I1IiiI / Oo0Ooo - Ii1I
 oOOO0O0OOo0 = map_request . json_telemetry
 if ( oOOO0O0OOo0 != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( oOOO0O0OOo0 , ei = etr_in_ts )
  if 69 - 69: iIii1I11I1II1 % iII111i + ooOoO0o * i1IIi + iII111i * I1Ii111
  if 67 - 67: Ii1I % Oo0Ooo - Oo0Ooo . I11i + IiII
 IIii1i = lisp_build_map_reply ( iIiiIIi1i111iI , oOooO00OOoO , iI1111Ii1I , oOO000 , LISP_NO_ACTION ,
 1440 , map_request , oOoo0oO , iiiI11111 , True , ttl )
 lisp_send_map_reply ( lisp_sockets , IIii1i , iII1II1iI , sport )
 return
 if 73 - 73: Oo0Ooo + iIii1I11I1II1 . iIii1I11I1II1
 if 73 - 73: ooOoO0o + OoOoOO00
 if 61 - 61: I1Ii111 * I1Ii111 % OOooOOo
 if 31 - 31: oO0o + Ii1I - iIii1I11I1II1 / i11iIiiIii
 if 9 - 9: IiII % OoO0O00
 if 58 - 58: iII111i
 if 12 - 12: OoO0O00
 if 59 - 59: OOooOOo + i1IIi
 if 8 - 8: i1IIi + Oo0Ooo / Ii1I . OoOoOO00 % i1IIi
 if 33 - 33: OoooooooOO + iIii1I11I1II1
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 iI1111Ii1I = target_site_eid . registered_rlocs
 if 68 - 68: II111iiii * iIii1I11I1II1 - OoO0O00 - I1ii11iIi11i * II111iiii
 iiiIiIII = lisp_site_eid_lookup ( seid , group , False )
 if ( iiiIiIII == None ) : return ( iI1111Ii1I )
 if 94 - 94: II111iiii - iII111i % Ii1I + I1IiiI - ooOoO0o
 if 70 - 70: iII111i + I1IiiI . O0
 if 13 - 13: I1IiiI / I1IiiI
 if 51 - 51: I1IiiI . IiII + ooOoO0o . oO0o . o0oOOo0O0Ooo
 o0OOO0ooo = None
 O00OoO0o0Oo = [ ]
 for oo0OOOoO0OoO in iI1111Ii1I :
  if ( oo0OOOoO0OoO . is_rtr ( ) ) : continue
  if ( oo0OOOoO0OoO . rloc . is_private_address ( ) ) :
   oooO0OOO0o = copy . deepcopy ( oo0OOOoO0OoO )
   O00OoO0o0Oo . append ( oooO0OOO0o )
   continue
   if 93 - 93: IiII
  o0OOO0ooo = oo0OOOoO0OoO
  break
  if 80 - 80: oO0o * I1Ii111 - i1IIi - OoooooooOO
 if ( o0OOO0ooo == None ) : return ( iI1111Ii1I )
 o0OOO0ooo = o0OOO0ooo . rloc . print_address_no_iid ( )
 if 85 - 85: OoO0O00 / i1IIi * o0oOOo0O0Ooo / oO0o
 if 11 - 11: IiII + II111iiii
 if 37 - 37: O0
 if 98 - 98: IiII * OoooooooOO . iII111i
 ii111I = None
 for oo0OOOoO0OoO in iiiIiIII . registered_rlocs :
  if ( oo0OOOoO0OoO . is_rtr ( ) ) : continue
  if ( oo0OOOoO0OoO . rloc . is_private_address ( ) ) : continue
  ii111I = oo0OOOoO0OoO
  break
  if 26 - 26: OoooooooOO % I1ii11iIi11i - i11iIiiIii
 if ( ii111I == None ) : return ( iI1111Ii1I )
 ii111I = ii111I . rloc . print_address_no_iid ( )
 if 84 - 84: OoO0O00
 if 67 - 67: I1Ii111 + I1Ii111
 if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
 if 58 - 58: OoooooooOO . II111iiii . O0 % I1Ii111 / OoooooooOO
 I1111iii1ii11 = target_site_eid . site_id
 if ( I1111iii1ii11 == 0 ) :
  if ( ii111I == o0OOO0ooo ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( o0OOO0ooo ) )
   if 64 - 64: Oo0Ooo + oO0o . OoO0O00
   return ( O00OoO0o0Oo )
   if 67 - 67: I11i
  return ( iI1111Ii1I )
  if 91 - 91: OOooOOo / OoO0O00
  if 36 - 36: I1IiiI . iII111i * I1Ii111 . IiII % I1ii11iIi11i
  if 44 - 44: I11i % I1ii11iIi11i - OoooooooOO % iII111i
  if 60 - 60: IiII % oO0o
  if 11 - 11: I1Ii111 - II111iiii
  if 12 - 12: i11iIiiIii
  if 9 - 9: OOooOOo * I1ii11iIi11i + iIii1I11I1II1 / OoO0O00 * OoooooooOO
 if ( I1111iii1ii11 == iiiIiIII . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( I1111iii1ii11 ) )
  return ( O00OoO0o0Oo )
  if 91 - 91: i11iIiiIii % IiII + oO0o . I1IiiI - I1IiiI
 return ( iI1111Ii1I )
 if 62 - 62: Oo0Ooo * II111iiii + o0oOOo0O0Ooo . OoOoOO00
 if 94 - 94: Oo0Ooo / I1IiiI * iIii1I11I1II1 - OoO0O00
 if 96 - 96: ooOoO0o - OoooooooOO * iIii1I11I1II1 . IiII - O0
 if 7 - 7: iIii1I11I1II1 . OoO0O00
 if 88 - 88: i1IIi * II111iiii / i11iIiiIii % IiII . IiII
 if 93 - 93: OoOoOO00 * i1IIi . Ii1I
 if 2 - 2: i1IIi
 if 84 - 84: i1IIi / Ii1I + OoOoOO00 % Ii1I . oO0o
 if 74 - 74: OOooOOo - o0oOOo0O0Ooo - I1Ii111 - OoO0O00
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 iIOooOoo0 = [ ]
 iI1111Ii1I = [ ]
 if 3 - 3: IiII % O0 + iII111i % I11i % OoOoOO00
 if 92 - 92: ooOoO0o + I1IiiI
 if 19 - 19: OoO0O00 * ooOoO0o % I1ii11iIi11i
 if 21 - 21: OoO0O00 * I11i
 if 76 - 76: I1IiiI - I1ii11iIi11i / I1ii11iIi11i . o0oOOo0O0Ooo % OoooooooOO
 if 39 - 39: OoooooooOO % iII111i
 o0o0O0 = False
 oOOooOOo = False
 for oo0OOOoO0OoO in registered_rloc_set :
  if ( oo0OOOoO0OoO . priority != 254 ) : continue
  oOOooOOo |= True
  if ( oo0OOOoO0OoO . rloc . is_exact_match ( mr_source ) == False ) : continue
  o0o0O0 = True
  break
  if 9 - 9: I11i / I11i
  if 35 - 35: ooOoO0o * OoOoOO00 . I1ii11iIi11i . I1Ii111 * I1ii11iIi11i
  if 66 - 66: Oo0Ooo % OoOoOO00 % I11i - OoO0O00
  if 77 - 77: iII111i * I1Ii111
  if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
  if 34 - 34: OoooooooOO * i11iIiiIii
  if 33 - 33: II111iiii
 if ( oOOooOOo == False ) : return ( registered_rloc_set )
 if 59 - 59: iIii1I11I1II1 % I11i
 if 93 - 93: I1ii11iIi11i
 if 50 - 50: ooOoO0o % OoO0O00 % OoO0O00
 if 36 - 36: I1IiiI * O0 . IiII / I1Ii111
 if 15 - 15: I11i + iII111i
 if 79 - 79: i11iIiiIii * IiII % iII111i
 if 18 - 18: iIii1I11I1II1 - O0 . o0oOOo0O0Ooo % oO0o
 if 73 - 73: IiII + I11i % I1IiiI * iII111i . O0
 if 17 - 17: OoO0O00 * OoOoOO00 % O0 % iII111i / i1IIi
 if 100 - 100: i11iIiiIii
 ooO00Oo0o0OOo = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 71 - 71: I11i * OOooOOo
 if 92 - 92: o0oOOo0O0Ooo
 if 31 - 31: O0 . o0oOOo0O0Ooo . O0 * OoOoOO00 - OoO0O00
 if 80 - 80: II111iiii % oO0o
 if 48 - 48: OOooOOo . II111iiii * OOooOOo - I11i / iIii1I11I1II1 / i11iIiiIii
 for oo0OOOoO0OoO in registered_rloc_set :
  if ( ooO00Oo0o0OOo and oo0OOOoO0OoO . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and oo0OOOoO0OoO . priority == 255 ) : continue
  if ( multicast and oo0OOOoO0OoO . mpriority == 255 ) : continue
  if ( oo0OOOoO0OoO . priority == 254 ) :
   iIOooOoo0 . append ( oo0OOOoO0OoO )
  else :
   iI1111Ii1I . append ( oo0OOOoO0OoO )
   if 37 - 37: II111iiii % O0 + iIii1I11I1II1 - I1IiiI . I11i + I1ii11iIi11i
   if 14 - 14: ooOoO0o % iIii1I11I1II1 % ooOoO0o / IiII + OOooOOo
   if 14 - 14: Oo0Ooo
   if 79 - 79: I1ii11iIi11i % I1Ii111 % I11i - iII111i * OoOoOO00
   if 48 - 48: O0 + OoOoOO00 - O0
   if 79 - 79: ooOoO0o . OoOoOO00 / OoooooooOO - II111iiii
 if ( o0o0O0 ) : return ( iI1111Ii1I )
 if 48 - 48: Oo0Ooo
 if 59 - 59: OoO0O00 % o0oOOo0O0Ooo
 if 83 - 83: iII111i % iIii1I11I1II1 / OOooOOo - OoOoOO00
 if 98 - 98: I11i % oO0o . I1IiiI % OoOoOO00
 if 32 - 32: I1ii11iIi11i / Ii1I
 if 54 - 54: I11i - i11iIiiIii
 if 91 - 91: Ii1I - OoO0O00 - I1IiiI % OoO0O00 . o0oOOo0O0Ooo
 if 85 - 85: ooOoO0o . ooOoO0o % Oo0Ooo . OOooOOo + OOooOOo / I1IiiI
 if 69 - 69: i1IIi + II111iiii / Ii1I
 if 4 - 4: I11i * OoOoOO00 % o0oOOo0O0Ooo % ooOoO0o - I1ii11iIi11i
 iI1111Ii1I = [ ]
 for oo0OOOoO0OoO in registered_rloc_set :
  if ( oo0OOOoO0OoO . rloc . is_private_address ( ) ) : iI1111Ii1I . append ( oo0OOOoO0OoO )
  if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 * I11i * OoOoOO00
 iI1111Ii1I += iIOooOoo0
 return ( iI1111Ii1I )
 if 14 - 14: i11iIiiIii * I1IiiI % O0 % iIii1I11I1II1
 if 18 - 18: Oo0Ooo % OOooOOo + IiII
 if 28 - 28: OOooOOo . OoO0O00 / o0oOOo0O0Ooo + II111iiii / iIii1I11I1II1 * II111iiii
 if 83 - 83: II111iiii . OoOoOO00 - i11iIiiIii . OoOoOO00 . i1IIi % OoooooooOO
 if 47 - 47: II111iiii
 if 30 - 30: i1IIi . Oo0Ooo / o0oOOo0O0Ooo + IiII * OOooOOo
 if 26 - 26: Ii1I % O0 - i1IIi % iII111i * OoO0O00
 if 60 - 60: I1ii11iIi11i * iII111i / OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
 if 94 - 94: OoO0O00 . ooOoO0o
 if 25 - 25: I1Ii111 % OOooOOo
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 ooOo0ooo0o0 = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 ooOo0ooo0o0 . add ( reply_eid )
 return
 if 16 - 16: OoOoOO00 % iII111i . OOooOOo * iIii1I11I1II1 / oO0o . OoooooooOO
 if 13 - 13: oO0o / iII111i . oO0o * i11iIiiIii . iIii1I11I1II1
 if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
 if 65 - 65: OOooOOo * I11i * Oo0Ooo
 if 21 - 21: Ii1I . iIii1I11I1II1
 if 84 - 84: OOooOOo
 if 67 - 67: I1IiiI % OoO0O00 % o0oOOo0O0Ooo % IiII
 if 33 - 33: ooOoO0o % I1IiiI
 if 98 - 98: oO0o . o0oOOo0O0Ooo + II111iiii
 if 62 - 62: ooOoO0o - OoooooooOO / I1ii11iIi11i / iII111i - o0oOOo0O0Ooo
 if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
 if 9 - 9: iII111i * Oo0Ooo % iII111i % Oo0Ooo * II111iiii
 if 71 - 71: II111iiii + I1ii11iIi11i * II111iiii
 if 59 - 59: OoO0O00
 if 81 - 81: i11iIiiIii
def lisp_convert_reply_to_notify ( packet ) :
 if 57 - 57: Oo0Ooo * iIii1I11I1II1 - OoOoOO00 % iII111i % I1ii11iIi11i + Ii1I
 if 82 - 82: IiII * Oo0Ooo - iIii1I11I1II1 - i11iIiiIii
 if 85 - 85: OoooooooOO
 if 37 - 37: OoooooooOO + O0 + I1ii11iIi11i + IiII * iII111i
 IiIIi = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 IiIIi = socket . ntohl ( IiIIi ) & 0xff
 oOO000 = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 67 - 67: OoOoOO00 . OOooOOo / i1IIi % oO0o + OOooOOo / OOooOOo
 if 59 - 59: o0oOOo0O0Ooo - o0oOOo0O0Ooo
 if 95 - 95: I1ii11iIi11i + I1Ii111 . Ii1I + I1Ii111 + I11i - I1IiiI
 if 80 - 80: Oo0Ooo % iII111i - IiII % OoooooooOO
 ooo0OOoo = ( LISP_MAP_NOTIFY << 28 ) | IiIIi
 Ii1I1i1IiiI = struct . pack ( "I" , socket . htonl ( ooo0OOoo ) )
 iI1 = struct . pack ( "I" , 0 )
 if 73 - 73: IiII + IiII % OoO0O00 % i1IIi . IiII
 if 94 - 94: i1IIi . ooOoO0o
 if 40 - 40: Oo0Ooo . I1Ii111 + i11iIiiIii / OOooOOo
 if 98 - 98: I1IiiI * Oo0Ooo
 packet = Ii1I1i1IiiI + oOO000 + iI1 + packet
 return ( packet )
 if 9 - 9: O0 / i11iIiiIii . iIii1I11I1II1 . IiII
 if 14 - 14: OoOoOO00 . OOooOOo - Oo0Ooo + I1Ii111 % ooOoO0o
 if 95 - 95: OoO0O00 * II111iiii + i1IIi
 if 22 - 22: Ii1I / ooOoO0o % I11i + OoO0O00 . ooOoO0o
 if 61 - 61: O0 - iIii1I11I1II1 * Oo0Ooo . Ii1I + O0
 if 20 - 20: ooOoO0o / ooOoO0o - Ii1I - ooOoO0o
 if 93 - 93: O0 * OoOoOO00 * iIii1I11I1II1
 if 3 - 3: I1ii11iIi11i - O0
def lisp_notify_subscribers ( lisp_sockets , eid_record , eid , site ) :
 I11i11i1 = eid . print_prefix ( )
 if ( lisp_pubsub_cache . has_key ( I11i11i1 ) == False ) : return
 if 46 - 46: iII111i
 for ooOo0ooo0o0 in lisp_pubsub_cache [ I11i11i1 ] . values ( ) :
  III1iii1 = ooOo0ooo0o0 . itr
  IiI1iI1 = ooOo0ooo0o0 . port
  OO000o0 = red ( III1iii1 . print_address_no_iid ( ) , False )
  o0O00ooOo = bold ( "subscriber" , False )
  oooOOOO0oOo = "0x" + lisp_hex_string ( ooOo0ooo0o0 . xtr_id )
  oOO000 = "0x" + lisp_hex_string ( ooOo0ooo0o0 . nonce )
  if 95 - 95: o0oOOo0O0Ooo % ooOoO0o . OOooOOo . ooOoO0o % iII111i - OOooOOo
  lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( o0O00ooOo , OO000o0 , IiI1iI1 , oooOOOO0oOo , green ( I11i11i1 , False ) , oOO000 ) )
  if 53 - 53: i11iIiiIii % OoooooooOO . i11iIiiIii
  if 66 - 66: I1Ii111 * I1ii11iIi11i . Ii1I
  lisp_build_map_notify ( lisp_sockets , eid_record , [ I11i11i1 ] , 1 , III1iii1 ,
 IiI1iI1 , ooOo0ooo0o0 . nonce , 0 , 0 , 0 , site , False )
  ooOo0ooo0o0 . map_notify_count += 1
  if 28 - 28: oO0o - I1IiiI
 return
 if 42 - 42: i1IIi
 if 8 - 8: Ii1I - oO0o
 if 73 - 73: Oo0Ooo . i11iIiiIii % i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 . i11iIiiIii
 if 61 - 61: i11iIiiIii + I11i * i1IIi . OoO0O00 . OoO0O00 - oO0o
 if 52 - 52: OOooOOo / ooOoO0o + I1ii11iIi11i - I1IiiI . II111iiii
 if 83 - 83: Oo0Ooo * OOooOOo - iIii1I11I1II1
 if 18 - 18: o0oOOo0O0Ooo + Ii1I . iIii1I11I1II1
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 31 - 31: I1ii11iIi11i / I1IiiI % ooOoO0o . OoO0O00 / IiII . II111iiii
 if 20 - 20: IiII * I1Ii111
 if 11 - 11: I11i * OoO0O00 * OoO0O00 * I1ii11iIi11i * IiII
 if 42 - 42: I1Ii111 * I1Ii111 * OoO0O00 - oO0o
 lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl , xtr_id )
 if 96 - 96: Oo0Ooo
 iIiiIIi1i111iI = green ( reply_eid . print_prefix ( ) , False )
 III1iii1 = red ( itr_rloc . print_address_no_iid ( ) , False )
 o0ooOoOO0 = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( o0ooOoOO0 ,
 iIiiIIi1i111iI , III1iii1 , xtr_id ) )
 if 22 - 22: OoooooooOO . IiII - iIii1I11I1II1
 if 75 - 75: o0oOOo0O0Ooo % IiII . ooOoO0o
 if 99 - 99: OoO0O00 . OoOoOO00 / I1ii11iIi11i
 if 39 - 39: o0oOOo0O0Ooo
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 return
 if 45 - 45: ooOoO0o - I1Ii111 * iIii1I11I1II1
 if 6 - 6: ooOoO0o % I1Ii111 % ooOoO0o . Ii1I * Oo0Ooo . IiII
 if 100 - 100: i1IIi . Ii1I . o0oOOo0O0Ooo + Ii1I - i1IIi . I11i
 if 19 - 19: i11iIiiIii + I11i - IiII . iII111i * i1IIi
 if 66 - 66: ooOoO0o
 if 4 - 4: iII111i / iII111i * OOooOOo + o0oOOo0O0Ooo . I1Ii111 + II111iiii
 if 90 - 90: IiII * iII111i % OoOoOO00 . i11iIiiIii
 if 5 - 5: O0 * i1IIi / IiII
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 4 - 4: II111iiii
 if 60 - 60: ooOoO0o - II111iiii * OoO0O00 + oO0o - iII111i
 if 39 - 39: OoO0O00 % I1Ii111 * I11i * Ii1I
 if 84 - 84: Oo0Ooo / OoO0O00 - II111iiii - OoOoOO00 - O0
 if 18 - 18: oO0o * I11i / o0oOOo0O0Ooo - OoooooooOO
 if 21 - 21: O0 - OoooooooOO
 iIiiIIi1i111iI = map_request . target_eid
 oOooO00OOoO = map_request . target_group
 I11i11i1 = lisp_print_eid_tuple ( iIiiIIi1i111iI , oOooO00OOoO )
 iII1II1iI = map_request . itr_rlocs [ 0 ]
 oooOOOO0oOo = map_request . xtr_id
 oOO000 = map_request . nonce
 Ooo0oo0oO000 = LISP_NO_ACTION
 ooOo0ooo0o0 = map_request . subscribe_bit
 if 21 - 21: iII111i * o0oOOo0O0Ooo
 if 85 - 85: I1ii11iIi11i . OoOoOO00 . i1IIi % OOooOOo * I11i . I1Ii111
 if 26 - 26: I1Ii111 + Oo0Ooo + II111iiii % OoOoOO00 % OOooOOo
 if 40 - 40: I1ii11iIi11i + i1IIi
 if 9 - 9: OOooOOo
 oO00O0000 = True
 IIIiI1I = ( lisp_get_eid_hash ( iIiiIIi1i111iI ) != None )
 if ( IIIiI1I ) :
  I1ii1I11iIi = map_request . map_request_signature
  if ( I1ii1I11iIi == None ) :
   oO00O0000 = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 65 - 65: IiII / O0 * II111iiii + oO0o
  else :
   o00ooo0O = map_request . signature_eid
   OO0OoooO0 , OOOO0o , oO00O0000 = lisp_lookup_public_key ( o00ooo0O )
   if ( oO00O0000 ) :
    oO00O0000 = map_request . verify_map_request_sig ( OOOO0o )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( o00ooo0O . print_address ( ) , OO0OoooO0 . print_address ( ) ) )
    if 53 - 53: O0 / iIii1I11I1II1 % ooOoO0o + i11iIiiIii / OoooooooOO
    if 87 - 87: O0 . OOooOOo
   O00o = bold ( "passed" , False ) if oO00O0000 else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( O00o ) )
   if 12 - 12: i11iIiiIii / o0oOOo0O0Ooo + o0oOOo0O0Ooo / iIii1I11I1II1 / OoooooooOO / Oo0Ooo
   if 35 - 35: OoOoOO00 + II111iiii
   if 46 - 46: O0 / I1ii11iIi11i + OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
 if ( ooOo0ooo0o0 and oO00O0000 == False ) :
  ooOo0ooo0o0 = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
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
  if 95 - 95: II111iiii - IiII % IiII . o0oOOo0O0Ooo
  if 19 - 19: II111iiii . ooOoO0o . I11i - OoooooooOO / I1ii11iIi11i . I1Ii111
  if 57 - 57: II111iiii . I1Ii111 . i11iIiiIii / OoOoOO00 - O0
  if 56 - 56: OOooOOo / I1Ii111
 IIIIiII = iII1II1iI if ( iII1II1iI . afi == ecm_source . afi ) else ecm_source
 if 45 - 45: I1IiiI / iIii1I11I1II1 - OoOoOO00
 Ii1ii1 = lisp_site_eid_lookup ( iIiiIIi1i111iI , oOooO00OOoO , False )
 if 75 - 75: II111iiii
 if ( Ii1ii1 == None or Ii1ii1 . is_star_g ( ) ) :
  iii = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( iii ,
 green ( I11i11i1 , False ) ) )
  if 65 - 65: IiII / oO0o
  if 57 - 57: IiII + oO0o - IiII
  if 51 - 51: OoOoOO00 % IiII / iII111i - oO0o - OoO0O00 . iIii1I11I1II1
  if 61 - 61: OoO0O00
  lisp_send_negative_map_reply ( lisp_sockets , iIiiIIi1i111iI , oOooO00OOoO , oOO000 , iII1II1iI ,
 mr_sport , 15 , oooOOOO0oOo , ooOo0ooo0o0 )
  if 60 - 60: I1IiiI % O0 % OoooooooOO / Ii1I
  return ( [ iIiiIIi1i111iI , oOooO00OOoO , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 9 - 9: OoooooooOO / I11i % I11i * O0 / II111iiii . II111iiii
  if 40 - 40: II111iiii + OoooooooOO / iII111i % O0 + OOooOOo . ooOoO0o
 oooOoOoo0o = Ii1ii1 . print_eid_tuple ( )
 Oo00OOo = Ii1ii1 . site . site_name
 if 47 - 47: oO0o
 if 91 - 91: I1IiiI * O0 + OoooooooOO * i1IIi % I1ii11iIi11i . IiII
 if 67 - 67: I1IiiI * I11i
 if 43 - 43: IiII * Oo0Ooo / OoOoOO00 + I1IiiI - i11iIiiIii + II111iiii
 if 81 - 81: I11i / Oo0Ooo % Ii1I % OoO0O00
 if ( IIIiI1I == False and Ii1ii1 . require_signature ) :
  I1ii1I11iIi = map_request . map_request_signature
  o00ooo0O = map_request . signature_eid
  if ( I1ii1I11iIi == None or o00ooo0O . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( Oo00OOo ) )
   oO00O0000 = False
  else :
   o00ooo0O = map_request . signature_eid
   OO0OoooO0 , OOOO0o , oO00O0000 = lisp_lookup_public_key ( o00ooo0O )
   if ( oO00O0000 ) :
    oO00O0000 = map_request . verify_map_request_sig ( OOOO0o )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( o00ooo0O . print_address ( ) , OO0OoooO0 . print_address ( ) ) )
    if 87 - 87: O0 % II111iiii
    if 42 - 42: I1IiiI . i1IIi
   O00o = bold ( "passed" , False ) if oO00O0000 else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( O00o ) )
   if 98 - 98: o0oOOo0O0Ooo % I11i . Oo0Ooo * Oo0Ooo % iII111i
   if 37 - 37: OoO0O00 / I1Ii111 . I1Ii111 * i1IIi
   if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
   if 13 - 13: II111iiii
   if 36 - 36: iII111i - oO0o / Oo0Ooo / O0 . OoO0O00 . i1IIi
   if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
 if ( oO00O0000 and Ii1ii1 . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( Oo00OOo , green ( oooOoOoo0o , False ) , green ( I11i11i1 , False ) ) )
  if 98 - 98: oO0o . Oo0Ooo
  if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
  if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
  if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
  if 64 - 64: OoooooooOO + OOooOOo
  if 36 - 36: I1IiiI - Ii1I / I1ii11iIi11i + Oo0Ooo % I1ii11iIi11i
  if ( Ii1ii1 . accept_more_specifics == False ) :
   iIiiIIi1i111iI = Ii1ii1 . eid
   oOooO00OOoO = Ii1ii1 . group
   if 86 - 86: iIii1I11I1II1 * OoO0O00
   if 82 - 82: I1IiiI - OoO0O00 % o0oOOo0O0Ooo
   if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
   if 98 - 98: Oo0Ooo . II111iiii * I11i
   if 39 - 39: IiII * o0oOOo0O0Ooo + Ii1I - I11i
  O0000 = 1
  if ( Ii1ii1 . force_ttl != None ) :
   O0000 = Ii1ii1 . force_ttl | 0x80000000
   if 70 - 70: oO0o * ooOoO0o / ooOoO0o - Ii1I * Ii1I % OOooOOo
   if 91 - 91: OoO0O00 - OoO0O00 % O0
   if 67 - 67: ooOoO0o * i1IIi
   if 66 - 66: o0oOOo0O0Ooo - I1ii11iIi11i . OoOoOO00 / iII111i - Ii1I - i1IIi
   if 97 - 97: oO0o % iII111i - OOooOOo . OoooooooOO
  lisp_send_negative_map_reply ( lisp_sockets , iIiiIIi1i111iI , oOooO00OOoO , oOO000 , iII1II1iI ,
 mr_sport , O0000 , oooOOOO0oOo , ooOo0ooo0o0 )
  if 94 - 94: Oo0Ooo
  return ( [ iIiiIIi1i111iI , oOooO00OOoO , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 10 - 10: i11iIiiIii / I1ii11iIi11i . i1IIi + i1IIi * iII111i
  if 64 - 64: II111iiii % I1ii11iIi11i . OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i
  if 43 - 43: OoooooooOO * I1IiiI
  if 2 - 2: OOooOOo / oO0o + I1ii11iIi11i + i11iIiiIii % iIii1I11I1II1 . I1ii11iIi11i
  if 100 - 100: Oo0Ooo * ooOoO0o + Ii1I / iII111i * o0oOOo0O0Ooo
 i1IIiiIIiII1 = False
 oo0OO = ""
 O0O0o0Oo = False
 if ( Ii1ii1 . force_nat_proxy_reply ) :
  oo0OO = ", nat-forced"
  i1IIiiIIiII1 = True
  O0O0o0Oo = True
 elif ( Ii1ii1 . force_proxy_reply ) :
  oo0OO = ", forced"
  O0O0o0Oo = True
 elif ( Ii1ii1 . proxy_reply_requested ) :
  oo0OO = ", requested"
  O0O0o0Oo = True
 elif ( map_request . pitr_bit and Ii1ii1 . pitr_proxy_reply_drop ) :
  oo0OO = ", drop-to-pitr"
  Ooo0oo0oO000 = LISP_DROP_ACTION
 elif ( Ii1ii1 . proxy_reply_action != "" ) :
  Ooo0oo0oO000 = Ii1ii1 . proxy_reply_action
  oo0OO = ", forced, action {}" . format ( Ooo0oo0oO000 )
  Ooo0oo0oO000 = LISP_DROP_ACTION if ( Ooo0oo0oO000 == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 21 - 21: OOooOOo
  if 2 - 2: I11i - OOooOOo / o0oOOo0O0Ooo
  if 14 - 14: I11i + Oo0Ooo + i11iIiiIii - i1IIi . O0
  if 47 - 47: o0oOOo0O0Ooo / i1IIi * IiII
  if 50 - 50: I11i
  if 9 - 9: iII111i . OoOoOO00 * iII111i
  if 54 - 54: i11iIiiIii * I1IiiI / IiII - OoO0O00 % i1IIi
 iiI11i1i1 = False
 iiiIiiiII = None
 if ( O0O0o0Oo and lisp_policies . has_key ( Ii1ii1 . policy ) ) :
  III1I1Iii1 = lisp_policies [ Ii1ii1 . policy ]
  if ( III1I1Iii1 . match_policy_map_request ( map_request , mr_source ) ) : iiiIiiiII = III1I1Iii1
  if 17 - 17: OoO0O00 * i1IIi
  if ( iiiIiiiII ) :
   o0 = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( o0 ,
 III1I1Iii1 . policy_name , III1I1Iii1 . set_action ) )
  else :
   o0 = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( o0 ,
 III1I1Iii1 . policy_name ) )
   iiI11i1i1 = True
   if 50 - 50: OoOoOO00 + I11i
   if 56 - 56: OOooOOo * OOooOOo + I1IiiI % I1IiiI - I11i
   if 1 - 1: OoooooooOO . ooOoO0o - i1IIi
 if ( oo0OO != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( I11i11i1 , False ) , Oo00OOo , green ( oooOoOoo0o , False ) ,
  # I1ii11iIi11i - OOooOOo . iIii1I11I1II1 * O0 + OoooooooOO
 oo0OO ) )
  if 83 - 83: OoooooooOO + Oo0Ooo
  iI1111Ii1I = Ii1ii1 . registered_rlocs
  O0000 = 1440
  if ( i1IIiiIIiII1 ) :
   if ( Ii1ii1 . site_id != 0 ) :
    IIiiiiI1i = map_request . source_eid
    iI1111Ii1I = lisp_get_private_rloc_set ( Ii1ii1 , IIiiiiI1i , oOooO00OOoO )
    if 96 - 96: OoOoOO00 % II111iiii % iII111i + OoO0O00 + o0oOOo0O0Ooo
   if ( iI1111Ii1I == Ii1ii1 . registered_rlocs ) :
    ii111IIiI = ( Ii1ii1 . group . is_null ( ) == False )
    O00OoO0o0Oo = lisp_get_partial_rloc_set ( iI1111Ii1I , IIIIiII , ii111IIiI )
    if ( O00OoO0o0Oo != iI1111Ii1I ) :
     O0000 = 15
     iI1111Ii1I = O00OoO0o0Oo
     if 55 - 55: i1IIi
     if 99 - 99: I1Ii111 - Ii1I . iII111i * I1IiiI
     if 41 - 41: OoO0O00 + I1ii11iIi11i * II111iiii + i11iIiiIii + OoOoOO00
     if 57 - 57: I1IiiI + IiII . OoOoOO00 * iIii1I11I1II1 % OoooooooOO
     if 21 - 21: I11i
     if 36 - 36: IiII + OoO0O00
     if 66 - 66: iIii1I11I1II1 / oO0o
     if 36 - 36: o0oOOo0O0Ooo % I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo
  if ( Ii1ii1 . force_ttl != None ) :
   O0000 = Ii1ii1 . force_ttl | 0x80000000
   if 18 - 18: oO0o / i1IIi * I11i
   if 71 - 71: OoooooooOO - i11iIiiIii * i1IIi % OOooOOo - oO0o / o0oOOo0O0Ooo
   if 77 - 77: iIii1I11I1II1 / OoOoOO00
   if 59 - 59: Oo0Ooo % OOooOOo
   if 14 - 14: I11i . OoO0O00
   if 46 - 46: ooOoO0o
  if ( iiiIiiiII ) :
   if ( iiiIiiiII . set_record_ttl ) :
    O0000 = iiiIiiiII . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( O0000 ) )
    if 48 - 48: i1IIi * I1IiiI / i11iIiiIii
   if ( iiiIiiiII . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    Ooo0oo0oO000 = LISP_POLICY_DENIED_ACTION
    iI1111Ii1I = [ ]
   else :
    oOo0o0 = iiiIiiiII . set_policy_map_reply ( )
    if ( oOo0o0 ) : iI1111Ii1I = [ oOo0o0 ]
    if 40 - 40: IiII
    if 42 - 42: O0 / II111iiii
    if 88 - 88: Oo0Ooo
  if ( iiI11i1i1 ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   Ooo0oo0oO000 = LISP_POLICY_DENIED_ACTION
   iI1111Ii1I = [ ]
   if 20 - 20: OoooooooOO * i1IIi * IiII / OoooooooOO - Oo0Ooo / i11iIiiIii
   if 28 - 28: iIii1I11I1II1 % OOooOOo * I1IiiI
  iiiI11111 = Ii1ii1 . echo_nonce_capable
  if 28 - 28: O0 . OoOoOO00
  if 27 - 27: I1ii11iIi11i / II111iiii + O0 % I1ii11iIi11i
  if 72 - 72: I1IiiI - i1IIi
  if 11 - 11: iIii1I11I1II1 . OoO0O00 * Ii1I
  if ( oO00O0000 ) :
   oOoOO = Ii1ii1 . eid
   iiIIII1Iii = Ii1ii1 . group
  else :
   oOoOO = iIiiIIi1i111iI
   iiIIII1Iii = oOooO00OOoO
   Ooo0oo0oO000 = LISP_AUTH_FAILURE_ACTION
   iI1111Ii1I = [ ]
   if 1 - 1: II111iiii % OOooOOo * Ii1I
   if 23 - 23: OoooooooOO * OOooOOo
   if 24 - 24: IiII + I1IiiI / OoooooooOO
   if 8 - 8: II111iiii . I1Ii111 * OoOoOO00 / iII111i - Oo0Ooo
   if 17 - 17: iII111i . O0
   if 27 - 27: I11i + iIii1I11I1II1 - i11iIiiIii
  packet = lisp_build_map_reply ( oOoOO , iiIIII1Iii , iI1111Ii1I ,
 oOO000 , Ooo0oo0oO000 , O0000 , map_request , None , iiiI11111 , False )
  if 81 - 81: I11i + oO0o * iIii1I11I1II1 * IiII
  if ( ooOo0ooo0o0 ) :
   lisp_process_pubsub ( lisp_sockets , packet , oOoOO , iII1II1iI ,
 mr_sport , oOO000 , O0000 , oooOOOO0oOo )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , iII1II1iI , mr_sport )
   if 7 - 7: I11i - I1IiiI . iII111i + O0 / iIii1I11I1II1 - I1Ii111
   if 32 - 32: ooOoO0o
  return ( [ Ii1ii1 . eid , Ii1ii1 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 9 - 9: I1Ii111
  if 77 - 77: OoooooooOO * I1Ii111
  if 63 - 63: IiII * oO0o * iIii1I11I1II1
  if 18 - 18: II111iiii * o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
  if 40 - 40: oO0o - o0oOOo0O0Ooo * II111iiii
 oOo0O0oO = len ( Ii1ii1 . registered_rlocs )
 if ( oOo0O0oO == 0 ) :
  lprint ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" . format ( green ( I11i11i1 , False ) , Oo00OOo ,
  # O0
 green ( oooOoOoo0o , False ) ) )
  return ( [ Ii1ii1 . eid , Ii1ii1 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 7 - 7: iII111i
  if 14 - 14: i1IIi - i1IIi + iII111i
  if 92 - 92: ooOoO0o
  if 58 - 58: iII111i % I11i
  if 71 - 71: I1IiiI + OoO0O00 + IiII * I11i
 oOOO = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 67 - 67: iII111i - OoO0O00 + I11i + O0
 I1I = map_request . target_eid . hash_address ( oOOO )
 I1I %= oOo0O0oO
 i1iii = Ii1ii1 . registered_rlocs [ I1I ]
 if 85 - 85: I1IiiI * I11i % o0oOOo0O0Ooo * Ii1I
 if ( i1iii . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( I11i11i1 , False ) ,
  # ooOoO0o - i11iIiiIii + i1IIi - I1IiiI
 Oo00OOo , green ( oooOoOoo0o , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( I11i11i1 , False ) ,
  # i11iIiiIii * iII111i + Ii1I
 red ( i1iii . rloc . print_address ( ) , False ) , Oo00OOo ,
 green ( oooOoOoo0o , False ) ) )
  if 9 - 9: II111iiii
  if 39 - 39: iII111i + iIii1I11I1II1 / Ii1I . IiII
  if 35 - 35: ooOoO0o - oO0o
  if 24 - 24: OoooooooOO / i1IIi / Ii1I
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , i1iii . rloc , to_etr = True )
  if 77 - 77: iII111i / OoO0O00 % Oo0Ooo % OoOoOO00 % IiII / II111iiii
 return ( [ Ii1ii1 . eid , Ii1ii1 . group , LISP_DDT_ACTION_MS_ACK ] )
 if 82 - 82: I1Ii111 + O0 . I1IiiI / I1ii11iIi11i % II111iiii
 if 46 - 46: O0 - I1IiiI + OoooooooOO / OoOoOO00
 if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
 if 57 - 57: O0
 if 23 - 23: OoO0O00 / II111iiii . I1ii11iIi11i . O0
 if 13 - 13: I1ii11iIi11i
 if 32 - 32: OOooOOo / I11i + I1Ii111 / Oo0Ooo * OoooooooOO / II111iiii
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 8 - 8: OoO0O00
 if 17 - 17: iIii1I11I1II1 - Oo0Ooo
 if 25 - 25: O0 + I1ii11iIi11i
 if 53 - 53: OoooooooOO . Oo0Ooo
 iIiiIIi1i111iI = map_request . target_eid
 oOooO00OOoO = map_request . target_group
 I11i11i1 = lisp_print_eid_tuple ( iIiiIIi1i111iI , oOooO00OOoO )
 oOO000 = map_request . nonce
 Ooo0oo0oO000 = LISP_DDT_ACTION_NULL
 if 35 - 35: OOooOOo % i11iIiiIii % ooOoO0o . O0
 if 9 - 9: ooOoO0o + iII111i / i1IIi % Oo0Ooo - o0oOOo0O0Ooo / I1IiiI
 if 42 - 42: OOooOOo + oO0o % O0 * I1ii11iIi11i + i11iIiiIii
 if 16 - 16: i1IIi . I11i + OoO0O00 % Ii1I * IiII + I1IiiI
 if 96 - 96: II111iiii + O0 - II111iiii
 o0oO0 = None
 if ( lisp_i_am_ms ) :
  Ii1ii1 = lisp_site_eid_lookup ( iIiiIIi1i111iI , oOooO00OOoO , False )
  if ( Ii1ii1 == None ) : return
  if 12 - 12: oO0o . Oo0Ooo - i11iIiiIii / Ii1I - i1IIi / OOooOOo
  if ( Ii1ii1 . registered ) :
   Ooo0oo0oO000 = LISP_DDT_ACTION_MS_ACK
   O0000 = 1440
  else :
   iIiiIIi1i111iI , oOooO00OOoO , Ooo0oo0oO000 = lisp_ms_compute_neg_prefix ( iIiiIIi1i111iI , oOooO00OOoO )
   Ooo0oo0oO000 = LISP_DDT_ACTION_MS_NOT_REG
   O0000 = 1
   if 88 - 88: ooOoO0o % I1IiiI
 else :
  o0oO0 = lisp_ddt_cache_lookup ( iIiiIIi1i111iI , oOooO00OOoO , False )
  if ( o0oO0 == None ) :
   Ooo0oo0oO000 = LISP_DDT_ACTION_NOT_AUTH
   O0000 = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( I11i11i1 , False ) ) )
   if 66 - 66: i11iIiiIii % i11iIiiIii
  elif ( o0oO0 . is_auth_prefix ( ) ) :
   if 38 - 38: iIii1I11I1II1
   if 80 - 80: OoO0O00
   if 72 - 72: I11i * II111iiii
   if 82 - 82: I1Ii111 . OoO0O00 * II111iiii
   Ooo0oo0oO000 = LISP_DDT_ACTION_DELEGATION_HOLE
   O0000 = 15
   Oo00O = o0oO0 . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( Oo00O ,
   # II111iiii / OoO0O00
 green ( I11i11i1 , False ) ) )
   if 33 - 33: OoooooooOO / i1IIi . Ii1I
   if ( oOooO00OOoO . is_null ( ) ) :
    iIiiIIi1i111iI = lisp_ddt_compute_neg_prefix ( iIiiIIi1i111iI , o0oO0 ,
 lisp_ddt_cache )
   else :
    oOooO00OOoO = lisp_ddt_compute_neg_prefix ( oOooO00OOoO , o0oO0 ,
 lisp_ddt_cache )
    iIiiIIi1i111iI = lisp_ddt_compute_neg_prefix ( iIiiIIi1i111iI , o0oO0 ,
 o0oO0 . source_cache )
    if 96 - 96: OoOoOO00 / Oo0Ooo . II111iiii / ooOoO0o
   o0oO0 = None
  else :
   Oo00O = o0oO0 . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( Oo00O , green ( I11i11i1 , False ) ) )
   if 56 - 56: IiII - ooOoO0o % oO0o / Oo0Ooo * oO0o % O0
   O0000 = 1440
   if 71 - 71: iII111i / II111iiii - II111iiii / I1IiiI
   if 24 - 24: O0 . I1IiiI + IiII . IiII
   if 53 - 53: II111iiii + Ii1I * o0oOOo0O0Ooo
   if 47 - 47: Ii1I % OOooOOo . Oo0Ooo
   if 94 - 94: Ii1I - iIii1I11I1II1 + I1IiiI - iIii1I11I1II1 . o0oOOo0O0Ooo
   if 3 - 3: O0 / I11i + OoOoOO00 % IiII / i11iIiiIii
 IIii1i = lisp_build_map_referral ( iIiiIIi1i111iI , oOooO00OOoO , o0oO0 , Ooo0oo0oO000 , O0000 , oOO000 )
 oOO000 = map_request . nonce >> 32
 if ( map_request . nonce != 0 and oOO000 != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , IIii1i , ecm_source , port )
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
 i111IiI1III1 = 0
 if 47 - 47: o0oOOo0O0Ooo . i1IIi % OoO0O00 + OoooooooOO . OoO0O00
 if 35 - 35: Oo0Ooo - Oo0Ooo + I11i
 if 17 - 17: O0 / IiII % I11i * i1IIi
 if 75 - 75: Ii1I . o0oOOo0O0Ooo / I11i
 for i111IiI1III1 in range ( oooOOOO ) :
  I1i1iI = 1 << ( oooOOOO - i111IiI1III1 - 1 )
  if ( o0oOOooo0ooO & I1i1iI ) : break
  if 42 - 42: o0oOOo0O0Ooo
  if 76 - 76: i1IIi
 if ( i111IiI1III1 > neg_prefix . mask_len ) : neg_prefix . mask_len = i111IiI1III1
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
 iIiiIIi1i111iI , o0oOo , III111iiI = parms
 if 45 - 45: i1IIi - OoO0O00 % Oo0Ooo
 if ( o0oOo == None ) :
  if ( entry . eid . instance_id != iIiiIIi1i111iI . instance_id ) :
   return ( [ True , parms ] )
   if 42 - 42: ooOoO0o - I11i * iII111i
  if ( entry . eid . afi != iIiiIIi1i111iI . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( o0oOo ) == False ) :
   return ( [ True , parms ] )
   if 39 - 39: OOooOOo - I1ii11iIi11i % IiII % I1ii11iIi11i * II111iiii - Ii1I
   if 19 - 19: I11i % OoOoOO00 / OoO0O00 % I11i + o0oOOo0O0Ooo / iII111i
   if 35 - 35: ooOoO0o % I11i * I1ii11iIi11i
   if 10 - 10: OoO0O00 + OoooooooOO + I1Ii111
   if 57 - 57: Ii1I % Ii1I * Oo0Ooo % i11iIiiIii
   if 12 - 12: oO0o . Oo0Ooo . I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
 lisp_find_negative_mask_len ( iIiiIIi1i111iI , entry . eid , III111iiI )
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
  o0oO0 = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( o0oO0 == None ) :
   III111iiI . mask_len = III111iiI . host_mask_len ( )
   II . mask_len = II . host_mask_len ( )
   return ( [ III111iiI , II , LISP_DDT_ACTION_NOT_AUTH ] )
   if 34 - 34: ooOoO0o - OoooooooOO . o0oOOo0O0Ooo
  oo0ooO = lisp_sites_by_eid
  if ( o0oO0 . is_auth_prefix ( ) ) : o0oOo = o0oO0 . eid
 else :
  o0oO0 = lisp_ddt_cache . lookup_cache ( group , False )
  if ( o0oO0 == None ) :
   III111iiI . mask_len = III111iiI . host_mask_len ( )
   II . mask_len = II . host_mask_len ( )
   return ( [ III111iiI , II , LISP_DDT_ACTION_NOT_AUTH ] )
   if 68 - 68: OOooOOo % Oo0Ooo * ooOoO0o * OoO0O00 / iII111i
  if ( o0oO0 . is_auth_prefix ( ) ) : o0oOo = o0oO0 . group
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
  oo0ooO = o0oO0 . source_cache
  if 67 - 67: ooOoO0o . Ii1I - Oo0Ooo * iII111i . I11i - OOooOOo
  if 10 - 10: I11i
  if 37 - 37: o0oOOo0O0Ooo / I1IiiI * oO0o / II111iiii
  if 39 - 39: IiII - i1IIi - IiII - OoooooooOO - I1ii11iIi11i
  if 66 - 66: IiII + i1IIi
 Ooo0oo0oO000 = LISP_DDT_ACTION_DELEGATION_HOLE if ( o0oOo != None ) else LISP_DDT_ACTION_NOT_AUTH
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
 return ( [ III111iiI , II , Ooo0oo0oO000 ] )
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
 iIiiIIi1i111iI = map_request . target_eid
 oOooO00OOoO = map_request . target_group
 oOO000 = map_request . nonce
 if 29 - 29: I1Ii111
 if ( action == LISP_DDT_ACTION_MS_ACK ) : O0000 = 1440
 if 95 - 95: OoOoOO00 * II111iiii + I1ii11iIi11i - I11i . I11i % i11iIiiIii
 if 23 - 23: OoO0O00
 if 26 - 26: I1ii11iIi11i
 if 66 - 66: i11iIiiIii - i11iIiiIii / Ii1I * OOooOOo / IiII
 iIII = lisp_map_referral ( )
 iIII . record_count = 1
 iIII . nonce = oOO000
 IIii1i = iIII . encode ( )
 iIII . print_map_referral ( )
 if 67 - 67: I1IiiI . I1Ii111 - OoOoOO00
 o0Oo0oo = False
 if 18 - 18: O0
 if 26 - 26: i1IIi - iIii1I11I1II1
 if 8 - 8: I1Ii111
 if 86 - 86: i1IIi
 if 26 - 26: o0oOOo0O0Ooo % I1Ii111 / Oo0Ooo
 if 68 - 68: II111iiii / Oo0Ooo / Oo0Ooo
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( iIiiIIi1i111iI ,
 oOooO00OOoO )
  O0000 = 15
  if 1 - 1: Oo0Ooo
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : O0000 = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : O0000 = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : O0000 = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0000 = 0
 if 73 - 73: Ii1I * iIii1I11I1II1 / o0oOOo0O0Ooo - o0oOOo0O0Ooo / i1IIi
 o00OooO0ooO0 = False
 oOo0O0oO = 0
 o0oO0 = lisp_ddt_cache_lookup ( iIiiIIi1i111iI , oOooO00OOoO , False )
 if ( o0oO0 != None ) :
  oOo0O0oO = len ( o0oO0 . delegation_set )
  o00OooO0ooO0 = o0oO0 . is_ms_peer_entry ( )
  o0oO0 . map_referrals_sent += 1
  if 33 - 33: OOooOOo + I1ii11iIi11i + I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
  if 46 - 46: iII111i
  if 56 - 56: Oo0Ooo / II111iiii
  if 61 - 61: Ii1I - i1IIi / ooOoO0o - Oo0Ooo / IiII % Oo0Ooo
  if 53 - 53: OoooooooOO + iII111i % II111iiii * IiII
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : o0Oo0oo = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  o0Oo0oo = ( o00OooO0ooO0 == False )
  if 10 - 10: OoOoOO00 % I11i
  if 46 - 46: i1IIi % IiII
  if 45 - 45: I1ii11iIi11i / I1ii11iIi11i - OoO0O00
  if 54 - 54: Ii1I + I1IiiI * OoOoOO00 + oO0o
  if 10 - 10: Ii1I - I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
 iI1I1I1I11I11 = lisp_eid_record ( )
 iI1I1I1I11I11 . rloc_count = oOo0O0oO
 iI1I1I1I11I11 . authoritative = True
 iI1I1I1I11I11 . action = action
 iI1I1I1I11I11 . ddt_incomplete = o0Oo0oo
 iI1I1I1I11I11 . eid = eid_prefix
 iI1I1I1I11I11 . group = group_prefix
 iI1I1I1I11I11 . record_ttl = O0000
 if 75 - 75: OOooOOo . ooOoO0o
 IIii1i += iI1I1I1I11I11 . encode ( )
 iI1I1I1I11I11 . print_record ( "  " , True )
 if 32 - 32: i1IIi / I11i + iIii1I11I1II1 . OOooOOo
 if 67 - 67: iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
 if 51 - 51: I1IiiI + O0
 if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
 if ( oOo0O0oO != 0 ) :
  for IIiIi1I1Ii11 in o0oO0 . delegation_set :
   I1i11 = lisp_rloc_record ( )
   I1i11 . rloc = IIiIi1I1Ii11 . delegate_address
   I1i11 . priority = IIiIi1I1Ii11 . priority
   I1i11 . weight = IIiIi1I1Ii11 . weight
   I1i11 . mpriority = 255
   I1i11 . mweight = 0
   I1i11 . reach_bit = True
   IIii1i += I1i11 . encode ( )
   I1i11 . print_record ( "    " )
   if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
   if 85 - 85: OoOoOO00
   if 57 - 57: Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
   if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
   if 72 - 72: Ii1I
   if 22 - 22: o0oOOo0O0Ooo / OoO0O00 + OoOoOO00 + Ii1I . II111iiii * I11i
   if 85 - 85: i11iIiiIii / I11i
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , IIii1i , ecm_source , port )
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
 Ooo0oo0oO000 = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
 if 63 - 63: OoOoOO00 % IiII . iII111i
 if 44 - 44: I1IiiI
 if 25 - 25: oO0o
 if 100 - 100: I1IiiI / IiII + OoO0O00 . iII111i
 if ( lisp_get_eid_hash ( eid ) != None ) :
  Ooo0oo0oO000 = LISP_SEND_MAP_REQUEST_ACTION
  if 39 - 39: OoooooooOO * OOooOOo - OoO0O00
  if 3 - 3: I11i . i11iIiiIii % Oo0Ooo % II111iiii . I11i
 IIii1i = lisp_build_map_reply ( eid , group , [ ] , nonce , Ooo0oo0oO000 , ttl , None ,
 None , False , False )
 if 88 - 88: iIii1I11I1II1 . OOooOOo % iII111i
 if 72 - 72: ooOoO0o + i11iIiiIii / i1IIi
 if 64 - 64: OOooOOo - OOooOOo
 if 42 - 42: i1IIi / ooOoO0o . I1Ii111 % OoOoOO00
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , IIii1i , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , IIii1i , dest , port )
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
 oOO000 = mr . nonce
 if 28 - 28: IiII - i1IIi - I1Ii111 % Ii1I - IiII
 if 73 - 73: iIii1I11I1II1 . iIii1I11I1II1 + oO0o % i11iIiiIii . IiII
 if 33 - 33: IiII - OOooOOo / i11iIiiIii * iIii1I11I1II1
 if 2 - 2: i11iIiiIii % ooOoO0o
 if 56 - 56: IiII % ooOoO0o + I1IiiI % I11i - OOooOOo
 if ( mr . last_request_sent_to ) :
  Oo = mr . last_request_sent_to . print_address ( )
  iIii = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( iIii and iIii . referral_set . has_key ( Oo ) ) :
   iIii . referral_set [ Oo ] . no_responses += 1
   if 64 - 64: ooOoO0o
   if 30 - 30: OoO0O00 + o0oOOo0O0Ooo / iIii1I11I1II1
   if 69 - 69: IiII - OoooooooOO + iII111i + iII111i - Ii1I
   if 27 - 27: I1ii11iIi11i % Oo0Ooo * iIii1I11I1II1 * O0 / I11i * Oo0Ooo
   if 97 - 97: IiII % Oo0Ooo % OoOoOO00
   if 87 - 87: i11iIiiIii . oO0o * I1IiiI * I1Ii111
   if 57 - 57: iIii1I11I1II1 / i11iIiiIii / IiII + I1ii11iIi11i % I1IiiI
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( oO0O0oo0o0oO , False ) , lisp_hex_string ( oOO000 ) ) )
  if 80 - 80: iIii1I11I1II1
  mr . dequeue_map_request ( )
  return
  if 23 - 23: II111iiii . ooOoO0o % I1Ii111
  if 39 - 39: OoooooooOO
 mr . retry_count += 1
 if 10 - 10: Oo0Ooo * iII111i
 IiII1iiI = green ( iI1ii111i1i , False )
 OooOOOoOoo0O0 = green ( oO0O0oo0o0oO , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # I1IiiI + o0oOOo0O0Ooo + I1IiiI . I1ii11iIi11i - I1IiiI
 red ( mr . itr . print_address ( ) , False ) , IiII1iiI , OooOOOoOoo0O0 ,
 lisp_hex_string ( oOO000 ) ) )
 if 97 - 97: oO0o + iII111i * OoOoOO00 % o0oOOo0O0Ooo
 if 57 - 57: OoooooooOO . Oo0Ooo + OoooooooOO + I1Ii111 + iIii1I11I1II1 + OoOoOO00
 if 69 - 69: OoO0O00
 if 24 - 24: i1IIi + o0oOOo0O0Ooo / oO0o - I1IiiI % I1IiiI
 lisp_send_ddt_map_request ( mr , False )
 if 100 - 100: Ii1I % I1Ii111 . iII111i % IiII * IiII . OoOoOO00
 if 68 - 68: iIii1I11I1II1
 if 30 - 30: I11i . I1ii11iIi11i - i1IIi / i1IIi + IiII . oO0o
 if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
 if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
 if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
 if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
 if 45 - 45: iIii1I11I1II1 . o0oOOo0O0Ooo % I1IiiI
 if 10 - 10: I1IiiI / i1IIi * o0oOOo0O0Ooo + Oo0Ooo - OoOoOO00 % iII111i
 if 88 - 88: Ii1I % Ii1I
 if 29 - 29: OOooOOo % I1ii11iIi11i
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 57 - 57: I1ii11iIi11i - OoOoOO00 + IiII
 if 58 - 58: OOooOOo % I1IiiI / oO0o . ooOoO0o . OoO0O00 / IiII
 if 72 - 72: ooOoO0o + ooOoO0o + o0oOOo0O0Ooo - o0oOOo0O0Ooo % Ii1I
 if 52 - 52: I11i % i1IIi . I1ii11iIi11i
 o0O0o0OOo = [ ]
 for OOii1I1I1i in referral . referral_set . values ( ) :
  if ( OOii1I1I1i . updown == False ) : continue
  if ( len ( o0O0o0OOo ) == 0 or o0O0o0OOo [ 0 ] . priority == OOii1I1I1i . priority ) :
   o0O0o0OOo . append ( OOii1I1I1i )
  elif ( o0O0o0OOo [ 0 ] . priority > OOii1I1I1i . priority ) :
   o0O0o0OOo = [ ]
   o0O0o0OOo . append ( OOii1I1I1i )
   if 96 - 96: OOooOOo * I11i - oO0o - Ii1I % I1ii11iIi11i . oO0o
   if 3 - 3: I11i
   if 18 - 18: I1ii11iIi11i % I1IiiI + I1IiiI / II111iiii + I1ii11iIi11i
 oOO00oOoo0 = len ( o0O0o0OOo )
 if ( oOO00oOoo0 == 0 ) : return ( None )
 if 52 - 52: OoooooooOO / IiII / IiII
 I1I = dest_eid . hash_address ( source_eid )
 I1I = I1I % oOO00oOoo0
 return ( o0O0o0OOo [ I1I ] )
 if 30 - 30: ooOoO0o % I11i + II111iiii . IiII - I1IiiI * OoOoOO00
 if 59 - 59: I1IiiI
 if 19 - 19: i1IIi * I1Ii111
 if 33 - 33: OOooOOo + OoOoOO00 % I1Ii111 / iIii1I11I1II1 % Ii1I % o0oOOo0O0Ooo
 if 49 - 49: OOooOOo
 if 1 - 1: I1ii11iIi11i - OoOoOO00 / oO0o + OoooooooOO % o0oOOo0O0Ooo
 if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 III1I111I1i1I = mr . lisp_sockets
 oOO000 = mr . nonce
 III1iii1 = mr . itr
 I1iio0OoOO00Ooo00 = mr . mr_source
 I11i11i1 = mr . print_eid_tuple ( )
 if 75 - 75: OOooOOo / II111iiii - Oo0Ooo + I1Ii111
 if 42 - 42: OoooooooOO * II111iiii + Ii1I % OoO0O00 / I1Ii111
 if 11 - 11: ooOoO0o / Oo0Ooo + i1IIi / IiII
 if 4 - 4: iII111i - Oo0Ooo
 if 100 - 100: OOooOOo . i1IIi
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( I11i11i1 , False ) , lisp_hex_string ( oOO000 ) ) )
  if 15 - 15: O0 % Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o * iII111i % O0
  mr . dequeue_map_request ( )
  return
  if 31 - 31: i1IIi . Ii1I - OoooooooOO * I11i * ooOoO0o % oO0o
  if 61 - 61: I1Ii111 . Ii1I * I1ii11iIi11i
  if 59 - 59: OoOoOO00 + Oo0Ooo . I1ii11iIi11i - Ii1I
  if 48 - 48: I1Ii111 % Ii1I + I1IiiI * OoooooooOO % OoOoOO00 % i11iIiiIii
  if 13 - 13: iII111i % i1IIi
  if 13 - 13: iII111i / OoooooooOO + Ii1I / iII111i
 if ( send_to_root ) :
  i111IiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  IIiI1I = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( I11i11i1 , False ) ) )
 else :
  i111IiI = mr . eid
  IIiI1I = mr . group
  if 56 - 56: i1IIi
  if 37 - 37: I1IiiI % i11iIiiIii + OoO0O00 * OOooOOo . o0oOOo0O0Ooo % IiII
  if 18 - 18: Oo0Ooo % IiII . OoOoOO00 - IiII + I1Ii111 + oO0o
  if 31 - 31: OOooOOo + OoOoOO00 * OOooOOo + OoOoOO00 / o0oOOo0O0Ooo . iIii1I11I1II1
  if 1 - 1: I1Ii111 * i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / Oo0Ooo
 IIiii1I1 = lisp_referral_cache_lookup ( i111IiI , IIiI1I , False )
 if ( IIiii1I1 == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( III1I111I1i1I , i111IiI , IIiI1I ,
 oOO000 , III1iii1 , mr . sport , 15 , None , False )
  return
  if 43 - 43: II111iiii % O0 + o0oOOo0O0Ooo / Ii1I
  if 55 - 55: Oo0Ooo / Oo0Ooo - I1IiiI
 oO0Oo0O0o00 = IIiii1I1 . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( oO0Oo0O0o00 ,
 IIiii1I1 . print_referral_type ( ) ) )
 if 92 - 92: I1Ii111 . I1IiiI
 OOii1I1I1i = lisp_get_referral_node ( IIiii1I1 , I1iio0OoOO00Ooo00 , mr . eid )
 if ( OOii1I1I1i == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( III1I111I1i1I , IIiii1I1 . eid ,
 IIiii1I1 . group , oOO000 , III1iii1 , mr . sport , 1 , None , False )
  return
  if 19 - 19: IiII / II111iiii + I1IiiI
  if 33 - 33: oO0o
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( OOii1I1I1i . referral_address . print_address ( ) ,
 # I1Ii111
 IIiii1I1 . print_referral_type ( ) , green ( I11i11i1 , False ) ,
 lisp_hex_string ( oOO000 ) ) )
 if 1 - 1: i11iIiiIii % I1Ii111 + I1ii11iIi11i
 if 17 - 17: Oo0Ooo
 if 59 - 59: OoO0O00 * o0oOOo0O0Ooo . I11i
 if 32 - 32: I1ii11iIi11i
 iiIiIIIIi11II = ( IIiii1I1 . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 IIiii1I1 . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( III1I111I1i1I , mr . packet , I1iio0OoOO00Ooo00 , mr . sport , mr . eid ,
 OOii1I1I1i . referral_address , to_ms = iiIiIIIIi11II , ddt = True )
 if 37 - 37: iIii1I11I1II1
 if 64 - 64: II111iiii * oO0o % I1Ii111 + i1IIi
 if 57 - 57: OoOoOO00 + OoOoOO00
 if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
 mr . last_request_sent_to = OOii1I1I1i . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 OOii1I1I1i . map_requests_sent += 1
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
 iIiiIIi1i111iI = map_request . target_eid
 oOooO00OOoO = map_request . target_group
 oO0O0oo0o0oO = map_request . print_eid_tuple ( )
 iI1ii111i1i = mr_source . print_address ( )
 oOO000 = map_request . nonce
 if 82 - 82: Ii1I * OOooOOo % ooOoO0o / OoO0O00 - Oo0Ooo . I1Ii111
 IiII1iiI = green ( iI1ii111i1i , False )
 OooOOOoOoo0O0 = green ( oO0O0oo0o0oO , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # ooOoO0o % OOooOOo % OoO0O00 . OoooooooOO / OoO0O00 * iIii1I11I1II1
 red ( ecm_source . print_address ( ) , False ) , IiII1iiI , OooOOOoOoo0O0 ,
 lisp_hex_string ( oOO000 ) ) )
 if 52 - 52: i11iIiiIii + OOooOOo - I11i
 if 43 - 43: OoOoOO00
 if 32 - 32: ooOoO0o * OoO0O00 * oO0o / I1ii11iIi11i
 if 72 - 72: I1ii11iIi11i * ooOoO0o % I1IiiI % OoOoOO00
 O0O0OOoO00 = lisp_ddt_map_request ( lisp_sockets , packet , iIiiIIi1i111iI , oOooO00OOoO , oOO000 )
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
 OO0o0 = packet
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
  packet = OO0o0
  iIiiIIi1i111iI , oOooO00OOoO , oOii = lisp_ms_process_map_request ( lisp_sockets ,
 OO0o0 , I1IIIiii1 , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , I1IIIiii1 , ecm_source ,
 ecm_port , oOii , iIiiIIi1i111iI , oOooO00OOoO )
   if 55 - 55: Oo0Ooo / I1IiiI
  return
  if 17 - 17: OOooOOo % iII111i . OOooOOo / II111iiii / II111iiii % Ii1I
  if 44 - 44: Oo0Ooo
  if 29 - 29: O0 + OoooooooOO
  if 82 - 82: O0 . I1Ii111 - IiII
  if 37 - 37: i11iIiiIii
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , OO0o0 , I1IIIiii1 ,
 ecm_source , mr_port , mr_source )
  if 67 - 67: ooOoO0o . Oo0Ooo
  if 15 - 15: OoO0O00 . oO0o - o0oOOo0O0Ooo
  if 28 - 28: OOooOOo * OoOoOO00 + OoooooooOO . OOooOOo / oO0o / OoOoOO00
  if 94 - 94: OoO0O00 / i1IIi . OoO0O00 . I1Ii111 + OoO0O00
  if 30 - 30: o0oOOo0O0Ooo + iIii1I11I1II1 - II111iiii - ooOoO0o + OoOoOO00 - II111iiii
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = OO0o0
  lisp_ddt_process_map_request ( lisp_sockets , I1IIIiii1 , ecm_source ,
 ecm_port )
  if 69 - 69: oO0o / O0 / I1IiiI + OoooooooOO * I11i * IiII
 return
 if 41 - 41: ooOoO0o % i11iIiiIii
 if 69 - 69: IiII - oO0o
 if 21 - 21: Oo0Ooo / I1Ii111
 if 72 - 72: OoOoOO00 . i11iIiiIii
 if 25 - 25: i1IIi
 if 69 - 69: OOooOOo / Ii1I
 if 67 - 67: i11iIiiIii . II111iiii + OoooooooOO % o0oOOo0O0Ooo + IiII * i1IIi
 if 53 - 53: oO0o * OoooooooOO + II111iiii . IiII * I1ii11iIi11i
def lisp_store_mr_stats ( source , nonce ) :
 O0O0OOoO00 = lisp_get_map_resolver ( source , None )
 if ( O0O0OOoO00 == None ) : return
 if 55 - 55: OoOoOO00
 if 27 - 27: I1IiiI
 if 81 - 81: Oo0Ooo
 if 43 - 43: i1IIi * O0 + ooOoO0o + OoO0O00
 O0O0OOoO00 . neg_map_replies_received += 1
 O0O0OOoO00 . last_reply = lisp_get_timestamp ( )
 if 99 - 99: IiII . OoOoOO00
 if 64 - 64: I1Ii111
 if 96 - 96: Ii1I
 if 100 - 100: ooOoO0o
 if ( ( O0O0OOoO00 . neg_map_replies_received % 100 ) == 0 ) : O0O0OOoO00 . total_rtt = 0
 if 43 - 43: Ii1I * ooOoO0o + O0 . II111iiii
 if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
 if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
 if 5 - 5: OoooooooOO + ooOoO0o - II111iiii . i11iIiiIii / oO0o - ooOoO0o
 if ( O0O0OOoO00 . last_nonce == nonce ) :
  O0O0OOoO00 . total_rtt += ( time . time ( ) - O0O0OOoO00 . last_used )
  O0O0OOoO00 . last_nonce = 0
  if 3 - 3: iII111i
 if ( ( O0O0OOoO00 . neg_map_replies_received % 10 ) == 0 ) : O0O0OOoO00 . last_nonce = 0
 return
 if 74 - 74: i11iIiiIii + OoooooooOO . OOooOOo
 if 29 - 29: IiII % OoO0O00
 if 53 - 53: OoooooooOO - OoOoOO00 / IiII - I1Ii111
 if 16 - 16: iIii1I11I1II1 / OOooOOo + I1IiiI * II111iiii . OOooOOo
 if 68 - 68: IiII * IiII + oO0o / o0oOOo0O0Ooo
 if 41 - 41: OoOoOO00 - O0
 if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl , itr_in_ts ) :
 global lisp_map_cache
 if 53 - 53: ooOoO0o + oO0o - II111iiii
 i1i11i = lisp_map_reply ( )
 packet = i1i11i . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
 i1i11i . print_map_reply ( )
 if 6 - 6: iIii1I11I1II1 + oO0o
 if 8 - 8: I1ii11iIi11i + o0oOOo0O0Ooo
 if 29 - 29: Ii1I . OOooOOo
 if 59 - 59: O0 . OoO0O00
 I1iio0O0o00oO0ooo = None
 for IiIIi1IiiIiI in range ( i1i11i . record_count ) :
  iI1I1I1I11I11 = lisp_eid_record ( )
  packet = iI1I1I1I11I11 . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 6 - 6: iIii1I11I1II1 . O0 . oO0o + I1ii11iIi11i
  iI1I1I1I11I11 . print_record ( "  " , False )
  if 32 - 32: I1IiiI / OOooOOo . i11iIiiIii - IiII . iII111i . Ii1I
  if 34 - 34: i1IIi % iII111i + Oo0Ooo * OoOoOO00 + OoO0O00
  if 37 - 37: I1Ii111 / OoooooooOO
  if 19 - 19: Ii1I - O0 + I1IiiI + OoooooooOO + ooOoO0o - Oo0Ooo
  if 45 - 45: I1IiiI . OoOoOO00 . OoOoOO00
  if ( iI1I1I1I11I11 . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , i1i11i . nonce )
   if 20 - 20: OoOoOO00
   if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
  OO00o0o0oo = ( iI1I1I1I11I11 . group . is_null ( ) == False )
  if 73 - 73: II111iiii
  if 81 - 81: I1IiiI + OoO0O00
  if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
  if 32 - 32: o0oOOo0O0Ooo - iII111i + i11iIiiIii / ooOoO0o . OoOoOO00 . IiII
  if 9 - 9: iIii1I11I1II1
  if ( lisp_decent_push_configured ) :
   Ooo0oo0oO000 = iI1I1I1I11I11 . action
   if ( OO00o0o0oo and Ooo0oo0oO000 == LISP_DROP_ACTION ) :
    if ( iI1I1I1I11I11 . eid . is_local ( ) ) : continue
    if 66 - 66: iIii1I11I1II1
    if 13 - 13: O0 / ooOoO0o
    if 64 - 64: i11iIiiIii + I1IiiI / Oo0Ooo - iII111i
    if 26 - 26: I1ii11iIi11i
    if 67 - 67: I1Ii111 * iIii1I11I1II1 / O0 + OoO0O00 * iIii1I11I1II1 % II111iiii
    if 13 - 13: Ii1I / ooOoO0o / iII111i % II111iiii * I1IiiI * II111iiii
    if 40 - 40: Ii1I / i1IIi . iII111i
  if ( iI1I1I1I11I11 . eid . is_null ( ) ) : continue
  if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
  if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
  if 85 - 85: I1IiiI + i1IIi % I1Ii111
  if 76 - 76: i11iIiiIii % i11iIiiIii
  if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
  if ( OO00o0o0oo ) :
   O0oOO0OOO = lisp_map_cache_lookup ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group )
  else :
   O0oOO0OOO = lisp_map_cache . lookup_cache ( iI1I1I1I11I11 . eid , True )
   if 69 - 69: O0 % I1ii11iIi11i
  ooOOO0ooo000OOO = ( O0oOO0OOO == None )
  if 4 - 4: Oo0Ooo - Oo0Ooo * OOooOOo / iII111i
  if 49 - 49: ooOoO0o . i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + OoO0O00
  if 65 - 65: I1ii11iIi11i + Ii1I / i11iIiiIii * I1Ii111 + OoooooooOO
  if 7 - 7: Oo0Ooo % o0oOOo0O0Ooo
  if 40 - 40: oO0o * IiII
  if ( O0oOO0OOO == None ) :
   iiIi111I1 , I11Iii1iIII1i , II1ioOO0Oo = lisp_allow_gleaning ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group ,
 None )
   if ( iiIi111I1 ) : continue
  else :
   if ( O0oOO0OOO . gleaned ) : continue
   if 39 - 39: IiII - o0oOOo0O0Ooo - I11i - Oo0Ooo - Ii1I
   if 9 - 9: ooOoO0o
   if 83 - 83: oO0o - iIii1I11I1II1 * iII111i
   if 17 - 17: I1IiiI . OoOoOO00
   if 14 - 14: OOooOOo
  iI1111Ii1I = [ ]
  for O0OO00 in range ( iI1I1I1I11I11 . rloc_count ) :
   I1i11 = lisp_rloc_record ( )
   I1i11 . keys = i1i11i . keys
   packet = I1i11 . decode ( packet , i1i11i . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 96 - 96: Ii1I / OoOoOO00
   I1i11 . print_record ( "    " )
   if 71 - 71: OOooOOo / i1IIi
   ii11iiiI1iII = None
   if ( O0oOO0OOO ) : ii11iiiI1iII = O0oOO0OOO . get_rloc ( I1i11 . rloc )
   if ( ii11iiiI1iII ) :
    oOo0o0 = ii11iiiI1iII
   else :
    oOo0o0 = lisp_rloc ( )
    if 7 - 7: I1IiiI / OOooOOo * iIii1I11I1II1 * Ii1I * i1IIi
    if 87 - 87: IiII * Oo0Ooo - OOooOOo * OoOoOO00
    if 61 - 61: Oo0Ooo - OoooooooOO % I1ii11iIi11i / i1IIi + O0 % ooOoO0o
    if 79 - 79: I1ii11iIi11i
    if 9 - 9: IiII . O0
    if 66 - 66: i11iIiiIii
    if 33 - 33: i11iIiiIii % OoO0O00 * I1ii11iIi11i
   IiI1iI1 = oOo0o0 . store_rloc_from_record ( I1i11 , i1i11i . nonce ,
 source )
   oOo0o0 . echo_nonce_capable = i1i11i . echo_nonce_capable
   if 96 - 96: I11i % OoooooooOO * I11i . IiII / I1Ii111
   if ( oOo0o0 . echo_nonce_capable ) :
    oo0o00OO = oOo0o0 . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , oo0o00OO ) == None ) :
     lisp_echo_nonce ( oo0o00OO )
     if 56 - 56: I1IiiI - iII111i % Ii1I . I1ii11iIi11i % i1IIi
     if 84 - 84: OoOoOO00
     if 99 - 99: OoO0O00 - OoOoOO00 - i1IIi / OoO0O00 * I1ii11iIi11i * iIii1I11I1II1
     if 65 - 65: iII111i - O0 / i1IIi . I1Ii111
     if 85 - 85: o0oOOo0O0Ooo % Ii1I
     if 81 - 81: oO0o / OoO0O00 * i1IIi % iIii1I11I1II1
   if ( oOo0o0 . json ) :
    if ( lisp_is_json_telemetry ( oOo0o0 . json . json_string ) ) :
     I1IIi = oOo0o0 . json . json_string
     I1IIi = lisp_encode_telemetry ( I1IIi , ii = itr_in_ts )
     oOo0o0 . json . json_string = I1IIi
     if 23 - 23: II111iiii . II111iiii
     if 17 - 17: i11iIiiIii / IiII * I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - iIii1I11I1II1
     if 21 - 21: OOooOOo % Ii1I
     if 3 - 3: OOooOOo / ooOoO0o / I1Ii111 . I11i
     if 54 - 54: I1ii11iIi11i - I1IiiI . OoOoOO00
     if 36 - 36: OoO0O00 * I1IiiI / iII111i
     if 95 - 95: Ii1I . Oo0Ooo
     if 42 - 42: IiII . i1IIi % O0 * ooOoO0o - OOooOOo % ooOoO0o
     if 99 - 99: i1IIi + OoOoOO00 - iII111i % II111iiii
     if 6 - 6: ooOoO0o - I1Ii111 . OoOoOO00
   if ( i1i11i . rloc_probe and I1i11 . probe_bit ) :
    if ( oOo0o0 . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( oOo0o0 , source , IiI1iI1 ,
 i1i11i , ttl )
     if 64 - 64: iII111i + I1ii11iIi11i
     if 88 - 88: I1Ii111 / i11iIiiIii - O0 . II111iiii / II111iiii * II111iiii
     if 56 - 56: Oo0Ooo / I1IiiI % I1Ii111 % I1ii11iIi11i * I1IiiI - IiII
     if 39 - 39: oO0o + iII111i . I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + OOooOOo
     if 61 - 61: ooOoO0o / I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * iII111i
     if 94 - 94: I1IiiI / I11i
   iI1111Ii1I . append ( oOo0o0 )
   if 100 - 100: Ii1I % OoO0O00 % OoooooooOO / II111iiii * I1Ii111
   if 64 - 64: I1Ii111 * OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / Oo0Ooo
   if 50 - 50: OOooOOo % i11iIiiIii
   if 99 - 99: IiII
   if ( lisp_data_plane_security and oOo0o0 . rloc_recent_rekey ( ) ) :
    I1iio0O0o00oO0ooo = oOo0o0
    if 87 - 87: IiII
    if 35 - 35: oO0o . O0 . Ii1I / ooOoO0o
    if 36 - 36: i11iIiiIii . II111iiii . I11i . II111iiii
    if 36 - 36: Ii1I + ooOoO0o / Oo0Ooo % Oo0Ooo
    if 2 - 2: oO0o - Oo0Ooo * OoO0O00 . ooOoO0o . OOooOOo - oO0o
    if 74 - 74: o0oOOo0O0Ooo
    if 18 - 18: Oo0Ooo % OOooOOo / OOooOOo . I1IiiI + i1IIi . I1IiiI
    if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
    if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
    if 6 - 6: O0 * I1Ii111 - II111iiii
    if 60 - 60: oO0o % oO0o
  if ( i1i11i . rloc_probe == False and lisp_nat_traversal ) :
   O00OoO0o0Oo = [ ]
   o0Oo0 = [ ]
   for oOo0o0 in iI1111Ii1I :
    if 7 - 7: Ii1I
    if 25 - 25: I1Ii111 . II111iiii % OoOoOO00
    if 72 - 72: I1ii11iIi11i . I1IiiI % I11i - iII111i / ooOoO0o
    if 91 - 91: IiII / I1IiiI - Ii1I + o0oOOo0O0Ooo
    if 90 - 90: I1ii11iIi11i * oO0o
    if ( oOo0o0 . rloc . is_private_address ( ) ) :
     oOo0o0 . priority = 1
     oOo0o0 . state = LISP_RLOC_UNREACH_STATE
     O00OoO0o0Oo . append ( oOo0o0 )
     o0Oo0 . append ( oOo0o0 . rloc . print_address_no_iid ( ) )
     continue
     if 29 - 29: OoOoOO00 % ooOoO0o . OoOoOO00 % OOooOOo - OoOoOO00
     if 81 - 81: i1IIi + I1IiiI - iIii1I11I1II1 / O0 . iIii1I11I1II1 - iIii1I11I1II1
     if 54 - 54: iII111i + OOooOOo + OoO0O00
     if 6 - 6: oO0o - OoooooooOO * iIii1I11I1II1 * I1ii11iIi11i
     if 65 - 65: IiII + OoOoOO00
     if 93 - 93: Ii1I
    if ( oOo0o0 . priority == 254 and lisp_i_am_rtr == False ) :
     O00OoO0o0Oo . append ( oOo0o0 )
     o0Oo0 . append ( oOo0o0 . rloc . print_address_no_iid ( ) )
     if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
    if ( oOo0o0 . priority != 254 and lisp_i_am_rtr ) :
     O00OoO0o0Oo . append ( oOo0o0 )
     o0Oo0 . append ( oOo0o0 . rloc . print_address_no_iid ( ) )
     if 5 - 5: OoO0O00 / ooOoO0o
     if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
     if 97 - 97: oO0o / Ii1I
   if ( o0Oo0 != [ ] ) :
    iI1111Ii1I = O00OoO0o0Oo
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( o0Oo0 ) )
    if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
    if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
    if 91 - 91: IiII * Ii1I * OOooOOo
    if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
    if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
    if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
    if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
  O00OoO0o0Oo = [ ]
  for oOo0o0 in iI1111Ii1I :
   if ( oOo0o0 . json != None ) : continue
   O00OoO0o0Oo . append ( oOo0o0 )
   if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
  if ( O00OoO0o0Oo != [ ] ) :
   OO = len ( iI1111Ii1I ) - len ( O00OoO0o0Oo )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( OO ) )
   if 95 - 95: IiII + iII111i % I1IiiI
   iI1111Ii1I = O00OoO0o0Oo
   if 18 - 18: Oo0Ooo
   if 8 - 8: O0 + iIii1I11I1II1 - O0
   if 67 - 67: O0
   if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
   if 28 - 28: O0 - Oo0Ooo
   if 58 - 58: iIii1I11I1II1 - OoooooooOO - iII111i
   if 43 - 43: ooOoO0o / o0oOOo0O0Ooo
   if 56 - 56: II111iiii * I1ii11iIi11i * O0 . iII111i . I1ii11iIi11i % I1Ii111
  if ( i1i11i . rloc_probe and O0oOO0OOO != None ) : iI1111Ii1I = O0oOO0OOO . rloc_set
  if 99 - 99: Oo0Ooo - OoO0O00 + OoooooooOO - I1Ii111 - I1ii11iIi11i % i1IIi
  if 49 - 49: IiII % OoooooooOO / Oo0Ooo - OoOoOO00 + o0oOOo0O0Ooo / Ii1I
  if 6 - 6: I11i % IiII
  if 48 - 48: Ii1I
  if 100 - 100: OoO0O00 % I1Ii111 + OoooooooOO / OoO0O00
  oOo0O0o000O0 = ooOOO0ooo000OOO
  if ( O0oOO0OOO and iI1111Ii1I != O0oOO0OOO . rloc_set ) :
   O0oOO0OOO . delete_rlocs_from_rloc_probe_list ( )
   oOo0O0o000O0 = True
   if 74 - 74: iII111i - O0 * o0oOOo0O0Ooo / OoooooooOO + II111iiii + Ii1I
   if 39 - 39: i11iIiiIii . IiII + I1ii11iIi11i % IiII
   if 96 - 96: I11i / I1IiiI . i1IIi
   if 67 - 67: i11iIiiIii
   if 3 - 3: IiII
  iIoO0oOOoOoO = O0oOO0OOO . uptime if ( O0oOO0OOO ) else None
  if ( O0oOO0OOO == None ) :
   O0oOO0OOO = lisp_mapping ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group , iI1111Ii1I )
   O0oOO0OOO . mapping_source = source
   if 3 - 3: I1Ii111 + i11iIiiIii - I1IiiI . I1IiiI
   if 40 - 40: O0 * O0 / OOooOOo . OOooOOo . I1ii11iIi11i + O0
   if 96 - 96: iII111i * i11iIiiIii * I1Ii111
   if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
   if 88 - 88: IiII
   if 29 - 29: iII111i . ooOoO0o
   if ( lisp_i_am_rtr and iI1I1I1I11I11 . group . is_null ( ) == False ) :
    O0oOO0OOO . map_cache_ttl = LISP_MCAST_TTL
   else :
    O0oOO0OOO . map_cache_ttl = iI1I1I1I11I11 . store_ttl ( )
    if 62 - 62: IiII
   O0oOO0OOO . action = iI1I1I1I11I11 . action
   O0oOO0OOO . add_cache ( oOo0O0o000O0 )
   if 95 - 95: ooOoO0o / i1IIi + II111iiii + OoO0O00 % OoO0O00
   if 18 - 18: ooOoO0o * I1IiiI / iII111i % iII111i
  Ii11Iiiiii = "Add"
  if ( iIoO0oOOoOoO ) :
   O0oOO0OOO . uptime = iIoO0oOOoOoO
   O0oOO0OOO . refresh_time = lisp_get_timestamp ( )
   Ii11Iiiiii = "Replace"
   if 95 - 95: ooOoO0o * OoO0O00 % OoooooooOO % OoO0O00
   if 79 - 79: II111iiii % Ii1I * oO0o * iII111i + II111iiii
  lprint ( "{} {} map-cache with {} RLOCs" . format ( Ii11Iiiiii ,
 green ( O0oOO0OOO . print_eid_tuple ( ) , False ) , len ( iI1111Ii1I ) ) )
  if 51 - 51: I1IiiI + iII111i + I1IiiI / Ii1I * IiII + OOooOOo
  if 70 - 70: I11i . IiII + IiII
  if 74 - 74: Ii1I
  if 11 - 11: I1ii11iIi11i
  if 83 - 83: O0
  if ( lisp_ipc_dp_socket and I1iio0O0o00oO0ooo != None ) :
   lisp_write_ipc_keys ( I1iio0O0o00oO0ooo )
   if 97 - 97: O0
   if 50 - 50: I1Ii111 / OoooooooOO . o0oOOo0O0Ooo + I1IiiI * i11iIiiIii
   if 28 - 28: I1Ii111 * II111iiii
   if 14 - 14: iIii1I11I1II1 / Ii1I + o0oOOo0O0Ooo . iII111i % iII111i . i1IIi
   if 67 - 67: IiII * II111iiii + ooOoO0o - i11iIiiIii
   if 15 - 15: I11i
   if 67 - 67: iIii1I11I1II1
  if ( ooOOO0ooo000OOO ) :
   oOoOoO0oOO0o0 = bold ( "RLOC-probe" , False )
   for oOo0o0 in O0oOO0OOO . best_rloc_set :
    oo0o00OO = red ( oOo0o0 . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( oOoOoO0oOO0o0 , oo0o00OO ) )
    lisp_send_map_request ( lisp_sockets , 0 , O0oOO0OOO . eid , O0oOO0OOO . group , oOo0o0 )
    if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
    if 9 - 9: Ii1I
    if 44 - 44: iII111i
 return
 if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
 if 37 - 37: OoO0O00 - Ii1I + OoO0O00
 if 49 - 49: OoooooooOO - I1ii11iIi11i % I1ii11iIi11i / i1IIi . ooOoO0o
 if 60 - 60: Oo0Ooo
 if 46 - 46: OoOoOO00 + i1IIi
 if 43 - 43: II111iiii * IiII % iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
 if 81 - 81: oO0o % I1ii11iIi11i % ooOoO0o * O0 - OOooOOo
 if 17 - 17: O0 % O0 / I1ii11iIi11i . Oo0Ooo . iII111i
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 4 - 4: OoO0O00
 packet = map_register . zero_auth ( packet )
 I1I = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 65 - 65: Oo0Ooo % O0 / I1Ii111 * IiII - oO0o
 if 32 - 32: Ii1I * OoO0O00 + ooOoO0o
 if 41 - 41: IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
 if 38 - 38: iII111i * OoooooooOO - IiII
 map_register . auth_data = I1I
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
 if 91 - 91: O0 + I1Ii111 * II111iiii - O0 . i11iIiiIii . Oo0Ooo
 if 54 - 54: ooOoO0o * I11i / I1ii11iIi11i % ooOoO0o
 if 76 - 76: I11i . I1IiiI
 if 66 - 66: oO0o % oO0o * IiII
 if 39 - 39: i1IIi * Ii1I + OoOoOO00 / oO0o
 if 6 - 6: I1ii11iIi11i / II111iiii / OoOoOO00 . i11iIiiIii - iII111i
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 43 - 43: i11iIiiIii * i11iIiiIii * I1Ii111
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  OO0iiI1I = hashlib . sha1
  if 18 - 18: o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  OO0iiI1I = hashlib . sha256
  if 79 - 79: i1IIi + OOooOOo . ooOoO0o
  if 37 - 37: O0 + OoooooooOO
 if ( do_hex ) :
  I1I = hmac . new ( password , packet , OO0iiI1I ) . hexdigest ( )
 else :
  I1I = hmac . new ( password , packet , OO0iiI1I ) . digest ( )
  if 16 - 16: OoO0O00 . OOooOOo - ooOoO0o
 return ( I1I )
 if 35 - 35: ooOoO0o . OOooOOo - oO0o * i11iIiiIii . I11i
 if 83 - 83: i11iIiiIii
 if 72 - 72: oO0o + II111iiii . O0 * oO0o + iII111i
 if 22 - 22: I11i + Ii1I . IiII - OoO0O00 - o0oOOo0O0Ooo
 if 84 - 84: OoooooooOO - Oo0Ooo
 if 86 - 86: O0 + OoO0O00 + O0 . I1IiiI
 if 82 - 82: OoOoOO00
 if 61 - 61: oO0o . o0oOOo0O0Ooo
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
 I1I = lisp_hash_me ( packet , alg_id , password , True )
 o0o00 = ( I1I == auth_data )
 if 28 - 28: iIii1I11I1II1 - o0oOOo0O0Ooo . iIii1I11I1II1 / I11i / I1Ii111 % iIii1I11I1II1
 if 45 - 45: OoO0O00 + ooOoO0o / iIii1I11I1II1 % i11iIiiIii
 if 16 - 16: i1IIi / oO0o - OOooOOo / Ii1I + I1IiiI
 if 62 - 62: i11iIiiIii . Ii1I . iII111i / I1Ii111 * OoO0O00
 if ( o0o00 == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( I1I , auth_data ) )
  if 31 - 31: OoOoOO00
  if 16 - 16: OoooooooOO
 return ( o0o00 )
 if 32 - 32: ooOoO0o - o0oOOo0O0Ooo / ooOoO0o + o0oOOo0O0Ooo + iII111i
 if 78 - 78: OoooooooOO . I1ii11iIi11i * oO0o . o0oOOo0O0Ooo * OoOoOO00 / oO0o
 if 47 - 47: OOooOOo
 if 40 - 40: I1ii11iIi11i
 if 67 - 67: I1Ii111 - OoO0O00 * ooOoO0o - oO0o / OoO0O00 . I1Ii111
 if 39 - 39: Ii1I
 if 90 - 90: I1Ii111 - I1Ii111 . i11iIiiIii + OoooooooOO % OOooOOo / Oo0Ooo
def lisp_retransmit_map_notify ( map_notify ) :
 oO0o0 = map_notify . etr
 IiI1iI1 = map_notify . etr_port
 if 51 - 51: o0oOOo0O0Ooo
 if 8 - 8: oO0o . oO0o . Ii1I
 if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
 if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
 if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( oO0o0 . print_address ( ) , False ) ) )
  if 10 - 10: ooOoO0o
  if 69 - 69: I11i + I1IiiI / oO0o
  ii1i1I1111ii = map_notify . nonce_key
  if ( lisp_map_notify_queue . has_key ( ii1i1I1111ii ) ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( ii1i1I1111ii ) )
   if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
   try :
    lisp_map_notify_queue . pop ( ii1i1I1111ii )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 85 - 85: I1Ii111 - oO0o
    if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
  return
  if 96 - 96: oO0o
  if 44 - 44: OoooooooOO / iII111i * Oo0Ooo % OoOoOO00 . oO0o
 III1I111I1i1I = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 97 - 97: iIii1I11I1II1 / ooOoO0o
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # i1IIi
 red ( oO0o0 . print_address ( ) , False ) , map_notify . retry_count ) )
 if 81 - 81: OoOoOO00 * i11iIiiIii + I1IiiI
 lisp_send_map_notify ( III1I111I1i1I , map_notify . packet , oO0o0 , IiI1iI1 )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 2 - 2: I11i - IiII + I1IiiI % OoO0O00 + iIii1I11I1II1 + oO0o
 if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
 if 57 - 57: oO0o + O0 - OoOoOO00
 if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 93 - 93: o0oOOo0O0Ooo + i1IIi
 if 24 - 24: i1IIi
 if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
 if 99 - 99: Oo0Ooo
 if 38 - 38: I1ii11iIi11i - I1IiiI
 if 50 - 50: iII111i % OoO0O00 - oO0o + Oo0Ooo . O0 . iII111i
 if 42 - 42: iII111i + I1ii11iIi11i
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 44 - 44: I1ii11iIi11i % IiII
 if 1 - 1: Oo0Ooo + IiII - I1Ii111 / I1Ii111
 if 25 - 25: OoOoOO00
 if 52 - 52: OOooOOo + IiII
 eid_record . rloc_count = len ( parent . registered_rlocs )
 Oo00o0oOO = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 51 - 51: iII111i % Ii1I . iIii1I11I1II1 / Oo0Ooo * Oo0Ooo % IiII
 if 5 - 5: OOooOOo - I1Ii111 + IiII
 if 82 - 82: OOooOOo
 if 26 - 26: ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
 for ii1I111i in parent . registered_rlocs :
  I1i11 = lisp_rloc_record ( )
  I1i11 . store_rloc_entry ( ii1I111i )
  Oo00o0oOO += I1i11 . encode ( )
  I1i11 . print_record ( "  " )
  del ( I1i11 )
  if 32 - 32: OoOoOO00 + iII111i
  if 8 - 8: o0oOOo0O0Ooo . IiII % iII111i / o0oOOo0O0Ooo * I1IiiI % I1ii11iIi11i
  if 91 - 91: I1Ii111 / II111iiii / O0
  if 35 - 35: ooOoO0o * I11i
  if 85 - 85: i1IIi
 for ii1I111i in parent . registered_rlocs :
  oO0o0 = ii1I111i . rloc
  ooo0o0o0OoOoo = lisp_map_notify ( lisp_sockets )
  ooo0o0o0OoOoo . record_count = 1
  IIIiI1i = map_register . key_id
  ooo0o0o0OoOoo . key_id = IIIiI1i
  ooo0o0o0OoOoo . alg_id = map_register . alg_id
  ooo0o0o0OoOoo . auth_len = map_register . auth_len
  ooo0o0o0OoOoo . nonce = map_register . nonce
  ooo0o0o0OoOoo . nonce_key = lisp_hex_string ( ooo0o0o0OoOoo . nonce )
  ooo0o0o0OoOoo . etr . copy_address ( oO0o0 )
  ooo0o0o0OoOoo . etr_port = map_register . sport
  ooo0o0o0OoOoo . site = parent . site
  IIii1i = ooo0o0o0OoOoo . encode ( Oo00o0oOO , parent . site . auth_key [ IIIiI1i ] )
  ooo0o0o0OoOoo . print_notify ( )
  if 72 - 72: I11i
  if 35 - 35: I1Ii111 + oO0o + II111iiii
  if 71 - 71: OoOoOO00 * OoOoOO00
  if 27 - 27: II111iiii + OoooooooOO - I11i * o0oOOo0O0Ooo
  ii1i1I1111ii = ooo0o0o0OoOoo . nonce_key
  if ( lisp_map_notify_queue . has_key ( ii1i1I1111ii ) ) :
   ooO0OooO = lisp_map_notify_queue [ ii1i1I1111ii ]
   ooO0OooO . retransmit_timer . cancel ( )
   del ( ooO0OooO )
   if 56 - 56: o0oOOo0O0Ooo / I1ii11iIi11i
  lisp_map_notify_queue [ ii1i1I1111ii ] = ooo0o0o0OoOoo
  if 25 - 25: iIii1I11I1II1 / OoO0O00 - o0oOOo0O0Ooo
  if 97 - 97: ooOoO0o % OoooooooOO * o0oOOo0O0Ooo
  if 8 - 8: I1ii11iIi11i + Oo0Ooo - iII111i
  if 53 - 53: ooOoO0o / IiII
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( oO0o0 . print_address ( ) , False ) ) )
  if 36 - 36: iIii1I11I1II1
  lisp_send ( lisp_sockets , oO0o0 , LISP_CTRL_PORT , IIii1i )
  if 78 - 78: II111iiii * I11i
  parent . site . map_notifies_sent += 1
  if 47 - 47: Ii1I
  if 42 - 42: I11i . oO0o - I1IiiI / OoO0O00
  if 75 - 75: I1IiiI / OoOoOO00 . I11i * iIii1I11I1II1
  if 53 - 53: iIii1I11I1II1
  ooo0o0o0OoOoo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ ooo0o0o0OoOoo ] )
  ooo0o0o0OoOoo . retransmit_timer . start ( )
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
 ii1i1I1111ii = lisp_hex_string ( nonce ) + source . print_address ( )
 if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
 if 34 - 34: O0 * oO0o
 if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
 if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
 if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
 if 88 - 88: i11iIiiIii
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( lisp_map_notify_queue . has_key ( ii1i1I1111ii ) ) :
  ooo0o0o0OoOoo = lisp_map_notify_queue [ ii1i1I1111ii ]
  IiII1iiI = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( ooo0o0o0OoOoo . nonce ) , IiII1iiI ) )
  if 13 - 13: I1IiiI
  return
  if 52 - 52: Ii1I * oO0o / I1Ii111 . IiII
  if 84 - 84: OoooooooOO - oO0o - I1Ii111
 ooo0o0o0OoOoo = lisp_map_notify ( lisp_sockets )
 ooo0o0o0OoOoo . record_count = record_count
 key_id = key_id
 ooo0o0o0OoOoo . key_id = key_id
 ooo0o0o0OoOoo . alg_id = alg_id
 ooo0o0o0OoOoo . auth_len = auth_len
 ooo0o0o0OoOoo . nonce = nonce
 ooo0o0o0OoOoo . nonce_key = lisp_hex_string ( nonce )
 ooo0o0o0OoOoo . etr . copy_address ( source )
 ooo0o0o0OoOoo . etr_port = port
 ooo0o0o0OoOoo . site = site
 ooo0o0o0OoOoo . eid_list = eid_list
 if 69 - 69: OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
 if 20 - 20: IiII
 if 17 - 17: o0oOOo0O0Ooo % iIii1I11I1II1
 if 66 - 66: OoooooooOO + IiII . II111iiii
 if ( map_register_ack == False ) :
  ii1i1I1111ii = ooo0o0o0OoOoo . nonce_key
  lisp_map_notify_queue [ ii1i1I1111ii ] = ooo0o0o0OoOoo
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
 IIii1i = ooo0o0o0OoOoo . encode ( eid_records , site . auth_key [ key_id ] )
 ooo0o0o0OoOoo . print_notify ( )
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
 lisp_send_map_notify ( lisp_sockets , IIii1i , ooo0o0o0OoOoo . etr , port )
 site . map_notifies_sent += 1
 if 73 - 73: Ii1I . IiII
 if ( map_register_ack ) : return
 if 43 - 43: I11i . IiII - iII111i * I1IiiI * iII111i
 if 90 - 90: i11iIiiIii * i1IIi
 if 88 - 88: i11iIiiIii - OoOoOO00
 if 53 - 53: iIii1I11I1II1 % I1Ii111 / Oo0Ooo % Oo0Ooo
 if 6 - 6: iII111i
 if 44 - 44: oO0o
 ooo0o0o0OoOoo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ ooo0o0o0OoOoo ] )
 ooo0o0o0OoOoo . retransmit_timer . start ( )
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
 IIii1i = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 89 - 89: iIii1I11I1II1 . I11i % I1ii11iIi11i + II111iiii . OoO0O00
 if 5 - 5: I1ii11iIi11i / I1IiiI . iII111i
 if 7 - 7: Ii1I
 if 62 - 62: I1ii11iIi11i + IiII . O0 - OoooooooOO * o0oOOo0O0Ooo % O0
 oO0o0 = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( oO0o0 . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , oO0o0 , LISP_CTRL_PORT , IIii1i )
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
 ooo0o0o0OoOoo = lisp_map_notify ( lisp_sockets )
 ooo0o0o0OoOoo . record_count = 1
 ooo0o0o0OoOoo . nonce = lisp_get_control_nonce ( )
 ooo0o0o0OoOoo . nonce_key = lisp_hex_string ( ooo0o0o0OoOoo . nonce )
 ooo0o0o0OoOoo . etr . copy_address ( xtr )
 ooo0o0o0OoOoo . etr_port = LISP_CTRL_PORT
 ooo0o0o0OoOoo . eid_list = eid_list
 ii1i1I1111ii = ooo0o0o0OoOoo . nonce_key
 if 56 - 56: OOooOOo % oO0o - OoOoOO00
 if 27 - 27: I1ii11iIi11i - IiII * OoooooooOO * I1ii11iIi11i + i11iIiiIii . IiII
 if 81 - 81: oO0o / iIii1I11I1II1
 if 15 - 15: Ii1I + I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
 if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
 if 28 - 28: ooOoO0o
 lisp_remove_eid_from_map_notify_queue ( ooo0o0o0OoOoo . eid_list )
 if ( lisp_map_notify_queue . has_key ( ii1i1I1111ii ) ) :
  ooo0o0o0OoOoo = lisp_map_notify_queue [ ii1i1I1111ii ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( ooo0o0o0OoOoo . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 88 - 88: oO0o
  return
  if 77 - 77: ooOoO0o + I1Ii111 . OoOoOO00
  if 2 - 2: i1IIi - IiII + iIii1I11I1II1 % i1IIi * II111iiii
  if 26 - 26: I11i
  if 57 - 57: I1ii11iIi11i + I1Ii111 + i11iIiiIii . i1IIi / i11iIiiIii
  if 43 - 43: Ii1I % I11i
 lisp_map_notify_queue [ ii1i1I1111ii ] = ooo0o0o0OoOoo
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
 IIii1i = iI1I1I1I11I11 . encode ( )
 if 95 - 95: I11i
 if 58 - 58: I1ii11iIi11i / i11iIiiIii + iII111i + I11i / oO0o
 if 8 - 8: I1ii11iIi11i
 if 100 - 100: OoooooooOO / I11i - Ii1I
 ooo0o0o0OoOoo . print_notify ( )
 iI1I1I1I11I11 . print_record ( "  " , False )
 if 11 - 11: OoO0O00
 if 20 - 20: Oo0Ooo
 if 34 - 34: I1Ii111 % i11iIiiIii / oO0o - i1IIi . o0oOOo0O0Ooo / oO0o
 if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
 for oo0OOOoO0OoO in site_eid . registered_rlocs :
  if ( Oooo0o0OOO0O0 ^ oo0OOOoO0OoO . is_rtr ( ) ) : continue
  I1i11 = lisp_rloc_record ( )
  I1i11 . store_rloc_entry ( oo0OOOoO0OoO )
  IIii1i += I1i11 . encode ( )
  I1i11 . print_record ( "    " )
  if 1 - 1: I1ii11iIi11i
  if 18 - 18: i11iIiiIii % OoO0O00 % OOooOOo . OOooOOo * Ii1I / II111iiii
  if 81 - 81: iII111i % IiII / I11i
  if 50 - 50: IiII + i1IIi % I1Ii111
  if 72 - 72: I1Ii111
 IIii1i = ooo0o0o0OoOoo . encode ( IIii1i , "" )
 if ( IIii1i == None ) : return
 if 6 - 6: II111iiii - i1IIi
 if 78 - 78: OoOoOO00 - Oo0Ooo * II111iiii % iIii1I11I1II1 . i11iIiiIii % iII111i
 if 85 - 85: I1ii11iIi11i + OOooOOo % i1IIi
 if 13 - 13: OOooOOo + i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
 lisp_send_map_notify ( lisp_sockets , IIii1i , xtr , LISP_CTRL_PORT )
 if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
 if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
 if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
 if 8 - 8: OoooooooOO * OOooOOo * iII111i - iII111i
 ooo0o0o0OoOoo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ ooo0o0o0OoOoo ] )
 ooo0o0o0OoOoo . retransmit_timer . start ( )
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
 for OOoo00o0 in rle_list :
  OO00o = lisp_site_eid_lookup ( OOoo00o0 [ 0 ] , OOoo00o0 [ 1 ] , True )
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
   for O00oo0ooo0O in i1II1i1i11I1i :
    IiIIi1I . append ( O00oo0ooo0O . address )
    IIiiII1iI1iI . append ( O00oo0ooo0O . address . print_address_no_iid ( ) )
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
    Ii1ii1 = lisp_site_eid_lookup ( OOoo00o0 [ 0 ] , IIiiiiI1iIiiI , False )
    if ( Ii1ii1 == None ) : continue
    if 39 - 39: oO0o . I1Ii111 + oO0o % OoOoOO00 - i11iIiiIii
    for oo0OOOoO0OoO in Ii1ii1 . registered_rlocs :
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
  for ii1I111i in IiIIi1I :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if oO00o00OoO else "x" , red ( ii1I111i . print_address_no_iid ( ) , False ) ,
   # II111iiii
 green ( OO00o . print_eid_tuple ( ) , False ) ) )
   if 42 - 42: OoooooooOO % OoO0O00 % i1IIi % i1IIi
   OoO0OOO0Oo0O = [ OO00o . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , OO00o , OoO0OOO0Oo0O , ii1I111i )
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
 OO0OoooO0 = lisp_address ( LISP_AFI_NAME , IiI11I11i , len ( IiI11I11i ) , o0OoO0000o )
 oOooO00OOoO = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 if 80 - 80: O0 * I11i * I1Ii111
 if 89 - 89: Ii1I * OoO0O00 . i1IIi . O0 - IiII - OoOoOO00
 if 25 - 25: iII111i + i1IIi
 if 64 - 64: IiII % I11i / iIii1I11I1II1
 Ii1ii1 = lisp_site_eid_lookup ( OO0OoooO0 , oOooO00OOoO , True )
 if ( Ii1ii1 == None ) : return ( [ OO0OoooO0 , None , False ] )
 if 66 - 66: Ii1I
 if 55 - 55: OOooOOo + I1IiiI + IiII . Ii1I * oO0o
 if 71 - 71: IiII - iII111i % I1IiiI * iII111i
 if 27 - 27: ooOoO0o - OoO0O00
 OOOO0o = None
 for oOo0o0 in Ii1ii1 . registered_rlocs :
  O0OO0o000o00 = oOo0o0 . json
  if ( O0OO0o000o00 == None ) : continue
  try :
   O0OO0o000o00 = json . loads ( O0OO0o000o00 . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( IiI11I11i ) )
   if 85 - 85: Ii1I % OoOoOO00
   return ( [ OO0OoooO0 , None , False ] )
   if 28 - 28: IiII
  if ( O0OO0o000o00 . has_key ( "public-key" ) == False ) : continue
  OOOO0o = O0OO0o000o00 [ "public-key" ]
  break
  if 32 - 32: IiII * II111iiii . Ii1I
 return ( [ OO0OoooO0 , OOOO0o , True ] )
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
 I1ii1I11iIi = json . loads ( rloc_record . json . json_string )
 if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
 if ( lisp_get_eid_hash ( eid ) ) :
  o00ooo0O = eid
 elif ( I1ii1I11iIi . has_key ( "signature-eid" ) ) :
  o0OOOo0OooO0O = I1ii1I11iIi [ "signature-eid" ]
  o00ooo0O = lisp_address ( LISP_AFI_IPV6 , o0OOOo0OooO0O , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 13 - 13: I1ii11iIi11i % i11iIiiIii
  if 47 - 47: oO0o - iII111i
  if 92 - 92: OoooooooOO * OoooooooOO
  if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
  if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
 OO0OoooO0 , OOOO0o , OOoO0 = lisp_lookup_public_key ( o00ooo0O )
 if ( OO0OoooO0 == None ) :
  I11i11i1 = green ( o00ooo0O . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( I11i11i1 ) )
  return ( False )
  if 78 - 78: II111iiii - i11iIiiIii . OOooOOo
  if 22 - 22: Oo0Ooo + ooOoO0o
 O00o0 = "found" if OOoO0 else bold ( "not found" , False )
 I11i11i1 = green ( OO0OoooO0 . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( I11i11i1 , O00o0 ) )
 if ( OOoO0 == False ) : return ( False )
 if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
 if ( OOOO0o == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
  if 26 - 26: Oo0Ooo . Ii1I
 iIIIIiiii = OOOO0o [ 0 : 8 ] + "..." + OOOO0o [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( iIIIIiiii ) )
 if 17 - 17: II111iiii - I1Ii111 - i11iIiiIii - iIii1I11I1II1
 if 10 - 10: I1IiiI
 if 40 - 40: OoO0O00 * oO0o / OoOoOO00
 if 37 - 37: iII111i * oO0o / I1IiiI * I1ii11iIi11i
 if 73 - 73: oO0o + O0
 O0OO00OO0oo = I1ii1I11iIi [ "signature" ]
 if 5 - 5: I1IiiI
 try :
  I1ii1I11iIi = binascii . a2b_base64 ( O0OO00OO0oo )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 22 - 22: II111iiii / iII111i
  if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
 OoOOOo0o0oo = len ( I1ii1I11iIi )
 if ( OoOOOo0o0oo & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( OoOOOo0o0oo ) )
  return ( False )
  if 81 - 81: iII111i . Oo0Ooo / i1IIi / i11iIiiIii
  if 77 - 77: I1Ii111
  if 92 - 92: iII111i * i11iIiiIii * o0oOOo0O0Ooo * OoO0O00
  if 70 - 70: Ii1I
  if 51 - 51: i1IIi % Oo0Ooo
 oo0oO00O000 = o00ooo0O . print_address ( )
 if 32 - 32: OoOoOO00 + iIii1I11I1II1 . OoO0O00 . I1ii11iIi11i . IiII
 if 97 - 97: ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + iII111i + OoOoOO00
 if 8 - 8: Oo0Ooo . oO0o + II111iiii
 if 100 - 100: OoOoOO00 . IiII / OoO0O00 * OoooooooOO - OoOoOO00
 OOOO0o = binascii . a2b_base64 ( OOOO0o )
 try :
  ii1i1I1111ii = ecdsa . VerifyingKey . from_pem ( OOOO0o )
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
  iII1Ii1iIIii = ii1i1I1111ii . verify ( I1ii1I11iIi , oo0oO00O000 , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( oo0oO00O000 ) )
  if 53 - 53: Ii1I - II111iiii * iIii1I11I1II1
  lprint ( "  Signature used '{}'" . format ( O0OO00OO0oo ) )
  return ( False )
  if 91 - 91: OoOoOO00 % iIii1I11I1II1
 return ( iII1Ii1iIIii )
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
   ooo0o0o0OoOoo = lisp_map_notify_queue [ ooO0oO0o0oo0 ]
   if ( ooOOooO not in ooo0o0o0OoOoo . eid_list ) : continue
   if 98 - 98: OoooooooOO - i11iIiiIii - iII111i + Ii1I - I1IiiI
   i1i1Ii11 . append ( ooO0oO0o0oo0 )
   ooOo0OO0O0 = ooo0o0o0OoOoo . retransmit_timer
   if ( ooOo0OO0O0 ) : ooOo0OO0O0 . cancel ( )
   if 24 - 24: OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - o0oOOo0O0Ooo . I1ii11iIi11i
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( ooo0o0o0OoOoo . nonce_key , green ( ooOOooO , False ) ) )
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
 Ii1I1i1IiiI = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 oOOo0Oo00o00O = ( Ii1I1i1IiiI >> 13 ) & 0x1
 if ( oOOo0Oo00o00O == 0 ) : return ( packet )
 if 49 - 49: II111iiii
 i111Ii = ( Ii1I1i1IiiI >> 14 ) & 0x7
 if 14 - 14: oO0o . OOooOOo * OOooOOo . OoO0O00
 if 27 - 27: OOooOOo - iII111i - IiII
 if 14 - 14: i11iIiiIii . I1ii11iIi11i % OoOoOO00 * Ii1I / OoO0O00
 if 56 - 56: o0oOOo0O0Ooo / I1IiiI + I11i + I1IiiI
 try :
  iIIi1oOoO0OoooOoOO = lisp_ms_encryption_keys [ i111Ii ]
  iIIi1oOoO0OoooOoOO = iIIi1oOoO0OoooOoOO . zfill ( 32 )
  i1Oo = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( i111Ii ) )
  return ( None )
  if 25 - 25: I1IiiI - I1ii11iIi11i
  if 64 - 64: OoOoOO00 / iIii1I11I1II1 / Oo0Ooo % I11i / OoooooooOO / i11iIiiIii
 OooOOOoOoo0O0 = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( OooOOOoOoo0O0 , i111Ii ) )
 if 61 - 61: O0 . Oo0Ooo . iIii1I11I1II1
 IIiiI11 = chacha . ChaCha ( iIIi1oOoO0OoooOoOO , i1Oo ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + IIiiI11 )
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
 OO0o0 , packet = O0o0oo0 . decode ( packet )
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
 O0Oo0 = [ ]
 if 72 - 72: iII111i * I1Ii111 * i11iIiiIii
 if 63 - 63: oO0o . OOooOOo . II111iiii . Oo0Ooo * iIii1I11I1II1
 if 81 - 81: OoO0O00
 if 84 - 84: I1ii11iIi11i / ooOoO0o - i11iIiiIii
 II111i = None
 iiI1I = packet
 OO00o0Oo0000 = [ ]
 IiIIi = O0o0oo0 . record_count
 for IiIIi1IiiIiI in range ( IiIIi ) :
  iI1I1I1I11I11 = lisp_eid_record ( )
  I1i11 = lisp_rloc_record ( )
  packet = iI1I1I1I11I11 . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 15 - 15: iII111i
  iI1I1I1I11I11 . print_record ( "  " , False )
  if 55 - 55: iII111i
  if 22 - 22: I1Ii111 % II111iiii % iIii1I11I1II1 % II111iiii
  if 33 - 33: II111iiii
  if 60 - 60: iIii1I11I1II1 / OOooOOo
  Ii1ii1 = lisp_site_eid_lookup ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group ,
 False )
  if 78 - 78: i11iIiiIii
  iiIiIiI1I1iii = Ii1ii1 . print_eid_tuple ( ) if Ii1ii1 else None
  if 33 - 33: OoOoOO00 - I1ii11iIi11i + IiII
  if 70 - 70: Ii1I % II111iiii
  if 90 - 90: IiII * OoOoOO00 * i1IIi * O0
  if 28 - 28: OoOoOO00 . Oo0Ooo - i1IIi * O0
  if 49 - 49: ooOoO0o . OoO0O00
  if 84 - 84: O0
  if 75 - 75: OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00 + o0oOOo0O0Ooo + I11i
  if ( Ii1ii1 and Ii1ii1 . accept_more_specifics == False ) :
   if ( Ii1ii1 . eid_record_matches ( iI1I1I1I11I11 ) == False ) :
    ooOOo000II = Ii1ii1 . parent_for_more_specifics
    if ( ooOOo000II ) : Ii1ii1 = ooOOo000II
    if 93 - 93: I1IiiI . ooOoO0o
    if 39 - 39: I1ii11iIi11i . I1Ii111 % iII111i
    if 5 - 5: II111iiii . I1IiiI . OoooooooOO * II111iiii * Oo0Ooo
    if 45 - 45: OOooOOo
    if 65 - 65: I1Ii111 % OOooOOo
    if 35 - 35: OOooOOo * oO0o
    if 19 - 19: iIii1I11I1II1 + IiII * iII111i - IiII
    if 87 - 87: o0oOOo0O0Ooo - I1Ii111
  I1II1I1III = ( Ii1ii1 and Ii1ii1 . accept_more_specifics )
  if ( I1II1I1III ) :
   I1Ii = lisp_site_eid ( Ii1ii1 . site )
   I1Ii . dynamic = True
   I1Ii . eid . copy_address ( iI1I1I1I11I11 . eid )
   I1Ii . group . copy_address ( iI1I1I1I11I11 . group )
   I1Ii . parent_for_more_specifics = Ii1ii1
   I1Ii . add_cache ( )
   I1Ii . inherit_from_ams_parent ( )
   Ii1ii1 . more_specific_registrations . append ( I1Ii )
   Ii1ii1 = I1Ii
  else :
   Ii1ii1 = lisp_site_eid_lookup ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group ,
 True )
   if 75 - 75: OoOoOO00 . IiII - OoO0O00 . o0oOOo0O0Ooo % II111iiii
   if 69 - 69: Ii1I % OoooooooOO
  I11i11i1 = iI1I1I1I11I11 . print_eid_tuple ( )
  if 62 - 62: Oo0Ooo / oO0o
  if ( Ii1ii1 == None ) :
   iii = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( iii , green ( I11i11i1 , False ) ,
 ", matched non-ams {}" . format ( green ( iiIiIiI1I1iii , False ) if iiIiIiI1I1iii else "" ) ) )
   if 87 - 87: oO0o
   if 39 - 39: iII111i
   if 46 - 46: i11iIiiIii * iII111i / Oo0Ooo % OOooOOo % oO0o / Ii1I
   if 75 - 75: Ii1I
   if 37 - 37: I1IiiI / OoO0O00 . OoO0O00 + i11iIiiIii - oO0o
   packet = I1i11 . end_of_rlocs ( packet , iI1I1I1I11I11 . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 57 - 57: I1IiiI . OoO0O00
   continue
   if 49 - 49: II111iiii + iII111i
   if 85 - 85: I11i / i11iIiiIii
  II111i = Ii1ii1 . site
  if 33 - 33: iIii1I11I1II1 % O0 + II111iiii * OOooOOo . Ii1I * iII111i
  if ( I1II1I1III ) :
   oOo = Ii1ii1 . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( oOo , False ) , II111i . site_name , green ( I11i11i1 , False ) ) )
   if 48 - 48: I11i * iIii1I11I1II1 / oO0o
  else :
   oOo = green ( Ii1ii1 . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( oOo , II111i . site_name , green ( I11i11i1 , False ) ) )
   if 34 - 34: i1IIi + oO0o * Oo0Ooo * I1Ii111 % OoooooooOO % ooOoO0o
   if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
   if 87 - 87: ooOoO0o
   if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
   if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
   if 26 - 26: O0
  if ( II111i . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( II111i . site_name ) )
   packet = I1i11 . end_of_rlocs ( packet , iI1I1I1I11I11 . rloc_count )
   continue
   if 97 - 97: OOooOOo + I11i % I1Ii111 % i11iIiiIii / I1ii11iIi11i
   if 21 - 21: O0 + iIii1I11I1II1 / i11iIiiIii . OOooOOo * i1IIi
   if 3 - 3: i1IIi % o0oOOo0O0Ooo + OoOoOO00
   if 32 - 32: OoO0O00 . Oo0Ooo * iIii1I11I1II1
   if 12 - 12: O0 + I1ii11iIi11i + I11i . I1Ii111
   if 48 - 48: Ii1I . iIii1I11I1II1 - iIii1I11I1II1 * I11i . OoooooooOO
   if 73 - 73: Ii1I / II111iiii - iIii1I11I1II1 . ooOoO0o * II111iiii . OOooOOo
   if 50 - 50: iIii1I11I1II1 + OoOoOO00 % O0 + OoO0O00 . i11iIiiIii / oO0o
  IIIiI1i = O0o0oo0 . key_id
  if ( II111i . auth_key . has_key ( IIIiI1i ) ) :
   IiiI1iI1i1 = II111i . auth_key [ IIIiI1i ]
  else :
   IiiI1iI1i1 = ""
   if 24 - 24: OOooOOo . I1Ii111
   if 59 - 59: Ii1I - I1ii11iIi11i % Ii1I . iII111i
  o0o00O00O = lisp_verify_auth ( OO0o0 , O0o0oo0 . alg_id ,
 O0o0oo0 . auth_data , IiiI1iI1i1 )
  OOO00OO0O = "dynamic " if Ii1ii1 . dynamic else ""
  if 81 - 81: I11i / iII111i
  OOI1I1iiI1iIIii = bold ( "passed" if o0o00O00O else "failed" , False )
  IIIiI1i = "key-id {}" . format ( IIIiI1i ) if IIIiI1i == O0o0oo0 . key_id else "bad key-id {}" . format ( O0o0oo0 . key_id )
  if 15 - 15: OoOoOO00 - I11i - oO0o
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( OOI1I1iiI1iIIii , OOO00OO0O , green ( I11i11i1 , False ) , IIIiI1i ) )
  if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii * Ii1I . I11i - OoOoOO00 % iII111i
  if 19 - 19: OoOoOO00 + OOooOOo - o0oOOo0O0Ooo + i11iIiiIii . OOooOOo
  if 14 - 14: Ii1I - O0 - IiII % Ii1I / OoOoOO00 * OoooooooOO
  if 57 - 57: Oo0Ooo % Oo0Ooo % O0 . I1Ii111 % I1ii11iIi11i
  if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
  if 12 - 12: ooOoO0o
  ooOOOO0oOo = True
  oOOO0OOo = ( lisp_get_eid_hash ( iI1I1I1I11I11 . eid ) != None )
  if ( oOOO0OOo or Ii1ii1 . require_signature ) :
   ooo0oOOo = "Required " if Ii1ii1 . require_signature else ""
   I11i11i1 = green ( I11i11i1 , False )
   oOo0o0 = lisp_find_sig_in_rloc_set ( packet , iI1I1I1I11I11 . rloc_count )
   if ( oOo0o0 == None ) :
    ooOOOO0oOo = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( ooo0oOOo ,
    # i11iIiiIii / Ii1I % Oo0Ooo % ooOoO0o
 bold ( "failed" , False ) , I11i11i1 ) )
   else :
    ooOOOO0oOo = lisp_verify_cga_sig ( iI1I1I1I11I11 . eid , oOo0o0 )
    OOI1I1iiI1iIIii = bold ( "passed" if ooOOOO0oOo else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( ooo0oOOo , OOI1I1iiI1iIIii , I11i11i1 ) )
    if 38 - 38: Ii1I / I11i - Ii1I
    if 85 - 85: Oo0Ooo + Oo0Ooo
    if 70 - 70: I1ii11iIi11i % OoO0O00 * iIii1I11I1II1 . oO0o
    if 11 - 11: IiII / OoOoOO00 / i11iIiiIii / I1Ii111 . II111iiii + iII111i
  if ( o0o00O00O == False or ooOOOO0oOo == False ) :
   packet = I1i11 . end_of_rlocs ( packet , iI1I1I1I11I11 . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 70 - 70: OoO0O00 % i11iIiiIii / OOooOOo % OoooooooOO . oO0o + OoooooooOO
   continue
   if 88 - 88: oO0o + OOooOOo
   if 14 - 14: I11i / i1IIi
   if 56 - 56: OoooooooOO
   if 59 - 59: I1ii11iIi11i + OoO0O00
   if 37 - 37: IiII * I1IiiI % O0
   if 32 - 32: ooOoO0o % II111iiii
  if ( O0o0oo0 . merge_register_requested ) :
   ooOOo000II = Ii1ii1
   ooOOo000II . inconsistent_registration = False
   if 60 - 60: i11iIiiIii
   if 11 - 11: o0oOOo0O0Ooo
   if 77 - 77: o0oOOo0O0Ooo / iIii1I11I1II1 * iIii1I11I1II1 / o0oOOo0O0Ooo * iII111i
   if 26 - 26: Ii1I
   if 1 - 1: OoOoOO00 . o0oOOo0O0Ooo + Oo0Ooo % Oo0Ooo * I1ii11iIi11i
   if ( Ii1ii1 . group . is_null ( ) ) :
    if ( ooOOo000II . site_id != O0o0oo0 . site_id ) :
     ooOOo000II . site_id = O0o0oo0 . site_id
     ooOOo000II . registered = False
     ooOOo000II . individual_registrations = { }
     ooOOo000II . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 50 - 50: IiII / i1IIi . I1ii11iIi11i
     if 75 - 75: I11i * oO0o + OoooooooOO . iII111i + OoO0O00
     if 44 - 44: II111iiii
   ii1i1I1111ii = source . address + O0o0oo0 . xtr_id
   if ( Ii1ii1 . individual_registrations . has_key ( ii1i1I1111ii ) ) :
    Ii1ii1 = Ii1ii1 . individual_registrations [ ii1i1I1111ii ]
   else :
    Ii1ii1 = lisp_site_eid ( II111i )
    Ii1ii1 . eid . copy_address ( ooOOo000II . eid )
    Ii1ii1 . group . copy_address ( ooOOo000II . group )
    ooOOo000II . individual_registrations [ ii1i1I1111ii ] = Ii1ii1
    if 65 - 65: I11i . iII111i . I1IiiI - Oo0Ooo % iIii1I11I1II1 / O0
  else :
   Ii1ii1 . inconsistent_registration = Ii1ii1 . merge_register_requested
   if 54 - 54: iII111i - I1Ii111
   if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
   if 7 - 7: i1IIi
  Ii1ii1 . map_registers_received += 1
  if 30 - 30: oO0o . i1IIi / I11i
  if 23 - 23: i1IIi + oO0o % iII111i - OoO0O00 - i1IIi
  if 74 - 74: Ii1I + I11i . OoooooooOO - I1ii11iIi11i
  if 2 - 2: oO0o - o0oOOo0O0Ooo
  if 80 - 80: i1IIi
  oOOOO = ( Ii1ii1 . is_rloc_in_rloc_set ( source ) == False )
  if ( iI1I1I1I11I11 . record_ttl == 0 and oOOOO ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 40 - 40: O0 . ooOoO0o * iII111i . I11i + I1Ii111 % OoO0O00
   continue
   if 9 - 9: IiII * oO0o - o0oOOo0O0Ooo
   if 17 - 17: iII111i % Oo0Ooo
   if 14 - 14: I1IiiI - I1Ii111 % I1IiiI - II111iiii
   if 34 - 34: I1ii11iIi11i * IiII / II111iiii / ooOoO0o * oO0o
   if 3 - 3: II111iiii
   if 61 - 61: oO0o . I1IiiI + i1IIi
  OoOo = Ii1ii1 . registered_rlocs
  Ii1ii1 . registered_rlocs = [ ]
  if 48 - 48: ooOoO0o - Ii1I - I11i
  if 70 - 70: O0 * I11i . i1IIi - ooOoO0o
  if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
  if 61 - 61: II111iiii / i1IIi . I1ii11iIi11i % iIii1I11I1II1
  OoOO0o0ooO = packet
  for O0OO00 in range ( iI1I1I1I11I11 . rloc_count ) :
   I1i11 = lisp_rloc_record ( )
   packet = I1i11 . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 68 - 68: OoO0O00 % OoO0O00 + i11iIiiIii / Ii1I
   I1i11 . print_record ( "    " )
   if 20 - 20: I1Ii111 + IiII - O0 + IiII / i1IIi
   if 100 - 100: OoooooooOO
   if 26 - 26: Ii1I * O0
   if 44 - 44: OoO0O00 - I11i
   if ( len ( II111i . allowed_rlocs ) > 0 ) :
    oo0o00OO = I1i11 . rloc . print_address ( )
    if ( II111i . allowed_rlocs . has_key ( oo0o00OO ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( oo0o00OO , False ) ) )
     if 65 - 65: Ii1I % OOooOOo . OoO0O00 - o0oOOo0O0Ooo
     if 8 - 8: OOooOOo % OoOoOO00 % Oo0Ooo . II111iiii
     Ii1ii1 . registered = False
     packet = I1i11 . end_of_rlocs ( packet ,
 iI1I1I1I11I11 . rloc_count - O0OO00 - 1 )
     break
     if 92 - 92: OoOoOO00
     if 26 - 26: Oo0Ooo
     if 3 - 3: I11i . OoO0O00 . i1IIi - I1IiiI * oO0o
     if 93 - 93: i1IIi + I1ii11iIi11i % Oo0Ooo + iIii1I11I1II1 / II111iiii
     if 100 - 100: iIii1I11I1II1 / II111iiii / Ii1I * Ii1I - OoO0O00
     if 36 - 36: ooOoO0o % i1IIi / OoOoOO00 % OoOoOO00 + Ii1I
   oOo0o0 = lisp_rloc ( )
   oOo0o0 . store_rloc_from_record ( I1i11 , None , source )
   if 35 - 35: Ii1I . ooOoO0o - ooOoO0o % OoO0O00 / oO0o
   if 33 - 33: I1Ii111 / i11iIiiIii / I1ii11iIi11i
   if 44 - 44: OoOoOO00 * Oo0Ooo
   if 51 - 51: OOooOOo / IiII % I1Ii111 . OoOoOO00 % Ii1I
   if 88 - 88: OoO0O00
   if 28 - 28: I1Ii111 - iIii1I11I1II1
   if ( source . is_exact_match ( oOo0o0 . rloc ) ) :
    oOo0o0 . map_notify_requested = O0o0oo0 . map_notify_requested
    if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
    if 65 - 65: iII111i . oO0o
    if 67 - 67: I1IiiI / iII111i / O0 % ooOoO0o - IiII / Ii1I
    if 31 - 31: I11i - oO0o * ooOoO0o
    if 64 - 64: I11i
   Ii1ii1 . registered_rlocs . append ( oOo0o0 )
   if 41 - 41: I1Ii111 * OoooooooOO / OoOoOO00 + OoO0O00 . OoOoOO00 + I1Ii111
   if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
  Ii1iIIi1I1II1I = ( Ii1ii1 . do_rloc_sets_match ( OoOo ) == False )
  if 93 - 93: o0oOOo0O0Ooo % OoooooooOO
  if 47 - 47: iIii1I11I1II1 - OOooOOo + I1ii11iIi11i * ooOoO0o + Oo0Ooo + OoO0O00
  if 64 - 64: OoOoOO00 - OoOoOO00 . OoooooooOO + ooOoO0o
  if 100 - 100: ooOoO0o . OoooooooOO % i1IIi % OoO0O00
  if 26 - 26: OoOoOO00 * IiII
  if 76 - 76: I1IiiI + IiII * I1ii11iIi11i * I1IiiI % Ii1I + ooOoO0o
  if ( O0o0oo0 . map_register_refresh and Ii1iIIi1I1II1I and
 Ii1ii1 . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   Ii1ii1 . registered_rlocs = OoOo
   continue
   if 46 - 46: OoOoOO00
   if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
   if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
   if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
   if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
   if 20 - 20: IiII
  if ( Ii1ii1 . registered == False ) :
   Ii1ii1 . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 81 - 81: Oo0Ooo / I1Ii111
  Ii1ii1 . last_registered = lisp_get_timestamp ( )
  Ii1ii1 . registered = ( iI1I1I1I11I11 . record_ttl != 0 )
  Ii1ii1 . last_registerer = source
  if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
  if 51 - 51: iII111i - ooOoO0o
  if 32 - 32: IiII - i11iIiiIii
  if 41 - 41: Ii1I % Ii1I * oO0o - I11i + iIii1I11I1II1 . ooOoO0o
  Ii1ii1 . auth_sha1_or_sha2 = o0oOOO000O
  Ii1ii1 . proxy_reply_requested = O0o0oo0 . proxy_reply_requested
  Ii1ii1 . lisp_sec_present = O0o0oo0 . lisp_sec_present
  Ii1ii1 . map_notify_requested = O0o0oo0 . map_notify_requested
  Ii1ii1 . mobile_node_requested = O0o0oo0 . mobile_node
  Ii1ii1 . merge_register_requested = O0o0oo0 . merge_register_requested
  if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
  Ii1ii1 . use_register_ttl_requested = O0o0oo0 . use_ttl_for_timeout
  if ( Ii1ii1 . use_register_ttl_requested ) :
   Ii1ii1 . register_ttl = iI1I1I1I11I11 . store_ttl ( )
  else :
   Ii1ii1 . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
  Ii1ii1 . xtr_id_present = O0o0oo0 . xtr_id_present
  if ( Ii1ii1 . xtr_id_present ) :
   Ii1ii1 . xtr_id = O0o0oo0 . xtr_id
   Ii1ii1 . site_id = O0o0oo0 . site_id
   if 49 - 49: I1Ii111 . OoooooooOO / o0oOOo0O0Ooo - iII111i - iII111i - i11iIiiIii
   if 37 - 37: OOooOOo
   if 79 - 79: I1Ii111 - OoO0O00 + ooOoO0o + oO0o . i11iIiiIii + i1IIi
   if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
   if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
  if ( O0o0oo0 . merge_register_requested ) :
   if ( ooOOo000II . merge_in_site_eid ( Ii1ii1 ) ) :
    O0Oo0 . append ( [ iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group ] )
    if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
   if ( O0o0oo0 . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , ooOOo000II , O0o0oo0 ,
 iI1I1I1I11I11 )
    if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
    if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
    if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
  if ( Ii1iIIi1I1II1I == False ) : continue
  if ( len ( O0Oo0 ) != 0 ) : continue
  if 22 - 22: ooOoO0o - OOooOOo
  OO00o0Oo0000 . append ( Ii1ii1 . print_eid_tuple ( ) )
  if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
  if 20 - 20: ooOoO0o - i11iIiiIii
  if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
  if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
  if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
  if 29 - 29: oO0o
  if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
  iI1I1I1I11I11 = iI1I1I1I11I11 . encode ( )
  iI1I1I1I11I11 += OoOO0o0ooO
  OoO0OOO0Oo0O = [ Ii1ii1 . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 78 - 78: Oo0Ooo
  for oOo0o0 in OoOo :
   if ( oOo0o0 . map_notify_requested == False ) : continue
   if ( oOo0o0 . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , iI1I1I1I11I11 , OoO0OOO0Oo0O , 1 , oOo0o0 . rloc ,
 LISP_CTRL_PORT , O0o0oo0 . nonce , O0o0oo0 . key_id ,
 O0o0oo0 . alg_id , O0o0oo0 . auth_len , II111i , False )
   if 77 - 77: oO0o % Oo0Ooo % O0
   if 51 - 51: IiII % IiII + OOooOOo . II111iiii / I1ii11iIi11i
   if 4 - 4: o0oOOo0O0Ooo % I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
   if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
   if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
  lisp_notify_subscribers ( lisp_sockets , iI1I1I1I11I11 , Ii1ii1 . eid , II111i )
  if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
  if 88 - 88: ooOoO0o
  if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
  if 20 - 20: i11iIiiIii * I11i
  if 29 - 29: IiII / OOooOOo
 if ( len ( O0Oo0 ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , O0Oo0 )
  if 39 - 39: O0 + II111iiii
  if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
  if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
  if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
  if 42 - 42: O0 / oO0o % O0 . i1IIi % OOooOOo
  if 13 - 13: I1IiiI % ooOoO0o + OOooOOo
 if ( O0o0oo0 . merge_register_requested ) : return
 if 91 - 91: oO0o - ooOoO0o
 if 20 - 20: i1IIi . IiII / o0oOOo0O0Ooo / I11i
 if 27 - 27: ooOoO0o . ooOoO0o - Ii1I % i11iIiiIii
 if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
 if 7 - 7: I1IiiI + OoooooooOO + o0oOOo0O0Ooo . OoooooooOO
 if ( O0o0oo0 . map_notify_requested and II111i != None ) :
  lisp_build_map_notify ( lisp_sockets , iiI1I , OO00o0Oo0000 ,
 O0o0oo0 . record_count , source , sport , O0o0oo0 . nonce ,
 O0o0oo0 . key_id , O0o0oo0 . alg_id , O0o0oo0 . auth_len ,
 II111i , True )
  if 29 - 29: iII111i * O0 + I1IiiI * IiII + iII111i - IiII
 return
 if 38 - 38: I1ii11iIi11i - Ii1I % OoooooooOO
 if 43 - 43: iIii1I11I1II1 / OoOoOO00
 if 13 - 13: o0oOOo0O0Ooo / I1Ii111
 if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
 if 32 - 32: oO0o
 if 72 - 72: I1IiiI
 if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
 if 87 - 87: Oo0Ooo
 if 7 - 7: iIii1I11I1II1
 if 85 - 85: iIii1I11I1II1 . O0
def lisp_process_multicast_map_notify ( packet , source ) :
 ooo0o0o0OoOoo = lisp_map_notify ( "" )
 packet = ooo0o0o0OoOoo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
  if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
 ooo0o0o0OoOoo . print_notify ( )
 if ( ooo0o0o0OoOoo . record_count == 0 ) : return
 if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
 iIiI11iII1I = ooo0o0o0OoOoo . eid_records
 if 92 - 92: I1IiiI / Ii1I - iIii1I11I1II1 - O0
 for IiIIi1IiiIiI in range ( ooo0o0o0OoOoo . record_count ) :
  iI1I1I1I11I11 = lisp_eid_record ( )
  iIiI11iII1I = iI1I1I1I11I11 . decode ( iIiI11iII1I )
  if ( packet == None ) : return
  iI1I1I1I11I11 . print_record ( "  " , False )
  if 15 - 15: iII111i % I11i * ooOoO0o . I1ii11iIi11i + oO0o / I1Ii111
  if 22 - 22: i1IIi % IiII . OoO0O00 * OoO0O00
  if 87 - 87: OOooOOo + OoO0O00 * OoOoOO00 + ooOoO0o . I1ii11iIi11i % IiII
  if 80 - 80: OoOoOO00
  O0oOO0OOO = lisp_map_cache_lookup ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group )
  if ( O0oOO0OOO == None ) :
   o0OoO0Oo , I11Iii1iIII1i , II1ioOO0Oo = lisp_allow_gleaning ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group ,
 None )
   if ( o0OoO0Oo == False ) : continue
   if 31 - 31: I11i * I1IiiI
   O0oOO0OOO = lisp_mapping ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group , [ ] )
   O0oOO0OOO . add_cache ( )
   if 80 - 80: I11i * IiII % iII111i + OoOoOO00
   if 56 - 56: OOooOOo . OOooOOo + oO0o
   if 7 - 7: o0oOOo0O0Ooo * II111iiii - I11i . Ii1I % OoooooooOO - I1IiiI
   if 24 - 24: Oo0Ooo / II111iiii * Oo0Ooo - ooOoO0o
   if 46 - 46: o0oOOo0O0Ooo
   if 41 - 41: I11i % II111iiii - II111iiii + OoO0O00
   if 98 - 98: iIii1I11I1II1 + OOooOOo * oO0o / o0oOOo0O0Ooo . iII111i
  if ( O0oOO0OOO . gleaned ) :
   lprint ( "Ignore Map-Notify for gleaned {}" . format ( green ( O0oOO0OOO . print_eid_tuple ( ) , False ) ) )
   if 52 - 52: IiII + iIii1I11I1II1
   continue
   if 22 - 22: IiII - OOooOOo + I1ii11iIi11i
   if 64 - 64: OoOoOO00
  O0oOO0OOO . mapping_source = None if source == "lisp-etr" else source
  O0oOO0OOO . map_cache_ttl = iI1I1I1I11I11 . store_ttl ( )
  if 79 - 79: IiII
  if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
  if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
  if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
  if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
  if ( len ( O0oOO0OOO . rloc_set ) != 0 and iI1I1I1I11I11 . rloc_count == 0 ) :
   O0oOO0OOO . rloc_set = [ ]
   O0oOO0OOO . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , O0oOO0OOO )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( O0oOO0OOO . print_eid_tuple ( ) , False ) ) )
   if 41 - 41: OoooooooOO + iII111i . OOooOOo
   continue
   if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
   if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
  I1IIi1iIIi = O0oOO0OOO . rtrs_in_rloc_set ( )
  if 11 - 11: Ii1I % i11iIiiIii % OoOoOO00 - II111iiii % I1Ii111
  if 42 - 42: iII111i / iIii1I11I1II1
  if 97 - 97: Oo0Ooo . OoooooooOO - I1ii11iIi11i
  if 3 - 3: O0 + Ii1I / OoooooooOO / i11iIiiIii
  if 83 - 83: Ii1I / OoOoOO00 . iIii1I11I1II1 / oO0o + IiII * I1Ii111
  for O0OO00 in range ( iI1I1I1I11I11 . rloc_count ) :
   I1i11 = lisp_rloc_record ( )
   iIiI11iII1I = I1i11 . decode ( iIiI11iII1I , None )
   I1i11 . print_record ( "    " )
   if ( iI1I1I1I11I11 . group . is_null ( ) ) : continue
   if ( I1i11 . rle == None ) : continue
   if 57 - 57: II111iiii + Oo0Ooo - Ii1I . OOooOOo * OoOoOO00
   if 87 - 87: o0oOOo0O0Ooo / O0 * iIii1I11I1II1
   if 81 - 81: Oo0Ooo
   if 69 - 69: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . I1IiiI
   if 27 - 27: Oo0Ooo % OoooooooOO / OOooOOo / II111iiii + i11iIiiIii
   OOO0ooOoOO = O0oOO0OOO . rloc_set [ 0 ] . stats if len ( O0oOO0OOO . rloc_set ) != 0 else None
   if 6 - 6: IiII
   if 68 - 68: Oo0Ooo
   if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
   if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
   oOo0o0 = lisp_rloc ( )
   oOo0o0 . store_rloc_from_record ( I1i11 , None , O0oOO0OOO . mapping_source )
   if ( OOO0ooOoOO != None ) : oOo0o0 . stats = copy . deepcopy ( OOO0ooOoOO )
   if 93 - 93: i11iIiiIii
   if ( I1IIi1iIIi and oOo0o0 . is_rtr ( ) == False ) : continue
   if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
   O0oOO0OOO . rloc_set = [ oOo0o0 ]
   O0oOO0OOO . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , O0oOO0OOO )
   if 40 - 40: IiII % IiII
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( O0oOO0OOO . print_eid_tuple ( ) , False ) ,
   # I1ii11iIi11i
 oOo0o0 . rle . print_rle ( False , True ) ) )
   if 92 - 92: i1IIi + IiII
   if 68 - 68: iIii1I11I1II1 . o0oOOo0O0Ooo % iIii1I11I1II1
 return
 if 35 - 35: OoooooooOO % O0 * I1Ii111 - iIii1I11I1II1 % iII111i
 if 15 - 15: O0 - Ii1I + OoOoOO00
 if 93 - 93: OoO0O00
 if 68 - 68: OOooOOo
 if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
 if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
 if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
 if 15 - 15: i1IIi . iII111i + IiII / I1ii11iIi11i - i1IIi / iII111i
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 ooo0o0o0OoOoo = lisp_map_notify ( "" )
 IIii1i = ooo0o0o0OoOoo . decode ( orig_packet )
 if ( IIii1i == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 27 - 27: OoOoOO00 / OoooooooOO + i1IIi % iIii1I11I1II1 / OoO0O00
  if 73 - 73: I1ii11iIi11i / OoOoOO00 / IiII + oO0o
 ooo0o0o0OoOoo . print_notify ( )
 if 73 - 73: I11i * o0oOOo0O0Ooo * I1IiiI . OoooooooOO % I1Ii111
 if 9 - 9: oO0o % I1Ii111 . O0 + I1ii11iIi11i - Ii1I - I1ii11iIi11i
 if 57 - 57: i11iIiiIii
 if 21 - 21: iIii1I11I1II1 / I1IiiI / iII111i
 if 19 - 19: Oo0Ooo / iIii1I11I1II1 / I11i
 IiII1iiI = source . print_address ( )
 if ( ooo0o0o0OoOoo . alg_id != 0 or ooo0o0o0OoOoo . auth_len != 0 ) :
  IIIIiI1 = None
  for ii1i1I1111ii in lisp_map_servers_list :
   if ( ii1i1I1111ii . find ( IiII1iiI ) == - 1 ) : continue
   IIIIiI1 = lisp_map_servers_list [ ii1i1I1111ii ]
   if 71 - 71: iIii1I11I1II1 * I1IiiI
  if ( IIIIiI1 == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( IiII1iiI ) )
   if 35 - 35: O0
   return
   if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
   if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
  IIIIiI1 . map_notifies_received += 1
  if 78 - 78: I1IiiI - iIii1I11I1II1
  o0o00O00O = lisp_verify_auth ( IIii1i , ooo0o0o0OoOoo . alg_id ,
 ooo0o0o0OoOoo . auth_data , IIIIiI1 . password )
  if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if o0o00O00O else "failed" ) )
  if 85 - 85: I11i + OoOoOO00 * O0 * O0
  if ( o0o00O00O == False ) : return
 else :
  IIIIiI1 = lisp_ms ( IiII1iiI , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 92 - 92: i11iIiiIii
  if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
  if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
  if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
  if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
  if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
 iIiI11iII1I = ooo0o0o0OoOoo . eid_records
 if ( ooo0o0o0OoOoo . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , iIiI11iII1I , ooo0o0o0OoOoo , IIIIiI1 )
  return
  if 42 - 42: OoOoOO00 . I11i % II111iiii
  if 19 - 19: OoooooooOO
  if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
  if 21 - 21: OOooOOo . Oo0Ooo - i1IIi
  if 56 - 56: I11i
  if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
  if 32 - 32: OOooOOo / i1IIi / OOooOOo
  if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
 iI1I1I1I11I11 = lisp_eid_record ( )
 IIii1i = iI1I1I1I11I11 . decode ( iIiI11iII1I )
 if ( IIii1i == None ) : return
 if 45 - 45: Oo0Ooo
 iI1I1I1I11I11 . print_record ( "  " , False )
 if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
 for O0OO00 in range ( iI1I1I1I11I11 . rloc_count ) :
  I1i11 = lisp_rloc_record ( )
  IIii1i = I1i11 . decode ( IIii1i , None )
  if ( IIii1i == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
  I1i11 . print_record ( "    " )
  if 52 - 52: OOooOOo + OoO0O00
  if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
  if 42 - 42: i1IIi
  if 52 - 52: OoO0O00 % iII111i % O0
  if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
 if ( iI1I1I1I11I11 . group . is_null ( ) == False ) :
  if 50 - 50: oO0o . I1Ii111
  if 38 - 38: iIii1I11I1II1 . Ii1I
  if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
  if 15 - 15: O0
  if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( iI1I1I1I11I11 . print_eid_tuple ( ) , False ) ) )
  if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
  if 25 - 25: ooOoO0o
  OoOO0o00OOO0o = lisp_control_packet_ipc ( orig_packet , IiII1iiI , "lisp-itr" , 0 )
  lisp_ipc ( OoOO0o00OOO0o , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 33 - 33: Oo0Ooo
  if 11 - 11: I11i
  if 55 - 55: i11iIiiIii * OoOoOO00 - OoOoOO00 * OoO0O00 / iII111i
  if 64 - 64: iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
  if 74 - 74: I1IiiI / o0oOOo0O0Ooo
 lisp_send_map_notify_ack ( lisp_sockets , iIiI11iII1I , ooo0o0o0OoOoo , IIIIiI1 )
 return
 if 53 - 53: iIii1I11I1II1 * oO0o
 if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
 if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
 if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
 if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
 if 60 - 60: oO0o * I1Ii111
 if 81 - 81: oO0o - OOooOOo - oO0o
 if 54 - 54: oO0o % I11i
def lisp_process_map_notify_ack ( packet , source ) :
 ooo0o0o0OoOoo = lisp_map_notify ( "" )
 packet = ooo0o0o0OoOoo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
  if 22 - 22: iIii1I11I1II1 - OoooooooOO
 ooo0o0o0OoOoo . print_notify ( )
 if 8 - 8: ooOoO0o % i11iIiiIii
 if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
 if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
 if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
 if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
 if ( ooo0o0o0OoOoo . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 73 - 73: O0 % i11iIiiIii
  if 16 - 16: O0
 iI1I1I1I11I11 = lisp_eid_record ( )
 if 15 - 15: i1IIi % i11iIiiIii
 if ( iI1I1I1I11I11 . decode ( ooo0o0o0OoOoo . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
 iI1I1I1I11I11 . print_record ( "  " , False )
 if 35 - 35: OoOoOO00 . oO0o / II111iiii
 I11i11i1 = iI1I1I1I11I11 . print_eid_tuple ( )
 if 97 - 97: Ii1I + I1Ii111 / II111iiii
 if 14 - 14: iII111i / IiII / oO0o
 if 55 - 55: OoO0O00 % O0
 if 92 - 92: OoooooooOO / O0
 if ( ooo0o0o0OoOoo . alg_id != LISP_NONE_ALG_ID and ooo0o0o0OoOoo . auth_len != 0 ) :
  Ii1ii1 = lisp_sites_by_eid . lookup_cache ( iI1I1I1I11I11 . eid , True )
  if ( Ii1ii1 == None ) :
   iii = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( iii , green ( I11i11i1 , False ) ) )
   if 14 - 14: i11iIiiIii
   return
   if 43 - 43: OOooOOo
  II111i = Ii1ii1 . site
  if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
  if 93 - 93: OoOoOO00
  if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
  if 72 - 72: ooOoO0o
  II111i . map_notify_acks_received += 1
  if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
  IIIiI1i = ooo0o0o0OoOoo . key_id
  if ( II111i . auth_key . has_key ( IIIiI1i ) ) :
   IiiI1iI1i1 = II111i . auth_key [ IIIiI1i ]
  else :
   IiiI1iI1i1 = ""
   if 53 - 53: OOooOOo * O0 . iII111i
   if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
  o0o00O00O = lisp_verify_auth ( packet , ooo0o0o0OoOoo . alg_id ,
 ooo0o0o0OoOoo . auth_data , IiiI1iI1i1 )
  if 78 - 78: iII111i
  IIIiI1i = "key-id {}" . format ( IIIiI1i ) if IIIiI1i == ooo0o0o0OoOoo . key_id else "bad key-id {}" . format ( ooo0o0o0OoOoo . key_id )
  if 80 - 80: i1IIi * I1IiiI + OOooOOo
  if 91 - 91: I1IiiI % OoOoOO00 * Oo0Ooo / I1ii11iIi11i
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if o0o00O00O else "failed" , IIIiI1i ) )
  if 57 - 57: i11iIiiIii / o0oOOo0O0Ooo . II111iiii
  if ( o0o00O00O == False ) : return
  if 63 - 63: O0
  if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
  if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
  if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
  if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
 if ( ooo0o0o0OoOoo . retransmit_timer ) : ooo0o0o0OoOoo . retransmit_timer . cancel ( )
 if 74 - 74: i11iIiiIii
 i1iii = source . print_address ( )
 ii1i1I1111ii = ooo0o0o0OoOoo . nonce_key
 if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
 if ( lisp_map_notify_queue . has_key ( ii1i1I1111ii ) ) :
  ooo0o0o0OoOoo = lisp_map_notify_queue . pop ( ii1i1I1111ii )
  if ( ooo0o0o0OoOoo . retransmit_timer ) : ooo0o0o0OoOoo . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( ii1i1I1111ii ) )
  if 6 - 6: I11i
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( ooo0o0o0OoOoo . nonce_key , red ( i1iii , False ) ) )
  if 70 - 70: ooOoO0o + OoooooooOO % OoOoOO00 % oO0o / Ii1I . I11i
  if 63 - 63: I1ii11iIi11i - ooOoO0o . OOooOOo / O0 . iIii1I11I1II1 - Ii1I
 return
 if 6 - 6: Ii1I
 if 60 - 60: iII111i + I1IiiI
 if 36 - 36: i1IIi . O0 . OoO0O00 % OOooOOo * I11i / Ii1I
 if 16 - 16: Oo0Ooo
 if 44 - 44: iIii1I11I1II1 - II111iiii . IiII . i1IIi
 if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
 if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
 if 43 - 43: I1ii11iIi11i + I11i
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 100 - 100: IiII - OoOoOO00 / I11i
 if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
 if 87 - 87: Oo0Ooo
 if 65 - 65: ooOoO0o . I1IiiI
 ooo0OO0O = False
 if ( group . is_null ( ) == False ) :
  ooo0OO0O = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 51 - 51: IiII
 if ( ooo0OO0O == False ) :
  ooo0OO0O = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 43 - 43: oO0o - I11i . i11iIiiIii
  if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
 if ( ooo0OO0O ) :
  oooOoOoo0o = lisp_print_eid_tuple ( eid , group )
  ii1IiIiIi11 = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 57 - 57: I11i % II111iiii
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( oooOoOoo0o , False ) , s ,
  # IiII * OoOoOO00 . ooOoO0o / IiII . o0oOOo0O0Ooo
 ii1IiIiIi11 ) )
  if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
 return ( ooo0OO0O )
 if 90 - 90: o0oOOo0O0Ooo / I1ii11iIi11i - oO0o - Ii1I - I1IiiI + I1Ii111
 if 93 - 93: I1IiiI - I11i . I1IiiI - iIii1I11I1II1
 if 1 - 1: O0 . Ii1I % Ii1I + II111iiii . oO0o
 if 24 - 24: o0oOOo0O0Ooo . I1Ii111 % O0
 if 67 - 67: I1IiiI * Ii1I
 if 64 - 64: OOooOOo
 if 90 - 90: iII111i . OoOoOO00 + i1IIi % ooOoO0o * I11i + OoooooooOO
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 2 - 2: o0oOOo0O0Ooo . II111iiii
 iIII = lisp_map_referral ( )
 packet = iIII . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 9 - 9: I1Ii111 - II111iiii + OoOoOO00 . OoO0O00
 iIII . print_map_referral ( )
 if 33 - 33: Oo0Ooo
 IiII1iiI = source . print_address ( )
 oOO000 = iIII . nonce
 if 12 - 12: i11iIiiIii . Oo0Ooo / OoOoOO00 + iII111i . Ii1I + ooOoO0o
 if 66 - 66: IiII
 if 41 - 41: II111iiii + Oo0Ooo / iII111i . IiII / iII111i / I1IiiI
 if 78 - 78: o0oOOo0O0Ooo % OoOoOO00 . O0
 for IiIIi1IiiIiI in range ( iIII . record_count ) :
  iI1I1I1I11I11 = lisp_eid_record ( )
  packet = iI1I1I1I11I11 . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 41 - 41: iIii1I11I1II1 . OOooOOo - Oo0Ooo % OOooOOo
  iI1I1I1I11I11 . print_record ( "  " , True )
  if 90 - 90: i11iIiiIii + OoooooooOO - i11iIiiIii + OoooooooOO
  if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
  if 79 - 79: II111iiii / OoooooooOO
  if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
  ii1i1I1111ii = str ( oOO000 )
  if ( ii1i1I1111ii not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( oOO000 ) , IiII1iiI ) )
   if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
   if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
   continue
   if 17 - 17: I1Ii111
  O0O0OOoO00 = lisp_ddt_map_requestQ [ ii1i1I1111ii ]
  if ( O0O0OOoO00 == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( oOO000 ) , IiII1iiI ) )
   if 2 - 2: O0 % OoOoOO00 + oO0o
   continue
   if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
   if 51 - 51: IiII
   if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
   if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
   if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
   if 95 - 95: O0 - OoOoOO00
  if ( lisp_map_referral_loop ( O0O0OOoO00 , iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group ,
 iI1I1I1I11I11 . action , IiII1iiI ) ) :
   O0O0OOoO00 . dequeue_map_request ( )
   continue
   if 68 - 68: ooOoO0o . I1Ii111
   if 84 - 84: OoooooooOO + oO0o % i1IIi + o0oOOo0O0Ooo * i1IIi
  O0O0OOoO00 . last_cached_prefix [ 0 ] = iI1I1I1I11I11 . eid
  O0O0OOoO00 . last_cached_prefix [ 1 ] = iI1I1I1I11I11 . group
  if 51 - 51: oO0o . OoooooooOO + OOooOOo * I1ii11iIi11i - ooOoO0o
  if 41 - 41: Oo0Ooo
  if 46 - 46: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii . iII111i
  if 66 - 66: oO0o % i1IIi % OoooooooOO
  Ii11Iiiiii = False
  IIiii1I1 = lisp_referral_cache_lookup ( iI1I1I1I11I11 . eid , iI1I1I1I11I11 . group ,
 True )
  if ( IIiii1I1 == None ) :
   Ii11Iiiiii = True
   IIiii1I1 = lisp_referral ( )
   IIiii1I1 . eid = iI1I1I1I11I11 . eid
   IIiii1I1 . group = iI1I1I1I11I11 . group
   if ( iI1I1I1I11I11 . ddt_incomplete == False ) : IIiii1I1 . add_cache ( )
  elif ( IIiii1I1 . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( IIiii1I1 . print_eid_tuple ( ) , False ) ) )
   if 58 - 58: OOooOOo
   O0O0OOoO00 . dequeue_map_request ( )
   continue
   if 89 - 89: iIii1I11I1II1 - i1IIi
   if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
  Ooo0oo0oO000 = iI1I1I1I11I11 . action
  IIiii1I1 . referral_source = source
  IIiii1I1 . referral_type = Ooo0oo0oO000
  O0000 = iI1I1I1I11I11 . store_ttl ( )
  IIiii1I1 . referral_ttl = O0000
  IIiii1I1 . expires = lisp_set_timestamp ( O0000 )
  if 9 - 9: I1Ii111 / II111iiii * I1Ii111 / I11i - OoO0O00
  if 36 - 36: IiII . OoOoOO00 . Ii1I
  if 31 - 31: iIii1I11I1II1
  if 84 - 84: I1ii11iIi11i - iII111i * I1IiiI
  o0Ooo = IIiii1I1 . is_referral_negative ( )
  if ( IIiii1I1 . referral_set . has_key ( IiII1iiI ) ) :
   OOii1I1I1i = IIiii1I1 . referral_set [ IiII1iiI ]
   if 30 - 30: I11i / o0oOOo0O0Ooo
   if ( OOii1I1I1i . updown == False and o0Ooo == False ) :
    OOii1I1I1i . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( IiII1iiI ) )
    if 52 - 52: Oo0Ooo + IiII * IiII - II111iiii
   elif ( OOii1I1I1i . updown == True and o0Ooo == True ) :
    OOii1I1I1i . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( IiII1iiI ) )
    if 99 - 99: OoooooooOO - I1ii11iIi11i / i1IIi
    if 44 - 44: I1IiiI * oO0o - OoOoOO00 + ooOoO0o
    if 75 - 75: ooOoO0o % OoooooooOO / OoooooooOO / Ii1I / I11i % IiII
    if 68 - 68: II111iiii . iIii1I11I1II1
    if 23 - 23: iIii1I11I1II1 + I1Ii111 + I1IiiI - i11iIiiIii % IiII % i1IIi
    if 24 - 24: OOooOOo - OoOoOO00 - i1IIi + O0 + I1IiiI . o0oOOo0O0Ooo
    if 97 - 97: I1Ii111 + Ii1I * ooOoO0o
    if 95 - 95: O0
  OOooO0O0O0o = { }
  for ii1i1I1111ii in IIiii1I1 . referral_set : OOooO0O0O0o [ ii1i1I1111ii ] = None
  if 13 - 13: ooOoO0o
  if 63 - 63: iII111i . I11i
  if 24 - 24: oO0o
  if 42 - 42: I1ii11iIi11i - OOooOOo
  for IiIIi1IiiIiI in range ( iI1I1I1I11I11 . rloc_count ) :
   I1i11 = lisp_rloc_record ( )
   packet = I1i11 . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 99 - 99: OoooooooOO % OOooOOo / I11i
   I1i11 . print_record ( "    " )
   if 77 - 77: II111iiii - IiII % OOooOOo
   if 22 - 22: OoooooooOO / oO0o
   if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
   if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
   oo0o00OO = I1i11 . rloc . print_address ( )
   if ( IIiii1I1 . referral_set . has_key ( oo0o00OO ) == False ) :
    OOii1I1I1i = lisp_referral_node ( )
    OOii1I1I1i . referral_address . copy_address ( I1i11 . rloc )
    IIiii1I1 . referral_set [ oo0o00OO ] = OOii1I1I1i
    if ( IiII1iiI == oo0o00OO and o0Ooo ) : OOii1I1I1i . updown = False
   else :
    OOii1I1I1i = IIiii1I1 . referral_set [ oo0o00OO ]
    if ( OOooO0O0O0o . has_key ( oo0o00OO ) ) : OOooO0O0O0o . pop ( oo0o00OO )
    if 12 - 12: I1Ii111
   OOii1I1I1i . priority = I1i11 . priority
   OOii1I1I1i . weight = I1i11 . weight
   if 17 - 17: I1Ii111 % oO0o + O0
   if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
   if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
   if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
   if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
  for ii1i1I1111ii in OOooO0O0O0o : IIiii1I1 . referral_set . pop ( ii1i1I1111ii )
  if 39 - 39: OoOoOO00 - I1ii11iIi11i / I1Ii111
  I11i11i1 = IIiii1I1 . print_eid_tuple ( )
  if 48 - 48: IiII - oO0o + I11i % o0oOOo0O0Ooo
  if ( Ii11Iiiiii ) :
   if ( iI1I1I1I11I11 . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( I11i11i1 , False ) ) )
    if 81 - 81: Oo0Ooo . I1Ii111 * iIii1I11I1II1
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( I11i11i1 , False ) , iI1I1I1I11I11 . rloc_count ) )
    if 60 - 60: OoooooooOO
    if 41 - 41: iIii1I11I1II1 + O0 % o0oOOo0O0Ooo - IiII . I11i * O0
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( I11i11i1 , False ) , iI1I1I1I11I11 . rloc_count ) )
   if 39 - 39: i11iIiiIii . Ii1I
   if 68 - 68: OOooOOo * ooOoO0o . I1IiiI - iII111i
   if 81 - 81: I11i % Oo0Ooo / iII111i
   if 44 - 44: Oo0Ooo
   if 90 - 90: Oo0Ooo . ooOoO0o / IiII * I1Ii111 . ooOoO0o + II111iiii
   if 43 - 43: iIii1I11I1II1 % OOooOOo + OoOoOO00 + I1ii11iIi11i - Oo0Ooo / Ii1I
  if ( Ooo0oo0oO000 == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( O0O0OOoO00 . lisp_sockets , IIiii1I1 . eid ,
 IIiii1I1 . group , O0O0OOoO00 . nonce , O0O0OOoO00 . itr , O0O0OOoO00 . sport , 15 , None , False )
   O0O0OOoO00 . dequeue_map_request ( )
   if 94 - 94: Ii1I / Oo0Ooo % II111iiii % Oo0Ooo * oO0o
   if 54 - 54: O0 / ooOoO0o * I1Ii111
  if ( Ooo0oo0oO000 == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( O0O0OOoO00 . tried_root ) :
    lisp_send_negative_map_reply ( O0O0OOoO00 . lisp_sockets , IIiii1I1 . eid ,
 IIiii1I1 . group , O0O0OOoO00 . nonce , O0O0OOoO00 . itr , O0O0OOoO00 . sport , 0 , None , False )
    O0O0OOoO00 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( O0O0OOoO00 , True )
    if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
    if 13 - 13: IiII + Oo0Ooo - I1Ii111
    if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
  if ( Ooo0oo0oO000 == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( IIiii1I1 . referral_set . has_key ( IiII1iiI ) ) :
    OOii1I1I1i = IIiii1I1 . referral_set [ IiII1iiI ]
    OOii1I1I1i . updown = False
    if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
   if ( len ( IIiii1I1 . referral_set ) == 0 ) :
    O0O0OOoO00 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( O0O0OOoO00 , False )
    if 95 - 95: oO0o / Ii1I + OoO0O00
    if 57 - 57: iIii1I11I1II1 + I1Ii111 % oO0o - Ii1I . I1IiiI
    if 39 - 39: OoO0O00 + II111iiii
  if ( Ooo0oo0oO000 in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( O0O0OOoO00 . eid . is_exact_match ( iI1I1I1I11I11 . eid ) ) :
    if ( not O0O0OOoO00 . tried_root ) :
     lisp_send_ddt_map_request ( O0O0OOoO00 , True )
    else :
     lisp_send_negative_map_reply ( O0O0OOoO00 . lisp_sockets ,
 IIiii1I1 . eid , IIiii1I1 . group , O0O0OOoO00 . nonce , O0O0OOoO00 . itr ,
 O0O0OOoO00 . sport , 15 , None , False )
     O0O0OOoO00 . dequeue_map_request ( )
     if 98 - 98: O0 - I1Ii111 % oO0o - iII111i + Ii1I * i1IIi
   else :
    lisp_send_ddt_map_request ( O0O0OOoO00 , False )
    if 76 - 76: o0oOOo0O0Ooo
    if 55 - 55: OOooOOo + I1ii11iIi11i * Oo0Ooo
    if 11 - 11: i1IIi - OoooooooOO * OoOoOO00 / oO0o - OoooooooOO - I1IiiI
  if ( Ooo0oo0oO000 == LISP_DDT_ACTION_MS_ACK ) : O0O0OOoO00 . dequeue_map_request ( )
  if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
 return
 if 49 - 49: iII111i + I11i . Oo0Ooo
 if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
 if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
 if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
 if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
 if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
 if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
 if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 ooOoO = lisp_ecm ( 0 )
 packet = ooOoO . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 1 - 1: i11iIiiIii
  if 1 - 1: iIii1I11I1II1
 ooOoO . print_ecm ( )
 if 73 - 73: iII111i + IiII
 Ii1I1i1IiiI = lisp_control_header ( )
 if ( Ii1I1i1IiiI . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 95 - 95: O0
  if 75 - 75: ooOoO0o
 IiIiiIiI = Ii1I1i1IiiI . type
 del ( Ii1I1i1IiiI )
 if 47 - 47: iII111i * ooOoO0o . I1IiiI / O0
 if ( IiIiiIiI != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 81 - 81: iII111i + I11i - I1ii11iIi11i + iIii1I11I1II1 / ooOoO0o
  if 60 - 60: iIii1I11I1II1 - OoO0O00
  if 11 - 11: IiII + I1IiiI . Ii1I * I1IiiI - OoooooooOO . II111iiii
  if 74 - 74: o0oOOo0O0Ooo . iIii1I11I1II1 * Ii1I / O0 - I1Ii111 % oO0o
  if 98 - 98: IiII
 Iii1iiIiI = ooOoO . udp_sport
 I1II1i = time . time ( )
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 ooOoO . source , Iii1iiIiI , ooOoO . ddt , - 1 , I1II1i )
 return
 if 50 - 50: OOooOOo
 if 20 - 20: i11iIiiIii
 if 10 - 10: iIii1I11I1II1 % i1IIi
 if 78 - 78: I11i + II111iiii % o0oOOo0O0Ooo
 if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
 if 44 - 44: I1ii11iIi11i
 if 39 - 39: iII111i + Oo0Ooo / oO0o
 if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
 if 99 - 99: I1IiiI * II111iiii
 if 84 - 84: II111iiii - I1IiiI
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
 if 35 - 35: I11i + i1IIi
 if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
 if 97 - 97: oO0o % iIii1I11I1II1
 if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
 if 16 - 16: I1IiiI
 if 39 - 39: ooOoO0o * II111iiii
 oO0o0 = ms . map_server
 if ( lisp_decent_push_configured and oO0o0 . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  oO0o0 = copy . deepcopy ( oO0o0 )
  oO0o0 . address = 0x7f000001
  I11i1iIiiIiIi = bold ( "Bootstrap" , False )
  i11ii = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( I11i1iIiiIiIi , i11ii ) )
  if 90 - 90: OoooooooOO * ooOoO0o
  if 14 - 14: I1IiiI % i1IIi
  if 35 - 35: ooOoO0o % o0oOOo0O0Ooo % ooOoO0o
  if 77 - 77: OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
  if 55 - 55: i1IIi
  if 64 - 64: oO0o . OOooOOo * i11iIiiIii + I1Ii111
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 88 - 88: O0
 if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
 if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
 if 90 - 90: i11iIiiIii - iII111i * oO0o
 if 79 - 79: IiII
 if ( ms . ekey != None ) :
  iIIi1oOoO0OoooOoOO = ms . ekey . zfill ( 32 )
  i1Oo = "0" * 8
  o0o0oO0OOO = chacha . ChaCha ( iIIi1oOoO0OoooOoOO , i1Oo ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + o0o0oO0OOO
  oOo = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( oOo , ms . ekey_id ) )
  if 38 - 38: I1Ii111
  if 56 - 56: i11iIiiIii
 ooOoOOoOOO = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  ooOoOOoOOO = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 84 - 84: OoooooooOO + Oo0Ooo . I11i + OOooOOo
  if 11 - 11: O0 . I1IiiI
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( oO0o0 . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , ooOoOOoOOO ) )
 if 86 - 86: IiII * II111iiii * ooOoO0o / OoooooooOO
 lisp_send ( lisp_sockets , oO0o0 , LISP_CTRL_PORT , packet )
 return
 if 73 - 73: i11iIiiIii - Oo0Ooo
 if 100 - 100: iIii1I11I1II1 + I1Ii111
 if 51 - 51: o0oOOo0O0Ooo * I11i
 if 42 - 42: OOooOOo % I11i
 if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
 if 81 - 81: I1IiiI
 if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
 if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 oo00Oo0 = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 83 - 83: iII111i - I1ii11iIi11i + iII111i
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
 if 60 - 60: I1ii11iIi11i / I1Ii111 % i11iIiiIii % oO0o % I1IiiI . Oo0Ooo
 packet = lisp_control_packet_ipc ( packet , oo00Oo0 , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 20 - 20: IiII - OOooOOo + OoOoOO00
 if 83 - 83: OoooooooOO / I1IiiI + iII111i - iIii1I11I1II1 % ooOoO0o
 if 74 - 74: OoO0O00
 if 13 - 13: I1ii11iIi11i / OoO0O00
 if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
 if 94 - 94: IiII * i1IIi
 if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
 if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
 if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
 if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
 if 32 - 32: I1IiiI + II111iiii * iII111i + O0 / O0 * Oo0Ooo
 if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
 if 66 - 66: i1IIi
 if 98 - 98: Oo0Ooo / iIii1I11I1II1
 if 33 - 33: O0 - iII111i
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 40 - 40: iII111i * I11i
 if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
 if 87 - 87: OoOoOO00
 if 30 - 30: IiII % OoOoOO00 + I1Ii111
 if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
 if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
 if 87 - 87: I11i
 if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 72 - 72: OoO0O00 * Oo0Ooo - IiII
 if 74 - 74: Ii1I
 if 26 - 26: I11i . O0
 if 68 - 68: Ii1I
 if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
 if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
 if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 44 - 44: I11i * iIii1I11I1II1 . I1ii11iIi11i
  if 9 - 9: o0oOOo0O0Ooo
  if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
  if 21 - 21: Ii1I * OoOoOO00
  if 29 - 29: iIii1I11I1II1 / ooOoO0o
  if 75 - 75: OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
 if ( lisp_nat_traversal ) :
  i1i1IIiII1I = lisp_get_any_translated_port ( )
  if ( i1i1IIiII1I != None ) : inner_sport = i1i1IIiII1I
  if 88 - 88: OoO0O00 % Ii1I
 ooOoO = lisp_ecm ( inner_sport )
 if 12 - 12: OoooooooOO . O0
 ooOoO . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 ooOoO . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 ooOoO . ddt = ddt
 Iii1 = ooOoO . encode ( packet , inner_source , inner_dest )
 if ( Iii1 == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 95 - 95: I1IiiI / OoooooooOO
 ooOoO . print_ecm ( )
 if 29 - 29: OoOoOO00
 packet = Iii1 + packet
 if 100 - 100: o0oOOo0O0Ooo - I1IiiI / I11i
 oo0o00OO = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( oo0o00OO ) )
 oO0o0 = lisp_convert_4to6 ( oo0o00OO )
 lisp_send ( lisp_sockets , oO0o0 , LISP_CTRL_PORT , packet )
 return
 if 43 - 43: o0oOOo0O0Ooo % iIii1I11I1II1
 if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
 if 4 - 4: Ii1I . i1IIi + Oo0Ooo % I11i . OoO0O00
 if 70 - 70: OOooOOo * OoOoOO00 / OoOoOO00 / OoOoOO00
 if 23 - 23: I1IiiI
 if 24 - 24: I1Ii111 * i1IIi % O0 * Ii1I + iII111i
 if 14 - 14: oO0o * iII111i + Ii1I + Ii1I * IiII
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
if 82 - 82: IiII * ooOoO0o / OOooOOo + OoOoOO00
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 32 - 32: IiII
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 90 - 90: I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
if 96 - 96: O0
if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
if 61 - 61: IiII . O0
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
def byte_swap_64 ( address ) :
 IiiIIi1 = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 32 - 32: OoO0O00 + OOooOOo . OoO0O00 - Oo0Ooo
 if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
 if 86 - 86: OOooOOo / OoooooooOO - IiII
 if 56 - 56: I1ii11iIi11i - i1IIi * OoooooooOO * O0 * I1IiiI - I1Ii111
 if 32 - 32: OoooooooOO . OOooOOo . OoO0O00 . IiII / I11i % i1IIi
 if 21 - 21: O0 . OoO0O00 * I1ii11iIi11i % iII111i + OoooooooOO
 if 8 - 8: oO0o * iII111i * I11i
 if 30 - 30: I1Ii111
 return ( IiiIIi1 )
 if 61 - 61: iII111i
 if 50 - 50: Ii1I / I1IiiI . O0
 if 49 - 49: I1Ii111 . OoO0O00 % O0
 if 15 - 15: I11i - Oo0Ooo / I1Ii111 . ooOoO0o % I1IiiI
 if 62 - 62: II111iiii + ooOoO0o + I1IiiI
 if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
 if 13 - 13: I1ii11iIi11i
 if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
 if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
 if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
 if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
 if 18 - 18: OoooooooOO - I1ii11iIi11i
 if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
 if 79 - 79: OOooOOo + Oo0Ooo
 if 33 - 33: iIii1I11I1II1
class lisp_cache_entries ( ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
  if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
  if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
class lisp_cache ( ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
  if 99 - 99: OOooOOo
 def cache_size ( self ) :
  return ( self . cache_count )
  if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
  if 53 - 53: oO0o / i1IIi - Oo0Ooo - i1IIi + IiII
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   i111ii1I111Ii = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   i111ii1I111Ii = prefix . mask_len
  else :
   i111ii1I111Ii = prefix . mask_len + 48
   if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
   if 56 - 56: Oo0Ooo % I1ii11iIi11i
  o0OoO0000o = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  O000oOOoOOO = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 53 - 53: OoO0O00 . I11i - ooOoO0o
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    iiiIIiiIi = prefix . addr_length ( ) * 2
    IiiIIi1 = lisp_hex_string ( prefix . address ) . zfill ( iiiIIiiIi )
   else :
    IiiIIi1 = prefix . address
    if 11 - 11: I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   O000oOOoOOO = "8003"
   IiiIIi1 = prefix . address . print_geo ( )
  else :
   O000oOOoOOO = ""
   IiiIIi1 = ""
   if 74 - 74: oO0o . I1Ii111 . II111iiii
   if 92 - 92: I1Ii111 % OoooooooOO * I1Ii111
  ii1i1I1111ii = o0OoO0000o + O000oOOoOOO + IiiIIi1
  return ( [ i111ii1I111Ii , ii1i1I1111ii ] )
  if 78 - 78: Oo0Ooo . I11i . oO0o + O0 / O0
  if 41 - 41: iII111i * OoO0O00 - OoO0O00
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  i111ii1I111Ii , ii1i1I1111ii = self . build_key ( prefix )
  if ( self . cache . has_key ( i111ii1I111Ii ) == False ) :
   self . cache [ i111ii1I111Ii ] = lisp_cache_entries ( )
   self . cache [ i111ii1I111Ii ] . entries = { }
   self . cache [ i111ii1I111Ii ] . entries_sorted = [ ]
   self . cache_sorted = sorted ( self . cache )
   if 72 - 72: o0oOOo0O0Ooo + oO0o . I1ii11iIi11i + OoO0O00 / I1Ii111
  if ( self . cache [ i111ii1I111Ii ] . entries . has_key ( ii1i1I1111ii ) == False ) :
   self . cache_count += 1
   if 58 - 58: Oo0Ooo / II111iiii % OoooooooOO % II111iiii
  self . cache [ i111ii1I111Ii ] . entries [ ii1i1I1111ii ] = entry
  self . cache [ i111ii1I111Ii ] . entries_sorted = sorted ( self . cache [ i111ii1I111Ii ] . entries )
  if 39 - 39: i1IIi
  if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
 def lookup_cache ( self , prefix , exact ) :
  oOOo , ii1i1I1111ii = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( oOOo ) == False ) : return ( None )
   if ( self . cache [ oOOo ] . entries . has_key ( ii1i1I1111ii ) == False ) : return ( None )
   return ( self . cache [ oOOo ] . entries [ ii1i1I1111ii ] )
   if 41 - 41: OoOoOO00 - iIii1I11I1II1
   if 40 - 40: i11iIiiIii / I1Ii111 . iII111i % I11i - Oo0Ooo
  O00o0 = None
  for i111ii1I111Ii in self . cache_sorted :
   if ( oOOo < i111ii1I111Ii ) : return ( O00o0 )
   for OOO00o0o0 in self . cache [ i111ii1I111Ii ] . entries_sorted :
    OoooOOo0Oo00o = self . cache [ i111ii1I111Ii ] . entries
    if ( OOO00o0o0 in OoooOOo0Oo00o ) :
     I1iII11ii1 = OoooOOo0Oo00o [ OOO00o0o0 ]
     if ( I1iII11ii1 == None ) : continue
     if ( prefix . is_more_specific ( I1iII11ii1 . eid ) ) : O00o0 = I1iII11ii1
     if 100 - 100: Oo0Ooo - OoOoOO00 % I1ii11iIi11i % OoOoOO00 - iIii1I11I1II1 . OoO0O00
     if 88 - 88: Ii1I % i1IIi / I1Ii111
     if 2 - 2: Ii1I . IiII % OoOoOO00
  return ( O00o0 )
  if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
  if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
 def delete_cache ( self , prefix ) :
  i111ii1I111Ii , ii1i1I1111ii = self . build_key ( prefix )
  if ( self . cache . has_key ( i111ii1I111Ii ) == False ) : return
  if ( self . cache [ i111ii1I111Ii ] . entries . has_key ( ii1i1I1111ii ) == False ) : return
  self . cache [ i111ii1I111Ii ] . entries . pop ( ii1i1I1111ii )
  self . cache [ i111ii1I111Ii ] . entries_sorted . remove ( ii1i1I1111ii )
  self . cache_count -= 1
  if 35 - 35: i11iIiiIii
  if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
 def walk_cache ( self , function , parms ) :
  for i111ii1I111Ii in self . cache_sorted :
   for ii1i1I1111ii in self . cache [ i111ii1I111Ii ] . entries_sorted :
    I1iII11ii1 = self . cache [ i111ii1I111Ii ] . entries [ ii1i1I1111ii ]
    OOOoo , parms = function ( I1iII11ii1 , parms )
    if ( OOOoo == False ) : return ( parms )
    if 10 - 10: oO0o - O0 / Ii1I - OOooOOo - I1Ii111
    if 41 - 41: O0 / I1IiiI - I1ii11iIi11i - i11iIiiIii
  return ( parms )
  if 2 - 2: OoO0O00 % O0 + iII111i * I1Ii111 / OOooOOo
  if 7 - 7: IiII
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 30 - 30: iIii1I11I1II1 - OoooooooOO + Oo0Ooo . i1IIi % o0oOOo0O0Ooo
  for i111ii1I111Ii in self . cache_sorted :
   for ii1i1I1111ii in self . cache [ i111ii1I111Ii ] . entries_sorted :
    I1iII11ii1 = self . cache [ i111ii1I111Ii ] . entries [ ii1i1I1111ii ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( i111ii1I111Ii , ii1i1I1111ii ,
 I1iII11ii1 ) )
    if 7 - 7: IiII - iII111i
    if 59 - 59: Oo0Ooo * ooOoO0o - Ii1I / II111iiii / Oo0Ooo
    if 8 - 8: IiII / OoooooooOO - iIii1I11I1II1
    if 10 - 10: I11i . I11i - OoO0O00 - II111iiii
    if 94 - 94: ooOoO0o
    if 28 - 28: IiII
    if 55 - 55: ooOoO0o + oO0o + OoOoOO00 / O0 * II111iiii * OoOoOO00
    if 53 - 53: Oo0Ooo
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 16 - 16: Ii1I
if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
if 78 - 78: OoO0O00 + oO0o
if 86 - 86: ooOoO0o . ooOoO0o + oO0o
if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
if 31 - 31: IiII + iII111i
if 5 - 5: O0 * Ii1I
def lisp_map_cache_lookup ( source , dest ) :
 if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
 OO00o0o0oo = dest . is_multicast_address ( )
 if 77 - 77: OOooOOo / OoooooooOO
 if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
 if 79 - 79: i11iIiiIii % o0oOOo0O0Ooo * II111iiii . i1IIi * Ii1I - i11iIiiIii
 if 31 - 31: IiII / o0oOOo0O0Ooo
 O0oOO0OOO = lisp_map_cache . lookup_cache ( dest , False )
 if ( O0oOO0OOO == None ) :
  I11i11i1 = source . print_sg ( dest ) if OO00o0o0oo else dest . print_address ( )
  I11i11i1 = green ( I11i11i1 , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( I11i11i1 ) )
  return ( None )
  if 27 - 27: Oo0Ooo
  if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
  if 35 - 35: o0oOOo0O0Ooo % iII111i / O0 * I1IiiI . o0oOOo0O0Ooo / OOooOOo
  if 81 - 81: I1ii11iIi11i - i11iIiiIii
  if 49 - 49: iII111i * I11i - II111iiii . o0oOOo0O0Ooo
 if ( OO00o0o0oo == False ) :
  ii111IIiI = green ( O0oOO0OOO . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , ii111IIiI ) )
  if 52 - 52: Ii1I + Ii1I - II111iiii . O0 + I1ii11iIi11i
  return ( O0oOO0OOO )
  if 60 - 60: i11iIiiIii + IiII
  if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
  if 86 - 86: Ii1I / oO0o
  if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
  if 60 - 60: II111iiii / Ii1I
 O0oOO0OOO = O0oOO0OOO . lookup_source_cache ( source , False )
 if ( O0oOO0OOO == None ) :
  I11i11i1 = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( I11i11i1 ) )
  return ( None )
  if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
  if 89 - 89: i1IIi / I1Ii111 + Ii1I - i1IIi
  if 66 - 66: OoooooooOO
  if 68 - 68: iII111i + I1Ii111
  if 90 - 90: o0oOOo0O0Ooo
 ii111IIiI = green ( O0oOO0OOO . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , ii111IIiI ) )
 if 48 - 48: iII111i + Ii1I
 return ( O0oOO0OOO )
 if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
 if 89 - 89: OOooOOo - I1Ii111 - iII111i
 if 67 - 67: oO0o
 if 76 - 76: I1IiiI % I1IiiI - IiII / OoOoOO00 / I1ii11iIi11i
 if 42 - 42: I1IiiI + I1ii11iIi11i + Oo0Ooo * i1IIi - II111iiii
 if 15 - 15: o0oOOo0O0Ooo
 if 60 - 60: I1ii11iIi11i / I1Ii111
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  iIii = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( iIii )
  if 13 - 13: I1Ii111
  if 52 - 52: II111iiii / OoO0O00 . Ii1I
  if 68 - 68: iII111i
  if 67 - 67: I1IiiI * I1IiiI
  if 100 - 100: iII111i * iII111i . Oo0Ooo
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 10 - 10: Oo0Ooo % ooOoO0o * Oo0Ooo
 if 48 - 48: ooOoO0o + II111iiii
 if 73 - 73: II111iiii
 if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
 if 35 - 35: II111iiii + IiII
 if 66 - 66: o0oOOo0O0Ooo % IiII
 iIii = lisp_referral_cache . lookup_cache ( group , exact )
 if ( iIii == None ) : return ( None )
 if 39 - 39: IiII
 i1IIiI1III = iIii . lookup_source_cache ( eid , exact )
 if ( i1IIiI1III ) : return ( i1IIiI1III )
 if 86 - 86: OOooOOo * I1ii11iIi11i . I1Ii111 . I11i % Oo0Ooo
 if ( exact ) : iIii = None
 return ( iIii )
 if 26 - 26: i11iIiiIii
 if 1 - 1: I11i / oO0o . O0 . i1IIi - O0
 if 18 - 18: I11i + ooOoO0o . i1IIi / OoOoOO00
 if 84 - 84: II111iiii / I1Ii111 / i11iIiiIii + I1ii11iIi11i
 if 27 - 27: iII111i / OoooooooOO
 if 76 - 76: I1ii11iIi11i + Ii1I . IiII % ooOoO0o
 if 57 - 57: iII111i % OOooOOo . oO0o + iIii1I11I1II1 + Oo0Ooo . O0
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  oo00O00ooO = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( oo00O00ooO )
  if 3 - 3: OoooooooOO % i11iIiiIii / II111iiii / OOooOOo
  if 12 - 12: Ii1I / IiII - OoO0O00 % I11i + ooOoO0o * OoooooooOO
  if 37 - 37: OoO0O00 % i11iIiiIii
  if 13 - 13: OoooooooOO - II111iiii / OoOoOO00 + OoooooooOO * oO0o
  if 32 - 32: I1Ii111 + OoooooooOO - OoOoOO00 . IiII
 if ( eid . is_null ( ) ) : return ( None )
 if 33 - 33: OoOoOO00 - I1IiiI + iII111i . iII111i
 if 68 - 68: OoO0O00 / OoO0O00 - I1IiiI + OoOoOO00
 if 22 - 22: iIii1I11I1II1 . i1IIi . OOooOOo % Oo0Ooo - i1IIi
 if 78 - 78: I1IiiI / i1IIi % II111iiii % I1IiiI % Ii1I
 if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
 if 38 - 38: IiII . I1Ii111
 oo00O00ooO = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( oo00O00ooO == None ) : return ( None )
 if 69 - 69: ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + Ii1I . ooOoO0o
 O0o0O0Oo0oo = oo00O00ooO . lookup_source_cache ( eid , exact )
 if ( O0o0O0Oo0oo ) : return ( O0o0O0Oo0oo )
 if 92 - 92: i1IIi
 if ( exact ) : oo00O00ooO = None
 return ( oo00O00ooO )
 if 3 - 3: iIii1I11I1II1 . I1ii11iIi11i
 if 97 - 97: O0
 if 82 - 82: OoooooooOO / I1Ii111 - ooOoO0o . I1Ii111
 if 41 - 41: I11i . I11i
 if 12 - 12: OoOoOO00 / I1IiiI
 if 4 - 4: Oo0Ooo * o0oOOo0O0Ooo
 if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
 if ( group . is_null ( ) ) :
  Ii1ii1 = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( Ii1ii1 )
  if 69 - 69: iII111i % I1ii11iIi11i
  if 19 - 19: IiII
  if 35 - 35: OoOoOO00
  if 18 - 18: II111iiii . OoOoOO00 + I1ii11iIi11i * oO0o + OoooooooOO
  if 39 - 39: I1IiiI * ooOoO0o / i11iIiiIii - oO0o - oO0o + O0
 if ( eid . is_null ( ) ) : return ( None )
 if 73 - 73: OOooOOo
 if 44 - 44: I1ii11iIi11i * i1IIi - iIii1I11I1II1 - oO0o - oO0o * II111iiii
 if 98 - 98: Oo0Ooo + ooOoO0o / OOooOOo . iIii1I11I1II1 . I1IiiI . OoOoOO00
 if 92 - 92: i1IIi + OoOoOO00 * i1IIi / IiII
 if 4 - 4: oO0o % OoO0O00 + IiII + o0oOOo0O0Ooo
 if 82 - 82: O0 / I1Ii111 + OOooOOo . IiII + Ii1I
 Ii1ii1 = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( Ii1ii1 == None ) : return ( None )
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
 if 78 - 78: OoOoOO00 - oO0o . I1ii11iIi11i * i11iIiiIii
 if 44 - 44: iIii1I11I1II1 * iII111i
 if 32 - 32: OoOoOO00
 if 65 - 65: iIii1I11I1II1 + iII111i
 IIiiiiI1i = Ii1ii1 . lookup_source_cache ( eid , exact )
 if ( IIiiiiI1i ) : return ( IIiiiiI1i )
 if 90 - 90: i11iIiiIii - Oo0Ooo
 if ( exact ) :
  Ii1ii1 = None
 else :
  ooOOo000II = Ii1ii1 . parent_for_more_specifics
  if ( ooOOo000II and ooOOo000II . accept_more_specifics ) :
   if ( group . is_more_specific ( ooOOo000II . group ) ) : Ii1ii1 = ooOOo000II
   if 31 - 31: OoOoOO00 + OoOoOO00 + OoooooooOO % O0
   if 14 - 14: i1IIi / OoooooooOO . I1IiiI * I1Ii111 + OoO0O00
 return ( Ii1ii1 )
 if 45 - 45: OoooooooOO * I1Ii111
 if 7 - 7: O0
 if 42 - 42: o0oOOo0O0Ooo / Ii1I
 if 31 - 31: OOooOOo
 if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
 if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
 if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
 if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
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
class lisp_address ( ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 47 - 47: i11iIiiIii
  if 21 - 21: i1IIi - oO0o - Oo0Ooo
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 11 - 11: i1IIi
  if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
  if 56 - 56: Ii1I . iII111i
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 52 - 52: i11iIiiIii
   if 1 - 1: i1IIi * iIii1I11I1II1
   if 29 - 29: I11i
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
  if 6 - 6: IiII / OoO0O00
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  IiiIIi1 = self . address
  if ( ( ( IiiIIi1 & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( IiiIIi1 & 0xff000000 ) >> 24 ) == 172 ) :
   O00oO0O0 = ( IiiIIi1 & 0x00ff0000 ) >> 16
   if ( O00oO0O0 >= 16 and O00oO0O0 <= 31 ) : return ( True )
   if 12 - 12: Oo0Ooo . OOooOOo / OoooooooOO + o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if ( ( ( IiiIIi1 & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 34 - 34: OOooOOo * iIii1I11I1II1 + OoooooooOO - I1Ii111 . I11i / II111iiii
  if 4 - 4: OoooooooOO * I1IiiI * II111iiii
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 72 - 72: I1Ii111
  if 80 - 80: iII111i + i1IIi
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 50 - 50: Ii1I
  return ( 0 )
  if 42 - 42: OoO0O00 / II111iiii % iII111i + I1Ii111 / O0
  if 91 - 91: iII111i * I1Ii111 - IiII - IiII * OOooOOo
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  IiiIIi1 = self . address >> 96
  return ( IiiIIi1 == 0x20010005 )
  if 84 - 84: I1Ii111 - O0 % i11iIiiIii / OoooooooOO
  if 75 - 75: Ii1I + ooOoO0o
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
   if 51 - 51: Ii1I . o0oOOo0O0Ooo * OOooOOo * I1IiiI
  return ( 0 )
  if 23 - 23: OoOoOO00
  if 39 - 39: OoOoOO00
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 40 - 40: IiII + II111iiii - Ii1I + Ii1I
  if 96 - 96: OoooooooOO * i1IIi * IiII + I11i
 def packet_format ( self ) :
  if 35 - 35: oO0o
  if 77 - 77: ooOoO0o + I1ii11iIi11i * o0oOOo0O0Ooo / i1IIi * I11i
  if 70 - 70: oO0o / iII111i * i1IIi / II111iiii / OoOoOO00 + oO0o
  if 30 - 30: i1IIi - iII111i - i11iIiiIii . OoOoOO00 . o0oOOo0O0Ooo
  if 74 - 74: i11iIiiIii / II111iiii
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 62 - 62: O0
  if 63 - 63: Oo0Ooo + Oo0Ooo
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
   iI1IiI1I1111I = IiiIIi1 & 0xffff
   IIii1i = struct . pack ( O00oO00oOO00O , Ii1iiI1i1 , iIi , iI1IiI1I1111I )
  elif ( self . is_e164 ( ) ) :
   IiiIIi1 = self . address
   Ii1iiI1i1 = ( IiiIIi1 >> 32 ) & 0xffffffff
   iIi = ( IiiIIi1 & 0xffffffff )
   IIii1i = struct . pack ( O00oO00oOO00O , Ii1iiI1i1 , iIi )
  elif ( self . is_dist_name ( ) ) :
   IIii1i += self . address + "\0"
   if 13 - 13: iII111i - O0
  return ( IIii1i )
  if 11 - 11: iIii1I11I1II1 + II111iiii % II111iiii
  if 33 - 33: I1IiiI * OoooooooOO % Ii1I
 def unpack_address ( self , packet ) :
  O00oO00oOO00O = self . packet_format ( )
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 79 - 79: ooOoO0o / I11i . I1ii11iIi11i
  IiiIIi1 = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( IiiIIi1 [ 0 ] )
   if 81 - 81: I1Ii111 % OoO0O00 / O0
  elif ( self . is_ipv6 ( ) ) :
   if 55 - 55: i1IIi - I1Ii111 + I11i
   if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
   if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
   if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
   if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
   if 34 - 34: I1IiiI + I1Ii111 % ooOoO0o
   if 24 - 24: Ii1I % II111iiii - i11iIiiIii
   if 52 - 52: OoO0O00
   if ( IiiIIi1 [ 0 ] <= 0xffff and ( IiiIIi1 [ 0 ] & 0xff ) == 0 ) :
    O000o0oO = ( IiiIIi1 [ 0 ] << 48 ) << 64
   else :
    O000o0oO = byte_swap_64 ( IiiIIi1 [ 0 ] ) << 64
    if 67 - 67: iIii1I11I1II1 + OOooOOo * i11iIiiIii
   oOoOooO0 = byte_swap_64 ( IiiIIi1 [ 1 ] )
   self . address = O000o0oO | oOoOooO0
   if 43 - 43: I1Ii111 * OOooOOo - IiII . i11iIiiIii
  elif ( self . is_mac ( ) ) :
   i1i1IIIi11Ii = IiiIIi1 [ 0 ]
   IIo0Oo0ooO0o0 = IiiIIi1 [ 1 ]
   i1I1iI111111I = IiiIIi1 [ 2 ]
   self . address = ( i1i1IIIi11Ii << 32 ) + ( IIo0Oo0ooO0o0 << 16 ) + i1I1iI111111I
   if 36 - 36: oO0o - I1Ii111
  elif ( self . is_e164 ( ) ) :
   self . address = ( IiiIIi1 [ 0 ] << 32 ) + IiiIIi1 [ 1 ]
   if 55 - 55: oO0o
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   ooOoooOoo0oO = 0
   if 10 - 10: I1IiiI
  packet = packet [ ooOoooOoo0oO : : ]
  return ( packet )
  if 17 - 17: i11iIiiIii % o0oOOo0O0Ooo . ooOoO0o
  if 34 - 34: OoooooooOO / iII111i / O0
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
  if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
  if 40 - 40: OOooOOo - OoooooooOO
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 36 - 36: i1IIi % OoOoOO00 - i1IIi
  if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 97 - 97: I11i . ooOoO0o
  if 87 - 87: oO0o / iIii1I11I1II1 - I11i + OoooooooOO
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 79 - 79: I1ii11iIi11i * IiII . I1ii11iIi11i
  if 65 - 65: iII111i - Ii1I - II111iiii * O0 + I1ii11iIi11i . iIii1I11I1II1
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 76 - 76: OoO0O00 * ooOoO0o
  if 32 - 32: O0 . oO0o * o0oOOo0O0Ooo . Ii1I + IiII
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 98 - 98: iII111i . II111iiii % O0
  if 43 - 43: OOooOOo % I1Ii111 . IiII % OoO0O00 + I1Ii111 % OoooooooOO
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 17 - 17: OoooooooOO - i1IIi * I11i
  if 33 - 33: i1IIi . Oo0Ooo + I11i
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
  if 78 - 78: I1Ii111 + I1Ii111
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
  if 19 - 19: Ii1I
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 51 - 51: oO0o
  if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 35 - 35: o0oOOo0O0Ooo % II111iiii + O0
  if 70 - 70: I1ii11iIi11i . II111iiii
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 54 - 54: OOooOOo
  if 67 - 67: I1IiiI . o0oOOo0O0Ooo / i1IIi * I1ii11iIi11i . Oo0Ooo + II111iiii
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 63 - 63: OoOoOO00 - OoOoOO00
  if 31 - 31: I1ii11iIi11i % O0 - i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o * ooOoO0o
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 18 - 18: OoO0O00 - OoO0O00 . o0oOOo0O0Ooo
  if 80 - 80: I11i + I1Ii111 / I1IiiI * OOooOOo % iII111i
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 48 - 48: iIii1I11I1II1 + i1IIi . I1IiiI % OoO0O00 - iIii1I11I1II1 / i1IIi
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 14 - 14: IiII . I11i
  return ( False )
  if 13 - 13: OoOoOO00 - I11i . OOooOOo % OoO0O00
  if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
  if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
  if 9 - 9: iIii1I11I1II1
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
  if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 34 - 34: iIii1I11I1II1
  if 65 - 65: II111iiii - iII111i / o0oOOo0O0Ooo
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 35 - 35: i11iIiiIii - Oo0Ooo . I1ii11iIi11i % OoOoOO00
  if 20 - 20: OoO0O00
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 93 - 93: ooOoO0o + o0oOOo0O0Ooo - I1ii11iIi11i
  if 56 - 56: Ii1I / Oo0Ooo
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 96 - 96: o0oOOo0O0Ooo . II111iiii
  if 14 - 14: OoooooooOO - i1IIi / i11iIiiIii - OOooOOo - i11iIiiIii . ooOoO0o
  if 8 - 8: oO0o * O0 - II111iiii + I1IiiI
  if 85 - 85: OoooooooOO % i11iIiiIii / IiII % OoOoOO00 + O0
  IiIIi1IiiIiI = addr_str . find ( "[" )
  O0OO00 = addr_str . find ( "]" )
  if ( IiIIi1IiiIiI != - 1 and O0OO00 != - 1 ) :
   self . instance_id = int ( addr_str [ IiIIi1IiiIiI + 1 : O0OO00 ] )
   addr_str = addr_str [ O0OO00 + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 6 - 6: OoooooooOO
    if 97 - 97: II111iiii + o0oOOo0O0Ooo * II111iiii
    if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
    if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
    if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
    if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
  if ( self . is_ipv4 ( ) ) :
   i11i1IIIiI1i = addr_str . split ( "." )
   i11II = int ( i11i1IIIiI1i [ 0 ] ) << 24
   i11II += int ( i11i1IIIiI1i [ 1 ] ) << 16
   i11II += int ( i11i1IIIiI1i [ 2 ] ) << 8
   i11II += int ( i11i1IIIiI1i [ 3 ] )
   self . address = i11II
  elif ( self . is_ipv6 ( ) ) :
   if 55 - 55: Ii1I . I1IiiI
   if 3 - 3: OoOoOO00 * I11i % I11i
   if 72 - 72: iII111i / I11i / I11i + I1IiiI * oO0o
   if 44 - 44: iII111i
   if 38 - 38: iII111i * i1IIi * iIii1I11I1II1 % iII111i . I1IiiI
   if 73 - 73: I1Ii111 / o0oOOo0O0Ooo * Oo0Ooo
   if 22 - 22: i11iIiiIii
   if 58 - 58: OOooOOo + o0oOOo0O0Ooo
   if 48 - 48: OOooOOo % i11iIiiIii + OoooooooOO
   if 64 - 64: OoooooooOO + OoooooooOO % OoO0O00 - OoooooooOO
   if 86 - 86: OoOoOO00 - OoO0O00 + Ii1I % I1ii11iIi11i - Oo0Ooo + oO0o
   if 32 - 32: I11i . I1ii11iIi11i - oO0o + I11i / ooOoO0o
   if 24 - 24: I1IiiI / O0 . O0
   if 13 - 13: i11iIiiIii - i11iIiiIii . iIii1I11I1II1 - O0 . I11i / i11iIiiIii
   if 59 - 59: ooOoO0o + I1ii11iIi11i . OoO0O00 . O0
   if 45 - 45: O0 . o0oOOo0O0Ooo + OoOoOO00 / I1ii11iIi11i + Ii1I % I1Ii111
   if 20 - 20: Oo0Ooo
   IIIIIiI1 = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 13 - 13: iII111i
   addr_str = binascii . hexlify ( addr_str )
   if 35 - 35: I1IiiI
   if ( IIIIIiI1 ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 88 - 88: iII111i
   self . address = int ( addr_str , 16 )
   if 96 - 96: OoOoOO00
  elif ( self . is_geo_prefix ( ) ) :
   iii1iOoOooOOo = lisp_geo ( None )
   iii1iOoOooOOo . name = "geo-prefix-{}" . format ( iii1iOoOooOOo )
   iii1iOoOooOOo . parse_geo_string ( addr_str )
   self . address = iii1iOoOooOOo
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
   if 84 - 84: OOooOOo
  self . mask_len = self . host_mask_len ( )
  if 68 - 68: I1Ii111
  if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   ooo = prefix_str . find ( "]" )
   i111IiI1III1 = len ( prefix_str [ ooo + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , i111IiI1III1 = prefix_str . split ( "/" )
  else :
   i1i = prefix_str . find ( "'" )
   if ( i1i == - 1 ) : return
   O0ooOo0 = prefix_str . find ( "'" , i1i + 1 )
   if ( O0ooOo0 == - 1 ) : return
   i111IiI1III1 = len ( prefix_str [ i1i + 1 : O0ooOo0 ] ) * 8
   if 54 - 54: oO0o + I11i - OoO0O00
   if 86 - 86: OoooooooOO
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( i111IiI1III1 )
  if 51 - 51: i11iIiiIii
  if 91 - 91: OOooOOo
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  IiIIi1i = ( 2 ** self . mask_len ) - 1
  oo0O = self . addr_length ( ) * 8 - self . mask_len
  IiIIi1i <<= oo0O
  self . address &= IiIIi1i
  if 55 - 55: Ii1I + I1Ii111
  if 65 - 65: ooOoO0o
 def is_geo_string ( self , addr_str ) :
  ooo = addr_str . find ( "]" )
  if ( ooo != - 1 ) : addr_str = addr_str [ ooo + 1 : : ]
  if 73 - 73: I1IiiI . iIii1I11I1II1
  iii1iOoOooOOo = addr_str . split ( "/" )
  if ( len ( iii1iOoOooOOo ) == 2 ) :
   if ( iii1iOoOooOOo [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 50 - 50: OoO0O00 - O0 % OOooOOo
  iii1iOoOooOOo = iii1iOoOooOOo [ 0 ]
  iii1iOoOooOOo = iii1iOoOooOOo . split ( "-" )
  ii1III = len ( iii1iOoOooOOo )
  if ( ii1III < 8 or ii1III > 9 ) : return ( False )
  if 27 - 27: i1IIi / ooOoO0o * I1ii11iIi11i - II111iiii
  for II1i11III in range ( 0 , ii1III ) :
   if ( II1i11III == 3 ) :
    if ( iii1iOoOooOOo [ II1i11III ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 65 - 65: Ii1I + O0 + iIii1I11I1II1 % I1Ii111
   if ( II1i11III == 7 ) :
    if ( iii1iOoOooOOo [ II1i11III ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 23 - 23: OoooooooOO . I11i . II111iiii / oO0o - i11iIiiIii
   if ( iii1iOoOooOOo [ II1i11III ] . isdigit ( ) == False ) : return ( False )
   if 67 - 67: o0oOOo0O0Ooo . I1Ii111 % iIii1I11I1II1 / I1Ii111
  return ( True )
  if 18 - 18: I11i * ooOoO0o
  if 46 - 46: IiII
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 96 - 96: iII111i / i11iIiiIii + Oo0Ooo . I1IiiI + iII111i % OoOoOO00
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
  if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
 def print_address ( self ) :
  IiiIIi1 = self . print_address_no_iid ( )
  o0OoO0000o = "[" + str ( self . instance_id )
  for IiIIi1IiiIiI in self . iid_list : o0OoO0000o += "," + str ( IiIIi1IiiIiI )
  o0OoO0000o += "]"
  IiiIIi1 = "{}{}" . format ( o0OoO0000o , IiiIIi1 )
  return ( IiiIIi1 )
  if 87 - 87: iII111i
  if 86 - 86: IiII - I11i
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   IiiIIi1 = self . address
   ooOoOo0 = IiiIIi1 >> 24
   oO0oOOOOOOoOO = ( IiiIIi1 >> 16 ) & 0xff
   iIIi1iI1III1ii1I = ( IiiIIi1 >> 8 ) & 0xff
   OOO0ooo0oO0 = IiiIIi1 & 0xff
   return ( "{}.{}.{}.{}" . format ( ooOoOo0 , oO0oOOOOOOoOO , iIIi1iI1III1ii1I , OOO0ooo0oO0 ) )
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
   if 30 - 30: I1Ii111 - iII111i * OoO0O00 * ooOoO0o
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 94 - 94: OoO0O00 % II111iiii % iII111i + OoooooooOO - o0oOOo0O0Ooo * I1Ii111
  if 9 - 9: ooOoO0o . O0 + II111iiii . OoooooooOO
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   oooOoooOoo00o = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , oooOoooOoo00o ) )
   if 24 - 24: OoooooooOO % iII111i . II111iiii - O0 . i1IIi % Ii1I
  IiiIIi1 = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( IiiIIi1 )
  if ( self . is_geo_prefix ( ) ) : return ( IiiIIi1 )
  if 65 - 65: Oo0Ooo
  ooo = IiiIIi1 . find ( "no-address" )
  if ( ooo == - 1 ) :
   IiiIIi1 = "{}/{}" . format ( IiiIIi1 , str ( self . mask_len ) )
  else :
   IiiIIi1 = IiiIIi1 [ 0 : ooo ]
   if 64 - 64: I1ii11iIi11i * OoOoOO00 + II111iiii . I11i - I1IiiI * O0
  return ( IiiIIi1 )
  if 74 - 74: OoO0O00 * O0 - oO0o * OoooooooOO % I1Ii111
  if 95 - 95: OoOoOO00 + ooOoO0o . iIii1I11I1II1 * o0oOOo0O0Ooo
 def print_prefix_no_iid ( self ) :
  IiiIIi1 = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( IiiIIi1 )
  if ( self . is_geo_prefix ( ) ) : return ( IiiIIi1 )
  return ( "{}/{}" . format ( IiiIIi1 , str ( self . mask_len ) ) )
  if 75 - 75: OOooOOo - i11iIiiIii - i1IIi - IiII * iII111i
  if 38 - 38: o0oOOo0O0Ooo - I1ii11iIi11i % o0oOOo0O0Ooo
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  IiiIIi1 = self . print_address ( )
  ooo = IiiIIi1 . find ( "]" )
  if ( ooo != - 1 ) : IiiIIi1 = IiiIIi1 [ ooo + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   IiiIIi1 = IiiIIi1 . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , IiiIIi1 ) )
   if 8 - 8: oO0o + I11i . I1ii11iIi11i
  return ( "{}-{}-{}" . format ( self . instance_id , IiiIIi1 , self . mask_len ) )
  if 57 - 57: I11i
  if 46 - 46: iII111i . OoO0O00 % Ii1I
 def print_sg ( self , g ) :
  IiII1iiI = self . print_prefix ( )
  I11III1I1II = IiII1iiI . find ( "]" ) + 1
  g = g . print_prefix ( )
  Oo0o0OoOo = g . find ( "]" ) + 1
  II11I = "[{}]({}, {})" . format ( self . instance_id , IiII1iiI [ I11III1I1II : : ] , g [ Oo0o0OoOo : : ] )
  return ( II11I )
  if 48 - 48: i1IIi / II111iiii + OOooOOo . OoOoOO00 / iII111i - OoO0O00
  if 45 - 45: I1Ii111 - OoO0O00 / Ii1I % OoooooooOO
 def hash_address ( self , addr ) :
  Ii1iiI1i1 = self . address
  iIi = addr . address
  if 98 - 98: iIii1I11I1II1 * i11iIiiIii / Ii1I / I1ii11iIi11i % o0oOOo0O0Ooo % IiII
  if ( self . is_geo_prefix ( ) ) : Ii1iiI1i1 = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : iIi = addr . address . print_geo ( )
  if 99 - 99: I1Ii111 % iII111i - Ii1I + Oo0Ooo % O0 % o0oOOo0O0Ooo
  if ( type ( Ii1iiI1i1 ) == str ) :
   Ii1iiI1i1 = int ( binascii . hexlify ( Ii1iiI1i1 [ 0 : 1 ] ) )
   if 22 - 22: I1ii11iIi11i . O0 - oO0o % OoO0O00 % OoooooooOO
  if ( type ( iIi ) == str ) :
   iIi = int ( binascii . hexlify ( iIi [ 0 : 1 ] ) )
   if 67 - 67: I11i
  return ( Ii1iiI1i1 ^ iIi )
  if 23 - 23: I1ii11iIi11i - OoOoOO00
  if 90 - 90: ooOoO0o - I11i / OoOoOO00
  if 12 - 12: II111iiii % I1IiiI - I1ii11iIi11i
  if 24 - 24: Ii1I + I11i
  if 5 - 5: I1Ii111 . Ii1I - ooOoO0o % OoooooooOO
  if 2 - 2: OOooOOo . IiII . iII111i / Oo0Ooo
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 86 - 86: OOooOOo . o0oOOo0O0Ooo - iIii1I11I1II1
  i111IiI1III1 = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   iI1i1I = 2 ** ( 32 - i111IiI1III1 )
   I11iiiIIi = prefix . instance_id
   oooOoooOoo00o = I11iiiIIi + iI1i1I
   return ( self . instance_id in range ( I11iiiIIi , oooOoooOoo00o ) )
   if 4 - 4: IiII + OoOoOO00 - I1Ii111 / I11i + II111iiii * iII111i
   if 35 - 35: ooOoO0o . ooOoO0o
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 86 - 86: I1ii11iIi11i + ooOoO0o + oO0o / OoO0O00 + OOooOOo / Oo0Ooo
   if 24 - 24: Oo0Ooo / OoO0O00 . II111iiii
   if 21 - 21: iII111i % i11iIiiIii
   if 99 - 99: Oo0Ooo
   if 40 - 40: OOooOOo % iII111i - oO0o
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   IiiIIi1 = self . address
   o0oo0o0o0 = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    IiiIIi1 = self . address . print_geo ( )
    o0oo0o0o0 = prefix . address . print_geo ( )
    if 28 - 28: I1IiiI % i11iIiiIii + II111iiii . ooOoO0o
   if ( len ( IiiIIi1 ) < len ( o0oo0o0o0 ) ) : return ( False )
   return ( IiiIIi1 . find ( o0oo0o0o0 ) == 0 )
   if 74 - 74: o0oOOo0O0Ooo
   if 4 - 4: I1ii11iIi11i * II111iiii - Oo0Ooo % i1IIi % O0 * i11iIiiIii
   if 62 - 62: OoO0O00 * I1Ii111 * Ii1I / ooOoO0o
   if 27 - 27: oO0o . iII111i . oO0o
   if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
  if ( self . mask_len < i111IiI1III1 ) : return ( False )
  if 14 - 14: I11i + ooOoO0o . oO0o * I11i
  oo0O = ( prefix . addr_length ( ) * 8 ) - i111IiI1III1
  IiIIi1i = ( 2 ** i111IiI1III1 - 1 ) << oo0O
  return ( ( self . address & IiIIi1i ) == prefix . address )
  if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
  if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
 def mask_address ( self , mask_len ) :
  oo0O = ( self . addr_length ( ) * 8 ) - mask_len
  IiIIi1i = ( 2 ** mask_len - 1 ) << oo0O
  self . address &= IiIIi1i
  if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
  if 33 - 33: I11i
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  iIi111 = self . print_prefix ( )
  OO0000Oo0O = prefix . print_prefix ( ) if prefix else ""
  return ( iIi111 == OO0000Oo0O )
  if 10 - 10: o0oOOo0O0Ooo - OoooooooOO - iIii1I11I1II1 - o0oOOo0O0Ooo / iII111i
  if 10 - 10: OoOoOO00 . i1IIi
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   I11II1i1i = lisp_myrlocs [ 0 ]
   if ( I11II1i1i == None ) : return ( False )
   I11II1i1i = I11II1i1i . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == I11II1i1i )
   if 14 - 14: OoooooooOO
  if ( self . is_ipv6 ( ) ) :
   I11II1i1i = lisp_myrlocs [ 1 ]
   if ( I11II1i1i == None ) : return ( False )
   I11II1i1i = I11II1i1i . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == I11II1i1i )
   if 44 - 44: I11i * I11i + OoooooooOO
  return ( False )
  if 26 - 26: I1Ii111 * Ii1I
  if 95 - 95: oO0o + OoOoOO00 / OoO0O00 % I1IiiI
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid == 0 and mask_len == 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 28 - 28: I1IiiI
  self . instance_id = iid
  self . mask_len = mask_len
  if 59 - 59: OOooOOo . I1IiiI / i1IIi / II111iiii . II111iiii
  if 54 - 54: iIii1I11I1II1 % ooOoO0o
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
  if 12 - 12: iIii1I11I1II1 % OoO0O00 * Oo0Ooo
  if 5 - 5: I11i - II111iiii * iIii1I11I1II1 / iIii1I11I1II1 % IiII * i1IIi
 def lcaf_encode_iid ( self ) :
  O000oo0O0OO0 = LISP_LCAF_INSTANCE_ID_TYPE
  O0III1Iiii1i11 = socket . htons ( self . lcaf_length ( O000oo0O0OO0 ) )
  o0OoO0000o = self . instance_id
  O000oOOoOOO = self . afi
  i111ii1I111Ii = 0
  if ( O000oOOoOOO < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    O000oOOoOOO = LISP_AFI_LCAF
    i111ii1I111Ii = 0
   else :
    O000oOOoOOO = 0
    i111ii1I111Ii = self . mask_len
    if 30 - 30: i1IIi % I1IiiI . OOooOOo % iIii1I11I1II1 . I1ii11iIi11i / o0oOOo0O0Ooo
    if 53 - 53: OOooOOo % ooOoO0o
    if 94 - 94: OOooOOo - O0 - I1Ii111 / OoooooooOO - iII111i
  O00O00oOO0Oo = struct . pack ( "BBBBH" , 0 , 0 , O000oo0O0OO0 , i111ii1I111Ii , O0III1Iiii1i11 )
  O00O00oOO0Oo += struct . pack ( "IH" , socket . htonl ( o0OoO0000o ) , socket . htons ( O000oOOoOOO ) )
  if ( O000oOOoOOO == 0 ) : return ( O00O00oOO0Oo )
  if 99 - 99: oO0o . i11iIiiIii % i1IIi + iII111i
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   O00O00oOO0Oo = O00O00oOO0Oo [ 0 : - 2 ]
   O00O00oOO0Oo += self . address . encode_geo ( )
   return ( O00O00oOO0Oo )
   if 91 - 91: I1Ii111 . II111iiii / Ii1I * O0
   if 33 - 33: oO0o * i1IIi + ooOoO0o * OOooOOo - O0 - iIii1I11I1II1
  O00O00oOO0Oo += self . pack_address ( )
  return ( O00O00oOO0Oo )
  if 35 - 35: I1Ii111
  if 12 - 12: Ii1I % I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
 def lcaf_decode_iid ( self , packet ) :
  O00oO00oOO00O = "BBBBH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 12 - 12: Oo0Ooo + I1IiiI
  I11Iii1iIII1i , II1ioOO0Oo , O000oo0O0OO0 , iIi1 , iiiIIiiIi = struct . unpack ( O00oO00oOO00O ,
 packet [ : ooOoooOoo0oO ] )
  packet = packet [ ooOoooOoo0oO : : ]
  if 75 - 75: O0 - iIii1I11I1II1 . i1IIi * II111iiii . II111iiii
  if ( O000oo0O0OO0 != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 16 - 16: I1Ii111 / I1IiiI % OOooOOo
  O00oO00oOO00O = "IH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
  if 61 - 61: I1ii11iIi11i . OOooOOo - O0 * OoOoOO00
  o0OoO0000o , O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  packet = packet [ ooOoooOoo0oO : : ]
  if 12 - 12: I1ii11iIi11i / I1Ii111
  iiiIIiiIi = socket . ntohs ( iiiIIiiIi )
  self . instance_id = socket . ntohl ( o0OoO0000o )
  O000oOOoOOO = socket . ntohs ( O000oOOoOOO )
  self . afi = O000oOOoOOO
  if ( iIi1 != 0 and O000oOOoOOO == 0 ) : self . mask_len = iIi1
  if ( O000oOOoOOO == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if iIi1 else LISP_AFI_ULTIMATE_ROOT
   if 5 - 5: Oo0Ooo / o0oOOo0O0Ooo % i11iIiiIii - ooOoO0o
   if 62 - 62: i11iIiiIii
   if 88 - 88: i11iIiiIii
   if 59 - 59: oO0o - OoooooooOO % ooOoO0o
   if 90 - 90: OoOoOO00
  if ( O000oOOoOOO == 0 ) : return ( packet )
  if 96 - 96: II111iiii % Ii1I
  if 84 - 84: I1IiiI . I1IiiI
  if 82 - 82: OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1 + I1ii11iIi11i
  if 45 - 45: iII111i . oO0o * iII111i
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 3 - 3: OoOoOO00 / Oo0Ooo - Oo0Ooo
   if 54 - 54: Oo0Ooo . OoO0O00 * I1IiiI % IiII
   if 97 - 97: o0oOOo0O0Ooo + Ii1I
   if 77 - 77: I11i - oO0o . Ii1I
   if 75 - 75: I11i * OoooooooOO % OoOoOO00 . i1IIi - Ii1I + iIii1I11I1II1
  if ( O000oOOoOOO == LISP_AFI_LCAF ) :
   O00oO00oOO00O = "BBBBH"
   ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
   if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
   if 74 - 74: ooOoO0o
   oO00OO0Ooo00O , II1iII1IIIIi , O000oo0O0OO0 , oOOooo00 , iI11iiI1 = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
   if 18 - 18: iIii1I11I1II1 - I11i - oO0o
   if 12 - 12: O0 + O0 + ooOoO0o . I1IiiI * II111iiii
   if ( O000oo0O0OO0 != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 47 - 47: i11iIiiIii % OOooOOo / ooOoO0o . IiII - I1IiiI
   iI11iiI1 = socket . ntohs ( iI11iiI1 )
   packet = packet [ ooOoooOoo0oO : : ]
   if ( iI11iiI1 > len ( packet ) ) : return ( None )
   if 10 - 10: Oo0Ooo / ooOoO0o / I1ii11iIi11i
   iii1iOoOooOOo = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = iii1iOoOooOOo
   packet = iii1iOoOooOOo . decode_geo ( packet , iI11iiI1 , oOOooo00 )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 98 - 98: O0 - I1Ii111 - i11iIiiIii
   if 85 - 85: II111iiii - I1ii11iIi11i % I1IiiI . I1IiiI - OoooooooOO - I11i
  O0III1Iiii1i11 = self . addr_length ( )
  if ( len ( packet ) < O0III1Iiii1i11 ) : return ( None )
  if 38 - 38: i1IIi + oO0o * ooOoO0o % Ii1I % ooOoO0o
  packet = self . unpack_address ( packet )
  return ( packet )
  if 80 - 80: OoO0O00 + OoOoOO00 % iII111i % OoooooooOO - ooOoO0o
  if 25 - 25: OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - Oo0Ooo . O0
  if 48 - 48: I1IiiI + oO0o % i11iIiiIii % iIii1I11I1II1
  if 14 - 14: iIii1I11I1II1
  if 78 - 78: I1Ii111 / Oo0Ooo - I1Ii111
  if 1 - 1: OoO0O00 - I1IiiI * o0oOOo0O0Ooo
  if 84 - 84: OoO0O00 % OoooooooOO
  if 66 - 66: OoOoOO00 . iII111i
  if 1 - 1: iII111i * i1IIi . iIii1I11I1II1 % O0 - OoooooooOO
  if 87 - 87: iII111i . Oo0Ooo * i11iIiiIii % o0oOOo0O0Ooo + Ii1I
  if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
  if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
  if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
  if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
  if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
  if 90 - 90: II111iiii + OOooOOo % I1Ii111 * iIii1I11I1II1 % iIii1I11I1II1
  if 55 - 55: II111iiii % O0 * O0 - II111iiii * I1IiiI % Oo0Ooo
  if 48 - 48: I1ii11iIi11i + OoooooooOO % i1IIi
  if 46 - 46: OoOoOO00
  if 75 - 75: I1IiiI
  if 37 - 37: iIii1I11I1II1 % OoO0O00 * ooOoO0o + I11i % ooOoO0o / i11iIiiIii
 def lcaf_encode_sg ( self , group ) :
  O000oo0O0OO0 = LISP_LCAF_MCAST_INFO_TYPE
  o0OoO0000o = socket . htonl ( self . instance_id )
  O0III1Iiii1i11 = socket . htons ( self . lcaf_length ( O000oo0O0OO0 ) )
  O00O00oOO0Oo = struct . pack ( "BBBBHIHBB" , 0 , 0 , O000oo0O0OO0 , 0 , O0III1Iiii1i11 , o0OoO0000o ,
 0 , self . mask_len , group . mask_len )
  if 14 - 14: i1IIi / ooOoO0o
  O00O00oOO0Oo += struct . pack ( "H" , socket . htons ( self . afi ) )
  O00O00oOO0Oo += self . pack_address ( )
  O00O00oOO0Oo += struct . pack ( "H" , socket . htons ( group . afi ) )
  O00O00oOO0Oo += group . pack_address ( )
  return ( O00O00oOO0Oo )
  if 10 - 10: ooOoO0o / OoooooooOO - ooOoO0o % O0 + oO0o - oO0o
  if 16 - 16: O0
 def lcaf_decode_sg ( self , packet ) :
  O00oO00oOO00O = "BBBBHIHBB"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( [ None , None ] )
  if 14 - 14: Ii1I . Ii1I . OOooOOo - O0 / OoO0O00 % II111iiii
  I11Iii1iIII1i , II1ioOO0Oo , O000oo0O0OO0 , O0Ooo000OO00 , iiiIIiiIi , o0OoO0000o , Ii1I111iiI , IIiiIiI11II , iIi1iI1I = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
  if 83 - 83: i11iIiiIii % i1IIi + o0oOOo0O0Ooo / I1Ii111 - ooOoO0o + I1ii11iIi11i
  packet = packet [ ooOoooOoo0oO : : ]
  if 73 - 73: Ii1I + i1IIi / Oo0Ooo
  if ( O000oo0O0OO0 != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 60 - 60: I1ii11iIi11i
  self . instance_id = socket . ntohl ( o0OoO0000o )
  iiiIIiiIi = socket . ntohs ( iiiIIiiIi ) - 8
  if 26 - 26: IiII . Ii1I
  if 35 - 35: I1ii11iIi11i + OOooOOo
  if 88 - 88: O0
  if 4 - 4: OoOoOO00 % iIii1I11I1II1 % OoooooooOO . oO0o
  if 27 - 27: II111iiii - OoOoOO00
  O00oO00oOO00O = "H"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( [ None , None ] )
  if ( iiiIIiiIi < ooOoooOoo0oO ) : return ( [ None , None ] )
  if 81 - 81: o0oOOo0O0Ooo - Oo0Ooo % IiII - ooOoO0o / O0
  O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  iiiIIiiIi -= ooOoooOoo0oO
  self . afi = socket . ntohs ( O000oOOoOOO )
  self . mask_len = IIiiIiI11II
  O0III1Iiii1i11 = self . addr_length ( )
  if ( iiiIIiiIi < O0III1Iiii1i11 ) : return ( [ None , None ] )
  if 27 - 27: Oo0Ooo
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 15 - 15: iIii1I11I1II1 . OoOoOO00 % Ii1I / i1IIi . o0oOOo0O0Ooo
  iiiIIiiIi -= O0III1Iiii1i11
  if 45 - 45: iIii1I11I1II1 - i1IIi % I1IiiI - I1Ii111 + oO0o
  if 15 - 15: iIii1I11I1II1 - OoooooooOO / ooOoO0o
  if 83 - 83: IiII + I1Ii111 / OoOoOO00 * IiII . oO0o
  if 22 - 22: O0 + ooOoO0o + I1Ii111
  if 57 - 57: OOooOOo . ooOoO0o - OoooooooOO - I1ii11iIi11i * O0
  O00oO00oOO00O = "H"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( [ None , None ] )
  if ( iiiIIiiIi < ooOoooOoo0oO ) : return ( [ None , None ] )
  if 85 - 85: I1IiiI * OoO0O00
  O000oOOoOOO = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  iiiIIiiIi -= ooOoooOoo0oO
  oOooO00OOoO = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  oOooO00OOoO . afi = socket . ntohs ( O000oOOoOOO )
  oOooO00OOoO . mask_len = iIi1iI1I
  oOooO00OOoO . instance_id = self . instance_id
  O0III1Iiii1i11 = self . addr_length ( )
  if ( iiiIIiiIi < O0III1Iiii1i11 ) : return ( [ None , None ] )
  if 63 - 63: I1IiiI - i11iIiiIii
  packet = oOooO00OOoO . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 4 - 4: OOooOOo + iIii1I11I1II1 / I1IiiI * Ii1I
  return ( [ packet , oOooO00OOoO ] )
  if 64 - 64: OoOoOO00
  if 94 - 94: OOooOOo * OoooooooOO * o0oOOo0O0Ooo / I1Ii111 . II111iiii
 def lcaf_decode_eid ( self , packet ) :
  O00oO00oOO00O = "BBB"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( [ None , None ] )
  if 37 - 37: O0 * II111iiii * I1IiiI - O0 - I11i / i1IIi
  if 27 - 27: i11iIiiIii + iIii1I11I1II1
  if 15 - 15: oO0o
  if 69 - 69: II111iiii * O0 . ooOoO0o * IiII
  if 25 - 25: I11i - I1ii11iIi11i . I1Ii111 . OoooooooOO
  O0Ooo000OO00 , II1iII1IIIIi , O000oo0O0OO0 = struct . unpack ( O00oO00oOO00O ,
 packet [ : ooOoooOoo0oO ] )
  if 4 - 4: IiII * OoO0O00 % I1ii11iIi11i * Ii1I . iII111i
  if ( O000oo0O0OO0 == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( O000oo0O0OO0 == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , oOooO00OOoO = self . lcaf_decode_sg ( packet )
   return ( [ packet , oOooO00OOoO ] )
  elif ( O000oo0O0OO0 == LISP_LCAF_GEO_COORD_TYPE ) :
   O00oO00oOO00O = "BBBBH"
   ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
   if ( len ( packet ) < ooOoooOoo0oO ) : return ( None )
   if 41 - 41: OoooooooOO % I11i . O0 + I1Ii111
   oO00OO0Ooo00O , II1iII1IIIIi , O000oo0O0OO0 , oOOooo00 , iI11iiI1 = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] )
   if 67 - 67: OoOoOO00 * OOooOOo / OOooOOo / OoooooooOO
   if 67 - 67: I11i - i1IIi . OoooooooOO / iIii1I11I1II1
   if ( O000oo0O0OO0 != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 34 - 34: OoO0O00 * II111iiii
   iI11iiI1 = socket . ntohs ( iI11iiI1 )
   packet = packet [ ooOoooOoo0oO : : ]
   if ( iI11iiI1 > len ( packet ) ) : return ( None )
   if 43 - 43: OoOoOO00 . I1IiiI
   iii1iOoOooOOo = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = iii1iOoOooOOo
   packet = iii1iOoOooOOo . decode_geo ( packet , iI11iiI1 , oOOooo00 )
   self . mask_len = self . host_mask_len ( )
   if 44 - 44: O0 / o0oOOo0O0Ooo
  return ( [ packet , None ] )
  if 19 - 19: I11i
  if 91 - 91: OOooOOo * OoooooooOO
  if 89 - 89: i1IIi / iII111i . I1Ii111
  if 74 - 74: I1ii11iIi11i % iII111i / OoooooooOO / I1ii11iIi11i % i11iIiiIii % ooOoO0o
  if 82 - 82: OoooooooOO . o0oOOo0O0Ooo * I1ii11iIi11i % I1ii11iIi11i * Ii1I
  if 83 - 83: I11i - Oo0Ooo + i11iIiiIii - i11iIiiIii
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 64 - 64: IiII % I1IiiI / ooOoO0o
  if 74 - 74: OoooooooOO
 def copy_elp_node ( self ) :
  i11iiIi11iiIIi1I = lisp_elp_node ( )
  i11iiIi11iiIIi1I . copy_address ( self . address )
  i11iiIi11iiIIi1I . probe = self . probe
  i11iiIi11iiIIi1I . strict = self . strict
  i11iiIi11iiIIi1I . eid = self . eid
  i11iiIi11iiIIi1I . we_are_last = self . we_are_last
  return ( i11iiIi11iiIIi1I )
  if 22 - 22: II111iiii . O0 * I1Ii111 % OoO0O00 / OoooooooOO + I1Ii111
  if 71 - 71: ooOoO0o . oO0o * OoooooooOO + iII111i - I1Ii111 . I1ii11iIi11i
  if 100 - 100: I11i + O0 - o0oOOo0O0Ooo * I1ii11iIi11i
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 94 - 94: Oo0Ooo . IiII / Ii1I / oO0o - I1IiiI
  if 77 - 77: i11iIiiIii . Ii1I - Ii1I
 def copy_elp ( self ) :
  I1IIiIi = lisp_elp ( self . elp_name )
  I1IIiIi . use_elp_node = self . use_elp_node
  I1IIiIi . we_are_last = self . we_are_last
  for i11iiIi11iiIIi1I in self . elp_nodes :
   I1IIiIi . elp_nodes . append ( i11iiIi11iiIIi1I . copy_elp_node ( ) )
   if 47 - 47: iII111i % OOooOOo . I1ii11iIi11i + I1ii11iIi11i . I1Ii111
  return ( I1IIiIi )
  if 20 - 20: oO0o - o0oOOo0O0Ooo + I1IiiI % OoOoOO00
  if 41 - 41: oO0o . ooOoO0o
 def print_elp ( self , want_marker ) :
  Ii1oo = ""
  for i11iiIi11iiIIi1I in self . elp_nodes :
   oooo0O00o = ""
   if ( want_marker ) :
    if ( i11iiIi11iiIIi1I == self . use_elp_node ) :
     oooo0O00o = "*"
    elif ( i11iiIi11iiIIi1I . we_are_last ) :
     oooo0O00o = "x"
     if 47 - 47: iII111i + iIii1I11I1II1 + Ii1I + OoO0O00 / ooOoO0o + I1ii11iIi11i
     if 83 - 83: Oo0Ooo + i1IIi
   Ii1oo += "{}{}({}{}{}), " . format ( oooo0O00o ,
 i11iiIi11iiIIi1I . address . print_address_no_iid ( ) ,
 "r" if i11iiIi11iiIIi1I . eid else "R" , "P" if i11iiIi11iiIIi1I . probe else "p" ,
 "S" if i11iiIi11iiIIi1I . strict else "s" )
   if 7 - 7: ooOoO0o . Oo0Ooo % ooOoO0o % O0 . OoO0O00 + OoOoOO00
  return ( Ii1oo [ 0 : - 2 ] if Ii1oo != "" else "" )
  if 50 - 50: OoO0O00
  if 25 - 25: I1IiiI / IiII . OOooOOo . I1ii11iIi11i % i1IIi
 def select_elp_node ( self ) :
  iiii1iiIii , OOoO00oOoo , OoO0o0OOOO = lisp_myrlocs
  ooo = None
  if 26 - 26: II111iiii - I11i % i11iIiiIii - I1ii11iIi11i + OoOoOO00
  for i11iiIi11iiIIi1I in self . elp_nodes :
   if ( iiii1iiIii and i11iiIi11iiIIi1I . address . is_exact_match ( iiii1iiIii ) ) :
    ooo = self . elp_nodes . index ( i11iiIi11iiIIi1I )
    break
    if 65 - 65: OoooooooOO / OoooooooOO % II111iiii
   if ( OOoO00oOoo and i11iiIi11iiIIi1I . address . is_exact_match ( OOoO00oOoo ) ) :
    ooo = self . elp_nodes . index ( i11iiIi11iiIIi1I )
    break
    if 68 - 68: OoooooooOO . iIii1I11I1II1 - Ii1I / OoO0O00 / oO0o
    if 14 - 14: OOooOOo + iIii1I11I1II1 - Ii1I % I11i % OoO0O00 - i11iIiiIii
    if 88 - 88: iII111i / I11i / I1ii11iIi11i + IiII * OoooooooOO . IiII
    if 3 - 3: ooOoO0o - Oo0Ooo
    if 86 - 86: I1ii11iIi11i * I1Ii111 / o0oOOo0O0Ooo . OoO0O00
    if 14 - 14: I11i * IiII / iIii1I11I1II1
    if 88 - 88: OoOoOO00 % II111iiii . I1IiiI / oO0o * IiII / i11iIiiIii
  if ( ooo == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   i11iiIi11iiIIi1I . we_are_last = False
   return
   if 76 - 76: o0oOOo0O0Ooo
   if 80 - 80: OOooOOo
   if 15 - 15: OOooOOo . OoOoOO00 / oO0o . I1ii11iIi11i % OoO0O00 - oO0o
   if 21 - 21: ooOoO0o . o0oOOo0O0Ooo . oO0o . i1IIi
   if 96 - 96: Ii1I % I11i * OoooooooOO . I1IiiI . iIii1I11I1II1
   if 8 - 8: O0 + o0oOOo0O0Ooo / O0 - I1ii11iIi11i % I1ii11iIi11i
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ ooo ] ) :
   self . use_elp_node = None
   i11iiIi11iiIIi1I . we_are_last = True
   return
   if 55 - 55: OoooooooOO * OoooooooOO % I1Ii111 / Ii1I / ooOoO0o
   if 12 - 12: i11iIiiIii + Ii1I % iIii1I11I1II1 + I1Ii111
   if 12 - 12: Ii1I + I1Ii111 / O0 * II111iiii
   if 67 - 67: iIii1I11I1II1 / I11i + ooOoO0o * I1Ii111 * oO0o
   if 100 - 100: OoooooooOO % I1IiiI / OoOoOO00 % OoOoOO00 . o0oOOo0O0Ooo
  self . use_elp_node = self . elp_nodes [ ooo + 1 ]
  return
  if 81 - 81: Ii1I - II111iiii + I11i / Ii1I
  if 89 - 89: i11iIiiIii + I1ii11iIi11i - ooOoO0o . ooOoO0o + Oo0Ooo % Ii1I
  if 96 - 96: I1Ii111 - I11i * I1Ii111
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
  if 32 - 32: I1IiiI / i1IIi / I1ii11iIi11i % i1IIi . ooOoO0o % I1ii11iIi11i
  if 97 - 97: OoO0O00 . OOooOOo % Ii1I + OoooooooOO * I1Ii111
 def copy_geo ( self ) :
  iii1iOoOooOOo = lisp_geo ( self . geo_name )
  iii1iOoOooOOo . latitude = self . latitude
  iii1iOoOooOOo . lat_mins = self . lat_mins
  iii1iOoOooOOo . lat_secs = self . lat_secs
  iii1iOoOooOOo . longitude = self . longitude
  iii1iOoOooOOo . long_mins = self . long_mins
  iii1iOoOooOOo . long_secs = self . long_secs
  iii1iOoOooOOo . altitude = self . altitude
  iii1iOoOooOOo . radius = self . radius
  return ( iii1iOoOooOOo )
  if 89 - 89: I11i
  if 91 - 91: OoooooooOO - IiII - Ii1I
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 36 - 36: OOooOOo
  if 76 - 76: OoO0O00 . i1IIi
 def parse_geo_string ( self , geo_str ) :
  ooo = geo_str . find ( "]" )
  if ( ooo != - 1 ) : geo_str = geo_str [ ooo + 1 : : ]
  if 98 - 98: O0
  if 86 - 86: O0 * oO0o + Oo0Ooo / II111iiii + i1IIi
  if 12 - 12: I1IiiI + OOooOOo / Ii1I % i11iIiiIii - I1Ii111 % I11i
  if 49 - 49: I11i * i1IIi - iII111i
  if 98 - 98: iIii1I11I1II1 - I11i % i11iIiiIii * I1IiiI / OoOoOO00 * ooOoO0o
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , Oo0Oo0o00oO = geo_str . split ( "/" )
   self . radius = int ( Oo0Oo0o00oO )
   if 21 - 21: I11i / I1Ii111 . Ii1I - Ii1I . I1ii11iIi11i
   if 52 - 52: o0oOOo0O0Ooo * o0oOOo0O0Ooo % I1ii11iIi11i % OoOoOO00 * OoooooooOO . I1ii11iIi11i
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 88 - 88: I1ii11iIi11i . i1IIi * iII111i
  O0oooo = geo_str [ 0 : 4 ]
  iiiiiI = geo_str [ 4 : 8 ]
  if 7 - 7: Oo0Ooo / oO0o . I1Ii111 % I11i
  if 85 - 85: II111iiii / o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO / Ii1I
  if 18 - 18: i11iIiiIii + o0oOOo0O0Ooo . i11iIiiIii
  if 50 - 50: IiII / OoooooooOO . I11i
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 93 - 93: OOooOOo / OoooooooOO % iII111i % Ii1I / I1Ii111 % OOooOOo
  if 25 - 25: i1IIi % Oo0Ooo . i1IIi * OoOoOO00 . Ii1I % OoO0O00
  if 47 - 47: o0oOOo0O0Ooo - i11iIiiIii / OoooooooOO
  if 93 - 93: I1IiiI * II111iiii * O0 % o0oOOo0O0Ooo + oO0o / ooOoO0o
  self . latitude = int ( O0oooo [ 0 ] )
  self . lat_mins = int ( O0oooo [ 1 ] )
  self . lat_secs = int ( O0oooo [ 2 ] )
  if ( O0oooo [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 79 - 79: OoO0O00 + ooOoO0o / oO0o % I1ii11iIi11i
  if 77 - 77: Ii1I / Ii1I / I1ii11iIi11i
  if 92 - 92: O0 * i11iIiiIii . OoOoOO00 * IiII / o0oOOo0O0Ooo * ooOoO0o
  if 74 - 74: O0 - o0oOOo0O0Ooo
  self . longitude = int ( iiiiiI [ 0 ] )
  self . long_mins = int ( iiiiiI [ 1 ] )
  self . long_secs = int ( iiiiiI [ 2 ] )
  if ( iiiiiI [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 68 - 68: I1Ii111
  if 19 - 19: o0oOOo0O0Ooo
 def print_geo ( self ) :
  oo0ooOOO00 = "N" if self . latitude < 0 else "S"
  O000o00 = "E" if self . longitude < 0 else "W"
  if 73 - 73: OoOoOO00 % I1Ii111 . I1ii11iIi11i
  oO0o0O0oOoo = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , oo0ooOOO00 , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , O000o00 )
  if 45 - 45: iIii1I11I1II1 % Ii1I . OoOoOO00 . o0oOOo0O0Ooo - OoooooooOO
  if ( self . no_geo_altitude ( ) == False ) :
   oO0o0O0oOoo += "-" + str ( self . altitude )
   if 46 - 46: I1ii11iIi11i
   if 32 - 32: iII111i * i11iIiiIii / IiII + i11iIiiIii + O0
   if 51 - 51: I1Ii111
   if 95 - 95: Ii1I / Ii1I * OoO0O00 . OoooooooOO . OoooooooOO * I11i
   if 76 - 76: OoooooooOO - Ii1I + IiII % OoOoOO00 / OoooooooOO
  if ( self . radius != 0 ) : oO0o0O0oOoo += "/{}" . format ( self . radius )
  return ( oO0o0O0oOoo )
  if 55 - 55: i11iIiiIii - IiII * OOooOOo + II111iiii . I1ii11iIi11i / O0
  if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
 def geo_url ( self ) :
  ooOo0OoO0 = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  ooOo0OoO0 = "10" if ( ooOo0OoO0 == "" or ooOo0OoO0 . isdigit ( ) == False ) else ooOo0OoO0
  OoO00OO0 , iIi1i = self . dms_to_decimal ( )
  oOoOI1I1Iii1 = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( OoO00OO0 , iIi1i , OoO00OO0 , iIi1i ,
  # iII111i
  # OoOoOO00 / oO0o % OoOoOO00
 ooOo0OoO0 )
  return ( oOoOI1I1Iii1 )
  if 14 - 14: Ii1I + I1IiiI - OoooooooOO . IiII - OOooOOo % IiII
  if 19 - 19: IiII + I1ii11iIi11i % Oo0Ooo
 def print_geo_url ( self ) :
  iii1iOoOooOOo = self . print_geo ( )
  if ( self . radius == 0 ) :
   oOoOI1I1Iii1 = self . geo_url ( )
   iI = "<a href='{}'>{}</a>" . format ( oOoOI1I1Iii1 , iii1iOoOooOOo )
  else :
   oOoOI1I1Iii1 = iii1iOoOooOOo . replace ( "/" , "-" )
   iI = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( oOoOI1I1Iii1 , iii1iOoOooOOo )
   if 32 - 32: OOooOOo
  return ( iI )
  if 46 - 46: II111iiii . OoO0O00
  if 97 - 97: oO0o
 def dms_to_decimal ( self ) :
  iiI1 , Ii1IiI , OoooOOooO0oo0O0 = self . latitude , self . lat_mins , self . lat_secs
  o0o0ooo = float ( abs ( iiI1 ) )
  o0o0ooo += float ( Ii1IiI * 60 + OoooOOooO0oo0O0 ) / 3600
  if ( iiI1 > 0 ) : o0o0ooo = - o0o0ooo
  i1iI11 = o0o0ooo
  if 9 - 9: I1Ii111 / OoO0O00 - OoO0O00
  iiI1 , Ii1IiI , OoooOOooO0oo0O0 = self . longitude , self . long_mins , self . long_secs
  o0o0ooo = float ( abs ( iiI1 ) )
  o0o0ooo += float ( Ii1IiI * 60 + OoooOOooO0oo0O0 ) / 3600
  if ( iiI1 > 0 ) : o0o0ooo = - o0o0ooo
  IIi1ooOoOO00o0 = o0o0ooo
  return ( ( i1iI11 , IIi1ooOoOO00o0 ) )
  if 27 - 27: O0 * OoO0O00 * I1ii11iIi11i
  if 40 - 40: O0 + oO0o - ooOoO0o + I1IiiI - IiII
 def get_distance ( self , geo_point ) :
  O00OOOOooO0OO = self . dms_to_decimal ( )
  OoOOooO0o = geo_point . dms_to_decimal ( )
  I1IIiIII111 = vincenty ( O00OOOOooO0OO , OoOOooO0o )
  return ( I1IIiIII111 . km )
  if 86 - 86: ooOoO0o / iII111i . OoooooooOO + I1Ii111 + I1Ii111
  if 35 - 35: Oo0Ooo + oO0o * o0oOOo0O0Ooo - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii
 def point_in_circle ( self , geo_point ) :
  oo00O0 = self . get_distance ( geo_point )
  return ( oo00O0 <= self . radius )
  if 41 - 41: IiII % i1IIi
  if 34 - 34: o0oOOo0O0Ooo - iII111i / O0 / OOooOOo - Oo0Ooo
 def encode_geo ( self ) :
  O00000oooOO = socket . htons ( LISP_AFI_LCAF )
  ii1III = socket . htons ( 20 + 2 )
  II1iII1IIIIi = 0
  if 29 - 29: OoooooooOO - iII111i
  OoO00OO0 = abs ( self . latitude )
  o0iII1 = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : II1iII1IIIIi |= 0x40
  if 9 - 9: iII111i . i11iIiiIii * IiII . I11i
  iIi1i = abs ( self . longitude )
  Ii111iI = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : II1iII1IIIIi |= 0x20
  if 71 - 71: ooOoO0o + OOooOOo * I1IiiI % I11i . I1Ii111 % OoooooooOO
  i1io00oO0O = 0
  if ( self . no_geo_altitude ( ) == False ) :
   i1io00oO0O = socket . htonl ( self . altitude )
   II1iII1IIIIi |= 0x10
   if 40 - 40: OoooooooOO . Ii1I . OoooooooOO
  Oo0Oo0o00oO = socket . htons ( self . radius )
  if ( Oo0Oo0o00oO != 0 ) : II1iII1IIIIi |= 0x06
  if 54 - 54: OOooOOo
  ooO0oOOoOO = struct . pack ( "HBBBBH" , O00000oooOO , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , ii1III )
  ooO0oOOoOO += struct . pack ( "BBHBBHBBHIHHH" , II1iII1IIIIi , 0 , 0 , OoO00OO0 , o0iII1 >> 16 ,
 socket . htons ( o0iII1 & 0x0ffff ) , iIi1i , Ii111iI >> 16 ,
 socket . htons ( Ii111iI & 0xffff ) , i1io00oO0O , Oo0Oo0o00oO , 0 , 0 )
  if 58 - 58: OoOoOO00 / I1Ii111 % O0
  return ( ooO0oOOoOO )
  if 14 - 14: I1IiiI . OOooOOo
  if 28 - 28: iII111i / oO0o / iII111i
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  O00oO00oOO00O = "BBHBBHBBHIHHH"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( lcaf_len < ooOoooOoo0oO ) : return ( None )
  if 97 - 97: II111iiii + Oo0Ooo
  II1iII1IIIIi , OOOo0OO0oO , iI1O0OOOo , OoO00OO0 , IIi1IIii1I , o0iII1 , iIi1i , iIi1i1Iii1I , Ii111iI , i1io00oO0O , Oo0Oo0o00oO , iiiIiIIIi1I , O000oOOoOOO = struct . unpack ( O00oO00oOO00O ,
  # II111iiii
 packet [ : ooOoooOoo0oO ] )
  if 14 - 14: I1Ii111
  if 81 - 81: II111iiii
  if 55 - 55: O0 + o0oOOo0O0Ooo * I1IiiI - OoooooooOO
  if 68 - 68: I11i + Oo0Ooo
  O000oOOoOOO = socket . ntohs ( O000oOOoOOO )
  if ( O000oOOoOOO == LISP_AFI_LCAF ) : return ( None )
  if 15 - 15: O0
  if ( II1iII1IIIIi & 0x40 ) : OoO00OO0 = - OoO00OO0
  self . latitude = OoO00OO0
  o0Oo0iI11IIi11i = ( ( IIi1IIii1I << 16 ) | socket . ntohs ( o0iII1 ) ) / 1000
  self . lat_mins = o0Oo0iI11IIi11i / 60
  self . lat_secs = o0Oo0iI11IIi11i % 60
  if 52 - 52: I1IiiI % Ii1I - Ii1I
  if ( II1iII1IIIIi & 0x20 ) : iIi1i = - iIi1i
  self . longitude = iIi1i
  OO00o0OoO = ( ( iIi1i1Iii1I << 16 ) | socket . ntohs ( Ii111iI ) ) / 1000
  self . long_mins = OO00o0OoO / 60
  self . long_secs = OO00o0OoO % 60
  if 3 - 3: i11iIiiIii / I1Ii111
  self . altitude = socket . ntohl ( i1io00oO0O ) if ( II1iII1IIIIi & 0x10 ) else - 1
  Oo0Oo0o00oO = socket . ntohs ( Oo0Oo0o00oO )
  self . radius = Oo0Oo0o00oO if ( II1iII1IIIIi & 0x02 ) else Oo0Oo0o00oO * 1000
  if 40 - 40: OoooooooOO / o0oOOo0O0Ooo + OoOoOO00
  self . geo_name = None
  packet = packet [ ooOoooOoo0oO : : ]
  if 73 - 73: OOooOOo / Oo0Ooo
  if ( O000oOOoOOO != 0 ) :
   self . rloc . afi = O000oOOoOOO
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 80 - 80: OoO0O00 + I1IiiI % i1IIi / I11i % i1IIi * i11iIiiIii
  return ( packet )
  if 27 - 27: OoOoOO00 / I1Ii111 * O0 / I1IiiI - IiII / o0oOOo0O0Ooo
  if 70 - 70: I1ii11iIi11i
  if 11 - 11: I1Ii111
  if 70 - 70: Ii1I
  if 22 - 22: Ii1I
  if 59 - 59: I1ii11iIi11i
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 90 - 90: OOooOOo / iII111i
  if 70 - 70: o0oOOo0O0Ooo
 def copy_rle_node ( self ) :
  O00oo0ooo0O = lisp_rle_node ( )
  O00oo0ooo0O . address . copy_address ( self . address )
  O00oo0ooo0O . level = self . level
  O00oo0ooo0O . translated_port = self . translated_port
  O00oo0ooo0O . rloc_name = self . rloc_name
  return ( O00oo0ooo0O )
  if 49 - 49: OOooOOo - I1IiiI + OoooooooOO % iII111i + o0oOOo0O0Ooo + OoOoOO00
  if 37 - 37: II111iiii % I1ii11iIi11i * OoOoOO00
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 35 - 35: i1IIi
  if 81 - 81: OoO0O00
 def get_encap_keys ( self ) :
  IiI1iI1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 45 - 45: OoooooooOO . O0 * oO0o + IiII
  oo0o00OO = self . address . print_address_no_iid ( ) + ":" + IiI1iI1
  if 18 - 18: II111iiii . O0 - I11i / I11i
  try :
   oOoo0oO = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ]
   if ( oOoo0oO [ 1 ] ) : return ( oOoo0oO [ 1 ] . encrypt_key , oOoo0oO [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 71 - 71: OoOoOO00 + iIii1I11I1II1 - II111iiii / i1IIi
   if 39 - 39: Ii1I + I1Ii111 * Oo0Ooo + OoOoOO00 / I1Ii111 - ooOoO0o
   if 66 - 66: I11i * OoO0O00
   if 98 - 98: IiII . Oo0Ooo + I1Ii111
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 63 - 63: oO0o * I1IiiI * oO0o
  if 56 - 56: oO0o - Ii1I % I1Ii111
 def copy_rle ( self ) :
  i1I1Ii11II1i = lisp_rle ( self . rle_name )
  for O00oo0ooo0O in self . rle_nodes :
   i1I1Ii11II1i . rle_nodes . append ( O00oo0ooo0O . copy_rle_node ( ) )
   if 100 - 100: OOooOOo * IiII % IiII / o0oOOo0O0Ooo * OoO0O00 % OoOoOO00
  i1I1Ii11II1i . build_forwarding_list ( )
  return ( i1I1Ii11II1i )
  if 12 - 12: I1IiiI
  if 32 - 32: I1Ii111
 def print_rle ( self , html , do_formatting ) :
  i1I1IiII = ""
  for O00oo0ooo0O in self . rle_nodes :
   IiI1iI1 = O00oo0ooo0O . translated_port
   if 35 - 35: O0 + II111iiii + o0oOOo0O0Ooo - OoO0O00 - Ii1I
   OOOi1I1111I = ""
   if ( O00oo0ooo0O . rloc_name != None ) :
    OOOi1I1111I = O00oo0ooo0O . rloc_name
    if ( do_formatting ) : OOOi1I1111I = blue ( OOOi1I1111I , html )
    if 65 - 65: oO0o + O0 / i11iIiiIii
    if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
   oo0o00OO = O00oo0ooo0O . address . print_address_no_iid ( )
   if ( O00oo0ooo0O . address . is_local ( ) ) : oo0o00OO = red ( oo0o00OO , html )
   i1I1IiII += "{}{}(L{}){}, " . format ( oo0o00OO , "" if IiI1iI1 == 0 else ":" + str ( IiI1iI1 ) , O00oo0ooo0O . level ,
   # oO0o % I11i * I11i . OOooOOo % OoooooooOO
 "" if O00oo0ooo0O . rloc_name == None else OOOi1I1111I )
   if 71 - 71: iII111i
  return ( i1I1IiII [ 0 : - 2 ] if i1I1IiII != "" else "" )
  if 48 - 48: OoOoOO00 + oO0o
  if 15 - 15: i11iIiiIii / IiII * I1ii11iIi11i - O0 % II111iiii + Ii1I
 def build_forwarding_list ( self ) :
  iIIi = - 1
  for O00oo0ooo0O in self . rle_nodes :
   if ( iIIi == - 1 ) :
    if ( O00oo0ooo0O . address . is_local ( ) ) : iIIi = O00oo0ooo0O . level
   else :
    if ( O00oo0ooo0O . level > iIIi ) : break
    if 100 - 100: Ii1I + O0 . iII111i - Ii1I + O0 . OOooOOo
    if 77 - 77: OOooOOo * OoOoOO00 - i1IIi * I1IiiI . I1Ii111
  iIIi = 0 if iIIi == - 1 else O00oo0ooo0O . level
  if 37 - 37: i1IIi - O0
  self . rle_forwarding_list = [ ]
  for O00oo0ooo0O in self . rle_nodes :
   if ( O00oo0ooo0O . level == iIIi or ( iIIi == 0 and
 O00oo0ooo0O . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and O00oo0ooo0O . address . is_local ( ) ) :
     oo0o00OO = O00oo0ooo0O . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( oo0o00OO ) )
     continue
     if 36 - 36: I1Ii111 . OoooooooOO - i1IIi % iII111i - II111iiii * i11iIiiIii
    self . rle_forwarding_list . append ( O00oo0ooo0O )
    if 90 - 90: OoOoOO00 % iII111i - Oo0Ooo
    if 13 - 13: o0oOOo0O0Ooo / O0 . I1Ii111 * I1Ii111
    if 76 - 76: Ii1I - iII111i
    if 79 - 79: o0oOOo0O0Ooo + IiII / o0oOOo0O0Ooo - I1IiiI / OoooooooOO
    if 17 - 17: OOooOOo * I1ii11iIi11i . Ii1I . iIii1I11I1II1 * OoooooooOO
class lisp_json ( ) :
 def __init__ ( self , name , string ) :
  self . json_name = name
  self . json_string = string
  if 60 - 60: II111iiii % Oo0Ooo * I11i * OoO0O00 - OoOoOO00
  if 65 - 65: iII111i
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 86 - 86: OoO0O00 / II111iiii % OoOoOO00 * OOooOOo . I1IiiI / IiII
  if 100 - 100: i1IIi / I1IiiI * I1ii11iIi11i % ooOoO0o + OoO0O00 * oO0o
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 51 - 51: I1Ii111 - OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00
   if 45 - 45: i11iIiiIii - II111iiii / i1IIi * OoOoOO00
   if 1 - 1: OOooOOo + I1IiiI + Ii1I . iII111i
 def print_json ( self , html ) :
  O0ooOo0o0oo0O = self . json_string
  oOOOO = "***"
  if ( html ) : oOOOO = red ( oOOOO , html )
  i1IiiiIIIIIi1 = oOOOO + self . json_string + oOOOO
  if ( self . valid_json ( ) ) : return ( O0ooOo0o0oo0O )
  return ( i1IiiiIIIIIi1 )
  if 41 - 41: oO0o + O0 / I1ii11iIi11i
  if 55 - 55: iIii1I11I1II1 * oO0o / iII111i / i1IIi % Oo0Ooo . OoOoOO00
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 50 - 50: IiII / o0oOOo0O0Ooo
  return ( True )
  if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
  if 52 - 52: O0
  if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
  if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
  if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
  if 83 - 83: oO0o / OoO0O00
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 34 - 34: OoooooooOO - i1IIi * O0
  if 83 - 83: I1IiiI + OoO0O00
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 41 - 41: Ii1I + II111iiii . OOooOOo * I1Ii111 / II111iiii
  if 32 - 32: Oo0Ooo - Ii1I % o0oOOo0O0Ooo
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . last_increment
  return ( oO000o0Oo00 <= 1 )
  if 15 - 15: iIii1I11I1II1 * I1ii11iIi11i / ooOoO0o * oO0o % OOooOOo
  if 62 - 62: Ii1I / Oo0Ooo . OoO0O00 - OOooOOo
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . last_increment
  return ( oO000o0Oo00 <= 60 )
  if 89 - 89: o0oOOo0O0Ooo % OoO0O00
  if 53 - 53: OoOoOO00 . ooOoO0o - OoO0O00
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 26 - 26: ooOoO0o - oO0o + OOooOOo * Ii1I - I11i % I1IiiI
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 73 - 73: ooOoO0o + Ii1I . O0 . iII111i
  return ( c1 , c2 )
  if 77 - 77: OOooOOo % I1IiiI - iII111i % I1Ii111
  if 29 - 29: iIii1I11I1II1 / i11iIiiIii + Oo0Ooo
 def normalize ( self , count ) :
  count = str ( count )
  Oo00O0oO = len ( count )
  if ( Oo00O0oO > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 56 - 56: i1IIi
  if ( Oo00O0oO > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 46 - 46: I1ii11iIi11i * ooOoO0o
  if ( Oo00O0oO > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 4 - 4: I1Ii111 * II111iiii
  return ( count )
  if 4 - 4: ooOoO0o * Oo0Ooo - I1ii11iIi11i % ooOoO0o % OoOoOO00
  if 18 - 18: OOooOOo / O0 . OoO0O00 - II111iiii * OOooOOo
 def get_stats ( self , summary , html ) :
  IIiiii1i1Ii = self . last_rate_check
  II1II = self . last_packet_count
  I111i1i = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 24 - 24: oO0o . Ii1I - Oo0Ooo . OoOoOO00
  i1iiiOO0O0O0OOOoO = self . last_rate_check - IIiiii1i1Ii
  if ( i1iiiOO0O0O0OOOoO == 0 ) :
   IiiIII11 = 0
   OoOOO0 = 0
  else :
   IiiIII11 = int ( ( self . packet_count - II1II ) / i1iiiOO0O0O0OOOoO )
   OoOOO0 = ( self . byte_count - I111i1i ) / i1iiiOO0O0O0OOOoO
   OoOOO0 = ( OoOOO0 * 8 ) / 1000000
   OoOOO0 = round ( OoOOO0 , 2 )
   if 42 - 42: oO0o + iIii1I11I1II1 / Ii1I - oO0o % oO0o . I1Ii111
   if 88 - 88: Oo0Ooo / Ii1I . OOooOOo * Oo0Ooo
   if 12 - 12: oO0o + ooOoO0o * IiII
   if 84 - 84: o0oOOo0O0Ooo * o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo + I1IiiI
   if 89 - 89: II111iiii
  iiI = self . normalize ( self . packet_count )
  iiI1I1I = self . normalize ( self . byte_count )
  if 76 - 76: Ii1I - iII111i
  if 89 - 89: II111iiii . Ii1I
  if 10 - 10: ooOoO0o - I1ii11iIi11i
  if 82 - 82: o0oOOo0O0Ooo / I11i - I11i / O0 * I1IiiI / OoO0O00
  if 71 - 71: I11i % I11i - i11iIiiIii + iIii1I11I1II1 / iII111i
  if ( summary ) :
   Ooooo000O0o0 = "<br>" if html else ""
   iiI , iiI1I1I = self . stat_colors ( iiI , iiI1I1I , html )
   i1iiii1II = "packet-count: {}{}byte-count: {}" . format ( iiI , Ooooo000O0o0 , iiI1I1I )
   OOO0ooOoOO = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( IiiIII11 , OoOOO0 )
   if 32 - 32: Ii1I * I1ii11iIi11i
   if ( html != "" ) : OOO0ooOoOO = lisp_span ( i1iiii1II , OOO0ooOoOO )
  else :
   I1iiiiII11 = str ( IiiIII11 )
   o0o0oii1iiiiI1IIi = str ( OoOOO0 )
   if ( html ) :
    iiI = lisp_print_cour ( iiI )
    I1iiiiII11 = lisp_print_cour ( I1iiiiII11 )
    iiI1I1I = lisp_print_cour ( iiI1I1I )
    o0o0oii1iiiiI1IIi = lisp_print_cour ( o0o0oii1iiiiI1IIi )
    if 96 - 96: I1Ii111 / oO0o . I1ii11iIi11i % I1IiiI * OOooOOo
   Ooooo000O0o0 = "<br>" if html else ", "
   if 99 - 99: i11iIiiIii - I1Ii111
   OOO0ooOoOO = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( iiI , Ooooo000O0o0 , I1iiiiII11 , Ooooo000O0o0 , iiI1I1I , Ooooo000O0o0 ,
   # OOooOOo
 o0o0oii1iiiiI1IIi )
   if 60 - 60: i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
  return ( OOO0ooOoOO )
  if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
  if 54 - 54: II111iiii * I1IiiI
  if 49 - 49: I1ii11iIi11i
  if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
  if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
  if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
  if 15 - 15: oO0o
  if 40 - 40: I1Ii111
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 77 - 77: II111iiii - o0oOOo0O0Ooo . Ii1I
if 47 - 47: o0oOOo0O0Ooo % OOooOOo + I1Ii111
if 64 - 64: ooOoO0o / IiII . I1IiiI
if 77 - 77: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
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
  if 90 - 90: I11i
  if ( recurse == False ) : return
  if 53 - 53: I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoooooooOO + IiII * I1IiiI
  if 16 - 16: i11iIiiIii - oO0o . i11iIiiIii + OoO0O00 + i11iIiiIii
  if 85 - 85: I1ii11iIi11i - ooOoO0o + I1Ii111 + I1Ii111
  if 13 - 13: II111iiii
  if 22 - 22: o0oOOo0O0Ooo
  if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
  iIiioOoooOo = lisp_get_default_route_next_hops ( )
  if ( iIiioOoooOo == [ ] or len ( iIiioOoooOo ) == 1 ) : return
  if 81 - 81: OoOoOO00 + I11i % Oo0Ooo % IiII * IiII * o0oOOo0O0Ooo
  self . rloc_next_hop = iIiioOoooOo [ 0 ]
  I1IIII = self
  for IiIiIi1i11II in iIiioOoooOo [ 1 : : ] :
   ii1II1 = lisp_rloc ( False )
   ii1II1 = copy . deepcopy ( self )
   ii1II1 . rloc_next_hop = IiIiIi1i11II
   I1IIII . next_rloc = ii1II1
   I1IIII = ii1II1
   if 20 - 20: i11iIiiIii / I1Ii111
   if 5 - 5: I1IiiI * o0oOOo0O0Ooo % o0oOOo0O0Ooo + I1IiiI
   if 35 - 35: oO0o + iII111i + I11i - I1ii11iIi11i - ooOoO0o - OOooOOo
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 77 - 77: OoooooooOO + OoooooooOO / oO0o * o0oOOo0O0Ooo / I11i
  if 86 - 86: I1IiiI % IiII - IiII
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 1 - 1: o0oOOo0O0Ooo + OoOoOO00 / OOooOOo % IiII
  if 16 - 16: IiII . I11i * O0 + OoooooooOO
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 37 - 37: OoO0O00 . i11iIiiIii - i11iIiiIii % I1Ii111 + II111iiii * i11iIiiIii
  if 83 - 83: OOooOOo % O0 - I11i . Ii1I % IiII
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 45 - 45: I11i % OoO0O00
  if 18 - 18: Ii1I / Ii1I * IiII
  if 33 - 33: ooOoO0o
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
  if 14 - 14: Oo0Ooo % I1Ii111 % ooOoO0o . oO0o * iIii1I11I1II1 . I1ii11iIi11i
  if 50 - 50: O0 * i11iIiiIii / iIii1I11I1II1 . I11i + i11iIiiIii
 def print_rloc ( self , indent ) :
  Oo0OO0000oooo = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , Oo0OO0000oooo , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 68 - 68: oO0o + o0oOOo0O0Ooo * iIii1I11I1II1 / i1IIi
  if 9 - 9: I11i % OoO0O00 . oO0o / I1ii11iIi11i
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  O0o0oO = self . rloc_name
  if ( cour ) : O0o0oO = lisp_print_cour ( O0o0oO )
  return ( 'rloc-name: {}' . format ( blue ( O0o0oO , cour ) ) )
  if 88 - 88: Oo0Ooo / IiII / II111iiii / I1ii11iIi11i + OoooooooOO
  if 65 - 65: iII111i % oO0o * IiII
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  IiI1iI1 = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 16 - 16: iII111i % I11i % OoOoOO00
  if 80 - 80: OoooooooOO * i11iIiiIii % oO0o / Oo0Ooo - I1ii11iIi11i
  if 92 - 92: o0oOOo0O0Ooo % i1IIi / I1Ii111 % ooOoO0o / oO0o
  if 2 - 2: i11iIiiIii / Ii1I - i1IIi % O0
  oOo0o0 = self . rloc
  if ( oOo0o0 . is_null ( ) == False ) :
   iIIIIiI = lisp_get_nat_info ( oOo0o0 , self . rloc_name )
   if ( iIIIIiI ) :
    IiI1iI1 = iIIIIiI . port
    I1iii11III = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    oo0o00OO = oOo0o0 . print_address_no_iid ( )
    o0O00oo0O = red ( oo0o00OO , False )
    IiiOo0OOoO0oo0oO = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 31 - 31: iIii1I11I1II1 + I1IiiI
    if 82 - 82: I1Ii111 / Ii1I % OoooooooOO - IiII / OoooooooOO
    if 23 - 23: iIii1I11I1II1
    if 7 - 7: IiII / OOooOOo + Oo0Ooo . I1IiiI
    if 33 - 33: I1Ii111 + OoooooooOO
    if 73 - 73: O0 . Oo0Ooo
    if ( iIIIIiI . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( o0O00oo0O , IiI1iI1 , IiiOo0OOoO0oo0oO ) )
     if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
     if 48 - 48: II111iiii % I1ii11iIi11i - II111iiii
     iIIIIiI = None if ( iIIIIiI == I1iii11III ) else I1iii11III
     if ( iIIIIiI and iIIIIiI . timed_out ( ) ) :
      IiI1iI1 = iIIIIiI . port
      o0O00oo0O = red ( iIIIIiI . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( o0O00oo0O , IiI1iI1 ,
      # o0oOOo0O0Ooo * I1Ii111
 IiiOo0OOoO0oo0oO ) )
      iIIIIiI = None
      if 65 - 65: I11i * iIii1I11I1II1 % OoO0O00 % I11i * O0 * i1IIi
      if 27 - 27: OoOoOO00 % OoooooooOO
      if 77 - 77: Ii1I % Oo0Ooo
      if 30 - 30: iIii1I11I1II1 * Oo0Ooo * OOooOOo * ooOoO0o
      if 6 - 6: iIii1I11I1II1 / oO0o % ooOoO0o
      if 19 - 19: iIii1I11I1II1 + I11i - iIii1I11I1II1 - Ii1I . Ii1I * OoO0O00
      if 32 - 32: I1IiiI + OOooOOo * oO0o
    if ( iIIIIiI ) :
     if ( iIIIIiI . address != oo0o00OO ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( o0O00oo0O , red ( iIIIIiI . address , False ) ) )
      if 100 - 100: OoO0O00
      self . rloc . store_address ( iIIIIiI . address )
      if 20 - 20: Ii1I % OoO0O00
     o0O00oo0O = red ( iIIIIiI . address , False )
     IiI1iI1 = iIIIIiI . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( o0O00oo0O , IiI1iI1 , IiiOo0OOoO0oo0oO ) )
     if 85 - 85: i1IIi % iIii1I11I1II1
     self . store_translated_rloc ( oOo0o0 , IiI1iI1 )
     if 10 - 10: O0 . oO0o * I1IiiI
     if 21 - 21: OoooooooOO
     if 76 - 76: i1IIi * i11iIiiIii / OOooOOo + I1Ii111
     if 50 - 50: oO0o % OoOoOO00 + I1IiiI
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
  if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
  if 79 - 79: oO0o + I1IiiI % iII111i + II111iiii % OoO0O00 % iII111i
  if 46 - 46: o0oOOo0O0Ooo
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for O00oo0ooo0O in self . rle . rle_nodes :
    O0o0oO = O00oo0ooo0O . rloc_name
    iIIIIiI = lisp_get_nat_info ( O00oo0ooo0O . address , O0o0oO )
    if ( iIIIIiI == None ) : continue
    if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
    IiI1iI1 = iIIIIiI . port
    ooOooo = O0o0oO
    if ( ooOooo ) : ooOooo = blue ( O0o0oO , False )
    if 44 - 44: I11i . oO0o
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( IiI1iI1 ,
    # ooOoO0o * iII111i - OoOoOO00 / I11i
 O00oo0ooo0O . address . print_address_no_iid ( ) , ooOooo ) )
    O00oo0ooo0O . translated_port = IiI1iI1
    if 3 - 3: i1IIi / ooOoO0o
    if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
    if 16 - 16: OoO0O00 / Ii1I * i11iIiiIii / o0oOOo0O0Ooo + I1Ii111
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 21 - 21: I11i % I1ii11iIi11i
  if 8 - 8: OOooOOo % OoO0O00 + O0 - o0oOOo0O0Ooo
  if 46 - 46: Oo0Ooo . ooOoO0o + OoOoOO00 - I11i / i11iIiiIii . iII111i
  if 80 - 80: II111iiii + OoO0O00 % ooOoO0o + i11iIiiIii
  I11II = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 86 - 86: iII111i * IiII . IiII
  if ( rloc_record . keys != None and I11II ) :
   ii1i1I1111ii = rloc_record . keys [ 1 ]
   if ( ii1i1I1111ii != None ) :
    oo0o00OO = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( IiI1iI1 )
    if 91 - 91: i11iIiiIii - IiII + Oo0Ooo . Oo0Ooo * oO0o
    ii1i1I1111ii . add_key_by_rloc ( oo0o00OO , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( oo0o00OO , False ) ) )
    if 89 - 89: iII111i + Oo0Ooo / Oo0Ooo / OoO0O00 + i11iIiiIii
    if 81 - 81: i11iIiiIii . iIii1I11I1II1 - OoooooooOO
    if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
  return ( IiI1iI1 )
  if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
  if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 42 - 42: OOooOOo
  if 36 - 36: OoooooooOO + ooOoO0o + iII111i
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 30 - 30: i1IIi % Ii1I
  if 18 - 18: o0oOOo0O0Ooo % I1ii11iIi11i . Ii1I . O0 * II111iiii + I1ii11iIi11i
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 45 - 45: OoO0O00 / I1ii11iIi11i * ooOoO0o * OOooOOo % i11iIiiIii * iII111i
  return ( True )
  if 33 - 33: oO0o . iII111i + Oo0Ooo
  if 33 - 33: ooOoO0o
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 46 - 46: OoOoOO00 / iII111i - OoO0O00 . o0oOOo0O0Ooo
  if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
  if 65 - 65: I1IiiI % iIii1I11I1II1
 def print_state_change ( self , new_state ) :
  oooooo = self . print_state ( )
  iI = "{} -> {}" . format ( oooooo , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   iI = bold ( iI , False )
   if 34 - 34: oO0o / IiII . Oo0Ooo . oO0o * i11iIiiIii
  return ( iI )
  if 26 - 26: OoooooooOO
  if 79 - 79: I1IiiI + I1IiiI
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 45 - 45: oO0o + I1IiiI / oO0o
  if 33 - 33: OoooooooOO - I1Ii111 . Oo0Ooo % OoooooooOO * ooOoO0o
 def print_recent_rloc_probe_rtts ( self ) :
  oooooooOOOOO = str ( self . recent_rloc_probe_rtts )
  oooooooOOOOO = oooooooOOOOO . replace ( "-1" , "?" )
  return ( oooooooOOOOO )
  if 60 - 60: OoO0O00 * I11i - I1ii11iIi11i . i1IIi
  if 85 - 85: II111iiii
 def compute_rloc_probe_rtt ( self ) :
  I1IIII = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  ooOO0o000 = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ I1IIII ] + ooOO0o000 [ 0 : - 1 ]
  if 47 - 47: OoooooooOO * iIii1I11I1II1
  if 65 - 65: oO0o * OoooooooOO . OOooOOo
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 75 - 75: o0oOOo0O0Ooo % iII111i
  if 35 - 35: OoooooooOO / OoOoOO00 * i1IIi * OoOoOO00 % Ii1I
 def print_recent_rloc_probe_hops ( self ) :
  i1ii11i1 = str ( self . recent_rloc_probe_hops )
  return ( i1ii11i1 )
  if 78 - 78: I1Ii111 % oO0o * iIii1I11I1II1
  if 1 - 1: i1IIi . iIii1I11I1II1
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < LISP_RLOC_PROBE_TTL / 2 ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 2 - 2: OOooOOo % Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
  if ( from_ttl < LISP_RLOC_PROBE_TTL / 2 ) :
   IiiIIi1i1iIi = "!"
  else :
   IiiIIi1i1iIi = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 89 - 89: I1Ii111
   if 87 - 87: iIii1I11I1II1 / I1ii11iIi11i
  I1IIII = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + IiiIIi1i1iIi
  ooOO0o000 = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ I1IIII ] + ooOO0o000 [ 0 : - 1 ]
  if 58 - 58: ooOoO0o
  if 82 - 82: OoOoOO00 * I1IiiI . I11i % I1IiiI . Oo0Ooo
 def store_rloc_probe_latencies ( self , json_telemetry ) :
  oOoO0Oo = lisp_decode_telemetry ( json_telemetry )
  if 12 - 12: OoooooooOO / I1Ii111 % I1Ii111 * iII111i % I1Ii111 * I1ii11iIi11i
  OOo = round ( float ( oOoO0Oo [ "etr-in" ] ) - float ( oOoO0Oo [ "itr-out" ] ) , 3 )
  i1i1 = round ( float ( oOoO0Oo [ "itr-in" ] ) - float ( oOoO0Oo [ "etr-out" ] ) , 3 )
  if 79 - 79: oO0o
  I1IIII = self . rloc_probe_latency
  self . rloc_probe_latency = str ( OOo ) + "/" + str ( i1i1 )
  ooOO0o000 = self . recent_rloc_probe_latencies
  self . recent_rloc_probe_latencies = [ I1IIII ] + ooOO0o000 [ 0 : - 1 ]
  if 52 - 52: oO0o + OoO0O00 / OoooooooOO - iIii1I11I1II1 / iII111i - oO0o
  if 68 - 68: I1IiiI - OoOoOO00 - iIii1I11I1II1 % i11iIiiIii * OoOoOO00 * OoO0O00
 def print_rloc_probe_latency ( self ) :
  return ( self . rloc_probe_latency )
  if 97 - 97: OoO0O00 - IiII + ooOoO0o % iIii1I11I1II1 % iII111i
  if 100 - 100: IiII - Ii1I * iIii1I11I1II1 . iII111i . i1IIi % Oo0Ooo
 def print_recent_rloc_probe_latencies ( self ) :
  i11I1i = str ( self . recent_rloc_probe_latencies )
  return ( i11I1i )
  if 8 - 8: oO0o % OOooOOo - i11iIiiIii - i1IIi / I1IiiI - OoooooooOO
  if 46 - 46: Oo0Ooo % i11iIiiIii * o0oOOo0O0Ooo
 def process_rloc_probe_reply ( self , ts , nonce , eid , group , hc , ttl , jt ) :
  oOo0o0 = self
  while ( True ) :
   if ( oOo0o0 . last_rloc_probe_nonce == nonce ) : break
   oOo0o0 = oOo0o0 . next_rloc
   if ( oOo0o0 == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 33 - 33: oO0o * ooOoO0o * Ii1I * IiII
    return
    if 39 - 39: i1IIi
    if 79 - 79: ooOoO0o - II111iiii - oO0o
    if 55 - 55: iII111i % iIii1I11I1II1 + Ii1I + oO0o . i11iIiiIii - OOooOOo
    if 14 - 14: oO0o - i11iIiiIii / OoOoOO00 % o0oOOo0O0Ooo / IiII * I1IiiI
    if 2 - 2: i1IIi / I1Ii111 + I1IiiI + I1ii11iIi11i - o0oOOo0O0Ooo + iIii1I11I1II1
    if 78 - 78: I1ii11iIi11i % i1IIi . I1Ii111 + Oo0Ooo . o0oOOo0O0Ooo % II111iiii
  oOo0o0 . last_rloc_probe_reply = ts
  oOo0o0 . compute_rloc_probe_rtt ( )
  O0ii1i = oOo0o0 . print_state_change ( "up" )
  if ( oOo0o0 . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( oOo0o0 . rloc , True )
   oOo0o0 . state = LISP_RLOC_UP_STATE
   oOo0o0 . last_state_change = lisp_get_timestamp ( )
   O0oOO0OOO = lisp_map_cache . lookup_cache ( eid , True )
   if ( O0oOO0OOO ) : lisp_write_ipc_map_cache ( True , O0oOO0OOO )
   if 75 - 75: I1IiiI * oO0o / Oo0Ooo - II111iiii . OoO0O00
   if 8 - 8: iII111i . i11iIiiIii . IiII . I1ii11iIi11i + I11i
   if 24 - 24: I1IiiI - I1IiiI . Oo0Ooo * IiII + I1IiiI / i1IIi
   if 18 - 18: II111iiii / iIii1I11I1II1 * I1ii11iIi11i . ooOoO0o * ooOoO0o
   if 89 - 89: I1IiiI - Oo0Ooo
  oOo0o0 . store_rloc_probe_hops ( hc , ttl )
  if 28 - 28: OoooooooOO . i1IIi . I1Ii111
  if 53 - 53: OoO0O00 * Oo0Ooo + Oo0Ooo
  if 62 - 62: OOooOOo - i1IIi + i11iIiiIii * I11i / OoO0O00
  if 84 - 84: IiII * OOooOOo
  if ( jt ) : oOo0o0 . store_rloc_probe_latencies ( jt )
  if 1 - 1: iII111i * I1IiiI . o0oOOo0O0Ooo . IiII
  oOoOoO0oOO0o0 = bold ( "RLOC-probe reply" , False )
  oo0o00OO = oOo0o0 . rloc . print_address_no_iid ( )
  I1ioOoo0O = bold ( str ( oOo0o0 . print_rloc_probe_rtt ( ) ) , False )
  III1I1Iii1 = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 16 - 16: o0oOOo0O0Ooo - iIii1I11I1II1 / OoooooooOO / I1ii11iIi11i + IiII
  IiIiIi1i11II = ""
  if ( oOo0o0 . rloc_next_hop != None ) :
   OooOOOoOoo0O0 , O0O0oo0O0O = oOo0o0 . rloc_next_hop
   IiIiIi1i11II = ", nh {}({})" . format ( O0O0oo0O0O , OooOOOoOoo0O0 )
   if 65 - 65: I1Ii111 . I1Ii111
   if 8 - 8: II111iiii - Oo0Ooo . iII111i
  OoO00OO0 = bold ( oOo0o0 . print_rloc_probe_latency ( ) , False )
  OoO00OO0 = ", latency {}" . format ( OoO00OO0 ) if jt else ""
  if 15 - 15: i11iIiiIii * I11i + oO0o
  oOo = green ( lisp_print_eid_tuple ( eid , group ) , False )
  if 67 - 67: IiII . OoO0O00
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}{}" ) . format ( oOoOoO0oOO0o0 , red ( oo0o00OO , False ) , III1I1Iii1 , oOo ,
  # ooOoO0o / o0oOOo0O0Ooo - OoooooooOO % I1IiiI
 O0ii1i , I1ioOoo0O , IiIiIi1i11II , str ( hc ) + "/" + str ( ttl ) , OoO00OO0 ) )
  if 94 - 94: OoooooooOO * I1ii11iIi11i
  if ( oOo0o0 . rloc_next_hop == None ) : return
  if 28 - 28: II111iiii / II111iiii / II111iiii
  if 70 - 70: OoO0O00 + O0 * OoO0O00
  if 25 - 25: OoooooooOO . Oo0Ooo + OOooOOo + Oo0Ooo * O0 % i1IIi
  if 71 - 71: II111iiii / Ii1I + i1IIi - OoOoOO00 + Ii1I
  oOo0o0 = None
  IiI1i11I11i1 = None
  while ( True ) :
   oOo0o0 = self if oOo0o0 == None else oOo0o0 . next_rloc
   if ( oOo0o0 == None ) : break
   if ( oOo0o0 . up_state ( ) == False ) : continue
   if ( oOo0o0 . rloc_probe_rtt == - 1 ) : continue
   if 51 - 51: II111iiii . oO0o % iII111i
   if ( IiI1i11I11i1 == None ) : IiI1i11I11i1 = oOo0o0
   if ( oOo0o0 . rloc_probe_rtt < IiI1i11I11i1 . rloc_probe_rtt ) : IiI1i11I11i1 = oOo0o0
   if 47 - 47: II111iiii - iII111i * I1IiiI . IiII
   if 41 - 41: OoOoOO00 / O0 + I1Ii111 . I1ii11iIi11i
  if ( IiI1i11I11i1 != None ) :
   OooOOOoOoo0O0 , O0O0oo0O0O = IiI1i11I11i1 . rloc_next_hop
   IiIiIi1i11II = bold ( "nh {}({})" . format ( O0O0oo0O0O , OooOOOoOoo0O0 ) , False )
   lprint ( "    Install host-route via best {}" . format ( IiIiIi1i11II ) )
   lisp_install_host_route ( oo0o00OO , None , False )
   lisp_install_host_route ( oo0o00OO , O0O0oo0O0O , True )
   if 48 - 48: Ii1I . o0oOOo0O0Ooo * O0 / OoooooooOO + I1Ii111 + Oo0Ooo
   if 92 - 92: Ii1I - o0oOOo0O0Ooo % I1IiiI + I1Ii111
   if 3 - 3: iIii1I11I1II1 + i11iIiiIii
 def add_to_rloc_probe_list ( self , eid , group ) :
  oo0o00OO = self . rloc . print_address_no_iid ( )
  IiI1iI1 = self . translated_port
  if ( IiI1iI1 != 0 ) : oo0o00OO += ":" + str ( IiI1iI1 )
  if 49 - 49: OoOoOO00 % iIii1I11I1II1 + I1Ii111
  if ( lisp_rloc_probe_list . has_key ( oo0o00OO ) == False ) :
   lisp_rloc_probe_list [ oo0o00OO ] = [ ]
   if 38 - 38: i11iIiiIii
   if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
  if ( group . is_null ( ) ) : group . instance_id = 0
  for i11iII1IiI , oOo , i11ii in lisp_rloc_probe_list [ oo0o00OO ] :
   if ( oOo . is_exact_match ( eid ) and i11ii . is_exact_match ( group ) ) :
    if ( i11iII1IiI == self ) :
     if ( lisp_rloc_probe_list [ oo0o00OO ] == [ ] ) :
      lisp_rloc_probe_list . pop ( oo0o00OO )
      if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
     return
     if 7 - 7: Oo0Ooo . iII111i % I1ii11iIi11i / iII111i
    lisp_rloc_probe_list [ oo0o00OO ] . remove ( [ i11iII1IiI , oOo , i11ii ] )
    break
    if 93 - 93: iII111i
    if 5 - 5: iII111i . I11i % I11i * Ii1I - I1ii11iIi11i . i11iIiiIii
  lisp_rloc_probe_list [ oo0o00OO ] . append ( [ self , eid , group ] )
  if 32 - 32: II111iiii
  if 58 - 58: I1IiiI - o0oOOo0O0Ooo - I1Ii111 . O0 % OoO0O00 . I11i
  if 41 - 41: iII111i . I1Ii111 - IiII / O0
  if 62 - 62: IiII * I1ii11iIi11i * iII111i * OoOoOO00
  if 12 - 12: Oo0Ooo * Ii1I / ooOoO0o % I11i % O0
  oOo0o0 = lisp_rloc_probe_list [ oo0o00OO ] [ 0 ] [ 0 ]
  if ( oOo0o0 . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 25 - 25: Oo0Ooo * oO0o
   if 78 - 78: OoOoOO00 / II111iiii
   if 6 - 6: I1Ii111 . OoOoOO00
 def delete_from_rloc_probe_list ( self , eid , group ) :
  oo0o00OO = self . rloc . print_address_no_iid ( )
  IiI1iI1 = self . translated_port
  if ( IiI1iI1 != 0 ) : oo0o00OO += ":" + str ( IiI1iI1 )
  if ( lisp_rloc_probe_list . has_key ( oo0o00OO ) == False ) : return
  if 75 - 75: Oo0Ooo + I11i
  oOOoO = [ ]
  for I1iII11ii1 in lisp_rloc_probe_list [ oo0o00OO ] :
   if ( I1iII11ii1 [ 0 ] != self ) : continue
   if ( I1iII11ii1 [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( I1iII11ii1 [ 2 ] . is_exact_match ( group ) == False ) : continue
   oOOoO = I1iII11ii1
   break
   if 1 - 1: O0 / OoOoOO00 + i11iIiiIii + ooOoO0o % o0oOOo0O0Ooo + OOooOOo
  if ( oOOoO == [ ] ) : return
  if 63 - 63: II111iiii * i1IIi - I1Ii111 + iIii1I11I1II1 % I11i - OOooOOo
  try :
   lisp_rloc_probe_list [ oo0o00OO ] . remove ( oOOoO )
   if ( lisp_rloc_probe_list [ oo0o00OO ] == [ ] ) :
    lisp_rloc_probe_list . pop ( oo0o00OO )
    if 95 - 95: iIii1I11I1II1 / oO0o - IiII - iII111i / iII111i % iIii1I11I1II1
  except :
   return
   if 30 - 30: I1ii11iIi11i + o0oOOo0O0Ooo * II111iiii
   if 81 - 81: I1IiiI / I1ii11iIi11i / OOooOOo
   if 89 - 89: Oo0Ooo % IiII
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  Oo0Ooo0O0 = ""
  oOo0o0 = self
  while ( True ) :
   i11IIiI1II = oOo0o0 . last_rloc_probe
   if ( i11IIiI1II == None ) : i11IIiI1II = 0
   i1I1iii1III1I11II1 = oOo0o0 . last_rloc_probe_reply
   if ( i1I1iii1III1I11II1 == None ) : i1I1iii1III1I11II1 = 0
   I1ioOoo0O = oOo0o0 . print_rloc_probe_rtt ( )
   IiII1iiI = space ( 4 )
   if 39 - 39: ooOoO0o + o0oOOo0O0Ooo + OOooOOo * OoOoOO00
   if ( oOo0o0 . rloc_next_hop == None ) :
    Oo0Ooo0O0 += "RLOC-Probing:\n"
   else :
    OooOOOoOoo0O0 , O0O0oo0O0O = oOo0o0 . rloc_next_hop
    Oo0Ooo0O0 += "RLOC-Probing for nh {}({}):\n" . format ( O0O0oo0O0O , OooOOOoOoo0O0 )
    if 98 - 98: iIii1I11I1II1 - oO0o
    if 91 - 91: iII111i % iII111i . ooOoO0o / iII111i
   Oo0Ooo0O0 += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( IiII1iiI , lisp_print_elapsed ( i11IIiI1II ) ,
   # OoO0O00 / OoooooooOO
 IiII1iiI , lisp_print_elapsed ( i1I1iii1III1I11II1 ) , I1ioOoo0O )
   if 4 - 4: Oo0Ooo
   if ( trailing_linefeed ) : Oo0Ooo0O0 += "\n"
   if 79 - 79: oO0o - OoO0O00
   oOo0o0 = oOo0o0 . next_rloc
   if ( oOo0o0 == None ) : break
   Oo0Ooo0O0 += "\n"
   if 49 - 49: ooOoO0o + iII111i % OoooooooOO / Oo0Ooo % i1IIi
  return ( Oo0Ooo0O0 )
  if 50 - 50: OoO0O00
  if 52 - 52: o0oOOo0O0Ooo + O0
 def get_encap_keys ( self ) :
  IiI1iI1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 13 - 13: OoO0O00
  oo0o00OO = self . rloc . print_address_no_iid ( ) + ":" + IiI1iI1
  if 56 - 56: OoOoOO00 . ooOoO0o * oO0o - I11i
  try :
   oOoo0oO = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ]
   if ( oOoo0oO [ 1 ] ) : return ( oOoo0oO [ 1 ] . encrypt_key , oOoo0oO [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 47 - 47: oO0o . i1IIi * I1ii11iIi11i % OOooOOo % IiII / Oo0Ooo
   if 39 - 39: i11iIiiIii . OOooOOo + Oo0Ooo
   if 92 - 92: O0 * Oo0Ooo / o0oOOo0O0Ooo % OoO0O00
 def rloc_recent_rekey ( self ) :
  IiI1iI1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 87 - 87: OoooooooOO / I11i . O0
  oo0o00OO = self . rloc . print_address_no_iid ( ) + ":" + IiI1iI1
  if 77 - 77: OOooOOo + oO0o * iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii
  try :
   ii1i1I1111ii = lisp_crypto_keys_by_rloc_encap [ oo0o00OO ] [ 1 ]
   if ( ii1i1I1111ii == None ) : return ( False )
   if ( ii1i1I1111ii . last_rekey == None ) : return ( True )
   return ( time . time ( ) - ii1i1I1111ii . last_rekey < 1 )
  except :
   return ( False )
   if 92 - 92: Oo0Ooo . o0oOOo0O0Ooo % OoooooooOO * i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo
   if 48 - 48: iII111i * I1ii11iIi11i * oO0o % O0 . OoO0O00
   if 11 - 11: OOooOOo / o0oOOo0O0Ooo
   if 98 - 98: oO0o + I11i . oO0o
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
  if 10 - 10: iII111i + i1IIi . I11i % ooOoO0o / ooOoO0o
  if 86 - 86: Oo0Ooo
 def print_mapping ( self , eid_indent , rloc_indent ) :
  Oo0OO0000oooo = lisp_print_elapsed ( self . uptime )
  oOooO00OOoO = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 7 - 7: iIii1I11I1II1
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , oOooO00OOoO , Oo0OO0000oooo ,
 len ( self . rloc_set ) ) )
  for oOo0o0 in self . rloc_set : oOo0o0 . print_rloc ( rloc_indent )
  if 86 - 86: IiII + iII111i * II111iiii - IiII - o0oOOo0O0Ooo
  if 8 - 8: OOooOOo . Ii1I
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 15 - 15: ooOoO0o / OOooOOo + i1IIi / Ii1I / OOooOOo
  if 47 - 47: Oo0Ooo + oO0o % OoooooooOO
 def print_ttl ( self ) :
  O0000 = self . map_cache_ttl
  if ( O0000 == None ) : return ( "forever" )
  if 23 - 23: I1Ii111 / i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1
  if ( O0000 >= 3600 ) :
   if ( ( O0000 % 3600 ) == 0 ) :
    O0000 = str ( O0000 / 3600 ) + " hours"
   else :
    O0000 = str ( O0000 * 60 ) + " mins"
    if 11 - 11: I11i % OoOoOO00 * Oo0Ooo
  elif ( O0000 >= 60 ) :
   if ( ( O0000 % 60 ) == 0 ) :
    O0000 = str ( O0000 / 60 ) + " mins"
   else :
    O0000 = str ( O0000 ) + " secs"
    if 48 - 48: OOooOOo
  else :
   O0000 = str ( O0000 ) + " secs"
   if 66 - 66: iII111i - I1Ii111 - i11iIiiIii . o0oOOo0O0Ooo + Oo0Ooo
  return ( O0000 )
  if 90 - 90: O0 - i11iIiiIii * ooOoO0o . I1ii11iIi11i . Ii1I - OoooooooOO
  if 23 - 23: o0oOOo0O0Ooo
 def refresh ( self ) :
  if ( self . group . is_null ( ) ) : return ( self . refresh_unicast ( ) )
  return ( self . refresh_multicast ( ) )
  if 88 - 88: I1Ii111 + iIii1I11I1II1 / o0oOOo0O0Ooo
  if 93 - 93: ooOoO0o % iIii1I11I1II1 - OOooOOo . IiII + ooOoO0o
 def refresh_unicast ( self ) :
  return ( self . is_active ( ) and self . has_ttl_elapsed ( ) and
 self . gleaned == False )
  if 63 - 63: I1ii11iIi11i / OOooOOo
  if 28 - 28: I11i / I1Ii111 + IiII * OoooooooOO - iIii1I11I1II1
 def refresh_multicast ( self ) :
  if 6 - 6: I11i % o0oOOo0O0Ooo / OoooooooOO . I1Ii111
  if 17 - 17: I1ii11iIi11i + OoooooooOO / iIii1I11I1II1 . II111iiii + Oo0Ooo
  if 7 - 7: O0 - I1ii11iIi11i - iIii1I11I1II1
  if 96 - 96: OoOoOO00 . I1IiiI . I11i * OoooooooOO + OoooooooOO * O0
  if 90 - 90: I11i + I1ii11iIi11i + OoooooooOO + OoOoOO00 + IiII / iII111i
  oO000o0Oo00 = int ( ( time . time ( ) - self . uptime ) % self . map_cache_ttl )
  ooII1111iI1I = ( oO000o0Oo00 in [ 0 , 1 , 2 ] )
  if ( ooII1111iI1I == False ) : return ( False )
  if 23 - 23: I11i
  if 73 - 73: I1Ii111 . iII111i + O0
  if 15 - 15: OoooooooOO . OoooooooOO
  if 2 - 2: iII111i - i11iIiiIii
  O0O = ( ( time . time ( ) - self . last_multicast_map_request ) <= 2 )
  if ( O0O ) : return ( False )
  if 84 - 84: IiII % iII111i
  self . last_multicast_map_request = lisp_get_timestamp ( )
  return ( True )
  if 79 - 79: O0 / IiII . i1IIi - i1IIi + i1IIi
  if 47 - 47: iII111i - I1Ii111 - I1Ii111 . ooOoO0o
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . last_refresh_time
  if ( oO000o0Oo00 >= self . map_cache_ttl ) : return ( True )
  if 5 - 5: i1IIi
  if 47 - 47: I11i * I11i . OoOoOO00
  if 68 - 68: OoooooooOO + OoOoOO00 + i11iIiiIii
  if 89 - 89: Oo0Ooo + Ii1I * O0 - I1Ii111
  if 33 - 33: iIii1I11I1II1 . I11i
  oO0oOo00 = self . map_cache_ttl - ( self . map_cache_ttl / 10 )
  if ( oO000o0Oo00 >= oO0oOo00 ) : return ( True )
  return ( False )
  if 21 - 21: I11i / OOooOOo
  if 96 - 96: i11iIiiIii * OoooooooOO - OoO0O00 % IiII * OOooOOo
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  oO000o0Oo00 = time . time ( ) - self . stats . last_increment
  return ( oO000o0Oo00 <= 60 )
  if 28 - 28: oO0o . oO0o
  if 79 - 79: OOooOOo + i11iIiiIii + OOooOOo % I1IiiI % OoOoOO00
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 50 - 50: o0oOOo0O0Ooo / iIii1I11I1II1 * OoO0O00
  if 44 - 44: II111iiii / o0oOOo0O0Ooo
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 81 - 81: I1Ii111 . Ii1I * ooOoO0o . IiII - OoOoOO00
  if 79 - 79: ooOoO0o - O0
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for oOo0o0 in self . best_rloc_set :
   oOo0o0 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 56 - 56: ooOoO0o
   if 89 - 89: O0 % iIii1I11I1II1 / OoOoOO00 - I1Ii111 - I1IiiI
   if 60 - 60: IiII % i11iIiiIii / OOooOOo
 def build_best_rloc_set ( self ) :
  IiIiI11iiiI1I = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 60 - 60: I11i
  if 98 - 98: OoOoOO00 % I1ii11iIi11i / OoOoOO00 % o0oOOo0O0Ooo / I1ii11iIi11i
  if 21 - 21: I1IiiI * IiII - Oo0Ooo % ooOoO0o * i1IIi
  if 23 - 23: I11i * II111iiii + OoooooooOO . i1IIi + OoO0O00 + OoOoOO00
  o0O00o000OOoO = 256
  for oOo0o0 in self . rloc_set :
   if ( oOo0o0 . up_state ( ) ) : o0O00o000OOoO = min ( oOo0o0 . priority , o0O00o000OOoO )
   if 12 - 12: I1IiiI - Oo0Ooo / I11i
   if 79 - 79: II111iiii . I1Ii111 * I1Ii111 + I11i + I1Ii111 % I1IiiI
   if 42 - 42: I11i - i1IIi . Oo0Ooo - i1IIi
   if 87 - 87: O0 . o0oOOo0O0Ooo % OOooOOo / I11i - I1Ii111 % i11iIiiIii
   if 3 - 3: oO0o + iII111i + OOooOOo
   if 54 - 54: i11iIiiIii + OoO0O00 - IiII - iII111i / I11i
   if 85 - 85: OOooOOo * OOooOOo * I1Ii111 - ooOoO0o . O0 % iII111i
   if 5 - 5: i1IIi * iII111i . o0oOOo0O0Ooo - I1ii11iIi11i
   if 84 - 84: i1IIi
   if 17 - 17: IiII + iII111i * OoO0O00 / iII111i
  for oOo0o0 in self . rloc_set :
   if ( oOo0o0 . priority <= o0O00o000OOoO ) :
    if ( oOo0o0 . unreach_state ( ) and oOo0o0 . last_rloc_probe == None ) :
     oOo0o0 . last_rloc_probe = lisp_get_timestamp ( )
     if 67 - 67: i1IIi * IiII . OoOoOO00 % iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
    self . best_rloc_set . append ( oOo0o0 )
    if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
    if 65 - 65: OoOoOO00
    if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
    if 58 - 58: OoO0O00 * I1IiiI - II111iiii / Ii1I - I1IiiI % OoooooooOO
    if 33 - 33: IiII / i1IIi + I1Ii111
    if 5 - 5: O0 / iII111i % II111iiii . Oo0Ooo - I11i
    if 84 - 84: oO0o * iII111i % i11iIiiIii - O0 . iIii1I11I1II1 - OoOoOO00
    if 73 - 73: OoOoOO00
  for oOo0o0 in IiIiI11iiiI1I :
   if ( oOo0o0 . priority < o0O00o000OOoO ) : continue
   oOo0o0 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 66 - 66: Oo0Ooo
  for oOo0o0 in self . best_rloc_set :
   if ( oOo0o0 . rloc . is_null ( ) ) : continue
   oOo0o0 . add_to_rloc_probe_list ( self . eid , self . group )
   if 42 - 42: i11iIiiIii / II111iiii . OOooOOo
   if 65 - 65: OoOoOO00 % II111iiii + Oo0Ooo
   if 24 - 24: OoO0O00 % OoooooooOO
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  IIii1i = lisp_packet . packet
  II1IiI11II = lisp_packet . inner_version
  iiiIIiiIi = len ( self . best_rloc_set )
  if ( iiiIIiiIi == 0 ) :
   self . stats . increment ( len ( IIii1i ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 92 - 92: OoooooooOO
   if 11 - 11: Oo0Ooo - II111iiii
  O0ooOOOOO = 4 if lisp_load_split_pings else 0
  I1I = lisp_packet . hash_ports ( )
  if ( II1IiI11II == 4 ) :
   for IiIIi1IiiIiI in range ( 8 + O0ooOOOOO ) :
    I1I = I1I ^ struct . unpack ( "B" , IIii1i [ IiIIi1IiiIiI + 12 ] ) [ 0 ]
    if 39 - 39: I1ii11iIi11i % Oo0Ooo / I11i
  elif ( II1IiI11II == 6 ) :
   for IiIIi1IiiIiI in range ( 0 , 32 + O0ooOOOOO , 4 ) :
    I1I = I1I ^ struct . unpack ( "I" , IIii1i [ IiIIi1IiiIiI + 8 : IiIIi1IiiIiI + 12 ] ) [ 0 ]
    if 57 - 57: Oo0Ooo + Ii1I * OoooooooOO
   I1I = ( I1I >> 16 ) + ( I1I & 0xffff )
   I1I = ( I1I >> 8 ) + ( I1I & 0xff )
  else :
   for IiIIi1IiiIiI in range ( 0 , 12 + O0ooOOOOO , 4 ) :
    I1I = I1I ^ struct . unpack ( "I" , IIii1i [ IiIIi1IiiIiI : IiIIi1IiiIiI + 4 ] ) [ 0 ]
    if 30 - 30: O0
    if 70 - 70: oO0o
    if 89 - 89: O0
  if ( lisp_data_plane_logging ) :
   i1ii1I1ii = [ ]
   for i11iII1IiI in self . best_rloc_set :
    if ( i11iII1IiI . rloc . is_null ( ) ) : continue
    i1ii1I1ii . append ( [ i11iII1IiI . rloc . print_address_no_iid ( ) , i11iII1IiI . print_state ( ) ] )
    if 26 - 26: iIii1I11I1II1 - ooOoO0o
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( I1I ) , I1I % iiiIIiiIi , red ( str ( i1ii1I1ii ) , False ) ) )
   if 100 - 100: Oo0Ooo - o0oOOo0O0Ooo + iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1
   if 4 - 4: OoOoOO00 / Oo0Ooo - OoO0O00 . OoOoOO00 / I1Ii111
   if 60 - 60: OOooOOo * I1Ii111
   if 17 - 17: iII111i * I11i / iIii1I11I1II1 - II111iiii
   if 97 - 97: II111iiii * o0oOOo0O0Ooo
   if 13 - 13: o0oOOo0O0Ooo . II111iiii
  oOo0o0 = self . best_rloc_set [ I1I % iiiIIiiIi ]
  if 76 - 76: II111iiii + I1Ii111 . OoooooooOO / IiII % i11iIiiIii
  if 87 - 87: Ii1I / OoOoOO00 / OOooOOo
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
  if 19 - 19: i1IIi + IiII . OoO0O00 / O0 - I1Ii111 - Oo0Ooo
  if 24 - 24: iII111i + i1IIi
  Oo0ooO0O0o00o = lisp_get_echo_nonce ( oOo0o0 . rloc , None )
  if ( Oo0ooO0O0o00o ) :
   Oo0ooO0O0o00o . change_state ( oOo0o0 )
   if ( oOo0o0 . no_echoed_nonce_state ( ) ) :
    Oo0ooO0O0o00o . request_nonce_sent = None
    if 31 - 31: OoOoOO00
    if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
    if 43 - 43: II111iiii - OoooooooOO
    if 11 - 11: I1IiiI
    if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
    if 64 - 64: OoO0O00 - OoO0O00
  if ( oOo0o0 . up_state ( ) == False ) :
   oOoo0OoOoOooo00o = I1I % iiiIIiiIi
   ooo = ( oOoo0OoOoOooo00o + 1 ) % iiiIIiiIi
   while ( ooo != oOoo0OoOoOooo00o ) :
    oOo0o0 = self . best_rloc_set [ ooo ]
    if ( oOo0o0 . up_state ( ) ) : break
    ooo = ( ooo + 1 ) % iiiIIiiIi
    if 70 - 70: I1ii11iIi11i % ooOoO0o . o0oOOo0O0Ooo . I1Ii111 + ooOoO0o
   if ( ooo == oOoo0OoOoOooo00o ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 92 - 92: i11iIiiIii
    if 45 - 45: oO0o * O0 % I1ii11iIi11i
    if 41 - 41: i11iIiiIii + IiII * o0oOOo0O0Ooo * I1Ii111 - iII111i
    if 94 - 94: o0oOOo0O0Ooo . o0oOOo0O0Ooo / OOooOOo
    if 50 - 50: i11iIiiIii - II111iiii * OoooooooOO + II111iiii - ooOoO0o
    if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
  oOo0o0 . stats . increment ( len ( IIii1i ) )
  if 98 - 98: iII111i . i1IIi + o0oOOo0O0Ooo * OoooooooOO - i11iIiiIii
  if 21 - 21: i11iIiiIii . oO0o * o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
  if 33 - 33: I1IiiI + O0 - I11i
  if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
  if ( oOo0o0 . rle_name and oOo0o0 . rle == None ) :
   if ( lisp_rle_list . has_key ( oOo0o0 . rle_name ) ) :
    oOo0o0 . rle = lisp_rle_list [ oOo0o0 . rle_name ]
    if 63 - 63: o0oOOo0O0Ooo . IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
    if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
  if ( oOo0o0 . rle ) : return ( [ None , None , None , None , oOo0o0 . rle , None ] )
  if 38 - 38: O0 % I1ii11iIi11i + O0
  if 37 - 37: Oo0Ooo / I1IiiI
  if 23 - 23: II111iiii / iII111i
  if 55 - 55: i11iIiiIii - Ii1I % OoooooooOO * OoooooooOO
  if ( oOo0o0 . elp and oOo0o0 . elp . use_elp_node ) :
   return ( [ oOo0o0 . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 92 - 92: iIii1I11I1II1
   if 47 - 47: Oo0Ooo + Oo0Ooo * ooOoO0o - OoOoOO00 + II111iiii
   if 10 - 10: II111iiii / ooOoO0o . Ii1I / I1Ii111 / oO0o
   if 8 - 8: OOooOOo / ooOoO0o * I11i + OOooOOo * i1IIi
   if 48 - 48: o0oOOo0O0Ooo - I1ii11iIi11i / iII111i
  Ooo000o0o = None if ( oOo0o0 . rloc . is_null ( ) ) else oOo0o0 . rloc
  IiI1iI1 = oOo0o0 . translated_port
  Ooo0oo0oO000 = self . action if ( Ooo000o0o == None ) else None
  if 31 - 31: i11iIiiIii % IiII + IiII / oO0o
  if 53 - 53: IiII
  if 52 - 52: I1Ii111 * I11i - II111iiii + OOooOOo + II111iiii
  if 91 - 91: i1IIi + Oo0Ooo - I1ii11iIi11i + I1ii11iIi11i * O0 / O0
  if 78 - 78: OoooooooOO
  oOO000 = None
  if ( Oo0ooO0O0o00o and Oo0ooO0O0o00o . request_nonce_timeout ( ) == False ) :
   oOO000 = Oo0ooO0O0o00o . get_request_or_echo_nonce ( ipc_socket , Ooo000o0o )
   if 8 - 8: Oo0Ooo - Oo0Ooo % O0 - Ii1I / o0oOOo0O0Ooo % Oo0Ooo
   if 51 - 51: iIii1I11I1II1 / iIii1I11I1II1 * I1ii11iIi11i / I11i
   if 18 - 18: Ii1I - i11iIiiIii + OoO0O00 . O0 - iII111i
   if 9 - 9: OoooooooOO / iII111i + o0oOOo0O0Ooo / II111iiii / I1Ii111
   if 44 - 44: I1IiiI / iII111i / Oo0Ooo
  return ( [ Ooo000o0o , IiI1iI1 , oOO000 , Ooo0oo0oO000 , None , oOo0o0 ] )
  if 66 - 66: I1Ii111 + OoooooooOO % I1IiiI . iII111i * Oo0Ooo + o0oOOo0O0Ooo
  if 96 - 96: OoO0O00 - ooOoO0o * Ii1I
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 34 - 34: OoO0O00 . Oo0Ooo % Ii1I . IiII + OoOoOO00
  if 10 - 10: OoooooooOO * iII111i * ooOoO0o . Ii1I % I1Ii111 / I1ii11iIi11i
  if 71 - 71: Ii1I + IiII
  if 10 - 10: II111iiii % o0oOOo0O0Ooo . o0oOOo0O0Ooo % iII111i
  if 2 - 2: OoooooooOO / IiII % Oo0Ooo % iIii1I11I1II1
  for oo0OOOoO0OoO in self . rloc_set :
   for oOo0o0 in rloc_address_set :
    if ( oOo0o0 . is_exact_match ( oo0OOOoO0OoO . rloc ) == False ) : continue
    oOo0o0 = None
    break
    if 62 - 62: oO0o
   if ( oOo0o0 == rloc_address_set [ - 1 ] ) : return ( False )
   if 47 - 47: I1IiiI - O0 - I1ii11iIi11i . OoOoOO00
  return ( True )
  if 98 - 98: o0oOOo0O0Ooo - OoO0O00 . I1ii11iIi11i / OOooOOo
  if 43 - 43: I1IiiI + OOooOOo + o0oOOo0O0Ooo
 def get_rloc ( self , rloc ) :
  for oo0OOOoO0OoO in self . rloc_set :
   i11iII1IiI = oo0OOOoO0OoO . rloc
   if ( rloc . is_exact_match ( i11iII1IiI ) ) : return ( oo0OOOoO0OoO )
   if 44 - 44: o0oOOo0O0Ooo % OoO0O00 . OoooooooOO
  return ( None )
  if 21 - 21: Oo0Ooo * Oo0Ooo - iII111i - O0
  if 87 - 87: OOooOOo / I1Ii111 - Ii1I + O0 - oO0o - O0
 def get_rloc_by_interface ( self , interface ) :
  for oo0OOOoO0OoO in self . rloc_set :
   if ( oo0OOOoO0OoO . interface == interface ) : return ( oo0OOOoO0OoO )
   if 68 - 68: iII111i + II111iiii + I1ii11iIi11i * OOooOOo / oO0o
  return ( None )
  if 41 - 41: OOooOOo + Oo0Ooo % I1IiiI
  if 3 - 3: ooOoO0o * Ii1I
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   I1111I = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( I1111I == None ) :
    I1111I = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , I1111I )
    if 29 - 29: OoooooooOO + OOooOOo
   I1111I . add_source_entry ( self )
   if 68 - 68: O0 + IiII / iII111i - OoOoOO00
   if 5 - 5: I1IiiI * OoooooooOO - II111iiii
   if 64 - 64: i1IIi
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   O0oOO0OOO = lisp_map_cache . lookup_cache ( self . group , True )
   if ( O0oOO0OOO == None ) :
    O0oOO0OOO = lisp_mapping ( self . group , self . group , [ ] )
    O0oOO0OOO . eid . copy_address ( self . group )
    O0oOO0OOO . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , O0oOO0OOO )
    if 77 - 77: OOooOOo - i1IIi / II111iiii . I1Ii111 + O0
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( O0oOO0OOO . group )
   O0oOO0OOO . add_source_entry ( self )
   if 1 - 1: OoooooooOO % iIii1I11I1II1 * I1ii11iIi11i
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 17 - 17: Ii1I * i1IIi % OoO0O00
  if 12 - 12: I1ii11iIi11i
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 86 - 86: iIii1I11I1II1 % iII111i
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    oOoOo0 = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( oOoOo0 ) )
    if 50 - 50: I1IiiI / Ii1I / Ii1I + O0 % I11i - i1IIi
  else :
   O0oOO0OOO = lisp_map_cache . lookup_cache ( self . group , True )
   if ( O0oOO0OOO == None ) : return
   if 72 - 72: II111iiii . OoO0O00 . II111iiii * I1ii11iIi11i
   iIIiI = O0oOO0OOO . lookup_source_cache ( self . eid , True )
   if ( iIIiI == None ) : return
   if 8 - 8: i1IIi * o0oOOo0O0Ooo % i11iIiiIii * OoO0O00 % OOooOOo . o0oOOo0O0Ooo
   O0oOO0OOO . source_cache . delete_cache ( self . eid )
   if ( O0oOO0OOO . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 54 - 54: I1ii11iIi11i * IiII - Ii1I + OoO0O00 * i11iIiiIii
    if 7 - 7: I1IiiI * II111iiii / i11iIiiIii / oO0o * i1IIi
    if 15 - 15: i1IIi
    if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 15 - 15: I1ii11iIi11i
  if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 56 - 56: I1IiiI . ooOoO0o
  if 35 - 35: iIii1I11I1II1 % Oo0Ooo + o0oOOo0O0Ooo * o0oOOo0O0Ooo % ooOoO0o
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 10 - 10: I1ii11iIi11i / II111iiii % II111iiii - OoooooooOO * o0oOOo0O0Ooo / ooOoO0o
  if 26 - 26: OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  o0OoO0000o = "," + str ( self . secondary_iid )
  return ( prefix . replace ( o0OoO0000o , o0OoO0000o + "*" ) )
  if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
  if 8 - 8: OoooooooOO % I11i - iII111i * OOooOOo . O0
 def increment_decap_stats ( self , packet ) :
  IiI1iI1 = packet . udp_dport
  if ( IiI1iI1 == LISP_DATA_PORT ) :
   oOo0o0 = self . get_rloc ( packet . outer_dest )
  else :
   if 40 - 40: I1Ii111 . oO0o + OoO0O00 % Oo0Ooo / II111iiii
   if 19 - 19: i11iIiiIii
   if 20 - 20: i11iIiiIii . II111iiii - I1ii11iIi11i / ooOoO0o % i11iIiiIii
   if 35 - 35: Oo0Ooo - I1ii11iIi11i . Oo0Ooo
   for oOo0o0 in self . rloc_set :
    if ( oOo0o0 . translated_port != 0 ) : break
    if 13 - 13: II111iiii / OoOoOO00 * iII111i % O0 % I1ii11iIi11i * i11iIiiIii
    if 92 - 92: i11iIiiIii + OoO0O00
  if ( oOo0o0 != None ) : oOo0o0 . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 94 - 94: I1ii11iIi11i + OoO0O00 . II111iiii + oO0o . II111iiii
  if 96 - 96: i11iIiiIii
 def rtrs_in_rloc_set ( self ) :
  for oOo0o0 in self . rloc_set :
   if ( oOo0o0 . is_rtr ( ) ) : return ( True )
   if 66 - 66: ooOoO0o * iII111i - iII111i - O0 . o0oOOo0O0Ooo
  return ( False )
  if 23 - 23: iIii1I11I1II1 / I11i % OoOoOO00 . OoO0O00
  if 90 - 90: iIii1I11I1II1 - OOooOOo . Ii1I % OoO0O00
 def add_recent_source ( self , source ) :
  self . recent_sources [ source . print_address ( ) ] = lisp_get_timestamp ( )
  if 89 - 89: i11iIiiIii
  if 86 - 86: Oo0Ooo % iIii1I11I1II1 . II111iiii / I11i % OoO0O00 % OoO0O00
  if 40 - 40: o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo * i1IIi
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 94 - 94: oO0o - II111iiii + OoOoOO00
  if 90 - 90: Oo0Ooo + Oo0Ooo + I1Ii111
 def get_timeout ( self , interface ) :
  try :
   Oo0o00000o = lisp_myinterfaces [ interface ]
   self . timeout = Oo0o00000o . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 31 - 31: iIii1I11I1II1
   if 100 - 100: I11i + IiII
   if 29 - 29: iIii1I11I1II1 % O0 / I1ii11iIi11i . I1Ii111 / O0 . iII111i
   if 11 - 11: OoO0O00 - II111iiii . I1IiiI - OOooOOo
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 54 - 54: i1IIi + OoOoOO00
  if 76 - 76: OoOoOO00
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 54 - 54: o0oOOo0O0Ooo . i11iIiiIii + I1IiiI * ooOoO0o - ooOoO0o
  if 28 - 28: I1Ii111 . i11iIiiIii * oO0o % ooOoO0o / iII111i . OOooOOo
  if 57 - 57: OoooooooOO . iIii1I11I1II1 % iII111i % Oo0Ooo
  if 92 - 92: I1Ii111 - Ii1I + I1Ii111
  if 8 - 8: Oo0Ooo . iII111i / i11iIiiIii + iIii1I11I1II1 - OoOoOO00
  if 1 - 1: i11iIiiIii
  if 25 - 25: OoooooooOO / II111iiii . OOooOOo * OoOoOO00 - OoooooooOO
  if 8 - 8: iII111i . iIii1I11I1II1 * O0
  if 87 - 87: OoO0O00 * OoooooooOO + OoOoOO00 . OoooooooOO + o0oOOo0O0Ooo + Ii1I
  if 26 - 26: i1IIi
def lisp_is_group_more_specific ( group_str , group_mapping ) :
 o0OoO0000o = group_mapping . group_prefix . instance_id
 i111IiI1III1 = group_mapping . group_prefix . mask_len
 oOooO00OOoO = lisp_address ( LISP_AFI_IPV4 , group_str , 32 , o0OoO0000o )
 if ( oOooO00OOoO . is_more_specific ( group_mapping . group_prefix ) ) : return ( i111IiI1III1 )
 return ( - 1 )
 if 33 - 33: OoOoOO00 + OOooOOo . i1IIi . IiII
 if 78 - 78: OoooooooOO * I11i / OOooOOo + oO0o . I1Ii111 * iII111i
 if 98 - 98: i1IIi
 if 28 - 28: Oo0Ooo . I1Ii111 . iIii1I11I1II1 + I1IiiI . II111iiii * I1ii11iIi11i
 if 26 - 26: i1IIi / i11iIiiIii * II111iiii
 if 11 - 11: Oo0Ooo % i1IIi
 if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
def lisp_lookup_group ( group ) :
 i1ii1I1ii = None
 for II111ii1 in lisp_group_mapping_list . values ( ) :
  i111IiI1III1 = lisp_is_group_more_specific ( group , II111ii1 )
  if ( i111IiI1III1 == - 1 ) : continue
  if ( i1ii1I1ii == None or i111IiI1III1 > i1ii1I1ii . group_prefix . mask_len ) : i1ii1I1ii = II111ii1
  if 35 - 35: I1Ii111 - iII111i . I11i . O0
 return ( i1ii1I1ii )
 if 87 - 87: OOooOOo * ooOoO0o / OoO0O00 / OoO0O00
 if 10 - 10: I11i % OOooOOo % i1IIi + I1IiiI - iIii1I11I1II1 + O0
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 9 - 9: oO0o % Ii1I
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
  if 20 - 20: OoooooooOO - OoooooooOO + Ii1I % I1Ii111
  if 54 - 54: IiII % oO0o + i11iIiiIii % O0
  if 56 - 56: OoOoOO00 / II111iiii . O0
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
  if 24 - 24: OoooooooOO * Ii1I * II111iiii
  if 75 - 75: I1IiiI / o0oOOo0O0Ooo . Ii1I / Ii1I / iII111i - Ii1I
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 39 - 39: OoO0O00 . iIii1I11I1II1 - oO0o
  if 60 - 60: OOooOOo + OOooOOo - Ii1I / iII111i
 def print_flags ( self , html ) :
  if ( html == False ) :
   Oo0Ooo0O0 = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # iII111i % OOooOOo * oO0o
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
   for O0OoOOoO in I11ii1i1I :
    oo0o00Oo0 = lisp_site_flags [ O0OoOOoO . upper ( ) ]
    oo0o00Oo0 = oo0o00Oo0 . format ( "" if O0OoOOoO . isupper ( ) else "not " )
    Oo0Ooo0O0 += lisp_span ( O0OoOOoO , oo0o00Oo0 )
    if ( O0OoOOoO . lower ( ) != "n" ) : Oo0Ooo0O0 += "-"
    if 35 - 35: oO0o
    if 63 - 63: I11i . I1IiiI + OoooooooOO + O0
  return ( Oo0Ooo0O0 )
  if 55 - 55: i11iIiiIii * Ii1I % OOooOOo + ooOoO0o - I1ii11iIi11i . Oo0Ooo
  if 48 - 48: o0oOOo0O0Ooo
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 55 - 55: OOooOOo - OoooooooOO * iIii1I11I1II1 + iII111i % II111iiii
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 33 - 33: I1Ii111 * oO0o * OoooooooOO + OOooOOo - I1IiiI + I1Ii111
  if 92 - 92: ooOoO0o * I11i % iIii1I11I1II1 + Ii1I - OoOoOO00
 def build_sort_key ( self ) :
  i11 = lisp_cache ( )
  i111ii1I111Ii , ii1i1I1111ii = i11 . build_key ( self . eid )
  o0I1i = ""
  if ( self . group . is_null ( ) == False ) :
   iIi1iI1I , o0I1i = i11 . build_key ( self . group )
   o0I1i = "-" + o0I1i [ 0 : 12 ] + "-" + str ( iIi1iI1I ) + "-" + o0I1i [ 12 : : ]
   if 86 - 86: i1IIi . oO0o % OOooOOo
  ii1i1I1111ii = ii1i1I1111ii [ 0 : 12 ] + "-" + str ( i111ii1I111Ii ) + "-" + ii1i1I1111ii [ 12 : : ] + o0I1i
  del ( i11 )
  return ( ii1i1I1111ii )
  if 99 - 99: oO0o / I1Ii111 * oO0o * I11i
  if 38 - 38: o0oOOo0O0Ooo + OoOoOO00
 def merge_in_site_eid ( self , child ) :
  I1IIIIi1i = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   I1IIIIi1i = self . merge_rles_in_site_eid ( )
   if 17 - 17: OoO0O00
   if 79 - 79: Ii1I - II111iiii
   if 57 - 57: II111iiii / OoooooooOO
   if 4 - 4: I11i * OoOoOO00
   if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
   if 87 - 87: oO0o . I11i
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 15 - 15: oO0o
  return ( I1IIIIi1i )
  if 45 - 45: Oo0Ooo * IiII * OoO0O00 + iIii1I11I1II1
  if 89 - 89: IiII . IiII . oO0o % iII111i
 def copy_rloc_records ( self ) :
  II1iIi = [ ]
  for oo0OOOoO0OoO in self . registered_rlocs :
   II1iIi . append ( copy . deepcopy ( oo0OOOoO0OoO ) )
   if 40 - 40: OOooOOo - Oo0Ooo . iII111i - I1IiiI % I1Ii111 - i11iIiiIii
  return ( II1iIi )
  if 23 - 23: I1ii11iIi11i - I1IiiI / o0oOOo0O0Ooo / I11i + OoO0O00
  if 47 - 47: i1IIi . i11iIiiIii / I1ii11iIi11i + OoooooooOO % i11iIiiIii - i1IIi
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for Ii1ii1 in self . individual_registrations . values ( ) :
   if ( self . site_id != Ii1ii1 . site_id ) : continue
   if ( Ii1ii1 . registered == False ) : continue
   self . registered_rlocs += Ii1ii1 . copy_rloc_records ( )
   if 9 - 9: I1ii11iIi11i
   if 68 - 68: I1IiiI + ooOoO0o * i11iIiiIii - OOooOOo / II111iiii
   if 81 - 81: O0 - I1IiiI / ooOoO0o % I1IiiI . iII111i
   if 63 - 63: oO0o * Ii1I
   if 95 - 95: OoooooooOO % I1ii11iIi11i . I1Ii111 . IiII
   if 98 - 98: OoooooooOO - OoO0O00 . oO0o - iIii1I11I1II1 * iIii1I11I1II1 % Ii1I
  II1iIi = [ ]
  for oo0OOOoO0OoO in self . registered_rlocs :
   if ( oo0OOOoO0OoO . rloc . is_null ( ) or len ( II1iIi ) == 0 ) :
    II1iIi . append ( oo0OOOoO0OoO )
    continue
    if 87 - 87: O0 % iII111i
   for oOo0o00OOOO in II1iIi :
    if ( oOo0o00OOOO . rloc . is_null ( ) ) : continue
    if ( oo0OOOoO0OoO . rloc . is_exact_match ( oOo0o00OOOO . rloc ) ) : break
    if 7 - 7: I1Ii111 + O0 % i11iIiiIii + o0oOOo0O0Ooo . OoooooooOO
   if ( oOo0o00OOOO == II1iIi [ - 1 ] ) : II1iIi . append ( oo0OOOoO0OoO )
   if 74 - 74: OOooOOo
  self . registered_rlocs = II1iIi
  if 10 - 10: OoOoOO00 / i11iIiiIii
  if 21 - 21: Ii1I - i1IIi / I11i + IiII
  if 44 - 44: OoooooooOO % I11i / O0
  if 94 - 94: IiII
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 83 - 83: OoO0O00
  if 55 - 55: iII111i
 def merge_rles_in_site_eid ( self ) :
  if 37 - 37: oO0o / o0oOOo0O0Ooo + I11i * OoO0O00 * o0oOOo0O0Ooo
  if 33 - 33: I1Ii111
  if 97 - 97: Ii1I / iII111i - ooOoO0o + IiII * OoOoOO00 - OOooOOo
  if 43 - 43: oO0o / II111iiii - iII111i / oO0o
  oO0oII11i = { }
  for oo0OOOoO0OoO in self . registered_rlocs :
   if ( oo0OOOoO0OoO . rle == None ) : continue
   for O00oo0ooo0O in oo0OOOoO0OoO . rle . rle_nodes :
    IiiIIi1 = O00oo0ooo0O . address . print_address_no_iid ( )
    oO0oII11i [ IiiIIi1 ] = O00oo0ooo0O . address
    if 76 - 76: iII111i
   break
   if 48 - 48: OOooOOo % I1Ii111 % ooOoO0o . I1ii11iIi11i * O0 . O0
   if 25 - 25: O0 - Ii1I - IiII
   if 72 - 72: Ii1I % O0 + II111iiii . i11iIiiIii
   if 66 - 66: II111iiii % I1IiiI
   if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 + I1Ii111 * OOooOOo . I1IiiI
  self . merge_rlocs_in_site_eid ( )
  if 96 - 96: I1ii11iIi11i
  if 37 - 37: OoO0O00 % o0oOOo0O0Ooo * O0 * O0 + iII111i
  if 18 - 18: i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % oO0o * Ii1I / I1IiiI
  if 46 - 46: o0oOOo0O0Ooo . ooOoO0o / Ii1I
  if 97 - 97: Ii1I . Oo0Ooo - O0 - I1Ii111 . i1IIi
  if 47 - 47: IiII * ooOoO0o - i1IIi % OoOoOO00 * i11iIiiIii . OoooooooOO
  if 84 - 84: OoOoOO00 / IiII - i1IIi - I1IiiI * OOooOOo
  if 35 - 35: II111iiii
  I1I1iI1 = [ ]
  for oo0OOOoO0OoO in self . registered_rlocs :
   if ( self . registered_rlocs . index ( oo0OOOoO0OoO ) == 0 ) :
    I1I1iI1 . append ( oo0OOOoO0OoO )
    continue
    if 82 - 82: ooOoO0o - ooOoO0o . Ii1I . i11iIiiIii % Ii1I + OOooOOo
   if ( oo0OOOoO0OoO . rle == None ) : I1I1iI1 . append ( oo0OOOoO0OoO )
   if 33 - 33: Oo0Ooo - OOooOOo / OoOoOO00 % II111iiii % OOooOOo + I1Ii111
  self . registered_rlocs = I1I1iI1
  if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
  if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
  if 98 - 98: IiII
  if 75 - 75: OoooooooOO % IiII + Ii1I - i1IIi / OoooooooOO
  if 57 - 57: iII111i
  if 18 - 18: II111iiii % i11iIiiIii + I11i - OOooOOo
  if 100 - 100: o0oOOo0O0Ooo / Ii1I - iIii1I11I1II1 / oO0o
  i1I1Ii11II1i = lisp_rle ( "" )
  O00oIi11I11iIi1i1 = { }
  O0o0oO = None
  for Ii1ii1 in self . individual_registrations . values ( ) :
   if ( Ii1ii1 . registered == False ) : continue
   oOoOO0O00Ooo = Ii1ii1 . registered_rlocs [ 0 ] . rle
   if ( oOoOO0O00Ooo == None ) : continue
   if 45 - 45: ooOoO0o
   O0o0oO = Ii1ii1 . registered_rlocs [ 0 ] . rloc_name
   for oo0II1I1I in oOoOO0O00Ooo . rle_nodes :
    IiiIIi1 = oo0II1I1I . address . print_address_no_iid ( )
    if ( O00oIi11I11iIi1i1 . has_key ( IiiIIi1 ) ) : break
    if 33 - 33: iIii1I11I1II1 . I1ii11iIi11i - O0 - IiII
    O00oo0ooo0O = lisp_rle_node ( )
    O00oo0ooo0O . address . copy_address ( oo0II1I1I . address )
    O00oo0ooo0O . level = oo0II1I1I . level
    O00oo0ooo0O . rloc_name = O0o0oO
    i1I1Ii11II1i . rle_nodes . append ( O00oo0ooo0O )
    O00oIi11I11iIi1i1 [ IiiIIi1 ] = oo0II1I1I . address
    if 51 - 51: OoooooooOO . I1IiiI . i11iIiiIii
    if 76 - 76: OoOoOO00 + iII111i . ooOoO0o + OoO0O00 + I1IiiI / IiII
    if 70 - 70: O0 * i11iIiiIii / Ii1I - II111iiii / O0
    if 30 - 30: IiII . I1ii11iIi11i % ooOoO0o
    if 15 - 15: oO0o
    if 86 - 86: O0
  if ( len ( i1I1Ii11II1i . rle_nodes ) == 0 ) : i1I1Ii11II1i = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = i1I1Ii11II1i
   if ( O0o0oO ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 13 - 13: I1ii11iIi11i . IiII - I11i
   if 81 - 81: i11iIiiIii
   if 7 - 7: IiII - OoOoOO00 * i1IIi
   if 14 - 14: I1ii11iIi11i . OoO0O00
   if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
  if ( oO0oII11i . keys ( ) == O00oIi11I11iIi1i1 . keys ( ) ) : return ( False )
  if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # OoO0O00 / O0
 oO0oII11i . keys ( ) , O00oIi11I11iIi1i1 . keys ( ) ) )
  if 84 - 84: ooOoO0o
  return ( True )
  if 92 - 92: I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
  if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
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
    if 76 - 76: OoooooooOO - O0
    if 17 - 17: Oo0Ooo % I1Ii111 . oO0o - O0
    if 32 - 32: O0 % O0
    if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
    if 65 - 65: I1ii11iIi11i % ooOoO0o - OoOoOO00 + ooOoO0o + Oo0Ooo
    IiI111II1I1iI . parent_for_more_specifics = self . parent_for_more_specifics
    if 95 - 95: I1Ii111 * i11iIiiIii - I1IiiI - OoOoOO00 . ooOoO0o
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( IiI111II1I1iI . group )
   IiI111II1I1iI . add_source_entry ( self )
   if 34 - 34: OoooooooOO % I1ii11iIi11i + OoooooooOO % i11iIiiIii / IiII - ooOoO0o
   if 74 - 74: iIii1I11I1II1 % II111iiii + IiII
   if 71 - 71: I1IiiI / O0 * i1IIi . i1IIi + Oo0Ooo
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   IiI111II1I1iI = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( IiI111II1I1iI == None ) : return
   if 32 - 32: i1IIi * I1Ii111 % I1IiiI / IiII . I1Ii111
   Ii1ii1 = IiI111II1I1iI . lookup_source_cache ( self . eid , True )
   if ( Ii1ii1 == None ) : return
   if 11 - 11: OOooOOo
   if ( IiI111II1I1iI . source_cache == None ) : return
   if 25 - 25: i1IIi
   IiI111II1I1iI . source_cache . delete_cache ( self . eid )
   if ( IiI111II1I1iI . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 99 - 99: OOooOOo + OoooooooOO . I1Ii111 * Oo0Ooo % oO0o
    if 75 - 75: iII111i
    if 8 - 8: I1ii11iIi11i . I11i / I1ii11iIi11i - i1IIi
    if 22 - 22: OOooOOo
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 7 - 7: O0 - I1ii11iIi11i - OoO0O00 * I1Ii111
  if 17 - 17: o0oOOo0O0Ooo % OoO0O00 - I11i * o0oOOo0O0Ooo - i1IIi / I1IiiI
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 100 - 100: OoO0O00 * i1IIi * o0oOOo0O0Ooo * Oo0Ooo - o0oOOo0O0Ooo
  if 100 - 100: iII111i - i11iIiiIii + OoO0O00
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 50 - 50: II111iiii
  if 42 - 42: OOooOOo * I1Ii111
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 53 - 53: II111iiii % OOooOOo / I1ii11iIi11i * OoOoOO00 % I1ii11iIi11i * iII111i
  if 91 - 91: iII111i . OoooooooOO
 def inherit_from_ams_parent ( self ) :
  ooOOo000II = self . parent_for_more_specifics
  if ( ooOOo000II == None ) : return
  self . force_proxy_reply = ooOOo000II . force_proxy_reply
  self . force_nat_proxy_reply = ooOOo000II . force_nat_proxy_reply
  self . force_ttl = ooOOo000II . force_ttl
  self . pitr_proxy_reply_drop = ooOOo000II . pitr_proxy_reply_drop
  self . proxy_reply_action = ooOOo000II . proxy_reply_action
  self . echo_nonce_capable = ooOOo000II . echo_nonce_capable
  self . policy = ooOOo000II . policy
  self . require_signature = ooOOo000II . require_signature
  if 90 - 90: i11iIiiIii - I1IiiI
  if 39 - 39: iII111i % OoooooooOO % Ii1I % I1IiiI
 def rtrs_in_rloc_set ( self ) :
  for oo0OOOoO0OoO in self . registered_rlocs :
   if ( oo0OOOoO0OoO . is_rtr ( ) ) : return ( True )
   if 63 - 63: OoO0O00 - I1Ii111 - II111iiii
  return ( False )
  if 79 - 79: II111iiii - II111iiii + OoOoOO00 / iII111i % OoooooooOO - OoO0O00
  if 22 - 22: o0oOOo0O0Ooo + I1Ii111 . Oo0Ooo
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for oo0OOOoO0OoO in self . registered_rlocs :
   if ( oo0OOOoO0OoO . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( oo0OOOoO0OoO . is_rtr ( ) ) : return ( True )
   if 84 - 84: O0 + I1IiiI % Oo0Ooo + OOooOOo
  return ( False )
  if 94 - 94: OOooOOo
  if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
 def is_rloc_in_rloc_set ( self , rloc ) :
  for oo0OOOoO0OoO in self . registered_rlocs :
   if ( oo0OOOoO0OoO . rle ) :
    for i1I1Ii11II1i in oo0OOOoO0OoO . rle . rle_nodes :
     if ( i1I1Ii11II1i . address . is_exact_match ( rloc ) ) : return ( True )
     if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
     if 31 - 31: I11i . o0oOOo0O0Ooo
   if ( oo0OOOoO0OoO . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 82 - 82: I11i - Oo0Ooo
  return ( False )
  if 77 - 77: I1IiiI + OoO0O00 % iIii1I11I1II1 - OOooOOo
  if 80 - 80: oO0o % I1ii11iIi11i * I1Ii111 + i1IIi
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 79 - 79: oO0o + IiII
  for oo0OOOoO0OoO in prev_rloc_set :
   ii11iiiI1iII = oo0OOOoO0OoO . rloc
   if ( self . is_rloc_in_rloc_set ( ii11iiiI1iII ) == False ) : return ( False )
   if 4 - 4: iII111i + OoooooooOO / I1Ii111
  return ( True )
  if 57 - 57: I1IiiI . iIii1I11I1II1 % iII111i * iII111i / I1Ii111
  if 30 - 30: O0 / I11i % OoOoOO00 * I1Ii111 / O0 % ooOoO0o
  if 36 - 36: iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
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
   if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 97 - 97: i11iIiiIii / O0 % OoO0O00
  if 88 - 88: i1IIi . I1IiiI
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
  try :
   IIiiI = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   OO00000 = IIiiI [ 2 ]
  except :
   return
   if 59 - 59: I1ii11iIi11i % OoO0O00 . i1IIi / I1ii11iIi11i
   if 44 - 44: o0oOOo0O0Ooo % o0oOOo0O0Ooo % oO0o
   if 76 - 76: ooOoO0o / iII111i
   if 29 - 29: OOooOOo / OoooooooOO % II111iiii
   if 68 - 68: iIii1I11I1II1 * iII111i % o0oOOo0O0Ooo
   if 45 - 45: OoooooooOO
  if ( len ( OO00000 ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 45 - 45: iIii1I11I1II1
   if 11 - 11: Ii1I * OoO0O00 % I1ii11iIi11i
  IiiIIi1 = OO00000 [ self . a_record_index ]
  if ( IiiIIi1 != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( IiiIIi1 )
   self . insert_mr ( )
   if 60 - 60: i11iIiiIii % II111iiii % I11i
   if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
   if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
   if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
   if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
   if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
  for IiiIIi1 in OO00000 [ 1 : : ] :
   OO0o = lisp_address ( LISP_AFI_NONE , IiiIIi1 , 0 , 0 )
   O0O0OOoO00 = lisp_get_map_resolver ( OO0o , None )
   if ( O0O0OOoO00 != None and O0O0OOoO00 . a_record_index == OO00000 . index ( IiiIIi1 ) ) :
    continue
    if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
   O0O0OOoO00 = lisp_mr ( IiiIIi1 , None , None )
   O0O0OOoO00 . a_record_index = OO00000 . index ( IiiIIi1 )
   O0O0OOoO00 . dns_name = self . dns_name
   O0O0OOoO00 . last_dns_resolve = lisp_get_timestamp ( )
   if 91 - 91: II111iiii * o0oOOo0O0Ooo
   if 20 - 20: iIii1I11I1II1 % Oo0Ooo * OoOoOO00 % IiII
   if 93 - 93: I11i * iIii1I11I1II1 * oO0o
   if 74 - 74: I1IiiI
   if 39 - 39: iII111i * IiII / iII111i * IiII % I1ii11iIi11i
  ii = [ ]
  for O0O0OOoO00 in lisp_map_resolvers_list . values ( ) :
   if ( self . dns_name != O0O0OOoO00 . dns_name ) : continue
   OO0o = O0O0OOoO00 . map_resolver . print_address_no_iid ( )
   if ( OO0o in OO00000 ) : continue
   ii . append ( O0O0OOoO00 )
   if 100 - 100: Ii1I / OoOoOO00 / ooOoO0o * IiII * II111iiii
  for O0O0OOoO00 in ii : O0O0OOoO00 . delete_mr ( )
  if 68 - 68: iIii1I11I1II1 . OoOoOO00 * OOooOOo * oO0o
  if 54 - 54: Ii1I % OoO0O00 % I1IiiI % OOooOOo / oO0o + I1IiiI
 def insert_mr ( self ) :
  ii1i1I1111ii = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ ii1i1I1111ii ] = self
  if 94 - 94: OoOoOO00 . O0
  if 86 - 86: oO0o % Oo0Ooo . OoooooooOO / OOooOOo / i1IIi
 def delete_mr ( self ) :
  ii1i1I1111ii = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( ii1i1I1111ii ) == False ) : return
  lisp_map_resolvers_list . pop ( ii1i1I1111ii )
  if 65 - 65: Ii1I . OoooooooOO % IiII - o0oOOo0O0Ooo . OOooOOo . II111iiii
  if 100 - 100: ooOoO0o / Oo0Ooo + I1ii11iIi11i + OoooooooOO
  if 100 - 100: I11i . OOooOOo - II111iiii % I11i % iIii1I11I1II1
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 4 - 4: o0oOOo0O0Ooo . iII111i / O0
  if 13 - 13: iII111i / IiII
  if 28 - 28: iII111i
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
  if 97 - 97: iIii1I11I1II1
  if 18 - 18: OOooOOo
 def print_referral ( self , eid_indent , referral_indent ) :
  Ooooo000 = lisp_print_elapsed ( self . uptime )
  Ii1i1Ii1I = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , Ooooo000 ,
  # O0 / II111iiii
 Ii1i1Ii1I , len ( self . referral_set ) ) )
  if 94 - 94: O0 + O0 % I1ii11iIi11i % i1IIi
  for OOii1I1I1i in self . referral_set . values ( ) :
   OOii1I1I1i . print_ref_node ( referral_indent )
   if 15 - 15: I1IiiI
   if 48 - 48: Ii1I * IiII % O0 - II111iiii
   if 66 - 66: iIii1I11I1II1 / OOooOOo
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 67 - 67: I1Ii111
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
  if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 46 - 46: I11i - ooOoO0o . I1IiiI
  if 36 - 36: I11i + OoO0O00 * O0 * OoOoOO00 * iII111i
 def print_ttl ( self ) :
  O0000 = self . referral_ttl
  if ( O0000 < 60 ) : return ( str ( O0000 ) + " secs" )
  if 90 - 90: i11iIiiIii / i1IIi
  if ( ( O0000 % 60 ) == 0 ) :
   O0000 = str ( O0000 / 60 ) + " mins"
  else :
   O0000 = str ( O0000 ) + " secs"
   if 35 - 35: Ii1I . I11i / oO0o / OoOoOO00
  return ( O0000 )
  if 5 - 5: I1ii11iIi11i . o0oOOo0O0Ooo * iII111i * I1ii11iIi11i % I1Ii111
  if 83 - 83: iIii1I11I1II1 * o0oOOo0O0Ooo % i11iIiiIii + OoO0O00 . O0
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # o0oOOo0O0Ooo % OOooOOo / Ii1I . iIii1I11I1II1 % o0oOOo0O0Ooo + o0oOOo0O0Ooo
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 63 - 63: i11iIiiIii
  if 34 - 34: OoooooooOO - O0 + ooOoO0o * I1IiiI
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   iIii = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( iIii == None ) :
    iIii = lisp_referral ( )
    iIii . eid . copy_address ( self . group )
    iIii . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , iIii )
    if 75 - 75: OOooOOo % iII111i
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( iIii . group )
   iIii . add_source_entry ( self )
   if 15 - 15: OoO0O00
   if 52 - 52: II111iiii / ooOoO0o
   if 23 - 23: i11iIiiIii % OoO0O00 - o0oOOo0O0Ooo + OoooooooOO
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   iIii = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( iIii == None ) : return
   if 12 - 12: Ii1I / I1IiiI . oO0o . I1IiiI + ooOoO0o - II111iiii
   i1IIiI1III = iIii . lookup_source_cache ( self . eid , True )
   if ( i1IIiI1III == None ) : return
   if 6 - 6: Oo0Ooo + Oo0Ooo - OoOoOO00 - II111iiii
   iIii . source_cache . delete_cache ( self . eid )
   if ( iIii . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
    if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
    if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
    if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
  if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 92 - 92: I11i
  if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
  if 98 - 98: iII111i % IiII + OoO0O00
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 23 - 23: OOooOOo
  if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
 def print_ref_node ( self , indent ) :
  Oo0OO0000oooo = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , Oo0OO0000oooo ,
  # OoO0O00 / O0 / ooOoO0o * ooOoO0o * ooOoO0o + iIii1I11I1II1
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 51 - 51: Oo0Ooo * Ii1I . II111iiii * Oo0Ooo . iII111i
  if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
  if 9 - 9: OoOoOO00 % i1IIi + IiII
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
   if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
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
   if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
   if 95 - 95: ooOoO0o
   if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
  try :
   IIiiI = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   OO00000 = IIiiI [ 2 ]
  except :
   return
   if 32 - 32: OoOoOO00 % i11iIiiIii
   if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
   if 44 - 44: I1Ii111 + ooOoO0o
   if 15 - 15: I11i + OoO0O00 + OoOoOO00
   if 100 - 100: I1Ii111
   if 78 - 78: OoOoOO00
  if ( len ( OO00000 ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
   if 36 - 36: OoOoOO00 * II111iiii . OoooooooOO * I11i . I11i
  IiiIIi1 = OO00000 [ self . a_record_index ]
  if ( IiiIIi1 != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( IiiIIi1 )
   self . insert_ms ( )
   if 13 - 13: I1ii11iIi11i * II111iiii
   if 93 - 93: OOooOOo / O0 - o0oOOo0O0Ooo + OoO0O00 * I1IiiI
   if 53 - 53: I1ii11iIi11i
   if 91 - 91: o0oOOo0O0Ooo - I1ii11iIi11i . i1IIi
   if 64 - 64: ooOoO0o
   if 23 - 23: Oo0Ooo . OoO0O00
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 49 - 49: oO0o % i11iIiiIii * Ii1I
  for IiiIIi1 in OO00000 [ 1 : : ] :
   OO0o = lisp_address ( LISP_AFI_NONE , IiiIIi1 , 0 , 0 )
   IIIIiI1 = lisp_get_map_server ( OO0o )
   if ( IIIIiI1 != None and IIIIiI1 . a_record_index == OO00000 . index ( IiiIIi1 ) ) :
    continue
    if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
   IIIIiI1 = copy . deepcopy ( self )
   IIIIiI1 . map_server . store_address ( IiiIIi1 )
   IIIIiI1 . a_record_index = OO00000 . index ( IiiIIi1 )
   IIIIiI1 . last_dns_resolve = lisp_get_timestamp ( )
   IIIIiI1 . insert_ms ( )
   if 61 - 61: O0 - i11iIiiIii * o0oOOo0O0Ooo
   if 92 - 92: Oo0Ooo + OOooOOo - i11iIiiIii
   if 26 - 26: O0 % Oo0Ooo + ooOoO0o - Ii1I . Oo0Ooo
   if 33 - 33: I1Ii111 / iII111i . I1Ii111 % II111iiii
   if 52 - 52: I1ii11iIi11i
  ii = [ ]
  for IIIIiI1 in lisp_map_servers_list . values ( ) :
   if ( self . dns_name != IIIIiI1 . dns_name ) : continue
   OO0o = IIIIiI1 . map_server . print_address_no_iid ( )
   if ( OO0o in OO00000 ) : continue
   ii . append ( IIIIiI1 )
   if 1 - 1: II111iiii + I1ii11iIi11i * OoOoOO00 % ooOoO0o - iII111i % OoooooooOO
  for IIIIiI1 in ii : IIIIiI1 . delete_ms ( )
  if 77 - 77: iII111i + o0oOOo0O0Ooo
  if 60 - 60: I1ii11iIi11i
 def insert_ms ( self ) :
  ii1i1I1111ii = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ ii1i1I1111ii ] = self
  if 23 - 23: iII111i % I1IiiI % I1Ii111 * oO0o * I1IiiI
  if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
 def delete_ms ( self ) :
  ii1i1I1111ii = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( ii1i1I1111ii ) == False ) : return
  lisp_map_servers_list . pop ( ii1i1I1111ii )
  if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
  if 52 - 52: OoooooooOO
  if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
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
  if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
  if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 86 - 86: Oo0Ooo / OoO0O00
  if 78 - 78: I1IiiI * I1IiiI
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 13 - 13: oO0o
  if 43 - 43: oO0o / Ii1I % OOooOOo
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 45 - 45: II111iiii
  if 41 - 41: Ii1I / OOooOOo * Oo0Ooo . O0 - i11iIiiIii
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 77 - 77: o0oOOo0O0Ooo + I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
  if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 43 - 43: OOooOOo . O0
  if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
 def set_socket ( self , device ) :
  IiII1iiI = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  IiII1iiI . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   IiII1iiI . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   IiII1iiI . close ( )
   IiII1iiI = None
   if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
  self . raw_socket = IiII1iiI
  if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
  if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
 def set_bridge_socket ( self , device ) :
  IiII1iiI = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   IiII1iiI = IiII1iiI . bind ( ( device , 0 ) )
   self . bridge_socket = IiII1iiI
  except :
   return
   if 24 - 24: ooOoO0o % I1Ii111 + OoO0O00 * o0oOOo0O0Ooo % O0 - i11iIiiIii
   if 49 - 49: o0oOOo0O0Ooo / OoOoOO00 + iII111i
   if 85 - 85: I1IiiI - o0oOOo0O0Ooo
   if 86 - 86: II111iiii + Ii1I * Ii1I
class lisp_datetime ( ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
  if 86 - 86: Ii1I
 def valid_datetime ( self ) :
  oOoOOoo0OoO = self . datetime_name
  if ( oOoOOoo0OoO . find ( ":" ) == - 1 ) : return ( False )
  if ( oOoOOoo0OoO . find ( "-" ) == - 1 ) : return ( False )
  o00o0O00O0O , iiIIi11I111 , O0o0Oo0o0 , time = oOoOOoo0OoO [ 0 : 4 ] , oOoOOoo0OoO [ 5 : 7 ] , oOoOOoo0OoO [ 8 : 10 ] , oOoOOoo0OoO [ 11 : : ]
  if 24 - 24: O0 * Oo0Ooo * o0oOOo0O0Ooo
  if ( ( o00o0O00O0O + iiIIi11I111 + O0o0Oo0o0 ) . isdigit ( ) == False ) : return ( False )
  if ( iiIIi11I111 < "01" and iiIIi11I111 > "12" ) : return ( False )
  if ( O0o0Oo0o0 < "01" and O0o0Oo0o0 > "31" ) : return ( False )
  if 26 - 26: OoO0O00 * ooOoO0o - oO0o . I1IiiI % I1IiiI
  i1IiiIii , O0Oo000o00O , oOO = time . split ( ":" )
  if 46 - 46: OOooOOo * iIii1I11I1II1
  if ( ( i1IiiIii + O0Oo000o00O + oOO ) . isdigit ( ) == False ) : return ( False )
  if ( i1IiiIii < "00" and i1IiiIii > "23" ) : return ( False )
  if ( O0Oo000o00O < "00" and O0Oo000o00O > "59" ) : return ( False )
  if ( oOO < "00" and oOO > "59" ) : return ( False )
  return ( True )
  if 33 - 33: OoO0O00 * II111iiii / i1IIi
  if 93 - 93: I1Ii111 % I11i
 def parse_datetime ( self ) :
  oOoOOO0O0o = self . datetime_name
  oOoOOO0O0o = oOoOOO0O0o . replace ( "-" , "" )
  oOoOOO0O0o = oOoOOO0O0o . replace ( ":" , "" )
  self . datetime = int ( oOoOOO0O0o )
  if 15 - 15: oO0o
  if 72 - 72: O0 - IiII
 def now ( self ) :
  Oo0OO0000oooo = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  Oo0OO0000oooo = lisp_datetime ( Oo0OO0000oooo )
  return ( Oo0OO0000oooo )
  if 49 - 49: IiII - OOooOOo * OOooOOo . O0
  if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
  if 61 - 61: OoO0O00
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 100 - 100: OoOoOO00
  if 97 - 97: OoooooooOO
 def past ( self ) :
  return ( self . future ( ) == False )
  if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
  if 35 - 35: iII111i % OoO0O00 * O0
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 37 - 37: OOooOOo
  if 100 - 100: Oo0Ooo * I1IiiI . ooOoO0o
 def this_year ( self ) :
  OO0OO0 = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  Oo0OO0000oooo = str ( self . datetime ) [ 0 : 4 ]
  return ( Oo0OO0000oooo == OO0OO0 )
  if 10 - 10: OoooooooOO . I11i / I1Ii111 % i11iIiiIii % iIii1I11I1II1
  if 65 - 65: IiII % OOooOOo / o0oOOo0O0Ooo * II111iiii - oO0o
 def this_month ( self ) :
  OO0OO0 = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  Oo0OO0000oooo = str ( self . datetime ) [ 0 : 6 ]
  return ( Oo0OO0000oooo == OO0OO0 )
  if 38 - 38: I1Ii111 * o0oOOo0O0Ooo
  if 32 - 32: iII111i / Ii1I / I1Ii111 - OoOoOO00 / OOooOOo * OoO0O00
 def today ( self ) :
  OO0OO0 = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  Oo0OO0000oooo = str ( self . datetime ) [ 0 : 8 ]
  return ( Oo0OO0000oooo == OO0OO0 )
  if 32 - 32: I1ii11iIi11i + ooOoO0o . i1IIi * iIii1I11I1II1 - I1IiiI
  if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
  if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
  if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
  if 17 - 17: OOooOOo / i11iIiiIii - i11iIiiIii . II111iiii . ooOoO0o
  if 38 - 38: OOooOOo . OoooooooOO . II111iiii + OoO0O00 / oO0o . OoooooooOO
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
  if 100 - 100: OoO0O00
  if 36 - 36: oO0o + Ii1I - O0
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
  if 19 - 19: O0 + I1Ii111 . I1Ii111 * IiII * ooOoO0o + i1IIi
  if 51 - 51: ooOoO0o % OoOoOO00 % i1IIi / O0
 def match_policy_map_request ( self , mr , srloc ) :
  for ii111IIiI in self . match_clauses :
   III1I1Iii1 = ii111IIiI . source_eid
   ooOOO000 = mr . source_eid
   if ( III1I1Iii1 and ooOOO000 and ooOOO000 . is_more_specific ( III1I1Iii1 ) == False ) : continue
   if 11 - 11: OOooOOo . I1ii11iIi11i * OOooOOo * OoO0O00
   III1I1Iii1 = ii111IIiI . dest_eid
   ooOOO000 = mr . target_eid
   if ( III1I1Iii1 and ooOOO000 and ooOOO000 . is_more_specific ( III1I1Iii1 ) == False ) : continue
   if 11 - 11: I11i
   III1I1Iii1 = ii111IIiI . source_rloc
   ooOOO000 = srloc
   if ( III1I1Iii1 and ooOOO000 and ooOOO000 . is_more_specific ( III1I1Iii1 ) == False ) : continue
   I1111III111ii = ii111IIiI . datetime_lower
   OOo00OOo = ii111IIiI . datetime_upper
   if ( I1111III111ii and OOo00OOo and I1111III111ii . now_in_range ( OOo00OOo ) == False ) : continue
   return ( True )
   if 64 - 64: i1IIi / O0 - oO0o
  return ( False )
  if 7 - 7: IiII . IiII * Ii1I
  if 1 - 1: i11iIiiIii
 def set_policy_map_reply ( self ) :
  OOiIII1 = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( OOiIII1 ) : return ( None )
  if 20 - 20: o0oOOo0O0Ooo . I1Ii111 + O0
  oOo0o0 = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   oOo0o0 . rloc . copy_address ( self . set_rloc_address )
   IiiIIi1 = oOo0o0 . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( IiiIIi1 ) )
   if 99 - 99: O0 / IiII . oO0o
  if ( self . set_rloc_record_name ) :
   oOo0o0 . rloc_name = self . set_rloc_record_name
   oooO = blue ( oOo0o0 . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( oooO ) )
   if 18 - 18: OoooooooOO * OoO0O00 * I1Ii111
  if ( self . set_geo_name ) :
   oOo0o0 . geo_name = self . set_geo_name
   oooO = oOo0o0 . geo_name
   Iiii1 = "" if lisp_geo_list . has_key ( oooO ) else "(not configured)"
   if 75 - 75: I11i * ooOoO0o * Oo0Ooo . i1IIi . ooOoO0o . ooOoO0o
   lprint ( "Policy set-geo-name '{}' {}" . format ( oooO , Iiii1 ) )
   if 24 - 24: iIii1I11I1II1
  if ( self . set_elp_name ) :
   oOo0o0 . elp_name = self . set_elp_name
   oooO = oOo0o0 . elp_name
   Iiii1 = "" if lisp_elp_list . has_key ( oooO ) else "(not configured)"
   if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
   lprint ( "Policy set-elp-name '{}' {}" . format ( oooO , Iiii1 ) )
   if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
  if ( self . set_rle_name ) :
   oOo0o0 . rle_name = self . set_rle_name
   oooO = oOo0o0 . rle_name
   Iiii1 = "" if lisp_rle_list . has_key ( oooO ) else "(not configured)"
   if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
   lprint ( "Policy set-rle-name '{}' {}" . format ( oooO , Iiii1 ) )
   if 62 - 62: o0oOOo0O0Ooo
  if ( self . set_json_name ) :
   oOo0o0 . json_name = self . set_json_name
   oooO = oOo0o0 . json_name
   Iiii1 = "" if lisp_json_list . has_key ( oooO ) else "(not configured)"
   if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
   lprint ( "Policy set-json-name '{}' {}" . format ( oooO , Iiii1 ) )
   if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
  return ( oOo0o0 )
  if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
  if 84 - 84: OoOoOO00
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 80 - 80: oO0o
  if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
  if 92 - 92: iII111i
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  if 96 - 96: OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
  if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
 def add ( self , eid_prefix ) :
  O0000 = self . ttl
  iIiiIIi1i111iI = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( iIiiIIi1i111iI ) == False ) :
   lisp_pubsub_cache [ iIiiIIi1i111iI ] = { }
   if 92 - 92: I1Ii111 - IiII / IiII
  ooOo0ooo0o0 = lisp_pubsub_cache [ iIiiIIi1i111iI ]
  if 42 - 42: IiII
  iI1IiI1IIi11I = "Add"
  if ( ooOo0ooo0o0 . has_key ( self . xtr_id ) ) :
   iI1IiI1IIi11I = "Replace"
   del ( ooOo0ooo0o0 [ self . xtr_id ] )
   if 94 - 94: i1IIi . II111iiii * iII111i - I1ii11iIi11i
  ooOo0ooo0o0 [ self . xtr_id ] = self
  if 14 - 14: Oo0Ooo * Oo0Ooo . I11i . I1ii11iIi11i - o0oOOo0O0Ooo / i11iIiiIii
  iIiiIIi1i111iI = green ( iIiiIIi1i111iI , False )
  III1iii1 = red ( self . itr . print_address_no_iid ( ) , False )
  oooOOOO0oOo = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( iI1IiI1IIi11I , iIiiIIi1i111iI ,
 III1iii1 , oooOOOO0oOo , O0000 ) )
  if 67 - 67: ooOoO0o - Ii1I / I1IiiI * I1ii11iIi11i . oO0o
  if 41 - 41: I1Ii111
 def delete ( self , eid_prefix ) :
  iIiiIIi1i111iI = eid_prefix . print_prefix ( )
  III1iii1 = red ( self . itr . print_address_no_iid ( ) , False )
  oooOOOO0oOo = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( iIiiIIi1i111iI ) ) :
   ooOo0ooo0o0 = lisp_pubsub_cache [ iIiiIIi1i111iI ]
   if ( ooOo0ooo0o0 . has_key ( self . xtr_id ) ) :
    ooOo0ooo0o0 . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( iIiiIIi1i111iI ,
 III1iii1 , oooOOOO0oOo ) )
    if 42 - 42: ooOoO0o . O0 * i11iIiiIii - I1ii11iIi11i * OoOoOO00
    if 11 - 11: i1IIi - IiII . ooOoO0o + I1ii11iIi11i / I1IiiI - I1ii11iIi11i
    if 37 - 37: I11i % Oo0Ooo
    if 86 - 86: O0 * II111iiii
    if 75 - 75: iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % I1ii11iIi11i . II111iiii
    if 11 - 11: I1ii11iIi11i - I1ii11iIi11i . ooOoO0o * Oo0Ooo + I1Ii111
    if 59 - 59: iII111i - OOooOOo - OoO0O00 . I1IiiI % o0oOOo0O0Ooo + iII111i
    if 10 - 10: iIii1I11I1II1 - Ii1I
    if 84 - 84: iII111i
    if 21 - 21: i11iIiiIii
    if 30 - 30: OoO0O00 + OoooooooOO
    if 98 - 98: I1ii11iIi11i % I1IiiI
    if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
    if 66 - 66: IiII
    if 56 - 56: oO0o + OoooooooOO
    if 75 - 75: O0 % Ii1I
    if 47 - 47: OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
    if 23 - 23: iII111i / iIii1I11I1II1
    if 5 - 5: O0
    if 64 - 64: i1IIi * i1IIi . iII111i - O0 - oO0o % OoooooooOO
    if 14 - 14: Ii1I % OoO0O00 % I1Ii111 * O0
    if 8 - 8: I1IiiI - i11iIiiIii * I1IiiI
class lisp_trace ( ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 6 - 6: O0 - OoOoOO00 - i11iIiiIii / iII111i
  if 63 - 63: OOooOOo
 def print_trace ( self ) :
  Oo0o00O0ooO0 = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( Oo0o00O0ooO0 ) )
  if 94 - 94: o0oOOo0O0Ooo
  if 40 - 40: O0 / I1ii11iIi11i + I1ii11iIi11i + ooOoO0o / OoOoOO00
 def encode ( self ) :
  ooo0OOoo = socket . htonl ( 0x90000000 )
  IIii1i = struct . pack ( "II" , ooo0OOoo , 0 )
  IIii1i += struct . pack ( "Q" , self . nonce )
  IIii1i += json . dumps ( self . packet_json )
  return ( IIii1i )
  if 90 - 90: O0
  if 28 - 28: iIii1I11I1II1
 def decode ( self , packet ) :
  O00oO00oOO00O = "I"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( False )
  ooo0OOoo = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  ooo0OOoo = socket . ntohl ( ooo0OOoo )
  if ( ( ooo0OOoo & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 39 - 39: iIii1I11I1II1 % Ii1I + I1ii11iIi11i . I1ii11iIi11i
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( False )
  IiiIIi1 = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if 80 - 80: I1IiiI % I1ii11iIi11i
  IiiIIi1 = socket . ntohl ( IiiIIi1 )
  o00o0OOoooo0 = IiiIIi1 >> 24
  o0OOOO0O00000O = ( IiiIIi1 >> 16 ) & 0xff
  III = ( IiiIIi1 >> 8 ) & 0xff
  iiii1iiIii = IiiIIi1 & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( o00o0OOoooo0 , o0OOOO0O00000O , III , iiii1iiIii )
  self . local_port = str ( ooo0OOoo & 0xffff )
  if 9 - 9: OoOoOO00 + ooOoO0o + iIii1I11I1II1 + O0 * I11i * iIii1I11I1II1
  O00oO00oOO00O = "Q"
  ooOoooOoo0oO = struct . calcsize ( O00oO00oOO00O )
  if ( len ( packet ) < ooOoooOoo0oO ) : return ( False )
  self . nonce = struct . unpack ( O00oO00oOO00O , packet [ : ooOoooOoo0oO ] ) [ 0 ]
  packet = packet [ ooOoooOoo0oO : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 4 - 4: i1IIi % OoOoOO00
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 93 - 93: Oo0Ooo / o0oOOo0O0Ooo . iII111i / i11iIiiIii + I11i
  return ( True )
  if 94 - 94: IiII - OoO0O00 * iII111i . I1IiiI
  if 27 - 27: I11i / o0oOOo0O0Ooo / II111iiii
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 93 - 93: II111iiii - I11i
  if 17 - 17: i1IIi + O0 * ooOoO0o
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  oOo0o0 , IiI1iI1 = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( oOo0o0 == None ) :
   oOo0o0 , IiI1iI1 = rts_rloc . split ( ":" )
   IiI1iI1 = int ( IiI1iI1 )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( oOo0o0 , IiI1iI1 ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( oOo0o0 ,
 IiI1iI1 ) )
   if 53 - 53: IiII / II111iiii / oO0o % O0 / I1Ii111
   if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
  if ( lisp_socket == None ) :
   IiII1iiI = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   IiII1iiI . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   IiII1iiI . sendto ( packet , ( oOo0o0 , IiI1iI1 ) )
   IiII1iiI . close ( )
  else :
   lisp_socket . sendto ( packet , ( oOo0o0 , IiI1iI1 ) )
   if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
   if 45 - 45: OOooOOo - OOooOOo % iII111i - IiII . O0
   if 6 - 6: iIii1I11I1II1 * II111iiii / O0 % IiII - I1Ii111
 def packet_length ( self ) :
  o0oOo00 = 8 ; oo0Oo00OO0000 = 4 + 4 + 8
  return ( o0oOo00 + oo0Oo00OO0000 + len ( json . dumps ( self . packet_json ) ) )
  if 74 - 74: Ii1I - OoOoOO00 + i11iIiiIii - II111iiii - i11iIiiIii . ooOoO0o
  if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  ii1i1I1111ii = self . local_rloc + ":" + self . local_port
  i11II = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ ii1i1I1111ii ] = i11II
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( ii1i1I1111ii , i11II ) )
  if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
  if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  ii1i1I1111ii = local_rloc_and_port
  try : i11II = lisp_rtr_nat_trace_cache [ ii1i1I1111ii ]
  except : i11II = ( None , None )
  return ( i11II )
  if 78 - 78: i1IIi
  if 25 - 25: Ii1I * II111iiii / OoOoOO00
  if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
  if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
  if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
  if 15 - 15: i11iIiiIii
  if 85 - 85: I1Ii111 + iII111i - oO0o
  if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
  if 64 - 64: OoOoOO00
  if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
  if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
def lisp_get_map_server ( address ) :
 for IIIIiI1 in lisp_map_servers_list . values ( ) :
  if ( IIIIiI1 . map_server . is_exact_match ( address ) ) : return ( IIIIiI1 )
  if 71 - 71: ooOoO0o
 return ( None )
 if 35 - 35: OoOoOO00
 if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
 if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
 if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
 if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
 if 89 - 89: iIii1I11I1II1 . ooOoO0o
 if 82 - 82: OoOoOO00 - II111iiii . OoO0O00 * ooOoO0o
def lisp_get_any_map_server ( ) :
 for IIIIiI1 in lisp_map_servers_list . values ( ) : return ( IIIIiI1 )
 return ( None )
 if 78 - 78: OoOoOO00 % oO0o
 if 39 - 39: iIii1I11I1II1
 if 72 - 72: II111iiii + I1Ii111 / Ii1I * iIii1I11I1II1
 if 95 - 95: OoooooooOO + OOooOOo + II111iiii + IiII + OoO0O00
 if 86 - 86: II111iiii / iII111i - I1ii11iIi11i
 if 65 - 65: I1ii11iIi11i + OoOoOO00
 if 43 - 43: O0 + I11i % II111iiii
 if 56 - 56: IiII + Oo0Ooo . IiII % iIii1I11I1II1 % ooOoO0o % ooOoO0o
 if 70 - 70: ooOoO0o / i1IIi - I11i - i11iIiiIii
 if 79 - 79: OoO0O00 - OoooooooOO % iII111i . O0
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  IiiIIi1 = address . print_address ( )
  O0O0OOoO00 = None
  for ii1i1I1111ii in lisp_map_resolvers_list :
   if ( ii1i1I1111ii . find ( IiiIIi1 ) == - 1 ) : continue
   O0O0OOoO00 = lisp_map_resolvers_list [ ii1i1I1111ii ]
   if 93 - 93: I1Ii111
  return ( O0O0OOoO00 )
  if 3 - 3: OoO0O00 / IiII - oO0o / oO0o
  if 50 - 50: II111iiii + OoOoOO00
  if 17 - 17: ooOoO0o + I1ii11iIi11i
  if 34 - 34: Ii1I / II111iiii + OoOoOO00 . II111iiii + OoooooooOO * o0oOOo0O0Ooo
  if 48 - 48: O0
  if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
  if 84 - 84: i11iIiiIii . OoooooooOO
 if ( eid == "" ) :
  O00o00ooo0Ooo = ""
 elif ( eid == None ) :
  O00o00ooo0Ooo = "all"
 else :
  I1111I = lisp_db_for_lookups . lookup_cache ( eid , False )
  O00o00ooo0Ooo = "all" if I1111I == None else I1111I . use_mr_name
  if 80 - 80: oO0o . oO0o
  if 64 - 64: I1IiiI + oO0o . I1ii11iIi11i
 i1IiIii = None
 for O0O0OOoO00 in lisp_map_resolvers_list . values ( ) :
  if ( O00o00ooo0Ooo == "" ) : return ( O0O0OOoO00 )
  if ( O0O0OOoO00 . mr_name != O00o00ooo0Ooo ) : continue
  if ( i1IiIii == None or O0O0OOoO00 . last_used < i1IiIii . last_used ) : i1IiIii = O0O0OOoO00
  if 77 - 77: OoooooooOO / II111iiii + Ii1I * o0oOOo0O0Ooo . i11iIiiIii
 return ( i1IiIii )
 if 24 - 24: I11i + OoO0O00
 if 76 - 76: II111iiii - O0 / Oo0Ooo % OoOoOO00
 if 1 - 1: I1ii11iIi11i / iIii1I11I1II1 . Oo0Ooo + I1IiiI / Oo0Ooo
 if 62 - 62: oO0o * OoOoOO00 % iII111i * ooOoO0o . Oo0Ooo . i11iIiiIii
 if 60 - 60: iIii1I11I1II1 + O0
 if 96 - 96: iII111i . i1IIi % o0oOOo0O0Ooo * iIii1I11I1II1 - iII111i - OoooooooOO
 if 13 - 13: i1IIi
 if 68 - 68: I1ii11iIi11i . IiII + O0 % i1IIi + iIii1I11I1II1
def lisp_get_decent_map_resolver ( eid ) :
 ooo = lisp_get_decent_index ( eid )
 Ii1II1IiI = str ( ooo ) + "." + lisp_decent_dns_suffix
 if 97 - 97: iIii1I11I1II1 / OoooooooOO % I1Ii111 . II111iiii
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( Ii1II1IiI , False ) , eid . print_prefix ( ) ) )
 if 48 - 48: i1IIi / i1IIi / i11iIiiIii - IiII
 if 69 - 69: OOooOOo . I1IiiI
 i1IiIii = None
 for O0O0OOoO00 in lisp_map_resolvers_list . values ( ) :
  if ( Ii1II1IiI != O0O0OOoO00 . dns_name ) : continue
  if ( i1IiIii == None or O0O0OOoO00 . last_used < i1IiIii . last_used ) : i1IiIii = O0O0OOoO00
  if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
 return ( i1IiIii )
 if 22 - 22: iII111i % I11i % O0 - I11i
 if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
 if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
 if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
 if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
 if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
 if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
def lisp_ipv4_input ( packet ) :
 if 97 - 97: iIii1I11I1II1 * I1Ii111
 if 39 - 39: I1Ii111 . II111iiii
 if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
 if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
 if ( ord ( packet [ 9 ] ) == 2 ) : return ( [ True , packet ] )
 if 34 - 34: I1IiiI
 if 56 - 56: Ii1I
 if 71 - 71: O0 / i1IIi
 if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
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
   if 82 - 82: oO0o * i11iIiiIii % o0oOOo0O0Ooo % IiII - I11i - OoO0O00
   if 24 - 24: oO0o . II111iiii + OoO0O00 * I1ii11iIi11i / oO0o
   if 86 - 86: I1Ii111 + I1ii11iIi11i
   if 63 - 63: ooOoO0o - i11iIiiIii . o0oOOo0O0Ooo - i1IIi - IiII
   if 32 - 32: I1Ii111 / iIii1I11I1II1 + oO0o % I11i * OoooooooOO
   if 69 - 69: OOooOOo
   if 9 - 9: i11iIiiIii * Oo0Ooo
 O0000 = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( O0000 == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( O0000 == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 33 - 33: oO0o / ooOoO0o
  return ( [ False , None ] )
  if 92 - 92: O0 . Oo0Ooo - Ii1I * I1IiiI * Oo0Ooo * iII111i
  if 78 - 78: Ii1I * iIii1I11I1II1 - Ii1I - I1ii11iIi11i * I1ii11iIi11i
 O0000 -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , O0000 ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( [ False , packet ] )
 if 44 - 44: o0oOOo0O0Ooo
 if 1 - 1: OoooooooOO / i11iIiiIii . o0oOOo0O0Ooo
 if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
 if 12 - 12: Oo0Ooo . o0oOOo0O0Ooo - i1IIi - oO0o % IiII . I11i
 if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
 if 64 - 64: O0 - iII111i
 if 82 - 82: O0
def lisp_ipv6_input ( packet ) :
 oO0o0 = packet . inner_dest
 packet = packet . packet
 if 37 - 37: I1Ii111
 if 98 - 98: iII111i - OoOoOO00 / I1Ii111 . OOooOOo - OOooOOo - ooOoO0o
 if 84 - 84: OOooOOo * ooOoO0o / O0
 if 96 - 96: I11i . I11i % II111iiii
 if 14 - 14: iII111i / OoooooooOO
 O0000 = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( O0000 == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( O0000 == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
  return ( None )
  if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
  if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
  if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
  if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
  if 11 - 11: I1IiiI
 if ( oO0o0 . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
  if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
 O0000 -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , O0000 ) + packet [ 8 : : ]
 return ( packet )
 if 91 - 91: OoO0O00
 if 8 - 8: oO0o
 if 96 - 96: IiII
 if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
 if 26 - 26: o0oOOo0O0Ooo . i1IIi
 if 62 - 62: IiII * I1ii11iIi11i % iIii1I11I1II1 / II111iiii - OoO0O00
 if 52 - 52: iII111i . I11i - I11i + oO0o + iIii1I11I1II1
 if 83 - 83: I11i * iIii1I11I1II1 + OoOoOO00
def lisp_mac_input ( packet ) :
 return ( packet )
 if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
 if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
 if 100 - 100: II111iiii / Oo0Ooo / iII111i / OOooOOo
 if 100 - 100: iIii1I11I1II1
 if 50 - 50: I1Ii111 / ooOoO0o * I11i
 if 53 - 53: II111iiii . IiII
 if 5 - 5: i1IIi % IiII
 if 16 - 16: ooOoO0o - iII111i % Ii1I . OoOoOO00
 if 56 - 56: i11iIiiIii % i11iIiiIii % OoooooooOO . Ii1I . iII111i + I11i
def lisp_rate_limit_map_request ( source , dest ) :
 if ( lisp_last_map_request_sent == None ) : return ( False )
 OO0OO0 = lisp_get_timestamp ( )
 oO000o0Oo00 = OO0OO0 - lisp_last_map_request_sent
 O0O = ( oO000o0Oo00 < LISP_MAP_REQUEST_RATE_LIMIT )
 if 64 - 64: O0
 if ( O0O ) :
  if ( source != None ) : source = source . print_address ( )
  dest = dest . print_address ( )
  dprint ( "Rate-limiting Map-Request for {} -> {}" . format ( source , dest ) )
  if 37 - 37: o0oOOo0O0Ooo / O0
 return ( O0O )
 if 58 - 58: I1Ii111 + OoooooooOO + iIii1I11I1II1
 if 13 - 13: o0oOOo0O0Ooo . I11i / O0
 if 39 - 39: I11i + oO0o + ooOoO0o % ooOoO0o - I1IiiI % Oo0Ooo
 if 9 - 9: IiII / iII111i * II111iiii + O0 % Oo0Ooo / i1IIi
 if 45 - 45: OoOoOO00 % i11iIiiIii . I1IiiI - O0 * i1IIi - I1IiiI
 if 48 - 48: IiII / iIii1I11I1II1
 if 20 - 20: oO0o / OoooooooOO
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ) :
 global lisp_last_map_request_sent
 if 95 - 95: Oo0Ooo . i11iIiiIii
 if 50 - 50: iII111i . i11iIiiIii - i1IIi
 if 24 - 24: i11iIiiIii % iII111i . oO0o
 if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
 if 34 - 34: I1ii11iIi11i % ooOoO0o / II111iiii * O0 % OOooOOo
 if 9 - 9: I1ii11iIi11i / I1ii11iIi11i - OOooOOo . iIii1I11I1II1
 Ii1IiII = OoOoooO0O00Oo = None
 if ( rloc ) :
  Ii1IiII = rloc . rloc
  OoOoooO0O00Oo = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 93 - 93: i1IIi / Ii1I / II111iiii - OoooooooOO / II111iiii % II111iiii
  if 38 - 38: I1ii11iIi11i + I1Ii111 / IiII % oO0o
  if 42 - 42: ooOoO0o
  if 62 - 62: OOooOOo + OoOoOO00 . iII111i
  if 26 - 26: OOooOOo
 OoOoOoo0Ooo0O0o , II1i1i1 , OoO0o0OOOO = lisp_myrlocs
 if ( OoOoOoo0Ooo0O0o == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 2 - 2: I11i % I1Ii111 - OoO0O00 % OoO0O00 % OOooOOo - OoO0O00
 if ( II1i1i1 == None and Ii1IiII != None and Ii1IiII . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
  if 59 - 59: iII111i
 I1IIIiii1 = lisp_map_request ( )
 I1IIIiii1 . record_count = 1
 I1IIIiii1 . nonce = lisp_get_control_nonce ( )
 I1IIIiii1 . rloc_probe = ( Ii1IiII != None )
 if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
 if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + OOooOOo
 if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
 if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
 if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
 if 77 - 77: ooOoO0o % I1IiiI
 if ( rloc ) : rloc . last_rloc_probe_nonce = I1IIIiii1 . nonce
 if 26 - 26: o0oOOo0O0Ooo
 OOoo00o0 = deid . is_multicast_address ( )
 if ( OOoo00o0 ) :
  I1IIIiii1 . target_eid = seid
  I1IIIiii1 . target_group = deid
 else :
  I1IIIiii1 . target_eid = deid
  if 72 - 72: I1IiiI
  if 90 - 90: ooOoO0o
  if 67 - 67: iIii1I11I1II1 + i1IIi * I1IiiI * OoooooooOO
  if 23 - 23: IiII
  if 32 - 32: OoOoOO00 - iII111i % oO0o / I1ii11iIi11i - o0oOOo0O0Ooo
  if 52 - 52: Ii1I / OoooooooOO % i11iIiiIii + iII111i
  if 59 - 59: Ii1I / o0oOOo0O0Ooo / oO0o + iII111i * I1ii11iIi11i - o0oOOo0O0Ooo
  if 70 - 70: O0 / I1ii11iIi11i + ooOoO0o . OoO0O00 - OoO0O00 / i11iIiiIii
  if 1 - 1: iIii1I11I1II1 % I1ii11iIi11i
 if ( I1IIIiii1 . rloc_probe == False ) :
  I1111I = lisp_get_signature_eid ( )
  if ( I1111I ) :
   I1IIIiii1 . signature_eid . copy_address ( I1111I . eid )
   I1IIIiii1 . privkey_filename = "./lisp-sig.pem"
   if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
   if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
   if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
   if 67 - 67: i1IIi * I1Ii111 * O0
   if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
   if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
 if ( seid == None or OOoo00o0 ) :
  I1IIIiii1 . source_eid . afi = LISP_AFI_NONE
 else :
  I1IIIiii1 . source_eid = seid
  if 18 - 18: I1ii11iIi11i - i1IIi - IiII * II111iiii % I1Ii111 . II111iiii
  if 80 - 80: oO0o + OoO0O00 + o0oOOo0O0Ooo . OoOoOO00
  if 75 - 75: i11iIiiIii
  if 58 - 58: iII111i
  if 48 - 48: OoO0O00 * OOooOOo / iII111i
  if 90 - 90: I1IiiI * i11iIiiIii . OOooOOo / o0oOOo0O0Ooo
  if 82 - 82: Oo0Ooo
  if 50 - 50: I1Ii111 * OOooOOo * OoOoOO00 / OoooooooOO % iII111i
  if 80 - 80: I1Ii111
  if 35 - 35: Ii1I . O0 % i11iIiiIii * oO0o - OoooooooOO
  if 87 - 87: iII111i * ooOoO0o - OOooOOo . O0
  if 20 - 20: OoOoOO00 - IiII
 if ( Ii1IiII != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( Ii1IiII . is_private_address ( ) == False ) :
   OoOoOoo0Ooo0O0o = lisp_get_any_translated_rloc ( )
   if 9 - 9: O0 . I11i % I1ii11iIi11i * oO0o - I1Ii111 - i1IIi
  if ( OoOoOoo0Ooo0O0o == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 66 - 66: II111iiii / Oo0Ooo
   if 93 - 93: iII111i + I11i * OoooooooOO . OoO0O00
   if 40 - 40: ooOoO0o * I1Ii111 + iII111i
   if 52 - 52: iII111i % I11i
   if 95 - 95: IiII + Ii1I / OoO0O00 - iII111i / I1IiiI
   if 27 - 27: Oo0Ooo + i1IIi + i11iIiiIii . OoO0O00 . OoO0O00
   if 56 - 56: I1Ii111 / OoO0O00 + o0oOOo0O0Ooo . OoooooooOO * Oo0Ooo
   if 14 - 14: OoO0O00
 if ( Ii1IiII == None or Ii1IiII . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and Ii1IiII == None ) :
   IiIi11I = lisp_get_any_translated_rloc ( )
   if ( IiIi11I != None ) : OoOoOoo0Ooo0O0o = IiIi11I
   if 65 - 65: IiII + I1ii11iIi11i / iII111i / I1IiiI + Ii1I
  I1IIIiii1 . itr_rlocs . append ( OoOoOoo0Ooo0O0o )
  if 88 - 88: IiII % iIii1I11I1II1
 if ( Ii1IiII == None or Ii1IiII . is_ipv6 ( ) ) :
  if ( II1i1i1 == None or II1i1i1 . is_ipv6_link_local ( ) ) :
   II1i1i1 = None
  else :
   I1IIIiii1 . itr_rloc_count = 1 if ( Ii1IiII == None ) else 0
   I1IIIiii1 . itr_rlocs . append ( II1i1i1 )
   if 3 - 3: ooOoO0o / I1Ii111 % iIii1I11I1II1 % I11i * oO0o / iIii1I11I1II1
   if 75 - 75: i11iIiiIii . iII111i
   if 68 - 68: OOooOOo . I1ii11iIi11i % I1ii11iIi11i . i11iIiiIii
   if 45 - 45: oO0o % I1ii11iIi11i * I1Ii111
   if 21 - 21: O0 + i11iIiiIii
   if 72 - 72: OoOoOO00 * OoooooooOO % O0 / I1ii11iIi11i % Ii1I - I11i
   if 65 - 65: iIii1I11I1II1 + II111iiii * OoO0O00 * i11iIiiIii / IiII
   if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
   if 52 - 52: II111iiii * o0oOOo0O0Ooo
 if ( Ii1IiII != None and I1IIIiii1 . itr_rlocs != [ ] ) :
  iII1II1iI = I1IIIiii1 . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   iII1II1iI = OoOoOoo0Ooo0O0o
  elif ( deid . is_ipv6 ( ) ) :
   iII1II1iI = II1i1i1
  else :
   iII1II1iI = OoOoOoo0Ooo0O0o
   if 95 - 95: I1Ii111 - OoooooooOO
   if 99 - 99: OoooooooOO % IiII . I11i + OoooooooOO
   if 57 - 57: Ii1I / I1IiiI * i1IIi
   if 21 - 21: I11i . O0 * OoooooooOO + ooOoO0o * oO0o % i11iIiiIii
   if 30 - 30: ooOoO0o * I1Ii111 + OoO0O00
   if 30 - 30: Ii1I / iII111i * Ii1I
 IIii1i = I1IIIiii1 . encode ( Ii1IiII , OoOoooO0O00Oo )
 I1IIIiii1 . print_map_request ( )
 if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
 if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
 if 71 - 71: i1IIi % O0 % ooOoO0o
 if 24 - 24: O0
 if 88 - 88: OoooooooOO / Oo0Ooo / oO0o
 if 99 - 99: I1Ii111 % OoOoOO00 % IiII - Ii1I
 if ( Ii1IiII != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   iIIIIiI = lisp_get_nat_info ( Ii1IiII , rloc . rloc_name )
   if 79 - 79: ooOoO0o + Oo0Ooo
   if 80 - 80: OoOoOO00 % OoO0O00 . OoO0O00 * OoO0O00 * O0
   if 18 - 18: II111iiii . o0oOOo0O0Ooo + OoO0O00
   if 69 - 69: OoO0O00 . ooOoO0o * ooOoO0o * iIii1I11I1II1
   if ( iIIIIiI == None ) :
    i11iII1IiI = rloc . rloc . print_address_no_iid ( )
    i11ii = "gleaned-{}" . format ( i11iII1IiI )
    III1I1Iii1 = rloc . translated_port
    iIIIIiI = lisp_nat_info ( i11iII1IiI , i11ii , III1I1Iii1 )
    if 8 - 8: iII111i . oO0o . OOooOOo + iII111i . Ii1I
   lisp_encapsulate_rloc_probe ( lisp_sockets , Ii1IiII , iIIIIiI ,
 IIii1i )
   return
   if 46 - 46: OoO0O00
   if 21 - 21: iIii1I11I1II1 - iII111i
  oo0o00OO = Ii1IiII . print_address_no_iid ( )
  oO0o0 = lisp_convert_4to6 ( oo0o00OO )
  lisp_send ( lisp_sockets , oO0o0 , LISP_CTRL_PORT , IIii1i )
  return
  if 15 - 15: O0 + iII111i + i11iIiiIii
  if 31 - 31: iIii1I11I1II1 * iIii1I11I1II1 . I11i
  if 52 - 52: i11iIiiIii / oO0o / IiII
  if 84 - 84: I11i . oO0o + ooOoO0o
  if 75 - 75: I1Ii111
  if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
 IiI1III1ii = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  O0O0OOoO00 = lisp_get_decent_map_resolver ( deid )
 else :
  O0O0OOoO00 = lisp_get_map_resolver ( None , IiI1III1ii )
  if 9 - 9: Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 . OoOoOO00 % I1IiiI
 if ( O0O0OOoO00 == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 66 - 66: Ii1I - ooOoO0o % OoO0O00
  return
  if 63 - 63: OoooooooOO * iII111i % ooOoO0o
 O0O0OOoO00 . last_used = lisp_get_timestamp ( )
 O0O0OOoO00 . map_requests_sent += 1
 if ( O0O0OOoO00 . last_nonce == 0 ) : O0O0OOoO00 . last_nonce = I1IIIiii1 . nonce
 if 17 - 17: OoO0O00 % II111iiii . i1IIi . OOooOOo
 if 49 - 49: II111iiii / OoOoOO00 * IiII % OoO0O00
 if 77 - 77: OoOoOO00 + OOooOOo % o0oOOo0O0Ooo
 if 3 - 3: ooOoO0o / i1IIi
 if ( seid == None ) : seid = iII1II1iI
 lisp_send_ecm ( lisp_sockets , IIii1i , seid , lisp_ephem_port , deid ,
 O0O0OOoO00 . map_resolver )
 if 71 - 71: Ii1I + oO0o % IiII
 if 15 - 15: ooOoO0o . Oo0Ooo
 if 42 - 42: OOooOOo . i11iIiiIii % O0 - OoO0O00
 if 34 - 34: OOooOOo % oO0o * OOooOOo * iIii1I11I1II1
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 18 - 18: I1IiiI / I11i
 if 64 - 64: I11i * i11iIiiIii
 if 16 - 16: I1Ii111 * II111iiii * I1Ii111 . o0oOOo0O0Ooo
 if 96 - 96: ooOoO0o - o0oOOo0O0Ooo % O0 * Ii1I . OoOoOO00
 O0O0OOoO00 . resolve_dns_name ( )
 return
 if 80 - 80: I1IiiI
 if 31 - 31: I1Ii111 + o0oOOo0O0Ooo . I1IiiI + I11i . oO0o
 if 50 - 50: Ii1I . OOooOOo
 if 84 - 84: OoOoOO00 * OoO0O00 + I1IiiI
 if 38 - 38: OoooooooOO % I1IiiI
 if 80 - 80: iII111i / O0 % OoooooooOO / Oo0Ooo
 if 75 - 75: ooOoO0o
 if 72 - 72: oO0o . OoooooooOO % ooOoO0o % OoO0O00 * oO0o * OoO0O00
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 14 - 14: I11i / I11i
 if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
 if 93 - 93: oO0o / ooOoO0o - I1Ii111
 if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
 iiIii1i = lisp_info ( )
 iiIii1i . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : iiIii1i . hostname += "-" + device_name
 if 4 - 4: I1Ii111
 oo0o00OO = dest . print_address_no_iid ( )
 if 15 - 15: I11i % I11i / iIii1I11I1II1 - i11iIiiIii / i1IIi
 if 9 - 9: OoooooooOO
 if 71 - 71: Ii1I
 if 59 - 59: i1IIi * ooOoO0o . iIii1I11I1II1
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
 iiII11iiiIII = False
 if ( device_name ) :
  iI1IiI1I1i = lisp_get_host_route_next_hop ( oo0o00OO )
  if 69 - 69: OoO0O00 / oO0o * I11i
  if 84 - 84: oO0o % ooOoO0o % I11i
  if 58 - 58: I11i
  if 93 - 93: I1IiiI
  if 62 - 62: i11iIiiIii + iIii1I11I1II1 / iII111i * iIii1I11I1II1 % I11i % O0
  if 10 - 10: OoOoOO00 . i1IIi . OoooooooOO * I1Ii111 + oO0o + OoO0O00
  if 66 - 66: i11iIiiIii + O0 * ooOoO0o - I1Ii111 - OOooOOo . IiII
  if 62 - 62: II111iiii / I1IiiI * iIii1I11I1II1
  if 85 - 85: II111iiii * Ii1I * O0
  if ( port == LISP_CTRL_PORT and iI1IiI1I1i != None ) :
   while ( True ) :
    time . sleep ( .01 )
    iI1IiI1I1i = lisp_get_host_route_next_hop ( oo0o00OO )
    if ( iI1IiI1I1i == None ) : break
    if 81 - 81: O0
    if 24 - 24: OoOoOO00 + I1IiiI - OOooOOo - ooOoO0o
    if 65 - 65: II111iiii - oO0o
  iIIII11 = lisp_get_default_route_next_hops ( )
  for OoO0o0OOOO , IiIiIi1i11II in iIIII11 :
   if ( OoO0o0OOOO != device_name ) : continue
   if 19 - 19: I1Ii111 / I1Ii111 - i1IIi
   if 99 - 99: O0
   if 37 - 37: iIii1I11I1II1 / I1Ii111 + OoO0O00
   if 85 - 85: ooOoO0o / I1IiiI
   if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
   if 99 - 99: i11iIiiIii - I1ii11iIi11i
   if ( iI1IiI1I1i != IiIiIi1i11II ) :
    if ( iI1IiI1I1i != None ) :
     lisp_install_host_route ( oo0o00OO , iI1IiI1I1i , False )
     if 64 - 64: IiII . OoOoOO00 . Oo0Ooo . I1Ii111 / I11i / Ii1I
    lisp_install_host_route ( oo0o00OO , IiIiIi1i11II , True )
    iiII11iiiIII = True
    if 95 - 95: iIii1I11I1II1 . Ii1I % oO0o - I11i % IiII
   break
   if 42 - 42: OoOoOO00 + oO0o * i1IIi + i11iIiiIii
   if 25 - 25: Ii1I - Ii1I - I1ii11iIi11i / i1IIi . OoOoOO00 % Oo0Ooo
   if 76 - 76: I1Ii111 / OoOoOO00
   if 61 - 61: Oo0Ooo . i1IIi
   if 78 - 78: i11iIiiIii
   if 20 - 20: Ii1I
 IIii1i = iiIii1i . encode ( )
 iiIii1i . print_info ( )
 if 100 - 100: OoooooooOO . I1Ii111
 if 32 - 32: iIii1I11I1II1 . iIii1I11I1II1 % II111iiii / Oo0Ooo . iIii1I11I1II1 . O0
 if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
 if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
 OOo0oOoOo = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 OOo0oOoOo = bold ( OOo0oOoOo , False )
 III1I1Iii1 = bold ( "{}" . format ( port ) , False )
 OO0o = red ( oo0o00OO , False )
 ooOo = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( ooOo , OO0o , III1I1Iii1 , OOo0oOoOo ) )
 if 87 - 87: ooOoO0o * II111iiii * O0 % I1IiiI
 if 69 - 69: ooOoO0o . OoooooooOO
 if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
 if 88 - 88: i1IIi - OoOoOO00
 if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
 if 7 - 7: Ii1I / iIii1I11I1II1
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , IIii1i )
 else :
  Ii1I1i1IiiI = lisp_data_header ( )
  Ii1I1i1IiiI . instance_id ( 0xffffff )
  Ii1I1i1IiiI = Ii1I1i1IiiI . encode ( )
  if ( Ii1I1i1IiiI ) :
   IIii1i = Ii1I1i1IiiI + IIii1i
   if 36 - 36: iIii1I11I1II1 % i11iIiiIii
   if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
   if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
   if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
   if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
   if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
   if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
   if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
   if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , IIii1i )
   if 38 - 38: IiII
   if 78 - 78: Oo0Ooo * I1ii11iIi11i % OOooOOo / Oo0Ooo + I1ii11iIi11i * IiII
   if 2 - 2: Oo0Ooo - OoOoOO00
   if 22 - 22: OoO0O00 - oO0o - O0
   if 49 - 49: iIii1I11I1II1 + I1Ii111 / i11iIiiIii
   if 62 - 62: ooOoO0o . I1IiiI * i11iIiiIii
   if 2 - 2: i11iIiiIii
 if ( iiII11iiiIII ) :
  lisp_install_host_route ( oo0o00OO , None , False )
  if ( iI1IiI1I1i != None ) : lisp_install_host_route ( oo0o00OO , iI1IiI1I1i , True )
  if 86 - 86: I1Ii111 + o0oOOo0O0Ooo
 return
 if 17 - 17: iIii1I11I1II1
 if 32 - 32: IiII - OoOoOO00
 if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
 if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
 if 83 - 83: OoO0O00 . I11i * I1ii11iIi11i - II111iiii
 if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
 if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 16 - 16: Oo0Ooo
 if 24 - 24: o0oOOo0O0Ooo . OoOoOO00
 if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
 iiIii1i = lisp_info ( )
 packet = iiIii1i . decode ( packet )
 if ( packet == None ) : return
 iiIii1i . print_info ( )
 if 96 - 96: I1IiiI . oO0o % O0
 if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
 if 87 - 87: OoooooooOO
 if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
 if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
 iiIii1i . info_reply = True
 iiIii1i . global_etr_rloc . store_address ( addr_str )
 iiIii1i . etr_port = sport
 if 23 - 23: o0oOOo0O0Ooo . o0oOOo0O0Ooo - iIii1I11I1II1 / o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + I1Ii111 . I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
 if 2 - 2: oO0o % iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
 if 45 - 45: II111iiii . iII111i
 if 55 - 55: ooOoO0o / iII111i / O0
 if ( iiIii1i . hostname != None ) :
  iiIii1i . private_etr_rloc . afi = LISP_AFI_NAME
  iiIii1i . private_etr_rloc . store_address ( iiIii1i . hostname )
  if 98 - 98: O0 % iII111i + II111iiii
  if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
 if ( rtr_list != None ) : iiIii1i . rtr_list = rtr_list
 packet = iiIii1i . encode ( )
 iiIii1i . print_info ( )
 if 23 - 23: iIii1I11I1II1 + oO0o . oO0o / o0oOOo0O0Ooo
 if 77 - 77: i1IIi * o0oOOo0O0Ooo * IiII
 if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
 if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
 if 36 - 36: O0
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 oO0o0 = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , oO0o0 , sport , packet )
 if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
 if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
 if 21 - 21: i1IIi * iII111i + OoO0O00
 if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
 if 85 - 85: OoooooooOO
 O0o0O00O0oo00 = lisp_info_source ( iiIii1i . hostname , addr_str , sport )
 O0o0O00O0oo00 . cache_address_for_info_source ( )
 return
 if 73 - 73: ooOoO0o * iII111i % O0
 if 46 - 46: OoOoOO00 + OoooooooOO * OOooOOo
 if 52 - 52: II111iiii . Oo0Ooo
 if 14 - 14: I11i
 if 67 - 67: OoOoOO00
 if 50 - 50: Oo0Ooo
 if 80 - 80: OoOoOO00 * OoO0O00 + i11iIiiIii + O0 + II111iiii
 if 13 - 13: OOooOOo / O0
def lisp_get_signature_eid ( ) :
 for I1111I in lisp_db_list :
  if ( I1111I . signature_eid ) : return ( I1111I )
  if 19 - 19: iIii1I11I1II1 + IiII * I11i * II111iiii + o0oOOo0O0Ooo + i11iIiiIii
 return ( None )
 if 69 - 69: iIii1I11I1II1 . II111iiii
 if 36 - 36: I1IiiI * i1IIi + OoOoOO00
 if 63 - 63: OoOoOO00 - iII111i
 if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
 if 82 - 82: iIii1I11I1II1 / OOooOOo
 if 7 - 7: OoooooooOO
 if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
 if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
def lisp_get_any_translated_port ( ) :
 for I1111I in lisp_db_list :
  for oo0OOOoO0OoO in I1111I . rloc_set :
   if ( oo0OOOoO0OoO . translated_rloc . is_null ( ) ) : continue
   return ( oo0OOOoO0OoO . translated_port )
   if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
   if 1 - 1: Ii1I . Ii1I % II111iiii + I11i + OoOoOO00
 return ( None )
 if 52 - 52: OoooooooOO - OoO0O00
 if 24 - 24: iII111i / Oo0Ooo - I1ii11iIi11i + o0oOOo0O0Ooo
 if 44 - 44: OoOoOO00 + I1IiiI . I1ii11iIi11i / i1IIi + II111iiii . Oo0Ooo
 if 39 - 39: o0oOOo0O0Ooo
 if 64 - 64: oO0o - i11iIiiIii
 if 62 - 62: OoooooooOO - OoooooooOO / OoO0O00 - II111iiii . iIii1I11I1II1
 if 2 - 2: O0 + o0oOOo0O0Ooo % OOooOOo . ooOoO0o % i1IIi
 if 21 - 21: OoOoOO00 / OoooooooOO + I1Ii111 - IiII
 if 62 - 62: Oo0Ooo % iII111i + OoooooooOO - I1ii11iIi11i % iII111i % iIii1I11I1II1
def lisp_get_any_translated_rloc ( ) :
 for I1111I in lisp_db_list :
  for oo0OOOoO0OoO in I1111I . rloc_set :
   if ( oo0OOOoO0OoO . translated_rloc . is_null ( ) ) : continue
   return ( oo0OOOoO0OoO . translated_rloc )
   if 54 - 54: IiII + OoOoOO00 / II111iiii % i11iIiiIii . I1Ii111
   if 69 - 69: i1IIi + ooOoO0o + Ii1I
 return ( None )
 if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
 if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
 if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
 if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
 if 8 - 8: i1IIi
 if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
 if 97 - 97: OoooooooOO % ooOoO0o . I1Ii111 / iII111i
def lisp_get_all_translated_rlocs ( ) :
 OooooO0 = [ ]
 for I1111I in lisp_db_list :
  for oo0OOOoO0OoO in I1111I . rloc_set :
   if ( oo0OOOoO0OoO . is_rloc_translated ( ) == False ) : continue
   IiiIIi1 = oo0OOOoO0OoO . translated_rloc . print_address_no_iid ( )
   OooooO0 . append ( IiiIIi1 )
   if 36 - 36: iII111i + oO0o / I1Ii111
   if 94 - 94: iIii1I11I1II1 - IiII . i11iIiiIii
 return ( OooooO0 )
 if 88 - 88: I1IiiI / i11iIiiIii * OOooOOo
 if 3 - 3: oO0o / o0oOOo0O0Ooo - OOooOOo . OoOoOO00 * I1Ii111
 if 61 - 61: OOooOOo + OoooooooOO
 if 17 - 17: I1Ii111 / OOooOOo . i11iIiiIii - I11i
 if 7 - 7: I1Ii111 + ooOoO0o % o0oOOo0O0Ooo
 if 53 - 53: i1IIi / iII111i % Ii1I % OoooooooOO
 if 63 - 63: OOooOOo + I1ii11iIi11i . i1IIi . Ii1I - I1ii11iIi11i * o0oOOo0O0Ooo
 if 79 - 79: ooOoO0o - O0
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 ooO00Oo0o0OOo = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 20 - 20: OOooOOo
 ii1iiiiI111111II = { }
 for oOo0o0 in rtr_list :
  if ( oOo0o0 == None ) : continue
  IiiIIi1 = rtr_list [ oOo0o0 ]
  if ( ooO00Oo0o0OOo and IiiIIi1 . is_private_address ( ) ) : continue
  ii1iiiiI111111II [ oOo0o0 ] = IiiIIi1
  if 24 - 24: OOooOOo / OOooOOo + I11i / iII111i . oO0o - iII111i
 rtr_list = ii1iiiiI111111II
 if 59 - 59: I1ii11iIi11i % II111iiii - i11iIiiIii - I1Ii111
 iii11I = [ ]
 for O000oOOoOOO in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( O000oOOoOOO == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 6 - 6: OoOoOO00 + o0oOOo0O0Ooo / O0
  if 84 - 84: ooOoO0o - o0oOOo0O0Ooo * iIii1I11I1II1 * iIii1I11I1II1
  if 30 - 30: i1IIi + OoOoOO00 - I1ii11iIi11i % i1IIi
  if 2 - 2: i11iIiiIii + i1IIi
  if 1 - 1: i11iIiiIii + iIii1I11I1II1 / I11i * OoOoOO00 - OoOoOO00 % IiII
  oOoOo0 = lisp_address ( O000oOOoOOO , "" , 0 , iid )
  oOoOo0 . make_default_route ( oOoOo0 )
  O0oOO0OOO = lisp_map_cache . lookup_cache ( oOoOo0 , True )
  if ( O0oOO0OOO ) :
   if ( O0oOO0OOO . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( O0oOO0OOO . print_eid_tuple ( ) , False ) ) )
    if 68 - 68: O0 . OoooooooOO
   elif ( O0oOO0OOO . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
   O0oOO0OOO . delete_cache ( )
   if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
   if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
  iii11I . append ( [ oOoOo0 , "" ] )
  if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
  if 37 - 37: I1ii11iIi11i * IiII
  if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
  if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
  oOooO00OOoO = lisp_address ( O000oOOoOOO , "" , 0 , iid )
  oOooO00OOoO . make_default_multicast_route ( oOooO00OOoO )
  Ii11I1Ii1 = lisp_map_cache . lookup_cache ( oOooO00OOoO , True )
  if ( Ii11I1Ii1 ) : Ii11I1Ii1 = Ii11I1Ii1 . source_cache . lookup_cache ( oOoOo0 , True )
  if ( Ii11I1Ii1 ) : Ii11I1Ii1 . delete_cache ( )
  if 46 - 46: OoooooooOO * OoO0O00 . I1Ii111
  iii11I . append ( [ oOoOo0 , oOooO00OOoO ] )
  if 95 - 95: ooOoO0o . I1ii11iIi11i . ooOoO0o / I1IiiI * OoOoOO00 . O0
 if ( len ( iii11I ) == 0 ) : return
 if 78 - 78: oO0o
 if 33 - 33: oO0o + i1IIi
 if 32 - 32: iIii1I11I1II1
 if 71 - 71: Ii1I * I1IiiI
 iI1111Ii1I = [ ]
 for ooOo in rtr_list :
  ooooO = rtr_list [ ooOo ]
  oo0OOOoO0OoO = lisp_rloc ( )
  oo0OOOoO0OoO . rloc . copy_address ( ooooO )
  oo0OOOoO0OoO . priority = 254
  oo0OOOoO0OoO . mpriority = 255
  oo0OOOoO0OoO . rloc_name = "RTR"
  iI1111Ii1I . append ( oo0OOOoO0OoO )
  if 49 - 49: IiII / OoOoOO00 / O0 * i11iIiiIii
  if 47 - 47: i11iIiiIii + iII111i + i11iIiiIii
 for oOoOo0 in iii11I :
  O0oOO0OOO = lisp_mapping ( oOoOo0 [ 0 ] , oOoOo0 [ 1 ] , iI1111Ii1I )
  O0oOO0OOO . mapping_source = map_resolver
  O0oOO0OOO . map_cache_ttl = LISP_MR_TTL * 60
  O0oOO0OOO . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( O0oOO0OOO . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 66 - 66: o0oOOo0O0Ooo . I1IiiI + OoooooooOO . iII111i / OoooooooOO - IiII
  iI1111Ii1I = copy . deepcopy ( iI1111Ii1I )
  if 47 - 47: o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
 return
 if 34 - 34: I11i / o0oOOo0O0Ooo * OOooOOo * OOooOOo
 if 89 - 89: I1ii11iIi11i . OoooooooOO
 if 61 - 61: i1IIi + i11iIiiIii
 if 59 - 59: i11iIiiIii * OOooOOo + i1IIi * iIii1I11I1II1 + I11i
 if 97 - 97: OoO0O00 - I11i . OoooooooOO
 if 58 - 58: I1ii11iIi11i / II111iiii / i11iIiiIii
 if 27 - 27: iIii1I11I1II1 - O0 + OoOoOO00
 if 28 - 28: oO0o . IiII * iII111i % Oo0Ooo - OoO0O00 / I11i
 if 67 - 67: i11iIiiIii + i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo
 if 94 - 94: O0 + OoO0O00 / I1IiiI * II111iiii * i11iIiiIii
def lisp_process_info_reply ( source , packet , store ) :
 if 55 - 55: OoooooooOO * O0 + i1IIi % I1IiiI
 if 10 - 10: II111iiii - Ii1I . I11i . O0 + Ii1I
 if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
 if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
 iiIii1i = lisp_info ( )
 packet = iiIii1i . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 21 - 21: I1ii11iIi11i - ooOoO0o
 iiIii1i . print_info ( )
 if 81 - 81: iII111i / i11iIiiIii / I1Ii111
 if 70 - 70: I1ii11iIi11i / i11iIiiIii
 if 90 - 90: II111iiii / OoOoOO00 . Ii1I . OoooooooOO
 if 76 - 76: OoooooooOO
 o0ooOOoOO0 = False
 for ooOo in iiIii1i . rtr_list :
  oo0o00OO = ooOo . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( oo0o00OO ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ oo0o00OO ] != None ) : continue
   if 80 - 80: I11i * oO0o . OoO0O00 . i11iIiiIii % iII111i
  o0ooOOoOO0 = True
  lisp_rtr_list [ oo0o00OO ] = ooOo
  if 29 - 29: Oo0Ooo % OOooOOo - OOooOOo + OoooooooOO + o0oOOo0O0Ooo . OoooooooOO
  if 64 - 64: I11i * OoO0O00 . I1IiiI
  if 99 - 99: IiII + OOooOOo - I11i . i1IIi % OoO0O00 - I11i
  if 96 - 96: I1Ii111 / Ii1I
  if 65 - 65: I1ii11iIi11i * O0 . IiII
 if ( lisp_i_am_itr and o0ooOOoOO0 ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for o0OoO0000o in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( o0OoO0000o ) , lisp_rtr_list )
    if 11 - 11: I11i / Ii1I % oO0o
    if 50 - 50: i11iIiiIii
    if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
    if 25 - 25: I11i / ooOoO0o % ooOoO0o - OOooOOo
    if 59 - 59: I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1 - O0 - i11iIiiIii
    if 4 - 4: I1IiiI
    if 36 - 36: Ii1I
 if ( store == False ) :
  return ( [ iiIii1i . global_etr_rloc , iiIii1i . etr_port , o0ooOOoOO0 ] )
  if 76 - 76: i11iIiiIii + i1IIi
  if 56 - 56: OoOoOO00 + II111iiii / i11iIiiIii * OoOoOO00 * OoooooooOO
  if 15 - 15: OoOoOO00 / OoooooooOO + OOooOOo
  if 76 - 76: Ii1I * iII111i . OoooooooOO
  if 92 - 92: iIii1I11I1II1 - Oo0Ooo - I1IiiI - OOooOOo * I1Ii111
  if 44 - 44: I1Ii111 - II111iiii / OOooOOo
 for I1111I in lisp_db_list :
  for oo0OOOoO0OoO in I1111I . rloc_set :
   oOo0o0 = oo0OOOoO0OoO . rloc
   II1i = oo0OOOoO0OoO . interface
   if ( II1i == None ) :
    if ( oOo0o0 . is_null ( ) ) : continue
    if ( oOo0o0 . is_local ( ) == False ) : continue
    if ( iiIii1i . private_etr_rloc . is_null ( ) == False and
 oOo0o0 . is_exact_match ( iiIii1i . private_etr_rloc ) == False ) :
     continue
     if 50 - 50: I11i / I1ii11iIi11i
   elif ( iiIii1i . private_etr_rloc . is_dist_name ( ) ) :
    O0o0oO = iiIii1i . private_etr_rloc . address
    if ( O0o0oO != oo0OOOoO0OoO . rloc_name ) : continue
    if 60 - 60: II111iiii / Ii1I + OoO0O00 % I1IiiI * i1IIi / II111iiii
    if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
   I11i11i1 = green ( I1111I . eid . print_prefix ( ) , False )
   o0O00oo0O = red ( oOo0o0 . print_address_no_iid ( ) , False )
   if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
   i11Ii = iiIii1i . global_etr_rloc . is_exact_match ( oOo0o0 )
   if ( oo0OOOoO0OoO . translated_port == 0 and i11Ii ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( o0O00oo0O ,
 II1i , I11i11i1 ) )
    continue
    if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
    if 48 - 48: O0
    if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
    if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
    if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
   O0O0O00ooO0O0 = iiIii1i . global_etr_rloc
   o0OOoOOO00O = oo0OOOoO0OoO . translated_rloc
   if ( o0OOoOOO00O . is_exact_match ( O0O0O00ooO0O0 ) and
 iiIii1i . etr_port == oo0OOOoO0OoO . translated_port ) : continue
   if 15 - 15: OoooooooOO . OOooOOo . I11i . OoOoOO00 + oO0o
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( iiIii1i . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # I1ii11iIi11i - O0 % OoOoOO00 - OOooOOo + I1Ii111 . i1IIi
 iiIii1i . etr_port , o0O00oo0O , II1i , I11i11i1 ) )
   if 68 - 68: I1Ii111
   oo0OOOoO0OoO . store_translated_rloc ( iiIii1i . global_etr_rloc ,
 iiIii1i . etr_port )
   if 23 - 23: OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
   if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
 return ( [ iiIii1i . global_etr_rloc , iiIii1i . etr_port , o0ooOOoOO0 ] )
 if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
 if 8 - 8: iII111i
 if 10 - 10: OoOoOO00 % I11i
 if 49 - 49: oO0o % ooOoO0o + II111iiii
 if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
 if 99 - 99: OoOoOO00
 if 46 - 46: I1ii11iIi11i / II111iiii / OoooooooOO / Ii1I
 if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 8 - 8: oO0o
 iIiiIIi1i111iI = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 I1I1ii = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 36 - 36: ooOoO0o . Ii1I * ooOoO0o - OoOoOO00
 if 20 - 20: ooOoO0o
 if 13 - 13: i11iIiiIii + i11iIiiIii
 if 21 - 21: OoooooooOO
 iIiiIIi1i111iI . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , iIiiIIi1i111iI , None )
 iIiiIIi1i111iI . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , iIiiIIi1i111iI , None )
 if 76 - 76: Ii1I . i11iIiiIii * I1IiiI % o0oOOo0O0Ooo * OoO0O00
 if 79 - 79: O0 % iIii1I11I1II1 * iII111i - II111iiii % Oo0Ooo + i11iIiiIii
 if 36 - 36: OOooOOo / o0oOOo0O0Ooo . OoOoOO00 - I11i
 if 89 - 89: i1IIi - iIii1I11I1II1 / II111iiii
 I1I1ii . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , I1I1ii , None )
 I1I1ii . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , I1I1ii , None )
 if 61 - 61: I1Ii111
 if 56 - 56: I1ii11iIi11i - OoooooooOO
 if 52 - 52: Oo0Ooo - I11i - IiII - OoOoOO00
 if 21 - 21: oO0o % o0oOOo0O0Ooo + I1Ii111 . OOooOOo / OOooOOo
 iI1OO0Oo = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 iI1OO0Oo . start ( )
 return
 if 87 - 87: O0 . oO0o * iII111i - I11i . I1IiiI + I11i
 if 16 - 16: o0oOOo0O0Ooo . iII111i / OoOoOO00 / i11iIiiIii - o0oOOo0O0Ooo
 if 35 - 35: ooOoO0o / I1Ii111 / I1Ii111
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
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 14 - 14: iIii1I11I1II1 * I11i . I11i * ooOoO0o * iII111i
 IiiIIi1 = lisp_get_interface_address ( rloc . interface )
 if ( IiiIIi1 == None ) : return
 if 60 - 60: iIii1I11I1II1 + i1IIi + oO0o - iIii1I11I1II1 . i11iIiiIii * OoooooooOO
 i111i111i = rloc . rloc . print_address_no_iid ( )
 I1iI1iIIIii = IiiIIi1 . print_address_no_iid ( )
 if 29 - 29: IiII / OoooooooOO + I1ii11iIi11i
 if ( i111i111i == I1iI1iIIIii ) : return
 if 21 - 21: I1ii11iIi11i
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , i111i111i , I1iI1iIIIii ) )
 if 35 - 35: IiII % Oo0Ooo * Ii1I . IiII
 if 16 - 16: I1ii11iIi11i % I1IiiI + Ii1I * I11i + i1IIi
 rloc . rloc . copy_address ( IiiIIi1 )
 lisp_myrlocs [ 0 ] = IiiIIi1
 return
 if 14 - 14: iII111i / ooOoO0o % IiII - I1IiiI . Oo0Ooo
 if 30 - 30: O0 . OOooOOo
 if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
 if 83 - 83: OoooooooOO
 if 53 - 53: o0oOOo0O0Ooo - Oo0Ooo / IiII + O0
 if 88 - 88: Oo0Ooo % I1Ii111 * O0 - i1IIi * OoO0O00
 if 74 - 74: Oo0Ooo % iIii1I11I1II1 + OOooOOo
 if 50 - 50: OoO0O00 . OoooooooOO
def lisp_update_encap_port ( mc ) :
 for oOo0o0 in mc . rloc_set :
  iIIIIiI = lisp_get_nat_info ( oOo0o0 . rloc , oOo0o0 . rloc_name )
  if ( iIIIIiI == None ) : continue
  if ( oOo0o0 . translated_port == iIIIIiI . port ) : continue
  if 31 - 31: OoO0O00
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( oOo0o0 . translated_port , iIIIIiI . port ,
  # OoOoOO00 % IiII + oO0o * o0oOOo0O0Ooo
 red ( oOo0o0 . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 39 - 39: O0 + iII111i + ooOoO0o / iIii1I11I1II1
  oOo0o0 . store_translated_rloc ( oOo0o0 . rloc , iIIIIiI . port )
  if 91 - 91: Ii1I
 return
 if 62 - 62: I1Ii111 . iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I11i % i1IIi
 if 72 - 72: oO0o
 if 3 - 3: ooOoO0o - Oo0Ooo / iII111i
 if 40 - 40: IiII + oO0o
 if 95 - 95: I1Ii111 % OOooOOo + Ii1I * i11iIiiIii + i11iIiiIii
 if 27 - 27: i11iIiiIii - iIii1I11I1II1 % I1Ii111
 if 10 - 10: i11iIiiIii - Ii1I - OoooooooOO % II111iiii
 if 42 - 42: OoOoOO00 + iII111i % Oo0Ooo
 if 25 - 25: IiII % O0 * I11i * OoOoOO00 / OoooooooOO
 if 80 - 80: I1IiiI . oO0o - I1IiiI - OoOoOO00 * ooOoO0o / O0
 if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
 if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
  if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
 OO0OO0 = lisp_get_timestamp ( )
 if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
 if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
 if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
 if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
 if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
 if 40 - 40: I1ii11iIi11i
 if ( mc . last_refresh_time + mc . map_cache_ttl > OO0OO0 ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 76 - 76: Oo0Ooo - I11i
  if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
  if 39 - 39: I1IiiI
  if 8 - 8: IiII * i1IIi * i1IIi * O0
  if 69 - 69: Oo0Ooo
 if ( lisp_nat_traversal and mc . eid . address == 0 and mc . eid . mask_len == 0 ) :
  return ( [ True , delete_list ] )
  if 48 - 48: iII111i
  if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
  if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
  if 89 - 89: iII111i
  if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
 oO000o0Oo00 = lisp_print_elapsed ( mc . last_refresh_time )
 oooOoOoo0o = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( oooOoOoo0o , False ) , bold ( "timed out" , False ) , oO000o0Oo00 ) )
 if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
 if 77 - 77: OoooooooOO - I11i / I1IiiI % OoOoOO00 - OOooOOo
 if 37 - 37: ooOoO0o
 if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
 if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
 if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
 if 82 - 82: iII111i - I1Ii111 - OoOoOO00
 if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
 if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
 if 44 - 44: O0
 if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
 if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
def lisp_timeout_map_cache_walk ( mc , parms ) :
 ii = parms [ 0 ]
 Oo0o0oO = parms [ 1 ]
 if 83 - 83: ooOoO0o * iIii1I11I1II1
 if 60 - 60: OoOoOO00 . OoOoOO00 - O0 % OoooooooOO % II111iiii - iII111i
 if 89 - 89: O0 - OoO0O00
 if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
 if ( mc . group . is_null ( ) ) :
  OOOoo , ii = lisp_timeout_map_cache_entry ( mc , ii )
  if ( ii == [ ] or mc != ii [ - 1 ] ) :
   Oo0o0oO = lisp_write_checkpoint_entry ( Oo0o0oO , mc )
   if 32 - 32: O0 + IiII
  return ( [ OOOoo , parms ] )
  if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
  if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 17 - 17: OOooOOo
 if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
 if 46 - 46: II111iiii * OoO0O00
 if 77 - 77: ooOoO0o * I11i
 if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 76 - 76: iII111i * OoooooooOO
 if 49 - 49: II111iiii - OOooOOo + II111iiii + OoOoOO00
 if 51 - 51: i11iIiiIii
 if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
 if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
 if 63 - 63: II111iiii - Oo0Ooo
 if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
def lisp_timeout_map_cache ( lisp_map_cache ) :
 I1I1i = [ [ ] , [ ] ]
 I1I1i = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , I1I1i )
 if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
 if 78 - 78: IiII - I1IiiI
 if 59 - 59: oO0o + i1IIi - IiII % OOooOOo % iIii1I11I1II1
 if 71 - 71: OoO0O00
 if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
 ii = I1I1i [ 0 ]
 for O0oOO0OOO in ii : O0oOO0OOO . delete_cache ( )
 if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
 if 54 - 54: Ii1I / I1IiiI
 if 7 - 7: iIii1I11I1II1 . O0 + OOooOOo . Ii1I * Oo0Ooo
 if 25 - 25: I1Ii111 . Oo0Ooo % II111iiii . IiII - O0
 Oo0o0oO = I1I1i [ 1 ]
 lisp_checkpoint ( Oo0o0oO )
 return
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
 if 64 - 64: o0oOOo0O0Ooo . II111iiii * IiII % Oo0Ooo + I11i - OoooooooOO
 if 58 - 58: ooOoO0o
 if 15 - 15: O0 * OOooOOo * I11i + Ii1I * OoooooooOO + OOooOOo
 if 77 - 77: O0
def lisp_store_nat_info ( hostname , rloc , port ) :
 oo0o00OO = rloc . print_address_no_iid ( )
 O000Ooo0 = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( oo0o00OO , False ) , port )
 if 72 - 72: Oo0Ooo - I1ii11iIi11i
 OOII1i1IiI = lisp_nat_info ( oo0o00OO , hostname , port )
 if 45 - 45: o0oOOo0O0Ooo - ooOoO0o
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ OOII1i1IiI ]
  lprint ( O000Ooo0 . format ( "Store initial" ) )
  return ( True )
  if 2 - 2: OOooOOo + iII111i * ooOoO0o + II111iiii
  if 88 - 88: ooOoO0o * OoO0O00 * I1ii11iIi11i - I1IiiI * IiII * I11i
  if 37 - 37: iIii1I11I1II1
  if 50 - 50: o0oOOo0O0Ooo - OOooOOo * IiII % Oo0Ooo
  if 81 - 81: OoooooooOO - OoOoOO00 % I1ii11iIi11i % I1ii11iIi11i + OoOoOO00
  if 49 - 49: Ii1I + iIii1I11I1II1 . O0 * OOooOOo * OoooooooOO - OOooOOo
 iIIIIiI = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( iIIIIiI . address == oo0o00OO and iIIIIiI . port == port ) :
  iIIIIiI . uptime = lisp_get_timestamp ( )
  lprint ( O000Ooo0 . format ( "Refresh existing" ) )
  return ( False )
  if 23 - 23: iIii1I11I1II1 % I11i . OoO0O00 / i11iIiiIii % O0 * Ii1I
  if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
  if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
  if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
  if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
  if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
  if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
 IIiIIiiI11 = None
 for iIIIIiI in lisp_nat_state_info [ hostname ] :
  if ( iIIIIiI . address == oo0o00OO and iIIIIiI . port == port ) :
   IIiIIiiI11 = iIIIIiI
   break
   if 92 - 92: I1IiiI + oO0o % iII111i
   if 47 - 47: ooOoO0o . OOooOOo . oO0o + oO0o + i1IIi + iIii1I11I1II1
   if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
 if ( IIiIIiiI11 == None ) :
  lprint ( O000Ooo0 . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( IIiIIiiI11 )
  lprint ( O000Ooo0 . format ( "Use previous" ) )
  if 11 - 11: iII111i
  if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
 o0oOoOOoo0O = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ OOII1i1IiI ] + o0oOoOOoo0O
 return ( True )
 if 21 - 21: OoO0O00 - OOooOOo - i11iIiiIii . II111iiii
 if 98 - 98: IiII
 if 17 - 17: iII111i - OOooOOo / OOooOOo % OoO0O00 + i11iIiiIii % OoO0O00
 if 13 - 13: I1IiiI + Oo0Ooo * I1IiiI . i1IIi * I1ii11iIi11i + iII111i
 if 55 - 55: ooOoO0o
 if 68 - 68: Oo0Ooo
 if 3 - 3: Ii1I % Ii1I + oO0o
 if 19 - 19: Ii1I . IiII % o0oOOo0O0Ooo
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 92 - 92: i1IIi + IiII - iIii1I11I1II1 + i1IIi * ooOoO0o - i11iIiiIii
 oo0o00OO = rloc . print_address_no_iid ( )
 for iIIIIiI in lisp_nat_state_info [ hostname ] :
  if ( iIIIIiI . address == oo0o00OO ) : return ( iIIIIiI )
  if 68 - 68: o0oOOo0O0Ooo + IiII / iII111i - i11iIiiIii / OOooOOo
 return ( None )
 if 62 - 62: I1IiiI
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
 if 64 - 64: OOooOOo / OoOoOO00
 if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
 if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
 if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
 if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
 if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
 if 49 - 49: IiII
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 1 - 1: oO0o / I11i
 if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
 if 28 - 28: OOooOOo - O0 - O0 % i11iIiiIii * OoooooooOO
 if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
 if 24 - 24: O0
 if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
 oOiiIiIIIi11 = [ ]
 Ii1ii = [ ]
 if ( dest == None ) :
  for O0O0OOoO00 in lisp_map_resolvers_list . values ( ) :
   Ii1ii . append ( O0O0OOoO00 . map_resolver )
   if 36 - 36: OoO0O00 * I11i . ooOoO0o
  oOiiIiIIIi11 = Ii1ii
  if ( oOiiIiIIIi11 == [ ] ) :
   for IIIIiI1 in lisp_map_servers_list . values ( ) :
    oOiiIiIIIi11 . append ( IIIIiI1 . map_server )
    if 50 - 50: oO0o * OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
    if 55 - 55: II111iiii - IiII
  if ( oOiiIiIIIi11 == [ ] ) : return
 else :
  oOiiIiIIIi11 . append ( dest )
  if 24 - 24: oO0o % Ii1I / i1IIi
  if 84 - 84: i1IIi
  if 53 - 53: OoooooooOO - i1IIi - Ii1I
  if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
  if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
 OooooO0 = { }
 for I1111I in lisp_db_list :
  for oo0OOOoO0OoO in I1111I . rloc_set :
   lisp_update_local_rloc ( oo0OOOoO0OoO )
   if ( oo0OOOoO0OoO . rloc . is_null ( ) ) : continue
   if ( oo0OOOoO0OoO . interface == None ) : continue
   if 34 - 34: Ii1I
   IiiIIi1 = oo0OOOoO0OoO . rloc . print_address_no_iid ( )
   if ( IiiIIi1 in OooooO0 ) : continue
   OooooO0 [ IiiIIi1 ] = oo0OOOoO0OoO . interface
   if 5 - 5: II111iiii . I1ii11iIi11i
   if 85 - 85: I1Ii111 . IiII + II111iiii
 if ( OooooO0 == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
  return
  if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
  if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
  if 87 - 87: OOooOOo
  if 44 - 44: Oo0Ooo + iIii1I11I1II1
  if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
  if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
 for IiiIIi1 in OooooO0 :
  II1i = OooooO0 [ IiiIIi1 ]
  OO0o = red ( IiiIIi1 , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( OO0o ,
 II1i ) )
  OoO0o0OOOO = II1i if len ( OooooO0 ) > 1 else None
  for dest in oOiiIiIIIi11 :
   lisp_send_info_request ( lisp_sockets , dest , port , OoO0o0OOOO )
   if 10 - 10: O0 / I11i
   if 29 - 29: i11iIiiIii % I11i
   if 49 - 49: I11i
   if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
   if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
   if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
 if ( Ii1ii != [ ] ) :
  for O0O0OOoO00 in lisp_map_resolvers_list . values ( ) :
   O0O0OOoO00 . resolve_dns_name ( )
   if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
   if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
 return
 if 32 - 32: O0
 if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
 if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
 if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
 if 70 - 70: iIii1I11I1II1 - I11i
 if 2 - 2: oO0o / II111iiii * OoO0O00
 if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
 if 40 - 40: OOooOOo
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
 if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
 if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
 if 26 - 26: OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
 if 39 - 39: I1ii11iIi11i * I1IiiI * II111iiii . Oo0Ooo % I1IiiI
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
 if 98 - 98: OoO0O00 + oO0o - II111iiii
 if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
 if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
 if ( value . find ( "." ) != - 1 ) :
  IiiIIi1 = value . split ( "." )
  if ( len ( IiiIIi1 ) != 4 ) : return ( False )
  if 77 - 77: iIii1I11I1II1 * Oo0Ooo . IiII / oO0o + O0
  for O0OO0o0 in IiiIIi1 :
   if ( O0OO0o0 . isdigit ( ) == False ) : return ( False )
   if ( int ( O0OO0o0 ) > 255 ) : return ( False )
   if 65 - 65: O0 / O0 / iII111i % oO0o
  return ( True )
  if 49 - 49: OoO0O00 - IiII / ooOoO0o
  if 70 - 70: OoO0O00
  if 43 - 43: ooOoO0o + OOooOOo + II111iiii - I1IiiI
  if 58 - 58: I11i
  if 94 - 94: Oo0Ooo
 if ( value . find ( "-" ) != - 1 ) :
  IiiIIi1 = value . split ( "-" )
  for IiIIi1IiiIiI in [ "N" , "S" , "W" , "E" ] :
   if ( IiIIi1IiiIiI in IiiIIi1 ) :
    if ( len ( IiiIIi1 ) < 8 ) : return ( False )
    return ( True )
    if 39 - 39: I11i - oO0o % iII111i - ooOoO0o - OoOoOO00
    if 8 - 8: i1IIi % i1IIi % OoooooooOO % i1IIi . iIii1I11I1II1
    if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
    if 58 - 58: II111iiii * oO0o - i1IIi . I11i
    if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
    if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
    if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
 if ( value . find ( "-" ) != - 1 ) :
  IiiIIi1 = value . split ( "-" )
  if ( len ( IiiIIi1 ) != 3 ) : return ( False )
  if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
  for ii111iI11Iiii in IiiIIi1 :
   try : int ( ii111iI11Iiii , 16 )
   except : return ( False )
   if 54 - 54: iII111i
  return ( True )
  if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
  if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
  if 52 - 52: OOooOOo . OoOoOO00 - ooOoO0o % i1IIi
  if 15 - 15: oO0o
  if 6 - 6: oO0o . iIii1I11I1II1 - I1ii11iIi11i % IiII
 if ( value . find ( ":" ) != - 1 ) :
  IiiIIi1 = value . split ( ":" )
  if ( len ( IiiIIi1 ) < 2 ) : return ( False )
  if 58 - 58: iII111i * oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o
  oOoO0o = False
  OO = 0
  for ii111iI11Iiii in IiiIIi1 :
   OO += 1
   if ( ii111iI11Iiii == "" ) :
    if ( oOoO0o ) :
     if ( len ( IiiIIi1 ) == OO ) : break
     if ( OO > 2 ) : return ( False )
     if 85 - 85: OoooooooOO % OoOoOO00 + OoOoOO00 / iIii1I11I1II1
    oOoO0o = True
    continue
    if 70 - 70: oO0o . i11iIiiIii
   try : int ( ii111iI11Iiii , 16 )
   except : return ( False )
   if 7 - 7: iII111i * i11iIiiIii + Oo0Ooo - Ii1I
  return ( True )
  if 80 - 80: I11i + o0oOOo0O0Ooo * Ii1I
  if 48 - 48: oO0o . iII111i
  if 51 - 51: I1Ii111 . OoO0O00 + I1IiiI . o0oOOo0O0Ooo
  if 55 - 55: o0oOOo0O0Ooo + Ii1I % ooOoO0o
  if 41 - 41: OoO0O00 - I11i . I1Ii111 % i1IIi . I11i . II111iiii
 if ( value [ 0 ] == "+" ) :
  IiiIIi1 = value [ 1 : : ]
  for iiIiI1iI in IiiIIi1 :
   if ( iiIiI1iI . isdigit ( ) == False ) : return ( False )
   if 54 - 54: OOooOOo / IiII / II111iiii
  return ( True )
  if 19 - 19: I1Ii111 . I1Ii111
 return ( False )
 if 100 - 100: i1IIi - Ii1I * Oo0Ooo
 if 10 - 10: OoooooooOO * OOooOOo + iIii1I11I1II1 - I11i
 if 60 - 60: oO0o % II111iiii + Ii1I % Ii1I - OoO0O00
 if 27 - 27: I1Ii111 / I11i . I11i % I1Ii111 . I1Ii111
 if 80 - 80: o0oOOo0O0Ooo - o0oOOo0O0Ooo % I11i / ooOoO0o / IiII
 if 37 - 37: I1IiiI % I1ii11iIi11i / OoooooooOO - OoO0O00 . I1ii11iIi11i
 if 15 - 15: I11i / oO0o * ooOoO0o . o0oOOo0O0Ooo + I1ii11iIi11i
 if 35 - 35: i11iIiiIii
 if 71 - 71: O0 - OoooooooOO
 if 82 - 82: i11iIiiIii * II111iiii % IiII
 if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
 if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
def lisp_process_api ( process , lisp_socket , data_structure ) :
 o0Oo0000o00 , I1I1i = data_structure . split ( "%" )
 if 95 - 95: iII111i + OoooooooOO + O0 . OoOoOO00 + I1ii11iIi11i
 lprint ( "Process API request '{}', parameters: '{}'" . format ( o0Oo0000o00 ,
 I1I1i ) )
 if 79 - 79: OoooooooOO / iII111i / IiII . OoooooooOO
 oo00000ooOooO = [ ]
 if ( o0Oo0000o00 == "map-cache" ) :
  if ( I1I1i == "" ) :
   oo00000ooOooO = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , oo00000ooOooO )
  else :
   oo00000ooOooO = lisp_process_api_map_cache_entry ( json . loads ( I1I1i ) )
   if 92 - 92: I11i + O0 % II111iiii - I1ii11iIi11i + OoooooooOO . iIii1I11I1II1
   if 85 - 85: O0 - ooOoO0o
 if ( o0Oo0000o00 == "site-cache" ) :
  if ( I1I1i == "" ) :
   oo00000ooOooO = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 oo00000ooOooO )
  else :
   oo00000ooOooO = lisp_process_api_site_cache_entry ( json . loads ( I1I1i ) )
   if 35 - 35: o0oOOo0O0Ooo - I1IiiI
   if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
 if ( o0Oo0000o00 == "map-server" ) :
  I1I1i = { } if ( I1I1i == "" ) else json . loads ( I1I1i )
  oo00000ooOooO = lisp_process_api_ms_or_mr ( True , I1I1i )
  if 65 - 65: Ii1I % i11iIiiIii
 if ( o0Oo0000o00 == "map-resolver" ) :
  I1I1i = { } if ( I1I1i == "" ) else json . loads ( I1I1i )
  oo00000ooOooO = lisp_process_api_ms_or_mr ( False , I1I1i )
  if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
 if ( o0Oo0000o00 == "database-mapping" ) :
  oo00000ooOooO = lisp_process_api_database_mapping ( )
  if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
  if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
  if 88 - 88: iII111i
  if 94 - 94: OoooooooOO
  if 32 - 32: I1ii11iIi11i
 oo00000ooOooO = json . dumps ( oo00000ooOooO )
 OoOO0o00OOO0o = lisp_api_ipc ( process , oo00000ooOooO )
 lisp_ipc ( OoOO0o00OOO0o , lisp_socket , "lisp-core" )
 return
 if 8 - 8: I11i * i11iIiiIii - ooOoO0o
 if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
 if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
 if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
 if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
 if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
 if 42 - 42: II111iiii . iII111i
def lisp_process_api_map_cache ( mc , data ) :
 if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
 if 64 - 64: oO0o / IiII
 if 86 - 86: I11i
 if 36 - 36: o0oOOo0O0Ooo / OoO0O00
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
 if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
 if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
 if 12 - 12: I1IiiI . OOooOOo % Oo0Ooo
 if 86 - 86: i11iIiiIii
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
 if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
 if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
 if 79 - 79: I11i - II111iiii
 if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
 if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
 if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
def lisp_gather_map_cache_data ( mc , data ) :
 I1iII11ii1 = { }
 I1iII11ii1 [ "instance-id" ] = str ( mc . eid . instance_id )
 I1iII11ii1 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  I1iII11ii1 [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 44 - 44: I1IiiI * IiII . OoooooooOO
 I1iII11ii1 [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 I1iII11ii1 [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 I1iII11ii1 [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 I1iII11ii1 [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
 if 10 - 10: i1IIi + o0oOOo0O0Ooo
 if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
 if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 iI1111Ii1I = [ ]
 for oOo0o0 in mc . rloc_set :
  i11iII1IiI = { }
  if ( oOo0o0 . rloc_exists ( ) ) :
   i11iII1IiI [ "address" ] = oOo0o0 . rloc . print_address_no_iid ( )
   if 2 - 2: I11i
   if 12 - 12: i1IIi . I1Ii111
  if ( oOo0o0 . translated_port != 0 ) :
   i11iII1IiI [ "encap-port" ] = str ( oOo0o0 . translated_port )
   if 99 - 99: Oo0Ooo / i11iIiiIii
  i11iII1IiI [ "state" ] = oOo0o0 . print_state ( )
  if ( oOo0o0 . geo ) : i11iII1IiI [ "geo" ] = oOo0o0 . geo . print_geo ( )
  if ( oOo0o0 . elp ) : i11iII1IiI [ "elp" ] = oOo0o0 . elp . print_elp ( False )
  if ( oOo0o0 . rle ) : i11iII1IiI [ "rle" ] = oOo0o0 . rle . print_rle ( False , False )
  if ( oOo0o0 . json ) : i11iII1IiI [ "json" ] = oOo0o0 . json . print_json ( False )
  if ( oOo0o0 . rloc_name ) : i11iII1IiI [ "rloc-name" ] = oOo0o0 . rloc_name
  OOO0ooOoOO = oOo0o0 . stats . get_stats ( False , False )
  if ( OOO0ooOoOO ) : i11iII1IiI [ "stats" ] = OOO0ooOoOO
  i11iII1IiI [ "uptime" ] = lisp_print_elapsed ( oOo0o0 . uptime )
  i11iII1IiI [ "upriority" ] = str ( oOo0o0 . priority )
  i11iII1IiI [ "uweight" ] = str ( oOo0o0 . weight )
  i11iII1IiI [ "mpriority" ] = str ( oOo0o0 . mpriority )
  i11iII1IiI [ "mweight" ] = str ( oOo0o0 . mweight )
  O00i1I1Iii1Iiii = oOo0o0 . last_rloc_probe_reply
  if ( O00i1I1Iii1Iiii ) :
   i11iII1IiI [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( O00i1I1Iii1Iiii )
   i11iII1IiI [ "rloc-probe-rtt" ] = str ( oOo0o0 . rloc_probe_rtt )
   if 10 - 10: O0 . Ii1I . i1IIi
  i11iII1IiI [ "rloc-hop-count" ] = oOo0o0 . rloc_probe_hops
  i11iII1IiI [ "recent-rloc-hop-counts" ] = oOo0o0 . recent_rloc_probe_hops
  if 44 - 44: OoooooooOO % I1Ii111 / Oo0Ooo . Ii1I
  i11iII1IiI [ "rloc-probe-latency" ] = oOo0o0 . rloc_probe_latency
  i11iII1IiI [ "recent-rloc-probe-latencies" ] = oOo0o0 . recent_rloc_probe_latencies
  if 36 - 36: iII111i
  O0o0 = [ ]
  for I1ioOoo0O in oOo0o0 . recent_rloc_probe_rtts : O0o0 . append ( str ( I1ioOoo0O ) )
  i11iII1IiI [ "recent-rloc-probe-rtts" ] = O0o0
  if 8 - 8: OoooooooOO * i11iIiiIii * iII111i * O0 - OoOoOO00
  iI1111Ii1I . append ( i11iII1IiI )
  if 3 - 3: OoooooooOO % oO0o + OoOoOO00 % I1IiiI
 I1iII11ii1 [ "rloc-set" ] = iI1111Ii1I
 if 50 - 50: OoO0O00 - Oo0Ooo
 data . append ( I1iII11ii1 )
 return ( [ True , data ] )
 if 13 - 13: OoOoOO00
 if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
 if 90 - 90: oO0o * I1Ii111 / O0
 if 15 - 15: o0oOOo0O0Ooo * O0 . OOooOOo / Oo0Ooo
 if 28 - 28: OoooooooOO + OoooooooOO
 if 27 - 27: I11i . oO0o / OoooooooOO - OoO0O00 . I11i
 if 15 - 15: II111iiii * OoO0O00
def lisp_process_api_map_cache_entry ( parms ) :
 o0OoO0000o = parms [ "instance-id" ]
 o0OoO0000o = 0 if ( o0OoO0000o == "" ) else int ( o0OoO0000o )
 if 33 - 33: OoooooooOO . o0oOOo0O0Ooo . I1IiiI / I1ii11iIi11i . OoOoOO00
 if 58 - 58: Ii1I
 if 20 - 20: OOooOOo
 if 93 - 93: i1IIi . IiII % O0 * iII111i
 iIiiIIi1i111iI = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 iIiiIIi1i111iI . store_prefix ( parms [ "eid-prefix" ] )
 oO0o0 = iIiiIIi1i111iI
 oo00Oo0 = iIiiIIi1i111iI
 if 84 - 84: I11i
 if 99 - 99: I1ii11iIi11i
 if 78 - 78: I1Ii111 . IiII - OOooOOo
 if 93 - 93: iIii1I11I1II1
 if 33 - 33: OOooOOo . i1IIi
 oOooO00OOoO = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 if ( parms . has_key ( "group-prefix" ) ) :
  oOooO00OOoO . store_prefix ( parms [ "group-prefix" ] )
  oO0o0 = oOooO00OOoO
  if 63 - 63: II111iiii . oO0o * IiII
  if 73 - 73: iII111i . i1IIi + oO0o + OOooOOo + ooOoO0o - iIii1I11I1II1
 oo00000ooOooO = [ ]
 O0oOO0OOO = lisp_map_cache_lookup ( oo00Oo0 , oO0o0 )
 if ( O0oOO0OOO ) : OOOoo , oo00000ooOooO = lisp_process_api_map_cache ( O0oOO0OOO , oo00000ooOooO )
 return ( oo00000ooOooO )
 if 47 - 47: I11i
 if 88 - 88: OoO0O00 - OoooooooOO
 if 93 - 93: Oo0Ooo * I1IiiI
 if 60 - 60: I1Ii111 + OOooOOo % iII111i
 if 40 - 40: I11i + oO0o . O0 % oO0o
 if 12 - 12: iIii1I11I1II1
 if 9 - 9: OoOoOO00 * II111iiii / o0oOOo0O0Ooo * iII111i - II111iiii / i11iIiiIii
def lisp_process_api_site_cache ( se , data ) :
 if 14 - 14: i11iIiiIii + I1Ii111 . OoOoOO00 - oO0o * OoO0O00
 if 23 - 23: iIii1I11I1II1
 if 32 - 32: iII111i * iIii1I11I1II1 + I1Ii111 + IiII + O0 * OoO0O00
 if 100 - 100: II111iiii
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
 if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
 if 42 - 42: ooOoO0o + I1IiiI * iII111i / OoOoOO00 . i1IIi - OoooooooOO
 if 8 - 8: iIii1I11I1II1 - Oo0Ooo + iII111i
 if 40 - 40: o0oOOo0O0Ooo * I1IiiI
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 75 - 75: O0 * OOooOOo / ooOoO0o + I11i
 if 56 - 56: I1IiiI % OoooooooOO % Oo0Ooo
 if 19 - 19: i11iIiiIii - iIii1I11I1II1 . i1IIi . I1Ii111 / I1IiiI * I1Ii111
 if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i * OoOoOO00
 if 16 - 16: oO0o
 if 32 - 32: OoooooooOO
 if 77 - 77: Oo0Ooo . i1IIi - I11i
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 ii1i1II11II1i = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 Ii1II1IiI = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  ii1i1II11II1i . store_address ( data [ "address" ] )
  if 98 - 98: O0
  if 87 - 87: OoO0O00 % I1Ii111 - OOooOOo - II111iiii + iII111i
 i11II = { }
 if ( ms_or_mr ) :
  for IIIIiI1 in lisp_map_servers_list . values ( ) :
   if ( Ii1II1IiI ) :
    if ( Ii1II1IiI != IIIIiI1 . dns_name ) : continue
   else :
    if ( ii1i1II11II1i . is_exact_match ( IIIIiI1 . map_server ) == False ) : continue
    if 54 - 54: i1IIi % iII111i
    if 16 - 16: II111iiii - Oo0Ooo
   i11II [ "dns-name" ] = IIIIiI1 . dns_name
   i11II [ "address" ] = IIIIiI1 . map_server . print_address_no_iid ( )
   i11II [ "ms-name" ] = "" if IIIIiI1 . ms_name == None else IIIIiI1 . ms_name
   return ( [ i11II ] )
   if 44 - 44: OOooOOo / Oo0Ooo - I1ii11iIi11i + I11i . oO0o
 else :
  for O0O0OOoO00 in lisp_map_resolvers_list . values ( ) :
   if ( Ii1II1IiI ) :
    if ( Ii1II1IiI != O0O0OOoO00 . dns_name ) : continue
   else :
    if ( ii1i1II11II1i . is_exact_match ( O0O0OOoO00 . map_resolver ) == False ) : continue
    if 85 - 85: iIii1I11I1II1 / Ii1I
    if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
   i11II [ "dns-name" ] = O0O0OOoO00 . dns_name
   i11II [ "address" ] = O0O0OOoO00 . map_resolver . print_address_no_iid ( )
   i11II [ "mr-name" ] = "" if O0O0OOoO00 . mr_name == None else O0O0OOoO00 . mr_name
   return ( [ i11II ] )
   if 97 - 97: I1Ii111 + I1ii11iIi11i
   if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
 return ( [ ] )
 if 80 - 80: I11i
 if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
 if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
 if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
 if 46 - 46: Oo0Ooo / Oo0Ooo * IiII
 if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
 if 65 - 65: I11i
 if 92 - 92: iII111i . IiII + i1IIi % i1IIi
def lisp_process_api_database_mapping ( ) :
 oo00000ooOooO = [ ]
 if 11 - 11: I1ii11iIi11i + iIii1I11I1II1 - I1Ii111 * iIii1I11I1II1 * IiII + oO0o
 for I1111I in lisp_db_list :
  I1iII11ii1 = { }
  I1iII11ii1 [ "eid-prefix" ] = I1111I . eid . print_prefix ( )
  if ( I1111I . group . is_null ( ) == False ) :
   I1iII11ii1 [ "group-prefix" ] = I1111I . group . print_prefix ( )
   if 6 - 6: I1Ii111 * OOooOOo + i1IIi - Ii1I / oO0o
   if 81 - 81: I1Ii111 % oO0o * i1IIi * OoooooooOO / Oo0Ooo
  ooOOo = [ ]
  for i11iII1IiI in I1111I . rloc_set :
   oOo0o0 = { }
   if ( i11iII1IiI . rloc . is_null ( ) == False ) :
    oOo0o0 [ "rloc" ] = i11iII1IiI . rloc . print_address_no_iid ( )
    if 70 - 70: I1IiiI
   if ( i11iII1IiI . rloc_name != None ) : oOo0o0 [ "rloc-name" ] = i11iII1IiI . rloc_name
   if ( i11iII1IiI . interface != None ) : oOo0o0 [ "interface" ] = i11iII1IiI . interface
   iIiI1iiI1II1ii1 = i11iII1IiI . translated_rloc
   if ( iIiI1iiI1II1ii1 . is_null ( ) == False ) :
    oOo0o0 [ "translated-rloc" ] = iIiI1iiI1II1ii1 . print_address_no_iid ( )
    if 43 - 43: OoOoOO00
   if ( oOo0o0 != { } ) : ooOOo . append ( oOo0o0 )
   if 47 - 47: I1Ii111 - Ii1I
   if 44 - 44: II111iiii + OOooOOo % I1IiiI
   if 34 - 34: o0oOOo0O0Ooo / I1ii11iIi11i - o0oOOo0O0Ooo / i11iIiiIii
   if 18 - 18: oO0o
   if 43 - 43: I11i / OOooOOo + OOooOOo
  I1iII11ii1 [ "rlocs" ] = ooOOo
  if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
  if 90 - 90: OOooOOo
  if 29 - 29: OoOoOO00 - I1IiiI / oO0o + Oo0Ooo + I1Ii111 + O0
  if 65 - 65: oO0o
  oo00000ooOooO . append ( I1iII11ii1 )
  if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
 return ( oo00000ooOooO )
 if 13 - 13: Ii1I
 if 34 - 34: I1IiiI / iIii1I11I1II1
 if 35 - 35: oO0o / oO0o
 if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
 if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
 if 77 - 77: O0
 if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
def lisp_gather_site_cache_data ( se , data ) :
 I1iII11ii1 = { }
 I1iII11ii1 [ "site-name" ] = se . site . site_name
 I1iII11ii1 [ "instance-id" ] = str ( se . eid . instance_id )
 I1iII11ii1 [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  I1iII11ii1 [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 36 - 36: II111iiii
 I1iII11ii1 [ "registered" ] = "yes" if se . registered else "no"
 I1iII11ii1 [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 I1iII11ii1 [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
 IiiIIi1 = se . last_registerer
 IiiIIi1 = "none" if IiiIIi1 . is_null ( ) else IiiIIi1 . print_address ( )
 I1iII11ii1 [ "last-registerer" ] = IiiIIi1
 I1iII11ii1 [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 I1iII11ii1 [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 I1iII11ii1 [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  I1iII11ii1 [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 7 - 7: i11iIiiIii
  if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
  if 41 - 41: IiII % II111iiii
  if 99 - 99: IiII - O0
  if 59 - 59: iII111i % O0 + OOooOOo * ooOoO0o
 iI1111Ii1I = [ ]
 for oOo0o0 in se . registered_rlocs :
  i11iII1IiI = { }
  i11iII1IiI [ "address" ] = oOo0o0 . rloc . print_address_no_iid ( ) if oOo0o0 . rloc_exists ( ) else "none"
  if 27 - 27: I1Ii111 % i11iIiiIii * I1IiiI
  if 19 - 19: OoOoOO00 / o0oOOo0O0Ooo - iII111i / OoO0O00
  if ( oOo0o0 . geo ) : i11iII1IiI [ "geo" ] = oOo0o0 . geo . print_geo ( )
  if ( oOo0o0 . elp ) : i11iII1IiI [ "elp" ] = oOo0o0 . elp . print_elp ( False )
  if ( oOo0o0 . rle ) : i11iII1IiI [ "rle" ] = oOo0o0 . rle . print_rle ( False , True )
  if ( oOo0o0 . json ) : i11iII1IiI [ "json" ] = oOo0o0 . json . print_json ( False )
  if ( oOo0o0 . rloc_name ) : i11iII1IiI [ "rloc-name" ] = oOo0o0 . rloc_name
  i11iII1IiI [ "uptime" ] = lisp_print_elapsed ( oOo0o0 . uptime )
  i11iII1IiI [ "upriority" ] = str ( oOo0o0 . priority )
  i11iII1IiI [ "uweight" ] = str ( oOo0o0 . weight )
  i11iII1IiI [ "mpriority" ] = str ( oOo0o0 . mpriority )
  i11iII1IiI [ "mweight" ] = str ( oOo0o0 . mweight )
  if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
  iI1111Ii1I . append ( i11iII1IiI )
  if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
 I1iII11ii1 [ "registered-rlocs" ] = iI1111Ii1I
 if 89 - 89: Ii1I * Oo0Ooo / I1Ii111 * I1ii11iIi11i + O0 * Oo0Ooo
 data . append ( I1iII11ii1 )
 return ( [ True , data ] )
 if 74 - 74: I11i . I11i
 if 74 - 74: OoOoOO00 * ooOoO0o * I1Ii111
 if 56 - 56: iIii1I11I1II1 * OoO0O00 - oO0o * Ii1I
 if 62 - 62: i1IIi + I11i / OOooOOo - OoooooooOO % i1IIi . I1IiiI
 if 13 - 13: O0 * iII111i
 if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
 if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
def lisp_process_api_site_cache_entry ( parms ) :
 o0OoO0000o = parms [ "instance-id" ]
 o0OoO0000o = 0 if ( o0OoO0000o == "" ) else int ( o0OoO0000o )
 if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
 if 47 - 47: I1Ii111 * iII111i
 if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
 if 76 - 76: iIii1I11I1II1 . i11iIiiIii * II111iiii - iII111i
 iIiiIIi1i111iI = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 iIiiIIi1i111iI . store_prefix ( parms [ "eid-prefix" ] )
 if 51 - 51: I1IiiI
 if 52 - 52: I1Ii111
 if 82 - 82: iII111i + II111iiii
 if 29 - 29: O0 % Ii1I * ooOoO0o % O0
 if 83 - 83: oO0o
 oOooO00OOoO = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
 if ( parms . has_key ( "group-prefix" ) ) :
  oOooO00OOoO . store_prefix ( parms [ "group-prefix" ] )
  if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
  if 85 - 85: iIii1I11I1II1 / I11i
 oo00000ooOooO = [ ]
 IiI111II1I1iI = lisp_site_eid_lookup ( iIiiIIi1i111iI , oOooO00OOoO , False )
 if ( IiI111II1I1iI ) : lisp_gather_site_cache_data ( IiI111II1I1iI , oo00000ooOooO )
 return ( oo00000ooOooO )
 if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
 if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
 if 20 - 20: OOooOOo % i1IIi * Ii1I / i11iIiiIii
 if 89 - 89: ooOoO0o
 if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
 if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
 if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
def lisp_get_interface_instance_id ( device , source_eid ) :
 II1i = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  II1i = lisp_myinterfaces [ device ]
  if 20 - 20: I11i
  if 37 - 37: I1Ii111
  if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
  if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
  if 41 - 41: O0 / OoooooooOO - i1IIi
  if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
 if ( II1i == None or II1i . instance_id == None ) :
  return ( lisp_default_iid )
  if 32 - 32: oO0o / IiII - I11i . ooOoO0o
  if 69 - 69: i11iIiiIii * i11iIiiIii
  if 100 - 100: I1ii11iIi11i * I1ii11iIi11i + i1IIi
  if 96 - 96: I1Ii111 / I1IiiI + ooOoO0o
  if 16 - 16: I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo % OoOoOO00 + ooOoO0o % I1ii11iIi11i
  if 85 - 85: oO0o * OoooooooOO * iIii1I11I1II1 + iII111i
  if 67 - 67: Ii1I / i11iIiiIii % OoOoOO00 % O0 / OoOoOO00
  if 54 - 54: I11i . OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
  if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
 o0OoO0000o = II1i . get_instance_id ( )
 if ( source_eid == None ) : return ( o0OoO0000o )
 if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
 oooo = source_eid . instance_id
 i1ii1I1ii = None
 for II1i in lisp_multi_tenant_interfaces :
  if ( II1i . device != device ) : continue
  oOoOo0 = II1i . multi_tenant_eid
  source_eid . instance_id = oOoOo0 . instance_id
  if ( source_eid . is_more_specific ( oOoOo0 ) == False ) : continue
  if ( i1ii1I1ii == None or i1ii1I1ii . multi_tenant_eid . mask_len < oOoOo0 . mask_len ) :
   i1ii1I1ii = II1i
   if 14 - 14: I1Ii111 . Oo0Ooo / I11i * ooOoO0o - I1Ii111 / oO0o
   if 83 - 83: II111iiii
 source_eid . instance_id = oooo
 if 21 - 21: oO0o - I11i % o0oOOo0O0Ooo . Ii1I
 if ( i1ii1I1ii == None ) : return ( o0OoO0000o )
 return ( i1ii1I1ii . get_instance_id ( ) )
 if 41 - 41: o0oOOo0O0Ooo . i11iIiiIii + I11i % I1ii11iIi11i - II111iiii
 if 30 - 30: Oo0Ooo . oO0o / i11iIiiIii % i1IIi . OoO0O00
 if 12 - 12: II111iiii . I1Ii111
 if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
 if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
 if 61 - 61: I1ii11iIi11i
 if 12 - 12: OoO0O00
 if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
 if 7 - 7: Oo0Ooo
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( lisp_myinterfaces . has_key ( device ) == False ) : return ( None )
 if 38 - 38: Oo0Ooo - I1ii11iIi11i
 II1i = lisp_myinterfaces [ device ]
 I1iIiI1iiI11I = device if II1i . dynamic_eid_device == None else II1i . dynamic_eid_device
 if 81 - 81: iII111i + IiII + i11iIiiIii * I11i
 if 3 - 3: Ii1I
 if ( II1i . does_dynamic_eid_match ( eid ) ) : return ( I1iIiI1iiI11I )
 return ( None )
 if 71 - 71: iIii1I11I1II1 . OOooOOo / I11i / i1IIi
 if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
 if 86 - 86: Oo0Ooo
 if 97 - 97: I1IiiI
 if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
 if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
 if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 64 - 64: I1IiiI % ooOoO0o
 Oo0oOO0oO0O00 = lisp_process_rloc_probe_timer
 ooOo0OO0O0 = threading . Timer ( interval , Oo0oOO0oO0O00 , [ lisp_sockets ] )
 lisp_rloc_probe_timer = ooOo0OO0O0
 ooOo0OO0O0 . start ( )
 return
 if 27 - 27: OOooOOo - OoooooooOO - I1ii11iIi11i - o0oOOo0O0Ooo / OOooOOo
 if 58 - 58: I11i . I11i + O0 / I1IiiI
 if 45 - 45: OoooooooOO * II111iiii
 if 28 - 28: I1ii11iIi11i
 if 85 - 85: o0oOOo0O0Ooo
 if 20 - 20: OoooooooOO . ooOoO0o + ooOoO0o
 if 7 - 7: OoO0O00 / IiII - OoO0O00 . OOooOOo
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for ii1i1I1111ii in lisp_rloc_probe_list :
  ooOoiii1i1i11I = lisp_rloc_probe_list [ ii1i1I1111ii ]
  lprint ( "RLOC {}:" . format ( ii1i1I1111ii ) )
  for i11iII1IiI , oOo , i11ii in ooOoiii1i1i11I :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( i11iII1IiI ) ) , oOo . print_prefix ( ) ,
 i11ii . print_prefix ( ) , i11iII1IiI . translated_port ) )
   if 67 - 67: I1Ii111 . iII111i + Oo0Ooo / i11iIiiIii
   if 47 - 47: iII111i
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 16 - 16: OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
 if 60 - 60: OOooOOo . Ii1I
 if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
 if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
 if 38 - 38: IiII / I11i / IiII * iII111i
 if 30 - 30: oO0o
 if 30 - 30: IiII / OoO0O00
 if 89 - 89: oO0o . OoOoOO00 . IiII / iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00
 if 86 - 86: OoooooooOO - iIii1I11I1II1 . OoO0O00 * Ii1I / I1Ii111 + I1Ii111
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 52 - 52: iIii1I11I1II1 % OoO0O00 - IiII % i11iIiiIii - o0oOOo0O0Ooo
 if 25 - 25: Oo0Ooo - OOooOOo . i1IIi * OoOoOO00 / I11i / o0oOOo0O0Ooo
 if 54 - 54: OoOoOO00 / i1IIi + OOooOOo - I1ii11iIi11i - I1IiiI * I1Ii111
 if 91 - 91: OoooooooOO * OoooooooOO
 oOo0o0 , oOo , i11ii = eid_list [ 0 ]
 I11iIiiiIiii = [ lisp_print_eid_tuple ( oOo , i11ii ) ]
 if 75 - 75: ooOoO0o / Ii1I . Ii1I + I1ii11iIi11i
 for oOo0o0 , oOo , i11ii in eid_list [ 1 : : ] :
  oOo0o0 . state = LISP_RLOC_UNREACH_STATE
  oOo0o0 . last_state_change = lisp_get_timestamp ( )
  I11iIiiiIiii . append ( lisp_print_eid_tuple ( oOo , i11ii ) )
  if 99 - 99: Ii1I % Oo0Ooo % Oo0Ooo - Oo0Ooo * iIii1I11I1II1 / Ii1I
  if 6 - 6: o0oOOo0O0Ooo
 i1111i11iiIII = bold ( "unreachable" , False )
 o0O00oo0O = red ( oOo0o0 . rloc . print_address_no_iid ( ) , False )
 if 63 - 63: i1IIi / OoO0O00 * I1IiiI * iIii1I11I1II1 - I1ii11iIi11i - OoooooooOO
 for iIiiIIi1i111iI in I11iIiiiIiii :
  oOo = green ( iIiiIIi1i111iI , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( o0O00oo0O , i1111i11iiIII , oOo ) )
  if 36 - 36: i11iIiiIii / ooOoO0o - I1ii11iIi11i % I1IiiI
  if 67 - 67: OOooOOo % I1IiiI . OOooOOo / oO0o * o0oOOo0O0Ooo
  if 4 - 4: I1Ii111 % I1ii11iIi11i + Oo0Ooo % II111iiii / I1IiiI
  if 38 - 38: OoO0O00 / I11i . o0oOOo0O0Ooo / II111iiii
  if 59 - 59: i11iIiiIii
  if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
 for oOo0o0 , oOo , i11ii in eid_list :
  O0oOO0OOO = lisp_map_cache . lookup_cache ( oOo , True )
  if ( O0oOO0OOO ) : lisp_write_ipc_map_cache ( True , O0oOO0OOO )
  if 59 - 59: I1ii11iIi11i
 return
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
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
 if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
 if 54 - 54: oO0o * II111iiii
 if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
 o0o00O0OO0O0O = lisp_get_default_route_next_hops ( )
 if 66 - 66: Oo0Ooo % IiII
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 30 - 30: IiII - iII111i * iIii1I11I1II1 % ooOoO0o
 if 78 - 78: iIii1I11I1II1 % OoooooooOO . o0oOOo0O0Ooo
 if 85 - 85: i11iIiiIii
 if 96 - 96: OoOoOO00
 if 12 - 12: oO0o % OoO0O00 % I1ii11iIi11i . IiII % ooOoO0o
 OO = 0
 oOoOoO0oOO0o0 = bold ( "RLOC-probe" , False )
 for iio00oOO0OOO0O0 in lisp_rloc_probe_list . values ( ) :
  if 89 - 89: OoO0O00 % ooOoO0o . I11i % Ii1I * IiII
  if 94 - 94: OOooOOo . iIii1I11I1II1
  if 60 - 60: iII111i . Ii1I / I1IiiI
  if 92 - 92: OoooooooOO % II111iiii + I1ii11iIi11i
  if 93 - 93: OoooooooOO . I1ii11iIi11i
  Ooi1i1iIIi1IIi1 = None
  for oOO0O0OoooO00O , iIiiIIi1i111iI , oOooO00OOoO in iio00oOO0OOO0O0 :
   oo0o00OO = oOO0O0OoooO00O . rloc . print_address_no_iid ( )
   if 17 - 17: II111iiii
   if 91 - 91: oO0o - oO0o % Ii1I % iIii1I11I1II1 / OoOoOO00
   if 60 - 60: I1IiiI / iIii1I11I1II1 - o0oOOo0O0Ooo / OoooooooOO * OoooooooOO
   if 22 - 22: I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo . i1IIi * OoO0O00
   iiIi111I1 , IiIiiiI1111I , II1ioOO0Oo = lisp_allow_gleaning ( iIiiIIi1i111iI , None , oOO0O0OoooO00O )
   if ( iiIi111I1 and IiIiiiI1111I == False ) :
    oOo = green ( iIiiIIi1i111iI . print_address ( ) , False )
    oo0o00OO += ":{}" . format ( oOO0O0OoooO00O . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( oo0o00OO , False ) , oOo ) )
    if 64 - 64: Ii1I / I1ii11iIi11i
    continue
    if 30 - 30: OoooooooOO + O0 / I1ii11iIi11i * o0oOOo0O0Ooo
    if 11 - 11: O0 + OoO0O00 - Oo0Ooo - Oo0Ooo . i11iIiiIii
    if 15 - 15: Ii1I % i11iIiiIii / OoOoOO00
    if 85 - 85: ooOoO0o . i1IIi / iII111i % iIii1I11I1II1 / II111iiii / I1Ii111
    if 60 - 60: iIii1I11I1II1 - iIii1I11I1II1 . I11i
    if 55 - 55: OoO0O00
    if 87 - 87: Ii1I - iII111i / O0 - o0oOOo0O0Ooo - iIii1I11I1II1 % Ii1I
   if ( oOO0O0OoooO00O . down_state ( ) ) : continue
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
   if ( Ooi1i1iIIi1IIi1 ) :
    oOO0O0OoooO00O . last_rloc_probe_nonce = Ooi1i1iIIi1IIi1 . last_rloc_probe_nonce
    if 7 - 7: I1ii11iIi11i
    if ( Ooi1i1iIIi1IIi1 . translated_port == oOO0O0OoooO00O . translated_port and Ooi1i1iIIi1IIi1 . rloc_name == oOO0O0OoooO00O . rloc_name ) :
     if 37 - 37: O0 . II111iiii
     oOo = green ( lisp_print_eid_tuple ( iIiiIIi1i111iI , oOooO00OOoO ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( oo0o00OO , False ) , oOo ) )
     if 70 - 70: o0oOOo0O0Ooo / iII111i + i1IIi + I11i % iIii1I11I1II1 % Oo0Ooo
     if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
     if 1 - 1: I1ii11iIi11i / i1IIi . I1IiiI / Ii1I
     if 19 - 19: iIii1I11I1II1 / Oo0Ooo . O0 - Oo0Ooo
     if 74 - 74: I1ii11iIi11i * OoooooooOO . iII111i
     if 45 - 45: I1IiiI - IiII % ooOoO0o - IiII . Oo0Ooo - o0oOOo0O0Ooo
     oOO0O0OoooO00O . last_rloc_probe = Ooi1i1iIIi1IIi1 . last_rloc_probe
     continue
     if 27 - 27: iII111i
     if 64 - 64: iIii1I11I1II1 - OOooOOo . iII111i % o0oOOo0O0Ooo / II111iiii % OoooooooOO
     if 87 - 87: OoooooooOO
   IiIiIi1i11II = None
   oOo0o0 = None
   while ( True ) :
    oOo0o0 = oOO0O0OoooO00O if oOo0o0 == None else oOo0o0 . next_rloc
    if ( oOo0o0 == None ) : break
    if 70 - 70: o0oOOo0O0Ooo % OoooooooOO % I1IiiI . OoOoOO00 * I1IiiI - ooOoO0o
    if 92 - 92: I1IiiI . I11i
    if 66 - 66: I1Ii111 / I11i / OoooooooOO % OoOoOO00 . oO0o * iII111i
    if 34 - 34: I1ii11iIi11i * I1ii11iIi11i % I11i / OOooOOo % oO0o . OoOoOO00
    if 25 - 25: I1ii11iIi11i / I11i + i1IIi . I1IiiI + ooOoO0o
    if ( oOo0o0 . rloc_next_hop != None ) :
     if ( oOo0o0 . rloc_next_hop not in o0o00O0OO0O0O ) :
      if ( oOo0o0 . up_state ( ) ) :
       OooOOOoOoo0O0 , O0O0oo0O0O = oOo0o0 . rloc_next_hop
       oOo0o0 . state = LISP_RLOC_UNREACH_STATE
       oOo0o0 . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( oOo0o0 . rloc , False )
       if 29 - 29: IiII + I1ii11iIi11i
      i1111i11iiIII = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( O0O0oo0O0O , OooOOOoOoo0O0 ,
 red ( oo0o00OO , False ) , i1111i11iiIII ) )
      continue
      if 8 - 8: IiII % I1IiiI
      if 10 - 10: OoooooooOO / OoOoOO00
      if 77 - 77: OoOoOO00
      if 10 - 10: IiII / i11iIiiIii
      if 19 - 19: OoO0O00
      if 100 - 100: I1ii11iIi11i - I1ii11iIi11i
    I1IIII = oOo0o0 . last_rloc_probe
    ii1i1III11iI = 0 if I1IIII == None else time . time ( ) - I1IIII
    if ( oOo0o0 . unreach_state ( ) and ii1i1III11iI < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( oo0o00OO , False ) ) )
     if 51 - 51: I1Ii111
     continue
     if 71 - 71: OoOoOO00 * OoooooooOO + Ii1I % iII111i
     if 70 - 70: iIii1I11I1II1 * i1IIi
     if 57 - 57: Ii1I % iII111i % II111iiii - Oo0Ooo - o0oOOo0O0Ooo
     if 92 - 92: O0
     if 17 - 17: ooOoO0o
     if 8 - 8: o0oOOo0O0Ooo
    Oo0ooO0O0o00o = lisp_get_echo_nonce ( None , oo0o00OO )
    if ( Oo0ooO0O0o00o and Oo0ooO0O0o00o . request_nonce_timeout ( ) ) :
     oOo0o0 . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     oOo0o0 . last_state_change = lisp_get_timestamp ( )
     i1111i11iiIII = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( oo0o00OO , False ) , i1111i11iiIII ) )
     if 82 - 82: I1IiiI - OoO0O00 . Ii1I + I1IiiI * iII111i
     lisp_update_rtr_updown ( oOo0o0 . rloc , False )
     continue
     if 72 - 72: I11i . Oo0Ooo / IiII * Oo0Ooo % I1ii11iIi11i + iII111i
     if 49 - 49: i11iIiiIii + OoOoOO00
     if 61 - 61: II111iiii / II111iiii * o0oOOo0O0Ooo - IiII + I1ii11iIi11i
     if 38 - 38: Oo0Ooo
     if 29 - 29: I1ii11iIi11i / IiII . I1Ii111 + Ii1I + OoO0O00
     if 76 - 76: ooOoO0o . I11i * OoO0O00
    if ( Oo0ooO0O0o00o and Oo0ooO0O0o00o . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( oo0o00OO , False ) ) )
     if 53 - 53: II111iiii / OoOoOO00 / IiII * oO0o
     continue
     if 52 - 52: O0 % iII111i * iIii1I11I1II1 / I11i / I1IiiI * ooOoO0o
     if 93 - 93: iIii1I11I1II1 . II111iiii * OOooOOo - iIii1I11I1II1 . oO0o % Oo0Ooo
     if 92 - 92: OoO0O00
     if 42 - 42: I1ii11iIi11i - iIii1I11I1II1 % ooOoO0o
     if 7 - 7: Oo0Ooo / ooOoO0o + o0oOOo0O0Ooo
     if 38 - 38: o0oOOo0O0Ooo . O0 - OoO0O00 % I11i
    if ( oOo0o0 . last_rloc_probe != None ) :
     I1IIII = oOo0o0 . last_rloc_probe_reply
     if ( I1IIII == None ) : I1IIII = 0
     ii1i1III11iI = time . time ( ) - I1IIII
     if ( oOo0o0 . up_state ( ) and ii1i1III11iI >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 80 - 80: o0oOOo0O0Ooo
      oOo0o0 . state = LISP_RLOC_UNREACH_STATE
      oOo0o0 . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( oOo0o0 . rloc , False )
      i1111i11iiIII = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( oo0o00OO , False ) , i1111i11iiIII ) )
      if 100 - 100: iIii1I11I1II1 . OoOoOO00 . OoooooooOO / I1ii11iIi11i - I1IiiI * I11i
      if 5 - 5: i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1IiiI - II111iiii
      lisp_mark_rlocs_for_other_eids ( iio00oOO0OOO0O0 )
      if 15 - 15: I1Ii111
      if 38 - 38: O0
      if 50 - 50: i11iIiiIii * OoO0O00 + iII111i / O0 * oO0o % ooOoO0o
    oOo0o0 . last_rloc_probe = lisp_get_timestamp ( )
    if 6 - 6: OoO0O00 . o0oOOo0O0Ooo / Ii1I + Ii1I
    oo0Oo0Oo = "" if oOo0o0 . unreach_state ( ) == False else " unreachable"
    if 61 - 61: iIii1I11I1II1
    if 79 - 79: OoOoOO00 + Ii1I - oO0o - iIii1I11I1II1 + OoooooooOO
    if 87 - 87: ooOoO0o
    if 74 - 74: o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1IiiI - I1ii11iIi11i
    if 40 - 40: II111iiii . Oo0Ooo * I1Ii111
    if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
    if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
    Ii1IoO0 = ""
    O0O0oo0O0O = None
    if ( oOo0o0 . rloc_next_hop != None ) :
     OooOOOoOoo0O0 , O0O0oo0O0O = oOo0o0 . rloc_next_hop
     lisp_install_host_route ( oo0o00OO , O0O0oo0O0O , True )
     Ii1IoO0 = ", send on nh {}({})" . format ( O0O0oo0O0O , OooOOOoOoo0O0 )
     if 24 - 24: ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % iII111i - OOooOOo
     if 57 - 57: iIii1I11I1II1 . Oo0Ooo / O0
     if 86 - 86: I1IiiI + OOooOOo + IiII
     if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
     if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
    I1ioOoo0O = oOo0o0 . print_rloc_probe_rtt ( )
    oooO00OoO0O = oo0o00OO
    if ( oOo0o0 . translated_port != 0 ) :
     oooO00OoO0O += ":{}" . format ( oOo0o0 . translated_port )
     if 9 - 9: o0oOOo0O0Ooo / ooOoO0o + iII111i / II111iiii * Oo0Ooo
    oooO00OoO0O = red ( oooO00OoO0O , False )
    if ( oOo0o0 . rloc_name != None ) :
     oooO00OoO0O += " (" + blue ( oOo0o0 . rloc_name , False ) + ")"
     if 93 - 93: O0 % ooOoO0o
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( oOoOoO0oOO0o0 , oo0Oo0Oo ,
 oooO00OoO0O , I1ioOoo0O , Ii1IoO0 ) )
    if 48 - 48: i1IIi + iII111i - Ii1I
    if 9 - 9: o0oOOo0O0Ooo
    if 92 - 92: i11iIiiIii + OoooooooOO + O0 % oO0o
    if 90 - 90: Oo0Ooo * i11iIiiIii
    if 95 - 95: I1Ii111 % i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - I1Ii111
    if 69 - 69: iIii1I11I1II1 * oO0o
    if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
    if 64 - 64: I1IiiI % i11iIiiIii / oO0o
    if ( oOo0o0 . rloc_next_hop != None ) :
     IiIiIi1i11II = lisp_get_host_route_next_hop ( oo0o00OO )
     if ( IiIiIi1i11II ) : lisp_install_host_route ( oo0o00OO , IiIiIi1i11II , False )
     if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
     if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
     if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
     if 31 - 31: OoO0O00
     if 89 - 89: II111iiii
     if 33 - 33: OOooOOo / oO0o % OoOoOO00 * O0
    if ( oOo0o0 . rloc . is_null ( ) ) :
     oOo0o0 . rloc . copy_address ( oOO0O0OoooO00O . rloc )
     if 65 - 65: OoO0O00 % OoOoOO00 % I1ii11iIi11i / OoooooooOO
     if 85 - 85: O0 * OOooOOo % I1Ii111
     if 33 - 33: O0
     if 30 - 30: II111iiii . O0 . oO0o * I1ii11iIi11i + oO0o . o0oOOo0O0Ooo
     if 43 - 43: iIii1I11I1II1
    IIiiiiI1i = None if ( oOooO00OOoO . is_null ( ) ) else iIiiIIi1i111iI
    OooOooO00 = iIiiIIi1i111iI if ( oOooO00OOoO . is_null ( ) ) else oOooO00OOoO
    lisp_send_map_request ( lisp_sockets , 0 , IIiiiiI1i , OooOooO00 , oOo0o0 )
    Ooi1i1iIIi1IIi1 = oOO0O0OoooO00O
    if 83 - 83: OOooOOo / I1IiiI
    if 14 - 14: oO0o + iII111i . Oo0Ooo
    if 63 - 63: OOooOOo * II111iiii / i11iIiiIii - I1ii11iIi11i
    if 32 - 32: o0oOOo0O0Ooo - oO0o % IiII % I1ii11iIi11i
    if ( O0O0oo0O0O ) : lisp_install_host_route ( oo0o00OO , O0O0oo0O0O , False )
    if 99 - 99: ooOoO0o + oO0o - ooOoO0o % iII111i . iIii1I11I1II1
    if 55 - 55: ooOoO0o / i1IIi - ooOoO0o % ooOoO0o
    if 18 - 18: I11i - i1IIi / II111iiii
    if 60 - 60: I1IiiI . Oo0Ooo / IiII - OoooooooOO
    if 65 - 65: OoO0O00 - Ii1I
   if ( IiIiIi1i11II ) : lisp_install_host_route ( oo0o00OO , IiIiIi1i11II , True )
   if 98 - 98: OoOoOO00 * I1Ii111 * iIii1I11I1II1 * OoOoOO00
   if 15 - 15: Oo0Ooo
   if 100 - 100: IiII + I1ii11iIi11i + iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
   if 84 - 84: o0oOOo0O0Ooo * I11i
   OO += 1
   if ( ( OO % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 22 - 22: i1IIi + OOooOOo % OoooooooOO
   if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
   if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
 if 66 - 66: OoooooooOO
 if 90 - 90: IiII - OoOoOO00
 if 98 - 98: Oo0Ooo / oO0o . Ii1I
 if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
 if 37 - 37: iII111i - Ii1I . oO0o
 if 47 - 47: IiII / I1ii11iIi11i . o0oOOo0O0Ooo . ooOoO0o + OOooOOo . OOooOOo
 if 25 - 25: oO0o
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 43 - 43: Ii1I - o0oOOo0O0Ooo % oO0o - O0
 if 20 - 20: OoO0O00 . ooOoO0o / OoOoOO00 - OoOoOO00 . iII111i / OOooOOo
 if 39 - 39: iIii1I11I1II1 % ooOoO0o
 if 75 - 75: i1IIi * II111iiii * O0 * i11iIiiIii % iII111i / iII111i
 if ( lisp_i_am_itr == False ) : return
 if 36 - 36: IiII / I1IiiI % iII111i / iII111i
 if 38 - 38: OOooOOo * I1ii11iIi11i * I1Ii111 + I11i
 if 65 - 65: O0 + O0 * I1Ii111
 if 66 - 66: OOooOOo / O0 + i1IIi . O0 % I1ii11iIi11i - OoooooooOO
 if 16 - 16: I11i % iII111i
 if ( lisp_register_all_rtrs ) : return
 if 29 - 29: I1IiiI - ooOoO0o * OoO0O00 . i11iIiiIii % OoOoOO00 * o0oOOo0O0Ooo
 IIi111iIiI1I1 = rtr . print_address_no_iid ( )
 if 91 - 91: o0oOOo0O0Ooo
 if 59 - 59: I11i . I11i
 if 98 - 98: II111iiii
 if 20 - 20: iIii1I11I1II1
 if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
 if ( lisp_rtr_list . has_key ( IIi111iIiI1I1 ) == False ) : return
 if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( IIi111iIiI1I1 , False ) , bold ( updown , False ) ) )
 if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
 if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
 if 16 - 16: o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii . I1ii11iIi11i
 OoOO0o00OOO0o = "rtr%{}%{}" . format ( IIi111iIiI1I1 , updown )
 OoOO0o00OOO0o = lisp_command_ipc ( OoOO0o00OOO0o , "lisp-itr" )
 lisp_ipc ( OoOO0o00OOO0o , lisp_ipc_socket , "lisp-etr" )
 return
 if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
 if 83 - 83: OoooooooOO % I1ii11iIi11i . IiII + OOooOOo . iII111i - ooOoO0o
 if 100 - 100: o0oOOo0O0Ooo
 if 95 - 95: iII111i * oO0o * i1IIi
 if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
 if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
def lisp_process_rloc_probe_reply ( rloc_entry , source , port , map_reply , ttl ) :
 oOo0o0 = rloc_entry . rloc
 oOO000 = map_reply . nonce
 oo00oOO = map_reply . hop_count
 oOoOoO0oOO0o0 = bold ( "RLOC-probe reply" , False )
 i11Ii1iI1I1i1 = oOo0o0 . print_address_no_iid ( )
 IiIII1111i1ii = source . print_address_no_iid ( )
 II1iiii = lisp_rloc_probe_list
 oOOO0O0OOo0 = rloc_entry . json . json_string if rloc_entry . json else None
 if 11 - 11: I1IiiI
 if 92 - 92: iIii1I11I1II1 - I11i - OOooOOo / Ii1I . o0oOOo0O0Ooo . OoO0O00
 if 33 - 33: oO0o / I11i % ooOoO0o * I11i / oO0o - OoOoOO00
 if 89 - 89: iIii1I11I1II1 . II111iiii + IiII
 if 8 - 8: I1ii11iIi11i / II111iiii / II111iiii
 if 62 - 62: I11i - iII111i . Ii1I
 IiiIIi1 = i11Ii1iI1I1i1
 if ( II1iiii . has_key ( IiiIIi1 ) == False ) :
  IiiIIi1 += ":" + str ( port )
  if ( II1iiii . has_key ( IiiIIi1 ) == False ) :
   IiiIIi1 = IiIII1111i1ii
   if ( II1iiii . has_key ( IiiIIi1 ) == False ) :
    IiiIIi1 += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( oOoOoO0oOO0o0 , red ( i11Ii1iI1I1i1 , False ) , red ( IiIII1111i1ii ,
    # I1ii11iIi11i . ooOoO0o
 False ) , port ) )
    return
    if 43 - 43: I1Ii111 - IiII - OOooOOo
    if 2 - 2: Ii1I * i11iIiiIii
    if 100 - 100: i1IIi % I11i * Oo0Ooo
    if 71 - 71: Ii1I % iIii1I11I1II1 + OoOoOO00
    if 19 - 19: I1IiiI % I1IiiI / I1ii11iIi11i + iIii1I11I1II1 % iII111i / i11iIiiIii
    if 30 - 30: i1IIi % o0oOOo0O0Ooo - I1ii11iIi11i
    if 72 - 72: iIii1I11I1II1 + OOooOOo * ooOoO0o * O0 - I1IiiI
    if 36 - 36: I11i / II111iiii . oO0o - ooOoO0o % iII111i % OoOoOO00
 Oo0OO0000oooo = lisp_get_timestamp ( )
 for oOo0o0 , iIiiIIi1i111iI , oOooO00OOoO in lisp_rloc_probe_list [ IiiIIi1 ] :
  if ( lisp_i_am_rtr ) :
   if ( oOo0o0 . translated_port != 0 and oOo0o0 . translated_port != port ) :
    continue
    if 13 - 13: iIii1I11I1II1 - Oo0Ooo % IiII / iII111i - I1Ii111
    if 46 - 46: OoO0O00 / iII111i
  oOo0o0 . process_rloc_probe_reply ( Oo0OO0000oooo , oOO000 , iIiiIIi1i111iI , oOooO00OOoO , oo00oOO , ttl , oOOO0O0OOo0 )
  if 21 - 21: iIii1I11I1II1 / I1Ii111 * I1ii11iIi11i / Oo0Ooo . Oo0Ooo
 return
 if 2 - 2: Oo0Ooo + i11iIiiIii . I1ii11iIi11i * I1Ii111
 if 22 - 22: I1ii11iIi11i . i1IIi + I1ii11iIi11i / OoooooooOO - i11iIiiIii / iIii1I11I1II1
 if 96 - 96: o0oOOo0O0Ooo . I1Ii111 + Oo0Ooo . I11i + ooOoO0o
 if 33 - 33: OoO0O00 / OOooOOo % Oo0Ooo . o0oOOo0O0Ooo % II111iiii
 if 62 - 62: iII111i . OoooooooOO - i1IIi
 if 59 - 59: OoOoOO00 + i1IIi * OoooooooOO . oO0o
 if 38 - 38: I1ii11iIi11i / o0oOOo0O0Ooo
 if 95 - 95: iIii1I11I1II1 / OoOoOO00 % I1Ii111
def lisp_db_list_length ( ) :
 OO = 0
 for I1111I in lisp_db_list :
  OO += len ( I1111I . dynamic_eids ) if I1111I . dynamic_eid_configured ( ) else 1
  OO += len ( I1111I . eid . iid_list )
  if 54 - 54: OoooooooOO % Ii1I
 return ( OO )
 if 100 - 100: OOooOOo - I11i . O0 * i1IIi % OoooooooOO - ooOoO0o
 if 54 - 54: O0 + I11i
 if 71 - 71: OoOoOO00
 if 29 - 29: O0 . i11iIiiIii
 if 51 - 51: IiII
 if 53 - 53: O0
 if 19 - 19: o0oOOo0O0Ooo / iII111i % OoOoOO00
 if 65 - 65: o0oOOo0O0Ooo
def lisp_is_myeid ( eid ) :
 for I1111I in lisp_db_list :
  if ( eid . is_more_specific ( I1111I . eid ) ) : return ( True )
  if 89 - 89: iIii1I11I1II1 + OoooooooOO + i1IIi + OoooooooOO % IiII * OoO0O00
 return ( False )
 if 53 - 53: OOooOOo . IiII % I11i - OoO0O00 - Oo0Ooo
 if 58 - 58: I1Ii111 / OoooooooOO . I11i % I1Ii111
 if 8 - 8: Oo0Ooo % ooOoO0o / i11iIiiIii
 if 54 - 54: IiII
 if 85 - 85: OOooOOo - i1IIi
 if 10 - 10: I1ii11iIi11i
 if 3 - 3: ooOoO0o * O0 / o0oOOo0O0Ooo
 if 22 - 22: OoOoOO00 + OOooOOo . iII111i % iIii1I11I1II1 - I11i
 if 23 - 23: OoOoOO00 * I1Ii111
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
 if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
 if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
 if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
 if 25 - 25: OoO0O00 * oO0o
 if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
 if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 Oo0ooO0O0o00o = None
 if ( lisp_nonce_echo_list . has_key ( rloc_str ) ) :
  Oo0ooO0O0o00o = lisp_nonce_echo_list [ rloc_str ]
  if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
 return ( Oo0ooO0O0o00o )
 if 73 - 73: Oo0Ooo + II111iiii - IiII
 if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
 if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
 if 66 - 66: II111iiii * I1IiiI . Oo0Ooo * OoooooooOO % OoOoOO00 . II111iiii
 if 4 - 4: iII111i + I1Ii111 % OoOoOO00 / Ii1I
 if 94 - 94: OoO0O00
 if 35 - 35: I1ii11iIi11i % OoO0O00 + II111iiii % II111iiii / IiII - iII111i
 if 9 - 9: I1ii11iIi11i * o0oOOo0O0Ooo . oO0o
def lisp_decode_dist_name ( packet ) :
 OO = 0
 I1Iii1i11i = ""
 if 30 - 30: iIii1I11I1II1 * OoooooooOO . I1ii11iIi11i . i11iIiiIii . I1Ii111 * iIii1I11I1II1
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( OO == 255 ) : return ( [ None , None ] )
  I1Iii1i11i += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  OO += 1
  if 53 - 53: OoOoOO00 * I1ii11iIi11i % OoOoOO00 - OoO0O00 / I1ii11iIi11i / I1Ii111
  if 23 - 23: i11iIiiIii * OoooooooOO % OoooooooOO % i11iIiiIii . iIii1I11I1II1 + II111iiii
 packet = packet [ 1 : : ]
 return ( packet , I1Iii1i11i )
 if 49 - 49: i11iIiiIii - OoO0O00
 if 81 - 81: I11i - OOooOOo / oO0o - ooOoO0o
 if 60 - 60: OoO0O00 / I1ii11iIi11i % iII111i % i11iIiiIii * OoooooooOO * iII111i
 if 92 - 92: I11i % iIii1I11I1II1 * iII111i - OoooooooOO - I11i
 if 34 - 34: I1Ii111 / i1IIi / O0 / OoooooooOO
 if 55 - 55: I1Ii111 . I1IiiI * iIii1I11I1II1 / Ii1I . I1IiiI
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 if 85 - 85: II111iiii + I1ii11iIi11i
def lisp_write_flow_log ( flow_log ) :
 IIIii1i11111 = open ( "./logs/lisp-flow.log" , "a" )
 if 33 - 33: iII111i
 OO = 0
 for i1ii11III1 in flow_log :
  IIii1i = i1ii11III1 [ 3 ]
  iiiIi111i1i11 = IIii1i . print_flow ( i1ii11III1 [ 0 ] , i1ii11III1 [ 1 ] , i1ii11III1 [ 2 ] )
  IIIii1i11111 . write ( iiiIi111i1i11 )
  OO += 1
  if 64 - 64: Ii1I / Ii1I / OOooOOo / O0
 IIIii1i11111 . close ( )
 del ( flow_log )
 if 17 - 17: oO0o / I1Ii111 - Ii1I - i1IIi % oO0o
 OO = bold ( str ( OO ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( OO ) )
 return
 if 55 - 55: OOooOOo + oO0o - II111iiii
 if 5 - 5: iII111i * OoooooooOO . OoO0O00 % ooOoO0o + Ii1I
 if 59 - 59: OoOoOO00
 if 96 - 96: I1IiiI
 if 3 - 3: OoooooooOO
 if 3 - 3: IiII / O0 * i11iIiiIii . iII111i - iIii1I11I1II1
 if 56 - 56: ooOoO0o
def lisp_policy_command ( kv_pair ) :
 III1I1Iii1 = lisp_policy ( "" )
 O0o = None
 if 86 - 86: OoOoOO00 * iIii1I11I1II1 . OoOoOO00 / I1ii11iIi11i
 i111iiiI1I1Ii = [ ]
 for IiIIi1IiiIiI in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  i111iiiI1I1Ii . append ( lisp_policy_match ( ) )
  if 48 - 48: I1IiiI / OoooooooOO * IiII % Oo0Ooo
  if 67 - 67: i1IIi % Oo0Ooo . OoOoOO00 - Ii1I / OoooooooOO + iII111i
 for OoOOOo in kv_pair . keys ( ) :
  i11II = kv_pair [ OoOOOo ]
  if 90 - 90: iIii1I11I1II1 . Ii1I / i11iIiiIii . oO0o . I11i - I11i
  if 46 - 46: I11i
  if 2 - 2: I1Ii111 * oO0o
  if 93 - 93: I11i
  if ( OoOOOo == "instance-id" ) :
   for IiIIi1IiiIiI in range ( len ( i111iiiI1I1Ii ) ) :
    iiIiI1ii111Iiii = i11II [ IiIIi1IiiIiI ]
    if ( iiIiI1ii111Iiii == "" ) : continue
    oOoO00OoO0 = i111iiiI1I1Ii [ IiIIi1IiiIiI ]
    if ( oOoO00OoO0 . source_eid == None ) :
     oOoO00OoO0 . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 83 - 83: I11i
    if ( oOoO00OoO0 . dest_eid == None ) :
     oOoO00OoO0 . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 39 - 39: o0oOOo0O0Ooo * iIii1I11I1II1
    oOoO00OoO0 . source_eid . instance_id = int ( iiIiI1ii111Iiii )
    oOoO00OoO0 . dest_eid . instance_id = int ( iiIiI1ii111Iiii )
    if 13 - 13: iII111i + Oo0Ooo / oO0o / OOooOOo
    if 58 - 58: oO0o * I1ii11iIi11i % I1ii11iIi11i
  if ( OoOOOo == "source-eid" ) :
   for IiIIi1IiiIiI in range ( len ( i111iiiI1I1Ii ) ) :
    iiIiI1ii111Iiii = i11II [ IiIIi1IiiIiI ]
    if ( iiIiI1ii111Iiii == "" ) : continue
    oOoO00OoO0 = i111iiiI1I1Ii [ IiIIi1IiiIiI ]
    if ( oOoO00OoO0 . source_eid == None ) :
     oOoO00OoO0 . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 16 - 16: I11i / I1IiiI % I1IiiI
    o0OoO0000o = oOoO00OoO0 . source_eid . instance_id
    oOoO00OoO0 . source_eid . store_prefix ( iiIiI1ii111Iiii )
    oOoO00OoO0 . source_eid . instance_id = o0OoO0000o
    if 78 - 78: O0 % i11iIiiIii / IiII
    if 87 - 87: IiII % iIii1I11I1II1 * I1ii11iIi11i
  if ( OoOOOo == "destination-eid" ) :
   for IiIIi1IiiIiI in range ( len ( i111iiiI1I1Ii ) ) :
    iiIiI1ii111Iiii = i11II [ IiIIi1IiiIiI ]
    if ( iiIiI1ii111Iiii == "" ) : continue
    oOoO00OoO0 = i111iiiI1I1Ii [ IiIIi1IiiIiI ]
    if ( oOoO00OoO0 . dest_eid == None ) :
     oOoO00OoO0 . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 43 - 43: Ii1I - IiII / i11iIiiIii + OoOoOO00 + I1ii11iIi11i - o0oOOo0O0Ooo
    o0OoO0000o = oOoO00OoO0 . dest_eid . instance_id
    oOoO00OoO0 . dest_eid . store_prefix ( iiIiI1ii111Iiii )
    oOoO00OoO0 . dest_eid . instance_id = o0OoO0000o
    if 39 - 39: OoOoOO00 - i1IIi / oO0o % I11i * o0oOOo0O0Ooo * I1IiiI
    if 79 - 79: Ii1I
  if ( OoOOOo == "source-rloc" ) :
   for IiIIi1IiiIiI in range ( len ( i111iiiI1I1Ii ) ) :
    iiIiI1ii111Iiii = i11II [ IiIIi1IiiIiI ]
    if ( iiIiI1ii111Iiii == "" ) : continue
    oOoO00OoO0 = i111iiiI1I1Ii [ IiIIi1IiiIiI ]
    oOoO00OoO0 . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    oOoO00OoO0 . source_rloc . store_prefix ( iiIiI1ii111Iiii )
    if 56 - 56: I1ii11iIi11i
    if 40 - 40: OoooooooOO
  if ( OoOOOo == "destination-rloc" ) :
   for IiIIi1IiiIiI in range ( len ( i111iiiI1I1Ii ) ) :
    iiIiI1ii111Iiii = i11II [ IiIIi1IiiIiI ]
    if ( iiIiI1ii111Iiii == "" ) : continue
    oOoO00OoO0 = i111iiiI1I1Ii [ IiIIi1IiiIiI ]
    oOoO00OoO0 . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    oOoO00OoO0 . dest_rloc . store_prefix ( iiIiI1ii111Iiii )
    if 100 - 100: IiII - I11i
    if 79 - 79: iII111i % O0
  if ( OoOOOo == "rloc-record-name" ) :
   for IiIIi1IiiIiI in range ( len ( i111iiiI1I1Ii ) ) :
    iiIiI1ii111Iiii = i11II [ IiIIi1IiiIiI ]
    if ( iiIiI1ii111Iiii == "" ) : continue
    oOoO00OoO0 = i111iiiI1I1Ii [ IiIIi1IiiIiI ]
    oOoO00OoO0 . rloc_record_name = iiIiI1ii111Iiii
    if 73 - 73: Oo0Ooo
    if 13 - 13: OOooOOo - ooOoO0o
  if ( OoOOOo == "geo-name" ) :
   for IiIIi1IiiIiI in range ( len ( i111iiiI1I1Ii ) ) :
    iiIiI1ii111Iiii = i11II [ IiIIi1IiiIiI ]
    if ( iiIiI1ii111Iiii == "" ) : continue
    oOoO00OoO0 = i111iiiI1I1Ii [ IiIIi1IiiIiI ]
    oOoO00OoO0 . geo_name = iiIiI1ii111Iiii
    if 8 - 8: I1Ii111 % oO0o
    if 19 - 19: O0 + OoO0O00 - i1IIi % OoOoOO00 / Oo0Ooo + OoooooooOO
  if ( OoOOOo == "elp-name" ) :
   for IiIIi1IiiIiI in range ( len ( i111iiiI1I1Ii ) ) :
    iiIiI1ii111Iiii = i11II [ IiIIi1IiiIiI ]
    if ( iiIiI1ii111Iiii == "" ) : continue
    oOoO00OoO0 = i111iiiI1I1Ii [ IiIIi1IiiIiI ]
    oOoO00OoO0 . elp_name = iiIiI1ii111Iiii
    if 93 - 93: i11iIiiIii % OOooOOo . I11i * ooOoO0o
    if 90 - 90: OoO0O00
  if ( OoOOOo == "rle-name" ) :
   for IiIIi1IiiIiI in range ( len ( i111iiiI1I1Ii ) ) :
    iiIiI1ii111Iiii = i11II [ IiIIi1IiiIiI ]
    if ( iiIiI1ii111Iiii == "" ) : continue
    oOoO00OoO0 = i111iiiI1I1Ii [ IiIIi1IiiIiI ]
    oOoO00OoO0 . rle_name = iiIiI1ii111Iiii
    if 54 - 54: OOooOOo + Oo0Ooo * o0oOOo0O0Ooo - iIii1I11I1II1 * ooOoO0o
    if 76 - 76: i11iIiiIii * I1IiiI - IiII . o0oOOo0O0Ooo % iII111i . i11iIiiIii
  if ( OoOOOo == "json-name" ) :
   for IiIIi1IiiIiI in range ( len ( i111iiiI1I1Ii ) ) :
    iiIiI1ii111Iiii = i11II [ IiIIi1IiiIiI ]
    if ( iiIiI1ii111Iiii == "" ) : continue
    oOoO00OoO0 = i111iiiI1I1Ii [ IiIIi1IiiIiI ]
    oOoO00OoO0 . json_name = iiIiI1ii111Iiii
    if 69 - 69: O0 + o0oOOo0O0Ooo / ooOoO0o
    if 7 - 7: Ii1I . Ii1I . iIii1I11I1II1 / ooOoO0o
  if ( OoOOOo == "datetime-range" ) :
   for IiIIi1IiiIiI in range ( len ( i111iiiI1I1Ii ) ) :
    iiIiI1ii111Iiii = i11II [ IiIIi1IiiIiI ]
    oOoO00OoO0 = i111iiiI1I1Ii [ IiIIi1IiiIiI ]
    if ( iiIiI1ii111Iiii == "" ) : continue
    I1111III111ii = lisp_datetime ( iiIiI1ii111Iiii [ 0 : 19 ] )
    OOo00OOo = lisp_datetime ( iiIiI1ii111Iiii [ 19 : : ] )
    if ( I1111III111ii . valid_datetime ( ) and OOo00OOo . valid_datetime ( ) ) :
     oOoO00OoO0 . datetime_lower = I1111III111ii
     oOoO00OoO0 . datetime_upper = OOo00OOo
     if 70 - 70: O0
     if 42 - 42: I1Ii111 + OoooooooOO + I11i
     if 48 - 48: Oo0Ooo . IiII / ooOoO0o + I11i
     if 40 - 40: I1IiiI + I1ii11iIi11i * I1IiiI % Ii1I
     if 27 - 27: O0 / Oo0Ooo . oO0o
     if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
     if 36 - 36: i11iIiiIii * i1IIi % iII111i . Oo0Ooo
  if ( OoOOOo == "set-action" ) :
   III1I1Iii1 . set_action = i11II
   if 54 - 54: o0oOOo0O0Ooo % i1IIi % I1ii11iIi11i . o0oOOo0O0Ooo / OoOoOO00
  if ( OoOOOo == "set-record-ttl" ) :
   III1I1Iii1 . set_record_ttl = int ( i11II )
   if 55 - 55: O0 / OoooooooOO % Ii1I * O0 + iIii1I11I1II1 . iIii1I11I1II1
  if ( OoOOOo == "set-instance-id" ) :
   if ( III1I1Iii1 . set_source_eid == None ) :
    III1I1Iii1 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 55 - 55: Ii1I . OoooooooOO % Ii1I . IiII
   if ( III1I1Iii1 . set_dest_eid == None ) :
    III1I1Iii1 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 67 - 67: oO0o
   O0o = int ( i11II )
   III1I1Iii1 . set_source_eid . instance_id = O0o
   III1I1Iii1 . set_dest_eid . instance_id = O0o
   if 12 - 12: I1IiiI + OoooooooOO
  if ( OoOOOo == "set-source-eid" ) :
   if ( III1I1Iii1 . set_source_eid == None ) :
    III1I1Iii1 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
   III1I1Iii1 . set_source_eid . store_prefix ( i11II )
   if ( O0o != None ) : III1I1Iii1 . set_source_eid . instance_id = O0o
   if 19 - 19: OoooooooOO / IiII
  if ( OoOOOo == "set-destination-eid" ) :
   if ( III1I1Iii1 . set_dest_eid == None ) :
    III1I1Iii1 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
   III1I1Iii1 . set_dest_eid . store_prefix ( i11II )
   if ( O0o != None ) : III1I1Iii1 . set_dest_eid . instance_id = O0o
   if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
  if ( OoOOOo == "set-rloc-address" ) :
   III1I1Iii1 . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   III1I1Iii1 . set_rloc_address . store_address ( i11II )
   if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
  if ( OoOOOo == "set-rloc-record-name" ) :
   III1I1Iii1 . set_rloc_record_name = i11II
   if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
  if ( OoOOOo == "set-elp-name" ) :
   III1I1Iii1 . set_elp_name = i11II
   if 51 - 51: OoO0O00 - OoO0O00 * IiII
  if ( OoOOOo == "set-geo-name" ) :
   III1I1Iii1 . set_geo_name = i11II
   if 24 - 24: OoooooooOO . II111iiii
  if ( OoOOOo == "set-rle-name" ) :
   III1I1Iii1 . set_rle_name = i11II
   if 97 - 97: II111iiii . O0
  if ( OoOOOo == "set-json-name" ) :
   III1I1Iii1 . set_json_name = i11II
   if 18 - 18: iII111i
  if ( OoOOOo == "policy-name" ) :
   III1I1Iii1 . policy_name = i11II
   if 35 - 35: ooOoO0o / O0 / iIii1I11I1II1 - iIii1I11I1II1 + I11i
   if 8 - 8: I1Ii111 . oO0o % Oo0Ooo * OoooooooOO
   if 25 - 25: OoO0O00
   if 54 - 54: O0
   if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
   if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
 III1I1Iii1 . match_clauses = i111iiiI1I1Ii
 III1I1Iii1 . save_policy ( )
 return
 if 92 - 92: ooOoO0o - iII111i
 if 69 - 69: iII111i
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
if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
if 63 - 63: oO0o * OoO0O00 * oO0o
if 31 - 31: Oo0Ooo
if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
if 67 - 67: I1Ii111 . I1ii11iIi11i
if 2 - 2: O0 + I1Ii111
if 82 - 82: Ii1I / iII111i
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 13 - 13: I11i + iII111i
 oOoo0OoO = command
 if ( interface != "" ) : oOoo0OoO = interface + ": " + oOoo0OoO
 lprint ( "Send CLI command '{}' to hardware" . format ( oOoo0OoO ) )
 if 36 - 36: Ii1I * ooOoO0o * OoooooooOO + OoOoOO00
 commands = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 43 - 43: I1Ii111 - Oo0Ooo % i1IIi . II111iiii
 os . system ( "FastCli -c '{}'" . format ( commands ) )
 return
 if 80 - 80: IiII . iII111i + I1Ii111 + iII111i % Oo0Ooo
 if 98 - 98: i11iIiiIii . II111iiii + OoOoOO00
 if 25 - 25: I1IiiI + i11iIiiIii . I1Ii111 - I1ii11iIi11i
 if 67 - 67: OOooOOo - OOooOOo * I1IiiI - II111iiii . i1IIi + Oo0Ooo
 if 97 - 97: O0 / i11iIiiIii - o0oOOo0O0Ooo - OoOoOO00 . oO0o
 if 77 - 77: oO0o * oO0o . OoOoOO00 . i1IIi
 if 90 - 90: OOooOOo . Ii1I . II111iiii + Ii1I
def lisp_arista_is_alive ( prefix ) :
 ooO0ooooO = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 Oo0Ooo0O0 = commands . getoutput ( "FastCli -c '{}'" . format ( ooO0ooooO ) )
 if 2 - 2: I1Ii111 * OOooOOo + II111iiii - OoOoOO00
 if 94 - 94: Ii1I - iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
 if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
 if 96 - 96: OOooOOo % o0oOOo0O0Ooo / iIii1I11I1II1
 Oo0Ooo0O0 = Oo0Ooo0O0 . split ( "\n" ) [ 1 ]
 OoOoOOOo0oooo00 = Oo0Ooo0O0 . split ( " " )
 OoOoOOOo0oooo00 = OoOoOOOo0oooo00 [ - 1 ] . replace ( "\r" , "" )
 if 82 - 82: OoO0O00 + IiII . Ii1I * II111iiii * OoooooooOO
 if 67 - 67: i11iIiiIii % iII111i - OoOoOO00 + I1ii11iIi11i % i1IIi
 if 19 - 19: i11iIiiIii
 if 23 - 23: oO0o + I1ii11iIi11i + Oo0Ooo * OoooooooOO / Ii1I - OoO0O00
 return ( OoOoOOOo0oooo00 == "Y" )
 if 15 - 15: O0 . iIii1I11I1II1 - I1Ii111 + O0 + ooOoO0o / I1IiiI
 if 8 - 8: iII111i % O0 - OoOoOO00
 if 49 - 49: oO0o - OOooOOo / Ii1I / I1Ii111 . o0oOOo0O0Ooo . iII111i
 if 58 - 58: IiII + Ii1I
 if 89 - 89: Ii1I / Oo0Ooo * o0oOOo0O0Ooo / OoO0O00 + I11i
 if 4 - 4: I11i
 if 59 - 59: OoOoOO00 * I1ii11iIi11i / I1IiiI * II111iiii + OoOoOO00
 if 6 - 6: OoOoOO00 % oO0o + I11i * Ii1I
 if 13 - 13: I1ii11iIi11i / Oo0Ooo - I1Ii111 * OoOoOO00
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
def lisp_program_vxlan_hardware ( mc ) :
 if 29 - 29: OoO0O00
 if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
 if 63 - 63: O0 % iIii1I11I1II1 . o0oOOo0O0Ooo . I1IiiI * Ii1I % i1IIi
 if 47 - 47: II111iiii * I1ii11iIi11i
 if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
 if 71 - 71: I1ii11iIi11i * i1IIi
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 67 - 67: I1ii11iIi11i % OoOoOO00 . iII111i / Ii1I . I1IiiI
 if 48 - 48: IiII + II111iiii . I1IiiI % o0oOOo0O0Ooo
 if 57 - 57: OOooOOo . I11i % OoOoOO00
 if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 78 - 78: iII111i - OOooOOo / I1Ii111
 if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
 if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
 if 17 - 17: OoooooooOO % OoooooooOO + Oo0Ooo + I1Ii111
 OO0o0O0O0o0o = mc . eid . print_prefix_no_iid ( )
 oOo0o0 = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 56 - 56: I11i % OoOoOO00 - OoO0O00
 if 31 - 31: iII111i % i11iIiiIii - Ii1I / OOooOOo - I1Ii111
 if 60 - 60: o0oOOo0O0Ooo + Oo0Ooo . O0
 if 51 - 51: i11iIiiIii / iIii1I11I1II1 . I1IiiI - Ii1I * I1Ii111 . iII111i
 O0IiIiIIIIIII = commands . getoutput ( "ip route get {} | egrep vlan4094" . format ( OO0o0O0O0o0o ) )
 if 97 - 97: IiII - OOooOOo
 if ( O0IiIiIIIIIII != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( OO0o0O0O0o0o , False ) , O0IiIiIIIIIII ) )
  if 91 - 91: OoooooooOO % O0 * OoooooooOO . OOooOOo * I1Ii111 + OoO0O00
  return
  if 6 - 6: IiII + I11i / Ii1I / Oo0Ooo - oO0o
  if 31 - 31: i11iIiiIii % oO0o + ooOoO0o - i1IIi
  if 87 - 87: IiII + oO0o
  if 87 - 87: ooOoO0o
  if 47 - 47: i11iIiiIii
  if 84 - 84: Ii1I + ooOoO0o
  if 81 - 81: I1ii11iIi11i - iIii1I11I1II1
 I11I1I11IIIii = commands . getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( I11I1I11IIIii . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 95 - 95: i1IIi . I11i - OoO0O00 * Ii1I + OOooOOo + iII111i
 if ( I11I1I11IIIii . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 96 - 96: I1IiiI
 o0000O0oO00o = commands . getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( o0000O0oO00o == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 95 - 95: o0oOOo0O0Ooo * i1IIi - oO0o
 o0000O0oO00o = o0000O0oO00o . split ( "inet " ) [ 1 ]
 o0000O0oO00o = o0000O0oO00o . split ( "/" ) [ 0 ]
 if 94 - 94: i1IIi * oO0o + o0oOOo0O0Ooo % I11i % iII111i % O0
 if 3 - 3: I1ii11iIi11i / O0 * II111iiii . O0
 if 86 - 86: iIii1I11I1II1
 if 39 - 39: I11i
 if 77 - 77: OoO0O00 / OoO0O00 . ooOoO0o . Oo0Ooo * OoooooooOO * I11i
 if 63 - 63: iIii1I11I1II1 + ooOoO0o + o0oOOo0O0Ooo . ooOoO0o / o0oOOo0O0Ooo - IiII
 if 7 - 7: I1ii11iIi11i . iII111i . OOooOOo
 OOoOOOOOo0o = [ ]
 O0O0oOo = commands . getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for oOOo0ooO0 in O0O0oOo :
  if ( oOOo0ooO0 . find ( "vlan4094" ) == - 1 ) : continue
  if ( oOOo0ooO0 . find ( "(incomplete)" ) == - 1 ) : continue
  IiIiIi1i11II = oOOo0ooO0 . split ( " " ) [ 0 ]
  OOoOOOOOo0o . append ( IiIiIi1i11II )
  if 97 - 97: Ii1I / ooOoO0o . Ii1I * I1Ii111 + I1ii11iIi11i % IiII
  if 42 - 42: iII111i % OoOoOO00 . OoooooooOO
 IiIiIi1i11II = None
 I11II1i1i = o0000O0oO00o
 o0000O0oO00o = o0000O0oO00o . split ( "." )
 for IiIIi1IiiIiI in range ( 1 , 255 ) :
  o0000O0oO00o [ 3 ] = str ( IiIIi1IiiIiI )
  IiiIIi1 = "." . join ( o0000O0oO00o )
  if ( IiiIIi1 in OOoOOOOOo0o ) : continue
  if ( IiiIIi1 == I11II1i1i ) : continue
  IiIiIi1i11II = IiiIIi1
  break
  if 81 - 81: iII111i
 if ( IiIiIi1i11II == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 2 - 2: i1IIi
  return
  if 60 - 60: OOooOOo + I1ii11iIi11i / OoOoOO00 * i1IIi / O0
  if 24 - 24: Oo0Ooo . IiII % o0oOOo0O0Ooo . OOooOOo . I1IiiI + I1Ii111
  if 51 - 51: Oo0Ooo * I11i % i1IIi / iIii1I11I1II1 . OoooooooOO
  if 5 - 5: iIii1I11I1II1 % oO0o - II111iiii - OoOoOO00 / i1IIi
  if 20 - 20: II111iiii * OoOoOO00 . Ii1I . I1ii11iIi11i
  if 91 - 91: oO0o / OoOoOO00 % I1Ii111 % I1Ii111 / ooOoO0o
  if 39 - 39: OoO0O00 + OoO0O00 * iIii1I11I1II1 + I11i / OoO0O00
 OoOO0 = oOo0o0 . split ( "." )
 Oo0oOOOOO000 = lisp_hex_string ( OoOO0 [ 1 ] ) . zfill ( 2 )
 II1iiIiIi = lisp_hex_string ( OoOO0 [ 2 ] ) . zfill ( 2 )
 Oo0O = lisp_hex_string ( OoOO0 [ 3 ] ) . zfill ( 2 )
 Ii = "00:00:00:{}:{}:{}" . format ( Oo0oOOOOO000 , II1iiIiIi , Oo0O )
 Oo0oo = "0000.00{}.{}{}" . format ( Oo0oOOOOO000 , II1iiIiIi , Oo0O )
 ooO0o = "arp -i vlan4094 -s {} {}" . format ( IiIiIi1i11II , Ii )
 os . system ( ooO0o )
 if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
 if 39 - 39: OoooooooOO
 if 4 - 4: iIii1I11I1II1 - Oo0Ooo / OOooOOo % OoooooooOO . Oo0Ooo - Oo0Ooo
 if 41 - 41: II111iiii . o0oOOo0O0Ooo
 O0OoOo00 = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( Oo0oo , oOo0o0 )
 if 42 - 42: I11i / ooOoO0o % OoO0O00 * OoO0O00 * O0 . i1IIi
 lisp_send_to_arista ( O0OoOo00 , None )
 if 32 - 32: i11iIiiIii
 if 43 - 43: iIii1I11I1II1 + oO0o + OoooooooOO
 if 69 - 69: Oo0Ooo - o0oOOo0O0Ooo
 if 18 - 18: OoooooooOO
 if 52 - 52: i1IIi - II111iiii / i1IIi . I1Ii111 . OoooooooOO - IiII
 ii11iiiIiiiiiiIi1 = "ip route add {} via {}" . format ( OO0o0O0O0o0o , IiIiIi1i11II )
 os . system ( ii11iiiIiiiiiiIi1 )
 if 44 - 44: iIii1I11I1II1
 lprint ( "Hardware programmed with commands:" )
 ii11iiiIiiiiiiIi1 = ii11iiiIiiiiiiIi1 . replace ( OO0o0O0O0o0o , green ( OO0o0O0O0o0o , False ) )
 lprint ( "  " + ii11iiiIiiiiiiIi1 )
 lprint ( "  " + ooO0o )
 O0OoOo00 = O0OoOo00 . replace ( oOo0o0 , red ( oOo0o0 , False ) )
 lprint ( "  " + O0OoOo00 )
 return
 if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
 if 79 - 79: iII111i
 if 71 - 71: i1IIi / OoO0O00 / OOooOOo + I1Ii111
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
 if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
def lisp_clear_hardware_walk ( mc , parms ) :
 oOoOo0 = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( oOoOo0 ) )
 return ( [ True , None ] )
 if 12 - 12: I1ii11iIi11i - i11iIiiIii + I1IiiI . Oo0Ooo
 if 26 - 26: oO0o + I1Ii111 + IiII * o0oOOo0O0Ooo . oO0o
 if 95 - 95: OoOoOO00 . I1Ii111 / Ii1I . I1Ii111 % OoO0O00
 if 16 - 16: Ii1I / I1IiiI / I1IiiI - OoooooooOO
 if 13 - 13: OOooOOo / OoooooooOO
 if 7 - 7: II111iiii - ooOoO0o
 if 72 - 72: Ii1I
 if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list , lisp_gleaned_groups
 if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
 oOO0O = bold ( "User cleared" , False )
 OO = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( oOO0O , OO ) )
 if 18 - 18: I1Ii111
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
 lisp_map_cache = lisp_cache ( )
 if 24 - 24: i11iIiiIii + ooOoO0o
 if 80 - 80: IiII % I11i % oO0o
 if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
 if 70 - 70: iIii1I11I1II1
 if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
 lisp_rloc_probe_list = { }
 if 64 - 64: iII111i - Oo0Ooo
 if 73 - 73: iIii1I11I1II1 * I1Ii111 * OoO0O00
 if 68 - 68: ooOoO0o * Ii1I / I1ii11iIi11i * OoooooooOO + OoooooooOO . OoooooooOO
 if 50 - 50: I1IiiI % o0oOOo0O0Ooo
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 1 - 1: II111iiii
 if 22 - 22: I1Ii111 + iII111i
 if 50 - 50: iII111i % OoOoOO00 - II111iiii + II111iiii / OoO0O00
 if 69 - 69: Ii1I * II111iiii
 if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
 lisp_rtr_list = { }
 if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
 if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
 if 10 - 10: Ii1I / Oo0Ooo - i1IIi
 if 11 - 11: I11i * iII111i
 lisp_gleaned_groups = { }
 if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
 if 2 - 2: oO0o + I11i / I1Ii111 . I11i
 if 59 - 59: Ii1I
 if 47 - 47: iII111i % iII111i
 lisp_process_data_plane_restart ( True )
 return
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
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 48 - 48: I1Ii111 * oO0o / o0oOOo0O0Ooo * OoOoOO00 * ooOoO0o
 IiI1IIiIiI1I = lisp_myrlocs [ 0 ]
 if 78 - 78: oO0o - II111iiii . II111iiii * I1Ii111 % O0 - iII111i
 if 59 - 59: Oo0Ooo - IiII
 if 6 - 6: OOooOOo - I1IiiI . IiII
 if 40 - 40: II111iiii
 if 13 - 13: OoOoOO00
 iiiIIiiIi = len ( packet ) + 28
 Ooo0oO = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( iiiIIiiIi ) , 0 , 64 ,
 17 , 0 , socket . htonl ( IiI1IIiIiI1I . address ) , socket . htonl ( rloc . address ) )
 Ooo0oO = lisp_ip_checksum ( Ooo0oO )
 if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
 o0oOo00 = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( iiiIIiiIi - 20 ) , 0 )
 if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
 if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 packet = lisp_packet ( Ooo0oO + o0oOo00 + packet )
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( IiI1IIiIiI1I )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( IiI1IIiIiI1I )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
 o0O00oo0O = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  IiIii = " {}" . format ( blue ( nat_info . hostname , False ) )
  oOoOoO0oOO0o0 = bold ( "RLOC-probe request" , False )
 else :
  IiIii = ""
  oOoOoO0oOO0o0 = bold ( "RLOC-probe reply" , False )
  if 46 - 46: OOooOOo
  if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( oOoOoO0oOO0o0 , o0O00oo0O , IiIii , packet . encap_port ) )
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
 if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
 if 32 - 32: I1Ii111 * I1IiiI + Ii1I
 if 30 - 30: OoooooooOO / I1IiiI . iIii1I11I1II1 / ooOoO0o
 if 20 - 20: OoooooooOO * OOooOOo
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 77 - 77: Ii1I - OoooooooOO . OoOoOO00
 oo00o = lisp_sockets [ 3 ]
 packet . send_packet ( oo00o , packet . outer_dest )
 del ( packet )
 return
 if 94 - 94: ooOoO0o / ooOoO0o
 if 74 - 74: i11iIiiIii - oO0o % II111iiii . iIii1I11I1II1
 if 94 - 94: OOooOOo + oO0o / OoooooooOO + o0oOOo0O0Ooo - o0oOOo0O0Ooo . OOooOOo
 if 15 - 15: i11iIiiIii * O0 % iIii1I11I1II1 . OoooooooOO % oO0o + o0oOOo0O0Ooo
 if 37 - 37: oO0o + O0 . IiII * I1ii11iIi11i
 if 2 - 2: O0 . ooOoO0o
 if 97 - 97: i1IIi . Oo0Ooo
 if 81 - 81: OoOoOO00
def lisp_get_default_route_next_hops ( ) :
 if 81 - 81: O0
 if 57 - 57: oO0o - o0oOOo0O0Ooo % i11iIiiIii / OoOoOO00 . iIii1I11I1II1
 if 68 - 68: iII111i
 if 59 - 59: O0 - i11iIiiIii + OoooooooOO - iII111i - Oo0Ooo . OoooooooOO
 if ( lisp_is_macos ( ) ) :
  ooO0ooooO = "route -n get default"
  OoOo00oo0OooO = commands . getoutput ( ooO0ooooO ) . split ( "\n" )
  o0oOOOOOoOo0O = II1i = None
  for IIIii1i11111 in OoOo00oo0OooO :
   if ( IIIii1i11111 . find ( "gateway: " ) != - 1 ) : o0oOOOOOoOo0O = IIIii1i11111 . split ( ": " ) [ 1 ]
   if ( IIIii1i11111 . find ( "interface: " ) != - 1 ) : II1i = IIIii1i11111 . split ( ": " ) [ 1 ]
   if 95 - 95: OoOoOO00 * iIii1I11I1II1 / OoooooooOO % i1IIi
  return ( [ [ II1i , o0oOOOOOoOo0O ] ] )
  if 91 - 91: OOooOOo - OoOoOO00
  if 58 - 58: II111iiii . OOooOOo % II111iiii * oO0o % OoO0O00 % I11i
  if 71 - 71: Ii1I * II111iiii * I1IiiI
  if 22 - 22: oO0o
  if 96 - 96: ooOoO0o * iII111i . IiII
 ooO0ooooO = "ip route | egrep 'default via'"
 iIIII11 = commands . getoutput ( ooO0ooooO ) . split ( "\n" )
 if 77 - 77: OOooOOo - I11i % o0oOOo0O0Ooo
 iIiioOoooOo = [ ]
 for O0IiIiIIIIIII in iIIII11 :
  if ( O0IiIiIIIIIII . find ( " metric " ) != - 1 ) : continue
  i11iII1IiI = O0IiIiIIIIIII . split ( " " )
  try :
   IIiIiii1I1i = i11iII1IiI . index ( "via" ) + 1
   if ( IIiIiii1I1i >= len ( i11iII1IiI ) ) : continue
   iIIiiiiii = i11iII1IiI . index ( "dev" ) + 1
   if ( iIIiiiiii >= len ( i11iII1IiI ) ) : continue
  except :
   continue
   if 34 - 34: I1Ii111 . IiII % iII111i
   if 94 - 94: OOooOOo % i11iIiiIii . OOooOOo
  iIiioOoooOo . append ( [ i11iII1IiI [ iIIiiiiii ] , i11iII1IiI [ IIiIiii1I1i ] ] )
  if 55 - 55: OoOoOO00 . OoOoOO00 % o0oOOo0O0Ooo . I11i . I1ii11iIi11i - o0oOOo0O0Ooo
 return ( iIiioOoooOo )
 if 1 - 1: i11iIiiIii - i1IIi * oO0o - iIii1I11I1II1
 if 75 - 75: i1IIi * i11iIiiIii
 if 40 - 40: I1ii11iIi11i + OoO0O00
 if 8 - 8: i11iIiiIii - iIii1I11I1II1
 if 73 - 73: OoOoOO00
 if 25 - 25: iII111i / oO0o
 if 61 - 61: OoooooooOO . Ii1I . I11i + oO0o
def lisp_get_host_route_next_hop ( rloc ) :
 ooO0ooooO = "ip route | egrep '{} via'" . format ( rloc )
 O0IiIiIIIIIII = commands . getoutput ( ooO0ooooO ) . split ( " " )
 if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
 try : ooo = O0IiIiIIIIIII . index ( "via" ) + 1
 except : return ( None )
 if 61 - 61: I1IiiI / OOooOOo
 if ( ooo >= len ( O0IiIiIIIIIII ) ) : return ( None )
 return ( O0IiIiIIIIIII [ ooo ] )
 if 67 - 67: OoOoOO00
 if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
 if 30 - 30: O0 / oO0o * i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
 if 95 - 95: ooOoO0o % OOooOOo
 if 17 - 17: i1IIi + Ii1I
 if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
 if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 Ii1IoO0 = "none" if nh == None else nh
 if 26 - 26: oO0o / I1ii11iIi11i - oO0o
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , Ii1IoO0 ) )
 if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
 if ( nh == None ) :
  iI1IiI1IIi11I = "ip route {} {}/32" . format ( install , dest )
 else :
  iI1IiI1IIi11I = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
 os . system ( iI1IiI1IIi11I )
 return
 if 96 - 96: Ii1I
 if 90 - 90: II111iiii
 if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
 if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
 if 52 - 52: i11iIiiIii * ooOoO0o
 if 15 - 15: OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
 if 91 - 91: ooOoO0o
 if 47 - 47: II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 9 - 9: O0 + IiII
 IIIii1i11111 = open ( lisp_checkpoint_filename , "w" )
 for I1iII11ii1 in checkpoint_list :
  IIIii1i11111 . write ( I1iII11ii1 + "\n" )
  if 69 - 69: I1IiiI
 IIIii1i11111 . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
 if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
 if 86 - 86: ooOoO0o * OoOoOO00 + oO0o / II111iiii % OOooOOo
 if 89 - 89: O0 * Ii1I / OoO0O00 / OoOoOO00 % iII111i * iIii1I11I1II1
 if 72 - 72: iIii1I11I1II1 / iIii1I11I1II1 * I11i
 if 19 - 19: I1ii11iIi11i
 if 42 - 42: OoOoOO00 / IiII
 if 65 - 65: ooOoO0o - ooOoO0o * OoO0O00
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 99 - 99: I11i % ooOoO0o . I1Ii111
 IIIii1i11111 = open ( lisp_checkpoint_filename , "r" )
 if 34 - 34: ooOoO0o + oO0o + II111iiii . I1Ii111 . i1IIi
 OO = 0
 for I1iII11ii1 in IIIii1i11111 :
  OO += 1
  oOo = I1iII11ii1 . split ( " rloc " )
  ooOOo = [ ] if ( oOo [ 1 ] in [ "native-forward\n" , "\n" ] ) else oOo [ 1 ] . split ( ", " )
  if 14 - 14: OoO0O00 . ooOoO0o - i1IIi * I1IiiI
  if 24 - 24: iIii1I11I1II1 / I1Ii111
  iI1111Ii1I = [ ]
  for oOo0o0 in ooOOo :
   oo0OOOoO0OoO = lisp_rloc ( False )
   i11iII1IiI = oOo0o0 . split ( " " )
   oo0OOOoO0OoO . rloc . store_address ( i11iII1IiI [ 0 ] )
   oo0OOOoO0OoO . priority = int ( i11iII1IiI [ 1 ] )
   oo0OOOoO0OoO . weight = int ( i11iII1IiI [ 2 ] )
   iI1111Ii1I . append ( oo0OOOoO0OoO )
   if 16 - 16: OoOoOO00 * I1Ii111 - I1IiiI / I1Ii111
   if 64 - 64: I1ii11iIi11i . i1IIi % II111iiii % Oo0Ooo + oO0o - I1IiiI
  O0oOO0OOO = lisp_mapping ( "" , "" , iI1111Ii1I )
  if ( O0oOO0OOO != None ) :
   O0oOO0OOO . eid . store_prefix ( oOo [ 0 ] )
   O0oOO0OOO . checkpoint_entry = True
   O0oOO0OOO . map_cache_ttl = LISP_NMR_TTL * 60
   if ( iI1111Ii1I == [ ] ) : O0oOO0OOO . action = LISP_NATIVE_FORWARD_ACTION
   O0oOO0OOO . add_cache ( )
   continue
   if 24 - 24: IiII . II111iiii . II111iiii . OoOoOO00 . i11iIiiIii
   if 11 - 11: Ii1I
  OO -= 1
  if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
  if 44 - 44: iII111i
 IIIii1i11111 . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , OO , lisp_checkpoint_filename ) )
 return
 if 56 - 56: II111iiii / Oo0Ooo % IiII * II111iiii - iIii1I11I1II1 + ooOoO0o
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
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 42 - 42: OOooOOo - I1ii11iIi11i
 I1iII11ii1 = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 93 - 93: I1Ii111 + OOooOOo % ooOoO0o / I1Ii111 % OOooOOo . IiII
 for oo0OOOoO0OoO in mc . rloc_set :
  if ( oo0OOOoO0OoO . rloc . is_null ( ) ) : continue
  I1iII11ii1 += "{} {} {}, " . format ( oo0OOOoO0OoO . rloc . print_address_no_iid ( ) ,
 oo0OOOoO0OoO . priority , oo0OOOoO0OoO . weight )
  if 37 - 37: iII111i * oO0o / oO0o / Ii1I % I11i
  if 12 - 12: i11iIiiIii
 if ( mc . rloc_set != [ ] ) :
  I1iII11ii1 = I1iII11ii1 [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  I1iII11ii1 += "native-forward"
  if 62 - 62: oO0o + OOooOOo + oO0o + I1IiiI
  if 10 - 10: IiII - Oo0Ooo % ooOoO0o
 checkpoint_list . append ( I1iII11ii1 )
 return
 if 38 - 38: oO0o * o0oOOo0O0Ooo . I11i % II111iiii / I11i % Ii1I
 if 19 - 19: II111iiii / i11iIiiIii * II111iiii + OoOoOO00 - OoOoOO00
 if 7 - 7: OoOoOO00 - OoO0O00 % OoOoOO00 . I1ii11iIi11i % Oo0Ooo * iII111i
 if 90 - 90: IiII - OOooOOo + iIii1I11I1II1
 if 88 - 88: ooOoO0o . o0oOOo0O0Ooo . OOooOOo - I11i
 if 76 - 76: IiII % I1IiiI . iII111i
 if 5 - 5: ooOoO0o . oO0o - OoOoOO00 - OoooooooOO
def lisp_check_dp_socket ( ) :
 iIII11iii1 = lisp_ipc_dp_socket_name
 if ( os . path . exists ( iIII11iii1 ) == False ) :
  O0OO00Oo0 = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( iIII11iii1 , O0OO00Oo0 ) )
  return ( False )
  if 35 - 35: i1IIi / i11iIiiIii * OOooOOo * Ii1I / OoO0O00
 return ( True )
 if 59 - 59: i1IIi % IiII * iIii1I11I1II1
 if 71 - 71: O0 * oO0o % I1Ii111
 if 53 - 53: I11i - iIii1I11I1II1 - Ii1I / iII111i % I1Ii111
 if 59 - 59: OoooooooOO
 if 89 - 89: i1IIi / OoooooooOO . I1IiiI
 if 70 - 70: OOooOOo . I1Ii111
 if 20 - 20: i1IIi * IiII % II111iiii + IiII
def lisp_write_to_dp_socket ( entry ) :
 try :
  i1IIi11 = json . dumps ( entry )
  oOoooO0OO = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( oOoooO0OO , i1IIi11 ) )
  lisp_ipc_dp_socket . sendto ( i1IIi11 , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( i1IIi11 ) )
  if 54 - 54: OOooOOo
 return
 if 73 - 73: OoO0O00 . I1IiiI
 if 88 - 88: O0 . iIii1I11I1II1 . iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1 . Oo0Ooo
 if 8 - 8: iII111i
 if 78 - 78: i11iIiiIii % oO0o % ooOoO0o - I1Ii111
 if 53 - 53: oO0o + i1IIi . i11iIiiIii + OoO0O00 + Oo0Ooo
 if 27 - 27: OoooooooOO . I1IiiI + OoooooooOO % II111iiii . II111iiii - oO0o
 if 8 - 8: o0oOOo0O0Ooo . i1IIi . Ii1I - OoOoOO00 / iIii1I11I1II1
 if 11 - 11: oO0o - OOooOOo - I11i * I1IiiI
 if 25 - 25: OoOoOO00 - OOooOOo * I11i / iII111i + o0oOOo0O0Ooo - O0
def lisp_write_ipc_keys ( rloc ) :
 oo0o00OO = rloc . rloc . print_address_no_iid ( )
 IiI1iI1 = rloc . translated_port
 if ( IiI1iI1 != 0 ) : oo0o00OO += ":" + str ( IiI1iI1 )
 if ( lisp_rloc_probe_list . has_key ( oo0o00OO ) == False ) : return
 if 29 - 29: ooOoO0o
 for i11iII1IiI , oOo , i11ii in lisp_rloc_probe_list [ oo0o00OO ] :
  O0oOO0OOO = lisp_map_cache . lookup_cache ( oOo , True )
  if ( O0oOO0OOO == None ) : continue
  lisp_write_ipc_map_cache ( True , O0oOO0OOO )
  if 60 - 60: ooOoO0o / I1ii11iIi11i * i1IIi - IiII . II111iiii
 return
 if 65 - 65: oO0o * IiII
 if 97 - 97: IiII % OoO0O00 . OoOoOO00 - Ii1I
 if 28 - 28: O0 . I11i . I1IiiI - Ii1I - iII111i - iIii1I11I1II1
 if 14 - 14: OOooOOo + ooOoO0o
 if 56 - 56: o0oOOo0O0Ooo - OoOoOO00 - Ii1I
 if 50 - 50: I1ii11iIi11i
 if 24 - 24: ooOoO0o
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 19 - 19: oO0o
 if 97 - 97: IiII
 if 36 - 36: II111iiii
 if 83 - 83: I11i . ooOoO0o
 IiI1III = "add" if add_or_delete else "delete"
 I1iII11ii1 = { "type" : "map-cache" , "opcode" : IiI1III }
 if 57 - 57: IiII
 OO00o0o0oo = ( mc . group . is_null ( ) == False )
 if ( OO00o0o0oo ) :
  I1iII11ii1 [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  I1iII11ii1 [ "rles" ] = [ ]
 else :
  I1iII11ii1 [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  I1iII11ii1 [ "rlocs" ] = [ ]
  if 34 - 34: I1ii11iIi11i + i11iIiiIii - I1ii11iIi11i / OoOoOO00 + i1IIi . i11iIiiIii
 I1iII11ii1 [ "instance-id" ] = str ( mc . eid . instance_id )
 if 48 - 48: I1ii11iIi11i % OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii / OoOoOO00
 if ( OO00o0o0oo ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for O00oo0ooo0O in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    IiiIIi1 = O00oo0ooo0O . address . print_address_no_iid ( )
    IiI1iI1 = str ( 4341 ) if O00oo0ooo0O . translated_port == 0 else str ( O00oo0ooo0O . translated_port )
    if 73 - 73: OoOoOO00 + OOooOOo * II111iiii . OOooOOo % I1Ii111 % oO0o
    i11iII1IiI = { "rle" : IiiIIi1 , "port" : IiI1iI1 }
    iIIi1oOoO0OoooOoOO , oO00O0oO0O = O00oo0ooo0O . get_encap_keys ( )
    i11iII1IiI = lisp_build_json_keys ( i11iII1IiI , iIIi1oOoO0OoooOoOO , oO00O0oO0O , "encrypt-key" )
    I1iII11ii1 [ "rles" ] . append ( i11iII1IiI )
    if 12 - 12: i1IIi - I1IiiI - OOooOOo - i11iIiiIii % oO0o
    if 89 - 89: Ii1I - OOooOOo / ooOoO0o - IiII + iIii1I11I1II1 + OoO0O00
 else :
  for oOo0o0 in mc . rloc_set :
   if ( oOo0o0 . rloc . is_ipv4 ( ) == False and oOo0o0 . rloc . is_ipv6 ( ) == False ) :
    continue
    if 40 - 40: OoO0O00
   if ( oOo0o0 . up_state ( ) == False ) : continue
   if 69 - 69: iIii1I11I1II1 + OoOoOO00 * O0 - OoooooooOO / OOooOOo
   IiI1iI1 = str ( 4341 ) if oOo0o0 . translated_port == 0 else str ( oOo0o0 . translated_port )
   if 52 - 52: IiII % OOooOOo . II111iiii + IiII + i11iIiiIii * iIii1I11I1II1
   i11iII1IiI = { "rloc" : oOo0o0 . rloc . print_address_no_iid ( ) , "priority" :
 str ( oOo0o0 . priority ) , "weight" : str ( oOo0o0 . weight ) , "port" :
 IiI1iI1 }
   iIIi1oOoO0OoooOoOO , oO00O0oO0O = oOo0o0 . get_encap_keys ( )
   i11iII1IiI = lisp_build_json_keys ( i11iII1IiI , iIIi1oOoO0OoooOoOO , oO00O0oO0O , "encrypt-key" )
   I1iII11ii1 [ "rlocs" ] . append ( i11iII1IiI )
   if 21 - 21: OoooooooOO + iIii1I11I1II1 + OoOoOO00 . II111iiii . Ii1I / iII111i
   if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
   if 70 - 70: oO0o - I1IiiI + Ii1I
 if ( dont_send == False ) : lisp_write_to_dp_socket ( I1iII11ii1 )
 return ( I1iII11ii1 )
 if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
 if 37 - 37: o0oOOo0O0Ooo
 if 57 - 57: iII111i / i1IIi / i1IIi + IiII
 if 75 - 75: IiII / O0
 if 72 - 72: I11i
 if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
 if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 23 - 23: OoOoOO00 . oO0o - iII111i
 if 27 - 27: Oo0Ooo * OOooOOo - OoOoOO00
 if 1 - 1: II111iiii * i11iIiiIii . OoooooooOO
 if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
 iIIi1oOoO0OoooOoOO = keys [ 1 ] . encrypt_key
 oO00O0oO0O = keys [ 1 ] . icv_key
 if 88 - 88: I1Ii111
 if 16 - 16: Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . OoooooooOO * OoO0O00
 if 50 - 50: II111iiii + I11i . OoooooooOO . I1Ii111 - OOooOOo
 if 83 - 83: oO0o
 O00OoOo = rloc_addr . split ( ":" )
 if ( len ( O00OoOo ) == 1 ) :
  I1iII11ii1 = { "type" : "decap-keys" , "rloc" : O00OoOo [ 0 ] }
 else :
  I1iII11ii1 = { "type" : "decap-keys" , "rloc" : O00OoOo [ 0 ] , "port" : O00OoOo [ 1 ] }
  if 64 - 64: iII111i - OOooOOo % OoOoOO00
 I1iII11ii1 = lisp_build_json_keys ( I1iII11ii1 , iIIi1oOoO0OoooOoOO , oO00O0oO0O , "decrypt-key" )
 if 27 - 27: Ii1I % II111iiii . Oo0Ooo
 lisp_write_to_dp_socket ( I1iII11ii1 )
 return
 if 31 - 31: i11iIiiIii % ooOoO0o + I1IiiI * i1IIi
 if 24 - 24: II111iiii + iII111i . I1Ii111
 if 29 - 29: IiII + Oo0Ooo + iII111i / OoO0O00
 if 69 - 69: I1IiiI % I1IiiI . OoooooooOO - ooOoO0o / I11i
 if 32 - 32: iIii1I11I1II1 % oO0o / I1Ii111
 if 42 - 42: I11i / I1ii11iIi11i - I1IiiI * iII111i / I1IiiI / i11iIiiIii
 if 75 - 75: Oo0Ooo + IiII / I11i % I11i % IiII / I1Ii111
 if 95 - 95: OoOoOO00
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 78 - 78: I11i
 entry [ "keys" ] = [ ]
 ii1i1I1111ii = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( ii1i1I1111ii )
 return ( entry )
 if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
 if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
 if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
 if 53 - 53: I1IiiI % I1IiiI
 if 80 - 80: OoO0O00 - i11iIiiIii / iII111i * I1ii11iIi11i / I1IiiI - I1Ii111
 if 85 - 85: IiII
 if 72 - 72: iII111i * OoOoOO00
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 65 - 65: iIii1I11I1II1 / iIii1I11I1II1 % O0 / II111iiii . OOooOOo . O0
 if 65 - 65: I11i
 if 35 - 35: o0oOOo0O0Ooo - i11iIiiIii
 if 78 - 78: ooOoO0o - II111iiii - i1IIi
 I1iII11ii1 = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 18 - 18: OoooooooOO % OoOoOO00 - IiII / oO0o . OOooOOo . I1IiiI
 if 77 - 77: I1ii11iIi11i . OoO0O00 / OoOoOO00 / O0
 if 67 - 67: ooOoO0o % I11i % oO0o
 if 74 - 74: II111iiii
 for I1111I in lisp_db_list :
  if ( I1111I . eid . is_ipv4 ( ) == False and I1111I . eid . is_ipv6 ( ) == False ) : continue
  IIIIII = { "instance-id" : str ( I1111I . eid . instance_id ) ,
 "eid-prefix" : I1111I . eid . print_prefix_no_iid ( ) }
  I1iII11ii1 [ "database-mappings" ] . append ( IIIIII )
  if 32 - 32: i1IIi % iIii1I11I1II1 . O0 % i11iIiiIii / i11iIiiIii
 lisp_write_to_dp_socket ( I1iII11ii1 )
 if 75 - 75: I1ii11iIi11i - IiII . II111iiii / i1IIi
 if 76 - 76: II111iiii * O0 - Oo0Ooo + OoooooooOO
 if 37 - 37: OoooooooOO + i11iIiiIii
 if 20 - 20: I1IiiI + iII111i + O0 * O0
 if 18 - 18: I11i - I11i . OoOoOO00 . ooOoO0o
 I1iII11ii1 = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( I1iII11ii1 )
 return
 if 31 - 31: ooOoO0o
 if 87 - 87: OoooooooOO + OOooOOo - I1ii11iIi11i / I1IiiI + ooOoO0o - Oo0Ooo
 if 19 - 19: ooOoO0o + I1ii11iIi11i - ooOoO0o
 if 17 - 17: I11i * i1IIi + iIii1I11I1II1 % I1IiiI
 if 44 - 44: IiII + I1IiiI . Ii1I % Oo0Ooo
 if 97 - 97: O0
 if 95 - 95: OoO0O00 % iII111i / I1IiiI * OoooooooOO
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 31 - 31: iIii1I11I1II1
 if 62 - 62: o0oOOo0O0Ooo - iII111i / II111iiii . o0oOOo0O0Ooo
 if 20 - 20: iIii1I11I1II1 % OOooOOo
 if 91 - 91: ooOoO0o
 I1iII11ii1 = { "type" : "interfaces" , "interfaces" : [ ] }
 if 96 - 96: I1IiiI . OOooOOo
 for II1i in lisp_myinterfaces . values ( ) :
  if ( II1i . instance_id == None ) : continue
  IIIIII = { "interface" : II1i . device ,
 "instance-id" : str ( II1i . instance_id ) }
  I1iII11ii1 [ "interfaces" ] . append ( IIIIII )
  if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
  if 34 - 34: IiII % oO0o
 lisp_write_to_dp_socket ( I1iII11ii1 )
 return
 if 54 - 54: I1IiiI
 if 80 - 80: OoOoOO00 . I1IiiI / I1ii11iIi11i . iII111i
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
def lisp_parse_auth_key ( value ) :
 iio00oOO0OOO0O0 = value . split ( "[" )
 III1IiiiiI111 = { }
 if ( len ( iio00oOO0OOO0O0 ) == 1 ) :
  III1IiiiiI111 [ 0 ] = value
  return ( III1IiiiiI111 )
  if 96 - 96: OoooooooOO * ooOoO0o * O0 % o0oOOo0O0Ooo / o0oOOo0O0Ooo * o0oOOo0O0Ooo
  if 53 - 53: OoOoOO00 + i11iIiiIii . i11iIiiIii - ooOoO0o - OOooOOo
 for iiIiI1ii111Iiii in iio00oOO0OOO0O0 :
  if ( iiIiI1ii111Iiii == "" ) : continue
  ooo = iiIiI1ii111Iiii . find ( "]" )
  IIIiI1i = iiIiI1ii111Iiii [ 0 : ooo ]
  try : IIIiI1i = int ( IIIiI1i )
  except : return
  if 76 - 76: I1Ii111
  III1IiiiiI111 [ IIIiI1i ] = iiIiI1ii111Iiii [ ooo + 1 : : ]
  if 63 - 63: OoOoOO00 + oO0o . IiII + I1ii11iIi11i - I1Ii111 % ooOoO0o
 return ( III1IiiiiI111 )
 if 7 - 7: i11iIiiIii . I1Ii111 . I1Ii111 / OoO0O00
 if 80 - 80: o0oOOo0O0Ooo . i1IIi * I1ii11iIi11i + OoOoOO00 % oO0o % oO0o
 if 75 - 75: I1IiiI
 if 53 - 53: I1IiiI / o0oOOo0O0Ooo / o0oOOo0O0Ooo - o0oOOo0O0Ooo
 if 48 - 48: OoOoOO00 / IiII
 if 24 - 24: IiII + OoooooooOO * Ii1I % iIii1I11I1II1
 if 22 - 22: I1Ii111 - I1ii11iIi11i . Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
 if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
 if 46 - 46: oO0o + OoOoOO00
 if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
 if 59 - 59: O0
 if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
 if 17 - 17: Ii1I % I1ii11iIi11i + I11i
 if 80 - 80: i1IIi . OoooooooOO % OoooooooOO . oO0o / OOooOOo
 if 85 - 85: OOooOOo
 if 80 - 80: ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
def lisp_reassemble ( packet ) :
 O00000OO00OO = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
 if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
 if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
 if 72 - 72: IiII / II111iiii
 if ( O00000OO00OO == 0 or O00000OO00OO == 0x4000 ) : return ( packet )
 if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
 if 21 - 21: I1ii11iIi11i
 if 60 - 60: i1IIi / OoO0O00 . Ii1I
 if 16 - 16: i11iIiiIii + OoOoOO00 % Oo0Ooo + I1ii11iIi11i * Ii1I / I1Ii111
 oOoO0O00o = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 OOo = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 26 - 26: iII111i
 iIiII11iIiI1 = ( O00000OO00OO & 0x2000 == 0 and ( O00000OO00OO & 0x1fff ) != 0 )
 I1iII11ii1 = [ ( O00000OO00OO & 0x1fff ) * 8 , OOo - 20 , packet , iIiII11iIiI1 ]
 if 49 - 49: I1IiiI * OoOoOO00 . OoOoOO00 % I1Ii111 * iIii1I11I1II1 . OOooOOo
 if 9 - 9: OoOoOO00 - O0 + Oo0Ooo
 if 89 - 89: IiII - iII111i + IiII
 if 39 - 39: oO0o % I11i . oO0o * I11i
 if 36 - 36: i1IIi / I1ii11iIi11i * iIii1I11I1II1
 if 44 - 44: Ii1I / I1Ii111
 if 81 - 81: OoooooooOO * I1IiiI * II111iiii . Oo0Ooo
 if 28 - 28: iII111i * I1IiiI + Oo0Ooo % I1ii11iIi11i / OoooooooOO * ooOoO0o
 if ( O00000OO00OO == 0x2000 ) :
  i1i1IIiII1I , OOO = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  i1i1IIiII1I = socket . ntohs ( i1i1IIiII1I )
  OOO = socket . ntohs ( OOO )
  if ( OOO not in [ 4341 , 8472 , 4789 ] and i1i1IIiII1I != 4341 ) :
   lisp_reassembly_queue [ oOoO0O00o ] = [ ]
   I1iII11ii1 [ 2 ] = None
   if 45 - 45: OoO0O00 + iIii1I11I1II1 + ooOoO0o - OoO0O00
   if 22 - 22: I1IiiI
   if 28 - 28: OoO0O00 / ooOoO0o % OoOoOO00 - Ii1I * i11iIiiIii + I1ii11iIi11i
   if 90 - 90: ooOoO0o * o0oOOo0O0Ooo + Ii1I / I11i % II111iiii
   if 59 - 59: I11i + iII111i + I11i
   if 84 - 84: I1IiiI * Ii1I . I1IiiI % OOooOOo * Ii1I % OoO0O00
 if ( lisp_reassembly_queue . has_key ( oOoO0O00o ) == False ) :
  lisp_reassembly_queue [ oOoO0O00o ] = [ ]
  if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
  if 42 - 42: oO0o / i1IIi . IiII
  if 12 - 12: i11iIiiIii . ooOoO0o
  if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
  if 88 - 88: OoooooooOO . I1IiiI
 i1IiIiiii = lisp_reassembly_queue [ oOoO0O00o ]
 if 40 - 40: o0oOOo0O0Ooo / I1ii11iIi11i + I1IiiI / Oo0Ooo
 if 83 - 83: i11iIiiIii
 if 86 - 86: OoO0O00 * oO0o + ooOoO0o % iII111i
 if 81 - 81: i11iIiiIii . II111iiii * I11i + Ii1I / O0 . Oo0Ooo
 if 29 - 29: IiII - IiII - OoooooooOO . Ii1I % OoooooooOO - OoOoOO00
 if ( len ( i1IiIiiii ) == 1 and i1IiIiiii [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( oOoO0O00o ) . zfill ( 4 ) ) )
  if 33 - 33: oO0o * OoO0O00 / i11iIiiIii - I1IiiI * OoO0O00
  return ( None )
  if 19 - 19: OoooooooOO
  if 34 - 34: OoOoOO00 . oO0o
  if 53 - 53: oO0o + OoooooooOO * ooOoO0o
  if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
  if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
 i1IiIiiii . append ( I1iII11ii1 )
 i1IiIiiii = sorted ( i1IiIiiii )
 if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
 if 80 - 80: II111iiii . i11iIiiIii
 if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
 if 33 - 33: iIii1I11I1II1
 IiiIIi1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 IiiIIi1 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 ooo00o0 = IiiIIi1 . print_address_no_iid ( )
 IiiIIi1 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 Ii1iIiIII1IiIiii = IiiIIi1 . print_address_no_iid ( )
 IiiIIi1 = red ( "{} -> {}" . format ( ooo00o0 , Ii1iIiIII1IiIiii ) , False )
 if 72 - 72: I1Ii111 * I1ii11iIi11i * Ii1I % II111iiii * Ii1I / O0
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if I1iII11ii1 [ 2 ] == None else "" , IiiIIi1 , lisp_hex_string ( oOoO0O00o ) . zfill ( 4 ) ,
 # I11i
 # i11iIiiIii - i1IIi * O0 * OoOoOO00 % oO0o . II111iiii
 lisp_hex_string ( O00000OO00OO ) . zfill ( 4 ) ) )
 if 80 - 80: i1IIi / IiII - O0
 if 89 - 89: I1IiiI * II111iiii / ooOoO0o
 if 85 - 85: I1ii11iIi11i / II111iiii . o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i
 if 94 - 94: Ii1I * IiII + IiII / o0oOOo0O0Ooo . I1Ii111 % iIii1I11I1II1
 if 83 - 83: o0oOOo0O0Ooo . Ii1I / i1IIi / IiII
 if ( i1IiIiiii [ 0 ] [ 0 ] != 0 or i1IiIiiii [ - 1 ] [ 3 ] == False ) : return ( None )
 OoOOo0o0o = i1IiIiiii [ 0 ]
 for oO in i1IiIiiii [ 1 : : ] :
  O00000OO00OO = oO [ 0 ]
  O0o0oOo00Oo0 , I11OO0 = OoOOo0o0o [ 0 ] , OoOOo0o0o [ 1 ]
  if ( O0o0oOo00Oo0 + I11OO0 != O00000OO00OO ) : return ( None )
  OoOOo0o0o = oO
  if 5 - 5: II111iiii % I11i * OOooOOo
 lisp_reassembly_queue . pop ( oOoO0O00o )
 if 66 - 66: OOooOOo - OOooOOo * I11i . I11i - iII111i
 if 4 - 4: O0 . IiII
 if 94 - 94: OoooooooOO . I1ii11iIi11i
 if 64 - 64: I1Ii111 % II111iiii + OoO0O00 % o0oOOo0O0Ooo
 if 37 - 37: iII111i - iIii1I11I1II1 / I1Ii111 + iIii1I11I1II1 % I1ii11iIi11i . OoO0O00
 packet = i1IiIiiii [ 0 ] [ 2 ]
 for oO in i1IiIiiii [ 1 : : ] : packet += oO [ 2 ] [ 20 : : ]
 if 79 - 79: I1ii11iIi11i / i11iIiiIii . i1IIi - I1Ii111 + I1IiiI
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( oOoO0O00o ) . zfill ( 4 ) , len ( packet ) ) )
 if 9 - 9: iIii1I11I1II1 / iIii1I11I1II1
 if 24 - 24: OOooOOo . I1IiiI % i11iIiiIii
 if 43 - 43: OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i + OoO0O00 . I1Ii111 . iII111i
 if 1 - 1: iII111i / OoO0O00 / OoOoOO00 * Oo0Ooo * OoooooooOO
 if 59 - 59: iII111i
 iiiIIiiIi = socket . htons ( len ( packet ) )
 Ii1I1i1IiiI = packet [ 0 : 2 ] + struct . pack ( "H" , iiiIIiiIi ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 14 - 14: oO0o . IiII + iIii1I11I1II1 - i1IIi
 if 46 - 46: i11iIiiIii * II111iiii / i11iIiiIii % i11iIiiIii * II111iiii + i11iIiiIii
 Ii1I1i1IiiI = lisp_ip_checksum ( Ii1I1i1IiiI )
 return ( Ii1I1i1IiiI + packet [ 20 : : ] )
 if 87 - 87: Oo0Ooo + OoO0O00 / II111iiii * OoooooooOO
 if 95 - 95: I1Ii111 * o0oOOo0O0Ooo + OoO0O00 % OoOoOO00 - ooOoO0o / OoOoOO00
 if 45 - 45: OoooooooOO / oO0o / o0oOOo0O0Ooo + Ii1I + O0 . iII111i
 if 34 - 34: iIii1I11I1II1 . o0oOOo0O0Ooo + ooOoO0o
 if 96 - 96: O0 / ooOoO0o
 if 82 - 82: OoO0O00 * OOooOOo * I11i * I1Ii111 % iIii1I11I1II1
 if 50 - 50: Ii1I * Ii1I % I11i / iIii1I11I1II1 / ooOoO0o / iII111i
 if 91 - 91: Ii1I - O0 . I11i - OoooooooOO * IiII . II111iiii
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 oo0o00OO = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( oo0o00OO ) ) : return ( oo0o00OO )
 if 38 - 38: I1IiiI + OoO0O00
 oo0o00OO = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( oo0o00OO ) ) : return ( oo0o00OO )
 if 11 - 11: iIii1I11I1II1 + i1IIi * IiII - Oo0Ooo
 if 66 - 66: I1Ii111 . Ii1I / I1ii11iIi11i / iIii1I11I1II1 + O0 / i1IIi
 if 72 - 72: ooOoO0o . II111iiii
 if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
 for IIIi1Ii111I in lisp_crypto_keys_by_rloc_decap :
  OO0o = IIIi1Ii111I . split ( ":" )
  if ( len ( OO0o ) == 1 ) : continue
  OO0o = OO0o [ 0 ] if len ( OO0o ) == 2 else ":" . join ( OO0o [ 0 : - 1 ] )
  if ( OO0o == oo0o00OO ) :
   oOoo0oO = lisp_crypto_keys_by_rloc_decap [ IIIi1Ii111I ]
   lisp_crypto_keys_by_rloc_decap [ oo0o00OO ] = oOoo0oO
   return ( oo0o00OO )
   if 18 - 18: o0oOOo0O0Ooo / OOooOOo
   if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
 return ( None )
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
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 iiIi111IiIiI = addr + ":" + str ( port )
 if 92 - 92: o0oOOo0O0Ooo * Ii1I % I1IiiI * O0 * Oo0Ooo * IiII
 if ( lisp_i_am_rtr ) :
  if ( lisp_rloc_probe_list . has_key ( addr ) ) : return ( addr )
  if 95 - 95: II111iiii * iII111i + I1IiiI + Oo0Ooo
  if 45 - 45: I1ii11iIi11i / Ii1I - i11iIiiIii . i1IIi
  if 63 - 63: I1ii11iIi11i % ooOoO0o
  if 82 - 82: iII111i
  if 94 - 94: OoooooooOO / iII111i * ooOoO0o / i1IIi * i11iIiiIii * II111iiii
  if 98 - 98: Ii1I * Ii1I / IiII
  for iIIIIiI in lisp_nat_state_info . values ( ) :
   for i1IIiiIIiII1 in iIIIIiI :
    if ( addr == i1IIiiIIiII1 . address ) : return ( iiIi111IiIiI )
    if 1 - 1: OOooOOo
    if 47 - 47: i11iIiiIii - I11i
  return ( addr )
  if 38 - 38: Oo0Ooo % OoooooooOO + iII111i
 return ( iiIi111IiIiI )
 if 31 - 31: OoO0O00 + I1Ii111 / iIii1I11I1II1
 if 11 - 11: ooOoO0o - OoOoOO00
 if 19 - 19: O0 . OoOoOO00 - i1IIi . oO0o
 if 96 - 96: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoO0O00 * iIii1I11I1II1 + ooOoO0o - ooOoO0o
 if 4 - 4: OoO0O00 - OOooOOo
 if 21 - 21: I1Ii111 * i11iIiiIii
 if 63 - 63: oO0o + OoOoOO00
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 50 - 50: o0oOOo0O0Ooo / Oo0Ooo * ooOoO0o * Ii1I
 return
 if 97 - 97: I1IiiI / oO0o + I1Ii111 + I1Ii111
 if 86 - 86: o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * ooOoO0o
 if 20 - 20: Ii1I * iII111i / ooOoO0o
 if 18 - 18: Oo0Ooo * Ii1I / i11iIiiIii . OoO0O00 + OoooooooOO
 if 23 - 23: I1IiiI - I1ii11iIi11i . O0 . OoOoOO00 . OoO0O00
 if 81 - 81: IiII * I11i - iIii1I11I1II1
 if 41 - 41: oO0o * I11i + I1IiiI - OoO0O00
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 63 - 63: Oo0Ooo * Ii1I - Ii1I
 if 76 - 76: OoO0O00 . IiII % iIii1I11I1II1 / I1IiiI + iIii1I11I1II1 . I1IiiI
 if 57 - 57: IiII - i1IIi * ooOoO0o
 if 5 - 5: oO0o . O0 * IiII / Ii1I + OoO0O00
 if 75 - 75: OOooOOo * OoOoOO00
 if 82 - 82: Ii1I
 if 83 - 83: I1IiiI
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 22 - 22: IiII / Ii1I + I1Ii111 % iIii1I11I1II1
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
 if 62 - 62: OoOoOO00 * oO0o - I1IiiI / Ii1I
 if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
 if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
 if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
 if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
 if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
 if 9 - 9: i1IIi % iII111i / Ii1I
 if 83 - 83: oO0o
def lisp_is_rloc_probe ( packet , rr ) :
 o0oOo00 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( o0oOo00 == False ) : return ( [ packet , None , None , None ] )
 if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
 i1i1IIiII1I = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 OOO = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 iI1oO0O00O0oo0 = ( socket . htons ( LISP_CTRL_PORT ) in [ i1i1IIiII1I , OOO ] )
 if ( iI1oO0O00O0oo0 == False ) : return ( [ packet , None , None , None ] )
 if 33 - 33: iII111i + I11i * ooOoO0o / O0
 if ( rr == 0 ) :
  oOoOoO0oOO0o0 = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( oOoOoO0oOO0o0 == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  oOoOoO0oOO0o0 = lisp_is_rloc_probe_reply ( packet [ 28 ] )
  if ( oOoOoO0oOO0o0 == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  oOoOoO0oOO0o0 = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( oOoOoO0oOO0o0 == False ) :
   oOoOoO0oOO0o0 = lisp_is_rloc_probe_reply ( packet [ 28 ] )
   if ( oOoOoO0oOO0o0 == False ) : return ( [ packet , None , None , None ] )
   if 72 - 72: O0 * iIii1I11I1II1 * i1IIi
   if 53 - 53: I11i * ooOoO0o - Oo0Ooo + o0oOOo0O0Ooo
   if 52 - 52: Ii1I % OoOoOO00 / oO0o / OOooOOo
   if 22 - 22: iIii1I11I1II1 * Oo0Ooo % i1IIi % i11iIiiIii + oO0o
   if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
   if 34 - 34: Oo0Ooo . i1IIi
 oo00Oo0 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 oo00Oo0 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 97 - 97: I11i
 if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
 if 20 - 20: oO0o % OoOoOO00
 if 93 - 93: I1ii11iIi11i - Ii1I % i1IIi / i1IIi
 if ( oo00Oo0 . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 82 - 82: OOooOOo
 if 27 - 27: I1Ii111 / IiII - i1IIi * Ii1I
 if 90 - 90: ooOoO0o
 if 100 - 100: iII111i * i1IIi . iII111i / O0 / OoO0O00 - oO0o
 oo00Oo0 = oo00Oo0 . print_address_no_iid ( )
 IiI1iI1 = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 O0000 = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 65 - 65: OoOoOO00 + ooOoO0o * OoO0O00 % OoooooooOO + OoooooooOO * OoooooooOO
 i11iII1IiI = bold ( "Receive(pcap)" , False )
 IIIii1i11111 = bold ( "from " + oo00Oo0 , False )
 III1I1Iii1 = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( i11iII1IiI , len ( packet ) , IIIii1i11111 , IiI1iI1 , III1I1Iii1 ) )
 if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
 return ( [ packet , oo00Oo0 , IiI1iI1 , O0000 ] )
 if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
 if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
 if 55 - 55: Oo0Ooo - OOooOOo - O0
 if 40 - 40: OoOoOO00 - OOooOOo
 if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
 if 35 - 35: II111iiii
 if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
 if 96 - 96: O0
 if 15 - 15: i1IIi . iIii1I11I1II1
 if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
 if 11 - 11: I1IiiI % Ii1I * i11iIiiIii % OOooOOo + II111iiii
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 61 - 61: I1Ii111 + I11i + I1IiiI
 OoOO0o00OOO0o = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 48 - 48: I11i
 lisp_write_to_dp_socket ( OoOO0o00OOO0o )
 return
 if 67 - 67: o0oOOo0O0Ooo
 if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
 if 61 - 61: i11iIiiIii / Ii1I - OOooOOo . I1ii11iIi11i
 if 89 - 89: ooOoO0o % i11iIiiIii
 if 57 - 57: Oo0Ooo / ooOoO0o - O0 . ooOoO0o
 if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
 if 75 - 75: Ii1I
 if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
def lisp_external_data_plane ( ) :
 ooO0ooooO = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( commands . getoutput ( ooO0ooooO ) != "" ) : return ( True )
 if 99 - 99: oO0o + I11i % i1IIi . iII111i
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
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
 if 53 - 53: Ii1I
 if 63 - 63: I11i % OoOoOO00
 if 46 - 46: iIii1I11I1II1 . II111iiii / OoooooooOO - ooOoO0o * iII111i
 if 52 - 52: I11i + iII111i
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 9 - 9: OoOoOO00 % II111iiii . I11i * Oo0Ooo
 OoOooO = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 26 - 26: IiII
 if ( do_clear == False ) :
  OoooOOo0Oo00o = OoOooO [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , OoooOOo0Oo00o )
  if 8 - 8: i1IIi - i1IIi - O0 - OOooOOo * OOooOOo * OOooOOo
  if 70 - 70: oO0o
 lisp_write_to_dp_socket ( OoOooO )
 return
 if 16 - 16: I1IiiI - OoooooooOO + OOooOOo
 if 64 - 64: OoOoOO00
 if 31 - 31: i11iIiiIii / Ii1I * iII111i * OoooooooOO + OoO0O00
 if 91 - 91: ooOoO0o * o0oOOo0O0Ooo - o0oOOo0O0Ooo * Oo0Ooo
 if 70 - 70: Oo0Ooo . I1IiiI / OoO0O00
 if 65 - 65: o0oOOo0O0Ooo * O0 / IiII + II111iiii + I1ii11iIi11i
 if 94 - 94: I11i / I1ii11iIi11i / I11i + iII111i % oO0o + I1ii11iIi11i
 if 65 - 65: Oo0Ooo
 if 66 - 66: iII111i . I1ii11iIi11i - Oo0Ooo
 if 84 - 84: IiII + Oo0Ooo / OoooooooOO
 if 20 - 20: IiII . ooOoO0o . I1ii11iIi11i * I1IiiI
 if 84 - 84: IiII / OOooOOo + I1IiiI . IiII % i11iIiiIii % I1IiiI
 if 33 - 33: OoOoOO00 - OoO0O00 / OoooooooOO
 if 62 - 62: II111iiii
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 41 - 41: OOooOOo * ooOoO0o
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 47 - 47: OOooOOo + I1Ii111 . OoooooooOO * oO0o / I11i + Ii1I
  if 75 - 75: IiII
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 66 - 66: o0oOOo0O0Ooo + oO0o
  I11i11i1 = msg [ "eid-prefix" ]
  if 36 - 36: Oo0Ooo / IiII % Ii1I / o0oOOo0O0Ooo * I1Ii111
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 83 - 83: iIii1I11I1II1 - Oo0Ooo - iIii1I11I1II1 * I1ii11iIi11i - II111iiii + IiII
  o0OoO0000o = int ( msg [ "instance-id" ] )
  if 84 - 84: I11i
  if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
  if 21 - 21: Ii1I
  if 72 - 72: I1Ii111 . OoooooooOO / I1Ii111 - Ii1I / I1ii11iIi11i * I1ii11iIi11i
  iIiiIIi1i111iI = lisp_address ( LISP_AFI_NONE , "" , 0 , o0OoO0000o )
  iIiiIIi1i111iI . store_prefix ( I11i11i1 )
  O0oOO0OOO = lisp_map_cache_lookup ( None , iIiiIIi1i111iI )
  if ( O0oOO0OOO == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( I11i11i1 ) )
   if 72 - 72: IiII . Ii1I + OoooooooOO * OoOoOO00 + Oo0Ooo . iII111i
   continue
   if 92 - 92: O0 * Ii1I - I1ii11iIi11i - IiII . OoO0O00 + I1IiiI
   if 59 - 59: i1IIi * OOooOOo % Oo0Ooo
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( I11i11i1 ) )
   if 44 - 44: iIii1I11I1II1 . OOooOOo
   continue
   if 57 - 57: II111iiii + I1Ii111
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 42 - 42: OoOoOO00 % O0
  OoOOoOOOO0OOo = msg [ "rlocs" ]
  if 93 - 93: ooOoO0o
  if 14 - 14: OOooOOo * OoO0O00
  if 75 - 75: iIii1I11I1II1 . I1IiiI
  if 22 - 22: OoOoOO00 . OoooooooOO * oO0o . O0
  for Ii1I1i1IiiiI in OoOOoOOOO0OOo :
   if ( Ii1I1i1IiiiI . has_key ( "rloc" ) == False ) : continue
   if 21 - 21: I1IiiI + Oo0Ooo / Ii1I * OoooooooOO
   o0O00oo0O = Ii1I1i1IiiiI [ "rloc" ]
   if ( o0O00oo0O == "no-address" ) : continue
   if 71 - 71: o0oOOo0O0Ooo % ooOoO0o / oO0o - oO0o / OoooooooOO
   oOo0o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   oOo0o0 . store_address ( o0O00oo0O )
   if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
   oo0OOOoO0OoO = O0oOO0OOO . get_rloc ( oOo0o0 )
   if ( oo0OOOoO0OoO == None ) : continue
   if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
   if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
   if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
   if 16 - 16: I11i
   I111I = 0 if Ii1I1i1IiiiI . has_key ( "packet-count" ) == False else Ii1I1i1IiiiI [ "packet-count" ]
   if 75 - 75: II111iiii . iII111i - OoooooooOO - O0 % OoO0O00 % I1IiiI
   iiI1I1I = 0 if Ii1I1i1IiiiI . has_key ( "byte-count" ) == False else Ii1I1i1IiiiI [ "byte-count" ]
   if 84 - 84: Ii1I . ooOoO0o % O0 . II111iiii / oO0o / o0oOOo0O0Ooo
   Oo0OO0000oooo = 0 if Ii1I1i1IiiiI . has_key ( "seconds-last-packet" ) == False else Ii1I1i1IiiiI [ "seconds-last-packet" ]
   if 82 - 82: iIii1I11I1II1 * iIii1I11I1II1 . I1ii11iIi11i
   if 7 - 7: I1Ii111 % O0 . iIii1I11I1II1
   oo0OOOoO0OoO . stats . packet_count += I111I
   oo0OOOoO0OoO . stats . byte_count += iiI1I1I
   oo0OOOoO0OoO . stats . last_increment = lisp_get_timestamp ( ) - Oo0OO0000oooo
   if 19 - 19: iIii1I11I1II1
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( I111I , iiI1I1I ,
 Oo0OO0000oooo , I11i11i1 , o0O00oo0O ) )
   if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
   if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
   if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
   if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
   if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
  if ( O0oOO0OOO . group . is_null ( ) and O0oOO0OOO . has_ttl_elapsed ( ) ) :
   I11i11i1 = green ( O0oOO0OOO . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( I11i11i1 ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , O0oOO0OOO . eid , None )
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
 if 72 - 72: OoOoOO00 . OoooooooOO - OOooOOo
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
 if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
 if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 71 - 71: oO0o
 if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
 if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
 if 16 - 16: I1Ii111 + O0 - O0 * iIii1I11I1II1 / iII111i
 if 4 - 4: iII111i
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  OoOO0o00OOO0o = "stats%{}" . format ( json . dumps ( msg ) )
  OoOO0o00OOO0o = lisp_command_ipc ( OoOO0o00OOO0o , "lisp-itr" )
  lisp_ipc ( OoOO0o00OOO0o , lisp_ipc_socket , "lisp-etr" )
  return
  if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
  if 32 - 32: iII111i
  if 59 - 59: OoOoOO00 - I1Ii111
  if 34 - 34: ooOoO0o . OoooooooOO / ooOoO0o + OoooooooOO
  if 24 - 24: OoooooooOO * I1ii11iIi11i / O0 / Oo0Ooo * I1IiiI / ooOoO0o
  if 33 - 33: Ii1I
  if 20 - 20: Ii1I + I11i
  if 98 - 98: OOooOOo
 OoOO0o00OOO0o = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( OoOO0o00OOO0o , msg ) )
 if 58 - 58: i11iIiiIii / OoOoOO00
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 18 - 18: ooOoO0o + O0 - OOooOOo + iIii1I11I1II1 . OOooOOo * iIii1I11I1II1
 OO0O0O0OO = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 64 - 64: OoOoOO00 + oO0o / OoooooooOO . i11iIiiIii / II111iiii
 for o0o in OO0O0O0OO :
  I111I = 0 if msg . has_key ( o0o ) == False else msg [ o0o ] [ "packet-count" ]
  if 3 - 3: oO0o - IiII . oO0o + Ii1I
  lisp_decap_stats [ o0o ] . packet_count += I111I
  if 2 - 2: o0oOOo0O0Ooo + i1IIi - I1IiiI / IiII - i1IIi + iIii1I11I1II1
  iiI1I1I = 0 if msg . has_key ( o0o ) == False else msg [ o0o ] [ "byte-count" ]
  if 89 - 89: IiII . oO0o . IiII
  lisp_decap_stats [ o0o ] . byte_count += iiI1I1I
  if 70 - 70: O0 * I1Ii111 * O0
  Oo0OO0000oooo = 0 if msg . has_key ( o0o ) == False else msg [ o0o ] [ "seconds-last-packet" ]
  if 27 - 27: iIii1I11I1II1 * OOooOOo . I1Ii111 / OoooooooOO % O0 - I1ii11iIi11i
  lisp_decap_stats [ o0o ] . last_increment = lisp_get_timestamp ( ) - Oo0OO0000oooo
  if 49 - 49: OoooooooOO . I1ii11iIi11i / OoooooooOO * oO0o
 return
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
 if 28 - 28: IiII + I11i
 if 1 - 1: OoooooooOO - i11iIiiIii . OoooooooOO - o0oOOo0O0Ooo - OOooOOo * I1Ii111
 if 56 - 56: Ii1I . OoO0O00
 if 43 - 43: iII111i * iII111i
 if 31 - 31: O0 - iIii1I11I1II1 . I11i . oO0o
 if 96 - 96: OoooooooOO * iIii1I11I1II1 * Oo0Ooo
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 OO0oO0o00Ooo0o00o , oo00Oo0 = punt_socket . recvfrom ( 4000 )
 if 23 - 23: i11iIiiIii - ooOoO0o
 O000Ooo0 = json . loads ( OO0oO0o00Ooo0o00o )
 if ( type ( O000Ooo0 ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( oo00Oo0 ) )
  if 4 - 4: OoO0O00 . I1IiiI
  return
  if 28 - 28: iII111i % Oo0Ooo % I1IiiI + iII111i
 Oo0ooo = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( Oo0ooo , oo00Oo0 , O000Ooo0 ) )
 if 15 - 15: OoOoOO00 * I11i - OOooOOo + I11i % Oo0Ooo . OoOoOO00
 if ( O000Ooo0 . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 98 - 98: i1IIi - II111iiii
  if 85 - 85: o0oOOo0O0Ooo + I1IiiI . OoOoOO00
  if 52 - 52: Ii1I / OoOoOO00 . OOooOOo * IiII . OoooooooOO
  if 6 - 6: i1IIi . oO0o % IiII . Oo0Ooo % I11i
  if 86 - 86: OoooooooOO + IiII % o0oOOo0O0Ooo . i1IIi . iII111i
 if ( O000Ooo0 [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( O000Ooo0 , lisp_send_sockets , lisp_ephem_port )
  return
  if 25 - 25: iII111i * I1ii11iIi11i + I11i - I1ii11iIi11i
 if ( O000Ooo0 [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( O000Ooo0 , punt_socket )
  return
  if 75 - 75: IiII
  if 74 - 74: o0oOOo0O0Ooo - iIii1I11I1II1
  if 92 - 92: i11iIiiIii * iIii1I11I1II1 - I1Ii111 . i1IIi
  if 23 - 23: O0 - O0 . I1Ii111 . I1IiiI - I1IiiI * i1IIi
  if 8 - 8: I1IiiI . I1ii11iIi11i + oO0o % oO0o * oO0o
 if ( O000Ooo0 [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 70 - 70: II111iiii + IiII + O0 / Ii1I - i11iIiiIii
  if 72 - 72: II111iiii - II111iiii
  if 44 - 44: o0oOOo0O0Ooo + OoooooooOO
  if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
  if 87 - 87: OOooOOo * OoO0O00
 if ( O000Ooo0 [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 61 - 61: iII111i - II111iiii . I1Ii111 % II111iiii / I11i
 if ( O000Ooo0 . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( oo00Oo0 ) )
  if 86 - 86: II111iiii
  return
  if 94 - 94: o0oOOo0O0Ooo % Ii1I * Ii1I % Oo0Ooo / I1ii11iIi11i
  if 40 - 40: Oo0Ooo . II111iiii / II111iiii - i1IIi
  if 91 - 91: Ii1I
  if 45 - 45: I1ii11iIi11i + Oo0Ooo
  if 72 - 72: I1ii11iIi11i
 OoO0o0OOOO = O000Ooo0 [ "interface" ]
 if ( OoO0o0OOOO == "" ) :
  o0OoO0000o = int ( O000Ooo0 [ "instance-id" ] )
  if ( o0OoO0000o == - 1 ) : return
 else :
  o0OoO0000o = lisp_get_interface_instance_id ( OoO0o0OOOO , None )
  if 5 - 5: i1IIi
  if 31 - 31: iII111i - OoooooooOO + oO0o / OoooooooOO + I1ii11iIi11i
  if 93 - 93: o0oOOo0O0Ooo * I1ii11iIi11i % I1IiiI * ooOoO0o
  if 37 - 37: OoO0O00 * OoooooooOO / oO0o * I11i * I1ii11iIi11i
  if 42 - 42: OoooooooOO - ooOoO0o . OOooOOo + OoOoOO00
 IIiiiiI1i = None
 if ( O000Ooo0 . has_key ( "source-eid" ) ) :
  oO0o0O00O00O = O000Ooo0 [ "source-eid" ]
  IIiiiiI1i = lisp_address ( LISP_AFI_NONE , oO0o0O00O00O , 0 , o0OoO0000o )
  if ( IIiiiiI1i . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( oO0o0O00O00O ) )
   return
   if 53 - 53: o0oOOo0O0Ooo
   if 55 - 55: ooOoO0o . i1IIi - ooOoO0o + O0 + I1IiiI
 OooOooO00 = None
 if ( O000Ooo0 . has_key ( "dest-eid" ) ) :
  iI1IIiIIii = O000Ooo0 [ "dest-eid" ]
  OooOooO00 = lisp_address ( LISP_AFI_NONE , iI1IIiIIii , 0 , o0OoO0000o )
  if ( OooOooO00 . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( iI1IIiIIii ) )
   return
   if 95 - 95: O0 % I1ii11iIi11i . O0 . OOooOOo * i11iIiiIii - oO0o
   if 2 - 2: OOooOOo + II111iiii
   if 30 - 30: IiII
   if 99 - 99: O0 / OoO0O00 * II111iiii . II111iiii
   if 14 - 14: OoOoOO00 * i1IIi - OoOoOO00 . OoooooooOO
   if 24 - 24: iIii1I11I1II1 + OOooOOo * iII111i % IiII % OOooOOo
   if 64 - 64: IiII . I1ii11iIi11i - o0oOOo0O0Ooo - ooOoO0o + OoooooooOO
   if 95 - 95: iII111i . I1ii11iIi11i + ooOoO0o + o0oOOo0O0Ooo % OoO0O00
 if ( IIiiiiI1i ) :
  oOo = green ( IIiiiiI1i . print_address ( ) , False )
  I1111I = lisp_db_for_lookups . lookup_cache ( IIiiiiI1i , False )
  if ( I1111I != None ) :
   if 50 - 50: iII111i * O0 % II111iiii
   if 80 - 80: OOooOOo - II111iiii - OoO0O00
   if 62 - 62: Ii1I . i11iIiiIii % OOooOOo
   if 44 - 44: i1IIi * I1ii11iIi11i % Ii1I . Ii1I * I11i + II111iiii
   if 15 - 15: i1IIi - I11i - I1Ii111 / OoO0O00 + Oo0Ooo + I1IiiI
   if ( I1111I . dynamic_eid_configured ( ) ) :
    II1i = lisp_allow_dynamic_eid ( OoO0o0OOOO , IIiiiiI1i )
    if ( II1i != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( I1111I , IIiiiiI1i , OoO0o0OOOO , II1i )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( oOo , OoO0o0OOOO ) )
     if 81 - 81: IiII
     if 54 - 54: I1IiiI % OoO0O00 % OoOoOO00
     if 12 - 12: II111iiii . O0 * i11iIiiIii . I11i
  else :
   lprint ( "Punt from non-EID source {}" . format ( oOo ) )
   if 98 - 98: II111iiii + i1IIi * oO0o % I1IiiI
   if 53 - 53: i11iIiiIii . I1ii11iIi11i - OOooOOo - OOooOOo
   if 97 - 97: I1IiiI % iII111i % OoooooooOO / ooOoO0o / i11iIiiIii
   if 7 - 7: O0 % IiII / o0oOOo0O0Ooo
   if 79 - 79: IiII + I1Ii111
   if 59 - 59: iII111i - oO0o . ooOoO0o / IiII * i11iIiiIii
 if ( OooOooO00 ) :
  O0oOO0OOO = lisp_map_cache_lookup ( IIiiiiI1i , OooOooO00 )
  if ( O0oOO0OOO == None or O0oOO0OOO . action == LISP_SEND_MAP_REQUEST_ACTION ) :
   if 61 - 61: I11i - Oo0Ooo * II111iiii + iIii1I11I1II1
   if 37 - 37: OoooooooOO % II111iiii / o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i . iIii1I11I1II1
   if 73 - 73: OoOoOO00
   if 44 - 44: Oo0Ooo / oO0o
   if 9 - 9: i1IIi % I1IiiI + OoO0O00 * ooOoO0o / iIii1I11I1II1 / iII111i
   if ( lisp_rate_limit_map_request ( IIiiiiI1i , OooOooO00 ) ) : return
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 IIiiiiI1i , OooOooO00 , None )
  else :
   oOo = green ( OooOooO00 . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( oOo ) )
   if 80 - 80: OOooOOo / O0 % IiII * OoOoOO00
   if 53 - 53: OOooOOo + i11iIiiIii
 return
 if 25 - 25: i11iIiiIii
 if 51 - 51: iII111i . ooOoO0o
 if 70 - 70: I11i / O0 - I11i + o0oOOo0O0Ooo . ooOoO0o . o0oOOo0O0Ooo
 if 6 - 6: I11i + II111iiii - I1Ii111
 if 45 - 45: i1IIi / iII111i + i11iIiiIii * I11i + ooOoO0o / OoooooooOO
 if 56 - 56: I11i + I1Ii111
 if 80 - 80: II111iiii . Ii1I + o0oOOo0O0Ooo / II111iiii / OoO0O00 + iIii1I11I1II1
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 I1iII11ii1 = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( I1iII11ii1 )
 return ( [ True , jdata ] )
 if 29 - 29: o0oOOo0O0Ooo + OoOoOO00 + ooOoO0o - I1ii11iIi11i
 if 64 - 64: O0 / OoooooooOO
 if 28 - 28: I1ii11iIi11i + oO0o . Oo0Ooo % iIii1I11I1II1 / I1Ii111
 if 8 - 8: O0 . I1IiiI * o0oOOo0O0Ooo + I1IiiI
 if 44 - 44: i1IIi % iII111i . i11iIiiIii / I11i + OoooooooOO
 if 21 - 21: OoOoOO00 . OoO0O00 . OoOoOO00 + OoOoOO00
 if 30 - 30: I1IiiI - iII111i - OOooOOo + oO0o
 if 51 - 51: Ii1I % O0 / II111iiii . Oo0Ooo
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 90 - 90: i11iIiiIii * II111iiii % iIii1I11I1II1 . I1ii11iIi11i / Oo0Ooo . OOooOOo
 if 77 - 77: OoO0O00
 if 95 - 95: II111iiii
 if 59 - 59: iIii1I11I1II1 % OOooOOo / OoOoOO00 * I1Ii111 * OoooooooOO * O0
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 43 - 43: OoO0O00 * I1IiiI * OOooOOo * O0 - O0 / o0oOOo0O0Ooo
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 77 - 77: I11i % I1Ii111 . IiII % OoooooooOO * o0oOOo0O0Ooo
 if 87 - 87: iII111i + IiII / ooOoO0o * ooOoO0o * OOooOOo
 if 97 - 97: I1Ii111
 if 47 - 47: iII111i / I1ii11iIi11i - Ii1I . II111iiii
 if 56 - 56: O0 - i1IIi % o0oOOo0O0Ooo + IiII
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 42 - 42: o0oOOo0O0Ooo . OOooOOo % I11i - OoOoOO00
 if 38 - 38: OoooooooOO
 if 27 - 27: O0 + I1ii11iIi11i % Ii1I . i1IIi + OoO0O00 + OoOoOO00
 if 22 - 22: II111iiii / I1IiiI + o0oOOo0O0Ooo * I1IiiI . OoooooooOO * OOooOOo
 if 49 - 49: I1ii11iIi11i * I1IiiI + OOooOOo + i11iIiiIii * I1ii11iIi11i . o0oOOo0O0Ooo
 if 36 - 36: o0oOOo0O0Ooo - i11iIiiIii
 if 37 - 37: O0 + IiII + I1IiiI
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 I11i11i1 = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( I11i11i1 ) ) :
  db . dynamic_eids [ I11i11i1 ] . last_packet = lisp_get_timestamp ( )
  return
  if 50 - 50: OoooooooOO . I1Ii111
  if 100 - 100: ooOoO0o * ooOoO0o - Ii1I
  if 13 - 13: iII111i . I11i * OoO0O00 . i1IIi . iIii1I11I1II1 - o0oOOo0O0Ooo
  if 68 - 68: Ii1I % o0oOOo0O0Ooo / OoooooooOO + Ii1I - Ii1I
  if 79 - 79: II111iiii / IiII
 Oo0O0oOoO0o0 = lisp_dynamic_eid ( )
 Oo0O0oOoO0o0 . dynamic_eid . copy_address ( eid )
 Oo0O0oOoO0o0 . interface = routed_interface
 Oo0O0oOoO0o0 . last_packet = lisp_get_timestamp ( )
 Oo0O0oOoO0o0 . get_timeout ( routed_interface )
 db . dynamic_eids [ I11i11i1 ] = Oo0O0oOoO0o0
 if 4 - 4: O0 - i11iIiiIii % ooOoO0o * O0 - ooOoO0o
 OOoo00oOoo = ""
 if ( input_interface != routed_interface ) :
  OOoo00oOoo = ", routed-interface " + routed_interface
  if 87 - 87: II111iiii * iIii1I11I1II1 - i11iIiiIii . Ii1I . Ii1I % OOooOOo
  if 27 - 27: o0oOOo0O0Ooo
 i1i1ii1Ii1 = green ( I11i11i1 , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( i1i1ii1Ii1 , input_interface , OOoo00oOoo , Oo0O0oOoO0o0 . timeout ) )
 if 96 - 96: IiII * OoO0O00 - I1ii11iIi11i % OoO0O00
 if 16 - 16: OoO0O00 * I1IiiI
 if 58 - 58: oO0o * II111iiii * O0
 if 89 - 89: I1Ii111 + IiII % I1ii11iIi11i
 if 80 - 80: Oo0Ooo + ooOoO0o + IiII
 OoOO0o00OOO0o = "learn%{}%{}" . format ( I11i11i1 , routed_interface )
 OoOO0o00OOO0o = lisp_command_ipc ( OoOO0o00OOO0o , "lisp-itr" )
 lisp_ipc ( OoOO0o00OOO0o , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 76 - 76: I1Ii111
 if 23 - 23: O0 % I1ii11iIi11i % iIii1I11I1II1
 if 49 - 49: iII111i + I1Ii111 % OoOoOO00
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
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 26 - 26: IiII - I1Ii111 + i11iIiiIii % ooOoO0o * i11iIiiIii + Oo0Ooo
 if 39 - 39: Ii1I - i1IIi + i11iIiiIii
 if 21 - 21: IiII
 if 76 - 76: o0oOOo0O0Ooo % Oo0Ooo + OoO0O00
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 36 - 36: OOooOOo . oO0o
 ooOOo000II = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 15 - 15: I1IiiI + ooOoO0o - o0oOOo0O0Ooo
 for ii1i1I1111ii in lisp_crypto_keys_by_rloc_decap :
  if 62 - 62: Ii1I - OOooOOo
  if 88 - 88: iIii1I11I1II1 * Oo0Ooo / II111iiii / IiII / OoO0O00 % ooOoO0o
  if 19 - 19: I11i * iII111i . O0 * iII111i % I1ii11iIi11i - OoOoOO00
  if 68 - 68: I1Ii111 - OoO0O00 % Ii1I + i1IIi . ooOoO0o
  if ( ii1i1I1111ii . find ( addr_str ) == - 1 ) : continue
  if 36 - 36: oO0o * iIii1I11I1II1 - O0 - IiII * O0 + i11iIiiIii
  if 76 - 76: OoO0O00 % O0 / Ii1I + I1IiiI
  if 23 - 23: I1IiiI % IiII . o0oOOo0O0Ooo
  if 2 - 2: I1ii11iIi11i
  if ( ii1i1I1111ii == addr_str ) : continue
  if 51 - 51: iIii1I11I1II1 / II111iiii / iIii1I11I1II1 / oO0o % i1IIi
  if 54 - 54: ooOoO0o
  if 47 - 47: I11i * I1IiiI / oO0o
  if 98 - 98: Ii1I / oO0o * O0 + I1Ii111 - I1Ii111 + iII111i
  I1iII11ii1 = lisp_crypto_keys_by_rloc_decap [ ii1i1I1111ii ]
  if ( I1iII11ii1 == ooOOo000II ) : continue
  if 4 - 4: i1IIi
  if 43 - 43: oO0o * ooOoO0o - I11i
  if 70 - 70: oO0o / Ii1I
  if 15 - 15: iIii1I11I1II1 % ooOoO0o % i11iIiiIii
  iIIIi1iiIii = I1iII11ii1 [ 1 ]
  if ( packet_icv != iIIIi1iiIii . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( ii1i1I1111ii , False ) ) )
   continue
   if 60 - 60: ooOoO0o - IiII % i1IIi
   if 5 - 5: oO0o
  lprint ( "Changing decap crypto key to {}" . format ( red ( ii1i1I1111ii , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = I1iII11ii1
  if 29 - 29: i1IIi . OoOoOO00 . i1IIi + oO0o . I1Ii111 + O0
 return
 if 62 - 62: I1ii11iIi11i . IiII + OoO0O00 - OoOoOO00 * O0 + I1Ii111
 if 58 - 58: oO0o . OoO0O00 / ooOoO0o
 if 61 - 61: I11i + I1Ii111
 if 27 - 27: ooOoO0o / i1IIi . oO0o - OoooooooOO
 if 48 - 48: ooOoO0o % ooOoO0o / OoooooooOO + i1IIi * oO0o + ooOoO0o
 if 69 - 69: iII111i . iII111i
 if 46 - 46: IiII * Oo0Ooo + I1Ii111
 if 79 - 79: IiII
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 89 - 89: IiII * I11i + I1ii11iIi11i * oO0o - II111iiii
 if 58 - 58: ooOoO0o . I1Ii111 / i1IIi % I1ii11iIi11i + o0oOOo0O0Ooo
 if 94 - 94: i11iIiiIii + I1Ii111 . iII111i - ooOoO0o % I1Ii111
 if 94 - 94: i11iIiiIii - OOooOOo - O0 * OoooooooOO - ooOoO0o
 if 35 - 35: iII111i . i11iIiiIii - OOooOOo % Oo0Ooo + Ii1I . iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo / OoO0O00 + I1IiiI % i11iIiiIii % i1IIi
 if 22 - 22: I1Ii111 * O0 % OoO0O00 * I1ii11iIi11i
 if 47 - 47: OoO0O00 / OOooOOo / OoOoOO00 % i11iIiiIii / OoOoOO00
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 oooO = dns_name . split ( "." )
 oooO = "." . join ( oooO [ 1 : : ] )
 return ( oooO == lisp_decent_dns_suffix )
 if 52 - 52: ooOoO0o / I11i % i11iIiiIii - I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
 if 67 - 67: OoOoOO00 / I1Ii111 + i11iIiiIii - IiII
 if 79 - 79: I11i . I11i - OoOoOO00
 if 86 - 86: OoO0O00 * Oo0Ooo . iIii1I11I1II1 * O0
 if 52 - 52: iII111i - i11iIiiIii + o0oOOo0O0Ooo + i1IIi
 if 58 - 58: OOooOOo - Ii1I * I1Ii111 - O0 . oO0o
 if 72 - 72: i1IIi * iII111i * Ii1I / o0oOOo0O0Ooo . I1Ii111 + i11iIiiIii
def lisp_get_decent_index ( eid ) :
 I11i11i1 = eid . print_prefix ( )
 I11I = hashlib . sha256 ( I11i11i1 ) . hexdigest ( )
 ooo = int ( I11I , 16 ) % lisp_decent_modulus
 return ( ooo )
 if 45 - 45: o0oOOo0O0Ooo . i1IIi - I1IiiI + iIii1I11I1II1 * O0 . I1Ii111
 if 61 - 61: I1Ii111 . i1IIi % OoooooooOO
 if 54 - 54: Oo0Ooo
 if 26 - 26: II111iiii
 if 15 - 15: OoooooooOO * oO0o
 if 53 - 53: OoO0O00 * i1IIi / Oo0Ooo / OoO0O00 * ooOoO0o
 if 77 - 77: iIii1I11I1II1 % I1IiiI + o0oOOo0O0Ooo + I1Ii111 * Oo0Ooo * i1IIi
def lisp_get_decent_dns_name ( eid ) :
 ooo = lisp_get_decent_index ( eid )
 return ( str ( ooo ) + "." + lisp_decent_dns_suffix )
 if 14 - 14: iIii1I11I1II1 * iIii1I11I1II1 - OOooOOo . iII111i / ooOoO0o
 if 54 - 54: OoOoOO00 - I1IiiI - iII111i
 if 49 - 49: i11iIiiIii * Oo0Ooo
 if 100 - 100: Oo0Ooo * oO0o
 if 85 - 85: OoooooooOO . IiII / IiII . ooOoO0o . IiII % II111iiii
 if 65 - 65: oO0o - OoO0O00 / iII111i + ooOoO0o
 if 80 - 80: o0oOOo0O0Ooo + II111iiii * Ii1I % OoOoOO00 % I1IiiI + I1ii11iIi11i
 if 46 - 46: Oo0Ooo / Oo0Ooo % iII111i % I1IiiI
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 iIiiIIi1i111iI = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 ooo = lisp_get_decent_index ( iIiiIIi1i111iI )
 return ( str ( ooo ) + "." + lisp_decent_dns_suffix )
 if 85 - 85: OoO0O00 - Ii1I / O0
 if 45 - 45: IiII + I1Ii111 / I11i
 if 84 - 84: iII111i % II111iiii
 if 86 - 86: IiII % II111iiii / i1IIi * I1ii11iIi11i - O0 * OOooOOo
 if 53 - 53: OOooOOo * oO0o + i1IIi % Oo0Ooo + II111iiii
 if 34 - 34: oO0o % iII111i / IiII . IiII + i11iIiiIii
 if 68 - 68: O0 % oO0o * IiII % O0
 if 55 - 55: O0 % I1IiiI % O0
 if 27 - 27: I1IiiI + I1ii11iIi11i * I1Ii111 % Ii1I - Oo0Ooo
 if 87 - 87: i11iIiiIii % OOooOOo - OoOoOO00 * ooOoO0o / Oo0Ooo
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 74 - 74: OoooooooOO * ooOoO0o - I11i / I1ii11iIi11i % iIii1I11I1II1
 OoO00oo00 = 28 if packet . inner_version == 4 else 48
 O0O0oOoOOoO0O = packet . packet [ OoO00oo00 : : ]
 oo0Oo00OO0000 = lisp_trace ( )
 if ( oo0Oo00OO0000 . decode ( O0O0oOoOOoO0O ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 38 - 38: II111iiii - I1Ii111
  if 9 - 9: O0 % OOooOOo / i1IIi + II111iiii % iIii1I11I1II1
 O0oO0o00OO0O = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 89 - 89: Oo0Ooo - I1ii11iIi11i . I1Ii111
 if 65 - 65: ooOoO0o % OOooOOo + OOooOOo % I1Ii111 . I1IiiI % O0
 if 46 - 46: OoO0O00 * I1Ii111 + iII111i . oO0o % OOooOOo / i11iIiiIii
 if 1 - 1: I1ii11iIi11i % O0 - I1ii11iIi11i / OoooooooOO / OoO0O00
 if 82 - 82: i1IIi % Ii1I
 if 85 - 85: I1Ii111 * i11iIiiIii * iIii1I11I1II1 % iIii1I11I1II1
 if ( O0oO0o00OO0O != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : O0oO0o00OO0O += ":{}" . format ( packet . encap_port )
  if 64 - 64: OoO0O00 / Ii1I
  if 79 - 79: Ii1I % OOooOOo
  if 39 - 39: I1ii11iIi11i / Ii1I - II111iiii . i1IIi
  if 59 - 59: II111iiii
  if 36 - 36: ooOoO0o . II111iiii - OoOoOO00 % I1ii11iIi11i * O0
 I1iII11ii1 = { }
 I1iII11ii1 [ "node" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 91 - 91: iII111i + Oo0Ooo / OoooooooOO * iIii1I11I1II1 - OoO0O00
 Oo000o0OOO = packet . outer_source
 if ( Oo000o0OOO . is_null ( ) ) : Oo000o0OOO = lisp_myrlocs [ 0 ]
 I1iII11ii1 [ "srloc" ] = Oo000o0OOO . print_address_no_iid ( )
 if 96 - 96: I1ii11iIi11i % OoO0O00 . Oo0Ooo . OOooOOo . OoooooooOO / oO0o
 if 15 - 15: I11i - i1IIi
 if 15 - 15: ooOoO0o % I1Ii111 * OoooooooOO % IiII + I1ii11iIi11i - Ii1I
 if 67 - 67: i1IIi % I1ii11iIi11i * OOooOOo . Oo0Ooo
 if 82 - 82: iII111i . O0 / Oo0Ooo / OoooooooOO
 if ( I1iII11ii1 [ "node" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  I1iII11ii1 [ "srloc" ] += ":{}" . format ( packet . inner_sport )
  if 68 - 68: OoooooooOO . iIii1I11I1II1 / iII111i / OOooOOo
  if 35 - 35: I1ii11iIi11i * I11i % o0oOOo0O0Ooo + i1IIi % iII111i / IiII
 I1iII11ii1 [ "hn" ] = lisp_hostname
 ii1i1I1111ii = ed + "-ts"
 I1iII11ii1 [ ii1i1I1111ii ] = lisp_get_timestamp ( )
 if 41 - 41: IiII . OOooOOo % ooOoO0o
 if 25 - 25: i1IIi - OoO0O00
 if 54 - 54: OOooOOo + oO0o + OoO0O00 . OoO0O00
 if 29 - 29: OOooOOo / IiII * OOooOOo + II111iiii . oO0o * o0oOOo0O0Ooo
 if 37 - 37: I1Ii111 . oO0o * IiII
 if 41 - 41: I1Ii111 - iIii1I11I1II1 + Oo0Ooo
 if ( O0oO0o00OO0O == "?" and I1iII11ii1 [ "node" ] == "ETR" ) :
  I1111I = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( I1111I != None and len ( I1111I . rloc_set ) >= 1 ) :
   O0oO0o00OO0O = I1111I . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 56 - 56: IiII - I1ii11iIi11i - I1ii11iIi11i . I1Ii111
   if 55 - 55: OoO0O00
 I1iII11ii1 [ "drloc" ] = O0oO0o00OO0O
 if 11 - 11: OoooooooOO - I1IiiI . I1IiiI % o0oOOo0O0Ooo
 if 56 - 56: I1Ii111
 if 23 - 23: ooOoO0o . I11i - OOooOOo
 if 40 - 40: OoOoOO00
 if ( O0oO0o00OO0O == "?" and reason != None ) :
  I1iII11ii1 [ "drloc" ] += " ({})" . format ( reason )
  if 44 - 44: O0 + Oo0Ooo - iII111i + iIii1I11I1II1 / i11iIiiIii * IiII
  if 49 - 49: Oo0Ooo
  if 87 - 87: I1Ii111 + iII111i / IiII / ooOoO0o * OoooooooOO / OOooOOo
  if 44 - 44: IiII . I1Ii111
  if 46 - 46: O0 - ooOoO0o . I1ii11iIi11i % oO0o / OoOoOO00
 if ( rloc_entry != None ) :
  I1iII11ii1 [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  I1iII11ii1 [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  I1iII11ii1 [ "latencies" ] = rloc_entry . recent_rloc_probe_latencies
  if 93 - 93: I1ii11iIi11i * o0oOOo0O0Ooo . I11i . I1ii11iIi11i % i1IIi + Ii1I
  if 63 - 63: I1IiiI / OoooooooOO
  if 16 - 16: OoOoOO00
  if 67 - 67: O0 . I1Ii111
  if 42 - 42: OoOoOO00 % I1ii11iIi11i * I1Ii111 * i1IIi . i1IIi % OOooOOo
  if 90 - 90: oO0o * Oo0Ooo * oO0o . Ii1I * i1IIi
 IIiiiiI1i = packet . inner_source . print_address ( )
 OooOooO00 = packet . inner_dest . print_address ( )
 if ( oo0Oo00OO0000 . packet_json == [ ] ) :
  i1IIi11 = { }
  i1IIi11 [ "seid" ] = IIiiiiI1i
  i1IIi11 [ "deid" ] = OooOooO00
  i1IIi11 [ "paths" ] = [ ]
  oo0Oo00OO0000 . packet_json . append ( i1IIi11 )
  if 47 - 47: OOooOOo
  if 38 - 38: I11i
  if 15 - 15: OoO0O00 / ooOoO0o . OoO0O00 - iIii1I11I1II1 + OoooooooOO - OoO0O00
  if 44 - 44: O0 . OOooOOo . o0oOOo0O0Ooo . I1ii11iIi11i - II111iiii
  if 71 - 71: I1ii11iIi11i + o0oOOo0O0Ooo . i11iIiiIii * oO0o . i1IIi
  if 40 - 40: OoO0O00 - IiII
 for i1IIi11 in oo0Oo00OO0000 . packet_json :
  if ( i1IIi11 [ "deid" ] != OooOooO00 ) : continue
  i1IIi11 [ "paths" ] . append ( I1iII11ii1 )
  break
  if 43 - 43: I1Ii111 + i11iIiiIii % iII111i % I1Ii111 - ooOoO0o
  if 85 - 85: IiII % iIii1I11I1II1 . I1Ii111
  if 38 - 38: iII111i - I1IiiI / ooOoO0o
  if 46 - 46: OOooOOo . O0 / i11iIiiIii . OOooOOo
  if 19 - 19: I11i / Oo0Ooo + I1Ii111
  if 43 - 43: I1ii11iIi11i
  if 18 - 18: I11i / OOooOOo % I11i - o0oOOo0O0Ooo
  if 22 - 22: iII111i
 O00O000 = False
 if ( len ( oo0Oo00OO0000 . packet_json ) == 1 and I1iII11ii1 [ "node" ] == "ETR" and
 oo0Oo00OO0000 . myeid ( packet . inner_dest ) ) :
  i1IIi11 = { }
  i1IIi11 [ "seid" ] = OooOooO00
  i1IIi11 [ "deid" ] = IIiiiiI1i
  i1IIi11 [ "paths" ] = [ ]
  oo0Oo00OO0000 . packet_json . append ( i1IIi11 )
  O00O000 = True
  if 41 - 41: OoooooooOO . iII111i
  if 65 - 65: i11iIiiIii * ooOoO0o * I1ii11iIi11i
  if 15 - 15: OoO0O00
  if 75 - 75: IiII - OOooOOo + OOooOOo / Oo0Ooo - iII111i + O0
  if 1 - 1: o0oOOo0O0Ooo . II111iiii % OoooooooOO - oO0o - I1Ii111 * o0oOOo0O0Ooo
  if 70 - 70: o0oOOo0O0Ooo * I1IiiI * OoOoOO00 / I11i * O0 / IiII
 oo0Oo00OO0000 . print_trace ( )
 O0O0oOoOOoO0O = oo0Oo00OO0000 . encode ( )
 if 99 - 99: II111iiii
 if 34 - 34: OOooOOo + OoOoOO00 * o0oOOo0O0Ooo + I1ii11iIi11i + IiII * i1IIi
 if 73 - 73: I1ii11iIi11i - IiII - O0 . oO0o + Oo0Ooo % iII111i
 if 68 - 68: I1ii11iIi11i - OoooooooOO
 if 5 - 5: I1ii11iIi11i * I1IiiI + OoooooooOO / Oo0Ooo
 if 18 - 18: OoO0O00 * iII111i % I1IiiI . OOooOOo * o0oOOo0O0Ooo
 if 58 - 58: iII111i . IiII + iIii1I11I1II1
 if 13 - 13: oO0o * I1Ii111 / I1Ii111 . I1IiiI
 O0OOOOoo0o = oo0Oo00OO0000 . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "srloc" ]
 if ( O0oO0o00OO0O == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( O0OOOOoo0o ) )
  oo0Oo00OO0000 . return_to_sender ( lisp_socket , O0OOOOoo0o , O0O0oOoOOoO0O )
  return ( False )
  if 5 - 5: iII111i % Oo0Ooo - oO0o . i1IIi - i11iIiiIii % I1ii11iIi11i
  if 79 - 79: I1IiiI
  if 24 - 24: I1IiiI / II111iiii - I1Ii111
  if 68 - 68: I1IiiI
  if 97 - 97: Ii1I + o0oOOo0O0Ooo / OoO0O00
  if 97 - 97: i11iIiiIii % iIii1I11I1II1 + II111iiii
 O0OOOOo0 = oo0Oo00OO0000 . packet_length ( )
 if 90 - 90: OOooOOo / I1IiiI
 if 28 - 28: OoooooooOO + i1IIi
 if 29 - 29: Oo0Ooo
 if 98 - 98: OOooOOo / Oo0Ooo % Ii1I * OoooooooOO - oO0o
 if 64 - 64: I1IiiI - I1IiiI
 if 90 - 90: iII111i - I1IiiI - II111iiii / OOooOOo + Ii1I
 Iii1ii1 = packet . packet [ 0 : OoO00oo00 ]
 III1I1Iii1 = struct . pack ( "HH" , socket . htons ( O0OOOOo0 ) , 0 )
 Iii1ii1 = Iii1ii1 [ 0 : OoO00oo00 - 4 ] + III1I1Iii1
 if ( packet . inner_version == 6 and I1iII11ii1 [ "node" ] == "ETR" and
 len ( oo0Oo00OO0000 . packet_json ) == 2 ) :
  o0oOo00 = Iii1ii1 [ OoO00oo00 - 8 : : ] + O0O0oOoOOoO0O
  o0oOo00 = lisp_udp_checksum ( IIiiiiI1i , OooOooO00 , o0oOo00 )
  Iii1ii1 = Iii1ii1 [ 0 : OoO00oo00 - 8 ] + o0oOo00 [ 0 : 8 ]
  if 11 - 11: Ii1I / ooOoO0o / i11iIiiIii - OoOoOO00 / ooOoO0o
  if 11 - 11: OoO0O00 - O0 / I11i + I1ii11iIi11i + Ii1I
  if 56 - 56: I1Ii111 * OoOoOO00 * iII111i - Oo0Ooo - I1IiiI % iIii1I11I1II1
  if 69 - 69: I1IiiI - I11i
  if 95 - 95: OOooOOo % OoooooooOO . OOooOOo * Ii1I
  if 38 - 38: I1IiiI - Oo0Ooo + I1Ii111 % II111iiii
 if ( O00O000 ) :
  if ( packet . inner_version == 4 ) :
   Iii1ii1 = Iii1ii1 [ 0 : 12 ] + Iii1ii1 [ 16 : 20 ] + Iii1ii1 [ 12 : 16 ] + Iii1ii1 [ 22 : 24 ] + Iii1ii1 [ 20 : 22 ] + Iii1ii1 [ 24 : : ]
   if 90 - 90: iIii1I11I1II1
  else :
   Iii1ii1 = Iii1ii1 [ 0 : 8 ] + Iii1ii1 [ 24 : 40 ] + Iii1ii1 [ 8 : 24 ] + Iii1ii1 [ 42 : 44 ] + Iii1ii1 [ 40 : 42 ] + Iii1ii1 [ 44 : : ]
   if 91 - 91: I1IiiI / iIii1I11I1II1 * OoO0O00 + iII111i * IiII + OoooooooOO
   if 63 - 63: I1IiiI / Ii1I
  OooOOOoOoo0O0 = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = OooOOOoOoo0O0
  if 31 - 31: i1IIi - oO0o
  if 99 - 99: iII111i - i11iIiiIii + oO0o
  if 66 - 66: Oo0Ooo * I11i . iIii1I11I1II1 - OoO0O00
  if 11 - 11: I1Ii111 + iIii1I11I1II1 * O0 * Oo0Ooo
  if 66 - 66: OoooooooOO % OoO0O00 + i11iIiiIii + I1Ii111 % OoO0O00
 OoO00oo00 = 2 if packet . inner_version == 4 else 4
 oO0O0Oooo = 20 + O0OOOOo0 if packet . inner_version == 4 else O0OOOOo0
 Ooooo000O0o0 = struct . pack ( "H" , socket . htons ( oO0O0Oooo ) )
 Iii1ii1 = Iii1ii1 [ 0 : OoO00oo00 ] + Ooooo000O0o0 + Iii1ii1 [ OoO00oo00 + 2 : : ]
 if 8 - 8: IiII % II111iiii + IiII
 if 78 - 78: OOooOOo
 if 21 - 21: i11iIiiIii + o0oOOo0O0Ooo
 if 57 - 57: iII111i
 if ( packet . inner_version == 4 ) :
  Ooo0OO00oo = struct . pack ( "H" , 0 )
  Iii1ii1 = Iii1ii1 [ 0 : 10 ] + Ooo0OO00oo + Iii1ii1 [ 12 : : ]
  Ooooo000O0o0 = lisp_ip_checksum ( Iii1ii1 [ 0 : 20 ] )
  Iii1ii1 = Ooooo000O0o0 + Iii1ii1 [ 20 : : ]
  if 50 - 50: o0oOOo0O0Ooo + iII111i / i1IIi % II111iiii
  if 61 - 61: IiII
  if 5 - 5: OOooOOo % iIii1I11I1II1 % O0 * i11iIiiIii / I1Ii111
  if 48 - 48: IiII * oO0o
  if 53 - 53: i1IIi * iIii1I11I1II1 . OOooOOo
 packet . packet = Iii1ii1 + O0O0oOoOOoO0O
 return ( True )
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
def lisp_allow_gleaning ( eid , group , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False , False )
 if 4 - 4: II111iiii . OOooOOo - Ii1I - i11iIiiIii
 for I1iII11ii1 in lisp_glean_mappings :
  if ( I1iII11ii1 . has_key ( "instance-id" ) ) :
   o0OoO0000o = eid . instance_id
   oOoOooO0 , O000o0oO = I1iII11ii1 [ "instance-id" ]
   if ( o0OoO0000o < oOoOooO0 or o0OoO0000o > O000o0oO ) : continue
   if 27 - 27: iII111i * iII111i - OoO0O00 % o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if ( I1iII11ii1 . has_key ( "eid-prefix" ) ) :
   oOo = copy . deepcopy ( I1iII11ii1 [ "eid-prefix" ] )
   oOo . instance_id = eid . instance_id
   if ( eid . is_more_specific ( oOo ) == False ) : continue
   if 64 - 64: I1ii11iIi11i * ooOoO0o - OoooooooOO - I1IiiI
  if ( I1iII11ii1 . has_key ( "group-prefix" ) ) :
   if ( group == None ) : continue
   i11ii = copy . deepcopy ( I1iII11ii1 [ "group-prefix" ] )
   i11ii . instance_id = group . instance_id
   if ( group . is_more_specific ( i11ii ) == False ) : continue
   if 59 - 59: I1ii11iIi11i . I1Ii111 - OOooOOo / Oo0Ooo + OOooOOo . I1ii11iIi11i
  if ( I1iII11ii1 . has_key ( "rloc-prefix" ) ) :
   if ( rloc != None and rloc . is_more_specific ( I1iII11ii1 [ "rloc-prefix" ] )
 == False ) : continue
   if 69 - 69: Oo0Ooo
  return ( True , I1iII11ii1 [ "rloc-probe" ] , I1iII11ii1 [ "igmp-query" ] )
  if 34 - 34: I1Ii111 - ooOoO0o . o0oOOo0O0Ooo
 return ( False , False , False )
 if 52 - 52: o0oOOo0O0Ooo % I11i * I11i / iIii1I11I1II1
 if 77 - 77: OoOoOO00
 if 67 - 67: OoooooooOO / OoooooooOO + IiII - ooOoO0o
 if 72 - 72: Ii1I
 if 21 - 21: ooOoO0o + iII111i
 if 39 - 39: o0oOOo0O0Ooo % I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo
 if 78 - 78: OoO0O00 / o0oOOo0O0Ooo / O0 % OOooOOo % i1IIi
def lisp_build_gleaned_multicast ( seid , geid , rloc , port , igmp ) :
 iI1i1iIi1iiII = geid . print_address ( )
 oOoOoO0O0 = seid . print_address_no_iid ( )
 IiII1iiI = green ( "{}" . format ( oOoOoO0O0 ) , False )
 oOo = green ( "(*, {})" . format ( iI1i1iIi1iiII ) , False )
 i11iII1IiI = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 if 56 - 56: OoO0O00 . OOooOOo * OoO0O00 . ooOoO0o * OoooooooOO
 if 75 - 75: i1IIi - I11i
 if 5 - 5: OoO0O00 - oO0o - OOooOOo + II111iiii
 if 19 - 19: iIii1I11I1II1 * OoooooooOO - i11iIiiIii . I1Ii111 * OoO0O00
 O0oOO0OOO = lisp_map_cache_lookup ( seid , geid )
 if ( O0oOO0OOO == None ) :
  O0oOO0OOO = lisp_mapping ( "" , "" , [ ] )
  O0oOO0OOO . group . copy_address ( geid )
  O0oOO0OOO . eid . copy_address ( geid )
  O0oOO0OOO . eid . address = 0
  O0oOO0OOO . eid . mask_len = 0
  O0oOO0OOO . mapping_source . copy_address ( rloc )
  O0oOO0OOO . map_cache_ttl = LISP_IGMP_TTL
  O0oOO0OOO . gleaned = True
  O0oOO0OOO . add_cache ( )
  lprint ( "Add gleaned EID {} to map-cache" . format ( oOo ) )
  if 30 - 30: iII111i + I1IiiI * ooOoO0o
  if 53 - 53: iII111i + IiII
  if 52 - 52: II111iiii * i11iIiiIii - IiII * IiII / OoooooooOO
  if 18 - 18: IiII / O0 / I1ii11iIi11i
  if 47 - 47: oO0o / iIii1I11I1II1
  if 45 - 45: OoOoOO00 * o0oOOo0O0Ooo / I1ii11iIi11i * iII111i - I1ii11iIi11i
 oo0OOOoO0OoO = i1II = O00oo0ooo0O = None
 if ( O0oOO0OOO . rloc_set != [ ] ) :
  oo0OOOoO0OoO = O0oOO0OOO . rloc_set [ 0 ]
  if ( oo0OOOoO0OoO . rle ) :
   i1II = oo0OOOoO0OoO . rle
   for OoiiiiI111II in i1II . rle_nodes :
    if ( OoiiiiI111II . rloc_name != oOoOoO0O0 ) : continue
    O00oo0ooo0O = OoiiiiI111II
    break
    if 5 - 5: O0 % I1Ii111 % I1ii11iIi11i - o0oOOo0O0Ooo * OoOoOO00
    if 27 - 27: o0oOOo0O0Ooo
    if 33 - 33: IiII / o0oOOo0O0Ooo
    if 75 - 75: OOooOOo . I11i . I11i * II111iiii * Oo0Ooo
    if 39 - 39: i1IIi - ooOoO0o % OoO0O00 + O0 / iIii1I11I1II1
    if 78 - 78: ooOoO0o / i1IIi . OOooOOo * o0oOOo0O0Ooo . I1IiiI
    if 81 - 81: I11i - OoO0O00 - o0oOOo0O0Ooo
 if ( oo0OOOoO0OoO == None ) :
  oo0OOOoO0OoO = lisp_rloc ( )
  O0oOO0OOO . rloc_set = [ oo0OOOoO0OoO ]
  oo0OOOoO0OoO . priority = 253
  oo0OOOoO0OoO . mpriority = 255
  O0oOO0OOO . build_best_rloc_set ( )
  if 95 - 95: I11i + Ii1I
 if ( i1II == None ) :
  i1II = lisp_rle ( geid . print_address ( ) )
  oo0OOOoO0OoO . rle = i1II
  if 68 - 68: i11iIiiIii + I1IiiI / o0oOOo0O0Ooo
 if ( O00oo0ooo0O == None ) :
  O00oo0ooo0O = lisp_rle_node ( )
  O00oo0ooo0O . rloc_name = oOoOoO0O0
  i1II . rle_nodes . append ( O00oo0ooo0O )
  i1II . build_forwarding_list ( )
  lprint ( "Add RLE {} from {} for gleaned EID {}" . format ( i11iII1IiI , IiII1iiI , oOo ) )
 elif ( rloc . is_exact_match ( O00oo0ooo0O . address ) == False or
 port != O00oo0ooo0O . translated_port ) :
  lprint ( "Changed RLE {} from {} for gleaned EID {}" . format ( i11iII1IiI , IiII1iiI , oOo ) )
  if 63 - 63: I1IiiI
  if 20 - 20: oO0o + OoOoOO00
  if 32 - 32: o0oOOo0O0Ooo % oO0o % I1IiiI * OoooooooOO
  if 4 - 4: OOooOOo % oO0o
  if 18 - 18: Ii1I * I11i
 O00oo0ooo0O . store_translated_rloc ( rloc , port )
 if 14 - 14: ooOoO0o . ooOoO0o * OoOoOO00 * o0oOOo0O0Ooo - iII111i - I1Ii111
 if 53 - 53: Oo0Ooo * OoOoOO00 * II111iiii % IiII - I1ii11iIi11i
 if 56 - 56: Oo0Ooo . I1ii11iIi11i - i11iIiiIii / iIii1I11I1II1 . ooOoO0o
 if 28 - 28: OoooooooOO + I1IiiI / oO0o . iIii1I11I1II1 - oO0o
 if 64 - 64: I1Ii111 + Oo0Ooo / iII111i
 if ( igmp ) :
  iI1ii111i1i = seid . print_address ( )
  if ( lisp_gleaned_groups . has_key ( iI1ii111i1i ) == False ) :
   lisp_gleaned_groups [ iI1ii111i1i ] = { }
   if 61 - 61: Ii1I * Ii1I . OoOoOO00 + OoO0O00 * i11iIiiIii * OoO0O00
  lisp_gleaned_groups [ iI1ii111i1i ] [ iI1i1iIi1iiII ] = lisp_get_timestamp ( )
  if 4 - 4: OoooooooOO % iII111i % Oo0Ooo * IiII % o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 66 - 66: I1IiiI . Oo0Ooo - oO0o
  if 53 - 53: oO0o / Ii1I + oO0o + II111iiii
  if 70 - 70: OoooooooOO - I1Ii111 + OoOoOO00
  if 61 - 61: I1IiiI * I1Ii111 * i11iIiiIii
  if 68 - 68: OoOoOO00 - iII111i - I1IiiI
  if 37 - 37: iII111i - I1Ii111 + i1IIi / o0oOOo0O0Ooo % iII111i / iII111i
  if 8 - 8: i1IIi % I11i
def lisp_remove_gleaned_multicast ( seid , geid ) :
 if 12 - 12: ooOoO0o / II111iiii + ooOoO0o * I1ii11iIi11i / i1IIi - iIii1I11I1II1
 if 71 - 71: IiII - i11iIiiIii
 if 3 - 3: i11iIiiIii - o0oOOo0O0Ooo / oO0o . OoO0O00 * I11i + o0oOOo0O0Ooo
 if 18 - 18: OoooooooOO % oO0o / IiII - ooOoO0o
 O0oOO0OOO = lisp_map_cache_lookup ( seid , geid )
 if ( O0oOO0OOO == None ) : return
 if 80 - 80: I11i
 i1I1Ii11II1i = O0oOO0OOO . rloc_set [ 0 ] . rle
 if ( i1I1Ii11II1i == None ) : return
 if 98 - 98: iII111i / I1ii11iIi11i
 O0o0oO = seid . print_address_no_iid ( )
 O00o0 = False
 for O00oo0ooo0O in i1I1Ii11II1i . rle_nodes :
  if ( O00oo0ooo0O . rloc_name == O0o0oO ) :
   O00o0 = True
   break
   if 87 - 87: iII111i - O0 * ooOoO0o / II111iiii % OoooooooOO . o0oOOo0O0Ooo
   if 55 - 55: OOooOOo - o0oOOo0O0Ooo * I1IiiI / o0oOOo0O0Ooo + I1Ii111 + iIii1I11I1II1
 if ( O00o0 == False ) : return
 if 3 - 3: II111iiii % iII111i / IiII * ooOoO0o . OoooooooOO
 if 56 - 56: IiII * II111iiii + Oo0Ooo - O0 - OoO0O00 . I1Ii111
 if 53 - 53: i1IIi + IiII
 if 90 - 90: II111iiii / oO0o / oO0o . OoOoOO00 / OoO0O00 / iIii1I11I1II1
 i1I1Ii11II1i . rle_nodes . remove ( O00oo0ooo0O )
 i1I1Ii11II1i . build_forwarding_list ( )
 if 96 - 96: iIii1I11I1II1 % I1ii11iIi11i
 iI1i1iIi1iiII = geid . print_address ( )
 iI1ii111i1i = seid . print_address ( )
 IiII1iiI = green ( "{}" . format ( iI1ii111i1i ) , False )
 oOo = green ( "(*, {})" . format ( iI1i1iIi1iiII ) , False )
 lprint ( "Gleaned EID {} RLE removed for {}" . format ( oOo , IiII1iiI ) )
 if 35 - 35: i1IIi - OoooooooOO * Ii1I / OOooOOo % I11i
 if 72 - 72: I1Ii111 / OoO0O00 + II111iiii
 if 40 - 40: Ii1I + O0 . i11iIiiIii % I11i / Oo0Ooo
 if 25 - 25: IiII * IiII
 if ( lisp_gleaned_groups . has_key ( iI1ii111i1i ) ) :
  if ( lisp_gleaned_groups [ iI1ii111i1i ] . has_key ( iI1i1iIi1iiII ) ) :
   lisp_gleaned_groups [ iI1ii111i1i ] . pop ( iI1i1iIi1iiII )
   if 54 - 54: I1Ii111
   if 90 - 90: Oo0Ooo / Ii1I
   if 66 - 66: i11iIiiIii - I11i + oO0o . OoooooooOO
   if 77 - 77: OoO0O00 / OOooOOo
   if 97 - 97: OoOoOO00 / Ii1I * I1IiiI - Oo0Ooo % O0
   if 66 - 66: O0 + I1IiiI % iIii1I11I1II1 . i1IIi % II111iiii - i1IIi
 if ( i1I1Ii11II1i . rle_nodes == [ ] ) :
  O0oOO0OOO . delete_cache ( )
  lprint ( "Gleaned EID {} remove, no more RLEs" . format ( oOo ) )
  if 93 - 93: O0 + OoooooooOO % IiII % oO0o % I1ii11iIi11i
  if 36 - 36: I1IiiI - oO0o * Oo0Ooo + oO0o % iII111i - i11iIiiIii
  if 93 - 93: O0
  if 11 - 11: OoooooooOO . I1ii11iIi11i + I1ii11iIi11i
  if 73 - 73: OoooooooOO
  if 2 - 2: o0oOOo0O0Ooo % IiII + I1ii11iIi11i - i11iIiiIii
  if 100 - 100: II111iiii + oO0o
  if 85 - 85: I1ii11iIi11i % I1ii11iIi11i . Ii1I
def lisp_change_gleaned_multicast ( seid , rloc , port ) :
 iI1ii111i1i = seid . print_address ( )
 if ( lisp_gleaned_groups . has_key ( iI1ii111i1i ) == False ) : return
 if 42 - 42: oO0o + OoO0O00
 for oOooO00OOoO in lisp_gleaned_groups [ iI1ii111i1i ] :
  lisp_geid . store_address ( oOooO00OOoO )
  lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , port , False )
  if 16 - 16: Ii1I
  if 67 - 67: I1ii11iIi11i . OoooooooOO * I1Ii111 + Ii1I * OOooOOo
  if 84 - 84: OOooOOo
  if 78 - 78: O0 % O0
  if 72 - 72: o0oOOo0O0Ooo * IiII / II111iiii / iIii1I11I1II1
  if 41 - 41: iII111i / Ii1I
  if 11 - 11: Oo0Ooo % OOooOOo . ooOoO0o
  if 24 - 24: IiII / Oo0Ooo
  if 90 - 90: ooOoO0o . OOooOOo - Ii1I
  if 60 - 60: i11iIiiIii % iII111i . I1IiiI * I1ii11iIi11i
  if 30 - 30: Ii1I + i11iIiiIii . I11i + o0oOOo0O0Ooo - OoO0O00
  if 55 - 55: ooOoO0o - II111iiii . ooOoO0o . iII111i / OoooooooOO
  if 51 - 51: I1IiiI * I1Ii111 - ooOoO0o + IiII
  if 22 - 22: OoOoOO00 % Ii1I + iII111i
  if 64 - 64: ooOoO0o
  if 87 - 87: IiII - Ii1I / Oo0Ooo / I1ii11iIi11i . iII111i
  if 49 - 49: IiII * OoooooooOO * iIii1I11I1II1 * Oo0Ooo / iII111i % oO0o
  if 88 - 88: I1Ii111 * OOooOOo
  if 38 - 38: Oo0Ooo - OoooooooOO - OoooooooOO / II111iiii
  if 10 - 10: II111iiii - OoO0O00 / II111iiii % Ii1I - OoOoOO00
  if 90 - 90: I11i + II111iiii - oO0o - ooOoO0o / ooOoO0o / i11iIiiIii
  if 80 - 80: I1ii11iIi11i % O0 / II111iiii + iII111i
  if 22 - 22: Oo0Ooo + ooOoO0o . OOooOOo % Oo0Ooo . IiII
  if 34 - 34: Ii1I . OoOoOO00 - OOooOOo * Oo0Ooo - ooOoO0o . oO0o
  if 42 - 42: O0 + OoO0O00
  if 47 - 47: O0 % OoOoOO00 + Ii1I * iIii1I11I1II1
  if 55 - 55: Ii1I
  if 93 - 93: iII111i + OOooOOo . OoooooooOO . I1Ii111 . O0
  if 46 - 46: i11iIiiIii
  if 26 - 26: I11i * Oo0Ooo % OoO0O00 + Oo0Ooo - I1ii11iIi11i
  if 74 - 74: i1IIi + OoO0O00 . II111iiii + I1Ii111
  if 59 - 59: Ii1I . i11iIiiIii . o0oOOo0O0Ooo * iIii1I11I1II1 . OoOoOO00 . II111iiii
  if 67 - 67: OoO0O00 - Oo0Ooo + OOooOOo / OoOoOO00 + OOooOOo
  if 18 - 18: Oo0Ooo % OoOoOO00 % i1IIi
  if 66 - 66: OoOoOO00 % II111iiii
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
igmp_types = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 74 - 74: iII111i . OOooOOo * Ii1I / Oo0Ooo . OoO0O00 . I11i
lisp_igmp_record_types = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 65 - 65: i11iIiiIii - OoO0O00 / OoooooooOO * I1IiiI % iII111i
def lisp_process_igmp_packet ( packet ) :
 oo00Oo0 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 oo00Oo0 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 oo00Oo0 = bold ( "from {}" . format ( oo00Oo0 . print_address_no_iid ( ) ) , False )
 if 15 - 15: OOooOOo * Ii1I / ooOoO0o
 i11iII1IiI = bold ( "Receive" , False )
 lprint ( "{} {}-byte {}, IGMP packet: {}" . format ( i11iII1IiI , len ( packet ) , oo00Oo0 ,
 lisp_format_packet ( packet ) ) )
 if 70 - 70: i11iIiiIii * oO0o . I11i - OoooooooOO / I1ii11iIi11i
 if 10 - 10: IiII * OoOoOO00 . II111iiii . II111iiii * Oo0Ooo
 if 23 - 23: I1ii11iIi11i + I11i
 if 74 - 74: i1IIi % I1IiiI
 II1iI1iI = ( struct . unpack ( "B" , packet [ 0 ] ) [ 0 ] & 0x0f ) * 4
 if 78 - 78: OoO0O00 - Ii1I * I11i . I1ii11iIi11i
 if 26 - 26: Ii1I . OOooOOo / iII111i % OoOoOO00
 if 8 - 8: I1IiiI / O0 * I1IiiI . ooOoO0o * I1IiiI + I1Ii111
 if 52 - 52: i1IIi - IiII + OOooOOo
 oOoOoO = packet [ II1iI1iI : : ]
 I1iiooOo0000OO0O = struct . unpack ( "B" , oOoOoO [ 0 ] ) [ 0 ]
 if 6 - 6: Ii1I - i1IIi
 if 43 - 43: OoO0O00 + I1ii11iIi11i * iII111i % i11iIiiIii
 if 55 - 55: IiII
 if 6 - 6: IiII % iIii1I11I1II1 + I1IiiI - II111iiii + O0
 if 9 - 9: i1IIi
 oOooO00OOoO = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 oOooO00OOoO . address = socket . ntohl ( struct . unpack ( "II" , oOoOoO [ : 8 ] ) [ 1 ] )
 iI1i1iIi1iiII = oOooO00OOoO . print_address_no_iid ( )
 if 58 - 58: IiII . iII111i % O0 . Ii1I * Oo0Ooo
 if ( I1iiooOo0000OO0O == 17 ) :
  lprint ( "IGMP Query for group {}" . format ( iI1i1iIi1iiII ) )
  return ( True )
  if 54 - 54: OoO0O00 % OOooOOo - OoO0O00 . Oo0Ooo % i1IIi
  if 95 - 95: iII111i . OoooooooOO . o0oOOo0O0Ooo / II111iiii - OoooooooOO / I1Ii111
 Iii1I1I1I = ( I1iiooOo0000OO0O in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( Iii1I1I1I == False ) :
  iiiI1I1Ii1I1 = "{} ({})" . format ( I1iiooOo0000OO0O , igmp_types [ I1iiooOo0000OO0O ] ) if igmp_types . has_key ( I1iiooOo0000OO0O ) else I1iiooOo0000OO0O
  if 97 - 97: ooOoO0o / iIii1I11I1II1 - Ii1I . i1IIi
  lprint ( "IGMP type {} not supported" . format ( iiiI1I1Ii1I1 ) )
  return ( [ ] )
  if 1 - 1: IiII
  if 24 - 24: II111iiii . iIii1I11I1II1 + OoooooooOO + OoOoOO00 % i1IIi * oO0o
 if ( len ( oOoOoO ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 43 - 43: OoOoOO00 % OOooOOo
  if 32 - 32: I1Ii111 - I11i + iIii1I11I1II1 - OoO0O00
  if 25 - 25: OoO0O00 + i1IIi + OoooooooOO + iII111i / II111iiii
  if 12 - 12: Oo0Ooo / i11iIiiIii + i11iIiiIii % I1ii11iIi11i / II111iiii
  if 64 - 64: IiII . I1ii11iIi11i / OoOoOO00 * ooOoO0o
 if ( I1iiooOo0000OO0O == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( iI1i1iIi1iiII , False ) ) )
  return ( [ [ None , iI1i1iIi1iiII , False ] ] )
  if 55 - 55: II111iiii % o0oOOo0O0Ooo + IiII % i1IIi % OoooooooOO - O0
 if ( I1iiooOo0000OO0O in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( I1iiooOo0000OO0O == 0x12 ) else 2 , bold ( iI1i1iIi1iiII , False ) ) )
  if 39 - 39: i11iIiiIii / Ii1I / ooOoO0o
  if 93 - 93: o0oOOo0O0Ooo - Oo0Ooo / oO0o / OoOoOO00
  if 75 - 75: o0oOOo0O0Ooo * ooOoO0o % Ii1I
  if 94 - 94: OoooooooOO + II111iiii / iIii1I11I1II1 * ooOoO0o
  if 85 - 85: ooOoO0o / IiII
  if ( iI1i1iIi1iiII . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
  else :
   return ( [ [ None , iI1i1iIi1iiII , True ] ] )
   if 28 - 28: i11iIiiIii - OoOoOO00
   if 13 - 13: O0
   if 82 - 82: OoooooooOO
   if 59 - 59: I1Ii111 + I1ii11iIi11i + OoO0O00 % oO0o . i1IIi % O0
   if 22 - 22: i1IIi * OoOoOO00 + Ii1I
  return ( [ ] )
  if 48 - 48: Ii1I % IiII + OoO0O00 . IiII
  if 42 - 42: Ii1I
  if 70 - 70: I11i
  if 82 - 82: O0
  if 58 - 58: II111iiii . O0 - OoO0O00 - IiII
 IiIIi = oOooO00OOoO . address
 oOoOoO = oOoOoO [ 8 : : ]
 if 4 - 4: i11iIiiIii + i11iIiiIii / O0
 i1I11iIiii = "BBHI"
 i1IIi1i = struct . calcsize ( i1I11iIiii )
 Ii11iiI1i1iI = "I"
 O0O0o0oo00o = struct . calcsize ( Ii11iiI1i1iI )
 oo00Oo0 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 12 - 12: OoooooooOO + IiII . iII111i + I1IiiI
 if 18 - 18: Oo0Ooo / o0oOOo0O0Ooo + o0oOOo0O0Ooo + ooOoO0o
 if 62 - 62: Ii1I / OoOoOO00 . O0 - IiII + I1IiiI
 if 44 - 44: OoooooooOO / i11iIiiIii + Ii1I - Oo0Ooo
 oO0Oo000ooO0O = [ ]
 for IiIIi1IiiIiI in range ( IiIIi ) :
  if ( len ( oOoOoO ) < i1IIi1i ) : return
  o0oOo00O , I11Iii1iIII1i , O0ooOoo , ii1i1II11II1i = struct . unpack ( i1I11iIiii ,
 oOoOoO [ : i1IIi1i ] )
  if 34 - 34: I1Ii111
  oOoOoO = oOoOoO [ i1IIi1i : : ]
  if 51 - 51: OoooooooOO - OOooOOo / ooOoO0o
  if ( lisp_igmp_record_types . has_key ( o0oOo00O ) == False ) :
   lprint ( "Invalid record type {}" . format ( o0oOo00O ) )
   continue
   if 65 - 65: iIii1I11I1II1 * i1IIi
   if 48 - 48: O0 / I11i
  iIiiiiI = lisp_igmp_record_types [ o0oOo00O ]
  O0ooOoo = socket . ntohs ( O0ooOoo )
  oOooO00OOoO . address = socket . ntohl ( ii1i1II11II1i )
  iI1i1iIi1iiII = oOooO00OOoO . print_address_no_iid ( )
  if 31 - 31: Ii1I
  lprint ( "Record type: {}, group: {}, source-count: {}" . format ( iIiiiiI , iI1i1iIi1iiII , O0ooOoo ) )
  if 14 - 14: OOooOOo * I1Ii111 % OoO0O00
  if 49 - 49: I1IiiI . iII111i . II111iiii
  if 60 - 60: OoOoOO00
  if 71 - 71: O0 * OOooOOo . I1IiiI . I1Ii111 * I11i
  if 45 - 45: O0 . O0 . II111iiii * ooOoO0o
  if 2 - 2: OoO0O00 . o0oOOo0O0Ooo
  if 48 - 48: Ii1I
  iII111i1 = False
  if ( o0oOo00O in ( 1 , 5 ) ) : iII111i1 = True
  if ( o0oOo00O in ( 2 , 4 ) and O0ooOoo == 0 ) : iII111i1 = True
  OoOOOOOooo = "join" if ( iII111i1 ) else "leave"
  if 97 - 97: OoO0O00 + i11iIiiIii % I1IiiI * Ii1I
  if 89 - 89: IiII % i11iIiiIii + OoO0O00 . oO0o / I1IiiI . Ii1I
  if 11 - 11: ooOoO0o - I1Ii111 - I11i + OoOoOO00
  if 20 - 20: I11i + O0
  if ( iI1i1iIi1iiII . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   continue
   if 27 - 27: Oo0Ooo
   if 12 - 12: I1ii11iIi11i . iII111i - iII111i - OOooOOo - iIii1I11I1II1
   if 50 - 50: I1IiiI - iIii1I11I1II1 . iII111i - Ii1I / I1Ii111 + iII111i
   if 46 - 46: OOooOOo + iII111i % Oo0Ooo * iII111i % OoooooooOO * IiII
   if 27 - 27: I1IiiI + I1IiiI + I1ii11iIi11i - oO0o * OOooOOo
   if 53 - 53: I1ii11iIi11i / OoooooooOO * iIii1I11I1II1
   if 4 - 4: I1IiiI . iIii1I11I1II1 + OOooOOo / IiII . o0oOOo0O0Ooo . I11i
   if 52 - 52: ooOoO0o % i11iIiiIii . IiII + OoO0O00
  if ( O0ooOoo == 0 ) :
   oO0Oo000ooO0O . append ( [ None , iI1i1iIi1iiII , iII111i1 ] )
   lprint ( "IGMPv3 {} (*, {})" . format ( bold ( OoOOOOOooo , False ) ,
 bold ( iI1i1iIi1iiII , False ) ) )
   if 66 - 66: II111iiii . Ii1I
   if 42 - 42: iIii1I11I1II1 * iII111i * I1IiiI
   if 66 - 66: Oo0Ooo * i1IIi / I1ii11iIi11i / OoO0O00
   if 12 - 12: OOooOOo + iIii1I11I1II1 % I1Ii111 + OOooOOo
   if 19 - 19: OoO0O00 / I1IiiI - o0oOOo0O0Ooo - i1IIi + I1ii11iIi11i * OoooooooOO
  for O0OO00 in range ( O0ooOoo ) :
   if ( len ( oOoOoO ) < O0O0o0oo00o ) : return
   ii1i1II11II1i = struct . unpack ( Ii11iiI1i1iI , oOoOoO [ : O0O0o0oo00o ] ) [ 0 ]
   oo00Oo0 . address = socket . ntohl ( ii1i1II11II1i )
   o0I111II = oo00Oo0 . print_address_no_iid ( )
   oO0Oo000ooO0O . append ( [ o0I111II , iI1i1iIi1iiII , iII111i1 ] )
   lprint ( "{} ({}, {})" . format ( OoOOOOOooo ,
 green ( o0I111II , False ) , bold ( iI1i1iIi1iiII , False ) ) )
   oOoOoO = oOoOoO [ O0O0o0oo00o : : ]
   if 42 - 42: II111iiii . I1Ii111 * IiII . OoO0O00 * OoooooooOO
   if 53 - 53: i11iIiiIii * OoO0O00
   if 73 - 73: OOooOOo * i11iIiiIii - OoO0O00
   if 94 - 94: O0
   if 72 - 72: i1IIi - iII111i * I1IiiI % O0 - I11i * O0
   if 78 - 78: I1IiiI - OoO0O00 / Ii1I . i1IIi
   if 30 - 30: IiII
   if 21 - 21: i1IIi . iII111i - I1IiiI
 return ( oO0Oo000ooO0O )
 if 28 - 28: IiII / Ii1I - i1IIi - OoOoOO00
 if 65 - 65: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo
 if 77 - 77: OoooooooOO - Oo0Ooo - OoOoOO00 / I11i / O0 . i11iIiiIii
 if 27 - 27: I1Ii111 * O0
 if 9 - 9: i1IIi - Oo0Ooo - i11iIiiIii / iIii1I11I1II1 . i1IIi
 if 2 - 2: I11i + II111iiii - I11i / oO0o / I11i
 if 73 - 73: IiII % I1Ii111 . OoOoOO00
 if 96 - 96: I1IiiI / ooOoO0o / iIii1I11I1II1
lisp_geid = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
if 91 - 91: Ii1I . I11i
def lisp_glean_map_cache ( seid , rloc , encap_port , igmp ) :
 if 87 - 87: Oo0Ooo / IiII * OOooOOo + I1ii11iIi11i . I11i
 if 56 - 56: oO0o + oO0o % o0oOOo0O0Ooo + OOooOOo . II111iiii + i11iIiiIii
 if 45 - 45: iIii1I11I1II1 / o0oOOo0O0Ooo * OoooooooOO - Oo0Ooo
 if 77 - 77: II111iiii
 if 8 - 8: I1IiiI * II111iiii % I1ii11iIi11i
 if 88 - 88: Oo0Ooo . oO0o + OoOoOO00 % OoooooooOO
 OoII1IIiI1Ii = True
 O0oOO0OOO = lisp_map_cache . lookup_cache ( seid , True )
 if ( O0oOO0OOO and len ( O0oOO0OOO . rloc_set ) != 0 ) :
  O0oOO0OOO . last_refresh_time = lisp_get_timestamp ( )
  if 61 - 61: OOooOOo - ooOoO0o . iII111i
  III1I1 = O0oOO0OOO . rloc_set [ 0 ]
  ooooO0OO = III1I1 . rloc
  Oo0ooOoO0o = III1I1 . translated_port
  OoII1IIiI1Ii = ( ooooO0OO . is_exact_match ( rloc ) == False or
 Oo0ooOoO0o != encap_port )
  if 86 - 86: i1IIi . ooOoO0o * I11i + II111iiii
  if ( OoII1IIiI1Ii ) :
   oOo = green ( seid . print_address ( ) , False )
   i11iII1IiI = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
   lprint ( "Change gleaned EID {} to RLOC {}" . format ( oOo , i11iII1IiI ) )
   III1I1 . delete_from_rloc_probe_list ( O0oOO0OOO . eid , O0oOO0OOO . group )
   lisp_change_gleaned_multicast ( seid , rloc , encap_port )
   if 65 - 65: Oo0Ooo
 else :
  O0oOO0OOO = lisp_mapping ( "" , "" , [ ] )
  O0oOO0OOO . eid . copy_address ( seid )
  O0oOO0OOO . mapping_source . copy_address ( rloc )
  O0oOO0OOO . map_cache_ttl = LISP_GLEAN_TTL
  O0oOO0OOO . gleaned = True
  oOo = green ( seid . print_address ( ) , False )
  i11iII1IiI = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( oOo , i11iII1IiI ) )
  O0oOO0OOO . add_cache ( )
  if 70 - 70: O0 * iIii1I11I1II1 - IiII * I11i / Ii1I + i11iIiiIii
  if 26 - 26: II111iiii - I11i % I11i / ooOoO0o + Oo0Ooo
  if 91 - 91: I1IiiI % Ii1I - OOooOOo - Oo0Ooo / I1IiiI / OoO0O00
  if 40 - 40: OoooooooOO
  if 71 - 71: OOooOOo
 if ( OoII1IIiI1Ii ) :
  oo0OOOoO0OoO = lisp_rloc ( )
  oo0OOOoO0OoO . store_translated_rloc ( rloc , encap_port )
  oo0OOOoO0OoO . add_to_rloc_probe_list ( O0oOO0OOO . eid , O0oOO0OOO . group )
  oo0OOOoO0OoO . priority = 253
  oo0OOOoO0OoO . mpriority = 255
  iI1111Ii1I = [ oo0OOOoO0OoO ]
  O0oOO0OOO . rloc_set = iI1111Ii1I
  O0oOO0OOO . build_best_rloc_set ( )
  if 88 - 88: O0
  if 44 - 44: II111iiii - IiII / I1IiiI + ooOoO0o % iII111i - iII111i
  if 53 - 53: OoooooooOO
  if 41 - 41: i1IIi - oO0o
  if 41 - 41: I11i
 if ( igmp == None ) : return
 if 92 - 92: i11iIiiIii
 if 62 - 62: i1IIi / I1IiiI - o0oOOo0O0Ooo
 if 3 - 3: O0 * OoOoOO00 * I11i / OoOoOO00
 if 77 - 77: i1IIi
 if 3 - 3: iII111i * OoO0O00 - oO0o + iII111i . o0oOOo0O0Ooo + I1IiiI
 lisp_geid . instance_id = seid . instance_id
 if 65 - 65: O0 / OoOoOO00
 if 77 - 77: OoO0O00
 if 17 - 17: i1IIi
 if 35 - 35: OoOoOO00
 if 61 - 61: I1Ii111
 OoooOOo0Oo00o = lisp_process_igmp_packet ( igmp )
 if ( type ( OoooOOo0Oo00o ) == bool ) : return
 if 78 - 78: I1Ii111 * Ii1I % Ii1I + I1IiiI
 for oo00Oo0 , oOooO00OOoO , iII111i1 in OoooOOo0Oo00o :
  if ( oo00Oo0 != None ) : continue
  if 83 - 83: iIii1I11I1II1 + O0 / IiII . iIii1I11I1II1
  if 74 - 74: Oo0Ooo
  if 60 - 60: OoooooooOO
  if 16 - 16: iIii1I11I1II1 - OoOoOO00 / I1ii11iIi11i % O0 % o0oOOo0O0Ooo
  lisp_geid . store_address ( oOooO00OOoO )
  o0OoO0Oo , I11Iii1iIII1i , II1ioOO0Oo = lisp_allow_gleaning ( seid , lisp_geid , rloc )
  if ( o0OoO0Oo == False ) : continue
  if 99 - 99: ooOoO0o . o0oOOo0O0Ooo - O0 * I1Ii111 . i11iIiiIii / iIii1I11I1II1
  if ( iII111i1 ) :
   lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port ,
 True )
  else :
   lisp_remove_gleaned_multicast ( seid , lisp_geid )
   if 40 - 40: iIii1I11I1II1 + oO0o / iIii1I11I1II1 - i1IIi % OoO0O00
   if 22 - 22: OOooOOo
   if 65 - 65: i1IIi - oO0o . I1Ii111 . ooOoO0o % I1ii11iIi11i % I1ii11iIi11i
   if 1 - 1: I1Ii111 + I1Ii111
   if 96 - 96: iII111i + OoOoOO00 - o0oOOo0O0Ooo + Ii1I
   if 6 - 6: O0 . I11i
   if 22 - 22: Oo0Ooo . O0 / i1IIi - OoOoOO00
   if 41 - 41: II111iiii - I1ii11iIi11i - I1Ii111
   if 82 - 82: I1IiiI * I1IiiI / iIii1I11I1II1
   if 14 - 14: I11i + Ii1I - OOooOOo % Ii1I / Ii1I
   if 86 - 86: I1Ii111 - i11iIiiIii + Ii1I + I11i
   if 96 - 96: Ii1I
def lisp_is_json_telemetry ( json_string ) :
 try :
  oOoO0Oo = json . loads ( json_string )
  if ( type ( oOoO0Oo ) != dict ) : return ( None )
 except :
  lprint ( "Could not decode telemetry json: {}" . format ( json_string ) )
  return ( None )
  if 28 - 28: i1IIi . oO0o . IiII + Oo0Ooo . Oo0Ooo . i1IIi
  if 34 - 34: Oo0Ooo + IiII / i1IIi
 if ( oOoO0Oo . has_key ( "type" ) == False ) : return ( None )
 if ( oOoO0Oo . has_key ( "sub-type" ) == False ) : return ( None )
 if ( oOoO0Oo [ "type" ] != "telemetry" ) : return ( None )
 if ( oOoO0Oo [ "sub-type" ] != "timestamps" ) : return ( None )
 return ( oOoO0Oo )
 if 33 - 33: i1IIi
 if 26 - 26: ooOoO0o - Oo0Ooo * II111iiii - Oo0Ooo
 if 15 - 15: OoO0O00 - oO0o . OoOoOO00 / O0 * oO0o
 if 45 - 45: O0
 if 89 - 89: IiII - IiII % o0oOOo0O0Ooo * Oo0Ooo % ooOoO0o
 if 4 - 4: OoO0O00 % II111iiii / I11i
 if 95 - 95: I1Ii111 - I1Ii111 - iII111i + IiII . OoO0O00
 if 5 - 5: i11iIiiIii - O0 % ooOoO0o
 if 55 - 55: II111iiii
 if 7 - 7: I1Ii111 % o0oOOo0O0Ooo . oO0o . ooOoO0o % i1IIi / I1IiiI
 if 88 - 88: i11iIiiIii / oO0o - i1IIi / I1IiiI
 if 57 - 57: oO0o + O0 * I11i
def lisp_encode_telemetry ( json_string , ii = "?" , io = "?" , ei = "?" , eo = "?" ) :
 oOoO0Oo = lisp_is_json_telemetry ( json_string )
 if ( oOoO0Oo == None ) : return ( json_string )
 if 87 - 87: o0oOOo0O0Ooo % Oo0Ooo * I1ii11iIi11i / OoooooooOO / o0oOOo0O0Ooo
 if ( oOoO0Oo [ "itr-in" ] == "?" ) : oOoO0Oo [ "itr-in" ] = ii
 if ( oOoO0Oo [ "itr-out" ] == "?" ) : oOoO0Oo [ "itr-out" ] = io
 if ( oOoO0Oo [ "etr-in" ] == "?" ) : oOoO0Oo [ "etr-in" ] = ei
 if ( oOoO0Oo [ "etr-out" ] == "?" ) : oOoO0Oo [ "etr-out" ] = eo
 json_string = json . dumps ( oOoO0Oo )
 return ( json_string )
 if 78 - 78: Ii1I
 if 5 - 5: i1IIi * ooOoO0o / OoOoOO00 % i11iIiiIii
 if 57 - 57: IiII
 if 89 - 89: I1ii11iIi11i - I1Ii111 + o0oOOo0O0Ooo
 if 62 - 62: I1ii11iIi11i + OoooooooOO * OOooOOo
 if 49 - 49: i1IIi - I11i * II111iiii
 if 4 - 4: o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 57 - 57: I1IiiI * OOooOOo . i11iIiiIii * oO0o - OoOoOO00
 if 35 - 35: O0
 if 65 - 65: Oo0Ooo
 if 100 - 100: I1Ii111 . o0oOOo0O0Ooo * OoooooooOO . o0oOOo0O0Ooo
 if 90 - 90: i11iIiiIii . I1IiiI + ooOoO0o * OoooooooOO * OoooooooOO + oO0o
def lisp_decode_telemetry ( json_string ) :
 oOoO0Oo = lisp_is_json_telemetry ( json_string )
 if ( oOoO0Oo == None ) : return ( { } )
 return ( oOoO0Oo )
 if 77 - 77: OOooOOo * OoOoOO00
 if 75 - 75: Oo0Ooo * Oo0Ooo - IiII - OoOoOO00 / i11iIiiIii + I1Ii111
 if 57 - 57: i11iIiiIii / oO0o
 if 37 - 37: o0oOOo0O0Ooo + OoOoOO00 - i1IIi . Oo0Ooo
 if 3 - 3: ooOoO0o % OoooooooOO / I1Ii111 + oO0o - O0
 if 72 - 72: oO0o * OoO0O00
 if 89 - 89: OoooooooOO . OOooOOo
 if 96 - 96: o0oOOo0O0Ooo + OoOoOO00 / i11iIiiIii - o0oOOo0O0Ooo * i11iIiiIii + OOooOOo
 if 16 - 16: IiII / I1Ii111 . II111iiii * I11i
def lisp_telemetry_configured ( ) :
 if ( lisp_json_list . has_key ( "telemetry" ) == False ) : return ( None )
 if 33 - 33: I1ii11iIi11i / Oo0Ooo % i11iIiiIii
 ii11 = lisp_json_list [ "telemetry" ] . json_string
 if ( lisp_is_json_telemetry ( ii11 ) == None ) : return ( None )
 if 37 - 37: Oo0Ooo - I1Ii111 - IiII / oO0o % I1IiiI / I1Ii111
 return ( ii11 )
 if 80 - 80: iII111i - oO0o % i1IIi * iIii1I11I1II1 . oO0o
 if 86 - 86: Ii1I
 if 36 - 36: i11iIiiIii % i11iIiiIii
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
