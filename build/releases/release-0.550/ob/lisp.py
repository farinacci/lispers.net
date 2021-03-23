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
from __future__ import print_function
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
import traceback
from Crypto . Cipher import AES
import ecdsa
import json
import copy
import chacha
import poly1305
import geopy
import curve25519
try :
 from commands import getoutput
except :
 from subprocess import getoutput
 if 64 - 64: i11iIiiIii
try :
 import queue
except :
 import Queue as queue
 if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
 if 73 - 73: II111iiii
 if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
 if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
 if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
lisp_print_rloc_probe_list = False
if 46 - 46: ooOoO0o * I11i - OoooooooOO
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
if 94 - 94: i1IIi % Oo0Ooo
if 68 - 68: Ii1I / O0
if 46 - 46: O0 * II111iiii / IiII * Oo0Ooo * iII111i . I11i
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
if 62 - 62: i11iIiiIii - II111iiii % I1Ii111 - iIii1I11I1II1 . I1ii11iIi11i . II111iiii
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
if 61 - 61: oO0o / OoOoOO00 / iII111i * OoO0O00 . II111iiii
if 1 - 1: II111iiii - I1ii11iIi11i % i11iIiiIii + IiII . I1Ii111
if 55 - 55: iIii1I11I1II1 - I1IiiI . Ii1I * IiII * i1IIi / iIii1I11I1II1
if 79 - 79: oO0o + I1Ii111 . ooOoO0o * IiII % I11i . I1IiiI
if 94 - 94: iII111i * Ii1I / IiII . i1IIi * iII111i
lisp_myinterfaces = { }
lisp_iid_to_interface = { }
lisp_multi_tenant_interfaces = [ ]
if 47 - 47: i1IIi % i11iIiiIii
lisp_test_mr_timer = None
lisp_rloc_probe_timer = None
if 20 - 20: ooOoO0o * II111iiii
if 65 - 65: o0oOOo0O0Ooo * iIii1I11I1II1 * ooOoO0o
if 18 - 18: iIii1I11I1II1 / I11i + oO0o / Oo0Ooo - II111iiii - I11i
if 1 - 1: I11i - OOooOOo % O0 + I1IiiI - iII111i / I11i
lisp_registered_count = 0
if 31 - 31: OoO0O00 + II111iiii
if 13 - 13: OOooOOo * oO0o * I1IiiI
if 55 - 55: II111iiii
if 43 - 43: OoOoOO00 - i1IIi + I1Ii111 + Ii1I
lisp_info_sources_by_address = { }
lisp_info_sources_by_nonce = { }
if 17 - 17: o0oOOo0O0Ooo
if 64 - 64: Ii1I % i1IIi % OoooooooOO
if 3 - 3: iII111i + O0
if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
if 78 - 78: OoO0O00
if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
lisp_crypto_keys_by_nonce = { }
lisp_crypto_keys_by_rloc_encap = { }
lisp_crypto_keys_by_rloc_decap = { }
lisp_data_plane_security = False
lisp_search_decap_keys = True
if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
lisp_data_plane_logging = False
lisp_frame_logging = False
lisp_flow_logging = False
if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
if 14 - 14: I11i % O0
if 41 - 41: i1IIi + I1Ii111 + OOooOOo - IiII
if 77 - 77: Oo0Ooo . IiII % ooOoO0o
if 42 - 42: oO0o - i1IIi / i11iIiiIii + OOooOOo + OoO0O00
if 17 - 17: oO0o . Oo0Ooo . I1ii11iIi11i
if 3 - 3: OoOoOO00 . Oo0Ooo . I1IiiI / Ii1I
lisp_crypto_ephem_port = None
if 38 - 38: II111iiii % i11iIiiIii . ooOoO0o - OOooOOo + Ii1I
if 66 - 66: OoooooooOO * OoooooooOO . OOooOOo . i1IIi - OOooOOo
if 77 - 77: I11i - iIii1I11I1II1
if 82 - 82: i11iIiiIii . OOooOOo / Oo0Ooo * O0 % oO0o % iIii1I11I1II1
lisp_pitr = False
if 78 - 78: iIii1I11I1II1 - Ii1I * OoO0O00 + o0oOOo0O0Ooo + iII111i + iII111i
if 11 - 11: iII111i - OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
if 74 - 74: iII111i * O0
if 89 - 89: oO0o + Oo0Ooo
lisp_l2_overlay = False
if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
if 20 - 20: o0oOOo0O0Ooo
if 77 - 77: OoOoOO00 / I11i
lisp_rloc_probing = False
lisp_rloc_probe_list = { }
if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
if 95 - 95: OoO0O00 % oO0o . O0
if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
if 53 - 53: IiII + I1IiiI * oO0o
if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
lisp_register_all_rtrs = True
if 60 - 60: I11i / I11i
if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
if 83 - 83: OoooooooOO
if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
lisp_nonce_echoing = False
lisp_nonce_echo_list = { }
if 4 - 4: II111iiii / ooOoO0o . iII111i
if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
if 50 - 50: I1IiiI
if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
lisp_nat_traversal = False
if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
if 58 - 58: i11iIiiIii % I11i
if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
lisp_program_hardware = False
if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
if 16 - 16: I1IiiI * oO0o % IiII
if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
if 44 - 44: oO0o
lisp_checkpoint_map_cache = False
lisp_checkpoint_filename = "./lisp.checkpoint"
if 88 - 88: I1Ii111 % Ii1I . II111iiii
if 38 - 38: o0oOOo0O0Ooo
if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
if 26 - 26: iII111i
lisp_ipc_data_plane = False
lisp_ipc_dp_socket = None
lisp_ipc_dp_socket_name = "lisp-ipc-data-plane"
if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
if 39 - 39: I1ii11iIi11i / ooOoO0o - II111iiii
if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
if 91 - 91: oO0o % Oo0Ooo
if 64 - 64: I11i % iII111i - I1Ii111 - oO0o
lisp_ipc_lock = None
if 31 - 31: I11i - II111iiii . I11i
if 18 - 18: o0oOOo0O0Ooo
if 98 - 98: iII111i * iII111i / iII111i + I11i
if 34 - 34: ooOoO0o
if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
lisp_default_iid = 0
lisp_default_secondary_iid = 0
if 92 - 92: iII111i . I1Ii111
if 31 - 31: I1Ii111 . OoOoOO00 / O0
if 89 - 89: OoOoOO00
if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + ooOoO0o
if 4 - 4: ooOoO0o + O0 * OOooOOo
lisp_ms_rtr_list = [ ]
if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
if 25 - 25: I1ii11iIi11i
if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
if 13 - 13: OOooOOo / i11iIiiIii
if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
if 52 - 52: o0oOOo0O0Ooo
lisp_nat_state_info = { }
if 95 - 95: Ii1I
if 87 - 87: ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
if 91 - 91: O0
if 61 - 61: II111iiii
if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
lisp_last_map_request_sent = None
lisp_no_map_request_rate_limit = time . time ( )
if 42 - 42: OoO0O00
if 67 - 67: I1Ii111 . iII111i . O0
if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
lisp_last_icmp_too_big_sent = 0
if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
if 83 - 83: I11i / I1IiiI
if 34 - 34: IiII
if 57 - 57: oO0o . I11i . i1IIi
LISP_FLOW_LOG_SIZE = 100
lisp_flow_log = [ ]
if 42 - 42: I11i + I1ii11iIi11i % O0
if 6 - 6: oO0o
if 68 - 68: OoOoOO00 - OoO0O00
if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
lisp_policies = { }
if 1 - 1: iIii1I11I1II1 / II111iiii
if 33 - 33: I11i
if 18 - 18: o0oOOo0O0Ooo % iII111i * O0
if 87 - 87: i11iIiiIii
if 93 - 93: I1ii11iIi11i - OoO0O00 % i11iIiiIii . iII111i / iII111i - I1Ii111
lisp_load_split_pings = False
if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
if 51 - 51: O0 + iII111i
if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
lisp_eid_hashes = [ ]
if 48 - 48: O0
if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
if 41 - 41: Ii1I - O0 - O0
if 68 - 68: OOooOOo % I1Ii111
if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
if 23 - 23: O0
lisp_reassembly_queue = { }
if 85 - 85: Ii1I
if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
if 53 - 53: iII111i % II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
if 77 - 77: iIii1I11I1II1 * OoO0O00
if 95 - 95: I1IiiI + i11iIiiIii
lisp_pubsub_cache = { }
if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
if 80 - 80: II111iiii
if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
if 53 - 53: II111iiii
if 31 - 31: OoO0O00
if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
lisp_decent_push_configured = False
if 25 - 25: OoO0O00
if 62 - 62: OOooOOo + O0
if 98 - 98: o0oOOo0O0Ooo
if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
if 82 - 82: Ii1I
lisp_decent_modulus = 0
lisp_decent_dns_suffix = None
if 46 - 46: OoooooooOO . i11iIiiIii
if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
if 87 - 87: Oo0Ooo . IiII
if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
if 55 - 55: OOooOOo . I1IiiI
if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
lisp_ipc_socket = None
if 100 - 100: I1Ii111 * O0
if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
if 79 - 79: O0
if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
lisp_ms_encryption_keys = { }
lisp_ms_json_keys = { }
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
if 49 - 49: I1IiiI - I11i
lisp_rtr_nat_trace_cache = { }
if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
if 62 - 62: OoooooooOO * I1IiiI
if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
if 97 - 97: O0 + OoOoOO00
if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
if 77 - 77: OOooOOo * iIii1I11I1II1
if 98 - 98: I1IiiI % Ii1I * OoooooooOO
if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
lisp_glean_mappings = [ ]
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
lisp_gleaned_groups = { }
if 52 - 52: OOooOOo
if 19 - 19: I1IiiI
if 25 - 25: Ii1I / ooOoO0o
if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
if 71 - 71: I1Ii111 . II111iiii
lisp_icmp_raw_socket = None
if ( os . getenv ( "LISP_SEND_ICMP_TOO_BIG" ) != None ) :
 lisp_icmp_raw_socket = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_ICMP )
 lisp_icmp_raw_socket . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 if 62 - 62: OoooooooOO . I11i
 if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
lisp_ignore_df_bit = ( os . getenv ( "LISP_IGNORE_DF_BIT" ) != None )
if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
if 58 - 58: I1IiiI
if 53 - 53: i1IIi
if 59 - 59: o0oOOo0O0Ooo
if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
if 73 - 73: I11i % i11iIiiIii - I1IiiI
LISP_DATA_PORT = 4341
LISP_CTRL_PORT = 4342
LISP_L2_DATA_PORT = 8472
LISP_VXLAN_DATA_PORT = 4789
LISP_VXLAN_GPE_PORT = 4790
LISP_TRACE_PORT = 2434
if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
if 23 - 23: i11iIiiIii
if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
LISP_MAP_REQUEST = 1
LISP_MAP_REPLY = 2
LISP_MAP_REGISTER = 3
LISP_MAP_NOTIFY = 4
LISP_MAP_NOTIFY_ACK = 5
LISP_MAP_REFERRAL = 6
LISP_NAT_INFO = 7
LISP_ECM = 8
LISP_TRACE = 9
if 81 - 81: IiII % i1IIi . iIii1I11I1II1
if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
if 31 - 31: OOooOOo
LISP_NO_ACTION = 0
LISP_NATIVE_FORWARD_ACTION = 1
LISP_SEND_MAP_REQUEST_ACTION = 2
LISP_DROP_ACTION = 3
LISP_POLICY_DENIED_ACTION = 4
LISP_AUTH_FAILURE_ACTION = 5
LISP_SEND_PUBSUB_ACTION = 6
if 23 - 23: I1Ii111 . IiII
lisp_map_reply_action_string = [ "no-action" , "native-forward" ,
 "send-map-request" , "drop-action" , "policy-denied" ,
 "auth-failure" , "send-subscribe" ]
if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
if 42 - 42: Oo0Ooo
if 76 - 76: I1IiiI * iII111i % I1Ii111
if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
LISP_NONE_ALG_ID = 0
LISP_SHA_1_96_ALG_ID = 1
LISP_SHA_256_128_ALG_ID = 2
LISP_MD5_AUTH_DATA_LEN = 16
LISP_SHA1_160_AUTH_DATA_LEN = 20
LISP_SHA2_256_AUTH_DATA_LEN = 32
if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
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
if 42 - 42: I1IiiI
if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
LISP_MR_TTL = ( 24 * 60 )
LISP_REGISTER_TTL = 3
LISP_SHORT_TTL = 1
LISP_NMR_TTL = 15
LISP_GLEAN_TTL = 15
LISP_MCAST_TTL = 15
LISP_IGMP_TTL = 240
if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
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
if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
LISP_RLOC_PROBE_TTL = 128
LISP_RLOC_PROBE_INTERVAL = 10
LISP_RLOC_PROBE_REPLY_WAIT = 15
LISP_DEFAULT_DYN_EID_TIMEOUT = 15
LISP_NONCE_ECHO_INTERVAL = 10
LISP_IGMP_TIMEOUT_INTERVAL = 180
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
if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
LISP_CS_1024 = 0
LISP_CS_1024_G = 2
LISP_CS_1024_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 5 - 5: Ii1I
LISP_CS_2048_CBC = 1
LISP_CS_2048_CBC_G = 2
LISP_CS_2048_CBC_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 46 - 46: IiII
LISP_CS_25519_CBC = 2
LISP_CS_2048_GCM = 3
if 45 - 45: ooOoO0o
LISP_CS_3072 = 4
LISP_CS_3072_G = 2
LISP_CS_3072_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
LISP_CS_25519_GCM = 5
LISP_CS_25519_CHACHA = 6
if 17 - 17: OOooOOo / OOooOOo / I11i
LISP_4_32_MASK = 0xFFFFFFFF
LISP_8_64_MASK = 0xFFFFFFFFFFFFFFFF
LISP_16_128_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
use_chacha = ( os . getenv ( "LISP_USE_CHACHA" ) != None )
use_poly = ( os . getenv ( "LISP_USE_POLY" ) != None )
if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
if 9 - 9: Ii1I
if 59 - 59: I1IiiI * II111iiii . O0
if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
if 27 - 27: O0
def lisp_record_traceback ( * args ) :
 if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
 ii1III11 = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
 I1iiIIIi11 = open ( "./logs/lisp-traceback.log" , "a" )
 I1iiIIIi11 . write ( "---------- Exception occurred: {} ----------\n" . format ( ii1III11 ) )
 try :
  traceback . print_last ( file = I1iiIIIi11 )
 except :
  I1iiIIIi11 . write ( "traceback.print_last(file=fd) failed" )
  if 12 - 12: OoooooooOO % o0oOOo0O0Ooo * I11i % iIii1I11I1II1 / Ii1I
 try :
  traceback . print_last ( )
 except :
  print ( "traceback.print_last() failed" )
  if 27 - 27: i11iIiiIii % II111iiii % I11i . O0 - Oo0Ooo + OoOoOO00
 I1iiIIIi11 . close ( )
 return
 if 57 - 57: iIii1I11I1II1 / I11i - i1IIi
 if 51 - 51: IiII
 if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
 if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
 if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
 if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
 if 91 - 91: i11iIiiIii / i1IIi + iII111i + ooOoO0o * i11iIiiIii
def lisp_set_exception ( ) :
 sys . excepthook = lisp_record_traceback
 return
 if 66 - 66: iIii1I11I1II1 % i1IIi - O0 + I11i * I1Ii111 . IiII
 if 52 - 52: ooOoO0o + O0 . iII111i . I1ii11iIi11i . OoO0O00
 if 97 - 97: I1IiiI / iII111i
 if 71 - 71: II111iiii / i1IIi . I1ii11iIi11i % OoooooooOO . OoOoOO00
 if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 if 100 - 100: OoO0O00
def lisp_is_raspbian ( ) :
 if ( platform . dist ( ) [ 0 ] != "debian" ) : return ( False )
 return ( platform . machine ( ) in [ "armv6l" , "armv7l" ] )
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
 if 83 - 83: OoOoOO00 . OoooooooOO
 if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
 if 62 - 62: OoO0O00 / I1ii11iIi11i
 if 7 - 7: OoooooooOO . IiII
def lisp_is_ubuntu ( ) :
 return ( platform . dist ( ) [ 0 ] == "Ubuntu" )
 if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
 if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
 if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
 if 92 - 92: ooOoO0o
 if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
 if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
 if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
def lisp_is_fedora ( ) :
 return ( platform . dist ( ) [ 0 ] == "fedora" )
 if 92 - 92: I11i . I1Ii111
 if 85 - 85: I1ii11iIi11i . I1Ii111
 if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
 if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
 if 18 - 18: iIii1I11I1II1 % I11i
 if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
 if 75 - 75: OoooooooOO * IiII
def lisp_is_centos ( ) :
 return ( platform . dist ( ) [ 0 ] == "centos" )
 if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
 if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
 if 69 - 69: O0
 if 85 - 85: ooOoO0o / O0
 if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
 if 62 - 62: I1Ii111 . IiII . OoooooooOO
 if 11 - 11: OOooOOo / I11i
def lisp_is_debian ( ) :
 return ( platform . dist ( ) [ 0 ] == "debian" )
 if 73 - 73: i1IIi / i11iIiiIii
 if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
 if 85 - 85: OoOoOO00 + OOooOOo
 if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
 if 27 - 27: Ii1I
 if 67 - 67: I1IiiI
 if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
def lisp_is_debian_kali ( ) :
 return ( platform . dist ( ) [ 0 ] == "Kali" )
 if 91 - 91: I1Ii111 - OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o
 if 98 - 98: OoO0O00 . OoO0O00 * oO0o * II111iiii * I1Ii111
 if 92 - 92: Oo0Ooo
 if 40 - 40: OoOoOO00 / IiII
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
 if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
 if 61 - 61: II111iiii
def lisp_is_macos ( ) :
 return ( platform . uname ( ) [ 0 ] == "Darwin" )
 if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 if 90 - 90: iII111i
 if 31 - 31: OOooOOo + O0
 if 87 - 87: ooOoO0o
 if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
 if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
 if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
def lisp_is_alpine ( ) :
 return ( os . path . exists ( "/etc/alpine-release" ) )
 if 13 - 13: Oo0Ooo
 if 60 - 60: I1ii11iIi11i * I1IiiI
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 if 41 - 41: Ii1I
 if 77 - 77: I1Ii111
 if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
def lisp_is_x86 ( ) :
 I1IIIiii1 = platform . machine ( )
 return ( I1IIIiii1 in ( "x86" , "i686" , "x86_64" ) )
 if 65 - 65: I11i / II111iiii * Ii1I . iII111i * oO0o % OOooOOo
 if 69 - 69: ooOoO0o - OoO0O00 / i11iIiiIii + I1ii11iIi11i % OoooooooOO
 if 73 - 73: Ii1I - I1Ii111
 if 68 - 68: iII111i * OoooooooOO * iIii1I11I1II1 . II111iiii
 if 81 - 81: OOooOOo / O0 + I11i + Ii1I / I1IiiI
 if 27 - 27: OoOoOO00 * IiII
 if 59 - 59: IiII . IiII - II111iiii + IiII . i1IIi . OoO0O00
def lisp_is_linux ( ) :
 return ( platform . uname ( ) [ 0 ] == "Linux" )
 if 57 - 57: I1IiiI + Ii1I % oO0o + oO0o / II111iiii . Ii1I
 if 17 - 17: Ii1I + oO0o . OoO0O00 - Oo0Ooo * i11iIiiIii
 if 20 - 20: I1IiiI . OoooooooOO % OOooOOo
 if 63 - 63: I1IiiI % iIii1I11I1II1
 if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
 if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
 if 59 - 59: OOooOOo + i11iIiiIii
def lisp_is_python2 ( ) :
 oo0OOo0O = sys . version . split ( ) [ 0 ]
 return ( oo0OOo0O [ 0 : 3 ] == "2.7" )
 if 39 - 39: OoooooooOO + oO0o % OOooOOo / OOooOOo
 if 27 - 27: iII111i . I11i . iIii1I11I1II1 . iIii1I11I1II1
 if 20 - 20: o0oOOo0O0Ooo / i1IIi
 if 71 - 71: OoOoOO00 . i1IIi
 if 94 - 94: OOooOOo . I1Ii111
 if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
 if 47 - 47: OoooooooOO
def lisp_is_python3 ( ) :
 oo0OOo0O = sys . version . split ( ) [ 0 ]
 return ( oo0OOo0O [ 0 : 3 ] == "3.7" )
 if 4 - 4: I1IiiI % I11i
 if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
 if 82 - 82: ooOoO0o + II111iiii
 if 39 - 39: oO0o % iIii1I11I1II1 % O0 % OoooooooOO * I1ii11iIi11i + iII111i
 if 68 - 68: Oo0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 * iIii1I11I1II1 * i11iIiiIii + I1IiiI / OOooOOo % Ii1I
 if 58 - 58: OOooOOo * o0oOOo0O0Ooo + O0 % OOooOOo
def lisp_on_aws ( ) :
 iI1I1iIi11 = getoutput ( "sudo dmidecode -s bios-vendor" )
 if ( iI1I1iIi11 . find ( "command not found" ) != - 1 and lisp_on_docker ( ) ) :
  oo0ooOO = bold ( "AWS check" , False )
  lprint ( "{} - dmidecode not installed in docker container" . format ( oo0ooOO ) )
  if 24 - 24: OoO0O00 % OoO0O00 * iIii1I11I1II1
 return ( iI1I1iIi11 . lower ( ) . find ( "amazon" ) != - 1 )
 if 50 - 50: OoO0O00 . i11iIiiIii - oO0o . oO0o
 if 31 - 31: OOooOOo / Oo0Ooo * i1IIi . OoOoOO00
 if 57 - 57: OOooOOo + iIii1I11I1II1 % i1IIi % I1IiiI
 if 83 - 83: o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 . I11i % oO0o . OoooooooOO
 if 94 - 94: Ii1I + iIii1I11I1II1 % OoO0O00
 if 93 - 93: Ii1I - OOooOOo + iIii1I11I1II1 * o0oOOo0O0Ooo + I1Ii111 . iII111i
 if 49 - 49: OoooooooOO * I11i - Oo0Ooo . oO0o
def lisp_on_gcp ( ) :
 iI1I1iIi11 = getoutput ( "sudo dmidecode -s bios-version" )
 return ( iI1I1iIi11 . lower ( ) . find ( "google" ) != - 1 )
 if 89 - 89: ooOoO0o + Ii1I * ooOoO0o / ooOoO0o
 if 46 - 46: OoO0O00
 if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
 if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
 if 68 - 68: OoooooooOO % II111iiii
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
def lisp_on_docker ( ) :
 return ( os . path . exists ( "/.dockerenv" ) )
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if 2 - 2: Ii1I - IiII
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
def lisp_process_logfile ( ) :
 I111i1I1 = "./logs/lisp-{}.log" . format ( lisp_log_id )
 if ( os . path . exists ( I111i1I1 ) ) : return
 if 62 - 62: OOooOOo * I1Ii111 / Oo0Ooo * o0oOOo0O0Ooo
 sys . stdout . close ( )
 sys . stdout = open ( I111i1I1 , "a" )
 if 29 - 29: Oo0Ooo % OoO0O00 % IiII . o0oOOo0O0Ooo / OoooooooOO * ooOoO0o
 lisp_print_banner ( bold ( "logfile rotation" , False ) )
 return
 if 54 - 54: O0
 if 68 - 68: OoO0O00 * o0oOOo0O0Ooo . ooOoO0o % oO0o % I1Ii111
 if 75 - 75: OoOoOO00
 if 34 - 34: O0
 if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
 if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
 if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
 if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
def lisp_i_am ( name ) :
 global lisp_log_id , lisp_i_am_itr , lisp_i_am_etr , lisp_i_am_rtr
 global lisp_i_am_mr , lisp_i_am_ms , lisp_i_am_ddt , lisp_i_am_core
 global lisp_hostname
 if 56 - 56: i11iIiiIii . o0oOOo0O0Ooo - I1IiiI * I11i
 lisp_log_id = name
 if ( name == "itr" ) : lisp_i_am_itr = True
 if ( name == "etr" ) : lisp_i_am_etr = True
 if ( name == "rtr" ) : lisp_i_am_rtr = True
 if ( name == "mr" ) : lisp_i_am_mr = True
 if ( name == "ms" ) : lisp_i_am_ms = True
 if ( name == "ddt" ) : lisp_i_am_ddt = True
 if ( name == "core" ) : lisp_i_am_core = True
 if 91 - 91: oO0o + OoooooooOO - i1IIi
 if 84 - 84: Ii1I / IiII
 if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
 if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
 if 37 - 37: i11iIiiIii + i1IIi
 lisp_hostname = socket . gethostname ( )
 I1i11II = lisp_hostname . find ( "." )
 if ( I1i11II != - 1 ) : lisp_hostname = lisp_hostname [ 0 : I1i11II ]
 return
 if 31 - 31: oO0o / IiII * o0oOOo0O0Ooo . II111iiii
 if 89 - 89: O0
 if 2 - 2: I1ii11iIi11i . I1ii11iIi11i + I1ii11iIi11i * o0oOOo0O0Ooo
 if 100 - 100: Oo0Ooo % Ii1I / I11i
 if 30 - 30: Oo0Ooo - OOooOOo - iII111i
 if 81 - 81: o0oOOo0O0Ooo . OoooooooOO + OOooOOo * ooOoO0o
 if 74 - 74: i1IIi + O0 + Oo0Ooo
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
def lprint ( * args ) :
 I11iIiII = ( "force" in args )
 if ( lisp_debug_logging == False and I11iIiII == False ) : return
 if 66 - 66: Oo0Ooo - o0oOOo0O0Ooo * IiII + OoOoOO00 + o0oOOo0O0Ooo - iIii1I11I1II1
 lisp_process_logfile ( )
 ii1III11 = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 ii1III11 = ii1III11 [ : - 3 ]
 print ( "{}: {}:" . format ( ii1III11 , lisp_log_id ) , end = " " )
 if 17 - 17: oO0o
 for i1ii11 in args :
  if ( i1ii11 == "force" ) : continue
  print ( i1ii11 , end = " " )
  if 49 - 49: OoooooooOO / i11iIiiIii * i11iIiiIii
 print ( )
 if 58 - 58: oO0o
 try : sys . stdout . flush ( )
 except : pass
 return
 if 4 - 4: II111iiii . ooOoO0o / I1ii11iIi11i - i11iIiiIii
 if 72 - 72: O0 / ooOoO0o + OoooooooOO * iII111i
 if 61 - 61: OoooooooOO % II111iiii - I1IiiI % I1ii11iIi11i + i1IIi
 if 39 - 39: i1IIi
 if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if 53 - 53: Ii1I % Oo0Ooo
def fprint ( * args ) :
 O0ooOo0o0Oo = args + ( "force" , )
 lprint ( * O0ooOo0o0Oo )
 return
 if 71 - 71: iIii1I11I1II1 - OOooOOo . I1IiiI % OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 if 31 - 31: I11i % OOooOOo * I11i
 if 45 - 45: i1IIi . I1IiiI + OOooOOo - OoooooooOO % ooOoO0o
 if 1 - 1: iIii1I11I1II1
 if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
 if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
def dprint ( * args ) :
 if ( lisp_data_plane_logging ) : lprint ( * args )
 return
 if 4 - 4: OoooooooOO . ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if 10 - 10: I1Ii111 % I1IiiI
 if 97 - 97: OoooooooOO - I1Ii111
 if 58 - 58: iIii1I11I1II1 + O0
 if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
 if 46 - 46: i11iIiiIii - O0 . oO0o
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
def debug ( * args ) :
 lisp_process_logfile ( )
 if 83 - 83: I1Ii111
 ii1III11 = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 ii1III11 = ii1III11 [ : - 3 ]
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 print ( red ( ">>>" , False ) , end = " " )
 print ( "{}:" . format ( ii1III11 ) , end = " " )
 for i1ii11 in args : print ( i1ii11 , end = " " )
 print ( red ( "<<<\n" , False ) )
 try : sys . stdout . flush ( )
 except : pass
 return
 if 50 - 50: IiII % i1IIi
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
 if 62 - 62: i1IIi - OoOoOO00
 if 62 - 62: i1IIi + Oo0Ooo % IiII
def lisp_print_caller ( ) :
 fprint ( traceback . print_last ( ) )
 if 28 - 28: I1ii11iIi11i . i1IIi
 if 10 - 10: OoO0O00 / Oo0Ooo
 if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
 if 57 - 57: O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
def lisp_print_banner ( string ) :
 global lisp_version , lisp_hostname
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if ( lisp_version == "" ) :
  lisp_version = getoutput ( "cat lisp-version.txt" )
  if 23 - 23: II111iiii / oO0o
 iII1Iii1I11i = bold ( lisp_hostname , False )
 lprint ( "lispers.net LISP {} {}, version {}, hostname {}" . format ( string ,
 datetime . datetime . now ( ) , lisp_version , iII1Iii1I11i ) )
 return
 if 17 - 17: O0
 if 88 - 88: Oo0Ooo . O0 % OoooooooOO / OOooOOo
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
def green ( string , html ) :
 if ( html ) : return ( '<font color="green"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[92m" + string + "\033[0m" , html ) )
 if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 if 19 - 19: i11iIiiIii
 if 54 - 54: II111iiii . I11i
 if 73 - 73: OoOoOO00 . I1IiiI
 if 32 - 32: OoOoOO00 * I1IiiI % ooOoO0o * Ii1I . O0
 if 48 - 48: iII111i * iII111i
def green_last_sec ( string ) :
 return ( green ( string , True ) )
 if 13 - 13: Ii1I / I11i + OoOoOO00 . o0oOOo0O0Ooo % ooOoO0o
 if 48 - 48: I1IiiI / i11iIiiIii - o0oOOo0O0Ooo * oO0o / OoooooooOO
 if 89 - 89: iIii1I11I1II1 / I1IiiI - II111iiii / Ii1I . i11iIiiIii . Ii1I
 if 48 - 48: O0 + O0 . I1Ii111 - ooOoO0o
 if 63 - 63: oO0o
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 if 36 - 36: IiII
def green_last_min ( string ) :
 return ( '<font color="#58D68D"><b>{}</b></font>' . format ( string ) )
 if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
 if 74 - 74: I1Ii111 % I1ii11iIi11i
 if 7 - 7: II111iiii
 if 27 - 27: oO0o . OoooooooOO + i11iIiiIii
 if 86 - 86: I11i / o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + oO0o
 if 33 - 33: o0oOOo0O0Ooo . iII111i . IiII . i1IIi
 if 49 - 49: I1ii11iIi11i
def red ( string , html ) :
 if ( html ) : return ( '<font color="red"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[91m" + string + "\033[0m" , html ) )
 if 84 - 84: I11i - Oo0Ooo / O0 - I1Ii111
 if 21 - 21: O0 * O0 % I1ii11iIi11i
 if 94 - 94: I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
 if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 if 34 - 34: ooOoO0o
def blue ( string , html ) :
 if ( html ) : return ( '<font color="blue"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[94m" + string + "\033[0m" , html ) )
 if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
 if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
 if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
 if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
 if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
def bold ( string , html ) :
 if ( html ) : return ( "<b>{}</b>" . format ( string ) )
 return ( "\033[1m" + string + "\033[0m" )
 if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
 if 23 - 23: I11i
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
def convert_font ( string ) :
 I1Iii1iI1 = [ [ "[91m" , red ] , [ "[92m" , green ] , [ "[94m" , blue ] , [ "[1m" , bold ] ]
 o0 = "[0m"
 if 93 - 93: i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / o0oOOo0O0Ooo / II111iiii
 for I1i in I1Iii1iI1 :
  Oo = I1i [ 0 ]
  IiIiIi1I1 = I1i [ 1 ]
  IiI1ii1Ii = len ( Oo )
  I1i11II = string . find ( Oo )
  if ( I1i11II != - 1 ) : break
  if 51 - 51: i11iIiiIii * o0oOOo0O0Ooo / I1IiiI
  if 40 - 40: I1IiiI
 while ( I1i11II != - 1 ) :
  I1I1 = string [ I1i11II : : ] . find ( o0 )
  O0oOoo0OoO0O = string [ I1i11II + IiI1ii1Ii : I1i11II + I1I1 ]
  string = string [ : I1i11II ] + IiIiIi1I1 ( O0oOoo0OoO0O , True ) + string [ I1i11II + I1I1 + IiI1ii1Ii : : ]
  if 63 - 63: OoooooooOO / ooOoO0o
  I1i11II = string . find ( Oo )
  if 91 - 91: i1IIi - iIii1I11I1II1
  if 55 - 55: I1IiiI * o0oOOo0O0Ooo % ooOoO0o . iIii1I11I1II1 * I1Ii111
  if 92 - 92: I1Ii111 - iIii1I11I1II1
  if 32 - 32: Ii1I % OoO0O00 * OoO0O00 + IiII * II111iiii * Ii1I
  if 11 - 11: oO0o % II111iiii
 if ( string . find ( "[1m" ) != - 1 ) : string = convert_font ( string )
 return ( string )
 if 57 - 57: OOooOOo / Oo0Ooo
 if 69 - 69: oO0o - Oo0Ooo % IiII
 if 50 - 50: OoooooooOO
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
 if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
def lisp_space ( num ) :
 OoiIIIiIi1I1i = ""
 for OoOOoO0oOo in range ( num ) : OoiIIIiIi1I1i += "&#160;"
 return ( OoiIIIiIi1I1i )
 if 70 - 70: I11i % iIii1I11I1II1 . Oo0Ooo + Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 if 87 - 87: OoO0O00 % I1IiiI
 if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
def lisp_button ( string , url ) :
 ooOo0O0O0oOO0 = '<button style="background-color:transparent;border-radius:10px; ' + 'type="button">'
 if 10 - 10: Oo0Ooo + O0
 if 43 - 43: iIii1I11I1II1 / II111iiii % o0oOOo0O0Ooo - OOooOOo
 if ( url == None ) :
  oO0O000oOo = ooOo0O0O0oOO0 + string + "</button>"
 else :
  OoOOOO = '<a href="{}">' . format ( url )
  I1iiIi111I = lisp_space ( 2 )
  oO0O000oOo = I1iiIi111I + OoOOOO + ooOo0O0O0oOO0 + string + "</button></a>" + I1iiIi111I
  if 34 - 34: i11iIiiIii - II111iiii / I1IiiI % o0oOOo0O0Ooo
 return ( oO0O000oOo )
 if 33 - 33: OOooOOo
 if 35 - 35: i11iIiiIii - I1IiiI / OOooOOo + Ii1I * oO0o
 if 49 - 49: o0oOOo0O0Ooo * Ii1I + I11i + iII111i
 if 30 - 30: o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 if 50 - 50: ooOoO0o + i1IIi
 if 31 - 31: Ii1I
def lisp_print_cour ( string ) :
 OoiIIIiIi1I1i = '<font face="Courier New">{}</font>' . format ( string )
 return ( OoiIIIiIi1I1i )
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
 if 66 - 66: I1IiiI - IiII
 if 33 - 33: I1IiiI / OoO0O00
 if 12 - 12: II111iiii
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
def lisp_print_sans ( string ) :
 OoiIIIiIi1I1i = '<font face="Sans-Serif">{}</font>' . format ( string )
 return ( OoiIIIiIi1I1i )
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if 47 - 47: iII111i
 if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
def lisp_span ( string , hover_string ) :
 OoiIIIiIi1I1i = '<span title="{}">{}</span>' . format ( hover_string , string )
 return ( OoiIIIiIi1I1i )
 if 47 - 47: oO0o % iIii1I11I1II1
 if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
 if 98 - 98: iII111i + Ii1I - OoO0O00
 if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
 if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
 if 38 - 38: O0 - IiII % I1Ii111
 if 64 - 64: iIii1I11I1II1
def lisp_eid_help_hover ( output ) :
 IIi1iI = '''Unicast EID format:
  For longest match lookups: 
    <address> or [<iid>]<address>
  For exact match lookups: 
    <prefix> or [<iid>]<prefix>
Multicast EID format:
  For longest match lookups:
    <address>-><group> or
    [<iid>]<address>->[<iid>]<group>'''
 if 92 - 92: OoO0O00 * ooOoO0o
 if 35 - 35: i11iIiiIii
 ooO = lisp_span ( output , IIi1iI )
 return ( ooO )
 if 55 - 55: I11i
 if 83 - 83: IiII * I11i / Oo0Ooo
 if 32 - 32: o0oOOo0O0Ooo + OoOoOO00 - OoooooooOO
 if 39 - 39: OoooooooOO * OOooOOo * O0 . I11i . OoO0O00 + ooOoO0o
 if 9 - 9: OoOoOO00 + oO0o % OoooooooOO + o0oOOo0O0Ooo
 if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
def lisp_geo_help_hover ( output ) :
 IIi1iI = '''EID format:
    <address> or [<iid>]<address>
    '<name>' or [<iid>]'<name>'
Geo-Point format:
    d-m-s-<N|S>-d-m-s-<W|E> or 
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>
Geo-Prefix format:
    d-m-s-<N|S>-d-m-s-<W|E>/<km> or
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>/<km>'''
 if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
 if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
 ooO = lisp_span ( output , IIi1iI )
 return ( ooO )
 if 52 - 52: OoO0O00 % Ii1I * II111iiii
 if 4 - 4: I11i % O0 - OoooooooOO + ooOoO0o . oO0o % II111iiii
 if 9 - 9: II111iiii * II111iiii . i11iIiiIii * iIii1I11I1II1
 if 18 - 18: OoO0O00 . II111iiii % OoOoOO00 % Ii1I
 if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
def space ( num ) :
 OoiIIIiIi1I1i = ""
 for OoOOoO0oOo in range ( num ) : OoiIIIiIi1I1i += "&#160;"
 return ( OoiIIIiIi1I1i )
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 if 29 - 29: O0 . I1Ii111
 if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
 if 70 - 70: I1Ii111 + oO0o
 if 93 - 93: I1Ii111 + Ii1I
def lisp_get_ephemeral_port ( ) :
 return ( random . randrange ( 32768 , 65535 ) )
 if 33 - 33: O0
 if 78 - 78: O0 / II111iiii * OoO0O00
 if 50 - 50: OoooooooOO - iIii1I11I1II1 + i1IIi % I1Ii111 - iIii1I11I1II1 % O0
 if 58 - 58: IiII + iIii1I11I1II1
 if 65 - 65: II111iiii - I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 * iII111i + Ii1I
 if 79 - 79: ooOoO0o . OoOoOO00 % I1Ii111 - Oo0Ooo
 if 69 - 69: ooOoO0o - o0oOOo0O0Ooo . ooOoO0o
def lisp_get_data_nonce ( ) :
 return ( random . randint ( 0 , 0xffffff ) )
 if 9 - 9: oO0o % i11iIiiIii / Oo0Ooo
 if 20 - 20: oO0o * O0 + I11i - OoooooooOO . I11i
 if 60 - 60: o0oOOo0O0Ooo . o0oOOo0O0Ooo / iII111i
 if 45 - 45: O0 . i11iIiiIii % iII111i . OoOoOO00 % IiII % iIii1I11I1II1
 if 58 - 58: iIii1I11I1II1 . OoOoOO00 - i11iIiiIii * iIii1I11I1II1 % i11iIiiIii / I1IiiI
 if 80 - 80: I1ii11iIi11i / iIii1I11I1II1 % OoOoOO00
 if 80 - 80: OoO0O00 % iII111i
def lisp_get_control_nonce ( ) :
 return ( random . randint ( 0 , ( 2 ** 64 ) - 1 ) )
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if 13 - 13: OoO0O00
 if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
 if 2 - 2: OoooooooOO . OOooOOo . IiII
 if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 if 24 - 24: o0oOOo0O0Ooo
 if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
 if 28 - 28: OOooOOo % ooOoO0o
def lisp_hex_string ( integer_value ) :
 iiIiII11i1 = hex ( integer_value ) [ 2 : : ]
 if ( iiIiII11i1 [ - 1 ] == "L" ) : iiIiII11i1 = iiIiII11i1 [ 0 : - 1 ]
 return ( iiIiII11i1 )
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 if 21 - 21: OOooOOo
 if 6 - 6: IiII
 if 46 - 46: IiII + oO0o
def lisp_get_timestamp ( ) :
 return ( time . time ( ) )
 if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
 if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
 if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
 if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
def lisp_set_timestamp ( seconds ) :
 return ( time . time ( ) + seconds )
 if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
 if 24 - 24: OoOoOO00
 if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
 if 28 - 28: I1IiiI
 if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
 if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
def lisp_print_elapsed ( ts ) :
 if ( ts == 0 or ts == None ) : return ( "never" )
 Ii1i1 = time . time ( ) - ts
 Ii1i1 = round ( Ii1i1 , 0 )
 return ( str ( datetime . timedelta ( seconds = Ii1i1 ) ) )
 if 65 - 65: oO0o + I1ii11iIi11i / OOooOOo
 if 85 - 85: iIii1I11I1II1 / OoooooooOO % II111iiii
 if 49 - 49: i11iIiiIii % OoOoOO00 + I1Ii111 . II111iiii % iII111i * OOooOOo
 if 67 - 67: i1IIi
 if 5 - 5: II111iiii . OoooooooOO
 if 57 - 57: I1IiiI
 if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
def lisp_print_future ( ts ) :
 if ( ts == 0 ) : return ( "never" )
 iii11i1 = ts - time . time ( )
 if ( iii11i1 < 0 ) : return ( "expired" )
 iii11i1 = round ( iii11i1 , 0 )
 return ( str ( datetime . timedelta ( seconds = iii11i1 ) ) )
 if 48 - 48: ooOoO0o * I1ii11iIi11i
 if 15 - 15: OoO0O00 * I11i % iIii1I11I1II1 * I1ii11iIi11i
 if 31 - 31: OoO0O00 * O0 . oO0o
 if 59 - 59: II111iiii * i11iIiiIii
 if 54 - 54: O0 % OoooooooOO - I1IiiI
 if 61 - 61: Oo0Ooo * IiII . Oo0Ooo + Oo0Ooo / IiII * O0
 if 73 - 73: iII111i * iII111i / ooOoO0o
 if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
 if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
 if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
def lisp_print_eid_tuple ( eid , group ) :
 iIiI1I1ii1I1 = eid . print_prefix ( )
 if ( group . is_null ( ) ) : return ( iIiI1I1ii1I1 )
 if 83 - 83: OOooOOo / O0 % iII111i - o0oOOo0O0Ooo . Oo0Ooo
 iiiii1I1III1 = group . print_prefix ( )
 i1 = group . instance_id
 if 93 - 93: Oo0Ooo / IiII % I1ii11iIi11i
 if ( eid . is_null ( ) or eid . is_exact_match ( group ) ) :
  I1i11II = iiiii1I1III1 . find ( "]" ) + 1
  return ( "[{}](*, {})" . format ( i1 , iiiii1I1III1 [ I1i11II : : ] ) )
  if 77 - 77: i11iIiiIii % i1IIi % IiII
  if 15 - 15: iIii1I11I1II1 . O0
 O0o0O = eid . print_sg ( group )
 return ( O0o0O )
 if 6 - 6: II111iiii
 if 7 - 7: Ii1I % i1IIi * OoooooooOO * O0 + iII111i
 if 95 - 95: OoooooooOO + I11i - I1ii11iIi11i / I1ii11iIi11i . i1IIi . OoooooooOO
 if 29 - 29: ooOoO0o - i1IIi . I11i - I1ii11iIi11i + ooOoO0o + OoooooooOO
 if 36 - 36: i1IIi / ooOoO0o . iIii1I11I1II1
 if 12 - 12: Ii1I
 if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
def lisp_convert_6to4 ( addr_str ) :
 if ( addr_str . find ( "::ffff:" ) == - 1 ) : return ( addr_str )
 IiIIiiI = addr_str . split ( ":" )
 return ( IiIIiiI [ - 1 ] )
 if 60 - 60: I1Ii111
 if 98 - 98: ooOoO0o
 if 34 - 34: iIii1I11I1II1 * I11i * I11i / I1ii11iIi11i
 if 28 - 28: OoO0O00 - oO0o + OoOoOO00 + Ii1I / iIii1I11I1II1
 if 26 - 26: iIii1I11I1II1 - O0 . O0
 if 68 - 68: OOooOOo + oO0o . O0 . Ii1I % i1IIi % OOooOOo
 if 50 - 50: IiII + o0oOOo0O0Ooo
 if 96 - 96: OoO0O00
 if 92 - 92: Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 if 87 - 87: OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
def lisp_convert_4to6 ( addr_str ) :
 IiIIiiI = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 if ( IiIIiiI . is_ipv4_string ( addr_str ) ) : addr_str = "::ffff:" + addr_str
 IiIIiiI . store_address ( addr_str )
 return ( IiIIiiI )
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
def lisp_gethostbyname ( string ) :
 Oo00O0OO = string . split ( "." )
 oOOOoo0o = string . split ( ":" )
 iiiI1IiIIii = string . split ( "-" )
 if 25 - 25: I1ii11iIi11i + oO0o + OoooooooOO . II111iiii . iII111i
 if ( len ( Oo00O0OO ) == 4 ) :
  if ( Oo00O0OO [ 0 ] . isdigit ( ) and Oo00O0OO [ 1 ] . isdigit ( ) and Oo00O0OO [ 2 ] . isdigit ( ) and
 Oo00O0OO [ 3 ] . isdigit ( ) ) : return ( string )
  if 66 - 66: ooOoO0o * OoOoOO00
 if ( len ( oOOOoo0o ) > 1 ) :
  try :
   int ( oOOOoo0o [ 0 ] , 16 )
   return ( string )
  except :
   pass
   if 2 - 2: oO0o . I1Ii111 * Oo0Ooo + O0 - I11i * iIii1I11I1II1
   if 12 - 12: o0oOOo0O0Ooo * I1Ii111 % II111iiii * i1IIi * iIii1I11I1II1
   if 81 - 81: Oo0Ooo - I11i
   if 24 - 24: OoooooooOO . OoO0O00 * II111iiii
   if 59 - 59: I1Ii111 + OoO0O00 / OOooOOo
   if 97 - 97: Oo0Ooo * iII111i % ooOoO0o . iII111i - I1Ii111 - OOooOOo
   if 79 - 79: I1IiiI - ooOoO0o
 if ( len ( iiiI1IiIIii ) == 3 ) :
  for OoOOoO0oOo in range ( 3 ) :
   try : int ( iiiI1IiIIii [ OoOOoO0oOo ] , 16 )
   except : break
   if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
   if 83 - 83: IiII / I1Ii111
   if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 try :
  IiIIiiI = socket . gethostbyname ( string )
  return ( IiIIiiI )
 except :
  if ( lisp_is_alpine ( ) == False ) : return ( "" )
  if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
  if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
  if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
  if 80 - 80: OoooooooOO + IiII
  if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 try :
  IiIIiiI = socket . getaddrinfo ( string , 0 ) [ 0 ]
  if ( IiIIiiI [ 3 ] != string ) : return ( "" )
  IiIIiiI = IiIIiiI [ 4 ] [ 0 ]
 except :
  IiIIiiI = ""
  if 43 - 43: Oo0Ooo . I1Ii111
 return ( IiIIiiI )
 if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
 if 29 - 29: IiII . ooOoO0o - II111iiii
 if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
 if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
 if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
def lisp_ip_checksum ( data , hdrlen = 20 ) :
 if ( len ( data ) < hdrlen ) :
  lprint ( "IPv4 packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 5 - 5: IiII
  if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 O0O = binascii . hexlify ( data )
 if 80 - 80: iIii1I11I1II1
 if 23 - 23: II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 if 49 - 49: IiII * O0 . IiII
 ii1II1II = 0
 for OoOOoO0oOo in range ( 0 , hdrlen * 2 , 4 ) :
  ii1II1II += int ( O0O [ OoOOoO0oOo : OoOOoO0oOo + 4 ] , 16 )
  if 42 - 42: Ii1I
  if 68 - 68: OOooOOo . Oo0Ooo % ooOoO0o - OoooooooOO * iII111i . OOooOOo
  if 46 - 46: i11iIiiIii - OOooOOo * I1IiiI * I11i % I1ii11iIi11i * i1IIi
  if 5 - 5: O0 / ooOoO0o . Oo0Ooo + OoooooooOO
  if 97 - 97: IiII . Ii1I . Ii1I / iIii1I11I1II1 - OoO0O00 + iII111i
 ii1II1II = ( ii1II1II >> 16 ) + ( ii1II1II & 0xffff )
 ii1II1II += ii1II1II >> 16
 ii1II1II = socket . htons ( ~ ii1II1II & 0xffff )
 if 32 - 32: OOooOOo . o0oOOo0O0Ooo % IiII + I1ii11iIi11i + OoO0O00
 if 76 - 76: OoO0O00 - i11iIiiIii + OoOoOO00 + OOooOOo / OoooooooOO
 if 50 - 50: II111iiii - I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1
 if 91 - 91: II111iiii - O0 . iIii1I11I1II1 . O0 + I1ii11iIi11i - II111iiii
 ii1II1II = struct . pack ( "H" , ii1II1II )
 O0O = data [ 0 : 10 ] + ii1II1II + data [ 12 : : ]
 return ( O0O )
 if 26 - 26: o0oOOo0O0Ooo
 if 12 - 12: OoooooooOO / O0 + II111iiii * I1ii11iIi11i
 if 46 - 46: II111iiii - IiII * OoooooooOO / oO0o % IiII
 if 11 - 11: iIii1I11I1II1 . OoOoOO00 / IiII % ooOoO0o
 if 61 - 61: ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 if 3 - 3: OoooooooOO
def lisp_icmp_checksum ( data ) :
 if ( len ( data ) < 36 ) :
  lprint ( "ICMP packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
  if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 IIii1III = binascii . hexlify ( data )
 if 94 - 94: i11iIiiIii % OoooooooOO / I1IiiI
 if 24 - 24: I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 ii1II1II = 0
 for OoOOoO0oOo in range ( 0 , 36 , 4 ) :
  ii1II1II += int ( IIii1III [ OoOOoO0oOo : OoOOoO0oOo + 4 ] , 16 )
  if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
  if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
  if 27 - 27: OOooOOo
  if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
  if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 ii1II1II = ( ii1II1II >> 16 ) + ( ii1II1II & 0xffff )
 ii1II1II += ii1II1II >> 16
 ii1II1II = socket . htons ( ~ ii1II1II & 0xffff )
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 ii1II1II = struct . pack ( "H" , ii1II1II )
 IIii1III = data [ 0 : 2 ] + ii1II1II + data [ 4 : : ]
 return ( IIii1III )
 if 43 - 43: OoO0O00 % OoO0O00
 if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
 if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
 if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
 if 45 - 45: Ii1I - OOooOOo
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 if 36 - 36: I11i % OOooOOo
 if 72 - 72: I1IiiI / iII111i - O0 + I11i
 if 83 - 83: O0
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 if 41 - 41: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 100 - 100: Ii1I + iIii1I11I1II1
 if 59 - 59: IiII
 if 89 - 89: OoOoOO00 % iIii1I11I1II1
 if 35 - 35: I1ii11iIi11i + I1Ii111 - OoOoOO00 % oO0o % o0oOOo0O0Ooo % OoOoOO00
 if 45 - 45: I1IiiI * OOooOOo % OoO0O00
 if 24 - 24: ooOoO0o - I11i * oO0o
 if 87 - 87: Ii1I - I1ii11iIi11i % I1ii11iIi11i . oO0o / I1ii11iIi11i
 if 6 - 6: OoOoOO00 / iIii1I11I1II1 * OoooooooOO * i11iIiiIii
 if 79 - 79: IiII % OoO0O00
 if 81 - 81: i11iIiiIii + i11iIiiIii * OoO0O00 + IiII
 if 32 - 32: O0 . OoooooooOO
 if 15 - 15: I1IiiI . OoO0O00
 if 17 - 17: i11iIiiIii / Oo0Ooo . OoO0O00 / I1IiiI
 if 38 - 38: i1IIi . I1ii11iIi11i % Ii1I + iIii1I11I1II1 + O0
 if 47 - 47: OoO0O00 + IiII / II111iiii
 if 97 - 97: I1ii11iIi11i / I1IiiI % O0 + i1IIi - ooOoO0o
 if 38 - 38: o0oOOo0O0Ooo % I1Ii111 + i11iIiiIii + iII111i + ooOoO0o / i11iIiiIii
def lisp_udp_checksum ( source , dest , data ) :
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 I1iiIi111I = lisp_address ( LISP_AFI_IPV6 , source , LISP_IPV6_HOST_MASK_LEN , 0 )
 IiI11I111 = lisp_address ( LISP_AFI_IPV6 , dest , LISP_IPV6_HOST_MASK_LEN , 0 )
 Ooo000O00 = socket . htonl ( len ( data ) )
 i1iI1Iiii1I = socket . htonl ( LISP_UDP_PROTOCOL )
 I1iII = I1iiIi111I . pack_address ( )
 I1iII += IiI11I111 . pack_address ( )
 I1iII += struct . pack ( "II" , Ooo000O00 , i1iI1Iiii1I )
 if 29 - 29: i1IIi % iII111i / IiII + OoOoOO00 - OOooOOo - I1ii11iIi11i
 if 69 - 69: iIii1I11I1II1 . II111iiii . i1IIi - o0oOOo0O0Ooo
 if 79 - 79: ooOoO0o % OOooOOo
 if 54 - 54: OoOoOO00 - I1Ii111
 O0I1II1 = binascii . hexlify ( I1iII + data )
 oOOoo = len ( O0I1II1 ) % 4
 for OoOOoO0oOo in range ( 0 , oOOoo ) : O0I1II1 += "0"
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 ii1II1II = 0
 for OoOOoO0oOo in range ( 0 , len ( O0I1II1 ) , 4 ) :
  ii1II1II += int ( O0I1II1 [ OoOOoO0oOo : OoOOoO0oOo + 4 ] , 16 )
  if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
  if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
  if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
  if 79 - 79: oO0o - II111iiii
  if 43 - 43: i1IIi + O0 % OoO0O00 / Ii1I * I1IiiI
 ii1II1II = ( ii1II1II >> 16 ) + ( ii1II1II & 0xffff )
 ii1II1II += ii1II1II >> 16
 ii1II1II = socket . htons ( ~ ii1II1II & 0xffff )
 if 89 - 89: I1IiiI . Oo0Ooo + I1ii11iIi11i . O0 % o0oOOo0O0Ooo
 if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
 if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
 if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
 ii1II1II = struct . pack ( "H" , ii1II1II )
 O0I1II1 = data [ 0 : 6 ] + ii1II1II + data [ 8 : : ]
 return ( O0I1II1 )
 if 12 - 12: I1ii11iIi11i / Ii1I
 if 5 - 5: OoooooooOO
 if 18 - 18: I1IiiI % OoooooooOO - iII111i . i11iIiiIii * Oo0Ooo % Ii1I
 if 12 - 12: i1IIi / OOooOOo % ooOoO0o * IiII * O0 * iIii1I11I1II1
 if 93 - 93: Oo0Ooo / I1ii11iIi11i + i1IIi * oO0o . OoooooooOO
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 if 33 - 33: I11i % II111iiii + OoO0O00
def lisp_igmp_checksum ( igmp ) :
 OoIi1I1I = binascii . hexlify ( igmp )
 if 56 - 56: O0
 if 45 - 45: OoOoOO00 - OoO0O00 - OoOoOO00
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
 ii1II1II = 0
 for OoOOoO0oOo in range ( 0 , 24 , 4 ) :
  ii1II1II += int ( OoIi1I1I [ OoOOoO0oOo : OoOOoO0oOo + 4 ] , 16 )
  if 69 - 69: ooOoO0o % ooOoO0o
  if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
  if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
  if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
  if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
 ii1II1II = ( ii1II1II >> 16 ) + ( ii1II1II & 0xffff )
 ii1II1II += ii1II1II >> 16
 ii1II1II = socket . htons ( ~ ii1II1II & 0xffff )
 if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
 if 33 - 33: Ii1I
 if 93 - 93: ooOoO0o
 if 34 - 34: oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
 ii1II1II = struct . pack ( "H" , ii1II1II )
 igmp = igmp [ 0 : 2 ] + ii1II1II + igmp [ 4 : : ]
 return ( igmp )
 if 19 - 19: I1ii11iIi11i
 if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
 if 66 - 66: O0
 if 52 - 52: OoO0O00 * OoooooooOO
 if 12 - 12: O0 + IiII * i1IIi . OoO0O00
 if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
 if 28 - 28: iIii1I11I1II1
def lisp_get_interface_address ( device ) :
 if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
 if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
 if ( device not in netifaces . interfaces ( ) ) : return ( None )
 if 46 - 46: OoOoOO00 - O0
 if 70 - 70: I11i + Oo0Ooo * iIii1I11I1II1 . I1IiiI * I11i
 if 49 - 49: o0oOOo0O0Ooo
 if 25 - 25: iII111i . OoooooooOO * iIii1I11I1II1 . o0oOOo0O0Ooo / O0 + Ii1I
 ooo0o0 = netifaces . ifaddresses ( device )
 if ( ooo0o0 . has_key ( netifaces . AF_INET ) == False ) : return ( None )
 if 84 - 84: I11i - Oo0Ooo * O0 / Ii1I . Ii1I
 if 93 - 93: O0 / ooOoO0o + I1IiiI
 if 20 - 20: IiII / iII111i % OoooooooOO / iIii1I11I1II1 + I1IiiI
 if 57 - 57: o0oOOo0O0Ooo / I1Ii111
 iiIiII = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 7 - 7: Oo0Ooo - i1IIi . I1ii11iIi11i / iIii1I11I1II1 * o0oOOo0O0Ooo
 for IiIIiiI in ooo0o0 [ netifaces . AF_INET ] :
  O0O0 = IiIIiiI [ "addr" ]
  iiIiII . store_address ( O0O0 )
  return ( iiIiII )
  if 70 - 70: OOooOOo * oO0o / I1IiiI * OoOoOO00 * I1IiiI
 return ( None )
 if 61 - 61: oO0o + I1ii11iIi11i / i1IIi * oO0o
 if 90 - 90: Ii1I % oO0o
 if 6 - 6: OoooooooOO / i11iIiiIii / I1Ii111
 if 60 - 60: I1IiiI % oO0o / o0oOOo0O0Ooo % oO0o * i11iIiiIii / iII111i
 if 34 - 34: I1Ii111 - OOooOOo
 if 25 - 25: oO0o % I1IiiI + i11iIiiIii + O0 * OoooooooOO
 if 64 - 64: i1IIi
 if 10 - 10: I1Ii111 % O0 / I1IiiI % I11i
 if 25 - 25: II111iiii / OoO0O00
 if 64 - 64: O0 % ooOoO0o
 if 40 - 40: o0oOOo0O0Ooo + I11i
 if 77 - 77: i11iIiiIii % IiII + I1Ii111 % OoooooooOO - I11i
def lisp_get_input_interface ( packet ) :
 iIIiiIi = lisp_format_packet ( packet [ 0 : 12 ] ) . replace ( " " , "" )
 i1I111II = iIIiiIi [ 0 : 12 ]
 Oo0OOo = iIIiiIi [ 12 : : ]
 if 44 - 44: I11i * o0oOOo0O0Ooo
 try : II11ii1I11 = lisp_mymacs . has_key ( Oo0OOo )
 except : II11ii1I11 = False
 if 65 - 65: OOooOOo + II111iiii
 if ( lisp_mymacs . has_key ( i1I111II ) ) : return ( lisp_mymacs [ i1I111II ] , Oo0OOo , i1I111II , II11ii1I11 )
 if ( II11ii1I11 ) : return ( lisp_mymacs [ Oo0OOo ] , Oo0OOo , i1I111II , II11ii1I11 )
 return ( [ "?" ] , Oo0OOo , i1I111II , II11ii1I11 )
 if 61 - 61: i11iIiiIii * oO0o % Oo0Ooo * I1Ii111 - OoooooooOO - OoO0O00
 if 83 - 83: ooOoO0o / OOooOOo
 if 39 - 39: IiII + I11i
 if 9 - 9: I1IiiI % I11i . Oo0Ooo * I1IiiI
 if 99 - 99: O0 . o0oOOo0O0Ooo % I11i - Oo0Ooo / I11i
 if 20 - 20: OoOoOO00 * iII111i
 if 19 - 19: OoooooooOO
 if 76 - 76: OoO0O00 * oO0o
def lisp_get_local_interfaces ( ) :
 for OoO in netifaces . interfaces ( ) :
  iI1ii1iI1 = lisp_interface ( OoO )
  iI1ii1iI1 . add_interface ( )
  if 10 - 10: oO0o . Ii1I * OoOoOO00 * I1IiiI
 return
 if 43 - 43: ooOoO0o * I1Ii111 % OOooOOo
 if 38 - 38: Oo0Ooo
 if 34 - 34: OoOoOO00
 if 70 - 70: iIii1I11I1II1 * IiII - OOooOOo / Oo0Ooo % oO0o
 if 66 - 66: OoooooooOO + ooOoO0o * iII111i
 if 2 - 2: iII111i . OoO0O00 / oO0o
 if 41 - 41: OoO0O00 . I1Ii111 * IiII * I1Ii111
def lisp_get_loopback_address ( ) :
 for IiIIiiI in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( IiIIiiI [ "peer" ] == "127.0.0.1" ) : continue
  return ( IiIIiiI [ "peer" ] )
  if 74 - 74: iIii1I11I1II1 / o0oOOo0O0Ooo
 return ( None )
 if 58 - 58: iIii1I11I1II1 - I1IiiI % o0oOOo0O0Ooo % OoooooooOO * iIii1I11I1II1 + OOooOOo
 if 25 - 25: OOooOOo % O0
 if 44 - 44: I1Ii111 . Ii1I * II111iiii / IiII + iIii1I11I1II1
 if 14 - 14: O0 % IiII % Ii1I * oO0o
 if 65 - 65: I11i % oO0o + I1ii11iIi11i
 if 86 - 86: iIii1I11I1II1 / O0 . I1Ii111 % iIii1I11I1II1 % Oo0Ooo
 if 86 - 86: i11iIiiIii - o0oOOo0O0Ooo . ooOoO0o * Oo0Ooo / Ii1I % o0oOOo0O0Ooo
 if 61 - 61: o0oOOo0O0Ooo + OoOoOO00
def lisp_is_mac_string ( mac_str ) :
 iiiI1IiIIii = mac_str . split ( "/" )
 if ( len ( iiiI1IiIIii ) == 2 ) : mac_str = iiiI1IiIIii [ 0 ]
 return ( len ( mac_str ) == 14 and mac_str . count ( "-" ) == 2 )
 if 15 - 15: OoOoOO00 * oO0o + OOooOOo . I11i % I1IiiI - ooOoO0o
 if 13 - 13: OoOoOO00 % OoOoOO00 % Oo0Ooo % I1IiiI * i1IIi % I11i
 if 82 - 82: IiII . OoOoOO00 / ooOoO0o + iII111i - ooOoO0o
 if 55 - 55: ooOoO0o % Oo0Ooo % o0oOOo0O0Ooo
 if 29 - 29: IiII / iIii1I11I1II1 + I1ii11iIi11i % iII111i % I11i
 if 46 - 46: iIii1I11I1II1
 if 70 - 70: i1IIi . I11i
 if 74 - 74: I11i
def lisp_get_local_macs ( ) :
 for OoO in netifaces . interfaces ( ) :
  if 58 - 58: iIii1I11I1II1 * OoO0O00 * I1Ii111 * ooOoO0o . OoooooooOO
  if 6 - 6: I1ii11iIi11i - oO0o * i11iIiiIii + OoOoOO00 / ooOoO0o % OOooOOo
  if 38 - 38: OOooOOo % IiII % II111iiii - Oo0Ooo - iIii1I11I1II1
  if 9 - 9: o0oOOo0O0Ooo % I1ii11iIi11i . I1ii11iIi11i
  if 28 - 28: OoooooooOO % oO0o + I1ii11iIi11i + O0 . I1Ii111
  IiI11I111 = OoO . replace ( ":" , "" )
  IiI11I111 = OoO . replace ( "-" , "" )
  if ( IiI11I111 . isalnum ( ) == False ) : continue
  if 80 - 80: i11iIiiIii % I1ii11iIi11i
  if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
  if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
  if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
  if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
  try :
   iiii11IiIiI = netifaces . ifaddresses ( OoO )
  except :
   continue
   if 8 - 8: I1Ii111 + OoO0O00
  if ( iiii11IiIiI . has_key ( netifaces . AF_LINK ) == False ) : continue
  iiiI1IiIIii = iiii11IiIiI [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  iiiI1IiIIii = iiiI1IiIIii . replace ( ":" , "" )
  if 9 - 9: OOooOOo + o0oOOo0O0Ooo
  if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
  if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
  if 55 - 55: oO0o
  if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
  if ( len ( iiiI1IiIIii ) < 12 ) : continue
  if 97 - 97: I1Ii111 . I11i / I1IiiI
  if ( lisp_mymacs . has_key ( iiiI1IiIIii ) == False ) : lisp_mymacs [ iiiI1IiIIii ] = [ ]
  lisp_mymacs [ iiiI1IiIIii ] . append ( OoO )
  if 83 - 83: I11i - I1ii11iIi11i * oO0o
  if 90 - 90: Oo0Ooo * I1IiiI
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
 if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
 if 28 - 28: IiII * I1IiiI % IiII
 if 95 - 95: O0 / I11i . I1Ii111
 if 17 - 17: I11i
 if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
 if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
 if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
def lisp_get_local_rloc ( ) :
 OOoo0O0OOOo0 = getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( OOoo0O0OOOo0 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
 if 22 - 22: oO0o * iII111i
 if 4 - 4: OoOoOO00 - oO0o + I1IiiI
 if 36 - 36: IiII
 OOoo0O0OOOo0 = OOoo0O0OOOo0 . split ( "\n" ) [ 0 ]
 OoO = OOoo0O0OOOo0 . split ( ) [ - 1 ]
 if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
 IiIIiiI = ""
 iIi = lisp_is_macos ( )
 if ( iIi ) :
  OOoo0O0OOOo0 = getoutput ( "ifconfig {} | egrep 'inet '" . format ( OoO ) )
  if ( OOoo0O0OOOo0 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  ii1iI1i = 'ip addr show | egrep "inet " | egrep "{}"' . format ( OoO )
  OOoo0O0OOOo0 = getoutput ( ii1iI1i )
  if ( OOoo0O0OOOo0 == "" ) :
   ii1iI1i = 'ip addr show | egrep "inet " | egrep "global lo"'
   OOoo0O0OOOo0 = getoutput ( ii1iI1i )
   if 36 - 36: IiII + OoooooooOO / i11iIiiIii
  if ( OOoo0O0OOOo0 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 40 - 40: OoooooooOO * OoOoOO00 / II111iiii - I1ii11iIi11i + Ii1I
  if 72 - 72: IiII % o0oOOo0O0Ooo
  if 93 - 93: iIii1I11I1II1 + i11iIiiIii . o0oOOo0O0Ooo . i1IIi % I1IiiI % ooOoO0o
  if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
  if 52 - 52: IiII % ooOoO0o
  if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
 IiIIiiI = ""
 OOoo0O0OOOo0 = OOoo0O0OOOo0 . split ( "\n" )
 if 23 - 23: i11iIiiIii
 for OOooOoO in OOoo0O0OOOo0 :
  OoOOOO = OOooOoO . split ( ) [ 1 ]
  if ( iIi == False ) : OoOOOO = OoOOOO . split ( "/" ) [ 0 ]
  iIIiiiI = lisp_address ( LISP_AFI_IPV4 , OoOOOO , 32 , 0 )
  return ( iIIiiiI )
  if 42 - 42: i11iIiiIii . O0
 return ( lisp_address ( LISP_AFI_IPV4 , IiIIiiI , 32 , 0 ) )
 if 75 - 75: I1Ii111 + iIii1I11I1II1
 if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
 if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
 if 92 - 92: I11i / O0 * I1IiiI - I11i
 if 99 - 99: i11iIiiIii % OoooooooOO
 if 56 - 56: IiII * I1Ii111
 if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
 if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
 if 17 - 17: Ii1I + II111iiii + OoooooooOO / OOooOOo / IiII
 if 80 - 80: o0oOOo0O0Ooo % i1IIi / I11i
 if 56 - 56: i1IIi . i11iIiiIii
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 15 - 15: II111iiii * oO0o % iII111i / i11iIiiIii - oO0o + Oo0Ooo
 if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
 if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
 if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
 if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
 if 10 - 10: IiII / OoooooooOO
 if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
 if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
 if 25 - 25: iIii1I11I1II1
 if 63 - 63: ooOoO0o
 oO0oOOOooo = None
 I1i11II = 1
 Ii1iiI1i1 = os . getenv ( "LISP_ADDR_SELECT" )
 if ( Ii1iiI1i1 != None and Ii1iiI1i1 != "" ) :
  Ii1iiI1i1 = Ii1iiI1i1 . split ( ":" )
  if ( len ( Ii1iiI1i1 ) == 2 ) :
   oO0oOOOooo = Ii1iiI1i1 [ 0 ]
   I1i11II = Ii1iiI1i1 [ 1 ]
  else :
   if ( Ii1iiI1i1 [ 0 ] . isdigit ( ) ) :
    I1i11II = Ii1iiI1i1 [ 0 ]
   else :
    oO0oOOOooo = Ii1iiI1i1 [ 0 ]
    if 3 - 3: OOooOOo . IiII / Oo0Ooo
    if 89 - 89: OoooooooOO . iIii1I11I1II1 . Oo0Ooo * iIii1I11I1II1 - I1Ii111
  I1i11II = 1 if ( I1i11II == "" ) else int ( I1i11II )
  if 92 - 92: OoooooooOO - I1ii11iIi11i - OoooooooOO % I1IiiI % I1IiiI % iIii1I11I1II1
  if 92 - 92: iII111i * O0 % I1Ii111 . iIii1I11I1II1
 o00OoO = [ None , None , None ]
 o0o = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 i1I1I1I = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 iII1III = None
 if 58 - 58: I11i % i11iIiiIii / i11iIiiIii * ooOoO0o - I1Ii111
 for OoO in netifaces . interfaces ( ) :
  if ( oO0oOOOooo != None and oO0oOOOooo != OoO ) : continue
  ooo0o0 = netifaces . ifaddresses ( OoO )
  if ( ooo0o0 == { } ) : continue
  if 6 - 6: IiII * II111iiii % iIii1I11I1II1
  if 86 - 86: i1IIi * O0 % ooOoO0o . Oo0Ooo % ooOoO0o . Oo0Ooo
  if 71 - 71: iII111i . i11iIiiIii * O0 + O0
  if 57 - 57: OoooooooOO . I11i % II111iiii % I1IiiI + Ii1I
  iII1III = lisp_get_interface_instance_id ( OoO , None )
  if 70 - 70: IiII . i11iIiiIii
  if 76 - 76: iII111i . IiII % iII111i - I1Ii111
  if 51 - 51: OoooooooOO + o0oOOo0O0Ooo * iIii1I11I1II1 * oO0o / i1IIi
  if 19 - 19: iII111i - OoOoOO00 % oO0o / OoooooooOO % iII111i
  if ( ooo0o0 . has_key ( netifaces . AF_INET ) ) :
   Oo00O0OO = ooo0o0 [ netifaces . AF_INET ]
   ooOoOoO0 = 0
   for IiIIiiI in Oo00O0OO :
    o0o . store_address ( IiIIiiI [ "addr" ] )
    if ( o0o . is_ipv4_loopback ( ) ) : continue
    if ( o0o . is_ipv4_link_local ( ) ) : continue
    if ( o0o . address == 0 ) : continue
    ooOoOoO0 += 1
    o0o . instance_id = iII1III
    if ( oO0oOOOooo == None and
 lisp_db_for_lookups . lookup_cache ( o0o , False ) ) : continue
    o00OoO [ 0 ] = o0o
    if ( ooOoOoO0 == I1i11II ) : break
    if 31 - 31: i11iIiiIii - ooOoO0o / I1ii11iIi11i - Ii1I
    if 5 - 5: i11iIiiIii * Oo0Ooo
  if ( ooo0o0 . has_key ( netifaces . AF_INET6 ) ) :
   oOOOoo0o = ooo0o0 [ netifaces . AF_INET6 ]
   ooOoOoO0 = 0
   for IiIIiiI in oOOOoo0o :
    O0O0 = IiIIiiI [ "addr" ]
    i1I1I1I . store_address ( O0O0 )
    if ( i1I1I1I . is_ipv6_string_link_local ( O0O0 ) ) : continue
    if ( i1I1I1I . is_ipv6_loopback ( ) ) : continue
    ooOoOoO0 += 1
    i1I1I1I . instance_id = iII1III
    if ( oO0oOOOooo == None and
 lisp_db_for_lookups . lookup_cache ( i1I1I1I , False ) ) : continue
    o00OoO [ 1 ] = i1I1I1I
    if ( ooOoOoO0 == I1i11II ) : break
    if 29 - 29: Ii1I / ooOoO0o % I11i
    if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
    if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
    if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
    if 79 - 79: IiII + IiII + Ii1I
    if 39 - 39: O0 - OoooooooOO
  if ( o00OoO [ 0 ] == None ) : continue
  if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
  o00OoO [ 2 ] = OoO
  break
  if 79 - 79: O0
  if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
 ii1I11iI = o00OoO [ 0 ] . print_address_no_iid ( ) if o00OoO [ 0 ] else "none"
 O0Oo00 = o00OoO [ 1 ] . print_address_no_iid ( ) if o00OoO [ 1 ] else "none"
 OoO = o00OoO [ 2 ] if o00OoO [ 2 ] else "none"
 if 63 - 63: i1IIi % i11iIiiIii % II111iiii * OoooooooOO
 oO0oOOOooo = " (user selected)" if oO0oOOOooo != None else ""
 if 40 - 40: Oo0Ooo
 ii1I11iI = red ( ii1I11iI , False )
 O0Oo00 = red ( O0Oo00 , False )
 OoO = bold ( OoO , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( ii1I11iI , O0Oo00 , OoO , oO0oOOOooo , iII1III ) )
 if 47 - 47: OoOoOO00
 if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
 lisp_myrlocs = o00OoO
 return ( ( o00OoO [ 0 ] != None ) )
 if 71 - 71: i11iIiiIii / OoOoOO00 . oO0o
 if 33 - 33: oO0o
 if 39 - 39: OoO0O00 + O0 + ooOoO0o * II111iiii % O0 - O0
 if 41 - 41: IiII % o0oOOo0O0Ooo
 if 67 - 67: O0 % I1Ii111
 if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
 if 39 - 39: Ii1I
 if 60 - 60: OOooOOo
 if 62 - 62: I1Ii111 * I11i
def lisp_get_all_addresses ( ) :
 oOo = [ ]
 for iI1ii1iI1 in netifaces . interfaces ( ) :
  try : oOOoO0oO0oo0O = netifaces . ifaddresses ( iI1ii1iI1 )
  except : continue
  if 55 - 55: Oo0Ooo
  if ( oOOoO0oO0oo0O . has_key ( netifaces . AF_INET ) ) :
   for IiIIiiI in oOOoO0oO0oo0O [ netifaces . AF_INET ] :
    OoOOOO = IiIIiiI [ "addr" ]
    if ( OoOOOO . find ( "127.0.0.1" ) != - 1 ) : continue
    oOo . append ( OoOOOO )
    if 35 - 35: I1ii11iIi11i * iII111i . IiII . IiII - oO0o % OoOoOO00
    if 42 - 42: o0oOOo0O0Ooo - iIii1I11I1II1 % OoooooooOO
  if ( oOOoO0oO0oo0O . has_key ( netifaces . AF_INET6 ) ) :
   for IiIIiiI in oOOoO0oO0oo0O [ netifaces . AF_INET6 ] :
    OoOOOO = IiIIiiI [ "addr" ]
    if ( OoOOOO == "::1" ) : continue
    if ( OoOOOO [ 0 : 5 ] == "fe80:" ) : continue
    oOo . append ( OoOOOO )
    if 43 - 43: o0oOOo0O0Ooo - Oo0Ooo
    if 85 - 85: II111iiii + I1Ii111 - ooOoO0o * iIii1I11I1II1 % oO0o
    if 62 - 62: Ii1I + O0 * OoO0O00
 return ( oOo )
 if 59 - 59: II111iiii
 if 43 - 43: Oo0Ooo + OoooooooOO
 if 47 - 47: ooOoO0o
 if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
 if 23 - 23: II111iiii * iII111i
 if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
 if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
 if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
def lisp_get_all_multicast_rles ( ) :
 O00OoO0oo = [ ]
 OOoo0O0OOOo0 = getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( OOoo0O0OOOo0 == "" ) : return ( O00OoO0oo )
 if 44 - 44: i11iIiiIii - I1Ii111 % Oo0Ooo . I11i
 iIi1iIi11 = OOoo0O0OOOo0 . split ( "\n" )
 for OOooOoO in iIi1iIi11 :
  if ( OOooOoO [ 0 ] == "#" ) : continue
  O0OOO = OOooOoO . split ( "rle-address = " ) [ 1 ]
  iii1iII1I = int ( O0OOO . split ( "." ) [ 0 ] )
  if ( iii1iII1I >= 224 and iii1iII1I < 240 ) : O00OoO0oo . append ( O0OOO )
  if 50 - 50: O0
 return ( O00OoO0oo )
 if 96 - 96: OOooOOo
 if 38 - 38: iII111i * OoooooooOO
 if 2 - 2: oO0o - i11iIiiIii
 if 98 - 98: oO0o + OoooooooOO - I1Ii111 % i11iIiiIii / o0oOOo0O0Ooo . OoooooooOO
 if 87 - 87: i1IIi
 if 33 - 33: I1Ii111 % II111iiii
 if 49 - 49: I1ii11iIi11i + I11i / o0oOOo0O0Ooo + OoooooooOO + OOooOOo / IiII
 if 29 - 29: Ii1I - Ii1I / ooOoO0o
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
  if 49 - 49: I11i + oO0o % OoO0O00 - Oo0Ooo - O0 - OoooooooOO
  if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
 def encode ( self , nonce ) :
  if 18 - 18: Oo0Ooo % O0
  if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
  if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
  if 86 - 86: IiII
  if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 33 - 33: II111iiii - IiII - ooOoO0o
  if 92 - 92: OoO0O00 * IiII
  if 92 - 92: oO0o
  if 7 - 7: iII111i
  if 73 - 73: OoO0O00 % I1ii11iIi11i
  if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 62 - 62: i11iIiiIii
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 2 - 2: I1IiiI
  if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
  if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
  if 14 - 14: IiII . IiII % ooOoO0o
  if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
  if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
  self . lisp_header . key_id ( 0 )
  Ii = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and Ii == False ) :
   O0O0 = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 22 - 22: iIii1I11I1II1 / I1ii11iIi11i / IiII - I1IiiI % OoOoOO00
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( O0O0 ) ) :
    IiI11I1iiii1 = lisp_crypto_keys_by_rloc_encap [ O0O0 ]
    if ( IiI11I1iiii1 [ 1 ] ) :
     IiI11I1iiii1 [ 1 ] . use_count += 1
     o0o0ooOOo0oO , IiiiI1Ii = self . encrypt ( IiI11I1iiii1 [ 1 ] , O0O0 )
     if ( IiiiI1Ii ) : self . packet = o0o0ooOOo0oO
     if 41 - 41: OoOoOO00 - OOooOOo + ooOoO0o - i1IIi
     if 6 - 6: II111iiii
     if 7 - 7: i1IIi
     if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
     if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
     if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
     if 59 - 59: iIii1I11I1II1 / I1ii11iIi11i % ooOoO0o
     if 84 - 84: iIii1I11I1II1 / I1IiiI . OoOoOO00 % I11i
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    if ( self . gleaned_dest ) :
     self . udp_sport = LISP_DATA_PORT
    else :
     self . hash_packet ( )
     if 99 - 99: Oo0Ooo + i11iIiiIii
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 36 - 36: Ii1I * I1Ii111 * iIii1I11I1II1 - I11i % i11iIiiIii
  else :
   self . udp_sport = LISP_DATA_PORT
   if 98 - 98: iIii1I11I1II1 - i1IIi + ooOoO0o % I11i + ooOoO0o / oO0o
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 97 - 97: IiII % ooOoO0o + II111iiii - IiII % OoO0O00 + ooOoO0o
  if 31 - 31: o0oOOo0O0Ooo
  if 35 - 35: OoOoOO00 + Ii1I * ooOoO0o / OoOoOO00
  if 69 - 69: ooOoO0o . OOooOOo - I1IiiI
  IiIi = socket . htons ( self . udp_sport )
  IiiI1iii1iIiiI = socket . htons ( self . udp_dport )
  II1iiiiI1 = socket . htons ( self . udp_length )
  O0I1II1 = struct . pack ( "HHHH" , IiIi , IiiI1iii1iIiiI , II1iiiiI1 , self . udp_checksum )
  if 33 - 33: OoooooooOO % I1ii11iIi11i . O0 / I1ii11iIi11i
  if 63 - 63: IiII + iIii1I11I1II1 + I1IiiI + I1Ii111
  if 72 - 72: OoO0O00 + i11iIiiIii + I1ii11iIi11i
  if 96 - 96: oO0o % i1IIi / o0oOOo0O0Ooo
  Ii1IIi11 = self . lisp_header . encode ( )
  if 47 - 47: O0
  if 83 - 83: O0 + OoOoOO00 / O0 / I11i
  if 68 - 68: i1IIi . I11i . i1IIi + IiII % I1IiiI
  if 32 - 32: OoOoOO00 . iIii1I11I1II1 % oO0o . O0 . OoOoOO00 / iII111i
  if 45 - 45: iIii1I11I1II1
  if ( self . outer_version == 4 ) :
   I1I111IIIi1 = socket . htons ( self . udp_length + 20 )
   oOOo00O0O0 = socket . htons ( 0x4000 )
   iiIIiiI = struct . pack ( "BBHHHBBH" , 0x45 , self . outer_tos , I1I111IIIi1 , 0xdfdf ,
 oOOo00O0O0 , self . outer_ttl , 17 , 0 )
   iiIIiiI += self . outer_source . pack_address ( )
   iiIIiiI += self . outer_dest . pack_address ( )
   iiIIiiI = lisp_ip_checksum ( iiIIiiI )
  elif ( self . outer_version == 6 ) :
   iiIIiiI = ""
   if 90 - 90: I1Ii111 . OoOoOO00 * II111iiii % ooOoO0o
   if 36 - 36: I1IiiI - Oo0Ooo % OOooOOo . I11i + I11i + Ii1I
   if 28 - 28: Oo0Ooo / oO0o * OoOoOO00 + I1ii11iIi11i - I1Ii111
   if 78 - 78: I1IiiI . I1IiiI * OoO0O00 - i11iIiiIii
   if 86 - 86: O0
   if 11 - 11: Ii1I + iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
   if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
  else :
   return ( None )
   if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
   if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
  self . packet = iiIIiiI + O0I1II1 + Ii1IIi11 + self . packet
  return ( self )
  if 55 - 55: OoooooooOO
  if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
 def cipher_pad ( self , packet ) :
  i1iIii = len ( packet )
  if ( ( i1iIii % 16 ) != 0 ) :
   O0o00 = ( ( i1iIii / 16 ) + 1 ) * 16
   packet = packet . ljust ( O0o00 )
   if 8 - 8: I1Ii111 * Oo0Ooo - OOooOOo . iIii1I11I1II1
  return ( packet )
  if 48 - 48: i11iIiiIii / II111iiii + Ii1I + o0oOOo0O0Ooo . I1Ii111 % OOooOOo
  if 88 - 88: I1Ii111 . I1Ii111
 def encrypt ( self , key , addr_str ) :
  if ( key == None or key . shared_key == None ) :
   return ( [ self . packet , False ] )
   if 71 - 71: ooOoO0o . I1ii11iIi11i * O0 - I1Ii111 - II111iiii
   if 5 - 5: o0oOOo0O0Ooo
   if 66 - 66: iII111i / i11iIiiIii * O0
   if 78 - 78: IiII - I11i % O0 - OOooOOo % OoO0O00
   if 43 - 43: OoO0O00
  o0o0ooOOo0oO = self . cipher_pad ( self . packet )
  OoOooO = key . get_iv ( )
  if 23 - 23: Ii1I * ooOoO0o - I11i . O0 % iIii1I11I1II1
  ii1III11 = lisp_get_timestamp ( )
  iIiiII = None
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   iII1I = chacha . ChaCha ( key . encrypt_key , OoOooO ) . encrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   o00oOOo0Oo = binascii . unhexlify ( key . encrypt_key )
   try :
    Oooo0o0oO = AES . new ( o00oOOo0Oo , AES . MODE_GCM , OoOooO )
    iII1I = Oooo0o0oO . encrypt
    iIiiII = Oooo0o0oO . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 82 - 82: ooOoO0o
  else :
   o00oOOo0Oo = binascii . unhexlify ( key . encrypt_key )
   iII1I = AES . new ( o00oOOo0Oo , AES . MODE_CBC , OoOooO ) . encrypt
   if 70 - 70: iIii1I11I1II1 + i11iIiiIii + Oo0Ooo / iII111i
   if 9 - 9: OoOoOO00 - IiII
  iiIi = iII1I ( o0o0ooOOo0oO )
  if 31 - 31: i11iIiiIii + IiII - I1Ii111 * iII111i
  if ( iiIi == None ) : return ( [ self . packet , False ] )
  ii1III11 = int ( str ( time . time ( ) - ii1III11 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 60 - 60: iII111i + OoO0O00 + I11i % iIii1I11I1II1 . Oo0Ooo
  if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
  if 93 - 93: i11iIiiIii
  if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
  if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
  if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
  if ( iIiiII != None ) : iiIi += iIiiII ( )
  if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
  if 58 - 58: I11i
  if 7 - 7: II111iiii / IiII % I11i + I1IiiI - O0
  if 45 - 45: I1IiiI / iII111i + oO0o + IiII
  if 15 - 15: I1IiiI % OoO0O00
  self . lisp_header . key_id ( key . key_id )
  Ii1IIi11 = self . lisp_header . encode ( )
  if 66 - 66: oO0o * i11iIiiIii . I1Ii111
  o0O0OOOo0 = key . do_icv ( Ii1IIi11 + OoOooO + iiIi , OoOooO )
  if 4 - 4: ooOoO0o + O0 . i1IIi * I1ii11iIi11i - o0oOOo0O0Ooo
  IIiIIIi1iii1 = 4 if ( key . do_poly ) else 8
  if 37 - 37: iIii1I11I1II1 % I11i / IiII
  i1IIIII1 = bold ( "Encrypt" , False )
  IIIiiiiiI1I = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  O0oooO00ooO0 = "poly" if key . do_poly else "sha256"
  O0oooO00ooO0 = bold ( O0oooO00ooO0 , False )
  o00OOO0o00OO = "ICV({}): 0x{}...{}" . format ( O0oooO00ooO0 , o0O0OOOo0 [ 0 : IIiIIIi1iii1 ] , o0O0OOOo0 [ - IIiIIIi1iii1 : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( i1IIIII1 , key . key_id , addr_str , o00OOO0o00OO , IIIiiiiiI1I , ii1III11 ) )
  if 100 - 100: I11i
  if 36 - 36: OoO0O00 + II111iiii * OoOoOO00
  o0O0OOOo0 = int ( o0O0OOOo0 , 16 )
  if ( key . do_poly ) :
   i11i1IIIIII = byte_swap_64 ( ( o0O0OOOo0 >> 64 ) & LISP_8_64_MASK )
   OoOO0Ooooo0 = byte_swap_64 ( o0O0OOOo0 & LISP_8_64_MASK )
   o0O0OOOo0 = struct . pack ( "QQ" , i11i1IIIIII , OoOO0Ooooo0 )
  else :
   i11i1IIIIII = byte_swap_64 ( ( o0O0OOOo0 >> 96 ) & LISP_8_64_MASK )
   OoOO0Ooooo0 = byte_swap_64 ( ( o0O0OOOo0 >> 32 ) & LISP_8_64_MASK )
   OOOO = socket . htonl ( o0O0OOOo0 & 0xffffffff )
   o0O0OOOo0 = struct . pack ( "QQI" , i11i1IIIIII , OoOO0Ooooo0 , OOOO )
   if 10 - 10: II111iiii . OoO0O00
   if 89 - 89: ooOoO0o * Ii1I
  return ( [ OoOooO + iiIi + o0O0OOOo0 , True ] )
  if 93 - 93: i1IIi . Ii1I * I1Ii111 . ooOoO0o
  if 54 - 54: iII111i . i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo % iII111i
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 30 - 30: I11i
  if 85 - 85: II111iiii + ooOoO0o * I11i
  if 12 - 12: Ii1I . I1IiiI % o0oOOo0O0Ooo
  if 28 - 28: Ii1I - I1IiiI % OoO0O00 * I1Ii111
  if 80 - 80: OOooOOo * IiII
  if 4 - 4: iIii1I11I1II1 . I1Ii111 + II111iiii % OoooooooOO
  if ( key . do_poly ) :
   i11i1IIIIII , OoOO0Ooooo0 = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   Oo000 = byte_swap_64 ( i11i1IIIIII ) << 64
   Oo000 |= byte_swap_64 ( OoOO0Ooooo0 )
   Oo000 = lisp_hex_string ( Oo000 ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   IIiIIIi1iii1 = 4
   oO = bold ( "poly" , False )
  else :
   i11i1IIIIII , OoOO0Ooooo0 , OOOO = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   Oo000 = byte_swap_64 ( i11i1IIIIII ) << 96
   Oo000 |= byte_swap_64 ( OoOO0Ooooo0 ) << 32
   Oo000 |= socket . htonl ( OOOO )
   Oo000 = lisp_hex_string ( Oo000 ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   IIiIIIi1iii1 = 8
   oO = bold ( "sha" , False )
   if 21 - 21: II111iiii + Oo0Ooo
  Ii1IIi11 = self . lisp_header . encode ( )
  if 59 - 59: OOooOOo + I1IiiI / II111iiii / OoOoOO00
  if 80 - 80: OoOoOO00 + iIii1I11I1II1 . IiII
  if 76 - 76: I1IiiI * OOooOOo
  if 12 - 12: iIii1I11I1II1 / I11i % Ii1I
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   IIiiI11 = 8
   IIIiiiiiI1I = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   IIiiI11 = 12
   IIIiiiiiI1I = bold ( "aes-gcm" , False )
  else :
   IIiiI11 = 16
   IIIiiiiiI1I = bold ( "aes-cbc" , False )
   if 7 - 7: I1IiiI / OoO0O00 + I1Ii111 + I11i / I1IiiI
  OoOooO = packet [ 0 : IIiiI11 ]
  if 82 - 82: I1ii11iIi11i + OoooooooOO
  if 21 - 21: oO0o * oO0o / I11i . iII111i
  if 10 - 10: Ii1I * OOooOOo - Oo0Ooo - OoooooooOO / o0oOOo0O0Ooo
  if 86 - 86: I1Ii111 % I1IiiI
  Iii1iIIiii1ii = key . do_icv ( Ii1IIi11 + packet , OoOooO )
  if 13 - 13: iIii1I11I1II1 - II111iiii % O0 . Ii1I % OoO0O00
  Ii11iIiiI = "0x{}...{}" . format ( Oo000 [ 0 : IIiIIIi1iii1 ] , Oo000 [ - IIiIIIi1iii1 : : ] )
  iiII = "0x{}...{}" . format ( Iii1iIIiii1ii [ 0 : IIiIIIi1iii1 ] , Iii1iIIiii1ii [ - IIiIIIi1iii1 : : ] )
  if 30 - 30: ooOoO0o
  if ( Iii1iIIiii1ii != Oo000 ) :
   self . packet_error = "ICV-error"
   oOooOOOOoo0O = IIIiiiiiI1I + "/" + oO
   iIi11ii1 = bold ( "ICV failed ({})" . format ( oOooOOOOoo0O ) , False )
   o00OOO0o00OO = "packet-ICV {} != computed-ICV {}" . format ( Ii11iIiiI , iiII )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( iIi11ii1 , red ( addr_str , False ) ,
   # iIii1I11I1II1 / OoOoOO00 - I11i
 self . udp_sport , key . key_id , o00OOO0o00OO ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 57 - 57: II111iiii % I1IiiI
   if 34 - 34: I1IiiI
   if 57 - 57: OOooOOo . Ii1I % o0oOOo0O0Ooo
   if 32 - 32: I11i / IiII - O0 * iIii1I11I1II1
   if 70 - 70: OoooooooOO % OoooooooOO % OoO0O00
   if 98 - 98: OoO0O00
   lisp_retry_decap_keys ( addr_str , Ii1IIi11 + packet , OoOooO , Oo000 )
   return ( [ None , False ] )
   if 18 - 18: I11i + Oo0Ooo - OoO0O00 / I1Ii111 / OOooOOo
   if 53 - 53: OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
   if 52 - 52: I1Ii111 + I1Ii111
   if 73 - 73: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO + ooOoO0o . OoooooooOO / OOooOOo
   if 54 - 54: OoOoOO00 . OoooooooOO
  packet = packet [ IIiiI11 : : ]
  if 36 - 36: oO0o / II111iiii * IiII % I1ii11iIi11i
  if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
  if 28 - 28: Ii1I . I1ii11iIi11i
  if 77 - 77: I1ii11iIi11i % II111iiii
  ii1III11 = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   OOo00o0oo0 = chacha . ChaCha ( key . encrypt_key , OoOooO ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   o00oOOo0Oo = binascii . unhexlify ( key . encrypt_key )
   try :
    OOo00o0oo0 = AES . new ( o00oOOo0Oo , AES . MODE_GCM , OoOooO ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 33 - 33: o0oOOo0O0Ooo . OOooOOo + o0oOOo0O0Ooo / I1ii11iIi11i . Oo0Ooo + OoOoOO00
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 32 - 32: IiII - ooOoO0o * iII111i * I11i
   o00oOOo0Oo = binascii . unhexlify ( key . encrypt_key )
   OOo00o0oo0 = AES . new ( o00oOOo0Oo , AES . MODE_CBC , OoOooO ) . decrypt
   if 84 - 84: Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
   if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
  o0oO = OOo00o0oo0 ( packet )
  ii1III11 = int ( str ( time . time ( ) - ii1III11 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 53 - 53: I1IiiI
  if 10 - 10: I1Ii111 / i11iIiiIii - II111iiii
  if 48 - 48: OOooOOo
  if 26 - 26: iII111i * I1Ii111 * oO0o * OoOoOO00
  i1IIIII1 = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  O0oooO00ooO0 = "poly" if key . do_poly else "sha256"
  O0oooO00ooO0 = bold ( O0oooO00ooO0 , False )
  o00OOO0o00OO = "ICV({}): {}" . format ( O0oooO00ooO0 , Ii11iIiiI )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( i1IIIII1 , key . key_id , addr_str , o00OOO0o00OO , IIIiiiiiI1I , ii1III11 ) )
  if 48 - 48: iII111i % i11iIiiIii . OoooooooOO * IiII % OoO0O00 . iII111i
  if 6 - 6: O0 . ooOoO0o - oO0o / i11iIiiIii
  if 84 - 84: I11i / I1ii11iIi11i * o0oOOo0O0Ooo * OoO0O00 * OOooOOo * O0
  if 83 - 83: O0 % II111iiii + o0oOOo0O0Ooo / OoooooooOO
  if 75 - 75: II111iiii . I1IiiI + OOooOOo - OoOoOO00 - O0 . I11i
  if 19 - 19: Ii1I * i1IIi % O0 + I11i
  if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
  self . packet = self . packet [ 0 : header_length ]
  return ( [ o0oO , True ] )
  if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
  if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  ooOooOooOOO = 1000
  if 59 - 59: I11i
  if 63 - 63: OoO0O00 . oO0o + I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
  if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
  if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
  if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
  ii = [ ]
  IiI1ii1Ii = 0
  i1iIii = len ( inner_packet )
  while ( IiI1ii1Ii < i1iIii ) :
   oOOo00O0O0 = inner_packet [ IiI1ii1Ii : : ]
   if ( len ( oOOo00O0O0 ) > ooOooOooOOO ) : oOOo00O0O0 = oOOo00O0O0 [ 0 : ooOooOooOOO ]
   ii . append ( oOOo00O0O0 )
   IiI1ii1Ii += len ( oOOo00O0O0 )
   if 89 - 89: i1IIi . i1IIi
   if 10 - 10: iII111i % Oo0Ooo
   if 48 - 48: OOooOOo + I1Ii111 % OOooOOo
   if 84 - 84: O0 % Ii1I . Ii1I . iII111i * I11i
   if 43 - 43: OoOoOO00 . I1ii11iIi11i % i1IIi
   if 61 - 61: I1IiiI + oO0o % I1Ii111 % iIii1I11I1II1 - OoooooooOO
  iIIiI1 = [ ]
  IiI1ii1Ii = 0
  for oOOo00O0O0 in ii :
   if 4 - 4: OoooooooOO + iII111i % O0 + iIii1I11I1II1 % iII111i * i11iIiiIii
   if 32 - 32: OoOoOO00 + ooOoO0o + Ii1I + I1IiiI
   if 26 - 26: iII111i - Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
   if 37 - 37: o0oOOo0O0Ooo * OOooOOo + I1IiiI . I1ii11iIi11i * OoooooooOO
   OoooOO0 = IiI1ii1Ii if ( oOOo00O0O0 == ii [ - 1 ] ) else 0x2000 + IiI1ii1Ii
   OoooOO0 = socket . htons ( OoooOO0 )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , OoooOO0 ) + outer_hdr [ 8 : : ]
   if 69 - 69: II111iiii + iII111i
   if 55 - 55: i11iIiiIii + I1IiiI
   if 64 - 64: i11iIiiIii + i1IIi % O0 . I11i
   if 64 - 64: ooOoO0o / i1IIi % iII111i
   OOoOo0O0 = socket . htons ( len ( oOOo00O0O0 ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , OOoOo0O0 ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   iIIiI1 . append ( outer_hdr + oOOo00O0O0 )
   IiI1ii1Ii += len ( oOOo00O0O0 ) / 8
   if 39 - 39: I1Ii111 . OoO0O00 % ooOoO0o . OOooOOo / iII111i * OoO0O00
  return ( iIIiI1 )
  if 12 - 12: I1IiiI / o0oOOo0O0Ooo
  if 86 - 86: Oo0Ooo % OoOoOO00
 def send_icmp_too_big ( self , inner_packet ) :
  global lisp_last_icmp_too_big_sent
  global lisp_icmp_raw_socket
  if 77 - 77: Ii1I % OOooOOo / oO0o
  Ii1i1 = time . time ( ) - lisp_last_icmp_too_big_sent
  if ( Ii1i1 < LISP_ICMP_TOO_BIG_RATE_LIMIT ) :
   lprint ( "Rate limit sending ICMP Too-Big to {}" . format ( self . inner_source . print_address_no_iid ( ) ) )
   if 91 - 91: OoO0O00 / OoO0O00 . II111iiii . ooOoO0o - I1IiiI
   return ( False )
   if 23 - 23: I1IiiI
   if 7 - 7: iII111i % I1ii11iIi11i
   if 64 - 64: I1Ii111 + i11iIiiIii
   if 35 - 35: OoOoOO00 + i1IIi % OOooOOo
   if 68 - 68: IiII . ooOoO0o
   if 64 - 64: i1IIi + Oo0Ooo * I1IiiI / OOooOOo
   if 3 - 3: Oo0Ooo / ooOoO0o + ooOoO0o . I1ii11iIi11i
   if 50 - 50: iIii1I11I1II1 * oO0o
   if 85 - 85: i1IIi
   if 100 - 100: OoooooooOO / I11i % OoO0O00 + Ii1I
   if 42 - 42: Oo0Ooo / IiII . Ii1I * I1IiiI
   if 54 - 54: OoOoOO00 * iII111i + OoO0O00
   if 93 - 93: o0oOOo0O0Ooo / I1IiiI
   if 47 - 47: Oo0Ooo * OOooOOo
   if 98 - 98: oO0o - oO0o . ooOoO0o
  OooOOoO00OO00 = socket . htons ( 1400 )
  IIii1III = struct . pack ( "BBHHH" , 3 , 4 , 0 , 0 , OooOOoO00OO00 )
  IIii1III += inner_packet [ 0 : 20 + 8 ]
  IIii1III = lisp_icmp_checksum ( IIii1III )
  if 17 - 17: OoooooooOO * I1Ii111 * I1IiiI
  if 30 - 30: OoOoOO00 / oO0o / Ii1I * o0oOOo0O0Ooo * oO0o . I1IiiI
  if 93 - 93: OoOoOO00
  if 97 - 97: i11iIiiIii
  if 68 - 68: IiII * OoO0O00 . I11i / Ii1I . o0oOOo0O0Ooo - i11iIiiIii
  if 49 - 49: Oo0Ooo / Ii1I % I11i + oO0o - OoO0O00
  if 13 - 13: II111iiii
  OoOIiiIi1IiiiI = inner_packet [ 12 : 16 ]
  OO0oooOO = self . inner_source . print_address_no_iid ( )
  III = self . outer_source . pack_address ( )
  if 44 - 44: OOooOOo % iIii1I11I1II1
  if 30 - 30: i11iIiiIii - I1IiiI / I1ii11iIi11i
  if 26 - 26: ooOoO0o % oO0o + I1IiiI / IiII . I1IiiI
  if 38 - 38: OoooooooOO + OoooooooOO - i11iIiiIii * I1IiiI * i1IIi / II111iiii
  if 78 - 78: Oo0Ooo - I1Ii111 + iII111i * Ii1I * o0oOOo0O0Ooo
  if 23 - 23: Oo0Ooo - O0
  if 33 - 33: I1ii11iIi11i
  if 54 - 54: ooOoO0o * I1ii11iIi11i . II111iiii / OOooOOo % OOooOOo
  I1I111IIIi1 = socket . htons ( 20 + 36 )
  O0O = struct . pack ( "BBHHHBBH" , 0x45 , 0 , I1I111IIIi1 , 0 , 0 , 32 , 1 , 0 ) + III + OoOIiiIi1IiiiI
  O0O = lisp_ip_checksum ( O0O )
  O0O = self . fix_outer_header ( O0O )
  O0O += IIii1III
  IiIIii1 = bold ( "Too-Big" , False )
  lprint ( "Send ICMP {} to {}, mtu 1400: {}" . format ( IiIIii1 , OO0oooOO ,
 lisp_format_packet ( O0O ) ) )
  if 7 - 7: O0 - I1ii11iIi11i / OoOoOO00 - Ii1I - oO0o / OoooooooOO
  try :
   lisp_icmp_raw_socket . sendto ( O0O , ( OO0oooOO , 0 ) )
  except socket . error as I1i :
   lprint ( "lisp_icmp_raw_socket.sendto() failed: {}" . format ( I1i ) )
   return ( False )
   if 12 - 12: OoooooooOO
   if 55 - 55: I1ii11iIi11i + I1ii11iIi11i
   if 87 - 87: IiII
   if 78 - 78: oO0o % OoOoOO00
   if 1 - 1: OoOoOO00 - o0oOOo0O0Ooo / ooOoO0o - IiII / i1IIi
   if 28 - 28: OoO0O00 / I1Ii111 * I1IiiI + ooOoO0o
  lisp_last_icmp_too_big_sent = lisp_get_timestamp ( )
  return ( True )
  if 48 - 48: O0
 def fragment ( self ) :
  global lisp_icmp_raw_socket
  global lisp_ignore_df_bit
  if 44 - 44: OoO0O00 * oO0o
  o0o0ooOOo0oO = self . fix_outer_header ( self . packet )
  if 54 - 54: Ii1I % i1IIi
  if 51 - 51: iIii1I11I1II1 - I1IiiI
  if 61 - 61: OoooooooOO . Ii1I % oO0o * OoooooooOO
  if 96 - 96: Ii1I - II111iiii % OoOoOO00 * I1IiiI * I1IiiI . Oo0Ooo
  if 75 - 75: Oo0Ooo + Ii1I + OoO0O00
  if 97 - 97: ooOoO0o % i11iIiiIii % I11i
  i1iIii = len ( o0o0ooOOo0oO )
  if ( i1iIii <= 1500 ) : return ( [ o0o0ooOOo0oO ] , "Fragment-None" )
  if 21 - 21: Oo0Ooo / Ii1I / I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
  o0o0ooOOo0oO = self . packet
  if 86 - 86: i1IIi
  if 33 - 33: OoOoOO00 % i11iIiiIii * OOooOOo
  if 69 - 69: II111iiii + Oo0Ooo - oO0o . Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1
  if 75 - 75: OoO0O00 % OoooooooOO
  if 16 - 16: O0 / i1IIi
  if ( self . inner_version != 4 ) :
   OOoo0 = random . randint ( 0 , 0xffff )
   Ii11I1iIIi = o0o0ooOOo0oO [ 0 : 4 ] + struct . pack ( "H" , OOoo0 ) + o0o0ooOOo0oO [ 6 : 20 ]
   O0ooO = o0o0ooOOo0oO [ 20 : : ]
   iIIiI1 = self . fragment_outer ( Ii11I1iIIi , O0ooO )
   return ( iIIiI1 , "Fragment-Outer" )
   if 40 - 40: o0oOOo0O0Ooo . o0oOOo0O0Ooo * i11iIiiIii
   if 44 - 44: o0oOOo0O0Ooo
   if 80 - 80: I1ii11iIi11i + I11i - ooOoO0o - o0oOOo0O0Ooo % Ii1I
   if 85 - 85: I1Ii111
   if 62 - 62: Ii1I % II111iiii + IiII + OOooOOo % oO0o . I1IiiI
  OOoOo0ooOoo = 56 if ( self . outer_version == 6 ) else 36
  Ii11I1iIIi = o0o0ooOOo0oO [ 0 : OOoOo0ooOoo ]
  oO0OO00 = o0o0ooOOo0oO [ OOoOo0ooOoo : OOoOo0ooOoo + 20 ]
  O0ooO = o0o0ooOOo0oO [ OOoOo0ooOoo + 20 : : ]
  if 16 - 16: OoooooooOO / oO0o . Ii1I * ooOoO0o - I1IiiI
  if 32 - 32: I1IiiI / OoO0O00
  if 28 - 28: Oo0Ooo / IiII . iII111i + OoO0O00 + I11i % Oo0Ooo
  if 45 - 45: Oo0Ooo / O0 % OoooooooOO
  if 92 - 92: Ii1I . OoOoOO00 . I11i - OoooooooOO / ooOoO0o
  ooOo0 = struct . unpack ( "H" , oO0OO00 [ 6 : 8 ] ) [ 0 ]
  ooOo0 = socket . ntohs ( ooOo0 )
  if ( ooOo0 & 0x4000 ) :
   if ( lisp_icmp_raw_socket != None ) :
    I11I1i = o0o0ooOOo0oO [ OOoOo0ooOoo : : ]
    if ( self . send_icmp_too_big ( I11I1i ) ) : return ( [ ] , None )
    if 100 - 100: oO0o
   if ( lisp_ignore_df_bit ) :
    ooOo0 &= ~ 0x4000
   else :
    iiIiiiIii11i1 = bold ( "DF-bit set" , False )
    dprint ( "{} in inner header, packet discarded" . format ( iiIiiiIii11i1 ) )
    return ( [ ] , "Fragment-None-DF-bit" )
    if 87 - 87: OoO0O00 + OoooooooOO . ooOoO0o * I11i
    if 82 - 82: iIii1I11I1II1 * OoooooooOO
    if 50 - 50: I1Ii111 - II111iiii
  IiI1ii1Ii = 0
  i1iIii = len ( O0ooO )
  iIIiI1 = [ ]
  while ( IiI1ii1Ii < i1iIii ) :
   iIIiI1 . append ( O0ooO [ IiI1ii1Ii : IiI1ii1Ii + 1400 ] )
   IiI1ii1Ii += 1400
   if 33 - 33: IiII / IiII . i11iIiiIii * I1ii11iIi11i + o0oOOo0O0Ooo
   if 16 - 16: IiII
   if 10 - 10: OoOoOO00 . IiII * iIii1I11I1II1 - oO0o - OoOoOO00 / I1Ii111
   if 13 - 13: oO0o + OoOoOO00 % IiII % OoooooooOO
   if 22 - 22: I1Ii111
  ii = iIIiI1
  iIIiI1 = [ ]
  iI1 = True if ooOo0 & 0x2000 else False
  ooOo0 = ( ooOo0 & 0x1fff ) * 8
  for oOOo00O0O0 in ii :
   if 11 - 11: OOooOOo / I1IiiI
   if 98 - 98: I1ii11iIi11i - Ii1I * OoO0O00 . I1ii11iIi11i - I1Ii111
   if 4 - 4: i11iIiiIii + OoooooooOO / i11iIiiIii . OoooooooOO % I1ii11iIi11i / OoOoOO00
   if 35 - 35: I1ii11iIi11i % i1IIi + o0oOOo0O0Ooo - iIii1I11I1II1
   II1i1III1IIiI = ooOo0 / 8
   if ( iI1 ) :
    II1i1III1IIiI |= 0x2000
   elif ( oOOo00O0O0 != ii [ - 1 ] ) :
    II1i1III1IIiI |= 0x2000
    if 65 - 65: i1IIi . iIii1I11I1II1 + II111iiii - I1IiiI * ooOoO0o + O0
   II1i1III1IIiI = socket . htons ( II1i1III1IIiI )
   oO0OO00 = oO0OO00 [ 0 : 6 ] + struct . pack ( "H" , II1i1III1IIiI ) + oO0OO00 [ 8 : : ]
   if 87 - 87: I1Ii111 + OoooooooOO * i1IIi * i11iIiiIii
   if 74 - 74: OoooooooOO - o0oOOo0O0Ooo * iII111i
   if 37 - 37: o0oOOo0O0Ooo * Oo0Ooo
   if 11 - 11: oO0o
   if 62 - 62: OoooooooOO % oO0o * II111iiii * I1Ii111 * I1Ii111 / ooOoO0o
   if 90 - 90: I1Ii111 . II111iiii . I1ii11iIi11i
   i1iIii = len ( oOOo00O0O0 )
   ooOo0 += i1iIii
   OOoOo0O0 = socket . htons ( i1iIii + 20 )
   oO0OO00 = oO0OO00 [ 0 : 2 ] + struct . pack ( "H" , OOoOo0O0 ) + oO0OO00 [ 4 : 10 ] + struct . pack ( "H" , 0 ) + oO0OO00 [ 12 : : ]
   if 32 - 32: ooOoO0o - OoO0O00 . iII111i . iII111i % i1IIi * Ii1I
   oO0OO00 = lisp_ip_checksum ( oO0OO00 )
   o0o0 = oO0OO00 + oOOo00O0O0
   if 28 - 28: I11i . OoooooooOO * OOooOOo + i11iIiiIii % I1IiiI . iIii1I11I1II1
   if 63 - 63: II111iiii - I11i . OoOoOO00
   if 8 - 8: I1IiiI * ooOoO0o / IiII + OoOoOO00 . IiII - OOooOOo
   if 80 - 80: iIii1I11I1II1 / oO0o * Oo0Ooo - OOooOOo * iII111i
   if 97 - 97: IiII - I11i / II111iiii
   i1iIii = len ( o0o0 )
   if ( self . outer_version == 4 ) :
    OOoOo0O0 = i1iIii + OOoOo0ooOoo
    i1iIii += 16
    Ii11I1iIIi = Ii11I1iIIi [ 0 : 2 ] + struct . pack ( "H" , OOoOo0O0 ) + Ii11I1iIIi [ 4 : : ]
    if 26 - 26: iII111i + O0 * iII111i . i1IIi
    Ii11I1iIIi = lisp_ip_checksum ( Ii11I1iIIi )
    o0o0 = Ii11I1iIIi + o0o0
    o0o0 = self . fix_outer_header ( o0o0 )
    if 50 - 50: iIii1I11I1II1 - I11i % iII111i - Oo0Ooo
    if 52 - 52: oO0o + Ii1I - I1ii11iIi11i * Ii1I . OOooOOo + I1Ii111
    if 43 - 43: I1IiiI % IiII % I1ii11iIi11i
    if 53 - 53: oO0o % OOooOOo % I1ii11iIi11i . I1Ii111 . I1Ii111 . iII111i
    if 73 - 73: iII111i / ooOoO0o + OoO0O00 / OoOoOO00 . II111iiii * Ii1I
   IiII111I = OOoOo0ooOoo - 12
   OOoOo0O0 = socket . htons ( i1iIii )
   o0o0 = o0o0 [ 0 : IiII111I ] + struct . pack ( "H" , OOoOo0O0 ) + o0o0 [ IiII111I + 2 : : ]
   if 62 - 62: i1IIi * iIii1I11I1II1 % oO0o % OoOoOO00 / OoooooooOO
   iIIiI1 . append ( o0o0 )
   if 39 - 39: Oo0Ooo % iII111i
  return ( iIIiI1 , "Fragment-Inner" )
  if 90 - 90: I1IiiI * I1ii11iIi11i . I11i * Ii1I - o0oOOo0O0Ooo
  if 40 - 40: O0 / IiII - II111iiii + o0oOOo0O0Ooo % Oo0Ooo
 def fix_outer_header ( self , packet ) :
  if 93 - 93: ooOoO0o
  if 82 - 82: I1ii11iIi11i / ooOoO0o . i11iIiiIii + OOooOOo - OoOoOO00 / iII111i
  if 99 - 99: oO0o / i1IIi
  if 2 - 2: oO0o . iII111i
  if 42 - 42: OoO0O00 - I1ii11iIi11i * IiII - ooOoO0o
  if 75 - 75: iII111i * Oo0Ooo / I1Ii111 * Oo0Ooo / ooOoO0o
  if 14 - 14: i1IIi * iIii1I11I1II1 - Ii1I * OoOoOO00 - iII111i / oO0o
  if 73 - 73: I1ii11iIi11i - OoOoOO00 * O0 - OoOoOO00 - OoO0O00
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : 6 ] + packet [ 7 ] + packet [ 6 ] + packet [ 8 : : ]
    if 96 - 96: I1ii11iIi11i - O0
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 ] + packet [ 2 ] + packet [ 4 : : ]
    if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
    if 99 - 99: o0oOOo0O0Ooo + OOooOOo
  return ( packet )
  if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
  if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 76 - 76: oO0o / OoOoOO00
  dest = dest . print_address_no_iid ( )
  iIIiI1 , iI1II1iIiI11I = self . fragment ( )
  if 19 - 19: ooOoO0o / I1IiiI - Ii1I
  for o0o0 in iIIiI1 :
   if ( len ( iIIiI1 ) != 1 ) :
    self . packet = o0o0
    self . print_packet ( iI1II1iIiI11I , True )
    if 53 - 53: oO0o
    if 99 - 99: Oo0Ooo
   try : lisp_raw_socket . sendto ( o0o0 , ( dest , 0 ) )
   except socket . error as I1i :
    lprint ( "socket.sendto() failed: {}" . format ( I1i ) )
    if 17 - 17: i11iIiiIii - i11iIiiIii + I1ii11iIi11i * ooOoO0o * oO0o / OoooooooOO
    if 22 - 22: I1Ii111 * I1ii11iIi11i - IiII
    if 71 - 71: iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * I1IiiI % II111iiii
    if 35 - 35: I1Ii111 - OoOoOO00
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 61 - 61: I1Ii111 * o0oOOo0O0Ooo * OoO0O00 + I1ii11iIi11i . Oo0Ooo + i1IIi
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 82 - 82: Oo0Ooo + I1Ii111
   if 93 - 93: I11i * O0 * OOooOOo - o0oOOo0O0Ooo / I1ii11iIi11i
  o0o0ooOOo0oO = mac_header + self . packet
  if 54 - 54: i1IIi - OoO0O00 / OoooooooOO
  if 95 - 95: O0 + iIii1I11I1II1 . I1ii11iIi11i
  if 61 - 61: Ii1I * Ii1I
  if 70 - 70: I1Ii111 . I1ii11iIi11i / o0oOOo0O0Ooo * oO0o
  if 74 - 74: I1IiiI . ooOoO0o / iII111i . IiII
  if 74 - 74: Oo0Ooo / I1Ii111 % I1Ii111 . IiII
  if 72 - 72: i1IIi
  if 21 - 21: I1Ii111 . OOooOOo / i11iIiiIii * i1IIi
  if 82 - 82: ooOoO0o * Oo0Ooo % i11iIiiIii * i1IIi . OOooOOo
  if 89 - 89: IiII - i1IIi - IiII
  if 74 - 74: OoO0O00 % OoO0O00
  l2_socket . write ( o0o0ooOOo0oO )
  return
  if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
  if 91 - 91: I1IiiI / II111iiii * OOooOOo
 def bridge_l2_packet ( self , eid , db ) :
  try : ooOoo000 = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : iI1ii1iI1 = lisp_myinterfaces [ ooOoo000 . interface ]
  except : return
  try :
   socket = iI1ii1iI1 . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 56 - 56: ooOoO0o . iIii1I11I1II1 + i1IIi
  try : socket . send ( self . packet )
  except socket . error as I1i :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( I1i ) )
   if 84 - 84: iII111i % i1IIi
   if 62 - 62: I1ii11iIi11i . I1Ii111 . Ii1I
   if 19 - 19: I1ii11iIi11i / I1Ii111
 def is_lisp_packet ( self , packet ) :
  O0I1II1 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == LISP_UDP_PROTOCOL )
  if ( O0I1II1 == False ) : return ( False )
  if 35 - 35: Oo0Ooo * oO0o / OoooooooOO + O0 / OoooooooOO / OOooOOo
  IiO0o = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
  if ( socket . ntohs ( IiO0o ) == LISP_DATA_PORT ) : return ( True )
  IiO0o = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
  if ( socket . ntohs ( IiO0o ) == LISP_DATA_PORT ) : return ( True )
  return ( False )
  if 69 - 69: oO0o - I1Ii111 / Oo0Ooo
  if 15 - 15: i1IIi
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  o0o0ooOOo0oO = self . packet
  I1iiIIiI11I = len ( o0o0ooOOo0oO )
  I11II1I = oOoOo000 = True
  if 37 - 37: iII111i
  if 15 - 15: o0oOOo0O0Ooo % OoO0O00 / iII111i
  if 36 - 36: OoO0O00 + OoO0O00 % Oo0Ooo + Oo0Ooo / i1IIi % i1IIi
  if 20 - 20: OOooOOo * oO0o
  OOOoooOo00O = 0
  i1 = 0
  if ( is_lisp_packet ) :
   i1 = self . lisp_header . get_instance_id ( )
   iiIIiI1I = struct . unpack ( "B" , o0o0ooOOo0oO [ 0 : 1 ] ) [ 0 ]
   self . outer_version = iiIIiI1I >> 4
   if ( self . outer_version == 4 ) :
    if 67 - 67: I1ii11iIi11i % OoooooooOO
    if 41 - 41: OoO0O00 / IiII + I1Ii111 . I1Ii111 / oO0o
    if 74 - 74: Ii1I % i11iIiiIii . O0 * I1IiiI * i1IIi * OoooooooOO
    if 22 - 22: I1Ii111 + iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoooooooOO
    if 42 - 42: OoooooooOO - OoOoOO00 - OOooOOo * I1Ii111
    OO0 = struct . unpack ( "H" , o0o0ooOOo0oO [ 10 : 12 ] ) [ 0 ]
    o0o0ooOOo0oO = lisp_ip_checksum ( o0o0ooOOo0oO )
    ii1II1II = struct . unpack ( "H" , o0o0ooOOo0oO [ 10 : 12 ] ) [ 0 ]
    if ( ii1II1II != 0 ) :
     if ( OO0 != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( I1iiIIiI11I )
       if 14 - 14: OoooooooOO + OOooOOo . iII111i
       if 94 - 94: IiII / I1Ii111 * IiII - ooOoO0o
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 89 - 89: iIii1I11I1II1
      if 31 - 31: ooOoO0o . OOooOOo % ooOoO0o
      if 33 - 33: O0 * Ii1I - IiII . OoooooooOO + IiII
    i1I1iiiI = LISP_AFI_IPV4
    IiI1ii1Ii = 12
    self . outer_tos = struct . unpack ( "B" , o0o0ooOOo0oO [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , o0o0ooOOo0oO [ 8 : 9 ] ) [ 0 ]
    OOOoooOo00O = 20
   elif ( self . outer_version == 6 ) :
    i1I1iiiI = LISP_AFI_IPV6
    IiI1ii1Ii = 8
    i1IiIi1I1i = struct . unpack ( "H" , o0o0ooOOo0oO [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( i1IiIi1I1i ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , o0o0ooOOo0oO [ 7 : 8 ] ) [ 0 ]
    OOOoooOo00O = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( I1iiIIiI11I )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 39 - 39: i11iIiiIii + OOooOOo % iII111i + Ii1I * I1IiiI + I1Ii111
    if 72 - 72: II111iiii + I1Ii111 * OOooOOo . I1IiiI
   self . outer_source . afi = i1I1iiiI
   self . outer_dest . afi = i1I1iiiI
   o0ooOo000oo = self . outer_source . addr_length ( )
   if 81 - 81: OoooooooOO - IiII - IiII + iIii1I11I1II1 % I11i . OoooooooOO
   self . outer_source . unpack_address ( o0o0ooOOo0oO [ IiI1ii1Ii : IiI1ii1Ii + o0ooOo000oo ] )
   IiI1ii1Ii += o0ooOo000oo
   self . outer_dest . unpack_address ( o0o0ooOOo0oO [ IiI1ii1Ii : IiI1ii1Ii + o0ooOo000oo ] )
   o0o0ooOOo0oO = o0o0ooOOo0oO [ OOOoooOo00O : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 75 - 75: O0
   if 96 - 96: Ii1I
   if 24 - 24: O0
   if 33 - 33: OoooooooOO + oO0o * II111iiii / OOooOOo
   oooo = struct . unpack ( "H" , o0o0ooOOo0oO [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( oooo )
   oooo = struct . unpack ( "H" , o0o0ooOOo0oO [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( oooo )
   oooo = struct . unpack ( "H" , o0o0ooOOo0oO [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( oooo )
   oooo = struct . unpack ( "H" , o0o0ooOOo0oO [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( oooo )
   o0o0ooOOo0oO = o0o0ooOOo0oO [ 8 : : ]
   if 15 - 15: OOooOOo * O0 % I1IiiI / ooOoO0o
   if 17 - 17: oO0o - II111iiii - iII111i + I11i
   if 54 - 54: II111iiii * O0 % I1IiiI . I11i
   if 62 - 62: Ii1I . i11iIiiIii % O0 % I1Ii111 - Oo0Ooo
   I11II1I = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   oOoOo000 = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 69 - 69: II111iiii . OoOoOO00 * OoOoOO00 % Ii1I + I1IiiI
   if 100 - 100: i11iIiiIii - Oo0Ooo
   if 47 - 47: iII111i * OoOoOO00 * IiII
   if 46 - 46: Ii1I
   if ( self . lisp_header . decode ( o0o0ooOOo0oO ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( I1iiIIiI11I )
    if 42 - 42: iIii1I11I1II1
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 32 - 32: Oo0Ooo - Ii1I . OoooooooOO - OoooooooOO - Oo0Ooo . iIii1I11I1II1
   o0o0ooOOo0oO = o0o0ooOOo0oO [ 8 : : ]
   i1 = self . lisp_header . get_instance_id ( )
   OOOoooOo00O += 16
   if 34 - 34: Oo0Ooo
  if ( i1 == 0xffffff ) : i1 = 0
  if 31 - 31: i1IIi - I11i + I1Ii111 + ooOoO0o . ooOoO0o . O0
  if 33 - 33: i1IIi / iII111i * OoO0O00
  if 2 - 2: oO0o . OOooOOo
  if 43 - 43: iIii1I11I1II1
  I1I1iIIiii1 = False
  I1IIiiiiI1iIi = self . lisp_header . k_bits
  if ( I1IIiiiiI1iIi ) :
   O0O0 = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( O0O0 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( I1iiIIiI11I )
    if 82 - 82: i11iIiiIii + O0 - Ii1I
    self . print_packet ( "Receive" , is_lisp_packet )
    oO00oO0 = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( oO00oO0 , I1IIiiiiI1iIi ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 80 - 80: iII111i . O0
    if 25 - 25: iII111i / iIii1I11I1II1 + I1IiiI / ooOoO0o
   OO0Oo00o0o0 = lisp_crypto_keys_by_rloc_decap [ O0O0 ] [ I1IIiiiiI1iIi ]
   if ( OO0Oo00o0o0 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( I1iiIIiI11I )
    if 43 - 43: II111iiii . i11iIiiIii . Ii1I - OoOoOO00 . I1Ii111
    self . print_packet ( "Receive" , is_lisp_packet )
    oO00oO0 = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( oO00oO0 ,
 red ( O0O0 , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 15 - 15: I1ii11iIi11i - iIii1I11I1II1 % II111iiii / I11i
    if 46 - 46: iIii1I11I1II1
    if 96 - 96: IiII
    if 56 - 56: I11i / oO0o - oO0o
    if 40 - 40: i11iIiiIii * II111iiii
   OO0Oo00o0o0 . use_count += 1
   o0o0ooOOo0oO , I1I1iIIiii1 = self . decrypt ( o0o0ooOOo0oO , OOOoooOo00O , OO0Oo00o0o0 ,
 O0O0 )
   if ( I1I1iIIiii1 == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( I1iiIIiI11I )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 57 - 57: O0 * iIii1I11I1II1 % O0 . OoooooooOO
    if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
    if 16 - 16: OoO0O00 % I1Ii111 . i1IIi / I1ii11iIi11i - O0
    if 85 - 85: i1IIi . i1IIi
    if 16 - 16: I1IiiI - OOooOOo % Ii1I . OOooOOo + I1ii11iIi11i % i11iIiiIii
    if 59 - 59: i11iIiiIii - I11i
  iiIIiI1I = struct . unpack ( "B" , o0o0ooOOo0oO [ 0 : 1 ] ) [ 0 ]
  self . inner_version = iiIIiI1I >> 4
  if ( I11II1I and self . inner_version == 4 and iiIIiI1I >= 0x45 ) :
   oooO00oOOooO = socket . ntohs ( struct . unpack ( "H" , o0o0ooOOo0oO [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , o0o0ooOOo0oO [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , o0o0ooOOo0oO [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , o0o0ooOOo0oO [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( o0o0ooOOo0oO [ 12 : 16 ] )
   self . inner_dest . unpack_address ( o0o0ooOOo0oO [ 16 : 20 ] )
   ooOo0 = socket . ntohs ( struct . unpack ( "H" , o0o0ooOOo0oO [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( ooOo0 & 0x2000 or ooOo0 != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , o0o0ooOOo0oO [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , o0o0ooOOo0oO [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 34 - 34: iIii1I11I1II1 / II111iiii
  elif ( I11II1I and self . inner_version == 6 and iiIIiI1I >= 0x60 ) :
   oooO00oOOooO = socket . ntohs ( struct . unpack ( "H" , o0o0ooOOo0oO [ 4 : 6 ] ) [ 0 ] ) + 40
   i1IiIi1I1i = struct . unpack ( "H" , o0o0ooOOo0oO [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( i1IiIi1I1i ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , o0o0ooOOo0oO [ 7 : 8 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , o0o0ooOOo0oO [ 6 : 7 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( o0o0ooOOo0oO [ 8 : 24 ] )
   self . inner_dest . unpack_address ( o0o0ooOOo0oO [ 24 : 40 ] )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , o0o0ooOOo0oO [ 40 : 42 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , o0o0ooOOo0oO [ 42 : 44 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 3 - 3: o0oOOo0O0Ooo - OoooooooOO + iII111i . I11i
  elif ( oOoOo000 ) :
   oooO00oOOooO = len ( o0o0ooOOo0oO )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_protocol = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( o0o0ooOOo0oO [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( o0o0ooOOo0oO [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( I1iiIIiI11I )
   if 88 - 88: I11i - iII111i
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( iiIIiI1I ) ) )
   if 68 - 68: Oo0Ooo % oO0o . IiII - o0oOOo0O0Ooo / i1IIi / OoooooooOO
   o0o0ooOOo0oO = lisp_format_packet ( o0o0ooOOo0oO [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( o0o0ooOOo0oO ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 34 - 34: I11i % Oo0Ooo + Ii1I
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = i1
  self . inner_dest . instance_id = i1
  if 93 - 93: Ii1I - I1Ii111 % O0
  if 11 - 11: i11iIiiIii
  if 6 - 6: II111iiii
  if 1 - 1: ooOoO0o % Oo0Ooo . oO0o
  if 98 - 98: II111iiii + II111iiii - iIii1I11I1II1 . OoOoOO00 . I1Ii111
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   OO0Ooo0O00ooOo0o = lisp_get_echo_nonce ( self . outer_source , None )
   if ( OO0Ooo0O00ooOo0o == None ) :
    iI = self . outer_source . print_address_no_iid ( )
    OO0Ooo0O00ooOo0o = lisp_echo_nonce ( iI )
    if 47 - 47: IiII . OOooOOo
   O0oo00o000 = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    OO0Ooo0O00ooOo0o . receive_request ( lisp_ipc_socket , O0oo00o000 )
   elif ( OO0Ooo0O00ooOo0o . request_nonce_sent ) :
    OO0Ooo0O00ooOo0o . receive_echo ( lisp_ipc_socket , O0oo00o000 )
    if 5 - 5: I1ii11iIi11i * Ii1I % I11i % II111iiii
    if 9 - 9: o0oOOo0O0Ooo % I1Ii111 + I11i
    if 55 - 55: OoO0O00 - I1ii11iIi11i
    if 38 - 38: iIii1I11I1II1 % IiII % OoO0O00 % O0 * iIii1I11I1II1 / I1Ii111
    if 65 - 65: OOooOOo - I1IiiI * I1Ii111
    if 99 - 99: I1IiiI
    if 64 - 64: I1ii11iIi11i * Ii1I * Oo0Ooo % IiII % ooOoO0o
  if ( I1I1iIIiii1 ) : self . packet += o0o0ooOOo0oO [ : oooO00oOOooO ]
  if 55 - 55: II111iiii - I1Ii111 - OOooOOo % Ii1I
  if 49 - 49: Oo0Ooo * I1Ii111
  if 53 - 53: Oo0Ooo / Ii1I + oO0o . iII111i + IiII
  if 19 - 19: Ii1I
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 51 - 51: iIii1I11I1II1
  if 8 - 8: OoO0O00 / o0oOOo0O0Ooo % iII111i . i11iIiiIii . OoooooooOO . Ii1I
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 8 - 8: OoO0O00 * Oo0Ooo
  if 41 - 41: Oo0Ooo / OoO0O00 / OoOoOO00 - i11iIiiIii - OoOoOO00
 def strip_outer_headers ( self ) :
  IiI1ii1Ii = 16
  IiI1ii1Ii += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ IiI1ii1Ii : : ]
  return ( self )
  if 4 - 4: I11i . IiII
  if 39 - 39: OOooOOo . Oo0Ooo - OoOoOO00 * i11iIiiIii
 def hash_ports ( self ) :
  o0o0ooOOo0oO = self . packet
  iiIIiI1I = self . inner_version
  iIIi111I1i1i = 0
  if ( iiIIiI1I == 4 ) :
   IiIii111III1 = struct . unpack ( "B" , o0o0ooOOo0oO [ 9 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( IiIii111III1 )
   if ( IiIii111III1 in [ 6 , 17 ] ) :
    iIIi111I1i1i = IiIii111III1
    iIIi111I1i1i += struct . unpack ( "I" , o0o0ooOOo0oO [ 20 : 24 ] ) [ 0 ]
    iIIi111I1i1i = ( iIIi111I1i1i >> 16 ) ^ ( iIIi111I1i1i & 0xffff )
    if 39 - 39: i11iIiiIii - OOooOOo - I1Ii111 + OoooooooOO / I1IiiI / iIii1I11I1II1
    if 16 - 16: OoOoOO00 / Ii1I . I1Ii111 % i11iIiiIii % I1IiiI / OOooOOo
  if ( iiIIiI1I == 6 ) :
   IiIii111III1 = struct . unpack ( "B" , o0o0ooOOo0oO [ 6 ] ) [ 0 ]
   if ( IiIii111III1 in [ 6 , 17 ] ) :
    iIIi111I1i1i = IiIii111III1
    iIIi111I1i1i += struct . unpack ( "I" , o0o0ooOOo0oO [ 40 : 44 ] ) [ 0 ]
    iIIi111I1i1i = ( iIIi111I1i1i >> 16 ) ^ ( iIIi111I1i1i & 0xffff )
    if 85 - 85: I11i + I1Ii111
    if 11 - 11: I11i
  return ( iIIi111I1i1i )
  if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
  if 11 - 11: I1ii11iIi11i / O0 + II111iiii
 def hash_packet ( self ) :
  iIIi111I1i1i = self . inner_source . address ^ self . inner_dest . address
  iIIi111I1i1i += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   iIIi111I1i1i = ( iIIi111I1i1i >> 16 ) ^ ( iIIi111I1i1i & 0xffff )
  elif ( self . inner_version == 6 ) :
   iIIi111I1i1i = ( iIIi111I1i1i >> 64 ) ^ ( iIIi111I1i1i & 0xffffffffffffffff )
   iIIi111I1i1i = ( iIIi111I1i1i >> 32 ) ^ ( iIIi111I1i1i & 0xffffffff )
   iIIi111I1i1i = ( iIIi111I1i1i >> 16 ) ^ ( iIIi111I1i1i & 0xffff )
   if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
  self . udp_sport = 0xf000 | ( iIIi111I1i1i & 0xfff )
  if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
  if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   iiIIi1i111i = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # O0 + oO0o + o0oOOo0O0Ooo
 green ( iiIIi1i111i , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 81 - 81: iIii1I11I1II1
   if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   Ii11II11iI1 = "decap"
   Ii11II11iI1 += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   Ii11II11iI1 = s_or_r
   if ( Ii11II11iI1 in [ "Send" , "Replicate" ] or Ii11II11iI1 . find ( "Fragment" ) != - 1 ) :
    Ii11II11iI1 = "encap"
    if 89 - 89: OoooooooOO % II111iiii - OoO0O00 % i11iIiiIii
    if 7 - 7: IiII
  III11i = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 54 - 54: I1Ii111 / o0oOOo0O0Ooo
  if 39 - 39: OOooOOo % oO0o * I1ii11iIi11i - O0 + I1IiiI + o0oOOo0O0Ooo
  if 64 - 64: II111iiii / II111iiii
  if 52 - 52: I1Ii111 * I1ii11iIi11i
  if 35 - 35: o0oOOo0O0Ooo % OoO0O00
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   OOooOoO = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 27 - 27: Ii1I - iIii1I11I1II1 * Ii1I
   OOooOoO += bold ( "control-packet" , False ) + ": {} ..."
   if 30 - 30: o0oOOo0O0Ooo + Ii1I / OoooooooOO - IiII % oO0o
   dprint ( OOooOoO . format ( bold ( s_or_r , False ) , red ( III11i , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   OOooOoO = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 21 - 21: OoooooooOO % OoOoOO00 - OoOoOO00 / I1ii11iIi11i / o0oOOo0O0Ooo
   if 15 - 15: ooOoO0o / ooOoO0o % OoooooooOO . I1Ii111
   if 93 - 93: I1ii11iIi11i * I1ii11iIi11i / OoooooooOO
   if 6 - 6: I1ii11iIi11i * Oo0Ooo + iIii1I11I1II1
  if ( self . lisp_header . k_bits ) :
   if ( Ii11II11iI1 == "encap" ) : Ii11II11iI1 = "encrypt/encap"
   if ( Ii11II11iI1 == "decap" ) : Ii11II11iI1 = "decap/decrypt"
   if 19 - 19: O0 % II111iiii * o0oOOo0O0Ooo
   if 27 - 27: OOooOOo * IiII / i11iIiiIii - oO0o + II111iiii
  iiIIi1i111i = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 43 - 43: I1ii11iIi11i - II111iiii
  dprint ( OOooOoO . format ( bold ( s_or_r , False ) , red ( III11i , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( iiIIi1i111i , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( Ii11II11iI1 ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 56 - 56: I1ii11iIi11i . i1IIi / iII111i % oO0o / O0 * I11i
  if 98 - 98: O0 + iII111i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 23 - 23: OoooooooOO . iIii1I11I1II1 / i1IIi
  if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
 def get_raw_socket ( self ) :
  i1 = str ( self . lisp_header . get_instance_id ( ) )
  if ( i1 == "0" ) : return ( None )
  if ( lisp_iid_to_interface . has_key ( i1 ) == False ) : return ( None )
  if 74 - 74: Oo0Ooo - II111iiii - IiII
  iI1ii1iI1 = lisp_iid_to_interface [ i1 ]
  I1iiIi111I = iI1ii1iI1 . get_socket ( )
  if ( I1iiIi111I == None ) :
   i1IIIII1 = bold ( "SO_BINDTODEVICE" , False )
   IiII1II1 = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( i1IIIII1 , "drop" if IiII1II1 else "forward" ) )
   if 61 - 61: Ii1I + I1IiiI / i1IIi + i1IIi / oO0o
   if ( IiII1II1 ) : return ( None )
   if 47 - 47: I1Ii111
   if 25 - 25: iII111i + I1IiiI + OoOoOO00 + I1Ii111 % O0
  i1 = bold ( i1 , False )
  IiI11I111 = bold ( iI1ii1iI1 . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( i1 , IiI11I111 ) )
  return ( I1iiIi111I )
  if 26 - 26: ooOoO0o + OoOoOO00
  if 17 - 17: I1ii11iIi11i - iII111i % Oo0Ooo * O0 % O0 * OOooOOo
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 6 - 6: I1Ii111
  ii1iiIiiiI11 = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or ii1iiIiiiI11 ) :
   o00o0o0o = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = o00o0o0o ) . start ( )
   if ( ii1iiIiiiI11 ) : os . system ( "rm ./log-flows" )
   return
   if 11 - 11: iIii1I11I1II1 / Ii1I + OoooooooOO % i1IIi * i11iIiiIii
   if 86 - 86: i11iIiiIii - O0 - i11iIiiIii . iIii1I11I1II1 . IiII
  ii1III11 = datetime . datetime . now ( )
  lisp_flow_log . append ( [ ii1III11 , encap , self . packet , self ] )
  if 84 - 84: i1IIi / iIii1I11I1II1 / oO0o / Ii1I
  if 7 - 7: OoOoOO00 . OOooOOo % Oo0Ooo
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  o00OO000 = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 53 - 53: OoOoOO00 - i1IIi % I1ii11iIi11i
  iIIIiiiII = red ( self . outer_source . print_address_no_iid ( ) , False )
  I1IiiiiIIII = red ( self . outer_dest . print_address_no_iid ( ) , False )
  oo000o = green ( self . inner_source . print_address ( ) , False )
  iIIIII = green ( self . inner_dest . print_address ( ) , False )
  if 48 - 48: OoOoOO00 * OoooooooOO + OoooooooOO * iIii1I11I1II1 * II111iiii % i11iIiiIii
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   o00OO000 += " {}:{} -> {}:{}, LISP control message type {}\n"
   o00OO000 = o00OO000 . format ( iIIIiiiII , self . udp_sport , I1IiiiiIIII , self . udp_dport ,
 self . inner_version )
   return ( o00OO000 )
   if 22 - 22: OoO0O00 . OoOoOO00 % II111iiii - O0
   if 52 - 52: OoO0O00
  if ( self . outer_dest . is_null ( ) == False ) :
   o00OO000 += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   o00OO000 = o00OO000 . format ( iIIIiiiII , self . udp_sport , I1IiiiiIIII , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 49 - 49: Ii1I . I1ii11iIi11i % ooOoO0o . Oo0Ooo * OOooOOo
   if 44 - 44: iIii1I11I1II1 / O0 * Oo0Ooo + I1IiiI . ooOoO0o
   if 20 - 20: iII111i + o0oOOo0O0Ooo . I1Ii111 / i11iIiiIii
   if 7 - 7: OoOoOO00 / OoOoOO00 . I1Ii111 * O0 + IiII + oO0o
   if 98 - 98: II111iiii * IiII - I1IiiI % o0oOOo0O0Ooo - iII111i % I1ii11iIi11i
  if ( self . lisp_header . k_bits != 0 ) :
   Oo0Oo0o00oO = "\n"
   if ( self . packet_error != "" ) :
    Oo0Oo0o00oO = " ({})" . format ( self . packet_error ) + Oo0Oo0o00oO
    if 81 - 81: I1ii11iIi11i % iII111i
   o00OO000 += ", encrypted" + Oo0Oo0o00oO
   return ( o00OO000 )
   if 22 - 22: OoooooooOO + o0oOOo0O0Ooo . I11i + I1IiiI + OoooooooOO . OoOoOO00
   if 93 - 93: I1IiiI
   if 89 - 89: OoooooooOO % i11iIiiIii + I1Ii111
   if 12 - 12: OoOoOO00 * ooOoO0o
   if 59 - 59: II111iiii * OoooooooOO - OoooooooOO
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 33 - 33: O0 . i11iIiiIii % o0oOOo0O0Ooo
   if 50 - 50: ooOoO0o
  IiIii111III1 = packet [ 9 ] if self . inner_version == 4 else packet [ 6 ]
  IiIii111III1 = struct . unpack ( "B" , IiIii111III1 ) [ 0 ]
  if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
  o00OO000 += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  o00OO000 = o00OO000 . format ( oo000o , iIIIII , len ( packet ) , self . inner_tos ,
 self . inner_ttl , IiIii111III1 )
  if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
  if 59 - 59: iII111i - OoooooooOO / ooOoO0o + I1ii11iIi11i . o0oOOo0O0Ooo - iII111i
  if 29 - 29: oO0o
  if 26 - 26: O0 % OOooOOo - IiII . OOooOOo
  if ( IiIii111III1 in [ 6 , 17 ] ) :
   OOo0O0 = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( OOo0O0 ) == 4 ) :
    OOo0O0 = socket . ntohl ( struct . unpack ( "I" , OOo0O0 ) [ 0 ] )
    o00OO000 += ", ports {} -> {}" . format ( OOo0O0 >> 16 , OOo0O0 & 0xffff )
    if 24 - 24: I1IiiI / iIii1I11I1II1 / O0 . iIii1I11I1II1 - OoO0O00 . iIii1I11I1II1
  elif ( IiIii111III1 == 1 ) :
   II1IiI1II1 = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( II1IiI1II1 ) == 2 ) :
    II1IiI1II1 = socket . ntohs ( struct . unpack ( "H" , II1IiI1II1 ) [ 0 ] )
    o00OO000 += ", icmp-seq {}" . format ( II1IiI1II1 )
    if 21 - 21: OoooooooOO . O0 / i11iIiiIii
    if 86 - 86: OoOoOO00 / OOooOOo
  if ( self . packet_error != "" ) :
   o00OO000 += " ({})" . format ( self . packet_error )
   if 40 - 40: iIii1I11I1II1 / ooOoO0o / I1IiiI + I1ii11iIi11i * OOooOOo
  o00OO000 += "\n"
  return ( o00OO000 )
  if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
  if 91 - 91: Ii1I + I11i - Oo0Ooo % OoOoOO00 . iII111i
 def is_trace ( self ) :
  OOo0O0 = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in OOo0O0 )
  if 51 - 51: OOooOOo / I11i
  if 51 - 51: ooOoO0o * oO0o - I1Ii111 + iII111i
  if 46 - 46: o0oOOo0O0Ooo - i11iIiiIii % OoO0O00 / Ii1I - OoOoOO00
  if 88 - 88: oO0o * I1IiiI / OoO0O00 - OOooOOo / i1IIi . I1Ii111
  if 26 - 26: i11iIiiIii - ooOoO0o
  if 45 - 45: ooOoO0o + II111iiii % iII111i
  if 55 - 55: ooOoO0o - oO0o % I1IiiI
  if 61 - 61: ooOoO0o
  if 22 - 22: iIii1I11I1II1 / ooOoO0o / I1IiiI - o0oOOo0O0Ooo
  if 21 - 21: oO0o . i11iIiiIii * I11i . OOooOOo / OOooOOo
  if 42 - 42: OoooooooOO / I1Ii111 . o0oOOo0O0Ooo / O0 - IiII * IiII
  if 1 - 1: Ii1I % I1Ii111
  if 97 - 97: OoOoOO00
  if 13 - 13: OoOoOO00 % OOooOOo . O0 / Oo0Ooo % Oo0Ooo
  if 19 - 19: I1Ii111 % ooOoO0o - ooOoO0o % I1IiiI . OOooOOo - OoooooooOO
  if 100 - 100: I1IiiI + Ii1I + o0oOOo0O0Ooo . i1IIi % OoooooooOO
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 64 - 64: O0 % i1IIi * I1Ii111 - Ii1I + Oo0Ooo
class lisp_data_header ( ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 65 - 65: OoOoOO00 . i11iIiiIii
  if 36 - 36: oO0o * iII111i + IiII * iII111i . I1ii11iIi11i - iIii1I11I1II1
 def print_header ( self , e_or_d ) :
  i1IIi1ii1i1ii = lisp_hex_string ( self . first_long & 0xffffff )
  oOoOO = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 8 - 8: I1IiiI . i11iIiiIii / I1IiiI * I11i
  OOooOoO = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 87 - 87: IiII - O0 + I1IiiI / OoooooooOO * iII111i / i1IIi
  return ( OOooOoO . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 i1IIi1ii1i1ii , oOoOO ) )
  if 28 - 28: o0oOOo0O0Ooo - iII111i * I1ii11iIi11i - II111iiii % II111iiii - IiII
  if 76 - 76: I1Ii111
 def encode ( self ) :
  Iii1I = "II"
  i1IIi1ii1i1ii = socket . htonl ( self . first_long )
  oOoOO = socket . htonl ( self . second_long )
  if 11 - 11: Oo0Ooo + II111iiii - I1ii11iIi11i
  OoOOoo0o00O0oO = struct . pack ( Iii1I , i1IIi1ii1i1ii , oOoOO )
  return ( OoOOoo0o00O0oO )
  if 28 - 28: OoooooooOO % O0 - OOooOOo / o0oOOo0O0Ooo / I1IiiI
  if 41 - 41: II111iiii * IiII / OoO0O00 . oO0o
 def decode ( self , packet ) :
  Iii1I = "II"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( False )
  if 12 - 12: i11iIiiIii . I11i * OOooOOo % i1IIi . ooOoO0o
  i1IIi1ii1i1ii , oOoOO = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  if 58 - 58: iII111i % iIii1I11I1II1 . iIii1I11I1II1 / I11i
  if 79 - 79: OoO0O00 / OOooOOo - i1IIi + i1IIi - IiII + IiII
  self . first_long = socket . ntohl ( i1IIi1ii1i1ii )
  self . second_long = socket . ntohl ( oOoOO )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 67 - 67: OoO0O00 * OoO0O00 / OoooooooOO
  if 79 - 79: o0oOOo0O0Ooo % iIii1I11I1II1 / II111iiii / Ii1I / Ii1I + O0
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 46 - 46: i1IIi / IiII
  if 84 - 84: OoOoOO00 / iIii1I11I1II1 + oO0o % ooOoO0o + oO0o - iIii1I11I1II1
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 27 - 27: O0 / o0oOOo0O0Ooo * I1IiiI
  if 41 - 41: ooOoO0o
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 11 - 11: i1IIi / I1Ii111 * I1ii11iIi11i * I1Ii111 * ooOoO0o - i11iIiiIii
  if 96 - 96: I1ii11iIi11i % I1ii11iIi11i
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 1 - 1: I1IiiI . Ii1I
  if 26 - 26: oO0o - ooOoO0o % Oo0Ooo - oO0o + IiII
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
  if 21 - 21: O0 * ooOoO0o % OoO0O00
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 14 - 14: O0 / I1Ii111 / ooOoO0o + IiII - IiII
  if 10 - 10: O0 - I1ii11iIi11i / I1Ii111 % OoOoOO00 / OoooooooOO / Ii1I
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 73 - 73: ooOoO0o + IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . I1Ii111
  if 76 - 76: I11i . I1ii11iIi11i * OoooooooOO % iII111i
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 24 - 24: OoooooooOO
  if 83 - 83: O0 / OoO0O00
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 62 - 62: I11i
  if 73 - 73: Ii1I % OoO0O00 * OOooOOo
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 84 - 84: Oo0Ooo
  if 18 - 18: OoooooooOO
  if 85 - 85: OoooooooOO . OoO0O00 . OoO0O00
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
  if 70 - 70: I11i
  if 72 - 72: I1Ii111 - ooOoO0o - I1IiiI - iII111i + OOooOOo - i1IIi
 def send_ipc ( self , ipc_socket , ipc ) :
  iIiI111ii1Ii = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  OO0oooOO = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , iIiI111ii1Ii )
  lisp_ipc ( ipc , ipc_socket , OO0oooOO )
  if 59 - 59: O0 . o0oOOo0O0Ooo % I1ii11iIi11i * oO0o + I11i
  if 82 - 82: OoooooooOO
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  Oo0O = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , Oo0O )
  if 8 - 8: o0oOOo0O0Ooo . II111iiii . iII111i - i11iIiiIii
  if 50 - 50: Ii1I . O0 % OoO0O00 . oO0o + Ii1I . OoOoOO00
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  Oo0O = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , Oo0O )
  if 69 - 69: i11iIiiIii + i11iIiiIii . i11iIiiIii - i11iIiiIii % Ii1I / iII111i
  if 59 - 59: OoooooooOO
 def receive_request ( self , ipc_socket , nonce ) :
  oOO00O00o00 = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( oOO00O00o00 != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 51 - 51: OoooooooOO / o0oOOo0O0Ooo
  if 15 - 15: II111iiii - Ii1I - iII111i . oO0o / i11iIiiIii
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 38 - 38: OoO0O00
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 3 - 3: II111iiii . I1IiiI / Oo0Ooo + o0oOOo0O0Ooo
  if 54 - 54: i1IIi - II111iiii . i1IIi
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 33 - 33: iII111i + Oo0Ooo % I11i . oO0o
  if 6 - 6: IiII + I1ii11iIi11i
  if 62 - 62: oO0o . I1Ii111 - OoooooooOO * II111iiii . i11iIiiIii
  if 13 - 13: iIii1I11I1II1 * o0oOOo0O0Ooo - i11iIiiIii
  if 63 - 63: OoooooooOO * I1Ii111
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   II1Iiiii = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 70 - 70: OoooooooOO / OOooOOo - OoO0O00 % OoooooooOO
   if 25 - 25: Oo0Ooo % o0oOOo0O0Ooo % i1IIi
   if ( remote_rloc . address > II1Iiiii . address ) :
    OoOOOO = "exit"
    self . request_nonce_sent = None
   else :
    OoOOOO = "stay in"
    self . echo_nonce_sent = None
    if 31 - 31: IiII . II111iiii % Oo0Ooo * Ii1I + Ii1I
    if 87 - 87: OoO0O00
   I1i11i = bold ( "collision" , False )
   OOoOo0O0 = red ( II1Iiiii . print_address_no_iid ( ) , False )
   iiiI1I = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( I1i11i ,
 OOoOo0O0 , iiiI1I , OoOOOO ) )
   if 92 - 92: Oo0Ooo % o0oOOo0O0Ooo - ooOoO0o / ooOoO0o / OoOoOO00
   if 84 - 84: OOooOOo
   if 4 - 4: IiII . I1Ii111 / Ii1I / iII111i + II111iiii
   if 32 - 32: i1IIi + iIii1I11I1II1 . I1ii11iIi11i . I11i - Ii1I
   if 55 - 55: I1ii11iIi11i / OoooooooOO - OoO0O00 / I1IiiI
  if ( self . echo_nonce_sent != None ) :
   O0oo00o000 = self . echo_nonce_sent
   I1i = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( I1i ,
 lisp_hex_string ( O0oo00o000 ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( O0oo00o000 )
   if 23 - 23: I11i * I1Ii111 * o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + o0oOOo0O0Ooo
   if 41 - 41: IiII * OoooooooOO . ooOoO0o % i11iIiiIii
   if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
   if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
   if 8 - 8: o0oOOo0O0Ooo
   if 78 - 78: i1IIi - Oo0Ooo
   if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
  O0oo00o000 = self . request_nonce_sent
  i11iII11I1III = self . last_request_nonce_sent
  if ( O0oo00o000 and i11iII11I1III != None ) :
   if ( time . time ( ) - i11iII11I1III >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( O0oo00o000 ) ) )
    if 44 - 44: OOooOOo . iIii1I11I1II1 . i11iIiiIii % OoooooooOO . ooOoO0o
    return ( None )
    if 53 - 53: IiII + O0
    if 88 - 88: OoooooooOO
    if 46 - 46: O0 % OoooooooOO
    if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
    if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
    if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
    if 2 - 2: ooOoO0o - O0 - I1ii11iIi11i / I11i * OoOoOO00
    if 26 - 26: I1ii11iIi11i + I1Ii111 - oO0o + IiII % OOooOOo
    if 84 - 84: I11i % Ii1I % O0 * o0oOOo0O0Ooo
  if ( O0oo00o000 == None ) :
   O0oo00o000 = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( O0oo00o000 )
   if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
   self . request_nonce_sent = O0oo00o000
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( O0oo00o000 ) ) )
   if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
   if 65 - 65: I1ii11iIi11i / ooOoO0o
   if 23 - 23: OOooOOo / OOooOOo * o0oOOo0O0Ooo * OOooOOo
   if 57 - 57: iII111i
   if 29 - 29: I1IiiI
   if ( lisp_i_am_itr == False ) : return ( O0oo00o000 | 0x80000000 )
   self . send_request_ipc ( ipc_socket , O0oo00o000 )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( O0oo00o000 ) ) )
   if 41 - 41: I1Ii111 * OoO0O00 - iII111i . Ii1I
   if 41 - 41: iIii1I11I1II1 - O0 - I1ii11iIi11i - oO0o + I1Ii111
   if 22 - 22: O0 % IiII % iII111i % I1IiiI
   if 34 - 34: iII111i . Oo0Ooo % I1ii11iIi11i . iII111i % IiII / IiII
   if 84 - 84: Ii1I
   if 1 - 1: oO0o - Oo0Ooo * iIii1I11I1II1 * Oo0Ooo * i1IIi
   if 9 - 9: iII111i - iII111i
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( O0oo00o000 | 0x80000000 )
  if 3 - 3: O0 + O0 - O0 - O0 % OoooooooOO + oO0o
  if 20 - 20: OoO0O00 + I11i . II111iiii / i11iIiiIii
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 50 - 50: OoooooooOO / OoO0O00 % iIii1I11I1II1
  Ii1i1 = time . time ( ) - self . last_request_nonce_sent
  IIIIi11111 = self . last_echo_nonce_rcvd
  return ( Ii1i1 >= LISP_NONCE_ECHO_INTERVAL and IIIIi11111 == None )
  if 99 - 99: O0 * i11iIiiIii % OOooOOo * II111iiii
  if 98 - 98: O0 + iIii1I11I1II1
 def recently_requested ( self ) :
  IIIIi11111 = self . last_request_nonce_sent
  if ( IIIIi11111 == None ) : return ( False )
  if 94 - 94: i1IIi * OoO0O00 * OoOoOO00
  Ii1i1 = time . time ( ) - IIIIi11111
  return ( Ii1i1 <= LISP_NONCE_ECHO_INTERVAL )
  if 93 - 93: ooOoO0o / OOooOOo * O0
  if 17 - 17: OoO0O00 / ooOoO0o % I1IiiI
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 47 - 47: Oo0Ooo * OoO0O00 / o0oOOo0O0Ooo * I1IiiI
  if 60 - 60: I1ii11iIi11i / IiII . i11iIiiIii / OoO0O00 % II111iiii
  if 6 - 6: iII111i % o0oOOo0O0Ooo + I1Ii111
  if 91 - 91: o0oOOo0O0Ooo + O0 * oO0o * IiII * I1ii11iIi11i
  IIIIi11111 = self . last_good_echo_nonce_rcvd
  if ( IIIIi11111 == None ) : IIIIi11111 = 0
  Ii1i1 = time . time ( ) - IIIIi11111
  if ( Ii1i1 <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 83 - 83: OoooooooOO
  if 52 - 52: o0oOOo0O0Ooo / OoOoOO00 % oO0o % OoO0O00 / IiII % o0oOOo0O0Ooo
  if 88 - 88: OOooOOo / i11iIiiIii / Ii1I / i11iIiiIii * I1ii11iIi11i % I11i
  if 43 - 43: OoOoOO00 * OoO0O00 % i1IIi * Ii1I + iIii1I11I1II1
  if 80 - 80: o0oOOo0O0Ooo . iII111i . OoooooooOO
  if 63 - 63: ooOoO0o . OOooOOo
  IIIIi11111 = self . last_new_request_nonce_sent
  if ( IIIIi11111 == None ) : IIIIi11111 = 0
  Ii1i1 = time . time ( ) - IIIIi11111
  return ( Ii1i1 <= LISP_NONCE_ECHO_INTERVAL )
  if 66 - 66: I1IiiI
  if 99 - 99: OoO0O00 % O0 . I1Ii111 - I1ii11iIi11i . Oo0Ooo / OoOoOO00
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   o0oOOoOoo = bold ( "down" , False )
   ooO0O = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , o0oOOoOoo , ooO0O ) )
   if 55 - 55: OOooOOo - II111iiii - IiII . I11i + oO0o - oO0o
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 29 - 29: OoOoOO00 - I1Ii111 % OOooOOo
   if 45 - 45: IiII / Oo0Ooo + OoooooooOO
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 77 - 77: oO0o . Ii1I / O0 * oO0o
  if ( self . recently_requested ( ) == False ) :
   oOoO0O0o = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , oOoO0O0o ) )
   if 84 - 84: OoOoOO00 - I11i
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 80 - 80: i11iIiiIii % OOooOOo - Oo0Ooo % OOooOOo
   if 89 - 89: Ii1I * I11i + OoOoOO00 / i11iIiiIii
   if 68 - 68: OoooooooOO * I11i
 def print_echo_nonce ( self ) :
  oOOO = lisp_print_elapsed ( self . last_request_nonce_sent )
  Iii111111 = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 23 - 23: I1Ii111 - iIii1I11I1II1 - II111iiii + I1Ii111 % Ii1I / I11i
  oO0o0o0OO0o00 = lisp_print_elapsed ( self . last_echo_nonce_sent )
  IiII11 = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  I1iiIi111I = space ( 4 )
  if 56 - 56: I1IiiI
  OoiIIIiIi1I1i = "Nonce-Echoing:\n"
  OoiIIIiIi1I1i += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( I1iiIi111I , oOOO , I1iiIi111I , Iii111111 )
  if 49 - 49: i1IIi % oO0o / OOooOOo . I1ii11iIi11i - I1Ii111
  OoiIIIiIi1I1i += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( I1iiIi111I , IiII11 , I1iiIi111I , oO0o0o0OO0o00 )
  if 12 - 12: i11iIiiIii + I11i - I1ii11iIi11i
  if 27 - 27: iII111i
  return ( OoiIIIiIi1I1i )
  if 22 - 22: OoOoOO00 / I1IiiI
  if 33 - 33: I11i
  if 37 - 37: OoOoOO00 % o0oOOo0O0Ooo * OoO0O00 / i11iIiiIii * II111iiii * iII111i
  if 70 - 70: ooOoO0o . i11iIiiIii % OoOoOO00 + oO0o
  if 95 - 95: I1ii11iIi11i
  if 48 - 48: I11i
  if 14 - 14: iIii1I11I1II1 / o0oOOo0O0Ooo * IiII
  if 35 - 35: iIii1I11I1II1
  if 34 - 34: OoO0O00 % I1IiiI . o0oOOo0O0Ooo % OoO0O00 % OoO0O00
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
    if 30 - 30: I1IiiI + I1IiiI
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   OO0Oo00o0o0 = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( OO0Oo00o0o0 )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 75 - 75: I1IiiI - ooOoO0o - I1IiiI % oO0o % OoooooooOO
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 13 - 13: ooOoO0o * OoO0O00 % iIii1I11I1II1 / IiII * iII111i . Oo0Ooo
  if 23 - 23: ooOoO0o / IiII . iII111i * Ii1I
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 87 - 87: i11iIiiIii
  if 34 - 34: i1IIi
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 64 - 64: iIii1I11I1II1 / IiII / Oo0Ooo - I1ii11iIi11i
  OoOooO = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   OoOooO = struct . pack ( "Q" , OoOooO & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   o00oOOO = struct . pack ( "I" , ( OoOooO >> 64 ) & LISP_4_32_MASK )
   OoOOOo0 = struct . pack ( "Q" , OoOooO & LISP_8_64_MASK )
   OoOooO = o00oOOO + OoOOOo0
  else :
   OoOooO = struct . pack ( "QQ" , OoOooO >> 64 , OoOooO & LISP_8_64_MASK )
  return ( OoOooO )
  if 53 - 53: o0oOOo0O0Ooo / I11i % O0 / iIii1I11I1II1 / iII111i
  if 1 - 1: Oo0Ooo . i11iIiiIii
 def key_length ( self , key ) :
  if ( type ( key ) != str ) : key = self . normalize_pub_key ( key )
  return ( len ( key ) / 2 )
  if 9 - 9: OoooooooOO / I11i
  if 47 - 47: OoooooooOO
 def print_key ( self , key ) :
  o00oOOo0Oo = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( o00oOOo0Oo [ 0 : 4 ] , o00oOOo0Oo [ - 4 : : ] , self . key_length ( o00oOOo0Oo ) ) )
  if 48 - 48: OoOoOO00 . IiII % I1IiiI + I11i
  if 37 - 37: Oo0Ooo + I1Ii111 * oO0o / o0oOOo0O0Ooo
 def normalize_pub_key ( self , key ) :
  if ( type ( key ) == str ) :
   if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
   return ( key )
   if 78 - 78: IiII + I11i - o0oOOo0O0Ooo + OoO0O00 / iIii1I11I1II1
  key = lisp_hex_string ( key ) . zfill ( 256 )
  return ( key )
  if 47 - 47: OOooOOo
  if 20 - 20: I1Ii111 % ooOoO0o - I1Ii111 * OoooooooOO / I1ii11iIi11i
 def print_keys ( self , do_bold = True ) :
  OOoOo0O0 = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   OOoOo0O0 += "none"
  else :
   OOoOo0O0 += self . print_key ( self . local_public_key )
   if 57 - 57: IiII % I11i * OOooOOo % I1ii11iIi11i
  iiiI1I = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   iiiI1I += "none"
  else :
   iiiI1I += self . print_key ( self . remote_public_key )
   if 65 - 65: i1IIi - OoooooooOO
  OO0o = "ECDH" if ( self . curve25519 ) else "DH"
  oOO00o0 = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( OO0o , oOO00o0 , OOoOo0O0 , iiiI1I ) )
  if 29 - 29: II111iiii - iII111i / oO0o % OoooooooOO % iII111i + IiII
  if 44 - 44: O0 / O0
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 25 - 25: o0oOOo0O0Ooo + iIii1I11I1II1 + IiII + I1ii11iIi11i / I1Ii111 - i1IIi
  if 15 - 15: O0 % Oo0Ooo % IiII % OoooooooOO - IiII
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
  OO0Oo00o0o0 = self . local_private_key
  OoIi1I1I = self . dh_g_value
  IIIiIIi111 = self . dh_p_value
  return ( int ( ( OoIi1I1I ** OO0Oo00o0o0 ) % IIIiIIi111 ) )
  if 77 - 77: I1IiiI / I1Ii111
  if 65 - 65: I1ii11iIi11i * O0 . OoooooooOO * I11i / IiII
 def compute_shared_key ( self , ed , print_shared = False ) :
  OO0Oo00o0o0 = self . local_private_key
  oO0 = self . remote_public_key
  if 73 - 73: i11iIiiIii + OoOoOO00 / I11i - OoooooooOO
  oOii1iiiiii = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( oOii1iiiiii , self . print_keys ( ) ) )
  if 69 - 69: OoOoOO00 + O0 - I11i - iIii1I11I1II1 . OoO0O00
  if ( self . curve25519 ) :
   i1I = curve25519 . Public ( oO0 )
   self . shared_key = self . curve25519 . get_shared_key ( i1I )
  else :
   IIIiIIi111 = self . dh_p_value
   self . shared_key = ( oO0 ** OO0Oo00o0o0 ) % IIIiIIi111
   if 73 - 73: Ii1I * OoooooooOO * I11i - i11iIiiIii
   if 58 - 58: o0oOOo0O0Ooo + OoOoOO00 - IiII
   if 82 - 82: Ii1I . iIii1I11I1II1 / Ii1I / oO0o % iIii1I11I1II1
   if 34 - 34: OOooOOo
   if 99 - 99: II111iiii
   if 13 - 13: I11i - ooOoO0o + iII111i % I11i . iII111i - i1IIi
   if 67 - 67: OOooOOo . i11iIiiIii + ooOoO0o . iIii1I11I1II1
  if ( print_shared ) :
   o00oOOo0Oo = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( o00oOOo0Oo ) )
   if 28 - 28: I1IiiI + I1IiiI + I1Ii111
   if 22 - 22: I1Ii111
   if 89 - 89: ooOoO0o . OoO0O00 * OoooooooOO + OoOoOO00 / O0
   if 60 - 60: I11i
   if 97 - 97: i11iIiiIii * iIii1I11I1II1 / II111iiii
  self . compute_encrypt_icv_keys ( )
  if 66 - 66: II111iiii + iII111i * oO0o % I11i / i1IIi / iIii1I11I1II1
  if 62 - 62: OoOoOO00 + oO0o * IiII + O0 / OOooOOo + ooOoO0o
  if 38 - 38: i1IIi / iIii1I11I1II1 + iII111i
  if 26 - 26: I1ii11iIi11i . Ii1I % o0oOOo0O0Ooo
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 4 - 4: I1Ii111
  if 80 - 80: Oo0Ooo . O0 % o0oOOo0O0Ooo . o0oOOo0O0Ooo
 def compute_encrypt_icv_keys ( self ) :
  OOoo000Ooo = hashlib . sha256
  if ( self . curve25519 ) :
   iiii1II = self . shared_key
  else :
   iiii1II = lisp_hex_string ( self . shared_key )
   if 28 - 28: OoooooooOO % I11i
   if 3 - 3: o0oOOo0O0Ooo / Oo0Ooo - OoO0O00 + II111iiii
   if 3 - 3: i11iIiiIii
   if 20 - 20: i1IIi * iII111i + OoO0O00 * OoO0O00 / Oo0Ooo
   if 83 - 83: I1ii11iIi11i
  OOoOo0O0 = self . local_public_key
  if ( type ( OOoOo0O0 ) != int ) : OOoOo0O0 = int ( binascii . hexlify ( OOoOo0O0 ) , 16 )
  iiiI1I = self . remote_public_key
  if ( type ( iiiI1I ) != int ) : iiiI1I = int ( binascii . hexlify ( iiiI1I ) , 16 )
  OOo0OOooO0 = "0001" + "lisp-crypto" + lisp_hex_string ( OOoOo0O0 ^ iiiI1I ) + "0100"
  if 80 - 80: I1ii11iIi11i
  ooOOO = hmac . new ( OOo0OOooO0 , iiii1II , OOoo000Ooo ) . hexdigest ( )
  ooOOO = int ( ooOOO , 16 )
  if 95 - 95: I11i
  if 76 - 76: II111iiii - i1IIi . O0 * i11iIiiIii % o0oOOo0O0Ooo - iII111i
  if 30 - 30: I1Ii111 % oO0o + oO0o * OoooooooOO - I1ii11iIi11i
  if 69 - 69: I1ii11iIi11i + OoO0O00 / O0 + II111iiii / i11iIiiIii
  iiii = ( ooOOO >> 128 ) & LISP_16_128_MASK
  OOO00Oo00o = ooOOO & LISP_16_128_MASK
  self . encrypt_key = lisp_hex_string ( iiii ) . zfill ( 32 )
  IiII1Iiii = 32 if self . do_poly else 40
  self . icv_key = lisp_hex_string ( OOO00Oo00o ) . zfill ( IiII1Iiii )
  if 16 - 16: iII111i . O0 - I1Ii111 * I1Ii111
  if 80 - 80: Ii1I % I1ii11iIi11i
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   OOoo000OO00 = self . icv . poly1305aes
   O000oo0O0OO0 = self . icv . binascii . hexlify
   nonce = O000oo0O0OO0 ( nonce )
   oOoo0ooO = OOoo000OO00 ( self . encrypt_key , self . icv_key , nonce , packet )
   oOoo0ooO = O000oo0O0OO0 ( oOoo0ooO )
  else :
   OO0Oo00o0o0 = binascii . unhexlify ( self . icv_key )
   oOoo0ooO = hmac . new ( OO0Oo00o0o0 , packet , self . icv ) . hexdigest ( )
   oOoo0ooO = oOoo0ooO [ 0 : 40 ]
   if 48 - 48: iII111i
  return ( oOoo0ooO )
  if 85 - 85: I1ii11iIi11i . oO0o . O0
  if 16 - 16: I1ii11iIi11i % I1ii11iIi11i % I1Ii111 + I11i . I1Ii111 + OOooOOo
 def add_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 85 - 85: i11iIiiIii . I11i + Ii1I / Ii1I
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 43 - 43: IiII . OoooooooOO - II111iiii
  if 90 - 90: I1IiiI - iIii1I11I1II1 + I1ii11iIi11i * OOooOOo * oO0o
 def delete_key_by_nonce ( self , nonce ) :
  if ( lisp_crypto_keys_by_nonce . has_key ( nonce ) == False ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 19 - 19: I1Ii111 * II111iiii % Oo0Ooo - i1IIi
  if 27 - 27: OoOoOO00 . O0 / I1ii11iIi11i . iIii1I11I1II1
 def add_key_by_rloc ( self , addr_str , encap ) :
  I11IIi = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 51 - 51: i1IIi % o0oOOo0O0Ooo - oO0o - IiII
  if 14 - 14: ooOoO0o + Ii1I
  if ( I11IIi . has_key ( addr_str ) == False ) :
   I11IIi [ addr_str ] = [ None , None , None , None ]
   if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
  I11IIi [ addr_str ] [ self . key_id ] = self
  if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
  if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
  if 28 - 28: iIii1I11I1II1 . O0
  if 32 - 32: OoooooooOO
  if 29 - 29: I1ii11iIi11i
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , I11IIi [ addr_str ] )
   if 41 - 41: Ii1I
   if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
   if 47 - 47: O0 . o0oOOo0O0Ooo / Ii1I * iII111i
 def encode_lcaf ( self , rloc_addr ) :
  O0OOO0o0O = self . normalize_pub_key ( self . local_public_key )
  oOo0oOooOoO00 = self . key_length ( O0OOO0o0O )
  II1I1Ii = ( 6 + oOo0oOooOoO00 + 2 )
  if ( rloc_addr != None ) : II1I1Ii += rloc_addr . addr_length ( )
  if 8 - 8: iII111i . Ii1I - i1IIi % OoO0O00 / I11i
  o0o0ooOOo0oO = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( II1I1Ii ) , 1 , 0 )
  if 13 - 13: Oo0Ooo / OoOoOO00 . I1ii11iIi11i . OOooOOo
  if 31 - 31: o0oOOo0O0Ooo
  if 59 - 59: Oo0Ooo / Oo0Ooo
  if 87 - 87: I1ii11iIi11i % OoOoOO00 + Ii1I . i11iIiiIii / Ii1I
  if 32 - 32: Ii1I + IiII + I1ii11iIi11i
  if 79 - 79: i1IIi / Ii1I
  oOO00o0 = self . cipher_suite
  o0o0ooOOo0oO += struct . pack ( "BBH" , oOO00o0 , 0 , socket . htons ( oOo0oOooOoO00 ) )
  if 81 - 81: iIii1I11I1II1
  if 86 - 86: IiII % IiII % OoooooooOO
  if 42 - 42: Oo0Ooo . oO0o + O0 / OOooOOo % OoooooooOO
  if 19 - 19: ooOoO0o / Ii1I
  for OoOOoO0oOo in range ( 0 , oOo0oOooOoO00 * 2 , 16 ) :
   OO0Oo00o0o0 = int ( O0OOO0o0O [ OoOOoO0oOo : OoOOoO0oOo + 16 ] , 16 )
   o0o0ooOOo0oO += struct . pack ( "Q" , byte_swap_64 ( OO0Oo00o0o0 ) )
   if 43 - 43: OoOoOO00 % Ii1I + Oo0Ooo - OoooooooOO . O0 % Oo0Ooo
   if 98 - 98: o0oOOo0O0Ooo * Oo0Ooo - Ii1I . ooOoO0o
   if 2 - 2: Oo0Ooo - ooOoO0o % iIii1I11I1II1
   if 88 - 88: I1Ii111 - OoO0O00
   if 79 - 79: iII111i
  if ( rloc_addr ) :
   o0o0ooOOo0oO += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   o0o0ooOOo0oO += rloc_addr . pack_address ( )
   if 45 - 45: II111iiii + iII111i . I11i . O0 * i1IIi - Ii1I
  return ( o0o0ooOOo0oO )
  if 48 - 48: I1ii11iIi11i + Oo0Ooo
  if 76 - 76: I1ii11iIi11i
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 98 - 98: II111iiii + I1IiiI - I1ii11iIi11i . Ii1I
  if 51 - 51: Ii1I + i11iIiiIii * OoO0O00 % Oo0Ooo / I1IiiI - iIii1I11I1II1
  if 20 - 20: I1Ii111 . I11i . Ii1I + I11i - OOooOOo * oO0o
  if 82 - 82: OoO0O00
  if ( lcaf_len == 0 ) :
   Iii1I = "HHBBH"
   IiiiiI = struct . calcsize ( Iii1I )
   if ( len ( packet ) < IiiiiI ) : return ( None )
   if 78 - 78: II111iiii / I11i - i11iIiiIii + I1ii11iIi11i * Oo0Ooo
   i1I1iiiI , i1Ii1II , iIiI1 , i1Ii1II , lcaf_len = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
   if 23 - 23: iIii1I11I1II1 - i1IIi - IiII * IiII . IiII
   if 79 - 79: I11i - OoOoOO00 + I1Ii111 / I1IiiI * OoooooooOO
   if ( iIiI1 != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 26 - 26: II111iiii * iII111i + o0oOOo0O0Ooo / O0 + i1IIi - I11i
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ IiiiiI : : ]
   if 56 - 56: OOooOOo
   if 76 - 76: i1IIi % iIii1I11I1II1 - o0oOOo0O0Ooo + IiII - I11i
   if 81 - 81: I1ii11iIi11i + OoooooooOO - OOooOOo * O0
   if 100 - 100: iIii1I11I1II1 - OoOoOO00
   if 28 - 28: Oo0Ooo . O0 . I11i
   if 60 - 60: II111iiii + I1Ii111 / oO0o % OoooooooOO - i1IIi
  iIiI1 = LISP_LCAF_SECURITY_TYPE
  Iii1I = "BBBBH"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 57 - 57: ooOoO0o
  OO00O0O , i1Ii1II , oOO00o0 , i1Ii1II , oOo0oOooOoO00 = struct . unpack ( Iii1I ,
 packet [ : IiiiiI ] )
  if 52 - 52: I1ii11iIi11i
  if 93 - 93: iII111i . i11iIiiIii
  if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
  if 49 - 49: O0 . Oo0Ooo / Ii1I
  if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
  if 86 - 86: I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
  packet = packet [ IiiiiI : : ]
  oOo0oOooOoO00 = socket . ntohs ( oOo0oOooOoO00 )
  if ( len ( packet ) < oOo0oOooOoO00 ) : return ( None )
  if 20 - 20: iII111i . OoooooooOO + iII111i + ooOoO0o * I1ii11iIi11i
  if 44 - 44: i11iIiiIii
  if 69 - 69: OOooOOo * O0 + i11iIiiIii
  if 65 - 65: O0 / iII111i . i1IIi * iII111i / iIii1I11I1II1 - oO0o
  OOOo00OOooO = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( oOO00o0 not in OOOo00OOooO ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( OOOo00OOooO ,
 oOO00o0 ) )
   packet = packet [ oOo0oOooOoO00 : : ]
   return ( packet )
   if 57 - 57: oO0o . o0oOOo0O0Ooo % I1ii11iIi11i - o0oOOo0O0Ooo
   if 64 - 64: o0oOOo0O0Ooo
  self . cipher_suite = oOO00o0
  if 69 - 69: O0 % iII111i . Oo0Ooo + iII111i
  if 57 - 57: I1ii11iIi11i . I1Ii111 . IiII . Oo0Ooo % oO0o * I1ii11iIi11i
  if 84 - 84: ooOoO0o . I1ii11iIi11i
  if 1 - 1: Oo0Ooo * O0 . I1IiiI + ooOoO0o / OoOoOO00 + I11i
  if 68 - 68: II111iiii
  O0OOO0o0O = 0
  for OoOOoO0oOo in range ( 0 , oOo0oOooOoO00 , 8 ) :
   OO0Oo00o0o0 = byte_swap_64 ( struct . unpack ( "Q" , packet [ OoOOoO0oOo : OoOOoO0oOo + 8 ] ) [ 0 ] )
   O0OOO0o0O <<= 64
   O0OOO0o0O |= OO0Oo00o0o0
   if 61 - 61: OOooOOo . I1ii11iIi11i * oO0o / I1Ii111 - OoO0O00
  self . remote_public_key = O0OOO0o0O
  if 18 - 18: I1Ii111
  if 34 - 34: iII111i + I1Ii111 * I11i / II111iiii
  if 14 - 14: II111iiii + iII111i + Ii1I / iII111i . iIii1I11I1II1
  if 85 - 85: I11i % I11i . O0
  if 40 - 40: OoO0O00 * OoOoOO00 * iIii1I11I1II1 / OoOoOO00 * OoooooooOO / I1ii11iIi11i
  if ( self . curve25519 ) :
   OO0Oo00o0o0 = lisp_hex_string ( self . remote_public_key )
   OO0Oo00o0o0 = OO0Oo00o0o0 . zfill ( 64 )
   IiiI11i11ii = ""
   for OoOOoO0oOo in range ( 0 , len ( OO0Oo00o0o0 ) , 2 ) :
    IiiI11i11ii += chr ( int ( OO0Oo00o0o0 [ OoOOoO0oOo : OoOOoO0oOo + 2 ] , 16 ) )
    if 42 - 42: I1Ii111 * Oo0Ooo % OoOoOO00
   self . remote_public_key = IiiI11i11ii
   if 6 - 6: OOooOOo - O0 * I1ii11iIi11i
   if 98 - 98: IiII * iII111i . OoooooooOO . O0
  packet = packet [ oOo0oOooOoO00 : : ]
  return ( packet )
  if 89 - 89: iII111i / O0 % OoooooooOO - O0 . OoO0O00
  if 32 - 32: ooOoO0o
  if 26 - 26: O0 * Ii1I - I1IiiI - iII111i / iIii1I11I1II1
  if 57 - 57: I1ii11iIi11i - OoO0O00 * iIii1I11I1II1
  if 26 - 26: OoO0O00 % ooOoO0o % o0oOOo0O0Ooo % OoOoOO00 . iII111i % O0
  if 91 - 91: II111iiii . Oo0Ooo . oO0o - OoooooooOO / OoOoOO00
  if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
  if 55 - 55: OoO0O00
class lisp_thread ( ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
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
  if 77 - 77: o0oOOo0O0Ooo
  if 63 - 63: ooOoO0o * oO0o + ooOoO0o * Ii1I + Oo0Ooo / I1ii11iIi11i
 def decode ( self , packet ) :
  Iii1I = "BBBBQ"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( False )
  if 15 - 15: O0 . I1ii11iIi11i * I1ii11iIi11i
  o00oO0O , IIi1 , OOoO0OooO , self . record_count , self . nonce = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  if 38 - 38: I1IiiI . oO0o / O0 % Oo0Ooo / IiII / OoooooooOO
  if 11 - 11: O0 / I1Ii111 / iIii1I11I1II1 % Ii1I
  self . type = o00oO0O >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( o00oO0O & 0x01 ) else False
   self . rloc_probe = True if ( o00oO0O & 0x02 ) else False
   self . smr_invoked_bit = True if ( IIi1 & 0x40 ) else False
   if 31 - 31: I11i . i11iIiiIii . OoO0O00 * Oo0Ooo % Ii1I . o0oOOo0O0Ooo
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( o00oO0O & 0x04 ) else False
   self . to_etr = True if ( o00oO0O & 0x02 ) else False
   self . to_ms = True if ( o00oO0O & 0x01 ) else False
   if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( o00oO0O & 0x08 ) else False
   if 93 - 93: ooOoO0o % I1Ii111
  return ( True )
  if 46 - 46: I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
  if 43 - 43: ooOoO0o . i1IIi
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 68 - 68: IiII % Oo0Ooo . O0 - OoOoOO00 + I1ii11iIi11i . i11iIiiIii
  if 45 - 45: I1IiiI
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
  if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
  if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 61 - 61: Oo0Ooo - I1Ii111
  if 51 - 51: iII111i * ooOoO0o / O0 / O0
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 52 - 52: OoooooooOO % O0
  if 56 - 56: oO0o - i1IIi * OoooooooOO - II111iiii
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 28 - 28: i1IIi / I11i . o0oOOo0O0Ooo
  if 11 - 11: Oo0Ooo * OoooooooOO - i11iIiiIii
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 13 - 13: i11iIiiIii . O0 / OOooOOo * i1IIi
  if 14 - 14: IiII + IiII . I11i / Ii1I . iIii1I11I1II1
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
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
  if 46 - 46: Oo0Ooo . ooOoO0o % Oo0Ooo / II111iiii * ooOoO0o * OOooOOo
  if 59 - 59: I1Ii111 * iII111i
  if 31 - 31: I11i / O0
  if 57 - 57: i1IIi % ooOoO0o
  if 69 - 69: o0oOOo0O0Ooo
  if 69 - 69: I1Ii111
  if 83 - 83: iIii1I11I1II1 . o0oOOo0O0Ooo + I1Ii111 . OoooooooOO / ooOoO0o + II111iiii
  if 90 - 90: Ii1I * iII111i / OOooOOo
  if 68 - 68: OoOoOO00
  if 65 - 65: oO0o
  if 82 - 82: o0oOOo0O0Ooo
  if 80 - 80: i1IIi % OoOoOO00 + OoO0O00 - OoooooooOO / iIii1I11I1II1 + I1Ii111
  if 65 - 65: Ii1I
  if 71 - 71: I1Ii111 % I1Ii111 . oO0o + i11iIiiIii - i11iIiiIii
  if 16 - 16: iIii1I11I1II1 / I1IiiI / I1Ii111 - i11iIiiIii . ooOoO0o / OOooOOo
  if 13 - 13: o0oOOo0O0Ooo % O0 - I1Ii111 * OoooooooOO / Oo0Ooo - OoooooooOO
  if 78 - 78: oO0o % OoooooooOO
  if 73 - 73: I1IiiI % ooOoO0o % IiII + i1IIi - OoooooooOO / oO0o
  if 78 - 78: OoooooooOO % oO0o - i11iIiiIii
  if 37 - 37: IiII % Ii1I % i1IIi
  if 23 - 23: ooOoO0o - O0 + i11iIiiIii
  if 98 - 98: OoooooooOO
  if 61 - 61: o0oOOo0O0Ooo . IiII . O0 + OoooooooOO + O0
  if 65 - 65: i1IIi * OOooOOo * OoooooooOO - IiII . iII111i - OoO0O00
  if 71 - 71: Ii1I * OoOoOO00
  if 33 - 33: i1IIi . i1IIi * OoooooooOO % I1Ii111 * o0oOOo0O0Ooo
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
  if 64 - 64: ooOoO0o / ooOoO0o + I1ii11iIi11i * OOooOOo % OOooOOo
  if 87 - 87: OoO0O00 * Oo0Ooo
 def print_map_register ( self ) :
  OoO0o00O0oOOo = lisp_hex_string ( self . xtr_id )
  if 69 - 69: i1IIi . I1IiiI + IiII
  OOooOoO = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 95 - 95: I1IiiI - OOooOOo . Oo0Ooo / O0 + Ii1I
  lprint ( OOooOoO . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # iII111i / Oo0Ooo + I11i . Ii1I
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , OoO0o00O0oOOo , self . site_id ) )
  if 5 - 5: Ii1I - I1Ii111
  if 66 - 66: I11i + I1ii11iIi11i . I1Ii111
  if 35 - 35: I1Ii111 . I11i . I1ii11iIi11i
  if 22 - 22: Oo0Ooo - OoooooooOO
 def encode ( self ) :
  i1IIi1ii1i1ii = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : i1IIi1ii1i1ii |= 0x08000000
  if ( self . lisp_sec_present ) : i1IIi1ii1i1ii |= 0x04000000
  if ( self . xtr_id_present ) : i1IIi1ii1i1ii |= 0x02000000
  if ( self . map_register_refresh ) : i1IIi1ii1i1ii |= 0x1000
  if ( self . use_ttl_for_timeout ) : i1IIi1ii1i1ii |= 0x800
  if ( self . merge_register_requested ) : i1IIi1ii1i1ii |= 0x400
  if ( self . mobile_node ) : i1IIi1ii1i1ii |= 0x200
  if ( self . map_notify_requested ) : i1IIi1ii1i1ii |= 0x100
  if ( self . encryption_key_id != None ) :
   i1IIi1ii1i1ii |= 0x2000
   i1IIi1ii1i1ii |= self . encryption_key_id << 14
   if 48 - 48: iIii1I11I1II1
   if 26 - 26: i11iIiiIii . OOooOOo - O0
   if 73 - 73: I1IiiI
   if 95 - 95: OoO0O00 % OoO0O00 * oO0o - OoO0O00
   if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 14 - 14: i11iIiiIii % OOooOOo * o0oOOo0O0Ooo * OoOoOO00
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 55 - 55: I1Ii111 * OOooOOo * I1Ii111
    if 70 - 70: O0 . Ii1I
    if 33 - 33: OOooOOo * Ii1I
  o0o0ooOOo0oO = struct . pack ( "I" , socket . htonl ( i1IIi1ii1i1ii ) )
  o0o0ooOOo0oO += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 64 - 64: i11iIiiIii . iIii1I11I1II1
  o0o0ooOOo0oO = self . zero_auth ( o0o0ooOOo0oO )
  return ( o0o0ooOOo0oO )
  if 7 - 7: OoOoOO00 % ooOoO0o + OoOoOO00 - OoOoOO00 * i11iIiiIii % OoO0O00
  if 57 - 57: OOooOOo / OoO0O00 + I1ii11iIi11i
 def zero_auth ( self , packet ) :
  IiI1ii1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  Oo0OO0o0oOO0 = ""
  i1II1IiIIi = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   Oo0OO0o0oOO0 = struct . pack ( "QQI" , 0 , 0 , 0 )
   i1II1IiIIi = struct . calcsize ( "QQI" )
   if 70 - 70: OOooOOo / I1ii11iIi11i
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   Oo0OO0o0oOO0 = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   i1II1IiIIi = struct . calcsize ( "QQQQ" )
   if 72 - 72: OoooooooOO + OoooooooOO
  packet = packet [ 0 : IiI1ii1Ii ] + Oo0OO0o0oOO0 + packet [ IiI1ii1Ii + i1II1IiIIi : : ]
  return ( packet )
  if 42 - 42: ooOoO0o / IiII
  if 62 - 62: I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + I1IiiI / II111iiii
 def encode_auth ( self , packet ) :
  IiI1ii1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  i1II1IiIIi = self . auth_len
  Oo0OO0o0oOO0 = self . auth_data
  packet = packet [ 0 : IiI1ii1Ii ] + Oo0OO0o0oOO0 + packet [ IiI1ii1Ii + i1II1IiIIi : : ]
  return ( packet )
  if 91 - 91: I1IiiI % O0 / oO0o * I1Ii111 + Ii1I - i1IIi
  if 71 - 71: OoOoOO00 / IiII / II111iiii * OOooOOo - I1ii11iIi11i - iIii1I11I1II1
 def decode ( self , packet ) :
  iII111I = packet
  Iii1I = "I"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( [ None , None ] )
  if 78 - 78: II111iiii * iIii1I11I1II1 / IiII . I1ii11iIi11i
  i1IIi1ii1i1ii = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  i1IIi1ii1i1ii = socket . ntohl ( i1IIi1ii1i1ii [ 0 ] )
  packet = packet [ IiiiiI : : ]
  if 13 - 13: OoOoOO00 . I1IiiI . o0oOOo0O0Ooo * oO0o / Ii1I
  Iii1I = "QBBH"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( [ None , None ] )
  if 38 - 38: IiII - i1IIi . i11iIiiIii
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  if 28 - 28: I1Ii111 / oO0o . I1ii11iIi11i
  if 83 - 83: I11i
  self . nonce = byte_swap_64 ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( i1IIi1ii1i1ii & 0x08000000 ) else False
  if 36 - 36: iIii1I11I1II1
  self . lisp_sec_present = True if ( i1IIi1ii1i1ii & 0x04000000 ) else False
  self . xtr_id_present = True if ( i1IIi1ii1i1ii & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( i1IIi1ii1i1ii & 0x800 ) else False
  self . map_register_refresh = True if ( i1IIi1ii1i1ii & 0x1000 ) else False
  self . merge_register_requested = True if ( i1IIi1ii1i1ii & 0x400 ) else False
  self . mobile_node = True if ( i1IIi1ii1i1ii & 0x200 ) else False
  self . map_notify_requested = True if ( i1IIi1ii1i1ii & 0x100 ) else False
  self . record_count = i1IIi1ii1i1ii & 0xff
  if 74 - 74: IiII * I1ii11iIi11i - OoooooooOO
  if 59 - 59: ooOoO0o * OoO0O00 - I1Ii111 % oO0o
  if 95 - 95: II111iiii + II111iiii
  if 33 - 33: i1IIi . Oo0Ooo - IiII
  self . encrypt_bit = True if i1IIi1ii1i1ii & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( i1IIi1ii1i1ii >> 14 ) & 0x7
   if 30 - 30: OoooooooOO % OOooOOo
   if 14 - 14: OoOoOO00 / OoO0O00 / i11iIiiIii - OoOoOO00 / o0oOOo0O0Ooo - OOooOOo
   if 81 - 81: iII111i % Ii1I . ooOoO0o
   if 66 - 66: I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
   if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( iII111I ) == False ) : return ( [ None , None ] )
   if 82 - 82: Oo0Ooo / Ii1I / Ii1I % Ii1I
   if 20 - 20: ooOoO0o
  packet = packet [ IiiiiI : : ]
  if 63 - 63: iIii1I11I1II1 . OoO0O00
  if 100 - 100: i1IIi * i1IIi
  if 26 - 26: OOooOOo . OoO0O00 % OoOoOO00
  if 94 - 94: IiII
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 15 - 15: Ii1I - IiII / O0
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 28 - 28: I1Ii111 . i1IIi / I1ii11iIi11i
    if 77 - 77: i11iIiiIii / I1Ii111 / i11iIiiIii % OoOoOO00 - I1Ii111
   i1II1IiIIi = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    IiiiiI = struct . calcsize ( "QQI" )
    if ( i1II1IiIIi < IiiiiI ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 80 - 80: I1Ii111 % OoOoOO00 . OoooooooOO . II111iiii % IiII
    I1i1I1i1I1 , i1IOO , Oo0OO0ooO0O0O = struct . unpack ( "QQI" , packet [ : i1II1IiIIi ] )
    oO00O = ""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    IiiiiI = struct . calcsize ( "QQQQ" )
    if ( i1II1IiIIi < IiiiiI ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 63 - 63: O0 % iIii1I11I1II1 / O0
    I1i1I1i1I1 , i1IOO , Oo0OO0ooO0O0O , oO00O = struct . unpack ( "QQQQ" ,
 packet [ : i1II1IiIIi ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 5 - 5: i11iIiiIii * ooOoO0o % iII111i - I11i
    return ( [ None , None ] )
    if 5 - 5: O0 * IiII * OOooOOo + I1Ii111 % Oo0Ooo - I1ii11iIi11i
   self . auth_data = lisp_concat_auth_data ( self . alg_id , I1i1I1i1I1 , i1IOO ,
 Oo0OO0ooO0O0O , oO00O )
   iII111I = self . zero_auth ( iII111I )
   packet = packet [ self . auth_len : : ]
   if 62 - 62: I1ii11iIi11i + I11i
  return ( [ iII111I , packet ] )
  if 90 - 90: iIii1I11I1II1
  if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
 def encode_xtr_id ( self , packet ) :
  oO000oOo0oO0 = self . xtr_id >> 64
  IIIiiii1 = self . xtr_id & 0xffffffffffffffff
  oO000oOo0oO0 = byte_swap_64 ( oO000oOo0oO0 )
  IIIiiii1 = byte_swap_64 ( IIIiiii1 )
  oOO0o0OO = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , oO000oOo0oO0 , IIIiiii1 , oOO0o0OO )
  return ( packet )
  if 91 - 91: i1IIi - I1ii11iIi11i * I1IiiI
  if 24 - 24: OoOoOO00 * Ii1I
 def decode_xtr_id ( self , packet ) :
  IiiiiI = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < IiiiiI ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - IiiiiI : : ]
  oO000oOo0oO0 , IIIiiii1 , oOO0o0OO = struct . unpack ( "QQQ" ,
 packet [ : IiiiiI ] )
  oO000oOo0oO0 = byte_swap_64 ( oO000oOo0oO0 )
  IIIiiii1 = byte_swap_64 ( IIIiiii1 )
  self . xtr_id = ( oO000oOo0oO0 << 64 ) | IIIiiii1
  self . site_id = byte_swap_64 ( oOO0o0OO )
  return ( True )
  if 17 - 17: OoO0O00 . I1IiiI * O0
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
  if 86 - 86: II111iiii - OoooooooOO - ooOoO0o % iII111i
  if 16 - 16: ooOoO0o + Oo0Ooo + OoooooooOO
 def print_notify ( self ) :
  Oo0OO0o0oOO0 = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( Oo0OO0o0oOO0 ) != 40 ) :
   Oo0OO0o0oOO0 = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( Oo0OO0o0oOO0 ) != 64 ) :
   Oo0OO0o0oOO0 = self . auth_data
   if 87 - 87: I1IiiI . oO0o / IiII - OoooooooOO
  OOooOoO = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( OOooOoO . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # OOooOOo - oO0o
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , Oo0OO0o0oOO0 ) )
  if 1 - 1: iIii1I11I1II1 / i11iIiiIii * II111iiii
  if 48 - 48: I1ii11iIi11i + O0 * oO0o + I1ii11iIi11i + I1ii11iIi11i
  if 60 - 60: II111iiii % Oo0Ooo
  if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   Oo0OO0o0oOO0 = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 47 - 47: I1Ii111 + I1IiiI
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   Oo0OO0o0oOO0 = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 40 - 40: iIii1I11I1II1 % Ii1I + II111iiii - I1IiiI
  packet += Oo0OO0o0oOO0
  return ( packet )
  if 80 - 80: oO0o
  if 81 - 81: OoooooooOO / ooOoO0o * iIii1I11I1II1 . Oo0Ooo + oO0o / O0
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   i1IIi1ii1i1ii = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   i1IIi1ii1i1ii = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 84 - 84: II111iiii - o0oOOo0O0Ooo
  o0o0ooOOo0oO = struct . pack ( "I" , socket . htonl ( i1IIi1ii1i1ii ) )
  o0o0ooOOo0oO += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 78 - 78: IiII
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = o0o0ooOOo0oO + eid_records
   return ( self . packet )
   if 58 - 58: i11iIiiIii - OoOoOO00
   if 67 - 67: I1ii11iIi11i / iII111i + iIii1I11I1II1 % I1IiiI
   if 99 - 99: ooOoO0o . Ii1I
   if 92 - 92: i1IIi
   if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
  o0o0ooOOo0oO = self . zero_auth ( o0o0ooOOo0oO )
  o0o0ooOOo0oO += eid_records
  if 30 - 30: OoooooooOO % o0oOOo0O0Ooo + ooOoO0o * OoO0O00
  iIIi111I1i1i = lisp_hash_me ( o0o0ooOOo0oO , self . alg_id , password , False )
  if 57 - 57: I11i + iIii1I11I1II1 . OoO0O00 + oO0o
  IiI1ii1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  i1II1IiIIi = self . auth_len
  self . auth_data = iIIi111I1i1i
  o0o0ooOOo0oO = o0o0ooOOo0oO [ 0 : IiI1ii1Ii ] + iIIi111I1i1i + o0o0ooOOo0oO [ IiI1ii1Ii + i1II1IiIIi : : ]
  self . packet = o0o0ooOOo0oO
  return ( o0o0ooOOo0oO )
  if 4 - 4: Ii1I
  if 43 - 43: i1IIi . I1IiiI * iIii1I11I1II1 * i11iIiiIii - OOooOOo + ooOoO0o
 def decode ( self , packet ) :
  iII111I = packet
  Iii1I = "I"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 56 - 56: Oo0Ooo % i11iIiiIii / Ii1I . I1Ii111 . OoO0O00 - OoOoOO00
  i1IIi1ii1i1ii = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  i1IIi1ii1i1ii = socket . ntohl ( i1IIi1ii1i1ii [ 0 ] )
  self . map_notify_ack = ( ( i1IIi1ii1i1ii >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = i1IIi1ii1i1ii & 0xff
  packet = packet [ IiiiiI : : ]
  if 32 - 32: I1Ii111 / oO0o / I1IiiI
  Iii1I = "QBBH"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 22 - 22: OoO0O00 - OoOoOO00 . Oo0Ooo + o0oOOo0O0Ooo
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  if 69 - 69: oO0o - I1IiiI
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ IiiiiI : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 10 - 10: i1IIi / iII111i . II111iiii * i1IIi % OoooooooOO
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 83 - 83: I11i . OOooOOo + I1Ii111 * I11i . I1Ii111 + oO0o
  if 64 - 64: Ii1I . o0oOOo0O0Ooo - i1IIi
  if 35 - 35: I1ii11iIi11i % OoooooooOO
  if 59 - 59: I1IiiI % I11i
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 32 - 32: I1IiiI * O0 + O0
  i1II1IiIIi = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   I1i1I1i1I1 , i1IOO , Oo0OO0ooO0O0O = struct . unpack ( "QQI" , packet [ : i1II1IiIIi ] )
   oO00O = ""
   if 34 - 34: IiII
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   I1i1I1i1I1 , i1IOO , Oo0OO0ooO0O0O , oO00O = struct . unpack ( "QQQQ" ,
 packet [ : i1II1IiIIi ] )
   if 5 - 5: OoO0O00 . I1IiiI
  self . auth_data = lisp_concat_auth_data ( self . alg_id , I1i1I1i1I1 , i1IOO ,
 Oo0OO0ooO0O0O , oO00O )
  if 48 - 48: Oo0Ooo - OoO0O00 . I11i - iIii1I11I1II1 % Ii1I
  IiiiiI = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( iII111I [ : IiiiiI ] )
  IiiiiI += i1II1IiIIi
  packet += iII111I [ IiiiiI : : ]
  return ( packet )
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
  if 7 - 7: OoO0O00 - ooOoO0o % i1IIi
  if 24 - 24: OoO0O00 % O0 % I11i
  if 61 - 61: ooOoO0o . iII111i / ooOoO0o * OoooooooOO
  if 13 - 13: II111iiii
  if 17 - 17: II111iiii
  if 66 - 66: IiII * oO0o
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
  if 73 - 73: i11iIiiIii + O0 % O0
  if 70 - 70: II111iiii * OoooooooOO - Ii1I + oO0o * O0
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 49 - 49: oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 74 - 74: ooOoO0o % I1ii11iIi11i * i1IIi
  if 18 - 18: OoOoOO00
 def print_map_request ( self ) :
  OoO0o00O0oOOo = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   OoO0o00O0oOOo = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 30 - 30: II111iiii
   if 27 - 27: i1IIi - iIii1I11I1II1 + O0 % Oo0Ooo / OOooOOo + i1IIi
   if 48 - 48: Oo0Ooo
  OOooOoO = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 70 - 70: OoooooooOO * i11iIiiIii
  lprint ( OOooOoO . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # i1IIi % OoO0O00 * I1ii11iIi11i . OoooooooOO
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , OoO0o00O0oOOo ) )
  if 96 - 96: OoOoOO00 . i11iIiiIii - i1IIi . I1IiiI
  IiI11I1iiii1 = self . keys
  for OO in self . itr_rlocs :
   if ( OO . afi == LISP_AFI_LCAF and self . json_telemetry != None ) :
    continue
    if 62 - 62: Ii1I
   iiI = red ( OO . print_address_no_iid ( ) , False )
   lprint ( "  itr-rloc: afi {} {}{}" . format ( OO . afi , iiI ,
 "" if ( IiI11I1iiii1 == None ) else ", " + IiI11I1iiii1 [ 1 ] . print_keys ( ) ) )
   IiI11I1iiii1 = None
   if 39 - 39: o0oOOo0O0Ooo
  if ( self . json_telemetry != None ) :
   lprint ( "  itr-rloc: afi {} telemetry: {}" . format ( LISP_AFI_LCAF ,
 self . json_telemetry ) )
   if 89 - 89: OoooooooOO + iII111i . I1Ii111 / Ii1I
   if 75 - 75: iIii1I11I1II1 * iII111i / OoOoOO00 * II111iiii . i1IIi
   if 6 - 6: Ii1I % Ii1I / OoooooooOO * oO0o . I1IiiI . i1IIi
 def sign_map_request ( self , privkey ) :
  O00 = self . signature_eid . print_address ( )
  O00Oo = self . source_eid . print_address ( )
  oOOo = self . target_eid . print_address ( )
  oOO0 = lisp_hex_string ( self . nonce ) + O00Oo + oOOo
  self . map_request_signature = privkey . sign ( oOO0 )
  IIIiiiIi1I1 = binascii . b2a_base64 ( self . map_request_signature )
  IIIiiiIi1I1 = { "source-eid" : O00Oo , "signature-eid" : O00 ,
 "signature" : IIIiiiIi1I1 }
  return ( json . dumps ( IIIiiiIi1I1 ) )
  if 10 - 10: OoO0O00 - II111iiii % o0oOOo0O0Ooo - OoOoOO00 + OoO0O00
  if 88 - 88: iIii1I11I1II1 % ooOoO0o + o0oOOo0O0Ooo * OoOoOO00 / I11i . OoO0O00
 def verify_map_request_sig ( self , pubkey ) :
  Oooo0oOoO0000 = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( Oooo0oOoO0000 ) )
   return ( False )
   if 95 - 95: I11i - iIii1I11I1II1
   if 20 - 20: o0oOOo0O0Ooo / o0oOOo0O0Ooo
  O00Oo = self . source_eid . print_address ( )
  oOOo = self . target_eid . print_address ( )
  oOO0 = lisp_hex_string ( self . nonce ) + O00Oo + oOOo
  pubkey = binascii . a2b_base64 ( pubkey )
  if 28 - 28: OoooooooOO . ooOoO0o / II111iiii + I11i / O0 . OoooooooOO
  ooo0oooooOoo0 = True
  try :
   OO0Oo00o0o0 = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 41 - 41: i11iIiiIii . o0oOOo0O0Ooo
   ooo0oooooOoo0 = False
   if 58 - 58: iIii1I11I1II1 * Ii1I . ooOoO0o . Oo0Ooo * Ii1I
   if 63 - 63: OoOoOO00 . I11i * o0oOOo0O0Ooo - I11i % I11i
  if ( ooo0oooooOoo0 ) :
   try :
    ooo0oooooOoo0 = OO0Oo00o0o0 . verify ( self . map_request_signature , oOO0 )
   except :
    ooo0oooooOoo0 = False
    if 62 - 62: I11i - ooOoO0o / ooOoO0o
    if 95 - 95: OoOoOO00 - i1IIi / I1Ii111 . ooOoO0o % OOooOOo - i1IIi
    if 12 - 12: iII111i
  o0oOoO00o = bold ( "passed" if ooo0oooooOoo0 else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( o0oOoO00o , Oooo0oOoO0000 ) )
  return ( ooo0oooooOoo0 )
  if 98 - 98: iII111i / i11iIiiIii
  if 37 - 37: OoO0O00 / i11iIiiIii
 def encode_json ( self , json_string ) :
  iIiI1 = LISP_LCAF_JSON_TYPE
  IiI11Iiii = socket . htons ( LISP_AFI_LCAF )
  I11IiI1III = socket . htons ( len ( json_string ) + 4 )
  O0o = socket . htons ( len ( json_string ) )
  o0o0ooOOo0oO = struct . pack ( "HBBBBHH" , IiI11Iiii , 0 , 0 , iIiI1 , 0 , I11IiI1III ,
 O0o )
  o0o0ooOOo0oO += json_string
  o0o0ooOOo0oO += struct . pack ( "H" , 0 )
  return ( o0o0ooOOo0oO )
  if 54 - 54: II111iiii . iIii1I11I1II1 / I1Ii111 / oO0o
  if 20 - 20: i1IIi * ooOoO0o
 def encode ( self , probe_dest , probe_port ) :
  i1IIi1ii1i1ii = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  if 2 - 2: O0 . Ii1I
  OO00O = lisp_telemetry_configured ( ) if ( self . rloc_probe ) else None
  if ( OO00O != None ) : self . itr_rloc_count += 1
  i1IIi1ii1i1ii = i1IIi1ii1i1ii | ( self . itr_rloc_count << 8 )
  if 79 - 79: i11iIiiIii + IiII - i11iIiiIii . OoooooooOO + OoO0O00 . i11iIiiIii
  if ( self . auth_bit ) : i1IIi1ii1i1ii |= 0x08000000
  if ( self . map_data_present ) : i1IIi1ii1i1ii |= 0x04000000
  if ( self . rloc_probe ) : i1IIi1ii1i1ii |= 0x02000000
  if ( self . smr_bit ) : i1IIi1ii1i1ii |= 0x01000000
  if ( self . pitr_bit ) : i1IIi1ii1i1ii |= 0x00800000
  if ( self . smr_invoked_bit ) : i1IIi1ii1i1ii |= 0x00400000
  if ( self . mobile_node ) : i1IIi1ii1i1ii |= 0x00200000
  if ( self . xtr_id_present ) : i1IIi1ii1i1ii |= 0x00100000
  if ( self . local_xtr ) : i1IIi1ii1i1ii |= 0x00004000
  if ( self . dont_reply_bit ) : i1IIi1ii1i1ii |= 0x00002000
  if 9 - 9: OoOoOO00 - I11i . OoooooooOO % ooOoO0o
  o0o0ooOOo0oO = struct . pack ( "I" , socket . htonl ( i1IIi1ii1i1ii ) )
  o0o0ooOOo0oO += struct . pack ( "Q" , self . nonce )
  if 13 - 13: OoO0O00 * iIii1I11I1II1 + II111iiii - Oo0Ooo - OoOoOO00
  if 43 - 43: iII111i / I1Ii111 * I1IiiI % ooOoO0o % I1IiiI
  if 18 - 18: OoO0O00
  if 99 - 99: iII111i / oO0o . i11iIiiIii / I11i + i1IIi - I11i
  if 50 - 50: i1IIi
  if 56 - 56: OoO0O00 + I1Ii111 / Ii1I
  o0O0O00 = False
  iIii11II11 = self . privkey_filename
  if ( iIii11II11 != None and os . path . exists ( iIii11II11 ) ) :
   III1I = open ( iIii11II11 , "r" ) ; OO0Oo00o0o0 = III1I . read ( ) ; III1I . close ( )
   try :
    OO0Oo00o0o0 = ecdsa . SigningKey . from_pem ( OO0Oo00o0o0 )
   except :
    return ( None )
    if 58 - 58: i11iIiiIii + iIii1I11I1II1 * o0oOOo0O0Ooo - OoOoOO00
   i11i = self . sign_map_request ( OO0Oo00o0o0 )
   o0O0O00 = True
  elif ( self . map_request_signature != None ) :
   IIIiiiIi1I1 = binascii . b2a_base64 ( self . map_request_signature )
   i11i = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : IIIiiiIi1I1 }
   i11i = json . dumps ( i11i )
   o0O0O00 = True
   if 31 - 31: Oo0Ooo % iIii1I11I1II1 . O0
  if ( o0O0O00 ) :
   o0o0ooOOo0oO += self . encode_json ( i11i )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    o0o0ooOOo0oO += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    o0o0ooOOo0oO += self . source_eid . lcaf_encode_iid ( )
   else :
    o0o0ooOOo0oO += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    o0o0ooOOo0oO += self . source_eid . pack_address ( )
    if 80 - 80: I11i / Oo0Ooo + I1ii11iIi11i
    if 18 - 18: II111iiii - iII111i / iIii1I11I1II1 % OoOoOO00 % I1ii11iIi11i / o0oOOo0O0Ooo
    if 47 - 47: OOooOOo
    if 24 - 24: Ii1I % o0oOOo0O0Ooo
    if 87 - 87: o0oOOo0O0Ooo % iII111i / ooOoO0o - IiII + i11iIiiIii
    if 85 - 85: OoooooooOO * IiII . OOooOOo / iII111i / OoooooooOO
    if 87 - 87: OoO0O00
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   O0O0 = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 32 - 32: i11iIiiIii - OoOoOO00 * I11i . Oo0Ooo * ooOoO0o
   if ( lisp_crypto_keys_by_rloc_encap . has_key ( O0O0 ) ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ O0O0 ]
    if 21 - 21: OOooOOo
    if 11 - 11: oO0o % i11iIiiIii * O0
    if 28 - 28: I1Ii111 / iIii1I11I1II1 + OOooOOo . I1ii11iIi11i % OOooOOo + OoO0O00
    if 79 - 79: oO0o
    if 39 - 39: I1Ii111 % oO0o % O0 % O0 - iII111i - oO0o
    if 83 - 83: i11iIiiIii + iIii1I11I1II1
    if 21 - 21: o0oOOo0O0Ooo / i11iIiiIii % I1Ii111
  for OO in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( OO ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     IiI11I1iiii1 = lisp_keys ( 1 )
     self . keys = [ None , IiI11I1iiii1 , None , None ]
     if 56 - 56: o0oOOo0O0Ooo * iIii1I11I1II1 . Ii1I + OoOoOO00 % I1Ii111
    IiI11I1iiii1 = self . keys [ 1 ]
    IiI11I1iiii1 . add_key_by_nonce ( self . nonce )
    o0o0ooOOo0oO += IiI11I1iiii1 . encode_lcaf ( OO )
   else :
    o0o0ooOOo0oO += struct . pack ( "H" , socket . htons ( OO . afi ) )
    o0o0ooOOo0oO += OO . pack_address ( )
    if 11 - 11: OOooOOo
    if 12 - 12: OoooooooOO * OOooOOo * I1ii11iIi11i * ooOoO0o
    if 26 - 26: OoooooooOO . i1IIi + OoO0O00
    if 42 - 42: i11iIiiIii * o0oOOo0O0Ooo % I11i % Oo0Ooo + o0oOOo0O0Ooo * i11iIiiIii
    if 66 - 66: Ii1I / IiII . OoooooooOO * Oo0Ooo % i11iIiiIii
    if 100 - 100: I1ii11iIi11i % II111iiii * i11iIiiIii - iII111i
  if ( OO00O != None ) :
   ii1III11 = str ( time . time ( ) )
   OO00O = lisp_encode_telemetry ( OO00O , io = ii1III11 )
   self . json_telemetry = OO00O
   o0o0ooOOo0oO += self . encode_json ( OO00O )
   if 69 - 69: OOooOOo + iII111i / I1Ii111
   if 37 - 37: iIii1I11I1II1 * I11i / IiII * Oo0Ooo % i11iIiiIii
  o00O00 = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 16 - 16: OOooOOo % IiII - II111iiii - o0oOOo0O0Ooo * i11iIiiIii / I1Ii111
  if 74 - 74: iII111i % i1IIi / Oo0Ooo . O0
  iIIi1i111iI = 0
  if ( self . subscribe_bit ) :
   iIIi1i111iI = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 10 - 10: IiII % II111iiii
    if 50 - 50: OoOoOO00 * iII111i
    if 59 - 59: I1IiiI * I1IiiI / I11i
  Iii1I = "BB"
  o0o0ooOOo0oO += struct . pack ( Iii1I , iIIi1i111iI , o00O00 )
  if 92 - 92: o0oOOo0O0Ooo
  if ( self . target_group . is_null ( ) == False ) :
   o0o0ooOOo0oO += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   o0o0ooOOo0oO += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   o0o0ooOOo0oO += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   o0o0ooOOo0oO += self . target_eid . lcaf_encode_iid ( )
  else :
   o0o0ooOOo0oO += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   o0o0ooOOo0oO += self . target_eid . pack_address ( )
   if 8 - 8: iII111i + I1ii11iIi11i . Ii1I
   if 50 - 50: Oo0Ooo
   if 16 - 16: Ii1I - OoOoOO00 % Oo0Ooo / Ii1I . I11i + ooOoO0o
   if 78 - 78: iIii1I11I1II1 + OoO0O00 + i11iIiiIii
   if 21 - 21: Oo0Ooo + Ii1I % ooOoO0o + OoOoOO00 % I11i
  if ( self . subscribe_bit ) : o0o0ooOOo0oO = self . encode_xtr_id ( o0o0ooOOo0oO )
  return ( o0o0ooOOo0oO )
  if 22 - 22: i1IIi / OoooooooOO . OoO0O00
  if 83 - 83: I1IiiI - OoooooooOO + I1ii11iIi11i . Ii1I / o0oOOo0O0Ooo + ooOoO0o
 def lcaf_decode_json ( self , packet ) :
  Iii1I = "BBBBHH"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 90 - 90: I1IiiI - i11iIiiIii
  iIii1iI11 , iIiOOO0oo0OO0o0 , iIiI1 , OOoO0 , I11IiI1III , O0o = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  if 78 - 78: I11i - I1IiiI * IiII
  if 43 - 43: OoooooooOO . OOooOOo
  if ( iIiI1 != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 33 - 33: o0oOOo0O0Ooo % OoOoOO00 * I1IiiI
  if 26 - 26: I11i . iII111i . o0oOOo0O0Ooo
  if 15 - 15: OoO0O00 / iII111i
  if 46 - 46: OoooooooOO . I1Ii111
  I11IiI1III = socket . ntohs ( I11IiI1III )
  O0o = socket . ntohs ( O0o )
  packet = packet [ IiiiiI : : ]
  if ( len ( packet ) < I11IiI1III ) : return ( None )
  if ( I11IiI1III != O0o + 2 ) : return ( None )
  if 15 - 15: Ii1I
  if 84 - 84: OoOoOO00 - ooOoO0o - OoooooooOO . OoooooooOO % IiII
  if 38 - 38: OoO0O00 * I1ii11iIi11i
  if 4 - 4: OoO0O00 . I1ii11iIi11i
  i11i = packet [ 0 : O0o ]
  packet = packet [ O0o : : ]
  if 21 - 21: i11iIiiIii / OoO0O00 / I1ii11iIi11i * O0 - II111iiii * OOooOOo
  if 27 - 27: o0oOOo0O0Ooo . OoOoOO00 * Ii1I * iII111i * O0
  if 93 - 93: IiII % I1Ii111 % II111iiii
  if 20 - 20: OoooooooOO * I1Ii111
  if ( lisp_is_json_telemetry ( i11i ) != None ) :
   self . json_telemetry = i11i
   if 38 - 38: iII111i . OoooooooOO
   if 28 - 28: I1Ii111 * i1IIi . I1ii11iIi11i
   if 75 - 75: O0 / oO0o * ooOoO0o - OOooOOo / i1IIi
   if 61 - 61: I11i
   if 100 - 100: O0 - iIii1I11I1II1 * Oo0Ooo
  Iii1I = "H"
  IiiiiI = struct . calcsize ( Iii1I )
  i1I1iiiI = struct . unpack ( Iii1I , packet [ : IiiiiI ] ) [ 0 ]
  packet = packet [ IiiiiI : : ]
  if ( i1I1iiiI != 0 ) : return ( packet )
  if 35 - 35: ooOoO0o
  if ( self . json_telemetry != None ) : return ( packet )
  if 57 - 57: OoO0O00 . Oo0Ooo + I1IiiI
  if 18 - 18: I1IiiI - I1ii11iIi11i * I11i / i11iIiiIii - o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 31 - 31: I11i
  if 100 - 100: i11iIiiIii * i11iIiiIii . iIii1I11I1II1 % iII111i * I1ii11iIi11i
  try :
   i11i = json . loads ( i11i )
  except :
   return ( None )
   if 17 - 17: Ii1I * IiII * i11iIiiIii / I1ii11iIi11i / i11iIiiIii
   if 23 - 23: OoooooooOO + i11iIiiIii / Oo0Ooo / iII111i . iII111i * I1IiiI
   if 98 - 98: IiII
   if 23 - 23: I11i / i1IIi * OoO0O00
   if 51 - 51: OOooOOo - OoooooooOO / OoooooooOO % OoooooooOO
  if ( i11i . has_key ( "source-eid" ) == False ) : return ( packet )
  oOooOOo000o0o = i11i [ "source-eid" ]
  i1I1iiiI = LISP_AFI_IPV4 if oOooOOo000o0o . count ( "." ) == 3 else LISP_AFI_IPV6 if oOooOOo000o0o . count ( ":" ) == 7 else None
  if 79 - 79: I1Ii111 + oO0o - iIii1I11I1II1 * OoOoOO00 / OoooooooOO
  if ( i1I1iiiI == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( oOooOOo000o0o ) )
   return ( None )
   if 49 - 49: OoooooooOO + I1Ii111
   if 39 - 39: oO0o * I1Ii111 - ooOoO0o + O0
  self . source_eid . afi = i1I1iiiI
  self . source_eid . store_address ( oOooOOo000o0o )
  if 14 - 14: i1IIi . i1IIi + OoO0O00
  if ( i11i . has_key ( "signature-eid" ) == False ) : return ( packet )
  oOooOOo000o0o = i11i [ "signature-eid" ]
  if ( oOooOOo000o0o . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( oOooOOo000o0o ) )
   return ( None )
   if 95 - 95: I1IiiI / o0oOOo0O0Ooo % II111iiii * I1Ii111 . IiII % OoO0O00
   if 45 - 45: I1ii11iIi11i . I11i . II111iiii - II111iiii * OoooooooOO
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( oOooOOo000o0o )
  if 71 - 71: OOooOOo
  if ( i11i . has_key ( "signature" ) == False ) : return ( packet )
  IIIiiiIi1I1 = binascii . a2b_base64 ( i11i [ "signature" ] )
  self . map_request_signature = IIIiiiIi1I1
  return ( packet )
  if 87 - 87: II111iiii / iIii1I11I1II1 % I1ii11iIi11i
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00
 def decode ( self , packet , source , port ) :
  Iii1I = "I"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 92 - 92: OoOoOO00 . Oo0Ooo * I11i
  i1IIi1ii1i1ii = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  i1IIi1ii1i1ii = i1IIi1ii1i1ii [ 0 ]
  packet = packet [ IiiiiI : : ]
  if 86 - 86: O0
  Iii1I = "Q"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 55 - 55: Ii1I / I1Ii111 / I1ii11iIi11i % ooOoO0o % I1IiiI
  O0oo00o000 = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  packet = packet [ IiiiiI : : ]
  if 55 - 55: oO0o + OoooooooOO % i1IIi
  i1IIi1ii1i1ii = socket . ntohl ( i1IIi1ii1i1ii )
  self . auth_bit = True if ( i1IIi1ii1i1ii & 0x08000000 ) else False
  self . map_data_present = True if ( i1IIi1ii1i1ii & 0x04000000 ) else False
  self . rloc_probe = True if ( i1IIi1ii1i1ii & 0x02000000 ) else False
  self . smr_bit = True if ( i1IIi1ii1i1ii & 0x01000000 ) else False
  self . pitr_bit = True if ( i1IIi1ii1i1ii & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( i1IIi1ii1i1ii & 0x00400000 ) else False
  self . mobile_node = True if ( i1IIi1ii1i1ii & 0x00200000 ) else False
  self . xtr_id_present = True if ( i1IIi1ii1i1ii & 0x00100000 ) else False
  self . local_xtr = True if ( i1IIi1ii1i1ii & 0x00004000 ) else False
  self . dont_reply_bit = True if ( i1IIi1ii1i1ii & 0x00002000 ) else False
  self . itr_rloc_count = ( ( i1IIi1ii1i1ii >> 8 ) & 0x1f )
  self . record_count = i1IIi1ii1i1ii & 0xff
  self . nonce = O0oo00o000 [ 0 ]
  if 24 - 24: I1ii11iIi11i - Oo0Ooo
  if 36 - 36: I1IiiI . OOooOOo % II111iiii * IiII
  if 34 - 34: I11i % iII111i - ooOoO0o - I1IiiI
  if 44 - 44: Ii1I . o0oOOo0O0Ooo . iIii1I11I1II1 + OoooooooOO - I1IiiI
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 22 - 22: I11i * I1ii11iIi11i . OoooooooOO / Oo0Ooo / Ii1I
   if 54 - 54: I1Ii111 % Ii1I + ooOoO0o
  IiiiiI = struct . calcsize ( "H" )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 45 - 45: Ii1I / oO0o * I1Ii111 . Ii1I
  i1I1iiiI = struct . unpack ( "H" , packet [ : IiiiiI ] )
  self . source_eid . afi = socket . ntohs ( i1I1iiiI [ 0 ] )
  packet = packet [ IiiiiI : : ]
  if 25 - 25: I1ii11iIi11i / I1ii11iIi11i
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   OO0OoOo0O = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( OO0OoOo0O )
    if ( packet == None ) : return ( None )
    if 84 - 84: OoooooooOO + iII111i . i11iIiiIii - O0 / O0 % i1IIi
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 38 - 38: iIii1I11I1II1 - II111iiii
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 47 - 47: I1ii11iIi11i
  i1ooOO000 = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  IIiI1iIiiii1 = self . itr_rloc_count + 1
  if 66 - 66: i1IIi % OoooooooOO * i11iIiiIii + oO0o * O0 / OoO0O00
  while ( IIiI1iIiiii1 != 0 ) :
   IiiiiI = struct . calcsize ( "H" )
   if ( len ( packet ) < IiiiiI ) : return ( None )
   if 14 - 14: I1IiiI . IiII
   i1I1iiiI = socket . ntohs ( struct . unpack ( "H" , packet [ : IiiiiI ] ) [ 0 ] )
   OO = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   OO . afi = i1I1iiiI
   if 29 - 29: OoooooooOO / IiII + OoOoOO00 - I1Ii111 + IiII . i1IIi
   if 26 - 26: i11iIiiIii - II111iiii
   if 43 - 43: I1IiiI
   if 35 - 35: ooOoO0o + OoOoOO00 * OoooooooOO - II111iiii
   if 19 - 19: i1IIi / Ii1I / OoOoOO00 . I1IiiI / Ii1I % o0oOOo0O0Ooo
   if ( OO . afi == LISP_AFI_LCAF ) :
    iII111I = packet
    i1i11Ii1 = packet [ IiiiiI : : ]
    packet = self . lcaf_decode_json ( i1i11Ii1 )
    if ( packet == i1i11Ii1 ) : packet = iII111I
    if 14 - 14: OOooOOo . o0oOOo0O0Ooo / II111iiii % OOooOOo
    if 98 - 98: I1IiiI
    if 51 - 51: OoOoOO00 * OoooooooOO * Oo0Ooo
    if 28 - 28: i11iIiiIii - Ii1I
    if 59 - 59: II111iiii - OoO0O00
    if 31 - 31: I11i - OoOoOO00 / o0oOOo0O0Ooo * OoOoOO00 / Oo0Ooo + o0oOOo0O0Ooo
   if ( OO . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < OO . addr_length ( ) ) : return ( None )
    packet = OO . unpack_address ( packet [ IiiiiI : : ] )
    if ( packet == None ) : return ( None )
    if 46 - 46: IiII * OoO0O00 / OOooOOo + Oo0Ooo
    if ( i1ooOO000 ) :
     self . itr_rlocs . append ( OO )
     IIiI1iIiiii1 -= 1
     continue
     if 24 - 24: ooOoO0o % OOooOOo . O0 * Oo0Ooo
     if 52 - 52: O0 . I1Ii111 + iII111i / i11iIiiIii
    O0O0 = lisp_build_crypto_decap_lookup_key ( OO , port )
    if 52 - 52: oO0o % Oo0Ooo * II111iiii
    if 24 - 24: i11iIiiIii * i1IIi * i1IIi
    if 27 - 27: i1IIi - oO0o + OOooOOo
    if 3 - 3: IiII % I1Ii111 . OoooooooOO
    if 19 - 19: I1Ii111 * Ii1I - oO0o
    if ( lisp_nat_traversal and OO . is_private_address ( ) and source ) : OO = source
    if 78 - 78: OoO0O00 - Ii1I / OOooOOo
    ooOo000 = lisp_crypto_keys_by_rloc_decap
    if ( ooOo000 . has_key ( O0O0 ) ) : ooOo000 . pop ( O0O0 )
    if 87 - 87: Oo0Ooo + I1IiiI % I1IiiI * i11iIiiIii
    if 68 - 68: iII111i . OOooOOo
    if 6 - 6: Ii1I - o0oOOo0O0Ooo % I11i + i11iIiiIii
    if 40 - 40: O0 . Ii1I
    if 58 - 58: i11iIiiIii * iII111i / Ii1I - oO0o - I1ii11iIi11i % o0oOOo0O0Ooo
    if 16 - 16: OoooooooOO
    lisp_write_ipc_decap_key ( O0O0 , None )
    if 71 - 71: Ii1I % O0 / I1Ii111 % iII111i - II111iiii / OoO0O00
   elif ( self . json_telemetry == None ) :
    if 30 - 30: I11i
    if 60 - 60: ooOoO0o - Ii1I . I1IiiI * oO0o * i11iIiiIii
    if 29 - 29: OoO0O00 - Oo0Ooo . oO0o / OoO0O00 % i11iIiiIii
    if 26 - 26: ooOoO0o . I1Ii111 / II111iiii % Ii1I
    iII111I = packet
    O00o0oO0oO0 = lisp_keys ( 1 )
    packet = O00o0oO0oO0 . decode_lcaf ( iII111I , 0 )
    if 28 - 28: IiII . o0oOOo0O0Ooo
    if ( packet == None ) : return ( None )
    if 87 - 87: iIii1I11I1II1 * II111iiii - I1Ii111 % I1Ii111 - OOooOOo
    if 10 - 10: I1Ii111
    if 78 - 78: O0
    if 60 - 60: oO0o
    OOOo00OOooO = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( O00o0oO0oO0 . cipher_suite in OOOo00OOooO ) :
     if ( O00o0oO0oO0 . cipher_suite == LISP_CS_25519_CBC or
 O00o0oO0oO0 . cipher_suite == LISP_CS_25519_GCM ) :
      OO0Oo00o0o0 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 5 - 5: o0oOOo0O0Ooo / o0oOOo0O0Ooo - ooOoO0o * OoooooooOO . OoooooooOO . I1Ii111
     if ( O00o0oO0oO0 . cipher_suite == LISP_CS_25519_CHACHA ) :
      OO0Oo00o0o0 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 56 - 56: iII111i % I1IiiI * OOooOOo * i11iIiiIii
    else :
     OO0Oo00o0o0 = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 15 - 15: I1IiiI - oO0o - II111iiii + O0
    packet = OO0Oo00o0o0 . decode_lcaf ( iII111I , 0 )
    if ( packet == None ) : return ( None )
    if 54 - 54: iIii1I11I1II1 - IiII - IiII
    if ( len ( packet ) < IiiiiI ) : return ( None )
    i1I1iiiI = struct . unpack ( "H" , packet [ : IiiiiI ] ) [ 0 ]
    OO . afi = socket . ntohs ( i1I1iiiI )
    if ( len ( packet ) < OO . addr_length ( ) ) : return ( None )
    if 18 - 18: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii
    packet = OO . unpack_address ( packet [ IiiiiI : : ] )
    if ( packet == None ) : return ( None )
    if 63 - 63: iII111i - OoO0O00 * OOooOOo
    if ( i1ooOO000 ) :
     self . itr_rlocs . append ( OO )
     IIiI1iIiiii1 -= 1
     continue
     if 89 - 89: iII111i / Oo0Ooo
     if 66 - 66: o0oOOo0O0Ooo + OoOoOO00 % OoooooooOO . I11i
    O0O0 = lisp_build_crypto_decap_lookup_key ( OO , port )
    if 30 - 30: II111iiii - Oo0Ooo - i11iIiiIii + O0
    Ooo0OO0 = None
    if ( lisp_nat_traversal and OO . is_private_address ( ) and source ) : OO = source
    if 71 - 71: Ii1I + i11iIiiIii
    if 92 - 92: iIii1I11I1II1 + Ii1I
    if ( lisp_crypto_keys_by_rloc_decap . has_key ( O0O0 ) ) :
     IiI11I1iiii1 = lisp_crypto_keys_by_rloc_decap [ O0O0 ]
     Ooo0OO0 = IiI11I1iiii1 [ 1 ] if IiI11I1iiii1 and IiI11I1iiii1 [ 1 ] else None
     if 69 - 69: Oo0Ooo
     if 70 - 70: O0 - OoO0O00 - Oo0Ooo
    O00o0OoO0OOOo = True
    if ( Ooo0OO0 ) :
     if ( Ooo0OO0 . compare_keys ( OO0Oo00o0o0 ) ) :
      self . keys = [ None , Ooo0OO0 , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( O0O0 , False ) ) )
      if 72 - 72: ooOoO0o * i11iIiiIii / OoO0O00
     else :
      O00o0OoO0OOOo = False
      IIIiIII111iii = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( IIIiIII111iii , red ( O0O0 ,
 False ) ) )
      OO0Oo00o0o0 . copy_keypair ( Ooo0OO0 )
      OO0Oo00o0o0 . uptime = Ooo0OO0 . uptime
      Ooo0OO0 = None
      if 61 - 61: OoO0O00 . i11iIiiIii - OoO0O00
      if 8 - 8: I1ii11iIi11i * IiII / Oo0Ooo
      if 99 - 99: OOooOOo * I1Ii111 . ooOoO0o - i1IIi - I11i % IiII
    if ( Ooo0OO0 == None ) :
     self . keys = [ None , OO0Oo00o0o0 , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      OO0Oo00o0o0 . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( O0O0 , False ) ) )
     elif ( OO0Oo00o0o0 . remote_public_key != None ) :
      if ( O00o0OoO0OOOo ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # I11i - OoooooooOO + I1Ii111
 red ( O0O0 , False ) ) )
       if 44 - 44: o0oOOo0O0Ooo / i11iIiiIii
      OO0Oo00o0o0 . compute_shared_key ( "decap" )
      OO0Oo00o0o0 . add_key_by_rloc ( O0O0 , False )
      if 95 - 95: iII111i * i1IIi . OoooooooOO - O0 % ooOoO0o
      if 41 - 41: IiII
      if 29 - 29: ooOoO0o
      if 70 - 70: oO0o . O0 % I11i % IiII - I11i * I1ii11iIi11i
   self . itr_rlocs . append ( OO )
   IIiI1iIiiii1 -= 1
   if 22 - 22: i1IIi
   if 82 - 82: oO0o . iIii1I11I1II1 - I1ii11iIi11i
  IiiiiI = struct . calcsize ( "BBH" )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 55 - 55: Oo0Ooo % Ii1I . iIii1I11I1II1 * I1Ii111
  iIIi1i111iI , o00O00 , i1I1iiiI = struct . unpack ( "BBH" , packet [ : IiiiiI ] )
  self . subscribe_bit = ( iIIi1i111iI & 0x80 )
  self . target_eid . afi = socket . ntohs ( i1I1iiiI )
  packet = packet [ IiiiiI : : ]
  if 33 - 33: O0 - I1IiiI / I1ii11iIi11i / OoO0O00 + iII111i - oO0o
  self . target_eid . mask_len = o00O00
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , I1I111 = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( I1I111 ) : self . target_group = I1I111
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ IiiiiI : : ]
   if 98 - 98: ooOoO0o
  return ( packet )
  if 38 - 38: O0 * i1IIi - OoO0O00 * OoO0O00
  if 11 - 11: ooOoO0o - Ii1I . oO0o * Ii1I
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 85 - 85: i1IIi
  if 94 - 94: OoooooooOO . O0 / OoooooooOO
 def encode_xtr_id ( self , packet ) :
  oO000oOo0oO0 = self . xtr_id >> 64
  IIIiiii1 = self . xtr_id & 0xffffffffffffffff
  oO000oOo0oO0 = byte_swap_64 ( oO000oOo0oO0 )
  IIIiiii1 = byte_swap_64 ( IIIiiii1 )
  packet += struct . pack ( "QQ" , oO000oOo0oO0 , IIIiiii1 )
  return ( packet )
  if 67 - 67: i11iIiiIii + OoOoOO00
  if 50 - 50: ooOoO0o . i1IIi + I1ii11iIi11i . OOooOOo
 def decode_xtr_id ( self , packet ) :
  IiiiiI = struct . calcsize ( "QQ" )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  packet = packet [ len ( packet ) - IiiiiI : : ]
  oO000oOo0oO0 , IIIiiii1 = struct . unpack ( "QQ" , packet [ : IiiiiI ] )
  oO000oOo0oO0 = byte_swap_64 ( oO000oOo0oO0 )
  IIIiiii1 = byte_swap_64 ( IIIiiii1 )
  self . xtr_id = ( oO000oOo0oO0 << 64 ) | IIIiiii1
  return ( True )
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
class lisp_map_reply ( ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 97 - 97: I1IiiI / o0oOOo0O0Ooo
  if 13 - 13: I1ii11iIi11i
 def print_map_reply ( self ) :
  OOooOoO = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 72 - 72: Oo0Ooo + IiII / Ii1I * Oo0Ooo
  lprint ( OOooOoO . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # I1ii11iIi11i * iIii1I11I1II1 % OoOoOO00
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 50 - 50: i11iIiiIii + ooOoO0o
  if 41 - 41: I1IiiI * OoO0O00 + IiII / OoO0O00 . I1Ii111
 def encode ( self ) :
  i1IIi1ii1i1ii = ( LISP_MAP_REPLY << 28 ) | self . record_count
  i1IIi1ii1i1ii |= self . hop_count << 8
  if ( self . rloc_probe ) : i1IIi1ii1i1ii |= 0x08000000
  if ( self . echo_nonce_capable ) : i1IIi1ii1i1ii |= 0x04000000
  if ( self . security ) : i1IIi1ii1i1ii |= 0x02000000
  if 2 - 2: O0 % o0oOOo0O0Ooo
  o0o0ooOOo0oO = struct . pack ( "I" , socket . htonl ( i1IIi1ii1i1ii ) )
  o0o0ooOOo0oO += struct . pack ( "Q" , self . nonce )
  return ( o0o0ooOOo0oO )
  if 3 - 3: i11iIiiIii / OOooOOo + oO0o
  if 10 - 10: OoO0O00 . OoO0O00 + O0
 def decode ( self , packet ) :
  Iii1I = "I"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 13 - 13: i1IIi . I1IiiI
  i1IIi1ii1i1ii = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  i1IIi1ii1i1ii = i1IIi1ii1i1ii [ 0 ]
  packet = packet [ IiiiiI : : ]
  if 45 - 45: ooOoO0o % I11i
  Iii1I = "Q"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 37 - 37: iII111i
  O0oo00o000 = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  packet = packet [ IiiiiI : : ]
  if 70 - 70: O0 + iIii1I11I1II1 % O0 * o0oOOo0O0Ooo - Oo0Ooo - ooOoO0o
  i1IIi1ii1i1ii = socket . ntohl ( i1IIi1ii1i1ii )
  self . rloc_probe = True if ( i1IIi1ii1i1ii & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( i1IIi1ii1i1ii & 0x04000000 ) else False
  self . security = True if ( i1IIi1ii1i1ii & 0x02000000 ) else False
  self . hop_count = ( i1IIi1ii1i1ii >> 8 ) & 0xff
  self . record_count = i1IIi1ii1i1ii & 0xff
  self . nonce = O0oo00o000 [ 0 ]
  if 94 - 94: i1IIi + IiII / OoooooooOO - oO0o / OOooOOo / OoOoOO00
  if ( lisp_crypto_keys_by_nonce . has_key ( self . nonce ) ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 55 - 55: OOooOOo
  return ( packet )
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
  if 42 - 42: O0 . I1Ii111 / I11i
  if 69 - 69: OoOoOO00 / I1Ii111 * I1IiiI
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 76 - 76: O0 + II111iiii * OoO0O00
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 1 - 1: o0oOOo0O0Ooo
  if 34 - 34: o0oOOo0O0Ooo + OOooOOo . OoO0O00 + I1IiiI + OoooooooOO
 def print_ttl ( self ) :
  O0OOo = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   O0OOo = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( O0OOo % 60 ) == 0 ) :
   O0OOo = str ( O0OOo / 60 ) + " hours"
  else :
   O0OOo = str ( O0OOo ) + " mins"
   if 15 - 15: o0oOOo0O0Ooo / ooOoO0o * Ii1I . iII111i * I11i * OoOoOO00
  return ( O0OOo )
  if 96 - 96: oO0o . II111iiii % I1Ii111
  if 52 - 52: Ii1I / i11iIiiIii / oO0o
 def store_ttl ( self ) :
  O0OOo = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : O0OOo = self . record_ttl & 0x7fffffff
  return ( O0OOo )
  if 54 - 54: oO0o
  if 88 - 88: OOooOOo / Ii1I . iII111i - OoOoOO00 + iII111i
 def print_record ( self , indent , ddt ) :
  O0OoooO = ""
  iii1I = ""
  o0OOOooo = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    o0OOOooo = lisp_map_referral_action_string [ self . action ]
    o0OOOooo = bold ( o0OOOooo , False )
    O0OoooO = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 34 - 34: i11iIiiIii % OoO0O00 - oO0o / OOooOOo / iII111i
    iii1I = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 5 - 5: I1Ii111 . oO0o
    if 77 - 77: iII111i / i11iIiiIii
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    o0OOOooo = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     o0OOOooo = bold ( o0OOOooo , False )
     if 20 - 20: O0 . I11i
     if 67 - 67: OoOoOO00 - ooOoO0o - iIii1I11I1II1
     if 31 - 31: II111iiii + o0oOOo0O0Ooo * i11iIiiIii . o0oOOo0O0Ooo
     if 73 - 73: oO0o / OOooOOo * II111iiii % OoooooooOO - i1IIi - ooOoO0o
  i1I1iiiI = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  OOooOoO = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 43 - 43: o0oOOo0O0Ooo + Ii1I % OoO0O00 . I1Ii111 + i1IIi
  lprint ( OOooOoO . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 o0OOOooo , "auth" if ( self . authoritative is True ) else "non-auth" ,
 O0OoooO , iii1I , self . map_version , i1I1iiiI ,
 green ( self . print_prefix ( ) , False ) ) )
  if 85 - 85: Oo0Ooo % I1ii11iIi11i / OOooOOo
  if 65 - 65: ooOoO0o + IiII - OoOoOO00 % II111iiii - iIii1I11I1II1
 def encode ( self ) :
  iiIIiI = self . action << 13
  if ( self . authoritative ) : iiIIiI |= 0x1000
  if ( self . ddt_incomplete ) : iiIIiI |= 0x800
  if 16 - 16: I11i
  if 23 - 23: o0oOOo0O0Ooo + ooOoO0o - IiII
  if 23 - 23: i11iIiiIii - Ii1I % iII111i + I11i * oO0o
  if 45 - 45: iII111i - I1ii11iIi11i * O0 % OoO0O00 % I1IiiI
  i1I1iiiI = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( i1I1iiiI < 0 ) : i1I1iiiI = LISP_AFI_LCAF
  I1IIiIiIIiIiI = ( self . group . is_null ( ) == False )
  if ( I1IIiIiIIiIiI ) : i1I1iiiI = LISP_AFI_LCAF
  if 37 - 37: oO0o % iII111i / II111iiii / OoO0O00 - IiII - ooOoO0o
  oO0IIIIi1IiI1I = ( self . signature_count << 12 ) | self . map_version
  o00O00 = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 39 - 39: o0oOOo0O0Ooo % iII111i . OoOoOO00 - I1Ii111
  o0o0ooOOo0oO = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , o00O00 , socket . htons ( iiIIiI ) ,
 socket . htons ( oO0IIIIi1IiI1I ) , socket . htons ( i1I1iiiI ) )
  if 39 - 39: i11iIiiIii * OoOoOO00 . OoOoOO00 . I1ii11iIi11i . Oo0Ooo
  if 61 - 61: I11i / OOooOOo
  if 85 - 85: OoOoOO00 - I11i . OoOoOO00 . OoOoOO00
  if 62 - 62: IiII % OoooooooOO * OoO0O00 + OoO0O00 % Ii1I % iII111i
  if ( I1IIiIiIIiIiI ) :
   o0o0ooOOo0oO += self . eid . lcaf_encode_sg ( self . group )
   return ( o0o0ooOOo0oO )
   if 66 - 66: I1IiiI . OOooOOo - OoO0O00 % Oo0Ooo * o0oOOo0O0Ooo - oO0o
   if 68 - 68: I11i - i11iIiiIii / o0oOOo0O0Ooo + ooOoO0o / I1IiiI
   if 31 - 31: I1Ii111 . OoooooooOO . i1IIi
   if 65 - 65: OoO0O00 . ooOoO0o
   if 12 - 12: I1Ii111 + O0 - oO0o . IiII
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   o0o0ooOOo0oO = o0o0ooOOo0oO [ 0 : - 2 ]
   o0o0ooOOo0oO += self . eid . address . encode_geo ( )
   return ( o0o0ooOOo0oO )
   if 46 - 46: IiII . ooOoO0o / iII111i
   if 63 - 63: II111iiii - I1ii11iIi11i * II111iiii
   if 92 - 92: OoO0O00 % ooOoO0o * O0 % iIii1I11I1II1 / i1IIi / OoOoOO00
   if 67 - 67: I1Ii111 + I11i + I1Ii111 . OOooOOo % o0oOOo0O0Ooo / ooOoO0o
   if 78 - 78: I1ii11iIi11i . O0
  if ( i1I1iiiI == LISP_AFI_LCAF ) :
   o0o0ooOOo0oO += self . eid . lcaf_encode_iid ( )
   return ( o0o0ooOOo0oO )
   if 56 - 56: oO0o - i1IIi * O0 / I11i * I1IiiI . I11i
   if 54 - 54: i11iIiiIii % i1IIi + Oo0Ooo / OoOoOO00
   if 26 - 26: I11i . I1ii11iIi11i
   if 55 - 55: OoOoOO00 * I1Ii111 % OoO0O00 - OoO0O00
   if 34 - 34: O0 * OoO0O00 - oO0o - IiII * Ii1I . II111iiii
  o0o0ooOOo0oO += self . eid . pack_address ( )
  return ( o0o0ooOOo0oO )
  if 28 - 28: O0 % iII111i - i1IIi
  if 49 - 49: ooOoO0o . I11i - iIii1I11I1II1
 def decode ( self , packet ) :
  Iii1I = "IBBHHH"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 41 - 41: ooOoO0o * i11iIiiIii % ooOoO0o . oO0o
  self . record_ttl , self . rloc_count , self . eid . mask_len , iiIIiI , self . map_version , self . eid . afi = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  if 97 - 97: oO0o - iII111i + IiII . OoOoOO00 + iIii1I11I1II1
  if 75 - 75: ooOoO0o + ooOoO0o . I1Ii111 % iII111i / iIii1I11I1II1 * iII111i
  if 13 - 13: II111iiii * i11iIiiIii - i1IIi * OoO0O00 + i1IIi
  self . record_ttl = socket . ntohl ( self . record_ttl )
  iiIIiI = socket . ntohs ( iiIIiI )
  self . action = ( iiIIiI >> 13 ) & 0x7
  self . authoritative = True if ( ( iiIIiI >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( iiIIiI >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ IiiiiI : : ]
  if 43 - 43: O0 % oO0o * I1IiiI
  if 64 - 64: II111iiii + i11iIiiIii
  if 17 - 17: O0 * I1IiiI
  if 40 - 40: iIii1I11I1II1 * iII111i % iIii1I11I1II1
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , iiIoOOOOoo0O00o = self . eid . lcaf_decode_eid ( packet )
   if ( iiIoOOOOoo0O00o ) : self . group = iiIoOOOOoo0O00o
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 5 - 5: Ii1I * iII111i
   if 33 - 33: I1IiiI % I11i . I1Ii111 / Ii1I * II111iiii * o0oOOo0O0Ooo
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 49 - 49: i1IIi * i11iIiiIii
  if 47 - 47: II111iiii / Oo0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 38 - 38: OOooOOo . iII111i / O0 . Ii1I / OoOoOO00
  if 52 - 52: O0 / i11iIiiIii * I1IiiI . i1IIi
  if 50 - 50: OoooooooOO . iII111i % o0oOOo0O0Ooo
  if 6 - 6: ooOoO0o - i1IIi . O0 . i1IIi . OoOoOO00
  if 42 - 42: i11iIiiIii * O0 % i11iIiiIii + OOooOOo
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
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 58 - 58: ooOoO0o
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
  if 98 - 98: Ii1I / OoO0O00 % OoooooooOO
  if 65 - 65: ooOoO0o % Oo0Ooo - I1IiiI % I1Ii111 + iIii1I11I1II1 / iIii1I11I1II1
 def print_ecm ( self ) :
  OOooOoO = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 94 - 94: IiII - Oo0Ooo . o0oOOo0O0Ooo - ooOoO0o - oO0o . I11i
  lprint ( OOooOoO . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 39 - 39: oO0o + OoOoOO00
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 68 - 68: i1IIi * oO0o / i11iIiiIii
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 96 - 96: I1IiiI
   if 78 - 78: OoO0O00
   if 72 - 72: I1ii11iIi11i / O0 % II111iiii / II111iiii
   if 48 - 48: OOooOOo % OOooOOo / iIii1I11I1II1 - i11iIiiIii
   if 57 - 57: I11i / IiII * i1IIi + II111iiii . o0oOOo0O0Ooo
   if 11 - 11: II111iiii
  i1IIi1ii1i1ii = ( LISP_ECM << 28 )
  if ( self . security ) : i1IIi1ii1i1ii |= 0x08000000
  if ( self . ddt ) : i1IIi1ii1i1ii |= 0x04000000
  if ( self . to_etr ) : i1IIi1ii1i1ii |= 0x02000000
  if ( self . to_ms ) : i1IIi1ii1i1ii |= 0x01000000
  if 66 - 66: Ii1I - I1IiiI . OoooooooOO * I1Ii111
  I11IIi11Iii1 = struct . pack ( "I" , socket . htonl ( i1IIi1ii1i1ii ) )
  if 77 - 77: I1Ii111 * I1IiiI
  O0O = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   O0O = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   O0O += self . source . pack_address ( )
   O0O += self . dest . pack_address ( )
   O0O = lisp_ip_checksum ( O0O )
   if 27 - 27: O0
  if ( self . afi == LISP_AFI_IPV6 ) :
   O0O = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   O0O += self . source . pack_address ( )
   O0O += self . dest . pack_address ( )
   if 32 - 32: O0
   if 48 - 48: iII111i . O0 * Oo0Ooo * Ii1I . I11i . O0
  I1iiIi111I = socket . htons ( self . udp_sport )
  IiI11I111 = socket . htons ( self . udp_dport )
  OOoOo0O0 = socket . htons ( self . udp_length )
  I1i11i = socket . htons ( self . udp_checksum )
  O0I1II1 = struct . pack ( "HHHH" , I1iiIi111I , IiI11I111 , OOoOo0O0 , I1i11i )
  return ( I11IIi11Iii1 + O0O + O0I1II1 )
  if 50 - 50: I11i . I1ii11iIi11i
  if 31 - 31: iIii1I11I1II1 . OOooOOo * ooOoO0o . iII111i - O0 . iIii1I11I1II1
 def decode ( self , packet ) :
  if 54 - 54: iIii1I11I1II1 / OOooOOo + oO0o % OoOoOO00 * OoOoOO00 - II111iiii
  if 43 - 43: Ii1I / I1Ii111 . oO0o + iIii1I11I1II1
  if 99 - 99: I1ii11iIi11i
  if 29 - 29: I1IiiI . IiII
  Iii1I = "I"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 8 - 8: i1IIi * O0
  i1IIi1ii1i1ii = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  if 60 - 60: Oo0Ooo - II111iiii + I1IiiI
  i1IIi1ii1i1ii = socket . ntohl ( i1IIi1ii1i1ii [ 0 ] )
  self . security = True if ( i1IIi1ii1i1ii & 0x08000000 ) else False
  self . ddt = True if ( i1IIi1ii1i1ii & 0x04000000 ) else False
  self . to_etr = True if ( i1IIi1ii1i1ii & 0x02000000 ) else False
  self . to_ms = True if ( i1IIi1ii1i1ii & 0x01000000 ) else False
  packet = packet [ IiiiiI : : ]
  if 17 - 17: OoOoOO00 % I1IiiI
  if 8 - 8: Oo0Ooo
  if 49 - 49: OoOoOO00 * I11i - o0oOOo0O0Ooo / OoO0O00 * oO0o
  if 51 - 51: ooOoO0o - iIii1I11I1II1 . I11i * OoOoOO00 + I1Ii111 * i1IIi
  if ( len ( packet ) < 1 ) : return ( None )
  iiIIiI1I = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  iiIIiI1I = iiIIiI1I >> 4
  if 37 - 37: IiII * oO0o / OoooooooOO . OoO0O00
  if ( iiIIiI1I == 4 ) :
   IiiiiI = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < IiiiiI ) : return ( None )
   if 77 - 77: II111iiii + OoOoOO00 * OOooOOo
   Ii1i1I1Ii , OOoOo0O0 , Ii1i1I1Ii , I11iI1I , IIIiIIi111 , I1i11i = struct . unpack ( "HHIBBH" , packet [ : IiiiiI ] )
   self . length = socket . ntohs ( OOoOo0O0 )
   self . ttl = I11iI1I
   self . protocol = IIIiIIi111
   self . ip_checksum = socket . ntohs ( I1i11i )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 60 - 60: iII111i * iIii1I11I1II1 . OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
   if 36 - 36: i1IIi . OoooooooOO - II111iiii - OoOoOO00 - IiII
   if 53 - 53: I1ii11iIi11i - II111iiii . i11iIiiIii
   if 76 - 76: iIii1I11I1II1 - Oo0Ooo
   IIIiIIi111 = struct . pack ( "H" , 0 )
   OOo00o000oOO0 = struct . calcsize ( "HHIBB" )
   II1II = struct . calcsize ( "H" )
   packet = packet [ : OOo00o000oOO0 ] + IIIiIIi111 + packet [ OOo00o000oOO0 + II1II : ]
   if 99 - 99: i1IIi + o0oOOo0O0Ooo . i11iIiiIii * I1IiiI
   packet = packet [ IiiiiI : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 63 - 63: I1IiiI % oO0o / iIii1I11I1II1 * Ii1I % OOooOOo . II111iiii
   if 56 - 56: IiII / i11iIiiIii . o0oOOo0O0Ooo . oO0o - i11iIiiIii
  if ( iiIIiI1I == 6 ) :
   IiiiiI = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < IiiiiI ) : return ( None )
   if 23 - 23: I1ii11iIi11i * i11iIiiIii % ooOoO0o
   Ii1i1I1Ii , OOoOo0O0 , IIIiIIi111 , I11iI1I = struct . unpack ( "IHBB" , packet [ : IiiiiI ] )
   self . length = socket . ntohs ( OOoOo0O0 )
   self . protocol = IIIiIIi111
   self . ttl = I11iI1I
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 47 - 47: iIii1I11I1II1 . OOooOOo / I11i % II111iiii
   packet = packet [ IiiiiI : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 92 - 92: I1ii11iIi11i % i11iIiiIii
   if 82 - 82: I1Ii111 * I1ii11iIi11i % Ii1I / o0oOOo0O0Ooo
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 28 - 28: iII111i % OoO0O00 - OOooOOo - Oo0Ooo
  IiiiiI = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 16 - 16: i11iIiiIii - i11iIiiIii . OoOoOO00 / i1IIi
  I1iiIi111I , IiI11I111 , OOoOo0O0 , I1i11i = struct . unpack ( "HHHH" , packet [ : IiiiiI ] )
  self . udp_sport = socket . ntohs ( I1iiIi111I )
  self . udp_dport = socket . ntohs ( IiI11I111 )
  self . udp_length = socket . ntohs ( OOoOo0O0 )
  self . udp_checksum = socket . ntohs ( I1i11i )
  packet = packet [ IiiiiI : : ]
  return ( packet )
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
  if 14 - 14: IiII * O0 + O0 - ooOoO0o . i11iIiiIii - IiII
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
  if 23 - 23: Ii1I * Ii1I / I11i
  if 11 - 11: OOooOOo
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  oOoOoO0Oo0oo = self . rloc_name
  if ( cour ) : oOoOoO0Oo0oo = lisp_print_cour ( oOoOoO0Oo0oo )
  return ( 'rloc-name: {}' . format ( blue ( oOoOoO0Oo0oo , cour ) ) )
  if 37 - 37: I11i / Oo0Ooo
  if 30 - 30: Ii1I / Ii1I * oO0o % I1IiiI - OOooOOo . I1Ii111
 def print_record ( self , indent ) :
  iI = self . print_rloc_name ( )
  if ( iI != "" ) : iI = ", " + iI
  iiIi1ii1IiI = ""
  if ( self . geo ) :
   Iii = ""
   if ( self . geo . geo_name ) : Iii = "'{}' " . format ( self . geo . geo_name )
   iiIi1ii1IiI = ", geo: {}{}" . format ( Iii , self . geo . print_geo ( ) )
   if 48 - 48: Ii1I % Ii1I % iIii1I11I1II1 / i11iIiiIii % iIii1I11I1II1 / ooOoO0o
  oOI1i = ""
  if ( self . elp ) :
   Iii = ""
   if ( self . elp . elp_name ) : Iii = "'{}' " . format ( self . elp . elp_name )
   oOI1i = ", elp: {}{}" . format ( Iii , self . elp . print_elp ( True ) )
   if 80 - 80: I1IiiI - O0
  OooOO = ""
  if ( self . rle ) :
   Iii = ""
   if ( self . rle . rle_name ) : Iii = "'{}' " . format ( self . rle . rle_name )
   OooOO = ", rle: {}{}" . format ( Iii , self . rle . print_rle ( False ,
 True ) )
   if 15 - 15: I11i * i1IIi + I1Ii111 % i1IIi * Ii1I
  O0oO0OOo = ""
  if ( self . json ) :
   Iii = ""
   if ( self . json . json_name ) :
    Iii = "'{}' " . format ( self . json . json_name )
    if 37 - 37: Oo0Ooo + iIii1I11I1II1 * I11i / II111iiii . OoOoOO00
   O0oO0OOo = ", json: {}" . format ( self . json . print_json ( False ) )
   if 77 - 77: oO0o + I11i . II111iiii
   if 3 - 3: IiII / o0oOOo0O0Ooo
  O0O0ii1IiIiI1 = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   O0O0ii1IiIiI1 = ", " + self . keys [ 1 ] . print_keys ( )
   if 12 - 12: iIii1I11I1II1 + ooOoO0o * I1Ii111 % OoooooooOO / iIii1I11I1II1
   if 43 - 43: O0 . i1IIi - OoooooooOO - i1IIi - I1ii11iIi11i
  OOooOoO = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( OOooOoO . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , iI , iiIi1ii1IiI ,
 oOI1i , OooOO , O0oO0OOo , O0O0ii1IiIiI1 ) )
  if 8 - 8: OoOoOO00 / Ii1I
  if 12 - 12: iIii1I11I1II1
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 52 - 52: oO0o . I1ii11iIi11i + oO0o
  if 73 - 73: II111iiii / i11iIiiIii / ooOoO0o
  if 1 - 1: iII111i + OoOoOO00 / IiII - I1IiiI % I1IiiI
 def store_rloc_entry ( self , rloc_entry ) :
  IIIi1iI1 = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 21 - 21: OOooOOo % O0 / I11i
  self . rloc . copy_address ( IIIi1iI1 )
  if 15 - 15: O0 - i1IIi . iIii1I11I1II1 - i11iIiiIii / Ii1I
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 11 - 11: iIii1I11I1II1 + I1IiiI
   if 15 - 15: o0oOOo0O0Ooo
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   Iii = rloc_entry . geo_name
   if ( Iii and lisp_geo_list . has_key ( Iii ) ) :
    self . geo = lisp_geo_list [ Iii ]
    if 55 - 55: i11iIiiIii / OoooooooOO - I11i
    if 89 - 89: I11i - i1IIi - i1IIi * OOooOOo - O0
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   Iii = rloc_entry . elp_name
   if ( Iii and lisp_elp_list . has_key ( Iii ) ) :
    self . elp = lisp_elp_list [ Iii ]
    if 94 - 94: Oo0Ooo / I11i . I1ii11iIi11i
    if 31 - 31: i11iIiiIii + iIii1I11I1II1 . II111iiii
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   Iii = rloc_entry . rle_name
   if ( Iii and lisp_rle_list . has_key ( Iii ) ) :
    self . rle = lisp_rle_list [ Iii ]
    if 72 - 72: I1Ii111 * OoO0O00 + Oo0Ooo / Ii1I % OOooOOo
    if 84 - 84: OoOoOO00 / o0oOOo0O0Ooo
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   Iii = rloc_entry . json_name
   if ( Iii and lisp_json_list . has_key ( Iii ) ) :
    self . json = lisp_json_list [ Iii ]
    if 9 - 9: Ii1I
    if 76 - 76: I1IiiI % Oo0Ooo / iIii1I11I1II1 - Oo0Ooo
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 34 - 34: OoOoOO00 - i1IIi + OOooOOo + Ii1I . o0oOOo0O0Ooo
  if 42 - 42: OoO0O00
 def encode_json ( self , lisp_json ) :
  i11i = lisp_json . json_string
  oO0ooOo = 0
  if ( lisp_json . json_encrypted ) :
   oO0ooOo = ( lisp_json . json_key_id << 5 ) | 0x02
   if 10 - 10: OoOoOO00 * ooOoO0o / iIii1I11I1II1 . OOooOOo
   if 93 - 93: Oo0Ooo / II111iiii . Oo0Ooo + i1IIi + i1IIi
  iIiI1 = LISP_LCAF_JSON_TYPE
  IiI11Iiii = socket . htons ( LISP_AFI_LCAF )
  II = self . rloc . addr_length ( ) + 2
  if 78 - 78: OOooOOo / II111iiii + oO0o / I11i * i1IIi
  I11IiI1III = socket . htons ( len ( i11i ) + II )
  if 93 - 93: II111iiii . I1IiiI
  O0o = socket . htons ( len ( i11i ) )
  o0o0ooOOo0oO = struct . pack ( "HBBBBHH" , IiI11Iiii , 0 , 0 , iIiI1 , oO0ooOo ,
 I11IiI1III , O0o )
  o0o0ooOOo0oO += i11i
  if 54 - 54: I1Ii111 - i1IIi * Ii1I - i1IIi
  if 3 - 3: oO0o + OoO0O00 - iII111i / Ii1I
  if 58 - 58: Ii1I * I11i
  if 95 - 95: oO0o
  if ( lisp_is_json_telemetry ( i11i ) ) :
   o0o0ooOOo0oO += struct . pack ( "H" , socket . htons ( self . rloc . afi ) )
   o0o0ooOOo0oO += self . rloc . pack_address ( )
  else :
   o0o0ooOOo0oO += struct . pack ( "H" , 0 )
   if 49 - 49: I1IiiI
  return ( o0o0ooOOo0oO )
  if 23 - 23: I1Ii111
  if 5 - 5: I1ii11iIi11i % OoOoOO00 . OoooooooOO . o0oOOo0O0Ooo + i11iIiiIii
 def encode_lcaf ( self ) :
  IiI11Iiii = socket . htons ( LISP_AFI_LCAF )
  o0Oo0OOO0 = ""
  if ( self . geo ) :
   o0Oo0OOO0 = self . geo . encode_geo ( )
   if 73 - 73: OoOoOO00 % oO0o / O0 - OoooooooOO
   if 87 - 87: iIii1I11I1II1
  I1I1IIi11II = ""
  if ( self . elp ) :
   O0Oo0ooO0OO00 = ""
   for oOo0Oo0o0 in self . elp . elp_nodes :
    i1I1iiiI = socket . htons ( oOo0Oo0o0 . address . afi )
    iIiOOO0oo0OO0o0 = 0
    if ( oOo0Oo0o0 . eid ) : iIiOOO0oo0OO0o0 |= 0x4
    if ( oOo0Oo0o0 . probe ) : iIiOOO0oo0OO0o0 |= 0x2
    if ( oOo0Oo0o0 . strict ) : iIiOOO0oo0OO0o0 |= 0x1
    iIiOOO0oo0OO0o0 = socket . htons ( iIiOOO0oo0OO0o0 )
    O0Oo0ooO0OO00 += struct . pack ( "HH" , iIiOOO0oo0OO0o0 , i1I1iiiI )
    O0Oo0ooO0OO00 += oOo0Oo0o0 . address . pack_address ( )
    if 72 - 72: O0 * I1Ii111 - iIii1I11I1II1 % i1IIi
    if 83 - 83: OoOoOO00 + OOooOOo / OoooooooOO
   IIi1iIIii1 = socket . htons ( len ( O0Oo0ooO0OO00 ) )
   I1I1IIi11II = struct . pack ( "HBBBBH" , IiI11Iiii , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , IIi1iIIii1 )
   I1I1IIi11II += O0Oo0ooO0OO00
   if 32 - 32: OoOoOO00 . Oo0Ooo . o0oOOo0O0Ooo / I1IiiI
   if 23 - 23: iII111i * I1ii11iIi11i / Ii1I - OoOoOO00 . II111iiii
  O00ooO0o0o000o = ""
  if ( self . rle ) :
   i111 = ""
   for o0Ii11I in self . rle . rle_nodes :
    i1I1iiiI = socket . htons ( o0Ii11I . address . afi )
    i111 += struct . pack ( "HBBH" , 0 , 0 , o0Ii11I . level , i1I1iiiI )
    i111 += o0Ii11I . address . pack_address ( )
    if ( o0Ii11I . rloc_name ) :
     i111 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     i111 += o0Ii11I . rloc_name + "\0"
     if 32 - 32: Oo0Ooo
     if 78 - 78: Ii1I . Oo0Ooo + I1IiiI - ooOoO0o
     if 5 - 5: I1IiiI % I1ii11iIi11i * oO0o + I1Ii111
   I11II1i11 = socket . htons ( len ( i111 ) )
   O00ooO0o0o000o = struct . pack ( "HBBBBH" , IiI11Iiii , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , I11II1i11 )
   O00ooO0o0o000o += i111
   if 42 - 42: i1IIi . OoOoOO00 * OoOoOO00 * OoOoOO00
   if 14 - 14: II111iiii / I1Ii111 . I1IiiI
  O0oO00o0O0 = ""
  if ( self . json ) :
   O0oO00o0O0 = self . encode_json ( self . json )
   if 19 - 19: I1Ii111 / O0
   if 55 - 55: II111iiii / ooOoO0o / II111iiii * OOooOOo
  o00oO = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   o00oO = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 44 - 44: O0 * o0oOOo0O0Ooo % OOooOOo
   if 98 - 98: oO0o / iIii1I11I1II1 - OoOoOO00
  I1Ii1i111I = ""
  if ( self . rloc_name ) :
   I1Ii1i111I += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   I1Ii1i111I += self . rloc_name + "\0"
   if 51 - 51: O0 + Ii1I * OoooooooOO . oO0o + OoooooooOO
   if 58 - 58: ooOoO0o . Oo0Ooo / I1ii11iIi11i + OoO0O00 * OoooooooOO / I1IiiI
  iii11i11 = len ( o0Oo0OOO0 ) + len ( I1I1IIi11II ) + len ( O00ooO0o0o000o ) + len ( o00oO ) + 2 + len ( O0oO00o0O0 ) + self . rloc . addr_length ( ) + len ( I1Ii1i111I )
  if 80 - 80: II111iiii / iIii1I11I1II1 - OoO0O00 . I11i / II111iiii
  iii11i11 = socket . htons ( iii11i11 )
  IIiiiI11I1 = struct . pack ( "HBBBBHH" , IiI11Iiii , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , iii11i11 , socket . htons ( self . rloc . afi ) )
  IIiiiI11I1 += self . rloc . pack_address ( )
  return ( IIiiiI11I1 + I1Ii1i111I + o0Oo0OOO0 + I1I1IIi11II + O00ooO0o0o000o + o00oO + O0oO00o0O0 )
  if 26 - 26: OoO0O00
  if 81 - 81: i1IIi / Oo0Ooo - iIii1I11I1II1 - i11iIiiIii / II111iiii
 def encode ( self ) :
  iIiOOO0oo0OO0o0 = 0
  if ( self . local_bit ) : iIiOOO0oo0OO0o0 |= 0x0004
  if ( self . probe_bit ) : iIiOOO0oo0OO0o0 |= 0x0002
  if ( self . reach_bit ) : iIiOOO0oo0OO0o0 |= 0x0001
  if 35 - 35: I1IiiI - IiII * I1Ii111 - ooOoO0o % oO0o
  o0o0ooOOo0oO = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( iIiOOO0oo0OO0o0 ) ,
 socket . htons ( self . rloc . afi ) )
  if 88 - 88: IiII * OoO0O00 / IiII * I1IiiI + O0 / IiII
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 41 - 41: OoOoOO00
   o0o0ooOOo0oO = o0o0ooOOo0oO [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   o0o0ooOOo0oO += self . rloc . pack_address ( )
   if 81 - 81: Ii1I . I1IiiI % o0oOOo0O0Ooo . OoOoOO00
  return ( o0o0ooOOo0oO )
  if 94 - 94: oO0o % Oo0Ooo + OoO0O00 * oO0o - i11iIiiIii / I11i
  if 46 - 46: IiII - OoO0O00 * iII111i . I1Ii111 - ooOoO0o . i1IIi
 def decode_lcaf ( self , packet , nonce , ms_json_encrypt ) :
  Iii1I = "HBBBBH"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 53 - 53: I1Ii111 * I1IiiI + Oo0Ooo + I1IiiI + OOooOOo
  i1I1iiiI , iIii1iI11 , iIiOOO0oo0OO0o0 , iIiI1 , OOoO0 , I11IiI1III = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  if 8 - 8: i11iIiiIii + OoOoOO00 . I1ii11iIi11i / OoooooooOO % II111iiii
  if 21 - 21: oO0o - o0oOOo0O0Ooo + ooOoO0o . I1IiiI * oO0o * Ii1I
  I11IiI1III = socket . ntohs ( I11IiI1III )
  packet = packet [ IiiiiI : : ]
  if ( I11IiI1III > len ( packet ) ) : return ( None )
  if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
  if 8 - 8: OoooooooOO - OoO0O00 / i11iIiiIii / O0 . IiII
  if 86 - 86: ooOoO0o * OoooooooOO + iII111i + o0oOOo0O0Ooo
  if 79 - 79: i1IIi % I1ii11iIi11i - OoO0O00 % I1ii11iIi11i
  if ( iIiI1 == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( I11IiI1III > 0 ) :
    Iii1I = "H"
    IiiiiI = struct . calcsize ( Iii1I )
    if ( I11IiI1III < IiiiiI ) : return ( None )
    if 6 - 6: Oo0Ooo / iII111i . i11iIiiIii
    oooO00oOOooO = len ( packet )
    i1I1iiiI = struct . unpack ( Iii1I , packet [ : IiiiiI ] ) [ 0 ]
    i1I1iiiI = socket . ntohs ( i1I1iiiI )
    if 8 - 8: I1ii11iIi11i + O0 - oO0o % II111iiii . I1Ii111
    if ( i1I1iiiI == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ IiiiiI : : ]
     self . rloc_name = None
     if ( i1I1iiiI == LISP_AFI_NAME ) :
      packet , oOoOoO0Oo0oo = lisp_decode_dist_name ( packet )
      self . rloc_name = oOoOoO0Oo0oo
     else :
      self . rloc . afi = i1I1iiiI
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 86 - 86: IiII
      if 71 - 71: Ii1I - i1IIi . I1IiiI
      if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
    I11IiI1III -= oooO00oOOooO - len ( packet )
    if 54 - 54: i1IIi . OoO0O00 + iII111i + OoO0O00 * i1IIi
    if 13 - 13: Oo0Ooo / OoO0O00 + OOooOOo
  elif ( iIiI1 == LISP_LCAF_GEO_COORD_TYPE ) :
   if 90 - 90: OoO0O00 * i11iIiiIii / oO0o
   if 91 - 91: iII111i - OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
   if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
   if 25 - 25: OoOoOO00 + IiII . i11iIiiIii
   ooOooo = lisp_geo ( "" )
   packet = ooOooo . decode_geo ( packet , I11IiI1III , OOoO0 )
   if ( packet == None ) : return ( None )
   self . geo = ooOooo
   if 48 - 48: O0 % I1ii11iIi11i
  elif ( iIiI1 == LISP_LCAF_JSON_TYPE ) :
   O0OOOooo = OOoO0 & 0x02
   if 25 - 25: OOooOOo % i1IIi + I1Ii111 * iIii1I11I1II1 * ooOoO0o + oO0o
   if 92 - 92: ooOoO0o . i11iIiiIii / I11i * I11i . iII111i
   if 59 - 59: OoO0O00 + OOooOOo . I1ii11iIi11i - iII111i % ooOoO0o
   if 9 - 9: IiII
   Iii1I = "H"
   IiiiiI = struct . calcsize ( Iii1I )
   if ( I11IiI1III < IiiiiI ) : return ( None )
   if 51 - 51: I1Ii111 + O0 + OoOoOO00 % O0 + oO0o
   O0o = struct . unpack ( Iii1I , packet [ : IiiiiI ] ) [ 0 ]
   O0o = socket . ntohs ( O0o )
   if ( I11IiI1III < IiiiiI + O0o ) : return ( None )
   if 65 - 65: II111iiii % I1ii11iIi11i + OOooOOo + Ii1I
   packet = packet [ IiiiiI : : ]
   self . json = lisp_json ( "" , packet [ 0 : O0o ] , O0OOOooo ,
 ms_json_encrypt )
   packet = packet [ O0o : : ]
   if 39 - 39: i11iIiiIii % iIii1I11I1II1 + ooOoO0o + i11iIiiIii - O0 - I11i
   if 71 - 71: OoooooooOO . OoOoOO00 % IiII * iII111i / OOooOOo
   if 63 - 63: O0 * O0 . IiII
   if 54 - 54: I1IiiI / i1IIi * I1ii11iIi11i
   i1I1iiiI = socket . ntohs ( struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ] )
   packet = packet [ 2 : : ]
   if 10 - 10: I1IiiI % II111iiii / I1IiiI
   if ( i1I1iiiI != 0 and lisp_is_json_telemetry ( self . json . json_string ) ) :
    self . rloc . afi = i1I1iiiI
    packet = self . rloc . unpack_address ( packet )
    if 13 - 13: II111iiii - i11iIiiIii
    if 90 - 90: I11i . OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
  elif ( iIiI1 == LISP_LCAF_ELP_TYPE ) :
   if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
   if 95 - 95: iII111i / ooOoO0o + I1Ii111
   if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
   if 81 - 81: I1ii11iIi11i
   Iii11i111iI = lisp_elp ( None )
   Iii11i111iI . elp_nodes = [ ]
   while ( I11IiI1III > 0 ) :
    iIiOOO0oo0OO0o0 , i1I1iiiI = struct . unpack ( "HH" , packet [ : 4 ] )
    if 76 - 76: I1Ii111 - O0
    i1I1iiiI = socket . ntohs ( i1I1iiiI )
    if ( i1I1iiiI == LISP_AFI_LCAF ) : return ( None )
    if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
    oOo0Oo0o0 = lisp_elp_node ( )
    Iii11i111iI . elp_nodes . append ( oOo0Oo0o0 )
    if 7 - 7: II111iiii + I11i
    iIiOOO0oo0OO0o0 = socket . ntohs ( iIiOOO0oo0OO0o0 )
    oOo0Oo0o0 . eid = ( iIiOOO0oo0OO0o0 & 0x4 )
    oOo0Oo0o0 . probe = ( iIiOOO0oo0OO0o0 & 0x2 )
    oOo0Oo0o0 . strict = ( iIiOOO0oo0OO0o0 & 0x1 )
    oOo0Oo0o0 . address . afi = i1I1iiiI
    oOo0Oo0o0 . address . mask_len = oOo0Oo0o0 . address . host_mask_len ( )
    packet = oOo0Oo0o0 . address . unpack_address ( packet [ 4 : : ] )
    I11IiI1III -= oOo0Oo0o0 . address . addr_length ( ) + 4
    if 99 - 99: iIii1I11I1II1 * oO0o
   Iii11i111iI . select_elp_node ( )
   self . elp = Iii11i111iI
   if 37 - 37: ooOoO0o * iII111i * I11i
  elif ( iIiI1 == LISP_LCAF_RLE_TYPE ) :
   if 11 - 11: I1IiiI
   if 48 - 48: O0 . I11i
   if 9 - 9: oO0o / Oo0Ooo
   if 85 - 85: i11iIiiIii / I1IiiI . OoO0O00 . I11i . oO0o * IiII
   O0OOO = lisp_rle ( None )
   O0OOO . rle_nodes = [ ]
   while ( I11IiI1III > 0 ) :
    Ii1i1I1Ii , I1iI1 , I1i11 , i1I1iiiI = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 19 - 19: I1Ii111 . I1ii11iIi11i * O0 + I1IiiI
    i1I1iiiI = socket . ntohs ( i1I1iiiI )
    if ( i1I1iiiI == LISP_AFI_LCAF ) : return ( None )
    if 9 - 9: iIii1I11I1II1 % iIii1I11I1II1 + Oo0Ooo % oO0o
    o0Ii11I = lisp_rle_node ( )
    O0OOO . rle_nodes . append ( o0Ii11I )
    if 70 - 70: O0
    o0Ii11I . level = I1i11
    o0Ii11I . address . afi = i1I1iiiI
    o0Ii11I . address . mask_len = o0Ii11I . address . host_mask_len ( )
    packet = o0Ii11I . address . unpack_address ( packet [ 6 : : ] )
    if 76 - 76: o0oOOo0O0Ooo % OOooOOo . I11i . iIii1I11I1II1 + I1Ii111 % OoooooooOO
    I11IiI1III -= o0Ii11I . address . addr_length ( ) + 6
    if ( I11IiI1III >= 2 ) :
     i1I1iiiI = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( i1I1iiiI ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , o0Ii11I . rloc_name = lisp_decode_dist_name ( packet )
      if 9 - 9: oO0o + Ii1I / I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo
      if ( packet == None ) : return ( None )
      I11IiI1III -= len ( o0Ii11I . rloc_name ) + 1 + 2
      if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
      if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
      if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
   self . rle = O0OOO
   self . rle . build_forwarding_list ( )
   if 30 - 30: i11iIiiIii % OOooOOo
  elif ( iIiI1 == LISP_LCAF_SECURITY_TYPE ) :
   if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
   if 27 - 27: I1IiiI + OoOoOO00 + iII111i
   if 70 - 70: I11i + IiII . ooOoO0o - I1ii11iIi11i
   if 34 - 34: i1IIi % Oo0Ooo . oO0o
   if 36 - 36: I1ii11iIi11i / I1Ii111 - IiII + OOooOOo + I1Ii111
   iII111I = packet
   O00o0oO0oO0 = lisp_keys ( 1 )
   packet = O00o0oO0oO0 . decode_lcaf ( iII111I , I11IiI1III , False )
   if ( packet == None ) : return ( None )
   if 62 - 62: Oo0Ooo . OoO0O00 * I1Ii111 . i11iIiiIii * O0
   if 10 - 10: Oo0Ooo / OoOoOO00 * OOooOOo - IiII + Ii1I
   if 62 - 62: I1IiiI . Ii1I
   if 74 - 74: Ii1I - I11i % ooOoO0o - I1IiiI - Ii1I - II111iiii
   OOOo00OOooO = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( O00o0oO0oO0 . cipher_suite in OOOo00OOooO ) :
    if ( O00o0oO0oO0 . cipher_suite == LISP_CS_25519_CBC ) :
     OO0Oo00o0o0 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 81 - 81: i1IIi * I1ii11iIi11i + IiII - OoO0O00 * i1IIi
    if ( O00o0oO0oO0 . cipher_suite == LISP_CS_25519_CHACHA ) :
     OO0Oo00o0o0 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 6 - 6: iIii1I11I1II1 % OoOoOO00 % II111iiii % o0oOOo0O0Ooo
   else :
    OO0Oo00o0o0 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 52 - 52: Ii1I - I1IiiI * iIii1I11I1II1 % Oo0Ooo * OOooOOo
   packet = OO0Oo00o0o0 . decode_lcaf ( iII111I , I11IiI1III , False )
   if ( packet == None ) : return ( None )
   if 67 - 67: OoooooooOO * I11i * Ii1I * iIii1I11I1II1
   if ( len ( packet ) < 2 ) : return ( None )
   i1I1iiiI = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( i1I1iiiI )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 22 - 22: OoO0O00 / o0oOOo0O0Ooo
   if 35 - 35: I1Ii111 / I1Ii111 + o0oOOo0O0Ooo - oO0o
   if 40 - 40: OoOoOO00 - II111iiii
   if 29 - 29: I1IiiI - O0
   if 36 - 36: I1IiiI * I1IiiI
   if 79 - 79: I1Ii111 - I11i
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 49 - 49: II111iiii + O0 * ooOoO0o - Oo0Ooo
   Ooo0oOO = self . rloc_name
   if ( Ooo0oOO ) : Ooo0oOO = blue ( self . rloc_name , False )
   if 26 - 26: Oo0Ooo - I1IiiI
   if 77 - 77: IiII + OoO0O00 - i1IIi - I1Ii111 % i11iIiiIii
   if 96 - 96: OoooooooOO - Oo0Ooo * OoooooooOO
   if 4 - 4: OoOoOO00 / OoooooooOO - iIii1I11I1II1 / o0oOOo0O0Ooo / I11i
   if 31 - 31: Oo0Ooo / I1ii11iIi11i - II111iiii - OOooOOo
   if 5 - 5: oO0o
   Ooo0OO0 = self . keys [ 1 ] if self . keys else None
   if ( Ooo0OO0 == None ) :
    if ( OO0Oo00o0o0 . remote_public_key == None ) :
     i1IIIII1 = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( i1IIIII1 , Ooo0oOO ) )
     OO0Oo00o0o0 = None
    else :
     i1IIIII1 = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( i1IIIII1 , Ooo0oOO ) )
     OO0Oo00o0o0 . compute_shared_key ( "encap" )
     if 51 - 51: i11iIiiIii
     if 21 - 21: O0 - IiII * i1IIi + o0oOOo0O0Ooo % I11i + iIii1I11I1II1
     if 35 - 35: i11iIiiIii + i1IIi
     if 16 - 16: OoO0O00 - I1Ii111 * iII111i
     if 41 - 41: i11iIiiIii + i1IIi / IiII * I1ii11iIi11i / iIii1I11I1II1
     if 70 - 70: I1IiiI % oO0o + iII111i % i11iIiiIii + ooOoO0o
     if 88 - 88: I11i * oO0o * I1ii11iIi11i - OOooOOo * IiII + o0oOOo0O0Ooo
     if 9 - 9: OoooooooOO
     if 26 - 26: OoOoOO00 + II111iiii - OoO0O00 + iII111i - iII111i % O0
     if 79 - 79: iIii1I11I1II1 - OoOoOO00 - O0 + I1ii11iIi11i
   if ( Ooo0OO0 ) :
    if ( OO0Oo00o0o0 . remote_public_key == None ) :
     OO0Oo00o0o0 = None
     IIIiIII111iii = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( IIIiIII111iii , Ooo0oOO ) )
    elif ( Ooo0OO0 . compare_keys ( OO0Oo00o0o0 ) ) :
     OO0Oo00o0o0 = Ooo0OO0
     lprint ( "    Maintain stored encap-keys for {}" . format ( Ooo0oOO ) )
     if 69 - 69: oO0o % OoooooooOO
    else :
     if ( Ooo0OO0 . remote_public_key == None ) :
      i1IIIII1 = "New encap-keying for existing state"
     else :
      i1IIIII1 = "Remote encap-rekeying"
      if 21 - 21: I1Ii111
     lprint ( "    {} for {}" . format ( bold ( i1IIIII1 , False ) ,
 Ooo0oOO ) )
     Ooo0OO0 . remote_public_key = OO0Oo00o0o0 . remote_public_key
     Ooo0OO0 . compute_shared_key ( "encap" )
     OO0Oo00o0o0 = Ooo0OO0
     if 62 - 62: Ii1I % o0oOOo0O0Ooo
     if 65 - 65: OoO0O00 + Oo0Ooo + IiII / OoOoOO00
   self . keys = [ None , OO0Oo00o0o0 , None , None ]
   if 37 - 37: oO0o - I11i
  else :
   if 64 - 64: OoO0O00 * OoOoOO00
   if 50 - 50: I1ii11iIi11i + I11i * iII111i
   if 27 - 27: OoOoOO00 * OOooOOo * iIii1I11I1II1 / i1IIi
   if 60 - 60: OOooOOo * I1Ii111 . oO0o
   packet = packet [ I11IiI1III : : ]
   if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
  return ( packet )
  if 51 - 51: I1IiiI . I11i - OoOoOO00
  if 10 - 10: Oo0Ooo * OOooOOo / IiII . o0oOOo0O0Ooo
 def decode ( self , packet , nonce , ms_json_encrypt = False ) :
  Iii1I = "BBBBHH"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 97 - 97: Ii1I . Ii1I % iII111i
  self . priority , self . weight , self . mpriority , self . mweight , iIiOOO0oo0OO0o0 , i1I1iiiI = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  if 49 - 49: Oo0Ooo % OOooOOo - OoooooooOO + IiII
  if 54 - 54: iIii1I11I1II1 - OoooooooOO / I11i / oO0o % I1IiiI + OoOoOO00
  iIiOOO0oo0OO0o0 = socket . ntohs ( iIiOOO0oo0OO0o0 )
  i1I1iiiI = socket . ntohs ( i1I1iiiI )
  self . local_bit = True if ( iIiOOO0oo0OO0o0 & 0x0004 ) else False
  self . probe_bit = True if ( iIiOOO0oo0OO0o0 & 0x0002 ) else False
  self . reach_bit = True if ( iIiOOO0oo0OO0o0 & 0x0001 ) else False
  if 26 - 26: OoO0O00 * II111iiii % OOooOOo * iII111i + iII111i
  if ( i1I1iiiI == LISP_AFI_LCAF ) :
   packet = packet [ IiiiiI - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
  else :
   self . rloc . afi = i1I1iiiI
   packet = packet [ IiiiiI : : ]
   packet = self . rloc . unpack_address ( packet )
   if 25 - 25: I11i - I1ii11iIi11i
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 100 - 100: I1Ii111 / Ii1I + OoOoOO00 . OoooooooOO
  if 83 - 83: O0
 def end_of_rlocs ( self , packet , rloc_count ) :
  for OoOOoO0oOo in range ( rloc_count ) :
   packet = self . decode ( packet , None , False )
   if ( packet == None ) : return ( None )
   if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
  return ( packet )
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
class lisp_map_referral ( ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 13 - 13: IiII
  if 56 - 56: Oo0Ooo
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # OoOoOO00 - II111iiii . I1IiiI . i1IIi
 lisp_hex_string ( self . nonce ) ) )
  if 60 - 60: iIii1I11I1II1 + ooOoO0o * i11iIiiIii + OoooooooOO
  if 43 - 43: I1ii11iIi11i % Oo0Ooo - i11iIiiIii / I1Ii111 * i1IIi
 def encode ( self ) :
  i1IIi1ii1i1ii = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  o0o0ooOOo0oO = struct . pack ( "I" , socket . htonl ( i1IIi1ii1i1ii ) )
  o0o0ooOOo0oO += struct . pack ( "Q" , self . nonce )
  return ( o0o0ooOOo0oO )
  if 78 - 78: o0oOOo0O0Ooo / OOooOOo / oO0o
  if 9 - 9: IiII + O0 / I1IiiI
 def decode ( self , packet ) :
  Iii1I = "I"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 92 - 92: OOooOOo / i11iIiiIii + OoooooooOO
  i1IIi1ii1i1ii = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  i1IIi1ii1i1ii = socket . ntohl ( i1IIi1ii1i1ii [ 0 ] )
  self . record_count = i1IIi1ii1i1ii & 0xff
  packet = packet [ IiiiiI : : ]
  if 9 - 9: iII111i
  Iii1I = "Q"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 9 - 9: O0 / o0oOOo0O0Ooo / I11i - i11iIiiIii - iII111i / IiII
  self . nonce = struct . unpack ( Iii1I , packet [ : IiiiiI ] ) [ 0 ]
  packet = packet [ IiiiiI : : ]
  return ( packet )
  if 46 - 46: IiII + OoooooooOO % I1IiiI
  if 51 - 51: I1IiiI * I1Ii111 . i11iIiiIii % Oo0Ooo . i1IIi - oO0o
  if 56 - 56: Oo0Ooo / II111iiii
  if 76 - 76: OoOoOO00 % OoO0O00 * O0
  if 39 - 39: ooOoO0o / iII111i
  if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
  if 59 - 59: I11i % Ii1I / OoOoOO00
  if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
class lisp_ddt_entry ( ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
  if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
  if 80 - 80: Oo0Ooo
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 58 - 58: I1Ii111 + OOooOOo
  if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  I111IiiII = self . delegation_set [ 0 ]
  return ( I111IiiII . print_node_type ( ) )
  if 4 - 4: OoO0O00 + I1ii11iIi11i + Ii1I + I1ii11iIi11i / iII111i
  if 15 - 15: OoooooooOO + I11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 76 - 76: O0 % Ii1I * ooOoO0o
  if 13 - 13: OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   i1iiI1iI11 = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( i1iiI1iI11 == None ) :
    i1iiI1iI11 = lisp_ddt_entry ( )
    i1iiI1iI11 . eid . copy_address ( self . group )
    i1iiI1iI11 . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , i1iiI1iI11 )
    if 89 - 89: Oo0Ooo * II111iiii * I1Ii111 / I1IiiI + I1IiiI . o0oOOo0O0Ooo
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( i1iiI1iI11 . group )
   i1iiI1iI11 . add_source_entry ( self )
   if 40 - 40: O0 - i1IIi - i11iIiiIii % IiII % II111iiii
   if 54 - 54: o0oOOo0O0Ooo + I1IiiI % ooOoO0o . Ii1I - o0oOOo0O0Ooo
   if 1 - 1: I1IiiI + iIii1I11I1II1
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 81 - 81: OoO0O00 * ooOoO0o
  if 98 - 98: OoOoOO00 % ooOoO0o * I1ii11iIi11i
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 64 - 64: OOooOOo + I11i . ooOoO0o
  if 17 - 17: OoOoOO00 . I1Ii111
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 10 - 10: I1ii11iIi11i * I1Ii111 * Ii1I * o0oOOo0O0Ooo - o0oOOo0O0Ooo + OoOoOO00
  if 92 - 92: Ii1I / iII111i . I1ii11iIi11i % Ii1I
  if 18 - 18: OOooOOo + I1IiiI + i1IIi + o0oOOo0O0Ooo % o0oOOo0O0Ooo
class lisp_ddt_node ( ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 48 - 48: O0
  if 5 - 5: OOooOOo / i11iIiiIii . I11i % OOooOOo
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 1 - 1: II111iiii + O0 * OoOoOO00 / IiII . O0
  if 87 - 87: IiII + I1IiiI
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 74 - 74: OoO0O00 + OoO0O00 % iII111i / I11i / O0
  if 54 - 54: o0oOOo0O0Ooo / OoooooooOO * ooOoO0o . OoOoOO00 - I1Ii111
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 69 - 69: oO0o - OoO0O00
  if 80 - 80: ooOoO0o + iIii1I11I1II1 . II111iiii + I1IiiI - oO0o % OoOoOO00
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 10 - 10: iIii1I11I1II1
  if 44 - 44: OoOoOO00 * oO0o . I1ii11iIi11i + i11iIiiIii
  if 85 - 85: I11i
  if 36 - 36: ooOoO0o % OoO0O00
  if 1 - 1: OoooooooOO - OoOoOO00
  if 35 - 35: I1Ii111
  if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
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
  if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
  if 92 - 92: iII111i % I1ii11iIi11i
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # iIii1I11I1II1
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 61 - 61: OOooOOo - OOooOOo / ooOoO0o * I1Ii111
  if 73 - 73: OoO0O00 * Ii1I
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 49 - 49: OoooooooOO / oO0o / I1IiiI + o0oOOo0O0Ooo * ooOoO0o . Oo0Ooo
  if 48 - 48: I11i + IiII / IiII
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( lisp_ddt_map_requestQ . has_key ( str ( self . nonce ) ) ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 65 - 65: I1ii11iIi11i - i1IIi % oO0o * iIii1I11I1II1 - IiII + ooOoO0o
   if 63 - 63: i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
   if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
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
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 81 - 81: OoOoOO00
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
if 8 - 8: i11iIiiIii - I1Ii111 / IiII
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
  if 28 - 28: I1Ii111
  if 27 - 27: iII111i * I1IiiI
 def print_info ( self ) :
  if ( self . info_reply ) :
   ooOo = "Info-Reply"
   IIIi1iI1 = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # I11i + I1Ii111 + ooOoO0o / OoOoOO00
   # I11i % I1Ii111 + Ii1I * OOooOOo / I1ii11iIi11i
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : IIIi1iI1 += "empty, "
   for IiIi1I1i1iIiI in self . rtr_list :
    IIIi1iI1 += red ( IiIi1I1i1iIiI . print_address_no_iid ( ) , False ) + ", "
    if 92 - 92: I11i + I1Ii111
   IIIi1iI1 = IIIi1iI1 [ 0 : - 2 ]
  else :
   ooOo = "Info-Request"
   III11iI1 = "<none>" if self . hostname == None else self . hostname
   IIIi1iI1 = ", hostname: {}" . format ( blue ( III11iI1 , False ) )
   if 66 - 66: O0 + ooOoO0o % ooOoO0o
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( ooOo , False ) ,
 lisp_hex_string ( self . nonce ) , IIIi1iI1 ) )
  if 28 - 28: Ii1I . I1Ii111
  if 40 - 40: Oo0Ooo + iIii1I11I1II1 - iII111i * iIii1I11I1II1 + iIii1I11I1II1 * iIii1I11I1II1
 def encode ( self ) :
  i1IIi1ii1i1ii = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : i1IIi1ii1i1ii |= ( 1 << 27 )
  if 3 - 3: oO0o - Oo0Ooo * I1IiiI / I1ii11iIi11i / OOooOOo
  if 45 - 45: II111iiii
  if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
  if 84 - 84: o0oOOo0O0Ooo
  if 40 - 40: OoooooooOO - oO0o / O0 * I1Ii111 . O0 + i11iIiiIii
  if 9 - 9: OOooOOo % O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
  if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
  o0o0ooOOo0oO = struct . pack ( "I" , socket . htonl ( i1IIi1ii1i1ii ) )
  o0o0ooOOo0oO += struct . pack ( "Q" , self . nonce )
  o0o0ooOOo0oO += struct . pack ( "III" , 0 , 0 , 0 )
  if 66 - 66: OOooOOo * Oo0Ooo
  if 58 - 58: OOooOOo
  if 96 - 96: IiII % OoooooooOO + O0 * II111iiii / OOooOOo . I1Ii111
  if 47 - 47: OoO0O00 - Oo0Ooo * OoO0O00 / oO0o
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    o0o0ooOOo0oO += struct . pack ( "H" , 0 )
   else :
    o0o0ooOOo0oO += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    o0o0ooOOo0oO += self . hostname + "\0"
    if 13 - 13: ooOoO0o
   return ( o0o0ooOOo0oO )
   if 55 - 55: i1IIi . I11i . II111iiii + O0 + ooOoO0o - i1IIi
   if 3 - 3: iIii1I11I1II1 / oO0o
   if 61 - 61: I1Ii111 / O0 - iII111i
   if 44 - 44: i1IIi
   if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
  i1I1iiiI = socket . htons ( LISP_AFI_LCAF )
  iIiI1 = LISP_LCAF_NAT_TYPE
  I11IiI1III = socket . htons ( 16 )
  OOoOOO = socket . htons ( self . ms_port )
  I1iiiI1i = socket . htons ( self . etr_port )
  o0o0ooOOo0oO += struct . pack ( "HHBBHHHH" , i1I1iiiI , 0 , iIiI1 , 0 , I11IiI1III ,
 OOoOOO , I1iiiI1i , socket . htons ( self . global_etr_rloc . afi ) )
  o0o0ooOOo0oO += self . global_etr_rloc . pack_address ( )
  o0o0ooOOo0oO += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  o0o0ooOOo0oO += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : o0o0ooOOo0oO += struct . pack ( "H" , 0 )
  if 69 - 69: iII111i * I11i
  if 43 - 43: o0oOOo0O0Ooo - IiII * Ii1I . i11iIiiIii / II111iiii
  if 61 - 61: OoOoOO00 / I1IiiI . I1ii11iIi11i % OOooOOo
  if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
  for IiIi1I1i1iIiI in self . rtr_list :
   o0o0ooOOo0oO += struct . pack ( "H" , socket . htons ( IiIi1I1i1iIiI . afi ) )
   o0o0ooOOo0oO += IiIi1I1i1iIiI . pack_address ( )
   if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
  return ( o0o0ooOOo0oO )
  if 15 - 15: o0oOOo0O0Ooo / i11iIiiIii
  if 63 - 63: I1ii11iIi11i - Ii1I + I11i
 def decode ( self , packet ) :
  iII111I = packet
  Iii1I = "I"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 98 - 98: iII111i / IiII * I1IiiI / oO0o - iIii1I11I1II1
  i1IIi1ii1i1ii = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  i1IIi1ii1i1ii = i1IIi1ii1i1ii [ 0 ]
  packet = packet [ IiiiiI : : ]
  if 72 - 72: O0 . OOooOOo
  Iii1I = "Q"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
  O0oo00o000 = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  if 74 - 74: i1IIi
  i1IIi1ii1i1ii = socket . ntohl ( i1IIi1ii1i1ii )
  self . nonce = O0oo00o000 [ 0 ]
  self . info_reply = i1IIi1ii1i1ii & 0x08000000
  self . hostname = None
  packet = packet [ IiiiiI : : ]
  if 80 - 80: ooOoO0o + I1Ii111 . I1ii11iIi11i % OoooooooOO
  if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
  if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
  if 35 - 35: i11iIiiIii + oO0o
  if 85 - 85: OoOoOO00 . O0 % OoooooooOO % oO0o
  Iii1I = "HH"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
  if 12 - 12: II111iiii - iIii1I11I1II1
  if 43 - 43: i11iIiiIii % OoO0O00
  if 100 - 100: i1IIi
  if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
  I1IIiiiiI1iIi , i1II1IiIIi = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  if ( i1II1IiIIi != 0 ) : return ( None )
  if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
  packet = packet [ IiiiiI : : ]
  Iii1I = "IBBH"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 71 - 71: IiII + OoO0O00
  O0OOo , i1Ii1II , Iii1iii1II , iIIi1iIi11 = struct . unpack ( Iii1I ,
 packet [ : IiiiiI ] )
  if 17 - 17: iIii1I11I1II1
  if ( iIIi1iIi11 != 0 ) : return ( None )
  packet = packet [ IiiiiI : : ]
  if 10 - 10: i11iIiiIii / iII111i - oO0o
  if 98 - 98: Ii1I % iII111i . I11i
  if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i % o0oOOo0O0Ooo . ooOoO0o - oO0o
  if 64 - 64: I11i * ooOoO0o
  if ( self . info_reply == False ) :
   Iii1I = "H"
   IiiiiI = struct . calcsize ( Iii1I )
   if ( len ( packet ) >= IiiiiI ) :
    i1I1iiiI = struct . unpack ( Iii1I , packet [ : IiiiiI ] ) [ 0 ]
    if ( socket . ntohs ( i1I1iiiI ) == LISP_AFI_NAME ) :
     packet = packet [ IiiiiI : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 86 - 86: OoooooooOO * I1IiiI
     if 88 - 88: Ii1I + O0
   return ( iII111I )
   if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
   if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
   if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
   if 85 - 85: OoooooooOO * ooOoO0o
   if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
  Iii1I = "HHBBHHH"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
  i1I1iiiI , Ii1i1I1Ii , iIiI1 , i1Ii1II , I11IiI1III , OOoOOO , I1iiiI1i = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  if 26 - 26: O0 % o0oOOo0O0Ooo + iII111i * I1ii11iIi11i * I1Ii111
  if 4 - 4: OOooOOo * OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
  if ( socket . ntohs ( i1I1iiiI ) != LISP_AFI_LCAF ) : return ( None )
  if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
  self . ms_port = socket . ntohs ( OOoOOO )
  self . etr_port = socket . ntohs ( I1iiiI1i )
  packet = packet [ IiiiiI : : ]
  if 62 - 62: I1Ii111 % II111iiii
  if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
  if 91 - 91: i11iIiiIii + Ii1I
  if 85 - 85: I11i % IiII
  Iii1I = "H"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
  if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
  if 24 - 24: ooOoO0o - I1Ii111 * II111iiii - II111iiii
  if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
  i1I1iiiI = struct . unpack ( Iii1I , packet [ : IiiiiI ] ) [ 0 ]
  packet = packet [ IiiiiI : : ]
  if ( i1I1iiiI != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( i1I1iiiI )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 93 - 93: Ii1I / iII111i
   if 100 - 100: Oo0Ooo
   if 94 - 94: I1ii11iIi11i / i1IIi * I1IiiI - I11i - I1ii11iIi11i
   if 6 - 6: I1ii11iIi11i % o0oOOo0O0Ooo + o0oOOo0O0Ooo / OOooOOo / I1IiiI
   if 67 - 67: OoOoOO00 . iII111i / OOooOOo * ooOoO0o + i1IIi
   if 100 - 100: OOooOOo . ooOoO0o + I1Ii111 . oO0o
  if ( len ( packet ) < IiiiiI ) : return ( iII111I )
  if 20 - 20: i11iIiiIii - i1IIi - iIii1I11I1II1 - OoooooooOO
  i1I1iiiI = struct . unpack ( Iii1I , packet [ : IiiiiI ] ) [ 0 ]
  packet = packet [ IiiiiI : : ]
  if ( i1I1iiiI != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( i1I1iiiI )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( iII111I )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 72 - 72: I1Ii111 . OoO0O00
   if 59 - 59: I1IiiI * I11i % i1IIi
   if 77 - 77: OOooOOo * OoooooooOO + I1IiiI + I1IiiI % oO0o . OoooooooOO
   if 60 - 60: iIii1I11I1II1
   if 13 - 13: II111iiii + Ii1I
  if ( len ( packet ) < IiiiiI ) : return ( iII111I )
  if 33 - 33: i1IIi
  i1I1iiiI = struct . unpack ( Iii1I , packet [ : IiiiiI ] ) [ 0 ]
  packet = packet [ IiiiiI : : ]
  if ( i1I1iiiI != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( i1I1iiiI )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( iII111I )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 36 - 36: ooOoO0o % ooOoO0o . i11iIiiIii
   if 42 - 42: OoO0O00 . I1Ii111 / Ii1I
   if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / oO0o . OoOoOO00
   if 74 - 74: I1IiiI * OoO0O00 + OoooooooOO * ooOoO0o . oO0o
   if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
   if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
  while ( len ( packet ) >= IiiiiI ) :
   i1I1iiiI = struct . unpack ( Iii1I , packet [ : IiiiiI ] ) [ 0 ]
   packet = packet [ IiiiiI : : ]
   if ( i1I1iiiI == 0 ) : continue
   IiIi1I1i1iIiI = lisp_address ( socket . ntohs ( i1I1iiiI ) , "" , 0 , 0 )
   packet = IiIi1I1i1iIiI . unpack_address ( packet )
   if ( packet == None ) : return ( iII111I )
   IiIi1I1i1iIiI . mask_len = IiIi1I1i1iIiI . host_mask_len ( )
   self . rtr_list . append ( IiIi1I1i1iIiI )
   if 81 - 81: i1IIi % iIii1I11I1II1
  return ( iII111I )
  if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
  if 82 - 82: ooOoO0o
  if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
class lisp_nat_info ( ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
  if 59 - 59: i11iIiiIii / OoO0O00
 def timed_out ( self ) :
  Ii1i1 = time . time ( ) - self . uptime
  return ( Ii1i1 >= ( LISP_INFO_INTERVAL * 2 ) )
  if 48 - 48: iIii1I11I1II1
  if 19 - 19: oO0o
  if 69 - 69: I1ii11iIi11i % iII111i - OoooooooOO % Ii1I * oO0o
class lisp_info_source ( ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 12 - 12: OoOoOO00 / I1Ii111 . O0 . IiII - OOooOOo - OoO0O00
  if 28 - 28: II111iiii . OoOoOO00 - o0oOOo0O0Ooo
 def cache_address_for_info_source ( self ) :
  OO0Oo00o0o0 = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ OO0Oo00o0o0 ] = self
  if 89 - 89: I1Ii111 * OoooooooOO . OOooOOo . I11i % i11iIiiIii
  if 8 - 8: I1ii11iIi11i + II111iiii . OoO0O00 + I1IiiI - II111iiii % OoO0O00
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
  if 85 - 85: i11iIiiIii % iII111i + II111iiii
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
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 73 - 73: iII111i
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 45 - 45: oO0o % O0 / O0
  if 98 - 98: I1Ii111
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  Oo0OO0o0oOO0 = auth1 + auth2 + auth3
  if 58 - 58: OOooOOo
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  Oo0OO0o0oOO0 = auth1 + auth2 + auth3 + auth4
  if 6 - 6: I1ii11iIi11i
 return ( Oo0OO0o0oOO0 )
 if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
 if 18 - 18: ooOoO0o
 if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
 if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
 if 29 - 29: Ii1I . II111iiii / I1Ii111
 if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
 if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
 if 81 - 81: i11iIiiIii - II111iiii + I11i
 if 52 - 52: II111iiii
 if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   iIIiIiiI = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 60 - 60: iIii1I11I1II1
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   iIIiIiiI = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 70 - 70: I11i
  iIIiIiiI . bind ( ( local_addr , int ( port ) ) )
 else :
  Iii = port
  if ( os . path . exists ( Iii ) ) :
   os . system ( "rm " + Iii )
   time . sleep ( 1 )
   if 38 - 38: o0oOOo0O0Ooo . OoO0O00 + I1ii11iIi11i - I1IiiI * i1IIi
  iIIiIiiI = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  iIIiIiiI . bind ( Iii )
  if 17 - 17: OoO0O00 % o0oOOo0O0Ooo
 return ( iIIiIiiI )
 if 21 - 21: OOooOOo + OOooOOo - i11iIiiIii * IiII % iIii1I11I1II1
 if 86 - 86: ooOoO0o + OoOoOO00
 if 94 - 94: IiII
 if 30 - 30: o0oOOo0O0Ooo % OoOoOO00 * IiII % iIii1I11I1II1 % O0
 if 76 - 76: II111iiii * I11i
 if 29 - 29: OoooooooOO . i1IIi
 if 46 - 46: I11i
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   iIIiIiiI = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 92 - 92: IiII * OoO0O00 . OoOoOO00 + iII111i - I1IiiI
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   iIIiIiiI = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 15 - 15: OoO0O00 / OoO0O00 * o0oOOo0O0Ooo * I1ii11iIi11i - o0oOOo0O0Ooo
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  iIIiIiiI = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  iIIiIiiI . bind ( internal_name )
  if 47 - 47: I1IiiI / OoOoOO00 / II111iiii
 return ( iIIiIiiI )
 if 7 - 7: oO0o . ooOoO0o
 if 73 - 73: i1IIi % I1Ii111 * ooOoO0o % OoO0O00
 if 70 - 70: ooOoO0o * I1ii11iIi11i
 if 26 - 26: i11iIiiIii - II111iiii . II111iiii * oO0o / Ii1I + I1IiiI
 if 12 - 12: OoO0O00 * iIii1I11I1II1 % I1Ii111 . O0 * OoOoOO00 * OOooOOo
 if 34 - 34: I1IiiI . i1IIi
 if 38 - 38: iIii1I11I1II1
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 64 - 64: i1IIi / OoO0O00
 if 68 - 68: I11i * O0 * oO0o + OoOoOO00 / IiII
 if 42 - 42: iIii1I11I1II1 % i1IIi - OoOoOO00 % I1ii11iIi11i * Ii1I + i11iIiiIii
 if 40 - 40: OOooOOo
 if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
 if 94 - 94: IiII
 if 69 - 69: I1Ii111 . I1Ii111
 if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
 if 8 - 8: iII111i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I % I11i / I1Ii111
 if 21 - 21: OoO0O00 + Ii1I / I1Ii111
 if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
 if 38 - 38: i1IIi
 if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
 if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
 if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
 if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
 if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
 if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
 if 2 - 2: OOooOOo / I11i * I11i + I11i / O0 - OOooOOo
 if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
 if 68 - 68: iII111i / OOooOOo
 if 28 - 28: II111iiii
 if 49 - 49: I1ii11iIi11i
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 33 - 33: iIii1I11I1II1
 if 72 - 72: I1ii11iIi11i * i11iIiiIii
 if 12 - 12: O0 - iIii1I11I1II1 % Oo0Ooo / O0 - IiII
 if 55 - 55: OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * i11iIiiIii + oO0o
 if 45 - 45: Ii1I
 if 8 - 8: oO0o + OOooOOo
 if 37 - 37: IiII - OoOoOO00 + oO0o - Oo0Ooo + IiII
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 33 - 33: Oo0Ooo % oO0o - I1IiiI + Oo0Ooo
 if 90 - 90: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1 % IiII * I1Ii111 . I1Ii111
 if 90 - 90: o0oOOo0O0Ooo - O0 % O0 - oO0o . OoooooooOO
 if 30 - 30: I11i + O0 / Ii1I / OoOoOO00 - oO0o + II111iiii
 if 21 - 21: iIii1I11I1II1 % OoooooooOO * OOooOOo % i1IIi
 if 73 - 73: OoooooooOO
 if 100 - 100: I11i / i1IIi / i1IIi % Ii1I - II111iiii . OoooooooOO
 if 72 - 72: Oo0Ooo * OoooooooOO % I1IiiI + I11i - II111iiii
 if 82 - 82: iIii1I11I1II1 / i1IIi * I1IiiI . i11iIiiIii
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 56 - 56: Ii1I * I1IiiI / ooOoO0o * II111iiii
 if 51 - 51: i1IIi . oO0o % OOooOOo
 if 90 - 90: OoooooooOO + iII111i / iIii1I11I1II1
 if 12 - 12: OoooooooOO
 if 9 - 9: O0 / O0 / I1IiiI - oO0o . ooOoO0o
 if 6 - 6: O0 - OoO0O00 + OoooooooOO % iIii1I11I1II1
 if 58 - 58: i11iIiiIii * OOooOOo . Oo0Ooo / iII111i - i1IIi
 if 45 - 45: Ii1I
 if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
 if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
 if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
 if 86 - 86: iII111i / i1IIi % Oo0Ooo
 if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
 if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
 if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
 if 14 - 14: OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
 if 92 - 92: OoO0O00 . i1IIi
def lisp_ipc ( packet , send_socket , node ) :
 if 22 - 22: Ii1I . I1IiiI
 if 54 - 54: OOooOOo / I1ii11iIi11i % oO0o
 if 66 - 66: I11i + iII111i
 if 50 - 50: IiII
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
  if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
 OOOOOooo = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 26 - 26: Oo0Ooo / I1IiiI
 IiI1ii1Ii = 0
 i1iIii = len ( packet )
 I11iIIii = 0
 iiIIiII1i = .001
 while ( i1iIii > 0 ) :
  i1111iIi = min ( i1iIii , OOOOOooo )
  I1iIi1iiIIII = packet [ IiI1ii1Ii : i1111iIi + IiI1ii1Ii ]
  if 26 - 26: i1IIi - II111iiii - Ii1I * i1IIi * OoOoOO00
  try :
   send_socket . sendto ( I1iIi1iiIIII , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( I1iIi1iiIIII ) , len ( packet ) , node ) )
   if 99 - 99: IiII / oO0o % ooOoO0o / Oo0Ooo * OoO0O00
   I11iIIii = 0
   iiIIiII1i = .001
   if 43 - 43: ooOoO0o
  except socket . error as I1i :
   if ( I11iIIii == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 86 - 86: ooOoO0o
    if 65 - 65: OoOoOO00
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( I1iIi1iiIIII ) , len ( packet ) , node , I1i ) )
   if 15 - 15: Ii1I - OoOoOO00
   if 27 - 27: O0
   I11iIIii += 1
   time . sleep ( iiIIiII1i )
   if 86 - 86: IiII + Ii1I / Oo0Ooo / O0 % iII111i - oO0o
   lprint ( "Retrying after {} ms ..." . format ( iiIIiII1i * 1000 ) )
   iiIIiII1i *= 2
   continue
   if 3 - 3: i11iIiiIii / I1ii11iIi11i % I1Ii111 + o0oOOo0O0Ooo + O0
   if 42 - 42: IiII / i11iIiiIii % o0oOOo0O0Ooo / II111iiii / IiII
  IiI1ii1Ii += i1111iIi
  i1iIii -= i1111iIi
  if 97 - 97: OOooOOo . OoOoOO00 / I11i - IiII - iIii1I11I1II1
 return
 if 82 - 82: II111iiii + OoO0O00 % iIii1I11I1II1 / O0
 if 75 - 75: OOooOOo * OoO0O00 + OoooooooOO + i11iIiiIii . OoO0O00
 if 94 - 94: I11i * ooOoO0o . I1IiiI / Ii1I - I1IiiI % OoooooooOO
 if 32 - 32: OoO0O00
 if 22 - 22: II111iiii . I11i
 if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
 if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 IiI1ii1Ii = 0
 O00o0OoO0OOOo = ""
 i1iIii = len ( packet ) * 2
 while ( IiI1ii1Ii < i1iIii ) :
  O00o0OoO0OOOo += packet [ IiI1ii1Ii : IiI1ii1Ii + 8 ] + " "
  IiI1ii1Ii += 8
  i1iIii -= 4
  if 94 - 94: OOooOOo / IiII
 return ( O00o0OoO0OOOo )
 if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
 if 22 - 22: OoOoOO00 - Oo0Ooo
 if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
 if 33 - 33: I11i + O0
 if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
 if 68 - 68: O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
 if 12 - 12: II111iiii + I11i
def lisp_send ( lisp_sockets , dest , port , packet ) :
 iIiIIi1i = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 92 - 92: Ii1I % o0oOOo0O0Ooo
 if 55 - 55: I11i + ooOoO0o / ooOoO0o % I1ii11iIi11i
 if 84 - 84: O0 + IiII - I1IiiI - I1Ii111 / OoooooooOO
 if 76 - 76: i11iIiiIii - Ii1I * I1ii11iIi11i + oO0o - OOooOOo
 if 42 - 42: o0oOOo0O0Ooo
 if 37 - 37: ooOoO0o / oO0o % O0 + Ii1I / OOooOOo
 if 14 - 14: I11i
 if 83 - 83: OoOoOO00 * iII111i
 if 75 - 75: i11iIiiIii . o0oOOo0O0Ooo / oO0o . OoO0O00 % Ii1I % Ii1I
 if 94 - 94: iII111i . Ii1I
 if 71 - 71: o0oOOo0O0Ooo * II111iiii / OOooOOo . OoO0O00
 if 73 - 73: I1Ii111 * OoO0O00 / OoOoOO00 . II111iiii
 iIIiiiI = dest . print_address_no_iid ( )
 if ( iIIiiiI . find ( "::ffff:" ) != - 1 and iIIiiiI . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : iIiIIi1i = lisp_sockets [ 0 ]
  if ( iIiIIi1i == None ) :
   iIiIIi1i = lisp_sockets [ 0 ]
   iIIiiiI = iIIiiiI . split ( "::ffff:" ) [ - 1 ]
   if 87 - 87: OoO0O00 + Oo0Ooo + O0 % OoooooooOO - iIii1I11I1II1
   if 100 - 100: Oo0Ooo + IiII
   if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + iIIiiiI , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 19 - 19: ooOoO0o + i1IIi / Oo0Ooo * II111iiii * I1Ii111 / ooOoO0o
 if 23 - 23: I1Ii111
 if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
 if 75 - 75: I11i . Ii1I / I1ii11iIi11i
 o00O0O0oOo0 = ( LISP_RLOC_PROBE_TTL == 128 )
 if ( o00O0O0oOo0 ) :
  II11ii = struct . unpack ( "B" , packet [ 0 ] ) [ 0 ]
  o00O0O0oOo0 = ( II11ii in [ 0x12 , 0x28 ] )
  if ( o00O0O0oOo0 ) : lisp_set_ttl ( iIiIIi1i , LISP_RLOC_PROBE_TTL )
  if 79 - 79: OOooOOo / Ii1I / i11iIiiIii / I11i % I11i % I11i
  if 6 - 6: iIii1I11I1II1 - I1Ii111 / I11i . i11iIiiIii
 try : iIiIIi1i . sendto ( packet , ( iIIiiiI , port ) )
 except socket . error as I1i :
  lprint ( "socket.sendto() failed: {}" . format ( I1i ) )
  if 20 - 20: OOooOOo % oO0o
  if 54 - 54: II111iiii / Ii1I + Oo0Ooo . o0oOOo0O0Ooo + I1Ii111
  if 27 - 27: o0oOOo0O0Ooo . I11i
  if 63 - 63: iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii + oO0o * II111iiii
  if 85 - 85: iII111i / Oo0Ooo . OOooOOo
 if ( o00O0O0oOo0 ) : lisp_set_ttl ( iIiIIi1i , 64 )
 return
 if 54 - 54: OoooooooOO - II111iiii
 if 33 - 33: OoOoOO00 - ooOoO0o - o0oOOo0O0Ooo - i1IIi + I11i
 if 14 - 14: iII111i / oO0o . oO0o - OOooOOo * i1IIi - i1IIi
 if 70 - 70: OoooooooOO
 if 60 - 60: OOooOOo - Ii1I * Ii1I
 if 69 - 69: i11iIiiIii . IiII + o0oOOo0O0Ooo % Ii1I - OoO0O00
 if 46 - 46: OoOoOO00 + iII111i * o0oOOo0O0Ooo - I1ii11iIi11i / oO0o + IiII
 if 1 - 1: iIii1I11I1II1 / OoooooooOO + Oo0Ooo . Ii1I
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 25 - 25: I1ii11iIi11i / i1IIi * oO0o - II111iiii * i1IIi
 if 57 - 57: OoO0O00 % OoO0O00
 if 67 - 67: O0 . i11iIiiIii + iIii1I11I1II1
 if 86 - 86: iIii1I11I1II1
 if 81 - 81: OOooOOo / I11i / OoooooooOO
 i1111iIi = total_length - len ( packet )
 if ( i1111iIi == 0 ) : return ( [ True , packet ] )
 if 74 - 74: I11i + OoooooooOO % II111iiii % o0oOOo0O0Ooo
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 27 - 27: OoO0O00 * Oo0Ooo
 if 80 - 80: i11iIiiIii . OoO0O00 - I11i % I11i
 if 21 - 21: I1IiiI . OoO0O00 * IiII % OoooooooOO - Oo0Ooo + Oo0Ooo
 if 94 - 94: ooOoO0o
 if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
 i1iIii = i1111iIi
 while ( i1iIii > 0 ) :
  try : I1iIi1iiIIII = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 95 - 95: II111iiii
  I1iIi1iiIIII = I1iIi1iiIIII [ 0 ]
  if 76 - 76: OoO0O00 % iII111i * OoOoOO00 / ooOoO0o / i1IIi
  if 45 - 45: Ii1I . I11i * I1Ii111 . i11iIiiIii
  if 34 - 34: O0 * o0oOOo0O0Ooo / IiII
  if 75 - 75: I1Ii111 - i1IIi - OoO0O00
  if 25 - 25: iII111i . o0oOOo0O0Ooo
  if ( I1iIi1iiIIII . find ( "packet@" ) == 0 ) :
   O0ooOO = I1iIi1iiIIII . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( I1iIi1iiIIII ) ,
   # II111iiii % ooOoO0o % I1Ii111 . II111iiii
 O0ooOO [ 1 ] if len ( O0ooOO ) > 2 else "?" )
   return ( [ False , I1iIi1iiIIII ] )
   if 88 - 88: I1ii11iIi11i - iIii1I11I1II1 / iII111i
   if 69 - 69: o0oOOo0O0Ooo % o0oOOo0O0Ooo . i11iIiiIii
  i1iIii -= len ( I1iIi1iiIIII )
  packet += I1iIi1iiIIII
  if 34 - 34: Oo0Ooo - i11iIiiIii
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( I1iIi1iiIIII ) , total_length , source ) )
  if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
  if 19 - 19: I1IiiI
 return ( [ True , packet ] )
 if 99 - 99: OOooOOo - OOooOOo
 if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
 if 83 - 83: o0oOOo0O0Ooo
 if 23 - 23: o0oOOo0O0Ooo . I11i
 if 67 - 67: iII111i
 if 52 - 52: IiII . OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / IiII . OoooooooOO . Oo0Ooo / ooOoO0o + O0
 if 38 - 38: I11i
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 o0o0ooOOo0oO = ""
 for I1iIi1iiIIII in payload : o0o0ooOOo0oO += I1iIi1iiIIII + "\x40"
 return ( o0o0ooOOo0oO [ : - 1 ] )
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
 if 56 - 56: oO0o
 if 55 - 55: iIii1I11I1II1 % oO0o % OOooOOo / I1Ii111 * OoooooooOO / Oo0Ooo
 if 88 - 88: I11i + OoO0O00 . iIii1I11I1II1 . II111iiii
 if 67 - 67: OOooOOo - ooOoO0o % iII111i % IiII
 if 71 - 71: OoO0O00 - ooOoO0o - I1IiiI + O0
 if 15 - 15: i1IIi
 if 43 - 43: II111iiii + OOooOOo . i11iIiiIii - II111iiii
 if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
 if 26 - 26: i1IIi - I1IiiI + IiII / OoO0O00 . I1ii11iIi11i
 if 82 - 82: I1Ii111 % iII111i . OoOoOO00 % OoO0O00 + I1ii11iIi11i
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 69 - 69: I1IiiI * OoOoOO00 - ooOoO0o . O0
  if 15 - 15: oO0o . IiII + I1Ii111 - OoooooooOO
  if 85 - 85: II111iiii - Oo0Ooo + oO0o . i11iIiiIii + Oo0Ooo
  if 86 - 86: ooOoO0o . OoO0O00
  try : i1i1i11i11 = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 9 - 9: Ii1I + OoO0O00 - I1IiiI % II111iiii - I1Ii111
  if 88 - 88: Ii1I - OOooOOo + Oo0Ooo . OoooooooOO
  if 50 - 50: i11iIiiIii % Oo0Ooo . I1Ii111
  if 96 - 96: iIii1I11I1II1 % iIii1I11I1II1
  if 18 - 18: iII111i . Oo0Ooo
  if 4 - 4: o0oOOo0O0Ooo % oO0o - OoOoOO00 * iIii1I11I1II1
  if ( internal == False ) :
   o0o0ooOOo0oO = i1i1i11i11 [ 0 ]
   iIiI111ii1Ii = lisp_convert_6to4 ( i1i1i11i11 [ 1 ] [ 0 ] )
   IiO0o = i1i1i11i11 [ 1 ] [ 1 ]
   if 96 - 96: Ii1I
   if ( IiO0o == LISP_DATA_PORT ) :
    iiii1IIIi1 = lisp_data_plane_logging
    oo0 = lisp_format_packet ( o0o0ooOOo0oO [ 0 : 60 ] ) + " ..."
   else :
    iiii1IIIi1 = True
    oo0 = lisp_format_packet ( o0o0ooOOo0oO )
    if 72 - 72: O0
    if 15 - 15: II111iiii / I11i % II111iiii % Ii1I % i11iIiiIii / I1Ii111
   if ( iiii1IIIi1 ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( o0o0ooOOo0oO ) , bold ( "from " + iIiI111ii1Ii , False ) , IiO0o ,
 oo0 ) )
    if 93 - 93: OOooOOo / OoooooooOO % iII111i
   return ( [ "packet" , iIiI111ii1Ii , IiO0o , o0o0ooOOo0oO ] )
   if 47 - 47: o0oOOo0O0Ooo - I1IiiI % O0 % I1Ii111 . O0 . OoOoOO00
   if 95 - 95: o0oOOo0O0Ooo * OOooOOo - iII111i * OoooooooOO - ooOoO0o / I1IiiI
   if 47 - 47: OoO0O00 % I1IiiI / OoOoOO00 - I1Ii111 / I1IiiI
   if 13 - 13: o0oOOo0O0Ooo % ooOoO0o
   if 15 - 15: iII111i * I1IiiI . iIii1I11I1II1 % I1IiiI / O0
   if 47 - 47: OoooooooOO - i11iIiiIii . I1IiiI / i1IIi
  oo0OOOOooOOo0 = False
  iiii1II = i1i1i11i11 [ 0 ]
  ooOo000OO = False
  if 19 - 19: iIii1I11I1II1 % OOooOOo . i11iIiiIii
  while ( oo0OOOOooOOo0 == False ) :
   iiii1II = iiii1II . split ( "@" )
   if 85 - 85: II111iiii * i1IIi * iIii1I11I1II1 - O0 % I1Ii111
   if ( len ( iiii1II ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( iiii1II [ 0 ] ) )
    if 36 - 36: Oo0Ooo * I11i / I1Ii111 / i1IIi
    ooOo000OO = True
    break
    if 60 - 60: iII111i + Oo0Ooo % i1IIi / II111iiii
    if 59 - 59: iII111i - O0 + Ii1I
   OoOO0 = iiii1II [ 0 ]
   try :
    oOoOO0OO = int ( iiii1II [ 1 ] )
   except :
    OoOOOoO0oo0 = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( OoOOOoO0oo0 , i1i1i11i11 ) )
    ooOo000OO = True
    break
    if 59 - 59: I1Ii111
   iIiI111ii1Ii = iiii1II [ 2 ]
   IiO0o = iiii1II [ 3 ]
   if 22 - 22: OoooooooOO
   if 88 - 88: I1Ii111 - OoO0O00
   if 29 - 29: I1IiiI . I1Ii111
   if 74 - 74: Oo0Ooo / OoOoOO00 + OoOoOO00 % i11iIiiIii . OoO0O00 + ooOoO0o
   if 77 - 77: ooOoO0o . I11i + OoooooooOO
   if 100 - 100: ooOoO0o . oO0o % I1ii11iIi11i . IiII * IiII - o0oOOo0O0Ooo
   if 49 - 49: iIii1I11I1II1 % Ii1I / OoooooooOO - II111iiii . Ii1I
   if 65 - 65: OoooooooOO + I1Ii111 % ooOoO0o + II111iiii . i1IIi + OoooooooOO
   if ( len ( iiii1II ) > 5 ) :
    o0o0ooOOo0oO = lisp_bit_stuff ( iiii1II [ 4 : : ] )
   else :
    o0o0ooOOo0oO = iiii1II [ 4 ]
    if 26 - 26: I1IiiI / II111iiii % I1ii11iIi11i * o0oOOo0O0Ooo . IiII / OoO0O00
    if 10 - 10: i11iIiiIii / i1IIi + O0 - i11iIiiIii % I11i - i1IIi
    if 38 - 38: O0 - I1IiiI + Oo0Ooo + ooOoO0o
    if 56 - 56: I1Ii111 + oO0o / Ii1I + I1Ii111
    if 21 - 21: OOooOOo / OoOoOO00 + OoOoOO00 + OoOoOO00 - i1IIi + Ii1I
    if 43 - 43: O0 % II111iiii
   oo0OOOOooOOo0 , o0o0ooOOo0oO = lisp_receive_segments ( lisp_socket , o0o0ooOOo0oO ,
 iIiI111ii1Ii , oOoOO0OO )
   if ( o0o0ooOOo0oO == None ) : return ( [ "" , "" , "" , "" ] )
   if 60 - 60: iII111i / ooOoO0o - Ii1I - OoooooooOO
   if 79 - 79: oO0o / iII111i . iIii1I11I1II1 * i11iIiiIii * i1IIi . iIii1I11I1II1
   if 31 - 31: OoooooooOO / ooOoO0o / OoooooooOO + ooOoO0o . O0 - IiII
   if 53 - 53: Oo0Ooo % iII111i % iII111i
   if 71 - 71: iII111i
   if ( oo0OOOOooOOo0 == False ) :
    iiii1II = o0o0ooOOo0oO
    continue
    if 99 - 99: O0 - OoOoOO00 * I1Ii111 - Oo0Ooo
    if 62 - 62: i1IIi + ooOoO0o + Oo0Ooo - i11iIiiIii
   if ( IiO0o == "" ) : IiO0o = "no-port"
   if ( OoOO0 == "command" and lisp_i_am_core == False ) :
    I1i11II = o0o0ooOOo0oO . find ( " {" )
    ii1i = o0o0ooOOo0oO if I1i11II == - 1 else o0o0ooOOo0oO [ : I1i11II ]
    ii1i = ": '" + ii1i + "'"
   else :
    ii1i = ""
    if 51 - 51: ooOoO0o - I1Ii111 * oO0o
    if 47 - 47: Oo0Ooo % OoO0O00 * Ii1I / OoOoOO00
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( o0o0ooOOo0oO ) , bold ( "from " + iIiI111ii1Ii , False ) , IiO0o , OoOO0 ,
 ii1i if ( OoOO0 in [ "command" , "api" ] ) else ": ... " if ( OoOO0 == "data-packet" ) else ": " + lisp_format_packet ( o0o0ooOOo0oO ) ) )
   if 1 - 1: I1IiiI
   if 68 - 68: ooOoO0o
   if 68 - 68: I11i % IiII
   if 1 - 1: I1IiiI + OOooOOo - OOooOOo * O0 + o0oOOo0O0Ooo * OOooOOo
   if 48 - 48: ooOoO0o - iII111i + I1ii11iIi11i * I1Ii111 % ooOoO0o * OoO0O00
  if ( ooOo000OO ) : continue
  return ( [ OoOO0 , iIiI111ii1Ii , IiO0o , o0o0ooOOo0oO ] )
  if 28 - 28: i1IIi / iII111i + OOooOOo
  if 89 - 89: Oo0Ooo + II111iiii * OoO0O00 + Oo0Ooo % II111iiii
  if 59 - 59: O0 + Oo0Ooo
  if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
  if 50 - 50: I11i . I11i % I1IiiI - i1IIi
  if 63 - 63: OoO0O00 . iII111i
  if 28 - 28: ooOoO0o . Oo0Ooo - OoooooooOO - I1Ii111 - OoooooooOO - oO0o
  if 25 - 25: I11i / I1Ii111 . i11iIiiIii % i1IIi
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 Iii1i111ii1i = False
 iIIiiIiI = time . time ( )
 if 70 - 70: Oo0Ooo * i11iIiiIii + IiII / OoOoOO00 . I1ii11iIi11i % OoOoOO00
 OoOOoo0o00O0oO = lisp_control_header ( )
 if ( OoOOoo0o00O0oO . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( Iii1i111ii1i )
  if 12 - 12: I11i % II111iiii % O0 % O0
  if 18 - 18: iII111i . IiII . I1IiiI
  if 40 - 40: IiII / oO0o + OoooooooOO / iII111i / II111iiii + i1IIi
  if 33 - 33: I11i + I1ii11iIi11i + i11iIiiIii * I1IiiI % oO0o % OoooooooOO
  if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
 oo0iiiI = source
 if ( source . find ( "lisp" ) == - 1 ) :
  I1iiIi111I = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  I1iiIi111I . string_to_afi ( source )
  I1iiIi111I . store_address ( source )
  source = I1iiIi111I
  if 37 - 37: II111iiii - OOooOOo % I1Ii111 * i1IIi
  if 42 - 42: I1Ii111 . ooOoO0o - O0 + i11iIiiIii
 if ( OoOOoo0o00O0oO . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl , iIIiiIiI )
  if 81 - 81: iIii1I11I1II1 - OoO0O00 . i11iIiiIii
 elif ( OoOOoo0o00O0oO . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl , iIIiiIiI )
  if 4 - 4: o0oOOo0O0Ooo / OoO0O00 - I11i
 elif ( OoOOoo0o00O0oO . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 52 - 52: II111iiii . iII111i
 elif ( OoOOoo0o00O0oO . type == LISP_MAP_NOTIFY ) :
  if ( oo0iiiI == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-rtr" ) ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-itr" ) ) :
   lisp_process_unicast_map_notify ( lisp_sockets , packet , source )
   if 36 - 36: I1IiiI * II111iiii
   if 68 - 68: oO0o * o0oOOo0O0Ooo + OoooooooOO - I1ii11iIi11i * i1IIi % OOooOOo
 elif ( OoOOoo0o00O0oO . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 39 - 39: I1Ii111 / I11i + oO0o / I1Ii111 % IiII * I1ii11iIi11i
 elif ( OoOOoo0o00O0oO . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 66 - 66: I1ii11iIi11i * ooOoO0o . i11iIiiIii * Oo0Ooo - I11i . I1IiiI
 elif ( OoOOoo0o00O0oO . type == LISP_NAT_INFO and OoOOoo0o00O0oO . is_info_reply ( ) ) :
  Ii1i1I1Ii , I1iI1 , Iii1i111ii1i = lisp_process_info_reply ( source , packet , True )
  if 43 - 43: I11i . iII111i . IiII - oO0o
 elif ( OoOOoo0o00O0oO . type == LISP_NAT_INFO and OoOOoo0o00O0oO . is_info_reply ( ) == False ) :
  O0O0 = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , O0O0 , udp_sport ,
 None )
  if 60 - 60: i1IIi + iII111i * i1IIi . iII111i
 elif ( OoOOoo0o00O0oO . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 40 - 40: i1IIi . OoO0O00
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( OoOOoo0o00O0oO . type ) )
  if 65 - 65: Oo0Ooo
 return ( Iii1i111ii1i )
 if 81 - 81: OOooOOo % OoooooooOO / IiII . Oo0Ooo - ooOoO0o . I1IiiI
 if 3 - 3: O0
 if 95 - 95: i11iIiiIii
 if 100 - 100: iIii1I11I1II1 * I1IiiI * Ii1I * i1IIi . I1Ii111 * I1IiiI
 if 54 - 54: o0oOOo0O0Ooo / iII111i + IiII - o0oOOo0O0Ooo - I11i
 if 28 - 28: I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * IiII + OoooooooOO
 if 52 - 52: I1Ii111
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp ) :
 if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
 IIIiIIi111 = bold ( "RLOC-probe" , False )
 if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( IIIiIIi111 ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 73 - 73: iII111i - o0oOOo0O0Ooo / OOooOOo + iII111i + o0oOOo0O0Ooo % II111iiii
  if 74 - 74: I11i * iIii1I11I1II1 - OoO0O00 / i1IIi / OoO0O00 / IiII
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( IIIiIIi111 ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
  if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( IIIiIIi111 ) )
 return
 if 77 - 77: OoOoOO00 + IiII + Oo0Ooo
 if 88 - 88: i1IIi
 if 45 - 45: iII111i % I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
 if 55 - 55: OoO0O00 % IiII
 if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
 if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
 if 63 - 63: I1Ii111 + iII111i
 if 6 - 6: I1ii11iIi11i + Ii1I
 if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 97 - 97: ooOoO0o + OOooOOo
 if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
 if 6 - 6: Oo0Ooo + I1IiiI
 if 48 - 48: oO0o . I1ii11iIi11i
 if 59 - 59: IiII - Ii1I
 if 62 - 62: OOooOOo * o0oOOo0O0Ooo + IiII * o0oOOo0O0Ooo * i11iIiiIii - O0
 if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , map_request ,
 keys , enc , auth , mr_ttl = - 1 ) :
 if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
 oO0O = map_request . rloc_probe if ( map_request != None ) else False
 O0O0O = map_request . json_telemetry if ( map_request != None ) else None
 if 46 - 46: II111iiii % iIii1I11I1II1 * i11iIiiIii
 if 24 - 24: II111iiii . OoO0O00 % II111iiii / I11i
 iIO0OOoOOO0OO = lisp_map_reply ( )
 iIO0OOoOOO0OO . rloc_probe = oO0O
 iIO0OOoOOO0OO . echo_nonce_capable = enc
 iIO0OOoOOO0OO . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 iIO0OOoOOO0OO . record_count = 1
 iIO0OOoOOO0OO . nonce = nonce
 o0o0ooOOo0oO = iIO0OOoOOO0OO . encode ( )
 iIO0OOoOOO0OO . print_map_reply ( )
 if 86 - 86: I1IiiI - o0oOOo0O0Ooo
 oOO0O0o0oOooO = lisp_eid_record ( )
 oOO0O0o0oOooO . rloc_count = len ( rloc_set )
 if ( O0O0O != None ) : oOO0O0o0oOooO . rloc_count += 1
 oOO0O0o0oOooO . authoritative = auth
 oOO0O0o0oOooO . record_ttl = ttl
 oOO0O0o0oOooO . action = action
 oOO0O0o0oOooO . eid = eid
 oOO0O0o0oOooO . group = group
 if 2 - 2: Oo0Ooo
 o0o0ooOOo0oO += oOO0O0o0oOooO . encode ( )
 oOO0O0o0oOooO . print_record ( "  " , False )
 if 80 - 80: I1Ii111 * II111iiii % Oo0Ooo * ooOoO0o + o0oOOo0O0Ooo
 ooo0oOO0OoOo0 = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 23 - 23: I1ii11iIi11i + II111iiii
 OOiIiIiiiI11i1 = None
 for O0O0OOo0O in rloc_set :
  o0OooO = O0O0OOo0O . rloc . is_multicast_address ( )
  iIIi = lisp_rloc_record ( )
  o0ooo0OOOoOo = oO0O and ( o0OooO or O0O0O == None )
  O0O0 = O0O0OOo0O . rloc . print_address_no_iid ( )
  if ( O0O0 in ooo0oOO0OoOo0 or o0OooO ) :
   iIIi . local_bit = True
   iIIi . probe_bit = o0ooo0OOOoOo
   iIIi . keys = keys
   if ( O0O0OOo0O . priority == 254 and lisp_i_am_rtr ) :
    iIIi . rloc_name = "RTR"
    if 33 - 33: ooOoO0o . I1Ii111 + I1IiiI . Oo0Ooo
   if ( OOiIiIiiiI11i1 == None ) : OOiIiIiiiI11i1 = O0O0OOo0O . rloc
   if 11 - 11: o0oOOo0O0Ooo * i11iIiiIii
  iIIi . store_rloc_entry ( O0O0OOo0O )
  iIIi . reach_bit = True
  iIIi . print_record ( "    " )
  o0o0ooOOo0oO += iIIi . encode ( )
  if 9 - 9: OoooooooOO / OoooooooOO
  if 57 - 57: OoO0O00 + i1IIi % OOooOOo * i11iIiiIii % i1IIi / o0oOOo0O0Ooo
  if 1 - 1: ooOoO0o
  if 81 - 81: iII111i . Oo0Ooo . O0 . II111iiii
  if 46 - 46: I1Ii111 % Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . oO0o
 if ( O0O0O != None ) :
  iIIi = lisp_rloc_record ( )
  if ( OOiIiIiiiI11i1 ) : iIIi . rloc . copy_address ( OOiIiIiiiI11i1 )
  iIIi . local_bit = True
  iIIi . probe_bit = True
  iIIi . reach_bit = True
  Ii1Iii1II11 = lisp_encode_telemetry ( O0O0O , eo = str ( time . time ( ) ) )
  iIIi . json = lisp_json ( "telemetry" , Ii1Iii1II11 )
  iIIi . print_record ( "    " )
  o0o0ooOOo0oO += iIIi . encode ( )
  if 13 - 13: O0
 return ( o0o0ooOOo0oO )
 if 60 - 60: IiII
 if 14 - 14: II111iiii - i1IIi % OoOoOO00
 if 29 - 29: OoooooooOO * O0 / iIii1I11I1II1
 if 29 - 29: OoO0O00 / IiII + i1IIi / OoO0O00 . Oo0Ooo
 if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
 if 14 - 14: i1IIi
 if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 I1IIIiIiii1i = lisp_map_referral ( )
 I1IIIiIiii1i . record_count = 1
 I1IIIiIiii1i . nonce = nonce
 o0o0ooOOo0oO = I1IIIiIiii1i . encode ( )
 I1IIIiIiii1i . print_map_referral ( )
 if 39 - 39: iII111i - Oo0Ooo * I1ii11iIi11i % OOooOOo / oO0o / Oo0Ooo
 oOO0O0o0oOooO = lisp_eid_record ( )
 if 53 - 53: ooOoO0o % OoO0O00 * O0 + II111iiii + iIii1I11I1II1
 Iii1I11Iiii1 = 0
 if ( ddt_entry == None ) :
  oOO0O0o0oOooO . eid = eid
  oOO0O0o0oOooO . group = group
 else :
  Iii1I11Iiii1 = len ( ddt_entry . delegation_set )
  oOO0O0o0oOooO . eid = ddt_entry . eid
  oOO0O0o0oOooO . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 91 - 91: o0oOOo0O0Ooo / Ii1I
 oOO0O0o0oOooO . rloc_count = Iii1I11Iiii1
 oOO0O0o0oOooO . authoritative = True
 if 10 - 10: Oo0Ooo / i1IIi + i1IIi * i1IIi
 if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
 if 27 - 27: oO0o + Ii1I . i11iIiiIii
 if 97 - 97: iII111i . I1IiiI
 if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
 O0OoooO = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( Iii1I11Iiii1 == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   I111IiiII = ddt_entry . delegation_set [ 0 ]
   if ( I111IiiII . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
   if ( I111IiiII . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 45 - 45: oO0o
    if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
    if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
    if 100 - 100: i11iIiiIii - iII111i - I11i
    if 5 - 5: oO0o % IiII * iII111i
    if 98 - 98: iII111i / OOooOOo + IiII
    if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0OoooO = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  O0OoooO = ( lisp_i_am_ms and I111IiiII . is_ms_peer ( ) == False )
  if 82 - 82: ooOoO0o % OOooOOo % Ii1I
  if 82 - 82: I1ii11iIi11i
 oOO0O0o0oOooO . action = action
 oOO0O0o0oOooO . ddt_incomplete = O0OoooO
 oOO0O0o0oOooO . record_ttl = ttl
 if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
 o0o0ooOOo0oO += oOO0O0o0oOooO . encode ( )
 oOO0O0o0oOooO . print_record ( "  " , True )
 if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
 if ( Iii1I11Iiii1 == 0 ) : return ( o0o0ooOOo0oO )
 if 53 - 53: OOooOOo * OoOoOO00 % iII111i
 for I111IiiII in ddt_entry . delegation_set :
  iIIi = lisp_rloc_record ( )
  iIIi . rloc = I111IiiII . delegate_address
  iIIi . priority = I111IiiII . priority
  iIIi . weight = I111IiiII . weight
  iIIi . mpriority = 255
  iIIi . mweight = 0
  iIIi . reach_bit = True
  o0o0ooOOo0oO += iIIi . encode ( )
  iIIi . print_record ( "    " )
  if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
 return ( o0o0ooOOo0oO )
 if 66 - 66: I1IiiI * OoOoOO00 . I1IiiI / Oo0Ooo - Ii1I
 if 69 - 69: iIii1I11I1II1 % iII111i + ooOoO0o * i1IIi + iII111i * I1Ii111
 if 67 - 67: Ii1I % Oo0Ooo - Oo0Ooo . I11i + IiII
 if 73 - 73: Oo0Ooo + iIii1I11I1II1 . iIii1I11I1II1
 if 73 - 73: ooOoO0o + OoOoOO00
 if 61 - 61: I1Ii111 * I1Ii111 % OOooOOo
 if 31 - 31: oO0o + Ii1I - iIii1I11I1II1 / i11iIiiIii
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 9 - 9: IiII % OoO0O00
 if ( map_request . target_group . is_null ( ) ) :
  oooOOoO0oo0 = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  oooOOoO0oo0 = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( oooOOoO0oo0 ) : oooOOoO0oo0 = oooOOoO0oo0 . lookup_source_cache ( map_request . target_eid , False )
  if 48 - 48: Oo0Ooo / iIii1I11I1II1
 iIiI1I1ii1I1 = map_request . print_prefix ( )
 if 80 - 80: i1IIi + I1IiiI / OoooooooOO + OOooOOo . Ii1I
 if ( oooOOoO0oo0 == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( iIiI1I1ii1I1 , False ) ) )
  if 96 - 96: iIii1I11I1II1 - I1ii11iIi11i
  return
  if 41 - 41: II111iiii - OoOoOO00 + OoooooooOO - I1ii11iIi11i . oO0o . o0oOOo0O0Ooo
  if 34 - 34: I1ii11iIi11i % I11i / Oo0Ooo * oO0o % ooOoO0o / OOooOOo
 iiiiiiiiII1i = oooOOoO0oo0 . print_eid_tuple ( )
 if 34 - 34: iIii1I11I1II1 * OoooooooOO * oO0o
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( iiiiiiiiII1i , False ) , green ( iIiI1I1ii1I1 , False ) ) )
 if 52 - 52: I1ii11iIi11i / OoOoOO00 * OoO0O00 + II111iiii * OoooooooOO
 if 11 - 11: Ii1I * iII111i * I1IiiI - Oo0Ooo
 if 76 - 76: oO0o * II111iiii
 if 81 - 81: I11i
 if 2 - 2: OoOoOO00
 oO0o0o00O = map_request . itr_rlocs [ 0 ]
 if ( oO0o0o00O . is_private_address ( ) and lisp_nat_traversal ) :
  oO0o0o00O = source
  if 88 - 88: I1Ii111 - i1IIi - iII111i . oO0o
  if 25 - 25: i1IIi * o0oOOo0O0Ooo / oO0o
 O0oo00o000 = map_request . nonce
 i1iIii1 = lisp_nonce_echoing
 IiI11I1iiii1 = map_request . keys
 if 42 - 42: OoooooooOO * iII111i / I1IiiI + OoooooooOO + ooOoO0o * iII111i
 if 35 - 35: I11i + OoooooooOO
 if 67 - 67: iII111i . OoO0O00 . i1IIi - Oo0Ooo
 if 92 - 92: I1Ii111 % II111iiii % I11i % O0 . I1Ii111 % o0oOOo0O0Ooo
 if 99 - 99: I1ii11iIi11i
 ooo0 = map_request . json_telemetry
 if ( ooo0 != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( ooo0 , ei = etr_in_ts )
  if 9 - 9: OoooooooOO * oO0o
  if 49 - 49: i11iIiiIii + OoO0O00 - OOooOOo
 oooOOoO0oo0 . map_replies_sent += 1
 if 9 - 9: II111iiii * OOooOOo / Oo0Ooo + iIii1I11I1II1 % I1IiiI
 o0o0ooOOo0oO = lisp_build_map_reply ( oooOOoO0oo0 . eid , oooOOoO0oo0 . group , oooOOoO0oo0 . rloc_set , O0oo00o000 ,
 LISP_NO_ACTION , 1440 , map_request , IiI11I1iiii1 , i1iIii1 , True , ttl )
 if 95 - 95: I1Ii111 . IiII % OoO0O00 - OOooOOo - I11i
 if 55 - 55: OoooooooOO % I1ii11iIi11i % iII111i / IiII
 if 65 - 65: II111iiii
 if 58 - 58: iIii1I11I1II1 / i11iIiiIii . iII111i . OOooOOo * I1ii11iIi11i + OoooooooOO
 if 13 - 13: OoooooooOO + iII111i * i11iIiiIii % IiII + oO0o . o0oOOo0O0Ooo
 if 31 - 31: o0oOOo0O0Ooo - ooOoO0o
 if 40 - 40: O0 / OoOoOO00 - I1Ii111
 if 60 - 60: IiII + I1IiiI
 if 61 - 61: OoO0O00
 if 96 - 96: ooOoO0o - OoooooooOO * iIii1I11I1II1 . IiII - O0
 if 7 - 7: iIii1I11I1II1 . OoO0O00
 if 88 - 88: i1IIi * II111iiii / i11iIiiIii % IiII . IiII
 if 93 - 93: OoOoOO00 * i1IIi . Ii1I
 if 2 - 2: i1IIi
 if 84 - 84: i1IIi / Ii1I + OoOoOO00 % Ii1I . oO0o
 if 74 - 74: OOooOOo - o0oOOo0O0Ooo - I1Ii111 - OoO0O00
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  i1I = ( oO0o0o00O . is_private_address ( ) == False )
  IiIi1I1i1iIiI = oO0o0o00O . print_address_no_iid ( )
  if ( ( i1I and lisp_rtr_list . has_key ( IiIi1I1i1iIiI ) ) or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , oO0o0o00O , None , o0o0ooOOo0oO )
   return
   if 40 - 40: o0oOOo0O0Ooo . IiII * OoOoOO00
   if 14 - 14: OOooOOo
   if 18 - 18: i11iIiiIii % iII111i
   if 70 - 70: O0 + iII111i % I11i % I1Ii111 + OoOoOO00 / ooOoO0o
   if 35 - 35: IiII + OoO0O00
   if 82 - 82: i1IIi - ooOoO0o / I11i + I11i % I1IiiI - OoooooooOO
 lisp_send_map_reply ( lisp_sockets , o0o0ooOOo0oO , oO0o0o00O , sport )
 return
 if 56 - 56: I1ii11iIi11i
 if 80 - 80: Oo0Ooo / OOooOOo / iII111i . o0oOOo0O0Ooo
 if 43 - 43: IiII
 if 74 - 74: OoooooooOO
 if 88 - 88: Ii1I * o0oOOo0O0Ooo / oO0o
 if 58 - 58: O0
 if 43 - 43: O0 / i1IIi / I11i % I1IiiI
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 82 - 82: i11iIiiIii * i11iIiiIii + I1Ii111 - I1ii11iIi11i * oO0o - Ii1I
 if 40 - 40: o0oOOo0O0Ooo + OoO0O00 % i1IIi % iII111i * I1Ii111
 if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
 if 34 - 34: OoooooooOO * i11iIiiIii
 oO0o0o00O = map_request . itr_rlocs [ 0 ]
 if ( oO0o0o00O . is_private_address ( ) ) : oO0o0o00O = source
 O0oo00o000 = map_request . nonce
 if 33 - 33: II111iiii
 oOooOOo000o0o = map_request . target_eid
 iiIoOOOOoo0O00o = map_request . target_group
 if 59 - 59: iIii1I11I1II1 % I11i
 oOO000OOO = [ ]
 for Oooo00 in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( Oooo00 == None ) : continue
  IIIi1iI1 = lisp_rloc ( )
  IIIi1iI1 . rloc . copy_address ( Oooo00 )
  IIIi1iI1 . priority = 254
  oOO000OOO . append ( IIIi1iI1 )
  if 15 - 15: I11i + iII111i
  if 79 - 79: i11iIiiIii * IiII % iII111i
 i1iIii1 = lisp_nonce_echoing
 IiI11I1iiii1 = map_request . keys
 if 18 - 18: iIii1I11I1II1 - O0 . o0oOOo0O0Ooo % oO0o
 if 73 - 73: IiII + I11i % I1IiiI * iII111i . O0
 if 17 - 17: OoO0O00 * OoOoOO00 % O0 % iII111i / i1IIi
 if 100 - 100: i11iIiiIii
 if 54 - 54: O0 * Ii1I + Ii1I
 ooo0 = map_request . json_telemetry
 if ( ooo0 != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( ooo0 , ei = etr_in_ts )
  if 59 - 59: i11iIiiIii % iII111i
  if 54 - 54: I11i . ooOoO0o / OOooOOo % I1Ii111
 o0o0ooOOo0oO = lisp_build_map_reply ( oOooOOo000o0o , iiIoOOOOoo0O00o , oOO000OOO , O0oo00o000 , LISP_NO_ACTION ,
 1440 , map_request , IiI11I1iiii1 , i1iIii1 , True , ttl )
 lisp_send_map_reply ( lisp_sockets , o0o0ooOOo0oO , oO0o0o00O , sport )
 return
 if 13 - 13: I11i / O0 . o0oOOo0O0Ooo . ooOoO0o
 if 7 - 7: OoO0O00 + OoooooooOO % II111iiii % oO0o
 if 48 - 48: OOooOOo . II111iiii * OOooOOo - I11i / iIii1I11I1II1 / i11iIiiIii
 if 37 - 37: II111iiii % O0 + iIii1I11I1II1 - I1IiiI . I11i + I1ii11iIi11i
 if 14 - 14: ooOoO0o % iIii1I11I1II1 % ooOoO0o / IiII + OOooOOo
 if 14 - 14: Oo0Ooo
 if 79 - 79: I1ii11iIi11i % I1Ii111 % I11i - iII111i * OoOoOO00
 if 48 - 48: O0 + OoOoOO00 - O0
 if 79 - 79: ooOoO0o . OoOoOO00 / OoooooooOO - II111iiii
 if 48 - 48: Oo0Ooo
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 oOO000OOO = target_site_eid . registered_rlocs
 if 59 - 59: OoO0O00 % o0oOOo0O0Ooo
 O0ooO0O0O00 = lisp_site_eid_lookup ( seid , group , False )
 if ( O0ooO0O0O00 == None ) : return ( oOO000OOO )
 if 5 - 5: I1IiiI % I1IiiI + OoooooooOO / I1ii11iIi11i
 if 77 - 77: OOooOOo / i11iIiiIii % iII111i * oO0o
 if 77 - 77: OOooOOo + i11iIiiIii / o0oOOo0O0Ooo + iII111i
 if 90 - 90: ooOoO0o
 OOI1I1 = None
 iii1 = [ ]
 for O0O0OOo0O in oOO000OOO :
  if ( O0O0OOo0O . is_rtr ( ) ) : continue
  if ( O0O0OOo0O . rloc . is_private_address ( ) ) :
   I11I1II1I1I1i = copy . deepcopy ( O0O0OOo0O )
   iii1 . append ( I11I1II1I1I1i )
   continue
   if 98 - 98: I1Ii111
  OOI1I1 = O0O0OOo0O
  break
  if 75 - 75: OOooOOo . i11iIiiIii * Ii1I
 if ( OOI1I1 == None ) : return ( oOO000OOO )
 OOI1I1 = OOI1I1 . rloc . print_address_no_iid ( )
 if 32 - 32: iIii1I11I1II1 . OoO0O00 / Oo0Ooo % OOooOOo + IiII
 if 28 - 28: OOooOOo . OoO0O00 / o0oOOo0O0Ooo + II111iiii / iIii1I11I1II1 * II111iiii
 if 83 - 83: II111iiii . OoOoOO00 - i11iIiiIii . OoOoOO00 . i1IIi % OoooooooOO
 if 47 - 47: II111iiii
 IiiI11Ii1 = None
 for O0O0OOo0O in O0ooO0O0O00 . registered_rlocs :
  if ( O0O0OOo0O . is_rtr ( ) ) : continue
  if ( O0O0OOo0O . rloc . is_private_address ( ) ) : continue
  IiiI11Ii1 = O0O0OOo0O
  break
  if 68 - 68: O0 - i1IIi % iII111i * I1ii11iIi11i + I11i
 if ( IiiI11Ii1 == None ) : return ( oOO000OOO )
 IiiI11Ii1 = IiiI11Ii1 . rloc . print_address_no_iid ( )
 if 94 - 94: iII111i / OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
 if 94 - 94: OoO0O00 . ooOoO0o
 if 25 - 25: I1Ii111 % OOooOOo
 if 82 - 82: Ii1I
 oOO0o0OO = target_site_eid . site_id
 if ( oOO0o0OO == 0 ) :
  if ( IiiI11Ii1 == OOI1I1 ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( OOI1I1 ) )
   if 17 - 17: iII111i . i1IIi . i1IIi
   return ( iii1 )
   if 76 - 76: OoooooooOO % IiII
  return ( oOO000OOO )
  if 81 - 81: iII111i . OOooOOo * i1IIi
  if 14 - 14: oO0o
  if 16 - 16: iII111i
  if 26 - 26: iII111i . oO0o * i11iIiiIii . iIii1I11I1II1
  if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
  if 65 - 65: OOooOOo * I11i * Oo0Ooo
  if 21 - 21: Ii1I . iIii1I11I1II1
 if ( oOO0o0OO == O0ooO0O0O00 . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( oOO0o0OO ) )
  return ( iii1 )
  if 84 - 84: OOooOOo
 return ( oOO000OOO )
 if 67 - 67: I1IiiI % OoO0O00 % o0oOOo0O0Ooo % IiII
 if 33 - 33: ooOoO0o % I1IiiI
 if 98 - 98: oO0o . o0oOOo0O0Ooo + II111iiii
 if 62 - 62: ooOoO0o - OoooooooOO / I1ii11iIi11i / iII111i - o0oOOo0O0Ooo
 if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
 if 9 - 9: iII111i * Oo0Ooo % iII111i % Oo0Ooo * II111iiii
 if 71 - 71: II111iiii + I1ii11iIi11i * II111iiii
 if 59 - 59: OoO0O00
 if 81 - 81: i11iIiiIii
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 OOOo0O00OO00O = [ ]
 oOO000OOO = [ ]
 if 91 - 91: Oo0Ooo - iIii1I11I1II1 - iII111i . OoooooooOO . iII111i + Oo0Ooo
 if 20 - 20: OoO0O00 . ooOoO0o - IiII
 if 82 - 82: oO0o
 if 26 - 26: I1ii11iIi11i
 if 40 - 40: OOooOOo
 if 90 - 90: OoOoOO00
 IiIIi11IiII = False
 OOOo0O0O0O0O0 = False
 for O0O0OOo0O in registered_rloc_set :
  if ( O0O0OOo0O . priority != 254 ) : continue
  OOOo0O0O0O0O0 |= True
  if ( O0O0OOo0O . rloc . is_exact_match ( mr_source ) == False ) : continue
  IiIIi11IiII = True
  break
  if 61 - 61: oO0o + I11i * OoooooooOO * I11i % OoOoOO00
  if 88 - 88: iII111i * iIii1I11I1II1 + IiII / II111iiii * i11iIiiIii
  if 22 - 22: OOooOOo + Oo0Ooo . I1Ii111 + i11iIiiIii / ooOoO0o - II111iiii
  if 93 - 93: O0 + i1IIi - O0
  if 13 - 13: i11iIiiIii
  if 14 - 14: I11i . OoOoOO00 . OOooOOo - Oo0Ooo + I1Ii111 % ooOoO0o
  if 95 - 95: OoO0O00 * II111iiii + i1IIi
 if ( OOOo0O0O0O0O0 == False ) : return ( registered_rloc_set )
 if 22 - 22: Ii1I / ooOoO0o % I11i + OoO0O00 . ooOoO0o
 if 61 - 61: O0 - iIii1I11I1II1 * Oo0Ooo . Ii1I + O0
 if 20 - 20: ooOoO0o / ooOoO0o - Ii1I - ooOoO0o
 if 93 - 93: O0 * OoOoOO00 * iIii1I11I1II1
 if 3 - 3: I1ii11iIi11i - O0
 if 46 - 46: iII111i
 if 99 - 99: oO0o
 if 85 - 85: I1Ii111 * iIii1I11I1II1 . OoOoOO00
 if 20 - 20: I11i * O0 - OoooooooOO * OOooOOo % oO0o * iII111i
 if 70 - 70: I11i + O0 . i11iIiiIii . OOooOOo
 IiI1iiIIiIiii = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 33 - 33: oO0o % I1Ii111 % Oo0Ooo . Ii1I
 if 3 - 3: I1Ii111 . o0oOOo0O0Ooo
 if 6 - 6: oO0o . OoOoOO00 * i11iIiiIii
 if 96 - 96: i1IIi . OoO0O00 . OoO0O00 - o0oOOo0O0Ooo - Ii1I
 if 33 - 33: ooOoO0o + I1ii11iIi11i - I1IiiI . iII111i / OoO0O00
 for O0O0OOo0O in registered_rloc_set :
  if ( IiI1iiIIiIiii and O0O0OOo0O . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and O0O0OOo0O . priority == 255 ) : continue
  if ( multicast and O0O0OOo0O . mpriority == 255 ) : continue
  if ( O0O0OOo0O . priority == 254 ) :
   OOOo0O00OO00O . append ( O0O0OOo0O )
  else :
   oOO000OOO . append ( O0O0OOo0O )
   if 91 - 91: OOooOOo - OoooooooOO . OoO0O00
   if 34 - 34: Ii1I . I1IiiI . i1IIi * I1ii11iIi11i
   if 77 - 77: ooOoO0o . II111iiii
   if 41 - 41: IiII
   if 27 - 27: IiII / IiII
   if 91 - 91: Ii1I
 if ( IiIIi11IiII ) : return ( oOO000OOO )
 if 93 - 93: OoO0O00 * OoO0O00 * I1ii11iIi11i * OoO0O00 * o0oOOo0O0Ooo
 if 84 - 84: I1Ii111 * OoO0O00 - ooOoO0o - Oo0Ooo . OoO0O00 % oO0o
 if 98 - 98: OoO0O00 . i1IIi
 if 58 - 58: i1IIi * O0 + I1ii11iIi11i . IiII
 if 11 - 11: OOooOOo + iIii1I11I1II1 - ooOoO0o * OoO0O00 * i11iIiiIii
 if 45 - 45: I1ii11iIi11i + Oo0Ooo
 if 7 - 7: Oo0Ooo + ooOoO0o - I1Ii111 * iIii1I11I1II1
 if 6 - 6: ooOoO0o % I1Ii111 % ooOoO0o . Ii1I * Oo0Ooo . IiII
 if 100 - 100: i1IIi . Ii1I . o0oOOo0O0Ooo + Ii1I - i1IIi . I11i
 if 19 - 19: i11iIiiIii + I11i - IiII . iII111i * i1IIi
 if 66 - 66: ooOoO0o
 if 4 - 4: iII111i / iII111i * OOooOOo + o0oOOo0O0Ooo . I1Ii111 + II111iiii
 oOO000OOO = [ ]
 for O0O0OOo0O in registered_rloc_set :
  if ( O0O0OOo0O . rloc . is_ipv6 ( ) ) : oOO000OOO . append ( O0O0OOo0O )
  if ( O0O0OOo0O . rloc . is_private_address ( ) ) : oOO000OOO . append ( O0O0OOo0O )
  if 90 - 90: IiII * iII111i % OoOoOO00 . i11iIiiIii
 oOO000OOO += OOOo0O00OO00O
 return ( oOO000OOO )
 if 5 - 5: O0 * i1IIi / IiII
 if 4 - 4: II111iiii
 if 60 - 60: ooOoO0o - II111iiii * OoO0O00 + oO0o - iII111i
 if 39 - 39: OoO0O00 % I1Ii111 * I11i * Ii1I
 if 84 - 84: Oo0Ooo / OoO0O00 - II111iiii - OoOoOO00 - O0
 if 18 - 18: oO0o * I11i / o0oOOo0O0Ooo - OoooooooOO
 if 21 - 21: O0 - OoooooooOO
 if 21 - 21: iII111i * o0oOOo0O0Ooo
 if 85 - 85: I1ii11iIi11i . OoOoOO00 . i1IIi % OOooOOo * I11i . I1Ii111
 if 26 - 26: I1Ii111 + Oo0Ooo + II111iiii % OoOoOO00 % OOooOOo
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 iIiii11 = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 iIiii11 . add ( reply_eid )
 return ( iIiii11 )
 if 38 - 38: Ii1I + OoOoOO00 % I1Ii111 % iII111i
 if 72 - 72: OoOoOO00 * I1ii11iIi11i + iIii1I11I1II1
 if 51 - 51: oO0o + I1IiiI - I1Ii111 * Oo0Ooo . II111iiii
 if 63 - 63: I1ii11iIi11i - ooOoO0o - II111iiii + II111iiii
 if 17 - 17: I1ii11iIi11i % OoO0O00 % oO0o
 if 60 - 60: i1IIi % Ii1I - O0 / iII111i
 if 14 - 14: i1IIi * OoooooooOO . IiII
 if 26 - 26: O0
 if 70 - 70: i1IIi % IiII % iIii1I11I1II1 . II111iiii * Oo0Ooo . o0oOOo0O0Ooo
 if 33 - 33: iIii1I11I1II1 / OoooooooOO / I1IiiI + II111iiii
 if 42 - 42: OoOoOO00 / i1IIi * O0
 if 46 - 46: OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
 if 96 - 96: IiII + i1IIi - I11i * I11i - OoO0O00 % II111iiii
 if 47 - 47: I1Ii111 . i11iIiiIii + oO0o . I1ii11iIi11i
 if 12 - 12: iIii1I11I1II1 % I1Ii111 * OoOoOO00 / OoooooooOO % OoooooooOO
def lisp_convert_reply_to_notify ( packet ) :
 if 81 - 81: iIii1I11I1II1 - Oo0Ooo - ooOoO0o . OoO0O00 + I1ii11iIi11i
 if 84 - 84: iII111i . OOooOOo . iII111i * oO0o % Ii1I . oO0o
 if 86 - 86: iII111i * ooOoO0o / iIii1I11I1II1 + Ii1I . iII111i
 if 64 - 64: IiII - Oo0Ooo % iII111i % I11i
 iIiI1IIi1Ii1i = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 iIiI1IIi1Ii1i = socket . ntohl ( iIiI1IIi1Ii1i ) & 0xff
 O0oo00o000 = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 28 - 28: I1IiiI - I1Ii111
 if 60 - 60: OOooOOo / O0 * o0oOOo0O0Ooo * OoooooooOO
 if 95 - 95: II111iiii
 if 2 - 2: I11i - OoooooooOO / I1ii11iIi11i . I1ii11iIi11i * i11iIiiIii % II111iiii
 i1IIi1ii1i1ii = ( LISP_MAP_NOTIFY << 28 ) | iIiI1IIi1Ii1i
 OoOOoo0o00O0oO = struct . pack ( "I" , socket . htonl ( i1IIi1ii1i1ii ) )
 O0oooO00ooO0 = struct . pack ( "I" , 0 )
 if 1 - 1: i11iIiiIii / OoOoOO00 - I1ii11iIi11i . I1IiiI / I1Ii111 % iIii1I11I1II1
 if 87 - 87: OoOoOO00 - II111iiii + Oo0Ooo
 if 44 - 44: i1IIi + I1ii11iIi11i / iIii1I11I1II1
 if 47 - 47: I1Ii111
 packet = OoOOoo0o00O0oO + O0oo00o000 + O0oooO00ooO0 + packet
 return ( packet )
 if 41 - 41: IiII
 if 25 - 25: I11i % iIii1I11I1II1
 if 27 - 27: iIii1I11I1II1 . O0 . oO0o
 if 21 - 21: oO0o * I1ii11iIi11i
 if 44 - 44: o0oOOo0O0Ooo * IiII - o0oOOo0O0Ooo
 if 90 - 90: i1IIi + I1ii11iIi11i * oO0o % i11iIiiIii - OoO0O00
 if 12 - 12: OoO0O00 . I1ii11iIi11i - I1IiiI % OOooOOo
 if 9 - 9: Ii1I / O0
def lisp_notify_subscribers ( lisp_sockets , eid_record , rloc_records ,
 registered_eid , site ) :
 if 95 - 95: iII111i / I11i
 for Ooooo in lisp_pubsub_cache :
  for iIiii11 in lisp_pubsub_cache [ Ooooo ] . values ( ) :
   I1i = iIiii11 . eid_prefix
   if ( I1i . is_more_specific ( registered_eid ) == False ) : continue
   if 40 - 40: II111iiii + OoooooooOO / iII111i % O0 + OOooOOo . ooOoO0o
   OO = iIiii11 . itr
   IiO0o = iIiii11 . port
   iiI = red ( OO . print_address_no_iid ( ) , False )
   Oo00OOo = bold ( "subscriber" , False )
   OoO0o00O0oOOo = "0x" + lisp_hex_string ( iIiii11 . xtr_id )
   O0oo00o000 = "0x" + lisp_hex_string ( iIiii11 . nonce )
   if 47 - 47: oO0o
   lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( Oo00OOo , iiI , IiO0o , OoO0o00O0oOOo , green ( Ooooo , False ) , O0oo00o000 ) )
   if 91 - 91: I1IiiI * O0 + OoooooooOO * i1IIi % I1ii11iIi11i . IiII
   if 67 - 67: I1IiiI * I11i
   if 43 - 43: IiII * Oo0Ooo / OoOoOO00 + I1IiiI - i11iIiiIii + II111iiii
   if 81 - 81: I11i / Oo0Ooo % Ii1I % OoO0O00
   if 87 - 87: O0 % II111iiii
   if 42 - 42: I1IiiI . i1IIi
   OOo00O0O0OO = copy . deepcopy ( eid_record )
   OOo00O0O0OO . eid . copy_address ( I1i )
   OOo00O0O0OO = OOo00O0O0OO . encode ( ) + rloc_records
   lisp_build_map_notify ( lisp_sockets , OOo00O0O0OO , [ Ooooo ] , 1 , OO ,
 IiO0o , iIiii11 . nonce , 0 , 0 , 0 , site , False )
   if 33 - 33: I1Ii111 . I1Ii111 * i1IIi
   iIiii11 . map_notify_count += 1
   if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
   if 13 - 13: II111iiii
 return
 if 36 - 36: iII111i - oO0o / Oo0Ooo / O0 . OoO0O00 . i1IIi
 if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
 if 98 - 98: oO0o . Oo0Ooo
 if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
 if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
 if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
 if 64 - 64: OoooooooOO + OOooOOo
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 36 - 36: I1IiiI - Ii1I / I1ii11iIi11i + Oo0Ooo % I1ii11iIi11i
 if 86 - 86: iIii1I11I1II1 * OoO0O00
 if 82 - 82: I1IiiI - OoO0O00 % o0oOOo0O0Ooo
 if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
 iIiii11 = lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl ,
 xtr_id )
 if 98 - 98: Oo0Ooo . II111iiii * I11i
 oOooOOo000o0o = green ( reply_eid . print_prefix ( ) , False )
 OO = red ( itr_rloc . print_address_no_iid ( ) , False )
 I1III11111Ii1 = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( I1III11111Ii1 ,
 oOooOOo000o0o , OO , xtr_id ) )
 if 61 - 61: Ii1I * Ii1I % I1Ii111 - o0oOOo0O0Ooo + I11i + OoO0O00
 if 9 - 9: IiII / i1IIi * IiII - o0oOOo0O0Ooo - iIii1I11I1II1
 if 58 - 58: I1ii11iIi11i + iII111i
 if 65 - 65: ooOoO0o / Ii1I - oO0o - O0 % OOooOOo
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 iIiii11 . map_notify_count += 1
 return
 if 16 - 16: Oo0Ooo . Ii1I . i11iIiiIii / I1ii11iIi11i . i1IIi + I1Ii111
 if 25 - 25: OOooOOo - II111iiii % I1ii11iIi11i . OoOoOO00 . OoooooooOO
 if 13 - 13: OoooooooOO + OoooooooOO * i11iIiiIii + iII111i
 if 25 - 25: oO0o + I1ii11iIi11i + i11iIiiIii % i11iIiiIii
 if 11 - 11: I11i * Oo0Ooo * ooOoO0o + i1IIi
 if 76 - 76: o0oOOo0O0Ooo * i1IIi / I1Ii111 * Oo0Ooo + II111iiii . OoOoOO00
 if 44 - 44: OoOoOO00
 if 63 - 63: OoOoOO00 % iIii1I11I1II1 . I1Ii111 * O0 * OOooOOo - I11i
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 52 - 52: I11i - I11i / OoooooooOO - iIii1I11I1II1 / i11iIiiIii - Oo0Ooo
 if 61 - 61: OOooOOo / iIii1I11I1II1 - Oo0Ooo % Oo0Ooo % Oo0Ooo
 if 66 - 66: OoooooooOO
 if 23 - 23: OoOoOO00
 if 35 - 35: I1Ii111 - i1IIi
 if 90 - 90: I11i . OoO0O00 . iIii1I11I1II1
 oOooOOo000o0o = map_request . target_eid
 iiIoOOOOoo0O00o = map_request . target_group
 iIiI1I1ii1I1 = lisp_print_eid_tuple ( oOooOOo000o0o , iiIoOOOOoo0O00o )
 oO0o0o00O = map_request . itr_rlocs [ 0 ]
 OoO0o00O0oOOo = map_request . xtr_id
 O0oo00o000 = map_request . nonce
 iiIIiI = LISP_NO_ACTION
 iIiii11 = map_request . subscribe_bit
 if 81 - 81: iII111i + I11i - i11iIiiIii * I1IiiI / IiII - Ii1I
 if 44 - 44: OoooooooOO . oO0o
 if 30 - 30: I1Ii111 % IiII / II111iiii
 if 68 - 68: oO0o / O0 / OOooOOo
 if 3 - 3: o0oOOo0O0Ooo / o0oOOo0O0Ooo
 iIiIiII1I11II = True
 OOo0oO = ( lisp_get_eid_hash ( oOooOOo000o0o ) != None )
 if ( OOo0oO ) :
  IIIiiiIi1I1 = map_request . map_request_signature
  if ( IIIiiiIi1I1 == None ) :
   iIiIiII1I11II = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 17 - 17: ooOoO0o - i1IIi
  else :
   O00 = map_request . signature_eid
   Oo00oOoo , ooOo0OO , iIiIiII1I11II = lisp_lookup_public_key ( O00 )
   if ( iIiIiII1I11II ) :
    iIiIiII1I11II = map_request . verify_map_request_sig ( ooOo0OO )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( O00 . print_address ( ) , Oo00oOoo . print_address ( ) ) )
    if 18 - 18: I1IiiI
    if 7 - 7: II111iiii % iII111i * I11i
   II1IIoOo0 = bold ( "passed" , False ) if iIiIiII1I11II else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( II1IIoOo0 ) )
   if 80 - 80: OOooOOo + oO0o . O0 - ooOoO0o / o0oOOo0O0Ooo
   if 58 - 58: Ii1I . iII111i * OoO0O00 + OoO0O00 % I1Ii111 + I1ii11iIi11i
   if 34 - 34: i11iIiiIii + OoOoOO00
 if ( iIiii11 and iIiIiII1I11II == False ) :
  iIiii11 = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 57 - 57: I1IiiI + IiII . OoOoOO00 * iIii1I11I1II1 % OoooooooOO
  if 21 - 21: I11i
  if 36 - 36: IiII + OoO0O00
  if 66 - 66: iIii1I11I1II1 / oO0o
  if 36 - 36: o0oOOo0O0Ooo % I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo
  if 18 - 18: oO0o / i1IIi * I11i
  if 71 - 71: OoooooooOO - i11iIiiIii * i1IIi % OOooOOo - oO0o / o0oOOo0O0Ooo
  if 77 - 77: iIii1I11I1II1 / OoOoOO00
  if 59 - 59: Oo0Ooo % OOooOOo
  if 14 - 14: I11i . OoO0O00
  if 46 - 46: ooOoO0o
  if 48 - 48: i1IIi * I1IiiI / i11iIiiIii
  if 40 - 40: IiII
  if 42 - 42: O0 / II111iiii
 oo00o0 = oO0o0o00O if ( oO0o0o00O . afi == ecm_source . afi ) else ecm_source
 if 22 - 22: I1ii11iIi11i * OoooooooOO
 iiI1I = lisp_site_eid_lookup ( oOooOOo000o0o , iiIoOOOOoo0O00o , False )
 if 31 - 31: iIii1I11I1II1 / O0
 if ( iiI1I == None or iiI1I . is_star_g ( ) ) :
  iiIIi1iI = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( iiIIi1iI ,
 green ( iIiI1I1ii1I1 , False ) ) )
  if 72 - 72: I1IiiI - i1IIi
  if 11 - 11: iIii1I11I1II1 . OoO0O00 * Ii1I
  if 65 - 65: Oo0Ooo / OoooooooOO
  if 60 - 60: II111iiii + I1IiiI % oO0o - o0oOOo0O0Ooo
  lisp_send_negative_map_reply ( lisp_sockets , oOooOOo000o0o , iiIoOOOOoo0O00o , O0oo00o000 , oO0o0o00O ,
 mr_sport , 15 , OoO0o00O0oOOo , iIiii11 )
  if 50 - 50: iIii1I11I1II1 - i11iIiiIii / iII111i + ooOoO0o / OOooOOo
  return ( [ oOooOOo000o0o , iiIoOOOOoo0O00o , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 80 - 80: IiII / OoooooooOO
  if 69 - 69: OoOoOO00 + IiII
 iiiiiiiiII1i = iiI1I . print_eid_tuple ( )
 ii1iIiII1Iiii1ii = iiI1I . site . site_name
 if 42 - 42: I1ii11iIi11i % i11iIiiIii . iII111i
 if 60 - 60: I1Ii111 % IiII - iIii1I11I1II1
 if 86 - 86: I1Ii111
 if 60 - 60: I1IiiI . iII111i + O0 / iIii1I11I1II1 - I1Ii111
 if 32 - 32: ooOoO0o
 if ( OOo0oO == False and iiI1I . require_signature ) :
  IIIiiiIi1I1 = map_request . map_request_signature
  O00 = map_request . signature_eid
  if ( IIIiiiIi1I1 == None or O00 . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( ii1iIiII1Iiii1ii ) )
   iIiIiII1I11II = False
  else :
   O00 = map_request . signature_eid
   Oo00oOoo , ooOo0OO , iIiIiII1I11II = lisp_lookup_public_key ( O00 )
   if ( iIiIiII1I11II ) :
    iIiIiII1I11II = map_request . verify_map_request_sig ( ooOo0OO )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( O00 . print_address ( ) , Oo00oOoo . print_address ( ) ) )
    if 9 - 9: I1Ii111
    if 77 - 77: OoooooooOO * I1Ii111
   II1IIoOo0 = bold ( "passed" , False ) if iIiIiII1I11II else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( II1IIoOo0 ) )
   if 63 - 63: IiII * oO0o * iIii1I11I1II1
   if 18 - 18: II111iiii * o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
   if 40 - 40: oO0o - o0oOOo0O0Ooo * II111iiii
   if 4 - 4: O0
   if 9 - 9: Oo0Ooo . i1IIi - i1IIi + I1Ii111 * ooOoO0o . I1ii11iIi11i
   if 17 - 17: I11i * I1ii11iIi11i % I1IiiI + OoO0O00 + IiII
 if ( iIiIiII1I11II and iiI1I . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( ii1iIiII1Iiii1ii , green ( iiiiiiiiII1i , False ) , green ( iIiI1I1ii1I1 , False ) ) )
  if 90 - 90: OoooooooOO - I1IiiI / I1ii11iIi11i + oO0o - o0oOOo0O0Ooo
  if 84 - 84: OoOoOO00 + O0 % Oo0Ooo
  if 22 - 22: iIii1I11I1II1 % i11iIiiIii
  if 29 - 29: ooOoO0o - iII111i + IiII % Ii1I - oO0o - ooOoO0o
  if 43 - 43: oO0o
  if 22 - 22: I1Ii111 + i11iIiiIii
  if ( iiI1I . accept_more_specifics == False ) :
   oOooOOo000o0o = iiI1I . eid
   iiIoOOOOoo0O00o = iiI1I . group
   if 49 - 49: O0 % II111iiii . OOooOOo + iII111i + iIii1I11I1II1 / i11iIiiIii
   if 79 - 79: II111iiii + ooOoO0o - i1IIi - i1IIi + II111iiii . i1IIi
   if 78 - 78: I1IiiI * I11i % OOooOOo + Ii1I + OoOoOO00
   if 23 - 23: iII111i / Oo0Ooo % OoooooooOO * OoooooooOO . iII111i / I1ii11iIi11i
   if 30 - 30: oO0o - OoOoOO00 . I1IiiI
  O0OOo = 1
  if ( iiI1I . force_ttl != None ) :
   O0OOo = iiI1I . force_ttl | 0x80000000
   if 17 - 17: OoOoOO00
   if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
   if 57 - 57: O0
   if 23 - 23: OoO0O00 / II111iiii . I1ii11iIi11i . O0
   if 13 - 13: I1ii11iIi11i
  lisp_send_negative_map_reply ( lisp_sockets , oOooOOo000o0o , iiIoOOOOoo0O00o , O0oo00o000 , oO0o0o00O ,
 mr_sport , O0OOo , OoO0o00O0oOOo , iIiii11 )
  if 32 - 32: OOooOOo / I11i + I1Ii111 / Oo0Ooo * OoooooooOO / II111iiii
  return ( [ oOooOOo000o0o , iiIoOOOOoo0O00o , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 8 - 8: OoO0O00
  if 17 - 17: iIii1I11I1II1 - Oo0Ooo
  if 25 - 25: O0 + I1ii11iIi11i
  if 53 - 53: OoooooooOO . Oo0Ooo
  if 35 - 35: OOooOOo % i11iIiiIii % ooOoO0o . O0
 I1i11ioOoO0 = False
 II1iIIii1i = ""
 i1I11I1I1I = False
 if ( iiI1I . force_nat_proxy_reply ) :
  II1iIIii1i = ", nat-forced"
  I1i11ioOoO0 = True
  i1I11I1I1I = True
 elif ( iiI1I . force_proxy_reply ) :
  II1iIIii1i = ", forced"
  i1I11I1I1I = True
 elif ( iiI1I . proxy_reply_requested ) :
  II1iIIii1i = ", requested"
  i1I11I1I1I = True
 elif ( map_request . pitr_bit and iiI1I . pitr_proxy_reply_drop ) :
  II1iIIii1i = ", drop-to-pitr"
  iiIIiI = LISP_DROP_ACTION
 elif ( iiI1I . proxy_reply_action != "" ) :
  iiIIiI = iiI1I . proxy_reply_action
  II1iIIii1i = ", forced, action {}" . format ( iiIIiI )
  iiIIiI = LISP_DROP_ACTION if ( iiIIiI == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 36 - 36: O0 - II111iiii
  if 97 - 97: I1IiiI
  if 87 - 87: I11i + iIii1I11I1II1
  if 91 - 91: oO0o
  if 58 - 58: i11iIiiIii / Ii1I - OoooooooOO
  if 25 - 25: i1IIi * ooOoO0o % OOooOOo / I1IiiI
  if 75 - 75: i11iIiiIii
 i1i = False
 I11i1 = None
 if ( i1I11I1I1I and lisp_policies . has_key ( iiI1I . policy ) ) :
  IIIiIIi111 = lisp_policies [ iiI1I . policy ]
  if ( IIIiIIi111 . match_policy_map_request ( map_request , mr_source ) ) : I11i1 = IIIiIIi111
  if 48 - 48: I1Ii111
  if ( I11i1 ) :
   IIiIIIi1iii1 = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( IIiIIIi1iii1 ,
 IIIiIIi111 . policy_name , IIIiIIi111 . set_action ) )
  else :
   IIiIIIi1iii1 = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( IIiIIIi1iii1 ,
 IIIiIIi111 . policy_name ) )
   i1i = True
   if 91 - 91: ooOoO0o / II111iiii % iIii1I11I1II1
   if 70 - 70: i1IIi - II111iiii / I1IiiI + OoooooooOO + i11iIiiIii / i1IIi
   if 80 - 80: i1IIi - iIii1I11I1II1 + OoooooooOO + ooOoO0o / IiII - I1ii11iIi11i
 if ( II1iIIii1i != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( iIiI1I1ii1I1 , False ) , ii1iIiII1Iiii1ii , green ( iiiiiiiiII1i , False ) ,
  # ooOoO0o % oO0o / Oo0Ooo * oO0o % I11i . I1ii11iIi11i
 II1iIIii1i ) )
  if 32 - 32: II111iiii - II111iiii / i1IIi / i11iIiiIii - O0
  oOO000OOO = iiI1I . registered_rlocs
  O0OOo = 1440
  if ( I1i11ioOoO0 ) :
   if ( iiI1I . site_id != 0 ) :
    i11 = map_request . source_eid
    oOO000OOO = lisp_get_private_rloc_set ( iiI1I , i11 , iiIoOOOOoo0O00o )
    if 53 - 53: II111iiii + Ii1I * o0oOOo0O0Ooo
   if ( oOO000OOO == iiI1I . registered_rlocs ) :
    i1i1I11I1I = ( iiI1I . group . is_null ( ) == False )
    iii1 = lisp_get_partial_rloc_set ( oOO000OOO , oo00o0 , i1i1I11I1I )
    if ( iii1 != oOO000OOO ) :
     O0OOo = 15
     oOO000OOO = iii1
     if 15 - 15: i11iIiiIii + o0oOOo0O0Ooo . Ii1I . I1IiiI
     if 8 - 8: iII111i % II111iiii + IiII
     if 5 - 5: i1IIi + II111iiii
     if 75 - 75: OOooOOo . IiII . I1IiiI + OoooooooOO
     if 35 - 35: I11i % i1IIi - I1ii11iIi11i . Oo0Ooo
     if 69 - 69: ooOoO0o * OoO0O00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
     if 35 - 35: I1IiiI . OOooOOo * OoO0O00 . I1ii11iIi11i - I1IiiI
     if 5 - 5: i1IIi * II111iiii
  if ( iiI1I . force_ttl != None ) :
   O0OOo = iiI1I . force_ttl | 0x80000000
   if 64 - 64: I1IiiI * iIii1I11I1II1 % I1Ii111
   if 22 - 22: OoooooooOO + I1Ii111 . o0oOOo0O0Ooo * Oo0Ooo
   if 61 - 61: iIii1I11I1II1
   if 95 - 95: I1ii11iIi11i + IiII * Ii1I - IiII
   if 58 - 58: I1ii11iIi11i - oO0o % I11i * O0
   if 43 - 43: OoOoOO00 + O0
  if ( I11i1 ) :
   if ( I11i1 . set_record_ttl ) :
    O0OOo = I11i1 . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( O0OOo ) )
    if 71 - 71: ooOoO0o * I1IiiI / I1ii11iIi11i
   if ( I11i1 . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    iiIIiI = LISP_POLICY_DENIED_ACTION
    oOO000OOO = [ ]
   else :
    IIIi1iI1 = I11i1 . set_policy_map_reply ( )
    if ( IIIi1iI1 ) : oOO000OOO = [ IIIi1iI1 ]
    if 8 - 8: I1Ii111 / iIii1I11I1II1
    if 29 - 29: i11iIiiIii % i1IIi + oO0o . I1ii11iIi11i
    if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
  if ( i1i ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   iiIIiI = LISP_POLICY_DENIED_ACTION
   oOO000OOO = [ ]
   if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
   if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
  i1iIii1 = iiI1I . echo_nonce_capable
  if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
  if 53 - 53: OOooOOo / I11i + OOooOOo / I1IiiI / OoO0O00
  if 12 - 12: i11iIiiIii % ooOoO0o / iII111i . IiII
  if 68 - 68: OOooOOo / iIii1I11I1II1 + I1IiiI . ooOoO0o * IiII
  if ( iIiIiII1I11II ) :
   oOoOO0oOOoO0o = iiI1I . eid
   iI1I = iiI1I . group
  else :
   oOoOO0oOOoO0o = oOooOOo000o0o
   iI1I = iiIoOOOOoo0O00o
   iiIIiI = LISP_AUTH_FAILURE_ACTION
   oOO000OOO = [ ]
   if 28 - 28: i1IIi
   if 69 - 69: OOooOOo % ooOoO0o - i1IIi . Oo0Ooo
   if 35 - 35: iIii1I11I1II1 - I11i / iIii1I11I1II1 % ooOoO0o % I1IiiI
   if 46 - 46: oO0o
   if 5 - 5: i1IIi % o0oOOo0O0Ooo + OoOoOO00 - I11i . Ii1I
   if 33 - 33: II111iiii * o0oOOo0O0Ooo
  if ( iIiii11 ) :
   oOoOO0oOOoO0o = oOooOOo000o0o
   iI1I = iiIoOOOOoo0O00o
   if 8 - 8: I1ii11iIi11i % o0oOOo0O0Ooo - IiII
   if 91 - 91: iIii1I11I1II1 . OoO0O00 - I1ii11iIi11i + I11i / Oo0Ooo + OoO0O00
   if 35 - 35: ooOoO0o * iII111i % iII111i + OOooOOo
   if 66 - 66: iII111i - ooOoO0o * I1ii11iIi11i - Ii1I / OoooooooOO
   if 86 - 86: I1IiiI % iII111i + Oo0Ooo + i1IIi % o0oOOo0O0Ooo
   if 85 - 85: Ii1I + I1Ii111 * I11i
  packet = lisp_build_map_reply ( oOoOO0oOOoO0o , iI1I , oOO000OOO ,
 O0oo00o000 , iiIIiI , O0OOo , map_request , None , i1iIii1 , False )
  if 59 - 59: Oo0Ooo
  if ( iIiii11 ) :
   lisp_process_pubsub ( lisp_sockets , packet , oOoOO0oOOoO0o , oO0o0o00O ,
 mr_sport , O0oo00o000 , O0OOo , OoO0o00O0oOOo )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , oO0o0o00O , mr_sport )
   if 35 - 35: OoooooooOO + I1ii11iIi11i * OOooOOo
   if 75 - 75: Ii1I * Oo0Ooo % iIii1I11I1II1 . O0 % oO0o
  return ( [ iiI1I . eid , iiI1I . group , LISP_DDT_ACTION_MS_ACK ] )
  if 4 - 4: I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
  if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
  if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
  if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
  if 66 - 66: iII111i % iII111i
 Iii1I11Iiii1 = len ( iiI1I . registered_rlocs )
 if ( Iii1I11Iiii1 == 0 ) :
  lprint ( ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" ) . format ( green ( iIiI1I1ii1I1 , False ) , ii1iIiII1Iiii1ii ,
  # i11iIiiIii + iII111i / i1IIi / Oo0Ooo
 green ( iiiiiiiiII1i , False ) ) )
  return ( [ iiI1I . eid , iiI1I . group , LISP_DDT_ACTION_MS_ACK ] )
  if 73 - 73: I1Ii111
  if 100 - 100: o0oOOo0O0Ooo + o0oOOo0O0Ooo
  if 75 - 75: Ii1I - o0oOOo0O0Ooo
  if 51 - 51: OoooooooOO . O0 / iII111i * OoO0O00
  if 89 - 89: II111iiii
 Iiii = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 30 - 30: I1IiiI
 iIIi111I1i1i = map_request . target_eid . hash_address ( Iiii )
 iIIi111I1i1i %= Iii1I11Iiii1
 OoO0OO0oO0ooOoO = iiI1I . registered_rlocs [ iIIi111I1i1i ]
 if 58 - 58: i11iIiiIii - iIii1I11I1II1 - o0oOOo0O0Ooo . Oo0Ooo * O0
 if ( OoO0OO0oO0ooOoO . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( iIiI1I1ii1I1 , False ) ,
  # ooOoO0o . Oo0Ooo
 ii1iIiII1Iiii1ii , green ( iiiiiiiiII1i , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( iIiI1I1ii1I1 , False ) ,
  # OOooOOo
 red ( OoO0OO0oO0ooOoO . rloc . print_address ( ) , False ) , ii1iIiII1Iiii1ii ,
 green ( iiiiiiiiII1i , False ) ) )
  if 64 - 64: Oo0Ooo % O0 . OOooOOo * OoooooooOO
  if 36 - 36: I1ii11iIi11i % OoooooooOO
  if 58 - 58: OoooooooOO
  if 57 - 57: I1ii11iIi11i % i1IIi % i1IIi % o0oOOo0O0Ooo
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , OoO0OO0oO0ooOoO . rloc , to_etr = True )
  if 45 - 45: IiII + oO0o . iII111i
 return ( [ iiI1I . eid , iiI1I . group , LISP_DDT_ACTION_MS_ACK ] )
 if 85 - 85: IiII * IiII * iII111i % i11iIiiIii
 if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
 if 10 - 10: OOooOOo / I1ii11iIi11i
 if 21 - 21: OoO0O00 % Oo0Ooo . o0oOOo0O0Ooo + IiII
 if 48 - 48: O0 / i1IIi / iII111i
 if 11 - 11: O0 - OoO0O00 + OoOoOO00 * ooOoO0o - Ii1I
 if 82 - 82: Ii1I - O0 * ooOoO0o . ooOoO0o
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 32 - 32: o0oOOo0O0Ooo . OoooooooOO % OOooOOo
 if 2 - 2: OoOoOO00 + I1ii11iIi11i + oO0o
 if 27 - 27: OoooooooOO - Ii1I / OoooooooOO + OoO0O00
 if 58 - 58: OOooOOo * I11i . I1IiiI
 oOooOOo000o0o = map_request . target_eid
 iiIoOOOOoo0O00o = map_request . target_group
 iIiI1I1ii1I1 = lisp_print_eid_tuple ( oOooOOo000o0o , iiIoOOOOoo0O00o )
 O0oo00o000 = map_request . nonce
 iiIIiI = LISP_DDT_ACTION_NULL
 if 46 - 46: I11i + II111iiii * iII111i % ooOoO0o - I1IiiI
 if 73 - 73: I1ii11iIi11i * iIii1I11I1II1 . I1Ii111 - Ii1I
 if 11 - 11: I11i
 if 48 - 48: IiII / O0
 if 46 - 46: ooOoO0o + oO0o
 i1iIi111iI1i = None
 if ( lisp_i_am_ms ) :
  iiI1I = lisp_site_eid_lookup ( oOooOOo000o0o , iiIoOOOOoo0O00o , False )
  if ( iiI1I == None ) : return
  if 49 - 49: i1IIi + I11i - Oo0Ooo * OOooOOo
  if ( iiI1I . registered ) :
   iiIIiI = LISP_DDT_ACTION_MS_ACK
   O0OOo = 1440
  else :
   oOooOOo000o0o , iiIoOOOOoo0O00o , iiIIiI = lisp_ms_compute_neg_prefix ( oOooOOo000o0o , iiIoOOOOoo0O00o )
   iiIIiI = LISP_DDT_ACTION_MS_NOT_REG
   O0OOo = 1
   if 86 - 86: i1IIi - IiII - Ii1I . I1IiiI + I1IiiI
 else :
  i1iIi111iI1i = lisp_ddt_cache_lookup ( oOooOOo000o0o , iiIoOOOOoo0O00o , False )
  if ( i1iIi111iI1i == None ) :
   iiIIiI = LISP_DDT_ACTION_NOT_AUTH
   O0OOo = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( iIiI1I1ii1I1 , False ) ) )
   if 89 - 89: o0oOOo0O0Ooo + iIii1I11I1II1 * OoooooooOO
  elif ( i1iIi111iI1i . is_auth_prefix ( ) ) :
   if 55 - 55: OoooooooOO / OOooOOo / iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo
   if 68 - 68: OOooOOo % Oo0Ooo * ooOoO0o * OoO0O00 / iII111i
   if 96 - 96: i11iIiiIii - I1IiiI % OoOoOO00 * Ii1I % OoO0O00 % O0
   if 100 - 100: oO0o . OoooooooOO
   iiIIiI = LISP_DDT_ACTION_DELEGATION_HOLE
   O0OOo = 15
   o0o0oO0000o = i1iIi111iI1i . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( o0o0oO0000o ,
   # IiII - O0
 green ( iIiI1I1ii1I1 , False ) ) )
   if 51 - 51: O0 + o0oOOo0O0Ooo
   if ( iiIoOOOOoo0O00o . is_null ( ) ) :
    oOooOOo000o0o = lisp_ddt_compute_neg_prefix ( oOooOOo000o0o , i1iIi111iI1i ,
 lisp_ddt_cache )
   else :
    iiIoOOOOoo0O00o = lisp_ddt_compute_neg_prefix ( iiIoOOOOoo0O00o , i1iIi111iI1i ,
 lisp_ddt_cache )
    oOooOOo000o0o = lisp_ddt_compute_neg_prefix ( oOooOOo000o0o , i1iIi111iI1i ,
 i1iIi111iI1i . source_cache )
    if 17 - 17: I1Ii111 - II111iiii / IiII . I1IiiI
   i1iIi111iI1i = None
  else :
   o0o0oO0000o = i1iIi111iI1i . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( o0o0oO0000o , green ( iIiI1I1ii1I1 , False ) ) )
   if 23 - 23: o0oOOo0O0Ooo * OoO0O00
   O0OOo = 1440
   if 20 - 20: i11iIiiIii * I1ii11iIi11i * ooOoO0o % iIii1I11I1II1 + iII111i
   if 51 - 51: O0 - I11i . o0oOOo0O0Ooo + o0oOOo0O0Ooo / I1Ii111
   if 32 - 32: II111iiii - Oo0Ooo
   if 69 - 69: o0oOOo0O0Ooo * I1ii11iIi11i / o0oOOo0O0Ooo * OoooooooOO
   if 60 - 60: OoOoOO00 / i1IIi * Oo0Ooo / i1IIi
   if 86 - 86: OoOoOO00 . I11i
 o0o0ooOOo0oO = lisp_build_map_referral ( oOooOOo000o0o , iiIoOOOOoo0O00o , i1iIi111iI1i , iiIIiI , O0OOo , O0oo00o000 )
 O0oo00o000 = map_request . nonce >> 32
 if ( map_request . nonce != 0 and O0oo00o000 != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , o0o0ooOOo0oO , ecm_source , port )
 return
 if 97 - 97: Ii1I
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
 if 15 - 15: I1IiiI
 if 88 - 88: IiII / I1ii11iIi11i % I11i + i11iIiiIii * O0 . I1Ii111
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 OOoOoO0oO = eid . hash_address ( entry_prefix )
 i1I1Ii = eid . addr_length ( ) * 8
 o00O00 = 0
 if 46 - 46: I11i + I1ii11iIi11i . I1ii11iIi11i % Ii1I . I1ii11iIi11i
 if 16 - 16: ooOoO0o / O0 * OoooooooOO % IiII - OOooOOo
 if 14 - 14: o0oOOo0O0Ooo * iII111i . OoO0O00 + i11iIiiIii + O0 / I11i
 if 99 - 99: I11i
 for o00O00 in range ( i1I1Ii ) :
  ooo00O0oo = 1 << ( i1I1Ii - o00O00 - 1 )
  if ( OOoOoO0oO & ooo00O0oo ) : break
  if 40 - 40: ooOoO0o
  if 57 - 57: i11iIiiIii / I1Ii111 * iII111i * OoOoOO00
 if ( o00O00 > neg_prefix . mask_len ) : neg_prefix . mask_len = o00O00
 return
 if 40 - 40: I1ii11iIi11i - OoooooooOO
 if 74 - 74: i11iIiiIii % i11iIiiIii / II111iiii + I1ii11iIi11i . OOooOOo
 if 83 - 83: I1IiiI . ooOoO0o . II111iiii % OOooOOo
 if 86 - 86: i11iIiiIii + I1ii11iIi11i / OoOoOO00 * OoooooooOO
 if 6 - 6: II111iiii
 if 26 - 26: iIii1I11I1II1 / iIii1I11I1II1 . IiII * i11iIiiIii
 if 21 - 21: OOooOOo + o0oOOo0O0Ooo
 if 28 - 28: OOooOOo + i1IIi + II111iiii / Oo0Ooo + iIii1I11I1II1 . Oo0Ooo
 if 73 - 73: Ii1I * iIii1I11I1II1 / o0oOOo0O0Ooo - o0oOOo0O0Ooo / i1IIi
 if 64 - 64: Ii1I * I1ii11iIi11i % II111iiii
def lisp_neg_prefix_walk ( entry , parms ) :
 oOooOOo000o0o , IiiI1i1I1II , O0OO = parms
 if 53 - 53: iII111i . i1IIi - i1IIi
 if ( IiiI1i1I1II == None ) :
  if ( entry . eid . instance_id != oOooOOo000o0o . instance_id ) :
   return ( [ True , parms ] )
   if 39 - 39: IiII - o0oOOo0O0Ooo
  if ( entry . eid . afi != oOooOOo000o0o . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( IiiI1i1I1II ) == False ) :
   return ( [ True , parms ] )
   if 76 - 76: oO0o / ooOoO0o
   if 25 - 25: IiII % o0oOOo0O0Ooo + o0oOOo0O0Ooo
   if 35 - 35: iII111i % IiII
   if 30 - 30: II111iiii . OoOoOO00 % OoOoOO00 % I11i / IiII / OoO0O00
   if 47 - 47: oO0o - I1ii11iIi11i
   if 42 - 42: Oo0Ooo - ooOoO0o % OoOoOO00 + OoOoOO00
 lisp_find_negative_mask_len ( oOooOOo000o0o , entry . eid , O0OO )
 return ( [ True , parms ] )
 if 61 - 61: I1Ii111
 if 67 - 67: I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
 if 75 - 75: OOooOOo . ooOoO0o
 if 32 - 32: i1IIi / I11i + iIii1I11I1II1 . OOooOOo
 if 67 - 67: iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
 if 51 - 51: I1IiiI + O0
 if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
 if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 85 - 85: OoOoOO00
 if 57 - 57: Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
 if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
 if 72 - 72: Ii1I
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 22 - 22: o0oOOo0O0Ooo / OoO0O00 + OoOoOO00 + Ii1I . II111iiii * I11i
 O0OO = lisp_address ( eid . afi , "" , 0 , 0 )
 O0OO . copy_address ( eid )
 O0OO . mask_len = 0
 if 85 - 85: i11iIiiIii / I11i
 Iii1i1 = ddt_entry . print_eid_tuple ( )
 IiiI1i1I1II = ddt_entry . eid
 if 32 - 32: ooOoO0o + I1ii11iIi11i + OoooooooOO - o0oOOo0O0Ooo % IiII
 if 75 - 75: i1IIi + II111iiii
 if 100 - 100: I11i - IiII . IiII . OoOoOO00 * OoooooooOO
 if 42 - 42: ooOoO0o * I1Ii111 + iII111i - iII111i
 if 71 - 71: i1IIi * I1Ii111 % iII111i * ooOoO0o / iIii1I11I1II1 % oO0o
 eid , IiiI1i1I1II , O0OO = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , IiiI1i1I1II , O0OO ) )
 if 60 - 60: OoOoOO00 % I1IiiI . i11iIiiIii % OoOoOO00 - I1Ii111
 if 71 - 71: OoooooooOO * Oo0Ooo
 if 80 - 80: iIii1I11I1II1
 if 91 - 91: OoOoOO00 + OoOoOO00 + ooOoO0o
 O0OO . mask_address ( O0OO . mask_len )
 if 44 - 44: I1ii11iIi11i * OOooOOo % OoO0O00 . I1IiiI % Ii1I + II111iiii
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # I1ii11iIi11i + i11iIiiIii - o0oOOo0O0Ooo / OoOoOO00 - OoOoOO00 % iIii1I11I1II1
 Iii1i1 , O0OO . print_prefix ( ) ) )
 return ( O0OO )
 if 87 - 87: iIii1I11I1II1 + i1IIi + oO0o . I1ii11iIi11i * I1IiiI / OoO0O00
 if 89 - 89: OoO0O00
 if 83 - 83: IiII + OOooOOo . OOooOOo
 if 44 - 44: OOooOOo
 if 11 - 11: i11iIiiIii % Oo0Ooo % II111iiii . IiII % OoOoOO00
 if 10 - 10: Ii1I
 if 68 - 68: Oo0Ooo % ooOoO0o + i11iIiiIii / oO0o / II111iiii
 if 63 - 63: OoO0O00 % i1IIi - OoooooooOO / ooOoO0o
def lisp_ms_compute_neg_prefix ( eid , group ) :
 O0OO = lisp_address ( eid . afi , "" , 0 , 0 )
 O0OO . copy_address ( eid )
 O0OO . mask_len = 0
 OOO0o0o = lisp_address ( group . afi , "" , 0 , 0 )
 OOO0o0o . copy_address ( group )
 OOO0o0o . mask_len = 0
 IiiI1i1I1II = None
 if 34 - 34: Oo0Ooo . iII111i
 if 86 - 86: I1ii11iIi11i * I1IiiI / OoO0O00 + i11iIiiIii / i11iIiiIii
 if 74 - 74: i11iIiiIii * OoooooooOO * i11iIiiIii * Oo0Ooo
 if 50 - 50: iIii1I11I1II1 / I1Ii111 / iII111i - o0oOOo0O0Ooo * OoO0O00
 if 18 - 18: I1ii11iIi11i - i1IIi * i11iIiiIii + I1IiiI - Oo0Ooo + OoOoOO00
 if ( group . is_null ( ) ) :
  i1iIi111iI1i = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( i1iIi111iI1i == None ) :
   O0OO . mask_len = O0OO . host_mask_len ( )
   OOO0o0o . mask_len = OOO0o0o . host_mask_len ( )
   return ( [ O0OO , OOO0o0o , LISP_DDT_ACTION_NOT_AUTH ] )
   if 77 - 77: OOooOOo % IiII + IiII / II111iiii
  iIi1i1Iii1Iii = lisp_sites_by_eid
  if ( i1iIi111iI1i . is_auth_prefix ( ) ) : IiiI1i1I1II = i1iIi111iI1i . eid
 else :
  i1iIi111iI1i = lisp_ddt_cache . lookup_cache ( group , False )
  if ( i1iIi111iI1i == None ) :
   O0OO . mask_len = O0OO . host_mask_len ( )
   OOO0o0o . mask_len = OOO0o0o . host_mask_len ( )
   return ( [ O0OO , OOO0o0o , LISP_DDT_ACTION_NOT_AUTH ] )
   if 27 - 27: OOooOOo + iIii1I11I1II1 . I1Ii111 % i1IIi % iII111i
  if ( i1iIi111iI1i . is_auth_prefix ( ) ) : IiiI1i1I1II = i1iIi111iI1i . group
  if 13 - 13: IiII / I11i + ooOoO0o - II111iiii . OOooOOo
  group , IiiI1i1I1II , OOO0o0o = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , IiiI1i1I1II , OOO0o0o ) )
  if 17 - 17: I1ii11iIi11i . Ii1I / IiII - i1IIi - Ii1I
  if 95 - 95: IiII % I11i % iIii1I11I1II1 . OoO0O00
  OOO0o0o . mask_address ( OOO0o0o . mask_len )
  if 11 - 11: i11iIiiIii - IiII . o0oOOo0O0Ooo / IiII - I1IiiI
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , IiiI1i1I1II . print_prefix ( ) if ( IiiI1i1I1II != None ) else "'not found'" ,
  # i11iIiiIii * i11iIiiIii . I11i / i11iIiiIii
  # I11i - IiII % ooOoO0o + I1IiiI % I11i - OOooOOo
  # i11iIiiIii - iIii1I11I1II1 / O0 / OoO0O00 + I1IiiI
 OOO0o0o . print_prefix ( ) ) )
  if 3 - 3: oO0o
  iIi1i1Iii1Iii = i1iIi111iI1i . source_cache
  if 17 - 17: OoO0O00 / OoO0O00 + o0oOOo0O0Ooo / OOooOOo . I1ii11iIi11i % IiII
  if 40 - 40: OoOoOO00
  if 81 - 81: Ii1I % I1Ii111 / I1ii11iIi11i % iII111i
  if 39 - 39: i1IIi . iII111i . Oo0Ooo % Oo0Ooo * IiII % Ii1I
  if 40 - 40: o0oOOo0O0Ooo * i11iIiiIii . ooOoO0o
 iiIIiI = LISP_DDT_ACTION_DELEGATION_HOLE if ( IiiI1i1I1II != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 63 - 63: I1Ii111 / Ii1I - iIii1I11I1II1 / i11iIiiIii / IiII + I11i
 if 57 - 57: iIii1I11I1II1 % iIii1I11I1II1
 if 23 - 23: II111iiii . ooOoO0o % I1Ii111
 if 39 - 39: OoooooooOO
 if 10 - 10: Oo0Ooo * iII111i
 if 78 - 78: Oo0Ooo / i11iIiiIii - I1IiiI
 eid , IiiI1i1I1II , O0OO = iIi1i1Iii1Iii . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , IiiI1i1I1II , O0OO ) )
 if 51 - 51: ooOoO0o / Oo0Ooo - I1Ii111 - iII111i
 if 68 - 68: I1ii11iIi11i - iIii1I11I1II1 * OoooooooOO
 if 44 - 44: OoooooooOO + I1Ii111 + OoO0O00
 if 15 - 15: iIii1I11I1II1 % i1IIi + iII111i
 O0OO . mask_address ( O0OO . mask_len )
 if 48 - 48: o0oOOo0O0Ooo / oO0o
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # I1IiiI % ooOoO0o + iII111i * Ii1I
 # I1Ii111
 IiiI1i1I1II . print_prefix ( ) if ( IiiI1i1I1II != None ) else "'not found'" , O0OO . print_prefix ( ) ) )
 if 79 - 79: IiII * IiII . OOooOOo + iIii1I11I1II1 . II111iiii
 if 87 - 87: I11i
 return ( [ O0OO , OOO0o0o , iiIIiI ] )
 if 67 - 67: i1IIi / i1IIi + IiII . oO0o
 if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
 if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
 if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
 if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
 if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
 if 45 - 45: iIii1I11I1II1 . o0oOOo0O0Ooo % I1IiiI
 if 10 - 10: I1IiiI / i1IIi * o0oOOo0O0Ooo + Oo0Ooo - OoOoOO00 % iII111i
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 88 - 88: Ii1I % Ii1I
 oOooOOo000o0o = map_request . target_eid
 iiIoOOOOoo0O00o = map_request . target_group
 O0oo00o000 = map_request . nonce
 if 29 - 29: OOooOOo % I1ii11iIi11i
 if ( action == LISP_DDT_ACTION_MS_ACK ) : O0OOo = 1440
 if 57 - 57: I1ii11iIi11i - OoOoOO00 + IiII
 if 58 - 58: OOooOOo % I1IiiI / oO0o . ooOoO0o . OoO0O00 / IiII
 if 72 - 72: ooOoO0o + ooOoO0o + o0oOOo0O0Ooo - o0oOOo0O0Ooo % Ii1I
 if 52 - 52: I11i % i1IIi . I1ii11iIi11i
 I1IIIiIiii1i = lisp_map_referral ( )
 I1IIIiIiii1i . record_count = 1
 I1IIIiIiii1i . nonce = O0oo00o000
 o0o0ooOOo0oO = I1IIIiIiii1i . encode ( )
 I1IIIiIiii1i . print_map_referral ( )
 if 62 - 62: ooOoO0o - I1ii11iIi11i
 O0OoooO = False
 if 71 - 71: I11i
 if 34 - 34: oO0o / O0 * oO0o
 if 47 - 47: iIii1I11I1II1 - o0oOOo0O0Ooo % Ii1I
 if 38 - 38: ooOoO0o / IiII * I1ii11iIi11i % I1ii11iIi11i % oO0o
 if 82 - 82: I1ii11iIi11i . i11iIiiIii - I11i . iII111i / OOooOOo
 if 60 - 60: I1IiiI / I1IiiI / II111iiii
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( oOooOOo000o0o ,
 iiIoOOOOoo0O00o )
  O0OOo = 15
  if 59 - 59: OOooOOo . oO0o + ooOoO0o % o0oOOo0O0Ooo . i11iIiiIii
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : O0OOo = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : O0OOo = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : O0OOo = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0OOo = 0
 if 27 - 27: OoOoOO00 - OoooooooOO / IiII / II111iiii * OOooOOo * ooOoO0o
 IiI = False
 Iii1I11Iiii1 = 0
 i1iIi111iI1i = lisp_ddt_cache_lookup ( oOooOOo000o0o , iiIoOOOOoo0O00o , False )
 if ( i1iIi111iI1i != None ) :
  Iii1I11Iiii1 = len ( i1iIi111iI1i . delegation_set )
  IiI = i1iIi111iI1i . is_ms_peer_entry ( )
  i1iIi111iI1i . map_referrals_sent += 1
  if 86 - 86: OoOoOO00 + OoooooooOO - OoooooooOO / I1Ii111 / I1Ii111 / I1IiiI
  if 95 - 95: OOooOOo % i1IIi + I1Ii111
  if 79 - 79: Ii1I
  if 77 - 77: i11iIiiIii + i11iIiiIii - I1ii11iIi11i % I1ii11iIi11i
  if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0OoooO = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  O0OoooO = ( IiI == False )
  if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
  if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
  if 77 - 77: OOooOOo + ooOoO0o / O0
  if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
  if 49 - 49: ooOoO0o . Ii1I
 oOO0O0o0oOooO = lisp_eid_record ( )
 oOO0O0o0oOooO . rloc_count = Iii1I11Iiii1
 oOO0O0o0oOooO . authoritative = True
 oOO0O0o0oOooO . action = action
 oOO0O0o0oOooO . ddt_incomplete = O0OoooO
 oOO0O0o0oOooO . eid = eid_prefix
 oOO0O0o0oOooO . group = group_prefix
 oOO0O0o0oOooO . record_ttl = O0OOo
 if 75 - 75: OOooOOo / II111iiii - Oo0Ooo + I1Ii111
 o0o0ooOOo0oO += oOO0O0o0oOooO . encode ( )
 oOO0O0o0oOooO . print_record ( "  " , True )
 if 42 - 42: OoooooooOO * II111iiii + Ii1I % OoO0O00 / I1Ii111
 if 11 - 11: ooOoO0o / Oo0Ooo + i1IIi / IiII
 if 4 - 4: iII111i - Oo0Ooo
 if 100 - 100: OOooOOo . i1IIi
 if ( Iii1I11Iiii1 != 0 ) :
  for I111IiiII in i1iIi111iI1i . delegation_set :
   iIIi = lisp_rloc_record ( )
   iIIi . rloc = I111IiiII . delegate_address
   iIIi . priority = I111IiiII . priority
   iIIi . weight = I111IiiII . weight
   iIIi . mpriority = 255
   iIIi . mweight = 0
   iIIi . reach_bit = True
   o0o0ooOOo0oO += iIIi . encode ( )
   iIIi . print_record ( "    " )
   if 15 - 15: O0 % Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o * iII111i % O0
   if 31 - 31: i1IIi . Ii1I - OoooooooOO * I11i * ooOoO0o % oO0o
   if 61 - 61: I1Ii111 . Ii1I * I1ii11iIi11i
   if 59 - 59: OoOoOO00 + Oo0Ooo . I1ii11iIi11i - Ii1I
   if 48 - 48: I1Ii111 % Ii1I + I1IiiI * OoooooooOO % OoOoOO00 % i11iIiiIii
   if 13 - 13: iII111i % i1IIi
   if 13 - 13: iII111i / OoooooooOO + Ii1I / iII111i
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , o0o0ooOOo0oO , ecm_source , port )
 return
 if 29 - 29: OOooOOo + ooOoO0o % o0oOOo0O0Ooo
 if 18 - 18: I11i + OoO0O00 + OoO0O00 . ooOoO0o
 if 37 - 37: i1IIi . IiII + I1IiiI % OoOoOO00
 if 3 - 3: i11iIiiIii + Ii1I % IiII - I1Ii111 / Oo0Ooo % iIii1I11I1II1
 if 86 - 86: Oo0Ooo + Oo0Ooo * oO0o * I1IiiI
 if 95 - 95: IiII - OoO0O00 + OOooOOo
 if 33 - 33: o0oOOo0O0Ooo . i11iIiiIii . ooOoO0o
 if 100 - 100: i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / i11iIiiIii + OOooOOo
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 55 - 55: i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # II111iiii % O0 + o0oOOo0O0Ooo / Ii1I
 red ( dest . print_address ( ) , False ) ) )
 if 55 - 55: Oo0Ooo / Oo0Ooo - I1IiiI
 iiIIiI = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 94 - 94: OoO0O00 % I11i
 if 41 - 41: I1ii11iIi11i * IiII
 if 16 - 16: I1Ii111 % iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / OoOoOO00
 if 29 - 29: OoooooooOO / oO0o
 if 1 - 1: OoOoOO00 . i11iIiiIii % I1Ii111 + OoooooooOO - Oo0Ooo . I1ii11iIi11i
 if ( lisp_get_eid_hash ( eid ) != None ) :
  iiIIiI = LISP_SEND_MAP_REQUEST_ACTION
  if 46 - 46: i11iIiiIii + I11i - iIii1I11I1II1 / OoO0O00 - ooOoO0o / i1IIi
  if 44 - 44: o0oOOo0O0Ooo + Oo0Ooo
 o0o0ooOOo0oO = lisp_build_map_reply ( eid , group , [ ] , nonce , iiIIiI , ttl , None ,
 None , False , False )
 if 46 - 46: OOooOOo % I1IiiI
 if 66 - 66: iIii1I11I1II1 . o0oOOo0O0Ooo - ooOoO0o
 if 27 - 27: Oo0Ooo - i1IIi * OoooooooOO - OoOoOO00 + OoOoOO00
 if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , o0o0ooOOo0oO , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , o0o0ooOOo0oO , dest , port )
  if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
 return
 if 85 - 85: iII111i % i11iIiiIii
 if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
 if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
 if 41 - 41: Ii1I + IiII
 if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
 if 53 - 53: I1IiiI % OOooOOo + Ii1I - Ii1I
 if 99 - 99: i1IIi * OoOoOO00 - i1IIi
def lisp_retransmit_ddt_map_request ( mr ) :
 OOOo = mr . mr_source . print_address ( )
 I111111 = mr . print_eid_tuple ( )
 O0oo00o000 = mr . nonce
 if 30 - 30: OoO0O00 - Oo0Ooo . IiII * ooOoO0o % OOooOOo % i11iIiiIii
 if 45 - 45: I1Ii111 / OoO0O00
 if 15 - 15: Oo0Ooo + oO0o . I11i % OoO0O00
 if 13 - 13: I1ii11iIi11i / ooOoO0o * I1Ii111
 if 45 - 45: I1ii11iIi11i - I11i
 if ( mr . last_request_sent_to ) :
  O000oO00 = mr . last_request_sent_to . print_address ( )
  O0OOoO = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( O0OOoO and O0OOoO . referral_set . has_key ( O000oO00 ) ) :
   O0OOoO . referral_set [ O000oO00 ] . no_responses += 1
   if 88 - 88: OoOoOO00 . i11iIiiIii % OoooooooOO . oO0o . O0 + iIii1I11I1II1
   if 11 - 11: OoO0O00 / I1Ii111 . OoOoOO00
   if 95 - 95: I1ii11iIi11i / Ii1I % ooOoO0o . OoooooooOO % OoOoOO00 . OoOoOO00
   if 1 - 1: I1ii11iIi11i % o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - ooOoO0o - OoO0O00
   if 94 - 94: OoO0O00 . Oo0Ooo / OoO0O00 + I1Ii111
   if 48 - 48: I1ii11iIi11i * i1IIi + I1Ii111
   if 80 - 80: I1IiiI % I11i
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( I111111 , False ) , lisp_hex_string ( O0oo00o000 ) ) )
  if 64 - 64: OOooOOo + i11iIiiIii + I1IiiI . I11i % I11i - o0oOOo0O0Ooo
  mr . dequeue_map_request ( )
  return
  if 3 - 3: I1IiiI / i1IIi + II111iiii + Oo0Ooo
  if 48 - 48: o0oOOo0O0Ooo
 mr . retry_count += 1
 if 16 - 16: II111iiii . Ii1I + I1Ii111 % i1IIi / i11iIiiIii + OOooOOo
 I1iiIi111I = green ( OOOo , False )
 IiI11I111 = green ( I111111 , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # iIii1I11I1II1 % Oo0Ooo + Oo0Ooo
 red ( mr . itr . print_address ( ) , False ) , I1iiIi111I , IiI11I111 ,
 lisp_hex_string ( O0oo00o000 ) ) )
 if 44 - 44: I11i / OoO0O00
 if 66 - 66: i11iIiiIii
 if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
 if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
 lisp_send_ddt_map_request ( mr , False )
 if 83 - 83: i1IIi * i1IIi - II111iiii / OoooooooOO . Ii1I + I1Ii111
 if 10 - 10: I11i
 if 24 - 24: Ii1I
 if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 25 - 25: I11i % i1IIi / I11i * i11iIiiIii
 if 71 - 71: IiII % I11i - OoooooooOO + I1IiiI / Oo0Ooo % I11i
 if 6 - 6: i1IIi * i11iIiiIii + ooOoO0o - IiII
 if 97 - 97: iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - Oo0Ooo - iIii1I11I1II1
 if 26 - 26: ooOoO0o + Oo0Ooo
 if 24 - 24: I1IiiI
 if 43 - 43: OoO0O00
 if 51 - 51: OoooooooOO % IiII % Oo0Ooo
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 50 - 50: I1IiiI - i11iIiiIii / I1ii11iIi11i . Ii1I - iIii1I11I1II1
 if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
 if 95 - 95: iII111i
 if 77 - 77: I1IiiI * II111iiii * iIii1I11I1II1
 i1III11i1iI11 = [ ]
 for iIiIIIiiIi in referral . referral_set . values ( ) :
  if ( iIiIIIiiIi . updown == False ) : continue
  if ( len ( i1III11i1iI11 ) == 0 or i1III11i1iI11 [ 0 ] . priority == iIiIIIiiIi . priority ) :
   i1III11i1iI11 . append ( iIiIIIiiIi )
  elif ( i1III11i1iI11 [ 0 ] . priority > iIiIIIiiIi . priority ) :
   i1III11i1iI11 = [ ]
   i1III11i1iI11 . append ( iIiIIIiiIi )
   if 25 - 25: OoooooooOO / iII111i * OOooOOo
   if 1 - 1: OOooOOo / II111iiii / II111iiii % OoO0O00 % iIii1I11I1II1
   if 36 - 36: I1IiiI / O0
 IiiI11I = len ( i1III11i1iI11 )
 if ( IiiI11I == 0 ) : return ( None )
 if 8 - 8: OOooOOo
 iIIi111I1i1i = dest_eid . hash_address ( source_eid )
 iIIi111I1i1i = iIIi111I1i1i % IiiI11I
 return ( i1III11i1iI11 [ iIIi111I1i1i ] )
 if 28 - 28: ooOoO0o
 if 37 - 37: OoOoOO00
 if 1 - 1: oO0o - II111iiii - IiII
 if 93 - 93: OoOoOO00 + OoooooooOO . OOooOOo / oO0o / OoOoOO00
 if 94 - 94: OoO0O00 / i1IIi . OoO0O00 . I1Ii111 + OoO0O00
 if 30 - 30: o0oOOo0O0Ooo + iIii1I11I1II1 - II111iiii - ooOoO0o + OoOoOO00 - II111iiii
 if 69 - 69: oO0o / O0 / I1IiiI + OoooooooOO * I11i * IiII
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 i1i1iI1Iiii = mr . lisp_sockets
 O0oo00o000 = mr . nonce
 OO = mr . itr
 IiiIiiii1i = mr . mr_source
 iIiI1I1ii1I1 = mr . print_eid_tuple ( )
 if 20 - 20: OOooOOo % O0 * Oo0Ooo . II111iiii
 if 82 - 82: OoO0O00
 if 54 - 54: i1IIi * OOooOOo - oO0o * OoooooooOO + II111iiii . IiII
 if 90 - 90: O0 - II111iiii + I1IiiI . iII111i
 if 3 - 3: o0oOOo0O0Ooo + i1IIi * Oo0Ooo
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( iIiI1I1ii1I1 , False ) , lisp_hex_string ( O0oo00o000 ) ) )
  if 6 - 6: OoO0O00 * OoooooooOO * iIii1I11I1II1
  mr . dequeue_map_request ( )
  return
  if 87 - 87: iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1
  if 79 - 79: ooOoO0o . oO0o + Ii1I * ooOoO0o + O0 . II111iiii
  if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
  if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
  if 5 - 5: OoooooooOO + ooOoO0o - II111iiii . i11iIiiIii / oO0o - ooOoO0o
  if 3 - 3: iII111i
 if ( send_to_root ) :
  ooooOo = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  IIIIIiiII11i = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( iIiI1I1ii1I1 , False ) ) )
 else :
  ooooOo = mr . eid
  IIIIIiiII11i = mr . group
  if 79 - 79: OoOoOO00 . OOooOOo
  if 97 - 97: II111iiii . OOooOOo
  if 68 - 68: IiII * IiII + oO0o / o0oOOo0O0Ooo
  if 41 - 41: OoOoOO00 - O0
  if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
 o0OOo0 = lisp_referral_cache_lookup ( ooooOo , IIIIIiiII11i , False )
 if ( o0OOo0 == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( i1i1iI1Iiii , ooooOo , IIIIIiiII11i ,
 O0oo00o000 , OO , mr . sport , 15 , None , False )
  return
  if 55 - 55: i11iIiiIii + I11i % oO0o * O0
  if 19 - 19: oO0o . i1IIi . Oo0Ooo
 Ooo00 = o0OOo0 . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( Ooo00 ,
 o0OOo0 . print_referral_type ( ) ) )
 if 59 - 59: O0 . OoO0O00
 iIiIIIiiIi = lisp_get_referral_node ( o0OOo0 , IiiIiiii1i , mr . eid )
 if ( iIiIIIiiIi == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( i1i1iI1Iiii , o0OOo0 . eid ,
 o0OOo0 . group , O0oo00o000 , OO , mr . sport , 1 , None , False )
  return
  if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
  if 81 - 81: i1IIi % I11i * iIii1I11I1II1
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( iIiIIIiiIi . referral_address . print_address ( ) ,
 # i1IIi * O0 . O0
 o0OOo0 . print_referral_type ( ) , green ( iIiI1I1ii1I1 , False ) ,
 lisp_hex_string ( O0oo00o000 ) ) )
 if 55 - 55: iIii1I11I1II1
 if 7 - 7: OoO0O00
 if 61 - 61: I1Ii111 / I1IiiI / OOooOOo . I1ii11iIi11i
 if 3 - 3: IiII
 Ii11iI11III = ( o0OOo0 . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 o0OOo0 . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( i1i1iI1Iiii , mr . packet , IiiIiiii1i , mr . sport , mr . eid ,
 iIiIIIiiIi . referral_address , to_ms = Ii11iI11III , ddt = True )
 if 44 - 44: i1IIi / OoooooooOO * OoooooooOO
 if 93 - 93: OoOoOO00 % Oo0Ooo . OoO0O00 / OoooooooOO
 if 59 - 59: OoO0O00 + O0 + i11iIiiIii / OoOoOO00 + iIii1I11I1II1 / OoOoOO00
 if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
 mr . last_request_sent_to = iIiIIIiiIi . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 iIiIIIiiIi . map_requests_sent += 1
 return
 if 93 - 93: OoO0O00 % IiII % ooOoO0o . I1IiiI
 if 96 - 96: II111iiii
 if 73 - 73: II111iiii
 if 81 - 81: I1IiiI + OoO0O00
 if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
 if 32 - 32: o0oOOo0O0Ooo - iII111i + i11iIiiIii / ooOoO0o . OoOoOO00 . IiII
 if 9 - 9: iIii1I11I1II1
 if 66 - 66: iIii1I11I1II1
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 13 - 13: O0 / ooOoO0o
 oOooOOo000o0o = map_request . target_eid
 iiIoOOOOoo0O00o = map_request . target_group
 I111111 = map_request . print_eid_tuple ( )
 OOOo = mr_source . print_address ( )
 O0oo00o000 = map_request . nonce
 if 64 - 64: i11iIiiIii + I1IiiI / Oo0Ooo - iII111i
 I1iiIi111I = green ( OOOo , False )
 IiI11I111 = green ( I111111 , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # I1ii11iIi11i . OOooOOo
 red ( ecm_source . print_address ( ) , False ) , I1iiIi111I , IiI11I111 ,
 lisp_hex_string ( O0oo00o000 ) ) )
 if 86 - 86: II111iiii * Oo0Ooo . IiII . iII111i + II111iiii . iIii1I11I1II1
 if 88 - 88: OoooooooOO % ooOoO0o
 if 71 - 71: II111iiii * I1IiiI * Oo0Ooo / II111iiii + iIii1I11I1II1 % i1IIi
 if 85 - 85: IiII * O0 . I1Ii111 . II111iiii
 IIIIIii1Ii1II = lisp_ddt_map_request ( lisp_sockets , packet , oOooOOo000o0o , iiIoOOOOoo0O00o , O0oo00o000 )
 IIIIIii1Ii1II . packet = packet
 IIIIIii1Ii1II . itr = ecm_source
 IIIIIii1Ii1II . mr_source = mr_source
 IIIIIii1Ii1II . sport = sport
 IIIIIii1Ii1II . from_pitr = map_request . pitr_bit
 IIIIIii1Ii1II . queue_map_request ( )
 if 33 - 33: I1Ii111 / II111iiii % i11iIiiIii % I1IiiI . iII111i
 lisp_send_ddt_map_request ( IIIIIii1Ii1II , False )
 return
 if 11 - 11: ooOoO0o / iIii1I11I1II1 * OOooOOo / I11i - Ii1I
 if 64 - 64: OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - OOooOOo - I1IiiI
 if 75 - 75: I1ii11iIi11i
 if 77 - 77: iIii1I11I1II1 . OOooOOo
 if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
 if 61 - 61: OOooOOo
 if 51 - 51: Oo0Ooo * OOooOOo / iII111i
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl , timestamp ) :
 if 49 - 49: ooOoO0o . i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + OoO0O00
 iII111I = packet
 OOo00o = lisp_map_request ( )
 packet = OOo00o . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 36 - 36: O0 . I11i / o0oOOo0O0Ooo + i1IIi + oO0o * IiII
  if 29 - 29: O0 - II111iiii + iII111i
 OOo00o . print_map_request ( )
 if 73 - 73: I1Ii111 - I11i + IiII - o0oOOo0O0Ooo - I11i - OOooOOo
 if 40 - 40: iIii1I11I1II1 . iII111i * I1ii11iIi11i + IiII - iIii1I11I1II1
 if 83 - 83: i1IIi
 if 9 - 9: iIii1I11I1II1 + i11iIiiIii
 if ( OOo00o . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , OOo00o , mr_source ,
 mr_port , ttl , timestamp )
  return
  if 70 - 70: I1IiiI - OoO0O00 % OOooOOo + ooOoO0o % II111iiii
  if 19 - 19: I11i + i1IIi / i1IIi - II111iiii + I1Ii111
  if 11 - 11: i11iIiiIii % i11iIiiIii / IiII - Oo0Ooo / O0 - I11i
  if 29 - 29: OOooOOo * iIii1I11I1II1 * ooOoO0o
  if 80 - 80: oO0o * I1Ii111
 if ( OOo00o . smr_bit ) :
  lisp_process_smr ( OOo00o )
  if 87 - 87: iII111i + OoOoOO00 % ooOoO0o - oO0o
  if 40 - 40: i1IIi / OoOoOO00 - I11i / ooOoO0o . Ii1I
  if 8 - 8: I1IiiI . IiII . OOooOOo . O0
  if 3 - 3: Ii1I + i11iIiiIii
  if 87 - 87: ooOoO0o - iII111i % I11i
 if ( OOo00o . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( OOo00o )
  if 88 - 88: I11i . OoooooooOO
  if 86 - 86: Ii1I - I1IiiI - iII111i % Ii1I . I1ii11iIi11i % i1IIi
  if 84 - 84: OoOoOO00
  if 99 - 99: OoO0O00 - OoOoOO00 - i1IIi / OoO0O00 * I1ii11iIi11i * iIii1I11I1II1
  if 65 - 65: iII111i - O0 / i1IIi . I1Ii111
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , OOo00o , mr_source ,
 mr_port , ttl , timestamp )
  if 85 - 85: o0oOOo0O0Ooo % Ii1I
  if 81 - 81: oO0o / OoO0O00 * i1IIi % iIii1I11I1II1
  if 23 - 23: II111iiii . II111iiii
  if 17 - 17: i11iIiiIii / IiII * I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - iIii1I11I1II1
  if 21 - 21: OOooOOo % Ii1I
 if ( lisp_i_am_ms ) :
  packet = iII111I
  oOooOOo000o0o , iiIoOOOOoo0O00o , IIi1IIIIIiIIII = lisp_ms_process_map_request ( lisp_sockets ,
 iII111I , OOo00o , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , OOo00o , ecm_source ,
 ecm_port , IIi1IIIIIiIIII , oOooOOo000o0o , iiIoOOOOoo0O00o )
   if 100 - 100: I1IiiI / I1Ii111 * i1IIi
  return
  if 4 - 4: OoO0O00 + O0 * OOooOOo * I1Ii111 / O0
  if 58 - 58: OOooOOo % ooOoO0o * I1IiiI - I1ii11iIi11i / I11i + iII111i
  if 26 - 26: OoOoOO00
  if 63 - 63: I1Ii111 . oO0o + OoO0O00 / I1ii11iIi11i % IiII * II111iiii
  if 92 - 92: iIii1I11I1II1 . OoooooooOO . ooOoO0o / II111iiii
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , iII111I , OOo00o ,
 ecm_source , mr_port , mr_source )
  if 30 - 30: i1IIi * Ii1I + Ii1I / I1Ii111
  if 84 - 84: I1IiiI - Oo0Ooo * OoO0O00 * oO0o
  if 13 - 13: I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + oO0o - iII111i
  if 32 - 32: I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * I1Ii111 % II111iiii
  if 33 - 33: ooOoO0o % I11i
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = iII111I
  lisp_ddt_process_map_request ( lisp_sockets , OOo00o , ecm_source ,
 ecm_port )
  if 72 - 72: OoO0O00 % OoooooooOO / II111iiii * oO0o * I1Ii111
 return
 if 98 - 98: OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / OoOoOO00 + I1IiiI
 if 74 - 74: ooOoO0o . IiII . O0 * I1IiiI * oO0o
 if 6 - 6: O0 . Ii1I / Oo0Ooo * o0oOOo0O0Ooo
 if 1 - 1: i11iIiiIii
 if 30 - 30: I11i
 if 26 - 26: Oo0Ooo - II111iiii % ooOoO0o
 if 81 - 81: i11iIiiIii + I1ii11iIi11i * oO0o
 if 86 - 86: OoO0O00 . ooOoO0o . o0oOOo0O0Ooo
def lisp_store_mr_stats ( source , nonce ) :
 IIIIIii1Ii1II = lisp_get_map_resolver ( source , None )
 if ( IIIIIii1Ii1II == None ) : return
 if 70 - 70: O0 % OoooooooOO - Ii1I * Oo0Ooo
 if 18 - 18: OOooOOo . I1IiiI + i1IIi . I1IiiI
 if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
 if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
 IIIIIii1Ii1II . neg_map_replies_received += 1
 IIIIIii1Ii1II . last_reply = lisp_get_timestamp ( )
 if 6 - 6: O0 * I1Ii111 - II111iiii
 if 60 - 60: oO0o % oO0o
 if 76 - 76: I1Ii111 / o0oOOo0O0Ooo
 if 19 - 19: O0 . i1IIi % iIii1I11I1II1 + OOooOOo * OoOoOO00 / I11i
 if ( ( IIIIIii1Ii1II . neg_map_replies_received % 100 ) == 0 ) : IIIIIii1Ii1II . total_rtt = 0
 if 82 - 82: I1ii11iIi11i
 if 75 - 75: I11i - II111iiii
 if 84 - 84: I1ii11iIi11i * IiII / I1IiiI - Ii1I + IiII - i1IIi
 if 98 - 98: II111iiii - iII111i % i11iIiiIii + ooOoO0o
 if ( IIIIIii1Ii1II . last_nonce == nonce ) :
  IIIIIii1Ii1II . total_rtt += ( time . time ( ) - IIIIIii1Ii1II . last_used )
  IIIIIii1Ii1II . last_nonce = 0
  if 76 - 76: OOooOOo - iII111i + IiII
 if ( ( IIIIIii1Ii1II . neg_map_replies_received % 10 ) == 0 ) : IIIIIii1Ii1II . last_nonce = 0
 return
 if 48 - 48: I1IiiI - II111iiii
 if 15 - 15: O0
 if 54 - 54: iIii1I11I1II1
 if 54 - 54: iII111i + OOooOOo + OoO0O00
 if 6 - 6: oO0o - OoooooooOO * iIii1I11I1II1 * I1ii11iIi11i
 if 65 - 65: IiII + OoOoOO00
 if 93 - 93: Ii1I
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl , itr_in_ts ) :
 global lisp_map_cache
 if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
 iIO0OOoOOO0OO = lisp_map_reply ( )
 packet = iIO0OOoOOO0OO . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 5 - 5: OoO0O00 / ooOoO0o
 iIO0OOoOOO0OO . print_map_reply ( )
 if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
 if 97 - 97: oO0o / Ii1I
 if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
 if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
 o0000o0OO00OO = None
 for OoOOoO0oOo in range ( iIO0OOoOOO0OO . record_count ) :
  oOO0O0o0oOooO = lisp_eid_record ( )
  packet = oOO0O0o0oOooO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 68 - 68: I1Ii111 + ooOoO0o - IiII * oO0o % OoO0O00 + i1IIi
  oOO0O0o0oOooO . print_record ( "  " , False )
  if 93 - 93: Ii1I - OoOoOO00 / I1IiiI % oO0o - Ii1I
  if 97 - 97: OOooOOo / ooOoO0o . Oo0Ooo - Oo0Ooo . OoOoOO00
  if 88 - 88: iIii1I11I1II1 - OoO0O00 + II111iiii
  if 100 - 100: I1Ii111 + I1IiiI + OOooOOo * iII111i
  if 35 - 35: Oo0Ooo . O0
  if ( oOO0O0o0oOooO . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , iIO0OOoOOO0OO . nonce )
   if 43 - 43: oO0o . O0 . OOooOOo
   if 3 - 3: i1IIi
  o0OooO = ( oOO0O0o0oOooO . group . is_null ( ) == False )
  if 85 - 85: i11iIiiIii % i1IIi
  if 78 - 78: ooOoO0o / I1ii11iIi11i
  if 72 - 72: II111iiii / O0 - I1ii11iIi11i + oO0o + iIii1I11I1II1
  if 65 - 65: OoO0O00 * II111iiii
  if 25 - 25: I1ii11iIi11i - I1Ii111 * I1Ii111 / O0 - iIii1I11I1II1 . iII111i
  if ( lisp_decent_push_configured ) :
   iiIIiI = oOO0O0o0oOooO . action
   if ( o0OooO and iiIIiI == LISP_DROP_ACTION ) :
    if ( oOO0O0o0oOooO . eid . is_local ( ) ) : continue
    if 83 - 83: ooOoO0o * oO0o * OoO0O00 + OoO0O00
    if 58 - 58: I1ii11iIi11i
    if 93 - 93: i1IIi - IiII + IiII % OoooooooOO / o0oOOo0O0Ooo
    if 39 - 39: I1IiiI + Ii1I - O0
    if 25 - 25: IiII % iIii1I11I1II1 + ooOoO0o % iII111i - OoO0O00
    if 36 - 36: OoooooooOO / oO0o + IiII . I1IiiI - o0oOOo0O0Ooo % OOooOOo
    if 15 - 15: Ii1I % IiII + IiII % iII111i - O0 * OoooooooOO
  if ( o0OooO == False and oOO0O0o0oOooO . eid . is_null ( ) ) : continue
  if 53 - 53: OoOoOO00 . Ii1I / Oo0Ooo
  if 62 - 62: i11iIiiIii
  if 38 - 38: I1ii11iIi11i % ooOoO0o * OoooooooOO + iIii1I11I1II1 % i1IIi / OOooOOo
  if 6 - 6: i11iIiiIii
  if 8 - 8: iIii1I11I1II1 + I1ii11iIi11i . i1IIi % OoOoOO00 % OoooooooOO * Oo0Ooo
  if ( o0OooO ) :
   ooOoOO0Oo = lisp_map_cache_lookup ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group )
  else :
   ooOoOO0Oo = lisp_map_cache . lookup_cache ( oOO0O0o0oOooO . eid , True )
   if 12 - 12: Oo0Ooo / iII111i
  ooo0IIi1I11 = ( ooOoOO0Oo == None )
  if 100 - 100: I1Ii111
  if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
  if 88 - 88: IiII
  if 29 - 29: iII111i . ooOoO0o
  if 62 - 62: IiII
  if ( ooOoOO0Oo == None ) :
   O0OoO , Ii1i1I1Ii , I1iI1 = lisp_allow_gleaning ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group ,
 None )
   if ( O0OoO ) : continue
  else :
   if ( ooOoOO0Oo . gleaned ) : continue
   if 27 - 27: OoO0O00 + OOooOOo / ooOoO0o * I1IiiI / I11i
   if 84 - 84: iII111i . i11iIiiIii % ooOoO0o % O0 + I1IiiI
   if 25 - 25: iIii1I11I1II1
   if 95 - 95: ooOoO0o * OoO0O00 % OoooooooOO % OoO0O00
   if 79 - 79: II111iiii % Ii1I * oO0o * iII111i + II111iiii
  oOO000OOO = [ ]
  OoO0oo = None
  for O0O0Oo in range ( oOO0O0o0oOooO . rloc_count ) :
   iIIi = lisp_rloc_record ( )
   iIIi . keys = iIO0OOoOOO0OO . keys
   packet = iIIi . decode ( packet , iIO0OOoOOO0OO . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 73 - 73: IiII * OoooooooOO % Ii1I
   iIIi . print_record ( "    " )
   if 11 - 11: I1ii11iIi11i
   o0i1i1iiI = None
   if ( ooOoOO0Oo ) : o0i1i1iiI = ooOoOO0Oo . get_rloc ( iIIi . rloc )
   if ( o0i1i1iiI ) :
    IIIi1iI1 = o0i1i1iiI
   else :
    IIIi1iI1 = lisp_rloc ( )
    if 55 - 55: i11iIiiIii / II111iiii / I1Ii111 * iIii1I11I1II1 / II111iiii * iIii1I11I1II1
    if 41 - 41: o0oOOo0O0Ooo . iII111i % iII111i . OOooOOo / OOooOOo
    if 98 - 98: II111iiii + ooOoO0o - iIii1I11I1II1 . I11i . iIii1I11I1II1 - iIii1I11I1II1
    if 91 - 91: ooOoO0o
    if 66 - 66: OOooOOo
    if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
    if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
   IiO0o = IIIi1iI1 . store_rloc_from_record ( iIIi , iIO0OOoOOO0OO . nonce ,
 source )
   IIIi1iI1 . echo_nonce_capable = iIO0OOoOOO0OO . echo_nonce_capable
   if 9 - 9: Ii1I
   if ( IIIi1iI1 . echo_nonce_capable ) :
    O0O0 = IIIi1iI1 . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , O0O0 ) == None ) :
     lisp_echo_nonce ( O0O0 )
     if 44 - 44: iII111i
     if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
     if 37 - 37: OoO0O00 - Ii1I + OoO0O00
     if 49 - 49: OoooooooOO - I1ii11iIi11i % I1ii11iIi11i / i1IIi . ooOoO0o
     if 60 - 60: Oo0Ooo
     if 46 - 46: OoOoOO00 + i1IIi
   if ( IIIi1iI1 . json ) :
    if ( lisp_is_json_telemetry ( IIIi1iI1 . json . json_string ) ) :
     Ii1Iii1II11 = IIIi1iI1 . json . json_string
     Ii1Iii1II11 = lisp_encode_telemetry ( Ii1Iii1II11 , ii = itr_in_ts )
     IIIi1iI1 . json . json_string = Ii1Iii1II11
     if 43 - 43: II111iiii * IiII % iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
     if 81 - 81: oO0o % I1ii11iIi11i % ooOoO0o * O0 - OOooOOo
     if 17 - 17: O0 % O0 / I1ii11iIi11i . Oo0Ooo . iII111i
     if 4 - 4: OoO0O00
     if 65 - 65: Oo0Ooo % O0 / I1Ii111 * IiII - oO0o
     if 32 - 32: Ii1I * OoO0O00 + ooOoO0o
     if 41 - 41: IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
     if 38 - 38: iII111i * OoooooooOO - IiII
     if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
     if 91 - 91: O0 + I1Ii111 * II111iiii - O0 . i11iIiiIii . Oo0Ooo
   if ( iIO0OOoOOO0OO . rloc_probe and iIIi . probe_bit ) :
    if ( IIIi1iI1 . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( IIIi1iI1 , source , IiO0o ,
 iIO0OOoOOO0OO , ttl , OoO0oo )
     if 54 - 54: ooOoO0o * I11i / I1ii11iIi11i % ooOoO0o
    if ( IIIi1iI1 . rloc . is_multicast_address ( ) ) : OoO0oo = IIIi1iI1
    if 76 - 76: I11i . I1IiiI
    if 66 - 66: oO0o % oO0o * IiII
    if 39 - 39: i1IIi * Ii1I + OoOoOO00 / oO0o
    if 6 - 6: I1ii11iIi11i / II111iiii / OoOoOO00 . i11iIiiIii - iII111i
    if 43 - 43: i11iIiiIii * i11iIiiIii * I1Ii111
   oOO000OOO . append ( IIIi1iI1 )
   if 80 - 80: oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / o0oOOo0O0Ooo % OoooooooOO
   if 31 - 31: o0oOOo0O0Ooo - OoO0O00 % I1IiiI
   if 23 - 23: OOooOOo
   if 97 - 97: Oo0Ooo / OoooooooOO . OoooooooOO
   if ( lisp_data_plane_security and IIIi1iI1 . rloc_recent_rekey ( ) ) :
    o0000o0OO00OO = IIIi1iI1
    if 47 - 47: OoO0O00
    if 52 - 52: I1IiiI * iIii1I11I1II1 % oO0o * IiII % oO0o
    if 9 - 9: I11i
    if 83 - 83: i11iIiiIii
    if 72 - 72: oO0o + II111iiii . O0 * oO0o + iII111i
    if 22 - 22: I11i + Ii1I . IiII - OoO0O00 - o0oOOo0O0Ooo
    if 84 - 84: OoooooooOO - Oo0Ooo
    if 86 - 86: O0 + OoO0O00 + O0 . I1IiiI
    if 82 - 82: OoOoOO00
    if 61 - 61: oO0o . o0oOOo0O0Ooo
    if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
  if ( iIO0OOoOOO0OO . rloc_probe == False and lisp_nat_traversal ) :
   iii1 = [ ]
   o0o00 = [ ]
   for IIIi1iI1 in oOO000OOO :
    if 28 - 28: iIii1I11I1II1 - o0oOOo0O0Ooo . iIii1I11I1II1 / I11i / I1Ii111 % iIii1I11I1II1
    if 45 - 45: OoO0O00 + ooOoO0o / iIii1I11I1II1 % i11iIiiIii
    if 16 - 16: i1IIi / oO0o - OOooOOo / Ii1I + I1IiiI
    if 62 - 62: i11iIiiIii . Ii1I . iII111i / I1Ii111 * OoO0O00
    if 31 - 31: OoOoOO00
    if ( IIIi1iI1 . rloc . is_private_address ( ) ) :
     IIIi1iI1 . priority = 1
     IIIi1iI1 . state = LISP_RLOC_UNREACH_STATE
     iii1 . append ( IIIi1iI1 )
     o0o00 . append ( IIIi1iI1 . rloc . print_address_no_iid ( ) )
     continue
     if 16 - 16: OoooooooOO
     if 32 - 32: ooOoO0o - o0oOOo0O0Ooo / ooOoO0o + o0oOOo0O0Ooo + iII111i
     if 78 - 78: OoooooooOO . I1ii11iIi11i * oO0o . o0oOOo0O0Ooo * OoOoOO00 / oO0o
     if 47 - 47: OOooOOo
     if 40 - 40: I1ii11iIi11i
     if 67 - 67: I1Ii111 - OoO0O00 * ooOoO0o - oO0o / OoO0O00 . I1Ii111
    if ( IIIi1iI1 . priority == 254 and lisp_i_am_rtr == False ) :
     iii1 . append ( IIIi1iI1 )
     o0o00 . append ( IIIi1iI1 . rloc . print_address_no_iid ( ) )
     if 39 - 39: Ii1I
    if ( IIIi1iI1 . priority != 254 and lisp_i_am_rtr ) :
     iii1 . append ( IIIi1iI1 )
     o0o00 . append ( IIIi1iI1 . rloc . print_address_no_iid ( ) )
     if 90 - 90: I1Ii111 - I1Ii111 . i11iIiiIii + OoooooooOO % OOooOOo / Oo0Ooo
     if 51 - 51: o0oOOo0O0Ooo
     if 8 - 8: oO0o . oO0o . Ii1I
   if ( o0o00 != [ ] ) :
    oOO000OOO = iii1
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( o0o00 ) )
    if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
    if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
    if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
    if 10 - 10: ooOoO0o
    if 69 - 69: I11i + I1IiiI / oO0o
    if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
    if 85 - 85: I1Ii111 - oO0o
  iii1 = [ ]
  for IIIi1iI1 in oOO000OOO :
   if ( IIIi1iI1 . json != None ) : continue
   iii1 . append ( IIIi1iI1 )
   if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
  if ( iii1 != [ ] ) :
   ooOoOoO0 = len ( oOO000OOO ) - len ( iii1 )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( ooOoOoO0 ) )
   if 96 - 96: oO0o
   oOO000OOO = iii1
   if 44 - 44: OoooooooOO / iII111i * Oo0Ooo % OoOoOO00 . oO0o
   if 97 - 97: iIii1I11I1II1 / ooOoO0o
   if 16 - 16: Oo0Ooo % IiII
   if 48 - 48: I1IiiI . I1Ii111 . o0oOOo0O0Ooo
   if 72 - 72: Ii1I * OoO0O00 / OoO0O00
   if 39 - 39: oO0o
   if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
   if 57 - 57: oO0o + O0 - OoOoOO00
  if ( iIO0OOoOOO0OO . rloc_probe and ooOoOO0Oo != None ) : oOO000OOO = ooOoOO0Oo . rloc_set
  if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
  if 93 - 93: o0oOOo0O0Ooo + i1IIi
  if 24 - 24: i1IIi
  if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
  if 99 - 99: Oo0Ooo
  iIiI111I = ooo0IIi1I11
  if ( ooOoOO0Oo and oOO000OOO != ooOoOO0Oo . rloc_set ) :
   ooOoOO0Oo . delete_rlocs_from_rloc_probe_list ( )
   iIiI111I = True
   if 42 - 42: i11iIiiIii - O0 + O0
   if 83 - 83: Oo0Ooo / I1ii11iIi11i % OoO0O00
   if 29 - 29: IiII - I1ii11iIi11i . Oo0Ooo + IiII - I1IiiI
   if 95 - 95: O0 / o0oOOo0O0Ooo + OoO0O00 / IiII - IiII % OOooOOo
   if 16 - 16: I1IiiI * iIii1I11I1II1 % o0oOOo0O0Ooo - IiII - OOooOOo
  ooo0O0O0oOO = ooOoOO0Oo . uptime if ( ooOoOO0Oo ) else None
  if ( ooOoOO0Oo == None ) :
   ooOoOO0Oo = lisp_mapping ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group , oOO000OOO )
   ooOoOO0Oo . mapping_source = source
   if 68 - 68: IiII * O0 % OOooOOo
   if 26 - 26: ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
   if 26 - 26: I1IiiI - OOooOOo
   if 34 - 34: I1Ii111 % I1IiiI . OoOoOO00 / iII111i + ooOoO0o . i11iIiiIii
   if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
   if 50 - 50: OoooooooOO * II111iiii
   if ( lisp_i_am_rtr and oOO0O0o0oOooO . group . is_null ( ) == False ) :
    ooOoOO0Oo . map_cache_ttl = LISP_MCAST_TTL
   else :
    ooOoOO0Oo . map_cache_ttl = oOO0O0o0oOooO . store_ttl ( )
    if 7 - 7: ooOoO0o / I11i * iII111i
   ooOoOO0Oo . action = oOO0O0o0oOooO . action
   ooOoOO0Oo . add_cache ( iIiI111I )
   if 17 - 17: O0 % I1Ii111
   if 28 - 28: i1IIi * ooOoO0o
  IiIii1i = "Add"
  if ( ooo0O0O0oOO ) :
   ooOoOO0Oo . uptime = ooo0O0O0oOO
   ooOoOO0Oo . refresh_time = lisp_get_timestamp ( )
   IiIii1i = "Replace"
   if 71 - 71: OoO0O00 + OoOoOO00 * oO0o
   if 29 - 29: IiII / OoOoOO00 + oO0o / II111iiii + oO0o
  lprint ( "{} {} map-cache with {} RLOCs" . format ( IiIii1i ,
 green ( ooOoOO0Oo . print_eid_tuple ( ) , False ) , len ( oOO000OOO ) ) )
  if 16 - 16: o0oOOo0O0Ooo % II111iiii - i11iIiiIii - IiII + O0 - i11iIiiIii
  if 58 - 58: OoooooooOO / I1ii11iIi11i - Oo0Ooo / II111iiii
  if 13 - 13: o0oOOo0O0Ooo + OoOoOO00 * ooOoO0o % IiII
  if 18 - 18: I1IiiI . I1ii11iIi11i + Oo0Ooo - iII111i
  if 53 - 53: ooOoO0o / IiII
  if ( lisp_ipc_dp_socket and o0000o0OO00OO != None ) :
   lisp_write_ipc_keys ( o0000o0OO00OO )
   if 36 - 36: iIii1I11I1II1
   if 78 - 78: II111iiii * I11i
   if 47 - 47: Ii1I
   if 42 - 42: I11i . oO0o - I1IiiI / OoO0O00
   if 75 - 75: I1IiiI / OoOoOO00 . I11i * iIii1I11I1II1
   if 53 - 53: iIii1I11I1II1
   if 8 - 8: O0 - O0 - II111iiii
  if ( ooo0IIi1I11 ) :
   OoO0oo0O = bold ( "RLOC-probe" , False )
   for IIIi1iI1 in ooOoOO0Oo . best_rloc_set :
    O0O0 = red ( IIIi1iI1 . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( OoO0oo0O , O0O0 ) )
    lisp_send_map_request ( lisp_sockets , 0 , ooOoOO0Oo . eid , ooOoOO0Oo . group , IIIi1iI1 )
    if 63 - 63: oO0o % Oo0Ooo * OoO0O00 / II111iiii / Ii1I - ooOoO0o
    if 14 - 14: ooOoO0o . o0oOOo0O0Ooo + II111iiii
    if 50 - 50: Ii1I - i1IIi * oO0o
 return
 if 52 - 52: I11i / oO0o - oO0o
 if 84 - 84: iIii1I11I1II1 - o0oOOo0O0Ooo
 if 37 - 37: iII111i * o0oOOo0O0Ooo
 if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
 if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
 if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
 if 34 - 34: O0 * oO0o
 if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
 packet = map_register . zero_auth ( packet )
 iIIi111I1i1i = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
 if 88 - 88: i11iIiiIii
 if 13 - 13: I1IiiI
 if 52 - 52: Ii1I * oO0o / I1Ii111 . IiII
 map_register . auth_data = iIIi111I1i1i
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 84 - 84: OoooooooOO - oO0o - I1Ii111
 if 69 - 69: OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
 if 20 - 20: IiII
 if 17 - 17: o0oOOo0O0Ooo % iIii1I11I1II1
 if 66 - 66: OoooooooOO + IiII . II111iiii
 if 66 - 66: iIii1I11I1II1 % I11i
 if 38 - 38: I1ii11iIi11i * ooOoO0o
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 77 - 77: OOooOOo - i11iIiiIii - I1ii11iIi11i
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  OOO0O0OOoOo = hashlib . sha1
  if 68 - 68: O0 . Ii1I * O0 * OoOoOO00 - OoOoOO00 * I1ii11iIi11i
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  OOO0O0OOoOo = hashlib . sha256
  if 28 - 28: OoO0O00 + oO0o * I11i % Ii1I % ooOoO0o
  if 72 - 72: II111iiii
 if ( do_hex ) :
  iIIi111I1i1i = hmac . new ( password , packet , OOO0O0OOoOo ) . hexdigest ( )
 else :
  iIIi111I1i1i = hmac . new ( password , packet , OOO0O0OOoOo ) . digest ( )
  if 28 - 28: O0
 return ( iIIi111I1i1i )
 if 99 - 99: OoOoOO00 + OoOoOO00 % OoO0O00
 if 65 - 65: Oo0Ooo * OoooooooOO + oO0o . I1IiiI + Ii1I
 if 34 - 34: i11iIiiIii / I11i % i1IIi
 if 6 - 6: OoO0O00 * iIii1I11I1II1 % oO0o % iII111i * iII111i
 if 96 - 96: IiII * iII111i / i11iIiiIii
 if 21 - 21: o0oOOo0O0Ooo / OoOoOO00 . oO0o - iIii1I11I1II1 % I1Ii111 / iII111i
 if 38 - 38: iIii1I11I1II1 . OoO0O00 * iIii1I11I1II1
 if 61 - 61: OoOoOO00 * I1IiiI
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 6 - 6: OoOoOO00
 iIIi111I1i1i = lisp_hash_me ( packet , alg_id , password , True )
 OOOoO0Oo0O = ( iIIi111I1i1i == auth_data )
 if 5 - 5: iII111i - iIii1I11I1II1 * IiII
 if 52 - 52: OOooOOo
 if 50 - 50: OoOoOO00 % o0oOOo0O0Ooo - II111iiii - i1IIi
 if 35 - 35: Oo0Ooo - ooOoO0o % OoO0O00
 if ( OOOoO0Oo0O == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( iIIi111I1i1i , auth_data ) )
  if 26 - 26: i1IIi * I1Ii111 * OoO0O00 - IiII
  if 26 - 26: Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
 return ( OOOoO0Oo0O )
 if 66 - 66: I1IiiI
 if 45 - 45: II111iiii * I1Ii111 - II111iiii / I1IiiI % oO0o
 if 83 - 83: oO0o % OoO0O00 + I1ii11iIi11i / OoooooooOO % iII111i
 if 22 - 22: I1Ii111
 if 41 - 41: O0 * i1IIi
 if 89 - 89: iIii1I11I1II1 . I11i % I1ii11iIi11i + II111iiii . OoO0O00
 if 5 - 5: I1ii11iIi11i / I1IiiI . iII111i
def lisp_retransmit_map_notify ( map_notify ) :
 OO0oooOO = map_notify . etr
 IiO0o = map_notify . etr_port
 if 7 - 7: Ii1I
 if 62 - 62: I1ii11iIi11i + IiII . O0 - OoooooooOO * o0oOOo0O0Ooo % O0
 if 63 - 63: OOooOOo + iII111i - IiII - I1IiiI % IiII . OoO0O00
 if 73 - 73: OoOoOO00
 if 47 - 47: oO0o
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( OO0oooOO . print_address ( ) , False ) ) )
  if 17 - 17: IiII
  if 47 - 47: I11i . I1IiiI % ooOoO0o . i11iIiiIii
  OO0Oo00o0o0 = map_notify . nonce_key
  if ( lisp_map_notify_queue . has_key ( OO0Oo00o0o0 ) ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( OO0Oo00o0o0 ) )
   if 63 - 63: I1ii11iIi11i % I11i % OoooooooOO
   try :
    lisp_map_notify_queue . pop ( OO0Oo00o0o0 )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 100 - 100: O0
    if 9 - 9: Ii1I
  return
  if 87 - 87: I1IiiI
  if 56 - 56: OOooOOo % oO0o - OoOoOO00
 i1i1iI1Iiii = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 27 - 27: I1ii11iIi11i - IiII * OoooooooOO * I1ii11iIi11i + i11iIiiIii . IiII
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # II111iiii / iIii1I11I1II1 - I1Ii111 . Ii1I + O0
 red ( OO0oooOO . print_address ( ) , False ) , map_notify . retry_count ) )
 if 33 - 33: OoO0O00 % OoooooooOO
 lisp_send_map_notify ( i1i1iI1Iiii , map_notify . packet , OO0oooOO , IiO0o )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 62 - 62: II111iiii % II111iiii % O0 % i11iIiiIii - iIii1I11I1II1
 if 65 - 65: II111iiii + ooOoO0o . IiII
 if 11 - 11: Oo0Ooo % ooOoO0o + I1Ii111 . OoOoOO00
 if 2 - 2: i1IIi - IiII + iIii1I11I1II1 % i1IIi * II111iiii
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 26 - 26: I11i
 if 57 - 57: I1ii11iIi11i + I1Ii111 + i11iIiiIii . i1IIi / i11iIiiIii
 if 43 - 43: Ii1I % I11i
 if 5 - 5: OoooooooOO % i11iIiiIii * o0oOOo0O0Ooo * OoooooooOO - o0oOOo0O0Ooo % I11i
 if 58 - 58: i11iIiiIii % Ii1I + Oo0Ooo - OoOoOO00 - i11iIiiIii / O0
 if 36 - 36: OOooOOo
 if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 95 - 95: i1IIi * O0 / II111iiii * OoOoOO00 * I1IiiI
 if 38 - 38: OOooOOo - OoOoOO00 / OoO0O00 / o0oOOo0O0Ooo - i11iIiiIii
 if 4 - 4: I1IiiI * o0oOOo0O0Ooo - I11i - OoooooooOO . OoooooooOO
 if 79 - 79: oO0o - iII111i
 eid_record . rloc_count = len ( parent . registered_rlocs )
 IiI1I1 = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 34 - 34: I1IiiI
 if 39 - 39: o0oOOo0O0Ooo . i1IIi * OoO0O00 / II111iiii / I1ii11iIi11i * OOooOOo
 if 39 - 39: O0 . OOooOOo
 if 95 - 95: I11i
 for OOOoI1Ii in parent . registered_rlocs :
  iIIi = lisp_rloc_record ( )
  iIIi . store_rloc_entry ( OOOoI1Ii )
  iIIi . local_bit = OOOoI1Ii . local_bit
  iIIi . probe_bit = OOOoI1Ii . probe_bit
  iIIi . reach_bit = OOOoI1Ii . reach_bit
  IiI1I1 += iIIi . encode ( )
  iIIi . print_record ( "  " )
  del ( iIIi )
  if 15 - 15: Oo0Ooo * OoooooooOO / I11i - Ii1I
  if 11 - 11: OoO0O00
  if 20 - 20: Oo0Ooo
  if 34 - 34: I1Ii111 % i11iIiiIii / oO0o - i1IIi . o0oOOo0O0Ooo / oO0o
  if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
 for OOOoI1Ii in parent . registered_rlocs :
  OO0oooOO = OOOoI1Ii . rloc
  ii11i1IiI = lisp_map_notify ( lisp_sockets )
  ii11i1IiI . record_count = 1
  I1IIiiiiI1iIi = map_register . key_id
  ii11i1IiI . key_id = I1IIiiiiI1iIi
  ii11i1IiI . alg_id = map_register . alg_id
  ii11i1IiI . auth_len = map_register . auth_len
  ii11i1IiI . nonce = map_register . nonce
  ii11i1IiI . nonce_key = lisp_hex_string ( ii11i1IiI . nonce )
  ii11i1IiI . etr . copy_address ( OO0oooOO )
  ii11i1IiI . etr_port = map_register . sport
  ii11i1IiI . site = parent . site
  o0o0ooOOo0oO = ii11i1IiI . encode ( IiI1I1 , parent . site . auth_key [ I1IIiiiiI1iIi ] )
  ii11i1IiI . print_notify ( )
  if 99 - 99: Ii1I / iII111i / Ii1I + iII111i
  if 18 - 18: OoOoOO00 % OoO0O00 + Ii1I * I1Ii111 / O0 % I1Ii111
  if 6 - 6: II111iiii - i1IIi
  if 78 - 78: OoOoOO00 - Oo0Ooo * II111iiii % iIii1I11I1II1 . i11iIiiIii % iII111i
  OO0Oo00o0o0 = ii11i1IiI . nonce_key
  if ( lisp_map_notify_queue . has_key ( OO0Oo00o0o0 ) ) :
   oO00oo0 = lisp_map_notify_queue [ OO0Oo00o0o0 ]
   oO00oo0 . retransmit_timer . cancel ( )
   del ( oO00oo0 )
   if 36 - 36: i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
  lisp_map_notify_queue [ OO0Oo00o0o0 ] = ii11i1IiI
  if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
  if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
  if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
  if 8 - 8: OoooooooOO * OOooOOo * iII111i - iII111i
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( OO0oooOO . print_address ( ) , False ) ) )
  if 32 - 32: I1Ii111
  lisp_send ( lisp_sockets , OO0oooOO , LISP_CTRL_PORT , o0o0ooOOo0oO )
  if 28 - 28: I11i . i11iIiiIii % iIii1I11I1II1 + OoOoOO00
  parent . site . map_notifies_sent += 1
  if 4 - 4: OOooOOo + I1ii11iIi11i - iII111i + OOooOOo / IiII
  if 23 - 23: iIii1I11I1II1 + OoooooooOO + ooOoO0o . iII111i . Oo0Ooo - iIii1I11I1II1
  if 25 - 25: O0 + I1IiiI % OOooOOo / Oo0Ooo . IiII / I1Ii111
  if 84 - 84: ooOoO0o . O0 + I1IiiI * OoO0O00 - I1IiiI
  ii11i1IiI . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ ii11i1IiI ] )
  ii11i1IiI . retransmit_timer . start ( )
  if 24 - 24: Ii1I
 return
 if 23 - 23: Oo0Ooo * i1IIi / I1IiiI . I11i - I1ii11iIi11i . iIii1I11I1II1
 if 15 - 15: O0 + o0oOOo0O0Ooo / oO0o
 if 27 - 27: Ii1I * II111iiii / oO0o
 if 99 - 99: I11i + ooOoO0o % I11i + O0 - Ii1I - I1Ii111
 if 3 - 3: Oo0Ooo . I1IiiI
 if 61 - 61: OoO0O00 - I1ii11iIi11i . Ii1I * i11iIiiIii
 if 97 - 97: ooOoO0o
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 58 - 58: iII111i
 OO0Oo00o0o0 = lisp_hex_string ( nonce ) + source . print_address ( )
 if 47 - 47: II111iiii % Oo0Ooo . iIii1I11I1II1 . oO0o
 if 52 - 52: I11i * I1IiiI % I11i - iII111i - Ii1I - OoooooooOO
 if 15 - 15: iII111i
 if 95 - 95: i11iIiiIii . Ii1I / II111iiii + II111iiii + Ii1I / I11i
 if 72 - 72: I1Ii111 . I1Ii111 * O0 + I1ii11iIi11i / Oo0Ooo
 if 96 - 96: oO0o . ooOoO0o * Oo0Ooo % ooOoO0o + I1Ii111 + iIii1I11I1II1
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( lisp_map_notify_queue . has_key ( OO0Oo00o0o0 ) ) :
  ii11i1IiI = lisp_map_notify_queue [ OO0Oo00o0o0 ]
  I1iiIi111I = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( ii11i1IiI . nonce ) , I1iiIi111I ) )
  if 45 - 45: II111iiii
  return
  if 42 - 42: ooOoO0o
  if 62 - 62: II111iiii * o0oOOo0O0Ooo . OoO0O00 / II111iiii
 ii11i1IiI = lisp_map_notify ( lisp_sockets )
 ii11i1IiI . record_count = record_count
 key_id = key_id
 ii11i1IiI . key_id = key_id
 ii11i1IiI . alg_id = alg_id
 ii11i1IiI . auth_len = auth_len
 ii11i1IiI . nonce = nonce
 ii11i1IiI . nonce_key = lisp_hex_string ( nonce )
 ii11i1IiI . etr . copy_address ( source )
 ii11i1IiI . etr_port = port
 ii11i1IiI . site = site
 ii11i1IiI . eid_list = eid_list
 if 5 - 5: OoO0O00 + O0 . OoooooooOO + I1IiiI + i1IIi * OOooOOo
 if 19 - 19: OoooooooOO + i11iIiiIii / II111iiii - Oo0Ooo . OOooOOo
 if 10 - 10: oO0o * Oo0Ooo
 if 55 - 55: OoO0O00 - i1IIi - I11i * oO0o
 if ( map_register_ack == False ) :
  OO0Oo00o0o0 = ii11i1IiI . nonce_key
  lisp_map_notify_queue [ OO0Oo00o0o0 ] = ii11i1IiI
  if 91 - 91: I1Ii111
  if 77 - 77: I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + Ii1I % II111iiii * II111iiii
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 41 - 41: II111iiii + Oo0Ooo - IiII / I1Ii111 - OOooOOo . oO0o
  if 100 - 100: ooOoO0o / I1ii11iIi11i * OoOoOO00 . I1ii11iIi11i . o0oOOo0O0Ooo * iIii1I11I1II1
  if 15 - 15: iII111i + o0oOOo0O0Ooo / IiII
  if 33 - 33: OoooooooOO . IiII * o0oOOo0O0Ooo
  if 41 - 41: Ii1I . iII111i . o0oOOo0O0Ooo % OoooooooOO % IiII
 o0o0ooOOo0oO = ii11i1IiI . encode ( eid_records , site . auth_key [ key_id ] )
 ii11i1IiI . print_notify ( )
 if 81 - 81: IiII * i11iIiiIii + i1IIi + OOooOOo . i1IIi
 if ( map_register_ack == False ) :
  oOO0O0o0oOooO = lisp_eid_record ( )
  oOO0O0o0oOooO . decode ( eid_records )
  oOO0O0o0oOooO . print_record ( "  " , False )
  if 6 - 6: i11iIiiIii - oO0o % OoO0O00 + iIii1I11I1II1
  if 69 - 69: IiII
  if 13 - 13: i11iIiiIii
  if 49 - 49: OoOoOO00
  if 61 - 61: I1Ii111 / I1Ii111 / iII111i / ooOoO0o - I1IiiI . o0oOOo0O0Ooo
 lisp_send_map_notify ( lisp_sockets , o0o0ooOOo0oO , ii11i1IiI . etr , port )
 site . map_notifies_sent += 1
 if 80 - 80: I1IiiI - OOooOOo . oO0o
 if ( map_register_ack ) : return
 if 75 - 75: oO0o + OoOoOO00 - OoooooooOO
 if 38 - 38: I11i / ooOoO0o / OoOoOO00 * OOooOOo . oO0o
 if 8 - 8: OoO0O00 . OOooOOo % I1Ii111 * OOooOOo / I1IiiI
 if 3 - 3: IiII - I1ii11iIi11i . o0oOOo0O0Ooo
 if 39 - 39: oO0o . I1Ii111 + oO0o % OoOoOO00 - i11iIiiIii
 if 69 - 69: I11i / OoO0O00
 ii11i1IiI . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ ii11i1IiI ] )
 ii11i1IiI . retransmit_timer . start ( )
 return
 if 73 - 73: i11iIiiIii / i1IIi
 if 8 - 8: O0 / OOooOOo + iII111i % iIii1I11I1II1 % iIii1I11I1II1 . ooOoO0o
 if 47 - 47: OoO0O00 / o0oOOo0O0Ooo / Ii1I * I1IiiI % ooOoO0o / I1Ii111
 if 80 - 80: I1Ii111 / O0 * O0
 if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
 if 89 - 89: i11iIiiIii - II111iiii
 if 67 - 67: IiII % I1Ii111 + i11iIiiIii
 if 53 - 53: OOooOOo
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
 if 21 - 21: I1Ii111 . i1IIi - iII111i % I1ii11iIi11i . OOooOOo
 if 52 - 52: Ii1I * I1ii11iIi11i
 if 21 - 21: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo * II111iiii % iIii1I11I1II1
 o0o0ooOOo0oO = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 9 - 9: I1ii11iIi11i + I11i
 if 20 - 20: iII111i + i1IIi / oO0o % OoooooooOO * OoOoOO00
 if 70 - 70: Oo0Ooo - OOooOOo * OOooOOo / o0oOOo0O0Ooo
 if 4 - 4: OoOoOO00 / OoO0O00
 OO0oooOO = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( OO0oooOO . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , OO0oooOO , LISP_CTRL_PORT , o0o0ooOOo0oO )
 return
 if 66 - 66: I1Ii111 / OoOoOO00
 if 53 - 53: OoOoOO00 . i11iIiiIii - OoooooooOO
 if 92 - 92: O0 - i11iIiiIii + OoO0O00 - OoooooooOO - o0oOOo0O0Ooo
 if 25 - 25: oO0o / oO0o / Ii1I / O0
 if 56 - 56: ooOoO0o
 if 19 - 19: O0 * I1IiiI + I1ii11iIi11i
 if 25 - 25: I11i - ooOoO0o / OoO0O00 / iII111i - OoO0O00
 if 86 - 86: OoO0O00
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 89 - 89: OoooooooOO % iII111i * I1ii11iIi11i + I1ii11iIi11i . Oo0Ooo
 ii11i1IiI = lisp_map_notify ( lisp_sockets )
 ii11i1IiI . record_count = 1
 ii11i1IiI . nonce = lisp_get_control_nonce ( )
 ii11i1IiI . nonce_key = lisp_hex_string ( ii11i1IiI . nonce )
 ii11i1IiI . etr . copy_address ( xtr )
 ii11i1IiI . etr_port = LISP_CTRL_PORT
 ii11i1IiI . eid_list = eid_list
 OO0Oo00o0o0 = ii11i1IiI . nonce_key
 if 4 - 4: I11i
 if 8 - 8: IiII
 if 1 - 1: ooOoO0o . IiII
 if 4 - 4: iIii1I11I1II1 % I1IiiI - OoooooooOO / iII111i
 if 55 - 55: O0 + iII111i * OoOoOO00 . i11iIiiIii * Ii1I + oO0o
 if 66 - 66: i1IIi . I1ii11iIi11i
 lisp_remove_eid_from_map_notify_queue ( ii11i1IiI . eid_list )
 if ( lisp_map_notify_queue . has_key ( OO0Oo00o0o0 ) ) :
  ii11i1IiI = lisp_map_notify_queue [ OO0Oo00o0o0 ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( ii11i1IiI . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 86 - 86: Oo0Ooo
  return
  if 48 - 48: OoO0O00
  if 55 - 55: OoO0O00 * i1IIi * I11i / iII111i
  if 42 - 42: IiII
  if 28 - 28: OoOoOO00 + OoOoOO00
  if 53 - 53: II111iiii % i1IIi + ooOoO0o . I1Ii111
 lisp_map_notify_queue [ OO0Oo00o0o0 ] = ii11i1IiI
 if 52 - 52: I1IiiI + I1Ii111 * oO0o / i11iIiiIii * iIii1I11I1II1
 if 27 - 27: Oo0Ooo
 if 85 - 85: iIii1I11I1II1 . o0oOOo0O0Ooo + oO0o
 if 79 - 79: O0 - iIii1I11I1II1 + i1IIi . I11i
 ii111 = site_eid . rtrs_in_rloc_set ( )
 if ( ii111 ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : ii111 = False
  if 4 - 4: oO0o / OoO0O00
  if 90 - 90: I11i . IiII / OoO0O00 . IiII
  if 62 - 62: i11iIiiIii * I11i + oO0o - i1IIi
  if 9 - 9: I1IiiI
  if 17 - 17: II111iiii + i11iIiiIii + IiII
 oOO0O0o0oOooO = lisp_eid_record ( )
 oOO0O0o0oOooO . record_ttl = 1440
 oOO0O0o0oOooO . eid . copy_address ( site_eid . eid )
 oOO0O0o0oOooO . group . copy_address ( site_eid . group )
 oOO0O0o0oOooO . rloc_count = 0
 for O0O0OOo0O in site_eid . registered_rlocs :
  if ( ii111 ^ O0O0OOo0O . is_rtr ( ) ) : continue
  oOO0O0o0oOooO . rloc_count += 1
  if 41 - 41: OoOoOO00 + i1IIi - iIii1I11I1II1
 o0o0ooOOo0oO = oOO0O0o0oOooO . encode ( )
 if 8 - 8: I1Ii111
 if 50 - 50: I1IiiI . IiII . OoOoOO00 * oO0o - ooOoO0o
 if 29 - 29: OoO0O00
 if 78 - 78: iII111i * ooOoO0o + O0 % ooOoO0o + OoO0O00
 ii11i1IiI . print_notify ( )
 oOO0O0o0oOooO . print_record ( "  " , False )
 if 41 - 41: II111iiii . oO0o + O0 % i1IIi . Ii1I
 if 90 - 90: ooOoO0o * I1IiiI / II111iiii % Oo0Ooo % OoooooooOO
 if 78 - 78: OoooooooOO . IiII
 if 55 - 55: I11i / I1ii11iIi11i * O0 + IiII % I11i
 for O0O0OOo0O in site_eid . registered_rlocs :
  if ( ii111 ^ O0O0OOo0O . is_rtr ( ) ) : continue
  iIIi = lisp_rloc_record ( )
  iIIi . store_rloc_entry ( O0O0OOo0O )
  iIIi . local_bit = O0O0OOo0O . local_bit
  iIIi . probe_bit = O0O0OOo0O . probe_bit
  iIIi . reach_bit = O0O0OOo0O . reach_bit
  o0o0ooOOo0oO += iIIi . encode ( )
  iIIi . print_record ( "    " )
  if 69 - 69: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO - ooOoO0o
  if 94 - 94: iIii1I11I1II1 / Oo0Ooo % IiII * IiII
  if 62 - 62: I11i . IiII - OOooOOo - I1Ii111 / OoooooooOO . Ii1I
  if 28 - 28: iII111i / I1ii11iIi11i - OoOoOO00 * Oo0Ooo + Ii1I * OoOoOO00
  if 94 - 94: oO0o
 o0o0ooOOo0oO = ii11i1IiI . encode ( o0o0ooOOo0oO , "" )
 if ( o0o0ooOOo0oO == None ) : return
 if 95 - 95: ooOoO0o * O0 + OOooOOo
 if 11 - 11: i1IIi / OoOoOO00 + OoOoOO00 + I1ii11iIi11i + OOooOOo
 if 21 - 21: ooOoO0o
 if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
 lisp_send_map_notify ( lisp_sockets , o0o0ooOOo0oO , xtr , LISP_CTRL_PORT )
 if 81 - 81: oO0o
 if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
 if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
 if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
 ii11i1IiI . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ ii11i1IiI ] )
 ii11i1IiI . retransmit_timer . start ( )
 return
 if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
 if 33 - 33: I11i
 if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
 if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
 if 32 - 32: oO0o
 if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 O0O0I11I1111i11i = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 41 - 41: I11i % OoO0O00 * OoO0O00
 for I1IIiIiIIiIiI in rle_list :
  iiIi1i1i = lisp_site_eid_lookup ( I1IIiIiIIiIiI [ 0 ] , I1IIiIiIIiIiI [ 1 ] , True )
  if ( iiIi1i1i == None ) : continue
  if 69 - 69: i11iIiiIii + Oo0Ooo / II111iiii % OoOoOO00
  if 4 - 4: II111iiii + ooOoO0o
  if 25 - 25: I1IiiI - iIii1I11I1II1
  if 11 - 11: I1Ii111 / iII111i - I11i
  if 87 - 87: I1Ii111 * i11iIiiIii . OOooOOo . OoooooooOO
  if 2 - 2: i11iIiiIii + oO0o
  if 40 - 40: i11iIiiIii + oO0o * IiII
  I1ii1 = iiIi1i1i . registered_rlocs
  if ( len ( I1ii1 ) == 0 ) :
   O00oO = { }
   for IiI11I11i in iiIi1i1i . individual_registrations . values ( ) :
    for O0O0OOo0O in IiI11I11i . registered_rlocs :
     if ( O0O0OOo0O . is_rtr ( ) == False ) : continue
     O00oO [ O0O0OOo0O . rloc . print_address ( ) ] = O0O0OOo0O
     if 83 - 83: I1IiiI * O0 . II111iiii
     if 80 - 80: O0 * I11i * I1Ii111
   I1ii1 = O00oO . values ( )
   if 89 - 89: Ii1I * OoO0O00 . i1IIi . O0 - IiII - OoOoOO00
   if 25 - 25: iII111i + i1IIi
   if 64 - 64: IiII % I11i / iIii1I11I1II1
   if 66 - 66: Ii1I
   if 55 - 55: OOooOOo + I1IiiI + IiII . Ii1I * oO0o
   if 71 - 71: IiII - iII111i % I1IiiI * iII111i
  i1I1I11II = [ ]
  o00o000o00O = False
  if ( iiIi1i1i . eid . address == 0 and iiIi1i1i . eid . mask_len == 0 ) :
   iiI11ii11ii1 = [ ]
   iIIiI1IIi = [ ]
   if ( len ( I1ii1 ) != 0 and I1ii1 [ 0 ] . rle != None ) :
    iIIiI1IIi = I1ii1 [ 0 ] . rle . rle_nodes
    if 44 - 44: i1IIi % I1IiiI
   for o0Ii11I in iIIiI1IIi :
    i1I1I11II . append ( o0Ii11I . address )
    iiI11ii11ii1 . append ( o0Ii11I . address . print_address_no_iid ( ) )
    if 28 - 28: I1ii11iIi11i * II111iiii
   lprint ( "Notify existing RLE-nodes {}" . format ( iiI11ii11ii1 ) )
  else :
   if 90 - 90: OOooOOo - i11iIiiIii / OoooooooOO - Ii1I * iIii1I11I1II1
   if 36 - 36: I1ii11iIi11i * IiII / OoooooooOO + i11iIiiIii . oO0o % Ii1I
   if 21 - 21: IiII - iIii1I11I1II1
   if 90 - 90: Oo0Ooo % I1Ii111 + iII111i * I1IiiI * OoOoOO00
   if 39 - 39: o0oOOo0O0Ooo * ooOoO0o / i1IIi
   for O0O0OOo0O in I1ii1 :
    if ( O0O0OOo0O . is_rtr ( ) ) : i1I1I11II . append ( O0O0OOo0O . rloc )
    if 25 - 25: O0 / Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo
    if 45 - 45: Ii1I * IiII - OOooOOo
    if 57 - 57: iII111i % OoO0O00 / OoooooooOO
    if 69 - 69: oO0o
    if 44 - 44: IiII - II111iiii % Ii1I
   o00o000o00O = ( len ( i1I1I11II ) != 0 )
   if ( o00o000o00O == False ) :
    iiI1I = lisp_site_eid_lookup ( I1IIiIiIIiIiI [ 0 ] , O0O0I11I1111i11i , False )
    if ( iiI1I == None ) : continue
    if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
    for O0O0OOo0O in iiI1I . registered_rlocs :
     if ( O0O0OOo0O . rloc . is_null ( ) ) : continue
     i1I1I11II . append ( O0O0OOo0O . rloc )
     if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
     if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
     if 59 - 59: OoOoOO00
     if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
     if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
     if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
   if ( len ( i1I1I11II ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( iiIi1i1i . print_eid_tuple ( ) , False ) ) )
    if 62 - 62: Oo0Ooo . II111iiii % OoO0O00 . Ii1I * OOooOOo + II111iiii
    continue
    if 7 - 7: OOooOOo
    if 22 - 22: Oo0Ooo + ooOoO0o
    if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
    if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
    if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
    if 26 - 26: Oo0Ooo . Ii1I
  for OOOoI1Ii in i1I1I11II :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if o00o000o00O else "x" , red ( OOOoI1Ii . print_address_no_iid ( ) , False ) ,
   # OoOoOO00
 green ( iiIi1i1i . print_eid_tuple ( ) , False ) ) )
   if 65 - 65: o0oOOo0O0Ooo + O0 - iIii1I11I1II1
   iII = [ iiIi1i1i . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , iiIi1i1i , iII , OOOoI1Ii )
   time . sleep ( .001 )
   if 26 - 26: o0oOOo0O0Ooo * iIii1I11I1II1 . O0 . I1IiiI
   if 40 - 40: OoO0O00 * oO0o / OoOoOO00
 return
 if 37 - 37: iII111i * oO0o / I1IiiI * I1ii11iIi11i
 if 73 - 73: oO0o + O0
 if 98 - 98: I11i % oO0o - I1Ii111 % o0oOOo0O0Ooo - IiII
 if 32 - 32: i11iIiiIii . I1IiiI
 if 22 - 22: II111iiii / iII111i
 if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
 if 62 - 62: O0 % o0oOOo0O0Ooo + iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
 if 21 - 21: o0oOOo0O0Ooo % O0
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for OoOOoO0oOo in range ( rloc_count ) :
  iIIi = lisp_rloc_record ( )
  packet = iIIi . decode ( packet , None )
  oooo0o = iIIi . json
  if ( oooo0o == None ) : continue
  if 95 - 95: ooOoO0o - ooOoO0o % IiII . OoO0O00 - iIii1I11I1II1 % Ii1I
  try :
   oooo0o = json . loads ( oooo0o . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 51 - 51: i1IIi % Oo0Ooo
   if 32 - 32: OoOoOO00 + iIii1I11I1II1 . OoO0O00 . I1ii11iIi11i . IiII
  if ( oooo0o . has_key ( "signature" ) == False ) : continue
  return ( iIIi )
  if 97 - 97: ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + iII111i + OoOoOO00
 return ( None )
 if 8 - 8: Oo0Ooo . oO0o + II111iiii
 if 100 - 100: OoOoOO00 . IiII / OoO0O00 * OoooooooOO - OoOoOO00
 if 98 - 98: OoO0O00 / I1ii11iIi11i + I1ii11iIi11i
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
 if 53 - 53: Ii1I - II111iiii * iIii1I11I1II1
 if 91 - 91: OoOoOO00 % iIii1I11I1II1
 if 81 - 81: i11iIiiIii / OoOoOO00 + iIii1I11I1II1
 if 65 - 65: o0oOOo0O0Ooo
 if 73 - 73: I11i . I1ii11iIi11i - OoO0O00 + OoooooooOO
def lisp_get_eid_hash ( eid ) :
 oo0OO = None
 for ooOo000OOooo in lisp_eid_hashes :
  if 45 - 45: I1Ii111 / I1IiiI + Ii1I / iII111i / Ii1I + I1Ii111
  if 12 - 12: Oo0Ooo . i1IIi + iIii1I11I1II1 % I1ii11iIi11i
  if 33 - 33: oO0o . oO0o / IiII + II111iiii
  if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
  i1 = ooOo000OOooo . instance_id
  if ( i1 == - 1 ) : ooOo000OOooo . instance_id = eid . instance_id
  if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
  I1Ii11IIiiI = eid . is_more_specific ( ooOo000OOooo )
  ooOo000OOooo . instance_id = i1
  if ( I1Ii11IIiiI ) :
   oo0OO = 128 - ooOo000OOooo . mask_len
   break
   if 25 - 25: OoO0O00
   if 83 - 83: II111iiii . iIii1I11I1II1
 if ( oo0OO == None ) : return ( None )
 if 77 - 77: O0 . OoOoOO00 % oO0o / OOooOOo
 iIIiiiI = eid . address
 i1i1Ii11 = ""
 for OoOOoO0oOo in range ( 0 , oo0OO / 16 ) :
  IiIIiiI = iIIiiiI & 0xffff
  IiIIiiI = hex ( IiIIiiI ) [ 2 : - 1 ]
  i1i1Ii11 = IiIIiiI . zfill ( 4 ) + ":" + i1i1Ii11
  iIIiiiI >>= 16
  if 68 - 68: OoOoOO00
 if ( oo0OO % 16 != 0 ) :
  IiIIiiI = iIIiiiI & 0xff
  IiIIiiI = hex ( IiIIiiI ) [ 2 : - 1 ]
  i1i1Ii11 = IiIIiiI . zfill ( 2 ) + ":" + i1i1Ii11
  if 14 - 14: iIii1I11I1II1 + oO0o / ooOoO0o
 return ( i1i1Ii11 [ 0 : - 1 ] )
 if 20 - 20: I1ii11iIi11i . II111iiii % I1Ii111 + I1Ii111 / OoooooooOO . Ii1I
 if 98 - 98: OoooooooOO - i11iIiiIii - iII111i + Ii1I - I1IiiI
 if 75 - 75: OOooOOo
 if 25 - 25: iII111i / I1ii11iIi11i - ooOoO0o
 if 53 - 53: IiII / OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - iIii1I11I1II1
 if 53 - 53: OOooOOo . I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if 40 - 40: OoooooooOO + iII111i % I1Ii111 . ooOoO0o
 if 2 - 2: ooOoO0o
 if 55 - 55: I11i + i1IIi * OoOoOO00 % Oo0Ooo * II111iiii . I1IiiI
 if 98 - 98: I1ii11iIi11i
 if 57 - 57: OOooOOo * I11i . oO0o
def lisp_lookup_public_key ( eid ) :
 i1 = eid . instance_id
 if 17 - 17: iII111i - OOooOOo * I1IiiI + i1IIi % I1ii11iIi11i
 if 71 - 71: Ii1I - o0oOOo0O0Ooo - oO0o
 if 27 - 27: O0 - iIii1I11I1II1
 if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
 if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
 OoOOo0 = lisp_get_eid_hash ( eid )
 if ( OoOOo0 == None ) : return ( [ None , None , False ] )
 if 61 - 61: IiII * I1Ii111 * OoO0O00 / oO0o - OoooooooOO
 OoOOo0 = "hash-" + OoOOo0
 Oo00oOoo = lisp_address ( LISP_AFI_NAME , OoOOo0 , len ( OoOOo0 ) , i1 )
 iiIoOOOOoo0O00o = lisp_address ( LISP_AFI_NONE , "" , 0 , i1 )
 if 5 - 5: o0oOOo0O0Ooo % OOooOOo % II111iiii
 if 86 - 86: O0 . ooOoO0o * OoooooooOO + Ii1I / I11i / II111iiii
 if 26 - 26: OoooooooOO - I1Ii111 / Oo0Ooo - iII111i % OoOoOO00 * OoooooooOO
 if 3 - 3: oO0o
 iiI1I = lisp_site_eid_lookup ( Oo00oOoo , iiIoOOOOoo0O00o , True )
 if ( iiI1I == None ) : return ( [ Oo00oOoo , None , False ] )
 if 3 - 3: I1ii11iIi11i . IiII + ooOoO0o
 if 66 - 66: OOooOOo + oO0o - ooOoO0o / Ii1I * OoO0O00 * i11iIiiIii
 if 69 - 69: I11i % i11iIiiIii
 if 34 - 34: Ii1I . OoooooooOO + II111iiii % oO0o
 ooOo0OO = None
 for IIIi1iI1 in iiI1I . registered_rlocs :
  Oo0OOo0Oo0 = IIIi1iI1 . json
  if ( Oo0OOo0Oo0 == None ) : continue
  try :
   Oo0OOo0Oo0 = json . loads ( Oo0OOo0Oo0 . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( OoOOo0 ) )
   if 79 - 79: I1Ii111
   return ( [ Oo00oOoo , None , False ] )
   if 81 - 81: OoooooooOO + OoOoOO00 / II111iiii
  if ( Oo0OOo0Oo0 . has_key ( "public-key" ) == False ) : continue
  ooOo0OO = Oo0OOo0Oo0 [ "public-key" ]
  break
  if 39 - 39: I1Ii111 * I1IiiI - o0oOOo0O0Ooo . oO0o . OOooOOo * i11iIiiIii
 return ( [ Oo00oOoo , ooOo0OO , True ] )
 if 70 - 70: OoOoOO00 / OOooOOo - o0oOOo0O0Ooo
 if 82 - 82: OOooOOo . i11iIiiIii . I1ii11iIi11i % OoOoOO00 * Ii1I / OoO0O00
 if 56 - 56: o0oOOo0O0Ooo / I1IiiI + I11i + I1IiiI
 if 34 - 34: Oo0Ooo / i11iIiiIii - ooOoO0o
 if 77 - 77: OoOoOO00 * OoooooooOO
 if 41 - 41: iIii1I11I1II1 - O0 . II111iiii + I1IiiI - II111iiii / oO0o
 if 35 - 35: ooOoO0o - OoOoOO00 / iIii1I11I1II1 / OOooOOo
 if 38 - 38: i1IIi % OoooooooOO
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 5 - 5: iIii1I11I1II1 + iIii1I11I1II1 . iIii1I11I1II1 + o0oOOo0O0Ooo
 if 45 - 45: I1IiiI - OoooooooOO - I1Ii111 - i1IIi - OoooooooOO * O0
 if 67 - 67: OoOoOO00 * o0oOOo0O0Ooo . IiII
 if 72 - 72: OoOoOO00 % OoooooooOO * O0
 if 27 - 27: I1ii11iIi11i . OoooooooOO / II111iiii . OOooOOo
 IIIiiiIi1I1 = json . loads ( rloc_record . json . json_string )
 if 58 - 58: oO0o / ooOoO0o
 if ( lisp_get_eid_hash ( eid ) ) :
  O00 = eid
 elif ( IIIiiiIi1I1 . has_key ( "signature-eid" ) ) :
  iII1II11II = IIIiiiIi1I1 [ "signature-eid" ]
  O00 = lisp_address ( LISP_AFI_IPV6 , iII1II11II , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 46 - 46: o0oOOo0O0Ooo % O0
  if 30 - 30: oO0o
  if 64 - 64: O0
  if 70 - 70: oO0o % I1IiiI . iIii1I11I1II1 - Oo0Ooo + OoOoOO00 % O0
  if 91 - 91: I1Ii111 - oO0o * ooOoO0o - I1ii11iIi11i + IiII + O0
 Oo00oOoo , ooOo0OO , IIi1II1i111i1i = lisp_lookup_public_key ( O00 )
 if ( Oo00oOoo == None ) :
  iIiI1I1ii1I1 = green ( O00 . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( iIiI1I1ii1I1 ) )
  return ( False )
  if 82 - 82: I11i . I1IiiI / I1Ii111 + ooOoO0o % iII111i
  if 47 - 47: I1Ii111 / iIii1I11I1II1 / i1IIi % O0 + i1IIi
 Ii1iI11I1ii1i = "found" if IIi1II1i111i1i else bold ( "not found" , False )
 iIiI1I1ii1I1 = green ( Oo00oOoo . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( iIiI1I1ii1I1 , Ii1iI11I1ii1i ) )
 if ( IIi1II1i111i1i == False ) : return ( False )
 if 65 - 65: ooOoO0o % I11i / O0 + OoooooooOO + OOooOOo % OoOoOO00
 if ( ooOo0OO == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 82 - 82: I11i . IiII
  if 27 - 27: I1Ii111 % O0 * OoooooooOO . Oo0Ooo
 o0oOOO000O = ooOo0OO [ 0 : 8 ] + "..." + ooOo0OO [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( o0oOOO000O ) )
 if 66 - 66: OoooooooOO
 if 4 - 4: Oo0Ooo % iII111i
 if 24 - 24: ooOoO0o * oO0o * Oo0Ooo . oO0o - OoOoOO00
 if 85 - 85: II111iiii
 if 51 - 51: Oo0Ooo
 OoO0OOOo0O0O0 = IIIiiiIi1I1 [ "signature" ]
 if 30 - 30: i11iIiiIii - I11i * ooOoO0o + iII111i % I1Ii111
 try :
  IIIiiiIi1I1 = binascii . a2b_base64 ( OoO0OOOo0O0O0 )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 1 - 1: iIii1I11I1II1 % i11iIiiIii - i11iIiiIii % II111iiii
  if 89 - 89: iII111i . OoO0O00 . iII111i
 iI1iIIII1 = len ( IIIiiiIi1I1 )
 if ( iI1iIIII1 & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( iI1iIIII1 ) )
  return ( False )
  if 75 - 75: OoooooooOO . II111iiii / Oo0Ooo . I1ii11iIi11i % IiII
  if 83 - 83: iII111i + i1IIi % I1IiiI % OOooOOo . iII111i % ooOoO0o
  if 15 - 15: iII111i
  if 55 - 55: iII111i
  if 22 - 22: I1Ii111 % II111iiii % iIii1I11I1II1 % II111iiii
 oOO0 = O00 . print_address ( )
 if 33 - 33: II111iiii
 if 60 - 60: iIii1I11I1II1 / OOooOOo
 if 78 - 78: i11iIiiIii
 if 20 - 20: OoooooooOO * OoooooooOO - OOooOOo
 ooOo0OO = binascii . a2b_base64 ( ooOo0OO )
 try :
  OO0Oo00o0o0 = ecdsa . VerifyingKey . from_pem ( ooOo0OO )
 except :
  II1iiiiIIIII = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( II1iiiiIIIII ) )
  return ( False )
  if 90 - 90: I11i / II111iiii % o0oOOo0O0Ooo * IiII * IiII
  if 46 - 46: O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - i1IIi * O0
  if 49 - 49: ooOoO0o . OoO0O00
  if 84 - 84: O0
  if 75 - 75: OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00 + o0oOOo0O0Ooo + I11i
  if 70 - 70: O0 - OoO0O00
  if 60 - 60: ooOoO0o
  if 95 - 95: I11i / o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
  if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
  if 8 - 8: OoooooooOO * ooOoO0o
  if 26 - 26: i11iIiiIii + oO0o - i1IIi
 try :
  ooo0oooooOoo0 = OO0Oo00o0o0 . verify ( IIIiiiIi1I1 , oOO0 , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( oOO0 ) )
  if 71 - 71: I1IiiI % I1Ii111 / oO0o % oO0o / iIii1I11I1II1 + I1Ii111
  lprint ( "  Signature used '{}'" . format ( OoO0OOOo0O0O0 ) )
  return ( False )
  if 86 - 86: IiII % i1IIi * o0oOOo0O0Ooo - I1Ii111
 return ( ooo0oooooOoo0 )
 if 37 - 37: iII111i % I1IiiI - I1ii11iIi11i % I11i
 if 35 - 35: O0 - OoooooooOO % iII111i
 if 48 - 48: OOooOOo % i11iIiiIii
 if 49 - 49: O0 * iII111i + II111iiii - OOooOOo
 if 29 - 29: OoooooooOO % II111iiii - Oo0Ooo / IiII - i11iIiiIii
 if 64 - 64: iII111i . I1Ii111 + I1Ii111
 if 1 - 1: OOooOOo % Oo0Ooo
 if 81 - 81: oO0o / I11i % Ii1I . I11i + OoooooooOO
 if 31 - 31: OoO0O00
 if 41 - 41: i11iIiiIii - I1ii11iIi11i - II111iiii
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 5 - 5: OoOoOO00 + i1IIi
 if 43 - 43: iII111i * I1IiiI
 if 20 - 20: I1IiiI . I11i * OoO0O00 . ooOoO0o . II111iiii
 if 6 - 6: Ii1I * OoOoOO00 % IiII + I11i
 if 20 - 20: oO0o
 Ii1I1I = [ ]
 for Oo0o0OOoOo in eid_list :
  for IiII1i in lisp_map_notify_queue :
   ii11i1IiI = lisp_map_notify_queue [ IiII1i ]
   if ( Oo0o0OOoOo not in ii11i1IiI . eid_list ) : continue
   if 99 - 99: O0 + O0 . iIii1I11I1II1 . ooOoO0o * o0oOOo0O0Ooo
   Ii1I1I . append ( IiII1i )
   i1i1I1Iii = ii11i1IiI . retransmit_timer
   if ( i1i1I1Iii ) : i1i1I1Iii . cancel ( )
   if 7 - 7: ooOoO0o
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( ii11i1IiI . nonce_key , green ( Oo0o0OOoOo , False ) ) )
   if 73 - 73: OOooOOo % iII111i % I1Ii111
   if 18 - 18: I1ii11iIi11i
   if 21 - 21: O0 + iIii1I11I1II1 / i11iIiiIii . OOooOOo * i1IIi
   if 3 - 3: i1IIi % o0oOOo0O0Ooo + OoOoOO00
   if 32 - 32: OoO0O00 . Oo0Ooo * iIii1I11I1II1
   if 12 - 12: O0 + I1ii11iIi11i + I11i . I1Ii111
   if 48 - 48: Ii1I . iIii1I11I1II1 - iIii1I11I1II1 * I11i . OoooooooOO
 for IiII1i in Ii1I1I : lisp_map_notify_queue . pop ( IiII1i )
 return
 if 73 - 73: Ii1I / II111iiii - iIii1I11I1II1 . ooOoO0o * II111iiii . OOooOOo
 if 50 - 50: iIii1I11I1II1 + OoOoOO00 % O0 + OoO0O00 . i11iIiiIii / oO0o
 if 31 - 31: I1IiiI % o0oOOo0O0Ooo . i11iIiiIii % OOooOOo - iIii1I11I1II1
 if 77 - 77: i11iIiiIii / OOooOOo
 if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
 if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
 if 59 - 59: oO0o * OoO0O00 - I11i * I1IiiI
 if 60 - 60: iII111i - OoooooooOO / iII111i % OoO0O00 . OoOoOO00 - o0oOOo0O0Ooo
def lisp_decrypt_map_register ( packet ) :
 if 71 - 71: iII111i * o0oOOo0O0Ooo * i11iIiiIii * O0
 if 77 - 77: OOooOOo % iII111i + I11i / OoOoOO00
 if 50 - 50: OoOoOO00 - i11iIiiIii - OOooOOo . iIii1I11I1II1
 if 97 - 97: oO0o % OOooOOo . OoooooooOO * Ii1I
 if 100 - 100: I1ii11iIi11i / Ii1I % Oo0Ooo
 OoOOoo0o00O0oO = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 oo0O00O0O0O00Ooo = ( OoOOoo0o00O0oO >> 13 ) & 0x1
 if ( oo0O00O0O0O00Ooo == 0 ) : return ( packet )
 if 97 - 97: i1IIi . I1ii11iIi11i . OOooOOo - ooOoO0o
 iiIi1iIIII1 = ( OoOOoo0o00O0oO >> 14 ) & 0x7
 if 65 - 65: I11i . o0oOOo0O0Ooo + i11iIiiIii
 if 4 - 4: oO0o . i11iIiiIii - OoooooooOO - I11i . Ii1I
 if 83 - 83: Oo0Ooo * II111iiii + Ii1I
 if 59 - 59: iII111i % OoO0O00 / Oo0Ooo + I1ii11iIi11i % Ii1I
 try :
  OooOo0o = lisp_ms_encryption_keys [ iiIi1iIIII1 ]
  OooOo0o = OooOo0o . zfill ( 32 )
  OoOooO = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( iiIi1iIIII1 ) )
  return ( None )
  if 88 - 88: II111iiii + i11iIiiIii
  if 14 - 14: II111iiii + OOooOOo * Ii1I * I1IiiI + OOooOOo . OOooOOo
 IiI11I111 = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( IiI11I111 , iiIi1iIIII1 ) )
 if 5 - 5: oO0o + OoooooooOO
 if 88 - 88: oO0o + OOooOOo
 if 14 - 14: I11i / i1IIi
 if 56 - 56: OoooooooOO
 o0oO = chacha . ChaCha ( OooOo0o , OoOooO , 20 ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + o0oO )
 if 59 - 59: I1ii11iIi11i + OoO0O00
 if 37 - 37: IiII * I1IiiI % O0
 if 32 - 32: ooOoO0o % II111iiii
 if 60 - 60: i11iIiiIii
 if 11 - 11: o0oOOo0O0Ooo
 if 77 - 77: o0oOOo0O0Ooo / iIii1I11I1II1 * iIii1I11I1II1 / o0oOOo0O0Ooo * iII111i
 if 26 - 26: Ii1I
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 1 - 1: OoOoOO00 . o0oOOo0O0Ooo + Oo0Ooo % Oo0Ooo * I1ii11iIi11i
 if 50 - 50: IiII / i1IIi . I1ii11iIi11i
 if 75 - 75: I11i * oO0o + OoooooooOO . iII111i + OoO0O00
 if 44 - 44: II111iiii
 if 65 - 65: I11i . iII111i . I1IiiI - Oo0Ooo % iIii1I11I1II1 / O0
 if 54 - 54: iII111i - I1Ii111
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
 iiIio0o0 = lisp_map_register ( )
 iII111I , packet = iiIio0o0 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 45 - 45: oO0o % oO0o
 iiIio0o0 . sport = sport
 if 85 - 85: i1IIi + oO0o % Ii1I + iIii1I11I1II1
 iiIio0o0 . print_map_register ( )
 if 72 - 72: I1ii11iIi11i / II111iiii . oO0o - o0oOOo0O0Ooo
 if 80 - 80: i1IIi
 if 40 - 40: O0 . ooOoO0o * iII111i . I11i + I1Ii111 % OoO0O00
 if 9 - 9: IiII * oO0o - o0oOOo0O0Ooo
 i1IiIIi11I = True
 if ( iiIio0o0 . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  i1IiIIi11I = True
  if 31 - 31: OOooOOo + IiII
 if ( iiIio0o0 . alg_id == LISP_SHA_256_128_ALG_ID ) :
  i1IiIIi11I = False
  if 56 - 56: OoooooooOO * II111iiii
  if 99 - 99: i11iIiiIii - II111iiii . Oo0Ooo - oO0o . I1IiiI + i1IIi
  if 69 - 69: O0 / i1IIi - OoOoOO00 + ooOoO0o - oO0o
  if 80 - 80: o0oOOo0O0Ooo % O0 * I11i . i1IIi - ooOoO0o
  if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
 Oooo0 = [ ]
 if 57 - 57: OOooOOo
 if 76 - 76: Oo0Ooo . I1Ii111 + iII111i / OoooooooOO . Oo0Ooo
 if 68 - 68: OoO0O00 % OoO0O00 + i11iIiiIii / Ii1I
 if 20 - 20: I1Ii111 + IiII - O0 + IiII / i1IIi
 ooo0ooOO0OO = None
 O0OII = packet
 OOoOo0oOoo = [ ]
 iIiI1IIi1Ii1i = iiIio0o0 . record_count
 for OoOOoO0oOo in range ( iIiI1IIi1Ii1i ) :
  oOO0O0o0oOooO = lisp_eid_record ( )
  iIIi = lisp_rloc_record ( )
  packet = oOO0O0o0oOooO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 38 - 38: I11i
  oOO0O0o0oOooO . print_record ( "  " , False )
  if 7 - 7: OoO0O00 . i1IIi - I1IiiI * I1Ii111 - iII111i
  if 45 - 45: I1ii11iIi11i % OoOoOO00
  if 39 - 39: II111iiii . ooOoO0o
  if 77 - 77: OoooooooOO . II111iiii
  iiI1I = lisp_site_eid_lookup ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group ,
 False )
  if 88 - 88: Ii1I - Oo0Ooo + Ii1I % OoooooooOO * i1IIi
  oO0O0o = iiI1I . print_eid_tuple ( ) if iiI1I else None
  if 78 - 78: Ii1I * i1IIi * oO0o + I1IiiI
  if 40 - 40: OoooooooOO * i11iIiiIii
  if 58 - 58: IiII / Oo0Ooo + o0oOOo0O0Ooo
  if 71 - 71: Ii1I - IiII
  if 2 - 2: OoOoOO00 % IiII % OoO0O00 . i1IIi / I1Ii111 - iIii1I11I1II1
  if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
  if 65 - 65: iII111i . oO0o
  if ( iiI1I and iiI1I . accept_more_specifics == False ) :
   if ( iiI1I . eid_record_matches ( oOO0O0o0oOooO ) == False ) :
    Ooo0 = iiI1I . parent_for_more_specifics
    if ( Ooo0 ) : iiI1I = Ooo0
    if 81 - 81: oO0o
    if 100 - 100: Ii1I * I1IiiI
    if 43 - 43: IiII % ooOoO0o - i11iIiiIii - I11i
    if 41 - 41: I1Ii111 * OoooooooOO / OoOoOO00 + OoO0O00 . OoOoOO00 + I1Ii111
    if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
    if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
    if 43 - 43: Oo0Ooo % I11i
    if 53 - 53: OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
  IiII1II1I = ( iiI1I and iiI1I . accept_more_specifics )
  if ( IiII1II1I ) :
   iIIIiIIi1 = lisp_site_eid ( iiI1I . site )
   iIIIiIIi1 . dynamic = True
   iIIIiIIi1 . eid . copy_address ( oOO0O0o0oOooO . eid )
   iIIIiIIi1 . group . copy_address ( oOO0O0o0oOooO . group )
   iIIIiIIi1 . parent_for_more_specifics = iiI1I
   iIIIiIIi1 . add_cache ( )
   iIIIiIIi1 . inherit_from_ams_parent ( )
   iiI1I . more_specific_registrations . append ( iIIIiIIi1 )
   iiI1I = iIIIiIIi1
  else :
   iiI1I = lisp_site_eid_lookup ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group ,
 True )
   if 100 - 100: ooOoO0o . OoooooooOO % i1IIi % OoO0O00
   if 26 - 26: OoOoOO00 * IiII
  iIiI1I1ii1I1 = oOO0O0o0oOooO . print_eid_tuple ( )
  if 76 - 76: I1IiiI + IiII * I1ii11iIi11i * I1IiiI % Ii1I + ooOoO0o
  if ( iiI1I == None ) :
   iiIIi1iI = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( iiIIi1iI , green ( iIiI1I1ii1I1 , False ) ,
 ", matched non-ams {}" . format ( green ( oO0O0o , False ) if oO0O0o else "" ) ) )
   if 46 - 46: OoOoOO00
   if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
   if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
   if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
   if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
   packet = iIIi . end_of_rlocs ( packet , oOO0O0o0oOooO . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 20 - 20: IiII
   continue
   if 81 - 81: Oo0Ooo / I1Ii111
   if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
  ooo0ooOO0OO = iiI1I . site
  if 51 - 51: iII111i - ooOoO0o
  if ( IiII1II1I ) :
   I1i = iiI1I . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( I1i , False ) , ooo0ooOO0OO . site_name , green ( iIiI1I1ii1I1 , False ) ) )
   if 32 - 32: IiII - i11iIiiIii
  else :
   I1i = green ( iiI1I . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( I1i , ooo0ooOO0OO . site_name , green ( iIiI1I1ii1I1 , False ) ) )
   if 41 - 41: Ii1I % Ii1I * oO0o - I11i + iIii1I11I1II1 . ooOoO0o
   if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
   if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
   if 49 - 49: I1Ii111 . OoooooooOO / o0oOOo0O0Ooo - iII111i - iII111i - i11iIiiIii
   if 37 - 37: OOooOOo
   if 79 - 79: I1Ii111 - OoO0O00 + ooOoO0o + oO0o . i11iIiiIii + i1IIi
  if ( ooo0ooOO0OO . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( ooo0ooOO0OO . site_name ) )
   packet = iIIi . end_of_rlocs ( packet , oOO0O0o0oOooO . rloc_count )
   continue
   if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
   if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
   if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
   if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
   if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
   if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
   if 22 - 22: ooOoO0o - OOooOOo
   if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
  I1IIiiiiI1iIi = iiIio0o0 . key_id
  if ( ooo0ooOO0OO . auth_key . has_key ( I1IIiiiiI1iIi ) ) :
   i1ii1IIii = ooo0ooOO0OO . auth_key [ I1IIiiiiI1iIi ]
  else :
   i1ii1IIii = ""
   if 99 - 99: I1ii11iIi11i % iII111i * IiII - I1IiiI
   if 60 - 60: OoO0O00
  O0oO0 = lisp_verify_auth ( iII111I , iiIio0o0 . alg_id ,
 iiIio0o0 . auth_data , i1ii1IIii )
  i1II11iiIiii = "dynamic " if iiI1I . dynamic else ""
  if 1 - 1: O0 % Ii1I + OOooOOo + oO0o
  o0oOoO00o = bold ( "passed" if O0oO0 else "failed" , False )
  I1IIiiiiI1iIi = "key-id {}" . format ( I1IIiiiiI1iIi ) if I1IIiiiiI1iIi == iiIio0o0 . key_id else "bad key-id {}" . format ( iiIio0o0 . key_id )
  if 68 - 68: o0oOOo0O0Ooo . OOooOOo % IiII
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( o0oOoO00o , i1II11iiIiii , green ( iIiI1I1ii1I1 , False ) , I1IIiiiiI1iIi ) )
  if 38 - 38: OOooOOo . II111iiii / i11iIiiIii - OOooOOo % ooOoO0o - I1IiiI
  if 92 - 92: OoOoOO00 - oO0o % o0oOOo0O0Ooo % OoooooooOO
  if 3 - 3: O0 / ooOoO0o . Ii1I
  if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
  if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
  if 88 - 88: ooOoO0o
  oo00ooo0o0 = True
  i11Ii = ( lisp_get_eid_hash ( oOO0O0o0oOooO . eid ) != None )
  if ( i11Ii or iiI1I . require_signature ) :
   i1I11 = "Required " if iiI1I . require_signature else ""
   iIiI1I1ii1I1 = green ( iIiI1I1ii1I1 , False )
   IIIi1iI1 = lisp_find_sig_in_rloc_set ( packet , oOO0O0o0oOooO . rloc_count )
   if ( IIIi1iI1 == None ) :
    oo00ooo0o0 = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( i1I11 ,
    # OoO0O00 - iII111i . OOooOOo - iIii1I11I1II1 . II111iiii
 bold ( "failed" , False ) , iIiI1I1ii1I1 ) )
   else :
    oo00ooo0o0 = lisp_verify_cga_sig ( oOO0O0o0oOooO . eid , IIIi1iI1 )
    o0oOoO00o = bold ( "passed" if oo00ooo0o0 else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( i1I11 , o0oOoO00o , iIiI1I1ii1I1 ) )
    if 50 - 50: IiII . ooOoO0o / OoooooooOO
    if 76 - 76: OoO0O00
    if 35 - 35: OoO0O00 * iIii1I11I1II1 . OoO0O00 % II111iiii % O0
    if 71 - 71: O0 . i1IIi % iIii1I11I1II1 % OoOoOO00
  if ( O0oO0 == False or oo00ooo0o0 == False ) :
   packet = iIIi . end_of_rlocs ( packet , oOO0O0o0oOooO . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 83 - 83: ooOoO0o + I1Ii111 - OoooooooOO
   continue
   if 55 - 55: OoooooooOO * O0 - II111iiii / IiII
   if 18 - 18: II111iiii % O0 - o0oOOo0O0Ooo * ooOoO0o
   if 74 - 74: I11i . oO0o + I11i * o0oOOo0O0Ooo / O0
   if 55 - 55: OoO0O00 / i11iIiiIii / o0oOOo0O0Ooo
   if 19 - 19: ooOoO0o * iII111i
   if 38 - 38: ooOoO0o
  if ( iiIio0o0 . merge_register_requested ) :
   Ooo0 = iiI1I
   Ooo0 . inconsistent_registration = False
   if 35 - 35: o0oOOo0O0Ooo * IiII * Oo0Ooo
   if 34 - 34: I11i - OoooooooOO % i1IIi + I1IiiI
   if 14 - 14: I1IiiI . o0oOOo0O0Ooo / I1Ii111
   if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
   if 32 - 32: oO0o
   if ( iiI1I . group . is_null ( ) ) :
    if ( Ooo0 . site_id != iiIio0o0 . site_id ) :
     Ooo0 . site_id = iiIio0o0 . site_id
     Ooo0 . registered = False
     Ooo0 . individual_registrations = { }
     Ooo0 . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 72 - 72: I1IiiI
     if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
     if 87 - 87: Oo0Ooo
   OO0Oo00o0o0 = iiIio0o0 . xtr_id
   if ( iiI1I . individual_registrations . has_key ( OO0Oo00o0o0 ) ) :
    iiI1I = iiI1I . individual_registrations [ OO0Oo00o0o0 ]
   else :
    iiI1I = lisp_site_eid ( ooo0ooOO0OO )
    iiI1I . eid . copy_address ( Ooo0 . eid )
    iiI1I . group . copy_address ( Ooo0 . group )
    iiI1I . encrypt_json = Ooo0 . encrypt_json
    Ooo0 . individual_registrations [ OO0Oo00o0o0 ] = iiI1I
    if 7 - 7: iIii1I11I1II1
  else :
   iiI1I . inconsistent_registration = iiI1I . merge_register_requested
   if 85 - 85: iIii1I11I1II1 . O0
   if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
   if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
  iiI1I . map_registers_received += 1
  if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
  if 8 - 8: OoO0O00 . OoO0O00
  if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
  if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
  if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
  II1iiiiIIIII = ( iiI1I . is_rloc_in_rloc_set ( source ) == False )
  if ( oOO0O0o0oOooO . record_ttl == 0 and II1iiiiIIIII ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 24 - 24: IiII
   continue
   if 95 - 95: IiII + OoOoOO00 * OOooOOo
   if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
   if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
   if 41 - 41: i1IIi / IiII
   if 73 - 73: o0oOOo0O0Ooo % ooOoO0o
   if 72 - 72: OoO0O00 * OoOoOO00 % I1IiiI - OOooOOo . Oo0Ooo
  O0Ooo000Ooo = iiI1I . registered_rlocs
  iiI1I . registered_rlocs = [ ]
  if 24 - 24: Oo0Ooo / II111iiii * Oo0Ooo - ooOoO0o
  if 46 - 46: o0oOOo0O0Ooo
  if 41 - 41: I11i % II111iiii - II111iiii + OoO0O00
  if 98 - 98: iIii1I11I1II1 + OOooOOo * oO0o / o0oOOo0O0Ooo . iII111i
  o0ooOO0 = packet
  for O0O0Oo in range ( oOO0O0o0oOooO . rloc_count ) :
   iIIi = lisp_rloc_record ( )
   packet = iIIi . decode ( packet , None , iiI1I . encrypt_json )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 36 - 36: oO0o - OoOoOO00 . O0 % IiII
   iIIi . print_record ( "    " )
   if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
   if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
   if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
   if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
   if ( len ( ooo0ooOO0OO . allowed_rlocs ) > 0 ) :
    O0O0 = iIIi . rloc . print_address ( )
    if ( ooo0ooOO0OO . allowed_rlocs . has_key ( O0O0 ) == False ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( O0O0 , False ) ) )
     if 41 - 41: OoooooooOO + iII111i . OOooOOo
     if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
     iiI1I . registered = False
     packet = iIIi . end_of_rlocs ( packet ,
 oOO0O0o0oOooO . rloc_count - O0O0Oo - 1 )
     break
     if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
     if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
     if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
     if 57 - 57: II111iiii % OoO0O00 * i1IIi
     if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
     if 9 - 9: II111iiii % OoooooooOO
   IIIi1iI1 = lisp_rloc ( )
   IIIi1iI1 . store_rloc_from_record ( iIIi , None , source )
   if 4 - 4: i1IIi * i11iIiiIii % OoooooooOO + OoOoOO00 . oO0o
   if 95 - 95: I1ii11iIi11i * OoOoOO00 % o0oOOo0O0Ooo / O0 + ooOoO0o % OOooOOo
   if 48 - 48: i1IIi + IiII - iIii1I11I1II1 . i11iIiiIii % OOooOOo + I1ii11iIi11i
   if 95 - 95: ooOoO0o + OoOoOO00 . II111iiii + Ii1I
   if 81 - 81: OoooooooOO / OOooOOo / Oo0Ooo
   if 26 - 26: iII111i
   if ( source . is_exact_match ( IIIi1iI1 . rloc ) ) :
    IIIi1iI1 . map_notify_requested = iiIio0o0 . map_notify_requested
    if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
    if 6 - 6: IiII
    if 68 - 68: Oo0Ooo
    if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
    if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
   iiI1I . registered_rlocs . append ( IIIi1iI1 )
   if 93 - 93: i11iIiiIii
   if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
  i11iI1iIi11 = ( iiI1I . do_rloc_sets_match ( O0Ooo000Ooo ) == False )
  if 49 - 49: iIii1I11I1II1
  if 82 - 82: I1IiiI . OOooOOo % ooOoO0o / O0
  if 60 - 60: iIii1I11I1II1 % iIii1I11I1II1 * o0oOOo0O0Ooo + OoO0O00 . OoOoOO00 % I1Ii111
  if 9 - 9: OoooooooOO % IiII % I1Ii111
  if 85 - 85: IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i1IIi . iII111i
  if 20 - 20: oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
  if ( iiIio0o0 . map_register_refresh and i11iI1iIi11 and
 iiI1I . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   iiI1I . registered_rlocs = O0Ooo000Ooo
   continue
   if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
   if 15 - 15: i1IIi . iII111i + IiII / I1ii11iIi11i - i1IIi / iII111i
   if 27 - 27: OoOoOO00 / OoooooooOO + i1IIi % iIii1I11I1II1 / OoO0O00
   if 73 - 73: I1ii11iIi11i / OoOoOO00 / IiII + oO0o
   if 73 - 73: I11i * o0oOOo0O0Ooo * I1IiiI . OoooooooOO % I1Ii111
   if 9 - 9: oO0o % I1Ii111 . O0 + I1ii11iIi11i - Ii1I - I1ii11iIi11i
  if ( iiI1I . registered == False ) :
   iiI1I . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 57 - 57: i11iIiiIii
  iiI1I . last_registered = lisp_get_timestamp ( )
  iiI1I . registered = ( oOO0O0o0oOooO . record_ttl != 0 )
  iiI1I . last_registerer = source
  if 21 - 21: iIii1I11I1II1 / I1IiiI / iII111i
  if 19 - 19: Oo0Ooo / iIii1I11I1II1 / I11i
  if 71 - 71: iIii1I11I1II1 * I1IiiI
  if 35 - 35: O0
  iiI1I . auth_sha1_or_sha2 = i1IiIIi11I
  iiI1I . proxy_reply_requested = iiIio0o0 . proxy_reply_requested
  iiI1I . lisp_sec_present = iiIio0o0 . lisp_sec_present
  iiI1I . map_notify_requested = iiIio0o0 . map_notify_requested
  iiI1I . mobile_node_requested = iiIio0o0 . mobile_node
  iiI1I . merge_register_requested = iiIio0o0 . merge_register_requested
  if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
  iiI1I . use_register_ttl_requested = iiIio0o0 . use_ttl_for_timeout
  if ( iiI1I . use_register_ttl_requested ) :
   iiI1I . register_ttl = oOO0O0o0oOooO . store_ttl ( )
  else :
   iiI1I . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
  iiI1I . xtr_id_present = iiIio0o0 . xtr_id_present
  if ( iiI1I . xtr_id_present ) :
   iiI1I . xtr_id = iiIio0o0 . xtr_id
   iiI1I . site_id = iiIio0o0 . site_id
   if 78 - 78: I1IiiI - iIii1I11I1II1
   if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
   if 85 - 85: I11i + OoOoOO00 * O0 * O0
   if 92 - 92: i11iIiiIii
   if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
  if ( iiIio0o0 . merge_register_requested ) :
   if ( Ooo0 . merge_in_site_eid ( iiI1I ) ) :
    Oooo0 . append ( [ oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group ] )
    if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
   if ( iiIio0o0 . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , Ooo0 , iiIio0o0 ,
 oOO0O0o0oOooO )
    if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
    if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
    if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
  if ( i11iI1iIi11 == False ) : continue
  if ( len ( Oooo0 ) != 0 ) : continue
  if 42 - 42: OoOoOO00 . I11i % II111iiii
  OOoOo0oOoo . append ( iiI1I . print_eid_tuple ( ) )
  if 19 - 19: OoooooooOO
  if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
  if 21 - 21: OOooOOo . Oo0Ooo - i1IIi
  if 56 - 56: I11i
  if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
  if 32 - 32: OOooOOo / i1IIi / OOooOOo
  if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
  ii1iII = copy . deepcopy ( oOO0O0o0oOooO )
  oOO0O0o0oOooO = oOO0O0o0oOooO . encode ( )
  oOO0O0o0oOooO += o0ooOO0
  iII = [ iiI1I . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 90 - 90: iII111i . o0oOOo0O0Ooo
  for IIIi1iI1 in O0Ooo000Ooo :
   if ( IIIi1iI1 . map_notify_requested == False ) : continue
   if ( IIIi1iI1 . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , oOO0O0o0oOooO , iII , 1 , IIIi1iI1 . rloc ,
 LISP_CTRL_PORT , iiIio0o0 . nonce , iiIio0o0 . key_id ,
 iiIio0o0 . alg_id , iiIio0o0 . auth_len , ooo0ooOO0OO , False )
   if 97 - 97: Oo0Ooo . I1ii11iIi11i - I1Ii111 - Ii1I / OOooOOo
   if 18 - 18: OoOoOO00 / OoO0O00 % ooOoO0o * Ii1I
   if 67 - 67: I11i . II111iiii + iIii1I11I1II1 - I1IiiI
   if 25 - 25: i1IIi . OoO0O00 - Ii1I
   if 42 - 42: O0 * iII111i . i1IIi / i11iIiiIii + Ii1I
  lisp_notify_subscribers ( lisp_sockets , ii1iII , o0ooOO0 ,
 iiI1I . eid , ooo0ooOO0OO )
  if 80 - 80: O0 + II111iiii + oO0o . Oo0Ooo * i1IIi
  if 8 - 8: Ii1I
  if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
  if 15 - 15: O0
  if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
 if ( len ( Oooo0 ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , Oooo0 )
  if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
  if 25 - 25: ooOoO0o
  if 33 - 33: Oo0Ooo
  if 11 - 11: I11i
  if 55 - 55: i11iIiiIii * OoOoOO00 - OoOoOO00 * OoO0O00 / iII111i
  if 64 - 64: iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
 if ( iiIio0o0 . merge_register_requested ) : return
 if 74 - 74: I1IiiI / o0oOOo0O0Ooo
 if 53 - 53: iIii1I11I1II1 * oO0o
 if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
 if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
 if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
 if ( iiIio0o0 . map_notify_requested and ooo0ooOO0OO != None ) :
  lisp_build_map_notify ( lisp_sockets , O0OII , OOoOo0oOoo ,
 iiIio0o0 . record_count , source , sport , iiIio0o0 . nonce ,
 iiIio0o0 . key_id , iiIio0o0 . alg_id , iiIio0o0 . auth_len ,
 ooo0ooOO0OO , True )
  if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
 return
 if 60 - 60: oO0o * I1Ii111
 if 81 - 81: oO0o - OOooOOo - oO0o
 if 54 - 54: oO0o % I11i
 if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
 if 22 - 22: iIii1I11I1II1 - OoooooooOO
 if 8 - 8: ooOoO0o % i11iIiiIii
 if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
 if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
def lisp_process_unicast_map_notify ( lisp_sockets , packet , source ) :
 ii11i1IiI = lisp_map_notify ( "" )
 packet = ii11i1IiI . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
  if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
 ii11i1IiI . print_notify ( )
 if ( ii11i1IiI . record_count == 0 ) : return
 if 73 - 73: O0 % i11iIiiIii
 iiIii1 = ii11i1IiI . eid_records
 if 5 - 5: OoO0O00 . iII111i * oO0o + I1IiiI . Oo0Ooo
 for OoOOoO0oOo in range ( ii11i1IiI . record_count ) :
  oOO0O0o0oOooO = lisp_eid_record ( )
  iiIii1 = oOO0O0o0oOooO . decode ( iiIii1 )
  if ( packet == None ) : return
  oOO0O0o0oOooO . print_record ( "  " , False )
  iIiI1I1ii1I1 = oOO0O0o0oOooO . print_eid_tuple ( )
  if 13 - 13: oO0o / ooOoO0o / OoOoOO00
  if 49 - 49: I1Ii111 / iIii1I11I1II1 / OoooooooOO + i1IIi % IiII
  if 64 - 64: I11i / O0 + i1IIi * II111iiii
  if 20 - 20: iIii1I11I1II1
  if 9 - 9: OoO0O00
  ooOoOO0Oo = lisp_map_cache_lookup ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . eid )
  if ( ooOoOO0Oo == None ) :
   I1i = green ( iIiI1I1ii1I1 , False )
   lprint ( "Ignoring Map-Notify EID {}, no subscribe-request entry" . format ( I1i ) )
   if 5 - 5: OOooOOo % iII111i % Oo0Ooo . I11i
   continue
   if 25 - 25: iIii1I11I1II1 * OoOoOO00 + ooOoO0o * I11i / I1Ii111 - I11i
   if 5 - 5: I1Ii111 * I11i . ooOoO0o . o0oOOo0O0Ooo - O0
   if 39 - 39: OoO0O00
   if 19 - 19: i1IIi
   if 53 - 53: OOooOOo * O0 . iII111i
   if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
   if 78 - 78: iII111i
  if ( ooOoOO0Oo . action != LISP_SEND_PUBSUB_ACTION ) :
   if ( ooOoOO0Oo . subscribed_eid == None ) :
    I1i = green ( iIiI1I1ii1I1 , False )
    lprint ( "Ignoring Map-Notify for non-subscribed EID {}" . format ( I1i ) )
    if 80 - 80: i1IIi * I1IiiI + OOooOOo
    continue
    if 91 - 91: I1IiiI % OoOoOO00 * Oo0Ooo / I1ii11iIi11i
    if 57 - 57: i11iIiiIii / o0oOOo0O0Ooo . II111iiii
    if 63 - 63: O0
    if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
    if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
    if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
    if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
    if 74 - 74: i11iIiiIii
  O0000oo0Oo = [ ]
  if ( ooOoOO0Oo . action == LISP_SEND_PUBSUB_ACTION ) :
   ooOoOO0Oo = lisp_mapping ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group , [ ] )
   ooOoOO0Oo . add_cache ( )
   i11o0o0OoOo00O0O = copy . deepcopy ( oOO0O0o0oOooO . eid )
   oo0ooOo0oo0Oo = copy . deepcopy ( oOO0O0o0oOooO . group )
  else :
   i11o0o0OoOo00O0O = ooOoOO0Oo . subscribed_eid
   oo0ooOo0oo0Oo = ooOoOO0Oo . subscribed_group
   O0000oo0Oo = ooOoOO0Oo . rloc_set
   ooOoOO0Oo . delete_rlocs_from_rloc_probe_list ( )
   ooOoOO0Oo . rloc_set = [ ]
   if 35 - 35: Oo0Ooo / OoooooooOO * O0 / Ii1I . OoO0O00
   if 93 - 93: I11i / OoooooooOO % Oo0Ooo . OoO0O00
   if 54 - 54: OoooooooOO . OoooooooOO / i1IIi * Oo0Ooo
   if 90 - 90: oO0o / Oo0Ooo + Oo0Ooo
   if 16 - 16: I1Ii111 / I1ii11iIi11i / I11i - I1IiiI
  ooOoOO0Oo . mapping_source = None if source == "lisp-itr" else source
  ooOoOO0Oo . map_cache_ttl = oOO0O0o0oOooO . store_ttl ( )
  ooOoOO0Oo . subscribed_eid = i11o0o0OoOo00O0O
  ooOoOO0Oo . subscribed_group = oo0ooOo0oo0Oo
  if 30 - 30: I1Ii111 + OoO0O00 % OoOoOO00 / I11i - iII111i
  if 35 - 35: o0oOOo0O0Ooo / I1Ii111 - ooOoO0o
  if 44 - 44: I1IiiI * I11i + I1ii11iIi11i / IiII
  if 95 - 95: OoOoOO00
  if 73 - 73: IiII * Oo0Ooo . I1IiiI - iIii1I11I1II1
  if ( len ( O0000oo0Oo ) != 0 and oOO0O0o0oOooO . rloc_count == 0 ) :
   ooOoOO0Oo . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , ooOoOO0Oo )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( iIiI1I1ii1I1 , False ) ) )
   if 100 - 100: i11iIiiIii - IiII
   continue
   if 43 - 43: oO0o - I11i . i11iIiiIii
   if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
   if 30 - 30: I1IiiI % oO0o * OoooooooOO
   if 64 - 64: I1IiiI
   if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
   if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
   if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
  O00o0OoO0OOOo = OOOOO0OO00OOO = 0
  for O0O0Oo in range ( oOO0O0o0oOooO . rloc_count ) :
   iIIi = lisp_rloc_record ( )
   iiIii1 = iIIi . decode ( iiIii1 , None )
   iIIi . print_record ( "    " )
   if 14 - 14: I1IiiI - i11iIiiIii . O0 % OOooOOo . Ii1I
   if 46 - 46: II111iiii . i1IIi - i11iIiiIii + I11i - I1Ii111
   if 6 - 6: ooOoO0o / Ii1I / iIii1I11I1II1 - IiII - ooOoO0o
   if 7 - 7: OoOoOO00 + i1IIi % ooOoO0o * I11i + i11iIiiIii / II111iiii
   Ii1iI11I1ii1i = False
   for iiiI1I in O0000oo0Oo :
    if ( iiiI1I . rloc . is_exact_match ( iIIi . rloc ) ) :
     Ii1iI11I1ii1i = True
     break
     if 2 - 2: O0 / o0oOOo0O0Ooo - OoO0O00 * II111iiii
     if 4 - 4: I1IiiI + Oo0Ooo . iIii1I11I1II1
   if ( Ii1iI11I1ii1i ) :
    IIIi1iI1 = copy . deepcopy ( iiiI1I )
    OOOOO0OO00OOO += 1
   else :
    IIIi1iI1 = lisp_rloc ( )
    O00o0OoO0OOOo += 1
    if 100 - 100: i11iIiiIii
    if 21 - 21: OoOoOO00 + iII111i . OoO0O00
    if 79 - 79: i11iIiiIii - OoO0O00 * OoO0O00 * i1IIi / iIii1I11I1II1 + iII111i
    if 27 - 27: iII111i / Ii1I / iII111i + OoooooooOO - O0 + OoO0O00
    if 62 - 62: iIii1I11I1II1
   IIIi1iI1 . store_rloc_from_record ( iIIi , None , ooOoOO0Oo . mapping_source )
   ooOoOO0Oo . rloc_set . append ( IIIi1iI1 )
   if 60 - 60: Oo0Ooo % IiII % OoO0O00 - i11iIiiIii
   if 53 - 53: i11iIiiIii + OoooooooOO
  lprint ( "Update {} map-cache entry with {}/{} new/replaced RLOCs" . format ( green ( iIiI1I1ii1I1 , False ) , O00o0OoO0OOOo , OOOOO0OO00OOO ) )
  if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
  if 79 - 79: II111iiii / OoooooooOO
  if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
  if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
  if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
  ooOoOO0Oo . build_best_rloc_set ( )
  lisp_write_ipc_map_cache ( True , ooOoOO0Oo )
  if 17 - 17: I1Ii111
  if 2 - 2: O0 % OoOoOO00 + oO0o
  if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
  if 51 - 51: IiII
  if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
  if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
 I1Ii11IIiiI = lisp_get_map_server ( source )
 if ( I1Ii11IIiiI == None ) :
  lprint ( "Cannot find Map-Server for Map-Notify source address {}" . format ( source . print_address_no_iid ( ) ) )
  if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
  return
  if 95 - 95: O0 - OoOoOO00
 lisp_send_map_notify_ack ( lisp_sockets , iiIii1 , ii11i1IiI , I1Ii11IIiiI )
 if 68 - 68: ooOoO0o . I1Ii111
 if 84 - 84: OoooooooOO + oO0o % i1IIi + o0oOOo0O0Ooo * i1IIi
 if 51 - 51: oO0o . OoooooooOO + OOooOOo * I1ii11iIi11i - ooOoO0o
 if 41 - 41: Oo0Ooo
 if 46 - 46: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii . iII111i
 if 66 - 66: oO0o % i1IIi % OoooooooOO
 if 58 - 58: OOooOOo
 if 89 - 89: iIii1I11I1II1 - i1IIi
 if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
 if 9 - 9: I1Ii111 / II111iiii * I1Ii111 / I11i - OoO0O00
def lisp_process_multicast_map_notify ( packet , source ) :
 ii11i1IiI = lisp_map_notify ( "" )
 packet = ii11i1IiI . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 36 - 36: IiII . OoOoOO00 . Ii1I
  if 31 - 31: iIii1I11I1II1
 ii11i1IiI . print_notify ( )
 if ( ii11i1IiI . record_count == 0 ) : return
 if 84 - 84: I1ii11iIi11i - iII111i * I1IiiI
 iiIii1 = ii11i1IiI . eid_records
 if 88 - 88: OOooOOo / Oo0Ooo
 for OoOOoO0oOo in range ( ii11i1IiI . record_count ) :
  oOO0O0o0oOooO = lisp_eid_record ( )
  iiIii1 = oOO0O0o0oOooO . decode ( iiIii1 )
  if ( packet == None ) : return
  oOO0O0o0oOooO . print_record ( "  " , False )
  if 31 - 31: II111iiii
  if 32 - 32: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 67 - 67: IiII + oO0o * IiII
  if 26 - 26: I1ii11iIi11i + i1IIi . i1IIi - oO0o + I1IiiI * o0oOOo0O0Ooo
  ooOoOO0Oo = lisp_map_cache_lookup ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group )
  if ( ooOoOO0Oo == None ) :
   o00000o , Ii1i1I1Ii , I1iI1 = lisp_allow_gleaning ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group ,
 None )
   if ( o00000o == False ) : continue
   if 16 - 16: I1IiiI . Ii1I
   ooOoOO0Oo = lisp_mapping ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group , [ ] )
   ooOoOO0Oo . add_cache ( )
   if 80 - 80: OOooOOo * O0 / iIii1I11I1II1 / IiII / OoOoOO00
   if 15 - 15: I1ii11iIi11i * iII111i + i11iIiiIii
   if 68 - 68: i1IIi / oO0o * I1ii11iIi11i - OoOoOO00 + Oo0Ooo / O0
   if 1 - 1: ooOoO0o - Oo0Ooo + I1Ii111
   if 90 - 90: I1Ii111 * O0 . iII111i - Oo0Ooo % iIii1I11I1II1
   if 7 - 7: I1ii11iIi11i % o0oOOo0O0Ooo % O0 % iIii1I11I1II1
   if 10 - 10: OoooooooOO - iII111i . i1IIi % oO0o . OoooooooOO + OOooOOo
  if ( ooOoOO0Oo . gleaned ) :
   lprint ( "Ignore Map-Notify for gleaned {}" . format ( green ( ooOoOO0Oo . print_eid_tuple ( ) , False ) ) )
   if 59 - 59: I1IiiI * OoooooooOO % OOooOOo / I11i
   continue
   if 77 - 77: II111iiii - IiII % OOooOOo
   if 22 - 22: OoooooooOO / oO0o
  ooOoOO0Oo . mapping_source = None if source == "lisp-etr" else source
  ooOoOO0Oo . map_cache_ttl = oOO0O0o0oOooO . store_ttl ( )
  if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
  if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
  if 12 - 12: I1Ii111
  if 17 - 17: I1Ii111 % oO0o + O0
  if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
  if ( len ( ooOoOO0Oo . rloc_set ) != 0 and oOO0O0o0oOooO . rloc_count == 0 ) :
   ooOoOO0Oo . rloc_set = [ ]
   ooOoOO0Oo . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , ooOoOO0Oo )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( ooOoOO0Oo . print_eid_tuple ( ) , False ) ) )
   if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
   continue
   if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
   if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
  iIiI1III = ooOoOO0Oo . rtrs_in_rloc_set ( )
  if 86 - 86: Ii1I - o0oOOo0O0Ooo % iII111i
  if 37 - 37: Oo0Ooo
  if 87 - 87: I1ii11iIi11i . OoooooooOO . ooOoO0o + iIii1I11I1II1 + O0 % I1ii11iIi11i
  if 53 - 53: IiII
  if 96 - 96: Oo0Ooo . i11iIiiIii / Ii1I . I1ii11iIi11i % I1Ii111
  for O0O0Oo in range ( oOO0O0o0oOooO . rloc_count ) :
   iIIi = lisp_rloc_record ( )
   iiIii1 = iIIi . decode ( iiIii1 , None )
   iIIi . print_record ( "    " )
   if ( oOO0O0o0oOooO . group . is_null ( ) ) : continue
   if ( iIIi . rle == None ) : continue
   if 68 - 68: ooOoO0o
   if 58 - 58: iII111i * I1IiiI
   if 82 - 82: Oo0Ooo / OoO0O00 % Oo0Ooo . ooOoO0o * O0
   if 39 - 39: I1Ii111 * IiII
   if 16 - 16: ooOoO0o + OoO0O00 / I11i * OoO0O00 . Oo0Ooo % OoOoOO00
   OO000 = ooOoOO0Oo . rloc_set [ 0 ] . stats if len ( ooOoOO0Oo . rloc_set ) != 0 else None
   if 30 - 30: Oo0Ooo % II111iiii % Oo0Ooo * o0oOOo0O0Ooo - Oo0Ooo
   if 23 - 23: iII111i
   if 96 - 96: oO0o . Ii1I / OoOoOO00 - O0 * iIii1I11I1II1 + Oo0Ooo
   if 35 - 35: Oo0Ooo - O0 * I11i % II111iiii % i11iIiiIii / I1IiiI
   IIIi1iI1 = lisp_rloc ( )
   IIIi1iI1 . store_rloc_from_record ( iIIi , None , ooOoOO0Oo . mapping_source )
   if ( OO000 != None ) : IIIi1iI1 . stats = copy . deepcopy ( OO000 )
   if 68 - 68: OoOoOO00 * ooOoO0o
   if ( iIiI1III and IIIi1iI1 . is_rtr ( ) == False ) : continue
   if 7 - 7: i11iIiiIii * i1IIi % I11i - IiII
   ooOoOO0Oo . rloc_set = [ IIIi1iI1 ]
   ooOoOO0Oo . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , ooOoOO0Oo )
   if 99 - 99: OoO0O00 * oO0o / Ii1I + OoO0O00
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( ooOoOO0Oo . print_eid_tuple ( ) , False ) ,
   # OoOoOO00 % I11i . oO0o * oO0o
 IIIi1iI1 . rle . print_rle ( False , True ) ) )
   if 6 - 6: Oo0Ooo / OoOoOO00 / II111iiii + IiII * o0oOOo0O0Ooo
   if 7 - 7: o0oOOo0O0Ooo * OoO0O00 - I1Ii111 % i1IIi % Ii1I
 return
 if 11 - 11: OoO0O00 - OOooOOo + I1ii11iIi11i * Oo0Ooo
 if 11 - 11: i1IIi - OoooooooOO * OoOoOO00 / oO0o - OoooooooOO - I1IiiI
 if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
 if 49 - 49: iII111i + I11i . Oo0Ooo
 if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
 if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
 if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
 if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 ii11i1IiI = lisp_map_notify ( "" )
 o0o0ooOOo0oO = ii11i1IiI . decode ( orig_packet )
 if ( o0o0ooOOo0oO == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
  if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
 ii11i1IiI . print_notify ( )
 if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
 if 1 - 1: i11iIiiIii
 if 1 - 1: iIii1I11I1II1
 if 73 - 73: iII111i + IiII
 if 95 - 95: O0
 I1iiIi111I = source . print_address ( )
 if ( ii11i1IiI . alg_id != 0 or ii11i1IiI . auth_len != 0 ) :
  I1Ii11IIiiI = None
  for OO0Oo00o0o0 in lisp_map_servers_list :
   if ( OO0Oo00o0o0 . find ( I1iiIi111I ) == - 1 ) : continue
   I1Ii11IIiiI = lisp_map_servers_list [ OO0Oo00o0o0 ]
   if 75 - 75: ooOoO0o
  if ( I1Ii11IIiiI == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( I1iiIi111I ) )
   if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
   return
   if 85 - 85: ooOoO0o
   if 29 - 29: iII111i . Ii1I
  I1Ii11IIiiI . map_notifies_received += 1
  if 43 - 43: I11i - I1ii11iIi11i + iIii1I11I1II1 / I1ii11iIi11i * oO0o / iIii1I11I1II1
  O0oO0 = lisp_verify_auth ( o0o0ooOOo0oO , ii11i1IiI . alg_id ,
 ii11i1IiI . auth_data , I1Ii11IIiiI . password )
  if 45 - 45: IiII
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if O0oO0 else "failed" ) )
  if 49 - 49: I1IiiI . Ii1I * I1IiiI - OoooooooOO . I11i / I1Ii111
  if ( O0oO0 == False ) : return
 else :
  I1Ii11IIiiI = lisp_ms ( I1iiIi111I , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 9 - 9: iIii1I11I1II1 * Ii1I / O0 - OOooOOo
  if 95 - 95: i11iIiiIii * II111iiii * OOooOOo * iIii1I11I1II1
  if 22 - 22: iIii1I11I1II1 / I1IiiI + OoOoOO00 - OOooOOo . i11iIiiIii / i11iIiiIii
  if 10 - 10: iIii1I11I1II1 % i1IIi
  if 78 - 78: I11i + II111iiii % o0oOOo0O0Ooo
  if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
 iiIii1 = ii11i1IiI . eid_records
 if ( ii11i1IiI . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , iiIii1 , ii11i1IiI , I1Ii11IIiiI )
  return
  if 44 - 44: I1ii11iIi11i
  if 39 - 39: iII111i + Oo0Ooo / oO0o
  if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
  if 99 - 99: I1IiiI * II111iiii
  if 84 - 84: II111iiii - I1IiiI
  if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
  if 35 - 35: I11i + i1IIi
  if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
 oOO0O0o0oOooO = lisp_eid_record ( )
 o0o0ooOOo0oO = oOO0O0o0oOooO . decode ( iiIii1 )
 if ( o0o0ooOOo0oO == None ) : return
 if 97 - 97: oO0o % iIii1I11I1II1
 oOO0O0o0oOooO . print_record ( "  " , False )
 if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
 for O0O0Oo in range ( oOO0O0o0oOooO . rloc_count ) :
  iIIi = lisp_rloc_record ( )
  o0o0ooOOo0oO = iIIi . decode ( o0o0ooOOo0oO , None )
  if ( o0o0ooOOo0oO == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 16 - 16: I1IiiI
  iIIi . print_record ( "    " )
  if 39 - 39: ooOoO0o * II111iiii
  if 90 - 90: OoooooooOO * ooOoO0o
  if 14 - 14: I1IiiI % i1IIi
  if 35 - 35: ooOoO0o % o0oOOo0O0Ooo % ooOoO0o
  if 77 - 77: OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
 if ( oOO0O0o0oOooO . group . is_null ( ) == False ) :
  if 55 - 55: i1IIi
  if 64 - 64: oO0o . OOooOOo * i11iIiiIii + I1Ii111
  if 88 - 88: O0
  if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
  if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( oOO0O0o0oOooO . print_eid_tuple ( ) , False ) ) )
  if 90 - 90: i11iIiiIii - iII111i * oO0o
  if 79 - 79: IiII
  Oo0O = lisp_control_packet_ipc ( orig_packet , I1iiIi111I , "lisp-itr" , 0 )
  lisp_ipc ( Oo0O , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 38 - 38: I1Ii111
  if 56 - 56: i11iIiiIii
  if 58 - 58: i11iIiiIii / OoOoOO00
  if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
  if 39 - 39: Oo0Ooo . OoO0O00
 lisp_send_map_notify_ack ( lisp_sockets , iiIii1 , ii11i1IiI , I1Ii11IIiiI )
 return
 if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
 if 100 - 100: ooOoO0o / OoooooooOO
 if 73 - 73: i11iIiiIii - Oo0Ooo
 if 100 - 100: iIii1I11I1II1 + I1Ii111
 if 51 - 51: o0oOOo0O0Ooo * I11i
 if 42 - 42: OOooOOo % I11i
 if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
 if 81 - 81: I1IiiI
def lisp_process_map_notify_ack ( packet , source ) :
 ii11i1IiI = lisp_map_notify ( "" )
 packet = ii11i1IiI . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
  if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
 ii11i1IiI . print_notify ( )
 if 83 - 83: iII111i - I1ii11iIi11i + iII111i
 if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
 if 60 - 60: I1ii11iIi11i / I1Ii111 % i11iIiiIii % oO0o % I1IiiI . Oo0Ooo
 if 20 - 20: IiII - OOooOOo + OoOoOO00
 if 83 - 83: OoooooooOO / I1IiiI + iII111i - iIii1I11I1II1 % ooOoO0o
 if ( ii11i1IiI . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 74 - 74: OoO0O00
  if 13 - 13: I1ii11iIi11i / OoO0O00
 oOO0O0o0oOooO = lisp_eid_record ( )
 if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
 if ( oOO0O0o0oOooO . decode ( ii11i1IiI . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 94 - 94: IiII * i1IIi
 oOO0O0o0oOooO . print_record ( "  " , False )
 if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
 iIiI1I1ii1I1 = oOO0O0o0oOooO . print_eid_tuple ( )
 if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
 if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
 if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
 if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
 if ( ii11i1IiI . alg_id != LISP_NONE_ALG_ID and ii11i1IiI . auth_len != 0 ) :
  iiI1I = lisp_sites_by_eid . lookup_cache ( oOO0O0o0oOooO . eid , True )
  if ( iiI1I == None ) :
   iiIIi1iI = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( iiIIi1iI , green ( iIiI1I1ii1I1 , False ) ) )
   if 32 - 32: I1IiiI + II111iiii * iII111i + O0 / O0 * Oo0Ooo
   return
   if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
  ooo0ooOO0OO = iiI1I . site
  if 66 - 66: i1IIi
  if 98 - 98: Oo0Ooo / iIii1I11I1II1
  if 33 - 33: O0 - iII111i
  if 40 - 40: iII111i * I11i
  ooo0ooOO0OO . map_notify_acks_received += 1
  if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  I1IIiiiiI1iIi = ii11i1IiI . key_id
  if ( ooo0ooOO0OO . auth_key . has_key ( I1IIiiiiI1iIi ) ) :
   i1ii1IIii = ooo0ooOO0OO . auth_key [ I1IIiiiiI1iIi ]
  else :
   i1ii1IIii = ""
   if 87 - 87: OoOoOO00
   if 30 - 30: IiII % OoOoOO00 + I1Ii111
  O0oO0 = lisp_verify_auth ( packet , ii11i1IiI . alg_id ,
 ii11i1IiI . auth_data , i1ii1IIii )
  if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
  I1IIiiiiI1iIi = "key-id {}" . format ( I1IIiiiiI1iIi ) if I1IIiiiiI1iIi == ii11i1IiI . key_id else "bad key-id {}" . format ( ii11i1IiI . key_id )
  if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
  if 87 - 87: I11i
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if O0oO0 else "failed" , I1IIiiiiI1iIi ) )
  if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
  if ( O0oO0 == False ) : return
  if 72 - 72: OoO0O00 * Oo0Ooo - IiII
  if 74 - 74: Ii1I
  if 26 - 26: I11i . O0
  if 68 - 68: Ii1I
  if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
 if ( ii11i1IiI . retransmit_timer ) : ii11i1IiI . retransmit_timer . cancel ( )
 if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
 OoO0OO0oO0ooOoO = source . print_address ( )
 OO0Oo00o0o0 = ii11i1IiI . nonce_key
 if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
 if ( lisp_map_notify_queue . has_key ( OO0Oo00o0o0 ) ) :
  ii11i1IiI = lisp_map_notify_queue . pop ( OO0Oo00o0o0 )
  if ( ii11i1IiI . retransmit_timer ) : ii11i1IiI . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( OO0Oo00o0o0 ) )
  if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( ii11i1IiI . nonce_key , red ( OoO0OO0oO0ooOoO , False ) ) )
  if 44 - 44: I11i * iIii1I11I1II1 . I1ii11iIi11i
  if 9 - 9: o0oOOo0O0Ooo
 return
 if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
 if 21 - 21: Ii1I * OoOoOO00
 if 29 - 29: iIii1I11I1II1 / ooOoO0o
 if 75 - 75: OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
 if 88 - 88: OoO0O00 % Ii1I
 if 12 - 12: OoooooooOO . O0
 if 33 - 33: OoooooooOO / I11i . II111iiii * i1IIi
 if 34 - 34: i11iIiiIii / OoOoOO00
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 100 - 100: o0oOOo0O0Ooo - I1IiiI / I11i
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 43 - 43: o0oOOo0O0Ooo % iIii1I11I1II1
 if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
 if 4 - 4: Ii1I . i1IIi + Oo0Ooo % I11i . OoO0O00
 if 70 - 70: OOooOOo * OoOoOO00 / OoOoOO00 / OoOoOO00
 ooOo000OO = False
 if ( group . is_null ( ) == False ) :
  ooOo000OO = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 23 - 23: I1IiiI
 if ( ooOo000OO == False ) :
  ooOo000OO = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 24 - 24: I1Ii111 * i1IIi % O0 * Ii1I + iII111i
  if 14 - 14: oO0o * iII111i + Ii1I + Ii1I * IiII
 if ( ooOo000OO ) :
  iiiiiiiiII1i = lisp_print_eid_tuple ( eid , group )
  O0o0O0Ooo000 = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 26 - 26: I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( iiiiiiiiII1i , False ) , s ,
  # i11iIiiIii * I1IiiI % OoooooooOO % iIii1I11I1II1 % IiII
 O0o0O0Ooo000 ) )
  if 20 - 20: ooOoO0o . O0 . Oo0Ooo . OoO0O00 / Oo0Ooo
 return ( ooOo000OO )
 if 85 - 85: o0oOOo0O0Ooo / I11i - OoOoOO00 - o0oOOo0O0Ooo
 if 99 - 99: I11i - I11i + Oo0Ooo
 if 71 - 71: IiII . I1Ii111 . oO0o
 if 30 - 30: IiII
 if 6 - 6: I1Ii111 % oO0o % I1ii11iIi11i
 if 36 - 36: IiII
 if 97 - 97: i1IIi % OoOoOO00 . Oo0Ooo - OoO0O00 - ooOoO0o
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 99 - 99: i11iIiiIii / I1Ii111 / I1IiiI * oO0o
 I1IIIiIiii1i = lisp_map_referral ( )
 packet = I1IIIiIiii1i . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 100 - 100: II111iiii * Ii1I . OoO0O00 . iII111i + i1IIi * I1IiiI
 I1IIIiIiii1i . print_map_referral ( )
 if 84 - 84: OoO0O00 + i1IIi
 I1iiIi111I = source . print_address ( )
 O0oo00o000 = I1IIIiIiii1i . nonce
 if 99 - 99: OOooOOo + o0oOOo0O0Ooo * I1Ii111 % OoooooooOO % I11i
 if 48 - 48: o0oOOo0O0Ooo / OoO0O00
 if 45 - 45: OOooOOo
 if 57 - 57: iIii1I11I1II1 + IiII - I1IiiI
 for OoOOoO0oOo in range ( I1IIIiIiii1i . record_count ) :
  oOO0O0o0oOooO = lisp_eid_record ( )
  packet = oOO0O0o0oOooO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 64 - 64: II111iiii . IiII / I1IiiI
  oOO0O0o0oOooO . print_record ( "  " , True )
  if 20 - 20: OoooooooOO - I1ii11iIi11i * I1ii11iIi11i * I1ii11iIi11i
  if 87 - 87: OoooooooOO * ooOoO0o
  if 6 - 6: I1Ii111 / ooOoO0o / OoooooooOO . iIii1I11I1II1
  if 68 - 68: OoO0O00
  OO0Oo00o0o0 = str ( O0oo00o000 )
  if ( OO0Oo00o0o0 not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( O0oo00o000 ) , I1iiIi111I ) )
   if 26 - 26: I11i % i1IIi / iIii1I11I1II1 % IiII . iII111i + I1ii11iIi11i
   if 49 - 49: O0 . IiII + I1Ii111 - I11i % II111iiii
   continue
   if 15 - 15: O0 - OoOoOO00 % II111iiii + O0 % O0 + OoOoOO00
  IIIIIii1Ii1II = lisp_ddt_map_requestQ [ OO0Oo00o0o0 ]
  if ( IIIIIii1Ii1II == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( O0oo00o000 ) , I1iiIi111I ) )
   if 34 - 34: I1Ii111
   continue
   if 69 - 69: iIii1I11I1II1 . OOooOOo % I11i
   if 28 - 28: I1Ii111 . ooOoO0o % I1IiiI
   if 62 - 62: II111iiii + ooOoO0o + I1IiiI
   if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
   if 13 - 13: I1ii11iIi11i
   if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
  if ( lisp_map_referral_loop ( IIIIIii1Ii1II , oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group ,
 oOO0O0o0oOooO . action , I1iiIi111I ) ) :
   IIIIIii1Ii1II . dequeue_map_request ( )
   continue
   if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
   if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
  IIIIIii1Ii1II . last_cached_prefix [ 0 ] = oOO0O0o0oOooO . eid
  IIIIIii1Ii1II . last_cached_prefix [ 1 ] = oOO0O0o0oOooO . group
  if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
  if 18 - 18: OoooooooOO - I1ii11iIi11i
  if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
  if 79 - 79: OOooOOo + Oo0Ooo
  IiIii1i = False
  o0OOo0 = lisp_referral_cache_lookup ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group ,
 True )
  if ( o0OOo0 == None ) :
   IiIii1i = True
   o0OOo0 = lisp_referral ( )
   o0OOo0 . eid = oOO0O0o0oOooO . eid
   o0OOo0 . group = oOO0O0o0oOooO . group
   if ( oOO0O0o0oOooO . ddt_incomplete == False ) : o0OOo0 . add_cache ( )
  elif ( o0OOo0 . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( o0OOo0 . print_eid_tuple ( ) , False ) ) )
   if 33 - 33: iIii1I11I1II1
   IIIIIii1Ii1II . dequeue_map_request ( )
   continue
   if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
   if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
  iiIIiI = oOO0O0o0oOooO . action
  o0OOo0 . referral_source = source
  o0OOo0 . referral_type = iiIIiI
  O0OOo = oOO0O0o0oOooO . store_ttl ( )
  o0OOo0 . referral_ttl = O0OOo
  o0OOo0 . expires = lisp_set_timestamp ( O0OOo )
  if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
  if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
  if 99 - 99: OOooOOo
  if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
  OOOoO = o0OOo0 . is_referral_negative ( )
  if ( o0OOo0 . referral_set . has_key ( I1iiIi111I ) ) :
   iIiIIIiiIi = o0OOo0 . referral_set [ I1iiIi111I ]
   if 39 - 39: IiII / oO0o % Ii1I
   if ( iIiIIIiiIi . updown == False and OOOoO == False ) :
    iIiIIIiiIi . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( I1iiIi111I ) )
    if 62 - 62: I11i - o0oOOo0O0Ooo
   elif ( iIiIIIiiIi . updown == True and OOOoO == True ) :
    iIiIIIiiIi . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( I1iiIi111I ) )
    if 82 - 82: I11i / I1ii11iIi11i + I1IiiI - iIii1I11I1II1
    if 45 - 45: ooOoO0o % ooOoO0o . I11i + i1IIi
    if 4 - 4: iII111i - i1IIi - OoOoOO00 - Oo0Ooo % iIii1I11I1II1
    if 61 - 61: I1Ii111
    if 26 - 26: OOooOOo + I1Ii111 * I1Ii111 / I11i % Oo0Ooo . OoooooooOO
    if 72 - 72: OoooooooOO - O0 . OoO0O00
    if 46 - 46: o0oOOo0O0Ooo % OoO0O00 + I11i % o0oOOo0O0Ooo + oO0o . Oo0Ooo
    if 58 - 58: I1Ii111 + I1ii11iIi11i
  o0o0oo = { }
  for OO0Oo00o0o0 in o0OOo0 . referral_set : o0o0oo [ OO0Oo00o0o0 ] = None
  if 39 - 39: i1IIi
  if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
  if 59 - 59: i1IIi
  if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
  for OoOOoO0oOo in range ( oOO0O0o0oOooO . rloc_count ) :
   iIIi = lisp_rloc_record ( )
   packet = iIIi . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
   iIIi . print_record ( "    " )
   if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
   if 71 - 71: OOooOOo
   if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
   if 73 - 73: iII111i / I1IiiI * ooOoO0o
   O0O0 = iIIi . rloc . print_address ( )
   if ( o0OOo0 . referral_set . has_key ( O0O0 ) == False ) :
    iIiIIIiiIi = lisp_referral_node ( )
    iIiIIIiiIi . referral_address . copy_address ( iIIi . rloc )
    o0OOo0 . referral_set [ O0O0 ] = iIiIIIiiIi
    if ( I1iiIi111I == O0O0 and OOOoO ) : iIiIIIiiIi . updown = False
   else :
    iIiIIIiiIi = o0OOo0 . referral_set [ O0O0 ]
    if ( o0o0oo . has_key ( O0O0 ) ) : o0o0oo . pop ( O0O0 )
    if 85 - 85: I11i + I11i + oO0o - OoOoOO00
   iIiIIIiiIi . priority = iIIi . priority
   iIiIIIiiIi . weight = iIIi . weight
   if 15 - 15: OoO0O00
   if 88 - 88: Ii1I % i1IIi / I1Ii111
   if 2 - 2: Ii1I . IiII % OoOoOO00
   if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
   if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
  for OO0Oo00o0o0 in o0o0oo : o0OOo0 . referral_set . pop ( OO0Oo00o0o0 )
  if 35 - 35: i11iIiiIii
  iIiI1I1ii1I1 = o0OOo0 . print_eid_tuple ( )
  if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
  if ( IiIii1i ) :
   if ( oOO0O0o0oOooO . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( iIiI1I1ii1I1 , False ) ) )
    if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( iIiI1I1ii1I1 , False ) , oOO0O0o0oOooO . rloc_count ) )
    if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
    if 59 - 59: i11iIiiIii . OOooOOo % Oo0Ooo + O0
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( iIiI1I1ii1I1 , False ) , oOO0O0o0oOooO . rloc_count ) )
   if 84 - 84: I1Ii111 / O0 - IiII . I11i / o0oOOo0O0Ooo
   if 12 - 12: i11iIiiIii / Ii1I + i1IIi
   if 54 - 54: I1IiiI
   if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
   if 37 - 37: Oo0Ooo
   if 33 - 33: OoooooooOO - O0 . O0 - o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoO0O00
  if ( iiIIiI == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( IIIIIii1Ii1II . lisp_sockets , o0OOo0 . eid ,
 o0OOo0 . group , IIIIIii1Ii1II . nonce , IIIIIii1Ii1II . itr , IIIIIii1Ii1II . sport , 15 , None , False )
   IIIIIii1Ii1II . dequeue_map_request ( )
   if 27 - 27: ooOoO0o . i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 * OoOoOO00 * oO0o
   if 19 - 19: O0 * II111iiii * OoOoOO00
  if ( iiIIiI == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( IIIIIii1Ii1II . tried_root ) :
    lisp_send_negative_map_reply ( IIIIIii1Ii1II . lisp_sockets , o0OOo0 . eid ,
 o0OOo0 . group , IIIIIii1Ii1II . nonce , IIIIIii1Ii1II . itr , IIIIIii1Ii1II . sport , 0 , None , False )
    IIIIIii1Ii1II . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( IIIIIii1Ii1II , True )
    if 53 - 53: Oo0Ooo
    if 16 - 16: Ii1I
    if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
  if ( iiIIiI == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( o0OOo0 . referral_set . has_key ( I1iiIi111I ) ) :
    iIiIIIiiIi = o0OOo0 . referral_set [ I1iiIi111I ]
    iIiIIIiiIi . updown = False
    if 78 - 78: OoO0O00 + oO0o
   if ( len ( o0OOo0 . referral_set ) == 0 ) :
    IIIIIii1Ii1II . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( IIIIIii1Ii1II , False )
    if 86 - 86: ooOoO0o . ooOoO0o + oO0o
    if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
    if 31 - 31: IiII + iII111i
  if ( iiIIiI in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( IIIIIii1Ii1II . eid . is_exact_match ( oOO0O0o0oOooO . eid ) ) :
    if ( not IIIIIii1Ii1II . tried_root ) :
     lisp_send_ddt_map_request ( IIIIIii1Ii1II , True )
    else :
     lisp_send_negative_map_reply ( IIIIIii1Ii1II . lisp_sockets ,
 o0OOo0 . eid , o0OOo0 . group , IIIIIii1Ii1II . nonce , IIIIIii1Ii1II . itr ,
 IIIIIii1Ii1II . sport , 15 , None , False )
     IIIIIii1Ii1II . dequeue_map_request ( )
     if 5 - 5: O0 * Ii1I
   else :
    lisp_send_ddt_map_request ( IIIIIii1Ii1II , False )
    if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
    if 77 - 77: OOooOOo / OoooooooOO
    if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
  if ( iiIIiI == LISP_DDT_ACTION_MS_ACK ) : IIIIIii1Ii1II . dequeue_map_request ( )
  if 79 - 79: i11iIiiIii % o0oOOo0O0Ooo * II111iiii . i1IIi * Ii1I - i11iIiiIii
 return
 if 31 - 31: IiII / o0oOOo0O0Ooo
 if 27 - 27: Oo0Ooo
 if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
 if 35 - 35: o0oOOo0O0Ooo % iII111i / O0 * I1IiiI . o0oOOo0O0Ooo / OOooOOo
 if 81 - 81: I1ii11iIi11i - i11iIiiIii
 if 49 - 49: iII111i * I11i - II111iiii . o0oOOo0O0Ooo
 if 52 - 52: Ii1I + Ii1I - II111iiii . O0 + I1ii11iIi11i
 if 60 - 60: i11iIiiIii + IiII
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 I11IIi11Iii1 = lisp_ecm ( 0 )
 packet = I11IIi11Iii1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
  if 86 - 86: Ii1I / oO0o
 I11IIi11Iii1 . print_ecm ( )
 if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
 OoOOoo0o00O0oO = lisp_control_header ( )
 if ( OoOOoo0o00O0oO . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 60 - 60: II111iiii / Ii1I
  if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
 OoO0 = OoOOoo0o00O0oO . type
 del ( OoOOoo0o00O0oO )
 if 66 - 66: OOooOOo / OoooooooOO . OoooooooOO % iII111i + I1Ii111
 if ( OoO0 != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 90 - 90: o0oOOo0O0Ooo
  if 48 - 48: iII111i + Ii1I
  if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
  if 89 - 89: OOooOOo - I1Ii111 - iII111i
  if 67 - 67: oO0o
 OoOoo0oOOO = I11IIi11Iii1 . udp_sport
 iIIiiIiI = time . time ( )
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 I11IIi11Iii1 . source , OoOoo0oOOO , I11IIi11Iii1 . ddt , - 1 , iIIiiIiI )
 return
 if 75 - 75: OoOoOO00 + iII111i - Oo0Ooo
 if 51 - 51: iIii1I11I1II1 / iIii1I11I1II1
 if 51 - 51: I1IiiI / I1Ii111 - iIii1I11I1II1 . I1Ii111
 if 52 - 52: II111iiii / OoO0O00 . Ii1I
 if 68 - 68: iII111i
 if 67 - 67: I1IiiI * I1IiiI
 if 100 - 100: iII111i * iII111i . Oo0Ooo
 if 10 - 10: Oo0Ooo % ooOoO0o * Oo0Ooo
 if 48 - 48: ooOoO0o + II111iiii
 if 73 - 73: II111iiii
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
 if 35 - 35: II111iiii + IiII
 if 66 - 66: o0oOOo0O0Ooo % IiII
 if 39 - 39: IiII
 if 18 - 18: iII111i % o0oOOo0O0Ooo - i1IIi
 if 53 - 53: o0oOOo0O0Ooo + IiII - ooOoO0o % i11iIiiIii - i11iIiiIii - I1Ii111
 if 79 - 79: II111iiii + i11iIiiIii . OOooOOo . I11i / iIii1I11I1II1
 OO0oooOO = ms . map_server
 if ( lisp_decent_push_configured and OO0oooOO . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  OO0oooOO = copy . deepcopy ( OO0oooOO )
  OO0oooOO . address = 0x7f000001
  ooOo0O0O0oOO0 = bold ( "Bootstrap" , False )
  OoIi1I1I = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( ooOo0O0O0oOO0 , OoIi1I1I ) )
  if 62 - 62: O0
  if 52 - 52: OoooooooOO . oO0o
  if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
  if 21 - 21: i11iIiiIii + II111iiii - i1IIi / OoooooooOO * OOooOOo % Oo0Ooo
  if 59 - 59: Ii1I
  if 77 - 77: I1ii11iIi11i * Ii1I * O0 * I1IiiI % OoO0O00 - iIii1I11I1II1
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 6 - 6: i11iIiiIii . I11i - OoooooooOO
 if 26 - 26: I1IiiI
 if 26 - 26: IiII . Ii1I / IiII - OoO0O00 % OoO0O00
 if 72 - 72: OoooooooOO * II111iiii + OoO0O00 % iIii1I11I1II1 . I1ii11iIi11i % OoooooooOO
 if 19 - 19: OoOoOO00 + I1Ii111
 if 19 - 19: I1ii11iIi11i / I1Ii111 + OoooooooOO - O0
 if ( ms . ekey != None ) :
  OooOo0o = ms . ekey . zfill ( 32 )
  OoOooO = "0" * 8
  iiIi = chacha . ChaCha ( OooOo0o , OoOooO , 20 ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + iiIi
  I1i = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( I1i , ms . ekey_id ) )
  if 49 - 49: I1ii11iIi11i / OoOoOO00 - I1IiiI + iII111i . OOooOOo % oO0o
  if 34 - 34: OoO0O00 - I1IiiI + OoOoOO00
 Iii1IIi11ii1i = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  Iii1IIi11ii1i = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 80 - 80: I1IiiI % Ii1I
  if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( OO0oooOO . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , Iii1IIi11ii1i ) )
 if 38 - 38: IiII . I1Ii111
 lisp_send ( lisp_sockets , OO0oooOO , LISP_CTRL_PORT , packet )
 return
 if 69 - 69: ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + Ii1I . ooOoO0o
 if 73 - 73: I11i % I11i . ooOoO0o + OoOoOO00
 if 33 - 33: i11iIiiIii . i11iIiiIii * i11iIiiIii / iIii1I11I1II1 / I1ii11iIi11i . ooOoO0o
 if 11 - 11: iII111i
 if 60 - 60: I1ii11iIi11i / I1Ii111
 if 10 - 10: OoO0O00 * iIii1I11I1II1 / I11i % II111iiii . OoOoOO00 / I1IiiI
 if 4 - 4: Oo0Ooo * o0oOOo0O0Ooo
 if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 iIiI111ii1Ii = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 69 - 69: iII111i % I1ii11iIi11i
 if 19 - 19: IiII
 packet = lisp_control_packet_ipc ( packet , iIiI111ii1Ii , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 35 - 35: OoOoOO00
 if 18 - 18: II111iiii . OoOoOO00 + I1ii11iIi11i * oO0o + OoooooooOO
 if 39 - 39: I1IiiI * ooOoO0o / i11iIiiIii - oO0o - oO0o + O0
 if 73 - 73: OOooOOo
 if 44 - 44: I1ii11iIi11i * i1IIi - iIii1I11I1II1 - oO0o - oO0o * II111iiii
 if 98 - 98: Oo0Ooo + ooOoO0o / OOooOOo . iIii1I11I1II1 . I1IiiI . OoOoOO00
 if 92 - 92: i1IIi + OoOoOO00 * i1IIi / IiII
 if 4 - 4: oO0o % OoO0O00 + IiII + o0oOOo0O0Ooo
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 82 - 82: O0 / I1Ii111 + OOooOOo . IiII + Ii1I
 if 31 - 31: i1IIi * OoO0O00 - Ii1I + I11i
 if 8 - 8: O0 + i1IIi . O0
 if 67 - 67: I1IiiI
 if 42 - 42: ooOoO0o - o0oOOo0O0Ooo % oO0o - ooOoO0o
 if 87 - 87: OoooooooOO / O0
 if 57 - 57: iIii1I11I1II1 / IiII + OoO0O00 * oO0o + Ii1I
 if 76 - 76: i11iIiiIii . OOooOOo / I11i * oO0o % iIii1I11I1II1 . ooOoO0o
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 75 - 75: O0 + I1IiiI
 if 67 - 67: OoOoOO00 % OoooooooOO / OoO0O00 - OoO0O00 / O0
 if 19 - 19: iIii1I11I1II1 / OOooOOo % I11i % I1IiiI / I1ii11iIi11i
 if 73 - 73: II111iiii
 if 26 - 26: II111iiii . iIii1I11I1II1 - I1Ii111 % OOooOOo
 if 83 - 83: OOooOOo + OoooooooOO % I1Ii111 % IiII + i11iIiiIii
 if 10 - 10: OoooooooOO . Ii1I % I1Ii111 + IiII
 if 78 - 78: OoOoOO00 - oO0o . I1ii11iIi11i * i11iIiiIii
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 44 - 44: iIii1I11I1II1 * iII111i
 if 32 - 32: OoOoOO00
 if 65 - 65: iIii1I11I1II1 + iII111i
 if 90 - 90: i11iIiiIii - Oo0Ooo
 if 31 - 31: OoOoOO00 + OoOoOO00 + OoooooooOO % O0
 if 14 - 14: i1IIi / OoooooooOO . I1IiiI * I1Ii111 + OoO0O00
 if 45 - 45: OoooooooOO * I1Ii111
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 7 - 7: O0
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 42 - 42: o0oOOo0O0Ooo / Ii1I
  if 31 - 31: OOooOOo
  if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
  if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
  if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
  if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
 if ( lisp_nat_traversal ) :
  IiIi = lisp_get_any_translated_port ( )
  if ( IiIi != None ) : inner_sport = IiIi
  if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
 I11IIi11Iii1 = lisp_ecm ( inner_sport )
 if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
 I11IIi11Iii1 . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 I11IIi11Iii1 . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 I11IIi11Iii1 . ddt = ddt
 oo = I11IIi11Iii1 . encode ( packet , inner_source , inner_dest )
 if ( oo == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 98 - 98: I1Ii111 . i11iIiiIii * iIii1I11I1II1 + oO0o
 I11IIi11Iii1 . print_ecm ( )
 if 96 - 96: II111iiii - OOooOOo * I1Ii111 . oO0o
 packet = oo + packet
 if 21 - 21: OoooooooOO * I11i * IiII / II111iiii * II111iiii / Oo0Ooo
 O0O0 = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( O0O0 ) )
 OO0oooOO = lisp_convert_4to6 ( O0O0 )
 lisp_send ( lisp_sockets , OO0oooOO , LISP_CTRL_PORT , packet )
 return
 if 42 - 42: oO0o % OOooOOo + oO0o + I1Ii111
 if 39 - 39: i11iIiiIii % OOooOOo % iIii1I11I1II1 / oO0o
 if 57 - 57: I1Ii111 % iII111i % oO0o . IiII + iIii1I11I1II1
 if 57 - 57: IiII
 if 29 - 29: o0oOOo0O0Ooo
 if 12 - 12: ooOoO0o + I11i * o0oOOo0O0Ooo % I1IiiI - OOooOOo
 if 40 - 40: OoooooooOO - o0oOOo0O0Ooo . I11i - Ii1I . Ii1I
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
if 57 - 57: I1Ii111 . oO0o - OoooooooOO
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 74 - 74: I1ii11iIi11i + o0oOOo0O0Ooo * i11iIiiIii % OoooooooOO - IiII % i1IIi
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 74 - 74: iII111i % I11i * i11iIiiIii . i11iIiiIii + iIii1I11I1II1 * i1IIi
if 53 - 53: I1ii11iIi11i + IiII / OOooOOo . OoooooooOO - ooOoO0o
if 47 - 47: i11iIiiIii
if 21 - 21: i1IIi - oO0o - Oo0Ooo
if 11 - 11: i1IIi
if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 56 - 56: Ii1I . iII111i
if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
if 52 - 52: i11iIiiIii
if 1 - 1: i1IIi * iIii1I11I1II1
if 29 - 29: I11i
def byte_swap_64 ( address ) :
 IiIIiiI = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
 if 6 - 6: IiII / OoO0O00
 if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
 if 77 - 77: Ii1I
 if 9 - 9: OOooOOo / OoooooooOO + iII111i
 if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
 if 20 - 20: I1Ii111
 if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
 return ( IiIIiiI )
 if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
 if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
 if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
 if 56 - 56: iII111i * II111iiii . OoooooooOO . I11i
 if 25 - 25: ooOoO0o % o0oOOo0O0Ooo - i11iIiiIii
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
class lisp_cache_entries ( ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 42 - 42: I1Ii111 - ooOoO0o % o0oOOo0O0Ooo * I1IiiI . o0oOOo0O0Ooo
  if 84 - 84: iIii1I11I1II1
  if 39 - 39: Ii1I . II111iiii / I1IiiI
class lisp_cache ( ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 44 - 44: Ii1I / Ii1I / OoO0O00 % ooOoO0o / I11i . I1ii11iIi11i
  if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
 def cache_size ( self ) :
  return ( self . cache_count )
  if 81 - 81: I1Ii111 % OoO0O00 / O0
  if 55 - 55: i1IIi - I1Ii111 + I11i
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   Iii1iii1II = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   Iii1iii1II = prefix . mask_len
  else :
   Iii1iii1II = prefix . mask_len + 48
   if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
   if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
  i1 = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  i1I1iiiI = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    i1iIii = prefix . addr_length ( ) * 2
    IiIIiiI = lisp_hex_string ( prefix . address ) . zfill ( i1iIii )
   else :
    IiIIiiI = prefix . address
    if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   i1I1iiiI = "8003"
   IiIIiiI = prefix . address . print_geo ( )
  else :
   i1I1iiiI = ""
   IiIIiiI = ""
   if 34 - 34: I1IiiI + I1Ii111 % ooOoO0o
   if 24 - 24: Ii1I % II111iiii - i11iIiiIii
  OO0Oo00o0o0 = i1 + i1I1iiiI + IiIIiiI
  return ( [ Iii1iii1II , OO0Oo00o0o0 ] )
  if 52 - 52: OoO0O00
  if 76 - 76: ooOoO0o - iII111i % ooOoO0o / oO0o . OOooOOo
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  Iii1iii1II , OO0Oo00o0o0 = self . build_key ( prefix )
  if ( self . cache . has_key ( Iii1iii1II ) == False ) :
   self . cache [ Iii1iii1II ] = lisp_cache_entries ( )
   self . cache_sorted = self . sort_in_entry ( self . cache_sorted , Iii1iii1II )
   if 50 - 50: IiII . i11iIiiIii % I11i
  if ( self . cache [ Iii1iii1II ] . entries . has_key ( OO0Oo00o0o0 ) == False ) :
   self . cache_count += 1
   if 22 - 22: i1IIi - II111iiii - OoOoOO00 . iII111i
  self . cache [ Iii1iii1II ] . entries [ OO0Oo00o0o0 ] = entry
  if 43 - 43: I1Ii111 * OOooOOo - IiII . i11iIiiIii
  if 34 - 34: iII111i . OoOoOO00
 def lookup_cache ( self , prefix , exact ) :
  IIIIi11IiiI , OO0Oo00o0o0 = self . build_key ( prefix )
  if ( exact ) :
   if ( self . cache . has_key ( IIIIi11IiiI ) == False ) : return ( None )
   if ( self . cache [ IIIIi11IiiI ] . entries . has_key ( OO0Oo00o0o0 ) == False ) : return ( None )
   return ( self . cache [ IIIIi11IiiI ] . entries [ OO0Oo00o0o0 ] )
   if 7 - 7: iIii1I11I1II1 - Ii1I % II111iiii + Ii1I
   if 19 - 19: I1ii11iIi11i
  Ii1iI11I1ii1i = None
  for Iii1iii1II in self . cache_sorted :
   if ( IIIIi11IiiI < Iii1iii1II ) : return ( Ii1iI11I1ii1i )
   for oOOoO0oO0oo0O in self . cache [ Iii1iii1II ] . entries . values ( ) :
    if ( prefix . is_more_specific ( oOOoO0oO0oo0O . eid ) ) :
     if ( Ii1iI11I1ii1i == None or
 oOOoO0oO0oo0O . eid . is_more_specific ( Ii1iI11I1ii1i . eid ) ) : Ii1iI11I1ii1i = oOOoO0oO0oo0O
     if 95 - 95: I11i
     if 39 - 39: IiII * I11i + I1IiiI
     if 60 - 60: I11i % Ii1I * oO0o % II111iiii + o0oOOo0O0Ooo
  return ( Ii1iI11I1ii1i )
  if 62 - 62: O0 - O0 - I1IiiI . OoO0O00 . i11iIiiIii % i11iIiiIii
  if 54 - 54: I1IiiI + OoooooooOO / iII111i / I11i . I11i % I11i
 def delete_cache ( self , prefix ) :
  Iii1iii1II , OO0Oo00o0o0 = self . build_key ( prefix )
  if ( self . cache . has_key ( Iii1iii1II ) == False ) : return
  if ( self . cache [ Iii1iii1II ] . entries . has_key ( OO0Oo00o0o0 ) == False ) : return
  self . cache [ Iii1iii1II ] . entries . pop ( OO0Oo00o0o0 )
  self . cache_count -= 1
  if 54 - 54: OoO0O00 * I11i * iIii1I11I1II1 * IiII
  if 12 - 12: O0 - iII111i * IiII . i11iIiiIii
 def walk_cache ( self , function , parms ) :
  for Iii1iii1II in self . cache_sorted :
   for oOOoO0oO0oo0O in self . cache [ Iii1iii1II ] . entries . values ( ) :
    I11i11I1i1i , parms = function ( oOOoO0oO0oo0O , parms )
    if ( I11i11I1i1i == False ) : return ( parms )
    if 40 - 40: OOooOOo - OoooooooOO
    if 36 - 36: i1IIi % OoOoOO00 - i1IIi
  return ( parms )
  if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
  if 97 - 97: I11i . ooOoO0o
 def sort_in_entry ( self , table , value ) :
  if ( table == [ ] ) : return ( [ value ] )
  if 87 - 87: oO0o / iIii1I11I1II1 - I11i + OoooooooOO
  I11iI1I = table
  while ( True ) :
   if ( len ( I11iI1I ) == 1 ) :
    if ( value == I11iI1I [ 0 ] ) : return ( table )
    I1i11II = table . index ( I11iI1I [ 0 ] )
    if ( value < I11iI1I [ 0 ] ) :
     return ( table [ 0 : I1i11II ] + [ value ] + table [ I1i11II : : ] )
     if 79 - 79: I1ii11iIi11i * IiII . I1ii11iIi11i
    if ( value > I11iI1I [ 0 ] ) :
     return ( table [ 0 : I1i11II + 1 ] + [ value ] + table [ I1i11II + 1 : : ] )
     if 65 - 65: iII111i - Ii1I - II111iiii * O0 + I1ii11iIi11i . iIii1I11I1II1
     if 76 - 76: OoO0O00 * ooOoO0o
   I1i11II = len ( I11iI1I ) / 2
   I11iI1I = I11iI1I [ 0 : I1i11II ] if ( value < I11iI1I [ I1i11II ] ) else I11iI1I [ I1i11II : : ]
   if 32 - 32: O0 . oO0o * o0oOOo0O0Ooo . Ii1I + IiII
   if 98 - 98: iII111i . II111iiii % O0
  return ( [ ] )
  if 43 - 43: OOooOOo % I1Ii111 . IiII % OoO0O00 + I1Ii111 % OoooooooOO
  if 17 - 17: OoooooooOO - i1IIi * I11i
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 33 - 33: i1IIi . Oo0Ooo + I11i
  for Iii1iii1II in self . cache_sorted :
   for OO0Oo00o0o0 in self . cache [ Iii1iii1II ] . entries :
    oOOoO0oO0oo0O = self . cache [ Iii1iii1II ] . entries [ OO0Oo00o0o0 ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( Iii1iii1II , OO0Oo00o0o0 ,
 oOOoO0oO0oo0O ) )
    if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
    if 78 - 78: I1Ii111 + I1Ii111
    if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
    if 19 - 19: Ii1I
    if 51 - 51: oO0o
    if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
    if 35 - 35: o0oOOo0O0Ooo % II111iiii + O0
    if 70 - 70: I1ii11iIi11i . II111iiii
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 54 - 54: OOooOOo
if 67 - 67: I1IiiI . o0oOOo0O0Ooo / i1IIi * I1ii11iIi11i . Oo0Ooo + II111iiii
if 63 - 63: OoOoOO00 - OoOoOO00
if 31 - 31: I1ii11iIi11i % O0 - i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o * ooOoO0o
if 18 - 18: OoO0O00 - OoO0O00 . o0oOOo0O0Ooo
if 80 - 80: I11i + I1Ii111 / I1IiiI * OOooOOo % iII111i
if 48 - 48: iIii1I11I1II1 + i1IIi . I1IiiI % OoO0O00 - iIii1I11I1II1 / i1IIi
def lisp_map_cache_lookup ( source , dest ) :
 if 14 - 14: IiII . I11i
 o0OooO = dest . is_multicast_address ( )
 if 13 - 13: OoOoOO00 - I11i . OOooOOo % OoO0O00
 if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
 if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
 if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
 ooOoOO0Oo = lisp_map_cache . lookup_cache ( dest , False )
 if ( ooOoOO0Oo == None ) :
  iIiI1I1ii1I1 = source . print_sg ( dest ) if o0OooO else dest . print_address ( )
  iIiI1I1ii1I1 = green ( iIiI1I1ii1I1 , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( iIiI1I1ii1I1 ) )
  return ( None )
  if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
  if 9 - 9: iIii1I11I1II1
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
  if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
 if ( o0OooO == False ) :
  i1i1I11I1I = green ( ooOoOO0Oo . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , i1i1I11I1I ) )
  if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
  return ( ooOoOO0Oo )
  if 34 - 34: iIii1I11I1II1
  if 65 - 65: II111iiii - iII111i / o0oOOo0O0Ooo
  if 35 - 35: i11iIiiIii - Oo0Ooo . I1ii11iIi11i % OoOoOO00
  if 20 - 20: OoO0O00
  if 93 - 93: ooOoO0o + o0oOOo0O0Ooo - I1ii11iIi11i
 ooOoOO0Oo = ooOoOO0Oo . lookup_source_cache ( source , False )
 if ( ooOoOO0Oo == None ) :
  iIiI1I1ii1I1 = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( iIiI1I1ii1I1 ) )
  return ( None )
  if 56 - 56: Ii1I / Oo0Ooo
  if 96 - 96: o0oOOo0O0Ooo . II111iiii
  if 14 - 14: OoooooooOO - i1IIi / i11iIiiIii - OOooOOo - i11iIiiIii . ooOoO0o
  if 8 - 8: oO0o * O0 - II111iiii + I1IiiI
  if 85 - 85: OoooooooOO % i11iIiiIii / IiII % OoOoOO00 + O0
 i1i1I11I1I = green ( ooOoOO0Oo . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , i1i1I11I1I ) )
 if 6 - 6: OoooooooOO
 return ( ooOoOO0Oo )
 if 97 - 97: II111iiii + o0oOOo0O0Ooo * II111iiii
 if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
 if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
 if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
 if 14 - 14: OOooOOo * IiII
 if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  O0OOoO = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( O0OOoO )
  if 33 - 33: OoO0O00
  if 91 - 91: I11i % I11i % iII111i
  if 19 - 19: I11i / I11i + I1IiiI * OoO0O00 - iII111i . Oo0Ooo
  if 76 - 76: iII111i % OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % i1IIi
  if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 38 - 38: OoOoOO00 % OoooooooOO . oO0o - OoooooooOO + I11i
 if 18 - 18: OoooooooOO + ooOoO0o * OoOoOO00 - OoO0O00
 if 42 - 42: oO0o % OoOoOO00 - oO0o + I11i / i11iIiiIii
 if 74 - 74: OoO0O00 - II111iiii - ooOoO0o % i1IIi
 if 42 - 42: i11iIiiIii / O0
 if 8 - 8: I1Ii111
 O0OOoO = lisp_referral_cache . lookup_cache ( group , exact )
 if ( O0OOoO == None ) : return ( None )
 if 51 - 51: i11iIiiIii
 IiiII = O0OOoO . lookup_source_cache ( eid , exact )
 if ( IiiII ) : return ( IiiII )
 if 58 - 58: i11iIiiIii * i11iIiiIii - OoO0O00
 if ( exact ) : O0OOoO = None
 return ( O0OOoO )
 if 8 - 8: i11iIiiIii * OoOoOO00 . o0oOOo0O0Ooo
 if 27 - 27: I1ii11iIi11i + Ii1I % I1Ii111
 if 20 - 20: Oo0Ooo
 if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
 if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
 if 84 - 84: OOooOOo
 if 68 - 68: I1Ii111
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  i1iiI1iI11 = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( i1iiI1iI11 )
  if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
  if 54 - 54: oO0o + I11i - OoO0O00
  if 86 - 86: OoooooooOO
  if 51 - 51: i11iIiiIii
  if 91 - 91: OOooOOo
 if ( eid . is_null ( ) ) : return ( None )
 if 22 - 22: OoooooooOO + OoOoOO00 - Ii1I . iII111i / OoooooooOO / I1IiiI
 if 73 - 73: i1IIi - Ii1I + oO0o * iIii1I11I1II1
 if 100 - 100: i11iIiiIii / iIii1I11I1II1 + Oo0Ooo + OoO0O00 - iII111i
 if 8 - 8: i11iIiiIii . O0 + o0oOOo0O0Ooo * oO0o + II111iiii
 if 61 - 61: ooOoO0o / ooOoO0o
 if 51 - 51: iIii1I11I1II1 / oO0o * I1Ii111 + i1IIi
 i1iiI1iI11 = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( i1iiI1iI11 == None ) : return ( None )
 if 96 - 96: Oo0Ooo + oO0o - Oo0Ooo - OoOoOO00 % OOooOOo . iIii1I11I1II1
 oooo0ooOOo = i1iiI1iI11 . lookup_source_cache ( eid , exact )
 if ( oooo0ooOOo ) : return ( oooo0ooOOo )
 if 67 - 67: o0oOOo0O0Ooo . I1Ii111 % iIii1I11I1II1 / I1Ii111
 if ( exact ) : i1iiI1iI11 = None
 return ( i1iiI1iI11 )
 if 18 - 18: I11i * ooOoO0o
 if 46 - 46: IiII
 if 96 - 96: iII111i / i11iIiiIii + Oo0Ooo . I1IiiI + iII111i % OoOoOO00
 if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
 if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
 if 87 - 87: iII111i
 if 86 - 86: IiII - I11i
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 99 - 99: i1IIi + I1ii11iIi11i
 if ( group . is_null ( ) ) :
  iiI1I = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( iiI1I )
  if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
  if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
  if 44 - 44: II111iiii / I1ii11iIi11i
  if 39 - 39: OoooooooOO % OoO0O00
  if 83 - 83: OOooOOo % I1IiiI + O0 % OoooooooOO
 if ( eid . is_null ( ) ) : return ( None )
 if 84 - 84: I11i - Oo0Ooo % ooOoO0o - II111iiii
 if 29 - 29: IiII
 if 4 - 4: II111iiii * o0oOOo0O0Ooo - IiII * iII111i
 if 91 - 91: I1Ii111 * iII111i * OoO0O00
 if 79 - 79: iII111i + oO0o
 if 19 - 19: I1Ii111 - OOooOOo . ooOoO0o . O0 + II111iiii . OoooooooOO
 iiI1I = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( iiI1I == None ) : return ( None )
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
 if 16 - 16: I1Ii111 * i1IIi . I1IiiI . OOooOOo % Ii1I - o0oOOo0O0Ooo
 if 89 - 89: Ii1I * I1ii11iIi11i * I1IiiI % iII111i % Ii1I + O0
 i11 = iiI1I . lookup_source_cache ( eid , exact )
 if ( i11 ) : return ( i11 )
 if 53 - 53: i11iIiiIii % I1ii11iIi11i
 if ( exact ) :
  iiI1I = None
 else :
  Ooo0 = iiI1I . parent_for_more_specifics
  if ( Ooo0 and Ooo0 . accept_more_specifics ) :
   if ( group . is_more_specific ( Ooo0 . group ) ) : iiI1I = Ooo0
   if 59 - 59: OOooOOo
   if 61 - 61: OoooooooOO + O0 - i1IIi % oO0o / I1ii11iIi11i
 return ( iiI1I )
 if 50 - 50: oO0o + II111iiii * OoOoOO00 % OoO0O00 . II111iiii % o0oOOo0O0Ooo
 if 32 - 32: i1IIi / Ii1I + i11iIiiIii % oO0o
 if 11 - 11: Ii1I - ooOoO0o % i11iIiiIii / OoooooooOO - O0 - IiII
 if 25 - 25: IiII + O0 + oO0o % iIii1I11I1II1 - II111iiii . I1IiiI
 if 62 - 62: IiII . O0 + oO0o - ooOoO0o * iIii1I11I1II1
 if 8 - 8: I1ii11iIi11i
 if 65 - 65: i11iIiiIii
 if 92 - 92: oO0o * II111iiii + I1Ii111
 if 49 - 49: II111iiii * I1IiiI * O0 / ooOoO0o * IiII
 if 94 - 94: OoO0O00 - I1IiiI * oO0o
 if 35 - 35: OOooOOo / i1IIi + OoO0O00
 if 31 - 31: OoO0O00 . i1IIi / OoooooooOO
 if 81 - 81: ooOoO0o . Oo0Ooo . OoOoOO00 + OOooOOo % iII111i - oO0o
 if 68 - 68: iII111i - O0 / Ii1I
 if 15 - 15: I1Ii111 / I1ii11iIi11i / I1IiiI % i11iIiiIii + II111iiii . ooOoO0o
 if 74 - 74: o0oOOo0O0Ooo
 if 4 - 4: I1ii11iIi11i * II111iiii - Oo0Ooo % i1IIi % O0 * i11iIiiIii
 if 62 - 62: OoO0O00 * I1Ii111 * Ii1I / ooOoO0o
 if 27 - 27: oO0o . iII111i . oO0o
 if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
 if 14 - 14: I11i + ooOoO0o . oO0o * I11i
 if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
 if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
 if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
 if 33 - 33: I11i
 if 37 - 37: Oo0Ooo
class lisp_address ( ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 36 - 36: IiII % I11i
  if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
  if 82 - 82: OoooooooOO
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 14 - 14: OoO0O00 / oO0o - OOooOOo
  if 100 - 100: IiII - I11i . iIii1I11I1II1 / iIii1I11I1II1
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 16 - 16: IiII + Oo0Ooo % I11i
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 16 - 16: ooOoO0o / I1Ii111
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 78 - 78: OoOoOO00 - II111iiii - OOooOOo + I1IiiI + O0 / I1IiiI
   if 59 - 59: OOooOOo . I1IiiI / i1IIi / II111iiii . II111iiii
   if 54 - 54: iIii1I11I1II1 % ooOoO0o
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
  if 92 - 92: I11i + OoO0O00 . OoooooooOO
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  IiIIiiI = self . address
  if ( ( ( IiIIiiI & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( IiIIiiI & 0xff000000 ) >> 24 ) == 172 ) :
   iIiIi1iIIii = ( IiIIiiI & 0x00ff0000 ) >> 16
   if ( iIiIi1iIIii >= 16 and iIiIi1iIIii <= 31 ) : return ( True )
   if 18 - 18: ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
  if ( ( ( IiIIiiI & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
  if 63 - 63: I11i
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 60 - 60: I1IiiI / I1ii11iIi11i / I11i / Ii1I + iIii1I11I1II1
  if 85 - 85: O0 / OOooOOo . OoOoOO00 / I1ii11iIi11i
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 80 - 80: I1ii11iIi11i * iII111i % i1IIi * OOooOOo % II111iiii % i1IIi
  return ( 0 )
  if 44 - 44: OoooooooOO
  if 18 - 18: i11iIiiIii
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  IiIIiiI = self . address >> 96
  return ( IiIIiiI == 0x20010005 )
  if 65 - 65: i1IIi . iIii1I11I1II1 % iIii1I11I1II1
  if 35 - 35: iIii1I11I1II1 - o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - OOooOOo . o0oOOo0O0Ooo
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
   if 12 - 12: iIii1I11I1II1 % OoO0O00 * Oo0Ooo
  return ( 0 )
  if 5 - 5: I11i - II111iiii * iIii1I11I1II1 / iIii1I11I1II1 % IiII * i1IIi
  if 30 - 30: i1IIi % I1IiiI . OOooOOo % iIii1I11I1II1 . I1ii11iIi11i / o0oOOo0O0Ooo
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 53 - 53: OOooOOo % ooOoO0o
  if 94 - 94: OOooOOo - O0 - I1Ii111 / OoooooooOO - iII111i
 def packet_format ( self ) :
  if 83 - 83: OOooOOo * I1ii11iIi11i * iII111i * I1ii11iIi11i . OoO0O00
  if 87 - 87: ooOoO0o . O0 - oO0o
  if 75 - 75: Oo0Ooo
  if 22 - 22: oO0o * I1Ii111 . II111iiii / Ii1I * O0
  if 33 - 33: oO0o * i1IIi + ooOoO0o * OOooOOo - O0 - iIii1I11I1II1
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 35 - 35: I1Ii111
  if 12 - 12: Ii1I % I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
 def pack_address ( self ) :
  Iii1I = self . packet_format ( )
  o0o0ooOOo0oO = ""
  if ( self . is_ipv4 ( ) ) :
   o0o0ooOOo0oO = struct . pack ( Iii1I , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   ii1I11iI = byte_swap_64 ( self . address >> 64 )
   O0Oo00 = byte_swap_64 ( self . address & 0xffffffffffffffff )
   o0o0ooOOo0oO = struct . pack ( Iii1I , ii1I11iI , O0Oo00 )
  elif ( self . is_mac ( ) ) :
   IiIIiiI = self . address
   ii1I11iI = ( IiIIiiI >> 32 ) & 0xffff
   O0Oo00 = ( IiIIiiI >> 16 ) & 0xffff
   iIiiii = IiIIiiI & 0xffff
   o0o0ooOOo0oO = struct . pack ( Iii1I , ii1I11iI , O0Oo00 , iIiiii )
  elif ( self . is_e164 ( ) ) :
   IiIIiiI = self . address
   ii1I11iI = ( IiIIiiI >> 32 ) & 0xffffffff
   O0Oo00 = ( IiIIiiI & 0xffffffff )
   o0o0ooOOo0oO = struct . pack ( Iii1I , ii1I11iI , O0Oo00 )
  elif ( self . is_dist_name ( ) ) :
   o0o0ooOOo0oO += self . address + "\0"
   if 46 - 46: I11i * OOooOOo
  return ( o0o0ooOOo0oO )
  if 57 - 57: iIii1I11I1II1
  if 11 - 11: OoooooooOO / II111iiii / I1IiiI . I1Ii111 / I1IiiI % OOooOOo
 def unpack_address ( self , packet ) :
  Iii1I = self . packet_format ( )
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 61 - 61: I1ii11iIi11i . OOooOOo - O0 * OoOoOO00
  IiIIiiI = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  if 12 - 12: I1ii11iIi11i / I1Ii111
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( IiIIiiI [ 0 ] )
   if 5 - 5: Oo0Ooo / o0oOOo0O0Ooo % i11iIiiIii - ooOoO0o
  elif ( self . is_ipv6 ( ) ) :
   if 62 - 62: i11iIiiIii
   if 88 - 88: i11iIiiIii
   if 59 - 59: oO0o - OoooooooOO % ooOoO0o
   if 90 - 90: OoOoOO00
   if 96 - 96: II111iiii % Ii1I
   if 84 - 84: I1IiiI . I1IiiI
   if 82 - 82: OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1 + I1ii11iIi11i
   if 45 - 45: iII111i . oO0o * iII111i
   if ( IiIIiiI [ 0 ] <= 0xffff and ( IiIIiiI [ 0 ] & 0xff ) == 0 ) :
    iIII = ( IiIIiiI [ 0 ] << 48 ) << 64
   else :
    iIII = byte_swap_64 ( IiIIiiI [ 0 ] ) << 64
    if 36 - 36: O0 - iII111i + I11i + I1IiiI
   OOO00 = byte_swap_64 ( IiIIiiI [ 1 ] )
   self . address = iIII | OOO00
   if 42 - 42: i11iIiiIii % Ii1I - IiII % ooOoO0o
  elif ( self . is_mac ( ) ) :
   OoOO = IiIIiiI [ 0 ]
   ii1i1iIIiI1 = IiIIiiI [ 1 ]
   oOoOoo00oo = IiIIiiI [ 2 ]
   self . address = ( OoOO << 32 ) + ( ii1i1iIIiI1 << 16 ) + oOoOoo00oo
   if 47 - 47: i11iIiiIii % OOooOOo / ooOoO0o . IiII - I1IiiI
  elif ( self . is_e164 ( ) ) :
   self . address = ( IiIIiiI [ 0 ] << 32 ) + IiIIiiI [ 1 ]
   if 10 - 10: Oo0Ooo / ooOoO0o / I1ii11iIi11i
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   IiiiiI = 0
   if 98 - 98: O0 - I1Ii111 - i11iIiiIii
  packet = packet [ IiiiiI : : ]
  return ( packet )
  if 85 - 85: II111iiii - I1ii11iIi11i % I1IiiI . I1IiiI - OoooooooOO - I11i
  if 38 - 38: i1IIi + oO0o * ooOoO0o % Ii1I % ooOoO0o
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 80 - 80: OoO0O00 + OoOoOO00 % iII111i % OoooooooOO - ooOoO0o
  if 25 - 25: OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - Oo0Ooo . O0
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 48 - 48: I1IiiI + oO0o % i11iIiiIii % iIii1I11I1II1
  if 14 - 14: iIii1I11I1II1
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 78 - 78: I1Ii111 / Oo0Ooo - I1Ii111
  if 1 - 1: OoO0O00 - I1IiiI * o0oOOo0O0Ooo
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 84 - 84: OoO0O00 % OoooooooOO
  if 66 - 66: OoOoOO00 . iII111i
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 1 - 1: iII111i * i1IIi . iIii1I11I1II1 % O0 - OoooooooOO
  if 87 - 87: iII111i . Oo0Ooo * i11iIiiIii % o0oOOo0O0Ooo + Ii1I
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
  if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
  if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
  if 90 - 90: II111iiii + OOooOOo % I1Ii111 * iIii1I11I1II1 % iIii1I11I1II1
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 55 - 55: II111iiii % O0 * O0 - II111iiii * I1IiiI % Oo0Ooo
  if 48 - 48: I1ii11iIi11i + OoooooooOO % i1IIi
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 46 - 46: OoOoOO00
  if 75 - 75: I1IiiI
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 37 - 37: iIii1I11I1II1 % OoO0O00 * ooOoO0o + I11i % ooOoO0o / i11iIiiIii
  if 14 - 14: i1IIi / ooOoO0o
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 10 - 10: ooOoO0o / OoooooooOO - ooOoO0o % O0 + oO0o - oO0o
  if 16 - 16: O0
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 14 - 14: Ii1I . Ii1I . OOooOOo - O0 / OoO0O00 % II111iiii
  if 5 - 5: iIii1I11I1II1 % OoOoOO00 % OOooOOo % O0 * oO0o . iIii1I11I1II1
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 96 - 96: i11iIiiIii + oO0o / I1ii11iIi11i . IiII % o0oOOo0O0Ooo
  if 41 - 41: o0oOOo0O0Ooo . i1IIi - OOooOOo
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 19 - 19: o0oOOo0O0Ooo % I1Ii111 % I11i
  if 1 - 1: I1IiiI / o0oOOo0O0Ooo - I1Ii111
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 50 - 50: I11i - OoOoOO00 + I1IiiI % Oo0Ooo / OoooooooOO - I1ii11iIi11i
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 26 - 26: IiII . Ii1I
  return ( False )
  if 35 - 35: I1ii11iIi11i + OOooOOo
  if 88 - 88: O0
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 4 - 4: OoOoOO00 % iIii1I11I1II1 % OoooooooOO . oO0o
  if 27 - 27: II111iiii - OoOoOO00
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 81 - 81: o0oOOo0O0Ooo - Oo0Ooo % IiII - ooOoO0o / O0
  if 27 - 27: Oo0Ooo
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 15 - 15: iIii1I11I1II1 . OoOoOO00 % Ii1I / i1IIi . o0oOOo0O0Ooo
  if 45 - 45: iIii1I11I1II1 - i1IIi % I1IiiI - I1Ii111 + oO0o
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 15 - 15: iIii1I11I1II1 - OoooooooOO / ooOoO0o
  if 83 - 83: IiII + I1Ii111 / OoOoOO00 * IiII . oO0o
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 22 - 22: O0 + ooOoO0o + I1Ii111
  if 57 - 57: OOooOOo . ooOoO0o - OoooooooOO - I1ii11iIi11i * O0
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 85 - 85: I1IiiI * OoO0O00
  if 63 - 63: I1IiiI - i11iIiiIii
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 4 - 4: OOooOOo + iIii1I11I1II1 / I1IiiI * Ii1I
  if 64 - 64: OoOoOO00
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 94 - 94: OOooOOo * OoooooooOO * o0oOOo0O0Ooo / I1Ii111 . II111iiii
  if 37 - 37: O0 * II111iiii * I1IiiI - O0 - I11i / i1IIi
  if 27 - 27: i11iIiiIii + iIii1I11I1II1
  if 15 - 15: oO0o
  OoOOoO0oOo = addr_str . find ( "[" )
  O0O0Oo = addr_str . find ( "]" )
  if ( OoOOoO0oOo != - 1 and O0O0Oo != - 1 ) :
   self . instance_id = int ( addr_str [ OoOOoO0oOo + 1 : O0O0Oo ] )
   addr_str = addr_str [ O0O0Oo + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 69 - 69: II111iiii * O0 . ooOoO0o * IiII
    if 25 - 25: I11i - I1ii11iIi11i . I1Ii111 . OoooooooOO
    if 4 - 4: IiII * OoO0O00 % I1ii11iIi11i * Ii1I . iII111i
    if 41 - 41: OoooooooOO % I11i . O0 + I1Ii111
    if 67 - 67: OoOoOO00 * OOooOOo / OOooOOo / OoooooooOO
    if 67 - 67: I11i - i1IIi . OoooooooOO / iIii1I11I1II1
  if ( self . is_ipv4 ( ) ) :
   iIiIiiIiIiiiI = addr_str . split ( "." )
   iiIiII11i1 = int ( iIiIiiIiIiiiI [ 0 ] ) << 24
   iiIiII11i1 += int ( iIiIiiIiIiiiI [ 1 ] ) << 16
   iiIiII11i1 += int ( iIiIiiIiIiiiI [ 2 ] ) << 8
   iiIiII11i1 += int ( iIiIiiIiIiiiI [ 3 ] )
   self . address = iiIiII11i1
  elif ( self . is_ipv6 ( ) ) :
   if 19 - 19: I11i
   if 91 - 91: OOooOOo * OoooooooOO
   if 89 - 89: i1IIi / iII111i . I1Ii111
   if 74 - 74: I1ii11iIi11i % iII111i / OoooooooOO / I1ii11iIi11i % i11iIiiIii % ooOoO0o
   if 82 - 82: OoooooooOO . o0oOOo0O0Ooo * I1ii11iIi11i % I1ii11iIi11i * Ii1I
   if 83 - 83: I11i - Oo0Ooo + i11iIiiIii - i11iIiiIii
   if 64 - 64: IiII % I1IiiI / ooOoO0o
   if 74 - 74: OoooooooOO
   if 22 - 22: II111iiii . O0 * I1Ii111 % OoO0O00 / OoooooooOO + I1Ii111
   if 71 - 71: ooOoO0o . oO0o * OoooooooOO + iII111i - I1Ii111 . I1ii11iIi11i
   if 100 - 100: I11i + O0 - o0oOOo0O0Ooo * I1ii11iIi11i
   if 94 - 94: Oo0Ooo . IiII / Ii1I / oO0o - I1IiiI
   if 77 - 77: i11iIiiIii . Ii1I - Ii1I
   if 47 - 47: iII111i % OOooOOo . I1ii11iIi11i + I1ii11iIi11i . I1Ii111
   if 20 - 20: oO0o - o0oOOo0O0Ooo + I1IiiI % OoOoOO00
   if 41 - 41: oO0o . ooOoO0o
   if 59 - 59: iIii1I11I1II1 - I1IiiI . ooOoO0o
   OoO0O0OoO0oO = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 38 - 38: iII111i - OoO0O00 / i1IIi + ooOoO0o . ooOoO0o . iII111i
   addr_str = binascii . hexlify ( addr_str )
   if 37 - 37: iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoooooooOO + OoO0O00
   if ( OoO0O0OoO0oO ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 25 - 25: I1IiiI / IiII . OOooOOo . I1ii11iIi11i % i1IIi
   self . address = int ( addr_str , 16 )
   if 12 - 12: O0 % O0
  elif ( self . is_geo_prefix ( ) ) :
   ooOooo = lisp_geo ( None )
   ooOooo . name = "geo-prefix-{}" . format ( ooOooo )
   ooOooo . parse_geo_string ( addr_str )
   self . address = ooOooo
  elif ( self . is_mac ( ) ) :
   addr_str = addr_str . replace ( "-" , "" )
   iiIiII11i1 = int ( addr_str , 16 )
   self . address = iiIiII11i1
  elif ( self . is_e164 ( ) ) :
   addr_str = addr_str [ 1 : : ]
   iiIiII11i1 = int ( addr_str , 16 )
   self . address = iiIiII11i1 << 4
  elif ( self . is_dist_name ( ) ) :
   self . address = addr_str . replace ( "'" , "" )
   if 9 - 9: O0 . I1IiiI + I1ii11iIi11i / OOooOOo * I1ii11iIi11i
  self . mask_len = self . host_mask_len ( )
  if 10 - 10: IiII % o0oOOo0O0Ooo / O0 / II111iiii
  if 81 - 81: Ii1I / o0oOOo0O0Ooo % OoOoOO00 . I1ii11iIi11i
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   I1i11II = prefix_str . find ( "]" )
   o00O00 = len ( prefix_str [ I1i11II + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , o00O00 = prefix_str . split ( "/" )
  else :
   Oo = prefix_str . find ( "'" )
   if ( Oo == - 1 ) : return
   o0 = prefix_str . find ( "'" , Oo + 1 )
   if ( o0 == - 1 ) : return
   o00O00 = len ( prefix_str [ Oo + 1 : o0 ] ) * 8
   if 47 - 47: II111iiii + OOooOOo / II111iiii . OOooOOo
   if 68 - 68: OoooooooOO
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( o00O00 )
  if 63 - 63: I1IiiI
  if 80 - 80: oO0o + iIii1I11I1II1
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  oOo0000OOo = ( 2 ** self . mask_len ) - 1
  O0o0 = self . addr_length ( ) * 8 - self . mask_len
  oOo0000OOo <<= O0o0
  self . address &= oOo0000OOo
  if 36 - 36: IiII * OoooooooOO . i11iIiiIii * i1IIi
  if 52 - 52: IiII + ooOoO0o - II111iiii - OoooooooOO * OoO0O00 - iIii1I11I1II1
 def is_geo_string ( self , addr_str ) :
  I1i11II = addr_str . find ( "]" )
  if ( I1i11II != - 1 ) : addr_str = addr_str [ I1i11II + 1 : : ]
  if 38 - 38: II111iiii % iIii1I11I1II1 * IiII * OoOoOO00 % II111iiii . I1IiiI
  ooOooo = addr_str . split ( "/" )
  if ( len ( ooOooo ) == 2 ) :
   if ( ooOooo [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 35 - 35: OoooooooOO - i11iIiiIii * i11iIiiIii % Ii1I - OOooOOo . iIii1I11I1II1
  ooOooo = ooOooo [ 0 ]
  ooOooo = ooOooo . split ( "-" )
  ooOoO0OOOO = len ( ooOooo )
  if ( ooOoO0OOOO < 8 or ooOoO0OOOO > 9 ) : return ( False )
  if 21 - 21: ooOoO0o . o0oOOo0O0Ooo . oO0o . i1IIi
  for O000oooooo0 in range ( 0 , ooOoO0OOOO ) :
   if ( O000oooooo0 == 3 ) :
    if ( ooOooo [ O000oooooo0 ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 40 - 40: i1IIi
   if ( O000oooooo0 == 7 ) :
    if ( ooOooo [ O000oooooo0 ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 53 - 53: Ii1I . I1ii11iIi11i - OOooOOo - ooOoO0o
   if ( ooOooo [ O000oooooo0 ] . isdigit ( ) == False ) : return ( False )
   if 17 - 17: OoooooooOO / I1IiiI * ooOoO0o % I1ii11iIi11i . OoO0O00
  return ( True )
  if 5 - 5: OoO0O00 % I1Ii111 . oO0o . Ii1I + I1IiiI
  if 95 - 95: II111iiii . iII111i - iIii1I11I1II1 / I11i + ooOoO0o * I1Ii111
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 92 - 92: iII111i * OoooooooOO % I1IiiI / OOooOOo
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 46 - 46: OoOoOO00
  if 52 - 52: o0oOOo0O0Ooo - OoO0O00 % i1IIi / Ii1I % IiII
 def print_address ( self ) :
  IiIIiiI = self . print_address_no_iid ( )
  i1 = "[" + str ( self . instance_id )
  for OoOOoO0oOo in self . iid_list : i1 += "," + str ( OoOOoO0oOo )
  i1 += "]"
  IiIIiiI = "{}{}" . format ( i1 , IiIIiiI )
  return ( IiIIiiI )
  if 100 - 100: oO0o . i11iIiiIii - ooOoO0o
  if 49 - 49: Oo0Ooo % ooOoO0o % o0oOOo0O0Ooo + ooOoO0o * I1Ii111 % I1IiiI
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   IiIIiiI = self . address
   ooo0O = IiIIiiI >> 24
   i1I11iI11I = ( IiIIiiI >> 16 ) & 0xff
   O00o = ( IiIIiiI >> 8 ) & 0xff
   OOoO00O = IiIIiiI & 0xff
   return ( "{}.{}.{}.{}" . format ( ooo0O , i1I11iI11I , O00o , OOoO00O ) )
  elif ( self . is_ipv6 ( ) ) :
   O0O0 = lisp_hex_string ( self . address ) . zfill ( 32 )
   O0O0 = binascii . unhexlify ( O0O0 )
   O0O0 = socket . inet_ntop ( socket . AF_INET6 , O0O0 )
   return ( "{}" . format ( O0O0 ) )
  elif ( self . is_geo_prefix ( ) ) :
   return ( "{}" . format ( self . address . print_geo ( ) ) )
  elif ( self . is_mac ( ) ) :
   O0O0 = lisp_hex_string ( self . address ) . zfill ( 12 )
   O0O0 = "{}-{}-{}" . format ( O0O0 [ 0 : 4 ] , O0O0 [ 4 : 8 ] ,
 O0O0 [ 8 : 12 ] )
   return ( "{}" . format ( O0O0 ) )
  elif ( self . is_e164 ( ) ) :
   O0O0 = lisp_hex_string ( self . address ) . zfill ( 15 )
   return ( "+{}" . format ( O0O0 ) )
  elif ( self . is_dist_name ( ) ) :
   return ( "'{}'" . format ( self . address ) )
  elif ( self . is_null ( ) ) :
   return ( "no-address" )
   if 16 - 16: I1IiiI % OoO0O00 . ooOoO0o / OoooooooOO
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 8 - 8: I1Ii111 % OoO0O00 . I1IiiI - OoOoOO00 + i1IIi / iIii1I11I1II1
  if 89 - 89: II111iiii / Ii1I % Ii1I
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   o00OO00Oo0 = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , o00OO00Oo0 ) )
   if 98 - 98: iIii1I11I1II1 - I11i % i11iIiiIii * I1IiiI / OoOoOO00 * ooOoO0o
  IiIIiiI = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( IiIIiiI )
  if ( self . is_geo_prefix ( ) ) : return ( IiIIiiI )
  if 78 - 78: i11iIiiIii % oO0o % Ii1I / I1Ii111 / I1Ii111
  I1i11II = IiIIiiI . find ( "no-address" )
  if ( I1i11II == - 1 ) :
   IiIIiiI = "{}/{}" . format ( IiIIiiI , str ( self . mask_len ) )
  else :
   IiIIiiI = IiIIiiI [ 0 : I1i11II ]
   if 20 - 20: iII111i / I11i / iIii1I11I1II1
  return ( IiIIiiI )
  if 94 - 94: i11iIiiIii % I1ii11iIi11i % IiII - I1Ii111
  if 55 - 55: I11i - ooOoO0o - iIii1I11I1II1 + I1ii11iIi11i / IiII
 def print_prefix_no_iid ( self ) :
  IiIIiiI = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( IiIIiiI )
  if ( self . is_geo_prefix ( ) ) : return ( IiIIiiI )
  return ( "{}/{}" . format ( IiIIiiI , str ( self . mask_len ) ) )
  if 49 - 49: I1ii11iIi11i
  if 91 - 91: OOooOOo % iII111i
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  IiIIiiI = self . print_address ( )
  I1i11II = IiIIiiI . find ( "]" )
  if ( I1i11II != - 1 ) : IiIIiiI = IiIIiiI [ I1i11II + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   IiIIiiI = IiIIiiI . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , IiIIiiI ) )
   if 40 - 40: i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i1IIi . O0
  return ( "{}-{}-{}" . format ( self . instance_id , IiIIiiI , self . mask_len ) )
  if 39 - 39: I1ii11iIi11i
  if 26 - 26: oO0o . I1Ii111 % I11i
 def print_sg ( self , g ) :
  I1iiIi111I = self . print_prefix ( )
  OooOo = I1iiIi111I . find ( "]" ) + 1
  g = g . print_prefix ( )
  i1iii = g . find ( "]" ) + 1
  O0o0O = "[{}]({}, {})" . format ( self . instance_id , I1iiIi111I [ OooOo : : ] , g [ i1iii : : ] )
  return ( O0o0O )
  if 51 - 51: OoOoOO00
  if 34 - 34: i11iIiiIii * OoooooooOO
 def hash_address ( self , addr ) :
  ii1I11iI = self . address
  O0Oo00 = addr . address
  if 74 - 74: OoooooooOO * iII111i % OOooOOo . OoooooooOO * I11i % I1Ii111
  if ( self . is_geo_prefix ( ) ) : ii1I11iI = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : O0Oo00 = addr . address . print_geo ( )
  if 67 - 67: I11i * i1IIi
  if ( type ( ii1I11iI ) == str ) :
   ii1I11iI = int ( binascii . hexlify ( ii1I11iI [ 0 : 1 ] ) )
   if 7 - 7: i1IIi * OoOoOO00 . Ii1I
  if ( type ( O0Oo00 ) == str ) :
   O0Oo00 = int ( binascii . hexlify ( O0Oo00 [ 0 : 1 ] ) )
   if 80 - 80: OoOoOO00 + o0oOOo0O0Ooo - II111iiii
  return ( ii1I11iI ^ O0Oo00 )
  if 3 - 3: ooOoO0o * I1Ii111
  if 34 - 34: Ii1I / Oo0Ooo . II111iiii - ooOoO0o - I1ii11iIi11i % OoOoOO00
  if 43 - 43: Ii1I * oO0o
  if 57 - 57: OoooooooOO + I1IiiI % I1ii11iIi11i % ooOoO0o * I1Ii111
  if 9 - 9: i11iIiiIii
  if 85 - 85: IiII / o0oOOo0O0Ooo * ooOoO0o
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 74 - 74: O0 - o0oOOo0O0Ooo
  o00O00 = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   oooOOo0o0ooO = 2 ** ( 32 - o00O00 )
   o000O000o000O = prefix . instance_id
   o00OO00Oo0 = o000O000o000O + oooOOo0o0ooO
   return ( self . instance_id in range ( o000O000o000O , o00OO00Oo0 ) )
   if 82 - 82: I1Ii111 . OoO0O00 - Ii1I
   if 75 - 75: i11iIiiIii
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 78 - 78: OoOoOO00
   if 61 - 61: OoOoOO00 . I1ii11iIi11i . I11i / IiII
   if 84 - 84: OoOoOO00 . IiII
   if 50 - 50: O0
   if 51 - 51: I1Ii111
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   IiIIiiI = self . address
   O000 = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    IiIIiiI = self . address . print_geo ( )
    O000 = prefix . address . print_geo ( )
    if 12 - 12: OoooooooOO . OoooooooOO * I11i
   if ( len ( IiIIiiI ) < len ( O000 ) ) : return ( False )
   return ( IiIIiiI . find ( O000 ) == 0 )
   if 76 - 76: OoooooooOO - Ii1I + IiII % OoOoOO00 / OoooooooOO
   if 55 - 55: i11iIiiIii - IiII * OOooOOo + II111iiii . I1ii11iIi11i / O0
   if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
   if 98 - 98: II111iiii - i1IIi - ooOoO0o
   if 36 - 36: IiII + o0oOOo0O0Ooo
  if ( self . mask_len < o00O00 ) : return ( False )
  if 81 - 81: OOooOOo / I11i % oO0o + ooOoO0o
  O0o0 = ( prefix . addr_length ( ) * 8 ) - o00O00
  oOo0000OOo = ( 2 ** o00O00 - 1 ) << O0o0
  return ( ( self . address & oOo0000OOo ) == prefix . address )
  if 10 - 10: oO0o / i11iIiiIii
  if 73 - 73: OoO0O00 - i1IIi
 def mask_address ( self , mask_len ) :
  O0o0 = ( self . addr_length ( ) * 8 ) - mask_len
  oOo0000OOo = ( 2 ** mask_len - 1 ) << O0o0
  self . address &= oOo0000OOo
  if 52 - 52: I1ii11iIi11i
  if 4 - 4: Ii1I - iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  iIIi1I1Iiii = self . print_prefix ( )
  OO0oOO00OOo = prefix . print_prefix ( ) if prefix else ""
  return ( iIIi1I1Iiii == OO0oOO00OOo )
  if 2 - 2: I1IiiI + II111iiii . ooOoO0o + oO0o . OoO0O00
  if 49 - 49: OoO0O00 . IiII
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   Ii1IiI = lisp_myrlocs [ 0 ]
   if ( Ii1IiI == None ) : return ( False )
   Ii1IiI = Ii1IiI . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == Ii1IiI )
   if 58 - 58: i1IIi . OoooooooOO % iIii1I11I1II1 * o0oOOo0O0Ooo + O0 / oO0o
  if ( self . is_ipv6 ( ) ) :
   Ii1IiI = lisp_myrlocs [ 1 ]
   if ( Ii1IiI == None ) : return ( False )
   Ii1IiI = Ii1IiI . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == Ii1IiI )
   if 77 - 77: I11i . I1ii11iIi11i
  return ( False )
  if 92 - 92: i11iIiiIii + I11i % I1IiiI / ooOoO0o
  if 28 - 28: i1IIi . I1IiiI
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid == 0 and mask_len == 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 41 - 41: I1ii11iIi11i . I1Ii111 * OoOoOO00 . I1Ii111 / o0oOOo0O0Ooo
  self . instance_id = iid
  self . mask_len = mask_len
  if 41 - 41: o0oOOo0O0Ooo / o0oOOo0O0Ooo . Oo0Ooo
  if 4 - 4: I1Ii111
 def lcaf_length ( self , lcaf_type ) :
  i1iIii = self . addr_length ( ) + 2
  if ( lcaf_type == LISP_LCAF_AFI_LIST_TYPE ) : i1iIii += 4
  if ( lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE ) : i1iIii += 4
  if ( lcaf_type == LISP_LCAF_ASN_TYPE ) : i1iIii += 4
  if ( lcaf_type == LISP_LCAF_APP_DATA_TYPE ) : i1iIii += 8
  if ( lcaf_type == LISP_LCAF_GEO_COORD_TYPE ) : i1iIii += 12
  if ( lcaf_type == LISP_LCAF_OPAQUE_TYPE ) : i1iIii += 0
  if ( lcaf_type == LISP_LCAF_NAT_TYPE ) : i1iIii += 4
  if ( lcaf_type == LISP_LCAF_NONCE_LOC_TYPE ) : i1iIii += 4
  if ( lcaf_type == LISP_LCAF_MCAST_INFO_TYPE ) : i1iIii = i1iIii * 2 + 8
  if ( lcaf_type == LISP_LCAF_ELP_TYPE ) : i1iIii += 0
  if ( lcaf_type == LISP_LCAF_SECURITY_TYPE ) : i1iIii += 6
  if ( lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE ) : i1iIii += 4
  if ( lcaf_type == LISP_LCAF_RLE_TYPE ) : i1iIii += 4
  return ( i1iIii )
  if 85 - 85: iIii1I11I1II1 % Oo0Ooo
  if 20 - 20: IiII + i11iIiiIii * OOooOOo
  if 27 - 27: O0 * OoO0O00 * I1ii11iIi11i
  if 40 - 40: O0 + oO0o - ooOoO0o + I1IiiI - IiII
  if 60 - 60: I1Ii111 * OoO0O00 * oO0o + oO0o
  if 34 - 34: o0oOOo0O0Ooo
  if 76 - 76: oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
  if 51 - 51: II111iiii / OoOoOO00
  if 69 - 69: i11iIiiIii
  if 77 - 77: I1ii11iIi11i % OoooooooOO - Oo0Ooo - Ii1I + I11i
  if 93 - 93: I1IiiI % O0 * OoO0O00 % OoOoOO00 . I1Ii111 * I1IiiI
  if 95 - 95: IiII + o0oOOo0O0Ooo - o0oOOo0O0Ooo
  if 83 - 83: ooOoO0o
  if 59 - 59: I1ii11iIi11i
  if 26 - 26: I11i . Ii1I
  if 94 - 94: ooOoO0o . I1IiiI + IiII % I1IiiI / o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 21 - 21: O0 / OOooOOo - II111iiii + I1ii11iIi11i / OoooooooOO
 def lcaf_encode_iid ( self ) :
  iIiI1 = LISP_LCAF_INSTANCE_ID_TYPE
  o0ooOo000oo = socket . htons ( self . lcaf_length ( iIiI1 ) )
  i1 = self . instance_id
  i1I1iiiI = self . afi
  Iii1iii1II = 0
  if ( i1I1iiiI < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    i1I1iiiI = LISP_AFI_LCAF
    Iii1iii1II = 0
   else :
    i1I1iiiI = 0
    Iii1iii1II = self . mask_len
    if 81 - 81: i11iIiiIii / Oo0Ooo * i1IIi + OoO0O00 + O0 % I1ii11iIi11i
    if 3 - 3: i11iIiiIii * IiII . Oo0Ooo % OoOoOO00 * I11i . iII111i
    if 80 - 80: I11i - IiII
  I11Ii111iiii1 = struct . pack ( "BBBBH" , 0 , 0 , iIiI1 , Iii1iii1II , o0ooOo000oo )
  I11Ii111iiii1 += struct . pack ( "IH" , socket . htonl ( i1 ) , socket . htons ( i1I1iiiI ) )
  if ( i1I1iiiI == 0 ) : return ( I11Ii111iiii1 )
  if 12 - 12: OoOoOO00 + ooOoO0o * OoOoOO00 . OoOoOO00 * Oo0Ooo + iIii1I11I1II1
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   I11Ii111iiii1 = I11Ii111iiii1 [ 0 : - 2 ]
   I11Ii111iiii1 += self . address . encode_geo ( )
   return ( I11Ii111iiii1 )
   if 17 - 17: Ii1I
   if 19 - 19: OOooOOo . OoOoOO00 % iIii1I11I1II1 % OoOoOO00
  I11Ii111iiii1 += self . pack_address ( )
  return ( I11Ii111iiii1 )
  if 92 - 92: o0oOOo0O0Ooo + II111iiii
  if 56 - 56: OoOoOO00 - OoOoOO00 / Ii1I
 def lcaf_decode_iid ( self , packet ) :
  Iii1I = "BBBBH"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 92 - 92: iIii1I11I1II1
  Ii1i1I1Ii , I1iI1 , iIiI1 , i1iIi , i1iIii = struct . unpack ( Iii1I ,
 packet [ : IiiiiI ] )
  packet = packet [ IiiiiI : : ]
  if 84 - 84: iII111i - ooOoO0o
  if ( iIiI1 != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 23 - 23: Oo0Ooo / I11i - OOooOOo
  Iii1I = "IH"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( None )
  if 53 - 53: ooOoO0o / OoOoOO00 - OoooooooOO * oO0o
  i1 , i1I1iiiI = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  packet = packet [ IiiiiI : : ]
  if 45 - 45: o0oOOo0O0Ooo . I1Ii111 % Ii1I
  i1iIii = socket . ntohs ( i1iIii )
  self . instance_id = socket . ntohl ( i1 )
  i1I1iiiI = socket . ntohs ( i1I1iiiI )
  self . afi = i1I1iiiI
  if ( i1iIi != 0 and i1I1iiiI == 0 ) : self . mask_len = i1iIi
  if ( i1I1iiiI == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if i1iIi else LISP_AFI_ULTIMATE_ROOT
   if 42 - 42: Oo0Ooo + i11iIiiIii - OOooOOo . I1ii11iIi11i % I1Ii111 . I1ii11iIi11i
   if 59 - 59: OoooooooOO
   if 91 - 91: i11iIiiIii / Oo0Ooo % I11i / O0
   if 80 - 80: II111iiii / I1ii11iIi11i % I1IiiI . Ii1I
   if 8 - 8: oO0o
  if ( i1I1iiiI == 0 ) : return ( packet )
  if 21 - 21: oO0o + iII111i . i11iIiiIii - II111iiii
  if 14 - 14: I1Ii111
  if 81 - 81: II111iiii
  if 55 - 55: O0 + o0oOOo0O0Ooo * I1IiiI - OoooooooOO
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 68 - 68: I11i + Oo0Ooo
   if 15 - 15: O0
   if 75 - 75: iII111i / OoOoOO00
   if 2 - 2: i1IIi + oO0o % iII111i % I1ii11iIi11i + ooOoO0o . iII111i
   if 26 - 26: I11i + o0oOOo0O0Ooo + Ii1I % I11i
  if ( i1I1iiiI == LISP_AFI_LCAF ) :
   Iii1I = "BBBBH"
   IiiiiI = struct . calcsize ( Iii1I )
   if ( len ( packet ) < IiiiiI ) : return ( None )
   if 95 - 95: IiII - O0 * oO0o * O0
   iIii1iI11 , iIiOOO0oo0OO0o0 , iIiI1 , OOoO0 , I11IiI1III = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
   if 47 - 47: I1IiiI
   if 20 - 20: I1Ii111
   if ( iIiI1 != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 40 - 40: OoooooooOO / o0oOOo0O0Ooo + OoOoOO00
   I11IiI1III = socket . ntohs ( I11IiI1III )
   packet = packet [ IiiiiI : : ]
   if ( I11IiI1III > len ( packet ) ) : return ( None )
   if 73 - 73: OOooOOo / Oo0Ooo
   ooOooo = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = ooOooo
   packet = ooOooo . decode_geo ( packet , I11IiI1III , OOoO0 )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 80 - 80: OoO0O00 + I1IiiI % i1IIi / I11i % i1IIi * i11iIiiIii
   if 27 - 27: OoOoOO00 / I1Ii111 * O0 / I1IiiI - IiII / o0oOOo0O0Ooo
  o0ooOo000oo = self . addr_length ( )
  if ( len ( packet ) < o0ooOo000oo ) : return ( None )
  if 70 - 70: I1ii11iIi11i
  packet = self . unpack_address ( packet )
  return ( packet )
  if 11 - 11: I1Ii111
  if 70 - 70: Ii1I
  if 22 - 22: Ii1I
  if 59 - 59: I1ii11iIi11i
  if 90 - 90: OOooOOo / iII111i
  if 70 - 70: o0oOOo0O0Ooo
  if 49 - 49: OOooOOo - I1IiiI + OoooooooOO % iII111i + o0oOOo0O0Ooo + OoOoOO00
  if 37 - 37: II111iiii % I1ii11iIi11i * OoOoOO00
  if 35 - 35: i1IIi
  if 81 - 81: OoO0O00
  if 45 - 45: OoooooooOO . O0 * oO0o + IiII
  if 18 - 18: II111iiii . O0 - I11i / I11i
  if 71 - 71: OoOoOO00 + iIii1I11I1II1 - II111iiii / i1IIi
  if 39 - 39: Ii1I + I1Ii111 * Oo0Ooo + OoOoOO00 / I1Ii111 - ooOoO0o
  if 66 - 66: I11i * OoO0O00
  if 98 - 98: IiII . Oo0Ooo + I1Ii111
  if 63 - 63: oO0o * I1IiiI * oO0o
  if 56 - 56: oO0o - Ii1I % I1Ii111
  if 100 - 100: OOooOOo * IiII % IiII / o0oOOo0O0Ooo * OoO0O00 % OoOoOO00
  if 12 - 12: I1IiiI
  if 32 - 32: I1Ii111
 def lcaf_encode_sg ( self , group ) :
  iIiI1 = LISP_LCAF_MCAST_INFO_TYPE
  i1 = socket . htonl ( self . instance_id )
  o0ooOo000oo = socket . htons ( self . lcaf_length ( iIiI1 ) )
  I11Ii111iiii1 = struct . pack ( "BBBBHIHBB" , 0 , 0 , iIiI1 , 0 , o0ooOo000oo , i1 ,
 0 , self . mask_len , group . mask_len )
  if 35 - 35: O0 + II111iiii + o0oOOo0O0Ooo - OoO0O00 - Ii1I
  I11Ii111iiii1 += struct . pack ( "H" , socket . htons ( self . afi ) )
  I11Ii111iiii1 += self . pack_address ( )
  I11Ii111iiii1 += struct . pack ( "H" , socket . htons ( group . afi ) )
  I11Ii111iiii1 += group . pack_address ( )
  return ( I11Ii111iiii1 )
  if 88 - 88: I1ii11iIi11i . O0 - o0oOOo0O0Ooo . I1ii11iIi11i * iII111i * I11i
  if 89 - 89: Oo0Ooo - oO0o + O0 / i11iIiiIii
 def lcaf_decode_sg ( self , packet ) :
  Iii1I = "BBBBHIHBB"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( [ None , None ] )
  if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
  Ii1i1I1Ii , I1iI1 , iIiI1 , i1Ii1II , i1iIii , i1 , O00o00Oo0 , IiIIIi1 , i1II1iIi111I1 = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
  if 8 - 8: OOooOOo
  packet = packet [ IiiiiI : : ]
  if 85 - 85: O0 % OOooOOo . Ii1I
  if ( iIiI1 != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 74 - 74: I1ii11iIi11i - I1Ii111 + i11iIiiIii / I1Ii111 / OoooooooOO + o0oOOo0O0Ooo
  self . instance_id = socket . ntohl ( i1 )
  i1iIii = socket . ntohs ( i1iIii ) - 8
  if 23 - 23: Oo0Ooo
  if 91 - 91: I1Ii111
  if 59 - 59: i1IIi % OOooOOo
  if 81 - 81: i11iIiiIii / OoO0O00 * OoOoOO00 % iII111i - iIii1I11I1II1 + I1ii11iIi11i
  if 20 - 20: O0 . I1Ii111 * Ii1I * II111iiii
  Iii1I = "H"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( [ None , None ] )
  if ( i1iIii < IiiiiI ) : return ( [ None , None ] )
  if 66 - 66: Ii1I % OoO0O00 % II111iiii - OOooOOo * o0oOOo0O0Ooo
  i1I1iiiI = struct . unpack ( Iii1I , packet [ : IiiiiI ] ) [ 0 ]
  packet = packet [ IiiiiI : : ]
  i1iIii -= IiiiiI
  self . afi = socket . ntohs ( i1I1iiiI )
  self . mask_len = IiIIIi1
  o0ooOo000oo = self . addr_length ( )
  if ( i1iIii < o0ooOo000oo ) : return ( [ None , None ] )
  if 33 - 33: OoooooooOO / I11i
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 98 - 98: I1ii11iIi11i . Ii1I . iIii1I11I1II1 * I1ii11iIi11i / Ii1I
  i1iIii -= o0ooOo000oo
  if 74 - 74: Oo0Ooo * I1Ii111
  if 72 - 72: OoOoOO00 + O0 - IiII * ooOoO0o
  if 20 - 20: II111iiii % OoOoOO00 * i11iIiiIii
  if 68 - 68: IiII / ooOoO0o
  if 100 - 100: ooOoO0o / I1IiiI
  Iii1I = "H"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( [ None , None ] )
  if ( i1iIii < IiiiiI ) : return ( [ None , None ] )
  if 69 - 69: ooOoO0o + OoO0O00 * o0oOOo0O0Ooo - ooOoO0o
  i1I1iiiI = struct . unpack ( Iii1I , packet [ : IiiiiI ] ) [ 0 ]
  packet = packet [ IiiiiI : : ]
  i1iIii -= IiiiiI
  iiIoOOOOoo0O00o = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  iiIoOOOOoo0O00o . afi = socket . ntohs ( i1I1iiiI )
  iiIoOOOOoo0O00o . mask_len = i1II1iIi111I1
  iiIoOOOOoo0O00o . instance_id = self . instance_id
  o0ooOo000oo = self . addr_length ( )
  if ( i1iIii < o0ooOo000oo ) : return ( [ None , None ] )
  if 66 - 66: OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00 + OOooOOo
  packet = iiIoOOOOoo0O00o . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 64 - 64: i1IIi
  return ( [ packet , iiIoOOOOoo0O00o ] )
  if 26 - 26: OoOoOO00 / o0oOOo0O0Ooo . OOooOOo + I1IiiI + Ii1I . iII111i
  if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
 def lcaf_decode_eid ( self , packet ) :
  Iii1I = "BBB"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( [ None , None ] )
  if 5 - 5: OoOoOO00 % i1IIi
  if 31 - 31: Oo0Ooo * O0 . OOooOOo . o0oOOo0O0Ooo + OoO0O00 + II111iiii
  if 76 - 76: Oo0Ooo + I1IiiI - O0
  if 58 - 58: IiII * i1IIi . I1IiiI - iII111i
  if 73 - 73: Oo0Ooo . OoOoOO00
  i1Ii1II , iIiOOO0oo0OO0o0 , iIiI1 = struct . unpack ( Iii1I ,
 packet [ : IiiiiI ] )
  if 50 - 50: IiII / o0oOOo0O0Ooo
  if ( iIiI1 == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( iIiI1 == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , iiIoOOOOoo0O00o = self . lcaf_decode_sg ( packet )
   return ( [ packet , iiIoOOOOoo0O00o ] )
  elif ( iIiI1 == LISP_LCAF_GEO_COORD_TYPE ) :
   Iii1I = "BBBBH"
   IiiiiI = struct . calcsize ( Iii1I )
   if ( len ( packet ) < IiiiiI ) : return ( None )
   if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
   iIii1iI11 , iIiOOO0oo0OO0o0 , iIiI1 , OOoO0 , I11IiI1III = struct . unpack ( Iii1I , packet [ : IiiiiI ] )
   if 52 - 52: O0
   if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
   if ( iIiI1 != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
   I11IiI1III = socket . ntohs ( I11IiI1III )
   packet = packet [ IiiiiI : : ]
   if ( I11IiI1III > len ( packet ) ) : return ( None )
   if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
   ooOooo = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = ooOooo
   packet = ooOooo . decode_geo ( packet , I11IiI1III , OOoO0 )
   self . mask_len = self . host_mask_len ( )
   if 83 - 83: oO0o / OoO0O00
  return ( [ packet , None ] )
  if 34 - 34: OoooooooOO - i1IIi * O0
  if 83 - 83: I1IiiI + OoO0O00
  if 41 - 41: Ii1I + II111iiii . OOooOOo * I1Ii111 / II111iiii
  if 32 - 32: Oo0Ooo - Ii1I % o0oOOo0O0Ooo
  if 15 - 15: iIii1I11I1II1 * I1ii11iIi11i / ooOoO0o * oO0o % OOooOOo
  if 62 - 62: Ii1I / Oo0Ooo . OoO0O00 - OOooOOo
class lisp_elp_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 89 - 89: o0oOOo0O0Ooo % OoO0O00
  if 53 - 53: OoOoOO00 . ooOoO0o - OoO0O00
 def copy_elp_node ( self ) :
  oOo0Oo0o0 = lisp_elp_node ( )
  oOo0Oo0o0 . copy_address ( self . address )
  oOo0Oo0o0 . probe = self . probe
  oOo0Oo0o0 . strict = self . strict
  oOo0Oo0o0 . eid = self . eid
  oOo0Oo0o0 . we_are_last = self . we_are_last
  return ( oOo0Oo0o0 )
  if 26 - 26: ooOoO0o - oO0o + OOooOOo * Ii1I - I11i % I1IiiI
  if 73 - 73: ooOoO0o + Ii1I . O0 . iII111i
  if 77 - 77: OOooOOo % I1IiiI - iII111i % I1Ii111
class lisp_elp ( ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 29 - 29: iIii1I11I1II1 / i11iIiiIii + Oo0Ooo
  if 99 - 99: I1IiiI - iII111i * Ii1I - OoOoOO00 / i11iIiiIii - i1IIi
 def copy_elp ( self ) :
  Iii11i111iI = lisp_elp ( self . elp_name )
  Iii11i111iI . use_elp_node = self . use_elp_node
  Iii11i111iI . we_are_last = self . we_are_last
  for oOo0Oo0o0 in self . elp_nodes :
   Iii11i111iI . elp_nodes . append ( oOo0Oo0o0 . copy_elp_node ( ) )
   if 46 - 46: I1ii11iIi11i * ooOoO0o
  return ( Iii11i111iI )
  if 4 - 4: I1Ii111 * II111iiii
  if 4 - 4: ooOoO0o * Oo0Ooo - I1ii11iIi11i % ooOoO0o % OoOoOO00
 def print_elp ( self , want_marker ) :
  oOI1i = ""
  for oOo0Oo0o0 in self . elp_nodes :
   IIii = ""
   if ( want_marker ) :
    if ( oOo0Oo0o0 == self . use_elp_node ) :
     IIii = "*"
    elif ( oOo0Oo0o0 . we_are_last ) :
     IIii = "x"
     if 56 - 56: II111iiii * iIii1I11I1II1 % I1ii11iIi11i
     if 83 - 83: i1IIi . i11iIiiIii / iII111i
   oOI1i += "{}{}({}{}{}), " . format ( IIii ,
 oOo0Oo0o0 . address . print_address_no_iid ( ) ,
 "r" if oOo0Oo0o0 . eid else "R" , "P" if oOo0Oo0o0 . probe else "p" ,
 "S" if oOo0Oo0o0 . strict else "s" )
   if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
  return ( oOI1i [ 0 : - 2 ] if oOI1i != "" else "" )
  if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
  if 4 - 4: Ii1I - Oo0Ooo . i1IIi + iIii1I11I1II1
 def select_elp_node ( self ) :
  Iii1 , O0O0O0O , OoO = lisp_myrlocs
  I1i11II = None
  if 50 - 50: OoOoOO00 / iII111i . I1ii11iIi11i
  for oOo0Oo0o0 in self . elp_nodes :
   if ( Iii1 and oOo0Oo0o0 . address . is_exact_match ( Iii1 ) ) :
    I1i11II = self . elp_nodes . index ( oOo0Oo0o0 )
    break
    if 26 - 26: Oo0Ooo
   if ( O0O0O0O and oOo0Oo0o0 . address . is_exact_match ( O0O0O0O ) ) :
    I1i11II = self . elp_nodes . index ( oOo0Oo0o0 )
    break
    if 61 - 61: Ii1I * oO0o * i11iIiiIii + OoO0O00
    if 43 - 43: OoO0O00 * OoO0O00 * oO0o
    if 24 - 24: oO0o
    if 77 - 77: i11iIiiIii - I1Ii111 - I1ii11iIi11i * Oo0Ooo / i11iIiiIii
    if 79 - 79: Oo0Ooo % Oo0Ooo . oO0o + ooOoO0o * iII111i * I11i
    if 87 - 87: o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo + I1IiiI
    if 89 - 89: II111iiii
  if ( I1i11II == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   oOo0Oo0o0 . we_are_last = False
   return
   if 41 - 41: iIii1I11I1II1
   if 26 - 26: Oo0Ooo / i1IIi + Oo0Ooo
   if 76 - 76: I1ii11iIi11i * i1IIi % oO0o
   if 80 - 80: i1IIi * II111iiii . O0 % I1ii11iIi11i / ooOoO0o
   if 58 - 58: I1IiiI * I1ii11iIi11i - i1IIi % I1Ii111 % O0
   if 24 - 24: I11i + I11i % I11i
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ I1i11II ] ) :
   self . use_elp_node = None
   oOo0Oo0o0 . we_are_last = True
   return
   if 63 - 63: i11iIiiIii + iIii1I11I1II1 / oO0o % IiII - O0
   if 21 - 21: II111iiii
   if 89 - 89: OOooOOo % i11iIiiIii * OoOoOO00 % oO0o / O0 * i1IIi
   if 16 - 16: IiII
   if 42 - 42: i1IIi / Ii1I * I1ii11iIi11i
  self . use_elp_node = self . elp_nodes [ I1i11II + 1 ]
  return
  if 9 - 9: I11i % i1IIi / i1IIi / OoO0O00
  if 46 - 46: I1Ii111 * II111iiii + II111iiii * O0 % II111iiii
  if 37 - 37: OOooOOo . iIii1I11I1II1 / O0 . ooOoO0o + OOooOOo - OoooooooOO
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
  if 96 - 96: I1Ii111 / oO0o . I1ii11iIi11i % I1IiiI * OOooOOo
  if 99 - 99: i11iIiiIii - I1Ii111
 def copy_geo ( self ) :
  ooOooo = lisp_geo ( self . geo_name )
  ooOooo . latitude = self . latitude
  ooOooo . lat_mins = self . lat_mins
  ooOooo . lat_secs = self . lat_secs
  ooOooo . longitude = self . longitude
  ooOooo . long_mins = self . long_mins
  ooOooo . long_secs = self . long_secs
  ooOooo . altitude = self . altitude
  ooOooo . radius = self . radius
  return ( ooOooo )
  if 4 - 4: o0oOOo0O0Ooo - i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
  if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 54 - 54: II111iiii * I1IiiI
  if 49 - 49: I1ii11iIi11i
 def parse_geo_string ( self , geo_str ) :
  I1i11II = geo_str . find ( "]" )
  if ( I1i11II != - 1 ) : geo_str = geo_str [ I1i11II + 1 : : ]
  if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
  if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
  if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
  if 15 - 15: oO0o
  if 40 - 40: I1Ii111
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , oooO0OO0 = geo_str . split ( "/" )
   self . radius = int ( oooO0OO0 )
   if 54 - 54: I1Ii111 % OoO0O00 - OoooooooOO
   if 96 - 96: IiII
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 31 - 31: Ii1I + O0 - OOooOOo * O0 * I11i
  OOooOo = geo_str [ 0 : 4 ]
  i1ii1IiiIIiI = geo_str [ 4 : 8 ]
  if 42 - 42: iII111i
  if 51 - 51: I1IiiI - OoOoOO00 * I1Ii111 * iIii1I11I1II1
  if 5 - 5: i11iIiiIii / o0oOOo0O0Ooo
  if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 12 - 12: I1ii11iIi11i / O0
  if 18 - 18: OoOoOO00 . i11iIiiIii + i1IIi / OoooooooOO - IiII % OoO0O00
  if 47 - 47: iII111i % IiII + I1Ii111 * o0oOOo0O0Ooo * OoooooooOO
  if 100 - 100: Oo0Ooo / I1IiiI / iII111i / I1Ii111 / oO0o % o0oOOo0O0Ooo
  self . latitude = int ( OOooOo [ 0 ] )
  self . lat_mins = int ( OOooOo [ 1 ] )
  self . lat_secs = int ( OOooOo [ 2 ] )
  if ( OOooOo [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 16 - 16: I1IiiI + I11i
  if 66 - 66: OoooooooOO % II111iiii / I1Ii111 . i11iIiiIii
  if 67 - 67: Ii1I + Oo0Ooo - I1IiiI - IiII + oO0o + Oo0Ooo
  if 84 - 84: I1ii11iIi11i % oO0o - OOooOOo * Ii1I
  self . longitude = int ( i1ii1IiiIIiI [ 0 ] )
  self . long_mins = int ( i1ii1IiiIIiI [ 1 ] )
  self . long_secs = int ( i1ii1IiiIIiI [ 2 ] )
  if ( i1ii1IiiIIiI [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 78 - 78: i1IIi / ooOoO0o / oO0o
  if 21 - 21: IiII % Ii1I + OOooOOo + IiII
 def print_geo ( self ) :
  oOOoO000 = "N" if self . latitude < 0 else "S"
  I1 = "E" if self . longitude < 0 else "W"
  if 96 - 96: O0 + Oo0Ooo / O0 * oO0o + i11iIiiIii
  iiIi1ii1IiI = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , oOOoO000 , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , I1 )
  if 74 - 74: OoOoOO00
  if ( self . no_geo_altitude ( ) == False ) :
   iiIi1ii1IiI += "-" + str ( self . altitude )
   if 91 - 91: i11iIiiIii / Ii1I % OOooOOo % O0 - I11i . I11i
   if 78 - 78: i1IIi + I11i % OoooooooOO + i1IIi + iII111i % Ii1I
   if 87 - 87: ooOoO0o . iIii1I11I1II1
   if 99 - 99: Ii1I + OoooooooOO * IiII * i11iIiiIii - iIii1I11I1II1
   if 58 - 58: IiII % i1IIi . i11iIiiIii
  if ( self . radius != 0 ) : iiIi1ii1IiI += "/{}" . format ( self . radius )
  return ( iiIi1ii1IiI )
  if 5 - 5: OoOoOO00
  if 75 - 75: OOooOOo
 def geo_url ( self ) :
  o0OooooO0 = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  o0OooooO0 = "10" if ( o0OooooO0 == "" or o0OooooO0 . isdigit ( ) == False ) else o0OooooO0
  ooOO00o , iiiIIiII111I = self . dms_to_decimal ( )
  o0000O = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( ooOO00o , iiiIIiII111I , ooOO00o , iiiIIiII111I ,
  # IiII % I11i / i1IIi . I1ii11iIi11i - Oo0Ooo
  # iII111i * o0oOOo0O0Ooo % i1IIi / OOooOOo
 o0OooooO0 )
  return ( o0000O )
  if 91 - 91: oO0o * i11iIiiIii
  if 61 - 61: o0oOOo0O0Ooo . Ii1I
 def print_geo_url ( self ) :
  ooOooo = self . print_geo ( )
  if ( self . radius == 0 ) :
   o0000O = self . geo_url ( )
   i1IIIII1 = "<a href='{}'>{}</a>" . format ( o0000O , ooOooo )
  else :
   o0000O = ooOooo . replace ( "/" , "-" )
   i1IIIII1 = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( o0000O , ooOooo )
   if 80 - 80: iIii1I11I1II1 . II111iiii
  return ( i1IIIII1 )
  if 50 - 50: o0oOOo0O0Ooo - O0 + OoO0O00
  if 22 - 22: I1Ii111 % O0 / I1Ii111 / I1Ii111
 def dms_to_decimal ( self ) :
  oO0ooo , Oo0OOoO0oo0oO , iii11i = self . latitude , self . lat_mins , self . lat_secs
  OOoo0oooooO = float ( abs ( oO0ooo ) )
  OOoo0oooooO += float ( Oo0OOoO0oo0oO * 60 + iii11i ) / 3600
  if ( oO0ooo > 0 ) : OOoo0oooooO = - OOoo0oooooO
  I1iIIii = OOoo0oooooO
  if 37 - 37: I11i . i11iIiiIii / Oo0Ooo . o0oOOo0O0Ooo / I1IiiI . OOooOOo
  oO0ooo , Oo0OOoO0oo0oO , iii11i = self . longitude , self . long_mins , self . long_secs
  OOoo0oooooO = float ( abs ( oO0ooo ) )
  OOoo0oooooO += float ( Oo0OOoO0oo0oO * 60 + iii11i ) / 3600
  if ( oO0ooo > 0 ) : OOoo0oooooO = - OOoo0oooooO
  i1II1iII = OOoo0oooooO
  return ( ( I1iIIii , i1II1iII ) )
  if 26 - 26: o0oOOo0O0Ooo * I1Ii111
  if 65 - 65: I11i * iIii1I11I1II1 % OoO0O00 % I11i * O0 * i1IIi
 def get_distance ( self , geo_point ) :
  iIi1i11IiI = self . dms_to_decimal ( )
  oO0O0oOoo0O0 = geo_point . dms_to_decimal ( )
  IiI1Ii = geopy . distance . distance ( iIi1i11IiI , oO0O0oOoo0O0 )
  return ( IiI1Ii . km )
  if 1 - 1: Ii1I * I1IiiI + Oo0Ooo + IiII + OOooOOo
  if 61 - 61: OoO0O00 . i1IIi / Ii1I % iII111i + Ii1I / i1IIi
 def point_in_circle ( self , geo_point ) :
  iii1Ii = self . get_distance ( geo_point )
  return ( iii1Ii <= self . radius )
  if 21 - 21: OoooooooOO
  if 76 - 76: i1IIi * i11iIiiIii / OOooOOo + I1Ii111
 def encode_geo ( self ) :
  IiI11Iiii = socket . htons ( LISP_AFI_LCAF )
  ooOoO0OOOO = socket . htons ( 20 + 2 )
  iIiOOO0oo0OO0o0 = 0
  if 50 - 50: oO0o % OoOoOO00 + I1IiiI
  ooOO00o = abs ( self . latitude )
  iii1I11I = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : iIiOOO0oo0OO0o0 |= 0x40
  if 77 - 77: I1Ii111 / IiII - OoOoOO00 + I1Ii111 % Oo0Ooo
  iiiIIiII111I = abs ( self . longitude )
  OO00o0 = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : iIiOOO0oo0OO0o0 |= 0x20
  if 42 - 42: O0 + oO0o - OoooooooOO - OoOoOO00 + O0
  IIii1I = 0
  if ( self . no_geo_altitude ( ) == False ) :
   IIii1I = socket . htonl ( self . altitude )
   iIiOOO0oo0OO0o0 |= 0x10
   if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
  oooO0OO0 = socket . htons ( self . radius )
  if ( oooO0OO0 != 0 ) : iIiOOO0oo0OO0o0 |= 0x06
  if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
  II11 = struct . pack ( "HBBBBH" , IiI11Iiii , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , ooOoO0OOOO )
  II11 += struct . pack ( "BBHBBHBBHIHHH" , iIiOOO0oo0OO0o0 , 0 , 0 , ooOO00o , iii1I11I >> 16 ,
 socket . htons ( iii1I11I & 0x0ffff ) , iiiIIiII111I , OO00o0 >> 16 ,
 socket . htons ( OO00o0 & 0xffff ) , IIii1I , oooO0OO0 , 0 , 0 )
  if 23 - 23: OoOoOO00
  return ( II11 )
  if 54 - 54: i1IIi / I11i % O0 - Ii1I - Oo0Ooo - OoO0O00
  if 63 - 63: o0oOOo0O0Ooo
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  Iii1I = "BBHBBHBBHIHHH"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( lcaf_len < IiiiiI ) : return ( None )
  if 46 - 46: Oo0Ooo . ooOoO0o + OoOoOO00 - I11i / i11iIiiIii . iII111i
  iIiOOO0oo0OO0o0 , Oo0OO0o , I11II , ooOO00o , o0o0000OoO0oO , iii1I11I , iiiIIiII111I , o00O0oOoO , OO00o0 , IIii1I , oooO0OO0 , i1iI , i1I1iiiI = struct . unpack ( Iii1I ,
  # OoooooooOO
 packet [ : IiiiiI ] )
  if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
  if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
  if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
  if 42 - 42: OOooOOo
  i1I1iiiI = socket . ntohs ( i1I1iiiI )
  if ( i1I1iiiI == LISP_AFI_LCAF ) : return ( None )
  if 36 - 36: OoooooooOO + ooOoO0o + iII111i
  if ( iIiOOO0oo0OO0o0 & 0x40 ) : ooOO00o = - ooOO00o
  self . latitude = ooOO00o
  ii1i11IiIi1 = ( ( o0o0000OoO0oO << 16 ) | socket . ntohs ( iii1I11I ) ) / 1000
  self . lat_mins = ii1i11IiIi1 / 60
  self . lat_secs = ii1i11IiIi1 % 60
  if 90 - 90: OoO0O00
  if ( iIiOOO0oo0OO0o0 & 0x20 ) : iiiIIiII111I = - iiiIIiII111I
  self . longitude = iiiIIiII111I
  I1iI1I1 = ( ( o00O0oOoO << 16 ) | socket . ntohs ( OO00o0 ) ) / 1000
  self . long_mins = I1iI1I1 / 60
  self . long_secs = I1iI1I1 % 60
  if 96 - 96: IiII % iII111i . OoOoOO00 / oO0o . OoO0O00
  self . altitude = socket . ntohl ( IIii1I ) if ( iIiOOO0oo0OO0o0 & 0x10 ) else - 1
  oooO0OO0 = socket . ntohs ( oooO0OO0 )
  self . radius = oooO0OO0 if ( iIiOOO0oo0OO0o0 & 0x02 ) else oooO0OO0 * 1000
  if 85 - 85: iIii1I11I1II1 / OoOoOO00 * I1ii11iIi11i
  self . geo_name = None
  packet = packet [ IiiiiI : : ]
  if 26 - 26: iII111i - OoO0O00 . o0oOOo0O0Ooo
  if ( i1I1iiiI != 0 ) :
   self . rloc . afi = i1I1iiiI
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
  return ( packet )
  if 65 - 65: I1IiiI % iIii1I11I1II1
  if 52 - 52: I1IiiI
  if 19 - 19: I1IiiI
  if 17 - 17: I11i + OoooooooOO
  if 63 - 63: IiII
  if 3 - 3: oO0o * II111iiii . O0
class lisp_rle_node ( ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
  if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
 def copy_rle_node ( self ) :
  o0Ii11I = lisp_rle_node ( )
  o0Ii11I . address . copy_address ( self . address )
  o0Ii11I . level = self . level
  o0Ii11I . translated_port = self . translated_port
  o0Ii11I . rloc_name = self . rloc_name
  return ( o0Ii11I )
  if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
  if 51 - 51: oO0o - I1ii11iIi11i + I1ii11iIi11i
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 100 - 100: I11i - I1ii11iIi11i . i1IIi
  if 85 - 85: II111iiii
 def get_encap_keys ( self ) :
  IiO0o = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 58 - 58: i1IIi - OoO0O00 + ooOoO0o
  O0O0 = self . address . print_address_no_iid ( ) + ":" + IiO0o
  if 6 - 6: IiII % I1IiiI + OoooooooOO * oO0o . iII111i + oO0o
  try :
   IiI11I1iiii1 = lisp_crypto_keys_by_rloc_encap [ O0O0 ]
   if ( IiI11I1iiii1 [ 1 ] ) : return ( IiI11I1iiii1 [ 1 ] . encrypt_key , IiI11I1iiii1 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 4 - 4: I11i % I1IiiI
   if 72 - 72: I1IiiI % II111iiii % iII111i / OoOoOO00
   if 96 - 96: OoOoOO00 % Ii1I
   if 50 - 50: IiII - II111iiii
class lisp_rle ( ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 10 - 10: OoooooooOO % Ii1I * OOooOOo + IiII * oO0o
  if 13 - 13: II111iiii
 def copy_rle ( self ) :
  O0OOO = lisp_rle ( self . rle_name )
  for o0Ii11I in self . rle_nodes :
   O0OOO . rle_nodes . append ( o0Ii11I . copy_rle_node ( ) )
   if 14 - 14: i11iIiiIii . IiII
  O0OOO . build_forwarding_list ( )
  return ( O0OOO )
  if 70 - 70: Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
  if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
 def print_rle ( self , html , do_formatting ) :
  OooOO = ""
  for o0Ii11I in self . rle_nodes :
   IiO0o = o0Ii11I . translated_port
   if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
   Ooo00oo = ""
   if ( o0Ii11I . rloc_name != None ) :
    Ooo00oo = o0Ii11I . rloc_name
    if ( do_formatting ) : Ooo00oo = blue ( Ooo00oo , html )
    Ooo00oo = "({})" . format ( Ooo00oo )
    if 39 - 39: OoO0O00 . II111iiii + iII111i + I1IiiI + ooOoO0o . OoooooooOO
    if 20 - 20: IiII * iII111i * I1Ii111 * I1ii11iIi11i * oO0o
   O0O0 = o0Ii11I . address . print_address_no_iid ( )
   if ( o0Ii11I . address . is_local ( ) ) : O0O0 = red ( O0O0 , html )
   OooOO += "{}{}{}, " . format ( O0O0 , "" if IiO0o == 0 else ":" + str ( IiO0o ) , Ooo00oo )
   if 58 - 58: o0oOOo0O0Ooo
   if 5 - 5: O0
  return ( OooOO [ 0 : - 2 ] if OooOO != "" else "" )
  if 23 - 23: OOooOOo . i11iIiiIii % o0oOOo0O0Ooo - OoOoOO00 * OoooooooOO - OoO0O00
  if 51 - 51: iIii1I11I1II1 / I1ii11iIi11i
 def build_forwarding_list ( self ) :
  I1i11 = - 1
  for o0Ii11I in self . rle_nodes :
   if ( I1i11 == - 1 ) :
    if ( o0Ii11I . address . is_local ( ) ) : I1i11 = o0Ii11I . level
   else :
    if ( o0Ii11I . level > I1i11 ) : break
    if 83 - 83: ooOoO0o % I1IiiI - OoOoOO00 - I11i
    if 12 - 12: I1Ii111 . OoO0O00 + I11i * OoO0O00 - IiII + I11i
  I1i11 = 0 if I1i11 == - 1 else o0Ii11I . level
  if 98 - 98: iII111i . I1Ii111 * IiII - Ii1I * OoooooooOO
  self . rle_forwarding_list = [ ]
  for o0Ii11I in self . rle_nodes :
   if ( o0Ii11I . level == I1i11 or ( I1i11 == 0 and
 o0Ii11I . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and o0Ii11I . address . is_local ( ) ) :
     O0O0 = o0Ii11I . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( O0O0 ) )
     continue
     if 13 - 13: iII111i
    self . rle_forwarding_list . append ( o0Ii11I )
    if 76 - 76: iIii1I11I1II1 + Oo0Ooo
    if 40 - 40: oO0o % i1IIi % ooOoO0o . oO0o % oO0o
    if 69 - 69: OoooooooOO . oO0o / OoooooooOO / OoOoOO00
    if 41 - 41: ooOoO0o + o0oOOo0O0Ooo . o0oOOo0O0Ooo / oO0o * IiII
    if 96 - 96: IiII % O0 + Ii1I / o0oOOo0O0Ooo + I1ii11iIi11i * II111iiii
class lisp_json ( ) :
 def __init__ ( self , name , string , encrypted = False , ms_encrypt = False ) :
  self . json_name = name
  self . json_encrypted = False
  try :
   json . loads ( string )
  except :
   lprint ( "Invalid JSON string: '{}'" . format ( string ) )
   string = '{ "?" : "?" }'
   if 65 - 65: Ii1I * Oo0Ooo * Oo0Ooo . Ii1I
  self . json_string = string
  if 4 - 4: i11iIiiIii - iIii1I11I1II1 % o0oOOo0O0Ooo * oO0o
  if 19 - 19: Ii1I
  if 47 - 47: IiII - IiII
  if 33 - 33: ooOoO0o
  if 23 - 23: I1Ii111 + OoO0O00
  if 35 - 35: Oo0Ooo - iIii1I11I1II1 - I1Ii111 % OOooOOo
  if 59 - 59: i1IIi
  if 38 - 38: Oo0Ooo . o0oOOo0O0Ooo % oO0o / i11iIiiIii * OoO0O00 % OoOoOO00
  if 18 - 18: OOooOOo
  if 12 - 12: I1Ii111 % II111iiii / o0oOOo0O0Ooo - iIii1I11I1II1 + II111iiii
  if ( len ( lisp_ms_json_keys ) != 0 ) :
   if ( ms_encrypt == False ) : return
   self . json_key_id = lisp_ms_json_keys . keys ( ) [ 0 ]
   self . json_key = lisp_ms_json_keys [ self . json_key_id ]
   self . encrypt_json ( )
   if 41 - 41: OOooOOo
   if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
  if ( lisp_log_id == "lig" and encrypted ) :
   OO0Oo00o0o0 = os . getenv ( "LISP_JSON_KEY" )
   if ( OO0Oo00o0o0 != None ) :
    I1i11II = - 1
    if ( OO0Oo00o0o0 [ 0 ] == "[" and "]" in OO0Oo00o0o0 ) :
     I1i11II = OO0Oo00o0o0 . find ( "]" )
     self . json_key_id = int ( OO0Oo00o0o0 [ 1 : I1i11II ] )
     if 64 - 64: I1IiiI . Oo0Ooo * OoO0O00
    self . json_key = OO0Oo00o0o0 [ I1i11II + 1 : : ]
    if 87 - 87: i1IIi / OoooooooOO
    self . decrypt_json ( )
    if 68 - 68: I1Ii111 / iIii1I11I1II1
    if 8 - 8: ooOoO0o * IiII * OOooOOo / I1IiiI
    if 40 - 40: i11iIiiIii + OoooooooOO
    if 2 - 2: o0oOOo0O0Ooo * OoO0O00
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 88 - 88: Oo0Ooo + oO0o + iII111i
  if 51 - 51: i1IIi + i11iIiiIii * I11i / iII111i + OoooooooOO
 def delete ( self ) :
  if ( lisp_json_list . has_key ( self . json_name ) ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 89 - 89: i11iIiiIii - I1Ii111 - O0 % iIii1I11I1II1 / IiII - O0
   if 63 - 63: OOooOOo
   if 23 - 23: Oo0Ooo / i1IIi - OOooOOo / Oo0Ooo
 def print_json ( self , html ) :
  IIiiiiII = self . json_string
  II1iiiiIIIII = "***"
  if ( html ) : II1iiiiIIIII = red ( II1iiiiIIIII , html )
  O00O0oo0O0OOo = II1iiiiIIIII + self . json_string + II1iiiiIIIII
  if ( self . valid_json ( ) ) : return ( IIiiiiII )
  return ( O00O0oo0O0OOo )
  if 14 - 14: O0 * oO0o + i11iIiiIii / iII111i + OoO0O00 . I1Ii111
  if 3 - 3: oO0o % OoooooooOO - O0
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 86 - 86: OoooooooOO - oO0o * o0oOOo0O0Ooo
  return ( True )
  if 76 - 76: I1IiiI
  if 94 - 94: OoooooooOO * I1ii11iIi11i
 def encrypt_json ( self ) :
  OooOo0o = self . json_key . zfill ( 32 )
  OoOooO = "0" * 8
  if 28 - 28: II111iiii / II111iiii / II111iiii
  oO0oOo = json . loads ( self . json_string )
  for OO0Oo00o0o0 in oO0oOo :
   iiIiII11i1 = oO0oOo [ OO0Oo00o0o0 ]
   if ( type ( iiIiII11i1 ) != str ) : iiIiII11i1 = str ( iiIiII11i1 )
   iiIiII11i1 = chacha . ChaCha ( OooOo0o , OoOooO ) . encrypt ( iiIiII11i1 )
   oO0oOo [ OO0Oo00o0o0 ] = binascii . hexlify ( iiIiII11i1 )
   if 88 - 88: OoooooooOO
  self . json_string = json . dumps ( oO0oOo )
  self . json_encrypted = True
  if 47 - 47: OOooOOo + Oo0Ooo * I11i
  if 8 - 8: Ii1I % i1IIi
 def decrypt_json ( self ) :
  OooOo0o = self . json_key . zfill ( 32 )
  OoOooO = "0" * 8
  if 29 - 29: oO0o % OoOoOO00 / OoOoOO00
  oO0oOo = json . loads ( self . json_string )
  for OO0Oo00o0o0 in oO0oOo :
   iiIiII11i1 = binascii . unhexlify ( oO0oOo [ OO0Oo00o0o0 ] )
   oO0oOo [ OO0Oo00o0o0 ] = chacha . ChaCha ( OooOo0o , OoOooO ) . encrypt ( iiIiII11i1 )
   if 79 - 79: IiII % OoooooooOO
  try :
   self . json_string = json . dumps ( oO0oOo )
   self . json_encrypted = False
  except :
   pass
   if 51 - 51: iII111i . oO0o % ooOoO0o % Ii1I . o0oOOo0O0Ooo
   if 43 - 43: II111iiii
   if 72 - 72: OoOoOO00 * oO0o - ooOoO0o / iII111i
   if 8 - 8: OoO0O00 * I1ii11iIi11i
   if 18 - 18: O0 + I1Ii111 . I1ii11iIi11i
   if 48 - 48: Ii1I . o0oOOo0O0Ooo * O0 / OoooooooOO + I1Ii111 + Oo0Ooo
   if 92 - 92: Ii1I - o0oOOo0O0Ooo % I1IiiI + I1Ii111
class lisp_stats ( ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 3 - 3: iIii1I11I1II1 + i11iIiiIii
  if 49 - 49: OoOoOO00 % iIii1I11I1II1 + I1Ii111
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 38 - 38: i11iIiiIii
  if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  Ii1i1 = time . time ( ) - self . last_increment
  return ( Ii1i1 <= 1 )
  if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
  if 7 - 7: Oo0Ooo . iII111i % I1ii11iIi11i / iII111i
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  Ii1i1 = time . time ( ) - self . last_increment
  return ( Ii1i1 <= 60 )
  if 93 - 93: iII111i
  if 5 - 5: iII111i . I11i % I11i * Ii1I - I1ii11iIi11i . i11iIiiIii
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 32 - 32: II111iiii
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 58 - 58: I1IiiI - o0oOOo0O0Ooo - I1Ii111 . O0 % OoO0O00 . I11i
  return ( c1 , c2 )
  if 41 - 41: iII111i . I1Ii111 - IiII / O0
  if 62 - 62: IiII * I1ii11iIi11i * iII111i * OoOoOO00
 def normalize ( self , count ) :
  count = str ( count )
  IIi11111iii1 = len ( count )
  if ( IIi11111iii1 > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 39 - 39: II111iiii % OoOoOO00 / O0 / II111iiii
  if ( IIi11111iii1 > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 15 - 15: I11i + I1IiiI / I11i + iIii1I11I1II1 * Oo0Ooo / I1ii11iIi11i
  if ( IIi11111iii1 > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 8 - 8: ooOoO0o . O0 / OoO0O00
  return ( count )
  if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
  if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
 def get_stats ( self , summary , html ) :
  o0000ooOO = self . last_rate_check
  O000o = self . last_packet_count
  iI1Ii1 = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 43 - 43: i1IIi / I1ii11iIi11i
  O0O0OI1IIiI1IIIii = self . last_rate_check - o0000ooOO
  if ( O0O0OI1IIiI1IIIii == 0 ) :
   oo0ooO0o0 = 0
   I1I11II1I = 0
  else :
   oo0ooO0o0 = int ( ( self . packet_count - O000o ) / O0O0OI1IIiI1IIIii )
   I1I11II1I = ( self . byte_count - iI1Ii1 ) / O0O0OI1IIiI1IIIii
   I1I11II1I = ( I1I11II1I * 8 ) / 1000000
   I1I11II1I = round ( I1I11II1I , 2 )
   if 59 - 59: OoOoOO00 * iII111i - OOooOOo
   if 49 - 49: I1ii11iIi11i / oO0o . oO0o * iII111i % iII111i . I1IiiI
   if 96 - 96: II111iiii / OoooooooOO + iIii1I11I1II1 . Ii1I + OoooooooOO
   if 62 - 62: OoOoOO00 + OoOoOO00 % OOooOOo * iII111i
   if 24 - 24: Oo0Ooo % i1IIi
  iIiIIi = self . normalize ( self . packet_count )
  iIIiI11 = self . normalize ( self . byte_count )
  if 59 - 59: OoOoOO00 % O0 * I1Ii111 - i1IIi
  if 68 - 68: OOooOOo % IiII / Oo0Ooo + OoOoOO00
  if 11 - 11: OoO0O00
  if 70 - 70: o0oOOo0O0Ooo * O0 * II111iiii
  if 38 - 38: OoO0O00 - I1IiiI * OoooooooOO / I11i . O0
  if ( summary ) :
   O00Ooo = "<br>" if html else ""
   iIiIIi , iIIiI11 = self . stat_colors ( iIiIIi , iIIiI11 , html )
   IIIiI1I1i1i1III = "packet-count: {}{}byte-count: {}" . format ( iIiIIi , O00Ooo , iIIiI11 )
   OO000 = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( oo0ooO0o0 , I1I11II1I )
   if 80 - 80: IiII % Ii1I - iIii1I11I1II1 - OoO0O00 . i1IIi . II111iiii
   if ( html != "" ) : OO000 = lisp_span ( IIIiI1I1i1i1III , OO000 )
  else :
   OOOOo0Oo0O0oo = str ( oo0ooO0o0 )
   O000ii = str ( I1I11II1I )
   if ( html ) :
    iIiIIi = lisp_print_cour ( iIiIIi )
    OOOOo0Oo0O0oo = lisp_print_cour ( OOOOo0Oo0O0oo )
    iIIiI11 = lisp_print_cour ( iIIiI11 )
    O000ii = lisp_print_cour ( O000ii )
    if 11 - 11: Oo0Ooo % I1Ii111 * oO0o % I1ii11iIi11i / o0oOOo0O0Ooo * O0
   O00Ooo = "<br>" if html else ", "
   if 27 - 27: OOooOOo
   OO000 = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( iIiIIi , O00Ooo , OOOOo0Oo0O0oo , O00Ooo , iIIiI11 , O00Ooo ,
   # OOooOOo . ooOoO0o / OOooOOo + i1IIi / I1IiiI
 O000ii )
   if 80 - 80: Oo0Ooo + Oo0Ooo + oO0o % i1IIi / ooOoO0o
  return ( OO000 )
  if 24 - 24: i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1 . I1IiiI
  if 81 - 81: OoOoOO00 * OoOoOO00 + OOooOOo . I11i - oO0o
  if 85 - 85: O0 * I1IiiI . Oo0Ooo - IiII
  if 84 - 84: I1Ii111 . iIii1I11I1II1 . O0 * I1ii11iIi11i
  if 59 - 59: i1IIi . o0oOOo0O0Ooo . Oo0Ooo * I1Ii111 + OoooooooOO
  if 11 - 11: I11i * ooOoO0o % iIii1I11I1II1 - O0
  if 68 - 68: ooOoO0o * OoooooooOO - OoooooooOO
  if 59 - 59: Ii1I / I11i / I1Ii111 + IiII * I1ii11iIi11i
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 18 - 18: O0
if 60 - 60: II111iiii % O0 - I1Ii111 / iII111i / I1IiiI
if 59 - 59: O0 / iIii1I11I1II1
if 49 - 49: O0 + I1IiiI
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
  self . uptime = lisp_get_timestamp ( )
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
  if 52 - 52: oO0o
  if ( recurse == False ) : return
  if 56 - 56: ooOoO0o
  if 94 - 94: OoOoOO00
  if 12 - 12: I11i * OoooooooOO + ooOoO0o
  if 16 - 16: IiII
  if 100 - 100: OoO0O00 % Oo0Ooo - OoooooooOO
  if 48 - 48: IiII / I11i * OoooooooOO
  iI1I111 = lisp_get_default_route_next_hops ( )
  if ( iI1I111 == [ ] or len ( iI1I111 ) == 1 ) : return
  if 89 - 89: OoO0O00
  self . rloc_next_hop = iI1I111 [ 0 ]
  i11iII11I1III = self
  for Oo00 in iI1I111 [ 1 : : ] :
   iI1iiiiiiiiI = lisp_rloc ( False )
   iI1iiiiiiiiI = copy . deepcopy ( self )
   iI1iiiiiiiiI . rloc_next_hop = Oo00
   i11iII11I1III . next_rloc = iI1iiiiiiiiI
   i11iII11I1III = iI1iiiiiiiiI
   if 84 - 84: Ii1I
   if 92 - 92: I11i
   if 64 - 64: iII111i / iII111i * iII111i % O0 / IiII . I1ii11iIi11i
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 23 - 23: i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
  if 82 - 82: O0 * ooOoO0o * iIii1I11I1II1 . i1IIi
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 47 - 47: I11i * I11i . OoOoOO00
  if 68 - 68: OoooooooOO + OoOoOO00 + i11iIiiIii
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 89 - 89: Oo0Ooo + Ii1I * O0 - I1Ii111
  if 33 - 33: iIii1I11I1II1 . I11i
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 63 - 63: oO0o - iII111i
  if 13 - 13: I1Ii111 / i1IIi % OoooooooOO / I11i
  if 66 - 66: I1Ii111 % o0oOOo0O0Ooo . iII111i . ooOoO0o + OOooOOo * II111iiii
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
  if 33 - 33: oO0o
  if 64 - 64: OoO0O00 % Oo0Ooo % I11i . iII111i % I1IiiI
 def print_rloc ( self , indent ) :
  ii1III11 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , ii1III11 , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 50 - 50: i1IIi + ooOoO0o - iIii1I11I1II1
  if 45 - 45: OoooooooOO / o0oOOo0O0Ooo / iII111i
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  oOoOoO0Oo0oo = self . rloc_name
  if ( cour ) : oOoOoO0Oo0oo = lisp_print_cour ( oOoOoO0Oo0oo )
  return ( 'rloc-name: {}' . format ( blue ( oOoOoO0Oo0oo , cour ) ) )
  if 72 - 72: I1Ii111
  if 94 - 94: ooOoO0o . IiII - Ii1I + I1ii11iIi11i / ooOoO0o
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  IiO0o = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 10 - 10: ooOoO0o . OOooOOo * O0 % II111iiii
  if 12 - 12: oO0o + I1IiiI * Oo0Ooo - iII111i
  if 88 - 88: OOooOOo . OoO0O00
  if 86 - 86: OoOoOO00 . o0oOOo0O0Ooo / ooOoO0o * I1IiiI . OoO0O00 / I1Ii111
  IIIi1iI1 = self . rloc
  if ( IIIi1iI1 . is_null ( ) == False ) :
   I1OOoO0OoOOo0 = lisp_get_nat_info ( IIIi1iI1 , self . rloc_name )
   if ( I1OOoO0OoOOo0 ) :
    IiO0o = I1OOoO0OoOOo0 . port
    o00O00oo0 = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    O0O0 = IIIi1iI1 . print_address_no_iid ( )
    iI = red ( O0O0 , False )
    OoooOo = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 36 - 36: o0oOOo0O0Ooo + I1Ii111 / iII111i
    if 48 - 48: I1IiiI % ooOoO0o * o0oOOo0O0Ooo * II111iiii - OoOoOO00
    if 12 - 12: I1IiiI - Oo0Ooo / I11i
    if 79 - 79: II111iiii . I1Ii111 * I1Ii111 + I11i + I1Ii111 % I1IiiI
    if 42 - 42: I11i - i1IIi . Oo0Ooo - i1IIi
    if 87 - 87: O0 . o0oOOo0O0Ooo % OOooOOo / I11i - I1Ii111 % i11iIiiIii
    if ( I1OOoO0OoOOo0 . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( iI , IiO0o , OoooOo ) )
     if 3 - 3: oO0o + iII111i + OOooOOo
     if 54 - 54: i11iIiiIii + OoO0O00 - IiII - iII111i / I11i
     I1OOoO0OoOOo0 = None if ( I1OOoO0OoOOo0 == o00O00oo0 ) else o00O00oo0
     if ( I1OOoO0OoOOo0 and I1OOoO0OoOOo0 . timed_out ( ) ) :
      IiO0o = I1OOoO0OoOOo0 . port
      iI = red ( I1OOoO0OoOOo0 . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( iI , IiO0o ,
      # iII111i * ooOoO0o % I1ii11iIi11i % i11iIiiIii * I11i * O0
 OoooOo ) )
      I1OOoO0OoOOo0 = None
      if 82 - 82: oO0o
      if 91 - 91: iII111i . o0oOOo0O0Ooo
      if 53 - 53: O0 % OoooooooOO / Oo0Ooo - IiII
      if 92 - 92: OoO0O00 / OOooOOo * IiII * iIii1I11I1II1 / IiII
      if 79 - 79: iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
      if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
      if 65 - 65: OoOoOO00
    if ( I1OOoO0OoOOo0 ) :
     if ( I1OOoO0OoOOo0 . address != O0O0 ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( iI , red ( I1OOoO0OoOOo0 . address , False ) ) )
      if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
      self . rloc . store_address ( I1OOoO0OoOOo0 . address )
      if 58 - 58: OoO0O00 * I1IiiI - II111iiii / Ii1I - I1IiiI % OoooooooOO
     iI = red ( I1OOoO0OoOOo0 . address , False )
     IiO0o = I1OOoO0OoOOo0 . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( iI , IiO0o , OoooOo ) )
     if 33 - 33: IiII / i1IIi + I1Ii111
     self . store_translated_rloc ( IIIi1iI1 , IiO0o )
     if 5 - 5: O0 / iII111i % II111iiii . Oo0Ooo - I11i
     if 84 - 84: oO0o * iII111i % i11iIiiIii - O0 . iIii1I11I1II1 - OoOoOO00
     if 73 - 73: OoOoOO00
     if 66 - 66: Oo0Ooo
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 42 - 42: i11iIiiIii / II111iiii . OOooOOo
  if 65 - 65: OoOoOO00 % II111iiii + Oo0Ooo
  if 24 - 24: OoO0O00 % OoooooooOO
  if 16 - 16: OoOoOO00 % Oo0Ooo * OoOoOO00 . Ii1I
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for o0Ii11I in self . rle . rle_nodes :
    oOoOoO0Oo0oo = o0Ii11I . rloc_name
    I1OOoO0OoOOo0 = lisp_get_nat_info ( o0Ii11I . address , oOoOoO0Oo0oo )
    if ( I1OOoO0OoOOo0 == None ) : continue
    if 91 - 91: I1Ii111 - OoooooooOO . i1IIi . I1ii11iIi11i
    IiO0o = I1OOoO0OoOOo0 . port
    Ooo0oOO = oOoOoO0Oo0oo
    if ( Ooo0oOO ) : Ooo0oOO = blue ( oOoOoO0Oo0oo , False )
    if 37 - 37: IiII - oO0o
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( IiO0o ,
    # I1IiiI . oO0o - OoO0O00 + Oo0Ooo - OOooOOo + I1ii11iIi11i
 o0Ii11I . address . print_address_no_iid ( ) , Ooo0oOO ) )
    o0Ii11I . translated_port = IiO0o
    if 32 - 32: I1ii11iIi11i % OoOoOO00 + Oo0Ooo
    if 92 - 92: II111iiii . O0 . iIii1I11I1II1 % IiII - i11iIiiIii
    if 9 - 9: OoO0O00
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 60 - 60: O0 / OoOoOO00 % i11iIiiIii % II111iiii / OoooooooOO
  if 52 - 52: ooOoO0o
  if 100 - 100: Oo0Ooo - o0oOOo0O0Ooo + iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1
  if 4 - 4: OoOoOO00 / Oo0Ooo - OoO0O00 . OoOoOO00 / I1Ii111
  o00oO00o0Ooo = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 97 - 97: II111iiii * o0oOOo0O0Ooo
  if ( rloc_record . keys != None and o00oO00o0Ooo ) :
   OO0Oo00o0o0 = rloc_record . keys [ 1 ]
   if ( OO0Oo00o0o0 != None ) :
    O0O0 = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( IiO0o )
    if 13 - 13: o0oOOo0O0Ooo . II111iiii
    OO0Oo00o0o0 . add_key_by_rloc ( O0O0 , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( O0O0 , False ) ) )
    if 76 - 76: II111iiii + I1Ii111 . OoooooooOO / IiII % i11iIiiIii
    if 87 - 87: Ii1I / OoOoOO00 / OOooOOo
    if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
  return ( IiO0o )
  if 19 - 19: i1IIi + IiII . OoO0O00 / O0 - I1Ii111 - Oo0Ooo
  if 24 - 24: iII111i + i1IIi
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 31 - 31: OoOoOO00
  if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 43 - 43: II111iiii - OoooooooOO
  if 11 - 11: I1IiiI
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
  return ( True )
  if 64 - 64: OoO0O00 - OoO0O00
  if 93 - 93: Oo0Ooo . O0
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 75 - 75: iII111i * II111iiii - I1IiiI
  if 30 - 30: i1IIi / ooOoO0o . ooOoO0o
  if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
 def print_state_change ( self , new_state ) :
  OoiI1iII1Ii111I = self . print_state ( )
  i1IIIII1 = "{} -> {}" . format ( OoiI1iII1Ii111I , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   i1IIIII1 = bold ( i1IIIII1 , False )
   if 51 - 51: I1Ii111 % i11iIiiIii + i1IIi - OOooOOo - Ii1I + oO0o
  return ( i1IIIII1 )
  if 5 - 5: Oo0Ooo / I1ii11iIi11i / ooOoO0o / o0oOOo0O0Ooo - i1IIi + IiII
  if 25 - 25: OoOoOO00 / ooOoO0o
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 73 - 73: iII111i
  if 34 - 34: o0oOOo0O0Ooo * I1ii11iIi11i
 def print_recent_rloc_probe_rtts ( self ) :
  i1ii = str ( self . recent_rloc_probe_rtts )
  i1ii = i1ii . replace ( "-1" , "?" )
  return ( i1ii )
  if 92 - 92: o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
  if 33 - 33: I1IiiI + O0 - I11i
 def compute_rloc_probe_rtt ( self ) :
  i11iII11I1III = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  O0oo0ooOO00O0 = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ i11iII11I1III ] + O0oo0ooOO00O0 [ 0 : - 1 ]
  if 9 - 9: IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
  if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 38 - 38: O0 % I1ii11iIi11i + O0
  if 37 - 37: Oo0Ooo / I1IiiI
 def print_recent_rloc_probe_hops ( self ) :
  ii1I = str ( self . recent_rloc_probe_hops )
  return ( ii1I )
  if 61 - 61: iII111i . I1Ii111 % OoooooooOO / I1Ii111
  if 8 - 8: OoOoOO00
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < LISP_RLOC_PROBE_TTL / 2 ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 80 - 80: IiII + I1ii11iIi11i + ooOoO0o
  if ( from_ttl < LISP_RLOC_PROBE_TTL / 2 ) :
   ii1ii = "!"
  else :
   ii1ii = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 10 - 10: Ii1I / I1Ii111 / O0 - II111iiii % IiII - ooOoO0o
   if 48 - 48: OOooOOo * OoOoOO00 / oO0o + II111iiii - I1ii11iIi11i
  i11iII11I1III = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + ii1ii
  O0oo0ooOO00O0 = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ i11iII11I1III ] + O0oo0ooOO00O0 [ 0 : - 1 ]
  if 85 - 85: I1ii11iIi11i * OoooooooOO . OOooOOo * OOooOOo
  if 13 - 13: I1IiiI / Ii1I - OoOoOO00 . i1IIi * oO0o * o0oOOo0O0Ooo
 def store_rloc_probe_latencies ( self , json_telemetry ) :
  I111I1Ii = lisp_decode_telemetry ( json_telemetry )
  if 45 - 45: I1Ii111 / Oo0Ooo * OOooOOo / Oo0Ooo
  IIiii1iii1II = round ( float ( I111I1Ii [ "etr-in" ] ) - float ( I111I1Ii [ "itr-out" ] ) , 3 )
  ooo00OOO = round ( float ( I111I1Ii [ "itr-in" ] ) - float ( I111I1Ii [ "etr-out" ] ) , 3 )
  if 56 - 56: I1Ii111 . iIii1I11I1II1
  i11iII11I1III = self . rloc_probe_latency
  self . rloc_probe_latency = str ( IIiii1iii1II ) + "/" + str ( ooo00OOO )
  O0oo0ooOO00O0 = self . recent_rloc_probe_latencies
  self . recent_rloc_probe_latencies = [ i11iII11I1III ] + O0oo0ooOO00O0 [ 0 : - 1 ]
  if 25 - 25: OoooooooOO % I1ii11iIi11i % Oo0Ooo % i11iIiiIii
  if 8 - 8: O0 - O0 % Ii1I
 def print_rloc_probe_latency ( self ) :
  return ( self . rloc_probe_latency )
  if 22 - 22: OoOoOO00
  if 85 - 85: II111iiii - II111iiii
 def print_recent_rloc_probe_latencies ( self ) :
  ooOo0OOo0ooO00OOO0OO = str ( self . recent_rloc_probe_latencies )
  return ( ooOo0OOo0ooO00OOO0OO )
  if 43 - 43: Ii1I * OOooOOo + OoO0O00 . Oo0Ooo % Ii1I . OoO0O00
  if 90 - 90: I1Ii111 . OoooooooOO * ooOoO0o
 def process_rloc_probe_reply ( self , ts , nonce , eid , group , hc , ttl , jt ) :
  IIIi1iI1 = self
  while ( True ) :
   if ( IIIi1iI1 . last_rloc_probe_nonce == nonce ) : break
   IIIi1iI1 = IIIi1iI1 . next_rloc
   if ( IIIi1iI1 == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 82 - 82: ooOoO0o
    return
    if 80 - 80: I1Ii111 / I11i - Oo0Ooo / IiII % O0
    if 67 - 67: i11iIiiIii / I11i - iII111i - OOooOOo . II111iiii
    if 16 - 16: Ii1I * iIii1I11I1II1 + i11iIiiIii - OoOoOO00 - o0oOOo0O0Ooo
    if 60 - 60: O0 - iIii1I11I1II1
    if 56 - 56: OOooOOo * o0oOOo0O0Ooo - O0
    if 45 - 45: OOooOOo - OoO0O00
  IIIi1iI1 . last_rloc_probe_reply = ts
  IIIi1iI1 . compute_rloc_probe_rtt ( )
  iI1II = IIIi1iI1 . print_state_change ( "up" )
  if ( IIIi1iI1 . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( IIIi1iI1 . rloc , True )
   IIIi1iI1 . state = LISP_RLOC_UP_STATE
   IIIi1iI1 . last_state_change = lisp_get_timestamp ( )
   ooOoOO0Oo = lisp_map_cache . lookup_cache ( eid , True )
   if ( ooOoOO0Oo ) : lisp_write_ipc_map_cache ( True , ooOoOO0Oo )
   if 50 - 50: iIii1I11I1II1 - OoooooooOO + I1ii11iIi11i / Oo0Ooo * OOooOOo
   if 37 - 37: O0 % I1Ii111 * OOooOOo / OOooOOo
   if 95 - 95: I1ii11iIi11i % o0oOOo0O0Ooo . oO0o
   if 9 - 9: OoOoOO00 % OoOoOO00 * ooOoO0o / I1IiiI - OOooOOo
   if 62 - 62: Oo0Ooo + OOooOOo - Oo0Ooo
  IIIi1iI1 . store_rloc_probe_hops ( hc , ttl )
  if 32 - 32: OoooooooOO
  if 99 - 99: II111iiii % Oo0Ooo / OOooOOo / I1ii11iIi11i % O0 + i1IIi
  if 90 - 90: OoOoOO00 % OoO0O00 . I1IiiI * oO0o
  if 17 - 17: O0 - i1IIi
  if ( jt ) : IIIi1iI1 . store_rloc_probe_latencies ( jt )
  if 77 - 77: OOooOOo - i1IIi / II111iiii . I1Ii111 + O0
  OoO0oo0O = bold ( "RLOC-probe reply" , False )
  O0O0 = IIIi1iI1 . rloc . print_address_no_iid ( )
  ii1iIiI111 = bold ( str ( IIIi1iI1 . print_rloc_probe_rtt ( ) ) , False )
  IIIiIIi111 = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 21 - 21: i11iIiiIii . IiII - OoooooooOO
  Oo00 = ""
  if ( IIIi1iI1 . rloc_next_hop != None ) :
   IiI11I111 , o0oOOoOo0O0 = IIIi1iI1 . rloc_next_hop
   Oo00 = ", nh {}({})" . format ( o0oOOoOo0O0 , IiI11I111 )
   if 25 - 25: Ii1I / Oo0Ooo
   if 79 - 79: o0oOOo0O0Ooo . i1IIi % I1ii11iIi11i % II111iiii . iIii1I11I1II1
  ooOO00o = bold ( IIIi1iI1 . print_rloc_probe_latency ( ) , False )
  ooOO00o = ", latency {}" . format ( ooOO00o ) if jt else ""
  if 45 - 45: I1ii11iIi11i / iIii1I11I1II1 + OoO0O00 / O0 - O0 - I1Ii111
  I1i = green ( lisp_print_eid_tuple ( eid , group ) , False )
  if 88 - 88: o0oOOo0O0Ooo % I1Ii111
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}{}" ) . format ( OoO0oo0O , red ( O0O0 , False ) , IIIiIIi111 , I1i ,
  # Ii1I
 iI1II , ii1iIiI111 , Oo00 , str ( hc ) + "/" + str ( ttl ) , ooOO00o ) )
  if 45 - 45: OOooOOo
  if ( IIIi1iI1 . rloc_next_hop == None ) : return
  if 54 - 54: ooOoO0o % I1ii11iIi11i - OoOoOO00 * Ii1I
  if 95 - 95: O0 . IiII % I1IiiI
  if 18 - 18: i11iIiiIii / ooOoO0o
  if 63 - 63: i11iIiiIii . i1IIi
  IIIi1iI1 = None
  IiI1I = None
  while ( True ) :
   IIIi1iI1 = self if IIIi1iI1 == None else IIIi1iI1 . next_rloc
   if ( IIIi1iI1 == None ) : break
   if ( IIIi1iI1 . up_state ( ) == False ) : continue
   if ( IIIi1iI1 . rloc_probe_rtt == - 1 ) : continue
   if 78 - 78: i11iIiiIii . i1IIi - o0oOOo0O0Ooo % o0oOOo0O0Ooo . i1IIi
   if ( IiI1I == None ) : IiI1I = IIIi1iI1
   if ( IIIi1iI1 . rloc_probe_rtt < IiI1I . rloc_probe_rtt ) : IiI1I = IIIi1iI1
   if 28 - 28: OoOoOO00
   if 31 - 31: i1IIi - I1IiiI . I1IiiI * Ii1I
  if ( IiI1I != None ) :
   IiI11I111 , o0oOOoOo0O0 = IiI1I . rloc_next_hop
   Oo00 = bold ( "nh {}({})" . format ( o0oOOoOo0O0 , IiI11I111 ) , False )
   lprint ( "    Install host-route via best {}" . format ( Oo00 ) )
   lisp_install_host_route ( O0O0 , None , False )
   lisp_install_host_route ( O0O0 , o0oOOoOo0O0 , True )
   if 80 - 80: OoOoOO00
   if 36 - 36: I11i - ooOoO0o - ooOoO0o . I1ii11iIi11i / II111iiii % OOooOOo
   if 26 - 26: OoooooooOO / ooOoO0o - iII111i / OoO0O00 . O0 * OOooOOo
 def add_to_rloc_probe_list ( self , eid , group ) :
  O0O0 = self . rloc . print_address_no_iid ( )
  IiO0o = self . translated_port
  if ( IiO0o != 0 ) : O0O0 += ":" + str ( IiO0o )
  if 85 - 85: iIii1I11I1II1 + iII111i + iII111i - ooOoO0o * OoO0O00
  if ( lisp_rloc_probe_list . has_key ( O0O0 ) == False ) :
   lisp_rloc_probe_list [ O0O0 ] = [ ]
   if 80 - 80: i11iIiiIii / OOooOOo . OoooooooOO % I11i - iII111i * iIii1I11I1II1
   if 70 - 70: Oo0Ooo
  if ( group . is_null ( ) ) : group . instance_id = 0
  for iiiI1I , I1i , OoIi1I1I in lisp_rloc_probe_list [ O0O0 ] :
   if ( I1i . is_exact_match ( eid ) and OoIi1I1I . is_exact_match ( group ) ) :
    if ( iiiI1I == self ) :
     if ( lisp_rloc_probe_list [ O0O0 ] == [ ] ) :
      lisp_rloc_probe_list . pop ( O0O0 )
      if 75 - 75: I1Ii111
     return
     if 40 - 40: OoO0O00 % Oo0Ooo / OoooooooOO / i11iIiiIii
    lisp_rloc_probe_list [ O0O0 ] . remove ( [ iiiI1I , I1i , OoIi1I1I ] )
    break
    if 5 - 5: O0 % i11iIiiIii
    if 60 - 60: I1ii11iIi11i / I11i
  lisp_rloc_probe_list [ O0O0 ] . append ( [ self , eid , group ] )
  if 100 - 100: I1IiiI
  if 44 - 44: iIii1I11I1II1 + Oo0Ooo - I1Ii111 . OoooooooOO
  if 28 - 28: Ii1I + OOooOOo % IiII . i11iIiiIii - I1IiiI * Oo0Ooo
  if 2 - 2: I11i * I1ii11iIi11i + O0
  if 44 - 44: iIii1I11I1II1 / II111iiii - ooOoO0o
  IIIi1iI1 = lisp_rloc_probe_list [ O0O0 ] [ 0 ] [ 0 ]
  if ( IIIi1iI1 . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 10 - 10: OOooOOo
   if 78 - 78: OOooOOo * I1ii11iIi11i % i11iIiiIii % o0oOOo0O0Ooo . I1ii11iIi11i / OoooooooOO
   if 12 - 12: iIii1I11I1II1 % OoO0O00 + OOooOOo * iIii1I11I1II1 - iIii1I11I1II1
 def delete_from_rloc_probe_list ( self , eid , group ) :
  O0O0 = self . rloc . print_address_no_iid ( )
  IiO0o = self . translated_port
  if ( IiO0o != 0 ) : O0O0 += ":" + str ( IiO0o )
  if ( lisp_rloc_probe_list . has_key ( O0O0 ) == False ) : return
  if 70 - 70: OoO0O00 % i11iIiiIii * IiII . I11i * Oo0Ooo
  ii11 = [ ]
  for oOOoO0oO0oo0O in lisp_rloc_probe_list [ O0O0 ] :
   if ( oOOoO0oO0oo0O [ 0 ] != self ) : continue
   if ( oOOoO0oO0oo0O [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( oOOoO0oO0oo0O [ 2 ] . is_exact_match ( group ) == False ) : continue
   ii11 = oOOoO0oO0oo0O
   break
   if 70 - 70: Oo0Ooo + O0 - o0oOOo0O0Ooo
  if ( ii11 == [ ] ) : return
  if 85 - 85: I1Ii111
  try :
   lisp_rloc_probe_list [ O0O0 ] . remove ( ii11 )
   if ( lisp_rloc_probe_list [ O0O0 ] == [ ] ) :
    lisp_rloc_probe_list . pop ( O0O0 )
    if 39 - 39: OoOoOO00 * oO0o
  except :
   return
   if 62 - 62: OoOoOO00 / OoOoOO00 * OoO0O00
   if 38 - 38: I1Ii111 + ooOoO0o % I11i
   if 22 - 22: I1Ii111 . Ii1I % I1Ii111 * I1IiiI / iIii1I11I1II1
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  OoiIIIiIi1I1i = ""
  IIIi1iI1 = self
  while ( True ) :
   II11i = IIIi1iI1 . last_rloc_probe
   if ( II11i == None ) : II11i = 0
   Ooo = IIIi1iI1 . last_rloc_probe_reply
   if ( Ooo == None ) : Ooo = 0
   ii1iIiI111 = IIIi1iI1 . print_rloc_probe_rtt ( )
   I1iiIi111I = space ( 4 )
   if 2 - 2: I1Ii111 / O0 . iIii1I11I1II1 * oO0o
   if ( IIIi1iI1 . rloc_next_hop == None ) :
    OoiIIIiIi1I1i += "RLOC-Probing:\n"
   else :
    IiI11I111 , o0oOOoOo0O0 = IIIi1iI1 . rloc_next_hop
    OoiIIIiIi1I1i += "RLOC-Probing for nh {}({}):\n" . format ( o0oOOoOo0O0 , IiI11I111 )
    if 57 - 57: II111iiii . I1IiiI - OOooOOo
    if 54 - 54: i1IIi + OoOoOO00
   OoiIIIiIi1I1i += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( I1iiIi111I , lisp_print_elapsed ( II11i ) ,
   # OoOoOO00 . Ii1I - o0oOOo0O0Ooo . i11iIiiIii + I1Ii111
 I1iiIi111I , lisp_print_elapsed ( Ooo ) , ii1iIiI111 )
   if 34 - 34: ooOoO0o * ooOoO0o / I1Ii111 . ooOoO0o
   if ( trailing_linefeed ) : OoiIIIiIi1I1i += "\n"
   if 4 - 4: II111iiii - iIii1I11I1II1 * OOooOOo % I1ii11iIi11i - i11iIiiIii
   IIIi1iI1 = IIIi1iI1 . next_rloc
   if ( IIIi1iI1 == None ) : break
   OoiIIIiIi1I1i += "\n"
   if 20 - 20: Ii1I . Oo0Ooo * Oo0Ooo * I1Ii111 - Oo0Ooo
  return ( OoiIIIiIi1I1i )
  if 78 - 78: OOooOOo . Oo0Ooo . iII111i / i11iIiiIii + iIii1I11I1II1 - OoOoOO00
  if 1 - 1: i11iIiiIii
 def get_encap_keys ( self ) :
  IiO0o = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 25 - 25: OoooooooOO / II111iiii . OOooOOo * OoOoOO00 - OoooooooOO
  O0O0 = self . rloc . print_address_no_iid ( ) + ":" + IiO0o
  if 8 - 8: iII111i . iIii1I11I1II1 * O0
  try :
   IiI11I1iiii1 = lisp_crypto_keys_by_rloc_encap [ O0O0 ]
   if ( IiI11I1iiii1 [ 1 ] ) : return ( IiI11I1iiii1 [ 1 ] . encrypt_key , IiI11I1iiii1 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 87 - 87: OoO0O00 * OoooooooOO + OoOoOO00 . OoooooooOO + o0oOOo0O0Ooo + Ii1I
   if 26 - 26: i1IIi
   if 33 - 33: OoOoOO00 + OOooOOo . i1IIi . IiII
 def rloc_recent_rekey ( self ) :
  IiO0o = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 78 - 78: OoooooooOO * I11i / OOooOOo + oO0o . I1Ii111 * iII111i
  O0O0 = self . rloc . print_address_no_iid ( ) + ":" + IiO0o
  if 98 - 98: i1IIi
  try :
   OO0Oo00o0o0 = lisp_crypto_keys_by_rloc_encap [ O0O0 ] [ 1 ]
   if ( OO0Oo00o0o0 == None ) : return ( False )
   if ( OO0Oo00o0o0 . last_rekey == None ) : return ( True )
   return ( time . time ( ) - OO0Oo00o0o0 . last_rekey < 1 )
  except :
   return ( False )
   if 28 - 28: Oo0Ooo . I1Ii111 . iIii1I11I1II1 + I1IiiI . II111iiii * I1ii11iIi11i
   if 26 - 26: i1IIi / i11iIiiIii * II111iiii
   if 11 - 11: Oo0Ooo % i1IIi
   if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
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
  self . register_ttl = LISP_REGISTER_TTL
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
  self . subscribed_eid = None
  self . subscribed_group = None
  if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
  if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
 def print_mapping ( self , eid_indent , rloc_indent ) :
  ii1III11 = lisp_print_elapsed ( self . uptime )
  iiIoOOOOoo0O00o = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , iiIoOOOOoo0O00o , ii1III11 ,
 len ( self . rloc_set ) ) )
  for IIIi1iI1 in self . rloc_set : IIIi1iI1 . print_rloc ( rloc_indent )
  if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
  if 8 - 8: OoooooooOO
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
  if 83 - 83: o0oOOo0O0Ooo * Ii1I - Oo0Ooo * iII111i - i11iIiiIii
 def print_ttl ( self ) :
  O0OOo = self . map_cache_ttl
  if ( O0OOo == None ) : return ( "forever" )
  if 6 - 6: I1IiiI + i11iIiiIii + O0 / i1IIi
  if ( O0OOo >= 3600 ) :
   if ( ( O0OOo % 3600 ) == 0 ) :
    O0OOo = str ( O0OOo / 3600 ) + " hours"
   else :
    O0OOo = str ( O0OOo * 60 ) + " mins"
    if 50 - 50: iII111i . II111iiii % I1Ii111 % I1IiiI / o0oOOo0O0Ooo . I1IiiI
  elif ( O0OOo >= 60 ) :
   if ( ( O0OOo % 60 ) == 0 ) :
    O0OOo = str ( O0OOo / 60 ) + " mins"
   else :
    O0OOo = str ( O0OOo ) + " secs"
    if 76 - 76: OOooOOo % iII111i
  else :
   O0OOo = str ( O0OOo ) + " secs"
   if 80 - 80: iIii1I11I1II1 + o0oOOo0O0Ooo + iIii1I11I1II1
  return ( O0OOo )
  if 63 - 63: OoOoOO00 - o0oOOo0O0Ooo % II111iiii - Ii1I
  if 81 - 81: iII111i % OOooOOo * oO0o
 def refresh ( self ) :
  if ( self . group . is_null ( ) ) : return ( self . refresh_unicast ( ) )
  return ( self . refresh_multicast ( ) )
  if 84 - 84: iII111i - OoooooooOO + I1ii11iIi11i - I1IiiI
  if 52 - 52: oO0o / ooOoO0o / iII111i / OoOoOO00 * iIii1I11I1II1
 def refresh_unicast ( self ) :
  return ( self . is_active ( ) and self . has_ttl_elapsed ( ) and
 self . gleaned == False )
  if 74 - 74: oO0o . I1ii11iIi11i - iIii1I11I1II1
  if 73 - 73: OoO0O00 / O0 . o0oOOo0O0Ooo
 def refresh_multicast ( self ) :
  if 100 - 100: Ii1I . OoO0O00 % I1ii11iIi11i % O0 * Oo0Ooo - OoOoOO00
  if 15 - 15: OOooOOo - OOooOOo - OoooooooOO * OoO0O00
  if 12 - 12: II111iiii * I1Ii111 / I1Ii111 * oO0o * Oo0Ooo
  if 17 - 17: OoOoOO00 % I1Ii111 / iII111i * I1Ii111
  if 96 - 96: Oo0Ooo % o0oOOo0O0Ooo . OoOoOO00 % i11iIiiIii / OoooooooOO
  Ii1i1 = int ( ( time . time ( ) - self . uptime ) % self . map_cache_ttl )
  Ooo0o0o0o = ( Ii1i1 in [ 0 , 1 , 2 ] )
  if ( Ooo0o0o0o == False ) : return ( False )
  if 86 - 86: i1IIi . oO0o % OOooOOo
  if 99 - 99: oO0o / I1Ii111 * oO0o * I11i
  if 38 - 38: o0oOOo0O0Ooo + OoOoOO00
  if 24 - 24: Ii1I - OOooOOo - o0oOOo0O0Ooo - I1Ii111 / OoooooooOO
  i1iI1iI = ( ( time . time ( ) - self . last_multicast_map_request ) <= 2 )
  if ( i1iI1iI ) : return ( False )
  if 32 - 32: OoooooooOO / i11iIiiIii
  self . last_multicast_map_request = lisp_get_timestamp ( )
  return ( True )
  if 30 - 30: OoOoOO00 % Ii1I / iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * OoO0O00
  if 25 - 25: i1IIi * oO0o . I11i
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  Ii1i1 = time . time ( ) - self . last_refresh_time
  if ( Ii1i1 >= self . map_cache_ttl ) : return ( True )
  if 15 - 15: oO0o
  if 45 - 45: Oo0Ooo * IiII * OoO0O00 + iIii1I11I1II1
  if 89 - 89: IiII . IiII . oO0o % iII111i
  if 27 - 27: OoOoOO00 + O0 % i1IIi - Oo0Ooo
  if 96 - 96: O0 % o0oOOo0O0Ooo + OOooOOo % I1IiiI
  OoOoooOO0O = self . map_cache_ttl - ( self . map_cache_ttl / 10 )
  if ( Ii1i1 >= OoOoooOO0O ) : return ( True )
  return ( False )
  if 47 - 47: i1IIi . i11iIiiIii / I1ii11iIi11i + OoooooooOO % i11iIiiIii - i1IIi
  if 9 - 9: I1ii11iIi11i
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  Ii1i1 = time . time ( ) - self . stats . last_increment
  return ( Ii1i1 <= 60 )
  if 68 - 68: I1IiiI + ooOoO0o * i11iIiiIii - OOooOOo / II111iiii
  if 81 - 81: O0 - I1IiiI / ooOoO0o % I1IiiI . iII111i
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 63 - 63: oO0o * Ii1I
  if 95 - 95: OoooooooOO % I1ii11iIi11i . I1Ii111 . IiII
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 98 - 98: OoooooooOO - OoO0O00 . oO0o - iIii1I11I1II1 * iIii1I11I1II1 % Ii1I
  if 87 - 87: O0 % iII111i
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for IIIi1iI1 in self . best_rloc_set :
   IIIi1iI1 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 57 - 57: Ii1I
   if 49 - 49: I11i
   if 22 - 22: Oo0Ooo % OOooOOo + O0 - OoO0O00 % I11i * O0
 def build_best_rloc_set ( self ) :
  iIiooooOooOO0 = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 20 - 20: I11i + IiII
  if 44 - 44: OoooooooOO % I11i / O0
  if 94 - 94: IiII
  if 83 - 83: OoO0O00
  oO0oOOO000O = 256
  for IIIi1iI1 in self . rloc_set :
   if ( IIIi1iI1 . up_state ( ) ) : oO0oOOO000O = min ( IIIi1iI1 . priority , oO0oOOO000O )
   if 51 - 51: I1Ii111 . ooOoO0o
   if 100 - 100: o0oOOo0O0Ooo % iII111i
   if 44 - 44: IiII * OoOoOO00 - OoO0O00 - OoooooooOO - I1ii11iIi11i - II111iiii
   if 26 - 26: ooOoO0o - i1IIi / OOooOOo + OoOoOO00 / iII111i
   if 27 - 27: I11i % Ii1I / iII111i . OoOoOO00
   if 88 - 88: iII111i - i11iIiiIii * I1Ii111 * i11iIiiIii - O0
   if 8 - 8: oO0o + O0
   if 52 - 52: I11i * OOooOOo - OoOoOO00 % iIii1I11I1II1 . II111iiii
   if 1 - 1: OOooOOo / I1IiiI / Ii1I * iII111i
   if 14 - 14: ooOoO0o . O0 * OOooOOo
  for IIIi1iI1 in self . rloc_set :
   if ( IIIi1iI1 . priority <= oO0oOOO000O ) :
    if ( IIIi1iI1 . unreach_state ( ) and IIIi1iI1 . last_rloc_probe == None ) :
     IIIi1iI1 . last_rloc_probe = lisp_get_timestamp ( )
     if 34 - 34: I1ii11iIi11i . OOooOOo + OoO0O00 % o0oOOo0O0Ooo * O0 * I1IiiI
    self . best_rloc_set . append ( IIIi1iI1 )
    if 9 - 9: IiII / i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % I1Ii111
    if 65 - 65: I1IiiI % OoOoOO00
    if 45 - 45: o0oOOo0O0Ooo
    if 33 - 33: ooOoO0o % O0 % I1ii11iIi11i % o0oOOo0O0Ooo + i11iIiiIii . I1Ii111
    if 21 - 21: I1Ii111 * I1ii11iIi11i * ooOoO0o
    if 73 - 73: OoOoOO00 * O0
    if 1 - 1: OOooOOo * OoooooooOO
    if 46 - 46: I1ii11iIi11i * I1Ii111 / OOooOOo / I1IiiI
  for IIIi1iI1 in iIiooooOooOO0 :
   if ( IIIi1iI1 . priority < oO0oOOO000O ) : continue
   IIIi1iI1 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 7 - 7: OOooOOo / OoOoOO00
  for IIIi1iI1 in self . best_rloc_set :
   if ( IIIi1iI1 . rloc . is_null ( ) ) : continue
   IIIi1iI1 . add_to_rloc_probe_list ( self . eid , self . group )
   if 93 - 93: iIii1I11I1II1 * Ii1I - iII111i
   if 94 - 94: iIii1I11I1II1 * iIii1I11I1II1 * I11i % i11iIiiIii
   if 38 - 38: I1IiiI % I1ii11iIi11i * I1IiiI + OOooOOo - OoOoOO00
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  o0o0ooOOo0oO = lisp_packet . packet
  o00O0O = lisp_packet . inner_version
  i1iIii = len ( self . best_rloc_set )
  if ( i1iIii == 0 ) :
   self . stats . increment ( len ( o0o0ooOOo0oO ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 72 - 72: Oo0Ooo
   if 28 - 28: iII111i . i11iIiiIii + o0oOOo0O0Ooo
  I1iiI1i1111 = 4 if lisp_load_split_pings else 0
  iIIi111I1i1i = lisp_packet . hash_ports ( )
  if ( o00O0O == 4 ) :
   for OoOOoO0oOo in range ( 8 + I1iiI1i1111 ) :
    iIIi111I1i1i = iIIi111I1i1i ^ struct . unpack ( "B" , o0o0ooOOo0oO [ OoOOoO0oOo + 12 ] ) [ 0 ]
    if 18 - 18: o0oOOo0O0Ooo * OoooooooOO % i1IIi
  elif ( o00O0O == 6 ) :
   for OoOOoO0oOo in range ( 0 , 32 + I1iiI1i1111 , 4 ) :
    iIIi111I1i1i = iIIi111I1i1i ^ struct . unpack ( "I" , o0o0ooOOo0oO [ OoOOoO0oOo + 8 : OoOOoO0oOo + 12 ] ) [ 0 ]
    if 17 - 17: iII111i . o0oOOo0O0Ooo / II111iiii % Oo0Ooo
   iIIi111I1i1i = ( iIIi111I1i1i >> 16 ) + ( iIIi111I1i1i & 0xffff )
   iIIi111I1i1i = ( iIIi111I1i1i >> 8 ) + ( iIIi111I1i1i & 0xff )
  else :
   for OoOOoO0oOo in range ( 0 , 12 + I1iiI1i1111 , 4 ) :
    iIIi111I1i1i = iIIi111I1i1i ^ struct . unpack ( "I" , o0o0ooOOo0oO [ OoOOoO0oOo : OoOOoO0oOo + 4 ] ) [ 0 ]
    if 1 - 1: OOooOOo % o0oOOo0O0Ooo * o0oOOo0O0Ooo / oO0o
    if 79 - 79: oO0o . OOooOOo
    if 82 - 82: I1Ii111 % II111iiii
  if ( lisp_data_plane_logging ) :
   Ii11I11iIi1i1 = [ ]
   for iiiI1I in self . best_rloc_set :
    if ( iiiI1I . rloc . is_null ( ) ) : continue
    Ii11I11iIi1i1 . append ( [ iiiI1I . rloc . print_address_no_iid ( ) , iiiI1I . print_state ( ) ] )
    if 95 - 95: OoO0O00 * i1IIi
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( iIIi111I1i1i ) , iIIi111I1i1i % i1iIii , red ( str ( Ii11I11iIi1i1 ) , False ) ) )
   if 43 - 43: Oo0Ooo % iII111i % O0 + i1IIi
   if 45 - 45: ooOoO0o
   if 89 - 89: iIii1I11I1II1 . I1Ii111
   if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
   if 59 - 59: IiII . OoO0O00 - OoooooooOO . O0
   if 33 - 33: Ii1I
  IIIi1iI1 = self . best_rloc_set [ iIIi111I1i1i % i1iIii ]
  if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
  if 40 - 40: I1IiiI / OOooOOo * Ii1I
  if 98 - 98: I1IiiI
  if 4 - 4: I1IiiI % O0 / Oo0Ooo / O0
  if 90 - 90: ooOoO0o - O0 . IiII - O0 . iIii1I11I1II1
  OO0Ooo0O00ooOo0o = lisp_get_echo_nonce ( IIIi1iI1 . rloc , None )
  if ( OO0Ooo0O00ooOo0o ) :
   OO0Ooo0O00ooOo0o . change_state ( IIIi1iI1 )
   if ( IIIi1iI1 . no_echoed_nonce_state ( ) ) :
    OO0Ooo0O00ooOo0o . request_nonce_sent = None
    if 42 - 42: I1ii11iIi11i
    if 51 - 51: iII111i % i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
    if 14 - 14: I1ii11iIi11i . OoO0O00
    if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
    if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
    if 29 - 29: O0 + iII111i
  if ( IIIi1iI1 . up_state ( ) == False ) :
   I1I111iI1IIi = iIIi111I1i1i % i1iIii
   I1i11II = ( I1I111iI1IIi + 1 ) % i1iIii
   while ( I1i11II != I1I111iI1IIi ) :
    IIIi1iI1 = self . best_rloc_set [ I1i11II ]
    if ( IIIi1iI1 . up_state ( ) ) : break
    I1i11II = ( I1i11II + 1 ) % i1iIii
    if 100 - 100: II111iiii % O0 . OoOoOO00 . O0 + OoOoOO00 / Ii1I
   if ( I1i11II == I1I111iI1IIi ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 21 - 21: O0 / OOooOOo . Oo0Ooo % O0
    if 95 - 95: O0 - I1IiiI / O0 % O0
    if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
    if 65 - 65: I1ii11iIi11i % ooOoO0o - OoOoOO00 + ooOoO0o + Oo0Ooo
    if 95 - 95: I1Ii111 * i11iIiiIii - I1IiiI - OoOoOO00 . ooOoO0o
    if 34 - 34: OoooooooOO % I1ii11iIi11i + OoooooooOO % i11iIiiIii / IiII - ooOoO0o
  IIIi1iI1 . stats . increment ( len ( o0o0ooOOo0oO ) )
  if 74 - 74: iIii1I11I1II1 % II111iiii + IiII
  if 71 - 71: I1IiiI / O0 * i1IIi . i1IIi + Oo0Ooo
  if 32 - 32: i1IIi * I1Ii111 % I1IiiI / IiII . I1Ii111
  if 11 - 11: OOooOOo
  if ( IIIi1iI1 . rle_name and IIIi1iI1 . rle == None ) :
   if ( lisp_rle_list . has_key ( IIIi1iI1 . rle_name ) ) :
    IIIi1iI1 . rle = lisp_rle_list [ IIIi1iI1 . rle_name ]
    if 25 - 25: i1IIi
    if 99 - 99: OOooOOo + OoooooooOO . I1Ii111 * Oo0Ooo % oO0o
  if ( IIIi1iI1 . rle ) : return ( [ None , None , None , None , IIIi1iI1 . rle , None ] )
  if 75 - 75: iII111i
  if 8 - 8: I1ii11iIi11i . I11i / I1ii11iIi11i - i1IIi
  if 22 - 22: OOooOOo
  if 7 - 7: O0 - I1ii11iIi11i - OoO0O00 * I1Ii111
  if ( IIIi1iI1 . elp and IIIi1iI1 . elp . use_elp_node ) :
   return ( [ IIIi1iI1 . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 17 - 17: o0oOOo0O0Ooo % OoO0O00 - I11i * o0oOOo0O0Ooo - i1IIi / I1IiiI
   if 100 - 100: OoO0O00 * i1IIi * o0oOOo0O0Ooo * Oo0Ooo - o0oOOo0O0Ooo
   if 100 - 100: iII111i - i11iIiiIii + OoO0O00
   if 50 - 50: II111iiii
   if 42 - 42: OOooOOo * I1Ii111
  Ooo00O0O0O = None if ( IIIi1iI1 . rloc . is_null ( ) ) else IIIi1iI1 . rloc
  IiO0o = IIIi1iI1 . translated_port
  iiIIiI = self . action if ( Ooo00O0O0O == None ) else None
  if 81 - 81: iIii1I11I1II1 / OoooooooOO % II111iiii * i11iIiiIii - Oo0Ooo / I1ii11iIi11i
  if 78 - 78: OoooooooOO % Ii1I % oO0o + o0oOOo0O0Ooo + OoO0O00
  if 53 - 53: Ii1I / o0oOOo0O0Ooo * I1IiiI / i1IIi / iII111i + iII111i
  if 66 - 66: i1IIi + I1IiiI
  if 45 - 45: I1Ii111 . iII111i + OoO0O00 - O0
  O0oo00o000 = None
  if ( OO0Ooo0O00ooOo0o and OO0Ooo0O00ooOo0o . request_nonce_timeout ( ) == False ) :
   O0oo00o000 = OO0Ooo0O00ooOo0o . get_request_or_echo_nonce ( ipc_socket , Ooo00O0O0O )
   if 71 - 71: Oo0Ooo + OOooOOo
   if 94 - 94: OOooOOo
   if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
   if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
   if 31 - 31: I11i . o0oOOo0O0Ooo
  return ( [ Ooo00O0O0O , IiO0o , O0oo00o000 , iiIIiI , None , IIIi1iI1 ] )
  if 82 - 82: I11i - Oo0Ooo
  if 77 - 77: I1IiiI + OoO0O00 % iIii1I11I1II1 - OOooOOo
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 80 - 80: oO0o % I1ii11iIi11i * I1Ii111 + i1IIi
  if 79 - 79: oO0o + IiII
  if 4 - 4: iII111i + OoooooooOO / I1Ii111
  if 57 - 57: I1IiiI . iIii1I11I1II1 % iII111i * iII111i / I1Ii111
  if 30 - 30: O0 / I11i % OoOoOO00 * I1Ii111 / O0 % ooOoO0o
  for O0O0OOo0O in self . rloc_set :
   for IIIi1iI1 in rloc_address_set :
    if ( IIIi1iI1 . is_exact_match ( O0O0OOo0O . rloc ) == False ) : continue
    IIIi1iI1 = None
    break
    if 36 - 36: iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
   if ( IIIi1iI1 == rloc_address_set [ - 1 ] ) : return ( False )
   if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
  return ( True )
  if 97 - 97: i11iIiiIii / O0 % OoO0O00
  if 88 - 88: i1IIi . I1IiiI
 def get_rloc ( self , rloc ) :
  for O0O0OOo0O in self . rloc_set :
   iiiI1I = O0O0OOo0O . rloc
   if ( rloc . is_exact_match ( iiiI1I ) ) : return ( O0O0OOo0O )
   if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
  return ( None )
  if 51 - 51: oO0o + Ii1I * Ii1I * I1ii11iIi11i % I11i - I1ii11iIi11i
  if 15 - 15: i1IIi / OoO0O00 - Oo0Ooo
 def get_rloc_by_interface ( self , interface ) :
  for O0O0OOo0O in self . rloc_set :
   if ( O0O0OOo0O . interface == interface ) : return ( O0O0OOo0O )
   if 74 - 74: o0oOOo0O0Ooo % Ii1I - II111iiii / ooOoO0o
  return ( None )
  if 84 - 84: I1IiiI + OOooOOo
  if 80 - 80: OOooOOo / OoOoOO00
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   oooOOoO0oo0 = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( oooOOoO0oo0 == None ) :
    oooOOoO0oo0 = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , oooOOoO0oo0 )
    if 93 - 93: OOooOOo
   oooOOoO0oo0 . add_source_entry ( self )
   if 82 - 82: iIii1I11I1II1 + OoO0O00 / iIii1I11I1II1 . iIii1I11I1II1
   if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
   if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   ooOoOO0Oo = lisp_map_cache . lookup_cache ( self . group , True )
   if ( ooOoOO0Oo == None ) :
    ooOoOO0Oo = lisp_mapping ( self . group , self . group , [ ] )
    ooOoOO0Oo . eid . copy_address ( self . group )
    ooOoOO0Oo . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , ooOoOO0Oo )
    if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( ooOoOO0Oo . group )
   ooOoOO0Oo . add_source_entry ( self )
   if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
  if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    IIi1iii1i1 = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( IIi1iii1i1 ) )
    if 29 - 29: oO0o / iIii1I11I1II1 % Oo0Ooo * Ii1I
  else :
   ooOoOO0Oo = lisp_map_cache . lookup_cache ( self . group , True )
   if ( ooOoOO0Oo == None ) : return
   if 49 - 49: OoO0O00 * I11i * iIii1I11I1II1 * I11i - I1IiiI . Oo0Ooo
   Oo00000Oooo = ooOoOO0Oo . lookup_source_cache ( self . eid , True )
   if ( Oo00000Oooo == None ) : return
   if 13 - 13: i1IIi % i1IIi % ooOoO0o + IiII * II111iiii * OOooOOo
   ooOoOO0Oo . source_cache . delete_cache ( self . eid )
   if ( ooOoOO0Oo . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 66 - 66: iIii1I11I1II1
    if 92 - 92: OOooOOo * o0oOOo0O0Ooo - IiII
    if 83 - 83: OoO0O00 % I1IiiI % OOooOOo / oO0o + I1IiiI
    if 94 - 94: OoOoOO00 . O0
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 86 - 86: oO0o % Oo0Ooo . OoooooooOO / OOooOOo / i1IIi
  if 65 - 65: Ii1I . OoooooooOO % IiII - o0oOOo0O0Ooo . OOooOOo . II111iiii
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 100 - 100: ooOoO0o / Oo0Ooo + I1ii11iIi11i + OoooooooOO
  if 100 - 100: I11i . OOooOOo - II111iiii % I11i % iIii1I11I1II1
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 4 - 4: o0oOOo0O0Ooo . iII111i / O0
  if 13 - 13: iII111i / IiII
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  i1 = "," + str ( self . secondary_iid )
  return ( prefix . replace ( i1 , i1 + "*" ) )
  if 28 - 28: iII111i
  if 97 - 97: iIii1I11I1II1
 def increment_decap_stats ( self , packet ) :
  IiO0o = packet . udp_dport
  if ( IiO0o == LISP_DATA_PORT ) :
   IIIi1iI1 = self . get_rloc ( packet . outer_dest )
  else :
   if 18 - 18: OOooOOo
   if 87 - 87: O0 - i1IIi . I11i / Ii1I % iIii1I11I1II1
   if 57 - 57: I11i . IiII / iIii1I11I1II1 - ooOoO0o
   if 50 - 50: O0 / II111iiii
   for IIIi1iI1 in self . rloc_set :
    if ( IIIi1iI1 . translated_port != 0 ) : break
    if 94 - 94: O0 + O0 % I1ii11iIi11i % i1IIi
    if 15 - 15: I1IiiI
  if ( IIIi1iI1 != None ) : IIIi1iI1 . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 48 - 48: Ii1I * IiII % O0 - II111iiii
  if 66 - 66: iIii1I11I1II1 / OOooOOo
 def rtrs_in_rloc_set ( self ) :
  for IIIi1iI1 in self . rloc_set :
   if ( IIIi1iI1 . is_rtr ( ) ) : return ( True )
   if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
  return ( False )
  if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
  if 67 - 67: I1Ii111
 def add_recent_source ( self , source ) :
  self . recent_sources [ source . print_address ( ) ] = lisp_get_timestamp ( )
  if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
  if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
  if 46 - 46: I11i - ooOoO0o . I1IiiI
class lisp_dynamic_eid ( ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 36 - 36: I11i + OoO0O00 * O0 * OoOoOO00 * iII111i
  if 90 - 90: i11iIiiIii / i1IIi
 def get_timeout ( self , interface ) :
  try :
   I1ioOo0oO0O0 = lisp_myinterfaces [ interface ]
   self . timeout = I1ioOo0oO0O0 . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 84 - 84: I1Ii111 - I11i % iIii1I11I1II1 * o0oOOo0O0Ooo % I1IiiI
   if 5 - 5: OoO0O00
   if 10 - 10: o0oOOo0O0Ooo % OOooOOo / Ii1I . iIii1I11I1II1 % o0oOOo0O0Ooo + o0oOOo0O0Ooo
   if 63 - 63: i11iIiiIii
class lisp_group_mapping ( ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 34 - 34: OoooooooOO - O0 + ooOoO0o * I1IiiI
  if 75 - 75: OOooOOo % iII111i
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 15 - 15: OoO0O00
  if 52 - 52: II111iiii / ooOoO0o
  if 23 - 23: i11iIiiIii % OoO0O00 - o0oOOo0O0Ooo + OoooooooOO
  if 12 - 12: Ii1I / I1IiiI . oO0o . I1IiiI + ooOoO0o - II111iiii
  if 6 - 6: Oo0Ooo + Oo0Ooo - OoOoOO00 - II111iiii
  if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
  if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
  if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
  if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
  if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
def lisp_is_group_more_specific ( group_str , group_mapping ) :
 i1 = group_mapping . group_prefix . instance_id
 o00O00 = group_mapping . group_prefix . mask_len
 iiIoOOOOoo0O00o = lisp_address ( LISP_AFI_IPV4 , group_str , 32 , i1 )
 if ( iiIoOOOOoo0O00o . is_more_specific ( group_mapping . group_prefix ) ) : return ( o00O00 )
 return ( - 1 )
 if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
 if 92 - 92: I11i
 if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
 if 98 - 98: iII111i % IiII + OoO0O00
 if 23 - 23: OOooOOo
 if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
 if 99 - 99: II111iiii + O0
def lisp_lookup_group ( group ) :
 Ii11I11iIi1i1 = None
 for O0O0oO00Oo00 in lisp_group_mapping_list . values ( ) :
  o00O00 = lisp_is_group_more_specific ( group , O0O0oO00Oo00 )
  if ( o00O00 == - 1 ) : continue
  if ( Ii11I11iIi1i1 == None or o00O00 > Ii11I11iIi1i1 . group_prefix . mask_len ) : Ii11I11iIi1i1 = O0O0oO00Oo00
  if 27 - 27: Oo0Ooo
 return ( Ii11I11iIi1i1 )
 if 81 - 81: Oo0Ooo * Ii1I % OoO0O00 * i1IIi . I1IiiI + Oo0Ooo
 if 45 - 45: OoO0O00
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 83 - 83: i1IIi + OoooooooOO * IiII
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
  if 65 - 65: II111iiii / I1Ii111 + I1IiiI - OoooooooOO + ooOoO0o - I1ii11iIi11i
  if 29 - 29: OoOoOO00 / OOooOOo / OoO0O00
  if 95 - 95: ooOoO0o
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
  if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
  if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 32 - 32: OoOoOO00 % i11iIiiIii
  if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
 def print_flags ( self , html ) :
  if ( html == False ) :
   OoiIIIiIi1I1i = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # OoOoOO00 / ooOoO0o * iIii1I11I1II1
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   IIi1 = self . print_flags ( False )
   IIi1 = IIi1 . split ( "-" )
   OoiIIIiIi1I1i = ""
   for iIII1i11iI in IIi1 :
    I1II1I1III1 = lisp_site_flags [ iIII1i11iI . upper ( ) ]
    I1II1I1III1 = I1II1I1III1 . format ( "" if iIII1i11iI . isupper ( ) else "not " )
    OoiIIIiIi1I1i += lisp_span ( iIII1i11iI , I1II1I1III1 )
    if ( iIII1i11iI . lower ( ) != "n" ) : OoiIIIiIi1I1i += "-"
    if 99 - 99: II111iiii . OoooooooOO * iIii1I11I1II1
    if 72 - 72: OoooooooOO . I1ii11iIi11i * I1Ii111 / OoooooooOO % OOooOOo
  return ( OoiIIIiIi1I1i )
  if 60 - 60: OoO0O00
  if 54 - 54: I1IiiI + O0 - I1Ii111 - oO0o + O0 - I1ii11iIi11i
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 21 - 21: ooOoO0o . i1IIi / Oo0Ooo . OoO0O00
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 49 - 49: oO0o % i11iIiiIii * Ii1I
  if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
 def build_sort_key ( self ) :
  oo0oO0OO = lisp_cache ( )
  Iii1iii1II , OO0Oo00o0o0 = oo0oO0OO . build_key ( self . eid )
  Iii11iIII = ""
  if ( self . group . is_null ( ) == False ) :
   i1II1iIi111I1 , Iii11iIII = oo0oO0OO . build_key ( self . group )
   Iii11iIII = "-" + Iii11iIII [ 0 : 12 ] + "-" + str ( i1II1iIi111I1 ) + "-" + Iii11iIII [ 12 : : ]
   if 99 - 99: Ii1I
  OO0Oo00o0o0 = OO0Oo00o0o0 [ 0 : 12 ] + "-" + str ( Iii1iii1II ) + "-" + OO0Oo00o0o0 [ 12 : : ] + Iii11iIII
  del ( oo0oO0OO )
  return ( OO0Oo00o0o0 )
  if 40 - 40: OoooooooOO - I1Ii111
  if 9 - 9: I1Ii111 % o0oOOo0O0Ooo / I1ii11iIi11i . iII111i . OoOoOO00
 def merge_in_site_eid ( self , child ) :
  I1II111i = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   I1II111i = self . merge_rles_in_site_eid ( )
   if 77 - 77: iII111i + o0oOOo0O0Ooo
   if 60 - 60: I1ii11iIi11i
   if 23 - 23: iII111i % I1IiiI % I1Ii111 * oO0o * I1IiiI
   if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
   if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
   if 52 - 52: OoooooooOO
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
  return ( I1II111i )
  if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
  if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
 def copy_rloc_records ( self ) :
  oOO0IiiiI = [ ]
  for O0O0OOo0O in self . registered_rlocs :
   oOO0IiiiI . append ( copy . deepcopy ( O0O0OOo0O ) )
   if 43 - 43: oO0o / Ii1I % OOooOOo
  return ( oOO0IiiiI )
  if 45 - 45: II111iiii
  if 41 - 41: Ii1I / OOooOOo * Oo0Ooo . O0 - i11iIiiIii
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for iiI1I in self . individual_registrations . values ( ) :
   if ( self . site_id != iiI1I . site_id ) : continue
   if ( iiI1I . registered == False ) : continue
   self . registered_rlocs += iiI1I . copy_rloc_records ( )
   if 77 - 77: o0oOOo0O0Ooo + I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
   if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
   if 43 - 43: OOooOOo . O0
   if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
   if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
   if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
  oOO0IiiiI = [ ]
  for O0O0OOo0O in self . registered_rlocs :
   if ( O0O0OOo0O . rloc . is_null ( ) or len ( oOO0IiiiI ) == 0 ) :
    oOO0IiiiI . append ( O0O0OOo0O )
    continue
    if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
   for I1I11I1IIi in oOO0IiiiI :
    if ( I1I11I1IIi . rloc . is_null ( ) ) : continue
    if ( O0O0OOo0O . rloc . is_exact_match ( I1I11I1IIi . rloc ) ) : break
    if 3 - 3: i1IIi + OoOoOO00 - OoOoOO00
   if ( I1I11I1IIi == oOO0IiiiI [ - 1 ] ) : oOO0IiiiI . append ( O0O0OOo0O )
   if 85 - 85: o0oOOo0O0Ooo / o0oOOo0O0Ooo + Oo0Ooo * II111iiii + Ii1I * Ii1I
  self . registered_rlocs = oOO0IiiiI
  if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
  if 86 - 86: Ii1I
  if 69 - 69: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
  if 1 - 1: Ii1I
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 43 - 43: o0oOOo0O0Ooo
  if 78 - 78: I1Ii111 % i1IIi * I11i
 def merge_rles_in_site_eid ( self ) :
  if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
  if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
  if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
  if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
  iiIOoOoo = { }
  for O0O0OOo0O in self . registered_rlocs :
   if ( O0O0OOo0O . rle == None ) : continue
   for o0Ii11I in O0O0OOo0O . rle . rle_nodes :
    IiIIiiI = o0Ii11I . address . print_address_no_iid ( )
    iiIOoOoo [ IiIIiiI ] = o0Ii11I . address
    if 66 - 66: I11i . IiII + o0oOOo0O0Ooo + iII111i
   break
   if 73 - 73: I1Ii111 . Oo0Ooo * O0 % OoOoOO00 . I1ii11iIi11i
   if 46 - 46: OOooOOo * iIii1I11I1II1
   if 33 - 33: OoO0O00 * II111iiii / i1IIi
   if 93 - 93: I1Ii111 % I11i
   if 64 - 64: I1IiiI % OoOoOO00 / Oo0Ooo
  self . merge_rlocs_in_site_eid ( )
  if 40 - 40: Ii1I + iIii1I11I1II1 / oO0o . II111iiii % O0 - IiII
  if 49 - 49: IiII - OOooOOo * OOooOOo . O0
  if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
  if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
  if 61 - 61: OoO0O00
  if 100 - 100: OoOoOO00
  if 97 - 97: OoooooooOO
  if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
  i11IiIi11I = [ ]
  for O0O0OOo0O in self . registered_rlocs :
   if ( self . registered_rlocs . index ( O0O0OOo0O ) == 0 ) :
    i11IiIi11I . append ( O0O0OOo0O )
    continue
    if 84 - 84: I1IiiI . o0oOOo0O0Ooo * I1ii11iIi11i
   if ( O0O0OOo0O . rle == None ) : i11IiIi11I . append ( O0O0OOo0O )
   if 41 - 41: o0oOOo0O0Ooo * Ii1I + I11i . O0
  self . registered_rlocs = i11IiIi11I
  if 17 - 17: Ii1I % I1Ii111
  if 69 - 69: iIii1I11I1II1
  if 65 - 65: IiII % OOooOOo / o0oOOo0O0Ooo * II111iiii - oO0o
  if 38 - 38: I1Ii111 * o0oOOo0O0Ooo
  if 32 - 32: iII111i / Ii1I / I1Ii111 - OoOoOO00 / OOooOOo * OoO0O00
  if 32 - 32: I1ii11iIi11i + ooOoO0o . i1IIi * iIii1I11I1II1 - I1IiiI
  if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
  O0OOO = lisp_rle ( "" )
  I1iiIi1iI1I11 = { }
  oOoOoO0Oo0oo = None
  for iiI1I in self . individual_registrations . values ( ) :
   if ( iiI1I . registered == False ) : continue
   O0oI1Iii = iiI1I . registered_rlocs [ 0 ] . rle
   if ( O0oI1Iii == None ) : continue
   if 5 - 5: II111iiii
   oOoOoO0Oo0oo = iiI1I . registered_rlocs [ 0 ] . rloc_name
   for ooOooOooOoOo in O0oI1Iii . rle_nodes :
    IiIIiiI = ooOooOooOoOo . address . print_address_no_iid ( )
    if ( I1iiIi1iI1I11 . has_key ( IiIIiiI ) ) : break
    if 100 - 100: OoO0O00
    o0Ii11I = lisp_rle_node ( )
    o0Ii11I . address . copy_address ( ooOooOooOoOo . address )
    o0Ii11I . level = ooOooOooOoOo . level
    o0Ii11I . rloc_name = oOoOoO0Oo0oo
    O0OOO . rle_nodes . append ( o0Ii11I )
    I1iiIi1iI1I11 [ IiIIiiI ] = ooOooOooOoOo . address
    if 36 - 36: oO0o + Ii1I - O0
    if 19 - 19: O0 + I1Ii111 . I1Ii111 * IiII * ooOoO0o + i1IIi
    if 51 - 51: ooOoO0o % OoOoOO00 % i1IIi / O0
    if 11 - 11: OOooOOo . I1ii11iIi11i * OOooOOo * OoO0O00
    if 11 - 11: I11i
    if 85 - 85: OoOoOO00 - Ii1I / Oo0Ooo % I1ii11iIi11i
  if ( len ( O0OOO . rle_nodes ) == 0 ) : O0OOO = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = O0OOO
   if ( oOoOoO0Oo0oo ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 12 - 12: i1IIi + o0oOOo0O0Ooo / oO0o . O0
   if 37 - 37: IiII
   if 99 - 99: i11iIiiIii % i11iIiiIii . I11i * I1ii11iIi11i . OoO0O00 / I1IiiI
   if 44 - 44: iII111i - OoO0O00 / i11iIiiIii
   if 55 - 55: O0 * OoO0O00 * i1IIi
  if ( iiIOoOoo . keys ( ) == I1iiIi1iI1I11 . keys ( ) ) : return ( False )
  if 9 - 9: IiII
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # OoOoOO00 / OoooooooOO * OoO0O00 * I1Ii111
 iiIOoOoo . keys ( ) , I1iiIi1iI1I11 . keys ( ) ) )
  if 12 - 12: i11iIiiIii / iIii1I11I1II1 . I11i % I1Ii111 * ooOoO0o % ooOoO0o
  return ( True )
  if 13 - 13: i1IIi . ooOoO0o . ooOoO0o
  if 24 - 24: iIii1I11I1II1
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   IiI11I11i = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( IiI11I11i == None ) :
    IiI11I11i = lisp_site_eid ( self . site )
    IiI11I11i . eid . copy_address ( self . group )
    IiI11I11i . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , IiI11I11i )
    if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
    if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
    if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
    if 62 - 62: o0oOOo0O0Ooo
    if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
    IiI11I11i . parent_for_more_specifics = self . parent_for_more_specifics
    if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( IiI11I11i . group )
   IiI11I11i . add_source_entry ( self )
   if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
   if 84 - 84: OoOoOO00
   if 80 - 80: oO0o
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   IiI11I11i = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( IiI11I11i == None ) : return
   if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
   iiI1I = IiI11I11i . lookup_source_cache ( self . eid , True )
   if ( iiI1I == None ) : return
   if 92 - 92: iII111i
   if ( IiI11I11i . source_cache == None ) : return
   if 96 - 96: OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
   IiI11I11i . source_cache . delete_cache ( self . eid )
   if ( IiI11I11i . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
    if 92 - 92: I1Ii111 - IiII / IiII
    if 42 - 42: IiII
    if 7 - 7: iIii1I11I1II1
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 35 - 35: IiII + O0 % I1Ii111 - I1ii11iIi11i - i1IIi
  if 100 - 100: I1Ii111 + i11iIiiIii - IiII / I1ii11iIi11i / iII111i
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 56 - 56: iII111i
  if 91 - 91: Oo0Ooo . I11i . I1ii11iIi11i
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 60 - 60: i11iIiiIii - OOooOOo
  if 78 - 78: I1IiiI * ooOoO0o % iIii1I11I1II1 / I1ii11iIi11i
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 61 - 61: I1Ii111 . Ii1I + OoooooooOO
  if 98 - 98: OOooOOo . ooOoO0o . OoOoOO00 - I1Ii111 . i1IIi - iIii1I11I1II1
 def inherit_from_ams_parent ( self ) :
  Ooo0 = self . parent_for_more_specifics
  if ( Ooo0 == None ) : return
  self . force_proxy_reply = Ooo0 . force_proxy_reply
  self . force_nat_proxy_reply = Ooo0 . force_nat_proxy_reply
  self . force_ttl = Ooo0 . force_ttl
  self . pitr_proxy_reply_drop = Ooo0 . pitr_proxy_reply_drop
  self . proxy_reply_action = Ooo0 . proxy_reply_action
  self . echo_nonce_capable = Ooo0 . echo_nonce_capable
  self . policy = Ooo0 . policy
  self . require_signature = Ooo0 . require_signature
  self . encrypt_json = Ooo0 . encrypt_json
  if 89 - 89: II111iiii * I1ii11iIi11i - I1IiiI
  if 58 - 58: Ii1I / Oo0Ooo % IiII
 def rtrs_in_rloc_set ( self ) :
  for O0O0OOo0O in self . registered_rlocs :
   if ( O0O0OOo0O . is_rtr ( ) ) : return ( True )
   if 33 - 33: II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % i11iIiiIii
  return ( False )
  if 60 - 60: iII111i . o0oOOo0O0Ooo
  if 56 - 56: I1ii11iIi11i
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for O0O0OOo0O in self . registered_rlocs :
   if ( O0O0OOo0O . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( O0O0OOo0O . is_rtr ( ) ) : return ( True )
   if 89 - 89: Oo0Ooo + I1ii11iIi11i * o0oOOo0O0Ooo * oO0o % O0 % OoO0O00
  return ( False )
  if 70 - 70: o0oOOo0O0Ooo + O0 % I1IiiI
  if 56 - 56: Ii1I
 def is_rloc_in_rloc_set ( self , rloc ) :
  for O0O0OOo0O in self . registered_rlocs :
   if ( O0O0OOo0O . rle ) :
    for O0OOO in O0O0OOo0O . rle . rle_nodes :
     if ( O0OOO . address . is_exact_match ( rloc ) ) : return ( True )
     if 84 - 84: iII111i
     if 21 - 21: i11iIiiIii
   if ( O0O0OOo0O . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 30 - 30: OoO0O00 + OoooooooOO
  return ( False )
  if 98 - 98: I1ii11iIi11i % I1IiiI
  if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 66 - 66: IiII
  for O0O0OOo0O in prev_rloc_set :
   o0i1i1iiI = O0O0OOo0O . rloc
   if ( self . is_rloc_in_rloc_set ( o0i1i1iiI ) == False ) : return ( False )
   if 56 - 56: oO0o + OoooooooOO
  return ( True )
  if 75 - 75: O0 % Ii1I
  if 47 - 47: OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
  if 23 - 23: iII111i / iIii1I11I1II1
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
   if 5 - 5: O0
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 64 - 64: i1IIi * i1IIi . iII111i - O0 - oO0o % OoooooooOO
  if 14 - 14: Ii1I % OoO0O00 % I1Ii111 * O0
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 8 - 8: I1IiiI - i11iIiiIii * I1IiiI
  try :
   ooo0o0 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   IiIIii1I = ooo0o0 [ 2 ]
  except :
   return
   if 9 - 9: IiII * i11iIiiIii * iIii1I11I1II1 % I11i % I1IiiI
   if 84 - 84: OoooooooOO
   if 51 - 51: O0 * Oo0Ooo - OoooooooOO % OoOoOO00 . I1ii11iIi11i
   if 44 - 44: ooOoO0o / IiII + O0 . II111iiii
   if 12 - 12: Oo0Ooo
   if 54 - 54: OoOoOO00 . O0 % I1ii11iIi11i - II111iiii % I11i
  if ( len ( IiIIii1I ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 34 - 34: OoOoOO00 % ooOoO0o * I1IiiI % IiII
   if 62 - 62: OoooooooOO . OoooooooOO / I11i % OoOoOO00
  IiIIiiI = IiIIii1I [ self . a_record_index ]
  if ( IiIIiiI != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( IiIIiiI )
   self . insert_mr ( )
   if 2 - 2: IiII % I1ii11iIi11i * OoO0O00 + Oo0Ooo * iII111i
   if 85 - 85: OOooOOo * I1IiiI - iIii1I11I1II1 - OoOoOO00 + ooOoO0o . OoO0O00
   if 46 - 46: OoO0O00 * I1Ii111 . O0
   if 86 - 86: i11iIiiIii . Ii1I / OoOoOO00 / I11i * i1IIi
   if 40 - 40: o0oOOo0O0Ooo
   if 33 - 33: i11iIiiIii + I1Ii111 % I1ii11iIi11i - I1Ii111 * OoO0O00
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 1 - 1: II111iiii / I1IiiI + II111iiii % II111iiii - I1Ii111
  for IiIIiiI in IiIIii1I [ 1 : : ] :
   OoOOOO = lisp_address ( LISP_AFI_NONE , IiIIiiI , 0 , 0 )
   IIIIIii1Ii1II = lisp_get_map_resolver ( OoOOOO , None )
   if ( IIIIIii1Ii1II != None and IIIIIii1Ii1II . a_record_index == IiIIii1I . index ( IiIIiiI ) ) :
    continue
    if 24 - 24: I11i / Oo0Ooo / i1IIi + IiII
   IIIIIii1Ii1II = lisp_mr ( IiIIiiI , None , None )
   IIIIIii1Ii1II . a_record_index = IiIIii1I . index ( IiIIiiI )
   IIIIIii1Ii1II . dns_name = self . dns_name
   IIIIIii1Ii1II . last_dns_resolve = lisp_get_timestamp ( )
   if 10 - 10: I11i - IiII / II111iiii / oO0o % O0 / I1Ii111
   if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
   if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
   if 45 - 45: OOooOOo - OOooOOo % iII111i - IiII . O0
   if 6 - 6: iIii1I11I1II1 * II111iiii / O0 % IiII - I1Ii111
  oo0Oo00OO0000 = [ ]
  for IIIIIii1Ii1II in lisp_map_resolvers_list . values ( ) :
   if ( self . dns_name != IIIIIii1Ii1II . dns_name ) : continue
   OoOOOO = IIIIIii1Ii1II . map_resolver . print_address_no_iid ( )
   if ( OoOOOO in IiIIii1I ) : continue
   oo0Oo00OO0000 . append ( IIIIIii1Ii1II )
   if 74 - 74: Ii1I - OoOoOO00 + i11iIiiIii - II111iiii - i11iIiiIii . ooOoO0o
  for IIIIIii1Ii1II in oo0Oo00OO0000 : IIIIIii1Ii1II . delete_mr ( )
  if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
  if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
 def insert_mr ( self ) :
  OO0Oo00o0o0 = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ OO0Oo00o0o0 ] = self
  if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
  if 78 - 78: i1IIi
 def delete_mr ( self ) :
  OO0Oo00o0o0 = self . mr_name + self . map_resolver . print_address ( )
  if ( lisp_map_resolvers_list . has_key ( OO0Oo00o0o0 ) == False ) : return
  lisp_map_resolvers_list . pop ( OO0Oo00o0o0 )
  if 25 - 25: Ii1I * II111iiii / OoOoOO00
  if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
  if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
class lisp_ddt_root ( ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
  if 15 - 15: i11iIiiIii
  if 85 - 85: I1Ii111 + iII111i - oO0o
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
  if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
  if 64 - 64: OoOoOO00
 def print_referral ( self , eid_indent , referral_indent ) :
  II1i1 = lisp_print_elapsed ( self . uptime )
  oOOOOOO0oO = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , II1i1 ,
  # O0 . O0 % ooOoO0o
 oOOOOOO0oO , len ( self . referral_set ) ) )
  if 35 - 35: OoOoOO00
  for iIiIIIiiIi in self . referral_set . values ( ) :
   iIiIIIiiIi . print_ref_node ( referral_indent )
   if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
   if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
   if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 89 - 89: iIii1I11I1II1 . ooOoO0o
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 82 - 82: OoOoOO00 - II111iiii . OoO0O00 * ooOoO0o
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 78 - 78: OoOoOO00 % oO0o
  if 39 - 39: iIii1I11I1II1
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 72 - 72: II111iiii + I1Ii111 / Ii1I * iIii1I11I1II1
  if 95 - 95: OoooooooOO + OOooOOo + II111iiii + IiII + OoO0O00
 def print_ttl ( self ) :
  O0OOo = self . referral_ttl
  if ( O0OOo < 60 ) : return ( str ( O0OOo ) + " secs" )
  if 86 - 86: II111iiii / iII111i - I1ii11iIi11i
  if ( ( O0OOo % 60 ) == 0 ) :
   O0OOo = str ( O0OOo / 60 ) + " mins"
  else :
   O0OOo = str ( O0OOo ) + " secs"
   if 65 - 65: I1ii11iIi11i + OoOoOO00
  return ( O0OOo )
  if 43 - 43: O0 + I11i % II111iiii
  if 56 - 56: IiII + Oo0Ooo . IiII % iIii1I11I1II1 % ooOoO0o % ooOoO0o
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # i1IIi - o0oOOo0O0Ooo * I1ii11iIi11i / i11iIiiIii % Ii1I
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 51 - 51: I11i + i11iIiiIii / O0 % I1Ii111
  if 8 - 8: oO0o . OoO0O00 / IiII - oO0o / OoOoOO00 - i1IIi
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   O0OOoO = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( O0OOoO == None ) :
    O0OOoO = lisp_referral ( )
    O0OOoO . eid . copy_address ( self . group )
    O0OOoO . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , O0OOoO )
    if 48 - 48: OoooooooOO + II111iiii
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( O0OOoO . group )
   O0OOoO . add_source_entry ( self )
   if 46 - 46: I1IiiI - II111iiii * OoO0O00 % OoooooooOO / OoO0O00 + II111iiii
   if 92 - 92: OoOoOO00 - iIii1I11I1II1
   if 10 - 10: iII111i - I1IiiI / I1ii11iIi11i - i1IIi - II111iiii % i11iIiiIii
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   O0OOoO = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( O0OOoO == None ) : return
   if 2 - 2: ooOoO0o % ooOoO0o
   IiiII = O0OOoO . lookup_source_cache ( self . eid , True )
   if ( IiiII == None ) : return
   if 94 - 94: ooOoO0o / OoooooooOO * i1IIi . Oo0Ooo * i11iIiiIii
   O0OOoO . source_cache . delete_cache ( self . eid )
   if ( O0OOoO . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 5 - 5: iIii1I11I1II1 / oO0o - Oo0Ooo - I1IiiI + iIii1I11I1II1
    if 63 - 63: iIii1I11I1II1 / ooOoO0o + O0 - o0oOOo0O0Ooo
    if 31 - 31: Ii1I
    if 76 - 76: OoO0O00 / II111iiii
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 92 - 92: o0oOOo0O0Ooo . i1IIi . OoOoOO00 / OoO0O00 % Ii1I
  if 61 - 61: i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 69 - 69: i11iIiiIii - iIii1I11I1II1
  if 40 - 40: I1IiiI / oO0o + ooOoO0o
  if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
class lisp_referral_node ( ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 37 - 37: I1ii11iIi11i
  if 24 - 24: O0 . I1Ii111 * i11iIiiIii
 def print_ref_node ( self , indent ) :
  ii1III11 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , ii1III11 ,
  # i1IIi % o0oOOo0O0Ooo * iIii1I11I1II1 - iII111i - iIii1I11I1II1 / OoooooooOO
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 25 - 25: O0 % OoOoOO00 - Ii1I * OoOoOO00 . i1IIi
  if 15 - 15: I1Ii111
  if 64 - 64: OOooOOo * Oo0Ooo
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
   if 96 - 96: Oo0Ooo / I1ii11iIi11i * iIii1I11I1II1 / iII111i
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
   if 18 - 18: I1Ii111
   if 29 - 29: i1IIi - I1IiiI / i1IIi
   if 64 - 64: IiII
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 69 - 69: OOooOOo . I1IiiI
  try :
   ooo0o0 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   IiIIii1I = ooo0o0 [ 2 ]
  except :
   return
   if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
   if 22 - 22: iII111i % I11i % O0 - I11i
   if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
   if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
   if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
   if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
  if ( len ( IiIIii1I ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
   if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
  IiIIiiI = IiIIii1I [ self . a_record_index ]
  if ( IiIIiiI != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( IiIIiiI )
   self . insert_ms ( )
   if 97 - 97: iIii1I11I1II1 * I1Ii111
   if 39 - 39: I1Ii111 . II111iiii
   if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
   if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
   if 34 - 34: I1IiiI
   if 56 - 56: Ii1I
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 71 - 71: O0 / i1IIi
  for IiIIiiI in IiIIii1I [ 1 : : ] :
   OoOOOO = lisp_address ( LISP_AFI_NONE , IiIIiiI , 0 , 0 )
   I1Ii11IIiiI = lisp_get_map_server ( OoOOOO )
   if ( I1Ii11IIiiI != None and I1Ii11IIiiI . a_record_index == IiIIii1I . index ( IiIIiiI ) ) :
    continue
    if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
   I1Ii11IIiiI = copy . deepcopy ( self )
   I1Ii11IIiiI . map_server . store_address ( IiIIiiI )
   I1Ii11IIiiI . a_record_index = IiIIii1I . index ( IiIIiiI )
   I1Ii11IIiiI . last_dns_resolve = lisp_get_timestamp ( )
   I1Ii11IIiiI . insert_ms ( )
   if 82 - 82: oO0o * i11iIiiIii % o0oOOo0O0Ooo % IiII - I11i - OoO0O00
   if 24 - 24: oO0o . II111iiii + OoO0O00 * I1ii11iIi11i / oO0o
   if 86 - 86: I1Ii111 + I1ii11iIi11i
   if 63 - 63: ooOoO0o - i11iIiiIii . o0oOOo0O0Ooo - i1IIi - IiII
   if 32 - 32: I1Ii111 / iIii1I11I1II1 + oO0o % I11i * OoooooooOO
  oo0Oo00OO0000 = [ ]
  for I1Ii11IIiiI in lisp_map_servers_list . values ( ) :
   if ( self . dns_name != I1Ii11IIiiI . dns_name ) : continue
   OoOOOO = I1Ii11IIiiI . map_server . print_address_no_iid ( )
   if ( OoOOOO in IiIIii1I ) : continue
   oo0Oo00OO0000 . append ( I1Ii11IIiiI )
   if 69 - 69: OOooOOo
  for I1Ii11IIiiI in oo0Oo00OO0000 : I1Ii11IIiiI . delete_ms ( )
  if 9 - 9: i11iIiiIii * Oo0Ooo
  if 33 - 33: oO0o / ooOoO0o
 def insert_ms ( self ) :
  OO0Oo00o0o0 = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ OO0Oo00o0o0 ] = self
  if 92 - 92: O0 . Oo0Ooo - Ii1I * I1IiiI * Oo0Ooo * iII111i
  if 78 - 78: Ii1I * iIii1I11I1II1 - Ii1I - I1ii11iIi11i * I1ii11iIi11i
 def delete_ms ( self ) :
  OO0Oo00o0o0 = self . ms_name + self . map_server . print_address ( )
  if ( lisp_map_servers_list . has_key ( OO0Oo00o0o0 ) == False ) : return
  lisp_map_servers_list . pop ( OO0Oo00o0o0 )
  if 44 - 44: o0oOOo0O0Ooo
  if 1 - 1: OoooooooOO / i11iIiiIii . o0oOOo0O0Ooo
  if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
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
  if 12 - 12: Oo0Ooo . o0oOOo0O0Ooo - i1IIi - oO0o % IiII . I11i
  if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 64 - 64: O0 - iII111i
  if 82 - 82: O0
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 37 - 37: I1Ii111
  if 98 - 98: iII111i - OoOoOO00 / I1Ii111 . OOooOOo - OOooOOo - ooOoO0o
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 84 - 84: OOooOOo * ooOoO0o / O0
  if 96 - 96: I11i . I11i % II111iiii
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 14 - 14: iII111i / OoooooooOO
  if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
  if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
 def set_socket ( self , device ) :
  I1iiIi111I = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  I1iiIi111I . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   I1iiIi111I . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   I1iiIi111I . close ( )
   I1iiIi111I = None
   if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
  self . raw_socket = I1iiIi111I
  if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
  if 11 - 11: I1IiiI
 def set_bridge_socket ( self , device ) :
  I1iiIi111I = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   I1iiIi111I = I1iiIi111I . bind ( ( device , 0 ) )
   self . bridge_socket = I1iiIi111I
  except :
   return
   if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
   if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
   if 91 - 91: OoO0O00
   if 8 - 8: oO0o
class lisp_datetime ( ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 96 - 96: IiII
  if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
 def valid_datetime ( self ) :
  iIiO00OooOoOO0o0 = self . datetime_name
  if ( iIiO00OooOoOO0o0 . find ( ":" ) == - 1 ) : return ( False )
  if ( iIiO00OooOoOO0o0 . find ( "-" ) == - 1 ) : return ( False )
  O0OOo0O , OoO0000 , II1I1I1 , time = iIiO00OooOoOO0o0 [ 0 : 4 ] , iIiO00OooOoOO0o0 [ 5 : 7 ] , iIiO00OooOoOO0o0 [ 8 : 10 ] , iIiO00OooOoOO0o0 [ 11 : : ]
  if 64 - 64: I1ii11iIi11i
  if ( ( O0OOo0O + OoO0000 + II1I1I1 ) . isdigit ( ) == False ) : return ( False )
  if ( OoO0000 < "01" and OoO0000 > "12" ) : return ( False )
  if ( II1I1I1 < "01" and II1I1I1 > "31" ) : return ( False )
  if 17 - 17: II111iiii + Ii1I - o0oOOo0O0Ooo * II111iiii / Oo0Ooo / II111iiii
  OooOOo0000Ooo , IiooOO000o0OO0 , ooooo0O00O = time . split ( ":" )
  if 14 - 14: Oo0Ooo
  if ( ( OooOOo0000Ooo + IiooOO000o0OO0 + ooooo0O00O ) . isdigit ( ) == False ) : return ( False )
  if ( OooOOo0000Ooo < "00" and OooOOo0000Ooo > "23" ) : return ( False )
  if ( IiooOO000o0OO0 < "00" and IiooOO000o0OO0 > "59" ) : return ( False )
  if ( ooooo0O00O < "00" and ooooo0O00O > "59" ) : return ( False )
  return ( True )
  if 20 - 20: O0 - I1ii11iIi11i
  if 34 - 34: OoO0O00 * iIii1I11I1II1 . iIii1I11I1II1
 def parse_datetime ( self ) :
  ii1iI1I1 = self . datetime_name
  ii1iI1I1 = ii1iI1I1 . replace ( "-" , "" )
  ii1iI1I1 = ii1iI1I1 . replace ( ":" , "" )
  self . datetime = int ( ii1iI1I1 )
  if 44 - 44: ooOoO0o % ooOoO0o - I1IiiI % Oo0Ooo
  if 9 - 9: IiII / iII111i * II111iiii + O0 % Oo0Ooo / i1IIi
 def now ( self ) :
  ii1III11 = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  ii1III11 = lisp_datetime ( ii1III11 )
  return ( ii1III11 )
  if 45 - 45: OoOoOO00 % i11iIiiIii . I1IiiI - O0 * i1IIi - I1IiiI
  if 48 - 48: IiII / iIii1I11I1II1
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 20 - 20: oO0o / OoooooooOO
  if 95 - 95: Oo0Ooo . i11iIiiIii
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 50 - 50: iII111i . i11iIiiIii - i1IIi
  if 24 - 24: i11iIiiIii % iII111i . oO0o
 def past ( self ) :
  return ( self . future ( ) == False )
  if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
  if 34 - 34: I1ii11iIi11i % ooOoO0o / II111iiii * O0 % OOooOOo
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 9 - 9: I1ii11iIi11i / I1ii11iIi11i - OOooOOo . iIii1I11I1II1
  if 33 - 33: I1IiiI + oO0o % I1IiiI / iII111i - ooOoO0o - i11iIiiIii
 def this_year ( self ) :
  iiI1 = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  ii1III11 = str ( self . datetime ) [ 0 : 4 ]
  return ( ii1III11 == iiI1 )
  if 39 - 39: I1ii11iIi11i * I1Ii111 . i1IIi * I1IiiI / o0oOOo0O0Ooo % II111iiii
  if 22 - 22: II111iiii % II111iiii
 def this_month ( self ) :
  iiI1 = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  ii1III11 = str ( self . datetime ) [ 0 : 6 ]
  return ( ii1III11 == iiI1 )
  if 38 - 38: I1ii11iIi11i + I1Ii111 / IiII % oO0o
  if 42 - 42: ooOoO0o
 def today ( self ) :
  iiI1 = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  ii1III11 = str ( self . datetime ) [ 0 : 8 ]
  return ( ii1III11 == iiI1 )
  if 62 - 62: OOooOOo + OoOoOO00 . iII111i
  if 26 - 26: OOooOOo
  if 89 - 89: i11iIiiIii . o0oOOo0O0Ooo % iIii1I11I1II1 * O0 + OOooOOo . o0oOOo0O0Ooo
  if 17 - 17: I1Ii111
  if 59 - 59: OoOoOO00 . OoOoOO00 * iII111i - Ii1I . i11iIiiIii
  if 68 - 68: iII111i
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
  if 68 - 68: I1Ii111 - OoO0O00 % OoO0O00 % OOooOOo - OoO0O00
  if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
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
  if 59 - 59: iII111i
  if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
 def match_policy_map_request ( self , mr , srloc ) :
  for i1i1I11I1I in self . match_clauses :
   IIIiIIi111 = i1i1I11I1I . source_eid
   I11iI1I = mr . source_eid
   if ( IIIiIIi111 and I11iI1I and I11iI1I . is_more_specific ( IIIiIIi111 ) == False ) : continue
   if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
   IIIiIIi111 = i1i1I11I1I . dest_eid
   I11iI1I = mr . target_eid
   if ( IIIiIIi111 and I11iI1I and I11iI1I . is_more_specific ( IIIiIIi111 ) == False ) : continue
   if 65 - 65: I1Ii111 + OOooOOo
   IIIiIIi111 = i1i1I11I1I . source_rloc
   I11iI1I = srloc
   if ( IIIiIIi111 and I11iI1I and I11iI1I . is_more_specific ( IIIiIIi111 ) == False ) : continue
   OOoOo0O0 = i1i1I11I1I . datetime_lower
   OO0O0OOooo = i1i1I11I1I . datetime_upper
   if ( OOoOo0O0 and OO0O0OOooo and OOoOo0O0 . now_in_range ( OO0O0OOooo ) == False ) : continue
   return ( True )
   if 19 - 19: ooOoO0o
  return ( False )
  if 53 - 53: O0 - ooOoO0o * I11i - oO0o / i1IIi % Ii1I
  if 100 - 100: i11iIiiIii / o0oOOo0O0Ooo
 def set_policy_map_reply ( self ) :
  o0o0OO = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( o0o0OO ) : return ( None )
  if 35 - 35: I1Ii111
  IIIi1iI1 = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   IIIi1iI1 . rloc . copy_address ( self . set_rloc_address )
   IiIIiiI = IIIi1iI1 . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( IiIIiiI ) )
   if 22 - 22: OoooooooOO / O0 / I1IiiI * I1ii11iIi11i % I11i + iII111i
  if ( self . set_rloc_record_name ) :
   IIIi1iI1 . rloc_name = self . set_rloc_record_name
   Iii = blue ( IIIi1iI1 . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( Iii ) )
   if 26 - 26: I1ii11iIi11i - o0oOOo0O0Ooo - i1IIi - Ii1I
  if ( self . set_geo_name ) :
   IIIi1iI1 . geo_name = self . set_geo_name
   Iii = IIIi1iI1 . geo_name
   oo0O0o = "" if lisp_geo_list . has_key ( Iii ) else "(not configured)"
   if 76 - 76: I1IiiI - oO0o
   lprint ( "Policy set-geo-name '{}' {}" . format ( Iii , oo0O0o ) )
   if 93 - 93: I1ii11iIi11i - OOooOOo - II111iiii * OoO0O00 . O0 - ooOoO0o
  if ( self . set_elp_name ) :
   IIIi1iI1 . elp_name = self . set_elp_name
   Iii = IIIi1iI1 . elp_name
   oo0O0o = "" if lisp_elp_list . has_key ( Iii ) else "(not configured)"
   if 53 - 53: OoO0O00 / i11iIiiIii . OoooooooOO
   lprint ( "Policy set-elp-name '{}' {}" . format ( Iii , oo0O0o ) )
   if 84 - 84: I1ii11iIi11i
  if ( self . set_rle_name ) :
   IIIi1iI1 . rle_name = self . set_rle_name
   Iii = IIIi1iI1 . rle_name
   oo0O0o = "" if lisp_rle_list . has_key ( Iii ) else "(not configured)"
   if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
   lprint ( "Policy set-rle-name '{}' {}" . format ( Iii , oo0O0o ) )
   if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
  if ( self . set_json_name ) :
   IIIi1iI1 . json_name = self . set_json_name
   Iii = IIIi1iI1 . json_name
   oo0O0o = "" if lisp_json_list . has_key ( Iii ) else "(not configured)"
   if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
   lprint ( "Policy set-json-name '{}' {}" . format ( Iii , oo0O0o ) )
   if 67 - 67: i1IIi * I1Ii111 * O0
  return ( IIIi1iI1 )
  if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
  if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 18 - 18: I1ii11iIi11i - i1IIi - IiII * II111iiii % I1Ii111 . II111iiii
  if 80 - 80: oO0o + OoO0O00 + o0oOOo0O0Ooo . OoOoOO00
  if 75 - 75: i11iIiiIii
class lisp_pubsub ( ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  self . eid_prefix = None
  if 58 - 58: iII111i
  if 48 - 48: OoO0O00 * OOooOOo / iII111i
 def add ( self , eid_prefix ) :
  self . eid_prefix = eid_prefix
  O0OOo = self . ttl
  oOooOOo000o0o = eid_prefix . print_prefix ( )
  if ( lisp_pubsub_cache . has_key ( oOooOOo000o0o ) == False ) :
   lisp_pubsub_cache [ oOooOOo000o0o ] = { }
   if 90 - 90: I1IiiI * i11iIiiIii . OOooOOo / o0oOOo0O0Ooo
  iIiii11 = lisp_pubsub_cache [ oOooOOo000o0o ]
  if 82 - 82: Oo0Ooo
  I11IiI1i11i1 = "Add"
  if ( iIiii11 . has_key ( self . xtr_id ) ) :
   I11IiI1i11i1 = "Replace"
   del ( iIiii11 [ self . xtr_id ] )
   if 35 - 35: Ii1I . O0 % i11iIiiIii * oO0o - OoooooooOO
  iIiii11 [ self . xtr_id ] = self
  if 87 - 87: iII111i * ooOoO0o - OOooOOo . O0
  oOooOOo000o0o = green ( oOooOOo000o0o , False )
  OO = red ( self . itr . print_address_no_iid ( ) , False )
  OoO0o00O0oOOo = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( I11IiI1i11i1 , oOooOOo000o0o ,
 OO , OoO0o00O0oOOo , O0OOo ) )
  if 20 - 20: OoOoOO00 - IiII
  if 9 - 9: O0 . I11i % I1ii11iIi11i * oO0o - I1Ii111 - i1IIi
 def delete ( self , eid_prefix ) :
  oOooOOo000o0o = eid_prefix . print_prefix ( )
  OO = red ( self . itr . print_address_no_iid ( ) , False )
  OoO0o00O0oOOo = "0x" + lisp_hex_string ( self . xtr_id )
  if ( lisp_pubsub_cache . has_key ( oOooOOo000o0o ) ) :
   iIiii11 = lisp_pubsub_cache [ oOooOOo000o0o ]
   if ( iIiii11 . has_key ( self . xtr_id ) ) :
    iIiii11 . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( oOooOOo000o0o ,
 OO , OoO0o00O0oOOo ) )
    if 66 - 66: II111iiii / Oo0Ooo
    if 93 - 93: iII111i + I11i * OoooooooOO . OoO0O00
    if 40 - 40: ooOoO0o * I1Ii111 + iII111i
    if 52 - 52: iII111i % I11i
    if 95 - 95: IiII + Ii1I / OoO0O00 - iII111i / I1IiiI
    if 27 - 27: Oo0Ooo + i1IIi + i11iIiiIii . OoO0O00 . OoO0O00
    if 56 - 56: I1Ii111 / OoO0O00 + o0oOOo0O0Ooo . OoooooooOO * Oo0Ooo
    if 14 - 14: OoO0O00
    if 21 - 21: II111iiii + i11iIiiIii + I11i % I1IiiI
    if 65 - 65: IiII + I1ii11iIi11i / iII111i / I1IiiI + Ii1I
    if 88 - 88: IiII % iIii1I11I1II1
    if 3 - 3: ooOoO0o / I1Ii111 % iIii1I11I1II1 % I11i * oO0o / iIii1I11I1II1
    if 75 - 75: i11iIiiIii . iII111i
    if 68 - 68: OOooOOo . I1ii11iIi11i % I1ii11iIi11i . i11iIiiIii
    if 45 - 45: oO0o % I1ii11iIi11i * I1Ii111
    if 21 - 21: O0 + i11iIiiIii
    if 72 - 72: OoOoOO00 * OoooooooOO % O0 / I1ii11iIi11i % Ii1I - I11i
    if 65 - 65: iIii1I11I1II1 + II111iiii * OoO0O00 * i11iIiiIii / IiII
    if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
    if 52 - 52: II111iiii * o0oOOo0O0Ooo
    if 95 - 95: I1Ii111 - OoooooooOO
    if 99 - 99: OoooooooOO % IiII . I11i + OoooooooOO
class lisp_trace ( ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 57 - 57: Ii1I / I1IiiI * i1IIi
  if 21 - 21: I11i . O0 * OoooooooOO + ooOoO0o * oO0o % i11iIiiIii
 def print_trace ( self ) :
  oO0oOo = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( oO0oOo ) )
  if 30 - 30: ooOoO0o * I1Ii111 + OoO0O00
  if 30 - 30: Ii1I / iII111i * Ii1I
 def encode ( self ) :
  i1IIi1ii1i1ii = socket . htonl ( 0x90000000 )
  o0o0ooOOo0oO = struct . pack ( "II" , i1IIi1ii1i1ii , 0 )
  o0o0ooOOo0oO += struct . pack ( "Q" , self . nonce )
  o0o0ooOOo0oO += json . dumps ( self . packet_json )
  return ( o0o0ooOOo0oO )
  if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
  if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
 def decode ( self , packet ) :
  Iii1I = "I"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( False )
  i1IIi1ii1i1ii = struct . unpack ( Iii1I , packet [ : IiiiiI ] ) [ 0 ]
  packet = packet [ IiiiiI : : ]
  i1IIi1ii1i1ii = socket . ntohl ( i1IIi1ii1i1ii )
  if ( ( i1IIi1ii1i1ii & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 71 - 71: i1IIi % O0 % ooOoO0o
  if ( len ( packet ) < IiiiiI ) : return ( False )
  IiIIiiI = struct . unpack ( Iii1I , packet [ : IiiiiI ] ) [ 0 ]
  packet = packet [ IiiiiI : : ]
  if 24 - 24: O0
  IiIIiiI = socket . ntohl ( IiIIiiI )
  oooO = IiIIiiI >> 24
  O000OO000 = ( IiIIiiI >> 16 ) & 0xff
  iI111IiI1I1Ii = ( IiIIiiI >> 8 ) & 0xff
  Iii1 = IiIIiiI & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( oooO , O000OO000 , iI111IiI1I1Ii , Iii1 )
  self . local_port = str ( i1IIi1ii1i1ii & 0xffff )
  if 18 - 18: II111iiii . o0oOOo0O0Ooo + OoO0O00
  Iii1I = "Q"
  IiiiiI = struct . calcsize ( Iii1I )
  if ( len ( packet ) < IiiiiI ) : return ( False )
  self . nonce = struct . unpack ( Iii1I , packet [ : IiiiiI ] ) [ 0 ]
  packet = packet [ IiiiiI : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 69 - 69: OoO0O00 . ooOoO0o * ooOoO0o * iIii1I11I1II1
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 8 - 8: iII111i . oO0o . OOooOOo + iII111i . Ii1I
  return ( True )
  if 46 - 46: OoO0O00
  if 21 - 21: iIii1I11I1II1 - iII111i
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 15 - 15: O0 + iII111i + i11iIiiIii
  if 31 - 31: iIii1I11I1II1 * iIii1I11I1II1 . I11i
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  IIIi1iI1 , IiO0o = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( IIIi1iI1 == None ) :
   IIIi1iI1 , IiO0o = rts_rloc . split ( ":" )
   IiO0o = int ( IiO0o )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( IIIi1iI1 , IiO0o ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( IIIi1iI1 ,
 IiO0o ) )
   if 52 - 52: i11iIiiIii / oO0o / IiII
   if 84 - 84: I11i . oO0o + ooOoO0o
  if ( lisp_socket == None ) :
   I1iiIi111I = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   I1iiIi111I . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   I1iiIi111I . sendto ( packet , ( IIIi1iI1 , IiO0o ) )
   I1iiIi111I . close ( )
  else :
   lisp_socket . sendto ( packet , ( IIIi1iI1 , IiO0o ) )
   if 75 - 75: I1Ii111
   if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
   if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
 def packet_length ( self ) :
  O0I1II1 = 8 ; O0Ooo0 = 4 + 4 + 8
  return ( O0I1II1 + O0Ooo0 + len ( json . dumps ( self . packet_json ) ) )
  if 48 - 48: Oo0Ooo - oO0o
  if 80 - 80: OoO0O00 * OoOoOO00 - OoooooooOO * iII111i % ooOoO0o
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  OO0Oo00o0o0 = self . local_rloc + ":" + self . local_port
  iiIiII11i1 = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ OO0Oo00o0o0 ] = iiIiII11i1
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( OO0Oo00o0o0 , iiIiII11i1 ) )
  if 17 - 17: OoO0O00 % II111iiii . i1IIi . OOooOOo
  if 49 - 49: II111iiii / OoOoOO00 * IiII % OoO0O00
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  OO0Oo00o0o0 = local_rloc_and_port
  try : iiIiII11i1 = lisp_rtr_nat_trace_cache [ OO0Oo00o0o0 ]
  except : iiIiII11i1 = ( None , None )
  return ( iiIiII11i1 )
  if 77 - 77: OoOoOO00 + OOooOOo % o0oOOo0O0Ooo
  if 3 - 3: ooOoO0o / i1IIi
  if 71 - 71: Ii1I + oO0o % IiII
  if 15 - 15: ooOoO0o . Oo0Ooo
  if 42 - 42: OOooOOo . i11iIiiIii % O0 - OoO0O00
  if 34 - 34: OOooOOo % oO0o * OOooOOo * iIii1I11I1II1
  if 18 - 18: I1IiiI / I11i
  if 64 - 64: I11i * i11iIiiIii
  if 16 - 16: I1Ii111 * II111iiii * I1Ii111 . o0oOOo0O0Ooo
  if 96 - 96: ooOoO0o - o0oOOo0O0Ooo % O0 * Ii1I . OoOoOO00
  if 80 - 80: I1IiiI
def lisp_get_map_server ( address ) :
 for I1Ii11IIiiI in lisp_map_servers_list . values ( ) :
  if ( I1Ii11IIiiI . map_server . is_exact_match ( address ) ) : return ( I1Ii11IIiiI )
  if 31 - 31: I1Ii111 + o0oOOo0O0Ooo . I1IiiI + I11i . oO0o
 return ( None )
 if 50 - 50: Ii1I . OOooOOo
 if 84 - 84: OoOoOO00 * OoO0O00 + I1IiiI
 if 38 - 38: OoooooooOO % I1IiiI
 if 80 - 80: iII111i / O0 % OoooooooOO / Oo0Ooo
 if 75 - 75: ooOoO0o
 if 72 - 72: oO0o . OoooooooOO % ooOoO0o % OoO0O00 * oO0o * OoO0O00
 if 14 - 14: I11i / I11i
def lisp_get_any_map_server ( ) :
 for I1Ii11IIiiI in lisp_map_servers_list . values ( ) : return ( I1Ii11IIiiI )
 return ( None )
 if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
 if 93 - 93: oO0o / ooOoO0o - I1Ii111
 if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
 if 26 - 26: O0 + Oo0Ooo
 if 30 - 30: IiII
 if 6 - 6: O0
 if 92 - 92: I11i
 if 76 - 76: I11i / iIii1I11I1II1 - i11iIiiIii / O0 / O0
 if 19 - 19: Ii1I . I1IiiI - i1IIi * ooOoO0o . iIii1I11I1II1
 if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  IiIIiiI = address . print_address ( )
  IIIIIii1Ii1II = None
  for OO0Oo00o0o0 in lisp_map_resolvers_list :
   if ( OO0Oo00o0o0 . find ( IiIIiiI ) == - 1 ) : continue
   IIIIIii1Ii1II = lisp_map_resolvers_list [ OO0Oo00o0o0 ]
   if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
  return ( IIIIIii1Ii1II )
  if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
  if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
  if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
  if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
  if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
  if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
  if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
 if ( eid == "" ) :
  o0oOOo0O0O0OOO = ""
 elif ( eid == None ) :
  o0oOOo0O0O0OOO = "all"
 else :
  oooOOoO0oo0 = lisp_db_for_lookups . lookup_cache ( eid , False )
  o0oOOo0O0O0OOO = "all" if oooOOoO0oo0 == None else oooOOoO0oo0 . use_mr_name
  if 25 - 25: IiII % O0 - I1IiiI + I1Ii111 . i11iIiiIii
  if 50 - 50: OOooOOo * OoooooooOO . OoO0O00 . oO0o
 o0IiI1I1i = None
 for IIIIIii1Ii1II in lisp_map_resolvers_list . values ( ) :
  if ( o0oOOo0O0O0OOO == "" ) : return ( IIIIIii1Ii1II )
  if ( IIIIIii1Ii1II . mr_name != o0oOOo0O0O0OOO ) : continue
  if ( o0IiI1I1i == None or IIIIIii1Ii1II . last_used < o0IiI1I1i . last_used ) : o0IiI1I1i = IIIIIii1Ii1II
  if 69 - 69: OoO0O00 / oO0o * I11i
 return ( o0IiI1I1i )
 if 84 - 84: oO0o % ooOoO0o % I11i
 if 58 - 58: I11i
 if 93 - 93: I1IiiI
 if 62 - 62: i11iIiiIii + iIii1I11I1II1 / iII111i * iIii1I11I1II1 % I11i % O0
 if 10 - 10: OoOoOO00 . i1IIi . OoooooooOO * I1Ii111 + oO0o + OoO0O00
 if 66 - 66: i11iIiiIii + O0 * ooOoO0o - I1Ii111 - OOooOOo . IiII
 if 62 - 62: II111iiii / I1IiiI * iIii1I11I1II1
 if 85 - 85: II111iiii * Ii1I * O0
def lisp_get_decent_map_resolver ( eid ) :
 I1i11II = lisp_get_decent_index ( eid )
 oooOOOO0O = str ( I1i11II ) + "." + lisp_decent_dns_suffix
 if 31 - 31: oO0o / Oo0Ooo / OoO0O00 + I1ii11iIi11i
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( oooOOOO0O , False ) , eid . print_prefix ( ) ) )
 if 34 - 34: OOooOOo * Oo0Ooo / I1Ii111 / OOooOOo
 if 92 - 92: O0 * O0
 o0IiI1I1i = None
 for IIIIIii1Ii1II in lisp_map_resolvers_list . values ( ) :
  if ( oooOOOO0O != IIIIIii1Ii1II . dns_name ) : continue
  if ( o0IiI1I1i == None or IIIIIii1Ii1II . last_used < o0IiI1I1i . last_used ) : o0IiI1I1i = IIIIIii1Ii1II
  if 37 - 37: iIii1I11I1II1 / I1Ii111 + OoO0O00
 return ( o0IiI1I1i )
 if 85 - 85: ooOoO0o / I1IiiI
 if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
 if 99 - 99: i11iIiiIii - I1ii11iIi11i
 if 64 - 64: IiII . OoOoOO00 . Oo0Ooo . I1Ii111 / I11i / Ii1I
 if 95 - 95: iIii1I11I1II1 . Ii1I % oO0o - I11i % IiII
 if 42 - 42: OoOoOO00 + oO0o * i1IIi + i11iIiiIii
 if 25 - 25: Ii1I - Ii1I - I1ii11iIi11i / i1IIi . OoOoOO00 % Oo0Ooo
def lisp_ipv4_input ( packet ) :
 if 76 - 76: I1Ii111 / OoOoOO00
 if 61 - 61: Oo0Ooo . i1IIi
 if 78 - 78: i11iIiiIii
 if 20 - 20: Ii1I
 if ( ord ( packet [ 9 ] ) == 2 ) : return ( [ True , packet ] )
 if 100 - 100: OoooooooOO . I1Ii111
 if 32 - 32: iIii1I11I1II1 . iIii1I11I1II1 % II111iiii / Oo0Ooo . iIii1I11I1II1 . O0
 if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
 if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
 ii1II1II = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
 if ( ii1II1II == 0 ) :
  dprint ( "Packet arrived with checksum of 0!" )
 else :
  packet = lisp_ip_checksum ( packet )
  ii1II1II = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
  if ( ii1II1II != 0 ) :
   dprint ( "IPv4 header checksum failed for inner header" )
   packet = lisp_format_packet ( packet [ 0 : 20 ] )
   dprint ( "Packet header: {}" . format ( packet ) )
   return ( [ False , None ] )
   if 87 - 87: I1ii11iIi11i . i1IIi - I11i + OoOoOO00 . O0
   if 37 - 37: IiII
   if 65 - 65: ooOoO0o * Ii1I / I1IiiI . i1IIi % ooOoO0o . OoooooooOO
   if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
   if 88 - 88: i1IIi - OoOoOO00
   if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
   if 7 - 7: Ii1I / iIii1I11I1II1
 O0OOo = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( O0OOo == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( O0OOo == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 36 - 36: iIii1I11I1II1 % i11iIiiIii
  return ( [ False , None ] )
  if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
  if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
 O0OOo -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , O0OOo ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( [ False , packet ] )
 if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
 if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
 if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
 if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
 if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
 if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
 if 38 - 38: IiII
def lisp_ipv6_input ( packet ) :
 OO0oooOO = packet . inner_dest
 packet = packet . packet
 if 78 - 78: Oo0Ooo * I1ii11iIi11i % OOooOOo / Oo0Ooo + I1ii11iIi11i * IiII
 if 2 - 2: Oo0Ooo - OoOoOO00
 if 22 - 22: OoO0O00 - oO0o - O0
 if 49 - 49: iIii1I11I1II1 + I1Ii111 / i11iIiiIii
 if 62 - 62: ooOoO0o . I1IiiI * i11iIiiIii
 O0OOo = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( O0OOo == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( O0OOo == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 2 - 2: i11iIiiIii
  return ( None )
  if 86 - 86: I1Ii111 + o0oOOo0O0Ooo
  if 17 - 17: iIii1I11I1II1
  if 32 - 32: IiII - OoOoOO00
  if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
  if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
 if ( OO0oooOO . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 83 - 83: OoO0O00 . I11i * I1ii11iIi11i - II111iiii
  if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
 O0OOo -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , O0OOo ) + packet [ 8 : : ]
 return ( packet )
 if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
 if 16 - 16: Oo0Ooo
 if 24 - 24: o0oOOo0O0Ooo . OoOoOO00
 if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
 if 96 - 96: I1IiiI . oO0o % O0
 if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
 if 87 - 87: OoooooooOO
def lisp_mac_input ( packet ) :
 return ( packet )
 if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
 if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
 if 23 - 23: o0oOOo0O0Ooo . o0oOOo0O0Ooo - iIii1I11I1II1 / o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + I1Ii111 . I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
 if 2 - 2: oO0o % iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
 if 45 - 45: II111iiii . iII111i
 if 55 - 55: ooOoO0o / iII111i / O0
 if 98 - 98: O0 % iII111i + II111iiii
 if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
def lisp_rate_limit_map_request ( dest ) :
 iiI1 = lisp_get_timestamp ( )
 if 23 - 23: iIii1I11I1II1 + oO0o . oO0o / o0oOOo0O0Ooo
 if 77 - 77: i1IIi * o0oOOo0O0Ooo * IiII
 if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
 if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
 Ii1i1 = iiI1 - lisp_no_map_request_rate_limit
 if ( Ii1i1 < LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME ) :
  Oo = int ( LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME - Ii1i1 )
  dprint ( "No Rate-Limit Mode for another {} secs" . format ( Oo ) )
  return ( False )
  if 36 - 36: O0
  if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
  if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
  if 21 - 21: i1IIi * iII111i + OoO0O00
  if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
 if ( lisp_last_map_request_sent == None ) : return ( False )
 Ii1i1 = iiI1 - lisp_last_map_request_sent
 i1iI1iI = ( Ii1i1 < LISP_MAP_REQUEST_RATE_LIMIT )
 if 85 - 85: OoooooooOO
 if ( i1iI1iI ) :
  dprint ( "Rate-limiting Map-Request for {}, sent {} secs ago" . format ( green ( dest . print_address ( ) , False ) , round ( Ii1i1 , 3 ) ) )
  if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
  if 8 - 8: I1Ii111
 return ( i1iI1iI )
 if 86 - 86: ooOoO0o + iII111i * O0 % OoO0O00 + OoOoOO00
 if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
 if 9 - 9: iIii1I11I1II1 + Ii1I + I11i
 if 96 - 96: OoO0O00 + i11iIiiIii + OoO0O00
 if 7 - 7: i1IIi . I1IiiI
 if 68 - 68: OoooooooOO
 if 91 - 91: IiII . ooOoO0o * I11i
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ,
 pubsub = False ) :
 global lisp_last_map_request_sent
 if 39 - 39: o0oOOo0O0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 . II111iiii
 if 36 - 36: I1IiiI * i1IIi + OoOoOO00
 if 63 - 63: OoOoOO00 - iII111i
 if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
 if 82 - 82: iIii1I11I1II1 / OOooOOo
 i1I1 = o0OoOO = None
 if ( rloc ) :
  i1I1 = rloc . rloc
  o0OoOO = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 87 - 87: iIii1I11I1II1 - iIii1I11I1II1 . I1ii11iIi11i . I1IiiI * iII111i * iIii1I11I1II1
  if 100 - 100: iIii1I11I1II1 . I1ii11iIi11i . i11iIiiIii % i11iIiiIii % I11i % Ii1I
  if 39 - 39: I11i + OoOoOO00
  if 52 - 52: OoooooooOO - OoO0O00
  if 24 - 24: iII111i / Oo0Ooo - I1ii11iIi11i + o0oOOo0O0Ooo
 IIiIiII , iIIiI , OoO = lisp_myrlocs
 if ( IIiIiII == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 64 - 64: oO0o - i11iIiiIii
 if ( iIIiI == None and i1I1 != None and i1I1 . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 62 - 62: OoooooooOO - OoooooooOO / OoO0O00 - II111iiii . iIii1I11I1II1
  if 2 - 2: O0 + o0oOOo0O0Ooo % OOooOOo . ooOoO0o % i1IIi
 OOo00o = lisp_map_request ( )
 OOo00o . record_count = 1
 OOo00o . nonce = lisp_get_control_nonce ( )
 OOo00o . rloc_probe = ( i1I1 != None )
 OOo00o . subscribe_bit = pubsub
 OOo00o . xtr_id_present = pubsub
 if 21 - 21: OoOoOO00 / OoooooooOO + I1Ii111 - IiII
 if 62 - 62: Oo0Ooo % iII111i + OoooooooOO - I1ii11iIi11i % iII111i % iIii1I11I1II1
 if 54 - 54: IiII + OoOoOO00 / II111iiii % i11iIiiIii . I1Ii111
 if 69 - 69: i1IIi + ooOoO0o + Ii1I
 if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
 if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
 if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
 if ( rloc ) : rloc . last_rloc_probe_nonce = OOo00o . nonce
 if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
 I1IIiIiIIiIiI = deid . is_multicast_address ( )
 if ( I1IIiIiIIiIiI ) :
  OOo00o . target_eid = seid
  OOo00o . target_group = deid
 else :
  OOo00o . target_eid = deid
  if 8 - 8: i1IIi
  if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
  if 97 - 97: OoooooooOO % ooOoO0o . I1Ii111 / iII111i
  if 59 - 59: II111iiii + O0 . I1ii11iIi11i . Oo0Ooo * OoO0O00
  if 35 - 35: oO0o / I1Ii111 * OOooOOo + OoooooooOO . IiII
  if 1 - 1: I1IiiI + I1Ii111 / OOooOOo . Ii1I . oO0o / I1ii11iIi11i
  if 54 - 54: OOooOOo
  if 86 - 86: oO0o * Oo0Ooo / OOooOOo
  if 18 - 18: II111iiii - I1Ii111
 if ( OOo00o . rloc_probe == False ) :
  oooOOoO0oo0 = lisp_get_signature_eid ( )
  if ( oooOOoO0oo0 ) :
   OOo00o . signature_eid . copy_address ( oooOOoO0oo0 . eid )
   OOo00o . privkey_filename = "./lisp-sig.pem"
   if 13 - 13: i11iIiiIii - O0 % OoOoOO00 + OOooOOo * ooOoO0o
   if 55 - 55: i1IIi - OOooOOo / I11i * Ii1I
   if 20 - 20: OoOoOO00 * iIii1I11I1II1 % O0 - i1IIi
   if 51 - 51: I1ii11iIi11i * Ii1I - oO0o / O0 * OoooooooOO
   if 12 - 12: i1IIi / iIii1I11I1II1 / O0 * OoO0O00
   if 15 - 15: i11iIiiIii / IiII + Ii1I % OOooOOo % I1ii11iIi11i * oO0o
 if ( seid == None or I1IIiIiIIiIiI ) :
  OOo00o . source_eid . afi = LISP_AFI_NONE
 else :
  OOo00o . source_eid = seid
  if 24 - 24: OOooOOo / OOooOOo + I11i / iII111i . oO0o - iII111i
  if 59 - 59: I1ii11iIi11i % II111iiii - i11iIiiIii - I1Ii111
  if 34 - 34: II111iiii + iII111i / IiII
  if 47 - 47: OoO0O00
  if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
  if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
  if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
  if 100 - 100: II111iiii . IiII . I11i
  if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
  if 3 - 3: OoooooooOO
  if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
  if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
 if ( i1I1 != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( i1I1 . is_private_address ( ) == False ) :
   IIiIiII = lisp_get_any_translated_rloc ( )
   if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
  if ( IIiIiII == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
   if 37 - 37: I1ii11iIi11i * IiII
   if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
   if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
   if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
   if 46 - 46: OoooooooOO * OoO0O00 . I1Ii111
   if 95 - 95: ooOoO0o . I1ii11iIi11i . ooOoO0o / I1IiiI * OoOoOO00 . O0
   if 78 - 78: oO0o
 if ( i1I1 == None or i1I1 . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and i1I1 == None ) :
   iIiiii1 = lisp_get_any_translated_rloc ( )
   if ( iIiiii1 != None ) : IIiIiII = iIiiii1
   if 21 - 21: I1IiiI % Oo0Ooo - II111iiii / I1IiiI . OoOoOO00 - o0oOOo0O0Ooo
  OOo00o . itr_rlocs . append ( IIiIiII )
  if 23 - 23: OoOoOO00 / O0 * OoOoOO00 . I1IiiI + Oo0Ooo . iII111i
 if ( i1I1 == None or i1I1 . is_ipv6 ( ) ) :
  if ( iIIiI == None or iIIiI . is_ipv6_link_local ( ) ) :
   iIIiI = None
  else :
   OOo00o . itr_rloc_count = 1 if ( i1I1 == None ) else 0
   OOo00o . itr_rlocs . append ( iIIiI )
   if 1 - 1: i11iIiiIii * OoO0O00 - OoooooooOO + OoooooooOO
   if 31 - 31: OoooooooOO - OoOoOO00 * II111iiii % ooOoO0o - ooOoO0o / i11iIiiIii
   if 8 - 8: I1IiiI . i1IIi - I11i
   if 85 - 85: OOooOOo * IiII % O0 / I1ii11iIi11i
   if 17 - 17: Oo0Ooo / i11iIiiIii / I11i - I1Ii111
   if 3 - 3: I1Ii111 - Oo0Ooo / iIii1I11I1II1
   if 71 - 71: o0oOOo0O0Ooo + i11iIiiIii + OoooooooOO % OoOoOO00 - I1ii11iIi11i / OoooooooOO
   if 26 - 26: II111iiii
   if 41 - 41: Oo0Ooo . OoOoOO00 . iII111i / i11iIiiIii
 if ( i1I1 != None and OOo00o . itr_rlocs != [ ] ) :
  oO0o0o00O = OOo00o . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   oO0o0o00O = IIiIiII
  elif ( deid . is_ipv6 ( ) ) :
   oO0o0o00O = iIIiI
  else :
   oO0o0o00O = IIiIiII
   if 65 - 65: iII111i * o0oOOo0O0Ooo * OoooooooOO + I11i + oO0o % OoO0O00
   if 1 - 1: I1ii11iIi11i . ooOoO0o
   if 54 - 54: OoOoOO00 % I1IiiI . ooOoO0o + IiII / i11iIiiIii / o0oOOo0O0Ooo
   if 51 - 51: OoOoOO00 / Ii1I . I1IiiI / Ii1I . II111iiii - iIii1I11I1II1
   if 78 - 78: I11i
   if 42 - 42: Ii1I
 o0o0ooOOo0oO = OOo00o . encode ( i1I1 , o0OoOO )
 OOo00o . print_map_request ( )
 if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
 if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
 if 21 - 21: I1ii11iIi11i - ooOoO0o
 if 81 - 81: iII111i / i11iIiiIii / I1Ii111
 if 70 - 70: I1ii11iIi11i / i11iIiiIii
 if 90 - 90: II111iiii / OoOoOO00 . Ii1I . OoooooooOO
 if ( i1I1 != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   I1OOoO0OoOOo0 = lisp_get_nat_info ( i1I1 , rloc . rloc_name )
   if 76 - 76: OoooooooOO
   if 78 - 78: IiII % i11iIiiIii
   if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
   if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
   if ( I1OOoO0OoOOo0 == None ) :
    iiiI1I = rloc . rloc . print_address_no_iid ( )
    OoIi1I1I = "gleaned-{}" . format ( iiiI1I )
    IIIiIIi111 = rloc . translated_port
    I1OOoO0OoOOo0 = lisp_nat_info ( iiiI1I , OoIi1I1I , IIIiIIi111 )
    if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
   lisp_encapsulate_rloc_probe ( lisp_sockets , i1I1 , I1OOoO0OoOOo0 ,
 o0o0ooOOo0oO )
   return
   if 19 - 19: o0oOOo0O0Ooo
   if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
  O0O0 = i1I1 . print_address_no_iid ( )
  OO0oooOO = lisp_convert_4to6 ( O0O0 )
  lisp_send ( lisp_sockets , OO0oooOO , LISP_CTRL_PORT , o0o0ooOOo0oO )
  return
  if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
  if 71 - 71: OoO0O00 - I11i
  if 96 - 96: I1Ii111 / Ii1I
  if 65 - 65: I1ii11iIi11i * O0 . IiII
  if 11 - 11: I11i / Ii1I % oO0o
  if 50 - 50: i11iIiiIii
 Oo00oO = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  IIIIIii1Ii1II = lisp_get_decent_map_resolver ( deid )
 else :
  IIIIIii1Ii1II = lisp_get_map_resolver ( None , Oo00oO )
  if 61 - 61: i1IIi - i1IIi - I11i
 if ( IIIIIii1Ii1II == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 68 - 68: ooOoO0o - I1ii11iIi11i - OoO0O00 % O0 / I1ii11iIi11i - iIii1I11I1II1
  return
  if 66 - 66: i11iIiiIii
 IIIIIii1Ii1II . last_used = lisp_get_timestamp ( )
 IIIIIii1Ii1II . map_requests_sent += 1
 if ( IIIIIii1Ii1II . last_nonce == 0 ) : IIIIIii1Ii1II . last_nonce = OOo00o . nonce
 if 4 - 4: I1IiiI
 if 36 - 36: Ii1I
 if 76 - 76: i11iIiiIii + i1IIi
 if 56 - 56: OoOoOO00 + II111iiii / i11iIiiIii * OoOoOO00 * OoooooooOO
 if ( seid == None ) : seid = oO0o0o00O
 lisp_send_ecm ( lisp_sockets , o0o0ooOOo0oO , seid , lisp_ephem_port , deid ,
 IIIIIii1Ii1II . map_resolver )
 if 15 - 15: OoOoOO00 / OoooooooOO + OOooOOo
 if 76 - 76: Ii1I * iII111i . OoooooooOO
 if 92 - 92: iIii1I11I1II1 - Oo0Ooo - I1IiiI - OOooOOo * I1Ii111
 if 44 - 44: I1Ii111 - II111iiii / OOooOOo
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 50 - 50: I11i / I1ii11iIi11i
 if 60 - 60: II111iiii / Ii1I + OoO0O00 % I1IiiI * i1IIi / II111iiii
 if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
 if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
 IIIIIii1Ii1II . resolve_dns_name ( )
 return
 if 3 - 3: OOooOOo / OoOoOO00 % iIii1I11I1II1
 if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 if 48 - 48: O0
 if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
 if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
 if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
 if 96 - 96: ooOoO0o * Ii1I + I11i + II111iiii * I1IiiI / iII111i
 if 40 - 40: OoooooooOO - I11i % OOooOOo - I1IiiI . I1IiiI + Ii1I
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 97 - 97: OOooOOo . OoooooooOO . OOooOOo . i11iIiiIii
 if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
 if 79 - 79: oO0o
 if 47 - 47: OoooooooOO - i1IIi * OOooOOo
 I1i1 = lisp_info ( )
 I1i1 . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : I1i1 . hostname += "-" + device_name
 if 61 - 61: O0 * OoooooooOO % O0 * Ii1I
 O0O0 = dest . print_address_no_iid ( )
 if 3 - 3: IiII + OoooooooOO - i1IIi
 if 94 - 94: ooOoO0o / iIii1I11I1II1 + I11i + I1ii11iIi11i
 if 67 - 67: IiII / o0oOOo0O0Ooo . O0
 if 7 - 7: II111iiii . OoOoOO00 % OoOoOO00 % Ii1I + Oo0Ooo - ooOoO0o
 if 29 - 29: OoOoOO00 - i1IIi
 if 5 - 5: I1IiiI - ooOoO0o + O0
 if 47 - 47: i1IIi - II111iiii - II111iiii
 if 31 - 31: Ii1I
 if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
 if 8 - 8: oO0o
 if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
 if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
 if 1 - 1: OoooooooOO . Ii1I
 if 68 - 68: Ii1I
 if 98 - 98: iII111i
 if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
 iiIIiIII11IIii = False
 if ( device_name ) :
  ii1IiIIiI = lisp_get_host_route_next_hop ( O0O0 )
  if 62 - 62: o0oOOo0O0Ooo + I1ii11iIi11i % OoOoOO00 * i1IIi
  if 69 - 69: Oo0Ooo - i11iIiiIii - I1IiiI * OOooOOo % OoO0O00
  if 35 - 35: Oo0Ooo
  if 90 - 90: I1IiiI - ooOoO0o + II111iiii + IiII * O0 . I1Ii111
  if 65 - 65: iIii1I11I1II1 % Oo0Ooo % I11i / OoooooooOO
  if 82 - 82: o0oOOo0O0Ooo
  if 33 - 33: OoOoOO00 / i11iIiiIii - I1IiiI - OoooooooOO + i1IIi * I1Ii111
  if 92 - 92: iII111i + OoO0O00
  if 70 - 70: iIii1I11I1II1
  if ( port == LISP_CTRL_PORT and ii1IiIIiI != None ) :
   while ( True ) :
    time . sleep ( .01 )
    ii1IiIIiI = lisp_get_host_route_next_hop ( O0O0 )
    if ( ii1IiIIiI == None ) : break
    if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
    if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
    if 14 - 14: I1Ii111 + Oo0Ooo
  ii11Iiii1iIiI = lisp_get_default_route_next_hops ( )
  for OoO , Oo00 in ii11Iiii1iIiI :
   if ( OoO != device_name ) : continue
   if 96 - 96: oO0o % IiII - ooOoO0o
   if 57 - 57: ooOoO0o / i11iIiiIii * o0oOOo0O0Ooo % i1IIi
   if 30 - 30: iIii1I11I1II1 / IiII % OoooooooOO . I11i
   if 100 - 100: ooOoO0o * I1ii11iIi11i % OoO0O00 * Oo0Ooo . i1IIi
   if 51 - 51: iIii1I11I1II1 . i11iIiiIii * i1IIi / OoOoOO00
   if 64 - 64: IiII % iII111i . Ii1I * II111iiii / OoOoOO00
   if ( ii1IiIIiI != Oo00 ) :
    if ( ii1IiIIiI != None ) :
     lisp_install_host_route ( O0O0 , ii1IiIIiI , False )
     if 25 - 25: OoooooooOO + i1IIi - I1ii11iIi11i . oO0o + IiII % I1Ii111
    lisp_install_host_route ( O0O0 , Oo00 , True )
    iiIIiIII11IIii = True
    if 36 - 36: Ii1I
   break
   if 88 - 88: Ii1I
   if 69 - 69: I1IiiI + Ii1I * I11i + i1IIi
   if 14 - 14: iII111i / ooOoO0o % IiII - I1IiiI . Oo0Ooo
   if 30 - 30: O0 . OOooOOo
   if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
   if 83 - 83: OoooooooOO
 o0o0ooOOo0oO = I1i1 . encode ( )
 I1i1 . print_info ( )
 if 53 - 53: o0oOOo0O0Ooo - Oo0Ooo / IiII + O0
 if 88 - 88: Oo0Ooo % I1Ii111 * O0 - i1IIi * OoO0O00
 if 74 - 74: Oo0Ooo % iIii1I11I1II1 + OOooOOo
 if 50 - 50: OoO0O00 . OoooooooOO
 iI1II11 = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 iI1II11 = bold ( iI1II11 , False )
 IIIiIIi111 = bold ( "{}" . format ( port ) , False )
 OoOOOO = red ( O0O0 , False )
 IiIi1I1i1iIiI = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( IiIi1I1i1iIiI , OoOOOO , IIIiIIi111 , iI1II11 ) )
 if 65 - 65: I1ii11iIi11i + O0 + iII111i + II111iiii
 if 100 - 100: I1Ii111
 if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
 if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
 if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
 if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , o0o0ooOOo0oO )
 else :
  OoOOoo0o00O0oO = lisp_data_header ( )
  OoOOoo0o00O0oO . instance_id ( 0xffffff )
  OoOOoo0o00O0oO = OoOOoo0o00O0oO . encode ( )
  if ( OoOOoo0o00O0oO ) :
   o0o0ooOOo0oO = OoOOoo0o00O0oO + o0o0ooOOo0oO
   if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
   if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
   if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
   if 74 - 74: OoooooooOO + Ii1I
   if 100 - 100: I1IiiI
   if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
   if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
   if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
   if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , o0o0ooOOo0oO )
   if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
   if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
   if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
   if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
   if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
   if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
   if 40 - 40: I1ii11iIi11i
 if ( iiIIiIII11IIii ) :
  lisp_install_host_route ( O0O0 , None , False )
  if ( ii1IiIIiI != None ) : lisp_install_host_route ( O0O0 , ii1IiIIiI , True )
  if 76 - 76: Oo0Ooo - I11i
 return
 if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
 if 39 - 39: I1IiiI
 if 8 - 8: IiII * i1IIi * i1IIi * O0
 if 69 - 69: Oo0Ooo
 if 48 - 48: iII111i
 if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
 if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 89 - 89: iII111i
 if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
 if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
 if 77 - 77: OoooooooOO - I11i / I1IiiI % OoOoOO00 - OOooOOo
 I1i1 = lisp_info ( )
 packet = I1i1 . decode ( packet )
 if ( packet == None ) : return
 I1i1 . print_info ( )
 if 37 - 37: ooOoO0o
 if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
 if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
 if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
 if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
 I1i1 . info_reply = True
 I1i1 . global_etr_rloc . store_address ( addr_str )
 I1i1 . etr_port = sport
 if 82 - 82: iII111i - I1Ii111 - OoOoOO00
 if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
 if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
 if 44 - 44: O0
 if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
 if ( I1i1 . hostname != None ) :
  I1i1 . private_etr_rloc . afi = LISP_AFI_NAME
  I1i1 . private_etr_rloc . store_address ( I1i1 . hostname )
  if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
  if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
 if ( rtr_list != None ) : I1i1 . rtr_list = rtr_list
 packet = I1i1 . encode ( )
 I1i1 . print_info ( )
 if 14 - 14: iIii1I11I1II1 * I1ii11iIi11i + OOooOOo + O0
 if 79 - 79: II111iiii - iII111i
 if 89 - 89: O0 - OoO0O00
 if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
 if 32 - 32: O0 + IiII
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 OO0oooOO = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , OO0oooOO , sport , packet )
 if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
 if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
 if 17 - 17: OOooOOo
 if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
 if 46 - 46: II111iiii * OoO0O00
 o00000OO0ooOo = lisp_info_source ( I1i1 . hostname , addr_str , sport )
 o00000OO0ooOo . cache_address_for_info_source ( )
 return
 if 47 - 47: Ii1I % II111iiii
 if 88 - 88: OoOoOO00 / oO0o - OoOoOO00 / OoOoOO00 % II111iiii
 if 47 - 47: i11iIiiIii . iII111i + o0oOOo0O0Ooo % iII111i
 if 93 - 93: OoO0O00 / i11iIiiIii / oO0o - o0oOOo0O0Ooo
 if 56 - 56: I11i + oO0o . i1IIi - II111iiii - o0oOOo0O0Ooo + OOooOOo
 if 24 - 24: ooOoO0o
 if 7 - 7: ooOoO0o . OoooooooOO . iII111i * II111iiii . II111iiii / OOooOOo
 if 46 - 46: Ii1I - Oo0Ooo / i1IIi % IiII - I1ii11iIi11i + OOooOOo
def lisp_get_signature_eid ( ) :
 for oooOOoO0oo0 in lisp_db_list :
  if ( oooOOoO0oo0 . signature_eid ) : return ( oooOOoO0oo0 )
  if 42 - 42: i1IIi - IiII % OOooOOo % iIii1I11I1II1
 return ( None )
 if 71 - 71: OoO0O00
 if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
 if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
 if 54 - 54: Ii1I / I1IiiI
 if 7 - 7: iIii1I11I1II1 . O0 + OOooOOo . Ii1I * Oo0Ooo
 if 25 - 25: I1Ii111 . Oo0Ooo % II111iiii . IiII - O0
 if 18 - 18: oO0o * OOooOOo
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
def lisp_get_any_translated_port ( ) :
 for oooOOoO0oo0 in lisp_db_list :
  for O0O0OOo0O in oooOOoO0oo0 . rloc_set :
   if ( O0O0OOo0O . translated_rloc . is_null ( ) ) : continue
   return ( O0O0OOo0O . translated_port )
   if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
   if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
 return ( None )
 if 96 - 96: II111iiii % I11i / Ii1I - i11iIiiIii
 if 63 - 63: I1IiiI
 if 15 - 15: iIii1I11I1II1 - I1ii11iIi11i % OoO0O00 * II111iiii / I11i + I11i
 if 23 - 23: I1IiiI
 if 51 - 51: i11iIiiIii / ooOoO0o - OoooooooOO + OoOoOO00 + oO0o
 if 57 - 57: iIii1I11I1II1
 if 19 - 19: Ii1I / o0oOOo0O0Ooo + O0 / iIii1I11I1II1 + II111iiii
 if 3 - 3: oO0o % OoO0O00 % OOooOOo
 if 64 - 64: o0oOOo0O0Ooo . II111iiii * IiII % Oo0Ooo + I11i - OoooooooOO
def lisp_get_any_translated_rloc ( ) :
 for oooOOoO0oo0 in lisp_db_list :
  for O0O0OOo0O in oooOOoO0oo0 . rloc_set :
   if ( O0O0OOo0O . translated_rloc . is_null ( ) ) : continue
   return ( O0O0OOo0O . translated_rloc )
   if 58 - 58: ooOoO0o
   if 15 - 15: O0 * OOooOOo * I11i + Ii1I * OoooooooOO + OOooOOo
 return ( None )
 if 77 - 77: O0
 if 98 - 98: iII111i - iII111i % i1IIi - I1Ii111 . I1IiiI % o0oOOo0O0Ooo
 if 38 - 38: IiII % OoOoOO00 . OOooOOo . I1ii11iIi11i
 if 34 - 34: iII111i . i11iIiiIii + OoO0O00 + o0oOOo0O0Ooo / ooOoO0o - i11iIiiIii
 if 63 - 63: ooOoO0o % OoO0O00 % ooOoO0o
 if 28 - 28: IiII * I1Ii111 * o0oOOo0O0Ooo + ooOoO0o - IiII / IiII
 if 73 - 73: iIii1I11I1II1 . I1ii11iIi11i + OOooOOo
def lisp_get_all_translated_rlocs ( ) :
 O00O00Oo0O = [ ]
 for oooOOoO0oo0 in lisp_db_list :
  for O0O0OOo0O in oooOOoO0oo0 . rloc_set :
   if ( O0O0OOo0O . is_rloc_translated ( ) == False ) : continue
   IiIIiiI = O0O0OOo0O . translated_rloc . print_address_no_iid ( )
   O00O00Oo0O . append ( IiIIiiI )
   if 79 - 79: I1ii11iIi11i + OoOoOO00 + OoO0O00 * Ii1I
   if 8 - 8: I1Ii111
 return ( O00O00Oo0O )
 if 6 - 6: I1ii11iIi11i % OOooOOo . IiII / iIii1I11I1II1 % I11i . OoooooooOO
 if 45 - 45: I1Ii111 . Ii1I . I11i + I1ii11iIi11i . OoOoOO00
 if 25 - 25: OoOoOO00 + OoO0O00 . iII111i / ooOoO0o * i1IIi
 if 63 - 63: I1IiiI / O0 * o0oOOo0O0Ooo / OoO0O00 - I1IiiI
 if 1 - 1: I1Ii111 . iII111i / IiII % iIii1I11I1II1 . iII111i + OoOoOO00
 if 12 - 12: ooOoO0o
 if 54 - 54: I11i - O0 * iII111i . II111iiii
 if 51 - 51: Oo0Ooo
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 IiI1iiIIiIiii = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 31 - 31: Oo0Ooo / oO0o
 IIiIIiiI11 = { }
 for IIIi1iI1 in rtr_list :
  if ( IIIi1iI1 == None ) : continue
  IiIIiiI = rtr_list [ IIIi1iI1 ]
  if ( IiI1iiIIiIiii and IiIIiiI . is_private_address ( ) ) : continue
  IIiIIiiI11 [ IIIi1iI1 ] = IiIIiiI
  if 92 - 92: I1IiiI + oO0o % iII111i
 rtr_list = IIiIIiiI11
 if 47 - 47: ooOoO0o . OOooOOo . oO0o + oO0o + i1IIi + iIii1I11I1II1
 Oo0oO0Oo0 = [ ]
 for i1I1iiiI in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( i1I1iiiI == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 11 - 11: iII111i
  if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
  if 89 - 89: I11i % II111iiii
  if 35 - 35: oO0o
  if 65 - 65: II111iiii
  IIi1iii1i1 = lisp_address ( i1I1iiiI , "" , 0 , iid )
  IIi1iii1i1 . make_default_route ( IIi1iii1i1 )
  ooOoOO0Oo = lisp_map_cache . lookup_cache ( IIi1iii1i1 , True )
  if ( ooOoOO0Oo ) :
   if ( ooOoOO0Oo . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( ooOoOO0Oo . print_eid_tuple ( ) , False ) ) )
    if 87 - 87: oO0o / OoO0O00 - oO0o
   elif ( ooOoOO0Oo . do_rloc_sets_match ( rtr_list . values ( ) ) ) :
    continue
    if 69 - 69: i11iIiiIii
   ooOoOO0Oo . delete_cache ( )
   if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
   if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
  Oo0oO0Oo0 . append ( [ IIi1iii1i1 , "" ] )
  if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
  if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
  if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
  if 14 - 14: I1ii11iIi11i / i11iIiiIii * I11i % o0oOOo0O0Ooo + IiII / I1ii11iIi11i
  iiIoOOOOoo0O00o = lisp_address ( i1I1iiiI , "" , 0 , iid )
  iiIoOOOOoo0O00o . make_default_multicast_route ( iiIoOOOOoo0O00o )
  oOoOooO = lisp_map_cache . lookup_cache ( iiIoOOOOoo0O00o , True )
  if ( oOoOooO ) : oOoOooO = oOoOooO . source_cache . lookup_cache ( IIi1iii1i1 , True )
  if ( oOoOooO ) : oOoOooO . delete_cache ( )
  if 11 - 11: OOooOOo + i11iIiiIii
  Oo0oO0Oo0 . append ( [ IIi1iii1i1 , iiIoOOOOoo0O00o ] )
  if 21 - 21: OoOoOO00 * OoooooooOO . I11i . I1Ii111
 if ( len ( Oo0oO0Oo0 ) == 0 ) : return
 if 95 - 95: iIii1I11I1II1 - I1Ii111 - I1ii11iIi11i
 if 91 - 91: I1IiiI
 if 19 - 19: i1IIi / OOooOOo + i1IIi * OoooooooOO
 if 61 - 61: oO0o / OoooooooOO . Ii1I / o0oOOo0O0Ooo . oO0o
 oOO000OOO = [ ]
 for IiIi1I1i1iIiI in rtr_list :
  IIiii111IIi1 = rtr_list [ IiIi1I1i1iIiI ]
  O0O0OOo0O = lisp_rloc ( )
  O0O0OOo0O . rloc . copy_address ( IIiii111IIi1 )
  O0O0OOo0O . priority = 254
  O0O0OOo0O . mpriority = 255
  O0O0OOo0O . rloc_name = "RTR"
  oOO000OOO . append ( O0O0OOo0O )
  if 87 - 87: oO0o
  if 52 - 52: i11iIiiIii
 for IIi1iii1i1 in Oo0oO0Oo0 :
  ooOoOO0Oo = lisp_mapping ( IIi1iii1i1 [ 0 ] , IIi1iii1i1 [ 1 ] , oOO000OOO )
  ooOoOO0Oo . mapping_source = map_resolver
  ooOoOO0Oo . map_cache_ttl = LISP_MR_TTL * 60
  ooOoOO0Oo . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( ooOoOO0Oo . print_eid_tuple ( ) , False ) , rtr_list . keys ( ) ) )
  if 75 - 75: i11iIiiIii % I1ii11iIi11i % Oo0Ooo + I1IiiI - OoooooooOO * oO0o
  oOO000OOO = copy . deepcopy ( oOO000OOO )
  if 20 - 20: OoOoOO00 % II111iiii
 return
 if 46 - 46: o0oOOo0O0Ooo % i11iIiiIii * ooOoO0o / i1IIi * i1IIi
 if 71 - 71: I1IiiI + i1IIi
 if 96 - 96: I1Ii111 . Oo0Ooo % I11i % I1ii11iIi11i % II111iiii * IiII
 if 69 - 69: OoO0O00 * Oo0Ooo * iII111i
 if 2 - 2: iII111i - Ii1I
 if 1 - 1: I1Ii111 / oO0o + iIii1I11I1II1
 if 88 - 88: o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii / I1ii11iIi11i
 if 49 - 49: IiII
 if 1 - 1: oO0o / I11i
def lisp_process_info_reply ( source , packet , store ) :
 if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
 if 28 - 28: OOooOOo - O0 - O0 % i11iIiiIii * OoooooooOO
 if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
 if 24 - 24: O0
 I1i1 = lisp_info ( )
 packet = I1i1 . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
 I1i1 . print_info ( )
 if 65 - 65: i11iIiiIii
 if 46 - 46: i11iIiiIii
 if 70 - 70: i1IIi + o0oOOo0O0Ooo
 if 44 - 44: iII111i . II111iiii % o0oOOo0O0Ooo
 iiiII1Ii11I1 = False
 for IiIi1I1i1iIiI in I1i1 . rtr_list :
  O0O0 = IiIi1I1i1iIiI . print_address_no_iid ( )
  if ( lisp_rtr_list . has_key ( O0O0 ) ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ O0O0 ] != None ) : continue
   if 94 - 94: OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
  iiiII1Ii11I1 = True
  lisp_rtr_list [ O0O0 ] = IiIi1I1i1iIiI
  if 55 - 55: II111iiii - IiII
  if 24 - 24: oO0o % Ii1I / i1IIi
  if 84 - 84: i1IIi
  if 53 - 53: OoooooooOO - i1IIi - Ii1I
  if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
 if ( lisp_i_am_itr and iiiII1Ii11I1 ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for i1 in lisp_iid_to_interface . keys ( ) :
    lisp_update_default_routes ( source , int ( i1 ) , lisp_rtr_list )
    if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
    if 34 - 34: Ii1I
    if 5 - 5: II111iiii . I1ii11iIi11i
    if 85 - 85: I1Ii111 . IiII + II111iiii
    if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
    if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
    if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
 if ( store == False ) :
  return ( [ I1i1 . global_etr_rloc , I1i1 . etr_port , iiiII1Ii11I1 ] )
  if 87 - 87: OOooOOo
  if 44 - 44: Oo0Ooo + iIii1I11I1II1
  if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
  if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
  if 10 - 10: O0 / I11i
  if 29 - 29: i11iIiiIii % I11i
 for oooOOoO0oo0 in lisp_db_list :
  for O0O0OOo0O in oooOOoO0oo0 . rloc_set :
   IIIi1iI1 = O0O0OOo0O . rloc
   iI1ii1iI1 = O0O0OOo0O . interface
   if ( iI1ii1iI1 == None ) :
    if ( IIIi1iI1 . is_null ( ) ) : continue
    if ( IIIi1iI1 . is_local ( ) == False ) : continue
    if ( I1i1 . private_etr_rloc . is_null ( ) == False and
 IIIi1iI1 . is_exact_match ( I1i1 . private_etr_rloc ) == False ) :
     continue
     if 49 - 49: I11i
   elif ( I1i1 . private_etr_rloc . is_dist_name ( ) ) :
    oOoOoO0Oo0oo = I1i1 . private_etr_rloc . address
    if ( oOoOoO0Oo0oo != O0O0OOo0O . rloc_name ) : continue
    if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
    if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
   iIiI1I1ii1I1 = green ( oooOOoO0oo0 . eid . print_prefix ( ) , False )
   iI = red ( IIIi1iI1 . print_address_no_iid ( ) , False )
   if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
   OO0oooo00 = I1i1 . global_etr_rloc . is_exact_match ( IIIi1iI1 )
   if ( O0O0OOo0O . translated_port == 0 and OO0oooo00 ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( iI ,
 iI1ii1iI1 , iIiI1I1ii1I1 ) )
    continue
    if 60 - 60: Ii1I . Ii1I . I11i / OoooooooOO + I1IiiI % iIii1I11I1II1
    if 8 - 8: IiII + IiII / I1ii11iIi11i
    if 49 - 49: I11i + OOooOOo - I1ii11iIi11i
    if 23 - 23: OOooOOo % I1ii11iIi11i + iIii1I11I1II1 + iII111i
    if 9 - 9: OOooOOo * o0oOOo0O0Ooo / I11i . i11iIiiIii
   i1iI11Ii1 = I1i1 . global_etr_rloc
   oOOOOo0 = O0O0OOo0O . translated_rloc
   if ( oOOOOo0 . is_exact_match ( i1iI11Ii1 ) and
 I1i1 . etr_port == O0O0OOo0O . translated_port ) : continue
   if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( I1i1 . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # OoooooooOO - iII111i
 I1i1 . etr_port , iI , iI1ii1iI1 , iIiI1I1ii1I1 ) )
   if 9 - 9: II111iiii % I1ii11iIi11i
   O0O0OOo0O . store_translated_rloc ( I1i1 . global_etr_rloc ,
 I1i1 . etr_port )
   if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
   if 26 - 26: OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
 return ( [ I1i1 . global_etr_rloc , I1i1 . etr_port , iiiII1Ii11I1 ] )
 if 39 - 39: I1ii11iIi11i * I1IiiI * II111iiii . Oo0Ooo % I1IiiI
 if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
 if 98 - 98: OoO0O00 + oO0o - II111iiii
 if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
 if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
 if 77 - 77: iIii1I11I1II1 * Oo0Ooo . IiII / oO0o + O0
 if 76 - 76: iII111i + o0oOOo0O0Ooo - OoooooooOO * oO0o % OoooooooOO - O0
 if 18 - 18: Ii1I
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 82 - 82: OoOoOO00 + OoO0O00 - IiII / ooOoO0o
 oOooOOo000o0o = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 oOOO0O = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 67 - 67: I1IiiI / i11iIiiIii - I1Ii111 % OoooooooOO
 if 36 - 36: oO0o % iII111i % oO0o
 if 56 - 56: ooOoO0o - O0 + iII111i % I11i / i1IIi
 if 78 - 78: i1IIi . iIii1I11I1II1
 oOooOOo000o0o . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , oOooOOo000o0o , None )
 oOooOOo000o0o . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , oOooOOo000o0o , None )
 if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
 if 58 - 58: II111iiii * oO0o - i1IIi . I11i
 if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
 if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
 oOOO0O . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , oOOO0O , None )
 oOOO0O . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , oOOO0O , None )
 if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
 if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
 if 31 - 31: i1IIi * Ii1I
 if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
 oOo0o00oo = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 oOo0o00oo . start ( )
 return
 if 1 - 1: iII111i - OoOoOO00 + II111iiii + o0oOOo0O0Ooo % iIii1I11I1II1 - OOooOOo
 if 60 - 60: ooOoO0o % iIii1I11I1II1 / iIii1I11I1II1
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
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 56 - 56: Oo0Ooo
 IiIIiiI = lisp_get_interface_address ( rloc . interface )
 if ( IiIIiiI == None ) : return
 if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
 I1iii = rloc . rloc . print_address_no_iid ( )
 O00o0OoO0OOOo = IiIIiiI . print_address_no_iid ( )
 if 7 - 7: ooOoO0o * o0oOOo0O0Ooo + ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
 if ( I1iii == O00o0OoO0OOOo ) : return
 if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , I1iii , O00o0OoO0OOOo ) )
 if 70 - 70: Oo0Ooo - I11i / I1ii11iIi11i % OoO0O00 % II111iiii
 if 72 - 72: i11iIiiIii * I11i
 rloc . rloc . copy_address ( IiIIiiI )
 lisp_myrlocs [ 0 ] = IiIIiiI
 return
 if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
 if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
 if 64 - 64: OoooooooOO
 if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
 if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
 if 71 - 71: O0 - OoooooooOO
 if 82 - 82: i11iIiiIii * II111iiii % IiII
 if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
def lisp_update_encap_port ( mc ) :
 for IIIi1iI1 in mc . rloc_set :
  I1OOoO0OoOOo0 = lisp_get_nat_info ( IIIi1iI1 . rloc , IIIi1iI1 . rloc_name )
  if ( I1OOoO0OoOOo0 == None ) : continue
  if ( IIIi1iI1 . translated_port == I1OOoO0OoOOo0 . port ) : continue
  if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( IIIi1iI1 . translated_port , I1OOoO0OoOOo0 . port ,
  # iII111i . I1ii11iIi11i % Ii1I . ooOoO0o
 red ( IIIi1iI1 . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 84 - 84: Ii1I / I1Ii111 % OoO0O00 % OoOoOO00 * i11iIiiIii . O0
  IIIi1iI1 . store_translated_rloc ( IIIi1iI1 . rloc , I1OOoO0OoOOo0 . port )
  if 44 - 44: Ii1I - i1IIi - OoooooooOO
 return
 if 23 - 23: IiII . I1Ii111 / OoOoOO00 * Ii1I % O0
 if 54 - 54: I1ii11iIi11i + i11iIiiIii
 if 16 - 16: iII111i
 if 29 - 29: ooOoO0o . I1IiiI + o0oOOo0O0Ooo - I1IiiI
 if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
 if 65 - 65: Ii1I % i11iIiiIii
 if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
 if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
 if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
 if 88 - 88: iII111i
 if 94 - 94: OoooooooOO
 if 32 - 32: I1ii11iIi11i
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 8 - 8: I11i * i11iIiiIii - ooOoO0o
  if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
 iiI1 = lisp_get_timestamp ( )
 if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
 if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
 if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
 if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
 if 42 - 42: II111iiii . iII111i
 if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
 if ( mc . last_refresh_time + mc . map_cache_ttl > iiI1 ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 64 - 64: oO0o / IiII
  if 86 - 86: I11i
  if 36 - 36: o0oOOo0O0Ooo / OoO0O00
  if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
  if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
 if ( lisp_nat_traversal and mc . eid . address == 0 and mc . eid . mask_len == 0 ) :
  return ( [ True , delete_list ] )
  if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
  if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
  if 12 - 12: I1IiiI . OOooOOo % Oo0Ooo
  if 86 - 86: i11iIiiIii
  if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
 Ii1i1 = lisp_print_elapsed ( mc . last_refresh_time )
 iiiiiiiiII1i = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( iiiiiiiiII1i , False ) , bold ( "timed out" , False ) , Ii1i1 ) )
 if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
 if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
 if 79 - 79: I11i - II111iiii
 if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
 if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
 if 44 - 44: I1IiiI * IiII . OoooooooOO
 if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
 if 10 - 10: i1IIi + o0oOOo0O0Ooo
 if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
 if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 if 2 - 2: I11i
def lisp_timeout_map_cache_walk ( mc , parms ) :
 oo0Oo00OO0000 = parms [ 0 ]
 iiOoOo = parms [ 1 ]
 if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
 if 42 - 42: iII111i / Oo0Ooo
 if 14 - 14: O0 . Oo0Ooo
 if 8 - 8: i11iIiiIii
 if ( mc . group . is_null ( ) ) :
  I11i11I1i1i , oo0Oo00OO0000 = lisp_timeout_map_cache_entry ( mc , oo0Oo00OO0000 )
  if ( oo0Oo00OO0000 == [ ] or mc != oo0Oo00OO0000 [ - 1 ] ) :
   iiOoOo = lisp_write_checkpoint_entry ( iiOoOo , mc )
   if 80 - 80: I1ii11iIi11i + Ii1I
  return ( [ I11i11I1i1i , parms ] )
  if 16 - 16: i11iIiiIii * Oo0Ooo
  if 76 - 76: iII111i . oO0o - i1IIi
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 94 - 94: O0 % iII111i
 if 90 - 90: IiII
 if 1 - 1: I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % oO0o + Ii1I
 if 46 - 46: I1IiiI + OoO0O00 - Oo0Ooo
 if 13 - 13: OoOoOO00
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
 if 90 - 90: oO0o * I1Ii111 / O0
 if 15 - 15: o0oOOo0O0Ooo * O0 . OOooOOo / Oo0Ooo
 if 28 - 28: OoooooooOO + OoooooooOO
 if 27 - 27: I11i . oO0o / OoooooooOO - OoO0O00 . I11i
 if 15 - 15: II111iiii * OoO0O00
 if 33 - 33: OoooooooOO . o0oOOo0O0Ooo . I1IiiI / I1ii11iIi11i . OoOoOO00
def lisp_timeout_map_cache ( lisp_map_cache ) :
 iiii11IiIiI = [ [ ] , [ ] ]
 iiii11IiIiI = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , iiii11IiIiI )
 if 58 - 58: Ii1I
 if 20 - 20: OOooOOo
 if 93 - 93: i1IIi . IiII % O0 * iII111i
 if 84 - 84: I11i
 if 99 - 99: I1ii11iIi11i
 oo0Oo00OO0000 = iiii11IiIiI [ 0 ]
 for ooOoOO0Oo in oo0Oo00OO0000 : ooOoOO0Oo . delete_cache ( )
 if 78 - 78: I1Ii111 . IiII - OOooOOo
 if 93 - 93: iIii1I11I1II1
 if 33 - 33: OOooOOo . i1IIi
 if 63 - 63: II111iiii . oO0o * IiII
 iiOoOo = iiii11IiIiI [ 1 ]
 lisp_checkpoint ( iiOoOo )
 return
 if 73 - 73: iII111i . i1IIi + oO0o + OOooOOo + ooOoO0o - iIii1I11I1II1
 if 47 - 47: I11i
 if 88 - 88: OoO0O00 - OoooooooOO
 if 93 - 93: Oo0Ooo * I1IiiI
 if 60 - 60: I1Ii111 + OOooOOo % iII111i
 if 40 - 40: I11i + oO0o . O0 % oO0o
 if 12 - 12: iIii1I11I1II1
 if 9 - 9: OoOoOO00 * II111iiii / o0oOOo0O0Ooo * iII111i - II111iiii / i11iIiiIii
 if 14 - 14: i11iIiiIii + I1Ii111 . OoOoOO00 - oO0o * OoO0O00
 if 23 - 23: iIii1I11I1II1
 if 32 - 32: iII111i * iIii1I11I1II1 + I1Ii111 + IiII + O0 * OoO0O00
 if 100 - 100: II111iiii
 if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
 if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
 if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
 if 42 - 42: ooOoO0o + I1IiiI * iII111i / OoOoOO00 . i1IIi - OoooooooOO
def lisp_store_nat_info ( hostname , rloc , port ) :
 O0O0 = rloc . print_address_no_iid ( )
 iiII1Ii1 = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( O0O0 , False ) , port )
 if 53 - 53: I1ii11iIi11i % O0 * II111iiii
 o0OO0o0oOo0Oo = lisp_nat_info ( O0O0 , hostname , port )
 if 2 - 2: O0
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) :
  lisp_nat_state_info [ hostname ] = [ o0OO0o0oOo0Oo ]
  lprint ( iiII1Ii1 . format ( "Store initial" ) )
  return ( True )
  if 21 - 21: IiII * I1IiiI
  if 95 - 95: O0 - i11iIiiIii - o0oOOo0O0Ooo
  if 97 - 97: OoooooooOO + oO0o . iIii1I11I1II1 / Ii1I / Oo0Ooo
  if 13 - 13: i1IIi - ooOoO0o % i11iIiiIii
  if 10 - 10: Ii1I % oO0o + oO0o * OoOoOO00 % iII111i / o0oOOo0O0Ooo
  if 17 - 17: iII111i / I1IiiI . II111iiii - OoO0O00 + iII111i
 I1OOoO0OoOOo0 = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( I1OOoO0OoOOo0 . address == O0O0 and I1OOoO0OoOOo0 . port == port ) :
  I1OOoO0OoOOo0 . uptime = lisp_get_timestamp ( )
  lprint ( iiII1Ii1 . format ( "Refresh existing" ) )
  return ( False )
  if 22 - 22: Oo0Ooo - I1ii11iIi11i + I11i . oO0o
  if 85 - 85: iIii1I11I1II1 / Ii1I
  if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
  if 97 - 97: I1Ii111 + I1ii11iIi11i
  if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
  if 80 - 80: I11i
  if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
 o0o0000 = None
 for I1OOoO0OoOOo0 in lisp_nat_state_info [ hostname ] :
  if ( I1OOoO0OoOOo0 . address == O0O0 and I1OOoO0OoOOo0 . port == port ) :
   o0o0000 = I1OOoO0OoOOo0
   break
   if 93 - 93: OoOoOO00
   if 55 - 55: iIii1I11I1II1 / o0oOOo0O0Ooo * I1IiiI + Oo0Ooo / Oo0Ooo * IiII
   if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
 if ( o0o0000 == None ) :
  lprint ( iiII1Ii1 . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( o0o0000 )
  lprint ( iiII1Ii1 . format ( "Use previous" ) )
  if 65 - 65: I11i
  if 92 - 92: iII111i . IiII + i1IIi % i1IIi
 IIIi111 = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ o0OO0o0oOo0Oo ] + IIIi111
 return ( True )
 if 11 - 11: oO0o * Ii1I . I1Ii111
 if 91 - 91: I1ii11iIi11i % i1IIi / Ii1I
 if 62 - 62: I11i % IiII * I1Ii111 - II111iiii / OoooooooOO
 if 39 - 39: I1IiiI . O0 + I1ii11iIi11i . iIii1I11I1II1 + ooOoO0o
 if 54 - 54: II111iiii / iII111i + OOooOOo - i11iIiiIii % I1Ii111 / OoO0O00
 if 2 - 2: II111iiii + I1Ii111 - Ii1I
 if 44 - 44: II111iiii + OOooOOo % I1IiiI
 if 34 - 34: o0oOOo0O0Ooo / I1ii11iIi11i - o0oOOo0O0Ooo / i11iIiiIii
def lisp_get_nat_info ( rloc , hostname ) :
 if ( lisp_nat_state_info . has_key ( hostname ) == False ) : return ( None )
 if 18 - 18: oO0o
 O0O0 = rloc . print_address_no_iid ( )
 for I1OOoO0OoOOo0 in lisp_nat_state_info [ hostname ] :
  if ( I1OOoO0OoOOo0 . address == O0O0 ) : return ( I1OOoO0OoOOo0 )
  if 43 - 43: I11i / OOooOOo + OOooOOo
 return ( None )
 if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
 if 90 - 90: OOooOOo
 if 29 - 29: OoOoOO00 - I1IiiI / oO0o + Oo0Ooo + I1Ii111 + O0
 if 65 - 65: oO0o
 if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
 if 13 - 13: Ii1I
 if 34 - 34: I1IiiI / iIii1I11I1II1
 if 35 - 35: oO0o / oO0o
 if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
 if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
 if 77 - 77: O0
 if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
 if 36 - 36: II111iiii
 if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
 if 7 - 7: i11iIiiIii
 if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
 if 41 - 41: IiII % II111iiii
 if 99 - 99: IiII - O0
 if 59 - 59: iII111i % O0 + OOooOOo * ooOoO0o
 if 27 - 27: I1Ii111 % i11iIiiIii * I1IiiI
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 19 - 19: OoOoOO00 / o0oOOo0O0Ooo - iII111i / OoO0O00
 if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
 if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
 if 89 - 89: Ii1I * Oo0Ooo / I1Ii111 * I1ii11iIi11i + O0 * Oo0Ooo
 if 74 - 74: I11i . I11i
 if 74 - 74: OoOoOO00 * ooOoO0o * I1Ii111
 OoOO0O0O0Ooo = [ ]
 O0oooooo0 = [ ]
 if ( dest == None ) :
  for IIIIIii1Ii1II in lisp_map_resolvers_list . values ( ) :
   O0oooooo0 . append ( IIIIIii1Ii1II . map_resolver )
   if 10 - 10: OoO0O00 / i1IIi - I1Ii111 - I11i * i1IIi
  OoOO0O0O0Ooo = O0oooooo0
  if ( OoOO0O0O0Ooo == [ ] ) :
   for I1Ii11IIiiI in lisp_map_servers_list . values ( ) :
    OoOO0O0O0Ooo . append ( I1Ii11IIiiI . map_server )
    if 8 - 8: ooOoO0o / I1ii11iIi11i * I1IiiI / OOooOOo
    if 77 - 77: OoOoOO00 - i11iIiiIii % OoOoOO00 / I1Ii111 / I1Ii111
  if ( OoOO0O0O0Ooo == [ ] ) : return
 else :
  OoOO0O0O0Ooo . append ( dest )
  if 84 - 84: IiII * i11iIiiIii / iII111i % iII111i + i11iIiiIii % ooOoO0o
  if 70 - 70: iIii1I11I1II1 - I1Ii111 . oO0o . iII111i / o0oOOo0O0Ooo
  if 8 - 8: O0 - I1Ii111
  if 82 - 82: iII111i + II111iiii
  if 29 - 29: O0 % Ii1I * ooOoO0o % O0
 O00O00Oo0O = { }
 for oooOOoO0oo0 in lisp_db_list :
  for O0O0OOo0O in oooOOoO0oo0 . rloc_set :
   lisp_update_local_rloc ( O0O0OOo0O )
   if ( O0O0OOo0O . rloc . is_null ( ) ) : continue
   if ( O0O0OOo0O . interface == None ) : continue
   if 83 - 83: oO0o
   IiIIiiI = O0O0OOo0O . rloc . print_address_no_iid ( )
   if ( IiIIiiI in O00O00Oo0O ) : continue
   O00O00Oo0O [ IiIIiiI ] = O0O0OOo0O . interface
   if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
   if 85 - 85: iIii1I11I1II1 / I11i
 if ( O00O00Oo0O == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
  return
  if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
  if 20 - 20: OOooOOo % i1IIi * Ii1I / i11iIiiIii
  if 89 - 89: ooOoO0o
  if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
  if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
  if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
 for IiIIiiI in O00O00Oo0O :
  iI1ii1iI1 = O00O00Oo0O [ IiIIiiI ]
  OoOOOO = red ( IiIIiiI , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( OoOOOO ,
 iI1ii1iI1 ) )
  OoO = iI1ii1iI1 if len ( O00O00Oo0O ) > 1 else None
  for dest in OoOO0O0O0Ooo :
   lisp_send_info_request ( lisp_sockets , dest , port , OoO )
   if 20 - 20: I11i
   if 37 - 37: I1Ii111
   if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
   if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
   if 41 - 41: O0 / OoooooooOO - i1IIi
   if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
 if ( O0oooooo0 != [ ] ) :
  for IIIIIii1Ii1II in lisp_map_resolvers_list . values ( ) :
   IIIIIii1Ii1II . resolve_dns_name ( )
   if 32 - 32: oO0o / IiII - I11i . ooOoO0o
   if 69 - 69: i11iIiiIii * i11iIiiIii
 return
 if 100 - 100: I1ii11iIi11i * I1ii11iIi11i + i1IIi
 if 96 - 96: I1Ii111 / I1IiiI + ooOoO0o
 if 16 - 16: I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo % OoOoOO00 + ooOoO0o % I1ii11iIi11i
 if 85 - 85: oO0o * OoooooooOO * iIii1I11I1II1 + iII111i
 if 67 - 67: Ii1I / i11iIiiIii % OoOoOO00 % O0 / OoOoOO00
 if 54 - 54: I11i . OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
 if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
 if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
 if 89 - 89: I1Ii111
 if 29 - 29: I11i * ooOoO0o - OoooooooOO
 if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
 if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
 if 73 - 73: OoooooooOO
 if 25 - 25: i1IIi . II111iiii . I1Ii111
 if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
 if ( value . find ( "." ) != - 1 ) :
  IiIIiiI = value . split ( "." )
  if ( len ( IiIIiiI ) != 4 ) : return ( False )
  if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
  for oooO0OoO in IiIIiiI :
   if ( oooO0OoO . isdigit ( ) == False ) : return ( False )
   if ( int ( oooO0OoO ) > 255 ) : return ( False )
   if 3 - 3: oO0o * O0 / iIii1I11I1II1
  return ( True )
  if 36 - 36: oO0o / I1ii11iIi11i + OoooooooOO
  if 77 - 77: I1IiiI % i11iIiiIii + Ii1I + iIii1I11I1II1 / IiII - iII111i
  if 57 - 57: OoO0O00 - OoO0O00 % I1Ii111 * I11i . i11iIiiIii
  if 10 - 10: oO0o % iIii1I11I1II1 . OOooOOo / I11i / i1IIi
  if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
 if ( value . find ( "-" ) != - 1 ) :
  IiIIiiI = value . split ( "-" )
  for OoOOoO0oOo in [ "N" , "S" , "W" , "E" ] :
   if ( OoOOoO0oOo in IiIIiiI ) :
    if ( len ( IiIIiiI ) < 8 ) : return ( False )
    return ( True )
    if 86 - 86: Oo0Ooo
    if 97 - 97: I1IiiI
    if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
    if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
    if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
    if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
    if 64 - 64: I1IiiI % ooOoO0o
 if ( value . find ( "-" ) != - 1 ) :
  IiIIiiI = value . split ( "-" )
  if ( len ( IiIIiiI ) != 3 ) : return ( False )
  if 72 - 72: O0 * II111iiii % OoO0O00 - I1IiiI * OOooOOo
  for O0o0O0OoOOoO in IiIIiiI :
   try : int ( O0o0O0OoOOoO , 16 )
   except : return ( False )
   if 66 - 66: iIii1I11I1II1 - Oo0Ooo % OoooooooOO % O0
  return ( True )
  if 33 - 33: I1Ii111 / II111iiii / II111iiii
  if 15 - 15: O0 * OoooooooOO - O0 + OoooooooOO
  if 40 - 40: O0 * OoooooooOO - oO0o + iIii1I11I1II1 * OOooOOo + I1ii11iIi11i
  if 43 - 43: OoO0O00 . O0
  if 36 - 36: I11i
 if ( value . find ( ":" ) != - 1 ) :
  IiIIiiI = value . split ( ":" )
  if ( len ( IiIIiiI ) < 2 ) : return ( False )
  if 28 - 28: ooOoO0o
  I11IIoO0oOoOo0oO0O = False
  ooOoOoO0 = 0
  for O0o0O0OoOOoO in IiIIiiI :
   ooOoOoO0 += 1
   if ( O0o0O0OoOOoO == "" ) :
    if ( I11IIoO0oOoOo0oO0O ) :
     if ( len ( IiIIiiI ) == ooOoOoO0 ) : break
     if ( ooOoOoO0 > 2 ) : return ( False )
     if 41 - 41: OoO0O00 % Oo0Ooo
    I11IIoO0oOoOo0oO0O = True
    continue
    if 60 - 60: OOooOOo . Ii1I
   try : int ( O0o0O0OoOOoO , 16 )
   except : return ( False )
   if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
  return ( True )
  if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
  if 38 - 38: IiII / I11i / IiII * iII111i
  if 30 - 30: oO0o
  if 30 - 30: IiII / OoO0O00
  if 89 - 89: oO0o . OoOoOO00 . IiII / iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00
 if ( value [ 0 ] == "+" ) :
  IiIIiiI = value [ 1 : : ]
  for Oooo0Oo0O in IiIIiiI :
   if ( Oooo0Oo0O . isdigit ( ) == False ) : return ( False )
   if 94 - 94: Ii1I - iIii1I11I1II1 % OoO0O00 - IiII % i11iIiiIii - o0oOOo0O0Ooo
  return ( True )
  if 25 - 25: Oo0Ooo - OOooOOo . i1IIi * OoOoOO00 / I11i / o0oOOo0O0Ooo
 return ( False )
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
def lisp_process_api ( process , lisp_socket , data_structure ) :
 I1III111iii11 , iiii11IiIiI = data_structure . split ( "%" )
 if 65 - 65: I11i . I1Ii111 % I1ii11iIi11i + Ii1I
 lprint ( "Process API request '{}', parameters: '{}'" . format ( I1III111iii11 ,
 iiii11IiIiI ) )
 if 40 - 40: I1IiiI / Oo0Ooo
 iiii1II = [ ]
 if ( I1III111iii11 == "map-cache" ) :
  if ( iiii11IiIiI == "" ) :
   iiii1II = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , iiii1II )
  else :
   iiii1II = lisp_process_api_map_cache_entry ( json . loads ( iiii11IiIiI ) )
   if 56 - 56: iIii1I11I1II1 + I11i
   if 32 - 32: I1ii11iIi11i / i11iIiiIii . OOooOOo . Oo0Ooo
 if ( I1III111iii11 == "site-cache" ) :
  if ( iiii11IiIiI == "" ) :
   iiii1II = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 iiii1II )
  else :
   iiii1II = lisp_process_api_site_cache_entry ( json . loads ( iiii11IiIiI ) )
   if 3 - 3: o0oOOo0O0Ooo
   if 68 - 68: OoOoOO00 + I1ii11iIi11i % i11iIiiIii
 if ( I1III111iii11 == "site-cache-summary" ) :
  iiii1II = lisp_process_api_site_cache_summary ( lisp_sites_by_eid )
  if 58 - 58: OoO0O00 / Oo0Ooo + Ii1I
 if ( I1III111iii11 == "map-server" ) :
  iiii11IiIiI = { } if ( iiii11IiIiI == "" ) else json . loads ( iiii11IiIiI )
  iiii1II = lisp_process_api_ms_or_mr ( True , iiii11IiIiI )
  if 63 - 63: OOooOOo / I1ii11iIi11i
 if ( I1III111iii11 == "map-resolver" ) :
  iiii11IiIiI = { } if ( iiii11IiIiI == "" ) else json . loads ( iiii11IiIiI )
  iiii1II = lisp_process_api_ms_or_mr ( False , iiii11IiIiI )
  if 86 - 86: O0 + iII111i + OoooooooOO / iII111i * I1ii11iIi11i * OoooooooOO
 if ( I1III111iii11 == "database-mapping" ) :
  iiii1II = lisp_process_api_database_mapping ( )
  if 89 - 89: oO0o - OOooOOo / iII111i - I1IiiI
  if 78 - 78: iIii1I11I1II1 + O0 + IiII . I11i / i11iIiiIii . O0
  if 21 - 21: OoOoOO00 * OOooOOo + oO0o + O0
  if 59 - 59: i1IIi / OoooooooOO . OoO0O00 / OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
  if 58 - 58: IiII . Ii1I + II111iiii
 iiii1II = json . dumps ( iiii1II )
 Oo0O = lisp_api_ipc ( process , iiii1II )
 lisp_ipc ( Oo0O , lisp_socket , "lisp-core" )
 return
 if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
 if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
 if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
 if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
def lisp_process_api_map_cache ( mc , data ) :
 if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
 if 54 - 54: oO0o * II111iiii
 if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
 if 98 - 98: ooOoO0o
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 73 - 73: I1Ii111
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 97 - 97: OoO0O00 * Ii1I + Oo0Ooo
 if 83 - 83: II111iiii - Oo0Ooo % II111iiii * o0oOOo0O0Ooo
 if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
 if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
 if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 76 - 76: iII111i * OOooOOo
 if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
 if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
 if 40 - 40: iII111i
 if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
 if 33 - 33: OoooooooOO
def lisp_gather_map_cache_data ( mc , data ) :
 oOOoO0oO0oo0O = { }
 oOOoO0oO0oo0O [ "instance-id" ] = str ( mc . eid . instance_id )
 oOOoO0oO0oo0O [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  oOOoO0oO0oo0O [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 59 - 59: i11iIiiIii - OoooooooOO . ooOoO0o / i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i
 oOOoO0oO0oo0O [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 oOOoO0oO0oo0O [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 oOOoO0oO0oo0O [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 oOOoO0oO0oo0O [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
 if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
 if 5 - 5: Oo0Ooo . I1Ii111
 if 77 - 77: i11iIiiIii / I1Ii111 / I1ii11iIi11i % oO0o
 if 83 - 83: Ii1I % iIii1I11I1II1 / I1ii11iIi11i + I11i
 oOO000OOO = [ ]
 for IIIi1iI1 in mc . rloc_set :
  iiiI1I = lisp_fill_rloc_in_json ( IIIi1iI1 )
  if 23 - 23: iIii1I11I1II1 - I1IiiI
  if 51 - 51: OoooooooOO / IiII / I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * OoooooooOO
  if 40 - 40: OoO0O00 / IiII . O0 / I1IiiI + OoO0O00 . o0oOOo0O0Ooo
  if 25 - 25: ooOoO0o * I1Ii111 * oO0o
  if 64 - 64: Ii1I / I1ii11iIi11i
  if ( IIIi1iI1 . rloc . is_multicast_address ( ) ) :
   iiiI1I [ "multicast-rloc-set" ] = [ ]
   for OoO0oo in IIIi1iI1 . multicast_rloc_probe_list . values ( ) :
    IIIIIii1Ii1II = lisp_fill_rloc_in_json ( OoO0oo )
    iiiI1I [ "multicast-rloc-set" ] . append ( IIIIIii1Ii1II )
    if 30 - 30: OoooooooOO + O0 / I1ii11iIi11i * o0oOOo0O0Ooo
    if 11 - 11: O0 + OoO0O00 - Oo0Ooo - Oo0Ooo . i11iIiiIii
    if 15 - 15: Ii1I % i11iIiiIii / OoOoOO00
  oOO000OOO . append ( iiiI1I )
  if 85 - 85: ooOoO0o . i1IIi / iII111i % iIii1I11I1II1 / II111iiii / I1Ii111
 oOOoO0oO0oo0O [ "rloc-set" ] = oOO000OOO
 if 60 - 60: iIii1I11I1II1 - iIii1I11I1II1 . I11i
 data . append ( oOOoO0oO0oo0O )
 return ( [ True , data ] )
 if 55 - 55: OoO0O00
 if 87 - 87: Ii1I - iII111i / O0 - o0oOOo0O0Ooo - iIii1I11I1II1 % Ii1I
 if 47 - 47: iII111i * I1Ii111 % o0oOOo0O0Ooo / OoOoOO00 / OoO0O00 % OoO0O00
 if 43 - 43: Oo0Ooo
 if 34 - 34: OoO0O00 . i1IIi + IiII * IiII
 if 76 - 76: OOooOOo
 if 54 - 54: O0 * II111iiii * OOooOOo
 if 44 - 44: I1IiiI
def lisp_fill_rloc_in_json ( rloc ) :
 iiiI1I = { }
 if ( rloc . rloc_exists ( ) ) :
  iiiI1I [ "address" ] = rloc . rloc . print_address_no_iid ( )
  if 66 - 66: o0oOOo0O0Ooo
  if 40 - 40: OOooOOo * Ii1I
 if ( rloc . translated_port != 0 ) :
  iiiI1I [ "encap-port" ] = str ( rloc . translated_port )
  if 38 - 38: ooOoO0o
 iiiI1I [ "state" ] = rloc . print_state ( )
 if ( rloc . geo ) : iiiI1I [ "geo" ] = rloc . geo . print_geo ( )
 if ( rloc . elp ) : iiiI1I [ "elp" ] = rloc . elp . print_elp ( False )
 if ( rloc . rle ) : iiiI1I [ "rle" ] = rloc . rle . print_rle ( False , False )
 if ( rloc . json ) : iiiI1I [ "json" ] = rloc . json . print_json ( False )
 if ( rloc . rloc_name ) : iiiI1I [ "rloc-name" ] = rloc . rloc_name
 OO000 = rloc . stats . get_stats ( False , False )
 if ( OO000 ) : iiiI1I [ "stats" ] = OO000
 iiiI1I [ "uptime" ] = lisp_print_elapsed ( rloc . uptime )
 iiiI1I [ "upriority" ] = str ( rloc . priority )
 iiiI1I [ "uweight" ] = str ( rloc . weight )
 iiiI1I [ "mpriority" ] = str ( rloc . mpriority )
 iiiI1I [ "mweight" ] = str ( rloc . mweight )
 iiI111I = rloc . last_rloc_probe_reply
 if ( iiI111I ) :
  iiiI1I [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( iiI111I )
  iiiI1I [ "rloc-probe-rtt" ] = str ( rloc . rloc_probe_rtt )
  if 22 - 22: i11iIiiIii - Ii1I + O0 - I1ii11iIi11i . Oo0Ooo
 iiiI1I [ "rloc-hop-count" ] = rloc . rloc_probe_hops
 iiiI1I [ "recent-rloc-hop-counts" ] = rloc . recent_rloc_probe_hops
 if 33 - 33: O0
 iiiI1I [ "rloc-probe-latency" ] = rloc . rloc_probe_latency
 iiiI1I [ "recent-rloc-probe-latencies" ] = rloc . recent_rloc_probe_latencies
 if 30 - 30: II111iiii * OoOoOO00 - OoO0O00 * OOooOOo / I11i
 oo0Ooo = [ ]
 for ii1iIiI111 in rloc . recent_rloc_probe_rtts : oo0Ooo . append ( str ( ii1iIiI111 ) )
 iiiI1I [ "recent-rloc-probe-rtts" ] = oo0Ooo
 return ( iiiI1I )
 if 42 - 42: oO0o . OOooOOo * OoO0O00
 if 88 - 88: I1ii11iIi11i
 if 21 - 21: i1IIi . I1IiiI / OoooooooOO % oO0o
 if 31 - 31: O0
 if 37 - 37: Oo0Ooo . OoOoOO00 % I1ii11iIi11i * O0
 if 20 - 20: ooOoO0o + I1IiiI - IiII % ooOoO0o - IiII . oO0o
 if 39 - 39: O0 / oO0o % oO0o * iIii1I11I1II1
def lisp_process_api_map_cache_entry ( parms ) :
 i1 = parms [ "instance-id" ]
 i1 = 0 if ( i1 == "" ) else int ( i1 )
 if 7 - 7: iII111i % o0oOOo0O0Ooo / II111iiii % IiII / iIii1I11I1II1
 if 17 - 17: I11i * I11i - O0 / IiII + OoOoOO00
 if 65 - 65: I1Ii111 * i1IIi
 if 10 - 10: OOooOOo % IiII
 oOooOOo000o0o = lisp_address ( LISP_AFI_NONE , "" , 0 , i1 )
 oOooOOo000o0o . store_prefix ( parms [ "eid-prefix" ] )
 OO0oooOO = oOooOOo000o0o
 iIiI111ii1Ii = oOooOOo000o0o
 if 20 - 20: I11i / OoooooooOO % OoOoOO00 . oO0o * I1IiiI % IiII
 if 84 - 84: I1ii11iIi11i % I11i / OOooOOo % O0
 if 63 - 63: Ii1I / I1ii11iIi11i / Oo0Ooo
 if 74 - 74: i1IIi
 if 38 - 38: II111iiii * i1IIi
 iiIoOOOOoo0O00o = lisp_address ( LISP_AFI_NONE , "" , 0 , i1 )
 if ( parms . has_key ( "group-prefix" ) ) :
  iiIoOOOOoo0O00o . store_prefix ( parms [ "group-prefix" ] )
  OO0oooOO = iiIoOOOOoo0O00o
  if 43 - 43: O0 - OOooOOo / I1IiiI * II111iiii . OoooooooOO / OoOoOO00
  if 77 - 77: OoOoOO00
 iiii1II = [ ]
 ooOoOO0Oo = lisp_map_cache_lookup ( iIiI111ii1Ii , OO0oooOO )
 if ( ooOoOO0Oo ) : I11i11I1i1i , iiii1II = lisp_process_api_map_cache ( ooOoOO0Oo , iiii1II )
 return ( iiii1II )
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
def lisp_process_api_site_cache_summary ( site_cache ) :
 ooo0ooOO0OO = { "site" : "" , "registrations" : [ ] }
 oOOoO0oO0oo0O = { "eid-prefix" : "" , "count" : 0 , "registered-count" : 0 }
 if 2 - 2: I11i - II111iiii / I1Ii111
 II1IIiIi = { }
 for Iii1iii1II in site_cache . cache_sorted :
  for IiI11I11i in site_cache . cache [ Iii1iii1II ] . entries . values ( ) :
   if ( IiI11I11i . accept_more_specifics == False ) : continue
   if ( II1IIiIi . has_key ( IiI11I11i . site . site_name ) == False ) :
    II1IIiIi [ IiI11I11i . site . site_name ] = [ ]
    if 70 - 70: i11iIiiIii - IiII
   I1i = copy . deepcopy ( oOOoO0oO0oo0O )
   I1i [ "eid-prefix" ] = IiI11I11i . eid . print_prefix ( )
   I1i [ "count" ] = len ( IiI11I11i . more_specific_registrations )
   for I1I1Ii in IiI11I11i . more_specific_registrations :
    if ( I1I1Ii . registered ) : I1i [ "registered-count" ] += 1
    if 98 - 98: OoO0O00 % oO0o - II111iiii / OoOoOO00 / IiII * oO0o
   II1IIiIi [ IiI11I11i . site . site_name ] . append ( I1i )
   if 52 - 52: O0 % iII111i * iIii1I11I1II1 / I11i / I1IiiI * ooOoO0o
   if 93 - 93: iIii1I11I1II1 . II111iiii * OOooOOo - iIii1I11I1II1 . oO0o % Oo0Ooo
   if 92 - 92: OoO0O00
 iiii1II = [ ]
 for ii1iIiII1Iiii1ii in II1IIiIi :
  I1iiIi111I = copy . deepcopy ( ooo0ooOO0OO )
  I1iiIi111I [ "site" ] = ii1iIiII1Iiii1ii
  I1iiIi111I [ "registrations" ] = II1IIiIi [ ii1iIiII1Iiii1ii ]
  iiii1II . append ( I1iiIi111I )
  if 42 - 42: I1ii11iIi11i - iIii1I11I1II1 % ooOoO0o
 return ( iiii1II )
 if 7 - 7: Oo0Ooo / ooOoO0o + o0oOOo0O0Ooo
 if 38 - 38: o0oOOo0O0Ooo . O0 - OoO0O00 % I11i
 if 80 - 80: o0oOOo0O0Ooo
 if 100 - 100: iIii1I11I1II1 . OoOoOO00 . OoooooooOO / I1ii11iIi11i - I1IiiI * I11i
 if 5 - 5: i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1IiiI - II111iiii
 if 15 - 15: I1Ii111
 if 38 - 38: O0
def lisp_process_api_site_cache ( se , data ) :
 if 50 - 50: i11iIiiIii * OoO0O00 + iII111i / O0 * oO0o % ooOoO0o
 if 6 - 6: OoO0O00 . o0oOOo0O0Ooo / Ii1I + Ii1I
 if 59 - 59: II111iiii - o0oOOo0O0Ooo * OoooooooOO
 if 83 - 83: oO0o . iIii1I11I1II1 . iII111i % Oo0Ooo
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 48 - 48: oO0o % OoO0O00 - OoooooooOO . IiII
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 11 - 11: I1Ii111 % o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i
 if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
 if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
 if 47 - 47: OOooOOo + IiII
 if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
 if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
 if 64 - 64: Ii1I
 if 4 - 4: OoOoOO00
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 iIIiiiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 oooOOOO0O = data [ "dns-name" ] if data . has_key ( "dns-name" ) else None
 if ( data . has_key ( "address" ) ) :
  iIIiiiI . store_address ( data [ "address" ] )
  if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
  if 48 - 48: iII111i / II111iiii * I1Ii111 + I11i / ooOoO0o . OoOoOO00
 iiIiII11i1 = { }
 if ( ms_or_mr ) :
  for I1Ii11IIiiI in lisp_map_servers_list . values ( ) :
   if ( oooOOOO0O ) :
    if ( oooOOOO0O != I1Ii11IIiiI . dns_name ) : continue
   else :
    if ( iIIiiiI . is_exact_match ( I1Ii11IIiiI . map_server ) == False ) : continue
    if 45 - 45: OOooOOo / Ii1I % O0
    if 7 - 7: oO0o * i11iIiiIii + OoooooooOO + I11i
   iiIiII11i1 [ "dns-name" ] = I1Ii11IIiiI . dns_name
   iiIiII11i1 [ "address" ] = I1Ii11IIiiI . map_server . print_address_no_iid ( )
   iiIiII11i1 [ "ms-name" ] = "" if I1Ii11IIiiI . ms_name == None else I1Ii11IIiiI . ms_name
   return ( [ iiIiII11i1 ] )
   if 9 - 9: II111iiii * Oo0Ooo * I1Ii111 . IiII
 else :
  for IIIIIii1Ii1II in lisp_map_resolvers_list . values ( ) :
   if ( oooOOOO0O ) :
    if ( oooOOOO0O != IIIIIii1Ii1II . dns_name ) : continue
   else :
    if ( iIIiiiI . is_exact_match ( IIIIIii1Ii1II . map_resolver ) == False ) : continue
    if 80 - 80: i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - OOooOOo * OoooooooOO
    if 96 - 96: oO0o
   iiIiII11i1 [ "dns-name" ] = IIIIIii1Ii1II . dns_name
   iiIiII11i1 [ "address" ] = IIIIIii1Ii1II . map_resolver . print_address_no_iid ( )
   iiIiII11i1 [ "mr-name" ] = "" if IIIIIii1Ii1II . mr_name == None else IIIIIii1Ii1II . mr_name
   return ( [ iiIiII11i1 ] )
   if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
   if 64 - 64: I1IiiI % i11iIiiIii / oO0o
 return ( [ ] )
 if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
 if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
 if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
 if 31 - 31: OoO0O00
 if 89 - 89: II111iiii
 if 33 - 33: OOooOOo / oO0o % OoOoOO00 * O0
 if 65 - 65: OoO0O00 % OoOoOO00 % I1ii11iIi11i / OoooooooOO
 if 85 - 85: O0 * OOooOOo % I1Ii111
def lisp_process_api_database_mapping ( ) :
 iiii1II = [ ]
 if 33 - 33: O0
 for oooOOoO0oo0 in lisp_db_list :
  oOOoO0oO0oo0O = { }
  oOOoO0oO0oo0O [ "eid-prefix" ] = oooOOoO0oo0 . eid . print_prefix ( )
  if ( oooOOoO0oo0 . group . is_null ( ) == False ) :
   oOOoO0oO0oo0O [ "group-prefix" ] = oooOOoO0oo0 . group . print_prefix ( )
   if 30 - 30: II111iiii . O0 . oO0o * I1ii11iIi11i + oO0o . o0oOOo0O0Ooo
   if 43 - 43: iIii1I11I1II1
  o00OoO = [ ]
  for iiiI1I in oooOOoO0oo0 . rloc_set :
   IIIi1iI1 = { }
   if ( iiiI1I . rloc . is_null ( ) == False ) :
    IIIi1iI1 [ "rloc" ] = iiiI1I . rloc . print_address_no_iid ( )
    if 88 - 88: I1IiiI - OoO0O00 . O0 . oO0o
   if ( iiiI1I . rloc_name != None ) : IIIi1iI1 [ "rloc-name" ] = iiiI1I . rloc_name
   if ( iiiI1I . interface != None ) : IIIi1iI1 [ "interface" ] = iiiI1I . interface
   Ooo0ooOOOo0 = iiiI1I . translated_rloc
   if ( Ooo0ooOOOo0 . is_null ( ) == False ) :
    IIIi1iI1 [ "translated-rloc" ] = Ooo0ooOOOo0 . print_address_no_iid ( )
    if 39 - 39: I1Ii111 - II111iiii - o0oOOo0O0Ooo / i11iIiiIii
   if ( IIIi1iI1 != { } ) : o00OoO . append ( IIIi1iI1 )
   if 59 - 59: OOooOOo - o0oOOo0O0Ooo
   if 82 - 82: IiII % ooOoO0o - OoO0O00 % ooOoO0o
   if 51 - 51: ooOoO0o % iII111i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
   if 20 - 20: i1IIi - ooOoO0o % OoooooooOO * I1ii11iIi11i + II111iiii % i1IIi
   if 30 - 30: i11iIiiIii - I1IiiI + o0oOOo0O0Ooo + IiII
  oOOoO0oO0oo0O [ "rlocs" ] = o00OoO
  if 16 - 16: I1ii11iIi11i / Ii1I + I1ii11iIi11i * I1Ii111
  if 49 - 49: ooOoO0o * OoOoOO00 . OoooooooOO . ooOoO0o + Oo0Ooo * IiII
  if 47 - 47: iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
  if 84 - 84: o0oOOo0O0Ooo * I11i
  iiii1II . append ( oOOoO0oO0oo0O )
  if 22 - 22: i1IIi + OOooOOo % OoooooooOO
 return ( iiii1II )
 if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
 if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
 if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
 if 66 - 66: OoooooooOO
 if 90 - 90: IiII - OoOoOO00
 if 98 - 98: Oo0Ooo / oO0o . Ii1I
 if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
def lisp_gather_site_cache_data ( se , data ) :
 oOOoO0oO0oo0O = { }
 oOOoO0oO0oo0O [ "site-name" ] = se . site . site_name
 oOOoO0oO0oo0O [ "instance-id" ] = str ( se . eid . instance_id )
 oOOoO0oO0oo0O [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  oOOoO0oO0oo0O [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 37 - 37: iII111i - Ii1I . oO0o
 oOOoO0oO0oo0O [ "registered" ] = "yes" if se . registered else "no"
 oOOoO0oO0oo0O [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 oOOoO0oO0oo0O [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 47 - 47: IiII / I1ii11iIi11i . o0oOOo0O0Ooo . ooOoO0o + OOooOOo . OOooOOo
 IiIIiiI = se . last_registerer
 IiIIiiI = "none" if IiIIiiI . is_null ( ) else IiIIiiI . print_address ( )
 oOOoO0oO0oo0O [ "last-registerer" ] = IiIIiiI
 oOOoO0oO0oo0O [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 oOOoO0oO0oo0O [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 oOOoO0oO0oo0O [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  oOOoO0oO0oo0O [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 25 - 25: oO0o
  if 43 - 43: Ii1I - o0oOOo0O0Ooo % oO0o - O0
  if 20 - 20: OoO0O00 . ooOoO0o / OoOoOO00 - OoOoOO00 . iII111i / OOooOOo
  if 39 - 39: iIii1I11I1II1 % ooOoO0o
  if 75 - 75: i1IIi * II111iiii * O0 * i11iIiiIii % iII111i / iII111i
 oOO000OOO = [ ]
 for IIIi1iI1 in se . registered_rlocs :
  iiiI1I = { }
  iiiI1I [ "address" ] = IIIi1iI1 . rloc . print_address_no_iid ( ) if IIIi1iI1 . rloc_exists ( ) else "none"
  if 36 - 36: IiII / I1IiiI % iII111i / iII111i
  if 38 - 38: OOooOOo * I1ii11iIi11i * I1Ii111 + I11i
  if ( IIIi1iI1 . geo ) : iiiI1I [ "geo" ] = IIIi1iI1 . geo . print_geo ( )
  if ( IIIi1iI1 . elp ) : iiiI1I [ "elp" ] = IIIi1iI1 . elp . print_elp ( False )
  if ( IIIi1iI1 . rle ) : iiiI1I [ "rle" ] = IIIi1iI1 . rle . print_rle ( False , True )
  if ( IIIi1iI1 . json ) : iiiI1I [ "json" ] = IIIi1iI1 . json . print_json ( False )
  if ( IIIi1iI1 . rloc_name ) : iiiI1I [ "rloc-name" ] = IIIi1iI1 . rloc_name
  iiiI1I [ "uptime" ] = lisp_print_elapsed ( IIIi1iI1 . uptime )
  iiiI1I [ "upriority" ] = str ( IIIi1iI1 . priority )
  iiiI1I [ "uweight" ] = str ( IIIi1iI1 . weight )
  iiiI1I [ "mpriority" ] = str ( IIIi1iI1 . mpriority )
  iiiI1I [ "mweight" ] = str ( IIIi1iI1 . mweight )
  if 65 - 65: O0 + O0 * I1Ii111
  oOO000OOO . append ( iiiI1I )
  if 66 - 66: OOooOOo / O0 + i1IIi . O0 % I1ii11iIi11i - OoooooooOO
 oOOoO0oO0oo0O [ "registered-rlocs" ] = oOO000OOO
 if 16 - 16: I11i % iII111i
 data . append ( oOOoO0oO0oo0O )
 return ( [ True , data ] )
 if 29 - 29: I1IiiI - ooOoO0o * OoO0O00 . i11iIiiIii % OoOoOO00 * o0oOOo0O0Ooo
 if 43 - 43: OoO0O00 * OOooOOo / I1Ii111 % OoOoOO00 . oO0o / OOooOOo
 if 62 - 62: O0 * I1ii11iIi11i - O0 / I11i % ooOoO0o
 if 1 - 1: O0 / iIii1I11I1II1
 if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
 if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
 if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
def lisp_process_api_site_cache_entry ( parms ) :
 i1 = parms [ "instance-id" ]
 i1 = 0 if ( i1 == "" ) else int ( i1 )
 if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
 if 16 - 16: o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii . I1ii11iIi11i
 if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
 oOooOOo000o0o = lisp_address ( LISP_AFI_NONE , "" , 0 , i1 )
 oOooOOo000o0o . store_prefix ( parms [ "eid-prefix" ] )
 if 83 - 83: OoooooooOO % I1ii11iIi11i . IiII + OOooOOo . iII111i - ooOoO0o
 if 100 - 100: o0oOOo0O0Ooo
 if 95 - 95: iII111i * oO0o * i1IIi
 if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
 if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 iiIoOOOOoo0O00o = lisp_address ( LISP_AFI_NONE , "" , 0 , i1 )
 if ( parms . has_key ( "group-prefix" ) ) :
  iiIoOOOOoo0O00o . store_prefix ( parms [ "group-prefix" ] )
  if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
  if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
 iiii1II = [ ]
 IiI11I11i = lisp_site_eid_lookup ( oOooOOo000o0o , iiIoOOOOoo0O00o , False )
 if ( IiI11I11i ) : lisp_gather_site_cache_data ( IiI11I11i , iiii1II )
 return ( iiii1II )
 if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
 if 76 - 76: OoO0O00
 if 92 - 92: iIii1I11I1II1 * O0 % I11i
 if 92 - 92: OoOoOO00 + oO0o
 if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
 if 28 - 28: I1IiiI . iIii1I11I1II1
 if 12 - 12: I1Ii111 * OOooOOo
def lisp_get_interface_instance_id ( device , source_eid ) :
 iI1ii1iI1 = None
 if ( lisp_myinterfaces . has_key ( device ) ) :
  iI1ii1iI1 = lisp_myinterfaces [ device ]
  if 11 - 11: II111iiii % O0 % O0 % o0oOOo0O0Ooo
  if 45 - 45: OoooooooOO * oO0o
  if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
  if 16 - 16: Oo0Ooo
  if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
  if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 if ( iI1ii1iI1 == None or iI1ii1iI1 . instance_id == None ) :
  return ( lisp_default_iid )
  if 67 - 67: I1IiiI
  if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
  if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
  if 33 - 33: OOooOOo - OoooooooOO . iII111i
  if 2 - 2: I11i + i1IIi
  if 52 - 52: I11i - OoO0O00 % I1Ii111 . OOooOOo
  if 90 - 90: O0 - Oo0Ooo / i1IIi * iIii1I11I1II1 % o0oOOo0O0Ooo / oO0o
  if 73 - 73: iII111i % iIii1I11I1II1 + o0oOOo0O0Ooo % Ii1I . II111iiii + IiII
  if 55 - 55: OoOoOO00 * II111iiii / iII111i + OOooOOo / OoooooooOO
 i1 = iI1ii1iI1 . get_instance_id ( )
 if ( source_eid == None ) : return ( i1 )
 if 12 - 12: II111iiii * O0 - Oo0Ooo + o0oOOo0O0Ooo . Oo0Ooo + iIii1I11I1II1
 I1i1iIIi = source_eid . instance_id
 Ii11I11iIi1i1 = None
 for iI1ii1iI1 in lisp_multi_tenant_interfaces :
  if ( iI1ii1iI1 . device != device ) : continue
  IIi1iii1i1 = iI1ii1iI1 . multi_tenant_eid
  source_eid . instance_id = IIi1iii1i1 . instance_id
  if ( source_eid . is_more_specific ( IIi1iii1i1 ) == False ) : continue
  if ( Ii11I11iIi1i1 == None or Ii11I11iIi1i1 . multi_tenant_eid . mask_len < IIi1iii1i1 . mask_len ) :
   Ii11I11iIi1i1 = iI1ii1iI1
   if 33 - 33: OoooooooOO - i11iIiiIii / ooOoO0o . OOooOOo
   if 16 - 16: I1Ii111 + Oo0Ooo . I11i + ooOoO0o
 source_eid . instance_id = I1i1iIIi
 if 33 - 33: OoO0O00 / OOooOOo % Oo0Ooo . o0oOOo0O0Ooo % II111iiii
 if ( Ii11I11iIi1i1 == None ) : return ( i1 )
 return ( Ii11I11iIi1i1 . get_instance_id ( ) )
 if 62 - 62: iII111i . OoooooooOO - i1IIi
 if 59 - 59: OoOoOO00 + i1IIi * OoooooooOO . oO0o
 if 38 - 38: I1ii11iIi11i / o0oOOo0O0Ooo
 if 95 - 95: iIii1I11I1II1 / OoOoOO00 % I1Ii111
 if 54 - 54: OoooooooOO % Ii1I
 if 100 - 100: OOooOOo - I11i . O0 * i1IIi % OoooooooOO - ooOoO0o
 if 54 - 54: O0 + I11i
 if 71 - 71: OoOoOO00
 if 29 - 29: O0 . i11iIiiIii
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( lisp_myinterfaces . has_key ( device ) == False ) : return ( None )
 if 51 - 51: IiII
 iI1ii1iI1 = lisp_myinterfaces [ device ]
 ooOI1IIiI11IiI = device if iI1ii1iI1 . dynamic_eid_device == None else iI1ii1iI1 . dynamic_eid_device
 if 16 - 16: I11i / iII111i . IiII
 if 43 - 43: iIii1I11I1II1 % I11i % I1ii11iIi11i * I11i
 if ( iI1ii1iI1 . does_dynamic_eid_match ( eid ) ) : return ( ooOI1IIiI11IiI )
 return ( None )
 if 57 - 57: I1ii11iIi11i + i1IIi - I1Ii111
 if 7 - 7: Ii1I
 if 72 - 72: OoO0O00 . Oo0Ooo % ooOoO0o / o0oOOo0O0Ooo . IiII . iII111i
 if 28 - 28: i1IIi % iIii1I11I1II1 . i11iIiiIii - OoO0O00
 if 97 - 97: O0 / i1IIi - Oo0Ooo % i11iIiiIii + OOooOOo % iII111i
 if 59 - 59: I11i
 if 23 - 23: OoOoOO00 * I1Ii111
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
 IIi1i111ii1I = lisp_process_rloc_probe_timer
 i1i1I1Iii = threading . Timer ( interval , IIi1i111ii1I , [ lisp_sockets ] )
 lisp_rloc_probe_timer = i1i1I1Iii
 i1i1I1Iii . start ( )
 return
 if 8 - 8: Oo0Ooo % O0 . II111iiii
 if 45 - 45: i1IIi % ooOoO0o / oO0o + oO0o / OOooOOo - oO0o
 if 91 - 91: i1IIi . Oo0Ooo . i11iIiiIii % iIii1I11I1II1 * OOooOOo
 if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
 if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
 if 73 - 73: Oo0Ooo + II111iiii - IiII
 if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for OO0Oo00o0o0 in lisp_rloc_probe_list :
  II1111 = lisp_rloc_probe_list [ OO0Oo00o0o0 ]
  lprint ( "RLOC {}:" . format ( OO0Oo00o0o0 ) )
  for iiiI1I , I1i , OoIi1I1I in II1111 :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( iiiI1I ) ) , I1i . print_prefix ( ) ,
 OoIi1I1I . print_prefix ( ) , iiiI1I . translated_port ) )
   if 65 - 65: O0 % OOooOOo * ooOoO0o * II111iiii
   if 9 - 9: Oo0Ooo * Ii1I
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 17 - 17: OoOoOO00
 if 28 - 28: oO0o
 if 45 - 45: I1Ii111 % OoOoOO00 / I1Ii111 % OoO0O00 . I1IiiI
 if 100 - 100: OoO0O00 - Ii1I + i1IIi / o0oOOo0O0Ooo / IiII
 if 85 - 85: OoOoOO00
 if 90 - 90: o0oOOo0O0Ooo . OoOoOO00 - i11iIiiIii * IiII
 if 37 - 37: OoooooooOO - I1Ii111 . Ii1I . i1IIi * IiII / ooOoO0o
 if 12 - 12: OoooooooOO
 if 8 - 8: i11iIiiIii . I1Ii111 * o0oOOo0O0Ooo . ooOoO0o
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 94 - 94: I1ii11iIi11i % OoOoOO00 - OoooooooOO
 if 42 - 42: I1Ii111 - i1IIi
 if 91 - 91: iII111i . OOooOOo / iIii1I11I1II1 . Oo0Ooo . II111iiii . OoOoOO00
 if 31 - 31: OoO0O00 . I1ii11iIi11i % I11i - II111iiii
 IIIi1iI1 , I1i , OoIi1I1I = eid_list [ 0 ]
 O0O0oO0O0 = [ lisp_print_eid_tuple ( I1i , OoIi1I1I ) ]
 if 83 - 83: ooOoO0o . iII111i / Ii1I * I11i % iIii1I11I1II1 * I1ii11iIi11i
 for IIIi1iI1 , I1i , OoIi1I1I in eid_list [ 1 : : ] :
  IIIi1iI1 . state = LISP_RLOC_UNREACH_STATE
  IIIi1iI1 . last_state_change = lisp_get_timestamp ( )
  O0O0oO0O0 . append ( lisp_print_eid_tuple ( I1i , OoIi1I1I ) )
  if 83 - 83: I11i . I1ii11iIi11i / I1Ii111 / II111iiii
  if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
 o0Oooo0oO0o0O = bold ( "unreachable" , False )
 iI = red ( IIIi1iI1 . rloc . print_address_no_iid ( ) , False )
 if 77 - 77: ooOoO0o * Oo0Ooo - ooOoO0o * iII111i
 for oOooOOo000o0o in O0O0oO0O0 :
  I1i = green ( oOooOOo000o0o , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( iI , o0Oooo0oO0o0O , I1i ) )
  if 31 - 31: I1ii11iIi11i / iIii1I11I1II1 / iII111i
  if 14 - 14: O0 * Oo0Ooo / i1IIi
  if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
  if 78 - 78: II111iiii % OOooOOo
  if 6 - 6: OOooOOo
  if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
 for IIIi1iI1 , I1i , OoIi1I1I in eid_list :
  ooOoOO0Oo = lisp_map_cache . lookup_cache ( I1i , True )
  if ( ooOoOO0Oo ) : lisp_write_ipc_map_cache ( True , ooOoOO0Oo )
  if 55 - 55: OOooOOo + oO0o - II111iiii
 return
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
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 59 - 59: ooOoO0o / OoooooooOO
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 71 - 71: OOooOOo + I11i * O0 / o0oOOo0O0Ooo + I1IiiI + Ii1I
 if 41 - 41: ooOoO0o * I1Ii111
 if 40 - 40: OoOoOO00
 if 60 - 60: IiII . i11iIiiIii * II111iiii . Ii1I
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 10 - 10: O0
 if 65 - 65: I11i % i11iIiiIii + i11iIiiIii % II111iiii
 if 95 - 95: I1Ii111 - I11i . II111iiii . i1IIi / II111iiii + Oo0Ooo
 if 96 - 96: iIii1I11I1II1 * iII111i / OOooOOo * iIii1I11I1II1 - O0
 I1Ii = lisp_get_default_route_next_hops ( )
 if 47 - 47: I1ii11iIi11i % I1IiiI . iII111i * I11i . I1IiiI + iII111i
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 53 - 53: iIii1I11I1II1
 if 56 - 56: OoooooooOO % II111iiii + oO0o
 if 67 - 67: ooOoO0o + I11i - I1ii11iIi11i - OoooooooOO
 if 37 - 37: I11i % I1IiiI
 if 32 - 32: OOooOOo + OoooooooOO . IiII . Oo0Ooo * iII111i
 ooOoOoO0 = 0
 OoO0oo0O = bold ( "RLOC-probe" , False )
 for OOO in lisp_rloc_probe_list . values ( ) :
  if 84 - 84: II111iiii % OoO0O00 * OoOoOO00 . OoOoOO00
  if 51 - 51: Oo0Ooo - o0oOOo0O0Ooo * II111iiii + i1IIi
  if 83 - 83: I11i * o0oOOo0O0Ooo * Ii1I + OoooooooOO
  if 76 - 76: I1ii11iIi11i . OoooooooOO + ooOoO0o / I1IiiI
  if 56 - 56: Ii1I % I11i / O0 % O0 % iIii1I11I1II1 + I1IiiI
  Ooo00Oo0OoOO0 = None
  for iIIi1I1 , oOooOOo000o0o , iiIoOOOOoo0O00o in OOO :
   O0O0 = iIIi1I1 . rloc . print_address_no_iid ( )
   if 1 - 1: OOooOOo
   if 99 - 99: IiII * OoO0O00 . iII111i - OOooOOo + I1Ii111
   if 36 - 36: I1Ii111 - ooOoO0o . ooOoO0o % ooOoO0o
   if 5 - 5: O0 / Ii1I * i11iIiiIii - iII111i
   O0OoO , IIiiI1 , I1iI1 = lisp_allow_gleaning ( oOooOOo000o0o , None , iIIi1I1 )
   if ( O0OoO and IIiiI1 == False ) :
    I1i = green ( oOooOOo000o0o . print_address ( ) , False )
    O0O0 += ":{}" . format ( iIIi1I1 . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( O0O0 , False ) , I1i ) )
    if 7 - 7: Ii1I . Ii1I . iIii1I11I1II1 / ooOoO0o
    continue
    if 70 - 70: O0
    if 42 - 42: I1Ii111 + OoooooooOO + I11i
    if 48 - 48: Oo0Ooo . IiII / ooOoO0o + I11i
    if 40 - 40: I1IiiI + I1ii11iIi11i * I1IiiI % Ii1I
    if 27 - 27: O0 / Oo0Ooo . oO0o
    if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
    if 36 - 36: i11iIiiIii * i1IIi % iII111i . Oo0Ooo
   if ( iIIi1I1 . down_state ( ) ) : continue
   if 54 - 54: o0oOOo0O0Ooo % i1IIi % I1ii11iIi11i . o0oOOo0O0Ooo / OoOoOO00
   if 55 - 55: O0 / OoooooooOO % Ii1I * O0 + iIii1I11I1II1 . iIii1I11I1II1
   if 55 - 55: Ii1I . OoooooooOO % Ii1I . IiII
   if 67 - 67: oO0o
   if 12 - 12: I1IiiI + OoooooooOO
   if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
   if 19 - 19: OoooooooOO / IiII
   if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
   if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
   if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
   if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
   if ( Ooo00Oo0OoOO0 ) :
    iIIi1I1 . last_rloc_probe_nonce = Ooo00Oo0OoOO0 . last_rloc_probe_nonce
    if 51 - 51: OoO0O00 - OoO0O00 * IiII
    if ( Ooo00Oo0OoOO0 . translated_port == iIIi1I1 . translated_port and Ooo00Oo0OoOO0 . rloc_name == iIIi1I1 . rloc_name ) :
     if 24 - 24: OoooooooOO . II111iiii
     I1i = green ( lisp_print_eid_tuple ( oOooOOo000o0o , iiIoOOOOoo0O00o ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( O0O0 , False ) , I1i ) )
     if 97 - 97: II111iiii . O0
     if 18 - 18: iII111i
     if 35 - 35: ooOoO0o / O0 / iIii1I11I1II1 - iIii1I11I1II1 + I11i
     if 8 - 8: I1Ii111 . oO0o % Oo0Ooo * OoooooooOO
     if 25 - 25: OoO0O00
     if 54 - 54: O0
     iIIi1I1 . last_rloc_probe = Ooo00Oo0OoOO0 . last_rloc_probe
     continue
     if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
     if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
     if 92 - 92: ooOoO0o - iII111i
   Oo00 = None
   IIIi1iI1 = None
   while ( True ) :
    IIIi1iI1 = iIIi1I1 if IIIi1iI1 == None else IIIi1iI1 . next_rloc
    if ( IIIi1iI1 == None ) : break
    if 69 - 69: iII111i
    if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
    if 63 - 63: oO0o * OoO0O00 * oO0o
    if 31 - 31: Oo0Ooo
    if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
    if ( IIIi1iI1 . rloc_next_hop != None ) :
     if ( IIIi1iI1 . rloc_next_hop not in I1Ii ) :
      if ( IIIi1iI1 . up_state ( ) ) :
       IiI11I111 , o0oOOoOo0O0 = IIIi1iI1 . rloc_next_hop
       IIIi1iI1 . state = LISP_RLOC_UNREACH_STATE
       IIIi1iI1 . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( IIIi1iI1 . rloc , False )
       if 67 - 67: I1Ii111 . I1ii11iIi11i
      o0Oooo0oO0o0O = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( o0oOOoOo0O0 , IiI11I111 ,
 red ( O0O0 , False ) , o0Oooo0oO0o0O ) )
      continue
      if 2 - 2: O0 + I1Ii111
      if 82 - 82: Ii1I / iII111i
      if 13 - 13: I11i + iII111i
      if 54 - 54: I1ii11iIi11i - I1IiiI . Ii1I
      if 59 - 59: Oo0Ooo + I1ii11iIi11i
      if 87 - 87: ooOoO0o * OoooooooOO + OoO0O00 + oO0o - I1Ii111
    i11iII11I1III = IIIi1iI1 . last_rloc_probe
    ooIi1I1I111I1 = 0 if i11iII11I1III == None else time . time ( ) - i11iII11I1III
    if ( IIIi1iI1 . unreach_state ( ) and ooIi1I1I111I1 < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( O0O0 , False ) ) )
     if 48 - 48: i11iIiiIii
     continue
     if 45 - 45: i1IIi + I1ii11iIi11i
     if 49 - 49: i11iIiiIii . I1ii11iIi11i
     if 91 - 91: ooOoO0o - OOooOOo - OOooOOo * o0oOOo0O0Ooo
     if 33 - 33: II111iiii
     if 39 - 39: ooOoO0o + I11i
     if 24 - 24: o0oOOo0O0Ooo
    OO0Ooo0O00ooOo0o = lisp_get_echo_nonce ( None , O0O0 )
    if ( OO0Ooo0O00ooOo0o and OO0Ooo0O00ooOo0o . request_nonce_timeout ( ) ) :
     IIIi1iI1 . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     IIIi1iI1 . last_state_change = lisp_get_timestamp ( )
     o0Oooo0oO0o0O = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( O0O0 , False ) , o0Oooo0oO0o0O ) )
     if 5 - 5: i11iIiiIii - oO0o + o0oOOo0O0Ooo % ooOoO0o
     lisp_update_rtr_updown ( IIIi1iI1 . rloc , False )
     continue
     if 63 - 63: oO0o
     if 7 - 7: IiII / i11iIiiIii - OOooOOo
     if 9 - 9: II111iiii + i11iIiiIii % I1Ii111 - Oo0Ooo * OOooOOo
     if 55 - 55: I1Ii111 + ooOoO0o
     if 58 - 58: iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
     if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
    if ( OO0Ooo0O00ooOo0o and OO0Ooo0O00ooOo0o . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( O0O0 , False ) ) )
     if 96 - 96: OOooOOo % o0oOOo0O0Ooo / iIii1I11I1II1
     continue
     if 60 - 60: i1IIi / iIii1I11I1II1 + I11i % iII111i
     if 64 - 64: I11i . i11iIiiIii / iIii1I11I1II1 . I11i
     if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
     if 20 - 20: I11i % I1ii11iIi11i . OoO0O00 % OoOoOO00
     if 84 - 84: OoooooooOO / i11iIiiIii . IiII / I1IiiI
     if 62 - 62: iII111i - I1IiiI + OoooooooOO
    if ( IIIi1iI1 . last_rloc_probe != None ) :
     i11iII11I1III = IIIi1iI1 . last_rloc_probe_reply
     if ( i11iII11I1III == None ) : i11iII11I1III = 0
     ooIi1I1I111I1 = time . time ( ) - i11iII11I1III
     if ( IIIi1iI1 . up_state ( ) and ooIi1I1I111I1 >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 59 - 59: iIii1I11I1II1 + i11iIiiIii * oO0o . Oo0Ooo . I1Ii111
      IIIi1iI1 . state = LISP_RLOC_UNREACH_STATE
      IIIi1iI1 . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( IIIi1iI1 . rloc , False )
      o0Oooo0oO0o0O = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( O0O0 , False ) , o0Oooo0oO0o0O ) )
      if 49 - 49: II111iiii
      if 99 - 99: Oo0Ooo . OOooOOo
      lisp_mark_rlocs_for_other_eids ( OOO )
      if 85 - 85: OoOoOO00 . IiII + oO0o - II111iiii
      if 70 - 70: O0 % I1Ii111
      if 13 - 13: I1ii11iIi11i % OoO0O00 / Ii1I * IiII
    IIIi1iI1 . last_rloc_probe = lisp_get_timestamp ( )
    if 82 - 82: ooOoO0o % Oo0Ooo
    II1ii1 = "" if IIIi1iI1 . unreach_state ( ) == False else " unreachable"
    if 59 - 59: OoOoOO00 * I1ii11iIi11i / I1IiiI * II111iiii + OoOoOO00
    if 6 - 6: OoOoOO00 % oO0o + I11i * Ii1I
    if 13 - 13: I1ii11iIi11i / Oo0Ooo - I1Ii111 * OoOoOO00
    if 47 - 47: IiII
    if 76 - 76: iII111i / II111iiii / I11i
    if 62 - 62: I1ii11iIi11i
    if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
    iiIii1I1I = ""
    o0oOOoOo0O0 = None
    if ( IIIi1iI1 . rloc_next_hop != None ) :
     IiI11I111 , o0oOOoOo0O0 = IIIi1iI1 . rloc_next_hop
     lisp_install_host_route ( O0O0 , o0oOOoOo0O0 , True )
     iiIii1I1I = ", send on nh {}({})" . format ( o0oOOoOo0O0 , IiI11I111 )
     if 2 - 2: O0 . OoOoOO00 * o0oOOo0O0Ooo
     if 90 - 90: I11i - OoO0O00 - I1Ii111 % OoooooooOO % o0oOOo0O0Ooo . o0oOOo0O0Ooo
     if 62 - 62: OOooOOo % OoooooooOO * ooOoO0o * I1ii11iIi11i * o0oOOo0O0Ooo
     if 36 - 36: I1ii11iIi11i / o0oOOo0O0Ooo - I11i . i1IIi . Ii1I % IiII
     if 84 - 84: II111iiii . Ii1I
    ii1iIiI111 = IIIi1iI1 . print_rloc_probe_rtt ( )
    oO00 = O0O0
    if ( IIIi1iI1 . translated_port != 0 ) :
     oO00 += ":{}" . format ( IIIi1iI1 . translated_port )
     if 18 - 18: OOooOOo - i11iIiiIii % II111iiii + oO0o
    oO00 = red ( oO00 , False )
    if ( IIIi1iI1 . rloc_name != None ) :
     oO00 += " (" + blue ( IIIi1iI1 . rloc_name , False ) + ")"
     if 82 - 82: Ii1I
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( OoO0oo0O , II1ii1 ,
 oO00 , ii1iIiI111 , iiIii1I1I ) )
    if 2 - 2: iII111i + I11i * I1ii11iIi11i - IiII
    if 97 - 97: iIii1I11I1II1 . II111iiii - II111iiii + I1ii11iIi11i
    if 30 - 30: Ii1I
    if 10 - 10: I1Ii111 / Ii1I * I1Ii111 / OoO0O00 - I1ii11iIi11i
    if 7 - 7: I1IiiI . OoO0O00 . OoOoOO00 . I1ii11iIi11i * OoO0O00 - IiII
    if 6 - 6: OoO0O00 + II111iiii - oO0o
    if 90 - 90: Oo0Ooo % Oo0Ooo + oO0o - OoooooooOO + OOooOOo % I11i
    if 61 - 61: I1IiiI % oO0o + OOooOOo - I1Ii111
    if ( IIIi1iI1 . rloc_next_hop != None ) :
     Oo00 = lisp_get_host_route_next_hop ( O0O0 )
     if ( Oo00 ) : lisp_install_host_route ( O0O0 , Oo00 , False )
     if 5 - 5: ooOoO0o . OoO0O00
     if 40 - 40: iII111i
     if 87 - 87: IiII / II111iiii
     if 44 - 44: OoO0O00 . I1Ii111 - OoooooooOO * OoOoOO00 . OoO0O00
     if 84 - 84: OOooOOo . OOooOOo . oO0o % iII111i * Oo0Ooo - iIii1I11I1II1
     if 4 - 4: iII111i
    if ( IIIi1iI1 . rloc . is_null ( ) ) :
     IIIi1iI1 . rloc . copy_address ( iIIi1I1 . rloc )
     if 23 - 23: i1IIi . iIii1I11I1II1 / I1IiiI . OoOoOO00 . iII111i / IiII
     if 65 - 65: Ii1I + IiII + I11i / I1Ii111 % iIii1I11I1II1
     if 17 - 17: I1ii11iIi11i * OOooOOo % II111iiii
     if 30 - 30: I1Ii111 . Ii1I . Oo0Ooo / OOooOOo * OoooooooOO / I1ii11iIi11i
     if 41 - 41: i1IIi
    i11 = None if ( iiIoOOOOoo0O00o . is_null ( ) ) else oOooOOo000o0o
    OOOO00o0OO0OOo0o = oOooOOo000o0o if ( iiIoOOOOoo0O00o . is_null ( ) ) else iiIoOOOOoo0O00o
    lisp_send_map_request ( lisp_sockets , 0 , i11 , OOOO00o0OO0OOo0o , IIIi1iI1 )
    Ooo00Oo0OoOO0 = iIIi1I1
    if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
    if 100 - 100: OoO0O00 . Oo0Ooo
    if 29 - 29: OoO0O00
    if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
    if ( o0oOOoOo0O0 ) : lisp_install_host_route ( O0O0 , o0oOOoOo0O0 , False )
    if 63 - 63: O0 % iIii1I11I1II1 . o0oOOo0O0Ooo . I1IiiI * Ii1I % i1IIi
    if 47 - 47: II111iiii * I1ii11iIi11i
    if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
    if 71 - 71: I1ii11iIi11i * i1IIi
    if 67 - 67: I1ii11iIi11i % OoOoOO00 . iII111i / Ii1I . I1IiiI
   if ( Oo00 ) : lisp_install_host_route ( O0O0 , Oo00 , True )
   if 48 - 48: IiII + II111iiii . I1IiiI % o0oOOo0O0Ooo
   if 57 - 57: OOooOOo . I11i % OoOoOO00
   if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
   if 78 - 78: iII111i - OOooOOo / I1Ii111
   ooOoOoO0 += 1
   if ( ( ooOoOoO0 % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
   if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
   if 17 - 17: OoooooooOO % OoooooooOO + Oo0Ooo + I1Ii111
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 56 - 56: I11i % OoOoOO00 - OoO0O00
 if 31 - 31: iII111i % i11iIiiIii - Ii1I / OOooOOo - I1Ii111
 if 60 - 60: o0oOOo0O0Ooo + Oo0Ooo . O0
 if 51 - 51: i11iIiiIii / iIii1I11I1II1 . I1IiiI - Ii1I * I1Ii111 . iII111i
 if 72 - 72: Ii1I . I11i / i1IIi % i1IIi + I1ii11iIi11i
 if 56 - 56: OoO0O00 - OoOoOO00 - II111iiii * o0oOOo0O0Ooo
 if 87 - 87: ooOoO0o * OoooooooOO % O0 * OoooooooOO . I1Ii111
 if 66 - 66: OoO0O00 * Ii1I . OoO0O00
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 90 - 90: II111iiii % Ii1I
 if 67 - 67: I1IiiI - I11i - i11iIiiIii
 if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
 if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
 if ( lisp_i_am_itr == False ) : return
 if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
 if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
 if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
 if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
 if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
 if ( lisp_register_all_rtrs ) : return
 if 57 - 57: I1Ii111 - IiII
 oO0O00 = rtr . print_address_no_iid ( )
 if 70 - 70: i11iIiiIii . II111iiii - IiII - O0 . O0 / IiII
 if 3 - 3: Oo0Ooo
 if 10 - 10: IiII % OoO0O00 / OoO0O00 . ooOoO0o . IiII
 if 38 - 38: I11i / iII111i - iIii1I11I1II1 + ooOoO0o + o0oOOo0O0Ooo . I1IiiI
 if 96 - 96: IiII - I1IiiI . I1ii11iIi11i . O0
 if ( lisp_rtr_list . has_key ( oO0O00 ) == False ) : return
 if 82 - 82: Ii1I % o0oOOo0O0Ooo . Oo0Ooo * OoO0O00 - Oo0Ooo
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( oO0O00 , False ) , bold ( updown , False ) ) )
 if 49 - 49: i11iIiiIii - I1IiiI * IiII
 if 92 - 92: Oo0Ooo % O0 * Oo0Ooo
 if 29 - 29: I1IiiI * iIii1I11I1II1 % ooOoO0o * OoO0O00 % Ii1I * I1ii11iIi11i
 if 90 - 90: Ii1I + O0 % OoOoOO00
 Oo0O = "rtr%{}%{}" . format ( oO0O00 , updown )
 Oo0O = lisp_command_ipc ( Oo0O , "lisp-itr" )
 lisp_ipc ( Oo0O , lisp_ipc_socket , "lisp-etr" )
 return
 if 18 - 18: iII111i . iIii1I11I1II1 . I1ii11iIi11i / OoO0O00 % OOooOOo
 if 30 - 30: OoOoOO00 * i1IIi / i1IIi . IiII
 if 8 - 8: IiII % o0oOOo0O0Ooo . i11iIiiIii
 if 69 - 69: I1Ii111 / Ii1I - ooOoO0o
 if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
 if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
 if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
def lisp_process_rloc_probe_reply ( rloc_entry , source , port , map_reply , ttl ,
 mrloc ) :
 IIIi1iI1 = rloc_entry . rloc
 O0oo00o000 = map_reply . nonce
 Ii11I1II1IIi = map_reply . hop_count
 OoO0oo0O = bold ( "RLOC-probe reply" , False )
 I1IiiIII1i1iIIIII1 = IIIi1iI1 . print_address_no_iid ( )
 O0OooOoOo00oo = source . print_address_no_iid ( )
 o0oo0oo0 = lisp_rloc_probe_list
 ooo0 = rloc_entry . json . json_string if rloc_entry . json else None
 ii1III11 = lisp_get_timestamp ( )
 if 35 - 35: o0oOOo0O0Ooo . I1Ii111
 if 18 - 18: OoooooooOO - o0oOOo0O0Ooo % i1IIi
 if 28 - 28: Oo0Ooo * OoooooooOO . I1Ii111 . iIii1I11I1II1 - Oo0Ooo / OOooOOo
 if 69 - 69: OoooooooOO
 if 51 - 51: OoO0O00 + i11iIiiIii / II111iiii
 if 52 - 52: o0oOOo0O0Ooo * I1ii11iIi11i % OoOoOO00 . Ii1I . OoO0O00 * I1Ii111
 if ( mrloc != None ) :
  I11I1Iiiii = mrloc . rloc . print_address_no_iid ( )
  if ( mrloc . multicast_rloc_probe_list . has_key ( I1IiiIII1i1iIIIII1 ) == False ) :
   iIIiIIi = lisp_rloc ( )
   iIIiIIi = copy . deepcopy ( mrloc )
   iIIiIIi . rloc . copy_address ( IIIi1iI1 )
   iIIiIIi . multicast_rloc_probe_list = { }
   mrloc . multicast_rloc_probe_list [ I1IiiIII1i1iIIIII1 ] = iIIiIIi
   if 69 - 69: Oo0Ooo - o0oOOo0O0Ooo
  iIIiIIi = mrloc . multicast_rloc_probe_list [ I1IiiIII1i1iIIIII1 ]
  iIIiIIi . last_rloc_probe_nonce = mrloc . last_rloc_probe_nonce
  iIIiIIi . last_rloc_probe = mrloc . last_rloc_probe
  iiiI1I , oOooOOo000o0o , iiIoOOOOoo0O00o = lisp_rloc_probe_list [ I11I1Iiiii ] [ 0 ]
  iIIiIIi . process_rloc_probe_reply ( ii1III11 , O0oo00o000 , oOooOOo000o0o , iiIoOOOOoo0O00o , Ii11I1II1IIi , ttl , ooo0 )
  mrloc . process_rloc_probe_reply ( ii1III11 , O0oo00o000 , oOooOOo000o0o , iiIoOOOOoo0O00o , Ii11I1II1IIi , ttl , ooo0 )
  return
  if 18 - 18: OoooooooOO
  if 52 - 52: i1IIi - II111iiii / i1IIi . I1Ii111 . OoooooooOO - IiII
  if 47 - 47: iIii1I11I1II1 / IiII
  if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
  if 30 - 30: i11iIiiIii . I1IiiI
  if 5 - 5: Ii1I / O0 + iIii1I11I1II1
  if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 IiIIiiI = I1IiiIII1i1iIIIII1
 if ( o0oo0oo0 . has_key ( IiIIiiI ) == False ) :
  IiIIiiI += ":" + str ( port )
  if ( o0oo0oo0 . has_key ( IiIIiiI ) == False ) :
   IiIIiiI = O0OooOoOo00oo
   if ( o0oo0oo0 . has_key ( IiIIiiI ) == False ) :
    IiIIiiI += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( OoO0oo0O , red ( I1IiiIII1i1iIIIII1 , False ) , red ( O0OooOoOo00oo ,
    # O0 + oO0o + OoOoOO00 - Ii1I
 False ) , port ) )
    return
    if 9 - 9: o0oOOo0O0Ooo % i1IIi / OoO0O00 / OOooOOo + I1Ii111
    if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
    if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
    if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
    if 12 - 12: I1ii11iIi11i - i11iIiiIii + I1IiiI . Oo0Ooo
    if 26 - 26: oO0o + I1Ii111 + IiII * o0oOOo0O0Ooo . oO0o
    if 95 - 95: OoOoOO00 . I1Ii111 / Ii1I . I1Ii111 % OoO0O00
    if 16 - 16: Ii1I / I1IiiI / I1IiiI - OoooooooOO
 for IIIi1iI1 , oOooOOo000o0o , iiIoOOOOoo0O00o in lisp_rloc_probe_list [ IiIIiiI ] :
  if ( lisp_i_am_rtr ) :
   if ( IIIi1iI1 . translated_port != 0 and IIIi1iI1 . translated_port != port ) :
    continue
    if 13 - 13: OOooOOo / OoooooooOO
    if 7 - 7: II111iiii - ooOoO0o
  IIIi1iI1 . process_rloc_probe_reply ( ii1III11 , O0oo00o000 , oOooOOo000o0o , iiIoOOOOoo0O00o , Ii11I1II1IIi , ttl , ooo0 )
  if 72 - 72: Ii1I
 return
 if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
 if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
 if 87 - 87: II111iiii
 if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
 if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
 if 24 - 24: i11iIiiIii + ooOoO0o
 if 80 - 80: IiII % I11i % oO0o
 if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
def lisp_db_list_length ( ) :
 ooOoOoO0 = 0
 for oooOOoO0oo0 in lisp_db_list :
  ooOoOoO0 += len ( oooOOoO0oo0 . dynamic_eids ) if oooOOoO0oo0 . dynamic_eid_configured ( ) else 1
  ooOoOoO0 += len ( oooOOoO0oo0 . eid . iid_list )
  if 70 - 70: iIii1I11I1II1
 return ( ooOoOoO0 )
 if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
 if 64 - 64: iII111i - Oo0Ooo
 if 73 - 73: iIii1I11I1II1 * I1Ii111 * OoO0O00
 if 68 - 68: ooOoO0o * Ii1I / I1ii11iIi11i * OoooooooOO + OoooooooOO . OoooooooOO
 if 50 - 50: I1IiiI % o0oOOo0O0Ooo
 if 1 - 1: II111iiii
 if 22 - 22: I1Ii111 + iII111i
 if 50 - 50: iII111i % OoOoOO00 - II111iiii + II111iiii / OoO0O00
def lisp_is_myeid ( eid ) :
 for oooOOoO0oo0 in lisp_db_list :
  if ( eid . is_more_specific ( oooOOoO0oo0 . eid ) ) : return ( True )
  if 69 - 69: Ii1I * II111iiii
 return ( False )
 if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
 if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
 if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
 if 10 - 10: Ii1I / Oo0Ooo - i1IIi
 if 11 - 11: I11i * iII111i
 if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
 if 2 - 2: oO0o + I11i / I1Ii111 . I11i
 if 59 - 59: Ii1I
 if 47 - 47: iII111i % iII111i
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
 if 23 - 23: IiII + oO0o + o0oOOo0O0Ooo . I1ii11iIi11i / i11iIiiIii + iIii1I11I1II1
 if 74 - 74: I11i % OOooOOo
 if 57 - 57: O0 + I1IiiI + i11iIiiIii
 if 90 - 90: I1ii11iIi11i . OoO0O00 * iIii1I11I1II1 - Oo0Ooo
 if 28 - 28: I1IiiI . ooOoO0o - ooOoO0o * OOooOOo . IiII
 if 16 - 16: iIii1I11I1II1 % i11iIiiIii / Ii1I % iIii1I11I1II1 / iII111i
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 27 - 27: II111iiii * OoooooooOO / Oo0Ooo % O0
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 OO0Ooo0O00ooOo0o = None
 if ( lisp_nonce_echo_list . has_key ( rloc_str ) ) :
  OO0Ooo0O00ooOo0o = lisp_nonce_echo_list [ rloc_str ]
  if 41 - 41: oO0o / iIii1I11I1II1 % iII111i - I1Ii111 % I11i * i11iIiiIii
 return ( OO0Ooo0O00ooOo0o )
 if 21 - 21: O0
 if 14 - 14: IiII / I1ii11iIi11i + Ii1I
 if 48 - 48: I1Ii111 * oO0o / o0oOOo0O0Ooo * OoOoOO00 * ooOoO0o
 if 38 - 38: I1IiiI * Ii1I + Oo0Ooo - OoooooooOO
 if 63 - 63: I1ii11iIi11i
 if 99 - 99: I1Ii111 % oO0o - II111iiii . ooOoO0o
 if 26 - 26: I1ii11iIi11i * iII111i . OoooooooOO - Oo0Ooo - IiII
 if 6 - 6: OOooOOo - I1IiiI . IiII
def lisp_decode_dist_name ( packet ) :
 ooOoOoO0 = 0
 iiiIi = ""
 if 89 - 89: I11i + II111iiii
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( ooOoOoO0 == 255 ) : return ( [ None , None ] )
  iiiIi += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  ooOoOoO0 += 1
  if 72 - 72: iII111i - Oo0Ooo / O0 + I1IiiI * Ii1I
  if 23 - 23: II111iiii % I11i * I11i + O0 . iII111i
 packet = packet [ 1 : : ]
 return ( packet , iiiIi )
 if 100 - 100: o0oOOo0O0Ooo
 if 65 - 65: iIii1I11I1II1
 if 11 - 11: O0
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
def lisp_write_flow_log ( flow_log ) :
 III1I = open ( "./logs/lisp-flow.log" , "a" )
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 ooOoOoO0 = 0
 for o00OO000 in flow_log :
  o0o0ooOOo0oO = o00OO000 [ 3 ]
  oooOOOo00OoO0 = o0o0ooOOo0oO . print_flow ( o00OO000 [ 0 ] , o00OO000 [ 1 ] , o00OO000 [ 2 ] )
  III1I . write ( oooOOOo00OoO0 )
  ooOoOoO0 += 1
  if 74 - 74: Oo0Ooo - oO0o + OoooooooOO
 III1I . close ( )
 del ( flow_log )
 if 44 - 44: o0oOOo0O0Ooo % ooOoO0o . oO0o - Oo0Ooo % OOooOOo
 ooOoOoO0 = bold ( str ( ooOoOoO0 ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( ooOoOoO0 ) )
 return
 if 15 - 15: o0oOOo0O0Ooo - Oo0Ooo / IiII
 if 94 - 94: Ii1I + o0oOOo0O0Ooo / II111iiii
 if 18 - 18: I1IiiI
 if 27 - 27: ooOoO0o
 if 20 - 20: OoooooooOO * OOooOOo
 if 77 - 77: Ii1I - OoooooooOO . OoOoOO00
 if 93 - 93: OoooooooOO / I1Ii111
def lisp_policy_command ( kv_pair ) :
 IIIiIIi111 = lisp_policy ( "" )
 ooo000OOo0Ooo = None
 if 15 - 15: OoO0O00 * i1IIi % OoO0O00 - oO0o / iIii1I11I1II1 - o0oOOo0O0Ooo
 o0o0ooo0oOOOO = [ ]
 for OoOOoO0oOo in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  o0o0ooo0oOOOO . append ( lisp_policy_match ( ) )
  if 57 - 57: O0 - I1Ii111 . IiII
  if 56 - 56: OoooooooOO
 for i1iiiI1iI1iiI in kv_pair . keys ( ) :
  iiIiII11i1 = kv_pair [ i1iiiI1iI1iiI ]
  if 81 - 81: Ii1I - OoooooooOO - i11iIiiIii . OoOoOO00
  if 14 - 14: iII111i . I1Ii111 - O0 - i11iIiiIii + o0oOOo0O0Ooo
  if 20 - 20: O0 % OoooooooOO + iII111i - ooOoO0o
  if 10 - 10: iII111i . iIii1I11I1II1 % ooOoO0o / oO0o
  if ( i1iiiI1iI1iiI == "instance-id" ) :
   for OoOOoO0oOo in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = iiIiII11i1 [ OoOOoO0oOo ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ OoOOoO0oOo ]
    if ( oOOoOo0O0 . source_eid == None ) :
     oOOoOo0O0 . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 56 - 56: i1IIi + I11i . i1IIi / II111iiii * OOooOOo - OoOoOO00
    if ( oOOoOo0O0 . dest_eid == None ) :
     oOOoOo0O0 . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 58 - 58: II111iiii . OOooOOo % II111iiii * oO0o % OoO0O00 % I11i
    oOOoOo0O0 . source_eid . instance_id = int ( i1i11i )
    oOOoOo0O0 . dest_eid . instance_id = int ( i1i11i )
    if 71 - 71: Ii1I * II111iiii * I1IiiI
    if 22 - 22: oO0o
  if ( i1iiiI1iI1iiI == "source-eid" ) :
   for OoOOoO0oOo in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = iiIiII11i1 [ OoOOoO0oOo ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ OoOOoO0oOo ]
    if ( oOOoOo0O0 . source_eid == None ) :
     oOOoOo0O0 . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 96 - 96: ooOoO0o * iII111i . IiII
    i1 = oOOoOo0O0 . source_eid . instance_id
    oOOoOo0O0 . source_eid . store_prefix ( i1i11i )
    oOOoOo0O0 . source_eid . instance_id = i1
    if 77 - 77: OOooOOo - I11i % o0oOOo0O0Ooo
    if 46 - 46: I1IiiI % oO0o . OoooooooOO . IiII / I11i - i1IIi
  if ( i1iiiI1iI1iiI == "destination-eid" ) :
   for OoOOoO0oOo in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = iiIiII11i1 [ OoOOoO0oOo ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ OoOOoO0oOo ]
    if ( oOOoOo0O0 . dest_eid == None ) :
     oOOoOo0O0 . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 43 - 43: OoOoOO00 - o0oOOo0O0Ooo
    i1 = oOOoOo0O0 . dest_eid . instance_id
    oOOoOo0O0 . dest_eid . store_prefix ( i1i11i )
    oOOoOo0O0 . dest_eid . instance_id = i1
    if 22 - 22: i1IIi
    if 33 - 33: O0
  if ( i1iiiI1iI1iiI == "source-rloc" ) :
   for OoOOoO0oOo in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = iiIiII11i1 [ OoOOoO0oOo ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ OoOOoO0oOo ]
    oOOoOo0O0 . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    oOOoOo0O0 . source_rloc . store_prefix ( i1i11i )
    if 34 - 34: I1Ii111 . IiII % iII111i
    if 94 - 94: OOooOOo % i11iIiiIii . OOooOOo
  if ( i1iiiI1iI1iiI == "destination-rloc" ) :
   for OoOOoO0oOo in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = iiIiII11i1 [ OoOOoO0oOo ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ OoOOoO0oOo ]
    oOOoOo0O0 . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    oOOoOo0O0 . dest_rloc . store_prefix ( i1i11i )
    if 55 - 55: OoOoOO00 . OoOoOO00 % o0oOOo0O0Ooo . I11i . I1ii11iIi11i - o0oOOo0O0Ooo
    if 1 - 1: i11iIiiIii - i1IIi * oO0o - iIii1I11I1II1
  if ( i1iiiI1iI1iiI == "rloc-record-name" ) :
   for OoOOoO0oOo in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = iiIiII11i1 [ OoOOoO0oOo ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ OoOOoO0oOo ]
    oOOoOo0O0 . rloc_record_name = i1i11i
    if 75 - 75: i1IIi * i11iIiiIii
    if 40 - 40: I1ii11iIi11i + OoO0O00
  if ( i1iiiI1iI1iiI == "geo-name" ) :
   for OoOOoO0oOo in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = iiIiII11i1 [ OoOOoO0oOo ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ OoOOoO0oOo ]
    oOOoOo0O0 . geo_name = i1i11i
    if 8 - 8: i11iIiiIii - iIii1I11I1II1
    if 73 - 73: OoOoOO00
  if ( i1iiiI1iI1iiI == "elp-name" ) :
   for OoOOoO0oOo in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = iiIiII11i1 [ OoOOoO0oOo ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ OoOOoO0oOo ]
    oOOoOo0O0 . elp_name = i1i11i
    if 25 - 25: iII111i / oO0o
    if 61 - 61: OoooooooOO . Ii1I . I11i + oO0o
  if ( i1iiiI1iI1iiI == "rle-name" ) :
   for OoOOoO0oOo in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = iiIiII11i1 [ OoOOoO0oOo ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ OoOOoO0oOo ]
    oOOoOo0O0 . rle_name = i1i11i
    if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
    if 61 - 61: I1IiiI / OOooOOo
  if ( i1iiiI1iI1iiI == "json-name" ) :
   for OoOOoO0oOo in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = iiIiII11i1 [ OoOOoO0oOo ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ OoOOoO0oOo ]
    oOOoOo0O0 . json_name = i1i11i
    if 67 - 67: OoOoOO00
    if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
  if ( i1iiiI1iI1iiI == "datetime-range" ) :
   for OoOOoO0oOo in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = iiIiII11i1 [ OoOOoO0oOo ]
    oOOoOo0O0 = o0o0ooo0oOOOO [ OoOOoO0oOo ]
    if ( i1i11i == "" ) : continue
    OOoOo0O0 = lisp_datetime ( i1i11i [ 0 : 19 ] )
    OO0O0OOooo = lisp_datetime ( i1i11i [ 19 : : ] )
    if ( OOoOo0O0 . valid_datetime ( ) and OO0O0OOooo . valid_datetime ( ) ) :
     oOOoOo0O0 . datetime_lower = OOoOo0O0
     oOOoOo0O0 . datetime_upper = OO0O0OOooo
     if 30 - 30: O0 / oO0o * i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
     if 95 - 95: ooOoO0o % OOooOOo
     if 17 - 17: i1IIi + Ii1I
     if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
     if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
     if 26 - 26: oO0o / I1ii11iIi11i - oO0o
     if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
  if ( i1iiiI1iI1iiI == "set-action" ) :
   IIIiIIi111 . set_action = iiIiII11i1
   if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
  if ( i1iiiI1iI1iiI == "set-record-ttl" ) :
   IIIiIIi111 . set_record_ttl = int ( iiIiII11i1 )
   if 96 - 96: Ii1I
  if ( i1iiiI1iI1iiI == "set-instance-id" ) :
   if ( IIIiIIi111 . set_source_eid == None ) :
    IIIiIIi111 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 90 - 90: II111iiii
   if ( IIIiIIi111 . set_dest_eid == None ) :
    IIIiIIi111 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
   ooo000OOo0Ooo = int ( iiIiII11i1 )
   IIIiIIi111 . set_source_eid . instance_id = ooo000OOo0Ooo
   IIIiIIi111 . set_dest_eid . instance_id = ooo000OOo0Ooo
   if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
  if ( i1iiiI1iI1iiI == "set-source-eid" ) :
   if ( IIIiIIi111 . set_source_eid == None ) :
    IIIiIIi111 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 52 - 52: i11iIiiIii * ooOoO0o
   IIIiIIi111 . set_source_eid . store_prefix ( iiIiII11i1 )
   if ( ooo000OOo0Ooo != None ) : IIIiIIi111 . set_source_eid . instance_id = ooo000OOo0Ooo
   if 15 - 15: OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
  if ( i1iiiI1iI1iiI == "set-destination-eid" ) :
   if ( IIIiIIi111 . set_dest_eid == None ) :
    IIIiIIi111 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 91 - 91: ooOoO0o
   IIIiIIi111 . set_dest_eid . store_prefix ( iiIiII11i1 )
   if ( ooo000OOo0Ooo != None ) : IIIiIIi111 . set_dest_eid . instance_id = ooo000OOo0Ooo
   if 47 - 47: II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
  if ( i1iiiI1iI1iiI == "set-rloc-address" ) :
   IIIiIIi111 . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   IIIiIIi111 . set_rloc_address . store_address ( iiIiII11i1 )
   if 9 - 9: O0 + IiII
  if ( i1iiiI1iI1iiI == "set-rloc-record-name" ) :
   IIIiIIi111 . set_rloc_record_name = iiIiII11i1
   if 69 - 69: I1IiiI
  if ( i1iiiI1iI1iiI == "set-elp-name" ) :
   IIIiIIi111 . set_elp_name = iiIiII11i1
   if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
  if ( i1iiiI1iI1iiI == "set-geo-name" ) :
   IIIiIIi111 . set_geo_name = iiIiII11i1
   if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
  if ( i1iiiI1iI1iiI == "set-rle-name" ) :
   IIIiIIi111 . set_rle_name = iiIiII11i1
   if 86 - 86: ooOoO0o * OoOoOO00 + oO0o / II111iiii % OOooOOo
  if ( i1iiiI1iI1iiI == "set-json-name" ) :
   IIIiIIi111 . set_json_name = iiIiII11i1
   if 89 - 89: O0 * Ii1I / OoO0O00 / OoOoOO00 % iII111i * iIii1I11I1II1
  if ( i1iiiI1iI1iiI == "policy-name" ) :
   IIIiIIi111 . policy_name = iiIiII11i1
   if 72 - 72: iIii1I11I1II1 / iIii1I11I1II1 * I11i
   if 19 - 19: I1ii11iIi11i
   if 42 - 42: OoOoOO00 / IiII
   if 65 - 65: ooOoO0o - ooOoO0o * OoO0O00
   if 99 - 99: I11i % ooOoO0o . I1Ii111
   if 34 - 34: ooOoO0o + oO0o + II111iiii . I1Ii111 . i1IIi
 IIIiIIi111 . match_clauses = o0o0ooo0oOOOO
 IIIiIIi111 . save_policy ( )
 return
 if 14 - 14: OoO0O00 . ooOoO0o - i1IIi * I1IiiI
 if 24 - 24: iIii1I11I1II1 / I1Ii111
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
if 16 - 16: OoOoOO00 * I1Ii111 - I1IiiI / I1Ii111
if 64 - 64: I1ii11iIi11i . i1IIi % II111iiii % Oo0Ooo + oO0o - I1IiiI
if 24 - 24: IiII . II111iiii . II111iiii . OoOoOO00 . i11iIiiIii
if 11 - 11: Ii1I
if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
if 44 - 44: iII111i
if 56 - 56: II111iiii / Oo0Ooo % IiII * II111iiii - iIii1I11I1II1 + ooOoO0o
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 33 - 33: o0oOOo0O0Ooo . I11i / I1IiiI
 iI1I1i111 = command
 if ( interface != "" ) : iI1I1i111 = interface + ": " + iI1I1i111
 lprint ( "Send CLI command '{}' to hardware" . format ( iI1I1i111 ) )
 if 29 - 29: IiII . iII111i * Oo0Ooo
 Ii1iii = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 88 - 88: OoooooooOO
 os . system ( "FastCli -c '{}'" . format ( Ii1iii ) )
 return
 if 40 - 40: ooOoO0o * oO0o * Ii1I . ooOoO0o + i11iIiiIii
 if 44 - 44: o0oOOo0O0Ooo / iIii1I11I1II1
 if 66 - 66: O0 % I11i . O0 * o0oOOo0O0Ooo / I1Ii111 + o0oOOo0O0Ooo
 if 24 - 24: i11iIiiIii * oO0o * I1IiiI - i1IIi * OoOoOO00
 if 5 - 5: I1ii11iIi11i % o0oOOo0O0Ooo . iII111i
 if 73 - 73: OoOoOO00 . o0oOOo0O0Ooo * OoOoOO00
 if 94 - 94: OoO0O00 / I1ii11iIi11i
def lisp_arista_is_alive ( prefix ) :
 ii1iI1i = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 OoiIIIiIi1I1i = getoutput ( "FastCli -c '{}'" . format ( ii1iI1i ) )
 if 50 - 50: OoOoOO00 % I1IiiI + I1Ii111 . iII111i . iII111i
 if 89 - 89: oO0o / I1ii11iIi11i % I1Ii111
 if 86 - 86: Ii1I * II111iiii % ooOoO0o
 if 82 - 82: OOooOOo . Oo0Ooo * ooOoO0o % II111iiii % II111iiii - oO0o
 OoiIIIiIi1I1i = OoiIIIiIi1I1i . split ( "\n" ) [ 1 ]
 OoooOOOOO0 = OoiIIIiIi1I1i . split ( " " )
 OoooOOOOO0 = OoooOOOOO0 [ - 1 ] . replace ( "\r" , "" )
 if 36 - 36: O0 / I1ii11iIi11i + iII111i * Oo0Ooo
 if 97 - 97: IiII * O0 - o0oOOo0O0Ooo
 if 77 - 77: II111iiii / I11i % OoooooooOO % I1IiiI % II111iiii
 if 99 - 99: Oo0Ooo
 return ( OoooOOOOO0 == "Y" )
 if 30 - 30: OoOoOO00 + I1Ii111 . OoOoOO00 - I11i
 if 42 - 42: OoOoOO00
 if 77 - 77: Oo0Ooo * IiII * I1ii11iIi11i + IiII
 if 37 - 37: IiII . OoooooooOO - i11iIiiIii * I1ii11iIi11i - OOooOOo
 if 74 - 74: Ii1I + i11iIiiIii * iII111i / o0oOOo0O0Ooo . i11iIiiIii
 if 99 - 99: OOooOOo - OoooooooOO + OoooooooOO . OOooOOo
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
 if 15 - 15: iIii1I11I1II1 * Oo0Ooo . iIii1I11I1II1 . Ii1I % iII111i - i11iIiiIii
 if 77 - 77: ooOoO0o - o0oOOo0O0Ooo * OoOoOO00 % oO0o
 if 4 - 4: i11iIiiIii + OoOoOO00
 if 45 - 45: ooOoO0o / OoooooooOO . Oo0Ooo
 if 35 - 35: i11iIiiIii / o0oOOo0O0Ooo / oO0o / I11i . O0
 if 53 - 53: i1IIi
 if 51 - 51: OoOoOO00 / iIii1I11I1II1 . oO0o - I1ii11iIi11i - OOooOOo
 if 90 - 90: i1IIi / oO0o * I1Ii111 + II111iiii % I11i
 if 41 - 41: o0oOOo0O0Ooo - II111iiii . ooOoO0o . iII111i - ooOoO0o / iII111i
 if 59 - 59: O0 / II111iiii * II111iiii - ooOoO0o
 if 63 - 63: I1ii11iIi11i * IiII % OoO0O00 . OoOoOO00 - II111iiii % IiII
 if 8 - 8: iIii1I11I1II1
 if 71 - 71: oO0o / o0oOOo0O0Ooo % iIii1I11I1II1 * iIii1I11I1II1
 if 29 - 29: ooOoO0o - OoOoOO00 - o0oOOo0O0Ooo
 if 54 - 54: Ii1I + i11iIiiIii + i1IIi - OoooooooOO
 if 100 - 100: oO0o . ooOoO0o
 if 14 - 14: OoooooooOO + iII111i / iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1 - IiII
 if 34 - 34: I1ii11iIi11i + i11iIiiIii - I1ii11iIi11i / OoOoOO00 + i1IIi . i11iIiiIii
 if 48 - 48: I1ii11iIi11i % OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii / OoOoOO00
 if 73 - 73: OoOoOO00 + OOooOOo * II111iiii . OOooOOo % I1Ii111 % oO0o
 if 79 - 79: I1ii11iIi11i % I11i
 if 78 - 78: i11iIiiIii % I1Ii111 + iIii1I11I1II1 + iII111i
 if 66 - 66: I1IiiI - o0oOOo0O0Ooo
def lisp_program_vxlan_hardware ( mc ) :
 if 67 - 67: oO0o . iII111i * Ii1I - OOooOOo / oO0o
 if 98 - 98: OoOoOO00 * OoO0O00 . Oo0Ooo
 if 6 - 6: I11i % iIii1I11I1II1 + I1Ii111
 if 48 - 48: II111iiii . OOooOOo . ooOoO0o - iII111i
 if 90 - 90: OOooOOo
 if 43 - 43: IiII + ooOoO0o
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 4 - 4: i1IIi
 if 89 - 89: Oo0Ooo / iIii1I11I1II1 . OoOoOO00
 if 6 - 6: Ii1I / iII111i
 if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 70 - 70: oO0o - I1IiiI + Ii1I
 if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
 if 37 - 37: o0oOOo0O0Ooo
 if 57 - 57: iII111i / i1IIi / i1IIi + IiII
 ooOo000OOooo = mc . eid . print_prefix_no_iid ( )
 IIIi1iI1 = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 75 - 75: IiII / O0
 if 72 - 72: I11i
 if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
 if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
 iIIOO0OO = getoutput ( "ip route get {} | egrep vlan4094" . format ( ooOo000OOooo ) )
 if 67 - 67: OoO0O00 . II111iiii * O0
 if ( iIIOO0OO != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( ooOo000OOooo , False ) , iIIOO0OO ) )
  if 1 - 1: o0oOOo0O0Ooo + Oo0Ooo
  return
  if 20 - 20: O0
  if 77 - 77: I1ii11iIi11i + OoooooooOO * OoO0O00 * iIii1I11I1II1 % I1Ii111
  if 22 - 22: i1IIi
  if 61 - 61: IiII
  if 3 - 3: ooOoO0o . Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . I1Ii111
  if 20 - 20: iII111i + II111iiii + i11iIiiIii
  if 75 - 75: OoooooooOO
 O0oO00O00O = getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( O0oO00O00O . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 26 - 26: oO0o . oO0o + I11i * OOooOOo
 if ( O0oO00O00O . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 48 - 48: iII111i + Ii1I
 iiI1iI = getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( iiI1iI == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 100 - 100: i1IIi / Oo0Ooo / II111iiii + iII111i . II111iiii * oO0o
 iiI1iI = iiI1iI . split ( "inet " ) [ 1 ]
 iiI1iI = iiI1iI . split ( "/" ) [ 0 ]
 if 36 - 36: Oo0Ooo + iII111i / OOooOOo + OOooOOo % i11iIiiIii / I1IiiI
 if 59 - 59: ooOoO0o / I11i
 if 32 - 32: iIii1I11I1II1 % oO0o / I1Ii111
 if 42 - 42: I11i / I1ii11iIi11i - I1IiiI * iII111i / I1IiiI / i11iIiiIii
 if 75 - 75: Oo0Ooo + IiII / I11i % I11i % IiII / I1Ii111
 if 95 - 95: OoOoOO00
 if 78 - 78: I11i
 OooO0O0oOOOoOO0O = [ ]
 O00O00OOo0oo0 = getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for OOooOoO in O00O00OOo0oo0 :
  if ( OOooOoO . find ( "vlan4094" ) == - 1 ) : continue
  if ( OOooOoO . find ( "(incomplete)" ) == - 1 ) : continue
  Oo00 = OOooOoO . split ( " " ) [ 0 ]
  OooO0O0oOOOoOO0O . append ( Oo00 )
  if 92 - 92: i1IIi + I1Ii111 . i1IIi % I1ii11iIi11i
  if 59 - 59: iII111i * O0
 Oo00 = None
 Ii1IiI = iiI1iI
 iiI1iI = iiI1iI . split ( "." )
 for OoOOoO0oOo in range ( 1 , 255 ) :
  iiI1iI [ 3 ] = str ( OoOOoO0oOo )
  IiIIiiI = "." . join ( iiI1iI )
  if ( IiIIiiI in OooO0O0oOOOoOO0O ) : continue
  if ( IiIIiiI == Ii1IiI ) : continue
  Oo00 = IiIIiiI
  break
  if 88 - 88: ooOoO0o / OoOoOO00 % IiII - iIii1I11I1II1 / I11i
 if ( Oo00 == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 15 - 15: O0 . II111iiii
  return
  if 14 - 14: oO0o . I11i . i1IIi + I1ii11iIi11i
  if 53 - 53: Ii1I
  if 35 - 35: oO0o * i1IIi / IiII / iII111i
  if 19 - 19: I1IiiI + iIii1I11I1II1 * O0 - OOooOOo
  if 32 - 32: O0 - II111iiii - i1IIi + O0 + OOooOOo
  if 44 - 44: I11i * oO0o % OoooooooOO % OoO0O00 / o0oOOo0O0Ooo
  if 37 - 37: OoO0O00 + OoOoOO00 - I1IiiI
 Ooo0ii = IIIi1iI1 . split ( "." )
 OOo0ooo0O = lisp_hex_string ( Ooo0ii [ 1 ] ) . zfill ( 2 )
 ooOOoOoOo = lisp_hex_string ( Ooo0ii [ 2 ] ) . zfill ( 2 )
 iIiI11ii = lisp_hex_string ( Ooo0ii [ 3 ] ) . zfill ( 2 )
 iiiI1IiIIii = "00:00:00:{}:{}:{}" . format ( OOo0ooo0O , ooOOoOoOo , iIiI11ii )
 I1i1iI1ii = "0000.00{}.{}{}" . format ( OOo0ooo0O , ooOOoOoOo , iIiI11ii )
 OOoO0oOOOO0O = "arp -i vlan4094 -s {} {}" . format ( Oo00 , iiiI1IiIIii )
 os . system ( OOoO0oOOOO0O )
 if 19 - 19: ooOoO0o + I1ii11iIi11i - ooOoO0o
 if 17 - 17: I11i * i1IIi + iIii1I11I1II1 % I1IiiI
 if 44 - 44: IiII + I1IiiI . Ii1I % Oo0Ooo
 if 97 - 97: O0
 OOo00Ooooo = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( I1i1iI1ii , IIIi1iI1 )
 if 62 - 62: o0oOOo0O0Ooo - iII111i / II111iiii . o0oOOo0O0Ooo
 lisp_send_to_arista ( OOo00Ooooo , None )
 if 20 - 20: iIii1I11I1II1 % OOooOOo
 if 91 - 91: ooOoO0o
 if 96 - 96: I1IiiI . OOooOOo
 if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
 if 34 - 34: IiII % oO0o
 o0OoOo = "ip route add {} via {}" . format ( ooOo000OOooo , Oo00 )
 os . system ( o0OoOo )
 if 33 - 33: I1ii11iIi11i
 lprint ( "Hardware programmed with commands:" )
 o0OoOo = o0OoOo . replace ( ooOo000OOooo , green ( ooOo000OOooo , False ) )
 lprint ( "  " + o0OoOo )
 lprint ( "  " + OOoO0oOOOO0O )
 OOo00Ooooo = OOo00Ooooo . replace ( IIIi1iI1 , red ( IIIi1iI1 , False ) )
 lprint ( "  " + OOo00Ooooo )
 return
 if 85 - 85: ooOoO0o / I11i
 if 52 - 52: OoooooooOO
 if 84 - 84: O0 . OOooOOo / IiII - i1IIi % OoooooooOO
 if 5 - 5: ooOoO0o % Oo0Ooo % II111iiii + ooOoO0o
 if 6 - 6: OoO0O00 + I1Ii111 - Ii1I / I1ii11iIi11i
 if 31 - 31: O0 . OoooooooOO % oO0o / i11iIiiIii
 if 85 - 85: I11i
def lisp_clear_hardware_walk ( mc , parms ) :
 IIi1iii1i1 = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( IIi1iii1i1 ) )
 return ( [ True , None ] )
 if 23 - 23: oO0o % I11i * Oo0Ooo + Oo0Ooo
 if 23 - 23: Ii1I % i1IIi - I1Ii111
 if 95 - 95: OoOoOO00 - ooOoO0o . i1IIi . OoooooooOO
 if 38 - 38: I1IiiI + I1ii11iIi11i - Oo0Ooo . i11iIiiIii - i1IIi
 if 11 - 11: IiII / I1IiiI . I1IiiI
 if 87 - 87: OoooooooOO * OoO0O00 * iIii1I11I1II1
 if 16 - 16: o0oOOo0O0Ooo * I11i + OoooooooOO + O0 / iIii1I11I1II1
 if 60 - 60: Ii1I % IiII * OoooooooOO * ooOoO0o * Ii1I
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list , lisp_gleaned_groups
 global lisp_no_map_request_rate_limit
 if 8 - 8: I1Ii111 - o0oOOo0O0Ooo
 OOOooOoO0O0 = bold ( "User cleared" , False )
 ooOoOoO0 = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( OOOooOoO0O0 , ooOoOoO0 ) )
 if 2 - 2: ooOoO0o - OoOoOO00 + oO0o . IiII + I1ii11iIi11i - OOooOOo
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 91 - 91: o0oOOo0O0Ooo . i11iIiiIii . I1Ii111 . I1Ii111 / Ii1I + I1Ii111
 lisp_map_cache = lisp_cache ( )
 if 5 - 5: i1IIi * I1ii11iIi11i + OoOoOO00 % OOooOOo
 if 64 - 64: O0 % o0oOOo0O0Ooo + OoooooooOO - I1IiiI
 if 29 - 29: o0oOOo0O0Ooo - OoOoOO00 - OoooooooOO / OoOoOO00
 if 88 - 88: OoOoOO00 - IiII
 lisp_no_map_request_rate_limit = lisp_get_timestamp ( )
 if 96 - 96: Ii1I % iIii1I11I1II1
 if 22 - 22: I1Ii111 - I1ii11iIi11i . Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
 if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
 if 46 - 46: oO0o + OoOoOO00
 if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
 lisp_rloc_probe_list = { }
 if 59 - 59: O0
 if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
 if 17 - 17: Ii1I % I1ii11iIi11i + I11i
 if 80 - 80: i1IIi . OoooooooOO % OoooooooOO . oO0o / OOooOOo
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 85 - 85: OOooOOo
 if 80 - 80: ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
 if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
 if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
 if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
 lisp_rtr_list = { }
 if 72 - 72: IiII / II111iiii
 if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
 if 21 - 21: I1ii11iIi11i
 if 60 - 60: i1IIi / OoO0O00 . Ii1I
 lisp_gleaned_groups = { }
 if 16 - 16: i11iIiiIii + OoOoOO00 % Oo0Ooo + I1ii11iIi11i * Ii1I / I1Ii111
 if 26 - 26: iII111i
 if 31 - 31: iII111i
 if 45 - 45: OoO0O00
 lisp_process_data_plane_restart ( True )
 return
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
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 42 - 42: I1ii11iIi11i * ooOoO0o + OoOoOO00 % I1ii11iIi11i . IiII
 OOOo000oOOO0O = lisp_myrlocs [ 0 ]
 if 85 - 85: IiII * I1IiiI * Ii1I . I1IiiI % ooOoO0o
 if 69 - 69: OoO0O00 % Ii1I % OoOoOO00 + o0oOOo0O0Ooo - I1ii11iIi11i
 if 21 - 21: OoOoOO00 + OoOoOO00 + oO0o / i1IIi . IiII
 if 12 - 12: i11iIiiIii . ooOoO0o
 if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
 i1iIii = len ( packet ) + 28
 O0O = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( i1iIii ) , 0 , 64 ,
 17 , 0 , socket . htonl ( OOOo000oOOO0O . address ) , socket . htonl ( rloc . address ) )
 O0O = lisp_ip_checksum ( O0O )
 if 88 - 88: OoooooooOO . I1IiiI
 O0I1II1 = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( i1iIii - 20 ) , 0 )
 if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
 if 7 - 7: i1IIi
 if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
 if 34 - 34: iII111i + i11iIiiIii . IiII
 packet = lisp_packet ( O0O + O0I1II1 + packet )
 if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
 if 29 - 29: II111iiii % i11iIiiIii % O0
 if 38 - 38: o0oOOo0O0Ooo * IiII
 if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( OOOo000oOOO0O )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( OOOo000oOOO0O )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
 iI = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  III11iI1 = " {}" . format ( blue ( nat_info . hostname , False ) )
  OoO0oo0O = bold ( "RLOC-probe request" , False )
 else :
  III11iI1 = ""
  OoO0oo0O = bold ( "RLOC-probe reply" , False )
  if 19 - 19: OoooooooOO
  if 34 - 34: OoOoOO00 . oO0o
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( OoO0oo0O , iI , III11iI1 , packet . encap_port ) )
 if 53 - 53: oO0o + OoooooooOO * ooOoO0o
 if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
 if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
 if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
 if 80 - 80: II111iiii . i11iIiiIii
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
 iIii1 = lisp_sockets [ 3 ]
 packet . send_packet ( iIii1 , packet . outer_dest )
 del ( packet )
 return
 if 88 - 88: iIii1I11I1II1 % iII111i
 if 25 - 25: O0 % i11iIiiIii
 if 67 - 67: I1ii11iIi11i / OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / II111iiii . I1IiiI
 if 72 - 72: I1Ii111 * I1ii11iIi11i * Ii1I % II111iiii * Ii1I / O0
 if 6 - 6: oO0o * ooOoO0o . I1Ii111 / OOooOOo . OoOoOO00
 if 4 - 4: Ii1I / II111iiii + o0oOOo0O0Ooo / IiII
 if 9 - 9: ooOoO0o + i1IIi / ooOoO0o / I11i * I1ii11iIi11i / OoooooooOO
 if 28 - 28: o0oOOo0O0Ooo
def lisp_get_default_route_next_hops ( ) :
 if 97 - 97: I1Ii111 - I1Ii111 * OoO0O00 % II111iiii * IiII
 if 2 - 2: I1Ii111 % iII111i . OoooooooOO - o0oOOo0O0Ooo
 if 30 - 30: i1IIi / I1Ii111 * oO0o - oO0o / oO0o
 if 9 - 9: IiII / o0oOOo0O0Ooo . IiII * O0 % i11iIiiIii % OoOoOO00
 if ( lisp_is_macos ( ) ) :
  ii1iI1i = "route -n get default"
  IIi1iIi1111 = getoutput ( ii1iI1i ) . split ( "\n" )
  IiI1i11II1II = iI1ii1iI1 = None
  for III1I in IIi1iIi1111 :
   if ( III1I . find ( "gateway: " ) != - 1 ) : IiI1i11II1II = III1I . split ( ": " ) [ 1 ]
   if ( III1I . find ( "interface: " ) != - 1 ) : iI1ii1iI1 = III1I . split ( ": " ) [ 1 ]
   if 95 - 95: I11i . I11i - i11iIiiIii % iIii1I11I1II1 / O0
  return ( [ [ iI1ii1iI1 , IiI1i11II1II ] ] )
  if 86 - 86: O0 / I1ii11iIi11i . I1ii11iIi11i - I1Ii111 % II111iiii + OOooOOo
  if 45 - 45: I1Ii111 + iII111i - iIii1I11I1II1 / Oo0Ooo
  if 92 - 92: iIii1I11I1II1 . OoO0O00 - I11i % I1ii11iIi11i / i11iIiiIii
  if 4 - 4: Oo0Ooo / I1IiiI * i1IIi . II111iiii
  if 13 - 13: i1IIi
 ii1iI1i = "ip route | egrep 'default via'"
 ii11Iiii1iIiI = getoutput ( ii1iI1i ) . split ( "\n" )
 if 39 - 39: OOooOOo
 iI1I111 = [ ]
 for iIIOO0OO in ii11Iiii1iIiI :
  if ( iIIOO0OO . find ( " metric " ) != - 1 ) : continue
  iiiI1I = iIIOO0OO . split ( " " )
  try :
   oOoOOO = iiiI1I . index ( "via" ) + 1
   if ( oOoOOO >= len ( iiiI1I ) ) : continue
   oo00o0o = iiiI1I . index ( "dev" ) + 1
   if ( oo00o0o >= len ( iiiI1I ) ) : continue
  except :
   continue
   if 82 - 82: ooOoO0o + OoOoOO00
   if 93 - 93: I1ii11iIi11i . iII111i . iIii1I11I1II1
  iI1I111 . append ( [ iiiI1I [ oo00o0o ] , iiiI1I [ oOoOOO ] ] )
  if 60 - 60: oO0o
 return ( iI1I111 )
 if 44 - 44: iIii1I11I1II1 - OoOoOO00 / iII111i * OoooooooOO . Ii1I / i11iIiiIii
 if 85 - 85: OoO0O00
 if 29 - 29: IiII
 if 57 - 57: OoooooooOO + IiII + II111iiii
 if 20 - 20: iII111i * I1IiiI * iII111i - o0oOOo0O0Ooo + i1IIi + ooOoO0o
 if 49 - 49: II111iiii * I1IiiI / oO0o
 if 50 - 50: Ii1I + O0 . I1IiiI * Oo0Ooo
def lisp_get_host_route_next_hop ( rloc ) :
 ii1iI1i = "ip route | egrep '{} via'" . format ( rloc )
 iIIOO0OO = getoutput ( ii1iI1i ) . split ( " " )
 if 15 - 15: Oo0Ooo
 try : I1i11II = iIIOO0OO . index ( "via" ) + 1
 except : return ( None )
 if 53 - 53: OoooooooOO * O0 / iII111i * ooOoO0o % I1Ii111 + OOooOOo
 if ( I1i11II >= len ( iIIOO0OO ) ) : return ( None )
 return ( iIIOO0OO [ I1i11II ] )
 if 95 - 95: I1Ii111 % OoOoOO00 . IiII * iII111i % Ii1I
 if 18 - 18: iIii1I11I1II1 / ooOoO0o / I1Ii111 % oO0o * Ii1I
 if 14 - 14: oO0o
 if 72 - 72: iIii1I11I1II1 / II111iiii * II111iiii + I1IiiI + iIii1I11I1II1 + oO0o
 if 46 - 46: I1Ii111
 if 23 - 23: Oo0Ooo * IiII - I1Ii111 . OoooooooOO
 if 78 - 78: OoOoOO00 - iIii1I11I1II1
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 iiIii1I1I = "none" if nh == None else nh
 if 20 - 20: i1IIi
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , iiIii1I1I ) )
 if 72 - 72: ooOoO0o . II111iiii
 if ( nh == None ) :
  I11IiI1i11i1 = "ip route {} {}/32" . format ( install , dest )
 else :
  I11IiI1i11i1 = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
 os . system ( I11IiI1i11i1 )
 return
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
 if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
 if 18 - 18: o0oOOo0O0Ooo / OOooOOo
 if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
 if 100 - 100: O0
 if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
 if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
 if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 38 - 38: Ii1I
 III1I = open ( lisp_checkpoint_filename , "w" )
 for oOOoO0oO0oo0O in checkpoint_list :
  III1I . write ( oOOoO0oO0oo0O + "\n" )
  if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
 III1I . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
 if 36 - 36: I1Ii111 - OoO0O00 . I1ii11iIi11i * I1ii11iIi11i
 if 9 - 9: OOooOOo - oO0o - iIii1I11I1II1 * i11iIiiIii / I11i
 if 2 - 2: i1IIi % iII111i * ooOoO0o / OoOoOO00 + Oo0Ooo
 if 59 - 59: i11iIiiIii / I1IiiI * iII111i
 if 16 - 16: i11iIiiIii * II111iiii - ooOoO0o
 if 80 - 80: iIii1I11I1II1 + iIii1I11I1II1 + I1Ii111 - IiII * iII111i - Ii1I
 if 89 - 89: O0 * ooOoO0o
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 36 - 36: I1ii11iIi11i * II111iiii * iII111i + I1IiiI + OoO0O00 + oO0o
 III1I = open ( lisp_checkpoint_filename , "r" )
 if 28 - 28: Ii1I - i11iIiiIii . oO0o / II111iiii
 ooOoOoO0 = 0
 for oOOoO0oO0oo0O in III1I :
  ooOoOoO0 += 1
  I1i = oOOoO0oO0oo0O . split ( " rloc " )
  o00OoO = [ ] if ( I1i [ 1 ] in [ "native-forward\n" , "\n" ] ) else I1i [ 1 ] . split ( ", " )
  if 82 - 82: iII111i * iII111i . IiII * II111iiii
  if 17 - 17: OoooooooOO % I1Ii111 * I1Ii111 / II111iiii . OoOoOO00 * iII111i
  oOO000OOO = [ ]
  for IIIi1iI1 in o00OoO :
   O0O0OOo0O = lisp_rloc ( False )
   iiiI1I = IIIi1iI1 . split ( " " )
   O0O0OOo0O . rloc . store_address ( iiiI1I [ 0 ] )
   O0O0OOo0O . priority = int ( iiiI1I [ 1 ] )
   O0O0OOo0O . weight = int ( iiiI1I [ 2 ] )
   oOO000OOO . append ( O0O0OOo0O )
   if 80 - 80: IiII % i11iIiiIii
   if 6 - 6: II111iiii + i11iIiiIii - Oo0Ooo % OOooOOo + Oo0Ooo
  ooOoOO0Oo = lisp_mapping ( "" , "" , oOO000OOO )
  if ( ooOoOO0Oo != None ) :
   ooOoOO0Oo . eid . store_prefix ( I1i [ 0 ] )
   ooOoOO0Oo . checkpoint_entry = True
   ooOoOO0Oo . map_cache_ttl = LISP_NMR_TTL * 60
   if ( oOO000OOO == [ ] ) : ooOoOO0Oo . action = LISP_NATIVE_FORWARD_ACTION
   ooOoOO0Oo . add_cache ( )
   continue
   if 46 - 46: iII111i
   if 31 - 31: OoO0O00 + I1Ii111 / iIii1I11I1II1
  ooOoOoO0 -= 1
  if 11 - 11: ooOoO0o - OoOoOO00
  if 19 - 19: O0 . OoOoOO00 - i1IIi . oO0o
 III1I . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , ooOoOoO0 , lisp_checkpoint_filename ) )
 return
 if 96 - 96: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoO0O00 * iIii1I11I1II1 + ooOoO0o - ooOoO0o
 if 4 - 4: OoO0O00 - OOooOOo
 if 21 - 21: I1Ii111 * i11iIiiIii
 if 63 - 63: oO0o + OoOoOO00
 if 50 - 50: o0oOOo0O0Ooo / Oo0Ooo * ooOoO0o * Ii1I
 if 97 - 97: I1IiiI / oO0o + I1Ii111 + I1Ii111
 if 86 - 86: o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * ooOoO0o
 if 20 - 20: Ii1I * iII111i / ooOoO0o
 if 18 - 18: Oo0Ooo * Ii1I / i11iIiiIii . OoO0O00 + OoooooooOO
 if 23 - 23: I1IiiI - I1ii11iIi11i . O0 . OoOoOO00 . OoO0O00
 if 81 - 81: IiII * I11i - iIii1I11I1II1
 if 41 - 41: oO0o * I11i + I1IiiI - OoO0O00
 if 63 - 63: Oo0Ooo * Ii1I - Ii1I
 if 76 - 76: OoO0O00 . IiII % iIii1I11I1II1 / I1IiiI + iIii1I11I1II1 . I1IiiI
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 57 - 57: IiII - i1IIi * ooOoO0o
 oOOoO0oO0oo0O = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 5 - 5: oO0o . O0 * IiII / Ii1I + OoO0O00
 for O0O0OOo0O in mc . rloc_set :
  if ( O0O0OOo0O . rloc . is_null ( ) ) : continue
  oOOoO0oO0oo0O += "{} {} {}, " . format ( O0O0OOo0O . rloc . print_address_no_iid ( ) ,
 O0O0OOo0O . priority , O0O0OOo0O . weight )
  if 75 - 75: OOooOOo * OoOoOO00
  if 82 - 82: Ii1I
 if ( mc . rloc_set != [ ] ) :
  oOOoO0oO0oo0O = oOOoO0oO0oo0O [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  oOOoO0oO0oo0O += "native-forward"
  if 83 - 83: I1IiiI
  if 22 - 22: IiII / Ii1I + I1Ii111 % iIii1I11I1II1
 checkpoint_list . append ( oOOoO0oO0oo0O )
 return
 if 75 - 75: OoOoOO00 % OoOoOO00 % o0oOOo0O0Ooo % I1ii11iIi11i + IiII
 if 45 - 45: I11i - iIii1I11I1II1
 if 20 - 20: OoOoOO00
 if 84 - 84: OoOoOO00
 if 59 - 59: Ii1I / I1Ii111 + i11iIiiIii
 if 20 - 20: O0 / I1Ii111 - OOooOOo % iIii1I11I1II1
 if 89 - 89: O0 * OoOoOO00 . ooOoO0o
def lisp_check_dp_socket ( ) :
 IiiI1IiIi1i1 = lisp_ipc_dp_socket_name
 if ( os . path . exists ( IiiI1IiIi1i1 ) == False ) :
  iiIIiII1I = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( IiiI1IiIi1i1 , iiIIiII1I ) )
  return ( False )
  if 66 - 66: I1IiiI / OoOoOO00 % I11i + o0oOOo0O0Ooo
 return ( True )
 if 51 - 51: iIii1I11I1II1 + I1ii11iIi11i % OoooooooOO + Ii1I
 if 20 - 20: O0 * I1ii11iIi11i + OoOoOO00 * OOooOOo . i1IIi . o0oOOo0O0Ooo
 if 26 - 26: OOooOOo - OoOoOO00 + I1ii11iIi11i + OoO0O00 - OoOoOO00 / o0oOOo0O0Ooo
 if 76 - 76: I1ii11iIi11i / oO0o + Ii1I - O0
 if 95 - 95: OoOoOO00
 if 69 - 69: iII111i / Ii1I
 if 83 - 83: oO0o
def lisp_write_to_dp_socket ( entry ) :
 try :
  II1i1iiiII1ii = json . dumps ( entry )
  IIi1I1I11I = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( IIi1I1I11I , II1i1iiiII1ii ) )
  lisp_ipc_dp_socket . sendto ( II1i1iiiII1ii , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( II1i1iiiII1ii ) )
  if 83 - 83: iIii1I11I1II1
 return
 if 92 - 92: OoO0O00 - iII111i
 if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
 if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
 if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
 if 70 - 70: I1Ii111 % iIii1I11I1II1
 if 74 - 74: i1IIi % i11iIiiIii + oO0o
 if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
 if 34 - 34: Oo0Ooo . i1IIi
 if 97 - 97: I11i
def lisp_write_ipc_keys ( rloc ) :
 O0O0 = rloc . rloc . print_address_no_iid ( )
 IiO0o = rloc . translated_port
 if ( IiO0o != 0 ) : O0O0 += ":" + str ( IiO0o )
 if ( lisp_rloc_probe_list . has_key ( O0O0 ) == False ) : return
 if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
 for iiiI1I , I1i , OoIi1I1I in lisp_rloc_probe_list [ O0O0 ] :
  ooOoOO0Oo = lisp_map_cache . lookup_cache ( I1i , True )
  if ( ooOoOO0Oo == None ) : continue
  lisp_write_ipc_map_cache ( True , ooOoOO0Oo )
  if 20 - 20: oO0o % OoOoOO00
 return
 if 93 - 93: I1ii11iIi11i - Ii1I % i1IIi / i1IIi
 if 82 - 82: OOooOOo
 if 27 - 27: I1Ii111 / IiII - i1IIi * Ii1I
 if 90 - 90: ooOoO0o
 if 100 - 100: iII111i * i1IIi . iII111i / O0 / OoO0O00 - oO0o
 if 65 - 65: OoOoOO00 + ooOoO0o * OoO0O00 % OoooooooOO + OoooooooOO * OoooooooOO
 if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
 if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
 if 55 - 55: Oo0Ooo - OOooOOo - O0
 if 40 - 40: OoOoOO00 - OOooOOo
 oOOoo = "add" if add_or_delete else "delete"
 oOOoO0oO0oo0O = { "type" : "map-cache" , "opcode" : oOOoo }
 if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
 o0OooO = ( mc . group . is_null ( ) == False )
 if ( o0OooO ) :
  oOOoO0oO0oo0O [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  oOOoO0oO0oo0O [ "rles" ] = [ ]
 else :
  oOOoO0oO0oo0O [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  oOOoO0oO0oo0O [ "rlocs" ] = [ ]
  if 35 - 35: II111iiii
 oOOoO0oO0oo0O [ "instance-id" ] = str ( mc . eid . instance_id )
 if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
 if ( o0OooO ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for o0Ii11I in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    IiIIiiI = o0Ii11I . address . print_address_no_iid ( )
    IiO0o = str ( 4341 ) if o0Ii11I . translated_port == 0 else str ( o0Ii11I . translated_port )
    if 96 - 96: O0
    iiiI1I = { "rle" : IiIIiiI , "port" : IiO0o }
    OooOo0o , iii = o0Ii11I . get_encap_keys ( )
    iiiI1I = lisp_build_json_keys ( iiiI1I , OooOo0o , iii , "encrypt-key" )
    oOOoO0oO0oo0O [ "rles" ] . append ( iiiI1I )
    if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
    if 11 - 11: I1IiiI % Ii1I * i11iIiiIii % OOooOOo + II111iiii
 else :
  for IIIi1iI1 in mc . rloc_set :
   if ( IIIi1iI1 . rloc . is_ipv4 ( ) == False and IIIi1iI1 . rloc . is_ipv6 ( ) == False ) :
    continue
    if 61 - 61: I1Ii111 + I11i + I1IiiI
   if ( IIIi1iI1 . up_state ( ) == False ) : continue
   if 48 - 48: I11i
   IiO0o = str ( 4341 ) if IIIi1iI1 . translated_port == 0 else str ( IIIi1iI1 . translated_port )
   if 67 - 67: o0oOOo0O0Ooo
   iiiI1I = { "rloc" : IIIi1iI1 . rloc . print_address_no_iid ( ) , "priority" :
 str ( IIIi1iI1 . priority ) , "weight" : str ( IIIi1iI1 . weight ) , "port" :
 IiO0o }
   OooOo0o , iii = IIIi1iI1 . get_encap_keys ( )
   iiiI1I = lisp_build_json_keys ( iiiI1I , OooOo0o , iii , "encrypt-key" )
   oOOoO0oO0oo0O [ "rlocs" ] . append ( iiiI1I )
   if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
   if 61 - 61: i11iIiiIii / Ii1I - OOooOOo . I1ii11iIi11i
   if 89 - 89: ooOoO0o % i11iIiiIii
 if ( dont_send == False ) : lisp_write_to_dp_socket ( oOOoO0oO0oo0O )
 return ( oOOoO0oO0oo0O )
 if 57 - 57: Oo0Ooo / ooOoO0o - O0 . ooOoO0o
 if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
 if 75 - 75: Ii1I
 if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
 if 99 - 99: oO0o + I11i % i1IIi . iII111i
 if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
 if 65 - 65: OoO0O00
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
 if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
 if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
 if 74 - 74: OoOoOO00 + I1ii11iIi11i
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 82 - 82: II111iiii
 OooOo0o = keys [ 1 ] . encrypt_key
 iii = keys [ 1 ] . icv_key
 if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
 if 48 - 48: ooOoO0o + Oo0Ooo / Oo0Ooo
 if 15 - 15: iIii1I11I1II1 . I1Ii111 * OoooooooOO * O0 % OOooOOo
 if 53 - 53: Ii1I
 o0OO0ooooO = rloc_addr . split ( ":" )
 if ( len ( o0OO0ooooO ) == 1 ) :
  oOOoO0oO0oo0O = { "type" : "decap-keys" , "rloc" : o0OO0ooooO [ 0 ] }
 else :
  oOOoO0oO0oo0O = { "type" : "decap-keys" , "rloc" : o0OO0ooooO [ 0 ] , "port" : o0OO0ooooO [ 1 ] }
  if 19 - 19: iII111i * i1IIi - I11i + O0 % Ii1I - OoOoOO00
 oOOoO0oO0oo0O = lisp_build_json_keys ( oOOoO0oO0oo0O , OooOo0o , iii , "decrypt-key" )
 if 1 - 1: I11i * Oo0Ooo
 lisp_write_to_dp_socket ( oOOoO0oO0oo0O )
 return
 if 53 - 53: II111iiii / i1IIi + OoooooooOO * O0
 if 62 - 62: IiII . O0
 if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
 if 91 - 91: OOooOOo % oO0o . OoOoOO00 . I1IiiI - OoOoOO00
 if 18 - 18: O0 - I1IiiI + i1IIi % i11iIiiIii
 if 97 - 97: iII111i * OoooooooOO + I1Ii111 + ooOoO0o - ooOoO0o
 if 63 - 63: o0oOOo0O0Ooo * OOooOOo + iIii1I11I1II1 + Oo0Ooo
 if 25 - 25: oO0o + IiII % o0oOOo0O0Ooo
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 24 - 24: OoOoOO00
 entry [ "keys" ] = [ ]
 OO0Oo00o0o0 = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( OO0Oo00o0o0 )
 return ( entry )
 if 87 - 87: I1ii11iIi11i / ooOoO0o * i1IIi
 if 71 - 71: OoOoOO00 - I11i
 if 83 - 83: oO0o + oO0o - Oo0Ooo . Oo0Ooo - iII111i . OOooOOo
 if 56 - 56: OoOoOO00 * IiII + i1IIi
 if 40 - 40: I1ii11iIi11i / O0
 if 87 - 87: ooOoO0o
 if 100 - 100: iII111i + II111iiii * Oo0Ooo * OOooOOo
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 6 - 6: IiII % OOooOOo
 if 3 - 3: OoOoOO00 / OoOoOO00 - II111iiii
 if 41 - 41: oO0o
 if 12 - 12: I1IiiI + I1Ii111
 oOOoO0oO0oo0O = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
 if 74 - 74: O0 % OOooOOo * OoOoOO00 / oO0o - Oo0Ooo
 if 79 - 79: Ii1I + IiII
 if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
 for oooOOoO0oo0 in lisp_db_list :
  if ( oooOOoO0oo0 . eid . is_ipv4 ( ) == False and oooOOoO0oo0 . eid . is_ipv6 ( ) == False ) : continue
  oOOo00o0 = { "instance-id" : str ( oooOOoO0oo0 . eid . instance_id ) ,
 "eid-prefix" : oooOOoO0oo0 . eid . print_prefix_no_iid ( ) }
  oOOoO0oO0oo0O [ "database-mappings" ] . append ( oOOo00o0 )
  if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
 lisp_write_to_dp_socket ( oOOoO0oO0oo0O )
 if 21 - 21: Ii1I
 if 72 - 72: I1Ii111 . OoooooooOO / I1Ii111 - Ii1I / I1ii11iIi11i * I1ii11iIi11i
 if 72 - 72: IiII . Ii1I + OoooooooOO * OoOoOO00 + Oo0Ooo . iII111i
 if 92 - 92: O0 * Ii1I - I1ii11iIi11i - IiII . OoO0O00 + I1IiiI
 if 59 - 59: i1IIi * OOooOOo % Oo0Ooo
 oOOoO0oO0oo0O = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( oOOoO0oO0oo0O )
 return
 if 44 - 44: iIii1I11I1II1 . OOooOOo
 if 57 - 57: II111iiii + I1Ii111
 if 42 - 42: OoOoOO00 % O0
 if 70 - 70: iIii1I11I1II1 * Oo0Ooo - I1IiiI / OoO0O00 + OoOoOO00
 if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
 if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
 if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
 if 26 - 26: Ii1I * I11i / I11i
 if 79 - 79: ooOoO0o / oO0o - oO0o / OoooooooOO
 if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
 oOOoO0oO0oo0O = { "type" : "interfaces" , "interfaces" : [ ] }
 if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
 for iI1ii1iI1 in lisp_myinterfaces . values ( ) :
  if ( iI1ii1iI1 . instance_id == None ) : continue
  oOOo00o0 = { "interface" : iI1ii1iI1 . device ,
 "instance-id" : str ( iI1ii1iI1 . instance_id ) }
  oOOoO0oO0oo0O [ "interfaces" ] . append ( oOOo00o0 )
  if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
  if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
 lisp_write_to_dp_socket ( oOOoO0oO0oo0O )
 return
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
 if 57 - 57: i1IIi
 if 41 - 41: I11i / Ii1I
def lisp_parse_auth_key ( value ) :
 OOO = value . split ( "[" )
 ii11i = { }
 if ( len ( OOO ) == 1 ) :
  ii11i [ 0 ] = value
  return ( ii11i )
  if 23 - 23: I1ii11iIi11i % I11i % I1Ii111
  if 13 - 13: I1IiiI + I1ii11iIi11i % ooOoO0o - O0
 for i1i11i in OOO :
  if ( i1i11i == "" ) : continue
  I1i11II = i1i11i . find ( "]" )
  I1IIiiiiI1iIi = i1i11i [ 0 : I1i11II ]
  try : I1IIiiiiI1iIi = int ( I1IIiiiiI1iIi )
  except : return
  if 44 - 44: I1IiiI / OoO0O00 - II111iiii - OoOoOO00
  ii11i [ I1IIiiiiI1iIi ] = i1i11i [ I1i11II + 1 : : ]
  if 12 - 12: I11i - iII111i % IiII
 return ( ii11i )
 if 36 - 36: OoOoOO00 . II111iiii / I11i
 if 46 - 46: OoOoOO00
 if 56 - 56: iIii1I11I1II1 - iIii1I11I1II1
 if 46 - 46: o0oOOo0O0Ooo
 if 67 - 67: OOooOOo - i11iIiiIii / oO0o * i11iIiiIii
 if 88 - 88: Ii1I - OoO0O00 * OoooooooOO - I1IiiI * I1ii11iIi11i
 if 52 - 52: oO0o % iII111i - I1IiiI - o0oOOo0O0Ooo
 if 66 - 66: o0oOOo0O0Ooo - Oo0Ooo - OoooooooOO * o0oOOo0O0Ooo + I1Ii111
 if 82 - 82: I11i * i1IIi / Ii1I + O0
 if 85 - 85: O0 + oO0o / I1Ii111
 if 65 - 65: o0oOOo0O0Ooo . Oo0Ooo . i1IIi / IiII . I11i . O0
 if 69 - 69: Oo0Ooo - i11iIiiIii
 if 87 - 87: Oo0Ooo % OOooOOo - Ii1I
 if 34 - 34: iII111i / Ii1I / I1IiiI * i11iIiiIii
 if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
 if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
def lisp_reassemble ( packet ) :
 OoooOO0 = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 71 - 71: oO0o
 if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
 if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
 if 16 - 16: I1Ii111 + O0 - O0 * iIii1I11I1II1 / iII111i
 if ( OoooOO0 == 0 or OoooOO0 == 0x4000 ) : return ( packet )
 if 4 - 4: iII111i
 if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
 if 32 - 32: iII111i
 if 59 - 59: OoOoOO00 - I1Ii111
 OOoo0 = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 IIiii1iii1II = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 34 - 34: ooOoO0o . OoooooooOO / ooOoO0o + OoooooooOO
 IiiIii1IiI1ii = ( OoooOO0 & 0x2000 == 0 and ( OoooOO0 & 0x1fff ) != 0 )
 oOOoO0oO0oo0O = [ ( OoooOO0 & 0x1fff ) * 8 , IIiii1iii1II - 20 , packet , IiiIii1IiI1ii ]
 if 78 - 78: Oo0Ooo / Ii1I
 if 74 - 74: OOooOOo . II111iiii - i11iIiiIii / OoooooooOO + OoOoOO00 * ooOoO0o
 if 63 - 63: OoO0O00
 if 66 - 66: iIii1I11I1II1
 if 98 - 98: iII111i . oO0o % I1Ii111 + Oo0Ooo
 if 83 - 83: Oo0Ooo % oO0o - iII111i
 if 49 - 49: oO0o / OoooooooOO . OoooooooOO
 if 1 - 1: I1IiiI - O0
 if ( OoooOO0 == 0x2000 ) :
  IiIi , IiiI1iii1iIiiI = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  IiIi = socket . ntohs ( IiIi )
  IiiI1iii1iIiiI = socket . ntohs ( IiiI1iii1iIiiI )
  if ( IiiI1iii1iIiiI not in [ 4341 , 8472 , 4789 ] and IiIi != 4341 ) :
   lisp_reassembly_queue [ OOoo0 ] = [ ]
   oOOoO0oO0oo0O [ 2 ] = None
   if 98 - 98: i11iIiiIii
   if 52 - 52: iIii1I11I1II1 - OoO0O00 * Ii1I - i11iIiiIii
   if 88 - 88: o0oOOo0O0Ooo - I1IiiI / I1IiiI
   if 54 - 54: i1IIi + IiII . iIii1I11I1II1 + O0 * IiII - OOooOOo
   if 41 - 41: ooOoO0o . O0 * iII111i / iIii1I11I1II1 * OOooOOo . II111iiii
   if 92 - 92: I1ii11iIi11i / I1ii11iIi11i . o0oOOo0O0Ooo + OoooooooOO . II111iiii
 if ( lisp_reassembly_queue . has_key ( OOoo0 ) == False ) :
  lisp_reassembly_queue [ OOoo0 ] = [ ]
  if 60 - 60: oO0o / OoOoOO00 % I1ii11iIi11i . ooOoO0o + iII111i - iIii1I11I1II1
  if 20 - 20: o0oOOo0O0Ooo . IiII / ooOoO0o / o0oOOo0O0Ooo - OoooooooOO / oO0o
  if 40 - 40: OOooOOo * OoO0O00
  if 21 - 21: oO0o
  if 30 - 30: I1ii11iIi11i . O0 . Oo0Ooo
 queue = lisp_reassembly_queue [ OOoo0 ]
 if 23 - 23: i11iIiiIii / I11i + i1IIi % I1Ii111
 if 100 - 100: Oo0Ooo
 if 13 - 13: I1IiiI + ooOoO0o * II111iiii
 if 32 - 32: iIii1I11I1II1 + O0 + i1IIi
 if 28 - 28: IiII + I11i
 if ( len ( queue ) == 1 and queue [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( OOoo0 ) . zfill ( 4 ) ) )
  if 1 - 1: OoooooooOO - i11iIiiIii . OoooooooOO - o0oOOo0O0Ooo - OOooOOo * I1Ii111
  return ( None )
  if 56 - 56: Ii1I . OoO0O00
  if 43 - 43: iII111i * iII111i
  if 31 - 31: O0 - iIii1I11I1II1 . I11i . oO0o
  if 96 - 96: OoooooooOO * iIii1I11I1II1 * Oo0Ooo
  if 76 - 76: OoO0O00 / i11iIiiIii % ooOoO0o % I11i * O0
 queue . append ( oOOoO0oO0oo0O )
 queue = sorted ( queue )
 if 84 - 84: II111iiii - iII111i / IiII . O0 % i1IIi / I1ii11iIi11i
 if 2 - 2: OoooooooOO . OoO0O00 . II111iiii / Ii1I - OOooOOo % Oo0Ooo
 if 47 - 47: OOooOOo * oO0o
 if 41 - 41: OoooooooOO * I1IiiI
 IiIIiiI = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 IiIIiiI . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 i1II1II11iII = IiIIiiI . print_address_no_iid ( )
 IiIIiiI . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 ooo0OOOo = IiIIiiI . print_address_no_iid ( )
 IiIIiiI = red ( "{} -> {}" . format ( i1II1II11iII , ooo0OOOo ) , False )
 if 32 - 32: Ii1I - Ii1I / i11iIiiIii
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if oOOoO0oO0oo0O [ 2 ] == None else "" , IiIIiiI , lisp_hex_string ( OOoo0 ) . zfill ( 4 ) ,
 # OOooOOo * IiII . OoooooooOO
 # Ii1I
 lisp_hex_string ( OoooOO0 ) . zfill ( 4 ) ) )
 if 7 - 7: oO0o % iIii1I11I1II1
 if 89 - 89: I11i + I11i * OoooooooOO + IiII % iIii1I11I1II1
 if 52 - 52: i1IIi
 if 85 - 85: I1Ii111 - iII111i
 if 44 - 44: I11i - I11i - IiII . I11i
 if ( queue [ 0 ] [ 0 ] != 0 or queue [ - 1 ] [ 3 ] == False ) : return ( None )
 Ii1I1iIi = queue [ 0 ]
 for oOOo00O0O0 in queue [ 1 : : ] :
  OoooOO0 = oOOo00O0O0 [ 0 ]
  Ii1Iii , O0ooo0 = Ii1I1iIi [ 0 ] , Ii1I1iIi [ 1 ]
  if ( Ii1Iii + O0ooo0 != OoooOO0 ) : return ( None )
  Ii1I1iIi = oOOo00O0O0
  if 1 - 1: I1ii11iIi11i + iII111i
 lisp_reassembly_queue . pop ( OOoo0 )
 if 61 - 61: oO0o - OOooOOo % II111iiii + IiII + O0 / o0oOOo0O0Ooo
 if 78 - 78: I11i
 if 32 - 32: II111iiii / II111iiii + o0oOOo0O0Ooo + OoooooooOO
 if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
 if 87 - 87: OOooOOo * OoO0O00
 packet = queue [ 0 ] [ 2 ]
 for oOOo00O0O0 in queue [ 1 : : ] : packet += oOOo00O0O0 [ 2 ] [ 20 : : ]
 if 61 - 61: iII111i - II111iiii . I1Ii111 % II111iiii / I11i
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( OOoo0 ) . zfill ( 4 ) , len ( packet ) ) )
 if 86 - 86: II111iiii
 if 94 - 94: o0oOOo0O0Ooo % Ii1I * Ii1I % Oo0Ooo / I1ii11iIi11i
 if 40 - 40: Oo0Ooo . II111iiii / II111iiii - i1IIi
 if 91 - 91: Ii1I
 if 45 - 45: I1ii11iIi11i + Oo0Ooo
 i1iIii = socket . htons ( len ( packet ) )
 OoOOoo0o00O0oO = packet [ 0 : 2 ] + struct . pack ( "H" , i1iIii ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 72 - 72: I1ii11iIi11i
 if 5 - 5: i1IIi
 OoOOoo0o00O0oO = lisp_ip_checksum ( OoOOoo0o00O0oO )
 return ( OoOOoo0o00O0oO + packet [ 20 : : ] )
 if 31 - 31: iII111i - OoooooooOO + oO0o / OoooooooOO + I1ii11iIi11i
 if 93 - 93: o0oOOo0O0Ooo * I1ii11iIi11i % I1IiiI * ooOoO0o
 if 37 - 37: OoO0O00 * OoooooooOO / oO0o * I11i * I1ii11iIi11i
 if 42 - 42: OoooooooOO - ooOoO0o . OOooOOo + OoOoOO00
 if 53 - 53: o0oOOo0O0Ooo
 if 55 - 55: ooOoO0o . i1IIi - ooOoO0o + O0 + I1IiiI
 if 31 - 31: OoO0O00 % I1Ii111
 if 62 - 62: oO0o / O0 - I1Ii111 . IiII
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 O0O0 = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( O0O0 ) ) : return ( O0O0 )
 if 81 - 81: i11iIiiIii
 O0O0 = addr . print_address_no_iid ( )
 if ( lisp_crypto_keys_by_rloc_decap . has_key ( O0O0 ) ) : return ( O0O0 )
 if 57 - 57: O0
 if 85 - 85: i11iIiiIii - i11iIiiIii - OoOoOO00 / II111iiii - II111iiii
 if 4 - 4: I1ii11iIi11i * O0 / OoO0O00 * II111iiii . iIii1I11I1II1 / OOooOOo
 if 97 - 97: i1IIi - OoOoOO00 . OoooooooOO
 if 24 - 24: iIii1I11I1II1 + OOooOOo * iII111i % IiII % OOooOOo
 for O0OOO0o00o0 in lisp_crypto_keys_by_rloc_decap :
  OoOOOO = O0OOO0o00o0 . split ( ":" )
  if ( len ( OoOOOO ) == 1 ) : continue
  OoOOOO = OoOOOO [ 0 ] if len ( OoOOOO ) == 2 else ":" . join ( OoOOOO [ 0 : - 1 ] )
  if ( OoOOOO == O0O0 ) :
   IiI11I1iiii1 = lisp_crypto_keys_by_rloc_decap [ O0OOO0o00o0 ]
   lisp_crypto_keys_by_rloc_decap [ O0O0 ] = IiI11I1iiii1
   return ( O0O0 )
   if 44 - 44: ooOoO0o + o0oOOo0O0Ooo % OoOoOO00 + I1IiiI
   if 96 - 96: O0 % Ii1I / I1ii11iIi11i + I1ii11iIi11i - OoO0O00 / oO0o
 return ( None )
 if 41 - 41: Ii1I
 if 78 - 78: OOooOOo
 if 44 - 44: i1IIi * I1ii11iIi11i % Ii1I . Ii1I * I11i + II111iiii
 if 15 - 15: i1IIi - I11i - I1Ii111 / OoO0O00 + Oo0Ooo + I1IiiI
 if 81 - 81: IiII
 if 54 - 54: I1IiiI % OoO0O00 % OoOoOO00
 if 12 - 12: II111iiii . O0 * i11iIiiIii . I11i
 if 98 - 98: II111iiii + i1IIi * oO0o % I1IiiI
 if 53 - 53: i11iIiiIii . I1ii11iIi11i - OOooOOo - OOooOOo
 if 97 - 97: I1IiiI % iII111i % OoooooooOO / ooOoO0o / i11iIiiIii
 if 7 - 7: O0 % IiII / o0oOOo0O0Ooo
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 o00O0O0 = addr + ":" + str ( port )
 if 2 - 2: ooOoO0o / IiII * oO0o . I1ii11iIi11i
 if ( lisp_i_am_rtr ) :
  if ( lisp_rloc_probe_list . has_key ( addr ) ) : return ( addr )
  if 51 - 51: Oo0Ooo * II111iiii + Oo0Ooo . Ii1I * OoooooooOO
  if 20 - 20: o0oOOo0O0Ooo . ooOoO0o
  if 67 - 67: I1ii11iIi11i
  if 14 - 14: OoOoOO00 . i1IIi + Oo0Ooo / O0 - IiII
  if 80 - 80: I1IiiI + ooOoO0o
  if 43 - 43: OoooooooOO * iIii1I11I1II1
  for I1OOoO0OoOOo0 in lisp_nat_state_info . values ( ) :
   for I1i11ioOoO0 in I1OOoO0OoOOo0 :
    if ( addr == I1i11ioOoO0 . address ) : return ( o00O0O0 )
    if 82 - 82: i1IIi - I11i % ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo
    if 20 - 20: i11iIiiIii - O0 / i11iIiiIii
  return ( addr )
  if 51 - 51: iII111i . ooOoO0o
 return ( o00O0O0 )
 if 70 - 70: I11i / O0 - I11i + o0oOOo0O0Ooo . ooOoO0o . o0oOOo0O0Ooo
 if 6 - 6: I11i + II111iiii - I1Ii111
 if 45 - 45: i1IIi / iII111i + i11iIiiIii * I11i + ooOoO0o / OoooooooOO
 if 56 - 56: I11i + I1Ii111
 if 80 - 80: II111iiii . Ii1I + o0oOOo0O0Ooo / II111iiii / OoO0O00 + iIii1I11I1II1
 if 29 - 29: o0oOOo0O0Ooo + OoOoOO00 + ooOoO0o - I1ii11iIi11i
 if 64 - 64: O0 / OoooooooOO
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_MULTICAST_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 28 - 28: I1ii11iIi11i + oO0o . Oo0Ooo % iIii1I11I1II1 / I1Ii111
 return
 if 8 - 8: O0 . I1IiiI * o0oOOo0O0Ooo + I1IiiI
 if 44 - 44: i1IIi % iII111i . i11iIiiIii / I11i + OoooooooOO
 if 21 - 21: OoOoOO00 . OoO0O00 . OoOoOO00 + OoOoOO00
 if 30 - 30: I1IiiI - iII111i - OOooOOo + oO0o
 if 51 - 51: Ii1I % O0 / II111iiii . Oo0Ooo
 if 90 - 90: i11iIiiIii * II111iiii % iIii1I11I1II1 . I1ii11iIi11i / Oo0Ooo . OOooOOo
 if 77 - 77: OoO0O00
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 95 - 95: II111iiii
 if 59 - 59: iIii1I11I1II1 % OOooOOo / OoOoOO00 * I1Ii111 * OoooooooOO * O0
 if 43 - 43: OoO0O00 * I1IiiI * OOooOOo * O0 - O0 / o0oOOo0O0Ooo
 if 77 - 77: I11i % I1Ii111 . IiII % OoooooooOO * o0oOOo0O0Ooo
 if 87 - 87: iII111i + IiII / ooOoO0o * ooOoO0o * OOooOOo
 if 97 - 97: I1Ii111
 if 47 - 47: iII111i / I1ii11iIi11i - Ii1I . II111iiii
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 56 - 56: O0 - i1IIi % o0oOOo0O0Ooo + IiII
 if 42 - 42: o0oOOo0O0Ooo . OOooOOo % I11i - OoOoOO00
 if 38 - 38: OoooooooOO
 if 27 - 27: O0 + I1ii11iIi11i % Ii1I . i1IIi + OoO0O00 + OoOoOO00
 if 22 - 22: II111iiii / I1IiiI + o0oOOo0O0Ooo * I1IiiI . OoooooooOO * OOooOOo
 if 49 - 49: I1ii11iIi11i * I1IiiI + OOooOOo + i11iIiiIii * I1ii11iIi11i . o0oOOo0O0Ooo
 if 36 - 36: o0oOOo0O0Ooo - i11iIiiIii
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
def lisp_is_rloc_probe ( packet , rr ) :
 O0I1II1 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( O0I1II1 == False ) : return ( [ packet , None , None , None ] )
 if 85 - 85: I1ii11iIi11i / IiII + oO0o
 IiIi = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 IiiI1iii1iIiiI = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 o0O = ( socket . htons ( LISP_CTRL_PORT ) in [ IiIi , IiiI1iii1iIiiI ] )
 if ( o0O == False ) : return ( [ packet , None , None , None ] )
 if 36 - 36: IiII % Ii1I - OoOoOO00 + OoO0O00 + IiII * Ii1I
 if ( rr == 0 ) :
  OoO0oo0O = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( OoO0oo0O == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  OoO0oo0O = lisp_is_rloc_probe_reply ( packet [ 28 ] )
  if ( OoO0oo0O == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  OoO0oo0O = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( OoO0oo0O == False ) :
   OoO0oo0O = lisp_is_rloc_probe_reply ( packet [ 28 ] )
   if ( OoO0oo0O == False ) : return ( [ packet , None , None , None ] )
   if 15 - 15: I1IiiI / O0 % I1ii11iIi11i % OoOoOO00 . OoOoOO00 + iII111i
   if 79 - 79: OOooOOo + Ii1I . I1Ii111 / Oo0Ooo / i11iIiiIii / O0
   if 28 - 28: i1IIi % OoO0O00 / i1IIi - o0oOOo0O0Ooo
   if 97 - 97: II111iiii + O0 . Ii1I + OoooooooOO
   if 39 - 39: i11iIiiIii + OoO0O00 + I11i * oO0o + iIii1I11I1II1 % o0oOOo0O0Ooo
   if 25 - 25: OoooooooOO
 iIiI111ii1Ii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 iIiI111ii1Ii . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 78 - 78: oO0o / i11iIiiIii * O0 / OOooOOo % i11iIiiIii % O0
 if 86 - 86: IiII
 if 26 - 26: IiII - I1Ii111 + i11iIiiIii % ooOoO0o * i11iIiiIii + Oo0Ooo
 if 39 - 39: Ii1I - i1IIi + i11iIiiIii
 if ( iIiI111ii1Ii . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 21 - 21: IiII
 if 76 - 76: o0oOOo0O0Ooo % Oo0Ooo + OoO0O00
 if 36 - 36: OOooOOo . oO0o
 if 15 - 15: I1IiiI + ooOoO0o - o0oOOo0O0Ooo
 iIiI111ii1Ii = iIiI111ii1Ii . print_address_no_iid ( )
 IiO0o = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 O0OOo = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 62 - 62: Ii1I - OOooOOo
 iiiI1I = bold ( "Receive(pcap)" , False )
 III1I = bold ( "from " + iIiI111ii1Ii , False )
 IIIiIIi111 = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( iiiI1I , len ( packet ) , III1I , IiO0o , IIIiIIi111 ) )
 if 88 - 88: iIii1I11I1II1 * Oo0Ooo / II111iiii / IiII / OoO0O00 % ooOoO0o
 return ( [ packet , iIiI111ii1Ii , IiO0o , O0OOo ] )
 if 19 - 19: I11i * iII111i . O0 * iII111i % I1ii11iIi11i - OoOoOO00
 if 68 - 68: I1Ii111 - OoO0O00 % Ii1I + i1IIi . ooOoO0o
 if 36 - 36: oO0o * iIii1I11I1II1 - O0 - IiII * O0 + i11iIiiIii
 if 76 - 76: OoO0O00 % O0 / Ii1I + I1IiiI
 if 23 - 23: I1IiiI % IiII . o0oOOo0O0Ooo
 if 2 - 2: I1ii11iIi11i
 if 51 - 51: iIii1I11I1II1 / II111iiii / iIii1I11I1II1 / oO0o % i1IIi
 if 54 - 54: ooOoO0o
 if 47 - 47: I11i * I1IiiI / oO0o
 if 98 - 98: Ii1I / oO0o * O0 + I1Ii111 - I1Ii111 + iII111i
 if 4 - 4: i1IIi
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 43 - 43: oO0o * ooOoO0o - I11i
 Oo0O = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 70 - 70: oO0o / Ii1I
 lisp_write_to_dp_socket ( Oo0O )
 return
 if 15 - 15: iIii1I11I1II1 % ooOoO0o % i11iIiiIii
 if 16 - 16: iII111i
 if 50 - 50: iIii1I11I1II1 - II111iiii % i1IIi
 if 48 - 48: O0
 if 60 - 60: ooOoO0o - IiII % i1IIi
 if 5 - 5: oO0o
 if 29 - 29: i1IIi . OoOoOO00 . i1IIi + oO0o . I1Ii111 + O0
 if 62 - 62: I1ii11iIi11i . IiII + OoO0O00 - OoOoOO00 * O0 + I1Ii111
def lisp_external_data_plane ( ) :
 ii1iI1i = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( getoutput ( ii1iI1i ) != "" ) : return ( True )
 if 58 - 58: oO0o . OoO0O00 / ooOoO0o
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 61 - 61: I11i + I1Ii111
 if 27 - 27: ooOoO0o / i1IIi . oO0o - OoooooooOO
 if 48 - 48: ooOoO0o % ooOoO0o / OoooooooOO + i1IIi * oO0o + ooOoO0o
 if 69 - 69: iII111i . iII111i
 if 46 - 46: IiII * Oo0Ooo + I1Ii111
 if 79 - 79: IiII
 if 89 - 89: IiII * I11i + I1ii11iIi11i * oO0o - II111iiii
 if 58 - 58: ooOoO0o . I1Ii111 / i1IIi % I1ii11iIi11i + o0oOOo0O0Ooo
 if 94 - 94: i11iIiiIii + I1Ii111 . iII111i - ooOoO0o % I1Ii111
 if 94 - 94: i11iIiiIii - OOooOOo - O0 * OoooooooOO - ooOoO0o
 if 35 - 35: iII111i . i11iIiiIii - OOooOOo % Oo0Ooo + Ii1I . iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo / OoO0O00 + I1IiiI % i11iIiiIii % i1IIi
 if 22 - 22: I1Ii111 * O0 % OoO0O00 * I1ii11iIi11i
 if 47 - 47: OoO0O00 / OOooOOo / OoOoOO00 % i11iIiiIii / OoOoOO00
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 52 - 52: ooOoO0o / I11i % i11iIiiIii - I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
 OOO0 = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 63 - 63: IiII
 if ( do_clear == False ) :
  o0O0O0OoO = OOO0 [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , o0O0O0OoO )
  if 92 - 92: O0
  if 52 - 52: iII111i - i11iIiiIii + o0oOOo0O0Ooo + i1IIi
 lisp_write_to_dp_socket ( OOO0 )
 return
 if 58 - 58: OOooOOo - Ii1I * I1Ii111 - O0 . oO0o
 if 72 - 72: i1IIi * iII111i * Ii1I / o0oOOo0O0Ooo . I1Ii111 + i11iIiiIii
 if 33 - 33: I11i / OoO0O00 * ooOoO0o + iIii1I11I1II1
 if 54 - 54: Oo0Ooo / IiII + i11iIiiIii . O0
 if 94 - 94: OoooooooOO + iII111i * OoooooooOO / o0oOOo0O0Ooo
 if 12 - 12: iIii1I11I1II1 / iIii1I11I1II1 / II111iiii
 if 93 - 93: oO0o
 if 53 - 53: OoO0O00 * i1IIi / Oo0Ooo / OoO0O00 * ooOoO0o
 if 77 - 77: iIii1I11I1II1 % I1IiiI + o0oOOo0O0Ooo + I1Ii111 * Oo0Ooo * i1IIi
 if 14 - 14: iIii1I11I1II1 * iIii1I11I1II1 - OOooOOo . iII111i / ooOoO0o
 if 54 - 54: OoOoOO00 - I1IiiI - iII111i
 if 49 - 49: i11iIiiIii * Oo0Ooo
 if 100 - 100: Oo0Ooo * oO0o
 if 85 - 85: OoooooooOO . IiII / IiII . ooOoO0o . IiII % II111iiii
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( msg . has_key ( "entries" ) == False ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 65 - 65: oO0o - OoO0O00 / iII111i + ooOoO0o
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 80 - 80: o0oOOo0O0Ooo + II111iiii * Ii1I % OoOoOO00 % I1IiiI + I1ii11iIi11i
  if 46 - 46: Oo0Ooo / Oo0Ooo % iII111i % I1IiiI
 for msg in msg [ "entries" ] :
  if ( msg . has_key ( "eid-prefix" ) == False ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 85 - 85: OoO0O00 - Ii1I / O0
  iIiI1I1ii1I1 = msg [ "eid-prefix" ]
  if 45 - 45: IiII + I1Ii111 / I11i
  if ( msg . has_key ( "instance-id" ) == False ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 84 - 84: iII111i % II111iiii
  i1 = int ( msg [ "instance-id" ] )
  if 86 - 86: IiII % II111iiii / i1IIi * I1ii11iIi11i - O0 * OOooOOo
  if 53 - 53: OOooOOo * oO0o + i1IIi % Oo0Ooo + II111iiii
  if 34 - 34: oO0o % iII111i / IiII . IiII + i11iIiiIii
  if 68 - 68: O0 % oO0o * IiII % O0
  oOooOOo000o0o = lisp_address ( LISP_AFI_NONE , "" , 0 , i1 )
  oOooOOo000o0o . store_prefix ( iIiI1I1ii1I1 )
  ooOoOO0Oo = lisp_map_cache_lookup ( None , oOooOOo000o0o )
  if ( ooOoOO0Oo == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( iIiI1I1ii1I1 ) )
   if 55 - 55: O0 % I1IiiI % O0
   continue
   if 27 - 27: I1IiiI + I1ii11iIi11i * I1Ii111 % Ii1I - Oo0Ooo
   if 87 - 87: i11iIiiIii % OOooOOo - OoOoOO00 * ooOoO0o / Oo0Ooo
  if ( msg . has_key ( "rlocs" ) == False ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( iIiI1I1ii1I1 ) )
   if 74 - 74: OoooooooOO * ooOoO0o - I11i / I1ii11iIi11i % iIii1I11I1II1
   continue
   if 94 - 94: Ii1I * I1Ii111 + OoOoOO00 . iIii1I11I1II1
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 44 - 44: Oo0Ooo . Oo0Ooo * Oo0Ooo
  I1i11iIi1ii111 = msg [ "rlocs" ]
  if 76 - 76: I1Ii111 - i11iIiiIii
  if 88 - 88: I1ii11iIi11i + OoOoOO00 % OoOoOO00 * Oo0Ooo - iIii1I11I1II1
  if 58 - 58: I1Ii111 - ooOoO0o % OOooOOo + OOooOOo % I1Ii111 . Ii1I
  if 33 - 33: OoOoOO00
  for OO0o00O in I1i11iIi1ii111 :
   if ( OO0o00O . has_key ( "rloc" ) == False ) : continue
   if 18 - 18: i11iIiiIii . Ii1I % I1ii11iIi11i - OoooooooOO . I1ii11iIi11i
   iI = OO0o00O [ "rloc" ]
   if ( iI == "no-address" ) : continue
   if 19 - 19: iII111i + I1IiiI
   IIIi1iI1 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   IIIi1iI1 . store_address ( iI )
   if 71 - 71: iII111i % o0oOOo0O0Ooo
   O0O0OOo0O = ooOoOO0Oo . get_rloc ( IIIi1iI1 )
   if ( O0O0OOo0O == None ) : continue
   if 91 - 91: i11iIiiIii * iIii1I11I1II1 % oO0o . II111iiii / Ii1I + Ii1I
   if 32 - 32: OOooOOo % OOooOOo + I1ii11iIi11i / Ii1I - i11iIiiIii
   if 28 - 28: iIii1I11I1II1 - II111iiii
   if 36 - 36: ooOoO0o . II111iiii - OoOoOO00 % I1ii11iIi11i * O0
   O0oO0oO = 0 if OO0o00O . has_key ( "packet-count" ) == False else OO0o00O [ "packet-count" ]
   if 13 - 13: I11i % iIii1I11I1II1 % iII111i
   iIIiI11 = 0 if OO0o00O . has_key ( "byte-count" ) == False else OO0o00O [ "byte-count" ]
   if 92 - 92: ooOoO0o / OoO0O00 + ooOoO0o + OOooOOo * i11iIiiIii - OoO0O00
   ii1III11 = 0 if OO0o00O . has_key ( "seconds-last-packet" ) == False else OO0o00O [ "seconds-last-packet" ]
   if 1 - 1: OOooOOo . OoooooooOO / oO0o
   if 15 - 15: I11i - i1IIi
   O0O0OOo0O . stats . packet_count += O0oO0oO
   O0O0OOo0O . stats . byte_count += iIIiI11
   O0O0OOo0O . stats . last_increment = lisp_get_timestamp ( ) - ii1III11
   if 15 - 15: ooOoO0o % I1Ii111 * OoooooooOO % IiII + I1ii11iIi11i - Ii1I
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( O0oO0oO , iIIiI11 ,
 ii1III11 , iIiI1I1ii1I1 , iI ) )
   if 67 - 67: i1IIi % I1ii11iIi11i * OOooOOo . Oo0Ooo
   if 82 - 82: iII111i . O0 / Oo0Ooo / OoooooooOO
   if 68 - 68: OoooooooOO . iIii1I11I1II1 / iII111i / OOooOOo
   if 35 - 35: I1ii11iIi11i * I11i % o0oOOo0O0Ooo + i1IIi % iII111i / IiII
   if 41 - 41: IiII . OOooOOo % ooOoO0o
  if ( ooOoOO0Oo . group . is_null ( ) and ooOoOO0Oo . has_ttl_elapsed ( ) ) :
   iIiI1I1ii1I1 = green ( ooOoOO0Oo . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( iIiI1I1ii1I1 ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , ooOoOO0Oo . eid , None )
   if 25 - 25: i1IIi - OoO0O00
   if 54 - 54: OOooOOo + oO0o + OoO0O00 . OoO0O00
 return
 if 29 - 29: OOooOOo / IiII * OOooOOo + II111iiii . oO0o * o0oOOo0O0Ooo
 if 37 - 37: I1Ii111 . oO0o * IiII
 if 41 - 41: I1Ii111 - iIii1I11I1II1 + Oo0Ooo
 if 56 - 56: IiII - I1ii11iIi11i - I1ii11iIi11i . I1Ii111
 if 55 - 55: OoO0O00
 if 11 - 11: OoooooooOO - I1IiiI . I1IiiI % o0oOOo0O0Ooo
 if 56 - 56: I1Ii111
 if 23 - 23: ooOoO0o . I11i - OOooOOo
 if 40 - 40: OoOoOO00
 if 44 - 44: O0 + Oo0Ooo - iII111i + iIii1I11I1II1 / i11iIiiIii * IiII
 if 49 - 49: Oo0Ooo
 if 87 - 87: I1Ii111 + iII111i / IiII / ooOoO0o * OoooooooOO / OOooOOo
 if 44 - 44: IiII . I1Ii111
 if 46 - 46: O0 - ooOoO0o . I1ii11iIi11i % oO0o / OoOoOO00
 if 93 - 93: I1ii11iIi11i * o0oOOo0O0Ooo . I11i . I1ii11iIi11i % i1IIi + Ii1I
 if 63 - 63: I1IiiI / OoooooooOO
 if 16 - 16: OoOoOO00
 if 67 - 67: O0 . I1Ii111
 if 42 - 42: OoOoOO00 % I1ii11iIi11i * I1Ii111 * i1IIi . i1IIi % OOooOOo
 if 90 - 90: oO0o * Oo0Ooo * oO0o . Ii1I * i1IIi
 if 47 - 47: OOooOOo
 if 38 - 38: I11i
 if 15 - 15: OoO0O00 / ooOoO0o . OoO0O00 - iIii1I11I1II1 + OoooooooOO - OoO0O00
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 44 - 44: O0 . OOooOOo . o0oOOo0O0Ooo . I1ii11iIi11i - II111iiii
 if 71 - 71: I1ii11iIi11i + o0oOOo0O0Ooo . i11iIiiIii * oO0o . i1IIi
 if 40 - 40: OoO0O00 - IiII
 if 43 - 43: I1Ii111 + i11iIiiIii % iII111i % I1Ii111 - ooOoO0o
 if 85 - 85: IiII % iIii1I11I1II1 . I1Ii111
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  Oo0O = "stats%{}" . format ( json . dumps ( msg ) )
  Oo0O = lisp_command_ipc ( Oo0O , "lisp-itr" )
  lisp_ipc ( Oo0O , lisp_ipc_socket , "lisp-etr" )
  return
  if 38 - 38: iII111i - I1IiiI / ooOoO0o
  if 46 - 46: OOooOOo . O0 / i11iIiiIii . OOooOOo
  if 19 - 19: I11i / Oo0Ooo + I1Ii111
  if 43 - 43: I1ii11iIi11i
  if 18 - 18: I11i / OOooOOo % I11i - o0oOOo0O0Ooo
  if 22 - 22: iII111i
  if 88 - 88: I11i + OoOoOO00 % IiII % OoO0O00 * O0 / OoooooooOO
  if 83 - 83: IiII + I1Ii111 . I1ii11iIi11i * iIii1I11I1II1
 Oo0O = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( Oo0O , msg ) )
 if 9 - 9: ooOoO0o % IiII - OoOoOO00
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 66 - 66: oO0o % Oo0Ooo
 Iio0oOoOO0 = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 95 - 95: IiII % o0oOOo0O0Ooo * I1IiiI * i1IIi
 for Iii11iii1I in Iio0oOoOO0 :
  O0oO0oO = 0 if msg . has_key ( Iii11iii1I ) == False else msg [ Iii11iii1I ] [ "packet-count" ]
  if 70 - 70: OoOoOO00 + OoOoOO00 - ooOoO0o - i1IIi * I1Ii111 % o0oOOo0O0Ooo
  lisp_decap_stats [ Iii11iii1I ] . packet_count += O0oO0oO
  if 56 - 56: i11iIiiIii * Oo0Ooo . I11i - Oo0Ooo
  iIIiI11 = 0 if msg . has_key ( Iii11iii1I ) == False else msg [ Iii11iii1I ] [ "byte-count" ]
  if 81 - 81: I1ii11iIi11i / OoooooooOO - I1ii11iIi11i . I1ii11iIi11i * OoO0O00
  lisp_decap_stats [ Iii11iii1I ] . byte_count += iIIiI11
  if 33 - 33: Oo0Ooo / OoooooooOO
  ii1III11 = 0 if msg . has_key ( Iii11iii1I ) == False else msg [ Iii11iii1I ] [ "seconds-last-packet" ]
  if 72 - 72: OOooOOo + O0 * ooOoO0o / o0oOOo0O0Ooo % OoOoOO00 - i11iIiiIii
  lisp_decap_stats [ Iii11iii1I ] . last_increment = lisp_get_timestamp ( ) - ii1III11
  if 85 - 85: iIii1I11I1II1 * o0oOOo0O0Ooo . I1Ii111
 return
 if 61 - 61: O0 * I1Ii111
 if 31 - 31: OOooOOo * oO0o % Oo0Ooo + i1IIi - I11i . OoooooooOO
 if 5 - 5: iII111i % Oo0Ooo - oO0o . i1IIi - i11iIiiIii % I1ii11iIi11i
 if 79 - 79: I1IiiI
 if 24 - 24: I1IiiI / II111iiii - I1Ii111
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
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 OO0Oo0oO , iIiI111ii1Ii = punt_socket . recvfrom ( 4000 )
 if 31 - 31: oO0o * OOooOOo % OoooooooOO . OOooOOo * Ii1I
 iiII1Ii1 = json . loads ( OO0Oo0oO )
 if ( type ( iiII1Ii1 ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( iIiI111ii1Ii ) )
  if 38 - 38: I1IiiI - Oo0Ooo + I1Ii111 % II111iiii
  return
  if 90 - 90: iIii1I11I1II1
 Oo0o = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( Oo0o , iIiI111ii1Ii , iiII1Ii1 ) )
 if 48 - 48: iII111i * IiII + OoooooooOO
 if ( iiII1Ii1 . has_key ( "type" ) == False ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 63 - 63: I1IiiI / Ii1I
  if 31 - 31: i1IIi - oO0o
  if 99 - 99: iII111i - i11iIiiIii + oO0o
  if 66 - 66: Oo0Ooo * I11i . iIii1I11I1II1 - OoO0O00
  if 11 - 11: I1Ii111 + iIii1I11I1II1 * O0 * Oo0Ooo
 if ( iiII1Ii1 [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( iiII1Ii1 , lisp_send_sockets , lisp_ephem_port )
  return
  if 66 - 66: OoooooooOO % OoO0O00 + i11iIiiIii + I1Ii111 % OoO0O00
 if ( iiII1Ii1 [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( iiII1Ii1 , punt_socket )
  return
  if 80 - 80: Oo0Ooo - Ii1I
  if 54 - 54: O0 - iIii1I11I1II1 . OoO0O00 . IiII % OoO0O00
  if 28 - 28: O0 % i1IIi % OoO0O00 / o0oOOo0O0Ooo . iIii1I11I1II1 - iII111i
  if 50 - 50: o0oOOo0O0Ooo + iII111i / i1IIi % II111iiii
  if 61 - 61: IiII
 if ( iiII1Ii1 [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 5 - 5: OOooOOo % iIii1I11I1II1 % O0 * i11iIiiIii / I1Ii111
  if 48 - 48: IiII * oO0o
  if 53 - 53: i1IIi * iIii1I11I1II1 . OOooOOo
  if 68 - 68: IiII % IiII - iII111i . IiII + OoooooooOO
  if 82 - 82: Ii1I . II111iiii / i1IIi * OoO0O00
 if ( iiII1Ii1 [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 80 - 80: I11i
 if ( iiII1Ii1 . has_key ( "interface" ) == False ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( iIiI111ii1Ii ) )
  if 96 - 96: i1IIi - I1ii11iIi11i * iII111i . OOooOOo . OoO0O00
  return
  if 93 - 93: oO0o * Oo0Ooo * IiII
  if 26 - 26: o0oOOo0O0Ooo + O0 % i11iIiiIii . ooOoO0o . I1IiiI + Oo0Ooo
  if 90 - 90: IiII * OoooooooOO + II111iiii / iII111i + i11iIiiIii / ooOoO0o
  if 20 - 20: II111iiii % I1ii11iIi11i - OoooooooOO * Ii1I / I11i - OoooooooOO
  if 11 - 11: I1IiiI + Ii1I + i11iIiiIii * I1ii11iIi11i - oO0o
 OoO = iiII1Ii1 [ "interface" ]
 if ( OoO == "" ) :
  i1 = int ( iiII1Ii1 [ "instance-id" ] )
  if ( i1 == - 1 ) : return
 else :
  i1 = lisp_get_interface_instance_id ( OoO , None )
  if 46 - 46: OoooooooOO - Oo0Ooo
  if 4 - 4: II111iiii . OOooOOo - Ii1I - i11iIiiIii
  if 27 - 27: iII111i * iII111i - OoO0O00 % o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 64 - 64: I1ii11iIi11i * ooOoO0o - OoooooooOO - I1IiiI
  if 59 - 59: I1ii11iIi11i . I1Ii111 - OOooOOo / Oo0Ooo + OOooOOo . I1ii11iIi11i
 i11 = None
 if ( iiII1Ii1 . has_key ( "source-eid" ) ) :
  O00Oo = iiII1Ii1 [ "source-eid" ]
  i11 = lisp_address ( LISP_AFI_NONE , O00Oo , 0 , i1 )
  if ( i11 . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( O00Oo ) )
   return
   if 69 - 69: Oo0Ooo
   if 34 - 34: I1Ii111 - ooOoO0o . o0oOOo0O0Ooo
 OOOO00o0OO0OOo0o = None
 if ( iiII1Ii1 . has_key ( "dest-eid" ) ) :
  OO00o0o0oO0 = iiII1Ii1 [ "dest-eid" ]
  OOOO00o0OO0OOo0o = lisp_address ( LISP_AFI_NONE , OO00o0o0oO0 , 0 , i1 )
  if ( OOOO00o0OO0OOo0o . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( OO00o0o0oO0 ) )
   return
   if 67 - 67: Oo0Ooo / OoooooooOO
   if 56 - 56: I11i * Ii1I . i1IIi / ooOoO0o + Oo0Ooo % I1ii11iIi11i
   if 73 - 73: I1Ii111 - o0oOOo0O0Ooo % Ii1I + OOooOOo
   if 33 - 33: o0oOOo0O0Ooo / O0 % OOooOOo
   if 66 - 66: Oo0Ooo % oO0o
   if 52 - 52: oO0o
   if 26 - 26: OoO0O00 % I1ii11iIi11i * O0 % OoO0O00
   if 98 - 98: OoO0O00 . ooOoO0o * I11i / i1IIi
 if ( i11 ) :
  I1i = green ( i11 . print_address ( ) , False )
  oooOOoO0oo0 = lisp_db_for_lookups . lookup_cache ( i11 , False )
  if ( oooOOoO0oo0 != None ) :
   if 57 - 57: i11iIiiIii % OOooOOo
   if 67 - 67: oO0o - OOooOOo + II111iiii
   if 19 - 19: iIii1I11I1II1 * OoooooooOO - i11iIiiIii . I1Ii111 * OoO0O00
   if 30 - 30: iII111i + I1IiiI * ooOoO0o
   if 53 - 53: iII111i + IiII
   if ( oooOOoO0oo0 . dynamic_eid_configured ( ) ) :
    iI1ii1iI1 = lisp_allow_dynamic_eid ( OoO , i11 )
    if ( iI1ii1iI1 != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( oooOOoO0oo0 , i11 , OoO , iI1ii1iI1 )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( I1i , OoO ) )
     if 52 - 52: II111iiii * i11iIiiIii - IiII * IiII / OoooooooOO
     if 18 - 18: IiII / O0 / I1ii11iIi11i
     if 47 - 47: oO0o / iIii1I11I1II1
  else :
   lprint ( "Punt from non-EID source {}" . format ( I1i ) )
   if 45 - 45: OoOoOO00 * o0oOOo0O0Ooo / I1ii11iIi11i * iII111i - I1ii11iIi11i
   if 48 - 48: Ii1I / OoO0O00
   if 45 - 45: O0 * OoO0O00 / I11i . II111iiii
   if 20 - 20: I11i - IiII
   if 75 - 75: i11iIiiIii + I11i % I11i . I1Ii111
   if 58 - 58: o0oOOo0O0Ooo * II111iiii + o0oOOo0O0Ooo . I1IiiI
 if ( OOOO00o0OO0OOo0o ) :
  ooOoOO0Oo = lisp_map_cache_lookup ( i11 , OOOO00o0OO0OOo0o )
  if ( ooOoOO0Oo == None or lisp_mr_or_pubsub ( ooOoOO0Oo . action ) ) :
   if 25 - 25: o0oOOo0O0Ooo * I11i
   if 70 - 70: OOooOOo
   if 11 - 11: I11i * II111iiii * Oo0Ooo + OOooOOo % i1IIi
   if 73 - 73: OoO0O00 + O0 / Ii1I . OoooooooOO % iIii1I11I1II1 * i1IIi
   if 84 - 84: o0oOOo0O0Ooo . iII111i / o0oOOo0O0Ooo + I1ii11iIi11i % OoO0O00
   if ( lisp_rate_limit_map_request ( OOOO00o0OO0OOo0o ) ) : return
   if 52 - 52: OoOoOO00 / Ii1I % OoOoOO00 % i11iIiiIii + I1IiiI / o0oOOo0O0Ooo
   iIiii11 = ( ooOoOO0Oo and ooOoOO0Oo . action == LISP_SEND_PUBSUB_ACTION )
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 i11 , OOOO00o0OO0OOo0o , None , iIiii11 )
  else :
   I1i = green ( OOOO00o0OO0OOo0o . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( I1i ) )
   if 63 - 63: I1IiiI
   if 20 - 20: oO0o + OoOoOO00
 return
 if 32 - 32: o0oOOo0O0Ooo % oO0o % I1IiiI * OoooooooOO
 if 4 - 4: OOooOOo % oO0o
 if 18 - 18: Ii1I * I11i
 if 14 - 14: ooOoO0o . ooOoO0o * OoOoOO00 * o0oOOo0O0Ooo - iII111i - I1Ii111
 if 53 - 53: Oo0Ooo * OoOoOO00 * II111iiii % IiII - I1ii11iIi11i
 if 56 - 56: Oo0Ooo . I1ii11iIi11i - i11iIiiIii / iIii1I11I1II1 . ooOoO0o
 if 28 - 28: OoooooooOO + I1IiiI / oO0o . iIii1I11I1II1 - oO0o
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 oOOoO0oO0oo0O = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( oOOoO0oO0oo0O )
 return ( [ True , jdata ] )
 if 64 - 64: I1Ii111 + Oo0Ooo / iII111i
 if 61 - 61: Ii1I * Ii1I . OoOoOO00 + OoO0O00 * i11iIiiIii * OoO0O00
 if 4 - 4: OoooooooOO % iII111i % Oo0Ooo * IiII % o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 66 - 66: I1IiiI . Oo0Ooo - oO0o
 if 53 - 53: oO0o / Ii1I + oO0o + II111iiii
 if 70 - 70: OoooooooOO - I1Ii111 + OoOoOO00
 if 61 - 61: I1IiiI * I1Ii111 * i11iIiiIii
 if 68 - 68: OoOoOO00 - iII111i - I1IiiI
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 37 - 37: iII111i - I1Ii111 + i1IIi / o0oOOo0O0Ooo % iII111i / iII111i
 if 8 - 8: i1IIi % I11i
 if 12 - 12: ooOoO0o / II111iiii + ooOoO0o * I1ii11iIi11i / i1IIi - iIii1I11I1II1
 if 71 - 71: IiII - i11iIiiIii
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 3 - 3: i11iIiiIii - o0oOOo0O0Ooo / oO0o . OoO0O00 * I11i + o0oOOo0O0Ooo
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 18 - 18: OoooooooOO % oO0o / IiII - ooOoO0o
 if 80 - 80: I11i
 if 98 - 98: iII111i / I1ii11iIi11i
 if 87 - 87: iII111i - O0 * ooOoO0o / II111iiii % OoooooooOO . o0oOOo0O0Ooo
 if 55 - 55: OOooOOo - o0oOOo0O0Ooo * I1IiiI / o0oOOo0O0Ooo + I1Ii111 + iIii1I11I1II1
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 3 - 3: II111iiii % iII111i / IiII * ooOoO0o . OoooooooOO
 if 56 - 56: IiII * II111iiii + Oo0Ooo - O0 - OoO0O00 . I1Ii111
 if 53 - 53: i1IIi + IiII
 if 90 - 90: II111iiii / oO0o / oO0o . OoOoOO00 / OoO0O00 / iIii1I11I1II1
 if 96 - 96: iIii1I11I1II1 % I1ii11iIi11i
 if 35 - 35: i1IIi - OoooooooOO * Ii1I / OOooOOo % I11i
 if 72 - 72: I1Ii111 / OoO0O00 + II111iiii
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 iIiI1I1ii1I1 = eid . print_address ( )
 if ( db . dynamic_eids . has_key ( iIiI1I1ii1I1 ) ) :
  db . dynamic_eids [ iIiI1I1ii1I1 ] . last_packet = lisp_get_timestamp ( )
  return
  if 40 - 40: Ii1I + O0 . i11iIiiIii % I11i / Oo0Ooo
  if 25 - 25: IiII * IiII
  if 54 - 54: I1Ii111
  if 90 - 90: Oo0Ooo / Ii1I
  if 66 - 66: i11iIiiIii - I11i + oO0o . OoooooooOO
 ooOoo000 = lisp_dynamic_eid ( )
 ooOoo000 . dynamic_eid . copy_address ( eid )
 ooOoo000 . interface = routed_interface
 ooOoo000 . last_packet = lisp_get_timestamp ( )
 ooOoo000 . get_timeout ( routed_interface )
 db . dynamic_eids [ iIiI1I1ii1I1 ] = ooOoo000
 if 77 - 77: OoO0O00 / OOooOOo
 OO00 = ""
 if ( input_interface != routed_interface ) :
  OO00 = ", routed-interface " + routed_interface
  if 64 - 64: Oo0Ooo % O0
  if 66 - 66: O0 + I1IiiI % iIii1I11I1II1 . i1IIi % II111iiii - i1IIi
 Oo0o00 = green ( iIiI1I1ii1I1 , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( Oo0o00 , input_interface , OO00 , ooOoo000 . timeout ) )
 if 76 - 76: Oo0Ooo - OOooOOo * ooOoO0o / oO0o
 if 46 - 46: oO0o % iII111i - i11iIiiIii
 if 93 - 93: O0
 if 11 - 11: OoooooooOO . I1ii11iIi11i + I1ii11iIi11i
 if 73 - 73: OoooooooOO
 Oo0O = "learn%{}%{}" . format ( iIiI1I1ii1I1 , routed_interface )
 Oo0O = lisp_command_ipc ( Oo0O , "lisp-itr" )
 lisp_ipc ( Oo0O , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 2 - 2: o0oOOo0O0Ooo % IiII + I1ii11iIi11i - i11iIiiIii
 if 100 - 100: II111iiii + oO0o
 if 85 - 85: I1ii11iIi11i % I1ii11iIi11i . Ii1I
 if 42 - 42: oO0o + OoO0O00
 if 16 - 16: Ii1I
 if 67 - 67: I1ii11iIi11i . OoooooooOO * I1Ii111 + Ii1I * OOooOOo
 if 84 - 84: OOooOOo
 if 78 - 78: O0 % O0
 if 72 - 72: o0oOOo0O0Ooo * IiII / II111iiii / iIii1I11I1II1
 if 41 - 41: iII111i / Ii1I
 if 11 - 11: Oo0Ooo % OOooOOo . ooOoO0o
 if 24 - 24: IiII / Oo0Ooo
 if 90 - 90: ooOoO0o . OOooOOo - Ii1I
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 60 - 60: i11iIiiIii % iII111i . I1IiiI * I1ii11iIi11i
 if 30 - 30: Ii1I + i11iIiiIii . I11i + o0oOOo0O0Ooo - OoO0O00
 if 55 - 55: ooOoO0o - II111iiii . ooOoO0o . iII111i / OoooooooOO
 if 51 - 51: I1IiiI * I1Ii111 - ooOoO0o + IiII
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 22 - 22: OoOoOO00 % Ii1I + iII111i
 Ooo0 = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 64 - 64: ooOoO0o
 for OO0Oo00o0o0 in lisp_crypto_keys_by_rloc_decap :
  if 87 - 87: IiII - Ii1I / Oo0Ooo / I1ii11iIi11i . iII111i
  if 49 - 49: IiII * OoooooooOO * iIii1I11I1II1 * Oo0Ooo / iII111i % oO0o
  if 88 - 88: I1Ii111 * OOooOOo
  if 38 - 38: Oo0Ooo - OoooooooOO - OoooooooOO / II111iiii
  if ( OO0Oo00o0o0 . find ( addr_str ) == - 1 ) : continue
  if 10 - 10: II111iiii - OoO0O00 / II111iiii % Ii1I - OoOoOO00
  if 90 - 90: I11i + II111iiii - oO0o - ooOoO0o / ooOoO0o / i11iIiiIii
  if 80 - 80: I1ii11iIi11i % O0 / II111iiii + iII111i
  if 22 - 22: Oo0Ooo + ooOoO0o . OOooOOo % Oo0Ooo . IiII
  if ( OO0Oo00o0o0 == addr_str ) : continue
  if 34 - 34: Ii1I . OoOoOO00 - OOooOOo * Oo0Ooo - ooOoO0o . oO0o
  if 42 - 42: O0 + OoO0O00
  if 47 - 47: O0 % OoOoOO00 + Ii1I * iIii1I11I1II1
  if 55 - 55: Ii1I
  oOOoO0oO0oo0O = lisp_crypto_keys_by_rloc_decap [ OO0Oo00o0o0 ]
  if ( oOOoO0oO0oo0O == Ooo0 ) : continue
  if 93 - 93: iII111i + OOooOOo . OoooooooOO . I1Ii111 . O0
  if 46 - 46: i11iIiiIii
  if 26 - 26: I11i * Oo0Ooo % OoO0O00 + Oo0Ooo - I1ii11iIi11i
  if 74 - 74: i1IIi + OoO0O00 . II111iiii + I1Ii111
  O0iIiiiIiI1IIII = oOOoO0oO0oo0O [ 1 ]
  if ( packet_icv != O0iIiiiIiI1IIII . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( OO0Oo00o0o0 , False ) ) )
   continue
   if 27 - 27: OoOoOO00 + OoooooooOO - iII111i + I11i + OoOoOO00
   if 25 - 25: Ii1I / II111iiii + o0oOOo0O0Ooo . I1ii11iIi11i
  lprint ( "Changing decap crypto key to {}" . format ( red ( OO0Oo00o0o0 , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = oOOoO0oO0oo0O
  if 3 - 3: iII111i / oO0o * II111iiii
 return
 if 21 - 21: o0oOOo0O0Ooo / I1ii11iIi11i
 if 48 - 48: i11iIiiIii % I1ii11iIi11i
 if 73 - 73: OoOoOO00 + O0 + I1IiiI . iIii1I11I1II1 / I1ii11iIi11i
 if 98 - 98: Oo0Ooo
 if 72 - 72: oO0o + OoooooooOO . O0 + IiII
 if 49 - 49: i1IIi - i11iIiiIii + II111iiii + Ii1I / OoO0O00
 if 34 - 34: I1ii11iIi11i * i11iIiiIii
 if 6 - 6: I1ii11iIi11i + I1IiiI / OoooooooOO % I11i * Oo0Ooo
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 20 - 20: Oo0Ooo
 if 85 - 85: I1Ii111
 if 98 - 98: OoO0O00 - IiII % iIii1I11I1II1 . OoOoOO00 + i1IIi + OoooooooOO
 if 29 - 29: I1ii11iIi11i * I1Ii111 - i1IIi * i11iIiiIii * iIii1I11I1II1 % I11i
 if 73 - 73: OoO0O00 . I1IiiI / o0oOOo0O0Ooo
 if 12 - 12: I11i * i11iIiiIii - O0 * o0oOOo0O0Ooo - IiII + I1IiiI
 if 7 - 7: oO0o + I1Ii111 . o0oOOo0O0Ooo / IiII + iIii1I11I1II1 % I1Ii111
 if 24 - 24: i11iIiiIii + iIii1I11I1II1
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 Iii = dns_name . split ( "." )
 Iii = "." . join ( Iii [ 1 : : ] )
 return ( Iii == lisp_decent_dns_suffix )
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
def lisp_get_decent_index ( eid ) :
 iIiI1I1ii1I1 = eid . print_prefix ( )
 II11iiII = hmac . new ( "lisp-decent" , iIiI1I1ii1I1 , hashlib . sha256 ) . hexdigest ( )
 if 28 - 28: I1IiiI
 if 36 - 36: iII111i
 if 64 - 64: II111iiii * iII111i / oO0o - I1IiiI / II111iiii
 if 57 - 57: I11i
 I1I11ii1i1i1I = os . getenv ( "LISP_DECENT_HASH_WIDTH" )
 if ( I1I11ii1i1i1I in [ "" , None ] ) :
  I1I11ii1i1i1I = 12
 else :
  I1I11ii1i1i1I = int ( I1I11ii1i1i1I )
  if ( I1I11ii1i1i1I > 32 ) :
   I1I11ii1i1i1I = 12
  else :
   I1I11ii1i1i1I *= 2
   if 93 - 93: iII111i % OOooOOo + Oo0Ooo * iII111i % oO0o % OOooOOo
   if 14 - 14: O0 * i11iIiiIii - i1IIi . iIii1I11I1II1 - OoOoOO00 % I1Ii111
   if 18 - 18: iII111i . i1IIi . i11iIiiIii . OOooOOo
 I1111i1ii = II11iiII [ 0 : I1I11ii1i1i1I ]
 I1i11II = int ( I1111i1ii , 16 ) % lisp_decent_modulus
 if 100 - 100: OoOoOO00 / o0oOOo0O0Ooo / O0 / OoO0O00
 lprint ( "LISP-Decent modulus {}, hash-width {}, mod-value {}, index {}" . format ( lisp_decent_modulus , I1I11ii1i1i1I / 2 , I1111i1ii , I1i11II ) )
 if 23 - 23: Ii1I + i11iIiiIii % IiII
 if 64 - 64: i11iIiiIii + OoooooooOO . oO0o * Ii1I
 return ( I1i11II )
 if 49 - 49: O0
 if 72 - 72: I1Ii111
 if 96 - 96: II111iiii / OOooOOo % i1IIi / Oo0Ooo
 if 22 - 22: I1IiiI % iIii1I11I1II1 % I1ii11iIi11i
 if 68 - 68: iII111i + I11i
 if 61 - 61: oO0o . I1Ii111
 if 74 - 74: O0 . Ii1I - iII111i % IiII + II111iiii
def lisp_get_decent_dns_name ( eid ) :
 I1i11II = lisp_get_decent_index ( eid )
 return ( str ( I1i11II ) + "." + lisp_decent_dns_suffix )
 if 71 - 71: oO0o + Ii1I % oO0o
 if 17 - 17: I1Ii111 % I1Ii111 * o0oOOo0O0Ooo
 if 84 - 84: I1Ii111 + iII111i . i1IIi / O0 / I1Ii111 + o0oOOo0O0Ooo
 if 70 - 70: O0 % ooOoO0o - iII111i + oO0o
 if 12 - 12: I1Ii111 - OoO0O00 % II111iiii % ooOoO0o / II111iiii % OoOoOO00
 if 74 - 74: iII111i . OOooOOo * Ii1I / Oo0Ooo . OoO0O00 . I11i
 if 65 - 65: i11iIiiIii - OoO0O00 / OoooooooOO * I1IiiI % iII111i
 if 15 - 15: OOooOOo * Ii1I / ooOoO0o
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 oOooOOo000o0o = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 I1i11II = lisp_get_decent_index ( oOooOOo000o0o )
 return ( str ( I1i11II ) + "." + lisp_decent_dns_suffix )
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
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 96 - 96: Oo0Ooo + I1ii11iIi11i . O0
 IiI1ii1Ii = 28 if packet . inner_version == 4 else 48
 oo0ooOo0oOo = packet . packet [ IiI1ii1Ii : : ]
 O0Ooo0 = lisp_trace ( )
 if ( O0Ooo0 . decode ( oo0ooOo0oOo ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 67 - 67: Ii1I % I1ii11iIi11i + OoO0O00 * i1IIi . OOooOOo
  if 76 - 76: I1ii11iIi11i + I1IiiI
 I11iIi1i = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 80 - 80: OoO0O00 * oO0o . OoOoOO00 + O0 / O0
 if 8 - 8: I11i - i11iIiiIii
 if 89 - 89: O0 % IiII . Oo0Ooo % Ii1I - I11i
 if 43 - 43: iIii1I11I1II1 % I11i + i1IIi + I1Ii111
 if 99 - 99: iII111i
 if 11 - 11: o0oOOo0O0Ooo / oO0o
 if ( I11iIi1i != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : I11iIi1i += ":{}" . format ( packet . encap_port )
  if 26 - 26: I1Ii111 / iIii1I11I1II1
  if 98 - 98: i11iIiiIii / iII111i
  if 32 - 32: ooOoO0o / OOooOOo + Oo0Ooo + II111iiii
  if 91 - 91: O0
  if 64 - 64: I1Ii111 - II111iiii + oO0o % ooOoO0o * oO0o
 oOOoO0oO0oo0O = { }
 oOOoO0oO0oo0O [ "node" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 27 - 27: iIii1I11I1II1 - Ii1I . i11iIiiIii / IiII . I1Ii111 / i11iIiiIii
 iIiooOOo0OOoOO0O = packet . outer_source
 if ( iIiooOOo0OOoOO0O . is_null ( ) ) : iIiooOOo0OOoOO0O = lisp_myrlocs [ 0 ]
 oOOoO0oO0oo0O [ "srloc" ] = iIiooOOo0OOoOO0O . print_address_no_iid ( )
 if 74 - 74: OoO0O00 . iII111i / OoO0O00 + Oo0Ooo
 if 21 - 21: I1IiiI . II111iiii % iIii1I11I1II1
 if 81 - 81: Oo0Ooo + i11iIiiIii
 if 79 - 79: I1IiiI
 if 60 - 60: I1ii11iIi11i - O0
 if ( oOOoO0oO0oo0O [ "node" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  oOOoO0oO0oo0O [ "srloc" ] += ":{}" . format ( packet . inner_sport )
  if 90 - 90: I1Ii111 - OoOoOO00
  if 96 - 96: I11i * Oo0Ooo / OOooOOo - IiII
 oOOoO0oO0oo0O [ "hn" ] = lisp_hostname
 OO0Oo00o0o0 = ed + "-ts"
 oOOoO0oO0oo0O [ OO0Oo00o0o0 ] = lisp_get_timestamp ( )
 if 75 - 75: OoooooooOO - O0
 if 39 - 39: i11iIiiIii / Ii1I / ooOoO0o
 if 93 - 93: o0oOOo0O0Ooo - Oo0Ooo / oO0o / OoOoOO00
 if 75 - 75: o0oOOo0O0Ooo * ooOoO0o % Ii1I
 if 94 - 94: OoooooooOO + II111iiii / iIii1I11I1II1 * ooOoO0o
 if 85 - 85: ooOoO0o / IiII
 if ( I11iIi1i == "?" and oOOoO0oO0oo0O [ "node" ] == "ETR" ) :
  oooOOoO0oo0 = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( oooOOoO0oo0 != None and len ( oooOOoO0oo0 . rloc_set ) >= 1 ) :
   I11iIi1i = oooOOoO0oo0 . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 28 - 28: i11iIiiIii - OoOoOO00
   if 13 - 13: O0
 oOOoO0oO0oo0O [ "drloc" ] = I11iIi1i
 if 82 - 82: OoooooooOO
 if 59 - 59: I1Ii111 + I1ii11iIi11i + OoO0O00 % oO0o . i1IIi % O0
 if 22 - 22: i1IIi * OoOoOO00 + Ii1I
 if 48 - 48: Ii1I % IiII + OoO0O00 . IiII
 if ( I11iIi1i == "?" and reason != None ) :
  oOOoO0oO0oo0O [ "drloc" ] += " ({})" . format ( reason )
  if 42 - 42: Ii1I
  if 70 - 70: I11i
  if 82 - 82: O0
  if 58 - 58: II111iiii . O0 - OoO0O00 - IiII
  if 4 - 4: i11iIiiIii + i11iIiiIii / O0
 if ( rloc_entry != None ) :
  oOOoO0oO0oo0O [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  oOOoO0oO0oo0O [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  oOOoO0oO0oo0O [ "latencies" ] = rloc_entry . recent_rloc_probe_latencies
  if 46 - 46: I11i % ooOoO0o - Ii1I
  if 25 - 25: O0 / i11iIiiIii . O0
  if 24 - 24: I1ii11iIi11i - i11iIiiIii / iII111i . Oo0Ooo / I1ii11iIi11i
  if 92 - 92: I11i % OoooooooOO
  if 14 - 14: i11iIiiIii * i11iIiiIii * OoOoOO00
  if 84 - 84: OOooOOo % I1Ii111 + I11i / I1IiiI . iII111i
 i11 = packet . inner_source . print_address ( )
 OOOO00o0OO0OOo0o = packet . inner_dest . print_address ( )
 if ( O0Ooo0 . packet_json == [ ] ) :
  II1i1iiiII1ii = { }
  II1i1iiiII1ii [ "seid" ] = i11
  II1i1iiiII1ii [ "deid" ] = OOOO00o0OO0OOo0o
  II1i1iiiII1ii [ "paths" ] = [ ]
  O0Ooo0 . packet_json . append ( II1i1iiiII1ii )
  if 78 - 78: oO0o . Oo0Ooo
  if 18 - 18: IiII
  if 35 - 35: OoooooooOO / i1IIi - OoO0O00 + Oo0Ooo - o0oOOo0O0Ooo
  if 100 - 100: II111iiii % i11iIiiIii % oO0o + O0
  if 46 - 46: OoO0O00 / I1IiiI - Oo0Ooo . o0oOOo0O0Ooo . Oo0Ooo % I11i
  if 43 - 43: IiII - O0 + I1Ii111 % OoooooooOO % OoO0O00 / I1Ii111
 for II1i1iiiII1ii in O0Ooo0 . packet_json :
  if ( II1i1iiiII1ii [ "deid" ] != OOOO00o0OO0OOo0o ) : continue
  II1i1iiiII1ii [ "paths" ] . append ( oOOoO0oO0oo0O )
  break
  if 48 - 48: I1ii11iIi11i . i1IIi % i1IIi - iII111i * o0oOOo0O0Ooo + IiII
  if 45 - 45: II111iiii . II111iiii + I1IiiI / I1Ii111 . OoO0O00 - o0oOOo0O0Ooo
  if 20 - 20: ooOoO0o % oO0o
  if 28 - 28: i1IIi . II111iiii + O0 / O0 % OoOoOO00 + OOooOOo
  if 24 - 24: OoooooooOO
  if 11 - 11: i11iIiiIii / iIii1I11I1II1 % ooOoO0o + OOooOOo
  if 73 - 73: OoOoOO00 + OoooooooOO + iIii1I11I1II1 + II111iiii * iIii1I11I1II1 - OoOoOO00
  if 71 - 71: O0 * OOooOOo . I1IiiI . I1Ii111 * I11i
 Iiii1iiiIIIi1I = False
 if ( len ( O0Ooo0 . packet_json ) == 1 and oOOoO0oO0oo0O [ "node" ] == "ETR" and
 O0Ooo0 . myeid ( packet . inner_dest ) ) :
  II1i1iiiII1ii = { }
  II1i1iiiII1ii [ "seid" ] = OOOO00o0OO0OOo0o
  II1i1iiiII1ii [ "deid" ] = i11
  II1i1iiiII1ii [ "paths" ] = [ ]
  O0Ooo0 . packet_json . append ( II1i1iiiII1ii )
  Iiii1iiiIIIi1I = True
  if 36 - 36: OoOoOO00 - Ii1I % OoooooooOO % iII111i
  if 81 - 81: i1IIi % OOooOOo - OoO0O00 - Oo0Ooo
  if 19 - 19: i1IIi
  if 97 - 97: OoO0O00 + i11iIiiIii % I1IiiI * Ii1I
  if 89 - 89: IiII % i11iIiiIii + OoO0O00 . oO0o / I1IiiI . Ii1I
  if 11 - 11: ooOoO0o - I1Ii111 - I11i + OoOoOO00
 O0Ooo0 . print_trace ( )
 oo0ooOo0oOo = O0Ooo0 . encode ( )
 if 20 - 20: I11i + O0
 if 27 - 27: Oo0Ooo
 if 12 - 12: I1ii11iIi11i . iII111i - iII111i - OOooOOo - iIii1I11I1II1
 if 50 - 50: I1IiiI - iIii1I11I1II1 . iII111i - Ii1I / I1Ii111 + iII111i
 if 46 - 46: OOooOOo + iII111i % Oo0Ooo * iII111i % OoooooooOO * IiII
 if 27 - 27: I1IiiI + I1IiiI + I1ii11iIi11i - oO0o * OOooOOo
 if 53 - 53: I1ii11iIi11i / OoooooooOO * iIii1I11I1II1
 if 4 - 4: I1IiiI . iIii1I11I1II1 + OOooOOo / IiII . o0oOOo0O0Ooo . I11i
 O0ooO0OOoo = O0Ooo0 . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "srloc" ]
 if ( I11iIi1i == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( O0ooO0OOoo ) )
  O0Ooo0 . return_to_sender ( lisp_socket , O0ooO0OOoo , oo0ooOo0oOo )
  return ( False )
  if 29 - 29: OoO0O00 + iIii1I11I1II1 * iII111i * OOooOOo + I1ii11iIi11i
  if 97 - 97: i1IIi / I1ii11iIi11i / OoO0O00
  if 12 - 12: OOooOOo + iIii1I11I1II1 % I1Ii111 + OOooOOo
  if 19 - 19: OoO0O00 / I1IiiI - o0oOOo0O0Ooo - i1IIi + I1ii11iIi11i * OoooooooOO
  if 74 - 74: I1Ii111 . I11i / Oo0Ooo
  if 88 - 88: oO0o % OoO0O00 - i11iIiiIii % I1Ii111 / O0 * IiII
 Ooo000O00 = O0Ooo0 . packet_length ( )
 if 99 - 99: o0oOOo0O0Ooo . ooOoO0o / i11iIiiIii
 if 44 - 44: IiII + OOooOOo % OoO0O00 . OoooooooOO * O0
 if 72 - 72: i1IIi - iII111i * I1IiiI % O0 - I11i * O0
 if 78 - 78: I1IiiI - OoO0O00 / Ii1I . i1IIi
 if 30 - 30: IiII
 if 21 - 21: i1IIi . iII111i - I1IiiI
 I1I1oOO0OoO = packet . packet [ 0 : IiI1ii1Ii ]
 IIIiIIi111 = struct . pack ( "HH" , socket . htons ( Ooo000O00 ) , 0 )
 I1I1oOO0OoO = I1I1oOO0OoO [ 0 : IiI1ii1Ii - 4 ] + IIIiIIi111
 if ( packet . inner_version == 6 and oOOoO0oO0oo0O [ "node" ] == "ETR" and
 len ( O0Ooo0 . packet_json ) == 2 ) :
  O0I1II1 = I1I1oOO0OoO [ IiI1ii1Ii - 8 : : ] + oo0ooOo0oOo
  O0I1II1 = lisp_udp_checksum ( i11 , OOOO00o0OO0OOo0o , O0I1II1 )
  I1I1oOO0OoO = I1I1oOO0OoO [ 0 : IiI1ii1Ii - 8 ] + O0I1II1 [ 0 : 8 ]
  if 52 - 52: oO0o * OOooOOo / II111iiii + II111iiii + I11i
  if 9 - 9: i11iIiiIii
  if 27 - 27: I1Ii111 * O0
  if 9 - 9: i1IIi - Oo0Ooo - i11iIiiIii / iIii1I11I1II1 . i1IIi
  if 2 - 2: I11i + II111iiii - I11i / oO0o / I11i
  if 73 - 73: IiII % I1Ii111 . OoOoOO00
 if ( Iiii1iiiIIIi1I ) :
  if ( packet . inner_version == 4 ) :
   I1I1oOO0OoO = I1I1oOO0OoO [ 0 : 12 ] + I1I1oOO0OoO [ 16 : 20 ] + I1I1oOO0OoO [ 12 : 16 ] + I1I1oOO0OoO [ 22 : 24 ] + I1I1oOO0OoO [ 20 : 22 ] + I1I1oOO0OoO [ 24 : : ]
   if 96 - 96: I1IiiI / ooOoO0o / iIii1I11I1II1
  else :
   I1I1oOO0OoO = I1I1oOO0OoO [ 0 : 8 ] + I1I1oOO0OoO [ 24 : 40 ] + I1I1oOO0OoO [ 8 : 24 ] + I1I1oOO0OoO [ 42 : 44 ] + I1I1oOO0OoO [ 40 : 42 ] + I1I1oOO0OoO [ 44 : : ]
   if 91 - 91: Ii1I . I11i
   if 87 - 87: Oo0Ooo / IiII * OOooOOo + I1ii11iIi11i . I11i
  IiI11I111 = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = IiI11I111
  if 56 - 56: oO0o + oO0o % o0oOOo0O0Ooo + OOooOOo . II111iiii + i11iIiiIii
  if 45 - 45: iIii1I11I1II1 / o0oOOo0O0Ooo * OoooooooOO - Oo0Ooo
  if 77 - 77: II111iiii
  if 8 - 8: I1IiiI * II111iiii % I1ii11iIi11i
  if 88 - 88: Oo0Ooo . oO0o + OoOoOO00 % OoooooooOO
 IiI1ii1Ii = 2 if packet . inner_version == 4 else 4
 OoII1IIiI1Ii = 20 + Ooo000O00 if packet . inner_version == 4 else Ooo000O00
 O00Ooo = struct . pack ( "H" , socket . htons ( OoII1IIiI1Ii ) )
 I1I1oOO0OoO = I1I1oOO0OoO [ 0 : IiI1ii1Ii ] + O00Ooo + I1I1oOO0OoO [ IiI1ii1Ii + 2 : : ]
 if 61 - 61: OOooOOo - ooOoO0o . iII111i
 if 24 - 24: o0oOOo0O0Ooo + IiII - I11i - oO0o
 if 24 - 24: i11iIiiIii / OoOoOO00 . OoO0O00 * OOooOOo
 if 61 - 61: OoooooooOO % II111iiii * I1ii11iIi11i . oO0o . OoooooooOO % IiII
 if ( packet . inner_version == 4 ) :
  I1i11i = struct . pack ( "H" , 0 )
  I1I1oOO0OoO = I1I1oOO0OoO [ 0 : 10 ] + I1i11i + I1I1oOO0OoO [ 12 : : ]
  O00Ooo = lisp_ip_checksum ( I1I1oOO0OoO [ 0 : 20 ] )
  I1I1oOO0OoO = O00Ooo + I1I1oOO0OoO [ 20 : : ]
  if 59 - 59: i1IIi
  if 85 - 85: I11i + oO0o / Oo0Ooo . ooOoO0o % O0 * o0oOOo0O0Ooo
  if 13 - 13: i1IIi * Oo0Ooo % i11iIiiIii % I11i / II111iiii - Ii1I
  if 71 - 71: OoOoOO00 % ooOoO0o
  if 36 - 36: Ii1I * oO0o / oO0o % I1IiiI % I1IiiI + I1IiiI
 packet . packet = I1I1oOO0OoO + oo0ooOo0oOo
 return ( True )
 if 41 - 41: OoooooooOO . O0 % OOooOOo
 if 88 - 88: O0
 if 44 - 44: II111iiii - IiII / I1IiiI + ooOoO0o % iII111i - iII111i
 if 53 - 53: OoooooooOO
 if 41 - 41: i1IIi - oO0o
 if 41 - 41: I11i
 if 92 - 92: i11iIiiIii
 if 62 - 62: i1IIi / I1IiiI - o0oOOo0O0Ooo
 if 3 - 3: O0 * OoOoOO00 * I11i / OoOoOO00
 if 77 - 77: i1IIi
def lisp_allow_gleaning ( eid , group , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False , False )
 if 3 - 3: iII111i * OoO0O00 - oO0o + iII111i . o0oOOo0O0Ooo + I1IiiI
 for oOOoO0oO0oo0O in lisp_glean_mappings :
  if ( oOOoO0oO0oo0O . has_key ( "instance-id" ) ) :
   i1 = eid . instance_id
   OOO00 , iIII = oOOoO0oO0oo0O [ "instance-id" ]
   if ( i1 < OOO00 or i1 > iIII ) : continue
   if 65 - 65: O0 / OoOoOO00
  if ( oOOoO0oO0oo0O . has_key ( "eid-prefix" ) ) :
   I1i = copy . deepcopy ( oOOoO0oO0oo0O [ "eid-prefix" ] )
   I1i . instance_id = eid . instance_id
   if ( eid . is_more_specific ( I1i ) == False ) : continue
   if 77 - 77: OoO0O00
  if ( oOOoO0oO0oo0O . has_key ( "group-prefix" ) ) :
   if ( group == None ) : continue
   OoIi1I1I = copy . deepcopy ( oOOoO0oO0oo0O [ "group-prefix" ] )
   OoIi1I1I . instance_id = group . instance_id
   if ( group . is_more_specific ( OoIi1I1I ) == False ) : continue
   if 17 - 17: i1IIi
  if ( oOOoO0oO0oo0O . has_key ( "rloc-prefix" ) ) :
   if ( rloc != None and rloc . is_more_specific ( oOOoO0oO0oo0O [ "rloc-prefix" ] )
 == False ) : continue
   if 35 - 35: OoOoOO00
  return ( True , oOOoO0oO0oo0O [ "rloc-probe" ] , oOOoO0oO0oo0O [ "igmp-query" ] )
  if 61 - 61: I1Ii111
 return ( False , False , False )
 if 78 - 78: I1Ii111 * Ii1I % Ii1I + I1IiiI
 if 83 - 83: iIii1I11I1II1 + O0 / IiII . iIii1I11I1II1
 if 74 - 74: Oo0Ooo
 if 60 - 60: OoooooooOO
 if 16 - 16: iIii1I11I1II1 - OoOoOO00 / I1ii11iIi11i % O0 % o0oOOo0O0Ooo
 if 99 - 99: ooOoO0o . o0oOOo0O0Ooo - O0 * I1Ii111 . i11iIiiIii / iIii1I11I1II1
 if 40 - 40: iIii1I11I1II1 + oO0o / iIii1I11I1II1 - i1IIi % OoO0O00
def lisp_build_gleaned_multicast ( seid , geid , rloc , port , igmp ) :
 iiiii1I1III1 = geid . print_address ( )
 iI1IiiIi1 = seid . print_address_no_iid ( )
 I1iiIi111I = green ( "{}" . format ( iI1IiiIi1 ) , False )
 I1i = green ( "(*, {})" . format ( iiiii1I1III1 ) , False )
 iiiI1I = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 if 82 - 82: I1ii11iIi11i % i11iIiiIii - OoOoOO00 / I1Ii111 * o0oOOo0O0Ooo * OoO0O00
 if 85 - 85: Oo0Ooo + Ii1I - OoooooooOO . O0
 if 10 - 10: OOooOOo / Oo0Ooo . O0 / i1IIi - OoOoOO00
 if 41 - 41: II111iiii - I1ii11iIi11i - I1Ii111
 ooOoOO0Oo = lisp_map_cache_lookup ( seid , geid )
 if ( ooOoOO0Oo == None ) :
  ooOoOO0Oo = lisp_mapping ( "" , "" , [ ] )
  ooOoOO0Oo . group . copy_address ( geid )
  ooOoOO0Oo . eid . copy_address ( geid )
  ooOoOO0Oo . eid . address = 0
  ooOoOO0Oo . eid . mask_len = 0
  ooOoOO0Oo . mapping_source . copy_address ( rloc )
  ooOoOO0Oo . map_cache_ttl = LISP_IGMP_TTL
  ooOoOO0Oo . gleaned = True
  ooOoOO0Oo . add_cache ( )
  lprint ( "Add gleaned EID {} to map-cache" . format ( I1i ) )
  if 82 - 82: I1IiiI * I1IiiI / iIii1I11I1II1
  if 14 - 14: I11i + Ii1I - OOooOOo % Ii1I / Ii1I
  if 86 - 86: I1Ii111 - i11iIiiIii + Ii1I + I11i
  if 96 - 96: Ii1I
  if 28 - 28: i1IIi . oO0o . IiII + Oo0Ooo . Oo0Ooo . i1IIi
  if 34 - 34: Oo0Ooo + IiII / i1IIi
 O0O0OOo0O = iiIIOOoOo0 = o0Ii11I = None
 if ( ooOoOO0Oo . rloc_set != [ ] ) :
  O0O0OOo0O = ooOoOO0Oo . rloc_set [ 0 ]
  if ( O0O0OOo0O . rle ) :
   iiIIOOoOo0 = O0O0OOo0O . rle
   for oOoII in iiIIOOoOo0 . rle_nodes :
    if ( oOoII . rloc_name != iI1IiiIi1 ) : continue
    o0Ii11I = oOoII
    break
    if 45 - 45: O0
    if 89 - 89: IiII - IiII % o0oOOo0O0Ooo * Oo0Ooo % ooOoO0o
    if 4 - 4: OoO0O00 % II111iiii / I11i
    if 95 - 95: I1Ii111 - I1Ii111 - iII111i + IiII . OoO0O00
    if 5 - 5: i11iIiiIii - O0 % ooOoO0o
    if 55 - 55: II111iiii
    if 7 - 7: I1Ii111 % o0oOOo0O0Ooo . oO0o . ooOoO0o % i1IIi / I1IiiI
 if ( O0O0OOo0O == None ) :
  O0O0OOo0O = lisp_rloc ( )
  ooOoOO0Oo . rloc_set = [ O0O0OOo0O ]
  O0O0OOo0O . priority = 253
  O0O0OOo0O . mpriority = 255
  ooOoOO0Oo . build_best_rloc_set ( )
  if 88 - 88: i11iIiiIii / oO0o - i1IIi / I1IiiI
 if ( iiIIOOoOo0 == None ) :
  iiIIOOoOo0 = lisp_rle ( geid . print_address ( ) )
  O0O0OOo0O . rle = iiIIOOoOo0
  if 57 - 57: oO0o + O0 * I11i
 if ( o0Ii11I == None ) :
  o0Ii11I = lisp_rle_node ( )
  o0Ii11I . rloc_name = iI1IiiIi1
  iiIIOOoOo0 . rle_nodes . append ( o0Ii11I )
  iiIIOOoOo0 . build_forwarding_list ( )
  lprint ( "Add RLE {} from {} for gleaned EID {}" . format ( iiiI1I , I1iiIi111I , I1i ) )
 elif ( rloc . is_exact_match ( o0Ii11I . address ) == False or
 port != o0Ii11I . translated_port ) :
  lprint ( "Changed RLE {} from {} for gleaned EID {}" . format ( iiiI1I , I1iiIi111I , I1i ) )
  if 87 - 87: o0oOOo0O0Ooo % Oo0Ooo * I1ii11iIi11i / OoooooooOO / o0oOOo0O0Ooo
  if 78 - 78: Ii1I
  if 5 - 5: i1IIi * ooOoO0o / OoOoOO00 % i11iIiiIii
  if 57 - 57: IiII
  if 89 - 89: I1ii11iIi11i - I1Ii111 + o0oOOo0O0Ooo
 o0Ii11I . store_translated_rloc ( rloc , port )
 if 62 - 62: I1ii11iIi11i + OoooooooOO * OOooOOo
 if 49 - 49: i1IIi - I11i * II111iiii
 if 4 - 4: o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 57 - 57: I1IiiI * OOooOOo . i11iIiiIii * oO0o - OoOoOO00
 if 35 - 35: O0
 if ( igmp ) :
  OOOo = seid . print_address ( )
  if ( lisp_gleaned_groups . has_key ( OOOo ) == False ) :
   lisp_gleaned_groups [ OOOo ] = { }
   if 65 - 65: Oo0Ooo
  lisp_gleaned_groups [ OOOo ] [ iiiii1I1III1 ] = lisp_get_timestamp ( )
  if 100 - 100: I1Ii111 . o0oOOo0O0Ooo * OoooooooOO . o0oOOo0O0Ooo
  if 90 - 90: i11iIiiIii . I1IiiI + ooOoO0o * OoooooooOO * OoooooooOO + oO0o
  if 77 - 77: OOooOOo * OoOoOO00
  if 75 - 75: Oo0Ooo * Oo0Ooo - IiII - OoOoOO00 / i11iIiiIii + I1Ii111
  if 57 - 57: i11iIiiIii / oO0o
  if 37 - 37: o0oOOo0O0Ooo + OoOoOO00 - i1IIi . Oo0Ooo
  if 3 - 3: ooOoO0o % OoooooooOO / I1Ii111 + oO0o - O0
  if 72 - 72: oO0o * OoO0O00
def lisp_remove_gleaned_multicast ( seid , geid ) :
 if 89 - 89: OoooooooOO . OOooOOo
 if 96 - 96: o0oOOo0O0Ooo + OoOoOO00 / i11iIiiIii - o0oOOo0O0Ooo * i11iIiiIii + OOooOOo
 if 16 - 16: IiII / I1Ii111 . II111iiii * I11i
 if 33 - 33: I1ii11iIi11i / Oo0Ooo % i11iIiiIii
 ooOoOO0Oo = lisp_map_cache_lookup ( seid , geid )
 if ( ooOoOO0Oo == None ) : return
 if 37 - 37: Oo0Ooo - I1Ii111 - IiII / oO0o % I1IiiI / I1Ii111
 O0OOO = ooOoOO0Oo . rloc_set [ 0 ] . rle
 if ( O0OOO == None ) : return
 if 80 - 80: iII111i - oO0o % i1IIi * iIii1I11I1II1 . oO0o
 oOoOoO0Oo0oo = seid . print_address_no_iid ( )
 Ii1iI11I1ii1i = False
 for o0Ii11I in O0OOO . rle_nodes :
  if ( o0Ii11I . rloc_name == oOoOoO0Oo0oo ) :
   Ii1iI11I1ii1i = True
   break
   if 86 - 86: Ii1I
   if 36 - 36: i11iIiiIii % i11iIiiIii
 if ( Ii1iI11I1ii1i == False ) : return
 if 91 - 91: Oo0Ooo + I1Ii111 % iII111i
 if 7 - 7: I1Ii111 + II111iiii
 if 63 - 63: OoO0O00 - o0oOOo0O0Ooo / iII111i % II111iiii * IiII
 if 71 - 71: IiII
 O0OOO . rle_nodes . remove ( o0Ii11I )
 O0OOO . build_forwarding_list ( )
 if 34 - 34: II111iiii
 iiiii1I1III1 = geid . print_address ( )
 OOOo = seid . print_address ( )
 I1iiIi111I = green ( "{}" . format ( OOOo ) , False )
 I1i = green ( "(*, {})" . format ( iiiii1I1III1 ) , False )
 lprint ( "Gleaned EID {} RLE removed for {}" . format ( I1i , I1iiIi111I ) )
 if 7 - 7: IiII / I1ii11iIi11i
 if 88 - 88: iIii1I11I1II1 / o0oOOo0O0Ooo
 if 68 - 68: OoooooooOO % Ii1I + ooOoO0o / oO0o
 if 60 - 60: i11iIiiIii / O0 / I1IiiI
 if ( lisp_gleaned_groups . has_key ( OOOo ) ) :
  if ( lisp_gleaned_groups [ OOOo ] . has_key ( iiiii1I1III1 ) ) :
   lisp_gleaned_groups [ OOOo ] . pop ( iiiii1I1III1 )
   if 99 - 99: I1IiiI / oO0o . OoO0O00 / ooOoO0o + IiII
   if 3 - 3: II111iiii . OOooOOo * i11iIiiIii / I11i
   if 16 - 16: I1ii11iIi11i - ooOoO0o + OoO0O00 . I11i / O0
   if 56 - 56: I1IiiI + Oo0Ooo * II111iiii + iIii1I11I1II1
   if 56 - 56: o0oOOo0O0Ooo * I1IiiI - I11i * I1Ii111 - I11i
   if 92 - 92: oO0o % iIii1I11I1II1 * o0oOOo0O0Ooo * OoooooooOO - iIii1I11I1II1
 if ( O0OOO . rle_nodes == [ ] ) :
  ooOoOO0Oo . delete_cache ( )
  lprint ( "Gleaned EID {} remove, no more RLEs" . format ( I1i ) )
  if 51 - 51: Ii1I - OoO0O00 + i1IIi
  if 11 - 11: II111iiii - iII111i + oO0o % Oo0Ooo
  if 56 - 56: IiII
  if 72 - 72: Oo0Ooo
  if 37 - 37: i11iIiiIii * I1IiiI % ooOoO0o
  if 23 - 23: OoO0O00 + o0oOOo0O0Ooo * I1IiiI
  if 76 - 76: i1IIi . OOooOOo
  if 78 - 78: OoooooooOO % OoOoOO00 * oO0o . I1ii11iIi11i
def lisp_change_gleaned_multicast ( seid , rloc , port ) :
 OOOo = seid . print_address ( )
 if ( lisp_gleaned_groups . has_key ( OOOo ) == False ) : return
 if 79 - 79: OoooooooOO
 for iiIoOOOOoo0O00o in lisp_gleaned_groups [ OOOo ] :
  lisp_geid . store_address ( iiIoOOOOoo0O00o )
  lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , port , False )
  if 6 - 6: i11iIiiIii / II111iiii + II111iiii + I1ii11iIi11i % IiII - I1ii11iIi11i
  if 92 - 92: IiII
  if 49 - 49: O0 . OoOoOO00
  if 7 - 7: i1IIi + II111iiii
  if 96 - 96: I1Ii111 / OoO0O00
  if 27 - 27: Ii1I
  if 90 - 90: I1ii11iIi11i
  if 43 - 43: OoO0O00 . I1IiiI . oO0o + Ii1I
  if 7 - 7: iII111i / Oo0Ooo - OoO0O00 + I1Ii111 * II111iiii * ooOoO0o
  if 80 - 80: oO0o - i1IIi / I11i . II111iiii % O0 % I11i
  if 70 - 70: iIii1I11I1II1 * i1IIi * OOooOOo - Oo0Ooo % i1IIi
  if 60 - 60: o0oOOo0O0Ooo . OOooOOo % II111iiii - I1ii11iIi11i
  if 4 - 4: OOooOOo % ooOoO0o
  if 39 - 39: Ii1I
  if 67 - 67: iIii1I11I1II1 - OOooOOo
  if 47 - 47: OOooOOo - OOooOOo * I1Ii111
  if 24 - 24: I1ii11iIi11i
  if 37 - 37: II111iiii - iIii1I11I1II1 / o0oOOo0O0Ooo . O0 + II111iiii
  if 9 - 9: o0oOOo0O0Ooo
  if 47 - 47: Ii1I * I1Ii111 / II111iiii
  if 73 - 73: ooOoO0o
  if 53 - 53: IiII . Oo0Ooo
  if 54 - 54: i11iIiiIii % ooOoO0o % I1Ii111 + o0oOOo0O0Ooo
  if 2 - 2: IiII
  if 25 - 25: OoOoOO00 . OoO0O00 * o0oOOo0O0Ooo . OoooooooOO - Oo0Ooo + I1IiiI
  if 82 - 82: OoO0O00 - Ii1I * I11i * o0oOOo0O0Ooo
  if 17 - 17: OoooooooOO + I1Ii111
  if 91 - 91: iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo
  if 98 - 98: o0oOOo0O0Ooo % II111iiii * IiII - i11iIiiIii * oO0o
  if 15 - 15: O0 - II111iiii - Oo0Ooo . I1ii11iIi11i % OoO0O00
  if 63 - 63: o0oOOo0O0Ooo / OoOoOO00 % I1ii11iIi11i % I11i
  if 58 - 58: O0 + iII111i
  if 66 - 66: i1IIi . O0 . i1IIi - iIii1I11I1II1 - ooOoO0o % I1ii11iIi11i
  if 96 - 96: i1IIi + oO0o - OoOoOO00 - OoOoOO00
  if 13 - 13: I11i
  if 52 - 52: iII111i . OoOoOO00 * iIii1I11I1II1 . iII111i * IiII
  if 52 - 52: iII111i + iII111i
  if 35 - 35: I1Ii111 * oO0o + Ii1I / I1IiiI + O0 - I11i
  if 42 - 42: o0oOOo0O0Ooo
  if 89 - 89: o0oOOo0O0Ooo
  if 99 - 99: I1ii11iIi11i + Oo0Ooo
  if 20 - 20: OoO0O00 / iII111i
  if 62 - 62: i1IIi % iIii1I11I1II1 + OoOoOO00 - I1IiiI . I1ii11iIi11i
  if 92 - 92: i11iIiiIii * o0oOOo0O0Ooo . Oo0Ooo
  if 15 - 15: o0oOOo0O0Ooo * IiII . iII111i % O0 . iIii1I11I1II1
  if 34 - 34: OOooOOo / iII111i * iIii1I11I1II1 + i11iIiiIii
  if 37 - 37: I11i + o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 8 - 8: Oo0Ooo * Ii1I % I11i - OoooooooOO
  if 11 - 11: OoO0O00 - oO0o
  if 50 - 50: II111iiii * IiII
  if 26 - 26: OoO0O00 . II111iiii
  if 19 - 19: iII111i / i11iIiiIii
  if 31 - 31: I1Ii111 / I1Ii111 % IiII
  if 68 - 68: O0 / OOooOOo % OoOoOO00
  if 68 - 68: OoooooooOO - IiII + I1IiiI * IiII / I11i - OoO0O00
  if 69 - 69: oO0o / II111iiii
  if 56 - 56: i1IIi + II111iiii + Ii1I . OoooooooOO
  if 26 - 26: OoooooooOO % Ii1I % I11i * oO0o - i1IIi - i1IIi
  if 76 - 76: i11iIiiIii + OoO0O00 - iII111i . OoOoOO00 * Oo0Ooo
  if 15 - 15: II111iiii + iIii1I11I1II1
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
  if 85 - 85: OOooOOo
  if 32 - 32: iII111i
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
  if 91 - 91: OoooooooOO
  if 86 - 86: iII111i / OoooooooOO - I1ii11iIi11i
  if 63 - 63: ooOoO0o % Ii1I * I1IiiI
  if 48 - 48: iII111i - iII111i - o0oOOo0O0Ooo + ooOoO0o - o0oOOo0O0Ooo / Ii1I
  if 43 - 43: I1IiiI + Ii1I
  if 37 - 37: OoOoOO00 - OoooooooOO . ooOoO0o - IiII % iIii1I11I1II1 . iIii1I11I1II1
igmp_types = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 64 - 64: OoOoOO00 + iII111i % I1Ii111 - OOooOOo + O0
lisp_igmp_record_types = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 83 - 83: I1Ii111 + I1Ii111
def lisp_process_igmp_packet ( packet ) :
 iIiI111ii1Ii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 iIiI111ii1Ii . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 iIiI111ii1Ii = bold ( "from {}" . format ( iIiI111ii1Ii . print_address_no_iid ( ) ) , False )
 if 43 - 43: oO0o * i1IIi * Ii1I . iIii1I11I1II1 % o0oOOo0O0Ooo
 iiiI1I = bold ( "Receive" , False )
 lprint ( "{} {}-byte {}, IGMP packet: {}" . format ( iiiI1I , len ( packet ) , iIiI111ii1Ii ,
 lisp_format_packet ( packet ) ) )
 if 97 - 97: I1IiiI . i1IIi * OoOoOO00 / OOooOOo
 if 50 - 50: II111iiii . OoO0O00
 if 60 - 60: I11i . iIii1I11I1II1
 if 41 - 41: II111iiii / I1IiiI
 i1II1 = ( struct . unpack ( "B" , packet [ 0 ] ) [ 0 ] & 0x0f ) * 4
 if 3 - 3: OoooooooOO + Oo0Ooo + OOooOOo
 if 20 - 20: Ii1I - oO0o - OoO0O00 + I1ii11iIi11i % OoO0O00 . i1IIi
 if 2 - 2: ooOoO0o * IiII . Ii1I
 if 69 - 69: IiII % i1IIi
 II1 = packet [ i1II1 : : ]
 IIi1i1II1iIiI = struct . unpack ( "B" , II1 [ 0 ] ) [ 0 ]
 if 75 - 75: I1Ii111 + IiII + OoO0O00 % I1ii11iIi11i
 if 100 - 100: I1ii11iIi11i % oO0o * i1IIi - II111iiii
 if 17 - 17: oO0o * I1Ii111 . i11iIiiIii - iIii1I11I1II1 + OOooOOo * OOooOOo
 if 63 - 63: I1ii11iIi11i + ooOoO0o . iIii1I11I1II1 . iIii1I11I1II1 * OoooooooOO * I1IiiI
 if 82 - 82: oO0o
 iiIoOOOOoo0O00o = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 iiIoOOOOoo0O00o . address = socket . ntohl ( struct . unpack ( "II" , II1 [ : 8 ] ) [ 1 ] )
 iiiii1I1III1 = iiIoOOOOoo0O00o . print_address_no_iid ( )
 if 12 - 12: Oo0Ooo
 if ( IIi1i1II1iIiI == 17 ) :
  lprint ( "IGMP Query for group {}" . format ( iiiii1I1III1 ) )
  return ( True )
  if 37 - 37: I1IiiI
  if 77 - 77: o0oOOo0O0Ooo / II111iiii + i11iIiiIii % Ii1I . iIii1I11I1II1
 O0OOiii11i = ( IIi1i1II1iIiI in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( O0OOiii11i == False ) :
  Iiii1Iii = "{} ({})" . format ( IIi1i1II1iIiI , igmp_types [ IIi1i1II1iIiI ] ) if igmp_types . has_key ( IIi1i1II1iIiI ) else IIi1i1II1iIiI
  if 44 - 44: i11iIiiIii % OoooooooOO
  lprint ( "IGMP type {} not supported" . format ( Iiii1Iii ) )
  return ( [ ] )
  if 77 - 77: OoooooooOO / oO0o * I1IiiI . II111iiii
  if 78 - 78: OoooooooOO
 if ( len ( II1 ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 45 - 45: IiII + i1IIi - OOooOOo
  if 74 - 74: oO0o * oO0o . I11i
  if 70 - 70: Ii1I % OoOoOO00 * Oo0Ooo * O0 + OoO0O00 / I1IiiI
  if 67 - 67: OoO0O00 * iIii1I11I1II1
  if 2 - 2: I1ii11iIi11i * iII111i . iIii1I11I1II1 * Oo0Ooo
 if ( IIi1i1II1iIiI == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( iiiii1I1III1 , False ) ) )
  return ( [ [ None , iiiii1I1III1 , False ] ] )
  if 34 - 34: i11iIiiIii % O0 . I1IiiI / ooOoO0o + OoO0O00
 if ( IIi1i1II1iIiI in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( IIi1i1II1iIiI == 0x12 ) else 2 , bold ( iiiii1I1III1 , False ) ) )
  if 28 - 28: Ii1I / iIii1I11I1II1
  if 41 - 41: iIii1I11I1II1
  if 57 - 57: I1Ii111 * o0oOOo0O0Ooo - o0oOOo0O0Ooo * I11i
  if 89 - 89: Ii1I % O0
  if 81 - 81: OoooooooOO / II111iiii - ooOoO0o
  if ( iiiii1I1III1 . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
  else :
   return ( [ [ None , iiiii1I1III1 , True ] ] )
   if 14 - 14: O0
   if 59 - 59: I11i % II111iiii . iIii1I11I1II1 * oO0o % Ii1I
   if 79 - 79: OoooooooOO . II111iiii
   if 55 - 55: II111iiii
   if 2 - 2: I1ii11iIi11i * i1IIi + OOooOOo / OoO0O00 % OoOoOO00 / O0
  return ( [ ] )
  if 47 - 47: OoooooooOO - i11iIiiIii - IiII * O0 * iII111i * Ii1I
  if 36 - 36: I1Ii111
  if 85 - 85: Oo0Ooo % OOooOOo
  if 10 - 10: O0 + Oo0Ooo + Ii1I % IiII
  if 89 - 89: oO0o / iII111i + OOooOOo
 iIiI1IIi1Ii1i = iiIoOOOOoo0O00o . address
 II1 = II1 [ 8 : : ]
 if 27 - 27: Ii1I / o0oOOo0O0Ooo % I11i
 oooo0oo0o00 = "BBHI"
 OOo0oOOO0ooO = struct . calcsize ( oooo0oo0o00 )
 o0OoO0 = "I"
 Oo0oo0000O = struct . calcsize ( o0OoO0 )
 iIiI111ii1Ii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 16 - 16: Ii1I . I1ii11iIi11i
 if 28 - 28: iII111i
 if 74 - 74: Ii1I + I1IiiI * iII111i / i11iIiiIii - ooOoO0o * OoooooooOO
 if 98 - 98: I1IiiI
 Oo0o0ooo0oo0 = [ ]
 for OoOOoO0oOo in range ( iIiI1IIi1Ii1i ) :
  if ( len ( II1 ) < OOo0oOOO0ooO ) : return
  III111I , Ii1i1I1Ii , o0oo0Oo0Oo00 , iIIiiiI = struct . unpack ( oooo0oo0o00 ,
 II1 [ : OOo0oOOO0ooO ] )
  if 1 - 1: i1IIi + iII111i - O0 - o0oOOo0O0Ooo
  II1 = II1 [ OOo0oOOO0ooO : : ]
  if 23 - 23: I1ii11iIi11i . OoO0O00 + OOooOOo % OoOoOO00 * o0oOOo0O0Ooo % OoOoOO00
  if ( lisp_igmp_record_types . has_key ( III111I ) == False ) :
   lprint ( "Invalid record type {}" . format ( III111I ) )
   continue
   if 96 - 96: iIii1I11I1II1 . iII111i + IiII
   if 51 - 51: Ii1I
  o0O0oo = lisp_igmp_record_types [ III111I ]
  o0oo0Oo0Oo00 = socket . ntohs ( o0oo0Oo0Oo00 )
  iiIoOOOOoo0O00o . address = socket . ntohl ( iIIiiiI )
  iiiii1I1III1 = iiIoOOOOoo0O00o . print_address_no_iid ( )
  if 63 - 63: I1IiiI + OoOoOO00
  lprint ( "Record type: {}, group: {}, source-count: {}" . format ( o0O0oo , iiiii1I1III1 , o0oo0Oo0Oo00 ) )
  if 55 - 55: o0oOOo0O0Ooo
  if 95 - 95: OoO0O00 * ooOoO0o * oO0o % Oo0Ooo
  if 36 - 36: I1IiiI - Ii1I + oO0o . iIii1I11I1II1
  if 47 - 47: Ii1I
  if 12 - 12: I1IiiI / IiII + OoOoOO00 . I1Ii111 / I1Ii111
  if 97 - 97: OOooOOo - iII111i . I1IiiI * oO0o . OoOoOO00 * IiII
  if 29 - 29: iIii1I11I1II1
  O00oOoo00 = False
  if ( III111I in ( 1 , 5 ) ) : O00oOoo00 = True
  if ( III111I in ( 2 , 4 ) and o0oo0Oo0Oo00 == 0 ) : O00oOoo00 = True
  IIiI1i1 = "join" if ( O00oOoo00 ) else "leave"
  if 54 - 54: OoOoOO00 / Ii1I
  if 84 - 84: Oo0Ooo / OoO0O00 . o0oOOo0O0Ooo - iII111i . iII111i - II111iiii
  if 99 - 99: I1Ii111 % Oo0Ooo
  if 61 - 61: OoooooooOO % i11iIiiIii + OOooOOo
  if ( iiiii1I1III1 . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   continue
   if 53 - 53: iII111i . iIii1I11I1II1
   if 59 - 59: II111iiii . II111iiii - iII111i
   if 46 - 46: oO0o / iIii1I11I1II1 + OoO0O00
   if 33 - 33: Ii1I . iIii1I11I1II1 . O0 * I1ii11iIi11i . OoOoOO00 / i11iIiiIii
   if 85 - 85: iII111i
   if 23 - 23: O0
   if 83 - 83: i11iIiiIii % OoooooooOO
   if 45 - 45: OoO0O00 + Ii1I
  if ( o0oo0Oo0Oo00 == 0 ) :
   Oo0o0ooo0oo0 . append ( [ None , iiiii1I1III1 , O00oOoo00 ] )
   lprint ( "IGMPv3 {} (*, {})" . format ( bold ( IIiI1i1 , False ) ,
 bold ( iiiii1I1III1 , False ) ) )
   if 90 - 90: O0 * i1IIi . i1IIi * I1ii11iIi11i + I1ii11iIi11i / i1IIi
   if 52 - 52: O0 / iIii1I11I1II1 * IiII
   if 50 - 50: oO0o . Ii1I . OoooooooOO * o0oOOo0O0Ooo
   if 25 - 25: o0oOOo0O0Ooo % ooOoO0o
   if 91 - 91: I1Ii111 * i11iIiiIii / o0oOOo0O0Ooo * oO0o - o0oOOo0O0Ooo * OOooOOo
  for O0O0Oo in range ( o0oo0Oo0Oo00 ) :
   if ( len ( II1 ) < Oo0oo0000O ) : return
   iIIiiiI = struct . unpack ( o0OoO0 , II1 [ : Oo0oo0000O ] ) [ 0 ]
   iIiI111ii1Ii . address = socket . ntohl ( iIIiiiI )
   iiiI11Ii1 = iIiI111ii1Ii . print_address_no_iid ( )
   Oo0o0ooo0oo0 . append ( [ iiiI11Ii1 , iiiii1I1III1 , O00oOoo00 ] )
   lprint ( "{} ({}, {})" . format ( IIiI1i1 ,
 green ( iiiI11Ii1 , False ) , bold ( iiiii1I1III1 , False ) ) )
   II1 = II1 [ Oo0oo0000O : : ]
   if 61 - 61: i1IIi
   if 23 - 23: OoOoOO00
   if 2 - 2: II111iiii * OoOoOO00 . iIii1I11I1II1 . ooOoO0o . ooOoO0o + iII111i
   if 60 - 60: I1ii11iIi11i / I1ii11iIi11i
   if 44 - 44: i11iIiiIii / ooOoO0o - iIii1I11I1II1 + OoO0O00
   if 62 - 62: i1IIi / I1Ii111 + ooOoO0o
   if 80 - 80: iII111i + OoO0O00 % OoO0O00
   if 4 - 4: OoOoOO00 * I11i * O0 . OoooooooOO + Ii1I % i1IIi
 return ( Oo0o0ooo0oo0 )
 if 11 - 11: OoOoOO00 % i11iIiiIii . OoOoOO00 % Oo0Ooo * Ii1I
 if 67 - 67: IiII - OoOoOO00 / I1Ii111 % oO0o % OOooOOo
 if 19 - 19: OoO0O00 - iII111i
 if 76 - 76: OoOoOO00 * ooOoO0o - iII111i * I1IiiI + I11i
 if 4 - 4: Oo0Ooo
 if 95 - 95: Oo0Ooo * i11iIiiIii - O0
 if 100 - 100: iIii1I11I1II1 / I1ii11iIi11i - o0oOOo0O0Ooo / iII111i
 if 73 - 73: OoooooooOO
lisp_geid = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
if 68 - 68: II111iiii / i11iIiiIii % i11iIiiIii % OoooooooOO
def lisp_glean_map_cache ( seid , rloc , encap_port , igmp ) :
 if 81 - 81: i1IIi + O0 . IiII . I1IiiI / ooOoO0o
 if 75 - 75: I1ii11iIi11i / OoOoOO00
 if 59 - 59: OoO0O00 . OoooooooOO % IiII
 if 35 - 35: I1ii11iIi11i + I1Ii111
 if 25 - 25: iIii1I11I1II1 / I11i % OoooooooOO / Oo0Ooo
 if 4 - 4: i1IIi % i1IIi % oO0o
 oOoO0OoOOooo = True
 ooOoOO0Oo = lisp_map_cache . lookup_cache ( seid , True )
 if ( ooOoOO0Oo and len ( ooOoOO0Oo . rloc_set ) != 0 ) :
  ooOoOO0Oo . last_refresh_time = lisp_get_timestamp ( )
  if 95 - 95: iII111i . OOooOOo - O0 . II111iiii - Oo0Ooo
  II1I11iiI1iii = ooOoOO0Oo . rloc_set [ 0 ]
  OO00Ooo = II1I11iiI1iii . rloc
  IiiIiiiI1i1iI = II1I11iiI1iii . translated_port
  oOoO0OoOOooo = ( OO00Ooo . is_exact_match ( rloc ) == False or
 IiiIiiiI1i1iI != encap_port )
  if 53 - 53: iIii1I11I1II1 . Ii1I / Ii1I % I1ii11iIi11i % I1Ii111
  if ( oOoO0OoOOooo ) :
   I1i = green ( seid . print_address ( ) , False )
   iiiI1I = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
   lprint ( "Change gleaned EID {} to RLOC {}" . format ( I1i , iiiI1I ) )
   II1I11iiI1iii . delete_from_rloc_probe_list ( ooOoOO0Oo . eid , ooOoOO0Oo . group )
   lisp_change_gleaned_multicast ( seid , rloc , encap_port )
   if 13 - 13: I11i + O0 * oO0o - II111iiii
 else :
  ooOoOO0Oo = lisp_mapping ( "" , "" , [ ] )
  ooOoOO0Oo . eid . copy_address ( seid )
  ooOoOO0Oo . mapping_source . copy_address ( rloc )
  ooOoOO0Oo . map_cache_ttl = LISP_GLEAN_TTL
  ooOoOO0Oo . gleaned = True
  I1i = green ( seid . print_address ( ) , False )
  iiiI1I = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( I1i , iiiI1I ) )
  ooOoOO0Oo . add_cache ( )
  if 4 - 4: I11i
  if 5 - 5: Oo0Ooo - iII111i % iIii1I11I1II1 * OoOoOO00
  if 41 - 41: i1IIi * IiII - i11iIiiIii / O0 + Oo0Ooo + ooOoO0o
  if 94 - 94: OoO0O00 . O0 + iIii1I11I1II1 . oO0o % oO0o
  if 7 - 7: I1ii11iIi11i * oO0o / OoOoOO00
 if ( oOoO0OoOOooo ) :
  O0O0OOo0O = lisp_rloc ( )
  O0O0OOo0O . store_translated_rloc ( rloc , encap_port )
  O0O0OOo0O . add_to_rloc_probe_list ( ooOoOO0Oo . eid , ooOoOO0Oo . group )
  O0O0OOo0O . priority = 253
  O0O0OOo0O . mpriority = 255
  oOO000OOO = [ O0O0OOo0O ]
  ooOoOO0Oo . rloc_set = oOO000OOO
  ooOoOO0Oo . build_best_rloc_set ( )
  if 89 - 89: OoO0O00 / oO0o % I11i - I1ii11iIi11i . o0oOOo0O0Ooo
  if 46 - 46: i11iIiiIii
  if 99 - 99: i11iIiiIii / oO0o / OoOoOO00 / O0 * I1ii11iIi11i
  if 72 - 72: ooOoO0o - I1Ii111 - iIii1I11I1II1 . I1IiiI
  if 77 - 77: Oo0Ooo * OoO0O00
 if ( igmp == None ) : return
 if 67 - 67: OoOoOO00 . I1Ii111 / I1IiiI * II111iiii
 if 45 - 45: I1ii11iIi11i * o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo
 if 58 - 58: OOooOOo + O0
 if 19 - 19: o0oOOo0O0Ooo
 if 8 - 8: OOooOOo * OOooOOo - Ii1I * OoOoOO00 % OoO0O00 * O0
 lisp_geid . instance_id = seid . instance_id
 if 70 - 70: I1IiiI
 if 17 - 17: I11i % OOooOOo - i11iIiiIii . OoooooooOO % OoO0O00 + OoO0O00
 if 24 - 24: Ii1I . OOooOOo . IiII / Oo0Ooo . Oo0Ooo . II111iiii
 if 63 - 63: ooOoO0o . I11i
 if 39 - 39: II111iiii % oO0o % I1IiiI - iIii1I11I1II1 / I1IiiI
 o0O0O0OoO = lisp_process_igmp_packet ( igmp )
 if ( type ( o0O0O0OoO ) == bool ) : return
 if 94 - 94: iII111i + oO0o
 for iIiI111ii1Ii , iiIoOOOOoo0O00o , O00oOoo00 in o0O0O0OoO :
  if ( iIiI111ii1Ii != None ) : continue
  if 43 - 43: iIii1I11I1II1 + iIii1I11I1II1
  if 8 - 8: iIii1I11I1II1
  if 30 - 30: OOooOOo - I1ii11iIi11i * iIii1I11I1II1 + Oo0Ooo
  if 25 - 25: IiII
  lisp_geid . store_address ( iiIoOOOOoo0O00o )
  o00000o , Ii1i1I1Ii , I1iI1 = lisp_allow_gleaning ( seid , lisp_geid , rloc )
  if ( o00000o == False ) : continue
  if 78 - 78: OoOoOO00 * iIii1I11I1II1 * ooOoO0o - OoooooooOO - IiII
  if ( O00oOoo00 ) :
   lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port ,
 True )
  else :
   lisp_remove_gleaned_multicast ( seid , lisp_geid )
   if 40 - 40: OoO0O00 . i11iIiiIii + ooOoO0o
   if 30 - 30: OOooOOo . OoO0O00 % iII111i - OoO0O00 % i11iIiiIii
   if 28 - 28: Ii1I + Oo0Ooo / iIii1I11I1II1
   if 57 - 57: o0oOOo0O0Ooo
   if 23 - 23: II111iiii
   if 88 - 88: I1IiiI / II111iiii * i11iIiiIii - oO0o - OOooOOo
   if 41 - 41: iIii1I11I1II1
   if 7 - 7: Oo0Ooo + iII111i . ooOoO0o
   if 31 - 31: iIii1I11I1II1 - OoOoOO00 - II111iiii / I1ii11iIi11i
   if 70 - 70: iIii1I11I1II1 / I1ii11iIi11i . I1Ii111 % I1ii11iIi11i
   if 40 - 40: I1Ii111 + o0oOOo0O0Ooo - I11i + OoO0O00
   if 49 - 49: i11iIiiIii % OoO0O00 - Ii1I + I1Ii111
def lisp_is_json_telemetry ( json_string ) :
 try :
  I111I1Ii = json . loads ( json_string )
  if ( type ( I111I1Ii ) != dict ) : return ( None )
 except :
  lprint ( "Could not decode telemetry json: {}" . format ( json_string ) )
  return ( None )
  if 7 - 7: ooOoO0o * I1ii11iIi11i - Ii1I % i1IIi + I11i
  if 22 - 22: I1IiiI - OOooOOo - II111iiii * I1IiiI
 if ( I111I1Ii . has_key ( "type" ) == False ) : return ( None )
 if ( I111I1Ii . has_key ( "sub-type" ) == False ) : return ( None )
 if ( I111I1Ii [ "type" ] != "telemetry" ) : return ( None )
 if ( I111I1Ii [ "sub-type" ] != "timestamps" ) : return ( None )
 return ( I111I1Ii )
 if 93 - 93: OOooOOo + I11i
 if 93 - 93: I1IiiI . I1ii11iIi11i * iII111i
 if 25 - 25: Oo0Ooo + o0oOOo0O0Ooo + OoOoOO00
 if 76 - 76: Oo0Ooo * Oo0Ooo + o0oOOo0O0Ooo % I11i + Oo0Ooo / o0oOOo0O0Ooo
 if 76 - 76: OOooOOo . ooOoO0o * iII111i . oO0o
 if 80 - 80: i1IIi . Ii1I
 if 59 - 59: OOooOOo . I11i
 if 88 - 88: i11iIiiIii / I1ii11iIi11i . I11i % OOooOOo
 if 75 - 75: ooOoO0o - OOooOOo
 if 97 - 97: i11iIiiIii / I11i % II111iiii
 if 20 - 20: I1Ii111 + OoooooooOO . o0oOOo0O0Ooo - ooOoO0o
 if 61 - 61: i11iIiiIii + OoooooooOO
def lisp_encode_telemetry ( json_string , ii = "?" , io = "?" , ei = "?" , eo = "?" ) :
 I111I1Ii = lisp_is_json_telemetry ( json_string )
 if ( I111I1Ii == None ) : return ( json_string )
 if 7 - 7: I1IiiI * OoO0O00 * I1IiiI
 if ( I111I1Ii [ "itr-in" ] == "?" ) : I111I1Ii [ "itr-in" ] = ii
 if ( I111I1Ii [ "itr-out" ] == "?" ) : I111I1Ii [ "itr-out" ] = io
 if ( I111I1Ii [ "etr-in" ] == "?" ) : I111I1Ii [ "etr-in" ] = ei
 if ( I111I1Ii [ "etr-out" ] == "?" ) : I111I1Ii [ "etr-out" ] = eo
 json_string = json . dumps ( I111I1Ii )
 return ( json_string )
 if 50 - 50: I1ii11iIi11i
 if 88 - 88: IiII
 if 55 - 55: Oo0Ooo + OOooOOo + IiII
 if 55 - 55: O0 . I1Ii111 * I1ii11iIi11i * o0oOOo0O0Ooo - ooOoO0o
 if 17 - 17: OOooOOo
 if 66 - 66: O0 - i11iIiiIii * O0 / iII111i . I1Ii111 / IiII
 if 96 - 96: OoOoOO00 / i11iIiiIii - OoooooooOO / II111iiii * i1IIi
 if 82 - 82: iII111i
 if 55 - 55: OoOoOO00 + I1ii11iIi11i % ooOoO0o % I1Ii111 . i1IIi % OOooOOo
 if 21 - 21: OoO0O00 / Ii1I . IiII
 if 35 - 35: i1IIi
 if 58 - 58: Ii1I - IiII / ooOoO0o % o0oOOo0O0Ooo + I1ii11iIi11i
def lisp_decode_telemetry ( json_string ) :
 I111I1Ii = lisp_is_json_telemetry ( json_string )
 if ( I111I1Ii == None ) : return ( { } )
 return ( I111I1Ii )
 if 89 - 89: IiII / OoooooooOO
 if 13 - 13: II111iiii . OOooOOo - O0 * oO0o
 if 71 - 71: ooOoO0o % ooOoO0o + o0oOOo0O0Ooo + iII111i / OoOoOO00
 if 27 - 27: I1ii11iIi11i * OoO0O00 - OoO0O00
 if 87 - 87: I1IiiI * I11i + iIii1I11I1II1 % i1IIi
 if 6 - 6: o0oOOo0O0Ooo
 if 94 - 94: I1ii11iIi11i * i11iIiiIii
 if 95 - 95: OoooooooOO - II111iiii . I1Ii111
 if 97 - 97: i1IIi * iIii1I11I1II1
def lisp_telemetry_configured ( ) :
 if ( lisp_json_list . has_key ( "telemetry" ) == False ) : return ( None )
 if 44 - 44: O0 - o0oOOo0O0Ooo - I1Ii111 % O0
 i11i = lisp_json_list [ "telemetry" ] . json_string
 if ( lisp_is_json_telemetry ( i11i ) == None ) : return ( None )
 if 31 - 31: i11iIiiIii - I11i
 return ( i11i )
 if 91 - 91: I11i - iII111i
 if 35 - 35: I1IiiI * I11i + I11i
 if 67 - 67: I1ii11iIi11i - I1IiiI + Ii1I * Ii1I + Oo0Ooo
 if 41 - 41: i11iIiiIii
 if 97 - 97: i1IIi / Ii1I / ooOoO0o . Ii1I - ooOoO0o + oO0o
 if 27 - 27: OOooOOo % O0
 if 96 - 96: OoooooooOO / OOooOOo
def lisp_mr_or_pubsub ( action ) :
 return ( action in [ LISP_SEND_MAP_REQUEST_ACTION , LISP_SEND_PUBSUB_ACTION ] )
 if 87 - 87: IiII - OoooooooOO
 if 53 - 53: OoOoOO00 + Oo0Ooo
 if 33 - 33: I11i - OOooOOo + Oo0Ooo - iII111i * iII111i
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
