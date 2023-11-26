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
from __future__ import division
from future import standard_library
standard_library . install_aliases ( )
from builtins import hex
from builtins import str
from builtins import int
from builtins import range
from builtins import object
from past . utils import old_div
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
from subprocess import getoutput
import queue
import distro
import pprint
if 64 - 64: i11iIiiIii
if 65 - 65: O0 / iIii1I11I1II1 % OoooooooOO - i1IIi
if 73 - 73: II111iiii
if 22 - 22: I1IiiI * Oo0Ooo / OoO0O00 . OoOoOO00 . o0oOOo0O0Ooo / I1ii11iIi11i
lisp_print_rloc_probe_list = False
if 48 - 48: oO0o / OOooOOo / I11i / Ii1I
if 48 - 48: iII111i % IiII + I1Ii111 / ooOoO0o * Ii1I
if 46 - 46: ooOoO0o * I11i - OoooooooOO
if 30 - 30: o0oOOo0O0Ooo - O0 % o0oOOo0O0Ooo - OoooooooOO * O0 * OoooooooOO
if 60 - 60: iIii1I11I1II1 / i1IIi * oO0o - I1ii11iIi11i + o0oOOo0O0Ooo
if 94 - 94: i1IIi % Oo0Ooo
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
if 68 - 68: Ii1I / O0
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
if 46 - 46: O0 * II111iiii / IiII * Oo0Ooo * iII111i . I11i
if 62 - 62: i11iIiiIii - II111iiii % I1Ii111 - iIii1I11I1II1 . I1ii11iIi11i . II111iiii
if 61 - 61: oO0o / OoOoOO00 / iII111i * OoO0O00 . II111iiii
if 1 - 1: II111iiii - I1ii11iIi11i % i11iIiiIii + IiII . I1Ii111
if 55 - 55: iIii1I11I1II1 - I1IiiI . Ii1I * IiII * i1IIi / iIii1I11I1II1
lisp_myinterfaces = { }
lisp_iid_to_interface = { }
lisp_multi_tenant_interfaces = [ ]
if 79 - 79: oO0o + I1Ii111 . ooOoO0o * IiII % I11i . I1IiiI
lisp_test_mr_timer = None
lisp_rloc_probe_timer = None
if 94 - 94: iII111i * Ii1I / IiII . i1IIi * iII111i
if 47 - 47: i1IIi % i11iIiiIii
if 20 - 20: ooOoO0o * II111iiii
if 65 - 65: o0oOOo0O0Ooo * iIii1I11I1II1 * ooOoO0o
lisp_registered_count = 0
if 18 - 18: iIii1I11I1II1 / I11i + oO0o / Oo0Ooo - II111iiii - I11i
if 1 - 1: I11i - OOooOOo % O0 + I1IiiI - iII111i / I11i
if 31 - 31: OoO0O00 + II111iiii
if 13 - 13: OOooOOo * oO0o * I1IiiI
lisp_info_sources_by_address = { }
lisp_info_sources_by_nonce = { }
if 55 - 55: II111iiii
if 43 - 43: OoOoOO00 - i1IIi + I1Ii111 + Ii1I
if 17 - 17: o0oOOo0O0Ooo
if 64 - 64: Ii1I % i1IIi % OoooooooOO
if 3 - 3: iII111i + O0
if 42 - 42: OOooOOo / i1IIi + i11iIiiIii - Ii1I
lisp_crypto_keys_by_nonce = { }
lisp_crypto_keys_by_rloc_encap = { }
lisp_crypto_keys_by_rloc_decap = { }
lisp_data_plane_security = False
lisp_search_decap_keys = True
if 78 - 78: OoO0O00
lisp_data_plane_logging = False
lisp_frame_logging = False
lisp_flow_logging = False
if 18 - 18: O0 - iII111i / iII111i + ooOoO0o % ooOoO0o - IiII
if 62 - 62: iII111i - IiII - OoOoOO00 % i1IIi / oO0o
if 77 - 77: II111iiii - II111iiii . I1IiiI / o0oOOo0O0Ooo
if 14 - 14: I11i % O0
if 41 - 41: i1IIi + I1Ii111 + OOooOOo - IiII
if 77 - 77: Oo0Ooo . IiII % ooOoO0o
if 42 - 42: oO0o - i1IIi / i11iIiiIii + OOooOOo + OoO0O00
lisp_crypto_ephem_port = None
if 17 - 17: oO0o . Oo0Ooo . I1ii11iIi11i
if 3 - 3: OoOoOO00 . Oo0Ooo . I1IiiI / Ii1I
if 38 - 38: II111iiii % i11iIiiIii . ooOoO0o - OOooOOo + Ii1I
if 66 - 66: OoooooooOO * OoooooooOO . OOooOOo . i1IIi - OOooOOo
lisp_pitr = False
if 77 - 77: I11i - iIii1I11I1II1
if 82 - 82: i11iIiiIii . OOooOOo / Oo0Ooo * O0 % oO0o % iIii1I11I1II1
if 78 - 78: iIii1I11I1II1 - Ii1I * OoO0O00 + o0oOOo0O0Ooo + iII111i + iII111i
if 11 - 11: iII111i - OoO0O00 % ooOoO0o % iII111i / OoOoOO00 - OoO0O00
lisp_l2_overlay = False
if 74 - 74: iII111i * O0
if 89 - 89: oO0o + Oo0Ooo
if 3 - 3: i1IIi / I1IiiI % I11i * i11iIiiIii / O0 * I11i
if 49 - 49: oO0o % Ii1I + i1IIi . I1IiiI % I1ii11iIi11i
if 48 - 48: I11i + I11i / II111iiii / iIii1I11I1II1
lisp_rloc_probing = False
lisp_rloc_probe_list = { }
lisp_rloc_probe_nonce_list = { }
if 20 - 20: o0oOOo0O0Ooo
if 77 - 77: OoOoOO00 / I11i
if 98 - 98: iIii1I11I1II1 / i1IIi / i11iIiiIii / o0oOOo0O0Ooo
if 28 - 28: OOooOOo - IiII . IiII + OoOoOO00 - OoooooooOO + O0
if 95 - 95: OoO0O00 % oO0o . O0
if 15 - 15: ooOoO0o / Ii1I . Ii1I - i1IIi
lisp_register_all_rtrs = True
if 53 - 53: IiII + I1IiiI * oO0o
if 61 - 61: i1IIi * OOooOOo / OoooooooOO . i11iIiiIii . OoOoOO00
if 60 - 60: I11i / I11i
if 46 - 46: Ii1I * OOooOOo - OoO0O00 * oO0o - I1Ii111
lisp_nonce_echoing = False
lisp_nonce_echo_list = { }
if 83 - 83: OoooooooOO
if 31 - 31: II111iiii - OOooOOo . I1Ii111 % OoOoOO00 - O0
if 4 - 4: II111iiii / ooOoO0o . iII111i
if 58 - 58: OOooOOo * i11iIiiIii / OoOoOO00 % I1Ii111 - I1ii11iIi11i / oO0o
lisp_nat_traversal = False
lisp_decent_nat = False
LISP_TP = "@tp-"
if 50 - 50: I1IiiI
if 34 - 34: I1IiiI * II111iiii % iII111i * OoOoOO00 - I1IiiI
if 33 - 33: o0oOOo0O0Ooo + OOooOOo * OoO0O00 - Oo0Ooo / oO0o % Ii1I
if 21 - 21: OoO0O00 * iIii1I11I1II1 % oO0o * i1IIi
if 16 - 16: O0 - I1Ii111 * iIii1I11I1II1 + iII111i
if 50 - 50: II111iiii - ooOoO0o * I1ii11iIi11i / I1Ii111 + o0oOOo0O0Ooo
if 88 - 88: Ii1I / I1Ii111 + iII111i - II111iiii / ooOoO0o - OoOoOO00
if 15 - 15: I1ii11iIi11i + OoOoOO00 - OoooooooOO / OOooOOo
lisp_program_hardware = False
if 58 - 58: i11iIiiIii % I11i
if 71 - 71: OOooOOo + ooOoO0o % i11iIiiIii + I1ii11iIi11i - IiII
if 88 - 88: OoOoOO00 - OoO0O00 % OOooOOo
if 16 - 16: I1IiiI * oO0o % IiII
lisp_checkpoint_map_cache = False
lisp_checkpoint_filename = "./lisp.checkpoint"
if 86 - 86: I1IiiI + Ii1I % i11iIiiIii * oO0o . ooOoO0o * I11i
if 44 - 44: oO0o
if 88 - 88: I1Ii111 % Ii1I . II111iiii
if 38 - 38: o0oOOo0O0Ooo
lisp_ipc_data_plane = False
lisp_ipc_dp_socket = None
lisp_ipc_dp_socket_name = "lisp-ipc-data-plane"
if 57 - 57: O0 / oO0o * I1Ii111 / OoOoOO00 . II111iiii
if 26 - 26: iII111i
if 91 - 91: OoO0O00 . I1ii11iIi11i + OoO0O00 - iII111i / OoooooooOO
if 39 - 39: I1ii11iIi11i / ooOoO0o - II111iiii
if 98 - 98: I1ii11iIi11i / I11i % oO0o . OoOoOO00
lisp_ipc_lock = None
if 91 - 91: oO0o % Oo0Ooo
if 64 - 64: I11i % iII111i - I1Ii111 - oO0o
if 31 - 31: I11i - II111iiii . I11i
if 18 - 18: o0oOOo0O0Ooo
if 98 - 98: iII111i * iII111i / iII111i + I11i
if 34 - 34: ooOoO0o
lisp_default_iid = 0
lisp_default_secondary_iid = 0
if 15 - 15: I11i * ooOoO0o * Oo0Ooo % i11iIiiIii % OoOoOO00 - OOooOOo
if 68 - 68: I1Ii111 % i1IIi . IiII . I1ii11iIi11i
if 92 - 92: iII111i . I1Ii111
if 31 - 31: I1Ii111 . OoOoOO00 / O0
if 89 - 89: OoOoOO00
lisp_ms_rtr_list = [ ]
if 68 - 68: OoO0O00 * OoooooooOO % O0 + OoO0O00 + ooOoO0o
if 4 - 4: ooOoO0o + O0 * OOooOOo
if 55 - 55: Oo0Ooo + iIii1I11I1II1 / OoOoOO00 * oO0o - i11iIiiIii - Ii1I
if 25 - 25: I1ii11iIi11i
if 7 - 7: i1IIi / I1IiiI * I1Ii111 . IiII . iIii1I11I1II1
if 13 - 13: OOooOOo / i11iIiiIii
lisp_nat_state_info = { }
if 2 - 2: I1IiiI / O0 / o0oOOo0O0Ooo % OoOoOO00 % Ii1I
if 52 - 52: o0oOOo0O0Ooo
if 95 - 95: Ii1I
if 87 - 87: ooOoO0o + OoOoOO00 . OOooOOo + OoOoOO00
if 91 - 91: O0
if 61 - 61: II111iiii
lisp_last_map_request_sent = None
lisp_no_map_request_rate_limit = time . time ( )
if 64 - 64: ooOoO0o / OoOoOO00 - O0 - I11i
if 86 - 86: I11i % OoOoOO00 / I1IiiI / OoOoOO00
if 42 - 42: OoO0O00
if 67 - 67: I1Ii111 . iII111i . O0
lisp_last_icmp_too_big_sent = 0
if 10 - 10: I1ii11iIi11i % I1ii11iIi11i - iIii1I11I1II1 / OOooOOo + Ii1I
if 87 - 87: oO0o * I1ii11iIi11i + OOooOOo / iIii1I11I1II1 / iII111i
if 37 - 37: iII111i - ooOoO0o * oO0o % i11iIiiIii - I1Ii111
if 83 - 83: I11i / I1IiiI
LISP_FLOW_LOG_SIZE = 100
lisp_flow_log = [ ]
if 34 - 34: IiII
if 57 - 57: oO0o . I11i . i1IIi
if 42 - 42: I11i + I1ii11iIi11i % O0
if 6 - 6: oO0o
lisp_policies = { }
if 68 - 68: OoOoOO00 - OoO0O00
if 28 - 28: OoO0O00 . OOooOOo / OOooOOo + Oo0Ooo . I1ii11iIi11i
if 1 - 1: iIii1I11I1II1 / II111iiii
if 33 - 33: I11i
if 18 - 18: o0oOOo0O0Ooo % iII111i * O0
lisp_load_split_pings = False
if 87 - 87: i11iIiiIii
if 93 - 93: I1ii11iIi11i - OoO0O00 % i11iIiiIii . iII111i / iII111i - I1Ii111
if 9 - 9: I1ii11iIi11i / Oo0Ooo - I1IiiI / OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo
if 91 - 91: iII111i % i1IIi % iIii1I11I1II1
if 20 - 20: OOooOOo % Ii1I / Ii1I + Ii1I
if 45 - 45: oO0o - IiII - OoooooooOO - OoO0O00 . II111iiii / O0
lisp_eid_hashes = [ ]
if 51 - 51: O0 + iII111i
if 8 - 8: oO0o * OoOoOO00 - Ii1I - OoO0O00 * OOooOOo % I1IiiI
if 48 - 48: O0
if 11 - 11: I11i + OoooooooOO - OoO0O00 / o0oOOo0O0Ooo + Oo0Ooo . II111iiii
if 41 - 41: Ii1I - O0 - O0
if 68 - 68: OOooOOo % I1Ii111
if 88 - 88: iIii1I11I1II1 - ooOoO0o + OOooOOo
if 40 - 40: I1IiiI * Ii1I + OOooOOo % iII111i
lisp_reassembly_queue = { }
if 74 - 74: oO0o - Oo0Ooo + OoooooooOO + I1Ii111 / OoOoOO00
if 23 - 23: O0
if 85 - 85: Ii1I
if 84 - 84: I1IiiI . iIii1I11I1II1 % OoooooooOO + Ii1I % OoooooooOO % OoO0O00
if 42 - 42: OoO0O00 / I11i / o0oOOo0O0Ooo + iII111i / OoOoOO00
if 84 - 84: ooOoO0o * II111iiii + Oo0Ooo
if 53 - 53: iII111i % II111iiii . IiII - iIii1I11I1II1 - IiII * II111iiii
lisp_pubsub_cache = { }
if 77 - 77: iIii1I11I1II1 * OoO0O00
if 95 - 95: I1IiiI + i11iIiiIii
if 6 - 6: ooOoO0o / i11iIiiIii + iII111i * oO0o
if 80 - 80: II111iiii
if 83 - 83: I11i . i11iIiiIii + II111iiii . o0oOOo0O0Ooo * I11i
if 53 - 53: II111iiii
lisp_decent_push_configured = False
if 31 - 31: OoO0O00
if 80 - 80: I1Ii111 . i11iIiiIii - o0oOOo0O0Ooo
if 25 - 25: OoO0O00
if 62 - 62: OOooOOo + O0
if 98 - 98: o0oOOo0O0Ooo
if 51 - 51: Oo0Ooo - oO0o + II111iiii * Ii1I . I11i + oO0o
lisp_decent_modulus = 0
lisp_decent_dns_suffix = None
if 78 - 78: i11iIiiIii / iII111i - Ii1I / OOooOOo + oO0o
if 82 - 82: Ii1I
if 46 - 46: OoooooooOO . i11iIiiIii
if 94 - 94: o0oOOo0O0Ooo * Ii1I / Oo0Ooo / Ii1I
if 87 - 87: Oo0Ooo . IiII
if 75 - 75: ooOoO0o + OoOoOO00 + o0oOOo0O0Ooo * I11i % oO0o . iII111i
lisp_ipc_socket = None
if 55 - 55: OOooOOo . I1IiiI
if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
if 100 - 100: I1Ii111 * O0
if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
lisp_ms_encryption_keys = { }
lisp_ms_json_keys = { }
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
if 63 - 63: OoOoOO00 * iII111i
lisp_rtr_nat_trace_cache = { }
if 69 - 69: O0 . OoO0O00
if 49 - 49: I1IiiI - I11i
if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
if 62 - 62: OoooooooOO * I1IiiI
if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
if 97 - 97: O0 + OoOoOO00
if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
if 77 - 77: OOooOOo * iIii1I11I1II1
lisp_glean_mappings = [ ]
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
lisp_gleaned_groups = { }
if 26 - 26: Ii1I % I1ii11iIi11i
if 76 - 76: IiII * iII111i
if 52 - 52: OOooOOo
if 19 - 19: I1IiiI
if 25 - 25: Ii1I / ooOoO0o
lisp_icmp_raw_socket = None
if ( os . getenv ( "LISP_SEND_ICMP_TOO_BIG" ) != None ) :
 lisp_icmp_raw_socket = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_ICMP )
 lisp_icmp_raw_socket . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
 if 71 - 71: I1Ii111 . II111iiii
lisp_ignore_df_bit = ( os . getenv ( "LISP_IGNORE_DF_BIT" ) != None )
if 62 - 62: OoooooooOO . I11i
if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
if 58 - 58: I1IiiI
if 53 - 53: i1IIi
if 59 - 59: o0oOOo0O0Ooo
LISP_DATA_PORT = 4341
LISP_CTRL_PORT = 4342
LISP_L2_DATA_PORT = 8472
LISP_VXLAN_DATA_PORT = 4789
LISP_VXLAN_GPE_PORT = 4790
LISP_TRACE_PORT = 2434
if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
if 73 - 73: I11i % i11iIiiIii - I1IiiI
if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
LISP_MAP_REQUEST = 1
LISP_MAP_REPLY = 2
LISP_MAP_REGISTER = 3
LISP_MAP_NOTIFY = 4
LISP_MAP_NOTIFY_ACK = 5
LISP_MAP_REFERRAL = 6
LISP_NAT_INFO = 7
LISP_ECM = 8
LISP_TRACE = 9
if 23 - 23: i11iIiiIii
if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
if 81 - 81: IiII % i1IIi . iIii1I11I1II1
if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
LISP_NO_ACTION = 0
LISP_NATIVE_FORWARD_ACTION = 1
LISP_SEND_MAP_REQUEST_ACTION = 2
LISP_DROP_ACTION = 3
LISP_POLICY_DENIED_ACTION = 4
LISP_AUTH_FAILURE_ACTION = 5
LISP_SEND_PUBSUB_ACTION = 6
LISP_NOT_REGISTERED_YET_ACTION = 7
if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
lisp_map_reply_action_string = [ "no-action" , "native-forward" ,
 "send-map-request" , "drop-action" , "policy-denied" ,
 "auth-failure" , "send-subscribe" , "not-registered-yet" ]
if 31 - 31: OOooOOo
if 23 - 23: I1Ii111 . IiII
if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
if 42 - 42: Oo0Ooo
LISP_NONE_ALG_ID = 0
LISP_SHA_1_96_ALG_ID = 1
LISP_SHA_256_128_ALG_ID = 2
LISP_MD5_AUTH_DATA_LEN = 16
LISP_SHA1_160_AUTH_DATA_LEN = 20
LISP_SHA2_256_AUTH_DATA_LEN = 32
if 76 - 76: I1IiiI * iII111i % I1Ii111
if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
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
if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
if 42 - 42: I1IiiI
if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
LISP_MR_TTL = ( 24 * 60 )
LISP_REGISTER_TTL = 3
LISP_SHORT_TTL = 1
LISP_NMR_TTL = 15
LISP_GLEAN_TTL = 15
LISP_MCAST_TTL = 15
LISP_IGMP_TTL = 240
if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
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
LISP_RLOC_PROBE_TTL = 64
LISP_RLOC_PROBE_INTERVAL = 10
LISP_RLOC_PROBE_REPLY_WAIT = 15
LISP_DEFAULT_DYN_EID_TIMEOUT = 15
LISP_NONCE_ECHO_INTERVAL = 10
LISP_IGMP_TIMEOUT_INTERVAL = 180
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
LISP_CS_1024 = 0
LISP_CS_1024_G = 2
LISP_CS_1024_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 28 - 28: ooOoO0o + i11iIiiIii / I11i % OoOoOO00 % Oo0Ooo - O0
LISP_CS_2048_CBC = 1
LISP_CS_2048_CBC_G = 2
LISP_CS_2048_CBC_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 54 - 54: i1IIi + II111iiii
LISP_CS_25519_CBC = 2
LISP_CS_2048_GCM = 3
if 83 - 83: I1ii11iIi11i - I1IiiI + OOooOOo
LISP_CS_3072 = 4
LISP_CS_3072_G = 2
LISP_CS_3072_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
if 5 - 5: Ii1I
LISP_CS_25519_GCM = 5
LISP_CS_25519_CHACHA = 6
if 46 - 46: IiII
LISP_4_32_MASK = 0xFFFFFFFF
LISP_8_64_MASK = 0xFFFFFFFFFFFFFFFF
LISP_16_128_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
if 45 - 45: ooOoO0o
use_chacha = ( os . getenv ( "LISP_USE_CHACHA" ) != None )
use_poly = ( os . getenv ( "LISP_USE_POLY" ) != None )
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
 if ( distro . linux_distribution ( ) [ 0 ] != "debian" ) : return ( False )
 return ( platform . machine ( ) in [ "armv6l" , "armv7l" ] )
 if 71 - 71: II111iiii / i1IIi . I1ii11iIi11i % OoooooooOO . OoOoOO00
 if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 if 100 - 100: OoO0O00
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
def lisp_is_ubuntu ( ) :
 return ( distro . linux_distribution ( ) [ 0 ] == "Ubuntu" )
 if 83 - 83: OoOoOO00 . OoooooooOO
 if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
 if 62 - 62: OoO0O00 / I1ii11iIi11i
 if 7 - 7: OoooooooOO . IiII
 if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
 if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
 if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
def lisp_is_fedora ( ) :
 return ( distro . linux_distribution ( ) [ 0 ] == "fedora" )
 if 92 - 92: ooOoO0o
 if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
 if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
 if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
 if 92 - 92: I11i . I1Ii111
 if 85 - 85: I1ii11iIi11i . I1Ii111
 if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
def lisp_is_centos ( ) :
 return ( distro . linux_distribution ( ) [ 0 ] == "centos" )
 if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
 if 18 - 18: iIii1I11I1II1 % I11i
 if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
 if 75 - 75: OoooooooOO * IiII
 if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
 if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
 if 69 - 69: O0
def lisp_is_debian ( ) :
 return ( platform . linux_distribution ( ) [ 0 ] == "debian" )
 if 85 - 85: ooOoO0o / O0
 if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
 if 62 - 62: I1Ii111 . IiII . OoooooooOO
 if 11 - 11: OOooOOo / I11i
 if 73 - 73: i1IIi / i11iIiiIii
 if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
 if 85 - 85: OoOoOO00 + OOooOOo
def lisp_is_debian_kali ( ) :
 return ( distro . linux_distribution ( ) [ 0 ] == "Kali" )
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
def lisp_is_apple_m ( ) :
 i1i1IIii1i1 = platform . machine ( )
 return ( i1i1IIii1i1 == "aarch64" )
 if 9 - 9: I1IiiI % I1IiiI % II111iiii
 if 30 - 30: IiII + I1Ii111 - IiII . IiII - II111iiii + O0
 if 86 - 86: i1IIi
 if 41 - 41: OoOoOO00 * I11i / OoOoOO00 % oO0o
 if 18 - 18: II111iiii . OoooooooOO % OoOoOO00 % Ii1I
 if 9 - 9: OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 if 2 - 2: OoooooooOO % OOooOOo
def lisp_is_linux ( ) :
 return ( platform . uname ( ) [ 0 ] == "Linux" )
 if 63 - 63: I1IiiI % iIii1I11I1II1
 if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
 if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
 if 59 - 59: OOooOOo + i11iIiiIii
 if 88 - 88: i11iIiiIii - ooOoO0o
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
 if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
def lisp_is_python2 ( ) :
 Iii = sys . version . split ( ) [ 0 ]
 return ( Iii [ 0 : 3 ] == "2.7" )
 if 20 - 20: o0oOOo0O0Ooo / i1IIi
 if 71 - 71: OoOoOO00 . i1IIi
 if 94 - 94: OOooOOo . I1Ii111
 if 84 - 84: O0 . I11i - II111iiii . ooOoO0o / II111iiii
 if 47 - 47: OoooooooOO
 if 4 - 4: I1IiiI % I11i
 if 10 - 10: IiII . OoooooooOO - OoO0O00 + IiII - O0
def lisp_is_python3 ( ) :
 Iii = sys . version . split ( ) [ 0 ]
 return ( Iii [ 0 : 2 ] == "3." )
 if 82 - 82: ooOoO0o + II111iiii
 if 39 - 39: oO0o % iIii1I11I1II1 % O0 % OoooooooOO * I1ii11iIi11i + iII111i
 if 68 - 68: Oo0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 * iIii1I11I1II1 * i11iIiiIii + I1IiiI / OOooOOo % Ii1I
 if 58 - 58: OOooOOo * o0oOOo0O0Ooo + O0 % OOooOOo
 if 25 - 25: Oo0Ooo % I1ii11iIi11i * ooOoO0o
 if 6 - 6: iII111i . IiII * OoOoOO00 . i1IIi
def lisp_on_aws ( ) :
 oOOo = getoutput ( "sudo dmidecode -s bios-version" )
 if ( oOOo . find ( "command not found" ) != - 1 and lisp_on_docker ( ) ) :
  I1IiIIi = bold ( "AWS check" , False )
  lprint ( "{} - dmidecode not installed in docker container" . format ( I1IiIIi ) )
  if 42 - 42: O0 . oO0o - o0oOOo0O0Ooo / i1IIi
 return ( oOOo . lower ( ) . find ( "amazon" ) != - 1 )
 if 68 - 68: O0 + OoOoOO00 / oO0o - OOooOOo + iIii1I11I1II1 % Ii1I
 if 23 - 23: ooOoO0o % o0oOOo0O0Ooo / I11i
 if 5 - 5: iIii1I11I1II1
 if 72 - 72: oO0o . I1Ii111 / OoOoOO00 + I11i % iIii1I11I1II1
 if 42 - 42: I1ii11iIi11i * OoOoOO00 % ooOoO0o - OoOoOO00 . i11iIiiIii - I1Ii111
 if 84 - 84: I1Ii111 - I1ii11iIi11i / I11i
 if 13 - 13: IiII - Oo0Ooo - ooOoO0o
def lisp_on_gcp ( ) :
 oOOo = getoutput ( "sudo dmidecode -s bios-version" )
 if ( oOOo . find ( "command not found" ) != - 1 and lisp_on_docker ( ) ) :
  I1IiIIi = bold ( "GCP check" , False )
  lprint ( "{} - dmidecode not installed in docker container" . format ( I1IiIIi ) )
  if 92 - 92: ooOoO0o / OoOoOO00 * OoO0O00 . I11i % II111iiii
 return ( oOOo . lower ( ) . find ( "google" ) != - 1 )
 if 71 - 71: I1Ii111 % i1IIi - II111iiii - OOooOOo + OOooOOo * ooOoO0o
 if 51 - 51: iIii1I11I1II1 / OoOoOO00 + OOooOOo - I11i + iII111i
 if 29 - 29: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO % OoooooooOO % II111iiii / iII111i
 if 70 - 70: i11iIiiIii % iII111i
 if 11 - 11: IiII % I1ii11iIi11i % Ii1I / II111iiii % I1Ii111 - Oo0Ooo
 if 96 - 96: I1ii11iIi11i / II111iiii . Ii1I - iII111i * I11i * oO0o
 if 76 - 76: Ii1I - II111iiii * OOooOOo / OoooooooOO
def lisp_on_docker ( ) :
 return ( os . path . exists ( "/.dockerenv" ) )
 if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if 45 - 45: IiII
def lisp_process_logfile ( ) :
 Ii1Iii111IiI1 = "./logs/lisp-{}.log" . format ( lisp_log_id )
 if ( os . path . exists ( Ii1Iii111IiI1 ) ) : return
 if 98 - 98: I1Ii111 - OoooooooOO % I1IiiI + O0 . Ii1I
 sys . stdout . close ( )
 sys . stdout = open ( Ii1Iii111IiI1 , "a" )
 if 56 - 56: II111iiii / oO0o + i11iIiiIii + OOooOOo
 lisp_print_banner ( bold ( "logfile rotation" , False ) )
 return
 if 54 - 54: Ii1I - I11i - I1Ii111 . iIii1I11I1II1
 if 79 - 79: Ii1I . OoO0O00
 if 40 - 40: o0oOOo0O0Ooo + Oo0Ooo . o0oOOo0O0Ooo % ooOoO0o
 if 15 - 15: Ii1I * Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - i11iIiiIii
 if 60 - 60: I1IiiI * I1Ii111 % OoO0O00 + oO0o
 if 52 - 52: i1IIi
 if 84 - 84: Ii1I / IiII
 if 86 - 86: OoOoOO00 * II111iiii - O0 . OoOoOO00 % iIii1I11I1II1 / OOooOOo
def lisp_i_am ( name ) :
 global lisp_log_id , lisp_i_am_itr , lisp_i_am_etr , lisp_i_am_rtr
 global lisp_i_am_mr , lisp_i_am_ms , lisp_i_am_ddt , lisp_i_am_core
 global lisp_hostname
 if 11 - 11: I1IiiI * oO0o + I1ii11iIi11i / I1ii11iIi11i
 lisp_log_id = name
 if ( name == "itr" ) : lisp_i_am_itr = True
 if ( name == "etr" ) : lisp_i_am_etr = True
 if ( name == "rtr" ) : lisp_i_am_rtr = True
 if ( name == "mr" ) : lisp_i_am_mr = True
 if ( name == "ms" ) : lisp_i_am_ms = True
 if ( name == "ddt" ) : lisp_i_am_ddt = True
 if ( name == "core" ) : lisp_i_am_core = True
 if 37 - 37: i11iIiiIii + i1IIi
 if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
 if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
 if 8 - 8: o0oOOo0O0Ooo
 if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
 lisp_hostname = socket . gethostname ( )
 o00o = lisp_hostname . find ( "." )
 if ( o00o != - 1 ) : lisp_hostname = lisp_hostname [ 0 : o00o ]
 return
 if 47 - 47: o0oOOo0O0Ooo + iII111i - oO0o % OoooooooOO
 if 52 - 52: I1Ii111 / ooOoO0o - I11i
 if 49 - 49: OoOoOO00 / Oo0Ooo . i11iIiiIii
 if 21 - 21: OoOoOO00 + i11iIiiIii + I1IiiI * o0oOOo0O0Ooo % iII111i % II111iiii
 if 55 - 55: Oo0Ooo - OOooOOo
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 if 72 - 72: i1IIi
 if 82 - 82: OoOoOO00 + OoooooooOO / i11iIiiIii * I1ii11iIi11i . OoooooooOO
def lprint ( * args ) :
 oooo0OOo = ( "force" in args )
 if ( lisp_debug_logging == False and oooo0OOo == False ) : return
 if 72 - 72: O0 / ooOoO0o + OoooooooOO * iII111i
 lisp_process_logfile ( )
 Oo0OO0000oooo = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 Oo0OO0000oooo = Oo0OO0000oooo [ : - 3 ]
 print ( "{}: {}:" . format ( Oo0OO0000oooo , lisp_log_id ) , end = " " )
 if 61 - 61: OoooooooOO % II111iiii - I1IiiI % I1ii11iIi11i + i1IIi
 for i1II in args :
  if ( i1II == "force" ) : continue
  print ( i1II , end = " " )
  if 15 - 15: OoOoOO00
 print ( )
 if 62 - 62: Ii1I
 try : sys . stdout . flush ( )
 except : pass
 return
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if 53 - 53: Ii1I % Oo0Ooo
 if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
 if 41 - 41: Ii1I % I1ii11iIi11i
 if 12 - 12: OOooOOo
 if 69 - 69: OoooooooOO + OOooOOo
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
def fprint ( * args ) :
 i11I1I1iiI = args + ( "force" , )
 lprint ( * i11I1I1iiI )
 return
 if 34 - 34: I11i % ooOoO0o . O0 . iIii1I11I1II1
 if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
 if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
 if 4 - 4: OoooooooOO . ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if 10 - 10: I1Ii111 % I1IiiI
 if 97 - 97: OoooooooOO - I1Ii111
def dprint ( * args ) :
 if ( lisp_data_plane_logging ) : lprint ( * args )
 return
 if 58 - 58: iIii1I11I1II1 + O0
 if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
 if 46 - 46: i11iIiiIii - O0 . oO0o
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 if 83 - 83: I1Ii111
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 if 50 - 50: IiII % i1IIi
def cprint ( instance ) :
 print ( "{}:" . format ( instance ) )
 pprint . pprint ( instance . __dict__ )
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
 if 62 - 62: i1IIi - OoOoOO00
 if 62 - 62: i1IIi + Oo0Ooo % IiII
 if 28 - 28: I1ii11iIi11i . i1IIi
 if 10 - 10: OoO0O00 / Oo0Ooo
def debug ( * args ) :
 lisp_process_logfile ( )
 if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
 Oo0OO0000oooo = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 Oo0OO0000oooo = Oo0OO0000oooo [ : - 3 ]
 if 57 - 57: O0 % OoOoOO00 % oO0o
 print ( red ( ">>>" , False ) , end = " " )
 print ( "{}:" . format ( Oo0OO0000oooo ) , end = " " )
 for i1II in args : print ( i1II , end = " " )
 print ( red ( "<<<\n" , False ) )
 try : sys . stdout . flush ( )
 except : pass
 return
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 if 19 - 19: I11i
def lisp_print_caller ( ) :
 fprint ( traceback . print_last ( ) )
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
 if 89 - 89: II111iiii / oO0o
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
def lisp_print_banner ( string ) :
 global lisp_version , lisp_hostname
 if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 if ( lisp_version == "" ) :
  lisp_version = getoutput ( "cat lisp-version.txt" )
  if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 iI = bold ( lisp_hostname , False )
 lprint ( "lispers.net LISP {} {}, version {}, hostname {}" . format ( string ,
 datetime . datetime . now ( ) , lisp_version , iI ) )
 return
 if 19 - 19: II111iiii
 if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
 if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
 if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 if 32 - 32: i11iIiiIii - I1Ii111
 if 53 - 53: OoooooooOO - IiII
 if 87 - 87: oO0o . I1IiiI
def green ( string , html ) :
 if ( html ) : return ( '<font color="green"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[92m" + string + "\033[0m" , html ) )
 if 17 - 17: Ii1I . i11iIiiIii
 if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
 if 63 - 63: oO0o
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 if 36 - 36: IiII
 if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
 if 74 - 74: I1Ii111 % I1ii11iIi11i
def green_last_sec ( string ) :
 return ( green ( string , True ) )
 if 7 - 7: II111iiii
 if 27 - 27: oO0o . OoooooooOO + i11iIiiIii
 if 86 - 86: I11i / o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + oO0o
 if 33 - 33: o0oOOo0O0Ooo . iII111i . IiII . i1IIi
 if 49 - 49: I1ii11iIi11i
 if 84 - 84: I11i - Oo0Ooo / O0 - I1Ii111
 if 21 - 21: O0 * O0 % I1ii11iIi11i
def green_last_min ( string ) :
 return ( '<font color="#58D68D"><b>{}</b></font>' . format ( string ) )
 if 94 - 94: I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
 if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 if 34 - 34: ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
 if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
def red ( string , html ) :
 if ( html ) : return ( '<font color="red"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[91m" + string + "\033[0m" , html ) )
 if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
 if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
 if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
 if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
 if 23 - 23: I11i
def blue ( string , html ) :
 if ( html ) : return ( '<font color="blue"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[94m" + string + "\033[0m" , html ) )
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
def bold ( string , html ) :
 if ( html ) : return ( "<b>{}</b>" . format ( string ) )
 return ( "\033[1m" + string + "\033[0m" )
 if 53 - 53: I11i + iIii1I11I1II1
 if 70 - 70: I1ii11iIi11i
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
 if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
def convert_font ( string ) :
 I1I111iI = [ [ "[91m" , red ] , [ "[92m" , green ] , [ "[94m" , blue ] , [ "[1m" , bold ] ]
 iIiI1IIiii11 = "[0m"
 if 33 - 33: iIii1I11I1II1 / iII111i - I1IiiI * I11i
 for o0o00oO0oo000 in I1I111iI :
  oO000o = o0o00oO0oo000 [ 0 ]
  o0Oo = o0o00oO0oo000 [ 1 ]
  o0O0 = len ( oO000o )
  o00o = string . find ( oO000o )
  if ( o00o != - 1 ) : break
  if 48 - 48: I11i - IiII + iIii1I11I1II1 + OoooooooOO
  if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 while ( o00o != - 1 ) :
  oOoOo = string [ o00o : : ] . find ( iIiI1IIiii11 )
  oO0OO = string [ o00o + o0O0 : o00o + oOoOo ]
  string = string [ : o00o ] + o0Oo ( oO0OO , True ) + string [ o00o + oOoOo + o0O0 : : ]
  if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
  o00o = string . find ( oO000o )
  if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
  if 62 - 62: o0oOOo0O0Ooo
  if 15 - 15: I11i + Ii1I . OOooOOo * OoO0O00 . OoOoOO00
  if 18 - 18: i1IIi % II111iiii + I1Ii111 % Ii1I
  if 72 - 72: iIii1I11I1II1
 if ( string . find ( "[1m" ) != - 1 ) : string = convert_font ( string )
 return ( string )
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
 if 87 - 87: OoO0O00 % I1IiiI
 if 77 - 77: iIii1I11I1II1 - i1IIi . oO0o
 if 26 - 26: o0oOOo0O0Ooo * IiII . i1IIi
 if 59 - 59: O0 + i1IIi - o0oOOo0O0Ooo
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
def lisp_space ( num ) :
 ooOo0O0O0oOO0 = ""
 for iIiIIi in range ( num ) : ooOo0O0O0oOO0 += "&#160;"
 return ( ooOo0O0O0oOO0 )
 if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
 if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
 if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
 if 3 - 3: iII111i . ooOoO0o % I1IiiI + I1ii11iIi11i
 if 64 - 64: i1IIi
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
 if 18 - 18: OOooOOo + I1Ii111
def lisp_button ( string , url ) :
 OO0OO0O = '<button style="background-color:transparent;border-radius:10px; ' + 'type="button">'
 if 75 - 75: I11i / o0oOOo0O0Ooo / OOooOOo / IiII % ooOoO0o + II111iiii
 if 4 - 4: iII111i - Oo0Ooo - IiII - I11i % i11iIiiIii / OoO0O00
 if ( url == None ) :
  i1iii11 = OO0OO0O + string + "</button>"
 else :
  oO = '<a href="{}">' . format ( url )
  o0O0o0000o0O0 = lisp_space ( 2 )
  i1iii11 = o0O0o0000o0O0 + oO + OO0OO0O + string + "</button></a>" + o0O0o0000o0O0
  if 53 - 53: I1Ii111
 return ( i1iii11 )
 if 69 - 69: OoOoOO00 . o0oOOo0O0Ooo . I1IiiI - I1ii11iIi11i
 if 32 - 32: OoooooooOO / I1IiiI / iIii1I11I1II1 + II111iiii . oO0o . o0oOOo0O0Ooo
 if 21 - 21: iIii1I11I1II1 / II111iiii % i1IIi
 if 8 - 8: OoO0O00 + OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
 if 47 - 47: iII111i
def lisp_print_cour ( string ) :
 ooOo0O0O0oOO0 = '<font face="Courier New">{}</font>' . format ( string )
 return ( ooOo0O0O0oOO0 )
 if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 if 47 - 47: oO0o % iIii1I11I1II1
 if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
 if 98 - 98: iII111i + Ii1I - OoO0O00
 if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
 if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
def lisp_print_sans ( string ) :
 ooOo0O0O0oOO0 = '<font face="Sans-Serif">{}</font>' . format ( string )
 return ( ooOo0O0O0oOO0 )
 if 38 - 38: O0 - IiII % I1Ii111
 if 64 - 64: iIii1I11I1II1
 if 15 - 15: I1ii11iIi11i + OOooOOo / I1ii11iIi11i / I1Ii111
 if 31 - 31: ooOoO0o + O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / o0oOOo0O0Ooo
 if 6 - 6: Oo0Ooo % IiII * I11i / I1IiiI + Oo0Ooo
 if 39 - 39: OoOoOO00 - Oo0Ooo / iII111i * OoooooooOO
 if 100 - 100: O0 . I11i . OoO0O00 + O0 * oO0o
def lisp_span ( string , hover_string ) :
 ooOo0O0O0oOO0 = '<span title="{}">{}</span>' . format ( hover_string , string )
 return ( ooOo0O0O0oOO0 )
 if 42 - 42: oO0o % OoooooooOO + o0oOOo0O0Ooo
 if 56 - 56: OoooooooOO + I1ii11iIi11i - iII111i
 if 24 - 24: o0oOOo0O0Ooo + ooOoO0o + I11i - iIii1I11I1II1
 if 49 - 49: I11i . ooOoO0o * OoOoOO00 % IiII . O0
 if 48 - 48: O0 * Ii1I - O0 / Ii1I + OoOoOO00
 if 52 - 52: OoO0O00 % Ii1I * II111iiii
 if 4 - 4: I11i % O0 - OoooooooOO + ooOoO0o . oO0o % II111iiii
def lisp_eid_help_hover ( output ) :
 Iiii1iiiIiI1 = '''Unicast EID format:
  For longest match lookups: 
    <address> or [<iid>]<address>
  For exact match lookups: 
    <prefix> or [<iid>]<prefix>
Multicast EID format:
  For longest match lookups:
    <address>-><group> or
    [<iid>]<address>->[<iid>]<group>'''
 if 27 - 27: Ii1I + I1IiiI * iIii1I11I1II1 . OoooooooOO * OoOoOO00
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 i11II = lisp_span ( output , Iiii1iiiIiI1 )
 return ( i11II )
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 if 29 - 29: O0 . I1Ii111
 if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
 if 70 - 70: I1Ii111 + oO0o
def lisp_geo_help_hover ( output ) :
 Iiii1iiiIiI1 = '''EID format:
    <address> or [<iid>]<address>
    '<name>' or [<iid>]'<name>'
Geo-Point format:
    d-m-s-<N|S>-d-m-s-<W|E> or 
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>
Geo-Prefix format:
    d-m-s-<N|S>-d-m-s-<W|E>/<km> or
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>/<km>'''
 if 93 - 93: I1Ii111 + Ii1I
 if 33 - 33: O0
 i11II = lisp_span ( output , Iiii1iiiIiI1 )
 return ( i11II )
 if 78 - 78: O0 / II111iiii * OoO0O00
 if 50 - 50: OoooooooOO - iIii1I11I1II1 + i1IIi % I1Ii111 - iIii1I11I1II1 % O0
 if 58 - 58: IiII + iIii1I11I1II1
 if 65 - 65: II111iiii - I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 * iII111i + Ii1I
 if 79 - 79: ooOoO0o . OoOoOO00 % I1Ii111 - Oo0Ooo
 if 69 - 69: ooOoO0o - o0oOOo0O0Ooo . ooOoO0o
 if 9 - 9: oO0o % i11iIiiIii / Oo0Ooo
def space ( num ) :
 ooOo0O0O0oOO0 = ""
 for iIiIIi in range ( num ) : ooOo0O0O0oOO0 += "&#160;"
 return ( ooOo0O0O0oOO0 )
 if 20 - 20: oO0o * O0 + I11i - OoooooooOO . I11i
 if 60 - 60: o0oOOo0O0Ooo . o0oOOo0O0Ooo / iII111i
 if 45 - 45: O0 . i11iIiiIii % iII111i . OoOoOO00 % IiII % iIii1I11I1II1
 if 58 - 58: iIii1I11I1II1 . OoOoOO00 - i11iIiiIii * iIii1I11I1II1 % i11iIiiIii / I1IiiI
 if 80 - 80: I1ii11iIi11i / iIii1I11I1II1 % OoOoOO00
 if 80 - 80: OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if 13 - 13: OoO0O00
def lisp_get_ephemeral_port ( ) :
 return ( random . randrange ( 32768 , 65535 ) )
 if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
 if 2 - 2: OoooooooOO . OOooOOo . IiII
 if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 if 24 - 24: o0oOOo0O0Ooo
 if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
 if 28 - 28: OOooOOo % ooOoO0o
def lisp_get_data_nonce ( ) :
 return ( random . randint ( 0 , 0xffffff ) )
 if 48 - 48: i11iIiiIii % oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 if 21 - 21: OOooOOo
def lisp_get_control_nonce ( ) :
 return ( random . randint ( 0 , ( 2 ** 64 ) - 1 ) )
 if 6 - 6: IiII
 if 46 - 46: IiII + oO0o
 if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
 if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
 if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
 if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
def lisp_hex_string ( integer_value ) :
 IiIi1i = hex ( integer_value ) [ 2 : : ]
 if ( IiIi1i [ - 1 ] == "L" ) : IiIi1i = IiIi1i [ 0 : - 1 ]
 return ( IiIi1i )
 if 99 - 99: OoOoOO00 . I1Ii111
 if 59 - 59: I11i / Oo0Ooo / OOooOOo / O0 / OoOoOO00 + o0oOOo0O0Ooo
 if 13 - 13: o0oOOo0O0Ooo % oO0o / I1Ii111 % I1Ii111 % O0
 if 90 - 90: IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
def lisp_get_timestamp ( ) :
 return ( time . time ( ) )
 if 79 - 79: OoOoOO00 / ooOoO0o
lisp_uptime = lisp_get_timestamp ( )
if 77 - 77: Oo0Ooo
if 46 - 46: I1Ii111
if 72 - 72: iII111i * OOooOOo
if 67 - 67: i1IIi
if 5 - 5: II111iiii . OoooooooOO
if 57 - 57: I1IiiI
def lisp_set_timestamp ( seconds ) :
 return ( time . time ( ) + seconds )
 if 35 - 35: OoooooooOO - I1Ii111 / OoO0O00
 if 50 - 50: OoOoOO00
 if 33 - 33: I11i
 if 98 - 98: OoOoOO00 % II111iiii
 if 95 - 95: iIii1I11I1II1 - I1Ii111 - OOooOOo + I1Ii111 % I1ii11iIi11i . I1IiiI
 if 41 - 41: O0 + oO0o . i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
 if 68 - 68: o0oOOo0O0Ooo
def lisp_print_elapsed ( ts ) :
 if ( ts == 0 or ts == None ) : return ( "never" )
 i11Ii1IIi = time . time ( ) - ts
 i11Ii1IIi = round ( i11Ii1IIi , 0 )
 return ( str ( datetime . timedelta ( seconds = i11Ii1IIi ) ) )
 if 36 - 36: O0 * OoO0O00 % iII111i * iII111i / OoO0O00 * IiII
 if 14 - 14: i1IIi . IiII + O0 * ooOoO0o
 if 76 - 76: OoO0O00
 if 92 - 92: I11i - iIii1I11I1II1 % OoooooooOO
 if 39 - 39: iII111i . I1IiiI * OoOoOO00 - i11iIiiIii
 if 1 - 1: iII111i * OoOoOO00
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
def lisp_print_future ( ts ) :
 if ( ts == 0 ) : return ( "never" )
 O0oOO0o = ts - time . time ( )
 if ( O0oOO0o < 0 ) : return ( "expired" )
 O0oOO0o = round ( O0oOO0o , 0 )
 return ( str ( datetime . timedelta ( seconds = O0oOO0o ) ) )
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if 69 - 69: I1ii11iIi11i
 if 83 - 83: o0oOOo0O0Ooo
 if 38 - 38: I1Ii111 + OoooooooOO . i1IIi
 if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
 if 48 - 48: iII111i + IiII
 if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
 if 14 - 14: OOooOOo
 if 79 - 79: Ii1I
 if 76 - 76: iIii1I11I1II1
 if 80 - 80: iIii1I11I1II1 . O0 / Ii1I % Ii1I
def lisp_print_eid_tuple ( eid , group ) :
 ooOo000OoO0o = eid . print_prefix ( )
 if ( group . is_null ( ) ) : return ( ooOo000OoO0o )
 if 58 - 58: I1ii11iIi11i
 ii1I = group . print_prefix ( )
 oO0O = group . instance_id
 if 59 - 59: OoooooooOO * Oo0Ooo + i1IIi
 if ( eid . is_null ( ) or eid . is_exact_match ( group ) ) :
  o00o = ii1I . find ( "]" ) + 1
  return ( "[{}](*, {})" . format ( oO0O , ii1I [ o00o : : ] ) )
  if 23 - 23: ooOoO0o
  if 13 - 13: iIii1I11I1II1
 OooooOo0 = eid . print_sg ( group )
 return ( OooooOo0 )
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
 if 77 - 77: II111iiii
 if 50 - 50: O0 . O0 . ooOoO0o % Oo0Ooo
 if 68 - 68: oO0o
 if 10 - 10: Ii1I
def lisp_convert_6to4 ( addr_str ) :
 if ( addr_str . find ( "::ffff:" ) == - 1 ) : return ( addr_str )
 OOOo = addr_str . split ( ":" )
 return ( OOOo [ - 1 ] )
 if 35 - 35: ooOoO0o - OoO0O00 . Oo0Ooo * Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 if 87 - 87: OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
def lisp_convert_4to6 ( addr_str ) :
 OOOo = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 if ( OOOo . is_ipv4_string ( addr_str ) ) : addr_str = "::ffff:" + addr_str
 OOOo . store_address ( addr_str )
 return ( OOOo )
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
 if 84 - 84: i1IIi
 if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
 if 56 - 56: i11iIiiIii - iIii1I11I1II1 . II111iiii
 if 81 - 81: IiII / OoOoOO00 * IiII . O0
 if 61 - 61: OoO0O00 * OOooOOo + I1Ii111 . iIii1I11I1II1 % I11i . I1Ii111
 if 53 - 53: I1Ii111 * IiII / iIii1I11I1II1 / I1IiiI % I1ii11iIi11i
def lisp_gethostbyname ( string ) :
 IIii = string . split ( "." )
 oOOO0 = string . split ( ":" )
 i111I11i1I = string . split ( "-" )
 if 85 - 85: OOooOOo * i1IIi % I1IiiI - ooOoO0o
 if ( len ( IIii ) == 4 ) :
  if ( IIii [ 0 ] . isdigit ( ) and IIii [ 1 ] . isdigit ( ) and IIii [ 2 ] . isdigit ( ) and
 IIii [ 3 ] . isdigit ( ) ) : return ( string )
  if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
 if ( len ( oOOO0 ) > 1 ) :
  try :
   int ( oOOO0 [ 0 ] , 16 )
   return ( string )
  except :
   pass
   if 83 - 83: IiII / I1Ii111
   if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
   if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
   if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
   if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
   if 80 - 80: OoooooooOO + IiII
   if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 if ( len ( i111I11i1I ) == 3 ) :
  for iIiIIi in range ( 3 ) :
   try : int ( i111I11i1I [ iIiIIi ] , 16 )
   except : break
   if 43 - 43: Oo0Ooo . I1Ii111
   if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
   if 29 - 29: IiII . ooOoO0o - II111iiii
 try :
  OOOo = socket . gethostbyname ( string )
  return ( OOOo )
 except :
  if ( lisp_is_alpine ( ) == False ) : return ( "" )
  if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
  if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
  if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
  if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
  if 59 - 59: I1Ii111 - IiII
 try :
  OOOo = socket . getaddrinfo ( string , 0 ) [ 0 ]
  if ( OOOo [ 3 ] != string ) : return ( "" )
  OOOo = OOOo [ 4 ] [ 0 ]
 except :
  OOOo = ""
  if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
 return ( OOOo )
 if 5 - 5: IiII
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 if 49 - 49: IiII * O0 . IiII
 if 19 - 19: II111iiii - IiII
 if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 if 89 - 89: OOooOOo
def lisp_ip_checksum ( data , hdrlen = 20 ) :
 if ( len ( data ) < hdrlen ) :
  lprint ( "IPv4 packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 69 - 69: ooOoO0o - OoooooooOO * O0
  if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
 I1IiiIiii1 = binascii . hexlify ( data )
 if 39 - 39: ooOoO0o / O0 * IiII
 if 17 - 17: Ii1I / iIii1I11I1II1 - OoO0O00 + I1IiiI % OOooOOo
 if 14 - 14: o0oOOo0O0Ooo % IiII + I1ii11iIi11i + OoO0O00
 if 76 - 76: OoO0O00 - i11iIiiIii + OoOoOO00 + OOooOOo / OoooooooOO
 IiI1Iii1 = 0
 for iIiIIi in range ( 0 , hdrlen * 2 , 4 ) :
  IiI1Iii1 += int ( I1IiiIiii1 [ iIiIIi : iIiIIi + 4 ] , 16 )
  if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
  if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
  if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
  if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
  if 88 - 88: o0oOOo0O0Ooo
 IiI1Iii1 = ( IiI1Iii1 >> 16 ) + ( IiI1Iii1 & 0xffff )
 IiI1Iii1 += IiI1Iii1 >> 16
 IiI1Iii1 = socket . htons ( ~ IiI1Iii1 & 0xffff )
 if 1 - 1: OoooooooOO
 if 48 - 48: ooOoO0o * OoOoOO00 - ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 IiI1Iii1 = struct . pack ( "H" , IiI1Iii1 )
 I1IiiIiii1 = data [ 0 : 10 ] + IiI1Iii1 + data [ 12 : : ]
 return ( I1IiiIiii1 )
 if 3 - 3: OoooooooOO
 if 71 - 71: IiII + i1IIi - iII111i - i11iIiiIii . I11i - ooOoO0o
 if 85 - 85: I1ii11iIi11i - OoOoOO00 / I1ii11iIi11i + OOooOOo - iII111i
 if 49 - 49: OoO0O00 - O0 / OoO0O00 * OoOoOO00 + I1Ii111
 if 35 - 35: II111iiii . I1IiiI / i1IIi / I1IiiI * oO0o
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
def lisp_icmp_checksum ( data ) :
 if ( len ( data ) < 36 ) :
  lprint ( "ICMP packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
  if 27 - 27: OOooOOo
 O0OO0ooO00 = binascii . hexlify ( data )
 if 83 - 83: iIii1I11I1II1
 if 63 - 63: OoooooooOO * OoO0O00 / I11i - oO0o . iIii1I11I1II1 + iII111i
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 IiI1Iii1 = 0
 for iIiIIi in range ( 0 , 36 , 4 ) :
  IiI1Iii1 += int ( O0OO0ooO00 [ iIiIIi : iIiIIi + 4 ] , 16 )
  if 43 - 43: OoO0O00 % OoO0O00
  if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
  if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
  if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
  if 45 - 45: Ii1I - OOooOOo
 IiI1Iii1 = ( IiI1Iii1 >> 16 ) + ( IiI1Iii1 & 0xffff )
 IiI1Iii1 += IiI1Iii1 >> 16
 IiI1Iii1 = socket . htons ( ~ IiI1Iii1 & 0xffff )
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 IiI1Iii1 = struct . pack ( "H" , IiI1Iii1 )
 O0OO0ooO00 = data [ 0 : 2 ] + IiI1Iii1 + data [ 4 : : ]
 return ( O0OO0ooO00 )
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
 if 94 - 94: iII111i - Oo0Ooo + oO0o
 if 59 - 59: I11i . I1IiiI - iIii1I11I1II1 + iIii1I11I1II1
 if 56 - 56: oO0o + ooOoO0o
 if 32 - 32: II111iiii + OoOoOO00 % ooOoO0o / OoOoOO00 + I1ii11iIi11i
 if 2 - 2: i11iIiiIii - I1Ii111 + OoO0O00 % I11i * Ii1I
 if 54 - 54: O0 - iII111i . OOooOOo % iII111i + iII111i
 if 36 - 36: OOooOOo % i11iIiiIii
 if 47 - 47: i1IIi + II111iiii . Oo0Ooo * oO0o . I11i / i1IIi
 if 50 - 50: I1Ii111 / i1IIi % OoooooooOO
def lisp_udp_checksum ( source , dest , data ) :
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 o0O0o0000o0O0 = lisp_address ( LISP_AFI_IPV6 , source , LISP_IPV6_HOST_MASK_LEN , 0 )
 iiIi = lisp_address ( LISP_AFI_IPV6 , dest , LISP_IPV6_HOST_MASK_LEN , 0 )
 OooooOo = socket . htonl ( len ( data ) )
 IIIiiiIiI = socket . htonl ( LISP_UDP_PROTOCOL )
 OO0OOoooo0o = o0O0o0000o0O0 . pack_address ( )
 OO0OOoooo0o += iiIi . pack_address ( )
 OO0OOoooo0o += struct . pack ( "II" , OooooOo , IIIiiiIiI )
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
 Ii1iiI1 = binascii . hexlify ( OO0OOoooo0o + data )
 o0ooOOoO0oO0 = len ( Ii1iiI1 ) % 4
 for iIiIIi in range ( 0 , o0ooOOoO0oO0 ) : Ii1iiI1 += "0"
 if 86 - 86: i1IIi / Ii1I * I1IiiI
 if 67 - 67: I1ii11iIi11i * I1ii11iIi11i / oO0o * OoooooooOO + OoOoOO00
 if 79 - 79: i1IIi
 if 1 - 1: oO0o / i1IIi
 IiI1Iii1 = 0
 for iIiIIi in range ( 0 , len ( Ii1iiI1 ) , 4 ) :
  IiI1Iii1 += int ( Ii1iiI1 [ iIiIIi : iIiIIi + 4 ] , 16 )
  if 74 - 74: I11i / OoooooooOO / Oo0Ooo * i11iIiiIii . II111iiii . OoooooooOO
  if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
  if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
  if 95 - 95: IiII * O0 * I1Ii111 . OoooooooOO % Oo0Ooo + I1ii11iIi11i
  if 98 - 98: oO0o . OoooooooOO
 IiI1Iii1 = ( IiI1Iii1 >> 16 ) + ( IiI1Iii1 & 0xffff )
 IiI1Iii1 += IiI1Iii1 >> 16
 IiI1Iii1 = socket . htons ( ~ IiI1Iii1 & 0xffff )
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 if 33 - 33: I11i % II111iiii + OoO0O00
 if 93 - 93: i1IIi . IiII / I1IiiI + IiII
 IiI1Iii1 = struct . pack ( "H" , IiI1Iii1 )
 Ii1iiI1 = data [ 0 : 6 ] + IiI1Iii1 + data [ 8 : : ]
 return ( Ii1iiI1 )
 if 58 - 58: I1ii11iIi11i + O0 . Oo0Ooo + OoOoOO00 - OoO0O00 - OoOoOO00
 if 41 - 41: Oo0Ooo / i1IIi / Oo0Ooo - iII111i . o0oOOo0O0Ooo
 if 65 - 65: O0 * i11iIiiIii . OoooooooOO / I1IiiI / iII111i
 if 69 - 69: ooOoO0o % ooOoO0o
 if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
 if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
 if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
 if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
def lisp_igmp_checksum ( igmp ) :
 o0O0Ooo = binascii . hexlify ( igmp )
 if 79 - 79: ooOoO0o . oO0o / oO0o - ooOoO0o * Oo0Ooo / o0oOOo0O0Ooo
 if 19 - 19: I1ii11iIi11i
 if 46 - 46: iIii1I11I1II1 . i11iIiiIii - OoOoOO00 % O0 / II111iiii * i1IIi
 if 66 - 66: O0
 IiI1Iii1 = 0
 for iIiIIi in range ( 0 , 24 , 4 ) :
  IiI1Iii1 += int ( o0O0Ooo [ iIiIIi : iIiIIi + 4 ] , 16 )
  if 52 - 52: OoO0O00 * OoooooooOO
  if 12 - 12: O0 + IiII * i1IIi . OoO0O00
  if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
  if 28 - 28: iIii1I11I1II1
  if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 IiI1Iii1 = ( IiI1Iii1 >> 16 ) + ( IiI1Iii1 & 0xffff )
 IiI1Iii1 += IiI1Iii1 >> 16
 IiI1Iii1 = socket . htons ( ~ IiI1Iii1 & 0xffff )
 if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
 if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
 if 46 - 46: OoOoOO00 - O0
 IiI1Iii1 = struct . pack ( "H" , IiI1Iii1 )
 igmp = igmp [ 0 : 2 ] + IiI1Iii1 + igmp [ 4 : : ]
 return ( igmp )
 if 70 - 70: I11i + Oo0Ooo * iIii1I11I1II1 . I1IiiI * I11i
 if 49 - 49: o0oOOo0O0Ooo
 if 25 - 25: iII111i . OoooooooOO * iIii1I11I1II1 . o0oOOo0O0Ooo / O0 + Ii1I
 if 68 - 68: Oo0Ooo
 if 22 - 22: OOooOOo
 if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
 if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
def lisp_get_interface_address ( device ) :
 if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
 if 94 - 94: i1IIi
 if 36 - 36: I1IiiI + Oo0Ooo
 if 46 - 46: iII111i
 if ( device not in netifaces . interfaces ( ) ) : return ( None )
 if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
 if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
 if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
 if 65 - 65: ooOoO0o - i1IIi
 O00Oo = netifaces . ifaddresses ( device )
 if ( netifaces . AF_INET not in O00Oo ) : return ( None )
 if 38 - 38: i1IIi . i11iIiiIii
 if 93 - 93: I11i * II111iiii / Ii1I - o0oOOo0O0Ooo
 if 98 - 98: i11iIiiIii / I1IiiI * o0oOOo0O0Ooo / I1Ii111
 if 67 - 67: I11i % oO0o
 ii1iiIi = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 21 - 21: I1ii11iIi11i
 for OOOo in O00Oo [ netifaces . AF_INET ] :
  Oo0o = OOOo [ "addr" ]
  ii1iiIi . store_address ( Oo0o )
  return ( ii1iiIi )
  if 73 - 73: i1IIi / II111iiii
 return ( None )
 if 45 - 45: Ii1I / ooOoO0o . OoooooooOO + OoO0O00
 if 51 - 51: iII111i % i11iIiiIii % IiII + I1Ii111 % I1ii11iIi11i
 if 16 - 16: OoOoOO00 / Oo0Ooo + O0 - OoOoOO00 . OoooooooOO
 if 19 - 19: o0oOOo0O0Ooo
 if 73 - 73: I1Ii111 * Oo0Ooo * OoOoOO00
 if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
 if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
 if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
 if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
 if 26 - 26: OOooOOo * Oo0Ooo
 if 31 - 31: I11i * oO0o . Ii1I
 if 35 - 35: I11i
def lisp_get_input_interface ( packet ) :
 o00oo = lisp_format_packet ( packet [ 0 : 12 ] )
 O0oO0oo0O = o00oo . replace ( " " , "" )
 oo = O0oO0oo0O [ 0 : 12 ]
 oOOO0ooOoOOO = O0oO0oo0O [ 12 : : ]
 if 68 - 68: O0
 try : o0oOoO00 = ( oOOO0ooOoOOO in lisp_mymacs )
 except : o0oOoO00 = False
 if 94 - 94: OoO0O00 + IiII + ooOoO0o
 if ( oo in lisp_mymacs ) : return ( lisp_mymacs [ oo ] , oOOO0ooOoOOO , oo , o0oOoO00 )
 if ( o0oOoO00 ) : return ( lisp_mymacs [ oOOO0ooOoOOO ] , oOOO0ooOoOOO , oo , o0oOoO00 )
 return ( [ "?" ] , oOOO0ooOoOOO , oo , o0oOoO00 )
 if 82 - 82: Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + IiII % iIii1I11I1II1
 if 61 - 61: OOooOOo / Oo0Ooo % OOooOOo - OoO0O00 + ooOoO0o / ooOoO0o
 if 82 - 82: Oo0Ooo
 if 5 - 5: OoO0O00 / OoO0O00 - O0 - I1Ii111 + I1Ii111
 if 99 - 99: I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - iIii1I11I1II1 - Ii1I
 if 31 - 31: IiII - OoO0O00 / OOooOOo . i1IIi / Ii1I
 if 66 - 66: OoO0O00
 if 72 - 72: I1Ii111
def lisp_get_local_interfaces ( ) :
 for OoO0 in netifaces . interfaces ( ) :
  i1i1111I = lisp_interface ( OoO0 )
  i1i1111I . add_interface ( )
  if 65 - 65: I11i % oO0o + I1ii11iIi11i
 return
 if 86 - 86: iIii1I11I1II1 / O0 . I1Ii111 % iIii1I11I1II1 % Oo0Ooo
 if 86 - 86: i11iIiiIii - o0oOOo0O0Ooo . ooOoO0o * Oo0Ooo / Ii1I % o0oOOo0O0Ooo
 if 61 - 61: o0oOOo0O0Ooo + OoOoOO00
 if 15 - 15: OoOoOO00 * oO0o + OOooOOo . I11i % I1IiiI - ooOoO0o
 if 13 - 13: OoOoOO00 % OoOoOO00 % Oo0Ooo % I1IiiI * i1IIi % I11i
 if 82 - 82: IiII . OoOoOO00 / ooOoO0o + iII111i - ooOoO0o
 if 55 - 55: ooOoO0o % Oo0Ooo % o0oOOo0O0Ooo
def lisp_get_loopback_address ( ) :
 for OOOo in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( OOOo [ "peer" ] == "127.0.0.1" ) : continue
  return ( OOOo [ "peer" ] )
  if 29 - 29: IiII / iIii1I11I1II1 + I1ii11iIi11i % iII111i % I11i
 return ( None )
 if 46 - 46: iIii1I11I1II1
 if 70 - 70: i1IIi . I11i
 if 74 - 74: I11i
 if 58 - 58: iIii1I11I1II1 * OoO0O00 * I1Ii111 * ooOoO0o . OoooooooOO
 if 6 - 6: I1ii11iIi11i - oO0o * i11iIiiIii + OoOoOO00 / ooOoO0o % OOooOOo
 if 38 - 38: OOooOOo % IiII % II111iiii - Oo0Ooo - iIii1I11I1II1
 if 9 - 9: o0oOOo0O0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 28 - 28: OoooooooOO % oO0o + I1ii11iIi11i + O0 . I1Ii111
def lisp_is_mac_string ( mac_str ) :
 i111I11i1I = mac_str . split ( "/" )
 if ( len ( i111I11i1I ) == 2 ) : mac_str = i111I11i1I [ 0 ]
 return ( len ( mac_str ) == 14 and mac_str . count ( "-" ) == 2 )
 if 80 - 80: i11iIiiIii % I1ii11iIi11i
 if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
 if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
 if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
 if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
 if 21 - 21: iII111i
 if 24 - 24: iII111i / ooOoO0o
 if 61 - 61: iIii1I11I1II1 + oO0o
def lisp_get_local_macs ( ) :
 for OoO0 in netifaces . interfaces ( ) :
  if 8 - 8: I1Ii111 + OoO0O00
  if 9 - 9: OOooOOo + o0oOOo0O0Ooo
  if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
  if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
  if 55 - 55: oO0o
  iiIi = OoO0 . replace ( ":" , "" )
  iiIi = OoO0 . replace ( "-" , "" )
  if ( iiIi . isalnum ( ) == False ) : continue
  if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
  if 97 - 97: I1Ii111 . I11i / I1IiiI
  if 83 - 83: I11i - I1ii11iIi11i * oO0o
  if 90 - 90: Oo0Ooo * I1IiiI
  if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
  try :
   I1iI1i11IiI11 = netifaces . ifaddresses ( OoO0 )
  except :
   continue
   if 82 - 82: I1Ii111 * OoO0O00
  if ( netifaces . AF_LINK not in I1iI1i11IiI11 ) : continue
  i111I11i1I = I1iI1i11IiI11 [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  i111I11i1I = i111I11i1I . replace ( ":" , "" )
  if 32 - 32: O0
  if 73 - 73: O0 . I1ii11iIi11i % IiII + OoO0O00 * I11i - OoOoOO00
  if 52 - 52: OOooOOo * oO0o + I11i * I11i % i1IIi % I11i
  if 96 - 96: o0oOOo0O0Ooo * oO0o - OOooOOo * o0oOOo0O0Ooo * i1IIi
  if 8 - 8: ooOoO0o - Oo0Ooo + iIii1I11I1II1 + i1IIi * Ii1I - iIii1I11I1II1
  if ( len ( i111I11i1I ) < 12 ) : continue
  if 30 - 30: I11i / I1ii11iIi11i
  if ( i111I11i1I not in lisp_mymacs ) : lisp_mymacs [ i111I11i1I ] = [ ]
  lisp_mymacs [ i111I11i1I ] . append ( OoO0 )
  if 22 - 22: oO0o * iII111i
  if 4 - 4: OoOoOO00 - oO0o + I1IiiI
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 36 - 36: IiII
 if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
 if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
 if 43 - 43: iIii1I11I1II1 % OoO0O00
 if 84 - 84: Oo0Ooo
 if 44 - 44: OoooooooOO * i11iIiiIii / Oo0Ooo
 if 75 - 75: OoooooooOO . OOooOOo + OoO0O00 / Ii1I - I1IiiI % Ii1I
 if 89 - 89: iII111i * iIii1I11I1II1 + i11iIiiIii . OoooooooOO
def lisp_get_local_rloc ( ) :
 O0O0 = getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( O0O0 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
 if 52 - 52: IiII % ooOoO0o
 if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
 if 23 - 23: i11iIiiIii
 O0O0 = O0O0 . split ( "\n" ) [ 0 ]
 OoO0 = O0O0 . split ( ) [ - 1 ]
 if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
 OOOo = ""
 ooOOo = lisp_is_macos ( )
 if ( ooOOo ) :
  O0O0 = getoutput ( "ifconfig {} | egrep 'inet '" . format ( OoO0 ) )
  if ( O0O0 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  i1 = 'ip addr show | egrep "inet " | egrep "{}"' . format ( OoO0 )
  O0O0 = getoutput ( i1 )
  if ( O0O0 == "" ) :
   i1 = 'ip addr show | egrep "inet " | egrep "global lo"'
   O0O0 = getoutput ( i1 )
   if 22 - 22: iIii1I11I1II1 * I1Ii111 / Oo0Ooo
  if ( O0O0 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 31 - 31: i11iIiiIii
  if 56 - 56: I11i / Ii1I + Oo0Ooo - i1IIi - IiII + iIii1I11I1II1
  if 75 - 75: I1ii11iIi11i
  if 92 - 92: I11i / O0 * I1IiiI - I11i
  if 99 - 99: i11iIiiIii % OoooooooOO
  if 56 - 56: IiII * I1Ii111
 OOOo = ""
 O0O0 = O0O0 . split ( "\n" )
 if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
 for I11I111i1I1 in O0O0 :
  oO = I11I111i1I1 . split ( ) [ 1 ]
  if ( ooOOo == False ) : oO = oO . split ( "/" ) [ 0 ]
  iii1 = lisp_address ( LISP_AFI_IPV4 , oO , 32 , 0 )
  return ( iii1 )
  if 88 - 88: I11i + I1IiiI - I11i / OoooooooOO - i11iIiiIii
 return ( lisp_address ( LISP_AFI_IPV4 , OOOo , 32 , 0 ) )
 if 24 - 24: iIii1I11I1II1
 if 89 - 89: Ii1I / i1IIi - o0oOOo0O0Ooo % I1IiiI . Oo0Ooo - O0
 if 71 - 71: OoO0O00 % I1IiiI - iII111i . iII111i
 if 22 - 22: ooOoO0o / ooOoO0o - Ii1I % I11i . OOooOOo + IiII
 if 64 - 64: i1IIi % I1ii11iIi11i / Ii1I % OoooooooOO
 if 24 - 24: I1Ii111 + OoooooooOO . IiII / OoOoOO00 / I11i
 if 65 - 65: OoooooooOO
 if 18 - 18: O0 - i1IIi . I1Ii111
 if 98 - 98: o0oOOo0O0Ooo
 if 73 - 73: Oo0Ooo - iII111i . oO0o % i1IIi . O0
 if 15 - 15: ooOoO0o . iIii1I11I1II1 * I1IiiI % I11i
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 21 - 21: OoO0O00 - I1IiiI . OoooooooOO
 if 6 - 6: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo / iIii1I11I1II1 * I1Ii111
 if 3 - 3: OOooOOo . IiII / Oo0Ooo
 if 89 - 89: OoooooooOO . iIii1I11I1II1 . Oo0Ooo * iIii1I11I1II1 - I1Ii111
 if 92 - 92: OoooooooOO - I1ii11iIi11i - OoooooooOO % I1IiiI % I1IiiI % iIii1I11I1II1
 if 92 - 92: iII111i * O0 % I1Ii111 . iIii1I11I1II1
 if 66 - 66: I11i + Ii1I
 if 48 - 48: I1ii11iIi11i
 if 96 - 96: ooOoO0o . OoooooooOO
 if 39 - 39: OOooOOo + OoO0O00
 oOoOOOO0OOO = None
 o00o = 1
 O0oo0oO00o = os . getenv ( "LISP_ADDR_SELECT" )
 if ( O0oo0oO00o != None and O0oo0oO00o != "" ) :
  O0oo0oO00o = O0oo0oO00o . split ( ":" )
  if ( len ( O0oo0oO00o ) == 2 ) :
   oOoOOOO0OOO = O0oo0oO00o [ 0 ]
   o00o = O0oo0oO00o [ 1 ]
  else :
   if ( O0oo0oO00o [ 0 ] . isdigit ( ) ) :
    o00o = O0oo0oO00o [ 0 ]
   else :
    oOoOOOO0OOO = O0oo0oO00o [ 0 ]
    if 35 - 35: iII111i * iIii1I11I1II1 / ooOoO0o * i1IIi * O0 % iIii1I11I1II1
    if 97 - 97: i11iIiiIii + Oo0Ooo * OOooOOo % iII111i . IiII
  o00o = 1 if ( o00o == "" ) else int ( o00o )
  if 4 - 4: O0 . iII111i - iIii1I11I1II1
  if 19 - 19: OOooOOo % OoO0O00 / Ii1I + II111iiii % OoooooooOO
 oOo000O00O0 = [ None , None , None ]
 iI1iiIii1I11I = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 Ii1IiiiI1ii = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 o0oOOoo0O = None
 if 57 - 57: I1IiiI . i11iIiiIii * II111iiii + OoooooooOO + Ii1I
 for OoO0 in netifaces . interfaces ( ) :
  if ( oOoOOOO0OOO != None and oOoOOOO0OOO != OoO0 ) : continue
  O00Oo = netifaces . ifaddresses ( OoO0 )
  if ( O00Oo == { } ) : continue
  if 73 - 73: O0 % I11i + iII111i . I1ii11iIi11i . I1ii11iIi11i + IiII
  if 30 - 30: OoOoOO00
  if 89 - 89: I11i
  if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
  o0oOOoo0O = lisp_get_interface_instance_id ( OoO0 , None )
  if 79 - 79: IiII + IiII + Ii1I
  if 39 - 39: O0 - OoooooooOO
  if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
  if 79 - 79: O0
  if ( netifaces . AF_INET in O00Oo ) :
   IIii = O00Oo [ netifaces . AF_INET ]
   IiI = 0
   for OOOo in IIii :
    iI1iiIii1I11I . store_address ( OOOo [ "addr" ] )
    if ( iI1iiIii1I11I . is_ipv4_loopback ( ) ) : continue
    if ( iI1iiIii1I11I . is_ipv4_link_local ( ) ) : continue
    if ( iI1iiIii1I11I . address == 0 ) : continue
    IiI += 1
    iI1iiIii1I11I . instance_id = o0oOOoo0O
    if ( oOoOOOO0OOO == None and
 lisp_db_for_lookups . lookup_cache ( iI1iiIii1I11I , False ) ) : continue
    oOo000O00O0 [ 0 ] = iI1iiIii1I11I
    if ( IiI == o00o ) : break
    if 9 - 9: II111iiii % OoOoOO00
    if 26 - 26: iIii1I11I1II1 - I1ii11iIi11i . IiII . IiII + iIii1I11I1II1 * Oo0Ooo
  if ( netifaces . AF_INET6 in O00Oo ) :
   oOOO0 = O00Oo [ netifaces . AF_INET6 ]
   IiI = 0
   for OOOo in oOOO0 :
    Oo0o = OOOo [ "addr" ]
    Ii1IiiiI1ii . store_address ( Oo0o )
    if ( Ii1IiiiI1ii . is_ipv6_string_link_local ( Oo0o ) ) : continue
    if ( Ii1IiiiI1ii . is_ipv6_loopback ( ) ) : continue
    IiI += 1
    Ii1IiiiI1ii . instance_id = o0oOOoo0O
    if ( oOoOOOO0OOO == None and
 lisp_db_for_lookups . lookup_cache ( Ii1IiiiI1ii , False ) ) : continue
    oOo000O00O0 [ 1 ] = Ii1IiiiI1ii
    if ( IiI == o00o ) : break
    if 85 - 85: OOooOOo + II111iiii - OOooOOo * oO0o - i1IIi % iII111i
    if 1 - 1: OoooooooOO / O0 + OoOoOO00 + OoOoOO00 . I1Ii111 - OoOoOO00
    if 9 - 9: I1Ii111 * OoooooooOO % I1IiiI / OoOoOO00 * I11i
    if 48 - 48: OoooooooOO . OoOoOO00
    if 65 - 65: oO0o . Oo0Ooo
    if 94 - 94: OoOoOO00 + IiII . ooOoO0o
  if ( oOo000O00O0 [ 0 ] == None ) : continue
  if 69 - 69: O0 - O0
  oOo000O00O0 [ 2 ] = OoO0
  break
  if 41 - 41: IiII % o0oOOo0O0Ooo
  if 67 - 67: O0 % I1Ii111
 III = oOo000O00O0 [ 0 ] . print_address_no_iid ( ) if oOo000O00O0 [ 0 ] else "none"
 I1I = oOo000O00O0 [ 1 ] . print_address_no_iid ( ) if oOo000O00O0 [ 1 ] else "none"
 OoO0 = oOo000O00O0 [ 2 ] if oOo000O00O0 [ 2 ] else "none"
 if 70 - 70: Ii1I . O0 - OOooOOo
 oOoOOOO0OOO = " (user selected)" if oOoOOOO0OOO != None else ""
 if 62 - 62: I1Ii111 * I11i
 III = red ( III , False )
 I1I = red ( I1I , False )
 OoO0 = bold ( OoO0 , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( III , I1I , OoO0 , oOoOOOO0OOO , o0oOOoo0O ) )
 if 74 - 74: OoOoOO00 . iIii1I11I1II1
 if 87 - 87: ooOoO0o
 lisp_myrlocs = oOo000O00O0
 return ( ( oOo000O00O0 [ 0 ] != None ) )
 if 41 - 41: OoOoOO00 . iIii1I11I1II1 % ooOoO0o + O0
 if 22 - 22: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o + I1ii11iIi11i * iII111i . i11iIiiIii
 if 90 - 90: OOooOOo * OoOoOO00 - Oo0Ooo + o0oOOo0O0Ooo
 if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
 if 44 - 44: I1Ii111 - IiII
 if 100 - 100: oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
 if 59 - 59: II111iiii
 if 43 - 43: Oo0Ooo + OoooooooOO
 if 47 - 47: ooOoO0o
def lisp_get_all_addresses ( ) :
 o00oOoo0o00 = [ ]
 for i1i1111I in netifaces . interfaces ( ) :
  try : iIiiI11II11i = netifaces . ifaddresses ( i1i1111I )
  except : continue
  if 98 - 98: iII111i - iII111i
  if ( netifaces . AF_INET in iIiiI11II11i ) :
   for OOOo in iIiiI11II11i [ netifaces . AF_INET ] :
    oO = OOOo [ "addr" ]
    if ( oO . find ( "127.0.0.1" ) != - 1 ) : continue
    o00oOoo0o00 . append ( oO )
    if 58 - 58: oO0o
    if 98 - 98: o0oOOo0O0Ooo * OoO0O00
  if ( netifaces . AF_INET6 in iIiiI11II11i ) :
   for OOOo in iIiiI11II11i [ netifaces . AF_INET6 ] :
    oO = OOOo [ "addr" ]
    if ( oO == "::1" ) : continue
    if ( oO [ 0 : 5 ] == "fe80:" ) : continue
    o00oOoo0o00 . append ( oO )
    if 10 - 10: oO0o - iII111i % II111iiii - I1Ii111 - i1IIi
    if 10 - 10: I1ii11iIi11i - I11i . I1Ii111
    if 8 - 8: iIii1I11I1II1 % oO0o + Oo0Ooo
 return ( o00oOoo0o00 )
 if 24 - 24: o0oOOo0O0Ooo / Ii1I / Ii1I % II111iiii - oO0o * oO0o
 if 58 - 58: OoOoOO00
 if 60 - 60: II111iiii
 if 90 - 90: OoOoOO00
 if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
 if 18 - 18: OoooooooOO
 if 57 - 57: ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo - OoooooooOO
 if 75 - 75: i11iIiiIii / o0oOOo0O0Ooo . IiII . i1IIi . i1IIi / I11i
def lisp_get_all_multicast_rles ( ) :
 o0OOo0O = [ ]
 O0O0 = getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( O0O0 == "" ) : return ( o0OOo0O )
 if 52 - 52: OoooooooOO / IiII % II111iiii
 Ii11I1I11II = O0O0 . split ( "\n" )
 for I11I111i1I1 in Ii11I1I11II :
  if ( I11I111i1I1 [ 0 ] == "#" ) : continue
  IIiiiI = I11I111i1I1 . split ( "rle-address = " ) [ 1 ]
  oO0Oooo0OoO = int ( IIiiiI . split ( "." ) [ 0 ] )
  if ( oO0Oooo0OoO >= 224 and oO0Oooo0OoO < 240 ) : o0OOo0O . append ( IIiiiI )
  if 38 - 38: I1IiiI . I1IiiI . Ii1I + I1ii11iIi11i * Oo0Ooo
 return ( o0OOo0O )
 if 61 - 61: II111iiii . IiII - O0 * IiII
 if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
 if 33 - 33: II111iiii - IiII - ooOoO0o
 if 92 - 92: OoO0O00 * IiII
 if 92 - 92: oO0o
 if 7 - 7: iII111i
 if 73 - 73: OoO0O00 % I1ii11iIi11i
 if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
class lisp_packet ( object ) :
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
  if 62 - 62: i11iIiiIii
  if 2 - 2: I1IiiI
 def encode ( self , nonce ) :
  if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
  if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
  if 14 - 14: IiII . IiII % ooOoO0o
  if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
  if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
  if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
  if 98 - 98: Ii1I - II111iiii / I1IiiI . oO0o * IiII . I11i
  if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 6 - 6: oO0o . I11i
  if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 50 - 50: oO0o % i1IIi * O0
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 4 - 4: iIii1I11I1II1 . i1IIi
  if 63 - 63: iIii1I11I1II1 + IiII % i1IIi / I1IiiI % II111iiii
  if 60 - 60: o0oOOo0O0Ooo . OoOoOO00 % I1Ii111 / I1IiiI / O0
  if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
  if 59 - 59: iIii1I11I1II1 / I1ii11iIi11i % ooOoO0o
  if 84 - 84: iIii1I11I1II1 / I1IiiI . OoOoOO00 % I11i
  self . lisp_header . key_id ( 0 )
  oOoO000 = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and oOoO000 == False ) :
   Oo0o = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 86 - 86: iIii1I11I1II1 - I11i % ooOoO0o . OOooOOo * OoOoOO00 . i1IIi
   if ( Oo0o in lisp_crypto_keys_by_rloc_encap ) :
    O0o0O0 = lisp_crypto_keys_by_rloc_encap [ Oo0o ]
    if ( O0o0O0 [ 1 ] ) :
     O0o0O0 [ 1 ] . use_count += 1
     OO0Oo00OO0oo , oOO00o0O0 = self . encrypt ( O0o0O0 [ 1 ] , Oo0o )
     if ( oOO00o0O0 ) : self . packet = OO0Oo00OO0oo
     if 47 - 47: ooOoO0o
     if 63 - 63: II111iiii / i11iIiiIii % II111iiii . I1ii11iIi11i
     if 6 - 6: OOooOOo + i11iIiiIii
     if 26 - 26: IiII / Ii1I - OoooooooOO
     if 9 - 9: OoooooooOO * I1ii11iIi11i
     if 9 - 9: Oo0Ooo + iII111i
     if 64 - 64: O0 * I1IiiI / I1IiiI
     if 57 - 57: I1ii11iIi11i / OoooooooOO % I1ii11iIi11i . O0 / I1ii11iIi11i
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    if ( self . gleaned_dest ) :
     self . udp_sport = LISP_DATA_PORT
    else :
     self . hash_packet ( )
     if 63 - 63: IiII + iIii1I11I1II1 + I1IiiI + I1Ii111
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 72 - 72: OoO0O00 + i11iIiiIii + I1ii11iIi11i
  else :
   self . udp_sport = LISP_DATA_PORT
   if 96 - 96: oO0o % i1IIi / o0oOOo0O0Ooo
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 13 - 13: II111iiii - Oo0Ooo % i11iIiiIii + iII111i
  if 88 - 88: O0 . oO0o % I1IiiI
  if 10 - 10: I1IiiI + O0
  if 75 - 75: O0 % iIii1I11I1II1 / OoOoOO00 % OOooOOo / IiII
  iiI1iiIiiiI1I = socket . htons ( self . udp_sport )
  i111I1 = socket . htons ( self . udp_dport )
  OOOo0Oo0O = socket . htons ( self . udp_length )
  Ii1iiI1 = struct . pack ( "HHHH" , iiI1iiIiiiI1I , i111I1 , OOOo0Oo0O , self . udp_checksum )
  if 48 - 48: ooOoO0o % OoOoOO00
  if 67 - 67: iIii1I11I1II1 % OoO0O00 + i11iIiiIii
  if 46 - 46: I1IiiI . IiII - i11iIiiIii - I1Ii111
  if 97 - 97: II111iiii % Oo0Ooo * IiII
  oOoOO0O00o = self . lisp_header . encode ( )
  if 77 - 77: I1Ii111 + oO0o
  if 38 - 38: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
  if 13 - 13: I1IiiI * oO0o
  if 41 - 41: IiII
  if 16 - 16: iIii1I11I1II1
  if ( self . outer_version == 4 ) :
   o000o0o00Oo = socket . htons ( self . udp_length + 20 )
   oo0O00o0O0Oo = socket . htons ( 0x4000 )
   iii11 = struct . pack ( "BBHHHBBH" , 0x45 , self . outer_tos , o000o0o00Oo , 0xdfdf ,
 oo0O00o0O0Oo , self . outer_ttl , 17 , 0 )
   iii11 += self . outer_source . pack_address ( )
   iii11 += self . outer_dest . pack_address ( )
   iii11 = lisp_ip_checksum ( iii11 )
  elif ( self . outer_version == 6 ) :
   iii11 = b""
   if 20 - 20: OOooOOo - iII111i / Oo0Ooo * OoO0O00
   if 55 - 55: OoooooooOO
   if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
   if 38 - 38: O0
   if 79 - 79: i1IIi . oO0o
   if 34 - 34: I1Ii111 * II111iiii
   if 71 - 71: IiII
  else :
   return ( None )
   if 97 - 97: I1ii11iIi11i
   if 86 - 86: Oo0Ooo - OOooOOo . OoOoOO00 . II111iiii * I1IiiI . II111iiii
  self . packet = iii11 + Ii1iiI1 + oOoOO0O00o + self . packet
  return ( self )
  if 34 - 34: o0oOOo0O0Ooo . I1Ii111 % IiII - O0 / I1Ii111
  if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
 def cipher_pad ( self , packet ) :
  iIo00oo = len ( packet )
  if ( ( iIo00oo % 16 ) != 0 ) :
   O000Oo00 = ( old_div ( iIo00oo , 16 ) + 1 ) * 16
   packet = packet . ljust ( O000Oo00 )
   if 43 - 43: OoO0O00 . ooOoO0o * Oo0Ooo
  return ( packet )
  if 20 - 20: i1IIi . i1IIi - I11i
  if 89 - 89: ooOoO0o - I11i . O0 % OoooooooOO . i11iIiiIii
 def encrypt ( self , key , addr_str ) :
  if ( key == None or key . shared_key == None ) :
   return ( [ self . packet , False ] )
   if 35 - 35: II111iiii / OoOoOO00 - O0 . II111iiii
   if 55 - 55: Oo0Ooo % i1IIi * I11i
   if 95 - 95: OOooOOo / II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
   if 63 - 63: iIii1I11I1II1 / ooOoO0o
   if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
  OO0Oo00OO0oo = self . cipher_pad ( self . packet )
  iI1ii = key . get_iv ( )
  if 61 - 61: Oo0Ooo * i1IIi . OoooooooOO
  Oo0OO0000oooo = lisp_get_timestamp ( )
  iIIiI = None
  O0O0O0OO00oo = False
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   I11IIIIiI1 = chacha . ChaCha ( key . encrypt_key , iI1ii ) . encrypt
   O0O0O0OO00oo = True
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   o0 = binascii . unhexlify ( key . encrypt_key )
   try :
    oOOO = AES . new ( o0 , AES . MODE_GCM , iI1ii )
    I11IIIIiI1 = oOOO . encrypt
    iIIiI = oOOO . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 62 - 62: Ii1I - oO0o % iIii1I11I1II1
  else :
   o0 = binascii . unhexlify ( key . encrypt_key )
   I11IIIIiI1 = AES . new ( o0 , AES . MODE_CBC , iI1ii ) . encrypt
   if 57 - 57: OoooooooOO / OoOoOO00
   if 44 - 44: OoOoOO00 * i1IIi * O0
  oooo0o0oO = I11IIIIiI1 ( OO0Oo00OO0oo )
  if 15 - 15: iIii1I11I1II1 . OOooOOo . I1ii11iIi11i * i11iIiiIii
  if ( oooo0o0oO == None ) : return ( [ self . packet , False ] )
  Oo0OO0000oooo = int ( str ( time . time ( ) - Oo0OO0000oooo ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 72 - 72: I11i
  if 26 - 26: IiII % Oo0Ooo
  if 72 - 72: O0 + o0oOOo0O0Ooo + I1IiiI / Oo0Ooo
  if 83 - 83: IiII - I1IiiI . Ii1I
  if 34 - 34: OoOoOO00 - oO0o * OoooooooOO
  if 5 - 5: i11iIiiIii * iII111i - Ii1I - I1ii11iIi11i - i1IIi + iII111i
  if ( O0O0O0OO00oo ) :
   oooo0o0oO = oooo0o0oO . encode ( "raw_unicode_escape" )
   if 4 - 4: ooOoO0o + O0 . i1IIi * I1ii11iIi11i - o0oOOo0O0Ooo
   if 42 - 42: o0oOOo0O0Ooo * OoOoOO00 . OoO0O00 - iII111i / II111iiii
   if 25 - 25: Oo0Ooo % OoOoOO00
   if 75 - 75: i1IIi
   if 74 - 74: Oo0Ooo + I1Ii111 - oO0o - OoO0O00 + iII111i - iIii1I11I1II1
   if 54 - 54: I1ii11iIi11i + II111iiii . I1IiiI / OoO0O00 . ooOoO0o
   if 58 - 58: IiII % i11iIiiIii * II111iiii . I1ii11iIi11i
  if ( iIIiI != None ) : oooo0o0oO += iIIiI ( )
  if 94 - 94: i11iIiiIii . OOooOOo + iIii1I11I1II1 * I1Ii111 * I1Ii111
  if 36 - 36: I11i - IiII . IiII
  if 60 - 60: i11iIiiIii * Oo0Ooo % OoO0O00 + OoO0O00
  if 84 - 84: iIii1I11I1II1 + OoooooooOO
  if 77 - 77: O0 * I1ii11iIi11i * oO0o + OoO0O00 + I1ii11iIi11i - I1Ii111
  self . lisp_header . key_id ( key . key_id )
  oOoOO0O00o = self . lisp_header . encode ( )
  if 10 - 10: I1ii11iIi11i + IiII
  Ooooo00 = key . do_icv ( oOoOO0O00o + iI1ii + oooo0o0oO , iI1ii )
  if 99 - 99: I1ii11iIi11i - oO0o
  iiI = 4 if ( key . do_poly ) else 8
  if 89 - 89: ooOoO0o * Ii1I
  Oo0 = bold ( "Encrypt" , False )
  o0O0o0oo0O0O = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  o00 = "poly" if key . do_poly else "sha256"
  o00 = bold ( o00 , False )
  i111i = "ICV({}): 0x{}...{}" . format ( o00 , Ooooo00 [ 0 : iiI ] , Ooooo00 [ - iiI : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( Oo0 , key . key_id , addr_str , i111i , o0O0o0oo0O0O , Oo0OO0000oooo ) )
  if 36 - 36: Ii1I
  if 73 - 73: II111iiii - oO0o
  Ooooo00 = int ( Ooooo00 , 16 )
  if ( key . do_poly ) :
   Oo0O00o0O0 = byte_swap_64 ( ( Ooooo00 >> 64 ) & LISP_8_64_MASK )
   Ii = byte_swap_64 ( Ooooo00 & LISP_8_64_MASK )
   Ooooo00 = struct . pack ( "QQ" , Oo0O00o0O0 , Ii )
  else :
   Oo0O00o0O0 = byte_swap_64 ( ( Ooooo00 >> 96 ) & LISP_8_64_MASK )
   Ii = byte_swap_64 ( ( Ooooo00 >> 32 ) & LISP_8_64_MASK )
   Iii11ii111 = socket . htonl ( Ooooo00 & 0xffffffff )
   Ooooo00 = struct . pack ( "QQI" , Oo0O00o0O0 , Ii , Iii11ii111 )
   if 75 - 75: O0
   if 56 - 56: OoO0O00 / II111iiii
  return ( [ iI1ii + oooo0o0oO + Ooooo00 , True ] )
  if 39 - 39: OoOoOO00 - OoooooooOO - i1IIi / II111iiii
  if 49 - 49: Oo0Ooo + O0 + IiII . II111iiii % ooOoO0o
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 33 - 33: OoOoOO00 . iIii1I11I1II1 / I11i % Ii1I
  if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
  if 27 - 27: OoO0O00 + Oo0Ooo
  if 92 - 92: I1IiiI % iII111i
  if 31 - 31: OoooooooOO - oO0o / I1Ii111
  if 62 - 62: i11iIiiIii - I11i
  if ( key . do_poly ) :
   Oo0O00o0O0 , Ii = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   o00OOOOooO = byte_swap_64 ( Oo0O00o0O0 ) << 64
   o00OOOOooO |= byte_swap_64 ( Ii )
   o00OOOOooO = lisp_hex_string ( o00OOOOooO ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   iiI = 4
   o0oo00oo0oO = bold ( "poly" , False )
  else :
   Oo0O00o0O0 , Ii , Iii11ii111 = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   o00OOOOooO = byte_swap_64 ( Oo0O00o0O0 ) << 96
   o00OOOOooO |= byte_swap_64 ( Ii ) << 32
   o00OOOOooO |= socket . htonl ( Iii11ii111 )
   o00OOOOooO = lisp_hex_string ( o00OOOOooO ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   iiI = 8
   o0oo00oo0oO = bold ( "sha" , False )
   if 49 - 49: I1IiiI
  oOoOO0O00o = self . lisp_header . encode ( )
  if 24 - 24: II111iiii / Ii1I . iIii1I11I1II1 - II111iiii % O0
  if 8 - 8: OoO0O00 % iII111i . OoooooooOO - Ii1I % OoooooooOO
  if 61 - 61: o0oOOo0O0Ooo / i11iIiiIii
  if 28 - 28: OOooOOo / OoOoOO00
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   iII1IiiIIIIii = 8
   o0O0o0oo0O0O = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   iII1IiiIIIIii = 12
   o0O0o0oo0O0O = bold ( "aes-gcm" , False )
  else :
   iII1IiiIIIIii = 16
   o0O0o0oo0O0O = bold ( "aes-cbc" , False )
   if 98 - 98: Oo0Ooo / oO0o - I1IiiI
  iI1ii = packet [ 0 : iII1IiiIIIIii ]
  if 81 - 81: OoooooooOO . OoOoOO00 * iIii1I11I1II1 / OoOoOO00 - I1ii11iIi11i % i1IIi
  if 77 - 77: I1IiiI / OoooooooOO
  if 33 - 33: i11iIiiIii + Ii1I % o0oOOo0O0Ooo % I1IiiI
  if 66 - 66: o0oOOo0O0Ooo % IiII
  o0O = key . do_icv ( oOoOO0O00o + packet , iI1ii )
  if 76 - 76: I11i
  iiIi1I1IIiIi1 = "0x{}...{}" . format ( o00OOOOooO [ 0 : iiI ] , o00OOOOooO [ - iiI : : ] )
  OOOoOoO0O = "0x{}...{}" . format ( o0O [ 0 : iiI ] , o0O [ - iiI : : ] )
  if 26 - 26: I1Ii111 * IiII % iIii1I11I1II1
  if ( o0O != o00OOOOooO ) :
   self . packet_error = "ICV-error"
   OO = o0O0o0oo0O0O + "/" + o0oo00oo0oO
   iii1IiiIiIIiI = bold ( "ICV failed ({})" . format ( OO ) , False )
   i111i = "packet-ICV {} != computed-ICV {}" . format ( iiIi1I1IIiIi1 , OOOoOoO0O )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( iii1IiiIiIIiI , red ( addr_str , False ) ,
   # iII111i / I1ii11iIi11i * oO0o / II111iiii + OOooOOo - O0
 self . udp_sport , key . key_id , i111i ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 16 - 16: II111iiii / Ii1I . Ii1I - Ii1I / I1ii11iIi11i
   if 28 - 28: OOooOOo * OoooooooOO + ooOoO0o % iII111i . iIii1I11I1II1
   if 17 - 17: IiII / o0oOOo0O0Ooo . OOooOOo + o0oOOo0O0Ooo / I1ii11iIi11i . Oo0Ooo
   if 39 - 39: o0oOOo0O0Ooo / IiII - iII111i
   if 96 - 96: I11i * I1ii11iIi11i * Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
   if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
   lisp_retry_decap_keys ( addr_str , oOoOO0O00o + packet , iI1ii , o00OOOOooO )
   return ( [ None , False ] )
   if 94 - 94: I11i / OoO0O00 . o0oOOo0O0Ooo
   if 1 - 1: Oo0Ooo . II111iiii
   if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
   if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
   if 4 - 4: IiII
  packet = packet [ iII1IiiIIIIii : : ]
  if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
  if 99 - 99: i11iIiiIii - iII111i
  if 85 - 85: I1Ii111 % I1ii11iIi11i
  if 95 - 95: OoO0O00 * OOooOOo * iII111i . o0oOOo0O0Ooo
  Oo0OO0000oooo = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   oooOo00 = chacha . ChaCha ( key . encrypt_key , iI1ii ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   o0 = binascii . unhexlify ( key . encrypt_key )
   try :
    oooOo00 = AES . new ( o0 , AES . MODE_GCM , iI1ii ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 1 - 1: I1IiiI + I1ii11iIi11i
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 70 - 70: iIii1I11I1II1 + I11i . I1ii11iIi11i / ooOoO0o
   o0 = binascii . unhexlify ( key . encrypt_key )
   oooOo00 = AES . new ( o0 , AES . MODE_CBC , iI1ii ) . decrypt
   if 77 - 77: Oo0Ooo / I11i . iII111i / I1Ii111 - OoooooooOO
   if 76 - 76: O0
  ooo = oooOo00 ( packet )
  Oo0OO0000oooo = int ( str ( time . time ( ) - Oo0OO0000oooo ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
  if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
  if 80 - 80: Ii1I
  if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
  Oo0 = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  o00 = "poly" if key . do_poly else "sha256"
  o00 = bold ( o00 , False )
  i111i = "ICV({}): {}" . format ( o00 , iiIi1I1IIiIi1 )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( Oo0 , key . key_id , addr_str , i111i , o0O0o0oo0O0O , Oo0OO0000oooo ) )
  if 59 - 59: I1ii11iIi11i + I11i . oO0o
  if 87 - 87: OoO0O00
  if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
  if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
  if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
  if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
  if 46 - 46: i11iIiiIii
  self . packet = self . packet [ 0 : header_length ]
  return ( [ ooo , True ] )
  if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
  if 48 - 48: I1Ii111 % iII111i % Ii1I % iIii1I11I1II1 . Ii1I
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  I11IIiI1IiI1 = 1000
  if 37 - 37: oO0o % I1Ii111 % oO0o
  if 14 - 14: OoO0O00 / I1IiiI
  if 66 - 66: Oo0Ooo / i11iIiiIii % ooOoO0o
  if 43 - 43: OOooOOo
  if 84 - 84: OOooOOo . IiII . iII111i
  iIII1I1i = [ ]
  o0O0 = 0
  iIo00oo = len ( inner_packet )
  while ( o0O0 < iIo00oo ) :
   oo0O00o0O0Oo = inner_packet [ o0O0 : : ]
   if ( len ( oo0O00o0O0Oo ) > I11IIiI1IiI1 ) : oo0O00o0O0Oo = oo0O00o0O0Oo [ 0 : I11IIiI1IiI1 ]
   iIII1I1i . append ( oo0O00o0O0Oo )
   o0O0 += len ( oo0O00o0O0Oo )
   if 26 - 26: iII111i - Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
   if 37 - 37: o0oOOo0O0Ooo * OOooOOo + I1IiiI . I1ii11iIi11i * OoooooooOO
   if 82 - 82: i11iIiiIii + iIii1I11I1II1 / Oo0Ooo + OOooOOo * II111iiii
   if 34 - 34: o0oOOo0O0Ooo % OoooooooOO
   if 36 - 36: I1IiiI
   if 64 - 64: i11iIiiIii + i1IIi % O0 . I11i
  o00o0 = [ ]
  o0O0 = 0
  for oo0O00o0O0Oo in iIII1I1i :
   if 84 - 84: OoOoOO00 - Oo0Ooo . ooOoO0o . IiII - Oo0Ooo
   if 99 - 99: I1Ii111
   if 75 - 75: ooOoO0o . OOooOOo / IiII
   if 84 - 84: OoooooooOO . I1IiiI / o0oOOo0O0Ooo
   oOO0O00o0O0 = o0O0 if ( oo0O00o0O0Oo == iIII1I1i [ - 1 ] ) else 0x2000 + o0O0
   oOO0O00o0O0 = socket . htons ( oOO0O00o0O0 )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , oOO0O00o0O0 ) + outer_hdr [ 8 : : ]
   if 68 - 68: i11iIiiIii + OoO0O00
   if 13 - 13: ooOoO0o - I1IiiI
   if 23 - 23: I1IiiI
   if 7 - 7: iII111i % I1ii11iIi11i
   o0oOOO = socket . htons ( len ( oo0O00o0O0Oo ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , o0oOOO ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   o00o0 . append ( outer_hdr + oo0O00o0O0Oo )
   o0O0 += len ( oo0O00o0O0Oo ) / 8
   if 47 - 47: OOooOOo / II111iiii % IiII . oO0o * I1ii11iIi11i
  return ( o00o0 )
  if 35 - 35: Oo0Ooo * II111iiii
  if 32 - 32: oO0o . Oo0Ooo / ooOoO0o + ooOoO0o . I1ii11iIi11i
 def send_icmp_too_big ( self , inner_packet ) :
  global lisp_last_icmp_too_big_sent
  global lisp_icmp_raw_socket
  if 50 - 50: iIii1I11I1II1 * oO0o
  i11Ii1IIi = time . time ( ) - lisp_last_icmp_too_big_sent
  if ( i11Ii1IIi < LISP_ICMP_TOO_BIG_RATE_LIMIT ) :
   lprint ( "Rate limit sending ICMP Too-Big to {}" . format ( self . inner_source . print_address_no_iid ( ) ) )
   if 85 - 85: i1IIi
   return ( False )
   if 100 - 100: OoooooooOO / I11i % OoO0O00 + Ii1I
   if 42 - 42: Oo0Ooo / IiII . Ii1I * I1IiiI
   if 54 - 54: OoOoOO00 * iII111i + OoO0O00
   if 93 - 93: o0oOOo0O0Ooo / I1IiiI
   if 47 - 47: Oo0Ooo * OOooOOo
   if 98 - 98: oO0o - oO0o . ooOoO0o
   if 60 - 60: I1IiiI * I1ii11iIi11i / O0 + I11i + IiII
   if 66 - 66: IiII * Oo0Ooo . OoooooooOO * I1Ii111
   if 93 - 93: IiII / i1IIi
   if 47 - 47: ooOoO0o - Ii1I
   if 98 - 98: oO0o . I1Ii111 / OoOoOO00 . ooOoO0o
   if 1 - 1: OOooOOo
   if 87 - 87: O0 * II111iiii + iIii1I11I1II1 % oO0o % i11iIiiIii - OoOoOO00
   if 73 - 73: iII111i + Ii1I
   if 37 - 37: oO0o - iIii1I11I1II1 + II111iiii . Ii1I % iIii1I11I1II1
  i11iiI = socket . htons ( 1400 )
  O0OO0ooO00 = struct . pack ( "BBHHH" , 3 , 4 , 0 , 0 , i11iiI )
  O0OO0ooO00 += inner_packet [ 0 : 20 + 8 ]
  O0OO0ooO00 = lisp_icmp_checksum ( O0OO0ooO00 )
  if 8 - 8: i1IIi + II111iiii / Ii1I + I1ii11iIi11i % Ii1I - iIii1I11I1II1
  if 29 - 29: Oo0Ooo + II111iiii
  if 95 - 95: oO0o
  if 48 - 48: I11i / iIii1I11I1II1 % II111iiii
  if 39 - 39: i1IIi . I1ii11iIi11i / I11i / I11i
  if 100 - 100: OoooooooOO - OoooooooOO + IiII
  if 32 - 32: OoOoOO00 * o0oOOo0O0Ooo / OoooooooOO
  oOooo00OOO000 = inner_packet [ 12 : 16 ]
  OooOOooo = self . inner_source . print_address_no_iid ( )
  O00oOoo00O = self . outer_source . pack_address ( )
  if 25 - 25: i11iIiiIii + I1ii11iIi11i - OoooooooOO . O0 % I1Ii111
  if 53 - 53: i1IIi
  if 59 - 59: o0oOOo0O0Ooo + I1IiiI % OoooooooOO - iIii1I11I1II1
  if 9 - 9: i1IIi - OoOoOO00
  if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
  if 46 - 46: Ii1I
  if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
  if 87 - 87: I1ii11iIi11i / I1IiiI
  o000o0o00Oo = socket . htons ( 20 + 36 )
  I1IiiIiii1 = struct . pack ( "BBHHHBBH" , 0x45 , 0 , o000o0o00Oo , 0 , 0 , 32 , 1 , 0 ) + O00oOoo00O + oOooo00OOO000
  I1IiiIiii1 = lisp_ip_checksum ( I1IiiIiii1 )
  I1IiiIiii1 = self . fix_outer_header ( I1IiiIiii1 )
  I1IiiIiii1 += O0OO0ooO00
  IIi1IiiIi1III = bold ( "Too-Big" , False )
  lprint ( "Send ICMP {} to {}, mtu 1400: {}" . format ( IIi1IiiIi1III , OooOOooo ,
 lisp_format_packet ( I1IiiIiii1 ) ) )
  if 19 - 19: i1IIi % I1IiiI - iIii1I11I1II1 - oO0o / I1ii11iIi11i
  try :
   lisp_icmp_raw_socket . sendto ( I1IiiIiii1 , ( OooOOooo , 0 ) )
  except socket . error as o0o00oO0oo000 :
   lprint ( "lisp_icmp_raw_socket.sendto() failed: {}" . format ( o0o00oO0oo000 ) )
   return ( False )
   if 16 - 16: Ii1I
   if 79 - 79: OoooooooOO - ooOoO0o * Ii1I - II111iiii % OoOoOO00 * IiII
   if 31 - 31: I1IiiI
   if 36 - 36: OoO0O00 + OoO0O00 + OoO0O00 % Oo0Ooo * iII111i
   if 98 - 98: I11i . I11i / Oo0Ooo / Ii1I / I1IiiI
   if 56 - 56: o0oOOo0O0Ooo / IiII
  lisp_last_icmp_too_big_sent = lisp_get_timestamp ( )
  return ( True )
  if 11 - 11: OoOoOO00 / I11i
 def fragment ( self ) :
  global lisp_icmp_raw_socket
  global lisp_ignore_df_bit
  if 47 - 47: OOooOOo . I1Ii111 % II111iiii + Oo0Ooo - oO0o . II111iiii
  OO0Oo00OO0oo = self . fix_outer_header ( self . packet )
  if 37 - 37: iIii1I11I1II1 . I1IiiI % OoO0O00 % OoooooooOO . OoooooooOO / O0
  if 25 - 25: II111iiii % II111iiii - Ii1I . O0
  if 79 - 79: IiII / OoO0O00 * OoooooooOO * OoOoOO00 + I1IiiI
  if 68 - 68: I11i / iIii1I11I1II1 . Oo0Ooo + i11iIiiIii + o0oOOo0O0Ooo
  if 92 - 92: OoO0O00 . o0oOOo0O0Ooo . Ii1I % OoOoOO00
  if 58 - 58: I1ii11iIi11i % Ii1I * Ii1I - iII111i
  iIo00oo = len ( OO0Oo00OO0oo )
  if ( iIo00oo <= 1500 ) : return ( [ OO0Oo00OO0oo ] , "Fragment-None" )
  if 9 - 9: ooOoO0o - Ii1I % II111iiii + IiII + OOooOOo % O0
  OO0Oo00OO0oo = self . packet
  if 65 - 65: OOooOOo - OoO0O00 % i11iIiiIii
  if 58 - 58: iII111i
  if 2 - 2: II111iiii + i1IIi
  if 68 - 68: OOooOOo + Ii1I
  if 58 - 58: IiII * Ii1I . i1IIi
  if ( self . inner_version != 4 ) :
   i11I1iiii = random . randint ( 0 , 0xffff )
   i1iIi = OO0Oo00OO0oo [ 0 : 4 ] + struct . pack ( "H" , i11I1iiii ) + OO0Oo00OO0oo [ 6 : 20 ]
   oOO00OOOoO0o = OO0Oo00OO0oo [ 20 : : ]
   o00o0 = self . fragment_outer ( i1iIi , oOO00OOOoO0o )
   return ( o00o0 , "Fragment-Outer" )
   if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
   if 36 - 36: OoOoOO00 . i11iIiiIii
   if 81 - 81: Oo0Ooo * iII111i * OoO0O00
   if 85 - 85: O0 * oO0o
   if 39 - 39: II111iiii * I1IiiI - iIii1I11I1II1
  Ii1 = 56 if ( self . outer_version == 6 ) else 36
  i1iIi = OO0Oo00OO0oo [ 0 : Ii1 ]
  o0OOOoo0000 = OO0Oo00OO0oo [ Ii1 : Ii1 + 20 ]
  oOO00OOOoO0o = OO0Oo00OO0oo [ Ii1 + 20 : : ]
  if 19 - 19: OoooooooOO . I1IiiI + I1Ii111 - I1IiiI / I1IiiI % IiII
  if 4 - 4: i11iIiiIii * I1ii11iIi11i + OoooooooOO - IiII . ooOoO0o . iIii1I11I1II1
  if 48 - 48: o0oOOo0O0Ooo * oO0o . I1IiiI - I1Ii111 + OOooOOo . Oo0Ooo
  if 62 - 62: I11i + OoooooooOO * iIii1I11I1II1 / i1IIi * O0
  if 10 - 10: iIii1I11I1II1 * OoooooooOO / OOooOOo
  III11iIII1 = struct . unpack ( "H" , o0OOOoo0000 [ 6 : 8 ] ) [ 0 ]
  III11iIII1 = socket . ntohs ( III11iIII1 )
  if ( III11iIII1 & 0x4000 ) :
   if ( lisp_icmp_raw_socket != None ) :
    Iiiiii = OO0Oo00OO0oo [ Ii1 : : ]
    if ( self . send_icmp_too_big ( Iiiiii ) ) : return ( [ ] , None )
    if 80 - 80: I1IiiI
   if ( lisp_ignore_df_bit ) :
    III11iIII1 &= ~ 0x4000
   else :
    oO0OOo = bold ( "DF-bit set" , False )
    dprint ( "{} in inner header, packet discarded" . format ( oO0OOo ) )
    return ( [ ] , "Fragment-None-DF-bit" )
    if 63 - 63: II111iiii . I1Ii111 % IiII + II111iiii
    if 81 - 81: OOooOOo - I1IiiI % o0oOOo0O0Ooo
    if 7 - 7: ooOoO0o - i1IIi . OoOoOO00
  o0O0 = 0
  iIo00oo = len ( oOO00OOOoO0o )
  o00o0 = [ ]
  while ( o0O0 < iIo00oo ) :
   o00o0 . append ( oOO00OOOoO0o [ o0O0 : o0O0 + 1400 ] )
   o0O0 += 1400
   if 12 - 12: IiII / OoO0O00 / O0 * IiII
   if 51 - 51: ooOoO0o * iII111i / i1IIi
   if 2 - 2: oO0o + IiII . iII111i - i1IIi + I1Ii111
   if 54 - 54: OoooooooOO . oO0o - iII111i
   if 76 - 76: I1Ii111
  iIII1I1i = o00o0
  o00o0 = [ ]
  O00o0 = True if III11iIII1 & 0x2000 else False
  III11iIII1 = ( III11iIII1 & 0x1fff ) * 8
  for oo0O00o0O0Oo in iIII1I1i :
   if 98 - 98: iIii1I11I1II1 + i11iIiiIii * I1ii11iIi11i / I1Ii111 / ooOoO0o - O0
   if 42 - 42: iII111i
   if 77 - 77: i1IIi * oO0o % OoooooooOO + O0 * ooOoO0o
   if 28 - 28: I11i . OoooooooOO * OOooOOo + i11iIiiIii % I1IiiI . iIii1I11I1II1
   ooo0Oo00O = old_div ( III11iIII1 , 8 )
   if ( O00o0 ) :
    ooo0Oo00O |= 0x2000
   elif ( oo0O00o0O0Oo != iIII1I1i [ - 1 ] ) :
    ooo0Oo00O |= 0x2000
    if 28 - 28: IiII + OoOoOO00 . IiII - Ii1I % i1IIi % iIii1I11I1II1
   ooo0Oo00O = socket . htons ( ooo0Oo00O )
   o0OOOoo0000 = o0OOOoo0000 [ 0 : 6 ] + struct . pack ( "H" , ooo0Oo00O ) + o0OOOoo0000 [ 8 : : ]
   if 100 - 100: Oo0Ooo - OOooOOo * ooOoO0o * OoO0O00
   if 64 - 64: I11i / II111iiii / OoO0O00 - ooOoO0o * iIii1I11I1II1 . iII111i
   if 25 - 25: OOooOOo - Ii1I . I11i
   if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
   if 37 - 37: OoO0O00 * I11i + Ii1I + I1ii11iIi11i * o0oOOo0O0Ooo
   if 95 - 95: Ii1I - i11iIiiIii % i11iIiiIii - O0 * I1Ii111
   iIo00oo = len ( oo0O00o0O0Oo )
   III11iIII1 += iIo00oo
   o0oOOO = socket . htons ( iIo00oo + 20 )
   o0OOOoo0000 = o0OOOoo0000 [ 0 : 2 ] + struct . pack ( "H" , o0oOOO ) + o0OOOoo0000 [ 4 : 10 ] + struct . pack ( "H" , 0 ) + o0OOOoo0000 [ 12 : : ]
   if 81 - 81: II111iiii * I1IiiI % i1IIi * i11iIiiIii + OoOoOO00
   o0OOOoo0000 = lisp_ip_checksum ( o0OOOoo0000 )
   oo0OoOO000O = o0OOOoo0000 + oo0O00o0O0Oo
   if 62 - 62: i1IIi * iIii1I11I1II1 % oO0o % OoOoOO00 / OoooooooOO
   if 39 - 39: Oo0Ooo % iII111i
   if 90 - 90: I1IiiI * I1ii11iIi11i . I11i * Ii1I - o0oOOo0O0Ooo
   if 40 - 40: O0 / IiII - II111iiii + o0oOOo0O0Ooo % Oo0Ooo
   if 93 - 93: ooOoO0o
   iIo00oo = len ( oo0OoOO000O )
   if ( self . outer_version == 4 ) :
    o0oOOO = iIo00oo + Ii1
    iIo00oo += 16
    i1iIi = i1iIi [ 0 : 2 ] + struct . pack ( "H" , o0oOOO ) + i1iIi [ 4 : : ]
    if 82 - 82: I1ii11iIi11i / ooOoO0o . i11iIiiIii + OOooOOo - OoOoOO00 / iII111i
    i1iIi = lisp_ip_checksum ( i1iIi )
    oo0OoOO000O = i1iIi + oo0OoOO000O
    oo0OoOO000O = self . fix_outer_header ( oo0OoOO000O )
    if 99 - 99: oO0o / i1IIi
    if 2 - 2: oO0o . iII111i
    if 42 - 42: OoO0O00 - I1ii11iIi11i * IiII - ooOoO0o
    if 75 - 75: iII111i * Oo0Ooo / I1Ii111 * Oo0Ooo / ooOoO0o
    if 14 - 14: i1IIi * iIii1I11I1II1 - Ii1I * OoOoOO00 - iII111i / oO0o
   OO0OOoOOO = Ii1 - 12
   o0oOOO = socket . htons ( iIo00oo )
   oo0OoOO000O = oo0OoOO000O [ 0 : OO0OOoOOO ] + struct . pack ( "H" , o0oOOO ) + oo0OoOO000O [ OO0OOoOOO + 2 : : ]
   if 96 - 96: I1ii11iIi11i - O0
   o00o0 . append ( oo0OoOO000O )
   if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
  return ( o00o0 , "Fragment-Inner" )
  if 99 - 99: o0oOOo0O0Ooo + OOooOOo
  if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
 def fix_outer_header ( self , packet ) :
  if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
  if 76 - 76: oO0o / OoOoOO00
  if 12 - 12: I1Ii111
  if 58 - 58: OoO0O00 + iIii1I11I1II1 % O0 + I11i + OoOoOO00 * OoooooooOO
  if 41 - 41: oO0o * I1IiiI
  if 76 - 76: oO0o . O0 * OoooooooOO + ooOoO0o
  if 53 - 53: Oo0Ooo
  if 3 - 3: IiII - OoooooooOO * OoooooooOO - I1IiiI / I1Ii111 * I1ii11iIi11i
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 : 4 ] + packet [ 2 : 3 ] + packet [ 4 : 6 ] + packet [ 7 : 8 ] + packet [ 6 : 7 ] + packet [ 8 : : ]
    if 58 - 58: IiII % iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * iII111i
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 : 4 ] + packet [ 2 : 3 ] + packet [ 4 : : ]
    if 32 - 32: OoooooooOO + o0oOOo0O0Ooo
    if 91 - 91: ooOoO0o - I1Ii111 * I1Ii111
  return ( packet )
  if 55 - 55: iIii1I11I1II1 + I1IiiI - Oo0Ooo
  if 24 - 24: OoO0O00 / I1Ii111 + iII111i * I11i * iII111i
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 10 - 10: I1IiiI - I1ii11iIi11i - Oo0Ooo - o0oOOo0O0Ooo
  dest = dest . print_address_no_iid ( )
  o00o0 , ii1IIii = self . fragment ( )
  if 11 - 11: I1IiiI - Ii1I * OOooOOo % o0oOOo0O0Ooo
  for oo0OoOO000O in o00o0 :
   if ( len ( o00o0 ) != 1 ) :
    self . packet = oo0OoOO000O
    self . print_packet ( ii1IIii , True )
    if 5 - 5: I1ii11iIi11i / o0oOOo0O0Ooo * I11i - i11iIiiIii - OoooooooOO / ooOoO0o
    if 6 - 6: I11i * OoooooooOO - OOooOOo + O0 * I1Ii111
   try : lisp_raw_socket . sendto ( oo0OoOO000O , ( dest , 0 ) )
   except socket . error as o0o00oO0oo000 :
    lprint ( "socket.sendto() failed: {}" . format ( o0o00oO0oo000 ) )
    if 90 - 90: i1IIi . oO0o / I1Ii111 . OOooOOo / I1Ii111
    if 1 - 1: iII111i % ooOoO0o
    if 99 - 99: iII111i + iIii1I11I1II1 . OOooOOo / OoO0O00 * I1ii11iIi11i
    if 87 - 87: IiII / II111iiii % OoO0O00 % OoO0O00
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 91 - 91: I1IiiI / II111iiii * OOooOOo
   if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
  OO0Oo00OO0oo = mac_header + self . packet
  if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
  if 81 - 81: OoO0O00 - iIii1I11I1II1
  if 60 - 60: I1Ii111
  if 77 - 77: I1IiiI / I1ii11iIi11i
  if 95 - 95: I1Ii111 * i1IIi + oO0o
  if 40 - 40: II111iiii
  if 7 - 7: OOooOOo / OoO0O00
  if 88 - 88: i1IIi
  if 53 - 53: ooOoO0o . OOooOOo . o0oOOo0O0Ooo + oO0o
  if 17 - 17: iIii1I11I1II1 + i1IIi . I1ii11iIi11i + Ii1I % i1IIi . oO0o
  if 57 - 57: oO0o
  l2_socket . write ( OO0Oo00OO0oo )
  return
  if 92 - 92: II111iiii - OoO0O00 - OOooOOo % I1IiiI - OoOoOO00 * I1Ii111
  if 16 - 16: iIii1I11I1II1 + OoooooooOO - ooOoO0o * IiII
 def bridge_l2_packet ( self , eid , db ) :
  try : iiI1IiI1I1I = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : i1i1111I = lisp_myinterfaces [ iiI1IiI1I1I . interface ]
  except : return
  try :
   socket = i1i1111I . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 42 - 42: Oo0Ooo + I1IiiI + I11i + i1IIi / OoooooooOO
  try : socket . send ( self . packet )
  except socket . error as o0o00oO0oo000 :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( o0o00oO0oo000 ) )
   if 20 - 20: oO0o - o0oOOo0O0Ooo * OoO0O00 % i1IIi - iIii1I11I1II1 . OOooOOo
   if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
   if 45 - 45: OOooOOo + I11i / OoooooooOO - Ii1I + OoooooooOO
 def is_lisp_packet ( self , packet ) :
  Ii1iiI1 = ( struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ] == LISP_UDP_PROTOCOL )
  if ( Ii1iiI1 == False ) : return ( False )
  if 42 - 42: iIii1I11I1II1 * I1IiiI * I1Ii111
  O00oo0o0o0oo = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
  if ( socket . ntohs ( O00oo0o0o0oo ) == LISP_DATA_PORT ) : return ( True )
  O00oo0o0o0oo = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
  if ( socket . ntohs ( O00oo0o0o0oo ) == LISP_DATA_PORT ) : return ( True )
  return ( False )
  if 22 - 22: I1Ii111 + iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoooooooOO
  if 42 - 42: OoooooooOO - OoOoOO00 - OOooOOo * I1Ii111
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  OO0Oo00OO0oo = self . packet
  OO0 = len ( OO0Oo00OO0oo )
  iii111 = o00O000oooOo = True
  if 100 - 100: ooOoO0o % I11i / O0 * Ii1I - i11iIiiIii
  if 90 - 90: IiII / II111iiii / o0oOOo0O0Ooo
  if 92 - 92: O0 * I1IiiI / OoO0O00
  if 44 - 44: I11i
  oOI1iI1Ii11 = 0
  oO0O = self . lisp_header . get_instance_id ( )
  if ( is_lisp_packet ) :
   I1II11IIi11i = struct . unpack ( "B" , OO0Oo00OO0oo [ 0 : 1 ] ) [ 0 ]
   self . outer_version = I1II11IIi11i >> 4
   if ( self . outer_version == 4 ) :
    if 67 - 67: iIii1I11I1II1 - iII111i
    if 81 - 81: O0
    if 38 - 38: iII111i
    if 78 - 78: i11iIiiIii . IiII % OoooooooOO - IiII - IiII + Ii1I
    if 11 - 11: I11i
    IioooooOOo0Oo = struct . unpack ( "H" , OO0Oo00OO0oo [ 10 : 12 ] ) [ 0 ]
    OO0Oo00OO0oo = lisp_ip_checksum ( OO0Oo00OO0oo )
    IiI1Iii1 = struct . unpack ( "H" , OO0Oo00OO0oo [ 10 : 12 ] ) [ 0 ]
    if ( IiI1Iii1 != 0 ) :
     if ( IioooooOOo0Oo != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( OO0 )
       if 29 - 29: O0 * i11iIiiIii / OoooooooOO / o0oOOo0O0Ooo . ooOoO0o
       if 70 - 70: OoooooooOO . ooOoO0o / oO0o . oO0o - o0oOOo0O0Ooo
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 29 - 29: I11i % OOooOOo - ooOoO0o
      if 26 - 26: O0 . I11i + iII111i - Ii1I . I11i
      if 2 - 2: I1ii11iIi11i . Oo0Ooo * OOooOOo % II111iiii . iII111i
    II1i1iI = LISP_AFI_IPV4
    o0O0 = 12
    self . outer_tos = struct . unpack ( "B" , OO0Oo00OO0oo [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , OO0Oo00OO0oo [ 8 : 9 ] ) [ 0 ]
    oOI1iI1Ii11 = 20
   elif ( self . outer_version == 6 ) :
    II1i1iI = LISP_AFI_IPV6
    o0O0 = 8
    iI111I1 = struct . unpack ( "H" , OO0Oo00OO0oo [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( iI111I1 ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , OO0Oo00OO0oo [ 7 : 8 ] ) [ 0 ]
    oOI1iI1Ii11 = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( OO0 )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 46 - 46: Ii1I
    if 42 - 42: iIii1I11I1II1
   self . outer_source . afi = II1i1iI
   self . outer_dest . afi = II1i1iI
   IIi1IiIii = self . outer_source . addr_length ( )
   if 40 - 40: I1IiiI
   self . outer_source . unpack_address ( OO0Oo00OO0oo [ o0O0 : o0O0 + IIi1IiIii ] )
   o0O0 += IIi1IiIii
   self . outer_dest . unpack_address ( OO0Oo00OO0oo [ o0O0 : o0O0 + IIi1IiIii ] )
   OO0Oo00OO0oo = OO0Oo00OO0oo [ oOI1iI1Ii11 : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 3 - 3: ooOoO0o / i1IIi - OoOoOO00
   if 73 - 73: OoooooooOO * O0 * ooOoO0o
   if 7 - 7: II111iiii + i1IIi
   if 95 - 95: i11iIiiIii + OoooooooOO / OOooOOo - iIii1I11I1II1 + iIii1I11I1II1
   I1I1iIIiii1 = struct . unpack ( "H" , OO0Oo00OO0oo [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( I1I1iIIiii1 )
   I1I1iIIiii1 = struct . unpack ( "H" , OO0Oo00OO0oo [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( I1I1iIIiii1 )
   I1I1iIIiii1 = struct . unpack ( "H" , OO0Oo00OO0oo [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( I1I1iIIiii1 )
   I1I1iIIiii1 = struct . unpack ( "H" , OO0Oo00OO0oo [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( I1I1iIIiii1 )
   OO0Oo00OO0oo = OO0Oo00OO0oo [ 8 : : ]
   if 32 - 32: Ii1I * I1ii11iIi11i - OoooooooOO / I1IiiI . ooOoO0o - i1IIi
   if 60 - 60: OoOoOO00 % OoOoOO00
   if 2 - 2: Ii1I . O0 - oO0o + IiII
   if 96 - 96: Ii1I + Ii1I
   iii111 = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   o00O000oooOo = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 28 - 28: iII111i
   if 6 - 6: I1IiiI - iII111i
   if 49 - 49: II111iiii
   if 33 - 33: o0oOOo0O0Ooo - oO0o % I1ii11iIi11i * I11i . OoooooooOO % Ii1I
   if ( self . lisp_header . decode ( OO0Oo00OO0oo ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( OO0 )
    if 29 - 29: iII111i + II111iiii . i11iIiiIii . Ii1I - O0
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 47 - 47: oO0o . I1ii11iIi11i - iIii1I11I1II1 % II111iiii / OoOoOO00 % OoooooooOO
   OO0Oo00OO0oo = OO0Oo00OO0oo [ 8 : : ]
   oO0O = self . lisp_header . get_instance_id ( )
   oOI1iI1Ii11 += 16
   if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
  if ( oO0O == 0xffffff ) : oO0O = 0
  if 84 - 84: II111iiii
  if 57 - 57: O0 * iIii1I11I1II1 % O0 . OoooooooOO
  if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
  if 16 - 16: OoO0O00 % I1Ii111 . i1IIi / I1ii11iIi11i - O0
  ooiIi11i1I11Ii = False
  oo0OO0oo = self . lisp_header . k_bits
  if ( oo0OO0oo ) :
   Oo0o = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( Oo0o == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( OO0 )
    if 54 - 54: II111iiii % o0oOOo0O0Ooo - i1IIi . I1IiiI - II111iiii / iIii1I11I1II1
    self . print_packet ( "Receive" , is_lisp_packet )
    iIIIii111 = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( iIIIii111 , oo0OO0oo ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 21 - 21: iII111i % IiII % Oo0Ooo % O0
    if 63 - 63: II111iiii * I1IiiI - OoooooooOO / I1IiiI
   III11II111 = lisp_crypto_keys_by_rloc_decap [ Oo0o ] [ oo0OO0oo ]
   if ( III11II111 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( OO0 )
    if 8 - 8: i11iIiiIii
    self . print_packet ( "Receive" , is_lisp_packet )
    iIIIii111 = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( iIIIii111 ,
 red ( Oo0o , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 4 - 4: i11iIiiIii
    if 28 - 28: OoO0O00
    if 73 - 73: Oo0Ooo . ooOoO0o - Oo0Ooo % OOooOOo / i11iIiiIii / iIii1I11I1II1
    if 15 - 15: ooOoO0o * iIii1I11I1II1 * oO0o
    if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
   III11II111 . use_count += 1
   OO0Oo00OO0oo , ooiIi11i1I11Ii = self . decrypt ( OO0Oo00OO0oo , oOI1iI1Ii11 , III11II111 , Oo0o )
   if ( ooiIi11i1I11Ii == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( OO0 )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 3 - 3: OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
    if 47 - 47: IiII . OOooOOo
    if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
    if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
    if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
    if 68 - 68: OoO0O00 % O0 * iIii1I11I1II1 / oO0o * o0oOOo0O0Ooo + OOooOOo
   if ( III11II111 . cipher_suite == LISP_CS_25519_CHACHA ) :
    OO0Oo00OO0oo = OO0Oo00OO0oo . encode ( "raw_unicode_escape" )
    if 89 - 89: ooOoO0o * I1IiiI . oO0o
    if 75 - 75: ooOoO0o - iII111i % iII111i + ooOoO0o * o0oOOo0O0Ooo - I1ii11iIi11i
    if 26 - 26: I11i * Ii1I % I1IiiI + iII111i
    if 38 - 38: iII111i - Oo0Ooo / Ii1I + oO0o . iII111i + IiII
    if 19 - 19: Ii1I
    if 51 - 51: iIii1I11I1II1
  I1II11IIi11i = struct . unpack ( "B" , OO0Oo00OO0oo [ 0 : 1 ] ) [ 0 ]
  self . inner_version = I1II11IIi11i >> 4
  if ( iii111 and self . inner_version == 4 and I1II11IIi11i >= 0x45 ) :
   II1I = socket . ntohs ( struct . unpack ( "H" , OO0Oo00OO0oo [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , OO0Oo00OO0oo [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , OO0Oo00OO0oo [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , OO0Oo00OO0oo [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( OO0Oo00OO0oo [ 12 : 16 ] )
   self . inner_dest . unpack_address ( OO0Oo00OO0oo [ 16 : 20 ] )
   III11iIII1 = socket . ntohs ( struct . unpack ( "H" , OO0Oo00OO0oo [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( III11iIII1 & 0x2000 or III11iIII1 != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , OO0Oo00OO0oo [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , OO0Oo00OO0oo [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 10 - 10: i11iIiiIii . OoooooooOO . O0 % ooOoO0o / OoO0O00
  elif ( iii111 and self . inner_version == 6 and I1II11IIi11i >= 0x60 ) :
   II1I = socket . ntohs ( struct . unpack ( "H" , OO0Oo00OO0oo [ 4 : 6 ] ) [ 0 ] ) + 40
   iI111I1 = struct . unpack ( "H" , OO0Oo00OO0oo [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( iI111I1 ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , OO0Oo00OO0oo [ 7 : 8 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , OO0Oo00OO0oo [ 6 : 7 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( OO0Oo00OO0oo [ 8 : 24 ] )
   self . inner_dest . unpack_address ( OO0Oo00OO0oo [ 24 : 40 ] )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , OO0Oo00OO0oo [ 40 : 42 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , OO0Oo00OO0oo [ 42 : 44 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 36 - 36: I1IiiI % i1IIi + OoO0O00
  elif ( o00O000oooOo ) :
   II1I = len ( OO0Oo00OO0oo )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_protocol = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( OO0Oo00OO0oo [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( OO0Oo00OO0oo [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( OO0 )
   if 59 - 59: i11iIiiIii - i11iIiiIii + I1IiiI
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( I1II11IIi11i ) ) )
   if 4 - 4: Oo0Ooo * O0 - oO0o % ooOoO0o + OoOoOO00
   OO0Oo00OO0oo = lisp_format_packet ( OO0Oo00OO0oo [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( OO0Oo00OO0oo ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 3 - 3: OoOoOO00
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = oO0O
  self . inner_dest . instance_id = oO0O
  if 91 - 91: O0 - I11i % I1Ii111
  if 46 - 46: ooOoO0o / I1IiiI . IiII % OoO0O00 / i11iIiiIii
  if 13 - 13: I1Ii111 % o0oOOo0O0Ooo + OOooOOo + I1Ii111 + i11iIiiIii - I1ii11iIi11i
  if 70 - 70: II111iiii * II111iiii . I1IiiI
  if 11 - 11: iII111i
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   i1OooO00oO00o = lisp_get_echo_nonce ( self . outer_source , None )
   if ( i1OooO00oO00o == None ) :
    IIII1iI1IiIiI = self . outer_source . print_address_no_iid ( )
    i1OooO00oO00o = lisp_echo_nonce ( IIII1iI1IiIiI )
    if 43 - 43: II111iiii
   o000oo = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    i1OooO00oO00o . receive_request ( lisp_ipc_socket , o000oo )
   elif ( i1OooO00oO00o . request_nonce_sent ) :
    i1OooO00oO00o . receive_echo ( lisp_ipc_socket , o000oo )
    if 58 - 58: ooOoO0o + II111iiii + Ii1I . OoooooooOO
    if 42 - 42: iIii1I11I1II1 / I11i . O0 . Ii1I
    if 12 - 12: i11iIiiIii - iIii1I11I1II1 * IiII * iII111i
    if 19 - 19: O0 + oO0o + o0oOOo0O0Ooo
    if 81 - 81: iIii1I11I1II1
    if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
    if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
  if ( ooiIi11i1I11Ii ) : self . packet += OO0Oo00OO0oo [ : II1I ]
  if 89 - 89: OoooooooOO % II111iiii - OoO0O00 % i11iIiiIii
  if 7 - 7: IiII
  if 15 - 15: Oo0Ooo + iII111i + I1IiiI * o0oOOo0O0Ooo
  if 33 - 33: o0oOOo0O0Ooo * Oo0Ooo
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 88 - 88: I1Ii111 % OOooOOo - OoOoOO00 - OoOoOO00 . I1IiiI
  if 52 - 52: II111iiii / II111iiii / I1IiiI - I1Ii111
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 91 - 91: I1IiiI + o0oOOo0O0Ooo % II111iiii + OoO0O00
  if 66 - 66: iIii1I11I1II1 * II111iiii % Oo0Ooo % I1IiiI - Ii1I
 def strip_outer_headers ( self ) :
  o0O0 = 16
  o0O0 += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ o0O0 : : ]
  return ( self )
  if 59 - 59: IiII % oO0o
  if 21 - 21: OoooooooOO % OoOoOO00 - OoOoOO00 / I1ii11iIi11i / o0oOOo0O0Ooo
 def hash_ports ( self ) :
  OO0Oo00OO0oo = self . packet
  I1II11IIi11i = self . inner_version
  I111i = 0
  if ( I1II11IIi11i == 4 ) :
   II1IiIiiI1III = struct . unpack ( "B" , OO0Oo00OO0oo [ 9 : 10 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( II1IiIiiI1III )
   if ( II1IiIiiI1III in [ 6 , 17 ] ) :
    I111i = II1IiIiiI1III
    I111i += struct . unpack ( "I" , OO0Oo00OO0oo [ 20 : 24 ] ) [ 0 ]
    I111i = ( I111i >> 16 ) ^ ( I111i & 0xffff )
    if 12 - 12: iII111i + O0
    if 85 - 85: II111iiii - Ii1I
  if ( I1II11IIi11i == 6 ) :
   II1IiIiiI1III = struct . unpack ( "B" , OO0Oo00OO0oo [ 6 : 7 ] ) [ 0 ]
   if ( II1IiIiiI1III in [ 6 , 17 ] ) :
    I111i = II1IiIiiI1III
    I111i += struct . unpack ( "I" , OO0Oo00OO0oo [ 40 : 44 ] ) [ 0 ]
    I111i = ( I111i >> 16 ) ^ ( I111i & 0xffff )
    if 93 - 93: IiII / i11iIiiIii - oO0o + OoO0O00 / i1IIi
    if 62 - 62: I1ii11iIi11i / OoooooooOO * I1IiiI - i1IIi
  return ( I111i )
  if 81 - 81: oO0o / O0 * ooOoO0o % OoOoOO00 / O0
  if 85 - 85: OoooooooOO + OoooooooOO
 def hash_packet ( self ) :
  I111i = self . inner_source . address ^ self . inner_dest . address
  I111i += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   I111i = ( I111i >> 16 ) ^ ( I111i & 0xffff )
  elif ( self . inner_version == 6 ) :
   I111i = ( I111i >> 64 ) ^ ( I111i & 0xffffffffffffffff )
   I111i = ( I111i >> 32 ) ^ ( I111i & 0xffffffff )
   I111i = ( I111i >> 16 ) ^ ( I111i & 0xffff )
   if 23 - 23: i1IIi
  self . udp_sport = 0xf000 | ( I111i & 0xfff )
  if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
  if 74 - 74: Oo0Ooo - II111iiii - IiII
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   IiII1II1 = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # Oo0Ooo % i1IIi % OoO0O00 / i1IIi
 green ( IiII1II1 , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 30 - 30: OoOoOO00 - i11iIiiIii
   if 94 - 94: OoOoOO00 % iII111i
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   iI11ii = "decap"
   iI11ii += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   iI11ii = s_or_r
   if ( iI11ii in [ "Send" , "Replicate" ] or iI11ii . find ( "Fragment" ) != - 1 ) :
    iI11ii = "encap"
    if 23 - 23: OoOoOO00 * IiII / oO0o
    if 60 - 60: ooOoO0o * Ii1I + I1Ii111 . OOooOOo . O0
  Ii1i1ii = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 53 - 53: O0 . OOooOOo
  if 79 - 79: OoooooooOO * I1Ii111 - i1IIi * OoooooooOO % O0 % iIii1I11I1II1
  if 82 - 82: OoOoOO00 . Ii1I
  if 73 - 73: I1Ii111
  if 25 - 25: IiII
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   I11I111i1I1 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 77 - 77: o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO . iIii1I11I1II1
   I11I111i1I1 += bold ( "control-packet" , False ) + ": {} ..."
   if 87 - 87: II111iiii - OoooooooOO / i1IIi . Ii1I - Oo0Ooo . i11iIiiIii
   dprint ( I11I111i1I1 . format ( bold ( s_or_r , False ) , red ( Ii1i1ii , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   I11I111i1I1 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 47 - 47: Oo0Ooo % OoO0O00 - ooOoO0o - Oo0Ooo * oO0o
   if 72 - 72: o0oOOo0O0Ooo % o0oOOo0O0Ooo + iII111i + I1ii11iIi11i / Oo0Ooo
   if 30 - 30: Oo0Ooo + I1IiiI + i11iIiiIii / OoO0O00
   if 64 - 64: IiII
  if ( self . lisp_header . k_bits ) :
   if ( iI11ii == "encap" ) : iI11ii = "encrypt/encap"
   if ( iI11ii == "decap" ) : iI11ii = "decap/decrypt"
   if 80 - 80: I1IiiI - i11iIiiIii / OoO0O00 / OoOoOO00 + OoOoOO00
   if 89 - 89: O0 + IiII * I1Ii111
  IiII1II1 = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 30 - 30: OoOoOO00
  dprint ( I11I111i1I1 . format ( bold ( s_or_r , False ) , red ( Ii1i1ii , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( IiII1II1 , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( iI11ii ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 39 - 39: I1ii11iIi11i + o0oOOo0O0Ooo + I1Ii111 + IiII
  if 48 - 48: I1Ii111 / ooOoO0o . iIii1I11I1II1
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 72 - 72: i1IIi . o0oOOo0O0Ooo
  if 3 - 3: OoOoOO00 % II111iiii - O0
 def get_raw_socket ( self ) :
  oO0O = str ( self . lisp_header . get_instance_id ( ) )
  if ( oO0O == "0" ) : return ( None )
  if ( oO0O not in lisp_iid_to_interface ) : return ( None )
  if 52 - 52: OoO0O00
  i1i1111I = lisp_iid_to_interface [ oO0O ]
  o0O0o0000o0O0 = i1i1111I . get_socket ( )
  if ( o0O0o0000o0O0 == None ) :
   Oo0 = bold ( "SO_BINDTODEVICE" , False )
   I1 = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( Oo0 , "drop" if I1 else "forward" ) )
   if 73 - 73: ooOoO0o . Oo0Ooo * OoO0O00 - I11i
   if ( I1 ) : return ( None )
   if 27 - 27: I1Ii111
   if 10 - 10: i11iIiiIii + ooOoO0o / OoooooooOO
  oO0O = bold ( oO0O , False )
  iiIi = bold ( i1i1111I . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( oO0O , iiIi ) )
  return ( o0O0o0000o0O0 )
  if 57 - 57: OoooooooOO % II111iiii - I1Ii111
  if 1 - 1: IiII
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 27 - 27: OoOoOO00 . I1Ii111 * OoOoOO00
  iI111iI11iII = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or iI111iI11iII ) :
   O000o0Oo0 = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = O000o0Oo0 ) . start ( )
   if ( iI111iI11iII ) : os . system ( "rm ./log-flows" )
   return
   if 31 - 31: O0 * iII111i - iII111i / iII111i - ooOoO0o / OoOoOO00
   if 16 - 16: o0oOOo0O0Ooo
  Oo0OO0000oooo = datetime . datetime . now ( )
  lisp_flow_log . append ( [ Oo0OO0000oooo , encap , self . packet , self ] )
  if 37 - 37: I1IiiI + OoooooooOO . I1Ii111 + I1IiiI . IiII
  if 44 - 44: OoOoOO00 . I1Ii111 . i1IIi . OoOoOO00 * ooOoO0o
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  ooOoooOoo0oO = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 50 - 50: ooOoO0o
  Oooo0O00OOo0o = red ( self . outer_source . print_address_no_iid ( ) , False )
  II1iiI1iIII1i = red ( self . outer_dest . print_address_no_iid ( ) , False )
  II1iI = green ( self . inner_source . print_address ( ) , False )
  oO00OOo0O0o0 = green ( self . inner_dest . print_address ( ) , False )
  if 31 - 31: iIii1I11I1II1 / OoooooooOO
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   ooOoooOoo0oO += " {}:{} -> {}:{}, LISP control message type {}\n"
   ooOoooOoo0oO = ooOoooOoo0oO . format ( Oooo0O00OOo0o , self . udp_sport , II1iiI1iIII1i , self . udp_dport ,
 self . inner_version )
   return ( ooOoooOoo0oO )
   if 8 - 8: iIii1I11I1II1 . iIii1I11I1II1 + Ii1I . OOooOOo
   if 58 - 58: iIii1I11I1II1 + I1Ii111 - I1ii11iIi11i - i1IIi * OoOoOO00
  if ( self . outer_dest . is_null ( ) == False ) :
   ooOoooOoo0oO += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   ooOoooOoo0oO = ooOoooOoo0oO . format ( Oooo0O00OOo0o , self . udp_sport , II1iiI1iIII1i , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 4 - 4: OoooooooOO
   if 7 - 7: IiII
   if 26 - 26: OOooOOo + Oo0Ooo
   if 71 - 71: I1IiiI . ooOoO0o
   if 43 - 43: I1ii11iIi11i * OOooOOo
  if ( self . lisp_header . k_bits != 0 ) :
   III1i1iI111I1 = "\n"
   if ( self . packet_error != "" ) :
    III1i1iI111I1 = " ({})" . format ( self . packet_error ) + III1i1iI111I1
    if 64 - 64: Oo0Ooo % OoOoOO00 . o0oOOo0O0Ooo % I1IiiI / OOooOOo
   ooOoooOoo0oO += ", encrypted" + III1i1iI111I1
   return ( ooOoooOoo0oO )
   if 74 - 74: IiII - oO0o * OoO0O00 - I1Ii111
   if 81 - 81: o0oOOo0O0Ooo % Ii1I - i11iIiiIii
   if 34 - 34: Ii1I - IiII + I1Ii111
   if 92 - 92: I1IiiI / OoO0O00 - OOooOOo / i11iIiiIii
   if 23 - 23: II111iiii / i11iIiiIii - OoO0O00 * OoO0O00 + iII111i * II111iiii
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 82 - 82: o0oOOo0O0Ooo + Ii1I * I1IiiI - oO0o
   if 6 - 6: OOooOOo / iIii1I11I1II1 / ooOoO0o / I1IiiI - i1IIi - OOooOOo
  II1IiIiiI1III = packet [ 9 : 10 ] if self . inner_version == 4 else packet [ 6 : 7 ]
  II1IiIiiI1III = struct . unpack ( "B" , II1IiIiiI1III ) [ 0 ]
  if 8 - 8: i11iIiiIii * I11i . OOooOOo / OOooOOo
  ooOoooOoo0oO += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  ooOoooOoo0oO = ooOoooOoo0oO . format ( II1iI , oO00OOo0O0o0 , len ( packet ) , self . inner_tos ,
 self . inner_ttl , II1IiIiiI1III )
  if 42 - 42: OoooooooOO / I1Ii111 . o0oOOo0O0Ooo / O0 - IiII * IiII
  if 1 - 1: Ii1I % I1Ii111
  if 97 - 97: OoOoOO00
  if 13 - 13: OoOoOO00 % OOooOOo . O0 / Oo0Ooo % Oo0Ooo
  if ( II1IiIiiI1III in [ 6 , 17 ] ) :
   I1I111iII1 = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( I1I111iII1 ) == 4 ) :
    I1I111iII1 = socket . ntohl ( struct . unpack ( "I" , I1I111iII1 ) [ 0 ] )
    ooOoooOoo0oO += ", ports {} -> {}" . format ( I1I111iII1 >> 16 , I1I111iII1 & 0xffff )
    if 20 - 20: Oo0Ooo % Oo0Ooo + iIii1I11I1II1 % iII111i - OoooooooOO / oO0o
  elif ( II1IiIiiI1III == 1 ) :
   O0II1IIiiIiI11 = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( O0II1IIiiIiI11 ) == 2 ) :
    O0II1IIiiIiI11 = socket . ntohs ( struct . unpack ( "H" , O0II1IIiiIiI11 ) [ 0 ] )
    ooOoooOoo0oO += ", icmp-seq {}" . format ( O0II1IIiiIiI11 )
    if 65 - 65: ooOoO0o * O0 * iII111i
    if 60 - 60: iIii1I11I1II1 . ooOoO0o + I1IiiI % oO0o
  if ( self . packet_error != "" ) :
   ooOoooOoo0oO += " ({})" . format ( self . packet_error )
   if 4 - 4: I1IiiI / II111iiii % O0 * ooOoO0o / II111iiii . Oo0Ooo
  ooOoooOoo0oO += "\n"
  return ( ooOoooOoo0oO )
  if 16 - 16: O0 + O0 - I1IiiI
  if 30 - 30: ooOoO0o
 def is_trace ( self ) :
  I1I111iII1 = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in I1I111iII1 )
  if 33 - 33: I1Ii111 * IiII - O0 + I1IiiI / IiII
  if 19 - 19: i1IIi % II111iiii
  if 85 - 85: IiII - o0oOOo0O0Ooo % OOooOOo - II111iiii
  if 56 - 56: Ii1I * i11iIiiIii
  if 92 - 92: II111iiii - O0 . I1Ii111
  if 59 - 59: OoOoOO00
  if 47 - 47: II111iiii - I1ii11iIi11i - Ii1I
  if 9 - 9: I1ii11iIi11i - IiII
  if 64 - 64: i1IIi
  if 71 - 71: IiII * o0oOOo0O0Ooo
  if 99 - 99: o0oOOo0O0Ooo
  if 28 - 28: OoooooooOO % O0 - OOooOOo / o0oOOo0O0Ooo / I1IiiI
  if 41 - 41: II111iiii * IiII / OoO0O00 . oO0o
  if 50 - 50: OoooooooOO + iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii . ooOoO0o
  if 75 - 75: iIii1I11I1II1 % ooOoO0o / OOooOOo - iII111i % i11iIiiIii
  if 11 - 11: I11i . Ii1I
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 87 - 87: OOooOOo + OOooOOo
class lisp_data_header ( object ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 45 - 45: i1IIi - Oo0Ooo
  if 87 - 87: OoOoOO00 - OoO0O00 * OoO0O00 / Ii1I . I11i * o0oOOo0O0Ooo
 def print_header ( self , e_or_d ) :
  iii1I = lisp_hex_string ( self . first_long & 0xffffff )
  oooo000 = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 27 - 27: iIii1I11I1II1 + oO0o % Oo0Ooo
  I11I111i1I1 = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 99 - 99: iIii1I11I1II1 - Oo0Ooo / O0 / IiII
  return ( I11I111i1I1 . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 iii1I , oooo000 ) )
  if 52 - 52: O0 + ooOoO0o
  if 11 - 11: i1IIi / I1Ii111 * I1ii11iIi11i * I1Ii111 * ooOoO0o - i11iIiiIii
 def encode ( self ) :
  oOOoooo0o0 = "II"
  iii1I = socket . htonl ( self . first_long )
  oooo000 = socket . htonl ( self . second_long )
  if 59 - 59: ooOoO0o % Oo0Ooo - oO0o + IiII
  I1IIII = struct . pack ( oOOoooo0o0 , iii1I , oooo000 )
  return ( I1IIII )
  if 69 - 69: IiII
  if 24 - 24: OoO0O00 / O0 * ooOoO0o % iIii1I11I1II1 + i1IIi % O0
 def decode ( self , packet ) :
  oOOoooo0o0 = "II"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( False )
  if 93 - 93: II111iiii . I11i - i1IIi * OoOoOO00
  iii1I , oooo000 = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  if 28 - 28: I11i % I1Ii111
  if 49 - 49: IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . Ii1I * I1ii11iIi11i
  self . first_long = socket . ntohl ( iii1I )
  self . second_long = socket . ntohl ( oooo000 )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 17 - 17: I1ii11iIi11i * OoooooooOO % i1IIi % OoooooooOO . iII111i
  if 20 - 20: OoO0O00 . oO0o
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 4 - 4: Oo0Ooo % Ii1I % OoO0O00 * iII111i % OoooooooOO
  if 38 - 38: OoooooooOO . iII111i
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 43 - 43: OoooooooOO
  if 8 - 8: OOooOOo + I11i . I11i
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 89 - 89: I1ii11iIi11i * I1ii11iIi11i * OoOoOO00 / iII111i
  if 60 - 60: OoO0O00 / iII111i / I1IiiI + oO0o
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 93 - 93: OoooooooOO * Ii1I / O0 + Ii1I - iIii1I11I1II1
  if 6 - 6: IiII - Oo0Ooo - I11i - O0 % OoooooooOO
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 88 - 88: O0 / o0oOOo0O0Ooo * o0oOOo0O0Ooo . o0oOOo0O0Ooo . O0
  if 27 - 27: i11iIiiIii % iII111i + Ii1I . OOooOOo
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 9 - 9: OoO0O00
  if 43 - 43: Ii1I . OOooOOo + I1IiiI * i11iIiiIii
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 2 - 2: OOooOOo
  if 3 - 3: I1IiiI . iII111i % O0 - ooOoO0o / O0
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 79 - 79: Ii1I + oO0o % ooOoO0o % I1IiiI
  if 68 - 68: II111iiii - OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo % II111iiii
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 53 - 53: iII111i . oO0o / Oo0Ooo . OoO0O00 . i11iIiiIii
  if 60 - 60: II111iiii
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 25 - 25: Oo0Ooo + o0oOOo0O0Ooo - OoO0O00
  if 57 - 57: II111iiii . i1IIi
  if 33 - 33: iII111i + Oo0Ooo % I11i . oO0o
class lisp_echo_nonce ( object ) :
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
  if 6 - 6: IiII + I1ii11iIi11i
  if 62 - 62: oO0o . I1Ii111 - OoooooooOO * II111iiii . i11iIiiIii
 def send_ipc ( self , ipc_socket , ipc ) :
  iiIIiIi1i1I1 = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  OooOOooo = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , iiIIiIi1i1I1 )
  lisp_ipc ( ipc , ipc_socket , OooOOooo )
  if 52 - 52: o0oOOo0O0Ooo % II111iiii . OoooooooOO
  if 7 - 7: II111iiii - I1ii11iIi11i / I11i % OoooooooOO + i1IIi
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  I1Iii1 = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , I1Iii1 )
  if 9 - 9: II111iiii % Oo0Ooo * Ii1I + IiII % OoO0O00 . i1IIi
  if 68 - 68: II111iiii % I1Ii111 * i11iIiiIii
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  I1Iii1 = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , I1Iii1 )
  if 9 - 9: II111iiii + I1ii11iIi11i / iII111i
  if 51 - 51: I11i % I1ii11iIi11i + OoooooooOO - I1IiiI * OoOoOO00 * iII111i
 def receive_request ( self , ipc_socket , nonce ) :
  I1I1i1 = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( I1I1i1 != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 36 - 36: I1IiiI / Oo0Ooo % iIii1I11I1II1 / O0 . I1ii11iIi11i
  if 53 - 53: o0oOOo0O0Ooo % OoooooooOO - oO0o - i1IIi / OoO0O00
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 33 - 33: IiII * I11i
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 96 - 96: o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + OoO0O00 - IiII - IiII
  if 2 - 2: ooOoO0o % i11iIiiIii
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
  if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
  if 8 - 8: o0oOOo0O0Ooo
  if 78 - 78: i1IIi - Oo0Ooo
  if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   i11iII11I1III = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 44 - 44: OOooOOo . iIii1I11I1II1 . i11iIiiIii % OoooooooOO . ooOoO0o
   if 53 - 53: IiII + O0
   if ( remote_rloc . address > i11iII11I1III . address ) :
    oO = "exit"
    self . request_nonce_sent = None
   else :
    oO = "stay in"
    self . echo_nonce_sent = None
    if 88 - 88: OoooooooOO
    if 46 - 46: O0 % OoooooooOO
   I1IiII = bold ( "collision" , False )
   o0oOOO = red ( i11iII11I1III . print_address_no_iid ( ) , False )
   o0O00o0o = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( I1IiII ,
 o0oOOO , o0O00o0o , oO ) )
   if 31 - 31: ooOoO0o % I1IiiI % IiII / I1Ii111
   if 74 - 74: i1IIi + oO0o - iIii1I11I1II1 . Oo0Ooo
   if 70 - 70: iII111i
   if 51 - 51: O0 - I1ii11iIi11i / I11i * II111iiii + OoO0O00 % I1ii11iIi11i
   if 58 - 58: oO0o + IiII % iII111i - Ii1I - OOooOOo % Ii1I
  if ( self . echo_nonce_sent != None ) :
   o000oo = self . echo_nonce_sent
   o0o00oO0oo000 = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( o0o00oO0oo000 ,
 lisp_hex_string ( o000oo ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( o000oo )
   if 86 - 86: o0oOOo0O0Ooo
   if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
   if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
   if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
   if 65 - 65: I1ii11iIi11i / ooOoO0o
   if 23 - 23: OOooOOo / OOooOOo * o0oOOo0O0Ooo * OOooOOo
   if 57 - 57: iII111i
  o000oo = self . request_nonce_sent
  iII11I = self . last_request_nonce_sent
  if ( o000oo and iII11I != None ) :
   if ( time . time ( ) - iII11I >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( o000oo ) ) )
    if 44 - 44: iII111i
    return ( None )
    if 79 - 79: o0oOOo0O0Ooo % OOooOOo . O0
    if 56 - 56: oO0o + i1IIi * iII111i - O0
    if 84 - 84: iII111i % I1IiiI / iIii1I11I1II1 * Ii1I * iIii1I11I1II1 + I1ii11iIi11i
    if 78 - 78: IiII / iII111i * Ii1I . OOooOOo . oO0o - I1Ii111
    if 39 - 39: ooOoO0o . i1IIi + OoooooooOO . iII111i - i11iIiiIii % I1Ii111
    if 38 - 38: oO0o
    if 9 - 9: I11i . OoO0O00 . oO0o / OoooooooOO
    if 59 - 59: iIii1I11I1II1 + i1IIi % II111iiii
    if 2 - 2: II111iiii + I11i . OoO0O00
  if ( o000oo == None ) :
   o000oo = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( o000oo )
   if 14 - 14: OOooOOo * I1IiiI - I1ii11iIi11i
   self . request_nonce_sent = o000oo
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( o000oo ) ) )
   if 10 - 10: iII111i % I1Ii111 * I1ii11iIi11i * O0 * i11iIiiIii % I1Ii111
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 68 - 68: OoooooooOO * OoOoOO00
   if 9 - 9: I1Ii111
   if 36 - 36: I1Ii111 / OoOoOO00 + OoOoOO00 * ooOoO0o / OOooOOo * O0
   if 17 - 17: OoO0O00 / ooOoO0o % I1IiiI
   if 47 - 47: Oo0Ooo * OoO0O00 / o0oOOo0O0Ooo * I1IiiI
   if ( lisp_i_am_itr == False ) : return ( o000oo | 0x80000000 )
   self . send_request_ipc ( ipc_socket , o000oo )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( o000oo ) ) )
   if 60 - 60: I1ii11iIi11i / IiII . i11iIiiIii / OoO0O00 % II111iiii
   if 6 - 6: iII111i % o0oOOo0O0Ooo + I1Ii111
   if 91 - 91: o0oOOo0O0Ooo + O0 * oO0o * IiII * I1ii11iIi11i
   if 83 - 83: OoooooooOO
   if 52 - 52: o0oOOo0O0Ooo / OoOoOO00 % oO0o % OoO0O00 / IiII % o0oOOo0O0Ooo
   if 88 - 88: OOooOOo / i11iIiiIii / Ii1I / i11iIiiIii * I1ii11iIi11i % I11i
   if 43 - 43: OoOoOO00 * OoO0O00 % i1IIi * Ii1I + iIii1I11I1II1
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( o000oo | 0x80000000 )
  if 80 - 80: o0oOOo0O0Ooo . iII111i . OoooooooOO
  if 63 - 63: ooOoO0o . OOooOOo
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 66 - 66: I1IiiI
  i11Ii1IIi = time . time ( ) - self . last_request_nonce_sent
  OOooO0oOoO = self . last_echo_nonce_rcvd
  return ( i11Ii1IIi >= LISP_NONCE_ECHO_INTERVAL and OOooO0oOoO == None )
  if 46 - 46: I1ii11iIi11i . II111iiii % oO0o + II111iiii
  if 55 - 55: OoooooooOO
 def recently_requested ( self ) :
  OOooO0oOoO = self . last_request_nonce_sent
  if ( OOooO0oOoO == None ) : return ( False )
  if 90 - 90: I1IiiI
  i11Ii1IIi = time . time ( ) - OOooO0oOoO
  return ( i11Ii1IIi <= LISP_NONCE_ECHO_INTERVAL )
  if 4 - 4: OOooOOo % ooOoO0o - OOooOOo - o0oOOo0O0Ooo
  if 30 - 30: IiII
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 34 - 34: oO0o - II111iiii - o0oOOo0O0Ooo + iII111i + I1Ii111
  if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
  if 20 - 20: i11iIiiIii - II111iiii - ooOoO0o % oO0o . ooOoO0o
  if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
  OOooO0oOoO = self . last_good_echo_nonce_rcvd
  if ( OOooO0oOoO == None ) : OOooO0oOoO = 0
  i11Ii1IIi = time . time ( ) - OOooO0oOoO
  if ( i11Ii1IIi <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 84 - 84: OoOoOO00 - I11i
  if 80 - 80: i11iIiiIii % OOooOOo - Oo0Ooo % OOooOOo
  if 89 - 89: Ii1I * I11i + OoOoOO00 / i11iIiiIii
  if 68 - 68: OoooooooOO * I11i
  if 86 - 86: o0oOOo0O0Ooo / OoOoOO00
  if 40 - 40: iII111i
  OOooO0oOoO = self . last_new_request_nonce_sent
  if ( OOooO0oOoO == None ) : OOooO0oOoO = 0
  i11Ii1IIi = time . time ( ) - OOooO0oOoO
  return ( i11Ii1IIi <= LISP_NONCE_ECHO_INTERVAL )
  if 62 - 62: ooOoO0o / OOooOOo
  if 74 - 74: iII111i % I1Ii111 / I1Ii111 - iIii1I11I1II1 - II111iiii + OOooOOo
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   o00o0O0o0o0 = bold ( "down" , False )
   Ii11i1IiII = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , o00o0O0o0o0 , Ii11i1IiII ) )
   if 96 - 96: i11iIiiIii - OoOoOO00 / iII111i % OoooooooOO / iIii1I11I1II1 - OOooOOo
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 52 - 52: iIii1I11I1II1 * OoOoOO00 + o0oOOo0O0Ooo . I11i
   if 59 - 59: iII111i . i1IIi
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 31 - 31: I1IiiI + I1IiiI
  if ( self . recently_requested ( ) == False ) :
   I11I1I = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , I11I1I ) )
   if 24 - 24: i11iIiiIii * II111iiii * iII111i
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 70 - 70: ooOoO0o . i11iIiiIii % OoOoOO00 + oO0o
   if 95 - 95: I1ii11iIi11i
   if 48 - 48: I11i
 def print_echo_nonce ( self ) :
  ii1I1 = lisp_print_elapsed ( self . last_request_nonce_sent )
  ii1 = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 81 - 81: I1IiiI . o0oOOo0O0Ooo % Ii1I
  iiIII = lisp_print_elapsed ( self . last_echo_nonce_sent )
  OOO00o0O = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  o0O0o0000o0O0 = space ( 4 )
  if 18 - 18: ooOoO0o
  ooOo0O0O0oOO0 = "Nonce-Echoing:\n"
  ooOo0O0O0oOO0 += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( o0O0o0000o0O0 , ii1I1 , o0O0o0000o0O0 , ii1 )
  if 92 - 92: OoO0O00 % iIii1I11I1II1 / IiII * iII111i . i1IIi + oO0o
  ooOo0O0O0oOO0 += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( o0O0o0000o0O0 , OOO00o0O , o0O0o0000o0O0 , iiIII )
  if 24 - 24: IiII . iII111i * IiII % i11iIiiIii . i11iIiiIii + i1IIi
  if 64 - 64: iIii1I11I1II1 / IiII / Oo0Ooo - I1ii11iIi11i
  return ( ooOo0O0O0oOO0 )
  if 100 - 100: IiII + i1IIi * OoO0O00
  if 64 - 64: oO0o * i11iIiiIii . Oo0Ooo
  if 52 - 52: Oo0Ooo / ooOoO0o / iII111i - o0oOOo0O0Ooo / iII111i
  if 74 - 74: i1IIi . iIii1I11I1II1
  if 85 - 85: I1IiiI
  if 10 - 10: O0 . II111iiii / OoooooooOO
  if 72 - 72: OoooooooOO . o0oOOo0O0Ooo + O0
  if 46 - 46: OoOoOO00 * I11i / oO0o + Oo0Ooo + IiII
  if 95 - 95: o0oOOo0O0Ooo - Ii1I
class lisp_keys ( object ) :
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
    if 67 - 67: I1ii11iIi11i * Oo0Ooo % o0oOOo0O0Ooo
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   III11II111 = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( III11II111 . encode ( ) )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 19 - 19: OoOoOO00 . OOooOOo . OoooooooOO
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 79 - 79: OOooOOo * ooOoO0o * I1IiiI * I1ii11iIi11i / I1ii11iIi11i
  if 62 - 62: ooOoO0o * Ii1I % I1ii11iIi11i - i1IIi - I1ii11iIi11i
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 24 - 24: OOooOOo
  if 71 - 71: IiII - i1IIi
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 56 - 56: OoOoOO00 + oO0o
  iI1ii = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   iI1ii = struct . pack ( "Q" , iI1ii & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   O0o0 = struct . pack ( "I" , ( iI1ii >> 64 ) & LISP_4_32_MASK )
   o00O0 = struct . pack ( "Q" , iI1ii & LISP_8_64_MASK )
   iI1ii = O0o0 + o00O0
  else :
   iI1ii = struct . pack ( "QQ" , iI1ii >> 64 , iI1ii & LISP_8_64_MASK )
  return ( iI1ii )
  if 19 - 19: IiII % OoooooooOO + OoooooooOO
  if 7 - 7: i1IIi
 def key_length ( self , key ) :
  if ( isinstance ( key , int ) ) : key = self . normalize_pub_key ( key )
  return ( old_div ( len ( key ) , 2 ) )
  if 91 - 91: OoOoOO00 - OoOoOO00 . IiII
  if 33 - 33: I1Ii111 - iIii1I11I1II1 / Ii1I % O0
 def print_key ( self , key ) :
  o0 = self . normalize_pub_key ( key )
  o0Oo0oOO00O = o0 [ 0 : 4 ] . decode ( )
  Oo00OO = o0 [ - 4 : : ] . decode ( )
  return ( "0x{}...{}({})" . format ( o0Oo0oOO00O , Oo00OO , self . key_length ( o0 ) ) )
  if 19 - 19: O0 + Ii1I * Ii1I * i1IIi
  if 28 - 28: oO0o * iII111i
 def normalize_pub_key ( self , key ) :
  if ( isinstance ( key , int ) ) :
   key = lisp_hex_string ( key ) . zfill ( 256 )
   return ( key )
   if 86 - 86: O0 . OoooooooOO * I11i / IiII
  if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
  return ( key )
  if 87 - 87: iIii1I11I1II1
  if 58 - 58: I1ii11iIi11i % i11iIiiIii + OoOoOO00 / I11i - OoooooooOO
 def print_keys ( self , do_bold = True ) :
  o0oOOO = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   o0oOOO += "none"
  else :
   o0oOOO += self . print_key ( self . local_public_key )
   if 62 - 62: OoO0O00 . OoOoOO00
  o0O00o0o = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   o0O00o0o += "none"
  else :
   o0O00o0o += self . print_key ( self . remote_public_key )
   if 22 - 22: ooOoO0o . i11iIiiIii . OoooooooOO . i1IIi
  IIIIiI1iiI = "ECDH" if ( self . curve25519 ) else "DH"
  i1I = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( IIIIiI1iiI , i1I , o0oOOO , o0O00o0o ) )
  if 73 - 73: Ii1I * OoooooooOO * I11i - i11iIiiIii
  if 58 - 58: o0oOOo0O0Ooo + OoOoOO00 - IiII
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 82 - 82: Ii1I . iIii1I11I1II1 / Ii1I / oO0o % iIii1I11I1II1
  if 34 - 34: OOooOOo
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 99 - 99: II111iiii
  III11II111 = self . local_private_key
  o0O0Ooo = self . dh_g_value
  o00oo = self . dh_p_value
  return ( int ( ( o0O0Ooo ** III11II111 ) % o00oo ) )
  if 13 - 13: I11i - ooOoO0o + iII111i % I11i . iII111i - i1IIi
  if 67 - 67: OOooOOo . i11iIiiIii + ooOoO0o . iIii1I11I1II1
 def compute_shared_key ( self , ed , print_shared = False ) :
  III11II111 = self . local_private_key
  iiIi1i = self . remote_public_key
  if 3 - 3: Ii1I * ooOoO0o . OoO0O00 * OoooooooOO + OoOoOO00 / O0
  o0O0ooooO0 = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( o0O0ooooO0 , self . print_keys ( ) ) )
  if 35 - 35: iII111i * OOooOOo
  if ( self . curve25519 ) :
   ooooO0OO0O = curve25519 . Public ( iiIi1i )
   self . shared_key = self . curve25519 . get_shared_key ( ooooO0OO0O )
  else :
   o00oo = self . dh_p_value
   self . shared_key = ( iiIi1i ** III11II111 ) % o00oo
   if 37 - 37: O0 / OOooOOo + Oo0Ooo * OoooooooOO + OoOoOO00 / iIii1I11I1II1
   if 84 - 84: iIii1I11I1II1 + I1ii11iIi11i
   if 77 - 77: i11iIiiIii - I1Ii111 . I1ii11iIi11i % Oo0Ooo . Ii1I
   if 9 - 9: o0oOOo0O0Ooo
   if 55 - 55: OOooOOo % iIii1I11I1II1 + I11i . ooOoO0o
   if 71 - 71: i11iIiiIii / i1IIi + OoOoOO00
   if 23 - 23: i11iIiiIii
  if ( print_shared ) :
   o0 = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( o0 ) )
   if 88 - 88: II111iiii - iII111i / OoooooooOO
   if 71 - 71: I1ii11iIi11i
   if 19 - 19: Oo0Ooo - OoO0O00 + i11iIiiIii / iIii1I11I1II1
   if 1 - 1: IiII % i1IIi
   if 41 - 41: OoO0O00 * OoO0O00 / iII111i + I1ii11iIi11i . o0oOOo0O0Ooo
  self . compute_encrypt_icv_keys ( )
  if 84 - 84: i11iIiiIii + OoO0O00 * I1IiiI + I1ii11iIi11i / Ii1I
  if 80 - 80: I1ii11iIi11i
  if 67 - 67: II111iiii
  if 2 - 2: o0oOOo0O0Ooo - O0 * Ii1I % IiII
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 64 - 64: i1IIi . ooOoO0o
  if 7 - 7: oO0o . iII111i - iII111i / I1Ii111 % Oo0Ooo
 def compute_encrypt_icv_keys ( self ) :
  OOoO00OOo = hashlib . sha256
  if ( self . curve25519 ) :
   iii = self . shared_key
  else :
   iii = lisp_hex_string ( self . shared_key )
   if 5 - 5: i1IIi / I1IiiI / OoooooooOO
   if 74 - 74: I1ii11iIi11i % I1Ii111 - OoO0O00 * I11i . OoooooooOO * OoO0O00
   if 99 - 99: OoOoOO00 . iII111i - OoooooooOO - O0
   if 6 - 6: OOooOOo
   if 3 - 3: O0 - I1Ii111 * Ii1I * OOooOOo / Ii1I
  o0oOOO = self . local_public_key
  if ( type ( o0oOOO ) != int ) : o0oOOO = int ( binascii . hexlify ( o0oOOO ) , 16 )
  o0O00o0o = self . remote_public_key
  if ( type ( o0O00o0o ) != int ) : o0O00o0o = int ( binascii . hexlify ( o0O00o0o ) , 16 )
  O0Ooo000OO00 = "0001" + "lisp-crypto" + lisp_hex_string ( o0oOOO ^ o0O00o0o ) + "0100"
  if 51 - 51: ooOoO0o * IiII * iIii1I11I1II1 / OoOoOO00 % IiII
  IIIIIii1iiIIi = hmac . new ( O0Ooo000OO00 . encode ( ) , iii , OOoO00OOo ) . hexdigest ( )
  IIIIIii1iiIIi = int ( IIIIIii1iiIIi , 16 )
  if 85 - 85: O0 + O0 - O0 - IiII . I1ii11iIi11i % Ii1I
  if 60 - 60: OoooooooOO * Oo0Ooo % I1Ii111
  if 68 - 68: O0 - Oo0Ooo . II111iiii % Ii1I % Oo0Ooo + i11iIiiIii
  if 90 - 90: II111iiii / OOooOOo * I1IiiI - Oo0Ooo
  I1IIiI11 = ( IIIIIii1iiIIi >> 128 ) & LISP_16_128_MASK
  oOooOoOoo = IIIIIii1iiIIi & LISP_16_128_MASK
  I1IIiI11 = lisp_hex_string ( I1IIiI11 ) . zfill ( 32 )
  self . encrypt_key = I1IIiI11 . encode ( )
  Ii1IIIiII1iIII = 32 if self . do_poly else 40
  oOooOoOoo = lisp_hex_string ( oOooOoOoo ) . zfill ( Ii1IIIiII1iIII )
  self . icv_key = oOooOoOoo . encode ( )
  if 62 - 62: II111iiii . ooOoO0o + OoO0O00 % OoO0O00 - O0 - II111iiii
  if 22 - 22: Ii1I - Oo0Ooo % I1ii11iIi11i % ooOoO0o % IiII
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   o00O = self . icv . poly1305aes
   oOoo0 = self . icv . binascii . hexlify
   nonce = oOoo0 ( nonce )
   iiiiiiiiiiiI = o00O ( self . encrypt_key , self . icv_key , nonce , packet )
   if ( lisp_is_python2 ( ) ) :
    iiiiiiiiiiiI = oOoo0 ( iiiiiiiiiiiI . encode ( "raw_unicode_escape" ) )
   else :
    iiiiiiiiiiiI = oOoo0 ( iiiiiiiiiiiI ) . decode ( )
    if 41 - 41: Ii1I
  else :
   III11II111 = binascii . unhexlify ( self . icv_key )
   iiiiiiiiiiiI = hmac . new ( III11II111 , packet , self . icv ) . hexdigest ( )
   iiiiiiiiiiiI = iiiiiiiiiiiI [ 0 : 40 ]
   if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
  return ( iiiiiiiiiiiI )
  if 47 - 47: O0 . o0oOOo0O0Ooo / Ii1I * iII111i
  if 63 - 63: I1Ii111 - oO0o - iII111i - ooOoO0o / oO0o + OoO0O00
 def add_key_by_nonce ( self , nonce ) :
  if ( nonce not in lisp_crypto_keys_by_nonce ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 94 - 94: IiII / I1IiiI . II111iiii
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
  if 37 - 37: OOooOOo + O0 + OOooOOo . iII111i . o0oOOo0O0Ooo
 def delete_key_by_nonce ( self , nonce ) :
  if ( nonce not in lisp_crypto_keys_by_nonce ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 78 - 78: I1IiiI / I11i + o0oOOo0O0Ooo . Oo0Ooo / O0
  if 49 - 49: I1ii11iIi11i
 def add_key_by_rloc ( self , addr_str , encap ) :
  oOO = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 18 - 18: Oo0Ooo + IiII
  if 79 - 79: OoO0O00 - O0 + II111iiii % Ii1I . I1IiiI
  if ( addr_str not in oOO ) :
   oOO [ addr_str ] = [ None , None , None , None ]
   if 43 - 43: I1IiiI % I1ii11iIi11i * Ii1I
  oOO [ addr_str ] [ self . key_id ] = self
  if 31 - 31: Ii1I / iII111i
  if 3 - 3: IiII
  if 37 - 37: Ii1I * OoooooooOO * I11i + Oo0Ooo . I1IiiI
  if 61 - 61: OOooOOo . OOooOOo
  if 17 - 17: II111iiii / ooOoO0o
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , oOO [ addr_str ] )
   if 80 - 80: OOooOOo * OoO0O00 + Ii1I
   if 62 - 62: OoooooooOO . O0 % Oo0Ooo
   if 98 - 98: o0oOOo0O0Ooo * Oo0Ooo - Ii1I . ooOoO0o
 def encode_lcaf ( self , rloc_addr ) :
  iI11i1iI = self . normalize_pub_key ( self . local_public_key )
  oo0O0Ooo0o0 = self . key_length ( iI11i1iI )
  oo0OoOOO = ( 6 + oo0O0Ooo0o0 + 2 )
  if ( rloc_addr != None ) : oo0OoOOO += rloc_addr . addr_length ( )
  if 76 - 76: I1ii11iIi11i
  OO0Oo00OO0oo = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( oo0OoOOO ) , 1 , 0 )
  if 98 - 98: II111iiii + I1IiiI - I1ii11iIi11i . Ii1I
  if 51 - 51: Ii1I + i11iIiiIii * OoO0O00 % Oo0Ooo / I1IiiI - iIii1I11I1II1
  if 20 - 20: I1Ii111 . I11i . Ii1I + I11i - OOooOOo * oO0o
  if 82 - 82: OoO0O00
  if 78 - 78: II111iiii / I11i - i11iIiiIii + I1ii11iIi11i * Oo0Ooo
  if 17 - 17: OoOoOO00
  i1I = self . cipher_suite
  OO0Oo00OO0oo += struct . pack ( "BBH" , i1I , 0 , socket . htons ( oo0O0Ooo0o0 ) )
  if 72 - 72: iII111i . Oo0Ooo - i11iIiiIii / I1IiiI
  if 64 - 64: oO0o
  if 80 - 80: o0oOOo0O0Ooo % iIii1I11I1II1
  if 63 - 63: IiII * i11iIiiIii
  for iIiIIi in range ( 0 , oo0O0Ooo0o0 * 2 , 16 ) :
   III11II111 = int ( iI11i1iI [ iIiIIi : iIiIIi + 16 ] , 16 )
   OO0Oo00OO0oo += struct . pack ( "Q" , byte_swap_64 ( III11II111 ) )
   if 86 - 86: I11i % I11i - OoOoOO00 + I1Ii111 / I1IiiI * OoooooooOO
   if 26 - 26: II111iiii * iII111i + o0oOOo0O0Ooo / O0 + i1IIi - I11i
   if 56 - 56: OOooOOo
   if 76 - 76: i1IIi % iIii1I11I1II1 - o0oOOo0O0Ooo + IiII - I11i
   if 81 - 81: I1ii11iIi11i + OoooooooOO - OOooOOo * O0
  if ( rloc_addr ) :
   OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   OO0Oo00OO0oo += rloc_addr . pack_address ( )
   if 100 - 100: iIii1I11I1II1 - OoOoOO00
  return ( OO0Oo00OO0oo )
  if 28 - 28: Oo0Ooo . O0 . I11i
  if 60 - 60: II111iiii + I1Ii111 / oO0o % OoooooooOO - i1IIi
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 57 - 57: ooOoO0o
  if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
  if 52 - 52: I1ii11iIi11i
  if 93 - 93: iII111i . i11iIiiIii
  if ( lcaf_len == 0 ) :
   oOOoooo0o0 = "HHBBH"
   I1I11i = struct . calcsize ( oOOoooo0o0 )
   if ( len ( packet ) < I1I11i ) : return ( None )
   if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
   II1i1iI , ii , ii1iI1IIiIi , ii , lcaf_len = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
   if 49 - 49: IiII % OoooooooOO - I1IiiI
   if 87 - 87: Ii1I % OoooooooOO . i11iIiiIii % iII111i
   if ( ii1iI1IIiIi != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 41 - 41: iII111i + I1Ii111
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ I1I11i : : ]
   if 96 - 96: O0 + OOooOOo . ooOoO0o + OOooOOo
   if 43 - 43: i11iIiiIii
   if 65 - 65: O0 / iII111i . i1IIi * iII111i / iIii1I11I1II1 - oO0o
   if 93 - 93: OoOoOO00 % i11iIiiIii - Ii1I % OoO0O00
   if 55 - 55: o0oOOo0O0Ooo . I1ii11iIi11i
   if 63 - 63: oO0o
  ii1iI1IIiIi = LISP_LCAF_SECURITY_TYPE
  oOOoooo0o0 = "BBBBH"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 79 - 79: I1ii11iIi11i - oO0o - o0oOOo0O0Ooo . OOooOOo
  Oo , ii , i1I , ii , oo0O0Ooo0o0 = struct . unpack ( oOOoooo0o0 ,
 packet [ : I1I11i ] )
  if 81 - 81: iII111i + IiII - i11iIiiIii
  if 60 - 60: I1Ii111
  if 14 - 14: Oo0Ooo % oO0o * iII111i - i11iIiiIii / I1ii11iIi11i * i11iIiiIii
  if 95 - 95: iIii1I11I1II1 + OoOoOO00 . I1IiiI + OoOoOO00 * I11i + OOooOOo
  if 14 - 14: Ii1I - O0
  if 68 - 68: II111iiii - I1ii11iIi11i - OoO0O00 * iIii1I11I1II1 / I1IiiI * I1ii11iIi11i
  packet = packet [ I1I11i : : ]
  oo0O0Ooo0o0 = socket . ntohs ( oo0O0Ooo0o0 )
  if ( len ( packet ) < oo0O0Ooo0o0 ) : return ( None )
  if 45 - 45: I1Ii111 * I11i / iIii1I11I1II1 / I1IiiI % II111iiii
  if 49 - 49: Ii1I / iII111i . iII111i . iII111i + i11iIiiIii % I11i
  if 7 - 7: IiII * ooOoO0o + OoOoOO00
  if 22 - 22: iII111i
  iIi = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( i1I not in iIi ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( iIi ,
 i1I ) )
   packet = packet [ oo0O0Ooo0o0 : : ]
   return ( packet )
   if 73 - 73: O0 . I1Ii111 - OoooooooOO % I11i % i1IIi
   if 14 - 14: I1Ii111 + Ii1I * Oo0Ooo
  self . cipher_suite = i1I
  if 49 - 49: Oo0Ooo
  if 57 - 57: O0 * ooOoO0o - iII111i - iIii1I11I1II1 * iII111i
  if 9 - 9: IiII . I11i
  if 23 - 23: O0 % OoooooooOO - O0 . I1IiiI + i11iIiiIii
  if 96 - 96: ooOoO0o % O0
  iI11i1iI = 0
  for iIiIIi in range ( 0 , oo0O0Ooo0o0 , 8 ) :
   III11II111 = byte_swap_64 ( struct . unpack ( "Q" , packet [ iIiIIi : iIiIIi + 8 ] ) [ 0 ] )
   iI11i1iI <<= 64
   iI11i1iI |= III11II111
   if 51 - 51: I1IiiI - iII111i / I1ii11iIi11i . I1ii11iIi11i + I1ii11iIi11i
  self . remote_public_key = iI11i1iI
  if 87 - 87: II111iiii . Ii1I * OoO0O00
  if 74 - 74: o0oOOo0O0Ooo % OoOoOO00 . iII111i % I1Ii111 . O0 % II111iiii
  if 5 - 5: oO0o - OoooooooOO / OoOoOO00
  if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
  if 55 - 55: OoO0O00
  if ( self . curve25519 ) :
   III11II111 = lisp_hex_string ( self . remote_public_key )
   III11II111 = III11II111 . zfill ( 64 )
   I111II1ii11I1 = b""
   for iIiIIi in range ( 0 , len ( III11II111 ) , 2 ) :
    iIiiIII = int ( III11II111 [ iIiIIi : iIiIIi + 2 ] , 16 )
    I111II1ii11I1 += lisp_store_byte ( iIiiIII )
    if 37 - 37: OoooooooOO / I1ii11iIi11i % o0oOOo0O0Ooo
   self . remote_public_key = I111II1ii11I1
   if 34 - 34: OoOoOO00 . I11i % oO0o - O0 * O0
   if 11 - 11: O0 * i11iIiiIii * II111iiii / OOooOOo * O0
  packet = packet [ oo0O0Ooo0o0 : : ]
  return ( packet )
  if 71 - 71: I11i . Oo0Ooo
  if 24 - 24: OOooOOo * OoooooooOO . O0 . OoO0O00 . I1IiiI
  if 80 - 80: O0 * OoO0O00 . I1Ii111 % O0
  if 12 - 12: OoooooooOO % IiII
  if 97 - 97: II111iiii % oO0o - II111iiii . ooOoO0o
  if 50 - 50: iII111i % I1ii11iIi11i + I11i * Oo0Ooo - i11iIiiIii
  if 24 - 24: i11iIiiIii . ooOoO0o + ooOoO0o - i11iIiiIii % OOooOOo
  if 58 - 58: I1IiiI
  if 94 - 94: o0oOOo0O0Ooo + Ii1I % o0oOOo0O0Ooo . I1Ii111 - ooOoO0o * I1IiiI
def lisp_store_byte_py2 ( byte ) :
 return ( chr ( byte ) )
 if 62 - 62: Oo0Ooo * i1IIi % I1ii11iIi11i + Oo0Ooo . O0 . ooOoO0o
def lisp_store_byte_py3 ( byte ) :
 return ( bytes ( [ byte ] ) )
 if 57 - 57: Oo0Ooo - I1Ii111 + O0 % o0oOOo0O0Ooo
 if 72 - 72: OOooOOo . OoOoOO00 / II111iiii
lisp_store_byte = lisp_store_byte_py2
if ( lisp_is_python3 ( ) ) : lisp_store_byte = lisp_store_byte_py3
if 69 - 69: OOooOOo * II111iiii - ooOoO0o - i1IIi + i11iIiiIii
if 50 - 50: OoooooooOO * i1IIi / oO0o
if 83 - 83: i1IIi
if 38 - 38: OoooooooOO * iIii1I11I1II1
if 54 - 54: OoooooooOO . I1Ii111
if 71 - 71: Ii1I
class lisp_thread ( object ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
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
class lisp_control_header ( object ) :
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
  if 14 - 14: IiII + IiII . I11i / Ii1I . iIii1I11I1II1
  if 10 - 10: II111iiii . OOooOOo / iII111i
 def decode ( self , packet ) :
  oOOoooo0o0 = "BBBBQ"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( False )
  if 35 - 35: iII111i / Oo0Ooo + O0 * iIii1I11I1II1 - O0
  iI111III1 , Ii1i111i , i1iiIIII , self . record_count , self . nonce = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  if 37 - 37: I1Ii111 * Ii1I + Oo0Ooo * I1Ii111 % o0oOOo0O0Ooo . Oo0Ooo
  if 37 - 37: Ii1I / II111iiii
  self . type = iI111III1 >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( iI111III1 & 0x01 ) else False
   self . rloc_probe = True if ( iI111III1 & 0x02 ) else False
   self . smr_invoked_bit = True if ( Ii1i111i & 0x40 ) else False
   if 66 - 66: ooOoO0o + oO0o % OoooooooOO
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( iI111III1 & 0x04 ) else False
   self . to_etr = True if ( iI111III1 & 0x02 ) else False
   self . to_ms = True if ( iI111III1 & 0x01 ) else False
   if 23 - 23: oO0o . OoOoOO00 + iIii1I11I1II1
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( iI111III1 & 0x08 ) else False
   if 17 - 17: IiII
  return ( True )
  if 12 - 12: i1IIi . OoO0O00
  if 14 - 14: OOooOOo + II111iiii % OOooOOo . oO0o * ooOoO0o
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 54 - 54: ooOoO0o * I11i - I1Ii111
  if 15 - 15: iII111i / O0
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 61 - 61: i1IIi / i1IIi + ooOoO0o . I1Ii111 * ooOoO0o
  if 19 - 19: o0oOOo0O0Ooo . II111iiii / i1IIi
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 82 - 82: O0 / iII111i * OoO0O00 - I11i + Oo0Ooo
  if 47 - 47: I1ii11iIi11i * I1IiiI / I1ii11iIi11i + Ii1I * II111iiii
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 78 - 78: I1Ii111 - i1IIi + OoOoOO00 + Oo0Ooo * I1ii11iIi11i * o0oOOo0O0Ooo
  if 97 - 97: i1IIi
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 29 - 29: I1IiiI
  if 37 - 37: I1ii11iIi11i * I1Ii111 * I1IiiI * O0
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 35 - 35: I1IiiI - I1ii11iIi11i * iII111i + IiII / i1IIi
  if 46 - 46: Oo0Ooo . ooOoO0o % Oo0Ooo / II111iiii * ooOoO0o * OOooOOo
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 59 - 59: I1Ii111 * iII111i
  if 31 - 31: I11i / O0
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
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
  if 64 - 64: ooOoO0o / ooOoO0o + I1ii11iIi11i * OOooOOo % OOooOOo
  if 87 - 87: OoO0O00 * Oo0Ooo
  if 83 - 83: i1IIi * I1Ii111 - IiII / Ii1I
  if 48 - 48: oO0o . II111iiii - OoOoOO00 % i1IIi . OoOoOO00
  if 32 - 32: Ii1I * I1IiiI - OOooOOo . Oo0Ooo / O0 + Ii1I
  if 67 - 67: OoOoOO00 % Oo0Ooo
  if 7 - 7: i11iIiiIii % I1ii11iIi11i / I1Ii111 % Oo0Ooo - OoO0O00
  if 73 - 73: I1ii11iIi11i
  if 92 - 92: i11iIiiIii + O0 * I11i
  if 60 - 60: o0oOOo0O0Ooo / Oo0Ooo
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
class lisp_map_register ( object ) :
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
  if 99 - 99: I1Ii111 - I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + II111iiii
  if 34 - 34: I1Ii111 * I11i
 def print_map_register ( self ) :
  i1oO0o00oOo00oO = lisp_hex_string ( self . xtr_id )
  if 68 - 68: iIii1I11I1II1 - I1IiiI . oO0o + OoOoOO00
  I11I111i1I1 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 94 - 94: o0oOOo0O0Ooo % o0oOOo0O0Ooo % II111iiii * iIii1I11I1II1 / IiII . I1ii11iIi11i
  lprint ( I11I111i1I1 . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # OOooOOo
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , i1oO0o00oOo00oO , self . site_id ) )
  if 12 - 12: I1IiiI . o0oOOo0O0Ooo * OoooooooOO
  if 64 - 64: OoOoOO00 + IiII - i1IIi . II111iiii . OoO0O00
  if 31 - 31: oO0o . iII111i - I11i . iIii1I11I1II1 + I11i . OoOoOO00
  if 86 - 86: I1ii11iIi11i - I1ii11iIi11i / iII111i - I1ii11iIi11i * iII111i + I1Ii111
 def encode ( self ) :
  iii1I = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : iii1I |= 0x08000000
  if ( self . lisp_sec_present ) : iii1I |= 0x04000000
  if ( self . xtr_id_present ) : iii1I |= 0x02000000
  if ( self . map_register_refresh ) : iii1I |= 0x1000
  if ( self . use_ttl_for_timeout ) : iii1I |= 0x800
  if ( self . merge_register_requested ) : iii1I |= 0x400
  if ( self . mobile_node ) : iii1I |= 0x200
  if ( self . map_notify_requested ) : iii1I |= 0x100
  if ( self . encryption_key_id != None ) :
   iii1I |= 0x2000
   iii1I |= self . encryption_key_id << 14
   if 61 - 61: Oo0Ooo / II111iiii / Oo0Ooo / i1IIi . Oo0Ooo - IiII
   if 30 - 30: OoooooooOO % OOooOOo
   if 14 - 14: OoOoOO00 / OoO0O00 / i11iIiiIii - OoOoOO00 / o0oOOo0O0Ooo - OOooOOo
   if 81 - 81: iII111i % Ii1I . ooOoO0o
   if 66 - 66: I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 82 - 82: Oo0Ooo / Ii1I / Ii1I % Ii1I
    if 20 - 20: ooOoO0o
    if 63 - 63: iIii1I11I1II1 . OoO0O00
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( iii1I ) )
  OO0Oo00OO0oo += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 100 - 100: i1IIi * i1IIi
  OO0Oo00OO0oo = self . zero_auth ( OO0Oo00OO0oo )
  return ( OO0Oo00OO0oo )
  if 26 - 26: OOooOOo . OoO0O00 % OoOoOO00
  if 94 - 94: IiII
 def zero_auth ( self , packet ) :
  o0O0 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  i1i1iiIi1 = b""
  i11iii11 = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   i1i1iiIi1 = struct . pack ( "QQI" , 0 , 0 , 0 )
   i11iii11 = struct . calcsize ( "QQI" )
   if 5 - 5: I1Ii111 + iII111i % I1Ii111 % i11iIiiIii
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   i1i1iiIi1 = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   i11iii11 = struct . calcsize ( "QQQQ" )
   if 46 - 46: OoooooooOO
  packet = packet [ 0 : o0O0 ] + i1i1iiIi1 + packet [ o0O0 + i11iii11 : : ]
  return ( packet )
  if 80 - 80: O0 * iII111i
  if 73 - 73: IiII / Ii1I + I1Ii111 . OOooOOo - II111iiii / iIii1I11I1II1
 def encode_auth ( self , packet ) :
  o0O0 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  i11iii11 = self . auth_len
  i1i1iiIi1 = self . auth_data
  packet = packet [ 0 : o0O0 ] + i1i1iiIi1 + packet [ o0O0 + i11iii11 : : ]
  return ( packet )
  if 79 - 79: I1Ii111 * Oo0Ooo . o0oOOo0O0Ooo - I1Ii111
  if 16 - 16: I1IiiI - O0 * I1ii11iIi11i . I1ii11iIi11i % OOooOOo
 def decode ( self , packet ) :
  IiI11 = packet
  oOOoooo0o0 = "I"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( [ None , None ] )
  if 49 - 49: Ii1I + OoooooooOO . O0 . i11iIiiIii
  iii1I = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  iii1I = socket . ntohl ( iii1I [ 0 ] )
  packet = packet [ I1I11i : : ]
  if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
  oOOoooo0o0 = "QBBH"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( [ None , None ] )
  if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
  if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( iii1I & 0x08000000 ) else False
  if 69 - 69: Oo0Ooo * ooOoO0o
  self . lisp_sec_present = True if ( iii1I & 0x04000000 ) else False
  self . xtr_id_present = True if ( iii1I & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( iii1I & 0x800 ) else False
  self . map_register_refresh = True if ( iii1I & 0x1000 ) else False
  self . merge_register_requested = True if ( iii1I & 0x400 ) else False
  self . mobile_node = True if ( iii1I & 0x200 ) else False
  self . map_notify_requested = True if ( iii1I & 0x100 ) else False
  self . record_count = iii1I & 0xff
  if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
  if 52 - 52: I1IiiI - i11iIiiIii / IiII . oO0o
  if 38 - 38: oO0o + OoooooooOO * OoOoOO00 % oO0o
  if 91 - 91: i1IIi - I1ii11iIi11i * I1IiiI
  self . encrypt_bit = True if iii1I & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( iii1I >> 14 ) & 0x7
   if 24 - 24: OoOoOO00 * Ii1I
   if 17 - 17: OoO0O00 . I1IiiI * O0
   if 81 - 81: OOooOOo
   if 58 - 58: II111iiii . I1Ii111 . Ii1I * OoooooooOO / Ii1I / I11i
   if 41 - 41: I11i + OoO0O00 . iII111i
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( IiI11 ) == False ) : return ( [ None , None ] )
   if 73 - 73: i11iIiiIii * I1IiiI + o0oOOo0O0Ooo / oO0o
   if 56 - 56: i1IIi
  packet = packet [ I1I11i : : ]
  if 11 - 11: i11iIiiIii % o0oOOo0O0Ooo / I11i * OoooooooOO
  if 82 - 82: IiII
  if 10 - 10: Oo0Ooo % OOooOOo / I11i * IiII - o0oOOo0O0Ooo
  if 54 - 54: i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i / I1IiiI . iIii1I11I1II1 / iII111i
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 1 - 1: I1Ii111 / OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % Ii1I
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 96 - 96: IiII / Ii1I % OoO0O00 . iIii1I11I1II1
    if 30 - 30: I11i - OoO0O00
   i11iii11 = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    I1I11i = struct . calcsize ( "QQI" )
    if ( i11iii11 < I1I11i ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 15 - 15: OoooooooOO
    iII1i , OO00o0O0OO0o0 , iiIi1Ii1ii = struct . unpack ( "QQI" , packet [ : i11iii11 ] )
    IIiI1iIiii = b""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    I1I11i = struct . calcsize ( "QQQQ" )
    if ( i11iii11 < I1I11i ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 53 - 53: I1Ii111 % I1ii11iIi11i
    iII1i , OO00o0O0OO0o0 , iiIi1Ii1ii , IIiI1iIiii = struct . unpack ( "QQQQ" ,
 packet [ : i11iii11 ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 17 - 17: OoooooooOO % Ii1I % O0
    return ( [ None , None ] )
    if 46 - 46: iII111i + I1Ii111 % OoooooooOO * I1ii11iIi11i
   self . auth_data = lisp_concat_auth_data ( self . alg_id , iII1i , OO00o0O0OO0o0 ,
 iiIi1Ii1ii , IIiI1iIiii )
   IiI11 = self . zero_auth ( IiI11 )
   packet = packet [ self . auth_len : : ]
   if 89 - 89: IiII - IiII % iII111i / I11i + oO0o - IiII
  return ( [ IiI11 , packet ] )
  if 97 - 97: Ii1I % OoOoOO00 / I1ii11iIi11i / iIii1I11I1II1 * OoooooooOO * OOooOOo
  if 80 - 80: oO0o / O0
 def encode_xtr_id ( self , packet ) :
  OOo00oO000o0O = self . xtr_id >> 64
  IIIIi1I = self . xtr_id & 0xffffffffffffffff
  OOo00oO000o0O = byte_swap_64 ( OOo00oO000o0O )
  IIIIi1I = byte_swap_64 ( IIIIi1I )
  I1III = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , OOo00oO000o0O , IIIIi1I , I1III )
  return ( packet )
  if 41 - 41: iIii1I11I1II1 - OoO0O00 * IiII
  if 65 - 65: OOooOOo / OOooOOo / iII111i * OoooooooOO
 def decode_xtr_id ( self , packet ) :
  I1I11i = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < I1I11i ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - I1I11i : : ]
  OOo00oO000o0O , IIIIi1I , I1III = struct . unpack ( "QQQ" ,
 packet [ : I1I11i ] )
  OOo00oO000o0O = byte_swap_64 ( OOo00oO000o0O )
  IIIIi1I = byte_swap_64 ( IIIIi1I )
  self . xtr_id = ( OOo00oO000o0O << 64 ) | IIIIi1I
  self . site_id = byte_swap_64 ( I1III )
  return ( True )
  if 40 - 40: Oo0Ooo * OoooooooOO + IiII
  if 58 - 58: I1IiiI
  if 21 - 21: IiII - I1IiiI . OOooOOo - oO0o
  if 1 - 1: iIii1I11I1II1 / i11iIiiIii * II111iiii
  if 48 - 48: I1ii11iIi11i + O0 * oO0o + I1ii11iIi11i + I1ii11iIi11i
  if 60 - 60: II111iiii % Oo0Ooo
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
class lisp_map_notify ( object ) :
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
  if 5 - 5: OoO0O00 . I1IiiI
  if 48 - 48: Oo0Ooo - OoO0O00 . I11i - iIii1I11I1II1 % Ii1I
 def print_notify ( self ) :
  i1i1iiIi1 = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( i1i1iiIi1 ) != 40 ) :
   i1i1iiIi1 = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( i1i1iiIi1 ) != 64 ) :
   i1i1iiIi1 = self . auth_data
   if 47 - 47: iII111i / OoooooooOO - II111iiii
  I11I111i1I1 = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( I11I111i1I1 . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # I1IiiI / o0oOOo0O0Ooo + iIii1I11I1II1 / O0 / OOooOOo % i1IIi
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , i1i1iiIi1 ) )
  if 65 - 65: OoO0O00 * OoOoOO00 . OoooooooOO - O0 * OoOoOO00 % OoOoOO00
  if 1 - 1: I1IiiI + OoooooooOO . I1IiiI + OOooOOo / I1Ii111
  if 73 - 73: o0oOOo0O0Ooo % I1ii11iIi11i . iIii1I11I1II1
  if 43 - 43: IiII / I11i + OoO0O00
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   i1i1iiIi1 = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 38 - 38: iII111i
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   i1i1iiIi1 = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 59 - 59: I1IiiI
  packet += i1i1iiIi1
  return ( packet )
  if 21 - 21: I1ii11iIi11i - oO0o * OoO0O00
  if 98 - 98: I1ii11iIi11i - OOooOOo % iIii1I11I1II1
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   iii1I = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   iii1I = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 54 - 54: I1ii11iIi11i + i1IIi - I11i * OoooooooOO
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( iii1I ) )
  OO0Oo00OO0oo += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 71 - 71: o0oOOo0O0Ooo + OoooooooOO * II111iiii / I1Ii111
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = OO0Oo00OO0oo + eid_records
   return ( self . packet )
   if 78 - 78: I1Ii111 % OOooOOo
   if 73 - 73: I1ii11iIi11i + iII111i * I1IiiI * I11i
   if 35 - 35: I11i * O0 * OoO0O00 . I1ii11iIi11i
   if 74 - 74: iII111i * iII111i * o0oOOo0O0Ooo / oO0o
   if 91 - 91: i11iIiiIii . I1ii11iIi11i / II111iiii
  OO0Oo00OO0oo = self . zero_auth ( OO0Oo00OO0oo )
  OO0Oo00OO0oo += eid_records
  if 97 - 97: Ii1I % i1IIi % IiII + Oo0Ooo - O0 - I11i
  I111i = lisp_hash_me ( OO0Oo00OO0oo , self . alg_id , password , False )
  if 64 - 64: Ii1I - iII111i
  o0O0 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  i11iii11 = self . auth_len
  self . auth_data = I111i
  OO0Oo00OO0oo = OO0Oo00OO0oo [ 0 : o0O0 ] + I111i + OO0Oo00OO0oo [ o0O0 + i11iii11 : : ]
  self . packet = OO0Oo00OO0oo
  return ( OO0Oo00OO0oo )
  if 12 - 12: i1IIi
  if 99 - 99: II111iiii - I1ii11iIi11i * IiII
 def decode ( self , packet ) :
  IiI11 = packet
  oOOoooo0o0 = "I"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 3 - 3: IiII - I1ii11iIi11i * iII111i * I1ii11iIi11i + Oo0Ooo
  iii1I = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  iii1I = socket . ntohl ( iii1I [ 0 ] )
  self . map_notify_ack = ( ( iii1I >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = iii1I & 0xff
  packet = packet [ I1I11i : : ]
  if 15 - 15: I1ii11iIi11i * Ii1I / iII111i . o0oOOo0O0Ooo / Ii1I % OoOoOO00
  oOOoooo0o0 = "QBBH"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 75 - 75: OoooooooOO % i11iIiiIii % iIii1I11I1II1 % I1ii11iIi11i / i11iIiiIii
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  if 96 - 96: ooOoO0o * oO0o / iIii1I11I1II1 / I11i
  if 5 - 5: o0oOOo0O0Ooo
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ I1I11i : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 83 - 83: I11i * I1IiiI . II111iiii * i1IIi % O0
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 35 - 35: OoOoOO00 % OoO0O00 + O0 * o0oOOo0O0Ooo % I1ii11iIi11i
  if 57 - 57: oO0o / I11i
  if 63 - 63: ooOoO0o * OoO0O00 * ooOoO0o + OoOoOO00
  if 25 - 25: iII111i * OoOoOO00 / I1IiiI / IiII
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 11 - 11: OOooOOo + i11iIiiIii
  i11iii11 = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   iII1i , OO00o0O0OO0o0 , iiIi1Ii1ii = struct . unpack ( "QQI" , packet [ : i11iii11 ] )
   IIiI1iIiii = ""
   if 14 - 14: OoOoOO00 / IiII + OoO0O00 - Ii1I
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   iII1i , OO00o0O0OO0o0 , iiIi1Ii1ii , IIiI1iIiii = struct . unpack ( "QQQQ" ,
 packet [ : i11iii11 ] )
   if 38 - 38: I1Ii111
  self . auth_data = lisp_concat_auth_data ( self . alg_id , iII1i , OO00o0O0OO0o0 ,
 iiIi1Ii1ii , IIiI1iIiii )
  if 30 - 30: II111iiii + I11i . i11iIiiIii + iIii1I11I1II1
  I1I11i = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( IiI11 [ : I1I11i ] )
  I1I11i += i11iii11
  packet += IiI11 [ I1I11i : : ]
  return ( packet )
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
  if 12 - 12: o0oOOo0O0Ooo
  if 58 - 58: iIii1I11I1II1 * Ii1I . ooOoO0o . Oo0Ooo * Ii1I
  if 63 - 63: OoOoOO00 . I11i * o0oOOo0O0Ooo - I11i % I11i
  if 62 - 62: I11i - ooOoO0o / ooOoO0o
class lisp_map_request ( object ) :
 def __init__ ( self ) :
  self . auth_bit = False
  self . map_data_present = False
  self . rloc_probe = False
  self . smr_bit = False
  self . pitr_bit = False
  self . smr_invoked_bit = False
  self . mobile_node = False
  self . xtr_id_present = False
  self . decent_nat_xtr = False
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
  if 95 - 95: OoOoOO00 - i1IIi / I1Ii111 . ooOoO0o % OOooOOo - i1IIi
  if 12 - 12: iII111i
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 96 - 96: O0
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 89 - 89: I1ii11iIi11i - Oo0Ooo
  if 26 - 26: ooOoO0o % ooOoO0o / II111iiii / iII111i
 def print_map_request ( self ) :
  i1oO0o00oOo00oO = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   i1oO0o00oOo00oO = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 2 - 2: i1IIi / i11iIiiIii + I1IiiI
   if 95 - 95: I1ii11iIi11i / IiII % iIii1I11I1II1 + O0
   if 6 - 6: IiII
  I11I111i1I1 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 73 - 73: o0oOOo0O0Ooo % o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i - Ii1I
  lprint ( I11I111i1I1 . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # IiII . o0oOOo0O0Ooo . O0 - I1IiiI / i1IIi . I1Ii111
 "D" if self . map_data_present else "d" ,
 "R" if self . rloc_probe else "r" ,
 "S" if self . smr_bit else "s" ,
 "P" if self . pitr_bit else "p" ,
 "I" if self . smr_invoked_bit else "i" ,
 "M" if self . mobile_node else "m" ,
 "X" if self . xtr_id_present else "x" ,
 "N" if self . decent_nat_xtr else "n" ,
 "L" if self . local_xtr else "l" ,
 "D" if self . dont_reply_bit else "d" , self . itr_rloc_count ,
 self . record_count , lisp_hex_string ( self . nonce ) ,
 self . source_eid . afi , green ( self . source_eid . print_address ( ) , False ) ,
 " (with sig)" if self . map_request_signature != None else "" ,
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , i1oO0o00oOo00oO ) )
  if 64 - 64: ooOoO0o / i1IIi
  O0o0O0 = self . keys
  for ooo00 in self . itr_rlocs :
   if ( ooo00 . afi == LISP_AFI_LCAF and self . json_telemetry != None ) :
    continue
    if 56 - 56: OOooOOo - I1Ii111
   OOoO0ooOooOoo = red ( ooo00 . print_address_no_iid ( ) , False )
   lprint ( "  itr-rloc: afi {} {}{}" . format ( ooo00 . afi , OOoO0ooOooOoo ,
 "" if ( O0o0O0 == None ) else ", " + O0o0O0 [ 1 ] . print_keys ( ) ) )
   O0o0O0 = None
   if 57 - 57: i11iIiiIii + I11i % ooOoO0o / iIii1I11I1II1
  if ( self . json_telemetry != None ) :
   lprint ( "  itr-rloc: afi {} telemetry: {}" . format ( LISP_AFI_LCAF ,
 self . json_telemetry ) )
   if 74 - 74: Oo0Ooo + OOooOOo . o0oOOo0O0Ooo / OoOoOO00 + Ii1I + i1IIi
   if 82 - 82: Ii1I * I11i / I1IiiI * iIii1I11I1II1 / ooOoO0o + IiII
   if 30 - 30: oO0o . i11iIiiIii / I11i + i1IIi - I11i
 def sign_map_request ( self , privkey ) :
  iIII = self . signature_eid . print_address ( )
  i11iI1I1I11II = self . source_eid . print_address ( )
  oo0 = self . target_eid . print_address ( )
  O00O0oO = lisp_hex_string ( self . nonce ) + i11iI1I1I11II + oo0
  self . map_request_signature = privkey . sign ( O00O0oO . encode ( ) )
  IIIIi1iII = binascii . b2a_base64 ( self . map_request_signature )
  IIIIi1iII = { "source-eid" : i11iI1I1I11II , "signature-eid" : iIII ,
 "signature" : IIIIi1iII . decode ( ) }
  return ( json . dumps ( IIIIi1iII ) )
  if 49 - 49: i1IIi . IiII
  if 82 - 82: OoO0O00 / I11i
 def verify_map_request_sig ( self , pubkey ) :
  ii1iIIIi1Iii1 = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( ii1iIIIi1Iii1 ) )
   return ( False )
   if 77 - 77: I11i
   if 50 - 50: o0oOOo0O0Ooo - OoOoOO00
  i11iI1I1I11II = self . source_eid . print_address ( )
  oo0 = self . target_eid . print_address ( )
  O00O0oO = lisp_hex_string ( self . nonce ) + i11iI1I1I11II + oo0
  pubkey = binascii . a2b_base64 ( pubkey )
  if 1 - 1: i1IIi / Ii1I % IiII - I11i % o0oOOo0O0Ooo
  I1I1i111 = True
  try :
   III11II111 = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 19 - 19: IiII
   I1I1i111 = False
   if 32 - 32: iII111i / IiII / OoO0O00 . I1IiiI
   if 75 - 75: I1Ii111 . iIii1I11I1II1 + IiII % Oo0Ooo
  if ( I1I1i111 ) :
   try :
    O00O0oO = O00O0oO . encode ( )
    I1I1i111 = III11II111 . verify ( self . map_request_signature , O00O0oO )
   except :
    I1I1i111 = False
    if 99 - 99: OOooOOo . iIii1I11I1II1
    if 45 - 45: I1Ii111 - O0 . I1Ii111 / I1Ii111 / OoOoOO00
    if 12 - 12: OOooOOo
  OOO0oOO = bold ( "passed" if I1I1i111 else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( OOO0oOO , ii1iIIIi1Iii1 ) )
  return ( I1I1i111 )
  if 93 - 93: OOooOOo * Ii1I - o0oOOo0O0Ooo . oO0o . iII111i
  if 64 - 64: Oo0Ooo / iIii1I11I1II1 . OoO0O00 / o0oOOo0O0Ooo / I11i
 def encode_json ( self , json_string ) :
  ii1iI1IIiIi = LISP_LCAF_JSON_TYPE
  I11IiiI1 = socket . htons ( LISP_AFI_LCAF )
  ooo0oO0o000O0 = socket . htons ( len ( json_string ) + 4 )
  iiIi11i1I1 = socket . htons ( len ( json_string ) )
  OO0Oo00OO0oo = struct . pack ( "HBBBBHH" , I11IiiI1 , 0 , 0 , ii1iI1IIiIi , 0 , ooo0oO0o000O0 ,
 iiIi11i1I1 )
  OO0Oo00OO0oo += json_string . encode ( )
  OO0Oo00OO0oo += struct . pack ( "H" , 0 )
  return ( OO0Oo00OO0oo )
  if 72 - 72: IiII + i11iIiiIii - OOooOOo
  if 67 - 67: iIii1I11I1II1 % IiII
 def encode ( self , probe_dest , probe_port ) :
  iii1I = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  if 97 - 97: iII111i
  iI1I1iIi11II1 = lisp_telemetry_configured ( ) if ( self . rloc_probe ) else None
  if ( iI1I1iIi11II1 != None ) : self . itr_rloc_count += 1
  iii1I = iii1I | ( self . itr_rloc_count << 8 )
  if 25 - 25: Oo0Ooo * IiII % I1IiiI . iII111i % iII111i * Oo0Ooo
  if ( self . auth_bit ) : iii1I |= 0x08000000
  if ( self . map_data_present ) : iii1I |= 0x04000000
  if ( self . rloc_probe ) : iii1I |= 0x02000000
  if ( self . smr_bit ) : iii1I |= 0x01000000
  if ( self . pitr_bit ) : iii1I |= 0x00800000
  if ( self . smr_invoked_bit ) : iii1I |= 0x00400000
  if ( self . mobile_node ) : iii1I |= 0x00200000
  if ( self . xtr_id_present ) : iii1I |= 0x00100000
  if ( self . decent_nat_xtr ) : iii1I |= 0x00008000
  if ( self . local_xtr ) : iii1I |= 0x00004000
  if ( self . dont_reply_bit ) : iii1I |= 0x00002000
  if 1 - 1: Oo0Ooo / ooOoO0o * Ii1I - OoooooooOO * I11i * OOooOOo
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( iii1I ) )
  OO0Oo00OO0oo += struct . pack ( "Q" , self . nonce )
  if 63 - 63: II111iiii - o0oOOo0O0Ooo * i11iIiiIii / I11i * iII111i - iII111i
  if 32 - 32: Oo0Ooo . O0
  if 48 - 48: I1ii11iIi11i % II111iiii + I11i
  if 25 - 25: IiII * o0oOOo0O0Ooo / I1IiiI . IiII % II111iiii
  if 50 - 50: OoOoOO00 * iII111i
  if 59 - 59: I1IiiI * I1IiiI / I11i
  ooOO0oO0 = False
  ii1I11 = self . privkey_filename
  if ( ii1I11 != None and os . path . exists ( ii1I11 ) ) :
   ii1I11ooOOoo0 = open ( ii1I11 , "r" ) ; III11II111 = ii1I11ooOOoo0 . read ( ) ; ii1I11ooOOoo0 . close ( )
   try :
    III11II111 = ecdsa . SigningKey . from_pem ( III11II111 )
   except :
    return ( None )
    if 47 - 47: Ii1I % ooOoO0o + Ii1I
   IIiii11IiIi = self . sign_map_request ( III11II111 )
   ooOO0oO0 = True
  elif ( self . map_request_signature != None ) :
   IIIIi1iII = binascii . b2a_base64 ( self . map_request_signature )
   IIiii11IiIi = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : IIIIi1iII }
   IIiii11IiIi = json . dumps ( IIiii11IiIi )
   ooOO0oO0 = True
   if 5 - 5: Ii1I / o0oOOo0O0Ooo + IiII * OoooooooOO
  if ( ooOO0oO0 ) :
   OO0Oo00OO0oo += self . encode_json ( IIiii11IiIi )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    OO0Oo00OO0oo += self . source_eid . lcaf_encode_iid ( )
   else :
    OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    OO0Oo00OO0oo += self . source_eid . pack_address ( )
    if 52 - 52: OoO0O00 . II111iiii
    if 2 - 2: i1IIi + O0 + i1IIi * I1IiiI
    if 73 - 73: OoO0O00 + oO0o . o0oOOo0O0Ooo / iII111i % OoO0O00 - OOooOOo
    if 4 - 4: o0oOOo0O0Ooo * Oo0Ooo
    if 68 - 68: Ii1I % Ii1I
    if 26 - 26: o0oOOo0O0Ooo . Ii1I * OoOoOO00
    if 58 - 58: I1IiiI * OoO0O00 * i11iIiiIii / OOooOOo / I1IiiI
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   Oo0o = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 46 - 46: IiII - I1IiiI + OoO0O00 / I11i . i11iIiiIii
   if ( Oo0o in lisp_crypto_keys_by_rloc_encap ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ Oo0o ]
    if 84 - 84: OoooooooOO . OoO0O00 / OoOoOO00 * i1IIi
    if 6 - 6: iIii1I11I1II1 * iIii1I11I1II1
    if 77 - 77: OOooOOo % oO0o + iIii1I11I1II1 * Ii1I . IiII . Oo0Ooo
    if 29 - 29: I1ii11iIi11i + OoooooooOO . OoO0O00 . i1IIi - OoooooooOO * i11iIiiIii
    if 19 - 19: I1ii11iIi11i * O0 - ooOoO0o
    if 27 - 27: iII111i / o0oOOo0O0Ooo . OoOoOO00 * Ii1I * I1Ii111
    if 81 - 81: I1Ii111
  for ooo00 in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( ooo00 ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     O0o0O0 = lisp_keys ( 1 )
     self . keys = [ None , O0o0O0 , None , None ]
     if 45 - 45: OOooOOo * II111iiii * OoooooooOO / OoooooooOO * I1Ii111
    O0o0O0 = self . keys [ 1 ]
    O0o0O0 . add_key_by_nonce ( self . nonce )
    OO0Oo00OO0oo += O0o0O0 . encode_lcaf ( ooo00 )
   else :
    OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( ooo00 . afi ) )
    OO0Oo00OO0oo += ooo00 . pack_address ( )
    if 38 - 38: iII111i . OoooooooOO
    if 28 - 28: I1Ii111 * i1IIi . I1ii11iIi11i
    if 75 - 75: O0 / oO0o * ooOoO0o - OOooOOo / i1IIi
    if 61 - 61: I11i
    if 100 - 100: O0 - iIii1I11I1II1 * Oo0Ooo
    if 35 - 35: ooOoO0o
  if ( iI1I1iIi11II1 != None ) :
   Oo0OO0000oooo = str ( time . time ( ) )
   iI1I1iIi11II1 = lisp_encode_telemetry ( iI1I1iIi11II1 , io = Oo0OO0000oooo )
   self . json_telemetry = iI1I1iIi11II1
   OO0Oo00OO0oo += self . encode_json ( iI1I1iIi11II1 )
   if 57 - 57: OoO0O00 . Oo0Ooo + I1IiiI
   if 18 - 18: I1IiiI - I1ii11iIi11i * I11i / i11iIiiIii - o0oOOo0O0Ooo % o0oOOo0O0Ooo
  i111iii1i1 = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 85 - 85: Ii1I . Ii1I * IiII * i1IIi
  if 4 - 4: i11iIiiIii - i1IIi
  oooo = 0
  if ( self . subscribe_bit ) :
   oooo = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 36 - 36: iII111i
    if 91 - 91: ooOoO0o + IiII . I1IiiI / I11i / IiII
    if 23 - 23: I1ii11iIi11i - OOooOOo - i1IIi
  oOOoooo0o0 = "BB"
  OO0Oo00OO0oo += struct . pack ( oOOoooo0o0 , oooo , i111iii1i1 )
  if 20 - 20: OoooooooOO / Oo0Ooo * OoO0O00 . o0oOOo0O0Ooo . I1IiiI
  if ( self . target_group . is_null ( ) == False ) :
   OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   OO0Oo00OO0oo += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   OO0Oo00OO0oo += self . target_eid . lcaf_encode_iid ( )
  else :
   OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   OO0Oo00OO0oo += self . target_eid . pack_address ( )
   if 75 - 75: iIii1I11I1II1 - Ii1I % O0 % IiII
   if 6 - 6: Oo0Ooo % oO0o * ooOoO0o - i1IIi . OoOoOO00
   if 20 - 20: Oo0Ooo / I1Ii111 . Oo0Ooo
   if 60 - 60: I1ii11iIi11i - I1IiiI * O0 * Oo0Ooo . i1IIi . OoOoOO00
   if 24 - 24: IiII * I1IiiI / OOooOOo
  if ( self . subscribe_bit ) : OO0Oo00OO0oo = self . encode_xtr_id ( OO0Oo00OO0oo )
  return ( OO0Oo00OO0oo )
  if 51 - 51: iIii1I11I1II1 / I11i * OoO0O00 * Ii1I + I1ii11iIi11i . OoooooooOO
  if 75 - 75: IiII / OoooooooOO / O0 % OOooOOo
 def lcaf_decode_json ( self , packet ) :
  oOOoooo0o0 = "BBBBHH"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 87 - 87: II111iiii / iIii1I11I1II1 % I1ii11iIi11i
  iII1IiI1I11i , Ii1i11I11i , ii1iI1IIiIi , oO0oooo , ooo0oO0o000O0 , iiIi11i1I1 = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  if 59 - 59: Oo0Ooo + O0 - I11i + OOooOOo
  if 97 - 97: I1IiiI * o0oOOo0O0Ooo
  if ( ii1iI1IIiIi != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 79 - 79: iII111i - ooOoO0o - OoO0O00 / iIii1I11I1II1 % Ii1I
  if 2 - 2: iIii1I11I1II1 + OoooooooOO - i1IIi / Ii1I
  if 88 - 88: I1ii11iIi11i . OoooooooOO / Oo0Ooo / o0oOOo0O0Ooo % Oo0Ooo
  if 80 - 80: Ii1I + OoO0O00 * OoooooooOO - IiII % O0 - I1Ii111
  ooo0oO0o000O0 = socket . ntohs ( ooo0oO0o000O0 )
  iiIi11i1I1 = socket . ntohs ( iiIi11i1I1 )
  packet = packet [ I1I11i : : ]
  if ( len ( packet ) < ooo0oO0o000O0 ) : return ( None )
  if ( ooo0oO0o000O0 != iiIi11i1I1 + 4 ) : return ( None )
  if 80 - 80: II111iiii / I1ii11iIi11i
  if 60 - 60: OOooOOo - iII111i + iIii1I11I1II1 + II111iiii + iII111i
  if 35 - 35: Oo0Ooo * O0 / oO0o * i1IIi . I11i . O0
  if 22 - 22: oO0o / II111iiii . OoOoOO00
  IIiii11IiIi = packet [ 0 : iiIi11i1I1 ]
  packet = packet [ iiIi11i1I1 : : ]
  if 9 - 9: i11iIiiIii + ooOoO0o . iIii1I11I1II1 * OoOoOO00
  if 4 - 4: I1Ii111 + iII111i % O0
  if 98 - 98: i1IIi + I1Ii111 - I1ii11iIi11i . OoooooooOO / O0 / iII111i
  if 66 - 66: i1IIi % OoooooooOO * i11iIiiIii + oO0o * O0 / OoO0O00
  if ( lisp_is_json_telemetry ( IIiii11IiIi ) != None ) :
   self . json_telemetry = IIiii11IiIi
   if 14 - 14: I1IiiI . IiII
   if 29 - 29: OoooooooOO / IiII + OoOoOO00 - I1Ii111 + IiII . i1IIi
   if 26 - 26: i11iIiiIii - II111iiii
   if 43 - 43: I1IiiI
   if 35 - 35: ooOoO0o + OoOoOO00 * OoooooooOO - II111iiii
  oOOoooo0o0 = "H"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  II1i1iI = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] ) [ 0 ]
  packet = packet [ I1I11i : : ]
  if ( II1i1iI != 0 ) : return ( packet )
  if 19 - 19: i1IIi / Ii1I / OoOoOO00 . I1IiiI / Ii1I % o0oOOo0O0Ooo
  if ( self . json_telemetry != None ) : return ( packet )
  if 39 - 39: ooOoO0o - OoooooooOO
  if 88 - 88: i1IIi + iIii1I11I1II1 * i11iIiiIii - OoooooooOO % o0oOOo0O0Ooo
  if 74 - 74: ooOoO0o - i11iIiiIii
  if 34 - 34: IiII + I1Ii111 + Oo0Ooo / II111iiii
  try :
   IIiii11IiIi = json . loads ( IIiii11IiIi )
  except :
   return ( None )
   if 33 - 33: Ii1I . i1IIi - II111iiii - OoO0O00
   if 31 - 31: I11i - OoOoOO00 / o0oOOo0O0Ooo * OoOoOO00 / Oo0Ooo + o0oOOo0O0Ooo
   if 46 - 46: IiII * OoO0O00 / OOooOOo + Oo0Ooo
   if 24 - 24: ooOoO0o % OOooOOo . O0 * Oo0Ooo
   if 52 - 52: O0 . I1Ii111 + iII111i / i11iIiiIii
  if ( "source-eid" not in IIiii11IiIi ) : return ( packet )
  oO0OooO0o0 = IIiii11IiIi [ "source-eid" ]
  II1i1iI = LISP_AFI_IPV4 if oO0OooO0o0 . count ( "." ) == 3 else LISP_AFI_IPV6 if oO0OooO0o0 . count ( ":" ) == 7 else None
  if 23 - 23: OoO0O00 / o0oOOo0O0Ooo
  if ( II1i1iI == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( oO0OooO0o0 ) )
   return ( None )
   if 22 - 22: OOooOOo - OoO0O00 . I11i
   if 89 - 89: I1Ii111
  self . source_eid . afi = II1i1iI
  self . source_eid . store_address ( oO0OooO0o0 )
  if 19 - 19: IiII + I1Ii111
  if ( "signature-eid" not in IIiii11IiIi ) : return ( packet )
  oO0OooO0o0 = IIiii11IiIi [ "signature-eid" ]
  if ( oO0OooO0o0 . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( oO0OooO0o0 ) )
   return ( None )
   if 65 - 65: Ii1I - oO0o + i1IIi + OOooOOo % iII111i
   if 5 - 5: OoO0O00 / iII111i / OOooOOo
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( oO0OooO0o0 )
  if 70 - 70: OoOoOO00 - I11i + ooOoO0o / i11iIiiIii / I1IiiI % iIii1I11I1II1
  if ( "signature" not in IIiii11IiIi ) : return ( packet )
  IIIIi1iII = binascii . a2b_base64 ( IIiii11IiIi [ "signature" ] )
  self . map_request_signature = IIIIi1iII
  return ( packet )
  if 83 - 83: oO0o . Ii1I - o0oOOo0O0Ooo % I11i + i11iIiiIii
  if 40 - 40: O0 . Ii1I
 def decode ( self , packet , source , port ) :
  oOOoooo0o0 = "I"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 58 - 58: i11iIiiIii * iII111i / Ii1I - oO0o - I1ii11iIi11i % o0oOOo0O0Ooo
  iii1I = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  iii1I = iii1I [ 0 ]
  packet = packet [ I1I11i : : ]
  if 16 - 16: OoooooooOO
  oOOoooo0o0 = "Q"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 71 - 71: Ii1I % O0 / I1Ii111 % iII111i - II111iiii / OoO0O00
  o000oo = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  packet = packet [ I1I11i : : ]
  if 30 - 30: I11i
  iii1I = socket . ntohl ( iii1I )
  self . auth_bit = True if ( iii1I & 0x08000000 ) else False
  self . map_data_present = True if ( iii1I & 0x04000000 ) else False
  self . rloc_probe = True if ( iii1I & 0x02000000 ) else False
  self . smr_bit = True if ( iii1I & 0x01000000 ) else False
  self . pitr_bit = True if ( iii1I & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( iii1I & 0x00400000 ) else False
  self . mobile_node = True if ( iii1I & 0x00200000 ) else False
  self . xtr_id_present = True if ( iii1I & 0x00100000 ) else False
  self . decent_nat_xtr = True if ( iii1I & 0x00008000 ) else False
  self . local_xtr = True if ( iii1I & 0x00004000 ) else False
  self . dont_reply_bit = True if ( iii1I & 0x00002000 ) else False
  self . itr_rloc_count = ( ( iii1I >> 8 ) & 0x1f )
  self . record_count = iii1I & 0xff
  self . nonce = o000oo [ 0 ]
  if 60 - 60: ooOoO0o - Ii1I . I1IiiI * oO0o * i11iIiiIii
  if 29 - 29: OoO0O00 - Oo0Ooo . oO0o / OoO0O00 % i11iIiiIii
  if 26 - 26: ooOoO0o . I1Ii111 / II111iiii % Ii1I
  if 82 - 82: OOooOOo % O0 % iIii1I11I1II1 % IiII + i11iIiiIii
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 64 - 64: i1IIi / IiII . IiII - I1Ii111 % OOooOOo . II111iiii
   if 78 - 78: I1Ii111 - O0 - I1Ii111 . iIii1I11I1II1 % I1ii11iIi11i . OoooooooOO
  I1I11i = struct . calcsize ( "H" )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 64 - 64: IiII
  II1i1iI = struct . unpack ( "H" , packet [ : I1I11i ] )
  self . source_eid . afi = socket . ntohs ( II1i1iI [ 0 ] )
  packet = packet [ I1I11i : : ]
  if 21 - 21: o0oOOo0O0Ooo - ooOoO0o * OoooooooOO . OoooooooOO
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   II111i1I = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( II111i1I )
    if ( packet == None ) : return ( None )
    if 2 - 2: o0oOOo0O0Ooo
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 58 - 58: oO0o - II111iiii + O0
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 54 - 54: iIii1I11I1II1 - IiII - IiII
  iiiiiI = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  I1I11ii1III = self . itr_rloc_count + 1
  if 34 - 34: OoOoOO00 % OoooooooOO . II111iiii % OOooOOo
  while ( I1I11ii1III != 0 ) :
   I1I11i = struct . calcsize ( "H" )
   if ( len ( packet ) < I1I11i ) : return ( None )
   if 66 - 66: Oo0Ooo - OoO0O00
   II1i1iI = socket . ntohs ( struct . unpack ( "H" , packet [ : I1I11i ] ) [ 0 ] )
   ooo00 = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   ooo00 . afi = II1i1iI
   if 2 - 2: I1Ii111
   if 96 - 96: OoooooooOO / I1ii11iIi11i * OoO0O00
   if 82 - 82: Oo0Ooo / i11iIiiIii % II111iiii * iIii1I11I1II1 + Ii1I
   if 69 - 69: Oo0Ooo
   if 70 - 70: O0 - OoO0O00 - Oo0Ooo
   if ( ooo00 . afi == LISP_AFI_LCAF ) :
    IiI11 = packet
    O00o0OoO0OOOo = packet [ I1I11i : : ]
    packet = self . lcaf_decode_json ( O00o0OoO0OOOo )
    if ( packet == None ) : return ( None )
    if ( packet == O00o0OoO0OOOo ) : packet = IiI11
    if 72 - 72: ooOoO0o * i11iIiiIii / OoO0O00
    if 47 - 47: OoO0O00 * iIii1I11I1II1 - I1ii11iIi11i - I1Ii111 + IiII
    if 91 - 91: O0
    if 26 - 26: OoooooooOO + oO0o + OoO0O00 . O0
    if 46 - 46: OoooooooOO - Oo0Ooo * I1Ii111 * OOooOOo * I1Ii111 . oO0o
    if 96 - 96: Ii1I / IiII % o0oOOo0O0Ooo + I11i
   if ( ooo00 . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < ooo00 . addr_length ( ) ) : return ( None )
    packet = ooo00 . unpack_address ( packet [ I1I11i : : ] )
    if ( packet == None ) : return ( None )
    if 46 - 46: OoO0O00 * I1IiiI
    if ( iiiiiI ) :
     self . itr_rlocs . append ( ooo00 )
     I1I11ii1III -= 1
     continue
     if 25 - 25: I1Ii111 . IiII % O0 % i1IIi
     if 53 - 53: O0 % ooOoO0o
    Oo0o = lisp_build_crypto_decap_lookup_key ( ooo00 , port )
    if 41 - 41: IiII
    if 29 - 29: ooOoO0o
    if 70 - 70: oO0o . O0 % I11i % IiII - I11i * I1ii11iIi11i
    if 22 - 22: i1IIi
    if 82 - 82: oO0o . iIii1I11I1II1 - I1ii11iIi11i
    if ( lisp_nat_traversal and ooo00 . is_private_address ( ) and source ) : ooo00 = source
    if 55 - 55: Oo0Ooo % Ii1I . iIii1I11I1II1 * I1Ii111
    IiiIiIIII = lisp_crypto_keys_by_rloc_decap
    if ( Oo0o in IiiIiIIII ) : IiiIiIIII . pop ( Oo0o )
    if 81 - 81: I1Ii111 / I1Ii111 + ooOoO0o - Ii1I
    if 93 - 93: ooOoO0o . o0oOOo0O0Ooo + O0 * i1IIi - OoO0O00 * OoO0O00
    if 11 - 11: ooOoO0o - Ii1I . oO0o * Ii1I
    if 85 - 85: i1IIi
    if 94 - 94: OoooooooOO . O0 / OoooooooOO
    if 67 - 67: i11iIiiIii + OoOoOO00
    lisp_write_ipc_decap_key ( Oo0o , None )
    if 50 - 50: ooOoO0o . i1IIi + I1ii11iIi11i . OOooOOo
   elif ( self . json_telemetry == None ) :
    if 97 - 97: I1IiiI
    if 63 - 63: O0 - OoOoOO00 / i11iIiiIii / OoooooooOO / ooOoO0o / II111iiii
    if 45 - 45: II111iiii . OoO0O00 + OoO0O00 * iIii1I11I1II1
    if 23 - 23: IiII * OoOoOO00 % Ii1I / Ii1I - ooOoO0o - OOooOOo
    IiI11 = packet
    O00 = lisp_keys ( 1 )
    packet = O00 . decode_lcaf ( IiI11 , 0 )
    if 17 - 17: II111iiii + ooOoO0o + iII111i . I1ii11iIi11i
    if ( packet == None ) : return ( None )
    if 36 - 36: I1IiiI
    if 75 - 75: I1IiiI % II111iiii * oO0o % i1IIi % OOooOOo
    if 93 - 93: OoOoOO00
    if 48 - 48: i11iIiiIii
    iIi = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( O00 . cipher_suite in iIi ) :
     if ( O00 . cipher_suite == LISP_CS_25519_CBC or
 O00 . cipher_suite == LISP_CS_25519_GCM ) :
      III11II111 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 25 - 25: I1IiiI . iIii1I11I1II1 * i11iIiiIii / oO0o % Ii1I
     if ( O00 . cipher_suite == LISP_CS_25519_CHACHA ) :
      III11II111 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 55 - 55: i11iIiiIii % i1IIi
    else :
     III11II111 = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 39 - 39: I11i % o0oOOo0O0Ooo . o0oOOo0O0Ooo * I1Ii111 + oO0o
    packet = III11II111 . decode_lcaf ( IiI11 , 0 )
    if ( packet == None ) : return ( None )
    if 70 - 70: OoO0O00
    if ( len ( packet ) < I1I11i ) : return ( None )
    II1i1iI = struct . unpack ( "H" , packet [ : I1I11i ] ) [ 0 ]
    ooo00 . afi = socket . ntohs ( II1i1iI )
    if ( len ( packet ) < ooo00 . addr_length ( ) ) : return ( None )
    if 55 - 55: I1IiiI
    packet = ooo00 . unpack_address ( packet [ I1I11i : : ] )
    if ( packet == None ) : return ( None )
    if 61 - 61: Oo0Ooo * I11i % i1IIi
    if ( iiiiiI ) :
     self . itr_rlocs . append ( ooo00 )
     I1I11ii1III -= 1
     continue
     if 21 - 21: iIii1I11I1II1 % O0
     if 19 - 19: IiII / o0oOOo0O0Ooo - Ii1I . i11iIiiIii + oO0o % OoOoOO00
    Oo0o = lisp_build_crypto_decap_lookup_key ( ooo00 , port )
    if 97 - 97: OOooOOo . OOooOOo . iII111i . iII111i
    Ooo0oOoOoOoo = None
    if ( lisp_nat_traversal and ooo00 . is_private_address ( ) and source ) : ooo00 = source
    if 40 - 40: I1ii11iIi11i . OoO0O00
    if 30 - 30: ooOoO0o % I1IiiI . oO0o
    if ( Oo0o in lisp_crypto_keys_by_rloc_decap ) :
     O0o0O0 = lisp_crypto_keys_by_rloc_decap [ Oo0o ]
     Ooo0oOoOoOoo = O0o0O0 [ 1 ] if O0o0O0 and O0o0O0 [ 1 ] else None
     if 48 - 48: OoOoOO00
     if 28 - 28: I11i / O0 * IiII - I1Ii111 % IiII
    I11I1 = True
    if ( Ooo0oOoOoOoo ) :
     if ( Ooo0oOoOoOoo . compare_keys ( III11II111 ) ) :
      self . keys = [ None , Ooo0oOoOoOoo , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( Oo0o , False ) ) )
      if 58 - 58: iII111i % iIii1I11I1II1 * OoO0O00
     else :
      I11I1 = False
      I1I1iI1i = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( I1I1iI1i , red ( Oo0o ,
 False ) ) )
      III11II111 . copy_keypair ( Ooo0oOoOoOoo )
      III11II111 . uptime = Ooo0oOoOoOoo . uptime
      Ooo0oOoOoOoo = None
      if 13 - 13: OoO0O00 - Oo0Ooo / OoO0O00
      if 34 - 34: i11iIiiIii + OoO0O00 + i11iIiiIii . IiII % O0
      if 64 - 64: o0oOOo0O0Ooo . iIii1I11I1II1
    if ( Ooo0oOoOoOoo == None ) :
     self . keys = [ None , III11II111 , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      III11II111 . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( Oo0o , False ) ) )
     elif ( III11II111 . remote_public_key != None ) :
      if ( I11I1 ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # I1ii11iIi11i - O0 * oO0o % iIii1I11I1II1 . I1IiiI - OOooOOo
 red ( Oo0o , False ) ) )
       if 77 - 77: OoOoOO00 + i1IIi - iIii1I11I1II1
      III11II111 . compute_shared_key ( "decap" )
      III11II111 . add_key_by_rloc ( Oo0o , False )
      if 65 - 65: i11iIiiIii + I11i
      if 44 - 44: ooOoO0o
      if 35 - 35: II111iiii + iII111i / I1ii11iIi11i * I1IiiI . I11i
      if 97 - 97: I1IiiI / o0oOOo0O0Ooo
   self . itr_rlocs . append ( ooo00 )
   I1I11ii1III -= 1
   if 13 - 13: I1ii11iIi11i
   if 72 - 72: Oo0Ooo + IiII / Ii1I * Oo0Ooo
  I1I11i = struct . calcsize ( "BBH" )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 41 - 41: OOooOOo - OoOoOO00 . I1IiiI + i11iIiiIii + OoO0O00 * iII111i
  oooo , i111iii1i1 , II1i1iI = struct . unpack ( "BBH" , packet [ : I1I11i ] )
  self . subscribe_bit = ( oooo & 0x80 )
  self . target_eid . afi = socket . ntohs ( II1i1iI )
  packet = packet [ I1I11i : : ]
  if 85 - 85: OoO0O00 + II111iiii
  self . target_eid . mask_len = i111iii1i1
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , o0oo0oO = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( o0oo0oO ) : self . target_group = o0oo0oO
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ I1I11i : : ]
   if 3 - 3: i11iIiiIii / OOooOOo + oO0o
  return ( packet )
  if 10 - 10: OoO0O00 . OoO0O00 + O0
  if 13 - 13: i1IIi . I1IiiI
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 45 - 45: ooOoO0o % I11i
  if 37 - 37: iII111i
 def encode_xtr_id ( self , packet ) :
  OOo00oO000o0O = self . xtr_id >> 64
  IIIIi1I = self . xtr_id & 0xffffffffffffffff
  OOo00oO000o0O = byte_swap_64 ( OOo00oO000o0O )
  IIIIi1I = byte_swap_64 ( IIIIi1I )
  packet += struct . pack ( "QQ" , OOo00oO000o0O , IIIIi1I )
  return ( packet )
  if 70 - 70: O0 + iIii1I11I1II1 % O0 * o0oOOo0O0Ooo - Oo0Ooo - ooOoO0o
  if 94 - 94: i1IIi + IiII / OoooooooOO - oO0o / OOooOOo / OoOoOO00
 def decode_xtr_id ( self , packet ) :
  I1I11i = struct . calcsize ( "QQ" )
  if ( len ( packet ) < I1I11i ) : return ( None )
  packet = packet [ len ( packet ) - I1I11i : : ]
  OOo00oO000o0O , IIIIi1I = struct . unpack ( "QQ" , packet [ : I1I11i ] )
  OOo00oO000o0O = byte_swap_64 ( OOo00oO000o0O )
  IIIIi1I = byte_swap_64 ( IIIIi1I )
  self . xtr_id = ( OOo00oO000o0O << 64 ) | IIIIi1I
  return ( True )
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
class lisp_map_reply ( object ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 84 - 84: IiII
  if 42 - 42: O0 . I1Ii111 / I11i
 def print_map_reply ( self ) :
  I11I111i1I1 = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 69 - 69: OoOoOO00 / I1Ii111 * I1IiiI
  lprint ( I11I111i1I1 . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # OoOoOO00 + ooOoO0o . OoO0O00 / O0 . o0oOOo0O0Ooo
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 34 - 34: o0oOOo0O0Ooo + OOooOOo . OoO0O00 + I1IiiI + OoooooooOO
  if 90 - 90: Ii1I / OoOoOO00 - iIii1I11I1II1 / i1IIi * I1Ii111 - ooOoO0o
 def encode ( self ) :
  iii1I = ( LISP_MAP_REPLY << 28 ) | self . record_count
  iii1I |= self . hop_count << 8
  if ( self . rloc_probe ) : iii1I |= 0x08000000
  if ( self . echo_nonce_capable ) : iii1I |= 0x04000000
  if ( self . security ) : iii1I |= 0x02000000
  if 2 - 2: iII111i * I11i * ooOoO0o + i11iIiiIii + oO0o
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( iii1I ) )
  OO0Oo00OO0oo += struct . pack ( "Q" , self . nonce )
  return ( OO0Oo00OO0oo )
  if 81 - 81: o0oOOo0O0Ooo * OoO0O00
  if 18 - 18: i11iIiiIii / o0oOOo0O0Ooo - oO0o . I11i * i1IIi
 def decode ( self , packet ) :
  oOOoooo0o0 = "I"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 67 - 67: Ii1I
  iii1I = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  iii1I = iii1I [ 0 ]
  packet = packet [ I1I11i : : ]
  if 64 - 64: OoOoOO00 + iII111i * OoOoOO00 - I1IiiI * OoooooooOO
  oOOoooo0o0 = "Q"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 27 - 27: II111iiii + i11iIiiIii
  o000oo = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  packet = packet [ I1I11i : : ]
  if 32 - 32: i1IIi
  iii1I = socket . ntohl ( iii1I )
  self . rloc_probe = True if ( iii1I & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( iii1I & 0x04000000 ) else False
  self . security = True if ( iii1I & 0x02000000 ) else False
  self . hop_count = ( iii1I >> 8 ) & 0xff
  self . record_count = iii1I & 0xff
  self . nonce = o000oo [ 0 ]
  if 76 - 76: II111iiii % ooOoO0o - I1ii11iIi11i
  if ( self . nonce in lisp_crypto_keys_by_nonce ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 50 - 50: II111iiii / I1IiiI . Ii1I % i11iIiiIii
  return ( packet )
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
  if 71 - 71: Ii1I
  if 43 - 43: o0oOOo0O0Ooo / ooOoO0o
  if 88 - 88: i11iIiiIii - i1IIi + Oo0Ooo - O0
  if 50 - 50: I1ii11iIi11i
  if 37 - 37: oO0o % iII111i / II111iiii / OoO0O00 - IiII - ooOoO0o
  if 69 - 69: I1ii11iIi11i . OoooooooOO % I1Ii111
  if 79 - 79: I1IiiI - IiII . OoooooooOO - I1ii11iIi11i
  if 79 - 79: OOooOOo + o0oOOo0O0Ooo % iII111i . oO0o
  if 49 - 49: Ii1I + i11iIiiIii * OoOoOO00 . OoOoOO00 . I1ii11iIi11i . Oo0Ooo
  if 61 - 61: I11i / OOooOOo
  if 85 - 85: OoOoOO00 - I11i . OoOoOO00 . OoOoOO00
  if 62 - 62: IiII % OoooooooOO * OoO0O00 + OoO0O00 % Ii1I % iII111i
  if 66 - 66: I1IiiI . OOooOOo - OoO0O00 % Oo0Ooo * o0oOOo0O0Ooo - oO0o
  if 68 - 68: I11i - i11iIiiIii / o0oOOo0O0Ooo + ooOoO0o / I1IiiI
  if 31 - 31: I1Ii111 . OoooooooOO . i1IIi
  if 65 - 65: OoO0O00 . ooOoO0o
  if 12 - 12: I1Ii111 + O0 - oO0o . IiII
class lisp_eid_record ( object ) :
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
  if 46 - 46: IiII . ooOoO0o / iII111i
  if 63 - 63: II111iiii - I1ii11iIi11i * II111iiii
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 92 - 92: OoO0O00 % ooOoO0o * O0 % iIii1I11I1II1 / i1IIi / OoOoOO00
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 67 - 67: I1Ii111 + I11i + I1Ii111 . OOooOOo % o0oOOo0O0Ooo / ooOoO0o
  if 78 - 78: I1ii11iIi11i . O0
 def print_ttl ( self ) :
  OO0ooo00o = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   OO0ooo00o = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( OO0ooo00o % 60 ) == 0 ) :
   OO0ooo00o = str ( old_div ( OO0ooo00o , 60 ) ) + " hours"
  else :
   OO0ooo00o = str ( OO0ooo00o ) + " mins"
   if 35 - 35: I1ii11iIi11i - i11iIiiIii % i1IIi + Oo0Ooo / OoOoOO00
  return ( OO0ooo00o )
  if 26 - 26: I11i . I1ii11iIi11i
  if 55 - 55: OoOoOO00 * I1Ii111 % OoO0O00 - OoO0O00
 def store_ttl ( self ) :
  OO0ooo00o = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : OO0ooo00o = self . record_ttl & 0x7fffffff
  return ( OO0ooo00o )
  if 34 - 34: O0 * OoO0O00 - oO0o - IiII * Ii1I . II111iiii
  if 28 - 28: O0 % iII111i - i1IIi
 def print_record ( self , indent , ddt ) :
  i1OOO = ""
  Ooo0O00OOO0 = ""
  IIi11I = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    IIi11I = lisp_map_referral_action_string [ self . action ]
    IIi11I = bold ( IIi11I , False )
    i1OOO = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 96 - 96: ooOoO0o
    Ooo0O00OOO0 = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 75 - 75: iII111i / iIii1I11I1II1 * iIii1I11I1II1 * ooOoO0o % I1ii11iIi11i / i11iIiiIii
    if 90 - 90: OoO0O00 + i1IIi
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    IIi11I = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     IIi11I = bold ( IIi11I , False )
     if 43 - 43: O0 % oO0o * I1IiiI
     if 64 - 64: II111iiii + i11iIiiIii
     if 17 - 17: O0 * I1IiiI
     if 40 - 40: iIii1I11I1II1 * iII111i % iIii1I11I1II1
  II1i1iI = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  I11I111i1I1 = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 39 - 39: i1IIi . Ii1I - Oo0Ooo
  lprint ( I11I111i1I1 . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 IIi11I , "auth" if ( self . authoritative is True ) else "non-auth" ,
 i1OOO , Ooo0O00OOO0 , self . map_version , II1i1iI ,
 green ( self . print_prefix ( ) , False ) ) )
  if 91 - 91: I1IiiI - OoooooooOO - OoooooooOO
  if 69 - 69: iII111i * i11iIiiIii / i1IIi
 def encode ( self ) :
  Oo00Oo0o000 = self . action << 13
  if ( self . authoritative ) : Oo00Oo0o000 |= 0x1000
  if ( self . ddt_incomplete ) : Oo00Oo0o000 |= 0x800
  if 93 - 93: OoOoOO00 - OoooooooOO
  if 92 - 92: OoOoOO00 . i1IIi
  if 24 - 24: Oo0Ooo + I11i
  if 9 - 9: iII111i / O0 . Ii1I / o0oOOo0O0Ooo + I1ii11iIi11i
  II1i1iI = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( II1i1iI < 0 ) : II1i1iI = LISP_AFI_LCAF
  iiiiiIIii11I = ( self . group . is_null ( ) == False )
  if ( iiiiiIIii11I ) : II1i1iI = LISP_AFI_LCAF
  if 6 - 6: ooOoO0o - i1IIi . O0 . i1IIi . OoOoOO00
  Ii1iIi1IiiiIi = ( self . signature_count << 12 ) | self . map_version
  i111iii1i1 = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 65 - 65: IiII . OOooOOo % iII111i / O0
  OO0Oo00OO0oo = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , i111iii1i1 , socket . htons ( Oo00Oo0o000 ) ,
 socket . htons ( Ii1iIi1IiiiIi ) , socket . htons ( II1i1iI ) )
  if 95 - 95: i11iIiiIii % i11iIiiIii
  if 19 - 19: ooOoO0o
  if 44 - 44: I1Ii111 - i11iIiiIii * I1IiiI
  if 84 - 84: O0 % Ii1I
  if ( iiiiiIIii11I ) :
   OO0Oo00OO0oo += self . eid . lcaf_encode_sg ( self . group )
   return ( OO0Oo00OO0oo )
   if 3 - 3: I1IiiI . I11i / I1ii11iIi11i
   if 2 - 2: IiII + I11i / iIii1I11I1II1 . i11iIiiIii . i1IIi * ooOoO0o
   if 14 - 14: Oo0Ooo . O0 - oO0o - i11iIiiIii
   if 8 - 8: I1IiiI / iIii1I11I1II1 / OoooooooOO / Oo0Ooo / ooOoO0o
   if 80 - 80: I11i
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   OO0Oo00OO0oo = OO0Oo00OO0oo [ 0 : - 2 ]
   OO0Oo00OO0oo += self . eid . address . encode_geo ( )
   return ( OO0Oo00OO0oo )
   if 26 - 26: II111iiii + I1IiiI . II111iiii - oO0o % OoO0O00
   if 1 - 1: OoO0O00 - II111iiii
   if 75 - 75: Oo0Ooo - OoOoOO00 + oO0o % i1IIi * OOooOOo
   if 56 - 56: OoOoOO00 / OoO0O00 / I1IiiI % OoooooooOO
   if 39 - 39: I1IiiI + II111iiii * Oo0Ooo % Ii1I . o0oOOo0O0Ooo * oO0o
  if ( II1i1iI == LISP_AFI_LCAF ) :
   OO0Oo00OO0oo += self . eid . lcaf_encode_iid ( )
   return ( OO0Oo00OO0oo )
   if 42 - 42: Ii1I / Oo0Ooo
   if 25 - 25: OoooooooOO % Ii1I * I1Ii111 * I11i + I1IiiI % I1ii11iIi11i
   if 70 - 70: Ii1I + I1ii11iIi11i * I11i * i1IIi . I1Ii111
   if 76 - 76: OoooooooOO * OoOoOO00 . OoooooooOO
   if 46 - 46: ooOoO0o * o0oOOo0O0Ooo % II111iiii / I1Ii111
  OO0Oo00OO0oo += self . eid . pack_address ( )
  return ( OO0Oo00OO0oo )
  if 29 - 29: OoO0O00 - i11iIiiIii % Oo0Ooo % o0oOOo0O0Ooo
  if 30 - 30: oO0o - Ii1I % Ii1I
 def decode ( self , packet ) :
  oOOoooo0o0 = "IBBHHH"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 8 - 8: IiII
  self . record_ttl , self . rloc_count , self . eid . mask_len , Oo00Oo0o000 , self . map_version , self . eid . afi = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  if 68 - 68: IiII . OoooooooOO - i11iIiiIii + i11iIiiIii
  if 81 - 81: OoOoOO00 + iII111i . i11iIiiIii
  if 10 - 10: OoOoOO00 + I11i - iIii1I11I1II1 - I11i
  self . record_ttl = socket . ntohl ( self . record_ttl )
  Oo00Oo0o000 = socket . ntohs ( Oo00Oo0o000 )
  self . action = ( Oo00Oo0o000 >> 13 ) & 0x7
  self . authoritative = True if ( ( Oo00Oo0o000 >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( Oo00Oo0o000 >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ I1I11i : : ]
  if 58 - 58: ooOoO0o
  if 98 - 98: Ii1I / OoO0O00 % OoooooooOO
  if 65 - 65: ooOoO0o % Oo0Ooo - I1IiiI % I1Ii111 + iIii1I11I1II1 / iIii1I11I1II1
  if 94 - 94: IiII - Oo0Ooo . o0oOOo0O0Ooo - ooOoO0o - oO0o . I11i
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , iII1I1i = self . eid . lcaf_decode_eid ( packet )
   if ( iII1I1i ) : self . group = iII1I1i
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 33 - 33: ooOoO0o . I1IiiI . i11iIiiIii % OoO0O00
   if 72 - 72: I1ii11iIi11i / O0 % II111iiii / II111iiii
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 48 - 48: OOooOOo % OOooOOo / iIii1I11I1II1 - i11iIiiIii
  if 57 - 57: I11i / IiII * i1IIi + II111iiii . o0oOOo0O0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
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
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 60 - 60: I1Ii111 . oO0o / Oo0Ooo * ooOoO0o + OoOoOO00 - i1IIi
class lisp_ecm ( object ) :
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
  if 13 - 13: i11iIiiIii * oO0o / I11i * I1IiiI
  if 31 - 31: iIii1I11I1II1 * Ii1I % OOooOOo . II111iiii
 def print_ecm ( self ) :
  I11I111i1I1 = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 56 - 56: IiII / i11iIiiIii . o0oOOo0O0Ooo . oO0o - i11iIiiIii
  lprint ( I11I111i1I1 . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 23 - 23: I1ii11iIi11i * i11iIiiIii % ooOoO0o
  if 47 - 47: iIii1I11I1II1 . OOooOOo / I11i % II111iiii
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 92 - 92: I1ii11iIi11i % i11iIiiIii
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 82 - 82: I1Ii111 * I1ii11iIi11i % Ii1I / o0oOOo0O0Ooo
   if 28 - 28: iII111i % OoO0O00 - OOooOOo - Oo0Ooo
   if 16 - 16: i11iIiiIii - i11iIiiIii . OoOoOO00 / i1IIi
   if 76 - 76: O0 * OoO0O00 / O0
   if 23 - 23: I1ii11iIi11i . iIii1I11I1II1 - i11iIiiIii / II111iiii
   if 48 - 48: oO0o - II111iiii * I1IiiI
  iii1I = ( LISP_ECM << 28 )
  if ( self . security ) : iii1I |= 0x08000000
  if ( self . ddt ) : iii1I |= 0x04000000
  if ( self . to_etr ) : iii1I |= 0x02000000
  if ( self . to_ms ) : iii1I |= 0x01000000
  if 78 - 78: I1IiiI * i11iIiiIii * II111iiii
  Iiiiii1i1I1I = struct . pack ( "I" , socket . htonl ( iii1I ) )
  if 11 - 11: II111iiii / I1Ii111 * iII111i + I1ii11iIi11i
  I1IiiIiii1 = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   I1IiiIiii1 = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   I1IiiIiii1 += self . source . pack_address ( )
   I1IiiIiii1 += self . dest . pack_address ( )
   I1IiiIiii1 = lisp_ip_checksum ( I1IiiIiii1 )
   if 38 - 38: OoooooooOO
  if ( self . afi == LISP_AFI_IPV6 ) :
   I1IiiIiii1 = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   I1IiiIiii1 += self . source . pack_address ( )
   I1IiiIiii1 += self . dest . pack_address ( )
   if 46 - 46: i1IIi % iIii1I11I1II1
   if 80 - 80: OoooooooOO / O0 / I1Ii111 - Oo0Ooo . i11iIiiIii
  o0O0o0000o0O0 = socket . htons ( self . udp_sport )
  iiIi = socket . htons ( self . udp_dport )
  o0oOOO = socket . htons ( self . udp_length )
  I1IiII = socket . htons ( self . udp_checksum )
  Ii1iiI1 = struct . pack ( "HHHH" , o0O0o0000o0O0 , iiIi , o0oOOO , I1IiII )
  return ( Iiiiii1i1I1I + I1IiiIiii1 + Ii1iiI1 )
  if 3 - 3: Oo0Ooo - OOooOOo * OoO0O00 - II111iiii . OoooooooOO
  if 14 - 14: I1IiiI
 def decode ( self , packet ) :
  if 41 - 41: I1Ii111 % i1IIi + OoO0O00 / oO0o
  if 48 - 48: i1IIi . Oo0Ooo . i1IIi . I1ii11iIi11i * I1IiiI - Ii1I
  if 83 - 83: OoooooooOO
  if 42 - 42: I1ii11iIi11i . i1IIi - OoOoOO00 - oO0o + i11iIiiIii
  oOOoooo0o0 = "I"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 65 - 65: I1IiiI - O0
  iii1I = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  if 15 - 15: I11i + OoOoOO00 / Oo0Ooo - I1IiiI * I1ii11iIi11i % oO0o
  iii1I = socket . ntohl ( iii1I [ 0 ] )
  self . security = True if ( iii1I & 0x08000000 ) else False
  self . ddt = True if ( iii1I & 0x04000000 ) else False
  self . to_etr = True if ( iii1I & 0x02000000 ) else False
  self . to_ms = True if ( iii1I & 0x01000000 ) else False
  packet = packet [ I1I11i : : ]
  if 90 - 90: Ii1I / I11i
  if 98 - 98: i1IIi
  if 97 - 97: I1Ii111 + O0 - II111iiii / I11i
  if 84 - 84: iIii1I11I1II1 % Ii1I / OoooooooOO
  if ( len ( packet ) < 1 ) : return ( None )
  I1II11IIi11i = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  I1II11IIi11i = I1II11IIi11i >> 4
  if 62 - 62: OOooOOo * OoO0O00 * OoO0O00 + OoooooooOO . IiII + OoO0O00
  if ( I1II11IIi11i == 4 ) :
   I1I11i = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < I1I11i ) : return ( None )
   if 13 - 13: O0 . I1IiiI % OoO0O00 - I11i . O0
   iII , o0oOOO , iII , oOOOooOOO , o00oo , I1IiII = struct . unpack ( "HHIBBH" , packet [ : I1I11i ] )
   self . length = socket . ntohs ( o0oOOO )
   self . ttl = oOOOooOOO
   self . protocol = o00oo
   self . ip_checksum = socket . ntohs ( I1IiII )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 8 - 8: iII111i
   if 52 - 52: OoO0O00 - I1Ii111
   if 9 - 9: I1IiiI . i11iIiiIii
   if 3 - 3: I1IiiI + I1ii11iIi11i * I1Ii111 - i1IIi . OOooOOo
   o00oo = struct . pack ( "H" , 0 )
   iIIIIi = struct . calcsize ( "HHIBB" )
   IiIi1II1Ii = struct . calcsize ( "H" )
   packet = packet [ : iIIIIi ] + o00oo + packet [ iIIIIi + IiIi1II1Ii : ]
   if 53 - 53: O0
   packet = packet [ I1I11i : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 28 - 28: iII111i % OoO0O00 . OoO0O00 / IiII * Oo0Ooo * iII111i
   if 49 - 49: I1IiiI / I1Ii111 * iII111i + I1IiiI % oO0o % ooOoO0o
  if ( I1II11IIi11i == 6 ) :
   I1I11i = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < I1I11i ) : return ( None )
   if 27 - 27: OoO0O00 / iII111i . I1ii11iIi11i
   iII , o0oOOO , o00oo , oOOOooOOO = struct . unpack ( "IHBB" , packet [ : I1I11i ] )
   self . length = socket . ntohs ( o0oOOO )
   self . protocol = o00oo
   self . ttl = oOOOooOOO
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 71 - 71: OoO0O00 . i11iIiiIii . iIii1I11I1II1 + I1IiiI - o0oOOo0O0Ooo
   packet = packet [ I1I11i : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 34 - 34: iII111i
   if 6 - 6: OoO0O00 . OoOoOO00 + I1ii11iIi11i
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 24 - 24: OoO0O00 . Ii1I
  I1I11i = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 26 - 26: O0 * I1IiiI - OOooOOo * OoooooooOO * II111iiii % OoOoOO00
  o0O0o0000o0O0 , iiIi , o0oOOO , I1IiII = struct . unpack ( "HHHH" , packet [ : I1I11i ] )
  self . udp_sport = socket . ntohs ( o0O0o0000o0O0 )
  self . udp_dport = socket . ntohs ( iiIi )
  self . udp_length = socket . ntohs ( o0oOOO )
  self . udp_checksum = socket . ntohs ( I1IiII )
  packet = packet [ I1I11i : : ]
  return ( packet )
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
  if 31 - 31: i11iIiiIii + iIii1I11I1II1 . II111iiii
  if 72 - 72: I1Ii111 * OoO0O00 + Oo0Ooo / Ii1I % OOooOOo
  if 84 - 84: OoOoOO00 / o0oOOo0O0Ooo
  if 9 - 9: Ii1I
  if 76 - 76: I1IiiI % Oo0Ooo / iIii1I11I1II1 - Oo0Ooo
  if 34 - 34: OoOoOO00 - i1IIi + OOooOOo + Ii1I . o0oOOo0O0Ooo
  if 42 - 42: OoO0O00
  if 59 - 59: OoO0O00 . I1Ii111 % OoO0O00
class lisp_rloc_record ( object ) :
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
  if 22 - 22: Oo0Ooo
  if 21 - 21: o0oOOo0O0Ooo
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  o0oo0 = self . rloc_name
  if ( cour ) : o0oo0 = lisp_print_cour ( o0oo0 )
  return ( 'rloc-name: {}' . format ( blue ( o0oo0 , cour ) ) )
  if 93 - 93: Oo0Ooo / II111iiii . Oo0Ooo + i1IIi + i1IIi
  if 30 - 30: OoOoOO00 . OOooOOo % OOooOOo / II111iiii + i1IIi
 def print_record ( self , indent ) :
  IIII1iI1IiIiI = self . print_rloc_name ( )
  if ( IIII1iI1IiIiI != "" ) : IIII1iI1IiIiI = ", " + IIII1iI1IiIiI
  Oo0ooooOOO = ""
  if ( self . geo ) :
   OO0o = ""
   if ( self . geo . geo_name ) : OO0o = "'{}' " . format ( self . geo . geo_name )
   Oo0ooooOOO = ", geo: {}{}" . format ( OO0o , self . geo . print_geo ( ) )
   if 3 - 3: oO0o + OoO0O00 - iII111i / Ii1I
  o000oOOoooo0o = ""
  if ( self . elp ) :
   OO0o = ""
   if ( self . elp . elp_name ) : OO0o = "'{}' " . format ( self . elp . elp_name )
   o000oOOoooo0o = ", elp: {}{}" . format ( OO0o , self . elp . print_elp ( True ) )
   if 75 - 75: O0 - iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - o0oOOo0O0Ooo
  IIi1III11I1Ii = ""
  if ( self . rle ) :
   OO0o = ""
   if ( self . rle . rle_name ) : OO0o = "'{}' " . format ( self . rle . rle_name )
   IIi1III11I1Ii = ", rle: {}{}" . format ( OO0o , self . rle . print_rle ( False ,
 True ) )
   if 62 - 62: OoooooooOO . iIii1I11I1II1 * II111iiii . IiII
  O0OOo0 = ""
  if ( self . json ) :
   OO0o = ""
   if ( self . json . json_name ) :
    OO0o = "'{}' " . format ( self . json . json_name )
    if 97 - 97: oO0o + ooOoO0o % I11i
   O0OOo0 = ", json: {}" . format ( self . json . print_json ( False ) )
   if 41 - 41: i1IIi * O0
   if 60 - 60: Oo0Ooo + I11i % iIii1I11I1II1 % oO0o - I1Ii111 / o0oOOo0O0Ooo
  I11I = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   I11I = ", " + self . keys [ 1 ] . print_keys ( )
   if 89 - 89: o0oOOo0O0Ooo
   if 95 - 95: i1IIi . OoOoOO00 % OoOoOO00 + OOooOOo / OoooooooOO
  I11I111i1I1 = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( I11I111i1I1 . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , IIII1iI1IiIiI , Oo0ooooOOO ,
 o000oOOoooo0o , IIi1III11I1Ii , O0OOo0 , I11I ) )
  if 39 - 39: OoO0O00 % iII111i . oO0o . II111iiii - i11iIiiIii
  if 85 - 85: O0 - OoOoOO00
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 17 - 17: o0oOOo0O0Ooo / i1IIi / OOooOOo
  if 91 - 91: I1ii11iIi11i / Ii1I - OoOoOO00 . I11i / oO0o
  if 16 - 16: IiII % iII111i . oO0o . I1IiiI % O0 * I11i
 def store_rloc_entry ( self , rloc_entry ) :
  OOOo0 = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 82 - 82: OoO0O00 % OOooOOo . I1ii11iIi11i + II111iiii / I11i % I1ii11iIi11i
  self . rloc . copy_address ( OOOo0 )
  if 32 - 32: Oo0Ooo
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 78 - 78: Ii1I . Oo0Ooo + I1IiiI - ooOoO0o
   if 5 - 5: I1IiiI % I1ii11iIi11i * oO0o + I1Ii111
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   OO0o = rloc_entry . geo_name
   if ( OO0o and OO0o in lisp_geo_list ) :
    self . geo = lisp_geo_list [ OO0o ]
    if 4 - 4: IiII - OoOoOO00 % IiII - I1Ii111 / OoO0O00 * o0oOOo0O0Ooo
    if 7 - 7: OoOoOO00 * I1Ii111
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   OO0o = rloc_entry . elp_name
   if ( OO0o and OO0o in lisp_elp_list ) :
    self . elp = lisp_elp_list [ OO0o ]
    if 46 - 46: OoOoOO00 . II111iiii / i11iIiiIii
    if 92 - 92: oO0o - I11i
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   OO0o = rloc_entry . rle_name
   if ( OO0o and OO0o in lisp_rle_list ) :
    self . rle = lisp_rle_list [ OO0o ]
    if 95 - 95: oO0o
    if 88 - 88: iII111i / I1Ii111 + i1IIi / I1Ii111 / o0oOOo0O0Ooo . oO0o
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   OO0o = rloc_entry . json_name
   if ( OO0o and OO0o in lisp_json_list ) :
    self . json = lisp_json_list [ OO0o ]
    if 32 - 32: ooOoO0o / IiII
    if 28 - 28: OoooooooOO % iII111i / i11iIiiIii % OoO0O00 - Oo0Ooo
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 90 - 90: OOooOOo
  if 52 - 52: OoO0O00 * oO0o / iIii1I11I1II1 - OoOoOO00
 def encode_json ( self , lisp_json ) :
  IIiii11IiIi = lisp_json . json_string
  I1Ii1i111I = 0
  if ( lisp_json . json_encrypted ) :
   I1Ii1i111I = ( lisp_json . json_key_id << 5 ) | 0x02
   if 51 - 51: O0 + Ii1I * OoooooooOO . oO0o + OoooooooOO
   if 58 - 58: ooOoO0o . Oo0Ooo / I1ii11iIi11i + OoO0O00 * OoooooooOO / I1IiiI
  ii1iI1IIiIi = LISP_LCAF_JSON_TYPE
  I11IiiI1 = socket . htons ( LISP_AFI_LCAF )
  iii11i11 = self . rloc . addr_length ( ) + 2
  if 80 - 80: II111iiii / iIii1I11I1II1 - OoO0O00 . I11i / II111iiii
  ooo0oO0o000O0 = socket . htons ( len ( IIiii11IiIi ) + iii11i11 )
  if 20 - 20: o0oOOo0O0Ooo % i1IIi / Oo0Ooo / I11i * Oo0Ooo
  iiIi11i1I1 = socket . htons ( len ( IIiii11IiIi ) )
  OO0Oo00OO0oo = struct . pack ( "HBBBBHH" , I11IiiI1 , 0 , 0 , ii1iI1IIiIi , I1Ii1i111I ,
 ooo0oO0o000O0 , iiIi11i1I1 )
  OO0Oo00OO0oo += IIiii11IiIi . encode ( )
  if 91 - 91: OoO0O00 . iII111i
  if 82 - 82: I1ii11iIi11i / Oo0Ooo
  if 63 - 63: I1IiiI
  if 3 - 3: iII111i + I1ii11iIi11i
  if ( lisp_is_json_telemetry ( IIiii11IiIi ) ) :
   OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( self . rloc . afi ) )
   OO0Oo00OO0oo += self . rloc . pack_address ( )
  else :
   OO0Oo00OO0oo += struct . pack ( "H" , 0 )
   if 35 - 35: oO0o * iII111i * oO0o * I1Ii111 * IiII * i1IIi
  return ( OO0Oo00OO0oo )
  if 43 - 43: OoO0O00 * I1IiiI / IiII . i11iIiiIii + iII111i + o0oOOo0O0Ooo
  if 1 - 1: I1IiiI % o0oOOo0O0Ooo . I1Ii111 + I11i * oO0o
 def encode_lcaf ( self ) :
  I11IiiI1 = socket . htons ( LISP_AFI_LCAF )
  iIIIii1I1I11I = b""
  if ( self . geo ) :
   iIIIii1I1I11I = self . geo . encode_geo ( )
   if 6 - 6: I1Ii111 - ooOoO0o . o0oOOo0O0Ooo / ooOoO0o % OoO0O00 * I1IiiI
   if 49 - 49: I1IiiI + O0 - I11i
  iIiOoo0 = b""
  if ( self . elp ) :
   OOo00o0 = b""
   for O00oOo in self . elp . elp_nodes :
    II1i1iI = socket . htons ( O00oOo . address . afi )
    Ii1i11I11i = 0
    if ( O00oOo . eid ) : Ii1i11I11i |= 0x4
    if ( O00oOo . probe ) : Ii1i11I11i |= 0x2
    if ( O00oOo . strict ) : Ii1i11I11i |= 0x1
    Ii1i11I11i = socket . htons ( Ii1i11I11i )
    OOo00o0 += struct . pack ( "HH" , Ii1i11I11i , II1i1iI )
    OOo00o0 += O00oOo . address . pack_address ( )
    if 83 - 83: OoooooooOO / O0 - o0oOOo0O0Ooo % I1IiiI / OoO0O00
    if 31 - 31: iIii1I11I1II1
   II11IiI1I1I1 = socket . htons ( len ( OOo00o0 ) )
   iIiOoo0 = struct . pack ( "HBBBBH" , I11IiiI1 , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , II11IiI1I1I1 )
   iIiOoo0 += OOo00o0
   if 25 - 25: Ii1I - I1ii11iIi11i + Oo0Ooo . I1IiiI
   if 36 - 36: iII111i
  iIIIi1Iii11 = b""
  if ( self . rle ) :
   III1iiii11 = b""
   for iIiII in self . rle . rle_nodes :
    II1i1iI = socket . htons ( iIiII . address . afi )
    III1iiii11 += struct . pack ( "HBBH" , 0 , 0 , iIiII . level , II1i1iI )
    III1iiii11 += iIiII . address . pack_address ( )
    if ( iIiII . rloc_name ) :
     III1iiii11 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     III1iiii11 += ( iIiII . rloc_name + "\0" ) . encode ( )
     if 75 - 75: o0oOOo0O0Ooo / OoooooooOO % OoO0O00 / OoOoOO00 + iII111i
     if 91 - 91: iIii1I11I1II1 / II111iiii + Oo0Ooo
     if 47 - 47: IiII % I1Ii111 + OoO0O00
   i11I1iI1I = socket . htons ( len ( III1iiii11 ) )
   iIIIi1Iii11 = struct . pack ( "HBBBBH" , I11IiiI1 , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , i11I1iI1I )
   iIIIi1Iii11 += III1iiii11
   if 28 - 28: II111iiii / o0oOOo0O0Ooo
   if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
  iIi1i1I = b""
  if ( self . json ) :
   iIi1i1I = self . encode_json ( self . json )
   if 36 - 36: OoooooooOO + O0
   if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
  o00OOOoooo00 = b""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   o00OOOoooo00 = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
   if 42 - 42: I1Ii111 - i11iIiiIii % II111iiii * ooOoO0o . O0 % I11i
  OOOo0OO000o = b""
  if ( self . rloc_name ) :
   OOOo0OO000o += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   OOOo0OO000o += ( self . rloc_name + "\0" ) . encode ( )
   if 11 - 11: I11i - I1Ii111 + O0 + OoOoOO00 % O0 + oO0o
   if 65 - 65: II111iiii % I1ii11iIi11i + OOooOOo + Ii1I
  IiIiI1IiIi = len ( iIIIii1I1I11I ) + len ( iIiOoo0 ) + len ( iIIIi1Iii11 ) + len ( o00OOOoooo00 ) + 2 + len ( iIi1i1I ) + self . rloc . addr_length ( ) + len ( OOOo0OO000o )
  if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
  IiIiI1IiIi = socket . htons ( IiIiI1IiIi )
  O0ooo0O = struct . pack ( "HBBBBHH" , I11IiiI1 , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , IiIiI1IiIi , socket . htons ( self . rloc . afi ) )
  O0ooo0O += self . rloc . pack_address ( )
  return ( O0ooo0O + OOOo0OO000o + iIIIii1I1I11I + iIiOoo0 + iIIIi1Iii11 + o00OOOoooo00 + iIi1i1I )
  if 38 - 38: IiII / i1IIi
  if 60 - 60: OoOoOO00
 def encode ( self ) :
  Ii1i11I11i = 0
  if ( self . local_bit ) : Ii1i11I11i |= 0x0004
  if ( self . probe_bit ) : Ii1i11I11i |= 0x0002
  if ( self . reach_bit ) : Ii1i11I11i |= 0x0001
  if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
  OO0Oo00OO0oo = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( Ii1i11I11i ) ,
 socket . htons ( self . rloc . afi ) )
  if 61 - 61: IiII . IiII
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 17 - 17: OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
   try :
    OO0Oo00OO0oo = OO0Oo00OO0oo [ 0 : - 2 ] + self . encode_lcaf ( )
   except :
    lprint ( "Could not encode LCAF for RLOC-record" )
    if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
  else :
   OO0Oo00OO0oo += self . rloc . pack_address ( )
   if 95 - 95: iII111i / ooOoO0o + I1Ii111
  return ( OO0Oo00OO0oo )
  if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
  if 81 - 81: I1ii11iIi11i
 def decode_lcaf ( self , packet , nonce , ms_json_encrypt ) :
  oOOoooo0o0 = "HBBBBH"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 31 - 31: O0 % ooOoO0o / I1IiiI * iII111i % iIii1I11I1II1 * OoOoOO00
  II1i1iI , iII1IiI1I11i , Ii1i11I11i , ii1iI1IIiIi , oO0oooo , ooo0oO0o000O0 = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  if 76 - 76: I1Ii111 - O0
  if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
  ooo0oO0o000O0 = socket . ntohs ( ooo0oO0o000O0 )
  packet = packet [ I1I11i : : ]
  if ( ooo0oO0o000O0 > len ( packet ) ) : return ( None )
  if 7 - 7: II111iiii + I11i
  if 99 - 99: iIii1I11I1II1 * oO0o
  if 37 - 37: ooOoO0o * iII111i * I11i
  if 11 - 11: I1IiiI
  if ( ii1iI1IIiIi == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( ooo0oO0o000O0 > 0 ) :
    oOOoooo0o0 = "H"
    I1I11i = struct . calcsize ( oOOoooo0o0 )
    if ( ooo0oO0o000O0 < I1I11i ) : return ( None )
    if 48 - 48: O0 . I11i
    II1I = len ( packet )
    II1i1iI = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] ) [ 0 ]
    II1i1iI = socket . ntohs ( II1i1iI )
    if 9 - 9: oO0o / Oo0Ooo
    if ( II1i1iI == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ I1I11i : : ]
     self . rloc_name = None
     if ( II1i1iI == LISP_AFI_NAME ) :
      packet , o0oo0 = lisp_decode_dist_name ( packet )
      self . rloc_name = o0oo0
     else :
      self . rloc . afi = II1i1iI
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 85 - 85: i11iIiiIii / I1IiiI . OoO0O00 . I11i . oO0o * IiII
      if 41 - 41: Ii1I / OoO0O00 / OoO0O00 * I11i
      if 31 - 31: Ii1I / OoooooooOO % iIii1I11I1II1 - IiII * I1IiiI - O0
    ooo0oO0o000O0 -= II1I - len ( packet )
    if 31 - 31: oO0o
    if 74 - 74: OoO0O00
  elif ( ii1iI1IIiIi == LISP_LCAF_GEO_COORD_TYPE ) :
   if 11 - 11: oO0o + O0 % Ii1I . I11i * o0oOOo0O0Ooo
   if 14 - 14: I11i . iIii1I11I1II1 + I1Ii111 % OoooooooOO
   if 9 - 9: oO0o + Ii1I / I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo
   if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
   I1II1II1i = lisp_geo ( "" )
   packet = I1II1II1i . decode_geo ( packet , ooo0oO0o000O0 , oO0oooo )
   if ( packet == None ) : return ( None )
   self . geo = I1II1II1i
   if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
  elif ( ii1iI1IIiIi == LISP_LCAF_JSON_TYPE ) :
   ii1I1I1iII = oO0oooo & 0x02
   if 2 - 2: i11iIiiIii / iII111i % II111iiii
   if 42 - 42: OoOoOO00 / iII111i + OOooOOo
   if 61 - 61: i11iIiiIii % oO0o * ooOoO0o
   if 59 - 59: OOooOOo + i1IIi
   oOOoooo0o0 = "H"
   I1I11i = struct . calcsize ( oOOoooo0o0 )
   if ( ooo0oO0o000O0 < I1I11i ) : return ( None )
   if 10 - 10: Oo0Ooo - i1IIi % I1ii11iIi11i
   iiIi11i1I1 = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] ) [ 0 ]
   iiIi11i1I1 = socket . ntohs ( iiIi11i1I1 )
   if ( ooo0oO0o000O0 < I1I11i + iiIi11i1I1 ) : return ( None )
   if 54 - 54: IiII + OOooOOo + oO0o * O0 % ooOoO0o + OoO0O00
   packet = packet [ I1I11i : : ]
   self . json = lisp_json ( "" , packet [ 0 : iiIi11i1I1 ] , ii1I1I1iII ,
 ms_json_encrypt )
   packet = packet [ iiIi11i1I1 : : ]
   if 13 - 13: i11iIiiIii * O0 . OoooooooOO % I1Ii111 + I1ii11iIi11i + OOooOOo
   if 45 - 45: oO0o % i11iIiiIii / Ii1I / IiII % Ii1I - Ii1I
   if 73 - 73: I1ii11iIi11i * I1ii11iIi11i / II111iiii % iII111i
   if 74 - 74: OoO0O00 / I1ii11iIi11i - ooOoO0o * i1IIi + I1ii11iIi11i . I11i
   II1i1iI = socket . ntohs ( struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ] )
   packet = packet [ 2 : : ]
   if 13 - 13: iII111i + o0oOOo0O0Ooo / iII111i - Ii1I - iII111i
   if ( II1i1iI != 0 and lisp_is_json_telemetry ( self . json . json_string ) ) :
    self . rloc . afi = II1i1iI
    packet = self . rloc . unpack_address ( packet )
    if 34 - 34: IiII . OOooOOo + OOooOOo - OoooooooOO * I1Ii111
    if 72 - 72: iIii1I11I1II1 % i1IIi / OoO0O00 / I1IiiI - II111iiii - I1Ii111
  elif ( ii1iI1IIiIi == LISP_LCAF_ELP_TYPE ) :
   if 43 - 43: o0oOOo0O0Ooo - Oo0Ooo - I1ii11iIi11i / II111iiii + I1IiiI / I1ii11iIi11i
   if 34 - 34: Oo0Ooo
   if 21 - 21: I1IiiI / I1IiiI % I1Ii111 - OoOoOO00 % OoOoOO00 - II111iiii
   if 97 - 97: oO0o
   o0Ooo0oOOooO = lisp_elp ( None )
   o0Ooo0oOOooO . elp_nodes = [ ]
   while ( ooo0oO0o000O0 > 0 ) :
    Ii1i11I11i , II1i1iI = struct . unpack ( "HH" , packet [ : 4 ] )
    if 36 - 36: Ii1I % OoO0O00
    II1i1iI = socket . ntohs ( II1i1iI )
    if ( II1i1iI == LISP_AFI_LCAF ) : return ( None )
    if 89 - 89: I1ii11iIi11i + I11i / i11iIiiIii * ooOoO0o
    O00oOo = lisp_elp_node ( )
    o0Ooo0oOOooO . elp_nodes . append ( O00oOo )
    if 36 - 36: iII111i / OoooooooOO + Ii1I . I1IiiI
    Ii1i11I11i = socket . ntohs ( Ii1i11I11i )
    O00oOo . eid = ( Ii1i11I11i & 0x4 )
    O00oOo . probe = ( Ii1i11I11i & 0x2 )
    O00oOo . strict = ( Ii1i11I11i & 0x1 )
    O00oOo . address . afi = II1i1iI
    O00oOo . address . mask_len = O00oOo . address . host_mask_len ( )
    packet = O00oOo . address . unpack_address ( packet [ 4 : : ] )
    ooo0oO0o000O0 -= O00oOo . address . addr_length ( ) + 4
    if 48 - 48: II111iiii / II111iiii . I11i - I1IiiI
   o0Ooo0oOOooO . select_elp_node ( )
   self . elp = o0Ooo0oOOooO
   if 67 - 67: I1ii11iIi11i + I1ii11iIi11i
  elif ( ii1iI1IIiIi == LISP_LCAF_RLE_TYPE ) :
   if 52 - 52: i11iIiiIii - O0
   if 64 - 64: i11iIiiIii . I1Ii111 / O0 - IiII
   if 88 - 88: Ii1I / OoO0O00 - I11i
   if 11 - 11: OoO0O00 / i1IIi . OoooooooOO
   IIiiiI = lisp_rle ( "" )
   IIiiiI . rle_nodes = [ ]
   while ( ooo0oO0o000O0 > 0 ) :
    iII , I111I1I , i11i , II1i1iI = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 58 - 58: OOooOOo
    II1i1iI = socket . ntohs ( II1i1iI )
    if ( II1i1iI == LISP_AFI_LCAF ) : return ( None )
    if 72 - 72: OoO0O00 + OOooOOo - Oo0Ooo % ooOoO0o . IiII
    iIiII = lisp_rle_node ( )
    IIiiiI . rle_nodes . append ( iIiII )
    if 95 - 95: iII111i % OOooOOo - IiII - OoOoOO00 % o0oOOo0O0Ooo * O0
    iIiII . level = i11i
    iIiII . address . afi = II1i1iI
    iIiII . address . mask_len = iIiII . address . host_mask_len ( )
    packet = iIiII . address . unpack_address ( packet [ 6 : : ] )
    if 16 - 16: I1Ii111 / Oo0Ooo
    ooo0oO0o000O0 -= iIiII . address . addr_length ( ) + 6
    if ( ooo0oO0o000O0 >= 2 ) :
     II1i1iI = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( II1i1iI ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , iIiII . rloc_name = lisp_decode_dist_name ( packet )
      if 48 - 48: Oo0Ooo / oO0o + iII111i % iII111i
      if ( packet == None ) : return ( None )
      ooo0oO0o000O0 -= len ( iIiII . rloc_name ) + 1 + 2
      if 9 - 9: I1ii11iIi11i - o0oOOo0O0Ooo . Oo0Ooo + I1ii11iIi11i . OOooOOo
      if 30 - 30: OoooooooOO - iIii1I11I1II1 / oO0o * Ii1I / Ii1I
      if 52 - 52: OoOoOO00 - OoO0O00 + I1IiiI + IiII
   self . rle = IIiiiI
   self . rle . build_forwarding_list ( )
   if 49 - 49: oO0o / I11i - oO0o
  elif ( ii1iI1IIiIi == LISP_LCAF_SECURITY_TYPE ) :
   if 31 - 31: OoOoOO00 + I1IiiI + I1ii11iIi11i + I11i * II111iiii % oO0o
   if 90 - 90: OOooOOo * iIii1I11I1II1 / i1IIi
   if 60 - 60: OOooOOo * I1Ii111 . oO0o
   if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
   if 51 - 51: I1IiiI . I11i - OoOoOO00
   IiI11 = packet
   O00 = lisp_keys ( 1 )
   packet = O00 . decode_lcaf ( IiI11 , ooo0oO0o000O0 )
   if ( packet == None ) : return ( None )
   if 10 - 10: Oo0Ooo * OOooOOo / IiII . o0oOOo0O0Ooo
   if 97 - 97: Ii1I . Ii1I % iII111i
   if 49 - 49: Oo0Ooo % OOooOOo - OoooooooOO + IiII
   if 54 - 54: iIii1I11I1II1 - OoooooooOO / I11i / oO0o % I1IiiI + OoOoOO00
   iIi = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( O00 . cipher_suite in iIi ) :
    if ( O00 . cipher_suite == LISP_CS_25519_CBC ) :
     III11II111 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 26 - 26: OoO0O00 * II111iiii % OOooOOo * iII111i + iII111i
    if ( O00 . cipher_suite == LISP_CS_25519_CHACHA ) :
     III11II111 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 25 - 25: I11i - I1ii11iIi11i
   else :
    III11II111 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 100 - 100: I1Ii111 / Ii1I + OoOoOO00 . OoooooooOO
   packet = III11II111 . decode_lcaf ( IiI11 , ooo0oO0o000O0 )
   if ( packet == None ) : return ( None )
   if 83 - 83: O0
   if ( len ( packet ) < 2 ) : return ( None )
   II1i1iI = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( II1i1iI )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
   if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
   if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
   if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
   if 46 - 46: o0oOOo0O0Ooo
   if 28 - 28: i1IIi
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
   o0o00O000o0o = self . rloc_name
   if ( o0o00O000o0o ) : o0o00O000o0o = blue ( self . rloc_name , False )
   if 77 - 77: OOooOOo % OOooOOo * Oo0Ooo / iII111i - OoooooooOO - iII111i
   if 52 - 52: I1Ii111 + i1IIi % iII111i % I11i * iIii1I11I1II1 % o0oOOo0O0Ooo
   if 77 - 77: iIii1I11I1II1 * OOooOOo % ooOoO0o
   if 80 - 80: II111iiii
   if 66 - 66: Oo0Ooo . I1Ii111
   if 59 - 59: iII111i - I1IiiI . I1IiiI - Ii1I * OoOoOO00
   Ooo0oOoOoOoo = self . keys [ 1 ] if self . keys else None
   if ( Ooo0oOoOoOoo == None ) :
    if ( III11II111 . remote_public_key == None ) :
     Oo0 = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( Oo0 , o0o00O000o0o ) )
     III11II111 = None
    else :
     Oo0 = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( Oo0 , o0o00O000o0o ) )
     III11II111 . compute_shared_key ( "encap" )
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
   if ( Ooo0oOoOoOoo ) :
    if ( III11II111 . remote_public_key == None ) :
     III11II111 = None
     I1I1iI1i = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( I1I1iI1i , o0o00O000o0o ) )
    elif ( Ooo0oOoOoOoo . compare_keys ( III11II111 ) ) :
     III11II111 = Ooo0oOoOoOoo
     lprint ( "    Maintain stored encap-keys for {}" . format ( o0o00O000o0o ) )
     if 38 - 38: OOooOOo - OoO0O00 . ooOoO0o
    else :
     if ( Ooo0oOoOoOoo . remote_public_key == None ) :
      Oo0 = "New encap-keying for existing state"
     else :
      Oo0 = "Remote encap-rekeying"
      if 50 - 50: o0oOOo0O0Ooo
     lprint ( "    {} for {}" . format ( bold ( Oo0 , False ) ,
 o0o00O000o0o ) )
     Ooo0oOoOoOoo . remote_public_key = III11II111 . remote_public_key
     Ooo0oOoOoOoo . compute_shared_key ( "encap" )
     III11II111 = Ooo0oOoOoOoo
     if 85 - 85: II111iiii . iII111i - i1IIi
     if 23 - 23: iII111i . Ii1I - OoO0O00 / I1ii11iIi11i / O0
   self . keys = [ None , III11II111 , None , None ]
   if 4 - 4: i1IIi % Oo0Ooo % Ii1I * ooOoO0o - I11i
  else :
   if 76 - 76: iIii1I11I1II1 / ooOoO0o % I1ii11iIi11i % OOooOOo
   if 13 - 13: IiII
   if 56 - 56: Oo0Ooo
   if 55 - 55: i11iIiiIii + iIii1I11I1II1 / i1IIi / I1ii11iIi11i
   packet = packet [ ooo0oO0o000O0 : : ]
   if 64 - 64: IiII . OoO0O00 * i11iIiiIii
  return ( packet )
  if 18 - 18: Ii1I % o0oOOo0O0Ooo - Oo0Ooo
  if 28 - 28: IiII
 def decode ( self , packet , nonce , ms_json_encrypt = False ) :
  oOOoooo0o0 = "BBBBHH"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 93 - 93: Oo0Ooo % i1IIi
  self . priority , self . weight , self . mpriority , self . mweight , Ii1i11I11i , II1i1iI = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  if 51 - 51: oO0o % O0
  if 41 - 41: I1IiiI * I1IiiI . I1Ii111
  Ii1i11I11i = socket . ntohs ( Ii1i11I11i )
  II1i1iI = socket . ntohs ( II1i1iI )
  self . local_bit = True if ( Ii1i11I11i & 0x0004 ) else False
  self . probe_bit = True if ( Ii1i11I11i & 0x0002 ) else False
  self . reach_bit = True if ( Ii1i11I11i & 0x0001 ) else False
  if 38 - 38: I1IiiI % i11iIiiIii
  if ( II1i1iI == LISP_AFI_LCAF ) :
   packet = packet [ I1I11i - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
  else :
   self . rloc . afi = II1i1iI
   packet = packet [ I1I11i : : ]
   packet = self . rloc . unpack_address ( packet )
   if 17 - 17: i11iIiiIii
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 81 - 81: I1Ii111
  if 25 - 25: I1IiiI
 def end_of_rlocs ( self , packet , rloc_count ) :
  for iIiIIi in range ( rloc_count ) :
   packet = self . decode ( packet , None , False )
   if ( packet == None ) : return ( None )
   if 52 - 52: I1ii11iIi11i % i1IIi . IiII % OoOoOO00
  return ( packet )
  if 50 - 50: OOooOOo * I1IiiI / o0oOOo0O0Ooo
  if 91 - 91: iIii1I11I1II1 / OOooOOo * O0 . o0oOOo0O0Ooo + oO0o / I1ii11iIi11i
  if 33 - 33: II111iiii + Ii1I
  if 46 - 46: IiII + O0 + i1IIi + ooOoO0o / iII111i
  if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
  if 59 - 59: I11i % Ii1I / OoOoOO00
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
class lisp_map_referral ( object ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 52 - 52: O0 % iII111i
  if 81 - 81: OoooooooOO % OoOoOO00 % Oo0Ooo - I1IiiI
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # Ii1I / o0oOOo0O0Ooo - OoOoOO00
 lisp_hex_string ( self . nonce ) ) )
  if 2 - 2: i11iIiiIii
  if 53 - 53: OoooooooOO % i11iIiiIii
 def encode ( self ) :
  iii1I = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( iii1I ) )
  OO0Oo00OO0oo += struct . pack ( "Q" , self . nonce )
  return ( OO0Oo00OO0oo )
  if 69 - 69: i11iIiiIii - OoOoOO00 % I1Ii111 / II111iiii . OoOoOO00
  if 14 - 14: IiII . OoO0O00 / I1IiiI * Ii1I % OoO0O00 + OOooOOo
 def decode ( self , packet ) :
  oOOoooo0o0 = "I"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 45 - 45: i1IIi % I11i
  iii1I = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  iii1I = socket . ntohl ( iii1I [ 0 ] )
  self . record_count = iii1I & 0xff
  packet = packet [ I1I11i : : ]
  if 6 - 6: II111iiii % I1Ii111 - i11iIiiIii / ooOoO0o
  oOOoooo0o0 = "Q"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 51 - 51: OOooOOo * o0oOOo0O0Ooo / oO0o
  self . nonce = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] ) [ 0 ]
  packet = packet [ I1I11i : : ]
  return ( packet )
  if 43 - 43: I1IiiI * OoooooooOO * OoOoOO00 . OOooOOo / I1IiiI
  if 71 - 71: O0 + iIii1I11I1II1 . oO0o + iII111i
  if 49 - 49: oO0o
  if 36 - 36: iII111i . I11i . i1IIi + I11i
  if 97 - 97: II111iiii . OoooooooOO - OoOoOO00
  if 35 - 35: I1Ii111
  if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
  if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
class lisp_ddt_entry ( object ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 92 - 92: iII111i % I1ii11iIi11i
  if 16 - 16: oO0o
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
  if 24 - 24: Ii1I + IiII + OoooooooOO / oO0o / I1IiiI + IiII
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 52 - 52: ooOoO0o
  if 38 - 38: OoO0O00 + I1IiiI % IiII
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  OOO0o0OOoO00 = self . delegation_set [ 0 ]
  return ( OOO0o0OOoO00 . print_node_type ( ) )
  if 63 - 63: i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
  if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 84 - 84: OOooOOo * i1IIi . iIii1I11I1II1 * iII111i + I1Ii111 + II111iiii
  if 97 - 97: Ii1I - IiII
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   OOo = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( OOo == None ) :
    OOo = lisp_ddt_entry ( )
    OOo . eid . copy_address ( self . group )
    OOo . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , OOo )
    if 98 - 98: II111iiii * OoooooooOO % oO0o - iII111i
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OOo . group )
   OOo . add_source_entry ( self )
   if 97 - 97: OoO0O00 / OOooOOo + Ii1I % O0
   if 36 - 36: OoooooooOO . I1Ii111 + OoOoOO00 % OoO0O00 % I11i . iIii1I11I1II1
   if 57 - 57: oO0o % iII111i + IiII + oO0o
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 31 - 31: iII111i + I1IiiI % OOooOOo
  if 6 - 6: i1IIi / OoOoOO00 + I11i . OoO0O00 . iII111i * II111iiii
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 58 - 58: i1IIi / I1ii11iIi11i - IiII / I11i
  if 68 - 68: OOooOOo % OoOoOO00 / I1IiiI % iII111i / O0 % i1IIi
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 2 - 2: i1IIi / OOooOOo * O0
  if 99 - 99: OoooooooOO . OoOoOO00 / II111iiii
  if 64 - 64: iII111i / i1IIi . I1IiiI + O0
class lisp_ddt_node ( object ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 5 - 5: O0 . i11iIiiIii
  if 71 - 71: o0oOOo0O0Ooo + iII111i + ooOoO0o
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 27 - 27: OoooooooOO . iII111i * I1Ii111 % O0 + OoooooooOO - iII111i
  if 86 - 86: i1IIi
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 81 - 81: OoOoOO00
  if 52 - 52: iII111i * IiII % I1IiiI * I11i
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 73 - 73: I1Ii111 * ooOoO0o
  if 62 - 62: OOooOOo . I1IiiI * iIii1I11I1II1 + OoO0O00 * ooOoO0o / oO0o
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 14 - 14: iII111i / OoO0O00
  if 75 - 75: IiII
  if 68 - 68: IiII - i1IIi % IiII . OoO0O00 . i11iIiiIii . OoooooooOO
  if 32 - 32: iII111i + OoO0O00 % IiII + I1IiiI
  if 69 - 69: I1Ii111 + I11i - iIii1I11I1II1 - II111iiii . Ii1I
  if 74 - 74: I1ii11iIi11i % o0oOOo0O0Ooo + O0 - i11iIiiIii - IiII % OOooOOo
  if 39 - 39: OoO0O00 - o0oOOo0O0Ooo
class lisp_ddt_map_request ( object ) :
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
  if 71 - 71: iII111i . OoO0O00 + ooOoO0o - OOooOOo - Oo0Ooo
  if 100 - 100: OoooooooOO - o0oOOo0O0Ooo + I1Ii111 . OoooooooOO % i11iIiiIii
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # OOooOOo - II111iiii * OoooooooOO . i1IIi
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 42 - 42: o0oOOo0O0Ooo
  if 73 - 73: o0oOOo0O0Ooo . OoO0O00 . IiII + I1ii11iIi11i % ooOoO0o
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 38 - 38: II111iiii + OoO0O00 - II111iiii * OoOoOO00
  if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo + I1IiiI * iIii1I11I1II1 + Oo0Ooo + i11iIiiIii
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( self . nonce in lisp_ddt_map_requestQ ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 67 - 67: i1IIi % I1Ii111 / i11iIiiIii . OoO0O00 - I1ii11iIi11i
   if 15 - 15: o0oOOo0O0Ooo . OoO0O00 * i1IIi % I11i % OoOoOO00
   if 25 - 25: OoOoOO00 . iIii1I11I1II1 - iII111i % II111iiii . OoOoOO00
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
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
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 38 - 38: IiII - OoO0O00 % Ii1I - II111iiii
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
if 28 - 28: I1Ii111
if 27 - 27: iII111i * I1IiiI
if 60 - 60: i1IIi / I1IiiI - I1ii11iIi11i
if 41 - 41: I1Ii111 + ooOoO0o / OOooOOo + I11i % Oo0Ooo
if 91 - 91: I1IiiI % I1ii11iIi11i % oO0o / i1IIi * iIii1I11I1II1 + I11i
if 48 - 48: ooOoO0o / I1ii11iIi11i / OoO0O00 / II111iiii * OoOoOO00
if 73 - 73: I11i / I1IiiI - IiII - i1IIi * IiII - OOooOOo
if 39 - 39: I11i . ooOoO0o * II111iiii
if 21 - 21: Ii1I
if 92 - 92: OoO0O00 * I1ii11iIi11i + iIii1I11I1II1
if 88 - 88: iIii1I11I1II1 + iIii1I11I1II1 * i11iIiiIii . I1ii11iIi11i % oO0o
if 94 - 94: I1IiiI / I1ii11iIi11i / OOooOOo
if 45 - 45: II111iiii
if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
if 84 - 84: o0oOOo0O0Ooo
if 40 - 40: OoooooooOO - oO0o / O0 * I1Ii111 . O0 + i11iIiiIii
if 9 - 9: OOooOOo % O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
if 66 - 66: OOooOOo * Oo0Ooo
if 58 - 58: OOooOOo
if 96 - 96: IiII % OoooooooOO + O0 * II111iiii / OOooOOo . I1Ii111
if 47 - 47: OoO0O00 - Oo0Ooo * OoO0O00 / oO0o
if 13 - 13: ooOoO0o
if 55 - 55: i1IIi . I11i . II111iiii + O0 + ooOoO0o - i1IIi
if 3 - 3: iIii1I11I1II1 / oO0o
if 61 - 61: I1Ii111 / O0 - iII111i
if 44 - 44: i1IIi
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
class lisp_info ( object ) :
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
  if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
  if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
 def print_info ( self ) :
  if ( self . info_reply ) :
   iiI1IiI = "Info-Reply"
   OOOo0 = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # OOooOOo . oO0o . IiII + I1IiiI - OoooooooOO
   # I1IiiI / i11iIiiIii % IiII * iIii1I11I1II1 . I1IiiI
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : OOOo0 += "empty, "
   for oOo in self . rtr_list :
    OOOo0 += red ( oOo . print_address_no_iid ( ) , False ) + ", "
    if 70 - 70: OoO0O00
   OOOo0 = OOOo0 [ 0 : - 2 ]
  else :
   iiI1IiI = "Info-Request"
   oo0O = "<none>" if self . hostname == None else self . hostname
   OOOo0 = ", hostname: {}" . format ( blue ( oo0O , False ) )
   if 1 - 1: OOooOOo % oO0o * OoOoOO00 / I1ii11iIi11i % Ii1I * iIii1I11I1II1
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( iiI1IiI , False ) ,
 lisp_hex_string ( self . nonce ) , OOOo0 ) )
  if 96 - 96: oO0o
  if 88 - 88: OoO0O00 / OoO0O00 * I1ii11iIi11i + I1IiiI % i1IIi
 def encode ( self ) :
  iii1I = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : iii1I |= ( 1 << 27 )
  if 86 - 86: II111iiii / I1Ii111
  if 39 - 39: OoOoOO00 / o0oOOo0O0Ooo . II111iiii
  if 74 - 74: I11i . OoO0O00 . I1Ii111 . iII111i
  if 17 - 17: iIii1I11I1II1
  if 10 - 10: i11iIiiIii / iII111i - oO0o
  if 98 - 98: Ii1I % iII111i . I11i
  if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i % o0oOOo0O0Ooo . ooOoO0o - oO0o
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( iii1I ) )
  OO0Oo00OO0oo += struct . pack ( "Q" , self . nonce )
  OO0Oo00OO0oo += struct . pack ( "III" , 0 , 0 , 0 )
  if 64 - 64: I11i * ooOoO0o
  if 86 - 86: OoooooooOO * I1IiiI
  if 88 - 88: Ii1I + O0
  if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    OO0Oo00OO0oo += struct . pack ( "H" , 0 )
   else :
    OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    OO0Oo00OO0oo += ( self . hostname + "\0" ) . encode ( )
    if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
   return ( OO0Oo00OO0oo )
   if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
   if 85 - 85: OoooooooOO * ooOoO0o
   if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
   if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
   if 26 - 26: O0 % o0oOOo0O0Ooo + iII111i * I1ii11iIi11i * I1Ii111
  II1i1iI = socket . htons ( LISP_AFI_LCAF )
  ii1iI1IIiIi = LISP_LCAF_NAT_TYPE
  ooo0oO0o000O0 = socket . htons ( 16 )
  II1i1i1IIiIi = socket . htons ( self . ms_port )
  IIIO00o = socket . htons ( self . etr_port )
  OO0Oo00OO0oo += struct . pack ( "HHBBHHHH" , II1i1iI , 0 , ii1iI1IIiIi , 0 , ooo0oO0o000O0 ,
 II1i1i1IIiIi , IIIO00o , socket . htons ( self . global_etr_rloc . afi ) )
  OO0Oo00OO0oo += self . global_etr_rloc . pack_address ( )
  OO0Oo00OO0oo += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  OO0Oo00OO0oo += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : OO0Oo00OO0oo += struct . pack ( "H" , 0 )
  if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
  if 91 - 91: i11iIiiIii + Ii1I
  if 85 - 85: I11i % IiII
  if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
  for oOo in self . rtr_list :
   OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( oOo . afi ) )
   OO0Oo00OO0oo += oOo . pack_address ( )
   if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
  return ( OO0Oo00OO0oo )
  if 24 - 24: ooOoO0o - I1Ii111 * II111iiii - II111iiii
  if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
 def decode ( self , packet ) :
  IiI11 = packet
  oOOoooo0o0 = "I"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 93 - 93: Ii1I / iII111i
  iii1I = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  iii1I = iii1I [ 0 ]
  packet = packet [ I1I11i : : ]
  if 100 - 100: Oo0Ooo
  oOOoooo0o0 = "Q"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 94 - 94: I1ii11iIi11i / i1IIi * I1IiiI - I11i - I1ii11iIi11i
  o000oo = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  if 6 - 6: I1ii11iIi11i % o0oOOo0O0Ooo + o0oOOo0O0Ooo / OOooOOo / I1IiiI
  iii1I = socket . ntohl ( iii1I )
  self . nonce = o000oo [ 0 ]
  self . info_reply = iii1I & 0x08000000
  self . hostname = None
  packet = packet [ I1I11i : : ]
  if 67 - 67: OoOoOO00 . iII111i / OOooOOo * ooOoO0o + i1IIi
  if 100 - 100: OOooOOo . ooOoO0o + I1Ii111 . oO0o
  if 20 - 20: i11iIiiIii - i1IIi - iIii1I11I1II1 - OoooooooOO
  if 72 - 72: I1Ii111 . OoO0O00
  if 59 - 59: I1IiiI * I11i % i1IIi
  oOOoooo0o0 = "HH"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 77 - 77: OOooOOo * OoooooooOO + I1IiiI + I1IiiI % oO0o . OoooooooOO
  if 60 - 60: iIii1I11I1II1
  if 13 - 13: II111iiii + Ii1I
  if 33 - 33: i1IIi
  if 36 - 36: ooOoO0o % ooOoO0o . i11iIiiIii
  oo0OO0oo , i11iii11 = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  if ( i11iii11 != 0 ) : return ( None )
  if 42 - 42: OoO0O00 . I1Ii111 / Ii1I
  packet = packet [ I1I11i : : ]
  oOOoooo0o0 = "IBBH"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / oO0o . OoOoOO00
  OO0ooo00o , ii , OoOO0oo0OOOO , iiiiI1IiiI = struct . unpack ( oOOoooo0o0 ,
 packet [ : I1I11i ] )
  if 71 - 71: OoOoOO00 + iII111i - I1IiiI
  if ( iiiiI1IiiI != 0 ) : return ( None )
  packet = packet [ I1I11i : : ]
  if 80 - 80: OoO0O00 . ooOoO0o
  if 58 - 58: iII111i / o0oOOo0O0Ooo . iII111i % OoO0O00
  if 38 - 38: iIii1I11I1II1 % IiII * OoooooooOO - OOooOOo
  if 15 - 15: I1IiiI + iIii1I11I1II1 . i11iIiiIii % oO0o
  if ( self . info_reply == False ) :
   oOOoooo0o0 = "H"
   I1I11i = struct . calcsize ( oOOoooo0o0 )
   if ( len ( packet ) >= I1I11i ) :
    II1i1iI = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] ) [ 0 ]
    if ( socket . ntohs ( II1i1iI ) == LISP_AFI_NAME ) :
     packet = packet [ I1I11i : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 92 - 92: I11i
     if 96 - 96: O0 / i1IIi - i11iIiiIii / OoOoOO00 + OoooooooOO
   return ( IiI11 )
   if 12 - 12: oO0o . OOooOOo
   if 76 - 76: oO0o - I11i * I1Ii111 . oO0o % iIii1I11I1II1
   if 86 - 86: OoooooooOO + I1Ii111
   if 5 - 5: I1ii11iIi11i
   if 89 - 89: OoO0O00 - OoOoOO00 / II111iiii . I1ii11iIi11i
  oOOoooo0o0 = "HHBBHHH"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 50 - 50: Ii1I * I1Ii111 * OoooooooOO . OoooooooOO
  II1i1iI , iII , ii1iI1IIiIi , ii , ooo0oO0o000O0 , II1i1i1IIiIi , IIIO00o = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  if 67 - 67: i11iIiiIii % ooOoO0o . I1ii11iIi11i + II111iiii . OoO0O00
  if 42 - 42: I11i / OoO0O00 / OoO0O00 * OOooOOo
  if ( socket . ntohs ( II1i1iI ) != LISP_AFI_LCAF ) : return ( None )
  if 2 - 2: II111iiii % oO0o . I1Ii111
  self . ms_port = socket . ntohs ( II1i1i1IIiIi )
  self . etr_port = socket . ntohs ( IIIO00o )
  packet = packet [ I1I11i : : ]
  if 100 - 100: OoOoOO00 + OoOoOO00
  if 26 - 26: II111iiii * iII111i + OOooOOo
  if 28 - 28: Ii1I + O0
  if 44 - 44: oO0o
  oOOoooo0o0 = "H"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 51 - 51: o0oOOo0O0Ooo * o0oOOo0O0Ooo . Ii1I
  if 14 - 14: OoO0O00 . I11i % II111iiii % i11iIiiIii + OoooooooOO
  if 50 - 50: i11iIiiIii * I11i + i11iIiiIii - i1IIi
  if 69 - 69: I1IiiI + IiII + oO0o * I1ii11iIi11i . iIii1I11I1II1 / OoooooooOO
  II1i1iI = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] ) [ 0 ]
  packet = packet [ I1I11i : : ]
  if ( II1i1iI != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( II1i1iI )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 77 - 77: Oo0Ooo - ooOoO0o
   if 68 - 68: Ii1I * O0
   if 61 - 61: II111iiii - OoO0O00 . iIii1I11I1II1 * o0oOOo0O0Ooo . OoO0O00 % IiII
   if 11 - 11: oO0o + I11i
   if 6 - 6: i1IIi . o0oOOo0O0Ooo + OoO0O00 + OOooOOo + oO0o
   if 30 - 30: O0
  if ( len ( packet ) < I1I11i ) : return ( IiI11 )
  if 98 - 98: I1Ii111
  II1i1iI = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] ) [ 0 ]
  packet = packet [ I1I11i : : ]
  if ( II1i1iI != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( II1i1iI )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( IiI11 )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 58 - 58: OOooOOo
   if 6 - 6: I1ii11iIi11i
   if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
   if 18 - 18: ooOoO0o
   if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
  if ( len ( packet ) < I1I11i ) : return ( IiI11 )
  if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
  II1i1iI = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] ) [ 0 ]
  packet = packet [ I1I11i : : ]
  if ( II1i1iI != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( II1i1iI )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( IiI11 )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 29 - 29: Ii1I . II111iiii / I1Ii111
   if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
   if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
   if 81 - 81: i11iIiiIii - II111iiii + I11i
   if 52 - 52: II111iiii
   if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
  while ( len ( packet ) >= I1I11i ) :
   II1i1iI = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] ) [ 0 ]
   packet = packet [ I1I11i : : ]
   if ( II1i1iI == 0 ) : continue
   oOo = lisp_address ( socket . ntohs ( II1i1iI ) , "" , 0 , 0 )
   packet = oOo . unpack_address ( packet )
   if ( packet == None ) : return ( IiI11 )
   oOo . mask_len = oOo . host_mask_len ( )
   self . rtr_list . append ( oOo )
   if 26 - 26: I1ii11iIi11i - OoO0O00
  return ( IiI11 )
  if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
  if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
  if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
class lisp_nat_info ( object ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
  if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
 def timed_out ( self ) :
  i11Ii1IIi = time . time ( ) - self . uptime
  return ( i11Ii1IIi >= ( LISP_INFO_INTERVAL * 2 ) )
  if 15 - 15: Ii1I
  if 29 - 29: I11i / I1IiiI / OoooooooOO . OoOoOO00 / I11i . I1Ii111
  if 69 - 69: O0 * OoOoOO00 + o0oOOo0O0Ooo + I1IiiI % iII111i . OoooooooOO
class lisp_info_source ( object ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 45 - 45: I1Ii111 + oO0o - o0oOOo0O0Ooo - OoOoOO00 + I1IiiI / II111iiii
  if 46 - 46: II111iiii . iIii1I11I1II1
 def cache_address_for_info_source ( self ) :
  III11II111 = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ III11II111 ] = self
  if 62 - 62: I1ii11iIi11i % i1IIi % I1Ii111 * ooOoO0o % OOooOOo + I1IiiI
  if 100 - 100: II111iiii - o0oOOo0O0Ooo * OoooooooOO . ooOoO0o / II111iiii / oO0o
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
  if 43 - 43: iIii1I11I1II1 + ooOoO0o * iII111i + iIii1I11I1II1 . I1Ii111
  if 87 - 87: I1Ii111
  if 47 - 47: II111iiii + I1IiiI . Oo0Ooo / iIii1I11I1II1
  if 14 - 14: i1IIi / OoO0O00 / iII111i % I1Ii111
  if 72 - 72: OoO0O00 . II111iiii - IiII + IiII + iIii1I11I1II1 % oO0o
  if 21 - 21: iII111i + OoOoOO00 - i11iIiiIii % O0 + OOooOOo
  if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
  if 94 - 94: IiII
  if 69 - 69: I1Ii111 . I1Ii111
  if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
  if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 8 - 8: iII111i % o0oOOo0O0Ooo
 if ( lisp_is_x86 ( ) or lisp_is_apple_m ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 87 - 87: Ii1I % I11i / I1Ii111
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 21 - 21: OoO0O00 + Ii1I / I1Ii111
  if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  i1i1iiIi1 = auth1 + auth2 + auth3
  if 38 - 38: i1IIi
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  i1i1iiIi1 = auth1 + auth2 + auth3 + auth4
  if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
 return ( i1i1iiIi1 )
 if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
 if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
 if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
 if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
 if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
 if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
 if 2 - 2: OOooOOo / I11i * I11i + I11i / O0 - OOooOOo
 if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
 if 68 - 68: iII111i / OOooOOo
 if 28 - 28: II111iiii
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   iiii1i1I = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 3 - 3: I11i
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   iiii1i1I = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 51 - 51: Ii1I
  iiii1i1I . bind ( ( local_addr , int ( port ) ) )
 else :
  OO0o = port
  if ( os . path . exists ( OO0o ) ) :
   os . system ( "rm " + OO0o )
   time . sleep ( 1 )
   if 15 - 15: o0oOOo0O0Ooo + O0
  iiii1i1I = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  iiii1i1I . bind ( OO0o )
  if 90 - 90: i11iIiiIii * I1Ii111 % i1IIi + OoOoOO00
 return ( iiii1i1I )
 if 84 - 84: i11iIiiIii + oO0o
 if 45 - 45: Ii1I
 if 8 - 8: oO0o + OOooOOo
 if 37 - 37: IiII - OoOoOO00 + oO0o - Oo0Ooo + IiII
 if 33 - 33: Oo0Ooo % oO0o - I1IiiI + Oo0Ooo
 if 90 - 90: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1 % IiII * I1Ii111 . I1Ii111
 if 90 - 90: o0oOOo0O0Ooo - O0 % O0 - oO0o . OoooooooOO
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   iiii1i1I = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 30 - 30: I11i + O0 / Ii1I / OoOoOO00 - oO0o + II111iiii
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   iiii1i1I = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 21 - 21: iIii1I11I1II1 % OoooooooOO * OOooOOo % i1IIi
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  iiii1i1I = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  iiii1i1I . bind ( internal_name )
  if 73 - 73: OoooooooOO
 return ( iiii1i1I )
 if 100 - 100: I11i / i1IIi / i1IIi % Ii1I - II111iiii . OoooooooOO
 if 72 - 72: Oo0Ooo * OoooooooOO % I1IiiI + I11i - II111iiii
 if 82 - 82: iIii1I11I1II1 / i1IIi * I1IiiI . i11iIiiIii
 if 56 - 56: Ii1I * I1IiiI / ooOoO0o * II111iiii
 if 51 - 51: i1IIi . oO0o % OOooOOo
 if 90 - 90: OoooooooOO + iII111i / iIii1I11I1II1
 if 12 - 12: OoooooooOO
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 9 - 9: O0 / O0 / I1IiiI - oO0o . ooOoO0o
 if 6 - 6: O0 - OoO0O00 + OoooooooOO % iIii1I11I1II1
 if 58 - 58: i11iIiiIii * OOooOOo . Oo0Ooo / iII111i - i1IIi
 if 45 - 45: Ii1I
 if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
 if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
 if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
 if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 86 - 86: iII111i / i1IIi % Oo0Ooo
 if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
 if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
 if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
 if 14 - 14: OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
 if 92 - 92: OoO0O00 . i1IIi
 if 22 - 22: Ii1I . I1IiiI
 if 54 - 54: OOooOOo / I1ii11iIi11i % oO0o
 if 66 - 66: I11i + iII111i
 if 50 - 50: IiII
 if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
def lisp_packet_ipc ( packet , source , sport ) :
 I1IIII = "packet@{}@{}@{}@" . format ( str ( len ( packet ) ) , source , str ( sport ) )
 return ( I1IIII . encode ( ) + packet )
 if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
 if 55 - 55: OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
 if 37 - 37: Ii1I + o0oOOo0O0Ooo
 if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
 if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
 if 8 - 8: I11i - I11i % IiII
 if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
 if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
 if 25 - 25: iII111i / iII111i % OoOoOO00 / ooOoO0o
 if 81 - 81: OOooOOo * oO0o
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 I1IIII = "control-packet@{}@{}@" . format ( dest , str ( dport ) )
 return ( I1IIII . encode ( ) + packet )
 if 32 - 32: Oo0Ooo * OoO0O00 + ooOoO0o . O0 * oO0o * iIii1I11I1II1
 if 50 - 50: i1IIi
 if 53 - 53: II111iiii + O0 . ooOoO0o * IiII + i1IIi
 if 80 - 80: Ii1I + O0
 if 59 - 59: i11iIiiIii - OoooooooOO % I11i . OoO0O00 - Oo0Ooo * o0oOOo0O0Ooo
 if 7 - 7: II111iiii % Ii1I * i11iIiiIii
 if 28 - 28: II111iiii / ooOoO0o * i11iIiiIii % OOooOOo
 if 18 - 18: I11i - IiII - iIii1I11I1II1
 if 82 - 82: II111iiii + OoO0O00 % iIii1I11I1II1 / O0
def lisp_data_packet_ipc ( packet , source ) :
 I1IIII = "data-packet@{}@{}@@" . format ( str ( len ( packet ) ) , source )
 return ( I1IIII . encode ( ) + packet )
 if 75 - 75: OOooOOo * OoO0O00 + OoooooooOO + i11iIiiIii . OoO0O00
 if 94 - 94: I11i * ooOoO0o . I1IiiI / Ii1I - I1IiiI % OoooooooOO
 if 32 - 32: OoO0O00
 if 22 - 22: II111iiii . I11i
 if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
 if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
 if 94 - 94: OOooOOo / IiII
 if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
 if 22 - 22: OoOoOO00 - Oo0Ooo
 if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
 if 33 - 33: I11i + O0
def lisp_command_ipc ( ipc , source ) :
 OO0Oo00OO0oo = "command@{}@{}@@" . format ( len ( ipc ) , source ) + ipc
 return ( OO0Oo00OO0oo . encode ( ) )
 if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
 if 68 - 68: O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
 if 12 - 12: II111iiii + I11i
 if 9 - 9: I1ii11iIi11i
 if 51 - 51: I1ii11iIi11i
 if 37 - 37: I1IiiI % I1Ii111
 if 22 - 22: o0oOOo0O0Ooo % OOooOOo - I11i + ooOoO0o / OOooOOo
 if 98 - 98: I11i * O0 + IiII - oO0o
 if 35 - 35: OoooooooOO * Ii1I
 if 73 - 73: ooOoO0o . OoO0O00 % I1ii11iIi11i - oO0o
 if 67 - 67: o0oOOo0O0Ooo . I11i + i1IIi
def lisp_api_ipc ( source , data ) :
 OO0Oo00OO0oo = "api@" + str ( len ( data ) ) + "@" + source + "@@" + data
 return ( OO0Oo00OO0oo . encode ( ) )
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
def lisp_ipc ( packet , send_socket , node ) :
 if 75 - 75: I11i . Ii1I / I1ii11iIi11i
 if 99 - 99: Ii1I
 if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
 if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 21 - 21: iII111i
  if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
 oo00 = 1500 if ( packet . find ( b"control-packet" ) == - 1 ) else 9000
 if 64 - 64: i1IIi % Oo0Ooo / O0 % Oo0Ooo
 o0O0 = 0
 iIo00oo = len ( packet )
 IiiiI1I11i1II = 0
 Ii1Ii1iII = .001
 while ( iIo00oo > 0 ) :
  oooo0OOO0 = min ( iIo00oo , oo00 )
  Oo0o0o = packet [ o0O0 : oooo0OOO0 + o0O0 ]
  if 81 - 81: oO0o
  try :
   if ( type ( Oo0o0o ) == str ) : Oo0o0o = Oo0o0o . encode ( )
   send_socket . sendto ( Oo0o0o , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( Oo0o0o ) , len ( packet ) , node ) )
   if 62 - 62: OOooOOo * i1IIi - OOooOOo / i11iIiiIii
   IiiiI1I11i1II = 0
   Ii1Ii1iII = .001
   if 17 - 17: I1ii11iIi11i + ooOoO0o % Ii1I % OOooOOo
  except socket . error as o0o00oO0oo000 :
   if ( IiiiI1I11i1II == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 73 - 73: i11iIiiIii
    if 44 - 44: o0oOOo0O0Ooo % Ii1I - OoOoOO00 + OoOoOO00 * IiII + iII111i
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( Oo0o0o ) , len ( packet ) , node , o0o00oO0oo000 ) )
   if 58 - 58: I1ii11iIi11i / oO0o + i11iIiiIii * o0oOOo0O0Ooo
   if 19 - 19: OoOoOO00
   IiiiI1I11i1II += 1
   time . sleep ( Ii1Ii1iII )
   if 17 - 17: Oo0Ooo
   lprint ( "Retrying after {} ms ..." . format ( Ii1Ii1iII * 1000 ) )
   Ii1Ii1iII *= 2
   continue
   if 76 - 76: II111iiii % I1ii11iIi11i
   if 99 - 99: oO0o - I1Ii111
  o0O0 += oooo0OOO0
  iIo00oo -= oooo0OOO0
  if 29 - 29: I1IiiI - I11i
 return
 if 42 - 42: Oo0Ooo - O0 . OoOoOO00
 if 4 - 4: IiII
 if 2 - 2: iII111i
 if 47 - 47: i1IIi % I11i
 if 17 - 17: OoOoOO00 - iII111i % I11i / o0oOOo0O0Ooo / II111iiii
 if 22 - 22: Oo0Ooo + I1ii11iIi11i % i11iIiiIii . OoO0O00 - I11i % I11i
 if 21 - 21: I1IiiI . OoO0O00 * IiII % OoooooooOO - Oo0Ooo + Oo0Ooo
 if 94 - 94: ooOoO0o
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 o0O0 = 0
 I11I1 = b""
 iIo00oo = len ( packet ) * 2
 while ( o0O0 < iIo00oo ) :
  I11I1 += packet [ o0O0 : o0O0 + 8 ] + b" "
  o0O0 += 8
  iIo00oo -= 4
  if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
 return ( I11I1 . decode ( ) )
 if 95 - 95: II111iiii
 if 76 - 76: OoO0O00 % iII111i * OoOoOO00 / ooOoO0o / i1IIi
 if 45 - 45: Ii1I . I11i * I1Ii111 . i11iIiiIii
 if 34 - 34: O0 * o0oOOo0O0Ooo / IiII
 if 75 - 75: I1Ii111 - i1IIi - OoO0O00
 if 25 - 25: iII111i . o0oOOo0O0Ooo
 if 62 - 62: I11i + i1IIi . I1ii11iIi11i - I1ii11iIi11i
def lisp_send ( lisp_sockets , dest , port , packet ) :
 if 68 - 68: ooOoO0o % OoooooooOO
 oOOOoo00O0Oo = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 53 - 53: I1IiiI
 if 32 - 32: i11iIiiIii + iII111i / OoO0O00 / OoO0O00
 if 46 - 46: OOooOOo - OoO0O00 * iIii1I11I1II1 / ooOoO0o + i1IIi
 if 58 - 58: ooOoO0o % OoO0O00 - I1Ii111 - I1ii11iIi11i . oO0o
 if 5 - 5: o0oOOo0O0Ooo . i1IIi / o0oOOo0O0Ooo . OOooOOo % i11iIiiIii
 if 82 - 82: i11iIiiIii / OoooooooOO * IiII + OoooooooOO
 if 52 - 52: IiII
 if 4 - 4: Oo0Ooo / OoOoOO00
 if 97 - 97: Oo0Ooo
 if 6 - 6: O0 - I1ii11iIi11i / OoooooooOO - Ii1I + Oo0Ooo
 if 88 - 88: OOooOOo - I1ii11iIi11i % iII111i
 if 58 - 58: OoO0O00 . O0 - i11iIiiIii . I1IiiI
 iii1 = dest . print_address_no_iid ( )
 if ( iii1 . find ( "::ffff:" ) != - 1 and iii1 . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : oOOOoo00O0Oo = lisp_sockets [ 0 ]
  if ( oOOOoo00O0Oo == None ) :
   oOOOoo00O0Oo = lisp_sockets [ 0 ]
   iii1 = iii1 . split ( "::ffff:" ) [ - 1 ]
   if 95 - 95: OoooooooOO / ooOoO0o * I11i - Ii1I
   if 94 - 94: I1Ii111 + OoO0O00 . OoooooooOO
   if 60 - 60: Ii1I . II111iiii
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + iii1 , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
 if 50 - 50: OoooooooOO + o0oOOo0O0Ooo + iIii1I11I1II1 + OOooOOo
 if 90 - 90: Ii1I * I11i % I1Ii111 - I1ii11iIi11i * I1Ii111 % OoO0O00
 if 50 - 50: iIii1I11I1II1
 try :
  oOOOoo00O0Oo . sendto ( packet , ( iii1 , port ) )
 except socket . error as o0o00oO0oo000 :
  lprint ( "socket.sendto() failed: {}" . format ( o0o00oO0oo000 ) )
  if 56 - 56: oO0o
 return
 if 55 - 55: iIii1I11I1II1 % oO0o % OOooOOo / I1Ii111 * OoooooooOO / Oo0Ooo
 if 88 - 88: I11i + OoO0O00 . iIii1I11I1II1 . II111iiii
 if 67 - 67: OOooOOo - ooOoO0o % iII111i % IiII
 if 71 - 71: OoO0O00 - ooOoO0o - I1IiiI + O0
 if 15 - 15: i1IIi
 if 43 - 43: II111iiii + OOooOOo . i11iIiiIii - II111iiii
 if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
 if 26 - 26: i1IIi - I1IiiI + IiII / OoO0O00 . I1ii11iIi11i
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 82 - 82: I1Ii111 % iII111i . OoOoOO00 % OoO0O00 + I1ii11iIi11i
 if 69 - 69: I1IiiI * OoOoOO00 - ooOoO0o . O0
 if 15 - 15: oO0o . IiII + I1Ii111 - OoooooooOO
 if 85 - 85: II111iiii - Oo0Ooo + oO0o . i11iIiiIii + Oo0Ooo
 if 86 - 86: ooOoO0o . OoO0O00
 oooo0OOO0 = total_length - len ( packet )
 if ( oooo0OOO0 == 0 ) : return ( [ True , packet ] )
 if 47 - 47: IiII % I1IiiI
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 91 - 91: Ii1I
 if 69 - 69: iII111i
 if 96 - 96: Ii1I
 if 39 - 39: OoO0O00 - I1IiiI % II111iiii - IiII * I1ii11iIi11i
 if 64 - 64: OOooOOo + Oo0Ooo . OoOoOO00 . OOooOOo + i11iIiiIii
 iIo00oo = oooo0OOO0
 while ( iIo00oo > 0 ) :
  try : Oo0o0o = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 7 - 7: ooOoO0o * I11i / iIii1I11I1II1
  Oo0o0o = Oo0o0o [ 0 ]
  if 15 - 15: OoooooooOO / iII111i
  if 40 - 40: o0oOOo0O0Ooo
  if 75 - 75: oO0o - OoOoOO00 * ooOoO0o . O0
  if 78 - 78: Oo0Ooo
  if 74 - 74: O0 / I11i
  oo0Ooo = Oo0o0o . decode ( )
  if ( oo0Ooo . find ( "packet@" ) == 0 ) :
   oo0Ooo = oo0Ooo . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( Oo0o0o ) ,
   # I11i
 oo0Ooo [ 1 ] if len ( oo0Ooo ) > 2 else "?" )
   return ( [ False , Oo0o0o ] )
   if 72 - 72: O0
   if 15 - 15: II111iiii / I11i % II111iiii % Ii1I % i11iIiiIii / I1Ii111
  iIo00oo -= len ( Oo0o0o )
  packet += Oo0o0o
  if 93 - 93: OOooOOo / OoooooooOO % iII111i
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( Oo0o0o ) , total_length , source ) )
  if 47 - 47: o0oOOo0O0Ooo - I1IiiI % O0 % I1Ii111 . O0 . OoOoOO00
  if 95 - 95: o0oOOo0O0Ooo * OOooOOo - iII111i * OoooooooOO - ooOoO0o / I1IiiI
 return ( [ True , packet ] )
 if 47 - 47: OoO0O00 % I1IiiI / OoOoOO00 - I1Ii111 / I1IiiI
 if 13 - 13: o0oOOo0O0Ooo % ooOoO0o
 if 15 - 15: iII111i * I1IiiI . iIii1I11I1II1 % I1IiiI / O0
 if 47 - 47: OoooooooOO - i11iIiiIii . I1IiiI / i1IIi
 if 74 - 74: OoooooooOO * ooOoO0o
 if 45 - 45: Oo0Ooo + iIii1I11I1II1 . o0oOOo0O0Ooo
 if 50 - 50: o0oOOo0O0Ooo % O0
 if 67 - 67: OoOoOO00
 if 21 - 21: I11i % Oo0Ooo + Oo0Ooo / iIii1I11I1II1 % iIii1I11I1II1
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 OO0Oo00OO0oo = b""
 for Oo0o0o in payload : OO0Oo00OO0oo += Oo0o0o + b"\x40"
 return ( OO0Oo00OO0oo [ : - 1 ] )
 if 66 - 66: iII111i
 if 72 - 72: ooOoO0o / oO0o / iII111i . I1Ii111 . I1ii11iIi11i + IiII
 if 39 - 39: I1IiiI % I1Ii111
 if 22 - 22: OoOoOO00 - OOooOOo % i1IIi + i1IIi
 if 28 - 28: oO0o + OoOoOO00 * Ii1I . I11i
 if 80 - 80: I1ii11iIi11i / OoOoOO00
 if 74 - 74: I1ii11iIi11i + O0 + o0oOOo0O0Ooo - iII111i
 if 48 - 48: ooOoO0o * iIii1I11I1II1 % Oo0Ooo
 if 60 - 60: OoOoOO00 / i1IIi * iIii1I11I1II1
 if 91 - 91: I1Ii111 . OoooooooOO / IiII / I1IiiI
 if 56 - 56: II111iiii + iIii1I11I1II1 / I1Ii111 / I1Ii111 % Oo0Ooo / OoOoOO00
 if 46 - 46: i11iIiiIii + OoO0O00 . ooOoO0o + OoO0O00 % i11iIiiIii
 if 97 - 97: OoooooooOO % IiII * iIii1I11I1II1
 if 97 - 97: iIii1I11I1II1 - I1Ii111 - o0oOOo0O0Ooo * o0oOOo0O0Ooo * OoOoOO00
 if 80 - 80: II111iiii . I1ii11iIi11i % i11iIiiIii / Ii1I / oO0o
 if 100 - 100: Ii1I . OoO0O00 * ooOoO0o
 if 4 - 4: i1IIi + OoooooooOO
 if 26 - 26: I1IiiI / II111iiii % I1ii11iIi11i * o0oOOo0O0Ooo . IiII / OoO0O00
 if 10 - 10: i11iIiiIii / i1IIi + O0 - i11iIiiIii % I11i - i1IIi
 if 38 - 38: O0 - I1IiiI + Oo0Ooo + ooOoO0o
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 56 - 56: I1Ii111 + oO0o / Ii1I + I1Ii111
  if 21 - 21: OOooOOo / OoOoOO00 + OoOoOO00 + OoOoOO00 - i1IIi + Ii1I
  if 43 - 43: O0 % II111iiii
  if 60 - 60: iII111i / ooOoO0o - Ii1I - OoooooooOO
  try : OOo0 = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 85 - 85: IiII
  if 4 - 4: i1IIi
  if 11 - 11: I1IiiI * OoooooooOO
  if 20 - 20: OoooooooOO + ooOoO0o . O0 - o0oOOo0O0Ooo * iII111i + Oo0Ooo
  if 82 - 82: I11i % iII111i . OOooOOo * O0 - ooOoO0o
  if 49 - 49: Oo0Ooo * I1ii11iIi11i - i1IIi + OoOoOO00
  if ( internal == False ) :
   OO0Oo00OO0oo = OOo0 [ 0 ]
   iiIIiIi1i1I1 = lisp_convert_6to4 ( OOo0 [ 1 ] [ 0 ] )
   O00oo0o0o0oo = OOo0 [ 1 ] [ 1 ]
   if 98 - 98: i11iIiiIii + OoooooooOO / I1IiiI / OOooOOo
   if ( O00oo0o0o0oo == LISP_DATA_PORT ) :
    II111I = lisp_data_plane_logging
    II1Ii1IiiI1 = lisp_format_packet ( OO0Oo00OO0oo [ 0 : 60 ] ) + " ..."
   else :
    II111I = True
    II1Ii1IiiI1 = lisp_format_packet ( OO0Oo00OO0oo )
    if 10 - 10: i1IIi % I11i % i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo + OOooOOo
    if 87 - 87: O0 + o0oOOo0O0Ooo * OoOoOO00 % o0oOOo0O0Ooo * ooOoO0o
   if ( II111I ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( OO0Oo00OO0oo ) , bold ( "from " + iiIIiIi1i1I1 , False ) , O00oo0o0o0oo ,
 II1Ii1IiiI1 ) )
    if 48 - 48: I1ii11iIi11i * I1Ii111 % ooOoO0o * II111iiii + OoOoOO00
   return ( [ "packet" , iiIIiIi1i1I1 , O00oo0o0o0oo , OO0Oo00OO0oo ] )
   if 17 - 17: iII111i + OOooOOo
   if 89 - 89: Oo0Ooo + II111iiii * OoO0O00 + Oo0Ooo % II111iiii
   if 59 - 59: O0 + Oo0Ooo
   if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
   if 50 - 50: I11i . I11i % I1IiiI - i1IIi
   if 63 - 63: OoO0O00 . iII111i
  I1ooO0OoOo = False
  iii = OOo0 [ 0 ]
  if ( type ( iii ) == str ) : iii = iii . encode ( )
  oo00ooo00o = False
  if 1 - 1: iII111i / iII111i % i11iIiiIii / iIii1I11I1II1 % i1IIi + o0oOOo0O0Ooo
  while ( I1ooO0OoOo == False ) :
   iii = iii . split ( b"@" )
   if 64 - 64: II111iiii / II111iiii + OoO0O00
   if ( len ( iii ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( iii [ 0 ] ) )
    if 70 - 70: Oo0Ooo * i11iIiiIii + IiII / OoOoOO00 . I1ii11iIi11i % OoOoOO00
    oo00ooo00o = True
    break
    if 12 - 12: I11i % II111iiii % O0 % O0
    if 18 - 18: iII111i . IiII . I1IiiI
   I1IIi = iii [ 0 ] . decode ( )
   try :
    iIiii1I1II1i = int ( iii [ 1 ] )
   except :
    oOoo0oOOO0o = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( oOoo0oOOO0o , OOo0 ) )
    oo00ooo00o = True
    break
    if 9 - 9: OOooOOo % OoooooooOO . IiII / O0 + iIii1I11I1II1 / OoooooooOO
   iiIIiIi1i1I1 = iii [ 2 ] . decode ( )
   O00oo0o0o0oo = iii [ 3 ] . decode ( )
   if 47 - 47: o0oOOo0O0Ooo - OOooOOo / OOooOOo
   if 97 - 97: OoO0O00 / i11iIiiIii - o0oOOo0O0Ooo * OoOoOO00 * i11iIiiIii . iII111i
   if 41 - 41: i11iIiiIii . i11iIiiIii + OoOoOO00 . i1IIi
   if 54 - 54: I11i + OoooooooOO - II111iiii . iII111i
   if 36 - 36: I1IiiI * II111iiii
   if 68 - 68: oO0o * o0oOOo0O0Ooo + OoooooooOO - I1ii11iIi11i * i1IIi % OOooOOo
   if 39 - 39: I1Ii111 / I11i + oO0o / I1Ii111 % IiII * I1ii11iIi11i
   if 66 - 66: I1ii11iIi11i * ooOoO0o . i11iIiiIii * Oo0Ooo - I11i . I1IiiI
   if ( len ( iii ) > 5 ) :
    OO0Oo00OO0oo = lisp_bit_stuff ( iii [ 4 : : ] )
   else :
    OO0Oo00OO0oo = iii [ 4 ]
    if 43 - 43: I11i . iII111i . IiII - oO0o
    if 60 - 60: i1IIi + iII111i * i1IIi . iII111i
    if 40 - 40: i1IIi . OoO0O00
    if 65 - 65: Oo0Ooo
    if 81 - 81: OOooOOo % OoooooooOO / IiII . Oo0Ooo - ooOoO0o . I1IiiI
    if 3 - 3: O0
   I1ooO0OoOo , OO0Oo00OO0oo = lisp_receive_segments ( lisp_socket , OO0Oo00OO0oo ,
 iiIIiIi1i1I1 , iIiii1I1II1i )
   if ( OO0Oo00OO0oo == None ) : return ( [ "" , "" , "" , "" ] )
   if 95 - 95: i11iIiiIii
   if 100 - 100: iIii1I11I1II1 * I1IiiI * Ii1I * i1IIi . I1Ii111 * I1IiiI
   if 54 - 54: o0oOOo0O0Ooo / iII111i + IiII - o0oOOo0O0Ooo - I11i
   if 28 - 28: I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * IiII + OoooooooOO
   if 52 - 52: I1Ii111
   if ( I1ooO0OoOo == False ) :
    iii = OO0Oo00OO0oo
    continue
    if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
    if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
   if ( O00oo0o0o0oo == "" ) : O00oo0o0o0oo = "no-port"
   if ( I1IIi == "command" and lisp_i_am_core == False ) :
    o00o = OO0Oo00OO0oo . find ( b" {" )
    O0oOO0O00 = OO0Oo00OO0oo if o00o == - 1 else OO0Oo00OO0oo [ : o00o ]
    O0oOO0O00 = ": '" + O0oOO0O00 . decode ( ) + "'"
   else :
    O0oOO0O00 = ""
    if 52 - 52: IiII % iII111i
    if 74 - 74: II111iiii . II111iiii + I1IiiI / OoO0O00
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( OO0Oo00OO0oo ) , bold ( "from " + iiIIiIi1i1I1 , False ) , O00oo0o0o0oo , I1IIi ,
 O0oOO0O00 if ( I1IIi in [ "command" , "api" ] ) else ": ... " if ( I1IIi == "data-packet" ) else ": " + lisp_format_packet ( OO0Oo00OO0oo ) ) )
   if 86 - 86: Ii1I + Ii1I - Oo0Ooo * I1IiiI
   if 52 - 52: I11i - OoO0O00 - I1IiiI % OoOoOO00 % OoOoOO00 + Oo0Ooo
   if 88 - 88: iIii1I11I1II1 * OoO0O00 / IiII
   if 74 - 74: I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
   if 55 - 55: OoO0O00 % IiII
  if ( oo00ooo00o ) : continue
  return ( [ I1IIi , iiIIiIi1i1I1 , O00oo0o0o0oo , OO0Oo00OO0oo ] )
  if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
  if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
  if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
  if 63 - 63: I1Ii111 + iII111i
  if 6 - 6: I1ii11iIi11i + Ii1I
  if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
  if 97 - 97: ooOoO0o + OOooOOo
  if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 iIiIiiI = False
 OO00 = time . time ( )
 if 62 - 62: OOooOOo * o0oOOo0O0Ooo + IiII * o0oOOo0O0Ooo * i11iIiiIii - O0
 I1IIII = lisp_control_header ( )
 if ( I1IIII . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( iIiIiiI )
  if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
  if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
  if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
  if 53 - 53: o0oOOo0O0Ooo * Ii1I
  if 42 - 42: I11i + iII111i / iIii1I11I1II1
 iii1Iii1 = source
 if ( source . find ( "lisp" ) == - 1 ) :
  o0O0o0000o0O0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  o0O0o0000o0O0 . string_to_afi ( source )
  o0O0o0000o0O0 . store_address ( source )
  source = o0O0o0000o0O0
  if 42 - 42: OoOoOO00 . I1ii11iIi11i
  if 77 - 77: I1ii11iIi11i % i1IIi + OOooOOo - OOooOOo - o0oOOo0O0Ooo
 if ( I1IIII . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl , OO00 )
  if 45 - 45: I1ii11iIi11i / o0oOOo0O0Ooo / I1IiiI - Oo0Ooo * ooOoO0o - I1ii11iIi11i
 elif ( I1IIII . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl , OO00 )
  if 71 - 71: I1IiiI % OoO0O00
 elif ( I1IIII . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 32 - 32: oO0o
 elif ( I1IIII . type == LISP_MAP_NOTIFY ) :
  if ( iii1Iii1 == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-rtr" ) ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-itr" ) ) :
   lisp_process_unicast_map_notify ( lisp_sockets , packet , source )
   if 2 - 2: Oo0Ooo
   if 80 - 80: I1Ii111 * II111iiii % Oo0Ooo * ooOoO0o + o0oOOo0O0Ooo
 elif ( I1IIII . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 96 - 96: ooOoO0o
 elif ( I1IIII . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 19 - 19: Ii1I
 elif ( I1IIII . type == LISP_NAT_INFO and I1IIII . is_info_reply ( ) ) :
  iII , I111I1I , iIiIiiI = lisp_process_info_reply ( source , packet , True )
  if 15 - 15: ooOoO0o - II111iiii - iIii1I11I1II1 - I1Ii111
 elif ( I1IIII . type == LISP_NAT_INFO and I1IIII . is_info_reply ( ) == False ) :
  Oo0o = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , Oo0o , udp_sport ,
 None )
  if 23 - 23: I1ii11iIi11i + II111iiii
 elif ( I1IIII . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 99 - 99: o0oOOo0O0Ooo . I1IiiI + o0oOOo0O0Ooo * o0oOOo0O0Ooo / O0
 else :
  lprint ( "Invalid LISP control packet type {}:" . format ( I1IIII . type ) )
  lprint ( lisp_format_packet ( packet ) )
  if 27 - 27: OOooOOo - I1Ii111
  if 33 - 33: OOooOOo - Ii1I - iII111i + I1ii11iIi11i - i11iIiiIii
 return ( iIiIiiI )
 if 89 - 89: iIii1I11I1II1 * I11i + OOooOOo
 if 27 - 27: i1IIi - OoO0O00
 if 23 - 23: iIii1I11I1II1 + Oo0Ooo * IiII
 if 80 - 80: OoooooooOO . ooOoO0o
 if 52 - 52: O0 + O0 + I1IiiI
 if 64 - 64: ooOoO0o
 if 35 - 35: I1IiiI . iIii1I11I1II1 + IiII / i11iIiiIii - II111iiii . OoooooooOO
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp ) :
 if 19 - 19: IiII - OoOoOO00
 o00oo = bold ( "RLOC-probe" , False )
 if 43 - 43: IiII / OOooOOo % II111iiii . o0oOOo0O0Ooo / i11iIiiIii
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( o00oo ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 5 - 5: oO0o % iII111i . Oo0Ooo . O0 . OoOoOO00 / iII111i
  if 78 - 78: Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . OoO0O00 - ooOoO0o
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( o00oo ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 81 - 81: o0oOOo0O0Ooo * OoooooooOO
  if 32 - 32: OoOoOO00 - I11i * i11iIiiIii . I1ii11iIi11i . IiII . iIii1I11I1II1
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( o00oo ) )
 return
 if 41 - 41: iII111i / OoOoOO00 / OoO0O00 / ooOoO0o
 if 16 - 16: iIii1I11I1II1 . II111iiii
 if 80 - 80: Oo0Ooo + IiII
 if 18 - 18: OoO0O00 . Oo0Ooo
 if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 14 - 14: i1IIi
 if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
 if 36 - 36: OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
 if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
 if 23 - 23: oO0o / o0oOOo0O0Ooo + I11i % IiII * OoO0O00
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 48 - 48: OoO0O00
 if 30 - 30: iIii1I11I1II1
 if 53 - 53: II111iiii
 if 40 - 40: Ii1I % oO0o
 if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
 if 78 - 78: oO0o
 if 20 - 20: i1IIi + i1IIi * i1IIi
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , map_request ,
 keys , enc , auth , mr_ttl = - 1 ) :
 if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
 iIi1i1i = map_request . rloc_probe if ( map_request != None ) else False
 I1II11 = map_request . json_telemetry if ( map_request != None ) else None
 if 87 - 87: I1ii11iIi11i - OoO0O00 + o0oOOo0O0Ooo * iIii1I11I1II1 + OoO0O00 + i11iIiiIii
 if 61 - 61: ooOoO0o % i1IIi % Ii1I
 iI1iI1 = lisp_map_reply ( )
 iI1iI1 . rloc_probe = iIi1i1i
 iI1iI1 . echo_nonce_capable = enc
 iI1iI1 . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 iI1iI1 . record_count = 1
 iI1iI1 . nonce = nonce
 OO0Oo00OO0oo = iI1iI1 . encode ( )
 iI1iI1 . print_map_reply ( )
 if 19 - 19: I1ii11iIi11i . Oo0Ooo * i11iIiiIii - iII111i - I11i
 iI1111Ii1I = lisp_eid_record ( )
 iI1111Ii1I . rloc_count = len ( rloc_set )
 if ( I1II11 != None ) : iI1111Ii1I . rloc_count += 1
 iI1111Ii1I . authoritative = auth
 iI1111Ii1I . record_ttl = ttl
 iI1111Ii1I . action = action
 iI1111Ii1I . eid = eid
 iI1111Ii1I . group = group
 if 67 - 67: IiII * II111iiii . i11iIiiIii / oO0o - OOooOOo + I11i
 OO0Oo00OO0oo += iI1111Ii1I . encode ( )
 iI1111Ii1I . print_record ( "  " , False )
 if 46 - 46: OoO0O00 % ooOoO0o % OOooOOo % Ii1I
 oO00oO0o = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 84 - 84: II111iiii . iII111i - OoOoOO00 . i11iIiiIii
 i1II111I11 = None
 for oO0O0oOOO0 in rloc_set :
  oOiI1111iI1 = oO0O0oOOO0 . rloc . is_multicast_address ( )
  Oo000O = lisp_rloc_record ( )
  OOOoOO000OO = iIi1i1i and ( oOiI1111iI1 or I1II11 == None )
  Oo0o = oO0O0oOOO0 . rloc . print_address_no_iid ( )
  if ( Oo0o in oO00oO0o or oOiI1111iI1 ) :
   Oo000O . local_bit = True
   Oo000O . probe_bit = OOOoOO000OO
   Oo000O . keys = keys
   if ( oO0O0oOOO0 . priority == 254 and lisp_i_am_rtr ) :
    Oo000O . rloc_name = "RTR"
    if 37 - 37: iIii1I11I1II1
   if ( i1II111I11 == None ) :
    if ( oO0O0oOOO0 . translated_rloc . is_null ( ) ) :
     i1II111I11 = oO0O0oOOO0 . rloc
    else :
     i1II111I11 = oO0O0oOOO0 . translated_rloc
     if 12 - 12: OoO0O00 / OoOoOO00 * Oo0Ooo - I1Ii111 * OOooOOo
     if 95 - 95: o0oOOo0O0Ooo / oO0o + Ii1I - OoooooooOO
     if 15 - 15: O0
  Oo000O . store_rloc_entry ( oO0O0oOOO0 )
  Oo000O . reach_bit = True
  Oo000O . print_record ( "    " )
  OO0Oo00OO0oo += Oo000O . encode ( )
  if 21 - 21: OoO0O00 * iIii1I11I1II1 - iIii1I11I1II1 % OoO0O00 . I1ii11iIi11i
  if 19 - 19: i1IIi % Ii1I . OoOoOO00
  if 22 - 22: iIii1I11I1II1 + Ii1I
  if 73 - 73: I1IiiI / OoO0O00 / OoooooooOO
  if 14 - 14: ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i . IiII + I1ii11iIi11i
 if ( I1II11 != None ) :
  Oo000O = lisp_rloc_record ( )
  if ( i1II111I11 ) : Oo000O . rloc . copy_address ( i1II111I11 )
  Oo000O . local_bit = True
  Oo000O . probe_bit = True
  Oo000O . reach_bit = True
  if ( lisp_i_am_rtr ) :
   Oo000O . priority = 254
   Oo000O . rloc_name = "RTR"
   if 30 - 30: I1ii11iIi11i + iIii1I11I1II1 . I1ii11iIi11i
  II11Ii11 = lisp_encode_telemetry ( I1II11 , eo = str ( time . time ( ) ) )
  Oo000O . json = lisp_json ( "telemetry" , II11Ii11 )
  Oo000O . print_record ( "    " )
  OO0Oo00OO0oo += Oo000O . encode ( )
  if 38 - 38: I1IiiI - OOooOOo * OoOoOO00 + O0 * I1IiiI
 return ( OO0Oo00OO0oo )
 if 8 - 8: I1IiiI
 if 31 - 31: o0oOOo0O0Ooo + OOooOOo
 if 7 - 7: IiII + iIii1I11I1II1
 if 97 - 97: oO0o
 if 52 - 52: I1ii11iIi11i / OoOoOO00 * OoO0O00 + II111iiii * OoooooooOO
 if 11 - 11: Ii1I * iII111i * I1IiiI - Oo0Ooo
 if 76 - 76: oO0o * II111iiii
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 oooO0OOO0o = lisp_map_referral ( )
 oooO0OOO0o . record_count = 1
 oooO0OOO0o . nonce = nonce
 OO0Oo00OO0oo = oooO0OOO0o . encode ( )
 oooO0OOO0o . print_map_referral ( )
 if 93 - 93: IiII
 iI1111Ii1I = lisp_eid_record ( )
 if 80 - 80: oO0o * I1Ii111 - i1IIi - OoooooooOO
 OO0oIiiI1iIii = 0
 if ( ddt_entry == None ) :
  iI1111Ii1I . eid = eid
  iI1111Ii1I . group = group
 else :
  OO0oIiiI1iIii = len ( ddt_entry . delegation_set )
  iI1111Ii1I . eid = ddt_entry . eid
  iI1111Ii1I . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 98 - 98: IiII * OoooooooOO . iII111i
 iI1111Ii1I . rloc_count = OO0oIiiI1iIii
 iI1111Ii1I . authoritative = True
 if 34 - 34: OoooooooOO + I1Ii111
 if 97 - 97: II111iiii + I11i + OOooOOo / i11iIiiIii - iII111i
 if 9 - 9: i1IIi - I1Ii111 + I1Ii111
 if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
 if 58 - 58: OoooooooOO . II111iiii . O0 % I1Ii111 / OoooooooOO
 i1OOO = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( OO0oIiiI1iIii == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   OOO0o0OOoO00 = ddt_entry . delegation_set [ 0 ]
   if ( OOO0o0OOoO00 . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 64 - 64: Oo0Ooo + oO0o . OoO0O00
   if ( OOO0o0OOoO00 . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 67 - 67: I11i
    if 91 - 91: OOooOOo / OoO0O00
    if 36 - 36: I1IiiI . iII111i * I1Ii111 . IiII % I1ii11iIi11i
    if 44 - 44: I11i % I1ii11iIi11i - OoooooooOO % iII111i
    if 60 - 60: IiII % oO0o
    if 11 - 11: I1Ii111 - II111iiii
    if 12 - 12: i11iIiiIii
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : i1OOO = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  i1OOO = ( lisp_i_am_ms and OOO0o0OOoO00 . is_ms_peer ( ) == False )
  if 9 - 9: OOooOOo * I1ii11iIi11i + iIii1I11I1II1 / OoO0O00 * OoooooooOO
  if 91 - 91: i11iIiiIii % IiII + oO0o . I1IiiI - I1IiiI
 iI1111Ii1I . action = action
 iI1111Ii1I . ddt_incomplete = i1OOO
 iI1111Ii1I . record_ttl = ttl
 if 62 - 62: Oo0Ooo * II111iiii + o0oOOo0O0Ooo . OoOoOO00
 OO0Oo00OO0oo += iI1111Ii1I . encode ( )
 iI1111Ii1I . print_record ( "  " , True )
 if 94 - 94: Oo0Ooo / I1IiiI * iIii1I11I1II1 - OoO0O00
 if ( OO0oIiiI1iIii == 0 ) : return ( OO0Oo00OO0oo )
 if 96 - 96: ooOoO0o - OoooooooOO * iIii1I11I1II1 . IiII - O0
 for OOO0o0OOoO00 in ddt_entry . delegation_set :
  Oo000O = lisp_rloc_record ( )
  Oo000O . rloc = OOO0o0OOoO00 . delegate_address
  Oo000O . priority = OOO0o0OOoO00 . priority
  Oo000O . weight = OOO0o0OOoO00 . weight
  Oo000O . mpriority = 255
  Oo000O . mweight = 0
  Oo000O . reach_bit = True
  OO0Oo00OO0oo += Oo000O . encode ( )
  Oo000O . print_record ( "    " )
  if 7 - 7: iIii1I11I1II1 . OoO0O00
 return ( OO0Oo00OO0oo )
 if 88 - 88: i1IIi * II111iiii / i11iIiiIii % IiII . IiII
 if 93 - 93: OoOoOO00 * i1IIi . Ii1I
 if 2 - 2: i1IIi
 if 84 - 84: i1IIi / Ii1I + OoOoOO00 % Ii1I . oO0o
 if 74 - 74: OOooOOo - o0oOOo0O0Ooo - I1Ii111 - OoO0O00
 if 40 - 40: o0oOOo0O0Ooo . IiII * OoOoOO00
 if 14 - 14: OOooOOo
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 18 - 18: i11iIiiIii % iII111i
 if ( map_request . target_group . is_null ( ) ) :
  Oo0000 = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  Oo0000 = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( Oo0000 ) : Oo0000 = Oo0000 . lookup_source_cache ( map_request . target_eid , False )
  if 50 - 50: OoOoOO00 / I1IiiI * I1IiiI / OoO0O00 * ooOoO0o % I1ii11iIi11i
 ooOo000OoO0o = map_request . print_prefix ( )
 if 21 - 21: OoO0O00 * I11i
 if ( Oo0000 == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( ooOo000OoO0o , False ) ) )
  if 76 - 76: I1IiiI - I1ii11iIi11i / I1ii11iIi11i . o0oOOo0O0Ooo % OoooooooOO
  return
  if 39 - 39: OoooooooOO % iII111i
  if 55 - 55: IiII . i11iIiiIii % OoooooooOO
 o0oOOOooOOoo = Oo0000 . print_eid_tuple ( )
 if 20 - 20: I11i % I1IiiI
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( o0oOOOooOOoo , False ) , green ( ooOo000OoO0o , False ) ) )
 if 82 - 82: i11iIiiIii * i11iIiiIii + I1Ii111 - I1ii11iIi11i * oO0o - Ii1I
 if 40 - 40: o0oOOo0O0Ooo + OoO0O00 % i1IIi % iII111i * I1Ii111
 if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
 if 34 - 34: OoooooooOO * i11iIiiIii
 if 33 - 33: II111iiii
 oo00oOOO00 = map_request . itr_rlocs [ 0 ]
 if ( oo00oOOO00 . is_private_address ( ) and lisp_nat_traversal ) :
  oo00oOOO00 = source
  if 81 - 81: Oo0Ooo + I1Ii111 - I1IiiI
  if 4 - 4: i1IIi
 o000oo = map_request . nonce
 OoO = lisp_nonce_echoing
 O0o0O0 = map_request . keys
 if 71 - 71: OoOoOO00 % i11iIiiIii * IiII % OoooooooOO % o0oOOo0O0Ooo - iIii1I11I1II1
 if 9 - 9: Ii1I
 if 53 - 53: Ii1I % IiII + I11i % IiII
 if 33 - 33: iII111i
 if 8 - 8: I11i
 oO0oo0o0ooO = map_request . json_telemetry
 if ( oO0oo0o0ooO != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( oO0oo0o0ooO , ei = etr_in_ts )
  if 41 - 41: OoO0O00 . Ii1I % II111iiii - i11iIiiIii % o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 2 - 2: ooOoO0o / OOooOOo % iIii1I11I1II1 * I1IiiI - I11i
 Oo0000 . map_replies_sent += 1
 if 3 - 3: i11iIiiIii
 OO0Oo00OO0oo = lisp_build_map_reply ( Oo0000 . eid , Oo0000 . group , Oo0000 . rloc_set , o000oo ,
 LISP_NO_ACTION , 1440 , map_request , O0o0O0 , OoO , True , ttl )
 if 52 - 52: oO0o . OoO0O00 + OoooooooOO % II111iiii % OoOoOO00 - I1Ii111
 if 2 - 2: II111iiii * OOooOOo - I11i / I1IiiI
 if 13 - 13: Oo0Ooo
 if 88 - 88: Oo0Ooo / oO0o . iIii1I11I1II1 . I1IiiI + I11i
 if 58 - 58: I11i
 if 76 - 76: iIii1I11I1II1 % ooOoO0o / IiII + iIii1I11I1II1 % Oo0Ooo . Ii1I
 if 72 - 72: Ii1I - I1ii11iIi11i * I1Ii111 % OoOoOO00 % OoOoOO00
 if 44 - 44: o0oOOo0O0Ooo . O0 + Ii1I
 if 61 - 61: ooOoO0o
 if 23 - 23: OoooooooOO - OoOoOO00 / i11iIiiIii
 if 37 - 37: I11i / o0oOOo0O0Ooo + oO0o % Ii1I
 if 83 - 83: I1ii11iIi11i . OOooOOo
 if 50 - 50: Ii1I - i11iIiiIii % Ii1I - OoOoOO00 + I1IiiI / OoooooooOO
 if 57 - 57: I1IiiI - I11i - I1Ii111 . oO0o % Ii1I
 if 59 - 59: I1IiiI % OoO0O00 . o0oOOo0O0Ooo
 if 85 - 85: ooOoO0o . ooOoO0o % Oo0Ooo . OOooOOo + OOooOOo / I1IiiI
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  if 69 - 69: i1IIi + II111iiii / Ii1I
  ooooO0OO0O = ( oo00oOOO00 . is_private_address ( ) == False )
  oOo = oo00oOOO00 . print_address_no_iid ( )
  if ( ooooO0OO0O and oOo in lisp_rtr_list and sport == 0 ) :
   lisp_encap_rloc_probe ( lisp_sockets , oo00oOOO00 , None , OO0Oo00OO0oo )
   return
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
  if ( lisp_decent_nat ) :
   oO0 = lisp_get_nat_info ( oo00oOOO00 , None )
   if ( oO0 == None ) :
    i111i1iIi1i = oo00oOOO00 . print_address_no_iid ( )
    lprint ( "Could not find NAT-info state for {}" . format ( i111i1iIi1i ) )
    return
    if 25 - 25: II111iiii % I11i
    if 16 - 16: OoOoOO00 % iII111i . OOooOOo * iIii1I11I1II1 / oO0o . OoooooooOO
    if 13 - 13: oO0o / iII111i . oO0o * i11iIiiIii . iIii1I11I1II1
    if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
    if 65 - 65: OOooOOo * I11i * Oo0Ooo
   lisp_encap_rloc_probe ( lisp_sockets , oo00oOOO00 , oO0 , OO0Oo00OO0oo )
   return
   if 21 - 21: Ii1I . iIii1I11I1II1
   if 84 - 84: OOooOOo
   if 67 - 67: I1IiiI % OoO0O00 % o0oOOo0O0Ooo % IiII
   if 33 - 33: ooOoO0o % I1IiiI
   if 98 - 98: oO0o . o0oOOo0O0Ooo + II111iiii
   if 62 - 62: ooOoO0o - OoooooooOO / I1ii11iIi11i / iII111i - o0oOOo0O0Ooo
 lisp_send_map_reply ( lisp_sockets , OO0Oo00OO0oo , oo00oOOO00 , sport )
 return
 if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
 if 9 - 9: iII111i * Oo0Ooo % iII111i % Oo0Ooo * II111iiii
 if 71 - 71: II111iiii + I1ii11iIi11i * II111iiii
 if 59 - 59: OoO0O00
 if 81 - 81: i11iIiiIii
 if 57 - 57: Oo0Ooo * iIii1I11I1II1 - OoOoOO00 % iII111i % I1ii11iIi11i + Ii1I
 if 82 - 82: IiII * Oo0Ooo - iIii1I11I1II1 - i11iIiiIii
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 85 - 85: OoooooooOO
 if 37 - 37: OoooooooOO + O0 + I1ii11iIi11i + IiII * iII111i
 if 15 - 15: i11iIiiIii / Oo0Ooo - OOooOOo . IiII
 if 11 - 11: OOooOOo / i1IIi % Oo0Ooo
 oo00oOOO00 = map_request . itr_rlocs [ 0 ]
 if ( oo00oOOO00 . is_private_address ( ) ) : oo00oOOO00 = source
 o000oo = map_request . nonce
 if 65 - 65: OOooOOo % I1ii11iIi11i
 oO0OooO0o0 = map_request . target_eid
 iII1I1i = map_request . target_group
 if 25 - 25: o0oOOo0O0Ooo - I1Ii111 * I1ii11iIi11i + OoooooooOO
 oO0O0O0O0OO = [ ]
 for Oo00O0000Ooo in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( Oo00O0000Ooo == None ) : continue
  OOOo0 = lisp_rloc ( )
  OOOo0 . rloc . copy_address ( Oo00O0000Ooo )
  OOOo0 . priority = 254
  oO0O0O0O0OO . append ( OOOo0 )
  if 86 - 86: i11iIiiIii / ooOoO0o / OOooOOo + Oo0Ooo . I1Ii111 + II111iiii
  if 4 - 4: II111iiii * I1IiiI * O0 + I1ii11iIi11i
 OoO = lisp_nonce_echoing
 O0o0O0 = map_request . keys
 if 24 - 24: iIii1I11I1II1
 if 2 - 2: iIii1I11I1II1
 if 87 - 87: I11i
 if 17 - 17: OOooOOo - Oo0Ooo + Ii1I
 if 94 - 94: OoO0O00 * OoO0O00 * II111iiii + i1IIi / i1IIi % Ii1I
 oO0oo0o0ooO = map_request . json_telemetry
 if ( oO0oo0o0ooO != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( oO0oo0o0ooO , ei = etr_in_ts )
  if 82 - 82: I11i + OoO0O00 . oO0o * I1ii11iIi11i % ooOoO0o . iIii1I11I1II1
  if 2 - 2: Ii1I + OoooooooOO . oO0o
 OO0Oo00OO0oo = lisp_build_map_reply ( oO0OooO0o0 , iII1I1i , oO0O0O0O0OO , o000oo , LISP_NO_ACTION ,
 1440 , map_request , O0o0O0 , OoO , True , ttl )
 lisp_send_map_reply ( lisp_sockets , OO0Oo00OO0oo , oo00oOOO00 , sport )
 return
 if 26 - 26: ooOoO0o - Ii1I - I1Ii111 * IiII + I1Ii111 . OoOoOO00
 if 12 - 12: OoooooooOO
 if 57 - 57: OoOoOO00 . iII111i . O0 * oO0o
 if 85 - 85: I1Ii111 * iIii1I11I1II1 . OoOoOO00
 if 20 - 20: I11i * O0 - OoooooooOO * OOooOOo % oO0o * iII111i
 if 70 - 70: I11i + O0 . i11iIiiIii . OOooOOo
 if 48 - 48: iIii1I11I1II1 * Ii1I - OoooooooOO / oO0o - OoO0O00 / i11iIiiIii
 if 24 - 24: I1IiiI
 if 63 - 63: I11i - iIii1I11I1II1 * Ii1I + OoooooooOO . i11iIiiIii
 if 94 - 94: OoO0O00 . oO0o . OoOoOO00 * i11iIiiIii
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 oO0O0O0O0OO = target_site_eid . registered_rlocs
 if 96 - 96: i1IIi . OoO0O00 . OoO0O00 - o0oOOo0O0Ooo - Ii1I
 I1IIiI = lisp_site_eid_lookup ( seid , group , False )
 if ( I1IIiI == None ) : return ( oO0O0O0O0OO )
 if 30 - 30: I1Ii111 + oO0o + iIii1I11I1II1 % OoO0O00 / I1IiiI
 if 55 - 55: Ii1I
 if 14 - 14: i1IIi * I1ii11iIi11i
 if 77 - 77: ooOoO0o . II111iiii
 iiii111i1111 = None
 I1I1II1 = [ ]
 for oO0O0oOOO0 in oO0O0O0O0OO :
  if ( oO0O0oOOO0 . is_rtr ( ) ) : continue
  if ( oO0O0oOOO0 . rloc . is_private_address ( ) ) :
   OOOO0oO0OO0oo = copy . deepcopy ( oO0O0oOOO0 )
   I1I1II1 . append ( OOOO0oO0OO0oo )
   continue
   if 45 - 45: o0oOOo0O0Ooo - IiII
  iiii111i1111 = oO0O0oOOO0
  break
  if 22 - 22: OoooooooOO . IiII - iIii1I11I1II1
 if ( iiii111i1111 == None ) : return ( oO0O0O0O0OO )
 iiii111i1111 = iiii111i1111 . rloc . print_address_no_iid ( )
 if 75 - 75: o0oOOo0O0Ooo % IiII . ooOoO0o
 if 99 - 99: OoO0O00 . OoOoOO00 / I1ii11iIi11i
 if 39 - 39: o0oOOo0O0Ooo
 if 45 - 45: ooOoO0o - I1Ii111 * iIii1I11I1II1
 I111i111iI1 = None
 for oO0O0oOOO0 in I1IIiI . registered_rlocs :
  if ( oO0O0oOOO0 . is_rtr ( ) ) : continue
  if ( oO0O0oOOO0 . rloc . is_private_address ( ) ) : continue
  I111i111iI1 = oO0O0oOOO0
  break
  if 100 - 100: i1IIi . Ii1I . o0oOOo0O0Ooo + Ii1I - i1IIi . I11i
 if ( I111i111iI1 == None ) : return ( oO0O0O0O0OO )
 I111i111iI1 = I111i111iI1 . rloc . print_address_no_iid ( )
 if 19 - 19: i11iIiiIii + I11i - IiII . iII111i * i1IIi
 if 66 - 66: ooOoO0o
 if 4 - 4: iII111i / iII111i * OOooOOo + o0oOOo0O0Ooo . I1Ii111 + II111iiii
 if 90 - 90: IiII * iII111i % OoOoOO00 . i11iIiiIii
 I1III = target_site_eid . site_id
 if ( I1III == 0 ) :
  if ( I111i111iI1 == iiii111i1111 ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( iiii111i1111 ) )
   if 5 - 5: O0 * i1IIi / IiII
   return ( I1I1II1 )
   if 4 - 4: II111iiii
  return ( oO0O0O0O0OO )
  if 60 - 60: ooOoO0o - II111iiii * OoO0O00 + oO0o - iII111i
  if 39 - 39: OoO0O00 % I1Ii111 * I11i * Ii1I
  if 84 - 84: Oo0Ooo / OoO0O00 - II111iiii - OoOoOO00 - O0
  if 18 - 18: oO0o * I11i / o0oOOo0O0Ooo - OoooooooOO
  if 21 - 21: O0 - OoooooooOO
  if 21 - 21: iII111i * o0oOOo0O0Ooo
  if 85 - 85: I1ii11iIi11i . OoOoOO00 . i1IIi % OOooOOo * I11i . I1Ii111
 if ( I1III == I1IIiI . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( I1III ) )
  return ( I1I1II1 )
  if 26 - 26: I1Ii111 + Oo0Ooo + II111iiii % OoOoOO00 % OOooOOo
 return ( oO0O0O0O0OO )
 if 40 - 40: I1ii11iIi11i + i1IIi
 if 9 - 9: OOooOOo
 if 74 - 74: OoOoOO00 - OOooOOo % OoOoOO00
 if 82 - 82: I11i % IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
 if 65 - 65: IiII / O0 * II111iiii + oO0o
 if 52 - 52: o0oOOo0O0Ooo - OoOoOO00 * II111iiii / OoooooooOO
 if 44 - 44: OOooOOo - oO0o + o0oOOo0O0Ooo - i1IIi % o0oOOo0O0Ooo
 if 79 - 79: iII111i . iIii1I11I1II1
 if 42 - 42: i11iIiiIii / IiII . O0 / OOooOOo . iII111i * i1IIi
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 Oo0iIiIii = [ ]
 oO0O0O0O0OO = [ ]
 if 29 - 29: Oo0Ooo
 if 35 - 35: OoOoOO00 + II111iiii
 if 46 - 46: O0 / I1ii11iIi11i + OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
 if 96 - 96: IiII + i1IIi - I11i * I11i - OoO0O00 % II111iiii
 if 47 - 47: I1Ii111 . i11iIiiIii + oO0o . I1ii11iIi11i
 if 12 - 12: iIii1I11I1II1 % I1Ii111 * OoOoOO00 / OoooooooOO % OoooooooOO
 OoOOo0OO = False
 Oo0oO000Oo0O = False
 for oO0O0oOOO0 in registered_rloc_set :
  if ( oO0O0oOOO0 . priority != 254 ) : continue
  Oo0oO000Oo0O |= True
  if ( oO0O0oOOO0 . rloc . is_exact_match ( mr_source ) == False ) : continue
  OoOOo0OO = True
  break
  if 86 - 86: iII111i * ooOoO0o / iIii1I11I1II1 + Ii1I . iII111i
  if 64 - 64: IiII - Oo0Ooo % iII111i % I11i
  if 42 - 42: Oo0Ooo . OoO0O00
  if 22 - 22: ooOoO0o - o0oOOo0O0Ooo + I11i / I1IiiI + OOooOOo
  if 10 - 10: oO0o / I1IiiI
  if 95 - 95: II111iiii - IiII % IiII . o0oOOo0O0Ooo
  if 19 - 19: II111iiii . ooOoO0o . I11i - OoooooooOO / I1ii11iIi11i . I1Ii111
 if ( Oo0oO000Oo0O == False ) : return ( registered_rloc_set )
 if 57 - 57: II111iiii . I1Ii111 . i11iIiiIii / OoOoOO00 - O0
 if 56 - 56: OOooOOo / I1Ii111
 if 13 - 13: oO0o + Oo0Ooo + Oo0Ooo / OoO0O00 + i1IIi + I1IiiI
 if 56 - 56: OoOoOO00
 if 10 - 10: iIii1I11I1II1 + i1IIi * Ii1I / iIii1I11I1II1 % OoOoOO00 / O0
 if 14 - 14: O0
 if 65 - 65: IiII / oO0o
 if 57 - 57: IiII + oO0o - IiII
 if 51 - 51: OoOoOO00 % IiII / iII111i - oO0o - OoO0O00 . iIii1I11I1II1
 if 61 - 61: OoO0O00
 Oo0ooo0o0oo = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 84 - 84: I11i * O0 / II111iiii . Oo0Ooo / IiII
 if 40 - 40: OoooooooOO / Ii1I
 if 81 - 81: iIii1I11I1II1 . ooOoO0o % I11i
 if 64 - 64: I1Ii111 . Oo0Ooo * o0oOOo0O0Ooo
 if 32 - 32: oO0o . I1Ii111 * I1Ii111
 for oO0O0oOOO0 in registered_rloc_set :
  if ( Oo0ooo0o0oo and oO0O0oOOO0 . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and oO0O0oOOO0 . priority == 255 ) : continue
  if ( multicast and oO0O0oOOO0 . mpriority == 255 ) : continue
  if ( oO0O0oOOO0 . priority == 254 ) :
   Oo0iIiIii . append ( oO0O0oOOO0 )
  else :
   oO0O0O0O0OO . append ( oO0O0oOOO0 )
   if 32 - 32: I1Ii111 . Ii1I / i1IIi
   if 2 - 2: OOooOOo * ooOoO0o / I11i + OoO0O00
   if 96 - 96: II111iiii * OoO0O00 + I1ii11iIi11i + OoOoOO00 / II111iiii . iII111i
   if 64 - 64: iII111i % Oo0Ooo
   if 79 - 79: IiII + iII111i / II111iiii . i1IIi + iIii1I11I1II1
   if 32 - 32: Ii1I * iII111i
 if ( OoOOo0OO ) : return ( oO0O0O0O0OO )
 if 52 - 52: I11i
 if 100 - 100: Oo0Ooo % Oo0Ooo % I1ii11iIi11i
 if 33 - 33: I1Ii111 . I1Ii111 * i1IIi
 if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
 if 13 - 13: II111iiii
 if 36 - 36: iII111i - oO0o / Oo0Ooo / O0 . OoO0O00 . i1IIi
 if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
 if 98 - 98: oO0o . Oo0Ooo
 if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
 if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
 if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
 if 64 - 64: OoooooooOO + OOooOOo
 oO0O0O0O0OO = [ ]
 for oO0O0oOOO0 in registered_rloc_set :
  if ( oO0O0oOOO0 . rloc . is_ipv6 ( ) ) : oO0O0O0O0OO . append ( oO0O0oOOO0 )
  if ( oO0O0oOOO0 . rloc . is_private_address ( ) ) : oO0O0O0O0OO . append ( oO0O0oOOO0 )
  if 36 - 36: I1IiiI - Ii1I / I1ii11iIi11i + Oo0Ooo % I1ii11iIi11i
 oO0O0O0O0OO += Oo0iIiIii
 return ( oO0O0O0O0OO )
 if 86 - 86: iIii1I11I1II1 * OoO0O00
 if 82 - 82: I1IiiI - OoO0O00 % o0oOOo0O0Ooo
 if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
 if 98 - 98: Oo0Ooo . II111iiii * I11i
 if 39 - 39: IiII * o0oOOo0O0Ooo + Ii1I - I11i
 if 70 - 70: oO0o * ooOoO0o / ooOoO0o - Ii1I * Ii1I % OOooOOo
 if 91 - 91: OoO0O00 - OoO0O00 % O0
 if 67 - 67: ooOoO0o * i1IIi
 if 66 - 66: o0oOOo0O0Ooo - I1ii11iIi11i . OoOoOO00 / iII111i - Ii1I - i1IIi
 if 97 - 97: oO0o % iII111i - OOooOOo . OoooooooOO
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 oo0ooo = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 oo0ooo . add ( reply_eid )
 return ( oo0ooo )
 if 58 - 58: I1Ii111 / iII111i / oO0o
 if 69 - 69: i11iIiiIii / O0 - OoooooooOO + I1ii11iIi11i . OoO0O00
 if 19 - 19: I1IiiI / iII111i . OOooOOo / oO0o + I1ii11iIi11i + OOooOOo
 if 1 - 1: iIii1I11I1II1
 if 59 - 59: ooOoO0o % I1IiiI + i1IIi * I1Ii111 % o0oOOo0O0Ooo * II111iiii
 if 22 - 22: OoOoOO00 * O0 + OoOoOO00 / iIii1I11I1II1 + oO0o + IiII
 if 69 - 69: iIii1I11I1II1 . I1Ii111 * iII111i
 if 6 - 6: I11i - IiII - I11i - II111iiii
 if 72 - 72: i1IIi / OOooOOo . Oo0Ooo . oO0o
 if 72 - 72: o0oOOo0O0Ooo % iIii1I11I1II1
 if 74 - 74: Oo0Ooo % OOooOOo + i11iIiiIii
 if 17 - 17: OoOoOO00 . I1IiiI
 if 30 - 30: i1IIi * OoOoOO00 * I11i . O0
 if 45 - 45: iII111i
 if 99 - 99: o0oOOo0O0Ooo % ooOoO0o % i11iIiiIii
def lisp_convert_reply_to_notify ( packet ) :
 if 32 - 32: IiII - Ii1I
 if 44 - 44: OoooooooOO . oO0o
 if 30 - 30: I1Ii111 % IiII / II111iiii
 if 68 - 68: oO0o / O0 / OOooOOo
 iIIii = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 iIIii = socket . ntohl ( iIIii ) & 0xff
 o000oo = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 93 - 93: OoOoOO00 / OoOoOO00 / OoOoOO00
 if 74 - 74: ooOoO0o % Oo0Ooo - iII111i - I1IiiI
 if 51 - 51: i11iIiiIii % OoOoOO00
 if 17 - 17: ooOoO0o - i1IIi
 iii1I = ( LISP_MAP_NOTIFY << 28 ) | iIIii
 I1IIII = struct . pack ( "I" , socket . htonl ( iii1I ) )
 o00 = struct . pack ( "I" , 0 )
 if 73 - 73: iIii1I11I1II1 - I1Ii111 % Oo0Ooo . O0
 if 16 - 16: OoO0O00 / Oo0Ooo / IiII . Oo0Ooo - OoooooooOO
 if 5 - 5: OoOoOO00 . I11i
 if 28 - 28: I11i % OOooOOo + Oo0Ooo / OoO0O00 % o0oOOo0O0Ooo + OoO0O00
 packet = I1IIII + o000oo + o00 + packet
 return ( packet )
 if 20 - 20: ooOoO0o . iII111i % OOooOOo + i11iIiiIii
 if 64 - 64: i1IIi . o0oOOo0O0Ooo * I1Ii111 - O0
 if 76 - 76: I1IiiI % Ii1I + OoO0O00 + I1ii11iIi11i * II111iiii + Oo0Ooo
 if 3 - 3: Ii1I - I1IiiI + O0
 if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
 if 45 - 45: OoooooooOO / oO0o . I1ii11iIi11i + OOooOOo
 if 54 - 54: Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
 if 61 - 61: I11i / IiII % OoooooooOO - i11iIiiIii * i1IIi % o0oOOo0O0Ooo
def lisp_notify_subscribers ( lisp_sockets , eid_record , rloc_records ,
 registered_eid , site ) :
 if 67 - 67: o0oOOo0O0Ooo - Ii1I
 for iIII1iii1 in lisp_pubsub_cache :
  for oo0ooo in list ( lisp_pubsub_cache [ iIII1iii1 ] . values ( ) ) :
   o0o00oO0oo000 = oo0ooo . eid_prefix
   if ( o0o00oO0oo000 . is_more_specific ( registered_eid ) == False ) : continue
   if 42 - 42: ooOoO0o . I1IiiI + ooOoO0o
   ooo00 = oo0ooo . itr
   O00oo0o0o0oo = oo0ooo . port
   OOoO0ooOooOoo = red ( ooo00 . print_address_no_iid ( ) , False )
   iiIi1 = bold ( "subscriber" , False )
   i1oO0o00oOo00oO = "0x" + lisp_hex_string ( oo0ooo . xtr_id )
   o000oo = "0x" + lisp_hex_string ( oo0ooo . nonce )
   if 42 - 42: O0 / II111iiii
   lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( iiIi1 , OOoO0ooOooOoo , O00oo0o0o0oo , i1oO0o00oOo00oO , green ( iIII1iii1 , False ) , o000oo ) )
   if 88 - 88: Oo0Ooo
   if 20 - 20: OoooooooOO * i1IIi * IiII / OoooooooOO - Oo0Ooo / i11iIiiIii
   if 28 - 28: iIii1I11I1II1 % OOooOOo * I1IiiI
   if 28 - 28: O0 . OoOoOO00
   if 27 - 27: I1ii11iIi11i / II111iiii + O0 % I1ii11iIi11i
   if 72 - 72: I1IiiI - i1IIi
   ii1IiiIiIIIi = copy . deepcopy ( eid_record )
   ii1IiiIiIIIi . eid . copy_address ( o0o00oO0oo000 )
   ii1IiiIiIIIi = ii1IiiIiIIIi . encode ( ) + rloc_records
   lisp_build_map_notify ( lisp_sockets , ii1IiiIiIIIi , [ iIII1iii1 ] , 1 , ooo00 ,
 O00oo0o0o0oo , oo0ooo . nonce , 0 , 0 , 0 , site , False )
   if 73 - 73: oO0o - o0oOOo0O0Ooo
   oo0ooo . map_notify_count += 1
   if 50 - 50: iIii1I11I1II1 - i11iIiiIii / iII111i + ooOoO0o / OOooOOo
   if 80 - 80: IiII / OoooooooOO
 return
 if 69 - 69: OoOoOO00 + IiII
 if 18 - 18: O0 / I11i
 if 10 - 10: I1Ii111 * i1IIi
 if 48 - 48: Oo0Ooo % i1IIi / iII111i . O0
 if 27 - 27: I11i + iIii1I11I1II1 - i11iIiiIii
 if 81 - 81: I11i + oO0o * iIii1I11I1II1 * IiII
 if 7 - 7: I11i - I1IiiI . iII111i + O0 / iIii1I11I1II1 - I1Ii111
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 32 - 32: ooOoO0o
 if 9 - 9: I1Ii111
 if 77 - 77: OoooooooOO * I1Ii111
 if 63 - 63: IiII * oO0o * iIii1I11I1II1
 oo0ooo = lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl ,
 xtr_id )
 if 18 - 18: II111iiii * o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
 oO0OooO0o0 = green ( reply_eid . print_prefix ( ) , False )
 ooo00 = red ( itr_rloc . print_address_no_iid ( ) , False )
 iI1Iiiiii = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( iI1Iiiiii ,
 oO0OooO0o0 , ooo00 , xtr_id ) )
 if 84 - 84: Oo0Ooo
 if 65 - 65: i1IIi + iII111i
 if 92 - 92: ooOoO0o
 if 58 - 58: iII111i % I11i
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 oo0ooo . map_notify_count += 1
 return
 if 71 - 71: I1IiiI + OoO0O00 + IiII * I11i
 if 61 - 61: I1IiiI / OoOoOO00
 if 58 - 58: o0oOOo0O0Ooo - Oo0Ooo % OoOoOO00 + I11i
 if 10 - 10: II111iiii / iIii1I11I1II1 % i11iIiiIii
 if 29 - 29: ooOoO0o - iII111i + IiII % Ii1I - oO0o - ooOoO0o
 if 43 - 43: oO0o
 if 22 - 22: I1Ii111 + i11iIiiIii
 if 49 - 49: O0 % II111iiii . OOooOOo + iII111i + iIii1I11I1II1 / i11iIiiIii
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 79 - 79: II111iiii + ooOoO0o - i1IIi - i1IIi + II111iiii . i1IIi
 if 78 - 78: I1IiiI * I11i % OOooOOo + Ii1I + OoOoOO00
 if 23 - 23: iII111i / Oo0Ooo % OoooooooOO * OoooooooOO . iII111i / I1ii11iIi11i
 if 30 - 30: oO0o - OoOoOO00 . I1IiiI
 if 17 - 17: OoOoOO00
 if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
 oO0OooO0o0 = map_request . target_eid
 iII1I1i = map_request . target_group
 ooOo000OoO0o = lisp_print_eid_tuple ( oO0OooO0o0 , iII1I1i )
 oo00oOOO00 = map_request . itr_rlocs [ 0 ]
 i1oO0o00oOo00oO = map_request . xtr_id
 o000oo = map_request . nonce
 Oo00Oo0o000 = LISP_NO_ACTION
 oo0ooo = map_request . subscribe_bit
 ooooooOoo = map_request . decent_nat_xtr
 if 15 - 15: IiII / OOooOOo / I11i + i1IIi
 if 95 - 95: i1IIi + II111iiii . iIii1I11I1II1 . OoooooooOO + o0oOOo0O0Ooo / iIii1I11I1II1
 if 40 - 40: OoO0O00 / O0
 if 60 - 60: iIii1I11I1II1 / Oo0Ooo / oO0o + iII111i
 if 66 - 66: iIii1I11I1II1 . O0 * IiII . ooOoO0o + i1IIi
 OOOoo0OO0O0 = True
 iii1iiI1 = ( lisp_get_eid_hash ( oO0OooO0o0 ) != None )
 if ( iii1iiI1 ) :
  IIIIi1iII = map_request . map_request_signature
  if ( IIIIi1iII == None ) :
   OOOoo0OO0O0 = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 73 - 73: Ii1I * IiII + I1IiiI
  else :
   iIII = map_request . signature_eid
   ooOoo0 , iiI1i1iIIIii , OOOoo0OO0O0 = lisp_lookup_public_key ( iIII )
   if ( OOOoo0OO0O0 ) :
    OOOoo0OO0O0 = map_request . verify_map_request_sig ( iiI1i1iIIIii )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( iIII . print_address ( ) , ooOoo0 . print_address ( ) ) )
    if 62 - 62: i1IIi / IiII - OOooOOo / I1IiiI * OOooOOo
    if 32 - 32: i11iIiiIii . i11iIiiIii + Ii1I . OoO0O00 . I11i
   Ii1Ii11Ii1 = bold ( "passed" , False ) if OOOoo0OO0O0 else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( Ii1Ii11Ii1 ) )
   if 74 - 74: OOooOOo . iII111i
   if 58 - 58: II111iiii / OoO0O00
   if 33 - 33: OoooooooOO / i1IIi . Ii1I
 if ( oo0ooo and OOOoo0OO0O0 == False ) :
  oo0ooo = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 96 - 96: OoOoOO00 / Oo0Ooo . II111iiii / ooOoO0o
  if 56 - 56: IiII - ooOoO0o % oO0o / Oo0Ooo * oO0o % O0
  if 71 - 71: iII111i / II111iiii - II111iiii / I1IiiI
  if 24 - 24: O0 . I1IiiI + IiII . IiII
  if 53 - 53: II111iiii + Ii1I * o0oOOo0O0Ooo
  if 47 - 47: Ii1I % OOooOOo . Oo0Ooo
  if 94 - 94: Ii1I - iIii1I11I1II1 + I1IiiI - iIii1I11I1II1 . o0oOOo0O0Ooo
  if 3 - 3: O0 / I11i + OoOoOO00 % IiII / i11iIiiIii
  if 25 - 25: II111iiii / I1ii11iIi11i % iIii1I11I1II1
  if 69 - 69: IiII
  if 36 - 36: I1IiiI / oO0o
  if 72 - 72: i1IIi - I1ii11iIi11i . OOooOOo + I1Ii111 - ooOoO0o
  if 69 - 69: o0oOOo0O0Ooo * I1IiiI - I11i
  if 11 - 11: OOooOOo * O0
 Iiii1iiI = oo00oOOO00 if ( oo00oOOO00 . afi == ecm_source . afi ) else ecm_source
 if 35 - 35: OOooOOo / I1Ii111 . I1ii11iIi11i / OoooooooOO + I1Ii111 . I1Ii111
 ooo0OOO00 = lisp_site_eid_lookup ( oO0OooO0o0 , iII1I1i , False )
 if 56 - 56: I1ii11iIi11i * o0oOOo0O0Ooo - iII111i - ooOoO0o - I11i
 if ( ooo0OOO00 == None or ooo0OOO00 . is_star_g ( ) ) :
  iIIi = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( iIIi ,
 green ( ooOo000OoO0o , False ) ) )
  if 71 - 71: ooOoO0o * I1IiiI / I1ii11iIi11i
  if 8 - 8: I1Ii111 / iIii1I11I1II1
  if 29 - 29: i11iIiiIii % i1IIi + oO0o . I1ii11iIi11i
  if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
  lisp_send_negative_map_reply ( lisp_sockets , oO0OooO0o0 , iII1I1i , o000oo , oo00oOOO00 ,
 mr_sport , 15 , i1oO0o00oOo00oO , oo0ooo )
  if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
  return ( [ oO0OooO0o0 , iII1I1i , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
  if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
 o0oOOOooOOoo = ooo0OOO00 . print_eid_tuple ( )
 O0O0o = ooo0OOO00 . site . site_name
 if 69 - 69: OoO0O00 + iIii1I11I1II1
 if 52 - 52: i1IIi . i11iIiiIii * IiII * I11i % I1IiiI
 if 67 - 67: O0 . I1Ii111 + ooOoO0o
 if 88 - 88: I1Ii111 . O0 - oO0o + i1IIi % Oo0Ooo
 if 39 - 39: I1Ii111 - I1IiiI
 if ( iii1iiI1 == False and ooo0OOO00 . require_signature ) :
  IIIIi1iII = map_request . map_request_signature
  iIII = map_request . signature_eid
  if ( IIIIi1iII == None or iIII . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( O0O0o ) )
   OOOoo0OO0O0 = False
  else :
   iIII = map_request . signature_eid
   ooOoo0 , iiI1i1iIIIii , OOOoo0OO0O0 = lisp_lookup_public_key ( iIII )
   if ( OOOoo0OO0O0 ) :
    OOOoo0OO0O0 = map_request . verify_map_request_sig ( iiI1i1iIIIii )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( iIII . print_address ( ) , ooOoo0 . print_address ( ) ) )
    if 18 - 18: i1IIi
    if 42 - 42: II111iiii - i1IIi . oO0o % OOooOOo % ooOoO0o - i11iIiiIii
   Ii1Ii11Ii1 = bold ( "passed" , False ) if OOOoo0OO0O0 else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( Ii1Ii11Ii1 ) )
   if 23 - 23: OOooOOo + iIii1I11I1II1 - i1IIi
   if 72 - 72: OOooOOo . I1IiiI * O0 + i11iIiiIii - iII111i
   if 79 - 79: o0oOOo0O0Ooo + I1ii11iIi11i
   if 46 - 46: I11i
   if 78 - 78: IiII / II111iiii
   if 55 - 55: Oo0Ooo
 if ( OOOoo0OO0O0 and ooo0OOO00 . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( O0O0o , green ( o0oOOOooOOoo , False ) , green ( ooOo000OoO0o , False ) ) )
  if 80 - 80: o0oOOo0O0Ooo - I1Ii111 * O0 * iIii1I11I1II1
  if 59 - 59: I1ii11iIi11i + I11i / OoO0O00
  if 36 - 36: o0oOOo0O0Ooo + ooOoO0o * I11i
  if 81 - 81: OOooOOo * I11i - I1ii11iIi11i
  if 82 - 82: I1ii11iIi11i * II111iiii - OoooooooOO % iII111i * I1IiiI % OoOoOO00
  if 81 - 81: I11i + o0oOOo0O0Ooo / iII111i
  if ( ooo0OOO00 . accept_more_specifics == False ) :
   oO0OooO0o0 = ooo0OOO00 . eid
   iII1I1i = ooo0OOO00 . group
   if 35 - 35: ooOoO0o % I11i * I1ii11iIi11i
   if 10 - 10: OoO0O00 + OoooooooOO + I1Ii111
   if 57 - 57: Ii1I % Ii1I * Oo0Ooo % i11iIiiIii
   if 12 - 12: oO0o . Oo0Ooo . I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
   if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
  OO0ooo00o = 1
  if ( ooo0OOO00 . force_ttl != None ) :
   OO0ooo00o = ooo0OOO00 . force_ttl | 0x80000000
   if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
  I1IIiII1 = ( ooo0OOO00 . proxy_reply_action == "not-registered-yet" )
  if 35 - 35: iII111i / iII111i * OoOoOO00 - i11iIiiIii
  if 27 - 27: i1IIi / I11i + I1Ii111 . II111iiii * OoO0O00
  if 55 - 55: i1IIi % Ii1I - o0oOOo0O0Ooo - o0oOOo0O0Ooo
  if 6 - 6: i1IIi
  lisp_send_negative_map_reply ( lisp_sockets , oO0OooO0o0 , iII1I1i , o000oo , oo00oOOO00 ,
 mr_sport , OO0ooo00o , i1oO0o00oOo00oO , oo0ooo , not_reg_yet = I1IIiII1 )
  if 10 - 10: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / i11iIiiIii - I1IiiI . O0
  return ( [ oO0OooO0o0 , iII1I1i , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 2 - 2: II111iiii
  if 13 - 13: Ii1I % i11iIiiIii
  if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
  if 50 - 50: I1ii11iIi11i + iII111i
  if 64 - 64: oO0o
 i1Iiii1I = False
 II1Iii1Ii = ""
 iIiIiiII1I = False
 if ( ooo0OOO00 . force_nat_proxy_reply ) :
  II1Iii1Ii = ", nat-forced"
  i1Iiii1I = ( ooooooOoo == False )
  iIiIiiII1I = True
 elif ( ooo0OOO00 . force_proxy_reply ) :
  II1Iii1Ii = ", forced"
  iIiIiiII1I = True
 elif ( ooo0OOO00 . proxy_reply_requested ) :
  II1Iii1Ii = ", requested"
  iIiIiiII1I = True
 elif ( map_request . pitr_bit and ooo0OOO00 . pitr_proxy_reply_drop ) :
  II1Iii1Ii = ", drop-to-pitr"
  Oo00Oo0o000 = LISP_DROP_ACTION
 elif ( ooo0OOO00 . proxy_reply_action != "" ) :
  Oo00Oo0o000 = ooo0OOO00 . proxy_reply_action
  II1Iii1Ii = ", forced, action {}" . format ( Oo00Oo0o000 )
  Oo00Oo0o000 = LISP_DROP_ACTION if ( Oo00Oo0o000 == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 73 - 73: i1IIi % o0oOOo0O0Ooo
  if 45 - 45: IiII + oO0o . iII111i
  if 85 - 85: IiII * IiII * iII111i % i11iIiiIii
  if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
  if 10 - 10: OOooOOo / I1ii11iIi11i
  if 21 - 21: OoO0O00 % Oo0Ooo . o0oOOo0O0Ooo + IiII
  if 48 - 48: O0 / i1IIi / iII111i
 IiII1II1OO00oo00 = False
 iIooOOOOOOoO = None
 if ( iIiIiiII1I and ooo0OOO00 . policy in lisp_policies ) :
  o00oo = lisp_policies [ ooo0OOO00 . policy ]
  if ( o00oo . match_policy_map_request ( map_request , mr_source ) ) : iIooOOOOOOoO = o00oo
  if 67 - 67: Ii1I / OoOoOO00
  if ( iIooOOOOOOoO ) :
   iiI = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( iiI ,
 o00oo . policy_name , o00oo . set_action ) )
  else :
   iiI = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( iiI ,
 o00oo . policy_name ) )
   IiII1II1OO00oo00 = True
   if 19 - 19: OoO0O00 - OOooOOo * O0
   if 75 - 75: Ii1I + Oo0Ooo
   if 72 - 72: iII111i / o0oOOo0O0Ooo % I1IiiI * OOooOOo % I1ii11iIi11i * i11iIiiIii
 if ( II1Iii1Ii != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( ooOo000OoO0o , False ) , O0O0o , green ( o0oOOOooOOoo , False ) ,
  # o0oOOo0O0Ooo
 II1Iii1Ii ) )
  if 95 - 95: iIii1I11I1II1 . OoOoOO00 % i1IIi / O0 * OoOoOO00
  oO0O0O0O0OO = ooo0OOO00 . registered_rlocs
  OO0ooo00o = 1440
  if ( i1Iiii1I ) :
   if ( ooo0OOO00 . site_id != 0 ) :
    iIiI11iIi111i = map_request . source_eid
    oO0O0O0O0OO = lisp_get_private_rloc_set ( ooo0OOO00 , iIiI11iIi111i , iII1I1i )
    if 44 - 44: OoOoOO00 / OoO0O00 - oO0o / IiII % Oo0Ooo
   if ( oO0O0O0O0OO == ooo0OOO00 . registered_rlocs ) :
    OOoO0o0OOo0 = ( ooo0OOO00 . group . is_null ( ) == False )
    I1I1II1 = lisp_get_partial_rloc_set ( oO0O0O0O0OO , Iiii1iiI , OOoO0o0OOo0 )
    if ( I1I1II1 != oO0O0O0O0OO ) :
     OO0ooo00o = 15
     oO0O0O0O0OO = I1I1II1
     if 34 - 34: ooOoO0o - OoooooooOO . o0oOOo0O0Ooo
     if 83 - 83: II111iiii . OOooOOo
     if 88 - 88: O0
     if 12 - 12: Ii1I % OOooOOo % Oo0Ooo * I1Ii111
     if 96 - 96: iII111i + ooOoO0o
     if 100 - 100: OOooOOo . ooOoO0o + Ii1I + Ii1I
     if 70 - 70: ooOoO0o . iIii1I11I1II1 / oO0o
     if 18 - 18: Ii1I / OoooooooOO % i1IIi * o0oOOo0O0Ooo
  if ( ooo0OOO00 . force_ttl != None ) :
   OO0ooo00o = ooo0OOO00 . force_ttl | 0x80000000
   if 70 - 70: IiII % i1IIi / IiII - o0oOOo0O0Ooo . Oo0Ooo / O0
   if 54 - 54: o0oOOo0O0Ooo
   if 53 - 53: II111iiii / IiII . i1IIi + I1Ii111 / OoO0O00 - OoooooooOO
   if 67 - 67: ooOoO0o . Ii1I - Oo0Ooo * iII111i . I11i - OOooOOo
   if 10 - 10: I11i
   if 37 - 37: o0oOOo0O0Ooo / I1IiiI * oO0o / II111iiii
  if ( iIooOOOOOOoO ) :
   if ( iIooOOOOOOoO . set_record_ttl ) :
    OO0ooo00o = iIooOOOOOOoO . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( OO0ooo00o ) )
    if 39 - 39: IiII - i1IIi - IiII - OoooooooOO - I1ii11iIi11i
   if ( iIooOOOOOOoO . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    Oo00Oo0o000 = LISP_POLICY_DENIED_ACTION
    oO0O0O0O0OO = [ ]
   else :
    OOOo0 = iIooOOOOOOoO . set_policy_map_reply ( )
    if ( OOOo0 ) : oO0O0O0O0OO = [ OOOo0 ]
    if 66 - 66: IiII + i1IIi
    if 21 - 21: IiII / i11iIiiIii / OoOoOO00
    if 75 - 75: Ii1I . i1IIi / I1IiiI * iII111i . IiII / OoOoOO00
  if ( IiII1II1OO00oo00 ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   Oo00Oo0o000 = LISP_POLICY_DENIED_ACTION
   oO0O0O0O0OO = [ ]
   if 58 - 58: ooOoO0o + OOooOOo / ooOoO0o / i11iIiiIii
   if 95 - 95: ooOoO0o
  OoO = ooo0OOO00 . echo_nonce_capable
  if 10 - 10: OoO0O00 % ooOoO0o * o0oOOo0O0Ooo
  if 37 - 37: Ii1I . o0oOOo0O0Ooo
  if 34 - 34: ooOoO0o * IiII . Ii1I + iIii1I11I1II1
  if 1 - 1: i11iIiiIii + I11i
  if ( OOOoo0OO0O0 ) :
   O0oOoOoooO = ooo0OOO00 . eid
   I111iiiiI = ooo0OOO00 . group
  else :
   O0oOoOoooO = oO0OooO0o0
   I111iiiiI = iII1I1i
   Oo00Oo0o000 = LISP_AUTH_FAILURE_ACTION
   oO0O0O0O0OO = [ ]
   if 50 - 50: OoOoOO00 / iII111i * O0 . I1IiiI
   if 88 - 88: IiII / I1ii11iIi11i % I11i + i11iIiiIii * O0 . I1Ii111
   if 69 - 69: Oo0Ooo - OOooOOo / I1IiiI . i11iIiiIii * OoO0O00
   if 45 - 45: I1Ii111 + OOooOOo
   if 78 - 78: OoOoOO00 . Oo0Ooo % I11i
   if 7 - 7: I1ii11iIi11i % Ii1I . OoooooooOO - iII111i
  if ( oo0ooo ) :
   O0oOoOoooO = oO0OooO0o0
   I111iiiiI = iII1I1i
   if 18 - 18: O0 * OoooooooOO % IiII - iIii1I11I1II1 % IiII * o0oOOo0O0Ooo
   if 13 - 13: OoO0O00 + i11iIiiIii + O0 / ooOoO0o % iIii1I11I1II1
   if 75 - 75: oO0o / i1IIi / Ii1I * Oo0Ooo
   if 75 - 75: Oo0Ooo / OoooooooOO
   if 98 - 98: II111iiii - I1Ii111 . ooOoO0o * iII111i
   if 49 - 49: I1ii11iIi11i / OoooooooOO - I11i
  packet = lisp_build_map_reply ( O0oOoOoooO , I111iiiiI , oO0O0O0O0OO ,
 o000oo , Oo00Oo0o000 , OO0ooo00o , map_request , None , OoO , False )
  if 76 - 76: i1IIi . OoO0O00 . O0 / OOooOOo - iII111i
  if ( oo0ooo ) :
   lisp_process_pubsub ( lisp_sockets , packet , O0oOoOoooO , oo00oOOO00 ,
 mr_sport , o000oo , OO0ooo00o , i1oO0o00oOo00oO )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , oo00oOOO00 , mr_sport )
   if 60 - 60: I1IiiI
   if 3 - 3: II111iiii % IiII % I1IiiI - I1IiiI . I1Ii111 - OoOoOO00
  return ( [ ooo0OOO00 . eid , ooo0OOO00 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 18 - 18: O0
  if 26 - 26: i1IIi - iIii1I11I1II1
  if 8 - 8: I1Ii111
  if 86 - 86: i1IIi
  if 26 - 26: o0oOOo0O0Ooo % I1Ii111 / Oo0Ooo
 OO0oIiiI1iIii = len ( ooo0OOO00 . registered_rlocs )
 if ( OO0oIiiI1iIii == 0 ) :
  lprint ( ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" ) . format ( green ( ooOo000OoO0o , False ) , O0O0o ,
  # i1IIi + II111iiii / Oo0Ooo + iIii1I11I1II1 . Oo0Ooo
 green ( o0oOOOooOOoo , False ) ) )
  return ( [ ooo0OOO00 . eid , ooo0OOO00 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 73 - 73: Ii1I * iIii1I11I1II1 / o0oOOo0O0Ooo - o0oOOo0O0Ooo / i1IIi
  if 64 - 64: Ii1I * I1ii11iIi11i % II111iiii
  if 31 - 31: iIii1I11I1II1 % Oo0Ooo . I1IiiI % ooOoO0o
  if 38 - 38: I1ii11iIi11i + I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
  if 46 - 46: iII111i
 oOoO = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 88 - 88: i1IIi % oO0o / i1IIi * Oo0Ooo
 I111i = map_request . target_eid . hash_address ( oOoO )
 I111i %= OO0oIiiI1iIii
 OOOOo0 = ooo0OOO00 . registered_rlocs [ I111i ]
 if 84 - 84: IiII / II111iiii . OoOoOO00 % OoOoOO00 % I11i / i1IIi
 if ( OOOOo0 . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( ooOo000OoO0o , False ) ,
  # OoOoOO00 + I1ii11iIi11i / I1ii11iIi11i - o0oOOo0O0Ooo + Oo0Ooo - Ii1I
 O0O0o , green ( o0oOOOooOOoo , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( ooOo000OoO0o , False ) ,
  # OoOoOO00 + oO0o + I1Ii111 . Ii1I - I1IiiI / i1IIi
 red ( OOOOo0 . rloc . print_address ( ) , False ) , O0O0o ,
 green ( o0oOOOooOOoo , False ) ) )
  if 90 - 90: I1ii11iIi11i * o0oOOo0O0Ooo * II111iiii % iIii1I11I1II1
  if 68 - 68: oO0o / i1IIi / I11i + iIii1I11I1II1 . OOooOOo % o0oOOo0O0Ooo
  if 67 - 67: OoO0O00 % I1ii11iIi11i * o0oOOo0O0Ooo + OoO0O00 / I1IiiI
  if 8 - 8: o0oOOo0O0Ooo
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , OOOOo0 . rloc , to_etr = True )
  if 34 - 34: OoO0O00 * iIii1I11I1II1 * I1IiiI . OoooooooOO + I1ii11iIi11i % iIii1I11I1II1
 return ( [ ooo0OOO00 . eid , ooo0OOO00 . group , LISP_DDT_ACTION_MS_ACK ] )
 if 78 - 78: OoOoOO00 . oO0o - Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
 if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
 if 72 - 72: Ii1I
 if 22 - 22: o0oOOo0O0Ooo / OoO0O00 + OoOoOO00 + Ii1I . II111iiii * I11i
 if 85 - 85: i11iIiiIii / I11i
 if 28 - 28: i11iIiiIii + IiII / I11i . Ii1I / OoO0O00
 if 100 - 100: o0oOOo0O0Ooo - I11i . o0oOOo0O0Ooo
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 90 - 90: OoOoOO00 / II111iiii / I11i * I11i - iIii1I11I1II1
 if 87 - 87: IiII
 if 92 - 92: OoO0O00 / IiII - ooOoO0o
 if 45 - 45: iII111i - I11i * ooOoO0o * OOooOOo / I1Ii111 * iII111i
 oO0OooO0o0 = map_request . target_eid
 iII1I1i = map_request . target_group
 ooOo000OoO0o = lisp_print_eid_tuple ( oO0OooO0o0 , iII1I1i )
 o000oo = map_request . nonce
 Oo00Oo0o000 = LISP_DDT_ACTION_NULL
 if 33 - 33: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo % iIii1I11I1II1 + I11i / i11iIiiIii
 if 64 - 64: I11i * ooOoO0o / OoooooooOO
 if 38 - 38: iIii1I11I1II1 . OoO0O00 * OoOoOO00 + OoOoOO00 + ooOoO0o
 if 44 - 44: I1ii11iIi11i * OOooOOo % OoO0O00 . I1IiiI % Ii1I + II111iiii
 if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
 oOo00OoOoo = None
 if ( lisp_i_am_ms ) :
  ooo0OOO00 = lisp_site_eid_lookup ( oO0OooO0o0 , iII1I1i , False )
  if ( ooo0OOO00 == None ) : return
  if 65 - 65: I1IiiI - OoO0O00 / iIii1I11I1II1 * iII111i + OoOoOO00 + IiII
  if ( ooo0OOO00 . registered ) :
   Oo00Oo0o000 = LISP_DDT_ACTION_MS_ACK
   OO0ooo00o = 1440
  else :
   oO0OooO0o0 , iII1I1i , Oo00Oo0o000 = lisp_ms_compute_neg_prefix ( oO0OooO0o0 , iII1I1i )
   Oo00Oo0o000 = LISP_DDT_ACTION_MS_NOT_REG
   OO0ooo00o = 1
   if 16 - 16: OoO0O00 % OOooOOo . I11i . I11i
 else :
  oOo00OoOoo = lisp_ddt_cache_lookup ( oO0OooO0o0 , iII1I1i , False )
  if ( oOo00OoOoo == None ) :
   Oo00Oo0o000 = LISP_DDT_ACTION_NOT_AUTH
   OO0ooo00o = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( ooOo000OoO0o , False ) ) )
   if 4 - 4: O0 + I11i / OoOoOO00 * iIii1I11I1II1 . Ii1I
  elif ( oOo00OoOoo . is_auth_prefix ( ) ) :
   if 68 - 68: Oo0Ooo % ooOoO0o + i11iIiiIii / oO0o / II111iiii
   if 63 - 63: OoO0O00 % i1IIi - OoooooooOO / ooOoO0o
   if 75 - 75: OOooOOo + IiII + ooOoO0o / I1IiiI . iIii1I11I1II1 / Oo0Ooo
   if 81 - 81: I1Ii111 % II111iiii - Oo0Ooo / I1IiiI + i11iIiiIii . I11i
   Oo00Oo0o000 = LISP_DDT_ACTION_DELEGATION_HOLE
   OO0ooo00o = 15
   O0II = oOo00OoOoo . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( O0II ,
   # II111iiii % OoooooooOO . I1Ii111
 green ( ooOo000OoO0o , False ) ) )
   if 59 - 59: o0oOOo0O0Ooo * OoooooooOO + I1ii11iIi11i * IiII - OoO0O00 / i11iIiiIii
   if ( iII1I1i . is_null ( ) ) :
    oO0OooO0o0 = lisp_ddt_compute_neg_prefix ( oO0OooO0o0 , oOo00OoOoo ,
 lisp_ddt_cache )
   else :
    iII1I1i = lisp_ddt_compute_neg_prefix ( iII1I1i , oOo00OoOoo ,
 lisp_ddt_cache )
    oO0OooO0o0 = lisp_ddt_compute_neg_prefix ( oO0OooO0o0 , oOo00OoOoo ,
 oOo00OoOoo . source_cache )
    if 65 - 65: Oo0Ooo + Ii1I + I1ii11iIi11i
   oOo00OoOoo = None
  else :
   O0II = oOo00OoOoo . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( O0II , green ( ooOo000OoO0o , False ) ) )
   if 76 - 76: IiII + IiII / I1IiiI / ooOoO0o . OoOoOO00
   OO0ooo00o = 1440
   if 20 - 20: IiII / i11iIiiIii - ooOoO0o . OoooooooOO + OoooooooOO
   if 27 - 27: OOooOOo + iIii1I11I1II1 . I1Ii111 % i1IIi % iII111i
   if 13 - 13: IiII / I11i + ooOoO0o - II111iiii . OOooOOo
   if 17 - 17: I1ii11iIi11i . Ii1I / IiII - i1IIi - Ii1I
   if 95 - 95: IiII % I11i % iIii1I11I1II1 . OoO0O00
   if 11 - 11: i11iIiiIii - IiII . o0oOOo0O0Ooo / IiII - I1IiiI
 OO0Oo00OO0oo = lisp_build_map_referral ( oO0OooO0o0 , iII1I1i , oOo00OoOoo , Oo00Oo0o000 , OO0ooo00o , o000oo )
 o000oo = map_request . nonce >> 32
 if ( map_request . nonce != 0 and o000oo != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , OO0Oo00OO0oo , ecm_source , port )
 return
 if 66 - 66: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i * OOooOOo % IiII
 if 34 - 34: I1IiiI % I11i - iII111i - i11iIiiIii - iIii1I11I1II1 / i1IIi
 if 7 - 7: I1IiiI + iIii1I11I1II1 . oO0o
 if 17 - 17: OoO0O00 / OoO0O00 + o0oOOo0O0Ooo / OOooOOo . I1ii11iIi11i % IiII
 if 40 - 40: OoOoOO00
 if 81 - 81: Ii1I % I1Ii111 / I1ii11iIi11i % iII111i
 if 39 - 39: i1IIi . iII111i . Oo0Ooo % Oo0Ooo * IiII % Ii1I
 if 40 - 40: o0oOOo0O0Ooo * i11iIiiIii . ooOoO0o
 if 63 - 63: I1Ii111 / Ii1I - iIii1I11I1II1 / i11iIiiIii / IiII + I11i
 if 57 - 57: iIii1I11I1II1 % iIii1I11I1II1
 if 23 - 23: II111iiii . ooOoO0o % I1Ii111
 if 39 - 39: OoooooooOO
 if 10 - 10: Oo0Ooo * iII111i
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 oOOoo = eid . hash_address ( entry_prefix )
 O0OOO = eid . addr_length ( ) * 8
 i111iii1i1 = 0
 if 93 - 93: OoOoOO00 % I1ii11iIi11i - iIii1I11I1II1 * OoO0O00 / Oo0Ooo + OoooooooOO
 if 38 - 38: iIii1I11I1II1 + OOooOOo + OoO0O00 . iII111i / i1IIi + II111iiii
 if 54 - 54: Ii1I - I1IiiI + iII111i * iII111i
 if 78 - 78: I1Ii111
 for i111iii1i1 in range ( O0OOO ) :
  O0o0O0ooo0o0 = 1 << ( O0OOO - i111iii1i1 - 1 )
  if ( oOOoo & O0o0O0ooo0o0 ) : break
  if 67 - 67: i1IIi / i1IIi + IiII . oO0o
  if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
 if ( i111iii1i1 > neg_prefix . mask_len ) : neg_prefix . mask_len = i111iii1i1
 return
 if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
 if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
 if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
 if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
 if 45 - 45: iIii1I11I1II1 . o0oOOo0O0Ooo % I1IiiI
 if 10 - 10: I1IiiI / i1IIi * o0oOOo0O0Ooo + Oo0Ooo - OoOoOO00 % iII111i
 if 88 - 88: Ii1I % Ii1I
 if 29 - 29: OOooOOo % I1ii11iIi11i
 if 57 - 57: I1ii11iIi11i - OoOoOO00 + IiII
 if 58 - 58: OOooOOo % I1IiiI / oO0o . ooOoO0o . OoO0O00 / IiII
def lisp_neg_prefix_walk ( entry , parms ) :
 oO0OooO0o0 , O0O0OO0 , OO00ooOO = parms
 if 30 - 30: I1ii11iIi11i * O0 % I1IiiI % OoO0O00
 if ( O0O0OO0 == None ) :
  if ( entry . eid . instance_id != oO0OooO0o0 . instance_id ) :
   return ( [ True , parms ] )
   if 23 - 23: O0 * OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1
  if ( entry . eid . afi != oO0OooO0o0 . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( O0O0OO0 ) == False ) :
   return ( [ True , parms ] )
   if 68 - 68: Oo0Ooo % II111iiii % I1Ii111 * IiII
   if 68 - 68: I1ii11iIi11i % iII111i - i11iIiiIii % I1ii11iIi11i
   if 65 - 65: i11iIiiIii
   if 75 - 75: OOooOOo % I1ii11iIi11i
   if 40 - 40: I1IiiI / I1IiiI
   if 26 - 26: i11iIiiIii % OoO0O00 % Ii1I - ooOoO0o
 lisp_find_negative_mask_len ( oO0OooO0o0 , entry . eid , OO00ooOO )
 return ( [ True , parms ] )
 if 2 - 2: II111iiii . o0oOOo0O0Ooo * OoooooooOO + OoooooooOO
 if 18 - 18: II111iiii * OOooOOo * OoO0O00 * iIii1I11I1II1 % o0oOOo0O0Ooo / IiII
 if 95 - 95: I1ii11iIi11i + I1IiiI . OoooooooOO
 if 22 - 22: I1Ii111 / I1Ii111 / OOooOOo + OoOoOO00 % I1Ii111 / Ii1I
 if 14 - 14: o0oOOo0O0Ooo % i11iIiiIii + i11iIiiIii - I1ii11iIi11i % I1ii11iIi11i
 if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
 if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
 if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 77 - 77: OOooOOo + ooOoO0o / O0
 if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
 if 49 - 49: ooOoO0o . Ii1I
 if 75 - 75: OOooOOo / II111iiii - Oo0Ooo + I1Ii111
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 42 - 42: OoooooooOO * II111iiii + Ii1I % OoO0O00 / I1Ii111
 OO00ooOO = lisp_address ( eid . afi , "" , 0 , 0 )
 OO00ooOO . copy_address ( eid )
 OO00ooOO . mask_len = 0
 if 11 - 11: ooOoO0o / Oo0Ooo + i1IIi / IiII
 i1I1iiIii = ddt_entry . print_eid_tuple ( )
 O0O0OO0 = ddt_entry . eid
 if 93 - 93: OOooOOo . O0 + IiII - iII111i * iII111i
 if 6 - 6: iIii1I11I1II1 * i1IIi
 if 66 - 66: OoooooooOO * I11i * ooOoO0o % oO0o - Oo0Ooo
 if 17 - 17: Ii1I * I1ii11iIi11i - OoO0O00 - O0 + o0oOOo0O0Ooo + I1ii11iIi11i
 if 78 - 78: OOooOOo * Oo0Ooo * Ii1I
 eid , O0O0OO0 , OO00ooOO = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , O0O0OO0 , OO00ooOO ) )
 if 94 - 94: OoooooooOO % iII111i
 if 48 - 48: iIii1I11I1II1
 if 25 - 25: i1IIi % o0oOOo0O0Ooo . iII111i / OoooooooOO + i1IIi
 if 76 - 76: Oo0Ooo / OOooOOo + ooOoO0o % OoooooooOO - Oo0Ooo - I11i
 OO00ooOO . mask_address ( OO00ooOO . mask_len )
 if 36 - 36: OoO0O00 . Oo0Ooo * I1ii11iIi11i
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # i1IIi
 i1I1iiIii , OO00ooOO . print_prefix ( ) ) )
 return ( OO00ooOO )
 if 37 - 37: I1IiiI % i11iIiiIii + OoO0O00 * OOooOOo . o0oOOo0O0Ooo % IiII
 if 18 - 18: Oo0Ooo % IiII . OoOoOO00 - IiII + I1Ii111 + oO0o
 if 31 - 31: OOooOOo + OoOoOO00 * OOooOOo + OoOoOO00 / o0oOOo0O0Ooo . iIii1I11I1II1
 if 1 - 1: I1Ii111 * i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / Oo0Ooo
 if 3 - 3: OOooOOo - i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
 if 60 - 60: OoOoOO00 / i1IIi . Ii1I - OoO0O00 - OoooooooOO
 if 39 - 39: I1IiiI + i1IIi * OoO0O00 % I11i
 if 41 - 41: I1ii11iIi11i * IiII
def lisp_ms_compute_neg_prefix ( eid , group ) :
 OO00ooOO = lisp_address ( eid . afi , "" , 0 , 0 )
 OO00ooOO . copy_address ( eid )
 OO00ooOO . mask_len = 0
 I1ii1IiIi1 = lisp_address ( group . afi , "" , 0 , 0 )
 I1ii1IiIi1 . copy_address ( group )
 I1ii1IiIi1 . mask_len = 0
 O0O0OO0 = None
 if 50 - 50: I1IiiI / OoooooooOO
 if 61 - 61: I1Ii111
 if 1 - 1: i11iIiiIii % I1Ii111 + I1ii11iIi11i
 if 17 - 17: Oo0Ooo
 if 59 - 59: OoO0O00 * o0oOOo0O0Ooo . I11i
 if ( group . is_null ( ) ) :
  oOo00OoOoo = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( oOo00OoOoo == None ) :
   OO00ooOO . mask_len = OO00ooOO . host_mask_len ( )
   I1ii1IiIi1 . mask_len = I1ii1IiIi1 . host_mask_len ( )
   return ( [ OO00ooOO , I1ii1IiIi1 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 32 - 32: I1ii11iIi11i
  iiIiIIIIi11II = lisp_sites_by_eid
  if ( oOo00OoOoo . is_auth_prefix ( ) ) : O0O0OO0 = oOo00OoOoo . eid
 else :
  oOo00OoOoo = lisp_ddt_cache . lookup_cache ( group , False )
  if ( oOo00OoOoo == None ) :
   OO00ooOO . mask_len = OO00ooOO . host_mask_len ( )
   I1ii1IiIi1 . mask_len = I1ii1IiIi1 . host_mask_len ( )
   return ( [ OO00ooOO , I1ii1IiIi1 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 37 - 37: iIii1I11I1II1
  if ( oOo00OoOoo . is_auth_prefix ( ) ) : O0O0OO0 = oOo00OoOoo . group
  if 64 - 64: II111iiii * oO0o % I1Ii111 + i1IIi
  group , O0O0OO0 , I1ii1IiIi1 = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , O0O0OO0 , I1ii1IiIi1 ) )
  if 57 - 57: OoOoOO00 + OoOoOO00
  if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
  I1ii1IiIi1 . mask_address ( I1ii1IiIi1 . mask_len )
  if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , O0O0OO0 . print_prefix ( ) if ( O0O0OO0 != None ) else "'not found'" ,
  # I11i / i11iIiiIii % I1Ii111 % i11iIiiIii / I11i / OoO0O00
  # II111iiii - I1ii11iIi11i / I1ii11iIi11i
  # II111iiii * iIii1I11I1II1
 I1ii1IiIi1 . print_prefix ( ) ) )
  if 66 - 66: iIii1I11I1II1 . i1IIi - O0 * OoO0O00 * Oo0Ooo / Ii1I
  iiIiIIIIi11II = oOo00OoOoo . source_cache
  if 88 - 88: I1IiiI * I1ii11iIi11i * o0oOOo0O0Ooo
  if 58 - 58: OoooooooOO . I1ii11iIi11i % o0oOOo0O0Ooo * Ii1I - OoOoOO00 / OOooOOo
  if 56 - 56: ooOoO0o % I1Ii111 + I1ii11iIi11i / i1IIi + oO0o
  if 52 - 52: Oo0Ooo + i11iIiiIii
  if 50 - 50: iII111i + ooOoO0o * Ii1I % OOooOOo
 Oo00Oo0o000 = LISP_DDT_ACTION_DELEGATION_HOLE if ( O0O0OO0 != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 30 - 30: OoO0O00 - Oo0Ooo . IiII * ooOoO0o % OOooOOo % i11iIiiIii
 if 45 - 45: I1Ii111 / OoO0O00
 if 15 - 15: Oo0Ooo + oO0o . I11i % OoO0O00
 if 13 - 13: I1ii11iIi11i / ooOoO0o * I1Ii111
 if 45 - 45: I1ii11iIi11i - I11i
 if 60 - 60: OOooOOo - OOooOOo * OoOoOO00 / Ii1I % iII111i % Oo0Ooo
 eid , O0O0OO0 , OO00ooOO = iiIiIIIIi11II . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , O0O0OO0 , OO00ooOO ) )
 if 75 - 75: iIii1I11I1II1 - IiII - I1Ii111
 if 4 - 4: i11iIiiIii % OoooooooOO . i11iIiiIii
 if 61 - 61: iIii1I11I1II1 . Oo0Ooo . i1IIi
 if 45 - 45: I1Ii111
 OO00ooOO . mask_address ( OO00ooOO . mask_len )
 if 49 - 49: i1IIi * iII111i - iIii1I11I1II1 % I11i * O0 / OoOoOO00
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # IiII . I1ii11iIi11i % iII111i
 # i11iIiiIii - OOooOOo - ooOoO0o - OoO0O00
 O0O0OO0 . print_prefix ( ) if ( O0O0OO0 != None ) else "'not found'" , OO00ooOO . print_prefix ( ) ) )
 if 94 - 94: OoO0O00 . Oo0Ooo / OoO0O00 + I1Ii111
 if 48 - 48: I1ii11iIi11i * i1IIi + I1Ii111
 return ( [ OO00ooOO , I1ii1IiIi1 , Oo00Oo0o000 ] )
 if 80 - 80: I1IiiI % I11i
 if 64 - 64: OOooOOo + i11iIiiIii + I1IiiI . I11i % I11i - o0oOOo0O0Ooo
 if 3 - 3: I1IiiI / i1IIi + II111iiii + Oo0Ooo
 if 48 - 48: o0oOOo0O0Ooo
 if 16 - 16: II111iiii . Ii1I + I1Ii111 % i1IIi / i11iIiiIii + OOooOOo
 if 43 - 43: I1IiiI . Oo0Ooo + i1IIi + I11i / OoO0O00
 if 66 - 66: i11iIiiIii
 if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
 oO0OooO0o0 = map_request . target_eid
 iII1I1i = map_request . target_group
 o000oo = map_request . nonce
 if 83 - 83: i1IIi * i1IIi - II111iiii / OoooooooOO . Ii1I + I1Ii111
 if ( action == LISP_DDT_ACTION_MS_ACK ) : OO0ooo00o = 1440
 if 10 - 10: I11i
 if 24 - 24: Ii1I
 if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
 if 25 - 25: I11i % i1IIi / I11i * i11iIiiIii
 oooO0OOO0o = lisp_map_referral ( )
 oooO0OOO0o . record_count = 1
 oooO0OOO0o . nonce = o000oo
 OO0Oo00OO0oo = oooO0OOO0o . encode ( )
 oooO0OOO0o . print_map_referral ( )
 if 71 - 71: IiII % I11i - OoooooooOO + I1IiiI / Oo0Ooo % I11i
 i1OOO = False
 if 6 - 6: i1IIi * i11iIiiIii + ooOoO0o - IiII
 if 97 - 97: iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - Oo0Ooo - iIii1I11I1II1
 if 26 - 26: ooOoO0o + Oo0Ooo
 if 24 - 24: I1IiiI
 if 43 - 43: OoO0O00
 if 51 - 51: OoooooooOO % IiII % Oo0Ooo
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( oO0OooO0o0 ,
 iII1I1i )
  OO0ooo00o = 15
  if 50 - 50: I1IiiI - i11iIiiIii / I1ii11iIi11i . Ii1I - iIii1I11I1II1
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : OO0ooo00o = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : OO0ooo00o = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : OO0ooo00o = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : OO0ooo00o = 0
 if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
 o0O0o0oooo00 = False
 OO0oIiiI1iIii = 0
 oOo00OoOoo = lisp_ddt_cache_lookup ( oO0OooO0o0 , iII1I1i , False )
 if ( oOo00OoOoo != None ) :
  OO0oIiiI1iIii = len ( oOo00OoOoo . delegation_set )
  o0O0o0oooo00 = oOo00OoOoo . is_ms_peer_entry ( )
  oOo00OoOoo . map_referrals_sent += 1
  if 51 - 51: Ii1I - II111iiii % II111iiii * OOooOOo
  if 84 - 84: i1IIi . OoOoOO00 % I1ii11iIi11i . OoO0O00 + i11iIiiIii
  if 19 - 19: i1IIi / I1IiiI + IiII . iII111i
  if 68 - 68: iII111i
  if 29 - 29: II111iiii / II111iiii % OoO0O00 % Oo0Ooo . II111iiii
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : i1OOO = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  i1OOO = ( o0O0o0oooo00 == False )
  if 33 - 33: OoooooooOO . OoO0O00 % OoooooooOO
  if 9 - 9: IiII * O0 + OOooOOo . II111iiii
  if 14 - 14: iIii1I11I1II1 + i11iIiiIii + o0oOOo0O0Ooo + o0oOOo0O0Ooo - IiII / I1Ii111
  if 70 - 70: OoooooooOO + I1IiiI / OOooOOo
  if 19 - 19: I1Ii111 + i1IIi % OoooooooOO + i1IIi
 iI1111Ii1I = lisp_eid_record ( )
 iI1111Ii1I . rloc_count = OO0oIiiI1iIii
 iI1111Ii1I . authoritative = True
 iI1111Ii1I . action = action
 iI1111Ii1I . ddt_incomplete = i1OOO
 iI1111Ii1I . eid = eid_prefix
 iI1111Ii1I . group = group_prefix
 iI1111Ii1I . record_ttl = OO0ooo00o
 if 16 - 16: I1Ii111 + II111iiii + IiII
 OO0Oo00OO0oo += iI1111Ii1I . encode ( )
 iI1111Ii1I . print_record ( "  " , True )
 if 34 - 34: iIii1I11I1II1 - II111iiii - ooOoO0o + oO0o
 if 46 - 46: ooOoO0o % II111iiii
 if 61 - 61: OoO0O00 . I1IiiI
 if 89 - 89: IiII
 if ( OO0oIiiI1iIii != 0 ) :
  for OOO0o0OOoO00 in oOo00OoOoo . delegation_set :
   Oo000O = lisp_rloc_record ( )
   Oo000O . rloc = OOO0o0OOoO00 . delegate_address
   Oo000O . priority = OOO0o0OOoO00 . priority
   Oo000O . weight = OOO0o0OOoO00 . weight
   Oo000O . mpriority = 255
   Oo000O . mweight = 0
   Oo000O . reach_bit = True
   OO0Oo00OO0oo += Oo000O . encode ( )
   Oo000O . print_record ( "    " )
   if 73 - 73: II111iiii + ooOoO0o % OOooOOo . oO0o / oO0o * i1IIi
   if 19 - 19: I1Ii111 + I11i
   if 21 - 21: OoOoOO00
   if 2 - 2: i1IIi . OOooOOo
   if 23 - 23: Ii1I - OOooOOo
   if 89 - 89: i11iIiiIii
   if 40 - 40: OoooooooOO % OoO0O00
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , OO0Oo00OO0oo , ecm_source , port )
 return
 if 54 - 54: i1IIi * OOooOOo - oO0o * OoooooooOO + II111iiii . IiII
 if 90 - 90: O0 - II111iiii + I1IiiI . iII111i
 if 3 - 3: o0oOOo0O0Ooo + i1IIi * Oo0Ooo
 if 6 - 6: OoO0O00 * OoooooooOO * iIii1I11I1II1
 if 87 - 87: iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1
 if 79 - 79: ooOoO0o . oO0o + Ii1I * ooOoO0o + O0 . II111iiii
 if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
 if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub , not_reg_yet = False ) :
 if 5 - 5: OoooooooOO + ooOoO0o - II111iiii . i11iIiiIii / oO0o - ooOoO0o
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # O0
 red ( dest . print_address ( ) , False ) ) )
 if 85 - 85: Oo0Ooo + i11iIiiIii . OOooOOo / II111iiii / iII111i
 Oo00Oo0o000 = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 90 - 90: o0oOOo0O0Ooo - OoooooooOO - i1IIi
 if 47 - 47: I1Ii111 * Ii1I . iIii1I11I1II1 / OoOoOO00
 if 68 - 68: i11iIiiIii / OOooOOo / I1ii11iIi11i % IiII * IiII + II111iiii
 if 65 - 65: I1IiiI + OoOoOO00 - OoOoOO00 . oO0o
 if 84 - 84: Ii1I * i1IIi
 if ( lisp_get_eid_hash ( eid ) != None ) :
  Oo00Oo0o000 = LISP_SEND_MAP_REQUEST_ACTION
  if 42 - 42: OoOoOO00 - ooOoO0o + oO0o - II111iiii
 if ( not_reg_yet ) :
  Oo00Oo0o000 = LISP_NOT_REGISTERED_YET_ACTION
  if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
  if 6 - 6: iIii1I11I1II1 + oO0o
  if 8 - 8: I1ii11iIi11i + o0oOOo0O0Ooo
 OO0Oo00OO0oo = lisp_build_map_reply ( eid , group , [ ] , nonce , Oo00Oo0o000 , ttl , None ,
 None , False , False )
 if 29 - 29: Ii1I . OOooOOo
 if 59 - 59: O0 . OoO0O00
 if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
 if 81 - 81: i1IIi % I11i * iIii1I11I1II1
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , OO0Oo00OO0oo , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , OO0Oo00OO0oo , dest , port )
  if 39 - 39: iIii1I11I1II1 / O0 . OoooooooOO - O0 . OoO0O00 . oO0o
 return
 if 59 - 59: II111iiii * I1IiiI
 if 12 - 12: i11iIiiIii - IiII . iII111i . Ii1I
 if 34 - 34: i1IIi % iII111i + Oo0Ooo * OoOoOO00 + OoO0O00
 if 37 - 37: I1Ii111 / OoooooooOO
 if 19 - 19: Ii1I - O0 + I1IiiI + OoooooooOO + ooOoO0o - Oo0Ooo
 if 45 - 45: I1IiiI . OoOoOO00 . OoOoOO00
 if 20 - 20: OoOoOO00
def lisp_retransmit_ddt_map_request ( mr ) :
 OO00o0oO0O00 = mr . mr_source . print_address ( )
 O00o0o = mr . print_eid_tuple ( )
 o000oo = mr . nonce
 if 96 - 96: II111iiii
 if 73 - 73: II111iiii
 if 81 - 81: I1IiiI + OoO0O00
 if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
 if 32 - 32: o0oOOo0O0Ooo - iII111i + i11iIiiIii / ooOoO0o . OoOoOO00 . IiII
 if ( mr . last_request_sent_to ) :
  iIiiii1 = mr . last_request_sent_to . print_address ( )
  OoooOO0 = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( OoooOO0 and iIiiii1 in OoooOO0 . referral_set ) :
   OoooOO0 . referral_set [ iIiiii1 ] . no_responses += 1
   if 26 - 26: I1ii11iIi11i
   if 67 - 67: I1Ii111 * iIii1I11I1II1 / O0 + OoO0O00 * iIii1I11I1II1 % II111iiii
   if 13 - 13: Ii1I / ooOoO0o / iII111i % II111iiii * I1IiiI * II111iiii
   if 40 - 40: Ii1I / i1IIi . iII111i
   if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
   if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
   if 85 - 85: I1IiiI + i1IIi % I1Ii111
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( O00o0o , False ) , lisp_hex_string ( o000oo ) ) )
  if 76 - 76: i11iIiiIii % i11iIiiIii
  mr . dequeue_map_request ( )
  return
  if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
  if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
 mr . retry_count += 1
 if 69 - 69: O0 % I1ii11iIi11i
 o0O0o0000o0O0 = green ( OO00o0oO0O00 , False )
 iiIi = green ( O00o0o , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # i11iIiiIii / OOooOOo . ooOoO0o - OoOoOO00 - iII111i
 red ( mr . itr . print_address ( ) , False ) , o0O0o0000o0O0 , iiIi ,
 lisp_hex_string ( o000oo ) ) )
 if 25 - 25: ooOoO0o / iII111i
 if 86 - 86: oO0o + OOooOOo . o0oOOo0O0Ooo
 if 37 - 37: i1IIi + iII111i - IiII + ooOoO0o . i1IIi % i11iIiiIii
 if 92 - 92: I1IiiI
 lisp_send_ddt_map_request ( mr , False )
 if 40 - 40: oO0o + Oo0Ooo % I1IiiI - Ii1I
 if 94 - 94: Oo0Ooo
 if 93 - 93: O0
 if 27 - 27: o0oOOo0O0Ooo + i1IIi + oO0o * II111iiii * OoO0O00
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 64 - 64: I1IiiI
 if 27 - 27: I1Ii111 % I1Ii111 - I11i + IiII - oO0o
 if 52 - 52: OOooOOo % Ii1I + iIii1I11I1II1 . ooOoO0o
 if 83 - 83: oO0o - iIii1I11I1II1 * iII111i
 if 17 - 17: I1IiiI . OoOoOO00
 if 14 - 14: OOooOOo
 if 84 - 84: Ii1I + OoO0O00 + OOooOOo % ooOoO0o
 if 27 - 27: OoOoOO00 % I11i
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 19 - 19: i1IIi - OoOoOO00
 if 26 - 26: IiII . i11iIiiIii % i11iIiiIii / IiII - Oo0Ooo / o0oOOo0O0Ooo
 if 7 - 7: I1IiiI / OOooOOo * iIii1I11I1II1 * Ii1I * i1IIi
 if 87 - 87: IiII * Oo0Ooo - OOooOOo * OoOoOO00
 OO0ooOOo0 = [ ]
 for IiIiii1iIii in list ( referral . referral_set . values ( ) ) :
  if ( IiIiii1iIii . updown == False ) : continue
  if ( len ( OO0ooOOo0 ) == 0 or OO0ooOOo0 [ 0 ] . priority == IiIiii1iIii . priority ) :
   OO0ooOOo0 . append ( IiIiii1iIii )
  elif ( OO0ooOOo0 [ 0 ] . priority > IiIiii1iIii . priority ) :
   OO0ooOOo0 = [ ]
   OO0ooOOo0 . append ( IiIiii1iIii )
   if 33 - 33: i11iIiiIii % OoO0O00 * I1ii11iIi11i
   if 96 - 96: I11i % OoooooooOO * I11i . IiII / I1Ii111
   if 56 - 56: I1IiiI - iII111i % Ii1I . I1ii11iIi11i % i1IIi
 o00OOOO = len ( OO0ooOOo0 )
 if ( o00OOOO == 0 ) : return ( None )
 if 17 - 17: OoO0O00 * I1Ii111
 I111i = dest_eid . hash_address ( source_eid )
 I111i = I111i % o00OOOO
 return ( OO0ooOOo0 [ I111i ] )
 if 56 - 56: oO0o
 if 52 - 52: i1IIi % iIii1I11I1II1 . I1Ii111 / iII111i
 if 31 - 31: Ii1I - o0oOOo0O0Ooo % oO0o / OoO0O00 * I11i
 if 24 - 24: i1IIi
 if 21 - 21: II111iiii
 if 27 - 27: I1IiiI * i11iIiiIii
 if 86 - 86: I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - i1IIi . I11i / OOooOOo
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 ooOo0o00 = mr . lisp_sockets
 o000oo = mr . nonce
 ooo00 = mr . itr
 oOoOOOO0O = mr . mr_source
 ooOo000OoO0o = mr . print_eid_tuple ( )
 if 30 - 30: I1Ii111 * i1IIi
 if 4 - 4: OoO0O00 + O0 * OOooOOo * I1Ii111 / O0
 if 58 - 58: OOooOOo % ooOoO0o * I1IiiI - I1ii11iIi11i / I11i + iII111i
 if 26 - 26: OoOoOO00
 if 63 - 63: I1Ii111 . oO0o + OoO0O00 / I1ii11iIi11i % IiII * II111iiii
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( ooOo000OoO0o , False ) , lisp_hex_string ( o000oo ) ) )
  if 92 - 92: iIii1I11I1II1 . OoooooooOO . ooOoO0o / II111iiii
  mr . dequeue_map_request ( )
  return
  if 30 - 30: i1IIi * Ii1I + Ii1I / I1Ii111
  if 84 - 84: I1IiiI - Oo0Ooo * OoO0O00 * oO0o
  if 13 - 13: I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + oO0o - iII111i
  if 32 - 32: I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * I1Ii111 % II111iiii
  if 33 - 33: ooOoO0o % I11i
  if 72 - 72: OoO0O00 % OoooooooOO / II111iiii * oO0o * I1Ii111
 if ( send_to_root ) :
  OOO0oOooOOo00 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  I1oOOoOooo00OO = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( ooOo000OoO0o , False ) ) )
 else :
  OOO0oOooOOo00 = mr . eid
  I1oOOoOooo00OO = mr . group
  if 1 - 1: i11iIiiIii
  if 30 - 30: I11i
  if 26 - 26: Oo0Ooo - II111iiii % ooOoO0o
  if 81 - 81: i11iIiiIii + I1ii11iIi11i * oO0o
  if 86 - 86: OoO0O00 . ooOoO0o . o0oOOo0O0Ooo
 OoOo00OoOo = lisp_referral_cache_lookup ( OOO0oOooOOo00 , I1oOOoOooo00OO , False )
 if ( OoOo00OoOo == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( ooOo0o00 , OOO0oOooOOo00 , I1oOOoOooo00OO ,
 o000oo , ooo00 , mr . sport , 15 , None , False )
  return
  if 68 - 68: i11iIiiIii / I1IiiI / i11iIiiIii
  if 87 - 87: OoOoOO00 . OoO0O00 . I1Ii111 / Ii1I + Oo0Ooo % OoooooooOO
 O000ooOOo = OoOo00OoOo . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( O000ooOOo ,
 OoOo00OoOo . print_referral_type ( ) ) )
 if 37 - 37: o0oOOo0O0Ooo . II111iiii * II111iiii - oO0o % Ii1I - II111iiii
 IiIiii1iIii = lisp_get_referral_node ( OoOo00OoOo , oOoOOOO0O , mr . eid )
 if ( IiIiii1iIii == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( ooOo0o00 , OoOo00OoOo . eid ,
 OoOo00OoOo . group , o000oo , ooo00 , mr . sport , 1 , None , False )
  return
  if 31 - 31: OoooooooOO - O0 * Ii1I . OoO0O00 / I1Ii111 . OOooOOo
  if 28 - 28: iII111i % I1ii11iIi11i . I11i
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( IiIiii1iIii . referral_address . print_address ( ) ,
 # I11i - II111iiii
 OoOo00OoOo . print_referral_type ( ) , green ( ooOo000OoO0o , False ) ,
 lisp_hex_string ( o000oo ) ) )
 if 84 - 84: I1ii11iIi11i * IiII / I1IiiI - Ii1I + IiII - i1IIi
 if 98 - 98: II111iiii - iII111i % i11iIiiIii + ooOoO0o
 if 76 - 76: OOooOOo - iII111i + IiII
 if 48 - 48: I1IiiI - II111iiii
 iIiII1I1Ii = ( OoOo00OoOo . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 OoOo00OoOo . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( ooOo0o00 , mr . packet , oOoOOOO0O , mr . sport , mr . eid ,
 IiIiii1iIii . referral_address , to_ms = iIiII1I1Ii , ddt = True )
 if 62 - 62: IiII - iII111i . I1ii11iIi11i . oO0o
 if 22 - 22: OoOoOO00 * i11iIiiIii * Ii1I
 if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
 if 5 - 5: OoO0O00 / ooOoO0o
 mr . last_request_sent_to = IiIiii1iIii . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 IiIiii1iIii . map_requests_sent += 1
 return
 if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
 if 97 - 97: oO0o / Ii1I
 if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
 if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
 if 91 - 91: IiII * Ii1I * OOooOOo
 if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
 if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
 if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
 oO0OooO0o0 = map_request . target_eid
 iII1I1i = map_request . target_group
 O00o0o = map_request . print_eid_tuple ( )
 OO00o0oO0O00 = mr_source . print_address ( )
 o000oo = map_request . nonce
 if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
 o0O0o0000o0O0 = green ( OO00o0oO0O00 , False )
 iiIi = green ( O00o0o , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # I1IiiI + OOooOOo * I1IiiI % i11iIiiIii / O0 + OoO0O00
 red ( ecm_source . print_address ( ) , False ) , o0O0o0000o0O0 , iiIi ,
 lisp_hex_string ( o000oo ) ) )
 if 48 - 48: oO0o
 if 15 - 15: OOooOOo
 if 3 - 3: i1IIi
 if 85 - 85: i11iIiiIii % i1IIi
 o0O0oOoOO = lisp_ddt_map_request ( lisp_sockets , packet , oO0OooO0o0 , iII1I1i , o000oo )
 o0O0oOoOO . packet = packet
 o0O0oOoOO . itr = ecm_source
 o0O0oOoOO . mr_source = mr_source
 o0O0oOoOO . sport = sport
 o0O0oOoOO . from_pitr = map_request . pitr_bit
 o0O0oOoOO . queue_map_request ( )
 if 36 - 36: oO0o . iII111i / II111iiii + i1IIi
 lisp_send_ddt_map_request ( o0O0oOoOO , False )
 return
 if 100 - 100: ooOoO0o - II111iiii * I1ii11iIi11i * O0
 if 9 - 9: iII111i
 if 83 - 83: ooOoO0o * oO0o * OoO0O00 + OoO0O00
 if 58 - 58: I1ii11iIi11i
 if 93 - 93: i1IIi - IiII + IiII % OoooooooOO / o0oOOo0O0Ooo
 if 39 - 39: I1IiiI + Ii1I - O0
 if 25 - 25: IiII % iIii1I11I1II1 + ooOoO0o % iII111i - OoO0O00
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl , timestamp ) :
 if 36 - 36: OoooooooOO / oO0o + IiII . I1IiiI - o0oOOo0O0Ooo % OOooOOo
 IiI11 = packet
 I1I111I11i = lisp_map_request ( )
 packet = I1I111I11i . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 18 - 18: OoooooooOO + II111iiii + Oo0Ooo % oO0o
  if 6 - 6: Oo0Ooo
 I1I111I11i . print_map_request ( )
 if 88 - 88: IiII - Oo0Ooo * I11i / I1IiiI . i1IIi
 if 67 - 67: i11iIiiIii
 if 3 - 3: IiII
 if 47 - 47: O0
 if ( I1I111I11i . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , I1I111I11i , mr_source ,
 mr_port , ttl , timestamp )
  return
  if 60 - 60: OOooOOo / ooOoO0o + Oo0Ooo / O0 - oO0o
  if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
  if 4 - 4: I1IiiI
  if 31 - 31: ooOoO0o * i1IIi . O0
  if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
 if ( I1I111I11i . smr_bit ) :
  lisp_process_smr ( I1I111I11i )
  if 100 - 100: I1Ii111
  if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
  if 88 - 88: IiII
  if 29 - 29: iII111i . ooOoO0o
  if 62 - 62: IiII
 if ( I1I111I11i . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( I1I111I11i )
  if 95 - 95: ooOoO0o / i1IIi + II111iiii + OoO0O00 % OoO0O00
  if 18 - 18: ooOoO0o * I1IiiI / iII111i % iII111i
  if 9 - 9: i11iIiiIii % ooOoO0o % O0 + i1IIi / O0
  if 12 - 12: I1Ii111 - iII111i * iII111i + OoO0O00 . Ii1I % I11i
  if 28 - 28: ooOoO0o % OoO0O00 - II111iiii * IiII - I1IiiI + I1IiiI
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , I1I111I11i , mr_source ,
 mr_port , ttl , timestamp )
  if 84 - 84: IiII / Ii1I
  if 39 - 39: OOooOOo - iIii1I11I1II1 + OoOoOO00 % IiII * OoooooooOO % Ii1I
  if 11 - 11: I1ii11iIi11i
  if 83 - 83: O0
  if 97 - 97: O0
 if ( lisp_i_am_ms ) :
  packet = IiI11
  oO0OooO0o0 , iII1I1i , I1iiI = lisp_ms_process_map_request ( lisp_sockets ,
 IiI11 , I1I111I11i , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , I1I111I11i , ecm_source ,
 ecm_port , I1iiI , oO0OooO0o0 , iII1I1i )
   if 55 - 55: i11iIiiIii / II111iiii / I1Ii111 * iIii1I11I1II1 / II111iiii * iIii1I11I1II1
  return
  if 41 - 41: o0oOOo0O0Ooo . iII111i % iII111i . OOooOOo / OOooOOo
  if 98 - 98: II111iiii + ooOoO0o - iIii1I11I1II1 . I11i . iIii1I11I1II1 - iIii1I11I1II1
  if 91 - 91: ooOoO0o
  if 66 - 66: OOooOOo
  if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , IiI11 , I1I111I11i ,
 ecm_source , mr_port , mr_source )
  if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
  if 9 - 9: Ii1I
  if 44 - 44: iII111i
  if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
  if 37 - 37: OoO0O00 - Ii1I + OoO0O00
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = IiI11
  lisp_ddt_process_map_request ( lisp_sockets , I1I111I11i , ecm_source ,
 ecm_port )
  if 49 - 49: OoooooooOO - I1ii11iIi11i % I1ii11iIi11i / i1IIi . ooOoO0o
 return
 if 60 - 60: Oo0Ooo
 if 46 - 46: OoOoOO00 + i1IIi
 if 43 - 43: II111iiii * IiII % iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
 if 81 - 81: oO0o % I1ii11iIi11i % ooOoO0o * O0 - OOooOOo
 if 17 - 17: O0 % O0 / I1ii11iIi11i . Oo0Ooo . iII111i
 if 4 - 4: OoO0O00
 if 65 - 65: Oo0Ooo % O0 / I1Ii111 * IiII - oO0o
 if 32 - 32: Ii1I * OoO0O00 + ooOoO0o
def lisp_store_mr_stats ( source , nonce ) :
 o0O0oOoOO = lisp_get_map_resolver ( source , None )
 if ( o0O0oOoOO == None ) : return
 if 41 - 41: IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
 if 38 - 38: iII111i * OoooooooOO - IiII
 if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
 if 91 - 91: O0 + I1Ii111 * II111iiii - O0 . i11iIiiIii . Oo0Ooo
 o0O0oOoOO . neg_map_replies_received += 1
 o0O0oOoOO . last_reply = lisp_get_timestamp ( )
 if 54 - 54: ooOoO0o * I11i / I1ii11iIi11i % ooOoO0o
 if 76 - 76: I11i . I1IiiI
 if 66 - 66: oO0o % oO0o * IiII
 if 39 - 39: i1IIi * Ii1I + OoOoOO00 / oO0o
 if ( ( o0O0oOoOO . neg_map_replies_received % 100 ) == 0 ) : o0O0oOoOO . total_rtt = 0
 if 6 - 6: I1ii11iIi11i / II111iiii / OoOoOO00 . i11iIiiIii - iII111i
 if 43 - 43: i11iIiiIii * i11iIiiIii * I1Ii111
 if 80 - 80: oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / o0oOOo0O0Ooo % OoooooooOO
 if 31 - 31: o0oOOo0O0Ooo - OoO0O00 % I1IiiI
 if ( o0O0oOoOO . last_nonce == nonce ) :
  o0O0oOoOO . total_rtt += ( time . time ( ) - o0O0oOoOO . last_used )
  o0O0oOoOO . last_nonce = 0
  if 23 - 23: OOooOOo
 if ( ( o0O0oOoOO . neg_map_replies_received % 10 ) == 0 ) : o0O0oOoOO . last_nonce = 0
 return
 if 97 - 97: Oo0Ooo / OoooooooOO . OoooooooOO
 if 47 - 47: OoO0O00
 if 52 - 52: I1IiiI * iIii1I11I1II1 % oO0o * IiII % oO0o
 if 9 - 9: I11i
 if 83 - 83: i11iIiiIii
 if 72 - 72: oO0o + II111iiii . O0 * oO0o + iII111i
 if 22 - 22: I11i + Ii1I . IiII - OoO0O00 - o0oOOo0O0Ooo
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl , itr_in_ts ) :
 global lisp_map_cache
 if 84 - 84: OoooooooOO - Oo0Ooo
 iI1iI1 = lisp_map_reply ( )
 packet = iI1iI1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 86 - 86: O0 + OoO0O00 + O0 . I1IiiI
 iI1iI1 . print_map_reply ( )
 if 82 - 82: OoOoOO00
 if 61 - 61: oO0o . o0oOOo0O0Ooo
 if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
 if 70 - 70: I1IiiI
 o0o0OooOooo00 = None
 for iIiIIi in range ( iI1iI1 . record_count ) :
  iI1111Ii1I = lisp_eid_record ( )
  packet = iI1111Ii1I . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 93 - 93: OoO0O00
  iI1111Ii1I . print_record ( "  " , False )
  if 56 - 56: i1IIi + Ii1I * iIii1I11I1II1
  if 1 - 1: iII111i
  if 25 - 25: oO0o - i1IIi
  if 67 - 67: I1IiiI % I11i - OoooooooOO
  if 2 - 2: Ii1I
  if ( iI1111Ii1I . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , iI1iI1 . nonce )
   if 25 - 25: I1Ii111 * I1IiiI + OoOoOO00 . i11iIiiIii . I1IiiI . I11i
   if 61 - 61: o0oOOo0O0Ooo / ooOoO0o + o0oOOo0O0Ooo + Ii1I * iIii1I11I1II1 * OoooooooOO
  oOiI1111iI1 = ( iI1111Ii1I . group . is_null ( ) == False )
  if 86 - 86: oO0o . o0oOOo0O0Ooo * OoOoOO00 / oO0o
  if 47 - 47: OOooOOo
  if 40 - 40: I1ii11iIi11i
  if 67 - 67: I1Ii111 - OoO0O00 * ooOoO0o - oO0o / OoO0O00 . I1Ii111
  if 39 - 39: Ii1I
  if ( lisp_decent_push_configured ) :
   Oo00Oo0o000 = iI1111Ii1I . action
   if ( oOiI1111iI1 and Oo00Oo0o000 == LISP_DROP_ACTION ) :
    if ( iI1111Ii1I . eid . is_local ( ) ) : continue
    if 90 - 90: I1Ii111 - I1Ii111 . i11iIiiIii + OoooooooOO % OOooOOo / Oo0Ooo
    if 51 - 51: o0oOOo0O0Ooo
    if 8 - 8: oO0o . oO0o . Ii1I
    if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
    if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
    if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
    if 10 - 10: ooOoO0o
  if ( oOiI1111iI1 == False and iI1111Ii1I . eid . is_null ( ) ) : continue
  if 69 - 69: I11i + I1IiiI / oO0o
  if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
  if 85 - 85: I1Ii111 - oO0o
  if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
  if 96 - 96: oO0o
  if ( oOiI1111iI1 ) :
   Ii111 = lisp_map_cache . lookup_cache ( iI1111Ii1I . group , True )
   if ( Ii111 ) :
    Ii111 = Ii111 . lookup_source_cache ( iI1111Ii1I . eid , False )
    if 39 - 39: OoOoOO00
  else :
   Ii111 = lisp_map_cache . lookup_cache ( iI1111Ii1I . eid , True )
   if 61 - 61: OoooooooOO / ooOoO0o . i1IIi . Oo0Ooo % OoOoOO00 * OoO0O00
  i1O00oOO = ( Ii111 == None )
  if 39 - 39: oO0o
  if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
  if 57 - 57: oO0o + O0 - OoOoOO00
  if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
  if 93 - 93: o0oOOo0O0Ooo + i1IIi
  if ( Ii111 == None ) :
   iI1I , iII , I111I1I = lisp_allow_gleaning ( iI1111Ii1I . eid , iI1111Ii1I . group ,
 None )
   if ( iI1I ) : continue
  else :
   if ( Ii111 . gleaned ) : continue
   if 14 - 14: OoO0O00 * OoO0O00 - I1ii11iIi11i
   if 90 - 90: Oo0Ooo . II111iiii + I1ii11iIi11i - OoOoOO00 / I11i * iII111i
   if 58 - 58: oO0o + Oo0Ooo . O0
   if 8 - 8: II111iiii + iII111i + OoO0O00 - Ii1I / I1ii11iIi11i
   if 86 - 86: I1ii11iIi11i
  oO0O0O0O0OO = [ ]
  i1i11iiII = None
  o0oo0 = None
  for i111Ii11i in range ( iI1111Ii1I . rloc_count ) :
   Oo000O = lisp_rloc_record ( )
   Oo000O . keys = iI1iI1 . keys
   packet = Oo000O . decode ( packet , iI1iI1 . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 83 - 83: OOooOOo
   Oo000O . print_record ( "    " )
   if 55 - 55: OOooOOo * O0 % OoooooooOO % iIii1I11I1II1
   oO0oOO0O000 = None
   if ( Ii111 ) : oO0oOO0O000 = Ii111 . get_rloc ( Oo000O . rloc )
   if 10 - 10: oO0o / ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
   if ( oO0oOO0O000 ) :
    OOOo0 = oO0oOO0O000
   else :
    OOOo0 = lisp_rloc ( )
    if 26 - 26: I1IiiI - OOooOOo
    if 34 - 34: I1Ii111 % I1IiiI . OoOoOO00 / iII111i + ooOoO0o . i11iIiiIii
    if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
    if 50 - 50: OoooooooOO * II111iiii
    if 7 - 7: ooOoO0o / I11i * iII111i
    if 17 - 17: O0 % I1Ii111
    if 28 - 28: i1IIi * ooOoO0o
   O00oo0o0o0oo = OOOo0 . store_rloc_from_record ( Oo000O , iI1iI1 . nonce ,
 source )
   OOOo0 . echo_nonce_capable = iI1iI1 . echo_nonce_capable
   if 14 - 14: II111iiii + II111iiii - I11i / I11i . OoOoOO00 + OoO0O00
   if ( OOOo0 . echo_nonce_capable ) :
    Oo0o = OOOo0 . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , Oo0o ) == None ) :
     lisp_echo_nonce ( Oo0o )
     if 92 - 92: II111iiii - II111iiii % IiII
     if 48 - 48: oO0o / II111iiii + oO0o
     if 16 - 16: o0oOOo0O0Ooo % II111iiii - i11iIiiIii - IiII + O0 - i11iIiiIii
     if 58 - 58: OoooooooOO / I1ii11iIi11i - Oo0Ooo / II111iiii
     if 13 - 13: o0oOOo0O0Ooo + OoOoOO00 * ooOoO0o % IiII
     if 18 - 18: I1IiiI . I1ii11iIi11i + Oo0Ooo - iII111i
   if ( OOOo0 . json ) :
    if ( lisp_is_json_telemetry ( OOOo0 . json . json_string ) ) :
     II11Ii11 = OOOo0 . json . json_string
     II11Ii11 = lisp_encode_telemetry ( II11Ii11 , ii = itr_in_ts )
     OOOo0 . json . json_string = II11Ii11
     if 53 - 53: ooOoO0o / IiII
     if 36 - 36: iIii1I11I1II1
     if 78 - 78: II111iiii * I11i
     if 47 - 47: Ii1I
     if 42 - 42: I11i . oO0o - I1IiiI / OoO0O00
     if 75 - 75: I1IiiI / OoOoOO00 . I11i * iIii1I11I1II1
   if ( o0oo0 == None ) :
    o0oo0 = OOOo0 . rloc_name
    if 53 - 53: iIii1I11I1II1
    if 8 - 8: O0 - O0 - II111iiii
    if 77 - 77: i1IIi - ooOoO0o + O0 . OoO0O00 * I1Ii111 - I11i
    if 64 - 64: i1IIi + OoooooooOO + OOooOOo / ooOoO0o % I1IiiI . OoooooooOO
    if 96 - 96: II111iiii - OoOoOO00 + oO0o
    if 80 - 80: oO0o / OoOoOO00 - I11i / oO0o - iII111i - OoooooooOO
    if 57 - 57: o0oOOo0O0Ooo
    if 37 - 37: iII111i * o0oOOo0O0Ooo
    if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
   if ( iI1iI1 . rloc_probe and Oo000O . probe_bit ) :
    if ( OOOo0 . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( OOOo0 , source , O00oo0o0o0oo ,
 iI1iI1 , ttl , i1i11iiII , o0oo0 )
     if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
    if ( OOOo0 . rloc . is_multicast_address ( ) ) : i1i11iiII = OOOo0
    if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
    if 34 - 34: O0 * oO0o
    if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
    if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
    if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
   oO0O0O0O0OO . append ( OOOo0 )
   if 88 - 88: i11iIiiIii
   if 13 - 13: I1IiiI
   if 52 - 52: Ii1I * oO0o / I1Ii111 . IiII
   if 84 - 84: OoooooooOO - oO0o - I1Ii111
   if ( lisp_data_plane_security and OOOo0 . rloc_recent_rekey ( ) ) :
    o0o0OooOooo00 = OOOo0
    if 69 - 69: OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
    if 20 - 20: IiII
    if 17 - 17: o0oOOo0O0Ooo % iIii1I11I1II1
    if 66 - 66: OoooooooOO + IiII . II111iiii
    if 66 - 66: iIii1I11I1II1 % I11i
    if 38 - 38: I1ii11iIi11i * ooOoO0o
    if 77 - 77: OOooOOo - i11iIiiIii - I1ii11iIi11i
    if 94 - 94: OoO0O00 % iII111i - I1Ii111 + OoO0O00 - I1IiiI
    if 65 - 65: OOooOOo
    if 90 - 90: O0
    if 91 - 91: O0 * OoOoOO00 - OoOoOO00 * II111iiii - iII111i
  if ( iI1iI1 . rloc_probe == False and lisp_nat_traversal ) :
   I1I1II1 = [ ]
   iI111111iiii = [ ]
   for OOOo0 in oO0O0O0O0OO :
    IIII1iI1IiIiI = OOOo0 . rloc . print_address_no_iid ( )
    if 9 - 9: Oo0Ooo + OOooOOo + OoO0O00 + Ii1I - Oo0Ooo * OoOoOO00
    if 20 - 20: oO0o
    if 48 - 48: I1IiiI % OoO0O00
    if 33 - 33: Ii1I
    if 73 - 73: Ii1I . IiII
    if ( OOOo0 . rloc . is_private_address ( ) ) :
     OOOo0 . priority = 1
     OOOo0 . state = LISP_RLOC_UNREACH_STATE
     I1I1II1 . append ( OOOo0 )
     iI111111iiii . append ( IIII1iI1IiIiI )
     continue
     if 43 - 43: I11i . IiII - iII111i * I1IiiI * iII111i
     if 90 - 90: i11iIiiIii * i1IIi
     if 88 - 88: i11iIiiIii - OoOoOO00
     if 53 - 53: iIii1I11I1II1 % I1Ii111 / Oo0Ooo % Oo0Ooo
     if 6 - 6: iII111i
     if 44 - 44: oO0o
     if 23 - 23: I1IiiI + iIii1I11I1II1 . iII111i + OOooOOo - OoO0O00 + i1IIi
     if 60 - 60: i11iIiiIii + Oo0Ooo * OoOoOO00 . iII111i - iIii1I11I1II1 * IiII
     if 52 - 52: OOooOOo
     if 50 - 50: OoOoOO00 % o0oOOo0O0Ooo - II111iiii - i1IIi
    if ( lisp_i_am_rtr ) :
     if ( OOOo0 . priority != 254 ) :
      I1I1II1 . append ( OOOo0 )
      iI111111iiii . append ( IIII1iI1IiIiI )
      if 35 - 35: Oo0Ooo - ooOoO0o % OoO0O00
    elif ( lisp_decent_nat ) :
     I1I1II1 . append ( OOOo0 )
     iI111111iiii . append ( IIII1iI1IiIiI )
    elif ( OOOo0 . priority == 254 ) :
     I1I1II1 . append ( OOOo0 )
     iI111111iiii . append ( IIII1iI1IiIiI )
     if 26 - 26: i1IIi * I1Ii111 * OoO0O00 - IiII
     if 26 - 26: Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
     if 66 - 66: I1IiiI
   if ( iI111111iiii != [ ] ) :
    oO0O0O0O0OO = I1I1II1
    IiI1ii1iI111I = "NAT-decent" if ( lisp_decent_nat ) else "NAT-traversal"
    if 45 - 45: I1ii11iIi11i / OoooooooOO % iII111i
    lprint ( "{} optimized RLOC-set: {}" . format ( IiI1ii1iI111I , iI111111iiii ) )
    if 22 - 22: I1Ii111
    if 41 - 41: O0 * i1IIi
    if 89 - 89: iIii1I11I1II1 . I11i % I1ii11iIi11i + II111iiii . OoO0O00
    if 5 - 5: I1ii11iIi11i / I1IiiI . iII111i
    if 7 - 7: Ii1I
    if 62 - 62: I1ii11iIi11i + IiII . O0 - OoooooooOO * o0oOOo0O0Ooo % O0
    if 63 - 63: OOooOOo + iII111i - IiII - I1IiiI % IiII . OoO0O00
  I1I1II1 = [ ]
  for OOOo0 in oO0O0O0O0OO :
   if ( OOOo0 . json != None ) : continue
   I1I1II1 . append ( OOOo0 )
   if 73 - 73: OoOoOO00
  if ( I1I1II1 != [ ] ) :
   IiI = len ( oO0O0O0O0OO ) - len ( I1I1II1 )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( IiI ) )
   if 47 - 47: oO0o
   oO0O0O0O0OO = I1I1II1
   if 17 - 17: IiII
   if 47 - 47: I11i . I1IiiI % ooOoO0o . i11iIiiIii
   if 63 - 63: I1ii11iIi11i % I11i % OoooooooOO
   if 100 - 100: O0
   if 9 - 9: Ii1I
   if 87 - 87: I1IiiI
  if ( lisp_decent_nat ) :
   for OOOo0 in oO0O0O0O0OO :
    if ( OOOo0 . is_decent_nat_port ( ) == False ) : continue
    lisp_itr_nat_probe ( OOOo0 . rloc , OOOo0 . rloc_name , lisp_sockets [ 2 ] )
    if 56 - 56: OOooOOo % oO0o - OoOoOO00
    if 27 - 27: I1ii11iIi11i - IiII * OoooooooOO * I1ii11iIi11i + i11iIiiIii . IiII
    if 81 - 81: oO0o / iIii1I11I1II1
    if 15 - 15: Ii1I + I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
    if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
    if 28 - 28: ooOoO0o
    if 88 - 88: oO0o
    if 77 - 77: ooOoO0o + I1Ii111 . OoOoOO00
    if 2 - 2: i1IIi - IiII + iIii1I11I1II1 % i1IIi * II111iiii
  if ( iI1iI1 . rloc_probe and Ii111 != None ) : oO0O0O0O0OO = Ii111 . rloc_set
  if 26 - 26: I11i
  if 57 - 57: I1ii11iIi11i + I1Ii111 + i11iIiiIii . i1IIi / i11iIiiIii
  if 43 - 43: Ii1I % I11i
  if 5 - 5: OoooooooOO % i11iIiiIii * o0oOOo0O0Ooo * OoooooooOO - o0oOOo0O0Ooo % I11i
  if 58 - 58: i11iIiiIii % Ii1I + Oo0Ooo - OoOoOO00 - i11iIiiIii / O0
  iI11I11Iii = i1O00oOO
  if ( Ii111 and oO0O0O0O0OO != Ii111 . rloc_set ) :
   Ii111 . delete_rlocs_from_rloc_probe_list ( )
   iI11I11Iii = True
   if 20 - 20: I1Ii111
   if 75 - 75: I1IiiI / I1Ii111 . I1Ii111 / I1IiiI + OOooOOo + o0oOOo0O0Ooo
   if 68 - 68: i1IIi + OoO0O00
   if 60 - 60: i11iIiiIii . ooOoO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
   if 59 - 59: OoooooooOO . Ii1I . OOooOOo / iII111i - I1IiiI
  oO0OooO = Ii111 . uptime if ( Ii111 ) else None
  if ( Ii111 == None or iI11I11Iii ) :
   Ii111 = lisp_mapping ( iI1111Ii1I . eid , iI1111Ii1I . group , oO0O0O0O0OO )
   Ii111 . mapping_source = source
   if 94 - 94: o0oOOo0O0Ooo
   if 88 - 88: OoO0O00 / II111iiii
   if 27 - 27: OOooOOo - i1IIi + O0 . I1Ii111 % I11i . I1ii11iIi11i
   if 80 - 80: I1IiiI - i11iIiiIii
   if 39 - 39: I11i / O0 - I1ii11iIi11i . Oo0Ooo * OoooooooOO / o0oOOo0O0Ooo
   if 71 - 71: O0 . OoooooooOO + Oo0Ooo . ooOoO0o / Ii1I
   if ( lisp_i_am_rtr and iI1111Ii1I . group . is_null ( ) == False ) :
    Ii111 . map_cache_ttl = LISP_MCAST_TTL
   else :
    Ii111 . map_cache_ttl = iI1111Ii1I . store_ttl ( )
    if 92 - 92: I1ii11iIi11i . oO0o
   Ii111 . action = iI1111Ii1I . action
   Ii111 . add_cache ( iI11I11Iii )
   if 8 - 8: o0oOOo0O0Ooo / oO0o
   if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
  ii11i1IiI = "Add"
  if ( oO0OooO ) :
   Ii111 . uptime = oO0OooO
   Ii111 . refresh_time = lisp_get_timestamp ( )
   ii11i1IiI = "Replace"
   if 99 - 99: Ii1I / iII111i / Ii1I + iII111i
   if 18 - 18: OoOoOO00 % OoO0O00 + Ii1I * I1Ii111 / O0 % I1Ii111
  lprint ( "{} {} map-cache with {} RLOCs" . format ( ii11i1IiI ,
 green ( Ii111 . print_eid_tuple ( ) , False ) , len ( oO0O0O0O0OO ) ) )
  if 6 - 6: II111iiii - i1IIi
  if 78 - 78: OoOoOO00 - Oo0Ooo * II111iiii % iIii1I11I1II1 . i11iIiiIii % iII111i
  if 85 - 85: I1ii11iIi11i + OOooOOo % i1IIi
  if 13 - 13: OOooOOo + i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
  if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
  if ( lisp_ipc_dp_socket and o0o0OooOooo00 != None ) :
   lisp_write_ipc_keys ( o0o0OooOooo00 )
   if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
   if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
   if 8 - 8: OoooooooOO * OOooOOo * iII111i - iII111i
   if 32 - 32: I1Ii111
   if 28 - 28: I11i . i11iIiiIii % iIii1I11I1II1 + OoOoOO00
   if 4 - 4: OOooOOo + I1ii11iIi11i - iII111i + OOooOOo / IiII
   if 23 - 23: iIii1I11I1II1 + OoooooooOO + ooOoO0o . iII111i . Oo0Ooo - iIii1I11I1II1
  if ( i1O00oOO ) :
   Ii1IiI = bold ( "RLOC-probe" , False )
   for OOOo0 in Ii111 . best_rloc_set :
    Oo0o = red ( OOOo0 . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( Ii1IiI , Oo0o ) )
    lisp_send_map_request ( lisp_sockets , 0 , Ii111 . eid , Ii111 . group , OOOo0 )
    if 3 - 3: IiII / iII111i * iII111i
    if 15 - 15: O0 + I1IiiI * OoO0O00 - i1IIi + Ii1I . i1IIi
    if 99 - 99: II111iiii + iIii1I11I1II1 / o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 - iIii1I11I1II1
 return
 if 38 - 38: I1IiiI . oO0o - II111iiii
 if 37 - 37: i1IIi % oO0o / IiII * I11i + ooOoO0o % Oo0Ooo
 if 75 - 75: o0oOOo0O0Ooo . I1Ii111 % i1IIi . i11iIiiIii
 if 38 - 38: o0oOOo0O0Ooo - OoO0O00 - i11iIiiIii
 if 60 - 60: i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i * iII111i . oO0o + iII111i
 if 29 - 29: Oo0Ooo
 if 16 - 16: oO0o
 if 52 - 52: I11i * I1IiiI % I11i - iII111i - Ii1I - OoooooooOO
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 15 - 15: iII111i
 packet = map_register . zero_auth ( packet )
 I111i = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 95 - 95: i11iIiiIii . Ii1I / II111iiii + II111iiii + Ii1I / I11i
 if 72 - 72: I1Ii111 . I1Ii111 * O0 + I1ii11iIi11i / Oo0Ooo
 if 96 - 96: oO0o . ooOoO0o * Oo0Ooo % ooOoO0o + I1Ii111 + iIii1I11I1II1
 if 45 - 45: II111iiii
 map_register . auth_data = I111i
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 42 - 42: ooOoO0o
 if 62 - 62: II111iiii * o0oOOo0O0Ooo . OoO0O00 / II111iiii
 if 5 - 5: OoO0O00 + O0 . OoooooooOO + I1IiiI + i1IIi * OOooOOo
 if 19 - 19: OoooooooOO + i11iIiiIii / II111iiii - Oo0Ooo . OOooOOo
 if 10 - 10: oO0o * Oo0Ooo
 if 55 - 55: OoO0O00 - i1IIi - I11i * oO0o
 if 91 - 91: I1Ii111
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 77 - 77: I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + Ii1I % II111iiii * II111iiii
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  IiIIi1I = hashlib . sha1
  if 93 - 93: OOooOOo
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  IiIIi1I = hashlib . sha256
  if 65 - 65: i1IIi * ooOoO0o * OoooooooOO - i11iIiiIii + IiII - o0oOOo0O0Ooo
  if 12 - 12: I1IiiI
 if ( do_hex ) :
  I111i = hmac . new ( password . encode ( ) , packet , IiIIi1I ) . hexdigest ( )
 else :
  I111i = hmac . new ( password . encode ( ) , packet , IiIIi1I ) . digest ( )
  if 34 - 34: o0oOOo0O0Ooo / I1IiiI * i11iIiiIii + I1Ii111 / IiII
 return ( I111i )
 if 55 - 55: iIii1I11I1II1 % iIii1I11I1II1 % iII111i
 if 80 - 80: OoooooooOO % iII111i * IiII % IiII
 if 34 - 34: OoO0O00
 if 22 - 22: OOooOOo
 if 23 - 23: I1ii11iIi11i
 if 53 - 53: I11i
 if 64 - 64: iIii1I11I1II1 + O0 % IiII
 if 13 - 13: i11iIiiIii
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 49 - 49: OoOoOO00
 I111i = lisp_hash_me ( packet , alg_id , password , True )
 O0o0o = ( I111i == auth_data )
 if 85 - 85: iIii1I11I1II1 * o0oOOo0O0Ooo / OoOoOO00 % I1ii11iIi11i
 if 31 - 31: OOooOOo
 if 64 - 64: OoOoOO00 + I1ii11iIi11i - OoooooooOO + I11i + i1IIi
 if 72 - 72: I1Ii111 * OoOoOO00
 if ( O0o0o == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( I111i , auth_data ) )
  if 5 - 5: O0 - i11iIiiIii % Ii1I + ooOoO0o % I1Ii111
  if 27 - 27: i11iIiiIii / o0oOOo0O0Ooo + OoooooooOO * o0oOOo0O0Ooo - Oo0Ooo
 return ( O0o0o )
 if 70 - 70: oO0o
 if 44 - 44: oO0o % OoOoOO00 - OOooOOo . i1IIi / OoO0O00 % I11i
 if 22 - 22: i1IIi . O0
 if 100 - 100: I1IiiI . OOooOOo
 if 72 - 72: iIii1I11I1II1 % iIii1I11I1II1 . OoOoOO00 * OoooooooOO * OoO0O00
 if 26 - 26: Ii1I * I1IiiI % ooOoO0o / I1Ii111
 if 80 - 80: I1Ii111 / O0 * O0
def lisp_retransmit_map_notify ( map_notify ) :
 OooOOooo = map_notify . etr
 O00oo0o0o0oo = map_notify . etr_port
 if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
 if 89 - 89: i11iIiiIii - II111iiii
 if 67 - 67: IiII % I1Ii111 + i11iIiiIii
 if 53 - 53: OOooOOo
 if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( OooOOooo . print_address ( ) , False ) ) )
  if 21 - 21: I1Ii111 . i1IIi - iII111i % I1ii11iIi11i . OOooOOo
  if 52 - 52: Ii1I * I1ii11iIi11i
  III11II111 = map_notify . nonce_key
  if ( III11II111 in lisp_map_notify_queue ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( III11II111 ) )
   if 21 - 21: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo * II111iiii % iIii1I11I1II1
   try :
    lisp_map_notify_queue . pop ( III11II111 )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 9 - 9: I1ii11iIi11i + I11i
    if 20 - 20: iII111i + i1IIi / oO0o % OoooooooOO * OoOoOO00
  return
  if 70 - 70: Oo0Ooo - OOooOOo * OOooOOo / o0oOOo0O0Ooo
  if 4 - 4: OoOoOO00 / OoO0O00
 ooOo0o00 = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 66 - 66: I1Ii111 / OoOoOO00
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # OoooooooOO + I1ii11iIi11i + OoooooooOO . I1Ii111
 red ( OooOOooo . print_address ( ) , False ) , map_notify . retry_count ) )
 if 69 - 69: I1IiiI . I1ii11iIi11i . o0oOOo0O0Ooo + OoooooooOO
 lisp_send_map_notify ( ooOo0o00 , map_notify . packet , OooOOooo , O00oo0o0o0oo )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 52 - 52: i1IIi - oO0o
 if 33 - 33: Ii1I / I1ii11iIi11i . ooOoO0o . OoooooooOO
 if 45 - 45: OoO0O00 . I1ii11iIi11i + Ii1I / I11i - ooOoO0o / OoooooooOO
 if 44 - 44: OoO0O00 % O0 * IiII + iII111i
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 79 - 79: ooOoO0o
 if 82 - 82: O0 - Oo0Ooo - i11iIiiIii
 if 9 - 9: OoooooooOO . i11iIiiIii * iIii1I11I1II1 / IiII * i11iIiiIii
 if 57 - 57: o0oOOo0O0Ooo . I1IiiI / iII111i / ooOoO0o - OoO0O00
 if 8 - 8: iIii1I11I1II1 % ooOoO0o + OoO0O00 . oO0o % I1IiiI - O0
 if 25 - 25: i11iIiiIii * OoOoOO00 + OoO0O00 . o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + i1IIi / iII111i % O0 + II111iiii * i1IIi
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 49 - 49: o0oOOo0O0Ooo + OOooOOo - II111iiii
 if 34 - 34: ooOoO0o . I1Ii111
 if 52 - 52: I1IiiI + I1Ii111 * oO0o / i11iIiiIii * iIii1I11I1II1
 if 27 - 27: Oo0Ooo
 eid_record . rloc_count = len ( parent . registered_rlocs )
 ooI1IIiIiii = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 73 - 73: II111iiii . i1IIi
 if 80 - 80: i11iIiiIii % II111iiii / OoO0O00 - o0oOOo0O0Ooo * I11i . I1IiiI
 if 86 - 86: OoO0O00
 if 86 - 86: I1Ii111 - OoOoOO00 . o0oOOo0O0Ooo % oO0o
 for iiiiIi1I in parent . registered_rlocs :
  Oo000O = lisp_rloc_record ( )
  Oo000O . store_rloc_entry ( iiiiIi1I )
  Oo000O . local_bit = True
  Oo000O . probe_bit = False
  Oo000O . reach_bit = True
  ooI1IIiIiii += Oo000O . encode ( )
  Oo000O . print_record ( "  " )
  del ( Oo000O )
  if 45 - 45: o0oOOo0O0Ooo + iIii1I11I1II1 / O0
  if 2 - 2: I11i + I1IiiI . IiII . OoOoOO00 * oO0o - ooOoO0o
  if 29 - 29: OoO0O00
  if 78 - 78: iII111i * ooOoO0o + O0 % ooOoO0o + OoO0O00
  if 41 - 41: II111iiii . oO0o + O0 % i1IIi . Ii1I
 for iiiiIi1I in parent . registered_rlocs :
  OooOOooo = iiiiIi1I . rloc
  O0oo0o0Oo0oo = lisp_map_notify ( lisp_sockets )
  O0oo0o0Oo0oo . record_count = 1
  oo0OO0oo = map_register . key_id
  O0oo0o0Oo0oo . key_id = oo0OO0oo
  O0oo0o0Oo0oo . alg_id = map_register . alg_id
  O0oo0o0Oo0oo . auth_len = map_register . auth_len
  O0oo0o0Oo0oo . nonce = map_register . nonce
  O0oo0o0Oo0oo . nonce_key = lisp_hex_string ( O0oo0o0Oo0oo . nonce )
  O0oo0o0Oo0oo . etr . copy_address ( OooOOooo )
  O0oo0o0Oo0oo . etr_port = map_register . sport
  O0oo0o0Oo0oo . site = parent . site
  OO0Oo00OO0oo = O0oo0o0Oo0oo . encode ( ooI1IIiIiii , parent . site . auth_key [ oo0OO0oo ] )
  O0oo0o0Oo0oo . print_notify ( )
  if 20 - 20: iII111i - I11i / I1ii11iIi11i * O0 + IiII % I11i
  if 69 - 69: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO - ooOoO0o
  if 94 - 94: iIii1I11I1II1 / Oo0Ooo % IiII * IiII
  if 62 - 62: I11i . IiII - OOooOOo - I1Ii111 / OoooooooOO . Ii1I
  III11II111 = O0oo0o0Oo0oo . nonce_key
  if ( III11II111 in lisp_map_notify_queue ) :
   I1II1 = lisp_map_notify_queue [ III11II111 ]
   I1II1 . retransmit_timer . cancel ( )
   del ( I1II1 )
   if 48 - 48: IiII + OoOoOO00 % I1Ii111
  lisp_map_notify_queue [ III11II111 ] = O0oo0o0Oo0oo
  if 6 - 6: I1IiiI * ooOoO0o * O0 + OOooOOo
  if 11 - 11: i1IIi / OoOoOO00 + OoOoOO00 + I1ii11iIi11i + OOooOOo
  if 21 - 21: ooOoO0o
  if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( OooOOooo . print_address ( ) , False ) ) )
  if 81 - 81: oO0o
  lisp_send ( lisp_sockets , OooOOooo , LISP_CTRL_PORT , OO0Oo00OO0oo )
  if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
  parent . site . map_notifies_sent += 1
  if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
  if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
  if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
  if 33 - 33: I11i
  O0oo0o0Oo0oo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ O0oo0o0Oo0oo ] )
  O0oo0o0Oo0oo . retransmit_timer . start ( )
  if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
 return
 if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
 if 32 - 32: oO0o
 if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
 if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
 if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
 if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 94 - 94: Ii1I
 III11II111 = lisp_hex_string ( nonce ) + source . print_address ( )
 if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
 if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
 if 34 - 34: iIii1I11I1II1
 if 47 - 47: OOooOOo * iII111i
 if 71 - 71: IiII - OoooooooOO * i11iIiiIii . OoooooooOO % i1IIi . Oo0Ooo
 if 3 - 3: OoO0O00 + i11iIiiIii + oO0o * IiII
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( III11II111 in lisp_map_notify_queue ) :
  O0oo0o0Oo0oo = lisp_map_notify_queue [ III11II111 ]
  o0O0o0000o0O0 = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( O0oo0o0Oo0oo . nonce ) , o0O0o0000o0O0 ) )
  if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
  return
  if 70 - 70: OoO0O00
  if 42 - 42: OoooooooOO - I1Ii111 + I1ii11iIi11i * iII111i * iII111i / OoO0O00
 O0oo0o0Oo0oo = lisp_map_notify ( lisp_sockets )
 O0oo0o0Oo0oo . record_count = record_count
 key_id = key_id
 O0oo0o0Oo0oo . key_id = key_id
 O0oo0o0Oo0oo . alg_id = alg_id
 O0oo0o0Oo0oo . auth_len = auth_len
 O0oo0o0Oo0oo . nonce = nonce
 O0oo0o0Oo0oo . nonce_key = lisp_hex_string ( nonce )
 O0oo0o0Oo0oo . etr . copy_address ( source )
 O0oo0o0Oo0oo . etr_port = port
 O0oo0o0Oo0oo . site = site
 O0oo0o0Oo0oo . eid_list = eid_list
 if 85 - 85: O0 . II111iiii
 if 80 - 80: O0 * I11i * I1Ii111
 if 89 - 89: Ii1I * OoO0O00 . i1IIi . O0 - IiII - OoOoOO00
 if 25 - 25: iII111i + i1IIi
 if ( map_register_ack == False ) :
  III11II111 = O0oo0o0Oo0oo . nonce_key
  lisp_map_notify_queue [ III11II111 ] = O0oo0o0Oo0oo
  if 64 - 64: IiII % I11i / iIii1I11I1II1
  if 66 - 66: Ii1I
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 55 - 55: OOooOOo + I1IiiI + IiII . Ii1I * oO0o
  if 71 - 71: IiII - iII111i % I1IiiI * iII111i
  if 27 - 27: ooOoO0o - OoO0O00
  if 83 - 83: iII111i * OoOoOO00 - O0 * Ii1I
  if 79 - 79: I11i / iII111i % Ii1I / OoOoOO00 % O0 / IiII
 OO0Oo00OO0oo = O0oo0o0Oo0oo . encode ( eid_records , site . auth_key [ key_id ] )
 O0oo0o0Oo0oo . print_notify ( )
 if 32 - 32: IiII * II111iiii . Ii1I
 if ( map_register_ack == False ) :
  iI1111Ii1I = lisp_eid_record ( )
  iI1111Ii1I . decode ( eid_records )
  iI1111Ii1I . print_record ( "  " , False )
  if 68 - 68: I11i / O0
  if 6 - 6: oO0o - oO0o . I1IiiI % I1ii11iIi11i
  if 22 - 22: Ii1I / I1IiiI / II111iiii
  if 31 - 31: II111iiii - Ii1I * OOooOOo - i11iIiiIii / OoooooooOO - I1Ii111
  if 76 - 76: Oo0Ooo
 lisp_send_map_notify ( lisp_sockets , OO0Oo00OO0oo , O0oo0o0Oo0oo . etr , port )
 site . map_notifies_sent += 1
 if 93 - 93: i1IIi - I1IiiI * i11iIiiIii / Ii1I . Ii1I - i1IIi
 if ( map_register_ack ) : return
 if 19 - 19: iIii1I11I1II1 * OOooOOo * Oo0Ooo % I1IiiI
 if 93 - 93: IiII % OoOoOO00 / I1IiiI + o0oOOo0O0Ooo * ooOoO0o / i1IIi
 if 25 - 25: O0 / Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo
 if 45 - 45: Ii1I * IiII - OOooOOo
 if 57 - 57: iII111i % OoO0O00 / OoooooooOO
 if 69 - 69: oO0o
 O0oo0o0Oo0oo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ O0oo0o0Oo0oo ] )
 O0oo0o0Oo0oo . retransmit_timer . start ( )
 return
 if 44 - 44: IiII - II111iiii % Ii1I
 if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
 if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
 if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
 if 59 - 59: OoOoOO00
 if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
 if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
 if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 62 - 62: Oo0Ooo . II111iiii % OoO0O00 . Ii1I * OOooOOo + II111iiii
 if 7 - 7: OOooOOo
 if 22 - 22: Oo0Ooo + ooOoO0o
 if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
 map_notify . record_count = 0
 OO0Oo00OO0oo = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
 if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
 if 26 - 26: Oo0Ooo . Ii1I
 if 7 - 7: OoOoOO00 - o0oOOo0O0Ooo + oO0o
 OooOOooo = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( OooOOooo . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , OooOOooo , LISP_CTRL_PORT , OO0Oo00OO0oo )
 return
 if 8 - 8: iIii1I11I1II1
 if 6 - 6: oO0o
 if 51 - 51: I1Ii111 - o0oOOo0O0Ooo
 if 5 - 5: O0
 if 7 - 7: OoOoOO00 + OoO0O00 * I1IiiI
 if 63 - 63: I1ii11iIi11i + iII111i * i1IIi
 if 63 - 63: I1ii11iIi11i / II111iiii % oO0o + ooOoO0o . Ii1I % I11i
 if 59 - 59: I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 5 - 5: I1IiiI
 O0oo0o0Oo0oo = lisp_map_notify ( lisp_sockets )
 O0oo0o0Oo0oo . record_count = 1
 O0oo0o0Oo0oo . nonce = lisp_get_control_nonce ( )
 O0oo0o0Oo0oo . nonce_key = lisp_hex_string ( O0oo0o0Oo0oo . nonce )
 O0oo0o0Oo0oo . etr . copy_address ( xtr )
 O0oo0o0Oo0oo . etr_port = LISP_CTRL_PORT
 O0oo0o0Oo0oo . eid_list = eid_list
 III11II111 = O0oo0o0Oo0oo . nonce_key
 if 22 - 22: II111iiii / iII111i
 if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
 if 62 - 62: O0 % o0oOOo0O0Ooo + iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
 if 21 - 21: o0oOOo0O0Ooo % O0
 if 81 - 81: i1IIi + i1IIi
 if 3 - 3: I1Ii111 . I1ii11iIi11i * iII111i * i11iIiiIii * IiII
 lisp_remove_eid_from_map_notify_queue ( O0oo0o0Oo0oo . eid_list )
 if ( III11II111 in lisp_map_notify_queue ) :
  O0oo0o0Oo0oo = lisp_map_notify_queue [ III11II111 ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( O0oo0o0Oo0oo . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 52 - 52: iIii1I11I1II1 % o0oOOo0O0Ooo % I1IiiI
  return
  if 71 - 71: I1IiiI + iII111i
  if 47 - 47: iIii1I11I1II1 . OoO0O00 . iIii1I11I1II1
  if 57 - 57: IiII * ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + OoOoOO00
  if 83 - 83: OoOoOO00 . Oo0Ooo . OoO0O00
  if 65 - 65: iII111i * iIii1I11I1II1
 lisp_map_notify_queue [ III11II111 ] = O0oo0o0Oo0oo
 if 48 - 48: iII111i * OoO0O00
 if 57 - 57: ooOoO0o + I1IiiI
 if 32 - 32: I1ii11iIi11i + OOooOOo - I11i
 if 82 - 82: Oo0Ooo % Oo0Ooo
 if 91 - 91: I11i
 if 98 - 98: I11i - II111iiii . IiII % Oo0Ooo
 oOoO0O0 = site_eid . rtrs_in_rloc_set ( )
 if 73 - 73: i1IIi / OoOoOO00 - I1IiiI + I1ii11iIi11i
 if 8 - 8: oO0o
 if 65 - 65: OOooOOo + i1IIi * Ii1I % iIii1I11I1II1 . OOooOOo % I1ii11iIi11i
 if 98 - 98: OoooooooOO . o0oOOo0O0Ooo % OOooOOo / O0 + I1Ii111 % i11iIiiIii
 iI1111Ii1I = lisp_eid_record ( )
 iI1111Ii1I . record_ttl = 1440
 iI1111Ii1I . eid . copy_address ( site_eid . eid )
 iI1111Ii1I . group . copy_address ( site_eid . group )
 iI1111Ii1I . rloc_count = 0
 for oO0O0oOOO0 in site_eid . registered_rlocs :
  if ( oOoO0O0 ^ oO0O0oOOO0 . is_rtr ( ) ) : continue
  iI1111Ii1I . rloc_count += 1
  if 94 - 94: O0 + II111iiii - iII111i / i1IIi
 OO0Oo00OO0oo = iI1111Ii1I . encode ( )
 if 25 - 25: ooOoO0o . OoO0O00 - oO0o
 if 76 - 76: iIii1I11I1II1 / II111iiii * OoOoOO00 % iII111i . II111iiii + i11iIiiIii
 if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i
 if 53 - 53: I11i
 O0oo0o0Oo0oo . print_notify ( )
 iI1111Ii1I . print_record ( "  " , False )
 if 64 - 64: OoO0O00 + I11i / I1IiiI . II111iiii
 if 79 - 79: I1Ii111 + IiII / OoooooooOO
 if 53 - 53: Ii1I
 if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
 Oo0iIiIii = [ ]
 for oO0O0oOOO0 in site_eid . registered_rlocs :
  if ( oOoO0O0 ) :
   if ( oO0O0oOOO0 . is_rtr ( ) ) :
    Oo0iIiIii . append ( oO0O0oOOO0 . rloc )
    continue
    if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
    if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
    if 33 - 33: oO0o . oO0o / IiII + II111iiii
    if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
    if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
    if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
  Oo000O = lisp_rloc_record ( )
  Oo000O . store_rloc_entry ( oO0O0oOOO0 )
  Oo000O . local_bit = True
  Oo000O . probe_bit = False
  Oo000O . reach_bit = True
  OO0Oo00OO0oo += Oo000O . encode ( )
  Oo000O . print_record ( "    " )
  if 25 - 25: OoO0O00
  if 83 - 83: II111iiii . iIii1I11I1II1
  if 77 - 77: O0 . OoOoOO00 % oO0o / OOooOOo
  if 8 - 8: iII111i - i1IIi
  if 81 - 81: ooOoO0o / OOooOOo % OoOoOO00 . iIii1I11I1II1
 OO0Oo00OO0oo = O0oo0o0Oo0oo . encode ( OO0Oo00OO0oo , "" )
 if ( OO0Oo00OO0oo == None ) : return
 if 45 - 45: I1IiiI . ooOoO0o - OoooooooOO
 if 84 - 84: I1ii11iIi11i
 if 69 - 69: I1Ii111 + II111iiii
 if 92 - 92: OoooooooOO
 if ( Oo0iIiIii != [ ] ) :
  for oOo in Oo0iIiIii :
   lisp_send_map_notify ( lisp_sockets , OO0Oo00OO0oo , oOo , LISP_CTRL_PORT )
   if 80 - 80: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . oO0o % I1IiiI % I11i
 else :
  lisp_send_map_notify ( lisp_sockets , OO0Oo00OO0oo , xtr , LISP_CTRL_PORT )
  if 4 - 4: OoO0O00 / iII111i / I1ii11iIi11i - o0oOOo0O0Ooo * I1Ii111
  if 24 - 24: OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - o0oOOo0O0Ooo . I1ii11iIi11i
  if 2 - 2: I1IiiI . o0oOOo0O0Ooo / Oo0Ooo - OoOoOO00 - OoooooooOO
  if 73 - 73: I1Ii111 . i11iIiiIii * ooOoO0o . IiII - I11i + I1Ii111
  if 21 - 21: I1Ii111 + iIii1I11I1II1 + I1IiiI / O0 * I1ii11iIi11i
 O0oo0o0Oo0oo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ O0oo0o0Oo0oo ] )
 O0oo0o0Oo0oo . retransmit_timer . start ( )
 return
 if 57 - 57: OOooOOo * I11i . oO0o
 if 17 - 17: iII111i - OOooOOo * I1IiiI + i1IIi % I1ii11iIi11i
 if 71 - 71: Ii1I - o0oOOo0O0Ooo - oO0o
 if 27 - 27: O0 - iIii1I11I1II1
 if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
 if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
 if 97 - 97: i11iIiiIii + I1ii11iIi11i - I11i . oO0o
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 O00oOOOooO0O = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 69 - 69: IiII / O0 * ooOoO0o . OoOoOO00 * OoooooooOO
 for iiiiiIIii11I in rle_list :
  I1ii1 = lisp_site_eid_lookup ( iiiiiIIii11I [ 0 ] , iiiiiIIii11I [ 1 ] , True )
  if ( I1ii1 == None ) : continue
  if 58 - 58: I1Ii111 / o0oOOo0O0Ooo
  if 40 - 40: ooOoO0o * OoooooooOO + O0 . i11iIiiIii - OoOoOO00
  if 3 - 3: IiII + OOooOOo * OoO0O00 * OOooOOo
  if 66 - 66: ooOoO0o / Ii1I * OoO0O00 * i11iIiiIii
  if 69 - 69: I11i % i11iIiiIii
  if 34 - 34: Ii1I . OoooooooOO + II111iiii % oO0o
  if 69 - 69: i11iIiiIii % I1IiiI * i11iIiiIii - OoO0O00 * iIii1I11I1II1
  O0oooOoO0 = I1ii1 . registered_rlocs
  if ( len ( O0oooOoO0 ) == 0 ) :
   OooOoO00 = { }
   for IiII1I1 in list ( I1ii1 . individual_registrations . values ( ) ) :
    for oO0O0oOOO0 in IiII1I1 . registered_rlocs :
     if ( oO0O0oOOO0 . is_rtr ( ) == False ) : continue
     OooOoO00 [ oO0O0oOOO0 . rloc . print_address ( ) ] = oO0O0oOOO0
     if 89 - 89: OOooOOo
     if 16 - 16: Ii1I
   O0oooOoO0 = list ( OooOoO00 . values ( ) )
   if 57 - 57: i1IIi + OoO0O00 % OOooOOo - o0oOOo0O0Ooo / I1IiiI + OoO0O00
   if 73 - 73: OoO0O00 / Oo0Ooo / o0oOOo0O0Ooo
   if 3 - 3: II111iiii % OoOoOO00 * OoO0O00 / o0oOOo0O0Ooo * i11iIiiIii . O0
   if 35 - 35: I1IiiI - i1IIi
   if 29 - 29: I1ii11iIi11i + ooOoO0o - OoOoOO00 / II111iiii
   if 12 - 12: I1IiiI + i1IIi % i11iIiiIii / I1IiiI - iIii1I11I1II1
  iiII1I = [ ]
  II1 = False
  if ( I1ii1 . eid . address == 0 and I1ii1 . eid . mask_len == 0 ) :
   ooo0O0OoO00O0 = [ ]
   IiiI = [ ]
   if ( len ( O0oooOoO0 ) != 0 and O0oooOoO0 [ 0 ] . rle != None ) :
    IiiI = O0oooOoO0 [ 0 ] . rle . rle_nodes
    if 1 - 1: OoooooooOO / II111iiii . I1ii11iIi11i % II111iiii
   for iIiII in IiiI :
    iiII1I . append ( iIiII . address )
    ooo0O0OoO00O0 . append ( iIiII . address . print_address_no_iid ( ) )
    if 26 - 26: I1IiiI * OOooOOo + I1ii11iIi11i - I11i
   lprint ( "Notify existing RLE-nodes {}" . format ( ooo0O0OoO00O0 ) )
  else :
   if 42 - 42: I11i % OoOoOO00 - OoOoOO00
   if 31 - 31: O0 - O0 / oO0o - O0 . OOooOOo
   if 84 - 84: i11iIiiIii - OOooOOo / OoO0O00 . OOooOOo + OoOoOO00
   if 7 - 7: o0oOOo0O0Ooo * I1Ii111 * o0oOOo0O0Ooo - OoO0O00 * Oo0Ooo - IiII
   if 10 - 10: i1IIi - OoOoOO00
   for oO0O0oOOO0 in O0oooOoO0 :
    if ( oO0O0oOOO0 . is_rtr ( ) ) : iiII1I . append ( oO0O0oOOO0 . rloc )
    if 25 - 25: o0oOOo0O0Ooo . I1IiiI % iIii1I11I1II1 * Ii1I % I1IiiI * I11i
    if 21 - 21: O0 % II111iiii % OoOoOO00 / Ii1I * ooOoO0o
    if 82 - 82: I1IiiI % II111iiii * iIii1I11I1II1
    if 83 - 83: O0 + i1IIi
    if 47 - 47: iIii1I11I1II1 * i11iIiiIii % Ii1I + IiII
   II1 = ( len ( iiII1I ) != 0 )
   if ( II1 == False ) :
    ooo0OOO00 = lisp_site_eid_lookup ( iiiiiIIii11I [ 0 ] , O00oOOOooO0O , False )
    if ( ooo0OOO00 == None ) : continue
    if 39 - 39: i1IIi / i11iIiiIii % ooOoO0o - ooOoO0o % i1IIi
    for oO0O0oOOO0 in ooo0OOO00 . registered_rlocs :
     if ( oO0O0oOOO0 . rloc . is_null ( ) ) : continue
     iiII1I . append ( oO0O0oOOO0 . rloc )
     if 73 - 73: OoO0O00 . iII111i / OOooOOo
     if 50 - 50: O0 / IiII % oO0o / I1Ii111 % IiII
     if 10 - 10: OoooooooOO
     if 39 - 39: I11i . I1IiiI % Oo0Ooo + oO0o
     if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
     if 82 - 82: IiII % ooOoO0o
   if ( len ( iiII1I ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( I1ii1 . print_eid_tuple ( ) , False ) ) )
    if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
    continue
    if 27 - 27: Oo0Ooo . I1Ii111 - i1IIi * I1IiiI
    if 96 - 96: I1ii11iIi11i - Ii1I . I1ii11iIi11i
    if 89 - 89: II111iiii % I1ii11iIi11i % IiII . I11i
    if 49 - 49: iII111i % i11iIiiIii * I11i - oO0o . OOooOOo . i11iIiiIii
    if 26 - 26: iIii1I11I1II1 + i11iIiiIii % iII111i + I1IiiI + oO0o - ooOoO0o
    if 4 - 4: Oo0Ooo - IiII - I11i
  for iiiiIi1I in iiII1I :
   lprint ( "Build Map-Notify for {}" . format (
 green ( I1ii1 . print_eid_tuple ( ) , False ) ) )
   if 72 - 72: OoooooooOO
   iIO00O00o0Oo00 = [ I1ii1 . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , I1ii1 , iIO00O00o0Oo00 , iiiiIi1I )
   time . sleep ( .001 )
   if 85 - 85: i11iIiiIii . o0oOOo0O0Ooo * iII111i . I1ii11iIi11i / I1Ii111 % Ii1I
   if 27 - 27: II111iiii . iIii1I11I1II1 / I1ii11iIi11i / i1IIi / iIii1I11I1II1
 return
 if 70 - 70: i11iIiiIii . OoO0O00 / OoooooooOO * OoooooooOO - OOooOOo
 if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
 if 39 - 39: OoO0O00 + IiII - II111iiii % I11i
 if 80 - 80: o0oOOo0O0Ooo * ooOoO0o
 if 87 - 87: I1Ii111 + O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - IiII
 if 24 - 24: OoOoOO00
 if 19 - 19: ooOoO0o
 if 43 - 43: O0 . I1Ii111 % OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for iIiIIi in range ( rloc_count ) :
  Oo000O = lisp_rloc_record ( )
  packet = Oo000O . decode ( packet , None )
  i11iIiII = Oo000O . json
  if ( i11iIiII == None ) : continue
  if 17 - 17: IiII * I11i / o0oOOo0O0Ooo . OoooooooOO * I1IiiI . ooOoO0o
  try :
   i11iIiII = json . loads ( i11iIiII . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 39 - 39: I1ii11iIi11i . I1Ii111 % iII111i
   if 5 - 5: II111iiii . I1IiiI . OoooooooOO * II111iiii * Oo0Ooo
  if ( "signature" not in i11iIiII ) : continue
  return ( Oo000O )
  if 45 - 45: OOooOOo
 return ( None )
 if 65 - 65: I1Ii111 % OOooOOo
 if 35 - 35: OOooOOo * oO0o
 if 19 - 19: iIii1I11I1II1 + IiII * iII111i - IiII
 if 87 - 87: o0oOOo0O0Ooo - I1Ii111
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
 if 5 - 5: OoOoOO00 + i1IIi
 if 43 - 43: iII111i * I1IiiI
 if 20 - 20: I1IiiI . I11i * OoO0O00 . ooOoO0o . II111iiii
 if 6 - 6: Ii1I * OoOoOO00 % IiII + I11i
 if 20 - 20: oO0o
def lisp_get_eid_hash ( eid ) :
 Ii1I1I = None
 for Oo0o0OOoOo in lisp_eid_hashes :
  if 44 - 44: II111iiii + oO0o - i11iIiiIii * ooOoO0o
  if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
  if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
  if 26 - 26: O0
  oO0O = Oo0o0OOoOo . instance_id
  if ( oO0O == - 1 ) : Oo0o0OOoOo . instance_id = eid . instance_id
  if 97 - 97: OOooOOo + I11i % I1Ii111 % i11iIiiIii / I1ii11iIi11i
  IiiiiiOoO0 = eid . is_more_specific ( Oo0o0OOoOo )
  Oo0o0OOoOo . instance_id = oO0O
  if ( IiiiiiOoO0 ) :
   Ii1I1I = 128 - Oo0o0OOoOo . mask_len
   break
   if 22 - 22: OoOoOO00 - Oo0Ooo / i11iIiiIii
   if 44 - 44: iIii1I11I1II1 + o0oOOo0O0Ooo . O0 + I1ii11iIi11i + I11i . I1Ii111
 if ( Ii1I1I == None ) : return ( None )
 if 48 - 48: Ii1I . iIii1I11I1II1 - iIii1I11I1II1 * I11i . OoooooooOO
 iii1 = eid . address
 O0Ooo = ""
 for iIiIIi in range ( 0 , old_div ( Ii1I1I , 16 ) ) :
  OOOo = iii1 & 0xffff
  OOOo = hex ( OOOo ) [ 2 : : ]
  O0Ooo = OOOo . zfill ( 4 ) + ":" + O0Ooo
  iii1 >>= 16
  if 11 - 11: i11iIiiIii * OOooOOo / I1Ii111 + iIii1I11I1II1 + OoOoOO00 % OoOoOO00
 if ( Ii1I1I % 16 != 0 ) :
  OOOo = iii1 & 0xff
  OOOo = hex ( OOOo ) [ 2 : : ]
  O0Ooo = OOOo . zfill ( 2 ) + ":" + O0Ooo
  if 8 - 8: OoO0O00
 return ( O0Ooo [ 0 : - 1 ] )
 if 33 - 33: oO0o
 if 31 - 31: I1IiiI % o0oOOo0O0Ooo . i11iIiiIii % OOooOOo - iIii1I11I1II1
 if 77 - 77: i11iIiiIii / OOooOOo
 if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
 if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
 if 59 - 59: oO0o * OoO0O00 - I11i * I1IiiI
 if 60 - 60: iII111i - OoooooooOO / iII111i % OoO0O00 . OoOoOO00 - o0oOOo0O0Ooo
 if 71 - 71: iII111i * o0oOOo0O0Ooo * i11iIiiIii * O0
 if 77 - 77: OOooOOo % iII111i + I11i / OoOoOO00
 if 50 - 50: OoOoOO00 - i11iIiiIii - OOooOOo . iIii1I11I1II1
 if 97 - 97: oO0o % OOooOOo . OoooooooOO * Ii1I
def lisp_lookup_public_key ( eid ) :
 oO0O = eid . instance_id
 if 100 - 100: I1ii11iIi11i / Ii1I % Oo0Ooo
 if 83 - 83: O0 . I1Ii111 % I1ii11iIi11i
 if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
 if 12 - 12: ooOoO0o
 if 56 - 56: i1IIi
 I11II1iIi = lisp_get_eid_hash ( eid )
 if ( I11II1iIi == None ) : return ( [ None , None , False ] )
 if 81 - 81: oO0o - I1IiiI
 I11II1iIi = "hash-" + I11II1iIi
 ooOoo0 = lisp_address ( LISP_AFI_NAME , I11II1iIi , len ( I11II1iIi ) , oO0O )
 iII1I1i = lisp_address ( LISP_AFI_NONE , "" , 0 , oO0O )
 if 40 - 40: OoOoOO00 - I11i . o0oOOo0O0Ooo + i11iIiiIii . iII111i
 if 5 - 5: i11iIiiIii - OoooooooOO - I11i . Ii1I
 if 83 - 83: Oo0Ooo * II111iiii + Ii1I
 if 59 - 59: iII111i % OoO0O00 / Oo0Ooo + I1ii11iIi11i % Ii1I
 ooo0OOO00 = lisp_site_eid_lookup ( ooOoo0 , iII1I1i , True )
 if ( ooo0OOO00 == None ) : return ( [ ooOoo0 , None , False ] )
 if 59 - 59: O0 + oO0o . IiII . IiII / OoOoOO00 / II111iiii
 if 2 - 2: I1Ii111
 if 45 - 45: OOooOOo * ooOoO0o
 if 77 - 77: i11iIiiIii / OOooOOo % i11iIiiIii
 iiI1i1iIIIii = None
 for OOOo0 in ooo0OOO00 . registered_rlocs :
  ii1iIIIii = OOOo0 . json
  if ( ii1iIIIii == None ) : continue
  try :
   ii1iIIIii = json . loads ( ii1iIIIii . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( I11II1iIi ) )
   if 33 - 33: I1ii11iIi11i / OoooooooOO . i1IIi - I1ii11iIi11i + OoO0O00
   return ( [ ooOoo0 , None , False ] )
   if 37 - 37: IiII * I1IiiI % O0
  if ( "public-key" not in ii1iIIIii ) : continue
  iiI1i1iIIIii = ii1iIIIii [ "public-key" ]
  break
  if 32 - 32: ooOoO0o % II111iiii
 return ( [ ooOoo0 , iiI1i1iIIIii , True ] )
 if 60 - 60: i11iIiiIii
 if 11 - 11: o0oOOo0O0Ooo
 if 77 - 77: o0oOOo0O0Ooo / iIii1I11I1II1 * iIii1I11I1II1 / o0oOOo0O0Ooo * iII111i
 if 26 - 26: Ii1I
 if 1 - 1: OoOoOO00 . o0oOOo0O0Ooo + Oo0Ooo % Oo0Ooo * I1ii11iIi11i
 if 50 - 50: IiII / i1IIi . I1ii11iIi11i
 if 75 - 75: I11i * oO0o + OoooooooOO . iII111i + OoO0O00
 if 44 - 44: II111iiii
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 65 - 65: I11i . iII111i . I1IiiI - Oo0Ooo % iIii1I11I1II1 / O0
 if 54 - 54: iII111i - I1Ii111
 if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
 if 7 - 7: i1IIi
 if 30 - 30: oO0o . i1IIi / I11i
 IIIIi1iII = json . loads ( rloc_record . json . json_string )
 if 23 - 23: i1IIi + oO0o % iII111i - OoO0O00 - i1IIi
 if ( lisp_get_eid_hash ( eid ) ) :
  iIII = eid
 elif ( "signature-eid" in IIIIi1iII ) :
  O0o0OoO = IIIIi1iII [ "signature-eid" ]
  iIII = lisp_address ( LISP_AFI_IPV6 , O0o0OoO , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 2 - 2: oO0o - o0oOOo0O0Ooo
  if 80 - 80: i1IIi
  if 40 - 40: O0 . ooOoO0o * iII111i . I11i + I1Ii111 % OoO0O00
  if 9 - 9: IiII * oO0o - o0oOOo0O0Ooo
  if 17 - 17: iII111i % Oo0Ooo
 ooOoo0 , iiI1i1iIIIii , Ii11IiiI = lisp_lookup_public_key ( iIII )
 if ( ooOoo0 == None ) :
  ooOo000OoO0o = green ( iIII . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( ooOo000OoO0o ) )
  return ( False )
  if 69 - 69: OoooooooOO - OoooooooOO * ooOoO0o / oO0o * iIii1I11I1II1 . II111iiii
  if 61 - 61: oO0o . I1IiiI + i1IIi
 OoOo = "found" if Ii11IiiI else bold ( "not found" , False )
 ooOo000OoO0o = green ( ooOoo0 . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( ooOo000OoO0o , OoOo ) )
 if ( Ii11IiiI == False ) : return ( False )
 if 48 - 48: ooOoO0o - Ii1I - I11i
 if ( iiI1i1iIIIii == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 70 - 70: O0 * I11i . i1IIi - ooOoO0o
  if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
 Oooo0 = iiI1i1iIIIii [ 0 : 8 ] + "..." + iiI1i1iIIIii [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( Oooo0 ) )
 if 57 - 57: OOooOOo
 if 76 - 76: Oo0Ooo . I1Ii111 + iII111i / OoooooooOO . Oo0Ooo
 if 68 - 68: OoO0O00 % OoO0O00 + i11iIiiIii / Ii1I
 if 20 - 20: I1Ii111 + IiII - O0 + IiII / i1IIi
 if 100 - 100: OoooooooOO
 i1iIiII1II11i = IIIIi1iII [ "signature" ]
 if 70 - 70: o0oOOo0O0Ooo + o0oOOo0O0Ooo . OOooOOo % I11i
 try :
  IIIIi1iII = binascii . a2b_base64 ( i1iIiII1II11i )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 48 - 48: Oo0Ooo
  if 27 - 27: OoOoOO00 . O0 / i11iIiiIii + O0 % OoooooooOO % OoO0O00
 ooO00Oo0OOOo = len ( IIIIi1iII )
 if ( ooO00Oo0OOOo & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( ooO00Oo0OOOo ) )
  return ( False )
  if 14 - 14: Ii1I * II111iiii
  if 12 - 12: IiII / Ii1I
  if 54 - 54: Oo0Ooo + Ii1I % OoooooooOO * OOooOOo / OoOoOO00
  if 39 - 39: I1IiiI % i11iIiiIii % Ii1I
  if 59 - 59: ooOoO0o % OoO0O00 / I1IiiI - II111iiii + OoooooooOO * i11iIiiIii
 O00O0oO = iIII . print_address ( )
 if 58 - 58: IiII / Oo0Ooo + o0oOOo0O0Ooo
 if 71 - 71: Ii1I - IiII
 if 2 - 2: OoOoOO00 % IiII % OoO0O00 . i1IIi / I1Ii111 - iIii1I11I1II1
 if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
 iiI1i1iIIIii = binascii . a2b_base64 ( iiI1i1iIIIii )
 try :
  III11II111 = ecdsa . VerifyingKey . from_pem ( iiI1i1iIIIii )
 except :
  o0Oooo00oO0o00 = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( o0Oooo00oO0o00 ) )
  return ( False )
  if 31 - 31: I11i - oO0o * ooOoO0o
  if 64 - 64: I11i
  if 41 - 41: I1Ii111 * OoooooooOO / OoOoOO00 + OoO0O00 . OoOoOO00 + I1Ii111
  if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
  if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
  if 43 - 43: Oo0Ooo % I11i
  if 53 - 53: OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
  if 47 - 47: iIii1I11I1II1 - OOooOOo + I1ii11iIi11i * ooOoO0o + Oo0Ooo + OoO0O00
  if 64 - 64: OoOoOO00 - OoOoOO00 . OoooooooOO + ooOoO0o
  if 100 - 100: ooOoO0o . OoooooooOO % i1IIi % OoO0O00
  if 26 - 26: OoOoOO00 * IiII
 try :
  I1I1i111 = III11II111 . verify ( IIIIi1iII , O00O0oO . encode ( ) , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( O00O0oO ) )
  if 76 - 76: I1IiiI + IiII * I1ii11iIi11i * I1IiiI % Ii1I + ooOoO0o
  lprint ( "  Signature used '{}'" . format ( i1iIiII1II11i ) )
  return ( False )
  if 46 - 46: OoOoOO00
 return ( I1I1i111 )
 if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
 if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
 if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
 if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
 if 20 - 20: IiII
 if 81 - 81: Oo0Ooo / I1Ii111
 if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
 if 51 - 51: iII111i - ooOoO0o
 if 32 - 32: IiII - i11iIiiIii
 if 41 - 41: Ii1I % Ii1I * oO0o - I11i + iIii1I11I1II1 . ooOoO0o
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
 if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
 if 49 - 49: I1Ii111 . OoooooooOO / o0oOOo0O0Ooo - iII111i - iII111i - i11iIiiIii
 if 37 - 37: OOooOOo
 if 79 - 79: I1Ii111 - OoO0O00 + ooOoO0o + oO0o . i11iIiiIii + i1IIi
 I1IIi11 = [ ]
 for I1I1I in eid_list :
  for ii1iiIIII1I1 in lisp_map_notify_queue :
   O0oo0o0Oo0oo = lisp_map_notify_queue [ ii1iiIIII1I1 ]
   if ( I1I1I not in O0oo0o0Oo0oo . eid_list ) : continue
   if 11 - 11: IiII * i11iIiiIii % IiII
   I1IIi11 . append ( ii1iiIIII1I1 )
   iI1Ii1I = O0oo0o0Oo0oo . retransmit_timer
   if ( iI1Ii1I ) : iI1Ii1I . cancel ( )
   if 58 - 58: Oo0Ooo / ooOoO0o * ooOoO0o * OoO0O00
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( O0oo0o0Oo0oo . nonce_key , green ( I1I1I , False ) ) )
   if 52 - 52: O0
   if 90 - 90: I11i / Oo0Ooo . II111iiii / ooOoO0o - OOooOOo
   if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
   if 20 - 20: ooOoO0o - i11iIiiIii
   if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
   if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
   if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
 for ii1iiIIII1I1 in I1IIi11 : lisp_map_notify_queue . pop ( ii1iiIIII1I1 )
 return
 if 29 - 29: oO0o
 if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
 if 78 - 78: Oo0Ooo
 if 77 - 77: oO0o % Oo0Ooo % O0
 if 51 - 51: IiII % IiII + OOooOOo . II111iiii / I1ii11iIi11i
 if 4 - 4: o0oOOo0O0Ooo % I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
 if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
 if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
def lisp_decrypt_map_register ( packet ) :
 if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
 if 88 - 88: ooOoO0o
 if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
 if 20 - 20: i11iIiiIii * I11i
 if 29 - 29: IiII / OOooOOo
 I1IIII = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 iii1I1 = ( I1IIII >> 13 ) & 0x1
 if ( iii1I1 == 0 ) : return ( packet )
 if 70 - 70: OoO0O00 - iII111i . OOooOOo - iIii1I11I1II1 . II111iiii
 i1i = ( I1IIII >> 14 ) & 0x7
 if 97 - 97: Ii1I
 if 4 - 4: Ii1I + OoO0O00 * O0
 if 13 - 13: I11i + O0 / oO0o % O0 . I11i
 if 22 - 22: OoOoOO00 . I1IiiI % ooOoO0o + I1Ii111 - OoooooooOO
 try :
  OoOooo0oO0oOo = lisp_ms_encryption_keys [ i1i ]
  OoOooo0oO0oOo = OoOooo0oO0oOo . zfill ( 32 )
  iI1ii = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( i1i ) )
  return ( None )
  if 99 - 99: I11i * i11iIiiIii % Oo0Ooo % oO0o
  if 91 - 91: o0oOOo0O0Ooo / o0oOOo0O0Ooo . I1IiiI + OoooooooOO + i11iIiiIii
 iiIi = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( iiIi , i1i ) )
 if 51 - 51: I1Ii111 / ooOoO0o
 if 84 - 84: ooOoO0o . OoOoOO00 + IiII
 if 51 - 51: Oo0Ooo * I1ii11iIi11i + I11i - OoooooooOO % i1IIi + I1IiiI
 if 14 - 14: I1IiiI . o0oOOo0O0Ooo / I1Ii111
 ooo = chacha . ChaCha ( OoOooo0oO0oOo , iI1ii , 20 ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + ooo )
 if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
 if 32 - 32: oO0o
 if 72 - 72: I1IiiI
 if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
 if 87 - 87: Oo0Ooo
 if 7 - 7: iIii1I11I1II1
 if 85 - 85: iIii1I11I1II1 . O0
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
 if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
 if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
 if 8 - 8: OoO0O00 . OoO0O00
 if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
 if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
 i1II11I11III = lisp_map_register ( )
 IiI11 , packet = i1II11I11III . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 12 - 12: I1ii11iIi11i % Ii1I * OoOoOO00 . iIii1I11I1II1 * I1Ii111 - OoOoOO00
 i1II11I11III . sport = sport
 if 33 - 33: OoO0O00 * I1IiiI / i1IIi
 i1II11I11III . print_map_register ( )
 if 88 - 88: Ii1I / ooOoO0o - I11i % OoO0O00 * iII111i
 if 47 - 47: i11iIiiIii + Oo0Ooo % oO0o % O0
 if 98 - 98: oO0o - O0 / iII111i % oO0o % I1IiiI / i1IIi
 if 61 - 61: ooOoO0o + II111iiii
 oOoOOO00OoOoO = True
 if ( i1II11I11III . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  oOoOOO00OoOoO = True
  if 98 - 98: iIii1I11I1II1 + OOooOOo * oO0o / o0oOOo0O0Ooo . iII111i
 if ( i1II11I11III . alg_id == LISP_SHA_256_128_ALG_ID ) :
  oOoOOO00OoOoO = False
  if 52 - 52: IiII + iIii1I11I1II1
  if 22 - 22: IiII - OOooOOo + I1ii11iIi11i
  if 64 - 64: OoOoOO00
  if 79 - 79: IiII
  if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
 IiiIIIiiI = [ ]
 if 79 - 79: IiII . OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + Ii1I
 if 75 - 75: o0oOOo0O0Ooo / iIii1I11I1II1
 if 16 - 16: O0 . OoO0O00
 if 91 - 91: Oo0Ooo + O0 . iII111i
 OOOOoooO = None
 OO00ooOo0o = packet
 o00OOo0oO = [ ]
 iIIii = i1II11I11III . record_count
 for iIiIIi in range ( iIIii ) :
  iI1111Ii1I = lisp_eid_record ( )
  Oo000O = lisp_rloc_record ( )
  packet = iI1111Ii1I . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 59 - 59: I11i . iII111i
  iI1111Ii1I . print_record ( "  " , False )
  if 80 - 80: I1ii11iIi11i . I11i + I1Ii111 / i1IIi + OoooooooOO
  if 84 - 84: ooOoO0o
  if 47 - 47: Oo0Ooo
  if 60 - 60: i11iIiiIii - o0oOOo0O0Ooo
  ooo0OOO00 = lisp_site_eid_lookup ( iI1111Ii1I . eid , iI1111Ii1I . group ,
 False )
  if 36 - 36: II111iiii
  oo00II = ooo0OOO00 . print_eid_tuple ( ) if ooo0OOO00 else None
  if 17 - 17: OoOoOO00
  if 62 - 62: I1Ii111 * I11i - II111iiii + Oo0Ooo - Ii1I . ooOoO0o
  if 70 - 70: OoOoOO00 * o0oOOo0O0Ooo / IiII
  if 6 - 6: iII111i
  if 4 - 4: I1ii11iIi11i % o0oOOo0O0Ooo * Oo0Ooo
  if 97 - 97: OoOoOO00
  if 34 - 34: iII111i % Oo0Ooo
  if ( ooo0OOO00 and ooo0OOO00 . accept_more_specifics == False ) :
   if ( ooo0OOO00 . eid_record_matches ( iI1111Ii1I ) == False ) :
    i1Iii = ooo0OOO00 . parent_for_more_specifics
    if ( i1Iii ) : ooo0OOO00 = i1Iii
    if 85 - 85: OoO0O00 % I11i + I1IiiI / i1IIi + I1ii11iIi11i - O0
    if 13 - 13: O0 % iII111i + I1IiiI % O0 % oO0o . OoO0O00
    if 76 - 76: II111iiii + i11iIiiIii - OoooooooOO % OoOoOO00
    if 4 - 4: I1Ii111 + i11iIiiIii . Ii1I / iII111i
    if 24 - 24: Ii1I / II111iiii + I1IiiI
    if 100 - 100: Ii1I / IiII * O0
    if 60 - 60: Oo0Ooo / IiII / OoOoOO00 % iIii1I11I1II1 . o0oOOo0O0Ooo % iIii1I11I1II1
    if 35 - 35: OoooooooOO % O0 * I1Ii111 - iIii1I11I1II1 % iII111i
  iiI1I1iI = ( ooo0OOO00 and ooo0OOO00 . accept_more_specifics )
  if ( iiI1I1iI ) :
   o0000O0oOO = lisp_site_eid ( ooo0OOO00 . site )
   o0000O0oOO . dynamic = True
   o0000O0oOO . eid . copy_address ( iI1111Ii1I . eid )
   o0000O0oOO . group . copy_address ( iI1111Ii1I . group )
   o0000O0oOO . parent_for_more_specifics = ooo0OOO00
   o0000O0oOO . add_cache ( )
   o0000O0oOO . inherit_from_ams_parent ( )
   ooo0OOO00 . more_specific_registrations . append ( o0000O0oOO )
   ooo0OOO00 = o0000O0oOO
  else :
   ooo0OOO00 = lisp_site_eid_lookup ( iI1111Ii1I . eid , iI1111Ii1I . group ,
 True )
   if 56 - 56: i11iIiiIii - i1IIi
   if 82 - 82: Oo0Ooo - oO0o
  ooOo000OoO0o = iI1111Ii1I . print_eid_tuple ( )
  if 36 - 36: Oo0Ooo / Oo0Ooo - o0oOOo0O0Ooo - i11iIiiIii
  if ( ooo0OOO00 == None ) :
   iIIi = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( iIIi , green ( ooOo000OoO0o , False ) ,
 ", matched non-ams {}" . format ( green ( oo00II , False ) if oo00II else "" ) ) )
   if 59 - 59: i11iIiiIii / iIii1I11I1II1 / ooOoO0o
   if 2 - 2: iII111i + II111iiii
   if 88 - 88: i1IIi - iII111i / OOooOOo / i1IIi
   if 48 - 48: iII111i / OoooooooOO / iIii1I11I1II1
   if 41 - 41: II111iiii - II111iiii - OoO0O00 + oO0o * I11i
   packet = Oo000O . end_of_rlocs ( packet , iI1111Ii1I . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 77 - 77: IiII % iIii1I11I1II1 - OOooOOo / I1Ii111 / ooOoO0o . iII111i
   continue
   if 62 - 62: I1Ii111
   if 42 - 42: o0oOOo0O0Ooo
  OOOOoooO = ooo0OOO00 . site
  if 59 - 59: I1ii11iIi11i % O0 - i1IIi . Oo0Ooo
  if ( iiI1I1iI ) :
   o0o00oO0oo000 = ooo0OOO00 . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( o0o00oO0oo000 , False ) , OOOOoooO . site_name , green ( ooOo000OoO0o , False ) ) )
   if 18 - 18: II111iiii
  else :
   o0o00oO0oo000 = green ( ooo0OOO00 . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( o0o00oO0oo000 , OOOOoooO . site_name , green ( ooOo000OoO0o , False ) ) )
   if 31 - 31: Oo0Ooo / Oo0Ooo / iIii1I11I1II1 / I11i % OoooooooOO
   if 90 - 90: I1IiiI
   if 35 - 35: O0
   if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
   if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
   if 78 - 78: I1IiiI - iIii1I11I1II1
  if ( OOOOoooO . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( OOOOoooO . site_name ) )
   packet = Oo000O . end_of_rlocs ( packet , iI1111Ii1I . rloc_count )
   continue
   if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
   if 85 - 85: I11i + OoOoOO00 * O0 * O0
   if 92 - 92: i11iIiiIii
   if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
   if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
   if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
   if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
   if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
  oo0OO0oo = i1II11I11III . key_id
  if ( oo0OO0oo in OOOOoooO . auth_key ) :
   iI1 = OOOOoooO . auth_key [ oo0OO0oo ]
  else :
   iI1 = ""
   if 71 - 71: O0 / OoooooooOO
   if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
  iIIii1iIii1 = lisp_verify_auth ( IiI11 , i1II11I11III . alg_id ,
 i1II11I11III . auth_data , iI1 )
  IIi1i = "dynamic " if ooo0OOO00 . dynamic else ""
  if 23 - 23: oO0o * ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
  OOO0oOO = bold ( "passed" if iIIii1iIii1 else "failed" , False )
  oo0OO0oo = "key-id {}" . format ( oo0OO0oo ) if oo0OO0oo == i1II11I11III . key_id else "bad key-id {}" . format ( i1II11I11III . key_id )
  if 45 - 45: Oo0Ooo
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( OOO0oOO , IIi1i , green ( ooOo000OoO0o , False ) , oo0OO0oo ) )
  if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
  if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
  if 52 - 52: OOooOOo + OoO0O00
  if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
  if 42 - 42: i1IIi
  if 52 - 52: OoO0O00 % iII111i % O0
  IiIi1 = True
  OoOooO = ( lisp_get_eid_hash ( iI1111Ii1I . eid ) != None )
  if ( OoOooO or ooo0OOO00 . require_signature ) :
   ooo0 = "Required " if ooo0OOO00 . require_signature else ""
   ooOo000OoO0o = green ( ooOo000OoO0o , False )
   OOOo0 = lisp_find_sig_in_rloc_set ( packet , iI1111Ii1I . rloc_count )
   if ( OOOo0 == None ) :
    IiIi1 = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( ooo0 ,
    # IiII - Oo0Ooo - iIii1I11I1II1 % OoO0O00 - iIii1I11I1II1
 bold ( "failed" , False ) , ooOo000OoO0o ) )
   else :
    IiIi1 = lisp_verify_cga_sig ( iI1111Ii1I . eid , OOOo0 )
    OOO0oOO = bold ( "passed" if IiIi1 else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( ooo0 , OOO0oOO , ooOo000OoO0o ) )
    if 6 - 6: OoO0O00
    if 62 - 62: Ii1I
    if 11 - 11: I1Ii111 + I1IiiI - OOooOOo
    if 56 - 56: II111iiii + IiII * iIii1I11I1II1 - i1IIi + iIii1I11I1II1
  if ( iIIii1iIii1 == False or IiIi1 == False ) :
   packet = Oo000O . end_of_rlocs ( packet , iI1111Ii1I . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 98 - 98: Oo0Ooo . iIii1I11I1II1
   continue
   if 12 - 12: I11i - i11iIiiIii * OoOoOO00 - OoOoOO00 * II111iiii
   if 45 - 45: I1ii11iIi11i - iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
   if 74 - 74: I1IiiI / o0oOOo0O0Ooo
   if 53 - 53: iIii1I11I1II1 * oO0o
   if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
   if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
  if ( i1II11I11III . merge_register_requested ) :
   i1Iii = ooo0OOO00
   i1Iii . inconsistent_registration = False
   if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
   if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
   if 60 - 60: oO0o * I1Ii111
   if 81 - 81: oO0o - OOooOOo - oO0o
   if 54 - 54: oO0o % I11i
   if ( ooo0OOO00 . group . is_null ( ) ) :
    if ( i1Iii . site_id != i1II11I11III . site_id ) :
     i1Iii . site_id = i1II11I11III . site_id
     i1Iii . registered = False
     i1Iii . individual_registrations = { }
     i1Iii . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
     if 22 - 22: iIii1I11I1II1 - OoooooooOO
     if 8 - 8: ooOoO0o % i11iIiiIii
   III11II111 = i1II11I11III . xtr_id
   if ( III11II111 in ooo0OOO00 . individual_registrations ) :
    ooo0OOO00 = ooo0OOO00 . individual_registrations [ III11II111 ]
   else :
    ooo0OOO00 = lisp_site_eid ( OOOOoooO )
    ooo0OOO00 . eid . copy_address ( i1Iii . eid )
    ooo0OOO00 . group . copy_address ( i1Iii . group )
    ooo0OOO00 . encrypt_json = i1Iii . encrypt_json
    i1Iii . individual_registrations [ III11II111 ] = ooo0OOO00
    if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
  else :
   ooo0OOO00 . inconsistent_registration = ooo0OOO00 . merge_register_requested
   if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
   if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
   if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
  ooo0OOO00 . map_registers_received += 1
  if 73 - 73: O0 % i11iIiiIii
  if 16 - 16: O0
  if 15 - 15: i1IIi % i11iIiiIii
  if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
  if 35 - 35: OoOoOO00 . oO0o / II111iiii
  o0Oooo00oO0o00 = ( ooo0OOO00 . is_rloc_in_rloc_set ( source ) == False )
  if ( iI1111Ii1I . record_ttl == 0 and o0Oooo00oO0o00 ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 97 - 97: Ii1I + I1Ii111 / II111iiii
   continue
   if 14 - 14: iII111i / IiII / oO0o
   if 55 - 55: OoO0O00 % O0
   if 92 - 92: OoooooooOO / O0
   if 14 - 14: i11iIiiIii
   if 43 - 43: OOooOOo
   if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
  oO00o0O = ooo0OOO00 . registered_rlocs
  ooo0OOO00 . registered_rlocs = [ ]
  if 94 - 94: Ii1I . I1Ii111 * I11i . ooOoO0o . oO0o
  if 54 - 54: Oo0Ooo
  if 2 - 2: OoooooooOO / o0oOOo0O0Ooo / Oo0Ooo
  if 100 - 100: O0 . i11iIiiIii % I1Ii111 % OoooooooOO
  O00000o0 = packet
  for i111Ii11i in range ( iI1111Ii1I . rloc_count ) :
   Oo000O = lisp_rloc_record ( )
   packet = Oo000O . decode ( packet , None , ooo0OOO00 . encrypt_json )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 80 - 80: i1IIi * I1IiiI + OOooOOo
   Oo000O . print_record ( "    " )
   if 91 - 91: I1IiiI % OoOoOO00 * Oo0Ooo / I1ii11iIi11i
   if 57 - 57: i11iIiiIii / o0oOOo0O0Ooo . II111iiii
   if 63 - 63: O0
   if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
   if ( len ( OOOOoooO . allowed_rlocs ) > 0 ) :
    Oo0o = Oo000O . rloc . print_address ( )
    if ( Oo0o not in OOOOoooO . allowed_rlocs ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( Oo0o , False ) ) )
     if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
     if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
     ooo0OOO00 . registered = False
     packet = Oo000O . end_of_rlocs ( packet ,
 iI1111Ii1I . rloc_count - i111Ii11i - 1 )
     break
     if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
     if 74 - 74: i11iIiiIii
     if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
     if 6 - 6: I11i
     if 70 - 70: ooOoO0o + OoooooooOO % OoOoOO00 % oO0o / Ii1I . I11i
     if 63 - 63: I1ii11iIi11i - ooOoO0o . OOooOOo / O0 . iIii1I11I1II1 - Ii1I
   OOOo0 = lisp_rloc ( )
   OOOo0 . store_rloc_from_record ( Oo000O , None , source )
   if 6 - 6: Ii1I
   if 60 - 60: iII111i + I1IiiI
   if 36 - 36: i1IIi . O0 . OoO0O00 % OOooOOo * I11i / Ii1I
   if 16 - 16: Oo0Ooo
   if 44 - 44: iIii1I11I1II1 - II111iiii . IiII . i1IIi
   if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
   if ( source . is_exact_match ( OOOo0 . rloc ) ) :
    OOOo0 . map_notify_requested = i1II11I11III . map_notify_requested
    if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
    if 43 - 43: I1ii11iIi11i + I11i
    if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
    if 100 - 100: IiII - OoOoOO00 / I11i
    if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
   ooo0OOO00 . registered_rlocs . append ( OOOo0 )
   if 87 - 87: Oo0Ooo
   if 65 - 65: ooOoO0o . I1IiiI
  oOOOOo0o00Oo = ( ooo0OOO00 . do_rloc_sets_match ( oO00o0O ) == False )
  if 96 - 96: Ii1I - o0oOOo0O0Ooo % i11iIiiIii
  if 30 - 30: I1IiiI % oO0o * OoooooooOO
  if 64 - 64: I1IiiI
  if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
  if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
  if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
  if ( i1II11I11III . map_register_refresh and oOOOOo0o00Oo and
 ooo0OOO00 . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   ooo0OOO00 . registered_rlocs = oO00o0O
   continue
   if 90 - 90: o0oOOo0O0Ooo / I1ii11iIi11i - oO0o - Ii1I - I1IiiI + I1Ii111
   if 93 - 93: I1IiiI - I11i . I1IiiI - iIii1I11I1II1
   if 1 - 1: O0 . Ii1I % Ii1I + II111iiii . oO0o
   if 24 - 24: o0oOOo0O0Ooo . I1Ii111 % O0
   if 67 - 67: I1IiiI * Ii1I
   if 64 - 64: OOooOOo
  if ( ooo0OOO00 . registered == False ) :
   ooo0OOO00 . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 90 - 90: iII111i . OoOoOO00 + i1IIi % ooOoO0o * I11i + OoooooooOO
  ooo0OOO00 . last_registered = lisp_get_timestamp ( )
  ooo0OOO00 . registered = ( iI1111Ii1I . record_ttl != 0 )
  ooo0OOO00 . last_registerer = source
  if 2 - 2: o0oOOo0O0Ooo . II111iiii
  if 9 - 9: I1Ii111 - II111iiii + OoOoOO00 . OoO0O00
  if 33 - 33: Oo0Ooo
  if 12 - 12: i11iIiiIii . Oo0Ooo / OoOoOO00 + iII111i . Ii1I + ooOoO0o
  ooo0OOO00 . auth_sha1_or_sha2 = oOoOOO00OoOoO
  ooo0OOO00 . proxy_reply_requested = i1II11I11III . proxy_reply_requested
  ooo0OOO00 . lisp_sec_present = i1II11I11III . lisp_sec_present
  ooo0OOO00 . map_notify_requested = i1II11I11III . map_notify_requested
  ooo0OOO00 . mobile_node_requested = i1II11I11III . mobile_node
  ooo0OOO00 . merge_register_requested = i1II11I11III . merge_register_requested
  if 66 - 66: IiII
  ooo0OOO00 . use_register_ttl_requested = i1II11I11III . use_ttl_for_timeout
  if ( ooo0OOO00 . use_register_ttl_requested ) :
   ooo0OOO00 . register_ttl = iI1111Ii1I . store_ttl ( )
  else :
   ooo0OOO00 . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 41 - 41: II111iiii + Oo0Ooo / iII111i . IiII / iII111i / I1IiiI
  ooo0OOO00 . xtr_id_present = i1II11I11III . xtr_id_present
  if ( ooo0OOO00 . xtr_id_present ) :
   ooo0OOO00 . xtr_id = i1II11I11III . xtr_id
   ooo0OOO00 . site_id = i1II11I11III . site_id
   if 78 - 78: o0oOOo0O0Ooo % OoOoOO00 . O0
   if 41 - 41: iIii1I11I1II1 . OOooOOo - Oo0Ooo % OOooOOo
   if 90 - 90: i11iIiiIii + OoooooooOO - i11iIiiIii + OoooooooOO
   if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
   if 79 - 79: II111iiii / OoooooooOO
  if ( i1II11I11III . merge_register_requested ) :
   if ( i1Iii . merge_in_site_eid ( ooo0OOO00 ) ) :
    IiiIIIiiI . append ( [ iI1111Ii1I . eid , iI1111Ii1I . group ] )
    if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
   if ( i1II11I11III . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , i1Iii , i1II11I11III ,
 iI1111Ii1I )
    if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
    if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
    if 17 - 17: I1Ii111
  if ( oOOOOo0o00Oo == False ) : continue
  if ( len ( IiiIIIiiI ) != 0 ) : continue
  if 2 - 2: O0 % OoOoOO00 + oO0o
  o00OOo0oO . append ( ooo0OOO00 . print_eid_tuple ( ) )
  if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
  if 51 - 51: IiII
  if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
  if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
  if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
  if 95 - 95: O0 - OoOoOO00
  if 68 - 68: ooOoO0o . I1Ii111
  Oo0OOo0 = copy . deepcopy ( iI1111Ii1I )
  iI1111Ii1I = iI1111Ii1I . encode ( )
  iI1111Ii1I += O00000o0
  iIO00O00o0Oo00 = [ ooo0OOO00 . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 53 - 53: Ii1I - i11iIiiIii
  for OOOo0 in oO00o0O :
   if ( OOOo0 . map_notify_requested == False ) : continue
   if ( OOOo0 . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , iI1111Ii1I , iIO00O00o0Oo00 , 1 , OOOo0 . rloc ,
 LISP_CTRL_PORT , i1II11I11III . nonce , i1II11I11III . key_id ,
 i1II11I11III . alg_id , i1II11I11III . auth_len , OOOOoooO , False )
   if 63 - 63: ooOoO0o . oO0o % I1ii11iIi11i
   if 100 - 100: Oo0Ooo . oO0o + OoO0O00
   if 5 - 5: iIii1I11I1II1
   if 14 - 14: iII111i
   if 66 - 66: oO0o % i1IIi % OoooooooOO
  lisp_notify_subscribers ( lisp_sockets , Oo0OOo0 , O00000o0 ,
 ooo0OOO00 . eid , OOOOoooO )
  if 58 - 58: OOooOOo
  if 89 - 89: iIii1I11I1II1 - i1IIi
  if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
  if 9 - 9: I1Ii111 / II111iiii * I1Ii111 / I11i - OoO0O00
  if 36 - 36: IiII . OoOoOO00 . Ii1I
 if ( len ( IiiIIIiiI ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , IiiIIIiiI )
  if 31 - 31: iIii1I11I1II1
  if 84 - 84: I1ii11iIi11i - iII111i * I1IiiI
  if 88 - 88: OOooOOo / Oo0Ooo
  if 31 - 31: II111iiii
  if 32 - 32: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 67 - 67: IiII + oO0o * IiII
 if ( i1II11I11III . merge_register_requested ) : return
 if 26 - 26: I1ii11iIi11i + i1IIi . i1IIi - oO0o + I1IiiI * o0oOOo0O0Ooo
 if 62 - 62: ooOoO0o + ooOoO0o % I11i
 if 100 - 100: II111iiii . OoooooooOO
 if 32 - 32: I11i % OOooOOo * O0 / iIii1I11I1II1 / i1IIi
 if 87 - 87: OoO0O00 . I1ii11iIi11i * I1IiiI
 if ( i1II11I11III . map_notify_requested and OOOOoooO != None ) :
  lisp_build_map_notify ( lisp_sockets , OO00ooOo0o , o00OOo0oO ,
 i1II11I11III . record_count , source , sport , i1II11I11III . nonce ,
 i1II11I11III . key_id , i1II11I11III . alg_id , i1II11I11III . auth_len ,
 OOOOoooO , True )
  if 83 - 83: OOooOOo
 return
 if 86 - 86: I1Ii111 / oO0o
 if 67 - 67: OoOoOO00 + Oo0Ooo / i11iIiiIii . I1IiiI
 if 53 - 53: Oo0Ooo + IiII * ooOoO0o % OoooooooOO * oO0o . iII111i
 if 78 - 78: O0 . Ii1I - I1ii11iIi11i
 if 69 - 69: O0 % O0 . oO0o * OoooooooOO
 if 13 - 13: i1IIi % oO0o . OoooooooOO + I1ii11iIi11i - OOooOOo
 if 99 - 99: OoooooooOO % OOooOOo / I11i
 if 77 - 77: II111iiii - IiII % OOooOOo
def lisp_process_unicast_map_notify ( lisp_sockets , packet , source ) :
 O0oo0o0Oo0oo = lisp_map_notify ( "" )
 packet = O0oo0o0Oo0oo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 22 - 22: OoooooooOO / oO0o
  if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
 O0oo0o0Oo0oo . print_notify ( )
 if ( O0oo0o0Oo0oo . record_count == 0 ) : return
 if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
 iiI11IIii1II = O0oo0o0Oo0oo . eid_records
 Oo000O = lisp_rloc_record ( )
 if 82 - 82: ooOoO0o % II111iiii
 for iIiIIi in range ( O0oo0o0Oo0oo . record_count ) :
  iI1111Ii1I = lisp_eid_record ( )
  iiI11IIii1II = iI1111Ii1I . decode ( iiI11IIii1II )
  if ( packet == None ) : return
  iI1111Ii1I . print_record ( "  " , False )
  ooOo000OoO0o = iI1111Ii1I . print_eid_tuple ( )
  OO0oIiiI1iIii = iI1111Ii1I . rloc_count
  if 63 - 63: Oo0Ooo . I1ii11iIi11i
  if 82 - 82: o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i
  if 50 - 50: OoO0O00 . O0 * o0oOOo0O0Ooo . O0
  if 28 - 28: OoOoOO00 % iIii1I11I1II1 + i1IIi * I1IiiI + O0 + ooOoO0o
  if 2 - 2: o0oOOo0O0Ooo + I1IiiI + I1ii11iIi11i
  Ii111 = lisp_map_cache_lookup ( iI1111Ii1I . eid , iI1111Ii1I . eid )
  if ( Ii111 == None ) :
   o0o00oO0oo000 = green ( ooOo000OoO0o , False )
   lprint ( "Ignoring Map-Notify EID {}, no subscribe-request entry" . format ( o0o00oO0oo000 ) )
   if 94 - 94: o0oOOo0O0Ooo - OoOoOO00 * oO0o
   iiI11IIii1II = Oo000O . end_of_rlocs ( iiI11IIii1II , OO0oIiiI1iIii )
   continue
   if 80 - 80: iII111i - O0 + IiII + iIii1I11I1II1 * I1ii11iIi11i
   if 8 - 8: OoO0O00
   if 99 - 99: iII111i . I1ii11iIi11i . o0oOOo0O0Ooo
   if 4 - 4: I11i * Oo0Ooo . i11iIiiIii / Ii1I . I1ii11iIi11i % I1Ii111
   if 68 - 68: ooOoO0o
   if 58 - 58: iII111i * I1IiiI
   if 82 - 82: Oo0Ooo / OoO0O00 % Oo0Ooo . ooOoO0o * O0
  if ( Ii111 . action != LISP_SEND_PUBSUB_ACTION ) :
   if ( Ii111 . subscribed_eid == None ) :
    o0o00oO0oo000 = green ( ooOo000OoO0o , False )
    lprint ( "Ignoring Map-Notify for non-subscribed EID {}" . format ( o0o00oO0oo000 ) )
    if 39 - 39: I1Ii111 * IiII
    iiI11IIii1II = Oo000O . end_of_rlocs ( iiI11IIii1II , OO0oIiiI1iIii )
    continue
    if 16 - 16: ooOoO0o + OoO0O00 / I11i * OoO0O00 . Oo0Ooo % OoOoOO00
    if 65 - 65: Oo0Ooo / I1Ii111 % II111iiii % Ii1I
    if 70 - 70: II111iiii % Oo0Ooo * oO0o
    if 54 - 54: O0 / ooOoO0o * I1Ii111
    if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
    if 13 - 13: IiII + Oo0Ooo - I1Ii111
    if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
    if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
  oOO0O = [ ]
  if ( Ii111 . action == LISP_SEND_PUBSUB_ACTION ) :
   Ii111 = lisp_mapping ( iI1111Ii1I . eid , iI1111Ii1I . group , [ ] )
   Ii111 . add_cache ( )
   Oo00OOo = copy . deepcopy ( iI1111Ii1I . eid )
   ooOOo0 = copy . deepcopy ( iI1111Ii1I . group )
  else :
   Oo00OOo = Ii111 . subscribed_eid
   ooOOo0 = Ii111 . subscribed_group
   oOO0O = Ii111 . rloc_set
   Ii111 . delete_rlocs_from_rloc_probe_list ( )
   Ii111 . rloc_set = [ ]
   if 89 - 89: OOooOOo . o0oOOo0O0Ooo * OoO0O00 - iII111i
   if 93 - 93: Ii1I / o0oOOo0O0Ooo . OoO0O00 - OOooOOo + I1Ii111
   if 60 - 60: ooOoO0o . i1IIi - I1Ii111
   if 16 - 16: oO0o + oO0o
   if 62 - 62: I1IiiI
  Ii111 . mapping_source = None if source == "lisp-itr" else source
  Ii111 . map_cache_ttl = iI1111Ii1I . store_ttl ( )
  Ii111 . subscribed_eid = Oo00OOo
  Ii111 . subscribed_group = ooOOo0
  if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
  if 49 - 49: iII111i + I11i . Oo0Ooo
  if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
  if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
  if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
  if ( len ( oOO0O ) != 0 and iI1111Ii1I . rloc_count == 0 ) :
   Ii111 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , Ii111 )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( ooOo000OoO0o , False ) ) )
   if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
   iiI11IIii1II = Oo000O . end_of_rlocs ( iiI11IIii1II , OO0oIiiI1iIii )
   continue
   if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
   if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
   if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
   if 1 - 1: i11iIiiIii
   if 1 - 1: iIii1I11I1II1
   if 73 - 73: iII111i + IiII
   if 95 - 95: O0
  I11I1 = oo0OoOooOoOOO = 0
  for i111Ii11i in range ( OO0oIiiI1iIii ) :
   Oo000O = lisp_rloc_record ( )
   iiI11IIii1II = Oo000O . decode ( iiI11IIii1II , None )
   Oo000O . print_record ( "    " )
   if 91 - 91: ooOoO0o . I1IiiI / iII111i . OoO0O00 % I1ii11iIi11i * I11i
   if 37 - 37: iIii1I11I1II1 / I1ii11iIi11i * oO0o / iIii1I11I1II1
   if 45 - 45: IiII
   if 49 - 49: I1IiiI . Ii1I * I1IiiI - OoooooooOO . I11i / I1Ii111
   OoOo = False
   for o0O00o0o in oOO0O :
    if ( o0O00o0o . rloc . is_exact_match ( Oo000O . rloc ) ) :
     OoOo = True
     break
     if 9 - 9: iIii1I11I1II1 * Ii1I / O0 - OOooOOo
     if 95 - 95: i11iIiiIii * II111iiii * OOooOOo * iIii1I11I1II1
   if ( OoOo ) :
    OOOo0 = copy . deepcopy ( o0O00o0o )
    oo0OoOooOoOOO += 1
   else :
    OOOo0 = lisp_rloc ( )
    I11I1 += 1
    if 22 - 22: iIii1I11I1II1 / I1IiiI + OoOoOO00 - OOooOOo . i11iIiiIii / i11iIiiIii
    if 10 - 10: iIii1I11I1II1 % i1IIi
    if 78 - 78: I11i + II111iiii % o0oOOo0O0Ooo
    if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
    if 44 - 44: I1ii11iIi11i
   OOOo0 . store_rloc_from_record ( Oo000O , None , Ii111 . mapping_source )
   Ii111 . rloc_set . append ( OOOo0 )
   if 39 - 39: iII111i + Oo0Ooo / oO0o
   if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
  lprint ( "Update {} map-cache entry with {}/{} new/replaced RLOCs" . format ( green ( ooOo000OoO0o , False ) , I11I1 , oo0OoOooOoOOO ) )
  if 99 - 99: I1IiiI * II111iiii
  if 84 - 84: II111iiii - I1IiiI
  if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
  if 35 - 35: I11i + i1IIi
  if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
  Ii111 . build_best_rloc_set ( )
  lisp_write_ipc_map_cache ( True , Ii111 )
  if 97 - 97: oO0o % iIii1I11I1II1
  if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
  if 16 - 16: I1IiiI
  if 39 - 39: ooOoO0o * II111iiii
  if 90 - 90: OoooooooOO * ooOoO0o
  if 14 - 14: I1IiiI % i1IIi
 IiiiiiOoO0 = lisp_get_map_server ( source )
 if ( IiiiiiOoO0 == None ) :
  lprint ( "Cannot find Map-Server for Map-Notify source address {}" . format ( source . print_address_no_iid ( ) ) )
  if 35 - 35: ooOoO0o % o0oOOo0O0Ooo % ooOoO0o
  return
  if 77 - 77: OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
 lisp_send_map_notify_ack ( lisp_sockets , iiI11IIii1II , O0oo0o0Oo0oo , IiiiiiOoO0 )
 if 55 - 55: i1IIi
 if 64 - 64: oO0o . OOooOOo * i11iIiiIii + I1Ii111
 if 88 - 88: O0
 if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
 if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
 if 90 - 90: i11iIiiIii - iII111i * oO0o
 if 79 - 79: IiII
 if 38 - 38: I1Ii111
 if 56 - 56: i11iIiiIii
 if 58 - 58: i11iIiiIii / OoOoOO00
def lisp_process_multicast_map_notify ( packet , source ) :
 O0oo0o0Oo0oo = lisp_map_notify ( "" )
 packet = O0oo0o0Oo0oo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
  if 39 - 39: Oo0Ooo . OoO0O00
 O0oo0o0Oo0oo . print_notify ( )
 if ( O0oo0o0Oo0oo . record_count == 0 ) : return
 if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
 iiI11IIii1II = O0oo0o0Oo0oo . eid_records
 if 100 - 100: ooOoO0o / OoooooooOO
 for iIiIIi in range ( O0oo0o0Oo0oo . record_count ) :
  iI1111Ii1I = lisp_eid_record ( )
  iiI11IIii1II = iI1111Ii1I . decode ( iiI11IIii1II )
  if ( packet == None ) : return
  iI1111Ii1I . print_record ( "  " , False )
  if 73 - 73: i11iIiiIii - Oo0Ooo
  if 100 - 100: iIii1I11I1II1 + I1Ii111
  if 51 - 51: o0oOOo0O0Ooo * I11i
  if 42 - 42: OOooOOo % I11i
  Ii111 = lisp_map_cache_lookup ( iI1111Ii1I . eid , iI1111Ii1I . group )
  if ( Ii111 == None or Ii111 . action == LISP_SEND_PUBSUB_ACTION ) :
   if ( Ii111 == None ) :
    OOoOo0o0oOO0 , iII , I111I1I = lisp_allow_gleaning ( iI1111Ii1I . eid ,
 iI1111Ii1I . group , None )
    if ( OOoOo0o0oOO0 == False ) : continue
    if 17 - 17: OoOoOO00 % I1ii11iIi11i
    if 95 - 95: Ii1I / OOooOOo + OOooOOo . II111iiii
   Ii111 = lisp_mapping ( iI1111Ii1I . eid , iI1111Ii1I . group , [ ] )
   Ii111 . add_cache ( )
   if 13 - 13: I1IiiI
   if 60 - 60: iII111i . o0oOOo0O0Ooo + iII111i
   if 38 - 38: i11iIiiIii * I11i + Oo0Ooo - iIii1I11I1II1
   if 75 - 75: i1IIi * iII111i - I11i * i11iIiiIii
   if 75 - 75: I1IiiI . OoooooooOO + OOooOOo + IiII
   if 37 - 37: iII111i + i1IIi % Oo0Ooo / o0oOOo0O0Ooo / iII111i
   if 81 - 81: ooOoO0o
  if ( Ii111 . gleaned ) :
   lprint ( "Ignore Map-Notify for gleaned {}" . format ( green ( Ii111 . print_eid_tuple ( ) , False ) ) )
   if 74 - 74: OoO0O00
   continue
   if 13 - 13: I1ii11iIi11i / OoO0O00
   if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
  Ii111 . mapping_source = None if source == "lisp-etr" else source
  Ii111 . map_cache_ttl = iI1111Ii1I . store_ttl ( )
  if 94 - 94: IiII * i1IIi
  if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
  if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
  if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
  if ( len ( Ii111 . rloc_set ) != 0 and iI1111Ii1I . rloc_count == 0 ) :
   Ii111 . rloc_set = [ ]
   Ii111 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , Ii111 )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( Ii111 . print_eid_tuple ( ) , False ) ) )
   if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
   continue
   if 32 - 32: I1IiiI + II111iiii * iII111i + O0 / O0 * Oo0Ooo
   if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
  o0oo = Ii111 . rtrs_in_rloc_set ( )
  if 37 - 37: I1IiiI
  if 18 - 18: iII111i . OoooooooOO + iII111i * I11i
  if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  if 87 - 87: OoOoOO00
  if 30 - 30: IiII % OoOoOO00 + I1Ii111
  for i111Ii11i in range ( iI1111Ii1I . rloc_count ) :
   Oo000O = lisp_rloc_record ( )
   iiI11IIii1II = Oo000O . decode ( iiI11IIii1II , None )
   Oo000O . print_record ( "    " )
   if ( iI1111Ii1I . group . is_null ( ) ) : continue
   if ( Oo000O . rle == None ) : continue
   if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
   if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
   if 87 - 87: I11i
   if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
   if 72 - 72: OoO0O00 * Oo0Ooo - IiII
   oooo0o0o0oO = Ii111 . rloc_set [ 0 ] . stats if len ( Ii111 . rloc_set ) != 0 else None
   if 53 - 53: I1ii11iIi11i / O0 % O0 . OOooOOo
   if 16 - 16: Oo0Ooo + IiII / i1IIi . oO0o % O0 . O0
   if 60 - 60: IiII - o0oOOo0O0Ooo * iIii1I11I1II1 * i11iIiiIii + iII111i
   if 96 - 96: OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
   OOOo0 = lisp_rloc ( )
   OOOo0 . store_rloc_from_record ( Oo000O , None , Ii111 . mapping_source )
   if ( oooo0o0o0oO != None ) : OOOo0 . stats = copy . deepcopy ( oooo0o0o0oO )
   if 44 - 44: I11i * iIii1I11I1II1 . I1ii11iIi11i
   if ( o0oo and OOOo0 . is_rtr ( ) == False ) : continue
   if 9 - 9: o0oOOo0O0Ooo
   Ii111 . rloc_set = [ OOOo0 ]
   Ii111 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , Ii111 )
   if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( Ii111 . print_eid_tuple ( ) , False ) ,
   # iII111i / Ii1I
 OOOo0 . rle . print_rle ( False , True ) ) )
   if 47 - 47: i1IIi / iIii1I11I1II1
   if 98 - 98: OoO0O00 % iII111i / i1IIi + OOooOOo + O0
 return
 if 87 - 87: Ii1I / Ii1I + i1IIi . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
 if 20 - 20: I11i . I1Ii111
 if 29 - 29: OoooooooOO + II111iiii
 if 2 - 2: OoO0O00 * o0oOOo0O0Ooo - I1IiiI
 if 31 - 31: I1IiiI + o0oOOo0O0Ooo % iII111i . OoOoOO00 * oO0o
 if 56 - 56: IiII % I1Ii111
 if 52 - 52: II111iiii * Ii1I . Ii1I . i1IIi + Oo0Ooo % O0
 if 71 - 71: oO0o % OOooOOo * i1IIi
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 O0oo0o0Oo0oo = lisp_map_notify ( "" )
 OO0Oo00OO0oo = O0oo0o0Oo0oo . decode ( orig_packet )
 if ( OO0Oo00OO0oo == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 50 - 50: OoOoOO00 + i1IIi
  if 9 - 9: iII111i / I1Ii111 * Ii1I
 O0oo0o0Oo0oo . print_notify ( )
 if 25 - 25: OoO0O00 . iII111i % I11i . oO0o * iII111i + Oo0Ooo
 if 77 - 77: IiII % oO0o % IiII * ooOoO0o / OOooOOo + OoOoOO00
 if 32 - 32: IiII
 if 90 - 90: I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
 if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
 o0O0o0000o0O0 = source . print_address ( )
 if ( O0oo0o0Oo0oo . alg_id != 0 or O0oo0o0Oo0oo . auth_len != 0 ) :
  IiiiiiOoO0 = None
  for III11II111 in lisp_map_servers_list :
   if ( III11II111 . find ( o0O0o0000o0O0 ) == - 1 ) : continue
   IiiiiiOoO0 = lisp_map_servers_list [ III11II111 ]
   if 96 - 96: O0
  if ( IiiiiiOoO0 == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( o0O0o0000o0O0 ) )
   if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
   return
   if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
   if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
  IiiiiiOoO0 . map_notifies_received += 1
  if 61 - 61: IiII . O0
  iIIii1iIii1 = lisp_verify_auth ( OO0Oo00OO0oo , O0oo0o0Oo0oo . alg_id ,
 O0oo0o0Oo0oo . auth_data , IiiiiiOoO0 . password )
  if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if iIIii1iIii1 else "failed" ) )
  if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
  if ( iIIii1iIii1 == False ) : return
 else :
  IiiiiiOoO0 = lisp_ms ( o0O0o0000o0O0 , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
  if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
  if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
  if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
  if 32 - 32: OoO0O00 + OOooOOo . OoO0O00 - Oo0Ooo
  if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
 iiI11IIii1II = O0oo0o0Oo0oo . eid_records
 if ( O0oo0o0Oo0oo . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , iiI11IIii1II , O0oo0o0Oo0oo , IiiiiiOoO0 )
  return
  if 86 - 86: OOooOOo / OoooooooOO - IiII
  if 56 - 56: I1ii11iIi11i - i1IIi * OoooooooOO * O0 * I1IiiI - I1Ii111
  if 32 - 32: OoooooooOO . OOooOOo . OoO0O00 . IiII / I11i % i1IIi
  if 21 - 21: O0 . OoO0O00 * I1ii11iIi11i % iII111i + OoooooooOO
  if 8 - 8: oO0o * iII111i * I11i
  if 30 - 30: I1Ii111
  if 61 - 61: iII111i
  if 50 - 50: Ii1I / I1IiiI . O0
 iI1111Ii1I = lisp_eid_record ( )
 OO0Oo00OO0oo = iI1111Ii1I . decode ( iiI11IIii1II )
 if ( OO0Oo00OO0oo == None ) : return
 if 49 - 49: I1Ii111 . OoO0O00 % O0
 iI1111Ii1I . print_record ( "  " , False )
 if 15 - 15: I11i - Oo0Ooo / I1Ii111 . ooOoO0o % I1IiiI
 for i111Ii11i in range ( iI1111Ii1I . rloc_count ) :
  Oo000O = lisp_rloc_record ( )
  OO0Oo00OO0oo = Oo000O . decode ( OO0Oo00OO0oo , None )
  if ( OO0Oo00OO0oo == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 62 - 62: II111iiii + ooOoO0o + I1IiiI
  Oo000O . print_record ( "    " )
  if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
  if 13 - 13: I1ii11iIi11i
  if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
  if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
  if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
 if ( iI1111Ii1I . group . is_null ( ) == False ) :
  if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
  if 18 - 18: OoooooooOO - I1ii11iIi11i
  if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
  if 79 - 79: OOooOOo + Oo0Ooo
  if 33 - 33: iIii1I11I1II1
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( iI1111Ii1I . print_eid_tuple ( ) , False ) ) )
  if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
  if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
  I1Iii1 = lisp_control_packet_ipc ( orig_packet , o0O0o0000o0O0 , "lisp-itr" , 0 )
  lisp_ipc ( I1Iii1 , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
  if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
  if 99 - 99: OOooOOo
  if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
  if 53 - 53: oO0o / i1IIi - Oo0Ooo - i1IIi + IiII
 lisp_send_map_notify_ack ( lisp_sockets , iiI11IIii1II , O0oo0o0Oo0oo , IiiiiiOoO0 )
 return
 if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
 if 56 - 56: Oo0Ooo % I1ii11iIi11i
 if 53 - 53: OoO0O00 . I11i - ooOoO0o
 if 11 - 11: I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
 if 74 - 74: oO0o . I1Ii111 . II111iiii
 if 92 - 92: I1Ii111 % OoooooooOO * I1Ii111
 if 78 - 78: Oo0Ooo . I11i . oO0o + O0 / O0
 if 41 - 41: iII111i * OoO0O00 - OoO0O00
def lisp_process_map_notify_ack ( packet , source ) :
 O0oo0o0Oo0oo = lisp_map_notify ( "" )
 packet = O0oo0o0Oo0oo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 72 - 72: o0oOOo0O0Ooo + oO0o . I1ii11iIi11i + OoO0O00 / I1Ii111
  if 58 - 58: Oo0Ooo / II111iiii % OoooooooOO % II111iiii
 O0oo0o0Oo0oo . print_notify ( )
 if 39 - 39: i1IIi
 if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
 if 59 - 59: i1IIi
 if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
 if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
 if ( O0oo0o0Oo0oo . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
  if 71 - 71: OOooOOo
 iI1111Ii1I = lisp_eid_record ( )
 if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
 if ( iI1111Ii1I . decode ( O0oo0o0Oo0oo . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 73 - 73: iII111i / I1IiiI * ooOoO0o
 iI1111Ii1I . print_record ( "  " , False )
 if 85 - 85: I11i + I11i + oO0o - OoOoOO00
 ooOo000OoO0o = iI1111Ii1I . print_eid_tuple ( )
 if 15 - 15: OoO0O00
 if 88 - 88: Ii1I % i1IIi / I1Ii111
 if 2 - 2: Ii1I . IiII % OoOoOO00
 if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
 if ( O0oo0o0Oo0oo . alg_id != LISP_NONE_ALG_ID and O0oo0o0Oo0oo . auth_len != 0 ) :
  ooo0OOO00 = lisp_sites_by_eid . lookup_cache ( iI1111Ii1I . eid , True )
  if ( ooo0OOO00 == None ) :
   iIIi = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( iIIi , green ( ooOo000OoO0o , False ) ) )
   if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
   return
   if 35 - 35: i11iIiiIii
  OOOOoooO = ooo0OOO00 . site
  if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
  if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
  if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
  if 59 - 59: i11iIiiIii . OOooOOo % Oo0Ooo + O0
  OOOOoooO . map_notify_acks_received += 1
  if 84 - 84: I1Ii111 / O0 - IiII . I11i / o0oOOo0O0Ooo
  oo0OO0oo = O0oo0o0Oo0oo . key_id
  if ( oo0OO0oo in OOOOoooO . auth_key ) :
   iI1 = OOOOoooO . auth_key [ oo0OO0oo ]
  else :
   iI1 = ""
   if 12 - 12: i11iIiiIii / Ii1I + i1IIi
   if 54 - 54: I1IiiI
  iIIii1iIii1 = lisp_verify_auth ( packet , O0oo0o0Oo0oo . alg_id ,
 O0oo0o0Oo0oo . auth_data , iI1 )
  if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
  oo0OO0oo = "key-id {}" . format ( oo0OO0oo ) if oo0OO0oo == O0oo0o0Oo0oo . key_id else "bad key-id {}" . format ( O0oo0o0Oo0oo . key_id )
  if 37 - 37: Oo0Ooo
  if 33 - 33: OoooooooOO - O0 . O0 - o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoO0O00
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if iIIii1iIii1 else "failed" , oo0OO0oo ) )
  if 27 - 27: ooOoO0o . i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 * OoOoOO00 * oO0o
  if ( iIIii1iIii1 == False ) : return
  if 19 - 19: O0 * II111iiii * OoOoOO00
  if 53 - 53: Oo0Ooo
  if 16 - 16: Ii1I
  if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
  if 78 - 78: OoO0O00 + oO0o
 if ( O0oo0o0Oo0oo . retransmit_timer ) : O0oo0o0Oo0oo . retransmit_timer . cancel ( )
 if 86 - 86: ooOoO0o . ooOoO0o + oO0o
 OOOOo0 = source . print_address ( )
 III11II111 = O0oo0o0Oo0oo . nonce_key
 if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
 if ( III11II111 in lisp_map_notify_queue ) :
  O0oo0o0Oo0oo = lisp_map_notify_queue . pop ( III11II111 )
  if ( O0oo0o0Oo0oo . retransmit_timer ) : O0oo0o0Oo0oo . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( III11II111 ) )
  if 31 - 31: IiII + iII111i
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( O0oo0o0Oo0oo . nonce_key , red ( OOOOo0 , False ) ) )
  if 5 - 5: O0 * Ii1I
  if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
 return
 if 77 - 77: OOooOOo / OoooooooOO
 if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
 if 79 - 79: i11iIiiIii % o0oOOo0O0Ooo * II111iiii . i1IIi * Ii1I - i11iIiiIii
 if 31 - 31: IiII / o0oOOo0O0Ooo
 if 27 - 27: Oo0Ooo
 if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
 if 35 - 35: o0oOOo0O0Ooo % iII111i / O0 * I1IiiI . o0oOOo0O0Ooo / OOooOOo
 if 81 - 81: I1ii11iIi11i - i11iIiiIii
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 49 - 49: iII111i * I11i - II111iiii . o0oOOo0O0Ooo
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 52 - 52: Ii1I + Ii1I - II111iiii . O0 + I1ii11iIi11i
 if 60 - 60: i11iIiiIii + IiII
 if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
 if 86 - 86: Ii1I / oO0o
 oo00ooo00o = False
 if ( group . is_null ( ) == False ) :
  oo00ooo00o = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
 if ( oo00ooo00o == False ) :
  oo00ooo00o = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 60 - 60: II111iiii / Ii1I
  if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
 if ( oo00ooo00o ) :
  o0oOOOooOOoo = lisp_print_eid_tuple ( eid , group )
  OoO0OOoo = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 68 - 68: iII111i + I1Ii111
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( o0oOOOooOOoo , False ) , s ,
  # o0oOOo0O0Ooo . II111iiii + iII111i + OoO0O00 % i1IIi % oO0o
 OoO0OOoo ) )
  if 81 - 81: Ii1I
 return ( oo00ooo00o )
 if 8 - 8: I1ii11iIi11i * I1IiiI * OOooOOo - I1Ii111 - iII111i
 if 67 - 67: oO0o
 if 76 - 76: I1IiiI % I1IiiI - IiII / OoOoOO00 / I1ii11iIi11i
 if 42 - 42: I1IiiI + I1ii11iIi11i + Oo0Ooo * i1IIi - II111iiii
 if 15 - 15: o0oOOo0O0Ooo
 if 60 - 60: I1ii11iIi11i / I1Ii111
 if 13 - 13: I1Ii111
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 52 - 52: II111iiii / OoO0O00 . Ii1I
 oooO0OOO0o = lisp_map_referral ( )
 packet = oooO0OOO0o . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 68 - 68: iII111i
 oooO0OOO0o . print_map_referral ( )
 if 67 - 67: I1IiiI * I1IiiI
 o0O0o0000o0O0 = source . print_address ( )
 o000oo = oooO0OOO0o . nonce
 if 100 - 100: iII111i * iII111i . Oo0Ooo
 if 10 - 10: Oo0Ooo % ooOoO0o * Oo0Ooo
 if 48 - 48: ooOoO0o + II111iiii
 if 73 - 73: II111iiii
 for iIiIIi in range ( oooO0OOO0o . record_count ) :
  iI1111Ii1I = lisp_eid_record ( )
  packet = iI1111Ii1I . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
  iI1111Ii1I . print_record ( "  " , True )
  if 35 - 35: II111iiii + IiII
  if 66 - 66: o0oOOo0O0Ooo % IiII
  if 39 - 39: IiII
  if 18 - 18: iII111i % o0oOOo0O0Ooo - i1IIi
  III11II111 = str ( o000oo )
  if ( III11II111 not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( o000oo ) , o0O0o0000o0O0 ) )
   if 53 - 53: o0oOOo0O0Ooo + IiII - ooOoO0o % i11iIiiIii - i11iIiiIii - I1Ii111
   if 79 - 79: II111iiii + i11iIiiIii . OOooOOo . I11i / iIii1I11I1II1
   continue
   if 62 - 62: O0
  o0O0oOoOO = lisp_ddt_map_requestQ [ III11II111 ]
  if ( o0O0oOoOO == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( o000oo ) , o0O0o0000o0O0 ) )
   if 52 - 52: OoooooooOO . oO0o
   continue
   if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
   if 21 - 21: i11iIiiIii + II111iiii - i1IIi / OoooooooOO * OOooOOo % Oo0Ooo
   if 59 - 59: Ii1I
   if 77 - 77: I1ii11iIi11i * Ii1I * O0 * I1IiiI % OoO0O00 - iIii1I11I1II1
   if 6 - 6: i11iIiiIii . I11i - OoooooooOO
   if 26 - 26: I1IiiI
  if ( lisp_map_referral_loop ( o0O0oOoOO , iI1111Ii1I . eid , iI1111Ii1I . group ,
 iI1111Ii1I . action , o0O0o0000o0O0 ) ) :
   o0O0oOoOO . dequeue_map_request ( )
   continue
   if 26 - 26: IiII . Ii1I / IiII - OoO0O00 % OoO0O00
   if 72 - 72: OoooooooOO * II111iiii + OoO0O00 % iIii1I11I1II1 . I1ii11iIi11i % OoooooooOO
  o0O0oOoOO . last_cached_prefix [ 0 ] = iI1111Ii1I . eid
  o0O0oOoOO . last_cached_prefix [ 1 ] = iI1111Ii1I . group
  if 19 - 19: OoOoOO00 + I1Ii111
  if 19 - 19: I1ii11iIi11i / I1Ii111 + OoooooooOO - O0
  if 49 - 49: I1ii11iIi11i / OoOoOO00 - I1IiiI + iII111i . OOooOOo % oO0o
  if 34 - 34: OoO0O00 - I1IiiI + OoOoOO00
  ii11i1IiI = False
  OoOo00OoOo = lisp_referral_cache_lookup ( iI1111Ii1I . eid , iI1111Ii1I . group ,
 True )
  if ( OoOo00OoOo == None ) :
   ii11i1IiI = True
   OoOo00OoOo = lisp_referral ( )
   OoOo00OoOo . eid = iI1111Ii1I . eid
   OoOo00OoOo . group = iI1111Ii1I . group
   if ( iI1111Ii1I . ddt_incomplete == False ) : OoOo00OoOo . add_cache ( )
  elif ( OoOo00OoOo . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( OoOo00OoOo . print_eid_tuple ( ) , False ) ) )
   if 22 - 22: iIii1I11I1II1 . i1IIi . OOooOOo % Oo0Ooo - i1IIi
   o0O0oOoOO . dequeue_map_request ( )
   continue
   if 78 - 78: I1IiiI / i1IIi % II111iiii % I1IiiI % Ii1I
   if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
  Oo00Oo0o000 = iI1111Ii1I . action
  OoOo00OoOo . referral_source = source
  OoOo00OoOo . referral_type = Oo00Oo0o000
  OO0ooo00o = iI1111Ii1I . store_ttl ( )
  OoOo00OoOo . referral_ttl = OO0ooo00o
  OoOo00OoOo . expires = lisp_set_timestamp ( OO0ooo00o )
  if 38 - 38: IiII . I1Ii111
  if 69 - 69: ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + Ii1I . ooOoO0o
  if 73 - 73: I11i % I11i . ooOoO0o + OoOoOO00
  if 33 - 33: i11iIiiIii . i11iIiiIii * i11iIiiIii / iIii1I11I1II1 / I1ii11iIi11i . ooOoO0o
  iIiiI1i11Ii = OoOo00OoOo . is_referral_negative ( )
  if ( o0O0o0000o0O0 in OoOo00OoOo . referral_set ) :
   IiIiii1iIii = OoOo00OoOo . referral_set [ o0O0o0000o0O0 ]
   if 14 - 14: iIii1I11I1II1 % i1IIi / I1IiiI + I1IiiI . iII111i
   if ( IiIiii1iIii . updown == False and iIiiI1i11Ii == False ) :
    IiIiii1iIii . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( o0O0o0000o0O0 ) )
    if 40 - 40: I1ii11iIi11i + Ii1I % OOooOOo * oO0o
   elif ( IiIiii1iIii . updown == True and iIiiI1i11Ii == True ) :
    IiIiii1iIii . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( o0O0o0000o0O0 ) )
    if 77 - 77: OoooooooOO
    if 54 - 54: I11i * Oo0Ooo
    if 34 - 34: OOooOOo + I11i / I1ii11iIi11i % i11iIiiIii / IiII
    if 35 - 35: OoOoOO00
    if 18 - 18: II111iiii . OoOoOO00 + I1ii11iIi11i * oO0o + OoooooooOO
    if 39 - 39: I1IiiI * ooOoO0o / i11iIiiIii - oO0o - oO0o + O0
    if 73 - 73: OOooOOo
    if 44 - 44: I1ii11iIi11i * i1IIi - iIii1I11I1II1 - oO0o - oO0o * II111iiii
  OOo0o0o = { }
  for III11II111 in OoOo00OoOo . referral_set : OOo0o0o [ III11II111 ] = None
  if 15 - 15: I1IiiI
  if 50 - 50: Oo0Ooo - I1Ii111 / I1IiiI + IiII / o0oOOo0O0Ooo . iII111i
  if 61 - 61: OoO0O00 + o0oOOo0O0Ooo * iII111i
  if 84 - 84: Oo0Ooo . I1Ii111
  for iIiIIi in range ( iI1111Ii1I . rloc_count ) :
   Oo000O = lisp_rloc_record ( )
   packet = Oo000O . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 6 - 6: IiII + I1IiiI % iII111i - oO0o / OoO0O00
   Oo000O . print_record ( "    " )
   if 37 - 37: O0 % OoO0O00 + i11iIiiIii . O0 / OOooOOo
   if 15 - 15: I1ii11iIi11i + oO0o
   if 99 - 99: oO0o - ooOoO0o - II111iiii * OoooooooOO / O0
   if 57 - 57: iIii1I11I1II1 / IiII + OoO0O00 * oO0o + Ii1I
   Oo0o = Oo000O . rloc . print_address ( )
   if ( Oo0o not in OoOo00OoOo . referral_set ) :
    IiIiii1iIii = lisp_referral_node ( )
    IiIiii1iIii . referral_address . copy_address ( Oo000O . rloc )
    OoOo00OoOo . referral_set [ Oo0o ] = IiIiii1iIii
    if ( o0O0o0000o0O0 == Oo0o and iIiiI1i11Ii ) : IiIiii1iIii . updown = False
   else :
    IiIiii1iIii = OoOo00OoOo . referral_set [ Oo0o ]
    if ( Oo0o in OOo0o0o ) : OOo0o0o . pop ( Oo0o )
    if 76 - 76: i11iIiiIii . OOooOOo / I11i * oO0o % iIii1I11I1II1 . ooOoO0o
   IiIiii1iIii . priority = Oo000O . priority
   IiIiii1iIii . weight = Oo000O . weight
   if 75 - 75: O0 + I1IiiI
   if 67 - 67: OoOoOO00 % OoooooooOO / OoO0O00 - OoO0O00 / O0
   if 19 - 19: iIii1I11I1II1 / OOooOOo % I11i % I1IiiI / I1ii11iIi11i
   if 73 - 73: II111iiii
   if 26 - 26: II111iiii . iIii1I11I1II1 - I1Ii111 % OOooOOo
  for III11II111 in OOo0o0o : OoOo00OoOo . referral_set . pop ( III11II111 )
  if 83 - 83: OOooOOo + OoooooooOO % I1Ii111 % IiII + i11iIiiIii
  ooOo000OoO0o = OoOo00OoOo . print_eid_tuple ( )
  if 10 - 10: OoooooooOO . Ii1I % I1Ii111 + IiII
  if ( ii11i1IiI ) :
   if ( iI1111Ii1I . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( ooOo000OoO0o , False ) ) )
    if 78 - 78: OoOoOO00 - oO0o . I1ii11iIi11i * i11iIiiIii
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( ooOo000OoO0o , False ) , iI1111Ii1I . rloc_count ) )
    if 44 - 44: iIii1I11I1II1 * iII111i
    if 32 - 32: OoOoOO00
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( ooOo000OoO0o , False ) , iI1111Ii1I . rloc_count ) )
   if 65 - 65: iIii1I11I1II1 + iII111i
   if 90 - 90: i11iIiiIii - Oo0Ooo
   if 31 - 31: OoOoOO00 + OoOoOO00 + OoooooooOO % O0
   if 14 - 14: i1IIi / OoooooooOO . I1IiiI * I1Ii111 + OoO0O00
   if 45 - 45: OoooooooOO * I1Ii111
   if 7 - 7: O0
  if ( Oo00Oo0o000 == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( o0O0oOoOO . lisp_sockets , OoOo00OoOo . eid ,
 OoOo00OoOo . group , o0O0oOoOO . nonce , o0O0oOoOO . itr , o0O0oOoOO . sport , 15 , None , False )
   o0O0oOoOO . dequeue_map_request ( )
   if 42 - 42: o0oOOo0O0Ooo / Ii1I
   if 31 - 31: OOooOOo
  if ( Oo00Oo0o000 == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( o0O0oOoOO . tried_root ) :
    lisp_send_negative_map_reply ( o0O0oOoOO . lisp_sockets , OoOo00OoOo . eid ,
 OoOo00OoOo . group , o0O0oOoOO . nonce , o0O0oOoOO . itr , o0O0oOoOO . sport , 0 , None , False )
    o0O0oOoOO . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( o0O0oOoOO , True )
    if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
    if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
    if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
  if ( Oo00Oo0o000 == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( o0O0o0000o0O0 in OoOo00OoOo . referral_set ) :
    IiIiii1iIii = OoOo00OoOo . referral_set [ o0O0o0000o0O0 ]
    IiIiii1iIii . updown = False
    if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
   if ( len ( OoOo00OoOo . referral_set ) == 0 ) :
    o0O0oOoOO . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( o0O0oOoOO , False )
    if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
    if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
    if 65 - 65: I1IiiI . ooOoO0o
  if ( Oo00Oo0o000 in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( o0O0oOoOO . eid . is_exact_match ( iI1111Ii1I . eid ) ) :
    if ( not o0O0oOoOO . tried_root ) :
     lisp_send_ddt_map_request ( o0O0oOoOO , True )
    else :
     lisp_send_negative_map_reply ( o0O0oOoOO . lisp_sockets ,
 OoOo00OoOo . eid , OoOo00OoOo . group , o0O0oOoOO . nonce , o0O0oOoOO . itr ,
 o0O0oOoOO . sport , 15 , None , False )
     o0O0oOoOO . dequeue_map_request ( )
     if 51 - 51: I1Ii111
   else :
    lisp_send_ddt_map_request ( o0O0oOoOO , False )
    if 89 - 89: Oo0Ooo
    if 15 - 15: OOooOOo * II111iiii - OOooOOo * iIii1I11I1II1
    if 95 - 95: I1Ii111 / OoooooooOO * I11i * OoooooooOO
  if ( Oo00Oo0o000 == LISP_DDT_ACTION_MS_ACK ) : o0O0oOoOO . dequeue_map_request ( )
  if 88 - 88: I1IiiI / Oo0Ooo / oO0o + oO0o % OOooOOo + Oo0Ooo
 return
 if 63 - 63: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo % iIii1I11I1II1 / I1ii11iIi11i - iII111i
 if 72 - 72: iII111i % oO0o . IiII + I1ii11iIi11i . IiII . II111iiii
 if 10 - 10: I11i . ooOoO0o + I11i * Ii1I
 if 55 - 55: OOooOOo / iII111i + OoooooooOO - OoooooooOO
 if 51 - 51: O0 % Ii1I % Oo0Ooo - O0
 if 94 - 94: OoooooooOO - ooOoO0o % I1ii11iIi11i + I1Ii111
 if 51 - 51: I1ii11iIi11i . iII111i / i1IIi * ooOoO0o % I11i
 if 82 - 82: O0 % OoOoOO00 . iII111i . i1IIi . iII111i - Oo0Ooo
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 Iiiiii1i1I1I = lisp_ecm ( 0 )
 packet = Iiiiii1i1I1I . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 58 - 58: O0 * OOooOOo
  if 60 - 60: ooOoO0o
 Iiiiii1i1I1I . print_ecm ( )
 if 47 - 47: i11iIiiIii
 I1IIII = lisp_control_header ( )
 if ( I1IIII . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 21 - 21: i1IIi - oO0o - Oo0Ooo
  if 11 - 11: i1IIi
 O00o0Oo = I1IIII . type
 del ( I1IIII )
 if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
 if ( O00o0Oo != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 56 - 56: Ii1I . iII111i
  if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
  if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
  if 52 - 52: i11iIiiIii
  if 1 - 1: i1IIi * iIii1I11I1II1
 ii11IIiiI1 = Iiiiii1i1I1I . udp_sport
 OO00 = time . time ( )
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 Iiiiii1i1I1I . source , ii11IIiiI1 , Iiiiii1i1I1I . ddt , - 1 , OO00 )
 return
 if 100 - 100: ooOoO0o / II111iiii . IiII / iII111i + I1ii11iIi11i
 if 58 - 58: iIii1I11I1II1 * ooOoO0o - Ii1I - Ii1I . Oo0Ooo . i1IIi
 if 69 - 69: iII111i / o0oOOo0O0Ooo - I1IiiI
 if 87 - 87: OoO0O00 - o0oOOo0O0Ooo . i11iIiiIii / I1IiiI * II111iiii % i11iIiiIii
 if 48 - 48: IiII / II111iiii + iIii1I11I1II1 % Ii1I * I1IiiI / iII111i
 if 24 - 24: Ii1I . Ii1I + II111iiii
 if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
 if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
 if 56 - 56: iII111i * II111iiii . OoooooooOO . I11i
 if 25 - 25: ooOoO0o % o0oOOo0O0Ooo - i11iIiiIii
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 79 - 79: iII111i - I1IiiI % O0 / Oo0Ooo + OoOoOO00 . Oo0Ooo
 if 59 - 59: I1ii11iIi11i * OoOoOO00 / Ii1I
 if 80 - 80: IiII - ooOoO0o / OoOoOO00 / I11i * O0 + oO0o
 if 77 - 77: ooOoO0o + I1ii11iIi11i * o0oOOo0O0Ooo / i1IIi * I11i
 if 70 - 70: oO0o / iII111i * i1IIi / II111iiii / OoOoOO00 + oO0o
 if 30 - 30: i1IIi - iII111i - i11iIiiIii . OoOoOO00 . o0oOOo0O0Ooo
 if 74 - 74: i11iIiiIii / II111iiii
 OooOOooo = ms . map_server
 if ( lisp_decent_push_configured and OooOOooo . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  OooOOooo = copy . deepcopy ( OooOOooo )
  OooOOooo . address = 0x7f000001
  OO0OO0O = bold ( "Bootstrap" , False )
  o0O0Ooo = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( OO0OO0O , o0O0Ooo ) )
  if 62 - 62: O0
  if 63 - 63: Oo0Ooo + Oo0Ooo
  if 48 - 48: Oo0Ooo * I1ii11iIi11i % II111iiii
  if 42 - 42: I1Ii111 - ooOoO0o % o0oOOo0O0Ooo * I1IiiI . o0oOOo0O0Ooo
  if 84 - 84: iIii1I11I1II1
  if 39 - 39: Ii1I . II111iiii / I1IiiI
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 44 - 44: Ii1I / Ii1I / OoO0O00 % ooOoO0o / I11i . I1ii11iIi11i
 if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
 if 81 - 81: I1Ii111 % OoO0O00 / O0
 if 55 - 55: i1IIi - I1Ii111 + I11i
 if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
 if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
 if ( ms . ekey != None ) :
  OoOooo0oO0oOo = ms . ekey . zfill ( 32 )
  iI1ii = "0" * 8
  oooo0o0oO = chacha . ChaCha ( OoOooo0oO0oOo , iI1ii , 20 ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + oooo0o0oO
  o0o00oO0oo000 = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( o0o00oO0oo000 , ms . ekey_id ) )
  if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
  if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
 iI111iI = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  iI111iI = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 83 - 83: II111iiii - o0oOOo0O0Ooo . OoO0O00 . OOooOOo % o0oOOo0O0Ooo
  if 96 - 96: i1IIi % OoooooooOO * OOooOOo - Oo0Ooo + iIii1I11I1II1
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( OooOOooo . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , iI111iI ) )
 if 87 - 87: I11i . I1ii11iIi11i / i1IIi - II111iiii - i11iIiiIii
 lisp_send ( lisp_sockets , OooOOooo , LISP_CTRL_PORT , packet )
 return
 if 49 - 49: I1ii11iIi11i + I1Ii111 * OOooOOo - IiII . i11iIiiIii
 if 34 - 34: iII111i . OoOoOO00
 if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
 if 20 - 20: I1ii11iIi11i . iIii1I11I1II1 - Ii1I % OoO0O00
 if 27 - 27: iIii1I11I1II1 / I1Ii111 - I11i . OoO0O00 + ooOoO0o
 if 89 - 89: I1IiiI % I11i - OOooOOo
 if 71 - 71: OOooOOo % Oo0Ooo - o0oOOo0O0Ooo / I1Ii111 - O0 - oO0o
 if 10 - 10: I1IiiI
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 iiIIiIi1i1I1 = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 17 - 17: i11iIiiIii % o0oOOo0O0Ooo . ooOoO0o
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 34 - 34: OoooooooOO / iII111i / O0
 if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
 packet = lisp_control_packet_ipc ( packet , iiIIiIi1i1I1 , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
 if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
 if 40 - 40: OOooOOo - OoooooooOO
 if 36 - 36: i1IIi % OoOoOO00 - i1IIi
 if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
 if 97 - 97: I11i . ooOoO0o
 if 87 - 87: oO0o / iIii1I11I1II1 - I11i + OoooooooOO
 if 79 - 79: I1ii11iIi11i * IiII . I1ii11iIi11i
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 65 - 65: iII111i - Ii1I - II111iiii * O0 + I1ii11iIi11i . iIii1I11I1II1
 if 76 - 76: OoO0O00 * ooOoO0o
 if 32 - 32: O0 . oO0o * o0oOOo0O0Ooo . Ii1I + IiII
 if 98 - 98: iII111i . II111iiii % O0
 if 43 - 43: OOooOOo % I1Ii111 . IiII % OoO0O00 + I1Ii111 % OoooooooOO
 if 17 - 17: OoooooooOO - i1IIi * I11i
 if 33 - 33: i1IIi . Oo0Ooo + I11i
 if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 78 - 78: I1Ii111 + I1Ii111
 if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
 if 19 - 19: Ii1I
 if 51 - 51: oO0o
 if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
 if 35 - 35: o0oOOo0O0Ooo % II111iiii + O0
 if 70 - 70: I1ii11iIi11i . II111iiii
 if 54 - 54: OOooOOo
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 67 - 67: I1IiiI . o0oOOo0O0Ooo / i1IIi * I1ii11iIi11i . Oo0Ooo + II111iiii
 if 63 - 63: OoOoOO00 - OoOoOO00
 if 31 - 31: I1ii11iIi11i % O0 - i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o * ooOoO0o
 if 18 - 18: OoO0O00 - OoO0O00 . o0oOOo0O0Ooo
 if 80 - 80: I11i + I1Ii111 / I1IiiI * OOooOOo % iII111i
 if 48 - 48: iIii1I11I1II1 + i1IIi . I1IiiI % OoO0O00 - iIii1I11I1II1 / i1IIi
 if 14 - 14: IiII . I11i
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 13 - 13: OoOoOO00 - I11i . OOooOOo % OoO0O00
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
  if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
  if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
  if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
  if 9 - 9: iIii1I11I1II1
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
 if ( lisp_nat_traversal ) :
  iiI1iiIiiiI1I = lisp_get_any_translated_port ( )
  if ( iiI1iiIiiiI1I != None ) : inner_sport = iiI1iiIiiiI1I
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
 Iiiiii1i1I1I = lisp_ecm ( inner_sport )
 if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
 Iiiiii1i1I1I . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 Iiiiii1i1I1I . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 Iiiiii1i1I1I . ddt = ddt
 IIi1IiiIiiI = Iiiiii1i1I1I . encode ( packet , inner_source , inner_dest )
 if ( IIi1IiiIiiI == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 47 - 47: II111iiii / o0oOOo0O0Ooo * o0oOOo0O0Ooo + oO0o
 Iiiiii1i1I1I . print_ecm ( )
 if 3 - 3: Oo0Ooo
 packet = IIi1IiiIiiI + packet
 if 82 - 82: OoooooooOO + OoO0O00 . OoO0O00 * OoO0O00
 Oo0o = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( Oo0o ) )
 OooOOooo = lisp_convert_4to6 ( Oo0o )
 lisp_send ( lisp_sockets , OooOOooo , LISP_CTRL_PORT , packet )
 return
 if 99 - 99: I1ii11iIi11i - OoooooooOO - Ii1I / Oo0Ooo
 if 96 - 96: o0oOOo0O0Ooo . II111iiii
 if 14 - 14: OoooooooOO - i1IIi / i11iIiiIii - OOooOOo - i11iIiiIii . ooOoO0o
 if 8 - 8: oO0o * O0 - II111iiii + I1IiiI
 if 85 - 85: OoooooooOO % i11iIiiIii / IiII % OoOoOO00 + O0
 if 6 - 6: OoooooooOO
 if 97 - 97: II111iiii + o0oOOo0O0Ooo * II111iiii
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
if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
if 14 - 14: OOooOOo * IiII
if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
if 33 - 33: OoO0O00
if 91 - 91: I11i % I11i % iII111i
if 19 - 19: I11i / I11i + I1IiiI * OoO0O00 - iII111i . Oo0Ooo
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 76 - 76: iII111i % OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % i1IIi
if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
if 38 - 38: OoOoOO00 % OoooooooOO . oO0o - OoooooooOO + I11i
if 18 - 18: OoooooooOO + ooOoO0o * OoOoOO00 - OoO0O00
if 42 - 42: oO0o % OoOoOO00 - oO0o + I11i / i11iIiiIii
if 74 - 74: OoO0O00 - II111iiii - ooOoO0o % i1IIi
def byte_swap_64 ( address ) :
 OOOo = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 42 - 42: i11iIiiIii / O0
 if 8 - 8: I1Ii111
 if 51 - 51: i11iIiiIii
 if 1 - 1: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i
 if 58 - 58: i11iIiiIii * i11iIiiIii - OoO0O00
 if 8 - 8: i11iIiiIii * OoOoOO00 . o0oOOo0O0Ooo
 if 27 - 27: I1ii11iIi11i + Ii1I % I1Ii111
 if 20 - 20: Oo0Ooo
 return ( OOOo )
 if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
 if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
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
class lisp_cache_entries ( object ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 96 - 96: Oo0Ooo + oO0o - Oo0Ooo - OoOoOO00 % OOooOOo . iIii1I11I1II1
  if 93 - 93: iIii1I11I1II1 % OoooooooOO
  if 6 - 6: II111iiii / oO0o - OOooOOo . O0 - o0oOOo0O0Ooo
class lisp_cache ( object ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 72 - 72: iIii1I11I1II1 / OoooooooOO * ooOoO0o / ooOoO0o % O0 + IiII
  if 96 - 96: iII111i / i11iIiiIii + Oo0Ooo . I1IiiI + iII111i % OoOoOO00
 def cache_size ( self ) :
  return ( self . cache_count )
  if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
  if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   OoOO0oo0OOOO = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   OoOO0oo0OOOO = prefix . mask_len
  else :
   OoOO0oo0OOOO = prefix . mask_len + 48
   if 87 - 87: iII111i
   if 86 - 86: IiII - I11i
  oO0O = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  II1i1iI = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 99 - 99: i1IIi + I1ii11iIi11i
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    iIo00oo = prefix . addr_length ( ) * 2
    OOOo = lisp_hex_string ( prefix . address ) . zfill ( iIo00oo )
   else :
    OOOo = prefix . address
    if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   II1i1iI = "8003"
   OOOo = prefix . address . print_geo ( )
  else :
   II1i1iI = ""
   OOOo = ""
   if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
   if 44 - 44: II111iiii / I1ii11iIi11i
  III11II111 = oO0O + II1i1iI + OOOo
  return ( [ OoOO0oo0OOOO , III11II111 ] )
  if 39 - 39: OoooooooOO % OoO0O00
  if 83 - 83: OOooOOo % I1IiiI + O0 % OoooooooOO
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  OoOO0oo0OOOO , III11II111 = self . build_key ( prefix )
  if ( OoOO0oo0OOOO not in self . cache ) :
   self . cache [ OoOO0oo0OOOO ] = lisp_cache_entries ( )
   self . cache_sorted = self . sort_in_entry ( self . cache_sorted , OoOO0oo0OOOO )
   if 84 - 84: I11i - Oo0Ooo % ooOoO0o - II111iiii
  if ( III11II111 not in self . cache [ OoOO0oo0OOOO ] . entries ) :
   self . cache_count += 1
   if 29 - 29: IiII
  self . cache [ OoOO0oo0OOOO ] . entries [ III11II111 ] = entry
  if 4 - 4: II111iiii * o0oOOo0O0Ooo - IiII * iII111i
  if 91 - 91: I1Ii111 * iII111i * OoO0O00
 def lookup_cache ( self , prefix , exact ) :
  o0Oo0O0 , III11II111 = self . build_key ( prefix )
  if ( exact ) :
   if ( o0Oo0O0 not in self . cache ) : return ( None )
   if ( III11II111 not in self . cache [ o0Oo0O0 ] . entries ) : return ( None )
   return ( self . cache [ o0Oo0O0 ] . entries [ III11II111 ] )
   if 9 - 9: ooOoO0o . O0 + II111iiii . OoooooooOO
   if 97 - 97: O0 / OoOoOO00 / ooOoO0o
  OoOo = None
  for OoOO0oo0OOOO in self . cache_sorted :
   if ( o0Oo0O0 < OoOO0oo0OOOO ) : return ( OoOo )
   for iIiiI11II11i in list ( self . cache [ OoOO0oo0OOOO ] . entries . values ( ) ) :
    if ( prefix . is_more_specific ( iIiiI11II11i . eid ) ) :
     if ( OoOo == None or
 iIiiI11II11i . eid . is_more_specific ( OoOo . eid ) ) : OoOo = iIiiI11II11i
     if 11 - 11: II111iiii . i11iIiiIii - Ii1I . IiII
     if 10 - 10: OOooOOo * OoooooooOO
     if 12 - 12: II111iiii - O0 . i1IIi % oO0o % OoooooooOO
  return ( OoOo )
  if 36 - 36: IiII * OoOoOO00 - iIii1I11I1II1 + II111iiii
  if 65 - 65: I1IiiI * I11i . I1Ii111 % I1ii11iIi11i + O0
 def delete_cache ( self , prefix ) :
  OoOO0oo0OOOO , III11II111 = self . build_key ( prefix )
  if ( OoOO0oo0OOOO not in self . cache ) : return
  if ( III11II111 not in self . cache [ OoOO0oo0OOOO ] . entries ) : return
  self . cache [ OoOO0oo0OOOO ] . entries . pop ( III11II111 )
  self . cache_count -= 1
  if 91 - 91: OoooooooOO % I1Ii111 * OoO0O00 - OoOoOO00
  if 5 - 5: iIii1I11I1II1 * I11i - oO0o % oO0o % o0oOOo0O0Ooo . i1IIi
 def walk_cache ( self , function , parms ) :
  for OoOO0oo0OOOO in self . cache_sorted :
   for iIiiI11II11i in list ( self . cache [ OoOO0oo0OOOO ] . entries . values ( ) ) :
    OOOOO0OOoOOO , parms = function ( iIiiI11II11i , parms )
    if ( OOOOO0OOoOOO == False ) : return ( parms )
    if 12 - 12: I1ii11iIi11i - I11i . OoOoOO00 + iII111i . iII111i
    if 43 - 43: I1Ii111 + I1Ii111 % Oo0Ooo % OoO0O00 - ooOoO0o
  return ( parms )
  if 61 - 61: OoOoOO00 + Ii1I % i11iIiiIii - I1IiiI * OoO0O00 % iIii1I11I1II1
  if 66 - 66: iII111i + i1IIi
 def sort_in_entry ( self , table , value ) :
  if ( table == [ ] ) : return ( [ value ] )
  if 24 - 24: O0 / OoooooooOO - OoOoOO00
  oOOOooOOO = table
  while ( True ) :
   if ( len ( oOOOooOOO ) == 1 ) :
    if ( value == oOOOooOOO [ 0 ] ) : return ( table )
    o00o = table . index ( oOOOooOOO [ 0 ] )
    if ( value < oOOOooOOO [ 0 ] ) :
     return ( table [ 0 : o00o ] + [ value ] + table [ o00o : : ] )
     if 51 - 51: OoO0O00 + o0oOOo0O0Ooo - II111iiii * I11i + Ii1I
    if ( value > oOOOooOOO [ 0 ] ) :
     return ( table [ 0 : o00o + 1 ] + [ value ] + table [ o00o + 1 : : ] )
     if 16 - 16: I1Ii111 * i1IIi . I1IiiI . OOooOOo % Ii1I - o0oOOo0O0Ooo
     if 89 - 89: Ii1I * I1ii11iIi11i * I1IiiI % iII111i % Ii1I + O0
   o00o = old_div ( len ( oOOOooOOO ) , 2 )
   oOOOooOOO = oOOOooOOO [ 0 : o00o ] if ( value < oOOOooOOO [ o00o ] ) else oOOOooOOO [ o00o : : ]
   if 53 - 53: i11iIiiIii % I1ii11iIi11i
   if 59 - 59: OOooOOo
  return ( [ ] )
  if 61 - 61: OoooooooOO + O0 - i1IIi % oO0o / I1ii11iIi11i
  if 50 - 50: oO0o + II111iiii * OoOoOO00 % OoO0O00 . II111iiii % o0oOOo0O0Ooo
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 32 - 32: i1IIi / Ii1I + i11iIiiIii % oO0o
  for OoOO0oo0OOOO in self . cache_sorted :
   for III11II111 in self . cache [ OoOO0oo0OOOO ] . entries :
    iIiiI11II11i = self . cache [ OoOO0oo0OOOO ] . entries [ III11II111 ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( OoOO0oo0OOOO , III11II111 ,
 iIiiI11II11i ) )
    if 11 - 11: Ii1I - ooOoO0o % i11iIiiIii / OoooooooOO - O0 - IiII
    if 25 - 25: IiII + O0 + oO0o % iIii1I11I1II1 - II111iiii . I1IiiI
    if 62 - 62: IiII . O0 + oO0o - ooOoO0o * iIii1I11I1II1
    if 8 - 8: I1ii11iIi11i
    if 65 - 65: i11iIiiIii
    if 92 - 92: oO0o * II111iiii + I1Ii111
    if 49 - 49: II111iiii * I1IiiI * O0 / ooOoO0o * IiII
    if 94 - 94: OoO0O00 - I1IiiI * oO0o
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 35 - 35: OOooOOo / i1IIi + OoO0O00
if 31 - 31: OoO0O00 . i1IIi / OoooooooOO
if 81 - 81: ooOoO0o . Oo0Ooo . OoOoOO00 + OOooOOo % iII111i - oO0o
if 68 - 68: iII111i - O0 / Ii1I
if 15 - 15: I1Ii111 / I1ii11iIi11i / I1IiiI % i11iIiiIii + II111iiii . ooOoO0o
if 74 - 74: o0oOOo0O0Ooo
if 4 - 4: I1ii11iIi11i * II111iiii - Oo0Ooo % i1IIi % O0 * i11iIiiIii
def lisp_map_cache_lookup ( source , dest ) :
 if 62 - 62: OoO0O00 * I1Ii111 * Ii1I / ooOoO0o
 oOiI1111iI1 = dest . is_multicast_address ( )
 if 27 - 27: oO0o . iII111i . oO0o
 if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
 if 14 - 14: I11i + ooOoO0o . oO0o * I11i
 if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
 Ii111 = lisp_map_cache . lookup_cache ( dest , False )
 if ( Ii111 == None ) :
  ooOo000OoO0o = source . print_sg ( dest ) if oOiI1111iI1 else dest . print_address ( )
  ooOo000OoO0o = green ( ooOo000OoO0o , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( ooOo000OoO0o ) )
  return ( None )
  if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
  if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
  if 33 - 33: I11i
  if 37 - 37: Oo0Ooo
  if 36 - 36: IiII % I11i
 if ( oOiI1111iI1 == False ) :
  OOoO0o0OOo0 = green ( Ii111 . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , OOoO0o0OOo0 ) )
  if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
  return ( Ii111 )
  if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
  if 82 - 82: OoooooooOO
  if 14 - 14: OoO0O00 / oO0o - OOooOOo
  if 100 - 100: IiII - I11i . iIii1I11I1II1 / iIii1I11I1II1
  if 16 - 16: IiII + Oo0Ooo % I11i
 Ii111 = Ii111 . lookup_source_cache ( source , False )
 if ( Ii111 == None ) :
  ooOo000OoO0o = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( ooOo000OoO0o ) )
  return ( None )
  if 16 - 16: ooOoO0o / I1Ii111
  if 78 - 78: OoOoOO00 - II111iiii - OOooOOo + I1IiiI + O0 / I1IiiI
  if 59 - 59: OOooOOo . I1IiiI / i1IIi / II111iiii . II111iiii
  if 54 - 54: iIii1I11I1II1 % ooOoO0o
  if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
 OOoO0o0OOo0 = green ( Ii111 . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , OOoO0o0OOo0 ) )
 if 92 - 92: I11i + OoO0O00 . OoooooooOO
 return ( Ii111 )
 if 3 - 3: OoO0O00 % iIii1I11I1II1
 if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
 if 59 - 59: iIii1I11I1II1
 if 18 - 18: ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
 if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
 if 63 - 63: I11i
 if 60 - 60: I1IiiI / I1ii11iIi11i / I11i / Ii1I + iIii1I11I1II1
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  OoooOO0 = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( OoooOO0 )
  if 85 - 85: O0 / OOooOOo . OoOoOO00 / I1ii11iIi11i
  if 80 - 80: I1ii11iIi11i * iII111i % i1IIi * OOooOOo % II111iiii % i1IIi
  if 44 - 44: OoooooooOO
  if 18 - 18: i11iIiiIii
  if 65 - 65: i1IIi . iIii1I11I1II1 % iIii1I11I1II1
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 35 - 35: iIii1I11I1II1 - o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - OOooOOo . o0oOOo0O0Ooo
 if 12 - 12: iIii1I11I1II1 % OoO0O00 * Oo0Ooo
 if 5 - 5: I11i - II111iiii * iIii1I11I1II1 / iIii1I11I1II1 % IiII * i1IIi
 if 30 - 30: i1IIi % I1IiiI . OOooOOo % iIii1I11I1II1 . I1ii11iIi11i / o0oOOo0O0Ooo
 if 53 - 53: OOooOOo % ooOoO0o
 if 94 - 94: OOooOOo - O0 - I1Ii111 / OoooooooOO - iII111i
 OoooOO0 = lisp_referral_cache . lookup_cache ( group , exact )
 if ( OoooOO0 == None ) : return ( None )
 if 83 - 83: OOooOOo * I1ii11iIi11i * iII111i * I1ii11iIi11i . OoO0O00
 o0o0oOo00Oo = OoooOO0 . lookup_source_cache ( eid , exact )
 if ( o0o0oOo00Oo ) : return ( o0o0oOo00Oo )
 if 94 - 94: ooOoO0o / Ii1I
 if ( exact ) : OoooOO0 = None
 return ( OoooOO0 )
 if 9 - 9: I1Ii111 * oO0o
 if 44 - 44: ooOoO0o * oO0o
 if 67 - 67: iIii1I11I1II1 . iIii1I11I1II1 + iIii1I11I1II1 * iII111i
 if 70 - 70: I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
 if 12 - 12: Oo0Ooo + I1IiiI
 if 12 - 12: OoOoOO00 / II111iiii
 if 100 - 100: I1ii11iIi11i % iIii1I11I1II1 . IiII . OoooooooOO / II111iiii
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  OOo = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( OOo )
  if 28 - 28: I1IiiI
  if 27 - 27: I1IiiI % oO0o - iIii1I11I1II1 - o0oOOo0O0Ooo - IiII - O0
  if 46 - 46: II111iiii
  if 24 - 24: i11iIiiIii * i1IIi - I11i + o0oOOo0O0Ooo
  if 60 - 60: ooOoO0o
 if ( eid . is_null ( ) ) : return ( None )
 if 62 - 62: i11iIiiIii
 if 88 - 88: i11iIiiIii
 if 59 - 59: oO0o - OoooooooOO % ooOoO0o
 if 90 - 90: OoOoOO00
 if 96 - 96: II111iiii % Ii1I
 if 84 - 84: I1IiiI . I1IiiI
 OOo = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( OOo == None ) : return ( None )
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1 + I1ii11iIi11i
 i11 = OOo . lookup_source_cache ( eid , exact )
 if ( i11 ) : return ( i11 )
 if 61 - 61: Oo0Ooo . OoOoOO00 / Oo0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i
 if ( exact ) : OOo = None
 return ( OOo )
 if 9 - 9: OoO0O00 * I1IiiI % IiII
 if 97 - 97: o0oOOo0O0Ooo + Ii1I
 if 77 - 77: I11i - oO0o . Ii1I
 if 75 - 75: I11i * OoooooooOO % OoOoOO00 . i1IIi - Ii1I + iIii1I11I1II1
 if 74 - 74: ooOoO0o
 if 18 - 18: iIii1I11I1II1 - I11i - oO0o
 if 12 - 12: O0 + O0 + ooOoO0o . I1IiiI * II111iiii
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 47 - 47: i11iIiiIii % OOooOOo / ooOoO0o . IiII - I1IiiI
 if ( group . is_null ( ) ) :
  ooo0OOO00 = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( ooo0OOO00 )
  if 10 - 10: Oo0Ooo / ooOoO0o / I1ii11iIi11i
  if 98 - 98: O0 - I1Ii111 - i11iIiiIii
  if 85 - 85: II111iiii - I1ii11iIi11i % I1IiiI . I1IiiI - OoooooooOO - I11i
  if 38 - 38: i1IIi + oO0o * ooOoO0o % Ii1I % ooOoO0o
  if 80 - 80: OoO0O00 + OoOoOO00 % iII111i % OoooooooOO - ooOoO0o
 if ( eid . is_null ( ) ) : return ( None )
 if 25 - 25: OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - Oo0Ooo . O0
 if 48 - 48: I1IiiI + oO0o % i11iIiiIii % iIii1I11I1II1
 if 14 - 14: iIii1I11I1II1
 if 78 - 78: I1Ii111 / Oo0Ooo - I1Ii111
 if 1 - 1: OoO0O00 - I1IiiI * o0oOOo0O0Ooo
 if 84 - 84: OoO0O00 % OoooooooOO
 ooo0OOO00 = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( ooo0OOO00 == None ) : return ( None )
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
 if 14 - 14: i1IIi / ooOoO0o
 if 10 - 10: ooOoO0o / OoooooooOO - ooOoO0o % O0 + oO0o - oO0o
 if 16 - 16: O0
 if 14 - 14: Ii1I . Ii1I . OOooOOo - O0 / OoO0O00 % II111iiii
 iIiI11iIi111i = ooo0OOO00 . lookup_source_cache ( eid , exact )
 if ( iIiI11iIi111i ) : return ( iIiI11iIi111i )
 if 5 - 5: iIii1I11I1II1 % OoOoOO00 % OOooOOo % O0 * oO0o . iIii1I11I1II1
 if ( exact ) :
  ooo0OOO00 = None
 else :
  i1Iii = ooo0OOO00 . parent_for_more_specifics
  if ( i1Iii and i1Iii . accept_more_specifics ) :
   if ( group . is_more_specific ( i1Iii . group ) ) : ooo0OOO00 = i1Iii
   if 96 - 96: i11iIiiIii + oO0o / I1ii11iIi11i . IiII % o0oOOo0O0Ooo
   if 41 - 41: o0oOOo0O0Ooo . i1IIi - OOooOOo
 return ( ooo0OOO00 )
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
 if 45 - 45: iIii1I11I1II1 - i1IIi % I1IiiI - I1Ii111 + oO0o
 if 15 - 15: iIii1I11I1II1 - OoooooooOO / ooOoO0o
 if 83 - 83: IiII + I1Ii111 / OoOoOO00 * IiII . oO0o
 if 22 - 22: O0 + ooOoO0o + I1Ii111
 if 57 - 57: OOooOOo . ooOoO0o - OoooooooOO - I1ii11iIi11i * O0
 if 85 - 85: I1IiiI * OoO0O00
 if 63 - 63: I1IiiI - i11iIiiIii
 if 4 - 4: OOooOOo + iIii1I11I1II1 / I1IiiI * Ii1I
 if 64 - 64: OoOoOO00
 if 94 - 94: OOooOOo * OoooooooOO * o0oOOo0O0Ooo / I1Ii111 . II111iiii
 if 37 - 37: O0 * II111iiii * I1IiiI - O0 - I11i / i1IIi
 if 27 - 27: i11iIiiIii + iIii1I11I1II1
 if 15 - 15: oO0o
 if 69 - 69: II111iiii * O0 . ooOoO0o * IiII
 if 25 - 25: I11i - I1ii11iIi11i . I1Ii111 . OoooooooOO
class lisp_address ( object ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 4 - 4: IiII * OoO0O00 % I1ii11iIi11i * Ii1I . iII111i
  if 41 - 41: OoooooooOO % I11i . O0 + I1Ii111
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 67 - 67: OoOoOO00 * OOooOOo / OOooOOo / OoooooooOO
  if 67 - 67: I11i - i1IIi . OoooooooOO / iIii1I11I1II1
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 34 - 34: OoO0O00 * II111iiii
  if 43 - 43: OoOoOO00 . I1IiiI
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 44 - 44: O0 / o0oOOo0O0Ooo
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 19 - 19: I11i
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 91 - 91: OOooOOo * OoooooooOO
   if 89 - 89: i1IIi / iII111i . I1Ii111
   if 74 - 74: I1ii11iIi11i % iII111i / OoooooooOO / I1ii11iIi11i % i11iIiiIii % ooOoO0o
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 82 - 82: OoooooooOO . o0oOOo0O0Ooo * I1ii11iIi11i % I1ii11iIi11i * Ii1I
  if 83 - 83: I11i - Oo0Ooo + i11iIiiIii - i11iIiiIii
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  OOOo = self . address
  if ( ( ( OOOo & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( OOOo & 0xff000000 ) >> 24 ) == 172 ) :
   o0oO00ooo0o = ( OOOo & 0x00ff0000 ) >> 16
   if ( o0oO00ooo0o >= 16 and o0oO00ooo0o <= 31 ) : return ( True )
   if 26 - 26: iII111i . i1IIi * OoOoOO00 + I1Ii111 . IiII % i11iIiiIii
  if ( ( ( OOOo & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 98 - 98: I1IiiI - oO0o / i11iIiiIii % I1ii11iIi11i * oO0o * OoO0O00
  if 74 - 74: I1Ii111 . I1ii11iIi11i - Ii1I * i11iIiiIii
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 36 - 36: II111iiii * Ii1I
  if 53 - 53: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo . Ii1I
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 79 - 79: Ii1I % O0 * OOooOOo
  return ( 0 )
  if 41 - 41: I1ii11iIi11i . OoooooooOO * I1ii11iIi11i - oO0o
  if 40 - 40: I1IiiI % OoO0O00 + i11iIiiIii / oO0o
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  OOOo = self . address >> 96
  return ( OOOo == 0x20010005 )
  if 98 - 98: oO0o + iIii1I11I1II1 . ooOoO0o / I1ii11iIi11i
  if 77 - 77: OoOoOO00 / Oo0Ooo * OoOoOO00 % I1IiiI . II111iiii % OoO0O00
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
   if 38 - 38: iII111i - OoO0O00 / i1IIi + ooOoO0o . ooOoO0o . iII111i
  return ( 0 )
  if 37 - 37: iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoooooooOO + OoO0O00
  if 25 - 25: I1IiiI / IiII . OOooOOo . I1ii11iIi11i % i1IIi
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 12 - 12: O0 % O0
  if 9 - 9: O0 . I1IiiI + I1ii11iIi11i / OOooOOo * I1ii11iIi11i
 def packet_format ( self ) :
  if 10 - 10: IiII % o0oOOo0O0Ooo / O0 / II111iiii
  if 81 - 81: Ii1I / o0oOOo0O0Ooo % OoOoOO00 . I1ii11iIi11i
  if 47 - 47: II111iiii + OOooOOo / II111iiii . OOooOOo
  if 68 - 68: OoooooooOO
  if 63 - 63: I1IiiI
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 80 - 80: oO0o + iIii1I11I1II1
  if 87 - 87: I1ii11iIi11i % Ii1I . Ii1I
 def pack_address ( self ) :
  oOOoooo0o0 = self . packet_format ( )
  OO0Oo00OO0oo = b""
  if ( self . is_ipv4 ( ) ) :
   OO0Oo00OO0oo = struct . pack ( oOOoooo0o0 , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   III = byte_swap_64 ( self . address >> 64 )
   I1I = byte_swap_64 ( self . address & 0xffffffffffffffff )
   OO0Oo00OO0oo = struct . pack ( oOOoooo0o0 , III , I1I )
  elif ( self . is_mac ( ) ) :
   OOOo = self . address
   III = ( OOOo >> 32 ) & 0xffff
   I1I = ( OOOo >> 16 ) & 0xffff
   OOo00o0o = OOOo & 0xffff
   OO0Oo00OO0oo = struct . pack ( oOOoooo0o0 , III , I1I , OOo00o0o )
  elif ( self . is_e164 ( ) ) :
   OOOo = self . address
   III = ( OOOo >> 32 ) & 0xffffffff
   I1I = ( OOOo & 0xffffffff )
   OO0Oo00OO0oo = struct . pack ( oOOoooo0o0 , III , I1I )
  elif ( self . is_dist_name ( ) ) :
   OO0Oo00OO0oo += ( self . address + "\0" ) . encode ( )
   if 74 - 74: I1Ii111 - i11iIiiIii * OoooooooOO
  return ( OO0Oo00OO0oo )
  if 90 - 90: i1IIi
  if 52 - 52: IiII + ooOoO0o - II111iiii - OoooooooOO * OoO0O00 - iIii1I11I1II1
 def unpack_address ( self , packet ) :
  oOOoooo0o0 = self . packet_format ( )
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 38 - 38: II111iiii % iIii1I11I1II1 * IiII * OoOoOO00 % II111iiii . I1IiiI
  OOOo = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  if 35 - 35: OoooooooOO - i11iIiiIii * i11iIiiIii % Ii1I - OOooOOo . iIii1I11I1II1
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( OOOo [ 0 ] )
   if 96 - 96: OOooOOo
  elif ( self . is_ipv6 ( ) ) :
   if 18 - 18: oO0o . I1ii11iIi11i % oO0o
   if 43 - 43: oO0o / ooOoO0o . o0oOOo0O0Ooo . iIii1I11I1II1
   if 63 - 63: iII111i * iII111i
   if 78 - 78: iIii1I11I1II1 % iIii1I11I1II1 . iIii1I11I1II1 / Ii1I . O0 + i1IIi
   if 53 - 53: Ii1I . I1ii11iIi11i - OOooOOo - ooOoO0o
   if 17 - 17: OoooooooOO / I1IiiI * ooOoO0o % I1ii11iIi11i . OoO0O00
   if 5 - 5: OoO0O00 % I1Ii111 . oO0o . Ii1I + I1IiiI
   if 95 - 95: II111iiii . iII111i - iIii1I11I1II1 / I11i + ooOoO0o * I1Ii111
   if ( OOOo [ 0 ] <= 0xffff and ( OOOo [ 0 ] & 0xff ) == 0 ) :
    O00ooO0OoOO0O = ( OOOo [ 0 ] << 48 ) << 64
   else :
    O00ooO0OoOO0O = byte_swap_64 ( OOOo [ 0 ] ) << 64
    if 53 - 53: II111iiii + I11i / IiII % OoO0O00 * i11iIiiIii
   O0II11II1111 = byte_swap_64 ( OOOo [ 1 ] )
   self . address = O00ooO0OoOO0O | O0II11II1111
   if 32 - 32: I1IiiI / i1IIi / I1ii11iIi11i % i1IIi . ooOoO0o % I1ii11iIi11i
  elif ( self . is_mac ( ) ) :
   OOO00o00o = OOOo [ 0 ]
   OOoO00O = OOOo [ 1 ]
   IiiIi1ii111 = OOOo [ 2 ]
   self . address = ( OOO00o00o << 32 ) + ( OOoO00O << 16 ) + IiiIi1ii111
   if 7 - 7: I1IiiI - OoOoOO00 + II111iiii
  elif ( self . is_e164 ( ) ) :
   self . address = ( OOOo [ 0 ] << 32 ) + OOOo [ 1 ]
   if 25 - 25: IiII
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   I1I11i = 0
   if 46 - 46: OOooOOo / Ii1I
  packet = packet [ I1I11i : : ]
  return ( packet )
  if 80 - 80: I11i . I11i * OoOoOO00 + IiII
  if 74 - 74: iII111i / ooOoO0o * iIii1I11I1II1 - OOooOOo
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 74 - 74: i1IIi . IiII / ooOoO0o + I11i % i11iIiiIii % iII111i
  if 62 - 62: i1IIi % I1Ii111
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 94 - 94: i1IIi + iII111i
  if 25 - 25: I1Ii111 . Ii1I - Ii1I . o0oOOo0O0Ooo - IiII
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 91 - 91: o0oOOo0O0Ooo % I1ii11iIi11i % OoOoOO00 * iIii1I11I1II1
  if 18 - 18: OoOoOO00 * I1ii11iIi11i . i1IIi * iII111i
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 67 - 67: IiII + i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i11iIiiIii
  if 23 - 23: Oo0Ooo
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 7 - 7: Oo0Ooo / oO0o . I1Ii111 % I11i
  if 85 - 85: II111iiii / o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO / Ii1I
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 18 - 18: i11iIiiIii + o0oOOo0O0Ooo . i11iIiiIii
  if 50 - 50: IiII / OoooooooOO . I11i
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 93 - 93: OOooOOo / OoooooooOO % iII111i % Ii1I / I1Ii111 % OOooOOo
  if 25 - 25: i1IIi % Oo0Ooo . i1IIi * OoOoOO00 . Ii1I % OoO0O00
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 47 - 47: o0oOOo0O0Ooo - i11iIiiIii / OoooooooOO
  if 93 - 93: I1IiiI * II111iiii * O0 % o0oOOo0O0Ooo + oO0o / ooOoO0o
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 79 - 79: OoO0O00 + ooOoO0o / oO0o % I1ii11iIi11i
  if 77 - 77: Ii1I / Ii1I / I1ii11iIi11i
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 92 - 92: O0 * i11iIiiIii . OoOoOO00 * IiII / o0oOOo0O0Ooo * ooOoO0o
  if 74 - 74: O0 - o0oOOo0O0Ooo
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 68 - 68: I1Ii111
  if 19 - 19: o0oOOo0O0Ooo
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 63 - 63: OoooooooOO % ooOoO0o
  if 26 - 26: OOooOOo + Oo0Ooo
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 97 - 97: I1Ii111 * I1Ii111 + iII111i % Ii1I / iII111i
  if 73 - 73: OoOoOO00 % I1Ii111 . I1ii11iIi11i
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 45 - 45: iIii1I11I1II1 % Ii1I . OoOoOO00 . o0oOOo0O0Ooo - OoooooooOO
  if 46 - 46: I1ii11iIi11i
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 32 - 32: iII111i * i11iIiiIii / IiII + i11iIiiIii + O0
  if 51 - 51: I1Ii111
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 95 - 95: Ii1I / Ii1I * OoO0O00 . OoooooooOO . OoooooooOO * I11i
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 76 - 76: OoooooooOO - Ii1I + IiII % OoOoOO00 / OoooooooOO
  return ( False )
  if 55 - 55: i11iIiiIii - IiII * OOooOOo + II111iiii . I1ii11iIi11i / O0
  if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 98 - 98: II111iiii - i1IIi - ooOoO0o
  if 36 - 36: IiII + o0oOOo0O0Ooo
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 81 - 81: OOooOOo / I11i % oO0o + ooOoO0o
  if 10 - 10: oO0o / i11iIiiIii
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 73 - 73: OoO0O00 - i1IIi
  if 52 - 52: I1ii11iIi11i
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 4 - 4: Ii1I - iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
  if 18 - 18: oO0o % iIii1I11I1II1 + ooOoO0o
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 34 - 34: I1IiiI - OoooooooOO . IiII - OOooOOo % IiII
  if 19 - 19: IiII + I1ii11iIi11i % Oo0Ooo
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 32 - 32: OOooOOo
  if 46 - 46: II111iiii . OoO0O00
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 97 - 97: oO0o
  if 45 - 45: i11iIiiIii / IiII + OoO0O00
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 55 - 55: Ii1I / II111iiii - oO0o
  if 58 - 58: i1IIi . OoooooooOO % iIii1I11I1II1 * o0oOOo0O0Ooo + O0 / oO0o
  if 77 - 77: I11i . I1ii11iIi11i
  if 92 - 92: i11iIiiIii + I11i % I1IiiI / ooOoO0o
  iIiIIi = addr_str . find ( "[" )
  i111Ii11i = addr_str . find ( "]" )
  if ( iIiIIi != - 1 and i111Ii11i != - 1 ) :
   self . instance_id = int ( addr_str [ iIiIIi + 1 : i111Ii11i ] )
   addr_str = addr_str [ i111Ii11i + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 28 - 28: i1IIi . I1IiiI
    if 41 - 41: I1ii11iIi11i . I1Ii111 * OoOoOO00 . I1Ii111 / o0oOOo0O0Ooo
    if 41 - 41: o0oOOo0O0Ooo / o0oOOo0O0Ooo . Oo0Ooo
    if 4 - 4: I1Ii111
    if 85 - 85: iIii1I11I1II1 % Oo0Ooo
    if 20 - 20: IiII + i11iIiiIii * OOooOOo
  if ( self . is_ipv4 ( ) ) :
   ii1III1IiIII1 = addr_str . split ( "." )
   IiIi1i = int ( ii1III1IiIII1 [ 0 ] ) << 24
   IiIi1i += int ( ii1III1IiIII1 [ 1 ] ) << 16
   IiIi1i += int ( ii1III1IiIII1 [ 2 ] ) << 8
   IiIi1i += int ( ii1III1IiIII1 [ 3 ] )
   self . address = IiIi1i
  elif ( self . is_ipv6 ( ) ) :
   if 51 - 51: I1ii11iIi11i * OOooOOo
   if 100 - 100: OoO0O00 * oO0o + I1IiiI - o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoO0O00
   if 65 - 65: OoooooooOO / OoOoOO00 + I1IiiI - II111iiii / OoOoOO00
   if 69 - 69: i11iIiiIii
   if 77 - 77: I1ii11iIi11i % OoooooooOO - Oo0Ooo - Ii1I + I11i
   if 93 - 93: I1IiiI % O0 * OoO0O00 % OoOoOO00 . I1Ii111 * I1IiiI
   if 95 - 95: IiII + o0oOOo0O0Ooo - o0oOOo0O0Ooo
   if 83 - 83: ooOoO0o
   if 59 - 59: I1ii11iIi11i
   if 26 - 26: I11i . Ii1I
   if 94 - 94: ooOoO0o . I1IiiI + IiII % I1IiiI / o0oOOo0O0Ooo % o0oOOo0O0Ooo
   if 21 - 21: O0 / OOooOOo - II111iiii + I1ii11iIi11i / OoooooooOO
   if 81 - 81: i11iIiiIii / Oo0Ooo * i1IIi + OoO0O00 + O0 % I1ii11iIi11i
   if 3 - 3: i11iIiiIii * IiII . Oo0Ooo % OoOoOO00 * I11i . iII111i
   if 80 - 80: I11i - IiII
   if 40 - 40: OOooOOo * I1IiiI % I11i . I1Ii111 % O0 . O0
   if 14 - 14: ooOoO0o . OoOoOO00 + ooOoO0o * OoOoOO00 . OoOoOO00 * Oo0Ooo
   ii1i = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 54 - 54: OOooOOo
   addr_str = binascii . hexlify ( addr_str )
   if 77 - 77: iIii1I11I1II1 % I1Ii111 + II111iiii
   if ( ii1i ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 40 - 40: I1ii11iIi11i / I1ii11iIi11i + I1IiiI + OoOoOO00
   self . address = int ( addr_str , 16 )
   if 76 - 76: iIii1I11I1II1 . iIii1I11I1II1 / OOooOOo / OoOoOO00 / iII111i / II111iiii
  elif ( self . is_geo_prefix ( ) ) :
   I1II1II1i = lisp_geo ( None )
   I1II1II1i . name = "geo-prefix-{}" . format ( I1II1II1i )
   I1II1II1i . parse_geo_string ( addr_str )
   self . address = I1II1II1i
  elif ( self . is_mac ( ) ) :
   addr_str = addr_str . replace ( "-" , "" )
   IiIi1i = int ( addr_str , 16 )
   self . address = IiIi1i
  elif ( self . is_e164 ( ) ) :
   addr_str = addr_str [ 1 : : ]
   IiIi1i = int ( addr_str , 16 )
   self . address = IiIi1i << 4
  elif ( self . is_dist_name ( ) ) :
   self . address = addr_str . replace ( "'" , "" )
   if 64 - 64: i1IIi * II111iiii + I1ii11iIi11i + OOooOOo % I1ii11iIi11i - OoooooooOO
  self . mask_len = self . host_mask_len ( )
  if 96 - 96: IiII + oO0o / Oo0Ooo + OoooooooOO
  if 53 - 53: Ii1I * IiII + Oo0Ooo + i11iIiiIii - iIii1I11I1II1
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   o00o = prefix_str . find ( "]" )
   i111iii1i1 = len ( prefix_str [ o00o + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , i111iii1i1 = prefix_str . split ( "/" )
  else :
   oO000o = prefix_str . find ( "'" )
   if ( oO000o == - 1 ) : return
   iIiI1IIiii11 = prefix_str . find ( "'" , oO000o + 1 )
   if ( iIiI1IIiii11 == - 1 ) : return
   i111iii1i1 = len ( prefix_str [ oO000o + 1 : iIiI1IIiii11 ] ) * 8
   if 66 - 66: O0 - I1ii11iIi11i * iIii1I11I1II1 - I1Ii111 / I1ii11iIi11i
   if 24 - 24: Ii1I
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( i111iii1i1 )
  if 39 - 39: O0 % Ii1I
  if 63 - 63: OOooOOo / I1ii11iIi11i
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  iiiIiIIIi1I = ( 2 ** self . mask_len ) - 1
  ii1oOOOo = self . addr_length ( ) * 8 - self . mask_len
  iiiIiIIIi1I <<= ii1oOOOo
  self . address &= iiiIiIIIi1I
  if 90 - 90: I1IiiI - OOooOOo / OoO0O00 / I11i
  if 39 - 39: OoooooooOO
 def is_geo_string ( self , addr_str ) :
  o00o = addr_str . find ( "]" )
  if ( o00o != - 1 ) : addr_str = addr_str [ o00o + 1 : : ]
  if 6 - 6: II111iiii / OoOoOO00 % ooOoO0o . i1IIi + I11i
  I1II1II1i = addr_str . split ( "/" )
  if ( len ( I1II1II1i ) == 2 ) :
   if ( I1II1II1i [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 63 - 63: OoO0O00 % i11iIiiIii - iII111i * o0oOOo0O0Ooo / OoOoOO00
  I1II1II1i = I1II1II1i [ 0 ]
  I1II1II1i = I1II1II1i . split ( "-" )
  o0000OO0 = len ( I1II1II1i )
  if ( o0000OO0 < 8 or o0000OO0 > 9 ) : return ( False )
  if 89 - 89: IiII
  for ooooo0O in range ( 0 , o0000OO0 ) :
   if ( ooooo0O == 3 ) :
    if ( I1II1II1i [ ooooo0O ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 47 - 47: I1IiiI / o0oOOo0O0Ooo
   if ( ooooo0O == 7 ) :
    if ( I1II1II1i [ ooooo0O ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 47 - 47: i1IIi / Oo0Ooo % IiII % OoO0O00 + Ii1I
   if ( I1II1II1i [ ooooo0O ] . isdigit ( ) == False ) : return ( False )
   if 31 - 31: I11i / I11i
  return ( True )
  if 90 - 90: II111iiii . I1Ii111
  if 26 - 26: I1Ii111 * O0 / oO0o
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 33 - 33: o0oOOo0O0Ooo * OOooOOo
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 7 - 7: i11iIiiIii . OOooOOo * Ii1I . i1IIi
  if 4 - 4: O0 - IiII - II111iiii / iII111i - OOooOOo
 def print_address ( self ) :
  OOOo = self . print_address_no_iid ( )
  oO0O = "[" + str ( self . instance_id )
  for iIiIIi in self . iid_list : oO0O += "," + str ( iIiIIi )
  oO0O += "]"
  OOOo = "{}{}" . format ( oO0O , OOOo )
  return ( OOOo )
  if 6 - 6: ooOoO0o + OOooOOo - I1IiiI + OOooOOo
  if 16 - 16: OoO0O00 * OoOoOO00 - Oo0Ooo
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   OOOo = self . address
   I1IIIiiIIIii1iII = OOOo >> 24
   oooOoo00 = ( OOOo >> 16 ) & 0xff
   OOOoooo = ( OOOo >> 8 ) & 0xff
   I111II = OOOo & 0xff
   return ( "{}.{}.{}.{}" . format ( I1IIIiiIIIii1iII , oooOoo00 , OOOoooo , I111II ) )
  elif ( self . is_ipv6 ( ) ) :
   Oo0o = lisp_hex_string ( self . address ) . zfill ( 32 )
   Oo0o = binascii . unhexlify ( Oo0o )
   Oo0o = socket . inet_ntop ( socket . AF_INET6 , Oo0o )
   return ( "{}" . format ( Oo0o ) )
  elif ( self . is_geo_prefix ( ) ) :
   return ( "{}" . format ( self . address . print_geo ( ) ) )
  elif ( self . is_mac ( ) ) :
   Oo0o = lisp_hex_string ( self . address ) . zfill ( 12 )
   Oo0o = "{}-{}-{}" . format ( Oo0o [ 0 : 4 ] , Oo0o [ 4 : 8 ] ,
 Oo0o [ 8 : 12 ] )
   return ( "{}" . format ( Oo0o ) )
  elif ( self . is_e164 ( ) ) :
   Oo0o = lisp_hex_string ( self . address ) . zfill ( 15 )
   return ( "+{}" . format ( Oo0o ) )
  elif ( self . is_dist_name ( ) ) :
   return ( "'{}'" . format ( self . address ) )
  elif ( self . is_null ( ) ) :
   return ( "no-address" )
   if 22 - 22: I1Ii111 - OOooOOo * i1IIi
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 88 - 88: ooOoO0o + iIii1I11I1II1 + OoO0O00 * I1Ii111 + oO0o
  if 39 - 39: ooOoO0o - oO0o + OoOoOO00 - oO0o - Ii1I % I1Ii111
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   O000o00O0OOoo = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , O000o00O0OOoo ) )
   if 32 - 32: I1Ii111 . I1IiiI
  OOOo = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( OOOo )
  if ( self . is_geo_prefix ( ) ) : return ( OOOo )
  if 78 - 78: OoOoOO00 . I1ii11iIi11i / o0oOOo0O0Ooo
  o00o = OOOo . find ( "no-address" )
  if ( o00o == - 1 ) :
   OOOo = "{}/{}" . format ( OOOo , str ( self . mask_len ) )
  else :
   OOOo = OOOo [ 0 : o00o ]
   if 57 - 57: IiII % O0 * I1ii11iIi11i
  return ( OOOo )
  if 61 - 61: O0
  if 51 - 51: I1Ii111 - I11i % o0oOOo0O0Ooo * Oo0Ooo - oO0o + II111iiii
 def print_prefix_no_iid ( self ) :
  OOOo = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( OOOo )
  if ( self . is_geo_prefix ( ) ) : return ( OOOo )
  return ( "{}/{}" . format ( OOOo , str ( self . mask_len ) ) )
  if 7 - 7: oO0o
  if 98 - 98: Ii1I + oO0o + i1IIi + IiII % IiII
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  OOOo = self . print_address ( )
  o00o = OOOo . find ( "]" )
  if ( o00o != - 1 ) : OOOo = OOOo [ o00o + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   OOOo = OOOo . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , OOOo ) )
   if 79 - 79: oO0o % I11i * I11i . OOooOOo % OoooooooOO
  return ( "{}-{}-{}" . format ( self . instance_id , OOOo , self . mask_len ) )
  if 71 - 71: iII111i
  if 48 - 48: OoOoOO00 + oO0o
 def print_sg ( self , g ) :
  o0O0o0000o0O0 = self . print_prefix ( )
  Ii11 = o0O0o0000o0O0 . find ( "]" ) + 1
  g = g . print_prefix ( )
  OoOo000O0oo = g . find ( "]" ) + 1
  OooooOo0 = "[{}]({}, {})" . format ( self . instance_id , o0O0o0000o0O0 [ Ii11 : : ] , g [ OoOo000O0oo : : ] )
  return ( OooooOo0 )
  if 66 - 66: Ii1I + O0 . Ii1I % IiII % I1ii11iIi11i - OoOoOO00
  if 94 - 94: I1IiiI . I1Ii111
 def hash_address ( self , addr ) :
  III = self . address
  I1I = addr . address
  if 37 - 37: i1IIi - O0
  if ( self . is_geo_prefix ( ) ) : III = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : I1I = addr . address . print_geo ( )
  if 36 - 36: I1Ii111 . OoooooooOO - i1IIi % iII111i - II111iiii * i11iIiiIii
  if ( type ( III ) == str ) :
   III = int ( binascii . hexlify ( III [ 0 : 1 ] ) )
   if 90 - 90: OoOoOO00 % iII111i - Oo0Ooo
  if ( type ( I1I ) == str ) :
   I1I = int ( binascii . hexlify ( I1I [ 0 : 1 ] ) )
   if 13 - 13: o0oOOo0O0Ooo / O0 . I1Ii111 * I1Ii111
  return ( III ^ I1I )
  if 76 - 76: Ii1I - iII111i
  if 79 - 79: o0oOOo0O0Ooo + IiII / o0oOOo0O0Ooo - I1IiiI / OoooooooOO
  if 17 - 17: OOooOOo * I1ii11iIi11i . Ii1I . iIii1I11I1II1 * OoooooooOO
  if 60 - 60: II111iiii % Oo0Ooo * I11i * OoO0O00 - OoOoOO00
  if 65 - 65: iII111i
  if 86 - 86: OoO0O00 / II111iiii % OoOoOO00 * OOooOOo . I1IiiI / IiII
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 100 - 100: i1IIi / I1IiiI * I1ii11iIi11i % ooOoO0o + OoO0O00 * oO0o
  i111iii1i1 = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   O0ooo00Oo = 2 ** ( 32 - i111iii1i1 )
   oOOooo0 = prefix . instance_id
   O000o00O0OOoo = oOOooo0 + O0ooo00Oo
   return ( self . instance_id in range ( oOOooo0 , O000o00O0OOoo ) )
   if 22 - 22: o0oOOo0O0Ooo . OOooOOo + OoOoOO00
   if 34 - 34: Ii1I
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 85 - 85: ooOoO0o % i11iIiiIii * oO0o / ooOoO0o / I1Ii111 . i11iIiiIii
   if 23 - 23: i1IIi + I1Ii111 / Oo0Ooo * O0 . O0
   if 67 - 67: OoO0O00 - II111iiii + Ii1I
   if 41 - 41: oO0o + O0 / I1ii11iIi11i
   if 55 - 55: iIii1I11I1II1 * oO0o / iII111i / i1IIi % Oo0Ooo . OoOoOO00
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   OOOo = self . address
   i1IiI = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    OOOo = self . address . print_geo ( )
    i1IiI = prefix . address . print_geo ( )
    if 53 - 53: OoO0O00 + iII111i / OoooooooOO
   if ( len ( OOOo ) < len ( i1IiI ) ) : return ( False )
   return ( OOOo . find ( i1IiI ) == 0 )
   if 52 - 52: O0
   if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
   if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
   if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
   if 83 - 83: oO0o / OoO0O00
  if ( self . mask_len < i111iii1i1 ) : return ( False )
  if 34 - 34: OoooooooOO - i1IIi * O0
  ii1oOOOo = ( prefix . addr_length ( ) * 8 ) - i111iii1i1
  iiiIiIIIi1I = ( 2 ** i111iii1i1 - 1 ) << ii1oOOOo
  return ( ( self . address & iiiIiIIIi1I ) == prefix . address )
  if 83 - 83: I1IiiI + OoO0O00
  if 41 - 41: Ii1I + II111iiii . OOooOOo * I1Ii111 / II111iiii
 def mask_address ( self , mask_len ) :
  ii1oOOOo = ( self . addr_length ( ) * 8 ) - mask_len
  iiiIiIIIi1I = ( 2 ** mask_len - 1 ) << ii1oOOOo
  self . address &= iiiIiIIIi1I
  if 32 - 32: Oo0Ooo - Ii1I % o0oOOo0O0Ooo
  if 15 - 15: iIii1I11I1II1 * I1ii11iIi11i / ooOoO0o * oO0o % OOooOOo
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  O0oO = self . print_prefix ( )
  o0o0OOOOoO = prefix . print_prefix ( ) if prefix else ""
  return ( O0oO == o0o0OOOOoO )
  if 54 - 54: II111iiii + OOooOOo * Oo0Ooo * I1Ii111 - o0oOOo0O0Ooo % Ii1I
  if 69 - 69: I11i + OoOoOO00 - i11iIiiIii * O0 % O0
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   O00Oo000 = lisp_myrlocs [ 0 ]
   if ( O00Oo000 == None ) : return ( False )
   O00Oo000 = O00Oo000 . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == O00Oo000 )
   if 29 - 29: iIii1I11I1II1 / i11iIiiIii + Oo0Ooo
  if ( self . is_ipv6 ( ) ) :
   O00Oo000 = lisp_myrlocs [ 1 ]
   if ( O00Oo000 == None ) : return ( False )
   O00Oo000 = O00Oo000 . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == O00Oo000 )
   if 99 - 99: I1IiiI - iII111i * Ii1I - OoOoOO00 / i11iIiiIii - i1IIi
  return ( False )
  if 46 - 46: I1ii11iIi11i * ooOoO0o
  if 4 - 4: I1Ii111 * II111iiii
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid == 0 and mask_len == 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 4 - 4: ooOoO0o * Oo0Ooo - I1ii11iIi11i % ooOoO0o % OoOoOO00
  self . instance_id = iid
  self . mask_len = mask_len
  if 18 - 18: OOooOOo / O0 . OoO0O00 - II111iiii * OOooOOo
  if 13 - 13: OoO0O00 % i1IIi . i11iIiiIii / iII111i
 def lcaf_length ( self , lcaf_type ) :
  iIo00oo = self . addr_length ( ) + 2
  if ( lcaf_type == LISP_LCAF_AFI_LIST_TYPE ) : iIo00oo += 4
  if ( lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE ) : iIo00oo += 4
  if ( lcaf_type == LISP_LCAF_ASN_TYPE ) : iIo00oo += 4
  if ( lcaf_type == LISP_LCAF_APP_DATA_TYPE ) : iIo00oo += 8
  if ( lcaf_type == LISP_LCAF_GEO_COORD_TYPE ) : iIo00oo += 12
  if ( lcaf_type == LISP_LCAF_OPAQUE_TYPE ) : iIo00oo += 0
  if ( lcaf_type == LISP_LCAF_NAT_TYPE ) : iIo00oo += 4
  if ( lcaf_type == LISP_LCAF_NONCE_LOC_TYPE ) : iIo00oo += 4
  if ( lcaf_type == LISP_LCAF_MCAST_INFO_TYPE ) : iIo00oo = iIo00oo * 2 + 8
  if ( lcaf_type == LISP_LCAF_ELP_TYPE ) : iIo00oo += 0
  if ( lcaf_type == LISP_LCAF_SECURITY_TYPE ) : iIo00oo += 6
  if ( lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE ) : iIo00oo += 4
  if ( lcaf_type == LISP_LCAF_RLE_TYPE ) : iIo00oo += 4
  return ( iIo00oo )
  if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
  if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
  if 4 - 4: Ii1I - Oo0Ooo . i1IIi + iIii1I11I1II1
  if 28 - 28: O0 / ooOoO0o / IiII - I11i + IiII + OoO0O00
  if 84 - 84: Oo0Ooo + OoOoOO00 / iII111i . I1ii11iIi11i
  if 26 - 26: Oo0Ooo
  if 61 - 61: Ii1I * oO0o * i11iIiiIii + OoO0O00
  if 43 - 43: OoO0O00 * OoO0O00 * oO0o
  if 24 - 24: oO0o
  if 77 - 77: i11iIiiIii - I1Ii111 - I1ii11iIi11i * Oo0Ooo / i11iIiiIii
  if 79 - 79: Oo0Ooo % Oo0Ooo . oO0o + ooOoO0o * iII111i * I11i
  if 87 - 87: o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo + I1IiiI
  if 89 - 89: II111iiii
  if 41 - 41: iIii1I11I1II1
  if 26 - 26: Oo0Ooo / i1IIi + Oo0Ooo
  if 76 - 76: I1ii11iIi11i * i1IIi % oO0o
  if 80 - 80: i1IIi * II111iiii . O0 % I1ii11iIi11i / ooOoO0o
 def lcaf_encode_iid ( self ) :
  ii1iI1IIiIi = LISP_LCAF_INSTANCE_ID_TYPE
  IIi1IiIii = socket . htons ( self . lcaf_length ( ii1iI1IIiIi ) )
  oO0O = self . instance_id
  II1i1iI = self . afi
  OoOO0oo0OOOO = 0
  if ( II1i1iI < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    II1i1iI = LISP_AFI_LCAF
    OoOO0oo0OOOO = 0
   else :
    II1i1iI = 0
    OoOO0oo0OOOO = self . mask_len
    if 58 - 58: I1IiiI * I1ii11iIi11i - i1IIi % I1Ii111 % O0
    if 24 - 24: I11i + I11i % I11i
    if 63 - 63: i11iIiiIii + iIii1I11I1II1 / oO0o % IiII - O0
  i111I = struct . pack ( "BBBBH" , 0 , 0 , ii1iI1IIiIi , OoOO0oo0OOOO , IIi1IiIii )
  i111I += struct . pack ( "IH" , socket . htonl ( oO0O ) , socket . htons ( II1i1iI ) )
  if ( II1i1iI == 0 ) : return ( i111I )
  if 89 - 89: I11i
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   i111I = i111I [ 0 : - 2 ]
   i111I += self . address . encode_geo ( )
   return ( i111I )
   if 48 - 48: I1Ii111 - O0
   if 23 - 23: iIii1I11I1II1
  i111I += self . pack_address ( )
  return ( i111I )
  if 88 - 88: I1IiiI + iII111i / Ii1I
  if 57 - 57: o0oOOo0O0Ooo
 def lcaf_decode_iid ( self , packet ) :
  oOOoooo0o0 = "BBBBH"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 69 - 69: i1IIi / i1IIi / OoOoOO00 + ooOoO0o % I1Ii111
  iII , I111I1I , ii1iI1IIiIi , ii1iiI1i1iiii , iIo00oo = struct . unpack ( oOOoooo0o0 ,
 packet [ : I1I11i ] )
  packet = packet [ I1I11i : : ]
  if 40 - 40: OOooOOo - ooOoO0o . OoooooooOO % O0 * I11i - I1ii11iIi11i
  if ( ii1iI1IIiIi != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 92 - 92: ooOoO0o % oO0o / i11iIiiIii
  oOOoooo0o0 = "IH"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( None )
  if 91 - 91: OOooOOo
  oO0O , II1i1iI = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  packet = packet [ I1I11i : : ]
  if 60 - 60: i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
  iIo00oo = socket . ntohs ( iIo00oo )
  self . instance_id = socket . ntohl ( oO0O )
  II1i1iI = socket . ntohs ( II1i1iI )
  self . afi = II1i1iI
  if ( ii1iiI1i1iiii != 0 and II1i1iI == 0 ) : self . mask_len = ii1iiI1i1iiii
  if ( II1i1iI == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if ii1iiI1i1iiii else LISP_AFI_ULTIMATE_ROOT
   if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
   if 54 - 54: II111iiii * I1IiiI
   if 49 - 49: I1ii11iIi11i
   if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
   if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
  if ( II1i1iI == 0 ) : return ( packet )
  if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
  if 15 - 15: oO0o
  if 40 - 40: I1Ii111
  if 77 - 77: II111iiii - o0oOOo0O0Ooo . Ii1I
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 47 - 47: o0oOOo0O0Ooo % OOooOOo + I1Ii111
   if 64 - 64: ooOoO0o / IiII . I1IiiI
   if 77 - 77: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
   if 90 - 90: I11i
   if 53 - 53: I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoooooooOO + IiII * I1IiiI
  if ( II1i1iI == LISP_AFI_LCAF ) :
   oOOoooo0o0 = "BBBBH"
   I1I11i = struct . calcsize ( oOOoooo0o0 )
   if ( len ( packet ) < I1I11i ) : return ( None )
   if 16 - 16: i11iIiiIii - oO0o . i11iIiiIii + OoO0O00 + i11iIiiIii
   iII1IiI1I11i , Ii1i11I11i , ii1iI1IIiIi , oO0oooo , ooo0oO0o000O0 = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
   if 85 - 85: I1ii11iIi11i - ooOoO0o + I1Ii111 + I1Ii111
   if 13 - 13: II111iiii
   if ( ii1iI1IIiIi != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 22 - 22: o0oOOo0O0Ooo
   ooo0oO0o000O0 = socket . ntohs ( ooo0oO0o000O0 )
   packet = packet [ I1I11i : : ]
   if ( ooo0oO0o000O0 > len ( packet ) ) : return ( None )
   if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
   I1II1II1i = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = I1II1II1i
   packet = I1II1II1i . decode_geo ( packet , ooo0oO0o000O0 , oO0oooo )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 12 - 12: I1ii11iIi11i / O0
   if 18 - 18: OoOoOO00 . i11iIiiIii + i1IIi / OoooooooOO - IiII % OoO0O00
  IIi1IiIii = self . addr_length ( )
  if ( len ( packet ) < IIi1IiIii ) : return ( None )
  if 47 - 47: iII111i % IiII + I1Ii111 * o0oOOo0O0Ooo * OoooooooOO
  packet = self . unpack_address ( packet )
  return ( packet )
  if 100 - 100: Oo0Ooo / I1IiiI / iII111i / I1Ii111 / oO0o % o0oOOo0O0Ooo
  if 16 - 16: I1IiiI + I11i
  if 66 - 66: OoooooooOO % II111iiii / I1Ii111 . i11iIiiIii
  if 67 - 67: Ii1I + Oo0Ooo - I1IiiI - IiII + oO0o + Oo0Ooo
  if 84 - 84: I1ii11iIi11i % oO0o - OOooOOo * Ii1I
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
  if 58 - 58: IiII % i1IIi . i11iIiiIii
  if 5 - 5: OoOoOO00
  if 75 - 75: OOooOOo
  if 60 - 60: ooOoO0o - II111iiii - iIii1I11I1II1
  if 23 - 23: I1ii11iIi11i
  if 68 - 68: OoO0O00 . oO0o / IiII - II111iiii % Oo0Ooo
 def lcaf_encode_sg ( self , group ) :
  ii1iI1IIiIi = LISP_LCAF_MCAST_INFO_TYPE
  oO0O = socket . htonl ( self . instance_id )
  IIi1IiIii = socket . htons ( self . lcaf_length ( ii1iI1IIiIi ) )
  i111I = struct . pack ( "BBBBHIHBB" , 0 , 0 , ii1iI1IIiIi , 0 , IIi1IiIii , oO0O ,
 0 , self . mask_len , group . mask_len )
  if 24 - 24: II111iiii / I1ii11iIi11i + oO0o / Ii1I + IiII % oO0o
  i111I += struct . pack ( "H" , socket . htons ( self . afi ) )
  i111I += self . pack_address ( )
  i111I += struct . pack ( "H" , socket . htons ( group . afi ) )
  i111I += group . pack_address ( )
  return ( i111I )
  if 86 - 86: I1IiiI
  if 83 - 83: I11i % Ii1I + IiII % I11i / i1IIi . oO0o
 def lcaf_decode_sg ( self , packet ) :
  oOOoooo0o0 = "BBBBHIHBB"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( [ None , None ] )
  if 56 - 56: I1Ii111 - OOooOOo % o0oOOo0O0Ooo
  iII , I111I1I , ii1iI1IIiIi , ii , iIo00oo , oO0O , i1i1IiIiiI , Oooo , iIIiIiI1 = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
  if 95 - 95: i1IIi . I1Ii111
  packet = packet [ I1I11i : : ]
  if 94 - 94: I1IiiI + Ii1I + i1IIi . iIii1I11I1II1
  if ( ii1iI1IIiIi != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 64 - 64: O0 * OOooOOo * I1IiiI - o0oOOo0O0Ooo
  self . instance_id = socket . ntohl ( oO0O )
  iIo00oo = socket . ntohs ( iIo00oo ) - 8
  if 86 - 86: i1IIi
  if 84 - 84: OoOoOO00
  if 31 - 31: iIii1I11I1II1 + I1IiiI
  if 82 - 82: I1Ii111 / Ii1I % OoooooooOO - IiII / OoooooooOO
  if 23 - 23: iIii1I11I1II1
  oOOoooo0o0 = "H"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( [ None , None ] )
  if ( iIo00oo < I1I11i ) : return ( [ None , None ] )
  if 7 - 7: IiII / OOooOOo + Oo0Ooo . I1IiiI
  II1i1iI = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] ) [ 0 ]
  packet = packet [ I1I11i : : ]
  iIo00oo -= I1I11i
  self . afi = socket . ntohs ( II1i1iI )
  self . mask_len = Oooo
  IIi1IiIii = self . addr_length ( )
  if ( iIo00oo < IIi1IiIii ) : return ( [ None , None ] )
  if 33 - 33: I1Ii111 + OoooooooOO
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 73 - 73: O0 . Oo0Ooo
  iIo00oo -= IIi1IiIii
  if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
  if 48 - 48: II111iiii % I1ii11iIi11i - II111iiii
  if 29 - 29: I1Ii111 - I1Ii111 - I11i * iIii1I11I1II1 % OoO0O00 % IiII
  if 73 - 73: i1IIi . OoooooooOO / OoOoOO00 % Ii1I / Ii1I / Ii1I
  if 40 - 40: I1Ii111 - iIii1I11I1II1
  oOOoooo0o0 = "H"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( [ None , None ] )
  if ( iIo00oo < I1I11i ) : return ( [ None , None ] )
  if 88 - 88: OOooOOo * O0 * OoOoOO00
  II1i1iI = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] ) [ 0 ]
  packet = packet [ I1I11i : : ]
  iIo00oo -= I1I11i
  iII1I1i = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  iII1I1i . afi = socket . ntohs ( II1i1iI )
  iII1I1i . mask_len = iIIiIiI1
  iII1I1i . instance_id = self . instance_id
  IIi1IiIii = self . addr_length ( )
  if ( iIo00oo < IIi1IiIii ) : return ( [ None , None ] )
  if 26 - 26: Ii1I
  packet = iII1I1i . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 65 - 65: iII111i / iIii1I11I1II1 + I11i - iIii1I11I1II1 - Ii1I . I1Ii111
  return ( [ packet , iII1I1i ] )
  if 77 - 77: OoOoOO00 / I1IiiI + IiII
  if 66 - 66: i11iIiiIii * OoooooooOO + iII111i / Ii1I
 def lcaf_decode_eid ( self , packet ) :
  oOOoooo0o0 = "BBB"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( [ None , None ] )
  if 42 - 42: Ii1I / iIii1I11I1II1 / Oo0Ooo . O0 . oO0o * I1IiiI
  if 21 - 21: OoooooooOO
  if 76 - 76: i1IIi * i11iIiiIii / OOooOOo + I1Ii111
  if 50 - 50: oO0o % OoOoOO00 + I1IiiI
  if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
  ii , Ii1i11I11i , ii1iI1IIiIi = struct . unpack ( oOOoooo0o0 ,
 packet [ : I1I11i ] )
  if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
  if ( ii1iI1IIiIi == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( ii1iI1IIiIi == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , iII1I1i = self . lcaf_decode_sg ( packet )
   return ( [ packet , iII1I1i ] )
  elif ( ii1iI1IIiIi == LISP_LCAF_GEO_COORD_TYPE ) :
   oOOoooo0o0 = "BBBBH"
   I1I11i = struct . calcsize ( oOOoooo0o0 )
   if ( len ( packet ) < I1I11i ) : return ( None )
   if 79 - 79: oO0o + I1IiiI % iII111i + II111iiii % OoO0O00 % iII111i
   iII1IiI1I11i , Ii1i11I11i , ii1iI1IIiIi , oO0oooo , ooo0oO0o000O0 = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] )
   if 46 - 46: o0oOOo0O0Ooo
   if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
   if ( ii1iI1IIiIi != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 44 - 44: I11i . oO0o
   ooo0oO0o000O0 = socket . ntohs ( ooo0oO0o000O0 )
   packet = packet [ I1I11i : : ]
   if ( ooo0oO0o000O0 > len ( packet ) ) : return ( None )
   if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
   I1II1II1i = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = I1II1II1i
   packet = I1II1II1i . decode_geo ( packet , ooo0oO0o000O0 , oO0oooo )
   self . mask_len = self . host_mask_len ( )
   if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
  return ( [ packet , None ] )
  if 16 - 16: OoO0O00 / Ii1I * i11iIiiIii / o0oOOo0O0Ooo + I1Ii111
  if 21 - 21: I11i % I1ii11iIi11i
  if 8 - 8: OOooOOo % OoO0O00 + O0 - o0oOOo0O0Ooo
  if 46 - 46: Oo0Ooo . ooOoO0o + OoOoOO00 - I11i / i11iIiiIii . iII111i
  if 80 - 80: II111iiii + OoO0O00 % ooOoO0o + i11iIiiIii
  if 30 - 30: Ii1I / I1ii11iIi11i % IiII - Oo0Ooo
class lisp_elp_node ( object ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 100 - 100: IiII . I1Ii111 * oO0o % OoO0O00 . iIii1I11I1II1 * Oo0Ooo
  if 100 - 100: IiII - OoOoOO00 % iII111i
 def copy_elp_node ( self ) :
  O00oOo = lisp_elp_node ( )
  O00oOo . copy_address ( self . address )
  O00oOo . probe = self . probe
  O00oOo . strict = self . strict
  O00oOo . eid = self . eid
  O00oOo . we_are_last = self . we_are_last
  return ( O00oOo )
  if 24 - 24: Oo0Ooo / OoO0O00 + i11iIiiIii
  if 81 - 81: i11iIiiIii . iIii1I11I1II1 - OoooooooOO
  if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
class lisp_elp ( object ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
  if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
 def copy_elp ( self ) :
  o0Ooo0oOOooO = lisp_elp ( self . elp_name )
  o0Ooo0oOOooO . use_elp_node = self . use_elp_node
  o0Ooo0oOOooO . we_are_last = self . we_are_last
  for O00oOo in self . elp_nodes :
   o0Ooo0oOOooO . elp_nodes . append ( O00oOo . copy_elp_node ( ) )
   if 42 - 42: OOooOOo
  return ( o0Ooo0oOOooO )
  if 36 - 36: OoooooooOO + ooOoO0o + iII111i
  if 30 - 30: i1IIi % Ii1I
 def print_elp ( self , want_marker ) :
  o000oOOoooo0o = ""
  for O00oOo in self . elp_nodes :
   IIiIi11iIi = ""
   if ( want_marker ) :
    if ( O00oOo == self . use_elp_node ) :
     IIiIi11iIi = "*"
    elif ( O00oOo . we_are_last ) :
     IIiIi11iIi = "x"
     if 56 - 56: II111iiii * iII111i + I1ii11iIi11i
     if 96 - 96: OOooOOo % i11iIiiIii * I1IiiI % i11iIiiIii + OoO0O00 - iII111i
   o000oOOoooo0o += "{}{}({}{}{}), " . format ( IIiIi11iIi ,
 O00oOo . address . print_address_no_iid ( ) ,
 "r" if O00oOo . eid else "R" , "P" if O00oOo . probe else "p" ,
 "S" if O00oOo . strict else "s" )
   if 39 - 39: ooOoO0o . OoOoOO00
  return ( o000oOOoooo0o [ 0 : - 2 ] if o000oOOoooo0o != "" else "" )
  if 60 - 60: o0oOOo0O0Ooo + iII111i
  if 8 - 8: OoOoOO00 - iIii1I11I1II1 * I1Ii111
 def select_elp_node ( self ) :
  iII1iii , oooOoOoooo , OoO0 = lisp_myrlocs
  o00o = None
  if 26 - 26: OoooooooOO % iIii1I11I1II1 - IiII
  for O00oOo in self . elp_nodes :
   if ( iII1iii and O00oOo . address . is_exact_match ( iII1iii ) ) :
    o00o = self . elp_nodes . index ( O00oOo )
    break
    if 3 - 3: oO0o * II111iiii . O0
   if ( oooOoOoooo and O00oOo . address . is_exact_match ( oooOoOoooo ) ) :
    o00o = self . elp_nodes . index ( O00oOo )
    break
    if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
    if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
    if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
    if 51 - 51: oO0o - I1ii11iIi11i + I1ii11iIi11i
    if 100 - 100: I11i - I1ii11iIi11i . i1IIi
    if 85 - 85: II111iiii
    if 58 - 58: i1IIi - OoO0O00 + ooOoO0o
  if ( o00o == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   O00oOo . we_are_last = False
   return
   if 6 - 6: IiII % I1IiiI + OoooooooOO * oO0o . iII111i + oO0o
   if 4 - 4: I11i % I1IiiI
   if 72 - 72: I1IiiI % II111iiii % iII111i / OoOoOO00
   if 96 - 96: OoOoOO00 % Ii1I
   if 50 - 50: IiII - II111iiii
   if 10 - 10: OoooooooOO % Ii1I * OOooOOo + IiII * oO0o
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ o00o ] ) :
   self . use_elp_node = None
   O00oOo . we_are_last = True
   return
   if 13 - 13: II111iiii
   if 14 - 14: i11iIiiIii . IiII
   if 70 - 70: Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
   if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
   if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
  self . use_elp_node = self . elp_nodes [ o00o + 1 ]
  return
  if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
  if 49 - 49: iII111i + OoOoOO00
  if 33 - 33: ooOoO0o
class lisp_geo ( object ) :
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
  if 19 - 19: I1Ii111 % IiII
  if 94 - 94: I1Ii111 * I1ii11iIi11i * I1ii11iIi11i - o0oOOo0O0Ooo . i11iIiiIii
 def copy_geo ( self ) :
  I1II1II1i = lisp_geo ( self . geo_name )
  I1II1II1i . latitude = self . latitude
  I1II1II1i . lat_mins = self . lat_mins
  I1II1II1i . lat_secs = self . lat_secs
  I1II1II1i . longitude = self . longitude
  I1II1II1i . long_mins = self . long_mins
  I1II1II1i . long_secs = self . long_secs
  I1II1II1i . altitude = self . altitude
  I1II1II1i . radius = self . radius
  return ( I1II1II1i )
  if 16 - 16: i1IIi
  if 88 - 88: OOooOOo
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 79 - 79: oO0o
  if 52 - 52: oO0o + OoO0O00 / OoooooooOO - iIii1I11I1II1 / iII111i - oO0o
 def parse_geo_string ( self , geo_str ) :
  o00o = geo_str . find ( "]" )
  if ( o00o != - 1 ) : geo_str = geo_str [ o00o + 1 : : ]
  if 68 - 68: I1IiiI - OoOoOO00 - iIii1I11I1II1 % i11iIiiIii * OoOoOO00 * OoO0O00
  if 97 - 97: OoO0O00 - IiII + ooOoO0o % iIii1I11I1II1 % iII111i
  if 100 - 100: IiII - Ii1I * iIii1I11I1II1 . iII111i . i1IIi % Oo0Ooo
  if 11 - 11: I11i + oO0o % Ii1I
  if 22 - 22: ooOoO0o
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , O0OoooOoo = geo_str . split ( "/" )
   self . radius = int ( O0OoooOoo )
   if 46 - 46: Oo0Ooo % i11iIiiIii * o0oOOo0O0Ooo
   if 33 - 33: oO0o * ooOoO0o * Ii1I * IiII
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 39 - 39: i1IIi
  o0OoOO00 = geo_str [ 0 : 4 ]
  oO0Ii1i1IIii = geo_str [ 4 : 8 ]
  if 78 - 78: o0oOOo0O0Ooo / IiII * I1IiiI
  if 2 - 2: i1IIi / I1Ii111 + I1IiiI + I1ii11iIi11i - o0oOOo0O0Ooo + iIii1I11I1II1
  if 78 - 78: I1ii11iIi11i % i1IIi . I1Ii111 + Oo0Ooo . o0oOOo0O0Ooo % II111iiii
  if 65 - 65: Ii1I . OoOoOO00 + O0 / iIii1I11I1II1 % Ii1I % I1Ii111
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 31 - 31: o0oOOo0O0Ooo - Oo0Ooo
  if 15 - 15: O0 + OOooOOo
  if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
  if 64 - 64: I1IiiI . Oo0Ooo * OoO0O00
  self . latitude = int ( o0OoOO00 [ 0 ] )
  self . lat_mins = int ( o0OoOO00 [ 1 ] )
  self . lat_secs = int ( o0OoOO00 [ 2 ] )
  if ( o0OoOO00 [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 87 - 87: i1IIi / OoooooooOO
  if 68 - 68: I1Ii111 / iIii1I11I1II1
  if 8 - 8: ooOoO0o * IiII * OOooOOo / I1IiiI
  if 40 - 40: i11iIiiIii + OoooooooOO
  self . longitude = int ( oO0Ii1i1IIii [ 0 ] )
  self . long_mins = int ( oO0Ii1i1IIii [ 1 ] )
  self . long_secs = int ( oO0Ii1i1IIii [ 2 ] )
  if ( oO0Ii1i1IIii [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 2 - 2: o0oOOo0O0Ooo * OoO0O00
  if 88 - 88: Oo0Ooo + oO0o + iII111i
 def print_geo ( self ) :
  Oo0oo0 = "N" if self . latitude < 0 else "S"
  I11II1iiiI1iIi1iI = "E" if self . longitude < 0 else "W"
  if 27 - 27: i1IIi - OOooOOo / Oo0Ooo
  Oo0ooooOOO = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , Oo0oo0 , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , I11II1iiiI1iIi1iI )
  if 16 - 16: o0oOOo0O0Ooo - iIii1I11I1II1 / OoooooooOO / I1ii11iIi11i + IiII
  if ( self . no_geo_altitude ( ) == False ) :
   Oo0ooooOOO += "-" + str ( self . altitude )
   if 73 - 73: OOooOOo % I1Ii111 + OoooooooOO / I1ii11iIi11i * oO0o % oO0o
   if 25 - 25: I1Ii111
   if 93 - 93: OoO0O00
   if 62 - 62: Oo0Ooo . iII111i
   if 15 - 15: i11iIiiIii * I11i + oO0o
  if ( self . radius != 0 ) : Oo0ooooOOO += "/{}" . format ( self . radius )
  return ( Oo0ooooOOO )
  if 67 - 67: IiII . OoO0O00
  if 59 - 59: oO0o * o0oOOo0O0Ooo
 def geo_url ( self ) :
  o0o0oO = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  o0o0oO = "10" if ( o0o0oO == "" or o0o0oO . isdigit ( ) == False ) else o0o0oO
  iiiii , oO0oOo = self . dms_to_decimal ( )
  oOOII1ii11iiI1Ii = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( iiiii , oO0oOo , iiiii , oO0oOo ,
  # Ii1I + I11i / IiII
  # Ii1I - O0
 o0o0oO )
  return ( oOOII1ii11iiI1Ii )
  if 85 - 85: Ii1I - iIii1I11I1II1 * o0oOOo0O0Ooo % iIii1I11I1II1 + II111iiii
  if 72 - 72: OoOoOO00 * oO0o - ooOoO0o / iII111i
 def print_geo_url ( self ) :
  I1II1II1i = self . print_geo ( )
  if ( self . radius == 0 ) :
   oOOII1ii11iiI1Ii = self . geo_url ( )
   Oo0 = "<a href='{}'>{}</a>" . format ( oOOII1ii11iiI1Ii , I1II1II1i )
  else :
   oOOII1ii11iiI1Ii = I1II1II1i . replace ( "/" , "-" )
   Oo0 = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( oOOII1ii11iiI1Ii , I1II1II1i )
   if 8 - 8: OoO0O00 * I1ii11iIi11i
  return ( Oo0 )
  if 18 - 18: O0 + I1Ii111 . I1ii11iIi11i
  if 48 - 48: Ii1I . o0oOOo0O0Ooo * O0 / OoooooooOO + I1Ii111 + Oo0Ooo
 def dms_to_decimal ( self ) :
  O00OOo0oo , iIIIi1Iii , Oo0O = self . latitude , self . lat_mins , self . lat_secs
  O0oooooO = float ( abs ( O00OOo0oo ) )
  O0oooooO += float ( iIIIi1Iii * 60 + Oo0O ) / 3600
  if ( O00OOo0oo > 0 ) : O0oooooO = - O0oooooO
  II = O0oooooO
  if 80 - 80: I1ii11iIi11i / I1Ii111 * iII111i . iII111i . O0
  O00OOo0oo , iIIIi1Iii , Oo0O = self . longitude , self . long_mins , self . long_secs
  O0oooooO = float ( abs ( O00OOo0oo ) )
  O0oooooO += float ( iIIIi1Iii * 60 + Oo0O ) / 3600
  if ( O00OOo0oo > 0 ) : O0oooooO = - O0oooooO
  O00O0oOooo = O0oooooO
  return ( ( II , O00O0oOooo ) )
  if 27 - 27: o0oOOo0O0Ooo * o0oOOo0O0Ooo + OoooooooOO - I1Ii111
  if 83 - 83: iIii1I11I1II1
 def get_distance ( self , geo_point ) :
  IIi1I1 = self . dms_to_decimal ( )
  IIIOO00Oo00Oo00 = geo_point . dms_to_decimal ( )
  Oooo0OO0oo = geopy . distance . distance ( IIi1I1 , IIIOO00Oo00Oo00 )
  return ( Oooo0OO0oo . km )
  if 47 - 47: II111iiii . iIii1I11I1II1
  if 95 - 95: II111iiii % Oo0Ooo + I11i
 def point_in_circle ( self , geo_point ) :
  oOOoO = self . get_distance ( geo_point )
  return ( oOOoO <= self . radius )
  if 1 - 1: O0 / OoOoOO00 + i11iIiiIii + ooOoO0o % o0oOOo0O0Ooo + OOooOOo
  if 63 - 63: II111iiii * i1IIi - I1Ii111 + iIii1I11I1II1 % I11i - OOooOOo
 def encode_geo ( self ) :
  I11IiiI1 = socket . htons ( LISP_AFI_LCAF )
  o0000OO0 = socket . htons ( 20 + 2 )
  Ii1i11I11i = 0
  if 95 - 95: iIii1I11I1II1 / oO0o - IiII - iII111i / iII111i % iIii1I11I1II1
  iiiii = abs ( self . latitude )
  iI1Ii1 = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : Ii1i11I11i |= 0x40
  if 43 - 43: i1IIi / I1ii11iIi11i
  oO0oOo = abs ( self . longitude )
  O0O0O = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : Ii1i11I11i |= 0x20
  if 35 - 35: Ii1I * I1ii11iIi11i + oO0o . I1ii11iIi11i % I1ii11iIi11i
  i1I1i = 0
  if ( self . no_geo_altitude ( ) == False ) :
   i1I1i = socket . htonl ( self . altitude )
   Ii1i11I11i |= 0x10
   if 17 - 17: i1IIi * Oo0Ooo * oO0o
  O0OoooOoo = socket . htons ( self . radius )
  if ( O0OoooOoo != 0 ) : Ii1i11I11i |= 0x06
  if 62 - 62: ooOoO0o + OoOoOO00 % OOooOOo - I1ii11iIi11i + OoO0O00
  o00O0oOo = struct . pack ( "HBBBBH" , I11IiiI1 , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , o0000OO0 )
  o00O0oOo += struct . pack ( "BBHBBHBBHIHHH" , Ii1i11I11i , 0 , 0 , iiiii , iI1Ii1 >> 16 ,
 socket . htons ( iI1Ii1 & 0x0ffff ) , oO0oOo , O0O0O >> 16 ,
 socket . htons ( O0O0O & 0xffff ) , i1I1i , O0OoooOoo , 0 , 0 )
  if 64 - 64: Ii1I - iIii1I11I1II1 * I1IiiI % iII111i * II111iiii / OoO0O00
  return ( o00O0oOo )
  if 16 - 16: iIii1I11I1II1
  if 39 - 39: oO0o / OoO0O00 - Ii1I + ooOoO0o + OOooOOo
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  oOOoooo0o0 = "BBHBBHBBHIHHH"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( lcaf_len < I1I11i ) : return ( None )
  if 84 - 84: iII111i / Oo0Ooo
  Ii1i11I11i , iIoOoooOO , o00OO0O , iiiii , o0o0O00o0 , iI1Ii1 , oO0oOo , iiiI1I1 , O0O0O , i1I1i , O0OoooOoo , OoII1Iiii1 , II1i1iI = struct . unpack ( oOOoooo0o0 ,
  # Ii1I
 packet [ : I1I11i ] )
  if 93 - 93: I1Ii111 % I1IiiI - iIii1I11I1II1
  if 28 - 28: OOooOOo . I1Ii111 . i11iIiiIii * Oo0Ooo
  if 74 - 74: OoooooooOO * i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo
  if 48 - 48: iII111i * I1ii11iIi11i * oO0o % O0 . OoO0O00
  II1i1iI = socket . ntohs ( II1i1iI )
  if ( II1i1iI == LISP_AFI_LCAF ) : return ( None )
  if 11 - 11: OOooOOo / o0oOOo0O0Ooo
  if ( Ii1i11I11i & 0x40 ) : iiiii = - iiiii
  self . latitude = iiiii
  oOo0Oo = old_div ( ( ( o0o0O00o0 << 16 ) | socket . ntohs ( iI1Ii1 ) ) , 1000 )
  self . lat_mins = old_div ( oOo0Oo , 60 )
  self . lat_secs = oOo0Oo % 60
  if 68 - 68: iIii1I11I1II1 % Ii1I / I11i
  if ( Ii1i11I11i & 0x20 ) : oO0oOo = - oO0oOo
  self . longitude = oO0oOo
  I1iIiii11I111 = old_div ( ( ( iiiI1I1 << 16 ) | socket . ntohs ( O0O0O ) ) , 1000 )
  self . long_mins = old_div ( I1iIiii11I111 , 60 )
  self . long_secs = I1iIiii11I111 % 60
  if 61 - 61: IiII - o0oOOo0O0Ooo
  self . altitude = socket . ntohl ( i1I1i ) if ( Ii1i11I11i & 0x10 ) else - 1
  O0OoooOoo = socket . ntohs ( O0OoooOoo )
  self . radius = O0OoooOoo if ( Ii1i11I11i & 0x02 ) else O0OoooOoo * 1000
  if 8 - 8: OOooOOo . Ii1I
  self . geo_name = None
  packet = packet [ I1I11i : : ]
  if 15 - 15: ooOoO0o / OOooOOo + i1IIi / Ii1I / OOooOOo
  if ( II1i1iI != 0 ) :
   self . rloc . afi = II1i1iI
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 47 - 47: Oo0Ooo + oO0o % OoooooooOO
  return ( packet )
  if 23 - 23: I1Ii111 / i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1
  if 11 - 11: I11i % OoOoOO00 * Oo0Ooo
  if 48 - 48: OOooOOo
  if 66 - 66: iII111i - I1Ii111 - i11iIiiIii . o0oOOo0O0Ooo + Oo0Ooo
  if 90 - 90: O0 - i11iIiiIii * ooOoO0o . I1ii11iIi11i . Ii1I - OoooooooOO
  if 23 - 23: o0oOOo0O0Ooo
class lisp_rle_node ( object ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 88 - 88: I1Ii111 + iIii1I11I1II1 / o0oOOo0O0Ooo
  if 93 - 93: ooOoO0o % iIii1I11I1II1 - OOooOOo . IiII + ooOoO0o
 def copy_rle_node ( self ) :
  iIiII = lisp_rle_node ( )
  iIiII . address . copy_address ( self . address )
  iIiII . level = self . level
  iIiII . translated_port = self . translated_port
  iIiII . rloc_name = self . rloc_name
  return ( iIiII )
  if 63 - 63: I1ii11iIi11i / OOooOOo
  if 28 - 28: I11i / I1Ii111 + IiII * OoooooooOO - iIii1I11I1II1
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 6 - 6: I11i % o0oOOo0O0Ooo / OoooooooOO . I1Ii111
  if 17 - 17: I1ii11iIi11i + OoooooooOO / iIii1I11I1II1 . II111iiii + Oo0Ooo
 def get_encap_keys ( self ) :
  O00oo0o0o0oo = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 7 - 7: O0 - I1ii11iIi11i - iIii1I11I1II1
  Oo0o = self . address . print_address_no_iid ( ) + ":" + O00oo0o0o0oo
  if 96 - 96: OoOoOO00 . I1IiiI . I11i * OoooooooOO + OoooooooOO * O0
  try :
   O0o0O0 = lisp_crypto_keys_by_rloc_encap [ Oo0o ]
   if ( O0o0O0 [ 1 ] ) : return ( O0o0O0 [ 1 ] . encrypt_key , O0o0O0 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 90 - 90: I11i + I1ii11iIi11i + OoooooooOO + OoOoOO00 + IiII / iII111i
   if 75 - 75: i11iIiiIii
   if 27 - 27: I11i - IiII - I1Ii111
   if 90 - 90: OoO0O00 . oO0o * O0 / I11i % O0 + I1Ii111
class lisp_rle ( object ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 48 - 48: iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
  if 84 - 84: Ii1I
 def copy_rle ( self ) :
  IIiiiI = lisp_rle ( self . rle_name )
  for iIiII in self . rle_nodes :
   IIiiiI . rle_nodes . append ( iIiII . copy_rle_node ( ) )
   if 92 - 92: I11i
  IIiiiI . build_forwarding_list ( )
  return ( IIiiiI )
  if 64 - 64: iII111i / iII111i * iII111i % O0 / IiII . I1ii11iIi11i
  if 23 - 23: i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
 def print_rle ( self , html , do_formatting ) :
  IIi1III11I1Ii = ""
  for iIiII in self . rle_nodes :
   O00oo0o0o0oo = iIiII . translated_port
   if 82 - 82: O0 * ooOoO0o * iIii1I11I1II1 . i1IIi
   i1i1I1IIiIIi = ""
   if ( iIiII . rloc_name != None ) :
    i1i1I1IIiIIi = iIiII . rloc_name
    if ( do_formatting ) : i1i1I1IIiIIi = blue ( i1i1I1IIiIIi , html )
    i1i1I1IIiIIi = "({})" . format ( i1i1I1IIiIIi )
    if 89 - 89: Oo0Ooo + Ii1I * O0 - I1Ii111
    if 33 - 33: iIii1I11I1II1 . I11i
   Oo0o = iIiII . address . print_address_no_iid ( )
   if ( iIiII . address . is_local ( ) ) : Oo0o = red ( Oo0o , html )
   IIi1III11I1Ii += "{}{}{}, " . format ( Oo0o , "" if O00oo0o0o0oo == 0 else ":" + str ( O00oo0o0o0oo ) , i1i1I1IIiIIi )
   if 63 - 63: oO0o - iII111i
   if 13 - 13: I1Ii111 / i1IIi % OoooooooOO / I11i
  return ( IIi1III11I1Ii [ 0 : - 2 ] if IIi1III11I1Ii != "" else "" )
  if 66 - 66: I1Ii111 % o0oOOo0O0Ooo . iII111i . ooOoO0o + OOooOOo * II111iiii
  if 33 - 33: oO0o
 def build_forwarding_list ( self ) :
  i11i = - 1
  for iIiII in self . rle_nodes :
   if ( i11i == - 1 ) :
    if ( iIiII . address . is_local ( ) ) : i11i = iIiII . level
   else :
    if ( iIiII . level > i11i ) : break
    if 64 - 64: OoO0O00 % Oo0Ooo % I11i . iII111i % I1IiiI
    if 50 - 50: i1IIi + ooOoO0o - iIii1I11I1II1
  i11i = 0 if i11i == - 1 else iIiII . level
  if 45 - 45: OoooooooOO / o0oOOo0O0Ooo / iII111i
  self . rle_forwarding_list = [ ]
  for iIiII in self . rle_nodes :
   if ( iIiII . level == i11i or ( i11i == 0 and
 iIiII . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and iIiII . address . is_local ( ) ) :
     Oo0o = iIiII . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( Oo0o ) )
     continue
     if 72 - 72: I1Ii111
    self . rle_forwarding_list . append ( iIiII )
    if 94 - 94: ooOoO0o . IiII - Ii1I + I1ii11iIi11i / ooOoO0o
    if 10 - 10: ooOoO0o . OOooOOo * O0 % II111iiii
    if 12 - 12: oO0o + I1IiiI * Oo0Ooo - iII111i
    if 88 - 88: OOooOOo . OoO0O00
    if 86 - 86: OoOoOO00 . o0oOOo0O0Ooo / ooOoO0o * I1IiiI . OoO0O00 / I1Ii111
class lisp_json ( object ) :
 def __init__ ( self , name , string , encrypted = False , ms_encrypt = False ) :
  if 47 - 47: I11i . iII111i * OoOoOO00 % OoooooooOO
  if 59 - 59: OoooooooOO + I1ii11iIi11i - I11i / I1IiiI * oO0o
  if 90 - 90: I1Ii111 + i1IIi * I1Ii111 / I11i * Oo0Ooo
  if 27 - 27: OoooooooOO
  if ( type ( string ) == bytes ) : string = string . decode ( )
  if 42 - 42: OoO0O00 + OoOoOO00
  self . json_name = name
  self . json_encrypted = False
  try :
   json . loads ( string )
  except :
   lprint ( "Invalid JSON string: '{}'" . format ( string ) )
   string = '{ "?" : "?" }'
   if 52 - 52: iII111i * OoOoOO00
  self . json_string = string
  if 80 - 80: I1Ii111 / IiII * o0oOOo0O0Ooo - OoOoOO00 / iIii1I11I1II1
  if 38 - 38: II111iiii / I11i + IiII % OoooooooOO
  if 27 - 27: OoOoOO00 * OoO0O00 * OOooOOo % I1IiiI * o0oOOo0O0Ooo + I1ii11iIi11i
  if 73 - 73: i1IIi
  if 52 - 52: IiII / i11iIiiIii * O0
  if 67 - 67: OOooOOo / I11i - I1Ii111 % i11iIiiIii
  if 3 - 3: oO0o + iII111i + OOooOOo
  if 54 - 54: i11iIiiIii + OoO0O00 - IiII - iII111i / I11i
  if 85 - 85: OOooOOo * OOooOOo * I1Ii111 - ooOoO0o . O0 % iII111i
  if 5 - 5: i1IIi * iII111i . o0oOOo0O0Ooo - I1ii11iIi11i
  if ( len ( lisp_ms_json_keys ) != 0 ) :
   if ( ms_encrypt == False ) : return
   self . json_key_id = list ( lisp_ms_json_keys . keys ( ) ) [ 0 ]
   self . json_key = lisp_ms_json_keys [ self . json_key_id ]
   self . encrypt_json ( )
   if 84 - 84: i1IIi
   if 17 - 17: IiII + iII111i * OoO0O00 / iII111i
  if ( lisp_log_id == "lig" and encrypted ) :
   III11II111 = os . getenv ( "LISP_JSON_KEY" )
   if ( III11II111 != None ) :
    o00o = - 1
    if ( III11II111 [ 0 ] == "[" and "]" in III11II111 ) :
     o00o = III11II111 . find ( "]" )
     self . json_key_id = int ( III11II111 [ 1 : o00o ] )
     if 67 - 67: i1IIi * IiII . OoOoOO00 % iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
    self . json_key = III11II111 [ o00o + 1 : : ]
    if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
    self . decrypt_json ( )
    if 65 - 65: OoOoOO00
    if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
    if 58 - 58: OoO0O00 * I1IiiI - II111iiii / Ii1I - I1IiiI % OoooooooOO
    if 33 - 33: IiII / i1IIi + I1Ii111
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 5 - 5: O0 / iII111i % II111iiii . Oo0Ooo - I11i
  if 84 - 84: oO0o * iII111i % i11iIiiIii - O0 . iIii1I11I1II1 - OoOoOO00
 def delete ( self ) :
  if ( self . json_name in lisp_json_list ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 73 - 73: OoOoOO00
   if 66 - 66: Oo0Ooo
   if 42 - 42: i11iIiiIii / II111iiii . OOooOOo
 def print_json ( self , html ) :
  oOOoOoo0Ooo = self . json_string
  o0Oooo00oO0o00 = "***"
  if ( html ) : o0Oooo00oO0o00 = red ( o0Oooo00oO0o00 , html )
  O0OoO00 = o0Oooo00oO0o00 + self . json_string + o0Oooo00oO0o00
  if ( self . valid_json ( ) ) : return ( oOOoOoo0Ooo )
  return ( O0OoO00 )
  if 58 - 58: O0 * iIii1I11I1II1 . I1ii11iIi11i / Oo0Ooo
  if 30 - 30: oO0o * O0 * o0oOOo0O0Ooo / oO0o
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 41 - 41: Oo0Ooo - OOooOOo + I1ii11iIi11i
  return ( True )
  if 32 - 32: I1ii11iIi11i % OoOoOO00 + Oo0Ooo
  if 92 - 92: II111iiii . O0 . iIii1I11I1II1 % IiII - i11iIiiIii
 def encrypt_json ( self ) :
  OoOooo0oO0oOo = self . json_key . zfill ( 32 )
  iI1ii = "0" * 8
  if 9 - 9: OoO0O00
  Oo0OoooOo = json . loads ( self . json_string )
  for III11II111 in Oo0OoooOo :
   IiIi1i = Oo0OoooOo [ III11II111 ]
   if ( type ( IiIi1i ) != str ) : IiIi1i = str ( IiIi1i )
   IiIi1i = chacha . ChaCha ( OoOooo0oO0oOo , iI1ii ) . encrypt ( IiIi1i )
   Oo0OoooOo [ III11II111 ] = binascii . hexlify ( IiIi1i )
   if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 + i1IIi - I11i . iIii1I11I1II1 * i11iIiiIii
  self . json_string = json . dumps ( Oo0OoooOo )
  self . json_encrypted = True
  if 71 - 71: oO0o + Oo0Ooo
  if 7 - 7: OoOoOO00 / I1ii11iIi11i * i1IIi
 def decrypt_json ( self ) :
  OoOooo0oO0oOo = self . json_key . zfill ( 32 )
  iI1ii = "0" * 8
  if 87 - 87: OoooooooOO * IiII - I1IiiI % I1ii11iIi11i % iIii1I11I1II1
  Oo0OoooOo = json . loads ( self . json_string )
  for III11II111 in Oo0OoooOo :
   IiIi1i = binascii . unhexlify ( Oo0OoooOo [ III11II111 ] )
   Oo0OoooOo [ III11II111 ] = chacha . ChaCha ( OoOooo0oO0oOo , iI1ii ) . encrypt ( IiIi1i )
   if 28 - 28: I1Ii111 / o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo . Ii1I / I11i
  try :
   self . json_string = json . dumps ( Oo0OoooOo )
   self . json_encrypted = False
  except :
   pass
   if 43 - 43: I1Ii111 . I1IiiI
   if 16 - 16: i11iIiiIii * Oo0Ooo * Ii1I / OoOoOO00 / OOooOOo
   if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
   if 19 - 19: i1IIi + IiII . OoO0O00 / O0 - I1Ii111 - Oo0Ooo
   if 24 - 24: iII111i + i1IIi
   if 31 - 31: OoOoOO00
   if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
class lisp_stats ( object ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 43 - 43: II111iiii - OoooooooOO
  if 11 - 11: I1IiiI
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
  if 64 - 64: OoO0O00 - OoO0O00
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  i11Ii1IIi = time . time ( ) - self . last_increment
  return ( i11Ii1IIi <= 1 )
  if 93 - 93: Oo0Ooo . O0
  if 75 - 75: iII111i * II111iiii - I1IiiI
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  i11Ii1IIi = time . time ( ) - self . last_increment
  return ( i11Ii1IIi <= 60 )
  if 30 - 30: i1IIi / ooOoO0o . ooOoO0o
  if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 97 - 97: i11iIiiIii . OoOoOO00 + oO0o * O0 % OoO0O00 - Ii1I
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 46 - 46: I1Ii111
  return ( c1 , c2 )
  if 87 - 87: o0oOOo0O0Ooo - iII111i * OoO0O00 * o0oOOo0O0Ooo . o0oOOo0O0Ooo / OOooOOo
  if 50 - 50: i11iIiiIii - II111iiii * OoooooooOO + II111iiii - ooOoO0o
 def normalize ( self , count ) :
  count = str ( count )
  Oo0oooO = len ( count )
  if ( Oo0oooO > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 98 - 98: iII111i . i1IIi + o0oOOo0O0Ooo * OoooooooOO - i11iIiiIii
  if ( Oo0oooO > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 21 - 21: i11iIiiIii . oO0o * o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
  if ( Oo0oooO > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 33 - 33: I1IiiI + O0 - I11i
  return ( count )
  if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
  if 63 - 63: o0oOOo0O0Ooo . IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
 def get_stats ( self , summary , html ) :
  o0O0oOO0oOOo = self . last_rate_check
  iIIii1III = self . last_packet_count
  I1ii1iiI1II = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 89 - 89: ooOoO0o - OoOoOO00 + II111iiii
  Iii1i = self . last_rate_check - o0O0oOO0oOOo
  if ( Iii1i == 0 ) :
   oOo0oO00O000 = 0
   iIIiI1I = 0
  else :
   oOo0oO00O000 = int ( old_div ( ( self . packet_count - iIIii1III ) ,
 Iii1i ) )
   iIIiI1I = old_div ( ( self . byte_count - I1ii1iiI1II ) , Iii1i )
   iIIiI1I = old_div ( ( iIIiI1I * 8 ) , 1000000 )
   iIIiI1I = round ( iIIiI1I , 2 )
   if 91 - 91: OoooooooOO . OOooOOo * iIii1I11I1II1 % IiII
   if 31 - 31: Ii1I - i11iIiiIii
   if 47 - 47: IiII / o0oOOo0O0Ooo - IiII . I11i - I1Ii111 * o0oOOo0O0Ooo
   if 75 - 75: OoO0O00 / II111iiii - I1Ii111
   if 95 - 95: OOooOOo / OoOoOO00 + I1ii11iIi11i
  Ooo0 = self . normalize ( self . packet_count )
  i1oOOoo00OOOO = self . normalize ( self . byte_count )
  if 18 - 18: I1Ii111
  if 11 - 11: I11i - OoooooooOO
  if 73 - 73: Oo0Ooo % O0 . OOooOOo + O0
  if 84 - 84: Ii1I
  if 22 - 22: OoOoOO00
  if ( summary ) :
   ooo0OOoO = "<br>" if html else ""
   Ooo0 , i1oOOoo00OOOO = self . stat_colors ( Ooo0 , i1oOOoo00OOOO , html )
   II1I11 = "packet-count: {}{}byte-count: {}" . format ( Ooo0 , ooo0OOoO , i1oOOoo00OOOO )
   oooo0o0o0oO = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( oOo0oO00O000 , iIIiI1I )
   if 20 - 20: I1IiiI
   if ( html != "" ) : oooo0o0o0oO = lisp_span ( II1I11 , oooo0o0o0oO )
  else :
   OOO0OOO = str ( oOo0oO00O000 )
   OO0oO0Oo0O0 = str ( iIIiI1I )
   if ( html ) :
    Ooo0 = lisp_print_cour ( Ooo0 )
    OOO0OOO = lisp_print_cour ( OOO0OOO )
    i1oOOoo00OOOO = lisp_print_cour ( i1oOOoo00OOOO )
    OO0oO0Oo0O0 = lisp_print_cour ( OO0oO0Oo0O0 )
    if 49 - 49: I1Ii111
   ooo0OOoO = "<br>" if html else ", "
   if 92 - 92: ooOoO0o
   oooo0o0o0oO = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( Ooo0 , ooo0OOoO , OOO0OOO , ooo0OOoO , i1oOOoo00OOOO , ooo0OOoO ,
   # ooOoO0o . Ii1I % I1Ii111 / I11i - I1IiiI
 OO0oO0Oo0O0 )
   if 39 - 39: O0 * Ii1I - i11iIiiIii / I11i - o0oOOo0O0Ooo
  return ( oooo0o0o0oO )
  if 81 - 81: OOooOOo
  if 28 - 28: Ii1I
  if 88 - 88: iIii1I11I1II1 + i11iIiiIii - OoOoOO00 - I1ii11iIi11i - I1IiiI
  if 58 - 58: iIii1I11I1II1
  if 56 - 56: OOooOOo * o0oOOo0O0Ooo - O0
  if 45 - 45: OOooOOo - OoO0O00
  if 49 - 49: OoOoOO00 / o0oOOo0O0Ooo % OoO0O00
  if 50 - 50: iIii1I11I1II1 - OoooooooOO + I1ii11iIi11i / Oo0Ooo * OOooOOo
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 37 - 37: O0 % I1Ii111 * OOooOOo / OOooOOo
if 95 - 95: I1ii11iIi11i % o0oOOo0O0Ooo . oO0o
if 9 - 9: OoOoOO00 % OoOoOO00 * ooOoO0o / I1IiiI - OOooOOo
if 62 - 62: Oo0Ooo + OOooOOo - Oo0Ooo
class lisp_rloc ( object ) :
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
  if 32 - 32: OoooooooOO
  if ( recurse == False ) : return
  if 99 - 99: II111iiii % Oo0Ooo / OOooOOo / I1ii11iIi11i % O0 + i1IIi
  if 90 - 90: OoOoOO00 % OoO0O00 . I1IiiI * oO0o
  if 17 - 17: O0 - i1IIi
  if 77 - 77: OOooOOo - i1IIi / II111iiii . I1Ii111 + O0
  if 1 - 1: OoooooooOO % iIii1I11I1II1 * I1ii11iIi11i
  if 17 - 17: Ii1I * i1IIi % OoO0O00
  i1i1i11i = lisp_get_default_route_next_hops ( )
  if ( i1i1i11i == [ ] or len ( i1i1i11i ) == 1 ) : return
  if 40 - 40: I1ii11iIi11i / I1Ii111 . OoOoOO00
  self . rloc_next_hop = i1i1i11i [ 0 ]
  iII11I = self
  for oo0O0 in i1i1i11i [ 1 : : ] :
   o0o0Oooo = lisp_rloc ( False )
   o0o0Oooo = copy . deepcopy ( self )
   o0o0Oooo . rloc_next_hop = oo0O0
   iII11I . next_rloc = o0o0Oooo
   iII11I = o0o0Oooo
   if 45 - 45: I1ii11iIi11i / iIii1I11I1II1 + OoO0O00 / O0 - O0 - I1Ii111
   if 88 - 88: o0oOOo0O0Ooo % I1Ii111
   if 4 - 4: i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 87 - 87: I1Ii111 % i11iIiiIii + O0
  if 67 - 67: OoooooooOO / i1IIi / ooOoO0o . i1IIi - i11iIiiIii . i1IIi
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
  if 15 - 15: I1ii11iIi11i
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
  if 56 - 56: I1IiiI . ooOoO0o
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 35 - 35: iIii1I11I1II1 % Oo0Ooo + o0oOOo0O0Ooo * o0oOOo0O0Ooo % ooOoO0o
  if 10 - 10: I1ii11iIi11i / II111iiii % II111iiii - OoooooooOO * o0oOOo0O0Ooo / ooOoO0o
  if 26 - 26: OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
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
  if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
  if 8 - 8: OoooooooOO % I11i - iII111i * OOooOOo . O0
 def print_rloc ( self , indent ) :
  Oo0OO0000oooo = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , Oo0OO0000oooo , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 40 - 40: I1Ii111 . oO0o + OoO0O00 % Oo0Ooo / II111iiii
  if 19 - 19: i11iIiiIii
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  o0oo0 = self . rloc_name
  if ( cour ) : o0oo0 = lisp_print_cour ( o0oo0 )
  return ( 'rloc-name: {}' . format ( blue ( o0oo0 , cour ) ) )
  if 20 - 20: i11iIiiIii . II111iiii - I1ii11iIi11i / ooOoO0o % i11iIiiIii
  if 35 - 35: Oo0Ooo - I1ii11iIi11i . Oo0Ooo
 def is_decent_nat_port ( self ) :
  Ii1IOo0Oo0oOoO = self . rloc_name
  if ( Ii1IOo0Oo0oOoO == None ) : return ( False )
  if ( Ii1IOo0Oo0oOoO . find ( LISP_TP ) == - 1 ) : return ( False )
  return ( True )
  if 94 - 94: I1ii11iIi11i + OoO0O00 . II111iiii + oO0o . II111iiii
  if 96 - 96: i11iIiiIii
 def store_decent_nat_port ( self ) :
  if ( self . is_decent_nat_port ( ) == False ) : return ( False )
  O00oo0o0o0oo = self . rloc_name . split ( LISP_TP ) [ - 1 ]
  self . translated_port = int ( O00oo0o0o0oo )
  return ( True )
  if 66 - 66: ooOoO0o * iII111i - iII111i - O0 . o0oOOo0O0Ooo
  if 23 - 23: iIii1I11I1II1 / I11i % OoOoOO00 . OoO0O00
 def normalize_decent_nat_rloc_name ( self ) :
  if ( self . is_decent_nat_port ( ) == False ) : return ( self . rloc_name )
  Ii1IOo0Oo0oOoO = self . rloc_name . split ( LISP_TP ) [ 0 ]
  return ( Ii1IOo0Oo0oOoO )
  if 90 - 90: iIii1I11I1II1 - OOooOOo . Ii1I % OoO0O00
  if 89 - 89: i11iIiiIii
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  O00oo0o0o0oo = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  if 86 - 86: Oo0Ooo % iIii1I11I1II1 . II111iiii / I11i % OoO0O00 % OoO0O00
  if ( rloc_record . rloc_name != None ) :
   self . rloc_name = rloc_record . rloc_name
   if 40 - 40: o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo * i1IIi
   if 94 - 94: oO0o - II111iiii + OoOoOO00
   if 90 - 90: Oo0Ooo + Oo0Ooo + I1Ii111
   if 81 - 81: i1IIi % iIii1I11I1II1 % Ii1I * ooOoO0o % i1IIi * I1IiiI
   if ( lisp_i_am_rtr == False ) :
    if ( self . store_decent_nat_port ( ) ) :
     self . translated_rloc . copy_address ( self . rloc )
     if 15 - 15: ooOoO0o
     if 26 - 26: IiII % ooOoO0o / OOooOOo
     if 14 - 14: i11iIiiIii . I1ii11iIi11i
     if 20 - 20: O0 . iIii1I11I1II1 * I1ii11iIi11i - O0 + I1ii11iIi11i / I1IiiI
     if 67 - 67: OoO0O00 / OoOoOO00 / i11iIiiIii % OoOoOO00
     if 54 - 54: o0oOOo0O0Ooo . i11iIiiIii + I1IiiI * ooOoO0o - ooOoO0o
   oo0O0 = self . next_rloc
   while ( oo0O0 != None ) :
    oo0O0 . rloc_name = self . rloc_name
    oo0O0 = oo0O0 . next_rloc
    if 28 - 28: I1Ii111 . i11iIiiIii * oO0o % ooOoO0o / iII111i . OOooOOo
    if 57 - 57: OoooooooOO . iIii1I11I1II1 % iII111i % Oo0Ooo
    if 92 - 92: I1Ii111 - Ii1I + I1Ii111
    if 8 - 8: Oo0Ooo . iII111i / i11iIiiIii + iIii1I11I1II1 - OoOoOO00
    if 1 - 1: i11iIiiIii
    if 25 - 25: OoooooooOO / II111iiii . OOooOOo * OoOoOO00 - OoooooooOO
  OOOo0 = self . rloc
  if ( OOOo0 . is_null ( ) == False and self . rloc_name != None ) :
   Ii1IOo0Oo0oOoO = self . normalize_decent_nat_rloc_name ( )
   i1o0 = lisp_get_nat_info ( OOOo0 , Ii1IOo0Oo0oOoO )
   if ( i1o0 ) :
    O00oo0o0o0oo = i1o0 . port
    OOooOO = lisp_nat_state_info [ Ii1IOo0Oo0oOoO ] [ 0 ]
    Oo0o = OOOo0 . print_address_no_iid ( )
    IIII1iI1IiIiI = red ( Oo0o , False )
    i1iiiiII = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 47 - 47: OOooOOo
    if 16 - 16: Ii1I * ooOoO0o
    if 90 - 90: I11i / Oo0Ooo
    if 70 - 70: oO0o
    if 97 - 97: ooOoO0o % i1IIi . IiII / Oo0Ooo . I1Ii111 . OoO0O00
    if 12 - 12: I1IiiI
    if ( i1o0 . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( IIII1iI1IiIiI , O00oo0o0o0oo , i1iiiiII ) )
     if 99 - 99: II111iiii - OoOoOO00
     if 22 - 22: i11iIiiIii * II111iiii
     i1o0 = None if ( i1o0 == OOooOO ) else OOooOO
     if ( i1o0 and i1o0 . timed_out ( ) ) :
      O00oo0o0o0oo = i1o0 . port
      IIII1iI1IiIiI = red ( i1o0 . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( IIII1iI1IiIiI , O00oo0o0o0oo ,
      # i1IIi
 i1iiiiII ) )
      i1o0 = None
      if 69 - 69: OOooOOo / I1Ii111 * II111iiii
      if 88 - 88: OOooOOo - I1IiiI + Oo0Ooo
      if 15 - 15: I11i / I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
      if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
      if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
      if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
      if 8 - 8: OoooooooOO
    if ( i1o0 ) :
     if ( i1o0 . address != Oo0o ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( IIII1iI1IiIiI , red ( i1o0 . address , False ) ) )
      if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
      self . rloc . store_address ( i1o0 . address )
      if 83 - 83: o0oOOo0O0Ooo * Ii1I - Oo0Ooo * iII111i - i11iIiiIii
     IIII1iI1IiIiI = red ( i1o0 . address , False )
     O00oo0o0o0oo = i1o0 . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( IIII1iI1IiIiI , O00oo0o0o0oo , i1iiiiII ) )
     if 6 - 6: I1IiiI + i11iIiiIii + O0 / i1IIi
     self . store_translated_rloc ( OOOo0 , O00oo0o0o0oo )
     if 50 - 50: iII111i . II111iiii % I1Ii111 % I1IiiI / o0oOOo0O0Ooo . I1IiiI
     if 76 - 76: OOooOOo % iII111i
     if 80 - 80: iIii1I11I1II1 + o0oOOo0O0Ooo + iIii1I11I1II1
     if 63 - 63: OoOoOO00 - o0oOOo0O0Ooo % II111iiii - Ii1I
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 81 - 81: iII111i % OOooOOo * oO0o
  if 84 - 84: iII111i - OoooooooOO + I1ii11iIi11i - I1IiiI
  if 52 - 52: oO0o / ooOoO0o / iII111i / OoOoOO00 * iIii1I11I1II1
  if 74 - 74: oO0o . I1ii11iIi11i - iIii1I11I1II1
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for iIiII in self . rle . rle_nodes :
    o0oo0 = iIiII . rloc_name
    i1o0 = lisp_get_nat_info ( iIiII . address , o0oo0 )
    if ( i1o0 == None ) : continue
    if 73 - 73: OoO0O00 / O0 . o0oOOo0O0Ooo
    O00oo0o0o0oo = i1o0 . port
    o0o00O000o0o = o0oo0
    if ( o0o00O000o0o ) : o0o00O000o0o = blue ( o0oo0 , False )
    if 100 - 100: Ii1I . OoO0O00 % I1ii11iIi11i % O0 * Oo0Ooo - OoOoOO00
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( O00oo0o0o0oo ,
    # o0oOOo0O0Ooo
 iIiII . address . print_address_no_iid ( ) , o0o00O000o0o ) )
    iIiII . translated_port = O00oo0o0o0oo
    if 55 - 55: OOooOOo - OoooooooOO * iIii1I11I1II1 + iII111i % II111iiii
    if 33 - 33: I1Ii111 * oO0o * OoooooooOO + OOooOOo - I1IiiI + I1Ii111
    if 92 - 92: ooOoO0o * I11i % iIii1I11I1II1 + Ii1I - OoOoOO00
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) :
   if ( self . state != LISP_RLOC_UP_STATE ) :
    self . last_state_change = lisp_get_timestamp ( )
    if 31 - 31: OoooooooOO
   self . state = LISP_RLOC_UP_STATE
   if 87 - 87: OoooooooOO - Ii1I . I11i / I1Ii111 . i1IIi
   if 86 - 86: i1IIi . oO0o % OOooOOo
   if 99 - 99: oO0o / I1Ii111 * oO0o * I11i
   if 38 - 38: o0oOOo0O0Ooo + OoOoOO00
   if 24 - 24: Ii1I - OOooOOo - o0oOOo0O0Ooo - I1Ii111 / OoooooooOO
  i1iI1iI = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 32 - 32: OoooooooOO / i11iIiiIii
  if ( rloc_record . keys != None and i1iI1iI ) :
   III11II111 = rloc_record . keys [ 1 ]
   if ( III11II111 != None ) :
    Oo0o = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( O00oo0o0o0oo )
    if 30 - 30: OoOoOO00 % Ii1I / iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * OoO0O00
    III11II111 . add_key_by_rloc ( Oo0o , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( Oo0o , False ) ) )
    if 25 - 25: i1IIi * oO0o . I11i
    if 15 - 15: oO0o
    if 45 - 45: Oo0Ooo * IiII * OoO0O00 + iIii1I11I1II1
  return ( O00oo0o0o0oo )
  if 89 - 89: IiII . IiII . oO0o % iII111i
  if 27 - 27: OoOoOO00 + O0 % i1IIi - Oo0Ooo
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if ( lisp_i_am_rtr == False ) :
   self . rloc_name += LISP_TP + str ( port )
   if 96 - 96: O0 % o0oOOo0O0Ooo + OOooOOo % I1IiiI
   if 51 - 51: i1IIi . o0oOOo0O0Ooo % I1IiiI - OoooooooOO / OoOoOO00 - I11i
   if 45 - 45: O0 * II111iiii / i11iIiiIii
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 38 - 38: OoooooooOO % i11iIiiIii - O0 / O0
  if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
  return ( True )
  if 85 - 85: IiII / Ii1I - I1ii11iIi11i * OOooOOo
  if 19 - 19: I1ii11iIi11i
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 12 - 12: ooOoO0o * I1ii11iIi11i * O0 / oO0o + iII111i - iIii1I11I1II1
  if 81 - 81: Ii1I
  if 87 - 87: O0 % iII111i
 def print_state_change ( self , new_state ) :
  oOo0o00OOOO = self . print_state ( )
  Oo0 = "{} -> {}" . format ( oOo0o00OOOO , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   Oo0 = bold ( Oo0 , False )
   if 7 - 7: I1Ii111 + O0 % i11iIiiIii + o0oOOo0O0Ooo . OoooooooOO
  return ( Oo0 )
  if 74 - 74: OOooOOo
  if 10 - 10: OoOoOO00 / i11iIiiIii
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 21 - 21: Ii1I - i1IIi / I11i + IiII
  if 44 - 44: OoooooooOO % I11i / O0
 def print_recent_rloc_probe_rtts ( self ) :
  o0oOOo0O0oOO = str ( self . recent_rloc_probe_rtts )
  o0oOOo0O0oOO = o0oOOo0O0oOO . replace ( "-1" , "?" )
  return ( o0oOOo0O0oOO )
  if 54 - 54: ooOoO0o % o0oOOo0O0Ooo + i11iIiiIii / ooOoO0o * II111iiii * Ii1I
  if 52 - 52: ooOoO0o + IiII * OoOoOO00 - OoO0O00 - OoooooooOO - oO0o
 def compute_rloc_probe_rtt ( self ) :
  iII11I = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  o0O0o = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ iII11I ] + o0O0o [ 0 : - 1 ]
  if 22 - 22: I1IiiI % iII111i + II111iiii
  if 60 - 60: OoooooooOO % O0 % OoOoOO00 % Ii1I * OOooOOo
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 83 - 83: ooOoO0o . I1ii11iIi11i * O0 . i1IIi . oO0o + O0
  if 52 - 52: I11i * OOooOOo - OoOoOO00 % iIii1I11I1II1 . II111iiii
 def print_recent_rloc_probe_hops ( self ) :
  I1ii1OOo = str ( self . recent_rloc_probe_hops )
  return ( I1ii1OOo )
  if 98 - 98: OOooOOo . ooOoO0o / I1ii11iIi11i . OOooOOo + OoO0O00 % IiII
  if 53 - 53: I1IiiI . iII111i . IiII / i11iIiiIii . o0oOOo0O0Ooo - I11i
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 66 - 66: II111iiii - I1IiiI % OoO0O00 + o0oOOo0O0Ooo . ooOoO0o / Ii1I
  if ( from_ttl < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   O0ooo0oO00 = "!"
  else :
   O0ooo0oO00 = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 86 - 86: I11i * ooOoO0o / O0 + i11iIiiIii
   if 18 - 18: OoooooooOO % OOooOOo + I1ii11iIi11i * I1Ii111 / OOooOOo / I1IiiI
  iII11I = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + O0ooo0oO00
  o0O0o = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ iII11I ] + o0O0o [ 0 : - 1 ]
  if 7 - 7: OOooOOo / OoOoOO00
  if 93 - 93: iIii1I11I1II1 * Ii1I - iII111i
 def store_rloc_probe_latencies ( self , json_telemetry ) :
  Oo0o00oO00o0O = lisp_decode_telemetry ( json_telemetry )
  if 37 - 37: OOooOOo - OoOoOO00
  o00O0O = round ( float ( Oo0o00oO00o0O [ "etr-in" ] ) - float ( Oo0o00oO00o0O [ "itr-out" ] ) , 3 )
  ooOo0O = round ( float ( Oo0o00oO00o0O [ "itr-in" ] ) - float ( Oo0o00oO00o0O [ "etr-out" ] ) , 3 )
  if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
  iII11I = self . rloc_probe_latency
  self . rloc_probe_latency = str ( o00O0O ) + "/" + str ( ooOo0O )
  o0O0o = self . recent_rloc_probe_latencies
  self . recent_rloc_probe_latencies = [ iII11I ] + o0O0o [ 0 : - 1 ]
  if 98 - 98: IiII
  if 75 - 75: OoooooooOO % IiII + Ii1I - i1IIi / OoooooooOO
 def print_rloc_probe_latency ( self ) :
  return ( self . rloc_probe_latency )
  if 57 - 57: iII111i
  if 18 - 18: II111iiii % i11iIiiIii + I11i - OOooOOo
 def print_recent_rloc_probe_latencies ( self ) :
  OOO0o = str ( self . recent_rloc_probe_latencies )
  return ( OOO0o )
  if 15 - 15: iII111i % I11i / II111iiii * O0
  if 61 - 61: OOooOOo / OoO0O00 % I11i * OoO0O00 / IiII / I1IiiI
 def process_rloc_probe_reply ( self , ts , nonce , eid , group , hc , ttl , jt ) :
  OOOo0 = self
  while ( True ) :
   if ( OOOo0 . last_rloc_probe_nonce == nonce ) : break
   OOOo0 = OOOo0 . next_rloc
   if ( OOOo0 == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 77 - 77: IiII / i1IIi + OOooOOo + Oo0Ooo % iII111i % OoOoOO00
    return
    if 6 - 6: i11iIiiIii + ooOoO0o
    if 89 - 89: iIii1I11I1II1 . I1Ii111
    if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
    if 59 - 59: IiII . OoO0O00 - OoooooooOO . O0
    if 33 - 33: Ii1I
    if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
  OOOo0 . last_rloc_probe_reply = ts
  OOOo0 . compute_rloc_probe_rtt ( )
  ii111 = OOOo0 . print_state_change ( "up" )
  if ( OOOo0 . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( OOOo0 . rloc , True )
   OOOo0 . state = LISP_RLOC_UP_STATE
   OOOo0 . last_state_change = lisp_get_timestamp ( )
   Ii111 = lisp_map_cache . lookup_cache ( eid , True )
   if ( Ii111 ) : lisp_write_ipc_map_cache ( True , Ii111 )
   if 98 - 98: I1IiiI
   if 4 - 4: I1IiiI % O0 / Oo0Ooo / O0
   if 90 - 90: ooOoO0o - O0 . IiII - O0 . iIii1I11I1II1
   if 42 - 42: I1ii11iIi11i
   if 51 - 51: iII111i % i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
  OOOo0 . store_rloc_probe_hops ( hc , ttl )
  if 14 - 14: I1ii11iIi11i . OoO0O00
  if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
  if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
  if 29 - 29: O0 + iII111i
  if ( jt ) : OOOo0 . store_rloc_probe_latencies ( jt )
  if 4 - 4: I11i * I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
  Ii1IiI = bold ( "RLOC-probe reply" , False )
  Oo0o = OOOo0 . rloc . print_address_no_iid ( )
  I1iiiiIIiiI1i = bold ( str ( OOOo0 . print_rloc_probe_rtt ( ) ) , False )
  o00oo = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 65 - 65: OoooooooOO . OOooOOo
  oo0O0 = ""
  if ( OOOo0 . rloc_next_hop != None ) :
   iiIi , o0Ooo0oo = OOOo0 . rloc_next_hop
   oo0O0 = ", nh {}({})" . format ( o0Ooo0oo , iiIi )
   if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
   if 65 - 65: I1ii11iIi11i % ooOoO0o - OoOoOO00 + ooOoO0o + Oo0Ooo
  iiiii = bold ( OOOo0 . print_rloc_probe_latency ( ) , False )
  iiiii = ", latency {}" . format ( iiiii ) if jt else ""
  if 95 - 95: I1Ii111 * i11iIiiIii - I1IiiI - OoOoOO00 . ooOoO0o
  o0o00oO0oo000 = green ( lisp_print_eid_tuple ( eid , group ) , False )
  if 34 - 34: OoooooooOO % I1ii11iIi11i + OoooooooOO % i11iIiiIii / IiII - ooOoO0o
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}{}" ) . format ( Ii1IiI , red ( Oo0o , False ) , o00oo , o0o00oO0oo000 ,
  # I11i + Oo0Ooo . IiII / iII111i % OoooooooOO
 ii111 , I1iiiiIIiiI1i , oo0O0 , str ( hc ) + "/" + str ( ttl ) , iiiii ) )
  if 35 - 35: O0 . Oo0Ooo / Oo0Ooo / Ii1I / i1IIi * I11i
  if ( OOOo0 . rloc_next_hop == None ) : return
  if 93 - 93: O0 + IiII
  if 91 - 91: iIii1I11I1II1
  if 66 - 66: i1IIi . ooOoO0o
  if 84 - 84: O0 % ooOoO0o / I1Ii111
  OOOo0 = None
  o0o0oOoOo = None
  while ( True ) :
   OOOo0 = self if OOOo0 == None else OOOo0 . next_rloc
   if ( OOOo0 == None ) : break
   if ( OOOo0 . up_state ( ) == False ) : continue
   if ( OOOo0 . rloc_probe_rtt == - 1 ) : continue
   if ( OOOo0 . last_rloc_probe_nonce != nonce ) : continue
   if 74 - 74: i1IIi - i11iIiiIii / O0 - o0oOOo0O0Ooo
   if ( o0o0oOoOo == None ) : o0o0oOoOo = OOOo0
   if ( OOOo0 . rloc_probe_rtt < o0o0oOoOo . rloc_probe_rtt ) : o0o0oOoOo = OOOo0
   if 65 - 65: oO0o
   if 57 - 57: I1Ii111 + IiII . o0oOOo0O0Ooo % OoO0O00 - I11i * oO0o
  if ( o0o0oOoOo != None ) :
   iiIi , o0Ooo0oo = o0o0oOoOo . rloc_next_hop
   oo0O0 = bold ( "nh {}({})" . format ( o0Ooo0oo , iiIi ) , False )
   lprint ( "    Install forwarding host-route via best {}" . format ( oo0O0 ) )
   lisp_install_host_route ( Oo0o , None , False )
   lisp_install_host_route ( Oo0o , o0Ooo0oo , True )
   if 55 - 55: I1IiiI / ooOoO0o
   if 81 - 81: ooOoO0o + I1Ii111 / I1ii11iIi11i - o0oOOo0O0Ooo + OoOoOO00 * OOooOOo
   if 83 - 83: OoO0O00 . O0 + II111iiii
 def add_to_rloc_probe_list ( self , eid , group ) :
  Oo0o = self . rloc . print_address_no_iid ( )
  O00oo0o0o0oo = self . translated_port
  if ( O00oo0o0o0oo != 0 ) : Oo0o += ":" + str ( O00oo0o0o0oo )
  if 42 - 42: OOooOOo * I1Ii111
  if ( Oo0o not in lisp_rloc_probe_list ) :
   lisp_rloc_probe_list [ Oo0o ] = [ ]
   if 53 - 53: II111iiii % OOooOOo / I1ii11iIi11i * OoOoOO00 % I1ii11iIi11i * iII111i
   if 91 - 91: iII111i . OoooooooOO
  if ( group . is_null ( ) ) : group . instance_id = 0
  for o0O00o0o , o0o00oO0oo000 , o0O0Ooo in lisp_rloc_probe_list [ Oo0o ] :
   if ( o0o00oO0oo000 . is_exact_match ( eid ) and o0O0Ooo . is_exact_match ( group ) ) :
    if ( o0O00o0o == self ) :
     if ( lisp_rloc_probe_list [ Oo0o ] == [ ] ) :
      lisp_rloc_probe_list . pop ( Oo0o )
      if 90 - 90: i11iIiiIii - I1IiiI
     return
     if 39 - 39: iII111i % OoooooooOO % Ii1I % I1IiiI
    lisp_rloc_probe_list [ Oo0o ] . remove ( [ o0O00o0o , o0o00oO0oo000 , o0O0Ooo ] )
    break
    if 63 - 63: OoO0O00 - I1Ii111 - II111iiii
    if 79 - 79: II111iiii - II111iiii + OoOoOO00 / iII111i % OoooooooOO - OoO0O00
  lisp_rloc_probe_list [ Oo0o ] . append ( [ self , eid , group ] )
  if 22 - 22: o0oOOo0O0Ooo + I1Ii111 . Oo0Ooo
  if 84 - 84: O0 + I1IiiI % Oo0Ooo + OOooOOo
  if 94 - 94: OOooOOo
  if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
  if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
  OOOo0 = lisp_rloc_probe_list [ Oo0o ] [ 0 ] [ 0 ]
  if ( OOOo0 . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 31 - 31: I11i . o0oOOo0O0Ooo
   if 82 - 82: I11i - Oo0Ooo
   if 77 - 77: I1IiiI + OoO0O00 % iIii1I11I1II1 - OOooOOo
 def delete_from_rloc_probe_list ( self , eid , group ) :
  Oo0o = self . rloc . print_address_no_iid ( )
  O00oo0o0o0oo = self . translated_port
  if ( O00oo0o0o0oo != 0 ) : Oo0o += ":" + str ( O00oo0o0o0oo )
  if ( Oo0o not in lisp_rloc_probe_list ) : return
  if 80 - 80: oO0o % I1ii11iIi11i * I1Ii111 + i1IIi
  oO0oOO = [ ]
  for iIiiI11II11i in lisp_rloc_probe_list [ Oo0o ] :
   if ( iIiiI11II11i [ 0 ] != self ) : continue
   if ( iIiiI11II11i [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( iIiiI11II11i [ 2 ] . is_exact_match ( group ) == False ) : continue
   oO0oOO = iIiiI11II11i
   break
   if 81 - 81: I1Ii111 / I1ii11iIi11i
  if ( oO0oOO == [ ] ) : return
  if 69 - 69: I1IiiI
  try :
   lisp_rloc_probe_list [ Oo0o ] . remove ( oO0oOO )
   if ( lisp_rloc_probe_list [ Oo0o ] == [ ] ) :
    lisp_rloc_probe_list . pop ( Oo0o )
    if 79 - 79: ooOoO0o
  except :
   return
   if 83 - 83: I1Ii111 % II111iiii
   if 89 - 89: Ii1I . I11i
   if 98 - 98: I1Ii111 / O0 % ooOoO0o
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  ooOo0O0O0oOO0 = ""
  OOOo0 = self
  while ( True ) :
   IiOo = OOOo0 . last_rloc_probe
   if ( IiOo == None ) : IiOo = 0
   oO0ooO0O00OO = OOOo0 . last_rloc_probe_reply
   if ( oO0ooO0O00OO == None ) : oO0ooO0O00OO = 0
   I1iiiiIIiiI1i = OOOo0 . print_rloc_probe_rtt ( )
   o0O0o0000o0O0 = space ( 4 )
   if 55 - 55: Oo0Ooo * i11iIiiIii / OOooOOo
   if ( OOOo0 . rloc_next_hop == None ) :
    ooOo0O0O0oOO0 += "RLOC-Probing:\n"
   else :
    iiIi , o0Ooo0oo = OOOo0 . rloc_next_hop
    ooOo0O0O0oOO0 += "RLOC-Probing for nh {}({}):\n" . format ( o0Ooo0oo , iiIi )
    if 10 - 10: OoooooooOO * i1IIi . I1IiiI
    if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
   ooOo0O0O0oOO0 += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( o0O0o0000o0O0 , lisp_print_elapsed ( IiOo ) ,
   # OoOoOO00 * ooOoO0o - IiII % Ii1I
 o0O0o0000o0O0 , lisp_print_elapsed ( oO0ooO0O00OO ) , I1iiiiIIiiI1i )
   if 76 - 76: I11i - iIii1I11I1II1 - i1IIi + i1IIi
   if ( trailing_linefeed ) : ooOo0O0O0oOO0 += "\n"
   if 60 - 60: I11i + OOooOOo - o0oOOo0O0Ooo
   OOOo0 = OOOo0 . next_rloc
   if ( OOOo0 == None ) : break
   ooOo0O0O0oOO0 += "\n"
   if 64 - 64: II111iiii / iII111i * OoOoOO00 / OOooOOo / Ii1I
  return ( ooOo0O0O0oOO0 )
  if 19 - 19: OoOoOO00 % I1Ii111
  if 13 - 13: o0oOOo0O0Ooo % iIii1I11I1II1 + OoO0O00 / iIii1I11I1II1 . iIii1I11I1II1
 def get_encap_keys ( self ) :
  O00oo0o0o0oo = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
  Oo0o = self . rloc . print_address_no_iid ( ) + ":" + O00oo0o0o0oo
  if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
  try :
   O0o0O0 = lisp_crypto_keys_by_rloc_encap [ Oo0o ]
   if ( O0o0O0 [ 1 ] ) : return ( O0o0O0 [ 1 ] . encrypt_key , O0o0O0 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
   if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
   if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
 def rloc_recent_rekey ( self ) :
  O00oo0o0o0oo = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
  Oo0o = self . rloc . print_address_no_iid ( ) + ":" + O00oo0o0o0oo
  if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
  try :
   III11II111 = lisp_crypto_keys_by_rloc_encap [ Oo0o ] [ 1 ]
   if ( III11II111 == None ) : return ( False )
   if ( III11II111 . last_rekey == None ) : return ( True )
   return ( time . time ( ) - III11II111 . last_rekey < 1 )
  except :
   return ( False )
   if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
   if 91 - 91: II111iiii * o0oOOo0O0Ooo
   if 20 - 20: iIii1I11I1II1 % Oo0Ooo * OoOoOO00 % IiII
 def refresh_decent_nat_rloc ( self , lisp_sockets , eid ) :
  Oo0OO0000oooo = self . last_state_change
  if ( Oo0OO0000oooo == None ) : return
  if ( ( time . time ( ) - Oo0OO0000oooo ) <= 60 ) : return
  if 93 - 93: I11i * iIii1I11I1II1 * oO0o
  o0o00oO0oo000 = green ( eid . print_address ( ) , False )
  o0O00o0o = red ( self . rloc . print_address_no_iid ( ) , False )
  Ii1IOo0Oo0oOoO = blue ( self . rloc_name , False )
  lprint ( "Refresh map-cache for {} for RLOC {}, {}" . format ( o0o00oO0oo000 , o0O00o0o , Ii1IOo0Oo0oOoO ) )
  if 74 - 74: I1IiiI
  lisp_send_map_request ( lisp_sockets , 0 , None , eid , None )
  if 39 - 39: iII111i * IiII / iII111i * IiII % I1ii11iIi11i
  if 27 - 27: iIii1I11I1II1 . ooOoO0o
  if 74 - 74: i1IIi % OoOoOO00
class lisp_mapping ( object ) :
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
  if 98 - 98: IiII * OOooOOo / O0 - I1Ii111 . I1Ii111 + OOooOOo
  if 61 - 61: iII111i * Ii1I % Ii1I + I1IiiI
 def print_mapping ( self , eid_indent , rloc_indent ) :
  Oo0OO0000oooo = lisp_print_elapsed ( self . uptime )
  iII1I1i = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 23 - 23: oO0o + I1Ii111 / OoooooooOO / O0 + IiII
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , iII1I1i , Oo0OO0000oooo ,
 len ( self . rloc_set ) ) )
  for OOOo0 in self . rloc_set : OOOo0 . print_rloc ( rloc_indent )
  if 80 - 80: i11iIiiIii - OoooooooOO + II111iiii / i1IIi - oO0o
  if 100 - 100: Ii1I
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 73 - 73: IiII - O0
  if 54 - 54: OOooOOo
 def print_ttl ( self ) :
  OO0ooo00o = self . map_cache_ttl
  if ( OO0ooo00o == None ) : return ( "forever" )
  if 28 - 28: i1IIi - Oo0Ooo * OoO0O00 + OoooooooOO - Ii1I * i11iIiiIii
  if ( OO0ooo00o >= 3600 ) :
   if ( ( OO0ooo00o % 3600 ) == 0 ) :
    OO0ooo00o = str ( old_div ( OO0ooo00o , 3600 ) ) + " hours"
   else :
    OO0ooo00o = str ( OO0ooo00o * 60 ) + " mins"
    if 71 - 71: iII111i - OOooOOo / iIii1I11I1II1 % i11iIiiIii
  elif ( OO0ooo00o >= 60 ) :
   if ( ( OO0ooo00o % 60 ) == 0 ) :
    OO0ooo00o = str ( old_div ( OO0ooo00o , 60 ) ) + " mins"
   else :
    OO0ooo00o = str ( OO0ooo00o ) + " secs"
    if 39 - 39: o0oOOo0O0Ooo
  else :
   OO0ooo00o = str ( OO0ooo00o ) + " secs"
   if 32 - 32: iIii1I11I1II1 . II111iiii / IiII % O0 / iII111i
  return ( OO0ooo00o )
  if 97 - 97: iIii1I11I1II1
  if 18 - 18: OOooOOo
 def refresh ( self ) :
  if ( self . group . is_null ( ) ) : return ( self . refresh_unicast ( ) )
  return ( self . refresh_multicast ( ) )
  if 87 - 87: O0 - i1IIi . I11i / Ii1I % iIii1I11I1II1
  if 57 - 57: I11i . IiII / iIii1I11I1II1 - ooOoO0o
 def refresh_unicast ( self ) :
  return ( self . is_active ( ) and self . has_ttl_elapsed ( ) and
 self . gleaned == False )
  if 50 - 50: O0 / II111iiii
  if 94 - 94: O0 + O0 % I1ii11iIi11i % i1IIi
 def refresh_multicast ( self ) :
  if 15 - 15: I1IiiI
  if 48 - 48: Ii1I * IiII % O0 - II111iiii
  if 66 - 66: iIii1I11I1II1 / OOooOOo
  if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
  if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
  i11Ii1IIi = int ( ( time . time ( ) - self . uptime ) % self . map_cache_ttl )
  o0000OoooO0Oo = ( i11Ii1IIi in [ 0 , 1 , 2 ] )
  if ( o0000OoooO0Oo == False ) : return ( False )
  if 3 - 3: I11i - Ii1I / OOooOOo . I1ii11iIi11i
  if 21 - 21: oO0o + O0 % ooOoO0o
  if 32 - 32: OoOoOO00 % IiII % OoO0O00
  if 95 - 95: ooOoO0o
  IiiiiIIi1i1i = ( ( time . time ( ) - self . last_multicast_map_request ) <= 2 )
  if ( IiiiiIIi1i1i ) : return ( False )
  if 64 - 64: OOooOOo . I1ii11iIi11i . IiII
  self . last_multicast_map_request = lisp_get_timestamp ( )
  return ( True )
  if 51 - 51: iII111i * I1Ii111 - I11i % iIii1I11I1II1 * o0oOOo0O0Ooo % I1IiiI
  if 5 - 5: OoO0O00
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  i11Ii1IIi = time . time ( ) - self . last_refresh_time
  if ( i11Ii1IIi >= self . map_cache_ttl ) : return ( True )
  if 10 - 10: o0oOOo0O0Ooo % OOooOOo / Ii1I . iIii1I11I1II1 % o0oOOo0O0Ooo + o0oOOo0O0Ooo
  if 63 - 63: i11iIiiIii
  if 34 - 34: OoooooooOO - O0 + ooOoO0o * I1IiiI
  if 75 - 75: OOooOOo % iII111i
  if 15 - 15: OoO0O00
  oo0o = self . map_cache_ttl - ( old_div ( self . map_cache_ttl , 10 ) )
  if ( i11Ii1IIi >= oo0o ) : return ( True )
  return ( False )
  if 55 - 55: oO0o . OoOoOO00 + OoooooooOO - ooOoO0o . OoooooooOO
  if 77 - 77: I1IiiI
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  i11Ii1IIi = time . time ( ) - self . stats . last_increment
  return ( i11Ii1IIi <= 60 )
  if 16 - 16: I1IiiI + ooOoO0o - O0 / o0oOOo0O0Ooo
  if 36 - 36: Oo0Ooo - OoOoOO00 - II111iiii
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
  if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
  if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for OOOo0 in self . best_rloc_set :
   OOOo0 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
   if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
   if 92 - 92: I11i
 def build_best_rloc_set ( self ) :
  IIii1I1Iiii = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 98 - 98: iII111i % IiII + OoO0O00
  if 23 - 23: OOooOOo
  if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
  if 99 - 99: II111iiii + O0
  O0O0oO00Oo00 = 256
  for OOOo0 in self . rloc_set :
   if ( OOOo0 . up_state ( ) ) : O0O0oO00Oo00 = min ( OOOo0 . priority , O0O0oO00Oo00 )
   if 27 - 27: Oo0Ooo
   if 81 - 81: Oo0Ooo * Ii1I % OoO0O00 * i1IIi . I1IiiI + Oo0Ooo
   if 45 - 45: OoO0O00
   if 83 - 83: i1IIi + OoooooooOO * IiII
   if 65 - 65: II111iiii / I1Ii111 + I1IiiI - OoooooooOO + ooOoO0o - I1ii11iIi11i
   if 29 - 29: OoOoOO00 / OOooOOo / OoO0O00
   if 95 - 95: ooOoO0o
   if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
   if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
   if 32 - 32: OoOoOO00 % i11iIiiIii
  for OOOo0 in self . rloc_set :
   if ( OOOo0 . priority <= O0O0oO00Oo00 ) :
    if ( OOOo0 . unreach_state ( ) and OOOo0 . last_rloc_probe == None ) :
     OOOo0 . last_rloc_probe = lisp_get_timestamp ( )
     if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
    self . best_rloc_set . append ( OOOo0 )
    if 44 - 44: I1Ii111 + ooOoO0o
    if 15 - 15: I11i + OoO0O00 + OoOoOO00
    if 100 - 100: I1Ii111
    if 78 - 78: OoOoOO00
    if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
    if 36 - 36: OoOoOO00 * II111iiii . OoooooooOO * I11i . I11i
    if 13 - 13: I1ii11iIi11i * II111iiii
    if 93 - 93: OOooOOo / O0 - o0oOOo0O0Ooo + OoO0O00 * I1IiiI
  for OOOo0 in IIii1I1Iiii :
   if ( OOOo0 . priority < O0O0oO00Oo00 ) : continue
   OOOo0 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 53 - 53: I1ii11iIi11i
  for OOOo0 in self . best_rloc_set :
   if ( OOOo0 . rloc . is_null ( ) ) : continue
   OOOo0 . add_to_rloc_probe_list ( self . eid , self . group )
   if 91 - 91: o0oOOo0O0Ooo - I1ii11iIi11i . i1IIi
   if 64 - 64: ooOoO0o
   if 23 - 23: Oo0Ooo . OoO0O00
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  OO0Oo00OO0oo = lisp_packet . packet
  iI1i1iIIIII = lisp_packet . inner_version
  iIo00oo = len ( self . best_rloc_set )
  if ( iIo00oo == 0 ) :
   self . stats . increment ( len ( OO0Oo00OO0oo ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 19 - 19: oO0o - I1ii11iIi11i + iII111i . o0oOOo0O0Ooo . OoO0O00 * Oo0Ooo
   if 39 - 39: i11iIiiIii - iII111i / O0 % Oo0Ooo
  Ii1IiIi1i111i = 4 if lisp_load_split_pings else 0
  I111i = lisp_packet . hash_ports ( )
  if ( iI1i1iIIIII == 4 ) :
   for iIiIIi in range ( 8 + Ii1IiIi1i111i ) :
    I111i = I111i ^ struct . unpack ( "B" , OO0Oo00OO0oo [ iIiIIi + 12 : iIiIIi + 13 ] ) [ 0 ]
    if 52 - 52: I1ii11iIi11i
  elif ( iI1i1iIIIII == 6 ) :
   for iIiIIi in range ( 0 , 32 + Ii1IiIi1i111i , 4 ) :
    I111i = I111i ^ struct . unpack ( "I" , OO0Oo00OO0oo [ iIiIIi + 8 : iIiIIi + 12 ] ) [ 0 ]
    if 1 - 1: II111iiii + I1ii11iIi11i * OoOoOO00 % ooOoO0o - iII111i % OoooooooOO
   I111i = ( I111i >> 16 ) + ( I111i & 0xffff )
   I111i = ( I111i >> 8 ) + ( I111i & 0xff )
  else :
   for iIiIIi in range ( 0 , 12 + Ii1IiIi1i111i , 4 ) :
    I111i = I111i ^ struct . unpack ( "I" , OO0Oo00OO0oo [ iIiIIi : iIiIIi + 4 ] ) [ 0 ]
    if 77 - 77: iII111i + o0oOOo0O0Ooo
    if 60 - 60: I1ii11iIi11i
    if 23 - 23: iII111i % I1IiiI % I1Ii111 * oO0o * I1IiiI
  if ( lisp_data_plane_logging ) :
   Ooo0i11II1IIIIi = [ ]
   for o0O00o0o in self . best_rloc_set :
    if ( o0O00o0o . rloc . is_null ( ) ) : continue
    Ooo0i11II1IIIIi . append ( [ o0O00o0o . rloc . print_address_no_iid ( ) , o0O00o0o . print_state ( ) ] )
    if 12 - 12: OoooooooOO . I1ii11iIi11i + O0 / OoOoOO00
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( I111i ) , I111i % iIo00oo , red ( str ( Ooo0i11II1IIIIi ) , False ) ) )
   if 20 - 20: I1ii11iIi11i * I1ii11iIi11i + I1ii11iIi11i / OoO0O00 - oO0o % O0
   if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
   if 86 - 86: Oo0Ooo / OoO0O00
   if 78 - 78: I1IiiI * I1IiiI
   if 13 - 13: oO0o
   if 43 - 43: oO0o / Ii1I % OOooOOo
  OOOo0 = self . best_rloc_set [ I111i % iIo00oo ]
  if 45 - 45: II111iiii
  if 41 - 41: Ii1I / OOooOOo * Oo0Ooo . O0 - i11iIiiIii
  if 77 - 77: o0oOOo0O0Ooo + I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
  if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
  if ( lisp_decent_nat and OOOo0 . stats . packet_count == 0 ) :
   o0O00o0o = self . find_rtr_rloc ( )
   if ( o0O00o0o != None ) : OOOo0 = o0O00o0o
   if 43 - 43: OOooOOo . O0
   if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
   if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
   if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
   if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
   if 24 - 24: ooOoO0o % I1Ii111 + OoO0O00 * o0oOOo0O0Ooo % O0 - i11iIiiIii
  i1OooO00oO00o = lisp_get_echo_nonce ( OOOo0 . rloc , None )
  if ( i1OooO00oO00o ) :
   i1OooO00oO00o . change_state ( OOOo0 )
   if ( OOOo0 . no_echoed_nonce_state ( ) ) :
    i1OooO00oO00o . request_nonce_sent = None
    if 49 - 49: o0oOOo0O0Ooo / OoOoOO00 + iII111i
    if 85 - 85: I1IiiI - o0oOOo0O0Ooo
    if 86 - 86: II111iiii + Ii1I * Ii1I
    if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
    if 86 - 86: Ii1I
    if 69 - 69: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
  if ( OOOo0 . up_state ( ) == False ) :
   iIiI1I111i1 = I111i % iIo00oo
   o00o = ( iIiI1I111i1 + 1 ) % iIo00oo
   while ( o00o != iIiI1I111i1 ) :
    OOOo0 = self . best_rloc_set [ o00o ]
    if ( OOOo0 . up_state ( ) ) : break
    o00o = ( o00o + 1 ) % iIo00oo
    if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
   if ( o00o == iIiI1I111i1 ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
    if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
    if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
    if 32 - 32: OoooooooOO . I1Ii111 - I1ii11iIi11i
    if 29 - 29: OoO0O00
    if 33 - 33: I1ii11iIi11i - O0
  OOOo0 . stats . increment ( len ( OO0Oo00OO0oo ) )
  if 72 - 72: Oo0Ooo * iII111i - I11i
  if 81 - 81: I1Ii111
  if 85 - 85: O0 % OoOoOO00 . I1ii11iIi11i
  if 46 - 46: OOooOOo * iIii1I11I1II1
  if ( OOOo0 . rle_name and OOOo0 . rle == None ) :
   if ( OOOo0 . rle_name in lisp_rle_list ) :
    OOOo0 . rle = lisp_rle_list [ OOOo0 . rle_name ]
    if 33 - 33: OoO0O00 * II111iiii / i1IIi
    if 93 - 93: I1Ii111 % I11i
  if ( OOOo0 . rle ) : return ( [ None , None , None , None , OOOo0 . rle , None ] )
  if 64 - 64: I1IiiI % OoOoOO00 / Oo0Ooo
  if 40 - 40: Ii1I + iIii1I11I1II1 / oO0o . II111iiii % O0 - IiII
  if 49 - 49: IiII - OOooOOo * OOooOOo . O0
  if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
  if ( OOOo0 . elp and OOOo0 . elp . use_elp_node ) :
   return ( [ OOOo0 . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
   if 61 - 61: OoO0O00
   if 100 - 100: OoOoOO00
   if 97 - 97: OoooooooOO
   if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
  i11IiIi11I = None if ( OOOo0 . rloc . is_null ( ) ) else OOOo0 . rloc
  O00oo0o0o0oo = OOOo0 . translated_port
  Oo00Oo0o000 = self . action if ( i11IiIi11I == None ) else None
  if 84 - 84: I1IiiI . o0oOOo0O0Ooo * I1ii11iIi11i
  if 41 - 41: o0oOOo0O0Ooo * Ii1I + I11i . O0
  if 17 - 17: Ii1I % I1Ii111
  if 69 - 69: iIii1I11I1II1
  if 65 - 65: IiII % OOooOOo / o0oOOo0O0Ooo * II111iiii - oO0o
  o000oo = None
  if ( i1OooO00oO00o and i1OooO00oO00o . request_nonce_timeout ( ) == False ) :
   o000oo = i1OooO00oO00o . get_request_or_echo_nonce ( ipc_socket , i11IiIi11I )
   if 38 - 38: I1Ii111 * o0oOOo0O0Ooo
   if 32 - 32: iII111i / Ii1I / I1Ii111 - OoOoOO00 / OOooOOo * OoO0O00
   if 32 - 32: I1ii11iIi11i + ooOoO0o . i1IIi * iIii1I11I1II1 - I1IiiI
   if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
   if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
  return ( [ i11IiIi11I , O00oo0o0o0oo , o000oo , Oo00Oo0o000 , None , OOOo0 ] )
  if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
  if 17 - 17: OOooOOo / i11iIiiIii - i11iIiiIii . II111iiii . ooOoO0o
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 38 - 38: OOooOOo . OoooooooOO . II111iiii + OoO0O00 / oO0o . OoooooooOO
  if 100 - 100: OoO0O00
  if 36 - 36: oO0o + Ii1I - O0
  if 19 - 19: O0 + I1Ii111 . I1Ii111 * IiII * ooOoO0o + i1IIi
  if 51 - 51: ooOoO0o % OoOoOO00 % i1IIi / O0
  for oO0O0oOOO0 in self . rloc_set :
   for OOOo0 in rloc_address_set :
    if ( OOOo0 . is_exact_match ( oO0O0oOOO0 . rloc ) == False ) : continue
    OOOo0 = None
    break
    if 11 - 11: OOooOOo . I1ii11iIi11i * OOooOOo * OoO0O00
   if ( OOOo0 == rloc_address_set [ - 1 ] ) : return ( False )
   if 11 - 11: I11i
  return ( True )
  if 85 - 85: OoOoOO00 - Ii1I / Oo0Ooo % I1ii11iIi11i
  if 12 - 12: i1IIi + o0oOOo0O0Ooo / oO0o . O0
 def get_rloc ( self , rloc ) :
  for oO0O0oOOO0 in self . rloc_set :
   o0O00o0o = oO0O0oOOO0 . rloc
   if ( rloc . is_exact_match ( o0O00o0o ) ) : return ( oO0O0oOOO0 )
   if 37 - 37: IiII
  return ( None )
  if 99 - 99: i11iIiiIii % i11iIiiIii . I11i * I1ii11iIi11i . OoO0O00 / I1IiiI
  if 44 - 44: iII111i - OoO0O00 / i11iIiiIii
 def get_rloc_by_interface ( self , interface ) :
  for oO0O0oOOO0 in self . rloc_set :
   if ( oO0O0oOOO0 . interface == interface ) : return ( oO0O0oOOO0 )
   if 55 - 55: O0 * OoO0O00 * i1IIi
  return ( None )
  if 9 - 9: IiII
  if 64 - 64: ooOoO0o + OoooooooOO
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   Oo0000 = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( Oo0000 == None ) :
    Oo0000 = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , Oo0000 )
    if 99 - 99: iIii1I11I1II1 * II111iiii * i11iIiiIii
   Oo0000 . add_source_entry ( self )
   if 10 - 10: OOooOOo
   if 75 - 75: I11i * ooOoO0o * Oo0Ooo . i1IIi . ooOoO0o . ooOoO0o
   if 24 - 24: iIii1I11I1II1
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   Ii111 = lisp_map_cache . lookup_cache ( self . group , True )
   if ( Ii111 == None ) :
    Ii111 = lisp_mapping ( self . group , self . group , [ ] )
    Ii111 . eid . copy_address ( self . group )
    Ii111 . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , Ii111 )
    if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( Ii111 . group )
   Ii111 . add_source_entry ( self )
   if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
  if 62 - 62: o0oOOo0O0Ooo
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    o00OO = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( o00OO ) )
    if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
  else :
   Ii111 = lisp_map_cache . lookup_cache ( self . group , True )
   if ( Ii111 == None ) : return
   if 84 - 84: OoOoOO00
   oO0oo00OO = Ii111 . lookup_source_cache ( self . eid , True )
   if ( oO0oo00OO == None ) : return
   if 52 - 52: I11i % I1Ii111 % i11iIiiIii
   Ii111 . source_cache . delete_cache ( self . eid )
   if ( Ii111 . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 84 - 84: I1IiiI % II111iiii + Oo0Ooo + OoOoOO00 + Oo0Ooo . I1Ii111
    if 58 - 58: II111iiii + I1Ii111 / I11i
    if 13 - 13: I1ii11iIi11i + II111iiii * IiII * OoooooooOO + O0 * O0
    if 15 - 15: Oo0Ooo % I11i * O0
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 61 - 61: I1ii11iIi11i - ooOoO0o / OoOoOO00 % OOooOOo * i1IIi . IiII
  if 27 - 27: I1ii11iIi11i % iII111i . Oo0Ooo * iIii1I11I1II1
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 40 - 40: I11i
  if 58 - 58: o0oOOo0O0Ooo / OOooOOo . oO0o % ooOoO0o
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 33 - 33: I1IiiI * I1ii11iIi11i . OoO0O00 - I1Ii111 . OoO0O00
  if 79 - 79: ooOoO0o
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  oO0O = "," + str ( self . secondary_iid )
  return ( prefix . replace ( oO0O , oO0O + "*" ) )
  if 90 - 90: OOooOOo
  if 4 - 4: OoOoOO00 - I1Ii111 . i1IIi - IiII . ooOoO0o + II111iiii
 def increment_decap_stats ( self , packet ) :
  O00oo0o0o0oo = packet . udp_dport
  if ( O00oo0o0o0oo == LISP_DATA_PORT ) :
   OOOo0 = self . get_rloc ( packet . outer_dest )
  else :
   if 56 - 56: I1ii11iIi11i / i1IIi + I11i % Oo0Ooo
   if 86 - 86: O0 * II111iiii
   if 75 - 75: iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % I1ii11iIi11i . II111iiii
   if 11 - 11: I1ii11iIi11i - I1ii11iIi11i . ooOoO0o * Oo0Ooo + I1Ii111
   for OOOo0 in self . rloc_set :
    if ( OOOo0 . translated_port != 0 ) : break
    if 59 - 59: iII111i - OOooOOo - OoO0O00 . I1IiiI % o0oOOo0O0Ooo + iII111i
    if 10 - 10: iIii1I11I1II1 - Ii1I
  if ( OOOo0 != None ) : OOOo0 . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 84 - 84: iII111i
  if 21 - 21: i11iIiiIii
 def rtrs_in_rloc_set ( self ) :
  for OOOo0 in self . rloc_set :
   if ( OOOo0 . is_rtr ( ) ) : return ( True )
   if 30 - 30: OoO0O00 + OoooooooOO
  return ( False )
  if 98 - 98: I1ii11iIi11i % I1IiiI
  if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
 def add_recent_source ( self , source ) :
  self . recent_sources [ source . print_address ( ) ] = lisp_get_timestamp ( )
  if 66 - 66: IiII
  if 56 - 56: oO0o + OoooooooOO
 def find_rtr_rloc ( self ) :
  if 75 - 75: O0 % Ii1I
  if 47 - 47: OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
  if 23 - 23: iII111i / iIii1I11I1II1
  if 5 - 5: O0
  if 64 - 64: i1IIi * i1IIi . iII111i - O0 - oO0o % OoooooooOO
  if 14 - 14: Ii1I % OoO0O00 % I1Ii111 * O0
  if 8 - 8: I1IiiI - i11iIiiIii * I1IiiI
  for OOOo0 in self . rloc_set :
   if ( OOOo0 . is_rtr ( ) and OOOo0 . up_state ( ) ) :
    if ( OOOo0 . stats . packet_count <= 4 ) : return ( OOOo0 )
    if 6 - 6: O0 - OoOoOO00 - i11iIiiIii / iII111i
    if 63 - 63: OOooOOo
  return ( None )
  if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
  if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
  if 96 - 96: iIii1I11I1II1 * II111iiii . iIii1I11I1II1
  if 13 - 13: Ii1I - OoOoOO00 . Ii1I
class lisp_dynamic_eid ( object ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 7 - 7: Ii1I - I11i / I1ii11iIi11i + iII111i
  if 47 - 47: I11i * IiII / oO0o - OoooooooOO . OoooooooOO / I11i
 def get_timeout ( self , interface ) :
  try :
   o0OOOO0O00000O = lisp_myinterfaces [ interface ]
   self . timeout = o0OOOO0O00000O . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 34 - 34: Oo0Ooo . O0 + OoO0O00 * OoOoOO00
   if 48 - 48: iIii1I11I1II1 + O0 * I11i * i11iIiiIii . Ii1I / i1IIi
   if 48 - 48: i1IIi % iIii1I11I1II1 + I1IiiI - OoOoOO00 % I11i . I1Ii111
   if 66 - 66: I1Ii111 * i11iIiiIii + I1IiiI % II111iiii
class lisp_group_mapping ( object ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 47 - 47: II111iiii % o0oOOo0O0Ooo
  if 26 - 26: I1ii11iIi11i / I11i / Oo0Ooo / i1IIi + O0 * ooOoO0o
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 53 - 53: IiII / II111iiii / oO0o % O0 / I1Ii111
  if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
  if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
  if 45 - 45: OOooOOo - OOooOOo % iII111i - IiII . O0
  if 6 - 6: iIii1I11I1II1 * II111iiii / O0 % IiII - I1Ii111
  if 64 - 64: ooOoO0o
  if 28 - 28: i11iIiiIii - IiII * I1ii11iIi11i + IiII * iII111i
  if 75 - 75: o0oOOo0O0Ooo * OoOoOO00 % I1ii11iIi11i + OOooOOo . II111iiii
  if 12 - 12: ooOoO0o
  if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
def lisp_is_group_more_specific ( group_str , group_mapping ) :
 Ii1ii11iIi1 = group_mapping . group_prefix
 iII1I1i = lisp_address ( LISP_AFI_NONE , group_str , 0 , Ii1ii11iIi1 . instance_id )
 if ( iII1I1i . afi != Ii1ii11iIi1 . afi ) : return ( - 1 )
 if 53 - 53: II111iiii + Ii1I + i11iIiiIii
 if ( iII1I1i . is_more_specific ( Ii1ii11iIi1 ) ) : return ( Ii1ii11iIi1 . mask_len )
 return ( - 1 )
 if 21 - 21: I1Ii111 + Ii1I
 if 30 - 30: IiII + I1Ii111
 if 36 - 36: I1IiiI + I11i
 if 91 - 91: II111iiii
 if 52 - 52: o0oOOo0O0Ooo . O0 % I11i . iIii1I11I1II1 % iIii1I11I1II1 / I1Ii111
 if 18 - 18: Ii1I * I1ii11iIi11i % I11i
 if 50 - 50: Ii1I . I1ii11iIi11i + iIii1I11I1II1 * i11iIiiIii . iII111i
def lisp_lookup_group ( group ) :
 Ooo0i11II1IIIIi = None
 for iI1IIIi1iIii1 in list ( lisp_group_mapping_list . values ( ) ) :
  i111iii1i1 = lisp_is_group_more_specific ( group , iI1IIIi1iIii1 )
  if ( i111iii1i1 == - 1 ) : continue
  if ( Ooo0i11II1IIIIi == None or i111iii1i1 > Ooo0i11II1IIIIi . group_prefix . mask_len ) : Ooo0i11II1IIIIi = iI1IIIi1iIii1
  if 64 - 64: OoOoOO00
 return ( Ooo0i11II1IIIIi )
 if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
 if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 71 - 71: ooOoO0o
class lisp_site ( object ) :
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
  if 35 - 35: OoOoOO00
  if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
  if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
class lisp_site_eid ( object ) :
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
  if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
  if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 89 - 89: iIii1I11I1II1 . ooOoO0o
  if 82 - 82: OoOoOO00 - II111iiii . OoO0O00 * ooOoO0o
 def print_flags ( self , html ) :
  if ( html == False ) :
   ooOo0O0O0oOO0 = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # iII111i / oO0o + O0 + I11i . o0oOOo0O0Ooo
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   Ii1i111i = self . print_flags ( False )
   Ii1i111i = Ii1i111i . split ( "-" )
   ooOo0O0O0oOO0 = ""
   for i111 in Ii1i111i :
    IIiI1IiI1I1 = lisp_site_flags [ i111 . upper ( ) ]
    IIiI1IiI1I1 = IIiI1IiI1I1 . format ( "" if i111 . isupper ( ) else "not " )
    ooOo0O0O0oOO0 += lisp_span ( i111 , IIiI1IiI1I1 )
    if ( i111 . lower ( ) != "n" ) : ooOo0O0O0oOO0 += "-"
    if 37 - 37: oO0o / iII111i
    if 58 - 58: OoO0O00 / OoOoOO00 - Oo0Ooo + OoOoOO00
  return ( ooOo0O0O0oOO0 )
  if 8 - 8: II111iiii % IiII - IiII + Oo0Ooo . iII111i
  if 90 - 90: OOooOOo . ooOoO0o * oO0o % ooOoO0o / o0oOOo0O0Ooo
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 25 - 25: i11iIiiIii % o0oOOo0O0Ooo % OoO0O00 - I11i
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 18 - 18: iII111i
  if 9 - 9: I1Ii111 . oO0o . OoO0O00 / IiII - oO0o / oO0o
 def build_sort_key ( self ) :
  iiIiiI1 = lisp_cache ( )
  OoOO0oo0OOOO , III11II111 = iiIiiI1 . build_key ( self . eid )
  oo0OooOOo0oO = ""
  if ( self . group . is_null ( ) == False ) :
   iIIiIiI1 , oo0OooOOo0oO = iiIiiI1 . build_key ( self . group )
   oo0OooOOo0oO = "-" + oo0OooOOo0oO [ 0 : 12 ] + "-" + str ( iIIiIiI1 ) + "-" + oo0OooOOo0oO [ 12 : : ]
   if 48 - 48: O0
  III11II111 = III11II111 [ 0 : 12 ] + "-" + str ( OoOO0oo0OOOO ) + "-" + III11II111 [ 12 : : ] + oo0OooOOo0oO
  del ( iiIiiI1 )
  return ( III11II111 )
  if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
  if 84 - 84: i11iIiiIii . OoooooooOO
 def merge_in_site_eid ( self , child ) :
  O00o00ooo0Ooo = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   O00o00ooo0Ooo = self . merge_rles_in_site_eid ( )
   if 80 - 80: oO0o . oO0o
   if 64 - 64: I1IiiI + oO0o . I1ii11iIi11i
   if 23 - 23: OoOoOO00
   if 98 - 98: o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I % I1IiiI
   if 19 - 19: I1Ii111 / O0 % o0oOOo0O0Ooo
   if 1 - 1: OoOoOO00 / I11i
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 43 - 43: o0oOOo0O0Ooo - i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
  return ( O00o00ooo0Ooo )
  if 69 - 69: i11iIiiIii - iIii1I11I1II1
  if 40 - 40: I1IiiI / oO0o + ooOoO0o
 def copy_rloc_records ( self ) :
  OO00o0oOoOo = [ ]
  for oO0O0oOOO0 in self . registered_rlocs :
   OO00o0oOoOo . append ( copy . deepcopy ( oO0O0oOOO0 ) )
   if 45 - 45: O0
  return ( OO00o0oOoOo )
  if 96 - 96: iII111i . i1IIi % o0oOOo0O0Ooo * iIii1I11I1II1 - iII111i - OoooooooOO
  if 13 - 13: i1IIi
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for ooo0OOO00 in list ( self . individual_registrations . values ( ) ) :
   if ( self . site_id != ooo0OOO00 . site_id ) : continue
   if ( ooo0OOO00 . registered == False ) : continue
   self . registered_rlocs += ooo0OOO00 . copy_rloc_records ( )
   if 68 - 68: I1ii11iIi11i . IiII + O0 % i1IIi + iIii1I11I1II1
   if 17 - 17: i1IIi - OOooOOo * ooOoO0o + i1IIi - ooOoO0o + I1ii11iIi11i
   if 28 - 28: iII111i
   if 18 - 18: I1Ii111
   if 29 - 29: i1IIi - I1IiiI / i1IIi
   if 64 - 64: IiII
   if 69 - 69: OOooOOo . I1IiiI
   if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
  OO00o0oOoOo = [ ]
  for oO0O0oOOO0 in self . registered_rlocs :
   if ( oO0O0oOOO0 . rloc . is_null ( ) or len ( OO00o0oOoOo ) == 0 ) :
    OO00o0oOoOo . append ( oO0O0oOOO0 )
    continue
    if 22 - 22: iII111i % I11i % O0 - I11i
   for O0Oo0 in OO00o0oOoOo :
    if ( O0Oo0 . rloc . is_null ( ) ) : continue
    if ( oO0O0oOOO0 . rloc . is_exact_match ( O0Oo0 . rloc ) ) :
     if ( oO0O0oOOO0 . rloc_name == O0Oo0 . rloc_name ) : break
     if 18 - 18: iII111i / OoooooooOO + o0oOOo0O0Ooo
     if 51 - 51: Ii1I
   if ( O0Oo0 == OO00o0oOoOo [ - 1 ] ) : OO00o0oOoOo . append ( oO0O0oOOO0 )
   if 23 - 23: o0oOOo0O0Ooo / iII111i % oO0o
  self . registered_rlocs = OO00o0oOoOo
  if 62 - 62: Oo0Ooo + I1Ii111 . I1IiiI
  if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
  if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
  if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 97 - 97: iIii1I11I1II1 * I1Ii111
  if 39 - 39: I1Ii111 . II111iiii
 def merge_rles_in_site_eid ( self ) :
  if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
  if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
  if 34 - 34: I1IiiI
  if 56 - 56: Ii1I
  ooooO = { }
  for oO0O0oOOO0 in self . registered_rlocs :
   if ( oO0O0oOOO0 . rle == None ) : continue
   for iIiII in oO0O0oOOO0 . rle . rle_nodes :
    if ( iIiII . rloc_name == None ) : continue
    OOOo = iIiII . address . print_address_no_iid ( ) + iIiII . rloc_name
    if 3 - 3: iIii1I11I1II1 - I1Ii111 . iII111i / ooOoO0o
    ooooO [ OOOo ] = iIiII . address
    if 86 - 86: i11iIiiIii % o0oOOo0O0Ooo % IiII - I1ii11iIi11i
   break
   if 75 - 75: Ii1I / oO0o . OoO0O00
   if 29 - 29: i1IIi + oO0o - I1IiiI * I1Ii111 + oO0o - Ii1I
   if 58 - 58: i11iIiiIii . o0oOOo0O0Ooo - i1IIi - I1IiiI * i1IIi % I1Ii111
   if 37 - 37: I11i
   if 61 - 61: OoooooooOO % iIii1I11I1II1 % O0 % I1Ii111 / Oo0Ooo . I1IiiI
  self . merge_rlocs_in_site_eid ( )
  if 20 - 20: ooOoO0o - I1Ii111
  if 97 - 97: O0
  if 56 - 56: Ii1I * I1IiiI * ooOoO0o
  if 39 - 39: iII111i % Ii1I * iIii1I11I1II1 - Ii1I - I1Ii111
  if 60 - 60: i11iIiiIii + i11iIiiIii - OoooooooOO + OoooooooOO
  if 5 - 5: o0oOOo0O0Ooo
  if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
  if 12 - 12: Oo0Ooo . o0oOOo0O0Ooo - i1IIi - oO0o % IiII . I11i
  IiII1i11i1I = [ ]
  for oO0O0oOOO0 in self . registered_rlocs :
   if ( self . registered_rlocs . index ( oO0O0oOOO0 ) == 0 ) :
    IiII1i11i1I . append ( oO0O0oOOO0 )
    continue
    if 64 - 64: O0 - iII111i
   if ( oO0O0oOOO0 . rle == None ) : IiII1i11i1I . append ( oO0O0oOOO0 )
   if 82 - 82: O0
  self . registered_rlocs = IiII1i11i1I
  if 37 - 37: I1Ii111
  if 98 - 98: iII111i - OoOoOO00 / I1Ii111 . OOooOOo - OOooOOo - ooOoO0o
  if 84 - 84: OOooOOo * ooOoO0o / O0
  if 96 - 96: I11i . I11i % II111iiii
  if 14 - 14: iII111i / OoooooooOO
  if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
  if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
  IIiiiI = lisp_rle ( "" )
  OO00o = { }
  o0oo0 = None
  for ooo0OOO00 in list ( self . individual_registrations . values ( ) ) :
   if ( ooo0OOO00 . registered == False ) : continue
   oO000oo = ooo0OOO00 . registered_rlocs [ 0 ] . rle
   if ( oO000oo == None ) : continue
   if 49 - 49: IiII . Oo0Ooo / II111iiii
   o0oo0 = ooo0OOO00 . registered_rlocs [ 0 ] . rloc_name
   for i1iIiiiIIi1 in oO000oo . rle_nodes :
    OOOo = i1iIiiiIIi1 . address . print_address_no_iid ( ) + o0oo0
    if ( OOOo in OO00o ) : break
    if 94 - 94: IiII * I1Ii111
    iIiII = lisp_rle_node ( )
    iIiII . address . copy_address ( i1iIiiiIIi1 . address )
    iIiII . level = i1iIiiiIIi1 . level
    iIiII . rloc_name = o0oo0
    IIiiiI . rle_nodes . append ( iIiII )
    OO00o [ OOOo ] = i1iIiiiIIi1 . address
    if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
    if 91 - 91: OoO0O00
    if 8 - 8: oO0o
    if 96 - 96: IiII
    if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
    if 26 - 26: o0oOOo0O0Ooo . i1IIi
  if ( len ( IIiiiI . rle_nodes ) == 0 ) : IIiiiI = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = IIiiiI
   if ( o0oo0 ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 62 - 62: IiII * I1ii11iIi11i % iIii1I11I1II1 / II111iiii - OoO0O00
   if 52 - 52: iII111i . I11i - I11i + oO0o + iIii1I11I1II1
   if 83 - 83: I11i * iIii1I11I1II1 + OoOoOO00
   if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
   if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
  if ( list ( ooooO . keys ( ) ) == list ( OO00o . keys ( ) ) ) : return ( False )
  if 100 - 100: II111iiii / Oo0Ooo / iII111i / OOooOOo
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # iIii1I11I1II1 . Oo0Ooo + I1Ii111 / ooOoO0o * o0oOOo0O0Ooo % i1IIi
 list ( ooooO . keys ( ) ) , list ( OO00o . keys ( ) ) ) )
  if 13 - 13: i11iIiiIii * II111iiii
  return ( True )
  if 75 - 75: OoooooooOO * OOooOOo
  if 64 - 64: iII111i % Ii1I . I1ii11iIi11i + iII111i * I11i . i11iIiiIii
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   IiII1I1 = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( IiII1I1 == None ) :
    IiII1I1 = lisp_site_eid ( self . site )
    IiII1I1 . eid . copy_address ( self . group )
    IiII1I1 . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , IiII1I1 )
    if 4 - 4: Ii1I . OoOoOO00
    if 84 - 84: iIii1I11I1II1 - Oo0Ooo . i1IIi / O0 - I1ii11iIi11i
    if 34 - 34: OoO0O00 * iIii1I11I1II1 . iIii1I11I1II1
    if 39 - 39: o0oOOo0O0Ooo
    if 29 - 29: Oo0Ooo . Oo0Ooo * OoO0O00 % Ii1I - ooOoO0o
    IiII1I1 . parent_for_more_specifics = self . parent_for_more_specifics
    if 67 - 67: I1IiiI % O0 + I1IiiI * I1Ii111 * OoOoOO00 * II111iiii
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( IiII1I1 . group )
   IiII1I1 . add_source_entry ( self )
   if 79 - 79: I1IiiI
   if 37 - 37: I1Ii111 + Ii1I
   if 50 - 50: i11iIiiIii
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   IiII1I1 = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( IiII1I1 == None ) : return
   if 57 - 57: O0 * i1IIi - I1IiiI
   ooo0OOO00 = IiII1I1 . lookup_source_cache ( self . eid , True )
   if ( ooo0OOO00 == None ) : return
   if 48 - 48: IiII / iIii1I11I1II1
   if ( IiII1I1 . source_cache == None ) : return
   if 20 - 20: oO0o / OoooooooOO
   IiII1I1 . source_cache . delete_cache ( self . eid )
   if ( IiII1I1 . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 95 - 95: Oo0Ooo . i11iIiiIii
    if 50 - 50: iII111i . i11iIiiIii - i1IIi
    if 24 - 24: i11iIiiIii % iII111i . oO0o
    if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 34 - 34: I1ii11iIi11i % ooOoO0o / II111iiii * O0 % OOooOOo
  if 9 - 9: I1ii11iIi11i / I1ii11iIi11i - OOooOOo . iIii1I11I1II1
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 33 - 33: I1IiiI + oO0o % I1IiiI / iII111i - ooOoO0o - i11iIiiIii
  if 39 - 39: i11iIiiIii / oO0o
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
  if 87 - 87: I1IiiI / Ii1I
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 54 - 54: OoooooooOO / Ii1I
  if 26 - 26: o0oOOo0O0Ooo + OoO0O00
 def inherit_from_ams_parent ( self ) :
  i1Iii = self . parent_for_more_specifics
  if ( i1Iii == None ) : return
  self . force_proxy_reply = i1Iii . force_proxy_reply
  self . force_nat_proxy_reply = i1Iii . force_nat_proxy_reply
  self . force_ttl = i1Iii . force_ttl
  self . pitr_proxy_reply_drop = i1Iii . pitr_proxy_reply_drop
  self . proxy_reply_action = i1Iii . proxy_reply_action
  self . echo_nonce_capable = i1Iii . echo_nonce_capable
  self . policy = i1Iii . policy
  self . require_signature = i1Iii . require_signature
  self . encrypt_json = i1Iii . encrypt_json
  if 59 - 59: Ii1I * IiII
  if 64 - 64: ooOoO0o . Oo0Ooo - OoOoOO00
 def rtrs_in_rloc_set ( self ) :
  for oO0O0oOOO0 in self . registered_rlocs :
   if ( oO0O0oOOO0 . is_rtr ( ) ) : return ( True )
   if 66 - 66: OoOoOO00
  return ( False )
  if 83 - 83: OOooOOo . IiII
  if 98 - 98: i11iIiiIii
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for oO0O0oOOO0 in self . registered_rlocs :
   if ( oO0O0oOOO0 . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( oO0O0oOOO0 . is_rtr ( ) ) : return ( True )
   if 74 - 74: iIii1I11I1II1 * O0 + OOooOOo . o0oOOo0O0Ooo
  return ( False )
  if 17 - 17: I1Ii111
  if 59 - 59: OoOoOO00 . OoOoOO00 * iII111i - Ii1I . i11iIiiIii
 def is_rloc_in_rloc_set ( self , rloc ) :
  for oO0O0oOOO0 in self . registered_rlocs :
   if ( oO0O0oOOO0 . rle ) :
    for IIiiiI in oO0O0oOOO0 . rle . rle_nodes :
     if ( IIiiiI . address . is_exact_match ( rloc ) ) : return ( True )
     if 68 - 68: iII111i
     if 68 - 68: I1Ii111 - OoO0O00 % OoO0O00 % OOooOOo - OoO0O00
   if ( oO0O0oOOO0 . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
  return ( False )
  if 59 - 59: iII111i
  if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
  for oO0O0oOOO0 in prev_rloc_set :
   oO0oOO0O000 = oO0O0oOOO0 . rloc
   if ( self . is_rloc_in_rloc_set ( oO0oOO0O000 ) == False ) : return ( False )
   if 65 - 65: I1Ii111 + OOooOOo
  return ( True )
  if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
  if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
  if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
class lisp_mr ( object ) :
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
   if 77 - 77: ooOoO0o % I1IiiI
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 26 - 26: o0oOOo0O0Ooo
  if 72 - 72: I1IiiI
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 90 - 90: ooOoO0o
  try :
   O00Oo = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   Oo0o0oi1 = O00Oo [ 2 ]
  except :
   return
   if 32 - 32: OoOoOO00 - iII111i % oO0o / I1ii11iIi11i - o0oOOo0O0Ooo
   if 52 - 52: Ii1I / OoooooooOO % i11iIiiIii + iII111i
   if 59 - 59: Ii1I / o0oOOo0O0Ooo / oO0o + iII111i * I1ii11iIi11i - o0oOOo0O0Ooo
   if 70 - 70: O0 / I1ii11iIi11i + ooOoO0o . OoO0O00 - OoO0O00 / i11iIiiIii
   if 1 - 1: iIii1I11I1II1 % I1ii11iIi11i
   if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
  if ( len ( Oo0o0oi1 ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
   if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
  OOOo = Oo0o0oi1 [ self . a_record_index ]
  if ( OOOo != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( OOOo )
   self . insert_mr ( )
   if 67 - 67: i1IIi * I1Ii111 * O0
   if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
   if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
   if 18 - 18: I1ii11iIi11i - i1IIi - IiII * II111iiii % I1Ii111 . II111iiii
   if 80 - 80: oO0o + OoO0O00 + o0oOOo0O0Ooo . OoOoOO00
   if 75 - 75: i11iIiiIii
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 58 - 58: iII111i
  for OOOo in Oo0o0oi1 [ 1 : : ] :
   oO = lisp_address ( LISP_AFI_NONE , OOOo , 0 , 0 )
   o0O0oOoOO = lisp_get_map_resolver ( oO , None )
   if ( o0O0oOoOO != None and o0O0oOoOO . a_record_index == Oo0o0oi1 . index ( OOOo ) ) :
    continue
    if 48 - 48: OoO0O00 * OOooOOo / iII111i
   o0O0oOoOO = lisp_mr ( OOOo , None , None )
   o0O0oOoOO . a_record_index = Oo0o0oi1 . index ( OOOo )
   o0O0oOoOO . dns_name = self . dns_name
   o0O0oOoOO . last_dns_resolve = lisp_get_timestamp ( )
   if 90 - 90: I1IiiI * i11iIiiIii . OOooOOo / o0oOOo0O0Ooo
   if 82 - 82: Oo0Ooo
   if 50 - 50: I1Ii111 * OOooOOo * OoOoOO00 / OoooooooOO % iII111i
   if 80 - 80: I1Ii111
   if 35 - 35: Ii1I . O0 % i11iIiiIii * oO0o - OoooooooOO
  O0O0o0oooOO0o = [ ]
  for o0O0oOoOO in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( self . dns_name != o0O0oOoOO . dns_name ) : continue
   oO = o0O0oOoOO . map_resolver . print_address_no_iid ( )
   if ( oO in Oo0o0oi1 ) : continue
   O0O0o0oooOO0o . append ( o0O0oOoOO )
   if 90 - 90: O0
  for o0O0oOoOO in O0O0o0oooOO0o : o0O0oOoOO . delete_mr ( )
  if 69 - 69: I1ii11iIi11i * oO0o - I1Ii111 - OOooOOo / I1IiiI
  if 33 - 33: I1Ii111 + oO0o
 def insert_mr ( self ) :
  III11II111 = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ III11II111 ] = self
  if 39 - 39: I11i * OoooooooOO . Oo0Ooo + IiII + ooOoO0o
  if 35 - 35: o0oOOo0O0Ooo % OOooOOo / I11i % Ii1I * IiII + i1IIi
 def delete_mr ( self ) :
  III11II111 = self . mr_name + self . map_resolver . print_address ( )
  if ( III11II111 not in lisp_map_resolvers_list ) : return
  lisp_map_resolvers_list . pop ( III11II111 )
  if 78 - 78: II111iiii + I1IiiI * Ii1I / Oo0Ooo
  if 37 - 37: O0 / iIii1I11I1II1 . OoO0O00
  if 43 - 43: I1IiiI % OoOoOO00 * O0 + o0oOOo0O0Ooo
class lisp_ddt_root ( object ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 97 - 97: iIii1I11I1II1 + O0
  if 41 - 41: OoOoOO00 - II111iiii
  if 46 - 46: OOooOOo
class lisp_referral ( object ) :
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
  if 73 - 73: iII111i - IiII + II111iiii
  if 58 - 58: Oo0Ooo % I1IiiI
 def print_referral ( self , eid_indent , referral_indent ) :
  O00o = lisp_print_elapsed ( self . uptime )
  I111 = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , O00o ,
  # IiII . II111iiii % iIii1I11I1II1 - I1IiiI % i11iIiiIii
 I111 , len ( self . referral_set ) ) )
  if 5 - 5: I1ii11iIi11i % OOooOOo . I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . OoOoOO00
  for IiIiii1iIii in list ( self . referral_set . values ( ) ) :
   IiIiii1iIii . print_ref_node ( referral_indent )
   if 73 - 73: I1ii11iIi11i * i1IIi * Oo0Ooo / O0
   if 1 - 1: iII111i * OOooOOo + II111iiii / Ii1I . I1ii11iIi11i
   if 61 - 61: oO0o % OoOoOO00 % ooOoO0o . I1Ii111 / OoO0O00
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 21 - 21: IiII
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 52 - 52: II111iiii * o0oOOo0O0Ooo
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 95 - 95: I1Ii111 - OoooooooOO
  if 99 - 99: OoooooooOO % IiII . I11i + OoooooooOO
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 57 - 57: Ii1I / I1IiiI * i1IIi
  if 21 - 21: I11i . O0 * OoooooooOO + ooOoO0o * oO0o % i11iIiiIii
 def print_ttl ( self ) :
  OO0ooo00o = self . referral_ttl
  if ( OO0ooo00o < 60 ) : return ( str ( OO0ooo00o ) + " secs" )
  if 30 - 30: ooOoO0o * I1Ii111 + OoO0O00
  if ( ( OO0ooo00o % 60 ) == 0 ) :
   OO0ooo00o = str ( old_div ( OO0ooo00o , 60 ) ) + " mins"
  else :
   OO0ooo00o = str ( OO0ooo00o ) + " secs"
   if 30 - 30: Ii1I / iII111i * Ii1I
  return ( OO0ooo00o )
  if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
  if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # I11i + Ii1I / ooOoO0o . i11iIiiIii / O0
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 88 - 88: OoooooooOO / Oo0Ooo / oO0o
  if 99 - 99: I1Ii111 % OoOoOO00 % IiII - Ii1I
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   OoooOO0 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( OoooOO0 == None ) :
    OoooOO0 = lisp_referral ( )
    OoooOO0 . eid . copy_address ( self . group )
    OoooOO0 . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , OoooOO0 )
    if 79 - 79: ooOoO0o + Oo0Ooo
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OoooOO0 . group )
   OoooOO0 . add_source_entry ( self )
   if 80 - 80: OoOoOO00 % OoO0O00 . OoO0O00 * OoO0O00 * O0
   if 18 - 18: II111iiii . o0oOOo0O0Ooo + OoO0O00
   if 69 - 69: OoO0O00 . ooOoO0o * ooOoO0o * iIii1I11I1II1
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   OoooOO0 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( OoooOO0 == None ) : return
   if 8 - 8: iII111i . oO0o . OOooOOo + iII111i . Ii1I
   o0o0oOo00Oo = OoooOO0 . lookup_source_cache ( self . eid , True )
   if ( o0o0oOo00Oo == None ) : return
   if 46 - 46: OoO0O00
   OoooOO0 . source_cache . delete_cache ( self . eid )
   if ( OoooOO0 . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 21 - 21: iIii1I11I1II1 - iII111i
    if 15 - 15: O0 + iII111i + i11iIiiIii
    if 31 - 31: iIii1I11I1II1 * iIii1I11I1II1 . I11i
    if 52 - 52: i11iIiiIii / oO0o / IiII
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 84 - 84: I11i . oO0o + ooOoO0o
  if 75 - 75: I1Ii111
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
  if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
  if 73 - 73: ooOoO0o + O0 - I11i . I1IiiI + OOooOOo
class lisp_referral_node ( object ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 36 - 36: I11i % OoO0O00 * OoOoOO00 - I1Ii111
  if 16 - 16: ooOoO0o % OOooOOo . OoO0O00 % II111iiii . iIii1I11I1II1
 def print_ref_node ( self , indent ) :
  Oo0OO0000oooo = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , Oo0OO0000oooo ,
  # OoOoOO00 - oO0o
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 27 - 27: OoOoOO00 * I11i
  if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
  if 70 - 70: I1IiiI . ooOoO0o / I11i / OoO0O00
class lisp_ms ( object ) :
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
   self . xtr_id = list ( lisp_map_servers_list . values ( ) ) [ 0 ] . xtr_id
   if 40 - 40: oO0o % iIii1I11I1II1 * iIii1I11I1II1 / Oo0Ooo * OoO0O00
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
   if 61 - 61: OOooOOo
   if 80 - 80: I1ii11iIi11i
   if 6 - 6: I1ii11iIi11i + OOooOOo % ooOoO0o
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 65 - 65: iIii1I11I1II1 % i1IIi / I1IiiI / oO0o % ooOoO0o / I11i
  try :
   O00Oo = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   Oo0o0oi1 = O00Oo [ 2 ]
  except :
   return
   if 2 - 2: I1ii11iIi11i
   if 90 - 90: II111iiii * I1Ii111 . ooOoO0o - I1ii11iIi11i % I11i * o0oOOo0O0Ooo
   if 85 - 85: iIii1I11I1II1
   if 76 - 76: i11iIiiIii % I1IiiI / I11i
   if 42 - 42: o0oOOo0O0Ooo . I1IiiI + I11i . OoOoOO00 - O0 / Ii1I
   if 66 - 66: IiII + OoOoOO00 + I1IiiI + i1IIi + OoooooooOO % I1IiiI
  if ( len ( Oo0o0oi1 ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 80 - 80: iII111i / O0 % OoooooooOO / Oo0Ooo
   if 75 - 75: ooOoO0o
  OOOo = Oo0o0oi1 [ self . a_record_index ]
  if ( OOOo != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( OOOo )
   self . insert_ms ( )
   if 72 - 72: oO0o . OoooooooOO % ooOoO0o % OoO0O00 * oO0o * OoO0O00
   if 14 - 14: I11i / I11i
   if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
   if 93 - 93: oO0o / ooOoO0o - I1Ii111
   if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
   if 26 - 26: O0 + Oo0Ooo
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 30 - 30: IiII
  for OOOo in Oo0o0oi1 [ 1 : : ] :
   oO = lisp_address ( LISP_AFI_NONE , OOOo , 0 , 0 )
   IiiiiiOoO0 = lisp_get_map_server ( oO )
   if ( IiiiiiOoO0 != None and IiiiiiOoO0 . a_record_index == Oo0o0oi1 . index ( OOOo ) ) :
    continue
    if 6 - 6: O0
   IiiiiiOoO0 = copy . deepcopy ( self )
   IiiiiiOoO0 . map_server . store_address ( OOOo )
   IiiiiiOoO0 . a_record_index = Oo0o0oi1 . index ( OOOo )
   IiiiiiOoO0 . last_dns_resolve = lisp_get_timestamp ( )
   IiiiiiOoO0 . insert_ms ( )
   if 92 - 92: I11i
   if 76 - 76: I11i / iIii1I11I1II1 - i11iIiiIii / O0 / O0
   if 19 - 19: Ii1I . I1IiiI - i1IIi * ooOoO0o . iIii1I11I1II1
   if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
   if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
  O0O0o0oooOO0o = [ ]
  for IiiiiiOoO0 in list ( lisp_map_servers_list . values ( ) ) :
   if ( self . dns_name != IiiiiiOoO0 . dns_name ) : continue
   oO = IiiiiiOoO0 . map_server . print_address_no_iid ( )
   if ( oO in Oo0o0oi1 ) : continue
   O0O0o0oooOO0o . append ( IiiiiiOoO0 )
   if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
  for IiiiiiOoO0 in O0O0o0oooOO0o : IiiiiiOoO0 . delete_ms ( )
  if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
  if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
 def insert_ms ( self ) :
  III11II111 = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ III11II111 ] = self
  if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
  if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
 def delete_ms ( self ) :
  III11II111 = self . ms_name + self . map_server . print_address ( )
  if ( III11II111 not in lisp_map_servers_list ) : return
  lisp_map_servers_list . pop ( III11II111 )
  if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
  if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
  if 83 - 83: OOooOOo . ooOoO0o / IiII
class lisp_interface ( object ) :
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
  if 80 - 80: I1Ii111 . I11i - I11i + I1ii11iIi11i
  if 42 - 42: I11i / IiII % O0 - Oo0Ooo
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 33 - 33: I1Ii111
  if 1 - 1: IiII - iIii1I11I1II1 % OoooooooOO
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 1 - 1: o0oOOo0O0Ooo - i11iIiiIii + I11i
  if 47 - 47: O0 + IiII + ooOoO0o + OOooOOo / OoOoOO00
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 31 - 31: oO0o * iII111i % OoOoOO00
  if 80 - 80: ooOoO0o % I1ii11iIi11i % I11i . I1Ii111
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 3 - 3: ooOoO0o - Oo0Ooo
  if 2 - 2: iII111i . iII111i
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 77 - 77: OOooOOo
  if 74 - 74: O0
 def set_socket ( self , device ) :
  o0O0o0000o0O0 = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  o0O0o0000o0O0 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   o0O0o0000o0O0 . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   o0O0o0000o0O0 . close ( )
   o0O0o0000o0O0 = None
   if 86 - 86: OoOoOO00
  self . raw_socket = o0O0o0000o0O0
  if 4 - 4: OoooooooOO * OoO0O00
  if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
 def set_bridge_socket ( self , device ) :
  o0O0o0000o0O0 = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   o0O0o0000o0O0 = o0O0o0000o0O0 . bind ( ( device , 0 ) )
   self . bridge_socket = o0O0o0000o0O0
  except :
   return
   if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
   if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
   if 6 - 6: I1IiiI - OoOoOO00
   if 63 - 63: OOooOOo - oO0o * I1IiiI
class lisp_datetime ( object ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 60 - 60: II111iiii - Oo0Ooo
  if 43 - 43: I1IiiI - IiII - OOooOOo
 def valid_datetime ( self ) :
  i1I1 = self . datetime_name
  if ( i1I1 . find ( ":" ) == - 1 ) : return ( False )
  if ( i1I1 . find ( "-" ) == - 1 ) : return ( False )
  IiiiI1I , o0OoOoo0OO , IiIiII1i1iIiI , time = i1I1 [ 0 : 4 ] , i1I1 [ 5 : 7 ] , i1I1 [ 8 : 10 ] , i1I1 [ 11 : : ]
  if 20 - 20: I11i / I1Ii111 % iIii1I11I1II1 % Ii1I . I1ii11iIi11i % oO0o
  if ( ( IiiiI1I + o0OoOoo0OO + IiIiII1i1iIiI ) . isdigit ( ) == False ) : return ( False )
  if ( o0OoOoo0OO < "01" and o0OoOoo0OO > "12" ) : return ( False )
  if ( IiIiII1i1iIiI < "01" and IiIiII1i1iIiI > "31" ) : return ( False )
  if 82 - 82: OoO0O00 * OoOoOO00 - IiII + Oo0Ooo - i1IIi
  iI1I1iIii1II , o0OO , ii1iii = time . split ( ":" )
  if 16 - 16: II111iiii * OoooooooOO . I1IiiI * O0 * iIii1I11I1II1
  if ( ( iI1I1iIii1II + o0OO + ii1iii ) . isdigit ( ) == False ) : return ( False )
  if ( iI1I1iIii1II < "00" and iI1I1iIii1II > "23" ) : return ( False )
  if ( o0OO < "00" and o0OO > "59" ) : return ( False )
  if ( ii1iii < "00" and ii1iii > "59" ) : return ( False )
  return ( True )
  if 72 - 72: II111iiii
  if 26 - 26: Oo0Ooo
 def parse_datetime ( self ) :
  iIooo0O = self . datetime_name
  iIooo0O = iIooo0O . replace ( "-" , "" )
  iIooo0O = iIooo0O . replace ( ":" , "" )
  self . datetime = int ( iIooo0O )
  if 61 - 61: iII111i + oO0o * I1IiiI * Ii1I - Ii1I
  if 74 - 74: iII111i + OOooOOo * IiII * i11iIiiIii % I1ii11iIi11i - i1IIi
 def now ( self ) :
  Oo0OO0000oooo = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  Oo0OO0000oooo = lisp_datetime ( Oo0OO0000oooo )
  return ( Oo0OO0000oooo )
  if 43 - 43: OoOoOO00 . Oo0Ooo . IiII . IiII - ooOoO0o
  if 97 - 97: O0 % I1IiiI
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 69 - 69: ooOoO0o . OoooooooOO
  if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 88 - 88: i1IIi - OoOoOO00
  if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
 def past ( self ) :
  return ( self . future ( ) == False )
  if 7 - 7: Ii1I / iIii1I11I1II1
  if 36 - 36: iIii1I11I1II1 % i11iIiiIii
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
  if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
 def this_year ( self ) :
  IiI1i11i = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  Oo0OO0000oooo = str ( self . datetime ) [ 0 : 4 ]
  return ( Oo0OO0000oooo == IiI1i11i )
  if 88 - 88: iIii1I11I1II1 % O0 * IiII / iIii1I11I1II1 % I1Ii111
  if 77 - 77: OoO0O00 * O0 + OoOoOO00 % O0 * Ii1I . OOooOOo
 def this_month ( self ) :
  IiI1i11i = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  Oo0OO0000oooo = str ( self . datetime ) [ 0 : 6 ]
  return ( Oo0OO0000oooo == IiI1i11i )
  if 52 - 52: O0 / I1Ii111 + o0oOOo0O0Ooo . O0 . OoO0O00
  if 81 - 81: o0oOOo0O0Ooo - OoOoOO00 - Oo0Ooo * i11iIiiIii - Ii1I
 def today ( self ) :
  IiI1i11i = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  Oo0OO0000oooo = str ( self . datetime ) [ 0 : 8 ]
  return ( Oo0OO0000oooo == IiI1i11i )
  if 88 - 88: O0 * OoO0O00 * ooOoO0o / iII111i . oO0o
  if 96 - 96: IiII . I1Ii111 % ooOoO0o
  if 39 - 39: II111iiii - OoO0O00 % I1Ii111 + IiII - i11iIiiIii
  if 31 - 31: OoOoOO00 + Oo0Ooo / OoO0O00 - OOooOOo
  if 62 - 62: OoOoOO00
  if 48 - 48: OoooooooOO . i11iIiiIii * oO0o
class lisp_policy_match ( object ) :
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
  if 41 - 41: ooOoO0o
  if 89 - 89: i11iIiiIii . i11iIiiIii . IiII
class lisp_policy ( object ) :
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
  if 29 - 29: o0oOOo0O0Ooo * iIii1I11I1II1 . iIii1I11I1II1
  if 32 - 32: IiII - OoOoOO00
 def match_policy_map_request ( self , mr , srloc ) :
  for OOoO0o0OOo0 in self . match_clauses :
   o00oo = OOoO0o0OOo0 . source_eid
   oOOOooOOO = mr . source_eid
   if ( o00oo and oOOOooOOO and oOOOooOOO . is_more_specific ( o00oo ) == False ) : continue
   if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
   o00oo = OOoO0o0OOo0 . dest_eid
   oOOOooOOO = mr . target_eid
   if ( o00oo and oOOOooOOO and oOOOooOOO . is_more_specific ( o00oo ) == False ) : continue
   if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
   o00oo = OOoO0o0OOo0 . source_rloc
   oOOOooOOO = srloc
   if ( o00oo and oOOOooOOO and oOOOooOOO . is_more_specific ( o00oo ) == False ) : continue
   o0oOOO = OOoO0o0OOo0 . datetime_lower
   OOOOoOOoo0 = OOoO0o0OOo0 . datetime_upper
   if ( o0oOOO and OOOOoOOoo0 and o0oOOO . now_in_range ( OOOOoOOoo0 ) == False ) : continue
   return ( True )
   if 49 - 49: OoooooooOO
  return ( False )
  if 64 - 64: I11i * I1Ii111
  if 93 - 93: OoooooooOO . iIii1I11I1II1
 def set_policy_map_reply ( self ) :
  iiIIIoOoOO0oO = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( iiIIIoOoOO0oO ) : return ( None )
  if 53 - 53: I11i * OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
  OOOo0 = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   OOOo0 . rloc . copy_address ( self . set_rloc_address )
   OOOo = OOOo0 . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( OOOo ) )
   if 96 - 96: I1IiiI . oO0o % O0
  if ( self . set_rloc_record_name ) :
   OOOo0 . rloc_name = self . set_rloc_record_name
   OO0o = blue ( OOOo0 . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( OO0o ) )
   if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
  if ( self . set_geo_name ) :
   OOOo0 . geo_name = self . set_geo_name
   OO0o = OOOo0 . geo_name
   o0O0ooO0OoOo0OOO = "" if ( OO0o in lisp_geo_list ) else "(not configured)"
   if 74 - 74: i1IIi * i11iIiiIii - o0oOOo0O0Ooo
   lprint ( "Policy set-geo-name '{}' {}" . format ( OO0o , o0O0ooO0OoOo0OOO ) )
   if 62 - 62: iIii1I11I1II1 / oO0o - OoO0O00 * I1Ii111
  if ( self . set_elp_name ) :
   OOOo0 . elp_name = self . set_elp_name
   OO0o = OOOo0 . elp_name
   o0O0ooO0OoOo0OOO = "" if ( OO0o in lisp_elp_list ) else "(not configured)"
   if 1 - 1: I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * i11iIiiIii - OOooOOo % oO0o
   lprint ( "Policy set-elp-name '{}' {}" . format ( OO0o , o0O0ooO0OoOo0OOO ) )
   if 35 - 35: I1ii11iIi11i / II111iiii * OoO0O00 - i11iIiiIii / iII111i / o0oOOo0O0Ooo
  if ( self . set_rle_name ) :
   OOOo0 . rle_name = self . set_rle_name
   OO0o = OOOo0 . rle_name
   o0O0ooO0OoOo0OOO = "" if ( OO0o in lisp_rle_list ) else "(not configured)"
   if 39 - 39: II111iiii * iII111i
   lprint ( "Policy set-rle-name '{}' {}" . format ( OO0o , o0O0ooO0OoOo0OOO ) )
   if 7 - 7: OOooOOo + OoOoOO00 . II111iiii * OoO0O00 . I1IiiI * o0oOOo0O0Ooo
  if ( self . set_json_name ) :
   OOOo0 . json_name = self . set_json_name
   OO0o = OOOo0 . json_name
   o0O0ooO0OoOo0OOO = "" if ( OO0o in lisp_json_list ) else "(not configured)"
   if 62 - 62: I1ii11iIi11i / iIii1I11I1II1 + oO0o . II111iiii
   lprint ( "Policy set-json-name '{}' {}" . format ( OO0o , o0O0ooO0OoOo0OOO ) )
   if 65 - 65: Oo0Ooo % i1IIi * o0oOOo0O0Ooo * IiII
  return ( OOOo0 )
  if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
  if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 36 - 36: O0
  if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
  if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
class lisp_pubsub ( object ) :
 def __init__ ( self , itr , port , nonce , ttl , xtr_id ) :
  self . itr = itr
  self . port = port
  self . nonce = nonce
  self . uptime = lisp_get_timestamp ( )
  self . ttl = ttl
  self . xtr_id = xtr_id
  self . map_notify_count = 0
  self . eid_prefix = None
  if 21 - 21: i1IIi * iII111i + OoO0O00
  if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
 def add ( self , eid_prefix ) :
  self . eid_prefix = eid_prefix
  OO0ooo00o = self . ttl
  oO0OooO0o0 = eid_prefix . print_prefix ( )
  if ( oO0OooO0o0 not in lisp_pubsub_cache ) :
   lisp_pubsub_cache [ oO0OooO0o0 ] = { }
   if 85 - 85: OoooooooOO
  oo0ooo = lisp_pubsub_cache [ oO0OooO0o0 ]
  if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
  i11I1111iIII = "Add"
  if ( self . xtr_id in oo0ooo ) :
   i11I1111iIII = "Replace"
   del ( oo0ooo [ self . xtr_id ] )
   if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
  oo0ooo [ self . xtr_id ] = self
  if 9 - 9: iIii1I11I1II1 + Ii1I + I11i
  oO0OooO0o0 = green ( oO0OooO0o0 , False )
  ooo00 = red ( self . itr . print_address_no_iid ( ) , False )
  i1oO0o00oOo00oO = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( i11I1111iIII , oO0OooO0o0 ,
 ooo00 , i1oO0o00oOo00oO , OO0ooo00o ) )
  if 96 - 96: OoO0O00 + i11iIiiIii + OoO0O00
  if 7 - 7: i1IIi . I1IiiI
 def delete ( self , eid_prefix ) :
  oO0OooO0o0 = eid_prefix . print_prefix ( )
  ooo00 = red ( self . itr . print_address_no_iid ( ) , False )
  i1oO0o00oOo00oO = "0x" + lisp_hex_string ( self . xtr_id )
  if ( oO0OooO0o0 in lisp_pubsub_cache ) :
   oo0ooo = lisp_pubsub_cache [ oO0OooO0o0 ]
   if ( self . xtr_id in oo0ooo ) :
    oo0ooo . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( oO0OooO0o0 ,
 ooo00 , i1oO0o00oOo00oO ) )
    if 68 - 68: OoooooooOO
    if 91 - 91: IiII . ooOoO0o * I11i
    if 39 - 39: o0oOOo0O0Ooo + i11iIiiIii
    if 69 - 69: iIii1I11I1II1 . II111iiii
    if 36 - 36: I1IiiI * i1IIi + OoOoOO00
    if 63 - 63: OoOoOO00 - iII111i
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
class lisp_trace ( object ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 54 - 54: IiII + OoOoOO00 / II111iiii % i11iIiiIii . I1Ii111
  if 69 - 69: i1IIi + ooOoO0o + Ii1I
 def print_trace ( self ) :
  Oo0OoooOo = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( Oo0OoooOo ) )
  if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
  if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
 def encode ( self ) :
  iii1I = socket . htonl ( 0x90000000 )
  OO0Oo00OO0oo = struct . pack ( "II" , iii1I , 0 )
  OO0Oo00OO0oo += struct . pack ( "Q" , self . nonce )
  OO0Oo00OO0oo += json . dumps ( self . packet_json )
  return ( OO0Oo00OO0oo )
  if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
  if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
 def decode ( self , packet ) :
  oOOoooo0o0 = "I"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( False )
  iii1I = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] ) [ 0 ]
  packet = packet [ I1I11i : : ]
  iii1I = socket . ntohl ( iii1I )
  if ( ( iii1I & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 8 - 8: i1IIi
  if ( len ( packet ) < I1I11i ) : return ( False )
  OOOo = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] ) [ 0 ]
  packet = packet [ I1I11i : : ]
  if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
  OOOo = socket . ntohl ( OOOo )
  Ooo0o00O0Oo = OOOo >> 24
  iI1i1iI11 = ( OOOo >> 16 ) & 0xff
  Ii1Iii1iIi = ( OOOo >> 8 ) & 0xff
  iII1iii = OOOo & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( Ooo0o00O0Oo , iI1i1iI11 , Ii1Iii1iIi , iII1iii )
  self . local_port = str ( iii1I & 0xffff )
  if 80 - 80: I1ii11iIi11i - o0oOOo0O0Ooo
  oOOoooo0o0 = "Q"
  I1I11i = struct . calcsize ( oOOoooo0o0 )
  if ( len ( packet ) < I1I11i ) : return ( False )
  self . nonce = struct . unpack ( oOOoooo0o0 , packet [ : I1I11i ] ) [ 0 ]
  packet = packet [ I1I11i : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 16 - 16: OoOoOO00 * oO0o * Oo0Ooo / OOooOOo
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 18 - 18: II111iiii - I1Ii111
  return ( True )
  if 13 - 13: i11iIiiIii - O0 % OoOoOO00 + OOooOOo * ooOoO0o
  if 55 - 55: i1IIi - OOooOOo / I11i * Ii1I
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 20 - 20: OoOoOO00 * iIii1I11I1II1 % O0 - i1IIi
  if 51 - 51: I1ii11iIi11i * Ii1I - oO0o / O0 * OoooooooOO
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  OOOo0 , O00oo0o0o0oo = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( OOOo0 == None ) :
   OOOo0 , O00oo0o0o0oo = rts_rloc . split ( ":" )
   O00oo0o0o0oo = int ( O00oo0o0o0oo )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( OOOo0 , O00oo0o0o0oo ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( OOOo0 ,
 O00oo0o0o0oo ) )
   if 12 - 12: i1IIi / iIii1I11I1II1 / O0 * OoO0O00
   if 15 - 15: i11iIiiIii / IiII + Ii1I % OOooOOo % I1ii11iIi11i * oO0o
  if ( lisp_socket == None ) :
   o0O0o0000o0O0 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   o0O0o0000o0O0 . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   o0O0o0000o0O0 . sendto ( packet , ( OOOo0 , O00oo0o0o0oo ) )
   o0O0o0000o0O0 . close ( )
  else :
   lisp_socket . sendto ( packet , ( OOOo0 , O00oo0o0o0oo ) )
   if 24 - 24: OOooOOo / OOooOOo + I11i / iII111i . oO0o - iII111i
   if 59 - 59: I1ii11iIi11i % II111iiii - i11iIiiIii - I1Ii111
   if 34 - 34: II111iiii + iII111i / IiII
 def packet_length ( self ) :
  Ii1iiI1 = 8 ; iIIiIi = 4 + 4 + 8
  return ( Ii1iiI1 + iIIiIi + len ( json . dumps ( self . packet_json ) ) )
  if 84 - 84: ooOoO0o - o0oOOo0O0Ooo * iIii1I11I1II1 * iIii1I11I1II1
  if 30 - 30: i1IIi + OoOoOO00 - I1ii11iIi11i % i1IIi
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  III11II111 = self . local_rloc + ":" + self . local_port
  IiIi1i = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ III11II111 ] = IiIi1i
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( III11II111 , IiIi1i ) )
  if 2 - 2: i11iIiiIii + i1IIi
  if 1 - 1: i11iIiiIii + iIii1I11I1II1 / I11i * OoOoOO00 - OoOoOO00 % IiII
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  III11II111 = local_rloc_and_port
  try : IiIi1i = lisp_rtr_nat_trace_cache [ III11II111 ]
  except : IiIi1i = ( None , None )
  return ( IiIi1i )
  if 68 - 68: O0 . OoooooooOO
  if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
  if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
  if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
  if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
  if 37 - 37: I1ii11iIi11i * IiII
  if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
  if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
  if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
  if 46 - 46: OoooooooOO * OoO0O00 . I1Ii111
  if 95 - 95: ooOoO0o . I1ii11iIi11i . ooOoO0o / I1IiiI * OoOoOO00 . O0
def lisp_get_map_server ( address ) :
 for IiiiiiOoO0 in list ( lisp_map_servers_list . values ( ) ) :
  if ( IiiiiiOoO0 . map_server . is_exact_match ( address ) ) : return ( IiiiiiOoO0 )
  if 78 - 78: oO0o
 return ( None )
 if 33 - 33: oO0o + i1IIi
 if 32 - 32: iIii1I11I1II1
 if 71 - 71: Ii1I * I1IiiI
 if 62 - 62: II111iiii / I1IiiI . I1ii11iIi11i
 if 49 - 49: IiII / OoOoOO00 / O0 * i11iIiiIii
 if 47 - 47: i11iIiiIii + iII111i + i11iIiiIii
 if 66 - 66: o0oOOo0O0Ooo . I1IiiI + OoooooooOO . iII111i / OoooooooOO - IiII
def lisp_get_any_map_server ( ) :
 for IiiiiiOoO0 in list ( lisp_map_servers_list . values ( ) ) : return ( IiiiiiOoO0 )
 return ( None )
 if 47 - 47: o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
 if 34 - 34: I11i / o0oOOo0O0Ooo * OOooOOo * OOooOOo
 if 89 - 89: I1ii11iIi11i . OoooooooOO
 if 61 - 61: i1IIi + i11iIiiIii
 if 59 - 59: i11iIiiIii * OOooOOo + i1IIi * iIii1I11I1II1 + I11i
 if 97 - 97: OoO0O00 - I11i . OoooooooOO
 if 58 - 58: I1ii11iIi11i / II111iiii / i11iIiiIii
 if 27 - 27: iIii1I11I1II1 - O0 + OoOoOO00
 if 28 - 28: oO0o . IiII * iII111i % Oo0Ooo - OoO0O00 / I11i
 if 67 - 67: i11iIiiIii + i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  OOOo = address . print_address ( )
  o0O0oOoOO = None
  for III11II111 in lisp_map_resolvers_list :
   if ( III11II111 . find ( OOOo ) == - 1 ) : continue
   o0O0oOoOO = lisp_map_resolvers_list [ III11II111 ]
   if 94 - 94: O0 + OoO0O00 / I1IiiI * II111iiii * i11iIiiIii
  return ( o0O0oOoOO )
  if 55 - 55: OoooooooOO * O0 + i1IIi % I1IiiI
  if 10 - 10: II111iiii - Ii1I . I11i . O0 + Ii1I
  if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
  if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
  if 21 - 21: I1ii11iIi11i - ooOoO0o
  if 81 - 81: iII111i / i11iIiiIii / I1Ii111
  if 70 - 70: I1ii11iIi11i / i11iIiiIii
 if ( eid == "" ) :
  OooOo = ""
 elif ( eid == None ) :
  OooOo = "all"
 else :
  Oo0000 = lisp_db_for_lookups . lookup_cache ( eid , False )
  OooOo = "all" if Oo0000 == None else Oo0000 . use_mr_name
  if 78 - 78: iIii1I11I1II1 % OoooooooOO
  if 78 - 78: IiII % i11iIiiIii
 IiII11111 = None
 for o0O0oOoOO in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( OooOo == "" ) : return ( o0O0oOoOO )
  if ( o0O0oOoOO . mr_name != OooOo ) : continue
  if ( IiII11111 == None or o0O0oOoOO . last_used < IiII11111 . last_used ) : IiII11111 = o0O0oOoOO
  if 4 - 4: OoO0O00 . i11iIiiIii % II111iiii * IiII
 return ( IiII11111 )
 if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
 if 19 - 19: o0oOOo0O0Ooo
 if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
 if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
 if 71 - 71: OoO0O00 - I11i
 if 96 - 96: I1Ii111 / Ii1I
 if 65 - 65: I1ii11iIi11i * O0 . IiII
 if 11 - 11: I11i / Ii1I % oO0o
def lisp_get_decent_map_resolver ( eid ) :
 o00o = lisp_get_decent_index ( eid )
 i1o00O = str ( o00o ) + "." + lisp_decent_dns_suffix
 if 29 - 29: Oo0Ooo
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( i1o00O , False ) , eid . print_prefix ( ) ) )
 if 61 - 61: i1IIi - i1IIi - I11i
 if 68 - 68: ooOoO0o - I1ii11iIi11i - OoO0O00 % O0 / I1ii11iIi11i - iIii1I11I1II1
 IiII11111 = None
 for o0O0oOoOO in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( i1o00O != o0O0oOoOO . dns_name ) : continue
  if ( IiII11111 == None or o0O0oOoOO . last_used < IiII11111 . last_used ) : IiII11111 = o0O0oOoOO
  if 66 - 66: i11iIiiIii
 return ( IiII11111 )
 if 4 - 4: I1IiiI
 if 36 - 36: Ii1I
 if 76 - 76: i11iIiiIii + i1IIi
 if 56 - 56: OoOoOO00 + II111iiii / i11iIiiIii * OoOoOO00 * OoooooooOO
 if 15 - 15: OoOoOO00 / OoooooooOO + OOooOOo
 if 76 - 76: Ii1I * iII111i . OoooooooOO
 if 92 - 92: iIii1I11I1II1 - Oo0Ooo - I1IiiI - OOooOOo * I1Ii111
def lisp_ipv4_input ( packet ) :
 if 44 - 44: I1Ii111 - II111iiii / OOooOOo
 if 50 - 50: I11i / I1ii11iIi11i
 if 60 - 60: II111iiii / Ii1I + OoO0O00 % I1IiiI * i1IIi / II111iiii
 if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
 if ( ord ( packet [ 9 : 10 ] ) == 2 ) : return ( [ True , packet ] )
 if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
 if 3 - 3: OOooOOo / OoOoOO00 % iIii1I11I1II1
 if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 if 48 - 48: O0
 IiI1Iii1 = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
 if ( IiI1Iii1 == 0 ) :
  dprint ( "Packet arrived with checksum of 0!" )
 else :
  packet = lisp_ip_checksum ( packet )
  IiI1Iii1 = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
  if ( IiI1Iii1 != 0 ) :
   dprint ( "IPv4 header checksum failed for inner header" )
   packet = lisp_format_packet ( packet [ 0 : 20 ] )
   dprint ( "Packet header: {}" . format ( packet ) )
   return ( [ False , None ] )
   if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
   if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
   if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
   if 96 - 96: ooOoO0o * Ii1I + I11i + II111iiii * I1IiiI / iII111i
   if 40 - 40: OoooooooOO - I11i % OOooOOo - I1IiiI . I1IiiI + Ii1I
   if 97 - 97: OOooOOo . OoooooooOO . OOooOOo . i11iIiiIii
   if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
 OO0ooo00o = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( OO0ooo00o == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( OO0ooo00o == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 79 - 79: oO0o
  return ( [ False , None ] )
  if 47 - 47: OoooooooOO - i1IIi * OOooOOo
  if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
 OO0ooo00o -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , OO0ooo00o ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( [ False , packet ] )
 if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
 if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
 if 8 - 8: iII111i
 if 10 - 10: OoOoOO00 % I11i
 if 49 - 49: oO0o % ooOoO0o + II111iiii
 if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
 if 99 - 99: OoOoOO00
def lisp_ipv6_input ( packet ) :
 OooOOooo = packet . inner_dest
 packet = packet . packet
 if 46 - 46: I1ii11iIi11i / II111iiii / OoooooooOO / Ii1I
 if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
 if 8 - 8: oO0o
 if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
 if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
 OO0ooo00o = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( OO0ooo00o == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( OO0ooo00o == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 1 - 1: OoooooooOO . Ii1I
  return ( None )
  if 68 - 68: Ii1I
  if 98 - 98: iII111i
  if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
  if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
  if 67 - 67: o0oOOo0O0Ooo
 if ( OooOOooo . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 58 - 58: IiII % o0oOOo0O0Ooo + i1IIi
  if 33 - 33: II111iiii
 OO0ooo00o -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , OO0ooo00o ) + packet [ 8 : : ]
 return ( packet )
 if 61 - 61: I1Ii111
 if 56 - 56: I1ii11iIi11i - OoooooooOO
 if 52 - 52: Oo0Ooo - I11i - IiII - OoOoOO00
 if 21 - 21: oO0o % o0oOOo0O0Ooo + I1Ii111 . OOooOOo / OOooOOo
 if 41 - 41: Oo0Ooo . ooOoO0o * oO0o
 if 31 - 31: Oo0Ooo * IiII / IiII
 if 3 - 3: I1Ii111
 if 65 - 65: iIii1I11I1II1 % Oo0Ooo % I11i / OoooooooOO
def lisp_mac_input ( packet ) :
 return ( packet )
 if 82 - 82: o0oOOo0O0Ooo
 if 33 - 33: OoOoOO00 / i11iIiiIii - I1IiiI - OoooooooOO + i1IIi * I1Ii111
 if 92 - 92: iII111i + OoO0O00
 if 70 - 70: iIii1I11I1II1
 if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
 if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
 if 14 - 14: I1Ii111 + Oo0Ooo
 if 35 - 35: i11iIiiIii * Ii1I
 if 100 - 100: O0 . iII111i / iIii1I11I1II1
def lisp_rate_limit_map_request ( dest ) :
 IiI1i11i = lisp_get_timestamp ( )
 if 47 - 47: ooOoO0o + OoOoOO00
 if 67 - 67: IiII - I1ii11iIi11i * i1IIi - ooOoO0o
 if 91 - 91: I11i
 if 54 - 54: I1ii11iIi11i / i1IIi
 i11Ii1IIi = IiI1i11i - lisp_no_map_request_rate_limit
 if ( i11Ii1IIi < LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME ) :
  oO000o = int ( LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME - i11Ii1IIi )
  dprint ( "No Rate-Limit Mode for another {} secs" . format ( oO000o ) )
  return ( False )
  if 14 - 14: iIii1I11I1II1 * I11i . I11i * ooOoO0o * iII111i
  if 60 - 60: iIii1I11I1II1 + i1IIi + oO0o - iIii1I11I1II1 . i11iIiiIii * OoooooooOO
  if 23 - 23: iII111i - IiII % i11iIiiIii
  if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
  if 60 - 60: OOooOOo - I1Ii111 * Oo0Ooo
 if ( lisp_last_map_request_sent == None ) : return ( False )
 i11Ii1IIi = IiI1i11i - lisp_last_map_request_sent
 IiiiiIIi1i1i = ( i11Ii1IIi < LISP_MAP_REQUEST_RATE_LIMIT )
 if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
 if ( IiiiiIIi1i1i ) :
  dprint ( "Rate-limiting Map-Request for {}, sent {} secs ago" . format ( green ( dest . print_address ( ) , False ) , round ( i11Ii1IIi , 3 ) ) )
  if 39 - 39: iIii1I11I1II1 / i1IIi % I11i % I1ii11iIi11i * IiII
  if 11 - 11: II111iiii + i1IIi
 return ( IiiiiIIi1i1i )
 if 1 - 1: OOooOOo
 if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
 if 83 - 83: OoooooooOO
 if 53 - 53: o0oOOo0O0Ooo - Oo0Ooo / IiII + O0
 if 88 - 88: Oo0Ooo % I1Ii111 * O0 - i1IIi * OoO0O00
 if 74 - 74: Oo0Ooo % iIii1I11I1II1 + OOooOOo
 if 50 - 50: OoO0O00 . OoooooooOO
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ,
 pubsub = False ) :
 global lisp_last_map_request_sent , lisp_rloc_probe_nonce_list
 if 31 - 31: OoO0O00
 if 55 - 55: OoOoOO00 + I1Ii111 * o0oOOo0O0Ooo - I1ii11iIi11i + OoOoOO00
 if 6 - 6: II111iiii % iIii1I11I1II1 * I1Ii111
 if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
 if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
 if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
 O00OO00Oooo = I1IIII1iiIIII11I = None
 if ( rloc ) :
  O00OO00Oooo = rloc . rloc
  I1IIII1iiIIII11I = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 25 - 25: IiII % O0 * I11i * OoOoOO00 / OoooooooOO
  if 80 - 80: I1IiiI . oO0o - I1IiiI - OoOoOO00 * ooOoO0o / O0
  if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
  if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
  if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
 OOo0o0 , i11i1 , OoO0 = lisp_myrlocs
 if ( OOo0o0 == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 35 - 35: OOooOOo
 if ( i11i1 == None and O00OO00Oooo != None and O00OO00Oooo . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 78 - 78: o0oOOo0O0Ooo % OoooooooOO . OOooOOo + i11iIiiIii
  if 48 - 48: II111iiii / OoOoOO00
 I1I111I11i = lisp_map_request ( )
 I1I111I11i . record_count = 1
 I1I111I11i . nonce = lisp_get_control_nonce ( )
 I1I111I11i . rloc_probe = ( O00OO00Oooo != None )
 I1I111I11i . subscribe_bit = pubsub
 I1I111I11i . xtr_id_present = pubsub
 I1I111I11i . decent_nat_xtr = lisp_decent_nat
 if 1 - 1: OOooOOo + OOooOOo % O0 % O0
 if 12 - 12: iIii1I11I1II1
 if 93 - 93: o0oOOo0O0Ooo % I11i - oO0o . Oo0Ooo
 if 94 - 94: Ii1I + IiII . IiII * I1Ii111
 if 54 - 54: ooOoO0o / O0 + Ii1I - I1ii11iIi11i / Oo0Ooo
 if 75 - 75: iII111i % i11iIiiIii + II111iiii - OOooOOo % O0
 if 94 - 94: I1IiiI . OOooOOo . IiII
 if ( rloc ) : rloc . last_rloc_probe_nonce = I1I111I11i . nonce
 if 87 - 87: I1Ii111 / O0 / iIii1I11I1II1 % OoOoOO00 + iII111i . iIii1I11I1II1
 iiiiiIIii11I = deid . is_multicast_address ( )
 if ( iiiiiIIii11I ) :
  I1I111I11i . target_eid = seid
  I1I111I11i . target_group = deid
 else :
  I1I111I11i . target_eid = deid
  if 36 - 36: O0 . OoO0O00 + Oo0Ooo + Oo0Ooo % I1Ii111 + ooOoO0o
  if 89 - 89: iII111i
  if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
  if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
  if 77 - 77: OoooooooOO - I11i / I1IiiI % OoOoOO00 - OOooOOo
  if 37 - 37: ooOoO0o
  if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
  if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
  if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
 if ( I1I111I11i . rloc_probe == False ) :
  Oo0000 = lisp_get_signature_eid ( )
  if ( Oo0000 ) :
   I1I111I11i . signature_eid . copy_address ( Oo0000 . eid )
   I1I111I11i . privkey_filename = "./lisp-sig.pem"
   if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
   if 82 - 82: iII111i - I1Ii111 - OoOoOO00
   if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
   if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
   if 44 - 44: O0
   if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
 if ( seid == None or iiiiiIIii11I ) :
  I1I111I11i . source_eid . afi = LISP_AFI_NONE
 else :
  I1I111I11i . source_eid = seid
  if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
  if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
  if 14 - 14: iIii1I11I1II1 * I1ii11iIi11i + OOooOOo + O0
  if 79 - 79: II111iiii - iII111i
  if 89 - 89: O0 - OoO0O00
  if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
  if 32 - 32: O0 + IiII
  if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
  if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
  if 17 - 17: OOooOOo
  if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
  if 46 - 46: II111iiii * OoO0O00
  if 77 - 77: ooOoO0o * I11i
  if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
  if 76 - 76: iII111i * OoooooooOO
 if ( O00OO00Oooo != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( lisp_decent_nat == False and
 O00OO00Oooo . is_private_address ( ) == False ) :
   OOo0o0 = lisp_get_any_translated_rloc ( )
   if 49 - 49: II111iiii - OOooOOo + II111iiii + OoOoOO00
  if ( OOo0o0 == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 51 - 51: i11iIiiIii
   if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
   if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
   if 63 - 63: II111iiii - Oo0Ooo
   if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
   if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
   if 78 - 78: IiII - I1IiiI
   if 59 - 59: oO0o + i1IIi - IiII % OOooOOo % iIii1I11I1II1
 if ( O00OO00Oooo == None or O00OO00Oooo . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and O00OO00Oooo == None ) :
   i111i1iIi1i = lisp_get_any_translated_rloc ( )
   if ( i111i1iIi1i != None ) : OOo0o0 = i111i1iIi1i
   if 71 - 71: OoO0O00
  I1I111I11i . itr_rlocs . append ( OOo0o0 )
  if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
 if ( O00OO00Oooo == None or O00OO00Oooo . is_ipv6 ( ) ) :
  if ( i11i1 == None or i11i1 . is_ipv6_link_local ( ) ) :
   i11i1 = None
  else :
   I1I111I11i . itr_rloc_count = 1 if ( O00OO00Oooo == None ) else 0
   I1I111I11i . itr_rlocs . append ( i11i1 )
   if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
   if 54 - 54: Ii1I / I1IiiI
   if 7 - 7: iIii1I11I1II1 . O0 + OOooOOo . Ii1I * Oo0Ooo
   if 25 - 25: I1Ii111 . Oo0Ooo % II111iiii . IiII - O0
   if 18 - 18: oO0o * OOooOOo
   if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
   if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
   if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
   if 96 - 96: II111iiii % I11i / Ii1I - i11iIiiIii
 if ( O00OO00Oooo != None and I1I111I11i . itr_rlocs != [ ] ) :
  oo00oOOO00 = I1I111I11i . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   oo00oOOO00 = OOo0o0
  elif ( deid . is_ipv6 ( ) ) :
   oo00oOOO00 = i11i1
  else :
   oo00oOOO00 = OOo0o0
   if 63 - 63: I1IiiI
   if 15 - 15: iIii1I11I1II1 - I1ii11iIi11i % OoO0O00 * II111iiii / I11i + I11i
   if 23 - 23: I1IiiI
   if 51 - 51: i11iIiiIii / ooOoO0o - OoooooooOO + OoOoOO00 + oO0o
   if 57 - 57: iIii1I11I1II1
   if 19 - 19: Ii1I / o0oOOo0O0Ooo + O0 / iIii1I11I1II1 + II111iiii
 OO0Oo00OO0oo = I1I111I11i . encode ( O00OO00Oooo , I1IIII1iiIIII11I )
 I1I111I11i . print_map_request ( )
 if 3 - 3: oO0o % OoO0O00 % OOooOOo
 if 64 - 64: o0oOOo0O0Ooo . II111iiii * IiII % Oo0Ooo + I11i - OoooooooOO
 if 58 - 58: ooOoO0o
 if 15 - 15: O0 * OOooOOo * I11i + Ii1I * OoooooooOO + OOooOOo
 if 77 - 77: O0
 if 98 - 98: iII111i - iII111i % i1IIi - I1Ii111 . I1IiiI % o0oOOo0O0Ooo
 if ( O00OO00Oooo != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   Ii1IOo0Oo0oOoO = rloc . normalize_decent_nat_rloc_name ( )
   i1o0 = lisp_get_nat_info ( O00OO00Oooo , Ii1IOo0Oo0oOoO )
   if 38 - 38: IiII % OoOoOO00 . OOooOOo . I1ii11iIi11i
   if 34 - 34: iII111i . i11iIiiIii + OoO0O00 + o0oOOo0O0Ooo / ooOoO0o - i11iIiiIii
   if 63 - 63: ooOoO0o % OoO0O00 % ooOoO0o
   if 28 - 28: IiII * I1Ii111 * o0oOOo0O0Ooo + ooOoO0o - IiII / IiII
   if 73 - 73: iIii1I11I1II1 . I1ii11iIi11i + OOooOOo
   if ( i1o0 == None ) :
    o0O00o0o = rloc . rloc . print_address_no_iid ( )
    o0O0Ooo = "glean-{}" . format ( o0O00o0o ) if lisp_i_am_rtr else "nat-{}" . format ( o0O00o0o )
    if 51 - 51: I11i % Oo0Ooo * OOooOOo % OoooooooOO - OoOoOO00 % Ii1I
    o00oo = rloc . translated_port
    i1o0 = lisp_nat_info ( o0O00o0o , o0O0Ooo , o00oo )
    if 60 - 60: OoOoOO00 - IiII + OoO0O00
    if 77 - 77: iIii1I11I1II1
   lisp_encap_rloc_probe ( lisp_sockets , O00OO00Oooo , i1o0 , OO0Oo00OO0oo )
   return
   if 92 - 92: IiII
   if 68 - 68: OOooOOo . IiII / iIii1I11I1II1 % i11iIiiIii
  if ( O00OO00Oooo . is_ipv4 ( ) and O00OO00Oooo . is_multicast_address ( ) ) :
   OooOOooo = O00OO00Oooo
  else :
   Oo0o = O00OO00Oooo . print_address_no_iid ( )
   OooOOooo = lisp_convert_4to6 ( Oo0o )
   if 74 - 74: iII111i + i11iIiiIii
   if 95 - 95: Ii1I
   if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
   if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
   if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
  lisp_rloc_probe_nonce_list [ I1I111I11i . nonce ] = Oo0o
  if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
  lisp_send ( lisp_sockets , OooOOooo , LISP_CTRL_PORT , OO0Oo00OO0oo )
  return
  if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
  if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
  if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
  if 49 - 49: iII111i / iII111i - OoOoOO00
  if 89 - 89: ooOoO0o
  if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
 Oo0oO0Oo0 = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  o0O0oOoOO = lisp_get_decent_map_resolver ( deid )
 else :
  o0O0oOoOO = lisp_get_map_resolver ( None , Oo0oO0Oo0 )
  if 11 - 11: iII111i
 if ( o0O0oOoOO == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
  return
  if 89 - 89: I11i % II111iiii
 o0O0oOoOO . last_used = lisp_get_timestamp ( )
 o0O0oOoOO . map_requests_sent += 1
 if ( o0O0oOoOO . last_nonce == 0 ) : o0O0oOoOO . last_nonce = I1I111I11i . nonce
 if 35 - 35: oO0o
 if 65 - 65: II111iiii
 if 87 - 87: oO0o / OoO0O00 - oO0o
 if 69 - 69: i11iIiiIii
 if ( seid == None ) : seid = oo00oOOO00
 lisp_send_ecm ( lisp_sockets , OO0Oo00OO0oo , seid , lisp_ephem_port , deid ,
 o0O0oOoOO . map_resolver )
 if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
 if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
 if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
 if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
 if 14 - 14: I1ii11iIi11i / i11iIiiIii * I11i % o0oOOo0O0Ooo + IiII / I1ii11iIi11i
 if 82 - 82: OOooOOo . oO0o
 if 12 - 12: i11iIiiIii + II111iiii
 o0O0oOoOO . resolve_dns_name ( )
 return
 if 49 - 49: OoooooooOO
 if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
 if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
 if 6 - 6: oO0o / II111iiii
 if 23 - 23: IiII - OoooooooOO / oO0o
 if 69 - 69: O0 - OoooooooOO
 if 31 - 31: o0oOOo0O0Ooo . i1IIi - i1IIi % i1IIi - iIii1I11I1II1
 if 50 - 50: IiII - OOooOOo % OoOoOO00
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 66 - 66: IiII * i11iIiiIii
 if 64 - 64: i11iIiiIii . I1Ii111 % i11iIiiIii % I11i
 if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
 if 64 - 64: OOooOOo / OoOoOO00
 i1I1ii11ii1 = lisp_info ( )
 i1I1ii11ii1 . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : i1I1ii11ii1 . hostname += "-" + device_name
 if 33 - 33: i1IIi / I1Ii111 * O0
 Oo0o = dest . print_address_no_iid ( )
 if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
 if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
 if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
 if 49 - 49: IiII
 if 1 - 1: oO0o / I11i
 if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
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
 IIiIiII1iIiIi = False
 if ( device_name ) :
  o0Oo0o0 = lisp_get_default_route_next_hops ( )
  lprint ( "Found default routes {}" . format ( o0Oo0o0 ) )
  if 3 - 3: OoOoOO00 - I1ii11iIi11i
  if ( len ( o0Oo0o0 ) == 1 ) :
   oo0O0 = o0Oo0o0 [ 0 ] [ 0 ]
   if ( oo0O0 != device_name ) :
    lprint ( "Multihoming config error, add this to your system:" )
    lprint ( "  'sudo ip route append default via <nh> dev {}'" . format ( device_name ) )
    if 17 - 17: Ii1I / OoOoOO00 % I1ii11iIi11i - IiII
    return
    if 76 - 76: Ii1I / o0oOOo0O0Ooo % IiII % Oo0Ooo
    if 68 - 68: o0oOOo0O0Ooo / O0 + i11iIiiIii % II111iiii
    if 10 - 10: iII111i - Oo0Ooo
  I1i11i = lisp_get_host_route_next_hop ( Oo0o )
  if ( I1i11i == None ) :
   lprint ( "No host route found for MS {}" . format ( Oo0o ) )
  else :
   lprint ( "Host route found for MS {}, nh {}" . format ( Oo0o ,
 I1i11i ) )
   if 84 - 84: i11iIiiIii - I11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo * Ii1I / OOooOOo
   if 37 - 37: iII111i . OoO0O00
   if 55 - 55: OoO0O00
   if 7 - 7: OOooOOo + IiII * iIii1I11I1II1
   if 69 - 69: OoO0O00 / iIii1I11I1II1 + OOooOOo
   if 66 - 66: iII111i
   if 23 - 23: ooOoO0o * II111iiii . II111iiii % I1Ii111
   if 69 - 69: I1ii11iIi11i * IiII / II111iiii
   if 10 - 10: O0 / I11i
   if 29 - 29: i11iIiiIii % I11i
  if ( port == LISP_CTRL_PORT and I1i11i != None ) :
   lprint ( "Waiting for host route {} to go away" . format ( Oo0o ) )
   while ( True ) :
    time . sleep ( .01 )
    I1i11i = lisp_get_host_route_next_hop ( Oo0o )
    if ( I1i11i == None ) : break
    if 49 - 49: I11i
    if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
    if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
  for OoO0 , oo0O0 in o0Oo0o0 :
   if ( OoO0 != device_name ) : continue
   if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
   if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
   if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
   if 32 - 32: O0
   if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
   if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
   if ( I1i11i != oo0O0 ) :
    if ( I1i11i != None ) :
     lisp_install_host_route ( Oo0o , I1i11i , False )
     if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
    lisp_install_host_route ( Oo0o , oo0O0 , True )
    IIiIiII1iIiIi = True
    if 70 - 70: iIii1I11I1II1 - I11i
   break
   if 2 - 2: oO0o / II111iiii * OoO0O00
   if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
   if 40 - 40: OOooOOo
   if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
   if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
   if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
 OO0Oo00OO0oo = i1I1ii11ii1 . encode ( )
 i1I1ii11ii1 . print_info ( )
 if 26 - 26: OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
 if 39 - 39: I1ii11iIi11i * I1IiiI * II111iiii . Oo0Ooo % I1IiiI
 if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
 if 98 - 98: OoO0O00 + oO0o - II111iiii
 oOOI1 = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 oOOI1 = bold ( oOOI1 , False )
 o00oo = bold ( "{}" . format ( port ) , False )
 oO = red ( Oo0o , False )
 oOo = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( oOo , oO , o00oo , oOOI1 ) )
 if 14 - 14: O0 / OoOoOO00
 if 66 - 66: Ii1I % I11i % iIii1I11I1II1 * O0
 if 37 - 37: Oo0Ooo * oO0o
 if 10 - 10: OoOoOO00 * I1ii11iIi11i * I1Ii111 - Ii1I . oO0o
 if 58 - 58: OoooooooOO . O0
 if 80 - 80: OoOoOO00 - o0oOOo0O0Ooo + OoooooooOO + ooOoO0o * OOooOOo
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , OO0Oo00OO0oo )
 else :
  I1IIII = lisp_data_header ( )
  I1IIII . instance_id ( 0xffffff )
  I1IIII = I1IIII . encode ( )
  if ( I1IIII ) :
   OO0Oo00OO0oo = I1IIII + OO0Oo00OO0oo
   if 10 - 10: o0oOOo0O0Ooo + ooOoO0o + Oo0Ooo
   if 67 - 67: I1IiiI / i11iIiiIii - I1Ii111 % OoooooooOO
   if 36 - 36: oO0o % iII111i % oO0o
   if 56 - 56: ooOoO0o - O0 + iII111i % I11i / i1IIi
   if 78 - 78: i1IIi . iIii1I11I1II1
   if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
   if 58 - 58: II111iiii * oO0o - i1IIi . I11i
   if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
   if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , OO0Oo00OO0oo )
   if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
   if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
   if 31 - 31: i1IIi * Ii1I
   if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
   if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
   if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
   if 52 - 52: OOooOOo . OoOoOO00 - ooOoO0o % i1IIi
 if ( IIiIiII1iIiIi ) :
  lisp_install_host_route ( Oo0o , None , False )
  if ( I1i11i != None ) : lisp_install_host_route ( Oo0o , I1i11i , True )
  if 15 - 15: oO0o
 return
 if 6 - 6: oO0o . iIii1I11I1II1 - I1ii11iIi11i % IiII
 if 58 - 58: iII111i * oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o
 if 63 - 63: oO0o . IiII . o0oOOo0O0Ooo
 if 16 - 16: iII111i . I11i - Oo0Ooo / I1IiiI + OoOoOO00
 if 14 - 14: iIii1I11I1II1 / i11iIiiIii - o0oOOo0O0Ooo . iII111i * OoO0O00
 if 5 - 5: Ii1I + OoOoOO00 % I11i + IiII
 if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
 if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
 if 7 - 7: I1Ii111 % i1IIi . I11i . O0 / i1IIi
 if 56 - 56: Oo0Ooo
 i1I1ii11ii1 = lisp_info ( )
 packet = i1I1ii11ii1 . decode ( packet )
 if ( packet == None ) : return
 i1I1ii11ii1 . print_info ( )
 if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
 if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
 if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
 if 70 - 70: Oo0Ooo - I11i / I1ii11iIi11i % OoO0O00 % II111iiii
 i1I1ii11ii1 . info_reply = True
 i1I1ii11ii1 . global_etr_rloc . store_address ( addr_str )
 i1I1ii11ii1 . etr_port = sport
 if 72 - 72: i11iIiiIii * I11i
 if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
 if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
 if 64 - 64: OoooooooOO
 if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
 if ( i1I1ii11ii1 . hostname != None ) :
  i1I1ii11ii1 . private_etr_rloc . afi = LISP_AFI_NAME
  i1I1ii11ii1 . private_etr_rloc . store_address ( i1I1ii11ii1 . hostname )
  if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
  if 71 - 71: O0 - OoooooooOO
 if ( rtr_list != None ) : i1I1ii11ii1 . rtr_list = rtr_list
 packet = i1I1ii11ii1 . encode ( )
 i1I1ii11ii1 . print_info ( )
 if 82 - 82: i11iIiiIii * II111iiii % IiII
 if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
 if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
 if 67 - 67: iII111i
 if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 OooOOooo = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , OooOOooo , sport , packet )
 if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
 if 60 - 60: i1IIi / iII111i
 if 10 - 10: I1Ii111 / OoOoOO00 * Ii1I % o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i
 if 2 - 2: iIii1I11I1II1
 if 85 - 85: O0 - ooOoO0o
 iIiI11ii = lisp_info_source ( i1I1ii11ii1 . hostname , addr_str , sport )
 iIiI11ii . cache_address_for_info_source ( )
 return
 if 82 - 82: iII111i + I1IiiI * Ii1I . i1IIi - Ii1I % i11iIiiIii
 if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
 if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
 if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
 if 88 - 88: iII111i
 if 94 - 94: OoooooooOO
 if 32 - 32: I1ii11iIi11i
 if 8 - 8: I11i * i11iIiiIii - ooOoO0o
def lisp_get_signature_eid ( ) :
 for Oo0000 in lisp_db_list :
  if ( Oo0000 . signature_eid ) : return ( Oo0000 )
  if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
 return ( None )
 if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
 if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
 if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
 if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
 if 42 - 42: II111iiii . iII111i
 if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
 if 64 - 64: oO0o / IiII
 if 86 - 86: I11i
def lisp_get_any_translated_port ( ) :
 for Oo0000 in lisp_db_list :
  for oO0O0oOOO0 in Oo0000 . rloc_set :
   if ( oO0O0oOOO0 . translated_rloc . is_null ( ) ) : continue
   return ( oO0O0oOOO0 . translated_port )
   if 36 - 36: o0oOOo0O0Ooo / OoO0O00
   if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
 return ( None )
 if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
 if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
 if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
 if 12 - 12: I1IiiI . OOooOOo % Oo0Ooo
 if 86 - 86: i11iIiiIii
 if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
 if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
 if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
 if 79 - 79: I11i - II111iiii
def lisp_get_any_translated_rloc ( ) :
 for Oo0000 in lisp_db_list :
  for oO0O0oOOO0 in Oo0000 . rloc_set :
   if ( oO0O0oOOO0 . translated_rloc . is_null ( ) ) : continue
   return ( oO0O0oOOO0 . translated_rloc )
   if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
   if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
 return ( None )
 if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
 if 44 - 44: I1IiiI * IiII . OoooooooOO
 if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
 if 10 - 10: i1IIi + o0oOOo0O0Ooo
 if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
 if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
def lisp_get_all_translated_rlocs ( ) :
 iiiii11iiI = [ ]
 for Oo0000 in lisp_db_list :
  for oO0O0oOOO0 in Oo0000 . rloc_set :
   if ( oO0O0oOOO0 . is_rloc_translated ( ) == False ) : continue
   OOOo = oO0O0oOOO0 . translated_rloc . print_address_no_iid ( )
   iiiii11iiI . append ( OOOo )
   if 4 - 4: iIii1I11I1II1 % OOooOOo % O0 / Ii1I * OoO0O00
   if 87 - 87: i1IIi / Oo0Ooo * iIii1I11I1II1
 return ( iiiii11iiI )
 if 24 - 24: O0
 if 38 - 38: O0
 if 4 - 4: OoO0O00 / Ii1I - i1IIi . i11iIiiIii * Oo0Ooo
 if 76 - 76: iII111i . oO0o - i1IIi
 if 94 - 94: O0 % iII111i
 if 90 - 90: IiII
 if 1 - 1: I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % oO0o + Ii1I
 if 46 - 46: I1IiiI + OoO0O00 - Oo0Ooo
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 Oo0ooo0o0oo = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 13 - 13: OoOoOO00
 Ooo0Oo0000O0O = { }
 for OOOo0 in rtr_list :
  if ( OOOo0 == None ) : continue
  OOOo = rtr_list [ OOOo0 ]
  if ( Oo0ooo0o0oo and OOOo . is_private_address ( ) ) : continue
  Ooo0Oo0000O0O [ OOOo0 ] = OOOo
  if 19 - 19: iIii1I11I1II1 . I1Ii111 - i11iIiiIii - OoooooooOO . Oo0Ooo % II111iiii
 rtr_list = Ooo0Oo0000O0O
 if 28 - 28: OoooooooOO / iII111i / iIii1I11I1II1
 oOooO0oo0 = [ ]
 for II1i1iI in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( II1i1iI == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 27 - 27: Ii1I / OoooooooOO . O0
  if 53 - 53: OoooooooOO / I1ii11iIi11i
  if 46 - 46: Ii1I . i11iIiiIii / I1Ii111 - I1ii11iIi11i
  if 13 - 13: IiII % I1Ii111
  if 9 - 9: OoooooooOO * ooOoO0o % I1ii11iIi11i . I1IiiI % O0
  o00OO = lisp_address ( II1i1iI , "" , 0 , iid )
  o00OO . make_default_route ( o00OO )
  Ii111 = lisp_map_cache . lookup_cache ( o00OO , True )
  if ( Ii111 ) :
   if ( Ii111 . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( Ii111 . print_eid_tuple ( ) , False ) ) )
    if 91 - 91: OOooOOo * OoooooooOO * I1IiiI . i1IIi
   elif ( Ii111 . do_rloc_sets_match ( list ( rtr_list . values ( ) ) ) ) :
    continue
    if 9 - 9: oO0o / i11iIiiIii + IiII / IiII - I11i
   Ii111 . delete_cache ( )
   if 87 - 87: iII111i
   if 37 - 37: oO0o + OoO0O00
  oOooO0oo0 . append ( [ o00OO , "" ] )
  if 66 - 66: iIii1I11I1II1 * iIii1I11I1II1 + IiII % I1IiiI
  if 60 - 60: I1Ii111 . IiII / Oo0Ooo
  if 32 - 32: OoOoOO00 + Ii1I * iII111i % Oo0Ooo
  if 61 - 61: OoooooooOO % iII111i - O0
  iII1I1i = lisp_address ( II1i1iI , "" , 0 , iid )
  iII1I1i . make_default_multicast_route ( iII1I1i )
  oooOoo0OO0 = lisp_map_cache . lookup_cache ( iII1I1i , True )
  if ( oooOoo0OO0 ) : oooOoo0OO0 = oooOoo0OO0 . source_cache . lookup_cache ( o00OO , True )
  if ( oooOoo0OO0 ) : oooOoo0OO0 . delete_cache ( )
  if 24 - 24: iIii1I11I1II1 . I11i
  oOooO0oo0 . append ( [ o00OO , iII1I1i ] )
  if 47 - 47: i11iIiiIii
 if ( len ( oOooO0oo0 ) == 0 ) : return
 if 92 - 92: I1Ii111 + OoO0O00 - iIii1I11I1II1 / iIii1I11I1II1
 if 32 - 32: iII111i * iIii1I11I1II1 + I1Ii111 + IiII + O0 * OoO0O00
 if 100 - 100: II111iiii
 if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
 oO0O0O0O0OO = [ ]
 for oOo in rtr_list :
  i11IiIII1iiI = rtr_list [ oOo ]
  oO0O0oOOO0 = lisp_rloc ( )
  oO0O0oOOO0 . rloc . copy_address ( i11IiIII1iiI )
  oO0O0oOOO0 . priority = 254
  oO0O0oOOO0 . mpriority = 255
  oO0O0oOOO0 . rloc_name = "RTR"
  oO0O0O0O0OO . append ( oO0O0oOOO0 )
  if 89 - 89: I1Ii111 + ooOoO0o + I1Ii111
  if 35 - 35: O0 * OoOoOO00
 for o00OO in oOooO0oo0 :
  Ii111 = lisp_mapping ( o00OO [ 0 ] , o00OO [ 1 ] , oO0O0O0O0OO )
  Ii111 . mapping_source = map_resolver
  Ii111 . map_cache_ttl = LISP_MR_TTL * 60
  Ii111 . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( Ii111 . print_eid_tuple ( ) , False ) , list ( rtr_list . keys ( ) ) ) )
  if 54 - 54: O0 / Oo0Ooo
  oO0O0O0O0OO = copy . deepcopy ( oO0O0O0O0OO )
  if 54 - 54: OoO0O00
 return
 if 38 - 38: II111iiii + o0oOOo0O0Ooo * I11i + I1Ii111 - II111iiii . OOooOOo
 if 38 - 38: I1ii11iIi11i % OOooOOo + iII111i / Oo0Ooo / IiII / oO0o
 if 2 - 2: iIii1I11I1II1
 if 9 - 9: I1Ii111 / IiII
 if 33 - 33: o0oOOo0O0Ooo + oO0o . o0oOOo0O0Ooo . I11i * OoooooooOO + iIii1I11I1II1
 if 64 - 64: OoooooooOO . Ii1I
 if 38 - 38: Oo0Ooo
 if 64 - 64: ooOoO0o % i11iIiiIii
 if 10 - 10: Ii1I % oO0o + oO0o * OoOoOO00 % iII111i / o0oOOo0O0Ooo
 if 17 - 17: iII111i / I1IiiI . II111iiii - OoO0O00 + iII111i
def lisp_process_info_reply ( source , packet , store ) :
 if 22 - 22: Oo0Ooo - I1ii11iIi11i + I11i . oO0o
 if 85 - 85: iIii1I11I1II1 / Ii1I
 if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
 if 97 - 97: I1Ii111 + I1ii11iIi11i
 i1I1ii11ii1 = lisp_info ( )
 packet = i1I1ii11ii1 . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
 i1I1ii11ii1 . print_info ( )
 if 80 - 80: I11i
 if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
 if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
 if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
 iI1I1 = False
 if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
 if 65 - 65: I11i
 if 92 - 92: iII111i . IiII + i1IIi % i1IIi
 if 11 - 11: I1ii11iIi11i + iIii1I11I1II1 - I1Ii111 * iIii1I11I1II1 * IiII + oO0o
 for oOo in i1I1ii11ii1 . rtr_list :
  Oo0o = oOo . print_address_no_iid ( )
  if ( Oo0o in lisp_rtr_list ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ Oo0o ] != None ) : continue
   if 6 - 6: I1Ii111 * OOooOOo + i1IIi - Ii1I / oO0o
  iI1I1 = True
  lisp_rtr_list [ Oo0o ] = oOo
  if 81 - 81: I1Ii111 % oO0o * i1IIi * OoooooooOO / Oo0Ooo
  if 70 - 70: I1IiiI
  if 35 - 35: i11iIiiIii
  if 59 - 59: ooOoO0o . iII111i - II111iiii
  if 30 - 30: o0oOOo0O0Ooo % iII111i - i11iIiiIii
 if ( lisp_i_am_itr and iI1I1 ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for oO0O in list ( lisp_iid_to_interface . keys ( ) ) :
    lisp_update_default_routes ( source , int ( oO0O ) , lisp_rtr_list )
    if 25 - 25: i11iIiiIii + OoOoOO00 + oO0o / Ii1I * Oo0Ooo + Oo0Ooo
    if 26 - 26: I1IiiI % I1ii11iIi11i + o0oOOo0O0Ooo / I1ii11iIi11i - I1IiiI
    if 55 - 55: OoooooooOO
    if 2 - 2: Oo0Ooo + I11i / OOooOOo + OOooOOo
    if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
    if 90 - 90: OOooOOo
    if 29 - 29: OoOoOO00 - I1IiiI / oO0o + Oo0Ooo + I1Ii111 + O0
 if ( store == False ) :
  return ( [ i1I1ii11ii1 . global_etr_rloc , i1I1ii11ii1 . etr_port , iI1I1 ] )
  if 65 - 65: oO0o
  if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
  if 13 - 13: Ii1I
  if 34 - 34: I1IiiI / iIii1I11I1II1
  if 35 - 35: oO0o / oO0o
  if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
 for Oo0000 in lisp_db_list :
  for oO0O0oOOO0 in Oo0000 . rloc_set :
   OOOo0 = oO0O0oOOO0 . rloc
   i1i1111I = oO0O0oOOO0 . interface
   o0oo0 = oO0O0oOOO0 . rloc_name
   if ( oO0O0oOOO0 . is_decent_nat_port ( ) ) :
    o0oo0 = o0oo0 . split ( LISP_TP ) [ 0 ]
    if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
    if 77 - 77: O0
   if ( i1i1111I == None ) :
    if ( OOOo0 . is_null ( ) ) : continue
    if ( OOOo0 . is_local ( ) == False ) : continue
    if ( i1I1ii11ii1 . private_etr_rloc . is_null ( ) == False and
 OOOo0 . is_exact_match ( i1I1ii11ii1 . private_etr_rloc ) == False ) :
     continue
     if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
   elif ( i1I1ii11ii1 . private_etr_rloc . is_dist_name ( ) ) :
    i1III = i1I1ii11ii1 . private_etr_rloc . address
    if ( i1III != o0oo0 ) : continue
    if 97 - 97: i1IIi
    if 7 - 7: i11iIiiIii
   ooOo000OoO0o = green ( Oo0000 . eid . print_prefix ( ) , False )
   IIII1iI1IiIiI = red ( OOOo0 . print_address_no_iid ( ) , False )
   if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
   i1i1iI1iII = i1I1ii11ii1 . global_etr_rloc . is_exact_match ( OOOo0 )
   if ( oO0O0oOOO0 . translated_port == 0 and i1i1iI1iII ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( IIII1iI1IiIiI ,
 i1i1111I , ooOo000OoO0o ) )
    continue
    if 72 - 72: O0 + OOooOOo * II111iiii * iII111i + IiII * i11iIiiIii
    if 35 - 35: i1IIi - OoOoOO00
    if 57 - 57: iII111i / iIii1I11I1II1 + I1ii11iIi11i * I1ii11iIi11i
    if 98 - 98: O0 % I1IiiI + O0 - iIii1I11I1II1 / I11i
    if 22 - 22: OOooOOo * i11iIiiIii / oO0o / IiII / I1Ii111
   OO00O = i1I1ii11ii1 . global_etr_rloc
   OO0i11I1I111I = oO0O0oOOO0 . translated_rloc
   if ( OO0i11I1I111I . is_exact_match ( OO00O ) and
 i1I1ii11ii1 . etr_port == oO0O0oOOO0 . translated_port ) : continue
   if 51 - 51: o0oOOo0O0Ooo . IiII + Ii1I - IiII - i1IIi + I1IiiI
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( i1I1ii11ii1 . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # OOooOOo - OoooooooOO % i1IIi . iIii1I11I1II1 / I1IiiI
 i1I1ii11ii1 . etr_port , IIII1iI1IiIiI , i1i1111I , ooOo000OoO0o ) )
   if 97 - 97: iII111i
   oO0O0oOOO0 . rloc_name = o0oo0
   oO0O0oOOO0 . store_translated_rloc ( i1I1ii11ii1 . global_etr_rloc ,
 i1I1ii11ii1 . etr_port )
   if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
   iI1I1 = True
   if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
   if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
 return ( [ i1I1ii11ii1 . global_etr_rloc , i1I1ii11ii1 . etr_port , iI1I1 ] )
 if 47 - 47: I1Ii111 * iII111i
 if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
 if 76 - 76: iIii1I11I1II1 . i11iIiiIii * II111iiii - iII111i
 if 51 - 51: I1IiiI
 if 52 - 52: I1Ii111
 if 82 - 82: iII111i + II111iiii
 if 29 - 29: O0 % Ii1I * ooOoO0o % O0
 if 83 - 83: oO0o
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
 oO0OooO0o0 = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 oo0Oo0o0O00O00 = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 11 - 11: I1ii11iIi11i % IiII + OOooOOo . I1Ii111
 if 45 - 45: o0oOOo0O0Ooo / OOooOOo % i1IIi * Ii1I / i11iIiiIii
 if 89 - 89: ooOoO0o
 if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
 oO0OooO0o0 . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , oO0OooO0o0 , None )
 oO0OooO0o0 . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , oO0OooO0o0 , None )
 if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
 if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
 if 20 - 20: I11i
 if 37 - 37: I1Ii111
 oo0Oo0o0O00O00 . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , oo0Oo0o0O00O00 , None )
 oo0Oo0o0O00O00 . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , oo0Oo0o0O00O00 , None )
 if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
 if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
 if 41 - 41: O0 / OoooooooOO - i1IIi
 if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
 III1 = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 III1 . start ( )
 return
 if 3 - 3: OOooOOo * ooOoO0o / i11iIiiIii . OoO0O00 * ooOoO0o
 if 58 - 58: i1IIi - OoO0O00 * II111iiii
 if 92 - 92: ooOoO0o / I1Ii111 . iII111i
 if 59 - 59: Ii1I - OoO0O00 % iII111i + I1ii11iIi11i * iII111i
 if 51 - 51: ooOoO0o - Oo0Ooo / iII111i . I11i - Ii1I / OOooOOo
 if 4 - 4: II111iiii + OoOoOO00 . ooOoO0o - I11i . I1IiiI
 if 46 - 46: II111iiii
 if 38 - 38: OOooOOo % II111iiii
 if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
 if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
 if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
 if 89 - 89: I1Ii111
 if 29 - 29: I11i * ooOoO0o - OoooooooOO
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
 OOOo = lisp_get_interface_address ( rloc . interface )
 if ( OOOo == None ) : return
 if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
 OOoo0oOoO = rloc . rloc . print_address_no_iid ( )
 I11I1 = OOOo . print_address_no_iid ( )
 if 73 - 73: OoooooooOO
 if ( OOoo0oOoO == I11I1 ) : return
 if 25 - 25: i1IIi . II111iiii . I1Ii111
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , OOoo0oOoO , I11I1 ) )
 if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
 if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
 rloc . rloc . copy_address ( OOOo )
 lisp_myrlocs [ 0 ] = OOOo
 return
 if 61 - 61: I1ii11iIi11i
 if 12 - 12: OoO0O00
 if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
 if 7 - 7: Oo0Ooo
 if 38 - 38: Oo0Ooo - I1ii11iIi11i
 if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
 if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
 if 3 - 3: Ii1I
def lisp_update_encap_port ( mc ) :
 for OOOo0 in mc . rloc_set :
  Ii1IOo0Oo0oOoO = OOOo0 . normalize_decent_nat_rloc_name ( )
  i1o0 = lisp_get_nat_info ( OOOo0 . rloc , Ii1IOo0Oo0oOoO )
  if ( i1o0 == None ) : continue
  if ( OOOo0 . translated_port == i1o0 . port ) : continue
  if 71 - 71: iIii1I11I1II1 . OOooOOo / I11i / i1IIi
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( OOOo0 . translated_port , i1o0 . port ,
  # II111iiii % OoO0O00 / Oo0Ooo * Oo0Ooo % I11i
 red ( OOOo0 . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 89 - 89: Oo0Ooo . OoooooooOO * I1Ii111 / OoooooooOO * I1Ii111 * oO0o
  OOOo0 . store_translated_rloc ( OOOo0 . rloc , i1o0 . port )
  if 15 - 15: II111iiii - I11i - i11iIiiIii % Oo0Ooo * O0
 return
 if 46 - 46: i11iIiiIii * ooOoO0o
 if 36 - 36: OoOoOO00
 if 63 - 63: ooOoO0o
 if 83 - 83: Oo0Ooo % I1IiiI % I11i
 if 54 - 54: Oo0Ooo . oO0o * I11i . i1IIi / Oo0Ooo
 if 28 - 28: I1IiiI - I1IiiI % I11i * OOooOOo
 if 97 - 97: iII111i
 if 27 - 27: ooOoO0o + OOooOOo / I1ii11iIi11i % I1Ii111
 if 68 - 68: OOooOOo % OOooOOo
 if 61 - 61: I1ii11iIi11i - i1IIi
 if 53 - 53: o0oOOo0O0Ooo - I11i . I11i + OoooooooOO
 if 6 - 6: II111iiii + I1Ii111
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 17 - 17: iIii1I11I1II1 / I1ii11iIi11i
  if 85 - 85: o0oOOo0O0Ooo
 IiI1i11i = lisp_get_timestamp ( )
 iiIiIiII1iI1IIi = mc . last_refresh_time
 if 13 - 13: Oo0Ooo . I11i . II111iiii
 if 6 - 6: OOooOOo . IiII / OoO0O00 * oO0o - I1Ii111 . OoOoOO00
 if 85 - 85: i11iIiiIii + OoOoOO00
 if 4 - 4: OOooOOo . OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
 if 60 - 60: OOooOOo . Ii1I
 if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
 if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
 if ( lisp_is_running ( "lisp-ms" ) and lisp_uptime + ( 5 * 60 ) >= IiI1i11i ) :
  if ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
   iiIiIiII1iI1IIi = 0
   lprint ( "Remove startup-mode native-forward map-cache entry" )
   if 38 - 38: IiII / I11i / IiII * iII111i
   if 30 - 30: oO0o
   if 30 - 30: IiII / OoO0O00
   if 89 - 89: oO0o . OoOoOO00 . IiII / iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00
   if 86 - 86: OoooooooOO - iIii1I11I1II1 . OoO0O00 * Ii1I / I1Ii111 + I1Ii111
   if 52 - 52: iIii1I11I1II1 % OoO0O00 - IiII % i11iIiiIii - o0oOOo0O0Ooo
   if 25 - 25: Oo0Ooo - OOooOOo . i1IIi * OoOoOO00 / I11i / o0oOOo0O0Ooo
 OOOoOO0o00o0o = ( mc . action != LISP_NOT_REGISTERED_YET_ACTION )
 if 17 - 17: i1IIi - ooOoO0o
 if 86 - 86: I1ii11iIi11i . o0oOOo0O0Ooo
 if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
 if 33 - 33: OOooOOo % OoooooooOO
 if 98 - 98: Ii1I
 if 38 - 38: ooOoO0o - iII111i * OOooOOo % I1ii11iIi11i + Oo0Ooo
 if ( OOOoOO0o00o0o and iiIiIiII1iI1IIi + mc . map_cache_ttl > IiI1i11i ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 95 - 95: iIii1I11I1II1 / O0 % O0
  if 53 - 53: ooOoO0o . ooOoO0o
  if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
  if 18 - 18: OoO0O00 * ooOoO0o
  if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
 if ( lisp_nat_traversal and mc . eid . address == 0 and mc . eid . mask_len == 0 ) :
  return ( [ True , delete_list ] )
  if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
  if 67 - 67: I1IiiI
  if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
  if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
  if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
 ooooOOO0OoO = lisp_print_elapsed ( mc . uptime )
 iII1Iii = lisp_print_elapsed ( mc . last_refresh_time )
 o0oOOOooOOoo = mc . print_eid_tuple ( )
 lprint ( ( "Map-cache entry {} {}, had uptime {}, last-refresh-time {}, " + "action was {}" ) . format ( green ( o0oOOOooOOoo , False ) ,
 # IiII - OoO0O00 * OoO0O00 . i1IIi % OoooooooOO
 bold ( "timed out" , False ) , ooooOOO0OoO , iII1Iii ,
 lisp_map_reply_action_string [ mc . action ] ) )
 if 99 - 99: I1ii11iIi11i * IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
 if 65 - 65: Ii1I + OoOoOO00 * Oo0Ooo . O0 . IiII
 if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
 if 34 - 34: I1ii11iIi11i . i1IIi * O0 / OoooooooOO
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 22 - 22: OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
 if 58 - 58: IiII . Ii1I + II111iiii
 if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
 if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
 if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
def lisp_timeout_map_cache_walk ( mc , parms ) :
 O0O0o0oooOO0o = parms [ 0 ]
 OOoOOo0o0oo0Ooo = parms [ 1 ]
 if 16 - 16: I11i - ooOoO0o
 if 54 - 54: oO0o * II111iiii
 if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
 if 98 - 98: ooOoO0o
 if ( mc . group . is_null ( ) ) :
  OOOOO0OOoOOO , O0O0o0oooOO0o = lisp_timeout_map_cache_entry ( mc , O0O0o0oooOO0o )
  if ( O0O0o0oooOO0o == [ ] or mc != O0O0o0oooOO0o [ - 1 ] ) :
   OOoOOo0o0oo0Ooo = lisp_write_checkpoint_entry ( OOoOOo0o0oo0Ooo , mc )
   if 73 - 73: I1Ii111
  return ( [ OOOOO0OOoOOO , parms ] )
  if 97 - 97: OoO0O00 * Ii1I + Oo0Ooo
  if 83 - 83: II111iiii - Oo0Ooo % II111iiii * o0oOOo0O0Ooo
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
 if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
 if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
 if 76 - 76: iII111i * OOooOOo
 if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
 if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
 if 40 - 40: iII111i
 if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
 if 33 - 33: OoooooooOO
 if 59 - 59: i11iIiiIii - OoooooooOO . ooOoO0o / i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i
 if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
def lisp_timeout_map_cache ( lisp_map_cache ) :
 I1iI1i11IiI11 = [ [ ] , [ ] ]
 I1iI1i11IiI11 = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , I1iI1i11IiI11 )
 if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
 if 5 - 5: Oo0Ooo . I1Ii111
 if 77 - 77: i11iIiiIii / I1Ii111 / I1ii11iIi11i % oO0o
 if 83 - 83: Ii1I % iIii1I11I1II1 / I1ii11iIi11i + I11i
 if 23 - 23: iIii1I11I1II1 - I1IiiI
 O0O0o0oooOO0o = I1iI1i11IiI11 [ 0 ]
 for Ii111 in O0O0o0oooOO0o : Ii111 . delete_cache ( )
 if 51 - 51: OoooooooOO / IiII / I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * OoooooooOO
 if 40 - 40: OoO0O00 / IiII . O0 / I1IiiI + OoO0O00 . o0oOOo0O0Ooo
 if 25 - 25: ooOoO0o * I1Ii111 * oO0o
 if 64 - 64: Ii1I / I1ii11iIi11i
 OOoOOo0o0oo0Ooo = I1iI1i11IiI11 [ 1 ]
 lisp_checkpoint ( OOoOOo0o0oo0Ooo )
 return
 if 30 - 30: OoooooooOO + O0 / I1ii11iIi11i * o0oOOo0O0Ooo
 if 11 - 11: O0 + OoO0O00 - Oo0Ooo - Oo0Ooo . i11iIiiIii
 if 15 - 15: Ii1I % i11iIiiIii / OoOoOO00
 if 85 - 85: ooOoO0o . i1IIi / iII111i % iIii1I11I1II1 / II111iiii / I1Ii111
 if 60 - 60: iIii1I11I1II1 - iIii1I11I1II1 . I11i
 if 55 - 55: OoO0O00
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
def lisp_store_nat_info ( hostname , rloc , port ) :
 Oo0o = rloc . print_address_no_iid ( )
 iiI111I = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( Oo0o , False ) , port )
 if 22 - 22: i11iIiiIii - Ii1I + O0 - I1ii11iIi11i . Oo0Ooo
 iiOOO0O = lisp_nat_info ( Oo0o , hostname , port )
 if 21 - 21: Ii1I % Oo0Ooo . iII111i . O0 + iIii1I11I1II1
 if ( hostname not in lisp_nat_state_info ) :
  lisp_nat_state_info [ hostname ] = [ iiOOO0O ]
  lprint ( iiI111I . format ( "Store initial" ) )
  return ( True )
  if 42 - 42: oO0o . OOooOOo * OoO0O00
  if 88 - 88: I1ii11iIi11i
  if 21 - 21: i1IIi . I1IiiI / OoooooooOO % oO0o
  if 31 - 31: O0
  if 37 - 37: Oo0Ooo . OoOoOO00 % I1ii11iIi11i * O0
  if 20 - 20: ooOoO0o + I1IiiI - IiII % ooOoO0o - IiII . oO0o
 i1o0 = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( i1o0 . address == Oo0o and i1o0 . port == port ) :
  i1o0 . uptime = lisp_get_timestamp ( )
  lprint ( iiI111I . format ( "Refresh existing" ) )
  return ( False )
  if 39 - 39: O0 / oO0o % oO0o * iIii1I11I1II1
  if 7 - 7: iII111i % o0oOOo0O0Ooo / II111iiii % IiII / iIii1I11I1II1
  if 17 - 17: I11i * I11i - O0 / IiII + OoOoOO00
  if 65 - 65: I1Ii111 * i1IIi
  if 10 - 10: OOooOOo % IiII
  if 20 - 20: I11i / OoooooooOO % OoOoOO00 . oO0o * I1IiiI % IiII
  if 84 - 84: I1ii11iIi11i % I11i / OOooOOo % O0
 o0oO = None
 for i1o0 in lisp_nat_state_info [ hostname ] :
  if ( i1o0 . address == Oo0o and i1o0 . port == port ) :
   o0oO = i1o0
   break
   if 38 - 38: i1IIi . I1IiiI + II111iiii * OoO0O00 / IiII
   if 60 - 60: II111iiii
   if 68 - 68: O0 / I1IiiI / OoOoOO00 / iIii1I11I1II1 % O0 + I1IiiI
 if ( o0oO == None ) :
  lprint ( iiI111I . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( o0oO )
  lprint ( iiI111I . format ( "Use previous" ) )
  if 23 - 23: OoooooooOO . OoO0O00 . OoooooooOO * I1ii11iIi11i - Oo0Ooo - iIii1I11I1II1
  if 91 - 91: iIii1I11I1II1 * Ii1I
 I11iIIi = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ iiOOO0O ] + I11iIIi
 return ( True )
 if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
 if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
 if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
 if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
 if 40 - 40: iII111i - I1IiiI + OoOoOO00
 if 2 - 2: I11i - II111iiii / I1Ii111
 if 27 - 27: OoO0O00 - I1ii11iIi11i * i11iIiiIii + Oo0Ooo
def lisp_get_nat_info ( rloc , hostname ) :
 Oo0o = rloc . print_address_no_iid ( )
 if 29 - 29: I1ii11iIi11i / IiII . I1Ii111 + Ii1I + OoO0O00
 if ( hostname == None ) :
  for hostname in lisp_nat_state_info :
   for i1o0 in lisp_nat_state_info [ hostname ] :
    if ( i1o0 . address == Oo0o ) : return ( i1o0 )
    if 76 - 76: ooOoO0o . I11i * OoO0O00
    if 53 - 53: II111iiii / OoOoOO00 / IiII * oO0o
  return ( None )
  if 52 - 52: O0 % iII111i * iIii1I11I1II1 / I11i / I1IiiI * ooOoO0o
  if 93 - 93: iIii1I11I1II1 . II111iiii * OOooOOo - iIii1I11I1II1 . oO0o % Oo0Ooo
 if ( hostname not in lisp_nat_state_info ) : return ( None )
 if 92 - 92: OoO0O00
 for i1o0 in lisp_nat_state_info [ hostname ] :
  if ( i1o0 . address == Oo0o ) : return ( i1o0 )
  if 42 - 42: I1ii11iIi11i - iIii1I11I1II1 % ooOoO0o
 return ( None )
 if 7 - 7: Oo0Ooo / ooOoO0o + o0oOOo0O0Ooo
 if 38 - 38: o0oOOo0O0Ooo . O0 - OoO0O00 % I11i
 if 80 - 80: o0oOOo0O0Ooo
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
 if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
 if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
 if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
 if 47 - 47: OOooOOo + IiII
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
 if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
 if 64 - 64: Ii1I
 if 4 - 4: OoOoOO00
 if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
 if 48 - 48: iII111i / II111iiii * I1Ii111 + I11i / ooOoO0o . OoOoOO00
 iI11 = [ ]
 i1IIiIi1 = [ ]
 if ( dest == None ) :
  for o0O0oOoOO in list ( lisp_map_resolvers_list . values ( ) ) :
   i1IIiIi1 . append ( o0O0oOoOO . map_resolver )
   if 9 - 9: II111iiii * Oo0Ooo * I1Ii111 . IiII
  iI11 = i1IIiIi1
  if ( iI11 == [ ] ) :
   for IiiiiiOoO0 in list ( lisp_map_servers_list . values ( ) ) :
    iI11 . append ( IiiiiiOoO0 . map_server )
    if 80 - 80: i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - OOooOOo * OoooooooOO
    if 96 - 96: oO0o
  if ( iI11 == [ ] ) : return
 else :
  iI11 . append ( dest )
  if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
  if 64 - 64: I1IiiI % i11iIiiIii / oO0o
  if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
  if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
  if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
 iiiii11iiI = { }
 for Oo0000 in lisp_db_list :
  for oO0O0oOOO0 in Oo0000 . rloc_set :
   lisp_update_local_rloc ( oO0O0oOOO0 )
   if ( oO0O0oOOO0 . rloc . is_null ( ) ) : continue
   if ( oO0O0oOOO0 . interface == None ) : continue
   if 31 - 31: OoO0O00
   OOOo = oO0O0oOOO0 . rloc . print_address_no_iid ( )
   if ( OOOo in iiiii11iiI ) : continue
   iiiii11iiI [ OOOo ] = oO0O0oOOO0 . interface
   if 89 - 89: II111iiii
   if 33 - 33: OOooOOo / oO0o % OoOoOO00 * O0
 if ( iiiii11iiI == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 65 - 65: OoO0O00 % OoOoOO00 % I1ii11iIi11i / OoooooooOO
  return
  if 85 - 85: O0 * OOooOOo % I1Ii111
  if 33 - 33: O0
 if ( len ( iiiii11iiI ) > 1 ) :
  lprint ( "NAT multihoming local RLOC-list {}" . format ( iiiii11iiI ) )
  if 30 - 30: II111iiii . O0 . oO0o * I1ii11iIi11i + oO0o . o0oOOo0O0Ooo
  if 43 - 43: iIii1I11I1II1
  if 88 - 88: I1IiiI - OoO0O00 . O0 . oO0o
  if 75 - 75: II111iiii % OOooOOo / iIii1I11I1II1 / OoO0O00 + oO0o
  if 16 - 16: oO0o + I1Ii111 - II111iiii - o0oOOo0O0Ooo / i11iIiiIii
  if 59 - 59: OOooOOo - o0oOOo0O0Ooo
 for OOOo in iiiii11iiI :
  i1i1111I = iiiii11iiI [ OOOo ]
  oO = red ( OOOo , False )
  lprint ( "Build Info-Request for private address {} on {}" . format ( oO ,
 i1i1111I ) )
  OoO0 = i1i1111I if len ( iiiii11iiI ) > 1 else None
  for dest in iI11 :
   lisp_send_info_request ( lisp_sockets , dest , port , OoO0 )
   if 82 - 82: IiII % ooOoO0o - OoO0O00 % ooOoO0o
   if 51 - 51: ooOoO0o % iII111i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
   if 20 - 20: i1IIi - ooOoO0o % OoooooooOO * I1ii11iIi11i + II111iiii % i1IIi
   if 30 - 30: i11iIiiIii - I1IiiI + o0oOOo0O0Ooo + IiII
   if 16 - 16: I1ii11iIi11i / Ii1I + I1ii11iIi11i * I1Ii111
   if 49 - 49: ooOoO0o * OoOoOO00 . OoooooooOO . ooOoO0o + Oo0Ooo * IiII
 if ( i1IIiIi1 != [ ] ) :
  for o0O0oOoOO in list ( lisp_map_resolvers_list . values ( ) ) :
   o0O0oOoOO . resolve_dns_name ( )
   if 47 - 47: iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
   if 84 - 84: o0oOOo0O0Ooo * I11i
 return
 if 22 - 22: i1IIi + OOooOOo % OoooooooOO
 if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
 if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
 if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
 if 66 - 66: OoooooooOO
 if 90 - 90: IiII - OoOoOO00
 if 98 - 98: Oo0Ooo / oO0o . Ii1I
 if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 37 - 37: iII111i - Ii1I . oO0o
 if 47 - 47: IiII / I1ii11iIi11i . o0oOOo0O0Ooo . ooOoO0o + OOooOOo . OOooOOo
 if 25 - 25: oO0o
 if 43 - 43: Ii1I - o0oOOo0O0Ooo % oO0o - O0
 if 20 - 20: OoO0O00 . ooOoO0o / OoOoOO00 - OoOoOO00 . iII111i / OOooOOo
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 39 - 39: iIii1I11I1II1 % ooOoO0o
 if 75 - 75: i1IIi * II111iiii * O0 * i11iIiiIii % iII111i / iII111i
 if 36 - 36: IiII / I1IiiI % iII111i / iII111i
 if 38 - 38: OOooOOo * I1ii11iIi11i * I1Ii111 + I11i
 if ( value . find ( "." ) != - 1 ) :
  OOOo = value . split ( "." )
  if ( len ( OOOo ) != 4 ) : return ( False )
  if 65 - 65: O0 + O0 * I1Ii111
  for iIiiIII in OOOo :
   if ( iIiiIII . isdigit ( ) == False ) : return ( False )
   if ( int ( iIiiIII ) > 255 ) : return ( False )
   if 66 - 66: OOooOOo / O0 + i1IIi . O0 % I1ii11iIi11i - OoooooooOO
  return ( True )
  if 16 - 16: I11i % iII111i
  if 29 - 29: I1IiiI - ooOoO0o * OoO0O00 . i11iIiiIii % OoOoOO00 * o0oOOo0O0Ooo
  if 43 - 43: OoO0O00 * OOooOOo / I1Ii111 % OoOoOO00 . oO0o / OOooOOo
  if 62 - 62: O0 * I1ii11iIi11i - O0 / I11i % ooOoO0o
  if 1 - 1: O0 / iIii1I11I1II1
 if ( value . find ( "-" ) != - 1 ) :
  OOOo = value . split ( "-" )
  for iIiIIi in [ "N" , "S" , "W" , "E" ] :
   if ( iIiIIi in OOOo ) :
    if ( len ( OOOo ) < 8 ) : return ( False )
    return ( True )
    if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
    if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
    if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
    if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
    if 16 - 16: o0oOOo0O0Ooo
    if 3 - 3: i11iIiiIii . I1ii11iIi11i
    if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
 if ( value . find ( "-" ) != - 1 ) :
  OOOo = value . split ( "-" )
  if ( len ( OOOo ) != 3 ) : return ( False )
  if 83 - 83: OoooooooOO % I1ii11iIi11i . IiII + OOooOOo . iII111i - ooOoO0o
  for o0O000Oo in OOOo :
   try : int ( o0O000Oo , 16 )
   except : return ( False )
   if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
  return ( True )
  if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
  if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
  if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
  if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
  if 76 - 76: OoO0O00
 if ( value . find ( ":" ) != - 1 ) :
  OOOo = value . split ( ":" )
  if ( len ( OOOo ) < 2 ) : return ( False )
  if 92 - 92: iIii1I11I1II1 * O0 % I11i
  oOO000 = False
  IiI = 0
  for o0O000Oo in OOOo :
   IiI += 1
   if ( o0O000Oo == "" ) :
    if ( oOO000 ) :
     if ( len ( OOOo ) == IiI ) : break
     if ( IiI > 2 ) : return ( False )
     if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1
    oOO000 = True
    continue
    if 2 - 2: Oo0Ooo + II111iiii * O0 / iIii1I11I1II1 / iIii1I11I1II1
   try : int ( o0O000Oo , 16 )
   except : return ( False )
   if 33 - 33: OOooOOo * OOooOOo . II111iiii % O0 % O0 % o0oOOo0O0Ooo
  return ( True )
  if 45 - 45: OoooooooOO * oO0o
  if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
  if 16 - 16: Oo0Ooo
  if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
  if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 if ( value [ 0 ] == "+" ) :
  OOOo = value [ 1 : : ]
  for o00o0I11I in OOOo :
   if ( o00o0I11I . isdigit ( ) == False ) : return ( False )
   if 71 - 71: Ii1I % iIii1I11I1II1 + OoOoOO00
  return ( True )
  if 19 - 19: I1IiiI % I1IiiI / I1ii11iIi11i + iIii1I11I1II1 % iII111i / i11iIiiIii
 return ( False )
 if 30 - 30: i1IIi % o0oOOo0O0Ooo - I1ii11iIi11i
 if 72 - 72: iIii1I11I1II1 + OOooOOo * ooOoO0o * O0 - I1IiiI
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
def lisp_process_api ( process , lisp_socket , data_structure ) :
 oo000O0o00 , I1iI1i11IiI11 = data_structure . split ( "%" )
 if 9 - 9: oO0o / ooOoO0o . i1IIi - O0 + I11i
 lprint ( "Process API request '{}', parameters: '{}'" . format ( oo000O0o00 ,
 I1iI1i11IiI11 ) )
 if 71 - 71: OoOoOO00
 iii = [ ]
 if ( oo000O0o00 == "map-cache" ) :
  if ( I1iI1i11IiI11 == "" ) :
   iii = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , iii )
  else :
   iii = lisp_process_api_map_cache_entry ( json . loads ( I1iI1i11IiI11 ) )
   if 29 - 29: O0 . i11iIiiIii
   if 51 - 51: IiII
 if ( oo000O0o00 == "site-cache" ) :
  if ( I1iI1i11IiI11 == "" ) :
   iii = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 iii )
  else :
   iii = lisp_process_api_site_cache_entry ( json . loads ( I1iI1i11IiI11 ) )
   if 53 - 53: O0
   if 19 - 19: o0oOOo0O0Ooo / iII111i % OoOoOO00
 if ( oo000O0o00 == "site-cache-summary" ) :
  iii = lisp_process_api_site_cache_summary ( lisp_sites_by_eid )
  if 65 - 65: o0oOOo0O0Ooo
 if ( oo000O0o00 == "map-server" ) :
  I1iI1i11IiI11 = { } if ( I1iI1i11IiI11 == "" ) else json . loads ( I1iI1i11IiI11 )
  iii = lisp_process_api_ms_or_mr ( True , I1iI1i11IiI11 )
  if 89 - 89: iIii1I11I1II1 + OoooooooOO + i1IIi + OoooooooOO % IiII * OoO0O00
 if ( oo000O0o00 == "map-resolver" ) :
  I1iI1i11IiI11 = { } if ( I1iI1i11IiI11 == "" ) else json . loads ( I1iI1i11IiI11 )
  iii = lisp_process_api_ms_or_mr ( False , I1iI1i11IiI11 )
  if 53 - 53: OOooOOo . IiII % I11i - OoO0O00 - Oo0Ooo
 if ( oo000O0o00 == "database-mapping" ) :
  iii = lisp_process_api_database_mapping ( )
  if 58 - 58: I1Ii111 / OoooooooOO . I11i % I1Ii111
  if 8 - 8: Oo0Ooo % ooOoO0o / i11iIiiIii
  if 54 - 54: IiII
  if 85 - 85: OOooOOo - i1IIi
  if 10 - 10: I1ii11iIi11i
 iii = json . dumps ( iii )
 I1Iii1 = lisp_api_ipc ( process , iii )
 lisp_ipc ( I1Iii1 , lisp_socket , "lisp-core" )
 return
 if 3 - 3: ooOoO0o * O0 / o0oOOo0O0Ooo
 if 22 - 22: OoOoOO00 + OOooOOo . iII111i % iIii1I11I1II1 - I11i
 if 23 - 23: OoOoOO00 * I1Ii111
 if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
 if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
 if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
 if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
def lisp_process_api_map_cache ( mc , data ) :
 if 25 - 25: OoO0O00 * oO0o
 if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
 if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
 if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 73 - 73: Oo0Ooo + II111iiii - IiII
 if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
 if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
 if 66 - 66: II111iiii * I1IiiI . Oo0Ooo * OoooooooOO % OoOoOO00 . II111iiii
 if 4 - 4: iII111i + I1Ii111 % OoOoOO00 / Ii1I
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 94 - 94: OoO0O00
 if 35 - 35: I1ii11iIi11i % OoO0O00 + II111iiii % II111iiii / IiII - iII111i
 if 9 - 9: I1ii11iIi11i * o0oOOo0O0Ooo . oO0o
 if 48 - 48: IiII . I1Ii111 + OoooooooOO - I1Ii111 . Ii1I . I1Ii111
 if 24 - 24: ooOoO0o * iIii1I11I1II1
 if 1 - 1: I1ii11iIi11i . O0
 if 3 - 3: iIii1I11I1II1 * ooOoO0o - OoOoOO00 * I1ii11iIi11i % OoOoOO00 - OoooooooOO
def lisp_gather_map_cache_data ( mc , data ) :
 iIiiI11II11i = { }
 iIiiI11II11i [ "instance-id" ] = str ( mc . eid . instance_id )
 iIiiI11II11i [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  iIiiI11II11i [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 42 - 42: I1Ii111 - i1IIi
 iIiiI11II11i [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 iIiiI11II11i [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 iIiiI11II11i [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 iIiiI11II11i [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 91 - 91: iII111i . OOooOOo / iIii1I11I1II1 . Oo0Ooo . II111iiii . OoOoOO00
 if 31 - 31: OoO0O00 . I1ii11iIi11i % I11i - II111iiii
 if 70 - 70: ooOoO0o - IiII - OoO0O00 / I11i
 if 59 - 59: IiII % ooOoO0o . iII111i / Ii1I * Ii1I
 if 73 - 73: I1ii11iIi11i . oO0o % I11i . I1ii11iIi11i / I1Ii111 / II111iiii
 oO0O0O0O0OO = [ ]
 for OOOo0 in mc . rloc_set :
  o0O00o0o = lisp_fill_rloc_in_json ( OOOo0 )
  if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
  if 76 - 76: I1Ii111
  if 91 - 91: iIii1I11I1II1 / Ii1I . I1IiiI
  if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
  if 85 - 85: II111iiii + I1ii11iIi11i
  if ( OOOo0 . rloc . is_multicast_address ( ) ) :
   o0O00o0o [ "multicast-rloc-set" ] = [ ]
   for i1i11iiII in list ( OOOo0 . multicast_rloc_probe_list . values ( ) ) :
    o0O0oOoOO = lisp_fill_rloc_in_json ( i1i11iiII )
    o0O00o0o [ "multicast-rloc-set" ] . append ( o0O0oOoOO )
    if 33 - 33: iII111i
    if 14 - 14: O0 * Oo0Ooo / i1IIi
    if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
  oO0O0O0O0OO . append ( o0O00o0o )
  if 78 - 78: II111iiii % OOooOOo
 iIiiI11II11i [ "rloc-set" ] = oO0O0O0O0OO
 if 6 - 6: OOooOOo
 data . append ( iIiiI11II11i )
 return ( [ True , data ] )
 if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
 if 55 - 55: OOooOOo + oO0o - II111iiii
 if 5 - 5: iII111i * OoooooooOO . OoO0O00 % ooOoO0o + Ii1I
 if 59 - 59: OoOoOO00
 if 96 - 96: I1IiiI
 if 3 - 3: OoooooooOO
 if 3 - 3: IiII / O0 * i11iIiiIii . iII111i - iIii1I11I1II1
 if 56 - 56: ooOoO0o
def lisp_fill_rloc_in_json ( rloc ) :
 o0O00o0o = { }
 Oo0o = None
 if ( rloc . rloc_exists ( ) ) :
  o0O00o0o [ "address" ] = rloc . rloc . print_address_no_iid ( )
  Oo0o = o0O00o0o [ "address" ]
  if 82 - 82: ooOoO0o . IiII . I1Ii111 - iIii1I11I1II1 + II111iiii . OoOoOO00
  if 59 - 59: Oo0Ooo
 if ( rloc . translated_port != 0 ) :
  o0O00o0o [ "encap-port" ] = str ( rloc . translated_port )
  Oo0o += ":" + o0O00o0o [ "encap-port" ]
  if 98 - 98: I1Ii111 * II111iiii / Oo0Ooo . Oo0Ooo % I1Ii111
  if 52 - 52: OoOoOO00
 if ( Oo0o and Oo0o in lisp_crypto_keys_by_rloc_encap ) :
  III11II111 = lisp_crypto_keys_by_rloc_encap [ Oo0o ] [ 1 ]
  if ( III11II111 != None and III11II111 . shared_key != None ) :
   o0O00o0o [ "encap-crypto" ] = "crypto-" + III11II111 . cipher_suite_string
   if 59 - 59: ooOoO0o / OoooooooOO
   if 71 - 71: OOooOOo + I11i * O0 / o0oOOo0O0Ooo + I1IiiI + Ii1I
   if 41 - 41: ooOoO0o * I1Ii111
 o0O00o0o [ "state" ] = rloc . print_state ( )
 if ( rloc . geo ) : o0O00o0o [ "geo" ] = rloc . geo . print_geo ( )
 if ( rloc . elp ) : o0O00o0o [ "elp" ] = rloc . elp . print_elp ( False )
 if ( rloc . rle ) : o0O00o0o [ "rle" ] = rloc . rle . print_rle ( False , False )
 if ( rloc . json ) : o0O00o0o [ "json" ] = rloc . json . print_json ( False )
 if ( rloc . rloc_name ) : o0O00o0o [ "rloc-name" ] = rloc . rloc_name
 oooo0o0o0oO = rloc . stats . get_stats ( False , False )
 if ( oooo0o0o0oO ) :
  o0O00o0o [ "stats" ] = oooo0o0o0oO
  o0O00o0o [ "recent-packet-sec" ] = rloc . stats . recent_packet_sec ( )
  o0O00o0o [ "recent-packet-min" ] = rloc . stats . recent_packet_min ( )
  if 40 - 40: OoOoOO00
 O00i1iii = lisp_print_elapsed ( rloc . last_state_change )
 if ( O00i1iii == "never" ) :
  O00i1iii = lisp_print_elapsed ( rloc . uptime )
  if 65 - 65: I11i % i11iIiiIii + i11iIiiIii % II111iiii
 o0O00o0o [ "uptime" ] = O00i1iii
 o0O00o0o [ "upriority" ] = str ( rloc . priority )
 o0O00o0o [ "uweight" ] = str ( rloc . weight )
 o0O00o0o [ "mpriority" ] = str ( rloc . mpriority )
 o0O00o0o [ "mweight" ] = str ( rloc . mweight )
 O0o0ooooO = rloc . last_rloc_probe_reply
 if ( O0o0ooooO ) :
  o0O00o0o [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( O0o0ooooO )
  o0O00o0o [ "rloc-probe-rtt" ] = str ( rloc . rloc_probe_rtt )
  if 29 - 29: Ii1I * iIii1I11I1II1 * i1IIi
 o0O00o0o [ "rloc-hop-count" ] = rloc . rloc_probe_hops
 o0O00o0o [ "recent-rloc-hop-counts" ] = rloc . recent_rloc_probe_hops
 if 83 - 83: oO0o % O0 . I11i / I11i / I1IiiI - OoOoOO00
 o0O00o0o [ "rloc-probe-latency" ] = rloc . rloc_probe_latency
 o0O00o0o [ "recent-rloc-probe-latencies" ] = rloc . recent_rloc_probe_latencies
 if 91 - 91: iIii1I11I1II1 - IiII + iIii1I11I1II1 % Oo0Ooo % I1IiiI
 OoOIIiI = [ ]
 for I1iiiiIIiiI1i in rloc . recent_rloc_probe_rtts : OoOIIiI . append ( str ( I1iiiiIIiiI1i ) )
 o0O00o0o [ "recent-rloc-probe-rtts" ] = OoOIIiI
 return ( o0O00o0o )
 if 67 - 67: ooOoO0o + I11i - I1ii11iIi11i - OoooooooOO
 if 37 - 37: I11i % I1IiiI
 if 32 - 32: OOooOOo + OoooooooOO . IiII . Oo0Ooo * iII111i
 if 86 - 86: I1ii11iIi11i . iII111i + Ii1I - IiII / i11iIiiIii + OoOoOO00
 if 50 - 50: o0oOOo0O0Ooo - IiII + OoOoOO00 - II111iiii
 if 24 - 24: I1Ii111 - IiII % I1IiiI - OoooooooOO % Ii1I
 if 56 - 56: I1ii11iIi11i
def lisp_process_api_map_cache_entry ( parms ) :
 oO0O = parms [ "instance-id" ]
 oO0O = 0 if ( oO0O == "" ) else int ( oO0O )
 if 40 - 40: OoooooooOO
 if 100 - 100: IiII - I11i
 if 79 - 79: iII111i % O0
 if 73 - 73: Oo0Ooo
 oO0OooO0o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , oO0O )
 oO0OooO0o0 . store_prefix ( parms [ "eid-prefix" ] )
 OooOOooo = oO0OooO0o0
 iiIIiIi1i1I1 = oO0OooO0o0
 if 13 - 13: OOooOOo - ooOoO0o
 if 8 - 8: I1Ii111 % oO0o
 if 19 - 19: O0 + OoO0O00 - i1IIi % OoOoOO00 / Oo0Ooo + OoooooooOO
 if 93 - 93: i11iIiiIii % OOooOOo . I11i * ooOoO0o
 if 90 - 90: OoO0O00
 iII1I1i = lisp_address ( LISP_AFI_NONE , "" , 0 , oO0O )
 if ( "group-prefix" in parms ) :
  iII1I1i . store_prefix ( parms [ "group-prefix" ] )
  OooOOooo = iII1I1i
  if 54 - 54: OOooOOo + Oo0Ooo * o0oOOo0O0Ooo - iIii1I11I1II1 * ooOoO0o
  if 76 - 76: i11iIiiIii * I1IiiI - IiII . o0oOOo0O0Ooo % iII111i . i11iIiiIii
 iii = [ ]
 Ii111 = lisp_map_cache_lookup ( iiIIiIi1i1I1 , OooOOooo )
 if ( Ii111 ) : OOOOO0OOoOOO , iii = lisp_process_api_map_cache ( Ii111 , iii )
 return ( iii )
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
def lisp_process_api_site_cache_summary ( site_cache ) :
 OOOOoooO = { "site" : "" , "registrations" : [ ] }
 iIiiI11II11i = { "eid-prefix" : "" , "count" : 0 , "registered-count" : 0 }
 if 55 - 55: Ii1I . OoooooooOO % Ii1I . IiII
 oooOoooOO = { }
 for OoOO0oo0OOOO in site_cache . cache_sorted :
  for IiII1I1 in list ( site_cache . cache [ OoOO0oo0OOOO ] . entries . values ( ) ) :
   if ( IiII1I1 . accept_more_specifics == False ) : continue
   if ( IiII1I1 . site . site_name not in oooOoooOO ) :
    oooOoooOO [ IiII1I1 . site . site_name ] = [ ]
    if 12 - 12: I1IiiI
   o0o00oO0oo000 = copy . deepcopy ( iIiiI11II11i )
   o0o00oO0oo000 [ "eid-prefix" ] = IiII1I1 . eid . print_prefix ( )
   o0o00oO0oo000 [ "count" ] = len ( IiII1I1 . more_specific_registrations )
   for iiiii1I1iI1ii in IiII1I1 . more_specific_registrations :
    if ( iiiii1I1iI1ii . registered ) : o0o00oO0oo000 [ "registered-count" ] += 1
    if 13 - 13: i1IIi
   oooOoooOO [ IiII1I1 . site . site_name ] . append ( o0o00oO0oo000 )
   if 19 - 19: I11i - I1IiiI / oO0o / IiII / oO0o % o0oOOo0O0Ooo
   if 42 - 42: I1ii11iIi11i
   if 22 - 22: IiII + I1ii11iIi11i + i11iIiiIii
 iii = [ ]
 for O0O0o in oooOoooOO :
  o0O0o0000o0O0 = copy . deepcopy ( OOOOoooO )
  o0O0o0000o0O0 [ "site" ] = O0O0o
  o0O0o0000o0O0 [ "registrations" ] = oooOoooOO [ O0O0o ]
  iii . append ( o0O0o0000o0O0 )
  if 3 - 3: o0oOOo0O0Ooo . oO0o + IiII + OoO0O00
 return ( iii )
 if 89 - 89: iIii1I11I1II1 / OoooooooOO
 if 28 - 28: i11iIiiIii / O0 / iIii1I11I1II1 / I1IiiI % OoooooooOO % ooOoO0o
 if 29 - 29: I1ii11iIi11i
 if 12 - 12: I11i . o0oOOo0O0Ooo . iIii1I11I1II1
 if 93 - 93: ooOoO0o - OoooooooOO + iIii1I11I1II1 / o0oOOo0O0Ooo + iIii1I11I1II1
 if 9 - 9: OoOoOO00 + ooOoO0o
 if 61 - 61: i11iIiiIii + OOooOOo - i1IIi
def lisp_process_api_site_cache ( se , data ) :
 if 2 - 2: I1ii11iIi11i / I1Ii111 / I1ii11iIi11i / iII111i * i11iIiiIii % iII111i
 if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
 if 63 - 63: oO0o * OoO0O00 * oO0o
 if 31 - 31: Oo0Ooo
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 67 - 67: I1Ii111 . I1ii11iIi11i
 if 2 - 2: O0 + I1Ii111
 if 82 - 82: Ii1I / iII111i
 if 13 - 13: I11i + iII111i
 if 54 - 54: I1ii11iIi11i - I1IiiI . Ii1I
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 59 - 59: Oo0Ooo + I1ii11iIi11i
 if 87 - 87: ooOoO0o * OoooooooOO + OoO0O00 + oO0o - I1Ii111
 if 70 - 70: i1IIi . Ii1I / Ii1I
 if 9 - 9: iII111i + I1Ii111 + iII111i % ooOoO0o + i11iIiiIii + i11iIiiIii
 if 45 - 45: i1IIi + I1ii11iIi11i
 if 49 - 49: i11iIiiIii . I1ii11iIi11i
 if 91 - 91: ooOoO0o - OOooOOo - OOooOOo * o0oOOo0O0Ooo
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 iii1 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 i1o00O = data [ "dns-name" ] if ( "dns-name" in data ) else None
 if ( "address" in data ) :
  iii1 . store_address ( data [ "address" ] )
  if 33 - 33: II111iiii
  if 39 - 39: ooOoO0o + I11i
 IiIi1i = { }
 if ( ms_or_mr ) :
  for IiiiiiOoO0 in list ( lisp_map_servers_list . values ( ) ) :
   if ( i1o00O ) :
    if ( i1o00O != IiiiiiOoO0 . dns_name ) : continue
   else :
    if ( iii1 . is_exact_match ( IiiiiiOoO0 . map_server ) == False ) : continue
    if 24 - 24: o0oOOo0O0Ooo
    if 5 - 5: i11iIiiIii - oO0o + o0oOOo0O0Ooo % ooOoO0o
   IiIi1i [ "dns-name" ] = IiiiiiOoO0 . dns_name
   IiIi1i [ "address" ] = IiiiiiOoO0 . map_server . print_address_no_iid ( )
   IiIi1i [ "ms-name" ] = "" if IiiiiiOoO0 . ms_name == None else IiiiiiOoO0 . ms_name
   return ( [ IiIi1i ] )
   if 63 - 63: oO0o
 else :
  for o0O0oOoOO in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( i1o00O ) :
    if ( i1o00O != o0O0oOoOO . dns_name ) : continue
   else :
    if ( iii1 . is_exact_match ( o0O0oOoOO . map_resolver ) == False ) : continue
    if 7 - 7: IiII / i11iIiiIii - OOooOOo
    if 9 - 9: II111iiii + i11iIiiIii % I1Ii111 - Oo0Ooo * OOooOOo
   IiIi1i [ "dns-name" ] = o0O0oOoOO . dns_name
   IiIi1i [ "address" ] = o0O0oOoOO . map_resolver . print_address_no_iid ( )
   IiIi1i [ "mr-name" ] = "" if o0O0oOoOO . mr_name == None else o0O0oOoOO . mr_name
   return ( [ IiIi1i ] )
   if 55 - 55: I1Ii111 + ooOoO0o
   if 58 - 58: iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
 return ( [ ] )
 if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
 if 96 - 96: OOooOOo % o0oOOo0O0Ooo / iIii1I11I1II1
 if 60 - 60: i1IIi / iIii1I11I1II1 + I11i % iII111i
 if 64 - 64: I11i . i11iIiiIii / iIii1I11I1II1 . I11i
 if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
 if 20 - 20: I11i % I1ii11iIi11i . OoO0O00 % OoOoOO00
 if 84 - 84: OoooooooOO / i11iIiiIii . IiII / I1IiiI
 if 62 - 62: iII111i - I1IiiI + OoooooooOO
def lisp_process_api_database_mapping ( ) :
 iii = [ ]
 if 59 - 59: iIii1I11I1II1 + i11iIiiIii * oO0o . Oo0Ooo . I1Ii111
 for Oo0000 in lisp_db_list :
  iIiiI11II11i = { }
  iIiiI11II11i [ "eid-prefix" ] = Oo0000 . eid . print_prefix ( )
  if ( Oo0000 . group . is_null ( ) == False ) :
   iIiiI11II11i [ "group-prefix" ] = Oo0000 . group . print_prefix ( )
   if 49 - 49: II111iiii
   if 99 - 99: Oo0Ooo . OOooOOo
  oOo000O00O0 = [ ]
  for o0O00o0o in Oo0000 . rloc_set :
   OOOo0 = { }
   if ( o0O00o0o . rloc . is_null ( ) == False ) :
    OOOo0 [ "rloc" ] = o0O00o0o . rloc . print_address_no_iid ( )
    if 85 - 85: OoOoOO00 . IiII + oO0o - II111iiii
   if ( o0O00o0o . rloc_name != None ) : OOOo0 [ "rloc-name" ] = o0O00o0o . rloc_name
   if ( o0O00o0o . interface != None ) : OOOo0 [ "interface" ] = o0O00o0o . interface
   oo0oO0OoO00 = o0O00o0o . translated_rloc
   if ( oo0oO0OoO00 . is_null ( ) == False ) :
    OOOo0 [ "translated-rloc" ] = oo0oO0OoO00 . print_address_no_iid ( )
    if ( o0O00o0o . translated_port != 0 ) :
     OOOo0 [ "translated-port" ] = o0O00o0o . translated_port
     if 89 - 89: Ii1I / Oo0Ooo * o0oOOo0O0Ooo / OoO0O00 + I11i
     if 4 - 4: I11i
   if ( OOOo0 != { } ) : oOo000O00O0 . append ( OOOo0 )
   if 59 - 59: OoOoOO00 * I1ii11iIi11i / I1IiiI * II111iiii + OoOoOO00
   if 6 - 6: OoOoOO00 % oO0o + I11i * Ii1I
   if 13 - 13: I1ii11iIi11i / Oo0Ooo - I1Ii111 * OoOoOO00
   if 47 - 47: IiII
   if 76 - 76: iII111i / II111iiii / I11i
  iIiiI11II11i [ "rlocs" ] = oOo000O00O0
  if 62 - 62: I1ii11iIi11i
  if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
  if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
  if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
  iii . append ( iIiiI11II11i )
  if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
 return ( iii )
 if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
 if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
 if 71 - 71: i1IIi
 if 79 - 79: iII111i * O0 / Ii1I / O0 % i1IIi
 if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
 if 62 - 62: Ii1I . I1ii11iIi11i . iII111i + I11i * o0oOOo0O0Ooo
 if 56 - 56: oO0o * iIii1I11I1II1 . II111iiii - II111iiii + II111iiii - i11iIiiIii
def lisp_gather_site_cache_data ( se , data ) :
 iIiiI11II11i = { }
 iIiiI11II11i [ "site-name" ] = se . site . site_name
 iIiiI11II11i [ "instance-id" ] = str ( se . eid . instance_id )
 iIiiI11II11i [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  iIiiI11II11i [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 79 - 79: iII111i
 iIiiI11II11i [ "registered" ] = "yes" if se . registered else "no"
 iIiiI11II11i [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 iIiiI11II11i [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 29 - 29: Ii1I * I1Ii111 / OoO0O00 - O0 - i11iIiiIii * I1IiiI
 OOOo = se . last_registerer
 OOOo = "none" if OOOo . is_null ( ) else OOOo . print_address ( )
 iIiiI11II11i [ "last-registerer" ] = OOOo
 iIiiI11II11i [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 iIiiI11II11i [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 iIiiI11II11i [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  iIiiI11II11i [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 2 - 2: OoOoOO00 . I1ii11iIi11i * I1ii11iIi11i
  if 42 - 42: OoO0O00 . OoO0O00 + II111iiii - IiII - OOooOOo * Oo0Ooo
  if 47 - 47: oO0o - OoooooooOO + iII111i
  if 69 - 69: I1ii11iIi11i - I1IiiI % oO0o + OOooOOo - I1Ii111
  if 5 - 5: ooOoO0o . OoO0O00
 oO0O0O0O0OO = [ ]
 for OOOo0 in se . registered_rlocs :
  o0O00o0o = { }
  o0O00o0o [ "address" ] = OOOo0 . rloc . print_address_no_iid ( ) if OOOo0 . rloc_exists ( ) else "none"
  if 40 - 40: iII111i
  if 87 - 87: IiII / II111iiii
  if ( OOOo0 . geo ) : o0O00o0o [ "geo" ] = OOOo0 . geo . print_geo ( )
  if ( OOOo0 . elp ) : o0O00o0o [ "elp" ] = OOOo0 . elp . print_elp ( False )
  if ( OOOo0 . rle ) : o0O00o0o [ "rle" ] = OOOo0 . rle . print_rle ( False , True )
  if ( OOOo0 . json ) : o0O00o0o [ "json" ] = OOOo0 . json . print_json ( False )
  if ( OOOo0 . rloc_name ) : o0O00o0o [ "rloc-name" ] = OOOo0 . rloc_name
  o0O00o0o [ "uptime" ] = lisp_print_elapsed ( OOOo0 . uptime )
  o0O00o0o [ "upriority" ] = str ( OOOo0 . priority )
  o0O00o0o [ "uweight" ] = str ( OOOo0 . weight )
  o0O00o0o [ "mpriority" ] = str ( OOOo0 . mpriority )
  o0O00o0o [ "mweight" ] = str ( OOOo0 . mweight )
  if ( OOOo0 . translated_port != 0 ) :
   o0O00o0o [ "encap-port" ] = str ( OOOo0 . translated_port )
   if 44 - 44: OoO0O00 . I1Ii111 - OoooooooOO * OoOoOO00 . OoO0O00
   if 84 - 84: OOooOOo . OOooOOo . oO0o % iII111i * Oo0Ooo - iIii1I11I1II1
   if 4 - 4: iII111i
  oO0O0O0O0OO . append ( o0O00o0o )
  if 23 - 23: i1IIi . iIii1I11I1II1 / I1IiiI . OoOoOO00 . iII111i / IiII
 iIiiI11II11i [ "registered-rlocs" ] = oO0O0O0O0OO
 if 65 - 65: Ii1I + IiII + I11i / I1Ii111 % iIii1I11I1II1
 data . append ( iIiiI11II11i )
 return ( [ True , data ] )
 if 17 - 17: I1ii11iIi11i * OOooOOo % II111iiii
 if 30 - 30: I1Ii111 . Ii1I . Oo0Ooo / OOooOOo * OoooooooOO / I1ii11iIi11i
 if 41 - 41: i1IIi
 if 75 - 75: o0oOOo0O0Ooo . I1Ii111 - I1Ii111 % Ii1I * OoooooooOO
 if 99 - 99: OOooOOo + o0oOOo0O0Ooo - OOooOOo . i1IIi
 if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
 if 100 - 100: OoO0O00 . Oo0Ooo
def lisp_process_api_site_cache_entry ( parms ) :
 oO0O = parms [ "instance-id" ]
 oO0O = 0 if ( oO0O == "" ) else int ( oO0O )
 if 29 - 29: OoO0O00
 if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
 if 63 - 63: O0 % iIii1I11I1II1 . o0oOOo0O0Ooo . I1IiiI * Ii1I % i1IIi
 if 47 - 47: II111iiii * I1ii11iIi11i
 oO0OooO0o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , oO0O )
 oO0OooO0o0 . store_prefix ( parms [ "eid-prefix" ] )
 if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
 if 71 - 71: I1ii11iIi11i * i1IIi
 if 67 - 67: I1ii11iIi11i % OoOoOO00 . iII111i / Ii1I . I1IiiI
 if 48 - 48: IiII + II111iiii . I1IiiI % o0oOOo0O0Ooo
 if 57 - 57: OOooOOo . I11i % OoOoOO00
 iII1I1i = lisp_address ( LISP_AFI_NONE , "" , 0 , oO0O )
 if ( "group-prefix" in parms ) :
  iII1I1i . store_prefix ( parms [ "group-prefix" ] )
  if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
  if 78 - 78: iII111i - OOooOOo / I1Ii111
 iii = [ ]
 IiII1I1 = lisp_site_eid_lookup ( oO0OooO0o0 , iII1I1i , False )
 if ( IiII1I1 ) : lisp_gather_site_cache_data ( IiII1I1 , iii )
 return ( iii )
 if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
 if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
 if 17 - 17: OoooooooOO % OoooooooOO + Oo0Ooo + I1Ii111
 if 56 - 56: I11i % OoOoOO00 - OoO0O00
 if 31 - 31: iII111i % i11iIiiIii - Ii1I / OOooOOo - I1Ii111
 if 60 - 60: o0oOOo0O0Ooo + Oo0Ooo . O0
 if 51 - 51: i11iIiiIii / iIii1I11I1II1 . I1IiiI - Ii1I * I1Ii111 . iII111i
def lisp_get_interface_instance_id ( device , source_eid ) :
 i1i1111I = None
 if ( device in lisp_myinterfaces ) :
  i1i1111I = lisp_myinterfaces [ device ]
  if 72 - 72: Ii1I . I11i / i1IIi % i1IIi + I1ii11iIi11i
  if 56 - 56: OoO0O00 - OoOoOO00 - II111iiii * o0oOOo0O0Ooo
  if 87 - 87: ooOoO0o * OoooooooOO % O0 * OoooooooOO . I1Ii111
  if 66 - 66: OoO0O00 * Ii1I . OoO0O00
  if 90 - 90: II111iiii % Ii1I
  if 67 - 67: I1IiiI - I11i - i11iIiiIii
 if ( i1i1111I == None or i1i1111I . instance_id == None ) :
  return ( lisp_default_iid )
  if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
  if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
  if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
  if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
  if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
  if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
  if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
  if 57 - 57: I1Ii111 - IiII
  if 89 - 89: oO0o + iII111i
 oO0O = i1i1111I . get_instance_id ( )
 if ( source_eid == None ) : return ( oO0O )
 if 52 - 52: OOooOOo % O0 * I1ii11iIi11i . I1ii11iIi11i / IiII
 ii1ii = source_eid . instance_id
 Ooo0i11II1IIIIi = None
 for i1i1111I in lisp_multi_tenant_interfaces :
  if ( i1i1111I . device != device ) : continue
  o00OO = i1i1111I . multi_tenant_eid
  source_eid . instance_id = o00OO . instance_id
  if ( source_eid . is_more_specific ( o00OO ) == False ) : continue
  if ( Ooo0i11II1IIIIi == None or Ooo0i11II1IIIIi . multi_tenant_eid . mask_len < o00OO . mask_len ) :
   Ooo0i11II1IIIIi = i1i1111I
   if 39 - 39: I11i
   if 77 - 77: OoO0O00 / OoO0O00 . ooOoO0o . Oo0Ooo * OoooooooOO * I11i
 source_eid . instance_id = ii1ii
 if 63 - 63: iIii1I11I1II1 + ooOoO0o + o0oOOo0O0Ooo . ooOoO0o / o0oOOo0O0Ooo - IiII
 if ( Ooo0i11II1IIIIi == None ) : return ( oO0O )
 return ( Ooo0i11II1IIIIi . get_instance_id ( ) )
 if 7 - 7: I1ii11iIi11i . iII111i . OOooOOo
 if 81 - 81: o0oOOo0O0Ooo . Oo0Ooo * OoO0O00 - OoOoOO00 + OoO0O00
 if 67 - 67: I1Ii111
 if 31 - 31: OoO0O00 * Oo0Ooo % O0 * II111iiii + ooOoO0o * I1IiiI
 if 77 - 77: ooOoO0o
 if 98 - 98: I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
 if 6 - 6: iII111i / iII111i . i11iIiiIii
 if 12 - 12: I11i - OoO0O00
 if 68 - 68: IiII - OoOoOO00
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( device not in lisp_myinterfaces ) : return ( None )
 if 22 - 22: i1IIi . IiII
 i1i1111I = lisp_myinterfaces [ device ]
 i1iIi1Ii1I1 = device if i1i1111I . dynamic_eid_device == None else i1i1111I . dynamic_eid_device
 if 100 - 100: I11i % i1IIi / OoooooooOO
 if 12 - 12: Ii1I . Ii1I
 if ( i1i1111I . does_dynamic_eid_match ( eid ) ) : return ( i1iIi1Ii1I1 )
 return ( None )
 if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
 if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
 if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
 if 42 - 42: i1IIi . OoO0O00 % iII111i
 if 57 - 57: I1ii11iIi11i / I1IiiI
 if 69 - 69: iII111i - iII111i . OoO0O00 / oO0o - OoO0O00 + I1Ii111
 if 98 - 98: iII111i . oO0o - O0 % I1IiiI . I1ii11iIi11i / i1IIi
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 72 - 72: I1IiiI / Oo0Ooo % IiII - O0 / O0 * O0
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 83 - 83: O0 / I1Ii111 - OoooooooOO
 I1Ii = lisp_process_rloc_probe_timer
 iI1Ii1I = threading . Timer ( interval , I1Ii , [ lisp_sockets ] )
 lisp_rloc_probe_timer = iI1Ii1I
 iI1Ii1I . start ( )
 return
 if 28 - 28: Oo0Ooo * OoooooooOO . I1Ii111 . iIii1I11I1II1 - Oo0Ooo / OOooOOo
 if 69 - 69: OoooooooOO
 if 51 - 51: OoO0O00 + i11iIiiIii / II111iiii
 if 52 - 52: o0oOOo0O0Ooo * I1ii11iIi11i % OoOoOO00 . Ii1I . OoO0O00 * I1Ii111
 if 26 - 26: ooOoO0o % OoO0O00 * OoO0O00 * O0 . i1IIi
 if 32 - 32: i11iIiiIii
 if 43 - 43: iIii1I11I1II1 + oO0o + OoooooooOO
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for III11II111 in lisp_rloc_probe_list :
  oOOoooO0 = lisp_rloc_probe_list [ III11II111 ]
  lprint ( "RLOC {}:" . format ( III11II111 ) )
  for o0O00o0o , o0o00oO0oo000 , o0O0Ooo in oOOoooO0 :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( o0O00o0o ) ) , o0o00oO0oo000 . print_prefix ( ) ,
 o0O0Ooo . print_prefix ( ) , o0O00o0o . translated_port ) )
   if 53 - 53: II111iiii / iIii1I11I1II1
   if 25 - 25: I1Ii111
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 58 - 58: OoOoOO00 * i1IIi
 if 20 - 20: IiII
 if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
 if 30 - 30: i11iIiiIii . I1IiiI
 if 5 - 5: Ii1I / O0 + iIii1I11I1II1
 if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
 if 79 - 79: iII111i
 if 71 - 71: i1IIi / OoO0O00 / OOooOOo + I1Ii111
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
 if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
 if 12 - 12: I1ii11iIi11i - i11iIiiIii + I1IiiI . Oo0Ooo
 OOOo0 , o0o00oO0oo000 , o0O0Ooo = eid_list [ 0 ]
 III111 = [ lisp_print_eid_tuple ( o0o00oO0oo000 , o0O0Ooo ) ]
 if 2 - 2: I1Ii111 - O0 % OoooooooOO + I1Ii111
 for OOOo0 , o0o00oO0oo000 , o0O0Ooo in eid_list [ 1 : : ] :
  OOOo0 . state = LISP_RLOC_UNREACH_STATE
  OOOo0 . last_state_change = lisp_get_timestamp ( )
  III111 . append ( lisp_print_eid_tuple ( o0o00oO0oo000 , o0O0Ooo ) )
  if 1 - 1: I1Ii111 % OoooooooOO + OoooooooOO - I1IiiI % I1IiiI
  if 51 - 51: iIii1I11I1II1 / I1IiiI
 Iiio0o0o0o0O0OO0 = bold ( "unreachable" , False )
 IIII1iI1IiIiI = red ( OOOo0 . rloc . print_address_no_iid ( ) , False )
 if 80 - 80: I1Ii111 * O0 % i11iIiiIii - Ii1I * oO0o % IiII
 for oO0OooO0o0 in III111 :
  o0o00oO0oo000 = green ( oO0OooO0o0 , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( IIII1iI1IiIiI , Iiio0o0o0o0O0OO0 , o0o00oO0oo000 ) )
  if 67 - 67: i11iIiiIii * II111iiii
  if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
  if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
  if 24 - 24: i11iIiiIii + ooOoO0o
  if 80 - 80: IiII % I11i % oO0o
  if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
 for OOOo0 , o0o00oO0oo000 , o0O0Ooo in eid_list :
  Ii111 = lisp_map_cache . lookup_cache ( o0o00oO0oo000 , True )
  if ( Ii111 ) : lisp_write_ipc_map_cache ( True , Ii111 )
  if 70 - 70: iIii1I11I1II1
 return
 if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
 if 64 - 64: iII111i - Oo0Ooo
 if 73 - 73: iIii1I11I1II1 * I1Ii111 * OoO0O00
 if 68 - 68: ooOoO0o * Ii1I / I1ii11iIi11i * OoooooooOO + OoooooooOO . OoooooooOO
 if 50 - 50: I1IiiI % o0oOOo0O0Ooo
 if 1 - 1: II111iiii
 if 22 - 22: I1Ii111 + iII111i
 if 50 - 50: iII111i % OoOoOO00 - II111iiii + II111iiii / OoO0O00
def lisp_process_multicast_rloc ( multicast_rloc ) :
 o0oo000oOo0Oo = multicast_rloc . rloc . print_address_no_iid ( )
 if 56 - 56: ooOoO0o % Oo0Ooo + I1ii11iIi11i + OoO0O00
 IiI1i11i = lisp_get_timestamp ( )
 for OOOo in multicast_rloc . multicast_rloc_probe_list :
  i1i11iiII = multicast_rloc . multicast_rloc_probe_list [ OOOo ]
  if ( i1i11iiII . last_rloc_probe_reply + LISP_RLOC_PROBE_REPLY_WAIT >= IiI1i11i ) :
   continue
   if 89 - 89: OOooOOo * ooOoO0o - I1Ii111 * i11iIiiIii
  if ( i1i11iiII . state == LISP_RLOC_UNREACH_STATE ) : continue
  if 81 - 81: O0 % i1IIi + oO0o % i1IIi + iIii1I11I1II1
  if 19 - 19: iII111i % Ii1I / II111iiii + IiII / Oo0Ooo * OOooOOo
  if 34 - 34: OOooOOo . oO0o + I11i / I1Ii111 . I11i
  if 59 - 59: Ii1I
  i1i11iiII . state = LISP_RLOC_UNREACH_STATE
  i1i11iiII . last_state_change = lisp_get_timestamp ( )
  if 47 - 47: iII111i % iII111i
  lprint ( "Multicast-RLOC {} member-RLOC {} went unreachable" . format ( o0oo000oOo0Oo , red ( OOOo , False ) ) )
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
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 38 - 38: I1IiiI * Ii1I + Oo0Ooo - OoooooooOO
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 63 - 63: I1ii11iIi11i
 if 99 - 99: I1Ii111 % oO0o - II111iiii . ooOoO0o
 if 26 - 26: I1ii11iIi11i * iII111i . OoooooooOO - Oo0Ooo - IiII
 if 6 - 6: OOooOOo - I1IiiI . IiII
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 40 - 40: II111iiii
 if 13 - 13: OoOoOO00
 if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
 if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
 IiIIiiiii1I11 = lisp_get_default_route_next_hops ( )
 if 69 - 69: i11iIiiIii - oO0o
 iiI111I = "---------- Start RLOC Probing for {} RLOC entries ----------" . format ( len ( lisp_rloc_probe_list ) )
 if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 lprint ( bold ( iiI111I , False ) )
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 IiI = 0
 Ii1IiI = bold ( "RLOC-probe" , False )
 for oooOOOo00OoO0 in list ( lisp_rloc_probe_list . values ( ) ) :
  if 74 - 74: Oo0Ooo - oO0o + OoooooooOO
  if 44 - 44: o0oOOo0O0Ooo % ooOoO0o . oO0o - Oo0Ooo % OOooOOo
  if 15 - 15: o0oOOo0O0Ooo - Oo0Ooo / IiII
  if 94 - 94: Ii1I + o0oOOo0O0Ooo / II111iiii
  if 18 - 18: I1IiiI
  iii1i11II1iiI = None
  for oo00o , oO0OooO0o0 , iII1I1i in oooOOOo00OoO0 :
   Oo0o = oo00o . rloc . print_address_no_iid ( )
   if 94 - 94: ooOoO0o / ooOoO0o
   if 74 - 74: i11iIiiIii - oO0o % II111iiii . iIii1I11I1II1
   if 94 - 94: OOooOOo + oO0o / OoooooooOO + o0oOOo0O0Ooo - o0oOOo0O0Ooo . OOooOOo
   if 15 - 15: i11iIiiIii * O0 % iIii1I11I1II1 . OoooooooOO % oO0o + o0oOOo0O0Ooo
   iI1I , IIii11 , I111I1I = lisp_allow_gleaning ( oO0OooO0o0 , None , oo00o )
   if ( iI1I and IIii11 == False ) :
    o0o00oO0oo000 = green ( oO0OooO0o0 . print_address ( ) , False )
    Oo0o += ":{}" . format ( oo00o . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( Oo0o , False ) , o0o00oO0oo000 ) )
    if 56 - 56: OoooooooOO
    continue
    if 12 - 12: ooOoO0o
    if 97 - 97: i1IIi . Oo0Ooo
    if 81 - 81: OoOoOO00
    if 81 - 81: O0
    if 57 - 57: oO0o - o0oOOo0O0Ooo % i11iIiiIii / OoOoOO00 . iIii1I11I1II1
    if 68 - 68: iII111i
    if 59 - 59: O0 - i11iIiiIii + OoooooooOO - iII111i - Oo0Ooo . OoooooooOO
   if ( oo00o . down_state ( ) ) : continue
   if 60 - 60: O0 * iIii1I11I1II1 - Ii1I * II111iiii . ooOoO0o
   if 61 - 61: I1IiiI . iII111i
   if 19 - 19: iIii1I11I1II1 * Oo0Ooo - I1IiiI - I1IiiI + O0 - I1Ii111
   if 56 - 56: I1Ii111 - i1IIi + I11i . i1IIi / II111iiii * oO0o
   if 70 - 70: ooOoO0o - II111iiii . I11i
   if 70 - 70: OOooOOo / iII111i - I11i + OoOoOO00 % Ii1I * IiII
   if 26 - 26: O0 / oO0o
   if 96 - 96: ooOoO0o * iII111i . IiII
   if 77 - 77: OOooOOo - I11i % o0oOOo0O0Ooo
   if 46 - 46: I1IiiI % oO0o . OoooooooOO . IiII / I11i - i1IIi
   if 43 - 43: OoOoOO00 - o0oOOo0O0Ooo
   if ( iii1i11II1iiI ) :
    oo00o . last_rloc_probe_nonce = iii1i11II1iiI . last_rloc_probe_nonce
    if 22 - 22: i1IIi
    if ( iii1i11II1iiI . translated_port == oo00o . translated_port and iii1i11II1iiI . rloc_name == oo00o . rloc_name ) :
     if 33 - 33: O0
     o0o00oO0oo000 = green ( lisp_print_eid_tuple ( oO0OooO0o0 , iII1I1i ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( Oo0o , False ) , o0o00oO0oo000 ) )
     if 34 - 34: I1Ii111 . IiII % iII111i
     if 94 - 94: OOooOOo % i11iIiiIii . OOooOOo
     if 55 - 55: OoOoOO00 . OoOoOO00 % o0oOOo0O0Ooo . I11i . I1ii11iIi11i - o0oOOo0O0Ooo
     if 1 - 1: i11iIiiIii - i1IIi * oO0o - iIii1I11I1II1
     if 75 - 75: i1IIi * i11iIiiIii
     if 40 - 40: I1ii11iIi11i + OoO0O00
     oo00o . last_rloc_probe = iii1i11II1iiI . last_rloc_probe
     continue
     if 8 - 8: i11iIiiIii - iIii1I11I1II1
     if 73 - 73: OoOoOO00
     if 25 - 25: iII111i / oO0o
     if 61 - 61: OoooooooOO . Ii1I . I11i + oO0o
     if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
     if 61 - 61: I1IiiI / OOooOOo
     if 67 - 67: OoOoOO00
     if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
   I1i11i = None
   if ( oo00o . rloc_next_hop != None ) :
    I1i11i = lisp_get_host_route_next_hop ( Oo0o )
    if ( I1i11i ) :
     lprint ( "Remove forwarding next-hop {}" . format ( I1i11i ) )
     lisp_install_host_route ( Oo0o , None , False )
     if 30 - 30: O0 / oO0o * i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
     if 95 - 95: ooOoO0o % OOooOOo
     if 17 - 17: i1IIi + Ii1I
   OOOo0 = None
   while ( True ) :
    OOOo0 = oo00o if OOOo0 == None else OOOo0 . next_rloc
    if ( OOOo0 == None ) : break
    if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
    if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
    if 26 - 26: oO0o / I1ii11iIi11i - oO0o
    if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
    if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
    if ( OOOo0 . rloc_next_hop != None ) :
     if ( OOOo0 . rloc_next_hop not in IiIIiiiii1I11 ) :
      iiIi , o0Ooo0oo = OOOo0 . rloc_next_hop
      if ( OOOo0 . up_state ( ) ) :
       OOOo0 . state = LISP_RLOC_UNREACH_STATE
       OOOo0 . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( OOOo0 . rloc , False )
       if 96 - 96: Ii1I
      Iiio0o0o0o0O0OO0 = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( o0Ooo0oo , iiIi ,
 red ( Oo0o , False ) , Iiio0o0o0o0O0OO0 ) )
      continue
      if 90 - 90: II111iiii
      if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
      if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
      if 52 - 52: i11iIiiIii * ooOoO0o
      if 15 - 15: OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
      if 91 - 91: ooOoO0o
    iII11I = OOOo0 . last_rloc_probe
    IiI111i = 0 if iII11I == None else time . time ( ) - iII11I
    if ( OOOo0 . unreach_state ( ) and IiI111i < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( Oo0o , False ) ) )
     if 36 - 36: OoooooooOO . O0 + OOooOOo * I1IiiI . iIii1I11I1II1
     continue
     if 93 - 93: OoOoOO00 % OoooooooOO * iIii1I11I1II1 . Ii1I % I1ii11iIi11i
     if 93 - 93: O0 % IiII
     if 40 - 40: iII111i - OoOoOO00 / IiII - I11i
     if 86 - 86: OoOoOO00 + oO0o / II111iiii % IiII % IiII * O0
     if 32 - 32: OoO0O00 / OoOoOO00 % iII111i * I11i . OoO0O00
     if 26 - 26: IiII
    i1OooO00oO00o = lisp_get_echo_nonce ( None , Oo0o )
    if ( i1OooO00oO00o and i1OooO00oO00o . request_nonce_timeout ( ) ) :
     OOOo0 . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     OOOo0 . last_state_change = lisp_get_timestamp ( )
     Iiio0o0o0o0O0OO0 = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( Oo0o , False ) , Iiio0o0o0o0O0OO0 ) )
     if 15 - 15: OoooooooOO / OoO0O00 - II111iiii / IiII + oO0o
     lisp_update_rtr_updown ( OOOo0 . rloc , False )
     continue
     if 48 - 48: iII111i * OoO0O00 * OoOoOO00 * I11i
     if 74 - 74: ooOoO0o
     if 93 - 93: Oo0Ooo % ooOoO0o
     if 38 - 38: II111iiii . I1Ii111 . iIii1I11I1II1 / o0oOOo0O0Ooo
     if 6 - 6: ooOoO0o - i1IIi * I1IiiI
     if 24 - 24: iIii1I11I1II1 / I1Ii111
    if ( i1OooO00oO00o and i1OooO00oO00o . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( Oo0o , False ) ) )
     if 16 - 16: OoOoOO00 * I1Ii111 - I1IiiI / I1Ii111
     continue
     if 64 - 64: I1ii11iIi11i . i1IIi % II111iiii % Oo0Ooo + oO0o - I1IiiI
     if 24 - 24: IiII . II111iiii . II111iiii . OoOoOO00 . i11iIiiIii
     if 11 - 11: Ii1I
     if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
     if 44 - 44: iII111i
     if 56 - 56: II111iiii / Oo0Ooo % IiII * II111iiii - iIii1I11I1II1 + ooOoO0o
    if ( OOOo0 . last_rloc_probe != None ) :
     iII11I = OOOo0 . last_rloc_probe_reply
     if ( iII11I == None ) : iII11I = 0
     IiI111i = time . time ( ) - iII11I
     if ( OOOo0 . up_state ( ) and IiI111i >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 33 - 33: o0oOOo0O0Ooo . I11i / I1IiiI
      OOOo0 . state = LISP_RLOC_UNREACH_STATE
      OOOo0 . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( OOOo0 . rloc , False )
      Iiio0o0o0o0O0OO0 = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( Oo0o , False ) , Iiio0o0o0o0O0OO0 ) )
      if 29 - 29: o0oOOo0O0Ooo - ooOoO0o
      if 59 - 59: I11i / IiII * OoO0O00 / IiII . I1Ii111
      lisp_mark_rlocs_for_other_eids ( oooOOOo00OoO0 )
      if 82 - 82: OOooOOo . iIii1I11I1II1 + I1Ii111
      if 14 - 14: IiII . i11iIiiIii
      if 17 - 17: ooOoO0o % ooOoO0o * oO0o
    OOOo0 . last_rloc_probe = lisp_get_timestamp ( )
    if 8 - 8: ooOoO0o + OoO0O00 . II111iiii / iIii1I11I1II1 - OOooOOo
    Oo0oOO0O = "" if OOOo0 . unreach_state ( ) == False else " unreachable"
    if 24 - 24: i11iIiiIii * oO0o * I1IiiI - i1IIi * OoOoOO00
    if 5 - 5: I1ii11iIi11i % o0oOOo0O0Ooo . iII111i
    if 73 - 73: OoOoOO00 . o0oOOo0O0Ooo * OoOoOO00
    if 94 - 94: OoO0O00 / I1ii11iIi11i
    if 50 - 50: OoOoOO00 % I1IiiI + I1Ii111 . iII111i . iII111i
    if 89 - 89: oO0o / I1ii11iIi11i % I1Ii111
    if 86 - 86: Ii1I * II111iiii % ooOoO0o
    if 82 - 82: OOooOOo . Oo0Ooo * ooOoO0o % II111iiii % II111iiii - oO0o
    OoooOOOOO0 = ""
    oo0O0 = None
    if 36 - 36: O0 / I1ii11iIi11i + iII111i * Oo0Ooo
    if 97 - 97: IiII * O0 - o0oOOo0O0Ooo
    if 77 - 77: II111iiii / I11i % OoooooooOO % I1IiiI % II111iiii
    if 99 - 99: Oo0Ooo
    if 30 - 30: OoOoOO00 + I1Ii111 . OoOoOO00 - I11i
    if 42 - 42: OoOoOO00
    if 77 - 77: Oo0Ooo * IiII * I1ii11iIi11i + IiII
    if 37 - 37: IiII . OoooooooOO - i11iIiiIii * I1ii11iIi11i - OOooOOo
    if ( OOOo0 . rloc_next_hop != None and oo0O0 != None ) :
     iiIi , oo0O0 = OOOo0 . rloc_next_hop
     lisp_install_host_route ( Oo0o , oo0O0 , True )
     OoooOOOOO0 = ", send to nh {} on {}" . format ( oo0O0 , bold ( iiIi , False ) )
     if 74 - 74: Ii1I + i11iIiiIii * iII111i / o0oOOo0O0Ooo . i11iIiiIii
     if 99 - 99: OOooOOo - OoooooooOO + OoooooooOO . OOooOOo
     if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
     if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
     if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
    I1iiiiIIiiI1i = OOOo0 . print_rloc_probe_rtt ( )
    oO0o00o0O = Oo0o
    if ( OOOo0 . translated_port != 0 ) :
     oO0o00o0O += ":{}" . format ( OOOo0 . translated_port )
     if 87 - 87: iII111i
    oO0o00o0O = red ( oO0o00o0O , False )
    if ( OOOo0 . rloc_name != None ) :
     oO0o00o0O += " (" + blue ( OOOo0 . rloc_name , False ) + ")"
     if 63 - 63: iII111i - I11i - iIii1I11I1II1 - Ii1I / iII111i % I1Ii111
    lprint ( "Send {} to{} {}, last rtt: {}{}" . format ( Ii1IiI , Oo0oOO0O ,
 oO0o00o0O , I1iiiiIIiiI1i , OoooOOOOO0 ) )
    if 59 - 59: OoooooooOO
    if 89 - 89: i1IIi / OoooooooOO . I1IiiI
    if 70 - 70: OOooOOo . I1Ii111
    if 20 - 20: i1IIi * IiII % II111iiii + IiII
    if 4 - 4: Ii1I + I1ii11iIi11i
    if ( OOOo0 . rloc . is_null ( ) ) :
     OOOo0 . rloc . copy_address ( oo00o . rloc )
     if 40 - 40: OOooOOo % iII111i
     if 5 - 5: O0 + i11iIiiIii . IiII - OOooOOo
     if 51 - 51: OOooOOo . I1IiiI % OoO0O00 . I1IiiI
     if 88 - 88: O0 . iIii1I11I1II1 . iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1 . Oo0Ooo
     if 8 - 8: iII111i
    if ( OOOo0 . multicast_rloc_probe_list != { } ) :
     lisp_process_multicast_rloc ( OOOo0 )
     if 78 - 78: i11iIiiIii % oO0o % ooOoO0o - I1Ii111
     if 53 - 53: oO0o + i1IIi . i11iIiiIii + OoO0O00 + Oo0Ooo
     if 27 - 27: OoooooooOO . I1IiiI + OoooooooOO % II111iiii . II111iiii - oO0o
     if 8 - 8: o0oOOo0O0Ooo . i1IIi . Ii1I - OoOoOO00 / iIii1I11I1II1
     if 11 - 11: oO0o - OOooOOo - I11i * I1IiiI
    iIiI11iIi111i = None if ( iII1I1i . is_null ( ) ) else oO0OooO0o0
    II11i1I1I = oO0OooO0o0 if ( iII1I1i . is_null ( ) ) else iII1I1i
    lisp_send_map_request ( lisp_sockets , 0 , iIiI11iIi111i , II11i1I1I , OOOo0 )
    iii1i11II1iiI = oo00o
    if 55 - 55: II111iiii
    if 8 - 8: iII111i - ooOoO0o / I1ii11iIi11i * i1IIi - IiII . II111iiii
    if 65 - 65: oO0o * IiII
    if 97 - 97: IiII % OoO0O00 . OoOoOO00 - Ii1I
    if 28 - 28: O0 . I11i . I1IiiI - Ii1I - iII111i - iIii1I11I1II1
    if 14 - 14: OOooOOo + ooOoO0o
    if ( OOOo0 . is_decent_nat_port ( ) and OOOo0 . unreach_state ( ) ) :
     OOOo0 . refresh_decent_nat_rloc ( lisp_sockets , II11i1I1I )
     if 56 - 56: o0oOOo0O0Ooo - OoOoOO00 - Ii1I
     if 50 - 50: I1ii11iIi11i
     if 24 - 24: ooOoO0o
     if 19 - 19: oO0o
     if 97 - 97: IiII
     if 36 - 36: II111iiii
    if ( oo0O0 ) : lisp_install_host_route ( Oo0o , oo0O0 , False )
    if 83 - 83: I11i . ooOoO0o
    if 57 - 57: IiII
    if 34 - 34: I1ii11iIi11i + i11iIiiIii - I1ii11iIi11i / OoOoOO00 + i1IIi . i11iIiiIii
    if 48 - 48: I1ii11iIi11i % OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii / OoOoOO00
    if 73 - 73: OoOoOO00 + OOooOOo * II111iiii . OOooOOo % I1Ii111 % oO0o
    if 79 - 79: I1ii11iIi11i % I11i
   if ( I1i11i ) :
    lprint ( "Reinstall forwarding next-hop {}" . format ( I1i11i ) )
    lisp_install_host_route ( Oo0o , I1i11i , True )
    if 78 - 78: i11iIiiIii % I1Ii111 + iIii1I11I1II1 + iII111i
    if 66 - 66: I1IiiI - o0oOOo0O0Ooo
    if 67 - 67: oO0o . iII111i * Ii1I - OOooOOo / oO0o
    if 98 - 98: OoOoOO00 * OoO0O00 . Oo0Ooo
    if 6 - 6: I11i % iIii1I11I1II1 + I1Ii111
   IiI += 1
   if ( ( IiI % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 48 - 48: II111iiii . OOooOOo . ooOoO0o - iII111i
   if 90 - 90: OOooOOo
   if 43 - 43: IiII + ooOoO0o
 lprint ( bold ( "---------- End RLOC Probing ----------" , False ) )
 return
 if 4 - 4: i1IIi
 if 89 - 89: Oo0Ooo / iIii1I11I1II1 . OoOoOO00
 if 6 - 6: Ii1I / iII111i
 if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
 if 70 - 70: oO0o - I1IiiI + Ii1I
 if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
 if 37 - 37: o0oOOo0O0Ooo
 if 57 - 57: iII111i / i1IIi / i1IIi + IiII
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 75 - 75: IiII / O0
 if 72 - 72: I11i
 if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
 if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
 if ( lisp_i_am_itr == False ) : return
 if 23 - 23: OoOoOO00 . oO0o - iII111i
 if 27 - 27: Oo0Ooo * OOooOOo - OoOoOO00
 if 1 - 1: II111iiii * i11iIiiIii . OoooooooOO
 if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
 if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
 if ( lisp_register_all_rtrs ) : return
 if 88 - 88: I1Ii111
 IIIIiI = rtr . print_address_no_iid ( )
 if 93 - 93: OoOoOO00 + iII111i
 if 49 - 49: I11i . i11iIiiIii
 if 18 - 18: OOooOOo * O0 % ooOoO0o - ooOoO0o
 if 46 - 46: o0oOOo0O0Ooo * oO0o / oO0o . oO0o + I11i * OOooOOo
 if 48 - 48: iII111i + Ii1I
 if ( IIIIiI not in lisp_rtr_list ) : return
 if 10 - 10: I1IiiI + o0oOOo0O0Ooo
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( IIIIiI , False ) , bold ( updown , False ) ) )
 if 75 - 75: Oo0Ooo
 if 100 - 100: i1IIi / Oo0Ooo / II111iiii + iII111i . II111iiii * oO0o
 if 36 - 36: Oo0Ooo + iII111i / OOooOOo + OOooOOo % i11iIiiIii / I1IiiI
 if 59 - 59: ooOoO0o / I11i
 I1Iii1 = "rtr%{}%{}" . format ( IIIIiI , updown )
 I1Iii1 = lisp_command_ipc ( I1Iii1 , "lisp-itr" )
 lisp_ipc ( I1Iii1 , lisp_ipc_socket , "lisp-etr" )
 return
 if 32 - 32: iIii1I11I1II1 % oO0o / I1Ii111
 if 42 - 42: I11i / I1ii11iIi11i - I1IiiI * iII111i / I1IiiI / i11iIiiIii
 if 75 - 75: Oo0Ooo + IiII / I11i % I11i % IiII / I1Ii111
 if 95 - 95: OoOoOO00
 if 78 - 78: I11i
 if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
 if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
def lisp_process_rloc_probe_reply ( rloc_entry , source , port , map_reply , ttl ,
 mrloc , rloc_name ) :
 global lisp_rloc_probe_nonce_list
 if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
 OOOo0 = rloc_entry . rloc
 o000oo = map_reply . nonce
 ooo00OOoo00 = map_reply . hop_count
 Ii1IiI = bold ( "RLOC-probe reply" , False )
 Ii11i11i1 = OOOo0 . print_address_no_iid ( )
 o0oo0oooo = source . print_address_no_iid ( )
 iiIi1IiII = lisp_rloc_probe_list
 oO0oo0o0ooO = rloc_entry . json . json_string if rloc_entry . json else None
 Oo0OO0000oooo = lisp_get_timestamp ( )
 if 5 - 5: oO0o + oO0o * i1IIi / IiII / iII111i
 if 19 - 19: I1IiiI + iIii1I11I1II1 * O0 - OOooOOo
 if 32 - 32: O0 - II111iiii - i1IIi + O0 + OOooOOo
 if 44 - 44: I11i * oO0o % OoooooooOO % OoO0O00 / o0oOOo0O0Ooo
 if 37 - 37: OoO0O00 + OoOoOO00 - I1IiiI
 if 68 - 68: i11iIiiIii / OOooOOo . i1IIi . i11iIiiIii . I11i
 if ( mrloc != None ) :
  Oo0ooo0O0 = mrloc . rloc . print_address_no_iid ( )
  if ( Ii11i11i1 not in mrloc . multicast_rloc_probe_list ) :
   IIiiIiii = lisp_rloc ( )
   IIiiIiii = copy . deepcopy ( mrloc )
   IIiiIiii . rloc . copy_address ( OOOo0 )
   IIiiIiii . multicast_rloc_probe_list = { }
   mrloc . multicast_rloc_probe_list [ Ii11i11i1 ] = IIiiIiii
   if 51 - 51: OoO0O00 / IiII * O0
  IIiiIiii = mrloc . multicast_rloc_probe_list [ Ii11i11i1 ]
  IIiiIiii . rloc_name = rloc_name
  IIiiIiii . last_rloc_probe_nonce = mrloc . last_rloc_probe_nonce
  IIiiIiii . last_rloc_probe = mrloc . last_rloc_probe
  o0O00o0o , oO0OooO0o0 , iII1I1i = lisp_rloc_probe_list [ Oo0ooo0O0 ] [ 0 ]
  IIiiIiii . process_rloc_probe_reply ( Oo0OO0000oooo , o000oo , oO0OooO0o0 , iII1I1i , ooo00OOoo00 , ttl , oO0oo0o0ooO )
  mrloc . process_rloc_probe_reply ( Oo0OO0000oooo , o000oo , oO0OooO0o0 , iII1I1i , ooo00OOoo00 , ttl , oO0oo0o0ooO )
  return
  if 10 - 10: oO0o - I11i
  if 1 - 1: OoOoOO00 . I1IiiI * ooOoO0o . iII111i * Oo0Ooo
  if 16 - 16: OoooooooOO % OoO0O00 - oO0o + ooOoO0o
  if 36 - 36: OoO0O00 + ooOoO0o
  if 67 - 67: OoooooooOO * IiII - OoOoOO00 % i1IIi
  if 71 - 71: I1IiiI
 if ( rloc_name . find ( LISP_TP ) != - 1 ) :
  port = int ( rloc_name . split ( LISP_TP ) [ - 1 ] )
  if 44 - 44: IiII + I1IiiI . Ii1I % Oo0Ooo
  if 97 - 97: O0
  if 95 - 95: OoO0O00 % iII111i / I1IiiI * OoooooooOO
  if 31 - 31: iIii1I11I1II1
  if 62 - 62: o0oOOo0O0Ooo - iII111i / II111iiii . o0oOOo0O0Ooo
  if 20 - 20: iIii1I11I1II1 % OOooOOo
  if 91 - 91: ooOoO0o
 OOOo = Ii11i11i1
 if ( OOOo not in iiIi1IiII ) :
  OOOo += ":" + str ( port )
  if ( OOOo not in iiIi1IiII ) :
   OOOo = o0oo0oooo
   if ( OOOo not in iiIi1IiII ) :
    OOOo += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( Ii1IiI , red ( Ii11i11i1 , False ) , red ( o0oo0oooo ,
    # OoooooooOO / OOooOOo + iII111i * OoooooooOO + II111iiii % o0oOOo0O0Ooo
 False ) , port ) )
    return
    if 100 - 100: O0 / I1IiiI
    if 20 - 20: oO0o * O0 - Ii1I + i11iIiiIii - OoOoOO00
    if 18 - 18: I1ii11iIi11i . iII111i
    if 31 - 31: I11i * o0oOOo0O0Ooo
    if 17 - 17: Ii1I * iIii1I11I1II1
    if 9 - 9: o0oOOo0O0Ooo - IiII
    if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
    if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
    if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
    if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
 if ( o000oo in lisp_rloc_probe_nonce_list ) :
  i1Ii11IIIi = lisp_rloc_probe_nonce_list . pop ( o000oo )
  if ( i1Ii11IIIi != OOOo ) :
   OOOo = i1Ii11IIIi
   lprint ( "    Obtain probed RLOC address {} from nonce 0x{}" . format ( OOOo , lisp_hex_string ( o000oo ) ) )
   if 98 - 98: i1IIi
   if 19 - 19: OoO0O00 % I1ii11iIi11i + I1ii11iIi11i
   if 3 - 3: i11iIiiIii - iIii1I11I1II1 / OoOoOO00
   if 34 - 34: I1IiiI . IiII / ooOoO0o + I1Ii111 / iIii1I11I1II1 + OoooooooOO
   if 80 - 80: OoO0O00 - OoOoOO00 % i1IIi / iIii1I11I1II1 . I11i - I11i
   if 76 - 76: ooOoO0o * iII111i / Ii1I * i1IIi . I1Ii111 - o0oOOo0O0Ooo
   if 52 - 52: OoOoOO00 % O0 + I1ii11iIi11i . i11iIiiIii
   if 59 - 59: Ii1I - I1Ii111 . ooOoO0o - OoOoOO00 + oO0o . OoO0O00
 for OOOo0 , oO0OooO0o0 , iII1I1i in lisp_rloc_probe_list [ OOOo ] :
  if ( lisp_i_am_rtr ) :
   if ( OOOo0 . translated_port != 0 and OOOo0 . translated_port != port ) :
    continue
    if 88 - 88: OOooOOo - ooOoO0o * o0oOOo0O0Ooo . OoooooooOO
    if 3 - 3: I1Ii111
  OOOo0 . process_rloc_probe_reply ( Oo0OO0000oooo , o000oo , oO0OooO0o0 , iII1I1i , ooo00OOoo00 , ttl , oO0oo0o0ooO )
  if 24 - 24: Ii1I + i11iIiiIii * I1Ii111 - OoOoOO00 / Ii1I - OoOoOO00
 return
 if 69 - 69: I11i - I1IiiI . oO0o - OoooooooOO
 if 33 - 33: o0oOOo0O0Ooo - o0oOOo0O0Ooo
 if 55 - 55: OoooooooOO / IiII + i1IIi
 if 54 - 54: ooOoO0o * Ii1I / Ii1I
 if 15 - 15: oO0o * I1Ii111
 if 11 - 11: Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
 if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
 if 46 - 46: oO0o + OoOoOO00
def lisp_db_list_length ( ) :
 IiI = 0
 for Oo0000 in lisp_db_list :
  IiI += len ( Oo0000 . dynamic_eids ) if Oo0000 . dynamic_eid_configured ( ) else 1
  IiI += len ( Oo0000 . eid . iid_list )
  if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
 return ( IiI )
 if 59 - 59: O0
 if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
 if 17 - 17: Ii1I % I1ii11iIi11i + I11i
 if 80 - 80: i1IIi . OoooooooOO % OoooooooOO . oO0o / OOooOOo
 if 85 - 85: OOooOOo
 if 80 - 80: ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
 if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
 if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
def lisp_is_myeid ( eid ) :
 for Oo0000 in lisp_db_list :
  if ( eid . is_more_specific ( Oo0000 . eid ) ) : return ( True )
  if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
 return ( False )
 if 72 - 72: IiII / II111iiii
 if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
 if 21 - 21: I1ii11iIi11i
 if 60 - 60: i1IIi / OoO0O00 . Ii1I
 if 16 - 16: i11iIiiIii + OoOoOO00 % Oo0Ooo + I1ii11iIi11i * Ii1I / I1Ii111
 if 26 - 26: iII111i
 if 31 - 31: iII111i
 if 45 - 45: OoO0O00
 if 55 - 55: iIii1I11I1II1 % iIii1I11I1II1 + I11i - ooOoO0o + I1IiiI * O0
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 47 - 47: ooOoO0o + iIii1I11I1II1 * OOooOOo . I1IiiI . o0oOOo0O0Ooo
 if 49 - 49: Oo0Ooo . OoOoOO00 * OOooOOo
 if 86 - 86: IiII * OOooOOo + Ii1I
 if 62 - 62: I11i
 if 86 - 86: Oo0Ooo % II111iiii + I1Ii111 / I1ii11iIi11i
 if 15 - 15: I1IiiI / I1Ii111 % iII111i
 if 57 - 57: I1Ii111 . iIii1I11I1II1 / Oo0Ooo / IiII / iII111i * OoOoOO00
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 35 - 35: i1IIi + I1Ii111 - ooOoO0o . I1ii11iIi11i + Oo0Ooo
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 i1OooO00oO00o = None
 if ( rloc_str in lisp_nonce_echo_list ) :
  i1OooO00oO00o = lisp_nonce_echo_list [ rloc_str ]
  if 43 - 43: oO0o . OoO0O00 * i1IIi
 return ( i1OooO00oO00o )
 if 1 - 1: ooOoO0o / i1IIi
 if 42 - 42: I1ii11iIi11i * ooOoO0o + OoOoOO00 % I1ii11iIi11i . IiII
 if 75 - 75: OoO0O00 * i1IIi - OOooOOo % II111iiii % OoO0O00 - OoOoOO00
 if 75 - 75: I11i * IiII * ooOoO0o
 if 31 - 31: Ii1I
 if 72 - 72: OOooOOo * Ii1I % OoO0O00
 if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
 if 42 - 42: oO0o / i1IIi . IiII
def lisp_decode_dist_name ( packet ) :
 IiI = 0
 iiOoo0o00o0ooO = b""
 if 88 - 88: OoooooooOO . I1IiiI
 while ( packet [ 0 : 1 ] != b"\x00" ) :
  if ( IiI == 255 ) : return ( [ None , None ] )
  iiOoo0o00o0ooO += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  IiI += 1
  if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
  if 7 - 7: i1IIi
 packet = packet [ 1 : : ]
 return ( packet , iiOoo0o00o0ooO . decode ( ) )
 if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
 if 34 - 34: iII111i + i11iIiiIii . IiII
 if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
 if 29 - 29: II111iiii % i11iIiiIii % O0
 if 38 - 38: o0oOOo0O0Ooo * IiII
 if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
 if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
 if 19 - 19: OoooooooOO
def lisp_write_flow_log ( flow_log ) :
 ii1I11ooOOoo0 = open ( "./logs/lisp-flow.log" , "a" )
 if 34 - 34: OoOoOO00 . oO0o
 IiI = 0
 for ooOoooOoo0oO in flow_log :
  OO0Oo00OO0oo = ooOoooOoo0oO [ 3 ]
  oO0o000 = OO0Oo00OO0oo . print_flow ( ooOoooOoo0oO [ 0 ] , ooOoooOoo0oO [ 1 ] , ooOoooOoo0oO [ 2 ] )
  ii1I11ooOOoo0 . write ( oO0o000 )
  IiI += 1
  if 57 - 57: o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
 ii1I11ooOOoo0 . close ( )
 del ( flow_log )
 if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
 IiI = bold ( str ( IiI ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( IiI ) )
 return
 if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
 if 80 - 80: II111iiii . i11iIiiIii
 if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
 if 33 - 33: iIii1I11I1II1
 if 52 - 52: iIii1I11I1II1 + O0
 if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
 if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
def lisp_policy_command ( kv_pair ) :
 o00oo = lisp_policy ( "" )
 i1111I111i = None
 if 24 - 24: O0 . IiII % i11iIiiIii - i1IIi * I1Ii111
 IiIi1Ii = [ ]
 for iIiIIi in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  IiIi1Ii . append ( lisp_policy_match ( ) )
  if 24 - 24: O0 * Oo0Ooo * I1IiiI * i1IIi
  if 30 - 30: I11i * I1ii11iIi11i / II111iiii . o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i
 for O0O0o0oO00o0 in list ( kv_pair . keys ( ) ) :
  IiIi1i = kv_pair [ O0O0o0oO00o0 ]
  if 55 - 55: o0oOOo0O0Ooo
  if 30 - 30: i1IIi / I1Ii111 * oO0o - oO0o / oO0o
  if 9 - 9: IiII / o0oOOo0O0Ooo . IiII * O0 % i11iIiiIii % OoOoOO00
  if 29 - 29: I1ii11iIi11i % ooOoO0o . OOooOOo . Ii1I . IiII
  if ( O0O0o0oO00o0 == "instance-id" ) :
   for iIiIIi in range ( len ( IiIi1Ii ) ) :
    OO0ii11II1II1 = IiIi1i [ iIiIIi ]
    if ( OO0ii11II1II1 == "" ) : continue
    oO00oooo00 = IiIi1Ii [ iIiIIi ]
    if ( oO00oooo00 . source_eid == None ) :
     oO00oooo00 . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 33 - 33: OoooooooOO
    if ( oO00oooo00 . dest_eid == None ) :
     oO00oooo00 . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 60 - 60: OOooOOo - Oo0Ooo * OOooOOo / OoO0O00
    oO00oooo00 . source_eid . instance_id = int ( OO0ii11II1II1 )
    oO00oooo00 . dest_eid . instance_id = int ( OO0ii11II1II1 )
    if 55 - 55: I1ii11iIi11i * II111iiii * iIii1I11I1II1
    if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i . Ii1I + I1IiiI % i11iIiiIii - i11iIiiIii
  if ( O0O0o0oO00o0 == "source-eid" ) :
   for iIiIIi in range ( len ( IiIi1Ii ) ) :
    OO0ii11II1II1 = IiIi1i [ iIiIIi ]
    if ( OO0ii11II1II1 == "" ) : continue
    oO00oooo00 = IiIi1Ii [ iIiIIi ]
    if ( oO00oooo00 . source_eid == None ) :
     oO00oooo00 . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 62 - 62: I1Ii111 + I1IiiI
    oO0O = oO00oooo00 . source_eid . instance_id
    oO00oooo00 . source_eid . store_prefix ( OO0ii11II1II1 )
    oO00oooo00 . source_eid . instance_id = oO0O
    if 9 - 9: iIii1I11I1II1 / iIii1I11I1II1
    if 24 - 24: OOooOOo . I1IiiI % i11iIiiIii
  if ( O0O0o0oO00o0 == "destination-eid" ) :
   for iIiIIi in range ( len ( IiIi1Ii ) ) :
    OO0ii11II1II1 = IiIi1i [ iIiIIi ]
    if ( OO0ii11II1II1 == "" ) : continue
    oO00oooo00 = IiIi1Ii [ iIiIIi ]
    if ( oO00oooo00 . dest_eid == None ) :
     oO00oooo00 . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 43 - 43: OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i + OoO0O00 . I1Ii111 . iII111i
    oO0O = oO00oooo00 . dest_eid . instance_id
    oO00oooo00 . dest_eid . store_prefix ( OO0ii11II1II1 )
    oO00oooo00 . dest_eid . instance_id = oO0O
    if 1 - 1: iII111i / OoO0O00 / OoOoOO00 * Oo0Ooo * OoooooooOO
    if 59 - 59: iII111i
  if ( O0O0o0oO00o0 == "source-rloc" ) :
   for iIiIIi in range ( len ( IiIi1Ii ) ) :
    OO0ii11II1II1 = IiIi1i [ iIiIIi ]
    if ( OO0ii11II1II1 == "" ) : continue
    oO00oooo00 = IiIi1Ii [ iIiIIi ]
    oO00oooo00 . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    oO00oooo00 . source_rloc . store_prefix ( OO0ii11II1II1 )
    if 14 - 14: oO0o . IiII + iIii1I11I1II1 - i1IIi
    if 46 - 46: i11iIiiIii * II111iiii / i11iIiiIii % i11iIiiIii * II111iiii + i11iIiiIii
  if ( O0O0o0oO00o0 == "destination-rloc" ) :
   for iIiIIi in range ( len ( IiIi1Ii ) ) :
    OO0ii11II1II1 = IiIi1i [ iIiIIi ]
    if ( OO0ii11II1II1 == "" ) : continue
    oO00oooo00 = IiIi1Ii [ iIiIIi ]
    oO00oooo00 . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    oO00oooo00 . dest_rloc . store_prefix ( OO0ii11II1II1 )
    if 87 - 87: Oo0Ooo + OoO0O00 / II111iiii * OoooooooOO
    if 95 - 95: I1Ii111 * o0oOOo0O0Ooo + OoO0O00 % OoOoOO00 - ooOoO0o / OoOoOO00
  if ( O0O0o0oO00o0 == "rloc-record-name" ) :
   for iIiIIi in range ( len ( IiIi1Ii ) ) :
    OO0ii11II1II1 = IiIi1i [ iIiIIi ]
    if ( OO0ii11II1II1 == "" ) : continue
    oO00oooo00 = IiIi1Ii [ iIiIIi ]
    oO00oooo00 . rloc_record_name = OO0ii11II1II1
    if 45 - 45: OoooooooOO / oO0o / o0oOOo0O0Ooo + Ii1I + O0 . iII111i
    if 34 - 34: iIii1I11I1II1 . o0oOOo0O0Ooo + ooOoO0o
  if ( O0O0o0oO00o0 == "geo-name" ) :
   for iIiIIi in range ( len ( IiIi1Ii ) ) :
    OO0ii11II1II1 = IiIi1i [ iIiIIi ]
    if ( OO0ii11II1II1 == "" ) : continue
    oO00oooo00 = IiIi1Ii [ iIiIIi ]
    oO00oooo00 . geo_name = OO0ii11II1II1
    if 96 - 96: O0 / ooOoO0o
    if 82 - 82: OoO0O00 * OOooOOo * I11i * I1Ii111 % iIii1I11I1II1
  if ( O0O0o0oO00o0 == "elp-name" ) :
   for iIiIIi in range ( len ( IiIi1Ii ) ) :
    OO0ii11II1II1 = IiIi1i [ iIiIIi ]
    if ( OO0ii11II1II1 == "" ) : continue
    oO00oooo00 = IiIi1Ii [ iIiIIi ]
    oO00oooo00 . elp_name = OO0ii11II1II1
    if 50 - 50: Ii1I * Ii1I % I11i / iIii1I11I1II1 / ooOoO0o / iII111i
    if 91 - 91: Ii1I - O0 . I11i - OoooooooOO * IiII . II111iiii
  if ( O0O0o0oO00o0 == "rle-name" ) :
   for iIiIIi in range ( len ( IiIi1Ii ) ) :
    OO0ii11II1II1 = IiIi1i [ iIiIIi ]
    if ( OO0ii11II1II1 == "" ) : continue
    oO00oooo00 = IiIi1Ii [ iIiIIi ]
    oO00oooo00 . rle_name = OO0ii11II1II1
    if 38 - 38: I1IiiI + OoO0O00
    if 11 - 11: iIii1I11I1II1 + i1IIi * IiII - Oo0Ooo
  if ( O0O0o0oO00o0 == "json-name" ) :
   for iIiIIi in range ( len ( IiIi1Ii ) ) :
    OO0ii11II1II1 = IiIi1i [ iIiIIi ]
    if ( OO0ii11II1II1 == "" ) : continue
    oO00oooo00 = IiIi1Ii [ iIiIIi ]
    oO00oooo00 . json_name = OO0ii11II1II1
    if 66 - 66: I1Ii111 . Ii1I / I1ii11iIi11i / iIii1I11I1II1 + O0 / i1IIi
    if 72 - 72: ooOoO0o . II111iiii
  if ( O0O0o0oO00o0 == "datetime-range" ) :
   for iIiIIi in range ( len ( IiIi1Ii ) ) :
    OO0ii11II1II1 = IiIi1i [ iIiIIi ]
    oO00oooo00 = IiIi1Ii [ iIiIIi ]
    if ( OO0ii11II1II1 == "" ) : continue
    o0oOOO = lisp_datetime ( OO0ii11II1II1 [ 0 : 19 ] )
    OOOOoOOoo0 = lisp_datetime ( OO0ii11II1II1 [ 19 : : ] )
    if ( o0oOOO . valid_datetime ( ) and OOOOoOOoo0 . valid_datetime ( ) ) :
     oO00oooo00 . datetime_lower = o0oOOO
     oO00oooo00 . datetime_upper = OOOOoOOoo0
     if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
     if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
     if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
     if 18 - 18: o0oOOo0O0Ooo / OOooOOo
     if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
     if 100 - 100: O0
     if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
  if ( O0O0o0oO00o0 == "set-action" ) :
   o00oo . set_action = IiIi1i
   if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
  if ( O0O0o0oO00o0 == "set-record-ttl" ) :
   o00oo . set_record_ttl = int ( IiIi1i )
   if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
  if ( O0O0o0oO00o0 == "set-instance-id" ) :
   if ( o00oo . set_source_eid == None ) :
    o00oo . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 38 - 38: Ii1I
   if ( o00oo . set_dest_eid == None ) :
    o00oo . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
   i1111I111i = int ( IiIi1i )
   o00oo . set_source_eid . instance_id = i1111I111i
   o00oo . set_dest_eid . instance_id = i1111I111i
   if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
  if ( O0O0o0oO00o0 == "set-source-eid" ) :
   if ( o00oo . set_source_eid == None ) :
    o00oo . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 36 - 36: I1Ii111 - OoO0O00 . I1ii11iIi11i * I1ii11iIi11i
   o00oo . set_source_eid . store_prefix ( IiIi1i )
   if ( i1111I111i != None ) : o00oo . set_source_eid . instance_id = i1111I111i
   if 9 - 9: OOooOOo - oO0o - iIii1I11I1II1 * i11iIiiIii / I11i
  if ( O0O0o0oO00o0 == "set-destination-eid" ) :
   if ( o00oo . set_dest_eid == None ) :
    o00oo . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 2 - 2: i1IIi % iII111i * ooOoO0o / OoOoOO00 + Oo0Ooo
   o00oo . set_dest_eid . store_prefix ( IiIi1i )
   if ( i1111I111i != None ) : o00oo . set_dest_eid . instance_id = i1111I111i
   if 59 - 59: i11iIiiIii / I1IiiI * iII111i
  if ( O0O0o0oO00o0 == "set-rloc-address" ) :
   o00oo . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   o00oo . set_rloc_address . store_address ( IiIi1i )
   if 16 - 16: i11iIiiIii * II111iiii - ooOoO0o
  if ( O0O0o0oO00o0 == "set-rloc-record-name" ) :
   o00oo . set_rloc_record_name = IiIi1i
   if 80 - 80: iIii1I11I1II1 + iIii1I11I1II1 + I1Ii111 - IiII * iII111i - Ii1I
  if ( O0O0o0oO00o0 == "set-elp-name" ) :
   o00oo . set_elp_name = IiIi1i
   if 89 - 89: O0 * ooOoO0o
  if ( O0O0o0oO00o0 == "set-geo-name" ) :
   o00oo . set_geo_name = IiIi1i
   if 36 - 36: I1ii11iIi11i * II111iiii * iII111i + I1IiiI + OoO0O00 + oO0o
  if ( O0O0o0oO00o0 == "set-rle-name" ) :
   o00oo . set_rle_name = IiIi1i
   if 28 - 28: Ii1I - i11iIiiIii . oO0o / II111iiii
  if ( O0O0o0oO00o0 == "set-json-name" ) :
   o00oo . set_json_name = IiIi1i
   if 82 - 82: iII111i * iII111i . IiII * II111iiii
  if ( O0O0o0oO00o0 == "policy-name" ) :
   o00oo . policy_name = IiIi1i
   if 17 - 17: OoooooooOO % I1Ii111 * I1Ii111 / II111iiii . OoOoOO00 * iII111i
   if 80 - 80: IiII % i11iIiiIii
   if 6 - 6: II111iiii + i11iIiiIii - Oo0Ooo % OOooOOo + Oo0Ooo
   if 46 - 46: iII111i
   if 31 - 31: OoO0O00 + I1Ii111 / iIii1I11I1II1
   if 11 - 11: ooOoO0o - OoOoOO00
 o00oo . match_clauses = IiIi1Ii
 o00oo . save_policy ( )
 return
 if 19 - 19: O0 . OoOoOO00 - i1IIi . oO0o
 if 96 - 96: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoO0O00 * iIii1I11I1II1 + ooOoO0o - ooOoO0o
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
if 4 - 4: OoO0O00 - OOooOOo
if 21 - 21: I1Ii111 * i11iIiiIii
if 63 - 63: oO0o + OoOoOO00
if 50 - 50: o0oOOo0O0Ooo / Oo0Ooo * ooOoO0o * Ii1I
if 97 - 97: I1IiiI / oO0o + I1Ii111 + I1Ii111
if 86 - 86: o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * ooOoO0o
if 20 - 20: Ii1I * iII111i / ooOoO0o
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 18 - 18: Oo0Ooo * Ii1I / i11iIiiIii . OoO0O00 + OoooooooOO
 IiiIiiiII = command
 if ( interface != "" ) : IiiIiiiII = interface + ": " + IiiIiiiII
 lprint ( "Send CLI command '{}' to hardware" . format ( IiiIiiiII ) )
 if 81 - 81: IiII * I11i - iIii1I11I1II1
 III1IIIII1II = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 78 - 78: I1Ii111 % OoO0O00 . IiII % iIii1I11I1II1 / OoO0O00
 os . system ( "FastCli -c '{}'" . format ( III1IIIII1II ) )
 return
 if 34 - 34: iIii1I11I1II1
 if 33 - 33: I1ii11iIi11i + I1Ii111 * ooOoO0o / i11iIiiIii
 if 83 - 83: oO0o
 if 93 - 93: II111iiii
 if 89 - 89: OoO0O00 % II111iiii % iII111i
 if 66 - 66: OoooooooOO % iII111i % i11iIiiIii
 if 35 - 35: OoooooooOO - IiII
def lisp_arista_is_alive ( prefix ) :
 i1 = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 ooOo0O0O0oOO0 = getoutput ( "FastCli -c '{}'" . format ( i1 ) )
 if 38 - 38: I1Ii111 % I11i . I11i % I11i + OoOoOO00
 if 79 - 79: I1ii11iIi11i + OoO0O00 * I1ii11iIi11i / I11i
 if 13 - 13: OoOoOO00 . iII111i
 if 11 - 11: Oo0Ooo - Ii1I / OoO0O00
 ooOo0O0O0oOO0 = ooOo0O0O0oOO0 . split ( "\n" ) [ 1 ]
 oOoo = ooOo0O0O0oOO0 . split ( " " )
 oOoo = oOoo [ - 1 ] . replace ( "\r" , "" )
 if 59 - 59: OOooOOo % IiII . ooOoO0o + O0 . ooOoO0o + iIii1I11I1II1
 if 68 - 68: i11iIiiIii . iII111i + OoooooooOO + II111iiii + iIii1I11I1II1 % I11i
 if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
 if 62 - 62: OoOoOO00 * oO0o - I1IiiI / Ii1I
 return ( oOoo == "Y" )
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
 if 61 - 61: I1Ii111 + I11i + I1IiiI
 if 48 - 48: I11i
 if 67 - 67: o0oOOo0O0Ooo
 if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
def lisp_program_vxlan_hardware ( mc ) :
 if 61 - 61: i11iIiiIii / Ii1I - OOooOOo . I1ii11iIi11i
 if 89 - 89: ooOoO0o % i11iIiiIii
 if 57 - 57: Oo0Ooo / ooOoO0o - O0 . ooOoO0o
 if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
 if 75 - 75: Ii1I
 if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 99 - 99: oO0o + I11i % i1IIi . iII111i
 if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
 if 65 - 65: OoO0O00
 if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
 if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
 if 74 - 74: OoOoOO00 + I1ii11iIi11i
 if 82 - 82: II111iiii
 Oo0o0OOoOo = mc . eid . print_prefix_no_iid ( )
 OOOo0 = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
 if 48 - 48: ooOoO0o + Oo0Ooo / Oo0Ooo
 if 15 - 15: iIii1I11I1II1 . I1Ii111 * OoooooooOO * O0 % OOooOOo
 if 53 - 53: Ii1I
 o0OO0ooooO = getoutput ( "ip route get {} | egrep vlan4094" . format ( Oo0o0OOoOo ) )
 if 19 - 19: iII111i * i1IIi - I11i + O0 % Ii1I - OoOoOO00
 if ( o0OO0ooooO != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( Oo0o0OOoOo , False ) , o0OO0ooooO ) )
  if 1 - 1: I11i * Oo0Ooo
  return
  if 53 - 53: II111iiii / i1IIi + OoooooooOO * O0
  if 62 - 62: IiII . O0
  if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
  if 91 - 91: OOooOOo % oO0o . OoOoOO00 . I1IiiI - OoOoOO00
  if 18 - 18: O0 - I1IiiI + i1IIi % i11iIiiIii
  if 97 - 97: iII111i * OoooooooOO + I1Ii111 + ooOoO0o - ooOoO0o
  if 63 - 63: o0oOOo0O0Ooo * OOooOOo + iIii1I11I1II1 + Oo0Ooo
 iI11Ii = getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( iI11Ii . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 7 - 7: OoO0O00 * I1ii11iIi11i / I1Ii111
 if ( iI11Ii . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 98 - 98: II111iiii % I1ii11iIi11i
 I1IIIIiIIIi = getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( I1IIIIiIIIi == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 85 - 85: Oo0Ooo - OoOoOO00 * IiII + i1IIi
 I1IIIIiIIIi = I1IIIIiIIIi . split ( "inet " ) [ 1 ]
 I1IIIIiIIIi = I1IIIIiIIIi . split ( "/" ) [ 0 ]
 if 40 - 40: I1ii11iIi11i / O0
 if 87 - 87: ooOoO0o
 if 100 - 100: iII111i + II111iiii * Oo0Ooo * OOooOOo
 if 6 - 6: IiII % OOooOOo
 if 3 - 3: OoOoOO00 / OoOoOO00 - II111iiii
 if 41 - 41: oO0o
 if 12 - 12: I1IiiI + I1Ii111
 O0O0o00 = [ ]
 iI111i1Ii = getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for I11I111i1I1 in iI111i1Ii :
  if ( I11I111i1I1 . find ( "vlan4094" ) == - 1 ) : continue
  if ( I11I111i1I1 . find ( "(incomplete)" ) == - 1 ) : continue
  oo0O0 = I11I111i1I1 . split ( " " ) [ 0 ]
  O0O0o00 . append ( oo0O0 )
  if 47 - 47: Oo0Ooo - i1IIi % Ii1I + IiII
  if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
 oo0O0 = None
 O00Oo000 = I1IIIIiIIIi
 I1IIIIiIIIi = I1IIIIiIIIi . split ( "." )
 for iIiIIi in range ( 1 , 255 ) :
  I1IIIIiIIIi [ 3 ] = str ( iIiIIi )
  OOOo = "." . join ( I1IIIIiIIIi )
  if ( OOOo in O0O0o00 ) : continue
  if ( OOOo == O00Oo000 ) : continue
  oo0O0 = OOOo
  break
  if 98 - 98: I1ii11iIi11i
 if ( oo0O0 == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 58 - 58: IiII / i11iIiiIii % I11i
  return
  if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
  if 21 - 21: Ii1I
  if 72 - 72: I1Ii111 . OoooooooOO / I1Ii111 - Ii1I / I1ii11iIi11i * I1ii11iIi11i
  if 72 - 72: IiII . Ii1I + OoooooooOO * OoOoOO00 + Oo0Ooo . iII111i
  if 92 - 92: O0 * Ii1I - I1ii11iIi11i - IiII . OoO0O00 + I1IiiI
  if 59 - 59: i1IIi * OOooOOo % Oo0Ooo
  if 44 - 44: iIii1I11I1II1 . OOooOOo
 oo0Oo0 = OOOo0 . split ( "." )
 i11iIIiIII = lisp_hex_string ( oo0Oo0 [ 1 ] ) . zfill ( 2 )
 IIi1i1ii1 = lisp_hex_string ( oo0Oo0 [ 2 ] ) . zfill ( 2 )
 ooooooOoO0 = lisp_hex_string ( oo0Oo0 [ 3 ] ) . zfill ( 2 )
 i111I11i1I = "00:00:00:{}:{}:{}" . format ( i11iIIiIII , IIi1i1ii1 , ooooooOoO0 )
 iiiI1i1I1 = "0000.00{}.{}{}" . format ( i11iIIiIII , IIi1i1ii1 , ooooooOoO0 )
 IiiiIiI = "arp -i vlan4094 -s {} {}" . format ( oo0O0 , i111I11i1I )
 os . system ( IiiiIiI )
 if 34 - 34: Oo0Ooo / Ii1I * OoooooooOO
 if 71 - 71: o0oOOo0O0Ooo % ooOoO0o / oO0o - oO0o / OoooooooOO
 if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
 if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
 Ii1I11iII = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( iiiI1i1I1 , OOOo0 )
 if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
 lisp_send_to_arista ( Ii1I11iII , None )
 if 16 - 16: I11i
 if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
 if 61 - 61: O0 % iII111i
 if 41 - 41: I1Ii111 * OoooooooOO
 if 76 - 76: OoooooooOO * II111iiii . II111iiii / o0oOOo0O0Ooo - iII111i
 Iiio00oooo = "ip route add {} via {}" . format ( Oo0o0OOoOo , oo0O0 )
 os . system ( Iiio00oooo )
 if 11 - 11: ooOoO0o
 lprint ( "Hardware programmed with commands:" )
 Iiio00oooo = Iiio00oooo . replace ( Oo0o0OOoOo , green ( Oo0o0OOoOo , False ) )
 lprint ( "  " + Iiio00oooo )
 lprint ( "  " + IiiiIiI )
 Ii1I11iII = Ii1I11iII . replace ( OOOo0 , red ( OOOo0 , False ) )
 lprint ( "  " + Ii1I11iII )
 return
 if 62 - 62: Ii1I
 if 27 - 27: ooOoO0o + ooOoO0o + II111iiii % I11i % I1Ii111
 if 13 - 13: O0 / iII111i + oO0o
 if 76 - 76: i11iIiiIii / OoO0O00 + ooOoO0o
 if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
 if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
 if 57 - 57: i1IIi
def lisp_clear_hardware_walk ( mc , parms ) :
 o00OO = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( o00OO ) )
 return ( [ True , None ] )
 if 41 - 41: I11i / Ii1I
 if 1 - 1: II111iiii / iII111i
 if 83 - 83: OoO0O00 / iII111i
 if 59 - 59: I1Ii111 % OOooOOo . I1IiiI + I1ii11iIi11i % oO0o
 if 96 - 96: OoO0O00
 if 53 - 53: oO0o + OoO0O00
 if 58 - 58: iIii1I11I1II1 + OoOoOO00
 if 65 - 65: iII111i % Oo0Ooo * iIii1I11I1II1 + I1IiiI + II111iiii
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list , lisp_gleaned_groups
 global lisp_no_map_request_rate_limit
 if 72 - 72: OoOoOO00 . OoooooooOO - OOooOOo
 iiIIII1 = bold ( "User cleared" , False )
 IiI = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( iiIIII1 , IiI ) )
 if 18 - 18: IiII
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 65 - 65: IiII
 lisp_map_cache = lisp_cache ( )
 if 76 - 76: I1Ii111 % I1ii11iIi11i + ooOoO0o / I1IiiI
 if 59 - 59: OOooOOo - o0oOOo0O0Ooo - o0oOOo0O0Ooo % I1IiiI
 if 55 - 55: o0oOOo0O0Ooo % I1ii11iIi11i - IiII + OoooooooOO
 if 44 - 44: iII111i * I1Ii111 - I1IiiI % i1IIi
 lisp_no_map_request_rate_limit = lisp_get_timestamp ( )
 if 35 - 35: iII111i . OoOoOO00 + i1IIi . I1Ii111 - oO0o
 if 92 - 92: o0oOOo0O0Ooo
 if 8 - 8: i1IIi / IiII . O0
 if 72 - 72: OOooOOo
 if 20 - 20: i11iIiiIii + Oo0Ooo * Oo0Ooo % OOooOOo
 lisp_rloc_probe_list = { }
 if 66 - 66: I1ii11iIi11i + iII111i / Ii1I / I1IiiI * i11iIiiIii
 if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
 if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
 if 71 - 71: oO0o
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
 if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
 if 16 - 16: I1Ii111 + O0 - O0 * iIii1I11I1II1 / iII111i
 if 4 - 4: iII111i
 if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
 lisp_rtr_list = { }
 if 32 - 32: iII111i
 if 59 - 59: OoOoOO00 - I1Ii111
 if 34 - 34: ooOoO0o . OoooooooOO / ooOoO0o + OoooooooOO
 if 24 - 24: OoooooooOO * I1ii11iIi11i / O0 / Oo0Ooo * I1IiiI / ooOoO0o
 lisp_gleaned_groups = { }
 if 33 - 33: Ii1I
 if 20 - 20: Ii1I + I11i
 if 98 - 98: OOooOOo
 if 58 - 58: i11iIiiIii / OoOoOO00
 lisp_process_data_plane_restart ( True )
 return
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
def lisp_encap_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 49 - 49: OoooooooOO . I1ii11iIi11i / OoooooooOO * oO0o
 if 81 - 81: I1ii11iIi11i . ooOoO0o + I1ii11iIi11i
 if 84 - 84: OoooooooOO
 if 95 - 95: o0oOOo0O0Ooo
 I1IIiIi1IIi = lisp_myrlocs [ 0 ]
 if ( lisp_i_am_rtr and lisp_on_aws ( ) ) :
  OOOo = lisp_get_interface_address ( "eth0" )
  if ( OOOo == None ) : OOOo = lisp_get_interface_address ( "ens5" )
  if ( OOOo ) : I1IIiIi1IIi = OOOo
  if 1 - 1: OoOoOO00 / I1ii11iIi11i . O0 . Oo0Ooo
  if 23 - 23: i11iIiiIii / I11i + i1IIi % I1Ii111
  if 100 - 100: Oo0Ooo
  if 13 - 13: I1IiiI + ooOoO0o * II111iiii
  if 32 - 32: iIii1I11I1II1 + O0 + i1IIi
  if 28 - 28: IiII + I11i
 iIo00oo = len ( packet ) + 28
 I1IiiIiii1 = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( iIo00oo ) , 0 , 64 ,
 17 , 0 , socket . htonl ( I1IIiIi1IIi . address ) , socket . htonl ( rloc . address ) )
 I1IiiIiii1 = lisp_ip_checksum ( I1IiiIiii1 )
 if 1 - 1: OoooooooOO - i11iIiiIii . OoooooooOO - o0oOOo0O0Ooo - OOooOOo * I1Ii111
 iiI1iiIiiiI1I = socket . htons ( LISP_DATA_PORT )
 i111I1 = socket . htons ( LISP_CTRL_PORT )
 Ii1iiI1 = struct . pack ( "HHHH" , iiI1iiIiiiI1I , i111I1 , socket . htons ( iIo00oo - 20 ) , 0 )
 if 56 - 56: Ii1I . OoO0O00
 if 43 - 43: iII111i * iII111i
 if 31 - 31: O0 - iIii1I11I1II1 . I11i . oO0o
 if 96 - 96: OoooooooOO * iIii1I11I1II1 * Oo0Ooo
 O00o0Oo = packet [ 0 : 1 ]
 packet = lisp_packet ( I1IiiIiii1 + Ii1iiI1 + packet )
 if 76 - 76: OoO0O00 / i11iIiiIii % ooOoO0o % I11i * O0
 if 84 - 84: II111iiii - iII111i / IiII . O0 % i1IIi / I1ii11iIi11i
 if 2 - 2: OoooooooOO . OoO0O00 . II111iiii / Ii1I - OOooOOo % Oo0Ooo
 if 47 - 47: OOooOOo * oO0o
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( I1IIiIi1IIi )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( I1IIiIi1IIi )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 41 - 41: OoooooooOO * I1IiiI
 IIII1iI1IiIiI = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  oo0O = " {}" . format ( blue ( nat_info . hostname , False ) )
 else :
  oo0O = ""
  if 3 - 3: IiII
 if ( lisp_is_rloc_probe_request ( O00o0Oo ) ) :
  Ii1IiI = bold ( "RLOC-probe request" , False )
 else :
  Ii1IiI = bold ( "RLOC-probe reply" , False )
  if 96 - 96: I11i - OOooOOo + I11i
  if 71 - 71: Oo0Ooo
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( Ii1IiI , IIII1iI1IiIiI , oo0O , packet . encap_port ) )
 if 48 - 48: o0oOOo0O0Ooo / II111iiii / OoOoOO00 * o0oOOo0O0Ooo + I1IiiI . OoOoOO00
 if 52 - 52: Ii1I / OoOoOO00 . OOooOOo * IiII . OoooooooOO
 if 6 - 6: i1IIi . oO0o % IiII . Oo0Ooo % I11i
 if 86 - 86: OoooooooOO + IiII % o0oOOo0O0Ooo . i1IIi . iII111i
 if 25 - 25: iII111i * I1ii11iIi11i + I11i - I1ii11iIi11i
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 75 - 75: IiII
 oOo0O0oO = lisp_sockets [ 3 ]
 packet . send_packet ( oOo0O0oO , packet . outer_dest )
 del ( packet )
 return
 if 15 - 15: I1Ii111
 if 25 - 25: I1ii11iIi11i * O0
 if 8 - 8: i11iIiiIii
 if 95 - 95: ooOoO0o + i1IIi / OOooOOo . i11iIiiIii
 if 31 - 31: iII111i - iII111i - oO0o
 if 62 - 62: Oo0Ooo % Oo0Ooo / OoooooooOO * o0oOOo0O0Ooo . Ii1I
 if 1 - 1: I1ii11iIi11i / II111iiii / II111iiii + o0oOOo0O0Ooo + OoooooooOO
 if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
def lisp_get_default_route_next_hops ( ) :
 if 87 - 87: OOooOOo * OoO0O00
 if 61 - 61: iII111i - II111iiii . I1Ii111 % II111iiii / I11i
 if 86 - 86: II111iiii
 if 94 - 94: o0oOOo0O0Ooo % Ii1I * Ii1I % Oo0Ooo / I1ii11iIi11i
 if ( lisp_is_macos ( ) ) :
  i1 = "route -n get default"
  IIiii1i1IiI = getoutput ( i1 ) . split ( "\n" )
  ooOoooo0O0 = i1i1111I = None
  for ii1I11ooOOoo0 in IIiii1i1IiI :
   if ( ii1I11ooOOoo0 . find ( "gateway: " ) != - 1 ) : ooOoooo0O0 = ii1I11ooOOoo0 . split ( ": " ) [ 1 ]
   if ( ii1I11ooOOoo0 . find ( "interface: " ) != - 1 ) : i1i1111I = ii1I11ooOOoo0 . split ( ": " ) [ 1 ]
   if 47 - 47: OoooooooOO
  return ( [ [ i1i1111I , ooOoooo0O0 ] ] )
  if 65 - 65: I1ii11iIi11i . o0oOOo0O0Ooo * I1Ii111
  if 52 - 52: IiII - ooOoO0o / I11i + OoO0O00 * II111iiii
  if 16 - 16: ooOoO0o - I1ii11iIi11i % oO0o + OoooooooOO - ooOoO0o . OoOoOO00
  if 67 - 67: O0 - o0oOOo0O0Ooo - OOooOOo
  if 17 - 17: i1IIi - ooOoO0o + O0 + I1IiiI / I11i / OoO0O00
 i1 = "ip route | egrep 'default via'"
 o0Oo0o0 = getoutput ( i1 ) . split ( "\n" )
 if 94 - 94: i1IIi - oO0o - O0 . I1Ii111
 i1i1i11i = [ ]
 for o0OO0ooooO in o0Oo0o0 :
  o0O00o0o = o0OO0ooooO . split ( )
  try :
   OoO0 = o0O00o0o [ - 1 ]
   oo0O0 = o0O00o0o [ - 3 ]
  except :
   continue
   if 86 - 86: i11iIiiIii . i11iIiiIii - iII111i . oO0o % i11iIiiIii
  i1i1i11i . append ( [ OoO0 , oo0O0 ] )
  if 65 - 65: OoooooooOO
 return ( i1i1i11i )
 if 50 - 50: II111iiii / IiII . I1ii11iIi11i * OoooooooOO
 if 9 - 9: O0 + II111iiii / OOooOOo . OoOoOO00 * i1IIi - O0
 if 48 - 48: i1IIi
 if 75 - 75: I1Ii111 . I11i % iII111i
 if 80 - 80: oO0o - i11iIiiIii % o0oOOo0O0Ooo * oO0o - OoOoOO00 - ooOoO0o
 if 16 - 16: iIii1I11I1II1 % OoO0O00 * OoOoOO00 - I11i * OoO0O00 - OoOoOO00
 if 35 - 35: I11i * II111iiii . Oo0Ooo % OOooOOo - II111iiii - OoO0O00
def lisp_get_host_route_next_hop ( rloc ) :
 i1 = "ip route | egrep '{} via'" . format ( rloc )
 o0OO0ooooO = getoutput ( i1 ) . split ( )
 if 62 - 62: Ii1I . i11iIiiIii % OOooOOo
 try : o00o = o0OO0ooooO . index ( "via" ) + 1
 except : return ( None )
 if 44 - 44: i1IIi * I1ii11iIi11i % Ii1I . Ii1I * I11i + II111iiii
 if ( o00o >= len ( o0OO0ooooO ) ) : return ( None )
 return ( o0OO0ooooO [ o00o ] )
 if 15 - 15: i1IIi - I11i - I1Ii111 / OoO0O00 + Oo0Ooo + I1IiiI
 if 81 - 81: IiII
 if 54 - 54: I1IiiI % OoO0O00 % OoOoOO00
 if 12 - 12: II111iiii . O0 * i11iIiiIii . I11i
 if 98 - 98: II111iiii + i1IIi * oO0o % I1IiiI
 if 53 - 53: i11iIiiIii . I1ii11iIi11i - OOooOOo - OOooOOo
 if 97 - 97: I1IiiI % iII111i % OoooooooOO / ooOoO0o / i11iIiiIii
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 OoooOOOOO0 = "none" if nh == None else nh
 if 7 - 7: O0 % IiII / o0oOOo0O0Ooo
 lprint ( "{} host-route {}/32, nh {}" . format ( install . title ( ) , dest , OoooOOOOO0 ) )
 if 79 - 79: IiII + I1Ii111
 if ( nh == None ) :
  i11I1111iIII = "ip route {} {}/32" . format ( install , dest )
 else :
  i11I1111iIII = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 59 - 59: iII111i - oO0o . ooOoO0o / IiII * i11iIiiIii
 os . system ( i11I1111iIII )
 return
 if 61 - 61: I11i - Oo0Ooo * II111iiii + iIii1I11I1II1
 if 37 - 37: OoooooooOO % II111iiii / o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i . iIii1I11I1II1
 if 73 - 73: OoOoOO00
 if 44 - 44: Oo0Ooo / oO0o
 if 9 - 9: i1IIi % I1IiiI + OoO0O00 * ooOoO0o / iIii1I11I1II1 / iII111i
 if 80 - 80: OOooOOo / O0 % IiII * OoOoOO00
 if 53 - 53: OOooOOo + i11iIiiIii
 if 25 - 25: i11iIiiIii
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 51 - 51: iII111i . ooOoO0o
 ii1I11ooOOoo0 = open ( lisp_checkpoint_filename , "w" )
 for iIiiI11II11i in checkpoint_list :
  ii1I11ooOOoo0 . write ( iIiiI11II11i + "\n" )
  if 70 - 70: I11i / O0 - I11i + o0oOOo0O0Ooo . ooOoO0o . o0oOOo0O0Ooo
 ii1I11ooOOoo0 . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 6 - 6: I11i + II111iiii - I1Ii111
 if 45 - 45: i1IIi / iII111i + i11iIiiIii * I11i + ooOoO0o / OoooooooOO
 if 56 - 56: I11i + I1Ii111
 if 80 - 80: II111iiii . Ii1I + o0oOOo0O0Ooo / II111iiii / OoO0O00 + iIii1I11I1II1
 if 29 - 29: o0oOOo0O0Ooo + OoOoOO00 + ooOoO0o - I1ii11iIi11i
 if 64 - 64: O0 / OoooooooOO
 if 28 - 28: I1ii11iIi11i + oO0o . Oo0Ooo % iIii1I11I1II1 / I1Ii111
 if 8 - 8: O0 . I1IiiI * o0oOOo0O0Ooo + I1IiiI
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 44 - 44: i1IIi % iII111i . i11iIiiIii / I11i + OoooooooOO
 ii1I11ooOOoo0 = open ( lisp_checkpoint_filename , "r" )
 if 21 - 21: OoOoOO00 . OoO0O00 . OoOoOO00 + OoOoOO00
 IiI = 0
 for iIiiI11II11i in ii1I11ooOOoo0 :
  IiI += 1
  o0o00oO0oo000 = iIiiI11II11i . split ( " rloc " )
  oOo000O00O0 = [ ] if ( o0o00oO0oo000 [ 1 ] in [ "native-forward\n" , "\n" ] ) else o0o00oO0oo000 [ 1 ] . split ( ", " )
  if 30 - 30: I1IiiI - iII111i - OOooOOo + oO0o
  if 51 - 51: Ii1I % O0 / II111iiii . Oo0Ooo
  oO0O0O0O0OO = [ ]
  for OOOo0 in oOo000O00O0 :
   oO0O0oOOO0 = lisp_rloc ( False )
   o0O00o0o = OOOo0 . split ( " " )
   oO0O0oOOO0 . rloc . store_address ( o0O00o0o [ 0 ] )
   oO0O0oOOO0 . priority = int ( o0O00o0o [ 1 ] )
   oO0O0oOOO0 . weight = int ( o0O00o0o [ 2 ] )
   oO0O0O0O0OO . append ( oO0O0oOOO0 )
   if 90 - 90: i11iIiiIii * II111iiii % iIii1I11I1II1 . I1ii11iIi11i / Oo0Ooo . OOooOOo
   if 77 - 77: OoO0O00
  Ii111 = lisp_mapping ( "" , "" , oO0O0O0O0OO )
  if ( Ii111 != None ) :
   Ii111 . eid . store_prefix ( o0o00oO0oo000 [ 0 ] )
   Ii111 . checkpoint_entry = True
   Ii111 . map_cache_ttl = LISP_NMR_TTL * 60
   if ( oO0O0O0O0OO == [ ] ) : Ii111 . action = LISP_NATIVE_FORWARD_ACTION
   Ii111 . add_cache ( )
   continue
   if 95 - 95: II111iiii
   if 59 - 59: iIii1I11I1II1 % OOooOOo / OoOoOO00 * I1Ii111 * OoooooooOO * O0
  IiI -= 1
  if 43 - 43: OoO0O00 * I1IiiI * OOooOOo * O0 - O0 / o0oOOo0O0Ooo
  if 77 - 77: I11i % I1Ii111 . IiII % OoooooooOO * o0oOOo0O0Ooo
 ii1I11ooOOoo0 . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , IiI , lisp_checkpoint_filename ) )
 return
 if 87 - 87: iII111i + IiII / ooOoO0o * ooOoO0o * OOooOOo
 if 97 - 97: I1Ii111
 if 47 - 47: iII111i / I1ii11iIi11i - Ii1I . II111iiii
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
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 68 - 68: Ii1I % o0oOOo0O0Ooo / OoooooooOO + Ii1I - Ii1I
 iIiiI11II11i = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 79 - 79: II111iiii / IiII
 for oO0O0oOOO0 in mc . rloc_set :
  if ( oO0O0oOOO0 . rloc . is_null ( ) ) : continue
  iIiiI11II11i += "{} {} {}, " . format ( oO0O0oOOO0 . rloc . print_address_no_iid ( ) ,
 oO0O0oOOO0 . priority , oO0O0oOOO0 . weight )
  if 4 - 4: O0 - i11iIiiIii % ooOoO0o * O0 - ooOoO0o
  if 96 - 96: oO0o % II111iiii . Ii1I % OoO0O00 . iIii1I11I1II1 / IiII
 if ( mc . rloc_set != [ ] ) :
  iIiiI11II11i = iIiiI11II11i [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  iIiiI11II11i += "native-forward"
  if 96 - 96: o0oOOo0O0Ooo / O0 . iIii1I11I1II1 . Ii1I % OOooOOo % II111iiii
  if 5 - 5: OoooooooOO / I1Ii111 % I1Ii111 / I1IiiI
 checkpoint_list . append ( iIiiI11II11i )
 return
 if 19 - 19: I1IiiI - ooOoO0o % IiII - o0oOOo0O0Ooo * OOooOOo + I1ii11iIi11i
 if 44 - 44: i1IIi
 if 85 - 85: I1ii11iIi11i / IiII + oO0o
 if 95 - 95: IiII . OoO0O00
 if 36 - 36: IiII % Ii1I - OoOoOO00 + OoO0O00 + IiII * Ii1I
 if 15 - 15: I1IiiI / O0 % I1ii11iIi11i % OoOoOO00 . OoOoOO00 + iII111i
 if 79 - 79: OOooOOo + Ii1I . I1Ii111 / Oo0Ooo / i11iIiiIii / O0
def lisp_check_dp_socket ( ) :
 IiiIIiI1IIi = lisp_ipc_dp_socket_name
 if ( os . path . exists ( IiiIIiI1IIi ) == False ) :
  i1iI1Ii = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( IiiIIiI1IIi , i1iI1Ii ) )
  return ( False )
  if 40 - 40: I11i * oO0o + Ii1I
 return ( True )
 if 13 - 13: O0 / Ii1I / i1IIi * oO0o
 if 85 - 85: II111iiii
 if 7 - 7: OOooOOo - O0 . iIii1I11I1II1 * II111iiii * IiII
 if 66 - 66: I1Ii111 + i11iIiiIii % ooOoO0o * i11iIiiIii + Oo0Ooo + OoOoOO00
 if 56 - 56: i1IIi + i1IIi . IiII . Oo0Ooo % OOooOOo
 if 51 - 51: OoO0O00 + i1IIi + iIii1I11I1II1
 if 68 - 68: OoOoOO00 . I1IiiI + ooOoO0o - o0oOOo0O0Ooo
def lisp_write_to_dp_socket ( entry ) :
 try :
  o00000oo = json . dumps ( entry )
  ii11I = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( ii11I , o00000oo ) )
  lisp_ipc_dp_socket . sendto ( o00000oo , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( o00000oo ) )
  if 100 - 100: ooOoO0o * I11i
 return
 if 6 - 6: O0 * iII111i % I1ii11iIi11i - OOooOOo + Ii1I
 if 54 - 54: OoO0O00 % Ii1I + i1IIi . Oo0Ooo * I1Ii111 * oO0o
 if 62 - 62: o0oOOo0O0Ooo
 if 6 - 6: OoO0O00 * i11iIiiIii . I1ii11iIi11i % OoO0O00 % O0 / OoO0O00
 if 80 - 80: OoOoOO00 / I1IiiI % O0
 if 90 - 90: O0 . o0oOOo0O0Ooo - OoooooooOO % iIii1I11I1II1
 if 19 - 19: iIii1I11I1II1 / iII111i
 if 62 - 62: OoooooooOO - ooOoO0o
 if 47 - 47: I11i * I1IiiI / oO0o
def lisp_write_ipc_keys ( rloc ) :
 Oo0o = rloc . rloc . print_address_no_iid ( )
 O00oo0o0o0oo = rloc . translated_port
 if ( O00oo0o0o0oo != 0 ) : Oo0o += ":" + str ( O00oo0o0o0oo )
 if ( Oo0o not in lisp_rloc_probe_list ) : return
 if 98 - 98: Ii1I / oO0o * O0 + I1Ii111 - I1Ii111 + iII111i
 for o0O00o0o , o0o00oO0oo000 , o0O0Ooo in lisp_rloc_probe_list [ Oo0o ] :
  Ii111 = lisp_map_cache . lookup_cache ( o0o00oO0oo000 , True )
  if ( Ii111 == None ) : continue
  lisp_write_ipc_map_cache ( True , Ii111 )
  if 4 - 4: i1IIi
 return
 if 43 - 43: oO0o * ooOoO0o - I11i
 if 70 - 70: oO0o / Ii1I
 if 15 - 15: iIii1I11I1II1 % ooOoO0o % i11iIiiIii
 if 16 - 16: iII111i
 if 50 - 50: iIii1I11I1II1 - II111iiii % i1IIi
 if 48 - 48: O0
 if 60 - 60: ooOoO0o - IiII % i1IIi
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 5 - 5: oO0o
 if 29 - 29: i1IIi . OoOoOO00 . i1IIi + oO0o . I1Ii111 + O0
 if 62 - 62: I1ii11iIi11i . IiII + OoO0O00 - OoOoOO00 * O0 + I1Ii111
 if 58 - 58: oO0o . OoO0O00 / ooOoO0o
 o0ooOOoO0oO0 = "add" if add_or_delete else "delete"
 iIiiI11II11i = { "type" : "map-cache" , "opcode" : o0ooOOoO0oO0 }
 if 61 - 61: I11i + I1Ii111
 oOiI1111iI1 = ( mc . group . is_null ( ) == False )
 if ( oOiI1111iI1 ) :
  iIiiI11II11i [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  iIiiI11II11i [ "rles" ] = [ ]
 else :
  iIiiI11II11i [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  iIiiI11II11i [ "rlocs" ] = [ ]
  if 27 - 27: ooOoO0o / i1IIi . oO0o - OoooooooOO
 iIiiI11II11i [ "instance-id" ] = str ( mc . eid . instance_id )
 if 48 - 48: ooOoO0o % ooOoO0o / OoooooooOO + i1IIi * oO0o + ooOoO0o
 if ( oOiI1111iI1 ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for iIiII in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    OOOo = iIiII . address . print_address_no_iid ( )
    O00oo0o0o0oo = str ( 4341 ) if iIiII . translated_port == 0 else str ( iIiII . translated_port )
    if 69 - 69: iII111i . iII111i
    o0O00o0o = { "rle" : OOOo , "port" : O00oo0o0o0oo }
    OoOooo0oO0oOo , i1II11i11111 = iIiII . get_encap_keys ( )
    o0O00o0o = lisp_build_json_keys ( o0O00o0o , OoOooo0oO0oOo , i1II11i11111 , "encrypt-key" )
    iIiiI11II11i [ "rles" ] . append ( o0O00o0o )
    if 36 - 36: I1ii11iIi11i * oO0o - I1ii11iIi11i / O0 % ooOoO0o
    if 30 - 30: i1IIi % I1ii11iIi11i + I1Ii111 - OoO0O00 % O0 . I1Ii111
 else :
  for OOOo0 in mc . rloc_set :
   if ( OOOo0 . rloc . is_ipv4 ( ) == False and OOOo0 . rloc . is_ipv6 ( ) == False ) :
    continue
    if 63 - 63: ooOoO0o % I1Ii111 * I1ii11iIi11i % I1ii11iIi11i . ooOoO0o - O0
   if ( OOOo0 . up_state ( ) == False ) : continue
   if 62 - 62: ooOoO0o
   O00oo0o0o0oo = str ( 4341 ) if OOOo0 . translated_port == 0 else str ( OOOo0 . translated_port )
   if 35 - 35: iII111i . i11iIiiIii - OOooOOo % Oo0Ooo + Ii1I . iIii1I11I1II1
   o0O00o0o = { "rloc" : OOOo0 . rloc . print_address_no_iid ( ) , "priority" :
 str ( OOOo0 . priority ) , "weight" : str ( OOOo0 . weight ) , "port" :
 O00oo0o0o0oo }
   OoOooo0oO0oOo , i1II11i11111 = OOOo0 . get_encap_keys ( )
   o0O00o0o = lisp_build_json_keys ( o0O00o0o , OoOooo0oO0oOo , i1II11i11111 , "encrypt-key" )
   iIiiI11II11i [ "rlocs" ] . append ( o0O00o0o )
   if 91 - 91: o0oOOo0O0Ooo / OoO0O00 + I1IiiI % i11iIiiIii % i1IIi
   if 22 - 22: I1Ii111 * O0 % OoO0O00 * I1ii11iIi11i
   if 47 - 47: OoO0O00 / OOooOOo / OoOoOO00 % i11iIiiIii / OoOoOO00
 if ( dont_send == False ) : lisp_write_to_dp_socket ( iIiiI11II11i )
 return ( iIiiI11II11i )
 if 52 - 52: ooOoO0o / I11i % i11iIiiIii - I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
 if 67 - 67: OoOoOO00 / I1Ii111 + i11iIiiIii - IiII
 if 79 - 79: I11i . I11i - OoOoOO00
 if 86 - 86: OoO0O00 * Oo0Ooo . iIii1I11I1II1 * O0
 if 52 - 52: iII111i - i11iIiiIii + o0oOOo0O0Ooo + i1IIi
 if 58 - 58: OOooOOo - Ii1I * I1Ii111 - O0 . oO0o
 if 72 - 72: i1IIi * iII111i * Ii1I / o0oOOo0O0Ooo . I1Ii111 + i11iIiiIii
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 33 - 33: I11i / OoO0O00 * ooOoO0o + iIii1I11I1II1
 if 54 - 54: Oo0Ooo / IiII + i11iIiiIii . O0
 if 94 - 94: OoooooooOO + iII111i * OoooooooOO / o0oOOo0O0Ooo
 if 12 - 12: iIii1I11I1II1 / iIii1I11I1II1 / II111iiii
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 93 - 93: oO0o
 OoOooo0oO0oOo = keys [ 1 ] . encrypt_key
 i1II11i11111 = keys [ 1 ] . icv_key
 if 53 - 53: OoO0O00 * i1IIi / Oo0Ooo / OoO0O00 * ooOoO0o
 if 77 - 77: iIii1I11I1II1 % I1IiiI + o0oOOo0O0Ooo + I1Ii111 * Oo0Ooo * i1IIi
 if 14 - 14: iIii1I11I1II1 * iIii1I11I1II1 - OOooOOo . iII111i / ooOoO0o
 if 54 - 54: OoOoOO00 - I1IiiI - iII111i
 iiI1i1II11ii = rloc_addr . split ( ":" )
 if ( len ( iiI1i1II11ii ) == 1 ) :
  iIiiI11II11i = { "type" : "decap-keys" , "rloc" : iiI1i1II11ii [ 0 ] }
 else :
  iIiiI11II11i = { "type" : "decap-keys" , "rloc" : iiI1i1II11ii [ 0 ] , "port" : iiI1i1II11ii [ 1 ] }
  if 19 - 19: IiII . ooOoO0o . IiII % oO0o / oO0o - oO0o
 iIiiI11II11i = lisp_build_json_keys ( iIiiI11II11i , OoOooo0oO0oOo , i1II11i11111 , "decrypt-key" )
 if 30 - 30: iII111i + Ii1I * IiII
 lisp_write_to_dp_socket ( iIiiI11II11i )
 return
 if 49 - 49: II111iiii * Ii1I % OoOoOO00 % OoOoOO00
 if 35 - 35: oO0o + Oo0Ooo / Oo0Ooo % iII111i
 if 84 - 84: OoOoOO00 * I1ii11iIi11i
 if 45 - 45: O0 % OoO0O00
 if 35 - 35: i1IIi * I11i * iII111i
 if 21 - 21: II111iiii * iII111i * IiII % II111iiii / iII111i
 if 22 - 22: iII111i - OOooOOo . Ii1I - I1Ii111
 if 67 - 67: I11i - OoO0O00 / Oo0Ooo
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 27 - 27: Ii1I % I1IiiI - iII111i
 entry [ "keys" ] = [ ]
 III11II111 = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( III11II111 )
 return ( entry )
 if 13 - 13: IiII + OOooOOo . I11i - ooOoO0o . Ii1I - IiII
 if 8 - 8: Ii1I + I11i . O0 / II111iiii
 if 79 - 79: IiII / I11i - I1Ii111
 if 62 - 62: IiII + I11i % I1ii11iIi11i . ooOoO0o % OoOoOO00
 if 27 - 27: I11i + IiII % o0oOOo0O0Ooo / II111iiii * I11i % I1ii11iIi11i
 if 12 - 12: I1Ii111 - I1IiiI % i11iIiiIii * iIii1I11I1II1 + OoOoOO00 + i11iIiiIii
 if 36 - 36: Oo0Ooo + oO0o / I1Ii111 / iII111i . O0 % II111iiii
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 67 - 67: I11i / iIii1I11I1II1 / ooOoO0o
 if 90 - 90: II111iiii % I1Ii111 - IiII . Oo0Ooo % OOooOOo - OoOoOO00
 if 89 - 89: Oo0Ooo - I1ii11iIi11i . I1Ii111
 if 65 - 65: ooOoO0o % OOooOOo + OOooOOo % I1Ii111 . I1IiiI % O0
 iIiiI11II11i = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 46 - 46: OoO0O00 * I1Ii111 + iII111i . oO0o % OOooOOo / i11iIiiIii
 if 1 - 1: I1ii11iIi11i % O0 - I1ii11iIi11i / OoooooooOO / OoO0O00
 if 82 - 82: i1IIi % Ii1I
 if 85 - 85: I1Ii111 * i11iIiiIii * iIii1I11I1II1 % iIii1I11I1II1
 for Oo0000 in lisp_db_list :
  if ( Oo0000 . eid . is_ipv4 ( ) == False and Oo0000 . eid . is_ipv6 ( ) == False ) : continue
  oO00o = { "instance-id" : str ( Oo0000 . eid . instance_id ) ,
 "eid-prefix" : Oo0000 . eid . print_prefix_no_iid ( ) }
  iIiiI11II11i [ "database-mappings" ] . append ( oO00o )
  if 74 - 74: Oo0Ooo - II111iiii - o0oOOo0O0Ooo - i11iIiiIii % II111iiii
 lisp_write_to_dp_socket ( iIiiI11II11i )
 if 22 - 22: II111iiii . OOooOOo + ooOoO0o . I1ii11iIi11i
 if 27 - 27: I1Ii111 + O0 - Ii1I * iII111i + i1IIi
 if 40 - 40: o0oOOo0O0Ooo / OoO0O00 . I11i % iIii1I11I1II1 % I1Ii111 % I1Ii111
 if 28 - 28: OoO0O00 + ooOoO0o + OOooOOo * i11iIiiIii - i11iIiiIii + Oo0Ooo
 if 13 - 13: OoooooooOO / iIii1I11I1II1 - I1ii11iIi11i / i1IIi % iIii1I11I1II1
 iIiiI11II11i = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( iIiiI11II11i )
 return
 if 86 - 86: iII111i * I11i * OoO0O00 / I1ii11iIi11i * I1ii11iIi11i
 if 79 - 79: I11i - I1Ii111 / iIii1I11I1II1 - OOooOOo
 if 38 - 38: iIii1I11I1II1 - OoooooooOO * II111iiii . OoooooooOO + OOooOOo
 if 59 - 59: OoooooooOO
 if 22 - 22: II111iiii
 if 85 - 85: I1Ii111 + I1ii11iIi11i * I11i % o0oOOo0O0Ooo + Ii1I
 if 23 - 23: IiII * OoO0O00
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 42 - 42: IiII
 if 83 - 83: i1IIi * o0oOOo0O0Ooo / OoO0O00 / o0oOOo0O0Ooo
 if 55 - 55: Oo0Ooo % O0 - OoO0O00
 if 42 - 42: OoooooooOO * OOooOOo
 iIiiI11II11i = { "type" : "interfaces" , "interfaces" : [ ] }
 if 93 - 93: OOooOOo + II111iiii . oO0o * Oo0Ooo - O0 + I1Ii111
 for i1i1111I in list ( lisp_myinterfaces . values ( ) ) :
  if ( i1i1111I . instance_id == None ) : continue
  oO00o = { "interface" : i1i1111I . device ,
 "instance-id" : str ( i1i1111I . instance_id ) }
  iIiiI11II11i [ "interfaces" ] . append ( oO00o )
  if 99 - 99: OoO0O00 * o0oOOo0O0Ooo + OoOoOO00 * iIii1I11I1II1
  if 38 - 38: I1ii11iIi11i - OOooOOo * O0 - I1ii11iIi11i
 lisp_write_to_dp_socket ( iIiiI11II11i )
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
 if 42 - 42: OoOoOO00 % I1ii11iIi11i * I1Ii111 * i1IIi . i1IIi % OOooOOo
def lisp_parse_auth_key ( value ) :
 oooOOOo00OoO0 = value . split ( "[" )
 OO0OoO00oOo0O = { }
 if ( len ( oooOOOo00OoO0 ) == 1 ) :
  OO0OoO00oOo0O [ 0 ] = value
  return ( OO0OoO00oOo0O )
  if 7 - 7: iII111i . OoO0O00 / ooOoO0o . OoO0O00 - Oo0Ooo
  if 15 - 15: OoO0O00 / Ii1I + O0 . i11iIiiIii
 for OO0ii11II1II1 in oooOOOo00OoO0 :
  if ( OO0ii11II1II1 == "" ) : continue
  o00o = OO0ii11II1II1 . find ( "]" )
  oo0OO0oo = OO0ii11II1II1 [ 0 : o00o ]
  try : oo0OO0oo = int ( oo0OO0oo )
  except : return
  if 68 - 68: o0oOOo0O0Ooo
  OO0OoO00oOo0O [ oo0OO0oo ] = OO0ii11II1II1 [ o00o + 1 : : ]
  if 54 - 54: I11i / OoOoOO00 % OoooooooOO - o0oOOo0O0Ooo
 return ( OO0OoO00oOo0O )
 if 84 - 84: iIii1I11I1II1
 if 65 - 65: OoooooooOO + I1ii11iIi11i
 if 41 - 41: OOooOOo + I1Ii111 + i11iIiiIii % iII111i % I1Ii111 - ooOoO0o
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
def lisp_reassemble ( packet ) :
 oOO0O00o0O0 = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 32 - 32: IiII
 if 99 - 99: II111iiii
 if 34 - 34: OOooOOo + OoOoOO00 * o0oOOo0O0Ooo + I1ii11iIi11i + IiII * i1IIi
 if 73 - 73: I1ii11iIi11i - IiII - O0 . oO0o + Oo0Ooo % iII111i
 if ( oOO0O00o0O0 == 0 or oOO0O00o0O0 == 0x4000 ) : return ( packet )
 if 68 - 68: I1ii11iIi11i - OoooooooOO
 if 5 - 5: I1ii11iIi11i * I1IiiI + OoooooooOO / Oo0Ooo
 if 18 - 18: OoO0O00 * iII111i % I1IiiI . OOooOOo * o0oOOo0O0Ooo
 if 58 - 58: iII111i . IiII + iIii1I11I1II1
 i11I1iiii = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 o00O0O = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 13 - 13: oO0o * I1Ii111 / I1Ii111 . I1IiiI
 O0OOOOoo0o = ( oOO0O00o0O0 & 0x2000 == 0 and ( oOO0O00o0O0 & 0x1fff ) != 0 )
 iIiiI11II11i = [ ( oOO0O00o0O0 & 0x1fff ) * 8 , o00O0O - 20 , packet , O0OOOOoo0o ]
 if 5 - 5: iII111i % Oo0Ooo - oO0o . i1IIi - i11iIiiIii % I1ii11iIi11i
 if 79 - 79: I1IiiI
 if 24 - 24: I1IiiI / II111iiii - I1Ii111
 if 68 - 68: I1IiiI
 if 97 - 97: Ii1I + o0oOOo0O0Ooo / OoO0O00
 if 97 - 97: i11iIiiIii % iIii1I11I1II1 + II111iiii
 if 90 - 90: OOooOOo / I1IiiI
 if 28 - 28: OoooooooOO + i1IIi
 if ( oOO0O00o0O0 == 0x2000 ) :
  iiI1iiIiiiI1I , i111I1 = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  iiI1iiIiiiI1I = socket . ntohs ( iiI1iiIiiiI1I )
  i111I1 = socket . ntohs ( i111I1 )
  if ( i111I1 not in [ 4341 , 8472 , 4789 ] and iiI1iiIiiiI1I != 4341 ) :
   lisp_reassembly_queue [ i11I1iiii ] = [ ]
   iIiiI11II11i [ 2 ] = None
   if 29 - 29: Oo0Ooo
   if 98 - 98: OOooOOo / Oo0Ooo % Ii1I * OoooooooOO - oO0o
   if 64 - 64: I1IiiI - I1IiiI
   if 90 - 90: iII111i - I1IiiI - II111iiii / OOooOOo + Ii1I
   if 34 - 34: i11iIiiIii + I1Ii111 / O0 / iIii1I11I1II1 * OoooooooOO % Ii1I
   if 32 - 32: i11iIiiIii - OoOoOO00 / iIii1I11I1II1 * o0oOOo0O0Ooo % I1IiiI + O0
 if ( i11I1iiii not in lisp_reassembly_queue ) :
  lisp_reassembly_queue [ i11I1iiii ] = [ ]
  if 36 - 36: I1ii11iIi11i + I1ii11iIi11i % I1Ii111 * ooOoO0o * OoOoOO00
  if 54 - 54: Oo0Ooo - I1IiiI % OOooOOo . I1ii11iIi11i / I1IiiI
  if 75 - 75: OOooOOo - O0 % iII111i . Ii1I % I1ii11iIi11i + I1ii11iIi11i
  if 32 - 32: Ii1I + II111iiii * IiII
  if 9 - 9: I1Ii111
 queue = lisp_reassembly_queue [ i11I1iiii ]
 if 96 - 96: I1Ii111 / iIii1I11I1II1
 if 48 - 48: iII111i * IiII + OoooooooOO
 if 63 - 63: I1IiiI / Ii1I
 if 31 - 31: i1IIi - oO0o
 if 99 - 99: iII111i - i11iIiiIii + oO0o
 if ( len ( queue ) == 1 and queue [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( i11I1iiii ) . zfill ( 4 ) ) )
  if 66 - 66: Oo0Ooo * I11i . iIii1I11I1II1 - OoO0O00
  return ( None )
  if 11 - 11: I1Ii111 + iIii1I11I1II1 * O0 * Oo0Ooo
  if 66 - 66: OoooooooOO % OoO0O00 + i11iIiiIii + I1Ii111 % OoO0O00
  if 80 - 80: Oo0Ooo - Ii1I
  if 54 - 54: O0 - iIii1I11I1II1 . OoO0O00 . IiII % OoO0O00
  if 28 - 28: O0 % i1IIi % OoO0O00 / o0oOOo0O0Ooo . iIii1I11I1II1 - iII111i
 queue . append ( iIiiI11II11i )
 queue = sorted ( queue )
 if 50 - 50: o0oOOo0O0Ooo + iII111i / i1IIi % II111iiii
 if 61 - 61: IiII
 if 5 - 5: OOooOOo % iIii1I11I1II1 % O0 * i11iIiiIii / I1Ii111
 if 48 - 48: IiII * oO0o
 OOOo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 OOOo . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 oooo00000O0o0 = OOOo . print_address_no_iid ( )
 OOOo . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 I1IIi1iI = OOOo . print_address_no_iid ( )
 OOOo = red ( "{} -> {}" . format ( oooo00000O0o0 , I1IIi1iI ) , False )
 if 80 - 80: I11i
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if iIiiI11II11i [ 2 ] == None else "" , OOOo , lisp_hex_string ( i11I1iiii ) . zfill ( 4 ) ,
 # oO0o % ooOoO0o / i11iIiiIii - O0 % OoO0O00 - I1Ii111
 # oO0o * Oo0Ooo * IiII
 lisp_hex_string ( oOO0O00o0O0 ) . zfill ( 4 ) ) )
 if 26 - 26: o0oOOo0O0Ooo + O0 % i11iIiiIii . ooOoO0o . I1IiiI + Oo0Ooo
 if 90 - 90: IiII * OoooooooOO + II111iiii / iII111i + i11iIiiIii / ooOoO0o
 if 20 - 20: II111iiii % I1ii11iIi11i - OoooooooOO * Ii1I / I11i - OoooooooOO
 if 11 - 11: I1IiiI + Ii1I + i11iIiiIii * I1ii11iIi11i - oO0o
 if 46 - 46: OoooooooOO - Oo0Ooo
 if ( queue [ 0 ] [ 0 ] != 0 or queue [ - 1 ] [ 3 ] == False ) : return ( None )
 IiIOoo000O00Oo = queue [ 0 ]
 for oo0O00o0O0Oo in queue [ 1 : : ] :
  oOO0O00o0O0 = oo0O00o0O0Oo [ 0 ]
  OO0OO0OoO , OOO0OOo = IiIOoo000O00Oo [ 0 ] , IiIOoo000O00Oo [ 1 ]
  if ( OO0OO0OoO + OOO0OOo != oOO0O00o0O0 ) : return ( None )
  IiIOoo000O00Oo = oo0O00o0O0Oo
  if 67 - 67: OoooooooOO % I1IiiI + o0oOOo0O0Ooo + I1Ii111
 lisp_reassembly_queue . pop ( i11I1iiii )
 if 12 - 12: o0oOOo0O0Ooo - Ii1I - I1Ii111 - II111iiii % iIii1I11I1II1 % Ii1I
 if 5 - 5: OOooOOo % OoooooooOO / Oo0Ooo
 if 16 - 16: ooOoO0o * i11iIiiIii % i1IIi % i1IIi
 if 44 - 44: Oo0Ooo % I11i - o0oOOo0O0Ooo - Ii1I * Oo0Ooo - Ii1I
 if 69 - 69: II111iiii + o0oOOo0O0Ooo
 packet = queue [ 0 ] [ 2 ]
 for oo0O00o0O0Oo in queue [ 1 : : ] : packet += oo0O00o0O0Oo [ 2 ] [ 20 : : ]
 if 75 - 75: OOooOOo
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( i11I1iiii ) . zfill ( 4 ) , len ( packet ) ) )
 if 66 - 66: Oo0Ooo % oO0o
 if 52 - 52: oO0o
 if 26 - 26: OoO0O00 % I1ii11iIi11i * O0 % OoO0O00
 if 98 - 98: OoO0O00 . ooOoO0o * I11i / i1IIi
 if 57 - 57: i11iIiiIii % OOooOOo
 iIo00oo = socket . htons ( len ( packet ) )
 I1IIII = packet [ 0 : 2 ] + struct . pack ( "H" , iIo00oo ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 67 - 67: oO0o - OOooOOo + II111iiii
 if 19 - 19: iIii1I11I1II1 * OoooooooOO - i11iIiiIii . I1Ii111 * OoO0O00
 I1IIII = lisp_ip_checksum ( I1IIII )
 return ( I1IIII + packet [ 20 : : ] )
 if 30 - 30: iII111i + I1IiiI * ooOoO0o
 if 53 - 53: iII111i + IiII
 if 52 - 52: II111iiii * i11iIiiIii - IiII * IiII / OoooooooOO
 if 18 - 18: IiII / O0 / I1ii11iIi11i
 if 47 - 47: oO0o / iIii1I11I1II1
 if 45 - 45: OoOoOO00 * o0oOOo0O0Ooo / I1ii11iIi11i * iII111i - I1ii11iIi11i
 if 48 - 48: Ii1I / OoO0O00
 if 45 - 45: O0 * OoO0O00 / I11i . II111iiii
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 Oo0o = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( Oo0o in lisp_crypto_keys_by_rloc_decap ) : return ( Oo0o )
 if 20 - 20: I11i - IiII
 Oo0o = addr . print_address_no_iid ( )
 if ( Oo0o in lisp_crypto_keys_by_rloc_decap ) : return ( Oo0o )
 if 75 - 75: i11iIiiIii + I11i % I11i . I1Ii111
 if 58 - 58: o0oOOo0O0Ooo * II111iiii + o0oOOo0O0Ooo . I1IiiI
 if 25 - 25: o0oOOo0O0Ooo * I11i
 if 70 - 70: OOooOOo
 if 11 - 11: I11i * II111iiii * Oo0Ooo + OOooOOo % i1IIi
 for OOooo00 in lisp_crypto_keys_by_rloc_decap :
  oO = OOooo00 . split ( ":" )
  if ( len ( oO ) == 1 ) : continue
  oO = oO [ 0 ] if len ( oO ) == 2 else ":" . join ( oO [ 0 : - 1 ] )
  if ( oO == Oo0o ) :
   O0o0O0 = lisp_crypto_keys_by_rloc_decap [ OOooo00 ]
   lisp_crypto_keys_by_rloc_decap [ Oo0o ] = O0o0O0
   return ( Oo0o )
   if 18 - 18: i1IIi . OOooOOo * o0oOOo0O0Ooo . iII111i / o0oOOo0O0Ooo + I11i
   if 56 - 56: I1Ii111 - OoOoOO00 / I11i
 return ( None )
 if 77 - 77: I1IiiI + I1IiiI . o0oOOo0O0Ooo + i11iIiiIii - I1IiiI
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
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 Ii111I11iI = addr + ":" + str ( port )
 if 52 - 52: iIii1I11I1II1 + o0oOOo0O0Ooo + oO0o + o0oOOo0O0Ooo
 if ( lisp_i_am_rtr ) :
  if ( addr in lisp_rloc_probe_list ) : return ( addr )
  if 55 - 55: OoOoOO00 - Ii1I
  if 35 - 35: OOooOOo / I1ii11iIi11i + OoOoOO00 / I1Ii111
  if 46 - 46: I1Ii111 + I1Ii111 / i11iIiiIii * OOooOOo
  if 39 - 39: oO0o + I1IiiI * iII111i + OOooOOo
  if 84 - 84: i1IIi * I11i / o0oOOo0O0Ooo
  if 23 - 23: O0 % Ii1I / I11i / I1Ii111 . i1IIi
  for i1o0 in list ( lisp_nat_state_info . values ( ) ) :
   for i1Iiii1I in i1o0 :
    if ( addr == i1Iiii1I . address ) : return ( Ii111I11iI )
    if 99 - 99: ooOoO0o / II111iiii * I1ii11iIi11i
    if 61 - 61: I11i . II111iiii
  return ( addr )
  if 59 - 59: i11iIiiIii . I1ii11iIi11i * I1IiiI . O0 - I1Ii111 - OoO0O00
 return ( Ii111I11iI )
 if 45 - 45: OoooooooOO - I11i - I1IiiI . oO0o - IiII
 if 96 - 96: I11i . I1IiiI * iII111i / IiII - I1Ii111
 if 59 - 59: O0 * ooOoO0o / II111iiii % OoooooooOO . o0oOOo0O0Ooo
 if 55 - 55: OOooOOo - o0oOOo0O0Ooo * I1IiiI / o0oOOo0O0Ooo + I1Ii111 + iIii1I11I1II1
 if 3 - 3: II111iiii % iII111i / IiII * ooOoO0o . OoooooooOO
 if 56 - 56: IiII * II111iiii + Oo0Ooo - O0 - OoO0O00 . I1Ii111
 if 53 - 53: i1IIi + IiII
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 90 - 90: II111iiii / oO0o / oO0o . OoOoOO00 / OoO0O00 / iIii1I11I1II1
 if 96 - 96: iIii1I11I1II1 % I1ii11iIi11i
 if 35 - 35: i1IIi - OoooooooOO * Ii1I / OOooOOo % I11i
 if 72 - 72: I1Ii111 / OoO0O00 + II111iiii
 if 40 - 40: Ii1I + O0 . i11iIiiIii % I11i / Oo0Ooo
 if 25 - 25: IiII * IiII
 if 54 - 54: I1Ii111
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 90 - 90: Oo0Ooo / Ii1I
 if 66 - 66: i11iIiiIii - I11i + oO0o . OoooooooOO
 if 77 - 77: OoO0O00 / OOooOOo
 if 97 - 97: OoOoOO00 / Ii1I * I1IiiI - Oo0Ooo % O0
 if 66 - 66: O0 + I1IiiI % iIii1I11I1II1 . i1IIi % II111iiii - i1IIi
 if 93 - 93: O0 + OoooooooOO % IiII % oO0o % I1ii11iIi11i
 if 36 - 36: I1IiiI - oO0o * Oo0Ooo + oO0o % iII111i - i11iIiiIii
 if 93 - 93: O0
 if 11 - 11: OoooooooOO . I1ii11iIi11i + I1ii11iIi11i
 if 73 - 73: OoooooooOO
 if 2 - 2: o0oOOo0O0Ooo % IiII + I1ii11iIi11i - i11iIiiIii
 if 100 - 100: II111iiii + oO0o
 if 85 - 85: I1ii11iIi11i % I1ii11iIi11i . Ii1I
 if 42 - 42: oO0o + OoO0O00
 if 16 - 16: Ii1I
 if 67 - 67: I1ii11iIi11i . OoooooooOO * I1Ii111 + Ii1I * OOooOOo
 if 84 - 84: OOooOOo
 if 78 - 78: O0 % O0
 if 72 - 72: o0oOOo0O0Ooo * IiII / II111iiii / iIii1I11I1II1
def lisp_is_rloc_probe ( packet , device , rr ) :
 Ii1iiI1 = ( struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ] == 17 )
 if ( Ii1iiI1 == False ) : return ( [ packet , None , None , None ] )
 if 41 - 41: iII111i / Ii1I
 iiI1iiIiiiI1I = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 i111I1 = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 iIi11iii1I1 = ( socket . htons ( LISP_CTRL_PORT ) in [ iiI1iiIiiiI1I , i111I1 ] )
 if ( iIi11iii1I1 == False ) : return ( [ packet , None , None , None ] )
 if 45 - 45: ooOoO0o
 if ( rr == 0 ) :
  Ii1IiI = lisp_is_rloc_probe_request ( packet [ 28 : 29 ] )
  if ( Ii1IiI == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  Ii1IiI = lisp_is_rloc_probe_reply ( packet [ 28 : 29 ] )
  if ( Ii1IiI == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  Ii1IiI = lisp_is_rloc_probe_request ( packet [ 28 : 29 ] )
  if ( Ii1IiI == False ) :
   Ii1IiI = lisp_is_rloc_probe_reply ( packet [ 28 : 29 ] )
   if ( Ii1IiI == False ) : return ( [ packet , None , None , None ] )
   if 52 - 52: I1ii11iIi11i % Ii1I - iIii1I11I1II1 . ooOoO0o % I1IiiI
   if 57 - 57: OoO0O00 % Ii1I
   if 11 - 11: OoO0O00
   if 74 - 74: OoO0O00 - OOooOOo - ooOoO0o - iIii1I11I1II1
   if 29 - 29: ooOoO0o
   if 31 - 31: o0oOOo0O0Ooo / IiII - oO0o / OoOoOO00 * IiII * i1IIi
 iiIIiIi1i1I1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 iiIIiIi1i1I1 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 45 - 45: OoOoOO00 + iII111i % iIii1I11I1II1 - IiII * OOooOOo
 if 62 - 62: Ii1I / Oo0Ooo / I1ii11iIi11i . OoOoOO00 % ooOoO0o * IiII
 if 97 - 97: ooOoO0o
 if 14 - 14: iII111i + iII111i
 if ( iiIIiIi1i1I1 . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 62 - 62: ooOoO0o / OOooOOo * I1ii11iIi11i + Oo0Ooo - OoooooooOO - OoooooooOO
 if 19 - 19: Ii1I . oO0o
 if 26 - 26: OOooOOo + II111iiii
 if 67 - 67: IiII + OoOoOO00 * I1ii11iIi11i % o0oOOo0O0Ooo / oO0o
 iiIIiIi1i1I1 = iiIIiIi1i1I1 . print_address_no_iid ( )
 O00oo0o0o0oo = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 OO0ooo00o = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 31 - 31: ooOoO0o / Ii1I . Ii1I - I1IiiI - Oo0Ooo . II111iiii
 o0O00o0o = bold ( "Receive(pcap-{})" . format ( device ) , False )
 ii1I11ooOOoo0 = bold ( "from " + iiIIiIi1i1I1 , False )
 o00oo = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( o0O00o0o , len ( packet ) , ii1I11ooOOoo0 , O00oo0o0o0oo , o00oo ) )
 if 82 - 82: Oo0Ooo % Oo0Ooo
 return ( [ packet , iiIIiIi1i1I1 , O00oo0o0o0oo , OO0ooo00o ] )
 if 17 - 17: OOooOOo % Oo0Ooo . I1IiiI * O0 * oO0o % OoOoOO00
 if 99 - 99: Oo0Ooo - ooOoO0o . OoO0O00 - Oo0Ooo / O0
 if 42 - 42: Ii1I - OoOoOO00 . OoOoOO00
 if 88 - 88: o0oOOo0O0Ooo . Ii1I . iII111i * iII111i + i11iIiiIii
 if 68 - 68: OoooooooOO
 if 5 - 5: OoOoOO00 . i11iIiiIii . OOooOOo / I11i * Oo0Ooo % Oo0Ooo
 if 44 - 44: I1ii11iIi11i + oO0o % i1IIi + OoooooooOO
 if 42 - 42: I1Ii111 / I1Ii111 - O0
 if 79 - 79: i11iIiiIii
 if 96 - 96: iIii1I11I1II1 . OoOoOO00 . OOooOOo / iII111i
 if 59 - 59: Oo0Ooo + OOooOOo / Oo0Ooo
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 49 - 49: OoO0O00 / Oo0Ooo % OoOoOO00 % i1IIi
 I1Iii1 = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 66 - 66: OoOoOO00 % II111iiii
 lisp_write_to_dp_socket ( I1Iii1 )
 return
 if 16 - 16: i11iIiiIii - I1IiiI + ooOoO0o * oO0o
 if 30 - 30: II111iiii / o0oOOo0O0Ooo
 if 57 - 57: I11i / I1ii11iIi11i . I11i
 if 68 - 68: OoOoOO00 + O0 . I1IiiI
 if 26 - 26: I1ii11iIi11i
 if 98 - 98: Oo0Ooo
 if 72 - 72: oO0o + OoooooooOO . O0 + IiII
 if 49 - 49: i1IIi - i11iIiiIii + II111iiii + Ii1I / OoO0O00
def lisp_external_data_plane ( ) :
 i1 = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( getoutput ( i1 ) != "" ) : return ( True )
 if 34 - 34: I1ii11iIi11i * i11iIiiIii
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
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
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 48 - 48: I1Ii111 / o0oOOo0O0Ooo - OOooOOo / o0oOOo0O0Ooo % O0
 iIiII1 = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 92 - 92: iIii1I11I1II1 - I1IiiI / OoO0O00 + I1IiiI
 if ( do_clear == False ) :
  IIii11I = iIiII1 [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , IIii11I )
  if 43 - 43: ooOoO0o
  if 90 - 90: IiII % oO0o - I11i
 lisp_write_to_dp_socket ( iIiII1 )
 return
 if 70 - 70: iII111i - II111iiii % I1ii11iIi11i - IiII - ooOoO0o
 if 20 - 20: OoOoOO00
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
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( "entries" not in msg ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 29 - 29: o0oOOo0O0Ooo / O0 / OoO0O00
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 23 - 23: Ii1I + i11iIiiIii % IiII
  if 64 - 64: i11iIiiIii + OoooooooOO . oO0o * Ii1I
 for msg in msg [ "entries" ] :
  if ( "eid-prefix" not in msg ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 49 - 49: O0
  ooOo000OoO0o = msg [ "eid-prefix" ]
  if 72 - 72: I1Ii111
  if ( "instance-id" not in msg ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 96 - 96: II111iiii / OOooOOo % i1IIi / Oo0Ooo
  oO0O = int ( msg [ "instance-id" ] )
  if 22 - 22: I1IiiI % iIii1I11I1II1 % I1ii11iIi11i
  if 68 - 68: iII111i + I11i
  if 61 - 61: oO0o . I1Ii111
  if 74 - 74: O0 . Ii1I - iII111i % IiII + II111iiii
  oO0OooO0o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , oO0O )
  oO0OooO0o0 . store_prefix ( ooOo000OoO0o )
  Ii111 = lisp_map_cache_lookup ( None , oO0OooO0o0 )
  if ( Ii111 == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( ooOo000OoO0o ) )
   if 71 - 71: oO0o + Ii1I % oO0o
   continue
   if 17 - 17: I1Ii111 % I1Ii111 * o0oOOo0O0Ooo
   if 84 - 84: I1Ii111 + iII111i . i1IIi / O0 / I1Ii111 + o0oOOo0O0Ooo
  if ( "rlocs" not in msg ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( ooOo000OoO0o ) )
   if 70 - 70: O0 % ooOoO0o - iII111i + oO0o
   continue
   if 12 - 12: I1Ii111 - OoO0O00 % II111iiii % ooOoO0o / II111iiii % OoOoOO00
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 74 - 74: iII111i . OOooOOo * Ii1I / Oo0Ooo . OoO0O00 . I11i
  OooO0o0O0 = msg [ "rlocs" ]
  if 15 - 15: OOooOOo * Ii1I / ooOoO0o
  if 70 - 70: i11iIiiIii * oO0o . I11i - OoooooooOO / I1ii11iIi11i
  if 10 - 10: IiII * OoOoOO00 . II111iiii . II111iiii * Oo0Ooo
  if 23 - 23: I1ii11iIi11i + I11i
  for oooOOOO0oO0 in OooO0o0O0 :
   if ( "rloc" not in oooOOOO0oO0 ) : continue
   if 28 - 28: I1ii11iIi11i % OoO0O00 - Ii1I * i11iIiiIii
   IIII1iI1IiIiI = oooOOOO0oO0 [ "rloc" ]
   if ( IIII1iI1IiIiI == "no-address" ) : continue
   if 71 - 71: oO0o / Ii1I . OOooOOo / I11i
   OOOo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   OOOo0 . store_address ( IIII1iI1IiIiI )
   if 85 - 85: I1Ii111 . I1IiiI / I1Ii111
   oO0O0oOOO0 = Ii111 . get_rloc ( OOOo0 )
   if ( oO0O0oOOO0 == None ) : continue
   if 7 - 7: I1IiiI
   if 95 - 95: I1IiiI + o0oOOo0O0Ooo * oO0o + Oo0Ooo / OOooOOo * ooOoO0o
   if 46 - 46: O0 + O0 - oO0o
   if 44 - 44: Ii1I / OoooooooOO . i1IIi - O0 * oO0o
   I11II1IiiI = 0 if ( "packet-count" not in oooOOOO0oO0 ) else oooOOOO0oO0 [ "packet-count" ]
   if 76 - 76: I1ii11iIi11i + I1IiiI
   i1oOOoo00OOOO = 0 if ( "byte-count" not in oooOOOO0oO0 ) else oooOOOO0oO0 [ "byte-count" ]
   if 41 - 41: iII111i - i11iIiiIii * i11iIiiIii - O0 * I11i % IiII
   Oo0OO0000oooo = 0 if ( "seconds-last-packet" not in oooOOOO0oO0 ) else oooOOOO0oO0 [ "seconds-last-packet" ]
   if 42 - 42: oO0o
   if 35 - 35: O0 / O0 . i1IIi
   oO0O0oOOO0 . stats . packet_count += I11II1IiiI
   oO0O0oOOO0 . stats . byte_count += i1oOOoo00OOOO
   oO0O0oOOO0 . stats . last_increment = lisp_get_timestamp ( ) - Oo0OO0000oooo
   if 58 - 58: IiII . iII111i % O0 . Ii1I * Oo0Ooo
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( I11II1IiiI , i1oOOoo00OOOO ,
 Oo0OO0000oooo , ooOo000OoO0o , IIII1iI1IiIiI ) )
   if 54 - 54: OoO0O00 % OOooOOo - OoO0O00 . Oo0Ooo % i1IIi
   if 95 - 95: iII111i . OoooooooOO . o0oOOo0O0Ooo / II111iiii - OoooooooOO / I1Ii111
   if 11 - 11: II111iiii / iII111i . oO0o / ooOoO0o / OOooOOo + OoO0O00
   if 37 - 37: iIii1I11I1II1 * O0
   if 64 - 64: I1Ii111 - II111iiii + oO0o % ooOoO0o * oO0o
  if ( Ii111 . group . is_null ( ) and Ii111 . has_ttl_elapsed ( ) ) :
   ooOo000OoO0o = green ( Ii111 . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( ooOo000OoO0o ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , Ii111 . eid , None )
   if 27 - 27: iIii1I11I1II1 - Ii1I . i11iIiiIii / IiII . I1Ii111 / i11iIiiIii
   if 27 - 27: OoOoOO00 . I11i / OoOoOO00
 return
 if 96 - 96: OoO0O00 - I1IiiI
 if 73 - 73: I1IiiI - o0oOOo0O0Ooo - I1Ii111
 if 34 - 34: iIii1I11I1II1 - i1IIi + OoO0O00 % Oo0Ooo + i1IIi
 if 46 - 46: I1IiiI
 if 82 - 82: iII111i . i1IIi
 if 38 - 38: Ii1I . I1IiiI . I1ii11iIi11i
 if 26 - 26: O0 - II111iiii * I1Ii111 - OoOoOO00
 if 96 - 96: I11i * Oo0Ooo / OOooOOo - IiII
 if 75 - 75: OoooooooOO - O0
 if 39 - 39: i11iIiiIii / Ii1I / ooOoO0o
 if 93 - 93: o0oOOo0O0Ooo - Oo0Ooo / oO0o / OoOoOO00
 if 75 - 75: o0oOOo0O0Ooo * ooOoO0o % Ii1I
 if 94 - 94: OoooooooOO + II111iiii / iIii1I11I1II1 * ooOoO0o
 if 85 - 85: ooOoO0o / IiII
 if 28 - 28: i11iIiiIii - OoOoOO00
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
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 46 - 46: I11i % ooOoO0o - Ii1I
 if 25 - 25: O0 / i11iIiiIii . O0
 if 24 - 24: I1ii11iIi11i - i11iIiiIii / iII111i . Oo0Ooo / I1ii11iIi11i
 if 92 - 92: I11i % OoooooooOO
 if 14 - 14: i11iIiiIii * i11iIiiIii * OoOoOO00
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  I1Iii1 = "stats%{}" . format ( json . dumps ( msg ) )
  I1Iii1 = lisp_command_ipc ( I1Iii1 , "lisp-itr" )
  lisp_ipc ( I1Iii1 , lisp_ipc_socket , "lisp-etr" )
  return
  if 84 - 84: OOooOOo % I1Ii111 + I11i / I1IiiI . iII111i
  if 78 - 78: oO0o . Oo0Ooo
  if 18 - 18: IiII
  if 35 - 35: OoooooooOO / i1IIi - OoO0O00 + Oo0Ooo - o0oOOo0O0Ooo
  if 100 - 100: II111iiii % i11iIiiIii % oO0o + O0
  if 46 - 46: OoO0O00 / I1IiiI - Oo0Ooo . o0oOOo0O0Ooo . Oo0Ooo % I11i
  if 43 - 43: IiII - O0 + I1Ii111 % OoooooooOO % OoO0O00 / I1Ii111
  if 48 - 48: I1ii11iIi11i . i1IIi % i1IIi - iII111i * o0oOOo0O0Ooo + IiII
 I1Iii1 = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( I1Iii1 , msg ) )
 if 45 - 45: II111iiii . II111iiii + I1IiiI / I1Ii111 . OoO0O00 - o0oOOo0O0Ooo
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 20 - 20: ooOoO0o % oO0o
 IiIi1iiiiiiIii1 = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 14 - 14: OOooOOo * I1Ii111 % OoO0O00
 for iIiooO000oo0 in IiIi1iiiiiiIii1 :
  I11II1IiiI = 0 if ( iIiooO000oo0 not in msg ) else msg [ iIiooO000oo0 ] [ "packet-count" ]
  lisp_decap_stats [ iIiooO000oo0 ] . packet_count += I11II1IiiI
  if 3 - 3: I1Ii111 * OoO0O00 % OOooOOo
  i1oOOoo00OOOO = 0 if ( iIiooO000oo0 not in msg ) else msg [ iIiooO000oo0 ] [ "byte-count" ]
  lisp_decap_stats [ iIiooO000oo0 ] . byte_count += i1oOOoo00OOOO
  if 8 - 8: i11iIiiIii
  Oo0OO0000oooo = 0 if ( iIiooO000oo0 not in msg ) else msg [ iIiooO000oo0 ] [ "seconds-last-packet" ]
  if 8 - 8: ooOoO0o / OoooooooOO . OoO0O00 . OoOoOO00 - Ii1I . OoO0O00
  lisp_decap_stats [ iIiooO000oo0 ] . last_increment = lisp_get_timestamp ( ) - Oo0OO0000oooo
  if 36 - 36: OoOoOO00 - Ii1I % OoooooooOO % iII111i
 return
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
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 I11iI1 , iiIIiIi1i1I1 = punt_socket . recvfrom ( 4000 )
 if 70 - 70: II111iiii * OoO0O00
 iiI111I = json . loads ( I11iI1 )
 if ( type ( iiI111I ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( iiIIiIi1i1I1 ) )
  if 66 - 66: o0oOOo0O0Ooo - i1IIi + ooOoO0o
  return
  if 57 - 57: OoO0O00 % O0
 oO000OOO0o = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( oO000OOO0o , iiIIiIi1i1I1 , iiI111I ) )
 if 28 - 28: O0 * ooOoO0o * OoooooooOO + II111iiii - i11iIiiIii * OoO0O00
 if ( "type" not in iiI111I ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 73 - 73: OOooOOo * i11iIiiIii - OoO0O00
  if 94 - 94: O0
  if 72 - 72: i1IIi - iII111i * I1IiiI % O0 - I11i * O0
  if 78 - 78: I1IiiI - OoO0O00 / Ii1I . i1IIi
  if 30 - 30: IiII
 if ( iiI111I [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( iiI111I , lisp_send_sockets , lisp_ephem_port )
  return
  if 21 - 21: i1IIi . iII111i - I1IiiI
 if ( iiI111I [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( iiI111I , punt_socket )
  return
  if 28 - 28: IiII / Ii1I - i1IIi - OoOoOO00
  if 65 - 65: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo
  if 77 - 77: OoooooooOO - Oo0Ooo - OoOoOO00 / I11i / O0 . i11iIiiIii
  if 27 - 27: I1Ii111 * O0
  if 9 - 9: i1IIi - Oo0Ooo - i11iIiiIii / iIii1I11I1II1 . i1IIi
 if ( iiI111I [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 2 - 2: I11i + II111iiii - I11i / oO0o / I11i
  if 73 - 73: IiII % I1Ii111 . OoOoOO00
  if 96 - 96: I1IiiI / ooOoO0o / iIii1I11I1II1
  if 91 - 91: Ii1I . I11i
  if 87 - 87: Oo0Ooo / IiII * OOooOOo + I1ii11iIi11i . I11i
 if ( iiI111I [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 56 - 56: oO0o + oO0o % o0oOOo0O0Ooo + OOooOOo . II111iiii + i11iIiiIii
 if ( "interface" not in iiI111I ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( iiIIiIi1i1I1 ) )
  if 45 - 45: iIii1I11I1II1 / o0oOOo0O0Ooo * OoooooooOO - Oo0Ooo
  return
  if 77 - 77: II111iiii
  if 8 - 8: I1IiiI * II111iiii % I1ii11iIi11i
  if 88 - 88: Oo0Ooo . oO0o + OoOoOO00 % OoooooooOO
  if 81 - 81: OoooooooOO . I1Ii111 + OoO0O00 % I1Ii111
  if 49 - 49: oO0o . oO0o % oO0o / Oo0Ooo
 OoO0 = iiI111I [ "interface" ]
 if ( OoO0 == "" ) :
  oO0O = int ( iiI111I [ "instance-id" ] )
  if ( oO0O == - 1 ) : return
 else :
  oO0O = lisp_get_interface_instance_id ( OoO0 , None )
  if 62 - 62: ooOoO0o . i1IIi % OoO0O00 - I1ii11iIi11i - IiII
  if 57 - 57: i1IIi - II111iiii - O0 . iII111i + OoO0O00
  if 67 - 67: OOooOOo * iII111i / iIii1I11I1II1 / I1ii11iIi11i
  if 10 - 10: OoooooooOO % I1ii11iIi11i * i1IIi . iII111i
  if 96 - 96: II111iiii % i11iIiiIii - Oo0Ooo
 iIiI11iIi111i = None
 if ( "source-eid" in iiI111I ) :
  i11iI1I1I11II = iiI111I [ "source-eid" ]
  iIiI11iIi111i = lisp_address ( LISP_AFI_NONE , i11iI1I1I11II , 0 , oO0O )
  if ( iIiI11iIi111i . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( i11iI1I1I11II ) )
   return
   if 70 - 70: O0 * iIii1I11I1II1 - IiII * I11i / Ii1I + i11iIiiIii
   if 26 - 26: II111iiii - I11i % I11i / ooOoO0o + Oo0Ooo
 II11i1I1I = None
 if ( "dest-eid" in iiI111I ) :
  OoO0O0oOooO = iiI111I [ "dest-eid" ]
  II11i1I1I = lisp_address ( LISP_AFI_NONE , OoO0O0oOooO , 0 , oO0O )
  if ( II11i1I1I . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( OoO0O0oOooO ) )
   return
   if 40 - 40: OoooooooOO
   if 71 - 71: OOooOOo
   if 88 - 88: O0
   if 44 - 44: II111iiii - IiII / I1IiiI + ooOoO0o % iII111i - iII111i
   if 53 - 53: OoooooooOO
   if 41 - 41: i1IIi - oO0o
   if 41 - 41: I11i
   if 92 - 92: i11iIiiIii
 if ( iIiI11iIi111i ) :
  o0o00oO0oo000 = green ( iIiI11iIi111i . print_address ( ) , False )
  Oo0000 = lisp_db_for_lookups . lookup_cache ( iIiI11iIi111i , False )
  if ( Oo0000 != None ) :
   if 62 - 62: i1IIi / I1IiiI - o0oOOo0O0Ooo
   if 3 - 3: O0 * OoOoOO00 * I11i / OoOoOO00
   if 77 - 77: i1IIi
   if 3 - 3: iII111i * OoO0O00 - oO0o + iII111i . o0oOOo0O0Ooo + I1IiiI
   if 65 - 65: O0 / OoOoOO00
   if ( Oo0000 . dynamic_eid_configured ( ) ) :
    i1i1111I = lisp_allow_dynamic_eid ( OoO0 , iIiI11iIi111i )
    if ( i1i1111I != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( Oo0000 , iIiI11iIi111i , OoO0 , i1i1111I )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( o0o00oO0oo000 , OoO0 ) )
     if 77 - 77: OoO0O00
     if 17 - 17: i1IIi
     if 35 - 35: OoOoOO00
  else :
   lprint ( "Punt from non-EID source {}" . format ( o0o00oO0oo000 ) )
   if 61 - 61: I1Ii111
   if 78 - 78: I1Ii111 * Ii1I % Ii1I + I1IiiI
   if 83 - 83: iIii1I11I1II1 + O0 / IiII . iIii1I11I1II1
   if 74 - 74: Oo0Ooo
   if 60 - 60: OoooooooOO
   if 16 - 16: iIii1I11I1II1 - OoOoOO00 / I1ii11iIi11i % O0 % o0oOOo0O0Ooo
 if ( II11i1I1I ) :
  Ii111 = lisp_map_cache_lookup ( iIiI11iIi111i , II11i1I1I )
  if ( Ii111 == None or lisp_mr_or_pubsub ( Ii111 . action ) ) :
   if 99 - 99: ooOoO0o . o0oOOo0O0Ooo - O0 * I1Ii111 . i11iIiiIii / iIii1I11I1II1
   if 40 - 40: iIii1I11I1II1 + oO0o / iIii1I11I1II1 - i1IIi % OoO0O00
   if 22 - 22: OOooOOo
   if 65 - 65: i1IIi - oO0o . I1Ii111 . ooOoO0o % I1ii11iIi11i % I1ii11iIi11i
   if 1 - 1: I1Ii111 + I1Ii111
   if ( lisp_rate_limit_map_request ( II11i1I1I ) ) : return
   if 96 - 96: iII111i + OoOoOO00 - o0oOOo0O0Ooo + Ii1I
   oo0ooo = ( Ii111 and Ii111 . action == LISP_SEND_PUBSUB_ACTION )
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 iIiI11iIi111i , II11i1I1I , None , oo0ooo )
  else :
   o0o00oO0oo000 = green ( II11i1I1I . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( o0o00oO0oo000 ) )
   if 6 - 6: O0 . I11i
   if 22 - 22: Oo0Ooo . O0 / i1IIi - OoOoOO00
 return
 if 41 - 41: II111iiii - I1ii11iIi11i - I1Ii111
 if 82 - 82: I1IiiI * I1IiiI / iIii1I11I1II1
 if 14 - 14: I11i + Ii1I - OOooOOo % Ii1I / Ii1I
 if 86 - 86: I1Ii111 - i11iIiiIii + Ii1I + I11i
 if 96 - 96: Ii1I
 if 28 - 28: i1IIi . oO0o . IiII + Oo0Ooo . Oo0Ooo . i1IIi
 if 34 - 34: Oo0Ooo + IiII / i1IIi
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 iIiiI11II11i = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( iIiiI11II11i )
 return ( [ True , jdata ] )
 if 33 - 33: i1IIi
 if 26 - 26: ooOoO0o - Oo0Ooo * II111iiii - Oo0Ooo
 if 15 - 15: OoO0O00 - oO0o . OoOoOO00 / O0 * oO0o
 if 45 - 45: O0
 if 89 - 89: IiII - IiII % o0oOOo0O0Ooo * Oo0Ooo % ooOoO0o
 if 4 - 4: OoO0O00 % II111iiii / I11i
 if 95 - 95: I1Ii111 - I1Ii111 - iII111i + IiII . OoO0O00
 if 5 - 5: i11iIiiIii - O0 % ooOoO0o
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 55 - 55: II111iiii
 if 7 - 7: I1Ii111 % o0oOOo0O0Ooo . oO0o . ooOoO0o % i1IIi / I1IiiI
 if 88 - 88: i11iIiiIii / oO0o - i1IIi / I1IiiI
 if 57 - 57: oO0o + O0 * I11i
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 87 - 87: o0oOOo0O0Ooo % Oo0Ooo * I1ii11iIi11i / OoooooooOO / o0oOOo0O0Ooo
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 78 - 78: Ii1I
 if 5 - 5: i1IIi * ooOoO0o / OoOoOO00 % i11iIiiIii
 if 57 - 57: IiII
 if 89 - 89: I1ii11iIi11i - I1Ii111 + o0oOOo0O0Ooo
 if 62 - 62: I1ii11iIi11i + OoooooooOO * OOooOOo
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 49 - 49: i1IIi - I11i * II111iiii
 if 4 - 4: o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 57 - 57: I1IiiI * OOooOOo . i11iIiiIii * oO0o - OoOoOO00
 if 35 - 35: O0
 if 65 - 65: Oo0Ooo
 if 100 - 100: I1Ii111 . o0oOOo0O0Ooo * OoooooooOO . o0oOOo0O0Ooo
 if 90 - 90: i11iIiiIii . I1IiiI + ooOoO0o * OoooooooOO * OoooooooOO + oO0o
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 ooOo000OoO0o = eid . print_address ( )
 if ( ooOo000OoO0o in db . dynamic_eids ) :
  db . dynamic_eids [ ooOo000OoO0o ] . last_packet = lisp_get_timestamp ( )
  return
  if 77 - 77: OOooOOo * OoOoOO00
  if 75 - 75: Oo0Ooo * Oo0Ooo - IiII - OoOoOO00 / i11iIiiIii + I1Ii111
  if 57 - 57: i11iIiiIii / oO0o
  if 37 - 37: o0oOOo0O0Ooo + OoOoOO00 - i1IIi . Oo0Ooo
  if 3 - 3: ooOoO0o % OoooooooOO / I1Ii111 + oO0o - O0
 iiI1IiI1I1I = lisp_dynamic_eid ( )
 iiI1IiI1I1I . dynamic_eid . copy_address ( eid )
 iiI1IiI1I1I . interface = routed_interface
 iiI1IiI1I1I . last_packet = lisp_get_timestamp ( )
 iiI1IiI1I1I . get_timeout ( routed_interface )
 db . dynamic_eids [ ooOo000OoO0o ] = iiI1IiI1I1I
 if 72 - 72: oO0o * OoO0O00
 oo0OOoOOo0 = ""
 if ( input_interface != routed_interface ) :
  oo0OOoOOo0 = ", routed-interface " + routed_interface
  if 51 - 51: OOooOOo . OOooOOo . I1IiiI
  if 90 - 90: I1Ii111
 ooOoO0OoO0 = green ( ooOo000OoO0o , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( ooOoO0OoO0 , input_interface , oo0OOoOOo0 , iiI1IiI1I1I . timeout ) )
 if 52 - 52: I1Ii111 - IiII / Ii1I
 if 64 - 64: I1Ii111 / Ii1I
 if 78 - 78: I11i % ooOoO0o - iIii1I11I1II1 / iIii1I11I1II1
 if 65 - 65: Ii1I . i1IIi + i11iIiiIii % I1Ii111 . OoO0O00 + Oo0Ooo
 if 82 - 82: O0 % I1IiiI / II111iiii * iII111i - OoO0O00 - II111iiii
 I1Iii1 = "learn%{}%{}" . format ( ooOo000OoO0o , routed_interface )
 I1Iii1 = lisp_command_ipc ( I1Iii1 , "lisp-itr" )
 lisp_ipc ( I1Iii1 , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 51 - 51: I1Ii111 % IiII / iIii1I11I1II1 % I1IiiI * i11iIiiIii
 if 26 - 26: II111iiii
 if 19 - 19: IiII - II111iiii / o0oOOo0O0Ooo . oO0o % OoooooooOO % I1IiiI
 if 76 - 76: oO0o * I1ii11iIi11i
 if 42 - 42: II111iiii . O0
 if 32 - 32: i1IIi % O0 / II111iiii - OoO0O00 + IiII * i11iIiiIii
 if 55 - 55: II111iiii
 if 93 - 93: i11iIiiIii / OoooooooOO % I1ii11iIi11i % I1ii11iIi11i
 if 37 - 37: OoO0O00 . I11i / I1ii11iIi11i . OoO0O00 - I1Ii111 + Oo0Ooo
def lisp_itr_nat_probe ( rloc , rloc_name , lisp_ipc_listen_socket ) :
 IIII1iI1IiIiI = rloc . print_address_no_iid ( )
 if 42 - 42: I1ii11iIi11i . I11i
 if 95 - 95: I1IiiI - I11i * I1Ii111 - I11i
 if 92 - 92: oO0o % iIii1I11I1II1 * o0oOOo0O0Ooo * OoooooooOO - iIii1I11I1II1
 if 51 - 51: Ii1I - OoO0O00 + i1IIi
 I1Iii1 = "nat%{}%{}" . format ( IIII1iI1IiIiI , rloc_name )
 I1Iii1 = lisp_command_ipc ( I1Iii1 , "lisp-itr" )
 lisp_ipc ( I1Iii1 , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 11 - 11: II111iiii - iII111i + oO0o % Oo0Ooo
 if 56 - 56: IiII
 if 72 - 72: Oo0Ooo
 if 37 - 37: i11iIiiIii * I1IiiI % ooOoO0o
 if 23 - 23: OoO0O00 + o0oOOo0O0Ooo * I1IiiI
 if 76 - 76: i1IIi . OOooOOo
 if 78 - 78: OoooooooOO % OoOoOO00 * oO0o . I1ii11iIi11i
 if 79 - 79: OoooooooOO
 if 6 - 6: i11iIiiIii / II111iiii + II111iiii + I1ii11iIi11i % IiII - I1ii11iIi11i
 if 92 - 92: IiII
 if 49 - 49: O0 . OoOoOO00
 if 7 - 7: i1IIi + II111iiii
 if 96 - 96: I1Ii111 / OoO0O00
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 27 - 27: Ii1I
 if 90 - 90: I1ii11iIi11i
 if 43 - 43: OoO0O00 . I1IiiI . oO0o + Ii1I
 if 7 - 7: iII111i / Oo0Ooo - OoO0O00 + I1Ii111 * II111iiii * ooOoO0o
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 80 - 80: oO0o - i1IIi / I11i . II111iiii % O0 % I11i
 i1Iii = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 70 - 70: iIii1I11I1II1 * i1IIi * OOooOOo - Oo0Ooo % i1IIi
 for III11II111 in lisp_crypto_keys_by_rloc_decap :
  if 60 - 60: o0oOOo0O0Ooo . OOooOOo % II111iiii - I1ii11iIi11i
  if 4 - 4: OOooOOo % ooOoO0o
  if 39 - 39: Ii1I
  if 67 - 67: iIii1I11I1II1 - OOooOOo
  if ( III11II111 . find ( addr_str ) == - 1 ) : continue
  if 47 - 47: OOooOOo - OOooOOo * I1Ii111
  if 24 - 24: I1ii11iIi11i
  if 37 - 37: II111iiii - iIii1I11I1II1 / o0oOOo0O0Ooo . O0 + II111iiii
  if 9 - 9: o0oOOo0O0Ooo
  if ( III11II111 == addr_str ) : continue
  if 47 - 47: Ii1I * I1Ii111 / II111iiii
  if 73 - 73: ooOoO0o
  if 53 - 53: IiII . Oo0Ooo
  if 54 - 54: i11iIiiIii % ooOoO0o % I1Ii111 + o0oOOo0O0Ooo
  iIiiI11II11i = lisp_crypto_keys_by_rloc_decap [ III11II111 ]
  if ( iIiiI11II11i == i1Iii ) : continue
  if 2 - 2: IiII
  if 25 - 25: OoOoOO00 . OoO0O00 * o0oOOo0O0Ooo . OoooooooOO - Oo0Ooo + I1IiiI
  if 82 - 82: OoO0O00 - Ii1I * I11i * o0oOOo0O0Ooo
  if 17 - 17: OoooooooOO + I1Ii111
  ooOoO000O0 = iIiiI11II11i [ 1 ]
  if ( packet_icv != ooOoO000O0 . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( III11II111 , False ) ) )
   continue
   if 30 - 30: I1Ii111 * oO0o . I11i . I1ii11iIi11i
   if 9 - 9: O0 / I11i + OoO0O00 - oO0o
  lprint ( "Changing decap crypto key to {}" . format ( red ( III11II111 , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = iIiiI11II11i
  if 60 - 60: OOooOOo - OoOoOO00
 return
 if 68 - 68: I1ii11iIi11i % Oo0Ooo / iII111i . OOooOOo
 if 87 - 87: i1IIi
 if 5 - 5: OOooOOo
 if 22 - 22: Ii1I . I1ii11iIi11i * I1ii11iIi11i * OoOoOO00
 if 23 - 23: I1ii11iIi11i - OoOoOO00 + i11iIiiIii . I11i
 if 52 - 52: iII111i . OoOoOO00 * iIii1I11I1II1 . iII111i * IiII
 if 52 - 52: iII111i + iII111i
 if 35 - 35: I1Ii111 * oO0o + Ii1I / I1IiiI + O0 - I11i
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 42 - 42: o0oOOo0O0Ooo
 if 89 - 89: o0oOOo0O0Ooo
 if 99 - 99: I1ii11iIi11i + Oo0Ooo
 if 20 - 20: OoO0O00 / iII111i
 if 62 - 62: i1IIi % iIii1I11I1II1 + OoOoOO00 - I1IiiI . I1ii11iIi11i
 if 92 - 92: i11iIiiIii * o0oOOo0O0Ooo . Oo0Ooo
 if 15 - 15: o0oOOo0O0Ooo * IiII . iII111i % O0 . iIii1I11I1II1
 if 34 - 34: OOooOOo / iII111i * iIii1I11I1II1 + i11iIiiIii
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 OO0o = dns_name . split ( "." )
 OO0o = "." . join ( OO0o [ 1 : : ] )
 return ( OO0o == lisp_decent_dns_suffix )
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
def lisp_get_decent_index ( eid ) :
 ooOo000OoO0o = eid . print_prefix ( )
 Ii1111IIIi = hmac . new ( b"lisp-decent" , ooOo000OoO0o , hashlib . sha256 ) . hexdigest ( )
 if 21 - 21: OoOoOO00 % oO0o . OoooooooOO + IiII % OoOoOO00
 if 37 - 37: II111iiii
 if 48 - 48: ooOoO0o . i11iIiiIii
 if 67 - 67: OoO0O00 + Oo0Ooo + I1Ii111
 I1i11 = os . getenv ( "LISP_DECENT_HASH_WIDTH" )
 if ( I1i11 in [ "" , None ] ) :
  I1i11 = 12
 else :
  I1i11 = int ( I1i11 )
  if ( I1i11 > 32 ) :
   I1i11 = 12
  else :
   I1i11 *= 2
   if 66 - 66: Oo0Ooo - i1IIi . I1ii11iIi11i
   if 13 - 13: OoO0O00 - I1IiiI - i11iIiiIii - OoOoOO00 - o0oOOo0O0Ooo
   if 12 - 12: O0 % I1Ii111
 ooO0O0 = Ii1111IIIi [ 0 : I1i11 ]
 o00o = int ( ooO0O0 , 16 ) % lisp_decent_modulus
 if 26 - 26: OoooooooOO - iIii1I11I1II1 + OoO0O00 % II111iiii + OoOoOO00 * O0
 lprint ( "LISP-Decent modulus {}, hash-width {}, mod-value {}, index {}" . format ( lisp_decent_modulus , old_div ( I1i11 , 2 ) , ooO0O0 , o00o ) )
 if 64 - 64: iIii1I11I1II1 * Ii1I
 if 5 - 5: I11i . I11i / i1IIi - o0oOOo0O0Ooo % Oo0Ooo
 return ( o00o )
 if 85 - 85: OOooOOo
 if 32 - 32: iII111i
 if 27 - 27: iIii1I11I1II1 - iII111i
 if 68 - 68: oO0o + OoooooooOO - i1IIi * OoOoOO00 % Oo0Ooo
 if 19 - 19: IiII * Oo0Ooo + I1IiiI * I1Ii111 % iIii1I11I1II1
 if 15 - 15: II111iiii % OoO0O00 % Oo0Ooo + I1Ii111
 if 54 - 54: I1Ii111 + OOooOOo
def lisp_get_decent_dns_name ( eid ) :
 o00o = lisp_get_decent_index ( eid )
 return ( str ( o00o ) + "." + lisp_decent_dns_suffix )
 if 6 - 6: Ii1I
 if 8 - 8: OoO0O00
 if 91 - 91: Ii1I
 if 12 - 12: OoooooooOO + i11iIiiIii
 if 63 - 63: OOooOOo . i11iIiiIii
 if 50 - 50: IiII % i11iIiiIii - iII111i . OoOoOO00 / Oo0Ooo
 if 30 - 30: Oo0Ooo . II111iiii + OoooooooOO % OoO0O00 * ooOoO0o * iIii1I11I1II1
 if 91 - 91: OoooooooOO
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 oO0OooO0o0 = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 o00o = lisp_get_decent_index ( oO0OooO0o0 )
 return ( str ( o00o ) + "." + lisp_decent_dns_suffix )
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
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 60 - 60: I11i . iIii1I11I1II1
 o0O0 = 28 if packet . inner_version == 4 else 48
 iiIiI = packet . packet [ o0O0 : : ]
 iIIiIi = lisp_trace ( )
 if ( iIIiIi . decode ( iiIiI ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 26 - 26: OoOoOO00 + i11iIiiIii % OoOoOO00 + I1IiiI / OOooOOo + OoooooooOO
  if 94 - 94: I1ii11iIi11i % Oo0Ooo - Ii1I + I1ii11iIi11i
 iiI1 = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 97 - 97: IiII
 if 76 - 76: iII111i / i1IIi * I1Ii111 . o0oOOo0O0Ooo . ooOoO0o
 if 41 - 41: oO0o * iII111i / iII111i / I1ii11iIi11i + I1IiiI * I1ii11iIi11i
 if 12 - 12: o0oOOo0O0Ooo % I1Ii111 + IiII + I11i
 if 44 - 44: I1ii11iIi11i * I1ii11iIi11i % oO0o * oO0o
 if 21 - 21: I1Ii111 . IiII
 if ( iiI1 != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : iiI1 += ":{}" . format ( packet . encap_port )
  if 61 - 61: I1Ii111
  if 64 - 64: OoO0O00
  if 14 - 14: OOooOOo - IiII - I1ii11iIi11i + ooOoO0o . iIii1I11I1II1 . IiII
  if 13 - 13: I1IiiI / i11iIiiIii % iIii1I11I1II1 - Oo0Ooo . i11iIiiIii + I1IiiI
  if 77 - 77: o0oOOo0O0Ooo / II111iiii + i11iIiiIii % Ii1I . iIii1I11I1II1
 iIiiI11II11i = { }
 iIiiI11II11i [ "n" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 66 - 66: iII111i / oO0o - OoO0O00 . Oo0Ooo
 i1iI1Iiii1I = packet . outer_source
 if ( i1iI1Iiii1I . is_null ( ) ) : i1iI1Iiii1I = lisp_myrlocs [ 0 ]
 iIiiI11II11i [ "sr" ] = i1iI1Iiii1I . print_address_no_iid ( )
 if 18 - 18: OoO0O00
 if 25 - 25: OoooooooOO . I1ii11iIi11i % OoooooooOO / oO0o * i11iIiiIii
 if 33 - 33: O0 % OoooooooOO
 if 45 - 45: IiII + i1IIi - OOooOOo
 if 74 - 74: oO0o * oO0o . I11i
 if ( iIiiI11II11i [ "n" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  iIiiI11II11i [ "sr" ] += ":{}" . format ( packet . inner_sport )
  if 70 - 70: Ii1I % OoOoOO00 * Oo0Ooo * O0 + OoO0O00 / I1IiiI
  if 67 - 67: OoO0O00 * iIii1I11I1II1
 iIiiI11II11i [ "hn" ] = lisp_hostname
 III11II111 = ed [ 0 ] + "ts"
 iIiiI11II11i [ III11II111 ] = lisp_get_timestamp ( )
 if 2 - 2: I1ii11iIi11i * iII111i . iIii1I11I1II1 * Oo0Ooo
 if 34 - 34: i11iIiiIii % O0 . I1IiiI / ooOoO0o + OoO0O00
 if 28 - 28: Ii1I / iIii1I11I1II1
 if 41 - 41: iIii1I11I1II1
 if 57 - 57: I1Ii111 * o0oOOo0O0Ooo - o0oOOo0O0Ooo * I11i
 if 89 - 89: Ii1I % O0
 if ( iiI1 == "?" and iIiiI11II11i [ "n" ] == "ETR" ) :
  Oo0000 = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( Oo0000 != None and len ( Oo0000 . rloc_set ) >= 1 ) :
   iiI1 = Oo0000 . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 81 - 81: OoooooooOO / II111iiii - ooOoO0o
   if 14 - 14: O0
 iIiiI11II11i [ "dr" ] = iiI1
 if 59 - 59: I11i % II111iiii . iIii1I11I1II1 * oO0o % Ii1I
 if 79 - 79: OoooooooOO . II111iiii
 if 55 - 55: II111iiii
 if 2 - 2: I1ii11iIi11i * i1IIi + OOooOOo / OoO0O00 % OoOoOO00 / O0
 if ( iiI1 == "?" and reason != None ) :
  iIiiI11II11i [ "dr" ] += " ({})" . format ( reason )
  if 47 - 47: OoooooooOO - i11iIiiIii - IiII * O0 * iII111i * Ii1I
  if 36 - 36: I1Ii111
  if 85 - 85: Oo0Ooo % OOooOOo
  if 10 - 10: O0 + Oo0Ooo + Ii1I % IiII
  if 89 - 89: oO0o / iII111i + OOooOOo
 if ( rloc_entry != None ) :
  iIiiI11II11i [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  iIiiI11II11i [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  iIiiI11II11i [ "lats" ] = rloc_entry . recent_rloc_probe_latencies
  if 27 - 27: Ii1I / o0oOOo0O0Ooo % I11i
  if 96 - 96: i11iIiiIii % O0
  if 11 - 11: II111iiii . i11iIiiIii % ooOoO0o * Ii1I * OoOoOO00 * OoooooooOO
  if 80 - 80: OoO0O00
  if 55 - 55: iIii1I11I1II1 % OoO0O00 / II111iiii - OoO0O00
  if 95 - 95: o0oOOo0O0Ooo / OOooOOo * OOooOOo * O0
 iIiI11iIi111i = packet . inner_source . print_address ( )
 II11i1I1I = packet . inner_dest . print_address ( )
 if ( iIIiIi . packet_json == [ ] ) :
  o00000oo = { }
  o00000oo [ "se" ] = iIiI11iIi111i
  o00000oo [ "de" ] = II11i1I1I
  o00000oo [ "paths" ] = [ ]
  iIIiIi . packet_json . append ( o00000oo )
  if 93 - 93: OOooOOo / ooOoO0o
  if 89 - 89: OoooooooOO + iIii1I11I1II1 / I1ii11iIi11i % iIii1I11I1II1 / iII111i
  if 74 - 74: Ii1I + I1IiiI * iII111i / i11iIiiIii - ooOoO0o * OoooooooOO
  if 98 - 98: I1IiiI
  if 85 - 85: OoooooooOO * i1IIi * O0 * OoooooooOO . IiII
  if 22 - 22: ooOoO0o
 for o00000oo in iIIiIi . packet_json :
  if ( o00000oo [ "de" ] != II11i1I1I ) : continue
  o00000oo [ "paths" ] . append ( iIiiI11II11i )
  break
  if 44 - 44: I1ii11iIi11i + IiII + IiII * I1ii11iIi11i - OoooooooOO / I1Ii111
  if 3 - 3: I1ii11iIi11i + o0oOOo0O0Ooo * I11i / Oo0Ooo
  if 31 - 31: i11iIiiIii % OoO0O00 - oO0o / o0oOOo0O0Ooo % O0
  if 53 - 53: iIii1I11I1II1 * I1ii11iIi11i
  if 46 - 46: OOooOOo % OoOoOO00 * iII111i
  if 55 - 55: I1IiiI * iIii1I11I1II1 . OoOoOO00
  if 82 - 82: iIii1I11I1II1 - iII111i % I1IiiI + I1IiiI * i1IIi % O0
  if 63 - 63: I1IiiI + OoOoOO00
 o0O0O000 = False
 if ( len ( iIIiIi . packet_json ) == 1 and iIiiI11II11i [ "n" ] == "ETR" and
 iIIiIi . myeid ( packet . inner_dest ) ) :
  o00000oo = { }
  o00000oo [ "se" ] = II11i1I1I
  o00000oo [ "de" ] = iIiI11iIi111i
  o00000oo [ "paths" ] = [ ]
  iIIiIi . packet_json . append ( o00000oo )
  o0O0O000 = True
  if 62 - 62: oO0o + I1IiiI - OoO0O00
  if 76 - 76: oO0o
  if 12 - 12: Ii1I . I11i . II111iiii
  if 34 - 34: O0 * OoooooooOO + I1Ii111
  if 94 - 94: I1ii11iIi11i * O0 - ooOoO0o % OoooooooOO + IiII - OoOoOO00
  if 88 - 88: iIii1I11I1II1 . I1Ii111
 iIIiIi . print_trace ( )
 iiIiI = iIIiIi . encode ( )
 if 88 - 88: OOooOOo % OoOoOO00 . I1IiiI . Ii1I
 if 76 - 76: I11i
 if 42 - 42: I1ii11iIi11i . iIii1I11I1II1 % I11i
 if 54 - 54: OoOoOO00 / Ii1I
 if 84 - 84: Oo0Ooo / OoO0O00 . o0oOOo0O0Ooo - iII111i . iII111i - II111iiii
 if 99 - 99: I1Ii111 % Oo0Ooo
 if 61 - 61: OoooooooOO % i11iIiiIii + OOooOOo
 if 53 - 53: iII111i . iIii1I11I1II1
 ooO = iIIiIi . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "sr" ]
 if ( iiI1 == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( ooO ) )
  iIIiIi . return_to_sender ( lisp_socket , ooO , iiIiI )
  return ( False )
  if 28 - 28: Oo0Ooo + oO0o / iIii1I11I1II1 + I1IiiI + I1Ii111
  if 6 - 6: iIii1I11I1II1 . O0 * I1ii11iIi11i . OoOoOO00 / i11iIiiIii
  if 85 - 85: iII111i
  if 23 - 23: O0
  if 83 - 83: i11iIiiIii % OoooooooOO
  if 45 - 45: OoO0O00 + Ii1I
 OooooOo = iIIiIi . packet_length ( )
 if 90 - 90: O0 * i1IIi . i1IIi * I1ii11iIi11i + I1ii11iIi11i / i1IIi
 if 52 - 52: O0 / iIii1I11I1II1 * IiII
 if 50 - 50: oO0o . Ii1I . OoooooooOO * o0oOOo0O0Ooo
 if 25 - 25: o0oOOo0O0Ooo % ooOoO0o
 if 91 - 91: I1Ii111 * i11iIiiIii / o0oOOo0O0Ooo * oO0o - o0oOOo0O0Ooo * OOooOOo
 if 2 - 2: i1IIi - OoOoOO00 / iII111i
 o0Ooo = packet . packet [ 0 : o0O0 ]
 o00oo = struct . pack ( "HH" , socket . htons ( OooooOo ) , 0 )
 o0Ooo = o0Ooo [ 0 : o0O0 - 4 ] + o00oo
 if ( packet . inner_version == 6 and iIiiI11II11i [ "n" ] == "ETR" and
 len ( iIIiIi . packet_json ) == 2 ) :
  Ii1iiI1 = o0Ooo [ o0O0 - 8 : : ] + iiIiI
  Ii1iiI1 = lisp_udp_checksum ( iIiI11iIi111i , II11i1I1I , Ii1iiI1 )
  o0Ooo = o0Ooo [ 0 : o0O0 - 8 ] + Ii1iiI1 [ 0 : 8 ]
  if 23 - 23: OoOoOO00
  if 2 - 2: II111iiii * OoOoOO00 . iIii1I11I1II1 . ooOoO0o . ooOoO0o + iII111i
  if 60 - 60: I1ii11iIi11i / I1ii11iIi11i
  if 44 - 44: i11iIiiIii / ooOoO0o - iIii1I11I1II1 + OoO0O00
  if 62 - 62: i1IIi / I1Ii111 + ooOoO0o
  if 80 - 80: iII111i + OoO0O00 % OoO0O00
  if 4 - 4: OoOoOO00 * I11i * O0 . OoooooooOO + Ii1I % i1IIi
  if 11 - 11: OoOoOO00 % i11iIiiIii . OoOoOO00 % Oo0Ooo * Ii1I
  if 67 - 67: IiII - OoOoOO00 / I1Ii111 % oO0o % OOooOOo
 if ( o0O0O000 ) :
  if ( packet . inner_version == 4 ) :
   o0Ooo = o0Ooo [ 0 : 12 ] + o0Ooo [ 16 : 20 ] + o0Ooo [ 12 : 16 ] + o0Ooo [ 22 : 24 ] + o0Ooo [ 20 : 22 ] + o0Ooo [ 24 : : ]
   if 19 - 19: OoO0O00 - iII111i
  else :
   o0Ooo = o0Ooo [ 0 : 8 ] + o0Ooo [ 24 : 40 ] + o0Ooo [ 8 : 24 ] + o0Ooo [ 42 : 44 ] + o0Ooo [ 40 : 42 ] + o0Ooo [ 44 : : ]
   if 76 - 76: OoOoOO00 * ooOoO0o - iII111i * I1IiiI + I11i
   if 4 - 4: Oo0Ooo
  iiIi = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = iiIi
  if 95 - 95: Oo0Ooo * i11iIiiIii - O0
  if 100 - 100: iIii1I11I1II1 / I1ii11iIi11i - o0oOOo0O0Ooo / iII111i
  if 73 - 73: OoooooooOO
  if 68 - 68: II111iiii / i11iIiiIii % i11iIiiIii % OoooooooOO
  if 81 - 81: i1IIi + O0 . IiII . I1IiiI / ooOoO0o
  if 75 - 75: I1ii11iIi11i / OoOoOO00
  if 59 - 59: OoO0O00 . OoooooooOO % IiII
 o0O0 = 2 if packet . inner_version == 4 else 4
 iI1iIi = 20 + OooooOo if packet . inner_version == 4 else OooooOo
 ooo0OOoO = struct . pack ( "H" , socket . htons ( iI1iIi ) )
 o0Ooo = o0Ooo [ 0 : o0O0 ] + ooo0OOoO + o0Ooo [ o0O0 + 2 : : ]
 if 12 - 12: II111iiii % Oo0Ooo / Oo0Ooo . i1IIi % Ii1I
 if 21 - 21: II111iiii - o0oOOo0O0Ooo * OoO0O00 . OOooOOo
 if 65 - 65: o0oOOo0O0Ooo + I1IiiI
 if 21 - 21: I1Ii111
 if ( packet . inner_version == 4 ) :
  I1IiII = struct . pack ( "H" , 0 )
  o0Ooo = o0Ooo [ 0 : 10 ] + I1IiII + o0Ooo [ 12 : : ]
  ooo0OOoO = lisp_ip_checksum ( o0Ooo [ 0 : 20 ] )
  o0Ooo = ooo0OOoO + o0Ooo [ 20 : : ]
  if 74 - 74: iII111i
  if 51 - 51: O0 . II111iiii - OoooooooOO + ooOoO0o - o0oOOo0O0Ooo
  if 86 - 86: OOooOOo % i11iIiiIii / OoOoOO00
  if 72 - 72: I1IiiI . oO0o
  if 76 - 76: Ii1I - Oo0Ooo * II111iiii
 packet . packet = o0Ooo + iiIiI
 return ( True )
 if 17 - 17: I1Ii111 * O0
 if 8 - 8: i11iIiiIii / OoO0O00 / OOooOOo
 if 26 - 26: I1ii11iIi11i . Ii1I - iIii1I11I1II1 . Ii1I / Ii1I % I11i
 if 56 - 56: OOooOOo . I11i + O0 * oO0o - i11iIiiIii / i11iIiiIii
 if 73 - 73: I1ii11iIi11i
 if 59 - 59: iII111i % iIii1I11I1II1 * OoOoOO00
 if 41 - 41: i1IIi * IiII - i11iIiiIii / O0 + Oo0Ooo + ooOoO0o
 if 94 - 94: OoO0O00 . O0 + iIii1I11I1II1 . oO0o % oO0o
 if 7 - 7: I1ii11iIi11i * oO0o / OoOoOO00
 if 89 - 89: OoO0O00 / oO0o % I11i - I1ii11iIi11i . o0oOOo0O0Ooo
def lisp_allow_gleaning ( eid , group , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False , False )
 if 46 - 46: i11iIiiIii
 for iIiiI11II11i in lisp_glean_mappings :
  if ( "instance-id" in iIiiI11II11i ) :
   oO0O = eid . instance_id
   O0II11II1111 , O00ooO0OoOO0O = iIiiI11II11i [ "instance-id" ]
   if ( oO0O < O0II11II1111 or oO0O > O00ooO0OoOO0O ) : continue
   if 99 - 99: i11iIiiIii / oO0o / OoOoOO00 / O0 * I1ii11iIi11i
  if ( "eid-prefix" in iIiiI11II11i ) :
   o0o00oO0oo000 = copy . deepcopy ( iIiiI11II11i [ "eid-prefix" ] )
   o0o00oO0oo000 . instance_id = eid . instance_id
   if ( eid . is_more_specific ( o0o00oO0oo000 ) == False ) : continue
   if 72 - 72: ooOoO0o - I1Ii111 - iIii1I11I1II1 . I1IiiI
  if ( "group-prefix" in iIiiI11II11i ) :
   if ( group == None ) : continue
   o0O0Ooo = copy . deepcopy ( iIiiI11II11i [ "group-prefix" ] )
   o0O0Ooo . instance_id = group . instance_id
   if ( group . is_more_specific ( o0O0Ooo ) == False ) : continue
   if 77 - 77: Oo0Ooo * OoO0O00
  if ( "rloc-prefix" in iIiiI11II11i ) :
   if ( rloc != None and rloc . is_more_specific ( iIiiI11II11i [ "rloc-prefix" ] )
 == False ) : continue
   if 67 - 67: OoOoOO00 . I1Ii111 / I1IiiI * II111iiii
  return ( True , iIiiI11II11i [ "rloc-probe" ] , iIiiI11II11i [ "igmp-query" ] )
  if 45 - 45: I1ii11iIi11i * o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo
 return ( False , False , False )
 if 58 - 58: OOooOOo + O0
 if 19 - 19: o0oOOo0O0Ooo
 if 8 - 8: OOooOOo * OOooOOo - Ii1I * OoOoOO00 % OoO0O00 * O0
 if 70 - 70: I1IiiI
 if 17 - 17: I11i % OOooOOo - i11iIiiIii . OoooooooOO % OoO0O00 + OoO0O00
 if 24 - 24: Ii1I . OOooOOo . IiII / Oo0Ooo . Oo0Ooo . II111iiii
 if 63 - 63: ooOoO0o . I11i
def lisp_build_gleaned_multicast ( seid , geid , rloc , port , igmp ) :
 ii1I = geid . print_address ( )
 Ii1IIiiii1 = seid . print_address_no_iid ( )
 o0O0o0000o0O0 = green ( "{}" . format ( Ii1IIiiii1 ) , False )
 o0o00oO0oo000 = green ( "(*, {})" . format ( ii1I ) , False )
 o0O00o0o = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 if 28 - 28: oO0o * II111iiii + Oo0Ooo
 if 11 - 11: O0
 if 9 - 9: II111iiii
 if 52 - 52: I1Ii111 % I1IiiI - Oo0Ooo . i1IIi
 Ii111 = lisp_map_cache_lookup ( seid , geid )
 if ( Ii111 == None ) :
  Ii111 = lisp_mapping ( "" , "" , [ ] )
  Ii111 . group . copy_address ( geid )
  Ii111 . eid . copy_address ( geid )
  Ii111 . eid . address = 0
  Ii111 . eid . mask_len = 0
  Ii111 . mapping_source . copy_address ( rloc )
  Ii111 . map_cache_ttl = LISP_IGMP_TTL
  Ii111 . gleaned = True
  Ii111 . add_cache ( )
  lprint ( "Add gleaned EID {} to map-cache" . format ( o0o00oO0oo000 ) )
  if 2 - 2: iII111i % OoOoOO00 * iIii1I11I1II1 * ooOoO0o - OoooooooOO - IiII
  if 40 - 40: OoO0O00 . i11iIiiIii + ooOoO0o
  if 30 - 30: OOooOOo . OoO0O00 % iII111i - OoO0O00 % i11iIiiIii
  if 28 - 28: Ii1I + Oo0Ooo / iIii1I11I1II1
  if 57 - 57: o0oOOo0O0Ooo
  if 23 - 23: II111iiii
 oO0O0oOOO0 = Oo0ooO0OoooOO = iIiII = None
 if ( Ii111 . rloc_set != [ ] ) :
  oO0O0oOOO0 = Ii111 . rloc_set [ 0 ]
  if ( oO0O0oOOO0 . rle ) :
   Oo0ooO0OoooOO = oO0O0oOOO0 . rle
   for Ii1IOo0Oo0oOoO in Oo0ooO0OoooOO . rle_nodes :
    if ( Ii1IOo0Oo0oOoO . rloc_name != Ii1IIiiii1 ) : continue
    iIiII = Ii1IOo0Oo0oOoO
    break
    if 39 - 39: iII111i
    if 97 - 97: oO0o - iIii1I11I1II1
    if 61 - 61: II111iiii / OOooOOo - oO0o
    if 19 - 19: O0
    if 60 - 60: I1ii11iIi11i * I1ii11iIi11i + I1Ii111 + o0oOOo0O0Ooo - OoO0O00
    if 75 - 75: o0oOOo0O0Ooo + i11iIiiIii % I1ii11iIi11i
    if 45 - 45: I1Ii111 % Ii1I . ooOoO0o
 if ( oO0O0oOOO0 == None ) :
  oO0O0oOOO0 = lisp_rloc ( )
  Ii111 . rloc_set = [ oO0O0oOOO0 ]
  oO0O0oOOO0 . priority = 253
  oO0O0oOOO0 . mpriority = 255
  Ii111 . build_best_rloc_set ( )
  if 99 - 99: I11i - OoOoOO00 % I11i / i1IIi
 if ( Oo0ooO0OoooOO == None ) :
  Oo0ooO0OoooOO = lisp_rle ( geid . print_address ( ) )
  oO0O0oOOO0 . rle = Oo0ooO0OoooOO
  if 55 - 55: o0oOOo0O0Ooo / ooOoO0o % I1IiiI / I1Ii111
 if ( iIiII == None ) :
  iIiII = lisp_rle_node ( )
  iIiII . rloc_name = Ii1IIiiii1
  Oo0ooO0OoooOO . rle_nodes . append ( iIiII )
  Oo0ooO0OoooOO . build_forwarding_list ( )
  lprint ( "Add RLE {} from {} for gleaned EID {}" . format ( o0O00o0o , o0O0o0000o0O0 , o0o00oO0oo000 ) )
 elif ( rloc . is_exact_match ( iIiII . address ) == False or
 port != iIiII . translated_port ) :
  lprint ( "Changed RLE {} from {} for gleaned EID {}" . format ( o0O00o0o , o0O0o0000o0O0 , o0o00oO0oo000 ) )
  if 30 - 30: I11i % OoOoOO00 * O0
  if 32 - 32: iII111i - Oo0Ooo / Oo0Ooo + o0oOOo0O0Ooo + Ii1I + IiII
  if 100 - 100: Oo0Ooo + o0oOOo0O0Ooo % Oo0Ooo
  if 73 - 73: o0oOOo0O0Ooo + Ii1I
  if 62 - 62: OOooOOo
 iIiII . store_translated_rloc ( rloc , port )
 if 91 - 91: iII111i . Ii1I - OoooooooOO / Ii1I / II111iiii - O0
 if 67 - 67: oO0o * i11iIiiIii / I1ii11iIi11i . I11i % OOooOOo
 if 75 - 75: ooOoO0o - OOooOOo
 if 97 - 97: i11iIiiIii / I11i % II111iiii
 if 20 - 20: I1Ii111 + OoooooooOO . o0oOOo0O0Ooo - ooOoO0o
 if ( igmp ) :
  OO00o0oO0O00 = seid . print_address ( )
  if ( OO00o0oO0O00 not in lisp_gleaned_groups ) :
   lisp_gleaned_groups [ OO00o0oO0O00 ] = { }
   if 61 - 61: i11iIiiIii + OoooooooOO
  lisp_gleaned_groups [ OO00o0oO0O00 ] [ ii1I ] = lisp_get_timestamp ( )
  if 7 - 7: I1IiiI * OoO0O00 * I1IiiI
  if 50 - 50: I1ii11iIi11i
  if 88 - 88: IiII
  if 55 - 55: Oo0Ooo + OOooOOo + IiII
  if 55 - 55: O0 . I1Ii111 * I1ii11iIi11i * o0oOOo0O0Ooo - ooOoO0o
  if 17 - 17: OOooOOo
  if 66 - 66: O0 - i11iIiiIii * O0 / iII111i . I1Ii111 / IiII
  if 96 - 96: OoOoOO00 / i11iIiiIii - OoooooooOO / II111iiii * i1IIi
def lisp_remove_gleaned_multicast ( seid , geid ) :
 if 82 - 82: iII111i
 if 55 - 55: OoOoOO00 + I1ii11iIi11i % ooOoO0o % I1Ii111 . i1IIi % OOooOOo
 if 21 - 21: OoO0O00 / Ii1I . IiII
 if 35 - 35: i1IIi
 Ii111 = lisp_map_cache_lookup ( seid , geid )
 if ( Ii111 == None ) : return
 if 58 - 58: Ii1I - IiII / ooOoO0o % o0oOOo0O0Ooo + I1ii11iIi11i
 IIiiiI = Ii111 . rloc_set [ 0 ] . rle
 if ( IIiiiI == None ) : return
 if 89 - 89: IiII / OoooooooOO
 o0oo0 = seid . print_address_no_iid ( )
 OoOo = False
 for iIiII in IIiiiI . rle_nodes :
  if ( iIiII . rloc_name == o0oo0 ) :
   OoOo = True
   break
   if 13 - 13: II111iiii . OOooOOo - O0 * oO0o
   if 71 - 71: ooOoO0o % ooOoO0o + o0oOOo0O0Ooo + iII111i / OoOoOO00
 if ( OoOo == False ) : return
 if 27 - 27: I1ii11iIi11i * OoO0O00 - OoO0O00
 if 87 - 87: I1IiiI * I11i + iIii1I11I1II1 % i1IIi
 if 6 - 6: o0oOOo0O0Ooo
 if 94 - 94: I1ii11iIi11i * i11iIiiIii
 IIiiiI . rle_nodes . remove ( iIiII )
 IIiiiI . build_forwarding_list ( )
 if 95 - 95: OoooooooOO - II111iiii . I1Ii111
 ii1I = geid . print_address ( )
 OO00o0oO0O00 = seid . print_address ( )
 o0O0o0000o0O0 = green ( "{}" . format ( OO00o0oO0O00 ) , False )
 o0o00oO0oo000 = green ( "(*, {})" . format ( ii1I ) , False )
 lprint ( "Gleaned EID {} RLE removed for {}" . format ( o0o00oO0oo000 , o0O0o0000o0O0 ) )
 if 97 - 97: i1IIi * iIii1I11I1II1
 if 44 - 44: O0 - o0oOOo0O0Ooo - I1Ii111 % O0
 if 31 - 31: i11iIiiIii - I11i
 if 91 - 91: I11i - iII111i
 if ( OO00o0oO0O00 in lisp_gleaned_groups ) :
  if ( ii1I in lisp_gleaned_groups [ OO00o0oO0O00 ] ) :
   lisp_gleaned_groups [ OO00o0oO0O00 ] . pop ( ii1I )
   if 35 - 35: I1IiiI * I11i + I11i
   if 67 - 67: I1ii11iIi11i - I1IiiI + Ii1I * Ii1I + Oo0Ooo
   if 41 - 41: i11iIiiIii
   if 97 - 97: i1IIi / Ii1I / ooOoO0o . Ii1I - ooOoO0o + oO0o
   if 27 - 27: OOooOOo % O0
   if 96 - 96: OoooooooOO / OOooOOo
 if ( IIiiiI . rle_nodes == [ ] ) :
  Ii111 . delete_cache ( )
  lprint ( "Gleaned EID {} remove, no more RLEs" . format ( o0o00oO0oo000 ) )
  if 87 - 87: IiII - OoooooooOO
  if 53 - 53: OoOoOO00 + Oo0Ooo
  if 33 - 33: I11i - OOooOOo + Oo0Ooo - iII111i * iII111i
  if 44 - 44: Oo0Ooo % OoOoOO00 / oO0o
  if 34 - 34: II111iiii + Ii1I + OoOoOO00
  if 9 - 9: I11i / oO0o * OoO0O00
  if 26 - 26: I1IiiI % OOooOOo * OoOoOO00
  if 14 - 14: I11i * Oo0Ooo . I1Ii111 * Ii1I . i11iIiiIii * I1ii11iIi11i
def lisp_change_gleaned_multicast ( seid , rloc , port ) :
 OO00o0oO0O00 = seid . print_address ( )
 if ( OO00o0oO0O00 not in lisp_gleaned_groups ) : return
 if 11 - 11: oO0o + oO0o + o0oOOo0O0Ooo / iIii1I11I1II1 / I11i
 for iII1I1i in lisp_gleaned_groups [ OO00o0oO0O00 ] :
  lisp_geid . store_address ( iII1I1i )
  lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , port , False )
  if 68 - 68: OoooooooOO + i1IIi % I1ii11iIi11i . iII111i
  if 69 - 69: ooOoO0o * II111iiii + i11iIiiIii / oO0o + I1Ii111 - OOooOOo
  if 84 - 84: O0
  if 29 - 29: I11i + o0oOOo0O0Ooo . ooOoO0o * I1Ii111 - o0oOOo0O0Ooo * O0
  if 58 - 58: iII111i . oO0o + i11iIiiIii
  if 2 - 2: OOooOOo * Ii1I
  if 17 - 17: I1ii11iIi11i * O0 / OoOoOO00 + i1IIi
  if 71 - 71: oO0o % IiII
  if 77 - 77: i1IIi * o0oOOo0O0Ooo - Oo0Ooo / I1Ii111 - Ii1I * IiII
  if 51 - 51: OoO0O00 * IiII
  if 36 - 36: II111iiii + I11i - O0
  if 24 - 24: I1Ii111 / OoOoOO00
  if 10 - 10: I11i . OoO0O00 / O0 / oO0o / o0oOOo0O0Ooo / ooOoO0o
  if 30 - 30: Oo0Ooo
  if 93 - 93: II111iiii - I1IiiI
  if 80 - 80: I11i . o0oOOo0O0Ooo % IiII - OoOoOO00 % OOooOOo / OoooooooOO
  if 57 - 57: OoooooooOO % o0oOOo0O0Ooo - iIii1I11I1II1 . OoooooooOO
  if 42 - 42: o0oOOo0O0Ooo % OoooooooOO * OoO0O00 - o0oOOo0O0Ooo
  if 83 - 83: i1IIi . i1IIi * ooOoO0o
  if 26 - 26: I1IiiI - IiII
  if 99 - 99: IiII * iII111i + i1IIi * I1Ii111
  if 88 - 88: o0oOOo0O0Ooo . IiII - Oo0Ooo
  if 24 - 24: Oo0Ooo - OOooOOo / Ii1I / II111iiii . Oo0Ooo - Ii1I
  if 5 - 5: IiII
  if 66 - 66: OoO0O00 . I1ii11iIi11i . OoooooooOO
  if 21 - 21: I11i / IiII + i1IIi . Oo0Ooo % II111iiii
  if 8 - 8: oO0o / iIii1I11I1II1 + OoooooooOO
  if 11 - 11: OOooOOo . O0 + IiII . i1IIi
  if 81 - 81: OoO0O00 - I11i - OoO0O00 + oO0o
  if 20 - 20: OoooooooOO - Oo0Ooo + I1Ii111 + OoooooooOO
  if 66 - 66: I1ii11iIi11i / oO0o % IiII + II111iiii % iII111i
  if 54 - 54: iII111i * O0 / I1IiiI % Ii1I
  if 12 - 12: IiII % I1IiiI - o0oOOo0O0Ooo - I1ii11iIi11i - i11iIiiIii * i1IIi
  if 96 - 96: II111iiii % o0oOOo0O0Ooo % oO0o * ooOoO0o
  if 79 - 79: iII111i
  if 74 - 74: Oo0Ooo - IiII - iII111i - IiII / IiII
  if 75 - 75: I11i - i11iIiiIii % O0 - O0 % O0
  if 93 - 93: ooOoO0o + iIii1I11I1II1
  if 27 - 27: i1IIi * i11iIiiIii - OoOoOO00 * Ii1I . IiII + iII111i
  if 25 - 25: I1ii11iIi11i % o0oOOo0O0Ooo - OoO0O00
  if 28 - 28: oO0o
  if 8 - 8: I11i / OoooooooOO % OoooooooOO . Oo0Ooo
  if 30 - 30: iII111i
  if 25 - 25: I11i % i1IIi + OOooOOo * Ii1I . i1IIi
  if 81 - 81: I11i % OoOoOO00 . Ii1I
  if 82 - 82: i1IIi / II111iiii
  if 40 - 40: II111iiii - I1Ii111 + Oo0Ooo / IiII
  if 15 - 15: I1Ii111 + ooOoO0o / II111iiii . OoOoOO00 - I1Ii111
  if 59 - 59: Ii1I * iIii1I11I1II1 - iIii1I11I1II1 % I1Ii111 - OoO0O00 / I1IiiI
  if 89 - 89: I1Ii111 . OoO0O00
  if 52 - 52: OoO0O00 - iIii1I11I1II1
  if 52 - 52: OOooOOo + I1IiiI * Ii1I % OoooooooOO / I1Ii111
  if 74 - 74: iIii1I11I1II1
  if 82 - 82: OOooOOo
  if 64 - 64: II111iiii
  if 48 - 48: iII111i + i11iIiiIii * I1IiiI % OoOoOO00
  if 49 - 49: Oo0Ooo
  if 67 - 67: iIii1I11I1II1 + I1Ii111 / I1Ii111 % I11i + I1Ii111
  if 7 - 7: iIii1I11I1II1 . Oo0Ooo / OoO0O00 / OoOoOO00
  if 7 - 7: OoOoOO00 * I1Ii111 / Ii1I - OoO0O00 / O0 / Oo0Ooo
  if 47 - 47: OoOoOO00
  if 18 - 18: OoO0O00 - iIii1I11I1II1
  if 91 - 91: iII111i / I1ii11iIi11i
  if 19 - 19: iIii1I11I1II1
  if 3 - 3: i11iIiiIii + Ii1I / I1Ii111
  if 74 - 74: II111iiii + I11i
  if 80 - 80: OOooOOo . oO0o / iIii1I11I1II1
  if 4 - 4: iII111i + I1IiiI
  if 95 - 95: Oo0Ooo / I1ii11iIi11i % OoO0O00
  if 47 - 47: I1IiiI + i1IIi + I1ii11iIi11i / OOooOOo * i11iIiiIii % I1Ii111
  if 7 - 7: OoOoOO00 * iII111i * i11iIiiIii + OoOoOO00
  if 20 - 20: i1IIi % Ii1I / iIii1I11I1II1 / II111iiii
  if 16 - 16: I1IiiI % Ii1I
  if 30 - 30: i11iIiiIii / i1IIi % O0 - OoooooooOO - OOooOOo
  if 55 - 55: OoooooooOO % ooOoO0o % I1Ii111 - Oo0Ooo % OoooooooOO . I11i
  if 22 - 22: i11iIiiIii
  if 39 - 39: oO0o / OoOoOO00 % iIii1I11I1II1 - OoOoOO00
  if 29 - 29: I1ii11iIi11i - I11i . I1ii11iIi11i - o0oOOo0O0Ooo - OoooooooOO % OoO0O00
  if 74 - 74: iIii1I11I1II1 / iII111i * OoO0O00 * iIii1I11I1II1 + i11iIiiIii
  if 90 - 90: II111iiii - oO0o - oO0o + I1IiiI
  if 36 - 36: OoooooooOO % OoooooooOO / OoO0O00 * I1IiiI
  if 55 - 55: O0 - O0
  if 32 - 32: I1IiiI + o0oOOo0O0Ooo + Oo0Ooo / OoO0O00 . I11i . Oo0Ooo
  if 32 - 32: I1Ii111 / i1IIi
  if 30 - 30: i11iIiiIii . II111iiii * Oo0Ooo + II111iiii - I1IiiI
  if 80 - 80: o0oOOo0O0Ooo - iII111i % i11iIiiIii % i11iIiiIii % OoooooooOO - IiII
  if 39 - 39: II111iiii / I1Ii111 + OoooooooOO + IiII + iIii1I11I1II1
  if 59 - 59: OoOoOO00 / II111iiii . Ii1I
  if 90 - 90: II111iiii
  if 77 - 77: i11iIiiIii . i11iIiiIii - iIii1I11I1II1 + OOooOOo
  if 55 - 55: OoO0O00 + Oo0Ooo
  if 74 - 74: i1IIi - I11i - oO0o % I1IiiI
igmp_types = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 57 - 57: Oo0Ooo / II111iiii + OoOoOO00
lisp_igmp_record_types = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 67 - 67: IiII * IiII % oO0o - IiII * i11iIiiIii - i11iIiiIii
def lisp_process_igmp_packet ( packet ) :
 iiIIiIi1i1I1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 iiIIiIi1i1I1 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 iiIIiIi1i1I1 = bold ( "from {}" . format ( iiIIiIi1i1I1 . print_address_no_iid ( ) ) , False )
 if 27 - 27: i1IIi
 o0O00o0o = bold ( "Receive" , False )
 lprint ( "{} {}-byte {}, IGMP packet: {}" . format ( o0O00o0o , len ( packet ) , iiIIiIi1i1I1 ,
 lisp_format_packet ( packet ) ) )
 if 29 - 29: OOooOOo % I11i * Oo0Ooo
 if 92 - 92: OoOoOO00 / OoooooooOO % OoooooooOO + o0oOOo0O0Ooo
 if 91 - 91: OoOoOO00 - iII111i / iII111i - OoO0O00
 if 97 - 97: Oo0Ooo / IiII % OOooOOo % Ii1I
 oooOO = ( struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ] & 0x0f ) * 4
 if 79 - 79: O0 / ooOoO0o + OoOoOO00
 if 23 - 23: I11i
 if 81 - 81: OoOoOO00 * ooOoO0o + OoOoOO00
 if 7 - 7: I1ii11iIi11i - II111iiii
 OOiii11II = packet [ oooOO : : ]
 oooo0O0 = struct . unpack ( "B" , OOiii11II [ 0 : 1 ] ) [ 0 ]
 if 17 - 17: i11iIiiIii
 if 53 - 53: i11iIiiIii
 if 55 - 55: Ii1I . OOooOOo / OOooOOo / Oo0Ooo
 if 91 - 91: OoooooooOO + iIii1I11I1II1 - OOooOOo / o0oOOo0O0Ooo
 if 79 - 79: OoO0O00 * OoooooooOO % I11i
 iII1I1i = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 iII1I1i . address = socket . ntohl ( struct . unpack ( "II" , OOiii11II [ : 8 ] ) [ 1 ] )
 ii1I = iII1I1i . print_address_no_iid ( )
 if 39 - 39: I1Ii111 - I1ii11iIi11i
 if ( oooo0O0 == 17 ) :
  lprint ( "IGMP Query for group {}" . format ( ii1I ) )
  return ( True )
  if 10 - 10: OoOoOO00 - I1IiiI * OOooOOo - iII111i % OoOoOO00 . Ii1I
  if 44 - 44: OOooOOo * I1ii11iIi11i + OoooooooOO * OoooooooOO
 oooOOOoooOoOO = ( oooo0O0 in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( oooOOOoooOoOO == False ) :
  ii1iIiI1 = "{} ({})" . format ( oooo0O0 , igmp_types [ oooo0O0 ] ) if ( oooo0O0 in igmp_types ) else oooo0O0
  if 15 - 15: I1IiiI . II111iiii % O0 / Oo0Ooo - I1ii11iIi11i - i1IIi
  lprint ( "IGMP type {} not supported" . format ( ii1iIiI1 ) )
  return ( [ ] )
  if 54 - 54: I1IiiI / OoO0O00 % i11iIiiIii % I1Ii111 / oO0o / oO0o
  if 82 - 82: IiII * ooOoO0o / ooOoO0o . OoooooooOO
 if ( len ( OOiii11II ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 39 - 39: iII111i / I1Ii111
  if 26 - 26: IiII
  if 66 - 66: OoO0O00 % i1IIi % OoooooooOO * OOooOOo
  if 65 - 65: I1ii11iIi11i / oO0o % OoooooooOO
  if 40 - 40: OOooOOo - iIii1I11I1II1 - OOooOOo
 if ( oooo0O0 == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( ii1I , False ) ) )
  return ( [ [ None , ii1I , False ] ] )
  if 23 - 23: OoOoOO00
 if ( oooo0O0 in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( oooo0O0 == 0x12 ) else 2 , bold ( ii1I , False ) ) )
  if 26 - 26: i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o + OoO0O00
  if 86 - 86: OoOoOO00 % i11iIiiIii . ooOoO0o + i1IIi + O0 - OOooOOo
  if 24 - 24: I11i - ooOoO0o + I1IiiI % O0 % iII111i * II111iiii
  if 35 - 35: oO0o - I11i - i1IIi
  if 83 - 83: ooOoO0o % OoooooooOO % Oo0Ooo * o0oOOo0O0Ooo * oO0o % i1IIi
  if ( ii1I . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
  else :
   return ( [ [ None , ii1I , True ] ] )
   if 66 - 66: Ii1I . ooOoO0o / OoooooooOO - I1IiiI - iIii1I11I1II1 + OOooOOo
   if 33 - 33: Ii1I + I1IiiI - iII111i . OoooooooOO / I1ii11iIi11i
   if 64 - 64: OoO0O00 + OoO0O00
   if 2 - 2: ooOoO0o * IiII . ooOoO0o
   if 5 - 5: o0oOOo0O0Ooo - o0oOOo0O0Ooo
  return ( [ ] )
  if 40 - 40: OoO0O00 % I11i - OoOoOO00
  if 51 - 51: iIii1I11I1II1 . OOooOOo % I1ii11iIi11i
  if 46 - 46: OoOoOO00 - iIii1I11I1II1 * Oo0Ooo * OOooOOo + i1IIi / iII111i
  if 11 - 11: Oo0Ooo
  if 65 - 65: I1IiiI
 iIIii = iII1I1i . address
 OOiii11II = OOiii11II [ 8 : : ]
 if 9 - 9: OOooOOo + I1Ii111 - O0
 oO000oOOO = "BBHI"
 OO00oOO0000 = struct . calcsize ( oO000oOOO )
 Oo0ooOoO = "I"
 IIi11iI = struct . calcsize ( Oo0ooOoO )
 iiIIiIi1i1I1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 45 - 45: OoooooooOO * II111iiii
 if 67 - 67: iII111i
 if 31 - 31: OoOoOO00 . OOooOOo % iIii1I11I1II1 % OoO0O00
 if 70 - 70: I1ii11iIi11i - I1ii11iIi11i / OoO0O00
 I1i = [ ]
 for iIiIIi in range ( iIIii ) :
  if ( len ( OOiii11II ) < OO00oOO0000 ) : return
  i1iiI1iiii , iII , OOOOO , iii1 = struct . unpack ( oO000oOOO ,
 OOiii11II [ : OO00oOO0000 ] )
  if 9 - 9: ooOoO0o / OOooOOo
  OOiii11II = OOiii11II [ OO00oOO0000 : : ]
  if 61 - 61: ooOoO0o % II111iiii + I1ii11iIi11i * OoooooooOO
  if ( i1iiI1iiii not in lisp_igmp_record_types ) :
   lprint ( "Invalid record type {}" . format ( i1iiI1iiii ) )
   continue
   if 16 - 16: OOooOOo / O0
   if 74 - 74: ooOoO0o + Oo0Ooo
  I1i11I11iIII = lisp_igmp_record_types [ i1iiI1iiii ]
  OOOOO = socket . ntohs ( OOOOO )
  iII1I1i . address = socket . ntohl ( iii1 )
  ii1I = iII1I1i . print_address_no_iid ( )
  if 97 - 97: IiII - IiII / IiII
  lprint ( "Record type: {}, group: {}, source-count: {}" . format ( I1i11I11iIII , ii1I , OOOOO ) )
  if 80 - 80: OoOoOO00 . oO0o % Ii1I - i11iIiiIii - Oo0Ooo
  if 5 - 5: Oo0Ooo * oO0o . OoO0O00 % i11iIiiIii
  if 64 - 64: OOooOOo / Ii1I - Ii1I . I1Ii111 / I1IiiI
  if 12 - 12: i1IIi
  if 65 - 65: I1IiiI + i1IIi * II111iiii / II111iiii + OoooooooOO
  if 100 - 100: IiII / i1IIi + I11i
  if 57 - 57: Ii1I % II111iiii
  i11IIIIi = False
  if ( i1iiI1iiii in ( 1 , 5 ) ) : i11IIIIi = True
  if ( i1iiI1iiii in ( 2 , 4 ) and OOOOO == 0 ) : i11IIIIi = True
  IiI1111ii1i = "join" if ( i11IIIIi ) else "leave"
  if 82 - 82: ooOoO0o
  if 97 - 97: I11i
  if 32 - 32: Oo0Ooo . I11i
  if 14 - 14: o0oOOo0O0Ooo
  if ( ii1I . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   continue
   if 47 - 47: I1ii11iIi11i . ooOoO0o - I11i
   if 12 - 12: i11iIiiIii + iIii1I11I1II1 * I1Ii111 * OOooOOo % Oo0Ooo
   if 35 - 35: Ii1I . OoO0O00 / I1Ii111 + Ii1I
   if 94 - 94: oO0o
   if 79 - 79: Oo0Ooo / oO0o % IiII
   if 15 - 15: iIii1I11I1II1 * Oo0Ooo * iIii1I11I1II1 % II111iiii / I1IiiI . OoO0O00
   if 81 - 81: IiII * OoOoOO00
   if 84 - 84: oO0o
  if ( OOOOO == 0 ) :
   I1i . append ( [ None , ii1I , i11IIIIi ] )
   lprint ( "IGMPv3 {} (*, {})" . format ( bold ( IiI1111ii1i , False ) ,
 bold ( ii1I , False ) ) )
   if 29 - 29: I1ii11iIi11i - i11iIiiIii + ooOoO0o % OoO0O00 + I11i
   if 34 - 34: O0 % iIii1I11I1II1 - I1Ii111 / oO0o
   if 83 - 83: I1IiiI / OOooOOo
   if 12 - 12: o0oOOo0O0Ooo / I11i . I1Ii111 % OOooOOo - II111iiii + iII111i
   if 42 - 42: O0 . i1IIi . iIii1I11I1II1 + O0 - i11iIiiIii * Oo0Ooo
  for i111Ii11i in range ( OOOOO ) :
   if ( len ( OOiii11II ) < IIi11iI ) : return
   iii1 = struct . unpack ( Oo0ooOoO , OOiii11II [ : IIi11iI ] ) [ 0 ]
   iiIIiIi1i1I1 . address = socket . ntohl ( iii1 )
   iIO00000 = iiIIiIi1i1I1 . print_address_no_iid ( )
   I1i . append ( [ iIO00000 , ii1I , i11IIIIi ] )
   lprint ( "{} ({}, {})" . format ( IiI1111ii1i ,
 green ( iIO00000 , False ) , bold ( ii1I , False ) ) )
   OOiii11II = OOiii11II [ IIi11iI : : ]
   if 24 - 24: OoOoOO00 % O0
   if 99 - 99: IiII . i1IIi - Oo0Ooo * i1IIi / Ii1I + I1ii11iIi11i
   if 46 - 46: OOooOOo - o0oOOo0O0Ooo
   if 48 - 48: Oo0Ooo
   if 22 - 22: IiII . I1ii11iIi11i / oO0o - OoooooooOO % OoooooooOO + ooOoO0o
   if 34 - 34: iII111i * iII111i / OoO0O00 . ooOoO0o - OoOoOO00
   if 14 - 14: I1Ii111 . I11i . IiII * I1Ii111 / O0 . i11iIiiIii
   if 19 - 19: OoooooooOO / I11i % I1Ii111 % Ii1I + OOooOOo * ooOoO0o
 return ( I1i )
 if 30 - 30: OOooOOo . Ii1I % i11iIiiIii . OoooooooOO . Ii1I
 if 28 - 28: OoO0O00 . iIii1I11I1II1 * I11i
 if 97 - 97: i1IIi . O0 + I11i * IiII
 if 53 - 53: oO0o
 if 9 - 9: iIii1I11I1II1
 if 18 - 18: OoO0O00
 if 93 - 93: iIii1I11I1II1
 if 84 - 84: II111iiii % I1IiiI / O0 + iII111i + OoooooooOO
lisp_geid = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
if 7 - 7: I1IiiI - OoOoOO00 - i1IIi * OoO0O00 . IiII / i1IIi
def lisp_glean_map_cache ( seid , rloc , encap_port , igmp ) :
 if 50 - 50: II111iiii % I1Ii111 . Oo0Ooo
 if 97 - 97: iIii1I11I1II1 % ooOoO0o . i1IIi - Ii1I
 if 60 - 60: O0 * OoO0O00
 if 91 - 91: II111iiii . Oo0Ooo / I11i + Oo0Ooo . I1ii11iIi11i % iII111i
 if 2 - 2: IiII . I11i
 if 38 - 38: i11iIiiIii % OoOoOO00 / ooOoO0o * o0oOOo0O0Ooo * OoO0O00
 o0o00 = True
 Ii111 = lisp_map_cache . lookup_cache ( seid , True )
 if ( Ii111 and len ( Ii111 . rloc_set ) != 0 ) :
  Ii111 . last_refresh_time = lisp_get_timestamp ( )
  if 38 - 38: I1Ii111 / Ii1I * OOooOOo + Oo0Ooo
  o0000oO0 = Ii111 . rloc_set [ 0 ]
  iII1iIii1 = o0000oO0 . rloc
  oOoOoOOO00ooO = o0000oO0 . translated_port
  o0o00 = ( iII1iIii1 . is_exact_match ( rloc ) == False or
 oOoOoOOO00ooO != encap_port )
  if 26 - 26: iII111i . OoO0O00 + I1IiiI . oO0o
  if ( o0o00 ) :
   o0o00oO0oo000 = green ( seid . print_address ( ) , False )
   o0O00o0o = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
   lprint ( "Change gleaned EID {} to RLOC {}" . format ( o0o00oO0oo000 , o0O00o0o ) )
   o0000oO0 . delete_from_rloc_probe_list ( Ii111 . eid , Ii111 . group )
   lisp_change_gleaned_multicast ( seid , rloc , encap_port )
   if 11 - 11: I11i % Ii1I . I1Ii111 % o0oOOo0O0Ooo * i11iIiiIii - I1IiiI
 else :
  Ii111 = lisp_mapping ( "" , "" , [ ] )
  Ii111 . eid . copy_address ( seid )
  Ii111 . mapping_source . copy_address ( rloc )
  Ii111 . map_cache_ttl = LISP_GLEAN_TTL
  Ii111 . gleaned = True
  o0o00oO0oo000 = green ( seid . print_address ( ) , False )
  o0O00o0o = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( o0o00oO0oo000 , o0O00o0o ) )
  Ii111 . add_cache ( )
  if 41 - 41: OOooOOo . iII111i
  if 82 - 82: O0 * o0oOOo0O0Ooo / oO0o
  if 6 - 6: I1Ii111 . o0oOOo0O0Ooo + I11i
  if 79 - 79: Oo0Ooo
  if 11 - 11: i1IIi
 if ( o0o00 ) :
  oO0O0oOOO0 = lisp_rloc ( )
  oO0O0oOOO0 . store_translated_rloc ( rloc , encap_port )
  oO0O0oOOO0 . add_to_rloc_probe_list ( Ii111 . eid , Ii111 . group )
  oO0O0oOOO0 . priority = 253
  oO0O0oOOO0 . mpriority = 255
  oO0O0O0O0OO = [ oO0O0oOOO0 ]
  Ii111 . rloc_set = oO0O0O0O0OO
  Ii111 . build_best_rloc_set ( )
  if 14 - 14: i1IIi
  if 3 - 3: I1Ii111
  if 82 - 82: iIii1I11I1II1 * iII111i - O0
  if 8 - 8: OoOoOO00 - I1Ii111 * OOooOOo
  if 97 - 97: OoOoOO00
 if ( igmp == None ) : return
 if 56 - 56: O0 * Oo0Ooo + I11i % i11iIiiIii * iIii1I11I1II1 * OOooOOo
 if 53 - 53: oO0o
 if 8 - 8: OoO0O00 / oO0o + IiII - o0oOOo0O0Ooo * I11i - IiII
 if 47 - 47: Ii1I / Ii1I
 if 92 - 92: OoO0O00 + Oo0Ooo / I1ii11iIi11i
 lisp_geid . instance_id = seid . instance_id
 if 86 - 86: OoooooooOO - OoOoOO00 . OoooooooOO
 if 92 - 92: i1IIi - OoooooooOO . o0oOOo0O0Ooo - i1IIi . i11iIiiIii
 if 81 - 81: IiII + OOooOOo . i1IIi - OoOoOO00
 if 30 - 30: Ii1I / IiII % II111iiii + o0oOOo0O0Ooo . Oo0Ooo / OoO0O00
 if 22 - 22: iII111i + I1IiiI * OoO0O00 - II111iiii / Oo0Ooo
 IIii11I = lisp_process_igmp_packet ( igmp )
 if ( type ( IIii11I ) == bool ) : return
 if 17 - 17: iIii1I11I1II1 / Ii1I + i1IIi / iII111i * OoooooooOO
 for iiIIiIi1i1I1 , iII1I1i , i11IIIIi in IIii11I :
  if ( iiIIiIi1i1I1 != None ) : continue
  if 1 - 1: i11iIiiIii * I1IiiI
  if 7 - 7: o0oOOo0O0Ooo / OoooooooOO * II111iiii % OoO0O00 + II111iiii
  if 24 - 24: i1IIi + i11iIiiIii - OoO0O00
  if 64 - 64: i1IIi % Oo0Ooo * i1IIi - II111iiii * OoooooooOO * o0oOOo0O0Ooo
  lisp_geid . store_address ( iII1I1i )
  OOoOo0o0oOO0 , iII , I111I1I = lisp_allow_gleaning ( seid , lisp_geid , rloc )
  if ( OOoOo0o0oOO0 == False ) : continue
  if 15 - 15: oO0o
  if ( i11IIIIi ) :
   lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port ,
 True )
  else :
   lisp_remove_gleaned_multicast ( seid , lisp_geid )
   if 28 - 28: Oo0Ooo
   if 15 - 15: OoooooooOO
   if 58 - 58: Oo0Ooo . i11iIiiIii * ooOoO0o % I1ii11iIi11i
   if 73 - 73: OoOoOO00 + O0 / OoooooooOO + I11i - iIii1I11I1II1 % OoOoOO00
   if 1 - 1: I11i * i1IIi . II111iiii / OoO0O00 * OoOoOO00 - Oo0Ooo
   if 32 - 32: IiII % II111iiii * I1ii11iIi11i + II111iiii * O0 + OoO0O00
   if 29 - 29: Oo0Ooo . I1ii11iIi11i
   if 5 - 5: I1IiiI - iIii1I11I1II1 . IiII . i1IIi
   if 55 - 55: i1IIi + I1IiiI - O0 - Oo0Ooo / O0
   if 14 - 14: iIii1I11I1II1 * OOooOOo % I11i * II111iiii
   if 4 - 4: iII111i + II111iiii + IiII . Oo0Ooo + iII111i
   if 22 - 22: oO0o - OoooooooOO . IiII
def lisp_is_json_telemetry ( json_string ) :
 try :
  Oo0o00oO00o0O = json . loads ( json_string )
  if ( type ( Oo0o00oO00o0O ) != dict ) : return ( None )
 except :
  lprint ( "Could not decode telemetry json: {}" . format ( json_string ) )
  return ( None )
  if 77 - 77: I1ii11iIi11i . OOooOOo
  if 26 - 26: OoooooooOO + i11iIiiIii
 if ( "type" not in Oo0o00oO00o0O ) : return ( None )
 if ( "sub-type" not in Oo0o00oO00o0O ) : return ( None )
 if ( Oo0o00oO00o0O [ "type" ] != "telemetry" ) : return ( None )
 if ( Oo0o00oO00o0O [ "sub-type" ] != "timestamps" ) : return ( None )
 return ( Oo0o00oO00o0O )
 if 11 - 11: i11iIiiIii - OoooooooOO + i1IIi / Oo0Ooo . o0oOOo0O0Ooo
 if 5 - 5: OOooOOo - iIii1I11I1II1 - OoooooooOO % ooOoO0o
 if 52 - 52: o0oOOo0O0Ooo
 if 91 - 91: o0oOOo0O0Ooo % II111iiii . I1IiiI * ooOoO0o
 if 23 - 23: I1ii11iIi11i . O0 . OOooOOo - OoO0O00
 if 28 - 28: OoOoOO00 / ooOoO0o % OoOoOO00
 if 27 - 27: II111iiii / O0 % o0oOOo0O0Ooo % I11i * oO0o + I1Ii111
 if 79 - 79: OOooOOo + iIii1I11I1II1 . II111iiii * O0 - I1Ii111 % iIii1I11I1II1
 if 74 - 74: OoO0O00 / OOooOOo - OoooooooOO * Oo0Ooo
 if 97 - 97: i1IIi . o0oOOo0O0Ooo . IiII / i11iIiiIii - oO0o + ooOoO0o
 if 6 - 6: Oo0Ooo + I1Ii111 - OoOoOO00 . i1IIi
 if 98 - 98: iIii1I11I1II1 . ooOoO0o
def lisp_encode_telemetry ( json_string , ii = "?" , io = "?" , ei = "?" , eo = "?" ) :
 Oo0o00oO00o0O = lisp_is_json_telemetry ( json_string )
 if ( Oo0o00oO00o0O == None ) : return ( json_string )
 if 51 - 51: I1IiiI . I1IiiI / oO0o + ooOoO0o % OoO0O00 * I11i
 if ( Oo0o00oO00o0O [ "itr-in" ] == "?" ) : Oo0o00oO00o0O [ "itr-in" ] = ii
 if ( Oo0o00oO00o0O [ "itr-out" ] == "?" ) : Oo0o00oO00o0O [ "itr-out" ] = io
 if ( Oo0o00oO00o0O [ "etr-in" ] == "?" ) : Oo0o00oO00o0O [ "etr-in" ] = ei
 if ( Oo0o00oO00o0O [ "etr-out" ] == "?" ) : Oo0o00oO00o0O [ "etr-out" ] = eo
 json_string = json . dumps ( Oo0o00oO00o0O )
 return ( json_string )
 if 65 - 65: iIii1I11I1II1 * II111iiii * II111iiii % ooOoO0o
 if 17 - 17: II111iiii - oO0o % I1IiiI . O0 % I1Ii111
 if 29 - 29: I1Ii111 - i1IIi
 if 2 - 2: iII111i % OoOoOO00 % I1IiiI % OoooooooOO / I1IiiI
 if 26 - 26: OOooOOo
 if 92 - 92: I1ii11iIi11i * oO0o - iIii1I11I1II1 * Ii1I
 if 1 - 1: OoooooooOO . OOooOOo
 if 37 - 37: II111iiii
 if 95 - 95: I1IiiI + I11i + i1IIi * O0 / OOooOOo
 if 12 - 12: OoooooooOO
 if 31 - 31: OoooooooOO % OOooOOo + OOooOOo + i11iIiiIii + ooOoO0o
 if 1 - 1: I11i % OoooooooOO
def lisp_decode_telemetry ( json_string ) :
 Oo0o00oO00o0O = lisp_is_json_telemetry ( json_string )
 if ( Oo0o00oO00o0O == None ) : return ( { } )
 return ( Oo0o00oO00o0O )
 if 94 - 94: Oo0Ooo + Oo0Ooo + IiII . o0oOOo0O0Ooo
 if 62 - 62: I1Ii111 / OoooooooOO * ooOoO0o
 if 88 - 88: oO0o / Oo0Ooo - OoOoOO00 * ooOoO0o - OoOoOO00 / i11iIiiIii
 if 50 - 50: iIii1I11I1II1 * OOooOOo . iII111i / ooOoO0o + OoOoOO00 - IiII
 if 80 - 80: i11iIiiIii * o0oOOo0O0Ooo
 if 71 - 71: OoO0O00 % I1ii11iIi11i * iII111i . o0oOOo0O0Ooo * oO0o - OoO0O00
 if 44 - 44: I11i / I1Ii111 * OOooOOo - I11i . iIii1I11I1II1
 if 71 - 71: OoO0O00 / IiII
 if 60 - 60: i11iIiiIii - iII111i . OoooooooOO * iII111i + II111iiii
def lisp_telemetry_configured ( ) :
 if ( "telemetry" not in lisp_json_list ) : return ( None )
 if 40 - 40: OOooOOo / iIii1I11I1II1 - Oo0Ooo / II111iiii % ooOoO0o . o0oOOo0O0Ooo
 IIiii11IiIi = lisp_json_list [ "telemetry" ] . json_string
 if ( lisp_is_json_telemetry ( IIiii11IiIi ) == None ) : return ( None )
 if 52 - 52: i1IIi
 return ( IIiii11IiIi )
 if 13 - 13: OoooooooOO / i11iIiiIii - OoOoOO00 + II111iiii . i1IIi
 if 2 - 2: I1IiiI % i1IIi . O0 . I1Ii111
 if 75 - 75: I1ii11iIi11i
 if 23 - 23: oO0o % i1IIi . II111iiii . IiII . I1ii11iIi11i
 if 22 - 22: OOooOOo / II111iiii . ooOoO0o
 if 2 - 2: IiII * Ii1I * I1ii11iIi11i % iII111i
 if 31 - 31: ooOoO0o * Oo0Ooo . I11i - OOooOOo . iII111i
def lisp_mr_or_pubsub ( action ) :
 return ( action in [ LISP_SEND_MAP_REQUEST_ACTION , LISP_SEND_PUBSUB_ACTION ] )
 if 96 - 96: I11i
 if 88 - 88: O0 + OoO0O00
 if 61 - 61: i11iIiiIii
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
