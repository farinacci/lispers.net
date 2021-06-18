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
if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
lisp_map_reply_action_string = [ "no-action" , "native-forward" ,
 "send-map-request" , "drop-action" , "policy-denied" ,
 "auth-failure" , "send-subscribe" ]
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
if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
LISP_RLOC_PROBE_TTL = 128
LISP_RLOC_PROBE_INTERVAL = 10
LISP_RLOC_PROBE_REPLY_WAIT = 15
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
use_chacha = ( os . getenv ( "LISP_USE_CHACHA" ) != None )
use_poly = ( os . getenv ( "LISP_USE_POLY" ) != None )
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
 if ( distro . linux_distribution ( ) [ 0 ] != "debian" ) : return ( False )
 return ( platform . machine ( ) in [ "armv6l" , "armv7l" ] )
 if 78 - 78: OoooooooOO . OoO0O00 + ooOoO0o - i1IIi
 if 31 - 31: OoooooooOO . OOooOOo
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
 return ( distro . linux_distribution ( ) [ 0 ] == "debian" )
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
def lisp_is_linux ( ) :
 return ( platform . uname ( ) [ 0 ] == "Linux" )
 if 9 - 9: I1IiiI % I1IiiI % II111iiii
 if 30 - 30: IiII + I1Ii111 - IiII . IiII - II111iiii + O0
 if 86 - 86: i1IIi
 if 41 - 41: OoOoOO00 * I11i / OoOoOO00 % oO0o
 if 18 - 18: II111iiii . OoooooooOO % OoOoOO00 % Ii1I
 if 9 - 9: OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 if 2 - 2: OoooooooOO % OOooOOo
def lisp_is_python2 ( ) :
 oOoOOo0oo0 = sys . version . split ( ) [ 0 ]
 return ( oOoOOo0oo0 [ 0 : 3 ] == "2.7" )
 if 60 - 60: ooOoO0o * I1Ii111 + Oo0Ooo
 if 19 - 19: OoO0O00 * I11i / I11i . OoooooooOO - OOooOOo + i11iIiiIii
 if 88 - 88: i11iIiiIii - ooOoO0o
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
 if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
 if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
 if 30 - 30: OoOoOO00
def lisp_is_python3 ( ) :
 oOoOOo0oo0 = sys . version . split ( ) [ 0 ]
 return ( oOoOOo0oo0 [ 0 : 2 ] == "3." )
 if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
 if 26 - 26: II111iiii * OoOoOO00
 if 10 - 10: II111iiii . iII111i
 if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
 if 88 - 88: iII111i
 if 19 - 19: II111iiii * IiII + Ii1I
 if 65 - 65: OOooOOo . I1Ii111 . OoO0O00 . iII111i - OOooOOo
def lisp_on_aws ( ) :
 ii111i = getoutput ( "sudo dmidecode -s bios-vendor" )
 if ( ii111i . find ( "command not found" ) != - 1 and lisp_on_docker ( ) ) :
  oooo00 = bold ( "AWS check" , False )
  lprint ( "{} - dmidecode not installed in docker container" . format ( oooo00 ) )
  if 77 - 77: ooOoO0o - I1IiiI % I11i - O0
 return ( ii111i . lower ( ) . find ( "amazon" ) != - 1 )
 if 67 - 67: OOooOOo + Oo0Ooo
 if 84 - 84: O0 * OoooooooOO - IiII * IiII
 if 8 - 8: ooOoO0o / i1IIi . oO0o
 if 41 - 41: iII111i + OoO0O00
 if 86 - 86: OoOoOO00 . iIii1I11I1II1 - OoO0O00
 if 56 - 56: O0
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
def lisp_on_gcp ( ) :
 ii111i = getoutput ( "sudo dmidecode -s bios-version" )
 return ( ii111i . lower ( ) . find ( "google" ) != - 1 )
 if 23 - 23: oO0o - OOooOOo + I11i
 if 12 - 12: I1IiiI / ooOoO0o % o0oOOo0O0Ooo / i11iIiiIii % OoooooooOO
 if 15 - 15: iIii1I11I1II1 % OoooooooOO - Oo0Ooo * Ii1I + I11i
 if 11 - 11: iII111i * Ii1I - OoOoOO00
 if 66 - 66: OoOoOO00 . i11iIiiIii - iII111i * o0oOOo0O0Ooo + OoooooooOO * I1ii11iIi11i
 if 74 - 74: Oo0Ooo
 if 61 - 61: Oo0Ooo - I1Ii111 * II111iiii % ooOoO0o * iIii1I11I1II1 + OoO0O00
def lisp_on_docker ( ) :
 return ( os . path . exists ( "/.dockerenv" ) )
 if 71 - 71: I11i / I11i * oO0o * oO0o / II111iiii
 if 35 - 35: OOooOOo * o0oOOo0O0Ooo * I1IiiI % Oo0Ooo . OoOoOO00
 if 58 - 58: I11i + II111iiii * iII111i * i11iIiiIii - iIii1I11I1II1
 if 68 - 68: OoooooooOO % II111iiii
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if 2 - 2: Ii1I - IiII
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
def lisp_process_logfile ( ) :
 IIIiIi = "./logs/lisp-{}.log" . format ( lisp_log_id )
 if ( os . path . exists ( IIIiIi ) ) : return
 if 34 - 34: OoooooooOO . O0 / oO0o * OoOoOO00 - I1ii11iIi11i
 sys . stdout . close ( )
 sys . stdout = open ( IIIiIi , "a" )
 if 36 - 36: i1IIi / O0 / OoO0O00 - O0 - i1IIi
 lisp_print_banner ( bold ( "logfile rotation" , False ) )
 return
 if 22 - 22: i1IIi + Ii1I
 if 54 - 54: ooOoO0o % OOooOOo . I1Ii111 + oO0o - OOooOOo * I1IiiI
 if 92 - 92: o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % OoO0O00 % IiII . OoooooooOO
 if 52 - 52: ooOoO0o / i11iIiiIii - OOooOOo . IiII % iIii1I11I1II1 + o0oOOo0O0Ooo
 if 71 - 71: oO0o % I11i * OoOoOO00 . O0 / Ii1I . I1ii11iIi11i
 if 58 - 58: Oo0Ooo / oO0o
 if 44 - 44: OOooOOo
 if 54 - 54: Ii1I - I11i - I1Ii111 . iIii1I11I1II1
def lisp_i_am ( name ) :
 global lisp_log_id , lisp_i_am_itr , lisp_i_am_etr , lisp_i_am_rtr
 global lisp_i_am_mr , lisp_i_am_ms , lisp_i_am_ddt , lisp_i_am_core
 global lisp_hostname
 if 79 - 79: Ii1I . OoO0O00
 lisp_log_id = name
 if ( name == "itr" ) : lisp_i_am_itr = True
 if ( name == "etr" ) : lisp_i_am_etr = True
 if ( name == "rtr" ) : lisp_i_am_rtr = True
 if ( name == "mr" ) : lisp_i_am_mr = True
 if ( name == "ms" ) : lisp_i_am_ms = True
 if ( name == "ddt" ) : lisp_i_am_ddt = True
 if ( name == "core" ) : lisp_i_am_core = True
 if 40 - 40: o0oOOo0O0Ooo + Oo0Ooo . o0oOOo0O0Ooo % ooOoO0o
 if 15 - 15: Ii1I * Oo0Ooo % I1ii11iIi11i * iIii1I11I1II1 - i11iIiiIii
 if 60 - 60: I1IiiI * I1Ii111 % OoO0O00 + oO0o
 if 52 - 52: i1IIi
 if 84 - 84: Ii1I / IiII
 lisp_hostname = socket . gethostname ( )
 OOOooo0OooOoO = lisp_hostname . find ( "." )
 if ( OOOooo0OooOoO != - 1 ) : lisp_hostname = lisp_hostname [ 0 : OOOooo0OooOoO ]
 return
 if 91 - 91: oO0o + I1IiiI
 if 59 - 59: I1IiiI + i11iIiiIii + i1IIi / I11i
 if 44 - 44: I11i . OoOoOO00 * I1IiiI + OoooooooOO - iII111i - IiII
 if 15 - 15: IiII / O0 . o0oOOo0O0Ooo . i11iIiiIii
 if 59 - 59: I1Ii111 - o0oOOo0O0Ooo - ooOoO0o
 if 48 - 48: i1IIi + I11i % OoOoOO00 / Oo0Ooo - o0oOOo0O0Ooo
 if 67 - 67: oO0o % o0oOOo0O0Ooo . OoooooooOO + OOooOOo * I11i * OoOoOO00
 if 36 - 36: O0 + Oo0Ooo
 if 5 - 5: Oo0Ooo * OoOoOO00
def lprint ( * args ) :
 ii1I11iIiIII1 = ( "force" in args )
 if ( lisp_debug_logging == False and ii1I11iIiIII1 == False ) : return
 if 52 - 52: o0oOOo0O0Ooo * IiII + OoOoOO00
 lisp_process_logfile ( )
 i1 = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 i1 = i1 [ : - 3 ]
 print ( "{}: {}:" . format ( i1 , lisp_log_id ) , end = " " )
 if 49 - 49: iIii1I11I1II1 - O0 . i1IIi - OoooooooOO
 for Ii1 in args :
  if ( Ii1 == "force" ) : continue
  print ( Ii1 , end = " " )
  if 73 - 73: i1IIi + iII111i . i11iIiiIii
 print ( )
 if 5 - 5: oO0o . I1ii11iIi11i . II111iiii . OoooooooOO
 try : sys . stdout . flush ( )
 except : pass
 return
 if 96 - 96: i11iIiiIii - OOooOOo % O0 / OoO0O00
 if 100 - 100: iII111i / Ii1I - OoooooooOO % II111iiii - I1IiiI % OoOoOO00
 if 60 - 60: iIii1I11I1II1 + i1IIi
 if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if 53 - 53: Ii1I % Oo0Ooo
 if 59 - 59: OOooOOo % iIii1I11I1II1 . i1IIi + II111iiii * IiII
def fprint ( * args ) :
 i1IiiI1iIi = args + ( "force" , )
 lprint ( * i1IiiI1iIi )
 return
 if 66 - 66: OoO0O00 * Oo0Ooo
 if 28 - 28: OoO0O00 % OoOoOO00 % I1ii11iIi11i + I1IiiI / I1IiiI
 if 71 - 71: OOooOOo * OoO0O00 % OoooooooOO % OoO0O00 / I1IiiI
 if 56 - 56: OoooooooOO % i11iIiiIii * iIii1I11I1II1 . OoO0O00 * O0
 if 23 - 23: i11iIiiIii
 if 39 - 39: o0oOOo0O0Ooo - I1ii11iIi11i % iII111i * OoO0O00 - OOooOOo / iII111i
 if 29 - 29: I1ii11iIi11i
 if 52 - 52: i11iIiiIii / i1IIi
def dprint ( * args ) :
 if ( lisp_data_plane_logging ) : lprint ( * args )
 return
 if 1 - 1: ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if 10 - 10: I1Ii111 % I1IiiI
 if 97 - 97: OoooooooOO - I1Ii111
 if 58 - 58: iIii1I11I1II1 + O0
 if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
 if 46 - 46: i11iIiiIii - O0 . oO0o
def cprint ( instance ) :
 print ( "{}:" . format ( instance ) )
 pprint . pprint ( instance . __dict__ )
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
 if 83 - 83: I1Ii111
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 if 50 - 50: IiII % i1IIi
 if 21 - 21: OoooooooOO - iIii1I11I1II1
 if 93 - 93: oO0o - o0oOOo0O0Ooo % OoOoOO00 . OoOoOO00 - ooOoO0o
 if 90 - 90: ooOoO0o + II111iiii * I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o / OoOoOO00 % i11iIiiIii % I1ii11iIi11i / I1IiiI
def debug ( * args ) :
 lisp_process_logfile ( )
 if 62 - 62: i1IIi - OoOoOO00
 i1 = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 i1 = i1 [ : - 3 ]
 if 62 - 62: i1IIi + Oo0Ooo % IiII
 print ( red ( ">>>" , False ) , end = " " )
 print ( "{}:" . format ( i1 ) , end = " " )
 for Ii1 in args : print ( Ii1 , end = " " )
 print ( red ( "<<<\n" , False ) )
 try : sys . stdout . flush ( )
 except : pass
 return
 if 28 - 28: I1ii11iIi11i . i1IIi
 if 10 - 10: OoO0O00 / Oo0Ooo
 if 15 - 15: iII111i . OoOoOO00 / iII111i * I11i - I1IiiI % I1ii11iIi11i
 if 57 - 57: O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
def lisp_print_caller ( ) :
 fprint ( traceback . print_last ( ) )
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
 if 89 - 89: II111iiii / oO0o
def lisp_print_banner ( string ) :
 global lisp_version , lisp_hostname
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 if ( lisp_version == "" ) :
  lisp_version = getoutput ( "cat lisp-version.txt" )
  if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 OOooo00 = bold ( lisp_hostname , False )
 lprint ( "lispers.net LISP {} {}, version {}, hostname {}" . format ( string ,
 datetime . datetime . now ( ) , lisp_version , OOooo00 ) )
 return
 if 35 - 35: I1Ii111 . OoOoOO00 * i11iIiiIii
 if 44 - 44: i11iIiiIii / Oo0Ooo
 if 42 - 42: OoooooooOO + Oo0Ooo % II111iiii + OoO0O00
 if 24 - 24: iII111i * II111iiii % iII111i % IiII + OoooooooOO
 if 29 - 29: II111iiii - OoooooooOO - i11iIiiIii . o0oOOo0O0Ooo
 if 19 - 19: II111iiii
 if 72 - 72: OoooooooOO / I1IiiI + Ii1I / OoOoOO00 * Ii1I
def green ( string , html ) :
 if ( html ) : return ( '<font color="green"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[92m" + string + "\033[0m" , html ) )
 if 34 - 34: O0 * O0 % OoooooooOO + iII111i * iIii1I11I1II1 % Ii1I
 if 25 - 25: I11i + OoOoOO00 . o0oOOo0O0Ooo % OoOoOO00 * OOooOOo
 if 32 - 32: i11iIiiIii - I1Ii111
 if 53 - 53: OoooooooOO - IiII
 if 87 - 87: oO0o . I1IiiI
 if 17 - 17: Ii1I . i11iIiiIii
 if 5 - 5: I1ii11iIi11i + O0 + O0 . I1Ii111 - ooOoO0o
def green_last_sec ( string ) :
 return ( green ( string , True ) )
 if 63 - 63: oO0o
 if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 if 36 - 36: IiII
 if 49 - 49: OOooOOo / OoooooooOO / I1IiiI
 if 74 - 74: I1Ii111 % I1ii11iIi11i
 if 7 - 7: II111iiii
 if 27 - 27: oO0o . OoooooooOO + i11iIiiIii
def green_last_min ( string ) :
 return ( '<font color="#58D68D"><b>{}</b></font>' . format ( string ) )
 if 86 - 86: I11i / o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + oO0o
 if 33 - 33: o0oOOo0O0Ooo . iII111i . IiII . i1IIi
 if 49 - 49: I1ii11iIi11i
 if 84 - 84: I11i - Oo0Ooo / O0 - I1Ii111
 if 21 - 21: O0 * O0 % I1ii11iIi11i
 if 94 - 94: I11i + II111iiii % i11iIiiIii
 if 8 - 8: ooOoO0o * O0
def red ( string , html ) :
 if ( html ) : return ( '<font color="red"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[91m" + string + "\033[0m" , html ) )
 if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 if 34 - 34: ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
 if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
 if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
 if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
def blue ( string , html ) :
 if ( html ) : return ( '<font color="blue"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[94m" + string + "\033[0m" , html ) )
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
 if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
 if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
 if 23 - 23: I11i
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
 if 14 - 14: I1ii11iIi11i
def bold ( string , html ) :
 if ( html ) : return ( "<b>{}</b>" . format ( string ) )
 return ( "\033[1m" + string + "\033[0m" )
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
 if 70 - 70: I1ii11iIi11i
def convert_font ( string ) :
 oo0O = [ [ "[91m" , red ] , [ "[92m" , green ] , [ "[94m" , blue ] , [ "[1m" , bold ] ]
 II = "[0m"
 if 28 - 28: IiII - IiII . i1IIi - ooOoO0o + I1IiiI . IiII
 for oO0ooOOO in oo0O :
  iIi1I1 = oO0ooOOO [ 0 ]
  O0oOoo0OoO0O = oO0ooOOO [ 1 ]
  oo00 = len ( iIi1I1 )
  OOOooo0OooOoO = string . find ( iIi1I1 )
  if ( OOOooo0OooOoO != - 1 ) : break
  if 33 - 33: iIii1I11I1II1 / iII111i - I1IiiI * I11i
  if 53 - 53: ooOoO0o
 while ( OOOooo0OooOoO != - 1 ) :
  o0oO0oo0000OO = string [ OOOooo0OooOoO : : ] . find ( II )
  I1i1ii1IiIii = string [ OOOooo0OooOoO + oo00 : OOOooo0OooOoO + o0oO0oo0000OO ]
  string = string [ : OOOooo0OooOoO ] + O0oOoo0OoO0O ( I1i1ii1IiIii , True ) + string [ OOOooo0OooOoO + o0oO0oo0000OO + oo00 : : ]
  if 69 - 69: OoOoOO00 % oO0o - I11i
  OOOooo0OooOoO = string . find ( iIi1I1 )
  if 38 - 38: iIii1I11I1II1 + i11iIiiIii / i11iIiiIii % OoO0O00 / ooOoO0o % Ii1I
  if 7 - 7: IiII * I1IiiI + i1IIi + i11iIiiIii + Oo0Ooo % I1IiiI
  if 62 - 62: o0oOOo0O0Ooo - Ii1I * OoOoOO00 - i11iIiiIii % ooOoO0o
  if 52 - 52: I1ii11iIi11i % oO0o - i11iIiiIii
  if 30 - 30: iII111i / OoO0O00 + oO0o
 if ( string . find ( "[1m" ) != - 1 ) : string = convert_font ( string )
 return ( string )
 if 6 - 6: iII111i . I11i + Ii1I . I1Ii111
 if 70 - 70: OoO0O00
 if 46 - 46: I11i - i1IIi
 if 46 - 46: I1Ii111 % Ii1I
 if 72 - 72: iIii1I11I1II1
 if 45 - 45: Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
 if 38 - 38: I1Ii111 % OOooOOo - OoooooooOO
def lisp_space ( num ) :
 oOo0OOoooO = ""
 for iIi1iIIIiIiI in range ( num ) : oOo0OOoooO += "&#160;"
 return ( oOo0OOoooO )
 if 62 - 62: i11iIiiIii % OOooOOo . IiII . OOooOOo
 if 84 - 84: i11iIiiIii * OoO0O00
 if 18 - 18: OOooOOo - Ii1I - OoOoOO00 / I1Ii111 - O0
 if 30 - 30: O0 + I1ii11iIi11i + II111iiii
 if 14 - 14: o0oOOo0O0Ooo / OOooOOo - iIii1I11I1II1 - oO0o % ooOoO0o
 if 49 - 49: ooOoO0o * oO0o / o0oOOo0O0Ooo / Oo0Ooo * iIii1I11I1II1
 if 57 - 57: OoOoOO00 - oO0o / ooOoO0o % i11iIiiIii
def lisp_button ( string , url ) :
 I11 = '<button style="background-color:transparent;border-radius:10px; ' + 'type="button">'
 if 100 - 100: I1ii11iIi11i + i11iIiiIii - i1IIi
 if 29 - 29: o0oOOo0O0Ooo / i11iIiiIii / I1IiiI % oO0o % i11iIiiIii
 if ( url == None ) :
  i111II = I11 + string + "</button>"
 else :
  OO0O00o0 = '<a href="{}">' . format ( url )
  I111 = lisp_space ( 2 )
  i111II = I111 + OO0O00o0 + I11 + string + "</button></a>" + I111
  if 36 - 36: i11iIiiIii / oO0o * I1ii11iIi11i * I1ii11iIi11i + Ii1I * I11i
 return ( i111II )
 if 32 - 32: OoO0O00
 if 50 - 50: ooOoO0o + i1IIi
 if 31 - 31: Ii1I
 if 78 - 78: i11iIiiIii + o0oOOo0O0Ooo + I1Ii111 / o0oOOo0O0Ooo % iIii1I11I1II1 % IiII
 if 83 - 83: iIii1I11I1II1 % OoOoOO00 % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i % O0
 if 47 - 47: o0oOOo0O0Ooo
 if 66 - 66: I1IiiI - IiII
def lisp_print_cour ( string ) :
 oOo0OOoooO = '<font face="Courier New">{}</font>' . format ( string )
 return ( oOo0OOoooO )
 if 33 - 33: I1IiiI / OoO0O00
 if 12 - 12: II111iiii
 if 2 - 2: i1IIi - I1IiiI + I11i . II111iiii
 if 25 - 25: oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
 if 43 - 43: I1ii11iIi11i - iII111i
 if 70 - 70: iII111i / OOooOOo % ooOoO0o - Ii1I
def lisp_print_sans ( string ) :
 oOo0OOoooO = '<font face="Sans-Serif">{}</font>' . format ( string )
 return ( oOo0OOoooO )
 if 47 - 47: iII111i
 if 92 - 92: OOooOOo + OoOoOO00 % i1IIi
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 if 47 - 47: oO0o % iIii1I11I1II1
 if 11 - 11: I1IiiI % Ii1I - OoO0O00 - oO0o + o0oOOo0O0Ooo
 if 98 - 98: iII111i + Ii1I - OoO0O00
 if 79 - 79: OOooOOo / I1Ii111 . OoOoOO00 - I1ii11iIi11i
def lisp_span ( string , hover_string ) :
 oOo0OOoooO = '<span title="{}">{}</span>' . format ( hover_string , string )
 return ( oOo0OOoooO )
 if 47 - 47: OoooooooOO % O0 * iII111i . Ii1I
 if 38 - 38: O0 - IiII % I1Ii111
 if 64 - 64: iIii1I11I1II1
 if 15 - 15: I1ii11iIi11i + OOooOOo / I1ii11iIi11i / I1Ii111
 if 31 - 31: ooOoO0o + O0 + ooOoO0o . iIii1I11I1II1 + Oo0Ooo / o0oOOo0O0Ooo
 if 6 - 6: Oo0Ooo % IiII * I11i / I1IiiI + Oo0Ooo
 if 39 - 39: OoOoOO00 - Oo0Ooo / iII111i * OoooooooOO
def lisp_eid_help_hover ( output ) :
 Ooo = '''Unicast EID format:
  For longest match lookups: 
    <address> or [<iid>]<address>
  For exact match lookups: 
    <prefix> or [<iid>]<prefix>
Multicast EID format:
  For longest match lookups:
    <address>-><group> or
    [<iid>]<address>->[<iid>]<group>'''
 if 73 - 73: ooOoO0o + oO0o . OoO0O00
 if 46 - 46: OoO0O00 - o0oOOo0O0Ooo / OoOoOO00 - OoooooooOO + oO0o
 OOOO = lisp_span ( output , Ooo )
 return ( OOOO )
 if 37 - 37: I11i - OoOoOO00 . iIii1I11I1II1 % ooOoO0o % Ii1I * OoOoOO00
 if 8 - 8: OoOoOO00 . ooOoO0o % oO0o . I1IiiI % I1IiiI . Ii1I
 if 47 - 47: I11i + ooOoO0o + II111iiii % i11iIiiIii
 if 93 - 93: I1ii11iIi11i % OoOoOO00 . O0 / iII111i * oO0o
 if 29 - 29: o0oOOo0O0Ooo
 if 86 - 86: II111iiii . IiII
 if 2 - 2: OoooooooOO
def lisp_geo_help_hover ( output ) :
 Ooo = '''EID format:
    <address> or [<iid>]<address>
    '<name>' or [<iid>]'<name>'
Geo-Point format:
    d-m-s-<N|S>-d-m-s-<W|E> or 
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>
Geo-Prefix format:
    d-m-s-<N|S>-d-m-s-<W|E>/<km> or
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>/<km>'''
 if 60 - 60: OoO0O00
 if 81 - 81: OoOoOO00 % Ii1I
 OOOO = lisp_span ( output , Ooo )
 return ( OOOO )
 if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
def space ( num ) :
 oOo0OOoooO = ""
 for iIi1iIIIiIiI in range ( num ) : oOo0OOoooO += "&#160;"
 return ( oOo0OOoooO )
 if 29 - 29: O0 . I1Ii111
 if 66 - 66: oO0o * iIii1I11I1II1 % iIii1I11I1II1 * IiII - ooOoO0o - IiII
 if 70 - 70: I1Ii111 + oO0o
 if 93 - 93: I1Ii111 + Ii1I
 if 33 - 33: O0
 if 78 - 78: O0 / II111iiii * OoO0O00
 if 50 - 50: OoooooooOO - iIii1I11I1II1 + i1IIi % I1Ii111 - iIii1I11I1II1 % O0
 if 58 - 58: IiII + iIii1I11I1II1
def lisp_get_ephemeral_port ( ) :
 return ( random . randrange ( 32768 , 65535 ) )
 if 65 - 65: II111iiii - I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 * iII111i + Ii1I
 if 79 - 79: ooOoO0o . OoOoOO00 % I1Ii111 - Oo0Ooo
 if 69 - 69: ooOoO0o - o0oOOo0O0Ooo . ooOoO0o
 if 9 - 9: oO0o % i11iIiiIii / Oo0Ooo
 if 20 - 20: oO0o * O0 + I11i - OoooooooOO . I11i
 if 60 - 60: o0oOOo0O0Ooo . o0oOOo0O0Ooo / iII111i
 if 45 - 45: O0 . i11iIiiIii % iII111i . OoOoOO00 % IiII % iIii1I11I1II1
def lisp_get_data_nonce ( ) :
 return ( random . randint ( 0 , 0xffffff ) )
 if 58 - 58: iIii1I11I1II1 . OoOoOO00 - i11iIiiIii * iIii1I11I1II1 % i11iIiiIii / I1IiiI
 if 80 - 80: I1ii11iIi11i / iIii1I11I1II1 % OoOoOO00
 if 80 - 80: OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if 13 - 13: OoO0O00
 if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
 if 2 - 2: OoooooooOO . OOooOOo . IiII
def lisp_get_control_nonce ( ) :
 return ( random . randint ( 0 , ( 2 ** 64 ) - 1 ) )
 if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 if 24 - 24: o0oOOo0O0Ooo
 if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
 if 28 - 28: OOooOOo % ooOoO0o
 if 48 - 48: i11iIiiIii % oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
def lisp_hex_string ( integer_value ) :
 oOO0 = hex ( integer_value ) [ 2 : : ]
 if ( oOO0 [ - 1 ] == "L" ) : oOO0 = oOO0 [ 0 : - 1 ]
 return ( oOO0 )
 if 15 - 15: Oo0Ooo + I11i . ooOoO0o - iIii1I11I1II1 / O0 % iIii1I11I1II1
 if 86 - 86: I1IiiI / oO0o * Ii1I
 if 64 - 64: ooOoO0o / O0 * OoOoOO00 * ooOoO0o
 if 60 - 60: I11i / i1IIi % I1ii11iIi11i / I1ii11iIi11i * I1ii11iIi11i . i11iIiiIii
 if 99 - 99: OoOoOO00
 if 77 - 77: o0oOOo0O0Ooo
 if 48 - 48: OoOoOO00 % I1ii11iIi11i / I11i . iIii1I11I1II1 * II111iiii
def lisp_get_timestamp ( ) :
 return ( time . time ( ) )
 if 65 - 65: OoOoOO00
 if 31 - 31: I11i * OoOoOO00 . IiII % Ii1I + Oo0Ooo
 if 47 - 47: O0 * I1IiiI * OoO0O00 . II111iiii
 if 95 - 95: Ii1I % IiII . O0 % I1Ii111
 if 68 - 68: Oo0Ooo . Oo0Ooo - I1ii11iIi11i / I11i . ooOoO0o / i1IIi
 if 12 - 12: I1ii11iIi11i * i1IIi * I11i
 if 23 - 23: OOooOOo / O0 / I1IiiI
def lisp_set_timestamp ( seconds ) :
 return ( time . time ( ) + seconds )
 if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
 if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
 if 79 - 79: OoOoOO00 / ooOoO0o
 if 77 - 77: Oo0Ooo
def lisp_print_elapsed ( ts ) :
 if ( ts == 0 or ts == None ) : return ( "never" )
 i1i111Iiiiiii = time . time ( ) - ts
 i1i111Iiiiiii = round ( i1i111Iiiiiii , 0 )
 return ( str ( datetime . timedelta ( seconds = i1i111Iiiiiii ) ) )
 if 19 - 19: I1IiiI . Oo0Ooo + OoooooooOO - I1IiiI
 if 93 - 93: iIii1I11I1II1 + I1IiiI + i11iIiiIii
 if 74 - 74: I11i / II111iiii + ooOoO0o * iIii1I11I1II1 - I1Ii111 - OoO0O00
 if 69 - 69: iIii1I11I1II1 * I1IiiI - iII111i + O0 + O0
 if 65 - 65: I1Ii111 / i11iIiiIii / OoO0O00 - OOooOOo
 if 9 - 9: I1IiiI / I1Ii111 - Oo0Ooo * iIii1I11I1II1
 if 86 - 86: II111iiii + ooOoO0o + IiII
def lisp_print_future ( ts ) :
 if ( ts == 0 ) : return ( "never" )
 I11i11I = ts - time . time ( )
 if ( I11i11I < 0 ) : return ( "expired" )
 I11i11I = round ( I11i11I , 0 )
 return ( str ( datetime . timedelta ( seconds = I11i11I ) ) )
 if 90 - 90: I1ii11iIi11i
 if 9 - 9: IiII + ooOoO0o
 if 7 - 7: O0 % I1Ii111 + I1ii11iIi11i + Ii1I % OoooooooOO . Oo0Ooo
 if 56 - 56: iII111i
 if 84 - 84: OoOoOO00 - i11iIiiIii
 if 1 - 1: iII111i * OoOoOO00
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
 if 69 - 69: I1ii11iIi11i
 if 83 - 83: o0oOOo0O0Ooo
def lisp_print_eid_tuple ( eid , group ) :
 i1iiii = eid . print_prefix ( )
 if ( group . is_null ( ) ) : return ( i1iiii )
 if 90 - 90: o0oOOo0O0Ooo % I1ii11iIi11i - iIii1I11I1II1 % OoOoOO00
 IIiI11I1I1i1i = group . print_prefix ( )
 oooo = group . instance_id
 if 70 - 70: Ii1I . i11iIiiIii % Ii1I . O0 - iIii1I11I1II1
 if ( eid . is_null ( ) or eid . is_exact_match ( group ) ) :
  OOOooo0OooOoO = IIiI11I1I1i1i . find ( "]" ) + 1
  return ( "[{}](*, {})" . format ( oooo , IIiI11I1I1i1i [ OOOooo0OooOoO : : ] ) )
  if 26 - 26: OOooOOo
  if 76 - 76: i1IIi * OoooooooOO * O0 + I1Ii111 * I1Ii111
 i1iIiIii = eid . print_sg ( group )
 return ( i1iIiIii )
 if 20 - 20: o0oOOo0O0Ooo * ooOoO0o
 if 10 - 10: I11i - Oo0Ooo
 if 59 - 59: OoooooooOO * Oo0Ooo + i1IIi
 if 23 - 23: ooOoO0o
 if 13 - 13: iIii1I11I1II1
 if 77 - 77: i11iIiiIii - iIii1I11I1II1 / oO0o / ooOoO0o / OoO0O00
 if 56 - 56: OoooooooOO * O0
 if 85 - 85: OoooooooOO % OoOoOO00 * iIii1I11I1II1
def lisp_convert_6to4 ( addr_str ) :
 if ( addr_str . find ( "::ffff:" ) == - 1 ) : return ( addr_str )
 IiI = addr_str . split ( ":" )
 return ( IiI [ - 1 ] )
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
 IiI = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 if ( IiI . is_ipv4_string ( addr_str ) ) : addr_str = "::ffff:" + addr_str
 IiI . store_address ( addr_str )
 return ( IiI )
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
  for iIi1iIIIiIiI in range ( 3 ) :
   try : int ( iiiI1IiIIii [ iIi1iIIIiIiI ] , 16 )
   except : break
   if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
   if 83 - 83: IiII / I1Ii111
   if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
 try :
  IiI = socket . gethostbyname ( string )
  return ( IiI )
 except :
  if ( lisp_is_alpine ( ) == False ) : return ( "" )
  if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
  if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
  if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
  if 80 - 80: OoooooooOO + IiII
  if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 try :
  IiI = socket . getaddrinfo ( string , 0 ) [ 0 ]
  if ( IiI [ 3 ] != string ) : return ( "" )
  IiI = IiI [ 4 ] [ 0 ]
 except :
  IiI = ""
  if 43 - 43: Oo0Ooo . I1Ii111
 return ( IiI )
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
 for iIi1iIIIiIiI in range ( 0 , hdrlen * 2 , 4 ) :
  ii1II1II += int ( O0O [ iIi1iIIIiIiI : iIi1iIIIiIiI + 4 ] , 16 )
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
 for iIi1iIIIiIiI in range ( 0 , 36 , 4 ) :
  ii1II1II += int ( IIii1III [ iIi1iIIIiIiI : iIi1iIIIiIiI + 4 ] , 16 )
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
 I111 = lisp_address ( LISP_AFI_IPV6 , source , LISP_IPV6_HOST_MASK_LEN , 0 )
 IiI11I111 = lisp_address ( LISP_AFI_IPV6 , dest , LISP_IPV6_HOST_MASK_LEN , 0 )
 Ooo000O00 = socket . htonl ( len ( data ) )
 i1iI1Iiii1I = socket . htonl ( LISP_UDP_PROTOCOL )
 I1iII = I111 . pack_address ( )
 I1iII += IiI11I111 . pack_address ( )
 I1iII += struct . pack ( "II" , Ooo000O00 , i1iI1Iiii1I )
 if 29 - 29: i1IIi % iII111i / IiII + OoOoOO00 - OOooOOo - I1ii11iIi11i
 if 69 - 69: iIii1I11I1II1 . II111iiii . i1IIi - o0oOOo0O0Ooo
 if 79 - 79: ooOoO0o % OOooOOo
 if 54 - 54: OoOoOO00 - I1Ii111
 O0I1II1 = binascii . hexlify ( I1iII + data )
 oOOoo = len ( O0I1II1 ) % 4
 for iIi1iIIIiIiI in range ( 0 , oOOoo ) : O0I1II1 += "0"
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 ii1II1II = 0
 for iIi1iIIIiIiI in range ( 0 , len ( O0I1II1 ) , 4 ) :
  ii1II1II += int ( O0I1II1 [ iIi1iIIIiIiI : iIi1iIIIiIiI + 4 ] , 16 )
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
 Oo = binascii . hexlify ( igmp )
 if 21 - 21: I1IiiI + I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 - OoO0O00 . Oo0Ooo
 if 59 - 59: OoO0O00 - OoO0O00 + iII111i
 if 32 - 32: i1IIi / Oo0Ooo - O0
 if 85 - 85: Ii1I - O0 * i11iIiiIii . i1IIi
 ii1II1II = 0
 for iIi1iIIIiIiI in range ( 0 , 24 , 4 ) :
  ii1II1II += int ( Oo [ iIi1iIIIiIiI : iIi1iIIIiIiI + 4 ] , 16 )
  if 20 - 20: iII111i / OOooOOo
  if 28 - 28: ooOoO0o * I11i % i11iIiiIii * iII111i / Ii1I
  if 41 - 41: OOooOOo - o0oOOo0O0Ooo + Ii1I
  if 15 - 15: I11i / o0oOOo0O0Ooo + Ii1I
  if 76 - 76: Ii1I + OoooooooOO / OOooOOo % OoO0O00 / I1ii11iIi11i
 ii1II1II = ( ii1II1II >> 16 ) + ( ii1II1II & 0xffff )
 ii1II1II += ii1II1II >> 16
 ii1II1II = socket . htons ( ~ ii1II1II & 0xffff )
 if 38 - 38: I1Ii111 . iII111i . I1IiiI * OoO0O00
 if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii / Ii1I
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
 if ( netifaces . AF_INET not in ooo0o0 ) : return ( None )
 if 84 - 84: I11i - Oo0Ooo * O0 / Ii1I . Ii1I
 if 93 - 93: O0 / ooOoO0o + I1IiiI
 if 20 - 20: IiII / iII111i % OoooooooOO / iIii1I11I1II1 + I1IiiI
 if 57 - 57: o0oOOo0O0Ooo / I1Ii111
 iiIiII = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 7 - 7: Oo0Ooo - i1IIi . I1ii11iIi11i / iIii1I11I1II1 * o0oOOo0O0Ooo
 for IiI in ooo0o0 [ netifaces . AF_INET ] :
  O0O0 = IiI [ "addr" ]
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
 iIIiiIi = lisp_format_packet ( packet [ 0 : 12 ] )
 i1I111II = iIIiiIi . replace ( " " , "" )
 Oo0OOo = i1I111II [ 0 : 12 ]
 i1II11I11ii1 = i1I111II [ 12 : : ]
 if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
 try : I1II1IiI1 = ( i1II11I11ii1 in lisp_mymacs )
 except : I1II1IiI1 = False
 if 26 - 26: OOooOOo * Oo0Ooo
 if ( Oo0OOo in lisp_mymacs ) : return ( lisp_mymacs [ Oo0OOo ] , i1II11I11ii1 , Oo0OOo , I1II1IiI1 )
 if ( I1II1IiI1 ) : return ( lisp_mymacs [ i1II11I11ii1 ] , i1II11I11ii1 , Oo0OOo , I1II1IiI1 )
 return ( [ "?" ] , i1II11I11ii1 , Oo0OOo , I1II1IiI1 )
 if 31 - 31: I11i * oO0o . Ii1I
 if 35 - 35: I11i
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
 if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
 if 68 - 68: O0
 if 76 - 76: I1ii11iIi11i
def lisp_get_local_interfaces ( ) :
 for ooO000OO in netifaces . interfaces ( ) :
  i111IIiIiiI1 = lisp_interface ( ooO000OO )
  i111IIiIiiI1 . add_interface ( )
  if 73 - 73: oO0o . II111iiii * iII111i % oO0o + OoOoOO00 - OoO0O00
 return
 if 19 - 19: iII111i * Oo0Ooo . iII111i . OoO0O00 / OoO0O00 - oO0o
 if 9 - 9: I1Ii111 * IiII * I1Ii111
 if 74 - 74: iIii1I11I1II1 / o0oOOo0O0Ooo
 if 58 - 58: iIii1I11I1II1 - I1IiiI % o0oOOo0O0Ooo % OoooooooOO * iIii1I11I1II1 + OOooOOo
 if 25 - 25: OOooOOo % O0
 if 44 - 44: I1Ii111 . Ii1I * II111iiii / IiII + iIii1I11I1II1
 if 14 - 14: O0 % IiII % Ii1I * oO0o
def lisp_get_loopback_address ( ) :
 for IiI in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( IiI [ "peer" ] == "127.0.0.1" ) : continue
  return ( IiI [ "peer" ] )
  if 65 - 65: I11i % oO0o + I1ii11iIi11i
 return ( None )
 if 86 - 86: iIii1I11I1II1 / O0 . I1Ii111 % iIii1I11I1II1 % Oo0Ooo
 if 86 - 86: i11iIiiIii - o0oOOo0O0Ooo . ooOoO0o * Oo0Ooo / Ii1I % o0oOOo0O0Ooo
 if 61 - 61: o0oOOo0O0Ooo + OoOoOO00
 if 15 - 15: OoOoOO00 * oO0o + OOooOOo . I11i % I1IiiI - ooOoO0o
 if 13 - 13: OoOoOO00 % OoOoOO00 % Oo0Ooo % I1IiiI * i1IIi % I11i
 if 82 - 82: IiII . OoOoOO00 / ooOoO0o + iII111i - ooOoO0o
 if 55 - 55: ooOoO0o % Oo0Ooo % o0oOOo0O0Ooo
 if 29 - 29: IiII / iIii1I11I1II1 + I1ii11iIi11i % iII111i % I11i
def lisp_is_mac_string ( mac_str ) :
 iiiI1IiIIii = mac_str . split ( "/" )
 if ( len ( iiiI1IiIIii ) == 2 ) : mac_str = iiiI1IiIIii [ 0 ]
 return ( len ( mac_str ) == 14 and mac_str . count ( "-" ) == 2 )
 if 46 - 46: iIii1I11I1II1
 if 70 - 70: i1IIi . I11i
 if 74 - 74: I11i
 if 58 - 58: iIii1I11I1II1 * OoO0O00 * I1Ii111 * ooOoO0o . OoooooooOO
 if 6 - 6: I1ii11iIi11i - oO0o * i11iIiiIii + OoOoOO00 / ooOoO0o % OOooOOo
 if 38 - 38: OOooOOo % IiII % II111iiii - Oo0Ooo - iIii1I11I1II1
 if 9 - 9: o0oOOo0O0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 28 - 28: OoooooooOO % oO0o + I1ii11iIi11i + O0 . I1Ii111
def lisp_get_local_macs ( ) :
 for ooO000OO in netifaces . interfaces ( ) :
  if 80 - 80: i11iIiiIii % I1ii11iIi11i
  if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
  if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
  if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
  if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
  IiI11I111 = ooO000OO . replace ( ":" , "" )
  IiI11I111 = ooO000OO . replace ( "-" , "" )
  if ( IiI11I111 . isalnum ( ) == False ) : continue
  if 21 - 21: iII111i
  if 24 - 24: iII111i / ooOoO0o
  if 61 - 61: iIii1I11I1II1 + oO0o
  if 8 - 8: I1Ii111 + OoO0O00
  if 9 - 9: OOooOOo + o0oOOo0O0Ooo
  try :
   I1iII1IIi1IiI = netifaces . ifaddresses ( ooO000OO )
  except :
   continue
   if 8 - 8: iIii1I11I1II1
  if ( netifaces . AF_LINK not in I1iII1IIi1IiI ) : continue
  iiiI1IiIIii = I1iII1IIi1IiI [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  iiiI1IiIIii = iiiI1IiIIii . replace ( ":" , "" )
  if 55 - 55: oO0o
  if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
  if 97 - 97: I1Ii111 . I11i / I1IiiI
  if 83 - 83: I11i - I1ii11iIi11i * oO0o
  if 90 - 90: Oo0Ooo * I1IiiI
  if ( len ( iiiI1IiIIii ) < 12 ) : continue
  if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
  if ( iiiI1IiIIii not in lisp_mymacs ) : lisp_mymacs [ iiiI1IiIIii ] = [ ]
  lisp_mymacs [ iiiI1IiIIii ] . append ( ooO000OO )
  if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
  if 28 - 28: IiII * I1IiiI % IiII
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 95 - 95: O0 / I11i . I1Ii111
 if 17 - 17: I11i
 if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
 if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
 if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
 if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
 if 38 - 38: I1Ii111
 if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
def lisp_get_local_rloc ( ) :
 iI1iIIIIIiIi1 = getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( iI1iIIIIIiIi1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
 if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
 if 43 - 43: iIii1I11I1II1 % OoO0O00
 if 84 - 84: Oo0Ooo
 iI1iIIIIIiIi1 = iI1iIIIIIiIi1 . split ( "\n" ) [ 0 ]
 ooO000OO = iI1iIIIIIiIi1 . split ( ) [ - 1 ]
 if 44 - 44: OoooooooOO * i11iIiiIii / Oo0Ooo
 IiI = ""
 OoO = lisp_is_macos ( )
 if ( OoO ) :
  iI1iIIIIIiIi1 = getoutput ( "ifconfig {} | egrep 'inet '" . format ( ooO000OO ) )
  if ( iI1iIIIIIiIi1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  oO00o00 = 'ip addr show | egrep "inet " | egrep "{}"' . format ( ooO000OO )
  iI1iIIIIIiIi1 = getoutput ( oO00o00 )
  if ( iI1iIIIIIiIi1 == "" ) :
   oO00o00 = 'ip addr show | egrep "inet " | egrep "global lo"'
   iI1iIIIIIiIi1 = getoutput ( oO00o00 )
   if 51 - 51: Oo0Ooo * iIii1I11I1II1 . OoooooooOO . Ii1I - OOooOOo / I1IiiI
  if ( iI1iIIIIIiIi1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 98 - 98: II111iiii + Ii1I + OoooooooOO / i1IIi - Ii1I
  if 87 - 87: iII111i / I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
  if 23 - 23: i11iIiiIii
  if 100 - 100: oO0o + O0 . I1IiiI + i1IIi - OoOoOO00 + o0oOOo0O0Ooo
  if 65 - 65: II111iiii / Oo0Ooo
  if 42 - 42: i11iIiiIii . O0
 IiI = ""
 iI1iIIIIIiIi1 = iI1iIIIIIiIi1 . split ( "\n" )
 if 75 - 75: I1Ii111 + iIii1I11I1II1
 for IiiiI1 in iI1iIIIIIiIi1 :
  OO0O00o0 = IiiiI1 . split ( ) [ 1 ]
  if ( OoO == False ) : OO0O00o0 = OO0O00o0 . split ( "/" ) [ 0 ]
  I1IIIi = lisp_address ( LISP_AFI_IPV4 , OO0O00o0 , 32 , 0 )
  return ( I1IIIi )
  if 39 - 39: I11i . I1ii11iIi11i . OOooOOo * I11i / O0 * o0oOOo0O0Ooo
 return ( lisp_address ( LISP_AFI_IPV4 , IiI , 32 , 0 ) )
 if 35 - 35: i1IIi * i11iIiiIii % I1ii11iIi11i / IiII / IiII
 if 91 - 91: OoO0O00 * I1Ii111 % OoO0O00 . o0oOOo0O0Ooo * I1ii11iIi11i . OOooOOo
 if 13 - 13: I1ii11iIi11i
 if 80 - 80: Oo0Ooo % IiII % OoooooooOO * Oo0Ooo % Ii1I
 if 41 - 41: OoooooooOO / i1IIi
 if 70 - 70: OoOoOO00 % o0oOOo0O0Ooo % i1IIi / I1ii11iIi11i % i11iIiiIii / i1IIi
 if 4 - 4: IiII
 if 93 - 93: oO0o % i1IIi
 if 83 - 83: I1IiiI . Oo0Ooo - I11i . o0oOOo0O0Ooo
 if 73 - 73: I1IiiI - iII111i . iII111i
 if 22 - 22: ooOoO0o / ooOoO0o - Ii1I % I11i . OOooOOo + IiII
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 64 - 64: i1IIi % I1ii11iIi11i / Ii1I % OoooooooOO
 if 24 - 24: I1Ii111 + OoooooooOO . IiII / OoOoOO00 / I11i
 if 65 - 65: OoooooooOO
 if 18 - 18: O0 - i1IIi . I1Ii111
 if 98 - 98: o0oOOo0O0Ooo
 if 73 - 73: Oo0Ooo - iII111i . oO0o % i1IIi . O0
 if 15 - 15: ooOoO0o . iIii1I11I1II1 * I1IiiI % I11i
 if 21 - 21: OoO0O00 - I1IiiI . OoooooooOO
 if 6 - 6: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo / iIii1I11I1II1 * I1Ii111
 if 3 - 3: OOooOOo . IiII / Oo0Ooo
 OooIIi111 = None
 OOOooo0OooOoO = 1
 oO0o0o0O = os . getenv ( "LISP_ADDR_SELECT" )
 if ( oO0o0o0O != None and oO0o0o0O != "" ) :
  oO0o0o0O = oO0o0o0O . split ( ":" )
  if ( len ( oO0o0o0O ) == 2 ) :
   OooIIi111 = oO0o0o0O [ 0 ]
   OOOooo0OooOoO = oO0o0o0O [ 1 ]
  else :
   if ( oO0o0o0O [ 0 ] . isdigit ( ) ) :
    OOOooo0OooOoO = oO0o0o0O [ 0 ]
   else :
    OooIIi111 = oO0o0o0O [ 0 ]
    if 11 - 11: I1Ii111 - I11i % i11iIiiIii . iIii1I11I1II1 * I1IiiI - Oo0Ooo
    if 73 - 73: O0 + ooOoO0o - O0 / OoooooooOO * Oo0Ooo
  OOOooo0OooOoO = 1 if ( OOOooo0OooOoO == "" ) else int ( OOOooo0OooOoO )
  if 32 - 32: OoO0O00 % I1IiiI % iII111i
  if 66 - 66: OoOoOO00 + o0oOOo0O0Ooo
 OOOO00 = [ None , None , None ]
 o0 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 I1iI111ii111i = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 o00 = None
 if 38 - 38: ooOoO0o
 for ooO000OO in netifaces . interfaces ( ) :
  if ( OooIIi111 != None and OooIIi111 != ooO000OO ) : continue
  ooo0o0 = netifaces . ifaddresses ( ooO000OO )
  if ( ooo0o0 == { } ) : continue
  if 38 - 38: O0 - IiII * Oo0Ooo . O0 . I1ii11iIi11i
  if 82 - 82: OoooooooOO
  if 75 - 75: II111iiii % I1IiiI + OOooOOo % OoooooooOO / IiII
  if 4 - 4: i11iIiiIii - OOooOOo % I1ii11iIi11i * I1Ii111 % o0oOOo0O0Ooo
  o00 = lisp_get_interface_instance_id ( ooO000OO , None )
  if 71 - 71: ooOoO0o . ooOoO0o - iIii1I11I1II1
  if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
  if 32 - 32: OoooooooOO % oO0o % iIii1I11I1II1 / O0
  if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
  if ( netifaces . AF_INET in ooo0o0 ) :
   Oo00O0OO = ooo0o0 [ netifaces . AF_INET ]
   O0oo0oOo = 0
   for IiI in Oo00O0OO :
    o0 . store_address ( IiI [ "addr" ] )
    if ( o0 . is_ipv4_loopback ( ) ) : continue
    if ( o0 . is_ipv4_link_local ( ) ) : continue
    if ( o0 . address == 0 ) : continue
    O0oo0oOo += 1
    o0 . instance_id = o00
    if ( OooIIi111 == None and
 lisp_db_for_lookups . lookup_cache ( o0 , False ) ) : continue
    OOOO00 [ 0 ] = o0
    if ( O0oo0oOo == OOOooo0OooOoO ) : break
    if 40 - 40: I11i % ooOoO0o
    if 71 - 71: OoO0O00
  if ( netifaces . AF_INET6 in ooo0o0 ) :
   oOOOoo0o = ooo0o0 [ netifaces . AF_INET6 ]
   O0oo0oOo = 0
   for IiI in oOOOoo0o :
    O0O0 = IiI [ "addr" ]
    I1iI111ii111i . store_address ( O0O0 )
    if ( I1iI111ii111i . is_ipv6_string_link_local ( O0O0 ) ) : continue
    if ( I1iI111ii111i . is_ipv6_loopback ( ) ) : continue
    O0oo0oOo += 1
    I1iI111ii111i . instance_id = o00
    if ( OooIIi111 == None and
 lisp_db_for_lookups . lookup_cache ( I1iI111ii111i , False ) ) : continue
    OOOO00 [ 1 ] = I1iI111ii111i
    if ( O0oo0oOo == OOOooo0OooOoO ) : break
    if 75 - 75: iII111i
    if 16 - 16: I1ii11iIi11i + II111iiii * OoOoOO00 . IiII
    if 10 - 10: iII111i * Ii1I - ooOoO0o . I11i - OOooOOo
    if 94 - 94: I1IiiI % IiII + OoO0O00
    if 90 - 90: i1IIi + O0 - oO0o . iII111i + iIii1I11I1II1
    if 88 - 88: Ii1I * O0 . I1Ii111 / OoooooooOO
  if ( OOOO00 [ 0 ] == None ) : continue
  if 29 - 29: OoooooooOO . II111iiii % OoOoOO00
  OOOO00 [ 2 ] = ooO000OO
  break
  if 26 - 26: iIii1I11I1II1 - I1ii11iIi11i . IiII . IiII + iIii1I11I1II1 * Oo0Ooo
  if 85 - 85: OOooOOo + II111iiii - OOooOOo * oO0o - i1IIi % iII111i
 IiIiI = OOOO00 [ 0 ] . print_address_no_iid ( ) if OOOO00 [ 0 ] else "none"
 iI1Ii11 = OOOO00 [ 1 ] . print_address_no_iid ( ) if OOOO00 [ 1 ] else "none"
 ooO000OO = OOOO00 [ 2 ] if OOOO00 [ 2 ] else "none"
 if 93 - 93: I1IiiI / ooOoO0o / I11i + II111iiii + i11iIiiIii
 OooIIi111 = " (user selected)" if OooIIi111 != None else ""
 if 16 - 16: I1IiiI - oO0o . Oo0Ooo
 IiIiI = red ( IiIiI , False )
 iI1Ii11 = red ( iI1Ii11 , False )
 ooO000OO = bold ( ooO000OO , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( IiIiI , iI1Ii11 , ooO000OO , OooIIi111 , o00 ) )
 if 94 - 94: OoOoOO00 + IiII . ooOoO0o
 if 69 - 69: O0 - O0
 lisp_myrlocs = OOOO00
 return ( ( OOOO00 [ 0 ] != None ) )
 if 41 - 41: IiII % o0oOOo0O0Ooo
 if 67 - 67: O0 % I1Ii111
 if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
 if 39 - 39: Ii1I
 if 60 - 60: OOooOOo
 if 62 - 62: I1Ii111 * I11i
 if 74 - 74: OoOoOO00 . iIii1I11I1II1
 if 87 - 87: ooOoO0o
 if 41 - 41: OoOoOO00 . iIii1I11I1II1 % ooOoO0o + O0
def lisp_get_all_addresses ( ) :
 IIiII11 = [ ]
 for i111IIiIiiI1 in netifaces . interfaces ( ) :
  try : oo0O00OOOOO = netifaces . ifaddresses ( i111IIiIiiI1 )
  except : continue
  if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
  if ( netifaces . AF_INET in oo0O00OOOOO ) :
   for IiI in oo0O00OOOOO [ netifaces . AF_INET ] :
    OO0O00o0 = IiI [ "addr" ]
    if ( OO0O00o0 . find ( "127.0.0.1" ) != - 1 ) : continue
    IIiII11 . append ( OO0O00o0 )
    if 44 - 44: I1Ii111 - IiII
    if 100 - 100: oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
  if ( netifaces . AF_INET6 in oo0O00OOOOO ) :
   for IiI in oo0O00OOOOO [ netifaces . AF_INET6 ] :
    OO0O00o0 = IiI [ "addr" ]
    if ( OO0O00o0 == "::1" ) : continue
    if ( OO0O00o0 [ 0 : 5 ] == "fe80:" ) : continue
    IIiII11 . append ( OO0O00o0 )
    if 59 - 59: II111iiii
    if 43 - 43: Oo0Ooo + OoooooooOO
    if 47 - 47: ooOoO0o
 return ( IIiII11 )
 if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
 if 23 - 23: II111iiii * iII111i
 if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
 if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
 if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
 if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
 if 21 - 21: OoO0O00
 if 63 - 63: I11i . O0 * I11i + iIii1I11I1II1
def lisp_get_all_multicast_rles ( ) :
 Ii1iIi = [ ]
 iI1iIIIIIiIi1 = getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( iI1iIIIIIiIi1 == "" ) : return ( Ii1iIi )
 if 79 - 79: OOooOOo % I1Ii111 / oO0o - iIii1I11I1II1 - OoOoOO00
 o0oOO = iI1iIIIIIiIi1 . split ( "\n" )
 for IiiiI1 in o0oOO :
  if ( IiiiI1 [ 0 ] == "#" ) : continue
  ooo0o0O = IiiiI1 . split ( "rle-address = " ) [ 1 ]
  IiiiIIi11II = int ( ooo0o0O . split ( "." ) [ 0 ] )
  if ( IiiiIIi11II >= 224 and IiiiIIi11II < 240 ) : Ii1iIi . append ( ooo0o0O )
  if 55 - 55: I11i
 return ( Ii1iIi )
 if 93 - 93: i11iIiiIii . o0oOOo0O0Ooo
 if 16 - 16: i1IIi . i1IIi / I1Ii111 % OoOoOO00 / I1IiiI * I1ii11iIi11i
 if 30 - 30: o0oOOo0O0Ooo + OoooooooOO + OOooOOo / II111iiii * Oo0Ooo
 if 59 - 59: Ii1I / OoOoOO00 * OoO0O00 * iII111i % oO0o
 if 61 - 61: Oo0Ooo - O0 - OoooooooOO
 if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
 if 18 - 18: Oo0Ooo % O0
 if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
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
  if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
  if 86 - 86: IiII
 def encode ( self , nonce ) :
  if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
  if 33 - 33: II111iiii - IiII - ooOoO0o
  if 92 - 92: OoO0O00 * IiII
  if 92 - 92: oO0o
  if 7 - 7: iII111i
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 73 - 73: OoO0O00 % I1ii11iIi11i
  if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
  if 62 - 62: i11iIiiIii
  if 2 - 2: I1IiiI
  if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
  if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 14 - 14: IiII . IiII % ooOoO0o
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
  if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
  if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
  if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
  if 98 - 98: Ii1I - II111iiii / I1IiiI . oO0o * IiII . I11i
  if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  self . lisp_header . key_id ( 0 )
  iI1 = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and iI1 == False ) :
   O0O0 = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
   if ( O0O0 in lisp_crypto_keys_by_rloc_encap ) :
    iI1iiiiiii = lisp_crypto_keys_by_rloc_encap [ O0O0 ]
    if ( iI1iiiiiii [ 1 ] ) :
     iI1iiiiiii [ 1 ] . use_count += 1
     Oo00oo , oO0oO = self . encrypt ( iI1iiiiiii [ 1 ] , O0O0 )
     if ( oO0oO ) : self . packet = Oo00oo
     if 71 - 71: I1Ii111 / I1IiiI / O0
     if 19 - 19: i11iIiiIii . I1IiiI + II111iiii / OOooOOo . I1ii11iIi11i * ooOoO0o
     if 59 - 59: iIii1I11I1II1 / I1ii11iIi11i % ooOoO0o
     if 84 - 84: iIii1I11I1II1 / I1IiiI . OoOoOO00 % I11i
     if 99 - 99: Oo0Ooo + i11iIiiIii
     if 36 - 36: Ii1I * I1Ii111 * iIii1I11I1II1 - I11i % i11iIiiIii
     if 98 - 98: iIii1I11I1II1 - i1IIi + ooOoO0o % I11i + ooOoO0o / oO0o
     if 97 - 97: IiII % ooOoO0o + II111iiii - IiII % OoO0O00 + ooOoO0o
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    if ( self . gleaned_dest ) :
     self . udp_sport = LISP_DATA_PORT
    else :
     self . hash_packet ( )
     if 31 - 31: o0oOOo0O0Ooo
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 35 - 35: OoOoOO00 + Ii1I * ooOoO0o / OoOoOO00
  else :
   self . udp_sport = LISP_DATA_PORT
   if 69 - 69: ooOoO0o . OOooOOo - I1IiiI
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 29 - 29: i11iIiiIii . I1ii11iIi11i / I1IiiI . OOooOOo + i11iIiiIii
  if 26 - 26: IiII / Ii1I - OoooooooOO
  if 9 - 9: OoooooooOO * I1ii11iIi11i
  if 9 - 9: Oo0Ooo + iII111i
  oooooO0oO0ooO = socket . htons ( self . udp_sport )
  iIII1IiI = socket . htons ( self . udp_dport )
  IIIIIiI1I1 = socket . htons ( self . udp_length )
  O0I1II1 = struct . pack ( "HHHH" , oooooO0oO0ooO , iIII1IiI , IIIIIiI1I1 , self . udp_checksum )
  if 62 - 62: o0oOOo0O0Ooo / iIii1I11I1II1
  if 55 - 55: Ii1I / OoO0O00 + iII111i . IiII
  if 47 - 47: O0
  if 83 - 83: O0 + OoOoOO00 / O0 / I11i
  OoIi11ii1 = self . lisp_header . encode ( )
  if 1 - 1: iIii1I11I1II1 % oO0o . iIii1I11I1II1
  if 10 - 10: iII111i + OoO0O00
  if 6 - 6: OoO0O00
  if 99 - 99: o0oOOo0O0Ooo * OOooOOo % oO0o * oO0o + OoooooooOO
  if 82 - 82: I11i / OoOoOO00 - OOooOOo / ooOoO0o
  if ( self . outer_version == 4 ) :
   I1iIIi = socket . htons ( self . udp_length + 20 )
   Ii = socket . htons ( 0x4000 )
   Oo00O0o0O = struct . pack ( "BBHHHBBH" , 0x45 , self . outer_tos , I1iIIi , 0xdfdf ,
 Ii , self . outer_ttl , 17 , 0 )
   Oo00O0o0O += self . outer_source . pack_address ( )
   Oo00O0o0O += self . outer_dest . pack_address ( )
   Oo00O0o0O = lisp_ip_checksum ( Oo00O0o0O )
  elif ( self . outer_version == 6 ) :
   Oo00O0o0O = b""
   if 86 - 86: I11i + O0 + Oo0Ooo - I11i
   if 34 - 34: II111iiii % I1IiiI % I1Ii111 + Oo0Ooo - OoOoOO00
   if 66 - 66: Ii1I * iIii1I11I1II1 - ooOoO0o / I1IiiI
   if 62 - 62: IiII . O0 . iIii1I11I1II1
   if 94 - 94: ooOoO0o % I11i % i1IIi
   if 90 - 90: Ii1I * OoO0O00
   if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
  else :
   return ( None )
   if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
   if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
  self . packet = Oo00O0o0O + O0I1II1 + OoIi11ii1 + self . packet
  return ( self )
  if 55 - 55: OoooooooOO
  if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
 def cipher_pad ( self , packet ) :
  i1iIii = len ( packet )
  if ( ( i1iIii % 16 ) != 0 ) :
   O0o00 = ( old_div ( i1iIii , 16 ) + 1 ) * 16
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
  Oo00oo = self . cipher_pad ( self . packet )
  OoOooO = key . get_iv ( )
  if 23 - 23: Ii1I * ooOoO0o - I11i . O0 % iIii1I11I1II1
  i1 = lisp_get_timestamp ( )
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
  iiIi = iII1I ( Oo00oo )
  if 31 - 31: i11iIiiIii + IiII - I1Ii111 * iII111i
  if ( iiIi == None ) : return ( [ self . packet , False ] )
  i1 = int ( str ( time . time ( ) - i1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 60 - 60: iII111i + OoO0O00 + I11i % iIii1I11I1II1 . Oo0Ooo
  if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
  if 93 - 93: i11iIiiIii
  if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
  if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
  if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
  iiIi = iiIi . encode ( "raw_unicode_escape" )
  if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
  if 58 - 58: I11i
  if 7 - 7: II111iiii / IiII % I11i + I1IiiI - O0
  if 45 - 45: I1IiiI / iII111i + oO0o + IiII
  if 15 - 15: I1IiiI % OoO0O00
  if 66 - 66: oO0o * i11iIiiIii . I1Ii111
  if ( iIiiII != None ) : iiIi += iIiiII ( )
  if 92 - 92: oO0o
  if 81 - 81: o0oOOo0O0Ooo % I1IiiI - iII111i / i11iIiiIii
  if 73 - 73: O0 * I1Ii111 . i1IIi
  if 51 - 51: OoO0O00 - iII111i % O0 - OoOoOO00
  if 53 - 53: iII111i / i1IIi / i1IIi
  self . lisp_header . key_id ( key . key_id )
  OoIi11ii1 = self . lisp_header . encode ( )
  if 77 - 77: I11i + i1IIi . I11i
  oO0OOO = key . do_icv ( OoIi11ii1 + OoOooO + iiIi , OoOooO )
  if 42 - 42: iIii1I11I1II1 % Ii1I - I1ii11iIi11i + iIii1I11I1II1
  iiI1I = 4 if ( key . do_poly ) else 8
  if 64 - 64: IiII * iIii1I11I1II1 . I1ii11iIi11i / I11i * iIii1I11I1II1
  i1i111III1 = bold ( "Encrypt" , False )
  III1i1IIII1i = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  i111 = "poly" if key . do_poly else "sha256"
  i111 = bold ( i111 , False )
  IIIIIII1i = "ICV({}): 0x{}...{}" . format ( i111 , oO0OOO [ 0 : iiI1I ] , oO0OOO [ - iiI1I : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( i1i111III1 , key . key_id , addr_str , IIIIIII1i , III1i1IIII1i , i1 ) )
  if 30 - 30: IiII - iII111i - OoO0O00
  if 33 - 33: iIii1I11I1II1 / iII111i
  oO0OOO = int ( oO0OOO , 16 )
  if ( key . do_poly ) :
   OOOOiiI = byte_swap_64 ( ( oO0OOO >> 64 ) & LISP_8_64_MASK )
   o000Ooo00o00O = byte_swap_64 ( oO0OOO & LISP_8_64_MASK )
   oO0OOO = struct . pack ( "QQ" , OOOOiiI , o000Ooo00o00O )
  else :
   OOOOiiI = byte_swap_64 ( ( oO0OOO >> 96 ) & LISP_8_64_MASK )
   o000Ooo00o00O = byte_swap_64 ( ( oO0OOO >> 32 ) & LISP_8_64_MASK )
   ooo0O0O0oo0 = socket . htonl ( oO0OOO & 0xffffffff )
   oO0OOO = struct . pack ( "QQI" , OOOOiiI , o000Ooo00o00O , ooo0O0O0oo0 )
   if 85 - 85: II111iiii + ooOoO0o * I11i
   if 12 - 12: Ii1I . I1IiiI % o0oOOo0O0Ooo
  return ( [ OoOooO + iiIi + oO0OOO , True ] )
  if 28 - 28: Ii1I - I1IiiI % OoO0O00 * I1Ii111
  if 80 - 80: OOooOOo * IiII
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 4 - 4: iIii1I11I1II1 . I1Ii111 + II111iiii % OoooooooOO
  if 82 - 82: OoooooooOO / ooOoO0o * I11i * O0 . I1ii11iIi11i
  if 21 - 21: II111iiii + Oo0Ooo
  if 59 - 59: OOooOOo + I1IiiI / II111iiii / OoOoOO00
  if 80 - 80: OoOoOO00 + iIii1I11I1II1 . IiII
  if 76 - 76: I1IiiI * OOooOOo
  if ( key . do_poly ) :
   OOOOiiI , o000Ooo00o00O = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   ii111 = byte_swap_64 ( OOOOiiI ) << 64
   ii111 |= byte_swap_64 ( o000Ooo00o00O )
   ii111 = lisp_hex_string ( ii111 ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   iiI1I = 4
   IIiiI11 = bold ( "poly" , False )
  else :
   OOOOiiI , o000Ooo00o00O , ooo0O0O0oo0 = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   ii111 = byte_swap_64 ( OOOOiiI ) << 96
   ii111 |= byte_swap_64 ( o000Ooo00o00O ) << 32
   ii111 |= socket . htonl ( ooo0O0O0oo0 )
   ii111 = lisp_hex_string ( ii111 ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   iiI1I = 8
   IIiiI11 = bold ( "sha" , False )
   if 7 - 7: I1IiiI / OoO0O00 + I1Ii111 + I11i / I1IiiI
  OoIi11ii1 = self . lisp_header . encode ( )
  if 82 - 82: I1ii11iIi11i + OoooooooOO
  if 21 - 21: oO0o * oO0o / I11i . iII111i
  if 10 - 10: Ii1I * OOooOOo - Oo0Ooo - OoooooooOO / o0oOOo0O0Ooo
  if 86 - 86: I1Ii111 % I1IiiI
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   Iii1iIIiii1ii = 8
   III1i1IIII1i = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   Iii1iIIiii1ii = 12
   III1i1IIII1i = bold ( "aes-gcm" , False )
  else :
   Iii1iIIiii1ii = 16
   III1i1IIII1i = bold ( "aes-cbc" , False )
   if 13 - 13: iIii1I11I1II1 - II111iiii % O0 . Ii1I % OoO0O00
  OoOooO = packet [ 0 : Iii1iIIiii1ii ]
  if 2 - 2: OoooooooOO - Ii1I % oO0o / I1IiiI / o0oOOo0O0Ooo
  if 3 - 3: II111iiii / OOooOOo
  if 48 - 48: ooOoO0o . I1ii11iIi11i
  if 49 - 49: i1IIi - OoOoOO00 . Oo0Ooo + iIii1I11I1II1 - ooOoO0o / Oo0Ooo
  iIi11ii1 = key . do_icv ( OoIi11ii1 + packet , OoOooO )
  if 49 - 49: oO0o . OoOoOO00
  O0oo = "0x{}...{}" . format ( ii111 [ 0 : iiI1I ] , ii111 [ - iiI1I : : ] )
  iIIi1 = "0x{}...{}" . format ( iIi11ii1 [ 0 : iiI1I ] , iIi11ii1 [ - iiI1I : : ] )
  if 76 - 76: I1IiiI - I1IiiI - o0oOOo0O0Ooo % ooOoO0o * O0
  if ( iIi11ii1 != ii111 ) :
   self . packet_error = "ICV-error"
   I1i1iI = III1i1IIII1i + "/" + IIiiI11
   oo0O0OO = bold ( "ICV failed ({})" . format ( I1i1iI ) , False )
   IIIIIII1i = "packet-ICV {} != computed-ICV {}" . format ( O0oo , iIIi1 )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( oo0O0OO , red ( addr_str , False ) ,
   # II111iiii + I1Ii111
 self . udp_sport , key . key_id , IIIIIII1i ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 68 - 68: Oo0Ooo - iIii1I11I1II1 - i1IIi - oO0o
   if 72 - 72: OoOoOO00 / I1Ii111 * IiII % iIii1I11I1II1
   if 53 - 53: OoO0O00 . O0 . I1IiiI * OOooOOo / o0oOOo0O0Ooo
   if 34 - 34: OoOoOO00
   if 16 - 16: i1IIi - I1Ii111 - II111iiii
   if 83 - 83: I1IiiI - OoO0O00 - o0oOOo0O0Ooo / O0 - I11i . II111iiii
   lisp_retry_decap_keys ( addr_str , OoIi11ii1 + packet , OoOooO , ii111 )
   return ( [ None , False ] )
   if 27 - 27: Ii1I
   if 59 - 59: Ii1I / II111iiii - IiII % OoOoOO00 % OoooooooOO
   if 79 - 79: iII111i . OoooooooOO . I1IiiI * O0 * OoO0O00 - OOooOOo
   if 33 - 33: I1ii11iIi11i . Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
   if 54 - 54: ooOoO0o * iII111i * iII111i % OoOoOO00 - OOooOOo % I1ii11iIi11i
  packet = packet [ Iii1iIIiii1ii : : ]
  if 44 - 44: Oo0Ooo . OOooOOo + I11i
  if 22 - 22: I1Ii111 * OoooooooOO + i11iIiiIii % OoO0O00
  if 53 - 53: I1IiiI
  if 10 - 10: I1Ii111 / i11iIiiIii - II111iiii
  i1 = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   iiI11111II = chacha . ChaCha ( key . encrypt_key , OoOooO ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   o00oOOo0Oo = binascii . unhexlify ( key . encrypt_key )
   try :
    iiI11111II = AES . new ( o00oOOo0Oo , AES . MODE_GCM , OoOooO ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 48 - 48: iII111i % i11iIiiIii . OoooooooOO * IiII % OoO0O00 . iII111i
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 6 - 6: O0 . ooOoO0o - oO0o / i11iIiiIii
   o00oOOo0Oo = binascii . unhexlify ( key . encrypt_key )
   iiI11111II = AES . new ( o00oOOo0Oo , AES . MODE_CBC , OoOooO ) . decrypt
   if 84 - 84: I11i / I1ii11iIi11i * o0oOOo0O0Ooo * OoO0O00 * OOooOOo * O0
   if 83 - 83: O0 % II111iiii + o0oOOo0O0Ooo / OoooooooOO
  Ooi1IIii1i = iiI11111II ( packet )
  i1 = int ( str ( time . time ( ) - i1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 60 - 60: Ii1I % Oo0Ooo / I11i . iII111i / I1Ii111 - OoooooooOO
  if 76 - 76: O0
  if 71 - 71: I1IiiI . i1IIi
  if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
  i1i111III1 = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  i111 = "poly" if key . do_poly else "sha256"
  i111 = bold ( i111 , False )
  IIIIIII1i = "ICV({}): {}" . format ( i111 , O0oo )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( i1i111III1 , key . key_id , addr_str , IIIIIII1i , III1i1IIII1i , i1 ) )
  if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
  if 80 - 80: Ii1I
  if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
  if 59 - 59: I1ii11iIi11i + I11i . oO0o
  if 87 - 87: OoO0O00
  if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
  if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
  self . packet = self . packet [ 0 : header_length ]
  return ( [ Ooi1IIii1i , True ] )
  if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
  if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  ii = 1000
  if 89 - 89: i1IIi . i1IIi
  if 10 - 10: iII111i % Oo0Ooo
  if 48 - 48: OOooOOo + I1Ii111 % OOooOOo
  if 84 - 84: O0 % Ii1I . Ii1I . iII111i * I11i
  if 43 - 43: OoOoOO00 . I1ii11iIi11i % i1IIi
  OO0O00 = [ ]
  oo00 = 0
  i1iIii = len ( inner_packet )
  while ( oo00 < i1iIii ) :
   Ii = inner_packet [ oo00 : : ]
   if ( len ( Ii ) > ii ) : Ii = Ii [ 0 : ii ]
   OO0O00 . append ( Ii )
   oo00 += len ( Ii )
   if 65 - 65: OoooooooOO
   if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
   if 83 - 83: ooOoO0o
   if 43 - 43: OOooOOo
   if 84 - 84: OOooOOo . IiII . iII111i
   if 2 - 2: Oo0Ooo - OoOoOO00
  I1iiII = [ ]
  oo00 = 0
  for Ii in OO0O00 :
   if 81 - 81: OoOoOO00 + o0oOOo0O0Ooo + Oo0Ooo
   if 79 - 79: Oo0Ooo - OoooooooOO % I1Ii111 + OoooooooOO - I11i % OoOoOO00
   if 5 - 5: OoOoOO00 . Oo0Ooo
   if 89 - 89: I1IiiI / iII111i / OoooooooOO - i11iIiiIii + I1IiiI
   Oo0ooo = oo00 if ( Ii == OO0O00 [ - 1 ] ) else 0x2000 + oo00
   Oo0ooo = socket . htons ( Oo0ooo )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , Oo0ooo ) + outer_hdr [ 8 : : ]
   if 73 - 73: II111iiii + OOooOOo * iII111i / iII111i
   if 74 - 74: O0 + iIii1I11I1II1 + oO0o * IiII
   if 39 - 39: I1Ii111 . OoO0O00 % ooOoO0o . OOooOOo / iII111i * OoO0O00
   if 12 - 12: I1IiiI / o0oOOo0O0Ooo
   oOO0O00o0O0 = socket . htons ( len ( Ii ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , oOO0O00o0O0 ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   I1iiII . append ( outer_hdr + Ii )
   oo00 += len ( Ii ) / 8
   if 68 - 68: i11iIiiIii + OoO0O00
  return ( I1iiII )
  if 13 - 13: ooOoO0o - I1IiiI
  if 23 - 23: I1IiiI
 def send_icmp_too_big ( self , inner_packet ) :
  global lisp_last_icmp_too_big_sent
  global lisp_icmp_raw_socket
  if 7 - 7: iII111i % I1ii11iIi11i
  i1i111Iiiiiii = time . time ( ) - lisp_last_icmp_too_big_sent
  if ( i1i111Iiiiiii < LISP_ICMP_TOO_BIG_RATE_LIMIT ) :
   lprint ( "Rate limit sending ICMP Too-Big to {}" . format ( self . inner_source . print_address_no_iid ( ) ) )
   if 64 - 64: I1Ii111 + i11iIiiIii
   return ( False )
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
   if 60 - 60: I1IiiI * I1ii11iIi11i / O0 + I11i + IiII
   if 66 - 66: IiII * Oo0Ooo . OoooooooOO * I1Ii111
   if 93 - 93: IiII / i1IIi
  i111IiIi1 = socket . htons ( 1400 )
  IIii1III = struct . pack ( "BBHHH" , 3 , 4 , 0 , 0 , i111IiIi1 )
  IIii1III += inner_packet [ 0 : 20 + 8 ]
  IIii1III = lisp_icmp_checksum ( IIii1III )
  if 16 - 16: i11iIiiIii * OOooOOo . IiII
  if 100 - 100: OoO0O00 . I11i / Ii1I . o0oOOo0O0Ooo - OoOoOO00 . I11i
  if 30 - 30: Ii1I % I11i + o0oOOo0O0Ooo
  if 65 - 65: iIii1I11I1II1 . iII111i / Ii1I
  if 12 - 12: I1IiiI + I1Ii111
  if 80 - 80: oO0o . O0
  if 90 - 90: II111iiii / OoO0O00 / Ii1I
  O0oooOOo0 = inner_packet [ 12 : 16 ]
  IIi11ii = self . inner_source . print_address_no_iid ( )
  IiI111I = self . outer_source . pack_address ( )
  if 62 - 62: OoooooooOO + IiII
  if 32 - 32: OoOoOO00 * o0oOOo0O0Ooo / OoooooooOO
  if 90 - 90: I1Ii111
  if 35 - 35: II111iiii / Ii1I
  if 79 - 79: OoOoOO00 + I1Ii111 * iII111i * Ii1I
  if 53 - 53: OOooOOo / Oo0Ooo
  if 10 - 10: I1ii11iIi11i . o0oOOo0O0Ooo
  if 75 - 75: O0 * i1IIi - I11i / OOooOOo % OOooOOo / OoOoOO00
  I1iIIi = socket . htons ( 20 + 36 )
  O0O = struct . pack ( "BBHHHBBH" , 0x45 , 0 , I1iIIi , 0 , 0 , 32 , 1 , 0 ) + IiI111I + O0oooOOo0
  O0O = lisp_ip_checksum ( O0O )
  O0O = self . fix_outer_header ( O0O )
  O0O += IIii1III
  Iii1i1Ii = bold ( "Too-Big" , False )
  lprint ( "Send ICMP {} to {}, mtu 1400: {}" . format ( Iii1i1Ii , IIi11ii ,
 lisp_format_packet ( O0O ) ) )
  if 23 - 23: OoOoOO00 - Ii1I - oO0o / OoooooooOO
  try :
   lisp_icmp_raw_socket . sendto ( O0O , ( IIi11ii , 0 ) )
  except socket . error as oO0ooOOO :
   lprint ( "lisp_icmp_raw_socket.sendto() failed: {}" . format ( oO0ooOOO ) )
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
  Oo00oo = self . fix_outer_header ( self . packet )
  if 54 - 54: Ii1I % i1IIi
  if 51 - 51: iIii1I11I1II1 - I1IiiI
  if 61 - 61: OoooooooOO . Ii1I % oO0o * OoooooooOO
  if 96 - 96: Ii1I - II111iiii % OoOoOO00 * I1IiiI * I1IiiI . Oo0Ooo
  if 75 - 75: Oo0Ooo + Ii1I + OoO0O00
  if 97 - 97: ooOoO0o % i11iIiiIii % I11i
  i1iIii = len ( Oo00oo )
  if ( i1iIii <= 1500 ) : return ( [ Oo00oo ] , "Fragment-None" )
  if 21 - 21: Oo0Ooo / Ii1I / I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
  Oo00oo = self . packet
  if 86 - 86: i1IIi
  if 33 - 33: OoOoOO00 % i11iIiiIii * OOooOOo
  if 69 - 69: II111iiii + Oo0Ooo - oO0o . Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1
  if 75 - 75: OoO0O00 % OoooooooOO
  if 16 - 16: O0 / i1IIi
  if ( self . inner_version != 4 ) :
   OOoo0 = random . randint ( 0 , 0xffff )
   Ii11I1iIIi = Oo00oo [ 0 : 4 ] + struct . pack ( "H" , OOoo0 ) + Oo00oo [ 6 : 20 ]
   O0ooO = Oo00oo [ 20 : : ]
   I1iiII = self . fragment_outer ( Ii11I1iIIi , O0ooO )
   return ( I1iiII , "Fragment-Outer" )
   if 40 - 40: o0oOOo0O0Ooo . o0oOOo0O0Ooo * i11iIiiIii
   if 44 - 44: o0oOOo0O0Ooo
   if 80 - 80: I1ii11iIi11i + I11i - ooOoO0o - o0oOOo0O0Ooo % Ii1I
   if 85 - 85: I1Ii111
   if 62 - 62: Ii1I % II111iiii + IiII + OOooOOo % oO0o . I1IiiI
  OOoOo0ooOoo = 56 if ( self . outer_version == 6 ) else 36
  Ii11I1iIIi = Oo00oo [ 0 : OOoOo0ooOoo ]
  oO0OO00 = Oo00oo [ OOoOo0ooOoo : OOoOo0ooOoo + 20 ]
  O0ooO = Oo00oo [ OOoOo0ooOoo + 20 : : ]
  if 16 - 16: OoooooooOO / oO0o . Ii1I * ooOoO0o - I1IiiI
  if 32 - 32: I1IiiI / OoO0O00
  if 28 - 28: Oo0Ooo / IiII . iII111i + OoO0O00 + I11i % Oo0Ooo
  if 45 - 45: Oo0Ooo / O0 % OoooooooOO
  if 92 - 92: Ii1I . OoOoOO00 . I11i - OoooooooOO / ooOoO0o
  ooOo0 = struct . unpack ( "H" , oO0OO00 [ 6 : 8 ] ) [ 0 ]
  ooOo0 = socket . ntohs ( ooOo0 )
  if ( ooOo0 & 0x4000 ) :
   if ( lisp_icmp_raw_socket != None ) :
    I11I1i = Oo00oo [ OOoOo0ooOoo : : ]
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
  oo00 = 0
  i1iIii = len ( O0ooO )
  I1iiII = [ ]
  while ( oo00 < i1iIii ) :
   I1iiII . append ( O0ooO [ oo00 : oo00 + 1400 ] )
   oo00 += 1400
   if 33 - 33: IiII / IiII . i11iIiiIii * I1ii11iIi11i + o0oOOo0O0Ooo
   if 16 - 16: IiII
   if 10 - 10: OoOoOO00 . IiII * iIii1I11I1II1 - oO0o - OoOoOO00 / I1Ii111
   if 13 - 13: oO0o + OoOoOO00 % IiII % OoooooooOO
   if 22 - 22: I1Ii111
  OO0O00 = I1iiII
  I1iiII = [ ]
  iI1iIi1 = True if ooOo0 & 0x2000 else False
  ooOo0 = ( ooOo0 & 0x1fff ) * 8
  for Ii in OO0O00 :
   if 67 - 67: IiII - iIii1I11I1II1 % OOooOOo + I1ii11iIi11i
   if 94 - 94: I1Ii111
   if 39 - 39: OoooooooOO
   if 19 - 19: i11iIiiIii
   oOOOO = old_div ( ooOo0 , 8 )
   if ( iI1iIi1 ) :
    oOOOO |= 0x2000
   elif ( Ii != OO0O00 [ - 1 ] ) :
    oOOOO |= 0x2000
    if 82 - 82: i1IIi + o0oOOo0O0Ooo - II111iiii . Ii1I
   oOOOO = socket . htons ( oOOOO )
   oO0OO00 = oO0OO00 [ 0 : 6 ] + struct . pack ( "H" , oOOOO ) + oO0OO00 [ 8 : : ]
   if 93 - 93: II111iiii * OoOoOO00 % o0oOOo0O0Ooo
   if 67 - 67: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o - i1IIi . OoOoOO00
   if 12 - 12: IiII / OoO0O00 / O0 * IiII
   if 51 - 51: ooOoO0o * iII111i / i1IIi
   if 2 - 2: oO0o + IiII . iII111i - i1IIi + I1Ii111
   if 54 - 54: OoooooooOO . oO0o - iII111i
   i1iIii = len ( Ii )
   ooOo0 += i1iIii
   oOO0O00o0O0 = socket . htons ( i1iIii + 20 )
   oO0OO00 = oO0OO00 [ 0 : 2 ] + struct . pack ( "H" , oOO0O00o0O0 ) + oO0OO00 [ 4 : 10 ] + struct . pack ( "H" , 0 ) + oO0OO00 [ 12 : : ]
   if 76 - 76: I1Ii111
   oO0OO00 = lisp_ip_checksum ( oO0OO00 )
   O00o0 = oO0OO00 + Ii
   if 98 - 98: iIii1I11I1II1 + i11iIiiIii * I1ii11iIi11i / I1Ii111 / ooOoO0o - O0
   if 42 - 42: iII111i
   if 77 - 77: i1IIi * oO0o % OoooooooOO + O0 * ooOoO0o
   if 28 - 28: I11i . OoooooooOO * OOooOOo + i11iIiiIii % I1IiiI . iIii1I11I1II1
   if 63 - 63: II111iiii - I11i . OoOoOO00
   i1iIii = len ( O00o0 )
   if ( self . outer_version == 4 ) :
    oOO0O00o0O0 = i1iIii + OOoOo0ooOoo
    i1iIii += 16
    Ii11I1iIIi = Ii11I1iIIi [ 0 : 2 ] + struct . pack ( "H" , oOO0O00o0O0 ) + Ii11I1iIIi [ 4 : : ]
    if 8 - 8: I1IiiI * ooOoO0o / IiII + OoOoOO00 . IiII - OOooOOo
    Ii11I1iIIi = lisp_ip_checksum ( Ii11I1iIIi )
    O00o0 = Ii11I1iIIi + O00o0
    O00o0 = self . fix_outer_header ( O00o0 )
    if 80 - 80: iIii1I11I1II1 / oO0o * Oo0Ooo - OOooOOo * iII111i
    if 97 - 97: IiII - I11i / II111iiii
    if 26 - 26: iII111i + O0 * iII111i . i1IIi
    if 50 - 50: iIii1I11I1II1 - I11i % iII111i - Oo0Ooo
    if 52 - 52: oO0o + Ii1I - I1ii11iIi11i * Ii1I . OOooOOo + I1Ii111
   iI11II11I1 = OOoOo0ooOoo - 12
   oOO0O00o0O0 = socket . htons ( i1iIii )
   O00o0 = O00o0 [ 0 : iI11II11I1 ] + struct . pack ( "H" , oOO0O00o0O0 ) + O00o0 [ iI11II11I1 + 2 : : ]
   if 67 - 67: I1ii11iIi11i
   I1iiII . append ( O00o0 )
   if 3 - 3: I1Ii111 . I11i % II111iiii * I1IiiI % i1IIi * OoO0O00
  return ( I1iiII , "Fragment-Inner" )
  if 5 - 5: II111iiii * i1IIi % Ii1I
  if 55 - 55: I1IiiI + iII111i
 def fix_outer_header ( self , packet ) :
  if 85 - 85: oO0o + iII111i % iII111i / I11i . I1IiiI - OoOoOO00
  if 19 - 19: I11i / iII111i + IiII
  if 76 - 76: iIii1I11I1II1 / I1Ii111 - I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo + OoooooooOO
  if 10 - 10: OoO0O00 * I11i / Oo0Ooo - I1Ii111
  if 11 - 11: IiII % I1ii11iIi11i / ooOoO0o . i11iIiiIii + OOooOOo - II111iiii
  if 50 - 50: i1IIi * oO0o / i11iIiiIii / i11iIiiIii / oO0o
  if 84 - 84: I1ii11iIi11i - iII111i + I1ii11iIi11i
  if 63 - 63: I11i * ooOoO0o % II111iiii % I1Ii111 + I1IiiI * Oo0Ooo
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 : 4 ] + packet [ 2 : 3 ] + packet [ 4 : 6 ] + packet [ 7 : 8 ] + packet [ 6 : 7 ] + packet [ 8 : : ]
    if 96 - 96: IiII
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 : 4 ] + packet [ 2 : 3 ] + packet [ 4 : : ]
    if 99 - 99: iIii1I11I1II1 - ooOoO0o
    if 79 - 79: I1IiiI + oO0o % I11i % oO0o
  return ( packet )
  if 56 - 56: I1ii11iIi11i + oO0o . OoO0O00 + OoooooooOO * I1ii11iIi11i - O0
  if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 99 - 99: o0oOOo0O0Ooo + OOooOOo
  dest = dest . print_address_no_iid ( )
  I1iiII , I1iI1iiI1Ii1 = self . fragment ( )
  if 62 - 62: I11i % oO0o / OoooooooOO % OoooooooOO
  for O00o0 in I1iiII :
   if ( len ( I1iiII ) != 1 ) :
    self . packet = O00o0
    self . print_packet ( I1iI1iiI1Ii1 , True )
    if 65 - 65: O0 . I1ii11iIi11i * I1Ii111
    if 39 - 39: iIii1I11I1II1 % O0 + Oo0Ooo
   try : lisp_raw_socket . sendto ( O00o0 , ( dest , 0 ) )
   except socket . error as oO0ooOOO :
    lprint ( "socket.sendto() failed: {}" . format ( oO0ooOOO ) )
    if 71 - 71: OoooooooOO + i1IIi + oO0o * Ii1I + i11iIiiIii - oO0o
    if 99 - 99: Oo0Ooo
    if 17 - 17: i11iIiiIii - i11iIiiIii + I1ii11iIi11i * ooOoO0o * oO0o / OoooooooOO
    if 22 - 22: I1Ii111 * I1ii11iIi11i - IiII
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 71 - 71: iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * I1IiiI % II111iiii
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 35 - 35: I1Ii111 - OoOoOO00
   if 61 - 61: I1Ii111 * o0oOOo0O0Ooo * OoO0O00 + I1ii11iIi11i . Oo0Ooo + i1IIi
  Oo00oo = mac_header + self . packet
  if 82 - 82: Oo0Ooo + I1Ii111
  if 93 - 93: I11i * O0 * OOooOOo - o0oOOo0O0Ooo / I1ii11iIi11i
  if 54 - 54: i1IIi - OoO0O00 / OoooooooOO
  if 95 - 95: O0 + iIii1I11I1II1 . I1ii11iIi11i
  if 61 - 61: Ii1I * Ii1I
  if 70 - 70: I1Ii111 . I1ii11iIi11i / o0oOOo0O0Ooo * oO0o
  if 74 - 74: I1IiiI . ooOoO0o / iII111i . IiII
  if 74 - 74: Oo0Ooo / I1Ii111 % I1Ii111 . IiII
  if 72 - 72: i1IIi
  if 21 - 21: I1Ii111 . OOooOOo / i11iIiiIii * i1IIi
  if 82 - 82: ooOoO0o * Oo0Ooo % i11iIiiIii * i1IIi . OOooOOo
  l2_socket . write ( Oo00oo )
  return
  if 89 - 89: IiII - i1IIi - IiII
  if 74 - 74: OoO0O00 % OoO0O00
 def bridge_l2_packet ( self , eid , db ) :
  try : IIIII1IIiIi = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : i111IIiIiiI1 = lisp_myinterfaces [ IIIII1IIiIi . interface ]
  except : return
  try :
   socket = i111IIiIiiI1 . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 91 - 91: I1IiiI / II111iiii * OOooOOo
  try : socket . send ( self . packet )
  except socket . error as oO0ooOOO :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( oO0ooOOO ) )
   if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
   if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
   if 81 - 81: OoO0O00 - iIii1I11I1II1
 def is_lisp_packet ( self , packet ) :
  O0I1II1 = ( struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ] == LISP_UDP_PROTOCOL )
  if ( O0I1II1 == False ) : return ( False )
  if 60 - 60: I1Ii111
  ooO0 = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
  if ( socket . ntohs ( ooO0 ) == LISP_DATA_PORT ) : return ( True )
  ooO0 = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
  if ( socket . ntohs ( ooO0 ) == LISP_DATA_PORT ) : return ( True )
  return ( False )
  if 35 - 35: Oo0Ooo * oO0o / OoooooooOO + O0 / OoooooooOO / OOooOOo
  if 44 - 44: i1IIi . I1ii11iIi11i - ooOoO0o . OOooOOo . o0oOOo0O0Ooo + oO0o
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  Oo00oo = self . packet
  IiiiII = len ( Oo00oo )
  OoOo00OoOO00 = oO0oOOoOo000O = True
  if 3 - 3: OoOoOO00 . o0oOOo0O0Ooo % OoO0O00 / Oo0Ooo * I1Ii111
  if 43 - 43: OoO0O00 % Oo0Ooo + I1IiiI
  if 40 - 40: i1IIi / OoooooooOO / OOooOOo * I1Ii111 - o0oOOo0O0Ooo
  if 77 - 77: i1IIi - iIii1I11I1II1 . OOooOOo
  IIiiIiIIiI1 = 0
  oooo = self . lisp_header . get_instance_id ( )
  if ( is_lisp_packet ) :
   I1IiI = struct . unpack ( "B" , Oo00oo [ 0 : 1 ] ) [ 0 ]
   self . outer_version = I1IiI >> 4
   if ( self . outer_version == 4 ) :
    if 79 - 79: OoOoOO00 + IiII
    if 14 - 14: I1Ii111 / I11i - OOooOOo * O0 % IiII . O0
    if 86 - 86: i1IIi * OoooooooOO
    if 22 - 22: I1Ii111 + iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoooooooOO
    if 42 - 42: OoooooooOO - OoOoOO00 - OOooOOo * I1Ii111
    OO0 = struct . unpack ( "H" , Oo00oo [ 10 : 12 ] ) [ 0 ]
    Oo00oo = lisp_ip_checksum ( Oo00oo )
    ii1II1II = struct . unpack ( "H" , Oo00oo [ 10 : 12 ] ) [ 0 ]
    if ( ii1II1II != 0 ) :
     if ( OO0 != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( IiiiII )
       if 14 - 14: OoooooooOO + OOooOOo . iII111i
       if 94 - 94: IiII / I1Ii111 * IiII - ooOoO0o
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 89 - 89: iIii1I11I1II1
      if 31 - 31: ooOoO0o . OOooOOo % ooOoO0o
      if 33 - 33: O0 * Ii1I - IiII . OoooooooOO + IiII
    i1I1iiiI = LISP_AFI_IPV4
    oo00 = 12
    self . outer_tos = struct . unpack ( "B" , Oo00oo [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , Oo00oo [ 8 : 9 ] ) [ 0 ]
    IIiiIiIIiI1 = 20
   elif ( self . outer_version == 6 ) :
    i1I1iiiI = LISP_AFI_IPV6
    oo00 = 8
    i1IiIi1I1i = struct . unpack ( "H" , Oo00oo [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( i1IiIi1I1i ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , Oo00oo [ 7 : 8 ] ) [ 0 ]
    IIiiIiIIiI1 = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( IiiiII )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 39 - 39: i11iIiiIii + OOooOOo % iII111i + Ii1I * I1IiiI + I1Ii111
    if 72 - 72: II111iiii + I1Ii111 * OOooOOo . I1IiiI
   self . outer_source . afi = i1I1iiiI
   self . outer_dest . afi = i1I1iiiI
   o0ooOo000oo = self . outer_source . addr_length ( )
   if 81 - 81: OoooooooOO - IiII - IiII + iIii1I11I1II1 % I11i . OoooooooOO
   self . outer_source . unpack_address ( Oo00oo [ oo00 : oo00 + o0ooOo000oo ] )
   oo00 += o0ooOo000oo
   self . outer_dest . unpack_address ( Oo00oo [ oo00 : oo00 + o0ooOo000oo ] )
   Oo00oo = Oo00oo [ IIiiIiIIiI1 : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 75 - 75: O0
   if 96 - 96: Ii1I
   if 24 - 24: O0
   if 33 - 33: OoooooooOO + oO0o * II111iiii / OOooOOo
   ooooI11iii1iIIIIi = struct . unpack ( "H" , Oo00oo [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( ooooI11iii1iIIIIi )
   ooooI11iii1iIIIIi = struct . unpack ( "H" , Oo00oo [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( ooooI11iii1iIIIIi )
   ooooI11iii1iIIIIi = struct . unpack ( "H" , Oo00oo [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( ooooI11iii1iIIIIi )
   ooooI11iii1iIIIIi = struct . unpack ( "H" , Oo00oo [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( ooooI11iii1iIIIIi )
   Oo00oo = Oo00oo [ 8 : : ]
   if 43 - 43: o0oOOo0O0Ooo % ooOoO0o - Ii1I / O0 . I1IiiI
   if 74 - 74: O0 % I11i % I11i . O0
   if 59 - 59: OOooOOo + O0 % iII111i / I11i + OoOoOO00 + Ii1I
   if 32 - 32: I1ii11iIi11i / Oo0Ooo . OoOoOO00 + iII111i * OoOoOO00 * IiII
   OoOo00OoOO00 = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   oO0oOOoOo000O = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 46 - 46: Ii1I
   if 42 - 42: iIii1I11I1II1
   if 32 - 32: Oo0Ooo - Ii1I . OoooooooOO - OoooooooOO - Oo0Ooo . iIii1I11I1II1
   if 34 - 34: Oo0Ooo
   if ( self . lisp_header . decode ( Oo00oo ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( IiiiII )
    if 31 - 31: i1IIi - I11i + I1Ii111 + ooOoO0o . ooOoO0o . O0
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 33 - 33: i1IIi / iII111i * OoO0O00
   Oo00oo = Oo00oo [ 8 : : ]
   oooo = self . lisp_header . get_instance_id ( )
   IIiiIiIIiI1 += 16
   if 2 - 2: oO0o . OOooOOo
  if ( oooo == 0xffffff ) : oooo = 0
  if 43 - 43: iIii1I11I1II1
  if 29 - 29: IiII % ooOoO0o + OoO0O00 . i1IIi + I1IiiI
  if 24 - 24: I1Ii111 / Ii1I * I1ii11iIi11i - OoooooooOO / I1IiiI . oO0o
  if 98 - 98: i1IIi - iII111i
  iI = False
  IiII11iI1 = self . lisp_header . k_bits
  if ( IiII11iI1 ) :
   O0O0 = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( O0O0 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( IiiiII )
    if 80 - 80: iII111i . O0
    self . print_packet ( "Receive" , is_lisp_packet )
    I1Iii = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( I1Iii , IiII11iI1 ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 33 - 33: o0oOOo0O0Ooo - oO0o % I1ii11iIi11i * I11i . OoooooooOO % Ii1I
    if 29 - 29: iII111i + II111iiii . i11iIiiIii . Ii1I - O0
   III = lisp_crypto_keys_by_rloc_decap [ O0O0 ] [ IiII11iI1 ]
   if ( III == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( IiiiII )
    if 60 - 60: II111iiii . I11i / OoooooooOO + ooOoO0o . iIii1I11I1II1
    self . print_packet ( "Receive" , is_lisp_packet )
    I1Iii = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( I1Iii ,
 red ( O0O0 , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 87 - 87: I1IiiI + I1ii11iIi11i % oO0o - Oo0Ooo
    if 33 - 33: II111iiii . I1ii11iIi11i - O0 * iIii1I11I1II1 % O0 . OoooooooOO
    if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
    if 16 - 16: OoO0O00 % I1Ii111 . i1IIi / I1ii11iIi11i - O0
    if 85 - 85: i1IIi . i1IIi
   III . use_count += 1
   Oo00oo , iI = self . decrypt ( Oo00oo , IIiiIiIIiI1 , III , O0O0 )
   if ( iI == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( IiiiII )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 16 - 16: I1IiiI - OOooOOo % Ii1I . OOooOOo + I1ii11iIi11i % i11iIiiIii
    if 59 - 59: i11iIiiIii - I11i
    if 59 - 59: OoooooooOO * o0oOOo0O0Ooo / I1Ii111
    if 75 - 75: o0oOOo0O0Ooo - OoooooooOO
    if 21 - 21: I1IiiI + iIii1I11I1II1 / i11iIiiIii / oO0o
    if 66 - 66: OoooooooOO + iII111i . IiII % i1IIi
   Oo00oo = Oo00oo . encode ( "raw_unicode_escape" )
   if 58 - 58: OOooOOo % iII111i * O0 + I1ii11iIi11i - IiII
   if 26 - 26: i1IIi / I1IiiI / I11i + I11i
   if 46 - 46: I1Ii111 % I1ii11iIi11i + Ii1I
   if 67 - 67: iIii1I11I1II1 . i11iIiiIii . i11iIiiIii . i11iIiiIii / I11i + ooOoO0o
   if 10 - 10: ooOoO0o - Oo0Ooo % II111iiii
  I1IiI = struct . unpack ( "B" , Oo00oo [ 0 : 1 ] ) [ 0 ]
  self . inner_version = I1IiI >> 4
  if ( OoOo00OoOO00 and self . inner_version == 4 and I1IiI >= 0x45 ) :
   oo = socket . ntohs ( struct . unpack ( "H" , Oo00oo [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , Oo00oo [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , Oo00oo [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , Oo00oo [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( Oo00oo [ 12 : 16 ] )
   self . inner_dest . unpack_address ( Oo00oo [ 16 : 20 ] )
   ooOo0 = socket . ntohs ( struct . unpack ( "H" , Oo00oo [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( ooOo0 & 0x2000 or ooOo0 != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , Oo00oo [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , Oo00oo [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 15 - 15: ooOoO0o * iIii1I11I1II1 * oO0o
  elif ( OoOo00OoOO00 and self . inner_version == 6 and I1IiI >= 0x60 ) :
   oo = socket . ntohs ( struct . unpack ( "H" , Oo00oo [ 4 : 6 ] ) [ 0 ] ) + 40
   i1IiIi1I1i = struct . unpack ( "H" , Oo00oo [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( i1IiIi1I1i ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , Oo00oo [ 7 : 8 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , Oo00oo [ 6 : 7 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( Oo00oo [ 8 : 24 ] )
   self . inner_dest . unpack_address ( Oo00oo [ 24 : 40 ] )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , Oo00oo [ 40 : 42 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , Oo00oo [ 42 : 44 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
  elif ( oO0oOOoOo000O ) :
   oo = len ( Oo00oo )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_protocol = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( Oo00oo [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( Oo00oo [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( IiiiII )
   if 3 - 3: OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( I1IiI ) ) )
   if 47 - 47: IiII . OOooOOo
   Oo00oo = lisp_format_packet ( Oo00oo [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( Oo00oo ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = oooo
  self . inner_dest . instance_id = oooo
  if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
  if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
  if 68 - 68: OoO0O00 % O0 * iIii1I11I1II1 / oO0o * o0oOOo0O0Ooo + OOooOOo
  if 89 - 89: ooOoO0o * I1IiiI . oO0o
  if 75 - 75: ooOoO0o - iII111i % iII111i + ooOoO0o * o0oOOo0O0Ooo - I1ii11iIi11i
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   I111Ii1I1I1iI = lisp_get_echo_nonce ( self . outer_source , None )
   if ( I111Ii1I1I1iI == None ) :
    IIIOo0O = self . outer_source . print_address_no_iid ( )
    I111Ii1I1I1iI = lisp_echo_nonce ( IIIOo0O )
    if 11 - 11: O0
   o0Oo0o = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    I111Ii1I1I1iI . receive_request ( lisp_ipc_socket , o0Oo0o )
   elif ( I111Ii1I1I1iI . request_nonce_sent ) :
    I111Ii1I1I1iI . receive_echo ( lisp_ipc_socket , o0Oo0o )
    if 4 - 4: OoooooooOO
    if 78 - 78: II111iiii
    if 96 - 96: OoO0O00 + I1IiiI % Oo0Ooo
    if 21 - 21: OoOoOO00 - i11iIiiIii - OoOoOO00
    if 4 - 4: I11i . IiII
    if 39 - 39: OOooOOo . Oo0Ooo - OoOoOO00 * i11iIiiIii
    if 4 - 4: OoOoOO00 * O0 - I11i
  if ( iI ) : self . packet += Oo00oo [ : oo ]
  if 72 - 72: I11i + ooOoO0o / I1IiiI . IiII % OoO0O00 / i11iIiiIii
  if 13 - 13: I1Ii111 % o0oOOo0O0Ooo + OOooOOo + I1Ii111 + i11iIiiIii - I1ii11iIi11i
  if 70 - 70: II111iiii * II111iiii . I1IiiI
  if 11 - 11: iII111i
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 20 - 20: Ii1I . I1Ii111 % Ii1I
  if 5 - 5: OOooOOo + iII111i
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 23 - 23: I1Ii111 % iIii1I11I1II1 . I11i
  if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
 def strip_outer_headers ( self ) :
  oo00 = 16
  oo00 += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ oo00 : : ]
  return ( self )
  if 11 - 11: I1ii11iIi11i / O0 + II111iiii
  if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
 def hash_ports ( self ) :
  Oo00oo = self . packet
  I1IiI = self . inner_version
  II1Iii1iI = 0
  if ( I1IiI == 4 ) :
   oo0 = struct . unpack ( "B" , Oo00oo [ 9 : 10 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( oo0 )
   if ( oo0 in [ 6 , 17 ] ) :
    II1Iii1iI = oo0
    II1Iii1iI += struct . unpack ( "I" , Oo00oo [ 20 : 24 ] ) [ 0 ]
    II1Iii1iI = ( II1Iii1iI >> 16 ) ^ ( II1Iii1iI & 0xffff )
    if 2 - 2: Ii1I
    if 12 - 12: i11iIiiIii - iIii1I11I1II1 * IiII * iII111i
  if ( I1IiI == 6 ) :
   oo0 = struct . unpack ( "B" , Oo00oo [ 6 : 7 ] ) [ 0 ]
   if ( oo0 in [ 6 , 17 ] ) :
    II1Iii1iI = oo0
    II1Iii1iI += struct . unpack ( "I" , Oo00oo [ 40 : 44 ] ) [ 0 ]
    II1Iii1iI = ( II1Iii1iI >> 16 ) ^ ( II1Iii1iI & 0xffff )
    if 19 - 19: O0 + oO0o + o0oOOo0O0Ooo
    if 81 - 81: iIii1I11I1II1
  return ( II1Iii1iI )
  if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
  if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
 def hash_packet ( self ) :
  II1Iii1iI = self . inner_source . address ^ self . inner_dest . address
  II1Iii1iI += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   II1Iii1iI = ( II1Iii1iI >> 16 ) ^ ( II1Iii1iI & 0xffff )
  elif ( self . inner_version == 6 ) :
   II1Iii1iI = ( II1Iii1iI >> 64 ) ^ ( II1Iii1iI & 0xffffffffffffffff )
   II1Iii1iI = ( II1Iii1iI >> 32 ) ^ ( II1Iii1iI & 0xffffffff )
   II1Iii1iI = ( II1Iii1iI >> 16 ) ^ ( II1Iii1iI & 0xffff )
   if 89 - 89: OoooooooOO % II111iiii - OoO0O00 % i11iIiiIii
  self . udp_sport = 0xf000 | ( II1Iii1iI & 0xfff )
  if 7 - 7: IiII
  if 15 - 15: Oo0Ooo + iII111i + I1IiiI * o0oOOo0O0Ooo
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   iII1111IIIIiI = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # oO0o - II111iiii / II111iiii
 green ( iII1111IIIIiI , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 29 - 29: I1Ii111 / I1ii11iIi11i * I1IiiI + iII111i
   if 52 - 52: OoO0O00 / Ii1I - IiII
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   I1IIi = "decap"
   I1IIi += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   I1IIi = s_or_r
   if ( I1IIi in [ "Send" , "Replicate" ] or I1IIi . find ( "Fragment" ) != - 1 ) :
    I1IIi = "encap"
    if 80 - 80: I11i / oO0o * Ii1I / iII111i
    if 19 - 19: i1IIi + II111iiii + o0oOOo0O0Ooo - iIii1I11I1II1
  o00oo00O0OoOo = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 6 - 6: I1ii11iIi11i * Oo0Ooo + iIii1I11I1II1
  if 19 - 19: O0 % II111iiii * o0oOOo0O0Ooo
  if 27 - 27: OOooOOo * IiII / i11iIiiIii - oO0o + II111iiii
  if 43 - 43: I1ii11iIi11i - II111iiii
  if 56 - 56: I1ii11iIi11i . i1IIi / iII111i % oO0o / O0 * I11i
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   IiiiI1 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 98 - 98: O0 + iII111i
   IiiiI1 += bold ( "control-packet" , False ) + ": {} ..."
   if 23 - 23: OoooooooOO . iIii1I11I1II1 / i1IIi
   dprint ( IiiiI1 . format ( bold ( s_or_r , False ) , red ( o00oo00O0OoOo , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   IiiiI1 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
   if 74 - 74: Oo0Ooo - II111iiii - IiII
   if 50 - 50: I1IiiI - oO0o + oO0o * I11i + oO0o
   if 70 - 70: i1IIi % OoO0O00 / i1IIi
  if ( self . lisp_header . k_bits ) :
   if ( I1IIi == "encap" ) : I1IIi = "encrypt/encap"
   if ( I1IIi == "decap" ) : I1IIi = "decap/decrypt"
   if 30 - 30: OoOoOO00 - i11iIiiIii
   if 94 - 94: OoOoOO00 % iII111i
  iII1111IIIIiI = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 39 - 39: OoOoOO00 + I1Ii111 % O0
  dprint ( IiiiI1 . format ( bold ( s_or_r , False ) , red ( o00oo00O0OoOo , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( iII1111IIIIiI , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( I1IIi ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 26 - 26: ooOoO0o + OoOoOO00
  if 17 - 17: I1ii11iIi11i - iII111i % Oo0Ooo * O0 % O0 * OOooOOo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 6 - 6: I1Ii111
  if 46 - 46: II111iiii * I1Ii111
 def get_raw_socket ( self ) :
  oooo = str ( self . lisp_header . get_instance_id ( ) )
  if ( oooo == "0" ) : return ( None )
  if ( oooo not in lisp_iid_to_interface ) : return ( None )
  if 23 - 23: i1IIi - O0
  i111IIiIiiI1 = lisp_iid_to_interface [ oooo ]
  I111 = i111IIiIiiI1 . get_socket ( )
  if ( I111 == None ) :
   i1i111III1 = bold ( "SO_BINDTODEVICE" , False )
   I11iI11i1i1 = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( i1i111III1 , "drop" if I11iI11i1i1 else "forward" ) )
   if 7 - 7: iII111i
   if ( I11iI11i1i1 ) : return ( None )
   if 18 - 18: OoOoOO00
   if 77 - 77: I1Ii111 . i11iIiiIii / Ii1I * i11iIiiIii - o0oOOo0O0Ooo
  oooo = bold ( oooo , False )
  IiI11I111 = bold ( i111IIiIiiI1 . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( oooo , IiI11I111 ) )
  return ( I111 )
  if 6 - 6: i11iIiiIii
  if 16 - 16: IiII
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 84 - 84: i1IIi / iIii1I11I1II1 / oO0o / Ii1I
  iIOOOO00 = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or iIOOOO00 ) :
   I11IIII1iI = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = I11IIII1iI ) . start ( )
   if ( iIOOOO00 ) : os . system ( "rm ./log-flows" )
   return
   if 37 - 37: OoO0O00 - Oo0Ooo
   if 38 - 38: i11iIiiIii / OoO0O00
  i1 = datetime . datetime . now ( )
  lisp_flow_log . append ( [ i1 , encap , self . packet , self ] )
  if 64 - 64: IiII
  if 80 - 80: I1IiiI - i11iIiiIii / OoO0O00 / OoOoOO00 + OoOoOO00
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  oo000o = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 6 - 6: OOooOOo + I1ii11iIi11i + Oo0Ooo
  o0OOo0o0o0ooo = red ( self . outer_source . print_address_no_iid ( ) , False )
  o0OOoo = red ( self . outer_dest . print_address_no_iid ( ) , False )
  oO0o00O = green ( self . inner_source . print_address ( ) , False )
  IIII1ii1iIIii = green ( self . inner_dest . print_address ( ) , False )
  if 96 - 96: OoO0O00 - iII111i
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   oo000o += " {}:{} -> {}:{}, LISP control message type {}\n"
   oo000o = oo000o . format ( o0OOo0o0o0ooo , self . udp_sport , o0OOoo , self . udp_dport ,
 self . inner_version )
   return ( oo000o )
   if 16 - 16: I1Ii111 / O0 . II111iiii * OoOoOO00
   if 7 - 7: I1Ii111 * O0 + OoOoOO00
  if ( self . outer_dest . is_null ( ) == False ) :
   oo000o += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   oo000o = oo000o . format ( o0OOo0o0o0ooo , self . udp_sport , o0OOoo , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 90 - 90: IiII * II111iiii * IiII - iII111i
   if 34 - 34: OOooOOo - I1ii11iIi11i * iII111i % Ii1I
   if 25 - 25: II111iiii + I1IiiI * ooOoO0o * I1ii11iIi11i . iII111i
   if 26 - 26: iII111i - ooOoO0o / OoooooooOO + o0oOOo0O0Ooo . Oo0Ooo
   if 75 - 75: O0 / OoOoOO00 . I1Ii111
  if ( self . lisp_header . k_bits != 0 ) :
   iI1iIi1ii1I1 = "\n"
   if ( self . packet_error != "" ) :
    iI1iIi1ii1I1 = " ({})" . format ( self . packet_error ) + iI1iIi1ii1I1
    if 59 - 59: II111iiii * OoooooooOO - OoooooooOO
   oo000o += ", encrypted" + iI1iIi1ii1I1
   return ( oo000o )
   if 33 - 33: O0 . i11iIiiIii % o0oOOo0O0Ooo
   if 50 - 50: ooOoO0o
   if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
   if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
   if 59 - 59: iII111i - OoooooooOO / ooOoO0o + I1ii11iIi11i . o0oOOo0O0Ooo - iII111i
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 29 - 29: oO0o
   if 26 - 26: O0 % OOooOOo - IiII . OOooOOo
  oo0 = packet [ 9 : 10 ] if self . inner_version == 4 else packet [ 6 : 7 ]
  oo0 = struct . unpack ( "B" , oo0 ) [ 0 ]
  if 70 - 70: o0oOOo0O0Ooo + I11i / iII111i + ooOoO0o / I1IiiI
  oo000o += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  oo000o = oo000o . format ( oO0o00O , IIII1ii1iIIii , len ( packet ) , self . inner_tos ,
 self . inner_ttl , oo0 )
  if 33 - 33: OoooooooOO . O0
  if 59 - 59: iIii1I11I1II1
  if 45 - 45: O0
  if 78 - 78: I11i - iIii1I11I1II1 + I1Ii111 - I1ii11iIi11i - I1Ii111
  if ( oo0 in [ 6 , 17 ] ) :
   iii1 = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( iii1 ) == 4 ) :
    iii1 = socket . ntohl ( struct . unpack ( "I" , iii1 ) [ 0 ] )
    oo000o += ", ports {} -> {}" . format ( iii1 >> 16 , iii1 & 0xffff )
    if 26 - 26: OOooOOo + Oo0Ooo
  elif ( oo0 == 1 ) :
   oo0iI1i11II1i1i = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( oo0iI1i11II1i1i ) == 2 ) :
    oo0iI1i11II1i1i = socket . ntohs ( struct . unpack ( "H" , oo0iI1i11II1i1i ) [ 0 ] )
    oo000o += ", icmp-seq {}" . format ( oo0iI1i11II1i1i )
    if 61 - 61: I11i * Ii1I + I11i - Oo0Ooo % OoOoOO00 . iII111i
    if 51 - 51: OOooOOo / I11i
  if ( self . packet_error != "" ) :
   oo000o += " ({})" . format ( self . packet_error )
   if 51 - 51: ooOoO0o * oO0o - I1Ii111 + iII111i
  oo000o += "\n"
  return ( oo000o )
  if 46 - 46: o0oOOo0O0Ooo - i11iIiiIii % OoO0O00 / Ii1I - OoOoOO00
  if 88 - 88: oO0o * I1IiiI / OoO0O00 - OOooOOo / i1IIi . I1Ii111
 def is_trace ( self ) :
  iii1 = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in iii1 )
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
  if 64 - 64: O0 % i1IIi * I1Ii111 - Ii1I + Oo0Ooo
  if 65 - 65: OoOoOO00 . i11iIiiIii
  if 36 - 36: oO0o * iII111i + IiII * iII111i . I1ii11iIi11i - iIii1I11I1II1
  if 14 - 14: I11i * oO0o + i11iIiiIii
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 84 - 84: iII111i / II111iiii
class lisp_data_header ( object ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 86 - 86: I1IiiI
  if 97 - 97: II111iiii
 def print_header ( self , e_or_d ) :
  iIiIii = lisp_hex_string ( self . first_long & 0xffffff )
  ii111I1IiiI1i = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 22 - 22: II111iiii / I1ii11iIi11i * IiII - o0oOOo0O0Ooo % I1ii11iIi11i
  IiiiI1 = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 70 - 70: II111iiii - IiII
  return ( IiiiI1 . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 iIiIii , ii111I1IiiI1i ) )
  if 76 - 76: I1Ii111
  if 43 - 43: O0 / I1Ii111 . iIii1I11I1II1 - OoOoOO00
 def encode ( self ) :
  iiII1iiI = "II"
  iIiIii = socket . htonl ( self . first_long )
  ii111I1IiiI1i = socket . htonl ( self . second_long )
  if 57 - 57: i11iIiiIii - I11i / ooOoO0o / o0oOOo0O0Ooo * i11iIiiIii * o0oOOo0O0Ooo
  IiIii1iIIII = struct . pack ( iiII1iiI , iIiIii , ii111I1IiiI1i )
  return ( IiIii1iIIII )
  if 92 - 92: IiII / iIii1I11I1II1
  if 43 - 43: ooOoO0o + OoooooooOO + iIii1I11I1II1 / OoooooooOO
 def decode ( self , packet ) :
  iiII1iiI = "II"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( False )
  if 58 - 58: iII111i % iIii1I11I1II1 . iIii1I11I1II1 / I11i
  iIiIii , ii111I1IiiI1i = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 79 - 79: OoO0O00 / OOooOOo - i1IIi + i1IIi - IiII + IiII
  if 67 - 67: OoO0O00 * OoO0O00 / OoooooooOO
  self . first_long = socket . ntohl ( iIiIii )
  self . second_long = socket . ntohl ( ii111I1IiiI1i )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 79 - 79: o0oOOo0O0Ooo % iIii1I11I1II1 / II111iiii / Ii1I / Ii1I + O0
  if 46 - 46: i1IIi / IiII
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 84 - 84: OoOoOO00 / iIii1I11I1II1 + oO0o % ooOoO0o + oO0o - iIii1I11I1II1
  if 27 - 27: O0 / o0oOOo0O0Ooo * I1IiiI
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 41 - 41: ooOoO0o
  if 11 - 11: i1IIi / I1Ii111 * I1ii11iIi11i * I1Ii111 * ooOoO0o - i11iIiiIii
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 96 - 96: I1ii11iIi11i % I1ii11iIi11i
  if 1 - 1: I1IiiI . Ii1I
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 26 - 26: oO0o - ooOoO0o % Oo0Ooo - oO0o + IiII
  if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 21 - 21: O0 * ooOoO0o % OoO0O00
  if 14 - 14: O0 / I1Ii111 / ooOoO0o + IiII - IiII
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 10 - 10: O0 - I1ii11iIi11i / I1Ii111 % OoOoOO00 / OoooooooOO / Ii1I
  if 73 - 73: ooOoO0o + IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . I1Ii111
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 76 - 76: I11i . I1ii11iIi11i * OoooooooOO % iII111i
  if 24 - 24: OoooooooOO
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 83 - 83: O0 / OoO0O00
  if 62 - 62: I11i
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 73 - 73: Ii1I % OoO0O00 * OOooOOo
  if 84 - 84: Oo0Ooo
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 18 - 18: OoooooooOO
  if 85 - 85: OoooooooOO . OoO0O00 . OoO0O00
  if 70 - 70: I11i
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
  if 72 - 72: I1Ii111 - ooOoO0o - I1IiiI - iII111i + OOooOOo - i1IIi
  if 45 - 45: OoO0O00 * I1IiiI
 def send_ipc ( self , ipc_socket , ipc ) :
  O0oo0OoO0oo = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  IIi11ii = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , O0oo0OoO0oo )
  lisp_ipc ( ipc , ipc_socket , IIi11ii )
  if 74 - 74: I1ii11iIi11i * oO0o + iII111i % O0
  if 18 - 18: i1IIi % IiII . O0 - O0 - O0 - II111iiii
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  OO = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , OO )
  if 84 - 84: Ii1I
  if 70 - 70: iIii1I11I1II1
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  OO = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , OO )
  if 45 - 45: O0 - OoOoOO00 % OOooOOo
  if 100 - 100: i11iIiiIii . OOooOOo . i11iIiiIii
 def receive_request ( self , ipc_socket , nonce ) :
  o00Oo = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( o00Oo != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 20 - 20: Ii1I . Oo0Ooo - I11i % I11i - I1IiiI * OOooOOo
  if 80 - 80: II111iiii / o0oOOo0O0Ooo . OOooOOo . o0oOOo0O0Ooo
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 29 - 29: OoooooooOO % II111iiii % i11iIiiIii - Oo0Ooo
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 5 - 5: I1ii11iIi11i . II111iiii . i1IIi
  if 35 - 35: o0oOOo0O0Ooo + OoO0O00 - I1ii11iIi11i
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 24 - 24: II111iiii
  if 23 - 23: Oo0Ooo - iII111i
  if 79 - 79: I11i . O0 - i1IIi
  if 42 - 42: oO0o - i11iIiiIii % oO0o - I1Ii111 * O0 / II111iiii
  if 5 - 5: Oo0Ooo
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   oOoOo0o0 = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 50 - 50: Oo0Ooo - o0oOOo0O0Ooo % II111iiii . O0 . oO0o % II111iiii
   if 18 - 18: I11i % OoooooooOO + OoO0O00 / I11i
   if ( remote_rloc . address > oOoOo0o0 . address ) :
    OO0O00o0 = "exit"
    self . request_nonce_sent = None
   else :
    OO0O00o0 = "stay in"
    self . echo_nonce_sent = None
    if 37 - 37: i1IIi - Ii1I / IiII . II111iiii % ooOoO0o
    if 39 - 39: Ii1I % i11iIiiIii * OoO0O00
   I1i11i = bold ( "collision" , False )
   oOO0O00o0O0 = red ( oOoOo0o0 . print_address_no_iid ( ) , False )
   iiiI1I = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( I1i11i ,
 oOO0O00o0O0 , iiiI1I , OO0O00o0 ) )
   if 92 - 92: Oo0Ooo % o0oOOo0O0Ooo - ooOoO0o / ooOoO0o / OoOoOO00
   if 84 - 84: OOooOOo
   if 4 - 4: IiII . I1Ii111 / Ii1I / iII111i + II111iiii
   if 32 - 32: i1IIi + iIii1I11I1II1 . I1ii11iIi11i . I11i - Ii1I
   if 55 - 55: I1ii11iIi11i / OoooooooOO - OoO0O00 / I1IiiI
  if ( self . echo_nonce_sent != None ) :
   o0Oo0o = self . echo_nonce_sent
   oO0ooOOO = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( oO0ooOOO ,
 lisp_hex_string ( o0Oo0o ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( o0Oo0o )
   if 23 - 23: I11i * I1Ii111 * o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + o0oOOo0O0Ooo
   if 41 - 41: IiII * OoooooooOO . ooOoO0o % i11iIiiIii
   if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
   if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
   if 8 - 8: o0oOOo0O0Ooo
   if 78 - 78: i1IIi - Oo0Ooo
   if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
  o0Oo0o = self . request_nonce_sent
  i11iII11I1III = self . last_request_nonce_sent
  if ( o0Oo0o and i11iII11I1III != None ) :
   if ( time . time ( ) - i11iII11I1III >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( o0Oo0o ) ) )
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
  if ( o0Oo0o == None ) :
   o0Oo0o = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( o0Oo0o )
   if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
   self . request_nonce_sent = o0Oo0o
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( o0Oo0o ) ) )
   if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
   if 65 - 65: I1ii11iIi11i / ooOoO0o
   if 23 - 23: OOooOOo / OOooOOo * o0oOOo0O0Ooo * OOooOOo
   if 57 - 57: iII111i
   if 29 - 29: I1IiiI
   if ( lisp_i_am_itr == False ) : return ( o0Oo0o | 0x80000000 )
   self . send_request_ipc ( ipc_socket , o0Oo0o )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( o0Oo0o ) ) )
   if 41 - 41: I1Ii111 * OoO0O00 - iII111i . Ii1I
   if 41 - 41: iIii1I11I1II1 - O0 - I1ii11iIi11i - oO0o + I1Ii111
   if 22 - 22: O0 % IiII % iII111i % I1IiiI
   if 34 - 34: iII111i . Oo0Ooo % I1ii11iIi11i . iII111i % IiII / IiII
   if 84 - 84: Ii1I
   if 1 - 1: oO0o - Oo0Ooo * iIii1I11I1II1 * Oo0Ooo * i1IIi
   if 9 - 9: iII111i - iII111i
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( o0Oo0o | 0x80000000 )
  if 3 - 3: O0 + O0 - O0 - O0 % OoooooooOO + oO0o
  if 20 - 20: OoO0O00 + I11i . II111iiii / i11iIiiIii
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 50 - 50: OoooooooOO / OoO0O00 % iIii1I11I1II1
  i1i111Iiiiiii = time . time ( ) - self . last_request_nonce_sent
  IIIIi11111 = self . last_echo_nonce_rcvd
  return ( i1i111Iiiiiii >= LISP_NONCE_ECHO_INTERVAL and IIIIi11111 == None )
  if 99 - 99: O0 * i11iIiiIii % OOooOOo * II111iiii
  if 98 - 98: O0 + iIii1I11I1II1
 def recently_requested ( self ) :
  IIIIi11111 = self . last_request_nonce_sent
  if ( IIIIi11111 == None ) : return ( False )
  if 94 - 94: i1IIi * OoO0O00 * OoOoOO00
  i1i111Iiiiiii = time . time ( ) - IIIIi11111
  return ( i1i111Iiiiiii <= LISP_NONCE_ECHO_INTERVAL )
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
  i1i111Iiiiiii = time . time ( ) - IIIIi11111
  if ( i1i111Iiiiiii <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 83 - 83: OoooooooOO
  if 52 - 52: o0oOOo0O0Ooo / OoOoOO00 % oO0o % OoO0O00 / IiII % o0oOOo0O0Ooo
  if 88 - 88: OOooOOo / i11iIiiIii / Ii1I / i11iIiiIii * I1ii11iIi11i % I11i
  if 43 - 43: OoOoOO00 * OoO0O00 % i1IIi * Ii1I + iIii1I11I1II1
  if 80 - 80: o0oOOo0O0Ooo . iII111i . OoooooooOO
  if 63 - 63: ooOoO0o . OOooOOo
  IIIIi11111 = self . last_new_request_nonce_sent
  if ( IIIIi11111 == None ) : IIIIi11111 = 0
  i1i111Iiiiiii = time . time ( ) - IIIIi11111
  return ( i1i111Iiiiiii <= LISP_NONCE_ECHO_INTERVAL )
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
  I111 = space ( 4 )
  if 56 - 56: I1IiiI
  oOo0OOoooO = "Nonce-Echoing:\n"
  oOo0OOoooO += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( I111 , oOOO , I111 , Iii111111 )
  if 49 - 49: i1IIi % oO0o / OOooOOo . I1ii11iIi11i - I1Ii111
  oOo0OOoooO += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( I111 , IiII11 , I111 , oO0o0o0OO0o00 )
  if 12 - 12: i11iIiiIii + I11i - I1ii11iIi11i
  if 27 - 27: iII111i
  return ( oOo0OOoooO )
  if 22 - 22: OoOoOO00 / I1IiiI
  if 33 - 33: I11i
  if 37 - 37: OoOoOO00 % o0oOOo0O0Ooo * OoO0O00 / i11iIiiIii * II111iiii * iII111i
  if 70 - 70: ooOoO0o . i11iIiiIii % OoOoOO00 + oO0o
  if 95 - 95: I1ii11iIi11i
  if 48 - 48: I11i
  if 14 - 14: iIii1I11I1II1 / o0oOOo0O0Ooo * IiII
  if 35 - 35: iIii1I11I1II1
  if 34 - 34: OoO0O00 % I1IiiI . o0oOOo0O0Ooo % OoO0O00 % OoO0O00
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
    if 30 - 30: I1IiiI + I1IiiI
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   III = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( III . encode ( ) )
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
  if ( isinstance ( key , int ) ) : key = self . normalize_pub_key ( key )
  return ( old_div ( len ( key ) , 2 ) )
  if 9 - 9: OoooooooOO / I11i
  if 47 - 47: OoooooooOO
 def print_key ( self , key ) :
  o00oOOo0Oo = self . normalize_pub_key ( key )
  II1 = o00oOOo0Oo [ 0 : 4 ] . decode ( )
  o0OOO = o00oOOo0Oo [ - 4 : : ] . decode ( )
  return ( "0x{}...{}({})" . format ( II1 , o0OOO , self . key_length ( o00oOOo0Oo ) ) )
  if 38 - 38: I1IiiI * o0oOOo0O0Ooo - OOooOOo % IiII + I11i - Oo0Ooo
  if 55 - 55: iIii1I11I1II1 + OoOoOO00
 def normalize_pub_key ( self , key ) :
  if ( isinstance ( key , int ) ) :
   key = lisp_hex_string ( key ) . zfill ( 256 )
   return ( key )
   if 7 - 7: Ii1I / I1Ii111 % ooOoO0o - I1Ii111 * I1IiiI
  if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
  return ( key )
  if 18 - 18: oO0o - IiII % I11i * Ii1I
  if 66 - 66: i1IIi - i1IIi - OOooOOo . I11i
 def print_keys ( self , do_bold = True ) :
  oOO0O00o0O0 = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   oOO0O00o0O0 += "none"
  else :
   oOO0O00o0O0 += self . print_key ( self . local_public_key )
   if 25 - 25: i1IIi * I1IiiI - OoOoOO00 + oO0o
  iiiI1I = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   iiiI1I += "none"
  else :
   iiiI1I += self . print_key ( self . remote_public_key )
   if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
  i1Iiiiii1II = "ECDH" if ( self . curve25519 ) else "DH"
  i1iII1i = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( i1Iiiiii1II , i1iII1i , oOO0O00o0O0 , iiiI1I ) )
  if 15 - 15: O0 % Oo0Ooo % IiII % OoooooooOO - IiII
  if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 22 - 22: Oo0Ooo % OoooooooOO - Oo0Ooo - iII111i . Ii1I
  if 100 - 100: II111iiii / I1Ii111 / iII111i - I1ii11iIi11i * iIii1I11I1II1
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 7 - 7: i1IIi . IiII % i11iIiiIii * I1ii11iIi11i . I11i % I1ii11iIi11i
  III = self . local_private_key
  Oo = self . dh_g_value
  iIIiiIi = self . dh_p_value
  return ( int ( ( Oo ** III ) % iIIiiIi ) )
  if 35 - 35: I1IiiI
  if 48 - 48: OoooooooOO % OoooooooOO - OoO0O00 . OoOoOO00
 def compute_shared_key ( self , ed , print_shared = False ) :
  III = self . local_private_key
  I1i = self . remote_public_key
  if 5 - 5: OoooooooOO
  i1IIIiI1ii = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( i1IIIiI1ii , self . print_keys ( ) ) )
  if 41 - 41: OoooooooOO
  if ( self . curve25519 ) :
   I1I111i = curve25519 . Public ( I1i )
   self . shared_key = self . curve25519 . get_shared_key ( I1I111i )
  else :
   iIIiiIi = self . dh_p_value
   self . shared_key = ( I1i ** III ) % iIIiiIi
   if 63 - 63: I1ii11iIi11i . I1IiiI + OOooOOo - IiII + iII111i
   if 78 - 78: Ii1I
   if 29 - 29: II111iiii
   if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
   if 84 - 84: Oo0Ooo % I11i * O0 * I11i
   if 66 - 66: OOooOOo / iIii1I11I1II1 - OoOoOO00 % O0 . ooOoO0o
   if 12 - 12: Oo0Ooo + I1IiiI
  if ( print_shared ) :
   o00oOOo0Oo = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( o00oOOo0Oo ) )
   if 37 - 37: i1IIi * i11iIiiIii
   if 95 - 95: i11iIiiIii % I1Ii111 * Oo0Ooo + i1IIi . O0 + I1ii11iIi11i
   if 7 - 7: OoO0O00 * i11iIiiIii * iIii1I11I1II1 / OOooOOo / I1Ii111
   if 35 - 35: iII111i * OOooOOo
   if 65 - 65: II111iiii % i1IIi
  self . compute_encrypt_icv_keys ( )
  if 13 - 13: OoO0O00 * I1Ii111 + Oo0Ooo - IiII
  if 31 - 31: OoO0O00
  if 68 - 68: OoO0O00 + i1IIi / iIii1I11I1II1 + II111iiii * iIii1I11I1II1 + I1ii11iIi11i
  if 77 - 77: i11iIiiIii - I1Ii111 . I1ii11iIi11i % Oo0Ooo . Ii1I
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 9 - 9: o0oOOo0O0Ooo
  if 55 - 55: OOooOOo % iIii1I11I1II1 + I11i . ooOoO0o
 def compute_encrypt_icv_keys ( self ) :
  ooOo = hashlib . sha256
  if ( self . curve25519 ) :
   iiooo0o0oO = self . shared_key
  else :
   iiooo0o0oO = lisp_hex_string ( self . shared_key )
   if 19 - 19: Oo0Ooo - OoO0O00 + i11iIiiIii / iIii1I11I1II1
   if 1 - 1: IiII % i1IIi
   if 41 - 41: OoO0O00 * OoO0O00 / iII111i + I1ii11iIi11i . o0oOOo0O0Ooo
   if 84 - 84: i11iIiiIii + OoO0O00 * I1IiiI + I1ii11iIi11i / Ii1I
   if 80 - 80: I1ii11iIi11i
  oOO0O00o0O0 = self . local_public_key
  if ( type ( oOO0O00o0O0 ) != int ) : oOO0O00o0O0 = int ( binascii . hexlify ( oOO0O00o0O0 ) , 16 )
  iiiI1I = self . remote_public_key
  if ( type ( iiiI1I ) != int ) : iiiI1I = int ( binascii . hexlify ( iiiI1I ) , 16 )
  ooOOO = "0001" + "lisp-crypto" + lisp_hex_string ( oOO0O00o0O0 ^ iiiI1I ) + "0100"
  if 95 - 95: I11i
  Oooo0o0oOO000O = hmac . new ( ooOOO . encode ( ) , iiooo0o0oO , ooOo ) . hexdigest ( )
  Oooo0o0oOO000O = int ( Oooo0o0oOO000O , 16 )
  if 61 - 61: oO0o - I1ii11iIi11i / iII111i % I1ii11iIi11i + OoO0O00 / Oo0Ooo
  if 10 - 10: i11iIiiIii / OoOoOO00
  if 27 - 27: I1IiiI / OoooooooOO
  if 74 - 74: I1ii11iIi11i % I1Ii111 - OoO0O00 * I11i . OoooooooOO * OoO0O00
  OOOooooOo0 = ( Oooo0o0oOO000O >> 128 ) & LISP_16_128_MASK
  o000o00OO00Oo = Oooo0o0oOO000O & LISP_16_128_MASK
  OOOooooOo0 = lisp_hex_string ( OOOooooOo0 ) . zfill ( 32 )
  self . encrypt_key = OOOooooOo0 . encode ( )
  I1II11I11111i = 32 if self . do_poly else 40
  o000o00OO00Oo = lisp_hex_string ( o000o00OO00Oo ) . zfill ( I1II11I11111i )
  self . icv_key = o000o00OO00Oo . encode ( )
  if 14 - 14: IiII + o0oOOo0O0Ooo + I1ii11iIi11i * o0oOOo0O0Ooo + OoO0O00
  if 2 - 2: II111iiii % i11iIiiIii
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   i11 = self . icv . poly1305aes
   iiIii11I1 = self . icv . binascii . hexlify
   nonce = iiIii11I1 ( nonce )
   oo0O000OooO0 = i11 ( self . encrypt_key , self . icv_key , nonce , packet )
   if ( lisp_is_python2 ( ) ) :
    oo0O000OooO0 = iiIii11I1 ( oo0O000OooO0 . encode ( "raw_unicode_escape" ) )
   else :
    oo0O000OooO0 = iiIii11I1 ( oo0O000OooO0 ) . decode ( )
    if 26 - 26: OoO0O00 % i11iIiiIii + oO0o * II111iiii / IiII
  else :
   III = binascii . unhexlify ( self . icv_key )
   oo0O000OooO0 = hmac . new ( III , packet , self . icv ) . hexdigest ( )
   oo0O000OooO0 = oo0O000OooO0 [ 0 : 40 ]
   if 70 - 70: Oo0Ooo / I1Ii111 . IiII - OOooOOo
  return ( oo0O000OooO0 )
  if 65 - 65: IiII - I1Ii111
  if 71 - 71: Oo0Ooo - i1IIi
 def add_key_by_nonce ( self , nonce ) :
  if ( nonce not in lisp_crypto_keys_by_nonce ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 27 - 27: OoOoOO00 . O0 / I1ii11iIi11i . iIii1I11I1II1
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 15 - 15: Ii1I + OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
  if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
 def delete_key_by_nonce ( self , nonce ) :
  if ( nonce not in lisp_crypto_keys_by_nonce ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
  if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
 def add_key_by_rloc ( self , addr_str , encap ) :
  O0ooOo = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 34 - 34: OoooooooOO . II111iiii * iIii1I11I1II1 / O0 . I1IiiI
  if 4 - 4: i11iIiiIii / I1ii11iIi11i
  if ( addr_str not in O0ooOo ) :
   O0ooOo [ addr_str ] = [ None , None , None , None ]
   if 41 - 41: Ii1I
  O0ooOo [ addr_str ] [ self . key_id ] = self
  if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
  if 47 - 47: O0 . o0oOOo0O0Ooo / Ii1I * iII111i
  if 63 - 63: I1Ii111 - oO0o - iII111i - ooOoO0o / oO0o + OoO0O00
  if 94 - 94: IiII / I1IiiI . II111iiii
  if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , O0ooOo [ addr_str ] )
   if 37 - 37: OOooOOo + O0 + OOooOOo . iII111i . o0oOOo0O0Ooo
   if 78 - 78: I1IiiI / I11i + o0oOOo0O0Ooo . Oo0Ooo / O0
   if 49 - 49: I1ii11iIi11i
 def encode_lcaf ( self , rloc_addr ) :
  oOO = self . normalize_pub_key ( self . local_public_key )
  iI111I = self . key_length ( oOO )
  i1iiII1I1I1ii = ( 6 + iI111I + 2 )
  if ( rloc_addr != None ) : i1iiII1I1I1ii += rloc_addr . addr_length ( )
  if 23 - 23: i11iIiiIii % IiII . Ii1I + Ii1I * IiII
  Oo00oo = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( i1iiII1I1I1ii ) , 1 , 0 )
  if 19 - 19: O0 % I1IiiI + oO0o
  if 23 - 23: OOooOOo
  if 68 - 68: OoooooooOO
  if 18 - 18: Ii1I * OoO0O00
  if 89 - 89: OoO0O00 + oO0o % iIii1I11I1II1 + I11i / O0
  if 38 - 38: ooOoO0o - o0oOOo0O0Ooo - O0 + ooOoO0o % OoOoOO00 . o0oOOo0O0Ooo
  i1iII1i = self . cipher_suite
  Oo00oo += struct . pack ( "BBH" , i1iII1i , 0 , socket . htons ( iI111I ) )
  if 40 - 40: iIii1I11I1II1 * OoooooooOO * I1Ii111 - Ii1I + i11iIiiIii
  if 81 - 81: OoO0O00 * OoooooooOO / iII111i
  if 8 - 8: O0 * i1IIi - OoOoOO00 % I1IiiI / I1ii11iIi11i
  if 39 - 39: I1ii11iIi11i . oO0o * II111iiii + I1IiiI - iIii1I11I1II1
  for iIi1iIIIiIiI in range ( 0 , iI111I * 2 , 16 ) :
   III = int ( oOO [ iIi1iIIIiIiI : iIi1iIIIiIiI + 16 ] , 16 )
   Oo00oo += struct . pack ( "Q" , byte_swap_64 ( III ) )
   if 56 - 56: IiII - Ii1I + i11iIiiIii * OoO0O00 % I1IiiI
   if 37 - 37: iIii1I11I1II1 + IiII / I1Ii111 . OoooooooOO
   if 72 - 72: oO0o % ooOoO0o % OOooOOo
   if 63 - 63: OoO0O00 . Ii1I % II111iiii / I11i - OoOoOO00
   if 4 - 4: Oo0Ooo - O0 / I11i + O0 - oO0o * Oo0Ooo
  if ( rloc_addr ) :
   Oo00oo += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   Oo00oo += rloc_addr . pack_address ( )
   if 25 - 25: I1IiiI
  return ( Oo00oo )
  if 64 - 64: oO0o
  if 80 - 80: o0oOOo0O0Ooo % iIii1I11I1II1
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 63 - 63: IiII * i11iIiiIii
  if 86 - 86: I11i % I11i - OoOoOO00 + I1Ii111 / I1IiiI * OoooooooOO
  if 26 - 26: II111iiii * iII111i + o0oOOo0O0Ooo / O0 + i1IIi - I11i
  if 56 - 56: OOooOOo
  if ( lcaf_len == 0 ) :
   iiII1iiI = "HHBBH"
   ooo0000oo0 = struct . calcsize ( iiII1iiI )
   if ( len ( packet ) < ooo0000oo0 ) : return ( None )
   if 76 - 76: i1IIi % iIii1I11I1II1 - o0oOOo0O0Ooo + IiII - I11i
   i1I1iiiI , OOOo00o , ooOoOoOo , OOOo00o , lcaf_len = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
   if 9 - 9: I11i - II111iiii + I1Ii111 / oO0o % I1ii11iIi11i
   if 17 - 17: iIii1I11I1II1 - ooOoO0o
   if ( ooOoOoOo != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ ooo0000oo0 : : ]
   if 52 - 52: I1ii11iIi11i
   if 93 - 93: iII111i . i11iIiiIii
   if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
   if 49 - 49: O0 . Oo0Ooo / Ii1I
   if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
   if 86 - 86: I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
  ooOoOoOo = LISP_LCAF_SECURITY_TYPE
  iiII1iiI = "BBBBH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 20 - 20: iII111i . OoooooooOO + iII111i + ooOoO0o * I1ii11iIi11i
  i1IIiiI1iii1 , OOOo00o , i1iII1i , OOOo00o , iI111I = struct . unpack ( iiII1iiI ,
 packet [ : ooo0000oo0 ] )
  if 100 - 100: iII111i / o0oOOo0O0Ooo
  if 11 - 11: I1ii11iIi11i * OoOoOO00 % i11iIiiIii - Ii1I
  if 77 - 77: II111iiii - o0oOOo0O0Ooo . I1ii11iIi11i
  if 63 - 63: oO0o
  if 79 - 79: I1ii11iIi11i - oO0o - o0oOOo0O0Ooo . OOooOOo
  if 65 - 65: i11iIiiIii . OoO0O00 % iII111i + IiII - i11iIiiIii
  packet = packet [ ooo0000oo0 : : ]
  iI111I = socket . ntohs ( iI111I )
  if ( len ( packet ) < iI111I ) : return ( None )
  if 60 - 60: I1Ii111
  if 14 - 14: Oo0Ooo % oO0o * iII111i - i11iIiiIii / I1ii11iIi11i * i11iIiiIii
  if 95 - 95: iIii1I11I1II1 + OoOoOO00 . I1IiiI + OoOoOO00 * I11i + OOooOOo
  if 14 - 14: Ii1I - O0
  OoOO0Ooo = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( i1iII1i not in OoOO0Ooo ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( OoOO0Ooo ,
 i1iII1i ) )
   packet = packet [ iI111I : : ]
   return ( packet )
   if 95 - 95: OoO0O00 - IiII % I1Ii111
   if 27 - 27: iIii1I11I1II1 / I1IiiI % OoOoOO00 / I1IiiI * Ii1I
  self . cipher_suite = i1iII1i
  if 13 - 13: iII111i . iII111i + i11iIiiIii % O0 % I1Ii111 + IiII
  if 42 - 42: i1IIi + iII111i . OoooooooOO + I1ii11iIi11i . I11i / Ii1I
  if 1 - 1: o0oOOo0O0Ooo
  if 95 - 95: OOooOOo / i1IIi % OoO0O00 . I1Ii111 + I1Ii111
  if 80 - 80: O0 + I1ii11iIi11i + OOooOOo
  oOO = 0
  for iIi1iIIIiIiI in range ( 0 , iI111I , 8 ) :
   III = byte_swap_64 ( struct . unpack ( "Q" , packet [ iIi1iIIIiIiI : iIi1iIIIiIiI + 8 ] ) [ 0 ] )
   oOO <<= 64
   oOO |= III
   if 95 - 95: I1ii11iIi11i
  self . remote_public_key = oOO
  if 98 - 98: IiII * iII111i . OoooooooOO . O0
  if 89 - 89: iII111i / O0 % OoooooooOO - O0 . OoO0O00
  if 32 - 32: ooOoO0o
  if 26 - 26: O0 * Ii1I - I1IiiI - iII111i / iIii1I11I1II1
  if 57 - 57: I1ii11iIi11i - OoO0O00 * iIii1I11I1II1
  if ( self . curve25519 ) :
   III = lisp_hex_string ( self . remote_public_key )
   III = III . zfill ( 64 )
   II111IiI11i = b""
   for iIi1iIIIiIiI in range ( 0 , len ( III ) , 2 ) :
    OoiIiiIi11 = int ( III [ iIi1iIIIiIiI : iIi1iIIIiIiI + 2 ] , 16 )
    II111IiI11i += lisp_store_byte ( OoiIiiIi11 )
    if 73 - 73: IiII - IiII / OoooooooOO
   self . remote_public_key = II111IiI11i
   if 53 - 53: o0oOOo0O0Ooo / OoO0O00 . OoooooooOO
   if 55 - 55: IiII * o0oOOo0O0Ooo * ooOoO0o - i1IIi / Ii1I * oO0o
  packet = packet [ iI111I : : ]
  return ( packet )
  if 85 - 85: i11iIiiIii . OoO0O00 + OoO0O00
  if 28 - 28: Oo0Ooo
  if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
  if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
  if 61 - 61: O0 . Ii1I . O0 * i11iIiiIii * II111iiii / I1Ii111
  if 69 - 69: I11i
  if 17 - 17: I11i
  if 38 - 38: I1Ii111 % OOooOOo
  if 9 - 9: O0 . iIii1I11I1II1
def lisp_store_byte_py2 ( byte ) :
 return ( chr ( byte ) )
 if 44 - 44: I1ii11iIi11i % IiII
def lisp_store_byte_py3 ( byte ) :
 return ( bytes ( [ byte ] ) )
 if 6 - 6: OoO0O00
 if 82 - 82: iIii1I11I1II1 . I11i / IiII / OOooOOo * II111iiii % oO0o
lisp_store_byte = lisp_store_byte_py2
if ( lisp_is_python3 ( ) ) : lisp_store_byte = lisp_store_byte_py3
if 62 - 62: II111iiii
if 96 - 96: I11i % OoOoOO00 * I1ii11iIi11i
if 94 - 94: Oo0Ooo - i1IIi . O0 % Oo0Ooo . ooOoO0o
if 63 - 63: i11iIiiIii % I1ii11iIi11i % I1IiiI . IiII * o0oOOo0O0Ooo + OOooOOo
if 77 - 77: o0oOOo0O0Ooo
if 63 - 63: ooOoO0o * oO0o + ooOoO0o * Ii1I + Oo0Ooo / I1ii11iIi11i
class lisp_thread ( object ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
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
  if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
  if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
 def decode ( self , packet ) :
  iiII1iiI = "BBBBQ"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( False )
  if 61 - 61: Oo0Ooo - I1Ii111
  O0o0oooOo0oo , OO0oOooo , ii1I , self . record_count , self . nonce = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 11 - 11: Oo0Ooo * OoooooooOO - i11iIiiIii
  if 13 - 13: i11iIiiIii . O0 / OOooOOo * i1IIi
  self . type = O0o0oooOo0oo >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( O0o0oooOo0oo & 0x01 ) else False
   self . rloc_probe = True if ( O0o0oooOo0oo & 0x02 ) else False
   self . smr_invoked_bit = True if ( OO0oOooo & 0x40 ) else False
   if 14 - 14: IiII + IiII . I11i / Ii1I . iIii1I11I1II1
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( O0o0oooOo0oo & 0x04 ) else False
   self . to_etr = True if ( O0o0oooOo0oo & 0x02 ) else False
   self . to_ms = True if ( O0o0oooOo0oo & 0x01 ) else False
   if 10 - 10: II111iiii . OOooOOo / iII111i
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( O0o0oooOo0oo & 0x08 ) else False
   if 35 - 35: iII111i / Oo0Ooo + O0 * iIii1I11I1II1 - O0
  return ( True )
  if 3 - 3: I1ii11iIi11i
  if 42 - 42: I11i % Oo0Ooo + IiII - I11i . iIii1I11I1II1 - Ii1I
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 27 - 27: iII111i % Oo0Ooo . I1ii11iIi11i . i1IIi % OoOoOO00 . o0oOOo0O0Ooo
  if 37 - 37: iII111i + I1Ii111 * Ii1I + IiII
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 39 - 39: O0 * Oo0Ooo - I1IiiI + Ii1I / II111iiii
  if 66 - 66: ooOoO0o + oO0o % OoooooooOO
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 23 - 23: oO0o . OoOoOO00 + iIii1I11I1II1
  if 17 - 17: IiII
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 12 - 12: i1IIi . OoO0O00
  if 14 - 14: OOooOOo + II111iiii % OOooOOo . oO0o * ooOoO0o
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 54 - 54: ooOoO0o * I11i - I1Ii111
  if 15 - 15: iII111i / O0
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 61 - 61: i1IIi / i1IIi + ooOoO0o . I1Ii111 * ooOoO0o
  if 19 - 19: o0oOOo0O0Ooo . II111iiii / i1IIi
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 82 - 82: O0 / iII111i * OoO0O00 - I11i + Oo0Ooo
  if 47 - 47: I1ii11iIi11i * I1IiiI / I1ii11iIi11i + Ii1I * II111iiii
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
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
  if 64 - 64: i11iIiiIii . iIii1I11I1II1
  if 7 - 7: OoOoOO00 % ooOoO0o + OoOoOO00 - OoOoOO00 * i11iIiiIii % OoO0O00
 def print_map_register ( self ) :
  oOOOOOo0OO0o0oOO0 = lisp_hex_string ( self . xtr_id )
  if 48 - 48: I11i
  IiiiI1 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 98 - 98: ooOoO0o - iIii1I11I1II1 + OOooOOo - iIii1I11I1II1
  lprint ( IiiiI1 . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # i1IIi / I1ii11iIi11i % OoooooooOO % OoooooooOO + OoooooooOO
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , oOOOOOo0OO0o0oOO0 , self . site_id ) )
  if 42 - 42: ooOoO0o / IiII
  if 62 - 62: I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + I1IiiI / II111iiii
  if 91 - 91: I1IiiI % O0 / oO0o * I1Ii111 + Ii1I - i1IIi
  if 71 - 71: OoOoOO00 / IiII / II111iiii * OOooOOo - I1ii11iIi11i - iIii1I11I1II1
 def encode ( self ) :
  iIiIii = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : iIiIii |= 0x08000000
  if ( self . lisp_sec_present ) : iIiIii |= 0x04000000
  if ( self . xtr_id_present ) : iIiIii |= 0x02000000
  if ( self . map_register_refresh ) : iIiIii |= 0x1000
  if ( self . use_ttl_for_timeout ) : iIiIii |= 0x800
  if ( self . merge_register_requested ) : iIiIii |= 0x400
  if ( self . mobile_node ) : iIiIii |= 0x200
  if ( self . map_notify_requested ) : iIiIii |= 0x100
  if ( self . encryption_key_id != None ) :
   iIiIii |= 0x2000
   iIiIii |= self . encryption_key_id << 14
   if 5 - 5: oO0o + OoOoOO00
   if 94 - 94: o0oOOo0O0Ooo % o0oOOo0O0Ooo % II111iiii * iIii1I11I1II1 / IiII . I1ii11iIi11i
   if 13 - 13: OoOoOO00 . I1IiiI . o0oOOo0O0Ooo * oO0o / Ii1I
   if 38 - 38: IiII - i1IIi . i11iIiiIii
   if 28 - 28: I1Ii111 / oO0o . I1ii11iIi11i
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 83 - 83: I11i
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 36 - 36: iIii1I11I1II1
    if 74 - 74: IiII * I1ii11iIi11i - OoooooooOO
    if 59 - 59: ooOoO0o * OoO0O00 - I1Ii111 % oO0o
  Oo00oo = struct . pack ( "I" , socket . htonl ( iIiIii ) )
  Oo00oo += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 95 - 95: II111iiii + II111iiii
  Oo00oo = self . zero_auth ( Oo00oo )
  return ( Oo00oo )
  if 33 - 33: i1IIi . Oo0Ooo - IiII
  if 30 - 30: OoooooooOO % OOooOOo
 def zero_auth ( self , packet ) :
  oo00 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  IIiI = b""
  oOOOO00o00 = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   IIiI = struct . pack ( "QQI" , 0 , 0 , 0 )
   oOOOO00o00 = struct . calcsize ( "QQI" )
   if 66 - 66: I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   IIiI = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   oOOOO00o00 = struct . calcsize ( "QQQQ" )
   if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
  packet = packet [ 0 : oo00 ] + IIiI + packet [ oo00 + oOOOO00o00 : : ]
  return ( packet )
  if 82 - 82: Oo0Ooo / Ii1I / Ii1I % Ii1I
  if 20 - 20: ooOoO0o
 def encode_auth ( self , packet ) :
  oo00 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  oOOOO00o00 = self . auth_len
  IIiI = self . auth_data
  packet = packet [ 0 : oo00 ] + IIiI + packet [ oo00 + oOOOO00o00 : : ]
  return ( packet )
  if 63 - 63: iIii1I11I1II1 . OoO0O00
  if 100 - 100: i1IIi * i1IIi
 def decode ( self , packet ) :
  i1o0o0oOO = packet
  iiII1iiI = "I"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( [ None , None ] )
  if 76 - 76: O0 * II111iiii
  iIiIii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  iIiIii = socket . ntohl ( iIiIii [ 0 ] )
  packet = packet [ ooo0000oo0 : : ]
  if 38 - 38: I1Ii111
  iiII1iiI = "QBBH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( [ None , None ] )
  if 18 - 18: Ii1I - iII111i
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 18 - 18: II111iiii
  if 92 - 92: o0oOOo0O0Ooo . I1Ii111 + iII111i % I1Ii111 % i11iIiiIii
  self . nonce = byte_swap_64 ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( iIiIii & 0x08000000 ) else False
  if 46 - 46: OoooooooOO
  self . lisp_sec_present = True if ( iIiIii & 0x04000000 ) else False
  self . xtr_id_present = True if ( iIiIii & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( iIiIii & 0x800 ) else False
  self . map_register_refresh = True if ( iIiIii & 0x1000 ) else False
  self . merge_register_requested = True if ( iIiIii & 0x400 ) else False
  self . mobile_node = True if ( iIiIii & 0x200 ) else False
  self . map_notify_requested = True if ( iIiIii & 0x100 ) else False
  self . record_count = iIiIii & 0xff
  if 80 - 80: O0 * iII111i
  if 73 - 73: IiII / Ii1I + I1Ii111 . OOooOOo - II111iiii / iIii1I11I1II1
  if 79 - 79: I1Ii111 * Oo0Ooo . o0oOOo0O0Ooo - I1Ii111
  if 16 - 16: I1IiiI - O0 * I1ii11iIi11i . I1ii11iIi11i % OOooOOo
  self . encrypt_bit = True if iIiIii & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( iIiIii >> 14 ) & 0x7
   if 39 - 39: II111iiii / I11i - OoOoOO00 * OoOoOO00 - Ii1I
   if 8 - 8: O0 . i11iIiiIii
   if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
   if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
   if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( i1o0o0oOO ) == False ) : return ( [ None , None ] )
   if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
   if 69 - 69: Oo0Ooo * ooOoO0o
  packet = packet [ ooo0000oo0 : : ]
  if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
  if 52 - 52: I1IiiI - i11iIiiIii / IiII . oO0o
  if 38 - 38: oO0o + OoooooooOO * OoOoOO00 % oO0o
  if 91 - 91: i1IIi - I1ii11iIi11i * I1IiiI
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 24 - 24: OoOoOO00 * Ii1I
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 17 - 17: OoO0O00 . I1IiiI * O0
    if 81 - 81: OOooOOo
   oOOOO00o00 = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    ooo0000oo0 = struct . calcsize ( "QQI" )
    if ( oOOOO00o00 < ooo0000oo0 ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 58 - 58: II111iiii . I1Ii111 . Ii1I * OoooooooOO / Ii1I / I11i
    i1iI11I , oOoOOO , iI1i11i1i1i = struct . unpack ( "QQI" , packet [ : oOOOO00o00 ] )
    OoO00O = b""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    ooo0000oo0 = struct . calcsize ( "QQQQ" )
    if ( oOOOO00o00 < ooo0000oo0 ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 87 - 87: ooOoO0o - i11iIiiIii / iIii1I11I1II1 % I1IiiI
    i1iI11I , oOoOOO , iI1i11i1i1i , OoO00O = struct . unpack ( "QQQQ" ,
 packet [ : oOOOO00o00 ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 56 - 56: I1IiiI
    return ( [ None , None ] )
    if 31 - 31: iII111i
   self . auth_data = lisp_concat_auth_data ( self . alg_id , i1iI11I , oOoOOO ,
 iI1i11i1i1i , OoO00O )
   i1o0o0oOO = self . zero_auth ( i1o0o0oOO )
   packet = packet [ self . auth_len : : ]
   if 1 - 1: I1Ii111 / OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % Ii1I
  return ( [ i1o0o0oOO , packet ] )
  if 96 - 96: IiII / Ii1I % OoO0O00 . iIii1I11I1II1
  if 30 - 30: I11i - OoO0O00
 def encode_xtr_id ( self , packet ) :
  iiii = self . xtr_id >> 64
  Oo000O00o0O = self . xtr_id & 0xffffffffffffffff
  iiii = byte_swap_64 ( iiii )
  Oo000O00o0O = byte_swap_64 ( Oo000O00o0O )
  o0o0oo0oO = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , iiii , Oo000O00o0O , o0o0oo0oO )
  return ( packet )
  if 6 - 6: i11iIiiIii + OoooooooOO % i11iIiiIii . I11i * OoooooooOO - Oo0Ooo
  if 88 - 88: oO0o
 def decode_xtr_id ( self , packet ) :
  ooo0000oo0 = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < ooo0000oo0 ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - ooo0000oo0 : : ]
  iiii , Oo000O00o0O , o0o0oo0oO = struct . unpack ( "QQQ" ,
 packet [ : ooo0000oo0 ] )
  iiii = byte_swap_64 ( iiii )
  Oo000O00o0O = byte_swap_64 ( Oo000O00o0O )
  self . xtr_id = ( iiii << 64 ) | Oo000O00o0O
  self . site_id = byte_swap_64 ( o0o0oo0oO )
  return ( True )
  if 33 - 33: o0oOOo0O0Ooo / i1IIi
  if 71 - 71: OoooooooOO - iII111i + Ii1I / O0 % o0oOOo0O0Ooo + OoO0O00
  if 83 - 83: IiII * I1ii11iIi11i / IiII * IiII - OOooOOo
  if 89 - 89: OoO0O00 % I11i
  if 51 - 51: ooOoO0o * Ii1I * OoooooooOO % OoOoOO00
  if 25 - 25: iIii1I11I1II1 * OoooooooOO * Ii1I - i1IIi
  if 23 - 23: o0oOOo0O0Ooo . ooOoO0o - OoooooooOO + I11i
  if 73 - 73: OoOoOO00
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
  if 43 - 43: i1IIi . I1IiiI * iIii1I11I1II1 * i11iIiiIii - OOooOOo + ooOoO0o
  if 56 - 56: Oo0Ooo % i11iIiiIii / Ii1I . I1Ii111 . OoO0O00 - OoOoOO00
 def print_notify ( self ) :
  IIiI = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( IIiI ) != 40 ) :
   IIiI = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( IIiI ) != 64 ) :
   IIiI = self . auth_data
   if 32 - 32: I1Ii111 / oO0o / I1IiiI
  IiiiI1 = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( IiiiI1 . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # OOooOOo - OoO0O00
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , IIiI ) )
  if 3 - 3: Oo0Ooo + OOooOOo - I1IiiI
  if 60 - 60: O0 / i1IIi % i11iIiiIii / iII111i
  if 97 - 97: i1IIi % OoooooooOO
  if 83 - 83: I11i . OOooOOo + I1Ii111 * I11i . I1Ii111 + oO0o
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   IIiI = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 64 - 64: Ii1I . o0oOOo0O0Ooo - i1IIi
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   IIiI = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 35 - 35: I1ii11iIi11i % OoooooooOO
  packet += IIiI
  return ( packet )
  if 59 - 59: I1IiiI % I11i
  if 32 - 32: I1IiiI * O0 + O0
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   iIiIii = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   iIiIii = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 34 - 34: IiII
  Oo00oo = struct . pack ( "I" , socket . htonl ( iIiIii ) )
  Oo00oo += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 5 - 5: OoO0O00 . I1IiiI
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = Oo00oo + eid_records
   return ( self . packet )
   if 48 - 48: Oo0Ooo - OoO0O00 . I11i - iIii1I11I1II1 % Ii1I
   if 47 - 47: iII111i / OoooooooOO - II111iiii
   if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
   if 23 - 23: i1IIi
   if 9 - 9: i1IIi % I1Ii111 - OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo
  Oo00oo = self . zero_auth ( Oo00oo )
  Oo00oo += eid_records
  if 18 - 18: Ii1I . OoOoOO00 + iII111i . I1IiiI + OoooooooOO . OoO0O00
  II1Iii1iI = lisp_hash_me ( Oo00oo , self . alg_id , password , False )
  if 31 - 31: I1Ii111 - I11i
  oo00 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  oOOOO00o00 = self . auth_len
  self . auth_data = II1Iii1iI
  Oo00oo = Oo00oo [ 0 : oo00 ] + II1Iii1iI + Oo00oo [ oo00 + oOOOO00o00 : : ]
  self . packet = Oo00oo
  return ( Oo00oo )
  if 49 - 49: iIii1I11I1II1 - iIii1I11I1II1 - OoOoOO00 + IiII / OoOoOO00
  if 74 - 74: OoooooooOO + I1ii11iIi11i % O0
 def decode ( self , packet ) :
  i1o0o0oOO = packet
  iiII1iiI = "I"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 32 - 32: I1ii11iIi11i + I1ii11iIi11i
  iIiIii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  iIiIii = socket . ntohl ( iIiIii [ 0 ] )
  self . map_notify_ack = ( ( iIiIii >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = iIiIii & 0xff
  packet = packet [ ooo0000oo0 : : ]
  if 89 - 89: ooOoO0o + oO0o + Ii1I - OOooOOo
  iiII1iiI = "QBBH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 12 - 12: OoOoOO00 - o0oOOo0O0Ooo - I1Ii111 / I11i
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 17 - 17: OoO0O00 - I1Ii111 - II111iiii / I1Ii111 / Ii1I
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ ooo0000oo0 : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 30 - 30: OOooOOo * I1ii11iIi11i % I1ii11iIi11i + iII111i * IiII
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 33 - 33: o0oOOo0O0Ooo + I11i * O0 * OoO0O00 . I1ii11iIi11i
  if 74 - 74: iII111i * iII111i * o0oOOo0O0Ooo / oO0o
  if 91 - 91: i11iIiiIii . I1ii11iIi11i / II111iiii
  if 97 - 97: Ii1I % i1IIi % IiII + Oo0Ooo - O0 - I11i
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 64 - 64: Ii1I - iII111i
  oOOOO00o00 = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   i1iI11I , oOoOOO , iI1i11i1i1i = struct . unpack ( "QQI" , packet [ : oOOOO00o00 ] )
   OoO00O = ""
   if 12 - 12: i1IIi
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   i1iI11I , oOoOOO , iI1i11i1i1i , OoO00O = struct . unpack ( "QQQQ" ,
 packet [ : oOOOO00o00 ] )
   if 99 - 99: II111iiii - I1ii11iIi11i * IiII
  self . auth_data = lisp_concat_auth_data ( self . alg_id , i1iI11I , oOoOOO ,
 iI1i11i1i1i , OoO00O )
  if 3 - 3: IiII - I1ii11iIi11i * iII111i * I1ii11iIi11i + Oo0Ooo
  ooo0000oo0 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( i1o0o0oOO [ : ooo0000oo0 ] )
  ooo0000oo0 += oOOOO00o00
  packet += i1o0o0oOO [ ooo0000oo0 : : ]
  return ( packet )
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
  if 55 - 55: II111iiii % o0oOOo0O0Ooo - OoO0O00
  if 48 - 48: ooOoO0o * iIii1I11I1II1 % OoOoOO00
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 100 - 100: II111iiii - i11iIiiIii + OoO0O00 % ooOoO0o - iIii1I11I1II1 * i11iIiiIii
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 30 - 30: OoO0O00 . OoO0O00 . Ii1I % Ii1I * i1IIi * oO0o
  if 74 - 74: OoooooooOO
 def print_map_request ( self ) :
  oOOOOOo0OO0o0oOO0 = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   oOOOOOo0OO0o0oOO0 = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 33 - 33: o0oOOo0O0Ooo - II111iiii
   if 95 - 95: OoooooooOO
   if 23 - 23: II111iiii + I11i / O0 . I11i . I1Ii111 + iIii1I11I1II1
  IiiiI1 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 2 - 2: i1IIi . O0 / o0oOOo0O0Ooo . II111iiii / OoO0O00 % i1IIi
  lprint ( IiiiI1 . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # i11iIiiIii
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , oOOOOOo0OO0o0oOO0 ) )
  if 52 - 52: ooOoO0o % iIii1I11I1II1 . i11iIiiIii % ooOoO0o
  iI1iiiiiii = self . keys
  for oO0oO00OO00 in self . itr_rlocs :
   if ( oO0oO00OO00 . afi == LISP_AFI_LCAF and self . json_telemetry != None ) :
    continue
    if 75 - 75: o0oOOo0O0Ooo + I1IiiI % ooOoO0o * I1Ii111
   Oooo000 = red ( oO0oO00OO00 . print_address_no_iid ( ) , False )
   lprint ( "  itr-rloc: afi {} {}{}" . format ( oO0oO00OO00 . afi , Oooo000 ,
 "" if ( iI1iiiiiii == None ) else ", " + iI1iiiiiii [ 1 ] . print_keys ( ) ) )
   iI1iiiiiii = None
   if 52 - 52: iIii1I11I1II1 / iII111i . O0 * IiII . I1IiiI
  if ( self . json_telemetry != None ) :
   lprint ( "  itr-rloc: afi {} telemetry: {}" . format ( LISP_AFI_LCAF ,
 self . json_telemetry ) )
   if 67 - 67: II111iiii + Ii1I - I1IiiI * ooOoO0o
   if 19 - 19: i11iIiiIii * Oo0Ooo
   if 33 - 33: i11iIiiIii + I1IiiI
 def sign_map_request ( self , privkey ) :
  OO00O = self . signature_eid . print_address ( )
  iiO0OoO0OOO00 = self . source_eid . print_address ( )
  IIIiii1I = self . target_eid . print_address ( )
  ii1iiii11IiI1 = lisp_hex_string ( self . nonce ) + iiO0OoO0OOO00 + IIIiii1I
  self . map_request_signature = privkey . sign ( ii1iiii11IiI1 . encode ( ) )
  O0OoO0ooOoo = binascii . b2a_base64 ( self . map_request_signature )
  O0OoO0ooOoo = { "source-eid" : iiO0OoO0OOO00 , "signature-eid" : OO00O ,
 "signature" : O0OoO0ooOoo . decode ( ) }
  return ( json . dumps ( O0OoO0ooOoo ) )
  if 43 - 43: O0
  if 57 - 57: i11iIiiIii + I11i % ooOoO0o / iIii1I11I1II1
 def verify_map_request_sig ( self , pubkey ) :
  OOoOoOO = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( OOoOoOO ) )
   return ( False )
   if 50 - 50: i1IIi % IiII % I1Ii111
   if 76 - 76: ooOoO0o % I1IiiI
  iiO0OoO0OOO00 = self . source_eid . print_address ( )
  IIIiii1I = self . target_eid . print_address ( )
  ii1iiii11IiI1 = lisp_hex_string ( self . nonce ) + iiO0OoO0OOO00 + IIIiii1I
  pubkey = binascii . a2b_base64 ( pubkey )
  if 18 - 18: OoO0O00
  O0oOo = True
  try :
   III = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 1 - 1: oO0o % I11i / OoOoOO00
   O0oOo = False
   if 15 - 15: OoO0O00 - OoOoOO00
   if 41 - 41: Ii1I * I11i
  if ( O0oOo ) :
   try :
    ii1iiii11IiI1 = ii1iiii11IiI1 . encode ( )
    O0oOo = III . verify ( self . map_request_signature , ii1iiii11IiI1 )
   except :
    O0oOo = False
    if 13 - 13: Oo0Ooo * o0oOOo0O0Ooo * iII111i
    if 71 - 71: OOooOOo + OoooooooOO + iIii1I11I1II1
    if 99 - 99: OoO0O00 - IiII * IiII + oO0o / iII111i + OOooOOo
  Oo0oOO = bold ( "passed" if O0oOo else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( Oo0oOO , OOoOoOO ) )
  return ( O0oOo )
  if 49 - 49: i1IIi . IiII
  if 82 - 82: OoO0O00 / I11i
 def encode_json ( self , json_string ) :
  ooOoOoOo = LISP_LCAF_JSON_TYPE
  ii1 = socket . htons ( LISP_AFI_LCAF )
  iIIIi1Iii1 = socket . htons ( len ( json_string ) + 4 )
  oOoOOOo0oo = socket . htons ( len ( json_string ) )
  Oo00oo = struct . pack ( "HBBBBHH" , ii1 , 0 , 0 , ooOoOoOo , 0 , iIIIi1Iii1 ,
 oOoOOOo0oo )
  Oo00oo += json_string . encode ( )
  Oo00oo += struct . pack ( "H" , 0 )
  return ( Oo00oo )
  if 68 - 68: IiII - I11i % II111iiii - o0oOOo0O0Ooo % ooOoO0o
  if 41 - 41: iII111i . ooOoO0o % OoooooooOO / I1IiiI * II111iiii - iII111i
 def encode ( self , probe_dest , probe_port ) :
  iIiIii = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  if 19 - 19: OoO0O00 . I11i / i11iIiiIii - OoOoOO00 * I11i . IiII
  Ii1i = lisp_telemetry_configured ( ) if ( self . rloc_probe ) else None
  if ( Ii1i != None ) : self . itr_rloc_count += 1
  iIiIii = iIiIii | ( self . itr_rloc_count << 8 )
  if 45 - 45: I1Ii111 - O0 . I1Ii111 / I1Ii111 / OoOoOO00
  if ( self . auth_bit ) : iIiIii |= 0x08000000
  if ( self . map_data_present ) : iIiIii |= 0x04000000
  if ( self . rloc_probe ) : iIiIii |= 0x02000000
  if ( self . smr_bit ) : iIiIii |= 0x01000000
  if ( self . pitr_bit ) : iIiIii |= 0x00800000
  if ( self . smr_invoked_bit ) : iIiIii |= 0x00400000
  if ( self . mobile_node ) : iIiIii |= 0x00200000
  if ( self . xtr_id_present ) : iIiIii |= 0x00100000
  if ( self . local_xtr ) : iIiIii |= 0x00004000
  if ( self . dont_reply_bit ) : iIiIii |= 0x00002000
  if 12 - 12: OOooOOo
  Oo00oo = struct . pack ( "I" , socket . htonl ( iIiIii ) )
  Oo00oo += struct . pack ( "Q" , self . nonce )
  if 75 - 75: OOooOOo + Ii1I + oO0o . Oo0Ooo
  if 93 - 93: OOooOOo * Ii1I - o0oOOo0O0Ooo . oO0o . iII111i
  if 64 - 64: Oo0Ooo / iIii1I11I1II1 . OoO0O00 / o0oOOo0O0Ooo / I11i
  if 3 - 3: OOooOOo - o0oOOo0O0Ooo * iIii1I11I1II1 . Ii1I + OoOoOO00 % I1Ii111
  if 11 - 11: OOooOOo
  if 12 - 12: OoooooooOO * OOooOOo * I1ii11iIi11i * ooOoO0o
  iiI = False
  i11i1I1 = self . privkey_filename
  if ( i11i1I1 != None and os . path . exists ( i11i1I1 ) ) :
   o0OoO0 = open ( i11i1I1 , "r" ) ; III = o0OoO0 . read ( ) ; o0OoO0 . close ( )
   try :
    III = ecdsa . SigningKey . from_pem ( III )
   except :
    return ( None )
    if 30 - 30: IiII . OoooooooOO * Oo0Ooo % ooOoO0o . oO0o
   OoOo00OO0o00 = self . sign_map_request ( III )
   iiI = True
  elif ( self . map_request_signature != None ) :
   O0OoO0ooOoo = binascii . b2a_base64 ( self . map_request_signature )
   OoOo00OO0o00 = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : O0OoO0ooOoo }
   OoOo00OO0o00 = json . dumps ( OoOo00OO0o00 )
   iiI = True
   if 37 - 37: iIii1I11I1II1 * I11i / IiII * Oo0Ooo % i11iIiiIii
  if ( iiI ) :
   Oo00oo += self . encode_json ( OoOo00OO0o00 )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    Oo00oo += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    Oo00oo += self . source_eid . lcaf_encode_iid ( )
   else :
    Oo00oo += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    Oo00oo += self . source_eid . pack_address ( )
    if 93 - 93: ooOoO0o + ooOoO0o
    if 65 - 65: OoooooooOO * I11i * oO0o % I1ii11iIi11i * II111iiii
    if 86 - 86: i11iIiiIii / I11i * iII111i - iII111i
    if 32 - 32: Oo0Ooo . O0
    if 48 - 48: I1ii11iIi11i % II111iiii + I11i
    if 25 - 25: IiII * o0oOOo0O0Ooo / I1IiiI . IiII % II111iiii
    if 50 - 50: OoOoOO00 * iII111i
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   O0O0 = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 59 - 59: I1IiiI * I1IiiI / I11i
   if ( O0O0 in lisp_crypto_keys_by_rloc_encap ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ O0O0 ]
    if 92 - 92: o0oOOo0O0Ooo
    if 8 - 8: iII111i + I1ii11iIi11i . Ii1I
    if 50 - 50: Oo0Ooo
    if 16 - 16: Ii1I - OoOoOO00 % Oo0Ooo / Ii1I . I11i + ooOoO0o
    if 78 - 78: iIii1I11I1II1 + OoO0O00 + i11iIiiIii
    if 21 - 21: Oo0Ooo + Ii1I % ooOoO0o + OoOoOO00 % I11i
    if 22 - 22: i1IIi / OoooooooOO . OoO0O00
  for oO0oO00OO00 in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( oO0oO00OO00 ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     iI1iiiiiii = lisp_keys ( 1 )
     self . keys = [ None , iI1iiiiiii , None , None ]
     if 83 - 83: I1IiiI - OoooooooOO + I1ii11iIi11i . Ii1I / o0oOOo0O0Ooo + ooOoO0o
    iI1iiiiiii = self . keys [ 1 ]
    iI1iiiiiii . add_key_by_nonce ( self . nonce )
    Oo00oo += iI1iiiiiii . encode_lcaf ( oO0oO00OO00 )
   else :
    Oo00oo += struct . pack ( "H" , socket . htons ( oO0oO00OO00 . afi ) )
    Oo00oo += oO0oO00OO00 . pack_address ( )
    if 90 - 90: I1IiiI - i11iIiiIii
    if 42 - 42: OOooOOo . Oo0Ooo
    if 21 - 21: iII111i . I1IiiI / I11i
    if 97 - 97: iIii1I11I1II1 + i1IIi - o0oOOo0O0Ooo
    if 73 - 73: OoO0O00 - i11iIiiIii % I1Ii111 / Oo0Ooo - OoooooooOO % OOooOOo
    if 79 - 79: I1IiiI / o0oOOo0O0Ooo . Ii1I * I1ii11iIi11i + I11i
  if ( Ii1i != None ) :
   i1 = str ( time . time ( ) )
   Ii1i = lisp_encode_telemetry ( Ii1i , io = i1 )
   self . json_telemetry = Ii1i
   Oo00oo += self . encode_json ( Ii1i )
   if 96 - 96: OoO0O00 * II111iiii
   if 1 - 1: I1IiiI - OoOoOO00
  OOOoOo0o0Ooo = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 22 - 22: OoOoOO00 * O0 / OoooooooOO
  if 95 - 95: iIii1I11I1II1
  OOOO0oo0o0O = 0
  if ( self . subscribe_bit ) :
   OOOO0oo0o0O = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 29 - 29: I1ii11iIi11i + OoooooooOO . OoO0O00 . i1IIi - OoooooooOO * i11iIiiIii
    if 19 - 19: I1ii11iIi11i * O0 - ooOoO0o
    if 27 - 27: iII111i / o0oOOo0O0Ooo . OoOoOO00 * Ii1I * I1Ii111
  iiII1iiI = "BB"
  Oo00oo += struct . pack ( iiII1iiI , OOOO0oo0o0O , OOOoOo0o0Ooo )
  if 81 - 81: I1Ii111
  if ( self . target_group . is_null ( ) == False ) :
   Oo00oo += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   Oo00oo += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   Oo00oo += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   Oo00oo += self . target_eid . lcaf_encode_iid ( )
  else :
   Oo00oo += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   Oo00oo += self . target_eid . pack_address ( )
   if 45 - 45: OOooOOo * II111iiii * OoooooooOO / OoooooooOO * I1Ii111
   if 38 - 38: iII111i . OoooooooOO
   if 28 - 28: I1Ii111 * i1IIi . I1ii11iIi11i
   if 75 - 75: O0 / oO0o * ooOoO0o - OOooOOo / i1IIi
   if 61 - 61: I11i
  if ( self . subscribe_bit ) : Oo00oo = self . encode_xtr_id ( Oo00oo )
  return ( Oo00oo )
  if 100 - 100: O0 - iIii1I11I1II1 * Oo0Ooo
  if 35 - 35: ooOoO0o
 def lcaf_decode_json ( self , packet ) :
  iiII1iiI = "BBBBHH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 57 - 57: OoO0O00 . Oo0Ooo + I1IiiI
  Ii1Ii1Ii , Ooo0000o , ooOoOoOo , ii11Ii1111 , iIIIi1Iii1 , oOoOOOo0oo = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 89 - 89: II111iiii . I1ii11iIi11i
  if 4 - 4: I1IiiI * OoooooooOO
  if ( ooOoOoOo != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 21 - 21: OoooooooOO
  if 36 - 36: iII111i
  if 91 - 91: ooOoO0o + IiII . I1IiiI / I11i / IiII
  if 23 - 23: I1ii11iIi11i - OOooOOo - i1IIi
  iIIIi1Iii1 = socket . ntohs ( iIIIi1Iii1 )
  oOoOOOo0oo = socket . ntohs ( oOoOOOo0oo )
  packet = packet [ ooo0000oo0 : : ]
  if ( len ( packet ) < iIIIi1Iii1 ) : return ( None )
  if ( iIIIi1Iii1 != oOoOOOo0oo + 4 ) : return ( None )
  if 20 - 20: OoooooooOO / Oo0Ooo * OoO0O00 . o0oOOo0O0Ooo . I1IiiI
  if 75 - 75: iIii1I11I1II1 - Ii1I % O0 % IiII
  if 6 - 6: Oo0Ooo % oO0o * ooOoO0o - i1IIi . OoOoOO00
  if 20 - 20: Oo0Ooo / I1Ii111 . Oo0Ooo
  OoOo00OO0o00 = packet [ 0 : oOoOOOo0oo ]
  packet = packet [ oOoOOOo0oo : : ]
  if 60 - 60: I1ii11iIi11i - I1IiiI * O0 * Oo0Ooo . i1IIi . OoOoOO00
  if 24 - 24: IiII * I1IiiI / OOooOOo
  if 51 - 51: iIii1I11I1II1 / I11i * OoO0O00 * Ii1I + I1ii11iIi11i . OoooooooOO
  if 75 - 75: IiII / OoooooooOO / O0 % OOooOOo
  if ( lisp_is_json_telemetry ( OoOo00OO0o00 ) != None ) :
   self . json_telemetry = OoOo00OO0o00
   if 87 - 87: II111iiii / iIii1I11I1II1 % I1ii11iIi11i
   if 11 - 11: o0oOOo0O0Ooo * OoO0O00
   if 92 - 92: OoOoOO00 . Oo0Ooo * I11i
   if 86 - 86: O0
   if 55 - 55: Ii1I / I1Ii111 / I1ii11iIi11i % ooOoO0o % I1IiiI
  iiII1iiI = "H"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  if ( i1I1iiiI != 0 ) : return ( packet )
  if 55 - 55: oO0o + OoooooooOO % i1IIi
  if ( self . json_telemetry != None ) : return ( packet )
  if 24 - 24: I1ii11iIi11i - Oo0Ooo
  if 36 - 36: I1IiiI . OOooOOo % II111iiii * IiII
  if 34 - 34: I11i % iII111i - ooOoO0o - I1IiiI
  if 44 - 44: Ii1I . o0oOOo0O0Ooo . iIii1I11I1II1 + OoooooooOO - I1IiiI
  try :
   OoOo00OO0o00 = json . loads ( OoOo00OO0o00 )
  except :
   return ( None )
   if 22 - 22: I11i * I1ii11iIi11i . OoooooooOO / Oo0Ooo / Ii1I
   if 54 - 54: I1Ii111 % Ii1I + ooOoO0o
   if 45 - 45: Ii1I / oO0o * I1Ii111 . Ii1I
   if 25 - 25: I1ii11iIi11i / I1ii11iIi11i
   if 79 - 79: Oo0Ooo - OoO0O00 % Oo0Ooo . II111iiii
  if ( "source-eid" not in OoOo00OO0o00 ) : return ( packet )
  o0Ooo0Oooo0o = OoOo00OO0o00 [ "source-eid" ]
  i1I1iiiI = LISP_AFI_IPV4 if o0Ooo0Oooo0o . count ( "." ) == 3 else LISP_AFI_IPV6 if o0Ooo0Oooo0o . count ( ":" ) == 7 else None
  if 22 - 22: oO0o / II111iiii . OoOoOO00
  if ( i1I1iiiI == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( o0Ooo0Oooo0o ) )
   return ( None )
   if 9 - 9: i11iIiiIii + ooOoO0o . iIii1I11I1II1 * OoOoOO00
   if 4 - 4: I1Ii111 + iII111i % O0
  self . source_eid . afi = i1I1iiiI
  self . source_eid . store_address ( o0Ooo0Oooo0o )
  if 98 - 98: i1IIi + I1Ii111 - I1ii11iIi11i . OoooooooOO / O0 / iII111i
  if ( "signature-eid" not in OoOo00OO0o00 ) : return ( packet )
  o0Ooo0Oooo0o = OoOo00OO0o00 [ "signature-eid" ]
  if ( o0Ooo0Oooo0o . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( o0Ooo0Oooo0o ) )
   return ( None )
   if 66 - 66: i1IIi % OoooooooOO * i11iIiiIii + oO0o * O0 / OoO0O00
   if 14 - 14: I1IiiI . IiII
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( o0Ooo0Oooo0o )
  if 29 - 29: OoooooooOO / IiII + OoOoOO00 - I1Ii111 + IiII . i1IIi
  if ( "signature" not in OoOo00OO0o00 ) : return ( packet )
  O0OoO0ooOoo = binascii . a2b_base64 ( OoOo00OO0o00 [ "signature" ] )
  self . map_request_signature = O0OoO0ooOoo
  return ( packet )
  if 26 - 26: i11iIiiIii - II111iiii
  if 43 - 43: I1IiiI
 def decode ( self , packet , source , port ) :
  iiII1iiI = "I"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 35 - 35: ooOoO0o + OoOoOO00 * OoooooooOO - II111iiii
  iIiIii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  iIiIii = iIiIii [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  if 19 - 19: i1IIi / Ii1I / OoOoOO00 . I1IiiI / Ii1I % o0oOOo0O0Ooo
  iiII1iiI = "Q"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 39 - 39: ooOoO0o - OoooooooOO
  o0Oo0o = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  packet = packet [ ooo0000oo0 : : ]
  if 88 - 88: i1IIi + iIii1I11I1II1 * i11iIiiIii - OoooooooOO % o0oOOo0O0Ooo
  iIiIii = socket . ntohl ( iIiIii )
  self . auth_bit = True if ( iIiIii & 0x08000000 ) else False
  self . map_data_present = True if ( iIiIii & 0x04000000 ) else False
  self . rloc_probe = True if ( iIiIii & 0x02000000 ) else False
  self . smr_bit = True if ( iIiIii & 0x01000000 ) else False
  self . pitr_bit = True if ( iIiIii & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( iIiIii & 0x00400000 ) else False
  self . mobile_node = True if ( iIiIii & 0x00200000 ) else False
  self . xtr_id_present = True if ( iIiIii & 0x00100000 ) else False
  self . local_xtr = True if ( iIiIii & 0x00004000 ) else False
  self . dont_reply_bit = True if ( iIiIii & 0x00002000 ) else False
  self . itr_rloc_count = ( ( iIiIii >> 8 ) & 0x1f )
  self . record_count = iIiIii & 0xff
  self . nonce = o0Oo0o [ 0 ]
  if 74 - 74: ooOoO0o - i11iIiiIii
  if 34 - 34: IiII + I1Ii111 + Oo0Ooo / II111iiii
  if 33 - 33: Ii1I . i1IIi - II111iiii - OoO0O00
  if 31 - 31: I11i - OoOoOO00 / o0oOOo0O0Ooo * OoOoOO00 / Oo0Ooo + o0oOOo0O0Ooo
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 46 - 46: IiII * OoO0O00 / OOooOOo + Oo0Ooo
   if 24 - 24: ooOoO0o % OOooOOo . O0 * Oo0Ooo
  ooo0000oo0 = struct . calcsize ( "H" )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 52 - 52: O0 . I1Ii111 + iII111i / i11iIiiIii
  i1I1iiiI = struct . unpack ( "H" , packet [ : ooo0000oo0 ] )
  self . source_eid . afi = socket . ntohs ( i1I1iiiI [ 0 ] )
  packet = packet [ ooo0000oo0 : : ]
  if 52 - 52: oO0o % Oo0Ooo * II111iiii
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   ii1iiiIIiIII = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( ii1iiiIIiIII )
    if ( packet == None ) : return ( None )
    if 3 - 3: IiII % I1Ii111 . OoooooooOO
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 19 - 19: I1Ii111 * Ii1I - oO0o
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 78 - 78: OoO0O00 - Ii1I / OOooOOo
  ooOo000 = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  OO0o0oo = self . itr_rloc_count + 1
  if 68 - 68: iII111i . OOooOOo
  while ( OO0o0oo != 0 ) :
   ooo0000oo0 = struct . calcsize ( "H" )
   if ( len ( packet ) < ooo0000oo0 ) : return ( None )
   if 6 - 6: Ii1I - o0oOOo0O0Ooo % I11i + i11iIiiIii
   i1I1iiiI = socket . ntohs ( struct . unpack ( "H" , packet [ : ooo0000oo0 ] ) [ 0 ] )
   oO0oO00OO00 = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   oO0oO00OO00 . afi = i1I1iiiI
   if 40 - 40: O0 . Ii1I
   if 58 - 58: i11iIiiIii * iII111i / Ii1I - oO0o - I1ii11iIi11i % o0oOOo0O0Ooo
   if 16 - 16: OoooooooOO
   if 71 - 71: Ii1I % O0 / I1Ii111 % iII111i - II111iiii / OoO0O00
   if 30 - 30: I11i
   if ( oO0oO00OO00 . afi == LISP_AFI_LCAF ) :
    i1o0o0oOO = packet
    O0o00o0Oo = packet [ ooo0000oo0 : : ]
    packet = self . lcaf_decode_json ( O0o00o0Oo )
    if ( packet == None ) : return ( None )
    if ( packet == O0o00o0Oo ) : packet = i1o0o0oOO
    if 29 - 29: OoO0O00 - Oo0Ooo . oO0o / OoO0O00 % i11iIiiIii
    if 26 - 26: ooOoO0o . I1Ii111 / II111iiii % Ii1I
    if 82 - 82: OOooOOo % O0 % iIii1I11I1II1 % IiII + i11iIiiIii
    if 64 - 64: i1IIi / IiII . IiII - I1Ii111 % OOooOOo . II111iiii
    if 78 - 78: I1Ii111 - O0 - I1Ii111 . iIii1I11I1II1 % I1ii11iIi11i . OoooooooOO
    if 64 - 64: IiII
   if ( oO0oO00OO00 . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < oO0oO00OO00 . addr_length ( ) ) : return ( None )
    packet = oO0oO00OO00 . unpack_address ( packet [ ooo0000oo0 : : ] )
    if ( packet == None ) : return ( None )
    if 21 - 21: o0oOOo0O0Ooo - ooOoO0o * OoooooooOO . OoooooooOO
    if ( ooOo000 ) :
     self . itr_rlocs . append ( oO0oO00OO00 )
     OO0o0oo -= 1
     continue
     if 17 - 17: OOooOOo - iII111i % I1IiiI * OOooOOo * iIii1I11I1II1 . o0oOOo0O0Ooo
     if 58 - 58: oO0o - II111iiii + O0
    O0O0 = lisp_build_crypto_decap_lookup_key ( oO0oO00OO00 , port )
    if 54 - 54: iIii1I11I1II1 - IiII - IiII
    if 18 - 18: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii
    if 63 - 63: iII111i - OoO0O00 * OOooOOo
    if 89 - 89: iII111i / Oo0Ooo
    if 66 - 66: o0oOOo0O0Ooo + OoOoOO00 % OoooooooOO . I11i
    if ( lisp_nat_traversal and oO0oO00OO00 . is_private_address ( ) and source ) : oO0oO00OO00 = source
    if 30 - 30: II111iiii - Oo0Ooo - i11iIiiIii + O0
    Ooo0OO0 = lisp_crypto_keys_by_rloc_decap
    if ( O0O0 in Ooo0OO0 ) : Ooo0OO0 . pop ( O0O0 )
    if 71 - 71: Ii1I + i11iIiiIii
    if 92 - 92: iIii1I11I1II1 + Ii1I
    if 69 - 69: Oo0Ooo
    if 70 - 70: O0 - OoO0O00 - Oo0Ooo
    if 95 - 95: IiII * II111iiii % o0oOOo0O0Ooo * Oo0Ooo . I11i
    if 46 - 46: II111iiii - OoO0O00 % ooOoO0o
    lisp_write_ipc_decap_key ( O0O0 , None )
    if 97 - 97: OoO0O00 . OoOoOO00
   elif ( self . json_telemetry == None ) :
    if 78 - 78: I1ii11iIi11i + I1ii11iIi11i . OoOoOO00 - IiII * iIii1I11I1II1 * O0
    if 26 - 26: OoooooooOO + oO0o + OoO0O00 . O0
    if 46 - 46: OoooooooOO - Oo0Ooo * I1Ii111 * OOooOOo * I1Ii111 . oO0o
    if 96 - 96: Ii1I / IiII % o0oOOo0O0Ooo + I11i
    i1o0o0oOO = packet
    iIiiIi1111ii = lisp_keys ( 1 )
    packet = iIiiIi1111ii . decode_lcaf ( i1o0o0oOO , 0 )
    if 53 - 53: O0 % ooOoO0o
    if ( packet == None ) : return ( None )
    if 41 - 41: IiII
    if 29 - 29: ooOoO0o
    if 70 - 70: oO0o . O0 % I11i % IiII - I11i * I1ii11iIi11i
    if 22 - 22: i1IIi
    OoOO0Ooo = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( iIiiIi1111ii . cipher_suite in OoOO0Ooo ) :
     if ( iIiiIi1111ii . cipher_suite == LISP_CS_25519_CBC or
 iIiiIi1111ii . cipher_suite == LISP_CS_25519_GCM ) :
      III = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 82 - 82: oO0o . iIii1I11I1II1 - I1ii11iIi11i
     if ( iIiiIi1111ii . cipher_suite == LISP_CS_25519_CHACHA ) :
      III = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 55 - 55: Oo0Ooo % Ii1I . iIii1I11I1II1 * I1Ii111
    else :
     III = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 33 - 33: O0 - I1IiiI / I1ii11iIi11i / OoO0O00 + iII111i - oO0o
    packet = III . decode_lcaf ( i1o0o0oOO , 0 )
    if ( packet == None ) : return ( None )
    if 27 - 27: I1Ii111 + ooOoO0o - I1Ii111 % i11iIiiIii * Oo0Ooo * o0oOOo0O0Ooo
    if ( len ( packet ) < ooo0000oo0 ) : return ( None )
    i1I1iiiI = struct . unpack ( "H" , packet [ : ooo0000oo0 ] ) [ 0 ]
    oO0oO00OO00 . afi = socket . ntohs ( i1I1iiiI )
    if ( len ( packet ) < oO0oO00OO00 . addr_length ( ) ) : return ( None )
    if 88 - 88: OOooOOo
    packet = oO0oO00OO00 . unpack_address ( packet [ ooo0000oo0 : : ] )
    if ( packet == None ) : return ( None )
    if 25 - 25: OoO0O00 + o0oOOo0O0Ooo . ooOoO0o - Ii1I . oO0o * Ii1I
    if ( ooOo000 ) :
     self . itr_rlocs . append ( oO0oO00OO00 )
     OO0o0oo -= 1
     continue
     if 85 - 85: i1IIi
     if 94 - 94: OoooooooOO . O0 / OoooooooOO
    O0O0 = lisp_build_crypto_decap_lookup_key ( oO0oO00OO00 , port )
    if 67 - 67: i11iIiiIii + OoOoOO00
    I1 = None
    if ( lisp_nat_traversal and oO0oO00OO00 . is_private_address ( ) and source ) : oO0oO00OO00 = source
    if 35 - 35: I1ii11iIi11i . OOooOOo
    if 97 - 97: I1IiiI
    if ( O0O0 in lisp_crypto_keys_by_rloc_decap ) :
     iI1iiiiiii = lisp_crypto_keys_by_rloc_decap [ O0O0 ]
     I1 = iI1iiiiiii [ 1 ] if iI1iiiiiii and iI1iiiiiii [ 1 ] else None
     if 63 - 63: O0 - OoOoOO00 / i11iIiiIii / OoooooooOO / ooOoO0o / II111iiii
     if 45 - 45: II111iiii . OoO0O00 + OoO0O00 * iIii1I11I1II1
    I11Ii1I1I1111 = True
    if ( I1 ) :
     if ( I1 . compare_keys ( III ) ) :
      self . keys = [ None , I1 , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( O0O0 , False ) ) )
      if 9 - 9: OoooooooOO * I1IiiI - Oo0Ooo / i11iIiiIii * iII111i
     else :
      I11Ii1I1I1111 = False
      oO = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( oO , red ( O0O0 ,
 False ) ) )
      III . copy_keypair ( I1 )
      III . uptime = I1 . uptime
      I1 = None
      if 75 - 75: I1IiiI % II111iiii * oO0o % i1IIi % OOooOOo
      if 93 - 93: OoOoOO00
      if 48 - 48: i11iIiiIii
    if ( I1 == None ) :
     self . keys = [ None , III , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      III . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( O0O0 , False ) ) )
     elif ( III . remote_public_key != None ) :
      if ( I11Ii1I1I1111 ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # i11iIiiIii % I1IiiI
 red ( O0O0 , False ) ) )
       if 90 - 90: II111iiii
      III . compute_shared_key ( "decap" )
      III . add_key_by_rloc ( O0O0 , False )
      if 2 - 2: Ii1I - OoooooooOO - i11iIiiIii % Oo0Ooo / Ii1I
      if 77 - 77: o0oOOo0O0Ooo . o0oOOo0O0Ooo * I1Ii111 + OOooOOo - i11iIiiIii
      if 45 - 45: I1IiiI . I1IiiI - Oo0Ooo * OOooOOo
      if 71 - 71: i1IIi / I11i
   self . itr_rlocs . append ( oO0oO00OO00 )
   OO0o0oo -= 1
   if 14 - 14: OoooooooOO
   if 99 - 99: o0oOOo0O0Ooo * o0oOOo0O0Ooo
  ooo0000oo0 = struct . calcsize ( "BBH" )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 6 - 6: i11iIiiIii + oO0o % ooOoO0o + i11iIiiIii - OOooOOo
  OOOO0oo0o0O , OOOoOo0o0Ooo , i1I1iiiI = struct . unpack ( "BBH" , packet [ : ooo0000oo0 ] )
  self . subscribe_bit = ( OOOO0oo0o0O & 0x80 )
  self . target_eid . afi = socket . ntohs ( i1I1iiiI )
  packet = packet [ ooo0000oo0 : : ]
  if 12 - 12: iII111i . oO0o % IiII * OoooooooOO . IiII
  self . target_eid . mask_len = OOOoOo0o0Ooo
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , iIi = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( iIi ) : self . target_group = iIi
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ ooo0000oo0 : : ]
   if 34 - 34: OoooooooOO
  return ( packet )
  if 40 - 40: I1ii11iIi11i . OoO0O00
  if 30 - 30: ooOoO0o % I1IiiI . oO0o
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 48 - 48: OoOoOO00
  if 28 - 28: I11i / O0 * IiII - I1Ii111 % IiII
 def encode_xtr_id ( self , packet ) :
  iiii = self . xtr_id >> 64
  Oo000O00o0O = self . xtr_id & 0xffffffffffffffff
  iiii = byte_swap_64 ( iiii )
  Oo000O00o0O = byte_swap_64 ( Oo000O00o0O )
  packet += struct . pack ( "QQ" , iiii , Oo000O00o0O )
  return ( packet )
  if 8 - 8: I11i / I1ii11iIi11i % I1ii11iIi11i % Ii1I + iII111i
  if 100 - 100: OoO0O00
 def decode_xtr_id ( self , packet ) :
  ooo0000oo0 = struct . calcsize ( "QQ" )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  packet = packet [ len ( packet ) - ooo0000oo0 : : ]
  iiii , Oo000O00o0O = struct . unpack ( "QQ" , packet [ : ooo0000oo0 ] )
  iiii = byte_swap_64 ( iiii )
  Oo000O00o0O = byte_swap_64 ( Oo000O00o0O )
  self . xtr_id = ( iiii << 64 ) | Oo000O00o0O
  return ( True )
  if 25 - 25: I1Ii111 - ooOoO0o + Oo0Ooo . I1IiiI % iIii1I11I1II1
  if 49 - 49: i1IIi + OoO0O00 + iII111i / Oo0Ooo
  if 5 - 5: i11iIiiIii + I11i . IiII
  if 9 - 9: i11iIiiIii / iIii1I11I1II1 - I1ii11iIi11i * I1ii11iIi11i
  if 99 - 99: I11i
  if 64 - 64: iIii1I11I1II1
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
  if 5 - 5: I11i / OoOoOO00
  if 48 - 48: i1IIi - oO0o . OoooooooOO - OoO0O00 - i1IIi
  if 19 - 19: oO0o % Ii1I + I1ii11iIi11i . II111iiii * i11iIiiIii
  if 87 - 87: Ii1I / I1Ii111 % OoOoOO00 * I1ii11iIi11i - OoooooooOO / OoOoOO00
  if 24 - 24: I11i . OOooOOo * i1IIi . I1ii11iIi11i / ooOoO0o / O0
class lisp_map_reply ( object ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 62 - 62: o0oOOo0O0Ooo % II111iiii
  if 22 - 22: oO0o - o0oOOo0O0Ooo
 def print_map_reply ( self ) :
  IiiiI1 = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 89 - 89: OOooOOo
  lprint ( IiiiI1 . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # O0 / iII111i
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 70 - 70: Oo0Ooo
  if 92 - 92: OOooOOo + i1IIi - ooOoO0o
 def encode ( self ) :
  iIiIii = ( LISP_MAP_REPLY << 28 ) | self . record_count
  iIiIii |= self . hop_count << 8
  if ( self . rloc_probe ) : iIiIii |= 0x08000000
  if ( self . echo_nonce_capable ) : iIiIii |= 0x04000000
  if ( self . security ) : iIiIii |= 0x02000000
  if 13 - 13: iII111i
  Oo00oo = struct . pack ( "I" , socket . htonl ( iIiIii ) )
  Oo00oo += struct . pack ( "Q" , self . nonce )
  return ( Oo00oo )
  if 79 - 79: OoooooooOO / OoO0O00 % Ii1I - OoOoOO00 * i1IIi + I1Ii111
  if 42 - 42: i11iIiiIii % I1Ii111 + i11iIiiIii % i11iIiiIii % I1ii11iIi11i
 def decode ( self , packet ) :
  iiII1iiI = "I"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 6 - 6: oO0o . o0oOOo0O0Ooo / I1IiiI
  iIiIii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  iIiIii = iIiIii [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  if 64 - 64: iII111i
  iiII1iiI = "Q"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 65 - 65: O0 / II111iiii * IiII % Ii1I + o0oOOo0O0Ooo
  o0Oo0o = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  packet = packet [ ooo0000oo0 : : ]
  if 43 - 43: I1Ii111 + OoO0O00 * OoooooooOO
  iIiIii = socket . ntohl ( iIiIii )
  self . rloc_probe = True if ( iIiIii & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( iIiIii & 0x04000000 ) else False
  self . security = True if ( iIiIii & 0x02000000 ) else False
  self . hop_count = ( iIiIii >> 8 ) & 0xff
  self . record_count = iIiIii & 0xff
  self . nonce = o0Oo0o [ 0 ]
  if 85 - 85: iII111i + OOooOOo
  if ( self . nonce in lisp_crypto_keys_by_nonce ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 36 - 36: OoO0O00 % II111iiii * O0 + II111iiii - oO0o - i1IIi
  return ( packet )
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
  if 27 - 27: II111iiii + i11iIiiIii
  if 32 - 32: i1IIi
  if 76 - 76: II111iiii % ooOoO0o - I1ii11iIi11i
  if 50 - 50: II111iiii / I1IiiI . Ii1I % i11iIiiIii
  if 66 - 66: oO0o / OOooOOo / iII111i
  if 5 - 5: I1Ii111 . oO0o
  if 77 - 77: iII111i / i11iIiiIii
  if 20 - 20: O0 . I11i
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
  if 67 - 67: OoOoOO00 - ooOoO0o - iIii1I11I1II1
  if 31 - 31: II111iiii + o0oOOo0O0Ooo * i11iIiiIii . o0oOOo0O0Ooo
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 73 - 73: oO0o / OOooOOo * II111iiii % OoooooooOO - i1IIi - ooOoO0o
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 43 - 43: o0oOOo0O0Ooo + Ii1I % OoO0O00 . I1Ii111 + i1IIi
  if 85 - 85: Oo0Ooo % I1ii11iIi11i / OOooOOo
 def print_ttl ( self ) :
  O0O00O = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   O0O00O = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( O0O00O % 60 ) == 0 ) :
   O0O00O = str ( old_div ( O0O00O , 60 ) ) + " hours"
  else :
   O0O00O = str ( O0O00O ) + " mins"
   if 51 - 51: Oo0Ooo . Oo0Ooo
  return ( O0O00O )
  if 34 - 34: I1ii11iIi11i - i11iIiiIii
  if 43 - 43: iIii1I11I1II1
 def store_ttl ( self ) :
  O0O00O = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : O0O00O = self . record_ttl & 0x7fffffff
  return ( O0O00O )
  if 73 - 73: OoOoOO00 + o0oOOo0O0Ooo
  if 58 - 58: i1IIi * I1ii11iIi11i % iII111i . OoO0O00 % IiII % I11i
 def print_record ( self , indent , ddt ) :
  oO00O0o0Oo = ""
  I1IIiIiIIiIiI = ""
  IIi1iiIII11 = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    IIi1iiIII11 = lisp_map_referral_action_string [ self . action ]
    IIi1iiIII11 = bold ( IIi1iiIII11 , False )
    oO00O0o0Oo = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 69 - 69: I1ii11iIi11i . OoooooooOO % I1Ii111
    I1IIiIiIIiIiI = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 79 - 79: I1IiiI - IiII . OoooooooOO - I1ii11iIi11i
    if 79 - 79: OOooOOo + o0oOOo0O0Ooo % iII111i . oO0o
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    IIi1iiIII11 = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     IIi1iiIII11 = bold ( IIi1iiIII11 , False )
     if 49 - 49: Ii1I + i11iIiiIii * OoOoOO00 . OoOoOO00 . I1ii11iIi11i . Oo0Ooo
     if 61 - 61: I11i / OOooOOo
     if 85 - 85: OoOoOO00 - I11i . OoOoOO00 . OoOoOO00
     if 62 - 62: IiII % OoooooooOO * OoO0O00 + OoO0O00 % Ii1I % iII111i
  i1I1iiiI = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  IiiiI1 = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 66 - 66: I1IiiI . OOooOOo - OoO0O00 % Oo0Ooo * o0oOOo0O0Ooo - oO0o
  lprint ( IiiiI1 . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 IIi1iiIII11 , "auth" if ( self . authoritative is True ) else "non-auth" ,
 oO00O0o0Oo , I1IIiIiIIiIiI , self . map_version , i1I1iiiI ,
 green ( self . print_prefix ( ) , False ) ) )
  if 68 - 68: I11i - i11iIiiIii / o0oOOo0O0Ooo + ooOoO0o / I1IiiI
  if 31 - 31: I1Ii111 . OoooooooOO . i1IIi
 def encode ( self ) :
  oOoO0OooO0O = self . action << 13
  if ( self . authoritative ) : oOoO0OooO0O |= 0x1000
  if ( self . ddt_incomplete ) : oOoO0OooO0O |= 0x800
  if 45 - 45: IiII
  if 24 - 24: oO0o % o0oOOo0O0Ooo + ooOoO0o / II111iiii - ooOoO0o * iII111i
  if 43 - 43: iII111i * i1IIi . I1IiiI . OoOoOO00 / IiII - Oo0Ooo
  if 95 - 95: OoooooooOO % OOooOOo * OOooOOo
  i1I1iiiI = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( i1I1iiiI < 0 ) : i1I1iiiI = LISP_AFI_LCAF
  I1iiIiI1II1ii = ( self . group . is_null ( ) == False )
  if ( I1iiIiI1II1ii ) : i1I1iiiI = LISP_AFI_LCAF
  if 10 - 10: O0 % I11i + I1ii11iIi11i - i11iIiiIii % i1IIi + II111iiii
  iii1I = ( self . signature_count << 12 ) | self . map_version
  OOOoOo0o0Ooo = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 55 - 55: OoOoOO00 * I1Ii111 % OoO0O00 - OoO0O00
  Oo00oo = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , OOOoOo0o0Ooo , socket . htons ( oOoO0OooO0O ) ,
 socket . htons ( iii1I ) , socket . htons ( i1I1iiiI ) )
  if 34 - 34: O0 * OoO0O00 - oO0o - IiII * Ii1I . II111iiii
  if 28 - 28: O0 % iII111i - i1IIi
  if 49 - 49: ooOoO0o . I11i - iIii1I11I1II1
  if 41 - 41: ooOoO0o * i11iIiiIii % ooOoO0o . oO0o
  if ( I1iiIiI1II1ii ) :
   Oo00oo += self . eid . lcaf_encode_sg ( self . group )
   return ( Oo00oo )
   if 97 - 97: oO0o - iII111i + IiII . OoOoOO00 + iIii1I11I1II1
   if 75 - 75: ooOoO0o + ooOoO0o . I1Ii111 % iII111i / iIii1I11I1II1 * iII111i
   if 13 - 13: II111iiii * i11iIiiIii - i1IIi * OoO0O00 + i1IIi
   if 43 - 43: O0 % oO0o * I1IiiI
   if 64 - 64: II111iiii + i11iIiiIii
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   Oo00oo = Oo00oo [ 0 : - 2 ]
   Oo00oo += self . eid . address . encode_geo ( )
   return ( Oo00oo )
   if 17 - 17: O0 * I1IiiI
   if 40 - 40: iIii1I11I1II1 * iII111i % iIii1I11I1II1
   if 39 - 39: i1IIi . Ii1I - Oo0Ooo
   if 91 - 91: I1IiiI - OoooooooOO - OoooooooOO
   if 69 - 69: iII111i * i11iIiiIii / i1IIi
  if ( i1I1iiiI == LISP_AFI_LCAF ) :
   Oo00oo += self . eid . lcaf_encode_iid ( )
   return ( Oo00oo )
   if 86 - 86: I1IiiI % I11i * O0 + i1IIi % I1Ii111
   if 97 - 97: II111iiii * OoOoOO00 - I1Ii111 / i11iIiiIii / OoOoOO00
   if 25 - 25: Oo0Ooo / Oo0Ooo
   if 74 - 74: OOooOOo
   if 30 - 30: O0 . Ii1I / o0oOOo0O0Ooo + I1IiiI - O0
  Oo00oo += self . eid . pack_address ( )
  return ( Oo00oo )
  if 88 - 88: i11iIiiIii
  if 33 - 33: OoO0O00 + O0
 def decode ( self , packet ) :
  iiII1iiI = "IBBHHH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 20 - 20: o0oOOo0O0Ooo % I11i . ooOoO0o - i1IIi . O0
  self . record_ttl , self . rloc_count , self . eid . mask_len , oOoO0OooO0O , self . map_version , self . eid . afi = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 10 - 10: i1IIi
  if 49 - 49: I1Ii111 - Ii1I . O0
  if 46 - 46: OOooOOo
  self . record_ttl = socket . ntohl ( self . record_ttl )
  oOoO0OooO0O = socket . ntohs ( oOoO0OooO0O )
  self . action = ( oOoO0OooO0O >> 13 ) & 0x7
  self . authoritative = True if ( ( oOoO0OooO0O >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( oOoO0OooO0O >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ ooo0000oo0 : : ]
  if 64 - 64: I1IiiI / OoOoOO00
  if 6 - 6: i11iIiiIii - iII111i * i1IIi - iII111i
  if 8 - 8: I11i / i11iIiiIii . O0 / OoO0O00 * oO0o + I1Ii111
  if 91 - 91: I1IiiI
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , oo0oOooo0O = self . eid . lcaf_decode_eid ( packet )
   if ( oo0oOooo0O ) : self . group = oo0oOooo0O
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 2 - 2: IiII + I11i / iIii1I11I1II1 . i11iIiiIii . i1IIi * ooOoO0o
   if 14 - 14: Oo0Ooo . O0 - oO0o - i11iIiiIii
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 8 - 8: I1IiiI / iIii1I11I1II1 / OoooooooOO / Oo0Ooo / ooOoO0o
  if 80 - 80: I11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
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
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 31 - 31: O0 . I1IiiI
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
  if 8 - 8: OoOoOO00
  if 99 - 99: iII111i
 def print_ecm ( self ) :
  IiiiI1 = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 93 - 93: I1Ii111
  lprint ( IiiiI1 . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 39 - 39: Ii1I
  if 10 - 10: OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i % iII111i / i11iIiiIii
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 14 - 14: i11iIiiIii % o0oOOo0O0Ooo * O0 % iIii1I11I1II1 . IiII - II111iiii
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 14 - 14: Ii1I % ooOoO0o - OoOoOO00
   if 52 - 52: OoO0O00 / i1IIi - Ii1I
   if 8 - 8: oO0o + ooOoO0o . I1ii11iIi11i . i1IIi / I1IiiI . IiII
   if 8 - 8: i1IIi * O0
   if 60 - 60: Oo0Ooo - II111iiii + I1IiiI
   if 17 - 17: OoOoOO00 % I1IiiI
  iIiIii = ( LISP_ECM << 28 )
  if ( self . security ) : iIiIii |= 0x08000000
  if ( self . ddt ) : iIiIii |= 0x04000000
  if ( self . to_etr ) : iIiIii |= 0x02000000
  if ( self . to_ms ) : iIiIii |= 0x01000000
  if 8 - 8: Oo0Ooo
  III1iI1III1I1 = struct . pack ( "I" , socket . htonl ( iIiIii ) )
  if 4 - 4: ooOoO0o
  O0O = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   O0O = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   O0O += self . source . pack_address ( )
   O0O += self . dest . pack_address ( )
   O0O = lisp_ip_checksum ( O0O )
   if 71 - 71: I1Ii111 + i1IIi * Oo0Ooo
  if ( self . afi == LISP_AFI_IPV6 ) :
   O0O = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   O0O += self . source . pack_address ( )
   O0O += self . dest . pack_address ( )
   if 51 - 51: OoooooooOO * O0 - OoO0O00 . Oo0Ooo % II111iiii + IiII
   if 48 - 48: IiII . II111iiii - i11iIiiIii * iII111i
  I111 = socket . htons ( self . udp_sport )
  IiI11I111 = socket . htons ( self . udp_dport )
  oOO0O00o0O0 = socket . htons ( self . udp_length )
  I1i11i = socket . htons ( self . udp_checksum )
  O0I1II1 = struct . pack ( "HHHH" , I111 , IiI11I111 , oOO0O00o0O0 , I1i11i )
  return ( III1iI1III1I1 + O0O + O0I1II1 )
  if 51 - 51: OoooooooOO + I11i . iII111i + i11iIiiIii * iII111i - OoO0O00
  if 60 - 60: iII111i * iIii1I11I1II1 . OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
 def decode ( self , packet ) :
  if 36 - 36: i1IIi . OoooooooOO - II111iiii - OoOoOO00 - IiII
  if 53 - 53: I1ii11iIi11i - II111iiii . i11iIiiIii
  if 76 - 76: iIii1I11I1II1 - Oo0Ooo
  if 79 - 79: I1IiiI * IiII . OoooooooOO % I1Ii111 * I1Ii111
  iiII1iiI = "I"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 17 - 17: I1Ii111 - I1Ii111 . oO0o / I1Ii111
  iIiIii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 36 - 36: I1ii11iIi11i * i1IIi + iIii1I11I1II1
  iIiIii = socket . ntohl ( iIiIii [ 0 ] )
  self . security = True if ( iIiIii & 0x08000000 ) else False
  self . ddt = True if ( iIiIii & 0x04000000 ) else False
  self . to_etr = True if ( iIiIii & 0x02000000 ) else False
  self . to_ms = True if ( iIiIii & 0x01000000 ) else False
  packet = packet [ ooo0000oo0 : : ]
  if 55 - 55: I1IiiI . I1Ii111 - I1IiiI % oO0o / iIii1I11I1II1 * Ii1I
  if 77 - 77: OOooOOo
  if 29 - 29: II111iiii % iIii1I11I1II1 * O0 . o0oOOo0O0Ooo
  if 56 - 56: i1IIi . ooOoO0o + I11i - i11iIiiIii
  if ( len ( packet ) < 1 ) : return ( None )
  I1IiI = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  I1IiI = I1IiI >> 4
  if 100 - 100: iIii1I11I1II1 - i1IIi . OOooOOo
  if ( I1IiI == 4 ) :
   ooo0000oo0 = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < ooo0000oo0 ) : return ( None )
   if 73 - 73: I1Ii111 / I11i / i11iIiiIii - I1ii11iIi11i % ooOoO0o
   Oo0OoO00O , oOO0O00o0O0 , Oo0OoO00O , IIiIIiiiiI , iIIiiIi , I1i11i = struct . unpack ( "HHIBBH" , packet [ : ooo0000oo0 ] )
   self . length = socket . ntohs ( oOO0O00o0O0 )
   self . ttl = IIiIIiiiiI
   self . protocol = iIIiiIi
   self . ip_checksum = socket . ntohs ( I1i11i )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 24 - 24: IiII + I1IiiI . O0 + OOooOOo / O0
   if 59 - 59: i1IIi . II111iiii . Oo0Ooo + oO0o
   if 65 - 65: I1IiiI / OoOoOO00 % I1IiiI * i11iIiiIii * OoooooooOO / I11i
   if 91 - 91: i11iIiiIii / i11iIiiIii
   iIIiiIi = struct . pack ( "H" , 0 )
   I1I1I = struct . calcsize ( "HHIBB" )
   Ii11I = struct . calcsize ( "H" )
   packet = packet [ : I1I1I ] + iIIiiIi + packet [ I1I1I + Ii11I : ]
   if 84 - 84: OoooooooOO + OoOoOO00 . Ii1I / i1IIi
   packet = packet [ ooo0000oo0 : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 15 - 15: II111iiii % i1IIi / oO0o . iIii1I11I1II1 * Oo0Ooo
   if 5 - 5: iII111i
  if ( I1IiI == 6 ) :
   ooo0000oo0 = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < ooo0000oo0 ) : return ( None )
   if 61 - 61: OOooOOo * OoO0O00 - O0
   Oo0OoO00O , oOO0O00o0O0 , iIIiiIi , IIiIIiiiiI = struct . unpack ( "IHBB" , packet [ : ooo0000oo0 ] )
   self . length = socket . ntohs ( oOO0O00o0O0 )
   self . protocol = iIIiiIi
   self . ttl = IIiIIiiiiI
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 30 - 30: iIii1I11I1II1
   packet = packet [ ooo0000oo0 : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 14 - 14: o0oOOo0O0Ooo + Ii1I
   if 91 - 91: OoooooooOO / oO0o + OoOoOO00
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 100 - 100: i1IIi
  ooo0000oo0 = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 13 - 13: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo
  I111 , IiI11I111 , oOO0O00o0O0 , I1i11i = struct . unpack ( "HHHH" , packet [ : ooo0000oo0 ] )
  self . udp_sport = socket . ntohs ( I111 )
  self . udp_dport = socket . ntohs ( IiI11I111 )
  self . udp_length = socket . ntohs ( oOO0O00o0O0 )
  self . udp_checksum = socket . ntohs ( I1i11i )
  packet = packet [ ooo0000oo0 : : ]
  return ( packet )
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
  if 30 - 30: II111iiii
  if 26 - 26: I11i - i1IIi - Oo0Ooo * O0 * OOooOOo . OoooooooOO
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  oOo = self . rloc_name
  if ( cour ) : oOo = lisp_print_cour ( oOo )
  return ( 'rloc-name: {}' . format ( blue ( oOo , cour ) ) )
  if 41 - 41: OOooOOo . iIii1I11I1II1 + ooOoO0o * I1Ii111 % i1IIi
  if 17 - 17: OoO0O00
 def print_record ( self , indent ) :
  IIIOo0O = self . print_rloc_name ( )
  if ( IIIOo0O != "" ) : IIIOo0O = ", " + IIIOo0O
  oOIIi = ""
  if ( self . geo ) :
   ooO0o = ""
   if ( self . geo . geo_name ) : ooO0o = "'{}' " . format ( self . geo . geo_name )
   oOIIi = ", geo: {}{}" . format ( ooO0o , self . geo . print_geo ( ) )
   if 3 - 3: o0oOOo0O0Ooo
  iIII1Iiii = ""
  if ( self . elp ) :
   ooO0o = ""
   if ( self . elp . elp_name ) : ooO0o = "'{}' " . format ( self . elp . elp_name )
   iIII1Iiii = ", elp: {}{}" . format ( ooO0o , self . elp . print_elp ( True ) )
   if 2 - 2: Ii1I . iII111i + OoOoOO00 / IiII - I1IiiI % I1IiiI
  IIIi1iI1 = ""
  if ( self . rle ) :
   ooO0o = ""
   if ( self . rle . rle_name ) : ooO0o = "'{}' " . format ( self . rle . rle_name )
   IIIi1iI1 = ", rle: {}{}" . format ( ooO0o , self . rle . print_rle ( False ,
 True ) )
   if 21 - 21: OOooOOo % O0 / I11i
  IiiiIiii = ""
  if ( self . json ) :
   ooO0o = ""
   if ( self . json . json_name ) :
    ooO0o = "'{}' " . format ( self . json . json_name )
    if 76 - 76: i1IIi
   IiiiIiii = ", json: {}" . format ( self . json . print_json ( False ) )
   if 38 - 38: I1IiiI
   if 15 - 15: o0oOOo0O0Ooo
  ooOoOO0Oo0oO0o = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   ooOoOO0Oo0oO0o = ", " + self . keys [ 1 ] . print_keys ( )
   if 94 - 94: Oo0Ooo / I11i . I1ii11iIi11i
   if 31 - 31: i11iIiiIii + iIii1I11I1II1 . II111iiii
  IiiiI1 = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( IiiiI1 . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , IIIOo0O , oOIIi ,
 iIII1Iiii , IIIi1iI1 , IiiiIiii , ooOoOO0Oo0oO0o ) )
  if 72 - 72: I1Ii111 * OoO0O00 + Oo0Ooo / Ii1I % OOooOOo
  if 84 - 84: OoOoOO00 / o0oOOo0O0Ooo
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 9 - 9: Ii1I
  if 76 - 76: I1IiiI % Oo0Ooo / iIii1I11I1II1 - Oo0Ooo
  if 34 - 34: OoOoOO00 - i1IIi + OOooOOo + Ii1I . o0oOOo0O0Ooo
 def store_rloc_entry ( self , rloc_entry ) :
  iIIiI11 = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 45 - 45: Oo0Ooo . i1IIi
  self . rloc . copy_address ( iIIiI11 )
  if 10 - 10: OoOoOO00 * ooOoO0o / iIii1I11I1II1 . OOooOOo
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 93 - 93: Oo0Ooo / II111iiii . Oo0Ooo + i1IIi + i1IIi
   if 30 - 30: OoOoOO00 . OOooOOo % OOooOOo / II111iiii + i1IIi
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   ooO0o = rloc_entry . geo_name
   if ( ooO0o and ooO0o in lisp_geo_list ) :
    self . geo = lisp_geo_list [ ooO0o ]
    if 61 - 61: i1IIi % II111iiii * II111iiii . o0oOOo0O0Ooo / I1ii11iIi11i - I1Ii111
    if 93 - 93: Ii1I - i1IIi
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   ooO0o = rloc_entry . elp_name
   if ( ooO0o and ooO0o in lisp_elp_list ) :
    self . elp = lisp_elp_list [ ooO0o ]
    if 3 - 3: oO0o + OoO0O00 - iII111i / Ii1I
    if 58 - 58: Ii1I * I11i
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   ooO0o = rloc_entry . rle_name
   if ( ooO0o and ooO0o in lisp_rle_list ) :
    self . rle = lisp_rle_list [ ooO0o ]
    if 95 - 95: oO0o
    if 49 - 49: I1IiiI
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   ooO0o = rloc_entry . json_name
   if ( ooO0o and ooO0o in lisp_json_list ) :
    self . json = lisp_json_list [ ooO0o ]
    if 23 - 23: I1Ii111
    if 5 - 5: I1ii11iIi11i % OoOoOO00 . OoooooooOO . o0oOOo0O0Ooo + i11iIiiIii
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 54 - 54: ooOoO0o - O0 + iII111i
  if 34 - 34: Ii1I - OOooOOo % iII111i
 def encode_json ( self , lisp_json ) :
  OoOo00OO0o00 = lisp_json . json_string
  iIii1iii1 = 0
  if ( lisp_json . json_encrypted ) :
   iIii1iii1 = ( lisp_json . json_key_id << 5 ) | 0x02
   if 80 - 80: I11i + o0oOOo0O0Ooo - I1Ii111 . OoO0O00 * oO0o + OOooOOo
   if 96 - 96: i1IIi + i1IIi * I1ii11iIi11i . Oo0Ooo * Oo0Ooo
  ooOoOoOo = LISP_LCAF_JSON_TYPE
  ii1 = socket . htons ( LISP_AFI_LCAF )
  OoOOo0Oo0o0 = self . rloc . addr_length ( ) + 2
  if 72 - 72: O0 * I1Ii111 - iIii1I11I1II1 % i1IIi
  iIIIi1Iii1 = socket . htons ( len ( OoOo00OO0o00 ) + OoOOo0Oo0o0 )
  if 83 - 83: OoOoOO00 + OOooOOo / OoooooooOO
  oOoOOOo0oo = socket . htons ( len ( OoOo00OO0o00 ) )
  Oo00oo = struct . pack ( "HBBBBHH" , ii1 , 0 , 0 , ooOoOoOo , iIii1iii1 ,
 iIIIi1Iii1 , oOoOOOo0oo )
  Oo00oo += OoOo00OO0o00 . encode ( )
  if 39 - 39: OoO0O00 % iII111i . oO0o . II111iiii - i11iIiiIii
  if 85 - 85: O0 - OoOoOO00
  if 17 - 17: o0oOOo0O0Ooo / i1IIi / OOooOOo
  if 91 - 91: I1ii11iIi11i / Ii1I - OoOoOO00 . I11i / oO0o
  if ( lisp_is_json_telemetry ( OoOo00OO0o00 ) ) :
   Oo00oo += struct . pack ( "H" , socket . htons ( self . rloc . afi ) )
   Oo00oo += self . rloc . pack_address ( )
  else :
   Oo00oo += struct . pack ( "H" , 0 )
   if 16 - 16: IiII % iII111i . oO0o . I1IiiI % O0 * I11i
  return ( Oo00oo )
  if 99 - 99: OoOoOO00 / OoooooooOO + iII111i * I11i * i11iIiiIii + OOooOOo
  if 40 - 40: II111iiii / I11i % I1IiiI - O0
 def encode_lcaf ( self ) :
  ii1 = socket . htons ( LISP_AFI_LCAF )
  Ii1IIII1i = b""
  if ( self . geo ) :
   Ii1IIII1i = self . geo . encode_geo ( )
   if 59 - 59: IiII / OoOoOO00 - I1Ii111 - ooOoO0o . oO0o
   if 87 - 87: oO0o + I1IiiI * I1Ii111 * o0oOOo0O0Ooo + O0
  I1IIiIi = b""
  if ( self . elp ) :
   iiII11iI11i1I = b""
   for oo0o in self . elp . elp_nodes :
    i1I1iiiI = socket . htons ( oo0o . address . afi )
    Ooo0000o = 0
    if ( oo0o . eid ) : Ooo0000o |= 0x4
    if ( oo0o . probe ) : Ooo0000o |= 0x2
    if ( oo0o . strict ) : Ooo0000o |= 0x1
    Ooo0000o = socket . htons ( Ooo0000o )
    iiII11iI11i1I += struct . pack ( "HH" , Ooo0000o , i1I1iiiI )
    iiII11iI11i1I += oo0o . address . pack_address ( )
    if 55 - 55: II111iiii / ooOoO0o / II111iiii * OOooOOo
    if 67 - 67: II111iiii
   OOii1II1IiIIiI = socket . htons ( len ( iiII11iI11i1I ) )
   I1IIiIi = struct . pack ( "HBBBBH" , ii1 , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , OOii1II1IiIIiI )
   I1IIiIi += iiII11iI11i1I
   if 20 - 20: IiII % I1IiiI + iIii1I11I1II1 % iII111i
   if 100 - 100: o0oOOo0O0Ooo - Oo0Ooo % I1Ii111 . i11iIiiIii % OoooooooOO
  II1i = b""
  if ( self . rle ) :
   oOO0Oo = b""
   for iIIi in self . rle . rle_nodes :
    i1I1iiiI = socket . htons ( iIIi . address . afi )
    oOO0Oo += struct . pack ( "HBBH" , 0 , 0 , iIIi . level , i1I1iiiI )
    oOO0Oo += iIIi . address . pack_address ( )
    if ( iIIi . rloc_name ) :
     oOO0Oo += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     oOO0Oo += ( iIIi . rloc_name + "\0" ) . encode ( )
     if 7 - 7: OoooooooOO % iII111i % Ii1I % II111iiii / oO0o
     if 15 - 15: OoO0O00
     if 18 - 18: OoooooooOO / OOooOOo % i1IIi - i1IIi / Oo0Ooo
   O0ooO0 = socket . htons ( len ( oOO0Oo ) )
   II1i = struct . pack ( "HBBBBH" , ii1 , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , O0ooO0 )
   II1i += oOO0Oo
   if 82 - 82: I1ii11iIi11i / Oo0Ooo
   if 63 - 63: I1IiiI
  i1II11 = b""
  if ( self . json ) :
   i1II11 = self . encode_json ( self . json )
   if 64 - 64: ooOoO0o % IiII - iII111i * i1IIi * I1Ii111 + IiII
   if 43 - 43: O0 / IiII
  i1Ii11I = b""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   i1Ii11I = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 14 - 14: I1Ii111 + I11i * OoO0O00 - Oo0Ooo
   if 97 - 97: oO0o - i11iIiiIii / I11i
  I11Ii1I1i = b""
  if ( self . rloc_name ) :
   I11Ii1I1i += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   I11Ii1I1i += ( self . rloc_name + "\0" ) . encode ( )
   if 97 - 97: Ii1I - ooOoO0o
   if 94 - 94: OoOoOO00 + OoO0O00 + I1IiiI
  oOooOoO0oo = len ( Ii1IIII1i ) + len ( I1IIiIi ) + len ( II1i ) + len ( i1Ii11I ) + 2 + len ( i1II11 ) + self . rloc . addr_length ( ) + len ( I11Ii1I1i )
  if 21 - 21: oO0o - o0oOOo0O0Ooo + ooOoO0o . I1IiiI * oO0o * Ii1I
  oOooOoO0oo = socket . htons ( oOooOoO0oo )
  IiIi11iiIi1 = struct . pack ( "HBBBBHH" , ii1 , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , oOooOoO0oo , socket . htons ( self . rloc . afi ) )
  IiIi11iiIi1 += self . rloc . pack_address ( )
  return ( IiIi11iiIi1 + I11Ii1I1i + Ii1IIII1i + I1IIiIi + II1i + i1Ii11I + i1II11 )
  if 54 - 54: OoO0O00 / I1IiiI
  if 4 - 4: O0
 def encode ( self ) :
  Ooo0000o = 0
  if ( self . local_bit ) : Ooo0000o |= 0x0004
  if ( self . probe_bit ) : Ooo0000o |= 0x0002
  if ( self . reach_bit ) : Ooo0000o |= 0x0001
  if 87 - 87: IiII - OoO0O00 * Oo0Ooo / o0oOOo0O0Ooo % oO0o % Ii1I
  Oo00oo = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( Ooo0000o ) ,
 socket . htons ( self . rloc . afi ) )
  if 25 - 25: Ii1I - I1ii11iIi11i + Oo0Ooo . I1IiiI
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 36 - 36: iII111i
   try :
    Oo00oo = Oo00oo [ 0 : - 2 ] + self . encode_lcaf ( )
   except :
    lprint ( "Could not encode LCAF for RLOC-record" )
    if 3 - 3: Ii1I
  else :
   Oo00oo += self . rloc . pack_address ( )
   if 44 - 44: O0 - oO0o % II111iiii . I1Ii111
  return ( Oo00oo )
  if 86 - 86: IiII
  if 71 - 71: Ii1I - i1IIi . I1IiiI
 def decode_lcaf ( self , packet , nonce , ms_json_encrypt ) :
  iiII1iiI = "HBBBBH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
  i1I1iiiI , Ii1Ii1Ii , Ooo0000o , ooOoOoOo , ii11Ii1111 , iIIIi1Iii1 = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 54 - 54: i1IIi . OoO0O00 + iII111i + OoO0O00 * i1IIi
  if 13 - 13: Oo0Ooo / OoO0O00 + OOooOOo
  iIIIi1Iii1 = socket . ntohs ( iIIIi1Iii1 )
  packet = packet [ ooo0000oo0 : : ]
  if ( iIIIi1Iii1 > len ( packet ) ) : return ( None )
  if 90 - 90: OoO0O00 * i11iIiiIii / oO0o
  if 91 - 91: iII111i - OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
  if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
  if 25 - 25: OoOoOO00 + IiII . i11iIiiIii
  if ( ooOoOoOo == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( iIIIi1Iii1 > 0 ) :
    iiII1iiI = "H"
    ooo0000oo0 = struct . calcsize ( iiII1iiI )
    if ( iIIIi1Iii1 < ooo0000oo0 ) : return ( None )
    if 87 - 87: I1IiiI + OoooooooOO + O0
    oo = len ( packet )
    i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
    i1I1iiiI = socket . ntohs ( i1I1iiiI )
    if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
    if ( i1I1iiiI == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ ooo0000oo0 : : ]
     self . rloc_name = None
     if ( i1I1iiiI == LISP_AFI_NAME ) :
      packet , oOo = lisp_decode_dist_name ( packet )
      self . rloc_name = oOo
     else :
      self . rloc . afi = i1I1iiiI
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 65 - 65: IiII
      if 74 - 74: Oo0Ooo + i1IIi - II111iiii / ooOoO0o / iII111i
      if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
    iIIIi1Iii1 -= oo - len ( packet )
    if 42 - 42: I1Ii111 - i11iIiiIii % II111iiii * ooOoO0o . O0 % I11i
    if 82 - 82: Oo0Ooo % O0 + I1ii11iIi11i % I1ii11iIi11i
  elif ( ooOoOoOo == LISP_LCAF_GEO_COORD_TYPE ) :
   if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
   if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
   if 29 - 29: Oo0Ooo - Ii1I - Oo0Ooo
   if 89 - 89: Oo0Ooo . OoO0O00 . I1ii11iIi11i * oO0o . O0
   Ooo0O00o00 = lisp_geo ( "" )
   packet = Ooo0O00o00 . decode_geo ( packet , iIIIi1Iii1 , ii11Ii1111 )
   if ( packet == None ) : return ( None )
   self . geo = Ooo0O00o00
   if 63 - 63: O0 * O0 . IiII
  elif ( ooOoOoOo == LISP_LCAF_JSON_TYPE ) :
   oo0oO = ii11Ii1111 & 0x02
   if 10 - 10: I1IiiI % II111iiii / I1IiiI
   if 13 - 13: II111iiii - i11iIiiIii
   if 90 - 90: I11i . OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
   if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
   iiII1iiI = "H"
   ooo0000oo0 = struct . calcsize ( iiII1iiI )
   if ( iIIIi1Iii1 < ooo0000oo0 ) : return ( None )
   if 95 - 95: iII111i / ooOoO0o + I1Ii111
   oOoOOOo0oo = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
   oOoOOOo0oo = socket . ntohs ( oOoOOOo0oo )
   if ( iIIIi1Iii1 < ooo0000oo0 + oOoOOOo0oo ) : return ( None )
   if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
   packet = packet [ ooo0000oo0 : : ]
   self . json = lisp_json ( "" , packet [ 0 : oOoOOOo0oo ] , oo0oO ,
 ms_json_encrypt )
   packet = packet [ oOoOOOo0oo : : ]
   if 81 - 81: I1ii11iIi11i
   if 31 - 31: O0 % ooOoO0o / I1IiiI * iII111i % iIii1I11I1II1 * OoOoOO00
   if 76 - 76: I1Ii111 - O0
   if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
   i1I1iiiI = socket . ntohs ( struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ] )
   packet = packet [ 2 : : ]
   if 7 - 7: II111iiii + I11i
   if ( i1I1iiiI != 0 and lisp_is_json_telemetry ( self . json . json_string ) ) :
    self . rloc . afi = i1I1iiiI
    packet = self . rloc . unpack_address ( packet )
    if 99 - 99: iIii1I11I1II1 * oO0o
    if 37 - 37: ooOoO0o * iII111i * I11i
  elif ( ooOoOoOo == LISP_LCAF_ELP_TYPE ) :
   if 11 - 11: I1IiiI
   if 48 - 48: O0 . I11i
   if 9 - 9: oO0o / Oo0Ooo
   if 85 - 85: i11iIiiIii / I1IiiI . OoO0O00 . I11i . oO0o * IiII
   I1iI1 = lisp_elp ( None )
   I1iI1 . elp_nodes = [ ]
   while ( iIIIi1Iii1 > 0 ) :
    Ooo0000o , i1I1iiiI = struct . unpack ( "HH" , packet [ : 4 ] )
    if 44 - 44: ooOoO0o / Ii1I / OoooooooOO % iIii1I11I1II1 - I1Ii111
    i1I1iiiI = socket . ntohs ( i1I1iiiI )
    if ( i1I1iiiI == LISP_AFI_LCAF ) : return ( None )
    if 86 - 86: O0 + O0 / I11i - iIii1I11I1II1
    oo0o = lisp_elp_node ( )
    I1iI1 . elp_nodes . append ( oo0o )
    if 42 - 42: OOooOOo
    Ooo0000o = socket . ntohs ( Ooo0000o )
    oo0o . eid = ( Ooo0000o & 0x4 )
    oo0o . probe = ( Ooo0000o & 0x2 )
    oo0o . strict = ( Ooo0000o & 0x1 )
    oo0o . address . afi = i1I1iiiI
    oo0o . address . mask_len = oo0o . address . host_mask_len ( )
    packet = oo0o . address . unpack_address ( packet [ 4 : : ] )
    iIIIi1Iii1 -= oo0o . address . addr_length ( ) + 4
    if 39 - 39: O0 % Ii1I . I11i * o0oOOo0O0Ooo
   I1iI1 . select_elp_node ( )
   self . elp = I1iI1
   if 14 - 14: I11i . iIii1I11I1II1 + I1Ii111 % OoooooooOO
  elif ( ooOoOoOo == LISP_LCAF_RLE_TYPE ) :
   if 9 - 9: oO0o + Ii1I / I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo
   if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
   if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
   if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
   ooo0o0O = lisp_rle ( None )
   ooo0o0O . rle_nodes = [ ]
   while ( iIIIi1Iii1 > 0 ) :
    Oo0OoO00O , ii1I1I1iII , ii11i , i1I1iiiI = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 42 - 42: OoOoOO00 / iII111i + OOooOOo
    i1I1iiiI = socket . ntohs ( i1I1iiiI )
    if ( i1I1iiiI == LISP_AFI_LCAF ) : return ( None )
    if 61 - 61: i11iIiiIii % oO0o * ooOoO0o
    iIIi = lisp_rle_node ( )
    ooo0o0O . rle_nodes . append ( iIIi )
    if 59 - 59: OOooOOo + i1IIi
    iIIi . level = ii11i
    iIIi . address . afi = i1I1iiiI
    iIIi . address . mask_len = iIIi . address . host_mask_len ( )
    packet = iIIi . address . unpack_address ( packet [ 6 : : ] )
    if 10 - 10: Oo0Ooo - i1IIi % I1ii11iIi11i
    iIIIi1Iii1 -= iIIi . address . addr_length ( ) + 6
    if ( iIIIi1Iii1 >= 2 ) :
     i1I1iiiI = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( i1I1iiiI ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , iIIi . rloc_name = lisp_decode_dist_name ( packet )
      if 54 - 54: IiII + OOooOOo + oO0o * O0 % ooOoO0o + OoO0O00
      if ( packet == None ) : return ( None )
      iIIIi1Iii1 -= len ( iIIi . rloc_name ) + 1 + 2
      if 13 - 13: i11iIiiIii * O0 . OoooooooOO % I1Ii111 + I1ii11iIi11i + OOooOOo
      if 45 - 45: oO0o % i11iIiiIii / Ii1I / IiII % Ii1I - Ii1I
      if 73 - 73: I1ii11iIi11i * I1ii11iIi11i / II111iiii % iII111i
   self . rle = ooo0o0O
   self . rle . build_forwarding_list ( )
   if 74 - 74: OoO0O00 / I1ii11iIi11i - ooOoO0o * i1IIi + I1ii11iIi11i . I11i
  elif ( ooOoOoOo == LISP_LCAF_SECURITY_TYPE ) :
   if 13 - 13: iII111i + o0oOOo0O0Ooo / iII111i - Ii1I - iII111i
   if 34 - 34: IiII . OOooOOo + OOooOOo - OoooooooOO * I1Ii111
   if 72 - 72: iIii1I11I1II1 % i1IIi / OoO0O00 / I1IiiI - II111iiii - I1Ii111
   if 43 - 43: o0oOOo0O0Ooo - Oo0Ooo - I1ii11iIi11i / II111iiii + I1IiiI / I1ii11iIi11i
   if 34 - 34: Oo0Ooo
   i1o0o0oOO = packet
   iIiiIi1111ii = lisp_keys ( 1 )
   packet = iIiiIi1111ii . decode_lcaf ( i1o0o0oOO , iIIIi1Iii1 )
   if ( packet == None ) : return ( None )
   if 21 - 21: I1IiiI / I1IiiI % I1Ii111 - OoOoOO00 % OoOoOO00 - II111iiii
   if 97 - 97: oO0o
   if 98 - 98: I1Ii111 * I1IiiI + iIii1I11I1II1
   if 75 - 75: oO0o
   OoOO0Ooo = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( iIiiIi1111ii . cipher_suite in OoOO0Ooo ) :
    if ( iIiiIi1111ii . cipher_suite == LISP_CS_25519_CBC ) :
     III = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 50 - 50: oO0o / Oo0Ooo
    if ( iIiiIi1111ii . cipher_suite == LISP_CS_25519_CHACHA ) :
     III = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 32 - 32: OoO0O00 % oO0o * I1ii11iIi11i + I11i / I1Ii111
   else :
    III = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 5 - 5: o0oOOo0O0Ooo + iII111i / OoooooooOO + Ii1I . OoOoOO00 / oO0o
   packet = III . decode_lcaf ( i1o0o0oOO , iIIIi1Iii1 )
   if ( packet == None ) : return ( None )
   if 18 - 18: II111iiii . o0oOOo0O0Ooo
   if ( len ( packet ) < 2 ) : return ( None )
   i1I1iiiI = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( i1I1iiiI )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 75 - 75: OoooooooOO - Oo0Ooo
   if 56 - 56: II111iiii - i11iIiiIii - oO0o . o0oOOo0O0Ooo
   if 4 - 4: i1IIi
   if 91 - 91: IiII . OoO0O00 * Ii1I / o0oOOo0O0Ooo
   if 41 - 41: I1IiiI . OoO0O00 / i1IIi . Oo0Ooo . oO0o
   if 44 - 44: iII111i * I11i + i11iIiiIii + i1IIi / IiII * II111iiii
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 58 - 58: OOooOOo
   OOO00O = self . rloc_name
   if ( OOO00O ) : OOO00O = blue ( self . rloc_name , False )
   if 5 - 5: I1Ii111 * I11i * oO0o * I1ii11iIi11i - OOooOOo * OoOoOO00
   if 88 - 88: OoooooooOO . II111iiii / Oo0Ooo * OoOoOO00
   if 52 - 52: OoO0O00 + oO0o
   if 84 - 84: O0 % I1ii11iIi11i % iIii1I11I1II1 - OoOoOO00 - Oo0Ooo
   if 7 - 7: II111iiii % oO0o % i1IIi . iIii1I11I1II1
   if 92 - 92: Ii1I / o0oOOo0O0Ooo % OOooOOo - OoOoOO00
   I1 = self . keys [ 1 ] if self . keys else None
   if ( I1 == None ) :
    if ( III . remote_public_key == None ) :
     i1i111III1 = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( i1i111III1 , OOO00O ) )
     III = None
    else :
     i1i111III1 = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( i1i111III1 , OOO00O ) )
     III . compute_shared_key ( "encap" )
     if 44 - 44: I1IiiI + OoOoOO00 * Oo0Ooo
     if 31 - 31: I11i - I1IiiI - OoO0O00 * OoOoOO00
     if 50 - 50: I1ii11iIi11i + I11i * iII111i
     if 27 - 27: OoOoOO00 * OOooOOo * iIii1I11I1II1 / i1IIi
     if 60 - 60: OOooOOo * I1Ii111 . oO0o
     if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
     if 51 - 51: I1IiiI . I11i - OoOoOO00
     if 10 - 10: Oo0Ooo * OOooOOo / IiII . o0oOOo0O0Ooo
     if 97 - 97: Ii1I . Ii1I % iII111i
     if 49 - 49: Oo0Ooo % OOooOOo - OoooooooOO + IiII
   if ( I1 ) :
    if ( III . remote_public_key == None ) :
     III = None
     oO = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( oO , OOO00O ) )
    elif ( I1 . compare_keys ( III ) ) :
     III = I1
     lprint ( "    Maintain stored encap-keys for {}" . format ( OOO00O ) )
     if 54 - 54: iIii1I11I1II1 - OoooooooOO / I11i / oO0o % I1IiiI + OoOoOO00
    else :
     if ( I1 . remote_public_key == None ) :
      i1i111III1 = "New encap-keying for existing state"
     else :
      i1i111III1 = "Remote encap-rekeying"
      if 26 - 26: OoO0O00 * II111iiii % OOooOOo * iII111i + iII111i
     lprint ( "    {} for {}" . format ( bold ( i1i111III1 , False ) ,
 OOO00O ) )
     I1 . remote_public_key = III . remote_public_key
     I1 . compute_shared_key ( "encap" )
     III = I1
     if 25 - 25: I11i - I1ii11iIi11i
     if 100 - 100: I1Ii111 / Ii1I + OoOoOO00 . OoooooooOO
   self . keys = [ None , III , None , None ]
   if 83 - 83: O0
  else :
   if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
   if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
   if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
   if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
   packet = packet [ iIIIi1Iii1 : : ]
   if 46 - 46: o0oOOo0O0Ooo
  return ( packet )
  if 28 - 28: i1IIi
  if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
 def decode ( self , packet , nonce , ms_json_encrypt = False ) :
  iiII1iiI = "BBBBHH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 62 - 62: I1Ii111 * I11i / I11i
  self . priority , self . weight , self . mpriority , self . mweight , Ooo0000o , i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 42 - 42: ooOoO0o * ooOoO0o / Ii1I / OOooOOo * OOooOOo
  if 92 - 92: Oo0Ooo / iII111i - OoooooooOO - o0oOOo0O0Ooo % ooOoO0o
  Ooo0000o = socket . ntohs ( Ooo0000o )
  i1I1iiiI = socket . ntohs ( i1I1iiiI )
  self . local_bit = True if ( Ooo0000o & 0x0004 ) else False
  self . probe_bit = True if ( Ooo0000o & 0x0002 ) else False
  self . reach_bit = True if ( Ooo0000o & 0x0001 ) else False
  if 35 - 35: i1IIi % iII111i % I11i * iIii1I11I1II1 % Ii1I - Oo0Ooo
  if ( i1I1iiiI == LISP_AFI_LCAF ) :
   packet = packet [ ooo0000oo0 - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
  else :
   self . rloc . afi = i1I1iiiI
   packet = packet [ ooo0000oo0 : : ]
   packet = self . rloc . unpack_address ( packet )
   if 94 - 94: iII111i
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 68 - 68: OoooooooOO % OOooOOo / OoooooooOO / I1Ii111 + Ii1I - o0oOOo0O0Ooo
  if 81 - 81: I1IiiI
 def end_of_rlocs ( self , packet , rloc_count ) :
  for iIi1iIIIiIiI in range ( rloc_count ) :
   packet = self . decode ( packet , None , False )
   if ( packet == None ) : return ( None )
   if 62 - 62: Ii1I * OoOoOO00
  return ( packet )
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
class lisp_map_referral ( object ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 50 - 50: OOooOOo * I1IiiI / o0oOOo0O0Ooo
  if 91 - 91: iIii1I11I1II1 / OOooOOo * O0 . o0oOOo0O0Ooo + oO0o / I1ii11iIi11i
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # Oo0Ooo / II111iiii
 lisp_hex_string ( self . nonce ) ) )
  if 76 - 76: OoOoOO00 % OoO0O00 * O0
  if 39 - 39: ooOoO0o / iII111i
 def encode ( self ) :
  iIiIii = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  Oo00oo = struct . pack ( "I" , socket . htonl ( iIiIii ) )
  Oo00oo += struct . pack ( "Q" , self . nonce )
  return ( Oo00oo )
  if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
  if 59 - 59: I11i % Ii1I / OoOoOO00
 def decode ( self , packet ) :
  iiII1iiI = "I"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
  iIiIii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  iIiIii = socket . ntohl ( iIiIii [ 0 ] )
  self . record_count = iIiIii & 0xff
  packet = packet [ ooo0000oo0 : : ]
  if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
  iiII1iiI = "Q"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
  self . nonce = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  return ( packet )
  if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
  if 80 - 80: Oo0Ooo
  if 58 - 58: I1Ii111 + OOooOOo
  if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
  if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
  if 41 - 41: Ii1I . OoO0O00 + I1ii11iIi11i + OoOoOO00
  if 76 - 76: iII111i - iIii1I11I1II1
  if 23 - 23: I11i / OoO0O00 % OOooOOo
class lisp_ddt_entry ( object ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 9 - 9: ooOoO0o % I1ii11iIi11i . OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
  if 21 - 21: Ii1I % O0
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 15 - 15: II111iiii * Ii1I + IiII % iII111i
  if 96 - 96: II111iiii * I1Ii111 / Oo0Ooo
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 35 - 35: I1IiiI
  if 54 - 54: I1ii11iIi11i % o0oOOo0O0Ooo . i1IIi
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  o0oO0OO0Oo0 = self . delegation_set [ 0 ]
  return ( o0oO0OO0Oo0 . print_node_type ( ) )
  if 64 - 64: i11iIiiIii - Oo0Ooo / iIii1I11I1II1 / I1IiiI % ooOoO0o
  if 42 - 42: Oo0Ooo * OoOoOO00 % ooOoO0o * oO0o - Oo0Ooo + OOooOOo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 5 - 5: OoooooooOO * O0 / I1Ii111 + ooOoO0o . I1Ii111
  if 57 - 57: ooOoO0o * OOooOOo % OoOoOO00 - OoOoOO00 - o0oOOo0O0Ooo * i1IIi
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   o0O0o0OOOoO = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( o0O0o0OOOoO == None ) :
    o0O0o0OOOoO = lisp_ddt_entry ( )
    o0O0o0OOOoO . eid . copy_address ( self . group )
    o0O0o0OOOoO . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , o0O0o0OOOoO )
    if 24 - 24: o0oOOo0O0Ooo - i11iIiiIii + i11iIiiIii . I1IiiI - OOooOOo
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( o0O0o0OOOoO . group )
   o0O0o0OOOoO . add_source_entry ( self )
   if 16 - 16: OOooOOo
   if 74 - 74: I11i . II111iiii + O0 * II111iiii
   if 50 - 50: IiII
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 7 - 7: OoO0O00 / I1IiiI * Ii1I % OoO0O00 + OoO0O00 % II111iiii
  if 83 - 83: O0 % o0oOOo0O0Ooo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 77 - 77: I1Ii111 - OoooooooOO
  if 2 - 2: OoOoOO00 - OOooOOo * o0oOOo0O0Ooo / OoO0O00 - IiII % I1IiiI
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 98 - 98: iIii1I11I1II1
  if 49 - 49: I1IiiI - I11i
  if 63 - 63: i11iIiiIii . OoO0O00 . oO0o
class lisp_ddt_node ( object ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 85 - 85: oO0o . I1ii11iIi11i + i11iIiiIii
  if 85 - 85: I11i
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 36 - 36: ooOoO0o % OoO0O00
  if 1 - 1: OoooooooOO - OoOoOO00
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 35 - 35: I1Ii111
  if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
  if 92 - 92: iII111i % I1ii11iIi11i
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 16 - 16: oO0o
  if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
  if 24 - 24: Ii1I + IiII + OoooooooOO / oO0o / I1IiiI + IiII
  if 52 - 52: ooOoO0o
  if 38 - 38: OoO0O00 + I1IiiI % IiII
  if 87 - 87: oO0o * Ii1I - I1Ii111 / oO0o
  if 65 - 65: OoOoOO00
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
  if 87 - 87: I11i - i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
  if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # I1Ii111 * iIii1I11I1II1 % I1Ii111 / OoOoOO00 . iII111i
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 40 - 40: ooOoO0o / I1ii11iIi11i / IiII % o0oOOo0O0Ooo - oO0o . i1IIi
  if 98 - 98: II111iiii * OoooooooOO % oO0o - iII111i
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 97 - 97: OoO0O00 / OOooOOo + Ii1I % O0
  if 36 - 36: OoooooooOO . I1Ii111 + OoOoOO00 % OoO0O00 % I11i . iIii1I11I1II1
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( self . nonce in lisp_ddt_map_requestQ ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 57 - 57: oO0o % iII111i + IiII + oO0o
   if 31 - 31: iII111i + I1IiiI % OOooOOo
   if 6 - 6: i1IIi / OoOoOO00 + I11i . OoO0O00 . iII111i * II111iiii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 58 - 58: i1IIi / I1ii11iIi11i - IiII / I11i
  if 68 - 68: OOooOOo % OoOoOO00 / I1IiiI % iII111i / O0 % i1IIi
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
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 71 - 71: iII111i . OoO0O00 + ooOoO0o - OOooOOo - Oo0Ooo
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
  if 94 - 94: I1IiiI / I1ii11iIi11i / OOooOOo
  if 45 - 45: II111iiii
 def print_info ( self ) :
  if ( self . info_reply ) :
   Oo0OoO = "Info-Reply"
   iIIiI11 = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # O0 * Oo0Ooo - ooOoO0o
   # I1IiiI . IiII - i11iIiiIii . I1Ii111
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : iIIiI11 += "empty, "
   for iiO0ooooOooo in self . rtr_list :
    iIIiI11 += red ( iiO0ooooOooo . print_address_no_iid ( ) , False ) + ", "
    if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
   iIIiI11 = iIIiI11 [ 0 : - 2 ]
  else :
   Oo0OoO = "Info-Request"
   oOOOo00000Oo = "<none>" if self . hostname == None else self . hostname
   iIIiI11 = ", hostname: {}" . format ( blue ( oOOOo00000Oo , False ) )
   if 94 - 94: II111iiii
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( Oo0OoO , False ) ,
 lisp_hex_string ( self . nonce ) , iIIiI11 ) )
  if 27 - 27: OOooOOo
  if 95 - 95: oO0o - I1Ii111 + Oo0Ooo
 def encode ( self ) :
  iIiIii = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : iIiIii |= ( 1 << 27 )
  if 32 - 32: iIii1I11I1II1 - ooOoO0o . o0oOOo0O0Ooo
  if 88 - 88: i1IIi
  if 9 - 9: II111iiii + O0 + ooOoO0o - i11iIiiIii / OoooooooOO
  if 27 - 27: oO0o
  if 61 - 61: I1Ii111 / O0 - iII111i
  if 44 - 44: i1IIi
  if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
  Oo00oo = struct . pack ( "I" , socket . htonl ( iIiIii ) )
  Oo00oo += struct . pack ( "Q" , self . nonce )
  Oo00oo += struct . pack ( "III" , 0 , 0 , 0 )
  if 89 - 89: OoOoOO00 + Oo0Ooo . OoOoOO00 - II111iiii
  if 85 - 85: OoooooooOO * OoooooooOO / Ii1I - II111iiii
  if 69 - 69: iII111i * I11i
  if 43 - 43: o0oOOo0O0Ooo - IiII * Ii1I . i11iIiiIii / II111iiii
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    Oo00oo += struct . pack ( "H" , 0 )
   else :
    Oo00oo += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    Oo00oo += ( self . hostname + "\0" ) . encode ( )
    if 61 - 61: OoOoOO00 / I1IiiI . I1ii11iIi11i % OOooOOo
   return ( Oo00oo )
   if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
   if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
   if 15 - 15: o0oOOo0O0Ooo / i11iIiiIii
   if 63 - 63: I1ii11iIi11i - Ii1I + I11i
   if 98 - 98: iII111i / IiII * I1IiiI / oO0o - iIii1I11I1II1
  i1I1iiiI = socket . htons ( LISP_AFI_LCAF )
  ooOoOoOo = LISP_LCAF_NAT_TYPE
  iIIIi1Iii1 = socket . htons ( 16 )
  oo0OoOoO0O = socket . htons ( self . ms_port )
  iI1ii1 = socket . htons ( self . etr_port )
  Oo00oo += struct . pack ( "HHBBHHHH" , i1I1iiiI , 0 , ooOoOoOo , 0 , iIIIi1Iii1 ,
 oo0OoOoO0O , iI1ii1 , socket . htons ( self . global_etr_rloc . afi ) )
  Oo00oo += self . global_etr_rloc . pack_address ( )
  Oo00oo += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  Oo00oo += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : Oo00oo += struct . pack ( "H" , 0 )
  if 55 - 55: i11iIiiIii * OOooOOo * I1ii11iIi11i
  if 17 - 17: iIii1I11I1II1 - OoOoOO00
  if 97 - 97: iIii1I11I1II1 / OOooOOo * i1IIi - OoO0O00 / ooOoO0o % Ii1I
  if 30 - 30: OoOoOO00 / oO0o . iII111i
  for iiO0ooooOooo in self . rtr_list :
   Oo00oo += struct . pack ( "H" , socket . htons ( iiO0ooooOooo . afi ) )
   Oo00oo += iiO0ooooOooo . pack_address ( )
   if 56 - 56: OoOoOO00
  return ( Oo00oo )
  if 83 - 83: OOooOOo
  if 17 - 17: IiII + I1IiiI - I11i . I1IiiI
 def decode ( self , packet ) :
  i1o0o0oOO = packet
  iiII1iiI = "I"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 34 - 34: ooOoO0o . i11iIiiIii * I1IiiI . II111iiii - iIii1I11I1II1
  iIiIii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  iIiIii = iIiIii [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  if 43 - 43: i11iIiiIii % OoO0O00
  iiII1iiI = "Q"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 100 - 100: i1IIi
  o0Oo0o = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
  iIiIii = socket . ntohl ( iIiIii )
  self . nonce = o0Oo0o [ 0 ]
  self . info_reply = iIiIii & 0x08000000
  self . hostname = None
  packet = packet [ ooo0000oo0 : : ]
  if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
  if 71 - 71: IiII + OoO0O00
  if 39 - 39: I1IiiI % IiII / II111iiii / II111iiii
  if 95 - 95: II111iiii + i11iIiiIii + o0oOOo0O0Ooo
  if 30 - 30: O0 - O0 % iIii1I11I1II1 + iII111i * OoooooooOO
  iiII1iiI = "HH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 1 - 1: O0
  if 36 - 36: oO0o . iII111i
  if 62 - 62: I11i + iIii1I11I1II1 % I11i * OOooOOo + iIii1I11I1II1 % Ii1I
  if 56 - 56: o0oOOo0O0Ooo
  if 55 - 55: oO0o - I1Ii111 / ooOoO0o % I1IiiI * OoooooooOO * I1IiiI
  IiII11iI1 , oOOOO00o00 = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if ( oOOOO00o00 != 0 ) : return ( None )
  if 88 - 88: Ii1I + O0
  packet = packet [ ooo0000oo0 : : ]
  iiII1iiI = "IBBH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
  O0O00O , OOOo00o , iiii11I1 , I1I11i1 = struct . unpack ( iiII1iiI ,
 packet [ : ooo0000oo0 ] )
  if 18 - 18: ooOoO0o / OOooOOo / I11i / OoooooooOO - Ii1I / I1ii11iIi11i
  if ( I1I11i1 != 0 ) : return ( None )
  packet = packet [ ooo0000oo0 : : ]
  if 45 - 45: ooOoO0o - OOooOOo . Ii1I
  if 99 - 99: I11i / OoOoOO00 % OoO0O00 * Ii1I / OOooOOo
  if 9 - 9: ooOoO0o - ooOoO0o * I1ii11iIi11i
  if 92 - 92: Ii1I
  if ( self . info_reply == False ) :
   iiII1iiI = "H"
   ooo0000oo0 = struct . calcsize ( iiII1iiI )
   if ( len ( packet ) >= ooo0000oo0 ) :
    i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
    if ( socket . ntohs ( i1I1iiiI ) == LISP_AFI_NAME ) :
     packet = packet [ ooo0000oo0 : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 88 - 88: OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
     if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
   return ( i1o0o0oOO )
   if 62 - 62: I1Ii111 % II111iiii
   if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
   if 91 - 91: i11iIiiIii + Ii1I
   if 85 - 85: I11i % IiII
   if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
  iiII1iiI = "HHBBHHH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
  i1I1iiiI , Oo0OoO00O , ooOoOoOo , OOOo00o , iIIIi1Iii1 , oo0OoOoO0O , iI1ii1 = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 24 - 24: ooOoO0o - I1Ii111 * II111iiii - II111iiii
  if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
  if ( socket . ntohs ( i1I1iiiI ) != LISP_AFI_LCAF ) : return ( None )
  if 93 - 93: Ii1I / iII111i
  self . ms_port = socket . ntohs ( oo0OoOoO0O )
  self . etr_port = socket . ntohs ( iI1ii1 )
  packet = packet [ ooo0000oo0 : : ]
  if 100 - 100: Oo0Ooo
  if 94 - 94: I1ii11iIi11i / i1IIi * I1IiiI - I11i - I1ii11iIi11i
  if 6 - 6: I1ii11iIi11i % o0oOOo0O0Ooo + o0oOOo0O0Ooo / OOooOOo / I1IiiI
  if 67 - 67: OoOoOO00 . iII111i / OOooOOo * ooOoO0o + i1IIi
  iiII1iiI = "H"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 100 - 100: OOooOOo . ooOoO0o + I1Ii111 . oO0o
  if 20 - 20: i11iIiiIii - i1IIi - iIii1I11I1II1 - OoooooooOO
  if 72 - 72: I1Ii111 . OoO0O00
  if 59 - 59: I1IiiI * I11i % i1IIi
  i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  if ( i1I1iiiI != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( i1I1iiiI )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 77 - 77: OOooOOo * OoooooooOO + I1IiiI + I1IiiI % oO0o . OoooooooOO
   if 60 - 60: iIii1I11I1II1
   if 13 - 13: II111iiii + Ii1I
   if 33 - 33: i1IIi
   if 36 - 36: ooOoO0o % ooOoO0o . i11iIiiIii
   if 42 - 42: OoO0O00 . I1Ii111 / Ii1I
  if ( len ( packet ) < ooo0000oo0 ) : return ( i1o0o0oOO )
  if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / oO0o . OoOoOO00
  i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  if ( i1I1iiiI != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( i1I1iiiI )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( i1o0o0oOO )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 74 - 74: I1IiiI * OoO0O00 + OoooooooOO * ooOoO0o . oO0o
   if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
   if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
   if 81 - 81: i1IIi % iIii1I11I1II1
   if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
  if ( len ( packet ) < ooo0000oo0 ) : return ( i1o0o0oOO )
  if 82 - 82: ooOoO0o
  i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  if ( i1I1iiiI != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( i1I1iiiI )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( i1o0o0oOO )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
   if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
   if 59 - 59: i11iIiiIii / OoO0O00
   if 48 - 48: iIii1I11I1II1
   if 19 - 19: oO0o
   if 69 - 69: I1ii11iIi11i % iII111i - OoooooooOO % Ii1I * oO0o
  while ( len ( packet ) >= ooo0000oo0 ) :
   i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
   packet = packet [ ooo0000oo0 : : ]
   if ( i1I1iiiI == 0 ) : continue
   iiO0ooooOooo = lisp_address ( socket . ntohs ( i1I1iiiI ) , "" , 0 , 0 )
   packet = iiO0ooooOooo . unpack_address ( packet )
   if ( packet == None ) : return ( i1o0o0oOO )
   iiO0ooooOooo . mask_len = iiO0ooooOooo . host_mask_len ( )
   self . rtr_list . append ( iiO0ooooOooo )
   if 12 - 12: OoOoOO00 / I1Ii111 . O0 . IiII - OOooOOo - OoO0O00
  return ( i1o0o0oOO )
  if 28 - 28: II111iiii . OoOoOO00 - o0oOOo0O0Ooo
  if 89 - 89: I1Ii111 * OoooooooOO . OOooOOo . I11i % i11iIiiIii
  if 8 - 8: I1ii11iIi11i + II111iiii . OoO0O00 + I1IiiI - II111iiii % OoO0O00
class lisp_nat_info ( object ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 85 - 85: i11iIiiIii % iII111i + II111iiii
  if 16 - 16: ooOoO0o * OoOoOO00 / OoOoOO00 + II111iiii
 def timed_out ( self ) :
  i1i111Iiiiiii = time . time ( ) - self . uptime
  return ( i1i111Iiiiiii >= ( LISP_INFO_INTERVAL * 2 ) )
  if 50 - 50: OoO0O00 / OOooOOo % I1IiiI / Ii1I + OoO0O00 . iIii1I11I1II1
  if 62 - 62: I1Ii111 + OoooooooOO - Ii1I - iIii1I11I1II1
  if 80 - 80: OoO0O00
class lisp_info_source ( object ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 72 - 72: II111iiii % i11iIiiIii + OoOoOO00 / I1Ii111 - i11iIiiIii
  if 39 - 39: i11iIiiIii - OOooOOo / OoO0O00 * OoOoOO00 / IiII
 def cache_address_for_info_source ( self ) :
  III = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ III ] = self
  if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 / Ii1I / II111iiii
  if 56 - 56: OOooOOo * iII111i / Ii1I
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
  if 9 - 9: I1ii11iIi11i * i11iIiiIii / I1Ii111 + iIii1I11I1II1
  if 1 - 1: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / oO0o
  if 73 - 73: iII111i
  if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo
  if 45 - 45: oO0o % O0 / O0
  if 98 - 98: I1Ii111
  if 58 - 58: OOooOOo
  if 6 - 6: I1ii11iIi11i
  if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
  if 18 - 18: ooOoO0o
  if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 29 - 29: Ii1I . II111iiii / I1Ii111
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
  if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  IIiI = auth1 + auth2 + auth3
  if 81 - 81: i11iIiiIii - II111iiii + I11i
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  IIiI = auth1 + auth2 + auth3 + auth4
  if 52 - 52: II111iiii
 return ( IIiI )
 if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
 if 26 - 26: I1ii11iIi11i - OoO0O00
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
 if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
 if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
 if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
 if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
 if 15 - 15: Ii1I
 if 29 - 29: I11i / I1IiiI / OoooooooOO . OoOoOO00 / I11i . I1Ii111
 if 69 - 69: O0 * OoOoOO00 + o0oOOo0O0Ooo + I1IiiI % iII111i . OoooooooOO
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   I1IIIII = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 48 - 48: II111iiii / OoOoOO00
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   I1IIIII = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 30 - 30: II111iiii
  I1IIIII . bind ( ( local_addr , int ( port ) ) )
 else :
  ooO0o = port
  if ( os . path . exists ( ooO0o ) ) :
   os . system ( "rm " + ooO0o )
   time . sleep ( 1 )
   if 12 - 12: I11i * OOooOOo - ooOoO0o / I1Ii111
  I1IIIII = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  I1IIIII . bind ( ooO0o )
  if 70 - 70: OOooOOo + ooOoO0o / I1ii11iIi11i * IiII / i11iIiiIii - OoooooooOO
 return ( I1IIIII )
 if 28 - 28: II111iiii / OoO0O00 - I1IiiI % IiII . OoO0O00 * iII111i
 if 14 - 14: I1Ii111
 if 87 - 87: I1Ii111
 if 47 - 47: II111iiii + I1IiiI . Oo0Ooo / iIii1I11I1II1
 if 14 - 14: i1IIi / OoO0O00 / iII111i % I1Ii111
 if 72 - 72: OoO0O00 . II111iiii - IiII + IiII + iIii1I11I1II1 % oO0o
 if 21 - 21: iII111i + OoOoOO00 - i11iIiiIii % O0 + OOooOOo
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   I1IIIII = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   I1IIIII = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 94 - 94: IiII
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  I1IIIII = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  I1IIIII . bind ( internal_name )
  if 69 - 69: I1Ii111 . I1Ii111
 return ( I1IIIII )
 if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
 if 8 - 8: iII111i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I % I11i / I1Ii111
 if 21 - 21: OoO0O00 + Ii1I / I1Ii111
 if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
 if 38 - 38: i1IIi
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
 if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
 if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
 if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
 if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
 if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
 if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
 if 2 - 2: OOooOOo / I11i * I11i + I11i / O0 - OOooOOo
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
 if 68 - 68: iII111i / OOooOOo
 if 28 - 28: II111iiii
 if 49 - 49: I1ii11iIi11i
 if 33 - 33: iIii1I11I1II1
 if 72 - 72: I1ii11iIi11i * i11iIiiIii
 if 12 - 12: O0 - iIii1I11I1II1 % Oo0Ooo / O0 - IiII
 if 55 - 55: OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * i11iIiiIii + oO0o
 if 45 - 45: Ii1I
 if 8 - 8: oO0o + OOooOOo
 if 37 - 37: IiII - OoOoOO00 + oO0o - Oo0Ooo + IiII
def lisp_packet_ipc ( packet , source , sport ) :
 IiIii1iIIII = "packet@{}@{}@{}@" . format ( str ( len ( packet ) ) , source , str ( sport ) )
 return ( IiIii1iIIII . encode ( ) + packet )
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
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 IiIii1iIIII = "control-packet@{}@{}@" . format ( dest , str ( dport ) )
 return ( IiIii1iIIII . encode ( ) + packet )
 if 51 - 51: i1IIi . oO0o % OOooOOo
 if 90 - 90: OoooooooOO + iII111i / iIii1I11I1II1
 if 12 - 12: OoooooooOO
 if 9 - 9: O0 / O0 / I1IiiI - oO0o . ooOoO0o
 if 6 - 6: O0 - OoO0O00 + OoooooooOO % iIii1I11I1II1
 if 58 - 58: i11iIiiIii * OOooOOo . Oo0Ooo / iII111i - i1IIi
 if 45 - 45: Ii1I
 if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
 if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
def lisp_data_packet_ipc ( packet , source ) :
 IiIii1iIIII = "data-packet@{}@{}@@" . format ( str ( len ( packet ) ) , source )
 return ( IiIii1iIIII . encode ( ) + packet )
 if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
 if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
 if 86 - 86: iII111i / i1IIi % Oo0Ooo
 if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
 if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
 if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
 if 14 - 14: OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
 if 92 - 92: OoO0O00 . i1IIi
 if 22 - 22: Ii1I . I1IiiI
 if 54 - 54: OOooOOo / I1ii11iIi11i % oO0o
 if 66 - 66: I11i + iII111i
def lisp_command_ipc ( ipc , source ) :
 Oo00oo = "command@{}@{}@@" . format ( len ( ipc ) , source ) + ipc
 return ( Oo00oo . encode ( ) )
 if 50 - 50: IiII
 if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
 if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
 if 55 - 55: OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
 if 37 - 37: Ii1I + o0oOOo0O0Ooo
 if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
 if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
 if 8 - 8: I11i - I11i % IiII
 if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
 if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
 if 25 - 25: iII111i / iII111i % OoOoOO00 / ooOoO0o
def lisp_api_ipc ( source , data ) :
 Oo00oo = "api@" + str ( len ( data ) ) + "@" + source + "@@" + data
 return ( Oo00oo . encode ( ) )
 if 81 - 81: OOooOOo * oO0o
 if 32 - 32: Oo0Ooo * OoO0O00 + ooOoO0o . O0 * oO0o * iIii1I11I1II1
 if 50 - 50: i1IIi
 if 53 - 53: II111iiii + O0 . ooOoO0o * IiII + i1IIi
 if 80 - 80: Ii1I + O0
 if 59 - 59: i11iIiiIii - OoooooooOO % I11i . OoO0O00 - Oo0Ooo * o0oOOo0O0Ooo
 if 7 - 7: II111iiii % Ii1I * i11iIiiIii
 if 28 - 28: II111iiii / ooOoO0o * i11iIiiIii % OOooOOo
 if 18 - 18: I11i - IiII - iIii1I11I1II1
 if 82 - 82: II111iiii + OoO0O00 % iIii1I11I1II1 / O0
 if 75 - 75: OOooOOo * OoO0O00 + OoooooooOO + i11iIiiIii . OoO0O00
 if 94 - 94: I11i * ooOoO0o . I1IiiI / Ii1I - I1IiiI % OoooooooOO
def lisp_ipc ( packet , send_socket , node ) :
 if 32 - 32: OoO0O00
 if 22 - 22: II111iiii . I11i
 if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
 if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 94 - 94: OOooOOo / IiII
  if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
 iIIII1ii = 1500 if ( packet . find ( b"control-packet" ) == - 1 ) else 9000
 if 92 - 92: II111iiii / I11i + O0
 oo00 = 0
 i1iIii = len ( packet )
 I11O00OOo0o0o0oo = 0
 iiiIIiIIi1 = .001
 while ( i1iIii > 0 ) :
  I11I = min ( i1iIii , iIIII1ii )
  O0o000 = packet [ oo00 : I11I + oo00 ]
  if 56 - 56: OoOoOO00 % I1ii11iIi11i . oO0o * OoooooooOO + OoooooooOO * Ii1I
  try :
   if ( type ( O0o000 ) == str ) : O0o000 = O0o000 . encode ( )
   send_socket . sendto ( O0o000 , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( O0o000 ) , len ( packet ) , node ) )
   if 73 - 73: ooOoO0o . OoO0O00 % I1ii11iIi11i - oO0o
   I11O00OOo0o0o0oo = 0
   iiiIIiIIi1 = .001
   if 67 - 67: o0oOOo0O0Ooo . I11i + i1IIi
  except socket . error as oO0ooOOO :
   if ( I11O00OOo0o0o0oo == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 100 - 100: Oo0Ooo - I1IiiI . OOooOOo % iIii1I11I1II1 . I11i
    if 83 - 83: OoOoOO00 * iII111i
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( O0o000 ) , len ( packet ) , node , oO0ooOOO ) )
   if 75 - 75: i11iIiiIii . o0oOOo0O0Ooo / oO0o . OoO0O00 % Ii1I % Ii1I
   if 94 - 94: iII111i . Ii1I
   I11O00OOo0o0o0oo += 1
   time . sleep ( iiiIIiIIi1 )
   if 71 - 71: o0oOOo0O0Ooo * II111iiii / OOooOOo . OoO0O00
   lprint ( "Retrying after {} ms ..." . format ( iiiIIiIIi1 * 1000 ) )
   iiiIIiIIi1 *= 2
   continue
   if 73 - 73: I1Ii111 * OoO0O00 / OoOoOO00 . II111iiii
   if 87 - 87: OoO0O00 + Oo0Ooo + O0 % OoooooooOO - iIii1I11I1II1
  oo00 += I11I
  i1iIii -= I11I
  if 100 - 100: Oo0Ooo + IiII
 return
 if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1
 if 19 - 19: ooOoO0o + i1IIi / Oo0Ooo * II111iiii * I1Ii111 / ooOoO0o
 if 23 - 23: I1Ii111
 if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
 if 75 - 75: I11i . Ii1I / I1ii11iIi11i
 if 99 - 99: Ii1I
 if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
 if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 oo00 = 0
 I11Ii1I1I1111 = b""
 i1iIii = len ( packet ) * 2
 while ( oo00 < i1iIii ) :
  I11Ii1I1I1111 += packet [ oo00 : oo00 + 8 ] + b" "
  oo00 += 8
  i1iIii -= 4
  if 21 - 21: iII111i
 return ( I11Ii1I1I1111 . decode ( ) )
 if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
 if 75 - 75: OoooooooOO
 if 24 - 24: oO0o % iII111i - II111iiii / Ii1I + O0
 if 37 - 37: I1Ii111 - i1IIi / iIii1I11I1II1
 if 53 - 53: Ii1I - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii + ooOoO0o
 if 63 - 63: Oo0Ooo * I1IiiI
 if 84 - 84: Oo0Ooo
def lisp_send ( lisp_sockets , dest , port , packet ) :
 OOoo = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 33 - 33: OoOoOO00 - ooOoO0o - o0oOOo0O0Ooo - i1IIi + I11i
 if 14 - 14: iII111i / oO0o . oO0o - OOooOOo * i1IIi - i1IIi
 if 70 - 70: OoooooooOO
 if 60 - 60: OOooOOo - Ii1I * Ii1I
 if 69 - 69: i11iIiiIii . IiII + o0oOOo0O0Ooo % Ii1I - OoO0O00
 if 46 - 46: OoOoOO00 + iII111i * o0oOOo0O0Ooo - I1ii11iIi11i / oO0o + IiII
 if 1 - 1: iIii1I11I1II1 / OoooooooOO + Oo0Ooo . Ii1I
 if 25 - 25: I1ii11iIi11i / i1IIi * oO0o - II111iiii * i1IIi
 if 57 - 57: OoO0O00 % OoO0O00
 if 67 - 67: O0 . i11iIiiIii + iIii1I11I1II1
 if 86 - 86: iIii1I11I1II1
 if 81 - 81: OOooOOo / I11i / OoooooooOO
 I1IIIi = dest . print_address_no_iid ( )
 if ( I1IIIi . find ( "::ffff:" ) != - 1 and I1IIIi . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : OOoo = lisp_sockets [ 0 ]
  if ( OOoo == None ) :
   OOoo = lisp_sockets [ 0 ]
   I1IIIi = I1IIIi . split ( "::ffff:" ) [ - 1 ]
   if 74 - 74: I11i + OoooooooOO % II111iiii % o0oOOo0O0Ooo
   if 27 - 27: OoO0O00 * Oo0Ooo
   if 80 - 80: i11iIiiIii . OoO0O00 - I11i % I11i
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + I1IIIi , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 21 - 21: I1IiiI . OoO0O00 * IiII % OoooooooOO - Oo0Ooo + Oo0Ooo
 if 94 - 94: ooOoO0o
 if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
 if 95 - 95: II111iiii
 OO00oOo0oO = ( LISP_RLOC_PROBE_TTL == 128 )
 if ( OO00oOo0oO ) :
  o00o0ooO0oo = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  OO00oOo0oO = ( o00o0ooO0oo in [ 0x12 , 0x28 ] )
  if ( OO00oOo0oO ) : lisp_set_ttl ( OOoo , LISP_RLOC_PROBE_TTL )
  if 55 - 55: OoO0O00 % I1Ii111 - i1IIi - i1IIi + i11iIiiIii / iII111i
  if 51 - 51: Oo0Ooo - O0 % o0oOOo0O0Ooo / I1ii11iIi11i
 try : OOoo . sendto ( packet , ( I1IIIi , port ) )
 except socket . error as oO0ooOOO :
  lprint ( "socket.sendto() failed: {}" . format ( oO0ooOOO ) )
  if 60 - 60: iII111i / OoooooooOO * II111iiii * Oo0Ooo * o0oOOo0O0Ooo
  if 60 - 60: iII111i . OOooOOo
  if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
  if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
  if 19 - 19: I1IiiI
 if ( OO00oOo0oO ) : lisp_set_ttl ( OOoo , 64 )
 return
 if 99 - 99: OOooOOo - OOooOOo
 if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
 if 83 - 83: o0oOOo0O0Ooo
 if 23 - 23: o0oOOo0O0Ooo . I11i
 if 67 - 67: iII111i
 if 52 - 52: IiII . OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / IiII . OoooooooOO . Oo0Ooo / ooOoO0o + O0
 if 38 - 38: I11i
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 66 - 66: II111iiii
 if 57 - 57: OoO0O00 / Oo0Ooo % I1IiiI * I1ii11iIi11i
 if 68 - 68: iII111i - o0oOOo0O0Ooo - OoO0O00 . O0 - i11iIiiIii
 if 2 - 2: I1ii11iIi11i * i1IIi
 if 17 - 17: I1ii11iIi11i * Ii1I % Oo0Ooo * I1Ii111 + OoO0O00 . OoooooooOO
 I11I = total_length - len ( packet )
 if ( I11I == 0 ) : return ( [ True , packet ] )
 if 60 - 60: Ii1I . II111iiii
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
 if 50 - 50: OoooooooOO + o0oOOo0O0Ooo + iIii1I11I1II1 + OOooOOo
 if 90 - 90: Ii1I * I11i % I1Ii111 - I1ii11iIi11i * I1Ii111 % OoO0O00
 if 50 - 50: iIii1I11I1II1
 if 56 - 56: oO0o
 i1iIii = I11I
 while ( i1iIii > 0 ) :
  try : O0o000 = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 55 - 55: iIii1I11I1II1 % oO0o % OOooOOo / I1Ii111 * OoooooooOO / Oo0Ooo
  O0o000 = O0o000 [ 0 ]
  if 88 - 88: I11i + OoO0O00 . iIii1I11I1II1 . II111iiii
  if 67 - 67: OOooOOo - ooOoO0o % iII111i % IiII
  if 71 - 71: OoO0O00 - ooOoO0o - I1IiiI + O0
  if 15 - 15: i1IIi
  if 43 - 43: II111iiii + OOooOOo . i11iIiiIii - II111iiii
  oOIi1IiIii1iII = O0o000 . decode ( )
  if ( oOIi1IiIii1iII . find ( "packet@" ) == 0 ) :
   oOIi1IiIii1iII = oOIi1IiIii1iII . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( O0o000 ) ,
   # iII111i % i11iIiiIii * OOooOOo % I1IiiI + OoO0O00
 oOIi1IiIii1iII [ 1 ] if len ( oOIi1IiIii1iII ) > 2 else "?" )
   return ( [ False , O0o000 ] )
   if 56 - 56: I1Ii111 - OOooOOo + iIii1I11I1II1 + O0 * iIii1I11I1II1
   if 62 - 62: oO0o
  i1iIii -= len ( O0o000 )
  packet += O0o000
  if 46 - 46: I1Ii111 - iII111i / oO0o % OoO0O00 / O0 + oO0o
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( O0o000 ) , total_length , source ) )
  if 35 - 35: Oo0Ooo
  if 86 - 86: ooOoO0o . OoO0O00
 return ( [ True , packet ] )
 if 47 - 47: IiII % I1IiiI
 if 91 - 91: Ii1I
 if 69 - 69: iII111i
 if 96 - 96: Ii1I
 if 39 - 39: OoO0O00 - I1IiiI % II111iiii - IiII * I1ii11iIi11i
 if 64 - 64: OOooOOo + Oo0Ooo . OoOoOO00 . OOooOOo + i11iIiiIii
 if 7 - 7: ooOoO0o * I11i / iIii1I11I1II1
 if 15 - 15: OoooooooOO / iII111i
 if 40 - 40: o0oOOo0O0Ooo
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 Oo00oo = b""
 for O0o000 in payload : Oo00oo += O0o000 + b"\x40"
 return ( Oo00oo [ : - 1 ] )
 if 75 - 75: oO0o - OoOoOO00 * ooOoO0o . O0
 if 78 - 78: Oo0Ooo
 if 74 - 74: O0 / I11i
 if 52 - 52: I1IiiI + oO0o * II111iiii
 if 15 - 15: I11i
 if 72 - 72: O0
 if 15 - 15: II111iiii / I11i % II111iiii % Ii1I % i11iIiiIii / I1Ii111
 if 93 - 93: OOooOOo / OoooooooOO % iII111i
 if 47 - 47: o0oOOo0O0Ooo - I1IiiI % O0 % I1Ii111 . O0 . OoOoOO00
 if 95 - 95: o0oOOo0O0Ooo * OOooOOo - iII111i * OoooooooOO - ooOoO0o / I1IiiI
 if 47 - 47: OoO0O00 % I1IiiI / OoOoOO00 - I1Ii111 / I1IiiI
 if 13 - 13: o0oOOo0O0Ooo % ooOoO0o
 if 15 - 15: iII111i * I1IiiI . iIii1I11I1II1 % I1IiiI / O0
 if 47 - 47: OoooooooOO - i11iIiiIii . I1IiiI / i1IIi
 if 74 - 74: OoooooooOO * ooOoO0o
 if 45 - 45: Oo0Ooo + iIii1I11I1II1 . o0oOOo0O0Ooo
 if 50 - 50: o0oOOo0O0Ooo % O0
 if 67 - 67: OoOoOO00
 if 21 - 21: I11i % Oo0Ooo + Oo0Ooo / iIii1I11I1II1 % iIii1I11I1II1
 if 66 - 66: iII111i
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 72 - 72: ooOoO0o / oO0o / iII111i . I1Ii111 . I1ii11iIi11i + IiII
  if 39 - 39: I1IiiI % I1Ii111
  if 22 - 22: OoOoOO00 - OOooOOo % i1IIi + i1IIi
  if 28 - 28: oO0o + OoOoOO00 * Ii1I . I11i
  try : oOO0O = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 36 - 36: O0 + o0oOOo0O0Ooo - OoOoOO00 * OoO0O00
  if 95 - 95: iIii1I11I1II1 % I1ii11iIi11i + II111iiii + ooOoO0o + iIii1I11I1II1 / I1Ii111
  if 59 - 59: I1Ii111
  if 22 - 22: OoooooooOO
  if 88 - 88: I1Ii111 - OoO0O00
  if 29 - 29: I1IiiI . I1Ii111
  if ( internal == False ) :
   Oo00oo = oOO0O [ 0 ]
   O0oo0OoO0oo = lisp_convert_6to4 ( oOO0O [ 1 ] [ 0 ] )
   ooO0 = oOO0O [ 1 ] [ 1 ]
   if 74 - 74: Oo0Ooo / OoOoOO00 + OoOoOO00 % i11iIiiIii . OoO0O00 + ooOoO0o
   if ( ooO0 == LISP_DATA_PORT ) :
    o0I11 = lisp_data_plane_logging
    IIiI11I1II1 = lisp_format_packet ( Oo00oo [ 0 : 60 ] ) + " ..."
   else :
    o0I11 = True
    IIiI11I1II1 = lisp_format_packet ( Oo00oo )
    if 77 - 77: II111iiii
    if 80 - 80: i11iIiiIii / Ii1I / ooOoO0o - OoO0O00
   if ( o0I11 ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( Oo00oo ) , bold ( "from " + O0oo0OoO0oo , False ) , ooO0 ,
 IIiI11I1II1 ) )
    if 17 - 17: OoO0O00 * i11iIiiIii * Oo0Ooo / OoooooooOO / II111iiii
   return ( [ "packet" , O0oo0OoO0oo , ooO0 , Oo00oo ] )
   if 92 - 92: iII111i + II111iiii
   if 88 - 88: o0oOOo0O0Ooo . IiII / O0 + ooOoO0o
   if 19 - 19: Oo0Ooo
   if 24 - 24: Ii1I . I1ii11iIi11i . i1IIi % Oo0Ooo
   if 63 - 63: OoO0O00 . I1IiiI + ooOoO0o + I1ii11iIi11i
   if 63 - 63: OoooooooOO * OoOoOO00 - Ii1I
  oo0OOOOOOOo0 = False
  iiooo0o0oO = oOO0O [ 0 ]
  if ( type ( iiooo0o0oO ) == str ) : iiooo0o0oO = iiooo0o0oO . encode ( )
  iiiIIi1I1I1 = False
  if 18 - 18: OoooooooOO * i11iIiiIii - iII111i % IiII . i11iIiiIii
  while ( oo0OOOOOOOo0 == False ) :
   iiooo0o0oO = iiooo0o0oO . split ( b"@" )
   if 8 - 8: I1IiiI . ooOoO0o
   if ( len ( iiooo0o0oO ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( iiooo0o0oO [ 0 ] ) )
    if 31 - 31: ooOoO0o / OoOoOO00
    iiiIIi1I1I1 = True
    break
    if 16 - 16: ooOoO0o
    if 61 - 61: IiII
   oO0000o00OO = iiooo0o0oO [ 0 ] . decode ( )
   try :
    II1IIII = int ( iiooo0o0oO [ 1 ] )
   except :
    iIIiiiii1iIII = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( iIIiiiii1iIII , oOO0O ) )
    iiiIIi1I1I1 = True
    break
    if 99 - 99: oO0o * OOooOOo + Oo0Ooo % OoO0O00 * Ii1I / OoOoOO00
   O0oo0OoO0oo = iiooo0o0oO [ 2 ] . decode ( )
   ooO0 = iiooo0o0oO [ 3 ] . decode ( )
   if 1 - 1: I1IiiI
   if 68 - 68: ooOoO0o
   if 68 - 68: I11i % IiII
   if 1 - 1: I1IiiI + OOooOOo - OOooOOo * O0 + o0oOOo0O0Ooo * OOooOOo
   if 48 - 48: ooOoO0o - iII111i + I1ii11iIi11i * I1Ii111 % ooOoO0o * OoO0O00
   if 28 - 28: i1IIi / iII111i + OOooOOo
   if 89 - 89: Oo0Ooo + II111iiii * OoO0O00 + Oo0Ooo % II111iiii
   if 59 - 59: O0 + Oo0Ooo
   if ( len ( iiooo0o0oO ) > 5 ) :
    Oo00oo = lisp_bit_stuff ( iiooo0o0oO [ 4 : : ] )
   else :
    Oo00oo = iiooo0o0oO [ 4 ]
    if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
    if 50 - 50: I11i . I11i % I1IiiI - i1IIi
    if 63 - 63: OoO0O00 . iII111i
    if 28 - 28: ooOoO0o . Oo0Ooo - OoooooooOO - I1Ii111 - OoooooooOO - oO0o
    if 25 - 25: I11i / I1Ii111 . i11iIiiIii % i1IIi
    if 21 - 21: O0 * IiII . iII111i / iII111i % i11iIiiIii / I11i
   oo0OOOOOOOo0 , Oo00oo = lisp_receive_segments ( lisp_socket , Oo00oo ,
 O0oo0OoO0oo , II1IIII )
   if ( Oo00oo == None ) : return ( [ "" , "" , "" , "" ] )
   if 15 - 15: o0oOOo0O0Ooo / OoO0O00 - i1IIi
   if 30 - 30: OoO0O00 / ooOoO0o % ooOoO0o
   if 40 - 40: i1IIi . iIii1I11I1II1 * OoOoOO00
   if 83 - 83: iIii1I11I1II1 + Ii1I - Ii1I % II111iiii
   if 82 - 82: O0
   if ( oo0OOOOOOOo0 == False ) :
    iiooo0o0oO = Oo00oo
    continue
    if 18 - 18: iII111i . IiII . I1IiiI
    if 40 - 40: IiII / oO0o + OoooooooOO / iII111i / II111iiii + i1IIi
   if ( ooO0 == "" ) : ooO0 = "no-port"
   if ( oO0000o00OO == "command" and lisp_i_am_core == False ) :
    OOOooo0OooOoO = Oo00oo . find ( b" {" )
    I1II1i = Oo00oo if OOOooo0OooOoO == - 1 else Oo00oo [ : OOOooo0OooOoO ]
    I1II1i = ": '" + I1II1i . decode ( ) + "'"
   else :
    I1II1i = ""
    if 81 - 81: oO0o % i11iIiiIii / Ii1I
    if 3 - 3: I1IiiI - O0 % O0
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( Oo00oo ) , bold ( "from " + O0oo0OoO0oo , False ) , ooO0 , oO0000o00OO ,
 I1II1i if ( oO0000o00OO in [ "command" , "api" ] ) else ": ... " if ( oO0000o00OO == "data-packet" ) else ": " + lisp_format_packet ( Oo00oo ) ) )
   if 85 - 85: iIii1I11I1II1 % OoooooooOO . Oo0Ooo * i1IIi . iIii1I11I1II1
   if 19 - 19: oO0o + II111iiii - OOooOOo
   if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
   if 81 - 81: iIii1I11I1II1 - OoO0O00 . i11iIiiIii
   if 4 - 4: o0oOOo0O0Ooo / OoO0O00 - I11i
  if ( iiiIIi1I1I1 ) : continue
  return ( [ oO0000o00OO , O0oo0OoO0oo , ooO0 , Oo00oo ] )
  if 52 - 52: II111iiii . iII111i
  if 36 - 36: I1IiiI * II111iiii
  if 68 - 68: oO0o * o0oOOo0O0Ooo + OoooooooOO - I1ii11iIi11i * i1IIi % OOooOOo
  if 39 - 39: I1Ii111 / I11i + oO0o / I1Ii111 % IiII * I1ii11iIi11i
  if 66 - 66: I1ii11iIi11i * ooOoO0o . i11iIiiIii * Oo0Ooo - I11i . I1IiiI
  if 43 - 43: I11i . iII111i . IiII - oO0o
  if 60 - 60: i1IIi + iII111i * i1IIi . iII111i
  if 40 - 40: i1IIi . OoO0O00
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 o0000o = False
 iIIi1iiii1ii = time . time ( )
 if 100 - 100: iIii1I11I1II1 * I1IiiI * Ii1I * i1IIi . I1Ii111 * I1IiiI
 IiIii1iIIII = lisp_control_header ( )
 if ( IiIii1iIIII . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( o0000o )
  if 54 - 54: o0oOOo0O0Ooo / iII111i + IiII - o0oOOo0O0Ooo - I11i
  if 28 - 28: I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * IiII + OoooooooOO
  if 52 - 52: I1Ii111
  if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
  if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
 O0oOO0O00 = source
 if ( source . find ( "lisp" ) == - 1 ) :
  I111 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  I111 . string_to_afi ( source )
  I111 . store_address ( source )
  source = I111
  if 52 - 52: IiII % iII111i
  if 74 - 74: II111iiii . II111iiii + I1IiiI / OoO0O00
 if ( IiIii1iIIII . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl , iIIi1iiii1ii )
  if 86 - 86: Ii1I + Ii1I - Oo0Ooo * I1IiiI
 elif ( IiIii1iIIII . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl , iIIi1iiii1ii )
  if 52 - 52: I11i - OoO0O00 - I1IiiI % OoOoOO00 % OoOoOO00 + Oo0Ooo
 elif ( IiIii1iIIII . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 88 - 88: iIii1I11I1II1 * OoO0O00 / IiII
 elif ( IiIii1iIIII . type == LISP_MAP_NOTIFY ) :
  if ( O0oOO0O00 == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-rtr" ) ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-itr" ) ) :
   lisp_process_unicast_map_notify ( lisp_sockets , packet , source )
   if 74 - 74: I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
   if 55 - 55: OoO0O00 % IiII
 elif ( IiIii1iIIII . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
 elif ( IiIii1iIIII . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
 elif ( IiIii1iIIII . type == LISP_NAT_INFO and IiIii1iIIII . is_info_reply ( ) ) :
  Oo0OoO00O , ii1I1I1iII , o0000o = lisp_process_info_reply ( source , packet , True )
  if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
 elif ( IiIii1iIIII . type == LISP_NAT_INFO and IiIii1iIIII . is_info_reply ( ) == False ) :
  O0O0 = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , O0O0 , udp_sport ,
 None )
  if 63 - 63: I1Ii111 + iII111i
 elif ( IiIii1iIIII . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 6 - 6: I1ii11iIi11i + Ii1I
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( IiIii1iIIII . type ) )
  if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
 return ( o0000o )
 if 97 - 97: ooOoO0o + OOooOOo
 if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
 if 6 - 6: Oo0Ooo + I1IiiI
 if 48 - 48: oO0o . I1ii11iIi11i
 if 59 - 59: IiII - Ii1I
 if 62 - 62: OOooOOo * o0oOOo0O0Ooo + IiII * o0oOOo0O0Ooo * i11iIiiIii - O0
 if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp ) :
 if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
 iIIiiIi = bold ( "RLOC-probe" , False )
 if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( iIIiiIi ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 53 - 53: o0oOOo0O0Ooo * Ii1I
  if 42 - 42: I11i + iII111i / iIii1I11I1II1
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( iIIiiIi ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 1 - 1: O0 - II111iiii
  if 75 - 75: II111iiii / OoO0O00 % II111iiii
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( iIIiiIi ) )
 return
 if 3 - 3: Ii1I - Ii1I % I1ii11iIi11i
 if 44 - 44: OOooOOo - o0oOOo0O0Ooo
 if 69 - 69: IiII + I1ii11iIi11i / o0oOOo0O0Ooo / OOooOOo
 if 31 - 31: oO0o + I1ii11iIi11i * i1IIi % I1IiiI % I1IiiI + iIii1I11I1II1
 if 62 - 62: OoooooooOO
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 38 - 38: iII111i % iII111i * ooOoO0o / OoO0O00 + ooOoO0o
 if 52 - 52: ooOoO0o . iIii1I11I1II1 / iIii1I11I1II1 % oO0o - oO0o * II111iiii
 if 57 - 57: I1Ii111
 if 23 - 23: I1ii11iIi11i + II111iiii
 if 99 - 99: o0oOOo0O0Ooo . I1IiiI + o0oOOo0O0Ooo * o0oOOo0O0Ooo / O0
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 27 - 27: OOooOOo - I1Ii111
 if 33 - 33: OOooOOo - Ii1I - iII111i + I1ii11iIi11i - i11iIiiIii
 if 89 - 89: iIii1I11I1II1 * I11i + OOooOOo
 if 27 - 27: i1IIi - OoO0O00
 if 23 - 23: iIii1I11I1II1 + Oo0Ooo * IiII
 if 80 - 80: OoooooooOO . ooOoO0o
 if 52 - 52: O0 + O0 + I1IiiI
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , map_request ,
 keys , enc , auth , mr_ttl = - 1 ) :
 if 64 - 64: ooOoO0o
 IIi1Ii = map_request . rloc_probe if ( map_request != None ) else False
 iiiI = map_request . json_telemetry if ( map_request != None ) else None
 if 87 - 87: I11i + IiII / OOooOOo
 if 70 - 70: II111iiii
 IiOo0oOoooO = lisp_map_reply ( )
 IiOo0oOoooO . rloc_probe = IIi1Ii
 IiOo0oOoooO . echo_nonce_capable = enc
 IiOo0oOoooO . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 IiOo0oOoooO . record_count = 1
 IiOo0oOoooO . nonce = nonce
 Oo00oo = IiOo0oOoooO . encode ( )
 IiOo0oOoooO . print_map_reply ( )
 if 84 - 84: I1ii11iIi11i * Oo0Ooo % I1IiiI - i11iIiiIii . OoooooooOO
 o0o0Ooo0OO00o = lisp_eid_record ( )
 o0o0Ooo0OO00o . rloc_count = len ( rloc_set )
 if ( iiiI != None ) : o0o0Ooo0OO00o . rloc_count += 1
 o0o0Ooo0OO00o . authoritative = auth
 o0o0Ooo0OO00o . record_ttl = ttl
 o0o0Ooo0OO00o . action = action
 o0o0Ooo0OO00o . eid = eid
 o0o0Ooo0OO00o . group = group
 if 5 - 5: I1ii11iIi11i
 Oo00oo += o0o0Ooo0OO00o . encode ( )
 o0o0Ooo0OO00o . print_record ( "  " , False )
 if 16 - 16: OoO0O00 . II111iiii - i1IIi % II111iiii + ooOoO0o + OoooooooOO
 ii1i1iiiI = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 36 - 36: iIii1I11I1II1 + I1IiiI + OoOoOO00 . iIii1I11I1II1
 iIiIii1I1 = None
 for OOOoOoo in rloc_set :
  II1OO0Oo0oOOO000 = OOOoOoo . rloc . is_multicast_address ( )
  ooOoooO = lisp_rloc_record ( )
  ii11I1 = IIi1Ii and ( II1OO0Oo0oOOO000 or iiiI == None )
  O0O0 = OOOoOoo . rloc . print_address_no_iid ( )
  if ( O0O0 in ii1i1iiiI or II1OO0Oo0oOOO000 ) :
   ooOoooO . local_bit = True
   ooOoooO . probe_bit = ii11I1
   ooOoooO . keys = keys
   if ( OOOoOoo . priority == 254 and lisp_i_am_rtr ) :
    ooOoooO . rloc_name = "RTR"
    if 74 - 74: i11iIiiIii . Ii1I . I1IiiI * I1IiiI
   if ( iIiIii1I1 == None ) : iIiIii1I1 = OOOoOoo . rloc
   if 51 - 51: oO0o . Oo0Ooo / i1IIi + i1IIi * i1IIi
  ooOoooO . store_rloc_entry ( OOOoOoo )
  ooOoooO . reach_bit = True
  ooOoooO . print_record ( "    " )
  Oo00oo += ooOoooO . encode ( )
  if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
  if 27 - 27: oO0o + Ii1I . i11iIiiIii
  if 97 - 97: iII111i . I1IiiI
  if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
  if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
 if ( iiiI != None ) :
  ooOoooO = lisp_rloc_record ( )
  if ( iIiIii1I1 ) : ooOoooO . rloc . copy_address ( iIiIii1I1 )
  ooOoooO . local_bit = True
  ooOoooO . probe_bit = True
  ooOoooO . reach_bit = True
  if ( lisp_i_am_rtr ) :
   ooOoooO . priority = 254
   ooOoooO . rloc_name = "RTR"
   if 45 - 45: oO0o
  I1i1iiII1iI1i = lisp_encode_telemetry ( iiiI , eo = str ( time . time ( ) ) )
  ooOoooO . json = lisp_json ( "telemetry" , I1i1iiII1iI1i )
  ooOoooO . print_record ( "    " )
  Oo00oo += ooOoooO . encode ( )
  if 72 - 72: I1ii11iIi11i
 return ( Oo00oo )
 if 100 - 100: i11iIiiIii - iII111i - I11i
 if 5 - 5: oO0o % IiII * iII111i
 if 98 - 98: iII111i / OOooOOo + IiII
 if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
 if 82 - 82: ooOoO0o % OOooOOo % Ii1I
 if 82 - 82: I1ii11iIi11i
 if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 iiIII111I111 = lisp_map_referral ( )
 iiIII111I111 . record_count = 1
 iiIII111I111 . nonce = nonce
 Oo00oo = iiIII111I111 . encode ( )
 iiIII111I111 . print_map_referral ( )
 if 9 - 9: OOooOOo + IiII - I1ii11iIi11i . OOooOOo + I11i
 o0o0Ooo0OO00o = lisp_eid_record ( )
 if 91 - 91: OoOoOO00 . i1IIi
 I1111i = 0
 if ( ddt_entry == None ) :
  o0o0Ooo0OO00o . eid = eid
  o0o0Ooo0OO00o . group = group
 else :
  I1111i = len ( ddt_entry . delegation_set )
  o0o0Ooo0OO00o . eid = ddt_entry . eid
  o0o0Ooo0OO00o . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 36 - 36: ooOoO0o * i1IIi + iII111i * OOooOOo * Ii1I
 o0o0Ooo0OO00o . rloc_count = I1111i
 o0o0Ooo0OO00o . authoritative = True
 if 74 - 74: Oo0Ooo - Oo0Ooo . I11i + I11i * OoO0O00
 if 48 - 48: iIii1I11I1II1 . I11i . II111iiii
 if 45 - 45: oO0o + ooOoO0o + OOooOOo * OOooOOo * o0oOOo0O0Ooo / Oo0Ooo
 if 61 - 61: OoooooooOO % i11iIiiIii . i1IIi . OOooOOo
 if 90 - 90: iIii1I11I1II1 - iIii1I11I1II1 % O0
 oO00O0o0Oo = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( I1111i == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   o0oO0OO0Oo0 = ddt_entry . delegation_set [ 0 ]
   if ( o0oO0OO0Oo0 . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 43 - 43: Oo0Ooo / i1IIi % Ii1I . OoOoOO00
   if ( o0oO0OO0Oo0 . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 22 - 22: iIii1I11I1II1 + Ii1I
    if 73 - 73: I1IiiI / OoO0O00 / OoooooooOO
    if 14 - 14: ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i . IiII + I1ii11iIi11i
    if 30 - 30: I1ii11iIi11i + iIii1I11I1II1 . I1ii11iIi11i
    if 9 - 9: I1IiiI - Ii1I * II111iiii - I11i
    if 85 - 85: oO0o % ooOoO0o / OOooOOo
    if 50 - 50: O0 * O0 / iIii1I11I1II1
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : oO00O0o0Oo = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  oO00O0o0Oo = ( lisp_i_am_ms and o0oO0OO0Oo0 . is_ms_peer ( ) == False )
  if 31 - 31: I1IiiI / o0oOOo0O0Ooo
  if 70 - 70: I1IiiI
 o0o0Ooo0OO00o . action = action
 o0o0Ooo0OO00o . ddt_incomplete = oO00O0o0Oo
 o0o0Ooo0OO00o . record_ttl = ttl
 if 36 - 36: ooOoO0o . oO0o . I11i - I1ii11iIi11i / OoOoOO00 * Oo0Ooo
 Oo00oo += o0o0Ooo0OO00o . encode ( )
 o0o0Ooo0OO00o . print_record ( "  " , True )
 if 42 - 42: OoooooooOO / o0oOOo0O0Ooo . Ii1I * iII111i * I1IiiI - Oo0Ooo
 if ( I1111i == 0 ) : return ( Oo00oo )
 if 76 - 76: oO0o * II111iiii
 for o0oO0OO0Oo0 in ddt_entry . delegation_set :
  ooOoooO = lisp_rloc_record ( )
  ooOoooO . rloc = o0oO0OO0Oo0 . delegate_address
  ooOoooO . priority = o0oO0OO0Oo0 . priority
  ooOoooO . weight = o0oO0OO0Oo0 . weight
  ooOoooO . mpriority = 255
  ooOoooO . mweight = 0
  ooOoooO . reach_bit = True
  Oo00oo += ooOoooO . encode ( )
  ooOoooO . print_record ( "    " )
  if 81 - 81: I11i
 return ( Oo00oo )
 if 2 - 2: OoOoOO00
 if 75 - 75: I1IiiI - OoooooooOO * I1Ii111
 if 1 - 1: o0oOOo0O0Ooo % oO0o * I1Ii111 - i1IIi - iII111i . oO0o
 if 25 - 25: i1IIi * o0oOOo0O0Ooo / oO0o
 if 11 - 11: IiII + II111iiii
 if 37 - 37: O0
 if 98 - 98: IiII * OoooooooOO . iII111i
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 34 - 34: OoooooooOO + I1Ii111
 if ( map_request . target_group . is_null ( ) ) :
  OoO0oO = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  OoO0oO = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( OoO0oO ) : OoO0oO = OoO0oO . lookup_source_cache ( map_request . target_eid , False )
  if 57 - 57: iII111i
 i1iiii = map_request . print_prefix ( )
 if 9 - 9: i1IIi - I1Ii111 + I1Ii111
 if ( OoO0oO == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( i1iiii , False ) ) )
  if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
  return
  if 58 - 58: OoooooooOO . II111iiii . O0 % I1Ii111 / OoooooooOO
  if 64 - 64: Oo0Ooo + oO0o . OoO0O00
 o0oo0OO0oO = OoO0oO . print_eid_tuple ( )
 if 95 - 95: I1Ii111 . IiII % OoO0O00 - OOooOOo - I11i
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( o0oo0OO0oO , False ) , green ( i1iiii , False ) ) )
 if 55 - 55: OoooooooOO % I1ii11iIi11i % iII111i / IiII
 if 65 - 65: II111iiii
 if 58 - 58: iIii1I11I1II1 / i11iIiiIii . iII111i . OOooOOo * I1ii11iIi11i + OoooooooOO
 if 13 - 13: OoooooooOO + iII111i * i11iIiiIii % IiII + oO0o . o0oOOo0O0Ooo
 if 31 - 31: o0oOOo0O0Ooo - ooOoO0o
 iiII1 = map_request . itr_rlocs [ 0 ]
 if ( iiII1 . is_private_address ( ) and lisp_nat_traversal ) :
  iiII1 = source
  if 60 - 60: IiII + I1IiiI
  if 61 - 61: OoO0O00
 o0Oo0o = map_request . nonce
 O00oooO0 = lisp_nonce_echoing
 iI1iiiiiii = map_request . keys
 if 10 - 10: I1IiiI
 if 14 - 14: OoO0O00
 if 88 - 88: i1IIi * II111iiii / i11iIiiIii % IiII . IiII
 if 93 - 93: OoOoOO00 * i1IIi . Ii1I
 if 2 - 2: i1IIi
 OoO00 = map_request . json_telemetry
 if ( OoO00 != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( OoO00 , ei = etr_in_ts )
  if 48 - 48: Ii1I
  if 62 - 62: oO0o - I1ii11iIi11i - oO0o - OoO0O00 * Oo0Ooo
 OoO0oO . map_replies_sent += 1
 if 47 - 47: o0oOOo0O0Ooo
 Oo00oo = lisp_build_map_reply ( OoO0oO . eid , OoO0oO . group , OoO0oO . rloc_set , o0Oo0o ,
 LISP_NO_ACTION , 1440 , map_request , iI1iiiiiii , O00oooO0 , True , ttl )
 if 88 - 88: iIii1I11I1II1 + OOooOOo . II111iiii / i11iIiiIii % OOooOOo % IiII
 if 38 - 38: OOooOOo
 if 82 - 82: OoOoOO00 % II111iiii * ooOoO0o + OoooooooOO + I1IiiI
 if 89 - 89: ooOoO0o % i1IIi - OoooooooOO
 if 100 - 100: Ii1I % I1ii11iIi11i % I1IiiI
 if 19 - 19: I1ii11iIi11i . o0oOOo0O0Ooo % Oo0Ooo / OoooooooOO
 if 68 - 68: iII111i
 if 55 - 55: IiII . i11iIiiIii % OoooooooOO
 if 88 - 88: Ii1I * o0oOOo0O0Ooo / oO0o
 if 58 - 58: O0
 if 43 - 43: O0 / i1IIi / I11i % I1IiiI
 if 82 - 82: i11iIiiIii * i11iIiiIii + I1Ii111 - I1ii11iIi11i * oO0o - Ii1I
 if 40 - 40: o0oOOo0O0Ooo + OoO0O00 % i1IIi % iII111i * I1Ii111
 if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
 if 34 - 34: OoooooooOO * i11iIiiIii
 if 33 - 33: II111iiii
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  I1I111i = ( iiII1 . is_private_address ( ) == False )
  iiO0ooooOooo = iiII1 . print_address_no_iid ( )
  if ( I1I111i and iiO0ooooOooo in lisp_rtr_list or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , iiII1 , None , Oo00oo )
   return
   if 59 - 59: iIii1I11I1II1 % I11i
   if 93 - 93: I1ii11iIi11i
   if 50 - 50: ooOoO0o % OoO0O00 % OoO0O00
   if 36 - 36: I1IiiI * O0 . IiII / I1Ii111
   if 15 - 15: I11i + iII111i
   if 79 - 79: i11iIiiIii * IiII % iII111i
 lisp_send_map_reply ( lisp_sockets , Oo00oo , iiII1 , sport )
 return
 if 18 - 18: iIii1I11I1II1 - O0 . o0oOOo0O0Ooo % oO0o
 if 73 - 73: IiII + I11i % I1IiiI * iII111i . O0
 if 17 - 17: OoO0O00 * OoOoOO00 % O0 % iII111i / i1IIi
 if 100 - 100: i11iIiiIii
 if 54 - 54: O0 * Ii1I + Ii1I
 if 59 - 59: i11iIiiIii % iII111i
 if 54 - 54: I11i . ooOoO0o / OOooOOo % I1Ii111
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 13 - 13: I11i / O0 . o0oOOo0O0Ooo . ooOoO0o
 if 7 - 7: OoO0O00 + OoooooooOO % II111iiii % oO0o
 if 48 - 48: OOooOOo . II111iiii * OOooOOo - I11i / iIii1I11I1II1 / i11iIiiIii
 if 37 - 37: II111iiii % O0 + iIii1I11I1II1 - I1IiiI . I11i + I1ii11iIi11i
 iiII1 = map_request . itr_rlocs [ 0 ]
 if ( iiII1 . is_private_address ( ) ) : iiII1 = source
 o0Oo0o = map_request . nonce
 if 14 - 14: ooOoO0o % iIii1I11I1II1 % ooOoO0o / IiII + OOooOOo
 o0Ooo0Oooo0o = map_request . target_eid
 oo0oOooo0O = map_request . target_group
 if 14 - 14: Oo0Ooo
 OO00O000OOO = [ ]
 for iIi1Ii1i in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( iIi1Ii1i == None ) : continue
  iIIiI11 = lisp_rloc ( )
  iIIiI11 . rloc . copy_address ( iIi1Ii1i )
  iIIiI11 . priority = 254
  OO00O000OOO . append ( iIIiI11 )
  if 46 - 46: II111iiii . i11iIiiIii + I1ii11iIi11i + I1IiiI
  if 74 - 74: iII111i - Ii1I - iII111i
 O00oooO0 = lisp_nonce_echoing
 iI1iiiiiii = map_request . keys
 if 23 - 23: I1ii11iIi11i
 if 69 - 69: OOooOOo * I11i % i11iIiiIii
 if 63 - 63: OoOoOO00 + I1IiiI / I1ii11iIi11i / o0oOOo0O0Ooo % I1IiiI
 if 67 - 67: I1Ii111 . oO0o % I1ii11iIi11i % OOooOOo + I1IiiI
 if 4 - 4: iII111i - i11iIiiIii * ooOoO0o
 OoO00 = map_request . json_telemetry
 if ( OoO00 != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( OoO00 , ei = etr_in_ts )
  if 74 - 74: Oo0Ooo . OOooOOo + OOooOOo / OOooOOo + I1IiiI + i1IIi
  if 32 - 32: i11iIiiIii % Ii1I
 Oo00oo = lisp_build_map_reply ( o0Ooo0Oooo0o , oo0oOooo0O , OO00O000OOO , o0Oo0o , LISP_NO_ACTION ,
 1440 , map_request , iI1iiiiiii , O00oooO0 , True , ttl )
 lisp_send_map_reply ( lisp_sockets , Oo00oo , iiII1 , sport )
 return
 if 92 - 92: OoOoOO00 % o0oOOo0O0Ooo % ooOoO0o - IiII - oO0o
 if 90 - 90: ooOoO0o
 if 11 - 11: OoOoOO00 % OOooOOo . i11iIiiIii * I1IiiI % O0 % iIii1I11I1II1
 if 18 - 18: Oo0Ooo % OOooOOo + IiII
 if 28 - 28: OOooOOo . OoO0O00 / o0oOOo0O0Ooo + II111iiii / iIii1I11I1II1 * II111iiii
 if 83 - 83: II111iiii . OoOoOO00 - i11iIiiIii . OoOoOO00 . i1IIi % OoooooooOO
 if 47 - 47: II111iiii
 if 30 - 30: i1IIi . Oo0Ooo / o0oOOo0O0Ooo + IiII * OOooOOo
 if 26 - 26: Ii1I % O0 - i1IIi % iII111i * OoO0O00
 if 60 - 60: I1ii11iIi11i * iII111i / OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 OO00O000OOO = target_site_eid . registered_rlocs
 if 94 - 94: OoO0O00 . ooOoO0o
 i111i1iIi1i = lisp_site_eid_lookup ( seid , group , False )
 if ( i111i1iIi1i == None ) : return ( OO00O000OOO )
 if 25 - 25: II111iiii % I11i
 if 16 - 16: OoOoOO00 % iII111i . OOooOOo * iIii1I11I1II1 / oO0o . OoooooooOO
 if 13 - 13: oO0o / iII111i . oO0o * i11iIiiIii . iIii1I11I1II1
 if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
 oO00Oooo0o0o0 = None
 Oo0O0O0oo0 = [ ]
 for OOOoOoo in OO00O000OOO :
  if ( OOOoOoo . is_rtr ( ) ) : continue
  if ( OOOoOoo . rloc . is_private_address ( ) ) :
   oOoOOOoO0O0oo = copy . deepcopy ( OOOoOoo )
   Oo0O0O0oo0 . append ( oOoOOOoO0O0oo )
   continue
   if 20 - 20: iII111i - OOooOOo - I11i * oO0o
  oO00Oooo0o0o0 = OOOoOoo
  break
  if 88 - 88: I1IiiI - I1Ii111
 if ( oO00Oooo0o0o0 == None ) : return ( OO00O000OOO )
 oO00Oooo0o0o0 = oO00Oooo0o0o0 . rloc . print_address_no_iid ( )
 if 50 - 50: OoOoOO00
 if 67 - 67: OOooOOo
 if 90 - 90: Oo0Ooo % iII111i % Oo0Ooo * I11i / OoOoOO00
 if 49 - 49: I1ii11iIi11i * II111iiii
 o0ooO00 = None
 for OOOoOoo in i111i1iIi1i . registered_rlocs :
  if ( OOOoOoo . is_rtr ( ) ) : continue
  if ( OOOoOoo . rloc . is_private_address ( ) ) : continue
  o0ooO00 = OOOoOoo
  break
  if 40 - 40: I11i . iII111i + OoOoOO00 % I1ii11iIi11i
 if ( o0ooO00 == None ) : return ( OO00O000OOO )
 o0ooO00 = o0ooO00 . rloc . print_address_no_iid ( )
 if 79 - 79: I1Ii111 - OOooOOo * I1ii11iIi11i + i11iIiiIii . iII111i
 if 3 - 3: Oo0Ooo
 if 81 - 81: OoO0O00 / OoO0O00 . I1ii11iIi11i
 if 100 - 100: iIii1I11I1II1 % II111iiii - I1ii11iIi11i . iIii1I11I1II1 + IiII % iIii1I11I1II1
 o0o0oo0oO = target_site_eid . site_id
 if ( o0o0oo0oO == 0 ) :
  if ( o0ooO00 == oO00Oooo0o0o0 ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( oO00Oooo0o0o0 ) )
   if 48 - 48: Ii1I % i1IIi
   return ( Oo0O0O0oo0 )
   if 38 - 38: OOooOOo / I1ii11iIi11i % oO0o / o0oOOo0O0Ooo
  return ( OO00O000OOO )
  if 54 - 54: OoOoOO00 * OoooooooOO - OoO0O00 * OoOoOO00 % I1ii11iIi11i * I11i
  if 34 - 34: I11i - oO0o + I11i * OoooooooOO * I11i
  if 73 - 73: OOooOOo * iII111i * OoO0O00
  if 11 - 11: I1Ii111 * II111iiii
  if 3 - 3: Oo0Ooo * OOooOOo
  if 13 - 13: I1Ii111 + i11iIiiIii / OOooOOo
  if 98 - 98: I1IiiI * Oo0Ooo
 if ( o0o0oo0oO == i111i1iIi1i . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( o0o0oo0oO ) )
  return ( Oo0O0O0oo0 )
  if 9 - 9: O0 / i11iIiiIii . iIii1I11I1II1 . IiII
 return ( OO00O000OOO )
 if 14 - 14: OoOoOO00 . OOooOOo - Oo0Ooo + I1Ii111 % ooOoO0o
 if 95 - 95: OoO0O00 * II111iiii + i1IIi
 if 22 - 22: Ii1I / ooOoO0o % I11i + OoO0O00 . ooOoO0o
 if 61 - 61: O0 - iIii1I11I1II1 * Oo0Ooo . Ii1I + O0
 if 20 - 20: ooOoO0o / ooOoO0o - Ii1I - ooOoO0o
 if 93 - 93: O0 * OoOoOO00 * iIii1I11I1II1
 if 3 - 3: I1ii11iIi11i - O0
 if 46 - 46: iII111i
 if 99 - 99: oO0o
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 o0ooOo000Oo0 = [ ]
 OO00O000OOO = [ ]
 if 16 - 16: ooOoO0o % iII111i - o0oOOo0O0Ooo % I11i + i11iIiiIii
 if 6 - 6: i11iIiiIii
 if 66 - 66: I1Ii111 * I1ii11iIi11i . Ii1I
 if 28 - 28: oO0o - I1IiiI
 if 42 - 42: i1IIi
 if 8 - 8: Ii1I - oO0o
 OO0i1 = False
 ooO0Oo0 = False
 for OOOoOoo in registered_rloc_set :
  if ( OOOoOoo . priority != 254 ) : continue
  ooO0Oo0 |= True
  if ( OOOoOoo . rloc . is_exact_match ( mr_source ) == False ) : continue
  OO0i1 = True
  break
  if 74 - 74: i1IIi
  if 3 - 3: OoO0O00 - o0oOOo0O0Ooo - Ii1I
  if 33 - 33: ooOoO0o + I1ii11iIi11i - I1IiiI . iII111i / OoO0O00
  if 91 - 91: OOooOOo - OoooooooOO . OoO0O00
  if 34 - 34: Ii1I . I1IiiI . i1IIi * I1ii11iIi11i
  if 77 - 77: ooOoO0o . II111iiii
  if 41 - 41: IiII
 if ( ooO0Oo0 == False ) : return ( registered_rloc_set )
 if 27 - 27: IiII / IiII
 if 91 - 91: Ii1I
 if 93 - 93: OoO0O00 * OoO0O00 * I1ii11iIi11i * OoO0O00 * o0oOOo0O0Ooo
 if 84 - 84: I1Ii111 * OoO0O00 - ooOoO0o - Oo0Ooo . OoO0O00 % oO0o
 if 98 - 98: OoO0O00 . i1IIi
 if 58 - 58: i1IIi * O0 + I1ii11iIi11i . IiII
 if 11 - 11: OOooOOo + iIii1I11I1II1 - ooOoO0o * OoO0O00 * i11iIiiIii
 if 45 - 45: I1ii11iIi11i + Oo0Ooo
 if 7 - 7: Oo0Ooo + ooOoO0o - I1Ii111 * iIii1I11I1II1
 if 6 - 6: ooOoO0o % I1Ii111 % ooOoO0o . Ii1I * Oo0Ooo . IiII
 OoooO0oo0o0 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 39 - 39: o0oOOo0O0Ooo
 if 73 - 73: IiII
 if 92 - 92: OOooOOo / ooOoO0o . I1Ii111 . iII111i / ooOoO0o
 if 83 - 83: iIii1I11I1II1 - OoO0O00 - I1Ii111
 if 27 - 27: IiII - iII111i * i11iIiiIii % i11iIiiIii + OoOoOO00 . I1Ii111
 for OOOoOoo in registered_rloc_set :
  if ( OoooO0oo0o0 and OOOoOoo . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and OOOoOoo . priority == 255 ) : continue
  if ( multicast and OOOoOoo . mpriority == 255 ) : continue
  if ( OOOoOoo . priority == 254 ) :
   o0ooOo000Oo0 . append ( OOOoOoo )
  else :
   OO00O000OOO . append ( OOOoOoo )
   if 10 - 10: IiII / i11iIiiIii
   if 6 - 6: I11i - OOooOOo
   if 100 - 100: Oo0Ooo / OOooOOo + iII111i - o0oOOo0O0Ooo + OoO0O00 % IiII
   if 91 - 91: Ii1I % I11i % Oo0Ooo / OoO0O00 - II111iiii - o0oOOo0O0Ooo
   if 50 - 50: OoooooooOO
   if 51 - 51: II111iiii - oO0o % OoooooooOO - II111iiii / O0 - OoooooooOO
 if ( OO0i1 ) : return ( OO00O000OOO )
 if 21 - 21: iII111i * o0oOOo0O0Ooo
 if 85 - 85: I1ii11iIi11i . OoOoOO00 . i1IIi % OOooOOo * I11i . I1Ii111
 if 26 - 26: I1Ii111 + Oo0Ooo + II111iiii % OoOoOO00 % OOooOOo
 if 40 - 40: I1ii11iIi11i + i1IIi
 if 9 - 9: OOooOOo
 if 74 - 74: OoOoOO00 - OOooOOo % OoOoOO00
 if 82 - 82: I11i % IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
 if 65 - 65: IiII / O0 * II111iiii + oO0o
 if 52 - 52: o0oOOo0O0Ooo - OoOoOO00 * II111iiii / OoooooooOO
 if 44 - 44: OOooOOo - oO0o + o0oOOo0O0Ooo - i1IIi % o0oOOo0O0Ooo
 if 79 - 79: iII111i . iIii1I11I1II1
 if 42 - 42: i11iIiiIii / IiII . O0 / OOooOOo . iII111i * i1IIi
 OO00O000OOO = [ ]
 for OOOoOoo in registered_rloc_set :
  if ( OOOoOoo . rloc . is_ipv6 ( ) ) : OO00O000OOO . append ( OOOoOoo )
  if ( OOOoOoo . rloc . is_private_address ( ) ) : OO00O000OOO . append ( OOOoOoo )
  if 83 - 83: iIii1I11I1II1 . II111iiii * Oo0Ooo . I1IiiI - I1IiiI - iIii1I11I1II1
 OO00O000OOO += o0ooOo000Oo0
 return ( OO00O000OOO )
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
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 iIiI1IIi1Ii1i = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 iIiI1IIi1Ii1i . add ( reply_eid )
 return ( iIiI1IIi1Ii1i )
 if 28 - 28: I1IiiI - I1Ii111
 if 60 - 60: OOooOOo / O0 * o0oOOo0O0Ooo * OoooooooOO
 if 95 - 95: II111iiii
 if 2 - 2: I11i - OoooooooOO / I1ii11iIi11i . I1ii11iIi11i * i11iIiiIii % II111iiii
 if 1 - 1: i11iIiiIii / OoOoOO00 - I1ii11iIi11i . I1IiiI / I1Ii111 % iIii1I11I1II1
 if 87 - 87: OoOoOO00 - II111iiii + Oo0Ooo
 if 44 - 44: i1IIi + I1ii11iIi11i / iIii1I11I1II1
 if 47 - 47: I1Ii111
 if 41 - 41: IiII
 if 25 - 25: I11i % iIii1I11I1II1
 if 27 - 27: iIii1I11I1II1 . O0 . oO0o
 if 21 - 21: oO0o * I1ii11iIi11i
 if 44 - 44: o0oOOo0O0Ooo * IiII - o0oOOo0O0Ooo
 if 90 - 90: i1IIi + I1ii11iIi11i * oO0o % i11iIiiIii - OoO0O00
 if 12 - 12: OoO0O00 . I1ii11iIi11i - I1IiiI % OOooOOo
def lisp_convert_reply_to_notify ( packet ) :
 if 9 - 9: Ii1I / O0
 if 95 - 95: iII111i / I11i
 if 86 - 86: O0 / II111iiii . Oo0Ooo / Oo0Ooo * II111iiii
 if 22 - 22: Ii1I
 oo0OOo00OOoO = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 oo0OOo00OOoO = socket . ntohl ( oo0OOo00OOoO ) & 0xff
 o0Oo0o = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 5 - 5: I1Ii111 * I1IiiI * O0 + I1Ii111
 if 19 - 19: i11iIiiIii / IiII - i1IIi - I1IiiI * I11i
 if 43 - 43: IiII * Oo0Ooo / OoOoOO00 + I1IiiI - i11iIiiIii + II111iiii
 if 81 - 81: I11i / Oo0Ooo % Ii1I % OoO0O00
 iIiIii = ( LISP_MAP_NOTIFY << 28 ) | oo0OOo00OOoO
 IiIii1iIIII = struct . pack ( "I" , socket . htonl ( iIiIii ) )
 i111 = struct . pack ( "I" , 0 )
 if 87 - 87: O0 % II111iiii
 if 42 - 42: I1IiiI . i1IIi
 if 98 - 98: o0oOOo0O0Ooo % I11i . Oo0Ooo * Oo0Ooo % iII111i
 if 37 - 37: OoO0O00 / I1Ii111 . I1Ii111 * i1IIi
 packet = IiIii1iIIII + o0Oo0o + i111 + packet
 return ( packet )
 if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
 if 13 - 13: II111iiii
 if 36 - 36: iII111i - oO0o / Oo0Ooo / O0 . OoO0O00 . i1IIi
 if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
 if 98 - 98: oO0o . Oo0Ooo
 if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
 if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
 if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
def lisp_notify_subscribers ( lisp_sockets , eid_record , rloc_records ,
 registered_eid , site ) :
 if 64 - 64: OoooooooOO + OOooOOo
 for IIi1II1I in lisp_pubsub_cache :
  for iIiI1IIi1Ii1i in list ( lisp_pubsub_cache [ IIi1II1I ] . values ( ) ) :
   oO0ooOOO = iIiI1IIi1Ii1i . eid_prefix
   if ( oO0ooOOO . is_more_specific ( registered_eid ) == False ) : continue
   if 57 - 57: I1Ii111 / OoO0O00 . OoOoOO00 % I1IiiI - OoO0O00 % o0oOOo0O0Ooo
   oO0oO00OO00 = iIiI1IIi1Ii1i . itr
   ooO0 = iIiI1IIi1Ii1i . port
   Oooo000 = red ( oO0oO00OO00 . print_address_no_iid ( ) , False )
   Oo0Oo0o = bold ( "subscriber" , False )
   oOOOOOo0OO0o0oOO0 = "0x" + lisp_hex_string ( iIiI1IIi1Ii1i . xtr_id )
   o0Oo0o = "0x" + lisp_hex_string ( iIiI1IIi1Ii1i . nonce )
   if 64 - 64: OoO0O00 * Oo0Ooo . II111iiii * Oo0Ooo % ooOoO0o - IiII
   lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( Oo0Oo0o , Oooo000 , ooO0 , oOOOOOo0OO0o0oOO0 , green ( IIi1II1I , False ) , o0Oo0o ) )
   if 40 - 40: Ii1I - OOooOOo % I1Ii111 * oO0o
   if 17 - 17: ooOoO0o - Ii1I * Ii1I % I1Ii111 - o0oOOo0O0Ooo + OoO0O00
   if 71 - 71: OOooOOo . IiII / ooOoO0o
   if 23 - 23: o0oOOo0O0Ooo * iIii1I11I1II1 - OoooooooOO - OoOoOO00
   if 59 - 59: Ii1I - ooOoO0o / Ii1I - oO0o - iII111i
   if 10 - 10: I1Ii111 . Oo0Ooo . Ii1I . i11iIiiIii / OoooooooOO
   o0o0 = copy . deepcopy ( eid_record )
   o0o0 . eid . copy_address ( oO0ooOOO )
   o0o0 = o0o0 . encode ( ) + rloc_records
   lisp_build_map_notify ( lisp_sockets , o0o0 , [ IIi1II1I ] , 1 , oO0oO00OO00 ,
 ooO0 , iIiI1IIi1Ii1i . nonce , 0 , 0 , 0 , site , False )
   if 64 - 64: II111iiii % I1ii11iIi11i . OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i
   iIiI1IIi1Ii1i . map_notify_count += 1
   if 43 - 43: OoooooooOO * I1IiiI
   if 2 - 2: OOooOOo / oO0o + I1ii11iIi11i + i11iIiiIii % iIii1I11I1II1 . I1ii11iIi11i
 return
 if 100 - 100: Oo0Ooo * ooOoO0o + Ii1I / iII111i * o0oOOo0O0Ooo
 if 26 - 26: I1Ii111 * OoOoOO00
 if 38 - 38: II111iiii
 if 50 - 50: OoOoOO00 . IiII - OOooOOo
 if 46 - 46: iIii1I11I1II1
 if 97 - 97: O0 * OOooOOo - o0oOOo0O0Ooo % o0oOOo0O0Ooo * II111iiii % I11i
 if 65 - 65: iIii1I11I1II1 / OOooOOo
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 2 - 2: I11i - OOooOOo / o0oOOo0O0Ooo
 if 14 - 14: I11i + Oo0Ooo + i11iIiiIii - i1IIi . O0
 if 47 - 47: o0oOOo0O0Ooo / i1IIi * IiII
 if 50 - 50: I11i
 iIiI1IIi1Ii1i = lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl ,
 xtr_id )
 if 9 - 9: iII111i . OoOoOO00 * iII111i
 o0Ooo0Oooo0o = green ( reply_eid . print_prefix ( ) , False )
 oO0oO00OO00 = red ( itr_rloc . print_address_no_iid ( ) , False )
 OoooO00OoooOo = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( OoooO00OoooOo ,
 o0Ooo0Oooo0o , oO0oO00OO00 , xtr_id ) )
 if 49 - 49: i1IIi * II111iiii * Oo0Ooo % oO0o / II111iiii
 if 8 - 8: I1IiiI . o0oOOo0O0Ooo / OoooooooOO - II111iiii
 if 93 - 93: OoOoOO00 / OoOoOO00 / OoOoOO00
 if 74 - 74: ooOoO0o % Oo0Ooo - iII111i - I1IiiI
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 iIiI1IIi1Ii1i . map_notify_count += 1
 return
 if 51 - 51: i11iIiiIii % OoOoOO00
 if 17 - 17: ooOoO0o - i1IIi
 if 73 - 73: iIii1I11I1II1 - I1Ii111 % Oo0Ooo . O0
 if 16 - 16: OoO0O00 / Oo0Ooo / IiII . Oo0Ooo - OoooooooOO
 if 5 - 5: OoOoOO00 . I11i
 if 28 - 28: I11i % OOooOOo + Oo0Ooo / OoO0O00 % o0oOOo0O0Ooo + OoO0O00
 if 20 - 20: ooOoO0o . iII111i % OOooOOo + i11iIiiIii
 if 64 - 64: i1IIi . o0oOOo0O0Ooo * I1Ii111 - O0
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 76 - 76: I1IiiI % Ii1I + OoO0O00 + I1ii11iIi11i * II111iiii + Oo0Ooo
 if 3 - 3: Ii1I - I1IiiI + O0
 if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
 if 45 - 45: OoooooooOO / oO0o . I1ii11iIi11i + OOooOOo
 if 54 - 54: Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
 if 61 - 61: I11i / IiII % OoooooooOO - i11iIiiIii * i1IIi % o0oOOo0O0Ooo
 o0Ooo0Oooo0o = map_request . target_eid
 oo0oOooo0O = map_request . target_group
 i1iiii = lisp_print_eid_tuple ( o0Ooo0Oooo0o , oo0oOooo0O )
 iiII1 = map_request . itr_rlocs [ 0 ]
 oOOOOOo0OO0o0oOO0 = map_request . xtr_id
 o0Oo0o = map_request . nonce
 oOoO0OooO0O = LISP_NO_ACTION
 iIiI1IIi1Ii1i = map_request . subscribe_bit
 if 67 - 67: o0oOOo0O0Ooo - Ii1I
 if 29 - 29: OoOoOO00 . I1ii11iIi11i
 if 24 - 24: OOooOOo + i1IIi . I11i . OoOoOO00 + OoooooooOO
 if 98 - 98: ooOoO0o + i1IIi / I1IiiI
 if 1 - 1: IiII . OoooooooOO + II111iiii
 iiIi11i1ii1I = True
 iiiI1i = ( lisp_get_eid_hash ( o0Ooo0Oooo0o ) != None )
 if ( iiiI1i ) :
  O0OoO0ooOoo = map_request . map_request_signature
  if ( O0OoO0ooOoo == None ) :
   iiIi11i1ii1I = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 91 - 91: II111iiii / iIii1I11I1II1 / OoOoOO00 . II111iiii
  else :
   OO00O = map_request . signature_eid
   oOo0oO0o , ooOoI1IiiI , iiIi11i1ii1I = lisp_lookup_public_key ( OO00O )
   if ( iiIi11i1ii1I ) :
    iiIi11i1ii1I = map_request . verify_map_request_sig ( ooOoI1IiiI )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( OO00O . print_address ( ) , oOo0oO0o . print_address ( ) ) )
    if 18 - 18: OoO0O00 - I11i / OOooOOo / oO0o
    if 53 - 53: I1ii11iIi11i % i1IIi . i11iIiiIii
   I1I1i = bold ( "passed" , False ) if iiIi11i1ii1I else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( I1I1i ) )
   if 28 - 28: OOooOOo / I1IiiI / IiII + I1IiiI / O0 / I11i
   if 10 - 10: I1Ii111 * i1IIi
   if 48 - 48: Oo0Ooo % i1IIi / iII111i . O0
 if ( iIiI1IIi1Ii1i and iiIi11i1ii1I == False ) :
  iIiI1IIi1Ii1i = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 27 - 27: I11i + iIii1I11I1II1 - i11iIiiIii
  if 81 - 81: I11i + oO0o * iIii1I11I1II1 * IiII
  if 7 - 7: I11i - I1IiiI . iII111i + O0 / iIii1I11I1II1 - I1Ii111
  if 32 - 32: ooOoO0o
  if 9 - 9: I1Ii111
  if 77 - 77: OoooooooOO * I1Ii111
  if 63 - 63: IiII * oO0o * iIii1I11I1II1
  if 18 - 18: II111iiii * o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
  if 40 - 40: oO0o - o0oOOo0O0Ooo * II111iiii
  if 4 - 4: O0
  if 9 - 9: Oo0Ooo . i1IIi - i1IIi + I1Ii111 * ooOoO0o . I1ii11iIi11i
  if 17 - 17: I11i * I1ii11iIi11i % I1IiiI + OoO0O00 + IiII
  if 90 - 90: OoooooooOO - I1IiiI / I1ii11iIi11i + oO0o - o0oOOo0O0Ooo
  if 84 - 84: OoOoOO00 + O0 % Oo0Ooo
 iiii1I1I11 = iiII1 if ( iiII1 . afi == ecm_source . afi ) else ecm_source
 if 88 - 88: oO0o % ooOoO0o - i11iIiiIii + oO0o
 i1iI11i = lisp_site_eid_lookup ( o0Ooo0Oooo0o , oo0oOooo0O , False )
 if 9 - 9: OOooOOo + Oo0Ooo
 if ( i1iI11i == None or i1iI11i . is_star_g ( ) ) :
  oo0oO0Oo = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( oo0oO0Oo ,
 green ( i1iiii , False ) ) )
  if 41 - 41: II111iiii . i1IIi
  if 78 - 78: I1IiiI * I11i % OOooOOo + Ii1I + OoOoOO00
  if 23 - 23: iII111i / Oo0Ooo % OoooooooOO * OoooooooOO . iII111i / I1ii11iIi11i
  if 30 - 30: oO0o - OoOoOO00 . I1IiiI
  lisp_send_negative_map_reply ( lisp_sockets , o0Ooo0Oooo0o , oo0oOooo0O , o0Oo0o , iiII1 ,
 mr_sport , 15 , oOOOOOo0OO0o0oOO0 , iIiI1IIi1Ii1i )
  if 17 - 17: OoOoOO00
  return ( [ o0Ooo0Oooo0o , oo0oOooo0O , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
  if 57 - 57: O0
 o0oo0OO0oO = i1iI11i . print_eid_tuple ( )
 IIiii = i1iI11i . site . site_name
 if 58 - 58: iIii1I11I1II1
 if 15 - 15: IiII / OOooOOo / I11i + i1IIi
 if 95 - 95: i1IIi + II111iiii . iIii1I11I1II1 . OoooooooOO + o0oOOo0O0Ooo / iIii1I11I1II1
 if 40 - 40: OoO0O00 / O0
 if 60 - 60: iIii1I11I1II1 / Oo0Ooo / oO0o + iII111i
 if ( iiiI1i == False and i1iI11i . require_signature ) :
  O0OoO0ooOoo = map_request . map_request_signature
  OO00O = map_request . signature_eid
  if ( O0OoO0ooOoo == None or OO00O . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( IIiii ) )
   iiIi11i1ii1I = False
  else :
   OO00O = map_request . signature_eid
   oOo0oO0o , ooOoI1IiiI , iiIi11i1ii1I = lisp_lookup_public_key ( OO00O )
   if ( iiIi11i1ii1I ) :
    iiIi11i1ii1I = map_request . verify_map_request_sig ( ooOoI1IiiI )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( OO00O . print_address ( ) , oOo0oO0o . print_address ( ) ) )
    if 66 - 66: iIii1I11I1II1 . O0 * IiII . ooOoO0o + i1IIi
    if 83 - 83: o0oOOo0O0Ooo / II111iiii + I1IiiI - iII111i + OoO0O00
   I1I1i = bold ( "passed" , False ) if iiIi11i1ii1I else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( I1I1i ) )
   if 67 - 67: I1Ii111 - OoOoOO00 . i11iIiiIii - I1Ii111 . i11iIiiIii
   if 25 - 25: I11i % I1Ii111 + Ii1I
   if 46 - 46: ooOoO0o + Oo0Ooo + oO0o / II111iiii . iIii1I11I1II1 * I1IiiI
   if 87 - 87: I11i + iIii1I11I1II1
   if 91 - 91: oO0o
   if 58 - 58: i11iIiiIii / Ii1I - OoooooooOO
 if ( iiIi11i1ii1I and i1iI11i . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( IIiii , green ( o0oo0OO0oO , False ) , green ( i1iiii , False ) ) )
  if 25 - 25: i1IIi * ooOoO0o % OOooOOo / I1IiiI
  if 75 - 75: i11iIiiIii
  if 38 - 38: iIii1I11I1II1
  if 80 - 80: OoO0O00
  if 72 - 72: I11i * II111iiii
  if 82 - 82: I1Ii111 . OoO0O00 * II111iiii
  if ( i1iI11i . accept_more_specifics == False ) :
   o0Ooo0Oooo0o = i1iI11i . eid
   oo0oOooo0O = i1iI11i . group
   if 99 - 99: iIii1I11I1II1 / iII111i % i1IIi - II111iiii / OoO0O00
   if 33 - 33: OoooooooOO / i1IIi . Ii1I
   if 96 - 96: OoOoOO00 / Oo0Ooo . II111iiii / ooOoO0o
   if 56 - 56: IiII - ooOoO0o % oO0o / Oo0Ooo * oO0o % O0
   if 71 - 71: iII111i / II111iiii - II111iiii / I1IiiI
  O0O00O = 1
  if ( i1iI11i . force_ttl != None ) :
   O0O00O = i1iI11i . force_ttl | 0x80000000
   if 24 - 24: O0 . I1IiiI + IiII . IiII
   if 53 - 53: II111iiii + Ii1I * o0oOOo0O0Ooo
   if 47 - 47: Ii1I % OOooOOo . Oo0Ooo
   if 94 - 94: Ii1I - iIii1I11I1II1 + I1IiiI - iIii1I11I1II1 . o0oOOo0O0Ooo
   if 3 - 3: O0 / I11i + OoOoOO00 % IiII / i11iIiiIii
  lisp_send_negative_map_reply ( lisp_sockets , o0Ooo0Oooo0o , oo0oOooo0O , o0Oo0o , iiII1 ,
 mr_sport , O0O00O , oOOOOOo0OO0o0oOO0 , iIiI1IIi1Ii1i )
  if 25 - 25: II111iiii / I1ii11iIi11i % iIii1I11I1II1
  return ( [ o0Ooo0Oooo0o , oo0oOooo0O , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 69 - 69: IiII
  if 36 - 36: I1IiiI / oO0o
  if 72 - 72: i1IIi - I1ii11iIi11i . OOooOOo + I1Ii111 - ooOoO0o
  if 69 - 69: o0oOOo0O0Ooo * I1IiiI - I11i
  if 11 - 11: OOooOOo * O0
 Iiii1iiI = False
 I1i1i = ""
 oo00ooo0OOO00 = False
 if ( i1iI11i . force_nat_proxy_reply ) :
  I1i1i = ", nat-forced"
  Iiii1iiI = True
  oo00ooo0OOO00 = True
 elif ( i1iI11i . force_proxy_reply ) :
  I1i1i = ", forced"
  oo00ooo0OOO00 = True
 elif ( i1iI11i . proxy_reply_requested ) :
  I1i1i = ", requested"
  oo00ooo0OOO00 = True
 elif ( map_request . pitr_bit and i1iI11i . pitr_proxy_reply_drop ) :
  I1i1i = ", drop-to-pitr"
  oOoO0OooO0O = LISP_DROP_ACTION
 elif ( i1iI11i . proxy_reply_action != "" ) :
  oOoO0OooO0O = i1iI11i . proxy_reply_action
  I1i1i = ", forced, action {}" . format ( oOoO0OooO0O )
  oOoO0OooO0O = LISP_DROP_ACTION if ( oOoO0OooO0O == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 56 - 56: I1ii11iIi11i * o0oOOo0O0Ooo - iII111i - ooOoO0o - I11i
  if 9 - 9: I1IiiI / O0 + I11i
  if 39 - 39: OoooooooOO * I1ii11iIi11i + II111iiii . I1Ii111 / II111iiii . I1ii11iIi11i
  if 72 - 72: OoOoOO00
  if 21 - 21: oO0o
  if 58 - 58: OoOoOO00 + i11iIiiIii % OOooOOo - i1IIi
  if 39 - 39: OoooooooOO . I1IiiI + OoOoOO00
 oO0oOoo = False
 O0o0Oo0oO0o0 = None
 if ( oo00ooo0OOO00 and i1iI11i . policy in lisp_policies ) :
  iIIiiIi = lisp_policies [ i1iI11i . policy ]
  if ( iIIiiIi . match_policy_map_request ( map_request , mr_source ) ) : O0o0Oo0oO0o0 = iIIiiIi
  if 39 - 39: OOooOOo / I1IiiI / iIii1I11I1II1 + Ii1I - i11iIiiIii
  if ( O0o0Oo0oO0o0 ) :
   iiI1I = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( iiI1I ,
 iIIiiIi . policy_name , iIIiiIi . set_action ) )
  else :
   iiI1I = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( iiI1I ,
 iIIiiIi . policy_name ) )
   oO0oOoo = True
   if 25 - 25: iII111i . OOooOOo * I1IiiI % OoO0O00 - O0 . I1IiiI
   if 92 - 92: I11i * I1Ii111 . O0 - oO0o + i1IIi % Oo0Ooo
   if 39 - 39: I1Ii111 - I1IiiI
 if ( I1i1i != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( i1iiii , False ) , IIiii , green ( o0oo0OO0oO , False ) ,
  # i1IIi . OoO0O00
 I1i1i ) )
  if 85 - 85: i11iIiiIii / OOooOOo / I11i - OOooOOo
  OO00O000OOO = i1iI11i . registered_rlocs
  O0O00O = 1440
  if ( Iiii1iiI ) :
   if ( i1iI11i . site_id != 0 ) :
    OoiIii11i11i = map_request . source_eid
    OO00O000OOO = lisp_get_private_rloc_set ( i1iI11i , OoiIii11i11i , oo0oOooo0O )
    if 46 - 46: oO0o
   if ( OO00O000OOO == i1iI11i . registered_rlocs ) :
    IiIIIIi11ii = ( i1iI11i . group . is_null ( ) == False )
    Oo0O0O0oo0 = lisp_get_partial_rloc_set ( OO00O000OOO , iiii1I1I11 , IiIIIIi11ii )
    if ( Oo0O0O0oo0 != OO00O000OOO ) :
     O0O00O = 15
     OO00O000OOO = Oo0O0O0oo0
     if 86 - 86: O0 - Oo0Ooo
     if 80 - 80: o0oOOo0O0Ooo - I1Ii111 * O0 * iIii1I11I1II1
     if 59 - 59: I1ii11iIi11i + I11i / OoO0O00
     if 36 - 36: o0oOOo0O0Ooo + ooOoO0o * I11i
     if 81 - 81: OOooOOo * I11i - I1ii11iIi11i
     if 82 - 82: I1ii11iIi11i * II111iiii - OoooooooOO % iII111i * I1IiiI % OoOoOO00
     if 81 - 81: I11i + o0oOOo0O0Ooo / iII111i
     if 35 - 35: ooOoO0o % I11i * I1ii11iIi11i
  if ( i1iI11i . force_ttl != None ) :
   O0O00O = i1iI11i . force_ttl | 0x80000000
   if 10 - 10: OoO0O00 + OoooooooOO + I1Ii111
   if 57 - 57: Ii1I % Ii1I * Oo0Ooo % i11iIiiIii
   if 12 - 12: oO0o . Oo0Ooo . I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
   if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
   if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
   if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
  if ( O0o0Oo0oO0o0 ) :
   if ( O0o0Oo0oO0o0 . set_record_ttl ) :
    O0O00O = O0o0Oo0oO0o0 . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( O0O00O ) )
    if 66 - 66: iII111i % iII111i
   if ( O0o0Oo0oO0o0 . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    oOoO0OooO0O = LISP_POLICY_DENIED_ACTION
    OO00O000OOO = [ ]
   else :
    iIIiI11 = O0o0Oo0oO0o0 . set_policy_map_reply ( )
    if ( iIIiI11 ) : OO00O000OOO = [ iIIiI11 ]
    if 59 - 59: II111iiii . i1IIi % i1IIi
    if 40 - 40: I1Ii111 . II111iiii * o0oOOo0O0Ooo + I11i - i1IIi
    if 67 - 67: o0oOOo0O0Ooo - O0 - i1IIi . ooOoO0o . iII111i
  if ( oO0oOoo ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   oOoO0OooO0O = LISP_POLICY_DENIED_ACTION
   OO00O000OOO = [ ]
   if 43 - 43: II111iiii . o0oOOo0O0Ooo + i11iIiiIii . O0 / O0 . II111iiii
   if 13 - 13: Ii1I % i11iIiiIii
  O00oooO0 = i1iI11i . echo_nonce_capable
  if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
  if 50 - 50: I1ii11iIi11i + iII111i
  if 64 - 64: oO0o
  if 11 - 11: o0oOOo0O0Ooo
  if ( iiIi11i1ii1I ) :
   ooIiIII1 = i1iI11i . eid
   i1I = i1iI11i . group
  else :
   ooIiIII1 = o0Ooo0Oooo0o
   i1I = oo0oOooo0O
   oOoO0OooO0O = LISP_AUTH_FAILURE_ACTION
   OO00O000OOO = [ ]
   if 20 - 20: I11i / OoooooooOO - I1ii11iIi11i
   if 7 - 7: oO0o - I11i
   if 59 - 59: Ii1I / o0oOOo0O0Ooo / OoO0O00 + IiII + i11iIiiIii
   if 64 - 64: o0oOOo0O0Ooo * IiII * IiII * iII111i % i11iIiiIii
   if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
   if 10 - 10: OOooOOo / I1ii11iIi11i
  if ( iIiI1IIi1Ii1i ) :
   ooIiIII1 = o0Ooo0Oooo0o
   i1I = oo0oOooo0O
   if 21 - 21: OoO0O00 % Oo0Ooo . o0oOOo0O0Ooo + IiII
   if 48 - 48: O0 / i1IIi / iII111i
   if 11 - 11: O0 - OoO0O00 + OoOoOO00 * ooOoO0o - Ii1I
   if 82 - 82: Ii1I - O0 * ooOoO0o . ooOoO0o
   if 32 - 32: o0oOOo0O0Ooo . OoooooooOO % OOooOOo
   if 2 - 2: OoOoOO00 + I1ii11iIi11i + oO0o
  packet = lisp_build_map_reply ( ooIiIII1 , i1I , OO00O000OOO ,
 o0Oo0o , oOoO0OooO0O , O0O00O , map_request , None , O00oooO0 , False )
  if 27 - 27: OoooooooOO - Ii1I / OoooooooOO + OoO0O00
  if ( iIiI1IIi1Ii1i ) :
   lisp_process_pubsub ( lisp_sockets , packet , ooIiIII1 , iiII1 ,
 mr_sport , o0Oo0o , O0O00O , oOOOOOo0OO0o0oOO0 )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , iiII1 , mr_sport )
   if 58 - 58: OOooOOo * I11i . I1IiiI
   if 46 - 46: I11i + II111iiii * iII111i % ooOoO0o - I1IiiI
  return ( [ i1iI11i . eid , i1iI11i . group , LISP_DDT_ACTION_MS_ACK ] )
  if 73 - 73: I1ii11iIi11i * iIii1I11I1II1 . I1Ii111 - Ii1I
  if 11 - 11: I11i
  if 48 - 48: IiII / O0
  if 46 - 46: ooOoO0o + oO0o
  if 7 - 7: ooOoO0o * oO0o . i1IIi
 I1111i = len ( i1iI11i . registered_rlocs )
 if ( I1111i == 0 ) :
  lprint ( ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" ) . format ( green ( i1iiii , False ) , IIiii ,
  # IiII * OoO0O00 / OoooooooOO % o0oOOo0O0Ooo + OoO0O00
 green ( o0oo0OO0oO , False ) ) )
  return ( [ i1iI11i . eid , i1iI11i . group , LISP_DDT_ACTION_MS_ACK ] )
  if 25 - 25: IiII % OOooOOo + Ii1I * I1ii11iIi11i
  if 25 - 25: iIii1I11I1II1 * OoOoOO00 % I1IiiI + IiII
  if 34 - 34: ooOoO0o - OoooooooOO . o0oOOo0O0Ooo
  if 83 - 83: II111iiii . OOooOOo
  if 88 - 88: O0
 I1111I11iI = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 81 - 81: oO0o * OOooOOo . ooOoO0o + Ii1I + OOooOOo % OoO0O00
 II1Iii1iI = map_request . target_eid . hash_address ( I1111I11iI )
 II1Iii1iI %= I1111i
 IiIi = i1iI11i . registered_rlocs [ II1Iii1iI ]
 if 58 - 58: I11i % OoooooooOO
 if ( IiIi . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( i1iiii , False ) ,
  # o0oOOo0O0Ooo / IiII % IiII % i1IIi / IiII - O0
 IIiii , green ( o0oo0OO0oO , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( i1iiii , False ) ,
  # Oo0Ooo / o0oOOo0O0Ooo . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 red ( IiIi . rloc . print_address ( ) , False ) , IIiii ,
 green ( o0oo0OO0oO , False ) ) )
  if 93 - 93: i11iIiiIii / IiII
  if 35 - 35: I1Ii111 / o0oOOo0O0Ooo
  if 44 - 44: IiII % i11iIiiIii
  if 99 - 99: ooOoO0o % iIii1I11I1II1 + o0oOOo0O0Ooo % I11i
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , IiIi . rloc , to_etr = True )
  if 66 - 66: iIii1I11I1II1
 return ( [ i1iI11i . eid , i1iI11i . group , LISP_DDT_ACTION_MS_ACK ] )
 if 74 - 74: OoooooooOO - I1Ii111 - I1IiiI
 if 30 - 30: Oo0Ooo / o0oOOo0O0Ooo % o0oOOo0O0Ooo * i1IIi
 if 58 - 58: OoooooooOO - OOooOOo - OoOoOO00 / i1IIi * Oo0Ooo / i1IIi
 if 86 - 86: OoOoOO00 . I11i
 if 97 - 97: Ii1I
 if 24 - 24: I1IiiI * i11iIiiIii
 if 83 - 83: OoOoOO00 * I1ii11iIi11i
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 64 - 64: II111iiii * i1IIi - ooOoO0o
 if 4 - 4: ooOoO0o . OoO0O00 . OoO0O00 % ooOoO0o * Oo0Ooo - I1IiiI
 if 8 - 8: I1IiiI - I1Ii111 - OoooooooOO * Oo0Ooo * Ii1I
 if 11 - 11: I1IiiI
 o0Ooo0Oooo0o = map_request . target_eid
 oo0oOooo0O = map_request . target_group
 i1iiii = lisp_print_eid_tuple ( o0Ooo0Oooo0o , oo0oOooo0O )
 o0Oo0o = map_request . nonce
 oOoO0OooO0O = LISP_DDT_ACTION_NULL
 if 43 - 43: I11i
 if 78 - 78: Ii1I % Oo0Ooo / OoO0O00 . iIii1I11I1II1 . II111iiii
 if 67 - 67: oO0o % I1Ii111
 if 72 - 72: I1IiiI . i11iIiiIii . OoOoOO00 + I1IiiI - I1Ii111 + iII111i
 if 15 - 15: I1IiiI
 O00OO = None
 if ( lisp_i_am_ms ) :
  i1iI11i = lisp_site_eid_lookup ( o0Ooo0Oooo0o , oo0oOooo0O , False )
  if ( i1iI11i == None ) : return
  if 75 - 75: O0 . I1Ii111 . Ii1I % Oo0Ooo - OOooOOo / i11iIiiIii
  if ( i1iI11i . registered ) :
   oOoO0OooO0O = LISP_DDT_ACTION_MS_ACK
   O0O00O = 1440
  else :
   o0Ooo0Oooo0o , oo0oOooo0O , oOoO0OooO0O = lisp_ms_compute_neg_prefix ( o0Ooo0Oooo0o , oo0oOooo0O )
   oOoO0OooO0O = LISP_DDT_ACTION_MS_NOT_REG
   O0O00O = 1
   if 35 - 35: OoO0O00 . II111iiii + I1Ii111 + Ii1I - O0 + OoOoOO00
 else :
  O00OO = lisp_ddt_cache_lookup ( o0Ooo0Oooo0o , oo0oOooo0O , False )
  if ( O00OO == None ) :
   oOoO0OooO0O = LISP_DDT_ACTION_NOT_AUTH
   O0O00O = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( i1iiii , False ) ) )
   if 77 - 77: O0 % Ii1I - I1ii11iIi11i
  elif ( O00OO . is_auth_prefix ( ) ) :
   if 17 - 17: OoooooooOO - OoooooooOO % I1Ii111 * Ii1I . OoooooooOO
   if 51 - 51: iIii1I11I1II1 % IiII * iIii1I11I1II1 - OoO0O00 % I1IiiI + i11iIiiIii
   if 33 - 33: I11i
   if 99 - 99: I11i
   oOoO0OooO0O = LISP_DDT_ACTION_DELEGATION_HOLE
   O0O00O = 15
   ooo00O0oo = O00OO . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( ooo00O0oo ,
   # ooOoO0o . o0oOOo0O0Ooo - II111iiii
 green ( i1iiii , False ) ) )
   if 5 - 5: ooOoO0o * OoOoOO00 * II111iiii + I1ii11iIi11i - I11i . Ii1I
   if ( oo0oOooo0O . is_null ( ) ) :
    o0Ooo0Oooo0o = lisp_ddt_compute_neg_prefix ( o0Ooo0Oooo0o , O00OO ,
 lisp_ddt_cache )
   else :
    oo0oOooo0O = lisp_ddt_compute_neg_prefix ( oo0oOooo0O , O00OO ,
 lisp_ddt_cache )
    o0Ooo0Oooo0o = lisp_ddt_compute_neg_prefix ( o0Ooo0Oooo0o , O00OO ,
 O00OO . source_cache )
    if 74 - 74: i1IIi
   O00OO = None
  else :
   ooo00O0oo = O00OO . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( ooo00O0oo , green ( i1iiii , False ) ) )
   if 3 - 3: O0 / OOooOOo - iII111i
   O0O00O = 1440
   if 60 - 60: I1IiiI
   if 3 - 3: II111iiii % IiII % I1IiiI - I1IiiI . I1Ii111 - OoOoOO00
   if 18 - 18: O0
   if 26 - 26: i1IIi - iIii1I11I1II1
   if 8 - 8: I1Ii111
   if 86 - 86: i1IIi
 Oo00oo = lisp_build_map_referral ( o0Ooo0Oooo0o , oo0oOooo0O , O00OO , oOoO0OooO0O , O0O00O , o0Oo0o )
 o0Oo0o = map_request . nonce >> 32
 if ( map_request . nonce != 0 and o0Oo0o != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , Oo00oo , ecm_source , port )
 return
 if 26 - 26: o0oOOo0O0Ooo % I1Ii111 / Oo0Ooo
 if 68 - 68: II111iiii / Oo0Ooo / Oo0Ooo
 if 1 - 1: Oo0Ooo
 if 73 - 73: Ii1I * iIii1I11I1II1 / o0oOOo0O0Ooo - o0oOOo0O0Ooo / i1IIi
 if 64 - 64: Ii1I * I1ii11iIi11i % II111iiii
 if 31 - 31: iIii1I11I1II1 % Oo0Ooo . I1IiiI % ooOoO0o
 if 38 - 38: I1ii11iIi11i + I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
 if 46 - 46: iII111i
 if 56 - 56: Oo0Ooo / II111iiii
 if 61 - 61: Ii1I - i1IIi / ooOoO0o - Oo0Ooo / IiII % Oo0Ooo
 if 53 - 53: OoooooooOO + iII111i % II111iiii * IiII
 if 10 - 10: OoOoOO00 % I11i
 if 46 - 46: i1IIi % IiII
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 iIIII = eid . hash_address ( entry_prefix )
 O00OOO = eid . addr_length ( ) * 8
 OOOoOo0o0Ooo = 0
 if 61 - 61: I1Ii111
 if 67 - 67: I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
 if 75 - 75: OOooOOo . ooOoO0o
 if 32 - 32: i1IIi / I11i + iIii1I11I1II1 . OOooOOo
 for OOOoOo0o0Ooo in range ( O00OOO ) :
  O00O0OOOo = 1 << ( O00OOO - OOOoOo0o0Ooo - 1 )
  if ( iIIII & O00O0OOOo ) : break
  if 42 - 42: i11iIiiIii . o0oOOo0O0Ooo
  if 34 - 34: OoO0O00 * iIii1I11I1II1 * I1IiiI . OoooooooOO + I1ii11iIi11i % iIii1I11I1II1
 if ( OOOoOo0o0Ooo > neg_prefix . mask_len ) : neg_prefix . mask_len = OOOoOo0o0Ooo
 return
 if 78 - 78: OoOoOO00 . oO0o - Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
 if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
 if 72 - 72: Ii1I
 if 22 - 22: o0oOOo0O0Ooo / OoO0O00 + OoOoOO00 + Ii1I . II111iiii * I11i
 if 85 - 85: i11iIiiIii / I11i
 if 28 - 28: i11iIiiIii + IiII / I11i . Ii1I / OoO0O00
 if 100 - 100: o0oOOo0O0Ooo - I11i . o0oOOo0O0Ooo
 if 90 - 90: OoOoOO00 / II111iiii / I11i * I11i - iIii1I11I1II1
 if 87 - 87: IiII
 if 92 - 92: OoO0O00 / IiII - ooOoO0o
def lisp_neg_prefix_walk ( entry , parms ) :
 o0Ooo0Oooo0o , I11111i1 , Oo00oOO00Ooo = parms
 if 72 - 72: oO0o
 if ( I11111i1 == None ) :
  if ( entry . eid . instance_id != o0Ooo0Oooo0o . instance_id ) :
   return ( [ True , parms ] )
   if 48 - 48: II111iiii % OoooooooOO * Ii1I + iIii1I11I1II1 . OoO0O00 * Oo0Ooo
  if ( entry . eid . afi != o0Ooo0Oooo0o . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( I11111i1 ) == False ) :
   return ( [ True , parms ] )
   if 50 - 50: ooOoO0o + ooOoO0o + IiII
   if 58 - 58: iIii1I11I1II1 % I11i + OoO0O00 / II111iiii % ooOoO0o
   if 46 - 46: i11iIiiIii - o0oOOo0O0Ooo / OoOoOO00 - I11i
   if 47 - 47: IiII
   if 85 - 85: I1IiiI . O0 / oO0o
   if 100 - 100: I1IiiI / IiII + OoO0O00 . iII111i
 lisp_find_negative_mask_len ( o0Ooo0Oooo0o , entry . eid , Oo00oOO00Ooo )
 return ( [ True , parms ] )
 if 39 - 39: OoooooooOO * OOooOOo - OoO0O00
 if 3 - 3: I11i . i11iIiiIii % Oo0Ooo % II111iiii . I11i
 if 88 - 88: iIii1I11I1II1 . OOooOOo % iII111i
 if 72 - 72: ooOoO0o + i11iIiiIii / i1IIi
 if 64 - 64: OOooOOo - OOooOOo
 if 42 - 42: i1IIi / ooOoO0o . I1Ii111 % OoOoOO00
 if 67 - 67: i1IIi * i11iIiiIii * I1IiiI
 if 23 - 23: Oo0Ooo
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 81 - 81: I1Ii111 % II111iiii - Oo0Ooo / I1IiiI + i11iIiiIii . I11i
 if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
 if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
 if 60 - 60: OoO0O00 / oO0o . I1IiiI + OoOoOO00 + I1ii11iIi11i % Ii1I
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 70 - 70: i1IIi * II111iiii * I1IiiI
 Oo00oOO00Ooo = lisp_address ( eid . afi , "" , 0 , 0 )
 Oo00oOO00Ooo . copy_address ( eid )
 Oo00oOO00Ooo . mask_len = 0
 if 7 - 7: OoooooooOO + II111iiii % o0oOOo0O0Ooo * O0 . OoO0O00 * OoooooooOO
 iI1ii111i1i = ddt_entry . print_eid_tuple ( )
 I11111i1 = ddt_entry . eid
 if 68 - 68: OoO0O00 * I11i
 if 52 - 52: II111iiii . OoooooooOO % O0 % II111iiii - I1ii11iIi11i % IiII
 if 66 - 66: I1Ii111 % I1ii11iIi11i
 if 77 - 77: I11i % iIii1I11I1II1 . iIii1I11I1II1 + oO0o % i11iIiiIii . IiII
 if 33 - 33: IiII - OOooOOo / i11iIiiIii * iIii1I11I1II1
 eid , I11111i1 , Oo00oOO00Ooo = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , I11111i1 , Oo00oOO00Ooo ) )
 if 2 - 2: i11iIiiIii % ooOoO0o
 if 56 - 56: IiII % ooOoO0o + I1IiiI % I11i - OOooOOo
 if 82 - 82: OoooooooOO . i1IIi . OoO0O00 . OoO0O00
 if 31 - 31: iIii1I11I1II1
 Oo00oOO00Ooo . mask_address ( Oo00oOO00Ooo . mask_len )
 if 64 - 64: ooOoO0o
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # OoO0O00 + OoO0O00
 iI1ii111i1i , Oo00oOO00Ooo . print_prefix ( ) ) )
 return ( Oo00oOO00Ooo )
 if 26 - 26: OOooOOo . I1ii11iIi11i % Oo0Ooo * OoooooooOO
 if 46 - 46: iII111i - II111iiii % I11i * iII111i - Oo0Ooo
 if 87 - 87: i1IIi
 if 8 - 8: Oo0Ooo % Oo0Ooo * IiII % Oo0Ooo % IiII + o0oOOo0O0Ooo
 if 10 - 10: ooOoO0o
 if 63 - 63: I1Ii111 / Ii1I - iIii1I11I1II1 / i11iIiiIii / IiII + I11i
 if 57 - 57: iIii1I11I1II1 % iIii1I11I1II1
 if 23 - 23: II111iiii . ooOoO0o % I1Ii111
def lisp_ms_compute_neg_prefix ( eid , group ) :
 Oo00oOO00Ooo = lisp_address ( eid . afi , "" , 0 , 0 )
 Oo00oOO00Ooo . copy_address ( eid )
 Oo00oOO00Ooo . mask_len = 0
 iii1IIiIIiiIIi1 = lisp_address ( group . afi , "" , 0 , 0 )
 iii1IIiIIiiIIi1 . copy_address ( group )
 iii1IIiIIiiIIi1 . mask_len = 0
 I11111i1 = None
 if 52 - 52: I1Ii111 - OOooOOo * OoOoOO00
 if 54 - 54: iIii1I11I1II1 * OoO0O00 / Oo0Ooo + OoooooooOO
 if 38 - 38: iIii1I11I1II1 + OOooOOo + OoO0O00 . iII111i / i1IIi + II111iiii
 if 54 - 54: Ii1I - I1IiiI + iII111i * iII111i
 if 78 - 78: I1Ii111
 if ( group . is_null ( ) ) :
  O00OO = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( O00OO == None ) :
   Oo00oOO00Ooo . mask_len = Oo00oOO00Ooo . host_mask_len ( )
   iii1IIiIIiiIIi1 . mask_len = iii1IIiIIiiIIi1 . host_mask_len ( )
   return ( [ Oo00oOO00Ooo , iii1IIiIIiiIIi1 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 79 - 79: IiII * IiII . OOooOOo + iIii1I11I1II1 . II111iiii
  oOOooOoo0O = lisp_sites_by_eid
  if ( O00OO . is_auth_prefix ( ) ) : I11111i1 = O00OO . eid
 else :
  O00OO = lisp_ddt_cache . lookup_cache ( group , False )
  if ( O00OO == None ) :
   Oo00oOO00Ooo . mask_len = Oo00oOO00Ooo . host_mask_len ( )
   iii1IIiIIiiIIi1 . mask_len = iii1IIiIIiiIIi1 . host_mask_len ( )
   return ( [ Oo00oOO00Ooo , iii1IIiIIiiIIi1 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
  if ( O00OO . is_auth_prefix ( ) ) : I11111i1 = O00OO . group
  if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
  group , I11111i1 , iii1IIiIIiiIIi1 = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , I11111i1 , iii1IIiIIiiIIi1 ) )
  if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
  if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
  iii1IIiIIiiIIi1 . mask_address ( iii1IIiIIiiIIi1 . mask_len )
  if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , I11111i1 . print_prefix ( ) if ( I11111i1 != None ) else "'not found'" ,
  # OoooooooOO + iII111i . o0oOOo0O0Ooo
  # I1Ii111 . I1IiiI / ooOoO0o
  # o0oOOo0O0Ooo + I1ii11iIi11i
 iii1IIiIIiiIIi1 . print_prefix ( ) ) )
  if 40 - 40: iII111i + OoooooooOO * Ii1I % II111iiii % I1IiiI
  oOOooOoo0O = O00OO . source_cache
  if 69 - 69: I1ii11iIi11i - o0oOOo0O0Ooo + OoO0O00 - IiII + I1ii11iIi11i
  if 96 - 96: OoooooooOO % iIii1I11I1II1 + OoooooooOO - I1IiiI * OoO0O00
  if 86 - 86: OoOoOO00 % OoO0O00 * oO0o * Ii1I - o0oOOo0O0Ooo
  if 77 - 77: I11i + O0 % I1ii11iIi11i / oO0o
  if 30 - 30: I1ii11iIi11i * O0 % I1IiiI % OoO0O00
 oOoO0OooO0O = LISP_DDT_ACTION_DELEGATION_HOLE if ( I11111i1 != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 23 - 23: O0 * OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1
 if 68 - 68: Oo0Ooo % II111iiii % I1Ii111 * IiII
 if 68 - 68: I1ii11iIi11i % iII111i - i11iIiiIii % I1ii11iIi11i
 if 65 - 65: i11iIiiIii
 if 75 - 75: OOooOOo % I1ii11iIi11i
 if 40 - 40: I1IiiI / I1IiiI
 eid , I11111i1 , Oo00oOO00Ooo = oOOooOoo0O . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , I11111i1 , Oo00oOO00Ooo ) )
 if 26 - 26: i11iIiiIii % OoO0O00 % Ii1I - ooOoO0o
 if 2 - 2: II111iiii . o0oOOo0O0Ooo * OoooooooOO + OoooooooOO
 if 18 - 18: II111iiii * OOooOOo * OoO0O00 * iIii1I11I1II1 % o0oOOo0O0Ooo / IiII
 if 95 - 95: I1ii11iIi11i + I1IiiI . OoooooooOO
 Oo00oOO00Ooo . mask_address ( Oo00oOO00Ooo . mask_len )
 if 22 - 22: I1Ii111 / I1Ii111 / OOooOOo + OoOoOO00 % I1Ii111 / Ii1I
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # Ii1I
 # OoOoOO00 - OOooOOo . I11i . I1ii11iIi11i - II111iiii
 I11111i1 . print_prefix ( ) if ( I11111i1 != None ) else "'not found'" , Oo00oOO00Ooo . print_prefix ( ) ) )
 if 48 - 48: OOooOOo - o0oOOo0O0Ooo / ooOoO0o
 if 42 - 42: I1ii11iIi11i * II111iiii + IiII + oO0o * OOooOOo + OoOoOO00
 return ( [ Oo00oOO00Ooo , iii1IIiIIiiIIi1 , oOoO0OooO0O ] )
 if 80 - 80: OoOoOO00 % OoooooooOO % Oo0Ooo % OOooOOo + ooOoO0o / O0
 if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
 if 49 - 49: ooOoO0o . Ii1I
 if 75 - 75: OOooOOo / II111iiii - Oo0Ooo + I1Ii111
 if 42 - 42: OoooooooOO * II111iiii + Ii1I % OoO0O00 / I1Ii111
 if 11 - 11: ooOoO0o / Oo0Ooo + i1IIi / IiII
 if 4 - 4: iII111i - Oo0Ooo
 if 100 - 100: OOooOOo . i1IIi
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 15 - 15: O0 % Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o * iII111i % O0
 o0Ooo0Oooo0o = map_request . target_eid
 oo0oOooo0O = map_request . target_group
 o0Oo0o = map_request . nonce
 if 31 - 31: i1IIi . Ii1I - OoooooooOO * I11i * ooOoO0o % oO0o
 if ( action == LISP_DDT_ACTION_MS_ACK ) : O0O00O = 1440
 if 61 - 61: I1Ii111 . Ii1I * I1ii11iIi11i
 if 59 - 59: OoOoOO00 + Oo0Ooo . I1ii11iIi11i - Ii1I
 if 48 - 48: I1Ii111 % Ii1I + I1IiiI * OoooooooOO % OoOoOO00 % i11iIiiIii
 if 13 - 13: iII111i % i1IIi
 iiIII111I111 = lisp_map_referral ( )
 iiIII111I111 . record_count = 1
 iiIII111I111 . nonce = o0Oo0o
 Oo00oo = iiIII111I111 . encode ( )
 iiIII111I111 . print_map_referral ( )
 if 13 - 13: iII111i / OoooooooOO + Ii1I / iII111i
 oO00O0o0Oo = False
 if 29 - 29: OOooOOo + ooOoO0o % o0oOOo0O0Ooo
 if 18 - 18: I11i + OoO0O00 + OoO0O00 . ooOoO0o
 if 37 - 37: i1IIi . IiII + I1IiiI % OoOoOO00
 if 3 - 3: i11iIiiIii + Ii1I % IiII - I1Ii111 / Oo0Ooo % iIii1I11I1II1
 if 86 - 86: Oo0Ooo + Oo0Ooo * oO0o * I1IiiI
 if 95 - 95: IiII - OoO0O00 + OOooOOo
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( o0Ooo0Oooo0o ,
 oo0oOooo0O )
  O0O00O = 15
  if 33 - 33: o0oOOo0O0Ooo . i11iIiiIii . ooOoO0o
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : O0O00O = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : O0O00O = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : O0O00O = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0O00O = 0
 if 100 - 100: i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / i11iIiiIii + OOooOOo
 Ooo0O = False
 I1111i = 0
 O00OO = lisp_ddt_cache_lookup ( o0Ooo0Oooo0o , oo0oOooo0O , False )
 if ( O00OO != None ) :
  I1111i = len ( O00OO . delegation_set )
  Ooo0O = O00OO . is_ms_peer_entry ( )
  O00OO . map_referrals_sent += 1
  if 69 - 69: iII111i - OoOoOO00 / O0
  if 22 - 22: o0oOOo0O0Ooo % OoooooooOO + oO0o + Oo0Ooo
  if 34 - 34: iII111i / I11i + i1IIi + I1ii11iIi11i * OoooooooOO * IiII
  if 70 - 70: iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / II111iiii + I1IiiI
  if 33 - 33: oO0o
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : oO00O0o0Oo = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  oO00O0o0Oo = ( Ooo0O == False )
  if 1 - 1: OoOoOO00 . i11iIiiIii % I1Ii111 + OoooooooOO - Oo0Ooo . I1ii11iIi11i
  if 46 - 46: i11iIiiIii + I11i - iIii1I11I1II1 / OoO0O00 - ooOoO0o / i1IIi
  if 44 - 44: o0oOOo0O0Ooo + Oo0Ooo
  if 46 - 46: OOooOOo % I1IiiI
  if 66 - 66: iIii1I11I1II1 . o0oOOo0O0Ooo - ooOoO0o
 o0o0Ooo0OO00o = lisp_eid_record ( )
 o0o0Ooo0OO00o . rloc_count = I1111i
 o0o0Ooo0OO00o . authoritative = True
 o0o0Ooo0OO00o . action = action
 o0o0Ooo0OO00o . ddt_incomplete = oO00O0o0Oo
 o0o0Ooo0OO00o . eid = eid_prefix
 o0o0Ooo0OO00o . group = group_prefix
 o0o0Ooo0OO00o . record_ttl = O0O00O
 if 27 - 27: Oo0Ooo - i1IIi * OoooooooOO - OoOoOO00 + OoOoOO00
 Oo00oo += o0o0Ooo0OO00o . encode ( )
 o0o0Ooo0OO00o . print_record ( "  " , True )
 if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
 if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
 if 85 - 85: iII111i % i11iIiiIii
 if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
 if ( I1111i != 0 ) :
  for o0oO0OO0Oo0 in O00OO . delegation_set :
   ooOoooO = lisp_rloc_record ( )
   ooOoooO . rloc = o0oO0OO0Oo0 . delegate_address
   ooOoooO . priority = o0oO0OO0Oo0 . priority
   ooOoooO . weight = o0oO0OO0Oo0 . weight
   ooOoooO . mpriority = 255
   ooOoooO . mweight = 0
   ooOoooO . reach_bit = True
   Oo00oo += ooOoooO . encode ( )
   ooOoooO . print_record ( "    " )
   if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
   if 41 - 41: Ii1I + IiII
   if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
   if 53 - 53: I1IiiI % OOooOOo + Ii1I - Ii1I
   if 99 - 99: i1IIi * OoOoOO00 - i1IIi
   if 65 - 65: OoO0O00 / i11iIiiIii + I1ii11iIi11i + OoOoOO00
   if 82 - 82: Ii1I * OOooOOo % ooOoO0o / OoO0O00 - Oo0Ooo . I1Ii111
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , Oo00oo , ecm_source , port )
 return
 if 90 - 90: I11i * i11iIiiIii % i1IIi + I1Ii111 / OoO0O00
 if 15 - 15: Oo0Ooo + oO0o . I11i % OoO0O00
 if 13 - 13: I1ii11iIi11i / ooOoO0o * I1Ii111
 if 45 - 45: I1ii11iIi11i - I11i
 if 60 - 60: OOooOOo - OOooOOo * OoOoOO00 / Ii1I % iII111i % Oo0Ooo
 if 75 - 75: iIii1I11I1II1 - IiII - I1Ii111
 if 4 - 4: i11iIiiIii % OoooooooOO . i11iIiiIii
 if 61 - 61: iIii1I11I1II1 . Oo0Ooo . i1IIi
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 45 - 45: I1Ii111
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # I1Ii111 * I1ii11iIi11i / iII111i
 red ( dest . print_address ( ) , False ) ) )
 if 78 - 78: ooOoO0o
 oOoO0OooO0O = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 73 - 73: OoOoOO00 . OoOoOO00
 if 1 - 1: I1ii11iIi11i % o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - ooOoO0o - OoO0O00
 if 94 - 94: OoO0O00 . Oo0Ooo / OoO0O00 + I1Ii111
 if 48 - 48: I1ii11iIi11i * i1IIi + I1Ii111
 if 80 - 80: I1IiiI % I11i
 if ( lisp_get_eid_hash ( eid ) != None ) :
  oOoO0OooO0O = LISP_SEND_MAP_REQUEST_ACTION
  if 64 - 64: OOooOOo + i11iIiiIii + I1IiiI . I11i % I11i - o0oOOo0O0Ooo
  if 3 - 3: I1IiiI / i1IIi + II111iiii + Oo0Ooo
 Oo00oo = lisp_build_map_reply ( eid , group , [ ] , nonce , oOoO0OooO0O , ttl , None ,
 None , False , False )
 if 48 - 48: o0oOOo0O0Ooo
 if 16 - 16: II111iiii . Ii1I + I1Ii111 % i1IIi / i11iIiiIii + OOooOOo
 if 43 - 43: I1IiiI . Oo0Ooo + i1IIi + I11i / OoO0O00
 if 66 - 66: i11iIiiIii
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , Oo00oo , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , Oo00oo , dest , port )
  if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
 return
 if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
 if 83 - 83: i1IIi * i1IIi - II111iiii / OoooooooOO . Ii1I + I1Ii111
 if 10 - 10: I11i
 if 24 - 24: Ii1I
 if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
 if 25 - 25: I11i % i1IIi / I11i * i11iIiiIii
 if 71 - 71: IiII % I11i - OoooooooOO + I1IiiI / Oo0Ooo % I11i
def lisp_retransmit_ddt_map_request ( mr ) :
 IiIiI11111i1i = mr . mr_source . print_address ( )
 o0OOoooO0 = mr . print_eid_tuple ( )
 o0Oo0o = mr . nonce
 if 37 - 37: I1IiiI . OoO0O00
 if 13 - 13: Oo0Ooo - OoooooooOO % Ii1I
 if 89 - 89: I11i + I1IiiI - II111iiii
 if 4 - 4: I1ii11iIi11i
 if 51 - 51: I1Ii111 . O0 - OoOoOO00 + i11iIiiIii * II111iiii
 if ( mr . last_request_sent_to ) :
  I1oo0oooo00OOO = mr . last_request_sent_to . print_address ( )
  O0oO0 = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( O0oO0 and I1oo0oooo00OOO in O0oO0 . referral_set ) :
   O0oO0 . referral_set [ I1oo0oooo00OOO ] . no_responses += 1
   if 80 - 80: i1IIi
   if 74 - 74: I1ii11iIi11i . OoO0O00 + i11iIiiIii
   if 19 - 19: i1IIi / I1IiiI + IiII . iII111i
   if 68 - 68: iII111i
   if 29 - 29: II111iiii / II111iiii % OoO0O00 % Oo0Ooo . II111iiii
   if 33 - 33: OoooooooOO . OoO0O00 % OoooooooOO
   if 9 - 9: IiII * O0 + OOooOOo . II111iiii
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( o0OOoooO0 , False ) , lisp_hex_string ( o0Oo0o ) ) )
  if 14 - 14: iIii1I11I1II1 + i11iIiiIii + o0oOOo0O0Ooo + o0oOOo0O0Ooo - IiII / I1Ii111
  mr . dequeue_map_request ( )
  return
  if 70 - 70: OoooooooOO + I1IiiI / OOooOOo
  if 19 - 19: I1Ii111 + i1IIi % OoooooooOO + i1IIi
 mr . retry_count += 1
 if 16 - 16: I1Ii111 + II111iiii + IiII
 I111 = green ( IiIiI11111i1i , False )
 IiI11I111 = green ( o0OOoooO0 , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # o0oOOo0O0Ooo - oO0o . II111iiii
 red ( mr . itr . print_address ( ) , False ) , I111 , IiI11I111 ,
 lisp_hex_string ( o0Oo0o ) ) )
 if 39 - 39: OoOoOO00 - OOooOOo / II111iiii * OoooooooOO - OoO0O00 . I1IiiI
 if 89 - 89: IiII
 if 73 - 73: II111iiii + ooOoO0o % OOooOOo . oO0o / oO0o * i1IIi
 if 19 - 19: I1Ii111 + I11i
 lisp_send_ddt_map_request ( mr , False )
 if 21 - 21: OoOoOO00
 if 2 - 2: i1IIi . OOooOOo
 if 23 - 23: Ii1I - OOooOOo
 if 89 - 89: i11iIiiIii
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 40 - 40: OoooooooOO % OoO0O00
 if 54 - 54: i1IIi * OOooOOo - oO0o * OoooooooOO + II111iiii . IiII
 if 90 - 90: O0 - II111iiii + I1IiiI . iII111i
 if 3 - 3: o0oOOo0O0Ooo + i1IIi * Oo0Ooo
 if 6 - 6: OoO0O00 * OoooooooOO * iIii1I11I1II1
 if 87 - 87: iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1
 if 79 - 79: ooOoO0o . oO0o + Ii1I * ooOoO0o + O0 . II111iiii
 if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
 if 5 - 5: OoooooooOO + ooOoO0o - II111iiii . i11iIiiIii / oO0o - ooOoO0o
 if 3 - 3: iII111i
 if 74 - 74: i11iIiiIii + OoooooooOO . OOooOOo
 i1IIIIiiII1 = [ ]
 for oooO00ooo00 in list ( referral . referral_set . values ( ) ) :
  if ( oooO00ooo00 . updown == False ) : continue
  if ( len ( i1IIIIiiII1 ) == 0 or i1IIIIiiII1 [ 0 ] . priority == oooO00ooo00 . priority ) :
   i1IIIIiiII1 . append ( oooO00ooo00 )
  elif ( i1IIIIiiII1 [ 0 ] . priority > oooO00ooo00 . priority ) :
   i1IIIIiiII1 = [ ]
   i1IIIIiiII1 . append ( oooO00ooo00 )
   if 56 - 56: OoOoOO00 * II111iiii * o0oOOo0O0Ooo - I1IiiI + OoOoOO00 - O0
   if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
   if 53 - 53: ooOoO0o + oO0o - II111iiii
 OOo000Oo = len ( i1IIIIiiII1 )
 if ( OOo000Oo == 0 ) : return ( None )
 if 19 - 19: oO0o . i1IIi . Oo0Ooo
 II1Iii1iI = dest_eid . hash_address ( source_eid )
 II1Iii1iI = II1Iii1iI % OOo000Oo
 return ( i1IIIIiiII1 [ II1Iii1iI ] )
 if 59 - 59: i1IIi / Ii1I . I1ii11iIi11i % II111iiii
 if 12 - 12: OoO0O00
 if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
 if 81 - 81: i1IIi % I11i * iIii1I11I1II1
 if 39 - 39: iIii1I11I1II1 / O0 . OoooooooOO - O0 . OoO0O00 . oO0o
 if 59 - 59: II111iiii * I1IiiI
 if 12 - 12: i11iIiiIii - IiII . iII111i . Ii1I
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 IiI11IIIIIi = mr . lisp_sockets
 o0Oo0o = mr . nonce
 oO0oO00OO00 = mr . itr
 Ii1OoOoOoO = mr . mr_source
 i1iiii = mr . print_eid_tuple ( )
 if 97 - 97: OoO0O00 + I1IiiI . i11iIiiIii
 if 48 - 48: iIii1I11I1II1 / OOooOOo + I1Ii111
 if 85 - 85: Ii1I % ooOoO0o . I1IiiI
 if 47 - 47: I1Ii111 - I1ii11iIi11i * OoO0O00 % IiII % ooOoO0o . I1IiiI
 if 96 - 96: II111iiii
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( i1iiii , False ) , lisp_hex_string ( o0Oo0o ) ) )
  if 73 - 73: II111iiii
  mr . dequeue_map_request ( )
  return
  if 81 - 81: I1IiiI + OoO0O00
  if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
  if 32 - 32: o0oOOo0O0Ooo - iII111i + i11iIiiIii / ooOoO0o . OoOoOO00 . IiII
  if 9 - 9: iIii1I11I1II1
  if 66 - 66: iIii1I11I1II1
  if 13 - 13: O0 / ooOoO0o
 if ( send_to_root ) :
  OoooOO0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  iI111iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( i1iiii , False ) ) )
 else :
  OoooOO0 = mr . eid
  iI111iiI = mr . group
  if 6 - 6: iII111i + II111iiii . IiII . Ii1I / ooOoO0o / I11i
  if 85 - 85: ooOoO0o / II111iiii / OoO0O00 + Ii1I / i1IIi . iII111i
  if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
  if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
  if 85 - 85: I1IiiI + i1IIi % I1Ii111
 oooo0o0o00o = lisp_referral_cache_lookup ( OoooOO0 , iI111iiI , False )
 if ( oooo0o0o00o == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( IiI11IIIIIi , OoooOO0 , iI111iiI ,
 o0Oo0o , oO0oO00OO00 , mr . sport , 15 , None , False )
  return
  if 23 - 23: I11i - oO0o % i11iIiiIii % I1ii11iIi11i + OOooOOo
  if 64 - 64: OOooOOo - I11i / I1ii11iIi11i . Ii1I
 i1IO0ooo00 = oooo0o0o00o . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( i1IO0ooo00 ,
 oooo0o0o00o . print_referral_type ( ) ) )
 if 86 - 86: oO0o + OOooOOo . o0oOOo0O0Ooo
 oooO00ooo00 = lisp_get_referral_node ( oooo0o0o00o , Ii1OoOoOoO , mr . eid )
 if ( oooO00ooo00 == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( IiI11IIIIIi , oooo0o0o00o . eid ,
 oooo0o0o00o . group , o0Oo0o , oO0oO00OO00 , mr . sport , 1 , None , False )
  return
  if 37 - 37: i1IIi + iII111i - IiII + ooOoO0o . i1IIi % i11iIiiIii
  if 92 - 92: I1IiiI
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( oooO00ooo00 . referral_address . print_address ( ) ,
 # OoO0O00 - I11i - Oo0Ooo
 oooo0o0o00o . print_referral_type ( ) , green ( i1iiii , False ) ,
 lisp_hex_string ( o0Oo0o ) ) )
 if 57 - 57: I1Ii111 % i11iIiiIii
 if 36 - 36: O0 . I11i / o0oOOo0O0Ooo + i1IIi + oO0o * IiII
 if 29 - 29: O0 - II111iiii + iII111i
 if 73 - 73: I1Ii111 - I11i + IiII - o0oOOo0O0Ooo - I11i - OOooOOo
 Ii1oO0o0ooo = ( oooo0o0o00o . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 oooo0o0o00o . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( IiI11IIIIIi , mr . packet , Ii1OoOoOoO , mr . sport , mr . eid ,
 oooO00ooo00 . referral_address , to_ms = Ii1oO0o0ooo , ddt = True )
 if 33 - 33: i11iIiiIii . iII111i % o0oOOo0O0Ooo
 if 35 - 35: OoO0O00 + OOooOOo % II111iiii * Ii1I / OoOoOO00
 if 71 - 71: OOooOOo / i1IIi
 if 50 - 50: iIii1I11I1II1 * IiII
 mr . last_request_sent_to = oooO00ooo00 . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 oooO00ooo00 . map_requests_sent += 1
 return
 if 73 - 73: II111iiii
 if 4 - 4: II111iiii * o0oOOo0O0Ooo + I11i . II111iiii
 if 35 - 35: ooOoO0o - ooOoO0o . i1IIi % oO0o * IiII * I1ii11iIi11i
 if 36 - 36: OoOoOO00 % ooOoO0o - Oo0Ooo - OoooooooOO % I1ii11iIi11i / OoOoOO00
 if 23 - 23: ooOoO0o . O0 % O0 - iIii1I11I1II1 / IiII
 if 8 - 8: i11iIiiIii . Oo0Ooo / i11iIiiIii % IiII
 if 41 - 41: iII111i * I11i % OoooooooOO * iIii1I11I1II1
 if 73 - 73: I1Ii111 * I1ii11iIi11i
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 79 - 79: I11i / O0 % Ii1I % I1ii11iIi11i
 o0Ooo0Oooo0o = map_request . target_eid
 oo0oOooo0O = map_request . target_group
 o0OOoooO0 = map_request . print_eid_tuple ( )
 IiIiI11111i1i = mr_source . print_address ( )
 o0Oo0o = map_request . nonce
 if 21 - 21: OoOoOO00 . ooOoO0o * OoO0O00 - OoOoOO00 - OoooooooOO
 I111 = green ( IiIiI11111i1i , False )
 IiI11I111 = green ( o0OOoooO0 , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # OoO0O00 * I1Ii111
 red ( ecm_source . print_address ( ) , False ) , I111 , IiI11I111 ,
 lisp_hex_string ( o0Oo0o ) ) )
 if 56 - 56: oO0o
 if 52 - 52: i1IIi % iIii1I11I1II1 . I1Ii111 / iII111i
 if 31 - 31: Ii1I - o0oOOo0O0Ooo % oO0o / OoO0O00 * I11i
 if 24 - 24: i1IIi
 iii1i = lisp_ddt_map_request ( lisp_sockets , packet , o0Ooo0Oooo0o , oo0oOooo0O , o0Oo0o )
 iii1i . packet = packet
 iii1i . itr = ecm_source
 iii1i . mr_source = mr_source
 iii1i . sport = sport
 iii1i . from_pitr = map_request . pitr_bit
 iii1i . queue_map_request ( )
 if 4 - 4: i11iIiiIii * i1IIi / OOooOOo + iIii1I11I1II1 - II111iiii / I11i
 lisp_send_ddt_map_request ( iii1i , False )
 return
 if 67 - 67: I1ii11iIi11i . OOooOOo / ooOoO0o / I1Ii111 . I11i
 if 54 - 54: I1ii11iIi11i - I1IiiI . OoOoOO00
 if 36 - 36: OoO0O00 * I1IiiI / iII111i
 if 95 - 95: Ii1I . Oo0Ooo
 if 42 - 42: IiII . i1IIi % O0 * ooOoO0o - OOooOOo % ooOoO0o
 if 99 - 99: i1IIi + OoOoOO00 - iII111i % II111iiii
 if 6 - 6: ooOoO0o - I1Ii111 . OoOoOO00
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl , timestamp ) :
 if 64 - 64: iII111i + I1ii11iIi11i
 i1o0o0oOO = packet
 O0Ooo = lisp_map_request ( )
 packet = O0Ooo . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 10 - 10: ooOoO0o / II111iiii
  if 30 - 30: i1IIi * Ii1I + Ii1I / I1Ii111
 O0Ooo . print_map_request ( )
 if 84 - 84: I1IiiI - Oo0Ooo * OoO0O00 * oO0o
 if 13 - 13: I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + oO0o - iII111i
 if 32 - 32: I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * I1Ii111 % II111iiii
 if 33 - 33: ooOoO0o % I11i
 if ( O0Ooo . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , O0Ooo , mr_source ,
 mr_port , ttl , timestamp )
  return
  if 72 - 72: OoO0O00 % OoooooooOO / II111iiii * oO0o * I1Ii111
  if 98 - 98: OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / OoOoOO00 + I1IiiI
  if 74 - 74: ooOoO0o . IiII . O0 * I1IiiI * oO0o
  if 6 - 6: O0 . Ii1I / Oo0Ooo * o0oOOo0O0Ooo
  if 1 - 1: i11iIiiIii
 if ( O0Ooo . smr_bit ) :
  lisp_process_smr ( O0Ooo )
  if 30 - 30: I11i
  if 26 - 26: Oo0Ooo - II111iiii % ooOoO0o
  if 81 - 81: i11iIiiIii + I1ii11iIi11i * oO0o
  if 86 - 86: OoO0O00 . ooOoO0o . o0oOOo0O0Ooo
  if 70 - 70: O0 % OoooooooOO - Ii1I * Oo0Ooo
 if ( O0Ooo . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( O0Ooo )
  if 18 - 18: OOooOOo . I1IiiI + i1IIi . I1IiiI
  if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
  if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
  if 6 - 6: O0 * I1Ii111 - II111iiii
  if 60 - 60: oO0o % oO0o
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , O0Ooo , mr_source ,
 mr_port , ttl , timestamp )
  if 76 - 76: I1Ii111 / o0oOOo0O0Ooo
  if 19 - 19: O0 . i1IIi % iIii1I11I1II1 + OOooOOo * OoOoOO00 / I11i
  if 82 - 82: I1ii11iIi11i
  if 75 - 75: I11i - II111iiii
  if 84 - 84: I1ii11iIi11i * IiII / I1IiiI - Ii1I + IiII - i1IIi
 if ( lisp_i_am_ms ) :
  packet = i1o0o0oOO
  o0Ooo0Oooo0o , oo0oOooo0O , Oo00Oo00O = lisp_ms_process_map_request ( lisp_sockets ,
 i1o0o0oOO , O0Ooo , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , O0Ooo , ecm_source ,
 ecm_port , Oo00Oo00O , o0Ooo0Oooo0o , oo0oOooo0O )
   if 67 - 67: iII111i + OoOoOO00 * o0oOOo0O0Ooo / II111iiii / iIii1I11I1II1
  return
  if 12 - 12: o0oOOo0O0Ooo
  if 13 - 13: o0oOOo0O0Ooo
  if 45 - 45: OoO0O00 % OoO0O00 % O0
  if 62 - 62: IiII - iII111i . I1ii11iIi11i . oO0o
  if 22 - 22: OoOoOO00 * i11iIiiIii * Ii1I
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , i1o0o0oOO , O0Ooo ,
 ecm_source , mr_port , mr_source )
  if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
  if 5 - 5: OoO0O00 / ooOoO0o
  if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
  if 97 - 97: oO0o / Ii1I
  if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = i1o0o0oOO
  lisp_ddt_process_map_request ( lisp_sockets , O0Ooo , ecm_source ,
 ecm_port )
  if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
 return
 if 91 - 91: IiII * Ii1I * OOooOOo
 if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
 if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
 if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
 if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
 if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
 if 95 - 95: IiII + iII111i % I1IiiI
 if 18 - 18: Oo0Ooo
def lisp_store_mr_stats ( source , nonce ) :
 iii1i = lisp_get_map_resolver ( source , None )
 if ( iii1i == None ) : return
 if 8 - 8: O0 + iIii1I11I1II1 - O0
 if 67 - 67: O0
 if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
 if 28 - 28: O0 - Oo0Ooo
 iii1i . neg_map_replies_received += 1
 iii1i . last_reply = lisp_get_timestamp ( )
 if 58 - 58: iIii1I11I1II1 - OoooooooOO - iII111i
 if 43 - 43: ooOoO0o / o0oOOo0O0Ooo
 if 56 - 56: II111iiii * I1ii11iIi11i * O0 . iII111i . I1ii11iIi11i % I1Ii111
 if 99 - 99: Oo0Ooo - OoO0O00 + OoooooooOO - I1Ii111 - I1ii11iIi11i % i1IIi
 if ( ( iii1i . neg_map_replies_received % 100 ) == 0 ) : iii1i . total_rtt = 0
 if 49 - 49: IiII % OoooooooOO / Oo0Ooo - OoOoOO00 + o0oOOo0O0Ooo / Ii1I
 if 6 - 6: I11i % IiII
 if 48 - 48: Ii1I
 if 100 - 100: OoO0O00 % I1Ii111 + OoooooooOO / OoO0O00
 if ( iii1i . last_nonce == nonce ) :
  iii1i . total_rtt += ( time . time ( ) - iii1i . last_used )
  iii1i . last_nonce = 0
  if 62 - 62: IiII
 if ( ( iii1i . neg_map_replies_received % 10 ) == 0 ) : iii1i . last_nonce = 0
 return
 if 66 - 66: o0oOOo0O0Ooo % OOooOOo
 if 15 - 15: Ii1I % IiII + IiII % iII111i - O0 * OoooooooOO
 if 53 - 53: OoOoOO00 . Ii1I / Oo0Ooo
 if 62 - 62: i11iIiiIii
 if 38 - 38: I1ii11iIi11i % ooOoO0o * OoooooooOO + iIii1I11I1II1 % i1IIi / OOooOOo
 if 6 - 6: i11iIiiIii
 if 8 - 8: iIii1I11I1II1 + I1ii11iIi11i . i1IIi % OoOoOO00 % OoooooooOO * Oo0Ooo
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl , itr_in_ts ) :
 global lisp_map_cache
 if 53 - 53: oO0o
 IiOo0oOoooO = lisp_map_reply ( )
 packet = IiOo0oOoooO . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
 IiOo0oOoooO . print_map_reply ( )
 if 4 - 4: I1IiiI
 if 31 - 31: ooOoO0o * i1IIi . O0
 if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
 if 100 - 100: I1Ii111
 O0oo0OOo00o0o = None
 for iIi1iIIIiIiI in range ( IiOo0oOoooO . record_count ) :
  o0o0Ooo0OO00o = lisp_eid_record ( )
  packet = o0o0Ooo0OO00o . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 18 - 18: iII111i
  o0o0Ooo0OO00o . print_record ( "  " , False )
  if 98 - 98: IiII . OOooOOo * ooOoO0o / OoO0O00
  if 21 - 21: OOooOOo / OoO0O00 + OoooooooOO
  if 66 - 66: II111iiii * I11i + iII111i * iII111i . i11iIiiIii % Ii1I
  if 96 - 96: I1IiiI . O0 / iIii1I11I1II1
  if 95 - 95: ooOoO0o * OoO0O00 % OoooooooOO % OoO0O00
  if ( o0o0Ooo0OO00o . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , IiOo0oOoooO . nonce )
   if 79 - 79: II111iiii % Ii1I * oO0o * iII111i + II111iiii
   if 51 - 51: I1IiiI + iII111i + I1IiiI / Ii1I * IiII + OOooOOo
  II1OO0Oo0oOOO000 = ( o0o0Ooo0OO00o . group . is_null ( ) == False )
  if 70 - 70: I11i . IiII + IiII
  if 74 - 74: Ii1I
  if 11 - 11: I1ii11iIi11i
  if 83 - 83: O0
  if 97 - 97: O0
  if ( lisp_decent_push_configured ) :
   oOoO0OooO0O = o0o0Ooo0OO00o . action
   if ( II1OO0Oo0oOOO000 and oOoO0OooO0O == LISP_DROP_ACTION ) :
    if ( o0o0Ooo0OO00o . eid . is_local ( ) ) : continue
    if 50 - 50: I1Ii111 / OoooooooOO . o0oOOo0O0Ooo + I1IiiI * i11iIiiIii
    if 28 - 28: I1Ii111 * II111iiii
    if 14 - 14: iIii1I11I1II1 / Ii1I + o0oOOo0O0Ooo . iII111i % iII111i . i1IIi
    if 67 - 67: IiII * II111iiii + ooOoO0o - i11iIiiIii
    if 15 - 15: I11i
    if 67 - 67: iIii1I11I1II1
    if 91 - 91: ooOoO0o
  if ( II1OO0Oo0oOOO000 == False and o0o0Ooo0OO00o . eid . is_null ( ) ) : continue
  if 66 - 66: OOooOOo
  if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
  if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
  if 9 - 9: Ii1I
  if 44 - 44: iII111i
  if ( II1OO0Oo0oOOO000 ) :
   I11iiI1III = lisp_map_cache_lookup ( o0o0Ooo0OO00o . eid , o0o0Ooo0OO00o . group )
  else :
   I11iiI1III = lisp_map_cache . lookup_cache ( o0o0Ooo0OO00o . eid , True )
   if 43 - 43: OoO0O00 % OOooOOo + oO0o
  IiIii1Ii = ( I11iiI1III == None )
  if 37 - 37: Oo0Ooo / i1IIi + OoO0O00
  if 83 - 83: OOooOOo / OOooOOo * OOooOOo . I1ii11iIi11i . iII111i % OOooOOo
  if 63 - 63: iII111i - o0oOOo0O0Ooo * OOooOOo . Ii1I . Ii1I
  if 7 - 7: i11iIiiIii . I1ii11iIi11i
  if 4 - 4: i11iIiiIii % OoO0O00 . oO0o
  if ( I11iiI1III == None ) :
   Ooo00O , Oo0OoO00O , ii1I1I1iII = lisp_allow_gleaning ( o0o0Ooo0OO00o . eid , o0o0Ooo0OO00o . group ,
 None )
   if ( Ooo00O ) : continue
  else :
   if ( I11iiI1III . gleaned ) : continue
   if 89 - 89: Oo0Ooo / Ii1I * OoO0O00 + ooOoO0o
   if 41 - 41: IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
   if 38 - 38: iII111i * OoooooooOO - IiII
   if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
   if 91 - 91: O0 + I1Ii111 * II111iiii - O0 . i11iIiiIii . Oo0Ooo
  OO00O000OOO = [ ]
  O0o00O00oo0oO = None
  for I1I1II1iI in range ( o0o0Ooo0OO00o . rloc_count ) :
   ooOoooO = lisp_rloc_record ( )
   ooOoooO . keys = IiOo0oOoooO . keys
   packet = ooOoooO . decode ( packet , IiOo0oOoooO . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 80 - 80: oO0o + O0
   ooOoooO . print_record ( "    " )
   if 84 - 84: i1IIi - II111iiii
   ii1II1i1 = None
   if ( I11iiI1III ) : ii1II1i1 = I11iiI1III . get_rloc ( ooOoooO . rloc )
   if ( ii1II1i1 ) :
    iIIiI11 = ii1II1i1
   else :
    iIIiI11 = lisp_rloc ( )
    if 5 - 5: IiII % oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / Ii1I
    if 55 - 55: Oo0Ooo / o0oOOo0O0Ooo
    if 51 - 51: I1IiiI + i11iIiiIii / ooOoO0o % I1IiiI + Oo0Ooo
    if 6 - 6: OoOoOO00 . O0
    if 44 - 44: ooOoO0o % I11i + ooOoO0o . oO0o
    if 70 - 70: O0 - I11i . iIii1I11I1II1 % I11i . OoOoOO00 % oO0o
    if 5 - 5: O0 * OoO0O00
   ooO0 = iIIiI11 . store_rloc_from_record ( ooOoooO , IiOo0oOoooO . nonce ,
 source )
   iIIiI11 . echo_nonce_capable = IiOo0oOoooO . echo_nonce_capable
   if 61 - 61: Ii1I / I11i + Ii1I . IiII - OoO0O00 - o0oOOo0O0Ooo
   if ( iIIiI11 . echo_nonce_capable ) :
    O0O0 = iIIiI11 . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , O0O0 ) == None ) :
     lisp_echo_nonce ( O0O0 )
     if 84 - 84: OoooooooOO - Oo0Ooo
     if 86 - 86: O0 + OoO0O00 + O0 . I1IiiI
     if 82 - 82: OoOoOO00
     if 61 - 61: oO0o . o0oOOo0O0Ooo
     if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
     if 70 - 70: I1IiiI
   if ( iIIiI11 . json ) :
    if ( lisp_is_json_telemetry ( iIIiI11 . json . json_string ) ) :
     I1i1iiII1iI1i = iIIiI11 . json . json_string
     I1i1iiII1iI1i = lisp_encode_telemetry ( I1i1iiII1iI1i , ii = itr_in_ts )
     iIIiI11 . json . json_string = I1i1iiII1iI1i
     if 74 - 74: ooOoO0o * II111iiii
     if 96 - 96: i11iIiiIii . I1IiiI - II111iiii . I11i
     if 79 - 79: OoO0O00 . OoOoOO00 - i1IIi + Ii1I * i11iIiiIii . OoooooooOO
     if 83 - 83: o0oOOo0O0Ooo / oO0o
     if 24 - 24: Ii1I + oO0o / OoooooooOO % i11iIiiIii
     if 1 - 1: iII111i / I1Ii111 * I1IiiI + OoOoOO00 . OoooooooOO
     if 5 - 5: I1IiiI
     if 74 - 74: i1IIi * Oo0Ooo - OoOoOO00 * o0oOOo0O0Ooo
     if 85 - 85: iIii1I11I1II1 * IiII / i11iIiiIii - ooOoO0o - o0oOOo0O0Ooo
     if 30 - 30: OoOoOO00 - OOooOOo . Oo0Ooo
   if ( IiOo0oOoooO . rloc_probe and ooOoooO . probe_bit ) :
    if ( iIIiI11 . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( iIIiI11 , source , ooO0 ,
 IiOo0oOoooO , ttl , O0o00O00oo0oO )
     if 11 - 11: IiII - I1Ii111 - OoO0O00 * o0oOOo0O0Ooo
    if ( iIIiI11 . rloc . is_multicast_address ( ) ) : O0o00O00oo0oO = iIIiI11
    if 99 - 99: O0 - OoO0O00
    if 95 - 95: Ii1I . IiII * o0oOOo0O0Ooo
    if 91 - 91: I1Ii111
    if 49 - 49: I11i
    if 17 - 17: Oo0Ooo % o0oOOo0O0Ooo
   OO00O000OOO . append ( iIIiI11 )
   if 3 - 3: OoO0O00 . oO0o . oO0o . Ii1I
   if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
   if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
   if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
   if ( lisp_data_plane_security and iIIiI11 . rloc_recent_rekey ( ) ) :
    O0oo0OOo00o0o = iIIiI11
    if 10 - 10: ooOoO0o
    if 69 - 69: I11i + I1IiiI / oO0o
    if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
    if 85 - 85: I1Ii111 - oO0o
    if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
    if 96 - 96: oO0o
    if 44 - 44: OoooooooOO / iII111i * Oo0Ooo % OoOoOO00 . oO0o
    if 97 - 97: iIii1I11I1II1 / ooOoO0o
    if 16 - 16: Oo0Ooo % IiII
    if 48 - 48: I1IiiI . I1Ii111 . o0oOOo0O0Ooo
    if 72 - 72: Ii1I * OoO0O00 / OoO0O00
  if ( IiOo0oOoooO . rloc_probe == False and lisp_nat_traversal ) :
   Oo0O0O0oo0 = [ ]
   iII1Ii1Ii = [ ]
   for iIIiI11 in OO00O000OOO :
    if 27 - 27: OoOoOO00 + I1ii11iIi11i - OoOoOO00 . iIii1I11I1II1
    if 72 - 72: OoO0O00 / I1IiiI . Ii1I
    if 11 - 11: I1Ii111 + OoO0O00 / i1IIi - i1IIi
    if 14 - 14: Ii1I - o0oOOo0O0Ooo
    if 14 - 14: OoO0O00 * OoO0O00 - I1ii11iIi11i
    if ( iIIiI11 . rloc . is_private_address ( ) ) :
     iIIiI11 . priority = 1
     iIIiI11 . state = LISP_RLOC_UNREACH_STATE
     Oo0O0O0oo0 . append ( iIIiI11 )
     iII1Ii1Ii . append ( iIIiI11 . rloc . print_address_no_iid ( ) )
     continue
     if 90 - 90: Oo0Ooo . II111iiii + I1ii11iIi11i - OoOoOO00 / I11i * iII111i
     if 58 - 58: oO0o + Oo0Ooo . O0
     if 8 - 8: II111iiii + iII111i + OoO0O00 - Ii1I / I1ii11iIi11i
     if 86 - 86: I1ii11iIi11i
     if 43 - 43: IiII - I1Ii111 / I1Ii111
     if 25 - 25: OoOoOO00
    if ( iIIiI11 . priority == 254 and lisp_i_am_rtr == False ) :
     Oo0O0O0oo0 . append ( iIIiI11 )
     iII1Ii1Ii . append ( iIIiI11 . rloc . print_address_no_iid ( ) )
     if 52 - 52: OOooOOo + IiII
    if ( iIIiI11 . priority != 254 and lisp_i_am_rtr ) :
     Oo0O0O0oo0 . append ( iIIiI11 )
     iII1Ii1Ii . append ( iIIiI11 . rloc . print_address_no_iid ( ) )
     if 73 - 73: OoooooooOO - I1Ii111 % iII111i / OOooOOo . o0oOOo0O0Ooo - IiII
     if 69 - 69: Ii1I . iIii1I11I1II1 / Oo0Ooo * Oo0Ooo % IiII
     if 5 - 5: OOooOOo - I1Ii111 + IiII
   if ( iII1Ii1Ii != [ ] ) :
    OO00O000OOO = Oo0O0O0oo0
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( iII1Ii1Ii ) )
    if 82 - 82: OOooOOo
    if 26 - 26: ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
    if 26 - 26: I1IiiI - OOooOOo
    if 34 - 34: I1Ii111 % I1IiiI . OoOoOO00 / iII111i + ooOoO0o . i11iIiiIii
    if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
    if 50 - 50: OoooooooOO * II111iiii
    if 7 - 7: ooOoO0o / I11i * iII111i
  Oo0O0O0oo0 = [ ]
  for iIIiI11 in OO00O000OOO :
   if ( iIIiI11 . json != None ) : continue
   Oo0O0O0oo0 . append ( iIIiI11 )
   if 17 - 17: O0 % I1Ii111
  if ( Oo0O0O0oo0 != [ ] ) :
   O0oo0oOo = len ( OO00O000OOO ) - len ( Oo0O0O0oo0 )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( O0oo0oOo ) )
   if 28 - 28: i1IIi * ooOoO0o
   OO00O000OOO = Oo0O0O0oo0
   if 14 - 14: II111iiii + II111iiii - I11i / I11i . OoOoOO00 + OoO0O00
   if 92 - 92: II111iiii - II111iiii % IiII
   if 48 - 48: oO0o / II111iiii + oO0o
   if 16 - 16: o0oOOo0O0Ooo % II111iiii - i11iIiiIii - IiII + O0 - i11iIiiIii
   if 58 - 58: OoooooooOO / I1ii11iIi11i - Oo0Ooo / II111iiii
   if 13 - 13: o0oOOo0O0Ooo + OoOoOO00 * ooOoO0o % IiII
   if 18 - 18: I1IiiI . I1ii11iIi11i + Oo0Ooo - iII111i
   if 53 - 53: ooOoO0o / IiII
  if ( IiOo0oOoooO . rloc_probe and I11iiI1III != None ) : OO00O000OOO = I11iiI1III . rloc_set
  if 36 - 36: iIii1I11I1II1
  if 78 - 78: II111iiii * I11i
  if 47 - 47: Ii1I
  if 42 - 42: I11i . oO0o - I1IiiI / OoO0O00
  if 75 - 75: I1IiiI / OoOoOO00 . I11i * iIii1I11I1II1
  ooO = IiIii1Ii
  if ( I11iiI1III and OO00O000OOO != I11iiI1III . rloc_set ) :
   I11iiI1III . delete_rlocs_from_rloc_probe_list ( )
   ooO = True
   if 64 - 64: OOooOOo
   if 8 - 8: ooOoO0o % o0oOOo0O0Ooo
   if 22 - 22: O0 * IiII . OoO0O00
   if 63 - 63: oO0o % Oo0Ooo * OoO0O00 / II111iiii / Ii1I - ooOoO0o
   if 14 - 14: ooOoO0o . o0oOOo0O0Ooo + II111iiii
  i11iIIIi1 = I11iiI1III . uptime if ( I11iiI1III ) else None
  if ( I11iiI1III == None ) :
   I11iiI1III = lisp_mapping ( o0o0Ooo0OO00o . eid , o0o0Ooo0OO00o . group , OO00O000OOO )
   I11iiI1III . mapping_source = source
   if 66 - 66: iII111i - I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
   if 27 - 27: o0oOOo0O0Ooo % o0oOOo0O0Ooo / ooOoO0o + OoooooooOO * iII111i . I11i
   if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
   if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
   if 34 - 34: O0 * oO0o
   if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
   if ( lisp_i_am_rtr and o0o0Ooo0OO00o . group . is_null ( ) == False ) :
    I11iiI1III . map_cache_ttl = LISP_MCAST_TTL
   else :
    I11iiI1III . map_cache_ttl = o0o0Ooo0OO00o . store_ttl ( )
    if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
   I11iiI1III . action = o0o0Ooo0OO00o . action
   I11iiI1III . add_cache ( ooO )
   if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
   if 88 - 88: i11iIiiIii
  iII11 = "Add"
  if ( i11iIIIi1 ) :
   I11iiI1III . uptime = i11iIIIi1
   I11iiI1III . refresh_time = lisp_get_timestamp ( )
   iII11 = "Replace"
   if 20 - 20: I1Ii111 . iII111i * I1ii11iIi11i + OoooooooOO
   if 56 - 56: OOooOOo * I1Ii111 % OOooOOo + Ii1I
  lprint ( "{} {} map-cache with {} RLOCs" . format ( iII11 ,
 green ( I11iiI1III . print_eid_tuple ( ) , False ) , len ( OO00O000OOO ) ) )
  if 78 - 78: OOooOOo * OoOoOO00
  if 20 - 20: IiII
  if 17 - 17: o0oOOo0O0Ooo % iIii1I11I1II1
  if 66 - 66: OoooooooOO + IiII . II111iiii
  if 66 - 66: iIii1I11I1II1 % I11i
  if ( lisp_ipc_dp_socket and O0oo0OOo00o0o != None ) :
   lisp_write_ipc_keys ( O0oo0OOo00o0o )
   if 38 - 38: I1ii11iIi11i * ooOoO0o
   if 77 - 77: OOooOOo - i11iIiiIii - I1ii11iIi11i
   if 94 - 94: OoO0O00 % iII111i - I1Ii111 + OoO0O00 - I1IiiI
   if 65 - 65: OOooOOo
   if 90 - 90: O0
   if 91 - 91: O0 * OoOoOO00 - OoOoOO00 * II111iiii - iII111i
   if 38 - 38: oO0o * I11i % OOooOOo
  if ( IiIii1Ii ) :
   Oooooo0OOO = bold ( "RLOC-probe" , False )
   for iIIiI11 in I11iiI1III . best_rloc_set :
    O0O0 = red ( iIIiI11 . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( Oooooo0OOO , O0O0 ) )
    lisp_send_map_request ( lisp_sockets , 0 , I11iiI1III . eid , I11iiI1III . group , iIIiI11 )
    if 70 - 70: oO0o + I1Ii111 % Oo0Ooo
    if 46 - 46: oO0o . OoOoOO00
    if 31 - 31: OoO0O00 + i11iIiiIii / I11i % O0 / Ii1I
 return
 if 90 - 90: iIii1I11I1II1 % oO0o % IiII
 if 84 - 84: I1IiiI * IiII * iII111i / i1IIi . II111iiii * o0oOOo0O0Ooo
 if 1 - 1: oO0o - iIii1I11I1II1 % i1IIi
 if 94 - 94: Oo0Ooo + iIii1I11I1II1 . OoO0O00 * oO0o . i1IIi
 if 85 - 85: O0 / OoOoOO00 . iII111i
 if 64 - 64: OoO0O00 + I1ii11iIi11i / OoO0O00 * I1Ii111 . Oo0Ooo
 if 5 - 5: iII111i - iIii1I11I1II1 * IiII
 if 52 - 52: OOooOOo
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 50 - 50: OoOoOO00 % o0oOOo0O0Ooo - II111iiii - i1IIi
 packet = map_register . zero_auth ( packet )
 II1Iii1iI = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 35 - 35: Oo0Ooo - ooOoO0o % OoO0O00
 if 26 - 26: i1IIi * I1Ii111 * OoO0O00 - IiII
 if 26 - 26: Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
 if 66 - 66: I1IiiI
 map_register . auth_data = II1Iii1iI
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 45 - 45: II111iiii * I1Ii111 - II111iiii / I1IiiI % oO0o
 if 83 - 83: oO0o % OoO0O00 + I1ii11iIi11i / OoooooooOO % iII111i
 if 22 - 22: I1Ii111
 if 41 - 41: O0 * i1IIi
 if 89 - 89: iIii1I11I1II1 . I11i % I1ii11iIi11i + II111iiii . OoO0O00
 if 5 - 5: I1ii11iIi11i / I1IiiI . iII111i
 if 7 - 7: Ii1I
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 62 - 62: I1ii11iIi11i + IiII . O0 - OoooooooOO * o0oOOo0O0Ooo % O0
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  O0O0O00 = hashlib . sha1
  if 31 - 31: IiII
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  O0O0O00 = hashlib . sha256
  if 43 - 43: OoOoOO00 . OoooooooOO + OoooooooOO - IiII . OoOoOO00
  if 56 - 56: I11i
 if ( do_hex ) :
  II1Iii1iI = hmac . new ( password . encode ( ) , packet , O0O0O00 ) . hexdigest ( )
 else :
  II1Iii1iI = hmac . new ( password . encode ( ) , packet , O0O0O00 ) . digest ( )
  if 75 - 75: ooOoO0o . oO0o . OoOoOO00
 return ( II1Iii1iI )
 if 72 - 72: I11i % ooOoO0o / O0 . O0
 if 7 - 7: O0 * I1ii11iIi11i + Ii1I + oO0o % oO0o
 if 47 - 47: oO0o * I1ii11iIi11i
 if 85 - 85: OoooooooOO * I1ii11iIi11i + i11iIiiIii . iII111i * II111iiii / oO0o
 if 14 - 14: I1Ii111
 if 49 - 49: I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
 if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
 if 28 - 28: ooOoO0o
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 88 - 88: oO0o
 II1Iii1iI = lisp_hash_me ( packet , alg_id , password , True )
 o0o0Oo = ( II1Iii1iI == auth_data )
 if 76 - 76: OoOoOO00 / iII111i * ooOoO0o . i1IIi
 if 28 - 28: I11i . I1ii11iIi11i
 if 80 - 80: OoO0O00 - OoooooooOO * i11iIiiIii
 if 20 - 20: OoO0O00 . II111iiii
 if ( o0o0Oo == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( II1Iii1iI , auth_data ) )
  if 70 - 70: i11iIiiIii % Ii1I * IiII / IiII . o0oOOo0O0Ooo
  if 52 - 52: o0oOOo0O0Ooo % I11i
 return ( o0o0Oo )
 if 58 - 58: i11iIiiIii % Ii1I + Oo0Ooo - OoOoOO00 - i11iIiiIii / O0
 if 36 - 36: OOooOOo
 if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
 if 95 - 95: i1IIi * O0 / II111iiii * OoOoOO00 * I1IiiI
 if 38 - 38: OOooOOo - OoOoOO00 / OoO0O00 / o0oOOo0O0Ooo - i11iIiiIii
 if 4 - 4: I1IiiI * o0oOOo0O0Ooo - I11i - OoooooooOO . OoooooooOO
 if 79 - 79: oO0o - iII111i
def lisp_retransmit_map_notify ( map_notify ) :
 IIi11ii = map_notify . etr
 ooO0 = map_notify . etr_port
 if 34 - 34: OoooooooOO + Ii1I - iII111i + OoooooooOO / I1IiiI
 if 39 - 39: o0oOOo0O0Ooo . i1IIi * OoO0O00 / II111iiii / I1ii11iIi11i * OOooOOo
 if 39 - 39: O0 . OOooOOo
 if 95 - 95: I11i
 if 58 - 58: I1ii11iIi11i / i11iIiiIii + iII111i + I11i / oO0o
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( IIi11ii . print_address ( ) , False ) ) )
  if 8 - 8: I1ii11iIi11i
  if 100 - 100: OoooooooOO / I11i - Ii1I
  III = map_notify . nonce_key
  if ( III in lisp_map_notify_queue ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( III ) )
   if 11 - 11: OoO0O00
   try :
    lisp_map_notify_queue . pop ( III )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 20 - 20: Oo0Ooo
    if 34 - 34: I1Ii111 % i11iIiiIii / oO0o - i1IIi . o0oOOo0O0Ooo / oO0o
  return
  if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
  if 1 - 1: I1ii11iIi11i
 IiI11IIIIIi = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 18 - 18: i11iIiiIii % OoO0O00 % OOooOOo . OOooOOo * Ii1I / II111iiii
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # Ii1I + OoooooooOO * I11i * OoOoOO00 + OoO0O00
 red ( IIi11ii . print_address ( ) , False ) , map_notify . retry_count ) )
 if 87 - 87: I1Ii111 / O0 % O0 * o0oOOo0O0Ooo / II111iiii
 lisp_send_map_notify ( IiI11IIIIIi , map_notify . packet , IIi11ii , ooO0 )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 25 - 25: I1ii11iIi11i * ooOoO0o + I11i + iIii1I11I1II1 / iIii1I11I1II1
 if 76 - 76: iII111i
 if 85 - 85: I1ii11iIi11i + OOooOOo % i1IIi
 if 13 - 13: OOooOOo + i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
 if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
 if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
 if 8 - 8: OoooooooOO * OOooOOo * iII111i - iII111i
 if 32 - 32: I1Ii111
 if 28 - 28: I11i . i11iIiiIii % iIii1I11I1II1 + OoOoOO00
 if 4 - 4: OOooOOo + I1ii11iIi11i - iII111i + OOooOOo / IiII
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 23 - 23: iIii1I11I1II1 + OoooooooOO + ooOoO0o . iII111i . Oo0Ooo - iIii1I11I1II1
 if 25 - 25: O0 + I1IiiI % OOooOOo / Oo0Ooo . IiII / I1Ii111
 if 84 - 84: ooOoO0o . O0 + I1IiiI * OoO0O00 - I1IiiI
 if 24 - 24: Ii1I
 eid_record . rloc_count = len ( parent . registered_rlocs )
 IIiiiiI1iIiiI = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 37 - 37: I1IiiI
 if 52 - 52: Oo0Ooo / Ii1I * II111iiii / oO0o
 if 99 - 99: I11i + ooOoO0o % I11i + O0 - Ii1I - I1Ii111
 if 3 - 3: Oo0Ooo . I1IiiI
 for OOoO00o0o in parent . registered_rlocs :
  ooOoooO = lisp_rloc_record ( )
  ooOoooO . store_rloc_entry ( OOoO00o0o )
  ooOoooO . local_bit = True
  ooOoooO . probe_bit = False
  ooOoooO . reach_bit = True
  IIiiiiI1iIiiI += ooOoooO . encode ( )
  ooOoooO . print_record ( "  " )
  del ( ooOoooO )
  if 99 - 99: iII111i . oO0o + II111iiii % O0
  if 40 - 40: iIii1I11I1II1
  if 64 - 64: ooOoO0o * OOooOOo % o0oOOo0O0Ooo + I11i
  if 64 - 64: Ii1I - iIii1I11I1II1 . iII111i . ooOoO0o * O0
  if 3 - 3: I1IiiI % II111iiii
 for OOoO00o0o in parent . registered_rlocs :
  IIi11ii = OOoO00o0o . rloc
  i1111 = lisp_map_notify ( lisp_sockets )
  i1111 . record_count = 1
  IiII11iI1 = map_register . key_id
  i1111 . key_id = IiII11iI1
  i1111 . alg_id = map_register . alg_id
  i1111 . auth_len = map_register . auth_len
  i1111 . nonce = map_register . nonce
  i1111 . nonce_key = lisp_hex_string ( i1111 . nonce )
  i1111 . etr . copy_address ( IIi11ii )
  i1111 . etr_port = map_register . sport
  i1111 . site = parent . site
  Oo00oo = i1111 . encode ( IIiiiiI1iIiiI , parent . site . auth_key [ IiII11iI1 ] )
  i1111 . print_notify ( )
  if 12 - 12: I1Ii111 * O0 + I1ii11iIi11i / ooOoO0o + i11iIiiIii * oO0o
  if 90 - 90: Oo0Ooo % ooOoO0o + I1Ii111 + OoO0O00 . II111iiii . OoO0O00
  if 10 - 10: I1ii11iIi11i - II111iiii * o0oOOo0O0Ooo . OoO0O00 / i11iIiiIii / iII111i
  if 42 - 42: O0 . OoooooooOO + Oo0Ooo
  III = i1111 . nonce_key
  if ( III in lisp_map_notify_queue ) :
   IIi1 = lisp_map_notify_queue [ III ]
   IIi1 . retransmit_timer . cancel ( )
   del ( IIi1 )
   if 46 - 46: i11iIiiIii / I1ii11iIi11i
  lisp_map_notify_queue [ III ] = i1111
  if 30 - 30: Oo0Ooo
  if 68 - 68: i1IIi
  if 98 - 98: o0oOOo0O0Ooo + I1ii11iIi11i - oO0o + i1IIi
  if 85 - 85: I1Ii111 - I1Ii111 . ooOoO0o % I1ii11iIi11i . OOooOOo
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( IIi11ii . print_address ( ) , False ) ) )
  if 98 - 98: iII111i . I1Ii111 % II111iiii
  lisp_send ( lisp_sockets , IIi11ii , LISP_CTRL_PORT , Oo00oo )
  if 28 - 28: OoOoOO00 * I1ii11iIi11i / Oo0Ooo
  parent . site . map_notifies_sent += 1
  if 17 - 17: I1Ii111 - OOooOOo . ooOoO0o - i1IIi * ooOoO0o * I1ii11iIi11i
  if 16 - 16: I1ii11iIi11i . o0oOOo0O0Ooo * iIii1I11I1II1
  if 15 - 15: iII111i + o0oOOo0O0Ooo / IiII
  if 33 - 33: OoooooooOO . IiII * o0oOOo0O0Ooo
  i1111 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ i1111 ] )
  i1111 . retransmit_timer . start ( )
  if 41 - 41: Ii1I . iII111i . o0oOOo0O0Ooo % OoooooooOO % IiII
 return
 if 81 - 81: IiII * i11iIiiIii + i1IIi + OOooOOo . i1IIi
 if 6 - 6: i11iIiiIii - oO0o % OoO0O00 + iIii1I11I1II1
 if 69 - 69: IiII
 if 13 - 13: i11iIiiIii
 if 49 - 49: OoOoOO00
 if 61 - 61: I1Ii111 / I1Ii111 / iII111i / ooOoO0o - I1IiiI . o0oOOo0O0Ooo
 if 80 - 80: I1IiiI - OOooOOo . oO0o
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 75 - 75: oO0o + OoOoOO00 - OoooooooOO
 III = lisp_hex_string ( nonce ) + source . print_address ( )
 if 38 - 38: I11i / ooOoO0o / OoOoOO00 * OOooOOo . oO0o
 if 8 - 8: OoO0O00 . OOooOOo % I1Ii111 * OOooOOo / I1IiiI
 if 3 - 3: IiII - I1ii11iIi11i . o0oOOo0O0Ooo
 if 39 - 39: oO0o . I1Ii111 + oO0o % OoOoOO00 - i11iIiiIii
 if 69 - 69: I11i / OoO0O00
 if 73 - 73: i11iIiiIii / i1IIi
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( III in lisp_map_notify_queue ) :
  i1111 = lisp_map_notify_queue [ III ]
  I111 = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( i1111 . nonce ) , I111 ) )
  if 8 - 8: O0 / OOooOOo + iII111i % iIii1I11I1II1 % iIii1I11I1II1 . ooOoO0o
  return
  if 47 - 47: OoO0O00 / o0oOOo0O0Ooo / Ii1I * I1IiiI % ooOoO0o / I1Ii111
  if 80 - 80: I1Ii111 / O0 * O0
 i1111 = lisp_map_notify ( lisp_sockets )
 i1111 . record_count = record_count
 key_id = key_id
 i1111 . key_id = key_id
 i1111 . alg_id = alg_id
 i1111 . auth_len = auth_len
 i1111 . nonce = nonce
 i1111 . nonce_key = lisp_hex_string ( nonce )
 i1111 . etr . copy_address ( source )
 i1111 . etr_port = port
 i1111 . site = site
 i1111 . eid_list = eid_list
 if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
 if 89 - 89: i11iIiiIii - II111iiii
 if 67 - 67: IiII % I1Ii111 + i11iIiiIii
 if 53 - 53: OOooOOo
 if ( map_register_ack == False ) :
  III = i1111 . nonce_key
  lisp_map_notify_queue [ III ] = i1111
  if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
  if 21 - 21: I1Ii111 . i1IIi - iII111i % I1ii11iIi11i . OOooOOo
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 52 - 52: Ii1I * I1ii11iIi11i
  if 21 - 21: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo * II111iiii % iIii1I11I1II1
  if 9 - 9: I1ii11iIi11i + I11i
  if 20 - 20: iII111i + i1IIi / oO0o % OoooooooOO * OoOoOO00
  if 70 - 70: Oo0Ooo - OOooOOo * OOooOOo / o0oOOo0O0Ooo
 Oo00oo = i1111 . encode ( eid_records , site . auth_key [ key_id ] )
 i1111 . print_notify ( )
 if 4 - 4: OoOoOO00 / OoO0O00
 if ( map_register_ack == False ) :
  o0o0Ooo0OO00o = lisp_eid_record ( )
  o0o0Ooo0OO00o . decode ( eid_records )
  o0o0Ooo0OO00o . print_record ( "  " , False )
  if 66 - 66: I1Ii111 / OoOoOO00
  if 53 - 53: OoOoOO00 . i11iIiiIii - OoooooooOO
  if 92 - 92: O0 - i11iIiiIii + OoO0O00 - OoooooooOO - o0oOOo0O0Ooo
  if 25 - 25: oO0o / oO0o / Ii1I / O0
  if 56 - 56: ooOoO0o
 lisp_send_map_notify ( lisp_sockets , Oo00oo , i1111 . etr , port )
 site . map_notifies_sent += 1
 if 19 - 19: O0 * I1IiiI + I1ii11iIi11i
 if ( map_register_ack ) : return
 if 25 - 25: I11i - ooOoO0o / OoO0O00 / iII111i - OoO0O00
 if 86 - 86: OoO0O00
 if 89 - 89: OoooooooOO % iII111i * I1ii11iIi11i + I1ii11iIi11i . Oo0Ooo
 if 4 - 4: I11i
 if 8 - 8: IiII
 if 1 - 1: ooOoO0o . IiII
 i1111 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ i1111 ] )
 i1111 . retransmit_timer . start ( )
 return
 if 4 - 4: iIii1I11I1II1 % I1IiiI - OoooooooOO / iII111i
 if 55 - 55: O0 + iII111i * OoOoOO00 . i11iIiiIii * Ii1I + oO0o
 if 66 - 66: i1IIi . I1ii11iIi11i
 if 86 - 86: Oo0Ooo
 if 48 - 48: OoO0O00
 if 55 - 55: OoO0O00 * i1IIi * I11i / iII111i
 if 42 - 42: IiII
 if 28 - 28: OoOoOO00 + OoOoOO00
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 53 - 53: II111iiii % i1IIi + ooOoO0o . I1Ii111
 if 52 - 52: I1IiiI + I1Ii111 * oO0o / i11iIiiIii * iIii1I11I1II1
 if 27 - 27: Oo0Ooo
 if 85 - 85: iIii1I11I1II1 . o0oOOo0O0Ooo + oO0o
 Oo00oo = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 79 - 79: O0 - iIii1I11I1II1 + i1IIi . I11i
 if 21 - 21: II111iiii
 if 23 - 23: I11i * i1IIi . oO0o / IiII + o0oOOo0O0Ooo
 if 1 - 1: IiII / OoO0O00 . oO0o * I1Ii111 - i11iIiiIii
 IIi11ii = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( IIi11ii . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , IIi11ii , LISP_CTRL_PORT , Oo00oo )
 return
 if 50 - 50: oO0o - O0 / I1IiiI . OoOoOO00 . Oo0Ooo
 if 30 - 30: IiII . OoO0O00 + Oo0Ooo
 if 48 - 48: iIii1I11I1II1 / i11iIiiIii . OoOoOO00 * I11i
 if 1 - 1: IiII . OoOoOO00 * o0oOOo0O0Ooo
 if 63 - 63: O0 / Ii1I + I1Ii111 % OoO0O00 % OOooOOo * O0
 if 35 - 35: OoO0O00 + OoooooooOO % Oo0Ooo / I11i - O0 . i1IIi
 if 76 - 76: IiII % I1IiiI * Ii1I / Ii1I / OoooooooOO + Ii1I
 if 19 - 19: OoooooooOO
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 88 - 88: I1IiiI % ooOoO0o % Oo0Ooo - O0
 i1111 = lisp_map_notify ( lisp_sockets )
 i1111 . record_count = 1
 i1111 . nonce = lisp_get_control_nonce ( )
 i1111 . nonce_key = lisp_hex_string ( i1111 . nonce )
 i1111 . etr . copy_address ( xtr )
 i1111 . etr_port = LISP_CTRL_PORT
 i1111 . eid_list = eid_list
 III = i1111 . nonce_key
 if 71 - 71: OOooOOo % Ii1I - i11iIiiIii - oO0o . ooOoO0o / I1Ii111
 if 53 - 53: iII111i . Oo0Ooo
 if 91 - 91: oO0o * OoooooooOO * oO0o % oO0o * II111iiii % I1Ii111
 if 8 - 8: Ii1I
 if 28 - 28: iII111i / I1ii11iIi11i - OoOoOO00 * Oo0Ooo + Ii1I * OoOoOO00
 if 94 - 94: oO0o
 lisp_remove_eid_from_map_notify_queue ( i1111 . eid_list )
 if ( III in lisp_map_notify_queue ) :
  i1111 = lisp_map_notify_queue [ III ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( i1111 . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 95 - 95: ooOoO0o * O0 + OOooOOo
  return
  if 11 - 11: i1IIi / OoOoOO00 + OoOoOO00 + I1ii11iIi11i + OOooOOo
  if 21 - 21: ooOoO0o
  if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
  if 81 - 81: oO0o
  if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
 lisp_map_notify_queue [ III ] = i1111
 if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
 if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
 if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
 if 33 - 33: I11i
 O0ooOOOo0O = site_eid . rtrs_in_rloc_set ( )
 if ( O0ooOOOo0O ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : O0ooOOOo0O = False
  if 42 - 42: I1IiiI
  if 47 - 47: II111iiii - I1IiiI . oO0o . oO0o
  if 94 - 94: OoO0O00 . I1ii11iIi11i / IiII
  if 23 - 23: oO0o * I1Ii111 . I1ii11iIi11i
  if 65 - 65: i11iIiiIii + Oo0Ooo % I1ii11iIi11i . OOooOOo
 o0o0Ooo0OO00o = lisp_eid_record ( )
 o0o0Ooo0OO00o . record_ttl = 1440
 o0o0Ooo0OO00o . eid . copy_address ( site_eid . eid )
 o0o0Ooo0OO00o . group . copy_address ( site_eid . group )
 o0o0Ooo0OO00o . rloc_count = 0
 for OOOoOoo in site_eid . registered_rlocs :
  if ( O0ooOOOo0O ^ OOOoOoo . is_rtr ( ) ) : continue
  o0o0Ooo0OO00o . rloc_count += 1
  if 22 - 22: ooOoO0o - I1Ii111 + I1Ii111 * OoOoOO00 * Ii1I
 Oo00oo = o0o0Ooo0OO00o . encode ( )
 if 78 - 78: O0 % Ii1I * OoO0O00 . I11i + I11i
 if 86 - 86: i1IIi + I1ii11iIi11i / i1IIi
 if 54 - 54: iIii1I11I1II1 * Ii1I
 if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
 i1111 . print_notify ( )
 o0o0Ooo0OO00o . print_record ( "  " , False )
 if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
 if 34 - 34: iIii1I11I1II1
 if 47 - 47: OOooOOo * iII111i
 if 71 - 71: IiII - OoooooooOO * i11iIiiIii . OoooooooOO % i1IIi . Oo0Ooo
 for OOOoOoo in site_eid . registered_rlocs :
  if ( O0ooOOOo0O ^ OOOoOoo . is_rtr ( ) ) : continue
  ooOoooO = lisp_rloc_record ( )
  ooOoooO . store_rloc_entry ( OOOoOoo )
  ooOoooO . local_bit = True
  ooOoooO . probe_bit = False
  ooOoooO . reach_bit = True
  Oo00oo += ooOoooO . encode ( )
  ooOoooO . print_record ( "    " )
  if 3 - 3: OoO0O00 + i11iIiiIii + oO0o * IiII
  if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
  if 70 - 70: OoO0O00
  if 42 - 42: OoooooooOO - I1Ii111 + I1ii11iIi11i * iII111i * iII111i / OoO0O00
  if 85 - 85: O0 . II111iiii
 Oo00oo = i1111 . encode ( Oo00oo , "" )
 if ( Oo00oo == None ) : return
 if 80 - 80: O0 * I11i * I1Ii111
 if 89 - 89: Ii1I * OoO0O00 . i1IIi . O0 - IiII - OoOoOO00
 if 25 - 25: iII111i + i1IIi
 if 64 - 64: IiII % I11i / iIii1I11I1II1
 lisp_send_map_notify ( lisp_sockets , Oo00oo , xtr , LISP_CTRL_PORT )
 if 66 - 66: Ii1I
 if 55 - 55: OOooOOo + I1IiiI + IiII . Ii1I * oO0o
 if 71 - 71: IiII - iII111i % I1IiiI * iII111i
 if 27 - 27: ooOoO0o - OoO0O00
 i1111 . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ i1111 ] )
 i1111 . retransmit_timer . start ( )
 return
 if 83 - 83: iII111i * OoOoOO00 - O0 * Ii1I
 if 79 - 79: I11i / iII111i % Ii1I / OoOoOO00 % O0 / IiII
 if 32 - 32: IiII * II111iiii . Ii1I
 if 68 - 68: I11i / O0
 if 6 - 6: oO0o - oO0o . I1IiiI % I1ii11iIi11i
 if 22 - 22: Ii1I / I1IiiI / II111iiii
 if 31 - 31: II111iiii - Ii1I * OOooOOo - i11iIiiIii / OoooooooOO - I1Ii111
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 o00Oo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 35 - 35: i11iIiiIii . Ii1I
 for I1iiIiI1II1ii in rle_list :
  OoO0 = lisp_site_eid_lookup ( I1iiIiI1II1ii [ 0 ] , I1iiIiI1II1ii [ 1 ] , True )
  if ( OoO0 == None ) : continue
  if 15 - 15: Ii1I % I1IiiI + ooOoO0o * IiII % OoOoOO00 / Oo0Ooo
  if 35 - 35: i1IIi - i1IIi * I1ii11iIi11i / O0 / Oo0Ooo - ooOoO0o
  if 51 - 51: OoO0O00 + Ii1I * o0oOOo0O0Ooo
  if 86 - 86: OoOoOO00 - iII111i % OoO0O00 / OOooOOo / O0
  if 61 - 61: oO0o + OOooOOo * II111iiii
  if 76 - 76: iII111i % I1IiiI % OOooOOo + OOooOOo
  if 38 - 38: I1Ii111 * I1Ii111 + iII111i
  oo0OooO = OoO0 . registered_rlocs
  if ( len ( oo0OooO ) == 0 ) :
   Oo0 = { }
   for ooOO00o in list ( OoO0 . individual_registrations . values ( ) ) :
    for OOOoOoo in ooOO00o . registered_rlocs :
     if ( OOOoOoo . is_rtr ( ) == False ) : continue
     Oo0 [ OOOoOoo . rloc . print_address ( ) ] = OOOoOoo
     if 100 - 100: iIii1I11I1II1 / oO0o
     if 26 - 26: OOooOOo / iIii1I11I1II1 / I1Ii111 + I11i - O0 . O0
   oo0OooO = list ( Oo0 . values ( ) )
   if 20 - 20: oO0o * O0 * Oo0Ooo
   if 81 - 81: OoO0O00 . ooOoO0o
   if 78 - 78: II111iiii - i11iIiiIii . OOooOOo
   if 22 - 22: Oo0Ooo + ooOoO0o
   if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
   if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
  IiiIIiIi = [ ]
  ooooO0oOOOOO = False
  if ( OoO0 . eid . address == 0 and OoO0 . eid . mask_len == 0 ) :
   ooo = [ ]
   IiI1Iiii = [ ]
   if ( len ( oo0OooO ) != 0 and oo0OooO [ 0 ] . rle != None ) :
    IiI1Iiii = oo0OooO [ 0 ] . rle . rle_nodes
    if 7 - 7: OoOoOO00 + OoO0O00 * I1IiiI
   for iIIi in IiI1Iiii :
    IiiIIiIi . append ( iIIi . address )
    ooo . append ( iIIi . address . print_address_no_iid ( ) )
    if 63 - 63: I1ii11iIi11i + iII111i * i1IIi
   lprint ( "Notify existing RLE-nodes {}" . format ( ooo ) )
  else :
   if 63 - 63: I1ii11iIi11i / II111iiii % oO0o + ooOoO0o . Ii1I % I11i
   if 59 - 59: I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
   if 5 - 5: I1IiiI
   if 22 - 22: II111iiii / iII111i
   if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
   for OOOoOoo in oo0OooO :
    if ( OOOoOoo . is_rtr ( ) ) : IiiIIiIi . append ( OOOoOoo . rloc )
    if 62 - 62: O0 % o0oOOo0O0Ooo + iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
    if 21 - 21: o0oOOo0O0Ooo % O0
    if 81 - 81: i1IIi + i1IIi
    if 3 - 3: I1Ii111 . I1ii11iIi11i * iII111i * i11iIiiIii * IiII
    if 52 - 52: iIii1I11I1II1 % o0oOOo0O0Ooo % I1IiiI
   ooooO0oOOOOO = ( len ( IiiIIiIi ) != 0 )
   if ( ooooO0oOOOOO == False ) :
    i1iI11i = lisp_site_eid_lookup ( I1iiIiI1II1ii [ 0 ] , o00Oo0 , False )
    if ( i1iI11i == None ) : continue
    if 71 - 71: I1IiiI + iII111i
    for OOOoOoo in i1iI11i . registered_rlocs :
     if ( OOOoOoo . rloc . is_null ( ) ) : continue
     IiiIIiIi . append ( OOOoOoo . rloc )
     if 47 - 47: iIii1I11I1II1 . OoO0O00 . iIii1I11I1II1
     if 57 - 57: IiII * ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + OoOoOO00
     if 83 - 83: OoOoOO00 . Oo0Ooo . OoO0O00
     if 65 - 65: iII111i * iIii1I11I1II1
     if 48 - 48: iII111i * OoO0O00
     if 57 - 57: ooOoO0o + I1IiiI
   if ( len ( IiiIIiIi ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( OoO0 . print_eid_tuple ( ) , False ) ) )
    if 32 - 32: I1ii11iIi11i + OOooOOo - I11i
    continue
    if 82 - 82: Oo0Ooo % Oo0Ooo
    if 91 - 91: I11i
    if 98 - 98: I11i - II111iiii . IiII % Oo0Ooo
    if 65 - 65: OoO0O00
    if 65 - 65: oO0o
    if 77 - 77: I11i * i1IIi - OOooOOo / OoOoOO00
  for OOoO00o0o in IiiIIiIi :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if ooooO0oOOOOO else "x" , red ( OOoO00o0o . print_address_no_iid ( ) , False ) ,
   # I1ii11iIi11i + O0 . oO0o
 green ( OoO0 . print_eid_tuple ( ) , False ) ) )
   if 65 - 65: OOooOOo + i1IIi * Ii1I % iIii1I11I1II1 . OOooOOo % I1ii11iIi11i
   OoO0Oo0 = [ OoO0 . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , OoO0 , OoO0Oo0 , OOoO00o0o )
   time . sleep ( .001 )
   if 91 - 91: I1Ii111
   if 54 - 54: o0oOOo0O0Ooo . i1IIi / iII111i
 return
 if 21 - 21: O0 + ooOoO0o
 if 53 - 53: Ii1I - II111iiii * iIii1I11I1II1
 if 91 - 91: OoOoOO00 % iIii1I11I1II1
 if 81 - 81: i11iIiiIii / OoOoOO00 + iIii1I11I1II1
 if 65 - 65: o0oOOo0O0Ooo
 if 73 - 73: I11i . I1ii11iIi11i - OoO0O00 + OoooooooOO
 if 71 - 71: I1IiiI
 if 27 - 27: OoO0O00 + i1IIi * OoooooooOO * iIii1I11I1II1 - Ii1I
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for iIi1iIIIiIiI in range ( rloc_count ) :
  ooOoooO = lisp_rloc_record ( )
  packet = ooOoooO . decode ( packet , None )
  OOoooO = ooOoooO . json
  if ( OOoooO == None ) : continue
  if 87 - 87: OoOoOO00 * I1IiiI
  try :
   OOoooO = json . loads ( OOoooO . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
   if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
  if ( "signature" not in OOoooO ) : continue
  return ( ooOoooO )
  if 33 - 33: oO0o . oO0o / IiII + II111iiii
 return ( None )
 if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
 if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
 if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
 if 25 - 25: OoO0O00
 if 83 - 83: II111iiii . iIii1I11I1II1
 if 77 - 77: O0 . OoOoOO00 % oO0o / OOooOOo
 if 8 - 8: iII111i - i1IIi
 if 81 - 81: ooOoO0o / OOooOOo % OoOoOO00 . iIii1I11I1II1
 if 45 - 45: I1IiiI . ooOoO0o - OoooooooOO
 if 84 - 84: I1ii11iIi11i
 if 69 - 69: I1Ii111 + II111iiii
 if 92 - 92: OoooooooOO
 if 80 - 80: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . oO0o % I1IiiI % I11i
 if 4 - 4: OoO0O00 / iII111i / I1ii11iIi11i - o0oOOo0O0Ooo * I1Ii111
 if 24 - 24: OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - o0oOOo0O0Ooo . I1ii11iIi11i
 if 2 - 2: I1IiiI . o0oOOo0O0Ooo / Oo0Ooo - OoOoOO00 - OoooooooOO
 if 73 - 73: I1Ii111 . i11iIiiIii * ooOoO0o . IiII - I11i + I1Ii111
 if 21 - 21: I1Ii111 + iIii1I11I1II1 + I1IiiI / O0 * I1ii11iIi11i
 if 57 - 57: OOooOOo * I11i . oO0o
def lisp_get_eid_hash ( eid ) :
 I11IIi1iI = None
 for o0OOOooO in lisp_eid_hashes :
  if 6 - 6: Ii1I
  if 23 - 23: o0oOOo0O0Ooo + I1IiiI
  if 85 - 85: o0oOOo0O0Ooo
  if 23 - 23: o0oOOo0O0Ooo / IiII - O0
  oooo = o0OOOooO . instance_id
  if ( oooo == - 1 ) : o0OOOooO . instance_id = eid . instance_id
  if 60 - 60: I1ii11iIi11i * i11iIiiIii + oO0o
  oO00000oOO = eid . is_more_specific ( o0OOOooO )
  o0OOOooO . instance_id = oooo
  if ( oO00000oOO ) :
   I11IIi1iI = 128 - o0OOOooO . mask_len
   break
   if 63 - 63: i11iIiiIii
   if 47 - 47: OOooOOo - II111iiii % I1Ii111 * O0 . ooOoO0o
 if ( I11IIi1iI == None ) : return ( None )
 if 96 - 96: II111iiii . I1IiiI % I11i
 I1IIIi = eid . address
 iIii1II111Ii = ""
 for iIi1iIIIiIiI in range ( 0 , old_div ( I11IIi1iI , 16 ) ) :
  IiI = I1IIIi & 0xffff
  IiI = hex ( IiI ) [ 2 : : ]
  iIii1II111Ii = IiI . zfill ( 4 ) + ":" + iIii1II111Ii
  I1IIIi >>= 16
  if 3 - 3: oO0o
 if ( I11IIi1iI % 16 != 0 ) :
  IiI = I1IIIi & 0xff
  IiI = hex ( IiI ) [ 2 : : ]
  iIii1II111Ii = IiI . zfill ( 2 ) + ":" + iIii1II111Ii
  if 3 - 3: I1ii11iIi11i . IiII + ooOoO0o
 return ( iIii1II111Ii [ 0 : - 1 ] )
 if 66 - 66: OOooOOo + oO0o - ooOoO0o / Ii1I * OoO0O00 * i11iIiiIii
 if 69 - 69: I11i % i11iIiiIii
 if 34 - 34: Ii1I . OoooooooOO + II111iiii % oO0o
 if 69 - 69: i11iIiiIii % I1IiiI * i11iIiiIii - OoO0O00 * iIii1I11I1II1
 if 70 - 70: I1Ii111 . OoOoOO00 % OoooooooOO + OoOoOO00 / II111iiii
 if 39 - 39: I1Ii111 * I1IiiI - o0oOOo0O0Ooo . oO0o . OOooOOo * i11iIiiIii
 if 70 - 70: OoOoOO00 / OOooOOo - o0oOOo0O0Ooo
 if 82 - 82: OOooOOo . i11iIiiIii . I1ii11iIi11i % OoOoOO00 * Ii1I / OoO0O00
 if 56 - 56: o0oOOo0O0Ooo / I1IiiI + I11i + I1IiiI
 if 34 - 34: Oo0Ooo / i11iIiiIii - ooOoO0o
 if 77 - 77: OoOoOO00 * OoooooooOO
def lisp_lookup_public_key ( eid ) :
 oooo = eid . instance_id
 if 41 - 41: iIii1I11I1II1 - O0 . II111iiii + I1IiiI - II111iiii / oO0o
 if 35 - 35: ooOoO0o - OoOoOO00 / iIii1I11I1II1 / OOooOOo
 if 38 - 38: i1IIi % OoooooooOO
 if 5 - 5: iIii1I11I1II1 + iIii1I11I1II1 . iIii1I11I1II1 + o0oOOo0O0Ooo
 if 45 - 45: I1IiiI - OoooooooOO - I1Ii111 - i1IIi - OoooooooOO * O0
 oOoO00O0O0ooo = lisp_get_eid_hash ( eid )
 if ( oOoO00O0O0ooo == None ) : return ( [ None , None , False ] )
 if 63 - 63: I1ii11iIi11i
 oOoO00O0O0ooo = "hash-" + oOoO00O0O0ooo
 oOo0oO0o = lisp_address ( LISP_AFI_NAME , oOoO00O0O0ooo , len ( oOoO00O0O0ooo ) , oooo )
 oo0oOooo0O = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
 if 34 - 34: O0
 if 26 - 26: II111iiii - oO0o / I1IiiI * OOooOOo + o0oOOo0O0Ooo
 if 59 - 59: Oo0Ooo + I11i % OoOoOO00 - I1IiiI + I11i
 if 53 - 53: II111iiii
 i1iI11i = lisp_site_eid_lookup ( oOo0oO0o , oo0oOooo0O , True )
 if ( i1iI11i == None ) : return ( [ oOo0oO0o , None , False ] )
 if 9 - 9: OoooooooOO - OOooOOo . I11i * oO0o
 if 3 - 3: iIii1I11I1II1 - OoO0O00
 if 38 - 38: O0 + ooOoO0o * I1Ii111 - oO0o * o0oOOo0O0Ooo
 if 97 - 97: Oo0Ooo - O0 * OoooooooOO
 ooOoI1IiiI = None
 for iIIiI11 in i1iI11i . registered_rlocs :
  oo0oO0O = iIIiI11 . json
  if ( oo0oO0O == None ) : continue
  try :
   oo0oO0O = json . loads ( oo0oO0O . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( oOoO00O0O0ooo ) )
   if 92 - 92: I11i
   return ( [ oOo0oO0o , None , False ] )
   if 77 - 77: I11i / iII111i / O0 % II111iiii % OoOoOO00 / I1Ii111
  if ( "public-key" not in oo0oO0O ) : continue
  ooOoI1IiiI = oo0oO0O [ "public-key" ]
  break
  if 77 - 77: OoOoOO00 % I1IiiI % II111iiii * iII111i . OoOoOO00 / O0
 return ( [ oOo0oO0o , ooOoI1IiiI , True ] )
 if 21 - 21: ooOoO0o - I11i . i11iIiiIii
 if 39 - 39: Oo0Ooo * II111iiii % OOooOOo / oO0o . ooOoO0o
 if 75 - 75: I11i / O0 + OoooooooOO + OOooOOo % iII111i + I1IiiI
 if 10 - 10: II111iiii * I11i - IiII * iIii1I11I1II1 . OoooooooOO
 if 39 - 39: I11i . I1IiiI % Oo0Ooo + oO0o
 if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
 if 82 - 82: IiII % ooOoO0o
 if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 27 - 27: Oo0Ooo . I1Ii111 - i1IIi * I1IiiI
 if 96 - 96: I1ii11iIi11i - Ii1I . I1ii11iIi11i
 if 89 - 89: II111iiii % I1ii11iIi11i % IiII . I11i
 if 49 - 49: iII111i % i11iIiiIii * I11i - oO0o . OOooOOo . i11iIiiIii
 if 26 - 26: iIii1I11I1II1 + i11iIiiIii % iII111i + I1IiiI + oO0o - ooOoO0o
 O0OoO0ooOoo = json . loads ( rloc_record . json . json_string )
 if 4 - 4: Oo0Ooo - IiII - I11i
 if ( lisp_get_eid_hash ( eid ) ) :
  OO00O = eid
 elif ( "signature-eid" in O0OoO0ooOoo ) :
  ooooI111I11i = O0OoO0ooOoo [ "signature-eid" ]
  OO00O = lisp_address ( LISP_AFI_IPV6 , ooooI111I11i , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 76 - 76: OOooOOo . iII111i % ooOoO0o
  if 15 - 15: iII111i
  if 55 - 55: iII111i
  if 22 - 22: I1Ii111 % II111iiii % iIii1I11I1II1 % II111iiii
  if 33 - 33: II111iiii
 oOo0oO0o , ooOoI1IiiI , oo00iI1i = lisp_lookup_public_key ( OO00O )
 if ( oOo0oO0o == None ) :
  i1iiii = green ( OO00O . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( i1iiii ) )
  return ( False )
  if 66 - 66: OOooOOo
  if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
 III11i1 = "found" if oo00iI1i else bold ( "not found" , False )
 i1iiii = green ( oOo0oO0o . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( i1iiii , III11i1 ) )
 if ( oo00iI1i == False ) : return ( False )
 if 80 - 80: o0oOOo0O0Ooo * ooOoO0o
 if ( ooOoI1IiiI == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 87 - 87: I1Ii111 + O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - IiII
  if 24 - 24: OoOoOO00
 iI1ii11iiiiII = ooOoI1IiiI [ 0 : 8 ] + "..." + ooOoI1IiiI [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( iI1ii11iiiiII ) )
 if 48 - 48: o0oOOo0O0Ooo + OOooOOo % OoooooooOO
 if 51 - 51: OoO0O00
 if 60 - 60: ooOoO0o
 if 95 - 95: I11i / o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
 if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
 ii1iIIiIIi111 = O0OoO0ooOoo [ "signature" ]
 if 35 - 35: OOooOOo * oO0o
 try :
  O0OoO0ooOoo = binascii . a2b_base64 ( ii1iIIiIIi111 )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 19 - 19: iIii1I11I1II1 + IiII * iII111i - IiII
  if 87 - 87: o0oOOo0O0Ooo - I1Ii111
 I1II1I1III = len ( O0OoO0ooOoo )
 if ( I1II1I1III & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( I1II1I1III ) )
  return ( False )
  if 6 - 6: iII111i / i1IIi + OOooOOo % OoOoOO00 . I1ii11iIi11i
  if 88 - 88: OoO0O00
  if 82 - 82: OOooOOo / I11i / OoooooooOO % oO0o
  if 27 - 27: oO0o + IiII
  if 5 - 5: iIii1I11I1II1 + OoOoOO00 * I1Ii111 * i11iIiiIii
 ii1iiii11IiI1 = OO00O . print_address ( )
 if 18 - 18: Oo0Ooo % OOooOOo % oO0o / I11i % O0
 if 76 - 76: OoooooooOO % O0 / OoO0O00
 if 41 - 41: i11iIiiIii - I1ii11iIi11i - II111iiii
 if 5 - 5: OoOoOO00 + i1IIi
 ooOoI1IiiI = binascii . a2b_base64 ( ooOoI1IiiI )
 try :
  III = ecdsa . VerifyingKey . from_pem ( ooOoI1IiiI )
 except :
  i1ii1ii11iIi = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( i1ii1ii11iIi ) )
  return ( False )
  if 99 - 99: OOooOOo . IiII
  if 77 - 77: I1IiiI + I11i * iIii1I11I1II1 / I1IiiI - iII111i
  if 42 - 42: oO0o * IiII
  if 37 - 37: I11i * ooOoO0o / IiII . I1ii11iIi11i + II111iiii
  if 55 - 55: OoO0O00
  if 63 - 63: o0oOOo0O0Ooo / IiII - i11iIiiIii
  if 99 - 99: O0 + O0 . iIii1I11I1II1 . ooOoO0o * o0oOOo0O0Ooo
  if 1 - 1: I1Ii111 - I11i . OoOoOO00
  if 72 - 72: II111iiii . O0 . I11i * OoO0O00
  if 70 - 70: iII111i % OoooooooOO * I1ii11iIi11i . I11i / OoO0O00
  if 6 - 6: O0 . i11iIiiIii
 try :
  O0oOo = III . verify ( O0OoO0ooOoo , ii1iiii11IiI1 . encode ( ) , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( ii1iiii11IiI1 ) )
  if 85 - 85: i11iIiiIii / Ii1I + Oo0Ooo / OoOoOO00 - I1IiiI
  lprint ( "  Signature used '{}'" . format ( ii1iIIiIIi111 ) )
  return ( False )
  if 39 - 39: OoO0O00
 return ( O0oOo )
 if 97 - 97: iIii1I11I1II1 . I1IiiI - O0
 if 41 - 41: I11i . OoOoOO00 * O0 % Ii1I
 if 54 - 54: ooOoO0o
 if 13 - 13: I11i
 if 18 - 18: II111iiii * oO0o % i11iIiiIii / IiII . ooOoO0o
 if 2 - 2: OoOoOO00 % I1Ii111
 if 35 - 35: OOooOOo
 if 50 - 50: iIii1I11I1II1 . I1IiiI + i11iIiiIii
 if 65 - 65: I11i % I1IiiI
 if 3 - 3: i11iIiiIii % OOooOOo - Ii1I . i1IIi
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 24 - 24: OOooOOo
 if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
 if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
 if 59 - 59: oO0o * OoO0O00 - I11i * I1IiiI
 if 60 - 60: iII111i - OoooooooOO / iII111i % OoO0O00 . OoOoOO00 - o0oOOo0O0Ooo
 O00O0oo0O00O = [ ]
 for oOOOOOOoo0 in eid_list :
  for I1Ii11i1 in lisp_map_notify_queue :
   i1111 = lisp_map_notify_queue [ I1Ii11i1 ]
   if ( oOOOOOOoo0 not in i1111 . eid_list ) : continue
   if 100 - 100: I1ii11iIi11i / Ii1I % Oo0Ooo
   O00O0oo0O00O . append ( I1Ii11i1 )
   oo0O00O0O0O00Ooo = i1111 . retransmit_timer
   if ( oo0O00O0O0O00Ooo ) : oo0O00O0O0O00Ooo . cancel ( )
   if 97 - 97: i1IIi . I1ii11iIi11i . OOooOOo - ooOoO0o
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( i1111 . nonce_key , green ( oOOOOOOoo0 , False ) ) )
   if 40 - 40: i11iIiiIii % i1IIi - iII111i
   if 22 - 22: I1IiiI - I11i + OoOoOO00 - i11iIiiIii
   if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
   if 61 - 61: oO0o . i11iIiiIii / Ii1I % iII111i
   if 36 - 36: OoO0O00 + Ii1I / I11i - iII111i % OoO0O00 / Oo0Ooo
   if 38 - 38: Ii1I - ooOoO0o - O0 + oO0o . iIii1I11I1II1
   if 90 - 90: i1IIi * OoOoOO00
 for I1Ii11i1 in O00O0oo0O00O : lisp_map_notify_queue . pop ( I1Ii11i1 )
 return
 if 27 - 27: iIii1I11I1II1
 if 95 - 95: iII111i / ooOoO0o % Ii1I
 if 44 - 44: OOooOOo . OOooOOo
 if 5 - 5: oO0o + OoooooooOO
 if 88 - 88: oO0o + OOooOOo
 if 14 - 14: I11i / i1IIi
 if 56 - 56: OoooooooOO
 if 59 - 59: I1ii11iIi11i + OoO0O00
def lisp_decrypt_map_register ( packet ) :
 if 37 - 37: IiII * I1IiiI % O0
 if 32 - 32: ooOoO0o % II111iiii
 if 60 - 60: i11iIiiIii
 if 11 - 11: o0oOOo0O0Ooo
 if 77 - 77: o0oOOo0O0Ooo / iIii1I11I1II1 * iIii1I11I1II1 / o0oOOo0O0Ooo * iII111i
 IiIii1iIIII = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 ii1iIII1I1I = ( IiIii1iIIII >> 13 ) & 0x1
 if ( ii1iIII1I1I == 0 ) : return ( packet )
 if 57 - 57: I1IiiI + i11iIiiIii * i1IIi
 O00OOooO0O = ( IiIii1iIIII >> 14 ) & 0x7
 if 44 - 44: II111iiii
 if 65 - 65: I11i . iII111i . I1IiiI - Oo0Ooo % iIii1I11I1II1 / O0
 if 54 - 54: iII111i - I1Ii111
 if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
 try :
  iiIio0o0 = lisp_ms_encryption_keys [ O00OOooO0O ]
  iiIio0o0 = iiIio0o0 . zfill ( 32 )
  OoOooO = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( O00OOooO0O ) )
  return ( None )
  if 45 - 45: oO0o % oO0o
  if 85 - 85: i1IIi + oO0o % Ii1I + iIii1I11I1II1
 IiI11I111 = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( IiI11I111 , O00OOooO0O ) )
 if 72 - 72: I1ii11iIi11i / II111iiii . oO0o - o0oOOo0O0Ooo
 if 80 - 80: i1IIi
 if 40 - 40: O0 . ooOoO0o * iII111i . I11i + I1Ii111 % OoO0O00
 if 9 - 9: IiII * oO0o - o0oOOo0O0Ooo
 Ooi1IIii1i = chacha . ChaCha ( iiIio0o0 , OoOooO , 20 ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + Ooi1IIii1i )
 if 17 - 17: iII111i % Oo0Ooo
 if 14 - 14: I1IiiI - I1Ii111 % I1IiiI - II111iiii
 if 34 - 34: I1ii11iIi11i * IiII / II111iiii / ooOoO0o * oO0o
 if 3 - 3: II111iiii
 if 61 - 61: oO0o . I1IiiI + i1IIi
 if 69 - 69: O0 / i1IIi - OoOoOO00 + ooOoO0o - oO0o
 if 80 - 80: o0oOOo0O0Ooo % O0 * I11i . i1IIi - ooOoO0o
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
 if 61 - 61: II111iiii / i1IIi . I1ii11iIi11i % iIii1I11I1II1
 if 66 - 66: iIii1I11I1II1 % OoOoOO00 + i1IIi * i11iIiiIii * OoooooooOO
 if 36 - 36: iII111i - OoO0O00 + I1IiiI + Ii1I . OoooooooOO
 if 75 - 75: oO0o * Oo0Ooo * O0
 if 22 - 22: ooOoO0o / OoooooooOO . II111iiii / Ii1I * OoO0O00 . i1IIi
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 62 - 62: oO0o % Ii1I - Ii1I
 IIIiI111I = lisp_map_register ( )
 i1o0o0oOO , packet = IIIiI111I . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 7 - 7: I1Ii111 / OoOoOO00 . II111iiii
 IIIiI111I . sport = sport
 if 9 - 9: I11i . I11i . OoooooooOO
 IIIiI111I . print_map_register ( )
 if 42 - 42: iII111i / oO0o / iII111i * OoO0O00
 if 25 - 25: OoOoOO00 - II111iiii + II111iiii . Ii1I * II111iiii
 if 12 - 12: IiII / Ii1I
 if 54 - 54: Oo0Ooo + Ii1I % OoooooooOO * OOooOOo / OoOoOO00
 iI1i1I111iI = True
 if ( IIIiI111I . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  iI1i1I111iI = True
  if 63 - 63: II111iiii + I1Ii111
 if ( IIIiI111I . alg_id == LISP_SHA_256_128_ALG_ID ) :
  iI1i1I111iI = False
  if 19 - 19: I1ii11iIi11i
  if 44 - 44: OoOoOO00 * Oo0Ooo
  if 51 - 51: OOooOOo / IiII % I1Ii111 . OoOoOO00 % Ii1I
  if 88 - 88: OoO0O00
  if 28 - 28: I1Ii111 - iIii1I11I1II1
 oO0oOOoo0OO0 = [ ]
 if 25 - 25: iII111i / iII111i
 if 7 - 7: II111iiii * Ii1I * OoO0O00 / o0oOOo0O0Ooo
 if 71 - 71: ooOoO0o - i11iIiiIii - OoO0O00 % iII111i * OoooooooOO * OoooooooOO
 if 44 - 44: OoO0O00 . OoOoOO00 + I1Ii111
 I1io0oOOooOoo0oO = None
 Oo0O0OO = packet
 oo0OoO0OoOO0O = [ ]
 oo0OOo00OOoO = IIIiI111I . record_count
 for iIi1iIIIiIiI in range ( oo0OOo00OOoO ) :
  o0o0Ooo0OO00o = lisp_eid_record ( )
  ooOoooO = lisp_rloc_record ( )
  packet = o0o0Ooo0OO00o . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 44 - 44: Oo0Ooo + oO0o + I1ii11iIi11i - iIii1I11I1II1 + Oo0Ooo + OoooooooOO
  o0o0Ooo0OO00o . print_record ( "  " , False )
  if 96 - 96: O0 - Ii1I * Ii1I / OoO0O00 / II111iiii / ooOoO0o
  if 48 - 48: ooOoO0o % I1IiiI + IiII * I1ii11iIi11i * I1IiiI % OoO0O00
  if 79 - 79: i11iIiiIii + OOooOOo + oO0o * iIii1I11I1II1 % iII111i . I1Ii111
  if 30 - 30: OoO0O00 / II111iiii
  i1iI11i = lisp_site_eid_lookup ( o0o0Ooo0OO00o . eid , o0o0Ooo0OO00o . group ,
 False )
  if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
  oOoOO000Oo0 = i1iI11i . print_eid_tuple ( ) if i1iI11i else None
  if 49 - 49: I11i - OoooooooOO + i11iIiiIii
  if 90 - 90: I1IiiI / I1Ii111 + Oo0Ooo / o0oOOo0O0Ooo + OOooOOo
  if 99 - 99: i1IIi - oO0o
  if 84 - 84: I1IiiI / IiII - OoO0O00 . Ii1I * IiII % Ii1I
  if 57 - 57: I11i + iIii1I11I1II1 . II111iiii * oO0o
  if 87 - 87: iII111i . II111iiii / Ii1I / O0 - oO0o
  if 49 - 49: I1ii11iIi11i . OoOoOO00 / O0 * i1IIi * I1ii11iIi11i . o0oOOo0O0Ooo
  if ( i1iI11i and i1iI11i . accept_more_specifics == False ) :
   if ( i1iI11i . eid_record_matches ( o0o0Ooo0OO00o ) == False ) :
    O0oOoO00O = i1iI11i . parent_for_more_specifics
    if ( O0oOoO00O ) : i1iI11i = O0oOoO00O
    if 95 - 95: OoO0O00 + O0 * oO0o
    if 39 - 39: i1IIi
    if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
    if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
    if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
    if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
    if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
    if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
  i1I1IiiIi = ( i1iI11i and i1iI11i . accept_more_specifics )
  if ( i1I1IiiIi ) :
   iI1i = lisp_site_eid ( i1iI11i . site )
   iI1i . dynamic = True
   iI1i . eid . copy_address ( o0o0Ooo0OO00o . eid )
   iI1i . group . copy_address ( o0o0Ooo0OO00o . group )
   iI1i . parent_for_more_specifics = i1iI11i
   iI1i . add_cache ( )
   iI1i . inherit_from_ams_parent ( )
   i1iI11i . more_specific_registrations . append ( iI1i )
   i1iI11i = iI1i
  else :
   i1iI11i = lisp_site_eid_lookup ( o0o0Ooo0OO00o . eid , o0o0Ooo0OO00o . group ,
 True )
   if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
   if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
  i1iiii = o0o0Ooo0OO00o . print_eid_tuple ( )
  if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
  if ( i1iI11i == None ) :
   oo0oO0Oo = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( oo0oO0Oo , green ( i1iiii , False ) ,
 ", matched non-ams {}" . format ( green ( oOoOO000Oo0 , False ) if oOoOO000Oo0 else "" ) ) )
   if 29 - 29: oO0o
   if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
   if 78 - 78: Oo0Ooo
   if 77 - 77: oO0o % Oo0Ooo % O0
   if 51 - 51: IiII % IiII + OOooOOo . II111iiii / I1ii11iIi11i
   packet = ooOoooO . end_of_rlocs ( packet , o0o0Ooo0OO00o . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 4 - 4: o0oOOo0O0Ooo % I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
   continue
   if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
   if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
  I1io0oOOooOoo0oO = i1iI11i . site
  if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
  if ( i1I1IiiIi ) :
   oO0ooOOO = i1iI11i . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( oO0ooOOO , False ) , I1io0oOOooOoo0oO . site_name , green ( i1iiii , False ) ) )
   if 88 - 88: ooOoO0o
  else :
   oO0ooOOO = green ( i1iI11i . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( oO0ooOOO , I1io0oOOooOoo0oO . site_name , green ( i1iiii , False ) ) )
   if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
   if 20 - 20: i11iIiiIii * I11i
   if 29 - 29: IiII / OOooOOo
   if 39 - 39: O0 + II111iiii
   if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
   if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
  if ( I1io0oOOooOoo0oO . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( I1io0oOOooOoo0oO . site_name ) )
   packet = ooOoooO . end_of_rlocs ( packet , o0o0Ooo0OO00o . rloc_count )
   continue
   if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
   if 42 - 42: O0 / oO0o % O0 . i1IIi % OOooOOo
   if 13 - 13: I1IiiI % ooOoO0o + OOooOOo
   if 91 - 91: oO0o - ooOoO0o
   if 20 - 20: i1IIi . IiII / o0oOOo0O0Ooo / I11i
   if 27 - 27: ooOoO0o . ooOoO0o - Ii1I % i11iIiiIii
   if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
   if 7 - 7: I1IiiI + OoooooooOO + o0oOOo0O0Ooo . OoooooooOO
  IiII11iI1 = IIIiI111I . key_id
  if ( IiII11iI1 in I1io0oOOooOoo0oO . auth_key ) :
   I1Ii1II1I11II = I1io0oOOooOoo0oO . auth_key [ IiII11iI1 ]
  else :
   I1Ii1II1I11II = ""
   if 56 - 56: Ii1I % OoO0O00 / I1IiiI / iIii1I11I1II1
   if 49 - 49: I1IiiI
  I1Iii1IIIiiiI = lisp_verify_auth ( i1o0o0oOO , IIIiI111I . alg_id ,
 IIIiI111I . auth_data , I1Ii1II1I11II )
  oOO00 = "dynamic " if i1iI11i . dynamic else ""
  if 25 - 25: IiII * iIii1I11I1II1
  Oo0oOO = bold ( "passed" if I1Iii1IIIiiiI else "failed" , False )
  IiII11iI1 = "key-id {}" . format ( IiII11iI1 ) if IiII11iI1 == IIIiI111I . key_id else "bad key-id {}" . format ( IIIiI111I . key_id )
  if 38 - 38: O0
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( Oo0oOO , oOO00 , green ( i1iiii , False ) , IiII11iI1 ) )
  if 14 - 14: i11iIiiIii / O0 . iII111i + II111iiii / OoOoOO00 + OOooOOo
  if 68 - 68: OOooOOo + I11i - ooOoO0o * OOooOOo . I11i + I1ii11iIi11i
  if 40 - 40: I1ii11iIi11i + I1Ii111 * Oo0Ooo % OoO0O00 % O0 % i1IIi
  if 2 - 2: II111iiii + OoOoOO00 - I11i
  if 71 - 71: o0oOOo0O0Ooo - I1Ii111
  if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
  Oo0OOoO0oO = True
  o00i1I11IIIi11I = ( lisp_get_eid_hash ( o0o0Ooo0OO00o . eid ) != None )
  if ( o00i1I11IIIi11I or i1iI11i . require_signature ) :
   OO0IIiI1Iiii11i = "Required " if i1iI11i . require_signature else ""
   i1iiii = green ( i1iiii , False )
   iIIiI11 = lisp_find_sig_in_rloc_set ( packet , o0o0Ooo0OO00o . rloc_count )
   if ( iIIiI11 == None ) :
    Oo0OOoO0oO = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( OO0IIiI1Iiii11i ,
    # ooOoO0o - I11i % OoO0O00 * OoOoOO00 % I1ii11iIi11i
 bold ( "failed" , False ) , i1iiii ) )
   else :
    Oo0OOoO0oO = lisp_verify_cga_sig ( o0o0Ooo0OO00o . eid , iIIiI11 )
    Oo0oOO = bold ( "passed" if Oo0OOoO0oO else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( OO0IIiI1Iiii11i , Oo0oOO , i1iiii ) )
    if 35 - 35: OOooOOo
    if 36 - 36: O0 - iII111i * oO0o - O0 / I11i
    if 83 - 83: OoooooooOO - i1IIi / i1IIi - ooOoO0o + II111iiii
    if 54 - 54: OoOoOO00 * o0oOOo0O0Ooo . OoO0O00
  if ( I1Iii1IIIiiiI == False or Oo0OOoO0oO == False ) :
   packet = ooOoooO . end_of_rlocs ( packet , o0o0Ooo0OO00o . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 53 - 53: oO0o % OoO0O00 / OoO0O00 / I11i * Oo0Ooo
   continue
   if 13 - 13: i1IIi % iIii1I11I1II1 - iII111i - I1IiiI - IiII + iIii1I11I1II1
   if 22 - 22: IiII - OOooOOo + I1ii11iIi11i
   if 64 - 64: OoOoOO00
   if 79 - 79: IiII
   if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
   if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
  if ( IIIiI111I . merge_register_requested ) :
   O0oOoO00O = i1iI11i
   O0oOoO00O . inconsistent_registration = False
   if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
   if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
   if 41 - 41: OoooooooOO + iII111i . OOooOOo
   if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
   if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
   if ( i1iI11i . group . is_null ( ) ) :
    if ( O0oOoO00O . site_id != IIIiI111I . site_id ) :
     O0oOoO00O . site_id = IIIiI111I . site_id
     O0oOoO00O . registered = False
     O0oOoO00O . individual_registrations = { }
     O0oOoO00O . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
     if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
     if 57 - 57: II111iiii % OoO0O00 * i1IIi
   III = IIIiI111I . xtr_id
   if ( III in i1iI11i . individual_registrations ) :
    i1iI11i = i1iI11i . individual_registrations [ III ]
   else :
    i1iI11i = lisp_site_eid ( I1io0oOOooOoo0oO )
    i1iI11i . eid . copy_address ( O0oOoO00O . eid )
    i1iI11i . group . copy_address ( O0oOoO00O . group )
    i1iI11i . encrypt_json = O0oOoO00O . encrypt_json
    O0oOoO00O . individual_registrations [ III ] = i1iI11i
    if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
  else :
   i1iI11i . inconsistent_registration = i1iI11i . merge_register_requested
   if 9 - 9: II111iiii % OoooooooOO
   if 4 - 4: i1IIi * i11iIiiIii % OoooooooOO + OoOoOO00 . oO0o
   if 95 - 95: I1ii11iIi11i * OoOoOO00 % o0oOOo0O0Ooo / O0 + ooOoO0o % OOooOOo
  i1iI11i . map_registers_received += 1
  if 48 - 48: i1IIi + IiII - iIii1I11I1II1 . i11iIiiIii % OOooOOo + I1ii11iIi11i
  if 95 - 95: ooOoO0o + OoOoOO00 . II111iiii + Ii1I
  if 81 - 81: OoooooooOO / OOooOOo / Oo0Ooo
  if 26 - 26: iII111i
  if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
  i1ii1ii11iIi = ( i1iI11i . is_rloc_in_rloc_set ( source ) == False )
  if ( o0o0Ooo0OO00o . record_ttl == 0 and i1ii1ii11iIi ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 6 - 6: IiII
   continue
   if 68 - 68: Oo0Ooo
   if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
   if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
   if 93 - 93: i11iIiiIii
   if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
   if 40 - 40: IiII % IiII
  IiIi11Iii1Ii = i1iI11i . registered_rlocs
  i1iI11i . registered_rlocs = [ ]
  if 35 - 35: OoooooooOO % O0 * I1Ii111 - iIii1I11I1II1 % iII111i
  if 15 - 15: O0 - Ii1I + OoOoOO00
  if 93 - 93: OoO0O00
  if 68 - 68: OOooOOo
  O0O0oOOOoOoo = packet
  for I1I1II1iI in range ( o0o0Ooo0OO00o . rloc_count ) :
   ooOoooO = lisp_rloc_record ( )
   packet = ooOoooO . decode ( packet , None , i1iI11i . encrypt_json )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 82 - 82: Oo0Ooo - oO0o
   ooOoooO . print_record ( "    " )
   if 36 - 36: Oo0Ooo / Oo0Ooo - o0oOOo0O0Ooo - i11iIiiIii
   if 59 - 59: i11iIiiIii / iIii1I11I1II1 / ooOoO0o
   if 2 - 2: iII111i + II111iiii
   if 88 - 88: i1IIi - iII111i / OOooOOo / i1IIi
   if ( len ( I1io0oOOooOoo0oO . allowed_rlocs ) > 0 ) :
    O0O0 = ooOoooO . rloc . print_address ( )
    if ( O0O0 not in I1io0oOOooOoo0oO . allowed_rlocs ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( O0O0 , False ) ) )
     if 48 - 48: iII111i / OoooooooOO / iIii1I11I1II1
     if 41 - 41: II111iiii - II111iiii - OoO0O00 + oO0o * I11i
     i1iI11i . registered = False
     packet = ooOoooO . end_of_rlocs ( packet ,
 o0o0Ooo0OO00o . rloc_count - I1I1II1iI - 1 )
     break
     if 77 - 77: IiII % iIii1I11I1II1 - OOooOOo / I1Ii111 / ooOoO0o . iII111i
     if 62 - 62: I1Ii111
     if 42 - 42: o0oOOo0O0Ooo
     if 59 - 59: I1ii11iIi11i % O0 - i1IIi . Oo0Ooo
     if 18 - 18: II111iiii
     if 31 - 31: Oo0Ooo / Oo0Ooo / iIii1I11I1II1 / I11i % OoooooooOO
   iIIiI11 = lisp_rloc ( )
   iIIiI11 . store_rloc_from_record ( ooOoooO , None , source )
   if 90 - 90: I1IiiI
   if 35 - 35: O0
   if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
   if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
   if 78 - 78: I1IiiI - iIii1I11I1II1
   if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
   if ( source . is_exact_match ( iIIiI11 . rloc ) ) :
    iIIiI11 . map_notify_requested = IIIiI111I . map_notify_requested
    if 85 - 85: I11i + OoOoOO00 * O0 * O0
    if 92 - 92: i11iIiiIii
    if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
    if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
    if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
   i1iI11i . registered_rlocs . append ( iIIiI11 )
   if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
   if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
  iI1oooo = ( i1iI11i . do_rloc_sets_match ( IiIi11Iii1Ii ) == False )
  if 97 - 97: I11i
  if 60 - 60: O0 * iII111i % I1ii11iIi11i
  if 92 - 92: OoOoOO00 / iIii1I11I1II1
  if 67 - 67: i1IIi + i11iIiiIii - i1IIi % OoOoOO00
  if 3 - 3: I1IiiI % ooOoO0o
  if 32 - 32: OOooOOo / i1IIi / OOooOOo
  if ( IIIiI111I . map_register_refresh and iI1oooo and
 i1iI11i . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   i1iI11i . registered_rlocs = IiIi11Iii1Ii
   continue
   if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
   if 45 - 45: Oo0Ooo
   if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
   if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
   if 52 - 52: OOooOOo + OoO0O00
   if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
  if ( i1iI11i . registered == False ) :
   i1iI11i . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 42 - 42: i1IIi
  i1iI11i . last_registered = lisp_get_timestamp ( )
  i1iI11i . registered = ( o0o0Ooo0OO00o . record_ttl != 0 )
  i1iI11i . last_registerer = source
  if 52 - 52: OoO0O00 % iII111i % O0
  if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
  if 50 - 50: oO0o . I1Ii111
  if 38 - 38: iIii1I11I1II1 . Ii1I
  i1iI11i . auth_sha1_or_sha2 = iI1i1I111iI
  i1iI11i . proxy_reply_requested = IIIiI111I . proxy_reply_requested
  i1iI11i . lisp_sec_present = IIIiI111I . lisp_sec_present
  i1iI11i . map_notify_requested = IIIiI111I . map_notify_requested
  i1iI11i . mobile_node_requested = IIIiI111I . mobile_node
  i1iI11i . merge_register_requested = IIIiI111I . merge_register_requested
  if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
  i1iI11i . use_register_ttl_requested = IIIiI111I . use_ttl_for_timeout
  if ( i1iI11i . use_register_ttl_requested ) :
   i1iI11i . register_ttl = o0o0Ooo0OO00o . store_ttl ( )
  else :
   i1iI11i . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 15 - 15: O0
  i1iI11i . xtr_id_present = IIIiI111I . xtr_id_present
  if ( i1iI11i . xtr_id_present ) :
   i1iI11i . xtr_id = IIIiI111I . xtr_id
   i1iI11i . site_id = IIIiI111I . site_id
   if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
   if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
   if 25 - 25: ooOoO0o
   if 33 - 33: Oo0Ooo
   if 11 - 11: I11i
  if ( IIIiI111I . merge_register_requested ) :
   if ( O0oOoO00O . merge_in_site_eid ( i1iI11i ) ) :
    oO0oOOoo0OO0 . append ( [ o0o0Ooo0OO00o . eid , o0o0Ooo0OO00o . group ] )
    if 55 - 55: i11iIiiIii * OoOoOO00 - OoOoOO00 * OoO0O00 / iII111i
   if ( IIIiI111I . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , O0oOoO00O , IIIiI111I ,
 o0o0Ooo0OO00o )
    if 64 - 64: iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
    if 74 - 74: I1IiiI / o0oOOo0O0Ooo
    if 53 - 53: iIii1I11I1II1 * oO0o
  if ( iI1oooo == False ) : continue
  if ( len ( oO0oOOoo0OO0 ) != 0 ) : continue
  if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
  oo0OoO0OoOO0O . append ( i1iI11i . print_eid_tuple ( ) )
  if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
  if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
  if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
  if 60 - 60: oO0o * I1Ii111
  if 81 - 81: oO0o - OOooOOo - oO0o
  if 54 - 54: oO0o % I11i
  if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
  iiiii11i = copy . deepcopy ( o0o0Ooo0OO00o )
  o0o0Ooo0OO00o = o0o0Ooo0OO00o . encode ( )
  o0o0Ooo0OO00o += O0O0oOOOoOoo
  OoO0Oo0 = [ i1iI11i . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
  for iIIiI11 in IiIi11Iii1Ii :
   if ( iIIiI11 . map_notify_requested == False ) : continue
   if ( iIIiI11 . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , o0o0Ooo0OO00o , OoO0Oo0 , 1 , iIIiI11 . rloc ,
 LISP_CTRL_PORT , IIIiI111I . nonce , IIIiI111I . key_id ,
 IIIiI111I . alg_id , IIIiI111I . auth_len , I1io0oOOooOoo0oO , False )
   if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
   if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
   if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
   if 73 - 73: O0 % i11iIiiIii
   if 16 - 16: O0
  lisp_notify_subscribers ( lisp_sockets , iiiii11i , O0O0oOOOoOoo ,
 i1iI11i . eid , I1io0oOOooOoo0oO )
  if 15 - 15: i1IIi % i11iIiiIii
  if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
  if 35 - 35: OoOoOO00 . oO0o / II111iiii
  if 97 - 97: Ii1I + I1Ii111 / II111iiii
  if 14 - 14: iII111i / IiII / oO0o
 if ( len ( oO0oOOoo0OO0 ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , oO0oOOoo0OO0 )
  if 55 - 55: OoO0O00 % O0
  if 92 - 92: OoooooooOO / O0
  if 14 - 14: i11iIiiIii
  if 43 - 43: OOooOOo
  if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
  if 93 - 93: OoOoOO00
 if ( IIIiI111I . merge_register_requested ) : return
 if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
 if 72 - 72: ooOoO0o
 if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
 if 53 - 53: OOooOOo * O0 . iII111i
 if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
 if ( IIIiI111I . map_notify_requested and I1io0oOOooOoo0oO != None ) :
  lisp_build_map_notify ( lisp_sockets , Oo0O0OO , oo0OoO0OoOO0O ,
 IIIiI111I . record_count , source , sport , IIIiI111I . nonce ,
 IIIiI111I . key_id , IIIiI111I . alg_id , IIIiI111I . auth_len ,
 I1io0oOOooOoo0oO , True )
  if 78 - 78: iII111i
 return
 if 80 - 80: i1IIi * I1IiiI + OOooOOo
 if 91 - 91: I1IiiI % OoOoOO00 * Oo0Ooo / I1ii11iIi11i
 if 57 - 57: i11iIiiIii / o0oOOo0O0Ooo . II111iiii
 if 63 - 63: O0
 if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
 if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
 if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
 if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
def lisp_process_unicast_map_notify ( lisp_sockets , packet , source ) :
 i1111 = lisp_map_notify ( "" )
 packet = i1111 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 74 - 74: i11iIiiIii
  if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
 i1111 . print_notify ( )
 if ( i1111 . record_count == 0 ) : return
 if 6 - 6: I11i
 O00o0Oo = i1111 . eid_records
 if 62 - 62: Ii1I
 for iIi1iIIIiIiI in range ( i1111 . record_count ) :
  o0o0Ooo0OO00o = lisp_eid_record ( )
  O00o0Oo = o0o0Ooo0OO00o . decode ( O00o0Oo )
  if ( packet == None ) : return
  o0o0Ooo0OO00o . print_record ( "  " , False )
  i1iiii = o0o0Ooo0OO00o . print_eid_tuple ( )
  if 75 - 75: o0oOOo0O0Ooo * i11iIiiIii - OoooooooOO * OOooOOo
  if 11 - 11: oO0o
  if 14 - 14: OoooooooOO . I1ii11iIi11i % I1IiiI / I1IiiI % Oo0Ooo
  if 97 - 97: i1IIi
  if 6 - 6: Ii1I
  I11iiI1III = lisp_map_cache_lookup ( o0o0Ooo0OO00o . eid , o0o0Ooo0OO00o . eid )
  if ( I11iiI1III == None ) :
   oO0ooOOO = green ( i1iiii , False )
   lprint ( "Ignoring Map-Notify EID {}, no subscribe-request entry" . format ( oO0ooOOO ) )
   if 43 - 43: i1IIi - Ii1I % iIii1I11I1II1 . OoO0O00 + oO0o - iIii1I11I1II1
   continue
   if 17 - 17: IiII . i1IIi
   if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
   if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
   if 43 - 43: I1ii11iIi11i + I11i
   if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
   if 100 - 100: IiII - OoOoOO00 / I11i
   if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
  if ( I11iiI1III . action != LISP_SEND_PUBSUB_ACTION ) :
   if ( I11iiI1III . subscribed_eid == None ) :
    oO0ooOOO = green ( i1iiii , False )
    lprint ( "Ignoring Map-Notify for non-subscribed EID {}" . format ( oO0ooOOO ) )
    if 87 - 87: Oo0Ooo
    continue
    if 65 - 65: ooOoO0o . I1IiiI
    if 51 - 51: IiII
    if 43 - 43: oO0o - I11i . i11iIiiIii
    if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
    if 30 - 30: I1IiiI % oO0o * OoooooooOO
    if 64 - 64: I1IiiI
    if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
    if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
  Iii11i1Ii = [ ]
  if ( I11iiI1III . action == LISP_SEND_PUBSUB_ACTION ) :
   I11iiI1III = lisp_mapping ( o0o0Ooo0OO00o . eid , o0o0Ooo0OO00o . group , [ ] )
   I11iiI1III . add_cache ( )
   o0oOOOOOO0OO = copy . deepcopy ( o0o0Ooo0OO00o . eid )
   OOOo0Oooo = copy . deepcopy ( o0o0Ooo0OO00o . group )
  else :
   o0oOOOOOO0OO = I11iiI1III . subscribed_eid
   OOOo0Oooo = I11iiI1III . subscribed_group
   Iii11i1Ii = I11iiI1III . rloc_set
   I11iiI1III . delete_rlocs_from_rloc_probe_list ( )
   I11iiI1III . rloc_set = [ ]
   if 70 - 70: O0
   if 67 - 67: Ii1I + II111iiii . i1IIi - i11iIiiIii + o0oOOo0O0Ooo
   if 72 - 72: OOooOOo . ooOoO0o / Ii1I / iIii1I11I1II1 - IiII - ooOoO0o
   if 7 - 7: OoOoOO00 + i1IIi % ooOoO0o * I11i + i11iIiiIii / II111iiii
   if 2 - 2: O0 / o0oOOo0O0Ooo - OoO0O00 * II111iiii
  I11iiI1III . mapping_source = None if source == "lisp-itr" else source
  I11iiI1III . map_cache_ttl = o0o0Ooo0OO00o . store_ttl ( )
  I11iiI1III . subscribed_eid = o0oOOOOOO0OO
  I11iiI1III . subscribed_group = OOOo0Oooo
  if 4 - 4: I1IiiI + Oo0Ooo . iIii1I11I1II1
  if 100 - 100: i11iIiiIii
  if 21 - 21: OoOoOO00 + iII111i . OoO0O00
  if 79 - 79: i11iIiiIii - OoO0O00 * OoO0O00 * i1IIi / iIii1I11I1II1 + iII111i
  if 27 - 27: iII111i / Ii1I / iII111i + OoooooooOO - O0 + OoO0O00
  if ( len ( Iii11i1Ii ) != 0 and o0o0Ooo0OO00o . rloc_count == 0 ) :
   I11iiI1III . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , I11iiI1III )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( i1iiii , False ) ) )
   if 62 - 62: iIii1I11I1II1
   continue
   if 60 - 60: Oo0Ooo % IiII % OoO0O00 - i11iIiiIii
   if 53 - 53: i11iIiiIii + OoooooooOO
   if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
   if 79 - 79: II111iiii / OoooooooOO
   if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
   if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
   if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
  I11Ii1I1I1111 = iiI1iIIIi1I1 = 0
  for I1I1II1iI in range ( o0o0Ooo0OO00o . rloc_count ) :
   ooOoooO = lisp_rloc_record ( )
   O00o0Oo = ooOoooO . decode ( O00o0Oo , None )
   ooOoooO . print_record ( "    " )
   if 65 - 65: OoooooooOO % OoooooooOO * o0oOOo0O0Ooo . IiII . o0oOOo0O0Ooo / OOooOOo
   if 72 - 72: OoOoOO00 . Ii1I % IiII . OoOoOO00 - i11iIiiIii % II111iiii
   if 15 - 15: I1ii11iIi11i * Ii1I . o0oOOo0O0Ooo - II111iiii . i11iIiiIii . iIii1I11I1II1
   if 81 - 81: i1IIi * O0 - OOooOOo + i1IIi
   III11i1 = False
   for iiiI1I in Iii11i1Ii :
    if ( iiiI1I . rloc . is_exact_match ( ooOoooO . rloc ) ) :
     III11i1 = True
     break
     if 4 - 4: iII111i * OoOoOO00 % I11i / OoOoOO00 - I1Ii111 / o0oOOo0O0Ooo
     if 24 - 24: i11iIiiIii % I1IiiI - ooOoO0o . OOooOOo
   if ( III11i1 ) :
    iIIiI11 = copy . deepcopy ( iiiI1I )
    iiI1iIIIi1I1 += 1
   else :
    iIIiI11 = lisp_rloc ( )
    I11Ii1I1I1111 += 1
    if 62 - 62: OoO0O00 * Oo0Ooo . oO0o + OoO0O00
    if 5 - 5: iIii1I11I1II1
    if 14 - 14: iII111i
    if 66 - 66: oO0o % i1IIi % OoooooooOO
    if 58 - 58: OOooOOo
   iIIiI11 . store_rloc_from_record ( ooOoooO , None , I11iiI1III . mapping_source )
   I11iiI1III . rloc_set . append ( iIIiI11 )
   if 89 - 89: iIii1I11I1II1 - i1IIi
   if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
  lprint ( "Update {} map-cache entry with {}/{} new/replaced RLOCs" . format ( green ( i1iiii , False ) , I11Ii1I1I1111 , iiI1iIIIi1I1 ) )
  if 9 - 9: I1Ii111 / II111iiii * I1Ii111 / I11i - OoO0O00
  if 36 - 36: IiII . OoOoOO00 . Ii1I
  if 31 - 31: iIii1I11I1II1
  if 84 - 84: I1ii11iIi11i - iII111i * I1IiiI
  if 88 - 88: OOooOOo / Oo0Ooo
  I11iiI1III . build_best_rloc_set ( )
  lisp_write_ipc_map_cache ( True , I11iiI1III )
  if 31 - 31: II111iiii
  if 32 - 32: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 67 - 67: IiII + oO0o * IiII
  if 26 - 26: I1ii11iIi11i + i1IIi . i1IIi - oO0o + I1IiiI * o0oOOo0O0Ooo
  if 62 - 62: ooOoO0o + ooOoO0o % I11i
  if 100 - 100: II111iiii . OoooooooOO
 oO00000oOO = lisp_get_map_server ( source )
 if ( oO00000oOO == None ) :
  lprint ( "Cannot find Map-Server for Map-Notify source address {}" . format ( source . print_address_no_iid ( ) ) )
  if 32 - 32: I11i % OOooOOo * O0 / iIii1I11I1II1 / i1IIi
  return
  if 87 - 87: OoO0O00 . I1ii11iIi11i * I1IiiI
 lisp_send_map_notify_ack ( lisp_sockets , O00o0Oo , i1111 , oO00000oOO )
 if 83 - 83: OOooOOo
 if 86 - 86: I1Ii111 / oO0o
 if 67 - 67: OoOoOO00 + Oo0Ooo / i11iIiiIii . I1IiiI
 if 53 - 53: Oo0Ooo + IiII * ooOoO0o % OoooooooOO * oO0o . iII111i
 if 78 - 78: O0 . Ii1I - I1ii11iIi11i
 if 69 - 69: O0 % O0 . oO0o * OoooooooOO
 if 13 - 13: i1IIi % oO0o . OoooooooOO + I1ii11iIi11i - OOooOOo
 if 99 - 99: OoooooooOO % OOooOOo / I11i
 if 77 - 77: II111iiii - IiII % OOooOOo
 if 22 - 22: OoooooooOO / oO0o
def lisp_process_multicast_map_notify ( packet , source ) :
 i1111 = lisp_map_notify ( "" )
 packet = i1111 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
  if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
 i1111 . print_notify ( )
 if ( i1111 . record_count == 0 ) : return
 if 12 - 12: I1Ii111
 O00o0Oo = i1111 . eid_records
 if 17 - 17: I1Ii111 % oO0o + O0
 for iIi1iIIIiIiI in range ( i1111 . record_count ) :
  o0o0Ooo0OO00o = lisp_eid_record ( )
  O00o0Oo = o0o0Ooo0OO00o . decode ( O00o0Oo )
  if ( packet == None ) : return
  o0o0Ooo0OO00o . print_record ( "  " , False )
  if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
  if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
  if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
  if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
  I11iiI1III = lisp_map_cache_lookup ( o0o0Ooo0OO00o . eid , o0o0Ooo0OO00o . group )
  if ( I11iiI1III == None ) :
   iIiI1III , Oo0OoO00O , ii1I1I1iII = lisp_allow_gleaning ( o0o0Ooo0OO00o . eid , o0o0Ooo0OO00o . group ,
 None )
   if ( iIiI1III == False ) : continue
   if 86 - 86: Ii1I - o0oOOo0O0Ooo % iII111i
   I11iiI1III = lisp_mapping ( o0o0Ooo0OO00o . eid , o0o0Ooo0OO00o . group , [ ] )
   I11iiI1III . add_cache ( )
   if 37 - 37: Oo0Ooo
   if 87 - 87: I1ii11iIi11i . OoooooooOO . ooOoO0o + iIii1I11I1II1 + O0 % I1ii11iIi11i
   if 53 - 53: IiII
   if 96 - 96: Oo0Ooo . i11iIiiIii / Ii1I . I1ii11iIi11i % I1Ii111
   if 68 - 68: ooOoO0o
   if 58 - 58: iII111i * I1IiiI
   if 82 - 82: Oo0Ooo / OoO0O00 % Oo0Ooo . ooOoO0o * O0
  if ( I11iiI1III . gleaned ) :
   lprint ( "Ignore Map-Notify for gleaned {}" . format ( green ( I11iiI1III . print_eid_tuple ( ) , False ) ) )
   if 39 - 39: I1Ii111 * IiII
   continue
   if 16 - 16: ooOoO0o + OoO0O00 / I11i * OoO0O00 . Oo0Ooo % OoOoOO00
   if 65 - 65: Oo0Ooo / I1Ii111 % II111iiii % Ii1I
  I11iiI1III . mapping_source = None if source == "lisp-etr" else source
  I11iiI1III . map_cache_ttl = o0o0Ooo0OO00o . store_ttl ( )
  if 70 - 70: II111iiii % Oo0Ooo * oO0o
  if 54 - 54: O0 / ooOoO0o * I1Ii111
  if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
  if 13 - 13: IiII + Oo0Ooo - I1Ii111
  if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
  if ( len ( I11iiI1III . rloc_set ) != 0 and o0o0Ooo0OO00o . rloc_count == 0 ) :
   I11iiI1III . rloc_set = [ ]
   I11iiI1III . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , I11iiI1III )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( I11iiI1III . print_eid_tuple ( ) , False ) ) )
   if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
   continue
   if 95 - 95: oO0o / Ii1I + OoO0O00
   if 57 - 57: iIii1I11I1II1 + I1Ii111 % oO0o - Ii1I . I1IiiI
  iIi11Ii = I11iiI1III . rtrs_in_rloc_set ( )
  if 70 - 70: oO0o - iII111i + Ii1I * Ii1I / o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 41 - 41: I1Ii111 % Oo0Ooo - iIii1I11I1II1
  if 96 - 96: I1Ii111 / II111iiii . oO0o + oO0o
  if 62 - 62: I1IiiI
  if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
  for I1I1II1iI in range ( o0o0Ooo0OO00o . rloc_count ) :
   ooOoooO = lisp_rloc_record ( )
   O00o0Oo = ooOoooO . decode ( O00o0Oo , None )
   ooOoooO . print_record ( "    " )
   if ( o0o0Ooo0OO00o . group . is_null ( ) ) : continue
   if ( ooOoooO . rle == None ) : continue
   if 49 - 49: iII111i + I11i . Oo0Ooo
   if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
   if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
   if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
   if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
   IIIii1i = I11iiI1III . rloc_set [ 0 ] . stats if len ( I11iiI1III . rloc_set ) != 0 else None
   if 2 - 2: OOooOOo - II111iiii + i11iIiiIii
   if 69 - 69: o0oOOo0O0Ooo
   if 14 - 14: Oo0Ooo % O0 % O0 . o0oOOo0O0Ooo
   if 34 - 34: i11iIiiIii + O0
   iIIiI11 = lisp_rloc ( )
   iIIiI11 . store_rloc_from_record ( ooOoooO , None , I11iiI1III . mapping_source )
   if ( IIIii1i != None ) : iIIiI11 . stats = copy . deepcopy ( IIIii1i )
   if 3 - 3: iIii1I11I1II1
   if ( iIi11Ii and iIIiI11 . is_rtr ( ) == False ) : continue
   if 15 - 15: Oo0Ooo / IiII % i11iIiiIii * I11i . iIii1I11I1II1
   I11iiI1III . rloc_set = [ iIIiI11 ]
   I11iiI1III . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , I11iiI1III )
   if 97 - 97: I1Ii111
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( I11iiI1III . print_eid_tuple ( ) , False ) ,
   # Oo0Ooo . II111iiii / i11iIiiIii - Oo0Ooo
 iIIiI11 . rle . print_rle ( False , True ) ) )
   if 47 - 47: iII111i * ooOoO0o . I1IiiI / O0
   if 81 - 81: iII111i + I11i - I1ii11iIi11i + iIii1I11I1II1 / ooOoO0o
 return
 if 60 - 60: iIii1I11I1II1 - OoO0O00
 if 11 - 11: IiII + I1IiiI . Ii1I * I1IiiI - OoooooooOO . II111iiii
 if 74 - 74: o0oOOo0O0Ooo . iIii1I11I1II1 * Ii1I / O0 - I1Ii111 % oO0o
 if 98 - 98: IiII
 if 30 - 30: iIii1I11I1II1 - ooOoO0o / iIii1I11I1II1 / I1IiiI + OoOoOO00 - iIii1I11I1II1
 if 69 - 69: i11iIiiIii . O0
 if 21 - 21: i1IIi . OoO0O00 % I11i + II111iiii % o0oOOo0O0Ooo
 if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 i1111 = lisp_map_notify ( "" )
 Oo00oo = i1111 . decode ( orig_packet )
 if ( Oo00oo == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 44 - 44: I1ii11iIi11i
  if 39 - 39: iII111i + Oo0Ooo / oO0o
 i1111 . print_notify ( )
 if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
 if 99 - 99: I1IiiI * II111iiii
 if 84 - 84: II111iiii - I1IiiI
 if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
 if 35 - 35: I11i + i1IIi
 I111 = source . print_address ( )
 if ( i1111 . alg_id != 0 or i1111 . auth_len != 0 ) :
  oO00000oOO = None
  for III in lisp_map_servers_list :
   if ( III . find ( I111 ) == - 1 ) : continue
   oO00000oOO = lisp_map_servers_list [ III ]
   if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
  if ( oO00000oOO == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( I111 ) )
   if 97 - 97: oO0o % iIii1I11I1II1
   return
   if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
   if 16 - 16: I1IiiI
  oO00000oOO . map_notifies_received += 1
  if 39 - 39: ooOoO0o * II111iiii
  I1Iii1IIIiiiI = lisp_verify_auth ( Oo00oo , i1111 . alg_id ,
 i1111 . auth_data , oO00000oOO . password )
  if 90 - 90: OoooooooOO * ooOoO0o
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if I1Iii1IIIiiiI else "failed" ) )
  if 14 - 14: I1IiiI % i1IIi
  if ( I1Iii1IIIiiiI == False ) : return
 else :
  oO00000oOO = lisp_ms ( I111 , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 35 - 35: ooOoO0o % o0oOOo0O0Ooo % ooOoO0o
  if 77 - 77: OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
  if 55 - 55: i1IIi
  if 64 - 64: oO0o . OOooOOo * i11iIiiIii + I1Ii111
  if 88 - 88: O0
  if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
 O00o0Oo = i1111 . eid_records
 if ( i1111 . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , O00o0Oo , i1111 , oO00000oOO )
  return
  if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
  if 90 - 90: i11iIiiIii - iII111i * oO0o
  if 79 - 79: IiII
  if 38 - 38: I1Ii111
  if 56 - 56: i11iIiiIii
  if 58 - 58: i11iIiiIii / OoOoOO00
  if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
  if 39 - 39: Oo0Ooo . OoO0O00
 o0o0Ooo0OO00o = lisp_eid_record ( )
 Oo00oo = o0o0Ooo0OO00o . decode ( O00o0Oo )
 if ( Oo00oo == None ) : return
 if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
 o0o0Ooo0OO00o . print_record ( "  " , False )
 if 100 - 100: ooOoO0o / OoooooooOO
 for I1I1II1iI in range ( o0o0Ooo0OO00o . rloc_count ) :
  ooOoooO = lisp_rloc_record ( )
  Oo00oo = ooOoooO . decode ( Oo00oo , None )
  if ( Oo00oo == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 73 - 73: i11iIiiIii - Oo0Ooo
  ooOoooO . print_record ( "    " )
  if 100 - 100: iIii1I11I1II1 + I1Ii111
  if 51 - 51: o0oOOo0O0Ooo * I11i
  if 42 - 42: OOooOOo % I11i
  if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
  if 81 - 81: I1IiiI
 if ( o0o0Ooo0OO00o . group . is_null ( ) == False ) :
  if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
  if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
  if 83 - 83: iII111i - I1ii11iIi11i + iII111i
  if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
  if 60 - 60: I1ii11iIi11i / I1Ii111 % i11iIiiIii % oO0o % I1IiiI . Oo0Ooo
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( o0o0Ooo0OO00o . print_eid_tuple ( ) , False ) ) )
  if 20 - 20: IiII - OOooOOo + OoOoOO00
  if 83 - 83: OoooooooOO / I1IiiI + iII111i - iIii1I11I1II1 % ooOoO0o
  OO = lisp_control_packet_ipc ( orig_packet , I111 , "lisp-itr" , 0 )
  lisp_ipc ( OO , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 74 - 74: OoO0O00
  if 13 - 13: I1ii11iIi11i / OoO0O00
  if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
  if 94 - 94: IiII * i1IIi
  if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
 lisp_send_map_notify_ack ( lisp_sockets , O00o0Oo , i1111 , oO00000oOO )
 return
 if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
 if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
 if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
 if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
 if 32 - 32: I1IiiI + II111iiii * iII111i + O0 / O0 * Oo0Ooo
 if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
 if 66 - 66: i1IIi
 if 98 - 98: Oo0Ooo / iIii1I11I1II1
def lisp_process_map_notify_ack ( packet , source ) :
 i1111 = lisp_map_notify ( "" )
 packet = i1111 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 33 - 33: O0 - iII111i
  if 40 - 40: iII111i * I11i
 i1111 . print_notify ( )
 if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
 if 87 - 87: OoOoOO00
 if 30 - 30: IiII % OoOoOO00 + I1Ii111
 if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
 if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
 if ( i1111 . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 87 - 87: I11i
  if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
 o0o0Ooo0OO00o = lisp_eid_record ( )
 if 72 - 72: OoO0O00 * Oo0Ooo - IiII
 if ( o0o0Ooo0OO00o . decode ( i1111 . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 74 - 74: Ii1I
 o0o0Ooo0OO00o . print_record ( "  " , False )
 if 26 - 26: I11i . O0
 i1iiii = o0o0Ooo0OO00o . print_eid_tuple ( )
 if 68 - 68: Ii1I
 if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
 if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
 if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
 if ( i1111 . alg_id != LISP_NONE_ALG_ID and i1111 . auth_len != 0 ) :
  i1iI11i = lisp_sites_by_eid . lookup_cache ( o0o0Ooo0OO00o . eid , True )
  if ( i1iI11i == None ) :
   oo0oO0Oo = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( oo0oO0Oo , green ( i1iiii , False ) ) )
   if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
   return
   if 44 - 44: I11i * iIii1I11I1II1 . I1ii11iIi11i
  I1io0oOOooOoo0oO = i1iI11i . site
  if 9 - 9: o0oOOo0O0Ooo
  if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
  if 21 - 21: Ii1I * OoOoOO00
  if 29 - 29: iIii1I11I1II1 / ooOoO0o
  I1io0oOOooOoo0oO . map_notify_acks_received += 1
  if 75 - 75: OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
  IiII11iI1 = i1111 . key_id
  if ( IiII11iI1 in I1io0oOOooOoo0oO . auth_key ) :
   I1Ii1II1I11II = I1io0oOOooOoo0oO . auth_key [ IiII11iI1 ]
  else :
   I1Ii1II1I11II = ""
   if 88 - 88: OoO0O00 % Ii1I
   if 12 - 12: OoooooooOO . O0
  I1Iii1IIIiiiI = lisp_verify_auth ( packet , i1111 . alg_id ,
 i1111 . auth_data , I1Ii1II1I11II )
  if 33 - 33: OoooooooOO / I11i . II111iiii * i1IIi
  IiII11iI1 = "key-id {}" . format ( IiII11iI1 ) if IiII11iI1 == i1111 . key_id else "bad key-id {}" . format ( i1111 . key_id )
  if 34 - 34: i11iIiiIii / OoOoOO00
  if 100 - 100: o0oOOo0O0Ooo - I1IiiI / I11i
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if I1Iii1IIIiiiI else "failed" , IiII11iI1 ) )
  if 43 - 43: o0oOOo0O0Ooo % iIii1I11I1II1
  if ( I1Iii1IIIiiiI == False ) : return
  if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
  if 4 - 4: Ii1I . i1IIi + Oo0Ooo % I11i . OoO0O00
  if 70 - 70: OOooOOo * OoOoOO00 / OoOoOO00 / OoOoOO00
  if 23 - 23: I1IiiI
  if 24 - 24: I1Ii111 * i1IIi % O0 * Ii1I + iII111i
 if ( i1111 . retransmit_timer ) : i1111 . retransmit_timer . cancel ( )
 if 14 - 14: oO0o * iII111i + Ii1I + Ii1I * IiII
 IiIi = source . print_address ( )
 III = i1111 . nonce_key
 if 82 - 82: IiII * ooOoO0o / OOooOOo + OoOoOO00
 if ( III in lisp_map_notify_queue ) :
  i1111 = lisp_map_notify_queue . pop ( III )
  if ( i1111 . retransmit_timer ) : i1111 . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( III ) )
  if 32 - 32: IiII
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( i1111 . nonce_key , red ( IiIi , False ) ) )
  if 90 - 90: I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
  if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
 return
 if 96 - 96: O0
 if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
 if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
 if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
 if 61 - 61: IiII . O0
 if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
 if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
 if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
 if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
 if 32 - 32: OoO0O00 + OOooOOo . OoO0O00 - Oo0Ooo
 if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
 iiiIIi1I1I1 = False
 if ( group . is_null ( ) == False ) :
  iiiIIi1I1I1 = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 86 - 86: OOooOOo / OoooooooOO - IiII
 if ( iiiIIi1I1I1 == False ) :
  iiiIIi1I1I1 = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 56 - 56: I1ii11iIi11i - i1IIi * OoooooooOO * O0 * I1IiiI - I1Ii111
  if 32 - 32: OoooooooOO . OOooOOo . OoO0O00 . IiII / I11i % i1IIi
 if ( iiiIIi1I1I1 ) :
  o0oo0OO0oO = lisp_print_eid_tuple ( eid , group )
  Ii1II1iiI1I = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 93 - 93: II111iiii % I1Ii111 . O0 - OoOoOO00 % OoOoOO00
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( o0oo0OO0oO , False ) , s ,
  # O0 % I1IiiI
 Ii1II1iiI1I ) )
  if 9 - 9: i11iIiiIii + OOooOOo * OoO0O00
 return ( iiiIIi1I1I1 )
 if 9 - 9: OOooOOo
 if 67 - 67: Oo0Ooo / I1Ii111 . ooOoO0o % oO0o / Oo0Ooo
 if 49 - 49: ooOoO0o + I1IiiI
 if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
 if 13 - 13: I1ii11iIi11i
 if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
 if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
 iiIII111I111 = lisp_map_referral ( )
 packet = iiIII111I111 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
 iiIII111I111 . print_map_referral ( )
 if 18 - 18: OoooooooOO - I1ii11iIi11i
 I111 = source . print_address ( )
 o0Oo0o = iiIII111I111 . nonce
 if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
 if 79 - 79: OOooOOo + Oo0Ooo
 if 33 - 33: iIii1I11I1II1
 if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
 for iIi1iIIIiIiI in range ( iiIII111I111 . record_count ) :
  o0o0Ooo0OO00o = lisp_eid_record ( )
  packet = o0o0Ooo0OO00o . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
  o0o0Ooo0OO00o . print_record ( "  " , True )
  if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
  if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
  if 99 - 99: OOooOOo
  if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
  III = str ( o0Oo0o )
  if ( III not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( o0Oo0o ) , I111 ) )
   if 53 - 53: oO0o / i1IIi - Oo0Ooo - i1IIi + IiII
   if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
   continue
   if 56 - 56: Oo0Ooo % I1ii11iIi11i
  iii1i = lisp_ddt_map_requestQ [ III ]
  if ( iii1i == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( o0Oo0o ) , I111 ) )
   if 53 - 53: OoO0O00 . I11i - ooOoO0o
   continue
   if 11 - 11: I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
   if 74 - 74: oO0o . I1Ii111 . II111iiii
   if 92 - 92: I1Ii111 % OoooooooOO * I1Ii111
   if 78 - 78: Oo0Ooo . I11i . oO0o + O0 / O0
   if 41 - 41: iII111i * OoO0O00 - OoO0O00
   if 72 - 72: o0oOOo0O0Ooo + oO0o . I1ii11iIi11i + OoO0O00 / I1Ii111
  if ( lisp_map_referral_loop ( iii1i , o0o0Ooo0OO00o . eid , o0o0Ooo0OO00o . group ,
 o0o0Ooo0OO00o . action , I111 ) ) :
   iii1i . dequeue_map_request ( )
   continue
   if 58 - 58: Oo0Ooo / II111iiii % OoooooooOO % II111iiii
   if 39 - 39: i1IIi
  iii1i . last_cached_prefix [ 0 ] = o0o0Ooo0OO00o . eid
  iii1i . last_cached_prefix [ 1 ] = o0o0Ooo0OO00o . group
  if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
  if 59 - 59: i1IIi
  if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
  if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
  iII11 = False
  oooo0o0o00o = lisp_referral_cache_lookup ( o0o0Ooo0OO00o . eid , o0o0Ooo0OO00o . group ,
 True )
  if ( oooo0o0o00o == None ) :
   iII11 = True
   oooo0o0o00o = lisp_referral ( )
   oooo0o0o00o . eid = o0o0Ooo0OO00o . eid
   oooo0o0o00o . group = o0o0Ooo0OO00o . group
   if ( o0o0Ooo0OO00o . ddt_incomplete == False ) : oooo0o0o00o . add_cache ( )
  elif ( oooo0o0o00o . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( oooo0o0o00o . print_eid_tuple ( ) , False ) ) )
   if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
   iii1i . dequeue_map_request ( )
   continue
   if 71 - 71: OOooOOo
   if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
  oOoO0OooO0O = o0o0Ooo0OO00o . action
  oooo0o0o00o . referral_source = source
  oooo0o0o00o . referral_type = oOoO0OooO0O
  O0O00O = o0o0Ooo0OO00o . store_ttl ( )
  oooo0o0o00o . referral_ttl = O0O00O
  oooo0o0o00o . expires = lisp_set_timestamp ( O0O00O )
  if 73 - 73: iII111i / I1IiiI * ooOoO0o
  if 85 - 85: I11i + I11i + oO0o - OoOoOO00
  if 15 - 15: OoO0O00
  if 88 - 88: Ii1I % i1IIi / I1Ii111
  i11o00O0OO = oooo0o0o00o . is_referral_negative ( )
  if ( I111 in oooo0o0o00o . referral_set ) :
   oooO00ooo00 = oooo0o0o00o . referral_set [ I111 ]
   if 86 - 86: iIii1I11I1II1 * IiII + I1ii11iIi11i + I1Ii111 . o0oOOo0O0Ooo
   if ( oooO00ooo00 . updown == False and i11o00O0OO == False ) :
    oooO00ooo00 . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( I111 ) )
    if 88 - 88: ooOoO0o
   elif ( oooO00ooo00 . updown == True and i11o00O0OO == True ) :
    oooO00ooo00 . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( I111 ) )
    if 4 - 4: i11iIiiIii . Ii1I - oO0o
    if 9 - 9: I1Ii111 - i1IIi * I1ii11iIi11i
    if 67 - 67: II111iiii * OoO0O00 + OoooooooOO / I11i . oO0o - II111iiii
    if 9 - 9: I1ii11iIi11i % I1Ii111 - I1ii11iIi11i + i1IIi
    if 6 - 6: I1ii11iIi11i / i11iIiiIii - I11i . OOooOOo
    if 44 - 44: iII111i . i1IIi % I1Ii111
    if 66 - 66: iIii1I11I1II1
    if 86 - 86: o0oOOo0O0Ooo % iIii1I11I1II1
  iIoooO00O0 = { }
  for III in oooo0o0o00o . referral_set : iIoooO00O0 [ III ] = None
  if 89 - 89: ooOoO0o - Ii1I / OoooooooOO
  if 29 - 29: Oo0Ooo . IiII / I1ii11iIi11i
  if 19 - 19: O0
  if 66 - 66: I11i
  for iIi1iIIIiIiI in range ( o0o0Ooo0OO00o . rloc_count ) :
   ooOoooO = lisp_rloc_record ( )
   packet = ooOoooO . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 55 - 55: OoO0O00 - I1Ii111 / ooOoO0o . i11iIiiIii / IiII
   ooOoooO . print_record ( "    " )
   if 55 - 55: ooOoO0o + oO0o + OoOoOO00 / O0 * II111iiii * OoOoOO00
   if 53 - 53: Oo0Ooo
   if 16 - 16: Ii1I
   if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
   O0O0 = ooOoooO . rloc . print_address ( )
   if ( O0O0 not in oooo0o0o00o . referral_set ) :
    oooO00ooo00 = lisp_referral_node ( )
    oooO00ooo00 . referral_address . copy_address ( ooOoooO . rloc )
    oooo0o0o00o . referral_set [ O0O0 ] = oooO00ooo00
    if ( I111 == O0O0 and i11o00O0OO ) : oooO00ooo00 . updown = False
   else :
    oooO00ooo00 = oooo0o0o00o . referral_set [ O0O0 ]
    if ( O0O0 in iIoooO00O0 ) : iIoooO00O0 . pop ( O0O0 )
    if 78 - 78: OoO0O00 + oO0o
   oooO00ooo00 . priority = ooOoooO . priority
   oooO00ooo00 . weight = ooOoooO . weight
   if 86 - 86: ooOoO0o . ooOoO0o + oO0o
   if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
   if 31 - 31: IiII + iII111i
   if 5 - 5: O0 * Ii1I
   if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
  for III in iIoooO00O0 : oooo0o0o00o . referral_set . pop ( III )
  if 77 - 77: OOooOOo / OoooooooOO
  i1iiii = oooo0o0o00o . print_eid_tuple ( )
  if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
  if ( iII11 ) :
   if ( o0o0Ooo0OO00o . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( i1iiii , False ) ) )
    if 79 - 79: i11iIiiIii % o0oOOo0O0Ooo * II111iiii . i1IIi * Ii1I - i11iIiiIii
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( i1iiii , False ) , o0o0Ooo0OO00o . rloc_count ) )
    if 31 - 31: IiII / o0oOOo0O0Ooo
    if 27 - 27: Oo0Ooo
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( i1iiii , False ) , o0o0Ooo0OO00o . rloc_count ) )
   if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
   if 35 - 35: o0oOOo0O0Ooo % iII111i / O0 * I1IiiI . o0oOOo0O0Ooo / OOooOOo
   if 81 - 81: I1ii11iIi11i - i11iIiiIii
   if 49 - 49: iII111i * I11i - II111iiii . o0oOOo0O0Ooo
   if 52 - 52: Ii1I + Ii1I - II111iiii . O0 + I1ii11iIi11i
   if 60 - 60: i11iIiiIii + IiII
  if ( oOoO0OooO0O == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( iii1i . lisp_sockets , oooo0o0o00o . eid ,
 oooo0o0o00o . group , iii1i . nonce , iii1i . itr , iii1i . sport , 15 , None , False )
   iii1i . dequeue_map_request ( )
   if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
   if 86 - 86: Ii1I / oO0o
  if ( oOoO0OooO0O == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( iii1i . tried_root ) :
    lisp_send_negative_map_reply ( iii1i . lisp_sockets , oooo0o0o00o . eid ,
 oooo0o0o00o . group , iii1i . nonce , iii1i . itr , iii1i . sport , 0 , None , False )
    iii1i . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( iii1i , True )
    if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
    if 60 - 60: II111iiii / Ii1I
    if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
  if ( oOoO0OooO0O == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( I111 in oooo0o0o00o . referral_set ) :
    oooO00ooo00 = oooo0o0o00o . referral_set [ I111 ]
    oooO00ooo00 . updown = False
    if 89 - 89: i1IIi / I1Ii111 + Ii1I - i1IIi
   if ( len ( oooo0o0o00o . referral_set ) == 0 ) :
    iii1i . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( iii1i , False )
    if 66 - 66: OoooooooOO
    if 68 - 68: iII111i + I1Ii111
    if 90 - 90: o0oOOo0O0Ooo
  if ( oOoO0OooO0O in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( iii1i . eid . is_exact_match ( o0o0Ooo0OO00o . eid ) ) :
    if ( not iii1i . tried_root ) :
     lisp_send_ddt_map_request ( iii1i , True )
    else :
     lisp_send_negative_map_reply ( iii1i . lisp_sockets ,
 oooo0o0o00o . eid , oooo0o0o00o . group , iii1i . nonce , iii1i . itr ,
 iii1i . sport , 15 , None , False )
     iii1i . dequeue_map_request ( )
     if 48 - 48: iII111i + Ii1I
   else :
    lisp_send_ddt_map_request ( iii1i , False )
    if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
    if 89 - 89: OOooOOo - I1Ii111 - iII111i
    if 67 - 67: oO0o
  if ( oOoO0OooO0O == LISP_DDT_ACTION_MS_ACK ) : iii1i . dequeue_map_request ( )
  if 76 - 76: I1IiiI % I1IiiI - IiII / OoOoOO00 / I1ii11iIi11i
 return
 if 42 - 42: I1IiiI + I1ii11iIi11i + Oo0Ooo * i1IIi - II111iiii
 if 15 - 15: o0oOOo0O0Ooo
 if 60 - 60: I1ii11iIi11i / I1Ii111
 if 13 - 13: I1Ii111
 if 52 - 52: II111iiii / OoO0O00 . Ii1I
 if 68 - 68: iII111i
 if 67 - 67: I1IiiI * I1IiiI
 if 100 - 100: iII111i * iII111i . Oo0Ooo
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 III1iI1III1I1 = lisp_ecm ( 0 )
 packet = III1iI1III1I1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 10 - 10: Oo0Ooo % ooOoO0o * Oo0Ooo
  if 48 - 48: ooOoO0o + II111iiii
 III1iI1III1I1 . print_ecm ( )
 if 73 - 73: II111iiii
 IiIii1iIIII = lisp_control_header ( )
 if ( IiIii1iIIII . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
  if 35 - 35: II111iiii + IiII
 oO0Oo0oO00O = IiIii1iIIII . type
 del ( IiIii1iIIII )
 if 54 - 54: IiII - Oo0Ooo
 if ( oO0Oo0oO00O != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 55 - 55: I11i * OOooOOo * I1ii11iIi11i . i11iIiiIii
  if 93 - 93: Oo0Ooo % i11iIiiIii / i11iIiiIii . II111iiii % I11i
  if 13 - 13: O0 . i1IIi - OoooooooOO . oO0o
  if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
  if 21 - 21: i11iIiiIii + II111iiii - i1IIi / OoooooooOO * OOooOOo % Oo0Ooo
 o000O000o0O = III1iI1III1I1 . udp_sport
 iIIi1iiii1ii = time . time ( )
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 III1iI1III1I1 . source , o000O000o0O , III1iI1III1I1 . ddt , - 1 , iIIi1iiii1ii )
 return
 if 62 - 62: O0 . O0 + i11iIiiIii
 if 57 - 57: II111iiii . I1IiiI . OOooOOo / IiII . II111iiii
 if 80 - 80: I11i * OoO0O00 + ooOoO0o % ooOoO0o
 if 16 - 16: iII111i / i11iIiiIii + iIii1I11I1II1
 if 76 - 76: OoooooooOO / Oo0Ooo / I1Ii111 + OoooooooOO
 if 65 - 65: Oo0Ooo - I1Ii111
 if 57 - 57: O0
 if 49 - 49: I1ii11iIi11i / OoOoOO00 - I1IiiI + iII111i . OOooOOo % oO0o
 if 34 - 34: OoO0O00 - I1IiiI + OoOoOO00
 if 22 - 22: iIii1I11I1II1 . i1IIi . OOooOOo % Oo0Ooo - i1IIi
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 78 - 78: I1IiiI / i1IIi % II111iiii % I1IiiI % Ii1I
 if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
 if 38 - 38: IiII . I1Ii111
 if 69 - 69: ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + Ii1I . ooOoO0o
 if 73 - 73: I11i % I11i . ooOoO0o + OoOoOO00
 if 33 - 33: i11iIiiIii . i11iIiiIii * i11iIiiIii / iIii1I11I1II1 / I1ii11iIi11i . ooOoO0o
 if 11 - 11: iII111i
 IIi11ii = ms . map_server
 if ( lisp_decent_push_configured and IIi11ii . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  IIi11ii = copy . deepcopy ( IIi11ii )
  IIi11ii . address = 0x7f000001
  I11 = bold ( "Bootstrap" , False )
  Oo = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( I11 , Oo ) )
  if 60 - 60: I1ii11iIi11i / I1Ii111
  if 10 - 10: OoO0O00 * iIii1I11I1II1 / I11i % II111iiii . OoOoOO00 / I1IiiI
  if 4 - 4: Oo0Ooo * o0oOOo0O0Ooo
  if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
  if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
  if 69 - 69: iII111i % I1ii11iIi11i
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 19 - 19: IiII
 if 35 - 35: OoOoOO00
 if 18 - 18: II111iiii . OoOoOO00 + I1ii11iIi11i * oO0o + OoooooooOO
 if 39 - 39: I1IiiI * ooOoO0o / i11iIiiIii - oO0o - oO0o + O0
 if 73 - 73: OOooOOo
 if 44 - 44: I1ii11iIi11i * i1IIi - iIii1I11I1II1 - oO0o - oO0o * II111iiii
 if ( ms . ekey != None ) :
  iiIio0o0 = ms . ekey . zfill ( 32 )
  OoOooO = "0" * 8
  iiIi = chacha . ChaCha ( iiIio0o0 , OoOooO , 20 ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + iiIi
  oO0ooOOO = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( oO0ooOOO , ms . ekey_id ) )
  if 98 - 98: Oo0Ooo + ooOoO0o / OOooOOo . iIii1I11I1II1 . I1IiiI . OoOoOO00
  if 92 - 92: i1IIi + OoOoOO00 * i1IIi / IiII
 IIIII1I11ii = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  IIIII1I11ii = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 39 - 39: OOooOOo . IiII + I1IiiI % iII111i - oO0o / OoO0O00
  if 37 - 37: O0 % OoO0O00 + i11iIiiIii . O0 / OOooOOo
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( IIi11ii . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , IIIII1I11ii ) )
 if 15 - 15: I1ii11iIi11i + oO0o
 lisp_send ( lisp_sockets , IIi11ii , LISP_CTRL_PORT , packet )
 return
 if 99 - 99: oO0o - ooOoO0o - II111iiii * OoooooooOO / O0
 if 57 - 57: iIii1I11I1II1 / IiII + OoO0O00 * oO0o + Ii1I
 if 76 - 76: i11iIiiIii . OOooOOo / I11i * oO0o % iIii1I11I1II1 . ooOoO0o
 if 75 - 75: O0 + I1IiiI
 if 67 - 67: OoOoOO00 % OoooooooOO / OoO0O00 - OoO0O00 / O0
 if 19 - 19: iIii1I11I1II1 / OOooOOo % I11i % I1IiiI / I1ii11iIi11i
 if 73 - 73: II111iiii
 if 26 - 26: II111iiii . iIii1I11I1II1 - I1Ii111 % OOooOOo
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 O0oo0OoO0oo = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 83 - 83: OOooOOo + OoooooooOO % I1Ii111 % IiII + i11iIiiIii
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 10 - 10: OoooooooOO . Ii1I % I1Ii111 + IiII
 if 78 - 78: OoOoOO00 - oO0o . I1ii11iIi11i * i11iIiiIii
 packet = lisp_control_packet_ipc ( packet , O0oo0OoO0oo , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 44 - 44: iIii1I11I1II1 * iII111i
 if 32 - 32: OoOoOO00
 if 65 - 65: iIii1I11I1II1 + iII111i
 if 90 - 90: i11iIiiIii - Oo0Ooo
 if 31 - 31: OoOoOO00 + OoOoOO00 + OoooooooOO % O0
 if 14 - 14: i1IIi / OoooooooOO . I1IiiI * I1Ii111 + OoO0O00
 if 45 - 45: OoooooooOO * I1Ii111
 if 7 - 7: O0
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 42 - 42: o0oOOo0O0Ooo / Ii1I
 if 31 - 31: OOooOOo
 if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
 if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
 if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
 if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
 if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
 if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 65 - 65: I1IiiI . ooOoO0o
 if 51 - 51: I1Ii111
 if 89 - 89: Oo0Ooo
 if 15 - 15: OOooOOo * II111iiii - OOooOOo * iIii1I11I1II1
 if 95 - 95: I1Ii111 / OoooooooOO * I11i * OoooooooOO
 if 88 - 88: I1IiiI / Oo0Ooo / oO0o + oO0o % OOooOOo + Oo0Ooo
 if 63 - 63: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo % iIii1I11I1II1 / I1ii11iIi11i - iII111i
 if 72 - 72: iII111i % oO0o . IiII + I1ii11iIi11i . IiII . II111iiii
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 10 - 10: I11i . ooOoO0o + I11i * Ii1I
 if 55 - 55: OOooOOo / iII111i + OoooooooOO - OoooooooOO
 if 51 - 51: O0 % Ii1I % Oo0Ooo - O0
 if 94 - 94: OoooooooOO - ooOoO0o % I1ii11iIi11i + I1Ii111
 if 51 - 51: I1ii11iIi11i . iII111i / i1IIi * ooOoO0o % I11i
 if 82 - 82: O0 % OoOoOO00 . iII111i . i1IIi . iII111i - Oo0Ooo
 if 58 - 58: O0 * OOooOOo
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 60 - 60: ooOoO0o
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 47 - 47: i11iIiiIii
  if 21 - 21: i1IIi - oO0o - Oo0Ooo
  if 11 - 11: i1IIi
  if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
  if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
  if 56 - 56: Ii1I . iII111i
 if ( lisp_nat_traversal ) :
  oooooO0oO0ooO = lisp_get_any_translated_port ( )
  if ( oooooO0oO0ooO != None ) : inner_sport = oooooO0oO0ooO
  if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
 III1iI1III1I1 = lisp_ecm ( inner_sport )
 if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
 III1iI1III1I1 . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 III1iI1III1I1 . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 III1iI1III1I1 . ddt = ddt
 ooIiii = III1iI1III1I1 . encode ( packet , inner_source , inner_dest )
 if ( ooIiii == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 71 - 71: ooOoO0o
 III1iI1III1I1 . print_ecm ( )
 if 71 - 71: i1IIi - oO0o / ooOoO0o * Ii1I
 packet = ooIiii + packet
 if 28 - 28: II111iiii . IiII / iII111i + I1ii11iIi11i - ooOoO0o * iIii1I11I1II1
 O0O0 = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( O0O0 ) )
 IIi11ii = lisp_convert_4to6 ( O0O0 )
 lisp_send ( lisp_sockets , IIi11ii , LISP_CTRL_PORT , packet )
 return
 if 53 - 53: Ii1I - Ii1I . Oo0Ooo . OOooOOo / OoooooooOO + iII111i
 if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
 if 20 - 20: I1Ii111
 if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
 if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
 if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
 if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
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
if 56 - 56: iII111i * II111iiii . OoooooooOO . I11i
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 25 - 25: ooOoO0o % o0oOOo0O0Ooo - i11iIiiIii
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 79 - 79: iII111i - I1IiiI % O0 / Oo0Ooo + OoOoOO00 . Oo0Ooo
if 59 - 59: I1ii11iIi11i * OoOoOO00 / Ii1I
if 80 - 80: IiII - ooOoO0o / OoOoOO00 / I11i * O0 + oO0o
if 77 - 77: ooOoO0o + I1ii11iIi11i * o0oOOo0O0Ooo / i1IIi * I11i
if 70 - 70: oO0o / iII111i * i1IIi / II111iiii / OoOoOO00 + oO0o
if 30 - 30: i1IIi - iII111i - i11iIiiIii . OoOoOO00 . o0oOOo0O0Ooo
if 74 - 74: i11iIiiIii / II111iiii
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 62 - 62: O0
if 63 - 63: Oo0Ooo + Oo0Ooo
if 48 - 48: Oo0Ooo * I1ii11iIi11i % II111iiii
if 42 - 42: I1Ii111 - ooOoO0o % o0oOOo0O0Ooo * I1IiiI . o0oOOo0O0Ooo
if 84 - 84: iIii1I11I1II1
if 39 - 39: Ii1I . II111iiii / I1IiiI
def byte_swap_64 ( address ) :
 IiI = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 44 - 44: Ii1I / Ii1I / OoO0O00 % ooOoO0o / I11i . I1ii11iIi11i
 if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
 if 81 - 81: I1Ii111 % OoO0O00 / O0
 if 55 - 55: i1IIi - I1Ii111 + I11i
 if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
 if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
 if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
 if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
 return ( IiI )
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
class lisp_cache_entries ( object ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 34 - 34: OoooooooOO / iII111i / O0
  if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
  if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
class lisp_cache ( object ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
  if 40 - 40: OOooOOo - OoooooooOO
 def cache_size ( self ) :
  return ( self . cache_count )
  if 36 - 36: i1IIi % OoOoOO00 - i1IIi
  if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   iiii11I1 = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   iiii11I1 = prefix . mask_len
  else :
   iiii11I1 = prefix . mask_len + 48
   if 97 - 97: I11i . ooOoO0o
   if 87 - 87: oO0o / iIii1I11I1II1 - I11i + OoooooooOO
  oooo = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  i1I1iiiI = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 79 - 79: I1ii11iIi11i * IiII . I1ii11iIi11i
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    i1iIii = prefix . addr_length ( ) * 2
    IiI = lisp_hex_string ( prefix . address ) . zfill ( i1iIii )
   else :
    IiI = prefix . address
    if 65 - 65: iII111i - Ii1I - II111iiii * O0 + I1ii11iIi11i . iIii1I11I1II1
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   i1I1iiiI = "8003"
   IiI = prefix . address . print_geo ( )
  else :
   i1I1iiiI = ""
   IiI = ""
   if 76 - 76: OoO0O00 * ooOoO0o
   if 32 - 32: O0 . oO0o * o0oOOo0O0Ooo . Ii1I + IiII
  III = oooo + i1I1iiiI + IiI
  return ( [ iiii11I1 , III ] )
  if 98 - 98: iII111i . II111iiii % O0
  if 43 - 43: OOooOOo % I1Ii111 . IiII % OoO0O00 + I1Ii111 % OoooooooOO
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  iiii11I1 , III = self . build_key ( prefix )
  if ( iiii11I1 not in self . cache ) :
   self . cache [ iiii11I1 ] = lisp_cache_entries ( )
   self . cache_sorted = self . sort_in_entry ( self . cache_sorted , iiii11I1 )
   if 17 - 17: OoooooooOO - i1IIi * I11i
  if ( III not in self . cache [ iiii11I1 ] . entries ) :
   self . cache_count += 1
   if 33 - 33: i1IIi . Oo0Ooo + I11i
  self . cache [ iiii11I1 ] . entries [ III ] = entry
  if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
  if 78 - 78: I1Ii111 + I1Ii111
 def lookup_cache ( self , prefix , exact ) :
  i1IIiii1IiIII , III = self . build_key ( prefix )
  if ( exact ) :
   if ( i1IIiii1IiIII not in self . cache ) : return ( None )
   if ( III not in self . cache [ i1IIiii1IiIII ] . entries ) : return ( None )
   return ( self . cache [ i1IIiii1IiIII ] . entries [ III ] )
   if 56 - 56: OoOoOO00
   if 36 - 36: OoO0O00 * I1IiiI + o0oOOo0O0Ooo % II111iiii + OOooOOo . OoooooooOO
  III11i1 = None
  for iiii11I1 in self . cache_sorted :
   if ( i1IIiii1IiIII < iiii11I1 ) : return ( III11i1 )
   for oo0O00OOOOO in list ( self . cache [ iiii11I1 ] . entries . values ( ) ) :
    if ( prefix . is_more_specific ( oo0O00OOOOO . eid ) ) :
     if ( III11i1 == None or
 oo0O00OOOOO . eid . is_more_specific ( III11i1 . eid ) ) : III11i1 = oo0O00OOOOO
     if 14 - 14: o0oOOo0O0Ooo / OOooOOo . ooOoO0o % O0
     if 35 - 35: ooOoO0o - i1IIi
     if 11 - 11: Oo0Ooo + oO0o / I1ii11iIi11i / OoOoOO00
  return ( III11i1 )
  if 49 - 49: Ii1I * I1ii11iIi11i
  if 66 - 66: ooOoO0o
 def delete_cache ( self , prefix ) :
  iiii11I1 , III = self . build_key ( prefix )
  if ( iiii11I1 not in self . cache ) : return
  if ( III not in self . cache [ iiii11I1 ] . entries ) : return
  self . cache [ iiii11I1 ] . entries . pop ( III )
  self . cache_count -= 1
  if 2 - 2: o0oOOo0O0Ooo
  if 86 - 86: OoooooooOO * I1ii11iIi11i + O0 + o0oOOo0O0Ooo + OOooOOo % OoO0O00
 def walk_cache ( self , function , parms ) :
  for iiii11I1 in self . cache_sorted :
   for oo0O00OOOOO in list ( self . cache [ iiii11I1 ] . entries . values ( ) ) :
    o0o0O0O0Oooo0 , parms = function ( oo0O00OOOOO , parms )
    if ( o0o0O0O0Oooo0 == False ) : return ( parms )
    if 34 - 34: I1IiiI + i1IIi . II111iiii . O0
    if 86 - 86: oO0o . OoOoOO00 - I11i . OOooOOo % OoO0O00
  return ( parms )
  if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
  if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
 def sort_in_entry ( self , table , value ) :
  if ( table == [ ] ) : return ( [ value ] )
  if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
  IIiIIiiiiI = table
  while ( True ) :
   if ( len ( IIiIIiiiiI ) == 1 ) :
    if ( value == IIiIIiiiiI [ 0 ] ) : return ( table )
    OOOooo0OooOoO = table . index ( IIiIIiiiiI [ 0 ] )
    if ( value < IIiIIiiiiI [ 0 ] ) :
     return ( table [ 0 : OOOooo0OooOoO ] + [ value ] + table [ OOOooo0OooOoO : : ] )
     if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
    if ( value > IIiIIiiiiI [ 0 ] ) :
     return ( table [ 0 : OOOooo0OooOoO + 1 ] + [ value ] + table [ OOOooo0OooOoO + 1 : : ] )
     if 9 - 9: iIii1I11I1II1
     if 75 - 75: I11i . II111iiii * I1IiiI * IiII
   OOOooo0OooOoO = old_div ( len ( IIiIIiiiiI ) , 2 )
   IIiIIiiiiI = IIiIIiiiiI [ 0 : OOOooo0OooOoO ] if ( value < IIiIIiiiiI [ OOOooo0OooOoO ] ) else IIiIIiiiiI [ OOOooo0OooOoO : : ]
   if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
   if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
  return ( [ ] )
  if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
  if 34 - 34: iIii1I11I1II1
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 65 - 65: II111iiii - iII111i / o0oOOo0O0Ooo
  for iiii11I1 in self . cache_sorted :
   for III in self . cache [ iiii11I1 ] . entries :
    oo0O00OOOOO = self . cache [ iiii11I1 ] . entries [ III ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( iiii11I1 , III ,
 oo0O00OOOOO ) )
    if 35 - 35: i11iIiiIii - Oo0Ooo . I1ii11iIi11i % OoOoOO00
    if 20 - 20: OoO0O00
    if 93 - 93: ooOoO0o + o0oOOo0O0Ooo - I1ii11iIi11i
    if 56 - 56: Ii1I / Oo0Ooo
    if 96 - 96: o0oOOo0O0Ooo . II111iiii
    if 14 - 14: OoooooooOO - i1IIi / i11iIiiIii - OOooOOo - i11iIiiIii . ooOoO0o
    if 8 - 8: oO0o * O0 - II111iiii + I1IiiI
    if 85 - 85: OoooooooOO % i11iIiiIii / IiII % OoOoOO00 + O0
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 6 - 6: OoooooooOO
if 97 - 97: II111iiii + o0oOOo0O0Ooo * II111iiii
if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
if 14 - 14: OOooOOo * IiII
def lisp_map_cache_lookup ( source , dest ) :
 if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
 II1OO0Oo0oOOO000 = dest . is_multicast_address ( )
 if 33 - 33: OoO0O00
 if 91 - 91: I11i % I11i % iII111i
 if 19 - 19: I11i / I11i + I1IiiI * OoO0O00 - iII111i . Oo0Ooo
 if 76 - 76: iII111i % OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % i1IIi
 I11iiI1III = lisp_map_cache . lookup_cache ( dest , False )
 if ( I11iiI1III == None ) :
  i1iiii = source . print_sg ( dest ) if II1OO0Oo0oOOO000 else dest . print_address ( )
  i1iiii = green ( i1iiii , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( i1iiii ) )
  return ( None )
  if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
  if 38 - 38: OoOoOO00 % OoooooooOO . oO0o - OoooooooOO + I11i
  if 18 - 18: OoooooooOO + ooOoO0o * OoOoOO00 - OoO0O00
  if 42 - 42: oO0o % OoOoOO00 - oO0o + I11i / i11iIiiIii
  if 74 - 74: OoO0O00 - II111iiii - ooOoO0o % i1IIi
 if ( II1OO0Oo0oOOO000 == False ) :
  IiIIIIi11ii = green ( I11iiI1III . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , IiIIIIi11ii ) )
  if 42 - 42: i11iIiiIii / O0
  return ( I11iiI1III )
  if 8 - 8: I1Ii111
  if 51 - 51: i11iIiiIii
  if 1 - 1: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i
  if 58 - 58: i11iIiiIii * i11iIiiIii - OoO0O00
  if 8 - 8: i11iIiiIii * OoOoOO00 . o0oOOo0O0Ooo
 I11iiI1III = I11iiI1III . lookup_source_cache ( source , False )
 if ( I11iiI1III == None ) :
  i1iiii = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( i1iiii ) )
  return ( None )
  if 27 - 27: I1ii11iIi11i + Ii1I % I1Ii111
  if 20 - 20: Oo0Ooo
  if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
  if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
  if 84 - 84: OOooOOo
 IiIIIIi11ii = green ( I11iiI1III . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , IiIIIIi11ii ) )
 if 68 - 68: I1Ii111
 return ( I11iiI1III )
 if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
 if 54 - 54: oO0o + I11i - OoO0O00
 if 86 - 86: OoooooooOO
 if 51 - 51: i11iIiiIii
 if 91 - 91: OOooOOo
 if 22 - 22: OoooooooOO + OoOoOO00 - Ii1I . iII111i / OoooooooOO / I1IiiI
 if 73 - 73: i1IIi - Ii1I + oO0o * iIii1I11I1II1
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  O0oO0 = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( O0oO0 )
  if 100 - 100: i11iIiiIii / iIii1I11I1II1 + Oo0Ooo + OoO0O00 - iII111i
  if 8 - 8: i11iIiiIii . O0 + o0oOOo0O0Ooo * oO0o + II111iiii
  if 61 - 61: ooOoO0o / ooOoO0o
  if 51 - 51: iIii1I11I1II1 / oO0o * I1Ii111 + i1IIi
  if 96 - 96: Oo0Ooo + oO0o - Oo0Ooo - OoOoOO00 % OOooOOo . iIii1I11I1II1
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 93 - 93: iIii1I11I1II1 % OoooooooOO
 if 6 - 6: II111iiii / oO0o - OOooOOo . O0 - o0oOOo0O0Ooo
 if 72 - 72: iIii1I11I1II1 / OoooooooOO * ooOoO0o / ooOoO0o % O0 + IiII
 if 96 - 96: iII111i / i11iIiiIii + Oo0Ooo . I1IiiI + iII111i % OoOoOO00
 if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
 if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
 O0oO0 = lisp_referral_cache . lookup_cache ( group , exact )
 if ( O0oO0 == None ) : return ( None )
 if 87 - 87: iII111i
 o000oOoO = O0oO0 . lookup_source_cache ( eid , exact )
 if ( o000oOoO ) : return ( o000oOoO )
 if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
 if ( exact ) : O0oO0 = None
 return ( O0oO0 )
 if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
 if 44 - 44: II111iiii / I1ii11iIi11i
 if 39 - 39: OoooooooOO % OoO0O00
 if 83 - 83: OOooOOo % I1IiiI + O0 % OoooooooOO
 if 84 - 84: I11i - Oo0Ooo % ooOoO0o - II111iiii
 if 29 - 29: IiII
 if 4 - 4: II111iiii * o0oOOo0O0Ooo - IiII * iII111i
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  o0O0o0OOOoO = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( o0O0o0OOOoO )
  if 91 - 91: I1Ii111 * iII111i * OoO0O00
  if 79 - 79: iII111i + oO0o
  if 19 - 19: I1Ii111 - OOooOOo . ooOoO0o . O0 + II111iiii . OoooooooOO
  if 97 - 97: O0 / OoOoOO00 / ooOoO0o
  if 11 - 11: II111iiii . i11iIiiIii - Ii1I . IiII
 if ( eid . is_null ( ) ) : return ( None )
 if 10 - 10: OOooOOo * OoooooooOO
 if 12 - 12: II111iiii - O0 . i1IIi % oO0o % OoooooooOO
 if 36 - 36: IiII * OoOoOO00 - iIii1I11I1II1 + II111iiii
 if 65 - 65: I1IiiI * I11i . I1Ii111 % I1ii11iIi11i + O0
 if 91 - 91: OoooooooOO % I1Ii111 * OoO0O00 - OoOoOO00
 if 5 - 5: iIii1I11I1II1 * I11i - oO0o % oO0o % o0oOOo0O0Ooo . i1IIi
 o0O0o0OOOoO = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( o0O0o0OOOoO == None ) : return ( None )
 if 95 - 95: Oo0Ooo * I1ii11iIi11i + iII111i - o0oOOo0O0Ooo - Oo0Ooo . OoO0O00
 oOOo0OOo00 = o0O0o0OOOoO . lookup_source_cache ( eid , exact )
 if ( oOOo0OOo00 ) : return ( oOOo0OOo00 )
 if 43 - 43: I1Ii111 + I1Ii111 % Oo0Ooo % OoO0O00 - ooOoO0o
 if ( exact ) : o0O0o0OOOoO = None
 return ( o0O0o0OOOoO )
 if 61 - 61: OoOoOO00 + Ii1I % i11iIiiIii - I1IiiI * OoO0O00 % iIii1I11I1II1
 if 66 - 66: iII111i + i1IIi
 if 24 - 24: O0 / OoooooooOO - OoOoOO00
 if 51 - 51: OoO0O00 + o0oOOo0O0Ooo - II111iiii * I11i + Ii1I
 if 16 - 16: I1Ii111 * i1IIi . I1IiiI . OOooOOo % Ii1I - o0oOOo0O0Ooo
 if 89 - 89: Ii1I * I1ii11iIi11i * I1IiiI % iII111i % Ii1I + O0
 if 53 - 53: i11iIiiIii % I1ii11iIi11i
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 59 - 59: OOooOOo
 if ( group . is_null ( ) ) :
  i1iI11i = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( i1iI11i )
  if 61 - 61: OoooooooOO + O0 - i1IIi % oO0o / I1ii11iIi11i
  if 50 - 50: oO0o + II111iiii * OoOoOO00 % OoO0O00 . II111iiii % o0oOOo0O0Ooo
  if 32 - 32: i1IIi / Ii1I + i11iIiiIii % oO0o
  if 11 - 11: Ii1I - ooOoO0o % i11iIiiIii / OoooooooOO - O0 - IiII
  if 25 - 25: IiII + O0 + oO0o % iIii1I11I1II1 - II111iiii . I1IiiI
 if ( eid . is_null ( ) ) : return ( None )
 if 62 - 62: IiII . O0 + oO0o - ooOoO0o * iIii1I11I1II1
 if 8 - 8: I1ii11iIi11i
 if 65 - 65: i11iIiiIii
 if 92 - 92: oO0o * II111iiii + I1Ii111
 if 49 - 49: II111iiii * I1IiiI * O0 / ooOoO0o * IiII
 if 94 - 94: OoO0O00 - I1IiiI * oO0o
 i1iI11i = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( i1iI11i == None ) : return ( None )
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
 if 36 - 36: IiII % I11i
 if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
 OoiIii11i11i = i1iI11i . lookup_source_cache ( eid , exact )
 if ( OoiIii11i11i ) : return ( OoiIii11i11i )
 if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
 if ( exact ) :
  i1iI11i = None
 else :
  O0oOoO00O = i1iI11i . parent_for_more_specifics
  if ( O0oOoO00O and O0oOoO00O . accept_more_specifics ) :
   if ( group . is_more_specific ( O0oOoO00O . group ) ) : i1iI11i = O0oOoO00O
   if 82 - 82: OoooooooOO
   if 14 - 14: OoO0O00 / oO0o - OOooOOo
 return ( i1iI11i )
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
 if 12 - 12: iIii1I11I1II1 % OoO0O00 * Oo0Ooo
 if 5 - 5: I11i - II111iiii * iIii1I11I1II1 / iIii1I11I1II1 % IiII * i1IIi
 if 30 - 30: i1IIi % I1IiiI . OOooOOo % iIii1I11I1II1 . I1ii11iIi11i / o0oOOo0O0Ooo
 if 53 - 53: OOooOOo % ooOoO0o
 if 94 - 94: OOooOOo - O0 - I1Ii111 / OoooooooOO - iII111i
class lisp_address ( object ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 83 - 83: OOooOOo * I1ii11iIi11i * iII111i * I1ii11iIi11i . OoO0O00
  if 87 - 87: ooOoO0o . O0 - oO0o
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 75 - 75: Oo0Ooo
  if 22 - 22: oO0o * I1Ii111 . II111iiii / Ii1I * O0
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 33 - 33: oO0o * i1IIi + ooOoO0o * OOooOOo - O0 - iIii1I11I1II1
  if 35 - 35: I1Ii111
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 12 - 12: Ii1I % I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 12 - 12: Oo0Ooo + I1IiiI
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 12 - 12: OoOoOO00 / II111iiii
   if 100 - 100: I1ii11iIi11i % iIii1I11I1II1 . IiII . OoooooooOO / II111iiii
   if 28 - 28: I1IiiI
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 27 - 27: I1IiiI % oO0o - iIii1I11I1II1 - o0oOOo0O0Ooo - IiII - O0
  if 46 - 46: II111iiii
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  IiI = self . address
  if ( ( ( IiI & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( IiI & 0xff000000 ) >> 24 ) == 172 ) :
   IiIiI1IIi1Ii = ( IiI & 0x00ff0000 ) >> 16
   if ( IiIiI1IIi1Ii >= 16 and IiIiI1IIi1Ii <= 31 ) : return ( True )
   if 5 - 5: i11iIiiIii . OoO0O00 - oO0o - OoooooooOO % IiII * O0
  if ( ( ( IiI & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 48 - 48: Ii1I / Ii1I / i1IIi * I1IiiI . iII111i + I1ii11iIi11i
  if 66 - 66: iIii1I11I1II1 . iIii1I11I1II1 + I1ii11iIi11i
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 45 - 45: iII111i . oO0o * iII111i
  if 3 - 3: OoOoOO00 / Oo0Ooo - Oo0Ooo
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 54 - 54: Oo0Ooo . OoO0O00 * I1IiiI % IiII
  return ( 0 )
  if 97 - 97: o0oOOo0O0Ooo + Ii1I
  if 77 - 77: I11i - oO0o . Ii1I
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  IiI = self . address >> 96
  return ( IiI == 0x20010005 )
  if 75 - 75: I11i * OoooooooOO % OoOoOO00 . i1IIi - Ii1I + iIii1I11I1II1
  if 74 - 74: ooOoO0o
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
   if 18 - 18: iIii1I11I1II1 - I11i - oO0o
  return ( 0 )
  if 12 - 12: O0 + O0 + ooOoO0o . I1IiiI * II111iiii
  if 47 - 47: i11iIiiIii % OOooOOo / ooOoO0o . IiII - I1IiiI
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 10 - 10: Oo0Ooo / ooOoO0o / I1ii11iIi11i
  if 98 - 98: O0 - I1Ii111 - i11iIiiIii
 def packet_format ( self ) :
  if 85 - 85: II111iiii - I1ii11iIi11i % I1IiiI . I1IiiI - OoooooooOO - I11i
  if 38 - 38: i1IIi + oO0o * ooOoO0o % Ii1I % ooOoO0o
  if 80 - 80: OoO0O00 + OoOoOO00 % iII111i % OoooooooOO - ooOoO0o
  if 25 - 25: OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - Oo0Ooo . O0
  if 48 - 48: I1IiiI + oO0o % i11iIiiIii % iIii1I11I1II1
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 14 - 14: iIii1I11I1II1
  if 78 - 78: I1Ii111 / Oo0Ooo - I1Ii111
 def pack_address ( self ) :
  iiII1iiI = self . packet_format ( )
  Oo00oo = b""
  if ( self . is_ipv4 ( ) ) :
   Oo00oo = struct . pack ( iiII1iiI , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   IiIiI = byte_swap_64 ( self . address >> 64 )
   iI1Ii11 = byte_swap_64 ( self . address & 0xffffffffffffffff )
   Oo00oo = struct . pack ( iiII1iiI , IiIiI , iI1Ii11 )
  elif ( self . is_mac ( ) ) :
   IiI = self . address
   IiIiI = ( IiI >> 32 ) & 0xffff
   iI1Ii11 = ( IiI >> 16 ) & 0xffff
   iI1II1i1I = IiI & 0xffff
   Oo00oo = struct . pack ( iiII1iiI , IiIiI , iI1Ii11 , iI1II1i1I )
  elif ( self . is_e164 ( ) ) :
   IiI = self . address
   IiIiI = ( IiI >> 32 ) & 0xffffffff
   iI1Ii11 = ( IiI & 0xffffffff )
   Oo00oo = struct . pack ( iiII1iiI , IiIiI , iI1Ii11 )
  elif ( self . is_dist_name ( ) ) :
   Oo00oo += ( self . address + "\0" ) . encode ( )
   if 19 - 19: iIii1I11I1II1 / iII111i + OOooOOo . ooOoO0o
  return ( Oo00oo )
  if 85 - 85: i1IIi
  if 78 - 78: oO0o
 def unpack_address ( self , packet ) :
  iiII1iiI = self . packet_format ( )
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 6 - 6: IiII
  IiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 69 - 69: iII111i
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( IiI [ 0 ] )
   if 87 - 87: i11iIiiIii % o0oOOo0O0Ooo + Ii1I
  elif ( self . is_ipv6 ( ) ) :
   if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
   if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
   if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
   if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
   if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
   if 90 - 90: II111iiii + OOooOOo % I1Ii111 * iIii1I11I1II1 % iIii1I11I1II1
   if 55 - 55: II111iiii % O0 * O0 - II111iiii * I1IiiI % Oo0Ooo
   if 48 - 48: I1ii11iIi11i + OoooooooOO % i1IIi
   if ( IiI [ 0 ] <= 0xffff and ( IiI [ 0 ] & 0xff ) == 0 ) :
    i1iiI11 = ( IiI [ 0 ] << 48 ) << 64
   else :
    i1iiI11 = byte_swap_64 ( IiI [ 0 ] ) << 64
    if 13 - 13: Oo0Ooo + iII111i * OoooooooOO % i11iIiiIii * II111iiii . OoooooooOO
   I1iO00O = byte_swap_64 ( IiI [ 1 ] )
   self . address = i1iiI11 | I1iO00O
   if 9 - 9: oO0o - O0 . iIii1I11I1II1 . ooOoO0o
  elif ( self . is_mac ( ) ) :
   I1Oo0O = IiI [ 0 ]
   i1i1I111iiIi1 = IiI [ 1 ]
   ooo00OOOoOO = IiI [ 2 ]
   self . address = ( I1Oo0O << 32 ) + ( i1i1I111iiIi1 << 16 ) + ooo00OOOoOO
   if 22 - 22: OoOoOO00 / o0oOOo0O0Ooo % I1Ii111 % i11iIiiIii % I1IiiI
  elif ( self . is_e164 ( ) ) :
   self . address = ( IiI [ 0 ] << 32 ) + IiI [ 1 ]
   if 22 - 22: o0oOOo0O0Ooo - I1Ii111
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   ooo0000oo0 = 0
   if 50 - 50: I11i - OoOoOO00 + I1IiiI % Oo0Ooo / OoooooooOO - I1ii11iIi11i
  packet = packet [ ooo0000oo0 : : ]
  return ( packet )
  if 26 - 26: IiII . Ii1I
  if 35 - 35: I1ii11iIi11i + OOooOOo
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 88 - 88: O0
  if 4 - 4: OoOoOO00 % iIii1I11I1II1 % OoooooooOO . oO0o
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 27 - 27: II111iiii - OoOoOO00
  if 81 - 81: o0oOOo0O0Ooo - Oo0Ooo % IiII - ooOoO0o / O0
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 27 - 27: Oo0Ooo
  if 15 - 15: iIii1I11I1II1 . OoOoOO00 % Ii1I / i1IIi . o0oOOo0O0Ooo
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 45 - 45: iIii1I11I1II1 - i1IIi % I1IiiI - I1Ii111 + oO0o
  if 15 - 15: iIii1I11I1II1 - OoooooooOO / ooOoO0o
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 83 - 83: IiII + I1Ii111 / OoOoOO00 * IiII . oO0o
  if 22 - 22: O0 + ooOoO0o + I1Ii111
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 57 - 57: OOooOOo . ooOoO0o - OoooooooOO - I1ii11iIi11i * O0
  if 85 - 85: I1IiiI * OoO0O00
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 63 - 63: I1IiiI - i11iIiiIii
  if 4 - 4: OOooOOo + iIii1I11I1II1 / I1IiiI * Ii1I
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 64 - 64: OoOoOO00
  if 94 - 94: OOooOOo * OoooooooOO * o0oOOo0O0Ooo / I1Ii111 . II111iiii
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 37 - 37: O0 * II111iiii * I1IiiI - O0 - I11i / i1IIi
  if 27 - 27: i11iIiiIii + iIii1I11I1II1
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 15 - 15: oO0o
  if 69 - 69: II111iiii * O0 . ooOoO0o * IiII
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 25 - 25: I11i - I1ii11iIi11i . I1Ii111 . OoooooooOO
  if 4 - 4: IiII * OoO0O00 % I1ii11iIi11i * Ii1I . iII111i
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 41 - 41: OoooooooOO % I11i . O0 + I1Ii111
  if 67 - 67: OoOoOO00 * OOooOOo / OOooOOo / OoooooooOO
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 67 - 67: I11i - i1IIi . OoooooooOO / iIii1I11I1II1
  if 34 - 34: OoO0O00 * II111iiii
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 43 - 43: OoOoOO00 . I1IiiI
  if 44 - 44: O0 / o0oOOo0O0Ooo
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 19 - 19: I11i
  if 91 - 91: OOooOOo * OoooooooOO
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 89 - 89: i1IIi / iII111i . I1Ii111
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 74 - 74: I1ii11iIi11i % iII111i / OoooooooOO / I1ii11iIi11i % i11iIiiIii % ooOoO0o
  return ( False )
  if 82 - 82: OoooooooOO . o0oOOo0O0Ooo * I1ii11iIi11i % I1ii11iIi11i * Ii1I
  if 83 - 83: I11i - Oo0Ooo + i11iIiiIii - i11iIiiIii
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 64 - 64: IiII % I1IiiI / ooOoO0o
  if 74 - 74: OoooooooOO
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 22 - 22: II111iiii . O0 * I1Ii111 % OoO0O00 / OoooooooOO + I1Ii111
  if 71 - 71: ooOoO0o . oO0o * OoooooooOO + iII111i - I1Ii111 . I1ii11iIi11i
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 100 - 100: I11i + O0 - o0oOOo0O0Ooo * I1ii11iIi11i
  if 94 - 94: Oo0Ooo . IiII / Ii1I / oO0o - I1IiiI
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 77 - 77: i11iIiiIii . Ii1I - Ii1I
  if 47 - 47: iII111i % OOooOOo . I1ii11iIi11i + I1ii11iIi11i . I1Ii111
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 20 - 20: oO0o - o0oOOo0O0Ooo + I1IiiI % OoOoOO00
  if 41 - 41: oO0o . ooOoO0o
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 59 - 59: iIii1I11I1II1 - I1IiiI . ooOoO0o
  if 58 - 58: I1IiiI * I1Ii111 + iII111i + iIii1I11I1II1 + I1IiiI
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 78 - 78: Oo0Ooo + ooOoO0o
  if 56 - 56: OoO0O00 / i1IIi + ooOoO0o . ooOoO0o . iII111i
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 37 - 37: iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoooooooOO + OoO0O00
  if 25 - 25: I1IiiI / IiII . OOooOOo . I1ii11iIi11i % i1IIi
  if 12 - 12: O0 % O0
  if 9 - 9: O0 . I1IiiI + I1ii11iIi11i / OOooOOo * I1ii11iIi11i
  iIi1iIIIiIiI = addr_str . find ( "[" )
  I1I1II1iI = addr_str . find ( "]" )
  if ( iIi1iIIIiIiI != - 1 and I1I1II1iI != - 1 ) :
   self . instance_id = int ( addr_str [ iIi1iIIIiIiI + 1 : I1I1II1iI ] )
   addr_str = addr_str [ I1I1II1iI + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 10 - 10: IiII % o0oOOo0O0Ooo / O0 / II111iiii
    if 81 - 81: Ii1I / o0oOOo0O0Ooo % OoOoOO00 . I1ii11iIi11i
    if 47 - 47: II111iiii + OOooOOo / II111iiii . OOooOOo
    if 68 - 68: OoooooooOO
    if 63 - 63: I1IiiI
    if 80 - 80: oO0o + iIii1I11I1II1
  if ( self . is_ipv4 ( ) ) :
   oOo0000OOo = addr_str . split ( "." )
   oOO0 = int ( oOo0000OOo [ 0 ] ) << 24
   oOO0 += int ( oOo0000OOo [ 1 ] ) << 16
   oOO0 += int ( oOo0000OOo [ 2 ] ) << 8
   oOO0 += int ( oOo0000OOo [ 3 ] )
   self . address = oOO0
  elif ( self . is_ipv6 ( ) ) :
   if 88 - 88: iII111i / I11i / I1ii11iIi11i + IiII * OoooooooOO . IiII
   if 3 - 3: ooOoO0o - Oo0Ooo
   if 86 - 86: I1ii11iIi11i * I1Ii111 / o0oOOo0O0Ooo . OoO0O00
   if 14 - 14: I11i * IiII / iIii1I11I1II1
   if 88 - 88: OoOoOO00 % II111iiii . I1IiiI / oO0o * IiII / i11iIiiIii
   if 76 - 76: o0oOOo0O0Ooo
   if 80 - 80: OOooOOo
   if 15 - 15: OOooOOo . OoOoOO00 / oO0o . I1ii11iIi11i % OoO0O00 - oO0o
   if 21 - 21: ooOoO0o . o0oOOo0O0Ooo . oO0o . i1IIi
   if 96 - 96: Ii1I % I11i * OoooooooOO . I1IiiI . iIii1I11I1II1
   if 8 - 8: O0 + o0oOOo0O0Ooo / O0 - I1ii11iIi11i % I1ii11iIi11i
   if 55 - 55: OoooooooOO * OoooooooOO % I1Ii111 / Ii1I / ooOoO0o
   if 12 - 12: i11iIiiIii + Ii1I % iIii1I11I1II1 + I1Ii111
   if 12 - 12: Ii1I + I1Ii111 / O0 * II111iiii
   if 67 - 67: iIii1I11I1II1 / I11i + ooOoO0o * I1Ii111 * oO0o
   if 100 - 100: OoooooooOO % I1IiiI / OoOoOO00 % OoOoOO00 . o0oOOo0O0Ooo
   if 81 - 81: Ii1I - II111iiii + I11i / Ii1I
   OoOOo0 = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 49 - 49: Oo0Ooo % ooOoO0o % o0oOOo0O0Ooo + ooOoO0o * I1Ii111 % I1IiiI
   addr_str = binascii . hexlify ( addr_str )
   if 85 - 85: i1IIi / i1IIi
   if ( OoOOo0 ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 77 - 77: i1IIi . ooOoO0o % ooOoO0o - Ii1I
   self . address = int ( addr_str , 16 )
   if 6 - 6: OOooOOo % Ii1I + ooOoO0o
  elif ( self . is_geo_prefix ( ) ) :
   Ooo0O00o00 = lisp_geo ( None )
   Ooo0O00o00 . name = "geo-prefix-{}" . format ( Ooo0O00o00 )
   Ooo0O00o00 . parse_geo_string ( addr_str )
   self . address = Ooo0O00o00
  elif ( self . is_mac ( ) ) :
   addr_str = addr_str . replace ( "-" , "" )
   oOO0 = int ( addr_str , 16 )
   self . address = oOO0
  elif ( self . is_e164 ( ) ) :
   addr_str = addr_str [ 1 : : ]
   oOO0 = int ( addr_str , 16 )
   self . address = oOO0 << 4
  elif ( self . is_dist_name ( ) ) :
   self . address = addr_str . replace ( "'" , "" )
   if 17 - 17: iIii1I11I1II1 * I1Ii111 % oO0o + o0oOOo0O0Ooo . Ii1I * Oo0Ooo
  self . mask_len = self . host_mask_len ( )
  if 16 - 16: I1IiiI % OoO0O00 . ooOoO0o / OoooooooOO
  if 8 - 8: I1Ii111 % OoO0O00 . I1IiiI - OoOoOO00 + i1IIi / iIii1I11I1II1
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   OOOooo0OooOoO = prefix_str . find ( "]" )
   OOOoOo0o0Ooo = len ( prefix_str [ OOOooo0OooOoO + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , OOOoOo0o0Ooo = prefix_str . split ( "/" )
  else :
   iIi1I1 = prefix_str . find ( "'" )
   if ( iIi1I1 == - 1 ) : return
   II = prefix_str . find ( "'" , iIi1I1 + 1 )
   if ( II == - 1 ) : return
   OOOoOo0o0Ooo = len ( prefix_str [ iIi1I1 + 1 : II ] ) * 8
   if 89 - 89: II111iiii / Ii1I % Ii1I
   if 57 - 57: I11i
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( OOOoOo0o0Ooo )
  if 95 - 95: OoOoOO00 + I11i * i1IIi - ooOoO0o % ooOoO0o
  if 58 - 58: OOooOOo
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  OoI1111i1 = ( 2 ** self . mask_len ) - 1
  oo00oOo0o0o = self . addr_length ( ) * 8 - self . mask_len
  OoI1111i1 <<= oo00oOo0o0o
  self . address &= OoI1111i1
  if 94 - 94: i11iIiiIii % I1ii11iIi11i % IiII - I1Ii111
  if 55 - 55: I11i - ooOoO0o - iIii1I11I1II1 + I1ii11iIi11i / IiII
 def is_geo_string ( self , addr_str ) :
  OOOooo0OooOoO = addr_str . find ( "]" )
  if ( OOOooo0OooOoO != - 1 ) : addr_str = addr_str [ OOOooo0OooOoO + 1 : : ]
  if 49 - 49: I1ii11iIi11i
  Ooo0O00o00 = addr_str . split ( "/" )
  if ( len ( Ooo0O00o00 ) == 2 ) :
   if ( Ooo0O00o00 [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 91 - 91: OOooOOo % iII111i
  Ooo0O00o00 = Ooo0O00o00 [ 0 ]
  Ooo0O00o00 = Ooo0O00o00 . split ( "-" )
  Iii = len ( Ooo0O00o00 )
  if ( Iii < 8 or Iii > 9 ) : return ( False )
  if 28 - 28: OoO0O00 + i11iIiiIii / i1IIi
  for iIiI in range ( 0 , Iii ) :
   if ( iIiI == 3 ) :
    if ( Ooo0O00o00 [ iIiI ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 70 - 70: iII111i % II111iiii % O0 / O0 - II111iiii . OoooooooOO
   if ( iIiI == 7 ) :
    if ( Ooo0O00o00 [ iIiI ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 78 - 78: OoOoOO00 + i11iIiiIii
   if ( Ooo0O00o00 [ iIiI ] . isdigit ( ) == False ) : return ( False )
   if 11 - 11: OoOoOO00 . I1IiiI + i11iIiiIii * OoooooooOO
  return ( True )
  if 74 - 74: OoooooooOO * iII111i % OOooOOo . OoooooooOO * I11i % I1Ii111
  if 67 - 67: I11i * i1IIi
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 7 - 7: i1IIi * OoOoOO00 . Ii1I
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 80 - 80: OoOoOO00 + o0oOOo0O0Ooo - II111iiii
  if 3 - 3: ooOoO0o * I1Ii111
 def print_address ( self ) :
  IiI = self . print_address_no_iid ( )
  oooo = "[" + str ( self . instance_id )
  for iIi1iIIIiIiI in self . iid_list : oooo += "," + str ( iIi1iIIIiIiI )
  oooo += "]"
  IiI = "{}{}" . format ( oooo , IiI )
  return ( IiI )
  if 34 - 34: Ii1I / Oo0Ooo . II111iiii - ooOoO0o - I1ii11iIi11i % OoOoOO00
  if 43 - 43: Ii1I * oO0o
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   IiI = self . address
   Oo0o0O0 = IiI >> 24
   Oooo00O = ( IiI >> 16 ) & 0xff
   OOoO = ( IiI >> 8 ) & 0xff
   oooOOo0o0ooO = IiI & 0xff
   return ( "{}.{}.{}.{}" . format ( Oo0o0O0 , Oooo00O , OOoO , oooOOo0o0ooO ) )
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
   if 66 - 66: Ii1I * I1Ii111 * OoO0O00
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 92 - 92: II111iiii * iII111i % OoOoOO00 % OoOoOO00 % i11iIiiIii
  if 93 - 93: Ii1I + iIii1I11I1II1 % Ii1I . iIii1I11I1II1
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   IiIiIi11 = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , IiIiIi11 ) )
   if 84 - 84: OoOoOO00 . IiII
  IiI = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( IiI )
  if ( self . is_geo_prefix ( ) ) : return ( IiI )
  if 50 - 50: O0
  OOOooo0OooOoO = IiI . find ( "no-address" )
  if ( OOOooo0OooOoO == - 1 ) :
   IiI = "{}/{}" . format ( IiI , str ( self . mask_len ) )
  else :
   IiI = IiI [ 0 : OOOooo0OooOoO ]
   if 51 - 51: I1Ii111
  return ( IiI )
  if 95 - 95: Ii1I / Ii1I * OoO0O00 . OoooooooOO . OoooooooOO * I11i
  if 76 - 76: OoooooooOO - Ii1I + IiII % OoOoOO00 / OoooooooOO
 def print_prefix_no_iid ( self ) :
  IiI = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( IiI )
  if ( self . is_geo_prefix ( ) ) : return ( IiI )
  return ( "{}/{}" . format ( IiI , str ( self . mask_len ) ) )
  if 55 - 55: i11iIiiIii - IiII * OOooOOo + II111iiii . I1ii11iIi11i / O0
  if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  IiI = self . print_address ( )
  OOOooo0OooOoO = IiI . find ( "]" )
  if ( OOOooo0OooOoO != - 1 ) : IiI = IiI [ OOOooo0OooOoO + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   IiI = IiI . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , IiI ) )
   if 98 - 98: II111iiii - i1IIi - ooOoO0o
  return ( "{}-{}-{}" . format ( self . instance_id , IiI , self . mask_len ) )
  if 36 - 36: IiII + o0oOOo0O0Ooo
  if 81 - 81: OOooOOo / I11i % oO0o + ooOoO0o
 def print_sg ( self , g ) :
  I111 = self . print_prefix ( )
  iIi1i = I111 . find ( "]" ) + 1
  g = g . print_prefix ( )
  oOoO = g . find ( "]" ) + 1
  i1iIiIii = "[{}]({}, {})" . format ( self . instance_id , I111 [ iIi1i : : ] , g [ oOoO : : ] )
  return ( i1iIiIii )
  if 4 - 4: Ii1I - iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
  if 18 - 18: oO0o % iIii1I11I1II1 + ooOoO0o
 def hash_address ( self , addr ) :
  IiIiI = self . address
  iI1Ii11 = addr . address
  if 34 - 34: I1IiiI - OoooooooOO . IiII - OOooOOo % IiII
  if ( self . is_geo_prefix ( ) ) : IiIiI = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : iI1Ii11 = addr . address . print_geo ( )
  if 19 - 19: IiII + I1ii11iIi11i % Oo0Ooo
  if ( type ( IiIiI ) == str ) :
   IiIiI = int ( binascii . hexlify ( IiIiI [ 0 : 1 ] ) )
   if 32 - 32: OOooOOo
  if ( type ( iI1Ii11 ) == str ) :
   iI1Ii11 = int ( binascii . hexlify ( iI1Ii11 [ 0 : 1 ] ) )
   if 46 - 46: II111iiii . OoO0O00
  return ( IiIiI ^ iI1Ii11 )
  if 97 - 97: oO0o
  if 45 - 45: i11iIiiIii / IiII + OoO0O00
  if 55 - 55: Ii1I / II111iiii - oO0o
  if 58 - 58: i1IIi . OoooooooOO % iIii1I11I1II1 * o0oOOo0O0Ooo + O0 / oO0o
  if 77 - 77: I11i . I1ii11iIi11i
  if 92 - 92: i11iIiiIii + I11i % I1IiiI / ooOoO0o
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 28 - 28: i1IIi . I1IiiI
  OOOoOo0o0Ooo = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   II1oo0OOOo = 2 ** ( 32 - OOOoOo0o0Ooo )
   oOoo00o0 = prefix . instance_id
   IiIiIi11 = oOoo00o0 + II1oo0OOOo
   return ( self . instance_id in range ( oOoo00o0 , IiIiIi11 ) )
   if 11 - 11: OoO0O00 / IiII + IiII
   if 4 - 4: Oo0Ooo / O0 * OoO0O00 * Oo0Ooo - Ii1I
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 43 - 43: o0oOOo0O0Ooo
   if 61 - 61: o0oOOo0O0Ooo * IiII / I1ii11iIi11i
   if 67 - 67: iII111i * OoO0O00 + oO0o - iIii1I11I1II1 / Ii1I - o0oOOo0O0Ooo
   if 45 - 45: OoooooooOO % OoOoOO00 / o0oOOo0O0Ooo + I1IiiI
   if 32 - 32: OOooOOo + i11iIiiIii
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   IiI = self . address
   I1IIiIII111 = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    IiI = self . address . print_geo ( )
    I1IIiIII111 = prefix . address . print_geo ( )
    if 86 - 86: ooOoO0o / iII111i . OoooooooOO + I1Ii111 + I1Ii111
   if ( len ( IiI ) < len ( I1IIiIII111 ) ) : return ( False )
   return ( IiI . find ( I1IIiIII111 ) == 0 )
   if 35 - 35: Oo0Ooo + oO0o * o0oOOo0O0Ooo - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii
   if 56 - 56: iIii1I11I1II1 / I11i
   if 78 - 78: i11iIiiIii * OoO0O00 * Ii1I / i1IIi * OOooOOo + o0oOOo0O0Ooo
   if 52 - 52: i1IIi % O0
   if 59 - 59: II111iiii + I1ii11iIi11i / iII111i . ooOoO0o
  if ( self . mask_len < OOOoOo0o0Ooo ) : return ( False )
  if 18 - 18: I1Ii111
  oo00oOo0o0o = ( prefix . addr_length ( ) * 8 ) - OOOoOo0o0Ooo
  OoI1111i1 = ( 2 ** OOOoOo0o0Ooo - 1 ) << oo00oOo0o0o
  return ( ( self . address & OoI1111i1 ) == prefix . address )
  if 40 - 40: OoOoOO00 / OOooOOo + O0
  if 57 - 57: iII111i
 def mask_address ( self , mask_len ) :
  oo00oOo0o0o = ( self . addr_length ( ) * 8 ) - mask_len
  OoI1111i1 = ( 2 ** mask_len - 1 ) << oo00oOo0o0o
  self . address &= OoI1111i1
  if 94 - 94: i11iIiiIii
  if 90 - 90: iII111i + i11iIiiIii + iII111i % I1IiiI % oO0o
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  O0000O = self . print_prefix ( )
  I1iiii1i1II = prefix . print_prefix ( ) if prefix else ""
  return ( O0000O == I1iiii1i1II )
  if 99 - 99: OoOoOO00 . OoOoOO00 * Oo0Ooo + OoooooooOO . Ii1I . OoooooooOO
  if 54 - 54: OOooOOo
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   ooO0oOOoOO = lisp_myrlocs [ 0 ]
   if ( ooO0oOOoOO == None ) : return ( False )
   ooO0oOOoOO = ooO0oOOoOO . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == ooO0oOOoOO )
   if 58 - 58: OoOoOO00 / I1Ii111 % O0
  if ( self . is_ipv6 ( ) ) :
   ooO0oOOoOO = lisp_myrlocs [ 1 ]
   if ( ooO0oOOoOO == None ) : return ( False )
   ooO0oOOoOO = ooO0oOOoOO . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == ooO0oOOoOO )
   if 14 - 14: I1IiiI . OOooOOo
  return ( False )
  if 28 - 28: iII111i / oO0o / iII111i
  if 97 - 97: II111iiii + Oo0Ooo
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid == 0 and mask_len == 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 57 - 57: o0oOOo0O0Ooo % OoooooooOO - oO0o * IiII + OoooooooOO
  self . instance_id = iid
  self . mask_len = mask_len
  if 65 - 65: OoooooooOO + OOooOOo - I1Ii111
  if 78 - 78: Oo0Ooo * OOooOOo + i11iIiiIii
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
  if 15 - 15: I1ii11iIi11i % I1Ii111 . I1ii11iIi11i - iIii1I11I1II1
  if 20 - 20: i1IIi - Ii1I . II111iiii + O0 % oO0o % II111iiii
  if 26 - 26: iIii1I11I1II1 - Ii1I / iIii1I11I1II1 . i1IIi - o0oOOo0O0Ooo
  if 48 - 48: iII111i . i11iIiiIii - iIii1I11I1II1 / iIii1I11I1II1
  if 92 - 92: II111iiii . oO0o - O0 + o0oOOo0O0Ooo * I1ii11iIi11i
  if 32 - 32: I1IiiI % OoO0O00
  if 71 - 71: OoooooooOO . I11i . I1IiiI
  if 27 - 27: i11iIiiIii + Oo0Ooo * I11i / OOooOOo - iII111i
  if 42 - 42: ooOoO0o . II111iiii % OoOoOO00 - I11i
  if 34 - 34: Ii1I % I1Ii111 % I1ii11iIi11i - IiII
  if 89 - 89: IiII
  if 64 - 64: OoOoOO00
  if 3 - 3: i11iIiiIii / I1Ii111
  if 40 - 40: OoooooooOO / o0oOOo0O0Ooo + OoOoOO00
  if 73 - 73: OOooOOo / Oo0Ooo
  if 80 - 80: OoO0O00 + I1IiiI % i1IIi / I11i % i1IIi * i11iIiiIii
  if 27 - 27: OoOoOO00 / I1Ii111 * O0 / I1IiiI - IiII / o0oOOo0O0Ooo
 def lcaf_encode_iid ( self ) :
  ooOoOoOo = LISP_LCAF_INSTANCE_ID_TYPE
  o0ooOo000oo = socket . htons ( self . lcaf_length ( ooOoOoOo ) )
  oooo = self . instance_id
  i1I1iiiI = self . afi
  iiii11I1 = 0
  if ( i1I1iiiI < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    i1I1iiiI = LISP_AFI_LCAF
    iiii11I1 = 0
   else :
    i1I1iiiI = 0
    iiii11I1 = self . mask_len
    if 70 - 70: I1ii11iIi11i
    if 11 - 11: I1Ii111
    if 70 - 70: Ii1I
  iIiI1iiI11i = struct . pack ( "BBBBH" , 0 , 0 , ooOoOoOo , iiii11I1 , o0ooOo000oo )
  iIiI1iiI11i += struct . pack ( "IH" , socket . htonl ( oooo ) , socket . htons ( i1I1iiiI ) )
  if ( i1I1iiiI == 0 ) : return ( iIiI1iiI11i )
  if 53 - 53: o0oOOo0O0Ooo * Oo0Ooo % I1IiiI
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   iIiI1iiI11i = iIiI1iiI11i [ 0 : - 2 ]
   iIiI1iiI11i += self . address . encode_geo ( )
   return ( iIiI1iiI11i )
   if 68 - 68: Oo0Ooo
   if 85 - 85: OoOoOO00 - OoO0O00 + Ii1I
  iIiI1iiI11i += self . pack_address ( )
  return ( iIiI1iiI11i )
  if 30 - 30: OoOoOO00 - O0 + iII111i / OoO0O00 . oO0o + iIii1I11I1II1
  if 19 - 19: Oo0Ooo . IiII - o0oOOo0O0Ooo / II111iiii . O0 - II111iiii
 def lcaf_decode_iid ( self , packet ) :
  iiII1iiI = "BBBBH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 75 - 75: OOooOOo % OoOoOO00 + iIii1I11I1II1 - II111iiii / i1IIi
  Oo0OoO00O , ii1I1I1iII , ooOoOoOo , I111II , i1iIii = struct . unpack ( iiII1iiI ,
 packet [ : ooo0000oo0 ] )
  packet = packet [ ooo0000oo0 : : ]
  if 22 - 22: I1Ii111 - OOooOOo * i1IIi
  if ( ooOoOoOo != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 88 - 88: ooOoO0o + iIii1I11I1II1 + OoO0O00 * I1Ii111 + oO0o
  iiII1iiI = "IH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 39 - 39: ooOoO0o - oO0o + OoOoOO00 - oO0o - Ii1I % I1Ii111
  oooo , i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  packet = packet [ ooo0000oo0 : : ]
  if 100 - 100: OOooOOo * IiII % IiII / o0oOOo0O0Ooo * OoO0O00 % OoOoOO00
  i1iIii = socket . ntohs ( i1iIii )
  self . instance_id = socket . ntohl ( oooo )
  i1I1iiiI = socket . ntohs ( i1I1iiiI )
  self . afi = i1I1iiiI
  if ( I111II != 0 and i1I1iiiI == 0 ) : self . mask_len = I111II
  if ( i1I1iiiI == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if I111II else LISP_AFI_ULTIMATE_ROOT
   if 12 - 12: I1IiiI
   if 32 - 32: I1Ii111
   if 35 - 35: O0 + II111iiii + o0oOOo0O0Ooo - OoO0O00 - Ii1I
   if 88 - 88: I1ii11iIi11i . O0 - o0oOOo0O0Ooo . I1ii11iIi11i * iII111i * I11i
   if 89 - 89: Oo0Ooo - oO0o + O0 / i11iIiiIii
  if ( i1I1iiiI == 0 ) : return ( packet )
  if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
  if 74 - 74: IiII - O0 % OOooOOo % OoooooooOO - I11i
  if 4 - 4: i1IIi + OoOoOO00 + iIii1I11I1II1 - i1IIi * i11iIiiIii
  if 99 - 99: I1ii11iIi11i - O0 % II111iiii + ooOoO0o % OoO0O00 * Ii1I
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 8 - 8: OOooOOo
   if 85 - 85: O0 % OOooOOo . Ii1I
   if 74 - 74: I1ii11iIi11i - I1Ii111 + i11iIiiIii / I1Ii111 / OoooooooOO + o0oOOo0O0Ooo
   if 23 - 23: Oo0Ooo
   if 91 - 91: I1Ii111
  if ( i1I1iiiI == LISP_AFI_LCAF ) :
   iiII1iiI = "BBBBH"
   ooo0000oo0 = struct . calcsize ( iiII1iiI )
   if ( len ( packet ) < ooo0000oo0 ) : return ( None )
   if 59 - 59: i1IIi % OOooOOo
   Ii1Ii1Ii , Ooo0000o , ooOoOoOo , ii11Ii1111 , iIIIi1Iii1 = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
   if 81 - 81: i11iIiiIii / OoO0O00 * OoOoOO00 % iII111i - iIii1I11I1II1 + I1ii11iIi11i
   if 20 - 20: O0 . I1Ii111 * Ii1I * II111iiii
   if ( ooOoOoOo != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 66 - 66: Ii1I % OoO0O00 % II111iiii - OOooOOo * o0oOOo0O0Ooo
   iIIIi1Iii1 = socket . ntohs ( iIIIi1Iii1 )
   packet = packet [ ooo0000oo0 : : ]
   if ( iIIIi1Iii1 > len ( packet ) ) : return ( None )
   if 33 - 33: OoooooooOO / I11i
   Ooo0O00o00 = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = Ooo0O00o00
   packet = Ooo0O00o00 . decode_geo ( packet , iIIIi1Iii1 , ii11Ii1111 )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 98 - 98: I1ii11iIi11i . Ii1I . iIii1I11I1II1 * I1ii11iIi11i / Ii1I
   if 74 - 74: Oo0Ooo * I1Ii111
  o0ooOo000oo = self . addr_length ( )
  if ( len ( packet ) < o0ooOo000oo ) : return ( None )
  if 72 - 72: OoOoOO00 + O0 - IiII * ooOoO0o
  packet = self . unpack_address ( packet )
  return ( packet )
  if 20 - 20: II111iiii % OoOoOO00 * i11iIiiIii
  if 68 - 68: IiII / ooOoO0o
  if 100 - 100: ooOoO0o / I1IiiI
  if 69 - 69: ooOoO0o + OoO0O00 * o0oOOo0O0Ooo - ooOoO0o
  if 66 - 66: OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00 + OOooOOo
  if 64 - 64: i1IIi
  if 26 - 26: OoOoOO00 / o0oOOo0O0Ooo . OOooOOo + I1IiiI + Ii1I . iII111i
  if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
  if 5 - 5: OoOoOO00 % i1IIi
  if 31 - 31: Oo0Ooo * O0 . OOooOOo . o0oOOo0O0Ooo + OoO0O00 + II111iiii
  if 76 - 76: Oo0Ooo + I1IiiI - O0
  if 58 - 58: IiII * i1IIi . I1IiiI - iII111i
  if 73 - 73: Oo0Ooo . OoOoOO00
  if 50 - 50: IiII / o0oOOo0O0Ooo
  if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
  if 52 - 52: O0
  if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
  if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
  if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
  if 83 - 83: oO0o / OoO0O00
  if 34 - 34: OoooooooOO - i1IIi * O0
 def lcaf_encode_sg ( self , group ) :
  ooOoOoOo = LISP_LCAF_MCAST_INFO_TYPE
  oooo = socket . htonl ( self . instance_id )
  o0ooOo000oo = socket . htons ( self . lcaf_length ( ooOoOoOo ) )
  iIiI1iiI11i = struct . pack ( "BBBBHIHBB" , 0 , 0 , ooOoOoOo , 0 , o0ooOo000oo , oooo ,
 0 , self . mask_len , group . mask_len )
  if 83 - 83: I1IiiI + OoO0O00
  iIiI1iiI11i += struct . pack ( "H" , socket . htons ( self . afi ) )
  iIiI1iiI11i += self . pack_address ( )
  iIiI1iiI11i += struct . pack ( "H" , socket . htons ( group . afi ) )
  iIiI1iiI11i += group . pack_address ( )
  return ( iIiI1iiI11i )
  if 41 - 41: Ii1I + II111iiii . OOooOOo * I1Ii111 / II111iiii
  if 32 - 32: Oo0Ooo - Ii1I % o0oOOo0O0Ooo
 def lcaf_decode_sg ( self , packet ) :
  iiII1iiI = "BBBBHIHBB"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( [ None , None ] )
  if 15 - 15: iIii1I11I1II1 * I1ii11iIi11i / ooOoO0o * oO0o % OOooOOo
  Oo0OoO00O , ii1I1I1iII , ooOoOoOo , OOOo00o , i1iIii , oooo , O0oO , o0o0OOOOoO , Oo0O0O = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 61 - 61: o0oOOo0O0Ooo % OOooOOo % I1IiiI % I1ii11iIi11i % ooOoO0o + i11iIiiIii
  packet = packet [ ooo0000oo0 : : ]
  if 76 - 76: O0
  if ( ooOoOoOo != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 81 - 81: I11i - o0oOOo0O0Ooo % Ii1I / I1Ii111 * II111iiii
  self . instance_id = socket . ntohl ( oooo )
  i1iIii = socket . ntohs ( i1iIii ) - 8
  if 40 - 40: OoO0O00 . i11iIiiIii
  if 36 - 36: o0oOOo0O0Ooo * iII111i / I1ii11iIi11i % i1IIi % I1ii11iIi11i + i11iIiiIii
  if 24 - 24: I1Ii111 / ooOoO0o - i11iIiiIii
  if 32 - 32: II111iiii * Ii1I . ooOoO0o * Oo0Ooo - I1ii11iIi11i % I11i
  if 96 - 96: Ii1I / OOooOOo / O0
  iiII1iiI = "H"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( [ None , None ] )
  if ( i1iIii < ooo0000oo0 ) : return ( [ None , None ] )
  if 8 - 8: iII111i + OOooOOo / I1ii11iIi11i . iII111i
  i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  i1iIii -= ooo0000oo0
  self . afi = socket . ntohs ( i1I1iiiI )
  self . mask_len = o0o0OOOOoO
  o0ooOo000oo = self . addr_length ( )
  if ( i1iIii < o0ooOo000oo ) : return ( [ None , None ] )
  if 45 - 45: i1IIi
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 28 - 28: iII111i
  i1iIii -= o0ooOo000oo
  if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
  if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
  if 4 - 4: Ii1I - Oo0Ooo . i1IIi + iIii1I11I1II1
  if 28 - 28: O0 / ooOoO0o / IiII - I11i + IiII + OoO0O00
  if 84 - 84: Oo0Ooo + OoOoOO00 / iII111i . I1ii11iIi11i
  iiII1iiI = "H"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( [ None , None ] )
  if ( i1iIii < ooo0000oo0 ) : return ( [ None , None ] )
  if 26 - 26: Oo0Ooo
  i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  i1iIii -= ooo0000oo0
  oo0oOooo0O = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  oo0oOooo0O . afi = socket . ntohs ( i1I1iiiI )
  oo0oOooo0O . mask_len = Oo0O0O
  oo0oOooo0O . instance_id = self . instance_id
  o0ooOo000oo = self . addr_length ( )
  if ( i1iIii < o0ooOo000oo ) : return ( [ None , None ] )
  if 61 - 61: Ii1I * oO0o * i11iIiiIii + OoO0O00
  packet = oo0oOooo0O . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 43 - 43: OoO0O00 * OoO0O00 * oO0o
  return ( [ packet , oo0oOooo0O ] )
  if 24 - 24: oO0o
  if 77 - 77: i11iIiiIii - I1Ii111 - I1ii11iIi11i * Oo0Ooo / i11iIiiIii
 def lcaf_decode_eid ( self , packet ) :
  iiII1iiI = "BBB"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( [ None , None ] )
  if 79 - 79: Oo0Ooo % Oo0Ooo . oO0o + ooOoO0o * iII111i * I11i
  if 87 - 87: o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo + I1IiiI
  if 89 - 89: II111iiii
  if 41 - 41: iIii1I11I1II1
  if 26 - 26: Oo0Ooo / i1IIi + Oo0Ooo
  OOOo00o , Ooo0000o , ooOoOoOo = struct . unpack ( iiII1iiI ,
 packet [ : ooo0000oo0 ] )
  if 76 - 76: I1ii11iIi11i * i1IIi % oO0o
  if ( ooOoOoOo == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( ooOoOoOo == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , oo0oOooo0O = self . lcaf_decode_sg ( packet )
   return ( [ packet , oo0oOooo0O ] )
  elif ( ooOoOoOo == LISP_LCAF_GEO_COORD_TYPE ) :
   iiII1iiI = "BBBBH"
   ooo0000oo0 = struct . calcsize ( iiII1iiI )
   if ( len ( packet ) < ooo0000oo0 ) : return ( None )
   if 80 - 80: i1IIi * II111iiii . O0 % I1ii11iIi11i / ooOoO0o
   Ii1Ii1Ii , Ooo0000o , ooOoOoOo , ii11Ii1111 , iIIIi1Iii1 = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
   if 58 - 58: I1IiiI * I1ii11iIi11i - i1IIi % I1Ii111 % O0
   if 24 - 24: I11i + I11i % I11i
   if ( ooOoOoOo != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 63 - 63: i11iIiiIii + iIii1I11I1II1 / oO0o % IiII - O0
   iIIIi1Iii1 = socket . ntohs ( iIIIi1Iii1 )
   packet = packet [ ooo0000oo0 : : ]
   if ( iIIIi1Iii1 > len ( packet ) ) : return ( None )
   if 21 - 21: II111iiii
   Ooo0O00o00 = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = Ooo0O00o00
   packet = Ooo0O00o00 . decode_geo ( packet , iIIIi1Iii1 , ii11Ii1111 )
   self . mask_len = self . host_mask_len ( )
   if 89 - 89: OOooOOo % i11iIiiIii * OoOoOO00 % oO0o / O0 * i1IIi
  return ( [ packet , None ] )
  if 16 - 16: IiII
  if 42 - 42: i1IIi / Ii1I * I1ii11iIi11i
  if 9 - 9: I11i % i1IIi / i1IIi / OoO0O00
  if 46 - 46: I1Ii111 * II111iiii + II111iiii * O0 % II111iiii
  if 37 - 37: OOooOOo . iIii1I11I1II1 / O0 . ooOoO0o + OOooOOo - OoooooooOO
  if 96 - 96: I1Ii111 / oO0o . I1ii11iIi11i % I1IiiI * OOooOOo
class lisp_elp_node ( object ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 99 - 99: i11iIiiIii - I1Ii111
  if 4 - 4: o0oOOo0O0Ooo - i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
 def copy_elp_node ( self ) :
  oo0o = lisp_elp_node ( )
  oo0o . copy_address ( self . address )
  oo0o . probe = self . probe
  oo0o . strict = self . strict
  oo0o . eid = self . eid
  oo0o . we_are_last = self . we_are_last
  return ( oo0o )
  if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
  if 54 - 54: II111iiii * I1IiiI
  if 49 - 49: I1ii11iIi11i
class lisp_elp ( object ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
  if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
 def copy_elp ( self ) :
  I1iI1 = lisp_elp ( self . elp_name )
  I1iI1 . use_elp_node = self . use_elp_node
  I1iI1 . we_are_last = self . we_are_last
  for oo0o in self . elp_nodes :
   I1iI1 . elp_nodes . append ( oo0o . copy_elp_node ( ) )
   if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
  return ( I1iI1 )
  if 15 - 15: oO0o
  if 40 - 40: I1Ii111
 def print_elp ( self , want_marker ) :
  iIII1Iiii = ""
  for oo0o in self . elp_nodes :
   oooO0OO0 = ""
   if ( want_marker ) :
    if ( oo0o == self . use_elp_node ) :
     oooO0OO0 = "*"
    elif ( oo0o . we_are_last ) :
     oooO0OO0 = "x"
     if 54 - 54: I1Ii111 % OoO0O00 - OoooooooOO
     if 96 - 96: IiII
   iIII1Iiii += "{}{}({}{}{}), " . format ( oooO0OO0 ,
 oo0o . address . print_address_no_iid ( ) ,
 "r" if oo0o . eid else "R" , "P" if oo0o . probe else "p" ,
 "S" if oo0o . strict else "s" )
   if 31 - 31: Ii1I + O0 - OOooOOo * O0 * I11i
  return ( iIII1Iiii [ 0 : - 2 ] if iIII1Iiii != "" else "" )
  if 53 - 53: I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoooooooOO + IiII * I1IiiI
  if 16 - 16: i11iIiiIii - oO0o . i11iIiiIii + OoO0O00 + i11iIiiIii
 def select_elp_node ( self ) :
  OOO0O00oo , iII1Ii1IiiIii , ooO000OO = lisp_myrlocs
  OOOooo0OooOoO = None
  if 93 - 93: OoOoOO00
  for oo0o in self . elp_nodes :
   if ( OOO0O00oo and oo0o . address . is_exact_match ( OOO0O00oo ) ) :
    OOOooo0OooOoO = self . elp_nodes . index ( oo0o )
    break
    if 48 - 48: i1IIi
   if ( iII1Ii1IiiIii and oo0o . address . is_exact_match ( iII1Ii1IiiIii ) ) :
    OOOooo0OooOoO = self . elp_nodes . index ( oo0o )
    break
    if 22 - 22: iII111i / OoO0O00 * OOooOOo + I11i
    if 84 - 84: IiII * IiII * o0oOOo0O0Ooo
    if 17 - 17: II111iiii * I1IiiI + II111iiii + I1IiiI % I11i * oO0o
    if 51 - 51: I1IiiI
    if 35 - 35: OOooOOo % oO0o
    if 73 - 73: II111iiii / i11iIiiIii
    if 91 - 91: OOooOOo
  if ( OOOooo0OooOoO == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   oo0o . we_are_last = False
   return
   if 92 - 92: o0oOOo0O0Ooo % o0oOOo0O0Ooo + I1IiiI
   if 35 - 35: oO0o + iII111i + I11i - I1ii11iIi11i - ooOoO0o - OOooOOo
   if 77 - 77: OoooooooOO + OoooooooOO / oO0o * o0oOOo0O0Ooo / I11i
   if 86 - 86: I1IiiI % IiII - IiII
   if 1 - 1: o0oOOo0O0Ooo + OoOoOO00 / OOooOOo % IiII
   if 16 - 16: IiII . I11i * O0 + OoooooooOO
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ OOOooo0OooOoO ] ) :
   self . use_elp_node = None
   oo0o . we_are_last = True
   return
   if 37 - 37: OoO0O00 . i11iIiiIii - i11iIiiIii % I1Ii111 + II111iiii * i11iIiiIii
   if 83 - 83: OOooOOo % O0 - I11i . Ii1I % IiII
   if 45 - 45: I11i % OoO0O00
   if 18 - 18: Ii1I / Ii1I * IiII
   if 33 - 33: ooOoO0o
  self . use_elp_node = self . elp_nodes [ OOOooo0OooOoO + 1 ]
  return
  if 14 - 14: Oo0Ooo % I1Ii111 % ooOoO0o . oO0o * iIii1I11I1II1 . I1ii11iIi11i
  if 50 - 50: O0 * i11iIiiIii / iIii1I11I1II1 . I11i + i11iIiiIii
  if 68 - 68: oO0o + o0oOOo0O0Ooo * iIii1I11I1II1 / i1IIi
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
  if 9 - 9: I11i % OoO0O00 . oO0o / I1ii11iIi11i
  if 88 - 88: Oo0Ooo / IiII / II111iiii / I1ii11iIi11i + OoooooooOO
 def copy_geo ( self ) :
  Ooo0O00o00 = lisp_geo ( self . geo_name )
  Ooo0O00o00 . latitude = self . latitude
  Ooo0O00o00 . lat_mins = self . lat_mins
  Ooo0O00o00 . lat_secs = self . lat_secs
  Ooo0O00o00 . longitude = self . longitude
  Ooo0O00o00 . long_mins = self . long_mins
  Ooo0O00o00 . long_secs = self . long_secs
  Ooo0O00o00 . altitude = self . altitude
  Ooo0O00o00 . radius = self . radius
  return ( Ooo0O00o00 )
  if 65 - 65: iII111i % oO0o * IiII
  if 16 - 16: iII111i % I11i % OoOoOO00
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 80 - 80: OoooooooOO * i11iIiiIii % oO0o / Oo0Ooo - I1ii11iIi11i
  if 92 - 92: o0oOOo0O0Ooo % i1IIi / I1Ii111 % ooOoO0o / oO0o
 def parse_geo_string ( self , geo_str ) :
  OOOooo0OooOoO = geo_str . find ( "]" )
  if ( OOOooo0OooOoO != - 1 ) : geo_str = geo_str [ OOOooo0OooOoO + 1 : : ]
  if 2 - 2: i11iIiiIii / Ii1I - i1IIi % O0
  if 12 - 12: Oo0Ooo + I1ii11iIi11i
  if 54 - 54: OoO0O00 . o0oOOo0O0Ooo / I11i
  if 95 - 95: i1IIi . I1Ii111
  if 94 - 94: I1IiiI + Ii1I + i1IIi . iIii1I11I1II1
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , Oo0OOoO0oo0oO = geo_str . split ( "/" )
   self . radius = int ( Oo0OOoO0oo0oO )
   if 31 - 31: iIii1I11I1II1 + I1IiiI
   if 82 - 82: I1Ii111 / Ii1I % OoooooooOO - IiII / OoooooooOO
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 23 - 23: iIii1I11I1II1
  I1I1 = geo_str [ 0 : 4 ]
  iiiI1ioo = geo_str [ 4 : 8 ]
  if 36 - 36: i11iIiiIii - I1IiiI
  if 69 - 69: i1IIi
  if 52 - 52: OoOoOO00 + II111iiii % I1ii11iIi11i - II111iiii / ooOoO0o
  if 54 - 54: I1Ii111 - I11i * iIii1I11I1II1 % OoO0O00 % I11i * ooOoO0o
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 10 - 10: OoooooooOO / I11i
  if 48 - 48: I1IiiI % Ii1I
  if 76 - 76: o0oOOo0O0Ooo / iIii1I11I1II1 * IiII
  if 36 - 36: ooOoO0o - OoOoOO00 . iIii1I11I1II1 / oO0o % OoooooooOO * iII111i
  self . latitude = int ( I1I1 [ 0 ] )
  self . lat_mins = int ( I1I1 [ 1 ] )
  self . lat_secs = int ( I1I1 [ 2 ] )
  if ( I1I1 [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 42 - 42: oO0o
  if 71 - 71: i11iIiiIii . I1Ii111 % OoO0O00 % I1IiiI
  if 46 - 46: IiII + oO0o - ooOoO0o
  if 2 - 2: i1IIi / Ii1I % OoO0O00
  self . longitude = int ( iiiI1ioo [ 0 ] )
  self . long_mins = int ( iiiI1ioo [ 1 ] )
  self . long_secs = int ( iiiI1ioo [ 2 ] )
  if ( iiiI1ioo [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 85 - 85: i1IIi % iIii1I11I1II1
  if 10 - 10: O0 . oO0o * I1IiiI
 def print_geo ( self ) :
  i1I1 = "N" if self . latitude < 0 else "S"
  iIOO0OOOo = "E" if self . longitude < 0 else "W"
  if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
  oOIIi = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , i1I1 , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , iIOO0OOOo )
  if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
  if ( self . no_geo_altitude ( ) == False ) :
   oOIIi += "-" + str ( self . altitude )
   if 79 - 79: oO0o + I1IiiI % iII111i + II111iiii % OoO0O00 % iII111i
   if 46 - 46: o0oOOo0O0Ooo
   if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
   if 44 - 44: I11i . oO0o
   if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
  if ( self . radius != 0 ) : oOIIi += "/{}" . format ( self . radius )
  return ( oOIIi )
  if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
  if 16 - 16: OoO0O00 / Ii1I * i11iIiiIii / o0oOOo0O0Ooo + I1Ii111
 def geo_url ( self ) :
  i1IiI1IIIIi = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  i1IiI1IIIIi = "10" if ( i1IiI1IIIIi == "" or i1IiI1IIIIi . isdigit ( ) == False ) else i1IiI1IIIIi
  ooOO0OOo0oo0 , Oo0OO0o = self . dms_to_decimal ( )
  I11II = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( ooOO0OOo0oo0 , Oo0OO0o , ooOO0OOo0oo0 , Oo0OO0o ,
  # ooOoO0o + O0 * IiII * I11i * i11iIiiIii - OoO0O00
  # Oo0Ooo . Oo0Ooo * IiII - OoOoOO00 % i1IIi % Oo0Ooo
 i1IiI1IIIIi )
  return ( I11II )
  if 24 - 24: OoO0O00 + iII111i . Oo0Ooo
  if 2 - 2: I1ii11iIi11i
 def print_geo_url ( self ) :
  Ooo0O00o00 = self . print_geo ( )
  if ( self . radius == 0 ) :
   I11II = self . geo_url ( )
   i1i111III1 = "<a href='{}'>{}</a>" . format ( I11II , Ooo0O00o00 )
  else :
   I11II = Ooo0O00o00 . replace ( "/" , "-" )
   i1i111III1 = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( I11II , Ooo0O00o00 )
   if 12 - 12: Ii1I - I1ii11iIi11i
  return ( i1i111III1 )
  if 10 - 10: Ii1I * i11iIiiIii - ooOoO0o
  if 65 - 65: OoOoOO00 * I1ii11iIi11i - I11i - OOooOOo
 def dms_to_decimal ( self ) :
  I1Ii1I , Ii1ii1I1 , iIIIiI11ii = self . latitude , self . lat_mins , self . lat_secs
  oo00OoOo00o = float ( abs ( I1Ii1I ) )
  oo00OoOo00o += float ( Ii1ii1I1 * 60 + iIIIiI11ii ) / 3600
  if ( I1Ii1I > 0 ) : oo00OoOo00o = - oo00OoOo00o
  iI1iI1I1 = oo00OoOo00o
  if 96 - 96: IiII % iII111i . OoOoOO00 / oO0o . OoO0O00
  I1Ii1I , Ii1ii1I1 , iIIIiI11ii = self . longitude , self . long_mins , self . long_secs
  oo00OoOo00o = float ( abs ( I1Ii1I ) )
  oo00OoOo00o += float ( Ii1ii1I1 * 60 + iIIIiI11ii ) / 3600
  if ( I1Ii1I > 0 ) : oo00OoOo00o = - oo00OoOo00o
  oo0OO = oo00OoOo00o
  return ( ( iI1iI1I1 , oo0OO ) )
  if 26 - 26: iII111i - OoO0O00 . o0oOOo0O0Ooo
  if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
 def get_distance ( self , geo_point ) :
  oooOoOoooo = self . dms_to_decimal ( )
  iiIi1iI1Ii = geo_point . dms_to_decimal ( )
  i1iI = geopy . distance . distance ( oooOoOoooo , iiIi1iI1Ii )
  return ( i1iI . km )
  if 33 - 33: Oo0Ooo + OoO0O00
  if 62 - 62: oO0o / I1IiiI
 def point_in_circle ( self , geo_point ) :
  Oo00 = self . get_distance ( geo_point )
  return ( Oo00 <= self . radius )
  if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
  if 51 - 51: oO0o - I1ii11iIi11i + I1ii11iIi11i
 def encode_geo ( self ) :
  ii1 = socket . htons ( LISP_AFI_LCAF )
  Iii = socket . htons ( 20 + 2 )
  Ooo0000o = 0
  if 100 - 100: I11i - I1ii11iIi11i . i1IIi
  ooOO0OOo0oo0 = abs ( self . latitude )
  oOOOo = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : Ooo0000o |= 0x40
  if 43 - 43: O0 * I11i * IiII
  Oo0OO0o = abs ( self . longitude )
  iiiII1Iii11i1 = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : Ooo0000o |= 0x20
  if 51 - 51: I11i + OoooooooOO / OoOoOO00 * i1IIi * I11i
  IiI1ii1 = 0
  if ( self . no_geo_altitude ( ) == False ) :
   IiI1ii1 = socket . htonl ( self . altitude )
   Ooo0000o |= 0x10
   if 82 - 82: I1Ii111
  Oo0OOoO0oo0oO = socket . htons ( self . radius )
  if ( Oo0OOoO0oo0oO != 0 ) : Ooo0000o |= 0x06
  if 78 - 78: I1Ii111 % oO0o * iIii1I11I1II1
  iii = struct . pack ( "HBBBBH" , ii1 , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , Iii )
  iii += struct . pack ( "BBHBBHBBHIHHH" , Ooo0000o , 0 , 0 , ooOO0OOo0oo0 , oOOOo >> 16 ,
 socket . htons ( oOOOo & 0x0ffff ) , Oo0OO0o , iiiII1Iii11i1 >> 16 ,
 socket . htons ( iiiII1Iii11i1 & 0xffff ) , IiI1ii1 , Oo0OOoO0oo0oO , 0 , 0 )
  if 2 - 2: OOooOOo % Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
  return ( iii )
  if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
  if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  iiII1iiI = "BBHBBHBBHIHHH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( lcaf_len < ooo0000oo0 ) : return ( None )
  if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
  Ooo0000o , i1Iii1 , i1111111II , ooOO0OOo0oo0 , ooooo0o0 , oOOOo , Oo0OO0o , oO0OOoOOo , iiiII1Iii11i1 , IiI1ii1 , Oo0OOoO0oo0oO , i1I11III , i1I1iiiI = struct . unpack ( iiII1iiI ,
  # iIii1I11I1II1 % i11iIiiIii * I1Ii111
 packet [ : ooo0000oo0 ] )
  if 48 - 48: I11i * OoO0O00 - OoO0O00
  if 88 - 88: I11i * iII111i . I1Ii111 * IiII - I1Ii111
  if 79 - 79: iIii1I11I1II1
  if 4 - 4: i1IIi % iIii1I11I1II1 + Oo0Ooo + OOooOOo % oO0o
  i1I1iiiI = socket . ntohs ( i1I1iiiI )
  if ( i1I1iiiI == LISP_AFI_LCAF ) : return ( None )
  if 76 - 76: ooOoO0o . iII111i
  if ( Ooo0000o & 0x40 ) : ooOO0OOo0oo0 = - ooOO0OOo0oo0
  self . latitude = ooOO0OOo0oo0
  OOoooOooOO = old_div ( ( ( ooooo0o0 << 16 ) | socket . ntohs ( oOOOo ) ) , 1000 )
  self . lat_mins = old_div ( OOoooOooOO , 60 )
  self . lat_secs = OOoooOooOO % 60
  if 69 - 69: i11iIiiIii * I1IiiI - o0oOOo0O0Ooo
  if ( Ooo0000o & 0x20 ) : Oo0OO0o = - Oo0OO0o
  self . longitude = Oo0OO0o
  O0000Ooo0OO0 = old_div ( ( ( oO0OOoOOo << 16 ) | socket . ntohs ( iiiII1Iii11i1 ) ) , 1000 )
  self . long_mins = old_div ( O0000Ooo0OO0 , 60 )
  self . long_secs = O0000Ooo0OO0 % 60
  if 58 - 58: o0oOOo0O0Ooo - IiII
  self . altitude = socket . ntohl ( IiI1ii1 ) if ( Ooo0000o & 0x10 ) else - 1
  Oo0OOoO0oo0oO = socket . ntohs ( Oo0OOoO0oo0oO )
  self . radius = Oo0OOoO0oo0oO if ( Ooo0000o & 0x02 ) else Oo0OOoO0oo0oO * 1000
  if 77 - 77: iIii1I11I1II1 + Ii1I + oO0o . i11iIiiIii - iIii1I11I1II1 % ooOoO0o
  self . geo_name = None
  packet = packet [ ooo0000oo0 : : ]
  if 53 - 53: i11iIiiIii / OoOoOO00 % o0oOOo0O0Ooo / IiII
  if ( i1I1iiiI != 0 ) :
   self . rloc . afi = i1I1iiiI
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 88 - 88: ooOoO0o . i1IIi
  return ( packet )
  if 21 - 21: OoO0O00 * I1ii11iIi11i + I1ii11iIi11i
  if 36 - 36: Ii1I . OOooOOo * iIii1I11I1II1 - i1IIi
  if 38 - 38: Oo0Ooo . o0oOOo0O0Ooo % oO0o / i11iIiiIii * OoO0O00 % OoOoOO00
  if 18 - 18: OOooOOo
  if 12 - 12: I1Ii111 % II111iiii / o0oOOo0O0Ooo - iIii1I11I1II1 + II111iiii
  if 41 - 41: OOooOOo
class lisp_rle_node ( object ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
  if 64 - 64: I1IiiI . Oo0Ooo * OoO0O00
 def copy_rle_node ( self ) :
  iIIi = lisp_rle_node ( )
  iIIi . address . copy_address ( self . address )
  iIIi . level = self . level
  iIIi . translated_port = self . translated_port
  iIIi . rloc_name = self . rloc_name
  return ( iIIi )
  if 87 - 87: i1IIi / OoooooooOO
  if 68 - 68: I1Ii111 / iIii1I11I1II1
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 8 - 8: ooOoO0o * IiII * OOooOOo / I1IiiI
  if 40 - 40: i11iIiiIii + OoooooooOO
 def get_encap_keys ( self ) :
  ooO0 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 2 - 2: o0oOOo0O0Ooo * OoO0O00
  O0O0 = self . address . print_address_no_iid ( ) + ":" + ooO0
  if 88 - 88: Oo0Ooo + oO0o + iII111i
  try :
   iI1iiiiiii = lisp_crypto_keys_by_rloc_encap [ O0O0 ]
   if ( iI1iiiiiii [ 1 ] ) : return ( iI1iiiiiii [ 1 ] . encrypt_key , iI1iiiiiii [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 51 - 51: i1IIi + i11iIiiIii * I11i / iII111i + OoooooooOO
   if 89 - 89: i11iIiiIii - I1Ii111 - O0 % iIii1I11I1II1 / IiII - O0
   if 63 - 63: OOooOOo
   if 23 - 23: Oo0Ooo / i1IIi - OOooOOo / Oo0Ooo
class lisp_rle ( object ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 16 - 16: o0oOOo0O0Ooo - iIii1I11I1II1 / OoooooooOO / I1ii11iIi11i + IiII
  if 73 - 73: OOooOOo % I1Ii111 + OoooooooOO / I1ii11iIi11i * oO0o % oO0o
 def copy_rle ( self ) :
  ooo0o0O = lisp_rle ( self . rle_name )
  for iIIi in self . rle_nodes :
   ooo0o0O . rle_nodes . append ( iIIi . copy_rle_node ( ) )
   if 25 - 25: I1Ii111
  ooo0o0O . build_forwarding_list ( )
  return ( ooo0o0O )
  if 93 - 93: OoO0O00
  if 62 - 62: Oo0Ooo . iII111i
 def print_rle ( self , html , do_formatting ) :
  IIIi1iI1 = ""
  for iIIi in self . rle_nodes :
   ooO0 = iIIi . translated_port
   if 15 - 15: i11iIiiIii * I11i + oO0o
   o0O = ""
   if ( iIIi . rloc_name != None ) :
    o0O = iIIi . rloc_name
    if ( do_formatting ) : o0O = blue ( o0O , html )
    o0O = "({})" . format ( o0O )
    if 59 - 59: oO0o * o0oOOo0O0Ooo
    if 76 - 76: I1IiiI
   O0O0 = iIIi . address . print_address_no_iid ( )
   if ( iIIi . address . is_local ( ) ) : O0O0 = red ( O0O0 , html )
   IIIi1iI1 += "{}{}{}, " . format ( O0O0 , "" if ooO0 == 0 else ":" + str ( ooO0 ) , o0O )
   if 94 - 94: OoooooooOO * I1ii11iIi11i
   if 28 - 28: II111iiii / II111iiii / II111iiii
  return ( IIIi1iI1 [ 0 : - 2 ] if IIIi1iI1 != "" else "" )
  if 70 - 70: OoO0O00 + O0 * OoO0O00
  if 25 - 25: OoooooooOO . Oo0Ooo + OOooOOo + Oo0Ooo * O0 % i1IIi
 def build_forwarding_list ( self ) :
  ii11i = - 1
  for iIIi in self . rle_nodes :
   if ( ii11i == - 1 ) :
    if ( iIIi . address . is_local ( ) ) : ii11i = iIIi . level
   else :
    if ( iIIi . level > ii11i ) : break
    if 71 - 71: II111iiii / Ii1I + i1IIi - OoOoOO00 + Ii1I
    if 31 - 31: OoooooooOO * Ii1I - iII111i . oO0o % Ii1I
  ii11i = 0 if ii11i == - 1 else iIIi . level
  if 97 - 97: Ii1I
  self . rle_forwarding_list = [ ]
  for iIIi in self . rle_nodes :
   if ( iIIi . level == ii11i or ( ii11i == 0 and
 iIIi . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and iIIi . address . is_local ( ) ) :
     O0O0 = iIIi . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( O0O0 ) )
     continue
     if 51 - 51: II111iiii . oO0o % iII111i
    self . rle_forwarding_list . append ( iIIi )
    if 47 - 47: II111iiii - iII111i * I1IiiI . IiII
    if 41 - 41: OoOoOO00 / O0 + I1Ii111 . I1ii11iIi11i
    if 48 - 48: Ii1I . o0oOOo0O0Ooo * O0 / OoooooooOO + I1Ii111 + Oo0Ooo
    if 92 - 92: Ii1I - o0oOOo0O0Ooo % I1IiiI + I1Ii111
    if 3 - 3: iIii1I11I1II1 + i11iIiiIii
class lisp_json ( object ) :
 def __init__ ( self , name , string , encrypted = False , ms_encrypt = False ) :
  if 49 - 49: OoOoOO00 % iIii1I11I1II1 + I1Ii111
  if 38 - 38: i11iIiiIii
  if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
  if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
  if ( type ( string ) == bytes ) : string = string . decode ( )
  if 7 - 7: Oo0Ooo . iII111i % I1ii11iIi11i / iII111i
  self . json_name = name
  self . json_encrypted = False
  try :
   json . loads ( string )
  except :
   lprint ( "Invalid JSON string: '{}'" . format ( string ) )
   string = '{ "?" : "?" }'
   if 93 - 93: iII111i
  self . json_string = string
  if 5 - 5: iII111i . I11i % I11i * Ii1I - I1ii11iIi11i . i11iIiiIii
  if 32 - 32: II111iiii
  if 58 - 58: I1IiiI - o0oOOo0O0Ooo - I1Ii111 . O0 % OoO0O00 . I11i
  if 41 - 41: iII111i . I1Ii111 - IiII / O0
  if 62 - 62: IiII * I1ii11iIi11i * iII111i * OoOoOO00
  if 12 - 12: Oo0Ooo * Ii1I / ooOoO0o % I11i % O0
  if 25 - 25: Oo0Ooo * oO0o
  if 78 - 78: OoOoOO00 / II111iiii
  if 6 - 6: I1Ii111 . OoOoOO00
  if 75 - 75: Oo0Ooo + I11i
  if ( len ( lisp_ms_json_keys ) != 0 ) :
   if ( ms_encrypt == False ) : return
   self . json_key_id = list ( lisp_ms_json_keys . keys ( ) ) [ 0 ]
   self . json_key = lisp_ms_json_keys [ self . json_key_id ]
   self . encrypt_json ( )
   if 87 - 87: I1IiiI
   if 36 - 36: OoO0O00 . ooOoO0o . O0 / OoO0O00
  if ( lisp_log_id == "lig" and encrypted ) :
   III = os . getenv ( "LISP_JSON_KEY" )
   if ( III != None ) :
    OOOooo0OooOoO = - 1
    if ( III [ 0 ] == "[" and "]" in III ) :
     OOOooo0OooOoO = III . find ( "]" )
     self . json_key_id = int ( III [ 1 : OOOooo0OooOoO ] )
     if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
    self . json_key = III [ OOOooo0OooOoO + 1 : : ]
    if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
    self . decrypt_json ( )
    if 72 - 72: I1ii11iIi11i
    if 74 - 74: I1Ii111 * iIii1I11I1II1 / oO0o - IiII - I1IiiI
    if 84 - 84: iIii1I11I1II1 % Oo0Ooo / I1ii11iIi11i + o0oOOo0O0Ooo * II111iiii
    if 81 - 81: I1IiiI / I1ii11iIi11i / OOooOOo
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 89 - 89: Oo0Ooo % IiII
  if 36 - 36: IiII % OoOoOO00 % I1ii11iIi11i
 def delete ( self ) :
  if ( self . json_name in lisp_json_list ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 7 - 7: I1ii11iIi11i % OoOoOO00 - O0 . I1Ii111
   if 9 - 9: Ii1I . OoooooooOO / ooOoO0o + i1IIi
   if 90 - 90: oO0o - OoOoOO00 % ooOoO0o
 def print_json ( self , html ) :
  o0OOO0OO = self . json_string
  i1ii1ii11iIi = "***"
  if ( html ) : i1ii1ii11iIi = red ( i1ii1ii11iIi , html )
  O0oOoO0 = i1ii1ii11iIi + self . json_string + i1ii1ii11iIi
  if ( self . valid_json ( ) ) : return ( o0OOO0OO )
  return ( O0oOoO0 )
  if 62 - 62: iIii1I11I1II1 * I1IiiI % iII111i * II111iiii / OoO0O00
  if 16 - 16: iIii1I11I1II1
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 39 - 39: oO0o / OoO0O00 - Ii1I + ooOoO0o + OOooOOo
  return ( True )
  if 84 - 84: iII111i / Oo0Ooo
  if 21 - 21: OoO0O00 . I1IiiI - OoO0O00
 def encrypt_json ( self ) :
  iiIio0o0 = self . json_key . zfill ( 32 )
  OoOooO = "0" * 8
  if 51 - 51: iIii1I11I1II1
  iIiI11II = json . loads ( self . json_string )
  for III in iIiI11II :
   oOO0 = iIiI11II [ III ]
   if ( type ( oOO0 ) != str ) : oOO0 = str ( oOO0 )
   oOO0 = chacha . ChaCha ( iiIio0o0 , OoOooO ) . encrypt ( oOO0 )
   iIiI11II [ III ] = binascii . hexlify ( oOO0 )
   if 73 - 73: O0 * I1Ii111 - i1IIi
  self . json_string = json . dumps ( iIiI11II )
  self . json_encrypted = True
  if 68 - 68: OOooOOo % IiII / Oo0Ooo + OoOoOO00
  if 11 - 11: OoO0O00
 def decrypt_json ( self ) :
  iiIio0o0 = self . json_key . zfill ( 32 )
  OoOooO = "0" * 8
  if 70 - 70: o0oOOo0O0Ooo * O0 * II111iiii
  iIiI11II = json . loads ( self . json_string )
  for III in iIiI11II :
   oOO0 = binascii . unhexlify ( iIiI11II [ III ] )
   iIiI11II [ III ] = chacha . ChaCha ( iiIio0o0 , OoOooO ) . encrypt ( oOO0 )
   if 38 - 38: OoO0O00 - I1IiiI * OoooooooOO / I11i . O0
  try :
   self . json_string = json . dumps ( iIiI11II )
   self . json_encrypted = False
  except :
   pass
   if 77 - 77: OOooOOo + oO0o * iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii
   if 92 - 92: Oo0Ooo . o0oOOo0O0Ooo % OoooooooOO * i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo
   if 48 - 48: iII111i * I1ii11iIi11i * oO0o % O0 . OoO0O00
   if 11 - 11: OOooOOo / o0oOOo0O0Ooo
   if 98 - 98: oO0o + I11i . oO0o
   if 10 - 10: iII111i + i1IIi . I11i % ooOoO0o / ooOoO0o
   if 86 - 86: Oo0Ooo
class lisp_stats ( object ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 7 - 7: iIii1I11I1II1
  if 86 - 86: IiII + iII111i * II111iiii - IiII - o0oOOo0O0Ooo
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 8 - 8: OOooOOo . Ii1I
  if 15 - 15: ooOoO0o / OOooOOo + i1IIi / Ii1I / OOooOOo
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  i1i111Iiiiiii = time . time ( ) - self . last_increment
  return ( i1i111Iiiiiii <= 1 )
  if 47 - 47: Oo0Ooo + oO0o % OoooooooOO
  if 23 - 23: I1Ii111 / i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  i1i111Iiiiiii = time . time ( ) - self . last_increment
  return ( i1i111Iiiiiii <= 60 )
  if 11 - 11: I11i % OoOoOO00 * Oo0Ooo
  if 48 - 48: OOooOOo
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 66 - 66: iII111i - I1Ii111 - i11iIiiIii . o0oOOo0O0Ooo + Oo0Ooo
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 90 - 90: O0 - i11iIiiIii * ooOoO0o . I1ii11iIi11i . Ii1I - OoooooooOO
  return ( c1 , c2 )
  if 23 - 23: o0oOOo0O0Ooo
  if 88 - 88: I1Ii111 + iIii1I11I1II1 / o0oOOo0O0Ooo
 def normalize ( self , count ) :
  count = str ( count )
  O0Ooo0O00O = len ( count )
  if ( O0Ooo0O00O > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 19 - 19: OOooOOo - II111iiii
  if ( O0Ooo0O00O > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 80 - 80: Oo0Ooo % I1Ii111
  if ( O0Ooo0O00O > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 91 - 91: OoooooooOO - O0 . iII111i - II111iiii % O0 - OoooooooOO
  return ( count )
  if 94 - 94: I1IiiI % I1ii11iIi11i
  if 30 - 30: iIii1I11I1II1 . OoOoOO00
 def get_stats ( self , summary , html ) :
  iIoOo00oOoO = self . last_rate_check
  Oo0oo00 = self . last_packet_count
  IIIiIIi = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 89 - 89: OoooooooOO % II111iiii . I1ii11iIi11i + o0oOOo0O0Ooo % I1Ii111 * IiII
  o0Ooo00 = self . last_rate_check - iIoOo00oOoO
  if ( o0Ooo00 == 0 ) :
   iI1iiiiiiiiI = 0
   o0o0O0o0000 = 0
  else :
   iI1iiiiiiiiI = int ( old_div ( ( self . packet_count - Oo0oo00 ) ,
 o0Ooo00 ) )
   o0o0O0o0000 = old_div ( ( self . byte_count - IIIiIIi ) , o0Ooo00 )
   o0o0O0o0000 = old_div ( ( o0o0O0o0000 * 8 ) , 1000000 )
   o0o0O0o0000 = round ( o0o0O0o0000 , 2 )
   if 81 - 81: O0 . IiII
   if 60 - 60: i1IIi + i1IIi
   if 47 - 47: iII111i - I1Ii111 - I1Ii111 . ooOoO0o
   if 5 - 5: i1IIi
   if 47 - 47: I11i * I11i . OoOoOO00
  ooOOo0O = self . normalize ( self . packet_count )
  i1Ii1iiii1Ii = self . normalize ( self . byte_count )
  if 54 - 54: iIii1I11I1II1 % II111iiii - OOooOOo * i1IIi
  if 26 - 26: OOooOOo % ooOoO0o
  if 80 - 80: o0oOOo0O0Ooo . iII111i . ooOoO0o + OOooOOo * I1IiiI / O0
  if 61 - 61: I11i % OOooOOo + i11iIiiIii + I11i
  if 69 - 69: OoOoOO00 + OoOoOO00 + o0oOOo0O0Ooo / iIii1I11I1II1 * OoO0O00
  if ( summary ) :
   iiI1 = "<br>" if html else ""
   ooOOo0O , i1Ii1iiii1Ii = self . stat_colors ( ooOOo0O , i1Ii1iiii1Ii , html )
   o00o0O0O0oO0o = "packet-count: {}{}byte-count: {}" . format ( ooOOo0O , iiI1 , i1Ii1iiii1Ii )
   IIIii1i = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( iI1iiiiiiiiI , o0o0O0o0000 )
   if 56 - 56: ooOoO0o
   if ( html != "" ) : IIIii1i = lisp_span ( o00o0O0O0oO0o , IIIii1i )
  else :
   OoooOOO0OO = str ( iI1iiiiiiiiI )
   Iii1I11iIiI1 = str ( o0o0O0o0000 )
   if ( html ) :
    ooOOo0O = lisp_print_cour ( ooOOo0O )
    OoooOOO0OO = lisp_print_cour ( OoooOOO0OO )
    i1Ii1iiii1Ii = lisp_print_cour ( i1Ii1iiii1Ii )
    Iii1I11iIiI1 = lisp_print_cour ( Iii1I11iIiI1 )
    if 100 - 100: I1IiiI
   iiI1 = "<br>" if html else ", "
   if 27 - 27: OoOoOO00 * O0 - I11i
   IIIii1i = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( ooOOo0O , iiI1 , OoooOOO0OO , iiI1 , i1Ii1iiii1Ii , iiI1 ,
   # iII111i % OoooooooOO + Ii1I - OoooooooOO + I1ii11iIi11i - i1IIi
 Iii1I11iIiI1 )
   if 73 - 73: oO0o / iII111i * I1Ii111 + i1IIi * I1Ii111 / I1Ii111
  return ( IIIii1i )
  if 75 - 75: iIii1I11I1II1 / OoO0O00 / i1IIi
  if 36 - 36: o0oOOo0O0Ooo + I1Ii111 / iII111i
  if 48 - 48: I1IiiI % ooOoO0o * o0oOOo0O0Ooo * II111iiii - OoOoOO00
  if 12 - 12: I1IiiI - Oo0Ooo / I11i
  if 79 - 79: II111iiii . I1Ii111 * I1Ii111 + I11i + I1Ii111 % I1IiiI
  if 42 - 42: I11i - i1IIi . Oo0Ooo - i1IIi
  if 87 - 87: O0 . o0oOOo0O0Ooo % OOooOOo / I11i - I1Ii111 % i11iIiiIii
  if 3 - 3: oO0o + iII111i + OOooOOo
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 54 - 54: i11iIiiIii + OoO0O00 - IiII - iII111i / I11i
if 85 - 85: OOooOOo * OOooOOo * I1Ii111 - ooOoO0o . O0 % iII111i
if 5 - 5: i1IIi * iII111i . o0oOOo0O0Ooo - I1ii11iIi11i
if 84 - 84: i1IIi
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
  if 17 - 17: IiII + iII111i * OoO0O00 / iII111i
  if ( recurse == False ) : return
  if 67 - 67: i1IIi * IiII . OoOoOO00 % iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
  if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
  if 65 - 65: OoOoOO00
  if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
  if 58 - 58: OoO0O00 * I1IiiI - II111iiii / Ii1I - I1IiiI % OoooooooOO
  if 33 - 33: IiII / i1IIi + I1Ii111
  Ii11i = lisp_get_default_route_next_hops ( )
  if ( Ii11i == [ ] or len ( Ii11i ) == 1 ) : return
  if 29 - 29: I11i + ooOoO0o % oO0o * iII111i
  self . rloc_next_hop = Ii11i [ 0 ]
  i11iII11I1III = self
  for OoII1 in Ii11i [ 1 : : ] :
   iiIIIiiii = lisp_rloc ( False )
   iiIIIiiii = copy . deepcopy ( self )
   iiIIIiiii . rloc_next_hop = OoII1
   i11iII11I1III . next_rloc = iiIIIiiii
   i11iII11I1III = iiIIIiiii
   if 70 - 70: Ii1I + Oo0Ooo + Oo0Ooo / i1IIi
   if 33 - 33: OoooooooOO + o0oOOo0O0Ooo . OoOoOO00 % Oo0Ooo * O0
   if 49 - 49: I1ii11iIi11i * I1Ii111 - OoooooooOO . i1IIi . I1ii11iIi11i
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 37 - 37: IiII - oO0o
  if 92 - 92: I1IiiI
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 51 - 51: OoO0O00 + Oo0Ooo - OOooOOo + I1ii11iIi11i
  if 32 - 32: I1ii11iIi11i % OoOoOO00 + Oo0Ooo
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 92 - 92: II111iiii . O0 . iIii1I11I1II1 % IiII - i11iIiiIii
  if 9 - 9: OoO0O00
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 60 - 60: O0 / OoOoOO00 % i11iIiiIii % II111iiii / OoooooooOO
  if 52 - 52: ooOoO0o
  if 100 - 100: Oo0Ooo - o0oOOo0O0Ooo + iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1
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
  if 4 - 4: OoOoOO00 / Oo0Ooo - OoO0O00 . OoOoOO00 / I1Ii111
  if 60 - 60: OOooOOo * I1Ii111
 def print_rloc ( self , indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , i1 , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 17 - 17: iII111i * I11i / iIii1I11I1II1 - II111iiii
  if 97 - 97: II111iiii * o0oOOo0O0Ooo
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  oOo = self . rloc_name
  if ( cour ) : oOo = lisp_print_cour ( oOo )
  return ( 'rloc-name: {}' . format ( blue ( oOo , cour ) ) )
  if 13 - 13: o0oOOo0O0Ooo . II111iiii
  if 76 - 76: II111iiii + I1Ii111 . OoooooooOO / IiII % i11iIiiIii
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  ooO0 = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 87 - 87: Ii1I / OoOoOO00 / OOooOOo
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
  if 19 - 19: i1IIi + IiII . OoO0O00 / O0 - I1Ii111 - Oo0Ooo
  if 24 - 24: iII111i + i1IIi
  iIIiI11 = self . rloc
  if ( iIIiI11 . is_null ( ) == False ) :
   iII1ii1 = lisp_get_nat_info ( iIIiI11 , self . rloc_name )
   if ( iII1ii1 ) :
    ooO0 = iII1ii1 . port
    oOoOooooO = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    O0O0 = iIIiI11 . print_address_no_iid ( )
    IIIOo0O = red ( O0O0 , False )
    O00ooO0Oo = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 63 - 63: I1Ii111 + iIii1I11I1II1 / Oo0Ooo
    if 6 - 6: ooOoO0o + I1ii11iIi11i * I1IiiI / OoO0O00 / OoooooooOO
    if 23 - 23: ooOoO0o
    if 99 - 99: OOooOOo % I11i
    if 56 - 56: ooOoO0o
    if 5 - 5: I1Ii111 + I1Ii111 * i11iIiiIii . OoO0O00
    if ( iII1ii1 . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( IIIOo0O , ooO0 , O00ooO0Oo ) )
     if 50 - 50: iII111i - I1ii11iIi11i . Ii1I + i11iIiiIii + IiII * I1Ii111
     if 51 - 51: iII111i * OoO0O00 * o0oOOo0O0Ooo . i1IIi
     iII1ii1 = None if ( iII1ii1 == oOoOooooO ) else oOoOooooO
     if ( iII1ii1 and iII1ii1 . timed_out ( ) ) :
      ooO0 = iII1ii1 . port
      IIIOo0O = red ( iII1ii1 . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( IIIOo0O , ooO0 ,
      # OoOoOO00 - oO0o % iII111i . II111iiii
 O00ooO0Oo ) )
      iII1ii1 = None
      if 36 - 36: II111iiii - ooOoO0o
      if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
      if 98 - 98: iII111i . i1IIi + o0oOOo0O0Ooo * OoooooooOO - i11iIiiIii
      if 21 - 21: i11iIiiIii . oO0o * o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
      if 33 - 33: I1IiiI + O0 - I11i
      if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
      if 63 - 63: o0oOOo0O0Ooo . IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
    if ( iII1ii1 ) :
     if ( iII1ii1 . address != O0O0 ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( IIIOo0O , red ( iII1ii1 . address , False ) ) )
      if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
      self . rloc . store_address ( iII1ii1 . address )
      if 38 - 38: O0 % I1ii11iIi11i + O0
     IIIOo0O = red ( iII1ii1 . address , False )
     ooO0 = iII1ii1 . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( IIIOo0O , ooO0 , O00ooO0Oo ) )
     if 37 - 37: Oo0Ooo / I1IiiI
     self . store_translated_rloc ( iIIiI11 , ooO0 )
     if 23 - 23: II111iiii / iII111i
     if 55 - 55: i11iIiiIii - Ii1I % OoooooooOO * OoooooooOO
     if 92 - 92: iIii1I11I1II1
     if 47 - 47: Oo0Ooo + Oo0Ooo * ooOoO0o - OoOoOO00 + II111iiii
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 10 - 10: II111iiii / ooOoO0o . Ii1I / I1Ii111 / oO0o
  if 8 - 8: OOooOOo / ooOoO0o * I11i + OOooOOo * i1IIi
  if 48 - 48: o0oOOo0O0Ooo - I1ii11iIi11i / iII111i
  if 63 - 63: O0 - IiII . OOooOOo % IiII . I1IiiI / oO0o
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for iIIi in self . rle . rle_nodes :
    oOo = iIIi . rloc_name
    iII1ii1 = lisp_get_nat_info ( iIIi . address , oOo )
    if ( iII1ii1 == None ) : continue
    if 79 - 79: OoOoOO00
    ooO0 = iII1ii1 . port
    OOO00O = oOo
    if ( OOO00O ) : OOO00O = blue ( oOo , False )
    if 88 - 88: oO0o * o0oOOo0O0Ooo
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( ooO0 ,
    # IiII
 iIIi . address . print_address_no_iid ( ) , OOO00O ) )
    iIIi . translated_port = ooO0
    if 52 - 52: I1Ii111 * I11i - II111iiii + OOooOOo + II111iiii
    if 91 - 91: i1IIi + Oo0Ooo - I1ii11iIi11i + I1ii11iIi11i * O0 / O0
    if 78 - 78: OoooooooOO
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 8 - 8: Oo0Ooo - Oo0Ooo % O0 - Ii1I / o0oOOo0O0Ooo % Oo0Ooo
  if 51 - 51: iIii1I11I1II1 / iIii1I11I1II1 * I1ii11iIi11i / I11i
  if 18 - 18: Ii1I - i11iIiiIii + OoO0O00 . O0 - iII111i
  if 9 - 9: OoooooooOO / iII111i + o0oOOo0O0Ooo / II111iiii / I1Ii111
  iIi1I = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 66 - 66: I1Ii111 + OoooooooOO % I1IiiI . iII111i * Oo0Ooo + o0oOOo0O0Ooo
  if ( rloc_record . keys != None and iIi1I ) :
   III = rloc_record . keys [ 1 ]
   if ( III != None ) :
    O0O0 = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( ooO0 )
    if 96 - 96: OoO0O00 - ooOoO0o * Ii1I
    III . add_key_by_rloc ( O0O0 , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( O0O0 , False ) ) )
    if 34 - 34: OoO0O00 . Oo0Ooo % Ii1I . IiII + OoOoOO00
    if 10 - 10: OoooooooOO * iII111i * ooOoO0o . Ii1I % I1Ii111 / I1ii11iIi11i
    if 71 - 71: Ii1I + IiII
  return ( ooO0 )
  if 10 - 10: II111iiii % o0oOOo0O0Ooo . o0oOOo0O0Ooo % iII111i
  if 2 - 2: OoooooooOO / IiII % Oo0Ooo % iIii1I11I1II1
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 62 - 62: oO0o
  if 47 - 47: I1IiiI - O0 - I1ii11iIi11i . OoOoOO00
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 98 - 98: o0oOOo0O0Ooo - OoO0O00 . I1ii11iIi11i / OOooOOo
  if 43 - 43: I1IiiI + OOooOOo + o0oOOo0O0Ooo
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 44 - 44: o0oOOo0O0Ooo % OoO0O00 . OoooooooOO
  return ( True )
  if 21 - 21: Oo0Ooo * Oo0Ooo - iII111i - O0
  if 87 - 87: OOooOOo / I1Ii111 - Ii1I + O0 - oO0o - O0
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 68 - 68: iII111i + II111iiii + I1ii11iIi11i * OOooOOo / oO0o
  if 41 - 41: OOooOOo + Oo0Ooo % I1IiiI
  if 3 - 3: ooOoO0o * Ii1I
 def print_state_change ( self , new_state ) :
  iiI1II = self . print_state ( )
  i1i111III1 = "{} -> {}" . format ( iiI1II , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   i1i111III1 = bold ( i1i111III1 , False )
   if 10 - 10: oO0o * iII111i
  return ( i1i111III1 )
  if 47 - 47: OoO0O00
  if 98 - 98: OoooooooOO - oO0o / O0
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 23 - 23: o0oOOo0O0Ooo % OoooooooOO % iIii1I11I1II1 / OoOoOO00 / I1Ii111
  if 6 - 6: Oo0Ooo
 def print_recent_rloc_probe_rtts ( self ) :
  ooOoO000oOoo = str ( self . recent_rloc_probe_rtts )
  ooOoO000oOoo = ooOoO000oOoo . replace ( "-1" , "?" )
  return ( ooOoO000oOoo )
  if 57 - 57: I11i / iII111i . i11iIiiIii % Oo0Ooo + I1ii11iIi11i / i11iIiiIii
  if 94 - 94: i1IIi * i1IIi / Ii1I
 def compute_rloc_probe_rtt ( self ) :
  i11iII11I1III = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  IiI1i1Iiii = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ i11iII11I1III ] + IiI1i1Iiii [ 0 : - 1 ]
  if 45 - 45: I1ii11iIi11i / iIii1I11I1II1 + OoO0O00 / O0 - O0 - I1Ii111
  if 88 - 88: o0oOOo0O0Ooo % I1Ii111
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 4 - 4: i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
  if 87 - 87: I1Ii111 % i11iIiiIii + O0
 def print_recent_rloc_probe_hops ( self ) :
  Ooooo = str ( self . recent_rloc_probe_hops )
  return ( Ooooo )
  if 96 - 96: iIii1I11I1II1 / i1IIi . OOooOOo + II111iiii
  if 4 - 4: I1IiiI * I11i % i11iIiiIii . I1ii11iIi11i
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
  if ( from_ttl < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   ooo0oOO0O0O0o = "!"
  else :
   ooo0oOO0O0O0o = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 96 - 96: I11i - II111iiii
   if 66 - 66: OoooooooOO * OoooooooOO
  i11iII11I1III = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + ooo0oOO0O0O0o
  IiI1i1Iiii = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ i11iII11I1III ] + IiI1i1Iiii [ 0 : - 1 ]
  if 54 - 54: iII111i / OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
  if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
 def store_rloc_probe_latencies ( self , json_telemetry ) :
  IiI111i1iI1 = lisp_decode_telemetry ( json_telemetry )
  if 3 - 3: oO0o + OoO0O00 % Oo0Ooo / OoooooooOO / i11iIiiIii . OoooooooOO
  oOi11iIIIIi = round ( float ( IiI111i1iI1 [ "etr-in" ] ) - float ( IiI111i1iI1 [ "itr-out" ] ) , 3 )
  o0o = round ( float ( IiI111i1iI1 [ "itr-in" ] ) - float ( IiI111i1iI1 [ "etr-out" ] ) , 3 )
  if 28 - 28: Ii1I + OOooOOo % IiII . i11iIiiIii - I1IiiI * Oo0Ooo
  i11iII11I1III = self . rloc_probe_latency
  self . rloc_probe_latency = str ( oOi11iIIIIi ) + "/" + str ( o0o )
  IiI1i1Iiii = self . recent_rloc_probe_latencies
  self . recent_rloc_probe_latencies = [ i11iII11I1III ] + IiI1i1Iiii [ 0 : - 1 ]
  if 2 - 2: I11i * I1ii11iIi11i + O0
  if 44 - 44: iIii1I11I1II1 / II111iiii - ooOoO0o
 def print_rloc_probe_latency ( self ) :
  return ( self . rloc_probe_latency )
  if 10 - 10: OOooOOo
  if 78 - 78: OOooOOo * I1ii11iIi11i % i11iIiiIii % o0oOOo0O0Ooo . I1ii11iIi11i / OoooooooOO
 def print_recent_rloc_probe_latencies ( self ) :
  IiII1IIii1 = str ( self . recent_rloc_probe_latencies )
  return ( IiII1IIii1 )
  if 80 - 80: IiII + i11iIiiIii . I1Ii111 * Oo0Ooo % OoooooooOO
  if 12 - 12: iII111i / I11i
 def process_rloc_probe_reply ( self , ts , nonce , eid , group , hc , ttl , jt ) :
  iIIiI11 = self
  while ( True ) :
   if ( iIIiI11 . last_rloc_probe_nonce == nonce ) : break
   iIIiI11 = iIIiI11 . next_rloc
   if ( iIIiI11 == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 70 - 70: Oo0Ooo + O0 - o0oOOo0O0Ooo
    return
    if 85 - 85: I1Ii111
    if 39 - 39: OoOoOO00 * oO0o
    if 62 - 62: OoOoOO00 / OoOoOO00 * OoO0O00
    if 38 - 38: I1Ii111 + ooOoO0o % I11i
    if 22 - 22: I1Ii111 . Ii1I % I1Ii111 * I1IiiI / iIii1I11I1II1
    if 12 - 12: Oo0Ooo / IiII % ooOoO0o / iIii1I11I1II1 % O0 / i11iIiiIii
  iIIiI11 . last_rloc_probe_reply = ts
  iIIiI11 . compute_rloc_probe_rtt ( )
  ooo0oOOOooOoO = iIIiI11 . print_state_change ( "up" )
  if ( iIIiI11 . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( iIIiI11 . rloc , True )
   iIIiI11 . state = LISP_RLOC_UP_STATE
   iIIiI11 . last_state_change = lisp_get_timestamp ( )
   I11iiI1III = lisp_map_cache . lookup_cache ( eid , True )
   if ( I11iiI1III ) : lisp_write_ipc_map_cache ( True , I11iiI1III )
   if 54 - 54: i1IIi + OoOoOO00
   if 76 - 76: OoOoOO00
   if 54 - 54: o0oOOo0O0Ooo . i11iIiiIii + I1IiiI * ooOoO0o - ooOoO0o
   if 28 - 28: I1Ii111 . i11iIiiIii * oO0o % ooOoO0o / iII111i . OOooOOo
   if 57 - 57: OoooooooOO . iIii1I11I1II1 % iII111i % Oo0Ooo
  iIIiI11 . store_rloc_probe_hops ( hc , ttl )
  if 92 - 92: I1Ii111 - Ii1I + I1Ii111
  if 8 - 8: Oo0Ooo . iII111i / i11iIiiIii + iIii1I11I1II1 - OoOoOO00
  if 1 - 1: i11iIiiIii
  if 25 - 25: OoooooooOO / II111iiii . OOooOOo * OoOoOO00 - OoooooooOO
  if ( jt ) : iIIiI11 . store_rloc_probe_latencies ( jt )
  if 8 - 8: iII111i . iIii1I11I1II1 * O0
  Oooooo0OOO = bold ( "RLOC-probe reply" , False )
  O0O0 = iIIiI11 . rloc . print_address_no_iid ( )
  OOOooOOoOO0o = bold ( str ( iIIiI11 . print_rloc_probe_rtt ( ) ) , False )
  iIIiiIi = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 5 - 5: I1ii11iIi11i / Oo0Ooo
  OoII1 = ""
  if ( iIIiI11 . rloc_next_hop != None ) :
   IiI11I111 , iii1111ii = iIIiI11 . rloc_next_hop
   OoII1 = ", nh {}({})" . format ( iii1111ii , IiI11I111 )
   if 71 - 71: iIii1I11I1II1 % ooOoO0o - I1Ii111
   if 81 - 81: i1IIi . IiII / Oo0Ooo . I1Ii111 . iIii1I11I1II1 + iIii1I11I1II1
  ooOO0OOo0oo0 = bold ( iIIiI11 . print_rloc_probe_latency ( ) , False )
  ooOO0OOo0oo0 = ", latency {}" . format ( ooOO0OOo0oo0 ) if jt else ""
  if 35 - 35: I1ii11iIi11i / OoOoOO00 / i1IIi / i11iIiiIii * iIii1I11I1II1 / i1IIi
  oO0ooOOO = green ( lisp_print_eid_tuple ( eid , group ) , False )
  if 69 - 69: OOooOOo / I1Ii111 * II111iiii
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}{}" ) . format ( Oooooo0OOO , red ( O0O0 , False ) , iIIiiIi , oO0ooOOO ,
  # o0oOOo0O0Ooo + OoO0O00 % Oo0Ooo + ooOoO0o . I11i / o0oOOo0O0Ooo
 ooo0oOOOooOoO , OOOooOOoOO0o , OoII1 , str ( hc ) + "/" + str ( ttl ) , ooOO0OOo0oo0 ) )
  if 56 - 56: iII111i * OoooooooOO . I1IiiI * oO0o - i11iIiiIii * iII111i
  if ( iIIiI11 . rloc_next_hop == None ) : return
  if 5 - 5: IiII . ooOoO0o - I1IiiI % i1IIi * OoO0O00
  if 45 - 45: I1Ii111
  if 76 - 76: OOooOOo % i1IIi + I1IiiI - iIii1I11I1II1 + O0
  if 9 - 9: oO0o % Ii1I
  iIIiI11 = None
  IiIi111I = None
  while ( True ) :
   iIIiI11 = self if iIIiI11 == None else iIIiI11 . next_rloc
   if ( iIIiI11 == None ) : break
   if ( iIIiI11 . up_state ( ) == False ) : continue
   if ( iIIiI11 . rloc_probe_rtt == - 1 ) : continue
   if 52 - 52: Oo0Ooo * iII111i - O0 . OoOoOO00 - I1IiiI
   if ( IiIi111I == None ) : IiIi111I = iIIiI11
   if ( iIIiI11 . rloc_probe_rtt < IiIi111I . rloc_probe_rtt ) : IiIi111I = iIIiI11
   if 47 - 47: II111iiii
   if 8 - 8: ooOoO0o + OoooooooOO
  if ( IiIi111I != None ) :
   IiI11I111 , iii1111ii = IiIi111I . rloc_next_hop
   OoII1 = bold ( "nh {}({})" . format ( iii1111ii , IiI11I111 ) , False )
   lprint ( "    Install host-route via best {}" . format ( OoII1 ) )
   lisp_install_host_route ( O0O0 , None , False )
   lisp_install_host_route ( O0O0 , iii1111ii , True )
   if 85 - 85: I11i / i1IIi * i11iIiiIii / I1IiiI - Ii1I
   if 25 - 25: iII111i - Oo0Ooo % iIii1I11I1II1 + o0oOOo0O0Ooo + iIii1I11I1II1
   if 63 - 63: OoOoOO00 - o0oOOo0O0Ooo % II111iiii - Ii1I
 def add_to_rloc_probe_list ( self , eid , group ) :
  O0O0 = self . rloc . print_address_no_iid ( )
  ooO0 = self . translated_port
  if ( ooO0 != 0 ) : O0O0 += ":" + str ( ooO0 )
  if 81 - 81: iII111i % OOooOOo * oO0o
  if ( O0O0 not in lisp_rloc_probe_list ) :
   lisp_rloc_probe_list [ O0O0 ] = [ ]
   if 84 - 84: iII111i - OoooooooOO + I1ii11iIi11i - I1IiiI
   if 52 - 52: oO0o / ooOoO0o / iII111i / OoOoOO00 * iIii1I11I1II1
  if ( group . is_null ( ) ) : group . instance_id = 0
  for iiiI1I , oO0ooOOO , Oo in lisp_rloc_probe_list [ O0O0 ] :
   if ( oO0ooOOO . is_exact_match ( eid ) and Oo . is_exact_match ( group ) ) :
    if ( iiiI1I == self ) :
     if ( lisp_rloc_probe_list [ O0O0 ] == [ ] ) :
      lisp_rloc_probe_list . pop ( O0O0 )
      if 74 - 74: oO0o . I1ii11iIi11i - iIii1I11I1II1
     return
     if 73 - 73: OoO0O00 / O0 . o0oOOo0O0Ooo
    lisp_rloc_probe_list [ O0O0 ] . remove ( [ iiiI1I , oO0ooOOO , Oo ] )
    break
    if 100 - 100: Ii1I . OoO0O00 % I1ii11iIi11i % O0 * Oo0Ooo - OoOoOO00
    if 15 - 15: OOooOOo - OOooOOo - OoooooooOO * OoO0O00
  lisp_rloc_probe_list [ O0O0 ] . append ( [ self , eid , group ] )
  if 12 - 12: II111iiii * I1Ii111 / I1Ii111 * oO0o * Oo0Ooo
  if 17 - 17: OoOoOO00 % I1Ii111 / iII111i * I1Ii111
  if 96 - 96: Oo0Ooo % o0oOOo0O0Ooo . OoOoOO00 % i11iIiiIii / OoooooooOO
  if 87 - 87: OoooooooOO - Ii1I . I11i / I1Ii111 . i1IIi
  if 86 - 86: i1IIi . oO0o % OOooOOo
  iIIiI11 = lisp_rloc_probe_list [ O0O0 ] [ 0 ] [ 0 ]
  if ( iIIiI11 . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 99 - 99: oO0o / I1Ii111 * oO0o * I11i
   if 38 - 38: o0oOOo0O0Ooo + OoOoOO00
   if 24 - 24: Ii1I - OOooOOo - o0oOOo0O0Ooo - I1Ii111 / OoooooooOO
 def delete_from_rloc_probe_list ( self , eid , group ) :
  O0O0 = self . rloc . print_address_no_iid ( )
  ooO0 = self . translated_port
  if ( ooO0 != 0 ) : O0O0 += ":" + str ( ooO0 )
  if ( O0O0 not in lisp_rloc_probe_list ) : return
  if 17 - 17: OoO0O00
  o0oOooooo = [ ]
  for oo0O00OOOOO in lisp_rloc_probe_list [ O0O0 ] :
   if ( oo0O00OOOOO [ 0 ] != self ) : continue
   if ( oo0O00OOOOO [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( oo0O00OOOOO [ 2 ] . is_exact_match ( group ) == False ) : continue
   o0oOooooo = oo0O00OOOOO
   break
   if 30 - 30: OoOoOO00 % Ii1I / iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * OoO0O00
  if ( o0oOooooo == [ ] ) : return
  if 25 - 25: i1IIi * oO0o . I11i
  try :
   lisp_rloc_probe_list [ O0O0 ] . remove ( o0oOooooo )
   if ( lisp_rloc_probe_list [ O0O0 ] == [ ] ) :
    lisp_rloc_probe_list . pop ( O0O0 )
    if 15 - 15: oO0o
  except :
   return
   if 45 - 45: Oo0Ooo * IiII * OoO0O00 + iIii1I11I1II1
   if 89 - 89: IiII . IiII . oO0o % iII111i
   if 27 - 27: OoOoOO00 + O0 % i1IIi - Oo0Ooo
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  oOo0OOoooO = ""
  iIIiI11 = self
  while ( True ) :
   OoOO00OO0o = iIIiI11 . last_rloc_probe
   if ( OoOO00OO0o == None ) : OoOO00OO0o = 0
   IIiiiII1 = iIIiI11 . last_rloc_probe_reply
   if ( IIiiiII1 == None ) : IIiiiII1 = 0
   OOOooOOoOO0o = iIIiI11 . print_rloc_probe_rtt ( )
   I111 = space ( 4 )
   if 45 - 45: O0 * II111iiii / i11iIiiIii
   if ( iIIiI11 . rloc_next_hop == None ) :
    oOo0OOoooO += "RLOC-Probing:\n"
   else :
    IiI11I111 , iii1111ii = iIIiI11 . rloc_next_hop
    oOo0OOoooO += "RLOC-Probing for nh {}({}):\n" . format ( iii1111ii , IiI11I111 )
    if 38 - 38: OoooooooOO % i11iIiiIii - O0 / O0
    if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
   oOo0OOoooO += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( I111 , lisp_print_elapsed ( OoOO00OO0o ) ,
   # OOooOOo % OOooOOo
 I111 , lisp_print_elapsed ( IIiiiII1 ) , OOOooOOoOO0o )
   if 8 - 8: Ii1I / ooOoO0o
   if ( trailing_linefeed ) : oOo0OOoooO += "\n"
   if 11 - 11: oO0o * OoooooooOO
   iIIiI11 = iIIiI11 . next_rloc
   if ( iIIiI11 == None ) : break
   oOo0OOoooO += "\n"
   if 88 - 88: I1Ii111 % OOooOOo - iIii1I11I1II1 / I1ii11iIi11i
  return ( oOo0OOoooO )
  if 12 - 12: ooOoO0o * I1ii11iIi11i * O0 / oO0o + iII111i - iIii1I11I1II1
  if 81 - 81: Ii1I
 def get_encap_keys ( self ) :
  ooO0 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 87 - 87: O0 % iII111i
  O0O0 = self . rloc . print_address_no_iid ( ) + ":" + ooO0
  if 57 - 57: Ii1I
  try :
   iI1iiiiiii = lisp_crypto_keys_by_rloc_encap [ O0O0 ]
   if ( iI1iiiiiii [ 1 ] ) : return ( iI1iiiiiii [ 1 ] . encrypt_key , iI1iiiiiii [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 49 - 49: I11i
   if 22 - 22: Oo0Ooo % OOooOOo + O0 - OoO0O00 % I11i * O0
   if 42 - 42: O0
 def rloc_recent_rekey ( self ) :
  ooO0 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 55 - 55: i11iIiiIii % OOooOOo
  O0O0 = self . rloc . print_address_no_iid ( ) + ":" + ooO0
  if 10 - 10: OoOoOO00 / i11iIiiIii
  try :
   III = lisp_crypto_keys_by_rloc_encap [ O0O0 ] [ 1 ]
   if ( III == None ) : return ( False )
   if ( III . last_rekey == None ) : return ( True )
   return ( time . time ( ) - III . last_rekey < 1 )
  except :
   return ( False )
   if 21 - 21: Ii1I - i1IIi / I11i + IiII
   if 44 - 44: OoooooooOO % I11i / O0
   if 94 - 94: IiII
   if 83 - 83: OoO0O00
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
  if 55 - 55: iII111i
  if 37 - 37: oO0o / o0oOOo0O0Ooo + I11i * OoO0O00 * o0oOOo0O0Ooo
 def print_mapping ( self , eid_indent , rloc_indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  oo0oOooo0O = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 33 - 33: I1Ii111
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , oo0oOooo0O , i1 ,
 len ( self . rloc_set ) ) )
  for iIIiI11 in self . rloc_set : iIIiI11 . print_rloc ( rloc_indent )
  if 97 - 97: Ii1I / iII111i - ooOoO0o + IiII * OoOoOO00 - OOooOOo
  if 43 - 43: oO0o / II111iiii - iII111i / oO0o
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 98 - 98: OoOoOO00 / OOooOOo
  if 31 - 31: II111iiii % I11i - I11i
 def print_ttl ( self ) :
  O0O00O = self . map_cache_ttl
  if ( O0O00O == None ) : return ( "forever" )
  if 17 - 17: iII111i . IiII + OOooOOo % I1Ii111 % i11iIiiIii
  if ( O0O00O >= 3600 ) :
   if ( ( O0O00O % 3600 ) == 0 ) :
    O0O00O = str ( old_div ( O0O00O , 3600 ) ) + " hours"
   else :
    O0O00O = str ( O0O00O * 60 ) + " mins"
    if 100 - 100: i11iIiiIii - O0 . OoO0O00 / O0 - Ii1I - IiII
  elif ( O0O00O >= 60 ) :
   if ( ( O0O00O % 60 ) == 0 ) :
    O0O00O = str ( old_div ( O0O00O , 60 ) ) + " mins"
   else :
    O0O00O = str ( O0O00O ) + " secs"
    if 72 - 72: Ii1I % O0 + II111iiii . i11iIiiIii
  else :
   O0O00O = str ( O0O00O ) + " secs"
   if 66 - 66: II111iiii % I1IiiI
  return ( O0O00O )
  if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 + I1Ii111 * OOooOOo . I1IiiI
  if 96 - 96: I1ii11iIi11i
 def refresh ( self ) :
  if ( self . group . is_null ( ) ) : return ( self . refresh_unicast ( ) )
  return ( self . refresh_multicast ( ) )
  if 37 - 37: OoO0O00 % o0oOOo0O0Ooo * O0 * O0 + iII111i
  if 18 - 18: i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % oO0o * Ii1I / I1IiiI
 def refresh_unicast ( self ) :
  return ( self . is_active ( ) and self . has_ttl_elapsed ( ) and
 self . gleaned == False )
  if 46 - 46: o0oOOo0O0Ooo . ooOoO0o / Ii1I
  if 97 - 97: Ii1I . Oo0Ooo - O0 - I1Ii111 . i1IIi
 def refresh_multicast ( self ) :
  if 47 - 47: IiII * ooOoO0o - i1IIi % OoOoOO00 * i11iIiiIii . OoooooooOO
  if 84 - 84: OoOoOO00 / IiII - i1IIi - I1IiiI * OOooOOo
  if 35 - 35: II111iiii
  if 28 - 28: I1Ii111 + IiII + I1ii11iIi11i . Ii1I
  if 82 - 82: ooOoO0o - ooOoO0o . Ii1I . i11iIiiIii % Ii1I + OOooOOo
  i1i111Iiiiiii = int ( ( time . time ( ) - self . uptime ) % self . map_cache_ttl )
  IIiI1I1i = ( i1i111Iiiiiii in [ 0 , 1 , 2 ] )
  if ( IIiI1I1i == False ) : return ( False )
  if 37 - 37: OoO0O00 * OoO0O00 % iIii1I11I1II1 % II111iiii + Oo0Ooo
  if 4 - 4: i11iIiiIii + OoOoOO00 - Ii1I * i1IIi * i11iIiiIii
  if 46 - 46: IiII . iII111i % OoooooooOO % IiII + Ii1I - OoooooooOO
  if 23 - 23: O0 - iII111i
  IiIiI1I1Ii = ( ( time . time ( ) - self . last_multicast_map_request ) <= 2 )
  if ( IiIiI1I1Ii ) : return ( False )
  if 51 - 51: i1IIi % oO0o . iII111i % i1IIi
  self . last_multicast_map_request = lisp_get_timestamp ( )
  return ( True )
  if 74 - 74: O0 / ooOoO0o - OOooOOo / OoO0O00 % I11i * II111iiii
  if 42 - 42: I1IiiI * Ii1I
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  i1i111Iiiiiii = time . time ( ) - self . last_refresh_time
  if ( i1i111Iiiiiii >= self . map_cache_ttl ) : return ( True )
  if 95 - 95: OoO0O00 * i1IIi
  if 43 - 43: Oo0Ooo % iII111i % O0 + i1IIi
  if 45 - 45: ooOoO0o
  if 89 - 89: iIii1I11I1II1 . I1Ii111
  if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
  O0ooo = self . map_cache_ttl - ( old_div ( self . map_cache_ttl , 10 ) )
  if ( i1i111Iiiiiii >= O0ooo ) : return ( True )
  return ( False )
  if 33 - 33: Ii1I
  if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  i1i111Iiiiiii = time . time ( ) - self . stats . last_increment
  return ( i1i111Iiiiiii <= 60 )
  if 40 - 40: I1IiiI / OOooOOo * Ii1I
  if 98 - 98: I1IiiI
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 4 - 4: I1IiiI % O0 / Oo0Ooo / O0
  if 90 - 90: ooOoO0o - O0 . IiII - O0 . iIii1I11I1II1
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 42 - 42: I1ii11iIi11i
  if 51 - 51: iII111i % i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for iIIiI11 in self . best_rloc_set :
   iIIiI11 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 14 - 14: I1ii11iIi11i . OoO0O00
   if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
   if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
 def build_best_rloc_set ( self ) :
  ii1i111 = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 58 - 58: Ii1I * oO0o . I1ii11iIi11i % I1IiiI - ooOoO0o
  if 100 - 100: i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
  if 76 - 76: OoooooooOO - O0
  if 17 - 17: Oo0Ooo % I1Ii111 . oO0o - O0
  iiiIIi1Iii = 256
  for iIIiI11 in self . rloc_set :
   if ( iIIiI11 . up_state ( ) ) : iiiIIi1Iii = min ( iIIiI11 . priority , iiiIIi1Iii )
   if 39 - 39: iII111i - I1ii11iIi11i % ooOoO0o - OoOoOO00 + OoOoOO00
   if 97 - 97: I11i * I1Ii111 * oO0o
   if 3 - 3: iIii1I11I1II1 / ooOoO0o + ooOoO0o + I11i
   if 20 - 20: OOooOOo - i1IIi / i11iIiiIii
   if 60 - 60: I11i * I11i + Oo0Ooo . IiII / iII111i % OoooooooOO
   if 35 - 35: O0 . Oo0Ooo / Oo0Ooo / Ii1I / i1IIi * I11i
   if 93 - 93: O0 + IiII
   if 91 - 91: iIii1I11I1II1
   if 66 - 66: i1IIi . ooOoO0o
   if 84 - 84: O0 % ooOoO0o / I1Ii111
  for iIIiI11 in self . rloc_set :
   if ( iIIiI11 . priority <= iiiIIi1Iii ) :
    if ( iIIiI11 . unreach_state ( ) and iIIiI11 . last_rloc_probe == None ) :
     iIIiI11 . last_rloc_probe = lisp_get_timestamp ( )
     if 75 - 75: I11i - iII111i . O0
    self . best_rloc_set . append ( iIIiI11 )
    if 52 - 52: I1ii11iIi11i
    if 22 - 22: I1ii11iIi11i - i1IIi / OOooOOo . o0oOOo0O0Ooo . oO0o
    if 9 - 9: ooOoO0o - I1Ii111 + IiII . iII111i
    if 52 - 52: I1Ii111 + oO0o % II111iiii - i1IIi
    if 32 - 32: I1Ii111 % ooOoO0o + I1Ii111 / I1ii11iIi11i - o0oOOo0O0Ooo + ooOoO0o
    if 46 - 46: OoO0O00 % OoO0O00 . O0 + II111iiii
    if 42 - 42: OOooOOo * I1Ii111
    if 53 - 53: II111iiii % OOooOOo / I1ii11iIi11i * OoOoOO00 % I1ii11iIi11i * iII111i
  for iIIiI11 in ii1i111 :
   if ( iIIiI11 . priority < iiiIIi1Iii ) : continue
   iIIiI11 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 91 - 91: iII111i . OoooooooOO
  for iIIiI11 in self . best_rloc_set :
   if ( iIIiI11 . rloc . is_null ( ) ) : continue
   iIIiI11 . add_to_rloc_probe_list ( self . eid , self . group )
   if 90 - 90: i11iIiiIii - I1IiiI
   if 39 - 39: iII111i % OoooooooOO % Ii1I % I1IiiI
   if 63 - 63: OoO0O00 - I1Ii111 - II111iiii
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  Oo00oo = lisp_packet . packet
  OoOooO00 = lisp_packet . inner_version
  i1iIii = len ( self . best_rloc_set )
  if ( i1iIii == 0 ) :
   self . stats . increment ( len ( Oo00oo ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 66 - 66: i1IIi + I1IiiI
   if 45 - 45: I1Ii111 . iII111i + OoO0O00 - O0
  oO00o00oo = 4 if lisp_load_split_pings else 0
  II1Iii1iI = lisp_packet . hash_ports ( )
  if ( OoOooO00 == 4 ) :
   for iIi1iIIIiIiI in range ( 8 + oO00o00oo ) :
    II1Iii1iI = II1Iii1iI ^ struct . unpack ( "B" , Oo00oo [ iIi1iIIIiIiI + 12 : iIi1iIIIiIiI + 13 ] ) [ 0 ]
    if 12 - 12: OoooooooOO . OOooOOo
  elif ( OoOooO00 == 6 ) :
   for iIi1iIIIiIiI in range ( 0 , 32 + oO00o00oo , 4 ) :
    II1Iii1iI = II1Iii1iI ^ struct . unpack ( "I" , Oo00oo [ iIi1iIIIiIiI + 8 : iIi1iIIIiIiI + 12 ] ) [ 0 ]
    if 83 - 83: I1ii11iIi11i * I1Ii111 . o0oOOo0O0Ooo
   II1Iii1iI = ( II1Iii1iI >> 16 ) + ( II1Iii1iI & 0xffff )
   II1Iii1iI = ( II1Iii1iI >> 8 ) + ( II1Iii1iI & 0xff )
  else :
   for iIi1iIIIiIiI in range ( 0 , 12 + oO00o00oo , 4 ) :
    II1Iii1iI = II1Iii1iI ^ struct . unpack ( "I" , Oo00oo [ iIi1iIIIiIiI : iIi1iIIIiIiI + 4 ] ) [ 0 ]
    if 86 - 86: I1ii11iIi11i * iII111i
    if 37 - 37: i1IIi / I11i . iII111i - II111iiii
    if 66 - 66: Ii1I + OoOoOO00 - I11i / o0oOOo0O0Ooo + iIii1I11I1II1
  if ( lisp_data_plane_logging ) :
   O0O0OO0o0 = [ ]
   for iiiI1I in self . best_rloc_set :
    if ( iiiI1I . rloc . is_null ( ) ) : continue
    O0O0OO0o0 . append ( [ iiiI1I . rloc . print_address_no_iid ( ) , iiiI1I . print_state ( ) ] )
    if 23 - 23: IiII - OoOoOO00 . OoO0O00
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( II1Iii1iI ) , II1Iii1iI % i1iIii , red ( str ( O0O0OO0o0 ) , False ) ) )
   if 81 - 81: I1Ii111 / I1ii11iIi11i
   if 69 - 69: I1IiiI
   if 79 - 79: ooOoO0o
   if 83 - 83: I1Ii111 % II111iiii
   if 89 - 89: Ii1I . I11i
   if 98 - 98: I1Ii111 / O0 % ooOoO0o
  iIIiI11 = self . best_rloc_set [ II1Iii1iI % i1iIii ]
  if 36 - 36: iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
  if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
  if 97 - 97: i11iIiiIii / O0 % OoO0O00
  if 88 - 88: i1IIi . I1IiiI
  if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
  I111Ii1I1I1iI = lisp_get_echo_nonce ( iIIiI11 . rloc , None )
  if ( I111Ii1I1I1iI ) :
   I111Ii1I1I1iI . change_state ( iIIiI11 )
   if ( iIIiI11 . no_echoed_nonce_state ( ) ) :
    I111Ii1I1I1iI . request_nonce_sent = None
    if 51 - 51: oO0o + Ii1I * Ii1I * I1ii11iIi11i % I11i - I1ii11iIi11i
    if 15 - 15: i1IIi / OoO0O00 - Oo0Ooo
    if 74 - 74: o0oOOo0O0Ooo % Ii1I - II111iiii / ooOoO0o
    if 84 - 84: I1IiiI + OOooOOo
    if 80 - 80: OOooOOo / OoOoOO00
    if 93 - 93: OOooOOo
  if ( iIIiI11 . up_state ( ) == False ) :
   OooOooo = II1Iii1iI % i1iIii
   OOOooo0OooOoO = ( OooOooo + 1 ) % i1iIii
   while ( OOOooo0OooOoO != OooOooo ) :
    iIIiI11 = self . best_rloc_set [ OOOooo0OooOoO ]
    if ( iIIiI11 . up_state ( ) ) : break
    OOOooo0OooOoO = ( OOOooo0OooOoO + 1 ) % i1iIii
    if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
   if ( OOOooo0OooOoO == OooOooo ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
    if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
    if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
    if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
    if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
    if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
  iIIiI11 . stats . increment ( len ( Oo00oo ) )
  if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
  if 91 - 91: II111iiii * o0oOOo0O0Ooo
  if 20 - 20: iIii1I11I1II1 % Oo0Ooo * OoOoOO00 % IiII
  if 93 - 93: I11i * iIii1I11I1II1 * oO0o
  if ( iIIiI11 . rle_name and iIIiI11 . rle == None ) :
   if ( iIIiI11 . rle_name in lisp_rle_list ) :
    iIIiI11 . rle = lisp_rle_list [ iIIiI11 . rle_name ]
    if 74 - 74: I1IiiI
    if 39 - 39: iII111i * IiII / iII111i * IiII % I1ii11iIi11i
  if ( iIIiI11 . rle ) : return ( [ None , None , None , None , iIIiI11 . rle , None ] )
  if 27 - 27: iIii1I11I1II1 . ooOoO0o
  if 74 - 74: i1IIi % OoOoOO00
  if 98 - 98: IiII * OOooOOo / O0 - I1Ii111 . I1Ii111 + OOooOOo
  if 61 - 61: iII111i * Ii1I % Ii1I + I1IiiI
  if ( iIIiI11 . elp and iIIiI11 . elp . use_elp_node ) :
   return ( [ iIIiI11 . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 23 - 23: oO0o + I1Ii111 / OoooooooOO / O0 + IiII
   if 80 - 80: i11iIiiIii - OoooooooOO + II111iiii / i1IIi - oO0o
   if 100 - 100: Ii1I
   if 73 - 73: IiII - O0
   if 54 - 54: OOooOOo
  Ii1IIIIi = None if ( iIIiI11 . rloc . is_null ( ) ) else iIIiI11 . rloc
  ooO0 = iIIiI11 . translated_port
  oOoO0OooO0O = self . action if ( Ii1IIIIi == None ) else None
  if 100 - 100: I11i . OOooOOo - II111iiii % I11i % iIii1I11I1II1
  if 4 - 4: o0oOOo0O0Ooo . iII111i / O0
  if 13 - 13: iII111i / IiII
  if 28 - 28: iII111i
  if 97 - 97: iIii1I11I1II1
  o0Oo0o = None
  if ( I111Ii1I1I1iI and I111Ii1I1I1iI . request_nonce_timeout ( ) == False ) :
   o0Oo0o = I111Ii1I1I1iI . get_request_or_echo_nonce ( ipc_socket , Ii1IIIIi )
   if 18 - 18: OOooOOo
   if 87 - 87: O0 - i1IIi . I11i / Ii1I % iIii1I11I1II1
   if 57 - 57: I11i . IiII / iIii1I11I1II1 - ooOoO0o
   if 50 - 50: O0 / II111iiii
   if 94 - 94: O0 + O0 % I1ii11iIi11i % i1IIi
  return ( [ Ii1IIIIi , ooO0 , o0Oo0o , oOoO0OooO0O , None , iIIiI11 ] )
  if 15 - 15: I1IiiI
  if 48 - 48: Ii1I * IiII % O0 - II111iiii
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 66 - 66: iIii1I11I1II1 / OOooOOo
  if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
  if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
  if 67 - 67: I1Ii111
  if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
  for OOOoOoo in self . rloc_set :
   for iIIiI11 in rloc_address_set :
    if ( iIIiI11 . is_exact_match ( OOOoOoo . rloc ) == False ) : continue
    iIIiI11 = None
    break
    if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
   if ( iIIiI11 == rloc_address_set [ - 1 ] ) : return ( False )
   if 46 - 46: I11i - ooOoO0o . I1IiiI
  return ( True )
  if 36 - 36: I11i + OoO0O00 * O0 * OoOoOO00 * iII111i
  if 90 - 90: i11iIiiIii / i1IIi
 def get_rloc ( self , rloc ) :
  for OOOoOoo in self . rloc_set :
   iiiI1I = OOOoOoo . rloc
   if ( rloc . is_exact_match ( iiiI1I ) ) : return ( OOOoOoo )
   if 35 - 35: Ii1I . I11i / oO0o / OoOoOO00
  return ( None )
  if 5 - 5: I1ii11iIi11i . o0oOOo0O0Ooo * iII111i * I1ii11iIi11i % I1Ii111
  if 83 - 83: iIii1I11I1II1 * o0oOOo0O0Ooo % i11iIiiIii + OoO0O00 . O0
 def get_rloc_by_interface ( self , interface ) :
  for OOOoOoo in self . rloc_set :
   if ( OOOoOoo . interface == interface ) : return ( OOOoOoo )
   if 87 - 87: II111iiii - iIii1I11I1II1 % I11i % I1IiiI . o0oOOo0O0Ooo
  return ( None )
  if 52 - 52: i11iIiiIii . oO0o / OoooooooOO - OoO0O00
  if 7 - 7: I1IiiI * I1IiiI % OOooOOo % iIii1I11I1II1 * OoO0O00 . o0oOOo0O0Ooo
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   OoO0oO = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( OoO0oO == None ) :
    OoO0oO = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , OoO0oO )
    if 32 - 32: ooOoO0o / i1IIi
   OoO0oO . add_source_entry ( self )
   if 55 - 55: oO0o . OoOoOO00 + OoooooooOO - ooOoO0o . OoooooooOO
   if 77 - 77: I1IiiI
   if 16 - 16: I1IiiI + ooOoO0o - O0 / o0oOOo0O0Ooo
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   I11iiI1III = lisp_map_cache . lookup_cache ( self . group , True )
   if ( I11iiI1III == None ) :
    I11iiI1III = lisp_mapping ( self . group , self . group , [ ] )
    I11iiI1III . eid . copy_address ( self . group )
    I11iiI1III . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , I11iiI1III )
    if 36 - 36: Oo0Ooo - OoOoOO00 - II111iiii
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( I11iiI1III . group )
   I11iiI1III . add_source_entry ( self )
   if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
  if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    Oo0OoOI1I11iII1I1i = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( Oo0OoOI1I11iII1I1i ) )
    if 73 - 73: Ii1I * OoooooooOO + iIii1I11I1II1
  else :
   I11iiI1III = lisp_map_cache . lookup_cache ( self . group , True )
   if ( I11iiI1III == None ) : return
   if 91 - 91: Oo0Ooo * iIii1I11I1II1 / ooOoO0o . Oo0Ooo
   O0Ooo0 = I11iiI1III . lookup_source_cache ( self . eid , True )
   if ( O0Ooo0 == None ) : return
   if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
   I11iiI1III . source_cache . delete_cache ( self . eid )
   if ( I11iiI1III . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 99 - 99: II111iiii + O0
    if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
    if 88 - 88: Oo0Ooo . iII111i
    if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 9 - 9: OoOoOO00 % i1IIi + IiII
  if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
  if 95 - 95: ooOoO0o
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
  if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  oooo = "," + str ( self . secondary_iid )
  return ( prefix . replace ( oooo , oooo + "*" ) )
  if 32 - 32: OoOoOO00 % i11iIiiIii
  if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
 def increment_decap_stats ( self , packet ) :
  ooO0 = packet . udp_dport
  if ( ooO0 == LISP_DATA_PORT ) :
   iIIiI11 = self . get_rloc ( packet . outer_dest )
  else :
   if 44 - 44: I1Ii111 + ooOoO0o
   if 15 - 15: I11i + OoO0O00 + OoOoOO00
   if 100 - 100: I1Ii111
   if 78 - 78: OoOoOO00
   for iIIiI11 in self . rloc_set :
    if ( iIIiI11 . translated_port != 0 ) : break
    if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
    if 36 - 36: OoOoOO00 * II111iiii . OoooooooOO * I11i . I11i
  if ( iIIiI11 != None ) : iIIiI11 . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 13 - 13: I1ii11iIi11i * II111iiii
  if 93 - 93: OOooOOo / O0 - o0oOOo0O0Ooo + OoO0O00 * I1IiiI
 def rtrs_in_rloc_set ( self ) :
  for iIIiI11 in self . rloc_set :
   if ( iIIiI11 . is_rtr ( ) ) : return ( True )
   if 53 - 53: I1ii11iIi11i
  return ( False )
  if 91 - 91: o0oOOo0O0Ooo - I1ii11iIi11i . i1IIi
  if 64 - 64: ooOoO0o
 def add_recent_source ( self , source ) :
  self . recent_sources [ source . print_address ( ) ] = lisp_get_timestamp ( )
  if 23 - 23: Oo0Ooo . OoO0O00
  if 49 - 49: oO0o % i11iIiiIii * Ii1I
  if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
class lisp_dynamic_eid ( object ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 61 - 61: O0 - i11iIiiIii * o0oOOo0O0Ooo
  if 92 - 92: Oo0Ooo + OOooOOo - i11iIiiIii
 def get_timeout ( self , interface ) :
  try :
   IiIII1i1IiI = lisp_myinterfaces [ interface ]
   self . timeout = IiIII1i1IiI . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 20 - 20: iII111i . I1Ii111 % o0oOOo0O0Ooo / I1ii11iIi11i . iII111i . OoOoOO00
   if 27 - 27: I11i - o0oOOo0O0Ooo + Ii1I * OoooooooOO * i1IIi % OoOoOO00
   if 83 - 83: iIii1I11I1II1 - i1IIi - Ii1I % iII111i
   if 69 - 69: I1Ii111 * oO0o * I1IiiI
class lisp_group_mapping ( object ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
  if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
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
def lisp_is_group_more_specific ( group_str , group_mapping ) :
 oooo = group_mapping . group_prefix . instance_id
 OOOoOo0o0Ooo = group_mapping . group_prefix . mask_len
 oo0oOooo0O = lisp_address ( LISP_AFI_IPV4 , group_str , 32 , oooo )
 if ( oo0oOooo0O . is_more_specific ( group_mapping . group_prefix ) ) : return ( OOOoOo0o0Ooo )
 return ( - 1 )
 if 77 - 77: o0oOOo0O0Ooo + I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
 if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
 if 43 - 43: OOooOOo . O0
 if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
 if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
 if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
 if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
def lisp_lookup_group ( group ) :
 O0O0OO0o0 = None
 for I1I11I1IIi in list ( lisp_group_mapping_list . values ( ) ) :
  OOOoOo0o0Ooo = lisp_is_group_more_specific ( group , I1I11I1IIi )
  if ( OOOoOo0o0Ooo == - 1 ) : continue
  if ( O0O0OO0o0 == None or OOOoOo0o0Ooo > O0O0OO0o0 . group_prefix . mask_len ) : O0O0OO0o0 = I1I11I1IIi
  if 3 - 3: i1IIi + OoOoOO00 - OoOoOO00
 return ( O0O0OO0o0 )
 if 85 - 85: o0oOOo0O0Ooo / o0oOOo0O0Ooo + Oo0Ooo * II111iiii + Ii1I * Ii1I
 if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 86 - 86: Ii1I
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
  if 69 - 69: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
  if 1 - 1: Ii1I
  if 43 - 43: o0oOOo0O0Ooo
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
  if 78 - 78: I1Ii111 % i1IIi * I11i
  if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
  if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
 def print_flags ( self , html ) :
  if ( html == False ) :
   oOo0OOoooO = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # ooOoO0o
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   OO0oOooo = self . print_flags ( False )
   OO0oOooo = OO0oOooo . split ( "-" )
   oOo0OOoooO = ""
   for I11IIo0oOooO0O in OO0oOooo :
    iiiIIi1 = lisp_site_flags [ I11IIo0oOooO0O . upper ( ) ]
    iiiIIi1 = iiiIIi1 . format ( "" if I11IIo0oOooO0O . isupper ( ) else "not " )
    oOo0OOoooO += lisp_span ( I11IIo0oOooO0O , iiiIIi1 )
    if ( I11IIo0oOooO0O . lower ( ) != "n" ) : oOo0OOoooO += "-"
    if 35 - 35: o0oOOo0O0Ooo + I11i % O0 % iII111i * I11i + O0
    if 11 - 11: OoOoOO00 - I1Ii111 / OOooOOo
  return ( oOo0OOoooO )
  if 12 - 12: IiII + OoO0O00
  if 18 - 18: I1Ii111 / OoooooooOO
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 77 - 77: oO0o % I11i + i1IIi + Oo0Ooo + I1Ii111 + OoO0O00
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 78 - 78: O0 . oO0o
  if 72 - 72: O0 - IiII
 def build_sort_key ( self ) :
  I111i1iI = lisp_cache ( )
  iiii11I1 , III = I111i1iI . build_key ( self . eid )
  OOo00OO = ""
  if ( self . group . is_null ( ) == False ) :
   Oo0O0O , OOo00OO = I111i1iI . build_key ( self . group )
   OOo00OO = "-" + OOo00OO [ 0 : 12 ] + "-" + str ( Oo0O0O ) + "-" + OOo00OO [ 12 : : ]
   if 52 - 52: i11iIiiIii + i11iIiiIii - i1IIi . i11iIiiIii - ooOoO0o + OoooooooOO
  III = III [ 0 : 12 ] + "-" + str ( iiii11I1 ) + "-" + III [ 12 : : ] + OOo00OO
  del ( I111i1iI )
  return ( III )
  if 50 - 50: OoooooooOO . OoOoOO00 * o0oOOo0O0Ooo / O0 % I1IiiI + Oo0Ooo
  if 75 - 75: OoO0O00 * Oo0Ooo . OOooOOo . OoO0O00 * Oo0Ooo * iIii1I11I1II1
 def merge_in_site_eid ( self , child ) :
  IIII1II1 = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   IIII1II1 = self . merge_rles_in_site_eid ( )
   if 10 - 10: OoooooooOO . I11i / I1Ii111 % i11iIiiIii % iIii1I11I1II1
   if 65 - 65: IiII % OOooOOo / o0oOOo0O0Ooo * II111iiii - oO0o
   if 38 - 38: I1Ii111 * o0oOOo0O0Ooo
   if 32 - 32: iII111i / Ii1I / I1Ii111 - OoOoOO00 / OOooOOo * OoO0O00
   if 32 - 32: I1ii11iIi11i + ooOoO0o . i1IIi * iIii1I11I1II1 - I1IiiI
   if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
  return ( IIII1II1 )
  if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
  if 17 - 17: OOooOOo / i11iIiiIii - i11iIiiIii . II111iiii . ooOoO0o
 def copy_rloc_records ( self ) :
  IIiiiIiI = [ ]
  for OOOoOoo in self . registered_rlocs :
   IIiiiIiI . append ( copy . deepcopy ( OOOoOoo ) )
   if 16 - 16: OoO0O00 . Oo0Ooo + oO0o + Ii1I - OoooooooOO . ooOoO0o
  return ( IIiiiIiI )
  if 44 - 44: O0
  if 91 - 91: ooOoO0o * OoOoOO00 * i1IIi * o0oOOo0O0Ooo - ooOoO0o % Ii1I
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for i1iI11i in list ( self . individual_registrations . values ( ) ) :
   if ( self . site_id != i1iI11i . site_id ) : continue
   if ( i1iI11i . registered == False ) : continue
   self . registered_rlocs += i1iI11i . copy_rloc_records ( )
   if 46 - 46: O0 / iIii1I11I1II1
   if 65 - 65: OOooOOo
   if 88 - 88: OOooOOo * iIii1I11I1II1 + I11i . iII111i
   if 55 - 55: I1IiiI + Ii1I % I1ii11iIi11i + iIii1I11I1II1
   if 64 - 64: i1IIi / O0 - oO0o
   if 7 - 7: IiII . IiII * Ii1I
  IIiiiIiI = [ ]
  for OOOoOoo in self . registered_rlocs :
   if ( OOOoOoo . rloc . is_null ( ) or len ( IIiiiIiI ) == 0 ) :
    IIiiiIiI . append ( OOOoOoo )
    continue
    if 1 - 1: i11iIiiIii
   for OOiIII1 in IIiiiIiI :
    if ( OOiIII1 . rloc . is_null ( ) ) : continue
    if ( OOOoOoo . rloc . is_exact_match ( OOiIII1 . rloc ) ) : break
    if 20 - 20: o0oOOo0O0Ooo . I1Ii111 + O0
   if ( OOiIII1 == IIiiiIiI [ - 1 ] ) : IIiiiIiI . append ( OOOoOoo )
   if 99 - 99: O0 / IiII . oO0o
  self . registered_rlocs = IIiiiIiI
  if 18 - 18: OoooooooOO * OoO0O00 * I1Ii111
  if 12 - 12: i11iIiiIii / iIii1I11I1II1 . I11i % I1Ii111 * ooOoO0o % ooOoO0o
  if 13 - 13: i1IIi . ooOoO0o . ooOoO0o
  if 24 - 24: iIii1I11I1II1
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
  if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
 def merge_rles_in_site_eid ( self ) :
  if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
  if 62 - 62: o0oOOo0O0Ooo
  if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
  if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
  I1oo00O0 = { }
  for OOOoOoo in self . registered_rlocs :
   if ( OOOoOoo . rle == None ) : continue
   for iIIi in OOOoOoo . rle . rle_nodes :
    IiI = iIIi . address . print_address_no_iid ( )
    I1oo00O0 [ IiI ] = iIIi . address
    if 5 - 5: OoooooooOO % I1ii11iIi11i - I1Ii111
   break
   if 28 - 28: OOooOOo
   if 87 - 87: o0oOOo0O0Ooo - Ii1I + I11i
   if 69 - 69: iII111i . Ii1I * OoOoOO00 / OoOoOO00 / OoOoOO00 + OoOoOO00
   if 17 - 17: I1ii11iIi11i * OoOoOO00 + II111iiii
   if 28 - 28: iIii1I11I1II1 % Oo0Ooo * I1Ii111 - IiII / OoO0O00 * OoooooooOO
  self . merge_rlocs_in_site_eid ( )
  if 88 - 88: O0
  if 15 - 15: Oo0Ooo % I11i * O0
  if 61 - 61: I1ii11iIi11i - ooOoO0o / OoOoOO00 % OOooOOo * i1IIi . IiII
  if 27 - 27: I1ii11iIi11i % iII111i . Oo0Ooo * iIii1I11I1II1
  if 40 - 40: I11i
  if 58 - 58: o0oOOo0O0Ooo / OOooOOo . oO0o % ooOoO0o
  if 33 - 33: I1IiiI * I1ii11iIi11i . OoO0O00 - I1Ii111 . OoO0O00
  if 79 - 79: ooOoO0o
  oo0OOo0Oo = [ ]
  for OOOoOoo in self . registered_rlocs :
   if ( self . registered_rlocs . index ( OOOoOoo ) == 0 ) :
    oo0OOo0Oo . append ( OOOoOoo )
    continue
    if 15 - 15: ooOoO0o + I1ii11iIi11i / I1IiiI - Oo0Ooo - Ii1I / I11i
   if ( OOOoOoo . rle == None ) : oo0OOo0Oo . append ( OOOoOoo )
   if 37 - 37: ooOoO0o / II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - Ii1I
  self . registered_rlocs = oo0OOo0Oo
  if 47 - 47: I1ii11iIi11i
  if 26 - 26: iII111i
  if 55 - 55: I1ii11iIi11i . ooOoO0o * Oo0Ooo + I1Ii111
  if 59 - 59: iII111i - OOooOOo - OoO0O00 . I1IiiI % o0oOOo0O0Ooo + iII111i
  if 10 - 10: iIii1I11I1II1 - Ii1I
  if 84 - 84: iII111i
  if 21 - 21: i11iIiiIii
  ooo0o0O = lisp_rle ( "" )
  iIi1i1I = { }
  oOo = None
  for i1iI11i in list ( self . individual_registrations . values ( ) ) :
   if ( i1iI11i . registered == False ) : continue
   iiI11Ii11iiI = i1iI11i . registered_rlocs [ 0 ] . rle
   if ( iiI11Ii11iiI == None ) : continue
   if 66 - 66: IiII
   oOo = i1iI11i . registered_rlocs [ 0 ] . rloc_name
   for oOo0o0 in iiI11Ii11iiI . rle_nodes :
    IiI = oOo0o0 . address . print_address_no_iid ( )
    if ( IiI in iIi1i1I ) : break
    if 9 - 9: I1ii11iIi11i + OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
    iIIi = lisp_rle_node ( )
    iIIi . address . copy_address ( oOo0o0 . address )
    iIIi . level = oOo0o0 . level
    iIIi . rloc_name = oOo
    ooo0o0O . rle_nodes . append ( iIIi )
    iIi1i1I [ IiI ] = oOo0o0 . address
    if 23 - 23: iII111i / iIii1I11I1II1
    if 5 - 5: O0
    if 64 - 64: i1IIi * i1IIi . iII111i - O0 - oO0o % OoooooooOO
    if 14 - 14: Ii1I % OoO0O00 % I1Ii111 * O0
    if 8 - 8: I1IiiI - i11iIiiIii * I1IiiI
    if 6 - 6: O0 - OoOoOO00 - i11iIiiIii / iII111i
  if ( len ( ooo0o0O . rle_nodes ) == 0 ) : ooo0o0O = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = ooo0o0O
   if ( oOo ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 63 - 63: OOooOOo
   if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
   if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
   if 96 - 96: iIii1I11I1II1 * II111iiii . iIii1I11I1II1
   if 13 - 13: Ii1I - OoOoOO00 . Ii1I
  if ( list ( I1oo00O0 . keys ( ) ) == list ( iIi1i1I . keys ( ) ) ) : return ( False )
  if 7 - 7: Ii1I - I11i / I1ii11iIi11i + iII111i
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # ooOoO0o * I1IiiI % IiII
 list ( I1oo00O0 . keys ( ) ) , list ( iIi1i1I . keys ( ) ) ) )
  if 62 - 62: OoooooooOO . OoooooooOO / I11i % OoOoOO00
  return ( True )
  if 2 - 2: IiII % I1ii11iIi11i * OoO0O00 + Oo0Ooo * iII111i
  if 85 - 85: OOooOOo * I1IiiI - iIii1I11I1II1 - OoOoOO00 + ooOoO0o . OoO0O00
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   ooOO00o = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( ooOO00o == None ) :
    ooOO00o = lisp_site_eid ( self . site )
    ooOO00o . eid . copy_address ( self . group )
    ooOO00o . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , ooOO00o )
    if 46 - 46: OoO0O00 * I1Ii111 . O0
    if 86 - 86: i11iIiiIii . Ii1I / OoOoOO00 / I11i * i1IIi
    if 40 - 40: o0oOOo0O0Ooo
    if 33 - 33: i11iIiiIii + I1Ii111 % I1ii11iIi11i - I1Ii111 * OoO0O00
    if 1 - 1: II111iiii / I1IiiI + II111iiii % II111iiii - I1Ii111
    ooOO00o . parent_for_more_specifics = self . parent_for_more_specifics
    if 24 - 24: I11i / Oo0Ooo / i1IIi + IiII
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( ooOO00o . group )
   ooOO00o . add_source_entry ( self )
   if 10 - 10: I11i - IiII / II111iiii / oO0o % O0 / I1Ii111
   if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
   if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   ooOO00o = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( ooOO00o == None ) : return
   if 45 - 45: OOooOOo - OOooOOo % iII111i - IiII . O0
   i1iI11i = ooOO00o . lookup_source_cache ( self . eid , True )
   if ( i1iI11i == None ) : return
   if 6 - 6: iIii1I11I1II1 * II111iiii / O0 % IiII - I1Ii111
   if ( ooOO00o . source_cache == None ) : return
   if 64 - 64: ooOoO0o
   ooOO00o . source_cache . delete_cache ( self . eid )
   if ( ooOO00o . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 28 - 28: i11iIiiIii - IiII * I1ii11iIi11i + IiII * iII111i
    if 75 - 75: o0oOOo0O0Ooo * OoOoOO00 % I1ii11iIi11i + OOooOOo . II111iiii
    if 12 - 12: ooOoO0o
    if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
  if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 78 - 78: i1IIi
  if 25 - 25: Ii1I * II111iiii / OoOoOO00
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
  if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
  if 15 - 15: i11iIiiIii
 def inherit_from_ams_parent ( self ) :
  O0oOoO00O = self . parent_for_more_specifics
  if ( O0oOoO00O == None ) : return
  self . force_proxy_reply = O0oOoO00O . force_proxy_reply
  self . force_nat_proxy_reply = O0oOoO00O . force_nat_proxy_reply
  self . force_ttl = O0oOoO00O . force_ttl
  self . pitr_proxy_reply_drop = O0oOoO00O . pitr_proxy_reply_drop
  self . proxy_reply_action = O0oOoO00O . proxy_reply_action
  self . echo_nonce_capable = O0oOoO00O . echo_nonce_capable
  self . policy = O0oOoO00O . policy
  self . require_signature = O0oOoO00O . require_signature
  self . encrypt_json = O0oOoO00O . encrypt_json
  if 85 - 85: I1Ii111 + iII111i - oO0o
  if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
 def rtrs_in_rloc_set ( self ) :
  for OOOoOoo in self . registered_rlocs :
   if ( OOOoOoo . is_rtr ( ) ) : return ( True )
   if 64 - 64: OoOoOO00
  return ( False )
  if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
  if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for OOOoOoo in self . registered_rlocs :
   if ( OOOoOoo . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( OOOoOoo . is_rtr ( ) ) : return ( True )
   if 71 - 71: ooOoO0o
  return ( False )
  if 35 - 35: OoOoOO00
  if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
 def is_rloc_in_rloc_set ( self , rloc ) :
  for OOOoOoo in self . registered_rlocs :
   if ( OOOoOoo . rle ) :
    for ooo0o0O in OOOoOoo . rle . rle_nodes :
     if ( ooo0o0O . address . is_exact_match ( rloc ) ) : return ( True )
     if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
     if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
   if ( OOOoOoo . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
  return ( False )
  if 89 - 89: iIii1I11I1II1 . ooOoO0o
  if 82 - 82: OoOoOO00 - II111iiii . OoO0O00 * ooOoO0o
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 78 - 78: OoOoOO00 % oO0o
  for OOOoOoo in prev_rloc_set :
   ii1II1i1 = OOOoOoo . rloc
   if ( self . is_rloc_in_rloc_set ( ii1II1i1 ) == False ) : return ( False )
   if 39 - 39: iIii1I11I1II1
  return ( True )
  if 72 - 72: II111iiii + I1Ii111 / Ii1I * iIii1I11I1II1
  if 95 - 95: OoooooooOO + OOooOOo + II111iiii + IiII + OoO0O00
  if 86 - 86: II111iiii / iII111i - I1ii11iIi11i
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
   if 65 - 65: I1ii11iIi11i + OoOoOO00
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 43 - 43: O0 + I11i % II111iiii
  if 56 - 56: IiII + Oo0Ooo . IiII % iIii1I11I1II1 % ooOoO0o % ooOoO0o
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 70 - 70: ooOoO0o / i1IIi - I11i - i11iIiiIii
  try :
   ooo0o0 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   OO0oo0o0 = ooo0o0 [ 2 ]
  except :
   return
   if 8 - 8: oO0o . OoO0O00 / IiII - oO0o / OoOoOO00 - i1IIi
   if 48 - 48: OoooooooOO + II111iiii
   if 46 - 46: I1IiiI - II111iiii * OoO0O00 % OoooooooOO / OoO0O00 + II111iiii
   if 92 - 92: OoOoOO00 - iIii1I11I1II1
   if 10 - 10: iII111i - I1IiiI / I1ii11iIi11i - i1IIi - II111iiii % i11iIiiIii
   if 2 - 2: ooOoO0o % ooOoO0o
  if ( len ( OO0oo0o0 ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 94 - 94: ooOoO0o / OoooooooOO * i1IIi . Oo0Ooo * i11iIiiIii
   if 5 - 5: iIii1I11I1II1 / oO0o - Oo0Ooo - I1IiiI + iIii1I11I1II1
  IiI = OO0oo0o0 [ self . a_record_index ]
  if ( IiI != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( IiI )
   self . insert_mr ( )
   if 63 - 63: iIii1I11I1II1 / ooOoO0o + O0 - o0oOOo0O0Ooo
   if 31 - 31: Ii1I
   if 76 - 76: OoO0O00 / II111iiii
   if 92 - 92: o0oOOo0O0Ooo . i1IIi . OoOoOO00 / OoO0O00 % Ii1I
   if 61 - 61: i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
   if 69 - 69: i11iIiiIii - iIii1I11I1II1
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 40 - 40: I1IiiI / oO0o + ooOoO0o
  for IiI in OO0oo0o0 [ 1 : : ] :
   OO0O00o0 = lisp_address ( LISP_AFI_NONE , IiI , 0 , 0 )
   iii1i = lisp_get_map_resolver ( OO0O00o0 , None )
   if ( iii1i != None and iii1i . a_record_index == OO0oo0o0 . index ( IiI ) ) :
    continue
    if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
   iii1i = lisp_mr ( IiI , None , None )
   iii1i . a_record_index = OO0oo0o0 . index ( IiI )
   iii1i . dns_name = self . dns_name
   iii1i . last_dns_resolve = lisp_get_timestamp ( )
   if 37 - 37: I1ii11iIi11i
   if 24 - 24: O0 . I1Ii111 * i11iIiiIii
   if 84 - 84: ooOoO0o / I1ii11iIi11i - o0oOOo0O0Ooo . OoooooooOO * iIii1I11I1II1
   if 16 - 16: I11i % O0
   if 56 - 56: Ii1I * OoOoOO00 . i1IIi
  iIi1II1IiI1I = [ ]
  for iii1i in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( self . dns_name != iii1i . dns_name ) : continue
   OO0O00o0 = iii1i . map_resolver . print_address_no_iid ( )
   if ( OO0O00o0 in OO0oo0o0 ) : continue
   iIi1II1IiI1I . append ( iii1i )
   if 28 - 28: iII111i
  for iii1i in iIi1II1IiI1I : iii1i . delete_mr ( )
  if 18 - 18: I1Ii111
  if 29 - 29: i1IIi - I1IiiI / i1IIi
 def insert_mr ( self ) :
  III = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ III ] = self
  if 64 - 64: IiII
  if 69 - 69: OOooOOo . I1IiiI
 def delete_mr ( self ) :
  III = self . mr_name + self . map_resolver . print_address ( )
  if ( III not in lisp_map_resolvers_list ) : return
  lisp_map_resolvers_list . pop ( III )
  if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
  if 22 - 22: iII111i % I11i % O0 - I11i
  if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
class lisp_ddt_root ( object ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
  if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
  if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
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
  if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
  if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
 def print_referral ( self , eid_indent , referral_indent ) :
  oo0Ooo0o00OO = lisp_print_elapsed ( self . uptime )
  ii1iIi = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , oo0Ooo0o00OO ,
  # Ii1I * Oo0Ooo / oO0o / Ii1I
 ii1iIi , len ( self . referral_set ) ) )
  if 34 - 34: I1IiiI
  for oooO00ooo00 in list ( self . referral_set . values ( ) ) :
   oooO00ooo00 . print_ref_node ( referral_indent )
   if 56 - 56: Ii1I
   if 71 - 71: O0 / i1IIi
   if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 82 - 82: oO0o * i11iIiiIii % o0oOOo0O0Ooo % IiII - I11i - OoO0O00
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 24 - 24: oO0o . II111iiii + OoO0O00 * I1ii11iIi11i / oO0o
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 86 - 86: I1Ii111 + I1ii11iIi11i
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 63 - 63: ooOoO0o - i11iIiiIii . o0oOOo0O0Ooo - i1IIi - IiII
  if 32 - 32: I1Ii111 / iIii1I11I1II1 + oO0o % I11i * OoooooooOO
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 69 - 69: OOooOOo
  if 9 - 9: i11iIiiIii * Oo0Ooo
 def print_ttl ( self ) :
  O0O00O = self . referral_ttl
  if ( O0O00O < 60 ) : return ( str ( O0O00O ) + " secs" )
  if 33 - 33: oO0o / ooOoO0o
  if ( ( O0O00O % 60 ) == 0 ) :
   O0O00O = str ( old_div ( O0O00O , 60 ) ) + " mins"
  else :
   O0O00O = str ( O0O00O ) + " secs"
   if 92 - 92: O0 . Oo0Ooo - Ii1I * I1IiiI * Oo0Ooo * iII111i
  return ( O0O00O )
  if 78 - 78: Ii1I * iIii1I11I1II1 - Ii1I - I1ii11iIi11i * I1ii11iIi11i
  if 44 - 44: o0oOOo0O0Ooo
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # OoOoOO00
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 20 - 20: i11iIiiIii
  if 2 - 2: o0oOOo0O0Ooo % OOooOOo * O0 * OOooOOo
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   O0oO0 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( O0oO0 == None ) :
    O0oO0 = lisp_referral ( )
    O0oO0 . eid . copy_address ( self . group )
    O0oO0 . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , O0oO0 )
    if 27 - 27: IiII . Oo0Ooo . I1ii11iIi11i
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( O0oO0 . group )
   O0oO0 . add_source_entry ( self )
   if 53 - 53: Ii1I / i11iIiiIii - I11i * OoooooooOO
   if 88 - 88: OoO0O00 / Ii1I + ooOoO0o . iIii1I11I1II1 * ooOoO0o
   if 56 - 56: o0oOOo0O0Ooo / iII111i . O0 % O0
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   O0oO0 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( O0oO0 == None ) : return
   if 37 - 37: I1Ii111
   o000oOoO = O0oO0 . lookup_source_cache ( self . eid , True )
   if ( o000oOoO == None ) : return
   if 98 - 98: iII111i - OoOoOO00 / I1Ii111 . OOooOOo - OOooOOo - ooOoO0o
   O0oO0 . source_cache . delete_cache ( self . eid )
   if ( O0oO0 . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 84 - 84: OOooOOo * ooOoO0o / O0
    if 96 - 96: I11i . I11i % II111iiii
    if 14 - 14: iII111i / OoooooooOO
    if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
  if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
  if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
  if 11 - 11: I1IiiI
class lisp_referral_node ( object ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
  if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
 def print_ref_node ( self , indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , i1 ,
  # OoO0O00 . iIii1I11I1II1 . ooOoO0o - IiII . iII111i + Ii1I
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 76 - 76: Ii1I . oO0o . Oo0Ooo
  if 13 - 13: iIii1I11I1II1 / o0oOOo0O0Ooo
  if 24 - 24: I1Ii111 % OOooOOo * i1IIi - iIii1I11I1II1
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
   if 61 - 61: o0oOOo0O0Ooo + Ii1I
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
   if 16 - 16: I11i - I11i + oO0o + iII111i . OoO0O00
   if 96 - 96: iIii1I11I1II1 + iII111i + I1Ii111 % I1IiiI * OOooOOo
   if 46 - 46: I1ii11iIi11i % Oo0Ooo * OOooOOo
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 64 - 64: I1ii11iIi11i
  try :
   ooo0o0 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   OO0oo0o0 = ooo0o0 [ 2 ]
  except :
   return
   if 17 - 17: II111iiii + Ii1I - o0oOOo0O0Ooo * II111iiii / Oo0Ooo / II111iiii
   if 82 - 82: i11iIiiIii * OoOoOO00 . i1IIi + IiII * ooOoO0o
   if 75 - 75: iIii1I11I1II1 / IiII / II111iiii . I11i
   if 23 - 23: OOooOOo . ooOoO0o - iII111i % Ii1I . I1ii11iIi11i + IiII
   if 81 - 81: I11i
   if 5 - 5: OoooooooOO
  if ( len ( OO0oo0o0 ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 5 - 5: iII111i + oO0o % O0 . OoooooooOO + i1IIi
   if 55 - 55: I1ii11iIi11i
  IiI = OO0oo0o0 [ self . a_record_index ]
  if ( IiI != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( IiI )
   self . insert_ms ( )
   if 34 - 34: OoO0O00 * iIii1I11I1II1 . iIii1I11I1II1
   if 39 - 39: o0oOOo0O0Ooo
   if 29 - 29: Oo0Ooo . Oo0Ooo * OoO0O00 % Ii1I - ooOoO0o
   if 67 - 67: I1IiiI % O0 + I1IiiI * I1Ii111 * OoOoOO00 * II111iiii
   if 79 - 79: I1IiiI
   if 37 - 37: I1Ii111 + Ii1I
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 50 - 50: i11iIiiIii
  for IiI in OO0oo0o0 [ 1 : : ] :
   OO0O00o0 = lisp_address ( LISP_AFI_NONE , IiI , 0 , 0 )
   oO00000oOO = lisp_get_map_server ( OO0O00o0 )
   if ( oO00000oOO != None and oO00000oOO . a_record_index == OO0oo0o0 . index ( IiI ) ) :
    continue
    if 57 - 57: O0 * i1IIi - I1IiiI
   oO00000oOO = copy . deepcopy ( self )
   oO00000oOO . map_server . store_address ( IiI )
   oO00000oOO . a_record_index = OO0oo0o0 . index ( IiI )
   oO00000oOO . last_dns_resolve = lisp_get_timestamp ( )
   oO00000oOO . insert_ms ( )
   if 48 - 48: IiII / iIii1I11I1II1
   if 20 - 20: oO0o / OoooooooOO
   if 95 - 95: Oo0Ooo . i11iIiiIii
   if 50 - 50: iII111i . i11iIiiIii - i1IIi
   if 24 - 24: i11iIiiIii % iII111i . oO0o
  iIi1II1IiI1I = [ ]
  for oO00000oOO in list ( lisp_map_servers_list . values ( ) ) :
   if ( self . dns_name != oO00000oOO . dns_name ) : continue
   OO0O00o0 = oO00000oOO . map_server . print_address_no_iid ( )
   if ( OO0O00o0 in OO0oo0o0 ) : continue
   iIi1II1IiI1I . append ( oO00000oOO )
   if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
  for oO00000oOO in iIi1II1IiI1I : oO00000oOO . delete_ms ( )
  if 34 - 34: I1ii11iIi11i % ooOoO0o / II111iiii * O0 % OOooOOo
  if 9 - 9: I1ii11iIi11i / I1ii11iIi11i - OOooOOo . iIii1I11I1II1
 def insert_ms ( self ) :
  III = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ III ] = self
  if 33 - 33: I1IiiI + oO0o % I1IiiI / iII111i - ooOoO0o - i11iIiiIii
  if 39 - 39: i11iIiiIii / oO0o
 def delete_ms ( self ) :
  III = self . ms_name + self . map_server . print_address ( )
  if ( III not in lisp_map_servers_list ) : return
  lisp_map_servers_list . pop ( III )
  if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
  if 87 - 87: I1IiiI / Ii1I
  if 54 - 54: OoooooooOO / Ii1I
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
  if 26 - 26: o0oOOo0O0Ooo + OoO0O00
  if 59 - 59: Ii1I * IiII
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 64 - 64: ooOoO0o . Oo0Ooo - OoOoOO00
  if 66 - 66: OoOoOO00
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 83 - 83: OOooOOo . IiII
  if 98 - 98: i11iIiiIii
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 74 - 74: iIii1I11I1II1 * O0 + OOooOOo . o0oOOo0O0Ooo
  if 17 - 17: I1Ii111
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 59 - 59: OoOoOO00 . OoOoOO00 * iII111i - Ii1I . i11iIiiIii
  if 68 - 68: iII111i
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 68 - 68: I1Ii111 - OoO0O00 % OoO0O00 % OOooOOo - OoO0O00
  if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
 def set_socket ( self , device ) :
  I111 = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  I111 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   I111 . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   I111 . close ( )
   I111 = None
   if 59 - 59: iII111i
  self . raw_socket = I111
  if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
  if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
 def set_bridge_socket ( self , device ) :
  I111 = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   I111 = I111 . bind ( ( device , 0 ) )
   self . bridge_socket = I111
  except :
   return
   if 65 - 65: I1Ii111 + OOooOOo
   if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
   if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
   if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
class lisp_datetime ( object ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 77 - 77: ooOoO0o % I1IiiI
  if 26 - 26: o0oOOo0O0Ooo
 def valid_datetime ( self ) :
  o0o0OO = self . datetime_name
  if ( o0o0OO . find ( ":" ) == - 1 ) : return ( False )
  if ( o0o0OO . find ( "-" ) == - 1 ) : return ( False )
  ii1iiii1i1II1 , oOOOOOo00 , i1O0oOO , time = o0o0OO [ 0 : 4 ] , o0o0OO [ 5 : 7 ] , o0o0OO [ 8 : 10 ] , o0o0OO [ 11 : : ]
  if 65 - 65: OOooOOo * o0oOOo0O0Ooo - I1Ii111 % O0 / I1ii11iIi11i + O0
  if ( ( ii1iiii1i1II1 + oOOOOOo00 + i1O0oOO ) . isdigit ( ) == False ) : return ( False )
  if ( oOOOOOo00 < "01" and oOOOOOo00 > "12" ) : return ( False )
  if ( i1O0oOO < "01" and i1O0oOO > "31" ) : return ( False )
  if 97 - 97: II111iiii + i11iIiiIii + OoooooooOO . iII111i
  I1I11Ii , OoI1 , oooO0OOO0OoO = time . split ( ":" )
  if 84 - 84: OoO0O00 . oO0o * OoO0O00 - IiII
  if ( ( I1I11Ii + OoI1 + oooO0OOO0OoO ) . isdigit ( ) == False ) : return ( False )
  if ( I1I11Ii < "00" and I1I11Ii > "23" ) : return ( False )
  if ( OoI1 < "00" and OoI1 > "59" ) : return ( False )
  if ( oooO0OOO0OoO < "00" and oooO0OOO0OoO > "59" ) : return ( False )
  return ( True )
  if 24 - 24: O0 * OOooOOo . OoO0O00 + iII111i + i1IIi + oO0o
  if 57 - 57: OOooOOo * OOooOOo
 def parse_datetime ( self ) :
  oOOoo0o0OOOo = self . datetime_name
  oOOoo0o0OOOo = oOOoo0o0OOOo . replace ( "-" , "" )
  oOOoo0o0OOOo = oOOoo0o0OOOo . replace ( ":" , "" )
  self . datetime = int ( oOOoo0o0OOOo )
  if 94 - 94: II111iiii % I1Ii111 . Ii1I / OoOoOO00 - OoO0O00 - OoO0O00
  if 13 - 13: I11i + i11iIiiIii . O0 - iII111i
 def now ( self ) :
  i1 = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  i1 = lisp_datetime ( i1 )
  return ( i1 )
  if 48 - 48: OoO0O00 * OOooOOo / iII111i
  if 90 - 90: I1IiiI * i11iIiiIii . OOooOOo / o0oOOo0O0Ooo
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 82 - 82: Oo0Ooo
  if 50 - 50: I1Ii111 * OOooOOo * OoOoOO00 / OoooooooOO % iII111i
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 80 - 80: I1Ii111
  if 35 - 35: Ii1I . O0 % i11iIiiIii * oO0o - OoooooooOO
 def past ( self ) :
  return ( self . future ( ) == False )
  if 87 - 87: iII111i * ooOoO0o - OOooOOo . O0
  if 20 - 20: OoOoOO00 - IiII
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 9 - 9: O0 . I11i % I1ii11iIi11i * oO0o - I1Ii111 - i1IIi
  if 66 - 66: II111iiii / Oo0Ooo
 def this_year ( self ) :
  O000oo = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  i1 = str ( self . datetime ) [ 0 : 4 ]
  return ( i1 == O000oo )
  if 45 - 45: IiII + I1IiiI * I1Ii111
  if 82 - 82: OOooOOo / I11i % Ii1I * OoOoOO00
 def this_month ( self ) :
  O000oo = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  i1 = str ( self . datetime ) [ 0 : 6 ]
  return ( i1 == O000oo )
  if 88 - 88: o0oOOo0O0Ooo % OoO0O00
  if 30 - 30: II111iiii / Oo0Ooo % Oo0Ooo + O0 / iIii1I11I1II1 . OoO0O00
 def today ( self ) :
  O000oo = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  i1 = str ( self . datetime ) [ 0 : 8 ]
  return ( i1 == O000oo )
  if 43 - 43: I1IiiI % OoOoOO00 * O0 + o0oOOo0O0Ooo
  if 97 - 97: iIii1I11I1II1 + O0
  if 41 - 41: OoOoOO00 - II111iiii
  if 46 - 46: OOooOOo
  if 73 - 73: iII111i - IiII + II111iiii
  if 58 - 58: Oo0Ooo % I1IiiI
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
  if 78 - 78: iII111i / iIii1I11I1II1 * IiII . ooOoO0o / I1Ii111 % I11i
  if 14 - 14: II111iiii % iIii1I11I1II1 - I1IiiI % i11iIiiIii . OOooOOo * I1ii11iIi11i
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
  if 12 - 12: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . OoOoOO00
  if 73 - 73: I1ii11iIi11i * i1IIi * Oo0Ooo / O0
 def match_policy_map_request ( self , mr , srloc ) :
  for IiIIIIi11ii in self . match_clauses :
   iIIiiIi = IiIIIIi11ii . source_eid
   IIiIIiiiiI = mr . source_eid
   if ( iIIiiIi and IIiIIiiiiI and IIiIIiiiiI . is_more_specific ( iIIiiIi ) == False ) : continue
   if 1 - 1: iII111i * OOooOOo + II111iiii / Ii1I . I1ii11iIi11i
   iIIiiIi = IiIIIIi11ii . dest_eid
   IIiIIiiiiI = mr . target_eid
   if ( iIIiiIi and IIiIIiiiiI and IIiIIiiiiI . is_more_specific ( iIIiiIi ) == False ) : continue
   if 61 - 61: oO0o % OoOoOO00 % ooOoO0o . I1Ii111 / OoO0O00
   iIIiiIi = IiIIIIi11ii . source_rloc
   IIiIIiiiiI = srloc
   if ( iIIiiIi and IIiIIiiiiI and IIiIIiiiiI . is_more_specific ( iIIiiIi ) == False ) : continue
   oOO0O00o0O0 = IiIIIIi11ii . datetime_lower
   ii11IIiI1iIi = IiIIIIi11ii . datetime_upper
   if ( oOO0O00o0O0 and ii11IIiI1iIi and oOO0O00o0O0 . now_in_range ( ii11IIiI1iIi ) == False ) : continue
   return ( True )
   if 81 - 81: II111iiii - II111iiii * o0oOOo0O0Ooo
  return ( False )
  if 95 - 95: I1Ii111 - OoooooooOO
  if 99 - 99: OoooooooOO % IiII . I11i + OoooooooOO
 def set_policy_map_reply ( self ) :
  o00oo = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( o00oo ) : return ( None )
  if 21 - 21: I11i . O0 * OoooooooOO + ooOoO0o * oO0o % i11iIiiIii
  iIIiI11 = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   iIIiI11 . rloc . copy_address ( self . set_rloc_address )
   IiI = iIIiI11 . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( IiI ) )
   if 30 - 30: ooOoO0o * I1Ii111 + OoO0O00
  if ( self . set_rloc_record_name ) :
   iIIiI11 . rloc_name = self . set_rloc_record_name
   ooO0o = blue ( iIIiI11 . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( ooO0o ) )
   if 30 - 30: Ii1I / iII111i * Ii1I
  if ( self . set_geo_name ) :
   iIIiI11 . geo_name = self . set_geo_name
   ooO0o = iIIiI11 . geo_name
   iI1IIi1Ii = "" if ( ooO0o in lisp_geo_list ) else "(not configured)"
   if 70 - 70: OoOoOO00
   lprint ( "Policy set-geo-name '{}' {}" . format ( ooO0o , iI1IIi1Ii ) )
   if 11 - 11: OoOoOO00 * OoOoOO00 % I11i
  if ( self . set_elp_name ) :
   iIIiI11 . elp_name = self . set_elp_name
   ooO0o = iIIiI11 . elp_name
   iI1IIi1Ii = "" if ( ooO0o in lisp_elp_list ) else "(not configured)"
   if 21 - 21: ooOoO0o . i11iIiiIii / IiII . i1IIi + OoooooooOO
   lprint ( "Policy set-elp-name '{}' {}" . format ( ooO0o , iI1IIi1Ii ) )
   if 18 - 18: ooOoO0o - I11i - I1Ii111
  if ( self . set_rle_name ) :
   iIIiI11 . rle_name = self . set_rle_name
   ooO0o = iIIiI11 . rle_name
   iI1IIi1Ii = "" if ( ooO0o in lisp_rle_list ) else "(not configured)"
   if 81 - 81: IiII - Ii1I % i1IIi
   lprint ( "Policy set-rle-name '{}' {}" . format ( ooO0o , iI1IIi1Ii ) )
   if 48 - 48: Ii1I + I11i % iIii1I11I1II1 + ooOoO0o + ooOoO0o + OoO0O00
  if ( self . set_json_name ) :
   iIIiI11 . json_name = self . set_json_name
   ooO0o = iIIiI11 . json_name
   iI1IIi1Ii = "" if ( ooO0o in lisp_json_list ) else "(not configured)"
   if 7 - 7: O0 + II111iiii
   lprint ( "Policy set-json-name '{}' {}" . format ( ooO0o , iI1IIi1Ii ) )
   if 44 - 44: OOooOOo + i11iIiiIii - I1Ii111 + ooOoO0o
  return ( iIIiI11 )
  if 92 - 92: O0 . iIii1I11I1II1 % iIii1I11I1II1 % OoO0O00 - i11iIiiIii - iII111i
  if 76 - 76: OoO0O00 . II111iiii / I1ii11iIi11i
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 15 - 15: OoOoOO00 . O0 + iII111i + I1IiiI . ooOoO0o + iIii1I11I1II1
  if 2 - 2: I11i
  if 52 - 52: i11iIiiIii / oO0o / IiII
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
  if 84 - 84: I11i . oO0o + ooOoO0o
  if 75 - 75: I1Ii111
 def add ( self , eid_prefix ) :
  self . eid_prefix = eid_prefix
  O0O00O = self . ttl
  o0Ooo0Oooo0o = eid_prefix . print_prefix ( )
  if ( o0Ooo0Oooo0o not in lisp_pubsub_cache ) :
   lisp_pubsub_cache [ o0Ooo0Oooo0o ] = { }
   if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
  iIiI1IIi1Ii1i = lisp_pubsub_cache [ o0Ooo0Oooo0o ]
  if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
  O0Ooo0iII111III = "Add"
  if ( self . xtr_id in iIiI1IIi1Ii1i ) :
   O0Ooo0iII111III = "Replace"
   del ( iIiI1IIi1Ii1i [ self . xtr_id ] )
   if 94 - 94: Ii1I
  iIiI1IIi1Ii1i [ self . xtr_id ] = self
  if 82 - 82: OOooOOo . OoO0O00 % II111iiii . i1IIi . OoOoOO00 - oO0o
  o0Ooo0Oooo0o = green ( o0Ooo0Oooo0o , False )
  oO0oO00OO00 = red ( self . itr . print_address_no_iid ( ) , False )
  oOOOOOo0OO0o0oOO0 = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( O0Ooo0iII111III , o0Ooo0Oooo0o ,
 oO0oO00OO00 , oOOOOOo0OO0o0oOO0 , O0O00O ) )
  if 27 - 27: OoOoOO00 * I11i
  if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
 def delete ( self , eid_prefix ) :
  o0Ooo0Oooo0o = eid_prefix . print_prefix ( )
  oO0oO00OO00 = red ( self . itr . print_address_no_iid ( ) , False )
  oOOOOOo0OO0o0oOO0 = "0x" + lisp_hex_string ( self . xtr_id )
  if ( o0Ooo0Oooo0o in lisp_pubsub_cache ) :
   iIiI1IIi1Ii1i = lisp_pubsub_cache [ o0Ooo0Oooo0o ]
   if ( self . xtr_id in iIiI1IIi1Ii1i ) :
    iIiI1IIi1Ii1i . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( o0Ooo0Oooo0o ,
 oO0oO00OO00 , oOOOOOo0OO0o0oOO0 ) )
    if 70 - 70: I1IiiI . ooOoO0o / I11i / OoO0O00
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
    if 93 - 93: oO0o / ooOoO0o - I1Ii111
    if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
    if 26 - 26: O0 + Oo0Ooo
    if 30 - 30: IiII
    if 6 - 6: O0
class lisp_trace ( object ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 92 - 92: I11i
  if 76 - 76: I11i / iIii1I11I1II1 - i11iIiiIii / O0 / O0
 def print_trace ( self ) :
  iIiI11II = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( iIiI11II ) )
  if 19 - 19: Ii1I . I1IiiI - i1IIi * ooOoO0o . iIii1I11I1II1
  if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
 def encode ( self ) :
  iIiIii = socket . htonl ( 0x90000000 )
  Oo00oo = struct . pack ( "II" , iIiIii , 0 )
  Oo00oo += struct . pack ( "Q" , self . nonce )
  Oo00oo += json . dumps ( self . packet_json )
  return ( Oo00oo )
  if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
  if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
 def decode ( self , packet ) :
  iiII1iiI = "I"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( False )
  iIiIii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  iIiIii = socket . ntohl ( iIiIii )
  if ( ( iIiIii & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
  if ( len ( packet ) < ooo0000oo0 ) : return ( False )
  IiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
  IiI = socket . ntohl ( IiI )
  OOoOO = IiI >> 24
  O000O00O0O = ( IiI >> 16 ) & 0xff
  iiOOoooO = ( IiI >> 8 ) & 0xff
  OOO0O00oo = IiI & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( OOoOO , O000O00O0O , iiOOoooO , OOO0O00oo )
  self . local_port = str ( iIiIii & 0xffff )
  if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
  iiII1iiI = "Q"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( False )
  self . nonce = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 83 - 83: OOooOOo . ooOoO0o / IiII
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 80 - 80: I1Ii111 . I11i - I11i + I1ii11iIi11i
  return ( True )
  if 42 - 42: I11i / IiII % O0 - Oo0Ooo
  if 33 - 33: I1Ii111
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 1 - 1: IiII - iIii1I11I1II1 % OoooooooOO
  if 1 - 1: o0oOOo0O0Ooo - i11iIiiIii + I11i
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  iIIiI11 , ooO0 = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( iIIiI11 == None ) :
   iIIiI11 , ooO0 = rts_rloc . split ( ":" )
   ooO0 = int ( ooO0 )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( iIIiI11 , ooO0 ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( iIIiI11 ,
 ooO0 ) )
   if 47 - 47: O0 + IiII + ooOoO0o + OOooOOo / OoOoOO00
   if 31 - 31: oO0o * iII111i % OoOoOO00
  if ( lisp_socket == None ) :
   I111 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   I111 . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   I111 . sendto ( packet , ( iIIiI11 , ooO0 ) )
   I111 . close ( )
  else :
   lisp_socket . sendto ( packet , ( iIIiI11 , ooO0 ) )
   if 80 - 80: ooOoO0o % I1ii11iIi11i % I11i . I1Ii111
   if 3 - 3: ooOoO0o - Oo0Ooo
   if 2 - 2: iII111i . iII111i
 def packet_length ( self ) :
  O0I1II1 = 8 ; o0oo0oOoo0 = 4 + 4 + 8
  return ( O0I1II1 + o0oo0oOoo0 + len ( json . dumps ( self . packet_json ) ) )
  if 17 - 17: OoO0O00 * OoO0O00 - OOooOOo
  if 93 - 93: I1Ii111 . o0oOOo0O0Ooo . ooOoO0o
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  III = self . local_rloc + ":" + self . local_port
  oOO0 = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ III ] = oOO0
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( III , oOO0 ) )
  if 63 - 63: OOooOOo . oO0o * OoooooooOO + ooOoO0o / iIii1I11I1II1 + iII111i
  if 45 - 45: ooOoO0o / O0 % O0 % i1IIi . I1IiiI - OoOoOO00
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  III = local_rloc_and_port
  try : oOO0 = lisp_rtr_nat_trace_cache [ III ]
  except : oOO0 = ( None , None )
  return ( oOO0 )
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
def lisp_get_map_server ( address ) :
 for oO00000oOO in list ( lisp_map_servers_list . values ( ) ) :
  if ( oO00000oOO . map_server . is_exact_match ( address ) ) : return ( oO00000oOO )
  if 42 - 42: OoOoOO00 + oO0o * i1IIi + i11iIiiIii
 return ( None )
 if 25 - 25: Ii1I - Ii1I - I1ii11iIi11i / i1IIi . OoOoOO00 % Oo0Ooo
 if 76 - 76: I1Ii111 / OoOoOO00
 if 61 - 61: Oo0Ooo . i1IIi
 if 78 - 78: i11iIiiIii
 if 20 - 20: Ii1I
 if 100 - 100: OoooooooOO . I1Ii111
 if 32 - 32: iIii1I11I1II1 . iIii1I11I1II1 % II111iiii / Oo0Ooo . iIii1I11I1II1 . O0
def lisp_get_any_map_server ( ) :
 for oO00000oOO in list ( lisp_map_servers_list . values ( ) ) : return ( oO00000oOO )
 return ( None )
 if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
 if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
 if 87 - 87: I1ii11iIi11i . i1IIi - I11i + OoOoOO00 . O0
 if 37 - 37: IiII
 if 65 - 65: ooOoO0o * Ii1I / I1IiiI . i1IIi % ooOoO0o . OoooooooOO
 if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
 if 88 - 88: i1IIi - OoOoOO00
 if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
 if 7 - 7: Ii1I / iIii1I11I1II1
 if 36 - 36: iIii1I11I1II1 % i11iIiiIii
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  IiI = address . print_address ( )
  iii1i = None
  for III in lisp_map_resolvers_list :
   if ( III . find ( IiI ) == - 1 ) : continue
   iii1i = lisp_map_resolvers_list [ III ]
   if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
  return ( iii1i )
  if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
  if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
  if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
  if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
  if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
  if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
  if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
 if ( eid == "" ) :
  i111I1Ii1II1 = ""
 elif ( eid == None ) :
  i111I1Ii1II1 = "all"
 else :
  OoO0oO = lisp_db_for_lookups . lookup_cache ( eid , False )
  i111I1Ii1II1 = "all" if OoO0oO == None else OoO0oO . use_mr_name
  if 57 - 57: I1IiiI . Oo0Ooo - i1IIi + oO0o + OOooOOo + oO0o
  if 6 - 6: OoO0O00 + OoooooooOO . I1Ii111
 Ii11Ii = None
 for iii1i in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( i111I1Ii1II1 == "" ) : return ( iii1i )
  if ( iii1i . mr_name != i111I1Ii1II1 ) : continue
  if ( Ii11Ii == None or iii1i . last_used < Ii11Ii . last_used ) : Ii11Ii = iii1i
  if 2 - 2: i11iIiiIii
 return ( Ii11Ii )
 if 86 - 86: I1Ii111 + o0oOOo0O0Ooo
 if 17 - 17: iIii1I11I1II1
 if 32 - 32: IiII - OoOoOO00
 if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
 if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
 if 83 - 83: OoO0O00 . I11i * I1ii11iIi11i - II111iiii
 if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
 if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
def lisp_get_decent_map_resolver ( eid ) :
 OOOooo0OooOoO = lisp_get_decent_index ( eid )
 iiiiII = str ( OOOooo0OooOoO ) + "." + lisp_decent_dns_suffix
 if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( iiiiII , False ) , eid . print_prefix ( ) ) )
 if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
 if 96 - 96: I1IiiI . oO0o % O0
 Ii11Ii = None
 for iii1i in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( iiiiII != iii1i . dns_name ) : continue
  if ( Ii11Ii == None or iii1i . last_used < Ii11Ii . last_used ) : Ii11Ii = iii1i
  if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
 return ( Ii11Ii )
 if 87 - 87: OoooooooOO
 if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
 if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
 if 23 - 23: o0oOOo0O0Ooo . o0oOOo0O0Ooo - iIii1I11I1II1 / o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + I1Ii111 . I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
 if 2 - 2: oO0o % iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
 if 45 - 45: II111iiii . iII111i
def lisp_ipv4_input ( packet ) :
 if 55 - 55: ooOoO0o / iII111i / O0
 if 98 - 98: O0 % iII111i + II111iiii
 if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
 if 23 - 23: iIii1I11I1II1 + oO0o . oO0o / o0oOOo0O0Ooo
 if ( ord ( packet [ 9 : 10 ] ) == 2 ) : return ( [ True , packet ] )
 if 77 - 77: i1IIi * o0oOOo0O0Ooo * IiII
 if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
 if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
 if 36 - 36: O0
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
   if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
   if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
   if 21 - 21: i1IIi * iII111i + OoO0O00
   if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
   if 85 - 85: OoooooooOO
   if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
   if 8 - 8: I1Ii111
 O0O00O = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( O0O00O == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( O0O00O == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 86 - 86: ooOoO0o + iII111i * O0 % OoO0O00 + OoOoOO00
  return ( [ False , None ] )
  if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
  if 9 - 9: iIii1I11I1II1 + Ii1I + I11i
 O0O00O -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , O0O00O ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( [ False , packet ] )
 if 96 - 96: OoO0O00 + i11iIiiIii + OoO0O00
 if 7 - 7: i1IIi . I1IiiI
 if 68 - 68: OoooooooOO
 if 91 - 91: IiII . ooOoO0o * I11i
 if 39 - 39: o0oOOo0O0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 . II111iiii
 if 36 - 36: I1IiiI * i1IIi + OoOoOO00
def lisp_ipv6_input ( packet ) :
 IIi11ii = packet . inner_dest
 packet = packet . packet
 if 63 - 63: OoOoOO00 - iII111i
 if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
 if 82 - 82: iIii1I11I1II1 / OOooOOo
 if 7 - 7: OoooooooOO
 if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
 O0O00O = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( O0O00O == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( O0O00O == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
  return ( None )
  if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
  if 1 - 1: Ii1I . Ii1I % II111iiii + I11i + OoOoOO00
  if 52 - 52: OoooooooOO - OoO0O00
  if 24 - 24: iII111i / Oo0Ooo - I1ii11iIi11i + o0oOOo0O0Ooo
  if 44 - 44: OoOoOO00 + I1IiiI . I1ii11iIi11i / i1IIi + II111iiii . Oo0Ooo
 if ( IIi11ii . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 39 - 39: o0oOOo0O0Ooo
  if 64 - 64: oO0o - i11iIiiIii
 O0O00O -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , O0O00O ) + packet [ 8 : : ]
 return ( packet )
 if 62 - 62: OoooooooOO - OoooooooOO / OoO0O00 - II111iiii . iIii1I11I1II1
 if 2 - 2: O0 + o0oOOo0O0Ooo % OOooOOo . ooOoO0o % i1IIi
 if 21 - 21: OoOoOO00 / OoooooooOO + I1Ii111 - IiII
 if 62 - 62: Oo0Ooo % iII111i + OoooooooOO - I1ii11iIi11i % iII111i % iIii1I11I1II1
 if 54 - 54: IiII + OoOoOO00 / II111iiii % i11iIiiIii . I1Ii111
 if 69 - 69: i1IIi + ooOoO0o + Ii1I
 if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
 if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
def lisp_mac_input ( packet ) :
 return ( packet )
 if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
 if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
 if 8 - 8: i1IIi
 if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
 if 97 - 97: OoooooooOO % ooOoO0o . I1Ii111 / iII111i
 if 59 - 59: II111iiii + O0 . I1ii11iIi11i . Oo0Ooo * OoO0O00
 if 35 - 35: oO0o / I1Ii111 * OOooOOo + OoooooooOO . IiII
 if 1 - 1: I1IiiI + I1Ii111 / OOooOOo . Ii1I . oO0o / I1ii11iIi11i
 if 54 - 54: OOooOOo
def lisp_rate_limit_map_request ( dest ) :
 O000oo = lisp_get_timestamp ( )
 if 86 - 86: oO0o * Oo0Ooo / OOooOOo
 if 18 - 18: II111iiii - I1Ii111
 if 13 - 13: i11iIiiIii - O0 % OoOoOO00 + OOooOOo * ooOoO0o
 if 55 - 55: i1IIi - OOooOOo / I11i * Ii1I
 i1i111Iiiiiii = O000oo - lisp_no_map_request_rate_limit
 if ( i1i111Iiiiiii < LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME ) :
  iIi1I1 = int ( LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME - i1i111Iiiiiii )
  dprint ( "No Rate-Limit Mode for another {} secs" . format ( iIi1I1 ) )
  return ( False )
  if 20 - 20: OoOoOO00 * iIii1I11I1II1 % O0 - i1IIi
  if 51 - 51: I1ii11iIi11i * Ii1I - oO0o / O0 * OoooooooOO
  if 12 - 12: i1IIi / iIii1I11I1II1 / O0 * OoO0O00
  if 15 - 15: i11iIiiIii / IiII + Ii1I % OOooOOo % I1ii11iIi11i * oO0o
  if 24 - 24: OOooOOo / OOooOOo + I11i / iII111i . oO0o - iII111i
 if ( lisp_last_map_request_sent == None ) : return ( False )
 i1i111Iiiiiii = O000oo - lisp_last_map_request_sent
 IiIiI1I1Ii = ( i1i111Iiiiiii < LISP_MAP_REQUEST_RATE_LIMIT )
 if 59 - 59: I1ii11iIi11i % II111iiii - i11iIiiIii - I1Ii111
 if ( IiIiI1I1Ii ) :
  dprint ( "Rate-limiting Map-Request for {}, sent {} secs ago" . format ( green ( dest . print_address ( ) , False ) , round ( i1i111Iiiiiii , 3 ) ) )
  if 34 - 34: II111iiii + iII111i / IiII
  if 47 - 47: OoO0O00
 return ( IiIiI1I1Ii )
 if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
 if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
 if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
 if 100 - 100: II111iiii . IiII . I11i
 if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
 if 3 - 3: OoooooooOO
 if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ,
 pubsub = False ) :
 global lisp_last_map_request_sent
 if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
 if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
 if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
 if 37 - 37: I1ii11iIi11i * IiII
 if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
 if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
 Ii11I1Ii1 = iiiI111i1iIi = None
 if ( rloc ) :
  Ii11I1Ii1 = rloc . rloc
  iiiI111i1iIi = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 99 - 99: iIii1I11I1II1 + O0 + OoooooooOO % I1IiiI - OoOoOO00 / oO0o
  if 22 - 22: iIii1I11I1II1 . I11i
  if 21 - 21: I1IiiI % Oo0Ooo - II111iiii / I1IiiI . OoOoOO00 - o0oOOo0O0Ooo
  if 23 - 23: OoOoOO00 / O0 * OoOoOO00 . I1IiiI + Oo0Ooo . iII111i
  if 1 - 1: i11iIiiIii * OoO0O00 - OoooooooOO + OoooooooOO
 Ii1I1iI1i , oOii11I111 , ooO000OO = lisp_myrlocs
 if ( Ii1I1iI1i == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 89 - 89: I1ii11iIi11i . OoooooooOO
 if ( oOii11I111 == None and Ii11I1Ii1 != None and Ii11I1Ii1 . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 61 - 61: i1IIi + i11iIiiIii
  if 59 - 59: i11iIiiIii * OOooOOo + i1IIi * iIii1I11I1II1 + I11i
 O0Ooo = lisp_map_request ( )
 O0Ooo . record_count = 1
 O0Ooo . nonce = lisp_get_control_nonce ( )
 O0Ooo . rloc_probe = ( Ii11I1Ii1 != None )
 O0Ooo . subscribe_bit = pubsub
 O0Ooo . xtr_id_present = pubsub
 if 97 - 97: OoO0O00 - I11i . OoooooooOO
 if 58 - 58: I1ii11iIi11i / II111iiii / i11iIiiIii
 if 27 - 27: iIii1I11I1II1 - O0 + OoOoOO00
 if 28 - 28: oO0o . IiII * iII111i % Oo0Ooo - OoO0O00 / I11i
 if 67 - 67: i11iIiiIii + i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo
 if 94 - 94: O0 + OoO0O00 / I1IiiI * II111iiii * i11iIiiIii
 if 55 - 55: OoooooooOO * O0 + i1IIi % I1IiiI
 if ( rloc ) : rloc . last_rloc_probe_nonce = O0Ooo . nonce
 if 10 - 10: II111iiii - Ii1I . I11i . O0 + Ii1I
 I1iiIiI1II1ii = deid . is_multicast_address ( )
 if ( I1iiIiI1II1ii ) :
  O0Ooo . target_eid = seid
  O0Ooo . target_group = deid
 else :
  O0Ooo . target_eid = deid
  if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
  if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
  if 21 - 21: I1ii11iIi11i - ooOoO0o
  if 81 - 81: iII111i / i11iIiiIii / I1Ii111
  if 70 - 70: I1ii11iIi11i / i11iIiiIii
  if 90 - 90: II111iiii / OoOoOO00 . Ii1I . OoooooooOO
  if 76 - 76: OoooooooOO
  if 78 - 78: IiII % i11iIiiIii
  if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
 if ( O0Ooo . rloc_probe == False ) :
  OoO0oO = lisp_get_signature_eid ( )
  if ( OoO0oO ) :
   O0Ooo . signature_eid . copy_address ( OoO0oO . eid )
   O0Ooo . privkey_filename = "./lisp-sig.pem"
   if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
   if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
   if 19 - 19: o0oOOo0O0Ooo
   if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
   if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
   if 71 - 71: OoO0O00 - I11i
 if ( seid == None or I1iiIiI1II1ii ) :
  O0Ooo . source_eid . afi = LISP_AFI_NONE
 else :
  O0Ooo . source_eid = seid
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
  if 56 - 56: OoOoOO00 + II111iiii / i11iIiiIii * OoOoOO00 * OoooooooOO
  if 15 - 15: OoOoOO00 / OoooooooOO + OOooOOo
 if ( Ii11I1Ii1 != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( Ii11I1Ii1 . is_private_address ( ) == False ) :
   Ii1I1iI1i = lisp_get_any_translated_rloc ( )
   if 76 - 76: Ii1I * iII111i . OoooooooOO
  if ( Ii1I1iI1i == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 92 - 92: iIii1I11I1II1 - Oo0Ooo - I1IiiI - OOooOOo * I1Ii111
   if 44 - 44: I1Ii111 - II111iiii / OOooOOo
   if 50 - 50: I11i / I1ii11iIi11i
   if 60 - 60: II111iiii / Ii1I + OoO0O00 % I1IiiI * i1IIi / II111iiii
   if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
   if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
   if 3 - 3: OOooOOo / OoOoOO00 % iIii1I11I1II1
   if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 if ( Ii11I1Ii1 == None or Ii11I1Ii1 . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and Ii11I1Ii1 == None ) :
   i1Oo = lisp_get_any_translated_rloc ( )
   if ( i1Oo != None ) : Ii1I1iI1i = i1Oo
   if 45 - 45: OoO0O00 + OoOoOO00 + o0oOOo0O0Ooo
  O0Ooo . itr_rlocs . append ( Ii1I1iI1i )
  if 70 - 70: OOooOOo % OoOoOO00
 if ( Ii11I1Ii1 == None or Ii11I1Ii1 . is_ipv6 ( ) ) :
  if ( oOii11I111 == None or oOii11I111 . is_ipv6_link_local ( ) ) :
   oOii11I111 = None
  else :
   O0Ooo . itr_rloc_count = 1 if ( Ii11I1Ii1 == None ) else 0
   O0Ooo . itr_rlocs . append ( oOii11I111 )
   if 86 - 86: OoooooooOO + OOooOOo + OOooOOo + I1Ii111 + OoooooooOO + ooOoO0o
   if 84 - 84: OoOoOO00 * OoOoOO00 % ooOoO0o % II111iiii / iII111i + Oo0Ooo
   if 95 - 95: iII111i . oO0o % iIii1I11I1II1 - I1IiiI
   if 38 - 38: ooOoO0o % iIii1I11I1II1 - OOooOOo
   if 13 - 13: OOooOOo . i11iIiiIii
   if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
   if 79 - 79: oO0o
   if 47 - 47: OoooooooOO - i1IIi * OOooOOo
   if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
 if ( Ii11I1Ii1 != None and O0Ooo . itr_rlocs != [ ] ) :
  iiII1 = O0Ooo . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   iiII1 = Ii1I1iI1i
  elif ( deid . is_ipv6 ( ) ) :
   iiII1 = oOii11I111
  else :
   iiII1 = Ii1I1iI1i
   if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
   if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
   if 8 - 8: iII111i
   if 10 - 10: OoOoOO00 % I11i
   if 49 - 49: oO0o % ooOoO0o + II111iiii
   if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
 Oo00oo = O0Ooo . encode ( Ii11I1Ii1 , iiiI111i1iIi )
 O0Ooo . print_map_request ( )
 if 99 - 99: OoOoOO00
 if 46 - 46: I1ii11iIi11i / II111iiii / OoooooooOO / Ii1I
 if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
 if 8 - 8: oO0o
 if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
 if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
 if ( Ii11I1Ii1 != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   iII1ii1 = lisp_get_nat_info ( Ii11I1Ii1 , rloc . rloc_name )
   if 1 - 1: OoooooooOO . Ii1I
   if 68 - 68: Ii1I
   if 98 - 98: iII111i
   if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
   if ( iII1ii1 == None ) :
    iiiI1I = rloc . rloc . print_address_no_iid ( )
    Oo = "gleaned-{}" . format ( iiiI1I )
    iIIiiIi = rloc . translated_port
    iII1ii1 = lisp_nat_info ( iiiI1I , Oo , iIIiiIi )
    if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
   lisp_encapsulate_rloc_probe ( lisp_sockets , Ii11I1Ii1 , iII1ii1 ,
 Oo00oo )
   return
   if 67 - 67: o0oOOo0O0Ooo
   if 58 - 58: IiII % o0oOOo0O0Ooo + i1IIi
  O0O0 = Ii11I1Ii1 . print_address_no_iid ( )
  IIi11ii = lisp_convert_4to6 ( O0O0 )
  lisp_send ( lisp_sockets , IIi11ii , LISP_CTRL_PORT , Oo00oo )
  return
  if 33 - 33: II111iiii
  if 61 - 61: I1Ii111
  if 56 - 56: I1ii11iIi11i - OoooooooOO
  if 52 - 52: Oo0Ooo - I11i - IiII - OoOoOO00
  if 21 - 21: oO0o % o0oOOo0O0Ooo + I1Ii111 . OOooOOo / OOooOOo
  if 41 - 41: Oo0Ooo . ooOoO0o * oO0o
 iIi11ii1II1i1 = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  iii1i = lisp_get_decent_map_resolver ( deid )
 else :
  iii1i = lisp_get_map_resolver ( None , iIi11ii1II1i1 )
  if 38 - 38: OoooooooOO % iII111i
 if ( iii1i == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 6 - 6: iII111i / OoOoOO00 / i11iIiiIii - o0oOOo0O0Ooo
  return
  if 35 - 35: ooOoO0o / I1Ii111 / I1Ii111
 iii1i . last_used = lisp_get_timestamp ( )
 iii1i . map_requests_sent += 1
 if ( iii1i . last_nonce == 0 ) : iii1i . last_nonce = O0Ooo . nonce
 if 19 - 19: OoO0O00 % i11iIiiIii % iIii1I11I1II1
 if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
 if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
 if 14 - 14: I1Ii111 + Oo0Ooo
 if ( seid == None ) : seid = iiII1
 lisp_send_ecm ( lisp_sockets , Oo00oo , seid , lisp_ephem_port , deid ,
 iii1i . map_resolver )
 if 35 - 35: i11iIiiIii * Ii1I
 if 100 - 100: O0 . iII111i / iIii1I11I1II1
 if 47 - 47: ooOoO0o + OoOoOO00
 if 67 - 67: IiII - I1ii11iIi11i * i1IIi - ooOoO0o
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 91 - 91: I11i
 if 54 - 54: I1ii11iIi11i / i1IIi
 if 14 - 14: iIii1I11I1II1 * I11i . I11i * ooOoO0o * iII111i
 if 60 - 60: iIii1I11I1II1 + i1IIi + oO0o - iIii1I11I1II1 . i11iIiiIii * OoooooooOO
 iii1i . resolve_dns_name ( )
 return
 if 23 - 23: iII111i - IiII % i11iIiiIii
 if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
 if 60 - 60: OOooOOo - I1Ii111 * Oo0Ooo
 if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
 if 39 - 39: iIii1I11I1II1 / i1IIi % I11i % I1ii11iIi11i * IiII
 if 11 - 11: II111iiii + i1IIi
 if 1 - 1: OOooOOo
 if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 83 - 83: OoooooooOO
 if 53 - 53: o0oOOo0O0Ooo - Oo0Ooo / IiII + O0
 if 88 - 88: Oo0Ooo % I1Ii111 * O0 - i1IIi * OoO0O00
 if 74 - 74: Oo0Ooo % iIii1I11I1II1 + OOooOOo
 iIiiI1II11 = lisp_info ( )
 iIiiI1II11 . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : iIiiI1II11 . hostname += "-" + device_name
 if 65 - 65: I1ii11iIi11i + O0 + iII111i + II111iiii
 O0O0 = dest . print_address_no_iid ( )
 if 100 - 100: I1Ii111
 if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
 if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
 if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
 if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
 if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
 if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
 if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
 if 74 - 74: OoooooooOO + Ii1I
 if 100 - 100: I1IiiI
 if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
 if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
 if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
 if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
 if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
 if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
 IIiIiII = False
 if ( device_name ) :
  O0ooooo0O = lisp_get_host_route_next_hop ( O0O0 )
  if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
  if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
  if 40 - 40: I1ii11iIi11i
  if 76 - 76: Oo0Ooo - I11i
  if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
  if 39 - 39: I1IiiI
  if 8 - 8: IiII * i1IIi * i1IIi * O0
  if 69 - 69: Oo0Ooo
  if 48 - 48: iII111i
  if ( port == LISP_CTRL_PORT and O0ooooo0O != None ) :
   while ( True ) :
    time . sleep ( .01 )
    O0ooooo0O = lisp_get_host_route_next_hop ( O0O0 )
    if ( O0ooooo0O == None ) : break
    if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
    if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
    if 89 - 89: iII111i
  IIOoo0O = lisp_get_default_route_next_hops ( )
  for ooO000OO , OoII1 in IIOoo0O :
   if ( ooO000OO != device_name ) : continue
   if 18 - 18: oO0o * IiII % oO0o
   if 8 - 8: OoO0O00 * iII111i % OoooooooOO - I11i / I1IiiI % oO0o
   if 50 - 50: iIii1I11I1II1 + i1IIi * Oo0Ooo * OoooooooOO - II111iiii
   if 79 - 79: o0oOOo0O0Ooo * O0
   if 49 - 49: I11i / OoO0O00 % IiII
   if 62 - 62: oO0o % oO0o / o0oOOo0O0Ooo + I1IiiI + OOooOOo
   if ( O0ooooo0O != OoII1 ) :
    if ( O0ooooo0O != None ) :
     lisp_install_host_route ( O0O0 , O0ooooo0O , False )
     if 45 - 45: O0 . OoO0O00 % OOooOOo + iIii1I11I1II1 * iII111i % OoO0O00
    lisp_install_host_route ( O0O0 , OoII1 , True )
    IIiIiII = True
    if 62 - 62: I1Ii111 - ooOoO0o + iIii1I11I1II1 % OOooOOo + Oo0Ooo
   break
   if 59 - 59: I1IiiI * II111iiii . i1IIi - i1IIi
   if 23 - 23: oO0o * OoO0O00 % O0 . OoOoOO00 * Oo0Ooo
   if 69 - 69: OoOoOO00 % I1ii11iIi11i % II111iiii * oO0o
   if 100 - 100: i11iIiiIii . IiII - I1IiiI + I1Ii111
   if 29 - 29: Oo0Ooo . I1IiiI % ooOoO0o * I1ii11iIi11i . iII111i
   if 14 - 14: OoOoOO00 - O0 % Ii1I
 Oo00oo = iIiiI1II11 . encode ( )
 iIiiI1II11 . print_info ( )
 if 19 - 19: iII111i / i1IIi * O0 - OoO0O00
 if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
 if 32 - 32: O0 + IiII
 if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
 i1IiI = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 i1IiI = bold ( i1IiI , False )
 iIIiiIi = bold ( "{}" . format ( port ) , False )
 OO0O00o0 = red ( O0O0 , False )
 iiO0ooooOooo = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( iiO0ooooOooo , OO0O00o0 , iIIiiIi , i1IiI ) )
 if 17 - 17: OOooOOo
 if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
 if 46 - 46: II111iiii * OoO0O00
 if 77 - 77: ooOoO0o * I11i
 if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
 if 76 - 76: iII111i * OoooooooOO
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , Oo00oo )
 else :
  IiIii1iIIII = lisp_data_header ( )
  IiIii1iIIII . instance_id ( 0xffffff )
  IiIii1iIIII = IiIii1iIIII . encode ( )
  if ( IiIii1iIIII ) :
   Oo00oo = IiIii1iIIII + Oo00oo
   if 49 - 49: II111iiii - OOooOOo + II111iiii + OoOoOO00
   if 51 - 51: i11iIiiIii
   if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
   if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
   if 63 - 63: II111iiii - Oo0Ooo
   if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
   if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
   if 78 - 78: IiII - I1IiiI
   if 59 - 59: oO0o + i1IIi - IiII % OOooOOo % iIii1I11I1II1
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , Oo00oo )
   if 71 - 71: OoO0O00
   if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
   if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
   if 54 - 54: Ii1I / I1IiiI
   if 7 - 7: iIii1I11I1II1 . O0 + OOooOOo . Ii1I * Oo0Ooo
   if 25 - 25: I1Ii111 . Oo0Ooo % II111iiii . IiII - O0
   if 18 - 18: oO0o * OOooOOo
 if ( IIiIiII ) :
  lisp_install_host_route ( O0O0 , None , False )
  if ( O0ooooo0O != None ) : lisp_install_host_route ( O0O0 , O0ooooo0O , True )
  if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
 return
 if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
 if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
 if 96 - 96: II111iiii % I11i / Ii1I - i11iIiiIii
 if 63 - 63: I1IiiI
 if 15 - 15: iIii1I11I1II1 - I1ii11iIi11i % OoO0O00 * II111iiii / I11i + I11i
 if 23 - 23: I1IiiI
 if 51 - 51: i11iIiiIii / ooOoO0o - OoooooooOO + OoOoOO00 + oO0o
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 57 - 57: iIii1I11I1II1
 if 19 - 19: Ii1I / o0oOOo0O0Ooo + O0 / iIii1I11I1II1 + II111iiii
 if 3 - 3: oO0o % OoO0O00 % OOooOOo
 if 64 - 64: o0oOOo0O0Ooo . II111iiii * IiII % Oo0Ooo + I11i - OoooooooOO
 iIiiI1II11 = lisp_info ( )
 packet = iIiiI1II11 . decode ( packet )
 if ( packet == None ) : return
 iIiiI1II11 . print_info ( )
 if 58 - 58: ooOoO0o
 if 15 - 15: O0 * OOooOOo * I11i + Ii1I * OoooooooOO + OOooOOo
 if 77 - 77: O0
 if 98 - 98: iII111i - iII111i % i1IIi - I1Ii111 . I1IiiI % o0oOOo0O0Ooo
 if 38 - 38: IiII % OoOoOO00 . OOooOOo . I1ii11iIi11i
 iIiiI1II11 . info_reply = True
 iIiiI1II11 . global_etr_rloc . store_address ( addr_str )
 iIiiI1II11 . etr_port = sport
 if 34 - 34: iII111i . i11iIiiIii + OoO0O00 + o0oOOo0O0Ooo / ooOoO0o - i11iIiiIii
 if 63 - 63: ooOoO0o % OoO0O00 % ooOoO0o
 if 28 - 28: IiII * I1Ii111 * o0oOOo0O0Ooo + ooOoO0o - IiII / IiII
 if 73 - 73: iIii1I11I1II1 . I1ii11iIi11i + OOooOOo
 if 51 - 51: I11i % Oo0Ooo * OOooOOo % OoooooooOO - OoOoOO00 % Ii1I
 if ( iIiiI1II11 . hostname != None ) :
  iIiiI1II11 . private_etr_rloc . afi = LISP_AFI_NAME
  iIiiI1II11 . private_etr_rloc . store_address ( iIiiI1II11 . hostname )
  if 60 - 60: OoOoOO00 - IiII + OoO0O00
  if 77 - 77: iIii1I11I1II1
 if ( rtr_list != None ) : iIiiI1II11 . rtr_list = rtr_list
 packet = iIiiI1II11 . encode ( )
 iIiiI1II11 . print_info ( )
 if 92 - 92: IiII
 if 68 - 68: OOooOOo . IiII / iIii1I11I1II1 % i11iIiiIii
 if 74 - 74: iII111i + i11iIiiIii
 if 95 - 95: Ii1I
 if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 IIi11ii = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , IIi11ii , sport , packet )
 if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
 if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
 if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
 if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
 if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
 IIiIIiiI11 = lisp_info_source ( iIiiI1II11 . hostname , addr_str , sport )
 IIiIIiiI11 . cache_address_for_info_source ( )
 return
 if 92 - 92: I1IiiI + oO0o % iII111i
 if 47 - 47: ooOoO0o . OOooOOo . oO0o + oO0o + i1IIi + iIii1I11I1II1
 if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
 if 11 - 11: iII111i
 if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
 if 89 - 89: I11i % II111iiii
 if 35 - 35: oO0o
 if 65 - 65: II111iiii
def lisp_get_signature_eid ( ) :
 for OoO0oO in lisp_db_list :
  if ( OoO0oO . signature_eid ) : return ( OoO0oO )
  if 87 - 87: oO0o / OoO0O00 - oO0o
 return ( None )
 if 69 - 69: i11iIiiIii
 if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
 if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
 if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
 if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
 if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
 if 14 - 14: I1ii11iIi11i / i11iIiiIii * I11i % o0oOOo0O0Ooo + IiII / I1ii11iIi11i
 if 82 - 82: OOooOOo . oO0o
def lisp_get_any_translated_port ( ) :
 for OoO0oO in lisp_db_list :
  for OOOoOoo in OoO0oO . rloc_set :
   if ( OOOoOoo . translated_rloc . is_null ( ) ) : continue
   return ( OOOoOoo . translated_port )
   if 12 - 12: i11iIiiIii + II111iiii
   if 49 - 49: OoooooooOO
 return ( None )
 if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
 if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
 if 6 - 6: oO0o / II111iiii
 if 23 - 23: IiII - OoooooooOO / oO0o
 if 69 - 69: O0 - OoooooooOO
 if 31 - 31: o0oOOo0O0Ooo . i1IIi - i1IIi % i1IIi - iIii1I11I1II1
 if 50 - 50: IiII - OOooOOo % OoOoOO00
 if 66 - 66: IiII * i11iIiiIii
 if 64 - 64: i11iIiiIii . I1Ii111 % i11iIiiIii % I11i
def lisp_get_any_translated_rloc ( ) :
 for OoO0oO in lisp_db_list :
  for OOOoOoo in OoO0oO . rloc_set :
   if ( OOOoOoo . translated_rloc . is_null ( ) ) : continue
   return ( OOOoOoo . translated_rloc )
   if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
   if 64 - 64: OOooOOo / OoOoOO00
 return ( None )
 if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
 if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
 if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
 if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
 if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
 if 49 - 49: IiII
 if 1 - 1: oO0o / I11i
def lisp_get_all_translated_rlocs ( ) :
 OOO0O0Oo0O0 = [ ]
 for OoO0oO in lisp_db_list :
  for OOOoOoo in OoO0oO . rloc_set :
   if ( OOOoOoo . is_rloc_translated ( ) == False ) : continue
   IiI = OOOoOoo . translated_rloc . print_address_no_iid ( )
   OOO0O0Oo0O0 . append ( IiI )
   if 53 - 53: iII111i
   if 7 - 7: OoooooooOO . Ii1I - OoooooooOO / i1IIi / i1IIi / iIii1I11I1II1
 return ( OOO0O0Oo0O0 )
 if 78 - 78: i11iIiiIii / O0 . OoooooooOO % i11iIiiIii / iIii1I11I1II1 . OoooooooOO
 if 1 - 1: oO0o - i11iIiiIii . OoOoOO00
 if 16 - 16: OOooOOo
 if 33 - 33: o0oOOo0O0Ooo / OoO0O00 + OoooooooOO
 if 82 - 82: o0oOOo0O0Ooo / i1IIi / i11iIiiIii * Oo0Ooo / OoO0O00
 if 95 - 95: I11i . OoOoOO00 * Ii1I
 if 94 - 94: OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
 if 55 - 55: II111iiii - IiII
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 OoooO0oo0o0 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 24 - 24: oO0o % Ii1I / i1IIi
 oOOOI11I = { }
 for iIIiI11 in rtr_list :
  if ( iIIiI11 == None ) : continue
  IiI = rtr_list [ iIIiI11 ]
  if ( OoooO0oo0o0 and IiI . is_private_address ( ) ) : continue
  oOOOI11I [ iIIiI11 ] = IiI
  if 52 - 52: Ii1I * II111iiii - OOooOOo % o0oOOo0O0Ooo
 rtr_list = oOOOI11I
 if 78 - 78: OOooOOo + OoooooooOO - I1IiiI - Ii1I . II111iiii . O0
 IIi1I1i11i11 = [ ]
 for i1I1iiiI in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( i1I1iiiI == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 52 - 52: oO0o
  if 73 - 73: IiII - II111iiii - OOooOOo % II111iiii + iIii1I11I1II1
  if 81 - 81: i11iIiiIii - O0 + I1IiiI
  if 39 - 39: IiII * OOooOOo . OoooooooOO + Oo0Ooo + iIii1I11I1II1
  if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
  Oo0OoOI1I11iII1I1i = lisp_address ( i1I1iiiI , "" , 0 , iid )
  Oo0OoOI1I11iII1I1i . make_default_route ( Oo0OoOI1I11iII1I1i )
  I11iiI1III = lisp_map_cache . lookup_cache ( Oo0OoOI1I11iII1I1i , True )
  if ( I11iiI1III ) :
   if ( I11iiI1III . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( I11iiI1III . print_eid_tuple ( ) , False ) ) )
    if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
   elif ( I11iiI1III . do_rloc_sets_match ( list ( rtr_list . values ( ) ) ) ) :
    continue
    if 10 - 10: O0 / I11i
   I11iiI1III . delete_cache ( )
   if 29 - 29: i11iIiiIii % I11i
   if 49 - 49: I11i
  IIi1I1i11i11 . append ( [ Oo0OoOI1I11iII1I1i , "" ] )
  if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
  if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
  if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
  if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
  oo0oOooo0O = lisp_address ( i1I1iiiI , "" , 0 , iid )
  oo0oOooo0O . make_default_multicast_route ( oo0oOooo0O )
  O0o0o0o0O = lisp_map_cache . lookup_cache ( oo0oOooo0O , True )
  if ( O0o0o0o0O ) : O0o0o0o0O = O0o0o0o0O . source_cache . lookup_cache ( Oo0OoOI1I11iII1I1i , True )
  if ( O0o0o0o0O ) : O0o0o0o0O . delete_cache ( )
  if 16 - 16: iIii1I11I1II1 / OoO0O00 . IiII + IiII / I1ii11iIi11i
  IIi1I1i11i11 . append ( [ Oo0OoOI1I11iII1I1i , oo0oOooo0O ] )
  if 49 - 49: I11i + OOooOOo - I1ii11iIi11i
 if ( len ( IIi1I1i11i11 ) == 0 ) : return
 if 23 - 23: OOooOOo % I1ii11iIi11i + iIii1I11I1II1 + iII111i
 if 9 - 9: OOooOOo * o0oOOo0O0Ooo / I11i . i11iIiiIii
 if 44 - 44: iII111i - II111iiii
 if 45 - 45: OoO0O00 % iII111i / iIii1I11I1II1 % I1IiiI + OOooOOo
 OO00O000OOO = [ ]
 for iiO0ooooOooo in rtr_list :
  o0Ii1i1ii11 = rtr_list [ iiO0ooooOooo ]
  OOOoOoo = lisp_rloc ( )
  OOOoOoo . rloc . copy_address ( o0Ii1i1ii11 )
  OOOoOoo . priority = 254
  OOOoOoo . mpriority = 255
  OOOoOoo . rloc_name = "RTR"
  OO00O000OOO . append ( OOOoOoo )
  if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
  if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
 for Oo0OoOI1I11iII1I1i in IIi1I1i11i11 :
  I11iiI1III = lisp_mapping ( Oo0OoOI1I11iII1I1i [ 0 ] , Oo0OoOI1I11iII1I1i [ 1 ] , OO00O000OOO )
  I11iiI1III . mapping_source = map_resolver
  I11iiI1III . map_cache_ttl = LISP_MR_TTL * 60
  I11iiI1III . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( I11iiI1III . print_eid_tuple ( ) , False ) , list ( rtr_list . keys ( ) ) ) )
  if 26 - 26: OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
  OO00O000OOO = copy . deepcopy ( OO00O000OOO )
  if 39 - 39: I1ii11iIi11i * I1IiiI * II111iiii . Oo0Ooo % I1IiiI
 return
 if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
 if 98 - 98: OoO0O00 + oO0o - II111iiii
 if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
 if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
 if 77 - 77: iIii1I11I1II1 * Oo0Ooo . IiII / oO0o + O0
 if 76 - 76: iII111i + o0oOOo0O0Ooo - OoooooooOO * oO0o % OoooooooOO - O0
 if 18 - 18: Ii1I
 if 82 - 82: OoOoOO00 + OoO0O00 - IiII / ooOoO0o
 if 70 - 70: OoO0O00
 if 43 - 43: ooOoO0o + OOooOOo + II111iiii - I1IiiI
def lisp_process_info_reply ( source , packet , store ) :
 if 58 - 58: I11i
 if 94 - 94: Oo0Ooo
 if 39 - 39: I11i - oO0o % iII111i - ooOoO0o - OoOoOO00
 if 8 - 8: i1IIi % i1IIi % OoooooooOO % i1IIi . iIii1I11I1II1
 iIiiI1II11 = lisp_info ( )
 packet = iIiiI1II11 . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
 iIiiI1II11 . print_info ( )
 if 58 - 58: II111iiii * oO0o - i1IIi . I11i
 if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
 if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
 if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
 I1i1 = False
 for iiO0ooooOooo in iIiiI1II11 . rtr_list :
  O0O0 = iiO0ooooOooo . print_address_no_iid ( )
  if ( O0O0 in lisp_rtr_list ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ O0O0 ] != None ) : continue
   if 51 - 51: I1IiiI . ooOoO0o / Ii1I / I1Ii111
  I1i1 = True
  lisp_rtr_list [ O0O0 ] = iiO0ooooOooo
  if 84 - 84: I11i - Ii1I
  if 36 - 36: i1IIi
  if 21 - 21: iII111i . OoOoOO00 % o0oOOo0O0Ooo - i11iIiiIii
  if 86 - 86: I1Ii111 % i11iIiiIii
  if 22 - 22: I1Ii111
 if ( lisp_i_am_itr and I1i1 ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for oooo in list ( lisp_iid_to_interface . keys ( ) ) :
    lisp_update_default_routes ( source , int ( oooo ) , lisp_rtr_list )
    if 64 - 64: OoOoOO00 + II111iiii + o0oOOo0O0Ooo % iIii1I11I1II1 - OOooOOo
    if 60 - 60: ooOoO0o % iIii1I11I1II1 / iIii1I11I1II1
    if 61 - 61: oO0o
    if 12 - 12: iIii1I11I1II1 - I1ii11iIi11i % I1ii11iIi11i * I1Ii111
    if 98 - 98: oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o - OoO0O00
    if 12 - 12: IiII . OoooooooOO - iIii1I11I1II1 % iII111i
    if 56 - 56: Oo0Ooo / I1IiiI + iIii1I11I1II1 + I1IiiI % iIii1I11I1II1
 if ( store == False ) :
  return ( [ iIiiI1II11 . global_etr_rloc , iIiiI1II11 . etr_port , I1i1 ] )
  if 64 - 64: O0
  if 55 - 55: OoO0O00 * oO0o . Ii1I + OoOoOO00 % I11i + IiII
  if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
  if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
  if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
  if 7 - 7: I1Ii111 % i1IIi . I11i . O0 / i1IIi
 for OoO0oO in lisp_db_list :
  for OOOoOoo in OoO0oO . rloc_set :
   iIIiI11 = OOOoOoo . rloc
   i111IIiIiiI1 = OOOoOoo . interface
   if ( i111IIiIiiI1 == None ) :
    if ( iIIiI11 . is_null ( ) ) : continue
    if ( iIIiI11 . is_local ( ) == False ) : continue
    if ( iIiiI1II11 . private_etr_rloc . is_null ( ) == False and
 iIIiI11 . is_exact_match ( iIiiI1II11 . private_etr_rloc ) == False ) :
     continue
     if 56 - 56: Oo0Ooo
   elif ( iIiiI1II11 . private_etr_rloc . is_dist_name ( ) ) :
    oOo = iIiiI1II11 . private_etr_rloc . address
    if ( oOo != OOOoOoo . rloc_name ) : continue
    if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
    if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
   i1iiii = green ( OoO0oO . eid . print_prefix ( ) , False )
   IIIOo0O = red ( iIIiI11 . print_address_no_iid ( ) , False )
   if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
   iIi1I11IIi = iIiiI1II11 . global_etr_rloc . is_exact_match ( iIIiI11 )
   if ( OOOoOoo . translated_port == 0 and iIi1I11IIi ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( IIIOo0O ,
 i111IIiIiiI1 , i1iiii ) )
    continue
    if 73 - 73: Ii1I - II111iiii + I1IiiI % i11iIiiIii * I11i
    if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
    if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
    if 64 - 64: OoooooooOO
    if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
   oOOoo0oO = iIiiI1II11 . global_etr_rloc
   iI1i1i11Ii1 = OOOoOoo . translated_rloc
   if ( iI1i1i11Ii1 . is_exact_match ( oOOoo0oO ) and
 iIiiI1II11 . etr_port == OOOoOoo . translated_port ) : continue
   if 80 - 80: IiII
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( iIiiI1II11 . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # I1ii11iIi11i - iII111i * i1IIi * iII111i
 iIiiI1II11 . etr_port , IIIOo0O , i111IIiIiiI1 , i1iiii ) )
   if 61 - 61: Oo0Ooo - o0oOOo0O0Ooo
   OOOoOoo . store_translated_rloc ( iIiiI1II11 . global_etr_rloc ,
 iIiiI1II11 . etr_port )
   if 36 - 36: OOooOOo
   if 16 - 16: I1ii11iIi11i % Ii1I . iII111i * I1IiiI * Ii1I
 return ( [ iIiiI1II11 . global_etr_rloc , iIiiI1II11 . etr_port , I1i1 ] )
 if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
 if 60 - 60: i1IIi / iII111i
 if 10 - 10: I1Ii111 / OoOoOO00 * Ii1I % o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i
 if 2 - 2: iIii1I11I1II1
 if 85 - 85: O0 - ooOoO0o
 if 35 - 35: o0oOOo0O0Ooo - I1IiiI
 if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
 if 65 - 65: Ii1I % i11iIiiIii
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
 o0Ooo0Oooo0o = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 II1iiII1ii111 = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 82 - 82: o0oOOo0O0Ooo / iIii1I11I1II1
 if 81 - 81: iII111i / i11iIiiIii * I1Ii111 % OoooooooOO . I1IiiI
 if 3 - 3: OoOoOO00 . I11i * i11iIiiIii - ooOoO0o
 if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
 o0Ooo0Oooo0o . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , o0Ooo0Oooo0o , None )
 o0Ooo0Oooo0o . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , o0Ooo0Oooo0o , None )
 if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
 if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
 if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
 if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
 II1iiII1ii111 . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , II1iiII1ii111 , None )
 II1iiII1ii111 . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , II1iiII1ii111 , None )
 if 42 - 42: II111iiii . iII111i
 if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
 if 64 - 64: oO0o / IiII
 if 86 - 86: I11i
 iIIi1OO00ooo = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 iIIi1OO00ooo . start ( )
 return
 if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
 if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
 if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
 if 12 - 12: I1IiiI . OOooOOo % Oo0Ooo
 if 86 - 86: i11iIiiIii
 if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
 if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
 if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
 if 79 - 79: I11i - II111iiii
 if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
 if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
 if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
 if 44 - 44: I1IiiI * IiII . OoooooooOO
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
 IiI = lisp_get_interface_address ( rloc . interface )
 if ( IiI == None ) : return
 if 10 - 10: i1IIi + o0oOOo0O0Ooo
 I111i1IIiii11 = rloc . rloc . print_address_no_iid ( )
 I11Ii1I1I1111 = IiI . print_address_no_iid ( )
 if 79 - 79: i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
 if ( I111i1IIiii11 == I11Ii1I1I1111 ) : return
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , I111i1IIiii11 , I11Ii1I1I1111 ) )
 if 2 - 2: I11i
 if 12 - 12: i1IIi . I1Ii111
 rloc . rloc . copy_address ( IiI )
 lisp_myrlocs [ 0 ] = IiI
 return
 if 99 - 99: Oo0Ooo / i11iIiiIii
 if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
 if 42 - 42: iII111i / Oo0Ooo
 if 14 - 14: O0 . Oo0Ooo
 if 8 - 8: i11iIiiIii
 if 80 - 80: I1ii11iIi11i + Ii1I
 if 16 - 16: i11iIiiIii * Oo0Ooo
 if 76 - 76: iII111i . oO0o - i1IIi
def lisp_update_encap_port ( mc ) :
 for iIIiI11 in mc . rloc_set :
  iII1ii1 = lisp_get_nat_info ( iIIiI11 . rloc , iIIiI11 . rloc_name )
  if ( iII1ii1 == None ) : continue
  if ( iIIiI11 . translated_port == iII1ii1 . port ) : continue
  if 94 - 94: O0 % iII111i
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( iIIiI11 . translated_port , iII1ii1 . port ,
  # IiII . ooOoO0o . I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OOooOOo
 red ( iIIiI11 . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 19 - 19: Ii1I - I1IiiI + OoOoOO00
  iIIiI11 . store_translated_rloc ( iIIiI11 . rloc , iII1ii1 . port )
  if 33 - 33: Oo0Ooo + O0 . I11i + I11i
 return
 if 100 - 100: iII111i . Oo0Ooo
 if 29 - 29: IiII * I1IiiI * oO0o * I1Ii111 / iIii1I11I1II1 . o0oOOo0O0Ooo
 if 95 - 95: O0 . OOooOOo / II111iiii + II111iiii
 if 45 - 45: II111iiii . iII111i
 if 11 - 11: oO0o / OoooooooOO - OoO0O00 . iIii1I11I1II1 % I1IiiI
 if 98 - 98: I1IiiI + Ii1I
 if 7 - 7: o0oOOo0O0Ooo . OoooooooOO
 if 32 - 32: I1ii11iIi11i
 if 46 - 46: Ii1I . i11iIiiIii / I1Ii111 - I1ii11iIi11i
 if 13 - 13: IiII % I1Ii111
 if 9 - 9: OoooooooOO * ooOoO0o % I1ii11iIi11i . I1IiiI % O0
 if 91 - 91: OOooOOo * OoooooooOO * I1IiiI . i1IIi
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 9 - 9: oO0o / i11iIiiIii + IiII / IiII - I11i
  if 87 - 87: iII111i
 O000oo = lisp_get_timestamp ( )
 if 37 - 37: oO0o + OoO0O00
 if 66 - 66: iIii1I11I1II1 * iIii1I11I1II1 + IiII % I1IiiI
 if 60 - 60: I1Ii111 . IiII / Oo0Ooo
 if 32 - 32: OoOoOO00 + Ii1I * iII111i % Oo0Ooo
 if 61 - 61: OoooooooOO % iII111i - O0
 if 62 - 62: iIii1I11I1II1
 if ( mc . last_refresh_time + mc . map_cache_ttl > O000oo ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 14 - 14: I1Ii111
  if 95 - 95: II111iiii / o0oOOo0O0Ooo * OOooOOo
  if 81 - 81: i11iIiiIii / iIii1I11I1II1
  if 73 - 73: i11iIiiIii . I1ii11iIi11i * OoOoOO00
  if 95 - 95: i1IIi + iIii1I11I1II1 . I1Ii111 / I1Ii111
 if ( lisp_nat_traversal and mc . eid . address == 0 and mc . eid . mask_len == 0 ) :
  return ( [ True , delete_list ] )
  if 84 - 84: Oo0Ooo . OoO0O00 * IiII
  if 95 - 95: OoO0O00
  if 100 - 100: II111iiii
  if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
  if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
 i1i111Iiiiiii = lisp_print_elapsed ( mc . last_refresh_time )
 o0oo0OO0oO = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( o0oo0OO0oO , False ) , bold ( "timed out" , False ) , i1i111Iiiiiii ) )
 if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
 if 42 - 42: ooOoO0o + I1IiiI * iII111i / OoOoOO00 . i1IIi - OoooooooOO
 if 8 - 8: iIii1I11I1II1 - Oo0Ooo + iII111i
 if 40 - 40: o0oOOo0O0Ooo * I1IiiI
 if 75 - 75: O0 * OOooOOo / ooOoO0o + I11i
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 56 - 56: I1IiiI % OoooooooOO % Oo0Ooo
 if 19 - 19: i11iIiiIii - iIii1I11I1II1 . i1IIi . I1Ii111 / I1IiiI * I1Ii111
 if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i * OoOoOO00
 if 16 - 16: oO0o
 if 32 - 32: OoooooooOO
 if 77 - 77: Oo0Ooo . i1IIi - I11i
 if 98 - 98: O0
 if 87 - 87: OoO0O00 % I1Ii111 - OOooOOo - II111iiii + iII111i
def lisp_timeout_map_cache_walk ( mc , parms ) :
 iIi1II1IiI1I = parms [ 0 ]
 oo0ooOoOO0 = parms [ 1 ]
 if 22 - 22: Oo0Ooo - I1ii11iIi11i + I11i . oO0o
 if 85 - 85: iIii1I11I1II1 / Ii1I
 if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
 if 97 - 97: I1Ii111 + I1ii11iIi11i
 if ( mc . group . is_null ( ) ) :
  o0o0O0O0Oooo0 , iIi1II1IiI1I = lisp_timeout_map_cache_entry ( mc , iIi1II1IiI1I )
  if ( iIi1II1IiI1I == [ ] or mc != iIi1II1IiI1I [ - 1 ] ) :
   oo0ooOoOO0 = lisp_write_checkpoint_entry ( oo0ooOoOO0 , mc )
   if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
  return ( [ o0o0O0O0Oooo0 , parms ] )
  if 80 - 80: I11i
  if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
 if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
 if 46 - 46: Oo0Ooo / Oo0Ooo * IiII
 if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
 if 65 - 65: I11i
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 92 - 92: iII111i . IiII + i1IIi % i1IIi
 if 11 - 11: I1ii11iIi11i + iIii1I11I1II1 - I1Ii111 * iIii1I11I1II1 * IiII + oO0o
 if 6 - 6: I1Ii111 * OOooOOo + i1IIi - Ii1I / oO0o
 if 81 - 81: I1Ii111 % oO0o * i1IIi * OoooooooOO / Oo0Ooo
 if 70 - 70: I1IiiI
 if 35 - 35: i11iIiiIii
 if 59 - 59: ooOoO0o . iII111i - II111iiii
def lisp_timeout_map_cache ( lisp_map_cache ) :
 I1iII1IIi1IiI = [ [ ] , [ ] ]
 I1iII1IIi1IiI = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , I1iII1IIi1IiI )
 if 30 - 30: o0oOOo0O0Ooo % iII111i - i11iIiiIii
 if 25 - 25: i11iIiiIii + OoOoOO00 + oO0o / Ii1I * Oo0Ooo + Oo0Ooo
 if 26 - 26: I1IiiI % I1ii11iIi11i + o0oOOo0O0Ooo / I1ii11iIi11i - I1IiiI
 if 55 - 55: OoooooooOO
 if 2 - 2: Oo0Ooo + I11i / OOooOOo + OOooOOo
 iIi1II1IiI1I = I1iII1IIi1IiI [ 0 ]
 for I11iiI1III in iIi1II1IiI1I : I11iiI1III . delete_cache ( )
 if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
 if 90 - 90: OOooOOo
 if 29 - 29: OoOoOO00 - I1IiiI / oO0o + Oo0Ooo + I1Ii111 + O0
 if 65 - 65: oO0o
 oo0ooOoOO0 = I1iII1IIi1IiI [ 1 ]
 lisp_checkpoint ( oo0ooOoOO0 )
 return
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
def lisp_store_nat_info ( hostname , rloc , port ) :
 O0O0 = rloc . print_address_no_iid ( )
 IIII = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( O0O0 , False ) , port )
 if 23 - 23: iIii1I11I1II1 + I1ii11iIi11i * ooOoO0o - OOooOOo % O0
 iiii1i11 = lisp_nat_info ( O0O0 , hostname , port )
 if 67 - 67: i1IIi . oO0o
 if ( hostname not in lisp_nat_state_info ) :
  lisp_nat_state_info [ hostname ] = [ iiii1i11 ]
  lprint ( IIII . format ( "Store initial" ) )
  return ( True )
  if 17 - 17: iII111i * I1IiiI % I1Ii111 + OoOoOO00 * ooOoO0o - O0
  if 36 - 36: O0 / I11i % OoOoOO00 % OoOoOO00 * iII111i
  if 99 - 99: o0oOOo0O0Ooo - iIii1I11I1II1 * OoO0O00 - oO0o * oO0o % IiII
  if 44 - 44: I11i / I1ii11iIi11i
  if 67 - 67: iIii1I11I1II1 / I1IiiI / I1IiiI . O0 * iII111i
  if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
 iII1ii1 = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( iII1ii1 . address == O0O0 and iII1ii1 . port == port ) :
  iII1ii1 . uptime = lisp_get_timestamp ( )
  lprint ( IIII . format ( "Refresh existing" ) )
  return ( False )
  if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
  if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
  if 47 - 47: I1Ii111 * iII111i
  if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
  if 76 - 76: iIii1I11I1II1 . i11iIiiIii * II111iiii - iII111i
  if 51 - 51: I1IiiI
  if 52 - 52: I1Ii111
 o0ooO0 = None
 for iII1ii1 in lisp_nat_state_info [ hostname ] :
  if ( iII1ii1 . address == O0O0 and iII1ii1 . port == port ) :
   o0ooO0 = iII1ii1
   break
   if 7 - 7: I11i % O0 * i11iIiiIii % I1Ii111 - I1Ii111 % Oo0Ooo
   if 83 - 83: i1IIi
   if 23 - 23: oO0o * II111iiii * i1IIi
 if ( o0ooO0 == None ) :
  lprint ( IIII . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( o0ooO0 )
  lprint ( IIII . format ( "Use previous" ) )
  if 14 - 14: Ii1I - I11i / i1IIi * OoOoOO00 * ooOoO0o
  if 78 - 78: iII111i % I1ii11iIi11i . I11i
 oo00O0oO000o = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ iiii1i11 ] + oo00O0oO000o
 return ( True )
 if 29 - 29: IiII . ooOoO0o . OOooOOo % I11i . I1Ii111
 if 75 - 75: OOooOOo % Oo0Ooo + iIii1I11I1II1 . I11i
 if 92 - 92: I1ii11iIi11i / ooOoO0o
 if 21 - 21: OoO0O00 % II111iiii / OoooooooOO
 if 4 - 4: i11iIiiIii + OoooooooOO * i1IIi * iIii1I11I1II1 - OOooOOo
 if 23 - 23: ooOoO0o + Oo0Ooo
 if 43 - 43: Ii1I
 if 87 - 87: OoO0O00
def lisp_get_nat_info ( rloc , hostname ) :
 if ( hostname not in lisp_nat_state_info ) : return ( None )
 if 32 - 32: I11i
 O0O0 = rloc . print_address_no_iid ( )
 for iII1ii1 in lisp_nat_state_info [ hostname ] :
  if ( iII1ii1 . address == O0O0 ) : return ( iII1ii1 )
  if 78 - 78: ooOoO0o * iII111i
 return ( None )
 if 31 - 31: I1IiiI + OOooOOo . OoooooooOO
 if 24 - 24: ooOoO0o
 if 53 - 53: I1ii11iIi11i % OOooOOo
 if 92 - 92: I1IiiI / ooOoO0o
 if 5 - 5: OoooooooOO - oO0o
 if 52 - 52: I11i . OOooOOo * ooOoO0o / i11iIiiIii . OoO0O00 * ooOoO0o
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
 if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
 if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
 if 73 - 73: OoooooooOO
 if 25 - 25: i1IIi . II111iiii . I1Ii111
 if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
 if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
 if 61 - 61: I1ii11iIi11i
 i1IiIi = [ ]
 IiiiIIiII = [ ]
 if ( dest == None ) :
  for iii1i in list ( lisp_map_resolvers_list . values ( ) ) :
   IiiiIIiII . append ( iii1i . map_resolver )
   if 60 - 60: ooOoO0o % Ii1I
  i1IiIi = IiiiIIiII
  if ( i1IiIi == [ ] ) :
   for oO00000oOO in list ( lisp_map_servers_list . values ( ) ) :
    i1IiIi . append ( oO00000oOO . map_server )
    if 33 - 33: OoO0O00 . II111iiii % iIii1I11I1II1
    if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
  if ( i1IiIi == [ ] ) : return
 else :
  i1IiIi . append ( dest )
  if 3 - 3: Ii1I
  if 71 - 71: iIii1I11I1II1 . OOooOOo / I11i / i1IIi
  if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
  if 86 - 86: Oo0Ooo
  if 97 - 97: I1IiiI
 OOO0O0Oo0O0 = { }
 for OoO0oO in lisp_db_list :
  for OOOoOoo in OoO0oO . rloc_set :
   lisp_update_local_rloc ( OOOoOoo )
   if ( OOOoOoo . rloc . is_null ( ) ) : continue
   if ( OOOoOoo . interface == None ) : continue
   if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
   IiI = OOOoOoo . rloc . print_address_no_iid ( )
   if ( IiI in OOO0O0Oo0O0 ) : continue
   OOO0O0Oo0O0 [ IiI ] = OOOoOoo . interface
   if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
   if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
 if ( OOO0O0Oo0O0 == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
  return
  if 64 - 64: I1IiiI % ooOoO0o
  if 72 - 72: O0 * II111iiii % OoO0O00 - I1IiiI * OOooOOo
  if 80 - 80: OOooOOo * I11i / OOooOOo - oO0o
  if 18 - 18: i1IIi - OOooOOo - o0oOOo0O0Ooo - iIii1I11I1II1
  if 72 - 72: OoooooooOO % I1IiiI . OoO0O00
  if 28 - 28: II111iiii / iIii1I11I1II1 / iII111i - o0oOOo0O0Ooo . I1IiiI / O0
 for IiI in OOO0O0Oo0O0 :
  i111IIiIiiI1 = OOO0O0Oo0O0 [ IiI ]
  OO0O00o0 = red ( IiI , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( OO0O00o0 ,
 i111IIiIiiI1 ) )
  ooO000OO = i111IIiIiiI1 if len ( OOO0O0Oo0O0 ) > 1 else None
  for dest in i1IiIi :
   lisp_send_info_request ( lisp_sockets , dest , port , ooO000OO )
   if 16 - 16: ooOoO0o * oO0o . OoooooooOO
   if 44 - 44: iIii1I11I1II1 * OOooOOo + OoO0O00 - OoooooooOO
   if 13 - 13: Oo0Ooo . I11i . II111iiii
   if 6 - 6: OOooOOo . IiII / OoO0O00 * oO0o - I1Ii111 . OoOoOO00
   if 85 - 85: i11iIiiIii + OoOoOO00
   if 4 - 4: OOooOOo . OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
 if ( IiiiIIiII != [ ] ) :
  for iii1i in list ( lisp_map_resolvers_list . values ( ) ) :
   iii1i . resolve_dns_name ( )
   if 60 - 60: OOooOOo . Ii1I
   if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
 return
 if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
 if 38 - 38: IiII / I11i / IiII * iII111i
 if 30 - 30: oO0o
 if 30 - 30: IiII / OoO0O00
 if 89 - 89: oO0o . OoOoOO00 . IiII / iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00
 if 86 - 86: OoooooooOO - iIii1I11I1II1 . OoO0O00 * Ii1I / I1Ii111 + I1Ii111
 if 52 - 52: iIii1I11I1II1 % OoO0O00 - IiII % i11iIiiIii - o0oOOo0O0Ooo
 if 25 - 25: Oo0Ooo - OOooOOo . i1IIi * OoOoOO00 / I11i / o0oOOo0O0Ooo
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 54 - 54: OoOoOO00 / i1IIi + OOooOOo - I1ii11iIi11i - I1IiiI * I1Ii111
 if 91 - 91: OoooooooOO * OoooooooOO
 if 27 - 27: ooOoO0o / I1IiiI * I1ii11iIi11i . o0oOOo0O0Ooo
 if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
 if 33 - 33: OOooOOo % OoooooooOO
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 98 - 98: Ii1I
 if 38 - 38: ooOoO0o - iII111i * OOooOOo % I1ii11iIi11i + Oo0Ooo
 if 95 - 95: iIii1I11I1II1 / O0 % O0
 if 53 - 53: ooOoO0o . ooOoO0o
 if ( value . find ( "." ) != - 1 ) :
  IiI = value . split ( "." )
  if ( len ( IiI ) != 4 ) : return ( False )
  if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
  for OoiIiiIi11 in IiI :
   if ( OoiIiiIi11 . isdigit ( ) == False ) : return ( False )
   if ( int ( OoiIiiIi11 ) > 255 ) : return ( False )
   if 18 - 18: OoO0O00 * ooOoO0o
  return ( True )
  if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
  if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
  if 67 - 67: I1IiiI
  if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
  if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
 if ( value . find ( "-" ) != - 1 ) :
  IiI = value . split ( "-" )
  for iIi1iIIIiIiI in [ "N" , "S" , "W" , "E" ] :
   if ( iIi1iIIIiIiI in IiI ) :
    if ( len ( IiI ) < 8 ) : return ( False )
    return ( True )
    if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
    if 59 - 59: i11iIiiIii
    if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
    if 59 - 59: I1ii11iIi11i
    if 47 - 47: I1IiiI + Oo0Ooo
    if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
    if 10 - 10: i1IIi % ooOoO0o / iII111i
 if ( value . find ( "-" ) != - 1 ) :
  IiI = value . split ( "-" )
  if ( len ( IiI ) != 3 ) : return ( False )
  if 98 - 98: IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
  for O00OoO in IiI :
   try : int ( O00OoO , 16 )
   except : return ( False )
   if 10 - 10: IiII
  return ( True )
  if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
  if 34 - 34: I1ii11iIi11i . i1IIi * O0 / OoooooooOO
  if 22 - 22: OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
  if 58 - 58: IiII . Ii1I + II111iiii
  if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
 if ( value . find ( ":" ) != - 1 ) :
  IiI = value . split ( ":" )
  if ( len ( IiI ) < 2 ) : return ( False )
  if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
  OOO0OoOO0O = False
  O0oo0oOo = 0
  for O00OoO in IiI :
   O0oo0oOo += 1
   if ( O00OoO == "" ) :
    if ( OOO0OoOO0O ) :
     if ( len ( IiI ) == O0oo0oOo ) : break
     if ( O0oo0oOo > 2 ) : return ( False )
     if 58 - 58: II111iiii - OOooOOo . IiII % O0
    OOO0OoOO0O = True
    continue
    if 53 - 53: o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
   try : int ( O00OoO , 16 )
   except : return ( False )
   if 34 - 34: OOooOOo
  return ( True )
  if 2 - 2: I1Ii111 / o0oOOo0O0Ooo + I11i * Ii1I
  if 1 - 1: i11iIiiIii * OoO0O00 * OoO0O00
  if 25 - 25: ooOoO0o / i11iIiiIii / OoOoOO00 % O0 / OoooooooOO
  if 28 - 28: ooOoO0o % i1IIi - oO0o * II111iiii
  if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
 if ( value [ 0 ] == "+" ) :
  IiI = value [ 1 : : ]
  for o0o00O0OO0O0O in IiI :
   if ( o0o00O0OO0O0O . isdigit ( ) == False ) : return ( False )
   if 66 - 66: Oo0Ooo % IiII
  return ( True )
  if 30 - 30: IiII - iII111i * iIii1I11I1II1 % ooOoO0o
 return ( False )
 if 78 - 78: iIii1I11I1II1 % OoooooooOO . o0oOOo0O0Ooo
 if 85 - 85: i11iIiiIii
 if 96 - 96: OoOoOO00
 if 12 - 12: oO0o % OoO0O00 % I1ii11iIi11i . IiII % ooOoO0o
 if 11 - 11: O0 . i1IIi % ooOoO0o
 if 84 - 84: OoO0O00 . ooOoO0o + o0oOOo0O0Ooo + I11i - I1ii11iIi11i
 if 78 - 78: I11i % i11iIiiIii + iII111i * I1Ii111 % IiII % I1Ii111
 if 22 - 22: OOooOOo
 if 11 - 11: iIii1I11I1II1 + i1IIi % I1IiiI % I1Ii111
 if 49 - 49: Oo0Ooo / I1ii11iIi11i / I1IiiI * OoooooooOO . I1ii11iIi11i
 if 100 - 100: iIii1I11I1II1 . i1IIi / OOooOOo * i11iIiiIii
 if 93 - 93: I1ii11iIi11i
 if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
 if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
def lisp_process_api ( process , lisp_socket , data_structure ) :
 iIOooo00OO , I1iII1IIi1IiI = data_structure . split ( "%" )
 if 83 - 83: Ii1I % iIii1I11I1II1 / I1ii11iIi11i + I11i
 lprint ( "Process API request '{}', parameters: '{}'" . format ( iIOooo00OO ,
 I1iII1IIi1IiI ) )
 if 23 - 23: iIii1I11I1II1 - I1IiiI
 iiooo0o0oO = [ ]
 if ( iIOooo00OO == "map-cache" ) :
  if ( I1iII1IIi1IiI == "" ) :
   iiooo0o0oO = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , iiooo0o0oO )
  else :
   iiooo0o0oO = lisp_process_api_map_cache_entry ( json . loads ( I1iII1IIi1IiI ) )
   if 51 - 51: OoooooooOO / IiII / I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * OoooooooOO
   if 40 - 40: OoO0O00 / IiII . O0 / I1IiiI + OoO0O00 . o0oOOo0O0Ooo
 if ( iIOooo00OO == "site-cache" ) :
  if ( I1iII1IIi1IiI == "" ) :
   iiooo0o0oO = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 iiooo0o0oO )
  else :
   iiooo0o0oO = lisp_process_api_site_cache_entry ( json . loads ( I1iII1IIi1IiI ) )
   if 25 - 25: ooOoO0o * I1Ii111 * oO0o
   if 64 - 64: Ii1I / I1ii11iIi11i
 if ( iIOooo00OO == "site-cache-summary" ) :
  iiooo0o0oO = lisp_process_api_site_cache_summary ( lisp_sites_by_eid )
  if 30 - 30: OoooooooOO + O0 / I1ii11iIi11i * o0oOOo0O0Ooo
 if ( iIOooo00OO == "map-server" ) :
  I1iII1IIi1IiI = { } if ( I1iII1IIi1IiI == "" ) else json . loads ( I1iII1IIi1IiI )
  iiooo0o0oO = lisp_process_api_ms_or_mr ( True , I1iII1IIi1IiI )
  if 11 - 11: O0 + OoO0O00 - Oo0Ooo - Oo0Ooo . i11iIiiIii
 if ( iIOooo00OO == "map-resolver" ) :
  I1iII1IIi1IiI = { } if ( I1iII1IIi1IiI == "" ) else json . loads ( I1iII1IIi1IiI )
  iiooo0o0oO = lisp_process_api_ms_or_mr ( False , I1iII1IIi1IiI )
  if 15 - 15: Ii1I % i11iIiiIii / OoOoOO00
 if ( iIOooo00OO == "database-mapping" ) :
  iiooo0o0oO = lisp_process_api_database_mapping ( )
  if 85 - 85: ooOoO0o . i1IIi / iII111i % iIii1I11I1II1 / II111iiii / I1Ii111
  if 60 - 60: iIii1I11I1II1 - iIii1I11I1II1 . I11i
  if 55 - 55: OoO0O00
  if 87 - 87: Ii1I - iII111i / O0 - o0oOOo0O0Ooo - iIii1I11I1II1 % Ii1I
  if 47 - 47: iII111i * I1Ii111 % o0oOOo0O0Ooo / OoOoOO00 / OoO0O00 % OoO0O00
 iiooo0o0oO = json . dumps ( iiooo0o0oO )
 OO = lisp_api_ipc ( process , iiooo0o0oO )
 lisp_ipc ( OO , lisp_socket , "lisp-core" )
 return
 if 43 - 43: Oo0Ooo
 if 34 - 34: OoO0O00 . i1IIi + IiII * IiII
 if 76 - 76: OOooOOo
 if 54 - 54: O0 * II111iiii * OOooOOo
 if 44 - 44: I1IiiI
 if 66 - 66: o0oOOo0O0Ooo
 if 40 - 40: OOooOOo * Ii1I
def lisp_process_api_map_cache ( mc , data ) :
 if 38 - 38: ooOoO0o
 if 5 - 5: OoooooooOO + iII111i - I11i
 if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
 if 7 - 7: I1ii11iIi11i
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 37 - 37: O0 . II111iiii
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 70 - 70: o0oOOo0O0Ooo / iII111i + i1IIi + I11i % iIii1I11I1II1 % Oo0Ooo
 if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
 if 1 - 1: I1ii11iIi11i / i1IIi . I1IiiI / Ii1I
 if 19 - 19: iIii1I11I1II1 / Oo0Ooo . O0 - Oo0Ooo
 if 74 - 74: I1ii11iIi11i * OoooooooOO . iII111i
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 45 - 45: I1IiiI - IiII % ooOoO0o - IiII . Oo0Ooo - o0oOOo0O0Ooo
 if 27 - 27: iII111i
 if 64 - 64: iIii1I11I1II1 - OOooOOo . iII111i % o0oOOo0O0Ooo / II111iiii % OoooooooOO
 if 87 - 87: OoooooooOO
 if 70 - 70: o0oOOo0O0Ooo % OoooooooOO % I1IiiI . OoOoOO00 * I1IiiI - ooOoO0o
 if 92 - 92: I1IiiI . I11i
 if 66 - 66: I1Ii111 / I11i / OoooooooOO % OoOoOO00 . oO0o * iII111i
def lisp_gather_map_cache_data ( mc , data ) :
 oo0O00OOOOO = { }
 oo0O00OOOOO [ "instance-id" ] = str ( mc . eid . instance_id )
 oo0O00OOOOO [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  oo0O00OOOOO [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 34 - 34: I1ii11iIi11i * I1ii11iIi11i % I11i / OOooOOo % oO0o . OoOoOO00
 oo0O00OOOOO [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 oo0O00OOOOO [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 oo0O00OOOOO [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 oo0O00OOOOO [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 25 - 25: I1ii11iIi11i / I11i + i1IIi . I1IiiI + ooOoO0o
 if 29 - 29: IiII + I1ii11iIi11i
 if 8 - 8: IiII % I1IiiI
 if 10 - 10: OoooooooOO / OoOoOO00
 if 77 - 77: OoOoOO00
 OO00O000OOO = [ ]
 for iIIiI11 in mc . rloc_set :
  iiiI1I = lisp_fill_rloc_in_json ( iIIiI11 )
  if 10 - 10: IiII / i11iIiiIii
  if 19 - 19: OoO0O00
  if 100 - 100: I1ii11iIi11i - I1ii11iIi11i
  if 38 - 38: I1Ii111
  if 23 - 23: Ii1I . I1ii11iIi11i + I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
  if ( iIIiI11 . rloc . is_multicast_address ( ) ) :
   iiiI1I [ "multicast-rloc-set" ] = [ ]
   for O0o00O00oo0oO in list ( iIIiI11 . multicast_rloc_probe_list . values ( ) ) :
    iii1i = lisp_fill_rloc_in_json ( O0o00O00oo0oO )
    iiiI1I [ "multicast-rloc-set" ] . append ( iii1i )
    if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
    if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
    if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
  OO00O000OOO . append ( iiiI1I )
  if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 oo0O00OOOOO [ "rloc-set" ] = OO00O000OOO
 if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
 data . append ( oo0O00OOOOO )
 return ( [ True , data ] )
 if 40 - 40: iII111i - I1IiiI + OoOoOO00
 if 2 - 2: I11i - II111iiii / I1Ii111
 if 27 - 27: OoO0O00 - I1ii11iIi11i * i11iIiiIii + Oo0Ooo
 if 29 - 29: I1ii11iIi11i / IiII . I1Ii111 + Ii1I + OoO0O00
 if 76 - 76: ooOoO0o . I11i * OoO0O00
 if 53 - 53: II111iiii / OoOoOO00 / IiII * oO0o
 if 52 - 52: O0 % iII111i * iIii1I11I1II1 / I11i / I1IiiI * ooOoO0o
 if 93 - 93: iIii1I11I1II1 . II111iiii * OOooOOo - iIii1I11I1II1 . oO0o % Oo0Ooo
def lisp_fill_rloc_in_json ( rloc ) :
 iiiI1I = { }
 O0O0 = None
 if ( rloc . rloc_exists ( ) ) :
  iiiI1I [ "address" ] = rloc . rloc . print_address_no_iid ( )
  O0O0 = iiiI1I [ "address" ]
  if 92 - 92: OoO0O00
  if 42 - 42: I1ii11iIi11i - iIii1I11I1II1 % ooOoO0o
 if ( rloc . translated_port != 0 ) :
  iiiI1I [ "encap-port" ] = str ( rloc . translated_port )
  O0O0 += ":" + iiiI1I [ "encap-port" ]
  if 7 - 7: Oo0Ooo / ooOoO0o + o0oOOo0O0Ooo
  if 38 - 38: o0oOOo0O0Ooo . O0 - OoO0O00 % I11i
 if ( O0O0 and O0O0 in lisp_crypto_keys_by_rloc_encap ) :
  III = lisp_crypto_keys_by_rloc_encap [ O0O0 ] [ 1 ]
  if ( III != None and III . shared_key != None ) :
   iiiI1I [ "encap-crypto" ] = "crypto-" + III . cipher_suite_string
   if 80 - 80: o0oOOo0O0Ooo
   if 100 - 100: iIii1I11I1II1 . OoOoOO00 . OoooooooOO / I1ii11iIi11i - I1IiiI * I11i
   if 5 - 5: i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1IiiI - II111iiii
 iiiI1I [ "state" ] = rloc . print_state ( )
 if ( rloc . geo ) : iiiI1I [ "geo" ] = rloc . geo . print_geo ( )
 if ( rloc . elp ) : iiiI1I [ "elp" ] = rloc . elp . print_elp ( False )
 if ( rloc . rle ) : iiiI1I [ "rle" ] = rloc . rle . print_rle ( False , False )
 if ( rloc . json ) : iiiI1I [ "json" ] = rloc . json . print_json ( False )
 if ( rloc . rloc_name ) : iiiI1I [ "rloc-name" ] = rloc . rloc_name
 IIIii1i = rloc . stats . get_stats ( False , False )
 if ( IIIii1i ) : iiiI1I [ "stats" ] = IIIii1i
 iiiI1I [ "uptime" ] = lisp_print_elapsed ( rloc . uptime )
 iiiI1I [ "upriority" ] = str ( rloc . priority )
 iiiI1I [ "uweight" ] = str ( rloc . weight )
 iiiI1I [ "mpriority" ] = str ( rloc . mpriority )
 iiiI1I [ "mweight" ] = str ( rloc . mweight )
 iIiiI11iIIi11 = rloc . last_rloc_probe_reply
 if ( iIiiI11iIIi11 ) :
  iiiI1I [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( iIiiI11iIIi11 )
  iiiI1I [ "rloc-probe-rtt" ] = str ( rloc . rloc_probe_rtt )
  if 9 - 9: ooOoO0o - oO0o . OoO0O00 . o0oOOo0O0Ooo / Oo0Ooo
 iiiI1I [ "rloc-hop-count" ] = rloc . rloc_probe_hops
 iiiI1I [ "recent-rloc-hop-counts" ] = rloc . recent_rloc_probe_hops
 if 78 - 78: OoOoOO00 - II111iiii - o0oOOo0O0Ooo * iII111i . o0oOOo0O0Ooo
 iiiI1I [ "rloc-probe-latency" ] = rloc . rloc_probe_latency
 iiiI1I [ "recent-rloc-probe-latencies" ] = rloc . recent_rloc_probe_latencies
 if 9 - 9: iIii1I11I1II1 . iII111i % OoOoOO00 + o0oOOo0O0Ooo
 OOoo0o000 = [ ]
 for OOOooOOoOO0o in rloc . recent_rloc_probe_rtts : OOoo0o000 . append ( str ( OOOooOOoOO0o ) )
 iiiI1I [ "recent-rloc-probe-rtts" ] = OOoo0o000
 return ( iiiI1I )
 if 63 - 63: o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i
 if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
 if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
 if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
def lisp_process_api_map_cache_entry ( parms ) :
 oooo = parms [ "instance-id" ]
 oooo = 0 if ( oooo == "" ) else int ( oooo )
 if 47 - 47: OOooOOo + IiII
 if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
 if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
 if 64 - 64: Ii1I
 o0Ooo0Oooo0o = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
 o0Ooo0Oooo0o . store_prefix ( parms [ "eid-prefix" ] )
 IIi11ii = o0Ooo0Oooo0o
 O0oo0OoO0oo = o0Ooo0Oooo0o
 if 4 - 4: OoOoOO00
 if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
 if 48 - 48: iII111i / II111iiii * I1Ii111 + I11i / ooOoO0o . OoOoOO00
 if 45 - 45: OOooOOo / Ii1I % O0
 if 7 - 7: oO0o * i11iIiiIii + OoooooooOO + I11i
 oo0oOooo0O = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
 if ( "group-prefix" in parms ) :
  oo0oOooo0O . store_prefix ( parms [ "group-prefix" ] )
  IIi11ii = oo0oOooo0O
  if 9 - 9: II111iiii * Oo0Ooo * I1Ii111 . IiII
  if 80 - 80: i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - OOooOOo * OoooooooOO
 iiooo0o0oO = [ ]
 I11iiI1III = lisp_map_cache_lookup ( O0oo0OoO0oo , IIi11ii )
 if ( I11iiI1III ) : o0o0O0O0Oooo0 , iiooo0o0oO = lisp_process_api_map_cache ( I11iiI1III , iiooo0o0oO )
 return ( iiooo0o0oO )
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
 if 85 - 85: O0 * OOooOOo % I1Ii111
def lisp_process_api_site_cache_summary ( site_cache ) :
 I1io0oOOooOoo0oO = { "site" : "" , "registrations" : [ ] }
 oo0O00OOOOO = { "eid-prefix" : "" , "count" : 0 , "registered-count" : 0 }
 if 33 - 33: O0
 IiiIIIiIIIii1II = { }
 for iiii11I1 in site_cache . cache_sorted :
  for ooOO00o in list ( site_cache . cache [ iiii11I1 ] . entries . values ( ) ) :
   if ( ooOO00o . accept_more_specifics == False ) : continue
   if ( ooOO00o . site . site_name not in IiiIIIiIIIii1II ) :
    IiiIIIiIIIii1II [ ooOO00o . site . site_name ] = [ ]
    if 33 - 33: OoO0O00
   oO0ooOOO = copy . deepcopy ( oo0O00OOOOO )
   oO0ooOOO [ "eid-prefix" ] = ooOO00o . eid . print_prefix ( )
   oO0ooOOO [ "count" ] = len ( ooOO00o . more_specific_registrations )
   for i111ii1ii in ooOO00o . more_specific_registrations :
    if ( i111ii1ii . registered ) : oO0ooOOO [ "registered-count" ] += 1
    if 37 - 37: OoooooooOO - Oo0Ooo % oO0o
   IiiIIIiIIIii1II [ ooOO00o . site . site_name ] . append ( oO0ooOOO )
   if 59 - 59: II111iiii - o0oOOo0O0Ooo / I1ii11iIi11i . oO0o / o0oOOo0O0Ooo - iII111i
   if 65 - 65: I1ii11iIi11i * OOooOOo * ooOoO0o + oO0o - OOooOOo
   if 100 - 100: iII111i
 iiooo0o0oO = [ ]
 for IIiii in IiiIIIiIIIii1II :
  I111 = copy . deepcopy ( I1io0oOOooOoo0oO )
  I111 [ "site" ] = IIiii
  I111 [ "registrations" ] = IiiIIIiIIIii1II [ IIiii ]
  iiooo0o0oO . append ( I111 )
  if 12 - 12: OoooooooOO - I1ii11iIi11i * iII111i / ooOoO0o
 return ( iiooo0o0oO )
 if 99 - 99: I1ii11iIi11i + I11i
 if 29 - 29: I1ii11iIi11i / oO0o
 if 2 - 2: Oo0Ooo / IiII - OoooooooOO
 if 65 - 65: OoO0O00 - Ii1I
 if 98 - 98: OoOoOO00 * I1Ii111 * iIii1I11I1II1 * OoOoOO00
 if 15 - 15: Oo0Ooo
 if 100 - 100: IiII + I1ii11iIi11i + iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
def lisp_process_api_site_cache ( se , data ) :
 if 84 - 84: o0oOOo0O0Ooo * I11i
 if 22 - 22: i1IIi + OOooOOo % OoooooooOO
 if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
 if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 66 - 66: OoooooooOO
 if 90 - 90: IiII - OoOoOO00
 if 98 - 98: Oo0Ooo / oO0o . Ii1I
 if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
 if 37 - 37: iII111i - Ii1I . oO0o
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 47 - 47: IiII / I1ii11iIi11i . o0oOOo0O0Ooo . ooOoO0o + OOooOOo . OOooOOo
 if 25 - 25: oO0o
 if 43 - 43: Ii1I - o0oOOo0O0Ooo % oO0o - O0
 if 20 - 20: OoO0O00 . ooOoO0o / OoOoOO00 - OoOoOO00 . iII111i / OOooOOo
 if 39 - 39: iIii1I11I1II1 % ooOoO0o
 if 75 - 75: i1IIi * II111iiii * O0 * i11iIiiIii % iII111i / iII111i
 if 36 - 36: IiII / I1IiiI % iII111i / iII111i
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 I1IIIi = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 iiiiII = data [ "dns-name" ] if ( "dns-name" in data ) else None
 if ( "address" in data ) :
  I1IIIi . store_address ( data [ "address" ] )
  if 38 - 38: OOooOOo * I1ii11iIi11i * I1Ii111 + I11i
  if 65 - 65: O0 + O0 * I1Ii111
 oOO0 = { }
 if ( ms_or_mr ) :
  for oO00000oOO in list ( lisp_map_servers_list . values ( ) ) :
   if ( iiiiII ) :
    if ( iiiiII != oO00000oOO . dns_name ) : continue
   else :
    if ( I1IIIi . is_exact_match ( oO00000oOO . map_server ) == False ) : continue
    if 66 - 66: OOooOOo / O0 + i1IIi . O0 % I1ii11iIi11i - OoooooooOO
    if 16 - 16: I11i % iII111i
   oOO0 [ "dns-name" ] = oO00000oOO . dns_name
   oOO0 [ "address" ] = oO00000oOO . map_server . print_address_no_iid ( )
   oOO0 [ "ms-name" ] = "" if oO00000oOO . ms_name == None else oO00000oOO . ms_name
   return ( [ oOO0 ] )
   if 29 - 29: I1IiiI - ooOoO0o * OoO0O00 . i11iIiiIii % OoOoOO00 * o0oOOo0O0Ooo
 else :
  for iii1i in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( iiiiII ) :
    if ( iiiiII != iii1i . dns_name ) : continue
   else :
    if ( I1IIIi . is_exact_match ( iii1i . map_resolver ) == False ) : continue
    if 43 - 43: OoO0O00 * OOooOOo / I1Ii111 % OoOoOO00 . oO0o / OOooOOo
    if 62 - 62: O0 * I1ii11iIi11i - O0 / I11i % ooOoO0o
   oOO0 [ "dns-name" ] = iii1i . dns_name
   oOO0 [ "address" ] = iii1i . map_resolver . print_address_no_iid ( )
   oOO0 [ "mr-name" ] = "" if iii1i . mr_name == None else iii1i . mr_name
   return ( [ oOO0 ] )
   if 1 - 1: O0 / iIii1I11I1II1
   if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
 return ( [ ] )
 if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
 if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
 if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
 if 16 - 16: o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii . I1ii11iIi11i
 if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
 if 83 - 83: OoooooooOO % I1ii11iIi11i . IiII + OOooOOo . iII111i - ooOoO0o
 if 100 - 100: o0oOOo0O0Ooo
def lisp_process_api_database_mapping ( ) :
 iiooo0o0oO = [ ]
 if 95 - 95: iII111i * oO0o * i1IIi
 for OoO0oO in lisp_db_list :
  oo0O00OOOOO = { }
  oo0O00OOOOO [ "eid-prefix" ] = OoO0oO . eid . print_prefix ( )
  if ( OoO0oO . group . is_null ( ) == False ) :
   oo0O00OOOOO [ "group-prefix" ] = OoO0oO . group . print_prefix ( )
   if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
   if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
  OOOO00 = [ ]
  for iiiI1I in OoO0oO . rloc_set :
   iIIiI11 = { }
   if ( iiiI1I . rloc . is_null ( ) == False ) :
    iIIiI11 [ "rloc" ] = iiiI1I . rloc . print_address_no_iid ( )
    if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
   if ( iiiI1I . rloc_name != None ) : iIIiI11 [ "rloc-name" ] = iiiI1I . rloc_name
   if ( iiiI1I . interface != None ) : iIIiI11 [ "interface" ] = iiiI1I . interface
   oo00oOO = iiiI1I . translated_rloc
   if ( oo00oOO . is_null ( ) == False ) :
    iIIiI11 [ "translated-rloc" ] = oo00oOO . print_address_no_iid ( )
    if 18 - 18: iII111i * OoO0O00 % i11iIiiIii
   if ( iIIiI11 != { } ) : OOOO00 . append ( iIIiI11 )
   if 76 - 76: OoO0O00
   if 92 - 92: iIii1I11I1II1 * O0 % I11i
   if 92 - 92: OoOoOO00 + oO0o
   if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
   if 28 - 28: I1IiiI . iIii1I11I1II1
  oo0O00OOOOO [ "rlocs" ] = OOOO00
  if 12 - 12: I1Ii111 * OOooOOo
  if 11 - 11: II111iiii % O0 % O0 % o0oOOo0O0Ooo
  if 45 - 45: OoooooooOO * oO0o
  if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
  iiooo0o0oO . append ( oo0O00OOOOO )
  if 16 - 16: Oo0Ooo
 return ( iiooo0o0oO )
 if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
 if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 if 67 - 67: I1IiiI
 if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
 if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
 if 33 - 33: OOooOOo - OoooooooOO . iII111i
 if 2 - 2: I11i + i1IIi
def lisp_gather_site_cache_data ( se , data ) :
 oo0O00OOOOO = { }
 oo0O00OOOOO [ "site-name" ] = se . site . site_name
 oo0O00OOOOO [ "instance-id" ] = str ( se . eid . instance_id )
 oo0O00OOOOO [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  oo0O00OOOOO [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 52 - 52: I11i - OoO0O00 % I1Ii111 . OOooOOo
 oo0O00OOOOO [ "registered" ] = "yes" if se . registered else "no"
 oo0O00OOOOO [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 oo0O00OOOOO [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 90 - 90: O0 - Oo0Ooo / i1IIi * iIii1I11I1II1 % o0oOOo0O0Ooo / oO0o
 IiI = se . last_registerer
 IiI = "none" if IiI . is_null ( ) else IiI . print_address ( )
 oo0O00OOOOO [ "last-registerer" ] = IiI
 oo0O00OOOOO [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 oo0O00OOOOO [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 oo0O00OOOOO [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  oo0O00OOOOO [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 73 - 73: iII111i % iIii1I11I1II1 + o0oOOo0O0Ooo % Ii1I . II111iiii + IiII
  if 55 - 55: OoOoOO00 * II111iiii / iII111i + OOooOOo / OoooooooOO
  if 12 - 12: II111iiii * O0 - Oo0Ooo + o0oOOo0O0Ooo . Oo0Ooo + iIii1I11I1II1
  if 4 - 4: I1Ii111 - I1Ii111 / I1ii11iIi11i . i1IIi + I1ii11iIi11i / oO0o
  if 18 - 18: iIii1I11I1II1 . ooOoO0o
 OO00O000OOO = [ ]
 for iIIiI11 in se . registered_rlocs :
  iiiI1I = { }
  iiiI1I [ "address" ] = iIIiI11 . rloc . print_address_no_iid ( ) if iIIiI11 . rloc_exists ( ) else "none"
  if 68 - 68: o0oOOo0O0Ooo
  if 36 - 36: Oo0Ooo . I11i + I1IiiI * i1IIi % Ii1I + OOooOOo
  if ( iIIiI11 . geo ) : iiiI1I [ "geo" ] = iIIiI11 . geo . print_geo ( )
  if ( iIIiI11 . elp ) : iiiI1I [ "elp" ] = iIIiI11 . elp . print_elp ( False )
  if ( iIIiI11 . rle ) : iiiI1I [ "rle" ] = iIIiI11 . rle . print_rle ( False , True )
  if ( iIIiI11 . json ) : iiiI1I [ "json" ] = iIIiI11 . json . print_json ( False )
  if ( iIIiI11 . rloc_name ) : iiiI1I [ "rloc-name" ] = iIIiI11 . rloc_name
  iiiI1I [ "uptime" ] = lisp_print_elapsed ( iIIiI11 . uptime )
  iiiI1I [ "upriority" ] = str ( iIIiI11 . priority )
  iiiI1I [ "uweight" ] = str ( iIIiI11 . weight )
  iiiI1I [ "mpriority" ] = str ( iIIiI11 . mpriority )
  iiiI1I [ "mweight" ] = str ( iIIiI11 . mweight )
  if 5 - 5: o0oOOo0O0Ooo % oO0o / OoO0O00
  OO00O000OOO . append ( iiiI1I )
  if 17 - 17: OoooooooOO - I1ii11iIi11i / OoO0O00 - I1Ii111 + i1IIi
 oo0O00OOOOO [ "registered-rlocs" ] = OO00O000OOO
 if 6 - 6: Oo0Ooo - II111iiii
 data . append ( oo0O00OOOOO )
 return ( [ True , data ] )
 if 33 - 33: I1Ii111 - I1IiiI + iII111i . OoOoOO00
 if 91 - 91: OOooOOo / Ii1I / IiII * OOooOOo
 if 68 - 68: I11i
 if 91 - 91: I11i
 if 24 - 24: ooOoO0o . i1IIi - O0 + I11i
 if 71 - 71: OoOoOO00
 if 29 - 29: O0 . i11iIiiIii
def lisp_process_api_site_cache_entry ( parms ) :
 oooo = parms [ "instance-id" ]
 oooo = 0 if ( oooo == "" ) else int ( oooo )
 if 51 - 51: IiII
 if 53 - 53: O0
 if 19 - 19: o0oOOo0O0Ooo / iII111i % OoOoOO00
 if 65 - 65: o0oOOo0O0Ooo
 o0Ooo0Oooo0o = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
 o0Ooo0Oooo0o . store_prefix ( parms [ "eid-prefix" ] )
 if 89 - 89: iIii1I11I1II1 + OoooooooOO + i1IIi + OoooooooOO % IiII * OoO0O00
 if 53 - 53: OOooOOo . IiII % I11i - OoO0O00 - Oo0Ooo
 if 58 - 58: I1Ii111 / OoooooooOO . I11i % I1Ii111
 if 8 - 8: Oo0Ooo % ooOoO0o / i11iIiiIii
 if 54 - 54: IiII
 oo0oOooo0O = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
 if ( "group-prefix" in parms ) :
  oo0oOooo0O . store_prefix ( parms [ "group-prefix" ] )
  if 85 - 85: OOooOOo - i1IIi
  if 10 - 10: I1ii11iIi11i
 iiooo0o0oO = [ ]
 ooOO00o = lisp_site_eid_lookup ( o0Ooo0Oooo0o , oo0oOooo0O , False )
 if ( ooOO00o ) : lisp_gather_site_cache_data ( ooOO00o , iiooo0o0oO )
 return ( iiooo0o0oO )
 if 3 - 3: ooOoO0o * O0 / o0oOOo0O0Ooo
 if 22 - 22: OoOoOO00 + OOooOOo . iII111i % iIii1I11I1II1 - I11i
 if 23 - 23: OoOoOO00 * I1Ii111
 if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
 if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
 if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
 if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
def lisp_get_interface_instance_id ( device , source_eid ) :
 i111IIiIiiI1 = None
 if ( device in lisp_myinterfaces ) :
  i111IIiIiiI1 = lisp_myinterfaces [ device ]
  if 25 - 25: OoO0O00 * oO0o
  if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
  if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
  if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
  if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
  if 73 - 73: Oo0Ooo + II111iiii - IiII
 if ( i111IIiIiiI1 == None or i111IIiIiiI1 . instance_id == None ) :
  return ( lisp_default_iid )
  if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
  if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
  if 66 - 66: II111iiii * I1IiiI . Oo0Ooo * OoooooooOO % OoOoOO00 . II111iiii
  if 4 - 4: iII111i + I1Ii111 % OoOoOO00 / Ii1I
  if 94 - 94: OoO0O00
  if 35 - 35: I1ii11iIi11i % OoO0O00 + II111iiii % II111iiii / IiII - iII111i
  if 9 - 9: I1ii11iIi11i * o0oOOo0O0Ooo . oO0o
  if 48 - 48: IiII . I1Ii111 + OoooooooOO - I1Ii111 . Ii1I . I1Ii111
  if 24 - 24: ooOoO0o * iIii1I11I1II1
 oooo = i111IIiIiiI1 . get_instance_id ( )
 if ( source_eid == None ) : return ( oooo )
 if 1 - 1: I1ii11iIi11i . O0
 IiI11I1IIIiIi = source_eid . instance_id
 O0O0OO0o0 = None
 for i111IIiIiiI1 in lisp_multi_tenant_interfaces :
  if ( i111IIiIiiI1 . device != device ) : continue
  Oo0OoOI1I11iII1I1i = i111IIiIiiI1 . multi_tenant_eid
  source_eid . instance_id = Oo0OoOI1I11iII1I1i . instance_id
  if ( source_eid . is_more_specific ( Oo0OoOI1I11iII1I1i ) == False ) : continue
  if ( O0O0OO0o0 == None or O0O0OO0o0 . multi_tenant_eid . mask_len < Oo0OoOI1I11iII1I1i . mask_len ) :
   O0O0OO0o0 = i111IIiIiiI1
   if 57 - 57: I1Ii111 / i11iIiiIii * OoooooooOO % OoooooooOO % i11iIiiIii . Oo0Ooo
   if 14 - 14: I1IiiI + o0oOOo0O0Ooo
 source_eid . instance_id = IiI11I1IIIiIi
 if 5 - 5: I1ii11iIi11i % I11i - II111iiii
 if ( O0O0OO0o0 == None ) : return ( oooo )
 return ( O0O0OO0o0 . get_instance_id ( ) )
 if 70 - 70: ooOoO0o - IiII - OoO0O00 / I11i
 if 59 - 59: IiII % ooOoO0o . iII111i / Ii1I * Ii1I
 if 73 - 73: I1ii11iIi11i . oO0o % I11i . I1ii11iIi11i / I1Ii111 / II111iiii
 if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
 if 76 - 76: I1Ii111
 if 91 - 91: iIii1I11I1II1 / Ii1I . I1IiiI
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 if 85 - 85: II111iiii + I1ii11iIi11i
 if 33 - 33: iII111i
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( device not in lisp_myinterfaces ) : return ( None )
 if 14 - 14: O0 * Oo0Ooo / i1IIi
 i111IIiIiiI1 = lisp_myinterfaces [ device ]
 Oo0o00OOo0 = device if i111IIiIiiI1 . dynamic_eid_device == None else i111IIiIiiI1 . dynamic_eid_device
 if 26 - 26: OOooOOo / OoooooooOO . i1IIi % o0oOOo0O0Ooo - I1Ii111
 if 65 - 65: i1IIi % o0oOOo0O0Ooo - Oo0Ooo + OOooOOo - oO0o
 if ( i111IIiIiiI1 . does_dynamic_eid_match ( eid ) ) : return ( Oo0o00OOo0 )
 return ( None )
 if 30 - 30: iII111i
 if 91 - 91: OoooooooOO . OoO0O00 % ooOoO0o + I1ii11iIi11i % iIii1I11I1II1
 if 48 - 48: I1IiiI . OoooooooOO . i11iIiiIii / i1IIi % ooOoO0o * O0
 if 1 - 1: I1ii11iIi11i
 if 85 - 85: I1ii11iIi11i
 if 6 - 6: IiII % ooOoO0o . IiII . I1Ii111 - iIii1I11I1II1 + iIii1I11I1II1
 if 30 - 30: OoooooooOO - ooOoO0o + Ii1I
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 88 - 88: II111iiii / Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo * OoOoOO00 . I1ii11iIi11i
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 32 - 32: OoooooooOO * I11i
 o00ooOOOo = lisp_process_rloc_probe_timer
 oo0O00O0O0O00Ooo = threading . Timer ( interval , o00ooOOOo , [ lisp_sockets ] )
 lisp_rloc_probe_timer = oo0O00O0O0O00Ooo
 oo0O00O0O0O00Ooo . start ( )
 return
 if 80 - 80: iII111i / I1Ii111 * Oo0Ooo
 if 6 - 6: o0oOOo0O0Ooo - IiII . iII111i
 if 3 - 3: II111iiii
 if 79 - 79: i11iIiiIii
 if 7 - 7: I11i - OoOoOO00 % I11i . i11iIiiIii
 if 28 - 28: oO0o * i11iIiiIii * i11iIiiIii % OoooooooOO / I1IiiI / II111iiii
 if 36 - 36: ooOoO0o % i1IIi . ooOoO0o % oO0o % O0 . II111iiii
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for III in lisp_rloc_probe_list :
  oOoO00OoO0 = lisp_rloc_probe_list [ III ]
  lprint ( "RLOC {}:" . format ( III ) )
  for iiiI1I , oO0ooOOO , Oo in oOoO00OoO0 :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( iiiI1I ) ) , oO0ooOOO . print_prefix ( ) ,
 Oo . print_prefix ( ) , iiiI1I . translated_port ) )
   if 83 - 83: I11i
   if 39 - 39: o0oOOo0O0Ooo * iIii1I11I1II1
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 13 - 13: iII111i + Oo0Ooo / oO0o / OOooOOo
 if 58 - 58: oO0o * I1ii11iIi11i % I1ii11iIi11i
 if 16 - 16: I11i / I1IiiI % I1IiiI
 if 78 - 78: O0 % i11iIiiIii / IiII
 if 87 - 87: IiII % iIii1I11I1II1 * I1ii11iIi11i
 if 43 - 43: Ii1I - IiII / i11iIiiIii + OoOoOO00 + I1ii11iIi11i - o0oOOo0O0Ooo
 if 39 - 39: OoOoOO00 - i1IIi / oO0o % I11i * o0oOOo0O0Ooo * I1IiiI
 if 79 - 79: Ii1I
 if 56 - 56: I1ii11iIi11i
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 40 - 40: OoooooooOO
 if 100 - 100: IiII - I11i
 if 79 - 79: iII111i % O0
 if 73 - 73: Oo0Ooo
 iIIiI11 , oO0ooOOO , Oo = eid_list [ 0 ]
 iI1ii11I = [ lisp_print_eid_tuple ( oO0ooOOO , Oo ) ]
 if 19 - 19: O0 + OoO0O00 - i1IIi % OoOoOO00 / Oo0Ooo + OoooooooOO
 for iIIiI11 , oO0ooOOO , Oo in eid_list [ 1 : : ] :
  iIIiI11 . state = LISP_RLOC_UNREACH_STATE
  iIIiI11 . last_state_change = lisp_get_timestamp ( )
  iI1ii11I . append ( lisp_print_eid_tuple ( oO0ooOOO , Oo ) )
  if 93 - 93: i11iIiiIii % OOooOOo . I11i * ooOoO0o
  if 90 - 90: OoO0O00
 O00OOO0 = bold ( "unreachable" , False )
 IIIOo0O = red ( iIIiI11 . rloc . print_address_no_iid ( ) , False )
 if 12 - 12: ooOoO0o % i11iIiiIii * I1IiiI - IiII . o0oOOo0O0Ooo % i11iIiiIii
 for o0Ooo0Oooo0o in iI1ii11I :
  oO0ooOOO = green ( o0Ooo0Oooo0o , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( IIIOo0O , O00OOO0 , oO0ooOOO ) )
  if 84 - 84: OOooOOo
  if 35 - 35: I1IiiI . ooOoO0o - O0
  if 63 - 63: Ii1I
  if 9 - 9: iIii1I11I1II1 / OOooOOo * O0 . Oo0Ooo + OoO0O00
  if 95 - 95: I11i . o0oOOo0O0Ooo + O0
  if 36 - 36: I1IiiI * ooOoO0o
 for iIIiI11 , oO0ooOOO , Oo in eid_list :
  I11iiI1III = lisp_map_cache . lookup_cache ( oO0ooOOO , True )
  if ( I11iiI1III ) : lisp_write_ipc_map_cache ( True , I11iiI1III )
  if 74 - 74: I1IiiI - ooOoO0o / I1ii11iIi11i
 return
 if 82 - 82: II111iiii % OoOoOO00
 if 32 - 32: i11iIiiIii
 if 38 - 38: IiII + I1Ii111 % Ii1I / Ii1I
 if 39 - 39: iII111i * i11iIiiIii
 if 31 - 31: IiII - Ii1I . i1IIi
 if 1 - 1: o0oOOo0O0Ooo + OOooOOo % Ii1I - O0 / I1ii11iIi11i
 if 20 - 20: o0oOOo0O0Ooo + II111iiii * Ii1I . OoooooooOO
 if 88 - 88: O0 + iIii1I11I1II1 . o0oOOo0O0Ooo . iIii1I11I1II1 - Ii1I
 if 74 - 74: Ii1I . IiII
 if 67 - 67: oO0o
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 12 - 12: I1IiiI + OoooooooOO
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
 if 19 - 19: OoooooooOO / IiII
 if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
 if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
 if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
 if 51 - 51: OoO0O00 - OoO0O00 * IiII
 if 24 - 24: OoooooooOO . II111iiii
 ooi1I = lisp_get_default_route_next_hops ( )
 if 74 - 74: II111iiii * O0
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 57 - 57: OoO0O00
 if 12 - 12: o0oOOo0O0Ooo . I1Ii111 . oO0o % Oo0Ooo * OoooooooOO
 if 25 - 25: OoO0O00
 if 54 - 54: O0
 if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
 O0oo0oOo = 0
 Oooooo0OOO = bold ( "RLOC-probe" , False )
 for Iii1iIi1i in list ( lisp_rloc_probe_list . values ( ) ) :
  if 60 - 60: OOooOOo * iII111i . ooOoO0o + O0 + o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 62 - 62: O0 * OoO0O00 / Oo0Ooo - oO0o * OoO0O00 * oO0o
  if 31 - 31: Oo0Ooo
  if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
  if 67 - 67: I1Ii111 . I1ii11iIi11i
  ii11ii1 = None
  for oO00O , o0Ooo0Oooo0o , oo0oOooo0O in Iii1iIi1i :
   O0O0 = oO00O . rloc . print_address_no_iid ( )
   if 46 - 46: i11iIiiIii - Ii1I / OoooooooOO - OoO0O00
   if 36 - 36: Ii1I * ooOoO0o * OoooooooOO + OoOoOO00
   if 43 - 43: I1Ii111 - Oo0Ooo % i1IIi . II111iiii
   if 80 - 80: IiII . iII111i + I1Ii111 + iII111i % Oo0Ooo
   Ooo00O , ooiiIIiii , ii1I1I1iII = lisp_allow_gleaning ( o0Ooo0Oooo0o , None , oO00O )
   if ( Ooo00O and ooiiIIiii == False ) :
    oO0ooOOO = green ( o0Ooo0Oooo0o . print_address ( ) , False )
    O0O0 += ":{}" . format ( oO00O . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( O0O0 , False ) , oO0ooOOO ) )
    if 58 - 58: OOooOOo - o0oOOo0O0Ooo * iII111i % o0oOOo0O0Ooo % O0 / II111iiii
    continue
    if 39 - 39: ooOoO0o + I11i
    if 24 - 24: o0oOOo0O0Ooo
    if 5 - 5: i11iIiiIii - oO0o + o0oOOo0O0Ooo % ooOoO0o
    if 63 - 63: oO0o
    if 7 - 7: IiII / i11iIiiIii - OOooOOo
    if 9 - 9: II111iiii + i11iIiiIii % I1Ii111 - Oo0Ooo * OOooOOo
    if 55 - 55: I1Ii111 + ooOoO0o
   if ( oO00O . down_state ( ) ) : continue
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
   if 49 - 49: II111iiii
   if ( ii11ii1 ) :
    oO00O . last_rloc_probe_nonce = ii11ii1 . last_rloc_probe_nonce
    if 99 - 99: Oo0Ooo . OOooOOo
    if ( ii11ii1 . translated_port == oO00O . translated_port and ii11ii1 . rloc_name == oO00O . rloc_name ) :
     if 85 - 85: OoOoOO00 . IiII + oO0o - II111iiii
     oO0ooOOO = green ( lisp_print_eid_tuple ( o0Ooo0Oooo0o , oo0oOooo0O ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( O0O0 , False ) , oO0ooOOO ) )
     if 70 - 70: O0 % I1Ii111
     if 13 - 13: I1ii11iIi11i % OoO0O00 / Ii1I * IiII
     if 82 - 82: ooOoO0o % Oo0Ooo
     if 26 - 26: OoO0O00 + i11iIiiIii % I11i . I1ii11iIi11i
     if 76 - 76: i1IIi + ooOoO0o - Oo0Ooo + OoOoOO00 / I1ii11iIi11i . OOooOOo
     if 50 - 50: IiII - Ii1I % iIii1I11I1II1
     oO00O . last_rloc_probe = ii11ii1 . last_rloc_probe
     continue
     if 60 - 60: o0oOOo0O0Ooo - Oo0Ooo
     if 92 - 92: OoOoOO00 + IiII . OoO0O00 % iII111i / II111iiii / I11i
     if 62 - 62: I1ii11iIi11i
   OoII1 = None
   iIIiI11 = None
   while ( True ) :
    iIIiI11 = oO00O if iIIiI11 == None else iIIiI11 . next_rloc
    if ( iIIiI11 == None ) : break
    if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
    if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
    if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
    if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
    if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
    if ( iIIiI11 . rloc_next_hop != None ) :
     if ( iIIiI11 . rloc_next_hop not in ooi1I ) :
      if ( iIIiI11 . up_state ( ) ) :
       IiI11I111 , iii1111ii = iIIiI11 . rloc_next_hop
       iIIiI11 . state = LISP_RLOC_UNREACH_STATE
       iIIiI11 . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( iIIiI11 . rloc , False )
       if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
      O00OOO0 = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( iii1111ii , IiI11I111 ,
 red ( O0O0 , False ) , O00OOO0 ) )
      continue
      if 71 - 71: i1IIi
      if 79 - 79: iII111i * O0 / Ii1I / O0 % i1IIi
      if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
      if 62 - 62: Ii1I . I1ii11iIi11i . iII111i + I11i * o0oOOo0O0Ooo
      if 56 - 56: oO0o * iIii1I11I1II1 . II111iiii - II111iiii + II111iiii - i11iIiiIii
      if 79 - 79: iII111i
    i11iII11I1III = iIIiI11 . last_rloc_probe
    I1i1IIIi1iii = 0 if i11iII11I1III == None else time . time ( ) - i11iII11I1III
    if ( iIIiI11 . unreach_state ( ) and I1i1IIIi1iii < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( O0O0 , False ) ) )
     if 43 - 43: OoOoOO00
     continue
     if 99 - 99: OoO0O00 - O0 * OoO0O00 + OoO0O00
     if 62 - 62: IiII - I1Ii111
     if 68 - 68: Oo0Ooo + oO0o - OoO0O00
     if 17 - 17: I11i % I1ii11iIi11i - I1IiiI % oO0o + I1ii11iIi11i
     if 68 - 68: i1IIi . ooOoO0o . Oo0Ooo + iII111i . I1IiiI * i1IIi
     if 88 - 88: iII111i + i11iIiiIii
    I111Ii1I1I1iI = lisp_get_echo_nonce ( None , O0O0 )
    if ( I111Ii1I1I1iI and I111Ii1I1I1iI . request_nonce_timeout ( ) ) :
     iIIiI11 . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     iIIiI11 . last_state_change = lisp_get_timestamp ( )
     O00OOO0 = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( O0O0 , False ) , O00OOO0 ) )
     if 42 - 42: I1Ii111 * O0 / OoO0O00 + iII111i
     lisp_update_rtr_updown ( iIIiI11 . rloc , False )
     continue
     if 86 - 86: OOooOOo
     if 6 - 6: oO0o % iII111i * Oo0Ooo - i11iIiiIii . OoooooooOO
     if 85 - 85: O0 * i1IIi
     if 29 - 29: i11iIiiIii
     if 34 - 34: OoOoOO00
     if 17 - 17: oO0o * OoOoOO00 % OoO0O00 % I1IiiI * I11i
    if ( I111Ii1I1I1iI and I111Ii1I1I1iI . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( O0O0 , False ) ) )
     if 78 - 78: OoooooooOO . I1Ii111 + Ii1I - II111iiii - IiII / iIii1I11I1II1
     continue
     if 92 - 92: Ii1I
     if 34 - 34: OOooOOo * OoooooooOO / I1ii11iIi11i
     if 41 - 41: i1IIi
     if 75 - 75: o0oOOo0O0Ooo . I1Ii111 - I1Ii111 % Ii1I * OoooooooOO
     if 99 - 99: OOooOOo + o0oOOo0O0Ooo - OOooOOo . i1IIi
     if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
    if ( iIIiI11 . last_rloc_probe != None ) :
     i11iII11I1III = iIIiI11 . last_rloc_probe_reply
     if ( i11iII11I1III == None ) : i11iII11I1III = 0
     I1i1IIIi1iii = time . time ( ) - i11iII11I1III
     if ( iIIiI11 . up_state ( ) and I1i1IIIi1iii >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 100 - 100: OoO0O00 . Oo0Ooo
      iIIiI11 . state = LISP_RLOC_UNREACH_STATE
      iIIiI11 . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( iIIiI11 . rloc , False )
      O00OOO0 = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( O0O0 , False ) , O00OOO0 ) )
      if 29 - 29: OoO0O00
      if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
      lisp_mark_rlocs_for_other_eids ( Iii1iIi1i )
      if 63 - 63: O0 % iIii1I11I1II1 . o0oOOo0O0Ooo . I1IiiI * Ii1I % i1IIi
      if 47 - 47: II111iiii * I1ii11iIi11i
      if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
    iIIiI11 . last_rloc_probe = lisp_get_timestamp ( )
    if 71 - 71: I1ii11iIi11i * i1IIi
    OOoOo0o0oO = "" if iIIiI11 . unreach_state ( ) == False else " unreachable"
    if 57 - 57: O0 * Ii1I / I1IiiI
    if 54 - 54: iIii1I11I1II1 + iII111i % OoOoOO00 % OOooOOo
    if 67 - 67: iII111i . II111iiii - I1IiiI / iII111i . Ii1I
    if 42 - 42: I1IiiI % I1Ii111 % iII111i + iII111i
    if 71 - 71: Oo0Ooo / OoOoOO00 - I1ii11iIi11i
    if 32 - 32: iII111i
    if 99 - 99: o0oOOo0O0Ooo . oO0o
    iIiI1iIiII1 = ""
    iii1111ii = None
    if ( iIIiI11 . rloc_next_hop != None ) :
     IiI11I111 , iii1111ii = iIIiI11 . rloc_next_hop
     lisp_install_host_route ( O0O0 , iii1111ii , True )
     iIiI1iIiII1 = ", send on nh {}({})" . format ( iii1111ii , IiI11I111 )
     if 56 - 56: I11i % OoOoOO00 - OoO0O00
     if 31 - 31: iII111i % i11iIiiIii - Ii1I / OOooOOo - I1Ii111
     if 60 - 60: o0oOOo0O0Ooo + Oo0Ooo . O0
     if 51 - 51: i11iIiiIii / iIii1I11I1II1 . I1IiiI - Ii1I * I1Ii111 . iII111i
     if 72 - 72: Ii1I . I11i / i1IIi % i1IIi + I1ii11iIi11i
    OOOooOOoOO0o = iIIiI11 . print_rloc_probe_rtt ( )
    OOOO0oO00 = O0O0
    if ( iIIiI11 . translated_port != 0 ) :
     OOOO0oO00 += ":{}" . format ( iIIiI11 . translated_port )
     if 91 - 91: OoooooooOO % O0 * OoooooooOO . OOooOOo * I1Ii111 + OoO0O00
    OOOO0oO00 = red ( OOOO0oO00 , False )
    if ( iIIiI11 . rloc_name != None ) :
     OOOO0oO00 += " (" + blue ( iIIiI11 . rloc_name , False ) + ")"
     if 6 - 6: IiII + I11i / Ii1I / Oo0Ooo - oO0o
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( Oooooo0OOO , OOoOo0o0oO ,
 OOOO0oO00 , OOOooOOoOO0o , iIiI1iIiII1 ) )
    if 31 - 31: i11iIiiIii % oO0o + ooOoO0o - i1IIi
    if 87 - 87: IiII + oO0o
    if 87 - 87: ooOoO0o
    if 47 - 47: i11iIiiIii
    if 84 - 84: Ii1I + ooOoO0o
    if 81 - 81: I1ii11iIi11i - iIii1I11I1II1
    if 31 - 31: I11i * oO0o % I1ii11iIi11i * I1Ii111 % OoOoOO00 + oO0o
    if 33 - 33: I1Ii111
    if ( iIIiI11 . rloc_next_hop != None ) :
     OoII1 = lisp_get_host_route_next_hop ( O0O0 )
     if ( OoII1 ) : lisp_install_host_route ( O0O0 , OoII1 , False )
     if 96 - 96: i1IIi
     if 52 - 52: OoO0O00 * Ii1I + OOooOOo + ooOoO0o * OoooooooOO
     if 34 - 34: I1Ii111 . I1Ii111 * ooOoO0o % OoOoOO00
     if 71 - 71: I1Ii111 - I1Ii111
     if 13 - 13: iII111i + I1ii11iIi11i - oO0o / IiII * i1IIi * Oo0Ooo
     if 65 - 65: Ii1I - OOooOOo % O0 * I1ii11iIi11i . II111iiii
    if ( iIIiI11 . rloc . is_null ( ) ) :
     iIIiI11 . rloc . copy_address ( oO00O . rloc )
     if 59 - 59: O0 . O0 / i11iIiiIii * Oo0Ooo . I11i . Ii1I
     if 89 - 89: O0 + OoO0O00
     if 3 - 3: Oo0Ooo * OoooooooOO * oO0o % OoOoOO00 * OoOoOO00 . ooOoO0o
     if 16 - 16: ooOoO0o / o0oOOo0O0Ooo - O0 * I1IiiI
     if 13 - 13: iII111i . iII111i % O0 % o0oOOo0O0Ooo
    OoiIii11i11i = None if ( oo0oOooo0O . is_null ( ) ) else o0Ooo0Oooo0o
    oOOOOOo0o = o0Ooo0Oooo0o if ( oo0oOooo0O . is_null ( ) ) else oo0oOooo0O
    lisp_send_map_request ( lisp_sockets , 0 , OoiIii11i11i , oOOOOOo0o , iIIiI11 )
    ii11ii1 = oO00O
    if 89 - 89: I11i + IiII + Oo0Ooo . ooOoO0o / I1IiiI * Ii1I
    if 14 - 14: Ii1I * I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
    if 6 - 6: iII111i / iII111i . i11iIiiIii
    if 12 - 12: I11i - OoO0O00
    if ( iii1111ii ) : lisp_install_host_route ( O0O0 , iii1111ii , False )
    if 68 - 68: IiII - OoOoOO00
    if 22 - 22: i1IIi . IiII
    if 8 - 8: IiII % o0oOOo0O0Ooo . i11iIiiIii
    if 69 - 69: I1Ii111 / Ii1I - ooOoO0o
    if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
   if ( OoII1 ) : lisp_install_host_route ( O0O0 , OoII1 , True )
   if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
   if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
   if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
   if 42 - 42: i1IIi . OoO0O00 % iII111i
   O0oo0oOo += 1
   if ( ( O0oo0oOo % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 57 - 57: I1ii11iIi11i / I1IiiI
   if 69 - 69: iII111i - iII111i . OoO0O00 / oO0o - OoO0O00 + I1Ii111
   if 98 - 98: iII111i . oO0o - O0 % I1IiiI . I1ii11iIi11i / i1IIi
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 72 - 72: I1IiiI / Oo0Ooo % IiII - O0 / O0 * O0
 if 83 - 83: O0 / I1Ii111 - OoooooooOO
 if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
 if 39 - 39: OoooooooOO
 if 4 - 4: iIii1I11I1II1 - Oo0Ooo / OOooOOo % OoooooooOO . Oo0Ooo - Oo0Ooo
 if 41 - 41: II111iiii . o0oOOo0O0Ooo
 if 92 - 92: Ii1I - O0 - i11iIiiIii + IiII % I1Ii111 + II111iiii
 if 71 - 71: ooOoO0o * I1Ii111 + i11iIiiIii + i1IIi . I1IiiI
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 15 - 15: OoO0O00
 if 37 - 37: OoO0O00 . OoooooooOO - OOooOOo
 if 34 - 34: o0oOOo0O0Ooo + iIii1I11I1II1 / o0oOOo0O0Ooo / ooOoO0o
 if 53 - 53: II111iiii / iIii1I11I1II1
 if ( lisp_i_am_itr == False ) : return
 if 25 - 25: I1Ii111
 if 58 - 58: OoOoOO00 * i1IIi
 if 20 - 20: IiII
 if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
 if 30 - 30: i11iIiiIii . I1IiiI
 if ( lisp_register_all_rtrs ) : return
 if 5 - 5: Ii1I / O0 + iIii1I11I1II1
 I1O0OOOoOOOO0 = rtr . print_address_no_iid ( )
 if 9 - 9: o0oOOo0O0Ooo % i1IIi / OoO0O00 / OOooOOo + I1Ii111
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
 if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
 if 12 - 12: I1ii11iIi11i - i11iIiiIii + I1IiiI . Oo0Ooo
 if ( I1O0OOOoOOOO0 not in lisp_rtr_list ) : return
 if 26 - 26: oO0o + I1Ii111 + IiII * o0oOOo0O0Ooo . oO0o
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( I1O0OOOoOOOO0 , False ) , bold ( updown , False ) ) )
 if 95 - 95: OoOoOO00 . I1Ii111 / Ii1I . I1Ii111 % OoO0O00
 if 16 - 16: Ii1I / I1IiiI / I1IiiI - OoooooooOO
 if 13 - 13: OOooOOo / OoooooooOO
 if 7 - 7: II111iiii - ooOoO0o
 OO = "rtr%{}%{}" . format ( I1O0OOOoOOOO0 , updown )
 OO = lisp_command_ipc ( OO , "lisp-itr" )
 lisp_ipc ( OO , lisp_ipc_socket , "lisp-etr" )
 return
 if 72 - 72: Ii1I
 if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
 if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
 if 87 - 87: II111iiii
 if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
 if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
 if 24 - 24: i11iIiiIii + ooOoO0o
def lisp_process_rloc_probe_reply ( rloc_entry , source , port , map_reply , ttl ,
 mrloc ) :
 iIIiI11 = rloc_entry . rloc
 o0Oo0o = map_reply . nonce
 o000O000oo = map_reply . hop_count
 Oooooo0OOO = bold ( "RLOC-probe reply" , False )
 I1I11iii1I1 = iIIiI11 . print_address_no_iid ( )
 o0oo0OoO0O = source . print_address_no_iid ( )
 oo00O0000o00 = lisp_rloc_probe_list
 OoO00 = rloc_entry . json . json_string if rloc_entry . json else None
 i1 = lisp_get_timestamp ( )
 if 56 - 56: O0 / OoooooooOO / OoOoOO00
 if 19 - 19: o0oOOo0O0Ooo / i11iIiiIii . i1IIi / Oo0Ooo / I1Ii111
 if 83 - 83: iII111i % o0oOOo0O0Ooo * OoOoOO00
 if 49 - 49: II111iiii / OoO0O00
 if 69 - 69: Ii1I * II111iiii
 if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
 if ( mrloc != None ) :
  OOOOOO0O00O00 = mrloc . rloc . print_address_no_iid ( )
  if ( I1I11iii1I1 not in mrloc . multicast_rloc_probe_list ) :
   o00oOo0OOoo = lisp_rloc ( )
   o00oOo0OOoo = copy . deepcopy ( mrloc )
   o00oOo0OOoo . rloc . copy_address ( iIIiI11 )
   o00oOo0OOoo . multicast_rloc_probe_list = { }
   mrloc . multicast_rloc_probe_list [ I1I11iii1I1 ] = o00oOo0OOoo
   if 19 - 19: iII111i % Ii1I / II111iiii + IiII / Oo0Ooo * OOooOOo
  o00oOo0OOoo = mrloc . multicast_rloc_probe_list [ I1I11iii1I1 ]
  o00oOo0OOoo . last_rloc_probe_nonce = mrloc . last_rloc_probe_nonce
  o00oOo0OOoo . last_rloc_probe = mrloc . last_rloc_probe
  iiiI1I , o0Ooo0Oooo0o , oo0oOooo0O = lisp_rloc_probe_list [ OOOOOO0O00O00 ] [ 0 ]
  o00oOo0OOoo . process_rloc_probe_reply ( i1 , o0Oo0o , o0Ooo0Oooo0o , oo0oOooo0O , o000O000oo , ttl , OoO00 )
  mrloc . process_rloc_probe_reply ( i1 , o0Oo0o , o0Ooo0Oooo0o , oo0oOooo0O , o000O000oo , ttl , OoO00 )
  return
  if 34 - 34: OOooOOo . oO0o + I11i / I1Ii111 . I11i
  if 59 - 59: Ii1I
  if 47 - 47: iII111i % iII111i
  if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
  if 23 - 23: IiII + oO0o + o0oOOo0O0Ooo . I1ii11iIi11i / i11iIiiIii + iIii1I11I1II1
  if 74 - 74: I11i % OOooOOo
  if 57 - 57: O0 + I1IiiI + i11iIiiIii
 IiI = I1I11iii1I1
 if ( IiI not in oo00O0000o00 ) :
  IiI += ":" + str ( port )
  if ( IiI not in oo00O0000o00 ) :
   IiI = o0oo0OoO0O
   if ( IiI not in oo00O0000o00 ) :
    IiI += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( Oooooo0OOO , red ( I1I11iii1I1 , False ) , red ( o0oo0OoO0O ,
    # iIii1I11I1II1 - iII111i - oO0o + Oo0Ooo . Ii1I / i11iIiiIii
 False ) , port ) )
    return
    if 31 - 31: I1Ii111 * i11iIiiIii * IiII - OoooooooOO
    if 82 - 82: II111iiii . Ii1I . i1IIi % iII111i . II111iiii
    if 61 - 61: I1IiiI / Ii1I . O0 + iII111i + oO0o / I11i
    if 14 - 14: I11i % iII111i * i11iIiiIii % i1IIi
    if 10 - 10: iIii1I11I1II1
    if 42 - 42: Oo0Ooo * I1ii11iIi11i
    if 77 - 77: ooOoO0o % I1IiiI * oO0o
    if 91 - 91: OoOoOO00 * Oo0Ooo * IiII - I1IiiI
 for iIIiI11 , o0Ooo0Oooo0o , oo0oOooo0O in lisp_rloc_probe_list [ IiI ] :
  if ( lisp_i_am_rtr ) :
   if ( iIIiI11 . translated_port != 0 and iIIiI11 . translated_port != port ) :
    continue
    if 37 - 37: Oo0Ooo - oO0o / I1ii11iIi11i . o0oOOo0O0Ooo * Ii1I
    if 95 - 95: i11iIiiIii - ooOoO0o / I11i / I1Ii111
  iIIiI11 . process_rloc_probe_reply ( i1 , o0Oo0o , o0Ooo0Oooo0o , oo0oOooo0O , o000O000oo , ttl , OoO00 )
  if 59 - 59: iII111i
 return
 if 59 - 59: Oo0Ooo - IiII
 if 6 - 6: OOooOOo - I1IiiI . IiII
 if 40 - 40: II111iiii
 if 13 - 13: OoOoOO00
 if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
 if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
 if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
def lisp_db_list_length ( ) :
 O0oo0oOo = 0
 for OoO0oO in lisp_db_list :
  O0oo0oOo += len ( OoO0oO . dynamic_eids ) if OoO0oO . dynamic_eid_configured ( ) else 1
  O0oo0oOo += len ( OoO0oO . eid . iid_list )
  if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 return ( O0oo0oOo )
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
 if 46 - 46: OOooOOo
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
def lisp_is_myeid ( eid ) :
 for OoO0oO in lisp_db_list :
  if ( eid . is_more_specific ( OoO0oO . eid ) ) : return ( True )
  if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
 return ( False )
 if 32 - 32: I1Ii111 * I1IiiI + Ii1I
 if 30 - 30: OoooooooOO / I1IiiI . iIii1I11I1II1 / ooOoO0o
 if 20 - 20: OoooooooOO * OOooOOo
 if 77 - 77: Ii1I - OoooooooOO . OoOoOO00
 if 93 - 93: OoooooooOO / I1Ii111
 if 91 - 91: I1Ii111
 if 18 - 18: ooOoO0o * I11i
 if 53 - 53: I11i . i11iIiiIii - iIii1I11I1II1 / I1Ii111
 if 86 - 86: i1IIi % OoO0O00 - OoooooooOO
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 63 - 63: o0oOOo0O0Ooo . iIii1I11I1II1 % IiII * i11iIiiIii
 if 70 - 70: iIii1I11I1II1
 if 12 - 12: OoOoOO00 / o0oOOo0O0Ooo - I1ii11iIi11i + oO0o + O0
 if 9 - 9: I1ii11iIi11i * OoooooooOO . O0 . ooOoO0o * i11iIiiIii / i1IIi
 if 38 - 38: OoOoOO00 . OoooooooOO % I1ii11iIi11i . oO0o % oO0o
 if 80 - 80: i11iIiiIii / OoOoOO00 . OOooOOo . iIii1I11I1II1
 if 81 - 81: I1ii11iIi11i * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 64 - 64: Oo0Ooo . I1ii11iIi11i / ooOoO0o % oO0o . iIii1I11I1II1
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 I111Ii1I1I1iI = None
 if ( rloc_str in lisp_nonce_echo_list ) :
  I111Ii1I1I1iI = lisp_nonce_echo_list [ rloc_str ]
  if 84 - 84: II111iiii . oO0o * O0 / iII111i + OoooooooOO
 return ( I111Ii1I1I1iI )
 if 99 - 99: I1ii11iIi11i . oO0o + Oo0Ooo + I1ii11iIi11i / I1Ii111 . I1ii11iIi11i
 if 95 - 95: OoOoOO00 * iIii1I11I1II1 / OoooooooOO % i1IIi
 if 91 - 91: OOooOOo - OoOoOO00
 if 58 - 58: II111iiii . OOooOOo % II111iiii * oO0o % OoO0O00 % I11i
 if 71 - 71: Ii1I * II111iiii * I1IiiI
 if 22 - 22: oO0o
 if 96 - 96: ooOoO0o * iII111i . IiII
 if 77 - 77: OOooOOo - I11i % o0oOOo0O0Ooo
def lisp_decode_dist_name ( packet ) :
 O0oo0oOo = 0
 IIiIiii1I1i = b""
 if 43 - 43: OoOoOO00 - o0oOOo0O0Ooo
 while ( packet [ 0 : 1 ] != b"\x00" ) :
  if ( O0oo0oOo == 255 ) : return ( [ None , None ] )
  IIiIiii1I1i += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  O0oo0oOo += 1
  if 22 - 22: i1IIi
  if 33 - 33: O0
 packet = packet [ 1 : : ]
 return ( packet , IIiIiii1I1i . decode ( ) )
 if 34 - 34: I1Ii111 . IiII % iII111i
 if 94 - 94: OOooOOo % i11iIiiIii . OOooOOo
 if 55 - 55: OoOoOO00 . OoOoOO00 % o0oOOo0O0Ooo . I11i . I1ii11iIi11i - o0oOOo0O0Ooo
 if 1 - 1: i11iIiiIii - i1IIi * oO0o - iIii1I11I1II1
 if 75 - 75: i1IIi * i11iIiiIii
 if 40 - 40: I1ii11iIi11i + OoO0O00
 if 8 - 8: i11iIiiIii - iIii1I11I1II1
 if 73 - 73: OoOoOO00
def lisp_write_flow_log ( flow_log ) :
 o0OoO0 = open ( "./logs/lisp-flow.log" , "a" )
 if 25 - 25: iII111i / oO0o
 O0oo0oOo = 0
 for oo000o in flow_log :
  Oo00oo = oo000o [ 3 ]
  OoooO0O0o0oOO = Oo00oo . print_flow ( oo000o [ 0 ] , oo000o [ 1 ] , oo000o [ 2 ] )
  o0OoO0 . write ( OoooO0O0o0oOO )
  O0oo0oOo += 1
  if 9 - 9: OoooooooOO / OOooOOo / O0 - OoOoOO00
 o0OoO0 . close ( )
 del ( flow_log )
 if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
 O0oo0oOo = bold ( str ( O0oo0oOo ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( O0oo0oOo ) )
 return
 if 30 - 30: O0 / oO0o * i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
 if 95 - 95: ooOoO0o % OOooOOo
 if 17 - 17: i1IIi + Ii1I
 if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
 if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
 if 26 - 26: oO0o / I1ii11iIi11i - oO0o
 if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
def lisp_policy_command ( kv_pair ) :
 iIIiiIi = lisp_policy ( "" )
 I1oO0 = None
 if 96 - 96: Ii1I
 o00ooOO = [ ]
 for iIi1iIIIiIiI in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  o00ooOO . append ( lisp_policy_match ( ) )
  if 74 - 74: iII111i / iIii1I11I1II1 * I11i + oO0o + iIii1I11I1II1 * o0oOOo0O0Ooo
  if 28 - 28: ooOoO0o . o0oOOo0O0Ooo . OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
 for oO0OoO000oO0o in list ( kv_pair . keys ( ) ) :
  oOO0 = kv_pair [ oO0OoO000oO0o ]
  if 18 - 18: IiII . i11iIiiIii % I1IiiI
  if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
  if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
  if 86 - 86: ooOoO0o * OoOoOO00 + oO0o / II111iiii % OOooOOo
  if ( oO0OoO000oO0o == "instance-id" ) :
   for iIi1iIIIiIiI in range ( len ( o00ooOO ) ) :
    Ooo0oO0O00o0 = oOO0 [ iIi1iIIIiIiI ]
    if ( Ooo0oO0O00o0 == "" ) : continue
    i1i = o00ooOO [ iIi1iIIIiIiI ]
    if ( i1i . source_eid == None ) :
     i1i . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 74 - 74: I1ii11iIi11i . OoO0O00
    if ( i1i . dest_eid == None ) :
     i1i . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 23 - 23: IiII + oO0o
    i1i . source_eid . instance_id = int ( Ooo0oO0O00o0 )
    i1i . dest_eid . instance_id = int ( Ooo0oO0O00o0 )
    if 48 - 48: iII111i * OoO0O00 * OoOoOO00 * I11i
    if 74 - 74: ooOoO0o
  if ( oO0OoO000oO0o == "source-eid" ) :
   for iIi1iIIIiIiI in range ( len ( o00ooOO ) ) :
    Ooo0oO0O00o0 = oOO0 [ iIi1iIIIiIiI ]
    if ( Ooo0oO0O00o0 == "" ) : continue
    i1i = o00ooOO [ iIi1iIIIiIiI ]
    if ( i1i . source_eid == None ) :
     i1i . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 93 - 93: Oo0Ooo % ooOoO0o
    oooo = i1i . source_eid . instance_id
    i1i . source_eid . store_prefix ( Ooo0oO0O00o0 )
    i1i . source_eid . instance_id = oooo
    if 38 - 38: II111iiii . I1Ii111 . iIii1I11I1II1 / o0oOOo0O0Ooo
    if 6 - 6: ooOoO0o - i1IIi * I1IiiI
  if ( oO0OoO000oO0o == "destination-eid" ) :
   for iIi1iIIIiIiI in range ( len ( o00ooOO ) ) :
    Ooo0oO0O00o0 = oOO0 [ iIi1iIIIiIiI ]
    if ( Ooo0oO0O00o0 == "" ) : continue
    i1i = o00ooOO [ iIi1iIIIiIiI ]
    if ( i1i . dest_eid == None ) :
     i1i . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 24 - 24: iIii1I11I1II1 / I1Ii111
    oooo = i1i . dest_eid . instance_id
    i1i . dest_eid . store_prefix ( Ooo0oO0O00o0 )
    i1i . dest_eid . instance_id = oooo
    if 16 - 16: OoOoOO00 * I1Ii111 - I1IiiI / I1Ii111
    if 64 - 64: I1ii11iIi11i . i1IIi % II111iiii % Oo0Ooo + oO0o - I1IiiI
  if ( oO0OoO000oO0o == "source-rloc" ) :
   for iIi1iIIIiIiI in range ( len ( o00ooOO ) ) :
    Ooo0oO0O00o0 = oOO0 [ iIi1iIIIiIiI ]
    if ( Ooo0oO0O00o0 == "" ) : continue
    i1i = o00ooOO [ iIi1iIIIiIiI ]
    i1i . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    i1i . source_rloc . store_prefix ( Ooo0oO0O00o0 )
    if 24 - 24: IiII . II111iiii . II111iiii . OoOoOO00 . i11iIiiIii
    if 11 - 11: Ii1I
  if ( oO0OoO000oO0o == "destination-rloc" ) :
   for iIi1iIIIiIiI in range ( len ( o00ooOO ) ) :
    Ooo0oO0O00o0 = oOO0 [ iIi1iIIIiIiI ]
    if ( Ooo0oO0O00o0 == "" ) : continue
    i1i = o00ooOO [ iIi1iIIIiIiI ]
    i1i . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    i1i . dest_rloc . store_prefix ( Ooo0oO0O00o0 )
    if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
    if 44 - 44: iII111i
  if ( oO0OoO000oO0o == "rloc-record-name" ) :
   for iIi1iIIIiIiI in range ( len ( o00ooOO ) ) :
    Ooo0oO0O00o0 = oOO0 [ iIi1iIIIiIiI ]
    if ( Ooo0oO0O00o0 == "" ) : continue
    i1i = o00ooOO [ iIi1iIIIiIiI ]
    i1i . rloc_record_name = Ooo0oO0O00o0
    if 56 - 56: II111iiii / Oo0Ooo % IiII * II111iiii - iIii1I11I1II1 + ooOoO0o
    if 33 - 33: o0oOOo0O0Ooo . I11i / I1IiiI
  if ( oO0OoO000oO0o == "geo-name" ) :
   for iIi1iIIIiIiI in range ( len ( o00ooOO ) ) :
    Ooo0oO0O00o0 = oOO0 [ iIi1iIIIiIiI ]
    if ( Ooo0oO0O00o0 == "" ) : continue
    i1i = o00ooOO [ iIi1iIIIiIiI ]
    i1i . geo_name = Ooo0oO0O00o0
    if 29 - 29: o0oOOo0O0Ooo - ooOoO0o
    if 59 - 59: I11i / IiII * OoO0O00 / IiII . I1Ii111
  if ( oO0OoO000oO0o == "elp-name" ) :
   for iIi1iIIIiIiI in range ( len ( o00ooOO ) ) :
    Ooo0oO0O00o0 = oOO0 [ iIi1iIIIiIiI ]
    if ( Ooo0oO0O00o0 == "" ) : continue
    i1i = o00ooOO [ iIi1iIIIiIiI ]
    i1i . elp_name = Ooo0oO0O00o0
    if 82 - 82: OOooOOo . iIii1I11I1II1 + I1Ii111
    if 14 - 14: IiII . i11iIiiIii
  if ( oO0OoO000oO0o == "rle-name" ) :
   for iIi1iIIIiIiI in range ( len ( o00ooOO ) ) :
    Ooo0oO0O00o0 = oOO0 [ iIi1iIIIiIiI ]
    if ( Ooo0oO0O00o0 == "" ) : continue
    i1i = o00ooOO [ iIi1iIIIiIiI ]
    i1i . rle_name = Ooo0oO0O00o0
    if 17 - 17: ooOoO0o % ooOoO0o * oO0o
    if 8 - 8: ooOoO0o + OoO0O00 . II111iiii / iIii1I11I1II1 - OOooOOo
  if ( oO0OoO000oO0o == "json-name" ) :
   for iIi1iIIIiIiI in range ( len ( o00ooOO ) ) :
    Ooo0oO0O00o0 = oOO0 [ iIi1iIIIiIiI ]
    if ( Ooo0oO0O00o0 == "" ) : continue
    i1i = o00ooOO [ iIi1iIIIiIiI ]
    i1i . json_name = Ooo0oO0O00o0
    if 87 - 87: iIii1I11I1II1 . IiII % I1IiiI . OoO0O00 - I1Ii111
    if 53 - 53: I1Ii111 % i11iIiiIii
  if ( oO0OoO000oO0o == "datetime-range" ) :
   for iIi1iIIIiIiI in range ( len ( o00ooOO ) ) :
    Ooo0oO0O00o0 = oOO0 [ iIi1iIIIiIiI ]
    i1i = o00ooOO [ iIi1iIIIiIiI ]
    if ( Ooo0oO0O00o0 == "" ) : continue
    oOO0O00o0O0 = lisp_datetime ( Ooo0oO0O00o0 [ 0 : 19 ] )
    ii11IIiI1iIi = lisp_datetime ( Ooo0oO0O00o0 [ 19 : : ] )
    if ( oOO0O00o0O0 . valid_datetime ( ) and ii11IIiI1iIi . valid_datetime ( ) ) :
     i1i . datetime_lower = oOO0O00o0O0
     i1i . datetime_upper = ii11IIiI1iIi
     if 99 - 99: I1IiiI - i1IIi * i11iIiiIii + OoO0O00
     if 80 - 80: o0oOOo0O0Ooo . I11i % iIii1I11I1II1 + OoOoOO00
     if 87 - 87: I1Ii111 + II111iiii / I1ii11iIi11i + OoOoOO00
     if 71 - 71: I1IiiI + iIii1I11I1II1 + O0 * iII111i % IiII
     if 42 - 42: OOooOOo - I1ii11iIi11i
     if 93 - 93: I1Ii111 + OOooOOo % ooOoO0o / I1Ii111 % OOooOOo . IiII
     if 37 - 37: iII111i * oO0o / oO0o / Ii1I % I11i
  if ( oO0OoO000oO0o == "set-action" ) :
   iIIiiIi . set_action = oOO0
   if 12 - 12: i11iIiiIii
  if ( oO0OoO000oO0o == "set-record-ttl" ) :
   iIIiiIi . set_record_ttl = int ( oOO0 )
   if 62 - 62: oO0o + OOooOOo + oO0o + I1IiiI
  if ( oO0OoO000oO0o == "set-instance-id" ) :
   if ( iIIiiIi . set_source_eid == None ) :
    iIIiiIi . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 10 - 10: IiII - Oo0Ooo % ooOoO0o
   if ( iIIiiIi . set_dest_eid == None ) :
    iIIiiIi . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 38 - 38: oO0o * o0oOOo0O0Ooo . I11i % II111iiii / I11i % Ii1I
   I1oO0 = int ( oOO0 )
   iIIiiIi . set_source_eid . instance_id = I1oO0
   iIIiiIi . set_dest_eid . instance_id = I1oO0
   if 19 - 19: II111iiii / i11iIiiIii * II111iiii + OoOoOO00 - OoOoOO00
  if ( oO0OoO000oO0o == "set-source-eid" ) :
   if ( iIIiiIi . set_source_eid == None ) :
    iIIiiIi . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 7 - 7: OoOoOO00 - OoO0O00 % OoOoOO00 . I1ii11iIi11i % Oo0Ooo * iII111i
   iIIiiIi . set_source_eid . store_prefix ( oOO0 )
   if ( I1oO0 != None ) : iIIiiIi . set_source_eid . instance_id = I1oO0
   if 90 - 90: IiII - OOooOOo + iIii1I11I1II1
  if ( oO0OoO000oO0o == "set-destination-eid" ) :
   if ( iIIiiIi . set_dest_eid == None ) :
    iIIiiIi . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 88 - 88: ooOoO0o . o0oOOo0O0Ooo . OOooOOo - I11i
   iIIiiIi . set_dest_eid . store_prefix ( oOO0 )
   if ( I1oO0 != None ) : iIIiiIi . set_dest_eid . instance_id = I1oO0
   if 76 - 76: IiII % I1IiiI . iII111i
  if ( oO0OoO000oO0o == "set-rloc-address" ) :
   iIIiiIi . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   iIIiiIi . set_rloc_address . store_address ( oOO0 )
   if 5 - 5: ooOoO0o . oO0o - OoOoOO00 - OoooooooOO
  if ( oO0OoO000oO0o == "set-rloc-record-name" ) :
   iIIiiIi . set_rloc_record_name = oOO0
   if 2 - 2: OOooOOo
  if ( oO0OoO000oO0o == "set-elp-name" ) :
   iIIiiIi . set_elp_name = oOO0
   if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
  if ( oO0OoO000oO0o == "set-geo-name" ) :
   iIIiiIi . set_geo_name = oOO0
   if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
  if ( oO0OoO000oO0o == "set-rle-name" ) :
   iIIiiIi . set_rle_name = oOO0
   if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
  if ( oO0OoO000oO0o == "set-json-name" ) :
   iIIiiIi . set_json_name = oOO0
   if 78 - 78: OoO0O00 - i1IIi % I1Ii111
  if ( oO0OoO000oO0o == "policy-name" ) :
   iIIiiIi . policy_name = oOO0
   if 87 - 87: I11i
   if 37 - 37: iII111i . I1Ii111 - iII111i - I11i - iIii1I11I1II1 - II111iiii
   if 80 - 80: I1Ii111 % O0 - IiII / II111iiii + i1IIi
   if 4 - 4: OOooOOo + II111iiii
   if 1 - 1: OoooooooOO * I1Ii111 - I11i / IiII
   if 43 - 43: i11iIiiIii * I1IiiI
 iIIiiIi . match_clauses = o00ooOO
 iIIiiIi . save_policy ( )
 return
 if 48 - 48: Oo0Ooo - OOooOOo / iII111i % I1ii11iIi11i . OoOoOO00
 if 6 - 6: i11iIiiIii
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
if 51 - 51: o0oOOo0O0Ooo - OoooooooOO - I11i % i11iIiiIii / I1IiiI + IiII
if 91 - 91: O0
if 13 - 13: o0oOOo0O0Ooo
if 15 - 15: iIii1I11I1II1 * Oo0Ooo . iIii1I11I1II1 . Ii1I % iII111i - i11iIiiIii
if 77 - 77: ooOoO0o - o0oOOo0O0Ooo * OoOoOO00 % oO0o
if 4 - 4: i11iIiiIii + OoOoOO00
if 45 - 45: ooOoO0o / OoooooooOO . Oo0Ooo
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 35 - 35: i11iIiiIii / o0oOOo0O0Ooo / oO0o / I11i . O0
 oO0oiII = command
 if ( interface != "" ) : oO0oiII = interface + ": " + oO0oiII
 lprint ( "Send CLI command '{}' to hardware" . format ( oO0oiII ) )
 if 65 - 65: IiII % I1IiiI % ooOoO0o / oO0o
 Ii1I1IIiii = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 97 - 97: I1IiiI % iII111i * oO0o - i1IIi
 os . system ( "FastCli -c '{}'" . format ( Ii1I1IIiii ) )
 return
 if 7 - 7: oO0o / ooOoO0o / IiII - I1ii11iIi11i * IiII % O0
 if 41 - 41: Ii1I + IiII / O0 . iIii1I11I1II1
 if 71 - 71: oO0o / o0oOOo0O0Ooo % iIii1I11I1II1 * iIii1I11I1II1
 if 29 - 29: ooOoO0o - OoOoOO00 - o0oOOo0O0Ooo
 if 54 - 54: Ii1I + i11iIiiIii + i1IIi - OoooooooOO
 if 100 - 100: oO0o . ooOoO0o
 if 14 - 14: OoooooooOO + iII111i / iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1 - IiII
def lisp_arista_is_alive ( prefix ) :
 oO00o00 = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 oOo0OOoooO = getoutput ( "FastCli -c '{}'" . format ( oO00o00 ) )
 if 34 - 34: I1ii11iIi11i + i11iIiiIii - I1ii11iIi11i / OoOoOO00 + i1IIi . i11iIiiIii
 if 48 - 48: I1ii11iIi11i % OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii / OoOoOO00
 if 73 - 73: OoOoOO00 + OOooOOo * II111iiii . OOooOOo % I1Ii111 % oO0o
 if 79 - 79: I1ii11iIi11i % I11i
 oOo0OOoooO = oOo0OOoooO . split ( "\n" ) [ 1 ]
 OoO0Oo0OoOo = oOo0OOoooO . split ( " " )
 OoO0Oo0OoOo = OoO0Oo0OoOo [ - 1 ] . replace ( "\r" , "" )
 if 52 - 52: i11iIiiIii % IiII - I1ii11iIi11i * Ii1I
 if 27 - 27: ooOoO0o - IiII + iIii1I11I1II1 + Oo0Ooo + O0
 if 42 - 42: OoO0O00 % I1Ii111 . I1ii11iIi11i + II111iiii . OoooooooOO
 if 66 - 66: iII111i * O0 * OoO0O00 % II111iiii
 return ( OoO0Oo0OoOo == "Y" )
 if 39 - 39: i11iIiiIii * i1IIi . OoOoOO00 * Oo0Ooo / iIii1I11I1II1 . OoOoOO00
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
 if 27 - 27: Oo0Ooo * OOooOOo - OoOoOO00
 if 1 - 1: II111iiii * i11iIiiIii . OoooooooOO
 if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
 if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
 if 88 - 88: I1Ii111
 if 16 - 16: Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . OoooooooOO * OoO0O00
 if 50 - 50: II111iiii + I11i . OoooooooOO . I1Ii111 - OOooOOo
 if 83 - 83: oO0o
 if 100 - 100: I1Ii111 + o0oOOo0O0Ooo * oO0o / oO0o . oO0o + iII111i
 if 71 - 71: II111iiii + iII111i + O0 % Oo0Ooo / I1IiiI
 if 52 - 52: Oo0Ooo . I1Ii111 * i1IIi / Oo0Ooo / OoO0O00
 if 29 - 29: iII111i
 if 91 - 91: Oo0Ooo - IiII
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
 if 80 - 80: OoO0O00 - i11iIiiIii / iII111i * I1ii11iIi11i / I1IiiI - I1Ii111
 if 85 - 85: IiII
 if 72 - 72: iII111i * OoOoOO00
 if 65 - 65: iIii1I11I1II1 / iIii1I11I1II1 % O0 / II111iiii . OOooOOo . O0
 if 65 - 65: I11i
 if 35 - 35: o0oOOo0O0Ooo - i11iIiiIii
 if 78 - 78: ooOoO0o - II111iiii - i1IIi
 if 18 - 18: OoooooooOO % OoOoOO00 - IiII / oO0o . OOooOOo . I1IiiI
def lisp_program_vxlan_hardware ( mc ) :
 if 77 - 77: I1ii11iIi11i . OoO0O00 / OoOoOO00 / O0
 if 67 - 67: ooOoO0o % I11i % oO0o
 if 74 - 74: II111iiii
 if 44 - 44: Oo0Ooo + OoO0O00 + OoOoOO00 - I1IiiI
 if 68 - 68: i11iIiiIii / OOooOOo . i1IIi . i11iIiiIii . I11i
 if 56 - 56: iIii1I11I1II1 - II111iiii * i1IIi / Ii1I
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 65 - 65: OOooOOo / I1IiiI . OoooooooOO + I1IiiI + OoooooooOO + i11iIiiIii
 if 20 - 20: I1IiiI + iII111i + O0 * O0
 if 18 - 18: I11i - I11i . OoOoOO00 . ooOoO0o
 if 31 - 31: ooOoO0o
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 87 - 87: OoooooooOO + OOooOOo - I1ii11iIi11i / I1IiiI + ooOoO0o - Oo0Ooo
 if 19 - 19: ooOoO0o + I1ii11iIi11i - ooOoO0o
 if 17 - 17: I11i * i1IIi + iIii1I11I1II1 % I1IiiI
 if 44 - 44: IiII + I1IiiI . Ii1I % Oo0Ooo
 o0OOOooO = mc . eid . print_prefix_no_iid ( )
 iIIiI11 = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 97 - 97: O0
 if 95 - 95: OoO0O00 % iII111i / I1IiiI * OoooooooOO
 if 31 - 31: iIii1I11I1II1
 if 62 - 62: o0oOOo0O0Ooo - iII111i / II111iiii . o0oOOo0O0Ooo
 ii11i11iiI = getoutput ( "ip route get {} | egrep vlan4094" . format ( o0OOOooO ) )
 if 67 - 67: OoOoOO00 % iII111i . o0oOOo0O0Ooo / II111iiii * O0 / I1IiiI
 if ( ii11i11iiI != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( o0OOOooO , False ) , ii11i11iiI ) )
  if 20 - 20: oO0o * O0 - Ii1I + i11iIiiIii - OoOoOO00
  return
  if 18 - 18: I1ii11iIi11i . iII111i
  if 31 - 31: I11i * o0oOOo0O0Ooo
  if 17 - 17: Ii1I * iIii1I11I1II1
  if 9 - 9: o0oOOo0O0Ooo - IiII
  if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
  if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
  if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
 I1II11IIIiI11 = getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( I1II11IIIiI11 . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 65 - 65: I1Ii111 * I1ii11iIi11i
 if ( I1II11IIIiI11 . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 54 - 54: ooOoO0o . i1IIi . OoooooooOO
 IIIIiII = getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( IIIIiII == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 2 - 2: OoOoOO00 . I1IiiI
 IIIIiII = IIIIiII . split ( "inet " ) [ 1 ]
 IIIIiII = IIIIiII . split ( "/" ) [ 0 ]
 if 88 - 88: I1IiiI
 if 34 - 34: ooOoO0o + I1Ii111 / iIii1I11I1II1 + Ii1I . o0oOOo0O0Ooo * OoO0O00
 if 74 - 74: i1IIi / iIii1I11I1II1 . I1ii11iIi11i
 if 71 - 71: ooOoO0o % ooOoO0o * iII111i / Ii1I * O0
 if 21 - 21: o0oOOo0O0Ooo * o0oOOo0O0Ooo - OoOoOO00 % OoOoOO00
 if 8 - 8: I1ii11iIi11i
 if 5 - 5: OOooOOo * i11iIiiIii % oO0o * ooOoO0o
 iII = [ ]
 O000oOoo = getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for IiiiI1 in O000oOoo :
  if ( IiiiI1 . find ( "vlan4094" ) == - 1 ) : continue
  if ( IiiiI1 . find ( "(incomplete)" ) == - 1 ) : continue
  OoII1 = IiiiI1 . split ( " " ) [ 0 ]
  iII . append ( OoII1 )
  if 10 - 10: I1Ii111 / Ii1I + i11iIiiIii * I1Ii111 - OoOoOO00 / I1ii11iIi11i
  if 78 - 78: oO0o % I11i - O0
 OoII1 = None
 ooO0oOOoOO = IIIIiII
 IIIIiII = IIIIiII . split ( "." )
 for iIi1iIIIiIiI in range ( 1 , 255 ) :
  IIIIiII [ 3 ] = str ( iIi1iIIIiIiI )
  IiI = "." . join ( IIIIiII )
  if ( IiI in iII ) : continue
  if ( IiI == ooO0oOOoOO ) : continue
  OoII1 = IiI
  break
  if 35 - 35: OoooooooOO - II111iiii / o0oOOo0O0Ooo - o0oOOo0O0Ooo
 if ( OoII1 == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 55 - 55: OoooooooOO / IiII + i1IIi
  return
  if 54 - 54: ooOoO0o * Ii1I / Ii1I
  if 15 - 15: oO0o * I1Ii111
  if 11 - 11: Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
  if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
  if 46 - 46: oO0o + OoOoOO00
  if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
  if 59 - 59: O0
 OOooOOo0ooO00OO0 = iIIiI11 . split ( "." )
 Oooo = lisp_hex_string ( OOooOOo0ooO00OO0 [ 1 ] ) . zfill ( 2 )
 I1i11I111i = lisp_hex_string ( OOooOOo0ooO00OO0 [ 2 ] ) . zfill ( 2 )
 I11iI1 = lisp_hex_string ( OOooOOo0ooO00OO0 [ 3 ] ) . zfill ( 2 )
 iiiI1IiIIii = "00:00:00:{}:{}:{}" . format ( Oooo , I1i11I111i , I11iI1 )
 ii1Ii1iII1iIi = "0000.00{}.{}{}" . format ( Oooo , I1i11I111i , I11iI1 )
 i1I1iII1111II = "arp -i vlan4094 -s {} {}" . format ( OoII1 , iiiI1IiIIii )
 os . system ( i1I1iII1111II )
 if 72 - 72: IiII / II111iiii
 if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
 if 21 - 21: I1ii11iIi11i
 if 60 - 60: i1IIi / OoO0O00 . Ii1I
 Ii1III1 = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( ii1Ii1iII1iIi , iIIiI11 )
 if 56 - 56: I1Ii111 % II111iiii
 lisp_send_to_arista ( Ii1III1 , None )
 if 11 - 11: i11iIiiIii / OoO0O00 * OoO0O00 . I1Ii111 - OOooOOo
 if 12 - 12: OOooOOo . OoOoOO00 % ooOoO0o
 if 100 - 100: OoOoOO00 . iII111i
 if 50 - 50: iIii1I11I1II1 * OOooOOo . I1IiiI . OoOoOO00 - O0 + Oo0Ooo
 if 89 - 89: IiII - iII111i + IiII
 IIi11I1IIii = "ip route add {} via {}" . format ( o0OOOooO , OoII1 )
 os . system ( IIi11I1IIii )
 if 93 - 93: OoO0O00 . I1IiiI / I1Ii111 % iII111i
 lprint ( "Hardware programmed with commands:" )
 IIi11I1IIii = IIi11I1IIii . replace ( o0OOOooO , green ( o0OOOooO , False ) )
 lprint ( "  " + IIi11I1IIii )
 lprint ( "  " + i1I1iII1111II )
 Ii1III1 = Ii1III1 . replace ( iIIiI11 , red ( iIIiI11 , False ) )
 lprint ( "  " + Ii1III1 )
 return
 if 57 - 57: I1Ii111 . iIii1I11I1II1 / Oo0Ooo / IiII / iII111i * OoOoOO00
 if 35 - 35: i1IIi + I1Ii111 - ooOoO0o . I1ii11iIi11i + Oo0Ooo
 if 43 - 43: oO0o . OoO0O00 * i1IIi
 if 1 - 1: ooOoO0o / i1IIi
 if 42 - 42: I1ii11iIi11i * ooOoO0o + OoOoOO00 % I1ii11iIi11i . IiII
 if 75 - 75: OoO0O00 * i1IIi - OOooOOo % II111iiii % OoO0O00 - OoOoOO00
 if 75 - 75: I11i * IiII * ooOoO0o
def lisp_clear_hardware_walk ( mc , parms ) :
 Oo0OoOI1I11iII1I1i = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( Oo0OoOI1I11iII1I1i ) )
 return ( [ True , None ] )
 if 31 - 31: Ii1I
 if 72 - 72: OOooOOo * Ii1I % OoO0O00
 if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
 if 42 - 42: oO0o / i1IIi . IiII
 if 12 - 12: i11iIiiIii . ooOoO0o
 if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
 if 88 - 88: OoooooooOO . I1IiiI
 if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list , lisp_gleaned_groups
 global lisp_no_map_request_rate_limit
 if 7 - 7: i1IIi
 iiIIIiII = bold ( "User cleared" , False )
 O0oo0oOo = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( iiIIIiII , O0oo0oOo ) )
 if 83 - 83: i11iIiiIii
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 86 - 86: OoO0O00 * oO0o + ooOoO0o % iII111i
 lisp_map_cache = lisp_cache ( )
 if 81 - 81: i11iIiiIii . II111iiii * I11i + Ii1I / O0 . Oo0Ooo
 if 29 - 29: IiII - IiII - OoooooooOO . Ii1I % OoooooooOO - OoOoOO00
 if 33 - 33: oO0o * OoO0O00 / i11iIiiIii - I1IiiI * OoO0O00
 if 19 - 19: OoooooooOO
 lisp_no_map_request_rate_limit = lisp_get_timestamp ( )
 if 34 - 34: OoOoOO00 . oO0o
 if 53 - 53: oO0o + OoooooooOO * ooOoO0o
 if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
 if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
 if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
 lisp_rloc_probe_list = { }
 if 80 - 80: II111iiii . i11iIiiIii
 if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
 if 33 - 33: iIii1I11I1II1
 if 52 - 52: iIii1I11I1II1 + O0
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
 if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
 if 29 - 29: iII111i % I1Ii111
 if 95 - 95: OOooOOo - ooOoO0o % i1IIi / O0 % I11i . IiII
 if 63 - 63: ooOoO0o
 lisp_rtr_list = { }
 if 22 - 22: OOooOOo . i11iIiiIii + II111iiii - Oo0Ooo % i1IIi / o0oOOo0O0Ooo
 if 90 - 90: IiII
 if 38 - 38: i1IIi / ooOoO0o / I11i * I1ii11iIi11i / II111iiii . iIii1I11I1II1
 if 52 - 52: I1ii11iIi11i % ooOoO0o * Ii1I * IiII + IiII / i11iIiiIii
 lisp_gleaned_groups = { }
 if 51 - 51: iIii1I11I1II1 * o0oOOo0O0Ooo % o0oOOo0O0Ooo . Ii1I / OoooooooOO
 if 23 - 23: oO0o * I1IiiI - oO0o - ooOoO0o . IiII / i11iIiiIii
 if 53 - 53: Ii1I * Ii1I . OoOoOO00 . OOooOOo / I1ii11iIi11i % O0
 if 98 - 98: OOooOOo
 lisp_process_data_plane_restart ( True )
 return
 if 11 - 11: OOooOOo * iIii1I11I1II1 % IiII - I1IiiI . I11i
 if 29 - 29: OOooOOo % I11i - OOooOOo - OOooOOo * I11i . oO0o
 if 75 - 75: II111iiii . O0 . I1Ii111 * O0 / OoooooooOO
 if 60 - 60: OOooOOo - Oo0Ooo * OOooOOo / OoO0O00
 if 55 - 55: I1ii11iIi11i * II111iiii * iIii1I11I1II1
 if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i . Ii1I + I1IiiI % i11iIiiIii - i11iIiiIii
 if 62 - 62: I1Ii111 + I1IiiI
 if 9 - 9: iIii1I11I1II1 / iIii1I11I1II1
 if 24 - 24: OOooOOo . I1IiiI % i11iIiiIii
 if 43 - 43: OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i + OoO0O00 . I1Ii111 . iII111i
 if 1 - 1: iII111i / OoO0O00 / OoOoOO00 * Oo0Ooo * OoooooooOO
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 59 - 59: iII111i
 IIIiiI11ii = lisp_myrlocs [ 0 ]
 if 30 - 30: iII111i . OoO0O00 . i11iIiiIii / I1ii11iIi11i * Oo0Ooo
 if 38 - 38: IiII + II111iiii
 if 20 - 20: iII111i * I1IiiI * iII111i - o0oOOo0O0Ooo + i1IIi + ooOoO0o
 if 49 - 49: II111iiii * I1IiiI / oO0o
 if 50 - 50: Ii1I + O0 . I1IiiI * Oo0Ooo
 i1iIii = len ( packet ) + 28
 O0O = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( i1iIii ) , 0 , 64 ,
 17 , 0 , socket . htonl ( IIIiiI11ii . address ) , socket . htonl ( rloc . address ) )
 O0O = lisp_ip_checksum ( O0O )
 if 15 - 15: Oo0Ooo
 O0I1II1 = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( i1iIii - 20 ) , 0 )
 if 53 - 53: OoooooooOO * O0 / iII111i * ooOoO0o % I1Ii111 + OOooOOo
 if 95 - 95: I1Ii111 % OoOoOO00 . IiII * iII111i % Ii1I
 if 18 - 18: iIii1I11I1II1 / ooOoO0o / I1Ii111 % oO0o * Ii1I
 if 14 - 14: oO0o
 packet = lisp_packet ( O0O + O0I1II1 + packet )
 if 72 - 72: iIii1I11I1II1 / II111iiii * II111iiii + I1IiiI + iIii1I11I1II1 + oO0o
 if 46 - 46: I1Ii111
 if 23 - 23: Oo0Ooo * IiII - I1Ii111 . OoooooooOO
 if 78 - 78: OoOoOO00 - iIii1I11I1II1
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( IIIiiI11ii )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( IIIiiI11ii )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 20 - 20: i1IIi
 IIIOo0O = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  oOOOo00000Oo = " {}" . format ( blue ( nat_info . hostname , False ) )
  Oooooo0OOO = bold ( "RLOC-probe request" , False )
 else :
  oOOOo00000Oo = ""
  Oooooo0OOO = bold ( "RLOC-probe reply" , False )
  if 72 - 72: ooOoO0o . II111iiii
  if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( Oooooo0OOO , IIIOo0O , oOOOo00000Oo , packet . encap_port ) )
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
 if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
 if 18 - 18: o0oOOo0O0Ooo / OOooOOo
 if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
 if 100 - 100: O0
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
 oooIIiI1iiIi1i = lisp_sockets [ 3 ]
 packet . send_packet ( oooIIiI1iiIi1i , packet . outer_dest )
 del ( packet )
 return
 if 82 - 82: I1ii11iIi11i . i1IIi + Ii1I
 if 4 - 4: OoO0O00
 if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
 if 36 - 36: I1Ii111 - OoO0O00 . I1ii11iIi11i * I1ii11iIi11i
 if 9 - 9: OOooOOo - oO0o - iIii1I11I1II1 * i11iIiiIii / I11i
 if 2 - 2: i1IIi % iII111i * ooOoO0o / OoOoOO00 + Oo0Ooo
 if 59 - 59: i11iIiiIii / I1IiiI * iII111i
 if 16 - 16: i11iIiiIii * II111iiii - ooOoO0o
def lisp_get_default_route_next_hops ( ) :
 if 80 - 80: iIii1I11I1II1 + iIii1I11I1II1 + I1Ii111 - IiII * iII111i - Ii1I
 if 89 - 89: O0 * ooOoO0o
 if 36 - 36: I1ii11iIi11i * II111iiii * iII111i + I1IiiI + OoO0O00 + oO0o
 if 28 - 28: Ii1I - i11iIiiIii . oO0o / II111iiii
 if ( lisp_is_macos ( ) ) :
  oO00o00 = "route -n get default"
  O0o000oo00o00 = getoutput ( oO00o00 ) . split ( "\n" )
  Iio0o00oo0OoOo = i111IIiIiiI1 = None
  for o0OoO0 in O0o000oo00o00 :
   if ( o0OoO0 . find ( "gateway: " ) != - 1 ) : Iio0o00oo0OoOo = o0OoO0 . split ( ": " ) [ 1 ]
   if ( o0OoO0 . find ( "interface: " ) != - 1 ) : i111IIiIiiI1 = o0OoO0 . split ( ": " ) [ 1 ]
   if 74 - 74: OOooOOo + OoOoOO00 + OoooooooOO
  return ( [ [ i111IIiIiiI1 , Iio0o00oo0OoOo ] ] )
  if 81 - 81: OoO0O00 + OoO0O00
  if 30 - 30: iIii1I11I1II1 . I1ii11iIi11i / OoOoOO00 * oO0o / O0 . o0oOOo0O0Ooo
  if 47 - 47: i1IIi
  if 61 - 61: OOooOOo * I1ii11iIi11i - ooOoO0o - Oo0Ooo + o0oOOo0O0Ooo . ooOoO0o
  if 98 - 98: II111iiii
 oO00o00 = "ip route | egrep 'default via'"
 IIOoo0O = getoutput ( oO00o00 ) . split ( "\n" )
 if 56 - 56: i1IIi % IiII / I1Ii111
 Ii11i = [ ]
 for ii11i11iiI in IIOoo0O :
  if ( ii11i11iiI . find ( " metric " ) != - 1 ) : continue
  iiiI1I = ii11i11iiI . split ( " " )
  try :
   IIIIII1I = iiiI1I . index ( "via" ) + 1
   if ( IIIIII1I >= len ( iiiI1I ) ) : continue
   O0OooOOO000 = iiiI1I . index ( "dev" ) + 1
   if ( O0OooOOO000 >= len ( iiiI1I ) ) : continue
  except :
   continue
   if 61 - 61: OoOoOO00 - I1Ii111 * ooOoO0o + Oo0Ooo / IiII
   if 79 - 79: ooOoO0o % OoooooooOO
  Ii11i . append ( [ iiiI1I [ O0OooOOO000 ] , iiiI1I [ IIIIII1I ] ] )
  if 67 - 67: I1IiiI + OoooooooOO % OoO0O00 . OoooooooOO + I11i / oO0o
 return ( Ii11i )
 if 33 - 33: I1ii11iIi11i
 if 5 - 5: O0
 if 50 - 50: Oo0Ooo % IiII * oO0o
 if 71 - 71: OoO0O00
 if 64 - 64: OoO0O00 - I1ii11iIi11i % OoO0O00 + OoOoOO00 - Oo0Ooo * I1ii11iIi11i
 if 78 - 78: I1Ii111 % OoO0O00 . IiII % iIii1I11I1II1 / OoO0O00
 if 34 - 34: iIii1I11I1II1
def lisp_get_host_route_next_hop ( rloc ) :
 oO00o00 = "ip route | egrep '{} via'" . format ( rloc )
 ii11i11iiI = getoutput ( oO00o00 ) . split ( " " )
 if 33 - 33: I1ii11iIi11i + I1Ii111 * ooOoO0o / i11iIiiIii
 try : OOOooo0OooOoO = ii11i11iiI . index ( "via" ) + 1
 except : return ( None )
 if 83 - 83: oO0o
 if ( OOOooo0OooOoO >= len ( ii11i11iiI ) ) : return ( None )
 return ( ii11i11iiI [ OOOooo0OooOoO ] )
 if 93 - 93: II111iiii
 if 89 - 89: OoO0O00 % II111iiii % iII111i
 if 66 - 66: OoooooooOO % iII111i % i11iIiiIii
 if 35 - 35: OoooooooOO - IiII
 if 38 - 38: I1Ii111 % I11i . I11i % I11i + OoOoOO00
 if 79 - 79: I1ii11iIi11i + OoO0O00 * I1ii11iIi11i / I11i
 if 13 - 13: OoOoOO00 . iII111i
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 iIiI1iIiII1 = "none" if nh == None else nh
 if 11 - 11: Oo0Ooo - Ii1I / OoO0O00
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , iIiI1iIiII1 ) )
 if 95 - 95: OoooooooOO
 if ( nh == None ) :
  O0Ooo0iII111III = "ip route {} {}/32" . format ( install , dest )
 else :
  O0Ooo0iII111III = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 64 - 64: I1ii11iIi11i . I1Ii111
 os . system ( O0Ooo0iII111III )
 return
 if 81 - 81: IiII . ooOoO0o + O0 . ooOoO0o + iIii1I11I1II1
 if 68 - 68: i11iIiiIii . iII111i + OoooooooOO + II111iiii + iIii1I11I1II1 % I11i
 if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
 if 62 - 62: OoOoOO00 * oO0o - I1IiiI / Ii1I
 if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
 if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
 if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
 if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
 o0OoO0 = open ( lisp_checkpoint_filename , "w" )
 for oo0O00OOOOO in checkpoint_list :
  o0OoO0 . write ( oo0O00OOOOO + "\n" )
  if 9 - 9: i1IIi % iII111i / Ii1I
 o0OoO0 . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 83 - 83: oO0o
 if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
 if 29 - 29: OoooooooOO
 if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
 if 83 - 83: iIii1I11I1II1
 if 92 - 92: OoO0O00 - iII111i
 if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
 if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
 o0OoO0 = open ( lisp_checkpoint_filename , "r" )
 if 70 - 70: I1Ii111 % iIii1I11I1II1
 O0oo0oOo = 0
 for oo0O00OOOOO in o0OoO0 :
  O0oo0oOo += 1
  oO0ooOOO = oo0O00OOOOO . split ( " rloc " )
  OOOO00 = [ ] if ( oO0ooOOO [ 1 ] in [ "native-forward\n" , "\n" ] ) else oO0ooOOO [ 1 ] . split ( ", " )
  if 74 - 74: i1IIi % i11iIiiIii + oO0o
  if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
  OO00O000OOO = [ ]
  for iIIiI11 in OOOO00 :
   OOOoOoo = lisp_rloc ( False )
   iiiI1I = iIIiI11 . split ( " " )
   OOOoOoo . rloc . store_address ( iiiI1I [ 0 ] )
   OOOoOoo . priority = int ( iiiI1I [ 1 ] )
   OOOoOoo . weight = int ( iiiI1I [ 2 ] )
   OO00O000OOO . append ( OOOoOoo )
   if 34 - 34: Oo0Ooo . i1IIi
   if 97 - 97: I11i
  I11iiI1III = lisp_mapping ( "" , "" , OO00O000OOO )
  if ( I11iiI1III != None ) :
   I11iiI1III . eid . store_prefix ( oO0ooOOO [ 0 ] )
   I11iiI1III . checkpoint_entry = True
   I11iiI1III . map_cache_ttl = LISP_NMR_TTL * 60
   if ( OO00O000OOO == [ ] ) : I11iiI1III . action = LISP_NATIVE_FORWARD_ACTION
   I11iiI1III . add_cache ( )
   continue
   if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
   if 20 - 20: oO0o % OoOoOO00
  O0oo0oOo -= 1
  if 93 - 93: I1ii11iIi11i - Ii1I % i1IIi / i1IIi
  if 82 - 82: OOooOOo
 o0OoO0 . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , O0oo0oOo , lisp_checkpoint_filename ) )
 return
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
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
 oo0O00OOOOO = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 11 - 11: I1IiiI % Ii1I * i11iIiiIii % OOooOOo + II111iiii
 for OOOoOoo in mc . rloc_set :
  if ( OOOoOoo . rloc . is_null ( ) ) : continue
  oo0O00OOOOO += "{} {} {}, " . format ( OOOoOoo . rloc . print_address_no_iid ( ) ,
 OOOoOoo . priority , OOOoOoo . weight )
  if 61 - 61: I1Ii111 + I11i + I1IiiI
  if 48 - 48: I11i
 if ( mc . rloc_set != [ ] ) :
  oo0O00OOOOO = oo0O00OOOOO [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  oo0O00OOOOO += "native-forward"
  if 67 - 67: o0oOOo0O0Ooo
  if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
 checkpoint_list . append ( oo0O00OOOOO )
 return
 if 61 - 61: i11iIiiIii / Ii1I - OOooOOo . I1ii11iIi11i
 if 89 - 89: ooOoO0o % i11iIiiIii
 if 57 - 57: Oo0Ooo / ooOoO0o - O0 . ooOoO0o
 if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
 if 75 - 75: Ii1I
 if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
 if 99 - 99: oO0o + I11i % i1IIi . iII111i
def lisp_check_dp_socket ( ) :
 OOoooOOOoo = lisp_ipc_dp_socket_name
 if ( os . path . exists ( OOoooOOOoo ) == False ) :
  OOI11iiiiiII1 = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( OOoooOOOoo , OOI11iiiiiII1 ) )
  return ( False )
  if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
 return ( True )
 if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
 if 74 - 74: OoOoOO00 + I1ii11iIi11i
 if 82 - 82: II111iiii
 if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
 if 48 - 48: ooOoO0o + Oo0Ooo / Oo0Ooo
 if 15 - 15: iIii1I11I1II1 . I1Ii111 * OoooooooOO * O0 % OOooOOo
 if 53 - 53: Ii1I
def lisp_write_to_dp_socket ( entry ) :
 try :
  o0OO0ooooO = json . dumps ( entry )
  I1IiI11iI1Iii = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( I1IiI11iI1Iii , o0OO0ooooO ) )
  lisp_ipc_dp_socket . sendto ( o0OO0ooooO , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( o0OO0ooooO ) )
  if 88 - 88: o0oOOo0O0Ooo + OoooooooOO - OoO0O00 / I1Ii111 / OoooooooOO
 return
 if 8 - 8: i11iIiiIii / O0 * OOooOOo * i1IIi
 if 57 - 57: O0 - IiII
 if 66 - 66: OOooOOo % i11iIiiIii % OoooooooOO - o0oOOo0O0Ooo + OoOoOO00 + OoooooooOO
 if 66 - 66: OoOoOO00 . Ii1I / i11iIiiIii / ooOoO0o
 if 76 - 76: OoO0O00 % OoO0O00 / I1ii11iIi11i * ooOoO0o * o0oOOo0O0Ooo - I1Ii111
 if 53 - 53: OoO0O00 % Oo0Ooo . i1IIi
 if 34 - 34: Ii1I - o0oOOo0O0Ooo * i1IIi
 if 7 - 7: OoO0O00 * I1ii11iIi11i / I1Ii111
 if 98 - 98: II111iiii % I1ii11iIi11i
def lisp_write_ipc_keys ( rloc ) :
 O0O0 = rloc . rloc . print_address_no_iid ( )
 ooO0 = rloc . translated_port
 if ( ooO0 != 0 ) : O0O0 += ":" + str ( ooO0 )
 if ( O0O0 not in lisp_rloc_probe_list ) : return
 if 48 - 48: iII111i % oO0o + oO0o - Oo0Ooo . OOooOOo
 for iiiI1I , oO0ooOOO , Oo in lisp_rloc_probe_list [ O0O0 ] :
  I11iiI1III = lisp_map_cache . lookup_cache ( oO0ooOOO , True )
  if ( I11iiI1III == None ) : continue
  lisp_write_ipc_map_cache ( True , I11iiI1III )
  if 38 - 38: iII111i
 return
 if 66 - 66: iII111i + Oo0Ooo + i1IIi * Oo0Ooo
 if 18 - 18: O0 - IiII
 if 5 - 5: I1ii11iIi11i * iII111i + II111iiii * Oo0Ooo * O0 - I1IiiI
 if 71 - 71: i11iIiiIii % I1IiiI + I1ii11iIi11i + II111iiii + OoooooooOO + oO0o
 if 12 - 12: I1IiiI + I1Ii111
 if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
 if 74 - 74: O0 % OOooOOo * OoOoOO00 / oO0o - Oo0Ooo
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 79 - 79: Ii1I + IiII
 if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
 if 98 - 98: I1ii11iIi11i
 if 58 - 58: IiII / i11iIiiIii % I11i
 oOOoo = "add" if add_or_delete else "delete"
 oo0O00OOOOO = { "type" : "map-cache" , "opcode" : oOOoo }
 if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
 II1OO0Oo0oOOO000 = ( mc . group . is_null ( ) == False )
 if ( II1OO0Oo0oOOO000 ) :
  oo0O00OOOOO [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  oo0O00OOOOO [ "rles" ] = [ ]
 else :
  oo0O00OOOOO [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  oo0O00OOOOO [ "rlocs" ] = [ ]
  if 21 - 21: Ii1I
 oo0O00OOOOO [ "instance-id" ] = str ( mc . eid . instance_id )
 if 72 - 72: I1Ii111 . OoooooooOO / I1Ii111 - Ii1I / I1ii11iIi11i * I1ii11iIi11i
 if ( II1OO0Oo0oOOO000 ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for iIIi in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    IiI = iIIi . address . print_address_no_iid ( )
    ooO0 = str ( 4341 ) if iIIi . translated_port == 0 else str ( iIIi . translated_port )
    if 72 - 72: IiII . Ii1I + OoooooooOO * OoOoOO00 + Oo0Ooo . iII111i
    iiiI1I = { "rle" : IiI , "port" : ooO0 }
    iiIio0o0 , OoO0OOo0OOoOO = iIIi . get_encap_keys ( )
    iiiI1I = lisp_build_json_keys ( iiiI1I , iiIio0o0 , OoO0OOo0OOoOO , "encrypt-key" )
    oo0O00OOOOO [ "rles" ] . append ( iiiI1I )
    if 91 - 91: OOooOOo % Oo0Ooo
    if 44 - 44: iIii1I11I1II1 . OOooOOo
 else :
  for iIIiI11 in mc . rloc_set :
   if ( iIIiI11 . rloc . is_ipv4 ( ) == False and iIIiI11 . rloc . is_ipv6 ( ) == False ) :
    continue
    if 57 - 57: II111iiii + I1Ii111
   if ( iIIiI11 . up_state ( ) == False ) : continue
   if 42 - 42: OoOoOO00 % O0
   ooO0 = str ( 4341 ) if iIIiI11 . translated_port == 0 else str ( iIIiI11 . translated_port )
   if 70 - 70: iIii1I11I1II1 * Oo0Ooo - I1IiiI / OoO0O00 + OoOoOO00
   iiiI1I = { "rloc" : iIIiI11 . rloc . print_address_no_iid ( ) , "priority" :
 str ( iIIiI11 . priority ) , "weight" : str ( iIIiI11 . weight ) , "port" :
 ooO0 }
   iiIio0o0 , OoO0OOo0OOoOO = iIIiI11 . get_encap_keys ( )
   iiiI1I = lisp_build_json_keys ( iiiI1I , iiIio0o0 , OoO0OOo0OOoOO , "encrypt-key" )
   oo0O00OOOOO [ "rlocs" ] . append ( iiiI1I )
   if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
   if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
   if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
 if ( dont_send == False ) : lisp_write_to_dp_socket ( oo0O00OOOOO )
 return ( oo0O00OOOOO )
 if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
 if 26 - 26: Ii1I * I11i / I11i
 if 79 - 79: ooOoO0o / oO0o - oO0o / OoooooooOO
 if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
 if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
 if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
 if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 16 - 16: I11i
 if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
 if 61 - 61: O0 % iII111i
 if 41 - 41: I1Ii111 * OoooooooOO
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 76 - 76: OoooooooOO * II111iiii . II111iiii / o0oOOo0O0Ooo - iII111i
 iiIio0o0 = keys [ 1 ] . encrypt_key
 OoO0OOo0OOoOO = keys [ 1 ] . icv_key
 if 49 - 49: O0 . I1ii11iIi11i . OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
 if 19 - 19: iIii1I11I1II1
 if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
 if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
 OOooOO000oo = rloc_addr . split ( ":" )
 if ( len ( OOooOO000oo ) == 1 ) :
  oo0O00OOOOO = { "type" : "decap-keys" , "rloc" : OOooOO000oo [ 0 ] }
 else :
  oo0O00OOOOO = { "type" : "decap-keys" , "rloc" : OOooOO000oo [ 0 ] , "port" : OOooOO000oo [ 1 ] }
  if 78 - 78: Oo0Ooo % O0 / i11iIiiIii
 oo0O00OOOOO = lisp_build_json_keys ( oo0O00OOOOO , iiIio0o0 , OoO0OOo0OOoOO , "decrypt-key" )
 if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
 lisp_write_to_dp_socket ( oo0O00OOOOO )
 return
 if 57 - 57: i1IIi
 if 41 - 41: I11i / Ii1I
 if 1 - 1: II111iiii / iII111i
 if 83 - 83: OoO0O00 / iII111i
 if 59 - 59: I1Ii111 % OOooOOo . I1IiiI + I1ii11iIi11i % oO0o
 if 96 - 96: OoO0O00
 if 53 - 53: oO0o + OoO0O00
 if 58 - 58: iIii1I11I1II1 + OoOoOO00
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 65 - 65: iII111i % Oo0Ooo * iIii1I11I1II1 + I1IiiI + II111iiii
 entry [ "keys" ] = [ ]
 III = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( III )
 return ( entry )
 if 72 - 72: OoOoOO00 . OoooooooOO - OOooOOo
 if 15 - 15: OoOoOO00
 if 13 - 13: I1ii11iIi11i - OOooOOo - i11iIiiIii / IiII
 if 65 - 65: IiII
 if 76 - 76: I1Ii111 % I1ii11iIi11i + ooOoO0o / I1IiiI
 if 59 - 59: OOooOOo - o0oOOo0O0Ooo - o0oOOo0O0Ooo % I1IiiI
 if 55 - 55: o0oOOo0O0Ooo % I1ii11iIi11i - IiII + OoooooooOO
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 44 - 44: iII111i * I1Ii111 - I1IiiI % i1IIi
 if 35 - 35: iII111i . OoOoOO00 + i1IIi . I1Ii111 - oO0o
 if 92 - 92: o0oOOo0O0Ooo
 if 8 - 8: i1IIi / IiII . O0
 oo0O00OOOOO = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 72 - 72: OOooOOo
 if 20 - 20: i11iIiiIii + Oo0Ooo * Oo0Ooo % OOooOOo
 if 66 - 66: I1ii11iIi11i + iII111i / Ii1I / I1IiiI * i11iIiiIii
 if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
 for OoO0oO in lisp_db_list :
  if ( OoO0oO . eid . is_ipv4 ( ) == False and OoO0oO . eid . is_ipv6 ( ) == False ) : continue
  OoOo00 = { "instance-id" : str ( OoO0oO . eid . instance_id ) ,
 "eid-prefix" : OoO0oO . eid . print_prefix_no_iid ( ) }
  oo0O00OOOOO [ "database-mappings" ] . append ( OoOo00 )
  if 36 - 36: oO0o . I1ii11iIi11i % Oo0Ooo * oO0o + I1IiiI
 lisp_write_to_dp_socket ( oo0O00OOOOO )
 if 15 - 15: ooOoO0o - Ii1I * OoOoOO00
 if 80 - 80: i1IIi % OOooOOo - ooOoO0o % iII111i . I1Ii111 + I1ii11iIi11i
 if 9 - 9: OoooooooOO . iII111i . iIii1I11I1II1 . I11i % ooOoO0o % I1IiiI
 if 78 - 78: OoO0O00 - ooOoO0o * I1IiiI * iII111i . i1IIi - OOooOOo
 if 47 - 47: oO0o + ooOoO0o . OoooooooOO / ooOoO0o + i1IIi / I1Ii111
 oo0O00OOOOO = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( oo0O00OOOOO )
 return
 if 92 - 92: I1IiiI
 if 56 - 56: I1Ii111 . Oo0Ooo
 if 29 - 29: I1IiiI * Ii1I . OoooooooOO
 if 18 - 18: I11i % iIii1I11I1II1 * OOooOOo
 if 58 - 58: i11iIiiIii / OoOoOO00
 if 18 - 18: ooOoO0o + O0 - OOooOOo + iIii1I11I1II1 . OOooOOo * iIii1I11I1II1
 if 83 - 83: OoO0O00 - Oo0Ooo * I1IiiI % Oo0Ooo % oO0o
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 64 - 64: OoOoOO00 + oO0o / OoooooooOO . i11iIiiIii / II111iiii
 if 55 - 55: ooOoO0o . i11iIiiIii . o0oOOo0O0Ooo
 if 52 - 52: IiII . oO0o + i11iIiiIii % IiII
 if 45 - 45: i1IIi - I1IiiI / IiII - I1IiiI
 oo0O00OOOOO = { "type" : "interfaces" , "interfaces" : [ ] }
 if 21 - 21: IiII
 for i111IIiIiiI1 in list ( lisp_myinterfaces . values ( ) ) :
  if ( i111IIiIiiI1 . instance_id == None ) : continue
  OoOo00 = { "interface" : i111IIiIiiI1 . device ,
 "instance-id" : str ( i111IIiIiiI1 . instance_id ) }
  oo0O00OOOOO [ "interfaces" ] . append ( OoOo00 )
  if 43 - 43: IiII
  if 9 - 9: OOooOOo * ooOoO0o + ooOoO0o . I1Ii111
 lisp_write_to_dp_socket ( oo0O00OOOOO )
 return
 if 8 - 8: IiII * iIii1I11I1II1
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
def lisp_parse_auth_key ( value ) :
 Iii1iIi1i = value . split ( "[" )
 i11i1Ii = { }
 if ( len ( Iii1iIi1i ) == 1 ) :
  i11i1Ii [ 0 ] = value
  return ( i11i1Ii )
  if 9 - 9: o0oOOo0O0Ooo
  if 20 - 20: ooOoO0o - I1Ii111 % II111iiii - O0
 for Ooo0oO0O00o0 in Iii1iIi1i :
  if ( Ooo0oO0O00o0 == "" ) : continue
  OOOooo0OooOoO = Ooo0oO0O00o0 . find ( "]" )
  IiII11iI1 = Ooo0oO0O00o0 [ 0 : OOOooo0OooOoO ]
  try : IiII11iI1 = int ( IiII11iI1 )
  except : return
  if 76 - 76: i1IIi + iII111i * iII111i
  i11i1Ii [ IiII11iI1 ] = Ooo0oO0O00o0 [ OOOooo0OooOoO + 1 : : ]
  if 31 - 31: O0 - iIii1I11I1II1 . I11i . oO0o
 return ( i11i1Ii )
 if 96 - 96: OoooooooOO * iIii1I11I1II1 * Oo0Ooo
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
 if 6 - 6: i1IIi . oO0o % IiII . Oo0Ooo % I11i
 if 86 - 86: OoooooooOO + IiII % o0oOOo0O0Ooo . i1IIi . iII111i
 if 25 - 25: iII111i * I1ii11iIi11i + I11i - I1ii11iIi11i
 if 75 - 75: IiII
 if 74 - 74: o0oOOo0O0Ooo - iIii1I11I1II1
def lisp_reassemble ( packet ) :
 Oo0ooo = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 92 - 92: i11iIiiIii * iIii1I11I1II1 - I1Ii111 . i1IIi
 if 23 - 23: O0 - O0 . I1Ii111 . I1IiiI - I1IiiI * i1IIi
 if 8 - 8: I1IiiI . I1ii11iIi11i + oO0o % oO0o * oO0o
 if 70 - 70: II111iiii + IiII + O0 / Ii1I - i11iIiiIii
 if ( Oo0ooo == 0 or Oo0ooo == 0x4000 ) : return ( packet )
 if 72 - 72: II111iiii - II111iiii
 if 44 - 44: o0oOOo0O0Ooo + OoooooooOO
 if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
 if 87 - 87: OOooOOo * OoO0O00
 OOoo0 = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 oOi11iIIIIi = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 61 - 61: iII111i - II111iiii . I1Ii111 % II111iiii / I11i
 o000O = ( Oo0ooo & 0x2000 == 0 and ( Oo0ooo & 0x1fff ) != 0 )
 oo0O00OOOOO = [ ( Oo0ooo & 0x1fff ) * 8 , oOi11iIIIIi - 20 , packet , o000O ]
 if 88 - 88: Ii1I % Oo0Ooo / Oo0Ooo - O0 - Oo0Ooo
 if 17 - 17: II111iiii - i1IIi
 if 91 - 91: Ii1I
 if 45 - 45: I1ii11iIi11i + Oo0Ooo
 if 72 - 72: I1ii11iIi11i
 if 5 - 5: i1IIi
 if 31 - 31: iII111i - OoooooooOO + oO0o / OoooooooOO + I1ii11iIi11i
 if 93 - 93: o0oOOo0O0Ooo * I1ii11iIi11i % I1IiiI * ooOoO0o
 if ( Oo0ooo == 0x2000 ) :
  oooooO0oO0ooO , iIII1IiI = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  oooooO0oO0ooO = socket . ntohs ( oooooO0oO0ooO )
  iIII1IiI = socket . ntohs ( iIII1IiI )
  if ( iIII1IiI not in [ 4341 , 8472 , 4789 ] and oooooO0oO0ooO != 4341 ) :
   lisp_reassembly_queue [ OOoo0 ] = [ ]
   oo0O00OOOOO [ 2 ] = None
   if 37 - 37: OoO0O00 * OoooooooOO / oO0o * I11i * I1ii11iIi11i
   if 42 - 42: OoooooooOO - ooOoO0o . OOooOOo + OoOoOO00
   if 53 - 53: o0oOOo0O0Ooo
   if 55 - 55: ooOoO0o . i1IIi - ooOoO0o + O0 + I1IiiI
   if 31 - 31: OoO0O00 % I1Ii111
   if 62 - 62: oO0o / O0 - I1Ii111 . IiII
 if ( OOoo0 not in lisp_reassembly_queue ) :
  lisp_reassembly_queue [ OOoo0 ] = [ ]
  if 81 - 81: i11iIiiIii
  if 57 - 57: O0
  if 85 - 85: i11iIiiIii - i11iIiiIii - OoOoOO00 / II111iiii - II111iiii
  if 4 - 4: I1ii11iIi11i * O0 / OoO0O00 * II111iiii . iIii1I11I1II1 / OOooOOo
  if 97 - 97: i1IIi - OoOoOO00 . OoooooooOO
 queue = lisp_reassembly_queue [ OOoo0 ]
 if 24 - 24: iIii1I11I1II1 + OOooOOo * iII111i % IiII % OOooOOo
 if 64 - 64: IiII . I1ii11iIi11i - o0oOOo0O0Ooo - ooOoO0o + OoooooooOO
 if 95 - 95: iII111i . I1ii11iIi11i + ooOoO0o + o0oOOo0O0Ooo % OoO0O00
 if 50 - 50: iII111i * O0 % II111iiii
 if 80 - 80: OOooOOo - II111iiii - OoO0O00
 if ( len ( queue ) == 1 and queue [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( OOoo0 ) . zfill ( 4 ) ) )
  if 62 - 62: Ii1I . i11iIiiIii % OOooOOo
  return ( None )
  if 44 - 44: i1IIi * I1ii11iIi11i % Ii1I . Ii1I * I11i + II111iiii
  if 15 - 15: i1IIi - I11i - I1Ii111 / OoO0O00 + Oo0Ooo + I1IiiI
  if 81 - 81: IiII
  if 54 - 54: I1IiiI % OoO0O00 % OoOoOO00
  if 12 - 12: II111iiii . O0 * i11iIiiIii . I11i
 queue . append ( oo0O00OOOOO )
 queue = sorted ( queue )
 if 98 - 98: II111iiii + i1IIi * oO0o % I1IiiI
 if 53 - 53: i11iIiiIii . I1ii11iIi11i - OOooOOo - OOooOOo
 if 97 - 97: I1IiiI % iII111i % OoooooooOO / ooOoO0o / i11iIiiIii
 if 7 - 7: O0 % IiII / o0oOOo0O0Ooo
 IiI = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 IiI . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 o00O0O0 = IiI . print_address_no_iid ( )
 IiI . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 I111II11IIii = IiI . print_address_no_iid ( )
 IiI = red ( "{} -> {}" . format ( o00O0O0 , I111II11IIii ) , False )
 if 37 - 37: OoooooooOO % II111iiii / o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i . iIii1I11I1II1
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if oo0O00OOOOO [ 2 ] == None else "" , IiI , lisp_hex_string ( OOoo0 ) . zfill ( 4 ) ,
 # OoOoOO00 . i1IIi + Oo0Ooo / O0 - IiII
 # Oo0Ooo / ooOoO0o + II111iiii + OoooooooOO * iIii1I11I1II1
 lisp_hex_string ( Oo0ooo ) . zfill ( 4 ) ) )
 if 82 - 82: i1IIi - I11i % ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo
 if 20 - 20: i11iIiiIii - O0 / i11iIiiIii
 if 51 - 51: iII111i . ooOoO0o
 if 70 - 70: I11i / O0 - I11i + o0oOOo0O0Ooo . ooOoO0o . o0oOOo0O0Ooo
 if 6 - 6: I11i + II111iiii - I1Ii111
 if ( queue [ 0 ] [ 0 ] != 0 or queue [ - 1 ] [ 3 ] == False ) : return ( None )
 IiI1 = queue [ 0 ]
 for Ii in queue [ 1 : : ] :
  Oo0ooo = Ii [ 0 ]
  o0o0oOo , I11iiI1iIiiII = IiI1 [ 0 ] , IiI1 [ 1 ]
  if ( o0o0oOo + I11iiI1iIiiII != Oo0ooo ) : return ( None )
  IiI1 = Ii
  if 11 - 11: Oo0Ooo - o0oOOo0O0Ooo
 lisp_reassembly_queue . pop ( OOoo0 )
 if 45 - 45: ooOoO0o - oO0o - I1IiiI
 if 21 - 21: OoooooooOO
 if 28 - 28: I1ii11iIi11i + oO0o . Oo0Ooo % iIii1I11I1II1 / I1Ii111
 if 8 - 8: O0 . I1IiiI * o0oOOo0O0Ooo + I1IiiI
 if 44 - 44: i1IIi % iII111i . i11iIiiIii / I11i + OoooooooOO
 packet = queue [ 0 ] [ 2 ]
 for Ii in queue [ 1 : : ] : packet += Ii [ 2 ] [ 20 : : ]
 if 21 - 21: OoOoOO00 . OoO0O00 . OoOoOO00 + OoOoOO00
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( OOoo0 ) . zfill ( 4 ) , len ( packet ) ) )
 if 30 - 30: I1IiiI - iII111i - OOooOOo + oO0o
 if 51 - 51: Ii1I % O0 / II111iiii . Oo0Ooo
 if 90 - 90: i11iIiiIii * II111iiii % iIii1I11I1II1 . I1ii11iIi11i / Oo0Ooo . OOooOOo
 if 77 - 77: OoO0O00
 if 95 - 95: II111iiii
 i1iIii = socket . htons ( len ( packet ) )
 IiIii1iIIII = packet [ 0 : 2 ] + struct . pack ( "H" , i1iIii ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 59 - 59: iIii1I11I1II1 % OOooOOo / OoOoOO00 * I1Ii111 * OoooooooOO * O0
 if 43 - 43: OoO0O00 * I1IiiI * OOooOOo * O0 - O0 / o0oOOo0O0Ooo
 IiIii1iIIII = lisp_ip_checksum ( IiIii1iIIII )
 return ( IiIii1iIIII + packet [ 20 : : ] )
 if 77 - 77: I11i % I1Ii111 . IiII % OoooooooOO * o0oOOo0O0Ooo
 if 87 - 87: iII111i + IiII / ooOoO0o * ooOoO0o * OOooOOo
 if 97 - 97: I1Ii111
 if 47 - 47: iII111i / I1ii11iIi11i - Ii1I . II111iiii
 if 56 - 56: O0 - i1IIi % o0oOOo0O0Ooo + IiII
 if 42 - 42: o0oOOo0O0Ooo . OOooOOo % I11i - OoOoOO00
 if 38 - 38: OoooooooOO
 if 27 - 27: O0 + I1ii11iIi11i % Ii1I . i1IIi + OoO0O00 + OoOoOO00
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 O0O0 = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( O0O0 in lisp_crypto_keys_by_rloc_decap ) : return ( O0O0 )
 if 22 - 22: II111iiii / I1IiiI + o0oOOo0O0Ooo * I1IiiI . OoooooooOO * OOooOOo
 O0O0 = addr . print_address_no_iid ( )
 if ( O0O0 in lisp_crypto_keys_by_rloc_decap ) : return ( O0O0 )
 if 49 - 49: I1ii11iIi11i * I1IiiI + OOooOOo + i11iIiiIii * I1ii11iIi11i . o0oOOo0O0Ooo
 if 36 - 36: o0oOOo0O0Ooo - i11iIiiIii
 if 37 - 37: O0 + IiII + I1IiiI
 if 50 - 50: OoooooooOO . I1Ii111
 if 100 - 100: ooOoO0o * ooOoO0o - Ii1I
 for I1OO in lisp_crypto_keys_by_rloc_decap :
  OO0O00o0 = I1OO . split ( ":" )
  if ( len ( OO0O00o0 ) == 1 ) : continue
  OO0O00o0 = OO0O00o0 [ 0 ] if len ( OO0O00o0 ) == 2 else ":" . join ( OO0O00o0 [ 0 : - 1 ] )
  if ( OO0O00o0 == O0O0 ) :
   iI1iiiiiii = lisp_crypto_keys_by_rloc_decap [ I1OO ]
   lisp_crypto_keys_by_rloc_decap [ O0O0 ] = iI1iiiiiii
   return ( O0O0 )
   if 8 - 8: iIii1I11I1II1 - o0oOOo0O0Ooo
   if 68 - 68: Ii1I % o0oOOo0O0Ooo / OoooooooOO + Ii1I - Ii1I
 return ( None )
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
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 OOo0o0o = addr + ":" + str ( port )
 if 37 - 37: O0 . II111iiii
 if ( lisp_i_am_rtr ) :
  if ( addr in lisp_rloc_probe_list ) : return ( addr )
  if 56 - 56: II111iiii / oO0o + o0oOOo0O0Ooo / OOooOOo * OoO0O00
  if 29 - 29: O0
  if 43 - 43: Oo0Ooo / OoO0O00 * Oo0Ooo . IiII + I11i
  if 46 - 46: iIii1I11I1II1 % i1IIi - OoooooooOO . Ii1I
  if 91 - 91: iII111i - i11iIiiIii
  if 27 - 27: iII111i
  for iII1ii1 in list ( lisp_nat_state_info . values ( ) ) :
   for Iiii1iiI in iII1ii1 :
    if ( addr == Iiii1iiI . address ) : return ( OOo0o0o )
    if 66 - 66: O0 . iIii1I11I1II1 * II111iiii * OOooOOo * IiII
    if 44 - 44: i11iIiiIii % ooOoO0o * i11iIiiIii + Oo0Ooo + I1ii11iIi11i + Ii1I
  return ( addr )
  if 43 - 43: i1IIi . iIii1I11I1II1
 return ( OOo0o0o )
 if 86 - 86: OOooOOo + OoOoOO00 - OoO0O00 + i1IIi + iIii1I11I1II1
 if 68 - 68: OoOoOO00 . I1IiiI + ooOoO0o - o0oOOo0O0Ooo
 if 62 - 62: Ii1I - OOooOOo
 if 88 - 88: iIii1I11I1II1 * Oo0Ooo / II111iiii / IiII / OoO0O00 % ooOoO0o
 if 19 - 19: I11i * iII111i . O0 * iII111i % I1ii11iIi11i - OoOoOO00
 if 68 - 68: I1Ii111 - OoO0O00 % Ii1I + i1IIi . ooOoO0o
 if 36 - 36: oO0o * iIii1I11I1II1 - O0 - IiII * O0 + i11iIiiIii
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_MULTICAST_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 76 - 76: OoO0O00 % O0 / Ii1I + I1IiiI
 return
 if 23 - 23: I1IiiI % IiII . o0oOOo0O0Ooo
 if 2 - 2: I1ii11iIi11i
 if 51 - 51: iIii1I11I1II1 / II111iiii / iIii1I11I1II1 / oO0o % i1IIi
 if 54 - 54: ooOoO0o
 if 47 - 47: I11i * I1IiiI / oO0o
 if 98 - 98: Ii1I / oO0o * O0 + I1Ii111 - I1Ii111 + iII111i
 if 4 - 4: i1IIi
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 43 - 43: oO0o * ooOoO0o - I11i
 if 70 - 70: oO0o / Ii1I
 if 15 - 15: iIii1I11I1II1 % ooOoO0o % i11iIiiIii
 if 16 - 16: iII111i
 if 50 - 50: iIii1I11I1II1 - II111iiii % i1IIi
 if 48 - 48: O0
 if 60 - 60: ooOoO0o - IiII % i1IIi
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 5 - 5: oO0o
 if 29 - 29: i1IIi . OoOoOO00 . i1IIi + oO0o . I1Ii111 + O0
 if 62 - 62: I1ii11iIi11i . IiII + OoO0O00 - OoOoOO00 * O0 + I1Ii111
 if 58 - 58: oO0o . OoO0O00 / ooOoO0o
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
 if 52 - 52: ooOoO0o / I11i % i11iIiiIii - I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
def lisp_is_rloc_probe ( packet , rr ) :
 O0I1II1 = ( struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ] == 17 )
 if ( O0I1II1 == False ) : return ( [ packet , None , None , None ] )
 if 67 - 67: OoOoOO00 / I1Ii111 + i11iIiiIii - IiII
 oooooO0oO0ooO = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 iIII1IiI = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 o0O0O0OoO = ( socket . htons ( LISP_CTRL_PORT ) in [ oooooO0oO0ooO , iIII1IiI ] )
 if ( o0O0O0OoO == False ) : return ( [ packet , None , None , None ] )
 if 92 - 92: O0
 if ( rr == 0 ) :
  Oooooo0OOO = lisp_is_rloc_probe_request ( packet [ 28 : 29 ] )
  if ( Oooooo0OOO == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  Oooooo0OOO = lisp_is_rloc_probe_reply ( packet [ 28 : 29 ] )
  if ( Oooooo0OOO == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  Oooooo0OOO = lisp_is_rloc_probe_request ( packet [ 28 : 29 ] )
  if ( Oooooo0OOO == False ) :
   Oooooo0OOO = lisp_is_rloc_probe_reply ( packet [ 28 : 29 ] )
   if ( Oooooo0OOO == False ) : return ( [ packet , None , None , None ] )
   if 52 - 52: iII111i - i11iIiiIii + o0oOOo0O0Ooo + i1IIi
   if 58 - 58: OOooOOo - Ii1I * I1Ii111 - O0 . oO0o
   if 72 - 72: i1IIi * iII111i * Ii1I / o0oOOo0O0Ooo . I1Ii111 + i11iIiiIii
   if 33 - 33: I11i / OoO0O00 * ooOoO0o + iIii1I11I1II1
   if 54 - 54: Oo0Ooo / IiII + i11iIiiIii . O0
   if 94 - 94: OoooooooOO + iII111i * OoooooooOO / o0oOOo0O0Ooo
 O0oo0OoO0oo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 O0oo0OoO0oo . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 12 - 12: iIii1I11I1II1 / iIii1I11I1II1 / II111iiii
 if 93 - 93: oO0o
 if 53 - 53: OoO0O00 * i1IIi / Oo0Ooo / OoO0O00 * ooOoO0o
 if 77 - 77: iIii1I11I1II1 % I1IiiI + o0oOOo0O0Ooo + I1Ii111 * Oo0Ooo * i1IIi
 if ( O0oo0OoO0oo . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 14 - 14: iIii1I11I1II1 * iIii1I11I1II1 - OOooOOo . iII111i / ooOoO0o
 if 54 - 54: OoOoOO00 - I1IiiI - iII111i
 if 49 - 49: i11iIiiIii * Oo0Ooo
 if 100 - 100: Oo0Ooo * oO0o
 O0oo0OoO0oo = O0oo0OoO0oo . print_address_no_iid ( )
 ooO0 = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 O0O00O = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 85 - 85: OoooooooOO . IiII / IiII . ooOoO0o . IiII % II111iiii
 iiiI1I = bold ( "Receive(pcap)" , False )
 o0OoO0 = bold ( "from " + O0oo0OoO0oo , False )
 iIIiiIi = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( iiiI1I , len ( packet ) , o0OoO0 , ooO0 , iIIiiIi ) )
 if 65 - 65: oO0o - OoO0O00 / iII111i + ooOoO0o
 return ( [ packet , O0oo0OoO0oo , ooO0 , O0O00O ] )
 if 80 - 80: o0oOOo0O0Ooo + II111iiii * Ii1I % OoOoOO00 % I1IiiI + I1ii11iIi11i
 if 46 - 46: Oo0Ooo / Oo0Ooo % iII111i % I1IiiI
 if 85 - 85: OoO0O00 - Ii1I / O0
 if 45 - 45: IiII + I1Ii111 / I11i
 if 84 - 84: iII111i % II111iiii
 if 86 - 86: IiII % II111iiii / i1IIi * I1ii11iIi11i - O0 * OOooOOo
 if 53 - 53: OOooOOo * oO0o + i1IIi % Oo0Ooo + II111iiii
 if 34 - 34: oO0o % iII111i / IiII . IiII + i11iIiiIii
 if 68 - 68: O0 % oO0o * IiII % O0
 if 55 - 55: O0 % I1IiiI % O0
 if 27 - 27: I1IiiI + I1ii11iIi11i * I1Ii111 % Ii1I - Oo0Ooo
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 87 - 87: i11iIiiIii % OOooOOo - OoOoOO00 * ooOoO0o / Oo0Ooo
 OO = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 74 - 74: OoooooooOO * ooOoO0o - I11i / I1ii11iIi11i % iIii1I11I1II1
 lisp_write_to_dp_socket ( OO )
 return
 if 94 - 94: Ii1I * I1Ii111 + OoOoOO00 . iIii1I11I1II1
 if 44 - 44: Oo0Ooo . Oo0Ooo * Oo0Ooo
 if 23 - 23: I1Ii111 / iII111i . O0 % II111iiii
 if 67 - 67: I11i / iIii1I11I1II1 / ooOoO0o
 if 90 - 90: II111iiii % I1Ii111 - IiII . Oo0Ooo % OOooOOo - OoOoOO00
 if 89 - 89: Oo0Ooo - I1ii11iIi11i . I1Ii111
 if 65 - 65: ooOoO0o % OOooOOo + OOooOOo % I1Ii111 . I1IiiI % O0
 if 46 - 46: OoO0O00 * I1Ii111 + iII111i . oO0o % OOooOOo / i11iIiiIii
def lisp_external_data_plane ( ) :
 oO00o00 = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( getoutput ( oO00o00 ) != "" ) : return ( True )
 if 1 - 1: I1ii11iIi11i % O0 - I1ii11iIi11i / OoooooooOO / OoO0O00
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 82 - 82: i1IIi % Ii1I
 if 85 - 85: I1Ii111 * i11iIiiIii * iIii1I11I1II1 % iIii1I11I1II1
 if 64 - 64: OoO0O00 / Ii1I
 if 79 - 79: Ii1I % OOooOOo
 if 39 - 39: I1ii11iIi11i / Ii1I - II111iiii . i1IIi
 if 59 - 59: II111iiii
 if 36 - 36: ooOoO0o . II111iiii - OoOoOO00 % I1ii11iIi11i * O0
 if 91 - 91: iII111i + Oo0Ooo / OoooooooOO * iIii1I11I1II1 - OoO0O00
 if 73 - 73: iIii1I11I1II1 % I1Ii111 % II111iiii * Oo0Ooo * OoO0O00
 if 48 - 48: OOooOOo * i11iIiiIii - i11iIiiIii + iIii1I11I1II1 + I1IiiI % OoooooooOO
 if 61 - 61: i1IIi
 if 56 - 56: iIii1I11I1II1 / I11i * iII111i * I11i * OoooooooOO
 if 44 - 44: I1ii11iIi11i - OOooOOo % I11i - I1Ii111 / iIii1I11I1II1 - OOooOOo
 if 38 - 38: iIii1I11I1II1 - OoooooooOO * II111iiii . OoooooooOO + OOooOOo
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 59 - 59: OoooooooOO
 i11I1 = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 96 - 96: I11i % o0oOOo0O0Ooo + i1IIi % II111iiii
 if ( do_clear == False ) :
  OOo00O = i11I1 [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , OOo00O )
  if 96 - 96: o0oOOo0O0Ooo / i1IIi
  if 42 - 42: Oo0Ooo - Oo0Ooo % O0 - OoO0O00
 lisp_write_to_dp_socket ( i11I1 )
 return
 if 42 - 42: OoooooooOO * OOooOOo
 if 93 - 93: OOooOOo + II111iiii . oO0o * Oo0Ooo - O0 + I1Ii111
 if 99 - 99: OoO0O00 * o0oOOo0O0Ooo + OoOoOO00 * iIii1I11I1II1
 if 38 - 38: I1ii11iIi11i - OOooOOo * O0 - I1ii11iIi11i
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
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( "entries" not in msg ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 63 - 63: I1IiiI / OoooooooOO
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 16 - 16: OoOoOO00
  if 67 - 67: O0 . I1Ii111
 for msg in msg [ "entries" ] :
  if ( "eid-prefix" not in msg ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 42 - 42: OoOoOO00 % I1ii11iIi11i * I1Ii111 * i1IIi . i1IIi % OOooOOo
  i1iiii = msg [ "eid-prefix" ]
  if 90 - 90: oO0o * Oo0Ooo * oO0o . Ii1I * i1IIi
  if ( "instance-id" not in msg ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 47 - 47: OOooOOo
  oooo = int ( msg [ "instance-id" ] )
  if 38 - 38: I11i
  if 15 - 15: OoO0O00 / ooOoO0o . OoO0O00 - iIii1I11I1II1 + OoooooooOO - OoO0O00
  if 44 - 44: O0 . OOooOOo . o0oOOo0O0Ooo . I1ii11iIi11i - II111iiii
  if 71 - 71: I1ii11iIi11i + o0oOOo0O0Ooo . i11iIiiIii * oO0o . i1IIi
  o0Ooo0Oooo0o = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
  o0Ooo0Oooo0o . store_prefix ( i1iiii )
  I11iiI1III = lisp_map_cache_lookup ( None , o0Ooo0Oooo0o )
  if ( I11iiI1III == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( i1iiii ) )
   if 40 - 40: OoO0O00 - IiII
   continue
   if 43 - 43: I1Ii111 + i11iIiiIii % iII111i % I1Ii111 - ooOoO0o
   if 85 - 85: IiII % iIii1I11I1II1 . I1Ii111
  if ( "rlocs" not in msg ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( i1iiii ) )
   if 38 - 38: iII111i - I1IiiI / ooOoO0o
   continue
   if 46 - 46: OOooOOo . O0 / i11iIiiIii . OOooOOo
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 19 - 19: I11i / Oo0Ooo + I1Ii111
  iiIi111I = msg [ "rlocs" ]
  if 72 - 72: i11iIiiIii / IiII * OoOoOO00 * I11i
  if 83 - 83: IiII % OoO0O00 * II111iiii
  if 7 - 7: oO0o % Oo0Ooo
  if 88 - 88: I1Ii111
  for OoOO0OOo0OO in iiIi111I :
   if ( "rloc" not in OoOO0OOo0OO ) : continue
   if 40 - 40: i11iIiiIii . O0 * I11i - oO0o / OOooOOo . oO0o
   IIIOo0O = OoOO0OOo0OO [ "rloc" ]
   if ( IIIOo0O == "no-address" ) : continue
   if 86 - 86: OOooOOo - I1Ii111 * IiII - i1IIi + ooOoO0o + I11i
   iIIiI11 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   iIIiI11 . store_address ( IIIOo0O )
   if 32 - 32: IiII
   OOOoOoo = I11iiI1III . get_rloc ( iIIiI11 )
   if ( OOOoOoo == None ) : continue
   if 99 - 99: II111iiii
   if 34 - 34: OOooOOo + OoOoOO00 * o0oOOo0O0Ooo + I1ii11iIi11i + IiII * i1IIi
   if 73 - 73: I1ii11iIi11i - IiII - O0 . oO0o + Oo0Ooo % iII111i
   if 68 - 68: I1ii11iIi11i - OoooooooOO
   IIIiiiIi11I1 = 0 if ( "packet-count" not in OoOO0OOo0OO ) else OoOO0OOo0OO [ "packet-count" ]
   if 85 - 85: I1IiiI
   i1Ii1iiii1Ii = 0 if ( "byte-count" not in OoOO0OOo0OO ) else OoOO0OOo0OO [ "byte-count" ]
   if 97 - 97: I1ii11iIi11i - i11iIiiIii + OoOoOO00 * iIii1I11I1II1 * iIii1I11I1II1
   i1 = 0 if ( "seconds-last-packet" not in OoOO0OOo0OO ) else OoOO0OOo0OO [ "seconds-last-packet" ]
   if 51 - 51: i1IIi - O0 * I1IiiI * IiII * I11i % oO0o
   if 47 - 47: i1IIi - I11i . OoooooooOO
   OOOoOoo . stats . packet_count += IIIiiiIi11I1
   OOOoOoo . stats . byte_count += i1Ii1iiii1Ii
   OOOoOoo . stats . last_increment = lisp_get_timestamp ( ) - i1
   if 5 - 5: iII111i % Oo0Ooo - oO0o . i1IIi - i11iIiiIii % I1ii11iIi11i
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( IIIiiiIi11I1 , i1Ii1iiii1Ii ,
 i1 , i1iiii , IIIOo0O ) )
   if 79 - 79: I1IiiI
   if 24 - 24: I1IiiI / II111iiii - I1Ii111
   if 68 - 68: I1IiiI
   if 97 - 97: Ii1I + o0oOOo0O0Ooo / OoO0O00
   if 97 - 97: i11iIiiIii % iIii1I11I1II1 + II111iiii
  if ( I11iiI1III . group . is_null ( ) and I11iiI1III . has_ttl_elapsed ( ) ) :
   i1iiii = green ( I11iiI1III . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( i1iiii ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , I11iiI1III . eid , None )
   if 90 - 90: OOooOOo / I1IiiI
   if 28 - 28: OoooooooOO + i1IIi
 return
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
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 48 - 48: IiII * oO0o
 if 53 - 53: i1IIi * iIii1I11I1II1 . OOooOOo
 if 68 - 68: IiII % IiII - iII111i . IiII + OoooooooOO
 if 82 - 82: Ii1I . II111iiii / i1IIi * OoO0O00
 if 80 - 80: I11i
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  OO = "stats%{}" . format ( json . dumps ( msg ) )
  OO = lisp_command_ipc ( OO , "lisp-itr" )
  lisp_ipc ( OO , lisp_ipc_socket , "lisp-etr" )
  return
  if 96 - 96: i1IIi - I1ii11iIi11i * iII111i . OOooOOo . OoO0O00
  if 93 - 93: oO0o * Oo0Ooo * IiII
  if 26 - 26: o0oOOo0O0Ooo + O0 % i11iIiiIii . ooOoO0o . I1IiiI + Oo0Ooo
  if 90 - 90: IiII * OoooooooOO + II111iiii / iII111i + i11iIiiIii / ooOoO0o
  if 20 - 20: II111iiii % I1ii11iIi11i - OoooooooOO * Ii1I / I11i - OoooooooOO
  if 11 - 11: I1IiiI + Ii1I + i11iIiiIii * I1ii11iIi11i - oO0o
  if 46 - 46: OoooooooOO - Oo0Ooo
  if 4 - 4: II111iiii . OOooOOo - Ii1I - i11iIiiIii
 OO = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( OO , msg ) )
 if 27 - 27: iII111i * iII111i - OoO0O00 % o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 64 - 64: I1ii11iIi11i * ooOoO0o - OoooooooOO - I1IiiI
 OOO0OOo = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 67 - 67: OoooooooOO % I1IiiI + o0oOOo0O0Ooo + I1Ii111
 for III1I11i in OOO0OOo :
  IIIiiiIi11I1 = 0 if ( III1I11i not in msg ) else msg [ III1I11i ] [ "packet-count" ]
  lisp_decap_stats [ III1I11i ] . packet_count += IIIiiiIi11I1
  if 73 - 73: Ii1I
  i1Ii1iiii1Ii = 0 if ( III1I11i not in msg ) else msg [ III1I11i ] [ "byte-count" ]
  lisp_decap_stats [ III1I11i ] . byte_count += i1Ii1iiii1Ii
  if 5 - 5: OOooOOo % OoooooooOO / Oo0Ooo
  i1 = 0 if ( III1I11i not in msg ) else msg [ III1I11i ] [ "seconds-last-packet" ]
  if 16 - 16: ooOoO0o * i11iIiiIii % i1IIi % i1IIi
  lisp_decap_stats [ III1I11i ] . last_increment = lisp_get_timestamp ( ) - i1
  if 44 - 44: Oo0Ooo % I11i - o0oOOo0O0Ooo - Ii1I * Oo0Ooo - Ii1I
 return
 if 69 - 69: II111iiii + o0oOOo0O0Ooo
 if 75 - 75: OOooOOo
 if 66 - 66: Oo0Ooo % oO0o
 if 52 - 52: oO0o
 if 26 - 26: OoO0O00 % I1ii11iIi11i * O0 % OoO0O00
 if 98 - 98: OoO0O00 . ooOoO0o * I11i / i1IIi
 if 57 - 57: i11iIiiIii % OOooOOo
 if 67 - 67: oO0o - OOooOOo + II111iiii
 if 19 - 19: iIii1I11I1II1 * OoooooooOO - i11iIiiIii . I1Ii111 * OoO0O00
 if 30 - 30: iII111i + I1IiiI * ooOoO0o
 if 53 - 53: iII111i + IiII
 if 52 - 52: II111iiii * i11iIiiIii - IiII * IiII / OoooooooOO
 if 18 - 18: IiII / O0 / I1ii11iIi11i
 if 47 - 47: oO0o / iIii1I11I1II1
 if 45 - 45: OoOoOO00 * o0oOOo0O0Ooo / I1ii11iIi11i * iII111i - I1ii11iIi11i
 if 48 - 48: Ii1I / OoO0O00
 if 45 - 45: O0 * OoO0O00 / I11i . II111iiii
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 i111IIi1 , O0oo0OoO0oo = punt_socket . recvfrom ( 4000 )
 if 73 - 73: I11i
 IIII = json . loads ( i111IIi1 )
 if ( type ( IIII ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( O0oo0OoO0oo ) )
  if 95 - 95: IiII - OoOoOO00 - iIii1I11I1II1 / o0oOOo0O0Ooo
  return
  if 33 - 33: IiII / o0oOOo0O0Ooo
 O0I11iII1Ii11II = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( O0I11iII1Ii11II , O0oo0OoO0oo , IIII ) )
 if 24 - 24: iIii1I11I1II1
 if ( "type" not in IIII ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 78 - 78: ooOoO0o / i1IIi . OOooOOo * o0oOOo0O0Ooo . I1IiiI
  if 81 - 81: I11i - OoO0O00 - o0oOOo0O0Ooo
  if 95 - 95: I11i + Ii1I
  if 68 - 68: i11iIiiIii + I1IiiI / o0oOOo0O0Ooo
  if 63 - 63: I1IiiI
 if ( IIII [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( IIII , lisp_send_sockets , lisp_ephem_port )
  return
  if 20 - 20: oO0o + OoOoOO00
 if ( IIII [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( IIII , punt_socket )
  return
  if 32 - 32: o0oOOo0O0Ooo % oO0o % I1IiiI * OoooooooOO
  if 4 - 4: OOooOOo % oO0o
  if 18 - 18: Ii1I * I11i
  if 14 - 14: ooOoO0o . ooOoO0o * OoOoOO00 * o0oOOo0O0Ooo - iII111i - I1Ii111
  if 53 - 53: Oo0Ooo * OoOoOO00 * II111iiii % IiII - I1ii11iIi11i
 if ( IIII [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 56 - 56: Oo0Ooo . I1ii11iIi11i - i11iIiiIii / iIii1I11I1II1 . ooOoO0o
  if 28 - 28: OoooooooOO + I1IiiI / oO0o . iIii1I11I1II1 - oO0o
  if 64 - 64: I1Ii111 + Oo0Ooo / iII111i
  if 61 - 61: Ii1I * Ii1I . OoOoOO00 + OoO0O00 * i11iIiiIii * OoO0O00
  if 4 - 4: OoooooooOO % iII111i % Oo0Ooo * IiII % o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if ( IIII [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 66 - 66: I1IiiI . Oo0Ooo - oO0o
 if ( "interface" not in IIII ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( O0oo0OoO0oo ) )
  if 53 - 53: oO0o / Ii1I + oO0o + II111iiii
  return
  if 70 - 70: OoooooooOO - I1Ii111 + OoOoOO00
  if 61 - 61: I1IiiI * I1Ii111 * i11iIiiIii
  if 68 - 68: OoOoOO00 - iII111i - I1IiiI
  if 37 - 37: iII111i - I1Ii111 + i1IIi / o0oOOo0O0Ooo % iII111i / iII111i
  if 8 - 8: i1IIi % I11i
 ooO000OO = IIII [ "interface" ]
 if ( ooO000OO == "" ) :
  oooo = int ( IIII [ "instance-id" ] )
  if ( oooo == - 1 ) : return
 else :
  oooo = lisp_get_interface_instance_id ( ooO000OO , None )
  if 12 - 12: ooOoO0o / II111iiii + ooOoO0o * I1ii11iIi11i / i1IIi - iIii1I11I1II1
  if 71 - 71: IiII - i11iIiiIii
  if 3 - 3: i11iIiiIii - o0oOOo0O0Ooo / oO0o . OoO0O00 * I11i + o0oOOo0O0Ooo
  if 18 - 18: OoooooooOO % oO0o / IiII - ooOoO0o
  if 80 - 80: I11i
 OoiIii11i11i = None
 if ( "source-eid" in IIII ) :
  iiO0OoO0OOO00 = IIII [ "source-eid" ]
  OoiIii11i11i = lisp_address ( LISP_AFI_NONE , iiO0OoO0OOO00 , 0 , oooo )
  if ( OoiIii11i11i . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( iiO0OoO0OOO00 ) )
   return
   if 98 - 98: iII111i / I1ii11iIi11i
   if 87 - 87: iII111i - O0 * ooOoO0o / II111iiii % OoooooooOO . o0oOOo0O0Ooo
 oOOOOOo0o = None
 if ( "dest-eid" in IIII ) :
  O00OooOOO = IIII [ "dest-eid" ]
  oOOOOOo0o = lisp_address ( LISP_AFI_NONE , O00OooOOO , 0 , oooo )
  if ( oOOOOOo0o . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( O00OooOOO ) )
   return
   if 94 - 94: i11iIiiIii
   if 76 - 76: II111iiii / ooOoO0o % i11iIiiIii * OoooooooOO * I1ii11iIi11i
   if 94 - 94: OoOoOO00 * o0oOOo0O0Ooo / oO0o + O0 . I1Ii111 + o0oOOo0O0Ooo
   if 22 - 22: IiII / ooOoO0o * i1IIi
   if 26 - 26: O0 - oO0o
   if 30 - 30: OoO0O00 / ooOoO0o . I1IiiI
   if 70 - 70: I1ii11iIi11i
   if 35 - 35: i1IIi - OoooooooOO * Ii1I / OOooOOo % I11i
 if ( OoiIii11i11i ) :
  oO0ooOOO = green ( OoiIii11i11i . print_address ( ) , False )
  OoO0oO = lisp_db_for_lookups . lookup_cache ( OoiIii11i11i , False )
  if ( OoO0oO != None ) :
   if 72 - 72: I1Ii111 / OoO0O00 + II111iiii
   if 40 - 40: Ii1I + O0 . i11iIiiIii % I11i / Oo0Ooo
   if 25 - 25: IiII * IiII
   if 54 - 54: I1Ii111
   if 90 - 90: Oo0Ooo / Ii1I
   if ( OoO0oO . dynamic_eid_configured ( ) ) :
    i111IIiIiiI1 = lisp_allow_dynamic_eid ( ooO000OO , OoiIii11i11i )
    if ( i111IIiIiiI1 != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( OoO0oO , OoiIii11i11i , ooO000OO , i111IIiIiiI1 )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( oO0ooOOO , ooO000OO ) )
     if 66 - 66: i11iIiiIii - I11i + oO0o . OoooooooOO
     if 77 - 77: OoO0O00 / OOooOOo
     if 97 - 97: OoOoOO00 / Ii1I * I1IiiI - Oo0Ooo % O0
  else :
   lprint ( "Punt from non-EID source {}" . format ( oO0ooOOO ) )
   if 66 - 66: O0 + I1IiiI % iIii1I11I1II1 . i1IIi % II111iiii - i1IIi
   if 93 - 93: O0 + OoooooooOO % IiII % oO0o % I1ii11iIi11i
   if 36 - 36: I1IiiI - oO0o * Oo0Ooo + oO0o % iII111i - i11iIiiIii
   if 93 - 93: O0
   if 11 - 11: OoooooooOO . I1ii11iIi11i + I1ii11iIi11i
   if 73 - 73: OoooooooOO
 if ( oOOOOOo0o ) :
  I11iiI1III = lisp_map_cache_lookup ( OoiIii11i11i , oOOOOOo0o )
  if ( I11iiI1III == None or lisp_mr_or_pubsub ( I11iiI1III . action ) ) :
   if 2 - 2: o0oOOo0O0Ooo % IiII + I1ii11iIi11i - i11iIiiIii
   if 100 - 100: II111iiii + oO0o
   if 85 - 85: I1ii11iIi11i % I1ii11iIi11i . Ii1I
   if 42 - 42: oO0o + OoO0O00
   if 16 - 16: Ii1I
   if ( lisp_rate_limit_map_request ( oOOOOOo0o ) ) : return
   if 67 - 67: I1ii11iIi11i . OoooooooOO * I1Ii111 + Ii1I * OOooOOo
   iIiI1IIi1Ii1i = ( I11iiI1III and I11iiI1III . action == LISP_SEND_PUBSUB_ACTION )
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 OoiIii11i11i , oOOOOOo0o , None , iIiI1IIi1Ii1i )
  else :
   oO0ooOOO = green ( oOOOOOo0o . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( oO0ooOOO ) )
   if 84 - 84: OOooOOo
   if 78 - 78: O0 % O0
 return
 if 72 - 72: o0oOOo0O0Ooo * IiII / II111iiii / iIii1I11I1II1
 if 41 - 41: iII111i / Ii1I
 if 11 - 11: Oo0Ooo % OOooOOo . ooOoO0o
 if 24 - 24: IiII / Oo0Ooo
 if 90 - 90: ooOoO0o . OOooOOo - Ii1I
 if 60 - 60: i11iIiiIii % iII111i . I1IiiI * I1ii11iIi11i
 if 30 - 30: Ii1I + i11iIiiIii . I11i + o0oOOo0O0Ooo - OoO0O00
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 oo0O00OOOOO = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( oo0O00OOOOO )
 return ( [ True , jdata ] )
 if 55 - 55: ooOoO0o - II111iiii . ooOoO0o . iII111i / OoooooooOO
 if 51 - 51: I1IiiI * I1Ii111 - ooOoO0o + IiII
 if 22 - 22: OoOoOO00 % Ii1I + iII111i
 if 64 - 64: ooOoO0o
 if 87 - 87: IiII - Ii1I / Oo0Ooo / I1ii11iIi11i . iII111i
 if 49 - 49: IiII * OoooooooOO * iIii1I11I1II1 * Oo0Ooo / iII111i % oO0o
 if 88 - 88: I1Ii111 * OOooOOo
 if 38 - 38: Oo0Ooo - OoooooooOO - OoooooooOO / II111iiii
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 10 - 10: II111iiii - OoO0O00 / II111iiii % Ii1I - OoOoOO00
 if 90 - 90: I11i + II111iiii - oO0o - ooOoO0o / ooOoO0o / i11iIiiIii
 if 80 - 80: I1ii11iIi11i % O0 / II111iiii + iII111i
 if 22 - 22: Oo0Ooo + ooOoO0o . OOooOOo % Oo0Ooo . IiII
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 34 - 34: Ii1I . OoOoOO00 - OOooOOo * Oo0Ooo - ooOoO0o . oO0o
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 42 - 42: O0 + OoO0O00
 if 47 - 47: O0 % OoOoOO00 + Ii1I * iIii1I11I1II1
 if 55 - 55: Ii1I
 if 93 - 93: iII111i + OOooOOo . OoooooooOO . I1Ii111 . O0
 if 46 - 46: i11iIiiIii
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 26 - 26: I11i * Oo0Ooo % OoO0O00 + Oo0Ooo - I1ii11iIi11i
 if 74 - 74: i1IIi + OoO0O00 . II111iiii + I1Ii111
 if 59 - 59: Ii1I . i11iIiiIii . o0oOOo0O0Ooo * iIii1I11I1II1 . OoOoOO00 . II111iiii
 if 67 - 67: OoO0O00 - Oo0Ooo + OOooOOo / OoOoOO00 + OOooOOo
 if 18 - 18: Oo0Ooo % OoOoOO00 % i1IIi
 if 66 - 66: OoOoOO00 % II111iiii
 if 16 - 16: i11iIiiIii - I1IiiI + ooOoO0o * oO0o
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 i1iiii = eid . print_address ( )
 if ( i1iiii in db . dynamic_eids ) :
  db . dynamic_eids [ i1iiii ] . last_packet = lisp_get_timestamp ( )
  return
  if 30 - 30: II111iiii / o0oOOo0O0Ooo
  if 57 - 57: I11i / I1ii11iIi11i . I11i
  if 68 - 68: OoOoOO00 + O0 . I1IiiI
  if 26 - 26: I1ii11iIi11i
  if 98 - 98: Oo0Ooo
 IIIII1IIiIi = lisp_dynamic_eid ( )
 IIIII1IIiIi . dynamic_eid . copy_address ( eid )
 IIIII1IIiIi . interface = routed_interface
 IIIII1IIiIi . last_packet = lisp_get_timestamp ( )
 IIIII1IIiIi . get_timeout ( routed_interface )
 db . dynamic_eids [ i1iiii ] = IIIII1IIiIi
 if 72 - 72: oO0o + OoooooooOO . O0 + IiII
 IiIiIii1I = ""
 if ( input_interface != routed_interface ) :
  IiIiIii1I = ", routed-interface " + routed_interface
  if 34 - 34: I1ii11iIi11i * i11iIiiIii
  if 6 - 6: I1ii11iIi11i + I1IiiI / OoooooooOO % I11i * Oo0Ooo
 i1i111 = green ( i1iiii , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( i1i111 , input_interface , IiIiIii1I , IIIII1IIiIi . timeout ) )
 if 54 - 54: IiII % iIii1I11I1II1 . OoO0O00
 if 47 - 47: OoooooooOO / ooOoO0o / I1Ii111
 if 58 - 58: IiII * IiII / I11i . iIii1I11I1II1
 if 73 - 73: OoooooooOO + OoooooooOO + o0oOOo0O0Ooo / IiII . ooOoO0o
 if 72 - 72: ooOoO0o . I1ii11iIi11i . Oo0Ooo - IiII
 OO = "learn%{}%{}" . format ( i1iiii , routed_interface )
 OO = lisp_command_ipc ( OO , "lisp-itr" )
 lisp_ipc ( OO , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 35 - 35: IiII
 if 36 - 36: I1Ii111 . o0oOOo0O0Ooo / IiII + OOooOOo
 if 11 - 11: II111iiii / i11iIiiIii + i1IIi . OoooooooOO * I1IiiI . II111iiii
 if 21 - 21: Ii1I . O0 . IiII + I11i
 if 86 - 86: OoOoOO00
 if 36 - 36: ooOoO0o * OoOoOO00 * OoooooooOO
 if 22 - 22: OoOoOO00 + I1ii11iIi11i * iIii1I11I1II1 + iIii1I11I1II1
 if 100 - 100: iII111i - ooOoO0o + I11i - oO0o * i1IIi
 if 62 - 62: OoO0O00 / OoOoOO00 * OoOoOO00
 if 83 - 83: oO0o * o0oOOo0O0Ooo
 if 25 - 25: o0oOOo0O0Ooo % Oo0Ooo . Oo0Ooo + OoO0O00
 if 23 - 23: I11i + I1ii11iIi11i * iIii1I11I1II1 - i1IIi
 if 33 - 33: I1IiiI + o0oOOo0O0Ooo . OoOoOO00
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 35 - 35: iII111i / Ii1I
 if 57 - 57: ooOoO0o . I1IiiI * OOooOOo
 if 87 - 87: I11i - I11i % iII111i - Ii1I
 if 29 - 29: oO0o - ooOoO0o * iIii1I11I1II1 / OoOoOO00
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 34 - 34: I1IiiI . Oo0Ooo
 O0oOoO00O = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 4 - 4: Ii1I - II111iiii * iII111i / oO0o - I1IiiI
 for III in lisp_crypto_keys_by_rloc_decap :
  if 32 - 32: iIii1I11I1II1 - I11i
  if 49 - 49: I11i * I1Ii111 - iIii1I11I1II1 * O0
  if 72 - 72: I1IiiI * iII111i
  if 61 - 61: Ii1I * Oo0Ooo * I1Ii111 % I11i + iII111i % oO0o
  if ( III . find ( addr_str ) == - 1 ) : continue
  if 67 - 67: IiII
  if 90 - 90: o0oOOo0O0Ooo
  if 5 - 5: i1IIi
  if 55 - 55: Ii1I
  if ( III == addr_str ) : continue
  if 46 - 46: OOooOOo / iII111i . i1IIi . i11iIiiIii . iIii1I11I1II1 % I11i
  if 62 - 62: I11i % II111iiii % OoooooooOO * ooOoO0o / oO0o
  if 29 - 29: o0oOOo0O0Ooo / O0 / OoO0O00
  if 23 - 23: Ii1I + i11iIiiIii % IiII
  oo0O00OOOOO = lisp_crypto_keys_by_rloc_decap [ III ]
  if ( oo0O00OOOOO == O0oOoO00O ) : continue
  if 64 - 64: i11iIiiIii + OoooooooOO . oO0o * Ii1I
  if 49 - 49: O0
  if 72 - 72: I1Ii111
  if 96 - 96: II111iiii / OOooOOo % i1IIi / Oo0Ooo
  ii1iI1iI11 = oo0O00OOOOO [ 1 ]
  if ( packet_icv != ii1iI1iI11 . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( III , False ) ) )
   continue
   if 61 - 61: oO0o . I1Ii111
   if 74 - 74: O0 . Ii1I - iII111i % IiII + II111iiii
  lprint ( "Changing decap crypto key to {}" . format ( red ( III , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = oo0O00OOOOO
  if 71 - 71: oO0o + Ii1I % oO0o
 return
 if 17 - 17: I1Ii111 % I1Ii111 * o0oOOo0O0Ooo
 if 84 - 84: I1Ii111 + iII111i . i1IIi / O0 / I1Ii111 + o0oOOo0O0Ooo
 if 70 - 70: O0 % ooOoO0o - iII111i + oO0o
 if 12 - 12: I1Ii111 - OoO0O00 % II111iiii % ooOoO0o / II111iiii % OoOoOO00
 if 74 - 74: iII111i . OOooOOo * Ii1I / Oo0Ooo . OoO0O00 . I11i
 if 65 - 65: i11iIiiIii - OoO0O00 / OoooooooOO * I1IiiI % iII111i
 if 15 - 15: OOooOOo * Ii1I / ooOoO0o
 if 70 - 70: i11iIiiIii * oO0o . I11i - OoooooooOO / I1ii11iIi11i
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 10 - 10: IiII * OoOoOO00 . II111iiii . II111iiii * Oo0Ooo
 if 23 - 23: I1ii11iIi11i + I11i
 if 74 - 74: i1IIi % I1IiiI
 if 44 - 44: Oo0Ooo - OoooooooOO % ooOoO0o + II111iiii
 if 60 - 60: o0oOOo0O0Ooo - ooOoO0o + i11iIiiIii % I1ii11iIi11i % II111iiii
 if 62 - 62: Ii1I
 if 30 - 30: iII111i % O0 + II111iiii * I1IiiI
 if 91 - 91: i11iIiiIii
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 ooO0o = dns_name . split ( "." )
 ooO0o = "." . join ( ooO0o [ 1 : : ] )
 return ( ooO0o == lisp_decent_dns_suffix )
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
def lisp_get_decent_index ( eid ) :
 i1iiii = eid . print_prefix ( )
 Iii1 = hmac . new ( b"lisp-decent" , i1iiii , hashlib . sha256 ) . hexdigest ( )
 if 32 - 32: ooOoO0o / OOooOOo + Oo0Ooo + II111iiii
 if 91 - 91: O0
 if 64 - 64: I1Ii111 - II111iiii + oO0o % ooOoO0o * oO0o
 if 27 - 27: iIii1I11I1II1 - Ii1I . i11iIiiIii / IiII . I1Ii111 / i11iIiiIii
 iIiooOOo0OOoOO0O = os . getenv ( "LISP_DECENT_HASH_WIDTH" )
 if ( iIiooOOo0OOoOO0O in [ "" , None ] ) :
  iIiooOOo0OOoOO0O = 12
 else :
  iIiooOOo0OOoOO0O = int ( iIiooOOo0OOoOO0O )
  if ( iIiooOOo0OOoOO0O > 32 ) :
   iIiooOOo0OOoOO0O = 12
  else :
   iIiooOOo0OOoOO0O *= 2
   if 74 - 74: OoO0O00 . iII111i / OoO0O00 + Oo0Ooo
   if 21 - 21: I1IiiI . II111iiii % iIii1I11I1II1
   if 81 - 81: Oo0Ooo + i11iIiiIii
 oOoOO = Iii1 [ 0 : iIiooOOo0OOoOO0O ]
 OOOooo0OooOoO = int ( oOoOO , 16 ) % lisp_decent_modulus
 if 9 - 9: I1ii11iIi11i / OoOoOO00 * o0oOOo0O0Ooo * I11i * Oo0Ooo / o0oOOo0O0Ooo
 lprint ( "LISP-Decent modulus {}, hash-width {}, mod-value {}, index {}" . format ( lisp_decent_modulus , old_div ( iIiooOOo0OOoOO0O , 2 ) , oOoOO , OOOooo0OooOoO ) )
 if 67 - 67: i1IIi % OoooooooOO - Oo0Ooo . I1IiiI + i1IIi . Ii1I
 if 98 - 98: o0oOOo0O0Ooo - OoooooooOO - OoooooooOO + OoOoOO00 - Oo0Ooo % ooOoO0o
 return ( OOOooo0OooOoO )
 if 54 - 54: Ii1I * I1ii11iIi11i * OoooooooOO + II111iiii / ooOoO0o
 if 11 - 11: OoooooooOO * ooOoO0o / II111iiii * oO0o / OoOoOO00 . iIii1I11I1II1
 if 9 - 9: iII111i
 if 13 - 13: IiII - Oo0Ooo
 if 94 - 94: I11i - iIii1I11I1II1 + oO0o
 if 72 - 72: i1IIi . OoO0O00
 if 95 - 95: OoOoOO00 + Ii1I
def lisp_get_decent_dns_name ( eid ) :
 OOOooo0OooOoO = lisp_get_decent_index ( eid )
 return ( str ( OOOooo0OooOoO ) + "." + lisp_decent_dns_suffix )
 if 48 - 48: Ii1I % IiII + OoO0O00 . IiII
 if 42 - 42: Ii1I
 if 70 - 70: I11i
 if 82 - 82: O0
 if 58 - 58: II111iiii . O0 - OoO0O00 - IiII
 if 4 - 4: i11iIiiIii + i11iIiiIii / O0
 if 46 - 46: I11i % ooOoO0o - Ii1I
 if 25 - 25: O0 / i11iIiiIii . O0
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 o0Ooo0Oooo0o = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 OOOooo0OooOoO = lisp_get_decent_index ( o0Ooo0Oooo0o )
 return ( str ( OOOooo0OooOoO ) + "." + lisp_decent_dns_suffix )
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
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 48 - 48: I1ii11iIi11i . i1IIi % i1IIi - iII111i * o0oOOo0O0Ooo + IiII
 oo00 = 28 if packet . inner_version == 4 else 48
 IiiIi1I = packet . packet [ oo00 : : ]
 o0oo0oOoo0 = lisp_trace ( )
 if ( o0oo0oOoo0 . decode ( IiiIi1I ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 42 - 42: OoooooooOO / ooOoO0o % II111iiii - ooOoO0o
  if 15 - 15: II111iiii + I1IiiI
 IIIiii = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 53 - 53: Ii1I . iIii1I11I1II1
 if 49 - 49: I11i % OoO0O00 * I1IiiI + I1IiiI . iII111i . II111iiii
 if 60 - 60: OoOoOO00
 if 71 - 71: O0 * OOooOOo . I1IiiI . I1Ii111 * I11i
 if 45 - 45: O0 . O0 . II111iiii * ooOoO0o
 if 2 - 2: OoO0O00 . o0oOOo0O0Ooo
 if ( IIIiii != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : IIIiii += ":{}" . format ( packet . encap_port )
  if 48 - 48: Ii1I
  if 45 - 45: I1ii11iIi11i - I11i + Ii1I
  if 82 - 82: iII111i
  if 81 - 81: i1IIi % OOooOOo - OoO0O00 - Oo0Ooo
  if 19 - 19: i1IIi
 oo0O00OOOOO = { }
 oo0O00OOOOO [ "n" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 97 - 97: OoO0O00 + i11iIiiIii % I1IiiI * Ii1I
 O0OooOoOoo0 = packet . outer_source
 if ( O0OooOoOoo0 . is_null ( ) ) : O0OooOoOoo0 = lisp_myrlocs [ 0 ]
 oo0O00OOOOO [ "sr" ] = O0OooOoOoo0 . print_address_no_iid ( )
 if 11 - 11: ooOoO0o - I1Ii111 - I11i + OoOoOO00
 if 20 - 20: I11i + O0
 if 27 - 27: Oo0Ooo
 if 12 - 12: I1ii11iIi11i . iII111i - iII111i - OOooOOo - iIii1I11I1II1
 if 50 - 50: I1IiiI - iIii1I11I1II1 . iII111i - Ii1I / I1Ii111 + iII111i
 if ( oo0O00OOOOO [ "n" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  oo0O00OOOOO [ "sr" ] += ":{}" . format ( packet . inner_sport )
  if 46 - 46: OOooOOo + iII111i % Oo0Ooo * iII111i % OoooooooOO * IiII
  if 27 - 27: I1IiiI + I1IiiI + I1ii11iIi11i - oO0o * OOooOOo
 oo0O00OOOOO [ "hn" ] = lisp_hostname
 III = ed [ 0 ] + "ts"
 oo0O00OOOOO [ III ] = lisp_get_timestamp ( )
 if 53 - 53: I1ii11iIi11i / OoooooooOO * iIii1I11I1II1
 if 4 - 4: I1IiiI . iIii1I11I1II1 + OOooOOo / IiII . o0oOOo0O0Ooo . I11i
 if 52 - 52: ooOoO0o % i11iIiiIii . IiII + OoO0O00
 if 66 - 66: II111iiii . Ii1I
 if 42 - 42: iIii1I11I1II1 * iII111i * I1IiiI
 if 66 - 66: Oo0Ooo * i1IIi / I1ii11iIi11i / OoO0O00
 if ( IIIiii == "?" and oo0O00OOOOO [ "n" ] == "ETR" ) :
  OoO0oO = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( OoO0oO != None and len ( OoO0oO . rloc_set ) >= 1 ) :
   IIIiii = OoO0oO . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 12 - 12: OOooOOo + iIii1I11I1II1 % I1Ii111 + OOooOOo
   if 19 - 19: OoO0O00 / I1IiiI - o0oOOo0O0Ooo - i1IIi + I1ii11iIi11i * OoooooooOO
 oo0O00OOOOO [ "dr" ] = IIIiii
 if 74 - 74: I1Ii111 . I11i / Oo0Ooo
 if 88 - 88: oO0o % OoO0O00 - i11iIiiIii % I1Ii111 / O0 * IiII
 if 99 - 99: o0oOOo0O0Ooo . ooOoO0o / i11iIiiIii
 if 44 - 44: IiII + OOooOOo % OoO0O00 . OoooooooOO * O0
 if ( IIIiii == "?" and reason != None ) :
  oo0O00OOOOO [ "dr" ] += " ({})" . format ( reason )
  if 72 - 72: i1IIi - iII111i * I1IiiI % O0 - I11i * O0
  if 78 - 78: I1IiiI - OoO0O00 / Ii1I . i1IIi
  if 30 - 30: IiII
  if 21 - 21: i1IIi . iII111i - I1IiiI
  if 28 - 28: IiII / Ii1I - i1IIi - OoOoOO00
 if ( rloc_entry != None ) :
  oo0O00OOOOO [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  oo0O00OOOOO [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  oo0O00OOOOO [ "lats" ] = rloc_entry . recent_rloc_probe_latencies
  if 65 - 65: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo
  if 77 - 77: OoooooooOO - Oo0Ooo - OoOoOO00 / I11i / O0 . i11iIiiIii
  if 27 - 27: I1Ii111 * O0
  if 9 - 9: i1IIi - Oo0Ooo - i11iIiiIii / iIii1I11I1II1 . i1IIi
  if 2 - 2: I11i + II111iiii - I11i / oO0o / I11i
  if 73 - 73: IiII % I1Ii111 . OoOoOO00
 OoiIii11i11i = packet . inner_source . print_address ( )
 oOOOOOo0o = packet . inner_dest . print_address ( )
 if ( o0oo0oOoo0 . packet_json == [ ] ) :
  o0OO0ooooO = { }
  o0OO0ooooO [ "se" ] = OoiIii11i11i
  o0OO0ooooO [ "de" ] = oOOOOOo0o
  o0OO0ooooO [ "paths" ] = [ ]
  o0oo0oOoo0 . packet_json . append ( o0OO0ooooO )
  if 96 - 96: I1IiiI / ooOoO0o / iIii1I11I1II1
  if 91 - 91: Ii1I . I11i
  if 87 - 87: Oo0Ooo / IiII * OOooOOo + I1ii11iIi11i . I11i
  if 56 - 56: oO0o + oO0o % o0oOOo0O0Ooo + OOooOOo . II111iiii + i11iIiiIii
  if 45 - 45: iIii1I11I1II1 / o0oOOo0O0Ooo * OoooooooOO - Oo0Ooo
  if 77 - 77: II111iiii
 for o0OO0ooooO in o0oo0oOoo0 . packet_json :
  if ( o0OO0ooooO [ "de" ] != oOOOOOo0o ) : continue
  o0OO0ooooO [ "paths" ] . append ( oo0O00OOOOO )
  break
  if 8 - 8: I1IiiI * II111iiii % I1ii11iIi11i
  if 88 - 88: Oo0Ooo . oO0o + OoOoOO00 % OoooooooOO
  if 81 - 81: OoooooooOO . I1Ii111 + OoO0O00 % I1Ii111
  if 49 - 49: oO0o . oO0o % oO0o / Oo0Ooo
  if 62 - 62: ooOoO0o . i1IIi % OoO0O00 - I1ii11iIi11i - IiII
  if 57 - 57: i1IIi - II111iiii - O0 . iII111i + OoO0O00
  if 67 - 67: OOooOOo * iII111i / iIii1I11I1II1 / I1ii11iIi11i
  if 10 - 10: OoooooooOO % I1ii11iIi11i * i1IIi . iII111i
 ooOoO000oO = False
 if ( len ( o0oo0oOoo0 . packet_json ) == 1 and oo0O00OOOOO [ "n" ] == "ETR" and
 o0oo0oOoo0 . myeid ( packet . inner_dest ) ) :
  o0OO0ooooO = { }
  o0OO0ooooO [ "se" ] = oOOOOOo0o
  o0OO0ooooO [ "de" ] = OoiIii11i11i
  o0OO0ooooO [ "paths" ] = [ ]
  o0oo0oOoo0 . packet_json . append ( o0OO0ooooO )
  ooOoO000oO = True
  if 13 - 13: i1IIi * Oo0Ooo % i11iIiiIii % I11i / II111iiii - Ii1I
  if 71 - 71: OoOoOO00 % ooOoO0o
  if 36 - 36: Ii1I * oO0o / oO0o % I1IiiI % I1IiiI + I1IiiI
  if 41 - 41: OoooooooOO . O0 % OOooOOo
  if 88 - 88: O0
  if 44 - 44: II111iiii - IiII / I1IiiI + ooOoO0o % iII111i - iII111i
 o0oo0oOoo0 . print_trace ( )
 IiiIi1I = o0oo0oOoo0 . encode ( )
 if 53 - 53: OoooooooOO
 if 41 - 41: i1IIi - oO0o
 if 41 - 41: I11i
 if 92 - 92: i11iIiiIii
 if 62 - 62: i1IIi / I1IiiI - o0oOOo0O0Ooo
 if 3 - 3: O0 * OoOoOO00 * I11i / OoOoOO00
 if 77 - 77: i1IIi
 if 3 - 3: iII111i * OoO0O00 - oO0o + iII111i . o0oOOo0O0Ooo + I1IiiI
 ooO0oii = o0oo0oOoo0 . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "sr" ]
 if ( IIIiii == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( ooO0oii ) )
  o0oo0oOoo0 . return_to_sender ( lisp_socket , ooO0oii , IiiIi1I )
  return ( False )
  if 35 - 35: OoOoOO00
  if 61 - 61: I1Ii111
  if 78 - 78: I1Ii111 * Ii1I % Ii1I + I1IiiI
  if 83 - 83: iIii1I11I1II1 + O0 / IiII . iIii1I11I1II1
  if 74 - 74: Oo0Ooo
  if 60 - 60: OoooooooOO
 Ooo000O00 = o0oo0oOoo0 . packet_length ( )
 if 16 - 16: iIii1I11I1II1 - OoOoOO00 / I1ii11iIi11i % O0 % o0oOOo0O0Ooo
 if 99 - 99: ooOoO0o . o0oOOo0O0Ooo - O0 * I1Ii111 . i11iIiiIii / iIii1I11I1II1
 if 40 - 40: iIii1I11I1II1 + oO0o / iIii1I11I1II1 - i1IIi % OoO0O00
 if 22 - 22: OOooOOo
 if 65 - 65: i1IIi - oO0o . I1Ii111 . ooOoO0o % I1ii11iIi11i % I1ii11iIi11i
 if 1 - 1: I1Ii111 + I1Ii111
 O0OOOO = packet . packet [ 0 : oo00 ]
 iIIiiIi = struct . pack ( "HH" , socket . htons ( Ooo000O00 ) , 0 )
 O0OOOO = O0OOOO [ 0 : oo00 - 4 ] + iIIiiIi
 if ( packet . inner_version == 6 and oo0O00OOOOO [ "n" ] == "ETR" and
 len ( o0oo0oOoo0 . packet_json ) == 2 ) :
  O0I1II1 = O0OOOO [ oo00 - 8 : : ] + IiiIi1I
  O0I1II1 = lisp_udp_checksum ( OoiIii11i11i , oOOOOOo0o , O0I1II1 )
  O0OOOO = O0OOOO [ 0 : oo00 - 8 ] + O0I1II1 [ 0 : 8 ]
  if 77 - 77: OoooooooOO
  if 10 - 10: I11i
  if 22 - 22: Oo0Ooo . O0 / i1IIi - OoOoOO00
  if 41 - 41: II111iiii - I1ii11iIi11i - I1Ii111
  if 82 - 82: I1IiiI * I1IiiI / iIii1I11I1II1
  if 14 - 14: I11i + Ii1I - OOooOOo % Ii1I / Ii1I
  if 86 - 86: I1Ii111 - i11iIiiIii + Ii1I + I11i
  if 96 - 96: Ii1I
  if 28 - 28: i1IIi . oO0o . IiII + Oo0Ooo . Oo0Ooo . i1IIi
 if ( ooOoO000oO ) :
  if ( packet . inner_version == 4 ) :
   O0OOOO = O0OOOO [ 0 : 12 ] + O0OOOO [ 16 : 20 ] + O0OOOO [ 12 : 16 ] + O0OOOO [ 22 : 24 ] + O0OOOO [ 20 : 22 ] + O0OOOO [ 24 : : ]
   if 34 - 34: Oo0Ooo + IiII / i1IIi
  else :
   O0OOOO = O0OOOO [ 0 : 8 ] + O0OOOO [ 24 : 40 ] + O0OOOO [ 8 : 24 ] + O0OOOO [ 42 : 44 ] + O0OOOO [ 40 : 42 ] + O0OOOO [ 44 : : ]
   if 33 - 33: i1IIi
   if 26 - 26: ooOoO0o - Oo0Ooo * II111iiii - Oo0Ooo
  IiI11I111 = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = IiI11I111
  if 15 - 15: OoO0O00 - oO0o . OoOoOO00 / O0 * oO0o
  if 45 - 45: O0
  if 89 - 89: IiII - IiII % o0oOOo0O0Ooo * Oo0Ooo % ooOoO0o
  if 4 - 4: OoO0O00 % II111iiii / I11i
  if 95 - 95: I1Ii111 - I1Ii111 - iII111i + IiII . OoO0O00
  if 5 - 5: i11iIiiIii - O0 % ooOoO0o
  if 55 - 55: II111iiii
 oo00 = 2 if packet . inner_version == 4 else 4
 I1iIiI11iiI = 20 + Ooo000O00 if packet . inner_version == 4 else Ooo000O00
 iiI1 = struct . pack ( "H" , socket . htons ( I1iIiI11iiI ) )
 O0OOOO = O0OOOO [ 0 : oo00 ] + iiI1 + O0OOOO [ oo00 + 2 : : ]
 if 88 - 88: i11iIiiIii / oO0o - i1IIi / I1IiiI
 if 57 - 57: oO0o + O0 * I11i
 if 87 - 87: o0oOOo0O0Ooo % Oo0Ooo * I1ii11iIi11i / OoooooooOO / o0oOOo0O0Ooo
 if 78 - 78: Ii1I
 if ( packet . inner_version == 4 ) :
  I1i11i = struct . pack ( "H" , 0 )
  O0OOOO = O0OOOO [ 0 : 10 ] + I1i11i + O0OOOO [ 12 : : ]
  iiI1 = lisp_ip_checksum ( O0OOOO [ 0 : 20 ] )
  O0OOOO = iiI1 + O0OOOO [ 20 : : ]
  if 5 - 5: i1IIi * ooOoO0o / OoOoOO00 % i11iIiiIii
  if 57 - 57: IiII
  if 89 - 89: I1ii11iIi11i - I1Ii111 + o0oOOo0O0Ooo
  if 62 - 62: I1ii11iIi11i + OoooooooOO * OOooOOo
  if 49 - 49: i1IIi - I11i * II111iiii
 packet . packet = O0OOOO + IiiIi1I
 return ( True )
 if 4 - 4: o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 57 - 57: I1IiiI * OOooOOo . i11iIiiIii * oO0o - OoOoOO00
 if 35 - 35: O0
 if 65 - 65: Oo0Ooo
 if 100 - 100: I1Ii111 . o0oOOo0O0Ooo * OoooooooOO . o0oOOo0O0Ooo
 if 90 - 90: i11iIiiIii . I1IiiI + ooOoO0o * OoooooooOO * OoooooooOO + oO0o
 if 77 - 77: OOooOOo * OoOoOO00
 if 75 - 75: Oo0Ooo * Oo0Ooo - IiII - OoOoOO00 / i11iIiiIii + I1Ii111
 if 57 - 57: i11iIiiIii / oO0o
 if 37 - 37: o0oOOo0O0Ooo + OoOoOO00 - i1IIi . Oo0Ooo
def lisp_allow_gleaning ( eid , group , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False , False )
 if 3 - 3: ooOoO0o % OoooooooOO / I1Ii111 + oO0o - O0
 for oo0O00OOOOO in lisp_glean_mappings :
  if ( "instance-id" in oo0O00OOOOO ) :
   oooo = eid . instance_id
   I1iO00O , i1iiI11 = oo0O00OOOOO [ "instance-id" ]
   if ( oooo < I1iO00O or oooo > i1iiI11 ) : continue
   if 72 - 72: oO0o * OoO0O00
  if ( "eid-prefix" in oo0O00OOOOO ) :
   oO0ooOOO = copy . deepcopy ( oo0O00OOOOO [ "eid-prefix" ] )
   oO0ooOOO . instance_id = eid . instance_id
   if ( eid . is_more_specific ( oO0ooOOO ) == False ) : continue
   if 89 - 89: OoooooooOO . OOooOOo
  if ( "group-prefix" in oo0O00OOOOO ) :
   if ( group == None ) : continue
   Oo = copy . deepcopy ( oo0O00OOOOO [ "group-prefix" ] )
   Oo . instance_id = group . instance_id
   if ( group . is_more_specific ( Oo ) == False ) : continue
   if 96 - 96: o0oOOo0O0Ooo + OoOoOO00 / i11iIiiIii - o0oOOo0O0Ooo * i11iIiiIii + OOooOOo
  if ( "rloc-prefix" in oo0O00OOOOO ) :
   if ( rloc != None and rloc . is_more_specific ( oo0O00OOOOO [ "rloc-prefix" ] )
 == False ) : continue
   if 16 - 16: IiII / I1Ii111 . II111iiii * I11i
  return ( True , oo0O00OOOOO [ "rloc-probe" ] , oo0O00OOOOO [ "igmp-query" ] )
  if 33 - 33: I1ii11iIi11i / Oo0Ooo % i11iIiiIii
 return ( False , False , False )
 if 37 - 37: Oo0Ooo - I1Ii111 - IiII / oO0o % I1IiiI / I1Ii111
 if 80 - 80: iII111i - oO0o % i1IIi * iIii1I11I1II1 . oO0o
 if 86 - 86: Ii1I
 if 36 - 36: i11iIiiIii % i11iIiiIii
 if 91 - 91: Oo0Ooo + I1Ii111 % iII111i
 if 7 - 7: I1Ii111 + II111iiii
 if 63 - 63: OoO0O00 - o0oOOo0O0Ooo / iII111i % II111iiii * IiII
def lisp_build_gleaned_multicast ( seid , geid , rloc , port , igmp ) :
 IIiI11I1I1i1i = geid . print_address ( )
 ooooooo0O0oo = seid . print_address_no_iid ( )
 I111 = green ( "{}" . format ( ooooooo0O0oo ) , False )
 oO0ooOOO = green ( "(*, {})" . format ( IIiI11I1I1i1i ) , False )
 iiiI1I = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 if 15 - 15: oO0o % OoooooooOO % Ii1I + i1IIi
 if 98 - 98: OoO0O00 - i11iIiiIii / O0 / I1IiiI
 if 99 - 99: I1IiiI / oO0o . OoO0O00 / ooOoO0o + IiII
 if 3 - 3: II111iiii . OOooOOo * i11iIiiIii / I11i
 I11iiI1III = lisp_map_cache_lookup ( seid , geid )
 if ( I11iiI1III == None ) :
  I11iiI1III = lisp_mapping ( "" , "" , [ ] )
  I11iiI1III . group . copy_address ( geid )
  I11iiI1III . eid . copy_address ( geid )
  I11iiI1III . eid . address = 0
  I11iiI1III . eid . mask_len = 0
  I11iiI1III . mapping_source . copy_address ( rloc )
  I11iiI1III . map_cache_ttl = LISP_IGMP_TTL
  I11iiI1III . gleaned = True
  I11iiI1III . add_cache ( )
  lprint ( "Add gleaned EID {} to map-cache" . format ( oO0ooOOO ) )
  if 16 - 16: I1ii11iIi11i - ooOoO0o + OoO0O00 . I11i / O0
  if 56 - 56: I1IiiI + Oo0Ooo * II111iiii + iIii1I11I1II1
  if 56 - 56: o0oOOo0O0Ooo * I1IiiI - I11i * I1Ii111 - I11i
  if 92 - 92: oO0o % iIii1I11I1II1 * o0oOOo0O0Ooo * OoooooooOO - iIii1I11I1II1
  if 51 - 51: Ii1I - OoO0O00 + i1IIi
  if 11 - 11: II111iiii - iII111i + oO0o % Oo0Ooo
 OOOoOoo = o0oOOO0o0o0o = iIIi = None
 if ( I11iiI1III . rloc_set != [ ] ) :
  OOOoOoo = I11iiI1III . rloc_set [ 0 ]
  if ( OOOoOoo . rle ) :
   o0oOOO0o0o0o = OOOoOoo . rle
   for i1Ii1ii in o0oOOO0o0o0o . rle_nodes :
    if ( i1Ii1ii . rloc_name != ooooooo0O0oo ) : continue
    iIIi = i1Ii1ii
    break
    if 24 - 24: oO0o % OoooooooOO % OoOoOO00 * i11iIiiIii
    if 65 - 65: O0 % O0 . II111iiii * i11iIiiIii
    if 39 - 39: II111iiii + Ii1I
    if 60 - 60: I1ii11iIi11i * O0 * OoOoOO00 * i1IIi
    if 6 - 6: OoOoOO00
    if 7 - 7: i1IIi + II111iiii
    if 96 - 96: I1Ii111 / OoO0O00
 if ( OOOoOoo == None ) :
  OOOoOoo = lisp_rloc ( )
  I11iiI1III . rloc_set = [ OOOoOoo ]
  OOOoOoo . priority = 253
  OOOoOoo . mpriority = 255
  I11iiI1III . build_best_rloc_set ( )
  if 27 - 27: Ii1I
 if ( o0oOOO0o0o0o == None ) :
  o0oOOO0o0o0o = lisp_rle ( geid . print_address ( ) )
  OOOoOoo . rle = o0oOOO0o0o0o
  if 90 - 90: I1ii11iIi11i
 if ( iIIi == None ) :
  iIIi = lisp_rle_node ( )
  iIIi . rloc_name = ooooooo0O0oo
  o0oOOO0o0o0o . rle_nodes . append ( iIIi )
  o0oOOO0o0o0o . build_forwarding_list ( )
  lprint ( "Add RLE {} from {} for gleaned EID {}" . format ( iiiI1I , I111 , oO0ooOOO ) )
 elif ( rloc . is_exact_match ( iIIi . address ) == False or
 port != iIIi . translated_port ) :
  lprint ( "Changed RLE {} from {} for gleaned EID {}" . format ( iiiI1I , I111 , oO0ooOOO ) )
  if 43 - 43: OoO0O00 . I1IiiI . oO0o + Ii1I
  if 7 - 7: iII111i / Oo0Ooo - OoO0O00 + I1Ii111 * II111iiii * ooOoO0o
  if 80 - 80: oO0o - i1IIi / I11i . II111iiii % O0 % I11i
  if 70 - 70: iIii1I11I1II1 * i1IIi * OOooOOo - Oo0Ooo % i1IIi
  if 60 - 60: o0oOOo0O0Ooo . OOooOOo % II111iiii - I1ii11iIi11i
 iIIi . store_translated_rloc ( rloc , port )
 if 4 - 4: OOooOOo % ooOoO0o
 if 39 - 39: Ii1I
 if 67 - 67: iIii1I11I1II1 - OOooOOo
 if 47 - 47: OOooOOo - OOooOOo * I1Ii111
 if 24 - 24: I1ii11iIi11i
 if ( igmp ) :
  IiIiI11111i1i = seid . print_address ( )
  if ( IiIiI11111i1i not in lisp_gleaned_groups ) :
   lisp_gleaned_groups [ IiIiI11111i1i ] = { }
   if 37 - 37: II111iiii - iIii1I11I1II1 / o0oOOo0O0Ooo . O0 + II111iiii
  lisp_gleaned_groups [ IiIiI11111i1i ] [ IIiI11I1I1i1i ] = lisp_get_timestamp ( )
  if 9 - 9: o0oOOo0O0Ooo
  if 47 - 47: Ii1I * I1Ii111 / II111iiii
  if 73 - 73: ooOoO0o
  if 53 - 53: IiII . Oo0Ooo
  if 54 - 54: i11iIiiIii % ooOoO0o % I1Ii111 + o0oOOo0O0Ooo
  if 2 - 2: IiII
  if 25 - 25: OoOoOO00 . OoO0O00 * o0oOOo0O0Ooo . OoooooooOO - Oo0Ooo + I1IiiI
  if 82 - 82: OoO0O00 - Ii1I * I11i * o0oOOo0O0Ooo
def lisp_remove_gleaned_multicast ( seid , geid ) :
 if 17 - 17: OoooooooOO + I1Ii111
 if 91 - 91: iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo
 if 98 - 98: o0oOOo0O0Ooo % II111iiii * IiII - i11iIiiIii * oO0o
 if 15 - 15: O0 - II111iiii - Oo0Ooo . I1ii11iIi11i % OoO0O00
 I11iiI1III = lisp_map_cache_lookup ( seid , geid )
 if ( I11iiI1III == None ) : return
 if 63 - 63: o0oOOo0O0Ooo / OoOoOO00 % I1ii11iIi11i % I11i
 ooo0o0O = I11iiI1III . rloc_set [ 0 ] . rle
 if ( ooo0o0O == None ) : return
 if 58 - 58: O0 + iII111i
 oOo = seid . print_address_no_iid ( )
 III11i1 = False
 for iIIi in ooo0o0O . rle_nodes :
  if ( iIIi . rloc_name == oOo ) :
   III11i1 = True
   break
   if 66 - 66: i1IIi . O0 . i1IIi - iIii1I11I1II1 - ooOoO0o % I1ii11iIi11i
   if 96 - 96: i1IIi + oO0o - OoOoOO00 - OoOoOO00
 if ( III11i1 == False ) : return
 if 13 - 13: I11i
 if 52 - 52: iII111i . OoOoOO00 * iIii1I11I1II1 . iII111i * IiII
 if 52 - 52: iII111i + iII111i
 if 35 - 35: I1Ii111 * oO0o + Ii1I / I1IiiI + O0 - I11i
 ooo0o0O . rle_nodes . remove ( iIIi )
 ooo0o0O . build_forwarding_list ( )
 if 42 - 42: o0oOOo0O0Ooo
 IIiI11I1I1i1i = geid . print_address ( )
 IiIiI11111i1i = seid . print_address ( )
 I111 = green ( "{}" . format ( IiIiI11111i1i ) , False )
 oO0ooOOO = green ( "(*, {})" . format ( IIiI11I1I1i1i ) , False )
 lprint ( "Gleaned EID {} RLE removed for {}" . format ( oO0ooOOO , I111 ) )
 if 89 - 89: o0oOOo0O0Ooo
 if 99 - 99: I1ii11iIi11i + Oo0Ooo
 if 20 - 20: OoO0O00 / iII111i
 if 62 - 62: i1IIi % iIii1I11I1II1 + OoOoOO00 - I1IiiI . I1ii11iIi11i
 if ( IiIiI11111i1i in lisp_gleaned_groups ) :
  if ( IIiI11I1I1i1i in lisp_gleaned_groups [ IiIiI11111i1i ] ) :
   lisp_gleaned_groups [ IiIiI11111i1i ] . pop ( IIiI11I1I1i1i )
   if 92 - 92: i11iIiiIii * o0oOOo0O0Ooo . Oo0Ooo
   if 15 - 15: o0oOOo0O0Ooo * IiII . iII111i % O0 . iIii1I11I1II1
   if 34 - 34: OOooOOo / iII111i * iIii1I11I1II1 + i11iIiiIii
   if 37 - 37: I11i + o0oOOo0O0Ooo . o0oOOo0O0Ooo
   if 8 - 8: Oo0Ooo * Ii1I % I11i - OoooooooOO
   if 11 - 11: OoO0O00 - oO0o
 if ( ooo0o0O . rle_nodes == [ ] ) :
  I11iiI1III . delete_cache ( )
  lprint ( "Gleaned EID {} remove, no more RLEs" . format ( oO0ooOOO ) )
  if 50 - 50: II111iiii * IiII
  if 26 - 26: OoO0O00 . II111iiii
  if 19 - 19: iII111i / i11iIiiIii
  if 31 - 31: I1Ii111 / I1Ii111 % IiII
  if 68 - 68: O0 / OOooOOo % OoOoOO00
  if 68 - 68: OoooooooOO - IiII + I1IiiI * IiII / I11i - OoO0O00
  if 69 - 69: oO0o / II111iiii
  if 56 - 56: i1IIi + II111iiii + Ii1I . OoooooooOO
def lisp_change_gleaned_multicast ( seid , rloc , port ) :
 IiIiI11111i1i = seid . print_address ( )
 if ( IiIiI11111i1i not in lisp_gleaned_groups ) : return
 if 26 - 26: OoooooooOO % Ii1I % I11i * oO0o - i1IIi - i1IIi
 for oo0oOooo0O in lisp_gleaned_groups [ IiIiI11111i1i ] :
  lisp_geid . store_address ( oo0oOooo0O )
  lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , port , False )
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
  if 17 - 17: o0oOOo0O0Ooo . OoO0O00 * ooOoO0o * II111iiii - OoooooooOO % iII111i
  if 47 - 47: I1IiiI * iIii1I11I1II1 - I11i - o0oOOo0O0Ooo
  if 47 - 47: IiII + OoO0O00 % ooOoO0o - iII111i - IiII - oO0o
  if 63 - 63: OoooooooOO / I1Ii111
  if 90 - 90: I1Ii111 . i11iIiiIii - iIii1I11I1II1 + I1Ii111
  if 67 - 67: IiII - I1ii11iIi11i + ooOoO0o . iIii1I11I1II1 . IiII
  if 13 - 13: I1IiiI / i11iIiiIii % iIii1I11I1II1 - Oo0Ooo . i11iIiiIii + I1IiiI
  if 77 - 77: o0oOOo0O0Ooo / II111iiii + i11iIiiIii % Ii1I . iIii1I11I1II1
  if 66 - 66: iII111i / oO0o - OoO0O00 . Oo0Ooo
  if 31 - 31: IiII % O0
  if 46 - 46: iIii1I11I1II1 - OoooooooOO . oO0o % iIii1I11I1II1 / i1IIi + Ii1I
  if 5 - 5: I1ii11iIi11i % II111iiii
  if 17 - 17: i11iIiiIii - II111iiii / O0 % OoO0O00 . Oo0Ooo + IiII
  if 60 - 60: I11i % I1IiiI
  if 99 - 99: oO0o . OOooOOo % iII111i * Ii1I
  if 98 - 98: Oo0Ooo * O0 + i1IIi
  if 41 - 41: i1IIi % OoO0O00 * iIii1I11I1II1
  if 2 - 2: I1ii11iIi11i * iII111i . iIii1I11I1II1 * Oo0Ooo
  if 34 - 34: i11iIiiIii % O0 . I1IiiI / ooOoO0o + OoO0O00
  if 28 - 28: Ii1I / iIii1I11I1II1
  if 41 - 41: iIii1I11I1II1
  if 57 - 57: I1Ii111 * o0oOOo0O0Ooo - o0oOOo0O0Ooo * I11i
  if 89 - 89: Ii1I % O0
  if 81 - 81: OoooooooOO / II111iiii - ooOoO0o
  if 14 - 14: O0
  if 59 - 59: I11i % II111iiii . iIii1I11I1II1 * oO0o % Ii1I
  if 79 - 79: OoooooooOO . II111iiii
  if 55 - 55: II111iiii
  if 2 - 2: I1ii11iIi11i * i1IIi + OOooOOo / OoO0O00 % OoOoOO00 / O0
  if 47 - 47: OoooooooOO - i11iIiiIii - IiII * O0 * iII111i * Ii1I
  if 36 - 36: I1Ii111
  if 85 - 85: Oo0Ooo % OOooOOo
  if 10 - 10: O0 + Oo0Ooo + Ii1I % IiII
  if 89 - 89: oO0o / iII111i + OOooOOo
  if 27 - 27: Ii1I / o0oOOo0O0Ooo % I11i
  if 96 - 96: i11iIiiIii % O0
  if 11 - 11: II111iiii . i11iIiiIii % ooOoO0o * Ii1I * OoOoOO00 * OoooooooOO
  if 80 - 80: OoO0O00
  if 55 - 55: iIii1I11I1II1 % OoO0O00 / II111iiii - OoO0O00
  if 95 - 95: o0oOOo0O0Ooo / OOooOOo * OOooOOo * O0
  if 93 - 93: OOooOOo / ooOoO0o
  if 89 - 89: OoooooooOO + iIii1I11I1II1 / I1ii11iIi11i % iIii1I11I1II1 / iII111i
  if 74 - 74: Ii1I + I1IiiI * iII111i / i11iIiiIii - ooOoO0o * OoooooooOO
  if 98 - 98: I1IiiI
  if 85 - 85: OoooooooOO * i1IIi * O0 * OoooooooOO . IiII
  if 22 - 22: ooOoO0o
igmp_types = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 44 - 44: I1ii11iIi11i + IiII + IiII * I1ii11iIi11i - OoooooooOO / I1Ii111
lisp_igmp_record_types = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 3 - 3: I1ii11iIi11i + o0oOOo0O0Ooo * I11i / Oo0Ooo
def lisp_process_igmp_packet ( packet ) :
 O0oo0OoO0oo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 O0oo0OoO0oo . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 O0oo0OoO0oo = bold ( "from {}" . format ( O0oo0OoO0oo . print_address_no_iid ( ) ) , False )
 if 31 - 31: i11iIiiIii % OoO0O00 - oO0o / o0oOOo0O0Ooo % O0
 iiiI1I = bold ( "Receive" , False )
 lprint ( "{} {}-byte {}, IGMP packet: {}" . format ( iiiI1I , len ( packet ) , O0oo0OoO0oo ,
 lisp_format_packet ( packet ) ) )
 if 53 - 53: iIii1I11I1II1 * I1ii11iIi11i
 if 46 - 46: OOooOOo % OoOoOO00 * iII111i
 if 55 - 55: I1IiiI * iIii1I11I1II1 . OoOoOO00
 if 82 - 82: iIii1I11I1II1 - iII111i % I1IiiI + I1IiiI * i1IIi % O0
 ooOOoO = ( struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ] & 0x0f ) * 4
 if 95 - 95: OoO0O00 * ooOoO0o * oO0o % Oo0Ooo
 if 36 - 36: I1IiiI - Ii1I + oO0o . iIii1I11I1II1
 if 47 - 47: Ii1I
 if 12 - 12: I1IiiI / IiII + OoOoOO00 . I1Ii111 / I1Ii111
 OOo00OoO = packet [ ooOOoO : : ]
 oooo00O00oOo = struct . unpack ( "B" , OOo00OoO [ 0 : 1 ] ) [ 0 ]
 if 31 - 31: O0 % OoO0O00 % O0 + iII111i - iIii1I11I1II1
 if 71 - 71: I1IiiI / Ii1I + IiII * OoooooooOO
 if 39 - 39: OoO0O00
 if 60 - 60: iII111i . iII111i - ooOoO0o / i1IIi
 if 68 - 68: oO0o + I11i + Oo0Ooo / OOooOOo . II111iiii - iIii1I11I1II1
 oo0oOooo0O = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 oo0oOooo0O . address = socket . ntohl ( struct . unpack ( "II" , OOo00OoO [ : 8 ] ) [ 1 ] )
 IIiI11I1I1i1i = oo0oOooo0O . print_address_no_iid ( )
 if 81 - 81: I1ii11iIi11i
 if ( oooo00O00oOo == 17 ) :
  lprint ( "IGMP Query for group {}" . format ( IIiI11I1I1i1i ) )
  return ( True )
  if 39 - 39: II111iiii
  if 60 - 60: OoOoOO00 % Oo0Ooo
 IiIi1i = ( oooo00O00oOo in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( IiIi1i == False ) :
  o0oIIi1i = "{} ({})" . format ( oooo00O00oOo , igmp_types [ oooo00O00oOo ] ) if ( oooo00O00oOo in igmp_types ) else oooo00O00oOo
  if 81 - 81: O0 . iII111i
  lprint ( "IGMP type {} not supported" . format ( o0oIIi1i ) )
  return ( [ ] )
  if 27 - 27: OoooooooOO . i1IIi + OoO0O00 + IiII % ooOoO0o
  if 88 - 88: OoooooooOO
 if ( len ( OOo00OoO ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 22 - 22: OoOoOO00 / i1IIi - i1IIi - Oo0Ooo - O0 / IiII
  if 11 - 11: oO0o + oO0o . Ii1I . OoooooooOO * i1IIi - I1IiiI
  if 69 - 69: I1Ii111 * ooOoO0o * II111iiii * i11iIiiIii
  if 88 - 88: oO0o - o0oOOo0O0Ooo * i11iIiiIii % OoO0O00
  if 62 - 62: OoOoOO00 / iII111i
 if ( oooo00O00oOo == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( IIiI11I1I1i1i , False ) ) )
  return ( [ [ None , IIiI11I1I1i1i , False ] ] )
  if 70 - 70: IiII / O0 - i1IIi
 if ( oooo00O00oOo in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( oooo00O00oOo == 0x12 ) else 2 , bold ( IIiI11I1I1i1i , False ) ) )
  if 23 - 23: OoOoOO00
  if 2 - 2: II111iiii * OoOoOO00 . iIii1I11I1II1 . ooOoO0o . ooOoO0o + iII111i
  if 60 - 60: I1ii11iIi11i / I1ii11iIi11i
  if 44 - 44: i11iIiiIii / ooOoO0o - iIii1I11I1II1 + OoO0O00
  if 62 - 62: i1IIi / I1Ii111 + ooOoO0o
  if ( IIiI11I1I1i1i . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
  else :
   return ( [ [ None , IIiI11I1I1i1i , True ] ] )
   if 80 - 80: iII111i + OoO0O00 % OoO0O00
   if 4 - 4: OoOoOO00 * I11i * O0 . OoooooooOO + Ii1I % i1IIi
   if 11 - 11: OoOoOO00 % i11iIiiIii . OoOoOO00 % Oo0Ooo * Ii1I
   if 67 - 67: IiII - OoOoOO00 / I1Ii111 % oO0o % OOooOOo
   if 19 - 19: OoO0O00 - iII111i
  return ( [ ] )
  if 76 - 76: OoOoOO00 * ooOoO0o - iII111i * I1IiiI + I11i
  if 4 - 4: Oo0Ooo
  if 95 - 95: Oo0Ooo * i11iIiiIii - O0
  if 100 - 100: iIii1I11I1II1 / I1ii11iIi11i - o0oOOo0O0Ooo / iII111i
  if 73 - 73: OoooooooOO
 oo0OOo00OOoO = oo0oOooo0O . address
 OOo00OoO = OOo00OoO [ 8 : : ]
 if 68 - 68: II111iiii / i11iIiiIii % i11iIiiIii % OoooooooOO
 Ooooo0o = "BBHI"
 IiiIIIIiI1 = struct . calcsize ( Ooooo0o )
 IiII1i = "I"
 o00iiI1i1 = struct . calcsize ( IiII1i )
 O0oo0OoO0oo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 21 - 21: II111iiii - o0oOOo0O0Ooo * OoO0O00 . OOooOOo
 if 65 - 65: o0oOOo0O0Ooo + I1IiiI
 if 21 - 21: I1Ii111
 if 74 - 74: iII111i
 OoOiI1I = [ ]
 for iIi1iIIIiIiI in range ( oo0OOo00OOoO ) :
  if ( len ( OOo00OoO ) < IiiIIIIiI1 ) : return
  o0ooO0oooO0 , Oo0OoO00O , I1Iiii11iiI , I1IIIi = struct . unpack ( Ooooo0o ,
 OOo00OoO [ : IiiIIIIiI1 ] )
  if 28 - 28: OoooooooOO
  OOo00OoO = OOo00OoO [ IiiIIIIiI1 : : ]
  if 45 - 45: ooOoO0o / I1ii11iIi11i . Ii1I - iIii1I11I1II1 . OoooooooOO
  if ( o0ooO0oooO0 not in lisp_igmp_record_types ) :
   lprint ( "Invalid record type {}" . format ( o0ooO0oooO0 ) )
   continue
   if 80 - 80: I11i % I1Ii111 - OOooOOo . I11i + I1Ii111
   if 9 - 9: II111iiii - i11iIiiIii . i11iIiiIii % I1ii11iIi11i
  o00oOO00oO = lisp_igmp_record_types [ o0ooO0oooO0 ]
  I1Iiii11iiI = socket . ntohs ( I1Iiii11iiI )
  oo0oOooo0O . address = socket . ntohl ( I1IIIi )
  IIiI11I1I1i1i = oo0oOooo0O . print_address_no_iid ( )
  if 88 - 88: OoOoOO00 . O0
  lprint ( "Record type: {}, group: {}, source-count: {}" . format ( o00oOO00oO , IIiI11I1I1i1i , I1Iiii11iiI ) )
  if 47 - 47: I1Ii111 * iIii1I11I1II1 % OoO0O00
  if 48 - 48: i11iIiiIii
  if 15 - 15: oO0o - OoO0O00 . I1ii11iIi11i * oO0o / OoOoOO00
  if 89 - 89: OoO0O00 / oO0o % I11i - I1ii11iIi11i . o0oOOo0O0Ooo
  if 46 - 46: i11iIiiIii
  if 99 - 99: i11iIiiIii / oO0o / OoOoOO00 / O0 * I1ii11iIi11i
  if 72 - 72: ooOoO0o - I1Ii111 - iIii1I11I1II1 . I1IiiI
  oOOOOoOo00OoO = False
  if ( o0ooO0oooO0 in ( 1 , 5 ) ) : oOOOOoOo00OoO = True
  if ( o0ooO0oooO0 in ( 2 , 4 ) and I1Iiii11iiI == 0 ) : oOOOOoOo00OoO = True
  OoO0oOOo = "join" if ( oOOOOoOo00OoO ) else "leave"
  if 50 - 50: OoooooooOO . o0oOOo0O0Ooo . IiII . OOooOOo * I1ii11iIi11i
  if 67 - 67: I11i % IiII + O0 + iIii1I11I1II1 % OoooooooOO / ooOoO0o
  if 80 - 80: OOooOOo - i11iIiiIii . OoooooooOO % OoO0O00 + OoO0O00
  if 24 - 24: Ii1I . OOooOOo . IiII / Oo0Ooo . Oo0Ooo . II111iiii
  if ( IIiI11I1I1i1i . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   continue
   if 63 - 63: ooOoO0o . I11i
   if 39 - 39: II111iiii % oO0o % I1IiiI - iIii1I11I1II1 / I1IiiI
   if 94 - 94: iII111i + oO0o
   if 43 - 43: iIii1I11I1II1 + iIii1I11I1II1
   if 8 - 8: iIii1I11I1II1
   if 30 - 30: OOooOOo - I1ii11iIi11i * iIii1I11I1II1 + Oo0Ooo
   if 25 - 25: IiII
   if 78 - 78: OoOoOO00 * iIii1I11I1II1 * ooOoO0o - OoooooooOO - IiII
  if ( I1Iiii11iiI == 0 ) :
   OoOiI1I . append ( [ None , IIiI11I1I1i1i , oOOOOoOo00OoO ] )
   lprint ( "IGMPv3 {} (*, {})" . format ( bold ( OoO0oOOo , False ) ,
 bold ( IIiI11I1I1i1i , False ) ) )
   if 40 - 40: OoO0O00 . i11iIiiIii + ooOoO0o
   if 30 - 30: OOooOOo . OoO0O00 % iII111i - OoO0O00 % i11iIiiIii
   if 28 - 28: Ii1I + Oo0Ooo / iIii1I11I1II1
   if 57 - 57: o0oOOo0O0Ooo
   if 23 - 23: II111iiii
  for I1I1II1iI in range ( I1Iiii11iiI ) :
   if ( len ( OOo00OoO ) < o00iiI1i1 ) : return
   I1IIIi = struct . unpack ( IiII1i , OOo00OoO [ : o00iiI1i1 ] ) [ 0 ]
   O0oo0OoO0oo . address = socket . ntohl ( I1IIIi )
   Oo0o = O0oo0OoO0oo . print_address_no_iid ( )
   OoOiI1I . append ( [ Oo0o , IIiI11I1I1i1i , oOOOOoOo00OoO ] )
   lprint ( "{} ({}, {})" . format ( OoO0oOOo ,
 green ( Oo0o , False ) , bold ( IIiI11I1I1i1i , False ) ) )
   OOo00OoO = OOo00OoO [ o00iiI1i1 : : ]
   if 53 - 53: oO0o
   if 62 - 62: O0 + O0 . Oo0Ooo + iIii1I11I1II1 + iII111i
   if 97 - 97: oO0o - iIii1I11I1II1
   if 61 - 61: II111iiii / OOooOOo - oO0o
   if 19 - 19: O0
   if 60 - 60: I1ii11iIi11i * I1ii11iIi11i + I1Ii111 + o0oOOo0O0Ooo - OoO0O00
   if 75 - 75: o0oOOo0O0Ooo + i11iIiiIii % I1ii11iIi11i
   if 45 - 45: I1Ii111 % Ii1I . ooOoO0o
 return ( OoOiI1I )
 if 99 - 99: I11i - OoOoOO00 % I11i / i1IIi
 if 55 - 55: o0oOOo0O0Ooo / ooOoO0o % I1IiiI / I1Ii111
 if 30 - 30: I11i % OoOoOO00 * O0
 if 32 - 32: iII111i - Oo0Ooo / Oo0Ooo + o0oOOo0O0Ooo + Ii1I + IiII
 if 100 - 100: Oo0Ooo + o0oOOo0O0Ooo % Oo0Ooo
 if 73 - 73: o0oOOo0O0Ooo + Ii1I
 if 62 - 62: OOooOOo
 if 91 - 91: iII111i . Ii1I - OoooooooOO / Ii1I / II111iiii - O0
lisp_geid = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
if 67 - 67: oO0o * i11iIiiIii / I1ii11iIi11i . I11i % OOooOOo
def lisp_glean_map_cache ( seid , rloc , encap_port , igmp ) :
 if 75 - 75: ooOoO0o - OOooOOo
 if 97 - 97: i11iIiiIii / I11i % II111iiii
 if 20 - 20: I1Ii111 + OoooooooOO . o0oOOo0O0Ooo - ooOoO0o
 if 61 - 61: i11iIiiIii + OoooooooOO
 if 7 - 7: I1IiiI * OoO0O00 * I1IiiI
 if 50 - 50: I1ii11iIi11i
 oOOOOO00O0oo = True
 I11iiI1III = lisp_map_cache . lookup_cache ( seid , True )
 if ( I11iiI1III and len ( I11iiI1III . rloc_set ) != 0 ) :
  I11iiI1III . last_refresh_time = lisp_get_timestamp ( )
  if 92 - 92: I1ii11iIi11i * o0oOOo0O0Ooo - OoooooooOO * OOooOOo . IiII - o0oOOo0O0Ooo
  Iiii1111iIIii = I11iiI1III . rloc_set [ 0 ]
  Ii1i1 = Iiii1111iIIii . rloc
  OO0O00Ii1iIiIi11 = Iiii1111iIIii . translated_port
  oOOOOO00O0oo = ( Ii1i1 . is_exact_match ( rloc ) == False or
 OO0O00Ii1iIiIi11 != encap_port )
  if 35 - 35: i1IIi
  if ( oOOOOO00O0oo ) :
   oO0ooOOO = green ( seid . print_address ( ) , False )
   iiiI1I = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
   lprint ( "Change gleaned EID {} to RLOC {}" . format ( oO0ooOOO , iiiI1I ) )
   Iiii1111iIIii . delete_from_rloc_probe_list ( I11iiI1III . eid , I11iiI1III . group )
   lisp_change_gleaned_multicast ( seid , rloc , encap_port )
   if 58 - 58: Ii1I - IiII / ooOoO0o % o0oOOo0O0Ooo + I1ii11iIi11i
 else :
  I11iiI1III = lisp_mapping ( "" , "" , [ ] )
  I11iiI1III . eid . copy_address ( seid )
  I11iiI1III . mapping_source . copy_address ( rloc )
  I11iiI1III . map_cache_ttl = LISP_GLEAN_TTL
  I11iiI1III . gleaned = True
  oO0ooOOO = green ( seid . print_address ( ) , False )
  iiiI1I = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( oO0ooOOO , iiiI1I ) )
  I11iiI1III . add_cache ( )
  if 89 - 89: IiII / OoooooooOO
  if 13 - 13: II111iiii . OOooOOo - O0 * oO0o
  if 71 - 71: ooOoO0o % ooOoO0o + o0oOOo0O0Ooo + iII111i / OoOoOO00
  if 27 - 27: I1ii11iIi11i * OoO0O00 - OoO0O00
  if 87 - 87: I1IiiI * I11i + iIii1I11I1II1 % i1IIi
 if ( oOOOOO00O0oo ) :
  OOOoOoo = lisp_rloc ( )
  OOOoOoo . store_translated_rloc ( rloc , encap_port )
  OOOoOoo . add_to_rloc_probe_list ( I11iiI1III . eid , I11iiI1III . group )
  OOOoOoo . priority = 253
  OOOoOoo . mpriority = 255
  OO00O000OOO = [ OOOoOoo ]
  I11iiI1III . rloc_set = OO00O000OOO
  I11iiI1III . build_best_rloc_set ( )
  if 6 - 6: o0oOOo0O0Ooo
  if 94 - 94: I1ii11iIi11i * i11iIiiIii
  if 95 - 95: OoooooooOO - II111iiii . I1Ii111
  if 97 - 97: i1IIi * iIii1I11I1II1
  if 44 - 44: O0 - o0oOOo0O0Ooo - I1Ii111 % O0
 if ( igmp == None ) : return
 if 31 - 31: i11iIiiIii - I11i
 if 91 - 91: I11i - iII111i
 if 35 - 35: I1IiiI * I11i + I11i
 if 67 - 67: I1ii11iIi11i - I1IiiI + Ii1I * Ii1I + Oo0Ooo
 if 41 - 41: i11iIiiIii
 lisp_geid . instance_id = seid . instance_id
 if 97 - 97: i1IIi / Ii1I / ooOoO0o . Ii1I - ooOoO0o + oO0o
 if 27 - 27: OOooOOo % O0
 if 96 - 96: OoooooooOO / OOooOOo
 if 87 - 87: IiII - OoooooooOO
 if 53 - 53: OoOoOO00 + Oo0Ooo
 OOo00O = lisp_process_igmp_packet ( igmp )
 if ( type ( OOo00O ) == bool ) : return
 if 33 - 33: I11i - OOooOOo + Oo0Ooo - iII111i * iII111i
 for O0oo0OoO0oo , oo0oOooo0O , oOOOOoOo00OoO in OOo00O :
  if ( O0oo0OoO0oo != None ) : continue
  if 44 - 44: Oo0Ooo % OoOoOO00 / oO0o
  if 34 - 34: II111iiii + Ii1I + OoOoOO00
  if 9 - 9: I11i / oO0o * OoO0O00
  if 26 - 26: I1IiiI % OOooOOo * OoOoOO00
  lisp_geid . store_address ( oo0oOooo0O )
  iIiI1III , Oo0OoO00O , ii1I1I1iII = lisp_allow_gleaning ( seid , lisp_geid , rloc )
  if ( iIiI1III == False ) : continue
  if 14 - 14: I11i * Oo0Ooo . I1Ii111 * Ii1I . i11iIiiIii * I1ii11iIi11i
  if ( oOOOOoOo00OoO ) :
   lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port ,
 True )
  else :
   lisp_remove_gleaned_multicast ( seid , lisp_geid )
   if 11 - 11: oO0o + oO0o + o0oOOo0O0Ooo / iIii1I11I1II1 / I11i
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
def lisp_is_json_telemetry ( json_string ) :
 try :
  IiI111i1iI1 = json . loads ( json_string )
  if ( type ( IiI111i1iI1 ) != dict ) : return ( None )
 except :
  lprint ( "Could not decode telemetry json: {}" . format ( json_string ) )
  return ( None )
  if 24 - 24: I1Ii111 / OoOoOO00
  if 10 - 10: I11i . OoO0O00 / O0 / oO0o / o0oOOo0O0Ooo / ooOoO0o
 if ( "type" not in IiI111i1iI1 ) : return ( None )
 if ( "sub-type" not in IiI111i1iI1 ) : return ( None )
 if ( IiI111i1iI1 [ "type" ] != "telemetry" ) : return ( None )
 if ( IiI111i1iI1 [ "sub-type" ] != "timestamps" ) : return ( None )
 return ( IiI111i1iI1 )
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
def lisp_encode_telemetry ( json_string , ii = "?" , io = "?" , ei = "?" , eo = "?" ) :
 IiI111i1iI1 = lisp_is_json_telemetry ( json_string )
 if ( IiI111i1iI1 == None ) : return ( json_string )
 if 21 - 21: I11i / IiII + i1IIi . Oo0Ooo % II111iiii
 if ( IiI111i1iI1 [ "itr-in" ] == "?" ) : IiI111i1iI1 [ "itr-in" ] = ii
 if ( IiI111i1iI1 [ "itr-out" ] == "?" ) : IiI111i1iI1 [ "itr-out" ] = io
 if ( IiI111i1iI1 [ "etr-in" ] == "?" ) : IiI111i1iI1 [ "etr-in" ] = ei
 if ( IiI111i1iI1 [ "etr-out" ] == "?" ) : IiI111i1iI1 [ "etr-out" ] = eo
 json_string = json . dumps ( IiI111i1iI1 )
 return ( json_string )
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
def lisp_decode_telemetry ( json_string ) :
 IiI111i1iI1 = lisp_is_json_telemetry ( json_string )
 if ( IiI111i1iI1 == None ) : return ( { } )
 return ( IiI111i1iI1 )
 if 27 - 27: i1IIi * i11iIiiIii - OoOoOO00 * Ii1I . IiII + iII111i
 if 25 - 25: I1ii11iIi11i % o0oOOo0O0Ooo - OoO0O00
 if 28 - 28: oO0o
 if 8 - 8: I11i / OoooooooOO % OoooooooOO . Oo0Ooo
 if 30 - 30: iII111i
 if 25 - 25: I11i % i1IIi + OOooOOo * Ii1I . i1IIi
 if 81 - 81: I11i % OoOoOO00 . Ii1I
 if 82 - 82: i1IIi / II111iiii
 if 40 - 40: II111iiii - I1Ii111 + Oo0Ooo / IiII
def lisp_telemetry_configured ( ) :
 if ( "telemetry" not in lisp_json_list ) : return ( None )
 if 15 - 15: I1Ii111 + ooOoO0o / II111iiii . OoOoOO00 - I1Ii111
 OoOo00OO0o00 = lisp_json_list [ "telemetry" ] . json_string
 if ( lisp_is_json_telemetry ( OoOo00OO0o00 ) == None ) : return ( None )
 if 59 - 59: Ii1I * iIii1I11I1II1 - iIii1I11I1II1 % I1Ii111 - OoO0O00 / I1IiiI
 return ( OoOo00OO0o00 )
 if 89 - 89: I1Ii111 . OoO0O00
 if 52 - 52: OoO0O00 - iIii1I11I1II1
 if 52 - 52: OOooOOo + I1IiiI * Ii1I % OoooooooOO / I1Ii111
 if 74 - 74: iIii1I11I1II1
 if 82 - 82: OOooOOo
 if 64 - 64: II111iiii
 if 48 - 48: iII111i + i11iIiiIii * I1IiiI % OoOoOO00
def lisp_mr_or_pubsub ( action ) :
 return ( action in [ LISP_SEND_MAP_REQUEST_ACTION , LISP_SEND_PUBSUB_ACTION ] )
 if 49 - 49: Oo0Ooo
 if 67 - 67: iIii1I11I1II1 + I1Ii111 / I1Ii111 % I11i + I1Ii111
 if 7 - 7: iIii1I11I1II1 . Oo0Ooo / OoO0O00 / OoOoOO00
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
