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
lisp_uptime = lisp_get_timestamp ( )
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
  iII1I = False
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   o00oOOo0Oo = chacha . ChaCha ( key . encrypt_key , OoOooO ) . encrypt
   iII1I = True
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   Oooo0o0oO = binascii . unhexlify ( key . encrypt_key )
   try :
    o0OOoOooO0ooO = AES . new ( Oooo0o0oO , AES . MODE_GCM , OoOooO )
    o00oOOo0Oo = o0OOoOooO0ooO . encrypt
    iIiiII = o0OOoOooO0ooO . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 50 - 50: i11iIiiIii + OoooooooOO / O0 + o0oOOo0O0Ooo / i11iIiiIii + oO0o
  else :
   Oooo0o0oO = binascii . unhexlify ( key . encrypt_key )
   o00oOOo0Oo = AES . new ( Oooo0o0oO , AES . MODE_CBC , OoOooO ) . encrypt
   if 90 - 90: iII111i * Ii1I - iII111i + OoO0O00 + I11i % O0
   if 11 - 11: OOooOOo % I1Ii111 * OoOoOO00
  OoO00oo0 = o00oOOo0Oo ( Oo00oo )
  if 96 - 96: i1IIi
  if ( OoO00oo0 == None ) : return ( [ self . packet , False ] )
  i1 = int ( str ( time . time ( ) - i1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 55 - 55: oO0o + OOooOOo + Ii1I
  if 82 - 82: I1ii11iIi11i . II111iiii / OoOoOO00 / OoO0O00
  if 47 - 47: iII111i + O0 / II111iiii * I1IiiI - OoooooooOO . Ii1I
  if 28 - 28: oO0o . oO0o . iIii1I11I1II1 . OOooOOo . I1ii11iIi11i * i11iIiiIii
  if 72 - 72: I11i
  if 26 - 26: IiII % Oo0Ooo
  if ( iII1I ) :
   OoO00oo0 = OoO00oo0 . encode ( "raw_unicode_escape" )
   if 72 - 72: O0 + o0oOOo0O0Ooo + I1IiiI / Oo0Ooo
   if 83 - 83: IiII - I1IiiI . Ii1I
   if 34 - 34: OoOoOO00 - oO0o * OoooooooOO
   if 5 - 5: i11iIiiIii * iII111i - Ii1I - I1ii11iIi11i - i1IIi + iII111i
   if 4 - 4: ooOoO0o + O0 . i1IIi * I1ii11iIi11i - o0oOOo0O0Ooo
   if 42 - 42: o0oOOo0O0Ooo * OoOoOO00 . OoO0O00 - iII111i / II111iiii
   if 25 - 25: Oo0Ooo % OoOoOO00
  if ( iIiiII != None ) : OoO00oo0 += iIiiII ( )
  if 75 - 75: i1IIi
  if 74 - 74: Oo0Ooo + I1Ii111 - oO0o - OoO0O00 + iII111i - iIii1I11I1II1
  if 54 - 54: I1ii11iIi11i + II111iiii . I1IiiI / OoO0O00 . ooOoO0o
  if 58 - 58: IiII % i11iIiiIii * II111iiii . I1ii11iIi11i
  if 94 - 94: i11iIiiIii . OOooOOo + iIii1I11I1II1 * I1Ii111 * I1Ii111
  self . lisp_header . key_id ( key . key_id )
  OoIi11ii1 = self . lisp_header . encode ( )
  if 36 - 36: I11i - IiII . IiII
  Oo0OOOO0oOoo0 = key . do_icv ( OoIi11ii1 + OoOooO + OoO00oo0 , OoOooO )
  if 92 - 92: IiII . Oo0Ooo - Oo0Ooo - o0oOOo0O0Ooo + I1Ii111 - O0
  i1I1Iiii = 4 if ( key . do_poly ) else 8
  if 15 - 15: ooOoO0o % o0oOOo0O0Ooo / oO0o - II111iiii . iIii1I11I1II1
  ii1111Iii11i = bold ( "Encrypt" , False )
  O0o0oo0O = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  Ooo00OOo000 = "poly" if key . do_poly else "sha256"
  Ooo00OOo000 = bold ( Ooo00OOo000 , False )
  i1ooOO00o0 = "ICV({}): 0x{}...{}" . format ( Ooo00OOo000 , Oo0OOOO0oOoo0 [ 0 : i1I1Iiii ] , Oo0OOOO0oOoo0 [ - i1I1Iiii : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( ii1111Iii11i , key . key_id , addr_str , i1ooOO00o0 , O0o0oo0O , i1 ) )
  if 44 - 44: I1IiiI % OOooOOo * i11iIiiIii * i11iIiiIii - Oo0Ooo . I1Ii111
  if 68 - 68: iII111i . I11i
  Oo0OOOO0oOoo0 = int ( Oo0OOOO0oOoo0 , 16 )
  if ( key . do_poly ) :
   i111iiIiiIiI = byte_swap_64 ( ( Oo0OOOO0oOoo0 >> 64 ) & LISP_8_64_MASK )
   OOooooO = byte_swap_64 ( Oo0OOOO0oOoo0 & LISP_8_64_MASK )
   Oo0OOOO0oOoo0 = struct . pack ( "QQ" , i111iiIiiIiI , OOooooO )
  else :
   i111iiIiiIiI = byte_swap_64 ( ( Oo0OOOO0oOoo0 >> 96 ) & LISP_8_64_MASK )
   OOooooO = byte_swap_64 ( ( Oo0OOOO0oOoo0 >> 32 ) & LISP_8_64_MASK )
   oOoo00 = socket . htonl ( Oo0OOOO0oOoo0 & 0xffffffff )
   Oo0OOOO0oOoo0 = struct . pack ( "QQI" , i111iiIiiIiI , OOooooO , oOoo00 )
   if 29 - 29: OOooOOo / OoOoOO00 . iIii1I11I1II1 / I11i % OoOoOO00 % iII111i
   if 49 - 49: II111iiii / IiII - Ii1I
  return ( [ OoOooO + OoO00oo0 + Oo0OOOO0oOoo0 , True ] )
  if 7 - 7: I1IiiI / OoO0O00 + I1Ii111 + I11i / I1IiiI
  if 82 - 82: I1ii11iIi11i + OoooooooOO
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 21 - 21: oO0o * oO0o / I11i . iII111i
  if 10 - 10: Ii1I * OOooOOo - Oo0Ooo - OoooooooOO / o0oOOo0O0Ooo
  if 86 - 86: I1Ii111 % I1IiiI
  if 22 - 22: i11iIiiIii * I1Ii111 . Oo0Ooo . OoooooooOO + I1IiiI
  if 24 - 24: II111iiii / Ii1I . iIii1I11I1II1 - II111iiii % O0
  if 8 - 8: OoO0O00 % iII111i . OoooooooOO - Ii1I % OoooooooOO
  if ( key . do_poly ) :
   i111iiIiiIiI , OOooooO = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   oOooo = byte_swap_64 ( i111iiIiiIiI ) << 64
   oOooo |= byte_swap_64 ( OOooooO )
   oOooo = lisp_hex_string ( oOooo ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   i1I1Iiii = 4
   Iii1II1 = bold ( "poly" , False )
  else :
   i111iiIiiIiI , OOooooO , oOoo00 = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   oOooo = byte_swap_64 ( i111iiIiiIiI ) << 96
   oOooo |= byte_swap_64 ( OOooooO ) << 32
   oOooo |= socket . htonl ( oOoo00 )
   oOooo = lisp_hex_string ( oOooo ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   i1I1Iiii = 8
   Iii1II1 = bold ( "sha" , False )
   if 54 - 54: OoOoOO00 . Oo0Ooo
  OoIi11ii1 = self . lisp_header . encode ( )
  if 38 - 38: i1IIi . Oo0Ooo * Oo0Ooo / I1ii11iIi11i
  if 65 - 65: ooOoO0o % O0
  if 17 - 17: i1IIi + oO0o . I11i + i1IIi - II111iiii % I1IiiI
  if 34 - 34: I1IiiI
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   o0OoOo0O00 = 8
   O0o0oo0O = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   o0OoOo0O00 = 12
   O0o0oo0O = bold ( "aes-gcm" , False )
  else :
   o0OoOo0O00 = 16
   O0o0oo0O = bold ( "aes-cbc" , False )
   if 9 - 9: OOooOOo
  OoOooO = packet [ 0 : o0OoOo0O00 ]
  if 38 - 38: I11i . OoO0O00 . i11iIiiIii * OoooooooOO + iII111i
  if 49 - 49: Oo0Ooo - OoO0O00 / I1Ii111 / o0oOOo0O0Ooo % oO0o
  if 38 - 38: o0oOOo0O0Ooo . oO0o / o0oOOo0O0Ooo % II111iiii
  if 47 - 47: I11i * iIii1I11I1II1 * iII111i - OoO0O00 . O0 . ooOoO0o
  iIiiIiIIiI = key . do_icv ( OoIi11ii1 + packet , OoOooO )
  if 93 - 93: IiII % I1ii11iIi11i
  IiIIii = "0x{}...{}" . format ( oOooo [ 0 : i1I1Iiii ] , oOooo [ - i1I1Iiii : : ] )
  oo0O0 = "0x{}...{}" . format ( iIiiIiIIiI [ 0 : i1I1Iiii ] , iIiiIiIIiI [ - i1I1Iiii : : ] )
  if 34 - 34: II111iiii - IiII % OoOoOO00 % Ii1I / ooOoO0o
  if ( iIiiIiIIiI != oOooo ) :
   self . packet_error = "ICV-error"
   Ii1II = O0o0oo0O + "/" + Iii1II1
   IIiII = bold ( "ICV failed ({})" . format ( Ii1II ) , False )
   i1ooOO00o0 = "packet-ICV {} != computed-ICV {}" . format ( IiIIii , oo0O0 )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( IIiII , red ( addr_str , False ) ,
   # I1IiiI + o0oOOo0O0Ooo - IiII
 self . udp_sport , key . key_id , i1ooOO00o0 ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 85 - 85: iII111i * iII111i % OoOoOO00 - OOooOOo % OoO0O00 - I1IiiI
   if 3 - 3: OOooOOo + i1IIi % I1ii11iIi11i
   if 100 - 100: OoooooooOO + i11iIiiIii % o0oOOo0O0Ooo + I1IiiI . Oo0Ooo . II111iiii
   if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
   if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
   if 4 - 4: IiII
   lisp_retry_decap_keys ( addr_str , OoIi11ii1 + packet , OoOooO , oOooo )
   return ( [ None , False ] )
   if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
   if 99 - 99: i11iIiiIii - iII111i
   if 85 - 85: I1Ii111 % I1ii11iIi11i
   if 95 - 95: OoO0O00 * OOooOOo * iII111i . o0oOOo0O0Ooo
   if 73 - 73: OoO0O00
  packet = packet [ o0OoOo0O00 : : ]
  if 28 - 28: OoooooooOO - I11i
  if 84 - 84: II111iiii
  if 36 - 36: OOooOOo - OoOoOO00 - iIii1I11I1II1
  if 10 - 10: I1ii11iIi11i / Ii1I * i1IIi % O0 + I11i
  i1 = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   I1i1ii1ii = chacha . ChaCha ( key . encrypt_key , OoOooO ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   Oooo0o0oO = binascii . unhexlify ( key . encrypt_key )
   try :
    I1i1ii1ii = AES . new ( Oooo0o0oO , AES . MODE_GCM , OoOooO ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 32 - 32: IiII / OoooooooOO
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 30 - 30: OoOoOO00 / I1IiiI - OoO0O00 - iII111i - i11iIiiIii
   Oooo0o0oO = binascii . unhexlify ( key . encrypt_key )
   I1i1ii1ii = AES . new ( Oooo0o0oO , AES . MODE_CBC , OoOooO ) . decrypt
   if 84 - 84: i1IIi - I1IiiI % iII111i
   if 80 - 80: o0oOOo0O0Ooo % iII111i
  ooOooOooOOO = I1i1ii1ii ( packet )
  i1 = int ( str ( time . time ( ) - i1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 59 - 59: I11i
  if 63 - 63: OoO0O00 . oO0o + I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
  if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
  if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
  ii1111Iii11i = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  Ooo00OOo000 = "poly" if key . do_poly else "sha256"
  Ooo00OOo000 = bold ( Ooo00OOo000 , False )
  i1ooOO00o0 = "ICV({}): {}" . format ( Ooo00OOo000 , IiIIii )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( ii1111Iii11i , key . key_id , addr_str , i1ooOO00o0 , O0o0oo0O , i1 ) )
  if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
  if 46 - 46: i11iIiiIii
  if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
  if 48 - 48: I1Ii111 % iII111i % Ii1I % iIii1I11I1II1 . Ii1I
  if 14 - 14: iII111i * OoO0O00 % O0 + I11i + I1ii11iIi11i
  if 23 - 23: Oo0Ooo % iII111i + Ii1I - I1Ii111
  if 65 - 65: OoooooooOO
  self . packet = self . packet [ 0 : header_length ]
  return ( [ ooOooOooOOO , True ] )
  if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
  if 83 - 83: ooOoO0o
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  i1Ii1i11ii = 1000
  if 58 - 58: OoOoOO00 + OoO0O00 * Ii1I
  if 31 - 31: oO0o - iII111i
  if 46 - 46: I1IiiI + Oo0Ooo - Ii1I
  if 99 - 99: OOooOOo + I1IiiI . I1ii11iIi11i * OoooooooOO
  if 82 - 82: i11iIiiIii + iIii1I11I1II1 / Oo0Ooo + OOooOOo * II111iiii
  iIiIiiIIIi1 = [ ]
  oo00 = 0
  i1iIii = len ( inner_packet )
  while ( oo00 < i1iIii ) :
   Ii = inner_packet [ oo00 : : ]
   if ( len ( Ii ) > i1Ii1i11ii ) : Ii = Ii [ 0 : i1Ii1i11ii ]
   iIiIiiIIIi1 . append ( Ii )
   oo00 += len ( Ii )
   if 25 - 25: O0
   if 73 - 73: II111iiii + OOooOOo * iII111i / iII111i
   if 74 - 74: O0 + iIii1I11I1II1 + oO0o * IiII
   if 39 - 39: I1Ii111 . OoO0O00 % ooOoO0o . OOooOOo / iII111i * OoO0O00
   if 12 - 12: I1IiiI / o0oOOo0O0Ooo
   if 86 - 86: Oo0Ooo % OoOoOO00
  o0o0O00oOo = [ ]
  oo00 = 0
  for Ii in iIiIiiIIIi1 :
   if 42 - 42: II111iiii
   if 60 - 60: i1IIi / I1IiiI . II111iiii . iII111i % oO0o - I1IiiI
   if 39 - 39: I1IiiI . OoO0O00 + I11i + OOooOOo / II111iiii % i11iIiiIii
   if 86 - 86: I1ii11iIi11i - i1IIi + Oo0Ooo * I1IiiI / i11iIiiIii % oO0o
   i1i1IIi = oo00 if ( Ii == iIiIiiIIIi1 [ - 1 ] ) else 0x2000 + oo00
   i1i1IIi = socket . htons ( i1i1IIi )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , i1i1IIi ) + outer_hdr [ 8 : : ]
   if 93 - 93: oO0o
   if 85 - 85: i1IIi
   if 100 - 100: OoooooooOO / I11i % OoO0O00 + Ii1I
   if 42 - 42: Oo0Ooo / IiII . Ii1I * I1IiiI
   oOO0O0ooOOOo = socket . htons ( len ( Ii ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , oOO0O0ooOOOo ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   o0o0O00oOo . append ( outer_hdr + Ii )
   oo00 += len ( Ii ) / 8
   if 91 - 91: ooOoO0o - oO0o + oO0o
  return ( o0o0O00oOo )
  if 14 - 14: I1ii11iIi11i * I1Ii111 % i1IIi / I1ii11iIi11i
  if 48 - 48: Oo0Ooo
 def send_icmp_too_big ( self , inner_packet ) :
  global lisp_last_icmp_too_big_sent
  global lisp_icmp_raw_socket
  if 75 - 75: I1ii11iIi11i - IiII * Oo0Ooo . OoooooooOO * I1Ii111 * I1IiiI
  i1i111Iiiiiii = time . time ( ) - lisp_last_icmp_too_big_sent
  if ( i1i111Iiiiiii < LISP_ICMP_TOO_BIG_RATE_LIMIT ) :
   lprint ( "Rate limit sending ICMP Too-Big to {}" . format ( self . inner_source . print_address_no_iid ( ) ) )
   if 30 - 30: OoOoOO00 / oO0o / Ii1I * o0oOOo0O0Ooo * oO0o . I1IiiI
   return ( False )
   if 93 - 93: OoOoOO00
   if 97 - 97: i11iIiiIii
   if 68 - 68: IiII * OoO0O00 . I11i / Ii1I . o0oOOo0O0Ooo - i11iIiiIii
   if 49 - 49: Oo0Ooo / Ii1I % I11i + oO0o - OoO0O00
   if 13 - 13: II111iiii
   if 83 - 83: OoooooooOO . I1IiiI + Ii1I * O0 / oO0o
   if 8 - 8: i1IIi + II111iiii / Ii1I + I1ii11iIi11i % Ii1I - iIii1I11I1II1
   if 29 - 29: Oo0Ooo + II111iiii
   if 95 - 95: oO0o
   if 48 - 48: I11i / iIii1I11I1II1 % II111iiii
   if 39 - 39: i1IIi . I1ii11iIi11i / I11i / I11i
   if 100 - 100: OoooooooOO - OoooooooOO + IiII
   if 32 - 32: OoOoOO00 * o0oOOo0O0Ooo / OoooooooOO
   if 90 - 90: I1Ii111
   if 35 - 35: II111iiii / Ii1I
  OO0000 = socket . htons ( 1400 )
  IIii1III = struct . pack ( "BBHHH" , 3 , 4 , 0 , 0 , OO0000 )
  IIii1III += inner_packet [ 0 : 20 + 8 ]
  IIii1III = lisp_icmp_checksum ( IIii1III )
  if 79 - 79: i1IIi / Oo0Ooo - I1IiiI . O0
  if 56 - 56: IiII % O0 * i1IIi - II111iiii
  if 74 - 74: i1IIi - OoOoOO00 % oO0o . O0 - OoooooooOO
  if 84 - 84: I1Ii111
  if 53 - 53: i1IIi
  if 59 - 59: o0oOOo0O0Ooo + I1IiiI % OoooooooOO - iIii1I11I1II1
  if 9 - 9: i1IIi - OoOoOO00
  Oo00o0OOo0OO = inner_packet [ 12 : 16 ]
  I1i1iiIi = self . inner_source . print_address_no_iid ( )
  IIi1IiiIi1III = self . outer_source . pack_address ( )
  if 19 - 19: i1IIi % I1IiiI - iIii1I11I1II1 - oO0o / I1ii11iIi11i
  if 16 - 16: Ii1I
  if 79 - 79: OoooooooOO - ooOoO0o * Ii1I - II111iiii % OoOoOO00 * IiII
  if 31 - 31: I1IiiI
  if 36 - 36: OoO0O00 + OoO0O00 + OoO0O00 % Oo0Ooo * iII111i
  if 98 - 98: I11i . I11i / Oo0Ooo / Ii1I / I1IiiI
  if 56 - 56: o0oOOo0O0Ooo / IiII
  if 11 - 11: OoOoOO00 / I11i
  I1iIIi = socket . htons ( 20 + 36 )
  O0O = struct . pack ( "BBHHHBBH" , 0x45 , 0 , I1iIIi , 0 , 0 , 32 , 1 , 0 ) + IIi1IiiIi1III + Oo00o0OOo0OO
  O0O = lisp_ip_checksum ( O0O )
  O0O = self . fix_outer_header ( O0O )
  O0O += IIii1III
  IIOoOOoOo = bold ( "Too-Big" , False )
  lprint ( "Send ICMP {} to {}, mtu 1400: {}" . format ( IIOoOOoOo , I1i1iiIi ,
 lisp_format_packet ( O0O ) ) )
  if 37 - 37: iIii1I11I1II1 . I1IiiI % OoO0O00 % OoooooooOO . OoooooooOO / O0
  try :
   lisp_icmp_raw_socket . sendto ( O0O , ( I1i1iiIi , 0 ) )
  except socket . error as oO0ooOOO :
   lprint ( "lisp_icmp_raw_socket.sendto() failed: {}" . format ( oO0ooOOO ) )
   return ( False )
   if 25 - 25: II111iiii % II111iiii - Ii1I . O0
   if 79 - 79: IiII / OoO0O00 * OoooooooOO * OoOoOO00 + I1IiiI
   if 68 - 68: I11i / iIii1I11I1II1 . Oo0Ooo + i11iIiiIii + o0oOOo0O0Ooo
   if 92 - 92: OoO0O00 . o0oOOo0O0Ooo . Ii1I % OoOoOO00
   if 58 - 58: I1ii11iIi11i % Ii1I * Ii1I - iII111i
   if 9 - 9: ooOoO0o - Ii1I % II111iiii + IiII + OOooOOo % O0
  lisp_last_icmp_too_big_sent = lisp_get_timestamp ( )
  return ( True )
  if 65 - 65: OOooOOo - OoO0O00 % i11iIiiIii
 def fragment ( self ) :
  global lisp_icmp_raw_socket
  global lisp_ignore_df_bit
  if 58 - 58: iII111i
  Oo00oo = self . fix_outer_header ( self . packet )
  if 2 - 2: II111iiii + i1IIi
  if 68 - 68: OOooOOo + Ii1I
  if 58 - 58: IiII * Ii1I . i1IIi
  if 19 - 19: oO0o
  if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
  if 94 - 94: iIii1I11I1II1 + IiII
  i1iIii = len ( Oo00oo )
  if ( i1iIii <= 1500 ) : return ( [ Oo00oo ] , "Fragment-None" )
  if 44 - 44: OoO0O00 + I11i % OoO0O00 + i1IIi + iII111i + O0
  Oo00oo = self . packet
  if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
  if 36 - 36: OoOoOO00 . i11iIiiIii
  if 81 - 81: Oo0Ooo * iII111i * OoO0O00
  if 85 - 85: O0 * oO0o
  if 39 - 39: II111iiii * I1IiiI - iIii1I11I1II1
  if ( self . inner_version != 4 ) :
   Ii1o0OOOoo0000 = random . randint ( 0 , 0xffff )
   IiIIii1i1i11iII = Oo00oo [ 0 : 4 ] + struct . pack ( "H" , Ii1o0OOOoo0000 ) + Oo00oo [ 6 : 20 ]
   o0II1 = Oo00oo [ 20 : : ]
   o0o0O00oOo = self . fragment_outer ( IiIIii1i1i11iII , o0II1 )
   return ( o0o0O00oOo , "Fragment-Outer" )
   if 86 - 86: oO0o . I1IiiI - I1Ii111 + iIii1I11I1II1
   if 66 - 66: I11i - I11i + IiII
   if 20 - 20: I1Ii111 . i1IIi
   if 9 - 9: OoO0O00
   if 89 - 89: i1IIi
  I11II = 56 if ( self . outer_version == 6 ) else 36
  IiIIii1i1i11iII = Oo00oo [ 0 : I11II ]
  OOO = Oo00oo [ I11II : I11II + 20 ]
  o0II1 = Oo00oo [ I11II + 20 : : ]
  if 58 - 58: I1Ii111 . i11iIiiIii + OoooooooOO / i11iIiiIii . OoooooooOO % I1IiiI
  if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
  if 22 - 22: iIii1I11I1II1 - Ii1I / I1IiiI * IiII
  if 26 - 26: o0oOOo0O0Ooo + OOooOOo - o0oOOo0O0Ooo + Oo0Ooo . oO0o
  if 97 - 97: i1IIi
  ii1iI1i1 = struct . unpack ( "H" , OOO [ 6 : 8 ] ) [ 0 ]
  ii1iI1i1 = socket . ntohs ( ii1iI1i1 )
  if ( ii1iI1i1 & 0x4000 ) :
   if ( lisp_icmp_raw_socket != None ) :
    o0o0oo0OOo0O0 = Oo00oo [ I11II : : ]
    if ( self . send_icmp_too_big ( o0o0oo0OOo0O0 ) ) : return ( [ ] , None )
    if 37 - 37: o0oOOo0O0Ooo * Oo0Ooo
   if ( lisp_ignore_df_bit ) :
    ii1iI1i1 &= ~ 0x4000
   else :
    iI11i1I1i = bold ( "DF-bit set" , False )
    dprint ( "{} in inner header, packet discarded" . format ( iI11i1I1i ) )
    return ( [ ] , "Fragment-None-DF-bit" )
    if 96 - 96: I1Ii111 / IiII * iIii1I11I1II1 + i11iIiiIii * I1ii11iIi11i / I1IiiI
    if 93 - 93: O0 * iIii1I11I1II1 + Ii1I % iII111i
    if 96 - 96: oO0o % Oo0Ooo
  oo00 = 0
  i1iIii = len ( o0II1 )
  o0o0O00oOo = [ ]
  while ( oo00 < i1iIii ) :
   o0o0O00oOo . append ( o0II1 [ oo00 : oo00 + 1400 ] )
   oo00 += 1400
   if 20 - 20: ooOoO0o . IiII / I11i . OoooooooOO * OOooOOo + Ii1I
   if 2 - 2: I1IiiI
   if 11 - 11: OOooOOo + iIii1I11I1II1 / OoOoOO00 % O0
   if 98 - 98: II111iiii + Oo0Ooo * iIii1I11I1II1 * I1ii11iIi11i + OOooOOo * Ii1I
   if 76 - 76: ooOoO0o . oO0o
  iIiIiiIIIi1 = o0o0O00oOo
  o0o0O00oOo = [ ]
  oO00OO0o0ooO = True if ii1iI1i1 & 0x2000 else False
  ii1iI1i1 = ( ii1iI1i1 & 0x1fff ) * 8
  for Ii in iIiIiiIIIi1 :
   if 42 - 42: O0 * iII111i . OoOoOO00 / OOooOOo - Ii1I . I11i
   if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
   if 37 - 37: OoO0O00 * I11i + Ii1I + I1ii11iIi11i * o0oOOo0O0Ooo
   if 95 - 95: Ii1I - i11iIiiIii % i11iIiiIii - O0 * I1Ii111
   Oo0O0oOoO0o0 = old_div ( ii1iI1i1 , 8 )
   if ( oO00OO0o0ooO ) :
    Oo0O0oOoO0o0 |= 0x2000
   elif ( Ii != iIiIiiIIIi1 [ - 1 ] ) :
    Oo0O0oOoO0o0 |= 0x2000
    if 21 - 21: I1IiiI - I1IiiI + iII111i % I1IiiI * oO0o
   Oo0O0oOoO0o0 = socket . htons ( Oo0O0oOoO0o0 )
   OOO = OOO [ 0 : 6 ] + struct . pack ( "H" , Oo0O0oOoO0o0 ) + OOO [ 8 : : ]
   if 74 - 74: iII111i / I11i . I1IiiI - OoooooooOO + II111iiii + I11i
   if 36 - 36: Ii1I * I1IiiI * I1ii11iIi11i . I11i * I1ii11iIi11i
   if 76 - 76: OOooOOo + O0 / IiII - OoO0O00
   if 27 - 27: Oo0Ooo - iIii1I11I1II1 * iII111i * II111iiii * I1ii11iIi11i
   if 9 - 9: i11iIiiIii + OOooOOo - OoOoOO00 / ooOoO0o % i1IIi / oO0o
   if 22 - 22: i1IIi
   i1iIii = len ( Ii )
   ii1iI1i1 += i1iIii
   oOO0O0ooOOOo = socket . htons ( i1iIii + 20 )
   OOO = OOO [ 0 : 2 ] + struct . pack ( "H" , oOO0O0ooOOOo ) + OOO [ 4 : 10 ] + struct . pack ( "H" , 0 ) + OOO [ 12 : : ]
   if 3 - 3: OoO0O00 * I1ii11iIi11i - iII111i + I1ii11iIi11i
   OOO = lisp_ip_checksum ( OOO )
   O0000oO00oO0o = OOO + Ii
   if 86 - 86: o0oOOo0O0Ooo / ooOoO0o . o0oOOo0O0Ooo % I1IiiI + oO0o % I11i
   if 72 - 72: ooOoO0o - I1ii11iIi11i + oO0o . OoOoOO00
   if 44 - 44: I1ii11iIi11i / O0 - IiII + OOooOOo . I11i . I1ii11iIi11i
   if 95 - 95: OoOoOO00 % I1Ii111 % i1IIi * o0oOOo0O0Ooo + OOooOOo
   if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
   i1iIii = len ( O0000oO00oO0o )
   if ( self . outer_version == 4 ) :
    oOO0O0ooOOOo = i1iIii + I11II
    i1iIii += 16
    IiIIii1i1i11iII = IiIIii1i1i11iII [ 0 : 2 ] + struct . pack ( "H" , oOO0O0ooOOOo ) + IiIIii1i1i11iII [ 4 : : ]
    if 61 - 61: iIii1I11I1II1 + oO0o * I11i - i1IIi % oO0o
    IiIIii1i1i11iII = lisp_ip_checksum ( IiIIii1i1i11iII )
    O0000oO00oO0o = IiIIii1i1i11iII + O0000oO00oO0o
    O0000oO00oO0o = self . fix_outer_header ( O0000oO00oO0o )
    if 76 - 76: oO0o / OoOoOO00
    if 12 - 12: I1Ii111
    if 58 - 58: OoO0O00 + iIii1I11I1II1 % O0 + I11i + OoOoOO00 * OoooooooOO
    if 41 - 41: oO0o * I1IiiI
    if 76 - 76: oO0o . O0 * OoooooooOO + ooOoO0o
   oo0O00 = I11II - 12
   oOO0O0ooOOOo = socket . htons ( i1iIii )
   O0000oO00oO0o = O0000oO00oO0o [ 0 : oo0O00 ] + struct . pack ( "H" , oOO0O0ooOOOo ) + O0000oO00oO0o [ oo0O00 + 2 : : ]
   if 19 - 19: i1IIi / IiII + I1ii11iIi11i * I1ii11iIi11i
   o0o0O00oOo . append ( O0000oO00oO0o )
   if 90 - 90: OoooooooOO * iII111i . i11iIiiIii . ooOoO0o - I1Ii111
  return ( o0o0O00oOo , "Fragment-Inner" )
  if 81 - 81: I1IiiI / OoooooooOO
  if 52 - 52: oO0o + I1Ii111 * I1Ii111 * Oo0Ooo - iIii1I11I1II1 + I1ii11iIi11i
 def fix_outer_header ( self , packet ) :
  if 34 - 34: iII111i / OoO0O00 / Oo0Ooo
  if 92 - 92: I1Ii111 % iII111i % o0oOOo0O0Ooo . I1IiiI - I1ii11iIi11i - o0oOOo0O0Ooo
  if 40 - 40: I1IiiI / OoooooooOO + OoO0O00 * OoO0O00
  if 9 - 9: iIii1I11I1II1
  if 57 - 57: ooOoO0o / Ii1I % o0oOOo0O0Ooo % i11iIiiIii
  if 95 - 95: I1Ii111 - o0oOOo0O0Ooo
  if 65 - 65: i11iIiiIii - OoooooooOO / O0 * IiII % I11i
  if 53 - 53: OOooOOo + I1Ii111
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 : 4 ] + packet [ 2 : 3 ] + packet [ 4 : 6 ] + packet [ 7 : 8 ] + packet [ 6 : 7 ] + packet [ 8 : : ]
    if 10 - 10: I11i * i1IIi . oO0o / I1Ii111 . OOooOOo / I1Ii111
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 : 4 ] + packet [ 2 : 3 ] + packet [ 4 : : ]
    if 1 - 1: iII111i % ooOoO0o
    if 99 - 99: iII111i + iIii1I11I1II1 . OOooOOo / OoO0O00 * I1ii11iIi11i
  return ( packet )
  if 87 - 87: IiII / II111iiii % OoO0O00 % OoO0O00
  if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 91 - 91: I1IiiI / II111iiii * OOooOOo
  dest = dest . print_address_no_iid ( )
  o0o0O00oOo , ooOoo000 = self . fragment ( )
  if 56 - 56: ooOoO0o . iIii1I11I1II1 + i1IIi
  for O0000oO00oO0o in o0o0O00oOo :
   if ( len ( o0o0O00oOo ) != 1 ) :
    self . packet = O0000oO00oO0o
    self . print_packet ( ooOoo000 , True )
    if 84 - 84: iII111i % i1IIi
    if 62 - 62: I1ii11iIi11i . I1Ii111 . Ii1I
   try : lisp_raw_socket . sendto ( O0000oO00oO0o , ( dest , 0 ) )
   except socket . error as oO0ooOOO :
    lprint ( "socket.sendto() failed: {}" . format ( oO0ooOOO ) )
    if 19 - 19: I1ii11iIi11i / I1Ii111
    if 35 - 35: Oo0Ooo * oO0o / OoooooooOO + O0 / OoooooooOO / OOooOOo
    if 44 - 44: i1IIi . I1ii11iIi11i - ooOoO0o . OOooOOo . o0oOOo0O0Ooo + oO0o
    if 17 - 17: iIii1I11I1II1 + i1IIi . I1ii11iIi11i + Ii1I % i1IIi . oO0o
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 57 - 57: oO0o
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 92 - 92: II111iiii - OoO0O00 - OOooOOo % I1IiiI - OoOoOO00 * I1Ii111
   if 16 - 16: iIii1I11I1II1 + OoooooooOO - ooOoO0o * IiII
  Oo00oo = mac_header + self . packet
  if 37 - 37: iII111i
  if 15 - 15: o0oOOo0O0Ooo % OoO0O00 / iII111i
  if 36 - 36: OoO0O00 + OoO0O00 % Oo0Ooo + Oo0Ooo / i1IIi % i1IIi
  if 20 - 20: OOooOOo * oO0o
  if 91 - 91: OoO0O00 % i1IIi - iIii1I11I1II1 . OOooOOo
  if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
  if 45 - 45: OOooOOo + I11i / OoooooooOO - Ii1I + OoooooooOO
  if 42 - 42: iIii1I11I1II1 * I1IiiI * I1Ii111
  if 62 - 62: OOooOOo * O0 % IiII . IiII . I1IiiI
  if 91 - 91: i1IIi . iII111i
  if 37 - 37: iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoO0O00 . o0oOOo0O0Ooo
  l2_socket . write ( Oo00oo )
  return
  if 62 - 62: I1ii11iIi11i
  if 47 - 47: I1Ii111 % OOooOOo * OoO0O00 . iIii1I11I1II1 % Oo0Ooo + OoooooooOO
 def bridge_l2_packet ( self , eid , db ) :
  try : I1Ii111I111 = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : i111IIiIiiI1 = lisp_myinterfaces [ I1Ii111I111 . interface ]
  except : return
  try :
   socket = i111IIiIiiI1 . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 7 - 7: I1IiiI
  try : socket . send ( self . packet )
  except socket . error as oO0ooOOO :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( oO0ooOOO ) )
   if 40 - 40: ooOoO0o
   if 80 - 80: I1IiiI * I1Ii111 % oO0o . i11iIiiIii % IiII
   if 42 - 42: OoooooooOO * II111iiii
 def is_lisp_packet ( self , packet ) :
  O0I1II1 = ( struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ] == LISP_UDP_PROTOCOL )
  if ( O0I1II1 == False ) : return ( False )
  if 53 - 53: I1Ii111 + i1IIi . OoO0O00 / i11iIiiIii + Ii1I % OoOoOO00
  I1I = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
  if ( socket . ntohs ( I1I ) == LISP_DATA_PORT ) : return ( True )
  I1I = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
  if ( socket . ntohs ( I1I ) == LISP_DATA_PORT ) : return ( True )
  return ( False )
  if 74 - 74: Oo0Ooo
  if 91 - 91: OOooOOo . I1IiiI % iII111i
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  Oo00oo = self . packet
  OO00OO = len ( Oo00oo )
  IiIiIi11iiIi1 = OoOoO0O00oo = True
  if 71 - 71: O0 % O0
  if 96 - 96: Ii1I
  if 24 - 24: O0
  if 33 - 33: OoooooooOO + oO0o * II111iiii / OOooOOo
  ooooI11iii1iIIIIi = 0
  oooo = self . lisp_header . get_instance_id ( )
  if ( is_lisp_packet ) :
   III1i1iiI1 = struct . unpack ( "B" , Oo00oo [ 0 : 1 ] ) [ 0 ]
   self . outer_version = III1i1iiI1 >> 4
   if ( self . outer_version == 4 ) :
    if 62 - 62: Ii1I . i11iIiiIii % O0 % I1Ii111 - Oo0Ooo
    if 69 - 69: II111iiii . OoOoOO00 * OoOoOO00 % Ii1I + I1IiiI
    if 100 - 100: i11iIiiIii - Oo0Ooo
    if 47 - 47: iII111i * OoOoOO00 * IiII
    if 46 - 46: Ii1I
    ii1 = struct . unpack ( "H" , Oo00oo [ 10 : 12 ] ) [ 0 ]
    Oo00oo = lisp_ip_checksum ( Oo00oo )
    ii1II1II = struct . unpack ( "H" , Oo00oo [ 10 : 12 ] ) [ 0 ]
    if ( ii1II1II != 0 ) :
     if ( ii1 != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( OO00OO )
       if 64 - 64: Ii1I . OoooooooOO - I1ii11iIi11i
       if 19 - 19: Oo0Ooo
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 15 - 15: Oo0Ooo . ooOoO0o / o0oOOo0O0Ooo
      if 23 - 23: OoO0O00 % OoooooooOO * ooOoO0o
      if 6 - 6: I1IiiI . II111iiii + I1Ii111 / OoO0O00 % I1IiiI . OoooooooOO
    Oooo000 = LISP_AFI_IPV4
    oo00 = 12
    self . outer_tos = struct . unpack ( "B" , Oo00oo [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , Oo00oo [ 8 : 9 ] ) [ 0 ]
    ooooI11iii1iIIIIi = 20
   elif ( self . outer_version == 6 ) :
    Oooo000 = LISP_AFI_IPV6
    oo00 = 8
    IIii1i1 = struct . unpack ( "H" , Oo00oo [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( IIii1i1 ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , Oo00oo [ 7 : 8 ] ) [ 0 ]
    ooooI11iii1iIIIIi = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( OO00OO )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 98 - 98: I1ii11iIi11i - OoooooooOO / I1IiiI . ooOoO0o - i1IIi
    if 60 - 60: OoOoOO00 % OoOoOO00
   self . outer_source . afi = Oooo000
   self . outer_dest . afi = Oooo000
   I1Ii11iI11ii = self . outer_source . addr_length ( )
   if 85 - 85: i1IIi
   self . outer_source . unpack_address ( Oo00oo [ oo00 : oo00 + I1Ii11iI11ii ] )
   oo00 += I1Ii11iI11ii
   self . outer_dest . unpack_address ( Oo00oo [ oo00 : oo00 + I1Ii11iI11ii ] )
   Oo00oo = Oo00oo [ ooooI11iii1iIIIIi : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 64 - 64: OoOoOO00 % iIii1I11I1II1
   if 28 - 28: oO0o * o0oOOo0O0Ooo
   if 83 - 83: I1ii11iIi11i * I11i . OoooooooOO % Ii1I
   if 29 - 29: iII111i + II111iiii . i11iIiiIii . Ii1I - O0
   III = struct . unpack ( "H" , Oo00oo [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( III )
   III = struct . unpack ( "H" , Oo00oo [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( III )
   III = struct . unpack ( "H" , Oo00oo [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( III )
   III = struct . unpack ( "H" , Oo00oo [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( III )
   Oo00oo = Oo00oo [ 8 : : ]
   if 60 - 60: II111iiii . I11i / OoooooooOO + ooOoO0o . iIii1I11I1II1
   if 87 - 87: I1IiiI + I1ii11iIi11i % oO0o - Oo0Ooo
   if 33 - 33: II111iiii . I1ii11iIi11i - O0 * iIii1I11I1II1 % O0 . OoooooooOO
   if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
   IiIiIi11iiIi1 = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   OoOoO0O00oo = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 16 - 16: OoO0O00 % I1Ii111 . i1IIi / I1ii11iIi11i - O0
   if 85 - 85: i1IIi . i1IIi
   if 16 - 16: I1IiiI - OOooOOo % Ii1I . OOooOOo + I1ii11iIi11i % i11iIiiIii
   if 59 - 59: i11iIiiIii - I11i
   if ( self . lisp_header . decode ( Oo00oo ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( OO00OO )
    if 59 - 59: OoooooooOO * o0oOOo0O0Ooo / I1Ii111
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 75 - 75: o0oOOo0O0Ooo - OoooooooOO
   Oo00oo = Oo00oo [ 8 : : ]
   oooo = self . lisp_header . get_instance_id ( )
   ooooI11iii1iIIIIi += 16
   if 21 - 21: I1IiiI + iIii1I11I1II1 / i11iIiiIii / oO0o
  if ( oooo == 0xffffff ) : oooo = 0
  if 66 - 66: OoooooooOO + iII111i . IiII % i1IIi
  if 58 - 58: OOooOOo % iII111i * O0 + I1ii11iIi11i - IiII
  if 26 - 26: i1IIi / I1IiiI / I11i + I11i
  if 46 - 46: I1Ii111 % I1ii11iIi11i + Ii1I
  Ooii = False
  i11iII1 = self . lisp_header . k_bits
  if ( i11iII1 ) :
   O0O0 = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( O0O0 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( OO00OO )
    if 75 - 75: OOooOOo / i11iIiiIii / iIii1I11I1II1
    self . print_packet ( "Receive" , is_lisp_packet )
    i11iI1111ii1I = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( i11iI1111ii1I , i11iII1 ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 89 - 89: i11iIiiIii / O0 - i1IIi % Oo0Ooo + i11iIiiIii
    if 44 - 44: i11iIiiIii / OOooOOo * ooOoO0o
   Ooo00o000o = lisp_crypto_keys_by_rloc_decap [ O0O0 ] [ i11iII1 ]
   if ( Ooo00o000o == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( OO00OO )
    if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
    self . print_packet ( "Receive" , is_lisp_packet )
    i11iI1111ii1I = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( i11iI1111ii1I ,
 red ( O0O0 , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
    if 68 - 68: OoO0O00 % O0 * iIii1I11I1II1 / oO0o * o0oOOo0O0Ooo + OOooOOo
    if 89 - 89: ooOoO0o * I1IiiI . oO0o
    if 75 - 75: ooOoO0o - iII111i % iII111i + ooOoO0o * o0oOOo0O0Ooo - I1ii11iIi11i
    if 26 - 26: I11i * Ii1I % I1IiiI + iII111i
   Ooo00o000o . use_count += 1
   Oo00oo , Ooii = self . decrypt ( Oo00oo , ooooI11iii1iIIIIi , Ooo00o000o , O0O0 )
   if ( Ooii == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( OO00OO )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 38 - 38: iII111i - Oo0Ooo / Ii1I + oO0o . iII111i + IiII
    if 19 - 19: Ii1I
    if 51 - 51: iIii1I11I1II1
    if 8 - 8: OoO0O00 / o0oOOo0O0Ooo % iII111i . i11iIiiIii . OoooooooOO . Ii1I
    if 8 - 8: OoO0O00 * Oo0Ooo
    if 41 - 41: Oo0Ooo / OoO0O00 / OoOoOO00 - i11iIiiIii - OoOoOO00
   if ( Ooo00o000o . cipher_suite == LISP_CS_25519_CHACHA ) :
    Oo00oo = Oo00oo . encode ( "raw_unicode_escape" )
    if 4 - 4: I11i . IiII
    if 39 - 39: OOooOOo . Oo0Ooo - OoOoOO00 * i11iIiiIii
    if 4 - 4: OoOoOO00 * O0 - I11i
    if 72 - 72: I11i + ooOoO0o / I1IiiI . IiII % OoO0O00 / i11iIiiIii
    if 13 - 13: I1Ii111 % o0oOOo0O0Ooo + OOooOOo + I1Ii111 + i11iIiiIii - I1ii11iIi11i
    if 70 - 70: II111iiii * II111iiii . I1IiiI
  III1i1iiI1 = struct . unpack ( "B" , Oo00oo [ 0 : 1 ] ) [ 0 ]
  self . inner_version = III1i1iiI1 >> 4
  if ( IiIiIi11iiIi1 and self . inner_version == 4 and III1i1iiI1 >= 0x45 ) :
   iiIi1111iiI1 = socket . ntohs ( struct . unpack ( "H" , Oo00oo [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , Oo00oo [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , Oo00oo [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , Oo00oo [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( Oo00oo [ 12 : 16 ] )
   self . inner_dest . unpack_address ( Oo00oo [ 16 : 20 ] )
   ii1iI1i1 = socket . ntohs ( struct . unpack ( "H" , Oo00oo [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( ii1iI1i1 & 0x2000 or ii1iI1i1 != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , Oo00oo [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , Oo00oo [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 85 - 85: I11i + I1Ii111
  elif ( IiIiIi11iiIi1 and self . inner_version == 6 and III1i1iiI1 >= 0x60 ) :
   iiIi1111iiI1 = socket . ntohs ( struct . unpack ( "H" , Oo00oo [ 4 : 6 ] ) [ 0 ] ) + 40
   IIii1i1 = struct . unpack ( "H" , Oo00oo [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( IIii1i1 ) >> 4 ) & 0xff
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
    if 11 - 11: I11i
  elif ( OoOoO0O00oo ) :
   iiIi1111iiI1 = len ( Oo00oo )
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
   if ( stats ) : stats [ self . packet_error ] . increment ( OO00OO )
   if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( III1i1iiI1 ) ) )
   if 11 - 11: I1ii11iIi11i / O0 + II111iiii
   Oo00oo = lisp_format_packet ( Oo00oo [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( Oo00oo ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = oooo
  self . inner_dest . instance_id = oooo
  if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
  if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
  if 2 - 2: Ii1I
  if 12 - 12: i11iIiiIii - iIii1I11I1II1 * IiII * iII111i
  if 19 - 19: O0 + oO0o + o0oOOo0O0Ooo
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   oO0 = lisp_get_echo_nonce ( self . outer_source , None )
   if ( oO0 == None ) :
    IIi11IiiiI11i = self . outer_source . print_address_no_iid ( )
    oO0 = lisp_echo_nonce ( IIi11IiiiI11i )
    if 68 - 68: oO0o + I11i * oO0o . IiII % Ii1I - OoooooooOO
   oOooo0oOOOO = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    oO0 . receive_request ( lisp_ipc_socket , oOooo0oOOOO )
   elif ( oO0 . request_nonce_sent ) :
    oO0 . receive_echo ( lisp_ipc_socket , oOooo0oOOOO )
    if 81 - 81: o0oOOo0O0Ooo / I1IiiI / o0oOOo0O0Ooo * IiII + OOooOOo % I1Ii111
    if 61 - 61: OoOoOO00 - OoOoOO00 . o0oOOo0O0Ooo + oO0o
    if 26 - 26: II111iiii / o0oOOo0O0Ooo
    if 32 - 32: I1ii11iIi11i * I1IiiI + o0oOOo0O0Ooo % II111iiii + OOooOOo + Ii1I
    if 90 - 90: Ii1I
    if 30 - 30: o0oOOo0O0Ooo + Ii1I / OoooooooOO - IiII % oO0o
    if 21 - 21: OoooooooOO % OoOoOO00 - OoOoOO00 / I1ii11iIi11i / o0oOOo0O0Ooo
  if ( Ooii ) : self . packet += Oo00oo [ : iiIi1111iiI1 ]
  if 15 - 15: ooOoO0o / ooOoO0o % OoooooooOO . I1Ii111
  if 93 - 93: I1ii11iIi11i * I1ii11iIi11i / OoooooooOO
  if 6 - 6: I1ii11iIi11i * Oo0Ooo + iIii1I11I1II1
  if 19 - 19: O0 % II111iiii * o0oOOo0O0Ooo
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 27 - 27: OOooOOo * IiII / i11iIiiIii - oO0o + II111iiii
  if 43 - 43: I1ii11iIi11i - II111iiii
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 56 - 56: I1ii11iIi11i . i1IIi / iII111i % oO0o / O0 * I11i
  if 98 - 98: O0 + iII111i
 def strip_outer_headers ( self ) :
  oo00 = 16
  oo00 += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ oo00 : : ]
  return ( self )
  if 23 - 23: OoooooooOO . iIii1I11I1II1 / i1IIi
  if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
 def hash_ports ( self ) :
  Oo00oo = self . packet
  III1i1iiI1 = self . inner_version
  oOOo0O0Oo = 0
  if ( III1i1iiI1 == 4 ) :
   III1I1I1iiIi = struct . unpack ( "B" , Oo00oo [ 9 : 10 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( III1I1I1iiIi )
   if ( III1I1I1iiIi in [ 6 , 17 ] ) :
    oOOo0O0Oo = III1I1I1iiIi
    oOOo0O0Oo += struct . unpack ( "I" , Oo00oo [ 20 : 24 ] ) [ 0 ]
    oOOo0O0Oo = ( oOOo0O0Oo >> 16 ) ^ ( oOOo0O0Oo & 0xffff )
    if 30 - 30: OoOoOO00 - i11iIiiIii
    if 94 - 94: OoOoOO00 % iII111i
  if ( III1i1iiI1 == 6 ) :
   III1I1I1iiIi = struct . unpack ( "B" , Oo00oo [ 6 : 7 ] ) [ 0 ]
   if ( III1I1I1iiIi in [ 6 , 17 ] ) :
    oOOo0O0Oo = III1I1I1iiIi
    oOOo0O0Oo += struct . unpack ( "I" , Oo00oo [ 40 : 44 ] ) [ 0 ]
    oOOo0O0Oo = ( oOOo0O0Oo >> 16 ) ^ ( oOOo0O0Oo & 0xffff )
    if 39 - 39: OoOoOO00 + I1Ii111 % O0
    if 26 - 26: ooOoO0o + OoOoOO00
  return ( oOOo0O0Oo )
  if 17 - 17: I1ii11iIi11i - iII111i % Oo0Ooo * O0 % O0 * OOooOOo
  if 6 - 6: I1Ii111
 def hash_packet ( self ) :
  oOOo0O0Oo = self . inner_source . address ^ self . inner_dest . address
  oOOo0O0Oo += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   oOOo0O0Oo = ( oOOo0O0Oo >> 16 ) ^ ( oOOo0O0Oo & 0xffff )
  elif ( self . inner_version == 6 ) :
   oOOo0O0Oo = ( oOOo0O0Oo >> 64 ) ^ ( oOOo0O0Oo & 0xffffffffffffffff )
   oOOo0O0Oo = ( oOOo0O0Oo >> 32 ) ^ ( oOOo0O0Oo & 0xffffffff )
   oOOo0O0Oo = ( oOOo0O0Oo >> 16 ) ^ ( oOOo0O0Oo & 0xffff )
   if 46 - 46: II111iiii * I1Ii111
  self . udp_sport = 0xf000 | ( oOOo0O0Oo & 0xfff )
  if 23 - 23: i1IIi - O0
  if 6 - 6: ooOoO0o % OoooooooOO * I1Ii111 - IiII
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   I1ii = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # iIii1I11I1II1 / Ii1I + OoooooooOO % i1IIi * i11iIiiIii
 green ( I1ii , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 86 - 86: i11iIiiIii - O0 - i11iIiiIii . iIii1I11I1II1 . IiII
   if 84 - 84: i1IIi / iIii1I11I1II1 / oO0o / Ii1I
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   iI = "decap"
   iI += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   iI = s_or_r
   if ( iI in [ "Send" , "Replicate" ] or iI . find ( "Fragment" ) != - 1 ) :
    iI = "encap"
    if 80 - 80: o0oOOo0O0Ooo + o0oOOo0O0Ooo + I1Ii111 * oO0o + I11i
    if 75 - 75: OoO0O00 - OoOoOO00 - i1IIi % Oo0Ooo - II111iiii
  oOoooO = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 64 - 64: IiII
  if 80 - 80: I1IiiI - i11iIiiIii / OoO0O00 / OoOoOO00 + OoOoOO00
  if 89 - 89: O0 + IiII * I1Ii111
  if 30 - 30: OoOoOO00
  if 39 - 39: I1ii11iIi11i + o0oOOo0O0Ooo + I1Ii111 + IiII
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   IiiiI1 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 48 - 48: I1Ii111 / ooOoO0o . iIii1I11I1II1
   IiiiI1 += bold ( "control-packet" , False ) + ": {} ..."
   if 72 - 72: i1IIi . o0oOOo0O0Ooo
   dprint ( IiiiI1 . format ( bold ( s_or_r , False ) , red ( oOoooO , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   IiiiI1 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 3 - 3: OoOoOO00 % II111iiii - O0
   if 52 - 52: OoO0O00
   if 49 - 49: Ii1I . I1ii11iIi11i % ooOoO0o . Oo0Ooo * OOooOOo
   if 44 - 44: iIii1I11I1II1 / O0 * Oo0Ooo + I1IiiI . ooOoO0o
  if ( self . lisp_header . k_bits ) :
   if ( iI == "encap" ) : iI = "encrypt/encap"
   if ( iI == "decap" ) : iI = "decap/decrypt"
   if 20 - 20: iII111i + o0oOOo0O0Ooo . I1Ii111 / i11iIiiIii
   if 7 - 7: OoOoOO00 / OoOoOO00 . I1Ii111 * O0 + IiII + oO0o
  I1ii = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 98 - 98: II111iiii * IiII - I1IiiI % o0oOOo0O0Ooo - iII111i % I1ii11iIi11i
  dprint ( IiiiI1 . format ( bold ( s_or_r , False ) , red ( oOoooO , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( I1ii , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( iI ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 69 - 69: i1IIi % OoO0O00 % I1Ii111 / ooOoO0o / ooOoO0o
  if 6 - 6: II111iiii % I1ii11iIi11i % i1IIi * ooOoO0o
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 47 - 47: O0
  if 55 - 55: OoO0O00 % O0 / OoooooooOO
 def get_raw_socket ( self ) :
  oooo = str ( self . lisp_header . get_instance_id ( ) )
  if ( oooo == "0" ) : return ( None )
  if ( oooo not in lisp_iid_to_interface ) : return ( None )
  if 49 - 49: I1IiiI . OoO0O00 * OoooooooOO % i11iIiiIii + iIii1I11I1II1 * i1IIi
  i111IIiIiiI1 = lisp_iid_to_interface [ oooo ]
  I111 = i111IIiIiiI1 . get_socket ( )
  if ( I111 == None ) :
   ii1111Iii11i = bold ( "SO_BINDTODEVICE" , False )
   oOO0oOoooOoo0 = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( ii1111Iii11i , "drop" if oOO0oOoooOoo0 else "forward" ) )
   if 1 - 1: O0 + iII111i * ooOoO0o - i11iIiiIii
   if ( oOO0oOoooOoo0 ) : return ( None )
   if 18 - 18: ooOoO0o
   if 37 - 37: Oo0Ooo % i11iIiiIii - I1IiiI * I1ii11iIi11i . ooOoO0o
  oooo = bold ( oooo , False )
  IiI11I111 = bold ( i111IIiIiiI1 . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( oooo , IiI11I111 ) )
  return ( I111 )
  if 62 - 62: OoooooooOO / ooOoO0o + I1ii11iIi11i . o0oOOo0O0Ooo - iII111i
  if 29 - 29: oO0o
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 26 - 26: O0 % OOooOOo - IiII . OOooOOo
  OOo0O0 = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or OOo0O0 ) :
   Iiiii = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = Iiiii ) . start ( )
   if ( OOo0O0 ) : os . system ( "rm ./log-flows" )
   return
   if 8 - 8: iIii1I11I1II1 . iIii1I11I1II1 + Ii1I . OOooOOo
   if 58 - 58: iIii1I11I1II1 + I1Ii111 - I1ii11iIi11i - i1IIi * OoOoOO00
  i1 = datetime . datetime . now ( )
  lisp_flow_log . append ( [ i1 , encap , self . packet , self ] )
  if 4 - 4: OoooooooOO
  if 7 - 7: IiII
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  iII1iii = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 97 - 97: I1Ii111 / OOooOOo - i11iIiiIii
  OO0o0o = red ( self . outer_source . print_address_no_iid ( ) , False )
  O0O0O00OoO0O = red ( self . outer_dest . print_address_no_iid ( ) , False )
  i1II11III = green ( self . inner_source . print_address ( ) , False )
  O0OO0oo = green ( self . inner_dest . print_address ( ) , False )
  if 41 - 41: OoOoOO00 % I1Ii111 * oO0o * i1IIi
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   iII1iii += " {}:{} -> {}:{}, LISP control message type {}\n"
   iII1iii = iII1iii . format ( OO0o0o , self . udp_sport , O0O0O00OoO0O , self . udp_dport ,
 self . inner_version )
   return ( iII1iii )
   if 32 - 32: I1IiiI + i11iIiiIii - I1Ii111 / II111iiii
   if 27 - 27: ooOoO0o . Oo0Ooo + ooOoO0o + iII111i
  if ( self . outer_dest . is_null ( ) == False ) :
   iII1iii += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   iII1iii = iII1iii . format ( OO0o0o , self . udp_sport , O0O0O00OoO0O , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 28 - 28: OoO0O00 - ooOoO0o - oO0o % oO0o / O0
   if 99 - 99: II111iiii - iIii1I11I1II1
   if 24 - 24: I1IiiI - i1IIi - O0 % I1Ii111 - iIii1I11I1II1 . I11i
   if 26 - 26: OoO0O00 % i1IIi * O0 . I1Ii111
   if 31 - 31: O0 - IiII * i11iIiiIii * i1IIi
  if ( self . lisp_header . k_bits != 0 ) :
   O0oOo00Oo0oo0 = "\n"
   if ( self . packet_error != "" ) :
    O0oOo00Oo0oo0 = " ({})" . format ( self . packet_error ) + O0oOo00Oo0oo0
    if 36 - 36: I1Ii111 / I1Ii111 % oO0o
   iII1iii += ", encrypted" + O0oOo00Oo0oo0
   return ( iII1iii )
   if 97 - 97: OoooooooOO * o0oOOo0O0Ooo + OoooooooOO % Ii1I * Oo0Ooo
   if 35 - 35: iIii1I11I1II1 % iII111i - i1IIi
   if 20 - 20: I11i % ooOoO0o . OOooOOo / I1Ii111
   if 50 - 50: oO0o + i11iIiiIii / i11iIiiIii + ooOoO0o + I1Ii111
   if 65 - 65: ooOoO0o * O0 * iII111i
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 60 - 60: iIii1I11I1II1 . ooOoO0o + I1IiiI % oO0o
   if 4 - 4: I1IiiI / II111iiii % O0 * ooOoO0o / II111iiii . Oo0Ooo
  III1I1I1iiIi = packet [ 9 : 10 ] if self . inner_version == 4 else packet [ 6 : 7 ]
  III1I1I1iiIi = struct . unpack ( "B" , III1I1I1iiIi ) [ 0 ]
  if 16 - 16: O0 + O0 - I1IiiI
  iII1iii += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  iII1iii = iII1iii . format ( i1II11III , O0OO0oo , len ( packet ) , self . inner_tos ,
 self . inner_ttl , III1I1I1iiIi )
  if 30 - 30: ooOoO0o
  if 33 - 33: I1Ii111 * IiII - O0 + I1IiiI / IiII
  if 19 - 19: i1IIi % II111iiii
  if 85 - 85: IiII - o0oOOo0O0Ooo % OOooOOo - II111iiii
  if ( III1I1I1iiIi in [ 6 , 17 ] ) :
   o0o0OOooo0Oo = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( o0o0OOooo0Oo ) == 4 ) :
    o0o0OOooo0Oo = socket . ntohl ( struct . unpack ( "I" , o0o0OOooo0Oo ) [ 0 ] )
    iII1iii += ", ports {} -> {}" . format ( o0o0OOooo0Oo >> 16 , o0o0OOooo0Oo & 0xffff )
    if 48 - 48: o0oOOo0O0Ooo + I1ii11iIi11i / I1ii11iIi11i
  elif ( III1I1I1iiIi == 1 ) :
   oOO0o0o0 = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( oOO0o0o0 ) == 2 ) :
    oOO0o0o0 = socket . ntohs ( struct . unpack ( "H" , oOO0o0o0 ) [ 0 ] )
    iII1iii += ", icmp-seq {}" . format ( oOO0o0o0 )
    if 87 - 87: i11iIiiIii * II111iiii - Ii1I % OoooooooOO
    if 55 - 55: i1IIi
  if ( self . packet_error != "" ) :
   iII1iii += " ({})" . format ( self . packet_error )
   if 67 - 67: I1IiiI - OoO0O00
  iII1iii += "\n"
  return ( iII1iii )
  if 60 - 60: i1IIi / iIii1I11I1II1 * oO0o + ooOoO0o + OoooooooOO + II111iiii
  if 13 - 13: iIii1I11I1II1 - OOooOOo
 def is_trace ( self ) :
  o0o0OOooo0Oo = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in o0o0OOooo0Oo )
  if 14 - 14: ooOoO0o
  if 75 - 75: iIii1I11I1II1 % ooOoO0o / OOooOOo - iII111i % i11iIiiIii
  if 11 - 11: I11i . Ii1I
  if 87 - 87: OOooOOo + OOooOOo
  if 45 - 45: i1IIi - Oo0Ooo
  if 87 - 87: OoOoOO00 - OoO0O00 * OoO0O00 / Ii1I . I11i * o0oOOo0O0Ooo
  if 21 - 21: II111iiii
  if 29 - 29: OoOoOO00 % Ii1I
  if 7 - 7: i1IIi / IiII / iII111i
  if 97 - 97: OoO0O00 + iIii1I11I1II1
  if 79 - 79: ooOoO0o + oO0o - II111iiii . Oo0Ooo
  if 26 - 26: IiII
  if 52 - 52: O0 + ooOoO0o
  if 11 - 11: i1IIi / I1Ii111 * I1ii11iIi11i * I1Ii111 * ooOoO0o - i11iIiiIii
  if 96 - 96: I1ii11iIi11i % I1ii11iIi11i
  if 1 - 1: I1IiiI . Ii1I
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 26 - 26: oO0o - ooOoO0o % Oo0Ooo - oO0o + IiII
class lisp_data_header ( object ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
  if 21 - 21: O0 * ooOoO0o % OoO0O00
 def print_header ( self , e_or_d ) :
  Iii1 = lisp_hex_string ( self . first_long & 0xffffff )
  I11i1IiiI = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 75 - 75: OoOoOO00 / OoooooooOO / I11i % OoOoOO00 * Ii1I * IiII
  IiiiI1 = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 11 - 11: I1ii11iIi11i / OOooOOo . Ii1I * I1ii11iIi11i
  return ( IiiiI1 . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 Iii1 , I11i1IiiI ) )
  if 17 - 17: I1ii11iIi11i * OoooooooOO % i1IIi % OoooooooOO . iII111i
  if 20 - 20: OoO0O00 . oO0o
 def encode ( self ) :
  II111I11iI = "II"
  Iii1 = socket . htonl ( self . first_long )
  I11i1IiiI = socket . htonl ( self . second_long )
  if 18 - 18: OoooooooOO
  ooo = struct . pack ( II111I11iI , Iii1 , I11i1IiiI )
  return ( ooo )
  if 42 - 42: OoooooooOO % I11i % IiII
  if 54 - 54: ooOoO0o - I1IiiI - iII111i + OOooOOo - OoO0O00 / OoooooooOO
 def decode ( self , packet ) :
  II111I11iI = "II"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( False )
  if 20 - 20: OoOoOO00 % O0
  Iii1 , I11i1IiiI = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  if 59 - 59: O0 . o0oOOo0O0Ooo % I1ii11iIi11i * oO0o + I11i
  if 82 - 82: OoooooooOO
  self . first_long = socket . ntohl ( Iii1 )
  self . second_long = socket . ntohl ( I11i1IiiI )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 88 - 88: O0 / o0oOOo0O0Ooo * o0oOOo0O0Ooo . o0oOOo0O0Ooo . O0
  if 27 - 27: i11iIiiIii % iII111i + Ii1I . OOooOOo
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 9 - 9: OoO0O00
  if 43 - 43: Ii1I . OOooOOo + I1IiiI * i11iIiiIii
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 2 - 2: OOooOOo
  if 3 - 3: I1IiiI . iII111i % O0 - ooOoO0o / O0
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 79 - 79: Ii1I + oO0o % ooOoO0o % I1IiiI
  if 68 - 68: II111iiii - OoooooooOO / iIii1I11I1II1 - o0oOOo0O0Ooo % II111iiii
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 53 - 53: iII111i . oO0o / Oo0Ooo . OoO0O00 . i11iIiiIii
  if 60 - 60: II111iiii
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 25 - 25: Oo0Ooo + o0oOOo0O0Ooo - OoO0O00
  if 57 - 57: II111iiii . i1IIi
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 33 - 33: iII111i + Oo0Ooo % I11i . oO0o
  if 6 - 6: IiII + I1ii11iIi11i
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 62 - 62: oO0o . I1Ii111 - OoooooooOO * II111iiii . i11iIiiIii
  if 13 - 13: iIii1I11I1II1 * o0oOOo0O0Ooo - i11iIiiIii
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 63 - 63: OoooooooOO * I1Ii111
  if 50 - 50: Oo0Ooo - o0oOOo0O0Ooo % II111iiii . O0 . oO0o % II111iiii
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 18 - 18: I11i % OoooooooOO + OoO0O00 / I11i
  if 37 - 37: i1IIi - Ii1I / IiII . II111iiii % ooOoO0o
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 39 - 39: Ii1I % i11iIiiIii * OoO0O00
  if 23 - 23: OOooOOo + ooOoO0o / i11iIiiIii * Oo0Ooo . OoO0O00
  if 28 - 28: iII111i - o0oOOo0O0Ooo
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
  if 92 - 92: Oo0Ooo % o0oOOo0O0Ooo - ooOoO0o / ooOoO0o / OoOoOO00
  if 84 - 84: OOooOOo
 def send_ipc ( self , ipc_socket , ipc ) :
  I1 = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  I1i1iiIi = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , I1 )
  lisp_ipc ( ipc , ipc_socket , I1i1iiIi )
  if 24 - 24: Ii1I / iII111i + I1IiiI / Oo0Ooo % iIii1I11I1II1 / iIii1I11I1II1
  if 10 - 10: I11i - o0oOOo0O0Ooo % OoooooooOO - I1ii11iIi11i
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  oOoo = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , oOoo )
  if 89 - 89: ooOoO0o % oO0o * Ii1I - Oo0Ooo / o0oOOo0O0Ooo + OoO0O00
  if 56 - 56: i11iIiiIii * iII111i / i11iIiiIii * Ii1I . iIii1I11I1II1 . I1ii11iIi11i
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  oOoo = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , oOoo )
  if 93 - 93: OoOoOO00 + I11i
  if 27 - 27: iIii1I11I1II1 * I11i
 def receive_request ( self , ipc_socket , nonce ) :
  iiI1iiiii = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( iiI1iiiii != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 53 - 53: o0oOOo0O0Ooo / Oo0Ooo / iII111i + Ii1I - OoO0O00
  if 18 - 18: oO0o * O0 - I1IiiI + O0 + I1Ii111
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 80 - 80: OOooOOo
  if 12 - 12: Ii1I
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 2 - 2: OoooooooOO
  if 100 - 100: Oo0Ooo / O0 * i11iIiiIii * OoooooooOO
  if 46 - 46: O0 % OoooooooOO
  if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
  if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   I1IIiIIiiI1i = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 83 - 83: I1ii11iIi11i * II111iiii . I1Ii111 - I11i
   if 46 - 46: OoO0O00 % I1ii11iIi11i
   if ( remote_rloc . address > I1IIiIIiiI1i . address ) :
    OO0O00o0 = "exit"
    self . request_nonce_sent = None
   else :
    OO0O00o0 = "stay in"
    self . echo_nonce_sent = None
    if 58 - 58: oO0o + IiII % iII111i - Ii1I - OOooOOo % Ii1I
    if 86 - 86: o0oOOo0O0Ooo
   IIIiIi11 = bold ( "collision" , False )
   oOO0O0ooOOOo = red ( I1IIiIIiiI1i . print_address_no_iid ( ) , False )
   O00o00o00OO0 = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( IIIiIi11 ,
 oOO0O0ooOOOo , O00o00o00OO0 , OO0O00o0 ) )
   if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
   if 65 - 65: I1ii11iIi11i / ooOoO0o
   if 23 - 23: OOooOOo / OOooOOo * o0oOOo0O0Ooo * OOooOOo
   if 57 - 57: iII111i
   if 29 - 29: I1IiiI
  if ( self . echo_nonce_sent != None ) :
   oOooo0oOOOO = self . echo_nonce_sent
   oO0ooOOO = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( oO0ooOOO ,
 lisp_hex_string ( oOooo0oOOOO ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( oOooo0oOOOO )
   if 41 - 41: I1Ii111 * OoO0O00 - iII111i . Ii1I
   if 41 - 41: iIii1I11I1II1 - O0 - I1ii11iIi11i - oO0o + I1Ii111
   if 22 - 22: O0 % IiII % iII111i % I1IiiI
   if 34 - 34: iII111i . Oo0Ooo % I1ii11iIi11i . iII111i % IiII / IiII
   if 84 - 84: Ii1I
   if 1 - 1: oO0o - Oo0Ooo * iIii1I11I1II1 * Oo0Ooo * i1IIi
   if 9 - 9: iII111i - iII111i
  oOooo0oOOOO = self . request_nonce_sent
  IiIiIi = self . last_request_nonce_sent
  if ( oOooo0oOOOO and IiIiIi != None ) :
   if ( time . time ( ) - IiIiIi >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( oOooo0oOOOO ) ) )
    if 74 - 74: OoO0O00
    return ( None )
    if 18 - 18: I1ii11iIi11i / OoO0O00 + I11i . i1IIi
    if 28 - 28: OoOoOO00
    if 45 - 45: I11i . OoO0O00
    if 14 - 14: OOooOOo * I1IiiI - I1ii11iIi11i
    if 10 - 10: iII111i % I1Ii111 * I1ii11iIi11i * O0 * i11iIiiIii % I1Ii111
    if 68 - 68: OoooooooOO * OoOoOO00
    if 9 - 9: I1Ii111
    if 36 - 36: I1Ii111 / OoOoOO00 + OoOoOO00 * ooOoO0o / OOooOOo * O0
    if 17 - 17: OoO0O00 / ooOoO0o % I1IiiI
  if ( oOooo0oOOOO == None ) :
   oOooo0oOOOO = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( oOooo0oOOOO )
   if 47 - 47: Oo0Ooo * OoO0O00 / o0oOOo0O0Ooo * I1IiiI
   self . request_nonce_sent = oOooo0oOOOO
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( oOooo0oOOOO ) ) )
   if 60 - 60: I1ii11iIi11i / IiII . i11iIiiIii / OoO0O00 % II111iiii
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 6 - 6: iII111i % o0oOOo0O0Ooo + I1Ii111
   if 91 - 91: o0oOOo0O0Ooo + O0 * oO0o * IiII * I1ii11iIi11i
   if 83 - 83: OoooooooOO
   if 52 - 52: o0oOOo0O0Ooo / OoOoOO00 % oO0o % OoO0O00 / IiII % o0oOOo0O0Ooo
   if 88 - 88: OOooOOo / i11iIiiIii / Ii1I / i11iIiiIii * I1ii11iIi11i % I11i
   if ( lisp_i_am_itr == False ) : return ( oOooo0oOOOO | 0x80000000 )
   self . send_request_ipc ( ipc_socket , oOooo0oOOOO )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( oOooo0oOOOO ) ) )
   if 43 - 43: OoOoOO00 * OoO0O00 % i1IIi * Ii1I + iIii1I11I1II1
   if 80 - 80: o0oOOo0O0Ooo . iII111i . OoooooooOO
   if 63 - 63: ooOoO0o . OOooOOo
   if 66 - 66: I1IiiI
   if 99 - 99: OoO0O00 % O0 . I1Ii111 - I1ii11iIi11i . Oo0Ooo / OoOoOO00
   if 60 - 60: I1ii11iIi11i
   if 78 - 78: oO0o + II111iiii
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( oOooo0oOOOO | 0x80000000 )
  if 55 - 55: OoooooooOO
  if 90 - 90: I1IiiI
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 4 - 4: OOooOOo % ooOoO0o - OOooOOo - o0oOOo0O0Ooo
  i1i111Iiiiiii = time . time ( ) - self . last_request_nonce_sent
  iI1IIIiIII11 = self . last_echo_nonce_rcvd
  return ( i1i111Iiiiiii >= LISP_NONCE_ECHO_INTERVAL and iI1IIIiIII11 == None )
  if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
  if 20 - 20: i11iIiiIii - II111iiii - ooOoO0o % oO0o . ooOoO0o
 def recently_requested ( self ) :
  iI1IIIiIII11 = self . last_request_nonce_sent
  if ( iI1IIIiIII11 == None ) : return ( False )
  if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
  i1i111Iiiiiii = time . time ( ) - iI1IIIiIII11
  return ( i1i111Iiiiiii <= LISP_NONCE_ECHO_INTERVAL )
  if 84 - 84: OoOoOO00 - I11i
  if 80 - 80: i11iIiiIii % OOooOOo - Oo0Ooo % OOooOOo
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 89 - 89: Ii1I * I11i + OoOoOO00 / i11iIiiIii
  if 68 - 68: OoooooooOO * I11i
  if 86 - 86: o0oOOo0O0Ooo / OoOoOO00
  if 40 - 40: iII111i
  iI1IIIiIII11 = self . last_good_echo_nonce_rcvd
  if ( iI1IIIiIII11 == None ) : iI1IIIiIII11 = 0
  i1i111Iiiiiii = time . time ( ) - iI1IIIiIII11
  if ( i1i111Iiiiiii <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 62 - 62: ooOoO0o / OOooOOo
  if 74 - 74: iII111i % I1Ii111 / I1Ii111 - iIii1I11I1II1 - II111iiii + OOooOOo
  if 92 - 92: I11i % I1Ii111
  if 18 - 18: ooOoO0o + I1Ii111 / OOooOOo / oO0o + iIii1I11I1II1 % IiII
  if 94 - 94: I11i
  if 37 - 37: oO0o
  iI1IIIiIII11 = self . last_new_request_nonce_sent
  if ( iI1IIIiIII11 == None ) : iI1IIIiIII11 = 0
  i1i111Iiiiiii = time . time ( ) - iI1IIIiIII11
  return ( i1i111Iiiiiii <= LISP_NONCE_ECHO_INTERVAL )
  if 52 - 52: I1ii11iIi11i * I1IiiI . OOooOOo + i1IIi % oO0o / iIii1I11I1II1
  if 68 - 68: I1Ii111 - OoOoOO00 . i11iIiiIii + o0oOOo0O0Ooo
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   Oo0oo = bold ( "down" , False )
   iii1I = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , Oo0oo , iii1I ) )
   if 89 - 89: iII111i + i1IIi - IiII + ooOoO0o . II111iiii
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 85 - 85: iIii1I11I1II1 - Ii1I * Oo0Ooo . oO0o + I1Ii111
   if 13 - 13: O0 + iIii1I11I1II1 % II111iiii + iIii1I11I1II1
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 85 - 85: I1IiiI * iIii1I11I1II1 . iII111i / iII111i
  if ( self . recently_requested ( ) == False ) :
   i1I1I = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , i1I1I ) )
   if 45 - 45: OoOoOO00 / I1IiiI
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 34 - 34: o0oOOo0O0Ooo % I1ii11iIi11i + Ii1I * I11i / oO0o
   if 18 - 18: ooOoO0o
   if 92 - 92: OoO0O00 % iIii1I11I1II1 / IiII * iII111i . i1IIi + oO0o
 def print_echo_nonce ( self ) :
  I11OooOooOOooo0 = lisp_print_elapsed ( self . last_request_nonce_sent )
  o0OO00oOO = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 45 - 45: iIii1I11I1II1 - Oo0Ooo . I11i - Oo0Ooo / ooOoO0o / o0oOOo0O0Ooo
  o00oooo0 = lisp_print_elapsed ( self . last_echo_nonce_sent )
  iIi = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  I111 = space ( 4 )
  if 9 - 9: OoooooooOO / I11i
  oOo0OOoooO = "Nonce-Echoing:\n"
  oOo0OOoooO += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( I111 , I11OooOooOOooo0 , I111 , o0OO00oOO )
  if 47 - 47: OoooooooOO
  oOo0OOoooO += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( I111 , iIi , I111 , o00oooo0 )
  if 48 - 48: OoOoOO00 . IiII % I1IiiI + I11i
  if 37 - 37: Oo0Ooo + I1Ii111 * oO0o / o0oOOo0O0Ooo
  return ( oOo0OOoooO )
  if 78 - 78: IiII + I11i - o0oOOo0O0Ooo + OoO0O00 / iIii1I11I1II1
  if 47 - 47: OOooOOo
  if 20 - 20: I1Ii111 % ooOoO0o - I1Ii111 * OoooooooOO / I1ii11iIi11i
  if 57 - 57: IiII % I11i * OOooOOo % I1ii11iIi11i
  if 65 - 65: i1IIi - OoooooooOO
  if 66 - 66: I1ii11iIi11i / i1IIi * I1IiiI - OoOoOO00 + oO0o
  if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
  if 19 - 19: IiII % OoooooooOO + OoooooooOO
  if 7 - 7: i1IIi
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
    if 91 - 91: OoOoOO00 - OoOoOO00 . IiII
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   Ooo00o000o = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( Ooo00o000o . encode ( ) )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 33 - 33: I1Ii111 - iIii1I11I1II1 / Ii1I % O0
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 80 - 80: IiII % OoooooooOO - IiII
  if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 22 - 22: Oo0Ooo % OoooooooOO - Oo0Ooo - iII111i . Ii1I
  if 100 - 100: II111iiii / I1Ii111 / iII111i - I1ii11iIi11i * iIii1I11I1II1
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 7 - 7: i1IIi . IiII % i11iIiiIii * I1ii11iIi11i . I11i % I1ii11iIi11i
  OoOooO = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   OoOooO = struct . pack ( "Q" , OoOooO & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   iII1i = struct . pack ( "I" , ( OoOooO >> 64 ) & LISP_4_32_MASK )
   oO = struct . pack ( "Q" , OoOooO & LISP_8_64_MASK )
   OoOooO = iII1i + oO
  else :
   OoOooO = struct . pack ( "QQ" , OoOooO >> 64 , OoOooO & LISP_8_64_MASK )
  return ( OoOooO )
  if 48 - 48: O0 - ooOoO0o
  if 15 - 15: OoooooooOO
 def key_length ( self , key ) :
  if ( isinstance ( key , int ) ) : key = self . normalize_pub_key ( key )
  return ( old_div ( len ( key ) , 2 ) )
  if 16 - 16: OOooOOo . I11i
  if 47 - 47: O0 - I11i - O0
 def print_key ( self , key ) :
  Oooo0o0oO = self . normalize_pub_key ( key )
  iii = Oooo0o0oO [ 0 : 4 ] . decode ( )
  oO000oO0oO = Oooo0o0oO [ - 4 : : ] . decode ( )
  return ( "0x{}...{}({})" . format ( iii , oO000oO0oO , self . key_length ( Oooo0o0oO ) ) )
  if 44 - 44: OOooOOo - IiII + iII111i
  if 78 - 78: Ii1I
 def normalize_pub_key ( self , key ) :
  if ( isinstance ( key , int ) ) :
   key = lisp_hex_string ( key ) . zfill ( 256 )
   return ( key )
   if 29 - 29: II111iiii
  if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
  return ( key )
  if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
  if 84 - 84: Oo0Ooo % I11i * O0 * I11i
 def print_keys ( self , do_bold = True ) :
  oOO0O0ooOOOo = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   oOO0O0ooOOOo += "none"
  else :
   oOO0O0ooOOOo += self . print_key ( self . local_public_key )
   if 66 - 66: OOooOOo / iIii1I11I1II1 - OoOoOO00 % O0 . ooOoO0o
  O00o00o00OO0 = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   O00o00o00OO0 += "none"
  else :
   O00o00o00OO0 += self . print_key ( self . remote_public_key )
   if 12 - 12: Oo0Ooo + I1IiiI
  iii111i11IIii = "ECDH" if ( self . curve25519 ) else "DH"
  ii11I1iii = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( iii111i11IIii , ii11I1iii , oOO0O0ooOOOo , O00o00o00OO0 ) )
  if 29 - 29: I1IiiI * IiII / OOooOOo % oO0o
  if 23 - 23: i1IIi / oO0o . OoO0O00 * I1Ii111 + oO0o
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 37 - 37: O0 / OOooOOo + Oo0Ooo * OoooooooOO + OoOoOO00 / iIii1I11I1II1
  if 84 - 84: iIii1I11I1II1 + I1ii11iIi11i
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 77 - 77: i11iIiiIii - I1Ii111 . I1ii11iIi11i % Oo0Ooo . Ii1I
  Ooo00o000o = self . local_private_key
  Oo = self . dh_g_value
  iIIiiIi = self . dh_p_value
  return ( int ( ( Oo ** Ooo00o000o ) % iIIiiIi ) )
  if 9 - 9: o0oOOo0O0Ooo
  if 55 - 55: OOooOOo % iIii1I11I1II1 + I11i . ooOoO0o
 def compute_shared_key ( self , ed , print_shared = False ) :
  Ooo00o000o = self . local_private_key
  ooOo = self . remote_public_key
  if 47 - 47: i11iIiiIii . IiII
  Ii1i1 = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( Ii1i1 , self . print_keys ( ) ) )
  if 3 - 3: o0oOOo0O0Ooo / Oo0Ooo - OoO0O00 + II111iiii
  if ( self . curve25519 ) :
   ii = curve25519 . Public ( ooOo )
   self . shared_key = self . curve25519 . get_shared_key ( ii )
  else :
   iIIiiIi = self . dh_p_value
   self . shared_key = ( ooOo ** Ooo00o000o ) % iIIiiIi
   if 68 - 68: OoO0O00 / I1Ii111 % II111iiii + Oo0Ooo + O0 % I1ii11iIi11i
   if 53 - 53: OoOoOO00 % ooOoO0o . OoO0O00 + I1IiiI / I1ii11iIi11i
   if 76 - 76: I1ii11iIi11i . iIii1I11I1II1 - i11iIiiIii / I1ii11iIi11i - o0oOOo0O0Ooo
   if 95 - 95: I11i
   if 76 - 76: II111iiii - i1IIi . O0 * i11iIiiIii % o0oOOo0O0Ooo - iII111i
   if 30 - 30: I1Ii111 % oO0o + oO0o * OoooooooOO - I1ii11iIi11i
   if 69 - 69: I1ii11iIi11i + OoO0O00 / O0 + II111iiii / i11iIiiIii
  if ( print_shared ) :
   Oooo0o0oO = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( Oooo0o0oO ) )
   if 48 - 48: OoooooooOO / I1IiiI
   if 19 - 19: OOooOOo * I1ii11iIi11i - ooOoO0o * i11iIiiIii + I11i
   if 92 - 92: OoO0O00
   if 99 - 99: OoOoOO00 . iII111i - OoooooooOO - O0
   if 6 - 6: OOooOOo
  self . compute_encrypt_icv_keys ( )
  if 3 - 3: O0 - I1Ii111 * Ii1I * OOooOOo / Ii1I
  if 58 - 58: Ii1I * iIii1I11I1II1 + ooOoO0o . ooOoO0o
  if 74 - 74: ooOoO0o - o0oOOo0O0Ooo * IiII % ooOoO0o
  if 93 - 93: iIii1I11I1II1 / OoOoOO00 % Oo0Ooo * I1Ii111 - OoO0O00 - o0oOOo0O0Ooo
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 44 - 44: OoooooooOO
  if 82 - 82: OoOoOO00 . OoOoOO00
 def compute_encrypt_icv_keys ( self ) :
  IIiIiIii11I1 = hashlib . sha256
  if ( self . curve25519 ) :
   oo0O000OooO0 = self . shared_key
  else :
   oo0O000OooO0 = lisp_hex_string ( self . shared_key )
   if 26 - 26: OoO0O00 % i11iIiiIii + oO0o * II111iiii / IiII
   if 70 - 70: Oo0Ooo / I1Ii111 . IiII - OOooOOo
   if 65 - 65: IiII - I1Ii111
   if 71 - 71: Oo0Ooo - i1IIi
   if 27 - 27: OoOoOO00 . O0 / I1ii11iIi11i . iIii1I11I1II1
  oOO0O0ooOOOo = self . local_public_key
  if ( type ( oOO0O0ooOOOo ) != int ) : oOO0O0ooOOOo = int ( binascii . hexlify ( oOO0O0ooOOOo ) , 16 )
  O00o00o00OO0 = self . remote_public_key
  if ( type ( O00o00o00OO0 ) != int ) : O00o00o00OO0 = int ( binascii . hexlify ( O00o00o00OO0 ) , 16 )
  I11IIi = "0001" + "lisp-crypto" + lisp_hex_string ( oOO0O0ooOOOo ^ O00o00o00OO0 ) + "0100"
  if 51 - 51: i1IIi % o0oOOo0O0Ooo - oO0o - IiII
  i11IIII = hmac . new ( I11IIi . encode ( ) , oo0O000OooO0 , IIiIiIii11I1 ) . hexdigest ( )
  i11IIII = int ( i11IIII , 16 )
  if 7 - 7: iII111i / I1ii11iIi11i
  if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
  if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
  if 28 - 28: iIii1I11I1II1 . O0
  iiiI = ( i11IIII >> 128 ) & LISP_16_128_MASK
  iI111iiI1II = i11IIII & LISP_16_128_MASK
  iiiI = lisp_hex_string ( iiiI ) . zfill ( 32 )
  self . encrypt_key = iiiI . encode ( )
  OOOoooO000O0 = 32 if self . do_poly else 40
  iI111iiI1II = lisp_hex_string ( iI111iiI1II ) . zfill ( OOOoooO000O0 )
  self . icv_key = iI111iiI1II . encode ( )
  if 63 - 63: oO0o - iII111i - ooOoO0o / oO0o + I1Ii111 + Oo0Ooo
  if 32 - 32: I1IiiI . I1IiiI / iIii1I11I1II1 - I11i - O0 % OOooOOo
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   iI1Iii1i1I = self . icv . poly1305aes
   OoO0 = self . icv . binascii . hexlify
   nonce = OoO0 ( nonce )
   IIiIi = iI1Iii1i1I ( self . encrypt_key , self . icv_key , nonce , packet )
   if ( lisp_is_python2 ( ) ) :
    IIiIi = OoO0 ( IIiIi . encode ( "raw_unicode_escape" ) )
   else :
    IIiIi = OoO0 ( IIiIi ) . decode ( )
    if 60 - 60: iIii1I11I1II1 / I1ii11iIi11i - II111iiii / Oo0Ooo
  else :
   Ooo00o000o = binascii . unhexlify ( self . icv_key )
   IIiIi = hmac . new ( Ooo00o000o , packet , self . icv ) . hexdigest ( )
   IIiIi = IIiIi [ 0 : 40 ]
   if 38 - 38: I11i % OoO0O00 - O0 + II111iiii % Ii1I . I1IiiI
  return ( IIiIi )
  if 43 - 43: I1IiiI % I1ii11iIi11i * Ii1I
  if 31 - 31: Ii1I / iII111i
 def add_key_by_nonce ( self , nonce ) :
  if ( nonce not in lisp_crypto_keys_by_nonce ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 3 - 3: IiII
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 37 - 37: Ii1I * OoooooooOO * I11i + Oo0Ooo . I1IiiI
  if 61 - 61: OOooOOo . OOooOOo
 def delete_key_by_nonce ( self , nonce ) :
  if ( nonce not in lisp_crypto_keys_by_nonce ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 17 - 17: II111iiii / ooOoO0o
  if 80 - 80: OOooOOo * OoO0O00 + Ii1I
 def add_key_by_rloc ( self , addr_str , encap ) :
  oo0 = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 10 - 10: o0oOOo0O0Ooo * o0oOOo0O0Ooo * o0oOOo0O0Ooo
  if 39 - 39: Ii1I
  if ( addr_str not in oo0 ) :
   oo0 [ addr_str ] = [ None , None , None , None ]
   if 98 - 98: OoOoOO00
  oo0 [ addr_str ] [ self . key_id ] = self
  if 52 - 52: ooOoO0o % IiII . OoooooooOO
  if 60 - 60: Ii1I + iII111i . ooOoO0o + II111iiii + iII111i . O0
  if 74 - 74: o0oOOo0O0Ooo . Ii1I / i1IIi + I1ii11iIi11i + Ii1I + i11iIiiIii
  if 56 - 56: Oo0Ooo - o0oOOo0O0Ooo / iIii1I11I1II1 / Ii1I - IiII - Oo0Ooo
  if 76 - 76: OOooOOo . I1IiiI + OOooOOo + iIii1I11I1II1 + IiII / iIii1I11I1II1
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , oo0 [ addr_str ] )
   if 95 - 95: I11i
   if 45 - 45: I11i - OOooOOo * iII111i - OoO0O00 . Ii1I
   if 77 - 77: oO0o / I11i
 def encode_lcaf ( self , rloc_addr ) :
  iIIiiI1Ii1II = self . normalize_pub_key ( self . local_public_key )
  iIiI1 = self . key_length ( iIIiiI1Ii1II )
  IiIi11i1 = ( 6 + iIiI1 + 2 )
  if ( rloc_addr != None ) : IiIi11i1 += rloc_addr . addr_length ( )
  if 87 - 87: o0oOOo0O0Ooo % Oo0Ooo % II111iiii + iII111i * I1IiiI
  Oo00oo = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( IiIi11i1 ) , 1 , 0 )
  if 18 - 18: ooOoO0o * II111iiii
  if 43 - 43: o0oOOo0O0Ooo / O0 + i1IIi - I1ii11iIi11i % i11iIiiIii
  if 69 - 69: OOooOOo % I1ii11iIi11i / OoOoOO00 . OOooOOo - IiII
  if 74 - 74: OoO0O00 - o0oOOo0O0Ooo - IiII . O0 % ooOoO0o
  if 32 - 32: OoOoOO00 . OoO0O00 / Oo0Ooo . i11iIiiIii
  if 9 - 9: I11i - II111iiii + I1Ii111 / oO0o % I1ii11iIi11i
  ii11I1iii = self . cipher_suite
  Oo00oo += struct . pack ( "BBH" , ii11I1iii , 0 , socket . htons ( iIiI1 ) )
  if 17 - 17: iIii1I11I1II1 - ooOoO0o
  if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
  if 52 - 52: I1ii11iIi11i
  if 93 - 93: iII111i . i11iIiiIii
  for iIi1iIIIiIiI in range ( 0 , iIiI1 * 2 , 16 ) :
   Ooo00o000o = int ( iIIiiI1Ii1II [ iIi1iIIIiIiI : iIi1iIIIiIiI + 16 ] , 16 )
   Oo00oo += struct . pack ( "Q" , byte_swap_64 ( Ooo00o000o ) )
   if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
   if 49 - 49: O0 . Oo0Ooo / Ii1I
   if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
   if 86 - 86: I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
   if 20 - 20: iII111i . OoooooooOO + iII111i + ooOoO0o * I1ii11iIi11i
  if ( rloc_addr ) :
   Oo00oo += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   Oo00oo += rloc_addr . pack_address ( )
   if 44 - 44: i11iIiiIii
  return ( Oo00oo )
  if 69 - 69: OOooOOo * O0 + i11iIiiIii
  if 65 - 65: O0 / iII111i . i1IIi * iII111i / iIii1I11I1II1 - oO0o
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 93 - 93: OoOoOO00 % i11iIiiIii - Ii1I % OoO0O00
  if 55 - 55: o0oOOo0O0Ooo . I1ii11iIi11i
  if 63 - 63: oO0o
  if 79 - 79: I1ii11iIi11i - oO0o - o0oOOo0O0Ooo . OOooOOo
  if ( lcaf_len == 0 ) :
   II111I11iI = "HHBBH"
   oO000 = struct . calcsize ( II111I11iI )
   if ( len ( packet ) < oO000 ) : return ( None )
   if 65 - 65: i11iIiiIii . OoO0O00 % iII111i + IiII - i11iIiiIii
   Oooo000 , oo00O0OO0oo0O , IIiiIIi1II11 , oo00O0OO0oo0O , lcaf_len = struct . unpack ( II111I11iI , packet [ : oO000 ] )
   if 14 - 14: Ii1I - O0
   if 68 - 68: II111iiii - I1ii11iIi11i - OoO0O00 * iIii1I11I1II1 / I1IiiI * I1ii11iIi11i
   if ( IIiiIIi1II11 != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 45 - 45: I1Ii111 * I11i / iIii1I11I1II1 / I1IiiI % II111iiii
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ oO000 : : ]
   if 49 - 49: Ii1I / iII111i . iII111i . iII111i + i11iIiiIii % I11i
   if 7 - 7: IiII * ooOoO0o + OoOoOO00
   if 22 - 22: iII111i
   if 48 - 48: I1ii11iIi11i . I1IiiI
   if 73 - 73: O0 . I1Ii111 - OoooooooOO % I11i % i1IIi
   if 14 - 14: I1Ii111 + Ii1I * Oo0Ooo
  IIiiIIi1II11 = LISP_LCAF_SECURITY_TYPE
  II111I11iI = "BBBBH"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 49 - 49: Oo0Ooo
  OoO0O00o0ooo0 , oo00O0OO0oo0O , ii11I1iii , oo00O0OO0oo0O , iIiI1 = struct . unpack ( II111I11iI ,
 packet [ : oO000 ] )
  if 75 - 75: Ii1I % O0
  if 57 - 57: O0 . OoO0O00
  if 32 - 32: ooOoO0o
  if 26 - 26: O0 * Ii1I - I1IiiI - iII111i / iIii1I11I1II1
  if 57 - 57: I1ii11iIi11i - OoO0O00 * iIii1I11I1II1
  if 26 - 26: OoO0O00 % ooOoO0o % o0oOOo0O0Ooo % OoOoOO00 . iII111i % O0
  packet = packet [ oO000 : : ]
  iIiI1 = socket . ntohs ( iIiI1 )
  if ( len ( packet ) < iIiI1 ) : return ( None )
  if 91 - 91: II111iiii . Oo0Ooo . oO0o - OoooooooOO / OoOoOO00
  if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
  if 55 - 55: OoO0O00
  if 20 - 20: ooOoO0o * I1Ii111 * o0oOOo0O0Ooo - ooOoO0o
  i1I1IiiIIIiiI = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( ii11I1iii not in i1I1IiiIIIiiI ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( i1I1IiiIIIiiI ,
 ii11I1iii ) )
   packet = packet [ iIiI1 : : ]
   return ( packet )
   if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
   if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
  self . cipher_suite = ii11I1iii
  if 61 - 61: O0 . Ii1I . O0 * i11iIiiIii * II111iiii / I1Ii111
  if 69 - 69: I11i
  if 17 - 17: I11i
  if 38 - 38: I1Ii111 % OOooOOo
  if 9 - 9: O0 . iIii1I11I1II1
  iIIiiI1Ii1II = 0
  for iIi1iIIIiIiI in range ( 0 , iIiI1 , 8 ) :
   Ooo00o000o = byte_swap_64 ( struct . unpack ( "Q" , packet [ iIi1iIIIiIiI : iIi1iIIIiIiI + 8 ] ) [ 0 ] )
   iIIiiI1Ii1II <<= 64
   iIIiiI1Ii1II |= Ooo00o000o
   if 44 - 44: I1ii11iIi11i % IiII
  self . remote_public_key = iIIiiI1Ii1II
  if 6 - 6: OoO0O00
  if 82 - 82: iIii1I11I1II1 . I11i / IiII / OOooOOo * II111iiii % oO0o
  if 62 - 62: II111iiii
  if 96 - 96: I11i % OoOoOO00 * I1ii11iIi11i
  if 94 - 94: Oo0Ooo - i1IIi . O0 % Oo0Ooo . ooOoO0o
  if ( self . curve25519 ) :
   Ooo00o000o = lisp_hex_string ( self . remote_public_key )
   Ooo00o000o = Ooo00o000o . zfill ( 64 )
   Oo0OoO00OO0 = b""
   for iIi1iIIIiIiI in range ( 0 , len ( Ooo00o000o ) , 2 ) :
    oO000OO0 = int ( Ooo00o000o [ iIi1iIIIiIiI : iIi1iIIIiIiI + 2 ] , 16 )
    Oo0OoO00OO0 += lisp_store_byte ( oO000OO0 )
    if 96 - 96: i1IIi % I1ii11iIi11i + iIii1I11I1II1
   self . remote_public_key = Oo0OoO00OO0
   if 37 - 37: O0
   if 97 - 97: oO0o - OoO0O00 + iII111i * O0
  packet = packet [ iIiI1 : : ]
  return ( packet )
  if 55 - 55: i11iIiiIii + i1IIi % II111iiii + I11i % ooOoO0o
  if 67 - 67: I1ii11iIi11i / Oo0Ooo * i11iIiiIii / OoOoOO00
  if 38 - 38: I1IiiI . oO0o / O0 % Oo0Ooo / IiII / OoooooooOO
  if 11 - 11: O0 / I1Ii111 / iIii1I11I1II1 % Ii1I
  if 31 - 31: I11i . i11iIiiIii . OoO0O00 * Oo0Ooo % Ii1I . o0oOOo0O0Ooo
  if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
  if 93 - 93: ooOoO0o % I1Ii111
  if 46 - 46: I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
  if 43 - 43: ooOoO0o . i1IIi
def lisp_store_byte_py2 ( byte ) :
 return ( chr ( byte ) )
 if 68 - 68: IiII % Oo0Ooo . O0 - OoOoOO00 + I1ii11iIi11i . i11iIiiIii
def lisp_store_byte_py3 ( byte ) :
 return ( bytes ( [ byte ] ) )
 if 45 - 45: I1IiiI
 if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
lisp_store_byte = lisp_store_byte_py2
if ( lisp_is_python3 ( ) ) : lisp_store_byte = lisp_store_byte_py3
if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
if 61 - 61: Oo0Ooo - I1Ii111
if 51 - 51: iII111i * ooOoO0o / O0 / O0
if 52 - 52: OoooooooOO % O0
class lisp_thread ( object ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
  if 56 - 56: oO0o - i1IIi * OoooooooOO - II111iiii
  if 28 - 28: i1IIi / I11i . o0oOOo0O0Ooo
  if 11 - 11: Oo0Ooo * OoooooooOO - i11iIiiIii
  if 13 - 13: i11iIiiIii . O0 / OOooOOo * i1IIi
  if 14 - 14: IiII + IiII . I11i / Ii1I . iIii1I11I1II1
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
  if 15 - 15: iII111i / O0
  if 61 - 61: i1IIi / i1IIi + ooOoO0o . I1Ii111 * ooOoO0o
 def decode ( self , packet ) :
  II111I11iI = "BBBBQ"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( False )
  if 19 - 19: o0oOOo0O0Ooo . II111iiii / i1IIi
  Oo00 , o0OO00 , oOO00 , self . record_count , self . nonce = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  if 27 - 27: oO0o * Oo0Ooo * Oo0Ooo / IiII + Oo0Ooo
  if 94 - 94: ooOoO0o - i1IIi . O0 / I1IiiI
  self . type = Oo00 >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( Oo00 & 0x01 ) else False
   self . rloc_probe = True if ( Oo00 & 0x02 ) else False
   self . smr_invoked_bit = True if ( o0OO00 & 0x40 ) else False
   if 37 - 37: I1ii11iIi11i * I1Ii111 * I1IiiI * O0
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( Oo00 & 0x04 ) else False
   self . to_etr = True if ( Oo00 & 0x02 ) else False
   self . to_ms = True if ( Oo00 & 0x01 ) else False
   if 35 - 35: I1IiiI - I1ii11iIi11i * iII111i + IiII / i1IIi
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( Oo00 & 0x08 ) else False
   if 46 - 46: Oo0Ooo . ooOoO0o % Oo0Ooo / II111iiii * ooOoO0o * OOooOOo
  return ( True )
  if 59 - 59: I1Ii111 * iII111i
  if 31 - 31: I11i / O0
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 57 - 57: i1IIi % ooOoO0o
  if 69 - 69: o0oOOo0O0Ooo
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 69 - 69: I1Ii111
  if 83 - 83: iIii1I11I1II1 . o0oOOo0O0Ooo + I1Ii111 . OoooooooOO / ooOoO0o + II111iiii
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 90 - 90: Ii1I * iII111i / OOooOOo
  if 68 - 68: OoOoOO00
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 65 - 65: oO0o
  if 82 - 82: o0oOOo0O0Ooo
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 80 - 80: i1IIi % OoOoOO00 + OoO0O00 - OoooooooOO / iIii1I11I1II1 + I1Ii111
  if 65 - 65: Ii1I
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 71 - 71: I1Ii111 % I1Ii111 . oO0o + i11iIiiIii - i11iIiiIii
  if 16 - 16: iIii1I11I1II1 / I1IiiI / I1Ii111 - i11iIiiIii . ooOoO0o / OOooOOo
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 13 - 13: o0oOOo0O0Ooo % O0 - I1Ii111 * OoooooooOO / Oo0Ooo - OoooooooOO
  if 78 - 78: oO0o % OoooooooOO
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
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
  if 81 - 81: iII111i % Ii1I . ooOoO0o
  if 66 - 66: I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
 def print_map_register ( self ) :
  Iiooo000o0OoOo = lisp_hex_string ( self . xtr_id )
  if 76 - 76: Ii1I % iIii1I11I1II1 / oO0o * iIii1I11I1II1 / iIii1I11I1II1
  IiiiI1 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 41 - 41: IiII / i1IIi / OoOoOO00 / OOooOOo . OoO0O00 % OoOoOO00
  lprint ( IiiiI1 . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # IiII . OoOoOO00 . Ii1I - IiII / II111iiii . Oo0Ooo
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , Iiooo000o0OoOo , self . site_id ) )
  if 6 - 6: i1IIi / Ii1I - OoooooooOO % II111iiii . Ii1I * i11iIiiIii
  if 55 - 55: Ii1I * Ii1I % I1Ii111
  if 2 - 2: OoooooooOO . II111iiii % IiII
  if 6 - 6: I1Ii111 % IiII / Ii1I + I1Ii111 . oO0o
 def encode ( self ) :
  Iii1 = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : Iii1 |= 0x08000000
  if ( self . lisp_sec_present ) : Iii1 |= 0x04000000
  if ( self . xtr_id_present ) : Iii1 |= 0x02000000
  if ( self . map_register_refresh ) : Iii1 |= 0x1000
  if ( self . use_ttl_for_timeout ) : Iii1 |= 0x800
  if ( self . merge_register_requested ) : Iii1 |= 0x400
  if ( self . mobile_node ) : Iii1 |= 0x200
  if ( self . map_notify_requested ) : Iii1 |= 0x100
  if ( self . encryption_key_id != None ) :
   Iii1 |= 0x2000
   Iii1 |= self . encryption_key_id << 14
   if 70 - 70: iIii1I11I1II1 / Ii1I
   if 61 - 61: O0 * o0oOOo0O0Ooo + I1Ii111 - OOooOOo . I1IiiI - IiII
   if 7 - 7: I1ii11iIi11i
   if 81 - 81: Oo0Ooo % II111iiii % o0oOOo0O0Ooo / I11i
   if 95 - 95: OoOoOO00 - O0 % OoooooooOO
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 13 - 13: i11iIiiIii
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
    if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
    if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
  Oo00oo = struct . pack ( "I" , socket . htonl ( Iii1 ) )
  Oo00oo += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
  Oo00oo = self . zero_auth ( Oo00oo )
  return ( Oo00oo )
  if 69 - 69: Oo0Ooo * ooOoO0o
  if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
 def zero_auth ( self , packet ) :
  oo00 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  Ooooo0OO = b""
  o0o0OO0OO = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   Ooooo0OO = struct . pack ( "QQI" , 0 , 0 , 0 )
   o0o0OO0OO = struct . calcsize ( "QQI" )
   if 21 - 21: I1IiiI - OoooooooOO / OoOoOO00 * OoooooooOO % OoooooooOO + OoO0O00
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   Ooooo0OO = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   o0o0OO0OO = struct . calcsize ( "QQQQ" )
   if 89 - 89: iII111i . OOooOOo . I1ii11iIi11i
  packet = packet [ 0 : oo00 ] + Ooooo0OO + packet [ oo00 + o0o0OO0OO : : ]
  return ( packet )
  if 93 - 93: II111iiii
  if 8 - 8: Ii1I * OoooooooOO / Ii1I / OoO0O00 % OoOoOO00 + I11i
 def encode_auth ( self , packet ) :
  oo00 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  o0o0OO0OO = self . auth_len
  Ooooo0OO = self . auth_data
  packet = packet [ 0 : oo00 ] + Ooooo0OO + packet [ oo00 + o0o0OO0OO : : ]
  return ( packet )
  if 16 - 16: I11i % ooOoO0o - i11iIiiIii
  if 38 - 38: o0oOOo0O0Ooo / I1ii11iIi11i - O0
 def decode ( self , packet ) :
  i1iiI11i1 = packet
  II111I11iI = "I"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( [ None , None ] )
  if 9 - 9: iII111i . Oo0Ooo % OOooOOo / I11i * IiII - o0oOOo0O0Ooo
  Iii1 = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  Iii1 = socket . ntohl ( Iii1 [ 0 ] )
  packet = packet [ oO000 : : ]
  if 54 - 54: i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i / I1IiiI . iIii1I11I1II1 / iII111i
  II111I11iI = "QBBH"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( [ None , None ] )
  if 1 - 1: I1Ii111 / OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % Ii1I
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  if 96 - 96: IiII / Ii1I % OoO0O00 . iIii1I11I1II1
  if 30 - 30: I11i - OoO0O00
  self . nonce = byte_swap_64 ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( Iii1 & 0x08000000 ) else False
  if 15 - 15: OoooooooOO
  self . lisp_sec_present = True if ( Iii1 & 0x04000000 ) else False
  self . xtr_id_present = True if ( Iii1 & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( Iii1 & 0x800 ) else False
  self . map_register_refresh = True if ( Iii1 & 0x1000 ) else False
  self . merge_register_requested = True if ( Iii1 & 0x400 ) else False
  self . mobile_node = True if ( Iii1 & 0x200 ) else False
  self . map_notify_requested = True if ( Iii1 & 0x100 ) else False
  self . record_count = Iii1 & 0xff
  if 31 - 31: II111iiii
  if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
  if 87 - 87: IiII
  if 45 - 45: oO0o + II111iiii * O0 % OOooOOo . iIii1I11I1II1
  self . encrypt_bit = True if Iii1 & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( Iii1 >> 14 ) & 0x7
   if 55 - 55: IiII
   if 43 - 43: OOooOOo
   if 17 - 17: i11iIiiIii
   if 94 - 94: OoooooooOO - IiII + oO0o . OoooooooOO / i1IIi
   if 53 - 53: I1Ii111 % I1ii11iIi11i
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( i1iiI11i1 ) == False ) : return ( [ None , None ] )
   if 17 - 17: OoooooooOO % Ii1I % O0
   if 46 - 46: iII111i + I1Ii111 % OoooooooOO * I1ii11iIi11i
  packet = packet [ oO000 : : ]
  if 89 - 89: IiII - IiII % iII111i / I11i + oO0o - IiII
  if 97 - 97: Ii1I % OoOoOO00 / I1ii11iIi11i / iIii1I11I1II1 * OoooooooOO * OOooOOo
  if 80 - 80: oO0o / O0
  if 55 - 55: I1IiiI * I11i / O0 % OoOoOO00
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 71 - 71: i11iIiiIii * OoOoOO00 * OOooOOo + oO0o + Oo0Ooo
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 59 - 59: IiII
    if 54 - 54: OOooOOo
   o0o0OO0OO = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    oO000 = struct . calcsize ( "QQI" )
    if ( o0o0OO0OO < oO000 ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 27 - 27: OoOoOO00 - OoO0O00 + o0oOOo0O0Ooo + ooOoO0o . OoO0O00
    OoOo000o , iIIi1IiiiII1i , IIiIii1iiI = struct . unpack ( "QQI" , packet [ : o0o0OO0OO ] )
    o0oOOOOOO = b""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    oO000 = struct . calcsize ( "QQQQ" )
    if ( o0o0OO0OO < oO000 ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 31 - 31: Oo0Ooo / I1ii11iIi11i - O0 + iII111i - iII111i
    OoOo000o , iIIi1IiiiII1i , IIiIii1iiI , o0oOOOOOO = struct . unpack ( "QQQQ" ,
 packet [ : o0o0OO0OO ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 85 - 85: OoOoOO00
    return ( [ None , None ] )
    if 29 - 29: I1IiiI * I1ii11iIi11i + iII111i
   self . auth_data = lisp_concat_auth_data ( self . alg_id , OoOo000o , iIIi1IiiiII1i ,
 IIiIii1iiI , o0oOOOOOO )
   i1iiI11i1 = self . zero_auth ( i1iiI11i1 )
   packet = packet [ self . auth_len : : ]
   if 11 - 11: o0oOOo0O0Ooo % I1IiiI / Ii1I
  return ( [ i1iiI11i1 , packet ] )
  if 17 - 17: IiII % OoooooooOO / ooOoO0o * OoooooooOO
  if 14 - 14: II111iiii + O0 - iII111i
 def encode_xtr_id ( self , packet ) :
  II1i1 = self . xtr_id >> 64
  ooO0OoOO0 = self . xtr_id & 0xffffffffffffffff
  II1i1 = byte_swap_64 ( II1i1 )
  ooO0OoOO0 = byte_swap_64 ( ooO0OoOO0 )
  o0oo00 = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , II1i1 , ooO0OoOO0 , o0oo00 )
  return ( packet )
  if 92 - 92: i1IIi
  if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
 def decode_xtr_id ( self , packet ) :
  oO000 = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < oO000 ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - oO000 : : ]
  II1i1 , ooO0OoOO0 , o0oo00 = struct . unpack ( "QQQ" ,
 packet [ : oO000 ] )
  II1i1 = byte_swap_64 ( II1i1 )
  ooO0OoOO0 = byte_swap_64 ( ooO0OoOO0 )
  self . xtr_id = ( II1i1 << 64 ) | ooO0OoOO0
  self . site_id = byte_swap_64 ( o0oo00 )
  return ( True )
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
  if 97 - 97: Ii1I % i1IIi % IiII + Oo0Ooo - O0 - I11i
  if 64 - 64: Ii1I - iII111i
 def print_notify ( self ) :
  Ooooo0OO = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( Ooooo0OO ) != 40 ) :
   Ooooo0OO = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( Ooooo0OO ) != 64 ) :
   Ooooo0OO = self . auth_data
   if 12 - 12: i1IIi
  IiiiI1 = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( IiiiI1 . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # o0oOOo0O0Ooo + I1Ii111 / IiII - Ii1I . IiII - iII111i
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , Ooooo0OO ) )
  if 58 - 58: OoO0O00 * Oo0Ooo - IiII . I1ii11iIi11i * Ii1I / O0
  if 83 - 83: Ii1I - Ii1I
  if 47 - 47: OOooOOo % OOooOOo / I11i . i1IIi . I1ii11iIi11i
  if 2 - 2: IiII - I1IiiI * I1IiiI - I11i . O0 . o0oOOo0O0Ooo
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   Ooooo0OO = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 83 - 83: I11i * I1IiiI . II111iiii * i1IIi % O0
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   Ooooo0OO = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 35 - 35: OoOoOO00 % OoO0O00 + O0 * o0oOOo0O0Ooo % I1ii11iIi11i
  packet += Ooooo0OO
  return ( packet )
  if 57 - 57: oO0o / I11i
  if 63 - 63: ooOoO0o * OoO0O00 * ooOoO0o + OoOoOO00
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   Iii1 = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   Iii1 = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 25 - 25: iII111i * OoOoOO00 / I1IiiI / IiII
  Oo00oo = struct . pack ( "I" , socket . htonl ( Iii1 ) )
  Oo00oo += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 11 - 11: OOooOOo + i11iIiiIii
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = Oo00oo + eid_records
   return ( self . packet )
   if 14 - 14: OoOoOO00 / IiII + OoO0O00 - Ii1I
   if 38 - 38: I1Ii111
   if 30 - 30: II111iiii + I11i . i11iIiiIii + iIii1I11I1II1
   if 100 - 100: oO0o * o0oOOo0O0Ooo / iII111i
   if 92 - 92: ooOoO0o / i11iIiiIii * OOooOOo
  Oo00oo = self . zero_auth ( Oo00oo )
  Oo00oo += eid_records
  if 55 - 55: ooOoO0o
  oOOo0O0Oo = lisp_hash_me ( Oo00oo , self . alg_id , password , False )
  if 1 - 1: OoO0O00
  oo00 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  o0o0OO0OO = self . auth_len
  self . auth_data = oOOo0O0Oo
  Oo00oo = Oo00oo [ 0 : oo00 ] + oOOo0O0Oo + Oo00oo [ oo00 + o0o0OO0OO : : ]
  self . packet = Oo00oo
  return ( Oo00oo )
  if 43 - 43: iIii1I11I1II1 - OOooOOo - o0oOOo0O0Ooo + I1ii11iIi11i - I1Ii111 % I1ii11iIi11i
  if 58 - 58: OoOoOO00
 def decode ( self , packet ) :
  i1iiI11i1 = packet
  II111I11iI = "I"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 27 - 27: IiII * OOooOOo - OoooooooOO . Ii1I - II111iiii
  Iii1 = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  Iii1 = socket . ntohl ( Iii1 [ 0 ] )
  self . map_notify_ack = ( ( Iii1 >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = Iii1 & 0xff
  packet = packet [ oO000 : : ]
  if 62 - 62: I1IiiI / iIii1I11I1II1 * I11i
  II111I11iI = "QBBH"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 84 - 84: IiII - OoOoOO00 . IiII + ooOoO0o . iII111i
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  if 96 - 96: Ii1I % iII111i * Ii1I % I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ oO000 : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 7 - 7: OoO0O00 - ooOoO0o % i1IIi
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 24 - 24: OoO0O00 % O0 % I11i
  if 61 - 61: ooOoO0o . iII111i / ooOoO0o * OoooooooOO
  if 13 - 13: II111iiii
  if 17 - 17: II111iiii
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 66 - 66: IiII * oO0o
  o0o0OO0OO = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   OoOo000o , iIIi1IiiiII1i , IIiIii1iiI = struct . unpack ( "QQI" , packet [ : o0o0OO0OO ] )
   o0oOOOOOO = ""
   if 73 - 73: i11iIiiIii + O0 % O0
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   OoOo000o , iIIi1IiiiII1i , IIiIii1iiI , o0oOOOOOO = struct . unpack ( "QQQQ" ,
 packet [ : o0o0OO0OO ] )
   if 70 - 70: II111iiii * OoooooooOO - Ii1I + oO0o * O0
  self . auth_data = lisp_concat_auth_data ( self . alg_id , OoOo000o , iIIi1IiiiII1i ,
 IIiIii1iiI , o0oOOOOOO )
  if 49 - 49: oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
  oO000 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( i1iiI11i1 [ : oO000 ] )
  oO000 += o0o0OO0OO
  packet += i1iiI11i1 [ oO000 : : ]
  return ( packet )
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
  if 95 - 95: OoOoOO00 - i1IIi / I1Ii111 . ooOoO0o % OOooOOo - i1IIi
  if 12 - 12: iII111i
  if 96 - 96: O0
  if 89 - 89: I1ii11iIi11i - Oo0Ooo
  if 26 - 26: ooOoO0o % ooOoO0o / II111iiii / iII111i
  if 2 - 2: i1IIi / i11iIiiIii + I1IiiI
  if 95 - 95: I1ii11iIi11i / IiII % iIii1I11I1II1 + O0
  if 6 - 6: IiII
  if 73 - 73: o0oOOo0O0Ooo % o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i - Ii1I
  if 97 - 97: IiII
  if 15 - 15: O0 - I1IiiI / i1IIi . I1Ii111
  if 64 - 64: ooOoO0o / i1IIi
  if 100 - 100: II111iiii
  if 16 - 16: Ii1I
  if 96 - 96: o0oOOo0O0Ooo / I1Ii111 % Ii1I - ooOoO0o
  if 35 - 35: OOooOOo
  if 90 - 90: i11iIiiIii
  if 47 - 47: OoO0O00 . i11iIiiIii
  if 9 - 9: OoOoOO00 - I11i . OoooooooOO % ooOoO0o
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
  if 13 - 13: OoO0O00 * iIii1I11I1II1 + II111iiii - Oo0Ooo - OoOoOO00
  if 43 - 43: iII111i / I1Ii111 * I1IiiI % ooOoO0o % I1IiiI
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 18 - 18: OoO0O00
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 99 - 99: iII111i / oO0o . i11iIiiIii / I11i + i1IIi - I11i
  if 50 - 50: i1IIi
 def print_map_request ( self ) :
  Iiooo000o0OoOo = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   Iiooo000o0OoOo = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 56 - 56: OoO0O00 + I1Ii111 / Ii1I
   if 75 - 75: OoOoOO00
   if 96 - 96: o0oOOo0O0Ooo * I11i * Oo0Ooo
  IiiiI1 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 36 - 36: OoooooooOO + ooOoO0o . oO0o * ooOoO0o + IiII
  lprint ( IiiiI1 . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # II111iiii * OoOoOO00 - iII111i
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , Iiooo000o0OoOo ) )
  if 67 - 67: Oo0Ooo - ooOoO0o . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  iI1iiiiiii = self . keys
  for ii1oO0Oo in self . itr_rlocs :
   if ( ii1oO0Oo . afi == LISP_AFI_LCAF and self . json_telemetry != None ) :
    continue
    if 12 - 12: Ii1I
   iIIIi1Iii1 = red ( ii1oO0Oo . print_address_no_iid ( ) , False )
   lprint ( "  itr-rloc: afi {} {}{}" . format ( ii1oO0Oo . afi , iIIIi1Iii1 ,
 "" if ( iI1iiiiiii == None ) else ", " + iI1iiiiiii [ 1 ] . print_keys ( ) ) )
   iI1iiiiiii = None
   if 77 - 77: I11i
  if ( self . json_telemetry != None ) :
   lprint ( "  itr-rloc: afi {} telemetry: {}" . format ( LISP_AFI_LCAF ,
 self . json_telemetry ) )
   if 50 - 50: o0oOOo0O0Ooo - OoOoOO00
   if 1 - 1: i1IIi / Ii1I % IiII - I11i % o0oOOo0O0Ooo
   if 28 - 28: ooOoO0o - IiII + iII111i . ooOoO0o % OoooooooOO
 def sign_map_request ( self , privkey ) :
  IIi1i = self . signature_eid . print_address ( )
  oo0Oo0 = self . source_eid . print_address ( )
  i1I1ii1iI1 = self . target_eid . print_address ( )
  OoI1Ii = lisp_hex_string ( self . nonce ) + oo0Oo0 + i1I1ii1iI1
  self . map_request_signature = privkey . sign ( OoI1Ii . encode ( ) )
  IIIII1iII1 = binascii . b2a_base64 ( self . map_request_signature )
  IIIII1iII1 = { "source-eid" : oo0Oo0 , "signature-eid" : IIi1i ,
 "signature" : IIIII1iII1 . decode ( ) }
  return ( json . dumps ( IIIII1iII1 ) )
  if 77 - 77: oO0o % O0 % O0 - iII111i - iII111i - I1IiiI
  if 37 - 37: iIii1I11I1II1
 def verify_map_request_sig ( self , pubkey ) :
  iI1i = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( iI1i ) )
   return ( False )
   if 93 - 93: iII111i % i11iIiiIii - OoOoOO00 . Ii1I
   if 72 - 72: iIii1I11I1II1 * OOooOOo . iIii1I11I1II1
  oo0Oo0 = self . source_eid . print_address ( )
  i1I1ii1iI1 = self . target_eid . print_address ( )
  OoI1Ii = lisp_hex_string ( self . nonce ) + oo0Oo0 + i1I1ii1iI1
  pubkey = binascii . a2b_base64 ( pubkey )
  if 62 - 62: IiII . IiII % ooOoO0o - OoOoOO00 / OoooooooOO . I1IiiI
  i11i1I1 = True
  try :
   Ooo00o000o = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 72 - 72: IiII + i11iIiiIii - OOooOOo
   i11i1I1 = False
   if 67 - 67: iIii1I11I1II1 % IiII
   if 97 - 97: iII111i
  if ( i11i1I1 ) :
   try :
    OoI1Ii = OoI1Ii . encode ( )
    i11i1I1 = Ooo00o000o . verify ( self . map_request_signature , OoI1Ii )
   except :
    i11i1I1 = False
    if 40 - 40: ooOoO0o
    if 61 - 61: iII111i - OOooOOo / iII111i . Oo0Ooo % OoO0O00
    if 70 - 70: I1Ii111 * Oo0Ooo
  Oo0 = bold ( "passed" if i11i1I1 else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( Oo0 , iI1i ) )
  return ( i11i1I1 )
  if 84 - 84: Oo0Ooo % I1Ii111 . Oo0Ooo / ooOoO0o * Ii1I - IiII
  if 16 - 16: OOooOOo % IiII - II111iiii - o0oOOo0O0Ooo * i11iIiiIii / I1Ii111
 def encode_json ( self , json_string ) :
  IIiiIIi1II11 = LISP_LCAF_JSON_TYPE
  O0oooOoOO0O = socket . htons ( LISP_AFI_LCAF )
  ii111iIii1 = socket . htons ( len ( json_string ) + 4 )
  oo0O0OO = socket . htons ( len ( json_string ) )
  Oo00oo = struct . pack ( "HBBBBHH" , O0oooOoOO0O , 0 , 0 , IIiiIIi1II11 , 0 , ii111iIii1 ,
 oo0O0OO )
  Oo00oo += json_string . encode ( )
  Oo00oo += struct . pack ( "H" , 0 )
  return ( Oo00oo )
  if 96 - 96: I1IiiI / I11i
  if 92 - 92: o0oOOo0O0Ooo
 def encode ( self , probe_dest , probe_port ) :
  Iii1 = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  if 8 - 8: iII111i + I1ii11iIi11i . Ii1I
  ii1I11 = lisp_telemetry_configured ( ) if ( self . rloc_probe ) else None
  if ( ii1I11 != None ) : self . itr_rloc_count += 1
  Iii1 = Iii1 | ( self . itr_rloc_count << 8 )
  if 47 - 47: OoooooooOO + Ii1I
  if ( self . auth_bit ) : Iii1 |= 0x08000000
  if ( self . map_data_present ) : Iii1 |= 0x04000000
  if ( self . rloc_probe ) : Iii1 |= 0x02000000
  if ( self . smr_bit ) : Iii1 |= 0x01000000
  if ( self . pitr_bit ) : Iii1 |= 0x00800000
  if ( self . smr_invoked_bit ) : Iii1 |= 0x00400000
  if ( self . mobile_node ) : Iii1 |= 0x00200000
  if ( self . xtr_id_present ) : Iii1 |= 0x00100000
  if ( self . local_xtr ) : Iii1 |= 0x00004000
  if ( self . dont_reply_bit ) : Iii1 |= 0x00002000
  if 44 - 44: Ii1I * OoOoOO00 + Oo0Ooo . i11iIiiIii + i1IIi
  Oo00oo = struct . pack ( "I" , socket . htonl ( Iii1 ) )
  Oo00oo += struct . pack ( "Q" , self . nonce )
  if 83 - 83: iII111i + OoOoOO00 % ooOoO0o
  if 76 - 76: i1IIi % I1IiiI + i1IIi
  if 2 - 2: iII111i + iII111i
  if 51 - 51: OoooooooOO + i11iIiiIii
  if 57 - 57: Oo0Ooo % o0oOOo0O0Ooo
  if 99 - 99: o0oOOo0O0Ooo / i11iIiiIii / II111iiii + OOooOOo . i1IIi + OoOoOO00
  II11 = False
  iIiOOO0oo0OO0o0 = self . privkey_filename
  if ( iIiOOO0oo0OO0o0 != None and os . path . exists ( iIiOOO0oo0OO0o0 ) ) :
   OOoO0 = open ( iIiOOO0oo0OO0o0 , "r" ) ; Ooo00o000o = OOoO0 . read ( ) ; OOoO0 . close ( )
   try :
    Ooo00o000o = ecdsa . SigningKey . from_pem ( Ooo00o000o )
   except :
    return ( None )
    if 78 - 78: I11i - I1IiiI * IiII
   iio0O0OOo = self . sign_map_request ( Ooo00o000o )
   II11 = True
  elif ( self . map_request_signature != None ) :
   IIIII1iII1 = binascii . b2a_base64 ( self . map_request_signature )
   iio0O0OOo = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : IIIII1iII1 }
   iio0O0OOo = json . dumps ( iio0O0OOo )
   II11 = True
   if 44 - 44: I11i
  if ( II11 ) :
   Oo00oo += self . encode_json ( iio0O0OOo )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    Oo00oo += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    Oo00oo += self . source_eid . lcaf_encode_iid ( )
   else :
    Oo00oo += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    Oo00oo += self . source_eid . pack_address ( )
    if 3 - 3: iIii1I11I1II1 - i1IIi / iII111i + i1IIi + O0
    if 18 - 18: iIii1I11I1II1 . iII111i % OOooOOo % oO0o + iIii1I11I1II1 * OoooooooOO
    if 78 - 78: IiII
    if 38 - 38: OoO0O00 * I1ii11iIi11i
    if 4 - 4: OoO0O00 . I1ii11iIi11i
    if 21 - 21: i11iIiiIii / OoO0O00 / I1ii11iIi11i * O0 - II111iiii * OOooOOo
    if 27 - 27: o0oOOo0O0Ooo . OoOoOO00 * Ii1I * iII111i * O0
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   O0O0 = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 93 - 93: IiII % I1Ii111 % II111iiii
   if ( O0O0 in lisp_crypto_keys_by_rloc_encap ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ O0O0 ]
    if 20 - 20: OoooooooOO * I1Ii111
    if 38 - 38: iII111i . OoooooooOO
    if 28 - 28: I1Ii111 * i1IIi . I1ii11iIi11i
    if 75 - 75: O0 / oO0o * ooOoO0o - OOooOOo / i1IIi
    if 61 - 61: I11i
    if 100 - 100: O0 - iIii1I11I1II1 * Oo0Ooo
    if 35 - 35: ooOoO0o
  for ii1oO0Oo in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( ii1oO0Oo ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     iI1iiiiiii = lisp_keys ( 1 )
     self . keys = [ None , iI1iiiiiii , None , None ]
     if 57 - 57: OoO0O00 . Oo0Ooo + I1IiiI
    iI1iiiiiii = self . keys [ 1 ]
    iI1iiiiiii . add_key_by_nonce ( self . nonce )
    Oo00oo += iI1iiiiiii . encode_lcaf ( ii1oO0Oo )
   else :
    Oo00oo += struct . pack ( "H" , socket . htons ( ii1oO0Oo . afi ) )
    Oo00oo += ii1oO0Oo . pack_address ( )
    if 18 - 18: I1IiiI - I1ii11iIi11i * I11i / i11iIiiIii - o0oOOo0O0Ooo % o0oOOo0O0Ooo
    if 31 - 31: I11i
    if 100 - 100: i11iIiiIii * i11iIiiIii . iIii1I11I1II1 % iII111i * I1ii11iIi11i
    if 17 - 17: Ii1I * IiII * i11iIiiIii / I1ii11iIi11i / i11iIiiIii
    if 23 - 23: OoooooooOO + i11iIiiIii / Oo0Ooo / iII111i . iII111i * I1IiiI
    if 98 - 98: IiII
  if ( ii1I11 != None ) :
   i1 = str ( time . time ( ) )
   ii1I11 = lisp_encode_telemetry ( ii1I11 , io = i1 )
   self . json_telemetry = ii1I11
   Oo00oo += self . encode_json ( ii1I11 )
   if 23 - 23: I11i / i1IIi * OoO0O00
   if 51 - 51: OOooOOo - OoooooooOO / OoooooooOO % OoooooooOO
  oOo = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 54 - 54: o0oOOo0O0Ooo % iIii1I11I1II1 - iII111i
  if 79 - 79: IiII . Ii1I . Oo0Ooo % oO0o * oO0o
  oOoO = 0
  if ( self . subscribe_bit ) :
   oOoO = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 31 - 31: I1Ii111 . I1ii11iIi11i + IiII
    if 65 - 65: I1IiiI * O0 * Oo0Ooo . O0
    if 23 - 23: OoO0O00 / IiII * II111iiii
  II111I11iI = "BB"
  Oo00oo += struct . pack ( II111I11iI , oOoO , oOo )
  if 32 - 32: I1Ii111 - iIii1I11I1II1 / I11i * OoO0O00 * OoO0O00
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
   if 77 - 77: I1ii11iIi11i
   if 16 - 16: II111iiii - II111iiii * I11i / OOooOOo . IiII
   if 36 - 36: I11i / iIii1I11I1II1
   if 59 - 59: i1IIi
   if 85 - 85: I1Ii111 + iIii1I11I1II1 + ooOoO0o + Oo0Ooo
  if ( self . subscribe_bit ) : Oo00oo = self . encode_xtr_id ( Oo00oo )
  return ( Oo00oo )
  if 75 - 75: O0 . I11i - Ii1I / I1Ii111 / I1ii11iIi11i % I11i
  if 97 - 97: OoOoOO00 - OoO0O00
 def lcaf_decode_json ( self , packet ) :
  II111I11iI = "BBBBHH"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 64 - 64: i1IIi / OoooooooOO / I1ii11iIi11i - Oo0Ooo + oO0o
  iI1i1II11I , OoO0o0oOOoOoo , IIiiIIi1II11 , I1iIiiiI1II1 , ii111iIii1 , oo0O0OO = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  if 94 - 94: ooOoO0o % I1ii11iIi11i + OoooooooOO
  if 77 - 77: O0 - Ii1I * II111iiii / I1ii11iIi11i / Ii1I - oO0o
  if ( IIiiIIi1II11 != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 66 - 66: OoO0O00 % Oo0Ooo . II111iiii
  if 84 - 84: ooOoO0o * OoooooooOO + O0
  if 84 - 84: i1IIi . I11i . i1IIi . Oo0Ooo
  if 21 - 21: II111iiii . O0 + Oo0Ooo - i11iIiiIii
  ii111iIii1 = socket . ntohs ( ii111iIii1 )
  oo0O0OO = socket . ntohs ( oo0O0OO )
  packet = packet [ oO000 : : ]
  if ( len ( packet ) < ii111iIii1 ) : return ( None )
  if ( ii111iIii1 != oo0O0OO + 4 ) : return ( None )
  if 5 - 5: iIii1I11I1II1 * i11iIiiIii + OoO0O00 + I11i * O0 % ooOoO0o
  if 88 - 88: o0oOOo0O0Ooo / i11iIiiIii * I1ii11iIi11i
  if 23 - 23: O0 / iII111i
  if 66 - 66: i1IIi % OoooooooOO * i11iIiiIii + oO0o * O0 / OoO0O00
  iio0O0OOo = packet [ 0 : oo0O0OO ]
  packet = packet [ oo0O0OO : : ]
  if 14 - 14: I1IiiI . IiII
  if 29 - 29: OoooooooOO / IiII + OoOoOO00 - I1Ii111 + IiII . i1IIi
  if 26 - 26: i11iIiiIii - II111iiii
  if 43 - 43: I1IiiI
  if ( lisp_is_json_telemetry ( iio0O0OOo ) != None ) :
   self . json_telemetry = iio0O0OOo
   if 35 - 35: ooOoO0o + OoOoOO00 * OoooooooOO - II111iiii
   if 19 - 19: i1IIi / Ii1I / OoOoOO00 . I1IiiI / Ii1I % o0oOOo0O0Ooo
   if 39 - 39: ooOoO0o - OoooooooOO
   if 88 - 88: i1IIi + iIii1I11I1II1 * i11iIiiIii - OoooooooOO % o0oOOo0O0Ooo
   if 74 - 74: ooOoO0o - i11iIiiIii
  II111I11iI = "H"
  oO000 = struct . calcsize ( II111I11iI )
  Oooo000 = struct . unpack ( II111I11iI , packet [ : oO000 ] ) [ 0 ]
  packet = packet [ oO000 : : ]
  if ( Oooo000 != 0 ) : return ( packet )
  if 34 - 34: IiII + I1Ii111 + Oo0Ooo / II111iiii
  if ( self . json_telemetry != None ) : return ( packet )
  if 33 - 33: Ii1I . i1IIi - II111iiii - OoO0O00
  if 31 - 31: I11i - OoOoOO00 / o0oOOo0O0Ooo * OoOoOO00 / Oo0Ooo + o0oOOo0O0Ooo
  if 46 - 46: IiII * OoO0O00 / OOooOOo + Oo0Ooo
  if 24 - 24: ooOoO0o % OOooOOo . O0 * Oo0Ooo
  try :
   iio0O0OOo = json . loads ( iio0O0OOo )
  except :
   return ( None )
   if 52 - 52: O0 . I1Ii111 + iII111i / i11iIiiIii
   if 52 - 52: oO0o % Oo0Ooo * II111iiii
   if 24 - 24: i11iIiiIii * i1IIi * i1IIi
   if 27 - 27: i1IIi - oO0o + OOooOOo
   if 3 - 3: IiII % I1Ii111 . OoooooooOO
  if ( "source-eid" not in iio0O0OOo ) : return ( packet )
  i1I1I1IIIi11 = iio0O0OOo [ "source-eid" ]
  Oooo000 = LISP_AFI_IPV4 if i1I1I1IIIi11 . count ( "." ) == 3 else LISP_AFI_IPV6 if i1I1I1IIIi11 . count ( ":" ) == 7 else None
  if 81 - 81: OoOoOO00
  if ( Oooo000 == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( i1I1I1IIIi11 ) )
   return ( None )
   if 21 - 21: iII111i / OOooOOo % IiII
   if 51 - 51: I11i + ooOoO0o / I1IiiI
  self . source_eid . afi = Oooo000
  self . source_eid . store_address ( i1I1I1IIIi11 )
  if 3 - 3: iIii1I11I1II1 / OOooOOo % oO0o . Ii1I - Ii1I
  if ( "signature-eid" not in iio0O0OOo ) : return ( packet )
  i1I1I1IIIi11 = iio0O0OOo [ "signature-eid" ]
  if ( i1I1I1IIIi11 . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( i1I1I1IIIi11 ) )
   return ( None )
   if 55 - 55: i11iIiiIii % OoooooooOO + O0
   if 7 - 7: ooOoO0o - i11iIiiIii * iII111i / Ii1I - o0oOOo0O0Ooo
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( i1I1I1IIIi11 )
  if 62 - 62: o0oOOo0O0Ooo - iIii1I11I1II1 . I11i . Ii1I * Ii1I
  if ( "signature" not in iio0O0OOo ) : return ( packet )
  IIIII1iII1 = binascii . a2b_base64 ( iio0O0OOo [ "signature" ] )
  self . map_request_signature = IIIII1iII1
  return ( packet )
  if 24 - 24: I11i
  if 93 - 93: I1IiiI % OoO0O00 / i11iIiiIii / I11i
 def decode ( self , packet , source , port ) :
  II111I11iI = "I"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 60 - 60: ooOoO0o - Ii1I . I1IiiI * oO0o * i11iIiiIii
  Iii1 = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  Iii1 = Iii1 [ 0 ]
  packet = packet [ oO000 : : ]
  if 29 - 29: OoO0O00 - Oo0Ooo . oO0o / OoO0O00 % i11iIiiIii
  II111I11iI = "Q"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 26 - 26: ooOoO0o . I1Ii111 / II111iiii % Ii1I
  oOooo0oOOOO = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  packet = packet [ oO000 : : ]
  if 82 - 82: OOooOOo % O0 % iIii1I11I1II1 % IiII + i11iIiiIii
  Iii1 = socket . ntohl ( Iii1 )
  self . auth_bit = True if ( Iii1 & 0x08000000 ) else False
  self . map_data_present = True if ( Iii1 & 0x04000000 ) else False
  self . rloc_probe = True if ( Iii1 & 0x02000000 ) else False
  self . smr_bit = True if ( Iii1 & 0x01000000 ) else False
  self . pitr_bit = True if ( Iii1 & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( Iii1 & 0x00400000 ) else False
  self . mobile_node = True if ( Iii1 & 0x00200000 ) else False
  self . xtr_id_present = True if ( Iii1 & 0x00100000 ) else False
  self . local_xtr = True if ( Iii1 & 0x00004000 ) else False
  self . dont_reply_bit = True if ( Iii1 & 0x00002000 ) else False
  self . itr_rloc_count = ( ( Iii1 >> 8 ) & 0x1f )
  self . record_count = Iii1 & 0xff
  self . nonce = oOooo0oOOOO [ 0 ]
  if 64 - 64: i1IIi / IiII . IiII - I1Ii111 % OOooOOo . II111iiii
  if 78 - 78: I1Ii111 - O0 - I1Ii111 . iIii1I11I1II1 % I1ii11iIi11i . OoooooooOO
  if 64 - 64: IiII
  if 21 - 21: o0oOOo0O0Ooo - ooOoO0o * OoooooooOO . OoooooooOO
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 17 - 17: OOooOOo - iII111i % I1IiiI * OOooOOo * iIii1I11I1II1 . o0oOOo0O0Ooo
   if 58 - 58: oO0o - II111iiii + O0
  oO000 = struct . calcsize ( "H" )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 54 - 54: iIii1I11I1II1 - IiII - IiII
  Oooo000 = struct . unpack ( "H" , packet [ : oO000 ] )
  self . source_eid . afi = socket . ntohs ( Oooo000 [ 0 ] )
  packet = packet [ oO000 : : ]
  if 18 - 18: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   o00O00oo0 = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( o00O00oo0 )
    if ( packet == None ) : return ( None )
    if 39 - 39: I1IiiI - iII111i - i11iIiiIii + OoooooooOO
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 74 - 74: OOooOOo - II111iiii
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 66 - 66: i11iIiiIii + I1Ii111 . ooOoO0o
  i1II = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  OO0o = self . itr_rloc_count + 1
  if 92 - 92: iIii1I11I1II1 + Ii1I
  while ( OO0o != 0 ) :
   oO000 = struct . calcsize ( "H" )
   if ( len ( packet ) < oO000 ) : return ( None )
   if 69 - 69: Oo0Ooo
   Oooo000 = socket . ntohs ( struct . unpack ( "H" , packet [ : oO000 ] ) [ 0 ] )
   ii1oO0Oo = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   ii1oO0Oo . afi = Oooo000
   if 70 - 70: O0 - OoO0O00 - Oo0Ooo
   if 95 - 95: IiII * II111iiii % o0oOOo0O0Ooo * Oo0Ooo . I11i
   if 46 - 46: II111iiii - OoO0O00 % ooOoO0o
   if 97 - 97: OoO0O00 . OoOoOO00
   if 78 - 78: I1ii11iIi11i + I1ii11iIi11i . OoOoOO00 - IiII * iIii1I11I1II1 * O0
   if ( ii1oO0Oo . afi == LISP_AFI_LCAF ) :
    i1iiI11i1 = packet
    IiIIiI = packet [ oO000 : : ]
    packet = self . lcaf_decode_json ( IiIIiI )
    if ( packet == None ) : return ( None )
    if ( packet == IiIIiI ) : packet = i1iiI11i1
    if 8 - 8: I1ii11iIi11i * IiII / Oo0Ooo
    if 99 - 99: OOooOOo * I1Ii111 . ooOoO0o - i1IIi - I11i % IiII
    if 40 - 40: OoOoOO00 % I1Ii111 / I1IiiI + i1IIi
    if 53 - 53: I1Ii111
    if 81 - 81: O0 % o0oOOo0O0Ooo / Ii1I / ooOoO0o . i11iIiiIii + IiII
    if 29 - 29: ooOoO0o
   if ( ii1oO0Oo . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < ii1oO0Oo . addr_length ( ) ) : return ( None )
    packet = ii1oO0Oo . unpack_address ( packet [ oO000 : : ] )
    if ( packet == None ) : return ( None )
    if 70 - 70: oO0o . O0 % I11i % IiII - I11i * I1ii11iIi11i
    if ( i1II ) :
     self . itr_rlocs . append ( ii1oO0Oo )
     OO0o -= 1
     continue
     if 22 - 22: i1IIi
     if 82 - 82: oO0o . iIii1I11I1II1 - I1ii11iIi11i
    O0O0 = lisp_build_crypto_decap_lookup_key ( ii1oO0Oo , port )
    if 55 - 55: Oo0Ooo % Ii1I . iIii1I11I1II1 * I1Ii111
    if 33 - 33: O0 - I1IiiI / I1ii11iIi11i / OoO0O00 + iII111i - oO0o
    if 27 - 27: I1Ii111 + ooOoO0o - I1Ii111 % i11iIiiIii * Oo0Ooo * o0oOOo0O0Ooo
    if 88 - 88: OOooOOo
    if 25 - 25: OoO0O00 + o0oOOo0O0Ooo . ooOoO0o - Ii1I . oO0o * Ii1I
    if ( lisp_nat_traversal and ii1oO0Oo . is_private_address ( ) and source ) : ii1oO0Oo = source
    if 85 - 85: i1IIi
    oooiiIiIIIi1 = lisp_crypto_keys_by_rloc_decap
    if ( O0O0 in oooiiIiIIIi1 ) : oooiiIiIIIi1 . pop ( O0O0 )
    if 35 - 35: I1ii11iIi11i . OOooOOo
    if 97 - 97: I1IiiI
    if 63 - 63: O0 - OoOoOO00 / i11iIiiIii / OoooooooOO / ooOoO0o / II111iiii
    if 45 - 45: II111iiii . OoO0O00 + OoO0O00 * iIii1I11I1II1
    if 23 - 23: IiII * OoOoOO00 % Ii1I / Ii1I - ooOoO0o - OOooOOo
    if 86 - 86: OOooOOo . OoooooooOO * I1IiiI - Oo0Ooo / i11iIiiIii * iII111i
    lisp_write_ipc_decap_key ( O0O0 , None )
    if 56 - 56: I1IiiI . I11i % iII111i
   elif ( self . json_telemetry == None ) :
    if 33 - 33: I11i / OOooOOo - OOooOOo / i11iIiiIii * OoOoOO00 + O0
    if 2 - 2: i11iIiiIii % I1IiiI
    if 90 - 90: II111iiii
    if 2 - 2: Ii1I - OoooooooOO - i11iIiiIii % Oo0Ooo / Ii1I
    i1iiI11i1 = packet
    OO = lisp_keys ( 1 )
    packet = OO . decode_lcaf ( i1iiI11i1 , 0 )
    if 92 - 92: I1Ii111 + OOooOOo - OoO0O00 . o0oOOo0O0Ooo
    if ( packet == None ) : return ( None )
    if 16 - 16: I1IiiI - ooOoO0o
    if 39 - 39: i1IIi % i1IIi / iIii1I11I1II1 % OoooooooOO . ooOoO0o
    if 30 - 30: o0oOOo0O0Ooo - Ii1I . i11iIiiIii + oO0o % ooOoO0o + I1ii11iIi11i
    if 5 - 5: OOooOOo . iII111i . oO0o % IiII * O0
    i1I1IiiIIIiiI = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( OO . cipher_suite in i1I1IiiIIIiiI ) :
     if ( OO . cipher_suite == LISP_CS_25519_CBC or
 OO . cipher_suite == LISP_CS_25519_GCM ) :
      Ooo00o000o = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 20 - 20: Oo0Ooo . I1IiiI . I1IiiI / OoooooooOO . OoooooooOO + iIii1I11I1II1
     if ( OO . cipher_suite == LISP_CS_25519_CHACHA ) :
      Ooo00o000o = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 60 - 60: OoOoOO00 / ooOoO0o % iIii1I11I1II1
    else :
     Ooo00o000o = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 32 - 32: i11iIiiIii + II111iiii + II111iiii % I11i
    packet = Ooo00o000o . decode_lcaf ( i1iiI11i1 , 0 )
    if ( packet == None ) : return ( None )
    if 96 - 96: o0oOOo0O0Ooo
    if ( len ( packet ) < oO000 ) : return ( None )
    Oooo000 = struct . unpack ( "H" , packet [ : oO000 ] ) [ 0 ]
    ii1oO0Oo . afi = socket . ntohs ( Oooo000 )
    if ( len ( packet ) < ii1oO0Oo . addr_length ( ) ) : return ( None )
    if 90 - 90: IiII * Ii1I . I11i / I1ii11iIi11i % I11i
    packet = ii1oO0Oo . unpack_address ( packet [ oO000 : : ] )
    if ( packet == None ) : return ( None )
    if 58 - 58: iII111i % iIii1I11I1II1 * OoO0O00
    if ( i1II ) :
     self . itr_rlocs . append ( ii1oO0Oo )
     OO0o -= 1
     continue
     if 25 - 25: I1Ii111 - ooOoO0o + Oo0Ooo . I1IiiI % iIii1I11I1II1
     if 49 - 49: i1IIi + OoO0O00 + iII111i / Oo0Ooo
    O0O0 = lisp_build_crypto_decap_lookup_key ( ii1oO0Oo , port )
    if 5 - 5: i11iIiiIii + I11i . IiII
    IiIi1 = None
    if ( lisp_nat_traversal and ii1oO0Oo . is_private_address ( ) and source ) : ii1oO0Oo = source
    if 59 - 59: O0 * oO0o % iIii1I11I1II1 . oO0o
    if 34 - 34: OoOoOO00 % OoOoOO00 + i1IIi - oO0o . OoooooooOO
    if ( O0O0 in lisp_crypto_keys_by_rloc_decap ) :
     iI1iiiiiii = lisp_crypto_keys_by_rloc_decap [ O0O0 ]
     IiIi1 = iI1iiiiiii [ 1 ] if iI1iiiiiii and iI1iiiiiii [ 1 ] else None
     if 40 - 40: I11i
     if 44 - 44: ooOoO0o
    Iii11Ii = True
    if ( IiIi1 ) :
     if ( IiIi1 . compare_keys ( Ooo00o000o ) ) :
      self . keys = [ None , IiIi1 , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( O0O0 , False ) ) )
      if 32 - 32: II111iiii * I1IiiI / iIii1I11I1II1 - I1ii11iIi11i . I11i
     else :
      Iii11Ii = False
      oo000O = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( oo000O , red ( O0O0 ,
 False ) ) )
      Ooo00o000o . copy_keypair ( IiIi1 )
      Ooo00o000o . uptime = IiIi1 . uptime
      IiIi1 = None
      if 41 - 41: OOooOOo - OoOoOO00 . I1IiiI + i11iIiiIii + OoO0O00 * iII111i
      if 85 - 85: OoO0O00 + II111iiii
      if 87 - 87: OoO0O00
    if ( IiIi1 == None ) :
     self . keys = [ None , Ooo00o000o , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      Ooo00o000o . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( O0O0 , False ) ) )
     elif ( Ooo00o000o . remote_public_key != None ) :
      if ( Iii11Ii ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # OoooooooOO . O0 % i11iIiiIii - OoooooooOO + OoO0O00 . OOooOOo
 red ( O0O0 , False ) ) )
       if 64 - 64: OoOoOO00
      Ooo00o000o . compute_shared_key ( "decap" )
      Ooo00o000o . add_key_by_rloc ( O0O0 , False )
      if 10 - 10: OoO0O00 + iIii1I11I1II1 . II111iiii
      if 8 - 8: OoO0O00 / II111iiii
      if 71 - 71: Oo0Ooo % iII111i . ooOoO0o % O0 + iIii1I11I1II1 % I1Ii111
      if 8 - 8: I1ii11iIi11i - ooOoO0o + iII111i * OoO0O00
   self . itr_rlocs . append ( ii1oO0Oo )
   OO0o -= 1
   if 22 - 22: I1ii11iIi11i * OoooooooOO
   if 33 - 33: OOooOOo / o0oOOo0O0Ooo + OOooOOo . i11iIiiIii
  oO000 = struct . calcsize ( "BBH" )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 19 - 19: OoOoOO00 % OoOoOO00
  oOoO , oOo , Oooo000 = struct . unpack ( "BBH" , packet [ : oO000 ] )
  self . subscribe_bit = ( oOoO & 0x80 )
  self . target_eid . afi = socket . ntohs ( Oooo000 )
  packet = packet [ oO000 : : ]
  if 74 - 74: i11iIiiIii / I1ii11iIi11i - oO0o . OoO0O00
  self . target_eid . mask_len = oOo
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , i1II1iI1ii1 = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( i1II1iI1ii1 ) : self . target_group = i1II1iI1ii1
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ oO000 : : ]
   if 93 - 93: iII111i % I1Ii111
  return ( packet )
  if 90 - 90: I1ii11iIi11i - OoooooooOO / OoOoOO00
  if 24 - 24: I11i . OOooOOo * i1IIi . I1ii11iIi11i / ooOoO0o / O0
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 62 - 62: o0oOOo0O0Ooo % II111iiii
  if 22 - 22: oO0o - o0oOOo0O0Ooo
 def encode_xtr_id ( self , packet ) :
  II1i1 = self . xtr_id >> 64
  ooO0OoOO0 = self . xtr_id & 0xffffffffffffffff
  II1i1 = byte_swap_64 ( II1i1 )
  ooO0OoOO0 = byte_swap_64 ( ooO0OoOO0 )
  packet += struct . pack ( "QQ" , II1i1 , ooO0OoOO0 )
  return ( packet )
  if 89 - 89: OOooOOo
  if 34 - 34: iII111i . OOooOOo
 def decode_xtr_id ( self , packet ) :
  oO000 = struct . calcsize ( "QQ" )
  if ( len ( packet ) < oO000 ) : return ( None )
  packet = packet [ len ( packet ) - oO000 : : ]
  II1i1 , ooO0OoOO0 = struct . unpack ( "QQ" , packet [ : oO000 ] )
  II1i1 = byte_swap_64 ( II1i1 )
  ooO0OoOO0 = byte_swap_64 ( ooO0OoOO0 )
  self . xtr_id = ( II1i1 << 64 ) | ooO0OoOO0
  return ( True )
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
  if 42 - 42: O0 . I1Ii111 / I11i
  if 69 - 69: OoOoOO00 / I1Ii111 * I1IiiI
  if 76 - 76: O0 + II111iiii * OoO0O00
  if 1 - 1: o0oOOo0O0Ooo
  if 34 - 34: o0oOOo0O0Ooo + OOooOOo . OoO0O00 + I1IiiI + OoooooooOO
  if 90 - 90: Ii1I / OoOoOO00 - iIii1I11I1II1 / i1IIi * I1Ii111 - ooOoO0o
  if 2 - 2: iII111i * I11i * ooOoO0o + i11iIiiIii + oO0o
  if 81 - 81: o0oOOo0O0Ooo * OoO0O00
  if 18 - 18: i11iIiiIii / o0oOOo0O0Ooo - oO0o . I11i * i1IIi
class lisp_map_reply ( object ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 67 - 67: Ii1I
  if 64 - 64: OoOoOO00 + iII111i * OoOoOO00 - I1IiiI * OoooooooOO
 def print_map_reply ( self ) :
  IiiiI1 = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 27 - 27: II111iiii + i11iIiiIii
  lprint ( IiiiI1 . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # i1IIi . Ii1I
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 38 - 38: o0oOOo0O0Ooo / I1ii11iIi11i * oO0o + II111iiii / i11iIiiIii
  if 34 - 34: i11iIiiIii % OoO0O00 - oO0o / OOooOOo / iII111i
 def encode ( self ) :
  Iii1 = ( LISP_MAP_REPLY << 28 ) | self . record_count
  Iii1 |= self . hop_count << 8
  if ( self . rloc_probe ) : Iii1 |= 0x08000000
  if ( self . echo_nonce_capable ) : Iii1 |= 0x04000000
  if ( self . security ) : Iii1 |= 0x02000000
  if 5 - 5: I1Ii111 . oO0o
  Oo00oo = struct . pack ( "I" , socket . htonl ( Iii1 ) )
  Oo00oo += struct . pack ( "Q" , self . nonce )
  return ( Oo00oo )
  if 77 - 77: iII111i / i11iIiiIii
  if 20 - 20: O0 . I11i
 def decode ( self , packet ) :
  II111I11iI = "I"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 67 - 67: OoOoOO00 - ooOoO0o - iIii1I11I1II1
  Iii1 = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  Iii1 = Iii1 [ 0 ]
  packet = packet [ oO000 : : ]
  if 31 - 31: II111iiii + o0oOOo0O0Ooo * i11iIiiIii . o0oOOo0O0Ooo
  II111I11iI = "Q"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 73 - 73: oO0o / OOooOOo * II111iiii % OoooooooOO - i1IIi - ooOoO0o
  oOooo0oOOOO = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  packet = packet [ oO000 : : ]
  if 43 - 43: o0oOOo0O0Ooo + Ii1I % OoO0O00 . I1Ii111 + i1IIi
  Iii1 = socket . ntohl ( Iii1 )
  self . rloc_probe = True if ( Iii1 & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( Iii1 & 0x04000000 ) else False
  self . security = True if ( Iii1 & 0x02000000 ) else False
  self . hop_count = ( Iii1 >> 8 ) & 0xff
  self . record_count = Iii1 & 0xff
  self . nonce = oOooo0oOOOO [ 0 ]
  if 85 - 85: Oo0Ooo % I1ii11iIi11i / OOooOOo
  if ( self . nonce in lisp_crypto_keys_by_nonce ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 65 - 65: ooOoO0o + IiII - OoOoOO00 % II111iiii - iIii1I11I1II1
  return ( packet )
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
  if 28 - 28: O0 % iII111i - i1IIi
  if 49 - 49: ooOoO0o . I11i - iIii1I11I1II1
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 41 - 41: ooOoO0o * i11iIiiIii % ooOoO0o . oO0o
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 97 - 97: oO0o - iII111i + IiII . OoOoOO00 + iIii1I11I1II1
  if 75 - 75: ooOoO0o + ooOoO0o . I1Ii111 % iII111i / iIii1I11I1II1 * iII111i
 def print_ttl ( self ) :
  IiIi1iIIiII1i = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   IiIi1iIIiII1i = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( IiIi1iIIiII1i % 60 ) == 0 ) :
   IiIi1iIIiII1i = str ( old_div ( IiIi1iIIiII1i , 60 ) ) + " hours"
  else :
   IiIi1iIIiII1i = str ( IiIi1iIIiII1i ) + " mins"
   if 87 - 87: oO0o / OoO0O00 / i11iIiiIii / OoooooooOO
  return ( IiIi1iIIiII1i )
  if 25 - 25: I1IiiI . Oo0Ooo + iIii1I11I1II1 * iII111i % Oo0Ooo . OoOoOO00
  if 13 - 13: Ii1I - Oo0Ooo
 def store_ttl ( self ) :
  IiIi1iIIiII1i = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : IiIi1iIIiII1i = self . record_ttl & 0x7fffffff
  return ( IiIi1iIIiII1i )
  if 91 - 91: I1IiiI - OoooooooOO - OoooooooOO
  if 69 - 69: iII111i * i11iIiiIii / i1IIi
 def print_record ( self , indent , ddt ) :
  Oo00Oo0o000 = ""
  oOo0ooOo = ""
  iI1i1i = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    iI1i1i = lisp_map_referral_action_string [ self . action ]
    iI1i1i = bold ( iI1i1i , False )
    Oo00Oo0o000 = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 83 - 83: O0
    oOo0ooOo = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 27 - 27: o0oOOo0O0Ooo + I1IiiI - IiII . i11iIiiIii . I1IiiI
    if 25 - 25: O0 + OOooOOo / iII111i
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    iI1i1i = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     iI1i1i = bold ( iI1i1i , False )
     if 51 - 51: I11i
     if 54 - 54: i1IIi . O0 . i1IIi . OoO0O00 + I1Ii111 - i11iIiiIii
     if 80 - 80: OoOoOO00
     if 5 - 5: I1IiiI - I1IiiI / O0 + OOooOOo - i11iIiiIii
  Oooo000 = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  IiiiI1 = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 87 - 87: i1IIi - O0 % OoooooooOO * i11iIiiIii % i11iIiiIii
  lprint ( IiiiI1 . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 iI1i1i , "auth" if ( self . authoritative is True ) else "non-auth" ,
 Oo00Oo0o000 , oOo0ooOo , self . map_version , Oooo000 ,
 green ( self . print_prefix ( ) , False ) ) )
  if 19 - 19: ooOoO0o
  if 44 - 44: I1Ii111 - i11iIiiIii * I1IiiI
 def encode ( self ) :
  oo0oOooo0O = self . action << 13
  if ( self . authoritative ) : oo0oOooo0O |= 0x1000
  if ( self . ddt_incomplete ) : oo0oOooo0O |= 0x800
  if 2 - 2: IiII + I11i / iIii1I11I1II1 . i11iIiiIii . i1IIi * ooOoO0o
  if 14 - 14: Oo0Ooo . O0 - oO0o - i11iIiiIii
  if 8 - 8: I1IiiI / iIii1I11I1II1 / OoooooooOO / Oo0Ooo / ooOoO0o
  if 80 - 80: I11i
  Oooo000 = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( Oooo000 < 0 ) : Oooo000 = LISP_AFI_LCAF
  IiiiIi = ( self . group . is_null ( ) == False )
  if ( IiiiIi ) : Oooo000 = LISP_AFI_LCAF
  if 81 - 81: i11iIiiIii + o0oOOo0O0Ooo / II111iiii + I11i
  OOO0O0 = ( self . signature_count << 12 ) | self . map_version
  oOo = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 25 - 25: oO0o - OoOoOO00 / OoO0O00 / Ii1I
  Oo00oo = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , oOo , socket . htons ( oo0oOooo0O ) ,
 socket . htons ( OOO0O0 ) , socket . htons ( Oooo000 ) )
  if 34 - 34: ooOoO0o + Oo0Ooo
  if 34 - 34: Ii1I / OoooooooOO + IiII % oO0o - I1IiiI + II111iiii
  if 79 - 79: iII111i / OoooooooOO % IiII
  if 78 - 78: Oo0Ooo * OOooOOo % I1ii11iIi11i + OOooOOo % Ii1I + IiII
  if ( IiiiIi ) :
   Oo00oo += self . eid . lcaf_encode_sg ( self . group )
   return ( Oo00oo )
   if 58 - 58: OoooooooOO % I1Ii111 / Oo0Ooo % OoooooooOO * OoOoOO00 . OoooooooOO
   if 46 - 46: ooOoO0o * o0oOOo0O0Ooo % II111iiii / I1Ii111
   if 29 - 29: OoO0O00 - i11iIiiIii % Oo0Ooo % o0oOOo0O0Ooo
   if 30 - 30: oO0o - Ii1I % Ii1I
   if 8 - 8: IiII
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   Oo00oo = Oo00oo [ 0 : - 2 ]
   Oo00oo += self . eid . address . encode_geo ( )
   return ( Oo00oo )
   if 68 - 68: IiII . OoooooooOO - i11iIiiIii + i11iIiiIii
   if 81 - 81: OoOoOO00 + iII111i . i11iIiiIii
   if 10 - 10: OoOoOO00 + I11i - iIii1I11I1II1 - I11i
   if 58 - 58: ooOoO0o
   if 98 - 98: Ii1I / OoO0O00 % OoooooooOO
  if ( Oooo000 == LISP_AFI_LCAF ) :
   Oo00oo += self . eid . lcaf_encode_iid ( )
   return ( Oo00oo )
   if 65 - 65: ooOoO0o % Oo0Ooo - I1IiiI % I1Ii111 + iIii1I11I1II1 / iIii1I11I1II1
   if 94 - 94: IiII - Oo0Ooo . o0oOOo0O0Ooo - ooOoO0o - oO0o . I11i
   if 39 - 39: oO0o + OoOoOO00
   if 68 - 68: i1IIi * oO0o / i11iIiiIii
   if 96 - 96: I1IiiI
  Oo00oo += self . eid . pack_address ( )
  return ( Oo00oo )
  if 78 - 78: OoO0O00
  if 72 - 72: I1ii11iIi11i / O0 % II111iiii / II111iiii
 def decode ( self , packet ) :
  II111I11iI = "IBBHHH"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 48 - 48: OOooOOo % OOooOOo / iIii1I11I1II1 - i11iIiiIii
  self . record_ttl , self . rloc_count , self . eid . mask_len , oo0oOooo0O , self . map_version , self . eid . afi = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  if 57 - 57: I11i / IiII * i1IIi + II111iiii . o0oOOo0O0Ooo
  if 11 - 11: II111iiii
  if 66 - 66: Ii1I - I1IiiI . OoooooooOO * I1Ii111
  self . record_ttl = socket . ntohl ( self . record_ttl )
  oo0oOooo0O = socket . ntohs ( oo0oOooo0O )
  self . action = ( oo0oOooo0O >> 13 ) & 0x7
  self . authoritative = True if ( ( oo0oOooo0O >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( oo0oOooo0O >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ oO000 : : ]
  if 16 - 16: IiII * OoO0O00 * i11iIiiIii - ooOoO0o
  if 88 - 88: iIii1I11I1II1 / Ii1I * IiII / I1Ii111
  if 31 - 31: O0 . I1IiiI
  if 8 - 8: OoOoOO00
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , o0o0Oo0o0oOo = self . eid . lcaf_decode_eid ( packet )
   if ( o0o0Oo0o0oOo ) : self . group = o0o0Oo0o0oOo
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 14 - 14: I1IiiI - i11iIiiIii * I1Ii111 . i11iIiiIii % ooOoO0o
   if 53 - 53: O0 . o0oOOo0O0Ooo . II111iiii * OoOoOO00 . OOooOOo
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 78 - 78: OoOoOO00 * OoOoOO00 - OoO0O00 / oO0o
  if 24 - 24: I1Ii111 . oO0o + ooOoO0o . I1ii11iIi11i . II111iiii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 25 - 25: I1IiiI
  if 88 - 88: i1IIi
  if 93 - 93: I1ii11iIi11i . OoO0O00
  if 67 - 67: II111iiii + OoooooooOO + I1IiiI
  if 76 - 76: O0 / Oo0Ooo . OoOoOO00
  if 81 - 81: o0oOOo0O0Ooo + II111iiii % I1Ii111 - oO0o + ooOoO0o - I1ii11iIi11i
  if 99 - 99: iIii1I11I1II1
  if 100 - 100: OoOoOO00 + I1Ii111 * Oo0Ooo / IiII - IiII
  if 19 - 19: OoooooooOO . Ii1I + Oo0Ooo + II111iiii
  if 88 - 88: O0 - OOooOOo * II111iiii
  if 84 - 84: iII111i
  if 51 - 51: OoooooooOO + I11i . iII111i + i11iIiiIii * iII111i - OoO0O00
  if 60 - 60: iII111i * iIii1I11I1II1 . OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
  if 36 - 36: i1IIi . OoooooooOO - II111iiii - OoOoOO00 - IiII
  if 53 - 53: I1ii11iIi11i - II111iiii . i11iIiiIii
  if 76 - 76: iIii1I11I1II1 - Oo0Ooo
  if 79 - 79: I1IiiI * IiII . OoooooooOO % I1Ii111 * I1Ii111
  if 17 - 17: I1Ii111 - I1Ii111 . oO0o / I1Ii111
  if 36 - 36: I1ii11iIi11i * i1IIi + iIii1I11I1II1
  if 55 - 55: I1IiiI . I1Ii111 - I1IiiI % oO0o / iIii1I11I1II1 * Ii1I
  if 77 - 77: OOooOOo
  if 29 - 29: II111iiii % iIii1I11I1II1 * O0 . o0oOOo0O0Ooo
  if 56 - 56: i1IIi . ooOoO0o + I11i - i11iIiiIii
  if 100 - 100: iIii1I11I1II1 - i1IIi . OOooOOo
  if 73 - 73: I1Ii111 / I11i / i11iIiiIii - I1ii11iIi11i % ooOoO0o
  if 92 - 92: I1IiiI - o0oOOo0O0Ooo % I1ii11iIi11i / iII111i % oO0o
  if 43 - 43: Oo0Ooo % oO0o . i11iIiiIii - O0
  if 5 - 5: i1IIi + Ii1I
  if 38 - 38: I1IiiI . O0 + OOooOOo / I1ii11iIi11i . iIii1I11I1II1 - i1IIi
  if 3 - 3: Oo0Ooo + oO0o
  if 65 - 65: I1IiiI / OoOoOO00 % I1IiiI * i11iIiiIii * OoooooooOO / I11i
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 91 - 91: i11iIiiIii / i11iIiiIii
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
  if 9 - 9: I11i / I1Ii111 + iIii1I11I1II1 + I1IiiI - II111iiii
  if 96 - 96: iII111i + Oo0Ooo - OoooooooOO . i1IIi + i1IIi % iIii1I11I1II1
 def print_ecm ( self ) :
  IiiiI1 = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 80 - 80: OoooooooOO / O0 / I1Ii111 - Oo0Ooo . i11iIiiIii
  lprint ( IiiiI1 . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 3 - 3: Oo0Ooo - OOooOOo * OoO0O00 - II111iiii . OoooooooOO
  if 14 - 14: I1IiiI
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 41 - 41: I1Ii111 % i1IIi + OoO0O00 / oO0o
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 48 - 48: i1IIi . Oo0Ooo . i1IIi . I1ii11iIi11i * I1IiiI - Ii1I
   if 83 - 83: OoooooooOO
   if 42 - 42: I1ii11iIi11i . i1IIi - OoOoOO00 - oO0o + i11iIiiIii
   if 65 - 65: I1IiiI - O0
   if 15 - 15: I11i + OoOoOO00 / Oo0Ooo - I1IiiI * I1ii11iIi11i % oO0o
   if 90 - 90: Ii1I / I11i
  Iii1 = ( LISP_ECM << 28 )
  if ( self . security ) : Iii1 |= 0x08000000
  if ( self . ddt ) : Iii1 |= 0x04000000
  if ( self . to_etr ) : Iii1 |= 0x02000000
  if ( self . to_ms ) : Iii1 |= 0x01000000
  if 98 - 98: i1IIi
  O0Oooo0 = struct . pack ( "I" , socket . htonl ( Iii1 ) )
  if 84 - 84: iIii1I11I1II1 % Ii1I / OoooooooOO
  O0O = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   O0O = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   O0O += self . source . pack_address ( )
   O0O += self . dest . pack_address ( )
   O0O = lisp_ip_checksum ( O0O )
   if 62 - 62: OOooOOo * OoO0O00 * OoO0O00 + OoooooooOO . IiII + OoO0O00
  if ( self . afi == LISP_AFI_IPV6 ) :
   O0O = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   O0O += self . source . pack_address ( )
   O0O += self . dest . pack_address ( )
   if 13 - 13: O0 . I1IiiI % OoO0O00 - I11i . O0
   if 14 - 14: iIii1I11I1II1
  I111 = socket . htons ( self . udp_sport )
  IiI11I111 = socket . htons ( self . udp_dport )
  oOO0O0ooOOOo = socket . htons ( self . udp_length )
  IIIiIi11 = socket . htons ( self . udp_checksum )
  O0I1II1 = struct . pack ( "HHHH" , I111 , IiI11I111 , oOO0O0ooOOOo , IIIiIi11 )
  return ( O0Oooo0 + O0O + O0I1II1 )
  if 48 - 48: i11iIiiIii * OoOoOO00 - I1IiiI + iIii1I11I1II1
  if 20 - 20: I1ii11iIi11i - iIii1I11I1II1 . iII111i
 def decode ( self , packet ) :
  if 52 - 52: OoO0O00 - I1Ii111
  if 9 - 9: I1IiiI . i11iIiiIii
  if 3 - 3: I1IiiI + I1ii11iIi11i * I1Ii111 - i1IIi . OOooOOo
  if 21 - 21: OOooOOo + o0oOOo0O0Ooo
  II111I11iI = "I"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 39 - 39: OoOoOO00 . I11i * OOooOOo . i1IIi
  Iii1 = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  if 69 - 69: IiII - i1IIi + o0oOOo0O0Ooo
  Iii1 = socket . ntohl ( Iii1 [ 0 ] )
  self . security = True if ( Iii1 & 0x08000000 ) else False
  self . ddt = True if ( Iii1 & 0x04000000 ) else False
  self . to_etr = True if ( Iii1 & 0x02000000 ) else False
  self . to_ms = True if ( Iii1 & 0x01000000 ) else False
  packet = packet [ oO000 : : ]
  if 5 - 5: II111iiii
  if 88 - 88: OoooooooOO % II111iiii + IiII + IiII * Oo0Ooo
  if 81 - 81: I1IiiI * ooOoO0o + I1Ii111
  if 49 - 49: I1IiiI % oO0o % II111iiii * II111iiii + OoooooooOO + iII111i
  if ( len ( packet ) < 1 ) : return ( None )
  III1i1iiI1 = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  III1i1iiI1 = III1i1iiI1 >> 4
  if 58 - 58: i11iIiiIii % iIii1I11I1II1 + OoO0O00 . I1ii11iIi11i . I1IiiI
  if ( III1i1iiI1 == 4 ) :
   oO000 = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < oO000 ) : return ( None )
   if 54 - 54: iII111i . OoO0O00 . iIii1I11I1II1
   iIiiiI1 , oOO0O0ooOOOo , iIiiiI1 , IiIi1I1i1iII , iIIiiIi , IIIiIi11 = struct . unpack ( "HHIBBH" , packet [ : oO000 ] )
   self . length = socket . ntohs ( oOO0O0ooOOOo )
   self . ttl = IiIi1I1i1iII
   self . protocol = iIIiiIi
   self . ip_checksum = socket . ntohs ( IIIiIi11 )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 86 - 86: I11i % I1Ii111 . I11i * IiII + IiII + II111iiii
   if 66 - 66: oO0o / O0 - OoOoOO00
   if 69 - 69: iIii1I11I1II1 * OoO0O00 / OoooooooOO % I1ii11iIi11i . I1IiiI % I11i
   if 40 - 40: i11iIiiIii % oO0o / OOooOOo
   iIIiiIi = struct . pack ( "H" , 0 )
   OOooo0o0000 = struct . calcsize ( "HHIBB" )
   OOo0O = struct . calcsize ( "H" )
   packet = packet [ : OOooo0o0000 ] + iIIiiIi + packet [ OOooo0o0000 + OOo0O : ]
   if 21 - 21: OoOoOO00 + i11iIiiIii - OoooooooOO % o0oOOo0O0Ooo * OoO0O00
   packet = packet [ oO000 : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 73 - 73: Oo0Ooo % oO0o * I1Ii111 / IiII
   if 88 - 88: ooOoO0o . II111iiii * O0 % IiII
  if ( III1i1iiI1 == 6 ) :
   oO000 = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < oO000 ) : return ( None )
   if 15 - 15: O0 % i1IIi - OOooOOo . IiII
   iIiiiI1 , oOO0O0ooOOOo , iIIiiIi , IiIi1I1i1iII = struct . unpack ( "IHBB" , packet [ : oO000 ] )
   self . length = socket . ntohs ( oOO0O0ooOOOo )
   self . protocol = iIIiiIi
   self . ttl = IiIi1I1i1iII
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 1 - 1: I1IiiI
   packet = packet [ oO000 : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 40 - 40: o0oOOo0O0Ooo % I11i % O0
   if 88 - 88: o0oOOo0O0Ooo - oO0o
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 73 - 73: II111iiii
  oO000 = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 7 - 7: O0 / OoO0O00
  I111 , IiI11I111 , oOO0O0ooOOOo , IIIiIi11 = struct . unpack ( "HHHH" , packet [ : oO000 ] )
  self . udp_sport = socket . ntohs ( I111 )
  self . udp_dport = socket . ntohs ( IiI11I111 )
  self . udp_length = socket . ntohs ( oOO0O0ooOOOo )
  self . udp_checksum = socket . ntohs ( IIIiIi11 )
  packet = packet [ oO000 : : ]
  return ( packet )
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
  if 22 - 22: Oo0Ooo
  if 21 - 21: o0oOOo0O0Ooo
  if 86 - 86: ooOoO0o / iIii1I11I1II1 . OOooOOo
  if 93 - 93: Oo0Ooo / II111iiii . Oo0Ooo + i1IIi + i1IIi
  if 30 - 30: OoOoOO00 . OOooOOo % OOooOOo / II111iiii + i1IIi
  if 61 - 61: i1IIi % II111iiii * II111iiii . o0oOOo0O0Ooo / I1ii11iIi11i - I1Ii111
  if 93 - 93: Ii1I - i1IIi
  if 3 - 3: oO0o + OoO0O00 - iII111i / Ii1I
  if 58 - 58: Ii1I * I11i
  if 95 - 95: oO0o
  if 49 - 49: I1IiiI
  if 23 - 23: I1Ii111
  if 5 - 5: I1ii11iIi11i % OoOoOO00 . OoooooooOO . o0oOOo0O0Ooo + i11iIiiIii
  if 54 - 54: ooOoO0o - O0 + iII111i
  if 34 - 34: Ii1I - OOooOOo % iII111i
  if 48 - 48: oO0o - O0
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
  if 17 - 17: iIii1I11I1II1 . IiII / ooOoO0o % I11i + o0oOOo0O0Ooo - iIii1I11I1II1
  if 95 - 95: OoOoOO00 + OOooOOo - I11i * i1IIi + i1IIi * O0
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  OO000o = self . rloc_name
  if ( cour ) : OO000o = lisp_print_cour ( OO000o )
  return ( 'rloc-name: {}' . format ( blue ( OO000o , cour ) ) )
  if 60 - 60: I1Ii111 / O0 - i1IIi * IiII
  if 72 - 72: O0 * I1Ii111 - iIii1I11I1II1 % i1IIi
 def print_record ( self , indent ) :
  IIi11IiiiI11i = self . print_rloc_name ( )
  if ( IIi11IiiiI11i != "" ) : IIi11IiiiI11i = ", " + IIi11IiiiI11i
  oOo0oO0 = ""
  if ( self . geo ) :
   o0o = ""
   if ( self . geo . geo_name ) : o0o = "'{}' " . format ( self . geo . geo_name )
   oOo0oO0 = ", geo: {}{}" . format ( o0o , self . geo . print_geo ( ) )
   if 62 - 62: i11iIiiIii / I1IiiI * O0 - OoOoOO00
  iIii1 = ""
  if ( self . elp ) :
   o0o = ""
   if ( self . elp . elp_name ) : o0o = "'{}' " . format ( self . elp . elp_name )
   iIii1 = ", elp: {}{}" . format ( o0o , self . elp . print_elp ( True ) )
   if 91 - 91: I1ii11iIi11i / Ii1I - OoOoOO00 . I11i / oO0o
  I1i1iI1i1i1 = ""
  if ( self . rle ) :
   o0o = ""
   if ( self . rle . rle_name ) : o0o = "'{}' " . format ( self . rle . rle_name )
   I1i1iI1i1i1 = ", rle: {}{}" . format ( o0o , self . rle . print_rle ( False ,
 True ) )
   if 99 - 99: OoOoOO00 / OoooooooOO + iII111i * I11i * i11iIiiIii + OOooOOo
  Ii11I = ""
  if ( self . json ) :
   o0o = ""
   if ( self . json . json_name ) :
    o0o = "'{}' " . format ( self . json . json_name )
    if 32 - 32: Oo0Ooo
   Ii11I = ", json: {}" . format ( self . json . print_json ( False ) )
   if 78 - 78: Ii1I . Oo0Ooo + I1IiiI - ooOoO0o
   if 5 - 5: I1IiiI % I1ii11iIi11i * oO0o + I1Ii111
  I11II1i11 = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   I11II1i11 = ", " + self . keys [ 1 ] . print_keys ( )
   if 42 - 42: i1IIi . OoOoOO00 * OoOoOO00 * OoOoOO00
   if 14 - 14: II111iiii / I1Ii111 . I1IiiI
  IiiiI1 = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( IiiiI1 . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , IIi11IiiiI11i , oOo0oO0 ,
 iIii1 , I1i1iI1i1i1 , Ii11I , I11II1i11 ) )
  if 66 - 66: I1Ii111 % oO0o . iII111i * i1IIi
  if 81 - 81: OoooooooOO * I1IiiI / I1Ii111
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 10 - 10: I1IiiI - II111iiii / IiII * II111iiii
  if 67 - 67: II111iiii . Ii1I % oO0o . Oo0Ooo + IiII
  if 10 - 10: OOooOOo - OoO0O00 * oO0o / iIii1I11I1II1 - OoOoOO00
 def store_rloc_entry ( self , rloc_entry ) :
  I1Ii1i111I = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 51 - 51: O0 + Ii1I * OoooooooOO . oO0o + OoooooooOO
  self . rloc . copy_address ( I1Ii1i111I )
  if 58 - 58: ooOoO0o . Oo0Ooo / I1ii11iIi11i + OoO0O00 * OoooooooOO / I1IiiI
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 24 - 24: O0 - iII111i . Ii1I
   if 20 - 20: Ii1I * I1IiiI % oO0o / i11iIiiIii . OoO0O00
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   o0o = rloc_entry . geo_name
   if ( o0o and o0o in lisp_geo_list ) :
    self . geo = lisp_geo_list [ o0o ]
    if 18 - 18: OoooooooOO / OOooOOo % i1IIi - i1IIi / Oo0Ooo
    if 94 - 94: I1Ii111 + i11iIiiIii / iII111i + OoooooooOO % i1IIi
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   o0o = rloc_entry . elp_name
   if ( o0o and o0o in lisp_elp_list ) :
    self . elp = lisp_elp_list [ o0o ]
    if 57 - 57: iIii1I11I1II1 - i11iIiiIii / II111iiii
    if 35 - 35: I1IiiI - IiII * I1Ii111 - ooOoO0o % oO0o
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   o0o = rloc_entry . rle_name
   if ( o0o and o0o in lisp_rle_list ) :
    self . rle = lisp_rle_list [ o0o ]
    if 88 - 88: IiII * OoO0O00 / IiII * I1IiiI + O0 / IiII
    if 41 - 41: OoOoOO00
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   o0o = rloc_entry . json_name
   if ( o0o and o0o in lisp_json_list ) :
    self . json = lisp_json_list [ o0o ]
    if 81 - 81: Ii1I . I1IiiI % o0oOOo0O0Ooo . OoOoOO00
    if 94 - 94: oO0o % Oo0Ooo + OoO0O00 * oO0o - i11iIiiIii / I11i
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 46 - 46: IiII - OoO0O00 * iII111i . I1Ii111 - ooOoO0o . i1IIi
  if 53 - 53: I1Ii111 * I1IiiI + Oo0Ooo + I1IiiI + OOooOOo
 def encode_json ( self , lisp_json ) :
  iio0O0OOo = lisp_json . json_string
  IiiIiI1 = 0
  if ( lisp_json . json_encrypted ) :
   IiiIiI1 = ( lisp_json . json_key_id << 5 ) | 0x02
   if 19 - 19: ooOoO0o / oO0o
   if 64 - 64: i11iIiiIii - I1Ii111 * I1IiiI
  IIiiIIi1II11 = LISP_LCAF_JSON_TYPE
  O0oooOoOO0O = socket . htons ( LISP_AFI_LCAF )
  OO00oOo00oo = self . rloc . addr_length ( ) + 2
  if 57 - 57: iII111i
  ii111iIii1 = socket . htons ( len ( iio0O0OOo ) + OO00oOo00oo )
  if 54 - 54: OoO0O00 / I1IiiI
  oo0O0OO = socket . htons ( len ( iio0O0OOo ) )
  Oo00oo = struct . pack ( "HBBBBHH" , O0oooOoOO0O , 0 , 0 , IIiiIIi1II11 , IiiIiI1 ,
 ii111iIii1 , oo0O0OO )
  Oo00oo += iio0O0OOo . encode ( )
  if 4 - 4: O0
  if 87 - 87: IiII - OoO0O00 * Oo0Ooo / o0oOOo0O0Ooo % oO0o % Ii1I
  if 25 - 25: Ii1I - I1ii11iIi11i + Oo0Ooo . I1IiiI
  if 36 - 36: iII111i
  if ( lisp_is_json_telemetry ( iio0O0OOo ) ) :
   Oo00oo += struct . pack ( "H" , socket . htons ( self . rloc . afi ) )
   Oo00oo += self . rloc . pack_address ( )
  else :
   Oo00oo += struct . pack ( "H" , 0 )
   if 3 - 3: Ii1I
  return ( Oo00oo )
  if 44 - 44: O0 - oO0o % II111iiii . I1Ii111
  if 86 - 86: IiII
 def encode_lcaf ( self ) :
  O0oooOoOO0O = socket . htons ( LISP_AFI_LCAF )
  o0oooo00 = b""
  if ( self . geo ) :
   o0oooo00 = self . geo . encode_geo ( )
   if 22 - 22: oO0o / II111iiii
   if 51 - 51: I11i % o0oOOo0O0Ooo / OoooooooOO % i1IIi
  i11IiiI = b""
  if ( self . elp ) :
   iI11I1I = b""
   for i11I1iI1I in self . elp . elp_nodes :
    Oooo000 = socket . htons ( i11I1iI1I . address . afi )
    OoO0o0oOOoOoo = 0
    if ( i11I1iI1I . eid ) : OoO0o0oOOoOoo |= 0x4
    if ( i11I1iI1I . probe ) : OoO0o0oOOoOoo |= 0x2
    if ( i11I1iI1I . strict ) : OoO0o0oOOoOoo |= 0x1
    OoO0o0oOOoOoo = socket . htons ( OoO0o0oOOoOoo )
    iI11I1I += struct . pack ( "HH" , OoO0o0oOOoOoo , Oooo000 )
    iI11I1I += i11I1iI1I . address . pack_address ( )
    if 28 - 28: II111iiii / o0oOOo0O0Ooo
    if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
   iIi1i1I = socket . htons ( len ( iI11I1I ) )
   i11IiiI = struct . pack ( "HBBBBH" , O0oooOoOO0O , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , iIi1i1I )
   i11IiiI += iI11I1I
   if 36 - 36: OoooooooOO + O0
   if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
  o00OOOoooo00 = b""
  if ( self . rle ) :
   o000 = b""
   for iI11i1ii11i11 in self . rle . rle_nodes :
    Oooo000 = socket . htons ( iI11i1ii11i11 . address . afi )
    o000 += struct . pack ( "HBBH" , 0 , 0 , iI11i1ii11i11 . level , Oooo000 )
    o000 += iI11i1ii11i11 . address . pack_address ( )
    if ( iI11i1ii11i11 . rloc_name ) :
     o000 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     o000 += ( iI11i1ii11i11 . rloc_name + "\0" ) . encode ( )
     if 59 - 59: OoO0O00 + OOooOOo . I1ii11iIi11i - iII111i % ooOoO0o
     if 9 - 9: IiII
     if 51 - 51: I1Ii111 + O0 + OoOoOO00 % O0 + oO0o
   OoOOOO0O00 = socket . htons ( len ( o000 ) )
   o00OOOoooo00 = struct . pack ( "HBBBBH" , O0oooOoOO0O , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , OoOOOO0O00 )
   o00OOOoooo00 += o000
   if 2 - 2: OoO0O00 . I1ii11iIi11i * i11iIiiIii
   if 65 - 65: I11i
  Ooo0o00OO0ooo0 = b""
  if ( self . json ) :
   Ooo0o00OO0ooo0 = self . encode_json ( self . json )
   if 54 - 54: I1IiiI / i1IIi * I1ii11iIi11i
   if 10 - 10: I1IiiI % II111iiii / I1IiiI
  iii11i11I = b""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   iii11i11I = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 23 - 23: I1Ii111 . Ii1I % OoO0O00
   if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
  o0O00 = b""
  if ( self . rloc_name ) :
   o0O00 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   o0O00 += ( self . rloc_name + "\0" ) . encode ( )
   if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
   if 81 - 81: I1ii11iIi11i
  Iii11i111iI = len ( o0oooo00 ) + len ( i11IiiI ) + len ( o00OOOoooo00 ) + len ( iii11i11I ) + 2 + len ( Ooo0o00OO0ooo0 ) + self . rloc . addr_length ( ) + len ( o0O00 )
  if 76 - 76: I1Ii111 - O0
  Iii11i111iI = socket . htons ( Iii11i111iI )
  Ii11111iiIi11 = struct . pack ( "HBBBBHH" , O0oooOoOO0O , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , Iii11i111iI , socket . htons ( self . rloc . afi ) )
  Ii11111iiIi11 += self . rloc . pack_address ( )
  return ( Ii11111iiIi11 + o0O00 + o0oooo00 + i11IiiI + o00OOOoooo00 + iii11i11I + Ooo0o00OO0ooo0 )
  if 18 - 18: oO0o . OoOoOO00 + ooOoO0o * iII111i * iIii1I11I1II1 % O0
  if 32 - 32: O0 / I11i . O0
 def encode ( self ) :
  OoO0o0oOOoOoo = 0
  if ( self . local_bit ) : OoO0o0oOOoOoo |= 0x0004
  if ( self . probe_bit ) : OoO0o0oOOoOoo |= 0x0002
  if ( self . reach_bit ) : OoO0o0oOOoOoo |= 0x0001
  if 25 - 25: Oo0Ooo - iII111i
  Oo00oo = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( OoO0o0oOOoOoo ) ,
 socket . htons ( self . rloc . afi ) )
  if 96 - 96: O0 . I1IiiI
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 2 - 2: I11i . oO0o * IiII
   try :
    Oo00oo = Oo00oo [ 0 : - 2 ] + self . encode_lcaf ( )
   except :
    lprint ( "Could not encode LCAF for RLOC-record" )
    if 41 - 41: Ii1I / OoO0O00 / OoO0O00 * I11i
  else :
   Oo00oo += self . rloc . pack_address ( )
   if 31 - 31: Ii1I / OoooooooOO % iIii1I11I1II1 - IiII * I1IiiI - O0
  return ( Oo00oo )
  if 31 - 31: oO0o
  if 74 - 74: OoO0O00
 def decode_lcaf ( self , packet , nonce , ms_json_encrypt ) :
  II111I11iI = "HBBBBH"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 11 - 11: oO0o + O0 % Ii1I . I11i * o0oOOo0O0Ooo
  Oooo000 , iI1i1II11I , OoO0o0oOOoOoo , IIiiIIi1II11 , I1iIiiiI1II1 , ii111iIii1 = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  if 14 - 14: I11i . iIii1I11I1II1 + I1Ii111 % OoooooooOO
  if 9 - 9: oO0o + Ii1I / I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo
  ii111iIii1 = socket . ntohs ( ii111iIii1 )
  packet = packet [ oO000 : : ]
  if ( ii111iIii1 > len ( packet ) ) : return ( None )
  if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
  if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
  if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
  if 30 - 30: i11iIiiIii % OOooOOo
  if ( IIiiIIi1II11 == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( ii111iIii1 > 0 ) :
    II111I11iI = "H"
    oO000 = struct . calcsize ( II111I11iI )
    if ( ii111iIii1 < oO000 ) : return ( None )
    if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
    iiIi1111iiI1 = len ( packet )
    Oooo000 = struct . unpack ( II111I11iI , packet [ : oO000 ] ) [ 0 ]
    Oooo000 = socket . ntohs ( Oooo000 )
    if 27 - 27: I1IiiI + OoOoOO00 + iII111i
    if ( Oooo000 == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ oO000 : : ]
     self . rloc_name = None
     if ( Oooo000 == LISP_AFI_NAME ) :
      packet , OO000o = lisp_decode_dist_name ( packet )
      self . rloc_name = OO000o
     else :
      self . rloc . afi = Oooo000
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 70 - 70: I11i + IiII . ooOoO0o - I1ii11iIi11i
      if 34 - 34: i1IIi % Oo0Ooo . oO0o
      if 36 - 36: I1ii11iIi11i / I1Ii111 - IiII + OOooOOo + I1Ii111
    ii111iIii1 -= iiIi1111iiI1 - len ( packet )
    if 62 - 62: Oo0Ooo . OoO0O00 * I1Ii111 . i11iIiiIii * O0
    if 10 - 10: Oo0Ooo / OoOoOO00 * OOooOOo - IiII + Ii1I
  elif ( IIiiIIi1II11 == LISP_LCAF_GEO_COORD_TYPE ) :
   if 62 - 62: I1IiiI . Ii1I
   if 74 - 74: Ii1I - I11i % ooOoO0o - I1IiiI - Ii1I - II111iiii
   if 81 - 81: i1IIi * I1ii11iIi11i + IiII - OoO0O00 * i1IIi
   if 6 - 6: iIii1I11I1II1 % OoOoOO00 % II111iiii % o0oOOo0O0Ooo
   O00o0o0O = lisp_geo ( "" )
   packet = O00o0o0O . decode_geo ( packet , ii111iIii1 , I1iIiiiI1II1 )
   if ( packet == None ) : return ( None )
   self . geo = O00o0o0O
   if 67 - 67: IiII - I1Ii111 . I1Ii111 % Ii1I
  elif ( IIiiIIi1II11 == LISP_LCAF_JSON_TYPE ) :
   iiII = I1iIiiiI1II1 & 0x02
   if 35 - 35: I1Ii111 / I1Ii111 + o0oOOo0O0Ooo - oO0o
   if 40 - 40: OoOoOO00 - II111iiii
   if 29 - 29: I1IiiI - O0
   if 36 - 36: I1IiiI * I1IiiI
   II111I11iI = "H"
   oO000 = struct . calcsize ( II111I11iI )
   if ( ii111iIii1 < oO000 ) : return ( None )
   if 79 - 79: I1Ii111 - I11i
   oo0O0OO = struct . unpack ( II111I11iI , packet [ : oO000 ] ) [ 0 ]
   oo0O0OO = socket . ntohs ( oo0O0OO )
   if ( ii111iIii1 < oO000 + oo0O0OO ) : return ( None )
   if 49 - 49: II111iiii + O0 * ooOoO0o - Oo0Ooo
   packet = packet [ oO000 : : ]
   self . json = lisp_json ( "" , packet [ 0 : oo0O0OO ] , iiII ,
 ms_json_encrypt )
   packet = packet [ oo0O0OO : : ]
   if 89 - 89: I1IiiI + I11i . oO0o . II111iiii + oO0o / Oo0Ooo
   if 32 - 32: OoO0O00 % oO0o * I1ii11iIi11i + I11i / I1Ii111
   if 5 - 5: o0oOOo0O0Ooo + iII111i / OoooooooOO + Ii1I . OoOoOO00 / oO0o
   if 18 - 18: II111iiii . o0oOOo0O0Ooo
   Oooo000 = socket . ntohs ( struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ] )
   packet = packet [ 2 : : ]
   if 75 - 75: OoooooooOO - Oo0Ooo
   if ( Oooo000 != 0 and lisp_is_json_telemetry ( self . json . json_string ) ) :
    self . rloc . afi = Oooo000
    packet = self . rloc . unpack_address ( packet )
    if 56 - 56: II111iiii - i11iIiiIii - oO0o . o0oOOo0O0Ooo
    if 4 - 4: i1IIi
  elif ( IIiiIIi1II11 == LISP_LCAF_ELP_TYPE ) :
   if 91 - 91: IiII . OoO0O00 * Ii1I / o0oOOo0O0Ooo
   if 41 - 41: I1IiiI . OoO0O00 / i1IIi . Oo0Ooo . oO0o
   if 44 - 44: iII111i * I11i + i11iIiiIii + i1IIi / IiII * II111iiii
   if 58 - 58: OOooOOo
   OOO00O = lisp_elp ( None )
   OOO00O . elp_nodes = [ ]
   while ( ii111iIii1 > 0 ) :
    OoO0o0oOOoOoo , Oooo000 = struct . unpack ( "HH" , packet [ : 4 ] )
    if 5 - 5: I1Ii111 * I11i * oO0o * I1ii11iIi11i - OOooOOo * OoOoOO00
    Oooo000 = socket . ntohs ( Oooo000 )
    if ( Oooo000 == LISP_AFI_LCAF ) : return ( None )
    if 88 - 88: OoooooooOO . II111iiii / Oo0Ooo * OoOoOO00
    i11I1iI1I = lisp_elp_node ( )
    OOO00O . elp_nodes . append ( i11I1iI1I )
    if 52 - 52: OoO0O00 + oO0o
    OoO0o0oOOoOoo = socket . ntohs ( OoO0o0oOOoOoo )
    i11I1iI1I . eid = ( OoO0o0oOOoOoo & 0x4 )
    i11I1iI1I . probe = ( OoO0o0oOOoOoo & 0x2 )
    i11I1iI1I . strict = ( OoO0o0oOOoOoo & 0x1 )
    i11I1iI1I . address . afi = Oooo000
    i11I1iI1I . address . mask_len = i11I1iI1I . address . host_mask_len ( )
    packet = i11I1iI1I . address . unpack_address ( packet [ 4 : : ] )
    ii111iIii1 -= i11I1iI1I . address . addr_length ( ) + 4
    if 84 - 84: O0 % I1ii11iIi11i % iIii1I11I1II1 - OoOoOO00 - Oo0Ooo
   OOO00O . select_elp_node ( )
   self . elp = OOO00O
   if 7 - 7: II111iiii % oO0o % i1IIi . iIii1I11I1II1
  elif ( IIiiIIi1II11 == LISP_LCAF_RLE_TYPE ) :
   if 92 - 92: Ii1I / o0oOOo0O0Ooo % OOooOOo - OoOoOO00
   if 44 - 44: I1IiiI + OoOoOO00 * Oo0Ooo
   if 31 - 31: I11i - I1IiiI - OoO0O00 * OoOoOO00
   if 50 - 50: I1ii11iIi11i + I11i * iII111i
   ooo0o0O = lisp_rle ( None )
   ooo0o0O . rle_nodes = [ ]
   while ( ii111iIii1 > 0 ) :
    iIiiiI1 , II11iiiII1Ii , O00OoO0 , Oooo000 = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 66 - 66: OoooooooOO + OoOoOO00 * OoO0O00 - I1IiiI . oO0o
    Oooo000 = socket . ntohs ( Oooo000 )
    if ( Oooo000 == LISP_AFI_LCAF ) : return ( None )
    if 74 - 74: o0oOOo0O0Ooo . Oo0Ooo * i1IIi
    iI11i1ii11i11 = lisp_rle_node ( )
    ooo0o0O . rle_nodes . append ( iI11i1ii11i11 )
    if 67 - 67: IiII
    iI11i1ii11i11 . level = O00OoO0
    iI11i1ii11i11 . address . afi = Oooo000
    iI11i1ii11i11 . address . mask_len = iI11i1ii11i11 . address . host_mask_len ( )
    packet = iI11i1ii11i11 . address . unpack_address ( packet [ 6 : : ] )
    if 54 - 54: i11iIiiIii + I11i % iII111i % I1ii11iIi11i + Oo0Ooo % o0oOOo0O0Ooo
    ii111iIii1 -= iI11i1ii11i11 . address . addr_length ( ) + 6
    if ( ii111iIii1 >= 2 ) :
     Oooo000 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( Oooo000 ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , iI11i1ii11i11 . rloc_name = lisp_decode_dist_name ( packet )
      if 66 - 66: IiII . I1Ii111 - oO0o
      if ( packet == None ) : return ( None )
      ii111iIii1 -= len ( iI11i1ii11i11 . rloc_name ) + 1 + 2
      if 12 - 12: i1IIi / I11i
      if 79 - 79: I1IiiI + II111iiii + ooOoO0o % OoO0O00
      if 72 - 72: OOooOOo * OoOoOO00
   self . rle = ooo0o0O
   self . rle . build_forwarding_list ( )
   if 81 - 81: II111iiii / I11i - ooOoO0o - i1IIi - I1Ii111
  elif ( IIiiIIi1II11 == LISP_LCAF_SECURITY_TYPE ) :
   if 38 - 38: OoOoOO00 . iII111i / O0 . OOooOOo + OOooOOo
   if 4 - 4: I11i
   if 95 - 95: II111iiii % o0oOOo0O0Ooo . I11i
   if 18 - 18: O0 / OoooooooOO * Oo0Ooo % iII111i
   if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
   i1iiI11i1 = packet
   OO = lisp_keys ( 1 )
   packet = OO . decode_lcaf ( i1iiI11i1 , ii111iIii1 )
   if ( packet == None ) : return ( None )
   if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
   if 46 - 46: o0oOOo0O0Ooo
   if 28 - 28: i1IIi
   if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
   i1I1IiiIIIiiI = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( OO . cipher_suite in i1I1IiiIIIiiI ) :
    if ( OO . cipher_suite == LISP_CS_25519_CBC ) :
     Ooo00o000o = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 62 - 62: I1Ii111 * I11i / I11i
    if ( OO . cipher_suite == LISP_CS_25519_CHACHA ) :
     Ooo00o000o = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 42 - 42: ooOoO0o * ooOoO0o / Ii1I / OOooOOo * OOooOOo
   else :
    Ooo00o000o = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 92 - 92: Oo0Ooo / iII111i - OoooooooOO - o0oOOo0O0Ooo % ooOoO0o
   packet = Ooo00o000o . decode_lcaf ( i1iiI11i1 , ii111iIii1 )
   if ( packet == None ) : return ( None )
   if 35 - 35: i1IIi % iII111i % I11i * iIii1I11I1II1 % Ii1I - Oo0Ooo
   if ( len ( packet ) < 2 ) : return ( None )
   Oooo000 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( Oooo000 )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 94 - 94: iII111i
   if 68 - 68: OoooooooOO % OOooOOo / OoooooooOO / I1Ii111 + Ii1I - o0oOOo0O0Ooo
   if 81 - 81: I1IiiI
   if 62 - 62: Ii1I * OoOoOO00
   if 27 - 27: Oo0Ooo + Oo0Ooo / II111iiii % I1Ii111
   if 11 - 11: Ii1I
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 54 - 54: I1IiiI * I1Ii111 / ooOoO0o / iIii1I11I1II1 % iII111i / oO0o
   I1Iii1i = self . rloc_name
   if ( I1Iii1i ) : I1Iii1i = blue ( self . rloc_name , False )
   if 50 - 50: Oo0Ooo
   if 14 - 14: O0
   if 67 - 67: II111iiii / O0
   if 10 - 10: i1IIi / Oo0Ooo
   if 20 - 20: Oo0Ooo * I1Ii111 / I1ii11iIi11i . ooOoO0o
   if 67 - 67: o0oOOo0O0Ooo . Oo0Ooo % I11i
   IiIi1 = self . keys [ 1 ] if self . keys else None
   if ( IiIi1 == None ) :
    if ( Ooo00o000o . remote_public_key == None ) :
     ii1111Iii11i = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( ii1111Iii11i , I1Iii1i ) )
     Ooo00o000o = None
    else :
     ii1111Iii11i = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( ii1111Iii11i , I1Iii1i ) )
     Ooo00o000o . compute_shared_key ( "encap" )
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
   if ( IiIi1 ) :
    if ( Ooo00o000o . remote_public_key == None ) :
     Ooo00o000o = None
     oo000O = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( oo000O , I1Iii1i ) )
    elif ( IiIi1 . compare_keys ( Ooo00o000o ) ) :
     Ooo00o000o = IiIi1
     lprint ( "    Maintain stored encap-keys for {}" . format ( I1Iii1i ) )
     if 18 - 18: Ii1I % o0oOOo0O0Ooo - Oo0Ooo
    else :
     if ( IiIi1 . remote_public_key == None ) :
      ii1111Iii11i = "New encap-keying for existing state"
     else :
      ii1111Iii11i = "Remote encap-rekeying"
      if 28 - 28: IiII
     lprint ( "    {} for {}" . format ( bold ( ii1111Iii11i , False ) ,
 I1Iii1i ) )
     IiIi1 . remote_public_key = Ooo00o000o . remote_public_key
     IiIi1 . compute_shared_key ( "encap" )
     Ooo00o000o = IiIi1
     if 93 - 93: Oo0Ooo % i1IIi
     if 51 - 51: oO0o % O0
   self . keys = [ None , Ooo00o000o , None , None ]
   if 41 - 41: I1IiiI * I1IiiI . I1Ii111
  else :
   if 38 - 38: I1IiiI % i11iIiiIii
   if 17 - 17: i11iIiiIii
   if 81 - 81: I1Ii111
   if 25 - 25: I1IiiI
   packet = packet [ ii111iIii1 : : ]
   if 52 - 52: I1ii11iIi11i % i1IIi . IiII % OoOoOO00
  return ( packet )
  if 50 - 50: OOooOOo * I1IiiI / o0oOOo0O0Ooo
  if 91 - 91: iIii1I11I1II1 / OOooOOo * O0 . o0oOOo0O0Ooo + oO0o / I1ii11iIi11i
 def decode ( self , packet , nonce , ms_json_encrypt = False ) :
  II111I11iI = "BBBBHH"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 33 - 33: II111iiii + Ii1I
  self . priority , self . weight , self . mpriority , self . mweight , OoO0o0oOOoOoo , Oooo000 = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  if 46 - 46: IiII + O0 + i1IIi + ooOoO0o / iII111i
  if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
  OoO0o0oOOoOoo = socket . ntohs ( OoO0o0oOOoOoo )
  Oooo000 = socket . ntohs ( Oooo000 )
  self . local_bit = True if ( OoO0o0oOOoOoo & 0x0004 ) else False
  self . probe_bit = True if ( OoO0o0oOOoOoo & 0x0002 ) else False
  self . reach_bit = True if ( OoO0o0oOOoOoo & 0x0001 ) else False
  if 59 - 59: I11i % Ii1I / OoOoOO00
  if ( Oooo000 == LISP_AFI_LCAF ) :
   packet = packet [ oO000 - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
  else :
   self . rloc . afi = Oooo000
   packet = packet [ oO000 : : ]
   packet = self . rloc . unpack_address ( packet )
   if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
  if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
 def end_of_rlocs ( self , packet , rloc_count ) :
  for iIi1iIIIiIiI in range ( rloc_count ) :
   packet = self . decode ( packet , None , False )
   if ( packet == None ) : return ( None )
   if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
  return ( packet )
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
class lisp_map_referral ( object ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 80 - 80: ooOoO0o + iIii1I11I1II1 . II111iiii + I1IiiI - oO0o % OoOoOO00
  if 10 - 10: iIii1I11I1II1
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # iII111i - iIii1I11I1II1 + oO0o
 lisp_hex_string ( self . nonce ) ) )
  if 36 - 36: iII111i . I11i . i1IIi + I11i
  if 97 - 97: II111iiii . OoooooooOO - OoOoOO00
 def encode ( self ) :
  Iii1 = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  Oo00oo = struct . pack ( "I" , socket . htonl ( Iii1 ) )
  Oo00oo += struct . pack ( "Q" , self . nonce )
  return ( Oo00oo )
  if 35 - 35: I1Ii111
  if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
 def decode ( self , packet ) :
  II111I11iI = "I"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
  Iii1 = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  Iii1 = socket . ntohl ( Iii1 [ 0 ] )
  self . record_count = Iii1 & 0xff
  packet = packet [ oO000 : : ]
  if 92 - 92: iII111i % I1ii11iIi11i
  II111I11iI = "Q"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 16 - 16: oO0o
  self . nonce = struct . unpack ( II111I11iI , packet [ : oO000 ] ) [ 0 ]
  packet = packet [ oO000 : : ]
  return ( packet )
  if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
  if 24 - 24: Ii1I + IiII + OoooooooOO / oO0o / I1IiiI + IiII
  if 52 - 52: ooOoO0o
  if 38 - 38: OoO0O00 + I1IiiI % IiII
  if 87 - 87: oO0o * Ii1I - I1Ii111 / oO0o
  if 65 - 65: OoOoOO00
  if 87 - 87: I11i - i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
  if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
class lisp_ddt_entry ( object ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 84 - 84: OOooOOo * i1IIi . iIii1I11I1II1 * iII111i + I1Ii111 + II111iiii
  if 97 - 97: Ii1I - IiII
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 64 - 64: oO0o . ooOoO0o / ooOoO0o - II111iiii
  if 81 - 81: I1ii11iIi11i
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 64 - 64: oO0o * OoO0O00 / OOooOOo + Ii1I % Oo0Ooo . IiII
  if 2 - 2: I1Ii111 + I11i
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  Ii1iII = self . delegation_set [ 0 ]
  return ( Ii1iII . print_node_type ( ) )
  if 71 - 71: iII111i + IiII + I1IiiI - OoOoOO00
  if 49 - 49: I1IiiI % O0 - OoooooooOO * OoO0O00 / iIii1I11I1II1 + I11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 7 - 7: iII111i * I1ii11iIi11i / oO0o
  if 31 - 31: I1ii11iIi11i - II111iiii
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   O000oO0Oo0 = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( O000oO0Oo0 == None ) :
    O000oO0Oo0 = lisp_ddt_entry ( )
    O000oO0Oo0 . eid . copy_address ( self . group )
    O000oO0Oo0 . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , O000oO0Oo0 )
    if 83 - 83: i1IIi
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( O000oO0Oo0 . group )
   O000oO0Oo0 . add_source_entry ( self )
   if 2 - 2: i1IIi / OOooOOo * O0
   if 99 - 99: OoooooooOO . OoOoOO00 / II111iiii
   if 64 - 64: iII111i / i1IIi . I1IiiI + O0
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 5 - 5: O0 . i11iIiiIii
  if 71 - 71: o0oOOo0O0Ooo + iII111i + ooOoO0o
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 27 - 27: OoooooooOO . iII111i * I1Ii111 % O0 + OoooooooOO - iII111i
  if 86 - 86: i1IIi
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 81 - 81: OoOoOO00
  if 52 - 52: iII111i * IiII % I1IiiI * I11i
  if 73 - 73: I1Ii111 * ooOoO0o
class lisp_ddt_node ( object ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 62 - 62: OOooOOo . I1IiiI * iIii1I11I1II1 + OoO0O00 * ooOoO0o / oO0o
  if 14 - 14: iII111i / OoO0O00
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 75 - 75: IiII
  if 68 - 68: IiII - i1IIi % IiII . OoO0O00 . i11iIiiIii . OoooooooOO
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 32 - 32: iII111i + OoO0O00 % IiII + I1IiiI
  if 69 - 69: I1Ii111 + I11i - iIii1I11I1II1 - II111iiii . Ii1I
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 74 - 74: I1ii11iIi11i % o0oOOo0O0Ooo + O0 - i11iIiiIii - IiII % OOooOOo
  if 39 - 39: OoO0O00 - o0oOOo0O0Ooo
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 71 - 71: iII111i . OoO0O00 + ooOoO0o - OOooOOo - Oo0Ooo
  if 100 - 100: OoooooooOO - o0oOOo0O0Ooo + I1Ii111 . OoooooooOO % i11iIiiIii
  if 64 - 64: I1Ii111 % OoooooooOO / i1IIi / OoO0O00
  if 2 - 2: I11i % o0oOOo0O0Ooo . OoO0O00 . OoO0O00
  if 89 - 89: ooOoO0o - oO0o + II111iiii + OoO0O00 - IiII
  if 27 - 27: I1Ii111 - o0oOOo0O0Ooo + OoO0O00
  if 38 - 38: OoOoOO00 + OoO0O00 . i11iIiiIii + Ii1I % i1IIi % I1IiiI
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
  if 93 - 93: i11iIiiIii
  if 63 - 63: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # Ii1I + Ii1I / OoOoOO00 % OOooOOo / OoOoOO00 . I1ii11iIi11i
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 11 - 11: iIii1I11I1II1 * OoOoOO00 / IiII . OOooOOo . iIii1I11I1II1
  if 38 - 38: i11iIiiIii + I1IiiI . i11iIiiIii - I11i * OOooOOo
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 59 - 59: iII111i / OoOoOO00 + OoOoOO00 - I1IiiI
  if 10 - 10: Ii1I / II111iiii
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( self . nonce in lisp_ddt_map_requestQ ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 53 - 53: i11iIiiIii . i1IIi . I1IiiI . ooOoO0o * OoOoOO00
   if 98 - 98: I1ii11iIi11i + ooOoO0o
   if 42 - 42: Oo0Ooo + OoOoOO00 - O0 / Oo0Ooo - OoooooooOO . Ii1I
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
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
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 62 - 62: o0oOOo0O0Ooo * I1Ii111 . iIii1I11I1II1 / i1IIi
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
if 35 - 35: i11iIiiIii + oO0o
if 85 - 85: OoOoOO00 . O0 % OoooooooOO % oO0o
if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
if 12 - 12: II111iiii - iIii1I11I1II1
if 43 - 43: i11iIiiIii % OoO0O00
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
  if 100 - 100: i1IIi
  if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
 def print_info ( self ) :
  if ( self . info_reply ) :
   O0o0oO00oO0OO = "Info-Reply"
   I1Ii1i111I = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # I1IiiI % IiII / II111iiii / II111iiii
   # OoO0O00 + OoOoOO00 / o0oOOo0O0Ooo . I11i / O0 - I11i
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : I1Ii1i111I += "empty, "
   for i11 in self . rtr_list :
    I1Ii1i111I += red ( i11 . print_address_no_iid ( ) , False ) + ", "
    if 17 - 17: iIii1I11I1II1
   I1Ii1i111I = I1Ii1i111I [ 0 : - 2 ]
  else :
   O0o0oO00oO0OO = "Info-Request"
   iiI1I = "<none>" if self . hostname == None else self . hostname
   I1Ii1i111I = ", hostname: {}" . format ( blue ( iiI1I , False ) )
   if 98 - 98: Ii1I % iII111i . I11i
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( O0o0oO00oO0OO , False ) ,
 lisp_hex_string ( self . nonce ) , I1Ii1i111I ) )
  if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i % o0oOOo0O0Ooo . ooOoO0o - oO0o
  if 64 - 64: I11i * ooOoO0o
 def encode ( self ) :
  Iii1 = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : Iii1 |= ( 1 << 27 )
  if 86 - 86: OoooooooOO * I1IiiI
  if 88 - 88: Ii1I + O0
  if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
  if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
  if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
  if 85 - 85: OoooooooOO * ooOoO0o
  if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
  Oo00oo = struct . pack ( "I" , socket . htonl ( Iii1 ) )
  Oo00oo += struct . pack ( "Q" , self . nonce )
  Oo00oo += struct . pack ( "III" , 0 , 0 , 0 )
  if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
  if 26 - 26: O0 % o0oOOo0O0Ooo + iII111i * I1ii11iIi11i * I1Ii111
  if 4 - 4: OOooOOo * OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
  if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    Oo00oo += struct . pack ( "H" , 0 )
   else :
    Oo00oo += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    Oo00oo += ( self . hostname + "\0" ) . encode ( )
    if 62 - 62: I1Ii111 % II111iiii
   return ( Oo00oo )
   if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
   if 91 - 91: i11iIiiIii + Ii1I
   if 85 - 85: I11i % IiII
   if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
   if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
  Oooo000 = socket . htons ( LISP_AFI_LCAF )
  IIiiIIi1II11 = LISP_LCAF_NAT_TYPE
  ii111iIii1 = socket . htons ( 16 )
  I111IiiI1 = socket . htons ( self . ms_port )
  Oo0OO = socket . htons ( self . etr_port )
  Oo00oo += struct . pack ( "HHBBHHHH" , Oooo000 , 0 , IIiiIIi1II11 , 0 , ii111iIii1 ,
 I111IiiI1 , Oo0OO , socket . htons ( self . global_etr_rloc . afi ) )
  Oo00oo += self . global_etr_rloc . pack_address ( )
  Oo00oo += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  Oo00oo += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : Oo00oo += struct . pack ( "H" , 0 )
  if 83 - 83: oO0o . II111iiii * Ii1I / ooOoO0o % iIii1I11I1II1
  if 40 - 40: i1IIi % I1Ii111 - oO0o / oO0o / I1ii11iIi11i % O0
  if 82 - 82: OoO0O00 - I1IiiI - i1IIi - I1IiiI % OOooOOo
  if 80 - 80: OoOoOO00
  for i11 in self . rtr_list :
   Oo00oo += struct . pack ( "H" , socket . htons ( i11 . afi ) )
   Oo00oo += i11 . pack_address ( )
   if 31 - 31: OOooOOo * ooOoO0o + ooOoO0o / O0 - OOooOOo
  return ( Oo00oo )
  if 47 - 47: I1Ii111 . OoooooooOO - oO0o - o0oOOo0O0Ooo . I1ii11iIi11i / iIii1I11I1II1
  if 20 - 20: i11iIiiIii / OoO0O00 * I1IiiI - I1IiiI * Ii1I
 def decode ( self , packet ) :
  i1iiI11i1 = packet
  II111I11iI = "I"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 73 - 73: ooOoO0o % I1Ii111
  Iii1 = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  Iii1 = Iii1 [ 0 ]
  packet = packet [ oO000 : : ]
  if 69 - 69: OoOoOO00 / OOooOOo / I1IiiI
  II111I11iI = "Q"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 12 - 12: I1ii11iIi11i . iIii1I11I1II1 . II111iiii . OoOoOO00
  oOooo0oOOOO = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  if 30 - 30: i11iIiiIii / Oo0Ooo / OOooOOo + i11iIiiIii * ooOoO0o
  Iii1 = socket . ntohl ( Iii1 )
  self . nonce = oOooo0oOOOO [ 0 ]
  self . info_reply = Iii1 & 0x08000000
  self . hostname = None
  packet = packet [ oO000 : : ]
  if 4 - 4: O0 + I1IiiI + I1Ii111
  if 80 - 80: Ii1I % OoooooooOO . i1IIi - OOooOOo
  if 10 - 10: I11i + iII111i % OoO0O00 / OoO0O00
  if 91 - 91: ooOoO0o . oO0o
  if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
  II111I11iI = "HH"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
  if 81 - 81: i1IIi % iIii1I11I1II1
  if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
  if 82 - 82: ooOoO0o
  if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
  i11iII1 , o0o0OO0OO = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  if ( o0o0OO0OO != 0 ) : return ( None )
  if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
  packet = packet [ oO000 : : ]
  II111I11iI = "IBBH"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 59 - 59: i11iIiiIii / OoO0O00
  IiIi1iIIiII1i , oo00O0OO0oo0O , iiiO0OO00o00Oo , oo0ooO0 = struct . unpack ( II111I11iI ,
 packet [ : oO000 ] )
  if 52 - 52: II111iiii + O0 + I1ii11iIi11i / OoOoOO00
  if ( oo0ooO0 != 0 ) : return ( None )
  packet = packet [ oO000 : : ]
  if 55 - 55: IiII % O0 * OoooooooOO / iII111i - i11iIiiIii % O0
  if 100 - 100: O0 - OoO0O00 / OoO0O00
  if 51 - 51: II111iiii % OoO0O00
  if 85 - 85: i11iIiiIii % iII111i + II111iiii
  if ( self . info_reply == False ) :
   II111I11iI = "H"
   oO000 = struct . calcsize ( II111I11iI )
   if ( len ( packet ) >= oO000 ) :
    Oooo000 = struct . unpack ( II111I11iI , packet [ : oO000 ] ) [ 0 ]
    if ( socket . ntohs ( Oooo000 ) == LISP_AFI_NAME ) :
     packet = packet [ oO000 : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 16 - 16: ooOoO0o * OoOoOO00 / OoOoOO00 + II111iiii
     if 50 - 50: OoO0O00 / OOooOOo % I1IiiI / Ii1I + OoO0O00 . iIii1I11I1II1
   return ( i1iiI11i1 )
   if 62 - 62: I1Ii111 + OoooooooOO - Ii1I - iIii1I11I1II1
   if 80 - 80: OoO0O00
   if 72 - 72: II111iiii % i11iIiiIii + OoOoOO00 / I1Ii111 - i11iIiiIii
   if 39 - 39: i11iIiiIii - OOooOOo / OoO0O00 * OoOoOO00 / IiII
   if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 / Ii1I / II111iiii
  II111I11iI = "HHBBHHH"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 56 - 56: OOooOOo * iII111i / Ii1I
  Oooo000 , iIiiiI1 , IIiiIIi1II11 , oo00O0OO0oo0O , ii111iIii1 , I111IiiI1 , Oo0OO = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  if 9 - 9: I1ii11iIi11i * i11iIiiIii / I1Ii111 + iIii1I11I1II1
  if 1 - 1: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / oO0o
  if ( socket . ntohs ( Oooo000 ) != LISP_AFI_LCAF ) : return ( None )
  if 73 - 73: iII111i
  self . ms_port = socket . ntohs ( I111IiiI1 )
  self . etr_port = socket . ntohs ( Oo0OO )
  packet = packet [ oO000 : : ]
  if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo
  if 45 - 45: oO0o % O0 / O0
  if 98 - 98: I1Ii111
  if 58 - 58: OOooOOo
  II111I11iI = "H"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 6 - 6: I1ii11iIi11i
  if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
  if 18 - 18: ooOoO0o
  if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
  Oooo000 = struct . unpack ( II111I11iI , packet [ : oO000 ] ) [ 0 ]
  packet = packet [ oO000 : : ]
  if ( Oooo000 != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( Oooo000 )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
   if 29 - 29: Ii1I . II111iiii / I1Ii111
   if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
   if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
   if 81 - 81: i11iIiiIii - II111iiii + I11i
   if 52 - 52: II111iiii
  if ( len ( packet ) < oO000 ) : return ( i1iiI11i1 )
  if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
  Oooo000 = struct . unpack ( II111I11iI , packet [ : oO000 ] ) [ 0 ]
  packet = packet [ oO000 : : ]
  if ( Oooo000 != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( Oooo000 )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( i1iiI11i1 )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 26 - 26: I1ii11iIi11i - OoO0O00
   if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
   if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
   if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
   if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
  if ( len ( packet ) < oO000 ) : return ( i1iiI11i1 )
  if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
  Oooo000 = struct . unpack ( II111I11iI , packet [ : oO000 ] ) [ 0 ]
  packet = packet [ oO000 : : ]
  if ( Oooo000 != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( Oooo000 )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( i1iiI11i1 )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 15 - 15: Ii1I
   if 29 - 29: I11i / I1IiiI / OoooooooOO . OoOoOO00 / I11i . I1Ii111
   if 69 - 69: O0 * OoOoOO00 + o0oOOo0O0Ooo + I1IiiI % iII111i . OoooooooOO
   if 45 - 45: I1Ii111 + oO0o - o0oOOo0O0Ooo - OoOoOO00 + I1IiiI / II111iiii
   if 46 - 46: II111iiii . iIii1I11I1II1
   if 62 - 62: I1ii11iIi11i % i1IIi % I1Ii111 * ooOoO0o % OOooOOo + I1IiiI
  while ( len ( packet ) >= oO000 ) :
   Oooo000 = struct . unpack ( II111I11iI , packet [ : oO000 ] ) [ 0 ]
   packet = packet [ oO000 : : ]
   if ( Oooo000 == 0 ) : continue
   i11 = lisp_address ( socket . ntohs ( Oooo000 ) , "" , 0 , 0 )
   packet = i11 . unpack_address ( packet )
   if ( packet == None ) : return ( i1iiI11i1 )
   i11 . mask_len = i11 . host_mask_len ( )
   self . rtr_list . append ( i11 )
   if 100 - 100: II111iiii - o0oOOo0O0Ooo * OoooooooOO . ooOoO0o / II111iiii / oO0o
  return ( i1iiI11i1 )
  if 43 - 43: iIii1I11I1II1 + ooOoO0o * iII111i + iIii1I11I1II1 . I1Ii111
  if 87 - 87: I1Ii111
  if 47 - 47: II111iiii + I1IiiI . Oo0Ooo / iIii1I11I1II1
class lisp_nat_info ( object ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 14 - 14: i1IIi / OoO0O00 / iII111i % I1Ii111
  if 72 - 72: OoO0O00 . II111iiii - IiII + IiII + iIii1I11I1II1 % oO0o
 def timed_out ( self ) :
  i1i111Iiiiiii = time . time ( ) - self . uptime
  return ( i1i111Iiiiiii >= ( LISP_INFO_INTERVAL * 2 ) )
  if 21 - 21: iII111i + OoOoOO00 - i11iIiiIii % O0 + OOooOOo
  if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
  if 94 - 94: IiII
class lisp_info_source ( object ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 69 - 69: I1Ii111 . I1Ii111
  if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
 def cache_address_for_info_source ( self ) :
  Ooo00o000o = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ Ooo00o000o ] = self
  if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
  if 8 - 8: iII111i % o0oOOo0O0Ooo
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
  if 87 - 87: Ii1I % I11i / I1Ii111
  if 21 - 21: OoO0O00 + Ii1I / I1Ii111
  if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
  if 38 - 38: i1IIi
  if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
  if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
  if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
  if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
  if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
  if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
  if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 2 - 2: OOooOOo / I11i * I11i + I11i / O0 - OOooOOo
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 68 - 68: iII111i / OOooOOo
  if 28 - 28: II111iiii
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  Ooooo0OO = auth1 + auth2 + auth3
  if 49 - 49: I1ii11iIi11i
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  Ooooo0OO = auth1 + auth2 + auth3 + auth4
  if 33 - 33: iIii1I11I1II1
 return ( Ooooo0OO )
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
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   Ii1i11i1ii1 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 88 - 88: OoooooooOO % i1IIi
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   Ii1i11i1ii1 = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 78 - 78: Ii1I - i11iIiiIii
  Ii1i11i1ii1 . bind ( ( local_addr , int ( port ) ) )
 else :
  o0o = port
  if ( os . path . exists ( o0o ) ) :
   os . system ( "rm " + o0o )
   time . sleep ( 1 )
   if 26 - 26: iII111i % I1Ii111
  Ii1i11i1ii1 = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  Ii1i11i1ii1 . bind ( o0o )
  if 37 - 37: OoOoOO00 . I1ii11iIi11i / II111iiii % oO0o % II111iiii
 return ( Ii1i11i1ii1 )
 if 14 - 14: OoooooooOO / i11iIiiIii / I1ii11iIi11i - Ii1I * I1IiiI / ooOoO0o
 if 98 - 98: Oo0Ooo - O0
 if 22 - 22: OOooOOo - OoO0O00 * OoooooooOO + iII111i / iIii1I11I1II1
 if 12 - 12: OoooooooOO
 if 9 - 9: O0 / O0 / I1IiiI - oO0o . ooOoO0o
 if 6 - 6: O0 - OoO0O00 + OoooooooOO % iIii1I11I1II1
 if 58 - 58: i11iIiiIii * OOooOOo . Oo0Ooo / iII111i - i1IIi
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   Ii1i11i1ii1 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 45 - 45: Ii1I
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   Ii1i11i1ii1 = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  Ii1i11i1ii1 = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  Ii1i11i1ii1 . bind ( internal_name )
  if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
 return ( Ii1i11i1ii1 )
 if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
 if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
 if 86 - 86: iII111i / i1IIi % Oo0Ooo
 if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
 if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
 if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
 if 14 - 14: OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 92 - 92: OoO0O00 . i1IIi
 if 22 - 22: Ii1I . I1IiiI
 if 54 - 54: OOooOOo / I1ii11iIi11i % oO0o
 if 66 - 66: I11i + iII111i
 if 50 - 50: IiII
 if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
 if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
 if 55 - 55: OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 37 - 37: Ii1I + o0oOOo0O0Ooo
 if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
 if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
 if 8 - 8: I11i - I11i % IiII
 if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
 if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
 if 25 - 25: iII111i / iII111i % OoOoOO00 / ooOoO0o
 if 81 - 81: OOooOOo * oO0o
 if 32 - 32: Oo0Ooo * OoO0O00 + ooOoO0o . O0 * oO0o * iIii1I11I1II1
 if 50 - 50: i1IIi
 if 53 - 53: II111iiii + O0 . ooOoO0o * IiII + i1IIi
def lisp_packet_ipc ( packet , source , sport ) :
 ooo = "packet@{}@{}@{}@" . format ( str ( len ( packet ) ) , source , str ( sport ) )
 return ( ooo . encode ( ) + packet )
 if 80 - 80: Ii1I + O0
 if 59 - 59: i11iIiiIii - OoooooooOO % I11i . OoO0O00 - Oo0Ooo * o0oOOo0O0Ooo
 if 7 - 7: II111iiii % Ii1I * i11iIiiIii
 if 28 - 28: II111iiii / ooOoO0o * i11iIiiIii % OOooOOo
 if 18 - 18: I11i - IiII - iIii1I11I1II1
 if 82 - 82: II111iiii + OoO0O00 % iIii1I11I1II1 / O0
 if 75 - 75: OOooOOo * OoO0O00 + OoooooooOO + i11iIiiIii . OoO0O00
 if 94 - 94: I11i * ooOoO0o . I1IiiI / Ii1I - I1IiiI % OoooooooOO
 if 32 - 32: OoO0O00
 if 22 - 22: II111iiii . I11i
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 ooo = "control-packet@{}@{}@" . format ( dest , str ( dport ) )
 return ( ooo . encode ( ) + packet )
 if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
 if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
 if 94 - 94: OOooOOo / IiII
 if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
 if 22 - 22: OoOoOO00 - Oo0Ooo
 if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
 if 33 - 33: I11i + O0
 if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
 if 68 - 68: O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
def lisp_data_packet_ipc ( packet , source ) :
 ooo = "data-packet@{}@{}@@" . format ( str ( len ( packet ) ) , source )
 return ( ooo . encode ( ) + packet )
 if 12 - 12: II111iiii + I11i
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
def lisp_command_ipc ( ipc , source ) :
 Oo00oo = "command@{}@{}@@" . format ( len ( ipc ) , source ) + ipc
 return ( Oo00oo . encode ( ) )
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
def lisp_api_ipc ( source , data ) :
 Oo00oo = "api@" + str ( len ( data ) ) + "@" + source + "@@" + data
 return ( Oo00oo . encode ( ) )
 if 99 - 99: Ii1I
 if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
 if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
 if 21 - 21: iII111i
 if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
 if 75 - 75: OoooooooOO
 if 24 - 24: oO0o % iII111i - II111iiii / Ii1I + O0
 if 37 - 37: I1Ii111 - i1IIi / iIii1I11I1II1
 if 53 - 53: Ii1I - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii + ooOoO0o
 if 63 - 63: Oo0Ooo * I1IiiI
 if 84 - 84: Oo0Ooo
 if 67 - 67: oO0o / II111iiii . I11i / oO0o
def lisp_ipc ( packet , send_socket , node ) :
 if 46 - 46: oO0o * Oo0Ooo - I11i / iIii1I11I1II1
 if 100 - 100: i11iIiiIii % oO0o
 if 62 - 62: OOooOOo * i1IIi - OOooOOo / i11iIiiIii
 if 17 - 17: I1ii11iIi11i + ooOoO0o % Ii1I % OOooOOo
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 73 - 73: i11iIiiIii
  if 44 - 44: o0oOOo0O0Ooo % Ii1I - OoOoOO00 + OoOoOO00 * IiII + iII111i
 OOOOoooOooO0 = 1500 if ( packet . find ( b"control-packet" ) == - 1 ) else 9000
 if 25 - 25: I1ii11iIi11i / i1IIi * oO0o - II111iiii * i1IIi
 oo00 = 0
 i1iIii = len ( packet )
 oOOOOooOoo = 0
 o0O = .001
 while ( i1iIii > 0 ) :
  I1i1 = min ( i1iIii , OOOOoooOooO0 )
  o0o0oOoo0O = packet [ oo00 : I1i1 + oo00 ]
  if 40 - 40: i11iIiiIii - o0oOOo0O0Ooo . I11i + I11i % i1IIi
  try :
   if ( type ( o0o0oOoo0O ) == str ) : o0o0oOoo0O = o0o0oOoo0O . encode ( )
   send_socket . sendto ( o0o0oOoo0O , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( o0o0oOoo0O ) , len ( packet ) , node ) )
   if 86 - 86: I1IiiI
   oOOOOooOoo = 0
   o0O = .001
   if 93 - 93: IiII % OoooooooOO - OoOoOO00
  except socket . error as oO0ooOOO :
   if ( oOOOOooOoo == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 36 - 36: O0 * Ii1I * Ii1I
    if 62 - 62: OoooooooOO
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( o0o0oOoo0O ) , len ( packet ) , node , oO0ooOOO ) )
   if 10 - 10: Ii1I * Oo0Ooo - I1Ii111
   if 11 - 11: iII111i % I11i
   oOOOOooOoo += 1
   time . sleep ( o0O )
   if 42 - 42: II111iiii * i1IIi + i1IIi * o0oOOo0O0Ooo + Ii1I . IiII
   lprint ( "Retrying after {} ms ..." . format ( o0O * 1000 ) )
   o0O *= 2
   continue
   if 72 - 72: I1Ii111
   if 3 - 3: I1Ii111 + O0
  oo00 += I1i1
  i1iIii -= I1i1
  if 20 - 20: I11i * I1ii11iIi11i + o0oOOo0O0Ooo * i1IIi
 return
 if 45 - 45: i11iIiiIii / iII111i
 if 51 - 51: Oo0Ooo - O0 % o0oOOo0O0Ooo / I1ii11iIi11i
 if 60 - 60: iII111i / OoooooooOO * II111iiii * Oo0Ooo * o0oOOo0O0Ooo
 if 60 - 60: iII111i . OOooOOo
 if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
 if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
 if 19 - 19: I1IiiI
 if 99 - 99: OOooOOo - OOooOOo
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 oo00 = 0
 Iii11Ii = b""
 i1iIii = len ( packet ) * 2
 while ( oo00 < i1iIii ) :
  Iii11Ii += packet [ oo00 : oo00 + 8 ] + b" "
  oo00 += 8
  i1iIii -= 4
  if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
 return ( Iii11Ii . decode ( ) )
 if 83 - 83: o0oOOo0O0Ooo
 if 23 - 23: o0oOOo0O0Ooo . I11i
 if 67 - 67: iII111i
 if 52 - 52: IiII . OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / IiII . OoooooooOO . Oo0Ooo / ooOoO0o + O0
 if 38 - 38: I11i
 if 66 - 66: II111iiii
def lisp_send ( lisp_sockets , dest , port , packet ) :
 OO0O = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 88 - 88: OOooOOo - I1ii11iIi11i % iII111i
 if 58 - 58: OoO0O00 . O0 - i11iIiiIii . I1IiiI
 if 95 - 95: OoooooooOO / ooOoO0o * I11i - Ii1I
 if 94 - 94: I1Ii111 + OoO0O00 . OoooooooOO
 if 60 - 60: Ii1I . II111iiii
 if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
 if 50 - 50: OoooooooOO + o0oOOo0O0Ooo + iIii1I11I1II1 + OOooOOo
 if 90 - 90: Ii1I * I11i % I1Ii111 - I1ii11iIi11i * I1Ii111 % OoO0O00
 if 50 - 50: iIii1I11I1II1
 if 56 - 56: oO0o
 if 55 - 55: iIii1I11I1II1 % oO0o % OOooOOo / I1Ii111 * OoooooooOO / Oo0Ooo
 if 88 - 88: I11i + OoO0O00 . iIii1I11I1II1 . II111iiii
 I1IIIi = dest . print_address_no_iid ( )
 if ( I1IIIi . find ( "::ffff:" ) != - 1 and I1IIIi . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : OO0O = lisp_sockets [ 0 ]
  if ( OO0O == None ) :
   OO0O = lisp_sockets [ 0 ]
   I1IIIi = I1IIIi . split ( "::ffff:" ) [ - 1 ]
   if 67 - 67: OOooOOo - ooOoO0o % iII111i % IiII
   if 71 - 71: OoO0O00 - ooOoO0o - I1IiiI + O0
   if 15 - 15: i1IIi
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + I1IIIi , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 43 - 43: II111iiii + OOooOOo . i11iIiiIii - II111iiii
 if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
 if 26 - 26: i1IIi - I1IiiI + IiII / OoO0O00 . I1ii11iIi11i
 if 82 - 82: I1Ii111 % iII111i . OoOoOO00 % OoO0O00 + I1ii11iIi11i
 OOOOo0ooOoOO = ( LISP_RLOC_PROBE_TTL == 128 )
 if ( OOOOo0ooOoOO ) :
  Oo00OoOOoOOo = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  OOOOo0ooOoOO = ( Oo00OoOOoOOo in [ 0x12 , 0x28 ] )
  if ( OOOOo0ooOoOO ) : lisp_set_ttl ( OO0O , LISP_RLOC_PROBE_TTL )
  if 40 - 40: iIii1I11I1II1 / OoO0O00 * II111iiii + IiII % I1Ii111 / iIii1I11I1II1
  if 79 - 79: iII111i . O0 * Oo0Ooo % o0oOOo0O0Ooo % OoO0O00
 try : OO0O . sendto ( packet , ( I1IIIi , port ) )
 except socket . error as oO0ooOOO :
  lprint ( "socket.sendto() failed: {}" . format ( oO0ooOOO ) )
  if 77 - 77: II111iiii - I1Ii111
  if 88 - 88: Ii1I - OOooOOo + Oo0Ooo . OoooooooOO
  if 50 - 50: i11iIiiIii % Oo0Ooo . I1Ii111
  if 96 - 96: iIii1I11I1II1 % iIii1I11I1II1
  if 18 - 18: iII111i . Oo0Ooo
 if ( OOOOo0ooOoOO ) : lisp_set_ttl ( OO0O , 64 )
 return
 if 4 - 4: o0oOOo0O0Ooo % oO0o - OoOoOO00 * iIii1I11I1II1
 if 96 - 96: Ii1I
 if 1 - 1: i1IIi % O0 / I11i
 if 52 - 52: I1IiiI + oO0o * II111iiii
 if 15 - 15: I11i
 if 72 - 72: O0
 if 15 - 15: II111iiii / I11i % II111iiii % Ii1I % i11iIiiIii / I1Ii111
 if 93 - 93: OOooOOo / OoooooooOO % iII111i
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 47 - 47: o0oOOo0O0Ooo - I1IiiI % O0 % I1Ii111 . O0 . OoOoOO00
 if 95 - 95: o0oOOo0O0Ooo * OOooOOo - iII111i * OoooooooOO - ooOoO0o / I1IiiI
 if 47 - 47: OoO0O00 % I1IiiI / OoOoOO00 - I1Ii111 / I1IiiI
 if 13 - 13: o0oOOo0O0Ooo % ooOoO0o
 if 15 - 15: iII111i * I1IiiI . iIii1I11I1II1 % I1IiiI / O0
 I1i1 = total_length - len ( packet )
 if ( I1i1 == 0 ) : return ( [ True , packet ] )
 if 47 - 47: OoooooooOO - i11iIiiIii . I1IiiI / i1IIi
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 74 - 74: OoooooooOO * ooOoO0o
 if 45 - 45: Oo0Ooo + iIii1I11I1II1 . o0oOOo0O0Ooo
 if 50 - 50: o0oOOo0O0Ooo % O0
 if 67 - 67: OoOoOO00
 if 21 - 21: I11i % Oo0Ooo + Oo0Ooo / iIii1I11I1II1 % iIii1I11I1II1
 i1iIii = I1i1
 while ( i1iIii > 0 ) :
  try : o0o0oOoo0O = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 66 - 66: iII111i
  o0o0oOoo0O = o0o0oOoo0O [ 0 ]
  if 72 - 72: ooOoO0o / oO0o / iII111i . I1Ii111 . I1ii11iIi11i + IiII
  if 39 - 39: I1IiiI % I1Ii111
  if 22 - 22: OoOoOO00 - OOooOOo % i1IIi + i1IIi
  if 28 - 28: oO0o + OoOoOO00 * Ii1I . I11i
  if 80 - 80: I1ii11iIi11i / OoOoOO00
  OOOoOO = o0o0oOoo0O . decode ( )
  if ( OOOoOO . find ( "packet@" ) == 0 ) :
   OOOoOO = OOOoOO . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( o0o0oOoo0O ) ,
   # OoO0O00 + ooOoO0o * iIii1I11I1II1 % I1ii11iIi11i + II111iiii + OoOoOO00
 OOOoOO [ 1 ] if len ( OOOoOO ) > 2 else "?" )
   return ( [ False , o0o0oOoo0O ] )
   if 98 - 98: I1Ii111 . I1ii11iIi11i
   if 5 - 5: OoooooooOO / IiII / I1ii11iIi11i / OoO0O00 * i1IIi / iIii1I11I1II1
  i1iIii -= len ( o0o0oOoo0O )
  packet += o0o0oOoo0O
  if 32 - 32: I1Ii111 % Oo0Ooo / OoOoOO00 + OoOoOO00 % i11iIiiIii . OoO0O00
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( o0o0oOoo0O ) , total_length , source ) )
  if 42 - 42: OoO0O00 % ooOoO0o . I11i + ooOoO0o . iIii1I11I1II1 * ooOoO0o
  if 79 - 79: I1ii11iIi11i . IiII * IiII - o0oOOo0O0Ooo
 return ( [ True , packet ] )
 if 49 - 49: iIii1I11I1II1 % Ii1I / OoooooooOO - II111iiii . Ii1I
 if 65 - 65: OoooooooOO + I1Ii111 % ooOoO0o + II111iiii . i1IIi + OoooooooOO
 if 26 - 26: I1IiiI / II111iiii % I1ii11iIi11i * o0oOOo0O0Ooo . IiII / OoO0O00
 if 10 - 10: i11iIiiIii / i1IIi + O0 - i11iIiiIii % I11i - i1IIi
 if 38 - 38: O0 - I1IiiI + Oo0Ooo + ooOoO0o
 if 56 - 56: I1Ii111 + oO0o / Ii1I + I1Ii111
 if 21 - 21: OOooOOo / OoOoOO00 + OoOoOO00 + OoOoOO00 - i1IIi + Ii1I
 if 43 - 43: O0 % II111iiii
 if 60 - 60: iII111i / ooOoO0o - Ii1I - OoooooooOO
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 Oo00oo = b""
 for o0o0oOoo0O in payload : Oo00oo += o0o0oOoo0O + b"\x40"
 return ( Oo00oo [ : - 1 ] )
 if 79 - 79: oO0o / iII111i . iIii1I11I1II1 * i11iIiiIii * i1IIi . iIii1I11I1II1
 if 31 - 31: OoooooooOO / ooOoO0o / OoooooooOO + ooOoO0o . O0 - IiII
 if 53 - 53: Oo0Ooo % iII111i % iII111i
 if 71 - 71: iII111i
 if 99 - 99: O0 - OoOoOO00 * I1Ii111 - Oo0Ooo
 if 62 - 62: i1IIi + ooOoO0o + Oo0Ooo - i11iIiiIii
 if 19 - 19: I1IiiI / OOooOOo
 if 6 - 6: I1ii11iIi11i + IiII * oO0o * OoOoOO00
 if 67 - 67: I1Ii111 + OoooooooOO + OoOoOO00 % iIii1I11I1II1 . I1IiiI
 if 68 - 68: ooOoO0o
 if 68 - 68: I11i % IiII
 if 1 - 1: I1IiiI + OOooOOo - OOooOOo * O0 + o0oOOo0O0Ooo * OOooOOo
 if 48 - 48: ooOoO0o - iII111i + I1ii11iIi11i * I1Ii111 % ooOoO0o * OoO0O00
 if 28 - 28: i1IIi / iII111i + OOooOOo
 if 89 - 89: Oo0Ooo + II111iiii * OoO0O00 + Oo0Ooo % II111iiii
 if 59 - 59: O0 + Oo0Ooo
 if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
 if 50 - 50: I11i . I11i % I1IiiI - i1IIi
 if 63 - 63: OoO0O00 . iII111i
 if 28 - 28: ooOoO0o . Oo0Ooo - OoooooooOO - I1Ii111 - OoooooooOO - oO0o
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 25 - 25: I11i / I1Ii111 . i11iIiiIii % i1IIi
  if 21 - 21: O0 * IiII . iII111i / iII111i % i11iIiiIii / I11i
  if 15 - 15: o0oOOo0O0Ooo / OoO0O00 - i1IIi
  if 30 - 30: OoO0O00 / ooOoO0o % ooOoO0o
  try : iio0OOoO0 = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 71 - 71: iII111i / O0 . OoOoOO00 / iII111i . iIii1I11I1II1
  if 88 - 88: ooOoO0o + II111iiii
  if 89 - 89: i1IIi - i1IIi / iII111i
  if 43 - 43: I1IiiI / IiII
  if 38 - 38: I1ii11iIi11i + i11iIiiIii * I1IiiI % oO0o % OoooooooOO
  if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
  if ( internal == False ) :
   Oo00oo = iio0OOoO0 [ 0 ]
   I1 = lisp_convert_6to4 ( iio0OOoO0 [ 1 ] [ 0 ] )
   I1I = iio0OOoO0 [ 1 ] [ 1 ]
   if 69 - 69: OoooooooOO
   if ( I1I == LISP_DATA_PORT ) :
    IiiiiI = lisp_data_plane_logging
    Ii1111iI = lisp_format_packet ( Oo00oo [ 0 : 60 ] ) + " ..."
   else :
    IiiiiI = True
    Ii1111iI = lisp_format_packet ( Oo00oo )
    if 51 - 51: I1Ii111
    if 51 - 51: O0 + iII111i . oO0o + i11iIiiIii . i11iIiiIii + i11iIiiIii
   if ( IiiiiI ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( Oo00oo ) , bold ( "from " + I1 , False ) , I1I ,
 Ii1111iI ) )
    if 46 - 46: oO0o - OoO0O00
   return ( [ "packet" , I1 , I1I , Oo00oo ] )
   if 74 - 74: i11iIiiIii / iII111i / i1IIi + I1Ii111
   if 33 - 33: IiII % IiII
   if 63 - 63: oO0o - IiII / I1ii11iIi11i
   if 82 - 82: Oo0Ooo - ooOoO0o
   if 25 - 25: I11i + oO0o / I1Ii111 % IiII * OOooOOo - I1Ii111
   if 100 - 100: ooOoO0o . i11iIiiIii * Oo0Ooo - i11iIiiIii
  oOo0o0O = False
  oo0O000OooO0 = iio0OOoO0 [ 0 ]
  if ( type ( oo0O000OooO0 ) == str ) : oo0O000OooO0 = oo0O000OooO0 . encode ( )
  OOOo00oo0 = False
  if 40 - 40: i1IIi . OoO0O00
  while ( oOo0o0O == False ) :
   oo0O000OooO0 = oo0O000OooO0 . split ( b"@" )
   if 65 - 65: Oo0Ooo
   if ( len ( oo0O000OooO0 ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( oo0O000OooO0 [ 0 ] ) )
    if 81 - 81: OOooOOo % OoooooooOO / IiII . Oo0Ooo - ooOoO0o . I1IiiI
    OOOo00oo0 = True
    break
    if 3 - 3: O0
    if 95 - 95: i11iIiiIii
   Oo0o00oo00OO0 = oo0O000OooO0 [ 0 ] . decode ( )
   try :
    I1I1II1 = int ( oo0O000OooO0 [ 1 ] )
   except :
    IiIi1II1i = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( IiIi1II1i , iio0OOoO0 ) )
    OOOo00oo0 = True
    break
    if 52 - 52: I1Ii111
   I1 = oo0O000OooO0 [ 2 ] . decode ( )
   I1I = oo0O000OooO0 [ 3 ] . decode ( )
   if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
   if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
   if 73 - 73: iII111i - o0oOOo0O0Ooo / OOooOOo + iII111i + o0oOOo0O0Ooo % II111iiii
   if 74 - 74: I11i * iIii1I11I1II1 - OoO0O00 / i1IIi / OoO0O00 / IiII
   if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
   if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
   if 77 - 77: OoOoOO00 + IiII + Oo0Ooo
   if 88 - 88: i1IIi
   if ( len ( oo0O000OooO0 ) > 5 ) :
    Oo00oo = lisp_bit_stuff ( oo0O000OooO0 [ 4 : : ] )
   else :
    Oo00oo = oo0O000OooO0 [ 4 ]
    if 45 - 45: iII111i % I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
    if 55 - 55: OoO0O00 % IiII
    if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
    if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
    if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
    if 63 - 63: I1Ii111 + iII111i
   oOo0o0O , Oo00oo = lisp_receive_segments ( lisp_socket , Oo00oo ,
 I1 , I1I1II1 )
   if ( Oo00oo == None ) : return ( [ "" , "" , "" , "" ] )
   if 6 - 6: I1ii11iIi11i + Ii1I
   if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
   if 97 - 97: ooOoO0o + OOooOOo
   if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
   if 6 - 6: Oo0Ooo + I1IiiI
   if ( oOo0o0O == False ) :
    oo0O000OooO0 = Oo00oo
    continue
    if 48 - 48: oO0o . I1ii11iIi11i
    if 59 - 59: IiII - Ii1I
   if ( I1I == "" ) : I1I = "no-port"
   if ( Oo0o00oo00OO0 == "command" and lisp_i_am_core == False ) :
    OOOooo0OooOoO = Oo00oo . find ( b" {" )
    O0OO000OOooO = Oo00oo if OOOooo0OooOoO == - 1 else Oo00oo [ : OOOooo0OooOoO ]
    O0OO000OOooO = ": '" + O0OO000OOooO . decode ( ) + "'"
   else :
    O0OO000OOooO = ""
    if 80 - 80: O0 - i1IIi + OoO0O00 . i11iIiiIii
    if 62 - 62: i1IIi % i1IIi
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( Oo00oo ) , bold ( "from " + I1 , False ) , I1I , Oo0o00oo00OO0 ,
 O0OO000OOooO if ( Oo0o00oo00OO0 in [ "command" , "api" ] ) else ": ... " if ( Oo0o00oo00OO0 == "data-packet" ) else ": " + lisp_format_packet ( Oo00oo ) ) )
   if 58 - 58: OoooooooOO - i11iIiiIii
   if 67 - 67: OoO0O00 - OoooooooOO
   if 66 - 66: oO0o - II111iiii - o0oOOo0O0Ooo * OoO0O00 % OoO0O00 + I11i
   if 28 - 28: i11iIiiIii . o0oOOo0O0Ooo / II111iiii . OoO0O00 % II111iiii / I11i
   if 42 - 42: OoOoOO00 . I1ii11iIi11i
  if ( OOOo00oo0 ) : continue
  return ( [ Oo0o00oo00OO0 , I1 , I1I , Oo00oo ] )
  if 77 - 77: I1ii11iIi11i % i1IIi + OOooOOo - OOooOOo - o0oOOo0O0Ooo
  if 45 - 45: I1ii11iIi11i / o0oOOo0O0Ooo / I1IiiI - Oo0Ooo * ooOoO0o - I1ii11iIi11i
  if 71 - 71: I1IiiI % OoO0O00
  if 32 - 32: oO0o
  if 2 - 2: Oo0Ooo
  if 80 - 80: I1Ii111 * II111iiii % Oo0Ooo * ooOoO0o + o0oOOo0O0Ooo
  if 96 - 96: ooOoO0o
  if 19 - 19: Ii1I
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 I1IiIi1ii = False
 I11iI = time . time ( )
 if 50 - 50: o0oOOo0O0Ooo * I1IiiI
 ooo = lisp_control_header ( )
 if ( ooo . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( I1IiIi1ii )
  if 51 - 51: II111iiii
  if 33 - 33: I1Ii111 % Ii1I / OOooOOo - OOooOOo
  if 80 - 80: o0oOOo0O0Ooo % i11iIiiIii - IiII
  if 34 - 34: Oo0Ooo . OOooOOo % II111iiii / i1IIi - i1IIi + OoOoOO00
  if 37 - 37: ooOoO0o
 Iiii1IIIiIi = source
 if ( source . find ( "lisp" ) == - 1 ) :
  I111 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  I111 . string_to_afi ( source )
  I111 . store_address ( source )
  source = I111
  if 33 - 33: ooOoO0o . I1Ii111 + I1IiiI . Oo0Ooo
  if 11 - 11: o0oOOo0O0Ooo * i11iIiiIii
 if ( ooo . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl , I11iI )
  if 9 - 9: OoooooooOO / OoooooooOO
 elif ( ooo . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl , I11iI )
  if 57 - 57: OoO0O00 + i1IIi % OOooOOo * i11iIiiIii % i1IIi / o0oOOo0O0Ooo
 elif ( ooo . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 1 - 1: ooOoO0o
 elif ( ooo . type == LISP_MAP_NOTIFY ) :
  if ( Iiii1IIIiIi == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-rtr" ) ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-itr" ) ) :
   lisp_process_unicast_map_notify ( lisp_sockets , packet , source )
   if 81 - 81: iII111i . Oo0Ooo . O0 . II111iiii
   if 46 - 46: I1Ii111 % Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . oO0o
 elif ( ooo . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 43 - 43: i1IIi % o0oOOo0O0Ooo * I1IiiI / oO0o * IiII + I11i
 elif ( ooo . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 13 - 13: O0
 elif ( ooo . type == LISP_NAT_INFO and ooo . is_info_reply ( ) ) :
  iIiiiI1 , II11iiiII1Ii , I1IiIi1ii = lisp_process_info_reply ( source , packet , True )
  if 60 - 60: IiII
 elif ( ooo . type == LISP_NAT_INFO and ooo . is_info_reply ( ) == False ) :
  O0O0 = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , O0O0 , udp_sport ,
 None )
  if 14 - 14: II111iiii - i1IIi % OoOoOO00
 elif ( ooo . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 29 - 29: OoooooooOO * O0 / iIii1I11I1II1
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( ooo . type ) )
  if 29 - 29: OoO0O00 / IiII + i1IIi / OoO0O00 . Oo0Ooo
 return ( I1IiIi1ii )
 if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
 if 14 - 14: i1IIi
 if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
 if 36 - 36: OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
 if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
 if 23 - 23: oO0o / o0oOOo0O0Ooo + I11i % IiII * OoO0O00
 if 48 - 48: OoO0O00
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp ) :
 if 30 - 30: iIii1I11I1II1
 iIIiiIi = bold ( "RLOC-probe" , False )
 if 53 - 53: II111iiii
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( iIIiiIi ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 40 - 40: Ii1I % oO0o
  if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( iIIiiIi ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 78 - 78: oO0o
  if 20 - 20: i1IIi + i1IIi * i1IIi
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( iIIiiIi ) )
 return
 if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
 if 27 - 27: oO0o + Ii1I . i11iIiiIii
 if 97 - 97: iII111i . I1IiiI
 if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
 if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 45 - 45: oO0o
 if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
 if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
 if 100 - 100: i11iIiiIii - iII111i - I11i
 if 5 - 5: oO0o % IiII * iII111i
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 98 - 98: iII111i / OOooOOo + IiII
 if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
 if 82 - 82: ooOoO0o % OOooOOo % Ii1I
 if 82 - 82: I1ii11iIi11i
 if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
 if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
 if 53 - 53: OOooOOo * OoOoOO00 % iII111i
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , map_request ,
 keys , enc , auth , mr_ttl = - 1 ) :
 if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
 OooOooOO0000 = map_request . rloc_probe if ( map_request != None ) else False
 i11Ii111I11 = map_request . json_telemetry if ( map_request != None ) else None
 if 79 - 79: i11iIiiIii + OoO0O00 + IiII % I11i
 if 42 - 42: iIii1I11I1II1 + iIii1I11I1II1 . I11i
 iIII1111IiIII = lisp_map_reply ( )
 iIII1111IiIII . rloc_probe = OooOooOO0000
 iIII1111IiIII . echo_nonce_capable = enc
 iIII1111IiIII . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 iIII1111IiIII . record_count = 1
 iIII1111IiIII . nonce = nonce
 Oo00oo = iIII1111IiIII . encode ( )
 iIII1111IiIII . print_map_reply ( )
 if 60 - 60: iIii1I11I1II1 / O0 . OOooOOo / OoO0O00 * I1ii11iIi11i
 IiIo0oo0O = lisp_eid_record ( )
 IiIo0oo0O . rloc_count = len ( rloc_set )
 if ( i11Ii111I11 != None ) : IiIo0oo0O . rloc_count += 1
 IiIo0oo0O . authoritative = auth
 IiIo0oo0O . record_ttl = ttl
 IiIo0oo0O . action = action
 IiIo0oo0O . eid = eid
 IiIo0oo0O . group = group
 if 22 - 22: iIii1I11I1II1 + Ii1I
 Oo00oo += IiIo0oo0O . encode ( )
 IiIo0oo0O . print_record ( "  " , False )
 if 73 - 73: I1IiiI / OoO0O00 / OoooooooOO
 I1iIiII1IiI = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 46 - 46: iIii1I11I1II1 . O0 - o0oOOo0O0Ooo - I1IiiI
 Oo00O0Oo = None
 for OO0oooo in rloc_set :
  iII1iii1iII1iI1II = OO0oooo . rloc . is_multicast_address ( )
  IiiI1 = lisp_rloc_record ( )
  OOoO0o0Oo0o = OooOooOO0000 and ( iII1iii1iII1iI1II or i11Ii111I11 == None )
  O0O0 = OO0oooo . rloc . print_address_no_iid ( )
  if ( O0O0 in I1iIiII1IiI or iII1iii1iII1iI1II ) :
   IiiI1 . local_bit = True
   IiiI1 . probe_bit = OOoO0o0Oo0o
   IiiI1 . keys = keys
   if ( OO0oooo . priority == 254 and lisp_i_am_rtr ) :
    IiiI1 . rloc_name = "RTR"
    if 72 - 72: iIii1I11I1II1
   if ( Oo00O0Oo == None ) : Oo00O0Oo = OO0oooo . rloc
   if 49 - 49: oO0o + iII111i + I1Ii111 . IiII . Ii1I
  IiiI1 . store_rloc_entry ( OO0oooo )
  IiiI1 . reach_bit = True
  IiiI1 . print_record ( "    " )
  Oo00oo += IiiI1 . encode ( )
  if 51 - 51: oO0o - oO0o * OoooooooOO / oO0o * OoO0O00 / ooOoO0o
  if 22 - 22: oO0o - iIii1I11I1II1
  if 33 - 33: II111iiii * O0 + O0
  if 98 - 98: IiII * OoooooooOO . iII111i
  if 34 - 34: OoooooooOO + I1Ii111
 if ( i11Ii111I11 != None ) :
  IiiI1 = lisp_rloc_record ( )
  if ( Oo00O0Oo ) : IiiI1 . rloc . copy_address ( Oo00O0Oo )
  IiiI1 . local_bit = True
  IiiI1 . probe_bit = True
  IiiI1 . reach_bit = True
  if ( lisp_i_am_rtr ) :
   IiiI1 . priority = 254
   IiiI1 . rloc_name = "RTR"
   if 97 - 97: II111iiii + I11i + OOooOOo / i11iIiiIii - iII111i
  iiI11111i = lisp_encode_telemetry ( i11Ii111I11 , eo = str ( time . time ( ) ) )
  IiiI1 . json = lisp_json ( "telemetry" , iiI11111i )
  IiiI1 . print_record ( "    " )
  Oo00oo += IiiI1 . encode ( )
  if 69 - 69: O0 . I1Ii111 % ooOoO0o - I1ii11iIi11i . Ii1I
 return ( Oo00oo )
 if 11 - 11: II111iiii . Ii1I
 if 9 - 9: OoooooooOO * oO0o
 if 49 - 49: i11iIiiIii + OoO0O00 - OOooOOo
 if 9 - 9: II111iiii * OOooOOo / Oo0Ooo + iIii1I11I1II1 % I1IiiI
 if 95 - 95: I1Ii111 . IiII % OoO0O00 - OOooOOo - I11i
 if 55 - 55: OoooooooOO % I1ii11iIi11i % iII111i / IiII
 if 65 - 65: II111iiii
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 Ooooo = lisp_map_referral ( )
 Ooooo . record_count = 1
 Ooooo . nonce = nonce
 Oo00oo = Ooooo . encode ( )
 Ooooo . print_map_referral ( )
 if 82 - 82: Oo0Ooo % OoooooooOO - IiII . OoooooooOO + iII111i * iII111i
 IiIo0oo0O = lisp_eid_record ( )
 if 4 - 4: OoooooooOO * o0oOOo0O0Ooo - I1IiiI
 I1IIiiII = 0
 if ( ddt_entry == None ) :
  IiIo0oo0O . eid = eid
  IiIo0oo0O . group = group
 else :
  I1IIiiII = len ( ddt_entry . delegation_set )
  IiIo0oo0O . eid = ddt_entry . eid
  IiIo0oo0O . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 94 - 94: Oo0Ooo / I1IiiI * iIii1I11I1II1 - OoO0O00
 IiIo0oo0O . rloc_count = I1IIiiII
 IiIo0oo0O . authoritative = True
 if 96 - 96: ooOoO0o - OoooooooOO * iIii1I11I1II1 . IiII - O0
 if 7 - 7: iIii1I11I1II1 . OoO0O00
 if 88 - 88: i1IIi * II111iiii / i11iIiiIii % IiII . IiII
 if 93 - 93: OoOoOO00 * i1IIi . Ii1I
 if 2 - 2: i1IIi
 Oo00Oo0o000 = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( I1IIiiII == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   Ii1iII = ddt_entry . delegation_set [ 0 ]
   if ( Ii1iII . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 84 - 84: i1IIi / Ii1I + OoOoOO00 % Ii1I . oO0o
   if ( Ii1iII . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 74 - 74: OOooOOo - o0oOOo0O0Ooo - I1Ii111 - OoO0O00
    if 40 - 40: o0oOOo0O0Ooo . IiII * OoOoOO00
    if 14 - 14: OOooOOo
    if 18 - 18: i11iIiiIii % iII111i
    if 70 - 70: O0 + iII111i % I11i % I1Ii111 + OoOoOO00 / ooOoO0o
    if 35 - 35: IiII + OoO0O00
    if 82 - 82: i1IIi - ooOoO0o / I11i + I11i % I1IiiI - OoooooooOO
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : Oo00Oo0o000 = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  Oo00Oo0o000 = ( lisp_i_am_ms and Ii1iII . is_ms_peer ( ) == False )
  if 56 - 56: I1ii11iIi11i
  if 80 - 80: Oo0Ooo / OOooOOo / iII111i . o0oOOo0O0Ooo
 IiIo0oo0O . action = action
 IiIo0oo0O . ddt_incomplete = Oo00Oo0o000
 IiIo0oo0O . record_ttl = ttl
 if 43 - 43: IiII
 Oo00oo += IiIo0oo0O . encode ( )
 IiIo0oo0O . print_record ( "  " , True )
 if 74 - 74: OoooooooOO
 if ( I1IIiiII == 0 ) : return ( Oo00oo )
 if 88 - 88: Ii1I * o0oOOo0O0Ooo / oO0o
 for Ii1iII in ddt_entry . delegation_set :
  IiiI1 = lisp_rloc_record ( )
  IiiI1 . rloc = Ii1iII . delegate_address
  IiiI1 . priority = Ii1iII . priority
  IiiI1 . weight = Ii1iII . weight
  IiiI1 . mpriority = 255
  IiiI1 . mweight = 0
  IiiI1 . reach_bit = True
  Oo00oo += IiiI1 . encode ( )
  IiiI1 . print_record ( "    " )
  if 58 - 58: O0
 return ( Oo00oo )
 if 43 - 43: O0 / i1IIi / I11i % I1IiiI
 if 82 - 82: i11iIiiIii * i11iIiiIii + I1Ii111 - I1ii11iIi11i * oO0o - Ii1I
 if 40 - 40: o0oOOo0O0Ooo + OoO0O00 % i1IIi % iII111i * I1Ii111
 if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
 if 34 - 34: OoooooooOO * i11iIiiIii
 if 33 - 33: II111iiii
 if 59 - 59: iIii1I11I1II1 % I11i
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 93 - 93: I1ii11iIi11i
 if ( map_request . target_group . is_null ( ) ) :
  i11IIII1Ii = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  i11IIII1Ii = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( i11IIII1Ii ) : i11IIII1Ii = i11IIII1Ii . lookup_source_cache ( map_request . target_eid , False )
  if 7 - 7: I1Ii111 * iIii1I11I1II1
 i1iiii = map_request . print_prefix ( )
 if 27 - 27: iII111i % OoOoOO00 % ooOoO0o
 if ( i11IIII1Ii == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( i1iiii , False ) ) )
  if 4 - 4: iII111i * oO0o / iIii1I11I1II1 - O0 . Ii1I
  return
  if 53 - 53: Ii1I % IiII + I11i % IiII
  if 33 - 33: iII111i
 i1I1I1ii1i = i11IIII1Ii . print_eid_tuple ( )
 if 100 - 100: i11iIiiIii
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( i1I1I1ii1i , False ) , green ( i1iiii , False ) ) )
 if 54 - 54: O0 * Ii1I + Ii1I
 if 59 - 59: i11iIiiIii % iII111i
 if 54 - 54: I11i . ooOoO0o / OOooOOo % I1Ii111
 if 13 - 13: I11i / O0 . o0oOOo0O0Ooo . ooOoO0o
 if 7 - 7: OoO0O00 + OoooooooOO % II111iiii % oO0o
 IIoOo0oooO0 = map_request . itr_rlocs [ 0 ]
 if ( IIoOo0oooO0 . is_private_address ( ) and lisp_nat_traversal ) :
  IIoOo0oooO0 = source
  if 81 - 81: O0 + oO0o
  if 12 - 12: I1IiiI
 oOooo0oOOOO = map_request . nonce
 Ii1111ii = lisp_nonce_echoing
 iI1iiiiiii = map_request . keys
 if 97 - 97: OOooOOo * O0 . Oo0Ooo
 if 79 - 79: I1ii11iIi11i % I1Ii111 % I11i - iII111i * OoOoOO00
 if 48 - 48: O0 + OoOoOO00 - O0
 if 79 - 79: ooOoO0o . OoOoOO00 / OoooooooOO - II111iiii
 if 48 - 48: Oo0Ooo
 oOO0O00ooO = map_request . json_telemetry
 if ( oOO0O00ooO != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( oOO0O00ooO , ei = etr_in_ts )
  if 69 - 69: OOooOOo * I11i % i11iIiiIii
  if 63 - 63: OoOoOO00 + I1IiiI / I1ii11iIi11i / o0oOOo0O0Ooo % I1IiiI
 i11IIII1Ii . map_replies_sent += 1
 if 67 - 67: I1Ii111 . oO0o % I1ii11iIi11i % OOooOOo + I1IiiI
 Oo00oo = lisp_build_map_reply ( i11IIII1Ii . eid , i11IIII1Ii . group , i11IIII1Ii . rloc_set , oOooo0oOOOO ,
 LISP_NO_ACTION , 1440 , map_request , iI1iiiiiii , Ii1111ii , True , ttl )
 if 4 - 4: iII111i - i11iIiiIii * ooOoO0o
 if 74 - 74: Oo0Ooo . OOooOOo + OOooOOo / OOooOOo + I1IiiI + i1IIi
 if 32 - 32: i11iIiiIii % Ii1I
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
 if 94 - 94: OoO0O00 . ooOoO0o
 if 25 - 25: I1Ii111 % OOooOOo
 if 82 - 82: Ii1I
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  ii = ( IIoOo0oooO0 . is_private_address ( ) == False )
  i11 = IIoOo0oooO0 . print_address_no_iid ( )
  if ( ii and i11 in lisp_rtr_list or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , IIoOo0oooO0 , None , Oo00oo )
   return
   if 17 - 17: iII111i . i1IIi . i1IIi
   if 76 - 76: OoooooooOO % IiII
   if 81 - 81: iII111i . OOooOOo * i1IIi
   if 14 - 14: oO0o
   if 16 - 16: iII111i
   if 26 - 26: iII111i . oO0o * i11iIiiIii . iIii1I11I1II1
 lisp_send_map_reply ( lisp_sockets , Oo00oo , IIoOo0oooO0 , sport )
 return
 if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
 if 65 - 65: OOooOOo * I11i * Oo0Ooo
 if 21 - 21: Ii1I . iIii1I11I1II1
 if 84 - 84: OOooOOo
 if 67 - 67: I1IiiI % OoO0O00 % o0oOOo0O0Ooo % IiII
 if 33 - 33: ooOoO0o % I1IiiI
 if 98 - 98: oO0o . o0oOOo0O0Ooo + II111iiii
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 62 - 62: ooOoO0o - OoooooooOO / I1ii11iIi11i / iII111i - o0oOOo0O0Ooo
 if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
 if 9 - 9: iII111i * Oo0Ooo % iII111i % Oo0Ooo * II111iiii
 if 71 - 71: II111iiii + I1ii11iIi11i * II111iiii
 IIoOo0oooO0 = map_request . itr_rlocs [ 0 ]
 if ( IIoOo0oooO0 . is_private_address ( ) ) : IIoOo0oooO0 = source
 oOooo0oOOOO = map_request . nonce
 if 59 - 59: OoO0O00
 i1I1I1IIIi11 = map_request . target_eid
 o0o0Oo0o0oOo = map_request . target_group
 if 81 - 81: i11iIiiIii
 OOOo0O00OO00O = [ ]
 for OOOoo0ooO in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( OOOoo0ooO == None ) : continue
  I1Ii1i111I = lisp_rloc ( )
  I1Ii1i111I . rloc . copy_address ( OOOoo0ooO )
  I1Ii1i111I . priority = 254
  OOOo0O00OO00O . append ( I1Ii1i111I )
  if 81 - 81: OoO0O00 / OoO0O00 . I1ii11iIi11i
  if 100 - 100: iIii1I11I1II1 % II111iiii - I1ii11iIi11i . iIii1I11I1II1 + IiII % iIii1I11I1II1
 Ii1111ii = lisp_nonce_echoing
 iI1iiiiiii = map_request . keys
 if 48 - 48: Ii1I % i1IIi
 if 38 - 38: OOooOOo / I1ii11iIi11i % oO0o / o0oOOo0O0Ooo
 if 54 - 54: OoOoOO00 * OoooooooOO - OoO0O00 * OoOoOO00 % I1ii11iIi11i * I11i
 if 34 - 34: I11i - oO0o + I11i * OoooooooOO * I11i
 if 73 - 73: OOooOOo * iII111i * OoO0O00
 oOO0O00ooO = map_request . json_telemetry
 if ( oOO0O00ooO != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( oOO0O00ooO , ei = etr_in_ts )
  if 11 - 11: I1Ii111 * II111iiii
  if 3 - 3: Oo0Ooo * OOooOOo
 Oo00oo = lisp_build_map_reply ( i1I1I1IIIi11 , o0o0Oo0o0oOo , OOOo0O00OO00O , oOooo0oOOOO , LISP_NO_ACTION ,
 1440 , map_request , iI1iiiiiii , Ii1111ii , True , ttl )
 lisp_send_map_reply ( lisp_sockets , Oo00oo , IIoOo0oooO0 , sport )
 return
 if 13 - 13: I1Ii111 + i11iIiiIii / OOooOOo
 if 98 - 98: I1IiiI * Oo0Ooo
 if 9 - 9: O0 / i11iIiiIii . iIii1I11I1II1 . IiII
 if 14 - 14: OoOoOO00 . OOooOOo - Oo0Ooo + I1Ii111 % ooOoO0o
 if 95 - 95: OoO0O00 * II111iiii + i1IIi
 if 22 - 22: Ii1I / ooOoO0o % I11i + OoO0O00 . ooOoO0o
 if 61 - 61: O0 - iIii1I11I1II1 * Oo0Ooo . Ii1I + O0
 if 20 - 20: ooOoO0o / ooOoO0o - Ii1I - ooOoO0o
 if 93 - 93: O0 * OoOoOO00 * iIii1I11I1II1
 if 3 - 3: I1ii11iIi11i - O0
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 OOOo0O00OO00O = target_site_eid . registered_rlocs
 if 46 - 46: iII111i
 o0O00ooOo = lisp_site_eid_lookup ( seid , group , False )
 if ( o0O00ooOo == None ) : return ( OOOo0O00OO00O )
 if 95 - 95: o0oOOo0O0Ooo % ooOoO0o . OOooOOo . ooOoO0o % iII111i - OOooOOo
 if 53 - 53: i11iIiiIii % OoooooooOO . i11iIiiIii
 if 66 - 66: I1Ii111 * I1ii11iIi11i . Ii1I
 if 28 - 28: oO0o - I1IiiI
 iiiIO0oO0ooo0O = None
 iIo0 = [ ]
 for OO0oooo in OOOo0O00OO00O :
  if ( OO0oooo . is_rtr ( ) ) : continue
  if ( OO0oooo . rloc . is_private_address ( ) ) :
   ooOO = copy . deepcopy ( OO0oooo )
   iIo0 . append ( ooOO )
   continue
   if 43 - 43: Ii1I - OOooOOo / ooOoO0o + I1ii11iIi11i
  iiiIO0oO0ooo0O = OO0oooo
  break
  if 58 - 58: I1IiiI
 if ( iiiIO0oO0ooo0O == None ) : return ( OOOo0O00OO00O )
 iiiIO0oO0ooo0O = iiiIO0oO0ooo0O . rloc . print_address_no_iid ( )
 if 30 - 30: I1Ii111 + oO0o + iIii1I11I1II1 % OoO0O00 / I1IiiI
 if 55 - 55: Ii1I
 if 14 - 14: i1IIi * I1ii11iIi11i
 if 77 - 77: ooOoO0o . II111iiii
 iiii111i1111 = None
 for OO0oooo in o0O00ooOo . registered_rlocs :
  if ( OO0oooo . is_rtr ( ) ) : continue
  if ( OO0oooo . rloc . is_private_address ( ) ) : continue
  iiii111i1111 = OO0oooo
  break
  if 45 - 45: IiII + IiII - o0oOOo0O0Ooo + I1Ii111 * I1Ii111 * o0oOOo0O0Ooo
 if ( iiii111i1111 == None ) : return ( OOOo0O00OO00O )
 iiii111i1111 = iiii111i1111 . rloc . print_address_no_iid ( )
 if 45 - 45: O0 * iII111i + oO0o + ooOoO0o
 if 29 - 29: OoO0O00
 if 24 - 24: IiII - OoOoOO00 / OoooooooOO . I1ii11iIi11i
 if 88 - 88: I11i
 o0oo00 = target_site_eid . site_id
 if ( o0oo00 == 0 ) :
  if ( iiii111i1111 == iiiIO0oO0ooo0O ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( iiiIO0oO0ooo0O ) )
   if 36 - 36: iIii1I11I1II1 - ooOoO0o * OoO0O00 * OoO0O00 . II111iiii
   return ( iIo0 )
   if 49 - 49: O0 + OoO0O00 - I1ii11iIi11i + ooOoO0o
  return ( OOOo0O00OO00O )
  if 90 - 90: O0 . Ii1I * OOooOOo * OoooooooOO * ooOoO0o * Ii1I
  if 12 - 12: ooOoO0o * OoooooooOO * i1IIi
  if 3 - 3: o0oOOo0O0Ooo + Ii1I - i1IIi . OoooooooOO % Ii1I
  if 39 - 39: o0oOOo0O0Ooo
  if 73 - 73: IiII
  if 92 - 92: OOooOOo / ooOoO0o . I1Ii111 . iII111i / ooOoO0o
  if 83 - 83: iIii1I11I1II1 - OoO0O00 - I1Ii111
 if ( o0oo00 == o0O00ooOo . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( o0oo00 ) )
  return ( iIo0 )
  if 27 - 27: IiII - iII111i * i11iIiiIii % i11iIiiIii + OoOoOO00 . I1Ii111
 return ( OOOo0O00OO00O )
 if 10 - 10: IiII / i11iIiiIii
 if 6 - 6: I11i - OOooOOo
 if 100 - 100: Oo0Ooo / OOooOOo + iII111i - o0oOOo0O0Ooo + OoO0O00 % IiII
 if 91 - 91: Ii1I % I11i % Oo0Ooo / OoO0O00 - II111iiii - o0oOOo0O0Ooo
 if 50 - 50: OoooooooOO
 if 51 - 51: II111iiii - oO0o % OoooooooOO - II111iiii / O0 - OoooooooOO
 if 21 - 21: iII111i * o0oOOo0O0Ooo
 if 85 - 85: I1ii11iIi11i . OoOoOO00 . i1IIi % OOooOOo * I11i . I1Ii111
 if 26 - 26: I1Ii111 + Oo0Ooo + II111iiii % OoOoOO00 % OOooOOo
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 iIiii11 = [ ]
 OOOo0O00OO00O = [ ]
 if 38 - 38: Ii1I + OoOoOO00 % I1Ii111 % iII111i
 if 72 - 72: OoOoOO00 * I1ii11iIi11i + iIii1I11I1II1
 if 51 - 51: oO0o + I1IiiI - I1Ii111 * Oo0Ooo . II111iiii
 if 63 - 63: I1ii11iIi11i - ooOoO0o - II111iiii + II111iiii
 if 17 - 17: I1ii11iIi11i % OoO0O00 % oO0o
 if 60 - 60: i1IIi % Ii1I - O0 / iII111i
 iiii1iii111i1 = False
 o0oiiIiiiiI = False
 for OO0oooo in registered_rloc_set :
  if ( OO0oooo . priority != 254 ) : continue
  o0oiiIiiiiI |= True
  if ( OO0oooo . rloc . is_exact_match ( mr_source ) == False ) : continue
  iiii1iii111i1 = True
  break
  if 35 - 35: OoOoOO00 + II111iiii
  if 46 - 46: O0 / I1ii11iIi11i + OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
  if 96 - 96: IiII + i1IIi - I11i * I11i - OoO0O00 % II111iiii
  if 47 - 47: I1Ii111 . i11iIiiIii + oO0o . I1ii11iIi11i
  if 12 - 12: iIii1I11I1II1 % I1Ii111 * OoOoOO00 / OoooooooOO % OoooooooOO
  if 81 - 81: iIii1I11I1II1 - Oo0Ooo - ooOoO0o . OoO0O00 + I1ii11iIi11i
  if 84 - 84: iII111i . OOooOOo . iII111i * oO0o % Ii1I . oO0o
 if ( o0oiiIiiiiI == False ) : return ( registered_rloc_set )
 if 86 - 86: iII111i * ooOoO0o / iIii1I11I1II1 + Ii1I . iII111i
 if 64 - 64: IiII - Oo0Ooo % iII111i % I11i
 if 42 - 42: Oo0Ooo . OoO0O00
 if 22 - 22: ooOoO0o - o0oOOo0O0Ooo + I11i / I1IiiI + OOooOOo
 if 10 - 10: oO0o / I1IiiI
 if 95 - 95: II111iiii - IiII % IiII . o0oOOo0O0Ooo
 if 19 - 19: II111iiii . ooOoO0o . I11i - OoooooooOO / I1ii11iIi11i . I1Ii111
 if 57 - 57: II111iiii . I1Ii111 . i11iIiiIii / OoOoOO00 - O0
 if 56 - 56: OOooOOo / I1Ii111
 if 13 - 13: oO0o + Oo0Ooo + Oo0Ooo / OoO0O00 + i1IIi + I1IiiI
 oo0Oo0o = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 22 - 22: iIii1I11I1II1 % OoOoOO00 / iIii1I11I1II1 . O0 . oO0o
 if 21 - 21: oO0o * I1ii11iIi11i
 if 44 - 44: o0oOOo0O0Ooo * IiII - o0oOOo0O0Ooo
 if 90 - 90: i1IIi + I1ii11iIi11i * oO0o % i11iIiiIii - OoO0O00
 if 12 - 12: OoO0O00 . I1ii11iIi11i - I1IiiI % OOooOOo
 for OO0oooo in registered_rloc_set :
  if ( oo0Oo0o and OO0oooo . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and OO0oooo . priority == 255 ) : continue
  if ( multicast and OO0oooo . mpriority == 255 ) : continue
  if ( OO0oooo . priority == 254 ) :
   iIiii11 . append ( OO0oooo )
  else :
   OOOo0O00OO00O . append ( OO0oooo )
   if 9 - 9: Ii1I / O0
   if 95 - 95: iII111i / I11i
   if 86 - 86: O0 / II111iiii . Oo0Ooo / Oo0Ooo * II111iiii
   if 22 - 22: Ii1I
   if 81 - 81: iIii1I11I1II1 . ooOoO0o % I11i
   if 64 - 64: I1Ii111 . Oo0Ooo * o0oOOo0O0Ooo
 if ( iiii1iii111i1 ) : return ( OOOo0O00OO00O )
 if 32 - 32: oO0o . I1Ii111 * I1Ii111
 if 32 - 32: I1Ii111 . Ii1I / i1IIi
 if 2 - 2: OOooOOo * ooOoO0o / I11i + OoO0O00
 if 96 - 96: II111iiii * OoO0O00 + I1ii11iIi11i + OoOoOO00 / II111iiii . iII111i
 if 64 - 64: iII111i % Oo0Ooo
 if 79 - 79: IiII + iII111i / II111iiii . i1IIi + iIii1I11I1II1
 if 32 - 32: Ii1I * iII111i
 if 52 - 52: I11i
 if 100 - 100: Oo0Ooo % Oo0Ooo % I1ii11iIi11i
 if 33 - 33: I1Ii111 . I1Ii111 * i1IIi
 if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
 if 13 - 13: II111iiii
 OOOo0O00OO00O = [ ]
 for OO0oooo in registered_rloc_set :
  if ( OO0oooo . rloc . is_ipv6 ( ) ) : OOOo0O00OO00O . append ( OO0oooo )
  if ( OO0oooo . rloc . is_private_address ( ) ) : OOOo0O00OO00O . append ( OO0oooo )
  if 36 - 36: iII111i - oO0o / Oo0Ooo / O0 . OoO0O00 . i1IIi
 OOOo0O00OO00O += iIiii11
 return ( OOOo0O00OO00O )
 if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
 if 98 - 98: oO0o . Oo0Ooo
 if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
 if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
 if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
 if 64 - 64: OoooooooOO + OOooOOo
 if 36 - 36: I1IiiI - Ii1I / I1ii11iIi11i + Oo0Ooo % I1ii11iIi11i
 if 86 - 86: iIii1I11I1II1 * OoO0O00
 if 82 - 82: I1IiiI - OoO0O00 % o0oOOo0O0Ooo
 if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 oO0II11II = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 oO0II11II . add ( reply_eid )
 return ( oO0II11II )
 if 55 - 55: OOooOOo % I1Ii111 * OoooooooOO - oO0o * ooOoO0o
 if 89 - 89: Ii1I % I1Ii111 - o0oOOo0O0Ooo + I11i + OoO0O00
 if 9 - 9: IiII / i1IIi * IiII - o0oOOo0O0Ooo - iIii1I11I1II1
 if 58 - 58: I1ii11iIi11i + iII111i
 if 65 - 65: ooOoO0o / Ii1I - oO0o - O0 % OOooOOo
 if 16 - 16: Oo0Ooo . Ii1I . i11iIiiIii / I1ii11iIi11i . i1IIi + I1Ii111
 if 25 - 25: OOooOOo - II111iiii % I1ii11iIi11i . OoOoOO00 . OoooooooOO
 if 13 - 13: OoooooooOO + OoooooooOO * i11iIiiIii + iII111i
 if 25 - 25: oO0o + I1ii11iIi11i + i11iIiiIii % i11iIiiIii
 if 11 - 11: I11i * Oo0Ooo * ooOoO0o + i1IIi
 if 76 - 76: o0oOOo0O0Ooo * i1IIi / I1Ii111 * Oo0Ooo + II111iiii . OoOoOO00
 if 44 - 44: OoOoOO00
 if 63 - 63: OoOoOO00 % iIii1I11I1II1 . I1Ii111 * O0 * OOooOOo - I11i
 if 52 - 52: I11i - I11i / OoooooooOO - iIii1I11I1II1 / i11iIiiIii - Oo0Ooo
 if 61 - 61: OOooOOo / iIii1I11I1II1 - Oo0Ooo % Oo0Ooo % Oo0Ooo
def lisp_convert_reply_to_notify ( packet ) :
 if 66 - 66: OoooooooOO
 if 23 - 23: OoOoOO00
 if 35 - 35: I1Ii111 - i1IIi
 if 90 - 90: I11i . OoO0O00 . iIii1I11I1II1
 O0O00oo = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 O0O00oo = socket . ntohl ( O0O00oo ) & 0xff
 oOooo0oOOOO = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 34 - 34: Ii1I * i1IIi + OoooooooOO . oO0o
 if 30 - 30: I1Ii111 % IiII / II111iiii
 if 68 - 68: oO0o / O0 / OOooOOo
 if 3 - 3: o0oOOo0O0Ooo / o0oOOo0O0Ooo
 Iii1 = ( LISP_MAP_NOTIFY << 28 ) | O0O00oo
 ooo = struct . pack ( "I" , socket . htonl ( Iii1 ) )
 Ooo00OOo000 = struct . pack ( "I" , 0 )
 if 17 - 17: OoO0O00 * i1IIi
 if 50 - 50: OoOoOO00 + I11i
 if 56 - 56: OOooOOo * OOooOOo + I1IiiI % I1IiiI - I11i
 if 1 - 1: OoooooooOO . ooOoO0o - i1IIi
 packet = ooo + oOooo0oOOOO + Ooo00OOo000 + packet
 return ( packet )
 if 73 - 73: iIii1I11I1II1 - I1Ii111 % Oo0Ooo . O0
 if 16 - 16: OoO0O00 / Oo0Ooo / IiII . Oo0Ooo - OoooooooOO
 if 5 - 5: OoOoOO00 . I11i
 if 28 - 28: I11i % OOooOOo + Oo0Ooo / OoO0O00 % o0oOOo0O0Ooo + OoO0O00
 if 20 - 20: ooOoO0o . iII111i % OOooOOo + i11iIiiIii
 if 64 - 64: i1IIi . o0oOOo0O0Ooo * I1Ii111 - O0
 if 76 - 76: I1IiiI % Ii1I + OoO0O00 + I1ii11iIi11i * II111iiii + Oo0Ooo
 if 3 - 3: Ii1I - I1IiiI + O0
def lisp_notify_subscribers ( lisp_sockets , eid_record , rloc_records ,
 registered_eid , site ) :
 if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
 for IiiII in lisp_pubsub_cache :
  for oO0II11II in list ( lisp_pubsub_cache [ IiiII ] . values ( ) ) :
   oO0ooOOO = oO0II11II . eid_prefix
   if ( oO0ooOOO . is_more_specific ( registered_eid ) == False ) : continue
   if 59 - 59: o0oOOo0O0Ooo - Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
   ii1oO0Oo = oO0II11II . itr
   I1I = oO0II11II . port
   iIIIi1Iii1 = red ( ii1oO0Oo . print_address_no_iid ( ) , False )
   O000 = bold ( "subscriber" , False )
   Iiooo000o0OoOo = "0x" + lisp_hex_string ( oO0II11II . xtr_id )
   oOooo0oOOOO = "0x" + lisp_hex_string ( oO0II11II . nonce )
   if 63 - 63: I1Ii111
   lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( O000 , iIIIi1Iii1 , I1I , Iiooo000o0OoOo , green ( IiiII , False ) , oOooo0oOOOO ) )
   if 4 - 4: o0oOOo0O0Ooo / OoooooooOO - o0oOOo0O0Ooo - II111iiii % II111iiii
   if 14 - 14: i1IIi - Oo0Ooo % OOooOOo
   if 14 - 14: I11i . OoO0O00
   if 46 - 46: ooOoO0o
   if 48 - 48: i1IIi * I1IiiI / i11iIiiIii
   if 40 - 40: IiII
   iii1i = copy . deepcopy ( eid_record )
   iii1i . eid . copy_address ( oO0ooOOO )
   iii1i = iii1i . encode ( ) + rloc_records
   lisp_build_map_notify ( lisp_sockets , iii1i , [ IiiII ] , 1 , ii1oO0Oo ,
 I1I , oO0II11II . nonce , 0 , 0 , 0 , site , False )
   if 40 - 40: ooOoO0o * OoooooooOO
   oO0II11II . map_notify_count += 1
   if 88 - 88: IiII / I1ii11iIi11i
   if 19 - 19: i11iIiiIii + II111iiii
 return
 if 37 - 37: I1Ii111 . I1IiiI - II111iiii / O0 . OoOoOO00
 if 27 - 27: I1ii11iIi11i / II111iiii + O0 % I1ii11iIi11i
 if 72 - 72: I1IiiI - i1IIi
 if 11 - 11: iIii1I11I1II1 . OoO0O00 * Ii1I
 if 65 - 65: Oo0Ooo / OoooooooOO
 if 60 - 60: II111iiii + I1IiiI % oO0o - o0oOOo0O0Ooo
 if 50 - 50: iIii1I11I1II1 - i11iIiiIii / iII111i + ooOoO0o / OOooOOo
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 80 - 80: IiII / OoooooooOO
 if 69 - 69: OoOoOO00 + IiII
 if 18 - 18: O0 / I11i
 if 10 - 10: I1Ii111 * i1IIi
 oO0II11II = lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl ,
 xtr_id )
 if 48 - 48: Oo0Ooo % i1IIi / iII111i . O0
 i1I1I1IIIi11 = green ( reply_eid . print_prefix ( ) , False )
 ii1oO0Oo = red ( itr_rloc . print_address_no_iid ( ) , False )
 i1Iii1I = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( i1Iii1I ,
 i1I1I1IIIi11 , ii1oO0Oo , xtr_id ) )
 if 42 - 42: oO0o * iIii1I11I1II1 * O0 * I1ii11iIi11i * I11i
 if 4 - 4: iII111i + O0 / I1ii11iIi11i
 if 11 - 11: iIii1I11I1II1 / O0 * I1Ii111 . OoooooooOO % OoooooooOO * I1Ii111
 if 63 - 63: IiII * oO0o * iIii1I11I1II1
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 oO0II11II . map_notify_count += 1
 return
 if 18 - 18: II111iiii * o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
 if 40 - 40: oO0o - o0oOOo0O0Ooo * II111iiii
 if 4 - 4: O0
 if 9 - 9: Oo0Ooo . i1IIi - i1IIi + I1Ii111 * ooOoO0o . I1ii11iIi11i
 if 17 - 17: I11i * I1ii11iIi11i % I1IiiI + OoO0O00 + IiII
 if 90 - 90: OoooooooOO - I1IiiI / I1ii11iIi11i + oO0o - o0oOOo0O0Ooo
 if 84 - 84: OoOoOO00 + O0 % Oo0Ooo
 if 22 - 22: iIii1I11I1II1 % i11iIiiIii
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 29 - 29: ooOoO0o - iII111i + IiII % Ii1I - oO0o - ooOoO0o
 if 43 - 43: oO0o
 if 22 - 22: I1Ii111 + i11iIiiIii
 if 49 - 49: O0 % II111iiii . OOooOOo + iII111i + iIii1I11I1II1 / i11iIiiIii
 if 79 - 79: II111iiii + ooOoO0o - i1IIi - i1IIi + II111iiii . i1IIi
 if 78 - 78: I1IiiI * I11i % OOooOOo + Ii1I + OoOoOO00
 i1I1I1IIIi11 = map_request . target_eid
 o0o0Oo0o0oOo = map_request . target_group
 i1iiii = lisp_print_eid_tuple ( i1I1I1IIIi11 , o0o0Oo0o0oOo )
 IIoOo0oooO0 = map_request . itr_rlocs [ 0 ]
 Iiooo000o0OoOo = map_request . xtr_id
 oOooo0oOOOO = map_request . nonce
 oo0oOooo0O = LISP_NO_ACTION
 oO0II11II = map_request . subscribe_bit
 if 23 - 23: iII111i / Oo0Ooo % OoooooooOO * OoooooooOO . iII111i / I1ii11iIi11i
 if 30 - 30: oO0o - OoOoOO00 . I1IiiI
 if 17 - 17: OoOoOO00
 if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
 if 57 - 57: O0
 IIiii = True
 ooO = ( lisp_get_eid_hash ( i1I1I1IIIi11 ) != None )
 if ( ooO ) :
  IIIII1iII1 = map_request . map_request_signature
  if ( IIIII1iII1 == None ) :
   IIiii = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 32 - 32: OOooOOo / I11i + I1Ii111 / Oo0Ooo * OoooooooOO / II111iiii
  else :
   IIi1i = map_request . signature_eid
   iiiIiIi , iIooO , IIiii = lisp_lookup_public_key ( IIi1i )
   if ( IIiii ) :
    IIiii = map_request . verify_map_request_sig ( iIooO )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( IIi1i . print_address ( ) , iiiIiIi . print_address ( ) ) )
    if 35 - 35: OOooOOo % i11iIiiIii % ooOoO0o . O0
    if 9 - 9: ooOoO0o + iII111i / i1IIi % Oo0Ooo - o0oOOo0O0Ooo / I1IiiI
   II1I1iI = bold ( "passed" , False ) if IIiii else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( II1I1iI ) )
   if 56 - 56: OoooooooOO
   if 91 - 91: i1IIi
   if 42 - 42: OoO0O00 % Ii1I * IiII + ooOoO0o + Oo0Ooo
 if ( oO0II11II and IIiii == False ) :
  oO0II11II = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 36 - 36: O0 - II111iiii
  if 97 - 97: I1IiiI
  if 87 - 87: I11i + iIii1I11I1II1
  if 91 - 91: oO0o
  if 58 - 58: i11iIiiIii / Ii1I - OoooooooOO
  if 25 - 25: i1IIi * ooOoO0o % OOooOOo / I1IiiI
  if 75 - 75: i11iIiiIii
  if 38 - 38: iIii1I11I1II1
  if 80 - 80: OoO0O00
  if 72 - 72: I11i * II111iiii
  if 82 - 82: I1Ii111 . OoO0O00 * II111iiii
  if 99 - 99: iIii1I11I1II1 / iII111i % i1IIi - II111iiii / OoO0O00
  if 33 - 33: OoooooooOO / i1IIi . Ii1I
  if 96 - 96: OoOoOO00 / Oo0Ooo . II111iiii / ooOoO0o
 O000oO0O0 = IIoOo0oooO0 if ( IIoOo0oooO0 . afi == ecm_source . afi ) else ecm_source
 if 63 - 63: I11i
 oOoooooOooO = lisp_site_eid_lookup ( i1I1I1IIIi11 , o0o0Oo0o0oOo , False )
 if 31 - 31: IiII
 if ( oOoooooOooO == None or oOoooooOooO . is_star_g ( ) ) :
  OOo00OO = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( OOo00OO ,
 green ( i1iiii , False ) ) )
  if 49 - 49: iIii1I11I1II1 % Oo0Ooo % I11i * Ii1I - OoO0O00
  if 15 - 15: i11iIiiIii + o0oOOo0O0Ooo . Ii1I . I1IiiI
  if 8 - 8: iII111i % II111iiii + IiII
  if 5 - 5: i1IIi + II111iiii
  lisp_send_negative_map_reply ( lisp_sockets , i1I1I1IIIi11 , o0o0Oo0o0oOo , oOooo0oOOOO , IIoOo0oooO0 ,
 mr_sport , 15 , Iiooo000o0OoOo , oO0II11II )
  if 75 - 75: OOooOOo . IiII . I1IiiI + OoooooooOO
  return ( [ i1I1I1IIIi11 , o0o0Oo0o0oOo , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 35 - 35: I11i % i1IIi - I1ii11iIi11i . Oo0Ooo
  if 69 - 69: ooOoO0o * OoO0O00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
 i1I1I1ii1i = oOoooooOooO . print_eid_tuple ( )
 Ii1oOOooo0 = oOoooooOooO . site . site_name
 if 24 - 24: I1IiiI - IiII
 if 32 - 32: I1Ii111 . I1ii11iIi11i / OoooooooOO + I1Ii111 . I1Ii111
 if 52 - 52: O0 - I1Ii111 . oO0o
 if 43 - 43: IiII * Ii1I - I1ii11iIi11i * I1ii11iIi11i
 if 53 - 53: oO0o % I11i * OoO0O00 . i1IIi
 if ( ooO == False and oOoooooOooO . require_signature ) :
  IIIII1iII1 = map_request . map_request_signature
  IIi1i = map_request . signature_eid
  if ( IIIII1iII1 == None or IIi1i . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( Ii1oOOooo0 ) )
   IIiii = False
  else :
   IIi1i = map_request . signature_eid
   iiiIiIi , iIooO , IIiii = lisp_lookup_public_key ( IIi1i )
   if ( IIiii ) :
    IIiii = map_request . verify_map_request_sig ( iIooO )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( IIi1i . print_address ( ) , iiiIiIi . print_address ( ) ) )
    if 35 - 35: I11i . IiII + ooOoO0o
    if 19 - 19: O0 - i1IIi / I1Ii111
   II1I1iI = bold ( "passed" , False ) if IIiii else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( II1I1iI ) )
   if 14 - 14: I11i - i11iIiiIii
   if 49 - 49: oO0o . I1ii11iIi11i
   if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
   if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
   if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
   if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
 if ( IIiii and oOoooooOooO . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( Ii1oOOooo0 , green ( i1I1I1ii1i , False ) , green ( i1iiii , False ) ) )
  if 53 - 53: OOooOOo / I11i + OOooOOo / I1IiiI / OoO0O00
  if 12 - 12: i11iIiiIii % ooOoO0o / iII111i . IiII
  if 68 - 68: OOooOOo / iIii1I11I1II1 + I1IiiI . ooOoO0o * IiII
  if 72 - 72: I1Ii111
  if 51 - 51: OoOoOO00
  if 61 - 61: Oo0Ooo / i1IIi + I1Ii111 - OoooooooOO / O0
  if ( oOoooooOooO . accept_more_specifics == False ) :
   i1I1I1IIIi11 = oOoooooOooO . eid
   o0o0Oo0o0oOo = oOoooooOooO . group
   if 25 - 25: I1ii11iIi11i * i11iIiiIii / i1IIi
   if 69 - 69: OOooOOo % ooOoO0o - i1IIi . Oo0Ooo
   if 35 - 35: iIii1I11I1II1 - I11i / iIii1I11I1II1 % ooOoO0o % I1IiiI
   if 46 - 46: oO0o
   if 5 - 5: i1IIi % o0oOOo0O0Ooo + OoOoOO00 - I11i . Ii1I
  IiIi1iIIiII1i = 1
  if ( oOoooooOooO . force_ttl != None ) :
   IiIi1iIIiII1i = oOoooooOooO . force_ttl | 0x80000000
   if 33 - 33: II111iiii * o0oOOo0O0Ooo
   if 8 - 8: I1ii11iIi11i % o0oOOo0O0Ooo - IiII
   if 91 - 91: iIii1I11I1II1 . OoO0O00 - I1ii11iIi11i + I11i / Oo0Ooo + OoO0O00
   if 35 - 35: ooOoO0o * iII111i % iII111i + OOooOOo
   if 66 - 66: iII111i - ooOoO0o * I1ii11iIi11i - Ii1I / OoooooooOO
  lisp_send_negative_map_reply ( lisp_sockets , i1I1I1IIIi11 , o0o0Oo0o0oOo , oOooo0oOOOO , IIoOo0oooO0 ,
 mr_sport , IiIi1iIIiII1i , Iiooo000o0OoOo , oO0II11II )
  if 86 - 86: I1IiiI % iII111i + Oo0Ooo + i1IIi % o0oOOo0O0Ooo
  return ( [ i1I1I1IIIi11 , o0o0Oo0o0oOo , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 85 - 85: Ii1I + I1Ii111 * I11i
  if 59 - 59: Oo0Ooo
  if 35 - 35: OoooooooOO + I1ii11iIi11i * OOooOOo
  if 75 - 75: Ii1I * Oo0Ooo % iIii1I11I1II1 . O0 % oO0o
  if 4 - 4: I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
 Ooo0000 = False
 Oo0OO0OoooOo0 = ""
 OOoOO0 = False
 if ( oOoooooOooO . force_nat_proxy_reply ) :
  Oo0OO0OoooOo0 = ", nat-forced"
  Ooo0000 = True
  OOoOO0 = True
 elif ( oOoooooOooO . force_proxy_reply ) :
  Oo0OO0OoooOo0 = ", forced"
  OOoOO0 = True
 elif ( oOoooooOooO . proxy_reply_requested ) :
  Oo0OO0OoooOo0 = ", requested"
  OOoOO0 = True
 elif ( map_request . pitr_bit and oOoooooOooO . pitr_proxy_reply_drop ) :
  Oo0OO0OoooOo0 = ", drop-to-pitr"
  oo0oOooo0O = LISP_DROP_ACTION
 elif ( oOoooooOooO . proxy_reply_action != "" ) :
  oo0oOooo0O = oOoooooOooO . proxy_reply_action
  Oo0OO0OoooOo0 = ", forced, action {}" . format ( oo0oOooo0O )
  oo0oOooo0O = LISP_DROP_ACTION if ( oo0oOooo0O == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 35 - 35: iII111i / iII111i * OoOoOO00 - i11iIiiIii
  if 27 - 27: i1IIi / I11i + I1Ii111 . II111iiii * OoO0O00
  if 55 - 55: i1IIi % Ii1I - o0oOOo0O0Ooo - o0oOOo0O0Ooo
  if 6 - 6: i1IIi
  if 10 - 10: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / i11iIiiIii - I1IiiI . O0
  if 2 - 2: II111iiii
  if 13 - 13: Ii1I % i11iIiiIii
 I11II1iI1i = False
 iII1 = None
 if ( OOoOO0 and oOoooooOooO . policy in lisp_policies ) :
  iIIiiIi = lisp_policies [ oOoooooOooO . policy ]
  if ( iIIiiIi . match_policy_map_request ( map_request , mr_source ) ) : iII1 = iIIiiIi
  if 64 - 64: oO0o
  if ( iII1 ) :
   i1I1Iiii = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( i1I1Iiii ,
 iIIiiIi . policy_name , iIIiiIi . set_action ) )
  else :
   i1I1Iiii = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( i1I1Iiii ,
 iIIiiIi . policy_name ) )
   I11II1iI1i = True
   if 11 - 11: o0oOOo0O0Ooo
   if 95 - 95: i1IIi . ooOoO0o . Oo0Ooo
   if 13 - 13: OOooOOo - Oo0Ooo % O0 . I1Ii111
 if ( Oo0OO0OoooOo0 != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( i1iiii , False ) , Ii1oOOooo0 , green ( i1I1I1ii1i , False ) ,
  # Oo0Ooo / I11i / OoooooooOO - I1ii11iIi11i
 Oo0OO0OoooOo0 ) )
  if 7 - 7: oO0o - I11i
  OOOo0O00OO00O = oOoooooOooO . registered_rlocs
  IiIi1iIIiII1i = 1440
  if ( Ooo0000 ) :
   if ( oOoooooOooO . site_id != 0 ) :
    O0oO = map_request . source_eid
    OOOo0O00OO00O = lisp_get_private_rloc_set ( oOoooooOooO , O0oO , o0o0Oo0o0oOo )
    if 45 - 45: IiII + oO0o . iII111i
   if ( OOOo0O00OO00O == oOoooooOooO . registered_rlocs ) :
    O00000ooO0OOo = ( oOoooooOooO . group . is_null ( ) == False )
    iIo0 = lisp_get_partial_rloc_set ( OOOo0O00OO00O , O000oO0O0 , O00000ooO0OOo )
    if ( iIo0 != OOOo0O00OO00O ) :
     IiIi1iIIiII1i = 15
     OOOo0O00OO00O = iIo0
     if 67 - 67: O0 . i1IIi / I1ii11iIi11i % i1IIi
     if 63 - 63: i11iIiiIii + Oo0Ooo + IiII - I1IiiI + I1IiiI
     if 8 - 8: iII111i / iIii1I11I1II1
     if 82 - 82: OoO0O00 . iII111i + I1ii11iIi11i + ooOoO0o
     if 79 - 79: oO0o - IiII % OoooooooOO . ooOoO0o * I1IiiI
     if 44 - 44: o0oOOo0O0Ooo
     if 76 - 76: i11iIiiIii % OoO0O00
     if 38 - 38: I1ii11iIi11i + II111iiii - I1ii11iIi11i
  if ( oOoooooOooO . force_ttl != None ) :
   IiIi1iIIiII1i = oOoooooOooO . force_ttl | 0x80000000
   if 67 - 67: Ii1I / OoOoOO00
   if 19 - 19: OoO0O00 - OOooOOo * O0
   if 75 - 75: Ii1I + Oo0Ooo
   if 72 - 72: iII111i / o0oOOo0O0Ooo % I1IiiI * OOooOOo % I1ii11iIi11i * i11iIiiIii
   if 12 - 12: Ii1I * iIii1I11I1II1 . OoOoOO00 % i1IIi
   if 24 - 24: OoOoOO00 . OoO0O00 / oO0o * OoO0O00 . ooOoO0o * i11iIiiIii
  if ( iII1 ) :
   if ( iII1 . set_record_ttl ) :
    IiIi1iIIiII1i = iII1 . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( IiIi1iIIiII1i ) )
    if 61 - 61: ooOoO0o % IiII
   if ( iII1 . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    oo0oOooo0O = LISP_POLICY_DENIED_ACTION
    OOOo0O00OO00O = [ ]
   else :
    I1Ii1i111I = iII1 . set_policy_map_reply ( )
    if ( I1Ii1i111I ) : OOOo0O00OO00O = [ I1Ii1i111I ]
    if 23 - 23: OoooooooOO % o0oOOo0O0Ooo + OoO0O00
    if 25 - 25: IiII % OOooOOo + Ii1I * I1ii11iIi11i
    if 25 - 25: iIii1I11I1II1 * OoOoOO00 % I1IiiI + IiII
  if ( I11II1iI1i ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   oo0oOooo0O = LISP_POLICY_DENIED_ACTION
   OOOo0O00OO00O = [ ]
   if 34 - 34: ooOoO0o - OoooooooOO . o0oOOo0O0Ooo
   if 83 - 83: II111iiii . OOooOOo
  Ii1111ii = oOoooooOooO . echo_nonce_capable
  if 88 - 88: O0
  if 12 - 12: Ii1I % OOooOOo % Oo0Ooo * I1Ii111
  if 96 - 96: iII111i + ooOoO0o
  if 100 - 100: OOooOOo . ooOoO0o + Ii1I + Ii1I
  if ( IIiii ) :
   o0oIIi1 = oOoooooOooO . eid
   ooO0000ooO0oO = oOoooooOooO . group
  else :
   o0oIIi1 = i1I1I1IIIi11
   ooO0000ooO0oO = o0o0Oo0o0oOo
   oo0oOooo0O = LISP_AUTH_FAILURE_ACTION
   OOOo0O00OO00O = [ ]
   if 28 - 28: o0oOOo0O0Ooo . o0oOOo0O0Ooo . o0oOOo0O0Ooo
   if 93 - 93: i11iIiiIii / IiII
   if 35 - 35: I1Ii111 / o0oOOo0O0Ooo
   if 44 - 44: IiII % i11iIiiIii
   if 99 - 99: ooOoO0o % iIii1I11I1II1 + o0oOOo0O0Ooo % I11i
   if 66 - 66: iIii1I11I1II1
  if ( oO0II11II ) :
   o0oIIi1 = i1I1I1IIIi11
   ooO0000ooO0oO = o0o0Oo0o0oOo
   if 74 - 74: OoooooooOO - I1Ii111 - I1IiiI
   if 30 - 30: Oo0Ooo / o0oOOo0O0Ooo % o0oOOo0O0Ooo * i1IIi
   if 58 - 58: OoooooooOO - OOooOOo - OoOoOO00 / i1IIi * Oo0Ooo / i1IIi
   if 86 - 86: OoOoOO00 . I11i
   if 97 - 97: Ii1I
   if 24 - 24: I1IiiI * i11iIiiIii
  packet = lisp_build_map_reply ( o0oIIi1 , ooO0000ooO0oO , OOOo0O00OO00O ,
 oOooo0oOOOO , oo0oOooo0O , IiIi1iIIiII1i , map_request , None , Ii1111ii , False )
  if 83 - 83: OoOoOO00 * I1ii11iIi11i
  if ( oO0II11II ) :
   lisp_process_pubsub ( lisp_sockets , packet , o0oIIi1 , IIoOo0oooO0 ,
 mr_sport , oOooo0oOOOO , IiIi1iIIiII1i , Iiooo000o0OoOo )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , IIoOo0oooO0 , mr_sport )
   if 64 - 64: II111iiii * i1IIi - ooOoO0o
   if 4 - 4: ooOoO0o . OoO0O00 . OoO0O00 % ooOoO0o * Oo0Ooo - I1IiiI
  return ( [ oOoooooOooO . eid , oOoooooOooO . group , LISP_DDT_ACTION_MS_ACK ] )
  if 8 - 8: I1IiiI - I1Ii111 - OoooooooOO * Oo0Ooo * Ii1I
  if 11 - 11: I1IiiI
  if 43 - 43: I11i
  if 78 - 78: Ii1I % Oo0Ooo / OoO0O00 . iIii1I11I1II1 . II111iiii
  if 67 - 67: oO0o % I1Ii111
 I1IIiiII = len ( oOoooooOooO . registered_rlocs )
 if ( I1IIiiII == 0 ) :
  lprint ( ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" ) . format ( green ( i1iiii , False ) , Ii1oOOooo0 ,
  # iIii1I11I1II1 * O0 / Oo0Ooo . o0oOOo0O0Ooo + I1IiiI
 green ( i1I1I1ii1i , False ) ) )
  return ( [ oOoooooOooO . eid , oOoooooOooO . group , LISP_DDT_ACTION_MS_ACK ] )
  if 48 - 48: iIii1I11I1II1 * I1IiiI . I1Ii111 * IiII / I1ii11iIi11i % I1IiiI
  if 75 - 75: O0 . I1Ii111 . Ii1I % Oo0Ooo - OOooOOo / i11iIiiIii
  if 35 - 35: OoO0O00 . II111iiii + I1Ii111 + Ii1I - O0 + OoOoOO00
  if 77 - 77: O0 % Ii1I - I1ii11iIi11i
  if 17 - 17: OoooooooOO - OoooooooOO % I1Ii111 * Ii1I . OoooooooOO
 Oo00Oo0OOO = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 5 - 5: I11i . ooOoO0o
 oOOo0O0Oo = map_request . target_eid . hash_address ( Oo00Oo0OOO )
 oOOo0O0Oo %= I1IIiiII
 IiIii11I1 = oOoooooOooO . registered_rlocs [ oOOo0O0Oo ]
 if 17 - 17: OoooooooOO + ooOoO0o
 if ( IiIii11I1 . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( i1iiii , False ) ,
  # II111iiii - I1Ii111 . ooOoO0o * iII111i
 Ii1oOOooo0 , green ( i1I1I1ii1i , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( i1iiii , False ) ,
  # II111iiii + I1ii11iIi11i - OoooooooOO
 red ( IiIii11I1 . rloc . print_address ( ) , False ) , Ii1oOOooo0 ,
 green ( i1I1I1ii1i , False ) ) )
  if 74 - 74: i11iIiiIii % i11iIiiIii / II111iiii + I1ii11iIi11i . OOooOOo
  if 83 - 83: I1IiiI . ooOoO0o . II111iiii % OOooOOo
  if 86 - 86: i11iIiiIii + I1ii11iIi11i / OoOoOO00 * OoooooooOO
  if 6 - 6: II111iiii
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , IiIii11I1 . rloc , to_etr = True )
  if 26 - 26: iIii1I11I1II1 / iIii1I11I1II1 . IiII * i11iIiiIii
 return ( [ oOoooooOooO . eid , oOoooooOooO . group , LISP_DDT_ACTION_MS_ACK ] )
 if 21 - 21: OOooOOo + o0oOOo0O0Ooo
 if 28 - 28: OOooOOo + i1IIi + II111iiii / Oo0Ooo + iIii1I11I1II1 . Oo0Ooo
 if 73 - 73: Ii1I * iIii1I11I1II1 / o0oOOo0O0Ooo - o0oOOo0O0Ooo / i1IIi
 if 64 - 64: Ii1I * I1ii11iIi11i % II111iiii
 if 31 - 31: iIii1I11I1II1 % Oo0Ooo . I1IiiI % ooOoO0o
 if 38 - 38: I1ii11iIi11i + I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
 if 46 - 46: iII111i
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 56 - 56: Oo0Ooo / II111iiii
 if 61 - 61: Ii1I - i1IIi / ooOoO0o - Oo0Ooo / IiII % Oo0Ooo
 if 53 - 53: OoooooooOO + iII111i % II111iiii * IiII
 if 10 - 10: OoOoOO00 % I11i
 i1I1I1IIIi11 = map_request . target_eid
 o0o0Oo0o0oOo = map_request . target_group
 i1iiii = lisp_print_eid_tuple ( i1I1I1IIIi11 , o0o0Oo0o0oOo )
 oOooo0oOOOO = map_request . nonce
 oo0oOooo0O = LISP_DDT_ACTION_NULL
 if 46 - 46: i1IIi % IiII
 if 45 - 45: I1ii11iIi11i / I1ii11iIi11i - OoO0O00
 if 54 - 54: Ii1I + I1IiiI * OoOoOO00 + oO0o
 if 10 - 10: Ii1I - I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
 if 75 - 75: OOooOOo . ooOoO0o
 IiI1i = None
 if ( lisp_i_am_ms ) :
  oOoooooOooO = lisp_site_eid_lookup ( i1I1I1IIIi11 , o0o0Oo0o0oOo , False )
  if ( oOoooooOooO == None ) : return
  if 11 - 11: o0oOOo0O0Ooo - iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
  if ( oOoooooOooO . registered ) :
   oo0oOooo0O = LISP_DDT_ACTION_MS_ACK
   IiIi1iIIiII1i = 1440
  else :
   i1I1I1IIIi11 , o0o0Oo0o0oOo , oo0oOooo0O = lisp_ms_compute_neg_prefix ( i1I1I1IIIi11 , o0o0Oo0o0oOo )
   oo0oOooo0O = LISP_DDT_ACTION_MS_NOT_REG
   IiIi1iIIiII1i = 1
   if 51 - 51: I1IiiI + O0
 else :
  IiI1i = lisp_ddt_cache_lookup ( i1I1I1IIIi11 , o0o0Oo0o0oOo , False )
  if ( IiI1i == None ) :
   oo0oOooo0O = LISP_DDT_ACTION_NOT_AUTH
   IiIi1iIIiII1i = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( i1iiii , False ) ) )
   if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
  elif ( IiI1i . is_auth_prefix ( ) ) :
   if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
   if 85 - 85: OoOoOO00
   if 57 - 57: Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
   if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
   oo0oOooo0O = LISP_DDT_ACTION_DELEGATION_HOLE
   IiIi1iIIiII1i = 15
   oo0oOOOOOo0 = IiI1i . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( oo0oOOOOOo0 ,
   # I11i / II111iiii * i11iIiiIii / II111iiii % Oo0Ooo % i11iIiiIii
 green ( i1iiii , False ) ) )
   if 24 - 24: I11i . Ii1I / ooOoO0o + I1ii11iIi11i + OoooooooOO - I11i
   if ( o0o0Oo0o0oOo . is_null ( ) ) :
    i1I1I1IIIi11 = lisp_ddt_compute_neg_prefix ( i1I1I1IIIi11 , IiI1i ,
 lisp_ddt_cache )
   else :
    o0o0Oo0o0oOo = lisp_ddt_compute_neg_prefix ( o0o0Oo0o0oOo , IiI1i ,
 lisp_ddt_cache )
    i1I1I1IIIi11 = lisp_ddt_compute_neg_prefix ( i1I1I1IIIi11 , IiI1i ,
 IiI1i . source_cache )
    if 51 - 51: I1IiiI % i1IIi + ooOoO0o / I1ii11iIi11i % iIii1I11I1II1 % IiII
   IiI1i = None
  else :
   oo0oOOOOOo0 = IiI1i . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( oo0oOOOOOo0 , green ( i1iiii , False ) ) )
   if 12 - 12: OoOoOO00 * OoO0O00 / IiII - OoO0O00 * o0oOOo0O0Ooo * iII111i
   IiIi1iIIiII1i = 1440
   if 84 - 84: ooOoO0o * OOooOOo / I1Ii111 * I1IiiI * ooOoO0o
   if 75 - 75: oO0o
   if 60 - 60: OoOoOO00 % I1IiiI . i11iIiiIii % OoOoOO00 - I1Ii111
   if 71 - 71: OoooooooOO * Oo0Ooo
   if 80 - 80: iIii1I11I1II1
   if 91 - 91: OoOoOO00 + OoOoOO00 + ooOoO0o
 Oo00oo = lisp_build_map_referral ( i1I1I1IIIi11 , o0o0Oo0o0oOo , IiI1i , oo0oOooo0O , IiIi1iIIiII1i , oOooo0oOOOO )
 oOooo0oOOOO = map_request . nonce >> 32
 if ( map_request . nonce != 0 and oOooo0oOOOO != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , Oo00oo , ecm_source , port )
 return
 if 44 - 44: I1ii11iIi11i * OOooOOo % OoO0O00 . I1IiiI % Ii1I + II111iiii
 if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
 if 63 - 63: OoOoOO00 % IiII . iII111i
 if 44 - 44: I1IiiI
 if 25 - 25: oO0o
 if 100 - 100: I1IiiI / IiII + OoO0O00 . iII111i
 if 39 - 39: OoooooooOO * OOooOOo - OoO0O00
 if 3 - 3: I11i . i11iIiiIii % Oo0Ooo % II111iiii . I11i
 if 88 - 88: iIii1I11I1II1 . OOooOOo % iII111i
 if 72 - 72: ooOoO0o + i11iIiiIii / i1IIi
 if 64 - 64: OOooOOo - OOooOOo
 if 42 - 42: i1IIi / ooOoO0o . I1Ii111 % OoOoOO00
 if 67 - 67: i1IIi * i11iIiiIii * I1IiiI
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 i1111I = eid . hash_address ( entry_prefix )
 iIiii1 = eid . addr_length ( ) * 8
 oOo = 0
 if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
 if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
 if 60 - 60: OoO0O00 / oO0o . I1IiiI + OoOoOO00 + I1ii11iIi11i % Ii1I
 if 70 - 70: i1IIi * II111iiii * I1IiiI
 for oOo in range ( iIiii1 ) :
  Ii1i1Ii = 1 << ( iIiii1 - oOo - 1 )
  if ( i1111I & Ii1i1Ii ) : break
  if 7 - 7: OoooooooOO + II111iiii / Oo0Ooo % O0 % OOooOOo . I1Ii111
  if 78 - 78: iIii1I11I1II1 % OOooOOo
 if ( oOo > neg_prefix . mask_len ) : neg_prefix . mask_len = oOo
 return
 if 27 - 27: I11i + ooOoO0o - II111iiii . OoooooooOO % O0 % I1ii11iIi11i
 if 28 - 28: IiII - i1IIi - I1Ii111 % Ii1I - IiII
 if 73 - 73: iIii1I11I1II1 . iIii1I11I1II1 + oO0o % i11iIiiIii . IiII
 if 33 - 33: IiII - OOooOOo / i11iIiiIii * iIii1I11I1II1
 if 2 - 2: i11iIiiIii % ooOoO0o
 if 56 - 56: IiII % ooOoO0o + I1IiiI % I11i - OOooOOo
 if 82 - 82: OoooooooOO . i1IIi . OoO0O00 . OoO0O00
 if 31 - 31: iIii1I11I1II1
 if 64 - 64: ooOoO0o
 if 30 - 30: OoO0O00 + o0oOOo0O0Ooo / iIii1I11I1II1
def lisp_neg_prefix_walk ( entry , parms ) :
 i1I1I1IIIi11 , O0OoO0O0 , o0O0O0ooo00O = parms
 if 97 - 97: IiII % Oo0Ooo % OoOoOO00
 if ( O0OoO0O0 == None ) :
  if ( entry . eid . instance_id != i1I1I1IIIi11 . instance_id ) :
   return ( [ True , parms ] )
   if 87 - 87: i11iIiiIii . oO0o * I1IiiI * I1Ii111
  if ( entry . eid . afi != i1I1I1IIIi11 . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( O0OoO0O0 ) == False ) :
   return ( [ True , parms ] )
   if 57 - 57: iIii1I11I1II1 / i11iIiiIii / IiII + I1ii11iIi11i % I1IiiI
   if 80 - 80: iIii1I11I1II1
   if 23 - 23: II111iiii . ooOoO0o % I1Ii111
   if 39 - 39: OoooooooOO
   if 10 - 10: Oo0Ooo * iII111i
   if 78 - 78: Oo0Ooo / i11iIiiIii - I1IiiI
 lisp_find_negative_mask_len ( i1I1I1IIIi11 , entry . eid , o0O0O0ooo00O )
 return ( [ True , parms ] )
 if 51 - 51: ooOoO0o / Oo0Ooo - I1Ii111 - iII111i
 if 68 - 68: I1ii11iIi11i - iIii1I11I1II1 * OoooooooOO
 if 44 - 44: OoooooooOO + I1Ii111 + OoO0O00
 if 15 - 15: iIii1I11I1II1 % i1IIi + iII111i
 if 48 - 48: o0oOOo0O0Ooo / oO0o
 if 61 - 61: I1IiiI + iII111i * Ii1I % I1Ii111 . Ii1I
 if 83 - 83: i11iIiiIii * OoOoOO00 * i11iIiiIii % II111iiii . i11iIiiIii * I11i
 if 67 - 67: i1IIi / i1IIi + IiII . oO0o
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
 if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
 if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
 if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
 o0O0O0ooo00O = lisp_address ( eid . afi , "" , 0 , 0 )
 o0O0O0ooo00O . copy_address ( eid )
 o0O0O0ooo00O . mask_len = 0
 if 45 - 45: iIii1I11I1II1 . o0oOOo0O0Ooo % I1IiiI
 Ii1iI = ddt_entry . print_eid_tuple ( )
 O0OoO0O0 = ddt_entry . eid
 if 54 - 54: Ii1I + iII111i + OoooooooOO * Ii1I
 if 76 - 76: I1IiiI / OOooOOo % I1ii11iIi11i - o0oOOo0O0Ooo + I1ii11iIi11i
 if 45 - 45: I1ii11iIi11i * iII111i * OOooOOo
 if 18 - 18: oO0o . ooOoO0o . I1IiiI
 if 41 - 41: I11i % ooOoO0o + ooOoO0o + o0oOOo0O0Ooo - o0oOOo0O0Ooo % Ii1I
 eid , O0OoO0O0 , o0O0O0ooo00O = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , O0OoO0O0 , o0O0O0ooo00O ) )
 if 52 - 52: I11i % i1IIi . I1ii11iIi11i
 if 62 - 62: ooOoO0o - I1ii11iIi11i
 if 71 - 71: I11i
 if 34 - 34: oO0o / O0 * oO0o
 o0O0O0ooo00O . mask_address ( o0O0O0ooo00O . mask_len )
 if 47 - 47: iIii1I11I1II1 - o0oOOo0O0Ooo % Ii1I
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # II111iiii % I1Ii111 * IiII
 Ii1iI , o0O0O0ooo00O . print_prefix ( ) ) )
 return ( o0O0O0ooo00O )
 if 68 - 68: I1ii11iIi11i % iII111i - i11iIiiIii % I1ii11iIi11i
 if 65 - 65: i11iIiiIii
 if 75 - 75: OOooOOo % I1ii11iIi11i
 if 40 - 40: I1IiiI / I1IiiI
 if 26 - 26: i11iIiiIii % OoO0O00 % Ii1I - ooOoO0o
 if 2 - 2: II111iiii . o0oOOo0O0Ooo * OoooooooOO + OoooooooOO
 if 18 - 18: II111iiii * OOooOOo * OoO0O00 * iIii1I11I1II1 % o0oOOo0O0Ooo / IiII
 if 95 - 95: I1ii11iIi11i + I1IiiI . OoooooooOO
def lisp_ms_compute_neg_prefix ( eid , group ) :
 o0O0O0ooo00O = lisp_address ( eid . afi , "" , 0 , 0 )
 o0O0O0ooo00O . copy_address ( eid )
 o0O0O0ooo00O . mask_len = 0
 I1i1IIi11i11II = lisp_address ( group . afi , "" , 0 , 0 )
 I1i1IIi11i11II . copy_address ( group )
 I1i1IIi11i11II . mask_len = 0
 O0OoO0O0 = None
 if 5 - 5: I11i . I1ii11iIi11i - OoOoOO00 / OoOoOO00
 if 63 - 63: o0oOOo0O0Ooo / OoO0O00 * ooOoO0o * OoOoOO00 - II111iiii
 if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
 if 77 - 77: OOooOOo + ooOoO0o / O0
 if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
 if ( group . is_null ( ) ) :
  IiI1i = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( IiI1i == None ) :
   o0O0O0ooo00O . mask_len = o0O0O0ooo00O . host_mask_len ( )
   I1i1IIi11i11II . mask_len = I1i1IIi11i11II . host_mask_len ( )
   return ( [ o0O0O0ooo00O , I1i1IIi11i11II , LISP_DDT_ACTION_NOT_AUTH ] )
   if 49 - 49: ooOoO0o . Ii1I
  O0Oo = lisp_sites_by_eid
  if ( IiI1i . is_auth_prefix ( ) ) : O0OoO0O0 = IiI1i . eid
 else :
  IiI1i = lisp_ddt_cache . lookup_cache ( group , False )
  if ( IiI1i == None ) :
   o0O0O0ooo00O . mask_len = o0O0O0ooo00O . host_mask_len ( )
   I1i1IIi11i11II . mask_len = I1i1IIi11i11II . host_mask_len ( )
   return ( [ o0O0O0ooo00O , I1i1IIi11i11II , LISP_DDT_ACTION_NOT_AUTH ] )
   if 47 - 47: OoO0O00 * I1Ii111 % OoooooooOO
  if ( IiI1i . is_auth_prefix ( ) ) : O0OoO0O0 = IiI1i . group
  if 38 - 38: Ii1I % i1IIi
  group , O0OoO0O0 , I1i1IIi11i11II = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , O0OoO0O0 , I1i1IIi11i11II ) )
  if 41 - 41: I1ii11iIi11i . ooOoO0o / Oo0Ooo + i1IIi / i11iIiiIii * I1IiiI
  if 63 - 63: ooOoO0o + i11iIiiIii / i1IIi - I1Ii111 . O0 % OOooOOo
  I1i1IIi11i11II . mask_address ( I1i1IIi11i11II . mask_len )
  if 39 - 39: o0oOOo0O0Ooo
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , O0OoO0O0 . print_prefix ( ) if ( O0OoO0O0 != None ) else "'not found'" ,
  # iII111i * O0 * I1Ii111 / i1IIi . Ii1I - IiII
  # I11i * I11i
  # oO0o - OoooooooOO + IiII * I1ii11iIi11i % o0oOOo0O0Ooo - OoO0O00
 I1i1IIi11i11II . print_prefix ( ) ) )
  if 47 - 47: Oo0Ooo
  O0Oo = IiI1i . source_cache
  if 52 - 52: OoOoOO00 % OOooOOo * Oo0Ooo * Ii1I
  if 94 - 94: OoooooooOO % iII111i
  if 48 - 48: iIii1I11I1II1
  if 25 - 25: i1IIi % o0oOOo0O0Ooo . iII111i / OoooooooOO + i1IIi
  if 76 - 76: Oo0Ooo / OOooOOo + ooOoO0o % OoooooooOO - Oo0Ooo - I11i
 oo0oOooo0O = LISP_DDT_ACTION_DELEGATION_HOLE if ( O0OoO0O0 != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 36 - 36: OoO0O00 . Oo0Ooo * I1ii11iIi11i
 if 16 - 16: IiII + OOooOOo
 if 33 - 33: ooOoO0o . i11iIiiIii + OOooOOo
 if 77 - 77: OoooooooOO * Ii1I * iIii1I11I1II1 + IiII
 if 53 - 53: IiII + I1Ii111 + oO0o
 if 31 - 31: OOooOOo + OoOoOO00 * OOooOOo + OoOoOO00 / o0oOOo0O0Ooo . iIii1I11I1II1
 eid , O0OoO0O0 , o0O0O0ooo00O = O0Oo . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , O0OoO0O0 , o0O0O0ooo00O ) )
 if 1 - 1: I1Ii111 * i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / Oo0Ooo
 if 3 - 3: OOooOOo - i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
 if 60 - 60: OoOoOO00 / i1IIi . Ii1I - OoO0O00 - OoooooooOO
 if 39 - 39: I1IiiI + i1IIi * OoO0O00 % I11i
 o0O0O0ooo00O . mask_address ( o0O0O0ooo00O . mask_len )
 if 41 - 41: I1ii11iIi11i * IiII
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # IiII
 # OoooooooOO * I1Ii111 . OoooooooOO + i1IIi + IiII
 O0OoO0O0 . print_prefix ( ) if ( O0OoO0O0 != None ) else "'not found'" , o0O0O0ooo00O . print_prefix ( ) ) )
 if 50 - 50: I1IiiI / OoooooooOO
 if 61 - 61: I1Ii111
 return ( [ o0O0O0ooo00O , I1i1IIi11i11II , oo0oOooo0O ] )
 if 1 - 1: i11iIiiIii % I1Ii111 + I1ii11iIi11i
 if 17 - 17: Oo0Ooo
 if 59 - 59: OoO0O00 * o0oOOo0O0Ooo . I11i
 if 32 - 32: I1ii11iIi11i
 if 44 - 44: i1IIi * OoO0O00
 if 21 - 21: Oo0Ooo - II111iiii + I11i
 if 69 - 69: Oo0Ooo - iIii1I11I1II1 . oO0o
 if 54 - 54: Ii1I / Oo0Ooo - i1IIi * OoooooooOO - OoOoOO00 + OoOoOO00
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
 i1I1I1IIIi11 = map_request . target_eid
 o0o0Oo0o0oOo = map_request . target_group
 oOooo0oOOOO = map_request . nonce
 if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
 if ( action == LISP_DDT_ACTION_MS_ACK ) : IiIi1iIIiII1i = 1440
 if 85 - 85: iII111i % i11iIiiIii
 if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
 if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
 if 41 - 41: Ii1I + IiII
 Ooooo = lisp_map_referral ( )
 Ooooo . record_count = 1
 Ooooo . nonce = oOooo0oOOOO
 Oo00oo = Ooooo . encode ( )
 Ooooo . print_map_referral ( )
 if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
 Oo00Oo0o000 = False
 if 53 - 53: I1IiiI % OOooOOo + Ii1I - Ii1I
 if 99 - 99: i1IIi * OoOoOO00 - i1IIi
 if 65 - 65: OoO0O00 / i11iIiiIii + I1ii11iIi11i + OoOoOO00
 if 82 - 82: Ii1I * OOooOOo % ooOoO0o / OoO0O00 - Oo0Ooo . I1Ii111
 if 90 - 90: I11i * i11iIiiIii % i1IIi + I1Ii111 / OoO0O00
 if 15 - 15: Oo0Ooo + oO0o . I11i % OoO0O00
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( i1I1I1IIIi11 ,
 o0o0Oo0o0oOo )
  IiIi1iIIiII1i = 15
  if 13 - 13: I1ii11iIi11i / ooOoO0o * I1Ii111
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : IiIi1iIIiII1i = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : IiIi1iIIiII1i = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : IiIi1iIIiII1i = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : IiIi1iIIiII1i = 0
 if 45 - 45: I1ii11iIi11i - I11i
 O000oO00 = False
 I1IIiiII = 0
 IiI1i = lisp_ddt_cache_lookup ( i1I1I1IIIi11 , o0o0Oo0o0oOo , False )
 if ( IiI1i != None ) :
  I1IIiiII = len ( IiI1i . delegation_set )
  O000oO00 = IiI1i . is_ms_peer_entry ( )
  IiI1i . map_referrals_sent += 1
  if 70 - 70: I11i + oO0o + o0oOOo0O0Ooo . I1Ii111 * i11iIiiIii
  if 46 - 46: O0 . i11iIiiIii / OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1
  if 39 - 39: i11iIiiIii + I1Ii111
  if 49 - 49: i1IIi * iII111i - iIii1I11I1II1 % I11i * O0 / OoOoOO00
  if 48 - 48: IiII
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : Oo00Oo0o000 = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  Oo00Oo0o000 = ( O000oO00 == False )
  if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - o0oOOo0O0Ooo
  if 98 - 98: o0oOOo0O0Ooo * OoO0O00 . OoooooooOO
  if 40 - 40: I1Ii111 + Oo0Ooo + I1Ii111
  if 57 - 57: I1Ii111 / II111iiii % iII111i
  if 32 - 32: IiII - OOooOOo + i11iIiiIii + I1IiiI . iII111i
 IiIo0oo0O = lisp_eid_record ( )
 IiIo0oo0O . rloc_count = I1IIiiII
 IiIo0oo0O . authoritative = True
 IiIo0oo0O . action = action
 IiIo0oo0O . ddt_incomplete = Oo00Oo0o000
 IiIo0oo0O . eid = eid_prefix
 IiIo0oo0O . group = group_prefix
 IiIo0oo0O . record_ttl = IiIi1iIIiII1i
 if 75 - 75: o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1IiiI / OoO0O00
 Oo00oo += IiIo0oo0O . encode ( )
 IiIo0oo0O . print_record ( "  " , True )
 if 22 - 22: Oo0Ooo / iIii1I11I1II1 + o0oOOo0O0Ooo
 if 16 - 16: II111iiii . Ii1I + I1Ii111 % i1IIi / i11iIiiIii + OOooOOo
 if 43 - 43: I1IiiI . Oo0Ooo + i1IIi + I11i / OoO0O00
 if 66 - 66: i11iIiiIii
 if ( I1IIiiII != 0 ) :
  for Ii1iII in IiI1i . delegation_set :
   IiiI1 = lisp_rloc_record ( )
   IiiI1 . rloc = Ii1iII . delegate_address
   IiiI1 . priority = Ii1iII . priority
   IiiI1 . weight = Ii1iII . weight
   IiiI1 . mpriority = 255
   IiiI1 . mweight = 0
   IiiI1 . reach_bit = True
   Oo00oo += IiiI1 . encode ( )
   IiiI1 . print_record ( "    " )
   if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
   if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
   if 83 - 83: i1IIi * i1IIi - II111iiii / OoooooooOO . Ii1I + I1Ii111
   if 10 - 10: I11i
   if 24 - 24: Ii1I
   if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
   if 25 - 25: I11i % i1IIi / I11i * i11iIiiIii
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , Oo00oo , ecm_source , port )
 return
 if 71 - 71: IiII % I11i - OoooooooOO + I1IiiI / Oo0Ooo % I11i
 if 6 - 6: i1IIi * i11iIiiIii + ooOoO0o - IiII
 if 97 - 97: iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - Oo0Ooo - iIii1I11I1II1
 if 26 - 26: ooOoO0o + Oo0Ooo
 if 24 - 24: I1IiiI
 if 43 - 43: OoO0O00
 if 51 - 51: OoooooooOO % IiII % Oo0Ooo
 if 50 - 50: I1IiiI - i11iIiiIii / I1ii11iIi11i . Ii1I - iIii1I11I1II1
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # iII111i . OoO0O00 % I1IiiI * II111iiii * OoooooooOO . II111iiii
 red ( dest . print_address ( ) , False ) ) )
 if 97 - 97: oO0o - Ii1I - II111iiii % II111iiii * OOooOOo
 oo0oOooo0O = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 84 - 84: i1IIi . OoOoOO00 % I1ii11iIi11i . OoO0O00 + i11iIiiIii
 if 19 - 19: i1IIi / I1IiiI + IiII . iII111i
 if 68 - 68: iII111i
 if 29 - 29: II111iiii / II111iiii % OoO0O00 % Oo0Ooo . II111iiii
 if 33 - 33: OoooooooOO . OoO0O00 % OoooooooOO
 if ( lisp_get_eid_hash ( eid ) != None ) :
  oo0oOooo0O = LISP_SEND_MAP_REQUEST_ACTION
  if 9 - 9: IiII * O0 + OOooOOo . II111iiii
  if 14 - 14: iIii1I11I1II1 + i11iIiiIii + o0oOOo0O0Ooo + o0oOOo0O0Ooo - IiII / I1Ii111
 Oo00oo = lisp_build_map_reply ( eid , group , [ ] , nonce , oo0oOooo0O , ttl , None ,
 None , False , False )
 if 70 - 70: OoooooooOO + I1IiiI / OOooOOo
 if 19 - 19: I1Ii111 + i1IIi % OoooooooOO + i1IIi
 if 16 - 16: I1Ii111 + II111iiii + IiII
 if 34 - 34: iIii1I11I1II1 - II111iiii - ooOoO0o + oO0o
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , Oo00oo , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , Oo00oo , dest , port )
  if 46 - 46: ooOoO0o % II111iiii
 return
 if 61 - 61: OoO0O00 . I1IiiI
 if 89 - 89: IiII
 if 73 - 73: II111iiii + ooOoO0o % OOooOOo . oO0o / oO0o * i1IIi
 if 19 - 19: I1Ii111 + I11i
 if 21 - 21: OoOoOO00
 if 2 - 2: i1IIi . OOooOOo
 if 23 - 23: Ii1I - OOooOOo
def lisp_retransmit_ddt_map_request ( mr ) :
 oOIII = mr . mr_source . print_address ( )
 OO00 = mr . print_eid_tuple ( )
 oOooo0oOOOO = mr . nonce
 if 65 - 65: iIii1I11I1II1 / IiII / IiII
 if 57 - 57: OoOoOO00 . O0 / iII111i / i11iIiiIii
 if 38 - 38: iII111i - Oo0Ooo / O0
 if 40 - 40: ooOoO0o + iIii1I11I1II1 / OoOoOO00 * iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1
 if 79 - 79: ooOoO0o . oO0o + Ii1I * ooOoO0o + O0 . II111iiii
 if ( mr . last_request_sent_to ) :
  I1III11iIIIi = mr . last_request_sent_to . print_address ( )
  OO0oO0O = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( OO0oO0O and I1III11iIIIi in OO0oO0O . referral_set ) :
   OO0oO0O . referral_set [ I1III11iIIIi ] . no_responses += 1
   if 81 - 81: i11iIiiIii . OoOoOO00 * o0oOOo0O0Ooo / O0 * OoooooooOO / i11iIiiIii
   if 62 - 62: i11iIiiIii * iII111i . Oo0Ooo % Oo0Ooo
   if 4 - 4: OoooooooOO
   if 66 - 66: iII111i / IiII
   if 45 - 45: o0oOOo0O0Ooo - i1IIi / o0oOOo0O0Ooo + IiII
   if 94 - 94: Ii1I
   if 21 - 21: OoOoOO00
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( OO00 , False ) , lisp_hex_string ( oOooo0oOOOO ) ) )
  if 68 - 68: i11iIiiIii / OOooOOo / I1ii11iIi11i % IiII * IiII + II111iiii
  mr . dequeue_map_request ( )
  return
  if 65 - 65: I1IiiI + OoOoOO00 - OoOoOO00 . oO0o
  if 84 - 84: Ii1I * i1IIi
 mr . retry_count += 1
 if 42 - 42: OoOoOO00 - ooOoO0o + oO0o - II111iiii
 I111 = green ( oOIII , False )
 IiI11I111 = green ( OO00 , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # o0oOOo0O0Ooo - i11iIiiIii + I11i % oO0o * OoooooooOO . OoO0O00
 red ( mr . itr . print_address ( ) , False ) , I111 , IiI11I111 ,
 lisp_hex_string ( oOooo0oOOOO ) ) )
 if 15 - 15: i1IIi . I1ii11iIi11i + II111iiii - i1IIi
 if 11 - 11: I1ii11iIi11i % iIii1I11I1II1 / OoO0O00 . oO0o . OoooooooOO
 if 93 - 93: iII111i / OoO0O00
 if 99 - 99: OOooOOo + ooOoO0o / iIii1I11I1II1 % iII111i + i1IIi
 lisp_send_ddt_map_request ( mr , False )
 if 12 - 12: O0
 if 55 - 55: iIii1I11I1II1
 if 7 - 7: OoO0O00
 if 61 - 61: I1Ii111 / I1IiiI / OOooOOo . I1ii11iIi11i
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 3 - 3: IiII
 if 2 - 2: I1IiiI % Ii1I % Oo0Ooo / ooOoO0o % Oo0Ooo + OoOoOO00
 if 44 - 44: i1IIi / OoooooooOO * OoooooooOO
 if 93 - 93: OoOoOO00 % Oo0Ooo . OoO0O00 / OoooooooOO
 if 59 - 59: OoO0O00 + O0 + i11iIiiIii / OoOoOO00 + iIii1I11I1II1 / OoOoOO00
 if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
 if 93 - 93: OoO0O00 % IiII % ooOoO0o . I1IiiI
 if 96 - 96: II111iiii
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 73 - 73: II111iiii
 if 81 - 81: I1IiiI + OoO0O00
 if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
 if 32 - 32: o0oOOo0O0Ooo - iII111i + i11iIiiIii / ooOoO0o . OoOoOO00 . IiII
 iIiiii1 = [ ]
 for OoooOO0 in list ( referral . referral_set . values ( ) ) :
  if ( OoooOO0 . updown == False ) : continue
  if ( len ( iIiiii1 ) == 0 or iIiiii1 [ 0 ] . priority == OoooOO0 . priority ) :
   iIiiii1 . append ( OoooOO0 )
  elif ( iIiiii1 [ 0 ] . priority > OoooOO0 . priority ) :
   iIiiii1 = [ ]
   iIiiii1 . append ( OoooOO0 )
   if 26 - 26: I1ii11iIi11i
   if 67 - 67: I1Ii111 * iIii1I11I1II1 / O0 + OoO0O00 * iIii1I11I1II1 % II111iiii
   if 13 - 13: Ii1I / ooOoO0o / iII111i % II111iiii * I1IiiI * II111iiii
 i1ii1 = len ( iIiiii1 )
 if ( i1ii1 == 0 ) : return ( None )
 if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
 oOOo0O0Oo = dest_eid . hash_address ( source_eid )
 oOOo0O0Oo = oOOo0O0Oo % i1ii1
 return ( iIiiii1 [ oOOo0O0Oo ] )
 if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
 if 85 - 85: I1IiiI + i1IIi % I1Ii111
 if 76 - 76: i11iIiiIii % i11iIiiIii
 if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
 if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
 if 69 - 69: O0 % I1ii11iIi11i
 if 77 - 77: iIii1I11I1II1 . OOooOOo
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 OO0ooo000 = mr . lisp_sockets
 oOooo0oOOOO = mr . nonce
 ii1oO0Oo = mr . itr
 iiIII1IiI = mr . mr_source
 i1iiii = mr . print_eid_tuple ( )
 if 85 - 85: i11iIiiIii * Ii1I * i1IIi
 if 2 - 2: I1IiiI . I1ii11iIi11i + oO0o + Oo0Ooo % I1IiiI - Ii1I
 if 94 - 94: Oo0Ooo
 if 93 - 93: O0
 if 27 - 27: o0oOOo0O0Ooo + i1IIi + oO0o * II111iiii * OoO0O00
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( i1iiii , False ) , lisp_hex_string ( oOooo0oOOOO ) ) )
  if 64 - 64: I1IiiI
  mr . dequeue_map_request ( )
  return
  if 27 - 27: I1Ii111 % I1Ii111 - I11i + IiII - oO0o
  if 52 - 52: OOooOOo % Ii1I + iIii1I11I1II1 . ooOoO0o
  if 83 - 83: oO0o - iIii1I11I1II1 * iII111i
  if 17 - 17: I1IiiI . OoOoOO00
  if 14 - 14: OOooOOo
  if 84 - 84: Ii1I + OoO0O00 + OOooOOo % ooOoO0o
 if ( send_to_root ) :
  iI1iiIiIi1i = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  OoIiIIi1iI1I1i = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( i1iiii , False ) ) )
 else :
  iI1iiIiIi1i = mr . eid
  OoIiIIi1iI1I1i = mr . group
  if 96 - 96: IiII / I1Ii111 - I1ii11iIi11i * iII111i + OOooOOo
  if 50 - 50: oO0o * OOooOOo + i1IIi / I1ii11iIi11i
  if 46 - 46: O0 % ooOoO0o
  if 79 - 79: I1ii11iIi11i
  if 9 - 9: IiII . O0
 oo = lisp_referral_cache_lookup ( iI1iiIiIi1i , OoIiIIi1iI1I1i , False )
 if ( oo == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( OO0ooo000 , iI1iiIiIi1i , OoIiIIi1iI1I1i ,
 oOooo0oOOOO , ii1oO0Oo , mr . sport , 15 , None , False )
  return
  if 38 - 38: IiII . I1ii11iIi11i + iII111i * I11i % IiII
  if 18 - 18: I11i
 II1Ii11i11Ii = oo . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( II1Ii11i11Ii ,
 oo . print_referral_type ( ) ) )
 if 84 - 84: OoOoOO00
 OoooOO0 = lisp_get_referral_node ( oo , iiIII1IiI , mr . eid )
 if ( OoooOO0 == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( OO0ooo000 , oo . eid ,
 oo . group , oOooo0oOOOO , ii1oO0Oo , mr . sport , 1 , None , False )
  return
  if 99 - 99: OoO0O00 - OoOoOO00 - i1IIi / OoO0O00 * I1ii11iIi11i * iIii1I11I1II1
  if 65 - 65: iII111i - O0 / i1IIi . I1Ii111
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( OoooOO0 . referral_address . print_address ( ) ,
 # I11i / Ii1I - o0oOOo0O0Ooo % oO0o / OoO0O00 * I11i
 oo . print_referral_type ( ) , green ( i1iiii , False ) ,
 lisp_hex_string ( oOooo0oOOOO ) ) )
 if 24 - 24: i1IIi
 if 21 - 21: II111iiii
 if 27 - 27: I1IiiI * i11iIiiIii
 if 86 - 86: I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - i1IIi . I11i / OOooOOo
 ooOo0o00 = ( oo . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 oo . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( OO0ooo000 , mr . packet , iiIII1IiI , mr . sport , mr . eid ,
 OoooOO0 . referral_address , to_ms = ooOo0o00 , ddt = True )
 if 54 - 54: I1ii11iIi11i - I1IiiI . OoOoOO00
 if 36 - 36: OoO0O00 * I1IiiI / iII111i
 if 95 - 95: Ii1I . Oo0Ooo
 if 42 - 42: IiII . i1IIi % O0 * ooOoO0o - OOooOOo % ooOoO0o
 mr . last_request_sent_to = OoooOO0 . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 OoooOO0 . map_requests_sent += 1
 return
 if 99 - 99: i1IIi + OoOoOO00 - iII111i % II111iiii
 if 6 - 6: ooOoO0o - I1Ii111 . OoOoOO00
 if 64 - 64: iII111i + I1ii11iIi11i
 if 88 - 88: I1Ii111 / i11iIiiIii - O0 . II111iiii / II111iiii * II111iiii
 if 56 - 56: Oo0Ooo / I1IiiI % I1Ii111 % I1ii11iIi11i * I1IiiI - IiII
 if 39 - 39: oO0o + iII111i . I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + OOooOOo
 if 61 - 61: ooOoO0o / I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * iII111i
 if 94 - 94: I1IiiI / I11i
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 100 - 100: Ii1I % OoO0O00 % OoooooooOO / II111iiii * I1Ii111
 i1I1I1IIIi11 = map_request . target_eid
 o0o0Oo0o0oOo = map_request . target_group
 OO00 = map_request . print_eid_tuple ( )
 oOIII = mr_source . print_address ( )
 oOooo0oOOOO = map_request . nonce
 if 64 - 64: I1Ii111 * OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / Oo0Ooo
 I111 = green ( oOIII , False )
 IiI11I111 = green ( OO00 , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # I11i / i11iIiiIii % ooOoO0o
 red ( ecm_source . print_address ( ) , False ) , I111 , IiI11I111 ,
 lisp_hex_string ( oOooo0oOOOO ) ) )
 if 8 - 8: O0 * I1IiiI * O0 - i11iIiiIii - II111iiii . Ii1I
 if 96 - 96: i11iIiiIii - i11iIiiIii . II111iiii
 if 3 - 3: Oo0Ooo / Oo0Ooo - II111iiii % iII111i * Oo0Ooo
 if 37 - 37: ooOoO0o
 OOoOo0O0O0oO = lisp_ddt_map_request ( lisp_sockets , packet , i1I1I1IIIi11 , o0o0Oo0o0oOo , oOooo0oOOOO )
 OOoOo0O0O0oO . packet = packet
 OOoOo0O0O0oO . itr = ecm_source
 OOoOo0O0O0oO . mr_source = mr_source
 OOoOo0O0O0oO . sport = sport
 OOoOo0O0O0oO . from_pitr = map_request . pitr_bit
 OOoOo0O0O0oO . queue_map_request ( )
 if 18 - 18: Oo0Ooo % OOooOOo / OOooOOo . I1IiiI + i1IIi . I1IiiI
 lisp_send_ddt_map_request ( OOoOo0O0O0oO , False )
 return
 if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
 if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
 if 6 - 6: O0 * I1Ii111 - II111iiii
 if 60 - 60: oO0o % oO0o
 if 76 - 76: I1Ii111 / o0oOOo0O0Ooo
 if 19 - 19: O0 . i1IIi % iIii1I11I1II1 + OOooOOo * OoOoOO00 / I11i
 if 82 - 82: I1ii11iIi11i
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl , timestamp ) :
 if 75 - 75: I11i - II111iiii
 i1iiI11i1 = packet
 OOo0OoO0O0o0 = lisp_map_request ( )
 packet = OOo0OoO0O0o0 . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 59 - 59: I11i / OoOoOO00 % ooOoO0o . Ii1I
  if 48 - 48: OoOoOO00 % IiII % i1IIi + o0oOOo0O0Ooo
 OOo0OoO0O0o0 . print_map_request ( )
 if 33 - 33: iIii1I11I1II1 . O0
 if 54 - 54: iIii1I11I1II1
 if 54 - 54: iII111i + OOooOOo + OoO0O00
 if 6 - 6: oO0o - OoooooooOO * iIii1I11I1II1 * I1ii11iIi11i
 if ( OOo0OoO0O0o0 . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , OOo0OoO0O0o0 , mr_source ,
 mr_port , ttl , timestamp )
  return
  if 65 - 65: IiII + OoOoOO00
  if 93 - 93: Ii1I
  if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
  if 5 - 5: OoO0O00 / ooOoO0o
  if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
 if ( OOo0OoO0O0o0 . smr_bit ) :
  lisp_process_smr ( OOo0OoO0O0o0 )
  if 97 - 97: oO0o / Ii1I
  if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
  if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
  if 91 - 91: IiII * Ii1I * OOooOOo
  if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
 if ( OOo0OoO0O0o0 . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( OOo0OoO0O0o0 )
  if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
  if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
  if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
  if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
  if 95 - 95: IiII + iII111i % I1IiiI
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , OOo0OoO0O0o0 , mr_source ,
 mr_port , ttl , timestamp )
  if 18 - 18: Oo0Ooo
  if 8 - 8: O0 + iIii1I11I1II1 - O0
  if 67 - 67: O0
  if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
  if 28 - 28: O0 - Oo0Ooo
 if ( lisp_i_am_ms ) :
  packet = i1iiI11i1
  i1I1I1IIIi11 , o0o0Oo0o0oOo , ooOo0Ooo0 = lisp_ms_process_map_request ( lisp_sockets ,
 i1iiI11i1 , OOo0OoO0O0o0 , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , OOo0OoO0O0o0 , ecm_source ,
 ecm_port , ooOo0Ooo0 , i1I1I1IIIi11 , o0o0Oo0o0oOo )
   if 55 - 55: I1Ii111 * I1Ii111 / O0 - O0
  return
  if 15 - 15: I1ii11iIi11i % ooOoO0o * oO0o * OoO0O00 + OoO0O00
  if 58 - 58: I1ii11iIi11i
  if 93 - 93: i1IIi - IiII + IiII % OoooooooOO / o0oOOo0O0Ooo
  if 39 - 39: I1IiiI + Ii1I - O0
  if 25 - 25: IiII % iIii1I11I1II1 + ooOoO0o % iII111i - OoO0O00
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , i1iiI11i1 , OOo0OoO0O0o0 ,
 ecm_source , mr_port , mr_source )
  if 36 - 36: OoooooooOO / oO0o + IiII . I1IiiI - o0oOOo0O0Ooo % OOooOOo
  if 15 - 15: Ii1I % IiII + IiII % iII111i - O0 * OoooooooOO
  if 53 - 53: OoOoOO00 . Ii1I / Oo0Ooo
  if 62 - 62: i11iIiiIii
  if 38 - 38: I1ii11iIi11i % ooOoO0o * OoooooooOO + iIii1I11I1II1 % i1IIi / OOooOOo
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = i1iiI11i1
  lisp_ddt_process_map_request ( lisp_sockets , OOo0OoO0O0o0 , ecm_source ,
 ecm_port )
  if 6 - 6: i11iIiiIii
 return
 if 8 - 8: iIii1I11I1II1 + I1ii11iIi11i . i1IIi % OoOoOO00 % OoooooooOO * Oo0Ooo
 if 53 - 53: oO0o
 if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
 if 4 - 4: I1IiiI
 if 31 - 31: ooOoO0o * i1IIi . O0
 if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
 if 100 - 100: I1Ii111
 if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
def lisp_store_mr_stats ( source , nonce ) :
 OOoOo0O0O0oO = lisp_get_map_resolver ( source , None )
 if ( OOoOo0O0O0oO == None ) : return
 if 88 - 88: IiII
 if 29 - 29: iII111i . ooOoO0o
 if 62 - 62: IiII
 if 95 - 95: ooOoO0o / i1IIi + II111iiii + OoO0O00 % OoO0O00
 OOoOo0O0O0oO . neg_map_replies_received += 1
 OOoOo0O0O0oO . last_reply = lisp_get_timestamp ( )
 if 18 - 18: ooOoO0o * I1IiiI / iII111i % iII111i
 if 9 - 9: i11iIiiIii % ooOoO0o % O0 + i1IIi / O0
 if 12 - 12: I1Ii111 - iII111i * iII111i + OoO0O00 . Ii1I % I11i
 if 28 - 28: ooOoO0o % OoO0O00 - II111iiii * IiII - I1IiiI + I1IiiI
 if ( ( OOoOo0O0O0oO . neg_map_replies_received % 100 ) == 0 ) : OOoOo0O0O0oO . total_rtt = 0
 if 84 - 84: IiII / Ii1I
 if 39 - 39: OOooOOo - iIii1I11I1II1 + OoOoOO00 % IiII * OoooooooOO % Ii1I
 if 11 - 11: I1ii11iIi11i
 if 83 - 83: O0
 if ( OOoOo0O0O0oO . last_nonce == nonce ) :
  OOoOo0O0O0oO . total_rtt += ( time . time ( ) - OOoOo0O0O0oO . last_used )
  OOoOo0O0O0oO . last_nonce = 0
  if 97 - 97: O0
 if ( ( OOoOo0O0O0oO . neg_map_replies_received % 10 ) == 0 ) : OOoOo0O0O0oO . last_nonce = 0
 return
 if 50 - 50: I1Ii111 / OoooooooOO . o0oOOo0O0Ooo + I1IiiI * i11iIiiIii
 if 28 - 28: I1Ii111 * II111iiii
 if 14 - 14: iIii1I11I1II1 / Ii1I + o0oOOo0O0Ooo . iII111i % iII111i . i1IIi
 if 67 - 67: IiII * II111iiii + ooOoO0o - i11iIiiIii
 if 15 - 15: I11i
 if 67 - 67: iIii1I11I1II1
 if 91 - 91: ooOoO0o
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl , itr_in_ts ) :
 global lisp_map_cache
 if 66 - 66: OOooOOo
 iIII1111IiIII = lisp_map_reply ( )
 packet = iIII1111IiIII . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
 iIII1111IiIII . print_map_reply ( )
 if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
 if 9 - 9: Ii1I
 if 44 - 44: iII111i
 if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
 iII1II1I = None
 for iIi1iIIIiIiI in range ( iIII1111IiIII . record_count ) :
  IiIo0oo0O = lisp_eid_record ( )
  packet = IiIo0oo0O . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 16 - 16: i1IIi - iIii1I11I1II1 - ooOoO0o / OoooooooOO - Oo0Ooo
  IiIo0oo0O . print_record ( "  " , False )
  if 46 - 46: OoOoOO00 + i1IIi
  if 43 - 43: II111iiii * IiII % iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
  if 81 - 81: oO0o % I1ii11iIi11i % ooOoO0o * O0 - OOooOOo
  if 17 - 17: O0 % O0 / I1ii11iIi11i . Oo0Ooo . iII111i
  if 4 - 4: OoO0O00
  if ( IiIo0oo0O . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , iIII1111IiIII . nonce )
   if 65 - 65: Oo0Ooo % O0 / I1Ii111 * IiII - oO0o
   if 32 - 32: Ii1I * OoO0O00 + ooOoO0o
  iII1iii1iII1iI1II = ( IiIo0oo0O . group . is_null ( ) == False )
  if 41 - 41: IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
  if 38 - 38: iII111i * OoooooooOO - IiII
  if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
  if 91 - 91: O0 + I1Ii111 * II111iiii - O0 . i11iIiiIii . Oo0Ooo
  if 54 - 54: ooOoO0o * I11i / I1ii11iIi11i % ooOoO0o
  if ( lisp_decent_push_configured ) :
   oo0oOooo0O = IiIo0oo0O . action
   if ( iII1iii1iII1iI1II and oo0oOooo0O == LISP_DROP_ACTION ) :
    if ( IiIo0oo0O . eid . is_local ( ) ) : continue
    if 76 - 76: I11i . I1IiiI
    if 66 - 66: oO0o % oO0o * IiII
    if 39 - 39: i1IIi * Ii1I + OoOoOO00 / oO0o
    if 6 - 6: I1ii11iIi11i / II111iiii / OoOoOO00 . i11iIiiIii - iII111i
    if 43 - 43: i11iIiiIii * i11iIiiIii * I1Ii111
    if 80 - 80: oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / o0oOOo0O0Ooo % OoooooooOO
    if 31 - 31: o0oOOo0O0Ooo - OoO0O00 % I1IiiI
  if ( iII1iii1iII1iI1II == False and IiIo0oo0O . eid . is_null ( ) ) : continue
  if 23 - 23: OOooOOo
  if 97 - 97: Oo0Ooo / OoooooooOO . OoooooooOO
  if 47 - 47: OoO0O00
  if 52 - 52: I1IiiI * iIii1I11I1II1 % oO0o * IiII % oO0o
  if 9 - 9: I11i
  if ( iII1iii1iII1iI1II ) :
   o0ooo0oOO0o = lisp_map_cache_lookup ( IiIo0oo0O . eid , IiIo0oo0O . group )
  else :
   o0ooo0oOO0o = lisp_map_cache . lookup_cache ( IiIo0oo0O . eid , True )
   if 78 - 78: iIii1I11I1II1 % I1ii11iIi11i % IiII
  o0oOoO0O = ( o0ooo0oOO0o == None )
  if 38 - 38: OoO0O00
  if 42 - 42: O0
  if 31 - 31: OoOoOO00 . II111iiii - oO0o . iII111i - I1ii11iIi11i
  if 90 - 90: OoooooooOO / ooOoO0o / I1IiiI
  if 70 - 70: I1IiiI
  if ( o0ooo0oOO0o == None ) :
   o0o0OooOooo00 , iIiiiI1 , II11iiiII1Ii = lisp_allow_gleaning ( IiIo0oo0O . eid , IiIo0oo0O . group ,
 None )
   if ( o0o0OooOooo00 ) : continue
  else :
   if ( o0ooo0oOO0o . gleaned ) : continue
   if 93 - 93: OoO0O00
   if 56 - 56: i1IIi + Ii1I * iIii1I11I1II1
   if 1 - 1: iII111i
   if 25 - 25: oO0o - i1IIi
   if 67 - 67: I1IiiI % I11i - OoooooooOO
  OOOo0O00OO00O = [ ]
  ii111IiiIii = None
  for iI1iII1II1 in range ( IiIo0oo0O . rloc_count ) :
   IiiI1 = lisp_rloc_record ( )
   IiiI1 . keys = iIII1111IiIII . keys
   packet = IiiI1 . decode ( packet , iIII1111IiIII . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 78 - 78: OoooooooOO . I1ii11iIi11i * oO0o . o0oOOo0O0Ooo * OoOoOO00 / oO0o
   IiiI1 . print_record ( "    " )
   if 47 - 47: OOooOOo
   iI1I11II = None
   if ( o0ooo0oOO0o ) : iI1I11II = o0ooo0oOO0o . get_rloc ( IiiI1 . rloc )
   if ( iI1I11II ) :
    I1Ii1i111I = iI1I11II
   else :
    I1Ii1i111I = lisp_rloc ( )
    if 99 - 99: O0 - OoO0O00
    if 95 - 95: Ii1I . IiII * o0oOOo0O0Ooo
    if 91 - 91: I1Ii111
    if 49 - 49: I11i
    if 17 - 17: Oo0Ooo % o0oOOo0O0Ooo
    if 3 - 3: OoO0O00 . oO0o . oO0o . Ii1I
    if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
   I1I = I1Ii1i111I . store_rloc_from_record ( IiiI1 , iIII1111IiIII . nonce ,
 source )
   I1Ii1i111I . echo_nonce_capable = iIII1111IiIII . echo_nonce_capable
   if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
   if ( I1Ii1i111I . echo_nonce_capable ) :
    O0O0 = I1Ii1i111I . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , O0O0 ) == None ) :
     lisp_echo_nonce ( O0O0 )
     if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
     if 10 - 10: ooOoO0o
     if 69 - 69: I11i + I1IiiI / oO0o
     if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
     if 85 - 85: I1Ii111 - oO0o
     if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
   if ( I1Ii1i111I . json ) :
    if ( lisp_is_json_telemetry ( I1Ii1i111I . json . json_string ) ) :
     iiI11111i = I1Ii1i111I . json . json_string
     iiI11111i = lisp_encode_telemetry ( iiI11111i , ii = itr_in_ts )
     I1Ii1i111I . json . json_string = iiI11111i
     if 96 - 96: oO0o
     if 44 - 44: OoooooooOO / iII111i * Oo0Ooo % OoOoOO00 . oO0o
     if 97 - 97: iIii1I11I1II1 / ooOoO0o
     if 16 - 16: Oo0Ooo % IiII
     if 48 - 48: I1IiiI . I1Ii111 . o0oOOo0O0Ooo
     if 72 - 72: Ii1I * OoO0O00 / OoO0O00
     if 39 - 39: oO0o
     if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
     if 57 - 57: oO0o + O0 - OoOoOO00
     if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
   if ( iIII1111IiIII . rloc_probe and IiiI1 . probe_bit ) :
    if ( I1Ii1i111I . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( I1Ii1i111I , source , I1I ,
 iIII1111IiIII , ttl , ii111IiiIii )
     if 93 - 93: o0oOOo0O0Ooo + i1IIi
    if ( I1Ii1i111I . rloc . is_multicast_address ( ) ) : ii111IiiIii = I1Ii1i111I
    if 24 - 24: i1IIi
    if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
    if 99 - 99: Oo0Ooo
    if 38 - 38: I1ii11iIi11i - I1IiiI
    if 50 - 50: iII111i % OoO0O00 - oO0o + Oo0Ooo . O0 . iII111i
   OOOo0O00OO00O . append ( I1Ii1i111I )
   if 42 - 42: iII111i + I1ii11iIi11i
   if 44 - 44: I1ii11iIi11i % IiII
   if 1 - 1: Oo0Ooo + IiII - I1Ii111 / I1Ii111
   if 25 - 25: OoOoOO00
   if ( lisp_data_plane_security and I1Ii1i111I . rloc_recent_rekey ( ) ) :
    iII1II1I = I1Ii1i111I
    if 52 - 52: OOooOOo + IiII
    if 73 - 73: OoooooooOO - I1Ii111 % iII111i / OOooOOo . o0oOOo0O0Ooo - IiII
    if 69 - 69: Ii1I . iIii1I11I1II1 / Oo0Ooo * Oo0Ooo % IiII
    if 5 - 5: OOooOOo - I1Ii111 + IiII
    if 82 - 82: OOooOOo
    if 26 - 26: ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
    if 26 - 26: I1IiiI - OOooOOo
    if 34 - 34: I1Ii111 % I1IiiI . OoOoOO00 / iII111i + ooOoO0o . i11iIiiIii
    if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
    if 50 - 50: OoooooooOO * II111iiii
    if 7 - 7: ooOoO0o / I11i * iII111i
  if ( iIII1111IiIII . rloc_probe == False and lisp_nat_traversal ) :
   iIo0 = [ ]
   ii1ii1i1i1I = [ ]
   for I1Ii1i111I in OOOo0O00OO00O :
    if 28 - 28: i1IIi / iIii1I11I1II1 % I1IiiI % OoOoOO00
    if 43 - 43: oO0o + I11i / IiII / OoOoOO00 + oO0o / Oo0Ooo
    if 28 - 28: IiII . o0oOOo0O0Ooo % II111iiii - I1ii11iIi11i
    if 2 - 2: OOooOOo * i11iIiiIii . I1ii11iIi11i
    if 56 - 56: o0oOOo0O0Ooo / I1ii11iIi11i
    if ( I1Ii1i111I . rloc . is_private_address ( ) ) :
     I1Ii1i111I . priority = 1
     I1Ii1i111I . state = LISP_RLOC_UNREACH_STATE
     iIo0 . append ( I1Ii1i111I )
     ii1ii1i1i1I . append ( I1Ii1i111I . rloc . print_address_no_iid ( ) )
     continue
     if 25 - 25: iIii1I11I1II1 / OoO0O00 - o0oOOo0O0Ooo
     if 97 - 97: ooOoO0o % OoooooooOO * o0oOOo0O0Ooo
     if 8 - 8: I1ii11iIi11i + Oo0Ooo - iII111i
     if 53 - 53: ooOoO0o / IiII
     if 36 - 36: iIii1I11I1II1
     if 78 - 78: II111iiii * I11i
    if ( I1Ii1i111I . priority == 254 and lisp_i_am_rtr == False ) :
     iIo0 . append ( I1Ii1i111I )
     ii1ii1i1i1I . append ( I1Ii1i111I . rloc . print_address_no_iid ( ) )
     if 47 - 47: Ii1I
    if ( I1Ii1i111I . priority != 254 and lisp_i_am_rtr ) :
     iIo0 . append ( I1Ii1i111I )
     ii1ii1i1i1I . append ( I1Ii1i111I . rloc . print_address_no_iid ( ) )
     if 42 - 42: I11i . oO0o - I1IiiI / OoO0O00
     if 75 - 75: I1IiiI / OoOoOO00 . I11i * iIii1I11I1II1
     if 53 - 53: iIii1I11I1II1
   if ( ii1ii1i1i1I != [ ] ) :
    OOOo0O00OO00O = iIo0
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( ii1ii1i1i1I ) )
    if 8 - 8: O0 - O0 - II111iiii
    if 77 - 77: i1IIi - ooOoO0o + O0 . OoO0O00 * I1Ii111 - I11i
    if 64 - 64: i1IIi + OoooooooOO + OOooOOo / ooOoO0o % I1IiiI . OoooooooOO
    if 96 - 96: II111iiii - OoOoOO00 + oO0o
    if 80 - 80: oO0o / OoOoOO00 - I11i / oO0o - iII111i - OoooooooOO
    if 57 - 57: o0oOOo0O0Ooo
    if 37 - 37: iII111i * o0oOOo0O0Ooo
  iIo0 = [ ]
  for I1Ii1i111I in OOOo0O00OO00O :
   if ( I1Ii1i111I . json != None ) : continue
   iIo0 . append ( I1Ii1i111I )
   if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
  if ( iIo0 != [ ] ) :
   O0oo0oOo = len ( OOOo0O00OO00O ) - len ( iIo0 )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( O0oo0oOo ) )
   if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
   OOOo0O00OO00O = iIo0
   if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
   if 34 - 34: O0 * oO0o
   if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
   if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
   if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
   if 88 - 88: i11iIiiIii
   if 13 - 13: I1IiiI
   if 52 - 52: Ii1I * oO0o / I1Ii111 . IiII
  if ( iIII1111IiIII . rloc_probe and o0ooo0oOO0o != None ) : OOOo0O00OO00O = o0ooo0oOO0o . rloc_set
  if 84 - 84: OoooooooOO - oO0o - I1Ii111
  if 69 - 69: OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
  if 20 - 20: IiII
  if 17 - 17: o0oOOo0O0Ooo % iIii1I11I1II1
  if 66 - 66: OoooooooOO + IiII . II111iiii
  oo0Oo0O00OO = o0oOoO0O
  if ( o0ooo0oOO0o and OOOo0O00OO00O != o0ooo0oOO0o . rloc_set ) :
   o0ooo0oOO0o . delete_rlocs_from_rloc_probe_list ( )
   oo0Oo0O00OO = True
   if 67 - 67: I1ii11iIi11i . iII111i * OoO0O00 % OOooOOo
   if 85 - 85: OOooOOo * I1IiiI + oO0o
   if 6 - 6: OoooooooOO * I1Ii111 . I1Ii111 % o0oOOo0O0Ooo . OoOoOO00
   if 100 - 100: II111iiii - Oo0Ooo % OoO0O00
   if 92 - 92: I11i % Ii1I % I11i * O0
  iioO0OOO = o0ooo0oOO0o . uptime if ( o0ooo0oOO0o ) else None
  if ( o0ooo0oOO0o == None ) :
   o0ooo0oOO0o = lisp_mapping ( IiIo0oo0O . eid , IiIo0oo0O . group , OOOo0O00OO00O )
   o0ooo0oOO0o . mapping_source = source
   if 77 - 77: OoOoOO00 + iIii1I11I1II1 / OoOoOO00 - Ii1I / OoO0O00 + I1IiiI
   if 3 - 3: i1IIi % Ii1I . OoO0O00 * iIii1I11I1II1 % I11i
   if 64 - 64: iII111i * I1IiiI * IiII * iII111i / i1IIi . IiII
   if 30 - 30: OoOoOO00 . oO0o - iIii1I11I1II1 % i1IIi
   if 94 - 94: Oo0Ooo + iIii1I11I1II1 . OoO0O00 * oO0o . i1IIi
   if 85 - 85: O0 / OoOoOO00 . iII111i
   if ( lisp_i_am_rtr and IiIo0oo0O . group . is_null ( ) == False ) :
    o0ooo0oOO0o . map_cache_ttl = LISP_MCAST_TTL
   else :
    o0ooo0oOO0o . map_cache_ttl = IiIo0oo0O . store_ttl ( )
    if 64 - 64: OoO0O00 + I1ii11iIi11i / OoO0O00 * I1Ii111 . Oo0Ooo
   o0ooo0oOO0o . action = IiIo0oo0O . action
   o0ooo0oOO0o . add_cache ( oo0Oo0O00OO )
   if 5 - 5: iII111i - iIii1I11I1II1 * IiII
   if 52 - 52: OOooOOo
  IIIIIiiIII = "Add"
  if ( iioO0OOO ) :
   o0ooo0oOO0o . uptime = iioO0OOO
   o0ooo0oOO0o . refresh_time = lisp_get_timestamp ( )
   IIIIIiiIII = "Replace"
   if 40 - 40: OoO0O00 * o0oOOo0O0Ooo / i1IIi * I1Ii111 * I1ii11iIi11i
   if 45 - 45: iII111i / Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
  lprint ( "{} {} map-cache with {} RLOCs" . format ( IIIIIiiIII ,
 green ( o0ooo0oOO0o . print_eid_tuple ( ) , False ) , len ( OOOo0O00OO00O ) ) )
  if 66 - 66: I1IiiI
  if 45 - 45: II111iiii * I1Ii111 - II111iiii / I1IiiI % oO0o
  if 83 - 83: oO0o % OoO0O00 + I1ii11iIi11i / OoooooooOO % iII111i
  if 22 - 22: I1Ii111
  if 41 - 41: O0 * i1IIi
  if ( lisp_ipc_dp_socket and iII1II1I != None ) :
   lisp_write_ipc_keys ( iII1II1I )
   if 89 - 89: iIii1I11I1II1 . I11i % I1ii11iIi11i + II111iiii . OoO0O00
   if 5 - 5: I1ii11iIi11i / I1IiiI . iII111i
   if 7 - 7: Ii1I
   if 62 - 62: I1ii11iIi11i + IiII . O0 - OoooooooOO * o0oOOo0O0Ooo % O0
   if 63 - 63: OOooOOo + iII111i - IiII - I1IiiI % IiII . OoO0O00
   if 73 - 73: OoOoOO00
   if 47 - 47: oO0o
  if ( o0oOoO0O ) :
   iIIi11Ii1iII = bold ( "RLOC-probe" , False )
   for I1Ii1i111I in o0ooo0oOO0o . best_rloc_set :
    O0O0 = red ( I1Ii1i111I . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( iIIi11Ii1iII , O0O0 ) )
    lisp_send_map_request ( lisp_sockets , 0 , o0ooo0oOO0o . eid , o0ooo0oOO0o . group , I1Ii1i111I )
    if 72 - 72: I11i % ooOoO0o / O0 . O0
    if 7 - 7: O0 * I1ii11iIi11i + Ii1I + oO0o % oO0o
    if 47 - 47: oO0o * I1ii11iIi11i
 return
 if 85 - 85: OoooooooOO * I1ii11iIi11i + i11iIiiIii . iII111i * II111iiii / oO0o
 if 14 - 14: I1Ii111
 if 49 - 49: I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
 if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
 if 28 - 28: ooOoO0o
 if 88 - 88: oO0o
 if 77 - 77: ooOoO0o + I1Ii111 . OoOoOO00
 if 2 - 2: i1IIi - IiII + iIii1I11I1II1 % i1IIi * II111iiii
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 26 - 26: I11i
 packet = map_register . zero_auth ( packet )
 oOOo0O0Oo = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 57 - 57: I1ii11iIi11i + I1Ii111 + i11iIiiIii . i1IIi / i11iIiiIii
 if 43 - 43: Ii1I % I11i
 if 5 - 5: OoooooooOO % i11iIiiIii * o0oOOo0O0Ooo * OoooooooOO - o0oOOo0O0Ooo % I11i
 if 58 - 58: i11iIiiIii % Ii1I + Oo0Ooo - OoOoOO00 - i11iIiiIii / O0
 map_register . auth_data = oOOo0O0Oo
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 36 - 36: OOooOOo
 if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
 if 95 - 95: i1IIi * O0 / II111iiii * OoOoOO00 * I1IiiI
 if 38 - 38: OOooOOo - OoOoOO00 / OoO0O00 / o0oOOo0O0Ooo - i11iIiiIii
 if 4 - 4: I1IiiI * o0oOOo0O0Ooo - I11i - OoooooooOO . OoooooooOO
 if 79 - 79: oO0o - iII111i
 if 34 - 34: OoooooooOO + Ii1I - iII111i + OoooooooOO / I1IiiI
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 39 - 39: o0oOOo0O0Ooo . i1IIi * OoO0O00 / II111iiii / I1ii11iIi11i * OOooOOo
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  iiO0 = hashlib . sha1
  if 58 - 58: I1ii11iIi11i / i11iIiiIii + iII111i + I11i / oO0o
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  iiO0 = hashlib . sha256
  if 8 - 8: I1ii11iIi11i
  if 100 - 100: OoooooooOO / I11i - Ii1I
 if ( do_hex ) :
  oOOo0O0Oo = hmac . new ( password . encode ( ) , packet , iiO0 ) . hexdigest ( )
 else :
  oOOo0O0Oo = hmac . new ( password . encode ( ) , packet , iiO0 ) . digest ( )
  if 11 - 11: OoO0O00
 return ( oOOo0O0Oo )
 if 20 - 20: Oo0Ooo
 if 34 - 34: I1Ii111 % i11iIiiIii / oO0o - i1IIi . o0oOOo0O0Ooo / oO0o
 if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
 if 1 - 1: I1ii11iIi11i
 if 18 - 18: i11iIiiIii % OoO0O00 % OOooOOo . OOooOOo * Ii1I / II111iiii
 if 81 - 81: iII111i % IiII / I11i
 if 50 - 50: IiII + i1IIi % I1Ii111
 if 72 - 72: I1Ii111
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 6 - 6: II111iiii - i1IIi
 oOOo0O0Oo = lisp_hash_me ( packet , alg_id , password , True )
 OO0O0ooo = ( oOOo0O0Oo == auth_data )
 if 76 - 76: iII111i
 if 85 - 85: I1ii11iIi11i + OOooOOo % i1IIi
 if 13 - 13: OOooOOo + i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
 if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
 if ( OO0O0ooo == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( oOOo0O0Oo , auth_data ) )
  if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
  if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
 return ( OO0O0ooo )
 if 8 - 8: OoooooooOO * OOooOOo * iII111i - iII111i
 if 32 - 32: I1Ii111
 if 28 - 28: I11i . i11iIiiIii % iIii1I11I1II1 + OoOoOO00
 if 4 - 4: OOooOOo + I1ii11iIi11i - iII111i + OOooOOo / IiII
 if 23 - 23: iIii1I11I1II1 + OoooooooOO + ooOoO0o . iII111i . Oo0Ooo - iIii1I11I1II1
 if 25 - 25: O0 + I1IiiI % OOooOOo / Oo0Ooo . IiII / I1Ii111
 if 84 - 84: ooOoO0o . O0 + I1IiiI * OoO0O00 - I1IiiI
def lisp_retransmit_map_notify ( map_notify ) :
 I1i1iiIi = map_notify . etr
 I1I = map_notify . etr_port
 if 24 - 24: Ii1I
 if 23 - 23: Oo0Ooo * i1IIi / I1IiiI . I11i - I1ii11iIi11i . iIii1I11I1II1
 if 15 - 15: O0 + o0oOOo0O0Ooo / oO0o
 if 27 - 27: Ii1I * II111iiii / oO0o
 if 99 - 99: I11i + ooOoO0o % I11i + O0 - Ii1I - I1Ii111
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( I1i1iiIi . print_address ( ) , False ) ) )
  if 3 - 3: Oo0Ooo . I1IiiI
  if 61 - 61: OoO0O00 - I1ii11iIi11i . Ii1I * i11iIiiIii
  Ooo00o000o = map_notify . nonce_key
  if ( Ooo00o000o in lisp_map_notify_queue ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( Ooo00o000o ) )
   if 97 - 97: ooOoO0o
   try :
    lisp_map_notify_queue . pop ( Ooo00o000o )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 58 - 58: iII111i
    if 47 - 47: II111iiii % Oo0Ooo . iIii1I11I1II1 . oO0o
  return
  if 52 - 52: I11i * I1IiiI % I11i - iII111i - Ii1I - OoooooooOO
  if 15 - 15: iII111i
 OO0ooo000 = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 95 - 95: i11iIiiIii . Ii1I / II111iiii + II111iiii + Ii1I / I11i
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # iIii1I11I1II1 % I1Ii111 * I1IiiI * II111iiii . I1ii11iIi11i
 red ( I1i1iiIi . print_address ( ) , False ) , map_notify . retry_count ) )
 if 36 - 36: i11iIiiIii * IiII - I11i * OoOoOO00 + OoO0O00 * I1Ii111
 lisp_send_map_notify ( OO0ooo000 , map_notify . packet , I1i1iiIi , I1I )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 14 - 14: II111iiii . O0 + ooOoO0o
 if 62 - 62: II111iiii * o0oOOo0O0Ooo . OoO0O00 / II111iiii
 if 5 - 5: OoO0O00 + O0 . OoooooooOO + I1IiiI + i1IIi * OOooOOo
 if 19 - 19: OoooooooOO + i11iIiiIii / II111iiii - Oo0Ooo . OOooOOo
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 10 - 10: oO0o * Oo0Ooo
 if 55 - 55: OoO0O00 - i1IIi - I11i * oO0o
 if 91 - 91: I1Ii111
 if 77 - 77: I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + Ii1I % II111iiii * II111iiii
 if 41 - 41: II111iiii + Oo0Ooo - IiII / I1Ii111 - OOooOOo . oO0o
 if 100 - 100: ooOoO0o / I1ii11iIi11i * OoOoOO00 . I1ii11iIi11i . o0oOOo0O0Ooo * iIii1I11I1II1
 if 15 - 15: iII111i + o0oOOo0O0Ooo / IiII
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 33 - 33: OoooooooOO . IiII * o0oOOo0O0Ooo
 if 41 - 41: Ii1I . iII111i . o0oOOo0O0Ooo % OoooooooOO % IiII
 if 81 - 81: IiII * i11iIiiIii + i1IIi + OOooOOo . i1IIi
 if 6 - 6: i11iIiiIii - oO0o % OoO0O00 + iIii1I11I1II1
 eid_record . rloc_count = len ( parent . registered_rlocs )
 ooooOoOO0o0o = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 94 - 94: I1ii11iIi11i * ooOoO0o
 if 12 - 12: Ii1I - OoOoOO00
 if 56 - 56: OOooOOo . oO0o
 if 75 - 75: oO0o + OoOoOO00 - OoooooooOO
 for I1i1o0 in parent . registered_rlocs :
  IiiI1 = lisp_rloc_record ( )
  IiiI1 . store_rloc_entry ( I1i1o0 )
  IiiI1 . local_bit = True
  IiiI1 . probe_bit = False
  IiiI1 . reach_bit = True
  ooooOoOO0o0o += IiiI1 . encode ( )
  IiiI1 . print_record ( "  " )
  del ( IiiI1 )
  if 64 - 64: OOooOOo
  if 5 - 5: OOooOOo % I1Ii111 * II111iiii
  if 69 - 69: OoO0O00 . o0oOOo0O0Ooo
  if 86 - 86: I1ii11iIi11i
  if 51 - 51: O0 % OoO0O00 - I1Ii111
 for I1i1o0 in parent . registered_rlocs :
  I1i1iiIi = I1i1o0 . rloc
  OOo0oo0O = lisp_map_notify ( lisp_sockets )
  OOo0oo0O . record_count = 1
  i11iII1 = map_register . key_id
  OOo0oo0O . key_id = i11iII1
  OOo0oo0O . alg_id = map_register . alg_id
  OOo0oo0O . auth_len = map_register . auth_len
  OOo0oo0O . nonce = map_register . nonce
  OOo0oo0O . nonce_key = lisp_hex_string ( OOo0oo0O . nonce )
  OOo0oo0O . etr . copy_address ( I1i1iiIi )
  OOo0oo0O . etr_port = map_register . sport
  OOo0oo0O . site = parent . site
  Oo00oo = OOo0oo0O . encode ( ooooOoOO0o0o , parent . site . auth_key [ i11iII1 ] )
  OOo0oo0O . print_notify ( )
  if 73 - 73: i11iIiiIii / i1IIi
  if 8 - 8: O0 / OOooOOo + iII111i % iIii1I11I1II1 % iIii1I11I1II1 . ooOoO0o
  if 47 - 47: OoO0O00 / o0oOOo0O0Ooo / Ii1I * I1IiiI % ooOoO0o / I1Ii111
  if 80 - 80: I1Ii111 / O0 * O0
  Ooo00o000o = OOo0oo0O . nonce_key
  if ( Ooo00o000o in lisp_map_notify_queue ) :
   IIiIiII1i = lisp_map_notify_queue [ Ooo00o000o ]
   IIiIiII1i . retransmit_timer . cancel ( )
   del ( IIiIiII1i )
   if 55 - 55: II111iiii
  lisp_map_notify_queue [ Ooo00o000o ] = OOo0oo0O
  if 67 - 67: IiII % I1Ii111 + i11iIiiIii
  if 53 - 53: OOooOOo
  if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
  if 21 - 21: I1Ii111 . i1IIi - iII111i % I1ii11iIi11i . OOooOOo
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( I1i1iiIi . print_address ( ) , False ) ) )
  if 52 - 52: Ii1I * I1ii11iIi11i
  lisp_send ( lisp_sockets , I1i1iiIi , LISP_CTRL_PORT , Oo00oo )
  if 21 - 21: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo * II111iiii % iIii1I11I1II1
  parent . site . map_notifies_sent += 1
  if 9 - 9: I1ii11iIi11i + I11i
  if 20 - 20: iII111i + i1IIi / oO0o % OoooooooOO * OoOoOO00
  if 70 - 70: Oo0Ooo - OOooOOo * OOooOOo / o0oOOo0O0Ooo
  if 4 - 4: OoOoOO00 / OoO0O00
  OOo0oo0O . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ OOo0oo0O ] )
  OOo0oo0O . retransmit_timer . start ( )
  if 66 - 66: I1Ii111 / OoOoOO00
 return
 if 53 - 53: OoOoOO00 . i11iIiiIii - OoooooooOO
 if 92 - 92: O0 - i11iIiiIii + OoO0O00 - OoooooooOO - o0oOOo0O0Ooo
 if 25 - 25: oO0o / oO0o / Ii1I / O0
 if 56 - 56: ooOoO0o
 if 19 - 19: O0 * I1IiiI + I1ii11iIi11i
 if 25 - 25: I11i - ooOoO0o / OoO0O00 / iII111i - OoO0O00
 if 86 - 86: OoO0O00
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 89 - 89: OoooooooOO % iII111i * I1ii11iIi11i + I1ii11iIi11i . Oo0Ooo
 Ooo00o000o = lisp_hex_string ( nonce ) + source . print_address ( )
 if 4 - 4: I11i
 if 8 - 8: IiII
 if 1 - 1: ooOoO0o . IiII
 if 4 - 4: iIii1I11I1II1 % I1IiiI - OoooooooOO / iII111i
 if 55 - 55: O0 + iII111i * OoOoOO00 . i11iIiiIii * Ii1I + oO0o
 if 66 - 66: i1IIi . I1ii11iIi11i
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( Ooo00o000o in lisp_map_notify_queue ) :
  OOo0oo0O = lisp_map_notify_queue [ Ooo00o000o ]
  I111 = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( OOo0oo0O . nonce ) , I111 ) )
  if 86 - 86: Oo0Ooo
  return
  if 48 - 48: OoO0O00
  if 55 - 55: OoO0O00 * i1IIi * I11i / iII111i
 OOo0oo0O = lisp_map_notify ( lisp_sockets )
 OOo0oo0O . record_count = record_count
 key_id = key_id
 OOo0oo0O . key_id = key_id
 OOo0oo0O . alg_id = alg_id
 OOo0oo0O . auth_len = auth_len
 OOo0oo0O . nonce = nonce
 OOo0oo0O . nonce_key = lisp_hex_string ( nonce )
 OOo0oo0O . etr . copy_address ( source )
 OOo0oo0O . etr_port = port
 OOo0oo0O . site = site
 OOo0oo0O . eid_list = eid_list
 if 42 - 42: IiII
 if 28 - 28: OoOoOO00 + OoOoOO00
 if 53 - 53: II111iiii % i1IIi + ooOoO0o . I1Ii111
 if 52 - 52: I1IiiI + I1Ii111 * oO0o / i11iIiiIii * iIii1I11I1II1
 if ( map_register_ack == False ) :
  Ooo00o000o = OOo0oo0O . nonce_key
  lisp_map_notify_queue [ Ooo00o000o ] = OOo0oo0O
  if 27 - 27: Oo0Ooo
  if 85 - 85: iIii1I11I1II1 . o0oOOo0O0Ooo + oO0o
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 79 - 79: O0 - iIii1I11I1II1 + i1IIi . I11i
  if 21 - 21: II111iiii
  if 23 - 23: I11i * i1IIi . oO0o / IiII + o0oOOo0O0Ooo
  if 1 - 1: IiII / OoO0O00 . oO0o * I1Ii111 - i11iIiiIii
  if 50 - 50: oO0o - O0 / I1IiiI . OoOoOO00 . Oo0Ooo
 Oo00oo = OOo0oo0O . encode ( eid_records , site . auth_key [ key_id ] )
 OOo0oo0O . print_notify ( )
 if 30 - 30: IiII . OoO0O00 + Oo0Ooo
 if ( map_register_ack == False ) :
  IiIo0oo0O = lisp_eid_record ( )
  IiIo0oo0O . decode ( eid_records )
  IiIo0oo0O . print_record ( "  " , False )
  if 48 - 48: iIii1I11I1II1 / i11iIiiIii . OoOoOO00 * I11i
  if 1 - 1: IiII . OoOoOO00 * o0oOOo0O0Ooo
  if 63 - 63: O0 / Ii1I + I1Ii111 % OoO0O00 % OOooOOo * O0
  if 35 - 35: OoO0O00 + OoooooooOO % Oo0Ooo / I11i - O0 . i1IIi
  if 76 - 76: IiII % I1IiiI * Ii1I / Ii1I / OoooooooOO + Ii1I
 lisp_send_map_notify ( lisp_sockets , Oo00oo , OOo0oo0O . etr , port )
 site . map_notifies_sent += 1
 if 19 - 19: OoooooooOO
 if ( map_register_ack ) : return
 if 88 - 88: I1IiiI % ooOoO0o % Oo0Ooo - O0
 if 71 - 71: OOooOOo % Ii1I - i11iIiiIii - oO0o . ooOoO0o / I1Ii111
 if 53 - 53: iII111i . Oo0Ooo
 if 91 - 91: oO0o * OoooooooOO * oO0o % oO0o * II111iiii % I1Ii111
 if 8 - 8: Ii1I
 if 28 - 28: iII111i / I1ii11iIi11i - OoOoOO00 * Oo0Ooo + Ii1I * OoOoOO00
 OOo0oo0O . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ OOo0oo0O ] )
 OOo0oo0O . retransmit_timer . start ( )
 return
 if 94 - 94: oO0o
 if 95 - 95: ooOoO0o * O0 + OOooOOo
 if 11 - 11: i1IIi / OoOoOO00 + OoOoOO00 + I1ii11iIi11i + OOooOOo
 if 21 - 21: ooOoO0o
 if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
 if 81 - 81: oO0o
 if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
 if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
 if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
 if 33 - 33: I11i
 if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
 Oo00oo = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
 if 32 - 32: oO0o
 if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
 I1i1iiIi = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( I1i1iiIi . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , I1i1iiIi , LISP_CTRL_PORT , Oo00oo )
 return
 if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
 if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
 if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
 if 94 - 94: Ii1I
 if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
 if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
 if 34 - 34: iIii1I11I1II1
 if 47 - 47: OOooOOo * iII111i
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 71 - 71: IiII - OoooooooOO * i11iIiiIii . OoooooooOO % i1IIi . Oo0Ooo
 OOo0oo0O = lisp_map_notify ( lisp_sockets )
 OOo0oo0O . record_count = 1
 OOo0oo0O . nonce = lisp_get_control_nonce ( )
 OOo0oo0O . nonce_key = lisp_hex_string ( OOo0oo0O . nonce )
 OOo0oo0O . etr . copy_address ( xtr )
 OOo0oo0O . etr_port = LISP_CTRL_PORT
 OOo0oo0O . eid_list = eid_list
 Ooo00o000o = OOo0oo0O . nonce_key
 if 3 - 3: OoO0O00 + i11iIiiIii + oO0o * IiII
 if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
 if 70 - 70: OoO0O00
 if 42 - 42: OoooooooOO - I1Ii111 + I1ii11iIi11i * iII111i * iII111i / OoO0O00
 if 85 - 85: O0 . II111iiii
 if 80 - 80: O0 * I11i * I1Ii111
 lisp_remove_eid_from_map_notify_queue ( OOo0oo0O . eid_list )
 if ( Ooo00o000o in lisp_map_notify_queue ) :
  OOo0oo0O = lisp_map_notify_queue [ Ooo00o000o ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( OOo0oo0O . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 89 - 89: Ii1I * OoO0O00 . i1IIi . O0 - IiII - OoOoOO00
  return
  if 25 - 25: iII111i + i1IIi
  if 64 - 64: IiII % I11i / iIii1I11I1II1
  if 66 - 66: Ii1I
  if 55 - 55: OOooOOo + I1IiiI + IiII . Ii1I * oO0o
  if 71 - 71: IiII - iII111i % I1IiiI * iII111i
 lisp_map_notify_queue [ Ooo00o000o ] = OOo0oo0O
 if 27 - 27: ooOoO0o - OoO0O00
 if 83 - 83: iII111i * OoOoOO00 - O0 * Ii1I
 if 79 - 79: I11i / iII111i % Ii1I / OoOoOO00 % O0 / IiII
 if 32 - 32: IiII * II111iiii . Ii1I
 o0ooO = site_eid . rtrs_in_rloc_set ( )
 if ( o0ooO ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : o0ooO = False
  if 67 - 67: oO0o . I1IiiI % i1IIi - OoO0O00
  if 33 - 33: I1IiiI / I1IiiI / I1ii11iIi11i * IiII / Ii1I
  if 55 - 55: i11iIiiIii / OoooooooOO - Ii1I * Oo0Ooo . I1Ii111
  if 96 - 96: IiII / OoooooooOO + i11iIiiIii . Ii1I
  if 64 - 64: OoooooooOO / IiII - IiII . Ii1I % Oo0Ooo
 IiIo0oo0O = lisp_eid_record ( )
 IiIo0oo0O . record_ttl = 1440
 IiIo0oo0O . eid . copy_address ( site_eid . eid )
 IiIo0oo0O . group . copy_address ( site_eid . group )
 IiIo0oo0O . rloc_count = 0
 for OO0oooo in site_eid . registered_rlocs :
  if ( o0ooO ^ OO0oooo . is_rtr ( ) ) : continue
  IiIo0oo0O . rloc_count += 1
  if 35 - 35: iII111i * I1IiiI * Oo0Ooo + I1Ii111 + i1IIi - ooOoO0o
 Oo00oo = IiIo0oo0O . encode ( )
 if 23 - 23: II111iiii - O0
 if 58 - 58: o0oOOo0O0Ooo * OoO0O00 + OoO0O00
 if 93 - 93: IiII - I1ii11iIi11i % I11i + i1IIi % OoO0O00
 if 20 - 20: oO0o . Oo0Ooo + IiII - II111iiii % Ii1I
 OOo0oo0O . print_notify ( )
 IiIo0oo0O . print_record ( "  " , False )
 if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
 if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
 if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
 if 59 - 59: OoOoOO00
 for OO0oooo in site_eid . registered_rlocs :
  if ( o0ooO ^ OO0oooo . is_rtr ( ) ) : continue
  IiiI1 = lisp_rloc_record ( )
  IiiI1 . store_rloc_entry ( OO0oooo )
  IiiI1 . local_bit = True
  IiiI1 . probe_bit = False
  IiiI1 . reach_bit = True
  Oo00oo += IiiI1 . encode ( )
  IiiI1 . print_record ( "    " )
  if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
  if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
  if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
  if 62 - 62: Oo0Ooo . II111iiii % OoO0O00 . Ii1I * OOooOOo + II111iiii
  if 7 - 7: OOooOOo
 Oo00oo = OOo0oo0O . encode ( Oo00oo , "" )
 if ( Oo00oo == None ) : return
 if 22 - 22: Oo0Ooo + ooOoO0o
 if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
 if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
 if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
 lisp_send_map_notify ( lisp_sockets , Oo00oo , xtr , LISP_CTRL_PORT )
 if 26 - 26: Oo0Ooo . Ii1I
 if 7 - 7: OoOoOO00 - o0oOOo0O0Ooo + oO0o
 if 8 - 8: iIii1I11I1II1
 if 6 - 6: oO0o
 OOo0oo0O . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ OOo0oo0O ] )
 OOo0oo0O . retransmit_timer . start ( )
 return
 if 51 - 51: I1Ii111 - o0oOOo0O0Ooo
 if 5 - 5: O0
 if 7 - 7: OoOoOO00 + OoO0O00 * I1IiiI
 if 63 - 63: I1ii11iIi11i + iII111i * i1IIi
 if 63 - 63: I1ii11iIi11i / II111iiii % oO0o + ooOoO0o . Ii1I % I11i
 if 59 - 59: I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
 if 5 - 5: I1IiiI
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 ii1i = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 79 - 79: OoooooooOO . OoOoOO00 * OoO0O00 + I11i / iII111i - Ii1I
 for IiiiIi in rle_list :
  iIi1i1ii = lisp_site_eid_lookup ( IiiiIi [ 0 ] , IiiiIi [ 1 ] , True )
  if ( iIi1i1ii == None ) : continue
  if 81 - 81: iII111i . Oo0Ooo / i1IIi / i11iIiiIii
  if 77 - 77: I1Ii111
  if 92 - 92: iII111i * i11iIiiIii * o0oOOo0O0Ooo * OoO0O00
  if 70 - 70: Ii1I
  if 51 - 51: i1IIi % Oo0Ooo
  if 32 - 32: OoOoOO00 + iIii1I11I1II1 . OoO0O00 . I1ii11iIi11i . IiII
  if 97 - 97: ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + iII111i + OoOoOO00
  iII11iI = iIi1i1ii . registered_rlocs
  if ( len ( iII11iI ) == 0 ) :
   IIIiI1IiIIII = { }
   for Oo0OO0o00OO in list ( iIi1i1ii . individual_registrations . values ( ) ) :
    for OO0oooo in Oo0OO0o00OO . registered_rlocs :
     if ( OO0oooo . is_rtr ( ) == False ) : continue
     IIIiI1IiIIII [ OO0oooo . rloc . print_address ( ) ] = OO0oooo
     if 74 - 74: II111iiii
     if 73 - 73: oO0o + OoO0O00 . O0 - Ii1I - I1Ii111 - I11i
   iII11iI = list ( IIIiI1IiIIII . values ( ) )
   if 64 - 64: OOooOOo / OoOoOO00
   if 50 - 50: O0 - oO0o . oO0o
   if 98 - 98: IiII % Ii1I / Ii1I
   if 10 - 10: Ii1I
   if 69 - 69: I1Ii111 * OoooooooOO . o0oOOo0O0Ooo % I1IiiI
   if 70 - 70: iII111i . i11iIiiIii * I1Ii111
  oOoIiIi = [ ]
  OO00oo0 = False
  if ( iIi1i1ii . eid . address == 0 and iIi1i1ii . eid . mask_len == 0 ) :
   Ii1IiiI = [ ]
   iiI1Ii1II = [ ]
   if ( len ( iII11iI ) != 0 and iII11iI [ 0 ] . rle != None ) :
    iiI1Ii1II = iII11iI [ 0 ] . rle . rle_nodes
    if 34 - 34: I11i / I1IiiI . II111iiii
   for iI11i1ii11i11 in iiI1Ii1II :
    oOoIiIi . append ( iI11i1ii11i11 . address )
    Ii1IiiI . append ( iI11i1ii11i11 . address . print_address_no_iid ( ) )
    if 79 - 79: I1Ii111 + IiII / OoooooooOO
   lprint ( "Notify existing RLE-nodes {}" . format ( Ii1IiiI ) )
  else :
   if 53 - 53: Ii1I
   if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
   if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
   if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
   if 33 - 33: oO0o . oO0o / IiII + II111iiii
   for OO0oooo in iII11iI :
    if ( OO0oooo . is_rtr ( ) ) : oOoIiIi . append ( OO0oooo . rloc )
    if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
    if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
    if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
    if 25 - 25: OoO0O00
    if 83 - 83: II111iiii . iIii1I11I1II1
   OO00oo0 = ( len ( oOoIiIi ) != 0 )
   if ( OO00oo0 == False ) :
    oOoooooOooO = lisp_site_eid_lookup ( IiiiIi [ 0 ] , ii1i , False )
    if ( oOoooooOooO == None ) : continue
    if 77 - 77: O0 . OoOoOO00 % oO0o / OOooOOo
    for OO0oooo in oOoooooOooO . registered_rlocs :
     if ( OO0oooo . rloc . is_null ( ) ) : continue
     oOoIiIi . append ( OO0oooo . rloc )
     if 8 - 8: iII111i - i1IIi
     if 81 - 81: ooOoO0o / OOooOOo % OoOoOO00 . iIii1I11I1II1
     if 45 - 45: I1IiiI . ooOoO0o - OoooooooOO
     if 84 - 84: I1ii11iIi11i
     if 69 - 69: I1Ii111 + II111iiii
     if 92 - 92: OoooooooOO
   if ( len ( oOoIiIi ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( iIi1i1ii . print_eid_tuple ( ) , False ) ) )
    if 80 - 80: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . oO0o % I1IiiI % I11i
    continue
    if 4 - 4: OoO0O00 / iII111i / I1ii11iIi11i - o0oOOo0O0Ooo * I1Ii111
    if 24 - 24: OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - o0oOOo0O0Ooo . I1ii11iIi11i
    if 2 - 2: I1IiiI . o0oOOo0O0Ooo / Oo0Ooo - OoOoOO00 - OoooooooOO
    if 73 - 73: I1Ii111 . i11iIiiIii * ooOoO0o . IiII - I11i + I1Ii111
    if 21 - 21: I1Ii111 + iIii1I11I1II1 + I1IiiI / O0 * I1ii11iIi11i
    if 57 - 57: OOooOOo * I11i . oO0o
  for I1i1o0 in oOoIiIi :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if OO00oo0 else "x" , red ( I1i1o0 . print_address_no_iid ( ) , False ) ,
   # iII111i
 green ( iIi1i1ii . print_eid_tuple ( ) , False ) ) )
   if 60 - 60: OOooOOo * I1IiiI + i1IIi % I11i - I1ii11iIi11i + Ii1I
   OooOoo0oo = [ iIi1i1ii . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , iIi1i1ii , OooOoo0oo , I1i1o0 )
   time . sleep ( .001 )
   if 37 - 37: iII111i + o0oOOo0O0Ooo . OoO0O00 / i1IIi
   if 52 - 52: O0 * Oo0Ooo - I1ii11iIi11i * Oo0Ooo
 return
 if 2 - 2: O0 - oO0o % ooOoO0o % IiII
 if 86 - 86: OoO0O00 / oO0o - i11iIiiIii . Ii1I + OOooOOo - OOooOOo
 if 28 - 28: O0 * ooOoO0o . OoOoOO00 * II111iiii . I1IiiI % I11i
 if 28 - 28: I1ii11iIi11i * OoooooooOO
 if 19 - 19: Oo0Ooo - iII111i % OoOoOO00 * i11iIiiIii / oO0o . i11iIiiIii
 if 46 - 46: I1ii11iIi11i
 if 50 - 50: OOooOOo * OoO0O00 * OOooOOo % I1IiiI - I1Ii111 * Ii1I
 if 88 - 88: OOooOOo . iII111i / I11i
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for iIi1iIIIiIiI in range ( rloc_count ) :
  IiiI1 = lisp_rloc_record ( )
  packet = IiiI1 . decode ( packet , None )
  ii1Ii1iI1 = IiiI1 . json
  if ( ii1Ii1iI1 == None ) : continue
  if 79 - 79: ooOoO0o . I1ii11iIi11i + IiII . iIii1I11I1II1 + OOooOOo
  try :
   ii1Ii1iI1 = json . loads ( ii1Ii1iI1 . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 79 - 79: I1Ii111
   if 81 - 81: OoooooooOO + OoOoOO00 / II111iiii
  if ( "signature" not in ii1Ii1iI1 ) : continue
  return ( IiiI1 )
  if 39 - 39: I1Ii111 * I1IiiI - o0oOOo0O0Ooo . oO0o . OOooOOo * i11iIiiIii
 return ( None )
 if 70 - 70: OoOoOO00 / OOooOOo - o0oOOo0O0Ooo
 if 82 - 82: OOooOOo . i11iIiiIii . I1ii11iIi11i % OoOoOO00 * Ii1I / OoO0O00
 if 56 - 56: o0oOOo0O0Ooo / I1IiiI + I11i + I1IiiI
 if 34 - 34: Oo0Ooo / i11iIiiIii - ooOoO0o
 if 77 - 77: OoOoOO00 * OoooooooOO
 if 41 - 41: iIii1I11I1II1 - O0 . II111iiii + I1IiiI - II111iiii / oO0o
 if 35 - 35: ooOoO0o - OoOoOO00 / iIii1I11I1II1 / OOooOOo
 if 38 - 38: i1IIi % OoooooooOO
 if 5 - 5: iIii1I11I1II1 + iIii1I11I1II1 . iIii1I11I1II1 + o0oOOo0O0Ooo
 if 45 - 45: I1IiiI - OoooooooOO - I1Ii111 - i1IIi - OoooooooOO * O0
 if 67 - 67: OoOoOO00 * o0oOOo0O0Ooo . IiII
 if 72 - 72: OoOoOO00 % OoooooooOO * O0
 if 27 - 27: I1ii11iIi11i . OoooooooOO / II111iiii . OOooOOo
 if 58 - 58: oO0o / ooOoO0o
 if 31 - 31: o0oOOo0O0Ooo % I11i - OoO0O00
 if 40 - 40: o0oOOo0O0Ooo % OoOoOO00 + I11i / O0 - II111iiii
 if 9 - 9: OoooooooOO - OOooOOo . I11i * oO0o
 if 3 - 3: iIii1I11I1II1 - OoO0O00
 if 38 - 38: O0 + ooOoO0o * I1Ii111 - oO0o * o0oOOo0O0Ooo
def lisp_get_eid_hash ( eid ) :
 oO0ooOoO = None
 for II1 in lisp_eid_hashes :
  if 35 - 35: I11i . ooOoO0o % I11i / iII111i / O0 % I11i
  if 29 - 29: I1Ii111 + Ii1I
  if 100 - 100: Ii1I + I1Ii111 / iIii1I11I1II1 / i1IIi % OoOoOO00
  if 6 - 6: oO0o + ooOoO0o
  oooo = II1 . instance_id
  if ( oooo == - 1 ) : II1 . instance_id = eid . instance_id
  if 13 - 13: Oo0Ooo . IiII % iII111i + i1IIi / OOooOOo
  I11i1IiIi1II1 = eid . is_more_specific ( II1 )
  II1 . instance_id = oooo
  if ( I11i1IiIi1II1 ) :
   oO0ooOoO = 128 - II1 . mask_len
   break
   if 34 - 34: I11i
   if 88 - 88: I11i - I1Ii111
 if ( oO0ooOoO == None ) : return ( None )
 if 86 - 86: iIii1I11I1II1
 I1IIIi = eid . address
 ii11iIII = ""
 for iIi1iIIIiIiI in range ( 0 , old_div ( oO0ooOoO , 16 ) ) :
  IiI = I1IIIi & 0xffff
  IiI = hex ( IiI ) [ 2 : : ]
  ii11iIII = IiI . zfill ( 4 ) + ":" + ii11iIII
  I1IIIi >>= 16
  if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
 if ( oO0ooOoO % 16 != 0 ) :
  IiI = I1IIIi & 0xff
  IiI = hex ( IiI ) [ 2 : : ]
  ii11iIII = IiI . zfill ( 2 ) + ":" + ii11iIII
  if 82 - 82: IiII % ooOoO0o
 return ( ii11iIII [ 0 : - 1 ] )
 if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
 if 27 - 27: Oo0Ooo . I1Ii111 - i1IIi * I1IiiI
 if 96 - 96: I1ii11iIi11i - Ii1I . I1ii11iIi11i
 if 89 - 89: II111iiii % I1ii11iIi11i % IiII . I11i
 if 49 - 49: iII111i % i11iIiiIii * I11i - oO0o . OOooOOo . i11iIiiIii
 if 26 - 26: iIii1I11I1II1 + i11iIiiIii % iII111i + I1IiiI + oO0o - ooOoO0o
 if 4 - 4: Oo0Ooo - IiII - I11i
 if 72 - 72: OoooooooOO
 if 19 - 19: Oo0Ooo . OOooOOo
 if 58 - 58: IiII % iII111i + i1IIi % I1IiiI % OOooOOo . iII111i
 if 85 - 85: i11iIiiIii . o0oOOo0O0Ooo * iII111i . I1ii11iIi11i / I1Ii111 % Ii1I
def lisp_lookup_public_key ( eid ) :
 oooo = eid . instance_id
 if 27 - 27: II111iiii . iIii1I11I1II1 / I1ii11iIi11i / i1IIi / iIii1I11I1II1
 if 70 - 70: i11iIiiIii . OoO0O00 / OoooooooOO * OoooooooOO - OOooOOo
 if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
 if 39 - 39: OoO0O00 + IiII - II111iiii % I11i
 if 80 - 80: o0oOOo0O0Ooo * ooOoO0o
 O0oooOo = lisp_get_eid_hash ( eid )
 if ( O0oooOo == None ) : return ( [ None , None , False ] )
 if 47 - 47: IiII + O0 / OoooooooOO + iIii1I11I1II1
 O0oooOo = "hash-" + O0oooOo
 iiiIiIi = lisp_address ( LISP_AFI_NAME , O0oooOo , len ( O0oooOo ) , oooo )
 o0o0Oo0o0oOo = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
 if 97 - 97: OoooooooOO * I11i . I1Ii111
 if 20 - 20: I1IiiI . I1ii11iIi11i
 if 55 - 55: OoOoOO00 + I11i - OOooOOo
 if 20 - 20: OoO0O00 . OoooooooOO - I1Ii111 * IiII
 oOoooooOooO = lisp_site_eid_lookup ( iiiIiIi , o0o0Oo0o0oOo , True )
 if ( oOoooooOooO == None ) : return ( [ iiiIiIi , None , False ] )
 if 20 - 20: o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
 if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
 if 8 - 8: OoooooooOO * ooOoO0o
 if 26 - 26: i11iIiiIii + oO0o - i1IIi
 iIooO = None
 for I1Ii1i111I in oOoooooOooO . registered_rlocs :
  OOo00OoOOo = I1Ii1i111I . json
  if ( OOo00OoOOo == None ) : continue
  try :
   OOo00OoOOo = json . loads ( OOo00OoOOo . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( O0oooOo ) )
   if 93 - 93: iII111i - IiII * o0oOOo0O0Ooo / I1Ii111 - oO0o + I11i
   return ( [ iiiIiIi , None , False ] )
   if 81 - 81: Ii1I + I11i - OoOoOO00 + I1ii11iIi11i
  if ( "public-key" not in OOo00OoOOo ) : continue
  iIooO = OOo00OoOOo [ "public-key" ]
  break
  if 6 - 6: iII111i / i1IIi + OOooOOo % OoOoOO00 . I1ii11iIi11i
 return ( [ iiiIiIi , iIooO , True ] )
 if 88 - 88: OoO0O00
 if 82 - 82: OOooOOo / I11i / OoooooooOO % oO0o
 if 27 - 27: oO0o + IiII
 if 5 - 5: iIii1I11I1II1 + OoOoOO00 * I1Ii111 * i11iIiiIii
 if 18 - 18: Oo0Ooo % OOooOOo % oO0o / I11i % O0
 if 76 - 76: OoooooooOO % O0 / OoO0O00
 if 41 - 41: i11iIiiIii - I1ii11iIi11i - II111iiii
 if 5 - 5: OoOoOO00 + i1IIi
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 43 - 43: iII111i * I1IiiI
 if 20 - 20: I1IiiI . I11i * OoO0O00 . ooOoO0o . II111iiii
 if 6 - 6: Ii1I * OoOoOO00 % IiII + I11i
 if 20 - 20: oO0o
 if 34 - 34: i1IIi + oO0o * Oo0Ooo * I1Ii111 % OoooooooOO % ooOoO0o
 IIIII1iII1 = json . loads ( rloc_record . json . json_string )
 if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
 if ( lisp_get_eid_hash ( eid ) ) :
  IIi1i = eid
 elif ( "signature-eid" in IIIII1iII1 ) :
  o0Oooooo00OoO = IIIII1iII1 [ "signature-eid" ]
  IIi1i = lisp_address ( LISP_AFI_IPV6 , o0Oooooo00OoO , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 65 - 65: I11i . I11i + i11iIiiIii - O0 / ooOoO0o . I11i
  if 44 - 44: I11i % I1Ii111 % i11iIiiIii / i1IIi - I11i
  if 42 - 42: II111iiii
  if 14 - 14: i11iIiiIii
  if 85 - 85: i11iIiiIii / Ii1I + Oo0Ooo / OoOoOO00 - I1IiiI
 iiiIiIi , iIooO , i1IiiII = lisp_lookup_public_key ( IIi1i )
 if ( iiiIiIi == None ) :
  i1iiii = green ( IIi1i . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( i1iiii ) )
  return ( False )
  if 8 - 8: iIii1I11I1II1 - I1Ii111 % OoOoOO00
  if 69 - 69: Ii1I
 ooo0o00o0Oooo = "found" if i1IiiII else bold ( "not found" , False )
 i1iiii = green ( iiiIiIi . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( i1iiii , ooo0o00o0Oooo ) )
 if ( i1IiiII == False ) : return ( False )
 if 86 - 86: II111iiii . OoOoOO00 % I1IiiI * OOooOOo . OoOoOO00 + O0
 if ( iIooO == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 15 - 15: i11iIiiIii / I1IiiI - iII111i
  if 75 - 75: o0oOOo0O0Ooo . I11i
 Ii1iii11II = iIooO [ 0 : 8 ] + "..." + iIooO [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( Ii1iii11II ) )
 if 58 - 58: I1ii11iIi11i % Ii1I . Ii1I * I1ii11iIi11i . OOooOOo
 if 12 - 12: OoOoOO00 * ooOoO0o % OOooOOo - oO0o * OoO0O00 - IiII
 if 74 - 74: I1Ii111 - iII111i - II111iiii
 if 20 - 20: iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo + oO0o % IiII
 if 84 - 84: IiII - O0 . I1ii11iIi11i % OOooOOo % iII111i + OoooooooOO
 oOOOOoo = IIIII1iII1 [ "signature" ]
 if 70 - 70: ooOoO0o
 try :
  IIIII1iII1 = binascii . a2b_base64 ( oOOOOoo )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 51 - 51: O0 - IiII % Ii1I / OoOoOO00 * OoooooooOO
  if 57 - 57: Oo0Ooo % Oo0Ooo % O0 . I1Ii111 % I1ii11iIi11i
 OO0O0O00Oo = len ( IIIII1iII1 )
 if ( OO0O0O00Oo & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( OO0O0O00Oo ) )
  return ( False )
  if 9 - 9: i11iIiiIii - i11iIiiIii / OOooOOo - ooOoO0o % OoOoOO00 + Ii1I
  if 3 - 3: iII111i / I1ii11iIi11i / I1IiiI - Oo0Ooo
  if 71 - 71: i11iIiiIii + Oo0Ooo % i11iIiiIii - i11iIiiIii
  if 84 - 84: oO0o
  if 55 - 55: oO0o
 OoI1Ii = IIi1i . print_address ( )
 if 19 - 19: I11i
 if 77 - 77: ooOoO0o + OoO0O00 + Ii1I / I11i - Ii1I
 if 85 - 85: Oo0Ooo + Oo0Ooo
 if 70 - 70: I1ii11iIi11i % OoO0O00 * iIii1I11I1II1 . oO0o
 iIooO = binascii . a2b_base64 ( iIooO )
 try :
  Ooo00o000o = ecdsa . VerifyingKey . from_pem ( iIooO )
 except :
  I1iIi = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( I1iIi ) )
  return ( False )
  if 2 - 2: I1Ii111
  if 45 - 45: OOooOOo * ooOoO0o
  if 77 - 77: i11iIiiIii / OOooOOo % i11iIiiIii
  if 19 - 19: OoooooooOO - I1IiiI * OoO0O00
  if 65 - 65: OoooooooOO . I11i / I1ii11iIi11i / i11iIiiIii
  if 20 - 20: OoOoOO00 / OoO0O00 - Oo0Ooo + ooOoO0o
  if 86 - 86: O0 / II111iiii / ooOoO0o % I1ii11iIi11i / iIii1I11I1II1
  if 1 - 1: O0
  if 55 - 55: i1IIi % IiII - i1IIi . IiII . o0oOOo0O0Ooo
  if 85 - 85: Ii1I . i11iIiiIii
  if 69 - 69: OoOoOO00
 try :
  i11i1I1 = Ooo00o000o . verify ( IIIII1iII1 , OoI1Ii . encode ( ) , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( OoI1Ii ) )
  if 49 - 49: Oo0Ooo % Oo0Ooo * OoOoOO00 - Oo0Ooo
  lprint ( "  Signature used '{}'" . format ( oOOOOoo ) )
  return ( False )
  if 32 - 32: i1IIi . I11i - IiII % OoO0O00 % iIii1I11I1II1 - OoooooooOO
 return ( i11i1I1 )
 if 47 - 47: OoO0O00 + II111iiii . IiII - I11i . iII111i . o0oOOo0O0Ooo
 if 31 - 31: I1IiiI + O0 . I1IiiI - iII111i - I1Ii111
 if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
 if 7 - 7: i1IIi
 if 30 - 30: oO0o . i1IIi / I11i
 if 23 - 23: i1IIi + oO0o % iII111i - OoO0O00 - i1IIi
 if 74 - 74: Ii1I + I11i . OoooooooOO - I1ii11iIi11i
 if 2 - 2: oO0o - o0oOOo0O0Ooo
 if 80 - 80: i1IIi
 if 40 - 40: O0 . ooOoO0o * iII111i . I11i + I1Ii111 % OoO0O00
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 9 - 9: IiII * oO0o - o0oOOo0O0Ooo
 if 17 - 17: iII111i % Oo0Ooo
 if 14 - 14: I1IiiI - I1Ii111 % I1IiiI - II111iiii
 if 34 - 34: I1ii11iIi11i * IiII / II111iiii / ooOoO0o * oO0o
 if 3 - 3: II111iiii
 oOi11i = [ ]
 for IIII in eid_list :
  for O00O0oo0Oo0 in lisp_map_notify_queue :
   OOo0oo0O = lisp_map_notify_queue [ O00O0oo0Oo0 ]
   if ( IIII not in OOo0oo0O . eid_list ) : continue
   if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
   oOi11i . append ( O00O0oo0Oo0 )
   Oooo0 = OOo0oo0O . retransmit_timer
   if ( Oooo0 ) : Oooo0 . cancel ( )
   if 57 - 57: OOooOOo
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( OOo0oo0O . nonce_key , green ( IIII , False ) ) )
   if 76 - 76: Oo0Ooo . I1Ii111 + iII111i / OoooooooOO . Oo0Ooo
   if 68 - 68: OoO0O00 % OoO0O00 + i11iIiiIii / Ii1I
   if 20 - 20: I1Ii111 + IiII - O0 + IiII / i1IIi
   if 100 - 100: OoooooooOO
   if 26 - 26: Ii1I * O0
   if 44 - 44: OoO0O00 - I11i
   if 65 - 65: Ii1I % OOooOOo . OoO0O00 - o0oOOo0O0Ooo
 for O00O0oo0Oo0 in oOi11i : lisp_map_notify_queue . pop ( O00O0oo0Oo0 )
 return
 if 8 - 8: OOooOOo % OoOoOO00 % Oo0Ooo . II111iiii
 if 92 - 92: OoOoOO00
 if 26 - 26: Oo0Ooo
 if 3 - 3: I11i . OoO0O00 . i1IIi - I1IiiI * oO0o
 if 93 - 93: i1IIi + I1ii11iIi11i % Oo0Ooo + iIii1I11I1II1 / II111iiii
 if 100 - 100: iIii1I11I1II1 / II111iiii / Ii1I * Ii1I - OoO0O00
 if 36 - 36: ooOoO0o % i1IIi / OoOoOO00 % OoOoOO00 + Ii1I
 if 35 - 35: Ii1I . ooOoO0o - ooOoO0o % OoO0O00 / oO0o
def lisp_decrypt_map_register ( packet ) :
 if 33 - 33: I1Ii111 / i11iIiiIii / I1ii11iIi11i
 if 44 - 44: OoOoOO00 * Oo0Ooo
 if 51 - 51: OOooOOo / IiII % I1Ii111 . OoOoOO00 % Ii1I
 if 88 - 88: OoO0O00
 if 28 - 28: I1Ii111 - iIii1I11I1II1
 ooo = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 oO0oOOoo0OO0 = ( ooo >> 13 ) & 0x1
 if ( oO0oOOoo0OO0 == 0 ) : return ( packet )
 if 25 - 25: iII111i / iII111i
 Ii11iII11I1Ii = ( ooo >> 14 ) & 0x7
 if 72 - 72: iII111i * OoooooooOO * OoooooooOO
 if 44 - 44: OoO0O00 . OoOoOO00 + I1Ii111
 if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
 if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
 try :
  iI1II1I1i1 = lisp_ms_encryption_keys [ Ii11iII11I1Ii ]
  iI1II1I1i1 = iI1II1I1i1 . zfill ( 32 )
  OoOooO = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( Ii11iII11I1Ii ) )
  return ( None )
  if 51 - 51: ooOoO0o + oO0o
  if 13 - 13: IiII - OoO0O00 - ooOoO0o
 IiI11I111 = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( IiI11I111 , Ii11iII11I1Ii ) )
 if 46 - 46: oO0o + I1ii11iIi11i - OoOoOO00
 if 15 - 15: OoooooooOO + ooOoO0o * I1ii11iIi11i
 if 6 - 6: OoooooooOO % i1IIi % II111iiii + ooOoO0o / IiII + Ii1I
 if 97 - 97: ooOoO0o / I1Ii111 * I1ii11iIi11i
 ooOooOooOOO = chacha . ChaCha ( iI1II1I1i1 , OoOooO , 20 ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + ooOooOooOOO )
 if 83 - 83: Ii1I + ooOoO0o
 if 46 - 46: OoOoOO00
 if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
 if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
 if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
 if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
 if 20 - 20: IiII
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 81 - 81: Oo0Ooo / I1Ii111
 if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
 if 51 - 51: iII111i - ooOoO0o
 if 32 - 32: IiII - i11iIiiIii
 if 41 - 41: Ii1I % Ii1I * oO0o - I11i + iIii1I11I1II1 . ooOoO0o
 if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
 I1i = lisp_map_register ( )
 i1iiI11i1 , packet = I1i . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 16 - 16: I1ii11iIi11i - I1ii11iIi11i % i11iIiiIii * Oo0Ooo
 I1i . sport = sport
 if 1 - 1: ooOoO0o % I1Ii111 - OoO0O00 + OoO0O00
 I1i . print_map_register ( )
 if 99 - 99: oO0o
 if 39 - 39: i1IIi
 if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
 if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
 O0O0oO00 = True
 if ( I1i . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  O0O0oO00 = True
  if 80 - 80: IiII
 if ( I1i . alg_id == LISP_SHA_256_128_ALG_ID ) :
  O0O0oO00 = False
  if 24 - 24: OoO0O00 + ooOoO0o
  if 57 - 57: iII111i
  if 37 - 37: i1IIi - I1Ii111 + IiII * ooOoO0o
  if 43 - 43: O0 . iII111i * I11i / i11iIiiIii
  if 39 - 39: oO0o / ooOoO0o
 OooOooo = [ ]
 if 21 - 21: i11iIiiIii * Ii1I / OoO0O00 + OoooooooOO
 if 31 - 31: I11i - ooOoO0o - o0oOOo0O0Ooo % I1IiiI * i11iIiiIii - OoO0O00
 if 56 - 56: ooOoO0o / OoO0O00 . OoooooooOO % iII111i / IiII
 if 64 - 64: ooOoO0o % O0 / oO0o
 iiI = None
 o0O0O0 = packet
 i111I1i1 = [ ]
 O0O00oo = I1i . record_count
 for iIi1iIIIiIiI in range ( O0O00oo ) :
  IiIo0oo0O = lisp_eid_record ( )
  IiiI1 = lisp_rloc_record ( )
  packet = IiIo0oo0O . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 19 - 19: i11iIiiIii - Ii1I
  IiIo0oo0O . print_record ( "  " , False )
  if 68 - 68: I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
  if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
  if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
  if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
  oOoooooOooO = lisp_site_eid_lookup ( IiIo0oo0O . eid , IiIo0oo0O . group ,
 False )
  if 88 - 88: ooOoO0o
  oo00ooo0o0 = oOoooooOooO . print_eid_tuple ( ) if oOoooooOooO else None
  if 29 - 29: IiII / OOooOOo
  if 39 - 39: O0 + II111iiii
  if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
  if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
  if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
  if 42 - 42: O0 / oO0o % O0 . i1IIi % OOooOOo
  if 13 - 13: I1IiiI % ooOoO0o + OOooOOo
  if ( oOoooooOooO and oOoooooOooO . accept_more_specifics == False ) :
   if ( oOoooooOooO . eid_record_matches ( IiIo0oo0O ) == False ) :
    oO0oOooo = oOoooooOooO . parent_for_more_specifics
    if ( oO0oOooo ) : oOoooooOooO = oO0oOooo
    if 90 - 90: I11i - II111iiii
    if 61 - 61: ooOoO0o
    if 52 - 52: Ii1I % I11i . oO0o + I11i * o0oOOo0O0Ooo / O0
    if 55 - 55: OoO0O00 / i11iIiiIii / o0oOOo0O0Ooo
    if 19 - 19: ooOoO0o * iII111i
    if 38 - 38: ooOoO0o
    if 35 - 35: o0oOOo0O0Ooo * IiII * Oo0Ooo
    if 34 - 34: I11i - OoooooooOO % i1IIi + I1IiiI
  iiiOOoo0OOOoo = ( oOoooooOooO and oOoooooOooO . accept_more_specifics )
  if ( iiiOOoo0OOOoo ) :
   IiiII11ii1 = lisp_site_eid ( oOoooooOooO . site )
   IiiII11ii1 . dynamic = True
   IiiII11ii1 . eid . copy_address ( IiIo0oo0O . eid )
   IiiII11ii1 . group . copy_address ( IiIo0oo0O . group )
   IiiII11ii1 . parent_for_more_specifics = oOoooooOooO
   IiiII11ii1 . add_cache ( )
   IiiII11ii1 . inherit_from_ams_parent ( )
   oOoooooOooO . more_specific_registrations . append ( IiiII11ii1 )
   oOoooooOooO = IiiII11ii1
  else :
   oOoooooOooO = lisp_site_eid_lookup ( IiIo0oo0O . eid , IiIo0oo0O . group ,
 True )
   if 87 - 87: Oo0Ooo
   if 7 - 7: iIii1I11I1II1
  i1iiii = IiIo0oo0O . print_eid_tuple ( )
  if 85 - 85: iIii1I11I1II1 . O0
  if ( oOoooooOooO == None ) :
   OOo00OO = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( OOo00OO , green ( i1iiii , False ) ,
 ", matched non-ams {}" . format ( green ( oo00ooo0o0 , False ) if oo00ooo0o0 else "" ) ) )
   if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
   if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
   if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
   if 8 - 8: OoO0O00 . OoO0O00
   if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
   packet = IiiI1 . end_of_rlocs ( packet , IiIo0oo0O . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
   continue
   if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
   if 24 - 24: IiII
  iiI = oOoooooOooO . site
  if 95 - 95: IiII + OoOoOO00 * OOooOOo
  if ( iiiOOoo0OOOoo ) :
   oO0ooOOO = oOoooooOooO . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( oO0ooOOO , False ) , iiI . site_name , green ( i1iiii , False ) ) )
   if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
  else :
   oO0ooOOO = green ( oOoooooOooO . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( oO0ooOOO , iiI . site_name , green ( i1iiii , False ) ) )
   if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
   if 41 - 41: i1IIi / IiII
   if 73 - 73: o0oOOo0O0Ooo % ooOoO0o
   if 72 - 72: OoO0O00 * OoOoOO00 % I1IiiI - OOooOOo . Oo0Ooo
   if 70 - 70: ooOoO0o . o0oOOo0O0Ooo * II111iiii - O0
   if 74 - 74: oO0o % I1IiiI / oO0o / Oo0Ooo / ooOoO0o
  if ( iiI . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( iiI . site_name ) )
   packet = IiiI1 . end_of_rlocs ( packet , IiIo0oo0O . rloc_count )
   continue
   if 29 - 29: ooOoO0o + iIii1I11I1II1 + OoO0O00 - o0oOOo0O0Ooo
   if 74 - 74: II111iiii - II111iiii + ooOoO0o + Oo0Ooo % iIii1I11I1II1
   if 90 - 90: oO0o / o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoOoOO00 / IiII
   if 13 - 13: oO0o + IiII
   if 36 - 36: oO0o - OoOoOO00 . O0 % IiII
   if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
   if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
   if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
  i11iII1 = I1i . key_id
  if ( i11iII1 in iiI . auth_key ) :
   Iii = iiI . auth_key [ i11iII1 ]
  else :
   Iii = ""
   if 6 - 6: OoO0O00
   if 91 - 91: Oo0Ooo + O0 . iII111i
  OOOOoooO = lisp_verify_auth ( i1iiI11i1 , I1i . alg_id ,
 I1i . auth_data , Iii )
  OO00ooOo0o = "dynamic " if oOoooooOooO . dynamic else ""
  if 90 - 90: OOooOOo - I1IiiI % o0oOOo0O0Ooo
  Oo0 = bold ( "passed" if OOOOoooO else "failed" , False )
  i11iII1 = "key-id {}" . format ( i11iII1 ) if i11iII1 == I1i . key_id else "bad key-id {}" . format ( I1i . key_id )
  if 26 - 26: Oo0Ooo . II111iiii - I11i . Ii1I % OOooOOo
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( Oo0 , OO00ooOo0o , green ( i1iiii , False ) , i11iII1 ) )
  if 4 - 4: I11i + I1Ii111 / i1IIi + OoooooooOO
  if 84 - 84: ooOoO0o
  if 47 - 47: Oo0Ooo
  if 60 - 60: i11iIiiIii - o0oOOo0O0Ooo
  if 36 - 36: II111iiii
  if 80 - 80: i11iIiiIii / iII111i
  ooOooOO000O = True
  oOOo0 = ( lisp_get_eid_hash ( IiIo0oo0O . eid ) != None )
  if ( oOOo0 or oOoooooOooO . require_signature ) :
   O0OoO0o = "Required " if oOoooooOooO . require_signature else ""
   i1iiii = green ( i1iiii , False )
   I1Ii1i111I = lisp_find_sig_in_rloc_set ( packet , IiIo0oo0O . rloc_count )
   if ( I1Ii1i111I == None ) :
    ooOooOO000O = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( O0OoO0o ,
    # iII111i
 bold ( "failed" , False ) , i1iiii ) )
   else :
    ooOooOO000O = lisp_verify_cga_sig ( IiIo0oo0O . eid , I1Ii1i111I )
    Oo0 = bold ( "passed" if ooOooOO000O else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( O0OoO0o , Oo0 , i1iiii ) )
    if 4 - 4: I1ii11iIi11i % o0oOOo0O0Ooo * Oo0Ooo
    if 97 - 97: OoOoOO00
    if 34 - 34: iII111i % Oo0Ooo
    if 25 - 25: OOooOOo / Oo0Ooo
  if ( OOOOoooO == False or ooOooOO000O == False ) :
   packet = IiiI1 . end_of_rlocs ( packet , IiIo0oo0O . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 26 - 26: iII111i
   continue
   if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
   if 6 - 6: IiII
   if 68 - 68: Oo0Ooo
   if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
   if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
   if 93 - 93: i11iIiiIii
  if ( I1i . merge_register_requested ) :
   oO0oOooo = oOoooooOooO
   oO0oOooo . inconsistent_registration = False
   if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
   if 40 - 40: IiII % IiII
   if 9 - 9: I1IiiI * i1IIi + OOooOOo * OoOoOO00
   if 8 - 8: iII111i
   if 51 - 51: I1IiiI
   if ( oOoooooOooO . group . is_null ( ) ) :
    if ( oO0oOooo . site_id != I1i . site_id ) :
     oO0oOooo . site_id = I1i . site_id
     oO0oOooo . registered = False
     oO0oOooo . individual_registrations = { }
     oO0oOooo . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 72 - 72: ooOoO0o / I1ii11iIi11i . Ii1I * iII111i . iIii1I11I1II1
     if 35 - 35: OoO0O00 . OoOoOO00 % O0 * OoO0O00
     if 68 - 68: OOooOOo
   Ooo00o000o = I1i . xtr_id
   if ( Ooo00o000o in oOoooooOooO . individual_registrations ) :
    oOoooooOooO = oOoooooOooO . individual_registrations [ Ooo00o000o ]
   else :
    oOoooooOooO = lisp_site_eid ( iiI )
    oOoooooOooO . eid . copy_address ( oO0oOooo . eid )
    oOoooooOooO . group . copy_address ( oO0oOooo . group )
    oOoooooOooO . encrypt_json = oO0oOooo . encrypt_json
    oO0oOooo . individual_registrations [ Ooo00o000o ] = oOoooooOooO
    if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
  else :
   oOoooooOooO . inconsistent_registration = oOoooooOooO . merge_register_requested
   if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
   if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
   if 15 - 15: i1IIi . iII111i + IiII / I1ii11iIi11i - i1IIi / iII111i
  oOoooooOooO . map_registers_received += 1
  if 27 - 27: OoOoOO00 / OoooooooOO + i1IIi % iIii1I11I1II1 / OoO0O00
  if 73 - 73: I1ii11iIi11i / OoOoOO00 / IiII + oO0o
  if 73 - 73: I11i * o0oOOo0O0Ooo * I1IiiI . OoooooooOO % I1Ii111
  if 9 - 9: oO0o % I1Ii111 . O0 + I1ii11iIi11i - Ii1I - I1ii11iIi11i
  if 57 - 57: i11iIiiIii
  I1iIi = ( oOoooooOooO . is_rloc_in_rloc_set ( source ) == False )
  if ( IiIo0oo0O . record_ttl == 0 and I1iIi ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 21 - 21: iIii1I11I1II1 / I1IiiI / iII111i
   continue
   if 19 - 19: Oo0Ooo / iIii1I11I1II1 / I11i
   if 71 - 71: iIii1I11I1II1 * I1IiiI
   if 35 - 35: O0
   if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
   if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
   if 78 - 78: I1IiiI - iIii1I11I1II1
  ii1II1II11I = oOoooooOooO . registered_rlocs
  oOoooooOooO . registered_rlocs = [ ]
  if 98 - 98: O0
  if 92 - 92: i11iIiiIii
  if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
  if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
  o0o0O0OO0 = packet
  for iI1iII1II1 in range ( IiIo0oo0O . rloc_count ) :
   IiiI1 = lisp_rloc_record ( )
   packet = IiiI1 . decode ( packet , None , oOoooooOooO . encrypt_json )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 14 - 14: I1ii11iIi11i * Ii1I - OOooOOo
   IiiI1 . print_record ( "    " )
   if 85 - 85: I11i - OoooooooOO
   if 68 - 68: iIii1I11I1II1 / OoO0O00 + OoOoOO00 . I11i % OoooooooOO / O0
   if 19 - 19: iIii1I11I1II1 * I11i
   if 60 - 60: O0 * iII111i % I1ii11iIi11i
   if ( len ( iiI . allowed_rlocs ) > 0 ) :
    O0O0 = IiiI1 . rloc . print_address ( )
    if ( O0O0 not in iiI . allowed_rlocs ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( O0O0 , False ) ) )
     if 92 - 92: OoOoOO00 / iIii1I11I1II1
     if 67 - 67: i1IIi + i11iIiiIii - i1IIi % OoOoOO00
     oOoooooOooO . registered = False
     packet = IiiI1 . end_of_rlocs ( packet ,
 IiIo0oo0O . rloc_count - iI1iII1II1 - 1 )
     break
     if 3 - 3: I1IiiI % ooOoO0o
     if 32 - 32: OOooOOo / i1IIi / OOooOOo
     if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
     if 45 - 45: Oo0Ooo
     if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
     if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
   I1Ii1i111I = lisp_rloc ( )
   I1Ii1i111I . store_rloc_from_record ( IiiI1 , None , source )
   if 52 - 52: OOooOOo + OoO0O00
   if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
   if 42 - 42: i1IIi
   if 52 - 52: OoO0O00 % iII111i % O0
   if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
   if 50 - 50: oO0o . I1Ii111
   if ( source . is_exact_match ( I1Ii1i111I . rloc ) ) :
    I1Ii1i111I . map_notify_requested = I1i . map_notify_requested
    if 38 - 38: iIii1I11I1II1 . Ii1I
    if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
    if 15 - 15: O0
    if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
    if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
   oOoooooOooO . registered_rlocs . append ( I1Ii1i111I )
   if 25 - 25: ooOoO0o
   if 33 - 33: Oo0Ooo
  iI11iII1Ii = ( oOoooooOooO . do_rloc_sets_match ( ii1II1II11I ) == False )
  if 45 - 45: I1ii11iIi11i - iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
  if 74 - 74: I1IiiI / o0oOOo0O0Ooo
  if 53 - 53: iIii1I11I1II1 * oO0o
  if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
  if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
  if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
  if ( I1i . map_register_refresh and iI11iII1Ii and
 oOoooooOooO . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   oOoooooOooO . registered_rlocs = ii1II1II11I
   continue
   if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
   if 60 - 60: oO0o * I1Ii111
   if 81 - 81: oO0o - OOooOOo - oO0o
   if 54 - 54: oO0o % I11i
   if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
   if 22 - 22: iIii1I11I1II1 - OoooooooOO
  if ( oOoooooOooO . registered == False ) :
   oOoooooOooO . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 8 - 8: ooOoO0o % i11iIiiIii
  oOoooooOooO . last_registered = lisp_get_timestamp ( )
  oOoooooOooO . registered = ( IiIo0oo0O . record_ttl != 0 )
  oOoooooOooO . last_registerer = source
  if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
  if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
  if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
  if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
  oOoooooOooO . auth_sha1_or_sha2 = O0O0oO00
  oOoooooOooO . proxy_reply_requested = I1i . proxy_reply_requested
  oOoooooOooO . lisp_sec_present = I1i . lisp_sec_present
  oOoooooOooO . map_notify_requested = I1i . map_notify_requested
  oOoooooOooO . mobile_node_requested = I1i . mobile_node
  oOoooooOooO . merge_register_requested = I1i . merge_register_requested
  if 73 - 73: O0 % i11iIiiIii
  oOoooooOooO . use_register_ttl_requested = I1i . use_ttl_for_timeout
  if ( oOoooooOooO . use_register_ttl_requested ) :
   oOoooooOooO . register_ttl = IiIo0oo0O . store_ttl ( )
  else :
   oOoooooOooO . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 16 - 16: O0
  oOoooooOooO . xtr_id_present = I1i . xtr_id_present
  if ( oOoooooOooO . xtr_id_present ) :
   oOoooooOooO . xtr_id = I1i . xtr_id
   oOoooooOooO . site_id = I1i . site_id
   if 15 - 15: i1IIi % i11iIiiIii
   if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
   if 35 - 35: OoOoOO00 . oO0o / II111iiii
   if 97 - 97: Ii1I + I1Ii111 / II111iiii
   if 14 - 14: iII111i / IiII / oO0o
  if ( I1i . merge_register_requested ) :
   if ( oO0oOooo . merge_in_site_eid ( oOoooooOooO ) ) :
    OooOooo . append ( [ IiIo0oo0O . eid , IiIo0oo0O . group ] )
    if 55 - 55: OoO0O00 % O0
   if ( I1i . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , oO0oOooo , I1i ,
 IiIo0oo0O )
    if 92 - 92: OoooooooOO / O0
    if 14 - 14: i11iIiiIii
    if 43 - 43: OOooOOo
  if ( iI11iII1Ii == False ) : continue
  if ( len ( OooOooo ) != 0 ) : continue
  if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
  i111I1i1 . append ( oOoooooOooO . print_eid_tuple ( ) )
  if 93 - 93: OoOoOO00
  if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
  if 72 - 72: ooOoO0o
  if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
  if 53 - 53: OOooOOo * O0 . iII111i
  if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
  if 78 - 78: iII111i
  ooOoO0O0O0Oo = copy . deepcopy ( IiIo0oo0O )
  IiIo0oo0O = IiIo0oo0O . encode ( )
  IiIo0oo0O += o0o0O0OO0
  OooOoo0oo = [ oOoooooOooO . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 40 - 40: Oo0Ooo - i11iIiiIii / o0oOOo0O0Ooo . II111iiii
  for I1Ii1i111I in ii1II1II11I :
   if ( I1Ii1i111I . map_notify_requested == False ) : continue
   if ( I1Ii1i111I . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , IiIo0oo0O , OooOoo0oo , 1 , I1Ii1i111I . rloc ,
 LISP_CTRL_PORT , I1i . nonce , I1i . key_id ,
 I1i . alg_id , I1i . auth_len , iiI , False )
   if 63 - 63: O0
   if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
   if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
   if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
   if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
  lisp_notify_subscribers ( lisp_sockets , ooOoO0O0O0Oo , o0o0O0OO0 ,
 oOoooooOooO . eid , iiI )
  if 74 - 74: i11iIiiIii
  if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
  if 6 - 6: I11i
  if 70 - 70: ooOoO0o + OoooooooOO % OoOoOO00 % oO0o / Ii1I . I11i
  if 63 - 63: I1ii11iIi11i - ooOoO0o . OOooOOo / O0 . iIii1I11I1II1 - Ii1I
 if ( len ( OooOooo ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , OooOooo )
  if 6 - 6: Ii1I
  if 60 - 60: iII111i + I1IiiI
  if 36 - 36: i1IIi . O0 . OoO0O00 % OOooOOo * I11i / Ii1I
  if 16 - 16: Oo0Ooo
  if 44 - 44: iIii1I11I1II1 - II111iiii . IiII . i1IIi
  if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
 if ( I1i . merge_register_requested ) : return
 if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
 if 43 - 43: I1ii11iIi11i + I11i
 if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
 if 100 - 100: IiII - OoOoOO00 / I11i
 if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
 if ( I1i . map_notify_requested and iiI != None ) :
  lisp_build_map_notify ( lisp_sockets , o0O0O0 , i111I1i1 ,
 I1i . record_count , source , sport , I1i . nonce ,
 I1i . key_id , I1i . alg_id , I1i . auth_len ,
 iiI , True )
  if 87 - 87: Oo0Ooo
 return
 if 65 - 65: ooOoO0o . I1IiiI
 if 51 - 51: IiII
 if 43 - 43: oO0o - I11i . i11iIiiIii
 if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
 if 30 - 30: I1IiiI % oO0o * OoooooooOO
 if 64 - 64: I1IiiI
 if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
 if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
def lisp_process_unicast_map_notify ( lisp_sockets , packet , source ) :
 OOo0oo0O = lisp_map_notify ( "" )
 packet = OOo0oo0O . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
  if 90 - 90: o0oOOo0O0Ooo / I1ii11iIi11i - oO0o - Ii1I - I1IiiI + I1Ii111
 OOo0oo0O . print_notify ( )
 if ( OOo0oo0O . record_count == 0 ) : return
 if 93 - 93: I1IiiI - I11i . I1IiiI - iIii1I11I1II1
 IiO0ooOoO = OOo0oo0O . eid_records
 if 3 - 3: I1Ii111 % OOooOOo . ooOoO0o / I1IiiI
 for iIi1iIIIiIiI in range ( OOo0oo0O . record_count ) :
  IiIo0oo0O = lisp_eid_record ( )
  IiO0ooOoO = IiIo0oo0O . decode ( IiO0ooOoO )
  if ( packet == None ) : return
  IiIo0oo0O . print_record ( "  " , False )
  i1iiii = IiIo0oo0O . print_eid_tuple ( )
  if 76 - 76: OOooOOo . ooOoO0o * iII111i . Oo0Ooo
  if 50 - 50: I1Ii111 / Oo0Ooo * OoooooooOO % II111iiii . i11iIiiIii
  if 51 - 51: o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 93 - 93: i11iIiiIii / OoO0O00 + I1IiiI
  if 4 - 4: ooOoO0o . i11iIiiIii . i1IIi
  o0ooo0oOO0o = lisp_map_cache_lookup ( IiIo0oo0O . eid , IiIo0oo0O . eid )
  if ( o0ooo0oOO0o == None ) :
   oO0ooOOO = green ( i1iiii , False )
   lprint ( "Ignoring Map-Notify EID {}, no subscribe-request entry" . format ( oO0ooOOO ) )
   if 37 - 37: i11iIiiIii + OoO0O00 * Ii1I
   continue
   if 100 - 100: IiII . I1Ii111 + II111iiii + i1IIi
   if 37 - 37: iII111i
   if 27 - 27: iII111i / Ii1I / iII111i + OoooooooOO - O0 + OoO0O00
   if 62 - 62: iIii1I11I1II1
   if 60 - 60: Oo0Ooo % IiII % OoO0O00 - i11iIiiIii
   if 53 - 53: i11iIiiIii + OoooooooOO
   if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
  if ( o0ooo0oOO0o . action != LISP_SEND_PUBSUB_ACTION ) :
   if ( o0ooo0oOO0o . subscribed_eid == None ) :
    oO0ooOOO = green ( i1iiii , False )
    lprint ( "Ignoring Map-Notify for non-subscribed EID {}" . format ( oO0ooOOO ) )
    if 79 - 79: II111iiii / OoooooooOO
    continue
    if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
    if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
    if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
    if 17 - 17: I1Ii111
    if 2 - 2: O0 % OoOoOO00 + oO0o
    if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
    if 51 - 51: IiII
    if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
  II1iii11I = [ ]
  if ( o0ooo0oOO0o . action == LISP_SEND_PUBSUB_ACTION ) :
   o0ooo0oOO0o = lisp_mapping ( IiIo0oo0O . eid , IiIo0oo0O . group , [ ] )
   o0ooo0oOO0o . add_cache ( )
   IIiiiii1I = copy . deepcopy ( IiIo0oo0O . eid )
   ooO0oo000 = copy . deepcopy ( IiIo0oo0O . group )
  else :
   IIiiiii1I = o0ooo0oOO0o . subscribed_eid
   ooO0oo000 = o0ooo0oOO0o . subscribed_group
   II1iii11I = o0ooo0oOO0o . rloc_set
   o0ooo0oOO0o . delete_rlocs_from_rloc_probe_list ( )
   o0ooo0oOO0o . rloc_set = [ ]
   if 74 - 74: I11i / OoOoOO00 - i1IIi
   if 93 - 93: o0oOOo0O0Ooo / i11iIiiIii % I1IiiI - OoooooooOO
   if 96 - 96: I1ii11iIi11i - OoO0O00 * Oo0Ooo . oO0o + OoO0O00
   if 5 - 5: iIii1I11I1II1
   if 14 - 14: iII111i
  o0ooo0oOO0o . mapping_source = None if source == "lisp-itr" else source
  o0ooo0oOO0o . map_cache_ttl = IiIo0oo0O . store_ttl ( )
  o0ooo0oOO0o . subscribed_eid = IIiiiii1I
  o0ooo0oOO0o . subscribed_group = ooO0oo000
  if 66 - 66: oO0o % i1IIi % OoooooooOO
  if 58 - 58: OOooOOo
  if 89 - 89: iIii1I11I1II1 - i1IIi
  if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
  if 9 - 9: I1Ii111 / II111iiii * I1Ii111 / I11i - OoO0O00
  if ( len ( II1iii11I ) != 0 and IiIo0oo0O . rloc_count == 0 ) :
   o0ooo0oOO0o . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , o0ooo0oOO0o )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( i1iiii , False ) ) )
   if 36 - 36: IiII . OoOoOO00 . Ii1I
   continue
   if 31 - 31: iIii1I11I1II1
   if 84 - 84: I1ii11iIi11i - iII111i * I1IiiI
   if 88 - 88: OOooOOo / Oo0Ooo
   if 31 - 31: II111iiii
   if 32 - 32: o0oOOo0O0Ooo % o0oOOo0O0Ooo
   if 67 - 67: IiII + oO0o * IiII
   if 26 - 26: I1ii11iIi11i + i1IIi . i1IIi - oO0o + I1IiiI * o0oOOo0O0Ooo
  Iii11Ii = o00000o = 0
  for iI1iII1II1 in range ( IiIo0oo0O . rloc_count ) :
   IiiI1 = lisp_rloc_record ( )
   IiO0ooOoO = IiiI1 . decode ( IiO0ooOoO , None )
   IiiI1 . print_record ( "    " )
   if 16 - 16: I1IiiI . Ii1I
   if 80 - 80: OOooOOo * O0 / iIii1I11I1II1 / IiII / OoOoOO00
   if 15 - 15: I1ii11iIi11i * iII111i + i11iIiiIii
   if 68 - 68: i1IIi / oO0o * I1ii11iIi11i - OoOoOO00 + Oo0Ooo / O0
   ooo0o00o0Oooo = False
   for O00o00o00OO0 in II1iii11I :
    if ( O00o00o00OO0 . rloc . is_exact_match ( IiiI1 . rloc ) ) :
     ooo0o00o0Oooo = True
     break
     if 1 - 1: ooOoO0o - Oo0Ooo + I1Ii111
     if 90 - 90: I1Ii111 * O0 . iII111i - Oo0Ooo % iIii1I11I1II1
   if ( ooo0o00o0Oooo ) :
    I1Ii1i111I = copy . deepcopy ( O00o00o00OO0 )
    o00000o += 1
   else :
    I1Ii1i111I = lisp_rloc ( )
    Iii11Ii += 1
    if 7 - 7: I1ii11iIi11i % o0oOOo0O0Ooo % O0 % iIii1I11I1II1
    if 10 - 10: OoooooooOO - iII111i . i1IIi % oO0o . OoooooooOO + OOooOOo
    if 59 - 59: I1IiiI * OoooooooOO % OOooOOo / I11i
    if 77 - 77: II111iiii - IiII % OOooOOo
    if 22 - 22: OoooooooOO / oO0o
   I1Ii1i111I . store_rloc_from_record ( IiiI1 , None , o0ooo0oOO0o . mapping_source )
   o0ooo0oOO0o . rloc_set . append ( I1Ii1i111I )
   if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
   if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
  lprint ( "Update {} map-cache entry with {}/{} new/replaced RLOCs" . format ( green ( i1iiii , False ) , Iii11Ii , o00000o ) )
  if 12 - 12: I1Ii111
  if 17 - 17: I1Ii111 % oO0o + O0
  if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
  if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
  if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
  o0ooo0oOO0o . build_best_rloc_set ( )
  lisp_write_ipc_map_cache ( True , o0ooo0oOO0o )
  if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
  if 39 - 39: OoOoOO00 - I1ii11iIi11i / I1Ii111
  if 48 - 48: IiII - oO0o + I11i % o0oOOo0O0Ooo
  if 81 - 81: Oo0Ooo . I1Ii111 * iIii1I11I1II1
  if 60 - 60: OoooooooOO
  if 41 - 41: iIii1I11I1II1 + O0 % o0oOOo0O0Ooo - IiII . I11i * O0
 I11i1IiIi1II1 = lisp_get_map_server ( source )
 if ( I11i1IiIi1II1 == None ) :
  lprint ( "Cannot find Map-Server for Map-Notify source address {}" . format ( source . print_address_no_iid ( ) ) )
  if 39 - 39: i11iIiiIii . Ii1I
  return
  if 68 - 68: OOooOOo * ooOoO0o . I1IiiI - iII111i
 lisp_send_map_notify_ack ( lisp_sockets , IiO0ooOoO , OOo0oo0O , I11i1IiIi1II1 )
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
def lisp_process_multicast_map_notify ( packet , source ) :
 OOo0oo0O = lisp_map_notify ( "" )
 packet = OOo0oo0O . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 95 - 95: oO0o / Ii1I + OoO0O00
  if 57 - 57: iIii1I11I1II1 + I1Ii111 % oO0o - Ii1I . I1IiiI
 OOo0oo0O . print_notify ( )
 if ( OOo0oo0O . record_count == 0 ) : return
 if 39 - 39: OoO0O00 + II111iiii
 IiO0ooOoO = OOo0oo0O . eid_records
 if 98 - 98: O0 - I1Ii111 % oO0o - iII111i + Ii1I * i1IIi
 for iIi1iIIIiIiI in range ( OOo0oo0O . record_count ) :
  IiIo0oo0O = lisp_eid_record ( )
  IiO0ooOoO = IiIo0oo0O . decode ( IiO0ooOoO )
  if ( packet == None ) : return
  IiIo0oo0O . print_record ( "  " , False )
  if 76 - 76: o0oOOo0O0Ooo
  if 55 - 55: OOooOOo + I1ii11iIi11i * Oo0Ooo
  if 11 - 11: i1IIi - OoooooooOO * OoOoOO00 / oO0o - OoooooooOO - I1IiiI
  if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
  o0ooo0oOO0o = lisp_map_cache_lookup ( IiIo0oo0O . eid , IiIo0oo0O . group )
  if ( o0ooo0oOO0o == None ) :
   i1i1Ii , iIiiiI1 , II11iiiII1Ii = lisp_allow_gleaning ( IiIo0oo0O . eid , IiIo0oo0O . group ,
 None )
   if ( i1i1Ii == False ) : continue
   if 64 - 64: I1IiiI
   o0ooo0oOO0o = lisp_mapping ( IiIo0oo0O . eid , IiIo0oo0O . group , [ ] )
   o0ooo0oOO0o . add_cache ( )
   if 41 - 41: ooOoO0o . I1ii11iIi11i . II111iiii * i1IIi - OoOoOO00
   if 54 - 54: I1ii11iIi11i
   if 73 - 73: I11i
   if 78 - 78: i11iIiiIii - OoOoOO00 * IiII % Ii1I
   if 95 - 95: iIii1I11I1II1 - iII111i / I1ii11iIi11i
   if 56 - 56: OoOoOO00 % iIii1I11I1II1 * OoO0O00
   if 58 - 58: I1IiiI
  if ( o0ooo0oOO0o . gleaned ) :
   lprint ( "Ignore Map-Notify for gleaned {}" . format ( green ( o0ooo0oOO0o . print_eid_tuple ( ) , False ) ) )
   if 17 - 17: O0 * i11iIiiIii
   continue
   if 40 - 40: OoO0O00 - i11iIiiIii / O0 % o0oOOo0O0Ooo
   if 14 - 14: Oo0Ooo % O0 % O0 . o0oOOo0O0Ooo
  o0ooo0oOO0o . mapping_source = None if source == "lisp-etr" else source
  o0ooo0oOO0o . map_cache_ttl = IiIo0oo0O . store_ttl ( )
  if 34 - 34: i11iIiiIii + O0
  if 3 - 3: iIii1I11I1II1
  if 15 - 15: Oo0Ooo / IiII % i11iIiiIii * I11i . iIii1I11I1II1
  if 97 - 97: I1Ii111
  if 55 - 55: Oo0Ooo
  if ( len ( o0ooo0oOO0o . rloc_set ) != 0 and IiIo0oo0O . rloc_count == 0 ) :
   o0ooo0oOO0o . rloc_set = [ ]
   o0ooo0oOO0o . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , o0ooo0oOO0o )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( o0ooo0oOO0o . print_eid_tuple ( ) , False ) ) )
   if 20 - 20: i11iIiiIii - Oo0Ooo
   continue
   if 47 - 47: iII111i * ooOoO0o . I1IiiI / O0
   if 81 - 81: iII111i + I11i - I1ii11iIi11i + iIii1I11I1II1 / ooOoO0o
  ooOo0O0oo = o0ooo0oOO0o . rtrs_in_rloc_set ( )
  if 86 - 86: I1IiiI - OoooooooOO . I11i / O0 * o0oOOo0O0Ooo
  if 97 - 97: I1IiiI
  if 80 - 80: OOooOOo . oO0o * i11iIiiIii * IiII
  if 30 - 30: iIii1I11I1II1 - ooOoO0o / iIii1I11I1II1 / I1IiiI + OoOoOO00 - iIii1I11I1II1
  if 69 - 69: i11iIiiIii . O0
  for iI1iII1II1 in range ( IiIo0oo0O . rloc_count ) :
   IiiI1 = lisp_rloc_record ( )
   IiO0ooOoO = IiiI1 . decode ( IiO0ooOoO , None )
   IiiI1 . print_record ( "    " )
   if ( IiIo0oo0O . group . is_null ( ) ) : continue
   if ( IiiI1 . rle == None ) : continue
   if 21 - 21: i1IIi . OoO0O00 % I11i + II111iiii % o0oOOo0O0Ooo
   if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
   if 44 - 44: I1ii11iIi11i
   if 39 - 39: iII111i + Oo0Ooo / oO0o
   if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
   ooo0oOooOO0o0 = o0ooo0oOO0o . rloc_set [ 0 ] . stats if len ( o0ooo0oOO0o . rloc_set ) != 0 else None
   if 91 - 91: II111iiii + I11i + i1IIi
   if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
   if 97 - 97: oO0o % iIii1I11I1II1
   if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
   I1Ii1i111I = lisp_rloc ( )
   I1Ii1i111I . store_rloc_from_record ( IiiI1 , None , o0ooo0oOO0o . mapping_source )
   if ( ooo0oOooOO0o0 != None ) : I1Ii1i111I . stats = copy . deepcopy ( ooo0oOooOO0o0 )
   if 16 - 16: I1IiiI
   if ( ooOo0O0oo and I1Ii1i111I . is_rtr ( ) == False ) : continue
   if 39 - 39: ooOoO0o * II111iiii
   o0ooo0oOO0o . rloc_set = [ I1Ii1i111I ]
   o0ooo0oOO0o . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , o0ooo0oOO0o )
   if 90 - 90: OoooooooOO * ooOoO0o
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( o0ooo0oOO0o . print_eid_tuple ( ) , False ) ,
   # i1IIi
 I1Ii1i111I . rle . print_rle ( False , True ) ) )
   if 79 - 79: I1IiiI / OoO0O00
   if 81 - 81: o0oOOo0O0Ooo % Ii1I * Ii1I % I1IiiI % iIii1I11I1II1 * i11iIiiIii
 return
 if 79 - 79: o0oOOo0O0Ooo % iIii1I11I1II1
 if 24 - 24: O0 - I1Ii111 - OoOoOO00 % i11iIiiIii
 if 92 - 92: O0 . o0oOOo0O0Ooo % iII111i - Oo0Ooo / OoooooooOO - O0
 if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
 if 90 - 90: i11iIiiIii - iII111i * oO0o
 if 79 - 79: IiII
 if 38 - 38: I1Ii111
 if 56 - 56: i11iIiiIii
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 OOo0oo0O = lisp_map_notify ( "" )
 Oo00oo = OOo0oo0O . decode ( orig_packet )
 if ( Oo00oo == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 58 - 58: i11iIiiIii / OoOoOO00
  if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
 OOo0oo0O . print_notify ( )
 if 39 - 39: Oo0Ooo . OoO0O00
 if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
 if 100 - 100: ooOoO0o / OoooooooOO
 if 73 - 73: i11iIiiIii - Oo0Ooo
 if 100 - 100: iIii1I11I1II1 + I1Ii111
 I111 = source . print_address ( )
 if ( OOo0oo0O . alg_id != 0 or OOo0oo0O . auth_len != 0 ) :
  I11i1IiIi1II1 = None
  for Ooo00o000o in lisp_map_servers_list :
   if ( Ooo00o000o . find ( I111 ) == - 1 ) : continue
   I11i1IiIi1II1 = lisp_map_servers_list [ Ooo00o000o ]
   if 51 - 51: o0oOOo0O0Ooo * I11i
  if ( I11i1IiIi1II1 == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( I111 ) )
   if 42 - 42: OOooOOo % I11i
   return
   if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
   if 81 - 81: I1IiiI
  I11i1IiIi1II1 . map_notifies_received += 1
  if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
  OOOOoooO = lisp_verify_auth ( Oo00oo , OOo0oo0O . alg_id ,
 OOo0oo0O . auth_data , I11i1IiIi1II1 . password )
  if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if OOOOoooO else "failed" ) )
  if 83 - 83: iII111i - I1ii11iIi11i + iII111i
  if ( OOOOoooO == False ) : return
 else :
  I11i1IiIi1II1 = lisp_ms ( I111 , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
  if 60 - 60: I1ii11iIi11i / I1Ii111 % i11iIiiIii % oO0o % I1IiiI . Oo0Ooo
  if 20 - 20: IiII - OOooOOo + OoOoOO00
  if 83 - 83: OoooooooOO / I1IiiI + iII111i - iIii1I11I1II1 % ooOoO0o
  if 74 - 74: OoO0O00
  if 13 - 13: I1ii11iIi11i / OoO0O00
 IiO0ooOoO = OOo0oo0O . eid_records
 if ( OOo0oo0O . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , IiO0ooOoO , OOo0oo0O , I11i1IiIi1II1 )
  return
  if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
  if 94 - 94: IiII * i1IIi
  if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
  if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
  if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
  if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
  if 32 - 32: I1IiiI + II111iiii * iII111i + O0 / O0 * Oo0Ooo
 IiIo0oo0O = lisp_eid_record ( )
 Oo00oo = IiIo0oo0O . decode ( IiO0ooOoO )
 if ( Oo00oo == None ) : return
 if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
 IiIo0oo0O . print_record ( "  " , False )
 if 66 - 66: i1IIi
 for iI1iII1II1 in range ( IiIo0oo0O . rloc_count ) :
  IiiI1 = lisp_rloc_record ( )
  Oo00oo = IiiI1 . decode ( Oo00oo , None )
  if ( Oo00oo == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 98 - 98: Oo0Ooo / iIii1I11I1II1
  IiiI1 . print_record ( "    " )
  if 33 - 33: O0 - iII111i
  if 40 - 40: iII111i * I11i
  if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  if 87 - 87: OoOoOO00
  if 30 - 30: IiII % OoOoOO00 + I1Ii111
 if ( IiIo0oo0O . group . is_null ( ) == False ) :
  if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
  if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
  if 87 - 87: I11i
  if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
  if 72 - 72: OoO0O00 * Oo0Ooo - IiII
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( IiIo0oo0O . print_eid_tuple ( ) , False ) ) )
  if 74 - 74: Ii1I
  if 26 - 26: I11i . O0
  oOoo = lisp_control_packet_ipc ( orig_packet , I111 , "lisp-itr" , 0 )
  lisp_ipc ( oOoo , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 68 - 68: Ii1I
  if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
  if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
  if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
  if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
 lisp_send_map_notify_ack ( lisp_sockets , IiO0ooOoO , OOo0oo0O , I11i1IiIi1II1 )
 return
 if 44 - 44: I11i * iIii1I11I1II1 . I1ii11iIi11i
 if 9 - 9: o0oOOo0O0Ooo
 if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
 if 21 - 21: Ii1I * OoOoOO00
 if 29 - 29: iIii1I11I1II1 / ooOoO0o
 if 75 - 75: OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
 if 88 - 88: OoO0O00 % Ii1I
 if 12 - 12: OoooooooOO . O0
def lisp_process_map_notify_ack ( packet , source ) :
 OOo0oo0O = lisp_map_notify ( "" )
 packet = OOo0oo0O . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 33 - 33: OoooooooOO / I11i . II111iiii * i1IIi
  if 34 - 34: i11iIiiIii / OoOoOO00
 OOo0oo0O . print_notify ( )
 if 100 - 100: o0oOOo0O0Ooo - I1IiiI / I11i
 if 43 - 43: o0oOOo0O0Ooo % iIii1I11I1II1
 if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
 if 4 - 4: Ii1I . i1IIi + Oo0Ooo % I11i . OoO0O00
 if 70 - 70: OOooOOo * OoOoOO00 / OoOoOO00 / OoOoOO00
 if ( OOo0oo0O . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 23 - 23: I1IiiI
  if 24 - 24: I1Ii111 * i1IIi % O0 * Ii1I + iII111i
 IiIo0oo0O = lisp_eid_record ( )
 if 14 - 14: oO0o * iII111i + Ii1I + Ii1I * IiII
 if ( IiIo0oo0O . decode ( OOo0oo0O . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 82 - 82: IiII * ooOoO0o / OOooOOo + OoOoOO00
 IiIo0oo0O . print_record ( "  " , False )
 if 32 - 32: IiII
 i1iiii = IiIo0oo0O . print_eid_tuple ( )
 if 90 - 90: I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
 if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
 if 96 - 96: O0
 if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
 if ( OOo0oo0O . alg_id != LISP_NONE_ALG_ID and OOo0oo0O . auth_len != 0 ) :
  oOoooooOooO = lisp_sites_by_eid . lookup_cache ( IiIo0oo0O . eid , True )
  if ( oOoooooOooO == None ) :
   OOo00OO = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( OOo00OO , green ( i1iiii , False ) ) )
   if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
   return
   if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
  iiI = oOoooooOooO . site
  if 61 - 61: IiII . O0
  if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
  if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
  if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
  iiI . map_notify_acks_received += 1
  if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
  i11iII1 = OOo0oo0O . key_id
  if ( i11iII1 in iiI . auth_key ) :
   Iii = iiI . auth_key [ i11iII1 ]
  else :
   Iii = ""
   if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
   if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
  OOOOoooO = lisp_verify_auth ( packet , OOo0oo0O . alg_id ,
 OOo0oo0O . auth_data , Iii )
  if 32 - 32: OoO0O00 + OOooOOo . OoO0O00 - Oo0Ooo
  i11iII1 = "key-id {}" . format ( i11iII1 ) if i11iII1 == OOo0oo0O . key_id else "bad key-id {}" . format ( OOo0oo0O . key_id )
  if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
  if 86 - 86: OOooOOo / OoooooooOO - IiII
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if OOOOoooO else "failed" , i11iII1 ) )
  if 56 - 56: I1ii11iIi11i - i1IIi * OoooooooOO * O0 * I1IiiI - I1Ii111
  if ( OOOOoooO == False ) : return
  if 32 - 32: OoooooooOO . OOooOOo . OoO0O00 . IiII / I11i % i1IIi
  if 21 - 21: O0 . OoO0O00 * I1ii11iIi11i % iII111i + OoooooooOO
  if 8 - 8: oO0o * iII111i * I11i
  if 30 - 30: I1Ii111
  if 61 - 61: iII111i
 if ( OOo0oo0O . retransmit_timer ) : OOo0oo0O . retransmit_timer . cancel ( )
 if 50 - 50: Ii1I / I1IiiI . O0
 IiIii11I1 = source . print_address ( )
 Ooo00o000o = OOo0oo0O . nonce_key
 if 49 - 49: I1Ii111 . OoO0O00 % O0
 if ( Ooo00o000o in lisp_map_notify_queue ) :
  OOo0oo0O = lisp_map_notify_queue . pop ( Ooo00o000o )
  if ( OOo0oo0O . retransmit_timer ) : OOo0oo0O . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( Ooo00o000o ) )
  if 15 - 15: I11i - Oo0Ooo / I1Ii111 . ooOoO0o % I1IiiI
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( OOo0oo0O . nonce_key , red ( IiIii11I1 , False ) ) )
  if 62 - 62: II111iiii + ooOoO0o + I1IiiI
  if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
 return
 if 13 - 13: I1ii11iIi11i
 if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
 if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
 if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
 if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
 if 18 - 18: OoooooooOO - I1ii11iIi11i
 if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
 if 79 - 79: OOooOOo + Oo0Ooo
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 33 - 33: iIii1I11I1II1
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
 if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
 if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
 if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
 OOOo00oo0 = False
 if ( group . is_null ( ) == False ) :
  OOOo00oo0 = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 99 - 99: OOooOOo
 if ( OOOo00oo0 == False ) :
  OOOo00oo0 = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
  if 53 - 53: oO0o / i1IIi - Oo0Ooo - i1IIi + IiII
 if ( OOOo00oo0 ) :
  i1I1I1ii1i = lisp_print_eid_tuple ( eid , group )
  OOoO0O0Oo0O = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 59 - 59: iIii1I11I1II1 + I1ii11iIi11i + ooOoO0o % iIii1I11I1II1
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( i1I1I1ii1i , False ) , s ,
  # I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
 OOoO0O0Oo0O ) )
  if 74 - 74: oO0o . I1Ii111 . II111iiii
 return ( OOOo00oo0 )
 if 92 - 92: I1Ii111 % OoooooooOO * I1Ii111
 if 78 - 78: Oo0Ooo . I11i . oO0o + O0 / O0
 if 41 - 41: iII111i * OoO0O00 - OoO0O00
 if 72 - 72: o0oOOo0O0Ooo + oO0o . I1ii11iIi11i + OoO0O00 / I1Ii111
 if 58 - 58: Oo0Ooo / II111iiii % OoooooooOO % II111iiii
 if 39 - 39: i1IIi
 if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 59 - 59: i1IIi
 Ooooo = lisp_map_referral ( )
 packet = Ooooo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
 Ooooo . print_map_referral ( )
 if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
 I111 = source . print_address ( )
 oOooo0oOOOO = Ooooo . nonce
 if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
 if 71 - 71: OOooOOo
 if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
 if 73 - 73: iII111i / I1IiiI * ooOoO0o
 for iIi1iIIIiIiI in range ( Ooooo . record_count ) :
  IiIo0oo0O = lisp_eid_record ( )
  packet = IiIo0oo0O . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 85 - 85: I11i + I11i + oO0o - OoOoOO00
  IiIo0oo0O . print_record ( "  " , True )
  if 15 - 15: OoO0O00
  if 88 - 88: Ii1I % i1IIi / I1Ii111
  if 2 - 2: Ii1I . IiII % OoOoOO00
  if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
  Ooo00o000o = str ( oOooo0oOOOO )
  if ( Ooo00o000o not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( oOooo0oOOOO ) , I111 ) )
   if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
   if 35 - 35: i11iIiiIii
   continue
   if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
  OOoOo0O0O0oO = lisp_ddt_map_requestQ [ Ooo00o000o ]
  if ( OOoOo0O0O0oO == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( oOooo0oOOOO ) , I111 ) )
   if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
   continue
   if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
   if 59 - 59: i11iIiiIii . OOooOOo % Oo0Ooo + O0
   if 84 - 84: I1Ii111 / O0 - IiII . I11i / o0oOOo0O0Ooo
   if 12 - 12: i11iIiiIii / Ii1I + i1IIi
   if 54 - 54: I1IiiI
   if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
  if ( lisp_map_referral_loop ( OOoOo0O0O0oO , IiIo0oo0O . eid , IiIo0oo0O . group ,
 IiIo0oo0O . action , I111 ) ) :
   OOoOo0O0O0oO . dequeue_map_request ( )
   continue
   if 37 - 37: Oo0Ooo
   if 33 - 33: OoooooooOO - O0 . O0 - o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoO0O00
  OOoOo0O0O0oO . last_cached_prefix [ 0 ] = IiIo0oo0O . eid
  OOoOo0O0O0oO . last_cached_prefix [ 1 ] = IiIo0oo0O . group
  if 27 - 27: ooOoO0o . i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 * OoOoOO00 * oO0o
  if 19 - 19: O0 * II111iiii * OoOoOO00
  if 53 - 53: Oo0Ooo
  if 16 - 16: Ii1I
  IIIIIiiIII = False
  oo = lisp_referral_cache_lookup ( IiIo0oo0O . eid , IiIo0oo0O . group ,
 True )
  if ( oo == None ) :
   IIIIIiiIII = True
   oo = lisp_referral ( )
   oo . eid = IiIo0oo0O . eid
   oo . group = IiIo0oo0O . group
   if ( IiIo0oo0O . ddt_incomplete == False ) : oo . add_cache ( )
  elif ( oo . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( oo . print_eid_tuple ( ) , False ) ) )
   if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
   OOoOo0O0O0oO . dequeue_map_request ( )
   continue
   if 78 - 78: OoO0O00 + oO0o
   if 86 - 86: ooOoO0o . ooOoO0o + oO0o
  oo0oOooo0O = IiIo0oo0O . action
  oo . referral_source = source
  oo . referral_type = oo0oOooo0O
  IiIi1iIIiII1i = IiIo0oo0O . store_ttl ( )
  oo . referral_ttl = IiIi1iIIiII1i
  oo . expires = lisp_set_timestamp ( IiIi1iIIiII1i )
  if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
  if 31 - 31: IiII + iII111i
  if 5 - 5: O0 * Ii1I
  if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
  oOoo0 = oo . is_referral_negative ( )
  if ( I111 in oo . referral_set ) :
   OoooOO0 = oo . referral_set [ I111 ]
   if 59 - 59: oO0o
   if ( OoooOO0 . updown == False and oOoo0 == False ) :
    OoooOO0 . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( I111 ) )
    if 77 - 77: OoOoOO00
   elif ( OoooOO0 . updown == True and oOoo0 == True ) :
    OoooOO0 . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( I111 ) )
    if 20 - 20: Ii1I - Ii1I * I1Ii111 . o0oOOo0O0Ooo
    if 10 - 10: i1IIi * o0oOOo0O0Ooo
    if 77 - 77: I1IiiI
    if 22 - 22: o0oOOo0O0Ooo * II111iiii
    if 16 - 16: ooOoO0o / Oo0Ooo * Ii1I
    if 4 - 4: I1ii11iIi11i + I11i . I1ii11iIi11i * I1IiiI
    if 89 - 89: I1IiiI - IiII % O0 . i1IIi / o0oOOo0O0Ooo
    if 69 - 69: o0oOOo0O0Ooo / i11iIiiIii - oO0o + iII111i * oO0o
  oOO0O = { }
  for Ooo00o000o in oo . referral_set : oOO0O [ Ooo00o000o ] = None
  if 76 - 76: iIii1I11I1II1 % OoO0O00 / I1ii11iIi11i . I1ii11iIi11i
  if 26 - 26: IiII . Oo0Ooo + iII111i
  if 92 - 92: Oo0Ooo - I1IiiI * I1IiiI
  if 78 - 78: OoOoOO00 + OoO0O00 % oO0o + Oo0Ooo
  for iIi1iIIIiIiI in range ( IiIo0oo0O . rloc_count ) :
   IiiI1 = lisp_rloc_record ( )
   packet = IiiI1 . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 60 - 60: II111iiii / Ii1I
   IiiI1 . print_record ( "    " )
   if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
   if 89 - 89: i1IIi / I1Ii111 + Ii1I - i1IIi
   if 66 - 66: OoooooooOO
   if 68 - 68: iII111i + I1Ii111
   O0O0 = IiiI1 . rloc . print_address ( )
   if ( O0O0 not in oo . referral_set ) :
    OoooOO0 = lisp_referral_node ( )
    OoooOO0 . referral_address . copy_address ( IiiI1 . rloc )
    oo . referral_set [ O0O0 ] = OoooOO0
    if ( I111 == O0O0 and oOoo0 ) : OoooOO0 . updown = False
   else :
    OoooOO0 = oo . referral_set [ O0O0 ]
    if ( O0O0 in oOO0O ) : oOO0O . pop ( O0O0 )
    if 90 - 90: o0oOOo0O0Ooo
   OoooOO0 . priority = IiiI1 . priority
   OoooOO0 . weight = IiiI1 . weight
   if 48 - 48: iII111i + Ii1I
   if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
   if 89 - 89: OOooOOo - I1Ii111 - iII111i
   if 67 - 67: oO0o
   if 76 - 76: I1IiiI % I1IiiI - IiII / OoOoOO00 / I1ii11iIi11i
  for Ooo00o000o in oOO0O : oo . referral_set . pop ( Ooo00o000o )
  if 42 - 42: I1IiiI + I1ii11iIi11i + Oo0Ooo * i1IIi - II111iiii
  i1iiii = oo . print_eid_tuple ( )
  if 15 - 15: o0oOOo0O0Ooo
  if ( IIIIIiiIII ) :
   if ( IiIo0oo0O . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( i1iiii , False ) ) )
    if 60 - 60: I1ii11iIi11i / I1Ii111
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( i1iiii , False ) , IiIo0oo0O . rloc_count ) )
    if 13 - 13: I1Ii111
    if 52 - 52: II111iiii / OoO0O00 . Ii1I
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( i1iiii , False ) , IiIo0oo0O . rloc_count ) )
   if 68 - 68: iII111i
   if 67 - 67: I1IiiI * I1IiiI
   if 100 - 100: iII111i * iII111i . Oo0Ooo
   if 10 - 10: Oo0Ooo % ooOoO0o * Oo0Ooo
   if 48 - 48: ooOoO0o + II111iiii
   if 73 - 73: II111iiii
  if ( oo0oOooo0O == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( OOoOo0O0O0oO . lisp_sockets , oo . eid ,
 oo . group , OOoOo0O0O0oO . nonce , OOoOo0O0O0oO . itr , OOoOo0O0O0oO . sport , 15 , None , False )
   OOoOo0O0O0oO . dequeue_map_request ( )
   if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
   if 35 - 35: II111iiii + IiII
  if ( oo0oOooo0O == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( OOoOo0O0O0oO . tried_root ) :
    lisp_send_negative_map_reply ( OOoOo0O0O0oO . lisp_sockets , oo . eid ,
 oo . group , OOoOo0O0O0oO . nonce , OOoOo0O0O0oO . itr , OOoOo0O0O0oO . sport , 0 , None , False )
    OOoOo0O0O0oO . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( OOoOo0O0O0oO , True )
    if 66 - 66: o0oOOo0O0Ooo % IiII
    if 39 - 39: IiII
    if 18 - 18: iII111i % o0oOOo0O0Ooo - i1IIi
  if ( oo0oOooo0O == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( I111 in oo . referral_set ) :
    OoooOO0 = oo . referral_set [ I111 ]
    OoooOO0 . updown = False
    if 53 - 53: o0oOOo0O0Ooo + IiII - ooOoO0o % i11iIiiIii - i11iIiiIii - I1Ii111
   if ( len ( oo . referral_set ) == 0 ) :
    OOoOo0O0O0oO . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( OOoOo0O0O0oO , False )
    if 79 - 79: II111iiii + i11iIiiIii . OOooOOo . I11i / iIii1I11I1II1
    if 62 - 62: O0
    if 52 - 52: OoooooooOO . oO0o
  if ( oo0oOooo0O in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( OOoOo0O0O0oO . eid . is_exact_match ( IiIo0oo0O . eid ) ) :
    if ( not OOoOo0O0O0oO . tried_root ) :
     lisp_send_ddt_map_request ( OOoOo0O0O0oO , True )
    else :
     lisp_send_negative_map_reply ( OOoOo0O0O0oO . lisp_sockets ,
 oo . eid , oo . group , OOoOo0O0O0oO . nonce , OOoOo0O0O0oO . itr ,
 OOoOo0O0O0oO . sport , 15 , None , False )
     OOoOo0O0O0oO . dequeue_map_request ( )
     if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
   else :
    lisp_send_ddt_map_request ( OOoOo0O0O0oO , False )
    if 21 - 21: i11iIiiIii + II111iiii - i1IIi / OoooooooOO * OOooOOo % Oo0Ooo
    if 59 - 59: Ii1I
    if 77 - 77: I1ii11iIi11i * Ii1I * O0 * I1IiiI % OoO0O00 - iIii1I11I1II1
  if ( oo0oOooo0O == LISP_DDT_ACTION_MS_ACK ) : OOoOo0O0O0oO . dequeue_map_request ( )
  if 6 - 6: i11iIiiIii . I11i - OoooooooOO
 return
 if 26 - 26: I1IiiI
 if 26 - 26: IiII . Ii1I / IiII - OoO0O00 % OoO0O00
 if 72 - 72: OoooooooOO * II111iiii + OoO0O00 % iIii1I11I1II1 . I1ii11iIi11i % OoooooooOO
 if 19 - 19: OoOoOO00 + I1Ii111
 if 19 - 19: I1ii11iIi11i / I1Ii111 + OoooooooOO - O0
 if 49 - 49: I1ii11iIi11i / OoOoOO00 - I1IiiI + iII111i . OOooOOo % oO0o
 if 34 - 34: OoO0O00 - I1IiiI + OoOoOO00
 if 22 - 22: iIii1I11I1II1 . i1IIi . OOooOOo % Oo0Ooo - i1IIi
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 O0Oooo0 = lisp_ecm ( 0 )
 packet = O0Oooo0 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 78 - 78: I1IiiI / i1IIi % II111iiii % I1IiiI % Ii1I
  if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
 O0Oooo0 . print_ecm ( )
 if 38 - 38: IiII . I1Ii111
 ooo = lisp_control_header ( )
 if ( ooo . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 69 - 69: ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + Ii1I . ooOoO0o
  if 73 - 73: I11i % I11i . ooOoO0o + OoOoOO00
 Iioooo = ooo . type
 del ( ooo )
 if 14 - 14: iIii1I11I1II1 * iII111i . i1IIi - OoooooooOO
 if ( Iioooo != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 56 - 56: ooOoO0o . OoO0O00 * iIii1I11I1II1 / I11i % II111iiii . i1IIi
  if 48 - 48: I1IiiI . Oo0Ooo * o0oOOo0O0Ooo
  if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
  if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
  if 69 - 69: iII111i % I1ii11iIi11i
 iIiIi1iiII1I = O0Oooo0 . udp_sport
 I11iI = time . time ( )
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 O0Oooo0 . source , iIiIi1iiII1I , O0Oooo0 . ddt , - 1 , I11iI )
 return
 if 47 - 47: Oo0Ooo . IiII * II111iiii / ooOoO0o
 if 59 - 59: oO0o
 if 62 - 62: O0 - i11iIiiIii % OOooOOo
 if 44 - 44: I1ii11iIi11i * i1IIi - iIii1I11I1II1 - oO0o - oO0o * II111iiii
 if 98 - 98: Oo0Ooo + ooOoO0o / OOooOOo . iIii1I11I1II1 . I1IiiI . OoOoOO00
 if 92 - 92: i1IIi + OoOoOO00 * i1IIi / IiII
 if 4 - 4: oO0o % OoO0O00 + IiII + o0oOOo0O0Ooo
 if 82 - 82: O0 / I1Ii111 + OOooOOo . IiII + Ii1I
 if 31 - 31: i1IIi * OoO0O00 - Ii1I + I11i
 if 8 - 8: O0 + i1IIi . O0
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 67 - 67: I1IiiI
 if 42 - 42: ooOoO0o - o0oOOo0O0Ooo % oO0o - ooOoO0o
 if 87 - 87: OoooooooOO / O0
 if 57 - 57: iIii1I11I1II1 / IiII + OoO0O00 * oO0o + Ii1I
 if 76 - 76: i11iIiiIii . OOooOOo / I11i * oO0o % iIii1I11I1II1 . ooOoO0o
 if 75 - 75: O0 + I1IiiI
 if 67 - 67: OoOoOO00 % OoooooooOO / OoO0O00 - OoO0O00 / O0
 I1i1iiIi = ms . map_server
 if ( lisp_decent_push_configured and I1i1iiIi . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  I1i1iiIi = copy . deepcopy ( I1i1iiIi )
  I1i1iiIi . address = 0x7f000001
  I11 = bold ( "Bootstrap" , False )
  Oo = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( I11 , Oo ) )
  if 19 - 19: iIii1I11I1II1 / OOooOOo % I11i % I1IiiI / I1ii11iIi11i
  if 73 - 73: II111iiii
  if 26 - 26: II111iiii . iIii1I11I1II1 - I1Ii111 % OOooOOo
  if 83 - 83: OOooOOo + OoooooooOO % I1Ii111 % IiII + i11iIiiIii
  if 10 - 10: OoooooooOO . Ii1I % I1Ii111 + IiII
  if 78 - 78: OoOoOO00 - oO0o . I1ii11iIi11i * i11iIiiIii
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 44 - 44: iIii1I11I1II1 * iII111i
 if 32 - 32: OoOoOO00
 if 65 - 65: iIii1I11I1II1 + iII111i
 if 90 - 90: i11iIiiIii - Oo0Ooo
 if 31 - 31: OoOoOO00 + OoOoOO00 + OoooooooOO % O0
 if 14 - 14: i1IIi / OoooooooOO . I1IiiI * I1Ii111 + OoO0O00
 if ( ms . ekey != None ) :
  iI1II1I1i1 = ms . ekey . zfill ( 32 )
  OoOooO = "0" * 8
  OoO00oo0 = chacha . ChaCha ( iI1II1I1i1 , OoOooO , 20 ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + OoO00oo0
  oO0ooOOO = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( oO0ooOOO , ms . ekey_id ) )
  if 45 - 45: OoooooooOO * I1Ii111
  if 7 - 7: O0
 iI1ii = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  iI1ii = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 66 - 66: IiII + i11iIiiIii
  if 89 - 89: oO0o * I1IiiI - i1IIi - Oo0Ooo
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( I1i1iiIi . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , iI1ii ) )
 if 39 - 39: I11i * O0 + OoO0O00
 lisp_send ( lisp_sockets , I1i1iiIi , LISP_CTRL_PORT , packet )
 return
 if 42 - 42: O0 / I1IiiI * Ii1I / iIii1I11I1II1 . i1IIi / I1IiiI
 if 66 - 66: I1ii11iIi11i % I1ii11iIi11i % I1ii11iIi11i % ooOoO0o + OoOoOO00
 if 55 - 55: OoooooooOO / OoOoOO00 % Oo0Ooo * OoO0O00 . OoooooooOO . OOooOOo
 if 79 - 79: i11iIiiIii / ooOoO0o / i11iIiiIii - I1Ii111
 if 89 - 89: Oo0Ooo
 if 15 - 15: OOooOOo * II111iiii - OOooOOo * iIii1I11I1II1
 if 95 - 95: I1Ii111 / OoooooooOO * I11i * OoooooooOO
 if 88 - 88: I1IiiI / Oo0Ooo / oO0o + oO0o % OOooOOo + Oo0Ooo
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 I1 = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 63 - 63: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo % iIii1I11I1II1 / I1ii11iIi11i - iII111i
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 72 - 72: iII111i % oO0o . IiII + I1ii11iIi11i . IiII . II111iiii
 if 10 - 10: I11i . ooOoO0o + I11i * Ii1I
 packet = lisp_control_packet_ipc ( packet , I1 , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 55 - 55: OOooOOo / iII111i + OoooooooOO - OoooooooOO
 if 51 - 51: O0 % Ii1I % Oo0Ooo - O0
 if 94 - 94: OoooooooOO - ooOoO0o % I1ii11iIi11i + I1Ii111
 if 51 - 51: I1ii11iIi11i . iII111i / i1IIi * ooOoO0o % I11i
 if 82 - 82: O0 % OoOoOO00 . iII111i . i1IIi . iII111i - Oo0Ooo
 if 58 - 58: O0 * OOooOOo
 if 60 - 60: ooOoO0o
 if 47 - 47: i11iIiiIii
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 21 - 21: i1IIi - oO0o - Oo0Ooo
 if 11 - 11: i1IIi
 if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
 if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
 if 56 - 56: Ii1I . iII111i
 if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
 if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
 if 52 - 52: i11iIiiIii
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 1 - 1: i1IIi * iIii1I11I1II1
 if 29 - 29: I11i
 if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
 if 6 - 6: IiII / OoO0O00
 if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
 if 77 - 77: Ii1I
 if 9 - 9: OOooOOo / OoooooooOO + iII111i
 if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 20 - 20: I1Ii111
 if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
 if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
 if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
 if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
 if 56 - 56: iII111i * II111iiii . OoooooooOO . I11i
 if 25 - 25: ooOoO0o % o0oOOo0O0Ooo - i11iIiiIii
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 79 - 79: iII111i - I1IiiI % O0 / Oo0Ooo + OoOoOO00 . Oo0Ooo
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 59 - 59: I1ii11iIi11i * OoOoOO00 / Ii1I
  if 80 - 80: IiII - ooOoO0o / OoOoOO00 / I11i * O0 + oO0o
  if 77 - 77: ooOoO0o + I1ii11iIi11i * o0oOOo0O0Ooo / i1IIi * I11i
  if 70 - 70: oO0o / iII111i * i1IIi / II111iiii / OoOoOO00 + oO0o
  if 30 - 30: i1IIi - iII111i - i11iIiiIii . OoOoOO00 . o0oOOo0O0Ooo
  if 74 - 74: i11iIiiIii / II111iiii
 if ( lisp_nat_traversal ) :
  oooooO0oO0ooO = lisp_get_any_translated_port ( )
  if ( oooooO0oO0ooO != None ) : inner_sport = oooooO0oO0ooO
  if 62 - 62: O0
 O0Oooo0 = lisp_ecm ( inner_sport )
 if 63 - 63: Oo0Ooo + Oo0Ooo
 O0Oooo0 . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 O0Oooo0 . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 O0Oooo0 . ddt = ddt
 iI1IiI1I1111I = O0Oooo0 . encode ( packet , inner_source , inner_dest )
 if ( iI1IiI1I1111I == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 13 - 13: iII111i - O0
 O0Oooo0 . print_ecm ( )
 if 11 - 11: iIii1I11I1II1 + II111iiii % II111iiii
 packet = iI1IiI1I1111I + packet
 if 33 - 33: I1IiiI * OoooooooOO % Ii1I
 O0O0 = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( O0O0 ) )
 I1i1iiIi = lisp_convert_4to6 ( O0O0 )
 lisp_send ( lisp_sockets , I1i1iiIi , LISP_CTRL_PORT , packet )
 return
 if 79 - 79: ooOoO0o / I11i . I1ii11iIi11i
 if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
 if 81 - 81: I1Ii111 % OoO0O00 / O0
 if 55 - 55: i1IIi - I1Ii111 + I11i
 if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
 if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
 if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
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
if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 34 - 34: I1IiiI + I1Ii111 % ooOoO0o
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 24 - 24: Ii1I % II111iiii - i11iIiiIii
if 52 - 52: OoO0O00
if 76 - 76: ooOoO0o - iII111i % ooOoO0o / oO0o . OOooOOo
if 50 - 50: IiII . i11iIiiIii % I11i
if 22 - 22: i1IIi - II111iiii - OoOoOO00 . iII111i
if 43 - 43: I1Ii111 * OOooOOo - IiII . i11iIiiIii
if 34 - 34: iII111i . OoOoOO00
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
if 20 - 20: I1ii11iIi11i . iIii1I11I1II1 - Ii1I % OoO0O00
if 27 - 27: iIii1I11I1II1 / I1Ii111 - I11i . OoO0O00 + ooOoO0o
if 89 - 89: I1IiiI % I11i - OOooOOo
if 71 - 71: OOooOOo % Oo0Ooo - o0oOOo0O0Ooo / I1Ii111 - O0 - oO0o
if 10 - 10: I1IiiI
def byte_swap_64 ( address ) :
 IiI = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 17 - 17: i11iIiiIii % o0oOOo0O0Ooo . ooOoO0o
 if 34 - 34: OoooooooOO / iII111i / O0
 if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
 if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
 if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
 if 40 - 40: OOooOOo - OoooooooOO
 if 36 - 36: i1IIi % OoOoOO00 - i1IIi
 if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
 return ( IiI )
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
class lisp_cache_entries ( object ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
  if 35 - 35: o0oOOo0O0Ooo % II111iiii + O0
  if 70 - 70: I1ii11iIi11i . II111iiii
class lisp_cache ( object ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 54 - 54: OOooOOo
  if 67 - 67: I1IiiI . o0oOOo0O0Ooo / i1IIi * I1ii11iIi11i . Oo0Ooo + II111iiii
 def cache_size ( self ) :
  return ( self . cache_count )
  if 63 - 63: OoOoOO00 - OoOoOO00
  if 31 - 31: I1ii11iIi11i % O0 - i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o * ooOoO0o
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   iiiO0OO00o00Oo = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   iiiO0OO00o00Oo = prefix . mask_len
  else :
   iiiO0OO00o00Oo = prefix . mask_len + 48
   if 18 - 18: OoO0O00 - OoO0O00 . o0oOOo0O0Ooo
   if 80 - 80: I11i + I1Ii111 / I1IiiI * OOooOOo % iII111i
  oooo = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  Oooo000 = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 48 - 48: iIii1I11I1II1 + i1IIi . I1IiiI % OoO0O00 - iIii1I11I1II1 / i1IIi
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    i1iIii = prefix . addr_length ( ) * 2
    IiI = lisp_hex_string ( prefix . address ) . zfill ( i1iIii )
   else :
    IiI = prefix . address
    if 14 - 14: IiII . I11i
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   Oooo000 = "8003"
   IiI = prefix . address . print_geo ( )
  else :
   Oooo000 = ""
   IiI = ""
   if 13 - 13: OoOoOO00 - I11i . OOooOOo % OoO0O00
   if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
  Ooo00o000o = oooo + Oooo000 + IiI
  return ( [ iiiO0OO00o00Oo , Ooo00o000o ] )
  if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
  if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  iiiO0OO00o00Oo , Ooo00o000o = self . build_key ( prefix )
  if ( iiiO0OO00o00Oo not in self . cache ) :
   self . cache [ iiiO0OO00o00Oo ] = lisp_cache_entries ( )
   self . cache_sorted = self . sort_in_entry ( self . cache_sorted , iiiO0OO00o00Oo )
   if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
  if ( Ooo00o000o not in self . cache [ iiiO0OO00o00Oo ] . entries ) :
   self . cache_count += 1
   if 9 - 9: iIii1I11I1II1
  self . cache [ iiiO0OO00o00Oo ] . entries [ Ooo00o000o ] = entry
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
 def lookup_cache ( self , prefix , exact ) :
  III1iIIIi , Ooo00o000o = self . build_key ( prefix )
  if ( exact ) :
   if ( III1iIIIi not in self . cache ) : return ( None )
   if ( Ooo00o000o not in self . cache [ III1iIIIi ] . entries ) : return ( None )
   return ( self . cache [ III1iIIIi ] . entries [ Ooo00o000o ] )
   if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
   if 34 - 34: iIii1I11I1II1
  ooo0o00o0Oooo = None
  for iiiO0OO00o00Oo in self . cache_sorted :
   if ( III1iIIIi < iiiO0OO00o00Oo ) : return ( ooo0o00o0Oooo )
   for oo0O00OOOOO in list ( self . cache [ iiiO0OO00o00Oo ] . entries . values ( ) ) :
    if ( prefix . is_more_specific ( oo0O00OOOOO . eid ) ) :
     if ( ooo0o00o0Oooo == None or
 oo0O00OOOOO . eid . is_more_specific ( ooo0o00o0Oooo . eid ) ) : ooo0o00o0Oooo = oo0O00OOOOO
     if 65 - 65: II111iiii - iII111i / o0oOOo0O0Ooo
     if 35 - 35: i11iIiiIii - Oo0Ooo . I1ii11iIi11i % OoOoOO00
     if 20 - 20: OoO0O00
  return ( ooo0o00o0Oooo )
  if 93 - 93: ooOoO0o + o0oOOo0O0Ooo - I1ii11iIi11i
  if 56 - 56: Ii1I / Oo0Ooo
 def delete_cache ( self , prefix ) :
  iiiO0OO00o00Oo , Ooo00o000o = self . build_key ( prefix )
  if ( iiiO0OO00o00Oo not in self . cache ) : return
  if ( Ooo00o000o not in self . cache [ iiiO0OO00o00Oo ] . entries ) : return
  self . cache [ iiiO0OO00o00Oo ] . entries . pop ( Ooo00o000o )
  self . cache_count -= 1
  if 96 - 96: o0oOOo0O0Ooo . II111iiii
  if 14 - 14: OoooooooOO - i1IIi / i11iIiiIii - OOooOOo - i11iIiiIii . ooOoO0o
 def walk_cache ( self , function , parms ) :
  for iiiO0OO00o00Oo in self . cache_sorted :
   for oo0O00OOOOO in list ( self . cache [ iiiO0OO00o00Oo ] . entries . values ( ) ) :
    IIIiIii111iii , parms = function ( oo0O00OOOOO , parms )
    if ( IIIiIii111iii == False ) : return ( parms )
    if 77 - 77: OoOoOO00 + O0 . OoooooooOO . OoO0O00 * II111iiii + IiII
    if 51 - 51: OoOoOO00 . II111iiii
  return ( parms )
  if 54 - 54: i1IIi * iII111i % ooOoO0o
  if 15 - 15: OOooOOo - II111iiii + OoO0O00 + i1IIi * o0oOOo0O0Ooo % o0oOOo0O0Ooo
 def sort_in_entry ( self , table , value ) :
  if ( table == [ ] ) : return ( [ value ] )
  if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
  IiIi1I1i1iII = table
  while ( True ) :
   if ( len ( IiIi1I1i1iII ) == 1 ) :
    if ( value == IiIi1I1i1iII [ 0 ] ) : return ( table )
    OOOooo0OooOoO = table . index ( IiIi1I1i1iII [ 0 ] )
    if ( value < IiIi1I1i1iII [ 0 ] ) :
     return ( table [ 0 : OOOooo0OooOoO ] + [ value ] + table [ OOOooo0OooOoO : : ] )
     if 14 - 14: OOooOOo * IiII
    if ( value > IiIi1I1i1iII [ 0 ] ) :
     return ( table [ 0 : OOOooo0OooOoO + 1 ] + [ value ] + table [ OOOooo0OooOoO + 1 : : ] )
     if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
     if 33 - 33: OoO0O00
   OOOooo0OooOoO = old_div ( len ( IiIi1I1i1iII ) , 2 )
   IiIi1I1i1iII = IiIi1I1i1iII [ 0 : OOOooo0OooOoO ] if ( value < IiIi1I1i1iII [ OOOooo0OooOoO ] ) else IiIi1I1i1iII [ OOOooo0OooOoO : : ]
   if 91 - 91: I11i % I11i % iII111i
   if 19 - 19: I11i / I11i + I1IiiI * OoO0O00 - iII111i . Oo0Ooo
  return ( [ ] )
  if 76 - 76: iII111i % OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % i1IIi
  if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 38 - 38: OoOoOO00 % OoooooooOO . oO0o - OoooooooOO + I11i
  for iiiO0OO00o00Oo in self . cache_sorted :
   for Ooo00o000o in self . cache [ iiiO0OO00o00Oo ] . entries :
    oo0O00OOOOO = self . cache [ iiiO0OO00o00Oo ] . entries [ Ooo00o000o ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( iiiO0OO00o00Oo , Ooo00o000o ,
 oo0O00OOOOO ) )
    if 18 - 18: OoooooooOO + ooOoO0o * OoOoOO00 - OoO0O00
    if 42 - 42: oO0o % OoOoOO00 - oO0o + I11i / i11iIiiIii
    if 74 - 74: OoO0O00 - II111iiii - ooOoO0o % i1IIi
    if 42 - 42: i11iIiiIii / O0
    if 8 - 8: I1Ii111
    if 51 - 51: i11iIiiIii
    if 1 - 1: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i
    if 58 - 58: i11iIiiIii * i11iIiiIii - OoO0O00
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 8 - 8: i11iIiiIii * OoOoOO00 . o0oOOo0O0Ooo
if 27 - 27: I1ii11iIi11i + Ii1I % I1Ii111
if 20 - 20: Oo0Ooo
if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
if 84 - 84: OOooOOo
if 68 - 68: I1Ii111
def lisp_map_cache_lookup ( source , dest ) :
 if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
 iII1iii1iII1iI1II = dest . is_multicast_address ( )
 if 54 - 54: oO0o + I11i - OoO0O00
 if 86 - 86: OoooooooOO
 if 51 - 51: i11iIiiIii
 if 91 - 91: OOooOOo
 o0ooo0oOO0o = lisp_map_cache . lookup_cache ( dest , False )
 if ( o0ooo0oOO0o == None ) :
  i1iiii = source . print_sg ( dest ) if iII1iii1iII1iI1II else dest . print_address ( )
  i1iiii = green ( i1iiii , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( i1iiii ) )
  return ( None )
  if 22 - 22: OoooooooOO + OoOoOO00 - Ii1I . iII111i / OoooooooOO / I1IiiI
  if 73 - 73: i1IIi - Ii1I + oO0o * iIii1I11I1II1
  if 100 - 100: i11iIiiIii / iIii1I11I1II1 + Oo0Ooo + OoO0O00 - iII111i
  if 8 - 8: i11iIiiIii . O0 + o0oOOo0O0Ooo * oO0o + II111iiii
  if 61 - 61: ooOoO0o / ooOoO0o
 if ( iII1iii1iII1iI1II == False ) :
  O00000ooO0OOo = green ( o0ooo0oOO0o . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , O00000ooO0OOo ) )
  if 51 - 51: iIii1I11I1II1 / oO0o * I1Ii111 + i1IIi
  return ( o0ooo0oOO0o )
  if 96 - 96: Oo0Ooo + oO0o - Oo0Ooo - OoOoOO00 % OOooOOo . iIii1I11I1II1
  if 93 - 93: iIii1I11I1II1 % OoooooooOO
  if 6 - 6: II111iiii / oO0o - OOooOOo . O0 - o0oOOo0O0Ooo
  if 72 - 72: iIii1I11I1II1 / OoooooooOO * ooOoO0o / ooOoO0o % O0 + IiII
  if 96 - 96: iII111i / i11iIiiIii + Oo0Ooo . I1IiiI + iII111i % OoOoOO00
 o0ooo0oOO0o = o0ooo0oOO0o . lookup_source_cache ( source , False )
 if ( o0ooo0oOO0o == None ) :
  i1iiii = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( i1iiii ) )
  return ( None )
  if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
  if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
  if 87 - 87: iII111i
  if 86 - 86: IiII - I11i
  if 99 - 99: i1IIi + I1ii11iIi11i
 O00000ooO0OOo = green ( o0ooo0oOO0o . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , O00000ooO0OOo ) )
 if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
 return ( o0ooo0oOO0o )
 if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
 if 44 - 44: II111iiii / I1ii11iIi11i
 if 39 - 39: OoooooooOO % OoO0O00
 if 83 - 83: OOooOOo % I1IiiI + O0 % OoooooooOO
 if 84 - 84: I11i - Oo0Ooo % ooOoO0o - II111iiii
 if 29 - 29: IiII
 if 4 - 4: II111iiii * o0oOOo0O0Ooo - IiII * iII111i
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  OO0oO0O = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( OO0oO0O )
  if 91 - 91: I1Ii111 * iII111i * OoO0O00
  if 79 - 79: iII111i + oO0o
  if 19 - 19: I1Ii111 - OOooOOo . ooOoO0o . O0 + II111iiii . OoooooooOO
  if 97 - 97: O0 / OoOoOO00 / ooOoO0o
  if 11 - 11: II111iiii . i11iIiiIii - Ii1I . IiII
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 10 - 10: OOooOOo * OoooooooOO
 if 12 - 12: II111iiii - O0 . i1IIi % oO0o % OoooooooOO
 if 36 - 36: IiII * OoOoOO00 - iIii1I11I1II1 + II111iiii
 if 65 - 65: I1IiiI * I11i . I1Ii111 % I1ii11iIi11i + O0
 if 91 - 91: OoooooooOO % I1Ii111 * OoO0O00 - OoOoOO00
 if 5 - 5: iIii1I11I1II1 * I11i - oO0o % oO0o % o0oOOo0O0Ooo . i1IIi
 OO0oO0O = lisp_referral_cache . lookup_cache ( group , exact )
 if ( OO0oO0O == None ) : return ( None )
 if 95 - 95: Oo0Ooo * I1ii11iIi11i + iII111i - o0oOOo0O0Ooo - Oo0Ooo . OoO0O00
 oOOo0OOo00 = OO0oO0O . lookup_source_cache ( eid , exact )
 if ( oOOo0OOo00 ) : return ( oOOo0OOo00 )
 if 43 - 43: I1Ii111 + I1Ii111 % Oo0Ooo % OoO0O00 - ooOoO0o
 if ( exact ) : OO0oO0O = None
 return ( OO0oO0O )
 if 61 - 61: OoOoOO00 + Ii1I % i11iIiiIii - I1IiiI * OoO0O00 % iIii1I11I1II1
 if 66 - 66: iII111i + i1IIi
 if 24 - 24: O0 / OoooooooOO - OoOoOO00
 if 51 - 51: OoO0O00 + o0oOOo0O0Ooo - II111iiii * I11i + Ii1I
 if 16 - 16: I1Ii111 * i1IIi . I1IiiI . OOooOOo % Ii1I - o0oOOo0O0Ooo
 if 89 - 89: Ii1I * I1ii11iIi11i * I1IiiI % iII111i % Ii1I + O0
 if 53 - 53: i11iIiiIii % I1ii11iIi11i
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  O000oO0Oo0 = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( O000oO0Oo0 )
  if 59 - 59: OOooOOo
  if 61 - 61: OoooooooOO + O0 - i1IIi % oO0o / I1ii11iIi11i
  if 50 - 50: oO0o + II111iiii * OoOoOO00 % OoO0O00 . II111iiii % o0oOOo0O0Ooo
  if 32 - 32: i1IIi / Ii1I + i11iIiiIii % oO0o
  if 11 - 11: Ii1I - ooOoO0o % i11iIiiIii / OoooooooOO - O0 - IiII
 if ( eid . is_null ( ) ) : return ( None )
 if 25 - 25: IiII + O0 + oO0o % iIii1I11I1II1 - II111iiii . I1IiiI
 if 62 - 62: IiII . O0 + oO0o - ooOoO0o * iIii1I11I1II1
 if 8 - 8: I1ii11iIi11i
 if 65 - 65: i11iIiiIii
 if 92 - 92: oO0o * II111iiii + I1Ii111
 if 49 - 49: II111iiii * I1IiiI * O0 / ooOoO0o * IiII
 O000oO0Oo0 = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( O000oO0Oo0 == None ) : return ( None )
 if 94 - 94: OoO0O00 - I1IiiI * oO0o
 i1Ii = O000oO0Oo0 . lookup_source_cache ( eid , exact )
 if ( i1Ii ) : return ( i1Ii )
 if 42 - 42: i11iIiiIii + OoO0O00
 if ( exact ) : O000oO0Oo0 = None
 return ( O000oO0Oo0 )
 if 30 - 30: iII111i / iII111i
 if 1 - 1: Oo0Ooo . OoOoOO00 + OOooOOo % iII111i - OOooOOo - OoOoOO00
 if 63 - 63: O0 / iIii1I11I1II1 % II111iiii * II111iiii * I1ii11iIi11i
 if 69 - 69: i11iIiiIii + i11iIiiIii
 if 27 - 27: O0 % i11iIiiIii - I1Ii111 * oO0o - I11i / Oo0Ooo
 if 78 - 78: O0 * i11iIiiIii
 if 62 - 62: OoO0O00 * I1Ii111 * Ii1I / ooOoO0o
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 27 - 27: oO0o . iII111i . oO0o
 if ( group . is_null ( ) ) :
  oOoooooOooO = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( oOoooooOooO )
  if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
  if 14 - 14: I11i + ooOoO0o . oO0o * I11i
  if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
  if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
  if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
 if ( eid . is_null ( ) ) : return ( None )
 if 33 - 33: I11i
 if 37 - 37: Oo0Ooo
 if 36 - 36: IiII % I11i
 if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
 if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
 if 82 - 82: OoooooooOO
 oOoooooOooO = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( oOoooooOooO == None ) : return ( None )
 if 14 - 14: OoO0O00 / oO0o - OOooOOo
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
 O0oO = oOoooooOooO . lookup_source_cache ( eid , exact )
 if ( O0oO ) : return ( O0oO )
 if 44 - 44: OoooooooOO
 if ( exact ) :
  oOoooooOooO = None
 else :
  oO0oOooo = oOoooooOooO . parent_for_more_specifics
  if ( oO0oOooo and oO0oOooo . accept_more_specifics ) :
   if ( group . is_more_specific ( oO0oOooo . group ) ) : oOoooooOooO = oO0oOooo
   if 18 - 18: i11iIiiIii
   if 65 - 65: i1IIi . iIii1I11I1II1 % iIii1I11I1II1
 return ( oOoooooOooO )
 if 35 - 35: iIii1I11I1II1 - o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - OOooOOo . o0oOOo0O0Ooo
 if 12 - 12: iIii1I11I1II1 % OoO0O00 * Oo0Ooo
 if 5 - 5: I11i - II111iiii * iIii1I11I1II1 / iIii1I11I1II1 % IiII * i1IIi
 if 30 - 30: i1IIi % I1IiiI . OOooOOo % iIii1I11I1II1 . I1ii11iIi11i / o0oOOo0O0Ooo
 if 53 - 53: OOooOOo % ooOoO0o
 if 94 - 94: OOooOOo - O0 - I1Ii111 / OoooooooOO - iII111i
 if 83 - 83: OOooOOo * I1ii11iIi11i * iII111i * I1ii11iIi11i . OoO0O00
 if 87 - 87: ooOoO0o . O0 - oO0o
 if 75 - 75: Oo0Ooo
 if 22 - 22: oO0o * I1Ii111 . II111iiii / Ii1I * O0
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
class lisp_address ( object ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 84 - 84: I1IiiI . I1IiiI
  if 82 - 82: OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1 + I1ii11iIi11i
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 45 - 45: iII111i . oO0o * iII111i
  if 3 - 3: OoOoOO00 / Oo0Ooo - Oo0Ooo
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 54 - 54: Oo0Ooo . OoO0O00 * I1IiiI % IiII
  if 97 - 97: o0oOOo0O0Ooo + Ii1I
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 77 - 77: I11i - oO0o . Ii1I
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 75 - 75: I11i * OoooooooOO % OoOoOO00 . i1IIi - Ii1I + iIii1I11I1II1
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 74 - 74: ooOoO0o
   if 18 - 18: iIii1I11I1II1 - I11i - oO0o
   if 12 - 12: O0 + O0 + ooOoO0o . I1IiiI * II111iiii
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 47 - 47: i11iIiiIii % OOooOOo / ooOoO0o . IiII - I1IiiI
  if 10 - 10: Oo0Ooo / ooOoO0o / I1ii11iIi11i
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  IiI = self . address
  if ( ( ( IiI & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( IiI & 0xff000000 ) >> 24 ) == 172 ) :
   ooO0o00Oo = ( IiI & 0x00ff0000 ) >> 16
   if ( ooO0o00Oo >= 16 and ooO0o00Oo <= 31 ) : return ( True )
   if 70 - 70: I1IiiI . I1IiiI - OoooooooOO - I11i
  if ( ( ( IiI & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 38 - 38: i1IIi + oO0o * ooOoO0o % Ii1I % ooOoO0o
  if 80 - 80: OoO0O00 + OoOoOO00 % iII111i % OoooooooOO - ooOoO0o
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 25 - 25: OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - Oo0Ooo . O0
  if 48 - 48: I1IiiI + oO0o % i11iIiiIii % iIii1I11I1II1
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 14 - 14: iIii1I11I1II1
  return ( 0 )
  if 78 - 78: I1Ii111 / Oo0Ooo - I1Ii111
  if 1 - 1: OoO0O00 - I1IiiI * o0oOOo0O0Ooo
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  IiI = self . address >> 96
  return ( IiI == 0x20010005 )
  if 84 - 84: OoO0O00 % OoooooooOO
  if 66 - 66: OoOoOO00 . iII111i
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
   if 1 - 1: iII111i * i1IIi . iIii1I11I1II1 % O0 - OoooooooOO
  return ( 0 )
  if 87 - 87: iII111i . Oo0Ooo * i11iIiiIii % o0oOOo0O0Ooo + Ii1I
  if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
  if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
 def packet_format ( self ) :
  if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
  if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
  if 90 - 90: II111iiii + OOooOOo % I1Ii111 * iIii1I11I1II1 % iIii1I11I1II1
  if 55 - 55: II111iiii % O0 * O0 - II111iiii * I1IiiI % Oo0Ooo
  if 48 - 48: I1ii11iIi11i + OoooooooOO % i1IIi
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 46 - 46: OoOoOO00
  if 75 - 75: I1IiiI
 def pack_address ( self ) :
  II111I11iI = self . packet_format ( )
  Oo00oo = b""
  if ( self . is_ipv4 ( ) ) :
   Oo00oo = struct . pack ( II111I11iI , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   IiIiI = byte_swap_64 ( self . address >> 64 )
   iI1Ii11 = byte_swap_64 ( self . address & 0xffffffffffffffff )
   Oo00oo = struct . pack ( II111I11iI , IiIiI , iI1Ii11 )
  elif ( self . is_mac ( ) ) :
   IiI = self . address
   IiIiI = ( IiI >> 32 ) & 0xffff
   iI1Ii11 = ( IiI >> 16 ) & 0xffff
   Ii1II111i1 = IiI & 0xffff
   Oo00oo = struct . pack ( II111I11iI , IiIiI , iI1Ii11 , Ii1II111i1 )
  elif ( self . is_e164 ( ) ) :
   IiI = self . address
   IiIiI = ( IiI >> 32 ) & 0xffffffff
   iI1Ii11 = ( IiI & 0xffffffff )
   Oo00oo = struct . pack ( II111I11iI , IiIiI , iI1Ii11 )
  elif ( self . is_dist_name ( ) ) :
   Oo00oo += ( self . address + "\0" ) . encode ( )
   if 5 - 5: II111iiii
  return ( Oo00oo )
  if 18 - 18: O0 * ooOoO0o
  if 32 - 32: OoooooooOO - ooOoO0o % O0 + oO0o - OoooooooOO - O0
 def unpack_address ( self , packet ) :
  II111I11iI = self . packet_format ( )
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 7 - 7: ooOoO0o
  IiI = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  if 17 - 17: Ii1I . OOooOOo - O0 / OoO0O00 % II111iiii
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( IiI [ 0 ] )
   if 5 - 5: iIii1I11I1II1 % OoOoOO00 % OOooOOo % O0 * oO0o . iIii1I11I1II1
  elif ( self . is_ipv6 ( ) ) :
   if 96 - 96: i11iIiiIii + oO0o / I1ii11iIi11i . IiII % o0oOOo0O0Ooo
   if 41 - 41: o0oOOo0O0Ooo . i1IIi - OOooOOo
   if 19 - 19: o0oOOo0O0Ooo % I1Ii111 % I11i
   if 1 - 1: I1IiiI / o0oOOo0O0Ooo - I1Ii111
   if 50 - 50: I11i - OoOoOO00 + I1IiiI % Oo0Ooo / OoooooooOO - I1ii11iIi11i
   if 26 - 26: IiII . Ii1I
   if 35 - 35: I1ii11iIi11i + OOooOOo
   if 88 - 88: O0
   if ( IiI [ 0 ] <= 0xffff and ( IiI [ 0 ] & 0xff ) == 0 ) :
    II1iiiIiiI = ( IiI [ 0 ] << 48 ) << 64
   else :
    II1iiiIiiI = byte_swap_64 ( IiI [ 0 ] ) << 64
    if 29 - 29: Ii1I % o0oOOo0O0Ooo - Ii1I
   Ii1iiiIi1ii1 = byte_swap_64 ( IiI [ 1 ] )
   self . address = II1iiiIiiI | Ii1iiiIi1ii1
   if 48 - 48: O0 % i1IIi
  elif ( self . is_mac ( ) ) :
   oOo0oOoO0Oo = IiI [ 0 ]
   IiiOO0o00Oo0Oo = IiI [ 1 ]
   iIO0oOO0Oo = IiI [ 2 ]
   self . address = ( oOo0oOoO0Oo << 32 ) + ( IiiOO0o00Oo0Oo << 16 ) + iIO0oOO0Oo
   if 94 - 94: iII111i . I1Ii111 / OoO0O00 / oO0o
  elif ( self . is_e164 ( ) ) :
   self . address = ( IiI [ 0 ] << 32 ) + IiI [ 1 ]
   if 31 - 31: i11iIiiIii / o0oOOo0O0Ooo . OOooOOo + II111iiii
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   oO000 = 0
   if 14 - 14: Ii1I + OoooooooOO - I1Ii111 + I1Ii111 % IiII % OoooooooOO
  packet = packet [ oO000 : : ]
  return ( packet )
  if 24 - 24: I1Ii111 . Oo0Ooo / ooOoO0o * O0
  if 85 - 85: I1IiiI - OOooOOo
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 7 - 7: i1IIi % II111iiii
  if 33 - 33: iIii1I11I1II1 . O0 . oO0o
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 69 - 69: II111iiii * O0 . ooOoO0o * IiII
  if 25 - 25: I11i - I1ii11iIi11i . I1Ii111 . OoooooooOO
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 4 - 4: IiII * OoO0O00 % I1ii11iIi11i * Ii1I . iII111i
  if 41 - 41: OoooooooOO % I11i . O0 + I1Ii111
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 67 - 67: OoOoOO00 * OOooOOo / OOooOOo / OoooooooOO
  if 67 - 67: I11i - i1IIi . OoooooooOO / iIii1I11I1II1
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 34 - 34: OoO0O00 * II111iiii
  if 43 - 43: OoOoOO00 . I1IiiI
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 44 - 44: O0 / o0oOOo0O0Ooo
  if 19 - 19: I11i
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 91 - 91: OOooOOo * OoooooooOO
  if 89 - 89: i1IIi / iII111i . I1Ii111
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 74 - 74: I1ii11iIi11i % iII111i / OoooooooOO / I1ii11iIi11i % i11iIiiIii % ooOoO0o
  if 82 - 82: OoooooooOO . o0oOOo0O0Ooo * I1ii11iIi11i % I1ii11iIi11i * Ii1I
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 83 - 83: I11i - Oo0Ooo + i11iIiiIii - i11iIiiIii
  if 64 - 64: IiII % I1IiiI / ooOoO0o
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 74 - 74: OoooooooOO
  if 22 - 22: II111iiii . O0 * I1Ii111 % OoO0O00 / OoooooooOO + I1Ii111
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 71 - 71: ooOoO0o . oO0o * OoooooooOO + iII111i - I1Ii111 . I1ii11iIi11i
  if 100 - 100: I11i + O0 - o0oOOo0O0Ooo * I1ii11iIi11i
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 94 - 94: Oo0Ooo . IiII / Ii1I / oO0o - I1IiiI
  if 77 - 77: i11iIiiIii . Ii1I - Ii1I
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 47 - 47: iII111i % OOooOOo . I1ii11iIi11i + I1ii11iIi11i . I1Ii111
  if 20 - 20: oO0o - o0oOOo0O0Ooo + I1IiiI % OoOoOO00
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 41 - 41: oO0o . ooOoO0o
  if 59 - 59: iIii1I11I1II1 - I1IiiI . ooOoO0o
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 58 - 58: I1IiiI * I1Ii111 + iII111i + iIii1I11I1II1 + I1IiiI
  if 78 - 78: Oo0Ooo + ooOoO0o
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 56 - 56: OoO0O00 / i1IIi + ooOoO0o . ooOoO0o . iII111i
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 37 - 37: iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoooooooOO + OoO0O00
  return ( False )
  if 25 - 25: I1IiiI / IiII . OOooOOo . I1ii11iIi11i % i1IIi
  if 12 - 12: O0 % O0
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 9 - 9: O0 . I1IiiI + I1ii11iIi11i / OOooOOo * I1ii11iIi11i
  if 10 - 10: IiII % o0oOOo0O0Ooo / O0 / II111iiii
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 81 - 81: Ii1I / o0oOOo0O0Ooo % OoOoOO00 . I1ii11iIi11i
  if 47 - 47: II111iiii + OOooOOo / II111iiii . OOooOOo
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 68 - 68: OoooooooOO
  if 63 - 63: I1IiiI
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 80 - 80: oO0o + iIii1I11I1II1
  if 87 - 87: I1ii11iIi11i % Ii1I . Ii1I
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 71 - 71: OoO0O00 - IiII . i1IIi * I1IiiI % I11i
  if 36 - 36: IiII * OoooooooOO . i11iIiiIii * i1IIi
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 52 - 52: IiII + ooOoO0o - II111iiii - OoooooooOO * OoO0O00 - iIii1I11I1II1
  if 38 - 38: II111iiii % iIii1I11I1II1 * IiII * OoOoOO00 % II111iiii . I1IiiI
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 35 - 35: OoooooooOO - i11iIiiIii * i11iIiiIii % Ii1I - OOooOOo . iIii1I11I1II1
  if 96 - 96: OOooOOo
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 18 - 18: oO0o . I1ii11iIi11i % oO0o
  if 43 - 43: oO0o / ooOoO0o . o0oOOo0O0Ooo . iIii1I11I1II1
  if 63 - 63: iII111i * iII111i
  if 78 - 78: iIii1I11I1II1 % iIii1I11I1II1 . iIii1I11I1II1 / Ii1I . O0 + i1IIi
  iIi1iIIIiIiI = addr_str . find ( "[" )
  iI1iII1II1 = addr_str . find ( "]" )
  if ( iIi1iIIIiIiI != - 1 and iI1iII1II1 != - 1 ) :
   self . instance_id = int ( addr_str [ iIi1iIIIiIiI + 1 : iI1iII1II1 ] )
   addr_str = addr_str [ iI1iII1II1 + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 53 - 53: Ii1I . I1ii11iIi11i - OOooOOo - ooOoO0o
    if 17 - 17: OoooooooOO / I1IiiI * ooOoO0o % I1ii11iIi11i . OoO0O00
    if 5 - 5: OoO0O00 % I1Ii111 . oO0o . Ii1I + I1IiiI
    if 95 - 95: II111iiii . iII111i - iIii1I11I1II1 / I11i + ooOoO0o * I1Ii111
    if 92 - 92: iII111i * OoooooooOO % I1IiiI / OOooOOo
    if 46 - 46: OoOoOO00
  if ( self . is_ipv4 ( ) ) :
   OO0Ooo000 = addr_str . split ( "." )
   oOO0 = int ( OO0Ooo000 [ 0 ] ) << 24
   oOO0 += int ( OO0Ooo000 [ 1 ] ) << 16
   oOO0 += int ( OO0Ooo000 [ 2 ] ) << 8
   oOO0 += int ( OO0Ooo000 [ 3 ] )
   self . address = oOO0
  elif ( self . is_ipv6 ( ) ) :
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
   if 25 - 25: I1Ii111 . Ii1I - Ii1I . o0oOOo0O0Ooo - IiII
   if 91 - 91: o0oOOo0O0Ooo % I1ii11iIi11i % OoOoOO00 * iIii1I11I1II1
   IIiI1i1I1I1i = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 4 - 4: OoO0O00 / OoOoOO00
   addr_str = binascii . hexlify ( addr_str )
   if 42 - 42: i1IIi . O0
   if ( IIiI1i1I1I1i ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 39 - 39: I1ii11iIi11i
   self . address = int ( addr_str , 16 )
   if 26 - 26: oO0o . I1Ii111 % I11i
  elif ( self . is_geo_prefix ( ) ) :
   O00o0o0O = lisp_geo ( None )
   O00o0o0O . name = "geo-prefix-{}" . format ( O00o0o0O )
   O00o0o0O . parse_geo_string ( addr_str )
   self . address = O00o0o0O
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
   if 85 - 85: II111iiii / o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO / Ii1I
  self . mask_len = self . host_mask_len ( )
  if 18 - 18: i11iIiiIii + o0oOOo0O0Ooo . i11iIiiIii
  if 50 - 50: IiII / OoooooooOO . I11i
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   OOOooo0OooOoO = prefix_str . find ( "]" )
   oOo = len ( prefix_str [ OOOooo0OooOoO + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , oOo = prefix_str . split ( "/" )
  else :
   iIi1I1 = prefix_str . find ( "'" )
   if ( iIi1I1 == - 1 ) : return
   II = prefix_str . find ( "'" , iIi1I1 + 1 )
   if ( II == - 1 ) : return
   oOo = len ( prefix_str [ iIi1I1 + 1 : II ] ) * 8
   if 93 - 93: OOooOOo / OoooooooOO % iII111i % Ii1I / I1Ii111 % OOooOOo
   if 25 - 25: i1IIi % Oo0Ooo . i1IIi * OoOoOO00 . Ii1I % OoO0O00
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( oOo )
  if 47 - 47: o0oOOo0O0Ooo - i11iIiiIii / OoooooooOO
  if 93 - 93: I1IiiI * II111iiii * O0 % o0oOOo0O0Ooo + oO0o / ooOoO0o
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  OOo00OOo0o0 = ( 2 ** self . mask_len ) - 1
  O0ooo0Oo00O00 = self . addr_length ( ) * 8 - self . mask_len
  OOo00OOo0o0 <<= O0ooo0Oo00O00
  self . address &= OOo00OOo0o0
  if 21 - 21: o0oOOo0O0Ooo . i11iIiiIii % OoooooooOO * O0
  if 52 - 52: OOooOOo / ooOoO0o . II111iiii / Oo0Ooo
 def is_geo_string ( self , addr_str ) :
  OOOooo0OooOoO = addr_str . find ( "]" )
  if ( OOOooo0OooOoO != - 1 ) : addr_str = addr_str [ OOOooo0OooOoO + 1 : : ]
  if 66 - 66: Ii1I * I1Ii111 * OoO0O00
  O00o0o0O = addr_str . split ( "/" )
  if ( len ( O00o0o0O ) == 2 ) :
   if ( O00o0o0O [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 92 - 92: II111iiii * iII111i % OoOoOO00 % OoOoOO00 % i11iIiiIii
  O00o0o0O = O00o0o0O [ 0 ]
  O00o0o0O = O00o0o0O . split ( "-" )
  O00oo0o = len ( O00o0o0O )
  if ( O00oo0o < 8 or O00oo0o > 9 ) : return ( False )
  if 48 - 48: OoooooooOO - O0 + I1IiiI - I11i
  for OoO0iI in range ( 0 , O00oo0o ) :
   if ( OoO0iI == 3 ) :
    if ( O00o0o0O [ OoO0iI ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 8 - 8: IiII * Ii1I / Ii1I * OoO0O00 . OoooooooOO . I1Ii111
   if ( OoO0iI == 7 ) :
    if ( O00o0o0O [ OoO0iI ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 18 - 18: I11i % OoooooooOO - Ii1I + IiII % II111iiii
   if ( O00o0o0O [ OoO0iI ] . isdigit ( ) == False ) : return ( False )
   if 49 - 49: IiII - o0oOOo0O0Ooo
  return ( True )
  if 3 - 3: Oo0Ooo * O0 % OoooooooOO / O0 - Ii1I . iIii1I11I1II1
  if 30 - 30: OoO0O00 + OOooOOo * i11iIiiIii - OoOoOO00 * II111iiii - oO0o
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 22 - 22: i1IIi + IiII + iII111i - I1IiiI - I11i - I11i
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 50 - 50: O0 * I1IiiI / i11iIiiIii - I11i
  if 28 - 28: i1IIi + O0 - i11iIiiIii - I1Ii111
 def print_address ( self ) :
  IiI = self . print_address_no_iid ( )
  oooo = "[" + str ( self . instance_id )
  for iIi1iIIIiIiI in self . iid_list : oooo += "," + str ( iIi1iIIIiIiI )
  oooo += "]"
  IiI = "{}{}" . format ( oooo , IiI )
  return ( IiI )
  if 54 - 54: iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
  if 18 - 18: oO0o % iIii1I11I1II1 + ooOoO0o
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   IiI = self . address
   IiiiI11I1 = IiI >> 24
   i11IIi = ( IiI >> 16 ) & 0xff
   IiiiI1i = ( IiI >> 8 ) & 0xff
   oooO0OO = IiI & 0xff
   return ( "{}.{}.{}.{}" . format ( IiiiI11I1 , i11IIi , IiiiI1i , oooO0OO ) )
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
   if 41 - 41: oO0o % II111iiii
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 61 - 61: i11iIiiIii * I11i / ooOoO0o / iIii1I11I1II1
  if 40 - 40: O0 / Ii1I - i11iIiiIii / I11i
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   OOo00oo0o = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , OOo00oo0o ) )
   if 18 - 18: i1IIi
  IiI = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( IiI )
  if ( self . is_geo_prefix ( ) ) : return ( IiI )
  if 33 - 33: iIii1I11I1II1 % ooOoO0o - I1Ii111
  OOOooo0OooOoO = IiI . find ( "no-address" )
  if ( OOOooo0OooOoO == - 1 ) :
   IiI = "{}/{}" . format ( IiI , str ( self . mask_len ) )
  else :
   IiI = IiI [ 0 : OOOooo0OooOoO ]
   if 9 - 9: I1Ii111 / OoO0O00 - OoO0O00
  return ( IiI )
  if 25 - 25: o0oOOo0O0Ooo . i11iIiiIii + I1Ii111 . iII111i
  if 23 - 23: Oo0Ooo . OoO0O00 / IiII + i11iIiiIii * OOooOOo
 def print_prefix_no_iid ( self ) :
  IiI = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( IiI )
  if ( self . is_geo_prefix ( ) ) : return ( IiI )
  return ( "{}/{}" . format ( IiI , str ( self . mask_len ) ) )
  if 27 - 27: O0 * OoO0O00 * I1ii11iIi11i
  if 40 - 40: O0 + oO0o - ooOoO0o + I1IiiI - IiII
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  IiI = self . print_address ( )
  OOOooo0OooOoO = IiI . find ( "]" )
  if ( OOOooo0OooOoO != - 1 ) : IiI = IiI [ OOOooo0OooOoO + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   IiI = IiI . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , IiI ) )
   if 60 - 60: I1Ii111 * OoO0O00 * oO0o + oO0o
  return ( "{}-{}-{}" . format ( self . instance_id , IiI , self . mask_len ) )
  if 34 - 34: o0oOOo0O0Ooo
  if 76 - 76: oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 def print_sg ( self , g ) :
  I111 = self . print_prefix ( )
  ooO0o = I111 . find ( "]" ) + 1
  g = g . print_prefix ( )
  I1IIiIII111 = g . find ( "]" ) + 1
  i1iIiIii = "[{}]({}, {})" . format ( self . instance_id , I111 [ ooO0o : : ] , g [ I1IIiIII111 : : ] )
  return ( i1iIiIii )
  if 86 - 86: ooOoO0o / iII111i . OoooooooOO + I1Ii111 + I1Ii111
  if 35 - 35: Oo0Ooo + oO0o * o0oOOo0O0Ooo - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii
 def hash_address ( self , addr ) :
  IiIiI = self . address
  iI1Ii11 = addr . address
  if 56 - 56: iIii1I11I1II1 / I11i
  if ( self . is_geo_prefix ( ) ) : IiIiI = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : iI1Ii11 = addr . address . print_geo ( )
  if 78 - 78: i11iIiiIii * OoO0O00 * Ii1I / i1IIi * OOooOOo + o0oOOo0O0Ooo
  if ( type ( IiIiI ) == str ) :
   IiIiI = int ( binascii . hexlify ( IiIiI [ 0 : 1 ] ) )
   if 52 - 52: i1IIi % O0
  if ( type ( iI1Ii11 ) == str ) :
   iI1Ii11 = int ( binascii . hexlify ( iI1Ii11 [ 0 : 1 ] ) )
   if 59 - 59: II111iiii + I1ii11iIi11i / iII111i . ooOoO0o
  return ( IiIiI ^ iI1Ii11 )
  if 18 - 18: I1Ii111
  if 40 - 40: OoOoOO00 / OOooOOo + O0
  if 57 - 57: iII111i
  if 94 - 94: i11iIiiIii
  if 90 - 90: iII111i + i11iIiiIii + iII111i % I1IiiI % oO0o
  if 71 - 71: ooOoO0o + OOooOOo * I1IiiI % I11i . I1Ii111 % OoooooooOO
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 7 - 7: iIii1I11I1II1
  oOo = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   oOO00oO0OOOoo = 2 ** ( 32 - oOo )
   IIi1 = prefix . instance_id
   OOo00oo0o = IIi1 + oOO00oO0OOOoo
   return ( self . instance_id in range ( IIi1 , OOo00oo0o ) )
   if 77 - 77: iIii1I11I1II1 % I1Ii111 + II111iiii
   if 40 - 40: I1ii11iIi11i / I1ii11iIi11i + I1IiiI + OoOoOO00
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 76 - 76: iIii1I11I1II1 . iIii1I11I1II1 / OOooOOo / OoOoOO00 / iII111i / II111iiii
   if 64 - 64: i1IIi * II111iiii + I1ii11iIi11i + OOooOOo % I1ii11iIi11i - OoooooooOO
   if 96 - 96: IiII + oO0o / Oo0Ooo + OoooooooOO
   if 53 - 53: Ii1I * IiII + Oo0Ooo + i11iIiiIii - iIii1I11I1II1
   if 66 - 66: O0 - I1ii11iIi11i * iIii1I11I1II1 - I1Ii111 / I1ii11iIi11i
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   IiI = self . address
   iIi1i1Iii1I = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    IiI = self . address . print_geo ( )
    iIi1i1Iii1I = prefix . address . print_geo ( )
    if 11 - 11: O0 % iIii1I11I1II1
   if ( len ( IiI ) < len ( iIi1i1Iii1I ) ) : return ( False )
   return ( IiI . find ( iIi1i1Iii1I ) == 0 )
   if 64 - 64: OoOoOO00 - oO0o
   if 8 - 8: i11iIiiIii - iIii1I11I1II1 / I1Ii111 . i11iIiiIii % o0oOOo0O0Ooo / oO0o
   if 36 - 36: IiII
   if 53 - 53: OoooooooOO / I1IiiI % I11i + Oo0Ooo
   if 15 - 15: O0
  if ( self . mask_len < oOo ) : return ( False )
  if 75 - 75: iII111i / OoOoOO00
  O0ooo0Oo00O00 = ( prefix . addr_length ( ) * 8 ) - oOo
  OOo00OOo0o0 = ( 2 ** oOo - 1 ) << O0ooo0Oo00O00
  return ( ( self . address & OOo00OOo0o0 ) == prefix . address )
  if 2 - 2: i1IIi + oO0o % iII111i % I1ii11iIi11i + ooOoO0o . iII111i
  if 26 - 26: I11i + o0oOOo0O0Ooo + Ii1I % I11i
 def mask_address ( self , mask_len ) :
  O0ooo0Oo00O00 = ( self . addr_length ( ) * 8 ) - mask_len
  OOo00OOo0o0 = ( 2 ** mask_len - 1 ) << O0ooo0Oo00O00
  self . address &= OOo00OOo0o0
  if 95 - 95: IiII - O0 * oO0o * O0
  if 47 - 47: I1IiiI
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  iIIiiIII1ii1I = self . print_prefix ( )
  OO0ooo = prefix . print_prefix ( ) if prefix else ""
  return ( iIIiiIII1ii1I == OO0ooo )
  if 75 - 75: i1IIi * II111iiii . II111iiii * I1Ii111 + I1Ii111
  if 25 - 25: oO0o
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   iI1iIii11i1i = lisp_myrlocs [ 0 ]
   if ( iI1iIii11i1i == None ) : return ( False )
   iI1iIii11i1i = iI1iIii11i1i . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == iI1iIii11i1i )
   if 4 - 4: O0 - IiII - II111iiii / iII111i - OOooOOo
  if ( self . is_ipv6 ( ) ) :
   iI1iIii11i1i = lisp_myrlocs [ 1 ]
   if ( iI1iIii11i1i == None ) : return ( False )
   iI1iIii11i1i = iI1iIii11i1i . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == iI1iIii11i1i )
   if 6 - 6: ooOoO0o + OOooOOo - I1IiiI + OOooOOo
  return ( False )
  if 16 - 16: OoO0O00 * OoOoOO00 - Oo0Ooo
  if 44 - 44: ooOoO0o / OoOoOO00 - O0 + iII111i / iIii1I11I1II1
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid == 0 and mask_len == 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 41 - 41: iIii1I11I1II1 - iII111i / O0
  self . instance_id = iid
  self . mask_len = mask_len
  if 39 - 39: OoooooooOO * iIii1I11I1II1 - o0oOOo0O0Ooo / O0
  if 29 - 29: I11i % OoOoOO00 - oO0o + II111iiii . II111iiii
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
  if 25 - 25: Oo0Ooo * ooOoO0o % I1Ii111
  if 34 - 34: OoOoOO00 / I1Ii111 - ooOoO0o
  if 66 - 66: I11i * OoO0O00
  if 98 - 98: IiII . Oo0Ooo + I1Ii111
  if 63 - 63: oO0o * I1IiiI * oO0o
  if 56 - 56: oO0o - Ii1I % I1Ii111
  if 100 - 100: OOooOOo * IiII % IiII / o0oOOo0O0Ooo * OoO0O00 % OoOoOO00
  if 12 - 12: I1IiiI
  if 32 - 32: I1Ii111
  if 35 - 35: O0 + II111iiii + o0oOOo0O0Ooo - OoO0O00 - Ii1I
  if 88 - 88: I1ii11iIi11i . O0 - o0oOOo0O0Ooo . I1ii11iIi11i * iII111i * I11i
  if 89 - 89: Oo0Ooo - oO0o + O0 / i11iIiiIii
  if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
  if 74 - 74: IiII - O0 % OOooOOo % OoooooooOO - I11i
  if 4 - 4: i1IIi + OoOoOO00 + iIii1I11I1II1 - i1IIi * i11iIiiIii
  if 99 - 99: I1ii11iIi11i - O0 % II111iiii + ooOoO0o % OoO0O00 * Ii1I
  if 8 - 8: OOooOOo
 def lcaf_encode_iid ( self ) :
  IIiiIIi1II11 = LISP_LCAF_INSTANCE_ID_TYPE
  I1Ii11iI11ii = socket . htons ( self . lcaf_length ( IIiiIIi1II11 ) )
  oooo = self . instance_id
  Oooo000 = self . afi
  iiiO0OO00o00Oo = 0
  if ( Oooo000 < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    Oooo000 = LISP_AFI_LCAF
    iiiO0OO00o00Oo = 0
   else :
    Oooo000 = 0
    iiiO0OO00o00Oo = self . mask_len
    if 85 - 85: O0 % OOooOOo . Ii1I
    if 74 - 74: I1ii11iIi11i - I1Ii111 + i11iIiiIii / I1Ii111 / OoooooooOO + o0oOOo0O0Ooo
    if 23 - 23: Oo0Ooo
  oOo0oO00oo0O0 = struct . pack ( "BBBBH" , 0 , 0 , IIiiIIi1II11 , iiiO0OO00o00Oo , I1Ii11iI11ii )
  oOo0oO00oo0O0 += struct . pack ( "IH" , socket . htonl ( oooo ) , socket . htons ( Oooo000 ) )
  if ( Oooo000 == 0 ) : return ( oOo0oO00oo0O0 )
  if 49 - 49: Oo0Ooo * I1ii11iIi11i . o0oOOo0O0Ooo / iIii1I11I1II1
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   oOo0oO00oo0O0 = oOo0oO00oo0O0 [ 0 : - 2 ]
   oOo0oO00oo0O0 += self . address . encode_geo ( )
   return ( oOo0oO00oo0O0 )
   if 9 - 9: I1Ii111 * II111iiii % Ii1I - Ii1I % OoO0O00 % o0oOOo0O0Ooo
   if 26 - 26: o0oOOo0O0Ooo - I1IiiI / OoooooooOO / ooOoO0o % iIii1I11I1II1 % I1ii11iIi11i
  oOo0oO00oo0O0 += self . pack_address ( )
  return ( oOo0oO00oo0O0 )
  if 6 - 6: iIii1I11I1II1 * I1ii11iIi11i / I11i % I1Ii111 / Oo0Ooo
  if 94 - 94: OoO0O00 - oO0o + iII111i . ooOoO0o * OoooooooOO
 def lcaf_decode_iid ( self , packet ) :
  II111I11iI = "BBBBH"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 42 - 42: iII111i / i11iIiiIii + II111iiii % IiII / ooOoO0o
  iIiiiI1 , II11iiiII1Ii , IIiiIIi1II11 , o0O0 , i1iIii = struct . unpack ( II111I11iI ,
 packet [ : oO000 ] )
  packet = packet [ oO000 : : ]
  if 57 - 57: ooOoO0o * oO0o + o0oOOo0O0Ooo
  if ( IIiiIIi1II11 != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 97 - 97: OoooooooOO * I1IiiI . Ii1I * I1IiiI
  II111I11iI = "IH"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( None )
  if 19 - 19: OoO0O00 + oO0o - i1IIi . IiII / OoOoOO00 / i11iIiiIii
  oooo , Oooo000 = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  packet = packet [ oO000 : : ]
  if 53 - 53: OoOoOO00 % OoooooooOO + Ii1I
  i1iIii = socket . ntohs ( i1iIii )
  self . instance_id = socket . ntohl ( oooo )
  Oooo000 = socket . ntohs ( Oooo000 )
  self . afi = Oooo000
  if ( o0O0 != 0 and Oooo000 == 0 ) : self . mask_len = o0O0
  if ( Oooo000 == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if o0O0 else LISP_AFI_ULTIMATE_ROOT
   if 85 - 85: ooOoO0o % i11iIiiIii * oO0o / ooOoO0o / I1Ii111 . i11iIiiIii
   if 23 - 23: i1IIi + I1Ii111 / Oo0Ooo * O0 . O0
   if 67 - 67: OoO0O00 - II111iiii + Ii1I
   if 41 - 41: oO0o + O0 / I1ii11iIi11i
   if 55 - 55: iIii1I11I1II1 * oO0o / iII111i / i1IIi % Oo0Ooo . OoOoOO00
  if ( Oooo000 == 0 ) : return ( packet )
  if 50 - 50: IiII / o0oOOo0O0Ooo
  if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
  if 52 - 52: O0
  if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
   if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
   if 83 - 83: oO0o / OoO0O00
   if 34 - 34: OoooooooOO - i1IIi * O0
   if 83 - 83: I1IiiI + OoO0O00
  if ( Oooo000 == LISP_AFI_LCAF ) :
   II111I11iI = "BBBBH"
   oO000 = struct . calcsize ( II111I11iI )
   if ( len ( packet ) < oO000 ) : return ( None )
   if 41 - 41: Ii1I + II111iiii . OOooOOo * I1Ii111 / II111iiii
   iI1i1II11I , OoO0o0oOOoOoo , IIiiIIi1II11 , I1iIiiiI1II1 , ii111iIii1 = struct . unpack ( II111I11iI , packet [ : oO000 ] )
   if 32 - 32: Oo0Ooo - Ii1I % o0oOOo0O0Ooo
   if 15 - 15: iIii1I11I1II1 * I1ii11iIi11i / ooOoO0o * oO0o % OOooOOo
   if ( IIiiIIi1II11 != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 62 - 62: Ii1I / Oo0Ooo . OoO0O00 - OOooOOo
   ii111iIii1 = socket . ntohs ( ii111iIii1 )
   packet = packet [ oO000 : : ]
   if ( ii111iIii1 > len ( packet ) ) : return ( None )
   if 89 - 89: o0oOOo0O0Ooo % OoO0O00
   O00o0o0O = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = O00o0o0O
   packet = O00o0o0O . decode_geo ( packet , ii111iIii1 , I1iIiiiI1II1 )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 53 - 53: OoOoOO00 . ooOoO0o - OoO0O00
   if 26 - 26: ooOoO0o - oO0o + OOooOOo * Ii1I - I11i % I1IiiI
  I1Ii11iI11ii = self . addr_length ( )
  if ( len ( packet ) < I1Ii11iI11ii ) : return ( None )
  if 73 - 73: ooOoO0o + Ii1I . O0 . iII111i
  packet = self . unpack_address ( packet )
  return ( packet )
  if 77 - 77: OOooOOo % I1IiiI - iII111i % I1Ii111
  if 29 - 29: iIii1I11I1II1 / i11iIiiIii + Oo0Ooo
  if 99 - 99: I1IiiI - iII111i * Ii1I - OoOoOO00 / i11iIiiIii - i1IIi
  if 46 - 46: I1ii11iIi11i * ooOoO0o
  if 4 - 4: I1Ii111 * II111iiii
  if 4 - 4: ooOoO0o * Oo0Ooo - I1ii11iIi11i % ooOoO0o % OoOoOO00
  if 18 - 18: OOooOOo / O0 . OoO0O00 - II111iiii * OOooOOo
  if 13 - 13: OoO0O00 % i1IIi . i11iIiiIii / iII111i
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
 def lcaf_encode_sg ( self , group ) :
  IIiiIIi1II11 = LISP_LCAF_MCAST_INFO_TYPE
  oooo = socket . htonl ( self . instance_id )
  I1Ii11iI11ii = socket . htons ( self . lcaf_length ( IIiiIIi1II11 ) )
  oOo0oO00oo0O0 = struct . pack ( "BBBBHIHBB" , 0 , 0 , IIiiIIi1II11 , 0 , I1Ii11iI11ii , oooo ,
 0 , self . mask_len , group . mask_len )
  if 41 - 41: iIii1I11I1II1
  oOo0oO00oo0O0 += struct . pack ( "H" , socket . htons ( self . afi ) )
  oOo0oO00oo0O0 += self . pack_address ( )
  oOo0oO00oo0O0 += struct . pack ( "H" , socket . htons ( group . afi ) )
  oOo0oO00oo0O0 += group . pack_address ( )
  return ( oOo0oO00oo0O0 )
  if 26 - 26: Oo0Ooo / i1IIi + Oo0Ooo
  if 76 - 76: I1ii11iIi11i * i1IIi % oO0o
 def lcaf_decode_sg ( self , packet ) :
  II111I11iI = "BBBBHIHBB"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( [ None , None ] )
  if 80 - 80: i1IIi * II111iiii . O0 % I1ii11iIi11i / ooOoO0o
  iIiiiI1 , II11iiiII1Ii , IIiiIIi1II11 , oo00O0OO0oo0O , i1iIii , oooo , OoOO0o00ooOO , O0O0Oooo0O , Ooi11I1i1IiI1i = struct . unpack ( II111I11iI , packet [ : oO000 ] )
  if 23 - 23: iIii1I11I1II1
  packet = packet [ oO000 : : ]
  if 88 - 88: I1IiiI + iII111i / Ii1I
  if ( IIiiIIi1II11 != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 57 - 57: o0oOOo0O0Ooo
  self . instance_id = socket . ntohl ( oooo )
  i1iIii = socket . ntohs ( i1iIii ) - 8
  if 69 - 69: i1IIi / i1IIi / OoOoOO00 + ooOoO0o % I1Ii111
  if 41 - 41: II111iiii * OOooOOo
  if 8 - 8: I1Ii111 + O0
  if 67 - 67: iIii1I11I1II1 . O0
  if 40 - 40: OOooOOo - ooOoO0o . OoooooooOO % O0 * I11i - I1ii11iIi11i
  II111I11iI = "H"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( [ None , None ] )
  if ( i1iIii < oO000 ) : return ( [ None , None ] )
  if 92 - 92: ooOoO0o % oO0o / i11iIiiIii
  Oooo000 = struct . unpack ( II111I11iI , packet [ : oO000 ] ) [ 0 ]
  packet = packet [ oO000 : : ]
  i1iIii -= oO000
  self . afi = socket . ntohs ( Oooo000 )
  self . mask_len = O0O0Oooo0O
  I1Ii11iI11ii = self . addr_length ( )
  if ( i1iIii < I1Ii11iI11ii ) : return ( [ None , None ] )
  if 91 - 91: OOooOOo
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 60 - 60: i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
  i1iIii -= I1Ii11iI11ii
  if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
  if 54 - 54: II111iiii * I1IiiI
  if 49 - 49: I1ii11iIi11i
  if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
  if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
  II111I11iI = "H"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( [ None , None ] )
  if ( i1iIii < oO000 ) : return ( [ None , None ] )
  if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
  Oooo000 = struct . unpack ( II111I11iI , packet [ : oO000 ] ) [ 0 ]
  packet = packet [ oO000 : : ]
  i1iIii -= oO000
  o0o0Oo0o0oOo = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  o0o0Oo0o0oOo . afi = socket . ntohs ( Oooo000 )
  o0o0Oo0o0oOo . mask_len = Ooi11I1i1IiI1i
  o0o0Oo0o0oOo . instance_id = self . instance_id
  I1Ii11iI11ii = self . addr_length ( )
  if ( i1iIii < I1Ii11iI11ii ) : return ( [ None , None ] )
  if 15 - 15: oO0o
  packet = o0o0Oo0o0oOo . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 40 - 40: I1Ii111
  return ( [ packet , o0o0Oo0o0oOo ] )
  if 77 - 77: II111iiii - o0oOOo0O0Ooo . Ii1I
  if 47 - 47: o0oOOo0O0Ooo % OOooOOo + I1Ii111
 def lcaf_decode_eid ( self , packet ) :
  II111I11iI = "BBB"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( [ None , None ] )
  if 64 - 64: ooOoO0o / IiII . I1IiiI
  if 77 - 77: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
  if 90 - 90: I11i
  if 53 - 53: I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoooooooOO + IiII * I1IiiI
  if 16 - 16: i11iIiiIii - oO0o . i11iIiiIii + OoO0O00 + i11iIiiIii
  oo00O0OO0oo0O , OoO0o0oOOoOoo , IIiiIIi1II11 = struct . unpack ( II111I11iI ,
 packet [ : oO000 ] )
  if 85 - 85: I1ii11iIi11i - ooOoO0o + I1Ii111 + I1Ii111
  if ( IIiiIIi1II11 == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( IIiiIIi1II11 == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , o0o0Oo0o0oOo = self . lcaf_decode_sg ( packet )
   return ( [ packet , o0o0Oo0o0oOo ] )
  elif ( IIiiIIi1II11 == LISP_LCAF_GEO_COORD_TYPE ) :
   II111I11iI = "BBBBH"
   oO000 = struct . calcsize ( II111I11iI )
   if ( len ( packet ) < oO000 ) : return ( None )
   if 13 - 13: II111iiii
   iI1i1II11I , OoO0o0oOOoOoo , IIiiIIi1II11 , I1iIiiiI1II1 , ii111iIii1 = struct . unpack ( II111I11iI , packet [ : oO000 ] )
   if 22 - 22: o0oOOo0O0Ooo
   if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
   if ( IIiiIIi1II11 != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 12 - 12: I1ii11iIi11i / O0
   ii111iIii1 = socket . ntohs ( ii111iIii1 )
   packet = packet [ oO000 : : ]
   if ( ii111iIii1 > len ( packet ) ) : return ( None )
   if 18 - 18: OoOoOO00 . i11iIiiIii + i1IIi / OoooooooOO - IiII % OoO0O00
   O00o0o0O = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = O00o0o0O
   packet = O00o0o0O . decode_geo ( packet , ii111iIii1 , I1iIiiiI1II1 )
   self . mask_len = self . host_mask_len ( )
   if 47 - 47: iII111i % IiII + I1Ii111 * o0oOOo0O0Ooo * OoooooooOO
  return ( [ packet , None ] )
  if 100 - 100: Oo0Ooo / I1IiiI / iII111i / I1Ii111 / oO0o % o0oOOo0O0Ooo
  if 16 - 16: I1IiiI + I11i
  if 66 - 66: OoooooooOO % II111iiii / I1Ii111 . i11iIiiIii
  if 67 - 67: Ii1I + Oo0Ooo - I1IiiI - IiII + oO0o + Oo0Ooo
  if 84 - 84: I1ii11iIi11i % oO0o - OOooOOo * Ii1I
  if 78 - 78: i1IIi / ooOoO0o / oO0o
class lisp_elp_node ( object ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 21 - 21: IiII % Ii1I + OOooOOo + IiII
  if 90 - 90: o0oOOo0O0Ooo
 def copy_elp_node ( self ) :
  i11I1iI1I = lisp_elp_node ( )
  i11I1iI1I . copy_address ( self . address )
  i11I1iI1I . probe = self . probe
  i11I1iI1I . strict = self . strict
  i11I1iI1I . eid = self . eid
  i11I1iI1I . we_are_last = self . we_are_last
  return ( i11I1iI1I )
  if 38 - 38: OoOoOO00 / OOooOOo % OoooooooOO * I1ii11iIi11i
  if 7 - 7: I11i * O0 + Oo0Ooo / O0 * oO0o + i11iIiiIii
  if 74 - 74: OoOoOO00
class lisp_elp ( object ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 91 - 91: i11iIiiIii / Ii1I % OOooOOo % O0 - I11i . I11i
  if 78 - 78: i1IIi + I11i % OoooooooOO + i1IIi + iII111i % Ii1I
 def copy_elp ( self ) :
  OOO00O = lisp_elp ( self . elp_name )
  OOO00O . use_elp_node = self . use_elp_node
  OOO00O . we_are_last = self . we_are_last
  for i11I1iI1I in self . elp_nodes :
   OOO00O . elp_nodes . append ( i11I1iI1I . copy_elp_node ( ) )
   if 87 - 87: ooOoO0o . iIii1I11I1II1
  return ( OOO00O )
  if 99 - 99: Ii1I + OoooooooOO * IiII * i11iIiiIii - iIii1I11I1II1
  if 58 - 58: IiII % i1IIi . i11iIiiIii
 def print_elp ( self , want_marker ) :
  iIii1 = ""
  for i11I1iI1I in self . elp_nodes :
   i1i1III = ""
   if ( want_marker ) :
    if ( i11I1iI1I == self . use_elp_node ) :
     i1i1III = "*"
    elif ( i11I1iI1I . we_are_last ) :
     i1i1III = "x"
     if 99 - 99: iIii1I11I1II1 / O0 / OOooOOo - I11i
     if 17 - 17: oO0o / IiII - I11i
   iIii1 += "{}{}({}{}{}), " . format ( i1i1III ,
 i11I1iI1I . address . print_address_no_iid ( ) ,
 "r" if i11I1iI1I . eid else "R" , "P" if i11I1iI1I . probe else "p" ,
 "S" if i11I1iI1I . strict else "s" )
   if 30 - 30: IiII / II111iiii / OoOoOO00
  return ( iIii1 [ 0 : - 2 ] if iIii1 != "" else "" )
  if 60 - 60: OoO0O00 - Ii1I
  if 82 - 82: IiII - I1IiiI . iII111i % I11i % Ii1I + iII111i
 def select_elp_node ( self ) :
  oooOOOO000 , o00o , ooO000OO = lisp_myrlocs
  OOOooo0OooOoO = None
  if 98 - 98: oO0o . i11iIiiIii / Ii1I - Ii1I
  for i11I1iI1I in self . elp_nodes :
   if ( oooOOOO000 and i11I1iI1I . address . is_exact_match ( oooOOOO000 ) ) :
    OOOooo0OooOoO = self . elp_nodes . index ( i11I1iI1I )
    break
    if 23 - 23: iIii1I11I1II1
   if ( o00o and i11I1iI1I . address . is_exact_match ( o00o ) ) :
    OOOooo0OooOoO = self . elp_nodes . index ( i11I1iI1I )
    break
    if 30 - 30: I1ii11iIi11i + OoO0O00 - O0
    if 42 - 42: I11i - I1Ii111
    if 24 - 24: i1IIi
    if 93 - 93: OoOoOO00 - Oo0Ooo + iIii1I11I1II1 % iIii1I11I1II1 / I1ii11iIi11i - I1Ii111
    if 9 - 9: I1ii11iIi11i - o0oOOo0O0Ooo / i11iIiiIii * iII111i / OoOoOO00 . I1IiiI
    if 23 - 23: I1IiiI . iII111i % i1IIi
    if 92 - 92: o0oOOo0O0Ooo % i1IIi / OoooooooOO * OoooooooOO / iIii1I11I1II1
  if ( OOOooo0OooOoO == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   i11I1iI1I . we_are_last = False
   return
   if 7 - 7: IiII / OOooOOo + Oo0Ooo . I1IiiI
   if 33 - 33: I1Ii111 + OoooooooOO
   if 73 - 73: O0 . Oo0Ooo
   if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
   if 48 - 48: II111iiii % I1ii11iIi11i - II111iiii
   if 29 - 29: I1Ii111 - I1Ii111 - I11i * iIii1I11I1II1 % OoO0O00 % IiII
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ OOOooo0OooOoO ] ) :
   self . use_elp_node = None
   i11I1iI1I . we_are_last = True
   return
   if 73 - 73: i1IIi . OoooooooOO / OoOoOO00 % Ii1I / Ii1I / Ii1I
   if 40 - 40: I1Ii111 - iIii1I11I1II1
   if 88 - 88: OOooOOo * O0 * OoOoOO00
   if 26 - 26: Ii1I
   if 65 - 65: iII111i / iIii1I11I1II1 + I11i - iIii1I11I1II1 - Ii1I . I1Ii111
  self . use_elp_node = self . elp_nodes [ OOOooo0OooOoO + 1 ]
  return
  if 77 - 77: OoOoOO00 / I1IiiI + IiII
  if 66 - 66: i11iIiiIii * OoooooooOO + iII111i / Ii1I
  if 42 - 42: Ii1I / iIii1I11I1II1 / Oo0Ooo . O0 . oO0o * I1IiiI
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
  if 21 - 21: OoooooooOO
  if 76 - 76: i1IIi * i11iIiiIii / OOooOOo + I1Ii111
 def copy_geo ( self ) :
  O00o0o0O = lisp_geo ( self . geo_name )
  O00o0o0O . latitude = self . latitude
  O00o0o0O . lat_mins = self . lat_mins
  O00o0o0O . lat_secs = self . lat_secs
  O00o0o0O . longitude = self . longitude
  O00o0o0O . long_mins = self . long_mins
  O00o0o0O . long_secs = self . long_secs
  O00o0o0O . altitude = self . altitude
  O00o0o0O . radius = self . radius
  return ( O00o0o0O )
  if 50 - 50: oO0o % OoOoOO00 + I1IiiI
  if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
  if 79 - 79: oO0o + I1IiiI % iII111i + II111iiii % OoO0O00 % iII111i
 def parse_geo_string ( self , geo_str ) :
  OOOooo0OooOoO = geo_str . find ( "]" )
  if ( OOOooo0OooOoO != - 1 ) : geo_str = geo_str [ OOOooo0OooOoO + 1 : : ]
  if 46 - 46: o0oOOo0O0Ooo
  if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
  if 44 - 44: I11i . oO0o
  if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
  if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , II11iI1ii11 = geo_str . split ( "/" )
   self . radius = int ( II11iI1ii11 )
   if 59 - 59: o0oOOo0O0Ooo
   if 76 - 76: OoO0O00 + O0 - OoOoOO00 - IiII
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 11 - 11: ooOoO0o + OoOoOO00 - i1IIi
  o0Oo0OO0o = geo_str [ 0 : 4 ]
  I11IIo0o0000OoO0oO = geo_str [ 4 : 8 ]
  if 100 - 100: IiII - OoOoOO00 % iII111i
  if 24 - 24: Oo0Ooo / OoO0O00 + i11iIiiIii
  if 81 - 81: i11iIiiIii . iIii1I11I1II1 - OoooooooOO
  if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
  if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
  if 42 - 42: OOooOOo
  if 36 - 36: OoooooooOO + ooOoO0o + iII111i
  self . latitude = int ( o0Oo0OO0o [ 0 ] )
  self . lat_mins = int ( o0Oo0OO0o [ 1 ] )
  self . lat_secs = int ( o0Oo0OO0o [ 2 ] )
  if ( o0Oo0OO0o [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 30 - 30: i1IIi % Ii1I
  if 18 - 18: o0oOOo0O0Ooo % I1ii11iIi11i . Ii1I . O0 * II111iiii + I1ii11iIi11i
  if 45 - 45: OoO0O00 / I1ii11iIi11i * ooOoO0o * OOooOOo % i11iIiiIii * iII111i
  if 33 - 33: oO0o . iII111i + Oo0Ooo
  self . longitude = int ( I11IIo0o0000OoO0oO [ 0 ] )
  self . long_mins = int ( I11IIo0o0000OoO0oO [ 1 ] )
  self . long_secs = int ( I11IIo0o0000OoO0oO [ 2 ] )
  if ( I11IIo0o0000OoO0oO [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 33 - 33: ooOoO0o
  if 46 - 46: OoOoOO00 / iII111i - OoO0O00 . o0oOOo0O0Ooo
 def print_geo ( self ) :
  I1iiI1iiiI = "N" if self . latitude < 0 else "S"
  IiIiIiiiI1 = "E" if self . longitude < 0 else "W"
  if 19 - 19: IiII . Oo0Ooo . oO0o * i11iIiiIii
  oOo0oO0 = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , I1iiI1iiiI , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , IiIiIiiiI1 )
  if 26 - 26: OoooooooOO
  if ( self . no_geo_altitude ( ) == False ) :
   oOo0oO0 += "-" + str ( self . altitude )
   if 79 - 79: I1IiiI + I1IiiI
   if 45 - 45: oO0o + I1IiiI / oO0o
   if 33 - 33: OoooooooOO - I1Ii111 . Oo0Ooo % OoooooooOO * ooOoO0o
   if 67 - 67: II111iiii * OoooooooOO
   if 2 - 2: i1IIi
  if ( self . radius != 0 ) : oOo0oO0 += "/{}" . format ( self . radius )
  return ( oOo0oO0 )
  if 18 - 18: o0oOOo0O0Ooo + OoOoOO00 - I1ii11iIi11i - ooOoO0o
  if 42 - 42: iIii1I11I1II1 % i1IIi - O0 * II111iiii
 def geo_url ( self ) :
  ooOO0o000 = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  ooOO0o000 = "10" if ( ooOO0o000 == "" or ooOO0o000 . isdigit ( ) == False ) else ooOO0o000
  iiiII1Iii11i1 , O0oo0O = self . dms_to_decimal ( )
  oO0OoO0oo0 = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( iiiII1Iii11i1 , O0oo0O , iiiII1Iii11i1 , O0oo0O ,
  # I1Ii111 . OoO0O00 % I1Ii111 % oO0o * iIii1I11I1II1
  # II111iiii
 ooOO0o000 )
  return ( oO0OoO0oo0 )
  if 14 - 14: i11iIiiIii . IiII
  if 70 - 70: Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
 def print_geo_url ( self ) :
  O00o0o0O = self . print_geo ( )
  if ( self . radius == 0 ) :
   oO0OoO0oo0 = self . geo_url ( )
   ii1111Iii11i = "<a href='{}'>{}</a>" . format ( oO0OoO0oo0 , O00o0o0O )
  else :
   oO0OoO0oo0 = O00o0o0O . replace ( "/" , "-" )
   ii1111Iii11i = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( oO0OoO0oo0 , O00o0o0O )
   if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
  return ( ii1111Iii11i )
  if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
  if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
 def dms_to_decimal ( self ) :
  i1Iii1 , i1111111II , ooooo0o0 = self . latitude , self . lat_mins , self . lat_secs
  oO0OOoOOo = float ( abs ( i1Iii1 ) )
  oO0OOoOOo += float ( i1111111II * 60 + ooooo0o0 ) / 3600
  if ( i1Iii1 > 0 ) : oO0OOoOOo = - oO0OOoOOo
  i1I11III = oO0OOoOOo
  if 50 - 50: I1Ii111 . I1Ii111 . OoO0O00 + I11i * o0oOOo0O0Ooo
  i1Iii1 , i1111111II , ooooo0o0 = self . longitude , self . long_mins , self . long_secs
  oO0OOoOOo = float ( abs ( i1Iii1 ) )
  oO0OOoOOo += float ( i1111111II * 60 + ooooo0o0 ) / 3600
  if ( i1Iii1 > 0 ) : oO0OOoOOo = - oO0OOoOOo
  i111i111I111 = oO0OOoOOo
  return ( ( i1I11III , i111i111I111 ) )
  if 16 - 16: i11iIiiIii
  if 83 - 83: Oo0Ooo / Oo0Ooo . I11i + oO0o % Ii1I
 def get_distance ( self , geo_point ) :
  i1II1IiiiIiiI = self . dms_to_decimal ( )
  I1iIiI = geo_point . dms_to_decimal ( )
  O0000Ooo0OO0 = geopy . distance . distance ( i1II1IiiiIiiI , I1iIiI )
  return ( O0000Ooo0OO0 . km )
  if 58 - 58: o0oOOo0O0Ooo - IiII
  if 77 - 77: iIii1I11I1II1 + Ii1I + oO0o . i11iIiiIii - iIii1I11I1II1 % ooOoO0o
 def point_in_circle ( self , geo_point ) :
  Oo0O = self . get_distance ( geo_point )
  return ( Oo0O <= self . radius )
  if 20 - 20: IiII * i11iIiiIii / i1IIi * i1IIi
  if 39 - 39: I1IiiI + I1ii11iIi11i - o0oOOo0O0Ooo + Ii1I . OOooOOo * I1ii11iIi11i
 def encode_geo ( self ) :
  O0oooOoOO0O = socket . htons ( LISP_AFI_LCAF )
  O00oo0o = socket . htons ( 20 + 2 )
  OoO0o0oOOoOoo = 0
  if 11 - 11: I1Ii111 + iIii1I11I1II1
  iiiII1Iii11i1 = abs ( self . latitude )
  IiI1i1II = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : OoO0o0oOOoOoo |= 0x40
  if 18 - 18: OOooOOo
  O0oo0O = abs ( self . longitude )
  I1iiIIIiiIi = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : OoO0o0oOOoOoo |= 0x20
  if 68 - 68: iII111i
  i1I = 0
  if ( self . no_geo_altitude ( ) == False ) :
   i1I = socket . htonl ( self . altitude )
   OoO0o0oOOoOoo |= 0x10
   if 59 - 59: I1Ii111 / I1IiiI - I1IiiI . Oo0Ooo * OoO0O00
  II11iI1ii11 = socket . htons ( self . radius )
  if ( II11iI1ii11 != 0 ) : OoO0o0oOOoOoo |= 0x06
  if 87 - 87: i1IIi / OoooooooOO
  o0ooOO0oOoOoOoooo0 = struct . pack ( "HBBBBH" , O0oooOoOO0O , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , O00oo0o )
  o0ooOO0oOoOoOoooo0 += struct . pack ( "BBHBBHBBHIHHH" , OoO0o0oOOoOoo , 0 , 0 , iiiII1Iii11i1 , IiI1i1II >> 16 ,
 socket . htons ( IiI1i1II & 0x0ffff ) , O0oo0O , I1iiIIIiiIi >> 16 ,
 socket . htons ( I1iiIIIiiIi & 0xffff ) , i1I , II11iI1ii11 , 0 , 0 )
  if 53 - 53: OoO0O00 * Oo0Ooo + Oo0Ooo
  return ( o0ooOO0oOoOoOoooo0 )
  if 62 - 62: OOooOOo - i1IIi + i11iIiiIii * I11i / OoO0O00
  if 84 - 84: IiII * OOooOOo
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  II111I11iI = "BBHBBHBBHIHHH"
  oO000 = struct . calcsize ( II111I11iI )
  if ( lcaf_len < oO000 ) : return ( None )
  if 1 - 1: iII111i * I1IiiI . o0oOOo0O0Ooo . IiII
  OoO0o0oOOoOoo , I1ioOoo0O , IIiiiiII , iiiII1Iii11i1 , O00O0oo0O0OOo , IiI1i1II , O0oo0O , IiIIiiI1iI1iI , I1iiIIIiiIi , i1I , II11iI1ii11 , Ooo0OOo0O , Oooo000 = struct . unpack ( II111I11iI ,
  # OoooooooOO % I1Ii111 + IiII / OoooooooOO
 packet [ : oO000 ] )
  if 60 - 60: II111iiii + II111iiii
  if 30 - 30: OOooOOo / OoO0O00
  if 38 - 38: O0 * i1IIi + IiII
  if 3 - 3: OoOoOO00
  Oooo000 = socket . ntohs ( Oooo000 )
  if ( Oooo000 == LISP_AFI_LCAF ) : return ( None )
  if 40 - 40: ooOoO0o % I11i + O0
  if ( OoO0o0oOOoOoo & 0x40 ) : iiiII1Iii11i1 = - iiiII1Iii11i1
  self . latitude = iiiII1Iii11i1
  IiiI1IiII1i = old_div ( ( ( O00O0oo0O0OOo << 16 ) | socket . ntohs ( IiI1i1II ) ) , 1000 )
  self . lat_mins = old_div ( IiiI1IiII1i , 60 )
  self . lat_secs = IiiI1IiII1i % 60
  if 75 - 75: o0oOOo0O0Ooo / O0 % OOooOOo * Ii1I - iIii1I11I1II1 * Ii1I
  if ( OoO0o0oOOoOoo & 0x20 ) : O0oo0O = - O0oo0O
  self . longitude = O0oo0O
  oo0OOOo00o = old_div ( ( ( IiIIiiI1iI1iI << 16 ) | socket . ntohs ( I1iiIIIiiIi ) ) , 1000 )
  self . long_mins = old_div ( oo0OOOo00o , 60 )
  self . long_secs = oo0OOOo00o % 60
  if 32 - 32: I1ii11iIi11i + OoOoOO00 / O0 + I1Ii111 . OoOoOO00 - ooOoO0o
  self . altitude = socket . ntohl ( i1I ) if ( OoO0o0oOOoOoo & 0x10 ) else - 1
  II11iI1ii11 = socket . ntohs ( II11iI1ii11 )
  self . radius = II11iI1ii11 if ( OoO0o0oOOoOoo & 0x02 ) else II11iI1ii11 * 1000
  if 15 - 15: o0oOOo0O0Ooo * O0 / OoooooooOO + I1Ii111 + Oo0Ooo
  self . geo_name = None
  packet = packet [ oO000 : : ]
  if 92 - 92: Ii1I - o0oOOo0O0Ooo % I1IiiI + I1Ii111
  if ( Oooo000 != 0 ) :
   self . rloc . afi = Oooo000
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 3 - 3: iIii1I11I1II1 + i11iIiiIii
  return ( packet )
  if 49 - 49: OoOoOO00 % iIii1I11I1II1 + I1Ii111
  if 38 - 38: i11iIiiIii
  if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
  if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
  if 7 - 7: Oo0Ooo . iII111i % I1ii11iIi11i / iII111i
  if 93 - 93: iII111i
class lisp_rle_node ( object ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 5 - 5: iII111i . I11i % I11i * Ii1I - I1ii11iIi11i . i11iIiiIii
  if 32 - 32: II111iiii
 def copy_rle_node ( self ) :
  iI11i1ii11i11 = lisp_rle_node ( )
  iI11i1ii11i11 . address . copy_address ( self . address )
  iI11i1ii11i11 . level = self . level
  iI11i1ii11i11 . translated_port = self . translated_port
  iI11i1ii11i11 . rloc_name = self . rloc_name
  return ( iI11i1ii11i11 )
  if 58 - 58: I1IiiI - o0oOOo0O0Ooo - I1Ii111 . O0 % OoO0O00 . I11i
  if 41 - 41: iII111i . I1Ii111 - IiII / O0
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 62 - 62: IiII * I1ii11iIi11i * iII111i * OoOoOO00
  if 12 - 12: Oo0Ooo * Ii1I / ooOoO0o % I11i % O0
 def get_encap_keys ( self ) :
  I1I = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 25 - 25: Oo0Ooo * oO0o
  O0O0 = self . address . print_address_no_iid ( ) + ":" + I1I
  if 78 - 78: OoOoOO00 / II111iiii
  try :
   iI1iiiiiii = lisp_crypto_keys_by_rloc_encap [ O0O0 ]
   if ( iI1iiiiiii [ 1 ] ) : return ( iI1iiiiiii [ 1 ] . encrypt_key , iI1iiiiiii [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 6 - 6: I1Ii111 . OoOoOO00
   if 75 - 75: Oo0Ooo + I11i
   if 87 - 87: I1IiiI
   if 36 - 36: OoO0O00 . ooOoO0o . O0 / OoO0O00
class lisp_rle ( object ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
  if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
 def copy_rle ( self ) :
  ooo0o0O = lisp_rle ( self . rle_name )
  for iI11i1ii11i11 in self . rle_nodes :
   ooo0o0O . rle_nodes . append ( iI11i1ii11i11 . copy_rle_node ( ) )
   if 72 - 72: I1ii11iIi11i
  ooo0o0O . build_forwarding_list ( )
  return ( ooo0o0O )
  if 74 - 74: I1Ii111 * iIii1I11I1II1 / oO0o - IiII - I1IiiI
  if 84 - 84: iIii1I11I1II1 % Oo0Ooo / I1ii11iIi11i + o0oOOo0O0Ooo * II111iiii
 def print_rle ( self , html , do_formatting ) :
  I1i1iI1i1i1 = ""
  for iI11i1ii11i11 in self . rle_nodes :
   I1I = iI11i1ii11i11 . translated_port
   if 81 - 81: I1IiiI / I1ii11iIi11i / OOooOOo
   oO0OO000OOo = ""
   if ( iI11i1ii11i11 . rloc_name != None ) :
    oO0OO000OOo = iI11i1ii11i11 . rloc_name
    if ( do_formatting ) : oO0OO000OOo = blue ( oO0OO000OOo , html )
    oO0OO000OOo = "({})" . format ( oO0OO000OOo )
    if 64 - 64: I1ii11iIi11i - iIii1I11I1II1 + I1Ii111 . oO0o . iIii1I11I1II1
    if 79 - 79: OoOoOO00 . ooOoO0o
   O0O0 = iI11i1ii11i11 . address . print_address_no_iid ( )
   if ( iI11i1ii11i11 . address . is_local ( ) ) : O0O0 = red ( O0O0 , html )
   I1i1iI1i1i1 += "{}{}{}, " . format ( O0O0 , "" if I1I == 0 else ":" + str ( I1I ) , oO0OO000OOo )
   if 22 - 22: oO0o + Ii1I - ooOoO0o + OoOoOO00 % OOooOOo - Oo0Ooo
   if 59 - 59: OoOoOO00 * iII111i - OOooOOo
  return ( I1i1iI1i1i1 [ 0 : - 2 ] if I1i1iI1i1i1 != "" else "" )
  if 49 - 49: I1ii11iIi11i / oO0o . oO0o * iII111i % iII111i . I1IiiI
  if 96 - 96: II111iiii / OoooooooOO + iIii1I11I1II1 . Ii1I + OoooooooOO
 def build_forwarding_list ( self ) :
  O00OoO0 = - 1
  for iI11i1ii11i11 in self . rle_nodes :
   if ( O00OoO0 == - 1 ) :
    if ( iI11i1ii11i11 . address . is_local ( ) ) : O00OoO0 = iI11i1ii11i11 . level
   else :
    if ( iI11i1ii11i11 . level > O00OoO0 ) : break
    if 62 - 62: OoOoOO00 + OoOoOO00 % OOooOOo * iII111i
    if 24 - 24: Oo0Ooo % i1IIi
  O00OoO0 = 0 if O00OoO0 == - 1 else iI11i1ii11i11 . level
  if 50 - 50: OoO0O00
  self . rle_forwarding_list = [ ]
  for iI11i1ii11i11 in self . rle_nodes :
   if ( iI11i1ii11i11 . level == O00OoO0 or ( O00OoO0 == 0 and
 iI11i1ii11i11 . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and iI11i1ii11i11 . address . is_local ( ) ) :
     O0O0 = iI11i1ii11i11 . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( O0O0 ) )
     continue
     if 52 - 52: o0oOOo0O0Ooo + O0
    self . rle_forwarding_list . append ( iI11i1ii11i11 )
    if 13 - 13: OoO0O00
    if 56 - 56: OoOoOO00 . ooOoO0o * oO0o - I11i
    if 47 - 47: oO0o . i1IIi * I1ii11iIi11i % OOooOOo % IiII / Oo0Ooo
    if 39 - 39: i11iIiiIii . OOooOOo + Oo0Ooo
    if 92 - 92: O0 * Oo0Ooo / o0oOOo0O0Ooo % OoO0O00
class lisp_json ( object ) :
 def __init__ ( self , name , string , encrypted = False , ms_encrypt = False ) :
  if 87 - 87: OoooooooOO / I11i . O0
  if 77 - 77: OOooOOo + oO0o * iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii
  if 92 - 92: Oo0Ooo . o0oOOo0O0Ooo % OoooooooOO * i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo
  if 48 - 48: iII111i * I1ii11iIi11i * oO0o % O0 . OoO0O00
  if ( type ( string ) == bytes ) : string = string . decode ( )
  if 11 - 11: OOooOOo / o0oOOo0O0Ooo
  self . json_name = name
  self . json_encrypted = False
  try :
   json . loads ( string )
  except :
   lprint ( "Invalid JSON string: '{}'" . format ( string ) )
   string = '{ "?" : "?" }'
   if 98 - 98: oO0o + I11i . oO0o
  self . json_string = string
  if 10 - 10: iII111i + i1IIi . I11i % ooOoO0o / ooOoO0o
  if 86 - 86: Oo0Ooo
  if 7 - 7: iIii1I11I1II1
  if 86 - 86: IiII + iII111i * II111iiii - IiII - o0oOOo0O0Ooo
  if 8 - 8: OOooOOo . Ii1I
  if 15 - 15: ooOoO0o / OOooOOo + i1IIi / Ii1I / OOooOOo
  if 47 - 47: Oo0Ooo + oO0o % OoooooooOO
  if 23 - 23: I1Ii111 / i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1
  if 11 - 11: I11i % OoOoOO00 * Oo0Ooo
  if 48 - 48: OOooOOo
  if ( len ( lisp_ms_json_keys ) != 0 ) :
   if ( ms_encrypt == False ) : return
   self . json_key_id = list ( lisp_ms_json_keys . keys ( ) ) [ 0 ]
   self . json_key = lisp_ms_json_keys [ self . json_key_id ]
   self . encrypt_json ( )
   if 66 - 66: iII111i - I1Ii111 - i11iIiiIii . o0oOOo0O0Ooo + Oo0Ooo
   if 90 - 90: O0 - i11iIiiIii * ooOoO0o . I1ii11iIi11i . Ii1I - OoooooooOO
  if ( lisp_log_id == "lig" and encrypted ) :
   Ooo00o000o = os . getenv ( "LISP_JSON_KEY" )
   if ( Ooo00o000o != None ) :
    OOOooo0OooOoO = - 1
    if ( Ooo00o000o [ 0 ] == "[" and "]" in Ooo00o000o ) :
     OOOooo0OooOoO = Ooo00o000o . find ( "]" )
     self . json_key_id = int ( Ooo00o000o [ 1 : OOOooo0OooOoO ] )
     if 23 - 23: o0oOOo0O0Ooo
    self . json_key = Ooo00o000o [ OOOooo0OooOoO + 1 : : ]
    if 88 - 88: I1Ii111 + iIii1I11I1II1 / o0oOOo0O0Ooo
    self . decrypt_json ( )
    if 93 - 93: ooOoO0o % iIii1I11I1II1 - OOooOOo . IiII + ooOoO0o
    if 63 - 63: I1ii11iIi11i / OOooOOo
    if 28 - 28: I11i / I1Ii111 + IiII * OoooooooOO - iIii1I11I1II1
    if 6 - 6: I11i % o0oOOo0O0Ooo / OoooooooOO . I1Ii111
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 17 - 17: I1ii11iIi11i + OoooooooOO / iIii1I11I1II1 . II111iiii + Oo0Ooo
  if 7 - 7: O0 - I1ii11iIi11i - iIii1I11I1II1
 def delete ( self ) :
  if ( self . json_name in lisp_json_list ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 96 - 96: OoOoOO00 . I1IiiI . I11i * OoooooooOO + OoooooooOO * O0
   if 90 - 90: I11i + I1ii11iIi11i + OoooooooOO + OoOoOO00 + IiII / iII111i
   if 75 - 75: i11iIiiIii
 def print_json ( self , html ) :
  i1I1111i = self . json_string
  I1iIi = "***"
  if ( html ) : I1iIi = red ( I1iIi , html )
  Iii11Ii1I = I1iIi + self . json_string + I1iIi
  if ( self . valid_json ( ) ) : return ( i1I1111i )
  return ( Iii11Ii1I )
  if 82 - 82: iIii1I11I1II1
  if 30 - 30: OoooooooOO
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 17 - 17: i1IIi
  return ( True )
  if 55 - 55: Ii1I . O0 * oO0o % i1IIi * IiII % iII111i
  if 79 - 79: O0 / IiII . i1IIi - i1IIi + i1IIi
 def encrypt_json ( self ) :
  iI1II1I1i1 = self . json_key . zfill ( 32 )
  OoOooO = "0" * 8
  if 47 - 47: iII111i - I1Ii111 - I1Ii111 . ooOoO0o
  iII1oO0OOoOOo0 = json . loads ( self . json_string )
  for Ooo00o000o in iII1oO0OOoOOo0 :
   oOO0 = iII1oO0OOoOOo0 [ Ooo00o000o ]
   if ( type ( oOO0 ) != str ) : oOO0 = str ( oOO0 )
   oOO0 = chacha . ChaCha ( iI1II1I1i1 , OoOooO ) . encrypt ( oOO0 )
   iII1oO0OOoOOo0 [ Ooo00o000o ] = binascii . hexlify ( oOO0 )
   if 53 - 53: iII111i + oO0o % O0
  self . json_string = json . dumps ( iII1oO0OOoOOo0 )
  self . json_encrypted = True
  if 92 - 92: O0 / iIii1I11I1II1
  if 72 - 72: o0oOOo0O0Ooo / iII111i - I1ii11iIi11i . II111iiii
 def decrypt_json ( self ) :
  iI1II1I1i1 = self . json_key . zfill ( 32 )
  OoOooO = "0" * 8
  if 95 - 95: II111iiii / I11i / ooOoO0o - I1Ii111 % i11iIiiIii
  iII1oO0OOoOOo0 = json . loads ( self . json_string )
  for Ooo00o000o in iII1oO0OOoOOo0 :
   oOO0 = binascii . unhexlify ( iII1oO0OOoOOo0 [ Ooo00o000o ] )
   iII1oO0OOoOOo0 [ Ooo00o000o ] = chacha . ChaCha ( iI1II1I1i1 , OoOooO ) . encrypt ( oOO0 )
   if 53 - 53: iII111i
  try :
   self . json_string = json . dumps ( iII1oO0OOoOOo0 )
   self . json_encrypted = False
  except :
   pass
   if 45 - 45: OOooOOo * I1IiiI / oO0o . Ii1I - OoO0O00 % OOooOOo
   if 40 - 40: I11i
   if 69 - 69: OoOoOO00 + OoOoOO00 + o0oOOo0O0Ooo / iIii1I11I1II1 * OoO0O00
   if 44 - 44: II111iiii / o0oOOo0O0Ooo
   if 81 - 81: I1Ii111 . Ii1I * ooOoO0o . IiII - OoOoOO00
   if 79 - 79: ooOoO0o - O0
   if 56 - 56: ooOoO0o
class lisp_stats ( object ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 89 - 89: O0 % iIii1I11I1II1 / OoOoOO00 - I1Ii111 - I1IiiI
  if 60 - 60: IiII % i11iIiiIii / OOooOOo
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 43 - 43: i11iIiiIii * II111iiii + ooOoO0o - OoooooooOO * II111iiii / OoO0O00
  if 92 - 92: O0 - ooOoO0o % iII111i
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  i1i111Iiiiiii = time . time ( ) - self . last_increment
  return ( i1i111Iiiiiii <= 1 )
  if 83 - 83: I1ii11iIi11i / OoOoOO00 % OoooooooOO
  if 54 - 54: I11i / I1IiiI * IiII - iII111i
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  i1i111Iiiiiii = time . time ( ) - self . last_increment
  return ( i1i111Iiiiiii <= 60 )
  if 37 - 37: i1IIi * I1Ii111 / I11i * II111iiii + OoooooooOO . OoO0O00
  if 22 - 22: OoOoOO00 + OoooooooOO - I1Ii111
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 82 - 82: Ii1I % I1Ii111 / ooOoO0o
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 86 - 86: II111iiii - iIii1I11I1II1 + oO0o + I1IiiI
  return ( c1 , c2 )
  if 29 - 29: Ii1I % OoooooooOO * II111iiii
  if 88 - 88: I1Ii111 + I11i + I1Ii111 % OoO0O00 / I1ii11iIi11i - I11i
 def normalize ( self , count ) :
  count = str ( count )
  iIi11ii1 = len ( count )
  if ( iIi11ii1 > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 55 - 55: I1ii11iIi11i - I11i
  if ( iIi11ii1 > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 73 - 73: i11iIiiIii . OoO0O00 + OoO0O00 - OOooOOo % OOooOOo - OoO0O00
  if ( iIi11ii1 > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 5 - 5: I1ii11iIi11i + i1IIi * I11i % iII111i
  return ( count )
  if 96 - 96: ooOoO0o % I1ii11iIi11i % i11iIiiIii * I11i * iII111i . i11iIiiIii
  if 65 - 65: i11iIiiIii / o0oOOo0O0Ooo % I1ii11iIi11i - O0 % OoooooooOO / o0oOOo0O0Ooo
 def get_stats ( self , summary , html ) :
  I1iI1I11ii11 = self . last_rate_check
  I1iOo0ooOOO = self . last_packet_count
  o0O00Oo = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 91 - 91: II111iiii
  OOOOooO00oooO = self . last_rate_check - I1iI1I11ii11
  if ( OOOOooO00oooO == 0 ) :
   Ii1i1ii = 0
   OoOI11I11IiiiI = 0
  else :
   Ii1i1ii = int ( old_div ( ( self . packet_count - I1iOo0ooOOO ) ,
 OOOOooO00oooO ) )
   OoOI11I11IiiiI = old_div ( ( self . byte_count - o0O00Oo ) , OOOOooO00oooO )
   OoOI11I11IiiiI = old_div ( ( OoOI11I11IiiiI * 8 ) , 1000000 )
   OoOI11I11IiiiI = round ( OoOI11I11IiiiI , 2 )
   if 14 - 14: iIii1I11I1II1 % OOooOOo + O0
   if 39 - 39: i1IIi + i11iIiiIii . II111iiii
   if 70 - 70: Ii1I + Oo0Ooo + Oo0Ooo / i1IIi
   if 33 - 33: OoooooooOO + o0oOOo0O0Ooo . OoOoOO00 % Oo0Ooo * O0
   if 49 - 49: I1ii11iIi11i * I1Ii111 - OoooooooOO . i1IIi . I1ii11iIi11i
  i1I1iiII = self . normalize ( self . packet_count )
  iII1IiI1 = self . normalize ( self . byte_count )
  if 57 - 57: Oo0Ooo + Ii1I * OoooooooOO
  if 30 - 30: O0
  if 70 - 70: oO0o
  if 89 - 89: O0
  if 3 - 3: iII111i - O0 / I11i
  if ( summary ) :
   Iiii111III = "<br>" if html else ""
   i1I1iiII , iII1IiI1 = self . stat_colors ( i1I1iiII , iII1IiI1 , html )
   o00iiIIIiIiI1 = "packet-count: {}{}byte-count: {}" . format ( i1I1iiII , Iiii111III , iII1IiI1 )
   ooo0oOooOO0o0 = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( Ii1i1ii , OoOI11I11IiiiI )
   if 60 - 60: OOooOOo * I1Ii111
   if ( html != "" ) : ooo0oOooOO0o0 = lisp_span ( o00iiIIIiIiI1 , ooo0oOooOO0o0 )
  else :
   I1i1Iii1i1iI = str ( Ii1i1ii )
   iIIIii1ii11i = str ( OoOI11I11IiiiI )
   if ( html ) :
    i1I1iiII = lisp_print_cour ( i1I1iiII )
    I1i1Iii1i1iI = lisp_print_cour ( I1i1Iii1i1iI )
    iII1IiI1 = lisp_print_cour ( iII1IiI1 )
    iIIIii1ii11i = lisp_print_cour ( iIIIii1ii11i )
    if 87 - 87: Ii1I / OoOoOO00 / OOooOOo
   Iiii111III = "<br>" if html else ", "
   if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
   ooo0oOooOO0o0 = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( i1I1iiII , Iiii111III , I1i1Iii1i1iI , Iiii111III , iII1IiI1 , Iiii111III ,
   # Oo0Ooo * i1IIi
 iIIIii1ii11i )
   if 5 - 5: OoO0O00 / O0 - I1Ii111 - i1IIi + Oo0Ooo / iII111i
  return ( ooo0oOooOO0o0 )
  if 24 - 24: OoOoOO00 . Oo0Ooo
  if 64 - 64: II111iiii . I1ii11iIi11i * oO0o . i1IIi + o0oOOo0O0Ooo
  if 30 - 30: iIii1I11I1II1
  if 3 - 3: o0oOOo0O0Ooo % iII111i - Ii1I
  if 29 - 29: Oo0Ooo
  if 91 - 91: oO0o / OoO0O00 + I1IiiI * iIii1I11I1II1
  if 38 - 38: I11i
  if 50 - 50: I1ii11iIi11i * I1IiiI / OoO0O00 / i1IIi / ooOoO0o . ooOoO0o
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
if 97 - 97: i11iIiiIii . OoOoOO00 + oO0o * O0 % OoO0O00 - Ii1I
if 46 - 46: I1Ii111
if 87 - 87: o0oOOo0O0Ooo - iII111i * OoO0O00 * o0oOOo0O0Ooo . o0oOOo0O0Ooo / OOooOOo
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
  if 50 - 50: i11iIiiIii - II111iiii * OoooooooOO + II111iiii - ooOoO0o
  if ( recurse == False ) : return
  if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
  if 98 - 98: iII111i . i1IIi + o0oOOo0O0Ooo * OoooooooOO - i11iIiiIii
  if 21 - 21: i11iIiiIii . oO0o * o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
  if 33 - 33: I1IiiI + O0 - I11i
  if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
  if 63 - 63: o0oOOo0O0Ooo . IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
  o0O0oOO0oOOo = lisp_get_default_route_next_hops ( )
  if ( o0O0oOO0oOOo == [ ] or len ( o0O0oOO0oOOo ) == 1 ) : return
  if 37 - 37: Oo0Ooo / I1IiiI
  self . rloc_next_hop = o0O0oOO0oOOo [ 0 ]
  IiIiIi = self
  for ii1I in o0O0oOO0oOOo [ 1 : : ] :
   O0Oo0o = lisp_rloc ( False )
   O0Oo0o = copy . deepcopy ( self )
   O0Oo0o . rloc_next_hop = ii1I
   IiIiIi . next_rloc = O0Oo0o
   IiIiIi = O0Oo0o
   if 14 - 14: Oo0Ooo % IiII + Oo0Ooo
   if 59 - 59: OoOoOO00 + O0 / I1IiiI % O0 / OoooooooOO * Ii1I
   if 26 - 26: O0 - II111iiii % IiII - OoOoOO00 * iII111i % OOooOOo
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 21 - 21: oO0o + II111iiii - I1ii11iIi11i
  if 85 - 85: I1ii11iIi11i * OoooooooOO . OOooOOo * OOooOOo
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 13 - 13: I1IiiI / Ii1I - OoOoOO00 . i1IIi * oO0o * o0oOOo0O0Ooo
  if 5 - 5: I11i - I1Ii111 * I11i - II111iiii + OOooOOo + II111iiii
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 91 - 91: i1IIi + Oo0Ooo - I1ii11iIi11i + I1ii11iIi11i * O0 / O0
  if 78 - 78: OoooooooOO
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 8 - 8: Oo0Ooo - Oo0Ooo % O0 - Ii1I / o0oOOo0O0Ooo % Oo0Ooo
  if 51 - 51: iIii1I11I1II1 / iIii1I11I1II1 * I1ii11iIi11i / I11i
  if 18 - 18: Ii1I - i11iIiiIii + OoO0O00 . O0 - iII111i
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
  if 9 - 9: OoooooooOO / iII111i + o0oOOo0O0Ooo / II111iiii / I1Ii111
  if 44 - 44: I1IiiI / iII111i / Oo0Ooo
 def print_rloc ( self , indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , i1 , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 66 - 66: I1Ii111 + OoooooooOO % I1IiiI . iII111i * Oo0Ooo + o0oOOo0O0Ooo
  if 96 - 96: OoO0O00 - ooOoO0o * Ii1I
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  OO000o = self . rloc_name
  if ( cour ) : OO000o = lisp_print_cour ( OO000o )
  return ( 'rloc-name: {}' . format ( blue ( OO000o , cour ) ) )
  if 34 - 34: OoO0O00 . Oo0Ooo % Ii1I . IiII + OoOoOO00
  if 10 - 10: OoooooooOO * iII111i * ooOoO0o . Ii1I % I1Ii111 / I1ii11iIi11i
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  I1I = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  if ( rloc_record . rloc_name != None ) :
   self . rloc_name = rloc_record . rloc_name
   if 71 - 71: Ii1I + IiII
   if 10 - 10: II111iiii % o0oOOo0O0Ooo . o0oOOo0O0Ooo % iII111i
   if 2 - 2: OoooooooOO / IiII % Oo0Ooo % iIii1I11I1II1
   if 62 - 62: oO0o
   if 47 - 47: I1IiiI - O0 - I1ii11iIi11i . OoOoOO00
  I1Ii1i111I = self . rloc
  if ( I1Ii1i111I . is_null ( ) == False ) :
   OOoOoO0O = lisp_get_nat_info ( I1Ii1i111I , self . rloc_name )
   if ( OOoOoO0O ) :
    I1I = OOoOoO0O . port
    iI1II = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    O0O0 = I1Ii1i111I . print_address_no_iid ( )
    IIi11IiiiI11i = red ( O0O0 , False )
    IiIiiI1I = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 66 - 66: iII111i - IiII . I1Ii111
    if 29 - 29: I1Ii111 - Ii1I + O0 - oO0o - O0
    if 68 - 68: iII111i + II111iiii + I1ii11iIi11i * OOooOOo / oO0o
    if 41 - 41: OOooOOo + Oo0Ooo % I1IiiI
    if 3 - 3: ooOoO0o * Ii1I
    if 29 - 29: OoooooooOO + OOooOOo
    if ( OOoOoO0O . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( IIi11IiiiI11i , I1I , IiIiiI1I ) )
     if 68 - 68: O0 + IiII / iII111i - OoOoOO00
     if 5 - 5: I1IiiI * OoooooooOO - II111iiii
     OOoOoO0O = None if ( OOoOoO0O == iI1II ) else iI1II
     if ( OOoOoO0O and OOoOoO0O . timed_out ( ) ) :
      I1I = OOoOoO0O . port
      IIi11IiiiI11i = red ( OOoOoO0O . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( IIi11IiiiI11i , I1I ,
      # i1IIi . iII111i % OOooOOo - OoooooooOO
 IiIiiI1I ) )
      OOoOoO0O = None
      if 21 - 21: II111iiii
      if 47 - 47: i11iIiiIii . OOooOOo + I1Ii111 / I1ii11iIi11i . I1IiiI . I1Ii111
      if 79 - 79: OoO0O00 / i11iIiiIii . IiII - I11i / iIii1I11I1II1
      if 81 - 81: Oo0Ooo . II111iiii + i11iIiiIii - OoOoOO00 * ooOoO0o
      if 25 - 25: Ii1I / Oo0Ooo
      if 79 - 79: o0oOOo0O0Ooo . i1IIi % I1ii11iIi11i % II111iiii . iIii1I11I1II1
      if 45 - 45: I1ii11iIi11i / iIii1I11I1II1 + OoO0O00 / O0 - O0 - I1Ii111
    if ( OOoOoO0O ) :
     if ( OOoOoO0O . address != O0O0 ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( IIi11IiiiI11i , red ( OOoOoO0O . address , False ) ) )
      if 88 - 88: o0oOOo0O0Ooo % I1Ii111
      self . rloc . store_address ( OOoOoO0O . address )
      if 4 - 4: i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
     IIi11IiiiI11i = red ( OOoOoO0O . address , False )
     I1I = OOoOoO0O . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( IIi11IiiiI11i , I1I , IiIiiI1I ) )
     if 87 - 87: I1Ii111 % i11iIiiIii + O0
     self . store_translated_rloc ( I1Ii1i111I , I1I )
     if 67 - 67: OoooooooOO / i1IIi / ooOoO0o . i1IIi - i11iIiiIii . i1IIi
     if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
     if 15 - 15: I1ii11iIi11i
     if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 56 - 56: I1IiiI . ooOoO0o
  if 35 - 35: iIii1I11I1II1 % Oo0Ooo + o0oOOo0O0Ooo * o0oOOo0O0Ooo % ooOoO0o
  if 10 - 10: I1ii11iIi11i / II111iiii % II111iiii - OoooooooOO * o0oOOo0O0Ooo / ooOoO0o
  if 26 - 26: OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for iI11i1ii11i11 in self . rle . rle_nodes :
    OO000o = iI11i1ii11i11 . rloc_name
    OOoOoO0O = lisp_get_nat_info ( iI11i1ii11i11 . address , OO000o )
    if ( OOoOoO0O == None ) : continue
    if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
    I1I = OOoOoO0O . port
    I1Iii1i = OO000o
    if ( I1Iii1i ) : I1Iii1i = blue ( OO000o , False )
    if 8 - 8: OoooooooOO % I11i - iII111i * OOooOOo . O0
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( I1I ,
    # i11iIiiIii % Oo0Ooo * oO0o
 iI11i1ii11i11 . address . print_address_no_iid ( ) , I1Iii1i ) )
    iI11i1ii11i11 . translated_port = I1I
    if 73 - 73: Oo0Ooo / OoooooooOO / i11iIiiIii
    if 5 - 5: O0 % i11iIiiIii
    if 60 - 60: I1ii11iIi11i / I11i
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 100 - 100: I1IiiI
  if 44 - 44: iIii1I11I1II1 + Oo0Ooo - I1Ii111 . OoooooooOO
  if 28 - 28: Ii1I + OOooOOo % IiII . i11iIiiIii - I1IiiI * Oo0Ooo
  if 2 - 2: I11i * I1ii11iIi11i + O0
  iiIi1 = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 10 - 10: OOooOOo
  if ( rloc_record . keys != None and iiIi1 ) :
   Ooo00o000o = rloc_record . keys [ 1 ]
   if ( Ooo00o000o != None ) :
    O0O0 = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( I1I )
    if 78 - 78: OOooOOo * I1ii11iIi11i % i11iIiiIii % o0oOOo0O0Ooo . I1ii11iIi11i / OoooooooOO
    Ooo00o000o . add_key_by_rloc ( O0O0 , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( O0O0 , False ) ) )
    if 12 - 12: iIii1I11I1II1 % OoO0O00 + OOooOOo * iIii1I11I1II1 - iIii1I11I1II1
    if 70 - 70: OoO0O00 % i11iIiiIii * IiII . I11i * Oo0Ooo
    if 17 - 17: i1IIi
  return ( I1I )
  if 29 - 29: OOooOOo % OoO0O00 + oO0o + o0oOOo0O0Ooo . iII111i
  if 14 - 14: i1IIi + OoOoOO00 * oO0o - II111iiii + IiII + OoOoOO00
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 42 - 42: Oo0Ooo + iII111i * ooOoO0o
  if 72 - 72: iIii1I11I1II1 % I1Ii111
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 77 - 77: I1Ii111 * I1IiiI / iIii1I11I1II1 . II111iiii * Oo0Ooo
  if 71 - 71: ooOoO0o / iIii1I11I1II1 % O0 / I1ii11iIi11i . I1Ii111 / i11iIiiIii
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 6 - 6: oO0o . OoO0O00 - II111iiii . I1IiiI - o0oOOo0O0Ooo - i1IIi
  return ( True )
  if 42 - 42: Ii1I + i11iIiiIii
  if 46 - 46: O0 % OoOoOO00 - I1Ii111 . I1IiiI
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 66 - 66: II111iiii * iIii1I11I1II1 * ooOoO0o * I11i . II111iiii - ooOoO0o
  if 15 - 15: I1ii11iIi11i - i11iIiiIii - Ii1I / Ii1I . iII111i
  if 36 - 36: oO0o + Oo0Ooo * I1Ii111 % OOooOOo . Oo0Ooo . I1IiiI
 def print_state_change ( self , new_state ) :
  oOii = self . print_state ( )
  ii1111Iii11i = "{} -> {}" . format ( oOii , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   ii1111Iii11i = bold ( ii1111Iii11i , False )
   if 5 - 5: i1IIi % OoooooooOO
  return ( ii1111Iii11i )
  if 8 - 8: OOooOOo * oO0o
  if 47 - 47: O0
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 42 - 42: iII111i
  if 99 - 99: O0
 def print_recent_rloc_probe_rtts ( self ) :
  OOOooOOoOO0o = str ( self . recent_rloc_probe_rtts )
  OOOooOOoOO0o = OOOooOOoOO0o . replace ( "-1" , "?" )
  return ( OOOooOOoOO0o )
  if 5 - 5: I1ii11iIi11i / Oo0Ooo
  if 47 - 47: OOooOOo
 def compute_rloc_probe_rtt ( self ) :
  IiIiIi = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  i111ii1I1iI1 = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ IiIiIi ] + i111ii1I1iI1 [ 0 : - 1 ]
  if 93 - 93: O0 * II111iiii / i11iIiiIii * O0 + I1Ii111
  if 42 - 42: iIii1I11I1II1
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 35 - 35: I1ii11iIi11i / OoOoOO00 / i1IIi / i11iIiiIii * iIii1I11I1II1 / i1IIi
  if 69 - 69: OOooOOo / I1Ii111 * II111iiii
 def print_recent_rloc_probe_hops ( self ) :
  o0OOOo0o = str ( self . recent_rloc_probe_hops )
  return ( o0OOOo0o )
  if 74 - 74: ooOoO0o - iII111i * OoooooooOO . ooOoO0o
  if 35 - 35: I1Ii111 - iII111i . I11i . O0
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 87 - 87: OOooOOo * ooOoO0o / OoO0O00 / OoO0O00
  if ( from_ttl < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   I111IiIIIii = "!"
  else :
   I111IiIIIii = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 9 - 9: oO0o % Ii1I
   if 20 - 20: OoooooooOO - OoooooooOO + Ii1I % I1Ii111
  IiIiIi = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + I111IiIIIii
  i111ii1I1iI1 = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ IiIiIi ] + i111ii1I1iI1 [ 0 : - 1 ]
  if 54 - 54: IiII % oO0o + i11iIiiIii % O0
  if 56 - 56: OoOoOO00 / II111iiii . O0
 def store_rloc_probe_latencies ( self , json_telemetry ) :
  ii11i11iiiIi1 = lisp_decode_telemetry ( json_telemetry )
  if 25 - 25: iII111i - Oo0Ooo % iIii1I11I1II1 + o0oOOo0O0Ooo + iIii1I11I1II1
  OO0OOo00O = round ( float ( ii11i11iiiIi1 [ "etr-in" ] ) - float ( ii11i11iiiIi1 [ "itr-out" ] ) , 3 )
  OOO0OO0OoOOo = round ( float ( ii11i11iiiIi1 [ "itr-in" ] ) - float ( ii11i11iiiIi1 [ "etr-out" ] ) , 3 )
  if 52 - 52: oO0o / ooOoO0o / iII111i / OoOoOO00 * iIii1I11I1II1
  IiIiIi = self . rloc_probe_latency
  self . rloc_probe_latency = str ( OO0OOo00O ) + "/" + str ( OOO0OO0OoOOo )
  i111ii1I1iI1 = self . recent_rloc_probe_latencies
  self . recent_rloc_probe_latencies = [ IiIiIi ] + i111ii1I1iI1 [ 0 : - 1 ]
  if 74 - 74: oO0o . I1ii11iIi11i - iIii1I11I1II1
  if 73 - 73: OoO0O00 / O0 . o0oOOo0O0Ooo
 def print_rloc_probe_latency ( self ) :
  return ( self . rloc_probe_latency )
  if 100 - 100: Ii1I . OoO0O00 % I1ii11iIi11i % O0 * Oo0Ooo - OoOoOO00
  if 15 - 15: OOooOOo - OOooOOo - OoooooooOO * OoO0O00
 def print_recent_rloc_probe_latencies ( self ) :
  Iii1111IIiI1 = str ( self . recent_rloc_probe_latencies )
  return ( Iii1111IIiI1 )
  if 48 - 48: I1Ii111 * iII111i
  if 93 - 93: I11i % iIii1I11I1II1 + Ii1I - I1IiiI + OoooooooOO . IiII
 def process_rloc_probe_reply ( self , ts , nonce , eid , group , hc , ttl , jt ) :
  I1Ii1i111I = self
  while ( True ) :
   if ( I1Ii1i111I . last_rloc_probe_nonce == nonce ) : break
   I1Ii1i111I = I1Ii1i111I . next_rloc
   if ( I1Ii1i111I == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 77 - 77: i11iIiiIii . OoooooooOO % iIii1I11I1II1 % I1Ii111
    return
    if 22 - 22: iIii1I11I1II1 + Ii1I / OOooOOo - oO0o * oO0o / IiII
    if 91 - 91: I11i - II111iiii + o0oOOo0O0Ooo + i1IIi + I1ii11iIi11i % Ii1I
    if 57 - 57: o0oOOo0O0Ooo - I1Ii111 / OoooooooOO . OoooooooOO
    if 44 - 44: oO0o / II111iiii % I1IiiI - II111iiii / OoooooooOO
    if 4 - 4: I11i * OoOoOO00
    if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
  I1Ii1i111I . last_rloc_probe_reply = ts
  I1Ii1i111I . compute_rloc_probe_rtt ( )
  oOoOII11IIi1Ii1i = I1Ii1i111I . print_state_change ( "up" )
  if ( I1Ii1i111I . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( I1Ii1i111I . rloc , True )
   I1Ii1i111I . state = LISP_RLOC_UP_STATE
   I1Ii1i111I . last_state_change = lisp_get_timestamp ( )
   o0ooo0oOO0o = lisp_map_cache . lookup_cache ( eid , True )
   if ( o0ooo0oOO0o ) : lisp_write_ipc_map_cache ( True , o0ooo0oOO0o )
   if 88 - 88: iII111i - I1ii11iIi11i / OoOoOO00 + O0 % oO0o
   if 22 - 22: o0oOOo0O0Ooo * O0 % Oo0Ooo
   if 52 - 52: I1IiiI % I1Ii111 - i1IIi . o0oOOo0O0Ooo % I1ii11iIi11i
   if 34 - 34: o0oOOo0O0Ooo / OoOoOO00
   if 74 - 74: IiII + i1IIi . II111iiii
  I1Ii1i111I . store_rloc_probe_hops ( hc , ttl )
  if 1 - 1: Ii1I - o0oOOo0O0Ooo / i11iIiiIii
  if 24 - 24: O0
  if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
  if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
  if ( jt ) : I1Ii1i111I . store_rloc_probe_latencies ( jt )
  if 85 - 85: IiII / Ii1I - I1ii11iIi11i * OOooOOo
  iIIi11Ii1iII = bold ( "RLOC-probe reply" , False )
  O0O0 = I1Ii1i111I . rloc . print_address_no_iid ( )
  ii1111Ii = bold ( str ( I1Ii1i111I . print_rloc_probe_rtt ( ) ) , False )
  iIIiiIi = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 8 - 8: oO0o - iIii1I11I1II1 * iII111i
  ii1I = ""
  if ( I1Ii1i111I . rloc_next_hop != None ) :
   IiI11I111 , Ii1i1Ii1Ii1i = I1Ii1i111I . rloc_next_hop
   ii1I = ", nh {}({})" . format ( Ii1i1Ii1Ii1i , IiI11I111 )
   if 86 - 86: OoOoOO00 + I1ii11iIi11i - Ii1I . I1Ii111 + I11i
   if 6 - 6: O0 . OoooooooOO - I11i
  iiiII1Iii11i1 = bold ( I1Ii1i111I . print_rloc_probe_latency ( ) , False )
  iiiII1Iii11i1 = ", latency {}" . format ( iiiII1Iii11i1 ) if jt else ""
  if 3 - 3: II111iiii . OoOoOO00 / i1IIi . I1ii11iIi11i - Ii1I
  oO0ooOOO = green ( lisp_print_eid_tuple ( eid , group ) , False )
  if 20 - 20: I11i + IiII
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}{}" ) . format ( iIIi11Ii1iII , red ( O0O0 , False ) , iIIiiIi , oO0ooOOO ,
  # OOooOOo + II111iiii . I11i
 oOoOII11IIi1Ii1i , ii1111Ii , ii1I , str ( hc ) + "/" + str ( ttl ) , iiiII1Iii11i1 ) )
  if 7 - 7: IiII . iIii1I11I1II1 % o0oOOo0O0Ooo + iII111i . OOooOOo + I1IiiI
  if ( I1Ii1i111I . rloc_next_hop == None ) : return
  if 64 - 64: iII111i - ooOoO0o % OoO0O00
  if 51 - 51: I1Ii111 . ooOoO0o
  if 100 - 100: o0oOOo0O0Ooo % iII111i
  if 44 - 44: IiII * OoOoOO00 - OoO0O00 - OoooooooOO - I1ii11iIi11i - II111iiii
  I1Ii1i111I = None
  I1iiI1iI1 = None
  while ( True ) :
   I1Ii1i111I = self if I1Ii1i111I == None else I1Ii1i111I . next_rloc
   if ( I1Ii1i111I == None ) : break
   if ( I1Ii1i111I . up_state ( ) == False ) : continue
   if ( I1Ii1i111I . rloc_probe_rtt == - 1 ) : continue
   if 27 - 27: I11i % Ii1I / iII111i . OoOoOO00
   if ( I1iiI1iI1 == None ) : I1iiI1iI1 = I1Ii1i111I
   if ( I1Ii1i111I . rloc_probe_rtt < I1iiI1iI1 . rloc_probe_rtt ) : I1iiI1iI1 = I1Ii1i111I
   if 88 - 88: iII111i - i11iIiiIii * I1Ii111 * i11iIiiIii - O0
   if 8 - 8: oO0o + O0
  if ( I1iiI1iI1 != None ) :
   IiI11I111 , Ii1i1Ii1Ii1i = I1iiI1iI1 . rloc_next_hop
   ii1I = bold ( "nh {}({})" . format ( Ii1i1Ii1Ii1i , IiI11I111 ) , False )
   lprint ( "    Install host-route via best {}" . format ( ii1I ) )
   lisp_install_host_route ( O0O0 , None , False )
   lisp_install_host_route ( O0O0 , Ii1i1Ii1Ii1i , True )
   if 52 - 52: I11i * OOooOOo - OoOoOO00 % iIii1I11I1II1 . II111iiii
   if 1 - 1: OOooOOo / I1IiiI / Ii1I * iII111i
   if 14 - 14: ooOoO0o . O0 * OOooOOo
 def add_to_rloc_probe_list ( self , eid , group ) :
  O0O0 = self . rloc . print_address_no_iid ( )
  I1I = self . translated_port
  if ( I1I != 0 ) : O0O0 += ":" + str ( I1I )
  if 34 - 34: I1ii11iIi11i . OOooOOo + OoO0O00 % o0oOOo0O0Ooo * O0 * I1IiiI
  if ( O0O0 not in lisp_rloc_probe_list ) :
   lisp_rloc_probe_list [ O0O0 ] = [ ]
   if 9 - 9: IiII / i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % I1Ii111
   if 65 - 65: I1IiiI % OoOoOO00
  if ( group . is_null ( ) ) : group . instance_id = 0
  for O00o00o00OO0 , oO0ooOOO , Oo in lisp_rloc_probe_list [ O0O0 ] :
   if ( oO0ooOOO . is_exact_match ( eid ) and Oo . is_exact_match ( group ) ) :
    if ( O00o00o00OO0 == self ) :
     if ( lisp_rloc_probe_list [ O0O0 ] == [ ] ) :
      lisp_rloc_probe_list . pop ( O0O0 )
      if 45 - 45: o0oOOo0O0Ooo
     return
     if 33 - 33: ooOoO0o % O0 % I1ii11iIi11i % o0oOOo0O0Ooo + i11iIiiIii . I1Ii111
    lisp_rloc_probe_list [ O0O0 ] . remove ( [ O00o00o00OO0 , oO0ooOOO , Oo ] )
    break
    if 21 - 21: I1Ii111 * I1ii11iIi11i * ooOoO0o
    if 73 - 73: OoOoOO00 * O0
  lisp_rloc_probe_list [ O0O0 ] . append ( [ self , eid , group ] )
  if 1 - 1: OOooOOo * OoooooooOO
  if 46 - 46: I1ii11iIi11i * I1Ii111 / OOooOOo / I1IiiI
  if 7 - 7: OOooOOo / OoOoOO00
  if 93 - 93: iIii1I11I1II1 * Ii1I - iII111i
  if 94 - 94: iIii1I11I1II1 * iIii1I11I1II1 * I11i % i11iIiiIii
  I1Ii1i111I = lisp_rloc_probe_list [ O0O0 ] [ 0 ] [ 0 ]
  if ( I1Ii1i111I . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 38 - 38: I1IiiI % I1ii11iIi11i * I1IiiI + OOooOOo - OoOoOO00
   if 78 - 78: OOooOOo + I1Ii111
   if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
 def delete_from_rloc_probe_list ( self , eid , group ) :
  O0O0 = self . rloc . print_address_no_iid ( )
  I1I = self . translated_port
  if ( I1I != 0 ) : O0O0 += ":" + str ( I1I )
  if ( O0O0 not in lisp_rloc_probe_list ) : return
  if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
  o000oO0O0ooo = [ ]
  for oo0O00OOOOO in lisp_rloc_probe_list [ O0O0 ] :
   if ( oo0O00OOOOO [ 0 ] != self ) : continue
   if ( oo0O00OOOOO [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( oo0O00OOOOO [ 2 ] . is_exact_match ( group ) == False ) : continue
   o000oO0O0ooo = oo0O00OOOOO
   break
   if 57 - 57: iII111i
  if ( o000oO0O0ooo == [ ] ) : return
  if 18 - 18: II111iiii % i11iIiiIii + I11i - OOooOOo
  try :
   lisp_rloc_probe_list [ O0O0 ] . remove ( o000oO0O0ooo )
   if ( lisp_rloc_probe_list [ O0O0 ] == [ ] ) :
    lisp_rloc_probe_list . pop ( O0O0 )
    if 100 - 100: o0oOOo0O0Ooo / Ii1I - iIii1I11I1II1 / oO0o
  except :
   return
   if 68 - 68: I11i / II111iiii * oO0o . II111iiii * OOooOOo
   if 78 - 78: I11i * OoO0O00 / II111iiii
   if 86 - 86: I1Ii111 % II111iiii
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  oOo0OOoooO = ""
  I1Ii1i111I = self
  while ( True ) :
   oOO0IIiiIi11iii1 = I1Ii1i111I . last_rloc_probe
   if ( oOO0IIiiIi11iii1 == None ) : oOO0IIiiIi11iii1 = 0
   II1I1I = I1Ii1i111I . last_rloc_probe_reply
   if ( II1I1I == None ) : II1I1I = 0
   ii1111Ii = I1Ii1i111I . print_rloc_probe_rtt ( )
   I111 = space ( 4 )
   if 33 - 33: iIii1I11I1II1 . I1ii11iIi11i - O0 - IiII
   if ( I1Ii1i111I . rloc_next_hop == None ) :
    oOo0OOoooO += "RLOC-Probing:\n"
   else :
    IiI11I111 , Ii1i1Ii1Ii1i = I1Ii1i111I . rloc_next_hop
    oOo0OOoooO += "RLOC-Probing for nh {}({}):\n" . format ( Ii1i1Ii1Ii1i , IiI11I111 )
    if 51 - 51: OoooooooOO . I1IiiI . i11iIiiIii
    if 76 - 76: OoOoOO00 + iII111i . ooOoO0o + OoO0O00 + I1IiiI / IiII
   oOo0OOoooO += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( I111 , lisp_print_elapsed ( oOO0IIiiIi11iii1 ) ,
   # ooOoO0o % I1IiiI . o0oOOo0O0Ooo . I1IiiI % II111iiii
 I111 , lisp_print_elapsed ( II1I1I ) , ii1111Ii )
   if 7 - 7: O0 + IiII
   if ( trailing_linefeed ) : oOo0OOoooO += "\n"
   if 79 - 79: iIii1I11I1II1 * oO0o . iIii1I11I1II1 * O0
   I1Ii1i111I = I1Ii1i111I . next_rloc
   if ( I1Ii1i111I == None ) : break
   oOo0OOoooO += "\n"
   if 13 - 13: I1ii11iIi11i . IiII - I11i
  return ( oOo0OOoooO )
  if 81 - 81: i11iIiiIii
  if 7 - 7: IiII - OoOoOO00 * i1IIi
 def get_encap_keys ( self ) :
  I1I = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 14 - 14: I1ii11iIi11i . OoO0O00
  O0O0 = self . rloc . print_address_no_iid ( ) + ":" + I1I
  if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
  try :
   iI1iiiiiii = lisp_crypto_keys_by_rloc_encap [ O0O0 ]
   if ( iI1iiiiiii [ 1 ] ) : return ( iI1iiiiiii [ 1 ] . encrypt_key , iI1iiiiiii [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
   if 29 - 29: O0 + iII111i
   if 4 - 4: I11i * I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
 def rloc_recent_rekey ( self ) :
  I1I = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
  O0O0 = self . rloc . print_address_no_iid ( ) + ":" + I1I
  if 76 - 76: OoooooooOO - O0
  try :
   Ooo00o000o = lisp_crypto_keys_by_rloc_encap [ O0O0 ] [ 1 ]
   if ( Ooo00o000o == None ) : return ( False )
   if ( Ooo00o000o . last_rekey == None ) : return ( True )
   return ( time . time ( ) - Ooo00o000o . last_rekey < 1 )
  except :
   return ( False )
   if 17 - 17: Oo0Ooo % I1Ii111 . oO0o - O0
   if 32 - 32: O0 % O0
   if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
   if 65 - 65: I1ii11iIi11i % ooOoO0o - OoOoOO00 + ooOoO0o + Oo0Ooo
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
  if 95 - 95: I1Ii111 * i11iIiiIii - I1IiiI - OoOoOO00 . ooOoO0o
  if 34 - 34: OoooooooOO % I1ii11iIi11i + OoooooooOO % i11iIiiIii / IiII - ooOoO0o
 def print_mapping ( self , eid_indent , rloc_indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  o0o0Oo0o0oOo = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 74 - 74: iIii1I11I1II1 % II111iiii + IiII
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , o0o0Oo0o0oOo , i1 ,
 len ( self . rloc_set ) ) )
  for I1Ii1i111I in self . rloc_set : I1Ii1i111I . print_rloc ( rloc_indent )
  if 71 - 71: I1IiiI / O0 * i1IIi . i1IIi + Oo0Ooo
  if 32 - 32: i1IIi * I1Ii111 % I1IiiI / IiII . I1Ii111
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 11 - 11: OOooOOo
  if 25 - 25: i1IIi
 def print_ttl ( self ) :
  IiIi1iIIiII1i = self . map_cache_ttl
  if ( IiIi1iIIiII1i == None ) : return ( "forever" )
  if 99 - 99: OOooOOo + OoooooooOO . I1Ii111 * Oo0Ooo % oO0o
  if ( IiIi1iIIiII1i >= 3600 ) :
   if ( ( IiIi1iIIiII1i % 3600 ) == 0 ) :
    IiIi1iIIiII1i = str ( old_div ( IiIi1iIIiII1i , 3600 ) ) + " hours"
   else :
    IiIi1iIIiII1i = str ( IiIi1iIIiII1i * 60 ) + " mins"
    if 75 - 75: iII111i
  elif ( IiIi1iIIiII1i >= 60 ) :
   if ( ( IiIi1iIIiII1i % 60 ) == 0 ) :
    IiIi1iIIiII1i = str ( old_div ( IiIi1iIIiII1i , 60 ) ) + " mins"
   else :
    IiIi1iIIiII1i = str ( IiIi1iIIiII1i ) + " secs"
    if 8 - 8: I1ii11iIi11i . I11i / I1ii11iIi11i - i1IIi
  else :
   IiIi1iIIiII1i = str ( IiIi1iIIiII1i ) + " secs"
   if 22 - 22: OOooOOo
  return ( IiIi1iIIiII1i )
  if 7 - 7: O0 - I1ii11iIi11i - OoO0O00 * I1Ii111
  if 17 - 17: o0oOOo0O0Ooo % OoO0O00 - I11i * o0oOOo0O0Ooo - i1IIi / I1IiiI
 def refresh ( self ) :
  if ( self . group . is_null ( ) ) : return ( self . refresh_unicast ( ) )
  return ( self . refresh_multicast ( ) )
  if 100 - 100: OoO0O00 * i1IIi * o0oOOo0O0Ooo * Oo0Ooo - o0oOOo0O0Ooo
  if 100 - 100: iII111i - i11iIiiIii + OoO0O00
 def refresh_unicast ( self ) :
  return ( self . is_active ( ) and self . has_ttl_elapsed ( ) and
 self . gleaned == False )
  if 50 - 50: II111iiii
  if 42 - 42: OOooOOo * I1Ii111
 def refresh_multicast ( self ) :
  if 53 - 53: II111iiii % OOooOOo / I1ii11iIi11i * OoOoOO00 % I1ii11iIi11i * iII111i
  if 91 - 91: iII111i . OoooooooOO
  if 90 - 90: i11iIiiIii - I1IiiI
  if 39 - 39: iII111i % OoooooooOO % Ii1I % I1IiiI
  if 63 - 63: OoO0O00 - I1Ii111 - II111iiii
  i1i111Iiiiiii = int ( ( time . time ( ) - self . uptime ) % self . map_cache_ttl )
  OoOooO00 = ( i1i111Iiiiiii in [ 0 , 1 , 2 ] )
  if ( OoOooO00 == False ) : return ( False )
  if 66 - 66: i1IIi + I1IiiI
  if 45 - 45: I1Ii111 . iII111i + OoO0O00 - O0
  if 71 - 71: Oo0Ooo + OOooOOo
  if 94 - 94: OOooOOo
  Ooooooo = ( ( time . time ( ) - self . last_multicast_map_request ) <= 2 )
  if ( Ooooooo ) : return ( False )
  if 66 - 66: iII111i + i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * IiII
  self . last_multicast_map_request = lisp_get_timestamp ( )
  return ( True )
  if 59 - 59: I1ii11iIi11i + i1IIi / I11i . iII111i - II111iiii
  if 66 - 66: Ii1I + OoOoOO00 - I11i / o0oOOo0O0Ooo + iIii1I11I1II1
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  i1i111Iiiiiii = time . time ( ) - self . last_refresh_time
  if ( i1i111Iiiiiii >= self . map_cache_ttl ) : return ( True )
  if 66 - 66: OOooOOo - I1Ii111 - OoOoOO00 - i1IIi * Ii1I
  if 23 - 23: IiII - OoOoOO00 . OoO0O00
  if 81 - 81: I1Ii111 / I1ii11iIi11i
  if 69 - 69: I1IiiI
  if 79 - 79: ooOoO0o
  o0o0oo000Oo = self . map_cache_ttl - ( old_div ( self . map_cache_ttl , 10 ) )
  if ( i1i111Iiiiiii >= o0o0oo000Oo ) : return ( True )
  return ( False )
  if 95 - 95: ooOoO0o . I11i + iIii1I11I1II1 . iII111i * i11iIiiIii
  if 34 - 34: IiII / I1Ii111 + O0 / OoO0O00
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  i1i111Iiiiiii = time . time ( ) - self . stats . last_increment
  return ( i1i111Iiiiiii <= 60 )
  if 96 - 96: I1Ii111 % o0oOOo0O0Ooo + OoO0O00 - ooOoO0o
  if 38 - 38: OOooOOo . O0
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 42 - 42: OoooooooOO / I1IiiI / o0oOOo0O0Ooo . I1ii11iIi11i . OoO0O00 % II111iiii
  if 55 - 55: o0oOOo0O0Ooo
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 87 - 87: ooOoO0o - IiII % Ii1I
  if 76 - 76: I11i - iIii1I11I1II1 - i1IIi + i1IIi
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for I1Ii1i111I in self . best_rloc_set :
   I1Ii1i111I . delete_from_rloc_probe_list ( self . eid , self . group )
   if 60 - 60: I11i + OOooOOo - o0oOOo0O0Ooo
   if 64 - 64: II111iiii / iII111i * OoOoOO00 / OOooOOo / Ii1I
   if 19 - 19: OoOoOO00 % I1Ii111
 def build_best_rloc_set ( self ) :
  IIIiiIiiiI1 = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 77 - 77: I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
  if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
  if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
  if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
  II1iI111 = 256
  for I1Ii1i111I in self . rloc_set :
   if ( I1Ii1i111I . up_state ( ) ) : II1iI111 = min ( I1Ii1i111I . priority , II1iI111 )
   if 69 - 69: I1ii11iIi11i % I1Ii111 / OoooooooOO % oO0o
   if 4 - 4: OoOoOO00 * i11iIiiIii - OoOoOO00 * o0oOOo0O0Ooo % I1ii11iIi11i
   if 19 - 19: OOooOOo
   if 73 - 73: ooOoO0o / O0 / I1Ii111 . OoooooooOO
   if 88 - 88: OoooooooOO - oO0o
   if 80 - 80: ooOoO0o
   if 38 - 38: IiII + OoO0O00 * I11i * iIii1I11I1II1 * oO0o
   if 74 - 74: I1IiiI
   if 39 - 39: iII111i * IiII / iII111i * IiII % I1ii11iIi11i
   if 27 - 27: iIii1I11I1II1 . ooOoO0o
  for I1Ii1i111I in self . rloc_set :
   if ( I1Ii1i111I . priority <= II1iI111 ) :
    if ( I1Ii1i111I . unreach_state ( ) and I1Ii1i111I . last_rloc_probe == None ) :
     I1Ii1i111I . last_rloc_probe = lisp_get_timestamp ( )
     if 74 - 74: i1IIi % OoOoOO00
    self . best_rloc_set . append ( I1Ii1i111I )
    if 98 - 98: IiII * OOooOOo / O0 - I1Ii111 . I1Ii111 + OOooOOo
    if 61 - 61: iII111i * Ii1I % Ii1I + I1IiiI
    if 23 - 23: oO0o + I1Ii111 / OoooooooOO / O0 + IiII
    if 80 - 80: i11iIiiIii - OoooooooOO + II111iiii / i1IIi - oO0o
    if 100 - 100: Ii1I
    if 73 - 73: IiII - O0
    if 54 - 54: OOooOOo
    if 28 - 28: i1IIi - Oo0Ooo * OoO0O00 + OoooooooOO - Ii1I * i11iIiiIii
  for I1Ii1i111I in IIIiiIiiiI1 :
   if ( I1Ii1i111I . priority < II1iI111 ) : continue
   I1Ii1i111I . delete_from_rloc_probe_list ( self . eid , self . group )
   if 71 - 71: iII111i - OOooOOo / iIii1I11I1II1 % i11iIiiIii
  for I1Ii1i111I in self . best_rloc_set :
   if ( I1Ii1i111I . rloc . is_null ( ) ) : continue
   I1Ii1i111I . add_to_rloc_probe_list ( self . eid , self . group )
   if 39 - 39: o0oOOo0O0Ooo
   if 32 - 32: iIii1I11I1II1 . II111iiii / IiII % O0 / iII111i
   if 97 - 97: iIii1I11I1II1
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  Oo00oo = lisp_packet . packet
  i11Iiiii11 = lisp_packet . inner_version
  i1iIii = len ( self . best_rloc_set )
  if ( i1iIii == 0 ) :
   self . stats . increment ( len ( Oo00oo ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 76 - 76: I1ii11iIi11i
   if 64 - 64: I11i
  Ii1Iiiii = 4 if lisp_load_split_pings else 0
  oOOo0O0Oo = lisp_packet . hash_ports ( )
  if ( i11Iiiii11 == 4 ) :
   for iIi1iIIIiIiI in range ( 8 + Ii1Iiiii ) :
    oOOo0O0Oo = oOOo0O0Oo ^ struct . unpack ( "B" , Oo00oo [ iIi1iIIIiIiI + 12 : iIi1iIIIiIiI + 13 ] ) [ 0 ]
    if 94 - 94: O0 + O0 % I1ii11iIi11i % i1IIi
  elif ( i11Iiiii11 == 6 ) :
   for iIi1iIIIiIiI in range ( 0 , 32 + Ii1Iiiii , 4 ) :
    oOOo0O0Oo = oOOo0O0Oo ^ struct . unpack ( "I" , Oo00oo [ iIi1iIIIiIiI + 8 : iIi1iIIIiIiI + 12 ] ) [ 0 ]
    if 15 - 15: I1IiiI
   oOOo0O0Oo = ( oOOo0O0Oo >> 16 ) + ( oOOo0O0Oo & 0xffff )
   oOOo0O0Oo = ( oOOo0O0Oo >> 8 ) + ( oOOo0O0Oo & 0xff )
  else :
   for iIi1iIIIiIiI in range ( 0 , 12 + Ii1Iiiii , 4 ) :
    oOOo0O0Oo = oOOo0O0Oo ^ struct . unpack ( "I" , Oo00oo [ iIi1iIIIiIiI : iIi1iIIIiIiI + 4 ] ) [ 0 ]
    if 48 - 48: Ii1I * IiII % O0 - II111iiii
    if 66 - 66: iIii1I11I1II1 / OOooOOo
    if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
  if ( lisp_data_plane_logging ) :
   OoO0ooOOo0o0 = [ ]
   for O00o00o00OO0 in self . best_rloc_set :
    if ( O00o00o00OO0 . rloc . is_null ( ) ) : continue
    OoO0ooOOo0o0 . append ( [ O00o00o00OO0 . rloc . print_address_no_iid ( ) , O00o00o00OO0 . print_state ( ) ] )
    if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( oOOo0O0Oo ) , oOOo0O0Oo % i1iIii , red ( str ( OoO0ooOOo0o0 ) , False ) ) )
   if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
   if 46 - 46: I11i - ooOoO0o . I1IiiI
   if 36 - 36: I11i + OoO0O00 * O0 * OoOoOO00 * iII111i
   if 90 - 90: i11iIiiIii / i1IIi
   if 35 - 35: Ii1I . I11i / oO0o / OoOoOO00
   if 5 - 5: I1ii11iIi11i . o0oOOo0O0Ooo * iII111i * I1ii11iIi11i % I1Ii111
  I1Ii1i111I = self . best_rloc_set [ oOOo0O0Oo % i1iIii ]
  if 83 - 83: iIii1I11I1II1 * o0oOOo0O0Ooo % i11iIiiIii + OoO0O00 . O0
  if 87 - 87: II111iiii - iIii1I11I1II1 % I11i % I1IiiI . o0oOOo0O0Ooo
  if 52 - 52: i11iIiiIii . oO0o / OoooooooOO - OoO0O00
  if 7 - 7: I1IiiI * I1IiiI % OOooOOo % iIii1I11I1II1 * OoO0O00 . o0oOOo0O0Ooo
  if 32 - 32: ooOoO0o / i1IIi
  oO0 = lisp_get_echo_nonce ( I1Ii1i111I . rloc , None )
  if ( oO0 ) :
   oO0 . change_state ( I1Ii1i111I )
   if ( I1Ii1i111I . no_echoed_nonce_state ( ) ) :
    oO0 . request_nonce_sent = None
    if 55 - 55: oO0o . OoOoOO00 + OoooooooOO - ooOoO0o . OoooooooOO
    if 77 - 77: I1IiiI
    if 16 - 16: I1IiiI + ooOoO0o - O0 / o0oOOo0O0Ooo
    if 36 - 36: Oo0Ooo - OoOoOO00 - II111iiii
    if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
    if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
  if ( I1Ii1i111I . up_state ( ) == False ) :
   IiI1I11iIiIIII = oOOo0O0Oo % i1iIii
   OOOooo0OooOoO = ( IiI1I11iIiIIII + 1 ) % i1iIii
   while ( OOOooo0OooOoO != IiI1I11iIiIIII ) :
    I1Ii1i111I = self . best_rloc_set [ OOOooo0OooOoO ]
    if ( I1Ii1i111I . up_state ( ) ) : break
    OOOooo0OooOoO = ( OOOooo0OooOoO + 1 ) % i1iIii
    if 88 - 88: ooOoO0o
   if ( OOOooo0OooOoO == IiI1I11iIiIIII ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 91 - 91: OoO0O00 % IiII / I1IiiI - i11iIiiIii - IiII * ooOoO0o
    if 54 - 54: O0 % o0oOOo0O0Ooo + o0oOOo0O0Ooo % i11iIiiIii * I11i
    if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
    if 98 - 98: iII111i % IiII + OoO0O00
    if 23 - 23: OOooOOo
    if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
  I1Ii1i111I . stats . increment ( len ( Oo00oo ) )
  if 99 - 99: II111iiii + O0
  if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
  if 88 - 88: Oo0Ooo . iII111i
  if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
  if ( I1Ii1i111I . rle_name and I1Ii1i111I . rle == None ) :
   if ( I1Ii1i111I . rle_name in lisp_rle_list ) :
    I1Ii1i111I . rle = lisp_rle_list [ I1Ii1i111I . rle_name ]
    if 9 - 9: OoOoOO00 % i1IIi + IiII
    if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
  if ( I1Ii1i111I . rle ) : return ( [ None , None , None , None , I1Ii1i111I . rle , None ] )
  if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
  if 95 - 95: ooOoO0o
  if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
  if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
  if ( I1Ii1i111I . elp and I1Ii1i111I . elp . use_elp_node ) :
   return ( [ I1Ii1i111I . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 32 - 32: OoOoOO00 % i11iIiiIii
   if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
   if 44 - 44: I1Ii111 + ooOoO0o
   if 15 - 15: I11i + OoO0O00 + OoOoOO00
   if 100 - 100: I1Ii111
  oo000OO = None if ( I1Ii1i111I . rloc . is_null ( ) ) else I1Ii1i111I . rloc
  I1I = I1Ii1i111I . translated_port
  oo0oOooo0O = self . action if ( oo000OO == None ) else None
  if 72 - 72: OoOoOO00 * Oo0Ooo + iII111i
  if 99 - 99: II111iiii . OoooooooOO * iIii1I11I1II1
  if 72 - 72: OoooooooOO . I1ii11iIi11i * I1Ii111 / OoooooooOO % OOooOOo
  if 60 - 60: OoO0O00
  if 54 - 54: I1IiiI + O0 - I1Ii111 - oO0o + O0 - I1ii11iIi11i
  oOooo0oOOOO = None
  if ( oO0 and oO0 . request_nonce_timeout ( ) == False ) :
   oOooo0oOOOO = oO0 . get_request_or_echo_nonce ( ipc_socket , oo000OO )
   if 21 - 21: ooOoO0o . i1IIi / Oo0Ooo . OoO0O00
   if 49 - 49: oO0o % i11iIiiIii * Ii1I
   if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
   if 61 - 61: O0 - i11iIiiIii * o0oOOo0O0Ooo
   if 92 - 92: Oo0Ooo + OOooOOo - i11iIiiIii
  return ( [ oo000OO , I1I , oOooo0oOOOO , oo0oOooo0O , None , I1Ii1i111I ] )
  if 26 - 26: O0 % Oo0Ooo + ooOoO0o - Ii1I . Oo0Ooo
  if 33 - 33: I1Ii111 / iII111i . I1Ii111 % II111iiii
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 52 - 52: I1ii11iIi11i
  if 1 - 1: II111iiii + I1ii11iIi11i * OoOoOO00 % ooOoO0o - iII111i % OoooooooOO
  if 77 - 77: iII111i + o0oOOo0O0Ooo
  if 60 - 60: I1ii11iIi11i
  if 23 - 23: iII111i % I1IiiI % I1Ii111 * oO0o * I1IiiI
  for OO0oooo in self . rloc_set :
   for I1Ii1i111I in rloc_address_set :
    if ( I1Ii1i111I . is_exact_match ( OO0oooo . rloc ) == False ) : continue
    I1Ii1i111I = None
    break
    if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
   if ( I1Ii1i111I == rloc_address_set [ - 1 ] ) : return ( False )
   if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
  return ( True )
  if 52 - 52: OoooooooOO
  if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
 def get_rloc ( self , rloc ) :
  for OO0oooo in self . rloc_set :
   O00o00o00OO0 = OO0oooo . rloc
   if ( rloc . is_exact_match ( O00o00o00OO0 ) ) : return ( OO0oooo )
   if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
  return ( None )
  if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
  if 86 - 86: Oo0Ooo / OoO0O00
 def get_rloc_by_interface ( self , interface ) :
  for OO0oooo in self . rloc_set :
   if ( OO0oooo . interface == interface ) : return ( OO0oooo )
   if 78 - 78: I1IiiI * I1IiiI
  return ( None )
  if 13 - 13: oO0o
  if 43 - 43: oO0o / Ii1I % OOooOOo
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   i11IIII1Ii = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( i11IIII1Ii == None ) :
    i11IIII1Ii = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , i11IIII1Ii )
    if 45 - 45: II111iiii
   i11IIII1Ii . add_source_entry ( self )
   if 41 - 41: Ii1I / OOooOOo * Oo0Ooo . O0 - i11iIiiIii
   if 77 - 77: o0oOOo0O0Ooo + I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
   if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   o0ooo0oOO0o = lisp_map_cache . lookup_cache ( self . group , True )
   if ( o0ooo0oOO0o == None ) :
    o0ooo0oOO0o = lisp_mapping ( self . group , self . group , [ ] )
    o0ooo0oOO0o . eid . copy_address ( self . group )
    o0ooo0oOO0o . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , o0ooo0oOO0o )
    if 43 - 43: OOooOOo . O0
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( o0ooo0oOO0o . group )
   o0ooo0oOO0o . add_source_entry ( self )
   if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
  if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    I1I11I1IIi = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( I1I11I1IIi ) )
    if 3 - 3: i1IIi + OoOoOO00 - OoOoOO00
  else :
   o0ooo0oOO0o = lisp_map_cache . lookup_cache ( self . group , True )
   if ( o0ooo0oOO0o == None ) : return
   if 85 - 85: o0oOOo0O0Ooo / o0oOOo0O0Ooo + Oo0Ooo * II111iiii + Ii1I * Ii1I
   II1Iii = o0ooo0oOO0o . lookup_source_cache ( self . eid , True )
   if ( II1Iii == None ) : return
   if 27 - 27: Ii1I . OoOoOO00 % oO0o % o0oOOo0O0Ooo / i11iIiiIii - iIii1I11I1II1
   o0ooo0oOO0o . source_cache . delete_cache ( self . eid )
   if ( o0ooo0oOO0o . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 77 - 77: o0oOOo0O0Ooo . OoOoOO00 % Ii1I
    if 94 - 94: I11i / IiII - OoOoOO00 % OoO0O00 % i11iIiiIii . Ii1I
    if 26 - 26: i1IIi - Ii1I * I1IiiI
    if 74 - 74: I1ii11iIi11i * oO0o * i1IIi % oO0o % I11i . i1IIi
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 90 - 90: I1Ii111 + O0
  if 100 - 100: II111iiii - I1Ii111 % OoO0O00
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 67 - 67: oO0o . I1IiiI % iIii1I11I1II1 + o0oOOo0O0Ooo / I1ii11iIi11i * II111iiii
  if 1 - 1: OoooooooOO / I1ii11iIi11i - O0
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 72 - 72: Oo0Ooo * iII111i - I11i
  if 81 - 81: I1Ii111
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  oooo = "," + str ( self . secondary_iid )
  return ( prefix . replace ( oooo , oooo + "*" ) )
  if 85 - 85: O0 % OoOoOO00 . I1ii11iIi11i
  if 46 - 46: OOooOOo * iIii1I11I1II1
 def increment_decap_stats ( self , packet ) :
  I1I = packet . udp_dport
  if ( I1I == LISP_DATA_PORT ) :
   I1Ii1i111I = self . get_rloc ( packet . outer_dest )
  else :
   if 33 - 33: OoO0O00 * II111iiii / i1IIi
   if 93 - 93: I1Ii111 % I11i
   if 64 - 64: I1IiiI % OoOoOO00 / Oo0Ooo
   if 40 - 40: Ii1I + iIii1I11I1II1 / oO0o . II111iiii % O0 - IiII
   for I1Ii1i111I in self . rloc_set :
    if ( I1Ii1i111I . translated_port != 0 ) : break
    if 49 - 49: IiII - OOooOOo * OOooOOo . O0
    if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
  if ( I1Ii1i111I != None ) : I1Ii1i111I . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
  if 61 - 61: OoO0O00
 def rtrs_in_rloc_set ( self ) :
  for I1Ii1i111I in self . rloc_set :
   if ( I1Ii1i111I . is_rtr ( ) ) : return ( True )
   if 100 - 100: OoOoOO00
  return ( False )
  if 97 - 97: OoooooooOO
  if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
 def add_recent_source ( self , source ) :
  self . recent_sources [ source . print_address ( ) ] = lisp_get_timestamp ( )
  if 35 - 35: iII111i % OoO0O00 * O0
  if 37 - 37: OOooOOo
  if 100 - 100: Oo0Ooo * I1IiiI . ooOoO0o
class lisp_dynamic_eid ( object ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 53 - 53: OOooOOo + o0oOOo0O0Ooo * Ii1I + O0
  if 75 - 75: OoooooooOO
 def get_timeout ( self , interface ) :
  try :
   I11iiI111iI = lisp_myinterfaces [ interface ]
   self . timeout = I11iiI111iI . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 90 - 90: II111iiii - Oo0Ooo - IiII / I1Ii111
   if 51 - 51: II111iiii * iII111i
   if 30 - 30: I1Ii111 - OoOoOO00 / OOooOOo * I1IiiI + Ii1I
   if 41 - 41: ooOoO0o . i1IIi * iIii1I11I1II1 - I1IiiI
class lisp_group_mapping ( object ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
  if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
  if 17 - 17: OOooOOo / i11iIiiIii - i11iIiiIii . II111iiii . ooOoO0o
  if 38 - 38: OOooOOo . OoooooooOO . II111iiii + OoO0O00 / oO0o . OoooooooOO
  if 100 - 100: OoO0O00
  if 36 - 36: oO0o + Ii1I - O0
  if 19 - 19: O0 + I1Ii111 . I1Ii111 * IiII * ooOoO0o + i1IIi
  if 51 - 51: ooOoO0o % OoOoOO00 % i1IIi / O0
  if 11 - 11: OOooOOo . I1ii11iIi11i * OOooOOo * OoO0O00
  if 11 - 11: I11i
  if 85 - 85: OoOoOO00 - Ii1I / Oo0Ooo % I1ii11iIi11i
def lisp_is_group_more_specific ( group_str , group_mapping ) :
 oooo = group_mapping . group_prefix . instance_id
 oOo = group_mapping . group_prefix . mask_len
 o0o0Oo0o0oOo = lisp_address ( LISP_AFI_IPV4 , group_str , 32 , oooo )
 if ( o0o0Oo0o0oOo . is_more_specific ( group_mapping . group_prefix ) ) : return ( oOo )
 return ( - 1 )
 if 12 - 12: i1IIi + o0oOOo0O0Ooo / oO0o . O0
 if 37 - 37: IiII
 if 99 - 99: i11iIiiIii % i11iIiiIii . I11i * I1ii11iIi11i . OoO0O00 / I1IiiI
 if 44 - 44: iII111i - OoO0O00 / i11iIiiIii
 if 55 - 55: O0 * OoO0O00 * i1IIi
 if 9 - 9: IiII
 if 64 - 64: ooOoO0o + OoooooooOO
def lisp_lookup_group ( group ) :
 OoO0ooOOo0o0 = None
 for oo0oooo00000 in list ( lisp_group_mapping_list . values ( ) ) :
  oOo = lisp_is_group_more_specific ( group , oo0oooo00000 )
  if ( oOo == - 1 ) : continue
  if ( OoO0ooOOo0o0 == None or oOo > OoO0ooOOo0o0 . group_prefix . mask_len ) : OoO0ooOOo0o0 = oo0oooo00000
  if 99 - 99: Oo0Ooo . i1IIi . ooOoO0o . i1IIi * iIii1I11I1II1 . I11i
 return ( OoO0ooOOo0o0 )
 if 82 - 82: I11i . ooOoO0o - ooOoO0o
 if 11 - 11: I1ii11iIi11i / o0oOOo0O0Ooo % I1ii11iIi11i / OoooooooOO
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 35 - 35: i1IIi % I11i * I1Ii111 + IiII
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
  if 53 - 53: I1IiiI
  if 62 - 62: o0oOOo0O0Ooo
  if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
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
  if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
  if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 84 - 84: OoOoOO00
  if 80 - 80: oO0o
 def print_flags ( self , html ) :
  if ( html == False ) :
   oOo0OOoooO = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # II111iiii * OOooOOo . OoOoOO00 * I1ii11iIi11i
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   o0OO00 = self . print_flags ( False )
   o0OO00 = o0OO00 . split ( "-" )
   oOo0OOoooO = ""
   for o000o000oOo in o0OO00 :
    iIiI1II = lisp_site_flags [ o000o000oOo . upper ( ) ]
    iIiI1II = iIiI1II . format ( "" if o000o000oOo . isupper ( ) else "not " )
    oOo0OOoooO += lisp_span ( o000o000oOo , iIiI1II )
    if ( o000o000oOo . lower ( ) != "n" ) : oOo0OOoooO += "-"
    if 46 - 46: I1Ii111 / I11i
    if 13 - 13: I1ii11iIi11i + II111iiii * IiII * OoooooooOO + O0 * O0
  return ( oOo0OOoooO )
  if 15 - 15: Oo0Ooo % I11i * O0
  if 61 - 61: I1ii11iIi11i - ooOoO0o / OoOoOO00 % OOooOOo * i1IIi . IiII
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 27 - 27: I1ii11iIi11i % iII111i . Oo0Ooo * iIii1I11I1II1
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 40 - 40: I11i
  if 58 - 58: o0oOOo0O0Ooo / OOooOOo . oO0o % ooOoO0o
 def build_sort_key ( self ) :
  IiiIIIi1I1i11 = lisp_cache ( )
  iiiO0OO00o00Oo , Ooo00o000o = IiiIIIi1I1i11 . build_key ( self . eid )
  I1o0O = ""
  if ( self . group . is_null ( ) == False ) :
   Ooi11I1i1IiI1i , I1o0O = IiiIIIi1I1i11 . build_key ( self . group )
   I1o0O = "-" + I1o0O [ 0 : 12 ] + "-" + str ( Ooi11I1i1IiI1i ) + "-" + I1o0O [ 12 : : ]
   if 25 - 25: IiII
  Ooo00o000o = Ooo00o000o [ 0 : 12 ] + "-" + str ( iiiO0OO00o00Oo ) + "-" + Ooo00o000o [ 12 : : ] + I1o0O
  del ( IiiIIIi1I1i11 )
  return ( Ooo00o000o )
  if 47 - 47: I1ii11iIi11i / I1IiiI - Oo0Ooo - Ii1I / Oo0Ooo % IiII
  if 33 - 33: II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % i11iIiiIii
 def merge_in_site_eid ( self , child ) :
  o0Oo00OO0O0 = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   o0Oo00OO0O0 = self . merge_rles_in_site_eid ( )
   if 55 - 55: OOooOOo - OoO0O00 . I1IiiI % o0oOOo0O0Ooo + iII111i
   if 10 - 10: iIii1I11I1II1 - Ii1I
   if 84 - 84: iII111i
   if 21 - 21: i11iIiiIii
   if 30 - 30: OoO0O00 + OoooooooOO
   if 98 - 98: I1ii11iIi11i % I1IiiI
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
  return ( o0Oo00OO0O0 )
  if 66 - 66: IiII
  if 56 - 56: oO0o + OoooooooOO
 def copy_rloc_records ( self ) :
  oo0OOOoOooO = [ ]
  for OO0oooo in self . registered_rlocs :
   oo0OOOoOooO . append ( copy . deepcopy ( OO0oooo ) )
   if 11 - 11: i1IIi / iII111i
  return ( oo0OOOoOooO )
  if 14 - 14: O0
  if 9 - 9: I1Ii111 * i11iIiiIii / o0oOOo0O0Ooo / iII111i
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for oOoooooOooO in list ( self . individual_registrations . values ( ) ) :
   if ( self . site_id != oOoooooOooO . site_id ) : continue
   if ( oOoooooOooO . registered == False ) : continue
   self . registered_rlocs += oOoooooOooO . copy_rloc_records ( )
   if 57 - 57: iII111i
   if 63 - 63: iIii1I11I1II1
   if 63 - 63: Ii1I % I1Ii111 + O0 * OoO0O00 . oO0o
   if 34 - 34: I1IiiI . I1ii11iIi11i . O0 - OoOoOO00 - i11iIiiIii / iII111i
   if 63 - 63: OOooOOo
   if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
  oo0OOOoOooO = [ ]
  for OO0oooo in self . registered_rlocs :
   if ( OO0oooo . rloc . is_null ( ) or len ( oo0OOOoOooO ) == 0 ) :
    oo0OOOoOooO . append ( OO0oooo )
    continue
    if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
   for ooooooOO0oO0 in oo0OOOoOooO :
    if ( ooooooOO0oO0 . rloc . is_null ( ) ) : continue
    if ( OO0oooo . rloc . is_exact_match ( ooooooOO0oO0 . rloc ) ) : break
    if 7 - 7: Ii1I - I11i / I1ii11iIi11i + iII111i
   if ( ooooooOO0oO0 == oo0OOOoOooO [ - 1 ] ) : oo0OOOoOooO . append ( OO0oooo )
   if 47 - 47: I11i * IiII / oO0o - OoooooooOO . OoooooooOO / I11i
  self . registered_rlocs = oo0OOOoOooO
  if 73 - 73: Ii1I . IiII % IiII
  if 56 - 56: I1Ii111 + iII111i + iII111i
  if 99 - 99: o0oOOo0O0Ooo % I1ii11iIi11i / Oo0Ooo . O0 + OoO0O00 * OoOoOO00
  if 48 - 48: iIii1I11I1II1 + O0 * I11i * i11iIiiIii . Ii1I / i1IIi
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 48 - 48: i1IIi % iIii1I11I1II1 + I1IiiI - OoOoOO00 % I11i . I1Ii111
  if 66 - 66: I1Ii111 * i11iIiiIii + I1IiiI % II111iiii
 def merge_rles_in_site_eid ( self ) :
  if 47 - 47: II111iiii % o0oOOo0O0Ooo
  if 26 - 26: I1ii11iIi11i / I11i / Oo0Ooo / i1IIi + O0 * ooOoO0o
  if 53 - 53: IiII / II111iiii / oO0o % O0 / I1Ii111
  if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
  Oo0oooo00 = { }
  for OO0oooo in self . registered_rlocs :
   if ( OO0oooo . rle == None ) : continue
   for iI11i1ii11i11 in OO0oooo . rle . rle_nodes :
    IiI = iI11i1ii11i11 . address . print_address_no_iid ( )
    Oo0oooo00 [ IiI ] = iI11i1ii11i11 . address
    if 68 - 68: iII111i + OOooOOo - Ii1I
   break
   if 67 - 67: OoooooooOO * O0 * Ii1I . ooOoO0o
   if 15 - 15: iII111i / O0
   if 65 - 65: oO0o * ooOoO0o . I11i / i11iIiiIii - IiII * OoO0O00
   if 57 - 57: iII111i * I11i % o0oOOo0O0Ooo * OoOoOO00 % I1ii11iIi11i + i11iIiiIii
   if 66 - 66: i11iIiiIii . ooOoO0o
  self . merge_rlocs_in_site_eid ( )
  if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
  if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
  if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
  if 78 - 78: i1IIi
  if 25 - 25: Ii1I * II111iiii / OoOoOO00
  if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
  if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
  if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
  i1iI1IIIi1iIii1 = [ ]
  for OO0oooo in self . registered_rlocs :
   if ( self . registered_rlocs . index ( OO0oooo ) == 0 ) :
    i1iI1IIIi1iIii1 . append ( OO0oooo )
    continue
    if 64 - 64: OoOoOO00
   if ( OO0oooo . rle == None ) : i1iI1IIIi1iIii1 . append ( OO0oooo )
   if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
  self . registered_rlocs = i1iI1IIIi1iIii1
  if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
  if 71 - 71: ooOoO0o
  if 35 - 35: OoOoOO00
  if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
  if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
  if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
  if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
  ooo0o0O = lisp_rle ( "" )
  ooOOOoo0O00 = { }
  OO000o = None
  for oOoooooOooO in list ( self . individual_registrations . values ( ) ) :
   if ( oOoooooOooO . registered == False ) : continue
   IIIii1I = oOoooooOooO . registered_rlocs [ 0 ] . rle
   if ( IIIii1I == None ) : continue
   if 43 - 43: I1Ii111 / I1Ii111
   OO000o = oOoooooOooO . registered_rlocs [ 0 ] . rloc_name
   for o0OoO0OoO0O0O in IIIii1I . rle_nodes :
    IiI = o0OoO0OoO0O0O . address . print_address_no_iid ( )
    if ( IiI in ooOOOoo0O00 ) : break
    if 26 - 26: iII111i - I1ii11iIi11i
    iI11i1ii11i11 = lisp_rle_node ( )
    iI11i1ii11i11 . address . copy_address ( o0OoO0OoO0O0O . address )
    iI11i1ii11i11 . level = o0OoO0OoO0O0O . level
    iI11i1ii11i11 . rloc_name = OO000o
    ooo0o0O . rle_nodes . append ( iI11i1ii11i11 )
    ooOOOoo0O00 [ IiI ] = o0OoO0OoO0O0O . address
    if 65 - 65: I1ii11iIi11i + OoOoOO00
    if 43 - 43: O0 + I11i % II111iiii
    if 56 - 56: IiII + Oo0Ooo . IiII % iIii1I11I1II1 % ooOoO0o % ooOoO0o
    if 70 - 70: ooOoO0o / i1IIi - I11i - i11iIiiIii
    if 79 - 79: OoO0O00 - OoooooooOO % iII111i . O0
    if 93 - 93: I1Ii111
  if ( len ( ooo0o0O . rle_nodes ) == 0 ) : ooo0o0O = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = ooo0o0O
   if ( OO000o ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 3 - 3: OoO0O00 / IiII - oO0o / oO0o
   if 50 - 50: II111iiii + OoOoOO00
   if 17 - 17: ooOoO0o + I1ii11iIi11i
   if 34 - 34: Ii1I / II111iiii + OoOoOO00 . II111iiii + OoooooooOO * o0oOOo0O0Ooo
   if 48 - 48: O0
  if ( list ( Oo0oooo00 . keys ( ) ) == list ( ooOOOoo0O00 . keys ( ) ) ) : return ( False )
  if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # i11iIiiIii / OoooooooOO . ooOoO0o % I1Ii111 * I11i
 list ( Oo0oooo00 . keys ( ) ) , list ( ooOOOoo0O00 . keys ( ) ) ) )
  if 28 - 28: OoooooooOO * i1IIi . Oo0Ooo * i11iIiiIii . OoooooooOO % iIii1I11I1II1
  return ( True )
  if 62 - 62: Oo0Ooo - I1IiiI + oO0o . I1ii11iIi11i
  if 23 - 23: OoOoOO00
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   Oo0OO0o00OO = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( Oo0OO0o00OO == None ) :
    Oo0OO0o00OO = lisp_site_eid ( self . site )
    Oo0OO0o00OO . eid . copy_address ( self . group )
    Oo0OO0o00OO . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , Oo0OO0o00OO )
    if 98 - 98: o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I % I1IiiI
    if 19 - 19: I1Ii111 / O0 % o0oOOo0O0Ooo
    if 1 - 1: OoOoOO00 / I11i
    if 43 - 43: o0oOOo0O0Ooo - i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
    if 69 - 69: i11iIiiIii - iIii1I11I1II1
    Oo0OO0o00OO . parent_for_more_specifics = self . parent_for_more_specifics
    if 40 - 40: I1IiiI / oO0o + ooOoO0o
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( Oo0OO0o00OO . group )
   Oo0OO0o00OO . add_source_entry ( self )
   if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
   if 37 - 37: I1ii11iIi11i
   if 24 - 24: O0 . I1Ii111 * i11iIiiIii
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   Oo0OO0o00OO = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( Oo0OO0o00OO == None ) : return
   if 84 - 84: ooOoO0o / I1ii11iIi11i - o0oOOo0O0Ooo . OoooooooOO * iIii1I11I1II1
   oOoooooOooO = Oo0OO0o00OO . lookup_source_cache ( self . eid , True )
   if ( oOoooooOooO == None ) : return
   if 16 - 16: I11i % O0
   if ( Oo0OO0o00OO . source_cache == None ) : return
   if 56 - 56: Ii1I * OoOoOO00 . i1IIi
   Oo0OO0o00OO . source_cache . delete_cache ( self . eid )
   if ( Oo0OO0o00OO . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 15 - 15: I1Ii111
    if 64 - 64: OOooOOo * Oo0Ooo
    if 96 - 96: Oo0Ooo / I1ii11iIi11i * iIii1I11I1II1 / iII111i
    if 18 - 18: I1Ii111
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 29 - 29: i1IIi - I1IiiI / i1IIi
  if 64 - 64: IiII
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 69 - 69: OOooOOo . I1IiiI
  if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 22 - 22: iII111i % I11i % O0 - I11i
  if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
  if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
 def inherit_from_ams_parent ( self ) :
  oO0oOooo = self . parent_for_more_specifics
  if ( oO0oOooo == None ) : return
  self . force_proxy_reply = oO0oOooo . force_proxy_reply
  self . force_nat_proxy_reply = oO0oOooo . force_nat_proxy_reply
  self . force_ttl = oO0oOooo . force_ttl
  self . pitr_proxy_reply_drop = oO0oOooo . pitr_proxy_reply_drop
  self . proxy_reply_action = oO0oOooo . proxy_reply_action
  self . echo_nonce_capable = oO0oOooo . echo_nonce_capable
  self . policy = oO0oOooo . policy
  self . require_signature = oO0oOooo . require_signature
  self . encrypt_json = oO0oOooo . encrypt_json
  if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
  if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
 def rtrs_in_rloc_set ( self ) :
  for OO0oooo in self . registered_rlocs :
   if ( OO0oooo . is_rtr ( ) ) : return ( True )
   if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
  return ( False )
  if 97 - 97: iIii1I11I1II1 * I1Ii111
  if 39 - 39: I1Ii111 . II111iiii
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for OO0oooo in self . registered_rlocs :
   if ( OO0oooo . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( OO0oooo . is_rtr ( ) ) : return ( True )
   if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
  return ( False )
  if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
  if 34 - 34: I1IiiI
 def is_rloc_in_rloc_set ( self , rloc ) :
  for OO0oooo in self . registered_rlocs :
   if ( OO0oooo . rle ) :
    for ooo0o0O in OO0oooo . rle . rle_nodes :
     if ( ooo0o0O . address . is_exact_match ( rloc ) ) : return ( True )
     if 56 - 56: Ii1I
     if 71 - 71: O0 / i1IIi
   if ( OO0oooo . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
  return ( False )
  if 82 - 82: oO0o * i11iIiiIii % o0oOOo0O0Ooo % IiII - I11i - OoO0O00
  if 24 - 24: oO0o . II111iiii + OoO0O00 * I1ii11iIi11i / oO0o
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 86 - 86: I1Ii111 + I1ii11iIi11i
  for OO0oooo in prev_rloc_set :
   iI1I11II = OO0oooo . rloc
   if ( self . is_rloc_in_rloc_set ( iI1I11II ) == False ) : return ( False )
   if 63 - 63: ooOoO0o - i11iIiiIii . o0oOOo0O0Ooo - i1IIi - IiII
  return ( True )
  if 32 - 32: I1Ii111 / iIii1I11I1II1 + oO0o % I11i * OoooooooOO
  if 69 - 69: OOooOOo
  if 9 - 9: i11iIiiIii * Oo0Ooo
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
   if 33 - 33: oO0o / ooOoO0o
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 92 - 92: O0 . Oo0Ooo - Ii1I * I1IiiI * Oo0Ooo * iII111i
  if 78 - 78: Ii1I * iIii1I11I1II1 - Ii1I - I1ii11iIi11i * I1ii11iIi11i
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 44 - 44: o0oOOo0O0Ooo
  try :
   ooo0o0 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   iiii = ooo0o0 [ 2 ]
  except :
   return
   if 53 - 53: IiII - I1Ii111 - OOooOOo . OoOoOO00 / iIii1I11I1II1
   if 89 - 89: Oo0Ooo
   if 57 - 57: i1IIi - oO0o % IiII . I11i
   if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
   if 64 - 64: O0 - iII111i
   if 82 - 82: O0
  if ( len ( iiii ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 37 - 37: I1Ii111
   if 98 - 98: iII111i - OoOoOO00 / I1Ii111 . OOooOOo - OOooOOo - ooOoO0o
  IiI = iiii [ self . a_record_index ]
  if ( IiI != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( IiI )
   self . insert_mr ( )
   if 84 - 84: OOooOOo * ooOoO0o / O0
   if 96 - 96: I11i . I11i % II111iiii
   if 14 - 14: iII111i / OoooooooOO
   if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
   if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
   if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
  for IiI in iiii [ 1 : : ] :
   OO0O00o0 = lisp_address ( LISP_AFI_NONE , IiI , 0 , 0 )
   OOoOo0O0O0oO = lisp_get_map_resolver ( OO0O00o0 , None )
   if ( OOoOo0O0O0oO != None and OOoOo0O0O0oO . a_record_index == iiii . index ( IiI ) ) :
    continue
    if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
   OOoOo0O0O0oO = lisp_mr ( IiI , None , None )
   OOoOo0O0O0oO . a_record_index = iiii . index ( IiI )
   OOoOo0O0O0oO . dns_name = self . dns_name
   OOoOo0O0O0oO . last_dns_resolve = lisp_get_timestamp ( )
   if 11 - 11: I1IiiI
   if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
   if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
   if 91 - 91: OoO0O00
   if 8 - 8: oO0o
  oO000Oo0oOOo = [ ]
  for OOoOo0O0O0oO in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( self . dns_name != OOoOo0O0O0oO . dns_name ) : continue
   OO0O00o0 = OOoOo0O0O0oO . map_resolver . print_address_no_iid ( )
   if ( OO0O00o0 in iiii ) : continue
   oO000Oo0oOOo . append ( OOoOo0O0O0oO )
   if 26 - 26: o0oOOo0O0Ooo . i1IIi
  for OOoOo0O0O0oO in oO000Oo0oOOo : OOoOo0O0O0oO . delete_mr ( )
  if 62 - 62: IiII * I1ii11iIi11i % iIii1I11I1II1 / II111iiii - OoO0O00
  if 52 - 52: iII111i . I11i - I11i + oO0o + iIii1I11I1II1
 def insert_mr ( self ) :
  Ooo00o000o = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ Ooo00o000o ] = self
  if 83 - 83: I11i * iIii1I11I1II1 + OoOoOO00
  if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
 def delete_mr ( self ) :
  Ooo00o000o = self . mr_name + self . map_resolver . print_address ( )
  if ( Ooo00o000o not in lisp_map_resolvers_list ) : return
  lisp_map_resolvers_list . pop ( Ooo00o000o )
  if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
  if 100 - 100: II111iiii / Oo0Ooo / iII111i / OOooOOo
  if 100 - 100: iIii1I11I1II1
class lisp_ddt_root ( object ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 50 - 50: I1Ii111 / ooOoO0o * I11i
  if 53 - 53: II111iiii . IiII
  if 5 - 5: i1IIi % IiII
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
  if 16 - 16: ooOoO0o - iII111i % Ii1I . OoOoOO00
  if 56 - 56: i11iIiiIii % i11iIiiIii % OoooooooOO . Ii1I . iII111i + I11i
 def print_referral ( self , eid_indent , referral_indent ) :
  oOoII = lisp_print_elapsed ( self . uptime )
  iIiiiIiIi1iI1 = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , oOoII ,
  # OoO0O00 % Ii1I - ooOoO0o
 iIiiiIiIi1iI1 , len ( self . referral_set ) ) )
  if 67 - 67: I1IiiI % O0 + I1IiiI * I1Ii111 * OoOoOO00 * II111iiii
  for OoooOO0 in list ( self . referral_set . values ( ) ) :
   OoooOO0 . print_ref_node ( referral_indent )
   if 79 - 79: I1IiiI
   if 37 - 37: I1Ii111 + Ii1I
   if 50 - 50: i11iIiiIii
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 57 - 57: O0 * i1IIi - I1IiiI
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 48 - 48: IiII / iIii1I11I1II1
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 20 - 20: oO0o / OoooooooOO
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 95 - 95: Oo0Ooo . i11iIiiIii
  if 50 - 50: iII111i . i11iIiiIii - i1IIi
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 24 - 24: i11iIiiIii % iII111i . oO0o
  if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
 def print_ttl ( self ) :
  IiIi1iIIiII1i = self . referral_ttl
  if ( IiIi1iIIiII1i < 60 ) : return ( str ( IiIi1iIIiII1i ) + " secs" )
  if 34 - 34: I1ii11iIi11i % ooOoO0o / II111iiii * O0 % OOooOOo
  if ( ( IiIi1iIIiII1i % 60 ) == 0 ) :
   IiIi1iIIiII1i = str ( old_div ( IiIi1iIIiII1i , 60 ) ) + " mins"
  else :
   IiIi1iIIiII1i = str ( IiIi1iIIiII1i ) + " secs"
   if 9 - 9: I1ii11iIi11i / I1ii11iIi11i - OOooOOo . iIii1I11I1II1
  return ( IiIi1iIIiII1i )
  if 33 - 33: I1IiiI + oO0o % I1IiiI / iII111i - ooOoO0o - i11iIiiIii
  if 39 - 39: i11iIiiIii / oO0o
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # ooOoO0o + I1ii11iIi11i * I1Ii111 . i1IIi * i1IIi
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 33 - 33: II111iiii - OoooooooOO / II111iiii % Oo0Ooo / o0oOOo0O0Ooo
  if 41 - 41: I1Ii111 / IiII % OoO0O00 - iIii1I11I1II1
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   OO0oO0O = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( OO0oO0O == None ) :
    OO0oO0O = lisp_referral ( )
    OO0oO0O . eid . copy_address ( self . group )
    OO0oO0O . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , OO0oO0O )
    if 98 - 98: OoOoOO00 + i11iIiiIii - iII111i + II111iiii
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OO0oO0O . group )
   OO0oO0O . add_source_entry ( self )
   if 10 - 10: ooOoO0o * i11iIiiIii . o0oOOo0O0Ooo % ooOoO0o
   if 14 - 14: i11iIiiIii . o0oOOo0O0Ooo % OoooooooOO
   if 15 - 15: I11i - OoOoOO00 . OoOoOO00 * iII111i - Ii1I . i11iIiiIii
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   OO0oO0O = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( OO0oO0O == None ) : return
   if 68 - 68: iII111i
   oOOo0OOo00 = OO0oO0O . lookup_source_cache ( self . eid , True )
   if ( oOOo0OOo00 == None ) : return
   if 68 - 68: I1Ii111 - OoO0O00 % OoO0O00 % OOooOOo - OoO0O00
   OO0oO0O . source_cache . delete_cache ( self . eid )
   if ( OO0oO0O . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
    if 59 - 59: iII111i
    if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
    if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 65 - 65: I1Ii111 + OOooOOo
  if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
  if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
  if 77 - 77: ooOoO0o % I1IiiI
class lisp_referral_node ( object ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 26 - 26: o0oOOo0O0Ooo
  if 72 - 72: I1IiiI
 def print_ref_node ( self , indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , i1 ,
  # ooOoO0o . o0oOOo0O0Ooo - iIii1I11I1II1 + i1IIi * I1IiiI * OoooooooOO
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 23 - 23: IiII
  if 32 - 32: OoOoOO00 - iII111i % oO0o / I1ii11iIi11i - o0oOOo0O0Ooo
  if 52 - 52: Ii1I / OoooooooOO % i11iIiiIii + iII111i
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
   if 59 - 59: Ii1I / o0oOOo0O0Ooo / oO0o + iII111i * I1ii11iIi11i - o0oOOo0O0Ooo
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
   if 70 - 70: O0 / I1ii11iIi11i + ooOoO0o . OoO0O00 - OoO0O00 / i11iIiiIii
   if 1 - 1: iIii1I11I1II1 % I1ii11iIi11i
   if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
  try :
   ooo0o0 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   iiii = ooo0o0 [ 2 ]
  except :
   return
   if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
   if 67 - 67: i1IIi * I1Ii111 * O0
   if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
   if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
   if 18 - 18: I1ii11iIi11i - i1IIi - IiII * II111iiii % I1Ii111 . II111iiii
   if 80 - 80: oO0o + OoO0O00 + o0oOOo0O0Ooo . OoOoOO00
  if ( len ( iiii ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 75 - 75: i11iIiiIii
   if 58 - 58: iII111i
  IiI = iiii [ self . a_record_index ]
  if ( IiI != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( IiI )
   self . insert_ms ( )
   if 48 - 48: OoO0O00 * OOooOOo / iII111i
   if 90 - 90: I1IiiI * i11iIiiIii . OOooOOo / o0oOOo0O0Ooo
   if 82 - 82: Oo0Ooo
   if 50 - 50: I1Ii111 * OOooOOo * OoOoOO00 / OoooooooOO % iII111i
   if 80 - 80: I1Ii111
   if 35 - 35: Ii1I . O0 % i11iIiiIii * oO0o - OoooooooOO
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 87 - 87: iII111i * ooOoO0o - OOooOOo . O0
  for IiI in iiii [ 1 : : ] :
   OO0O00o0 = lisp_address ( LISP_AFI_NONE , IiI , 0 , 0 )
   I11i1IiIi1II1 = lisp_get_map_server ( OO0O00o0 )
   if ( I11i1IiIi1II1 != None and I11i1IiIi1II1 . a_record_index == iiii . index ( IiI ) ) :
    continue
    if 20 - 20: OoOoOO00 - IiII
   I11i1IiIi1II1 = copy . deepcopy ( self )
   I11i1IiIi1II1 . map_server . store_address ( IiI )
   I11i1IiIi1II1 . a_record_index = iiii . index ( IiI )
   I11i1IiIi1II1 . last_dns_resolve = lisp_get_timestamp ( )
   I11i1IiIi1II1 . insert_ms ( )
   if 9 - 9: O0 . I11i % I1ii11iIi11i * oO0o - I1Ii111 - i1IIi
   if 66 - 66: II111iiii / Oo0Ooo
   if 93 - 93: iII111i + I11i * OoooooooOO . OoO0O00
   if 40 - 40: ooOoO0o * I1Ii111 + iII111i
   if 52 - 52: iII111i % I11i
  oO000Oo0oOOo = [ ]
  for I11i1IiIi1II1 in list ( lisp_map_servers_list . values ( ) ) :
   if ( self . dns_name != I11i1IiIi1II1 . dns_name ) : continue
   OO0O00o0 = I11i1IiIi1II1 . map_server . print_address_no_iid ( )
   if ( OO0O00o0 in iiii ) : continue
   oO000Oo0oOOo . append ( I11i1IiIi1II1 )
   if 95 - 95: IiII + Ii1I / OoO0O00 - iII111i / I1IiiI
  for I11i1IiIi1II1 in oO000Oo0oOOo : I11i1IiIi1II1 . delete_ms ( )
  if 27 - 27: Oo0Ooo + i1IIi + i11iIiiIii . OoO0O00 . OoO0O00
  if 56 - 56: I1Ii111 / OoO0O00 + o0oOOo0O0Ooo . OoooooooOO * Oo0Ooo
 def insert_ms ( self ) :
  Ooo00o000o = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ Ooo00o000o ] = self
  if 14 - 14: OoO0O00
  if 21 - 21: II111iiii + i11iIiiIii + I11i % I1IiiI
 def delete_ms ( self ) :
  Ooo00o000o = self . ms_name + self . map_server . print_address ( )
  if ( Ooo00o000o not in lisp_map_servers_list ) : return
  lisp_map_servers_list . pop ( Ooo00o000o )
  if 65 - 65: IiII + I1ii11iIi11i / iII111i / I1IiiI + Ii1I
  if 88 - 88: IiII % iIii1I11I1II1
  if 3 - 3: ooOoO0o / I1Ii111 % iIii1I11I1II1 % I11i * oO0o / iIii1I11I1II1
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
  if 75 - 75: i11iIiiIii . iII111i
  if 68 - 68: OOooOOo . I1ii11iIi11i % I1ii11iIi11i . i11iIiiIii
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 45 - 45: oO0o % I1ii11iIi11i * I1Ii111
  if 21 - 21: O0 + i11iIiiIii
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 72 - 72: OoOoOO00 * OoooooooOO % O0 / I1ii11iIi11i % Ii1I - I11i
  if 65 - 65: iIii1I11I1II1 + II111iiii * OoO0O00 * i11iIiiIii / IiII
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
  if 52 - 52: II111iiii * o0oOOo0O0Ooo
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 95 - 95: I1Ii111 - OoooooooOO
  if 99 - 99: OoooooooOO % IiII . I11i + OoooooooOO
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 57 - 57: Ii1I / I1IiiI * i1IIi
  if 21 - 21: I11i . O0 * OoooooooOO + ooOoO0o * oO0o % i11iIiiIii
 def set_socket ( self , device ) :
  I111 = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  I111 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   I111 . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   I111 . close ( )
   I111 = None
   if 30 - 30: ooOoO0o * I1Ii111 + OoO0O00
  self . raw_socket = I111
  if 30 - 30: Ii1I / iII111i * Ii1I
  if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
 def set_bridge_socket ( self , device ) :
  I111 = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   I111 = I111 . bind ( ( device , 0 ) )
   self . bridge_socket = I111
  except :
   return
   if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
   if 71 - 71: i1IIi % O0 % ooOoO0o
   if 24 - 24: O0
   if 88 - 88: OoooooooOO / Oo0Ooo / oO0o
class lisp_datetime ( object ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 99 - 99: I1Ii111 % OoOoOO00 % IiII - Ii1I
  if 79 - 79: ooOoO0o + Oo0Ooo
 def valid_datetime ( self ) :
  OOoO0O0Ooo = self . datetime_name
  if ( OOoO0O0Ooo . find ( ":" ) == - 1 ) : return ( False )
  if ( OOoO0O0Ooo . find ( "-" ) == - 1 ) : return ( False )
  iIII1 , o0000oo , ooOOOo00OoO , time = OOoO0O0Ooo [ 0 : 4 ] , OOoO0O0Ooo [ 5 : 7 ] , OOoO0O0Ooo [ 8 : 10 ] , OOoO0O0Ooo [ 11 : : ]
  if 21 - 21: iIii1I11I1II1 - iII111i
  if ( ( iIII1 + o0000oo + ooOOOo00OoO ) . isdigit ( ) == False ) : return ( False )
  if ( o0000oo < "01" and o0000oo > "12" ) : return ( False )
  if ( ooOOOo00OoO < "01" and ooOOOo00OoO > "31" ) : return ( False )
  if 15 - 15: O0 + iII111i + i11iIiiIii
  iiii1IIiiiI11 , iII11i11I1 , oOo00o = time . split ( ":" )
  if 50 - 50: OoO0O00 - iII111i + I1IiiI . I11i . I11i
  if ( ( iiii1IIiiiI11 + iII11i11I1 + oOo00o ) . isdigit ( ) == False ) : return ( False )
  if ( iiii1IIiiiI11 < "00" and iiii1IIiiiI11 > "23" ) : return ( False )
  if ( iII11i11I1 < "00" and iII11i11I1 > "59" ) : return ( False )
  if ( oOo00o < "00" and oOo00o > "59" ) : return ( False )
  return ( True )
  if 40 - 40: O0 - I11i . I1IiiI + Oo0Ooo - Ii1I - I11i
  if 98 - 98: OoOoOO00 - OoooooooOO * Ii1I
 def parse_datetime ( self ) :
  OO0 = self . datetime_name
  OO0 = OO0 . replace ( "-" , "" )
  OO0 = OO0 . replace ( ":" , "" )
  self . datetime = int ( OO0 )
  if 45 - 45: II111iiii
  if 14 - 14: OoOoOO00 - oO0o
 def now ( self ) :
  i1 = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  i1 = lisp_datetime ( i1 )
  return ( i1 )
  if 27 - 27: OoOoOO00 * I11i
  if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 70 - 70: I1IiiI . ooOoO0o / I11i / OoO0O00
  if 40 - 40: oO0o % iIii1I11I1II1 * iIii1I11I1II1 / Oo0Ooo * OoO0O00
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 61 - 61: OOooOOo
  if 80 - 80: I1ii11iIi11i
 def past ( self ) :
  return ( self . future ( ) == False )
  if 6 - 6: I1ii11iIi11i + OOooOOo % ooOoO0o
  if 65 - 65: iIii1I11I1II1 % i1IIi / I1IiiI / oO0o % ooOoO0o / I11i
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 2 - 2: I1ii11iIi11i
  if 90 - 90: II111iiii * I1Ii111 . ooOoO0o - I1ii11iIi11i % I11i * o0oOOo0O0Ooo
 def this_year ( self ) :
  o0Ooo0O0 = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  i1 = str ( self . datetime ) [ 0 : 4 ]
  return ( i1 == o0Ooo0O0 )
  if 11 - 11: I1IiiI + I11i . OoOoOO00 - II111iiii
  if 10 - 10: iII111i - IiII + OoOoOO00 + I1IiiI + Oo0Ooo
 def this_month ( self ) :
  o0Ooo0O0 = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  i1 = str ( self . datetime ) [ 0 : 6 ]
  return ( i1 == o0Ooo0O0 )
  if 25 - 25: I1IiiI / I1ii11iIi11i % iII111i / O0 % II111iiii
  if 20 - 20: O0 % I11i * iII111i
 def today ( self ) :
  o0Ooo0O0 = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  i1 = str ( self . datetime ) [ 0 : 8 ]
  return ( i1 == o0Ooo0O0 )
  if 6 - 6: OoooooooOO % ooOoO0o % OoO0O00 * IiII
  if 62 - 62: i1IIi . I11i / I11i
  if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
  if 93 - 93: oO0o / ooOoO0o - I1Ii111
  if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
  if 26 - 26: O0 + Oo0Ooo
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
  if 30 - 30: IiII
  if 6 - 6: O0
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
  if 92 - 92: I11i
  if 76 - 76: I11i / iIii1I11I1II1 - i11iIiiIii / O0 / O0
 def match_policy_map_request ( self , mr , srloc ) :
  for O00000ooO0OOo in self . match_clauses :
   iIIiiIi = O00000ooO0OOo . source_eid
   IiIi1I1i1iII = mr . source_eid
   if ( iIIiiIi and IiIi1I1i1iII and IiIi1I1i1iII . is_more_specific ( iIIiiIi ) == False ) : continue
   if 19 - 19: Ii1I . I1IiiI - i1IIi * ooOoO0o . iIii1I11I1II1
   iIIiiIi = O00000ooO0OOo . dest_eid
   IiIi1I1i1iII = mr . target_eid
   if ( iIIiiIi and IiIi1I1i1iII and IiIi1I1i1iII . is_more_specific ( iIIiiIi ) == False ) : continue
   if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
   iIIiiIi = O00000ooO0OOo . source_rloc
   IiIi1I1i1iII = srloc
   if ( iIIiiIi and IiIi1I1i1iII and IiIi1I1i1iII . is_more_specific ( iIIiiIi ) == False ) : continue
   oOO0O0ooOOOo = O00000ooO0OOo . datetime_lower
   I11iiI1i11I = O00000ooO0OOo . datetime_upper
   if ( oOO0O0ooOOOo and I11iiI1i11I and oOO0O0ooOOOo . now_in_range ( I11iiI1i11I ) == False ) : continue
   return ( True )
   if 3 - 3: Oo0Ooo . IiII . Oo0Ooo
  return ( False )
  if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
  if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
 def set_policy_map_reply ( self ) :
  OOoOO = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( OOoOO ) : return ( None )
  if 88 - 88: ooOoO0o % I11i % ooOoO0o + OoOoOO00 * I1ii11iIi11i % iIii1I11I1II1
  I1Ii1i111I = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   I1Ii1i111I . rloc . copy_address ( self . set_rloc_address )
   IiI = I1Ii1i111I . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( IiI ) )
   if 17 - 17: II111iiii
  if ( self . set_rloc_record_name ) :
   I1Ii1i111I . rloc_name = self . set_rloc_record_name
   o0o = blue ( I1Ii1i111I . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( o0o ) )
   if 54 - 54: o0oOOo0O0Ooo + I1IiiI / o0oOOo0O0Ooo / ooOoO0o % I11i % Ii1I
  if ( self . set_geo_name ) :
   I1Ii1i111I . geo_name = self . set_geo_name
   o0o = I1Ii1i111I . geo_name
   o00O0O0Oo0o = "" if ( o0o in lisp_geo_list ) else "(not configured)"
   if 96 - 96: oO0o % I1Ii111 . I11i - I11i + OoO0O00 - oO0o
   lprint ( "Policy set-geo-name '{}' {}" . format ( o0o , o00O0O0Oo0o ) )
   if 25 - 25: IiII % O0 - I1IiiI + I1Ii111 . i11iIiiIii
  if ( self . set_elp_name ) :
   I1Ii1i111I . elp_name = self . set_elp_name
   o0o = I1Ii1i111I . elp_name
   o00O0O0Oo0o = "" if ( o0o in lisp_elp_list ) else "(not configured)"
   if 50 - 50: OOooOOo * OoooooooOO . OoO0O00 . oO0o
   lprint ( "Policy set-elp-name '{}' {}" . format ( o0o , o00O0O0Oo0o ) )
   if 52 - 52: I11i . OOooOOo + OoO0O00
  if ( self . set_rle_name ) :
   I1Ii1i111I . rle_name = self . set_rle_name
   o0o = I1Ii1i111I . rle_name
   o00O0O0Oo0o = "" if ( o0o in lisp_rle_list ) else "(not configured)"
   if 10 - 10: Oo0Ooo * OoooooooOO * OOooOOo
   lprint ( "Policy set-rle-name '{}' {}" . format ( o0o , o00O0O0Oo0o ) )
   if 50 - 50: ooOoO0o + oO0o
  if ( self . set_json_name ) :
   I1Ii1i111I . json_name = self . set_json_name
   o0o = I1Ii1i111I . json_name
   o00O0O0Oo0o = "" if ( o0o in lisp_json_list ) else "(not configured)"
   if 74 - 74: Ii1I + OOooOOo - I11i * iIii1I11I1II1 - I1Ii111 % i11iIiiIii
   lprint ( "Policy set-json-name '{}' {}" . format ( o0o , o00O0O0Oo0o ) )
   if 32 - 32: Oo0Ooo * i1IIi . iII111i . iII111i
  return ( I1Ii1i111I )
  if 77 - 77: OOooOOo
  if 74 - 74: O0
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 86 - 86: OoOoOO00
  if 4 - 4: OoooooooOO * OoO0O00
  if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
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
  if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
  if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
 def add ( self , eid_prefix ) :
  self . eid_prefix = eid_prefix
  IiIi1iIIiII1i = self . ttl
  i1I1I1IIIi11 = eid_prefix . print_prefix ( )
  if ( i1I1I1IIIi11 not in lisp_pubsub_cache ) :
   lisp_pubsub_cache [ i1I1I1IIIi11 ] = { }
   if 6 - 6: I1IiiI - OoOoOO00
  oO0II11II = lisp_pubsub_cache [ i1I1I1IIIi11 ]
  if 63 - 63: OOooOOo - oO0o * I1IiiI
  ooOOOOOO0 = "Add"
  if ( self . xtr_id in oO0II11II ) :
   ooOOOOOO0 = "Replace"
   del ( oO0II11II [ self . xtr_id ] )
   if 69 - 69: i1IIi + I1Ii111
  oO0II11II [ self . xtr_id ] = self
  if 66 - 66: ooOoO0o / O0 . Oo0Ooo + iIii1I11I1II1 / I1Ii111 + OoO0O00
  i1I1I1IIIi11 = green ( i1I1I1IIIi11 , False )
  ii1oO0Oo = red ( self . itr . print_address_no_iid ( ) , False )
  Iiooo000o0OoOo = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( ooOOOOOO0 , i1I1I1IIIi11 ,
 ii1oO0Oo , Iiooo000o0OoOo , IiIi1iIIiII1i ) )
  if 85 - 85: ooOoO0o / I1IiiI
  if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
 def delete ( self , eid_prefix ) :
  i1I1I1IIIi11 = eid_prefix . print_prefix ( )
  ii1oO0Oo = red ( self . itr . print_address_no_iid ( ) , False )
  Iiooo000o0OoOo = "0x" + lisp_hex_string ( self . xtr_id )
  if ( i1I1I1IIIi11 in lisp_pubsub_cache ) :
   oO0II11II = lisp_pubsub_cache [ i1I1I1IIIi11 ]
   if ( self . xtr_id in oO0II11II ) :
    oO0II11II . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( i1I1I1IIIi11 ,
 ii1oO0Oo , Iiooo000o0OoOo ) )
    if 99 - 99: i11iIiiIii - I1ii11iIi11i
    if 64 - 64: IiII . OoOoOO00 . Oo0Ooo . I1Ii111 / I11i / Ii1I
    if 95 - 95: iIii1I11I1II1 . Ii1I % oO0o - I11i % IiII
    if 42 - 42: OoOoOO00 + oO0o * i1IIi + i11iIiiIii
    if 25 - 25: Ii1I - Ii1I - I1ii11iIi11i / i1IIi . OoOoOO00 % Oo0Ooo
    if 76 - 76: I1Ii111 / OoOoOO00
    if 61 - 61: Oo0Ooo . i1IIi
    if 78 - 78: i11iIiiIii
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
    if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
    if 7 - 7: Ii1I / iIii1I11I1II1
    if 36 - 36: iIii1I11I1II1 % i11iIiiIii
    if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
class lisp_trace ( object ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
  if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
 def print_trace ( self ) :
  iII1oO0OOoOOo0 = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( iII1oO0OOoOOo0 ) )
  if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
  if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
 def encode ( self ) :
  Iii1 = socket . htonl ( 0x90000000 )
  Oo00oo = struct . pack ( "II" , Iii1 , 0 )
  Oo00oo += struct . pack ( "Q" , self . nonce )
  Oo00oo += json . dumps ( self . packet_json )
  return ( Oo00oo )
  if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
  if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
 def decode ( self , packet ) :
  II111I11iI = "I"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( False )
  Iii1 = struct . unpack ( II111I11iI , packet [ : oO000 ] ) [ 0 ]
  packet = packet [ oO000 : : ]
  Iii1 = socket . ntohl ( Iii1 )
  if ( ( Iii1 & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
  if ( len ( packet ) < oO000 ) : return ( False )
  IiI = struct . unpack ( II111I11iI , packet [ : oO000 ] ) [ 0 ]
  packet = packet [ oO000 : : ]
  if 38 - 38: IiII
  IiI = socket . ntohl ( IiI )
  OO0Oo0OO0O0oo = IiI >> 24
  ooOOOOO = ( IiI >> 16 ) & 0xff
  iIii1iI = ( IiI >> 8 ) & 0xff
  oooOOOO000 = IiI & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( OO0Oo0OO0O0oo , ooOOOOO , iIii1iI , oooOOOO000 )
  self . local_port = str ( Iii1 & 0xffff )
  if 41 - 41: ooOoO0o
  II111I11iI = "Q"
  oO000 = struct . calcsize ( II111I11iI )
  if ( len ( packet ) < oO000 ) : return ( False )
  self . nonce = struct . unpack ( II111I11iI , packet [ : oO000 ] ) [ 0 ]
  packet = packet [ oO000 : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 89 - 89: i11iIiiIii . i11iIiiIii . IiII
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 29 - 29: o0oOOo0O0Ooo * iIii1I11I1II1 . iIii1I11I1II1
  return ( True )
  if 32 - 32: IiII - OoOoOO00
  if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
  if 83 - 83: OoO0O00 . I11i * I1ii11iIi11i - II111iiii
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  I1Ii1i111I , I1I = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( I1Ii1i111I == None ) :
   I1Ii1i111I , I1I = rts_rloc . split ( ":" )
   I1I = int ( I1I )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( I1Ii1i111I , I1I ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( I1Ii1i111I ,
 I1I ) )
   if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
   if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
  if ( lisp_socket == None ) :
   I111 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   I111 . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   I111 . sendto ( packet , ( I1Ii1i111I , I1I ) )
   I111 . close ( )
  else :
   lisp_socket . sendto ( packet , ( I1Ii1i111I , I1I ) )
   if 16 - 16: Oo0Ooo
   if 24 - 24: o0oOOo0O0Ooo . OoOoOO00
   if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 def packet_length ( self ) :
  O0I1II1 = 8 ; OooOo00o0 = 4 + 4 + 8
  return ( O0I1II1 + OooOo00o0 + len ( json . dumps ( self . packet_json ) ) )
  if 96 - 96: I1IiiI . oO0o % O0
  if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  Ooo00o000o = self . local_rloc + ":" + self . local_port
  oOO0 = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ Ooo00o000o ] = oOO0
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( Ooo00o000o , oOO0 ) )
  if 87 - 87: OoooooooOO
  if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  Ooo00o000o = local_rloc_and_port
  try : oOO0 = lisp_rtr_nat_trace_cache [ Ooo00o000o ]
  except : oOO0 = ( None , None )
  return ( oOO0 )
  if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
  if 23 - 23: o0oOOo0O0Ooo . o0oOOo0O0Ooo - iIii1I11I1II1 / o0oOOo0O0Ooo
  if 65 - 65: I1Ii111 + I1Ii111 . I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
  if 2 - 2: oO0o % iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
  if 45 - 45: II111iiii . iII111i
  if 55 - 55: ooOoO0o / iII111i / O0
  if 98 - 98: O0 % iII111i + II111iiii
  if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
  if 23 - 23: iIii1I11I1II1 + oO0o . oO0o / o0oOOo0O0Ooo
  if 77 - 77: i1IIi * o0oOOo0O0Ooo * IiII
  if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
def lisp_get_map_server ( address ) :
 for I11i1IiIi1II1 in list ( lisp_map_servers_list . values ( ) ) :
  if ( I11i1IiIi1II1 . map_server . is_exact_match ( address ) ) : return ( I11i1IiIi1II1 )
  if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
 return ( None )
 if 36 - 36: O0
 if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
 if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
 if 21 - 21: i1IIi * iII111i + OoO0O00
 if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
 if 85 - 85: OoooooooOO
 if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
def lisp_get_any_map_server ( ) :
 for I11i1IiIi1II1 in list ( lisp_map_servers_list . values ( ) ) : return ( I11i1IiIi1II1 )
 return ( None )
 if 8 - 8: I1Ii111
 if 86 - 86: ooOoO0o + iII111i * O0 % OoO0O00 + OoOoOO00
 if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
 if 9 - 9: iIii1I11I1II1 + Ii1I + I11i
 if 96 - 96: OoO0O00 + i11iIiiIii + OoO0O00
 if 7 - 7: i1IIi . I1IiiI
 if 68 - 68: OoooooooOO
 if 91 - 91: IiII . ooOoO0o * I11i
 if 39 - 39: o0oOOo0O0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 . II111iiii
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  IiI = address . print_address ( )
  OOoOo0O0O0oO = None
  for Ooo00o000o in lisp_map_resolvers_list :
   if ( Ooo00o000o . find ( IiI ) == - 1 ) : continue
   OOoOo0O0O0oO = lisp_map_resolvers_list [ Ooo00o000o ]
   if 36 - 36: I1IiiI * i1IIi + OoOoOO00
  return ( OOoOo0O0O0oO )
  if 63 - 63: OoOoOO00 - iII111i
  if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
  if 82 - 82: iIii1I11I1II1 / OOooOOo
  if 7 - 7: OoooooooOO
  if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
  if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
  if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
 if ( eid == "" ) :
  I1OoO0OO = ""
 elif ( eid == None ) :
  I1OoO0OO = "all"
 else :
  i11IIII1Ii = lisp_db_for_lookups . lookup_cache ( eid , False )
  I1OoO0OO = "all" if i11IIII1Ii == None else i11IIII1Ii . use_mr_name
  if 20 - 20: OoO0O00 / I1ii11iIi11i / iII111i / o0oOOo0O0Ooo
  if 37 - 37: o0oOOo0O0Ooo - ooOoO0o + OoOoOO00
 iiIIii = None
 for OOoOo0O0O0oO in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( I1OoO0OO == "" ) : return ( OOoOo0O0O0oO )
  if ( OOoOo0O0O0oO . mr_name != I1OoO0OO ) : continue
  if ( iiIIii == None or OOoOo0O0O0oO . last_used < iiIIii . last_used ) : iiIIii = OOoOo0O0O0oO
  if 27 - 27: iIii1I11I1II1 + oO0o - I1IiiI
 return ( iiIIii )
 if 54 - 54: oO0o . oO0o % i1IIi . OoooooooOO
 if 60 - 60: II111iiii . i11iIiiIii . iII111i
 if 35 - 35: Ii1I
 if 54 - 54: OOooOOo
 if 83 - 83: i1IIi / II111iiii - I1IiiI + I1ii11iIi11i . IiII * oO0o
 if 92 - 92: OoOoOO00 + oO0o % Ii1I / Ii1I - iII111i
 if 11 - 11: Oo0Ooo % II111iiii * Ii1I + II111iiii
 if 9 - 9: I1Ii111
def lisp_get_decent_map_resolver ( eid ) :
 OOOooo0OooOoO = lisp_get_decent_index ( eid )
 ooO0000 = str ( OOOooo0OooOoO ) + "." + lisp_decent_dns_suffix
 if 44 - 44: iII111i % O0 + I1IiiI
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( ooO0000 , False ) , eid . print_prefix ( ) ) )
 if 70 - 70: OOooOOo . I1Ii111
 if 63 - 63: ooOoO0o
 iiIIii = None
 for OOoOo0O0O0oO in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( ooO0000 != OOoOo0O0O0oO . dns_name ) : continue
  if ( iiIIii == None or OOoOo0O0O0oO . last_used < iiIIii . last_used ) : iiIIii = OOoOo0O0O0oO
  if 73 - 73: IiII + OoooooooOO % IiII
 return ( iiIIii )
 if 89 - 89: OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
 if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
 if 8 - 8: i1IIi
 if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
 if 97 - 97: OoooooooOO % ooOoO0o . I1Ii111 / iII111i
 if 59 - 59: II111iiii + O0 . I1ii11iIi11i . Oo0Ooo * OoO0O00
 if 35 - 35: oO0o / I1Ii111 * OOooOOo + OoooooooOO . IiII
def lisp_ipv4_input ( packet ) :
 if 1 - 1: I1IiiI + I1Ii111 / OOooOOo . Ii1I . oO0o / I1ii11iIi11i
 if 54 - 54: OOooOOo
 if 86 - 86: oO0o * Oo0Ooo / OOooOOo
 if 18 - 18: II111iiii - I1Ii111
 if ( ord ( packet [ 9 : 10 ] ) == 2 ) : return ( [ True , packet ] )
 if 13 - 13: i11iIiiIii - O0 % OoOoOO00 + OOooOOo * ooOoO0o
 if 55 - 55: i1IIi - OOooOOo / I11i * Ii1I
 if 20 - 20: OoOoOO00 * iIii1I11I1II1 % O0 - i1IIi
 if 51 - 51: I1ii11iIi11i * Ii1I - oO0o / O0 * OoooooooOO
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
   if 12 - 12: i1IIi / iIii1I11I1II1 / O0 * OoO0O00
   if 15 - 15: i11iIiiIii / IiII + Ii1I % OOooOOo % I1ii11iIi11i * oO0o
   if 24 - 24: OOooOOo / OOooOOo + I11i / iII111i . oO0o - iII111i
   if 59 - 59: I1ii11iIi11i % II111iiii - i11iIiiIii - I1Ii111
   if 34 - 34: II111iiii + iII111i / IiII
   if 47 - 47: OoO0O00
   if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
 IiIi1iIIiII1i = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( IiIi1iIIiII1i == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( IiIi1iIIiII1i == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
  return ( [ False , None ] )
  if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
  if 100 - 100: II111iiii . IiII . I11i
 IiIi1iIIiII1i -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , IiIi1iIIiII1i ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( [ False , packet ] )
 if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
 if 3 - 3: OoooooooOO
 if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
 if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
 if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
 if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
 if 37 - 37: I1ii11iIi11i * IiII
def lisp_ipv6_input ( packet ) :
 I1i1iiIi = packet . inner_dest
 packet = packet . packet
 if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
 if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
 if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
 if 46 - 46: OoooooooOO * OoO0O00 . I1Ii111
 if 95 - 95: ooOoO0o . I1ii11iIi11i . ooOoO0o / I1IiiI * OoOoOO00 . O0
 IiIi1iIIiII1i = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( IiIi1iIIiII1i == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( IiIi1iIIiII1i == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 78 - 78: oO0o
  return ( None )
  if 33 - 33: oO0o + i1IIi
  if 32 - 32: iIii1I11I1II1
  if 71 - 71: Ii1I * I1IiiI
  if 62 - 62: II111iiii / I1IiiI . I1ii11iIi11i
  if 49 - 49: IiII / OoOoOO00 / O0 * i11iIiiIii
 if ( I1i1iiIi . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 47 - 47: i11iIiiIii + iII111i + i11iIiiIii
  if 66 - 66: o0oOOo0O0Ooo . I1IiiI + OoooooooOO . iII111i / OoooooooOO - IiII
 IiIi1iIIiII1i -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , IiIi1iIIiII1i ) + packet [ 8 : : ]
 return ( packet )
 if 47 - 47: o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
 if 34 - 34: I11i / o0oOOo0O0Ooo * OOooOOo * OOooOOo
 if 89 - 89: I1ii11iIi11i . OoooooooOO
 if 61 - 61: i1IIi + i11iIiiIii
 if 59 - 59: i11iIiiIii * OOooOOo + i1IIi * iIii1I11I1II1 + I11i
 if 97 - 97: OoO0O00 - I11i . OoooooooOO
 if 58 - 58: I1ii11iIi11i / II111iiii / i11iIiiIii
 if 27 - 27: iIii1I11I1II1 - O0 + OoOoOO00
def lisp_mac_input ( packet ) :
 return ( packet )
 if 28 - 28: oO0o . IiII * iII111i % Oo0Ooo - OoO0O00 / I11i
 if 67 - 67: i11iIiiIii + i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo
 if 94 - 94: O0 + OoO0O00 / I1IiiI * II111iiii * i11iIiiIii
 if 55 - 55: OoooooooOO * O0 + i1IIi % I1IiiI
 if 10 - 10: II111iiii - Ii1I . I11i . O0 + Ii1I
 if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
 if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
 if 21 - 21: I1ii11iIi11i - ooOoO0o
 if 81 - 81: iII111i / i11iIiiIii / I1Ii111
def lisp_rate_limit_map_request ( dest ) :
 o0Ooo0O0 = lisp_get_timestamp ( )
 if 70 - 70: I1ii11iIi11i / i11iIiiIii
 if 90 - 90: II111iiii / OoOoOO00 . Ii1I . OoooooooOO
 if 76 - 76: OoooooooOO
 if 78 - 78: IiII % i11iIiiIii
 i1i111Iiiiiii = o0Ooo0O0 - lisp_no_map_request_rate_limit
 if ( i1i111Iiiiiii < LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME ) :
  iIi1I1 = int ( LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME - i1i111Iiiiiii )
  dprint ( "No Rate-Limit Mode for another {} secs" . format ( iIi1I1 ) )
  return ( False )
  if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
  if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
  if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
  if 19 - 19: o0oOOo0O0Ooo
  if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
 if ( lisp_last_map_request_sent == None ) : return ( False )
 i1i111Iiiiiii = o0Ooo0O0 - lisp_last_map_request_sent
 Ooooooo = ( i1i111Iiiiiii < LISP_MAP_REQUEST_RATE_LIMIT )
 if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
 if ( Ooooooo ) :
  dprint ( "Rate-limiting Map-Request for {}, sent {} secs ago" . format ( green ( dest . print_address ( ) , False ) , round ( i1i111Iiiiiii , 3 ) ) )
  if 71 - 71: OoO0O00 - I11i
  if 96 - 96: I1Ii111 / Ii1I
 return ( Ooooooo )
 if 65 - 65: I1ii11iIi11i * O0 . IiII
 if 11 - 11: I11i / Ii1I % oO0o
 if 50 - 50: i11iIiiIii
 if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
 if 25 - 25: I11i / ooOoO0o % ooOoO0o - OOooOOo
 if 59 - 59: I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1 - O0 - i11iIiiIii
 if 4 - 4: I1IiiI
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ,
 pubsub = False ) :
 global lisp_last_map_request_sent
 if 36 - 36: Ii1I
 if 76 - 76: i11iIiiIii + i1IIi
 if 56 - 56: OoOoOO00 + II111iiii / i11iIiiIii * OoOoOO00 * OoooooooOO
 if 15 - 15: OoOoOO00 / OoooooooOO + OOooOOo
 if 76 - 76: Ii1I * iII111i . OoooooooOO
 if 92 - 92: iIii1I11I1II1 - Oo0Ooo - I1IiiI - OOooOOo * I1Ii111
 i1ii1Iii1 = OooO00O0oooo0 = None
 if ( rloc ) :
  i1ii1Iii1 = rloc . rloc
  OooO00O0oooo0 = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 85 - 85: IiII + oO0o * I1ii11iIi11i . OoOoOO00 - I1ii11iIi11i * ooOoO0o
  if 32 - 32: o0oOOo0O0Ooo + OoOoOO00 . OOooOOo / OoOoOO00 % iIii1I11I1II1
  if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
  if 48 - 48: O0
  if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
 O00O0 , oO0O , ooO000OO = lisp_myrlocs
 if ( O00O0 == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 68 - 68: OoO0O00 * ooOoO0o / iII111i
 if ( oO0O == None and i1ii1Iii1 != None and i1ii1Iii1 . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 96 - 96: Ii1I + I11i + II111iiii * I1IiiI / Oo0Ooo % I1Ii111
  if 65 - 65: iII111i
 OOo0OoO0O0o0 = lisp_map_request ( )
 OOo0OoO0O0o0 . record_count = 1
 OOo0OoO0O0o0 . nonce = lisp_get_control_nonce ( )
 OOo0OoO0O0o0 . rloc_probe = ( i1ii1Iii1 != None )
 OOo0OoO0O0o0 . subscribe_bit = pubsub
 OOo0OoO0O0o0 . xtr_id_present = pubsub
 if 75 - 75: iIii1I11I1II1 - Oo0Ooo + Ii1I + ooOoO0o
 if 62 - 62: OOooOOo
 if 13 - 13: OOooOOo . i11iIiiIii
 if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
 if 79 - 79: oO0o
 if 47 - 47: OoooooooOO - i1IIi * OOooOOo
 if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
 if ( rloc ) : rloc . last_rloc_probe_nonce = OOo0OoO0O0o0 . nonce
 if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
 IiiiIi = deid . is_multicast_address ( )
 if ( IiiiIi ) :
  OOo0OoO0O0o0 . target_eid = seid
  OOo0OoO0O0o0 . target_group = deid
 else :
  OOo0OoO0O0o0 . target_eid = deid
  if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
  if 8 - 8: iII111i
  if 10 - 10: OoOoOO00 % I11i
  if 49 - 49: oO0o % ooOoO0o + II111iiii
  if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
  if 99 - 99: OoOoOO00
  if 46 - 46: I1ii11iIi11i / II111iiii / OoooooooOO / Ii1I
  if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
  if 8 - 8: oO0o
 if ( OOo0OoO0O0o0 . rloc_probe == False ) :
  i11IIII1Ii = lisp_get_signature_eid ( )
  if ( i11IIII1Ii ) :
   OOo0OoO0O0o0 . signature_eid . copy_address ( i11IIII1Ii . eid )
   OOo0OoO0O0o0 . privkey_filename = "./lisp-sig.pem"
   if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
   if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
   if 1 - 1: OoooooooOO . Ii1I
   if 68 - 68: Ii1I
   if 98 - 98: iII111i
   if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
 if ( seid == None or IiiiIi ) :
  OOo0OoO0O0o0 . source_eid . afi = LISP_AFI_NONE
 else :
  OOo0OoO0O0o0 . source_eid = seid
  if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
  if 67 - 67: o0oOOo0O0Ooo
  if 58 - 58: IiII % o0oOOo0O0Ooo + i1IIi
  if 33 - 33: II111iiii
  if 61 - 61: I1Ii111
  if 56 - 56: I1ii11iIi11i - OoooooooOO
  if 52 - 52: Oo0Ooo - I11i - IiII - OoOoOO00
  if 21 - 21: oO0o % o0oOOo0O0Ooo + I1Ii111 . OOooOOo / OOooOOo
  if 41 - 41: Oo0Ooo . ooOoO0o * oO0o
  if 31 - 31: Oo0Ooo * IiII / IiII
  if 3 - 3: I1Ii111
  if 65 - 65: iIii1I11I1II1 % Oo0Ooo % I11i / OoooooooOO
 if ( i1ii1Iii1 != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( i1ii1Iii1 . is_private_address ( ) == False ) :
   O00O0 = lisp_get_any_translated_rloc ( )
   if 82 - 82: o0oOOo0O0Ooo
  if ( O00O0 == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 33 - 33: OoOoOO00 / i11iIiiIii - I1IiiI - OoooooooOO + i1IIi * I1Ii111
   if 92 - 92: iII111i + OoO0O00
   if 70 - 70: iIii1I11I1II1
   if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
   if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
   if 14 - 14: I1Ii111 + Oo0Ooo
   if 35 - 35: i11iIiiIii * Ii1I
   if 100 - 100: O0 . iII111i / iIii1I11I1II1
 if ( i1ii1Iii1 == None or i1ii1Iii1 . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and i1ii1Iii1 == None ) :
   i1I1II = lisp_get_any_translated_rloc ( )
   if ( i1I1II != None ) : O00O0 = i1I1II
   if 86 - 86: OOooOOo - ooOoO0o / i11iIiiIii * o0oOOo0O0Ooo % II111iiii / I1ii11iIi11i
  OOo0OoO0O0o0 . itr_rlocs . append ( O00O0 )
  if 25 - 25: Ii1I
 if ( i1ii1Iii1 == None or i1ii1Iii1 . is_ipv6 ( ) ) :
  if ( oO0O == None or oO0O . is_ipv6_link_local ( ) ) :
   oO0O = None
  else :
   OOo0OoO0O0o0 . itr_rloc_count = 1 if ( i1ii1Iii1 == None ) else 0
   OOo0OoO0O0o0 . itr_rlocs . append ( oO0O )
   if 88 - 88: OoooooooOO
   if 73 - 73: ooOoO0o % iII111i * IiII - iIii1I11I1II1 + i1IIi + o0oOOo0O0Ooo
   if 63 - 63: iIii1I11I1II1
   if 88 - 88: OoooooooOO
   if 23 - 23: iII111i - IiII % i11iIiiIii
   if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
   if 60 - 60: OOooOOo - I1Ii111 * Oo0Ooo
   if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
   if 39 - 39: iIii1I11I1II1 / i1IIi % I11i % I1ii11iIi11i * IiII
 if ( i1ii1Iii1 != None and OOo0OoO0O0o0 . itr_rlocs != [ ] ) :
  IIoOo0oooO0 = OOo0OoO0O0o0 . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   IIoOo0oooO0 = O00O0
  elif ( deid . is_ipv6 ( ) ) :
   IIoOo0oooO0 = oO0O
  else :
   IIoOo0oooO0 = O00O0
   if 11 - 11: II111iiii + i1IIi
   if 1 - 1: OOooOOo
   if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
   if 83 - 83: OoooooooOO
   if 53 - 53: o0oOOo0O0Ooo - Oo0Ooo / IiII + O0
   if 88 - 88: Oo0Ooo % I1Ii111 * O0 - i1IIi * OoO0O00
 Oo00oo = OOo0OoO0O0o0 . encode ( i1ii1Iii1 , OooO00O0oooo0 )
 OOo0OoO0O0o0 . print_map_request ( )
 if 74 - 74: Oo0Ooo % iIii1I11I1II1 + OOooOOo
 if 50 - 50: OoO0O00 . OoooooooOO
 if 31 - 31: OoO0O00
 if 55 - 55: OoOoOO00 + I1Ii111 * o0oOOo0O0Ooo - I1ii11iIi11i + OoOoOO00
 if 6 - 6: II111iiii % iIii1I11I1II1 * I1Ii111
 if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
 if ( i1ii1Iii1 != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   OOoOoO0O = lisp_get_nat_info ( i1ii1Iii1 , rloc . rloc_name )
   if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
   if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
   if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
   if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
   if ( OOoOoO0O == None ) :
    O00o00o00OO0 = rloc . rloc . print_address_no_iid ( )
    Oo = "gleaned-{}" . format ( O00o00o00OO0 )
    iIIiiIi = rloc . translated_port
    OOoOoO0O = lisp_nat_info ( O00o00o00OO0 , Oo , iIIiiIi )
    if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
   lisp_encapsulate_rloc_probe ( lisp_sockets , i1ii1Iii1 , OOoOoO0O ,
 Oo00oo )
   return
   if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
   if 74 - 74: OoooooooOO + Ii1I
  O0O0 = i1ii1Iii1 . print_address_no_iid ( )
  I1i1iiIi = lisp_convert_4to6 ( O0O0 )
  lisp_send ( lisp_sockets , I1i1iiIi , LISP_CTRL_PORT , Oo00oo )
  return
  if 100 - 100: I1IiiI
  if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
  if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
  if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
  if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
  if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
 O0i1I1IiiI1 = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  OOoOo0O0O0oO = lisp_get_decent_map_resolver ( deid )
 else :
  OOoOo0O0O0oO = lisp_get_map_resolver ( None , O0i1I1IiiI1 )
  if 5 - 5: I1IiiI / OoOoOO00 / i11iIiiIii
 if ( OOoOo0O0O0oO == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 59 - 59: I11i - Ii1I - O0
  return
  if 7 - 7: OoooooooOO
 OOoOo0O0O0oO . last_used = lisp_get_timestamp ( )
 OOoOo0O0O0oO . map_requests_sent += 1
 if ( OOoOo0O0O0oO . last_nonce == 0 ) : OOoOo0O0O0oO . last_nonce = OOo0OoO0O0o0 . nonce
 if 13 - 13: I11i - o0oOOo0O0Ooo - O0 % Oo0Ooo - oO0o * OoOoOO00
 if 76 - 76: IiII
 if 88 - 88: o0oOOo0O0Ooo * II111iiii % Oo0Ooo * I1ii11iIi11i . I1IiiI % I1ii11iIi11i
 if 37 - 37: OOooOOo % OoO0O00 % oO0o . I11i / OOooOOo
 if ( seid == None ) : seid = IIoOo0oooO0
 lisp_send_ecm ( lisp_sockets , Oo00oo , seid , lisp_ephem_port , deid ,
 OOoOo0O0O0oO . map_resolver )
 if 8 - 8: iIii1I11I1II1 + O0 + IiII - IiII * I1Ii111 / i1IIi
 if 10 - 10: Oo0Ooo . i11iIiiIii + iIii1I11I1II1 % iII111i + i11iIiiIii
 if 6 - 6: OoOoOO00 + OOooOOo + Oo0Ooo
 if 43 - 43: IiII * iII111i . ooOoO0o / I1ii11iIi11i . ooOoO0o * II111iiii
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 30 - 30: iII111i
 if 51 - 51: ooOoO0o + oO0o
 if 80 - 80: O0 - I1Ii111 * Ii1I + I1ii11iIi11i % II111iiii . I11i
 if 80 - 80: OoOoOO00 - OOooOOo
 OOoOo0O0O0oO . resolve_dns_name ( )
 return
 if 37 - 37: ooOoO0o
 if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
 if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
 if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
 if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
 if 82 - 82: iII111i - I1Ii111 - OoOoOO00
 if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
 if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 44 - 44: O0
 if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
 if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
 if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
 IiIII1i1iIi1 = lisp_info ( )
 IiIII1i1iIi1 . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : IiIII1i1iIi1 . hostname += "-" + device_name
 if 89 - 89: O0 - OoO0O00
 O0O0 = dest . print_address_no_iid ( )
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
 if 49 - 49: II111iiii - OOooOOo + II111iiii + OoOoOO00
 if 51 - 51: i11iIiiIii
 if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
 if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
 if 63 - 63: II111iiii - Oo0Ooo
 if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
 OooI1I1iI1 = False
 if ( device_name ) :
  III1IIIi1111 = lisp_get_host_route_next_hop ( O0O0 )
  if 11 - 11: OoO0O00 . Ii1I % II111iiii + o0oOOo0O0Ooo / IiII
  if 25 - 25: i1IIi + o0oOOo0O0Ooo
  if 90 - 90: OoooooooOO * ooOoO0o + IiII * OoOoOO00 - OoOoOO00
  if 24 - 24: OoooooooOO / I1IiiI % iII111i . i11iIiiIii
  if 14 - 14: O0 . IiII - Ii1I
  if 39 - 39: O0 % I1Ii111
  if 82 - 82: II111iiii . IiII - O0
  if 18 - 18: oO0o * OOooOOo
  if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
  if ( port == LISP_CTRL_PORT and III1IIIi1111 != None ) :
   while ( True ) :
    time . sleep ( .01 )
    III1IIIi1111 = lisp_get_host_route_next_hop ( O0O0 )
    if ( III1IIIi1111 == None ) : break
    if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
    if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
    if 96 - 96: II111iiii % I11i / Ii1I - i11iIiiIii
  oo0Oo = lisp_get_default_route_next_hops ( )
  for ooO000OO , ii1I in oo0Oo :
   if ( ooO000OO != device_name ) : continue
   if 70 - 70: OoO0O00 * II111iiii / I11i + I11i
   if 23 - 23: I1IiiI
   if 51 - 51: i11iIiiIii / ooOoO0o - OoooooooOO + OoOoOO00 + oO0o
   if 57 - 57: iIii1I11I1II1
   if 19 - 19: Ii1I / o0oOOo0O0Ooo + O0 / iIii1I11I1II1 + II111iiii
   if 3 - 3: oO0o % OoO0O00 % OOooOOo
   if ( III1IIIi1111 != ii1I ) :
    if ( III1IIIi1111 != None ) :
     lisp_install_host_route ( O0O0 , III1IIIi1111 , False )
     if 64 - 64: o0oOOo0O0Ooo . II111iiii * IiII % Oo0Ooo + I11i - OoooooooOO
    lisp_install_host_route ( O0O0 , ii1I , True )
    OooI1I1iI1 = True
    if 58 - 58: ooOoO0o
   break
   if 15 - 15: O0 * OOooOOo * I11i + Ii1I * OoooooooOO + OOooOOo
   if 77 - 77: O0
   if 98 - 98: iII111i - iII111i % i1IIi - I1Ii111 . I1IiiI % o0oOOo0O0Ooo
   if 38 - 38: IiII % OoOoOO00 . OOooOOo . I1ii11iIi11i
   if 34 - 34: iII111i . i11iIiiIii + OoO0O00 + o0oOOo0O0Ooo / ooOoO0o - i11iIiiIii
   if 63 - 63: ooOoO0o % OoO0O00 % ooOoO0o
 Oo00oo = IiIII1i1iIi1 . encode ( )
 IiIII1i1iIi1 . print_info ( )
 if 28 - 28: IiII * I1Ii111 * o0oOOo0O0Ooo + ooOoO0o - IiII / IiII
 if 73 - 73: iIii1I11I1II1 . I1ii11iIi11i + OOooOOo
 if 51 - 51: I11i % Oo0Ooo * OOooOOo % OoooooooOO - OoOoOO00 % Ii1I
 if 60 - 60: OoOoOO00 - IiII + OoO0O00
 o0oOoOo00oo = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 o0oOoOo00oo = bold ( o0oOoOo00oo , False )
 iIIiiIi = bold ( "{}" . format ( port ) , False )
 OO0O00o0 = red ( O0O0 , False )
 i11 = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( i11 , OO0O00o0 , iIIiiIi , o0oOoOo00oo ) )
 if 74 - 74: iII111i + i11iIiiIii
 if 95 - 95: Ii1I
 if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
 if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
 if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
 if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , Oo00oo )
 else :
  ooo = lisp_data_header ( )
  ooo . instance_id ( 0xffffff )
  ooo = ooo . encode ( )
  if ( ooo ) :
   Oo00oo = ooo + Oo00oo
   if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
   if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
   if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
   if 49 - 49: iII111i / iII111i - OoOoOO00
   if 89 - 89: ooOoO0o
   if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
   if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
   if 11 - 11: iII111i
   if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , Oo00oo )
   if 89 - 89: I11i % II111iiii
   if 35 - 35: oO0o
   if 65 - 65: II111iiii
   if 87 - 87: oO0o / OoO0O00 - oO0o
   if 69 - 69: i11iIiiIii
   if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
   if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
 if ( OooI1I1iI1 ) :
  lisp_install_host_route ( O0O0 , None , False )
  if ( III1IIIi1111 != None ) : lisp_install_host_route ( O0O0 , III1IIIi1111 , True )
  if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
 return
 if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
 if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
 if 14 - 14: I1ii11iIi11i / i11iIiiIii * I11i % o0oOOo0O0Ooo + IiII / I1ii11iIi11i
 if 82 - 82: OOooOOo . oO0o
 if 12 - 12: i11iIiiIii + II111iiii
 if 49 - 49: OoooooooOO
 if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
 if 6 - 6: oO0o / II111iiii
 if 23 - 23: IiII - OoooooooOO / oO0o
 if 69 - 69: O0 - OoooooooOO
 IiIII1i1iIi1 = lisp_info ( )
 packet = IiIII1i1iIi1 . decode ( packet )
 if ( packet == None ) : return
 IiIII1i1iIi1 . print_info ( )
 if 31 - 31: o0oOOo0O0Ooo . i1IIi - i1IIi % i1IIi - iIii1I11I1II1
 if 50 - 50: IiII - OOooOOo % OoOoOO00
 if 66 - 66: IiII * i11iIiiIii
 if 64 - 64: i11iIiiIii . I1Ii111 % i11iIiiIii % I11i
 if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
 IiIII1i1iIi1 . info_reply = True
 IiIII1i1iIi1 . global_etr_rloc . store_address ( addr_str )
 IiIII1i1iIi1 . etr_port = sport
 if 64 - 64: OOooOOo / OoOoOO00
 if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
 if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
 if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
 if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
 if ( IiIII1i1iIi1 . hostname != None ) :
  IiIII1i1iIi1 . private_etr_rloc . afi = LISP_AFI_NAME
  IiIII1i1iIi1 . private_etr_rloc . store_address ( IiIII1i1iIi1 . hostname )
  if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
  if 49 - 49: IiII
 if ( rtr_list != None ) : IiIII1i1iIi1 . rtr_list = rtr_list
 packet = IiIII1i1iIi1 . encode ( )
 IiIII1i1iIi1 . print_info ( )
 if 1 - 1: oO0o / I11i
 if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
 if 28 - 28: OOooOOo - O0 - O0 % i11iIiiIii * OoooooooOO
 if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
 if 24 - 24: O0
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 I1i1iiIi = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , I1i1iiIi , sport , packet )
 if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
 if 65 - 65: i11iIiiIii
 if 46 - 46: i11iIiiIii
 if 70 - 70: i1IIi + o0oOOo0O0Ooo
 if 44 - 44: iII111i . II111iiii % o0oOOo0O0Ooo
 iiiII1Ii11I1 = lisp_info_source ( IiIII1i1iIi1 . hostname , addr_str , sport )
 iiiII1Ii11I1 . cache_address_for_info_source ( )
 return
 if 94 - 94: OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
 if 55 - 55: II111iiii - IiII
 if 24 - 24: oO0o % Ii1I / i1IIi
 if 84 - 84: i1IIi
 if 53 - 53: OoooooooOO - i1IIi - Ii1I
 if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
 if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
 if 34 - 34: Ii1I
def lisp_get_signature_eid ( ) :
 for i11IIII1Ii in lisp_db_list :
  if ( i11IIII1Ii . signature_eid ) : return ( i11IIII1Ii )
  if 5 - 5: II111iiii . I1ii11iIi11i
 return ( None )
 if 85 - 85: I1Ii111 . IiII + II111iiii
 if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
 if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
 if 87 - 87: OOooOOo
 if 44 - 44: Oo0Ooo + iIii1I11I1II1
 if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
 if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
def lisp_get_any_translated_port ( ) :
 for i11IIII1Ii in lisp_db_list :
  for OO0oooo in i11IIII1Ii . rloc_set :
   if ( OO0oooo . translated_rloc . is_null ( ) ) : continue
   return ( OO0oooo . translated_port )
   if 10 - 10: O0 / I11i
   if 29 - 29: i11iIiiIii % I11i
 return ( None )
 if 49 - 49: I11i
 if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
 if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
 if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
 if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
 if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
 if 32 - 32: O0
 if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
 if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
def lisp_get_any_translated_rloc ( ) :
 for i11IIII1Ii in lisp_db_list :
  for OO0oooo in i11IIII1Ii . rloc_set :
   if ( OO0oooo . translated_rloc . is_null ( ) ) : continue
   return ( OO0oooo . translated_rloc )
   if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
   if 70 - 70: iIii1I11I1II1 - I11i
 return ( None )
 if 2 - 2: oO0o / II111iiii * OoO0O00
 if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
 if 40 - 40: OOooOOo
 if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
 if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
 if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
 if 26 - 26: OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
def lisp_get_all_translated_rlocs ( ) :
 II1Iii1Ii11I = [ ]
 for i11IIII1Ii in lisp_db_list :
  for OO0oooo in i11IIII1Ii . rloc_set :
   if ( OO0oooo . is_rloc_translated ( ) == False ) : continue
   IiI = OO0oooo . translated_rloc . print_address_no_iid ( )
   II1Iii1Ii11I . append ( IiI )
   if 14 - 14: I1ii11iIi11i / i1IIi . ooOoO0o % OoO0O00 * OoO0O00 + oO0o
   if 65 - 65: Oo0Ooo % iIii1I11I1II1
 return ( II1Iii1Ii11I )
 if 40 - 40: iII111i + Ii1I . OoooooooOO . i1IIi
 if 7 - 7: I1ii11iIi11i - Ii1I % Ii1I
 if 75 - 75: O0 . II111iiii + Oo0Ooo * O0 - IiII % OoOoOO00
 if 85 - 85: I1Ii111 - Ii1I . I1ii11iIi11i - OoooooooOO
 if 10 - 10: Ii1I . iII111i
 if 62 - 62: o0oOOo0O0Ooo + OoooooooOO + IiII
 if 98 - 98: OoO0O00 . o0oOOo0O0Ooo + ooOoO0o + OOooOOo + oO0o
 if 29 - 29: i11iIiiIii - I11i
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 oo0Oo0o = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 94 - 94: Oo0Ooo
 I11II1I1I = { }
 for I1Ii1i111I in rtr_list :
  if ( I1Ii1i111I == None ) : continue
  IiI = rtr_list [ I1Ii1i111I ]
  if ( oo0Oo0o and IiI . is_private_address ( ) ) : continue
  I11II1I1I [ I1Ii1i111I ] = IiI
  if 8 - 8: i1IIi % i1IIi % OoooooooOO % i1IIi . iIii1I11I1II1
 rtr_list = I11II1I1I
 if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
 OoOOoo0oOOO0 = [ ]
 for Oooo000 in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( Oooo000 == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 34 - 34: oO0o
  if 40 - 40: OoO0O00
  if 29 - 29: i1IIi
  if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
  if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
  I1I11I1IIi = lisp_address ( Oooo000 , "" , 0 , iid )
  I1I11I1IIi . make_default_route ( I1I11I1IIi )
  o0ooo0oOO0o = lisp_map_cache . lookup_cache ( I1I11I1IIi , True )
  if ( o0ooo0oOO0o ) :
   if ( o0ooo0oOO0o . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( o0ooo0oOO0o . print_eid_tuple ( ) , False ) ) )
    if 31 - 31: i1IIi * Ii1I
   elif ( o0ooo0oOO0o . do_rloc_sets_match ( list ( rtr_list . values ( ) ) ) ) :
    continue
    if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
   o0ooo0oOO0o . delete_cache ( )
   if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
   if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
  OoOOoo0oOOO0 . append ( [ I1I11I1IIi , "" ] )
  if 52 - 52: OOooOOo . OoOoOO00 - ooOoO0o % i1IIi
  if 15 - 15: oO0o
  if 6 - 6: oO0o . iIii1I11I1II1 - I1ii11iIi11i % IiII
  if 58 - 58: iII111i * oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o
  o0o0Oo0o0oOo = lisp_address ( Oooo000 , "" , 0 , iid )
  o0o0Oo0o0oOo . make_default_multicast_route ( o0o0Oo0o0oOo )
  oOoO0o = lisp_map_cache . lookup_cache ( o0o0Oo0o0oOo , True )
  if ( oOoO0o ) : oOoO0o = oOoO0o . source_cache . lookup_cache ( I1I11I1IIi , True )
  if ( oOoO0o ) : oOoO0o . delete_cache ( )
  if 85 - 85: OoooooooOO % OoOoOO00 + OoOoOO00 / iIii1I11I1II1
  OoOOoo0oOOO0 . append ( [ I1I11I1IIi , o0o0Oo0o0oOo ] )
  if 70 - 70: oO0o . i11iIiiIii
 if ( len ( OoOOoo0oOOO0 ) == 0 ) : return
 if 7 - 7: iII111i * i11iIiiIii + Oo0Ooo - Ii1I
 if 80 - 80: I11i + o0oOOo0O0Ooo * Ii1I
 if 48 - 48: oO0o . iII111i
 if 51 - 51: I1Ii111 . OoO0O00 + I1IiiI . o0oOOo0O0Ooo
 OOOo0O00OO00O = [ ]
 for i11 in rtr_list :
  oO000O0 = rtr_list [ i11 ]
  OO0oooo = lisp_rloc ( )
  OO0oooo . rloc . copy_address ( oO000O0 )
  OO0oooo . priority = 254
  OO0oooo . mpriority = 255
  OO0oooo . rloc_name = "RTR"
  OOOo0O00OO00O . append ( OO0oooo )
  if 64 - 64: I11i . I1Ii111 % i11iIiiIii
  if 22 - 22: I11i
 for I1I11I1IIi in OoOOoo0oOOO0 :
  o0ooo0oOO0o = lisp_mapping ( I1I11I1IIi [ 0 ] , I1I11I1IIi [ 1 ] , OOOo0O00OO00O )
  o0ooo0oOO0o . mapping_source = map_resolver
  o0ooo0oOO0o . map_cache_ttl = LISP_MR_TTL * 60
  o0ooo0oOO0o . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( o0ooo0oOO0o . print_eid_tuple ( ) , False ) , list ( rtr_list . keys ( ) ) ) )
  if 30 - 30: i1IIi
  OOOo0O00OO00O = copy . deepcopy ( OOOo0O00OO00O )
  if 56 - 56: Oo0Ooo
 return
 if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
 if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
 if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
 if 70 - 70: Oo0Ooo - I11i / I1ii11iIi11i % OoO0O00 % II111iiii
 if 72 - 72: i11iIiiIii * I11i
 if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
 if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
 if 64 - 64: OoooooooOO
 if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
def lisp_process_info_reply ( source , packet , store ) :
 if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
 if 71 - 71: O0 - OoooooooOO
 if 82 - 82: i11iIiiIii * II111iiii % IiII
 if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
 IiIII1i1iIi1 = lisp_info ( )
 packet = IiIII1i1iIi1 . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
 IiIII1i1iIi1 . print_info ( )
 if 67 - 67: iII111i
 if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
 if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
 if 60 - 60: i1IIi / iII111i
 I11I = False
 for i11 in IiIII1i1iIi1 . rtr_list :
  O0O0 = i11 . print_address_no_iid ( )
  if ( O0O0 in lisp_rtr_list ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ O0O0 ] != None ) : continue
   if 72 - 72: o0oOOo0O0Ooo . OoOoOO00 / i11iIiiIii - iIii1I11I1II1 . iII111i
  I11I = True
  lisp_rtr_list [ O0O0 ] = i11
  if 29 - 29: ooOoO0o . I1IiiI + o0oOOo0O0Ooo - I1IiiI
  if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
  if 65 - 65: Ii1I % i11iIiiIii
  if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
  if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
 if ( lisp_i_am_itr and I11I ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for oooo in list ( lisp_iid_to_interface . keys ( ) ) :
    lisp_update_default_routes ( source , int ( oooo ) , lisp_rtr_list )
    if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
    if 88 - 88: iII111i
    if 94 - 94: OoooooooOO
    if 32 - 32: I1ii11iIi11i
    if 8 - 8: I11i * i11iIiiIii - ooOoO0o
    if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
    if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
 if ( store == False ) :
  return ( [ IiIII1i1iIi1 . global_etr_rloc , IiIII1i1iIi1 . etr_port , I11I ] )
  if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
  if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
  if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
  if 42 - 42: II111iiii . iII111i
  if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
  if 64 - 64: oO0o / IiII
 for i11IIII1Ii in lisp_db_list :
  for OO0oooo in i11IIII1Ii . rloc_set :
   I1Ii1i111I = OO0oooo . rloc
   i111IIiIiiI1 = OO0oooo . interface
   if ( i111IIiIiiI1 == None ) :
    if ( I1Ii1i111I . is_null ( ) ) : continue
    if ( I1Ii1i111I . is_local ( ) == False ) : continue
    if ( IiIII1i1iIi1 . private_etr_rloc . is_null ( ) == False and
 I1Ii1i111I . is_exact_match ( IiIII1i1iIi1 . private_etr_rloc ) == False ) :
     continue
     if 86 - 86: I11i
   elif ( IiIII1i1iIi1 . private_etr_rloc . is_dist_name ( ) ) :
    OO000o = IiIII1i1iIi1 . private_etr_rloc . address
    if ( OO000o != OO0oooo . rloc_name ) : continue
    if 36 - 36: o0oOOo0O0Ooo / OoO0O00
    if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
   i1iiii = green ( i11IIII1Ii . eid . print_prefix ( ) , False )
   IIi11IiiiI11i = red ( I1Ii1i111I . print_address_no_iid ( ) , False )
   if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
   OoOoooOo = IiIII1i1iIi1 . global_etr_rloc . is_exact_match ( I1Ii1i111I )
   if ( OO0oooo . translated_port == 0 and OoOoooOo ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( IIi11IiiiI11i ,
 i111IIiIiiI1 , i1iiii ) )
    continue
    if 82 - 82: iII111i * iIii1I11I1II1 * ooOoO0o + OoooooooOO / OoO0O00 . i11iIiiIii
    if 32 - 32: Oo0Ooo % O0 * I1ii11iIi11i . oO0o - iII111i
    if 61 - 61: ooOoO0o % II111iiii
    if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
    if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
   o0ooOOo0O = IiIII1i1iIi1 . global_etr_rloc
   OOOOO = OO0oooo . translated_rloc
   if ( OOOOO . is_exact_match ( o0ooOOo0O ) and
 IiIII1i1iIi1 . etr_port == OO0oooo . translated_port ) : continue
   if 8 - 8: o0oOOo0O0Ooo . IiII * OoO0O00 * Ii1I - i11iIiiIii - OoO0O00
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( IiIII1i1iIi1 . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # i11iIiiIii . Oo0Ooo / OoOoOO00 + IiII
 IiIII1i1iIi1 . etr_port , IIi11IiiiI11i , i111IIiIiiI1 , i1iiii ) )
   if 32 - 32: IiII
   OO0oooo . store_translated_rloc ( IiIII1i1iIi1 . global_etr_rloc ,
 IiIII1i1iIi1 . etr_port )
   if 20 - 20: oO0o * I1IiiI % I1Ii111 % i11iIiiIii
   if 44 - 44: ooOoO0o + o0oOOo0O0Ooo
 return ( [ IiIII1i1iIi1 . global_etr_rloc , IiIII1i1iIi1 . etr_port , I11I ] )
 if 10 - 10: i1IIi + o0oOOo0O0Ooo
 if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
 if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 if 2 - 2: I11i
 if 12 - 12: i1IIi . I1Ii111
 if 99 - 99: Oo0Ooo / i11iIiiIii
 if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 42 - 42: iII111i / Oo0Ooo
 i1I1I1IIIi11 = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 iiiioO0oo0o = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 36 - 36: O0 + OOooOOo * i1IIi - OoooooooOO * iII111i
 if 8 - 8: OoooooooOO * i11iIiiIii * iII111i * O0 - OoOoOO00
 if 3 - 3: OoooooooOO % oO0o + OoOoOO00 % I1IiiI
 if 50 - 50: OoO0O00 - Oo0Ooo
 i1I1I1IIIi11 . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , i1I1I1IIIi11 , None )
 i1I1I1IIIi11 . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , i1I1I1IIIi11 , None )
 if 13 - 13: OoOoOO00
 if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
 if 90 - 90: oO0o * I1Ii111 / O0
 if 15 - 15: o0oOOo0O0Ooo * O0 . OOooOOo / Oo0Ooo
 iiiioO0oo0o . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , iiiioO0oo0o , None )
 iiiioO0oo0o . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , iiiioO0oo0o , None )
 if 28 - 28: OoooooooOO + OoooooooOO
 if 27 - 27: I11i . oO0o / OoooooooOO - OoO0O00 . I11i
 if 15 - 15: II111iiii * OoO0O00
 if 33 - 33: OoooooooOO . o0oOOo0O0Ooo . I1IiiI / I1ii11iIi11i . OoOoOO00
 oooO0Ooo000 = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 oooO0Ooo000 . start ( )
 return
 if 9 - 9: OoooooooOO * ooOoO0o % I1ii11iIi11i . I1IiiI % O0
 if 91 - 91: OOooOOo * OoooooooOO * I1IiiI . i1IIi
 if 9 - 9: oO0o / i11iIiiIii + IiII / IiII - I11i
 if 87 - 87: iII111i
 if 37 - 37: oO0o + OoO0O00
 if 66 - 66: iIii1I11I1II1 * iIii1I11I1II1 + IiII % I1IiiI
 if 60 - 60: I1Ii111 . IiII / Oo0Ooo
 if 32 - 32: OoOoOO00 + Ii1I * iII111i % Oo0Ooo
 if 61 - 61: OoooooooOO % iII111i - O0
 if 62 - 62: iIii1I11I1II1
 if 14 - 14: I1Ii111
 if 95 - 95: II111iiii / o0oOOo0O0Ooo * OOooOOo
 if 81 - 81: i11iIiiIii / iIii1I11I1II1
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 73 - 73: i11iIiiIii . I1ii11iIi11i * OoOoOO00
 IiI = lisp_get_interface_address ( rloc . interface )
 if ( IiI == None ) : return
 if 95 - 95: i1IIi + iIii1I11I1II1 . I1Ii111 / I1Ii111
 oO0IiI1iiII11II1 = rloc . rloc . print_address_no_iid ( )
 Iii11Ii = IiI . print_address_no_iid ( )
 if 81 - 81: I1IiiI . I1Ii111
 if ( oO0IiI1iiII11II1 == Iii11Ii ) : return
 if 74 - 74: II111iiii - o0oOOo0O0Ooo + ooOoO0o - iIii1I11I1II1 / OoO0O00
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , oO0IiI1iiII11II1 , Iii11Ii ) )
 if 89 - 89: I1Ii111 + ooOoO0o + I1Ii111
 if 35 - 35: O0 * OoOoOO00
 rloc . rloc . copy_address ( IiI )
 lisp_myrlocs [ 0 ] = IiI
 return
 if 54 - 54: O0 / Oo0Ooo
 if 54 - 54: OoO0O00
 if 38 - 38: II111iiii + o0oOOo0O0Ooo * I11i + I1Ii111 - II111iiii . OOooOOo
 if 38 - 38: I1ii11iIi11i % OOooOOo + iII111i / Oo0Ooo / IiII / oO0o
 if 2 - 2: iIii1I11I1II1
 if 9 - 9: I1Ii111 / IiII
 if 33 - 33: o0oOOo0O0Ooo + oO0o . o0oOOo0O0Ooo . I11i * OoooooooOO + iIii1I11I1II1
 if 64 - 64: OoooooooOO . Ii1I
def lisp_update_encap_port ( mc ) :
 for I1Ii1i111I in mc . rloc_set :
  OOoOoO0O = lisp_get_nat_info ( I1Ii1i111I . rloc , I1Ii1i111I . rloc_name )
  if ( OOoOoO0O == None ) : continue
  if ( I1Ii1i111I . translated_port == OOoOoO0O . port ) : continue
  if 38 - 38: Oo0Ooo
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( I1Ii1i111I . translated_port , OOoOoO0O . port ,
  # I11i / i11iIiiIii * IiII . OOooOOo
 red ( I1Ii1i111I . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 79 - 79: I1Ii111 - OOooOOo - OoOoOO00
  I1Ii1i111I . store_translated_rloc ( I1Ii1i111I . rloc , OOoOoO0O . port )
  if 29 - 29: OoooooooOO - i1IIi % OoooooooOO * o0oOOo0O0Ooo / II111iiii
 return
 if 38 - 38: i1IIi % o0oOOo0O0Ooo - Oo0Ooo
 if 46 - 46: I11i . iII111i - I1IiiI / iIii1I11I1II1
 if 80 - 80: Ii1I % oO0o / I1Ii111
 if 12 - 12: II111iiii / ooOoO0o . Oo0Ooo / I1Ii111
 if 59 - 59: I1IiiI % O0
 if 93 - 93: OoooooooOO % IiII % Ii1I - i11iIiiIii
 if 74 - 74: ooOoO0o + OoOoOO00
 if 94 - 94: i11iIiiIii
 if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
 if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
 if 46 - 46: Oo0Ooo / Oo0Ooo * IiII
 if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 65 - 65: I11i
  if 92 - 92: iII111i . IiII + i1IIi % i1IIi
 o0Ooo0O0 = lisp_get_timestamp ( )
 IIIi111 = mc . last_refresh_time
 if 11 - 11: oO0o * Ii1I . I1Ii111
 if 91 - 91: I1ii11iIi11i % i1IIi / Ii1I
 if 62 - 62: I11i % IiII * I1Ii111 - II111iiii / OoooooooOO
 if 39 - 39: I1IiiI . O0 + I1ii11iIi11i . iIii1I11I1II1 + ooOoO0o
 if 54 - 54: II111iiii / iII111i + OOooOOo - i11iIiiIii % I1Ii111 / OoO0O00
 if 2 - 2: II111iiii + I1Ii111 - Ii1I
 if 44 - 44: II111iiii + OOooOOo % I1IiiI
 if ( lisp_is_running ( "lisp-ms" ) and lisp_uptime + ( 5 * 60 ) >= o0Ooo0O0 ) :
  if ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
   IIIi111 = 0
   lprint ( "Remove startup-mode native-forward map-cache entry" )
   if 34 - 34: o0oOOo0O0Ooo / I1ii11iIi11i - o0oOOo0O0Ooo / i11iIiiIii
   if 18 - 18: oO0o
   if 43 - 43: I11i / OOooOOo + OOooOOo
   if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
   if 90 - 90: OOooOOo
   if 29 - 29: OoOoOO00 - I1IiiI / oO0o + Oo0Ooo + I1Ii111 + O0
   if 65 - 65: oO0o
   if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
 if ( IIIi111 + mc . map_cache_ttl > o0Ooo0O0 ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 13 - 13: Ii1I
  if 34 - 34: I1IiiI / iIii1I11I1II1
  if 35 - 35: oO0o / oO0o
  if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
  if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
 if ( lisp_nat_traversal and mc . eid . address == 0 and mc . eid . mask_len == 0 ) :
  return ( [ True , delete_list ] )
  if 77 - 77: O0
  if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
  if 36 - 36: II111iiii
  if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
  if 7 - 7: i11iIiiIii
 Ii1Ii1ii = lisp_print_elapsed ( mc . uptime )
 i11i1 = lisp_print_elapsed ( mc . last_refresh_time )
 i1I1I1ii1i = mc . print_eid_tuple ( )
 lprint ( ( "Map-cache entry {} {}, had uptime {}, last-refresh-time {}" ) . format ( green ( i1I1I1ii1i , False ) , bold ( "timed out" , False ) , Ii1Ii1ii , i11i1 ) )
 if 25 - 25: O0 * o0oOOo0O0Ooo - iII111i % OoO0O00
 if 6 - 6: ooOoO0o % Oo0Ooo / I1Ii111 % i11iIiiIii * OoooooooOO + I1ii11iIi11i
 if 21 - 21: o0oOOo0O0Ooo - iII111i / OoO0O00
 if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
 if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 89 - 89: Ii1I * Oo0Ooo / I1Ii111 * I1ii11iIi11i + O0 * Oo0Ooo
 if 74 - 74: I11i . I11i
 if 74 - 74: OoOoOO00 * ooOoO0o * I1Ii111
 if 56 - 56: iIii1I11I1II1 * OoO0O00 - oO0o * Ii1I
 if 62 - 62: i1IIi + I11i / OOooOOo - OoooooooOO % i1IIi . I1IiiI
 if 13 - 13: O0 * iII111i
 if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
 if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
def lisp_timeout_map_cache_walk ( mc , parms ) :
 oO000Oo0oOOo = parms [ 0 ]
 Ooo000OO = parms [ 1 ]
 if 81 - 81: II111iiii
 if 47 - 47: I1Ii111 * iII111i
 if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
 if 76 - 76: iIii1I11I1II1 . i11iIiiIii * II111iiii - iII111i
 if ( mc . group . is_null ( ) ) :
  IIIiIii111iii , oO000Oo0oOOo = lisp_timeout_map_cache_entry ( mc , oO000Oo0oOOo )
  if ( oO000Oo0oOOo == [ ] or mc != oO000Oo0oOOo [ - 1 ] ) :
   Ooo000OO = lisp_write_checkpoint_entry ( Ooo000OO , mc )
   if 51 - 51: I1IiiI
  return ( [ IIIiIii111iii , parms ] )
  if 52 - 52: I1Ii111
  if 82 - 82: iII111i + II111iiii
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 29 - 29: O0 % Ii1I * ooOoO0o % O0
 if 83 - 83: oO0o
 if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
 if 85 - 85: iIii1I11I1II1 / I11i
 if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
 if 20 - 20: OOooOOo % i1IIi * Ii1I / i11iIiiIii
 if 89 - 89: ooOoO0o
 if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
 if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
 if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
 if 20 - 20: I11i
def lisp_timeout_map_cache ( lisp_map_cache ) :
 I1iII1IIi1IiI = [ [ ] , [ ] ]
 I1iII1IIi1IiI = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , I1iII1IIi1IiI )
 if 37 - 37: I1Ii111
 if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
 if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
 if 41 - 41: O0 / OoooooooOO - i1IIi
 if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
 oO000Oo0oOOo = I1iII1IIi1IiI [ 0 ]
 for o0ooo0oOO0o in oO000Oo0oOOo : o0ooo0oOO0o . delete_cache ( )
 if 32 - 32: oO0o / IiII - I11i . ooOoO0o
 if 69 - 69: i11iIiiIii * i11iIiiIii
 if 100 - 100: I1ii11iIi11i * I1ii11iIi11i + i1IIi
 if 96 - 96: I1Ii111 / I1IiiI + ooOoO0o
 Ooo000OO = I1iII1IIi1IiI [ 1 ]
 lisp_checkpoint ( Ooo000OO )
 return
 if 16 - 16: I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo % OoOoOO00 + ooOoO0o % I1ii11iIi11i
 if 85 - 85: oO0o * OoooooooOO * iIii1I11I1II1 + iII111i
 if 67 - 67: Ii1I / i11iIiiIii % OoOoOO00 % O0 / OoOoOO00
 if 54 - 54: I11i . OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
 if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
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
def lisp_store_nat_info ( hostname , rloc , port ) :
 O0O0 = rloc . print_address_no_iid ( )
 oooO0OoO = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( O0O0 , False ) , port )
 if 3 - 3: oO0o * O0 / iIii1I11I1II1
 iIIIi = lisp_nat_info ( O0O0 , hostname , port )
 if 77 - 77: I1IiiI % i11iIiiIii + Ii1I + iIii1I11I1II1 / IiII - iII111i
 if ( hostname not in lisp_nat_state_info ) :
  lisp_nat_state_info [ hostname ] = [ iIIIi ]
  lprint ( oooO0OoO . format ( "Store initial" ) )
  return ( True )
  if 57 - 57: OoO0O00 - OoO0O00 % I1Ii111 * I11i . i11iIiiIii
  if 10 - 10: oO0o % iIii1I11I1II1 . OOooOOo / I11i / i1IIi
  if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
  if 86 - 86: Oo0Ooo
  if 97 - 97: I1IiiI
  if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
 OOoOoO0O = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( OOoOoO0O . address == O0O0 and OOoOoO0O . port == port ) :
  OOoOoO0O . uptime = lisp_get_timestamp ( )
  lprint ( oooO0OoO . format ( "Refresh existing" ) )
  return ( False )
  if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
  if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
  if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
  if 64 - 64: I1IiiI % ooOoO0o
  if 72 - 72: O0 * II111iiii % OoO0O00 - I1IiiI * OOooOOo
  if 80 - 80: OOooOOo * I11i / OOooOOo - oO0o
  if 18 - 18: i1IIi - OOooOOo - o0oOOo0O0Ooo - iIii1I11I1II1
 ooooOo0ooo = None
 for OOoOoO0O in lisp_nat_state_info [ hostname ] :
  if ( OOoOoO0O . address == O0O0 and OOoOoO0O . port == port ) :
   ooooOo0ooo = OOoOoO0O
   break
   if 15 - 15: O0 * OoooooooOO - O0 + OoooooooOO
   if 40 - 40: O0 * OoooooooOO - oO0o + iIii1I11I1II1 * OOooOOo + I1ii11iIi11i
   if 43 - 43: OoO0O00 . O0
 if ( ooooOo0ooo == None ) :
  lprint ( oooO0OoO . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( ooooOo0ooo )
  lprint ( oooO0OoO . format ( "Use previous" ) )
  if 36 - 36: I11i
  if 28 - 28: ooOoO0o
 I11IIoO0oOoOo0oO0O = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ iIIIi ] + I11IIoO0oOoOo0oO0O
 return ( True )
 if 41 - 41: OoO0O00 % Oo0Ooo
 if 60 - 60: OOooOOo . Ii1I
 if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
 if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
 if 38 - 38: IiII / I11i / IiII * iII111i
 if 30 - 30: oO0o
 if 30 - 30: IiII / OoO0O00
 if 89 - 89: oO0o . OoOoOO00 . IiII / iIii1I11I1II1 . iIii1I11I1II1 / OoOoOO00
def lisp_get_nat_info ( rloc , hostname ) :
 if ( hostname not in lisp_nat_state_info ) : return ( None )
 if 86 - 86: OoooooooOO - iIii1I11I1II1 . OoO0O00 * Ii1I / I1Ii111 + I1Ii111
 O0O0 = rloc . print_address_no_iid ( )
 for OOoOoO0O in lisp_nat_state_info [ hostname ] :
  if ( OOoOoO0O . address == O0O0 ) : return ( OOoOoO0O )
  if 52 - 52: iIii1I11I1II1 % OoO0O00 - IiII % i11iIiiIii - o0oOOo0O0Ooo
 return ( None )
 if 25 - 25: Oo0Ooo - OOooOOo . i1IIi * OoOoOO00 / I11i / o0oOOo0O0Ooo
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
 if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
 if 67 - 67: I1IiiI
 if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
 if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
 if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
 if 59 - 59: i11iIiiIii
 if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 59 - 59: I1ii11iIi11i
 if 47 - 47: I1IiiI + Oo0Ooo
 if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
 if 10 - 10: i1IIi % ooOoO0o / iII111i
 if 98 - 98: IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
 if 65 - 65: Ii1I + OoOoOO00 * Oo0Ooo . O0 . IiII
 IiiIII1IIiI1iii = [ ]
 i11IIio0O = [ ]
 if ( dest == None ) :
  for OOoOo0O0O0oO in list ( lisp_map_resolvers_list . values ( ) ) :
   i11IIio0O . append ( OOoOo0O0O0oO . map_resolver )
   if 76 - 76: I11i / Oo0Ooo
  IiiIII1IIiI1iii = i11IIio0O
  if ( IiiIII1IIiI1iii == [ ] ) :
   for I11i1IiIi1II1 in list ( lisp_map_servers_list . values ( ) ) :
    IiiIII1IIiI1iii . append ( I11i1IiIi1II1 . map_server )
    if 2 - 2: IiII . i11iIiiIii % Oo0Ooo
    if 75 - 75: IiII + OOooOOo
  if ( IiiIII1IIiI1iii == [ ] ) : return
 else :
  IiiIII1IIiI1iii . append ( dest )
  if 92 - 92: OoOoOO00
  if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
  if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
  if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
  if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
 II1Iii1Ii11I = { }
 for i11IIII1Ii in lisp_db_list :
  for OO0oooo in i11IIII1Ii . rloc_set :
   lisp_update_local_rloc ( OO0oooo )
   if ( OO0oooo . rloc . is_null ( ) ) : continue
   if ( OO0oooo . interface == None ) : continue
   if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
   IiI = OO0oooo . rloc . print_address_no_iid ( )
   if ( IiI in II1Iii1Ii11I ) : continue
   II1Iii1Ii11I [ IiI ] = OO0oooo . interface
   if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
   if 54 - 54: oO0o * II111iiii
 if ( II1Iii1Ii11I == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
  return
  if 98 - 98: ooOoO0o
  if 73 - 73: I1Ii111
  if 97 - 97: OoO0O00 * Ii1I + Oo0Ooo
  if 83 - 83: II111iiii - Oo0Ooo % II111iiii * o0oOOo0O0Ooo
  if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
  if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
 for IiI in II1Iii1Ii11I :
  i111IIiIiiI1 = II1Iii1Ii11I [ IiI ]
  OO0O00o0 = red ( IiI , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( OO0O00o0 ,
 i111IIiIiiI1 ) )
  ooO000OO = i111IIiIiiI1 if len ( II1Iii1Ii11I ) > 1 else None
  for dest in IiiIII1IIiI1iii :
   lisp_send_info_request ( lisp_sockets , dest , port , ooO000OO )
   if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
   if 76 - 76: iII111i * OOooOOo
   if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
   if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
   if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
   if 40 - 40: iII111i
 if ( i11IIio0O != [ ] ) :
  for OOoOo0O0O0oO in list ( lisp_map_resolvers_list . values ( ) ) :
   OOoOo0O0O0oO . resolve_dns_name ( )
   if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
   if 33 - 33: OoooooooOO
 return
 if 59 - 59: i11iIiiIii - OoooooooOO . ooOoO0o / i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i
 if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
 if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
 if 5 - 5: Oo0Ooo . I1Ii111
 if 77 - 77: i11iIiiIii / I1Ii111 / I1ii11iIi11i % oO0o
 if 83 - 83: Ii1I % iIii1I11I1II1 / I1ii11iIi11i + I11i
 if 23 - 23: iIii1I11I1II1 - I1IiiI
 if 51 - 51: OoooooooOO / IiII / I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * OoooooooOO
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 40 - 40: OoO0O00 / IiII . O0 / I1IiiI + OoO0O00 . o0oOOo0O0Ooo
 if 25 - 25: ooOoO0o * I1Ii111 * oO0o
 if 64 - 64: Ii1I / I1ii11iIi11i
 if 30 - 30: OoooooooOO + O0 / I1ii11iIi11i * o0oOOo0O0Ooo
 if 11 - 11: O0 + OoO0O00 - Oo0Ooo - Oo0Ooo . i11iIiiIii
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 15 - 15: Ii1I % i11iIiiIii / OoOoOO00
 if 85 - 85: ooOoO0o . i1IIi / iII111i % iIii1I11I1II1 / II111iiii / I1Ii111
 if 60 - 60: iIii1I11I1II1 - iIii1I11I1II1 . I11i
 if 55 - 55: OoO0O00
 if ( value . find ( "." ) != - 1 ) :
  IiI = value . split ( "." )
  if ( len ( IiI ) != 4 ) : return ( False )
  if 87 - 87: Ii1I - iII111i / O0 - o0oOOo0O0Ooo - iIii1I11I1II1 % Ii1I
  for oO000OO0 in IiI :
   if ( oO000OO0 . isdigit ( ) == False ) : return ( False )
   if ( int ( oO000OO0 ) > 255 ) : return ( False )
   if 47 - 47: iII111i * I1Ii111 % o0oOOo0O0Ooo / OoOoOO00 / OoO0O00 % OoO0O00
  return ( True )
  if 43 - 43: Oo0Ooo
  if 34 - 34: OoO0O00 . i1IIi + IiII * IiII
  if 76 - 76: OOooOOo
  if 54 - 54: O0 * II111iiii * OOooOOo
  if 44 - 44: I1IiiI
 if ( value . find ( "-" ) != - 1 ) :
  IiI = value . split ( "-" )
  for iIi1iIIIiIiI in [ "N" , "S" , "W" , "E" ] :
   if ( iIi1iIIIiIiI in IiI ) :
    if ( len ( IiI ) < 8 ) : return ( False )
    return ( True )
    if 66 - 66: o0oOOo0O0Ooo
    if 40 - 40: OOooOOo * Ii1I
    if 38 - 38: ooOoO0o
    if 5 - 5: OoooooooOO + iII111i - I11i
    if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
    if 7 - 7: I1ii11iIi11i
    if 37 - 37: O0 . II111iiii
 if ( value . find ( "-" ) != - 1 ) :
  IiI = value . split ( "-" )
  if ( len ( IiI ) != 3 ) : return ( False )
  if 70 - 70: o0oOOo0O0Ooo / iII111i + i1IIi + I11i % iIii1I11I1II1 % Oo0Ooo
  for IiiIIiI in IiI :
   try : int ( IiiIIiI , 16 )
   except : return ( False )
   if 92 - 92: IiII + I1ii11iIi11i . I1ii11iIi11i / O0
  return ( True )
  if 25 - 25: Ii1I + OoooooooOO
  if 64 - 64: O0 . Oo0Ooo
  if 59 - 59: Oo0Ooo
  if 74 - 74: I1ii11iIi11i * OoooooooOO . iII111i
  if 45 - 45: I1IiiI - IiII % ooOoO0o - IiII . Oo0Ooo - o0oOOo0O0Ooo
 if ( value . find ( ":" ) != - 1 ) :
  IiI = value . split ( ":" )
  if ( len ( IiI ) < 2 ) : return ( False )
  if 27 - 27: iII111i
  Ooo000oO0 = False
  O0oo0oOo = 0
  for IiiIIiI in IiI :
   O0oo0oOo += 1
   if ( IiiIIiI == "" ) :
    if ( Ooo000oO0 ) :
     if ( len ( IiI ) == O0oo0oOo ) : break
     if ( O0oo0oOo > 2 ) : return ( False )
     if 28 - 28: iIii1I11I1II1 * OoooooooOO
    Ooo000oO0 = True
    continue
    if 70 - 70: o0oOOo0O0Ooo % OoooooooOO % I1IiiI . OoOoOO00 * I1IiiI - ooOoO0o
   try : int ( IiiIIiI , 16 )
   except : return ( False )
   if 92 - 92: I1IiiI . I11i
  return ( True )
  if 66 - 66: I1Ii111 / I11i / OoooooooOO % OoOoOO00 . oO0o * iII111i
  if 34 - 34: I1ii11iIi11i * I1ii11iIi11i % I11i / OOooOOo % oO0o . OoOoOO00
  if 25 - 25: I1ii11iIi11i / I11i + i1IIi . I1IiiI + ooOoO0o
  if 29 - 29: IiII + I1ii11iIi11i
  if 8 - 8: IiII % I1IiiI
 if ( value [ 0 ] == "+" ) :
  IiI = value [ 1 : : ]
  for iiI1i in IiI :
   if ( iiI1i . isdigit ( ) == False ) : return ( False )
   if 49 - 49: I1IiiI
  return ( True )
  if 23 - 23: OoooooooOO . OoO0O00 . OoooooooOO * I1ii11iIi11i - Oo0Ooo - iIii1I11I1II1
 return ( False )
 if 91 - 91: iIii1I11I1II1 * Ii1I
 if 37 - 37: I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
 if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
 if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
 if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
 if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
 if 40 - 40: iII111i - I1IiiI + OoOoOO00
 if 2 - 2: I11i - II111iiii / I1Ii111
 if 27 - 27: OoO0O00 - I1ii11iIi11i * i11iIiiIii + Oo0Ooo
 if 29 - 29: I1ii11iIi11i / IiII . I1Ii111 + Ii1I + OoO0O00
 if 76 - 76: ooOoO0o . I11i * OoO0O00
 if 53 - 53: II111iiii / OoOoOO00 / IiII * oO0o
 if 52 - 52: O0 % iII111i * iIii1I11I1II1 / I11i / I1IiiI * ooOoO0o
def lisp_process_api ( process , lisp_socket , data_structure ) :
 Oo0Iii1II1iI , I1iII1IIi1IiI = data_structure . split ( "%" )
 if 42 - 42: I1ii11iIi11i - iIii1I11I1II1 % ooOoO0o
 lprint ( "Process API request '{}', parameters: '{}'" . format ( Oo0Iii1II1iI ,
 I1iII1IIi1IiI ) )
 if 7 - 7: Oo0Ooo / ooOoO0o + o0oOOo0O0Ooo
 oo0O000OooO0 = [ ]
 if ( Oo0Iii1II1iI == "map-cache" ) :
  if ( I1iII1IIi1IiI == "" ) :
   oo0O000OooO0 = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , oo0O000OooO0 )
  else :
   oo0O000OooO0 = lisp_process_api_map_cache_entry ( json . loads ( I1iII1IIi1IiI ) )
   if 38 - 38: o0oOOo0O0Ooo . O0 - OoO0O00 % I11i
   if 80 - 80: o0oOOo0O0Ooo
 if ( Oo0Iii1II1iI == "site-cache" ) :
  if ( I1iII1IIi1IiI == "" ) :
   oo0O000OooO0 = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 oo0O000OooO0 )
  else :
   oo0O000OooO0 = lisp_process_api_site_cache_entry ( json . loads ( I1iII1IIi1IiI ) )
   if 100 - 100: iIii1I11I1II1 . OoOoOO00 . OoooooooOO / I1ii11iIi11i - I1IiiI * I11i
   if 5 - 5: i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1IiiI - II111iiii
 if ( Oo0Iii1II1iI == "site-cache-summary" ) :
  oo0O000OooO0 = lisp_process_api_site_cache_summary ( lisp_sites_by_eid )
  if 15 - 15: I1Ii111
 if ( Oo0Iii1II1iI == "map-server" ) :
  I1iII1IIi1IiI = { } if ( I1iII1IIi1IiI == "" ) else json . loads ( I1iII1IIi1IiI )
  oo0O000OooO0 = lisp_process_api_ms_or_mr ( True , I1iII1IIi1IiI )
  if 38 - 38: O0
 if ( Oo0Iii1II1iI == "map-resolver" ) :
  I1iII1IIi1IiI = { } if ( I1iII1IIi1IiI == "" ) else json . loads ( I1iII1IIi1IiI )
  oo0O000OooO0 = lisp_process_api_ms_or_mr ( False , I1iII1IIi1IiI )
  if 50 - 50: i11iIiiIii * OoO0O00 + iII111i / O0 * oO0o % ooOoO0o
 if ( Oo0Iii1II1iI == "database-mapping" ) :
  oo0O000OooO0 = lisp_process_api_database_mapping ( )
  if 6 - 6: OoO0O00 . o0oOOo0O0Ooo / Ii1I + Ii1I
  if 59 - 59: II111iiii - o0oOOo0O0Ooo * OoooooooOO
  if 83 - 83: oO0o . iIii1I11I1II1 . iII111i % Oo0Ooo
  if 48 - 48: oO0o % OoO0O00 - OoooooooOO . IiII
  if 11 - 11: I1Ii111 % o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i
 oo0O000OooO0 = json . dumps ( oo0O000OooO0 )
 oOoo = lisp_api_ipc ( process , oo0O000OooO0 )
 lisp_ipc ( oOoo , lisp_socket , "lisp-core" )
 return
 if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
 if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
 if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
 if 47 - 47: OOooOOo + IiII
def lisp_process_api_map_cache ( mc , data ) :
 if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
 if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
 if 64 - 64: Ii1I
 if 4 - 4: OoOoOO00
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 48 - 48: iII111i / II111iiii * I1Ii111 + I11i / ooOoO0o . OoOoOO00
 if 45 - 45: OOooOOo / Ii1I % O0
 if 7 - 7: oO0o * i11iIiiIii + OoooooooOO + I11i
 if 9 - 9: II111iiii * Oo0Ooo * I1Ii111 . IiII
 if 80 - 80: i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - OOooOOo * OoooooooOO
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 96 - 96: oO0o
 if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
 if 64 - 64: I1IiiI % i11iIiiIii / oO0o
 if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
 if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
 if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
 if 31 - 31: OoO0O00
def lisp_gather_map_cache_data ( mc , data ) :
 oo0O00OOOOO = { }
 oo0O00OOOOO [ "instance-id" ] = str ( mc . eid . instance_id )
 oo0O00OOOOO [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  oo0O00OOOOO [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 89 - 89: II111iiii
 oo0O00OOOOO [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 oo0O00OOOOO [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 oo0O00OOOOO [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 oo0O00OOOOO [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 33 - 33: OOooOOo / oO0o % OoOoOO00 * O0
 if 65 - 65: OoO0O00 % OoOoOO00 % I1ii11iIi11i / OoooooooOO
 if 85 - 85: O0 * OOooOOo % I1Ii111
 if 33 - 33: O0
 if 30 - 30: II111iiii . O0 . oO0o * I1ii11iIi11i + oO0o . o0oOOo0O0Ooo
 OOOo0O00OO00O = [ ]
 for I1Ii1i111I in mc . rloc_set :
  O00o00o00OO0 = lisp_fill_rloc_in_json ( I1Ii1i111I )
  if 43 - 43: iIii1I11I1II1
  if 88 - 88: I1IiiI - OoO0O00 . O0 . oO0o
  if 75 - 75: II111iiii % OOooOOo / iIii1I11I1II1 / OoO0O00 + oO0o
  if 16 - 16: oO0o + I1Ii111 - II111iiii - o0oOOo0O0Ooo / i11iIiiIii
  if 59 - 59: OOooOOo - o0oOOo0O0Ooo
  if ( I1Ii1i111I . rloc . is_multicast_address ( ) ) :
   O00o00o00OO0 [ "multicast-rloc-set" ] = [ ]
   for ii111IiiIii in list ( I1Ii1i111I . multicast_rloc_probe_list . values ( ) ) :
    OOoOo0O0O0oO = lisp_fill_rloc_in_json ( ii111IiiIii )
    O00o00o00OO0 [ "multicast-rloc-set" ] . append ( OOoOo0O0O0oO )
    if 82 - 82: IiII % ooOoO0o - OoO0O00 % ooOoO0o
    if 51 - 51: ooOoO0o % iII111i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
    if 20 - 20: i1IIi - ooOoO0o % OoooooooOO * I1ii11iIi11i + II111iiii % i1IIi
  OOOo0O00OO00O . append ( O00o00o00OO0 )
  if 30 - 30: i11iIiiIii - I1IiiI + o0oOOo0O0Ooo + IiII
 oo0O00OOOOO [ "rloc-set" ] = OOOo0O00OO00O
 if 16 - 16: I1ii11iIi11i / Ii1I + I1ii11iIi11i * I1Ii111
 data . append ( oo0O00OOOOO )
 return ( [ True , data ] )
 if 49 - 49: ooOoO0o * OoOoOO00 . OoooooooOO . ooOoO0o + Oo0Ooo * IiII
 if 47 - 47: iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
 if 84 - 84: o0oOOo0O0Ooo * I11i
 if 22 - 22: i1IIi + OOooOOo % OoooooooOO
 if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
 if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
 if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
 if 66 - 66: OoooooooOO
def lisp_fill_rloc_in_json ( rloc ) :
 O00o00o00OO0 = { }
 O0O0 = None
 if ( rloc . rloc_exists ( ) ) :
  O00o00o00OO0 [ "address" ] = rloc . rloc . print_address_no_iid ( )
  O0O0 = O00o00o00OO0 [ "address" ]
  if 90 - 90: IiII - OoOoOO00
  if 98 - 98: Oo0Ooo / oO0o . Ii1I
 if ( rloc . translated_port != 0 ) :
  O00o00o00OO0 [ "encap-port" ] = str ( rloc . translated_port )
  O0O0 += ":" + O00o00o00OO0 [ "encap-port" ]
  if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
  if 37 - 37: iII111i - Ii1I . oO0o
 if ( O0O0 and O0O0 in lisp_crypto_keys_by_rloc_encap ) :
  Ooo00o000o = lisp_crypto_keys_by_rloc_encap [ O0O0 ] [ 1 ]
  if ( Ooo00o000o != None and Ooo00o000o . shared_key != None ) :
   O00o00o00OO0 [ "encap-crypto" ] = "crypto-" + Ooo00o000o . cipher_suite_string
   if 47 - 47: IiII / I1ii11iIi11i . o0oOOo0O0Ooo . ooOoO0o + OOooOOo . OOooOOo
   if 25 - 25: oO0o
   if 43 - 43: Ii1I - o0oOOo0O0Ooo % oO0o - O0
 O00o00o00OO0 [ "state" ] = rloc . print_state ( )
 if ( rloc . geo ) : O00o00o00OO0 [ "geo" ] = rloc . geo . print_geo ( )
 if ( rloc . elp ) : O00o00o00OO0 [ "elp" ] = rloc . elp . print_elp ( False )
 if ( rloc . rle ) : O00o00o00OO0 [ "rle" ] = rloc . rle . print_rle ( False , False )
 if ( rloc . json ) : O00o00o00OO0 [ "json" ] = rloc . json . print_json ( False )
 if ( rloc . rloc_name ) : O00o00o00OO0 [ "rloc-name" ] = rloc . rloc_name
 ooo0oOooOO0o0 = rloc . stats . get_stats ( False , False )
 if ( ooo0oOooOO0o0 ) : O00o00o00OO0 [ "stats" ] = ooo0oOooOO0o0
 O00o00o00OO0 [ "uptime" ] = lisp_print_elapsed ( rloc . uptime )
 O00o00o00OO0 [ "upriority" ] = str ( rloc . priority )
 O00o00o00OO0 [ "uweight" ] = str ( rloc . weight )
 O00o00o00OO0 [ "mpriority" ] = str ( rloc . mpriority )
 O00o00o00OO0 [ "mweight" ] = str ( rloc . mweight )
 IIi = rloc . last_rloc_probe_reply
 if ( IIi ) :
  O00o00o00OO0 [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( IIi )
  O00o00o00OO0 [ "rloc-probe-rtt" ] = str ( rloc . rloc_probe_rtt )
  if 98 - 98: OoooooooOO + i1IIi + OOooOOo * Oo0Ooo
 O00o00o00OO0 [ "rloc-hop-count" ] = rloc . rloc_probe_hops
 O00o00o00OO0 [ "recent-rloc-hop-counts" ] = rloc . recent_rloc_probe_hops
 if 22 - 22: ooOoO0o . ooOoO0o % i1IIi * II111iiii * IiII
 O00o00o00OO0 [ "rloc-probe-latency" ] = rloc . rloc_probe_latency
 O00o00o00OO0 [ "recent-rloc-probe-latencies" ] = rloc . recent_rloc_probe_latencies
 if 6 - 6: II111iiii . iII111i % I1ii11iIi11i + IiII / I11i
 i1II1I1II11I = [ ]
 for ii1111Ii in rloc . recent_rloc_probe_rtts : i1II1I1II11I . append ( str ( ii1111Ii ) )
 O00o00o00OO0 [ "recent-rloc-probe-rtts" ] = i1II1I1II11I
 return ( O00o00o00OO0 )
 if 43 - 43: iII111i . I1Ii111 . OOooOOo
 if 89 - 89: OoOoOO00 % O0
 if 7 - 7: O0 % oO0o
 if 57 - 57: i1IIi . OOooOOo
 if 72 - 72: ooOoO0o / I1IiiI - ooOoO0o * OoO0O00 . OOooOOo
 if 1 - 1: o0oOOo0O0Ooo + I1Ii111 + OoO0O00 * OOooOOo / I1Ii111 % i11iIiiIii
 if 49 - 49: OOooOOo - oO0o
def lisp_process_api_map_cache_entry ( parms ) :
 oooo = parms [ "instance-id" ]
 oooo = 0 if ( oooo == "" ) else int ( oooo )
 if 73 - 73: o0oOOo0O0Ooo . I1IiiI - I11i . ooOoO0o % II111iiii . OoooooooOO
 if 8 - 8: OoooooooOO
 if 92 - 92: ooOoO0o + IiII * II111iiii
 if 41 - 41: I1IiiI + OoOoOO00 . OOooOOo
 i1I1I1IIIi11 = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
 i1I1I1IIIi11 . store_prefix ( parms [ "eid-prefix" ] )
 I1i1iiIi = i1I1I1IIIi11
 I1 = i1I1I1IIIi11
 if 57 - 57: II111iiii . iIii1I11I1II1
 if 32 - 32: o0oOOo0O0Ooo
 if 75 - 75: I1IiiI . II111iiii - iII111i % IiII * OoO0O00 % ooOoO0o
 if 38 - 38: I1IiiI / OoooooooOO
 if 16 - 16: i1IIi . i11iIiiIii . oO0o - I11i
 o0o0Oo0o0oOo = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
 if ( "group-prefix" in parms ) :
  o0o0Oo0o0oOo . store_prefix ( parms [ "group-prefix" ] )
  I1i1iiIi = o0o0Oo0o0oOo
  if 96 - 96: iII111i - OoOoOO00
  if 43 - 43: OoO0O00 - I1Ii111 % OoooooooOO % I1ii11iIi11i . OoOoOO00
 oo0O000OooO0 = [ ]
 o0ooo0oOO0o = lisp_map_cache_lookup ( I1 , I1i1iiIi )
 if ( o0ooo0oOO0o ) : IIIiIii111iii , oo0O000OooO0 = lisp_process_api_map_cache ( o0ooo0oOO0o , oo0O000OooO0 )
 return ( oo0O000OooO0 )
 if 87 - 87: OOooOOo
 if 60 - 60: ooOoO0o * o0oOOo0O0Ooo . OoO0O00 * iII111i * oO0o * i1IIi
 if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
 if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
 if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
 if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
 if 76 - 76: OoO0O00
 if 92 - 92: iIii1I11I1II1 * O0 % I11i
 if 92 - 92: OoOoOO00 + oO0o
 if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
def lisp_process_api_site_cache_summary ( site_cache ) :
 iiI = { "site" : "" , "registrations" : [ ] }
 oo0O00OOOOO = { "eid-prefix" : "" , "count" : 0 , "registered-count" : 0 }
 if 28 - 28: I1IiiI . iIii1I11I1II1
 i1IiI1i1i1iII = { }
 for iiiO0OO00o00Oo in site_cache . cache_sorted :
  for Oo0OO0o00OO in list ( site_cache . cache [ iiiO0OO00o00Oo ] . entries . values ( ) ) :
   if ( Oo0OO0o00OO . accept_more_specifics == False ) : continue
   if ( Oo0OO0o00OO . site . site_name not in i1IiI1i1i1iII ) :
    i1IiI1i1i1iII [ Oo0OO0o00OO . site . site_name ] = [ ]
    if 33 - 33: oO0o / I11i % ooOoO0o * I11i / oO0o - OoOoOO00
   oO0ooOOO = copy . deepcopy ( oo0O00OOOOO )
   oO0ooOOO [ "eid-prefix" ] = Oo0OO0o00OO . eid . print_prefix ( )
   oO0ooOOO [ "count" ] = len ( Oo0OO0o00OO . more_specific_registrations )
   for ooOII in Oo0OO0o00OO . more_specific_registrations :
    if ( ooOII . registered ) : oO0ooOOO [ "registered-count" ] += 1
    if 18 - 18: II111iiii / oO0o / o0oOOo0O0Ooo + I11i
   i1IiI1i1i1iII [ Oo0OO0o00OO . site . site_name ] . append ( oO0ooOOO )
   if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
   if 67 - 67: I1IiiI
   if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
 oo0O000OooO0 = [ ]
 for Ii1oOOooo0 in i1IiI1i1i1iII :
  I111 = copy . deepcopy ( iiI )
  I111 [ "site" ] = Ii1oOOooo0
  I111 [ "registrations" ] = i1IiI1i1i1iII [ Ii1oOOooo0 ]
  oo0O000OooO0 . append ( I111 )
  if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
 return ( oo0O000OooO0 )
 if 33 - 33: OOooOOo - OoooooooOO . iII111i
 if 2 - 2: I11i + i1IIi
 if 52 - 52: I11i - OoO0O00 % I1Ii111 . OOooOOo
 if 90 - 90: O0 - Oo0Ooo / i1IIi * iIii1I11I1II1 % o0oOOo0O0Ooo / oO0o
 if 73 - 73: iII111i % iIii1I11I1II1 + o0oOOo0O0Ooo % Ii1I . II111iiii + IiII
 if 55 - 55: OoOoOO00 * II111iiii / iII111i + OOooOOo / OoooooooOO
 if 12 - 12: II111iiii * O0 - Oo0Ooo + o0oOOo0O0Ooo . Oo0Ooo + iIii1I11I1II1
def lisp_process_api_site_cache ( se , data ) :
 if 4 - 4: I1Ii111 - I1Ii111 / I1ii11iIi11i . i1IIi + I1ii11iIi11i / oO0o
 if 18 - 18: iIii1I11I1II1 . ooOoO0o
 if 68 - 68: o0oOOo0O0Ooo
 if 36 - 36: Oo0Ooo . I11i + I1IiiI * i1IIi % Ii1I + OOooOOo
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 5 - 5: o0oOOo0O0Ooo % oO0o / OoO0O00
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 17 - 17: OoooooooOO - I1ii11iIi11i / OoO0O00 - I1Ii111 + i1IIi
 if 6 - 6: Oo0Ooo - II111iiii
 if 33 - 33: I1Ii111 - I1IiiI + iII111i . OoOoOO00
 if 91 - 91: OOooOOo / Ii1I / IiII * OOooOOo
 if 68 - 68: I11i
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 91 - 91: I11i
 if 24 - 24: ooOoO0o . i1IIi - O0 + I11i
 if 71 - 71: OoOoOO00
 if 29 - 29: O0 . i11iIiiIii
 if 51 - 51: IiII
 if 53 - 53: O0
 if 19 - 19: o0oOOo0O0Ooo / iII111i % OoOoOO00
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 I1IIIi = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 ooO0000 = data [ "dns-name" ] if ( "dns-name" in data ) else None
 if ( "address" in data ) :
  I1IIIi . store_address ( data [ "address" ] )
  if 65 - 65: o0oOOo0O0Ooo
  if 89 - 89: iIii1I11I1II1 + OoooooooOO + i1IIi + OoooooooOO % IiII * OoO0O00
 oOO0 = { }
 if ( ms_or_mr ) :
  for I11i1IiIi1II1 in list ( lisp_map_servers_list . values ( ) ) :
   if ( ooO0000 ) :
    if ( ooO0000 != I11i1IiIi1II1 . dns_name ) : continue
   else :
    if ( I1IIIi . is_exact_match ( I11i1IiIi1II1 . map_server ) == False ) : continue
    if 53 - 53: OOooOOo . IiII % I11i - OoO0O00 - Oo0Ooo
    if 58 - 58: I1Ii111 / OoooooooOO . I11i % I1Ii111
   oOO0 [ "dns-name" ] = I11i1IiIi1II1 . dns_name
   oOO0 [ "address" ] = I11i1IiIi1II1 . map_server . print_address_no_iid ( )
   oOO0 [ "ms-name" ] = "" if I11i1IiIi1II1 . ms_name == None else I11i1IiIi1II1 . ms_name
   return ( [ oOO0 ] )
   if 8 - 8: Oo0Ooo % ooOoO0o / i11iIiiIii
 else :
  for OOoOo0O0O0oO in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( ooO0000 ) :
    if ( ooO0000 != OOoOo0O0O0oO . dns_name ) : continue
   else :
    if ( I1IIIi . is_exact_match ( OOoOo0O0O0oO . map_resolver ) == False ) : continue
    if 54 - 54: IiII
    if 85 - 85: OOooOOo - i1IIi
   oOO0 [ "dns-name" ] = OOoOo0O0O0oO . dns_name
   oOO0 [ "address" ] = OOoOo0O0O0oO . map_resolver . print_address_no_iid ( )
   oOO0 [ "mr-name" ] = "" if OOoOo0O0O0oO . mr_name == None else OOoOo0O0O0oO . mr_name
   return ( [ oOO0 ] )
   if 10 - 10: I1ii11iIi11i
   if 3 - 3: ooOoO0o * O0 / o0oOOo0O0Ooo
 return ( [ ] )
 if 22 - 22: OoOoOO00 + OOooOOo . iII111i % iIii1I11I1II1 - I11i
 if 23 - 23: OoOoOO00 * I1Ii111
 if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
 if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
 if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
 if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
 if 25 - 25: OoO0O00 * oO0o
 if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
def lisp_process_api_database_mapping ( ) :
 oo0O000OooO0 = [ ]
 if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
 for i11IIII1Ii in lisp_db_list :
  oo0O00OOOOO = { }
  oo0O00OOOOO [ "eid-prefix" ] = i11IIII1Ii . eid . print_prefix ( )
  if ( i11IIII1Ii . group . is_null ( ) == False ) :
   oo0O00OOOOO [ "group-prefix" ] = i11IIII1Ii . group . print_prefix ( )
   if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
   if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
  OOOO00 = [ ]
  for O00o00o00OO0 in i11IIII1Ii . rloc_set :
   I1Ii1i111I = { }
   if ( O00o00o00OO0 . rloc . is_null ( ) == False ) :
    I1Ii1i111I [ "rloc" ] = O00o00o00OO0 . rloc . print_address_no_iid ( )
    if 73 - 73: Oo0Ooo + II111iiii - IiII
   if ( O00o00o00OO0 . rloc_name != None ) : I1Ii1i111I [ "rloc-name" ] = O00o00o00OO0 . rloc_name
   if ( O00o00o00OO0 . interface != None ) : I1Ii1i111I [ "interface" ] = O00o00o00OO0 . interface
   Ooii1 = O00o00o00OO0 . translated_rloc
   if ( Ooii1 . is_null ( ) == False ) :
    I1Ii1i111I [ "translated-rloc" ] = Ooii1 . print_address_no_iid ( )
    if 72 - 72: ooOoO0o + oO0o + IiII * I1Ii111 % oO0o
   if ( I1Ii1i111I != { } ) : OOOO00 . append ( I1Ii1i111I )
   if 55 - 55: IiII . ooOoO0o - II111iiii * I1IiiI . I1Ii111
   if 39 - 39: iIii1I11I1II1 . II111iiii + oO0o . iII111i + Ii1I
   if 91 - 91: Ii1I + I1Ii111
   if 7 - 7: ooOoO0o + I1ii11iIi11i % OoO0O00
   if 45 - 45: i1IIi / o0oOOo0O0Ooo / iII111i * OoOoOO00 . IiII
  oo0O00OOOOO [ "rlocs" ] = OOOO00
  if 60 - 60: o0oOOo0O0Ooo
  if 63 - 63: i11iIiiIii * Oo0Ooo * I1Ii111
  if 56 - 56: I1Ii111 . i11iIiiIii
  if 76 - 76: II111iiii / ooOoO0o * i11iIiiIii . O0 / O0 - i11iIiiIii
  oo0O000OooO0 . append ( oo0O00OOOOO )
  if 89 - 89: o0oOOo0O0Ooo . I1Ii111 * I11i + oO0o - OoooooooOO + OoO0O00
 return ( oo0O000OooO0 )
 if 25 - 25: i1IIi * I1Ii111 * iII111i . OoooooooOO
 if 70 - 70: iIii1I11I1II1
 if 1 - 1: II111iiii . I1IiiI + o0oOOo0O0Ooo
 if 5 - 5: I1ii11iIi11i % I11i - II111iiii
 if 70 - 70: ooOoO0o - IiII - OoO0O00 / I11i
 if 59 - 59: IiII % ooOoO0o . iII111i / Ii1I * Ii1I
 if 73 - 73: I1ii11iIi11i . oO0o % I11i . I1ii11iIi11i / I1Ii111 / II111iiii
def lisp_gather_site_cache_data ( se , data ) :
 oo0O00OOOOO = { }
 oo0O00OOOOO [ "site-name" ] = se . site . site_name
 oo0O00OOOOO [ "instance-id" ] = str ( se . eid . instance_id )
 oo0O00OOOOO [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  oo0O00OOOOO [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
 oo0O00OOOOO [ "registered" ] = "yes" if se . registered else "no"
 oo0O00OOOOO [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 oo0O00OOOOO [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 76 - 76: I1Ii111
 IiI = se . last_registerer
 IiI = "none" if IiI . is_null ( ) else IiI . print_address ( )
 oo0O00OOOOO [ "last-registerer" ] = IiI
 oo0O00OOOOO [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 oo0O00OOOOO [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 oo0O00OOOOO [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  oo0O00OOOOO [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 91 - 91: iIii1I11I1II1 / Ii1I . I1IiiI
  if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
  if 85 - 85: II111iiii + I1ii11iIi11i
  if 33 - 33: iII111i
  if 14 - 14: O0 * Oo0Ooo / i1IIi
 OOOo0O00OO00O = [ ]
 for I1Ii1i111I in se . registered_rlocs :
  O00o00o00OO0 = { }
  O00o00o00OO0 [ "address" ] = I1Ii1i111I . rloc . print_address_no_iid ( ) if I1Ii1i111I . rloc_exists ( ) else "none"
  if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
  if 78 - 78: II111iiii % OOooOOo
  if ( I1Ii1i111I . geo ) : O00o00o00OO0 [ "geo" ] = I1Ii1i111I . geo . print_geo ( )
  if ( I1Ii1i111I . elp ) : O00o00o00OO0 [ "elp" ] = I1Ii1i111I . elp . print_elp ( False )
  if ( I1Ii1i111I . rle ) : O00o00o00OO0 [ "rle" ] = I1Ii1i111I . rle . print_rle ( False , True )
  if ( I1Ii1i111I . json ) : O00o00o00OO0 [ "json" ] = I1Ii1i111I . json . print_json ( False )
  if ( I1Ii1i111I . rloc_name ) : O00o00o00OO0 [ "rloc-name" ] = I1Ii1i111I . rloc_name
  O00o00o00OO0 [ "uptime" ] = lisp_print_elapsed ( I1Ii1i111I . uptime )
  O00o00o00OO0 [ "upriority" ] = str ( I1Ii1i111I . priority )
  O00o00o00OO0 [ "uweight" ] = str ( I1Ii1i111I . weight )
  O00o00o00OO0 [ "mpriority" ] = str ( I1Ii1i111I . mpriority )
  O00o00o00OO0 [ "mweight" ] = str ( I1Ii1i111I . mweight )
  if 6 - 6: OOooOOo
  OOOo0O00OO00O . append ( O00o00o00OO0 )
  if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
 oo0O00OOOOO [ "registered-rlocs" ] = OOOo0O00OO00O
 if 55 - 55: OOooOOo + oO0o - II111iiii
 data . append ( oo0O00OOOOO )
 return ( [ True , data ] )
 if 5 - 5: iII111i * OoooooooOO . OoO0O00 % ooOoO0o + Ii1I
 if 59 - 59: OoOoOO00
 if 96 - 96: I1IiiI
 if 3 - 3: OoooooooOO
 if 3 - 3: IiII / O0 * i11iIiiIii . iII111i - iIii1I11I1II1
 if 56 - 56: ooOoO0o
 if 82 - 82: ooOoO0o . IiII . I1Ii111 - iIii1I11I1II1 + II111iiii . OoOoOO00
def lisp_process_api_site_cache_entry ( parms ) :
 oooo = parms [ "instance-id" ]
 oooo = 0 if ( oooo == "" ) else int ( oooo )
 if 59 - 59: Oo0Ooo
 if 98 - 98: I1Ii111 * II111iiii / Oo0Ooo . Oo0Ooo % I1Ii111
 if 52 - 52: OoOoOO00
 if 59 - 59: ooOoO0o / OoooooooOO
 i1I1I1IIIi11 = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
 i1I1I1IIIi11 . store_prefix ( parms [ "eid-prefix" ] )
 if 71 - 71: OOooOOo + I11i * O0 / o0oOOo0O0Ooo + I1IiiI + Ii1I
 if 41 - 41: ooOoO0o * I1Ii111
 if 40 - 40: OoOoOO00
 if 60 - 60: IiII . i11iIiiIii * II111iiii . Ii1I
 if 10 - 10: O0
 o0o0Oo0o0oOo = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
 if ( "group-prefix" in parms ) :
  o0o0Oo0o0oOo . store_prefix ( parms [ "group-prefix" ] )
  if 65 - 65: I11i % i11iIiiIii + i11iIiiIii % II111iiii
  if 95 - 95: I1Ii111 - I11i . II111iiii . i1IIi / II111iiii + Oo0Ooo
 oo0O000OooO0 = [ ]
 Oo0OO0o00OO = lisp_site_eid_lookup ( i1I1I1IIIi11 , o0o0Oo0o0oOo , False )
 if ( Oo0OO0o00OO ) : lisp_gather_site_cache_data ( Oo0OO0o00OO , oo0O000OooO0 )
 return ( oo0O000OooO0 )
 if 96 - 96: iIii1I11I1II1 * iII111i / OOooOOo * iIii1I11I1II1 - O0
 if 28 - 28: I11i / I1IiiI - I1Ii111 + I1ii11iIi11i % iIii1I11I1II1
 if 35 - 35: iIii1I11I1II1 % Oo0Ooo % iII111i / iIii1I11I1II1 - I1ii11iIi11i . Oo0Ooo
 if 81 - 81: II111iiii + oO0o
 if 67 - 67: ooOoO0o + I11i - I1ii11iIi11i - OoooooooOO
 if 37 - 37: I11i % I1IiiI
 if 32 - 32: OOooOOo + OoooooooOO . IiII . Oo0Ooo * iII111i
def lisp_get_interface_instance_id ( device , source_eid ) :
 i111IIiIiiI1 = None
 if ( device in lisp_myinterfaces ) :
  i111IIiIiiI1 = lisp_myinterfaces [ device ]
  if 86 - 86: I1ii11iIi11i . iII111i + Ii1I - IiII / i11iIiiIii + OoOoOO00
  if 50 - 50: o0oOOo0O0Ooo - IiII + OoOoOO00 - II111iiii
  if 24 - 24: I1Ii111 - IiII % I1IiiI - OoooooooOO % Ii1I
  if 56 - 56: I1ii11iIi11i
  if 40 - 40: OoooooooOO
  if 100 - 100: IiII - I11i
 if ( i111IIiIiiI1 == None or i111IIiIiiI1 . instance_id == None ) :
  return ( lisp_default_iid )
  if 79 - 79: iII111i % O0
  if 73 - 73: Oo0Ooo
  if 13 - 13: OOooOOo - ooOoO0o
  if 8 - 8: I1Ii111 % oO0o
  if 19 - 19: O0 + OoO0O00 - i1IIi % OoOoOO00 / Oo0Ooo + OoooooooOO
  if 93 - 93: i11iIiiIii % OOooOOo . I11i * ooOoO0o
  if 90 - 90: OoO0O00
  if 54 - 54: OOooOOo + Oo0Ooo * o0oOOo0O0Ooo - iIii1I11I1II1 * ooOoO0o
  if 76 - 76: i11iIiiIii * I1IiiI - IiII . o0oOOo0O0Ooo % iII111i . i11iIiiIii
 oooo = i111IIiIiiI1 . get_instance_id ( )
 if ( source_eid == None ) : return ( oooo )
 if 69 - 69: O0 + o0oOOo0O0Ooo / ooOoO0o
 I1io00 = source_eid . instance_id
 OoO0ooOOo0o0 = None
 for i111IIiIiiI1 in lisp_multi_tenant_interfaces :
  if ( i111IIiIiiI1 . device != device ) : continue
  I1I11I1IIi = i111IIiIiiI1 . multi_tenant_eid
  source_eid . instance_id = I1I11I1IIi . instance_id
  if ( source_eid . is_more_specific ( I1I11I1IIi ) == False ) : continue
  if ( OoO0ooOOo0o0 == None or OoO0ooOOo0o0 . multi_tenant_eid . mask_len < I1I11I1IIi . mask_len ) :
   OoO0ooOOo0o0 = i111IIiIiiI1
   if 8 - 8: OoO0O00
   if 39 - 39: OoO0O00 * I11i . OoOoOO00
 source_eid . instance_id = I1io00
 if 53 - 53: Oo0Ooo
 if ( OoO0ooOOo0o0 == None ) : return ( oooo )
 return ( OoO0ooOOo0o0 . get_instance_id ( ) )
 if 28 - 28: ooOoO0o + Oo0Ooo % I1IiiI - ooOoO0o / iII111i - I1IiiI
 if 76 - 76: I1IiiI + O0
 if 4 - 4: I1IiiI - OOooOOo * I1Ii111
 if 26 - 26: Oo0Ooo % ooOoO0o / i11iIiiIii * Oo0Ooo / oO0o
 if 87 - 87: Ii1I
 if 21 - 21: iII111i
 if 38 - 38: OOooOOo % Ii1I - O0 / I1ii11iIi11i
 if 20 - 20: o0oOOo0O0Ooo + II111iiii * Ii1I . OoooooooOO
 if 88 - 88: O0 + iIii1I11I1II1 . o0oOOo0O0Ooo . iIii1I11I1II1 - Ii1I
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( device not in lisp_myinterfaces ) : return ( None )
 if 74 - 74: Ii1I . IiII
 i111IIiIiiI1 = lisp_myinterfaces [ device ]
 oooOoooOO = device if i111IIiIiiI1 . dynamic_eid_device == None else i111IIiIiiI1 . dynamic_eid_device
 if 12 - 12: I1IiiI
 if 50 - 50: ooOoO0o
 if ( i111IIiIiiI1 . does_dynamic_eid_match ( eid ) ) : return ( oooOoooOO )
 return ( None )
 if 19 - 19: OoooooooOO / IiII
 if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
 if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
 if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
 if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
 if 51 - 51: OoO0O00 - OoO0O00 * IiII
 if 24 - 24: OoooooooOO . II111iiii
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 97 - 97: II111iiii . O0
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 18 - 18: iII111i
 I1iioo0oOo0 = lisp_process_rloc_probe_timer
 Oooo0 = threading . Timer ( interval , I1iioo0oOo0 , [ lisp_sockets ] )
 lisp_rloc_probe_timer = Oooo0
 Oooo0 . start ( )
 return
 if 80 - 80: Oo0Ooo * i1IIi / OoO0O00 . o0oOOo0O0Ooo
 if 15 - 15: OoooooooOO
 if 48 - 48: oO0o * Oo0Ooo + i11iIiiIii
 if 52 - 52: i11iIiiIii / I1IiiI * i1IIi - I1Ii111
 if 29 - 29: iII111i * i11iIiiIii % OoOoOO00 * ooOoO0o
 if 41 - 41: iIii1I11I1II1
 if 52 - 52: ooOoO0o - O0 * OoO0O00 / oO0o
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for Ooo00o000o in lisp_rloc_probe_list :
  I1IIiiI11 = lisp_rloc_probe_list [ Ooo00o000o ]
  lprint ( "RLOC {}:" . format ( Ooo00o000o ) )
  for O00o00o00OO0 , oO0ooOOO , Oo in I1IIiiI11 :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( O00o00o00OO0 ) ) , oO0ooOOO . print_prefix ( ) ,
 Oo . print_prefix ( ) , O00o00o00OO0 . translated_port ) )
   if 4 - 4: IiII * iIii1I11I1II1 . I11i + OOooOOo / II111iiii
   if 2 - 2: i11iIiiIii - OoO0O00 / I1Ii111 . II111iiii % Ii1I / iII111i
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 13 - 13: I11i + iII111i
 if 54 - 54: I1ii11iIi11i - I1IiiI . Ii1I
 if 59 - 59: Oo0Ooo + I1ii11iIi11i
 if 87 - 87: ooOoO0o * OoooooooOO + OoO0O00 + oO0o - I1Ii111
 if 70 - 70: i1IIi . Ii1I / Ii1I
 if 9 - 9: iII111i + I1Ii111 + iII111i % ooOoO0o + i11iIiiIii + i11iIiiIii
 if 45 - 45: i1IIi + I1ii11iIi11i
 if 49 - 49: i11iIiiIii . I1ii11iIi11i
 if 91 - 91: ooOoO0o - OOooOOo - OOooOOo * o0oOOo0O0Ooo
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 33 - 33: II111iiii
 if 39 - 39: ooOoO0o + I11i
 if 24 - 24: o0oOOo0O0Ooo
 if 5 - 5: i11iIiiIii - oO0o + o0oOOo0O0Ooo % ooOoO0o
 I1Ii1i111I , oO0ooOOO , Oo = eid_list [ 0 ]
 ooOo0Oo0o = [ lisp_print_eid_tuple ( oO0ooOOO , Oo ) ]
 if 76 - 76: Ii1I / oO0o . I1Ii111
 for I1Ii1i111I , oO0ooOOO , Oo in eid_list [ 1 : : ] :
  I1Ii1i111I . state = LISP_RLOC_UNREACH_STATE
  I1Ii1i111I . last_state_change = lisp_get_timestamp ( )
  ooOo0Oo0o . append ( lisp_print_eid_tuple ( oO0ooOOO , Oo ) )
  if 94 - 94: o0oOOo0O0Ooo - OoOoOO00 / I1Ii111
  if 99 - 99: O0 % oO0o % OOooOOo - Oo0Ooo
 II1iIi1ii1IIi = bold ( "unreachable" , False )
 IIi11IiiiI11i = red ( I1Ii1i111I . rloc . print_address_no_iid ( ) , False )
 if 82 - 82: iII111i + OoooooooOO % iIii1I11I1II1 - o0oOOo0O0Ooo - i1IIi / Oo0Ooo
 for i1I1I1IIIi11 in ooOo0Oo0o :
  oO0ooOOO = green ( i1I1I1IIIi11 , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( IIi11IiiiI11i , II1iIi1ii1IIi , oO0ooOOO ) )
  if 13 - 13: iII111i % oO0o - I11i . i11iIiiIii / iIii1I11I1II1
  if 11 - 11: iII111i % OoO0O00 % iIii1I11I1II1 + IiII * Ii1I
  if 93 - 93: OOooOOo / iII111i
  if 74 - 74: I1ii11iIi11i
  if 83 - 83: iII111i + i1IIi - OoooooooOO
  if 16 - 16: i1IIi
 for I1Ii1i111I , oO0ooOOO , Oo in eid_list :
  o0ooo0oOO0o = lisp_map_cache . lookup_cache ( oO0ooOOO , True )
  if ( o0ooo0oOO0o ) : lisp_write_ipc_map_cache ( True , o0ooo0oOO0o )
  if 86 - 86: OoOoOO00 - iII111i - Oo0Ooo
 return
 if 33 - 33: Ii1I - OoO0O00
 if 15 - 15: O0 . iIii1I11I1II1 - I1Ii111 + O0 + ooOoO0o / I1IiiI
 if 8 - 8: iII111i % O0 - OoOoOO00
 if 49 - 49: oO0o - OOooOOo / Ii1I / I1Ii111 . o0oOOo0O0Ooo . iII111i
 if 58 - 58: IiII + Ii1I
 if 89 - 89: Ii1I / Oo0Ooo * o0oOOo0O0Ooo / OoO0O00 + I11i
 if 4 - 4: I11i
 if 59 - 59: OoOoOO00 * I1ii11iIi11i / I1IiiI * II111iiii + OoOoOO00
 if 6 - 6: OoOoOO00 % oO0o + I11i * Ii1I
 if 13 - 13: I1ii11iIi11i / Oo0Ooo - I1Ii111 * OoOoOO00
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 47 - 47: IiII
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 76 - 76: iII111i / II111iiii / I11i
 if 62 - 62: I1ii11iIi11i
 if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
 if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
 if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
 if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
 if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
 o000oo = lisp_get_default_route_next_hops ( )
 if 79 - 79: i1IIi . iII111i - OoooooooOO % oO0o - OOooOOo
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 73 - 73: OoOoOO00
 if 27 - 27: iIii1I11I1II1 % i11iIiiIii % OoO0O00 - iII111i
 if 88 - 88: I1ii11iIi11i - ooOoO0o * iIii1I11I1II1 - o0oOOo0O0Ooo . II111iiii
 if 49 - 49: II111iiii - i11iIiiIii
 if 79 - 79: iII111i
 O0oo0oOo = 0
 iIIi11Ii1iII = bold ( "RLOC-probe" , False )
 for I1i1IIIi1iii in list ( lisp_rloc_probe_list . values ( ) ) :
  if 43 - 43: OoOoOO00
  if 99 - 99: OoO0O00 - O0 * OoO0O00 + OoO0O00
  if 62 - 62: IiII - I1Ii111
  if 68 - 68: Oo0Ooo + oO0o - OoO0O00
  if 17 - 17: I11i % I1ii11iIi11i - I1IiiI % oO0o + I1ii11iIi11i
  OoIIi11ii = None
  for o0oOO00 , i1I1I1IIIi11 , o0o0Oo0o0oOo in I1i1IIIi1iii :
   O0O0 = o0oOO00 . rloc . print_address_no_iid ( )
   if 20 - 20: OoOoOO00
   if 44 - 44: iIii1I11I1II1 * O0 % I11i % I1Ii111 - I1ii11iIi11i * Oo0Ooo
   if 11 - 11: OoooooooOO
   if 85 - 85: O0 * i1IIi
   o0o0OooOooo00 , iIi11I , II11iiiII1Ii = lisp_allow_gleaning ( i1I1I1IIIi11 , None , o0oOO00 )
   if ( o0o0OooOooo00 and iIi11I == False ) :
    oO0ooOOO = green ( i1I1I1IIIi11 . print_address ( ) , False )
    O0O0 += ":{}" . format ( o0oOO00 . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( O0O0 , False ) , oO0ooOOO ) )
    if 80 - 80: OoO0O00 % I1IiiI * I11i
    continue
    if 78 - 78: OoooooooOO . I1Ii111 + Ii1I - II111iiii - IiII / iIii1I11I1II1
    if 92 - 92: Ii1I
    if 34 - 34: OOooOOo * OoooooooOO / I1ii11iIi11i
    if 41 - 41: i1IIi
    if 75 - 75: o0oOOo0O0Ooo . I1Ii111 - I1Ii111 % Ii1I * OoooooooOO
    if 99 - 99: OOooOOo + o0oOOo0O0Ooo - OOooOOo . i1IIi
    if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
   if ( o0oOO00 . down_state ( ) ) : continue
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
   if ( OoIIi11ii ) :
    o0oOO00 . last_rloc_probe_nonce = OoIIi11ii . last_rloc_probe_nonce
    if 78 - 78: iII111i - OOooOOo / I1Ii111
    if ( OoIIi11ii . translated_port == o0oOO00 . translated_port and OoIIi11ii . rloc_name == o0oOO00 . rloc_name ) :
     if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
     oO0ooOOO = green ( lisp_print_eid_tuple ( i1I1I1IIIi11 , o0o0Oo0o0oOo ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( O0O0 , False ) , oO0ooOOO ) )
     if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
     if 17 - 17: OoooooooOO % OoooooooOO + Oo0Ooo + I1Ii111
     if 56 - 56: I11i % OoOoOO00 - OoO0O00
     if 31 - 31: iII111i % i11iIiiIii - Ii1I / OOooOOo - I1Ii111
     if 60 - 60: o0oOOo0O0Ooo + Oo0Ooo . O0
     if 51 - 51: i11iIiiIii / iIii1I11I1II1 . I1IiiI - Ii1I * I1Ii111 . iII111i
     o0oOO00 . last_rloc_probe = OoIIi11ii . last_rloc_probe
     continue
     if 72 - 72: Ii1I . I11i / i1IIi % i1IIi + I1ii11iIi11i
     if 56 - 56: OoO0O00 - OoOoOO00 - II111iiii * o0oOOo0O0Ooo
     if 87 - 87: ooOoO0o * OoooooooOO % O0 * OoooooooOO . I1Ii111
   ii1I = None
   I1Ii1i111I = None
   while ( True ) :
    I1Ii1i111I = o0oOO00 if I1Ii1i111I == None else I1Ii1i111I . next_rloc
    if ( I1Ii1i111I == None ) : break
    if 66 - 66: OoO0O00 * Ii1I . OoO0O00
    if 90 - 90: II111iiii % Ii1I
    if 67 - 67: I1IiiI - I11i - i11iIiiIii
    if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
    if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
    if ( I1Ii1i111I . rloc_next_hop != None ) :
     if ( I1Ii1i111I . rloc_next_hop not in o000oo ) :
      if ( I1Ii1i111I . up_state ( ) ) :
       IiI11I111 , Ii1i1Ii1Ii1i = I1Ii1i111I . rloc_next_hop
       I1Ii1i111I . state = LISP_RLOC_UNREACH_STATE
       I1Ii1i111I . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( I1Ii1i111I . rloc , False )
       if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
      II1iIi1ii1IIi = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( Ii1i1Ii1Ii1i , IiI11I111 ,
 red ( O0O0 , False ) , II1iIi1ii1IIi ) )
      continue
      if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
      if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
      if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
      if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
      if 57 - 57: I1Ii111 - IiII
      if 89 - 89: oO0o + iII111i
    IiIiIi = I1Ii1i111I . last_rloc_probe
    O00ooOoO0o = 0 if IiIiIi == None else time . time ( ) - IiIiIi
    if ( I1Ii1i111I . unreach_state ( ) and O00ooOoO0o < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( O0O0 , False ) ) )
     if 7 - 7: IiII . i11iIiiIii
     continue
     if 12 - 12: I11i . IiII % I1IiiI
     if 42 - 42: OoO0O00
     if 3 - 3: Oo0Ooo * OoooooooOO * oO0o % OoOoOO00 * OoOoOO00 . ooOoO0o
     if 16 - 16: ooOoO0o / o0oOOo0O0Ooo - O0 * I1IiiI
     if 13 - 13: iII111i . iII111i % O0 % o0oOOo0O0Ooo
     if 99 - 99: OoO0O00 - OoOoOO00 + OoO0O00
    oO0 = lisp_get_echo_nonce ( None , O0O0 )
    if ( oO0 and oO0 . request_nonce_timeout ( ) ) :
     I1Ii1i111I . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     I1Ii1i111I . last_state_change = lisp_get_timestamp ( )
     II1iIi1ii1IIi = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( O0O0 , False ) , II1iIi1ii1IIi ) )
     if 67 - 67: I1Ii111
     lisp_update_rtr_updown ( I1Ii1i111I . rloc , False )
     continue
     if 31 - 31: OoO0O00 * Oo0Ooo % O0 * II111iiii + ooOoO0o * I1IiiI
     if 77 - 77: ooOoO0o
     if 98 - 98: I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
     if 6 - 6: iII111i / iII111i . i11iIiiIii
     if 12 - 12: I11i - OoO0O00
     if 68 - 68: IiII - OoOoOO00
    if ( oO0 and oO0 . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( O0O0 , False ) ) )
     if 22 - 22: i1IIi . IiII
     continue
     if 8 - 8: IiII % o0oOOo0O0Ooo . i11iIiiIii
     if 69 - 69: I1Ii111 / Ii1I - ooOoO0o
     if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
     if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
     if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
     if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
    if ( I1Ii1i111I . last_rloc_probe != None ) :
     IiIiIi = I1Ii1i111I . last_rloc_probe_reply
     if ( IiIiIi == None ) : IiIiIi = 0
     O00ooOoO0o = time . time ( ) - IiIiIi
     if ( I1Ii1i111I . up_state ( ) and O00ooOoO0o >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 42 - 42: i1IIi . OoO0O00 % iII111i
      I1Ii1i111I . state = LISP_RLOC_UNREACH_STATE
      I1Ii1i111I . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( I1Ii1i111I . rloc , False )
      II1iIi1ii1IIi = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( O0O0 , False ) , II1iIi1ii1IIi ) )
      if 57 - 57: I1ii11iIi11i / I1IiiI
      if 69 - 69: iII111i - iII111i . OoO0O00 / oO0o - OoO0O00 + I1Ii111
      lisp_mark_rlocs_for_other_eids ( I1i1IIIi1iii )
      if 98 - 98: iII111i . oO0o - O0 % I1IiiI . I1ii11iIi11i / i1IIi
      if 72 - 72: I1IiiI / Oo0Ooo % IiII - O0 / O0 * O0
      if 83 - 83: O0 / I1Ii111 - OoooooooOO
    I1Ii1i111I . last_rloc_probe = lisp_get_timestamp ( )
    if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
    ii1oO00o = "" if I1Ii1i111I . unreach_state ( ) == False else " unreachable"
    if 20 - 20: Oo0Ooo + II111iiii + II111iiii . o0oOOo0O0Ooo
    if 92 - 92: Ii1I - O0 - i11iIiiIii + IiII % I1Ii111 + II111iiii
    if 71 - 71: ooOoO0o * I1Ii111 + i11iIiiIii + i1IIi . I1IiiI
    if 15 - 15: OoO0O00
    if 37 - 37: OoO0O00 . OoooooooOO - OOooOOo
    if 34 - 34: o0oOOo0O0Ooo + iIii1I11I1II1 / o0oOOo0O0Ooo / ooOoO0o
    if 53 - 53: II111iiii / iIii1I11I1II1
    iIi1Iiii11Ii1 = ""
    Ii1i1Ii1Ii1i = None
    if ( I1Ii1i111I . rloc_next_hop != None ) :
     IiI11I111 , Ii1i1Ii1Ii1i = I1Ii1i111I . rloc_next_hop
     lisp_install_host_route ( O0O0 , Ii1i1Ii1Ii1i , True )
     iIi1Iiii11Ii1 = ", send on nh {}({})" . format ( Ii1i1Ii1Ii1i , IiI11I111 )
     if 27 - 27: II111iiii - i1IIi
     if 4 - 4: I1IiiI
     if 5 - 5: Ii1I / O0 + iIii1I11I1II1
     if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
     if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
    ii1111Ii = I1Ii1i111I . print_rloc_probe_rtt ( )
    o0OoooOOO00 = O0O0
    if ( I1Ii1i111I . translated_port != 0 ) :
     o0OoooOOO00 += ":{}" . format ( I1Ii1i111I . translated_port )
     if 78 - 78: Oo0Ooo
    o0OoooOOO00 = red ( o0OoooOOO00 , False )
    if ( I1Ii1i111I . rloc_name != None ) :
     o0OoooOOO00 += " (" + blue ( I1Ii1i111I . rloc_name , False ) + ")"
     if 14 - 14: OOooOOo
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( iIIi11Ii1iII , ii1oO00o ,
 o0OoooOOO00 , ii1111Ii , iIi1Iiii11Ii1 ) )
    if 16 - 16: iII111i
    if 63 - 63: OoOoOO00
    if 96 - 96: O0
    if 18 - 18: I1IiiI
    if 73 - 73: OoOoOO00 % II111iiii - I1ii11iIi11i - I11i / I1ii11iIi11i . I1ii11iIi11i
    if 56 - 56: iIii1I11I1II1 . Oo0Ooo / II111iiii
    if 75 - 75: Oo0Ooo - I1Ii111 * IiII
    if 2 - 2: I1Ii111 - O0 % OoooooooOO + I1Ii111
    if ( I1Ii1i111I . rloc_next_hop != None ) :
     ii1I = lisp_get_host_route_next_hop ( O0O0 )
     if ( ii1I ) : lisp_install_host_route ( O0O0 , ii1I , False )
     if 1 - 1: I1Ii111 % OoooooooOO + OoooooooOO - I1IiiI % I1IiiI
     if 51 - 51: iIii1I11I1II1 / I1IiiI
     if 27 - 27: O0 . o0oOOo0O0Ooo / ooOoO0o / OoooooooOO % Ii1I
     if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
     if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
     if 87 - 87: II111iiii
    if ( I1Ii1i111I . rloc . is_null ( ) ) :
     I1Ii1i111I . rloc . copy_address ( o0oOO00 . rloc )
     if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
     if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
     if 24 - 24: i11iIiiIii + ooOoO0o
     if 80 - 80: IiII % I11i % oO0o
     if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
    O0oO = None if ( o0o0Oo0o0oOo . is_null ( ) ) else i1I1I1IIIi11
    oo0Oo00oo0OoO0O0 = i1I1I1IIIi11 if ( o0o0Oo0o0oOo . is_null ( ) ) else o0o0Oo0o0oOo
    lisp_send_map_request ( lisp_sockets , 0 , O0oO , oo0Oo00oo0OoO0O0 , I1Ii1i111I )
    OoIIi11ii = o0oOO00
    if 38 - 38: IiII . OoO0O00 * IiII % ooOoO0o * Ii1I / ooOoO0o
    if 56 - 56: O0 / OoooooooOO / OoOoOO00
    if 19 - 19: o0oOOo0O0Ooo / i11iIiiIii . i1IIi / Oo0Ooo / I1Ii111
    if 83 - 83: iII111i % o0oOOo0O0Ooo * OoOoOO00
    if ( Ii1i1Ii1Ii1i ) : lisp_install_host_route ( O0O0 , Ii1i1Ii1Ii1i , False )
    if 49 - 49: II111iiii / OoO0O00
    if 69 - 69: Ii1I * II111iiii
    if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
    if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
    if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
   if ( ii1I ) : lisp_install_host_route ( O0O0 , ii1I , True )
   if 10 - 10: Ii1I / Oo0Ooo - i1IIi
   if 11 - 11: I11i * iII111i
   if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
   if 2 - 2: oO0o + I11i / I1Ii111 . I11i
   O0oo0oOo += 1
   if ( ( O0oo0oOo % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 59 - 59: Ii1I
   if 47 - 47: iII111i % iII111i
   if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 23 - 23: IiII + oO0o + o0oOOo0O0Ooo . I1ii11iIi11i / i11iIiiIii + iIii1I11I1II1
 if 74 - 74: I11i % OOooOOo
 if 57 - 57: O0 + I1IiiI + i11iIiiIii
 if 90 - 90: I1ii11iIi11i . OoO0O00 * iIii1I11I1II1 - Oo0Ooo
 if 28 - 28: I1IiiI . ooOoO0o - ooOoO0o * OOooOOo . IiII
 if 16 - 16: iIii1I11I1II1 % i11iIiiIii / Ii1I % iIii1I11I1II1 / iII111i
 if 27 - 27: II111iiii * OoooooooOO / Oo0Ooo % O0
 if 41 - 41: oO0o / iIii1I11I1II1 % iII111i - I1Ii111 % I11i * i11iIiiIii
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 21 - 21: O0
 if 14 - 14: IiII / I1ii11iIi11i + Ii1I
 if 48 - 48: I1Ii111 * oO0o / o0oOOo0O0Ooo * OoOoOO00 * ooOoO0o
 if 38 - 38: I1IiiI * Ii1I + Oo0Ooo - OoooooooOO
 if ( lisp_i_am_itr == False ) : return
 if 63 - 63: I1ii11iIi11i
 if 99 - 99: I1Ii111 % oO0o - II111iiii . ooOoO0o
 if 26 - 26: I1ii11iIi11i * iII111i . OoooooooOO - Oo0Ooo - IiII
 if 6 - 6: OOooOOo - I1IiiI . IiII
 if 40 - 40: II111iiii
 if ( lisp_register_all_rtrs ) : return
 if 13 - 13: OoOoOO00
 II1i1OoOOo0o0o00 = rtr . print_address_no_iid ( )
 if 28 - 28: Oo0Ooo % iIii1I11I1II1 % iII111i . iIii1I11I1II1 * oO0o - OoooooooOO
 if 12 - 12: O0
 if 9 - 9: I1Ii111 - OOooOOo * OOooOOo / oO0o . oO0o / ooOoO0o
 if 4 - 4: o0oOOo0O0Ooo
 if 33 - 33: O0
 if ( II1i1OoOOo0o0o00 not in lisp_rtr_list ) : return
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( II1i1OoOOo0o0o00 , False ) , bold ( updown , False ) ) )
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
 oOoo = "rtr%{}%{}" . format ( II1i1OoOOo0o0o00 , updown )
 oOoo = lisp_command_ipc ( oOoo , "lisp-itr" )
 lisp_ipc ( oOoo , lisp_ipc_socket , "lisp-etr" )
 return
 if 46 - 46: OOooOOo
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
 if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
 if 32 - 32: I1Ii111 * I1IiiI + Ii1I
 if 30 - 30: OoooooooOO / I1IiiI . iIii1I11I1II1 / ooOoO0o
 if 20 - 20: OoooooooOO * OOooOOo
def lisp_process_rloc_probe_reply ( rloc_entry , source , port , map_reply , ttl ,
 mrloc ) :
 I1Ii1i111I = rloc_entry . rloc
 oOooo0oOOOO = map_reply . nonce
 o0ooO0ooo = map_reply . hop_count
 iIIi11Ii1iII = bold ( "RLOC-probe reply" , False )
 O0o = I1Ii1i111I . print_address_no_iid ( )
 I1IIi1Iiii11I = source . print_address_no_iid ( )
 oOoOOoO0o = lisp_rloc_probe_list
 oOO0O00ooO = rloc_entry . json . json_string if rloc_entry . json else None
 i1 = lisp_get_timestamp ( )
 if 99 - 99: OOooOOo . iIii1I11I1II1 . I11i . OoOoOO00 / o0oOOo0O0Ooo - Oo0Ooo
 if 57 - 57: O0 - I1Ii111 . IiII
 if 56 - 56: OoooooooOO
 if 12 - 12: ooOoO0o
 if 97 - 97: i1IIi . Oo0Ooo
 if 81 - 81: OoOoOO00
 if ( mrloc != None ) :
  oOO0OoooOo0 = mrloc . rloc . print_address_no_iid ( )
  if ( O0o not in mrloc . multicast_rloc_probe_list ) :
   I1IiIiIiI = lisp_rloc ( )
   I1IiIiIiI = copy . deepcopy ( mrloc )
   I1IiIiIiI . rloc . copy_address ( I1Ii1i111I )
   I1IiIiIiI . multicast_rloc_probe_list = { }
   mrloc . multicast_rloc_probe_list [ O0o ] = I1IiIiIiI
   if 83 - 83: Oo0Ooo
  I1IiIiIiI = mrloc . multicast_rloc_probe_list [ O0o ]
  I1IiIiIiI . last_rloc_probe_nonce = mrloc . last_rloc_probe_nonce
  I1IiIiIiI . last_rloc_probe = mrloc . last_rloc_probe
  O00o00o00OO0 , i1I1I1IIIi11 , o0o0Oo0o0oOo = lisp_rloc_probe_list [ oOO0OoooOo0 ] [ 0 ]
  I1IiIiIiI . process_rloc_probe_reply ( i1 , oOooo0oOOOO , i1I1I1IIIi11 , o0o0Oo0o0oOo , o0ooO0ooo , ttl , oOO0O00ooO )
  mrloc . process_rloc_probe_reply ( i1 , oOooo0oOOOO , i1I1I1IIIi11 , o0o0Oo0o0oOo , o0ooO0ooo , ttl , oOO0O00ooO )
  return
  if 20 - 20: ooOoO0o % oO0o . iII111i . Ii1I
  if 15 - 15: oO0o * i1IIi
  if 9 - 9: OoooooooOO % IiII * iIii1I11I1II1
  if 60 - 60: I1IiiI - I1IiiI + I1ii11iIi11i
  if 8 - 8: I1Ii111 - I1Ii111 - i1IIi + I11i . i1IIi / I1Ii111
  if 27 - 27: OoOoOO00 % ooOoO0o - II111iiii . I11i
  if 70 - 70: OOooOOo / iII111i - I11i + OoOoOO00 % Ii1I * IiII
 IiI = O0o
 if ( IiI not in oOoOOoO0o ) :
  IiI += ":" + str ( port )
  if ( IiI not in oOoOOoO0o ) :
   IiI = I1IIi1Iiii11I
   if ( IiI not in oOoOOoO0o ) :
    IiI += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( iIIi11Ii1iII , red ( O0o , False ) , red ( I1IIi1Iiii11I ,
    # i1IIi / O0
 False ) , port ) )
    return
    if 64 - 64: I1Ii111 + O0 * IiII % OoOoOO00 % OOooOOo - iII111i
    if 73 - 73: ooOoO0o + I1IiiI % oO0o . O0
    if 18 - 18: o0oOOo0O0Ooo * I11i
    if 24 - 24: oO0o / o0oOOo0O0Ooo + i1IIi
    if 15 - 15: i11iIiiIii / O0
    if 34 - 34: I1Ii111 . IiII % iII111i
    if 94 - 94: OOooOOo % i11iIiiIii . OOooOOo
    if 55 - 55: OoOoOO00 . OoOoOO00 % o0oOOo0O0Ooo . I11i . I1ii11iIi11i - o0oOOo0O0Ooo
 for I1Ii1i111I , i1I1I1IIIi11 , o0o0Oo0o0oOo in lisp_rloc_probe_list [ IiI ] :
  if ( lisp_i_am_rtr ) :
   if ( I1Ii1i111I . translated_port != 0 and I1Ii1i111I . translated_port != port ) :
    continue
    if 1 - 1: i11iIiiIii - i1IIi * oO0o - iIii1I11I1II1
    if 75 - 75: i1IIi * i11iIiiIii
  I1Ii1i111I . process_rloc_probe_reply ( i1 , oOooo0oOOOO , i1I1I1IIIi11 , o0o0Oo0o0oOo , o0ooO0ooo , ttl , oOO0O00ooO )
  if 40 - 40: I1ii11iIi11i + OoO0O00
 return
 if 8 - 8: i11iIiiIii - iIii1I11I1II1
 if 73 - 73: OoOoOO00
 if 25 - 25: iII111i / oO0o
 if 61 - 61: OoooooooOO . Ii1I . I11i + oO0o
 if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
 if 61 - 61: I1IiiI / OOooOOo
 if 67 - 67: OoOoOO00
 if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
def lisp_db_list_length ( ) :
 O0oo0oOo = 0
 for i11IIII1Ii in lisp_db_list :
  O0oo0oOo += len ( i11IIII1Ii . dynamic_eids ) if i11IIII1Ii . dynamic_eid_configured ( ) else 1
  O0oo0oOo += len ( i11IIII1Ii . eid . iid_list )
  if 30 - 30: O0 / oO0o * i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
 return ( O0oo0oOo )
 if 95 - 95: ooOoO0o % OOooOOo
 if 17 - 17: i1IIi + Ii1I
 if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
 if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
 if 26 - 26: oO0o / I1ii11iIi11i - oO0o
 if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
 if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
 if 96 - 96: Ii1I
def lisp_is_myeid ( eid ) :
 for i11IIII1Ii in lisp_db_list :
  if ( eid . is_more_specific ( i11IIII1Ii . eid ) ) : return ( True )
  if 90 - 90: II111iiii
 return ( False )
 if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
 if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
 if 52 - 52: i11iIiiIii * ooOoO0o
 if 15 - 15: OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
 if 91 - 91: ooOoO0o
 if 47 - 47: II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
 if 9 - 9: O0 + IiII
 if 69 - 69: I1IiiI
 if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
 if 86 - 86: ooOoO0o * OoOoOO00 + oO0o / II111iiii % OOooOOo
 if 89 - 89: O0 * Ii1I / OoO0O00 / OoOoOO00 % iII111i * iIii1I11I1II1
 if 72 - 72: iIii1I11I1II1 / iIii1I11I1II1 * I11i
 if 19 - 19: I1ii11iIi11i
 if 42 - 42: OoOoOO00 / IiII
 if 65 - 65: ooOoO0o - ooOoO0o * OoO0O00
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 99 - 99: I11i % ooOoO0o . I1Ii111
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 oO0 = None
 if ( rloc_str in lisp_nonce_echo_list ) :
  oO0 = lisp_nonce_echo_list [ rloc_str ]
  if 34 - 34: ooOoO0o + oO0o + II111iiii . I1Ii111 . i1IIi
 return ( oO0 )
 if 14 - 14: OoO0O00 . ooOoO0o - i1IIi * I1IiiI
 if 24 - 24: iIii1I11I1II1 / I1Ii111
 if 16 - 16: OoOoOO00 * I1Ii111 - I1IiiI / I1Ii111
 if 64 - 64: I1ii11iIi11i . i1IIi % II111iiii % Oo0Ooo + oO0o - I1IiiI
 if 24 - 24: IiII . II111iiii . II111iiii . OoOoOO00 . i11iIiiIii
 if 11 - 11: Ii1I
 if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
 if 44 - 44: iII111i
def lisp_decode_dist_name ( packet ) :
 O0oo0oOo = 0
 Oo0OOoOo0oOo = b""
 if 54 - 54: I1IiiI % II111iiii
 while ( packet [ 0 : 1 ] != b"\x00" ) :
  if ( O0oo0oOo == 255 ) : return ( [ None , None ] )
  Oo0OOoOo0oOo += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  O0oo0oOo += 1
  if 29 - 29: ooOoO0o - OOooOOo - I11i / I1Ii111
  if 88 - 88: O0 + IiII
 packet = packet [ 1 : : ]
 return ( packet , Oo0OOoOo0oOo . decode ( ) )
 if 91 - 91: OoooooooOO + OoO0O00 % I1Ii111 . I1IiiI . iIii1I11I1II1
 if 88 - 88: OoooooooOO
 if 40 - 40: ooOoO0o * oO0o * Ii1I . ooOoO0o + i11iIiiIii
 if 44 - 44: o0oOOo0O0Ooo / iIii1I11I1II1
 if 66 - 66: O0 % I11i . O0 * o0oOOo0O0Ooo / I1Ii111 + o0oOOo0O0Ooo
 if 24 - 24: i11iIiiIii * oO0o * I1IiiI - i1IIi * OoOoOO00
 if 5 - 5: I1ii11iIi11i % o0oOOo0O0Ooo . iII111i
 if 73 - 73: OoOoOO00 . o0oOOo0O0Ooo * OoOoOO00
def lisp_write_flow_log ( flow_log ) :
 OOoO0 = open ( "./logs/lisp-flow.log" , "a" )
 if 94 - 94: OoO0O00 / I1ii11iIi11i
 O0oo0oOo = 0
 for iII1iii in flow_log :
  Oo00oo = iII1iii [ 3 ]
  IIIIi1i111I = Oo00oo . print_flow ( iII1iii [ 0 ] , iII1iii [ 1 ] , iII1iii [ 2 ] )
  OOoO0 . write ( IIIIi1i111I )
  O0oo0oOo += 1
  if 27 - 27: I1ii11iIi11i % IiII * I1Ii111 + Ii1I
 OOoO0 . close ( )
 del ( flow_log )
 if 70 - 70: iII111i * I1Ii111
 O0oo0oOo = bold ( str ( O0oo0oOo ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( O0oo0oOo ) )
 return
 if 5 - 5: Oo0Ooo * ooOoO0o % II111iiii % II111iiii - oO0o
 if 71 - 71: iIii1I11I1II1 % i11iIiiIii . o0oOOo0O0Ooo - oO0o + Oo0Ooo
 if 69 - 69: I1IiiI - OoOoOO00 . I1ii11iIi11i
 if 88 - 88: ooOoO0o + ooOoO0o + oO0o * o0oOOo0O0Ooo . Ii1I
 if 72 - 72: I11i / I11i
 if 78 - 78: I1IiiI % II111iiii
 if 99 - 99: Oo0Ooo
def lisp_policy_command ( kv_pair ) :
 iIIiiIi = lisp_policy ( "" )
 IIi1II1 = None
 if 42 - 42: OoOoOO00
 OO00OO0O0o0O = [ ]
 for iIi1iIIIiIiI in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  OO00OO0O0o0O . append ( lisp_policy_match ( ) )
  if 17 - 17: o0oOOo0O0Ooo . OOooOOo - Ii1I % Ii1I + i11iIiiIii * I1IiiI
  if 82 - 82: o0oOOo0O0Ooo
 for IIIIiii1 in list ( kv_pair . keys ( ) ) :
  oOO0 = kv_pair [ IIIIiii1 ]
  if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
  if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
  if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
  if 78 - 78: OoO0O00 - i1IIi % I1Ii111
  if ( IIIIiii1 == "instance-id" ) :
   for iIi1iIIIiIiI in range ( len ( OO00OO0O0o0O ) ) :
    oO0o0O0O0O = oOO0 [ iIi1iIIIiIiI ]
    if ( oO0o0O0O0O == "" ) : continue
    Oo0OOoo0OooooO0o = OO00OO0O0o0O [ iIi1iIIIiIiI ]
    if ( Oo0OOoo0OooooO0o . source_eid == None ) :
     Oo0OOoo0OooooO0o . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 1 - 1: OoooooooOO * I1Ii111 - I11i / IiII
    if ( Oo0OOoo0OooooO0o . dest_eid == None ) :
     Oo0OOoo0OooooO0o . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 43 - 43: i11iIiiIii * I1IiiI
    Oo0OOoo0OooooO0o . source_eid . instance_id = int ( oO0o0O0O0O )
    Oo0OOoo0OooooO0o . dest_eid . instance_id = int ( oO0o0O0O0O )
    if 48 - 48: Oo0Ooo - OOooOOo / iII111i % I1ii11iIi11i . OoOoOO00
    if 6 - 6: i11iIiiIii
  if ( IIIIiii1 == "source-eid" ) :
   for iIi1iIIIiIiI in range ( len ( OO00OO0O0o0O ) ) :
    oO0o0O0O0O = oOO0 [ iIi1iIIIiIiI ]
    if ( oO0o0O0O0O == "" ) : continue
    Oo0OOoo0OooooO0o = OO00OO0O0o0O [ iIi1iIIIiIiI ]
    if ( Oo0OOoo0OooooO0o . source_eid == None ) :
     Oo0OOoo0OooooO0o . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 51 - 51: o0oOOo0O0Ooo - OoooooooOO - I11i % i11iIiiIii / I1IiiI + IiII
    oooo = Oo0OOoo0OooooO0o . source_eid . instance_id
    Oo0OOoo0OooooO0o . source_eid . store_prefix ( oO0o0O0O0O )
    Oo0OOoo0OooooO0o . source_eid . instance_id = oooo
    if 91 - 91: O0
    if 13 - 13: o0oOOo0O0Ooo
  if ( IIIIiii1 == "destination-eid" ) :
   for iIi1iIIIiIiI in range ( len ( OO00OO0O0o0O ) ) :
    oO0o0O0O0O = oOO0 [ iIi1iIIIiIiI ]
    if ( oO0o0O0O0O == "" ) : continue
    Oo0OOoo0OooooO0o = OO00OO0O0o0O [ iIi1iIIIiIiI ]
    if ( Oo0OOoo0OooooO0o . dest_eid == None ) :
     Oo0OOoo0OooooO0o . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 15 - 15: iIii1I11I1II1 * Oo0Ooo . iIii1I11I1II1 . Ii1I % iII111i - i11iIiiIii
    oooo = Oo0OOoo0OooooO0o . dest_eid . instance_id
    Oo0OOoo0OooooO0o . dest_eid . store_prefix ( oO0o0O0O0O )
    Oo0OOoo0OooooO0o . dest_eid . instance_id = oooo
    if 77 - 77: ooOoO0o - o0oOOo0O0Ooo * OoOoOO00 % oO0o
    if 4 - 4: i11iIiiIii + OoOoOO00
  if ( IIIIiii1 == "source-rloc" ) :
   for iIi1iIIIiIiI in range ( len ( OO00OO0O0o0O ) ) :
    oO0o0O0O0O = oOO0 [ iIi1iIIIiIiI ]
    if ( oO0o0O0O0O == "" ) : continue
    Oo0OOoo0OooooO0o = OO00OO0O0o0O [ iIi1iIIIiIiI ]
    Oo0OOoo0OooooO0o . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    Oo0OOoo0OooooO0o . source_rloc . store_prefix ( oO0o0O0O0O )
    if 45 - 45: ooOoO0o / OoooooooOO . Oo0Ooo
    if 35 - 35: i11iIiiIii / o0oOOo0O0Ooo / oO0o / I11i . O0
  if ( IIIIiii1 == "destination-rloc" ) :
   for iIi1iIIIiIiI in range ( len ( OO00OO0O0o0O ) ) :
    oO0o0O0O0O = oOO0 [ iIi1iIIIiIiI ]
    if ( oO0o0O0O0O == "" ) : continue
    Oo0OOoo0OooooO0o = OO00OO0O0o0O [ iIi1iIIIiIiI ]
    Oo0OOoo0OooooO0o . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    Oo0OOoo0OooooO0o . dest_rloc . store_prefix ( oO0o0O0O0O )
    if 53 - 53: i1IIi
    if 51 - 51: OoOoOO00 / iIii1I11I1II1 . oO0o - I1ii11iIi11i - OOooOOo
  if ( IIIIiii1 == "rloc-record-name" ) :
   for iIi1iIIIiIiI in range ( len ( OO00OO0O0o0O ) ) :
    oO0o0O0O0O = oOO0 [ iIi1iIIIiIiI ]
    if ( oO0o0O0O0O == "" ) : continue
    Oo0OOoo0OooooO0o = OO00OO0O0o0O [ iIi1iIIIiIiI ]
    Oo0OOoo0OooooO0o . rloc_record_name = oO0o0O0O0O
    if 90 - 90: i1IIi / oO0o * I1Ii111 + II111iiii % I11i
    if 41 - 41: o0oOOo0O0Ooo - II111iiii . ooOoO0o . iII111i - ooOoO0o / iII111i
  if ( IIIIiii1 == "geo-name" ) :
   for iIi1iIIIiIiI in range ( len ( OO00OO0O0o0O ) ) :
    oO0o0O0O0O = oOO0 [ iIi1iIIIiIiI ]
    if ( oO0o0O0O0O == "" ) : continue
    Oo0OOoo0OooooO0o = OO00OO0O0o0O [ iIi1iIIIiIiI ]
    Oo0OOoo0OooooO0o . geo_name = oO0o0O0O0O
    if 59 - 59: O0 / II111iiii * II111iiii - ooOoO0o
    if 63 - 63: I1ii11iIi11i * IiII % OoO0O00 . OoOoOO00 - II111iiii % IiII
  if ( IIIIiii1 == "elp-name" ) :
   for iIi1iIIIiIiI in range ( len ( OO00OO0O0o0O ) ) :
    oO0o0O0O0O = oOO0 [ iIi1iIIIiIiI ]
    if ( oO0o0O0O0O == "" ) : continue
    Oo0OOoo0OooooO0o = OO00OO0O0o0O [ iIi1iIIIiIiI ]
    Oo0OOoo0OooooO0o . elp_name = oO0o0O0O0O
    if 8 - 8: iIii1I11I1II1
    if 71 - 71: oO0o / o0oOOo0O0Ooo % iIii1I11I1II1 * iIii1I11I1II1
  if ( IIIIiii1 == "rle-name" ) :
   for iIi1iIIIiIiI in range ( len ( OO00OO0O0o0O ) ) :
    oO0o0O0O0O = oOO0 [ iIi1iIIIiIiI ]
    if ( oO0o0O0O0O == "" ) : continue
    Oo0OOoo0OooooO0o = OO00OO0O0o0O [ iIi1iIIIiIiI ]
    Oo0OOoo0OooooO0o . rle_name = oO0o0O0O0O
    if 29 - 29: ooOoO0o - OoOoOO00 - o0oOOo0O0Ooo
    if 54 - 54: Ii1I + i11iIiiIii + i1IIi - OoooooooOO
  if ( IIIIiii1 == "json-name" ) :
   for iIi1iIIIiIiI in range ( len ( OO00OO0O0o0O ) ) :
    oO0o0O0O0O = oOO0 [ iIi1iIIIiIiI ]
    if ( oO0o0O0O0O == "" ) : continue
    Oo0OOoo0OooooO0o = OO00OO0O0o0O [ iIi1iIIIiIiI ]
    Oo0OOoo0OooooO0o . json_name = oO0o0O0O0O
    if 100 - 100: oO0o . ooOoO0o
    if 14 - 14: OoooooooOO + iII111i / iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1 - IiII
  if ( IIIIiii1 == "datetime-range" ) :
   for iIi1iIIIiIiI in range ( len ( OO00OO0O0o0O ) ) :
    oO0o0O0O0O = oOO0 [ iIi1iIIIiIiI ]
    Oo0OOoo0OooooO0o = OO00OO0O0o0O [ iIi1iIIIiIiI ]
    if ( oO0o0O0O0O == "" ) : continue
    oOO0O0ooOOOo = lisp_datetime ( oO0o0O0O0O [ 0 : 19 ] )
    I11iiI1i11I = lisp_datetime ( oO0o0O0O0O [ 19 : : ] )
    if ( oOO0O0ooOOOo . valid_datetime ( ) and I11iiI1i11I . valid_datetime ( ) ) :
     Oo0OOoo0OooooO0o . datetime_lower = oOO0O0ooOOOo
     Oo0OOoo0OooooO0o . datetime_upper = I11iiI1i11I
     if 34 - 34: I1ii11iIi11i + i11iIiiIii - I1ii11iIi11i / OoOoOO00 + i1IIi . i11iIiiIii
     if 48 - 48: I1ii11iIi11i % OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii / OoOoOO00
     if 73 - 73: OoOoOO00 + OOooOOo * II111iiii . OOooOOo % I1Ii111 % oO0o
     if 79 - 79: I1ii11iIi11i % I11i
     if 78 - 78: i11iIiiIii % I1Ii111 + iIii1I11I1II1 + iII111i
     if 66 - 66: I1IiiI - o0oOOo0O0Ooo
     if 67 - 67: oO0o . iII111i * Ii1I - OOooOOo / oO0o
  if ( IIIIiii1 == "set-action" ) :
   iIIiiIi . set_action = oOO0
   if 98 - 98: OoOoOO00 * OoO0O00 . Oo0Ooo
  if ( IIIIiii1 == "set-record-ttl" ) :
   iIIiiIi . set_record_ttl = int ( oOO0 )
   if 6 - 6: I11i % iIii1I11I1II1 + I1Ii111
  if ( IIIIiii1 == "set-instance-id" ) :
   if ( iIIiiIi . set_source_eid == None ) :
    iIIiiIi . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 48 - 48: II111iiii . OOooOOo . ooOoO0o - iII111i
   if ( iIIiiIi . set_dest_eid == None ) :
    iIIiiIi . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 90 - 90: OOooOOo
   IIi1II1 = int ( oOO0 )
   iIIiiIi . set_source_eid . instance_id = IIi1II1
   iIIiiIi . set_dest_eid . instance_id = IIi1II1
   if 43 - 43: IiII + ooOoO0o
  if ( IIIIiii1 == "set-source-eid" ) :
   if ( iIIiiIi . set_source_eid == None ) :
    iIIiiIi . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 4 - 4: i1IIi
   iIIiiIi . set_source_eid . store_prefix ( oOO0 )
   if ( IIi1II1 != None ) : iIIiiIi . set_source_eid . instance_id = IIi1II1
   if 89 - 89: Oo0Ooo / iIii1I11I1II1 . OoOoOO00
  if ( IIIIiii1 == "set-destination-eid" ) :
   if ( iIIiiIi . set_dest_eid == None ) :
    iIIiiIi . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 6 - 6: Ii1I / iII111i
   iIIiiIi . set_dest_eid . store_prefix ( oOO0 )
   if ( IIi1II1 != None ) : iIIiiIi . set_dest_eid . instance_id = IIi1II1
   if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
  if ( IIIIiii1 == "set-rloc-address" ) :
   iIIiiIi . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   iIIiiIi . set_rloc_address . store_address ( oOO0 )
   if 70 - 70: oO0o - I1IiiI + Ii1I
  if ( IIIIiii1 == "set-rloc-record-name" ) :
   iIIiiIi . set_rloc_record_name = oOO0
   if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
  if ( IIIIiii1 == "set-elp-name" ) :
   iIIiiIi . set_elp_name = oOO0
   if 37 - 37: o0oOOo0O0Ooo
  if ( IIIIiii1 == "set-geo-name" ) :
   iIIiiIi . set_geo_name = oOO0
   if 57 - 57: iII111i / i1IIi / i1IIi + IiII
  if ( IIIIiii1 == "set-rle-name" ) :
   iIIiiIi . set_rle_name = oOO0
   if 75 - 75: IiII / O0
  if ( IIIIiii1 == "set-json-name" ) :
   iIIiiIi . set_json_name = oOO0
   if 72 - 72: I11i
  if ( IIIIiii1 == "policy-name" ) :
   iIIiiIi . policy_name = oOO0
   if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
   if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
   if 23 - 23: OoOoOO00 . oO0o - iII111i
   if 27 - 27: Oo0Ooo * OOooOOo - OoOoOO00
   if 1 - 1: II111iiii * i11iIiiIii . OoooooooOO
   if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
 iIIiiIi . match_clauses = OO00OO0O0o0O
 iIIiiIi . save_policy ( )
 return
 if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
 if 88 - 88: I1Ii111
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
if 16 - 16: Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . OoooooooOO * OoO0O00
if 50 - 50: II111iiii + I11i . OoooooooOO . I1Ii111 - OOooOOo
if 83 - 83: oO0o
if 100 - 100: I1Ii111 + o0oOOo0O0Ooo * oO0o / oO0o . oO0o + iII111i
if 71 - 71: II111iiii + iII111i + O0 % Oo0Ooo / I1IiiI
if 52 - 52: Oo0Ooo . I1Ii111 * i1IIi / Oo0Ooo / OoO0O00
if 29 - 29: iII111i
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 91 - 91: Oo0Ooo - IiII
 i1I1 = command
 if ( interface != "" ) : i1I1 = interface + ": " + i1I1
 lprint ( "Send CLI command '{}' to hardware" . format ( i1I1 ) )
 if 81 - 81: i11iIiiIii / I1ii11iIi11i + i1IIi / I11i * I1IiiI
 IiIoo0OO0Oo0ooo0 = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 87 - 87: I1IiiI + Ii1I * I11i
 os . system ( "FastCli -c '{}'" . format ( IiIoo0OO0Oo0ooo0 ) )
 return
 if 77 - 77: IiII / I1Ii111 * OoOoOO00 . O0 % I11i
 if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
 if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
 if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
 if 53 - 53: I1IiiI % I1IiiI
 if 80 - 80: OoO0O00 - i11iIiiIii / iII111i * I1ii11iIi11i / I1IiiI - I1Ii111
 if 85 - 85: IiII
def lisp_arista_is_alive ( prefix ) :
 oO00o00 = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 oOo0OOoooO = getoutput ( "FastCli -c '{}'" . format ( oO00o00 ) )
 if 72 - 72: iII111i * OoOoOO00
 if 65 - 65: iIii1I11I1II1 / iIii1I11I1II1 % O0 / II111iiii . OOooOOo . O0
 if 65 - 65: I11i
 if 35 - 35: o0oOOo0O0Ooo - i11iIiiIii
 oOo0OOoooO = oOo0OOoooO . split ( "\n" ) [ 1 ]
 o0Oooo00o = oOo0OOoooO . split ( " " )
 o0Oooo00o = o0Oooo00o [ - 1 ] . replace ( "\r" , "" )
 if 67 - 67: IiII / oO0o . O0
 if 70 - 70: I1ii11iIi11i % O0
 if 57 - 57: i1IIi + OoOoOO00
 if 8 - 8: Ii1I + I11i * oO0o % I11i
 return ( o0Oooo00o == "Y" )
 if 17 - 17: o0oOOo0O0Ooo + Oo0Ooo
 if 38 - 38: oO0o + I1IiiI + OOooOOo
 if 82 - 82: iIii1I11I1II1 . OOooOOo
 if 7 - 7: i11iIiiIii . I11i
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
 if 91 - 91: ooOoO0o
 if 96 - 96: I1IiiI . OOooOOo
 if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
 if 34 - 34: IiII % oO0o
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
 if 16 - 16: o0oOOo0O0Ooo * I11i + OoooooooOO + O0 / iIii1I11I1II1
 if 60 - 60: Ii1I % IiII * OoooooooOO * ooOoO0o * Ii1I
 if 8 - 8: I1Ii111 - o0oOOo0O0Ooo
 if 52 - 52: OoOoOO00 % O0 + I1ii11iIi11i . i11iIiiIii
 if 59 - 59: Ii1I - I1Ii111 . ooOoO0o - OoOoOO00 + oO0o . OoO0O00
 if 88 - 88: OOooOOo - ooOoO0o * o0oOOo0O0Ooo . OoooooooOO
 if 3 - 3: I1Ii111
 if 24 - 24: Ii1I + i11iIiiIii * I1Ii111 - OoOoOO00 / Ii1I - OoOoOO00
def lisp_program_vxlan_hardware ( mc ) :
 if 69 - 69: I11i - I1IiiI . oO0o - OoooooooOO
 if 33 - 33: o0oOOo0O0Ooo - o0oOOo0O0Ooo
 if 55 - 55: OoooooooOO / IiII + i1IIi
 if 54 - 54: ooOoO0o * Ii1I / Ii1I
 if 15 - 15: oO0o * I1Ii111
 if 11 - 11: Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
 if 46 - 46: oO0o + OoOoOO00
 if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
 if 59 - 59: O0
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
 if 17 - 17: Ii1I % I1ii11iIi11i + I11i
 if 80 - 80: i1IIi . OoooooooOO % OoooooooOO . oO0o / OOooOOo
 if 85 - 85: OOooOOo
 II1 = mc . eid . print_prefix_no_iid ( )
 I1Ii1i111I = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 80 - 80: ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
 if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
 if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
 if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
 o0oo = getoutput ( "ip route get {} | egrep vlan4094" . format ( II1 ) )
 if 64 - 64: OoOoOO00 / OoO0O00 + oO0o
 if ( o0oo != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( II1 , False ) , o0oo ) )
  if 16 - 16: I1ii11iIi11i . I1ii11iIi11i
  return
  if 38 - 38: O0 / OoO0O00
  if 80 - 80: ooOoO0o
  if 46 - 46: Ii1I
  if 48 - 48: I1Ii111 + i1IIi - Ii1I
  if 94 - 94: iII111i . I1IiiI
  if 5 - 5: OoooooooOO + o0oOOo0O0Ooo + OOooOOo * OoO0O00 . OOooOOo . I11i
  if 49 - 49: I1IiiI * OoOoOO00 . OoOoOO00 % I1Ii111 * iIii1I11I1II1 . OOooOOo
 iIIiI1II = getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( iIIiI1II . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 86 - 86: IiII * OOooOOo + Ii1I
 if ( iIIiI1II . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 62 - 62: I11i
 OOOoo0OoOo = getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( OOOoo0OoOo == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 34 - 34: iII111i * ooOoO0o - I1Ii111 . iIii1I11I1II1 / II111iiii
 OOOoo0OoOo = OOOoo0OoOo . split ( "inet " ) [ 1 ]
 OOOoo0OoOo = OOOoo0OoOo . split ( "/" ) [ 0 ]
 if 37 - 37: IiII * iII111i
 if 49 - 49: Oo0Ooo % I1ii11iIi11i / I1Ii111
 if 16 - 16: I1ii11iIi11i + OoO0O00 + iIii1I11I1II1 + ooOoO0o - i1IIi + i11iIiiIii
 if 33 - 33: i1IIi * OoO0O00
 if 76 - 76: OoOoOO00 - Ii1I * i11iIiiIii + IiII - I1Ii111 % ooOoO0o
 if 43 - 43: Ii1I / I11i % I1ii11iIi11i / OoO0O00
 if 49 - 49: iII111i + iII111i % ooOoO0o * i11iIiiIii / Ii1I
 o000O00OOOOOo = [ ]
 oOOoOoo = getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for IiiiI1 in oOOoOoo :
  if ( IiiiI1 . find ( "vlan4094" ) == - 1 ) : continue
  if ( IiiiI1 . find ( "(incomplete)" ) == - 1 ) : continue
  ii1I = IiiiI1 . split ( " " ) [ 0 ]
  o000O00OOOOOo . append ( ii1I )
  if 86 - 86: i1IIi
  if 5 - 5: ooOoO0o
 ii1I = None
 iI1iIii11i1i = OOOoo0OoOo
 OOOoo0OoOo = OOOoo0OoOo . split ( "." )
 for iIi1iIIIiIiI in range ( 1 , 255 ) :
  OOOoo0OoOo [ 3 ] = str ( iIi1iIIIiIiI )
  IiI = "." . join ( OOOoo0OoOo )
  if ( IiI in o000O00OOOOOo ) : continue
  if ( IiI == iI1iIii11i1i ) : continue
  ii1I = IiI
  break
  if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
 if ( ii1I == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 88 - 88: OoooooooOO . I1IiiI
  return
  if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
  if 7 - 7: i1IIi
  if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
  if 34 - 34: iII111i + i11iIiiIii . IiII
  if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
  if 29 - 29: II111iiii % i11iIiiIii % O0
  if 38 - 38: o0oOOo0O0Ooo * IiII
 OoOoOo00OoO = I1Ii1i111I . split ( "." )
 oOOoooOooOOOO = lisp_hex_string ( OoOoOo00OoO [ 1 ] ) . zfill ( 2 )
 Ii111II1I1I1 = lisp_hex_string ( OoOoOo00OoO [ 2 ] ) . zfill ( 2 )
 oOO0O0O = lisp_hex_string ( OoOoOo00OoO [ 3 ] ) . zfill ( 2 )
 iiiI1IiIIii = "00:00:00:{}:{}:{}" . format ( oOOoooOooOOOO , Ii111II1I1I1 , oOO0O0O )
 oOoOO0O0O = "0000.00{}.{}{}" . format ( oOOoooOooOOOO , Ii111II1I1I1 , oOO0O0O )
 oooO0000OoOOooo = "arp -i vlan4094 -s {} {}" . format ( ii1I , iiiI1IiIIii )
 os . system ( oooO0000OoOOooo )
 if 52 - 52: iIii1I11I1II1 + O0
 if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
 if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
 if 29 - 29: iII111i % I1Ii111
 O000oo0o = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( oOoOO0O0O , I1Ii1i111I )
 if 6 - 6: oO0o * ooOoO0o . I1Ii111 / OOooOOo . OoOoOO00
 lisp_send_to_arista ( O000oo0o , None )
 if 4 - 4: Ii1I / II111iiii + o0oOOo0O0Ooo / IiII
 if 9 - 9: ooOoO0o + i1IIi / ooOoO0o / I11i * I1ii11iIi11i / OoooooooOO
 if 28 - 28: o0oOOo0O0Ooo
 if 97 - 97: I1Ii111 - I1Ii111 * OoO0O00 % II111iiii * IiII
 if 2 - 2: I1Ii111 % iII111i . OoooooooOO - o0oOOo0O0Ooo
 Ii11 = "ip route add {} via {}" . format ( II1 , ii1I )
 os . system ( Ii11 )
 if 63 - 63: oO0o / O0 - II111iiii * IiII
 lprint ( "Hardware programmed with commands:" )
 Ii11 = Ii11 . replace ( II1 , green ( II1 , False ) )
 lprint ( "  " + Ii11 )
 lprint ( "  " + oooO0000OoOOooo )
 O000oo0o = O000oo0o . replace ( I1Ii1i111I , red ( I1Ii1i111I , False ) )
 lprint ( "  " + O000oo0o )
 return
 if 4 - 4: IiII * O0 % i11iIiiIii % OoOoOO00
 if 29 - 29: I1ii11iIi11i % ooOoO0o . OOooOOo . Ii1I . IiII
 if 69 - 69: o0oOOo0O0Ooo . i11iIiiIii * I11i + IiII / I11i
 if 66 - 66: I1ii11iIi11i % I1Ii111 - i11iIiiIii % I11i
 if 62 - 62: i11iIiiIii % iIii1I11I1II1 / IiII . I1IiiI * O0
 if 17 - 17: I1ii11iIi11i - I1Ii111 % II111iiii + OOooOOo
 if 45 - 45: I1Ii111 + iII111i - iIii1I11I1II1 / Oo0Ooo
def lisp_clear_hardware_walk ( mc , parms ) :
 I1I11I1IIi = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( I1I11I1IIi ) )
 return ( [ True , None ] )
 if 92 - 92: iIii1I11I1II1 . OoO0O00 - I11i % I1ii11iIi11i / i11iIiiIii
 if 4 - 4: Oo0Ooo / I1IiiI * i1IIi . II111iiii
 if 13 - 13: i1IIi
 if 39 - 39: OOooOOo
 if 73 - 73: OoO0O00 . ooOoO0o
 if 13 - 13: o0oOOo0O0Ooo - OoOoOO00
 if 60 - 60: OoO0O00
 if 17 - 17: i11iIiiIii % i1IIi % I1IiiI % ooOoO0o + I1Ii111 + Oo0Ooo
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list , lisp_gleaned_groups
 global lisp_no_map_request_rate_limit
 if 16 - 16: iII111i . I1ii11iIi11i . oO0o . OoO0O00
 OoOOo = bold ( "User cleared" , False )
 O0oo0oOo = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( OoOOo , O0oo0oOo ) )
 if 30 - 30: iII111i . OoO0O00 . i11iIiiIii / I1ii11iIi11i * Oo0Ooo
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 38 - 38: IiII + II111iiii
 lisp_map_cache = lisp_cache ( )
 if 20 - 20: iII111i * I1IiiI * iII111i - o0oOOo0O0Ooo + i1IIi + ooOoO0o
 if 49 - 49: II111iiii * I1IiiI / oO0o
 if 50 - 50: Ii1I + O0 . I1IiiI * Oo0Ooo
 if 15 - 15: Oo0Ooo
 lisp_no_map_request_rate_limit = lisp_get_timestamp ( )
 if 53 - 53: OoooooooOO * O0 / iII111i * ooOoO0o % I1Ii111 + OOooOOo
 if 95 - 95: I1Ii111 % OoOoOO00 . IiII * iII111i % Ii1I
 if 18 - 18: iIii1I11I1II1 / ooOoO0o / I1Ii111 % oO0o * Ii1I
 if 14 - 14: oO0o
 if 72 - 72: iIii1I11I1II1 / II111iiii * II111iiii + I1IiiI + iIii1I11I1II1 + oO0o
 lisp_rloc_probe_list = { }
 if 46 - 46: I1Ii111
 if 23 - 23: Oo0Ooo * IiII - I1Ii111 . OoooooooOO
 if 78 - 78: OoOoOO00 - iIii1I11I1II1
 if 20 - 20: i1IIi
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 72 - 72: ooOoO0o . II111iiii
 if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
 if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
 if 18 - 18: o0oOOo0O0Ooo / OOooOOo
 lisp_rtr_list = { }
 if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
 if 100 - 100: O0
 if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
 if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
 lisp_gleaned_groups = { }
 if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
 if 38 - 38: Ii1I
 if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
 if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
 lisp_process_data_plane_restart ( True )
 return
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
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 80 - 80: IiII % i11iIiiIii
 IiIi1II = lisp_myrlocs [ 0 ]
 if 70 - 70: OoooooooOO + I1IiiI % Oo0Ooo
 if 45 - 45: I1Ii111 / iIii1I11I1II1 . I1IiiI
 if 60 - 60: OoooooooOO + i11iIiiIii - o0oOOo0O0Ooo . OoooooooOO + oO0o / ooOoO0o
 if 93 - 93: I1ii11iIi11i - ooOoO0o - Oo0Ooo + o0oOOo0O0Ooo . ooOoO0o
 if 98 - 98: II111iiii
 i1iIii = len ( packet ) + 28
 O0O = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( i1iIii ) , 0 , 64 ,
 17 , 0 , socket . htonl ( IiIi1II . address ) , socket . htonl ( rloc . address ) )
 O0O = lisp_ip_checksum ( O0O )
 if 56 - 56: i1IIi % IiII / I1Ii111
 O0I1II1 = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( i1iIii - 20 ) , 0 )
 if 1 - 1: I1IiiI / OoOoOO00 - oO0o + OoooooooOO
 if 51 - 51: ooOoO0o + Ii1I * o0oOOo0O0Ooo * I1IiiI / oO0o + OoO0O00
 if 92 - 92: oO0o * o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * OoooooooOO * Oo0Ooo
 if 86 - 86: iII111i / OoooooooOO * I1Ii111 % I1IiiI + Ii1I
 packet = lisp_packet ( O0O + O0I1II1 + packet )
 if 16 - 16: OoO0O00
 if 41 - 41: i1IIi
 if 72 - 72: OoooooooOO / i11iIiiIii - O0 . OoOoOO00
 if 41 - 41: IiII + oO0o * iIii1I11I1II1 % oO0o + IiII
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( IiIi1II )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( IiIi1II )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 64 - 64: I1ii11iIi11i % OoO0O00 + oO0o
 IIi11IiiiI11i = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  iiI1I = " {}" . format ( blue ( nat_info . hostname , False ) )
  iIIi11Ii1iII = bold ( "RLOC-probe request" , False )
 else :
  iiI1I = ""
  iIIi11Ii1iII = bold ( "RLOC-probe reply" , False )
  if 47 - 47: I1ii11iIi11i + Ii1I % I1Ii111 % OoO0O00 . IiII % i1IIi
  if 14 - 14: O0 / I1IiiI . I1ii11iIi11i
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( iIIi11Ii1iII , IIi11IiiiI11i , iiI1I , packet . encap_port ) )
 if 47 - 47: I1Ii111 * ooOoO0o / iII111i . O0
 if 61 - 61: II111iiii . OoO0O00 * OoO0O00 % II111iiii % OOooOOo * OoOoOO00
 if 82 - 82: Ii1I
 if 83 - 83: I1IiiI
 if 22 - 22: IiII / Ii1I + I1Ii111 % iIii1I11I1II1
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 75 - 75: OoOoOO00 % OoOoOO00 % o0oOOo0O0Ooo % I1ii11iIi11i + IiII
 i1iiiI1i = lisp_sockets [ 3 ]
 packet . send_packet ( i1iiiI1i , packet . outer_dest )
 del ( packet )
 return
 if 48 - 48: OoooooooOO + OoO0O00 % i11iIiiIii * OoooooooOO
 if 64 - 64: I1ii11iIi11i . I1Ii111
 if 81 - 81: IiII . ooOoO0o + O0 . ooOoO0o + iIii1I11I1II1
 if 68 - 68: i11iIiiIii . iII111i + OoooooooOO + II111iiii + iIii1I11I1II1 % I11i
 if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
 if 62 - 62: OoOoOO00 * oO0o - I1IiiI / Ii1I
 if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
 if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
def lisp_get_default_route_next_hops ( ) :
 if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
 if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
 if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
 if 9 - 9: i1IIi % iII111i / Ii1I
 if ( lisp_is_macos ( ) ) :
  oO00o00 = "route -n get default"
  oo00O0o0o = getoutput ( oO00o00 ) . split ( "\n" )
  iI1iii = i111IIiIiiI1 = None
  for OOoO0 in oo00O0o0o :
   if ( OOoO0 . find ( "gateway: " ) != - 1 ) : iI1iii = OOoO0 . split ( ": " ) [ 1 ]
   if ( OOoO0 . find ( "interface: " ) != - 1 ) : i111IIiIiiI1 = OOoO0 . split ( ": " ) [ 1 ]
   if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
  return ( [ [ i111IIiIiiI1 , iI1iii ] ] )
  if 83 - 83: iIii1I11I1II1
  if 92 - 92: OoO0O00 - iII111i
  if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
  if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
  if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
 oO00o00 = "ip route | egrep 'default via'"
 oo0Oo = getoutput ( oO00o00 ) . split ( "\n" )
 if 70 - 70: I1Ii111 % iIii1I11I1II1
 o0O0oOO0oOOo = [ ]
 for o0oo in oo0Oo :
  if ( o0oo . find ( " metric " ) != - 1 ) : continue
  O00o00o00OO0 = o0oo . split ( " " )
  try :
   ooOoO000OoO = O00o00o00OO0 . index ( "via" ) + 1
   if ( ooOoO000OoO >= len ( O00o00o00OO0 ) ) : continue
   i1iI = O00o00o00OO0 . index ( "dev" ) + 1
   if ( i1iI >= len ( O00o00o00OO0 ) ) : continue
  except :
   continue
   if 30 - 30: Oo0Ooo
   if 23 - 23: I11i . OoOoOO00 * iII111i % OoOoOO00 . OoooooooOO + I1IiiI
  o0O0oOO0oOOo . append ( [ O00o00o00OO0 [ i1iI ] , O00o00o00OO0 [ ooOoO000OoO ] ] )
  if 82 - 82: I1Ii111 + o0oOOo0O0Ooo - iII111i - Ii1I
 return ( o0O0oOO0oOOo )
 if 30 - 30: iII111i / iIii1I11I1II1
 if 69 - 69: OoooooooOO - I1Ii111
 if 57 - 57: i1IIi * IiII % ooOoO0o . I1Ii111 * iII111i * i11iIiiIii
 if 23 - 23: i1IIi % O0
 if 59 - 59: oO0o - I1IiiI * OoOoOO00
 if 98 - 98: OoO0O00 % OoooooooOO + OoooooooOO * OoOoOO00 / OoO0O00 + o0oOOo0O0Ooo
 if 25 - 25: OoO0O00 % OoOoOO00
def lisp_get_host_route_next_hop ( rloc ) :
 oO00o00 = "ip route | egrep '{} via'" . format ( rloc )
 o0oo = getoutput ( oO00o00 ) . split ( " " )
 if 15 - 15: OoO0O00 + I1ii11iIi11i
 try : OOOooo0OooOoO = o0oo . index ( "via" ) + 1
 except : return ( None )
 if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
 if ( OOOooo0OooOoO >= len ( o0oo ) ) : return ( None )
 return ( o0oo [ OOOooo0OooOoO ] )
 if 55 - 55: Oo0Ooo - OOooOOo - O0
 if 40 - 40: OoOoOO00 - OOooOOo
 if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
 if 35 - 35: II111iiii
 if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
 if 96 - 96: O0
 if 15 - 15: i1IIi . iIii1I11I1II1
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 iIi1Iiii11Ii1 = "none" if nh == None else nh
 if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , iIi1Iiii11Ii1 ) )
 if 11 - 11: I1IiiI % Ii1I * i11iIiiIii % OOooOOo + II111iiii
 if ( nh == None ) :
  ooOOOOOO0 = "ip route {} {}/32" . format ( install , dest )
 else :
  ooOOOOOO0 = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 61 - 61: I1Ii111 + I11i + I1IiiI
 os . system ( ooOOOOOO0 )
 return
 if 48 - 48: I11i
 if 67 - 67: o0oOOo0O0Ooo
 if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
 if 61 - 61: i11iIiiIii / Ii1I - OOooOOo . I1ii11iIi11i
 if 89 - 89: ooOoO0o % i11iIiiIii
 if 57 - 57: Oo0Ooo / ooOoO0o - O0 . ooOoO0o
 if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
 if 75 - 75: Ii1I
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
 OOoO0 = open ( lisp_checkpoint_filename , "w" )
 for oo0O00OOOOO in checkpoint_list :
  OOoO0 . write ( oo0O00OOOOO + "\n" )
  if 99 - 99: oO0o + I11i % i1IIi . iII111i
 OOoO0 . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
 if 65 - 65: OoO0O00
 if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
 if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
 if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
 if 74 - 74: OoOoOO00 + I1ii11iIi11i
 if 82 - 82: II111iiii
 if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 48 - 48: ooOoO0o + Oo0Ooo / Oo0Ooo
 OOoO0 = open ( lisp_checkpoint_filename , "r" )
 if 15 - 15: iIii1I11I1II1 . I1Ii111 * OoooooooOO * O0 % OOooOOo
 O0oo0oOo = 0
 for oo0O00OOOOO in OOoO0 :
  O0oo0oOo += 1
  oO0ooOOO = oo0O00OOOOO . split ( " rloc " )
  OOOO00 = [ ] if ( oO0ooOOO [ 1 ] in [ "native-forward\n" , "\n" ] ) else oO0ooOOO [ 1 ] . split ( ", " )
  if 53 - 53: Ii1I
  if 63 - 63: I11i % OoOoOO00
  OOOo0O00OO00O = [ ]
  for I1Ii1i111I in OOOO00 :
   OO0oooo = lisp_rloc ( False )
   O00o00o00OO0 = I1Ii1i111I . split ( " " )
   OO0oooo . rloc . store_address ( O00o00o00OO0 [ 0 ] )
   OO0oooo . priority = int ( O00o00o00OO0 [ 1 ] )
   OO0oooo . weight = int ( O00o00o00OO0 [ 2 ] )
   OOOo0O00OO00O . append ( OO0oooo )
   if 46 - 46: iIii1I11I1II1 . II111iiii / OoooooooOO - ooOoO0o * iII111i
   if 52 - 52: I11i + iII111i
  o0ooo0oOO0o = lisp_mapping ( "" , "" , OOOo0O00OO00O )
  if ( o0ooo0oOO0o != None ) :
   o0ooo0oOO0o . eid . store_prefix ( oO0ooOOO [ 0 ] )
   o0ooo0oOO0o . checkpoint_entry = True
   o0ooo0oOO0o . map_cache_ttl = LISP_NMR_TTL * 60
   if ( OOOo0O00OO00O == [ ] ) : o0ooo0oOO0o . action = LISP_NATIVE_FORWARD_ACTION
   o0ooo0oOO0o . add_cache ( )
   continue
   if 9 - 9: OoOoOO00 % II111iiii . I11i * Oo0Ooo
   if 53 - 53: II111iiii / i1IIi + OoooooooOO * O0
  O0oo0oOo -= 1
  if 62 - 62: IiII . O0
  if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
 OOoO0 . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , O0oo0oOo , lisp_checkpoint_filename ) )
 return
 if 91 - 91: OOooOOo % oO0o . OoOoOO00 . I1IiiI - OoOoOO00
 if 18 - 18: O0 - I1IiiI + i1IIi % i11iIiiIii
 if 97 - 97: iII111i * OoooooooOO + I1Ii111 + ooOoO0o - ooOoO0o
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
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 3 - 3: OoOoOO00 / OoOoOO00 - II111iiii
 oo0O00OOOOO = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 41 - 41: oO0o
 for OO0oooo in mc . rloc_set :
  if ( OO0oooo . rloc . is_null ( ) ) : continue
  oo0O00OOOOO += "{} {} {}, " . format ( OO0oooo . rloc . print_address_no_iid ( ) ,
 OO0oooo . priority , OO0oooo . weight )
  if 12 - 12: I1IiiI + I1Ii111
  if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
 if ( mc . rloc_set != [ ] ) :
  oo0O00OOOOO = oo0O00OOOOO [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  oo0O00OOOOO += "native-forward"
  if 74 - 74: O0 % OOooOOo * OoOoOO00 / oO0o - Oo0Ooo
  if 79 - 79: Ii1I + IiII
 checkpoint_list . append ( oo0O00OOOOO )
 return
 if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
 if 98 - 98: I1ii11iIi11i
 if 58 - 58: IiII / i11iIiiIii % I11i
 if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
 if 21 - 21: Ii1I
 if 72 - 72: I1Ii111 . OoooooooOO / I1Ii111 - Ii1I / I1ii11iIi11i * I1ii11iIi11i
 if 72 - 72: IiII . Ii1I + OoooooooOO * OoOoOO00 + Oo0Ooo . iII111i
def lisp_check_dp_socket ( ) :
 OoO0OOo0OOoOO = lisp_ipc_dp_socket_name
 if ( os . path . exists ( OoO0OOo0OOoOO ) == False ) :
  oOOOooo0OoO = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( OoO0OOo0OOoOO , oOOOooo0OoO ) )
  return ( False )
  if 26 - 26: i1IIi + OoOoOO00 % OOooOOo . ooOoO0o % o0oOOo0O0Ooo . Oo0Ooo
 return ( True )
 if 19 - 19: OoO0O00 + I1Ii111 + oO0o
 if 48 - 48: O0 * ooOoO0o
 if 14 - 14: OOooOOo * OoO0O00
 if 75 - 75: iIii1I11I1II1 . I1IiiI
 if 22 - 22: OoOoOO00 . OoooooooOO * oO0o . O0
 if 14 - 14: II111iiii * I1IiiI * O0 % I11i
 if 48 - 48: i1IIi . o0oOOo0O0Ooo
def lisp_write_to_dp_socket ( entry ) :
 try :
  IIiI11 = json . dumps ( entry )
  I1Ii1IIiIi = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( I1Ii1IIiIi , IIiI11 ) )
  lisp_ipc_dp_socket . sendto ( IIiI11 , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( IIiI11 ) )
  if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
 return
 if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
 if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
 if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
 if 16 - 16: I11i
 if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
 if 61 - 61: O0 % iII111i
 if 41 - 41: I1Ii111 * OoooooooOO
 if 76 - 76: OoooooooOO * II111iiii . II111iiii / o0oOOo0O0Ooo - iII111i
 if 49 - 49: O0 . I1ii11iIi11i . OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
def lisp_write_ipc_keys ( rloc ) :
 O0O0 = rloc . rloc . print_address_no_iid ( )
 I1I = rloc . translated_port
 if ( I1I != 0 ) : O0O0 += ":" + str ( I1I )
 if ( O0O0 not in lisp_rloc_probe_list ) : return
 if 19 - 19: iIii1I11I1II1
 for O00o00o00OO0 , oO0ooOOO , Oo in lisp_rloc_probe_list [ O0O0 ] :
  o0ooo0oOO0o = lisp_map_cache . lookup_cache ( oO0ooOOO , True )
  if ( o0ooo0oOO0o == None ) : continue
  lisp_write_ipc_map_cache ( True , o0ooo0oOO0o )
  if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
 return
 if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
 if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
 if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
 if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
 if 57 - 57: i1IIi
 if 41 - 41: I11i / Ii1I
 if 1 - 1: II111iiii / iII111i
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 83 - 83: OoO0O00 / iII111i
 if 59 - 59: I1Ii111 % OOooOOo . I1IiiI + I1ii11iIi11i % oO0o
 if 96 - 96: OoO0O00
 if 53 - 53: oO0o + OoO0O00
 oOOoo = "add" if add_or_delete else "delete"
 oo0O00OOOOO = { "type" : "map-cache" , "opcode" : oOOoo }
 if 58 - 58: iIii1I11I1II1 + OoOoOO00
 iII1iii1iII1iI1II = ( mc . group . is_null ( ) == False )
 if ( iII1iii1iII1iI1II ) :
  oo0O00OOOOO [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  oo0O00OOOOO [ "rles" ] = [ ]
 else :
  oo0O00OOOOO [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  oo0O00OOOOO [ "rlocs" ] = [ ]
  if 65 - 65: iII111i % Oo0Ooo * iIii1I11I1II1 + I1IiiI + II111iiii
 oo0O00OOOOO [ "instance-id" ] = str ( mc . eid . instance_id )
 if 72 - 72: OoOoOO00 . OoooooooOO - OOooOOo
 if ( iII1iii1iII1iI1II ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for iI11i1ii11i11 in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    IiI = iI11i1ii11i11 . address . print_address_no_iid ( )
    I1I = str ( 4341 ) if iI11i1ii11i11 . translated_port == 0 else str ( iI11i1ii11i11 . translated_port )
    if 15 - 15: OoOoOO00
    O00o00o00OO0 = { "rle" : IiI , "port" : I1I }
    iI1II1I1i1 , III1ii1Ii = iI11i1ii11i11 . get_encap_keys ( )
    O00o00o00OO0 = lisp_build_json_keys ( O00o00o00OO0 , iI1II1I1i1 , III1ii1Ii , "encrypt-key" )
    oo0O00OOOOO [ "rles" ] . append ( O00o00o00OO0 )
    if 88 - 88: Ii1I - OoO0O00 * OoooooooOO - I1IiiI * I1ii11iIi11i
    if 52 - 52: oO0o % iII111i - I1IiiI - o0oOOo0O0Ooo
 else :
  for I1Ii1i111I in mc . rloc_set :
   if ( I1Ii1i111I . rloc . is_ipv4 ( ) == False and I1Ii1i111I . rloc . is_ipv6 ( ) == False ) :
    continue
    if 66 - 66: o0oOOo0O0Ooo - Oo0Ooo - OoooooooOO * o0oOOo0O0Ooo + I1Ii111
   if ( I1Ii1i111I . up_state ( ) == False ) : continue
   if 82 - 82: I11i * i1IIi / Ii1I + O0
   I1I = str ( 4341 ) if I1Ii1i111I . translated_port == 0 else str ( I1Ii1i111I . translated_port )
   if 85 - 85: O0 + oO0o / I1Ii111
   O00o00o00OO0 = { "rloc" : I1Ii1i111I . rloc . print_address_no_iid ( ) , "priority" :
 str ( I1Ii1i111I . priority ) , "weight" : str ( I1Ii1i111I . weight ) , "port" :
 I1I }
   iI1II1I1i1 , III1ii1Ii = I1Ii1i111I . get_encap_keys ( )
   O00o00o00OO0 = lisp_build_json_keys ( O00o00o00OO0 , iI1II1I1i1 , III1ii1Ii , "encrypt-key" )
   oo0O00OOOOO [ "rlocs" ] . append ( O00o00o00OO0 )
   if 65 - 65: o0oOOo0O0Ooo . Oo0Ooo . i1IIi / IiII . I11i . O0
   if 69 - 69: Oo0Ooo - i11iIiiIii
   if 87 - 87: Oo0Ooo % OOooOOo - Ii1I
 if ( dont_send == False ) : lisp_write_to_dp_socket ( oo0O00OOOOO )
 return ( oo0O00OOOOO )
 if 34 - 34: iII111i / Ii1I / I1IiiI * i11iIiiIii
 if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
 if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
 if 71 - 71: oO0o
 if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
 if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
 if 16 - 16: I1Ii111 + O0 - O0 * iIii1I11I1II1 / iII111i
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 4 - 4: iII111i
 if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
 if 32 - 32: iII111i
 if 59 - 59: OoOoOO00 - I1Ii111
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 34 - 34: ooOoO0o . OoooooooOO / ooOoO0o + OoooooooOO
 iI1II1I1i1 = keys [ 1 ] . encrypt_key
 III1ii1Ii = keys [ 1 ] . icv_key
 if 24 - 24: OoooooooOO * I1ii11iIi11i / O0 / Oo0Ooo * I1IiiI / ooOoO0o
 if 33 - 33: Ii1I
 if 20 - 20: Ii1I + I11i
 if 98 - 98: OOooOOo
 ooOooOoOOoo0Oo00O = rloc_addr . split ( ":" )
 if ( len ( ooOooOoOOoo0Oo00O ) == 1 ) :
  oo0O00OOOOO = { "type" : "decap-keys" , "rloc" : ooOooOoOOoo0Oo00O [ 0 ] }
 else :
  oo0O00OOOOO = { "type" : "decap-keys" , "rloc" : ooOooOoOOoo0Oo00O [ 0 ] , "port" : ooOooOoOOoo0Oo00O [ 1 ] }
  if 45 - 45: iII111i + Ii1I + oO0o + iII111i - OoOoOO00 + i1IIi
 oo0O00OOOOO = lisp_build_json_keys ( oo0O00OOOOO , iI1II1I1i1 , III1ii1Ii , "decrypt-key" )
 if 64 - 64: OoooooooOO
 lisp_write_to_dp_socket ( oo0O00OOOOO )
 return
 if 19 - 19: II111iiii
 if 55 - 55: ooOoO0o . i11iIiiIii . o0oOOo0O0Ooo
 if 52 - 52: IiII . oO0o + i11iIiiIii % IiII
 if 45 - 45: i1IIi - I1IiiI / IiII - I1IiiI
 if 21 - 21: IiII
 if 43 - 43: IiII
 if 9 - 9: OOooOOo * ooOoO0o + ooOoO0o . I1Ii111
 if 8 - 8: IiII * iIii1I11I1II1
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 7 - 7: I1Ii111 / OoooooooOO % O0 - I1ii11iIi11i
 entry [ "keys" ] = [ ]
 Ooo00o000o = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( Ooo00o000o )
 return ( entry )
 if 49 - 49: OoooooooOO . I1ii11iIi11i / OoooooooOO * oO0o
 if 81 - 81: I1ii11iIi11i . ooOoO0o + I1ii11iIi11i
 if 84 - 84: OoooooooOO
 if 95 - 95: o0oOOo0O0Ooo
 if 22 - 22: ooOoO0o / o0oOOo0O0Ooo - OoooooooOO / Oo0Ooo - I1Ii111 / OOooOOo
 if 41 - 41: oO0o . II111iiii
 if 47 - 47: I1ii11iIi11i
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 5 - 5: Oo0Ooo
 if 23 - 23: i11iIiiIii / I11i + i1IIi % I1Ii111
 if 100 - 100: Oo0Ooo
 if 13 - 13: I1IiiI + ooOoO0o * II111iiii
 oo0O00OOOOO = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 32 - 32: iIii1I11I1II1 + O0 + i1IIi
 if 28 - 28: IiII + I11i
 if 1 - 1: OoooooooOO - i11iIiiIii . OoooooooOO - o0oOOo0O0Ooo - OOooOOo * I1Ii111
 if 56 - 56: Ii1I . OoO0O00
 for i11IIII1Ii in lisp_db_list :
  if ( i11IIII1Ii . eid . is_ipv4 ( ) == False and i11IIII1Ii . eid . is_ipv6 ( ) == False ) : continue
  i11iIIiiii1I1 = { "instance-id" : str ( i11IIII1Ii . eid . instance_id ) ,
 "eid-prefix" : i11IIII1Ii . eid . print_prefix_no_iid ( ) }
  oo0O00OOOOO [ "database-mappings" ] . append ( i11iIIiiii1I1 )
  if 35 - 35: IiII / Oo0Ooo . Ii1I % OoO0O00 / i11iIiiIii % I11i
 lisp_write_to_dp_socket ( oo0O00OOOOO )
 if 96 - 96: O0 % I1Ii111 * II111iiii - iII111i / IiII . I11i
 if 8 - 8: I1ii11iIi11i / i11iIiiIii
 if 98 - 98: OoooooooOO
 if 13 - 13: II111iiii / Ii1I - iII111i
 if 67 - 67: I1IiiI + OOooOOo * oO0o
 oo0O00OOOOO = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( oo0O00OOOOO )
 return
 if 41 - 41: OoooooooOO * I1IiiI
 if 3 - 3: IiII
 if 96 - 96: I11i - OOooOOo + I11i
 if 71 - 71: Oo0Ooo
 if 48 - 48: o0oOOo0O0Ooo / II111iiii / OoOoOO00 * o0oOOo0O0Ooo + I1IiiI . OoOoOO00
 if 52 - 52: Ii1I / OoOoOO00 . OOooOOo * IiII . OoooooooOO
 if 6 - 6: i1IIi . oO0o % IiII . Oo0Ooo % I11i
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 86 - 86: OoooooooOO + IiII % o0oOOo0O0Ooo . i1IIi . iII111i
 if 25 - 25: iII111i * I1ii11iIi11i + I11i - I1ii11iIi11i
 if 75 - 75: IiII
 if 74 - 74: o0oOOo0O0Ooo - iIii1I11I1II1
 oo0O00OOOOO = { "type" : "interfaces" , "interfaces" : [ ] }
 if 92 - 92: i11iIiiIii * iIii1I11I1II1 - I1Ii111 . i1IIi
 for i111IIiIiiI1 in list ( lisp_myinterfaces . values ( ) ) :
  if ( i111IIiIiiI1 . instance_id == None ) : continue
  i11iIIiiii1I1 = { "interface" : i111IIiIiiI1 . device ,
 "instance-id" : str ( i111IIiIiiI1 . instance_id ) }
  oo0O00OOOOO [ "interfaces" ] . append ( i11iIIiiii1I1 )
  if 23 - 23: O0 - O0 . I1Ii111 . I1IiiI - I1IiiI * i1IIi
  if 8 - 8: I1IiiI . I1ii11iIi11i + oO0o % oO0o * oO0o
 lisp_write_to_dp_socket ( oo0O00OOOOO )
 return
 if 70 - 70: II111iiii + IiII + O0 / Ii1I - i11iIiiIii
 if 72 - 72: II111iiii - II111iiii
 if 44 - 44: o0oOOo0O0Ooo + OoooooooOO
 if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
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
def lisp_parse_auth_key ( value ) :
 I1i1IIIi1iii = value . split ( "[" )
 OO0O0o0O00Ooo = { }
 if ( len ( I1i1IIIi1iii ) == 1 ) :
  OO0O0o0O00Ooo [ 0 ] = value
  return ( OO0O0o0O00Ooo )
  if 95 - 95: I11i * OoO0O00 - oO0o - OoooooooOO
  if 1 - 1: OOooOOo + o0oOOo0O0Ooo + o0oOOo0O0Ooo . OOooOOo - ooOoO0o . I1ii11iIi11i
 for oO0o0O0O0O in I1i1IIIi1iii :
  if ( oO0o0O0O0O == "" ) : continue
  OOOooo0OooOoO = oO0o0O0O0O . find ( "]" )
  i11iII1 = oO0o0O0O0O [ 0 : OOOooo0OooOoO ]
  try : i11iII1 = int ( i11iII1 )
  except : return
  if 21 - 21: Oo0Ooo * I1IiiI . I1IiiI
  OO0O0o0O00Ooo [ i11iII1 ] = oO0o0O0O0O [ OOOooo0OooOoO + 1 : : ]
  if 27 - 27: I1Ii111 + OOooOOo - oO0o / O0 - O0
 return ( OO0O0o0O00Ooo )
 if 95 - 95: O0 % I1ii11iIi11i . O0 . OOooOOo * i11iIiiIii - oO0o
 if 2 - 2: OOooOOo + II111iiii
 if 30 - 30: IiII
 if 99 - 99: O0 / OoO0O00 * II111iiii . II111iiii
 if 14 - 14: OoOoOO00 * i1IIi - OoOoOO00 . OoooooooOO
 if 24 - 24: iIii1I11I1II1 + OOooOOo * iII111i % IiII % OOooOOo
 if 64 - 64: IiII . I1ii11iIi11i - o0oOOo0O0Ooo - ooOoO0o + OoooooooOO
 if 95 - 95: iII111i . I1ii11iIi11i + ooOoO0o + o0oOOo0O0Ooo % OoO0O00
 if 50 - 50: iII111i * O0 % II111iiii
 if 80 - 80: OOooOOo - II111iiii - OoO0O00
 if 62 - 62: Ii1I . i11iIiiIii % OOooOOo
 if 44 - 44: i1IIi * I1ii11iIi11i % Ii1I . Ii1I * I11i + II111iiii
 if 15 - 15: i1IIi - I11i - I1Ii111 / OoO0O00 + Oo0Ooo + I1IiiI
 if 81 - 81: IiII
 if 54 - 54: I1IiiI % OoO0O00 % OoOoOO00
 if 12 - 12: II111iiii . O0 * i11iIiiIii . I11i
def lisp_reassemble ( packet ) :
 i1i1IIi = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 98 - 98: II111iiii + i1IIi * oO0o % I1IiiI
 if 53 - 53: i11iIiiIii . I1ii11iIi11i - OOooOOo - OOooOOo
 if 97 - 97: I1IiiI % iII111i % OoooooooOO / ooOoO0o / i11iIiiIii
 if 7 - 7: O0 % IiII / o0oOOo0O0Ooo
 if ( i1i1IIi == 0 or i1i1IIi == 0x4000 ) : return ( packet )
 if 79 - 79: IiII + I1Ii111
 if 59 - 59: iII111i - oO0o . ooOoO0o / IiII * i11iIiiIii
 if 61 - 61: I11i - Oo0Ooo * II111iiii + iIii1I11I1II1
 if 37 - 37: OoooooooOO % II111iiii / o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i . iIii1I11I1II1
 Ii1o0OOOoo0000 = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 OO0OOo00O = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 73 - 73: OoOoOO00
 iIIi = ( i1i1IIi & 0x2000 == 0 and ( i1i1IIi & 0x1fff ) != 0 )
 oo0O00OOOOO = [ ( i1i1IIi & 0x1fff ) * 8 , OO0OOo00O - 20 , packet , iIIi ]
 if 88 - 88: Oo0Ooo / ooOoO0o + II111iiii + OoooooooOO * iIii1I11I1II1
 if 82 - 82: i1IIi - I11i % ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo
 if 20 - 20: i11iIiiIii - O0 / i11iIiiIii
 if 51 - 51: iII111i . ooOoO0o
 if 70 - 70: I11i / O0 - I11i + o0oOOo0O0Ooo . ooOoO0o . o0oOOo0O0Ooo
 if 6 - 6: I11i + II111iiii - I1Ii111
 if 45 - 45: i1IIi / iII111i + i11iIiiIii * I11i + ooOoO0o / OoooooooOO
 if 56 - 56: I11i + I1Ii111
 if ( i1i1IIi == 0x2000 ) :
  oooooO0oO0ooO , iIII1IiI = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  oooooO0oO0ooO = socket . ntohs ( oooooO0oO0ooO )
  iIII1IiI = socket . ntohs ( iIII1IiI )
  if ( iIII1IiI not in [ 4341 , 8472 , 4789 ] and oooooO0oO0ooO != 4341 ) :
   lisp_reassembly_queue [ Ii1o0OOOoo0000 ] = [ ]
   oo0O00OOOOO [ 2 ] = None
   if 80 - 80: II111iiii . Ii1I + o0oOOo0O0Ooo / II111iiii / OoO0O00 + iIii1I11I1II1
   if 29 - 29: o0oOOo0O0Ooo + OoOoOO00 + ooOoO0o - I1ii11iIi11i
   if 64 - 64: O0 / OoooooooOO
   if 28 - 28: I1ii11iIi11i + oO0o . Oo0Ooo % iIii1I11I1II1 / I1Ii111
   if 8 - 8: O0 . I1IiiI * o0oOOo0O0Ooo + I1IiiI
   if 44 - 44: i1IIi % iII111i . i11iIiiIii / I11i + OoooooooOO
 if ( Ii1o0OOOoo0000 not in lisp_reassembly_queue ) :
  lisp_reassembly_queue [ Ii1o0OOOoo0000 ] = [ ]
  if 21 - 21: OoOoOO00 . OoO0O00 . OoOoOO00 + OoOoOO00
  if 30 - 30: I1IiiI - iII111i - OOooOOo + oO0o
  if 51 - 51: Ii1I % O0 / II111iiii . Oo0Ooo
  if 90 - 90: i11iIiiIii * II111iiii % iIii1I11I1II1 . I1ii11iIi11i / Oo0Ooo . OOooOOo
  if 77 - 77: OoO0O00
 queue = lisp_reassembly_queue [ Ii1o0OOOoo0000 ]
 if 95 - 95: II111iiii
 if 59 - 59: iIii1I11I1II1 % OOooOOo / OoOoOO00 * I1Ii111 * OoooooooOO * O0
 if 43 - 43: OoO0O00 * I1IiiI * OOooOOo * O0 - O0 / o0oOOo0O0Ooo
 if 77 - 77: I11i % I1Ii111 . IiII % OoooooooOO * o0oOOo0O0Ooo
 if 87 - 87: iII111i + IiII / ooOoO0o * ooOoO0o * OOooOOo
 if ( len ( queue ) == 1 and queue [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( Ii1o0OOOoo0000 ) . zfill ( 4 ) ) )
  if 97 - 97: I1Ii111
  return ( None )
  if 47 - 47: iII111i / I1ii11iIi11i - Ii1I . II111iiii
  if 56 - 56: O0 - i1IIi % o0oOOo0O0Ooo + IiII
  if 42 - 42: o0oOOo0O0Ooo . OOooOOo % I11i - OoOoOO00
  if 38 - 38: OoooooooOO
  if 27 - 27: O0 + I1ii11iIi11i % Ii1I . i1IIi + OoO0O00 + OoOoOO00
 queue . append ( oo0O00OOOOO )
 queue = sorted ( queue )
 if 22 - 22: II111iiii / I1IiiI + o0oOOo0O0Ooo * I1IiiI . OoooooooOO * OOooOOo
 if 49 - 49: I1ii11iIi11i * I1IiiI + OOooOOo + i11iIiiIii * I1ii11iIi11i . o0oOOo0O0Ooo
 if 36 - 36: o0oOOo0O0Ooo - i11iIiiIii
 if 37 - 37: O0 + IiII + I1IiiI
 IiI = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 IiI . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 ii1o0O00o0o000o = IiI . print_address_no_iid ( )
 IiI . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 iIiI = IiI . print_address_no_iid ( )
 IiI = red ( "{} -> {}" . format ( ii1o0O00o0o000o , iIiI ) , False )
 if 68 - 68: Ii1I % o0oOOo0O0Ooo / OoooooooOO + Ii1I - Ii1I
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if oo0O00OOOOO [ 2 ] == None else "" , IiI , lisp_hex_string ( Ii1o0OOOoo0000 ) . zfill ( 4 ) ,
 # i1IIi / IiII / Ii1I . O0 - Ii1I
 # IiII
 lisp_hex_string ( i1i1IIi ) . zfill ( 4 ) ) )
 if 96 - 96: ooOoO0o . ooOoO0o * oO0o % iIii1I11I1II1
 if 29 - 29: O0 % OoooooooOO + IiII . IiII * II111iiii
 if 54 - 54: O0
 if 1 - 1: Ii1I
 if 76 - 76: II111iiii % o0oOOo0O0Ooo . OoooooooOO / I1Ii111 % i1IIi
 if ( queue [ 0 ] [ 0 ] != 0 or queue [ - 1 ] [ 3 ] == False ) : return ( None )
 o0Oo = queue [ 0 ]
 for Ii in queue [ 1 : : ] :
  i1i1IIi = Ii [ 0 ]
  O00OO0OOo , IiII1I1 = o0Oo [ 0 ] , o0Oo [ 1 ]
  if ( O00OO0OOo + IiII1I1 != i1i1IIi ) : return ( None )
  o0Oo = Ii
  if 29 - 29: IiII
 lisp_reassembly_queue . pop ( Ii1o0OOOoo0000 )
 if 45 - 45: I11i * I1ii11iIi11i * Ii1I
 if 43 - 43: OoO0O00 + IiII * Ii1I
 if 15 - 15: I1IiiI / O0 % I1ii11iIi11i % OoOoOO00 . OoOoOO00 + iII111i
 if 79 - 79: OOooOOo + Ii1I . I1Ii111 / Oo0Ooo / i11iIiiIii / O0
 if 28 - 28: i1IIi % OoO0O00 / i1IIi - o0oOOo0O0Ooo
 packet = queue [ 0 ] [ 2 ]
 for Ii in queue [ 1 : : ] : packet += Ii [ 2 ] [ 20 : : ]
 if 97 - 97: II111iiii + O0 . Ii1I + OoooooooOO
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( Ii1o0OOOoo0000 ) . zfill ( 4 ) , len ( packet ) ) )
 if 39 - 39: i11iIiiIii + OoO0O00 + I11i * oO0o + iIii1I11I1II1 % o0oOOo0O0Ooo
 if 25 - 25: OoooooooOO
 if 78 - 78: oO0o / i11iIiiIii * O0 / OOooOOo % i11iIiiIii % O0
 if 86 - 86: IiII
 if 26 - 26: IiII - I1Ii111 + i11iIiiIii % ooOoO0o * i11iIiiIii + Oo0Ooo
 i1iIii = socket . htons ( len ( packet ) )
 ooo = packet [ 0 : 2 ] + struct . pack ( "H" , i1iIii ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 39 - 39: Ii1I - i1IIi + i11iIiiIii
 if 21 - 21: IiII
 ooo = lisp_ip_checksum ( ooo )
 return ( ooo + packet [ 20 : : ] )
 if 76 - 76: o0oOOo0O0Ooo % Oo0Ooo + OoO0O00
 if 36 - 36: OOooOOo . oO0o
 if 15 - 15: I1IiiI + ooOoO0o - o0oOOo0O0Ooo
 if 62 - 62: Ii1I - OOooOOo
 if 88 - 88: iIii1I11I1II1 * Oo0Ooo / II111iiii / IiII / OoO0O00 % ooOoO0o
 if 19 - 19: I11i * iII111i . O0 * iII111i % I1ii11iIi11i - OoOoOO00
 if 68 - 68: I1Ii111 - OoO0O00 % Ii1I + i1IIi . ooOoO0o
 if 36 - 36: oO0o * iIii1I11I1II1 - O0 - IiII * O0 + i11iIiiIii
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 O0O0 = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( O0O0 in lisp_crypto_keys_by_rloc_decap ) : return ( O0O0 )
 if 76 - 76: OoO0O00 % O0 / Ii1I + I1IiiI
 O0O0 = addr . print_address_no_iid ( )
 if ( O0O0 in lisp_crypto_keys_by_rloc_decap ) : return ( O0O0 )
 if 23 - 23: I1IiiI % IiII . o0oOOo0O0Ooo
 if 2 - 2: I1ii11iIi11i
 if 51 - 51: iIii1I11I1II1 / II111iiii / iIii1I11I1II1 / oO0o % i1IIi
 if 54 - 54: ooOoO0o
 if 47 - 47: I11i * I1IiiI / oO0o
 for O00OO in lisp_crypto_keys_by_rloc_decap :
  OO0O00o0 = O00OO . split ( ":" )
  if ( len ( OO0O00o0 ) == 1 ) : continue
  OO0O00o0 = OO0O00o0 [ 0 ] if len ( OO0O00o0 ) == 2 else ":" . join ( OO0O00o0 [ 0 : - 1 ] )
  if ( OO0O00o0 == O0O0 ) :
   iI1iiiiiii = lisp_crypto_keys_by_rloc_decap [ O00OO ]
   lisp_crypto_keys_by_rloc_decap [ O0O0 ] = iI1iiiiiii
   return ( O0O0 )
   if 10 - 10: OoO0O00 * iII111i * iIii1I11I1II1 . i1IIi
   if 43 - 43: oO0o * ooOoO0o - I11i
 return ( None )
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
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 I1iiI = addr + ":" + str ( port )
 if 65 - 65: ooOoO0o + I11i
 if ( lisp_i_am_rtr ) :
  if ( addr in lisp_rloc_probe_list ) : return ( addr )
  if 99 - 99: Oo0Ooo * OoooooooOO
  if 94 - 94: oO0o + ooOoO0o
  if 69 - 69: iII111i . iII111i
  if 46 - 46: IiII * Oo0Ooo + I1Ii111
  if 79 - 79: IiII
  if 89 - 89: IiII * I11i + I1ii11iIi11i * oO0o - II111iiii
  for OOoOoO0O in list ( lisp_nat_state_info . values ( ) ) :
   for Ooo0000 in OOoOoO0O :
    if ( addr == Ooo0000 . address ) : return ( I1iiI )
    if 58 - 58: ooOoO0o . I1Ii111 / i1IIi % I1ii11iIi11i + o0oOOo0O0Ooo
    if 94 - 94: i11iIiiIii + I1Ii111 . iII111i - ooOoO0o % I1Ii111
  return ( addr )
  if 94 - 94: i11iIiiIii - OOooOOo - O0 * OoooooooOO - ooOoO0o
 return ( I1iiI )
 if 35 - 35: iII111i . i11iIiiIii - OOooOOo % Oo0Ooo + Ii1I . iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo / OoO0O00 + I1IiiI % i11iIiiIii % i1IIi
 if 22 - 22: I1Ii111 * O0 % OoO0O00 * I1ii11iIi11i
 if 47 - 47: OoO0O00 / OOooOOo / OoOoOO00 % i11iIiiIii / OoOoOO00
 if 52 - 52: ooOoO0o / I11i % i11iIiiIii - I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
 if 67 - 67: OoOoOO00 / I1Ii111 + i11iIiiIii - IiII
 if 79 - 79: I11i . I11i - OoOoOO00
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_MULTICAST_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 86 - 86: OoO0O00 * Oo0Ooo . iIii1I11I1II1 * O0
 return
 if 52 - 52: iII111i - i11iIiiIii + o0oOOo0O0Ooo + i1IIi
 if 58 - 58: OOooOOo - Ii1I * I1Ii111 - O0 . oO0o
 if 72 - 72: i1IIi * iII111i * Ii1I / o0oOOo0O0Ooo . I1Ii111 + i11iIiiIii
 if 33 - 33: I11i / OoO0O00 * ooOoO0o + iIii1I11I1II1
 if 54 - 54: Oo0Ooo / IiII + i11iIiiIii . O0
 if 94 - 94: OoooooooOO + iII111i * OoooooooOO / o0oOOo0O0Ooo
 if 12 - 12: iIii1I11I1II1 / iIii1I11I1II1 / II111iiii
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 93 - 93: oO0o
 if 53 - 53: OoO0O00 * i1IIi / Oo0Ooo / OoO0O00 * ooOoO0o
 if 77 - 77: iIii1I11I1II1 % I1IiiI + o0oOOo0O0Ooo + I1Ii111 * Oo0Ooo * i1IIi
 if 14 - 14: iIii1I11I1II1 * iIii1I11I1II1 - OOooOOo . iII111i / ooOoO0o
 if 54 - 54: OoOoOO00 - I1IiiI - iII111i
 if 49 - 49: i11iIiiIii * Oo0Ooo
 if 100 - 100: Oo0Ooo * oO0o
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
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
 if 68 - 68: O0 % oO0o * IiII % O0
 if 55 - 55: O0 % I1IiiI % O0
 if 27 - 27: I1IiiI + I1ii11iIi11i * I1Ii111 % Ii1I - Oo0Ooo
 if 87 - 87: i11iIiiIii % OOooOOo - OoOoOO00 * ooOoO0o / Oo0Ooo
 if 74 - 74: OoooooooOO * ooOoO0o - I11i / I1ii11iIi11i % iIii1I11I1II1
 if 94 - 94: Ii1I * I1Ii111 + OoOoOO00 . iIii1I11I1II1
 if 44 - 44: Oo0Ooo . Oo0Ooo * Oo0Ooo
 if 23 - 23: I1Ii111 / iII111i . O0 % II111iiii
 if 67 - 67: I11i / iIii1I11I1II1 / ooOoO0o
def lisp_is_rloc_probe ( packet , rr ) :
 O0I1II1 = ( struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ] == 17 )
 if ( O0I1II1 == False ) : return ( [ packet , None , None , None ] )
 if 90 - 90: II111iiii % I1Ii111 - IiII . Oo0Ooo % OOooOOo - OoOoOO00
 oooooO0oO0ooO = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 iIII1IiI = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 oOoO0O00 = ( socket . htons ( LISP_CTRL_PORT ) in [ oooooO0oO0ooO , iIII1IiI ] )
 if ( oOoO0O00 == False ) : return ( [ packet , None , None , None ] )
 if 100 - 100: iII111i % i11iIiiIii % I1Ii111
 if ( rr == 0 ) :
  iIIi11Ii1iII = lisp_is_rloc_probe_request ( packet [ 28 : 29 ] )
  if ( iIIi11Ii1iII == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  iIIi11Ii1iII = lisp_is_rloc_probe_reply ( packet [ 28 : 29 ] )
  if ( iIIi11Ii1iII == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  iIIi11Ii1iII = lisp_is_rloc_probe_request ( packet [ 28 : 29 ] )
  if ( iIIi11Ii1iII == False ) :
   iIIi11Ii1iII = lisp_is_rloc_probe_reply ( packet [ 28 : 29 ] )
   if ( iIIi11Ii1iII == False ) : return ( [ packet , None , None , None ] )
   if 77 - 77: OoOoOO00 . IiII
   if 86 - 86: I1Ii111 + iII111i . Ii1I
   if 65 - 65: i11iIiiIii % i11iIiiIii
   if 82 - 82: I1ii11iIi11i - OoooooooOO . OoooooooOO - OoO0O00 / iII111i
   if 32 - 32: Ii1I / o0oOOo0O0Ooo * I1Ii111 * i11iIiiIii * I11i
   if 14 - 14: oO0o
 I1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 I1 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 27 - 27: Ii1I + Ii1I
 if 32 - 32: OOooOOo % OOooOOo + I1ii11iIi11i / Ii1I - i11iIiiIii
 if 28 - 28: iIii1I11I1II1 - II111iiii
 if 36 - 36: ooOoO0o . II111iiii - OoOoOO00 % I1ii11iIi11i * O0
 if ( I1 . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 91 - 91: iII111i + Oo0Ooo / OoooooooOO * iIii1I11I1II1 - OoO0O00
 if 73 - 73: iIii1I11I1II1 % I1Ii111 % II111iiii * Oo0Ooo * OoO0O00
 if 48 - 48: OOooOOo * i11iIiiIii - i11iIiiIii + iIii1I11I1II1 + I1IiiI % OoooooooOO
 if 61 - 61: i1IIi
 I1 = I1 . print_address_no_iid ( )
 I1I = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 IiIi1iIIiII1i = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 56 - 56: iIii1I11I1II1 / I11i * iII111i * I11i * OoooooooOO
 O00o00o00OO0 = bold ( "Receive(pcap)" , False )
 OOoO0 = bold ( "from " + I1 , False )
 iIIiiIi = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( O00o00o00OO0 , len ( packet ) , OOoO0 , I1I , iIIiiIi ) )
 if 44 - 44: I1ii11iIi11i - OOooOOo % I11i - I1Ii111 / iIii1I11I1II1 - OOooOOo
 return ( [ packet , I1 , I1I , IiIi1iIIiII1i ] )
 if 38 - 38: iIii1I11I1II1 - OoooooooOO * II111iiii . OoooooooOO + OOooOOo
 if 59 - 59: OoooooooOO
 if 22 - 22: II111iiii
 if 85 - 85: I1Ii111 + I1ii11iIi11i * I11i % o0oOOo0O0Ooo + Ii1I
 if 23 - 23: IiII * OoO0O00
 if 42 - 42: IiII
 if 83 - 83: i1IIi * o0oOOo0O0Ooo / OoO0O00 / o0oOOo0O0Ooo
 if 55 - 55: Oo0Ooo % O0 - OoO0O00
 if 42 - 42: OoooooooOO * OOooOOo
 if 93 - 93: OOooOOo + II111iiii . oO0o * Oo0Ooo - O0 + I1Ii111
 if 99 - 99: OoO0O00 * o0oOOo0O0Ooo + OoOoOO00 * iIii1I11I1II1
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 38 - 38: I1ii11iIi11i - OOooOOo * O0 - I1ii11iIi11i
 oOoo = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 95 - 95: OoO0O00 . oO0o . OoooooooOO - iIii1I11I1II1
 lisp_write_to_dp_socket ( oOoo )
 return
 if 35 - 35: o0oOOo0O0Ooo / OoooooooOO - i1IIi * iIii1I11I1II1 + ooOoO0o
 if 66 - 66: Oo0Ooo - OoOoOO00 . I1Ii111 + O0 + o0oOOo0O0Ooo
 if 36 - 36: II111iiii % IiII . i11iIiiIii
 if 88 - 88: Oo0Ooo . IiII * Oo0Ooo
 if 92 - 92: I1IiiI % IiII
 if 95 - 95: OoooooooOO / OoO0O00 % O0 / I1Ii111 * Ii1I + I1ii11iIi11i
 if 7 - 7: ooOoO0o
 if 83 - 83: oO0o / I1Ii111 + I1Ii111 * I1ii11iIi11i
def lisp_external_data_plane ( ) :
 oO00o00 = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( getoutput ( oO00o00 ) != "" ) : return ( True )
 if 8 - 8: I11i . I1ii11iIi11i % i1IIi + Ii1I
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
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
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 46 - 46: OOooOOo . O0 / i11iIiiIii . OOooOOo
 i1II1 = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 43 - 43: I1ii11iIi11i
 if ( do_clear == False ) :
  I111I = i1II1 [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , I111I )
  if 72 - 72: i11iIiiIii / IiII * OoOoOO00 * I11i
  if 83 - 83: IiII % OoO0O00 * II111iiii
 lisp_write_to_dp_socket ( i1II1 )
 return
 if 7 - 7: oO0o % Oo0Ooo
 if 88 - 88: I1Ii111
 if 98 - 98: O0 . I11i + o0oOOo0O0Ooo * IiII
 if 46 - 46: OOooOOo / Oo0Ooo - iII111i + O0
 if 1 - 1: o0oOOo0O0Ooo . II111iiii % OoooooooOO - oO0o - I1Ii111 * o0oOOo0O0Ooo
 if 70 - 70: o0oOOo0O0Ooo * I1IiiI * OoOoOO00 / I11i * O0 / IiII
 if 99 - 99: II111iiii
 if 34 - 34: OOooOOo + OoOoOO00 * o0oOOo0O0Ooo + I1ii11iIi11i + IiII * i1IIi
 if 73 - 73: I1ii11iIi11i - IiII - O0 . oO0o + Oo0Ooo % iII111i
 if 68 - 68: I1ii11iIi11i - OoooooooOO
 if 5 - 5: I1ii11iIi11i * I1IiiI + OoooooooOO / Oo0Ooo
 if 18 - 18: OoO0O00 * iII111i % I1IiiI . OOooOOo * o0oOOo0O0Ooo
 if 58 - 58: iII111i . IiII + iIii1I11I1II1
 if 13 - 13: oO0o * I1Ii111 / I1Ii111 . I1IiiI
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( "entries" not in msg ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 93 - 93: I11i % OoOoOO00 - OOooOOo + iIii1I11I1II1 / OoooooooOO % i11iIiiIii
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 90 - 90: oO0o % iIii1I11I1II1 + o0oOOo0O0Ooo - I11i / i11iIiiIii
  if 57 - 57: I1IiiI . Oo0Ooo / I1IiiI / II111iiii - I1Ii111
 for msg in msg [ "entries" ] :
  if ( "eid-prefix" not in msg ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 68 - 68: I1IiiI
  i1iiii = msg [ "eid-prefix" ]
  if 97 - 97: Ii1I + o0oOOo0O0Ooo / OoO0O00
  if ( "instance-id" not in msg ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 97 - 97: i11iIiiIii % iIii1I11I1II1 + II111iiii
  oooo = int ( msg [ "instance-id" ] )
  if 90 - 90: OOooOOo / I1IiiI
  if 28 - 28: OoooooooOO + i1IIi
  if 29 - 29: Oo0Ooo
  if 98 - 98: OOooOOo / Oo0Ooo % Ii1I * OoooooooOO - oO0o
  i1I1I1IIIi11 = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
  i1I1I1IIIi11 . store_prefix ( i1iiii )
  o0ooo0oOO0o = lisp_map_cache_lookup ( None , i1I1I1IIIi11 )
  if ( o0ooo0oOO0o == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( i1iiii ) )
   if 64 - 64: I1IiiI - I1IiiI
   continue
   if 90 - 90: iII111i - I1IiiI - II111iiii / OOooOOo + Ii1I
   if 34 - 34: i11iIiiIii + I1Ii111 / O0 / iIii1I11I1II1 * OoooooooOO % Ii1I
  if ( "rlocs" not in msg ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( i1iiii ) )
   if 32 - 32: i11iIiiIii - OoOoOO00 / iIii1I11I1II1 * o0oOOo0O0Ooo % I1IiiI + O0
   continue
   if 36 - 36: I1ii11iIi11i + I1ii11iIi11i % I1Ii111 * ooOoO0o * OoOoOO00
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 54 - 54: Oo0Ooo - I1IiiI % OOooOOo . I1ii11iIi11i / I1IiiI
  O00oo000O = msg [ "rlocs" ]
  if 57 - 57: I1IiiI / Ii1I + II111iiii * IiII
  if 9 - 9: I1Ii111
  if 96 - 96: I1Ii111 / iIii1I11I1II1
  if 48 - 48: iII111i * IiII + OoooooooOO
  for oo0o in O00oo000O :
   if ( "rloc" not in oo0o ) : continue
   if 25 - 25: oO0o / OoO0O00 * iII111i - OoOoOO00
   IIi11IiiiI11i = oo0o [ "rloc" ]
   if ( IIi11IiiiI11i == "no-address" ) : continue
   if 1 - 1: o0oOOo0O0Ooo - Oo0Ooo * I11i . oO0o
   I1Ii1i111I = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   I1Ii1i111I . store_address ( IIi11IiiiI11i )
   if 15 - 15: I1ii11iIi11i . I1Ii111 + IiII
   OO0oooo = o0ooo0oOO0o . get_rloc ( I1Ii1i111I )
   if ( OO0oooo == None ) : continue
   if 15 - 15: Oo0Ooo . Ii1I - OoooooooOO % OoO0O00 + i11iIiiIii + iII111i
   if 91 - 91: OoooooooOO % Oo0Ooo - Ii1I
   if 54 - 54: O0 - iIii1I11I1II1 . OoO0O00 . IiII % OoO0O00
   if 28 - 28: O0 % i1IIi % OoO0O00 / o0oOOo0O0Ooo . iIii1I11I1II1 - iII111i
   IIi11ii = 0 if ( "packet-count" not in oo0o ) else oo0o [ "packet-count" ]
   if 61 - 61: IiII
   iII1IiI1 = 0 if ( "byte-count" not in oo0o ) else oo0o [ "byte-count" ]
   if 5 - 5: OOooOOo % iIii1I11I1II1 % O0 * i11iIiiIii / I1Ii111
   i1 = 0 if ( "seconds-last-packet" not in oo0o ) else oo0o [ "seconds-last-packet" ]
   if 48 - 48: IiII * oO0o
   if 53 - 53: i1IIi * iIii1I11I1II1 . OOooOOo
   OO0oooo . stats . packet_count += IIi11ii
   OO0oooo . stats . byte_count += iII1IiI1
   OO0oooo . stats . last_increment = lisp_get_timestamp ( ) - i1
   if 68 - 68: IiII % IiII - iII111i . IiII + OoooooooOO
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( IIi11ii , iII1IiI1 ,
 i1 , i1iiii , IIi11IiiiI11i ) )
   if 82 - 82: Ii1I . II111iiii / i1IIi * OoO0O00
   if 80 - 80: I11i
   if 96 - 96: i1IIi - I1ii11iIi11i * iII111i . OOooOOo . OoO0O00
   if 93 - 93: oO0o * Oo0Ooo * IiII
   if 26 - 26: o0oOOo0O0Ooo + O0 % i11iIiiIii . ooOoO0o . I1IiiI + Oo0Ooo
  if ( o0ooo0oOO0o . group . is_null ( ) and o0ooo0oOO0o . has_ttl_elapsed ( ) ) :
   i1iiii = green ( o0ooo0oOO0o . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( i1iiii ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , o0ooo0oOO0o . eid , None )
   if 90 - 90: IiII * OoooooooOO + II111iiii / iII111i + i11iIiiIii / ooOoO0o
   if 20 - 20: II111iiii % I1ii11iIi11i - OoooooooOO * Ii1I / I11i - OoooooooOO
 return
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
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 79 - 79: I1ii11iIi11i + O0 * OoooooooOO
 if 43 - 43: I11i
 if 29 - 29: o0oOOo0O0Ooo / I11i
 if 88 - 88: OoOoOO00 - Ii1I . O0 % I1Ii111 % I1ii11iIi11i
 if 56 - 56: OoOoOO00 - iIii1I11I1II1 / I1IiiI - i1IIi / o0oOOo0O0Ooo * I11i
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  oOoo = "stats%{}" . format ( json . dumps ( msg ) )
  oOoo = lisp_command_ipc ( oOoo , "lisp-itr" )
  lisp_ipc ( oOoo , lisp_ipc_socket , "lisp-etr" )
  return
  if 70 - 70: OOooOOo
  if 11 - 11: I11i * II111iiii * Oo0Ooo + OOooOOo % i1IIi
  if 73 - 73: OoO0O00 + O0 / Ii1I . OoooooooOO % iIii1I11I1II1 * i1IIi
  if 84 - 84: o0oOOo0O0Ooo . iII111i / o0oOOo0O0Ooo + I1ii11iIi11i % OoO0O00
  if 52 - 52: OoOoOO00 / Ii1I % OoOoOO00 % i11iIiiIii + I1IiiI / o0oOOo0O0Ooo
  if 63 - 63: I1IiiI
  if 20 - 20: oO0o + OoOoOO00
  if 32 - 32: o0oOOo0O0Ooo % oO0o % I1IiiI * OoooooooOO
 oOoo = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( oOoo , msg ) )
 if 4 - 4: OOooOOo % oO0o
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 18 - 18: Ii1I * I11i
 I1OOOOO00O00O0 = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 50 - 50: I1ii11iIi11i / I1ii11iIi11i * OOooOOo - Oo0Ooo . oO0o
 for ooI1Iii in I1OOOOO00O00O0 :
  IIi11ii = 0 if ( ooI1Iii not in msg ) else msg [ ooI1Iii ] [ "packet-count" ]
  lisp_decap_stats [ ooI1Iii ] . packet_count += IIi11ii
  if 32 - 32: oO0o
  iII1IiI1 = 0 if ( ooI1Iii not in msg ) else msg [ ooI1Iii ] [ "byte-count" ]
  lisp_decap_stats [ ooI1Iii ] . byte_count += iII1IiI1
  if 52 - 52: oO0o
  i1 = 0 if ( ooI1Iii not in msg ) else msg [ ooI1Iii ] [ "seconds-last-packet" ]
  if 64 - 64: I1Ii111 + Oo0Ooo / iII111i
  lisp_decap_stats [ ooI1Iii ] . last_increment = lisp_get_timestamp ( ) - i1
  if 61 - 61: Ii1I * Ii1I . OoOoOO00 + OoO0O00 * i11iIiiIii * OoO0O00
 return
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
 if 3 - 3: i11iIiiIii - o0oOOo0O0Ooo / oO0o . OoO0O00 * I11i + o0oOOo0O0Ooo
 if 18 - 18: OoooooooOO % oO0o / IiII - ooOoO0o
 if 80 - 80: I11i
 if 98 - 98: iII111i / I1ii11iIi11i
 if 87 - 87: iII111i - O0 * ooOoO0o / II111iiii % OoooooooOO . o0oOOo0O0Ooo
 if 55 - 55: OOooOOo - o0oOOo0O0Ooo * I1IiiI / o0oOOo0O0Ooo + I1Ii111 + iIii1I11I1II1
 if 3 - 3: II111iiii % iII111i / IiII * ooOoO0o . OoooooooOO
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 O0OoOOOooO0Oo , I1 = punt_socket . recvfrom ( 4000 )
 if 47 - 47: IiII * ooOoO0o
 oooO0OoO = json . loads ( O0OoOOOooO0Oo )
 if ( type ( oooO0OoO ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( I1 ) )
  if 22 - 22: oO0o / O0
  return
  if 63 - 63: i1IIi + OoO0O00
 I1iIIO0oo = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( I1iIIO0oo , I1 , oooO0OoO ) )
 if 80 - 80: I11i % Oo0Ooo % I1Ii111 / OoO0O00 + II111iiii
 if ( "type" not in oooO0OoO ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 40 - 40: Ii1I + O0 . i11iIiiIii % I11i / Oo0Ooo
  if 25 - 25: IiII * IiII
  if 54 - 54: I1Ii111
  if 90 - 90: Oo0Ooo / Ii1I
  if 66 - 66: i11iIiiIii - I11i + oO0o . OoooooooOO
 if ( oooO0OoO [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( oooO0OoO , lisp_send_sockets , lisp_ephem_port )
  return
  if 77 - 77: OoO0O00 / OOooOOo
 if ( oooO0OoO [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( oooO0OoO , punt_socket )
  return
  if 97 - 97: OoOoOO00 / Ii1I * I1IiiI - Oo0Ooo % O0
  if 66 - 66: O0 + I1IiiI % iIii1I11I1II1 . i1IIi % II111iiii - i1IIi
  if 93 - 93: O0 + OoooooooOO % IiII % oO0o % I1ii11iIi11i
  if 36 - 36: I1IiiI - oO0o * Oo0Ooo + oO0o % iII111i - i11iIiiIii
  if 93 - 93: O0
 if ( oooO0OoO [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 11 - 11: OoooooooOO . I1ii11iIi11i + I1ii11iIi11i
  if 73 - 73: OoooooooOO
  if 2 - 2: o0oOOo0O0Ooo % IiII + I1ii11iIi11i - i11iIiiIii
  if 100 - 100: II111iiii + oO0o
  if 85 - 85: I1ii11iIi11i % I1ii11iIi11i . Ii1I
 if ( oooO0OoO [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 42 - 42: oO0o + OoO0O00
 if ( "interface" not in oooO0OoO ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( I1 ) )
  if 16 - 16: Ii1I
  return
  if 67 - 67: I1ii11iIi11i . OoooooooOO * I1Ii111 + Ii1I * OOooOOo
  if 84 - 84: OOooOOo
  if 78 - 78: O0 % O0
  if 72 - 72: o0oOOo0O0Ooo * IiII / II111iiii / iIii1I11I1II1
  if 41 - 41: iII111i / Ii1I
 ooO000OO = oooO0OoO [ "interface" ]
 if ( ooO000OO == "" ) :
  oooo = int ( oooO0OoO [ "instance-id" ] )
  if ( oooo == - 1 ) : return
 else :
  oooo = lisp_get_interface_instance_id ( ooO000OO , None )
  if 11 - 11: Oo0Ooo % OOooOOo . ooOoO0o
  if 24 - 24: IiII / Oo0Ooo
  if 90 - 90: ooOoO0o . OOooOOo - Ii1I
  if 60 - 60: i11iIiiIii % iII111i . I1IiiI * I1ii11iIi11i
  if 30 - 30: Ii1I + i11iIiiIii . I11i + o0oOOo0O0Ooo - OoO0O00
 O0oO = None
 if ( "source-eid" in oooO0OoO ) :
  oo0Oo0 = oooO0OoO [ "source-eid" ]
  O0oO = lisp_address ( LISP_AFI_NONE , oo0Oo0 , 0 , oooo )
  if ( O0oO . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( oo0Oo0 ) )
   return
   if 55 - 55: ooOoO0o - II111iiii . ooOoO0o . iII111i / OoooooooOO
   if 51 - 51: I1IiiI * I1Ii111 - ooOoO0o + IiII
 oo0Oo00oo0OoO0O0 = None
 if ( "dest-eid" in oooO0OoO ) :
  iII11Ii111 = oooO0OoO [ "dest-eid" ]
  oo0Oo00oo0OoO0O0 = lisp_address ( LISP_AFI_NONE , iII11Ii111 , 0 , oooo )
  if ( oo0Oo00oo0OoO0O0 . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( iII11Ii111 ) )
   return
   if 62 - 62: Ii1I / Oo0Ooo / I1ii11iIi11i . OoOoOO00 % ooOoO0o * IiII
   if 97 - 97: ooOoO0o
   if 14 - 14: iII111i + iII111i
   if 62 - 62: ooOoO0o / OOooOOo * I1ii11iIi11i + Oo0Ooo - OoooooooOO - OoooooooOO
   if 19 - 19: Ii1I . oO0o
   if 26 - 26: OOooOOo + II111iiii
   if 67 - 67: IiII + OoOoOO00 * I1ii11iIi11i % o0oOOo0O0Ooo / oO0o
   if 31 - 31: ooOoO0o / Ii1I . Ii1I - I1IiiI - Oo0Ooo . II111iiii
 if ( O0oO ) :
  oO0ooOOO = green ( O0oO . print_address ( ) , False )
  i11IIII1Ii = lisp_db_for_lookups . lookup_cache ( O0oO , False )
  if ( i11IIII1Ii != None ) :
   if 82 - 82: Oo0Ooo % Oo0Ooo
   if 17 - 17: OOooOOo % Oo0Ooo . I1IiiI * O0 * oO0o % OoOoOO00
   if 99 - 99: Oo0Ooo - ooOoO0o . OoO0O00 - Oo0Ooo / O0
   if 42 - 42: Ii1I - OoOoOO00 . OoOoOO00
   if 88 - 88: o0oOOo0O0Ooo . Ii1I . iII111i * iII111i + i11iIiiIii
   if ( i11IIII1Ii . dynamic_eid_configured ( ) ) :
    i111IIiIiiI1 = lisp_allow_dynamic_eid ( ooO000OO , O0oO )
    if ( i111IIiIiiI1 != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( i11IIII1Ii , O0oO , ooO000OO , i111IIiIiiI1 )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( oO0ooOOO , ooO000OO ) )
     if 68 - 68: OoooooooOO
     if 5 - 5: OoOoOO00 . i11iIiiIii . OOooOOo / I11i * Oo0Ooo % Oo0Ooo
     if 44 - 44: I1ii11iIi11i + oO0o % i1IIi + OoooooooOO
  else :
   lprint ( "Punt from non-EID source {}" . format ( oO0ooOOO ) )
   if 42 - 42: I1Ii111 / I1Ii111 - O0
   if 79 - 79: i11iIiiIii
   if 96 - 96: iIii1I11I1II1 . OoOoOO00 . OOooOOo / iII111i
   if 59 - 59: Oo0Ooo + OOooOOo / Oo0Ooo
   if 49 - 49: OoO0O00 / Oo0Ooo % OoOoOO00 % i1IIi
   if 66 - 66: OoOoOO00 % II111iiii
 if ( oo0Oo00oo0OoO0O0 ) :
  o0ooo0oOO0o = lisp_map_cache_lookup ( O0oO , oo0Oo00oo0OoO0O0 )
  if ( o0ooo0oOO0o == None or lisp_mr_or_pubsub ( o0ooo0oOO0o . action ) ) :
   if 16 - 16: i11iIiiIii - I1IiiI + ooOoO0o * oO0o
   if 30 - 30: II111iiii / o0oOOo0O0Ooo
   if 57 - 57: I11i / I1ii11iIi11i . I11i
   if 68 - 68: OoOoOO00 + O0 . I1IiiI
   if 26 - 26: I1ii11iIi11i
   if ( lisp_rate_limit_map_request ( oo0Oo00oo0OoO0O0 ) ) : return
   if 98 - 98: Oo0Ooo
   oO0II11II = ( o0ooo0oOO0o and o0ooo0oOO0o . action == LISP_SEND_PUBSUB_ACTION )
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 O0oO , oo0Oo00oo0OoO0O0 , None , oO0II11II )
  else :
   oO0ooOOO = green ( oo0Oo00oo0OoO0O0 . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( oO0ooOOO ) )
   if 72 - 72: oO0o + OoooooooOO . O0 + IiII
   if 49 - 49: i1IIi - i11iIiiIii + II111iiii + Ii1I / OoO0O00
 return
 if 34 - 34: I1ii11iIi11i * i11iIiiIii
 if 6 - 6: I1ii11iIi11i + I1IiiI / OoooooooOO % I11i * Oo0Ooo
 if 20 - 20: Oo0Ooo
 if 85 - 85: I1Ii111
 if 98 - 98: OoO0O00 - IiII % iIii1I11I1II1 . OoOoOO00 + i1IIi + OoooooooOO
 if 29 - 29: I1ii11iIi11i * I1Ii111 - i1IIi * i11iIiiIii * iIii1I11I1II1 % I11i
 if 73 - 73: OoO0O00 . I1IiiI / o0oOOo0O0Ooo
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 oo0O00OOOOO = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( oo0O00OOOOO )
 return ( [ True , jdata ] )
 if 12 - 12: I11i * i11iIiiIii - O0 * o0oOOo0O0Ooo - IiII + I1IiiI
 if 7 - 7: oO0o + I1Ii111 . o0oOOo0O0Ooo / IiII + iIii1I11I1II1 % I1Ii111
 if 24 - 24: i11iIiiIii + iIii1I11I1II1
 if 22 - 22: i11iIiiIii . II111iiii / o0oOOo0O0Ooo / Ii1I . O0 . OoOoOO00
 if 89 - 89: O0 * Oo0Ooo + I1Ii111 + ooOoO0o * OoOoOO00
 if 20 - 20: OoO0O00 - OoOoOO00
 if 84 - 84: iIii1I11I1II1 + ooOoO0o . o0oOOo0O0Ooo % iII111i
 if 35 - 35: I11i - oO0o * oO0o / OoooooooOO + iII111i + OoOoOO00
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 48 - 48: I1Ii111 / o0oOOo0O0Ooo - OOooOOo / o0oOOo0O0Ooo % O0
 if 38 - 38: OoO0O00 + o0oOOo0O0Ooo / OoO0O00
 if 74 - 74: oO0o - i1IIi . Oo0Ooo / I1IiiI + o0oOOo0O0Ooo . OoOoOO00
 if 35 - 35: iII111i / Ii1I
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 57 - 57: ooOoO0o . I1IiiI * OOooOOo
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 87 - 87: I11i - I11i % iII111i - Ii1I
 if 29 - 29: oO0o - ooOoO0o * iIii1I11I1II1 / OoOoOO00
 if 34 - 34: I1IiiI . Oo0Ooo
 if 4 - 4: Ii1I - II111iiii * iII111i / oO0o - I1IiiI
 if 32 - 32: iIii1I11I1II1 - I11i
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 49 - 49: I11i * I1Ii111 - iIii1I11I1II1 * O0
 if 72 - 72: I1IiiI * iII111i
 if 61 - 61: Ii1I * Oo0Ooo * I1Ii111 % I11i + iII111i % oO0o
 if 67 - 67: IiII
 if 90 - 90: o0oOOo0O0Ooo
 if 5 - 5: i1IIi
 if 55 - 55: Ii1I
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 i1iiii = eid . print_address ( )
 if ( i1iiii in db . dynamic_eids ) :
  db . dynamic_eids [ i1iiii ] . last_packet = lisp_get_timestamp ( )
  return
  if 46 - 46: OOooOOo / iII111i . i1IIi . i11iIiiIii . iIii1I11I1II1 % I11i
  if 62 - 62: I11i % II111iiii % OoooooooOO * ooOoO0o / oO0o
  if 29 - 29: o0oOOo0O0Ooo / O0 / OoO0O00
  if 23 - 23: Ii1I + i11iIiiIii % IiII
  if 64 - 64: i11iIiiIii + OoooooooOO . oO0o * Ii1I
 I1Ii111I111 = lisp_dynamic_eid ( )
 I1Ii111I111 . dynamic_eid . copy_address ( eid )
 I1Ii111I111 . interface = routed_interface
 I1Ii111I111 . last_packet = lisp_get_timestamp ( )
 I1Ii111I111 . get_timeout ( routed_interface )
 db . dynamic_eids [ i1iiii ] = I1Ii111I111
 if 49 - 49: O0
 o0Ooo0OooOoO = ""
 if ( input_interface != routed_interface ) :
  o0Ooo0OooOoO = ", routed-interface " + routed_interface
  if 69 - 69: iIii1I11I1II1 % I1ii11iIi11i
  if 68 - 68: iII111i + I11i
 oOOooO000O0o0 = green ( i1iiii , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( oOOooO000O0o0 , input_interface , o0Ooo0OooOoO , I1Ii111I111 . timeout ) )
 if 40 - 40: OOooOOo - oO0o % OoooooooOO
 if 40 - 40: I1Ii111 * o0oOOo0O0Ooo * ooOoO0o * I1Ii111 + O0
 if 81 - 81: OoooooooOO / O0
 if 42 - 42: OOooOOo - OOooOOo - o0oOOo0O0Ooo . OoOoOO00 * oO0o % iIii1I11I1II1
 if 94 - 94: I11i * Ii1I + II111iiii / ooOoO0o
 oOoo = "learn%{}%{}" . format ( i1iiii , routed_interface )
 oOoo = lisp_command_ipc ( oOoo , "lisp-itr" )
 lisp_ipc ( oOoo , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 67 - 67: I11i + I1Ii111
 if 15 - 15: OOooOOo * Ii1I / Oo0Ooo . OoO0O00 . I11i
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
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 35 - 35: OoOoOO00 * I1Ii111 / Oo0Ooo - i1IIi - IiII + OOooOOo
 if 96 - 96: Oo0Ooo + I1ii11iIi11i . O0
 if 62 - 62: i1IIi % OoooooooOO % OoooooooOO
 if 53 - 53: O0 * oO0o
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 22 - 22: OOooOOo % Oo0Ooo % ooOoO0o - O0 + i1IIi
 oO0oOooo = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 67 - 67: OoO0O00 / I1IiiI - IiII + iII111i - iII111i
 for Ooo00o000o in lisp_crypto_keys_by_rloc_decap :
  if 4 - 4: IiII . Ii1I . IiII % OoO0O00
  if 12 - 12: OoOoOO00 + O0 / O0 . i1IIi
  if 58 - 58: IiII . iII111i % O0 . Ii1I * Oo0Ooo
  if 54 - 54: OoO0O00 % OOooOOo - OoO0O00 . Oo0Ooo % i1IIi
  if ( Ooo00o000o . find ( addr_str ) == - 1 ) : continue
  if 95 - 95: iII111i . OoooooooOO . o0oOOo0O0Ooo / II111iiii - OoooooooOO / I1Ii111
  if 11 - 11: II111iiii / iII111i . oO0o / ooOoO0o / OOooOOo + OoO0O00
  if 37 - 37: iIii1I11I1II1 * O0
  if 64 - 64: I1Ii111 - II111iiii + oO0o % ooOoO0o * oO0o
  if ( Ooo00o000o == addr_str ) : continue
  if 27 - 27: iIii1I11I1II1 - Ii1I . i11iIiiIii / IiII . I1Ii111 / i11iIiiIii
  if 27 - 27: OoOoOO00 . I11i / OoOoOO00
  if 96 - 96: OoO0O00 - I1IiiI
  if 73 - 73: I1IiiI - o0oOOo0O0Ooo - I1Ii111
  oo0O00OOOOO = lisp_crypto_keys_by_rloc_decap [ Ooo00o000o ]
  if ( oo0O00OOOOO == oO0oOooo ) : continue
  if 34 - 34: iIii1I11I1II1 - i1IIi + OoO0O00 % Oo0Ooo + i1IIi
  if 46 - 46: I1IiiI
  if 82 - 82: iII111i . i1IIi
  if 38 - 38: Ii1I . I1IiiI . I1ii11iIi11i
  Ii1iI1I1 = oo0O00OOOOO [ 1 ]
  if ( packet_icv != Ii1iI1I1 . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( Ooo00o000o , False ) ) )
   continue
   if 55 - 55: II111iiii % o0oOOo0O0Ooo + IiII % i1IIi % OoooooooOO - O0
   if 39 - 39: i11iIiiIii / Ii1I / ooOoO0o
  lprint ( "Changing decap crypto key to {}" . format ( red ( Ooo00o000o , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = oo0O00OOOOO
  if 93 - 93: o0oOOo0O0Ooo - Oo0Ooo / oO0o / OoOoOO00
 return
 if 75 - 75: o0oOOo0O0Ooo * ooOoO0o % Ii1I
 if 94 - 94: OoooooooOO + II111iiii / iIii1I11I1II1 * ooOoO0o
 if 85 - 85: ooOoO0o / IiII
 if 28 - 28: i11iIiiIii - OoOoOO00
 if 13 - 13: O0
 if 82 - 82: OoooooooOO
 if 59 - 59: I1Ii111 + I1ii11iIi11i + OoO0O00 % oO0o . i1IIi % O0
 if 22 - 22: i1IIi * OoOoOO00 + Ii1I
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 48 - 48: Ii1I % IiII + OoO0O00 . IiII
 if 42 - 42: Ii1I
 if 70 - 70: I11i
 if 82 - 82: O0
 if 58 - 58: II111iiii . O0 - OoO0O00 - IiII
 if 4 - 4: i11iIiiIii + i11iIiiIii / O0
 if 46 - 46: I11i % ooOoO0o - Ii1I
 if 25 - 25: O0 / i11iIiiIii . O0
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 o0o = dns_name . split ( "." )
 o0o = "." . join ( o0o [ 1 : : ] )
 return ( o0o == lisp_decent_dns_suffix )
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
def lisp_get_decent_index ( eid ) :
 i1iiii = eid . print_prefix ( )
 IiiIi1I = hmac . new ( b"lisp-decent" , i1iiii , hashlib . sha256 ) . hexdigest ( )
 if 42 - 42: OoooooooOO / ooOoO0o % II111iiii - ooOoO0o
 if 15 - 15: II111iiii + I1IiiI
 if 10 - 10: OoO0O00 . OOooOOo + iIii1I11I1II1 / iIii1I11I1II1 / o0oOOo0O0Ooo
 if 31 - 31: Ii1I
 i111IIIiIi1iI = os . getenv ( "LISP_DECENT_HASH_WIDTH" )
 if ( i111IIIiIi1iI in [ "" , None ] ) :
  i111IIIiIi1iI = 12
 else :
  i111IIIiIi1iI = int ( i111IIIiIi1iI )
  if ( i111IIIiIi1iI > 32 ) :
   i111IIIiIi1iI = 12
  else :
   i111IIIiIi1iI *= 2
   if 15 - 15: Ii1I % O0 * iIii1I11I1II1
   if 68 - 68: I1IiiI
   if 85 - 85: OoO0O00 % O0 - i11iIiiIii . iII111i . ooOoO0o / i11iIiiIii
 iIIi1II = IiiIi1I [ 0 : i111IIIiIi1iI ]
 OOOooo0OooOoO = int ( iIIi1II , 16 ) % lisp_decent_modulus
 if 53 - 53: I11i + iII111i % iII111i . iII111i
 lprint ( "LISP-Decent modulus {}, hash-width {}, mod-value {}, index {}" . format ( lisp_decent_modulus , old_div ( i111IIIiIi1iI , 2 ) , iIIi1II , OOOooo0OooOoO ) )
 if 66 - 66: oO0o / o0oOOo0O0Ooo - Oo0Ooo + O0 / i1IIi
 if 97 - 97: OoO0O00 + i11iIiiIii % I1IiiI * Ii1I
 return ( OOOooo0OooOoO )
 if 89 - 89: IiII % i11iIiiIii + OoO0O00 . oO0o / I1IiiI . Ii1I
 if 11 - 11: ooOoO0o - I1Ii111 - I11i + OoOoOO00
 if 20 - 20: I11i + O0
 if 27 - 27: Oo0Ooo
 if 12 - 12: I1ii11iIi11i . iII111i - iII111i - OOooOOo - iIii1I11I1II1
 if 50 - 50: I1IiiI - iIii1I11I1II1 . iII111i - Ii1I / I1Ii111 + iII111i
 if 46 - 46: OOooOOo + iII111i % Oo0Ooo * iII111i % OoooooooOO * IiII
def lisp_get_decent_dns_name ( eid ) :
 OOOooo0OooOoO = lisp_get_decent_index ( eid )
 return ( str ( OOOooo0OooOoO ) + "." + lisp_decent_dns_suffix )
 if 27 - 27: I1IiiI + I1IiiI + I1ii11iIi11i - oO0o * OOooOOo
 if 53 - 53: I1ii11iIi11i / OoooooooOO * iIii1I11I1II1
 if 4 - 4: I1IiiI . iIii1I11I1II1 + OOooOOo / IiII . o0oOOo0O0Ooo . I11i
 if 52 - 52: ooOoO0o % i11iIiiIii . IiII + OoO0O00
 if 66 - 66: II111iiii . Ii1I
 if 42 - 42: iIii1I11I1II1 * iII111i * I1IiiI
 if 66 - 66: Oo0Ooo * i1IIi / I1ii11iIi11i / OoO0O00
 if 12 - 12: OOooOOo + iIii1I11I1II1 % I1Ii111 + OOooOOo
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 i1I1I1IIIi11 = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 OOOooo0OooOoO = lisp_get_decent_index ( i1I1I1IIIi11 )
 return ( str ( OOOooo0OooOoO ) + "." + lisp_decent_dns_suffix )
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
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 65 - 65: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo
 oo00 = 28 if packet . inner_version == 4 else 48
 OoOOoOo0o = packet . packet [ oo00 : : ]
 OooOo00o0 = lisp_trace ( )
 if ( OooOo00o0 . decode ( OoOOoOo0o ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 9 - 9: II111iiii
  if 19 - 19: O0 * Ii1I . i1IIi - Oo0Ooo - i11iIiiIii / O0
 i1Iii1iI11 = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 37 - 37: i11iIiiIii * OoOoOO00 * Oo0Ooo * I1IiiI / II111iiii
 if 100 - 100: I1Ii111
 if 23 - 23: Ii1I
 if 74 - 74: OoooooooOO % I1Ii111 + OoO0O00 * i11iIiiIii - I11i - I1ii11iIi11i
 if 98 - 98: Ii1I - Oo0Ooo - o0oOOo0O0Ooo
 if 7 - 7: II111iiii + OoO0O00 . I1IiiI - iII111i . o0oOOo0O0Ooo
 if ( i1Iii1iI11 != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : i1Iii1iI11 += ":{}" . format ( packet . encap_port )
  if 65 - 65: Ii1I + O0
  if 30 - 30: OoOoOO00
  if 86 - 86: II111iiii % I1ii11iIi11i
  if 88 - 88: Oo0Ooo . oO0o + OoOoOO00 % OoooooooOO
  if 81 - 81: OoooooooOO . I1Ii111 + OoO0O00 % I1Ii111
 oo0O00OOOOO = { }
 oo0O00OOOOO [ "n" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 49 - 49: oO0o . oO0o % oO0o / Oo0Ooo
 O0oOOO0O0O = packet . outer_source
 if ( O0oOOO0O0O . is_null ( ) ) : O0oOOO0O0O = lisp_myrlocs [ 0 ]
 oo0O00OOOOO [ "sr" ] = O0oOOO0O0O . print_address_no_iid ( )
 if 24 - 24: i11iIiiIii / OoOoOO00 . OoO0O00 * OOooOOo
 if 61 - 61: OoooooooOO % II111iiii * I1ii11iIi11i . oO0o . OoooooooOO % IiII
 if 59 - 59: i1IIi
 if 85 - 85: I11i + oO0o / Oo0Ooo . ooOoO0o % O0 * o0oOOo0O0Ooo
 if 13 - 13: i1IIi * Oo0Ooo % i11iIiiIii % I11i / II111iiii - Ii1I
 if ( oo0O00OOOOO [ "n" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  oo0O00OOOOO [ "sr" ] += ":{}" . format ( packet . inner_sport )
  if 71 - 71: OoOoOO00 % ooOoO0o
  if 36 - 36: Ii1I * oO0o / oO0o % I1IiiI % I1IiiI + I1IiiI
 oo0O00OOOOO [ "hn" ] = lisp_hostname
 Ooo00o000o = ed [ 0 ] + "ts"
 oo0O00OOOOO [ Ooo00o000o ] = lisp_get_timestamp ( )
 if 41 - 41: OoooooooOO . O0 % OOooOOo
 if 88 - 88: O0
 if 44 - 44: II111iiii - IiII / I1IiiI + ooOoO0o % iII111i - iII111i
 if 53 - 53: OoooooooOO
 if 41 - 41: i1IIi - oO0o
 if 41 - 41: I11i
 if ( i1Iii1iI11 == "?" and oo0O00OOOOO [ "n" ] == "ETR" ) :
  i11IIII1Ii = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( i11IIII1Ii != None and len ( i11IIII1Ii . rloc_set ) >= 1 ) :
   i1Iii1iI11 = i11IIII1Ii . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 92 - 92: i11iIiiIii
   if 62 - 62: i1IIi / I1IiiI - o0oOOo0O0Ooo
 oo0O00OOOOO [ "dr" ] = i1Iii1iI11
 if 3 - 3: O0 * OoOoOO00 * I11i / OoOoOO00
 if 77 - 77: i1IIi
 if 3 - 3: iII111i * OoO0O00 - oO0o + iII111i . o0oOOo0O0Ooo + I1IiiI
 if 65 - 65: O0 / OoOoOO00
 if ( i1Iii1iI11 == "?" and reason != None ) :
  oo0O00OOOOO [ "dr" ] += " ({})" . format ( reason )
  if 77 - 77: OoO0O00
  if 17 - 17: i1IIi
  if 35 - 35: OoOoOO00
  if 61 - 61: I1Ii111
  if 78 - 78: I1Ii111 * Ii1I % Ii1I + I1IiiI
 if ( rloc_entry != None ) :
  oo0O00OOOOO [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  oo0O00OOOOO [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  oo0O00OOOOO [ "lats" ] = rloc_entry . recent_rloc_probe_latencies
  if 83 - 83: iIii1I11I1II1 + O0 / IiII . iIii1I11I1II1
  if 74 - 74: Oo0Ooo
  if 60 - 60: OoooooooOO
  if 16 - 16: iIii1I11I1II1 - OoOoOO00 / I1ii11iIi11i % O0 % o0oOOo0O0Ooo
  if 99 - 99: ooOoO0o . o0oOOo0O0Ooo - O0 * I1Ii111 . i11iIiiIii / iIii1I11I1II1
  if 40 - 40: iIii1I11I1II1 + oO0o / iIii1I11I1II1 - i1IIi % OoO0O00
 O0oO = packet . inner_source . print_address ( )
 oo0Oo00oo0OoO0O0 = packet . inner_dest . print_address ( )
 if ( OooOo00o0 . packet_json == [ ] ) :
  IIiI11 = { }
  IIiI11 [ "se" ] = O0oO
  IIiI11 [ "de" ] = oo0Oo00oo0OoO0O0
  IIiI11 [ "paths" ] = [ ]
  OooOo00o0 . packet_json . append ( IIiI11 )
  if 22 - 22: OOooOOo
  if 65 - 65: i1IIi - oO0o . I1Ii111 . ooOoO0o % I1ii11iIi11i % I1ii11iIi11i
  if 1 - 1: I1Ii111 + I1Ii111
  if 96 - 96: iII111i + OoOoOO00 - o0oOOo0O0Ooo + Ii1I
  if 6 - 6: O0 . I11i
  if 22 - 22: Oo0Ooo . O0 / i1IIi - OoOoOO00
 for IIiI11 in OooOo00o0 . packet_json :
  if ( IIiI11 [ "de" ] != oo0Oo00oo0OoO0O0 ) : continue
  IIiI11 [ "paths" ] . append ( oo0O00OOOOO )
  break
  if 41 - 41: II111iiii - I1ii11iIi11i - I1Ii111
  if 82 - 82: I1IiiI * I1IiiI / iIii1I11I1II1
  if 14 - 14: I11i + Ii1I - OOooOOo % Ii1I / Ii1I
  if 86 - 86: I1Ii111 - i11iIiiIii + Ii1I + I11i
  if 96 - 96: Ii1I
  if 28 - 28: i1IIi . oO0o . IiII + Oo0Ooo . Oo0Ooo . i1IIi
  if 34 - 34: Oo0Ooo + IiII / i1IIi
  if 33 - 33: i1IIi
 I11IIiIi1 = False
 if ( len ( OooOo00o0 . packet_json ) == 1 and oo0O00OOOOO [ "n" ] == "ETR" and
 OooOo00o0 . myeid ( packet . inner_dest ) ) :
  IIiI11 = { }
  IIiI11 [ "se" ] = oo0Oo00oo0OoO0O0
  IIiI11 [ "de" ] = O0oO
  IIiI11 [ "paths" ] = [ ]
  OooOo00o0 . packet_json . append ( IIiI11 )
  I11IIiIi1 = True
  if 63 - 63: oO0o . OoOoOO00 / IiII
  if 9 - 9: O0 + IiII . oO0o % IiII
  if 80 - 80: o0oOOo0O0Ooo * Oo0Ooo % i11iIiiIii * iII111i + i1IIi + II111iiii
  if 73 - 73: oO0o % oO0o * OoOoOO00 * O0 % OoO0O00 * i11iIiiIii
  if 49 - 49: I11i . ooOoO0o . i11iIiiIii - II111iiii
  if 7 - 7: I1Ii111 % o0oOOo0O0Ooo . oO0o . ooOoO0o % i1IIi / I1IiiI
 OooOo00o0 . print_trace ( )
 OoOOoOo0o = OooOo00o0 . encode ( )
 if 88 - 88: i11iIiiIii / oO0o - i1IIi / I1IiiI
 if 57 - 57: oO0o + O0 * I11i
 if 87 - 87: o0oOOo0O0Ooo % Oo0Ooo * I1ii11iIi11i / OoooooooOO / o0oOOo0O0Ooo
 if 78 - 78: Ii1I
 if 5 - 5: i1IIi * ooOoO0o / OoOoOO00 % i11iIiiIii
 if 57 - 57: IiII
 if 89 - 89: I1ii11iIi11i - I1Ii111 + o0oOOo0O0Ooo
 if 62 - 62: I1ii11iIi11i + OoooooooOO * OOooOOo
 ii11iiiII = OooOo00o0 . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "sr" ]
 if ( i1Iii1iI11 == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( ii11iiiII ) )
  OooOo00o0 . return_to_sender ( lisp_socket , ii11iiiII , OoOOoOo0o )
  return ( False )
  if 53 - 53: I1Ii111 % i11iIiiIii / I1Ii111 % i11iIiiIii
  if 67 - 67: I1IiiI + O0 . O0 - Oo0Ooo
  if 100 - 100: I1Ii111 . o0oOOo0O0Ooo * OoooooooOO . o0oOOo0O0Ooo
  if 90 - 90: i11iIiiIii . I1IiiI + ooOoO0o * OoooooooOO * OoooooooOO + oO0o
  if 77 - 77: OOooOOo * OoOoOO00
  if 75 - 75: Oo0Ooo * Oo0Ooo - IiII - OoOoOO00 / i11iIiiIii + I1Ii111
 Ooo000O00 = OooOo00o0 . packet_length ( )
 if 57 - 57: i11iIiiIii / oO0o
 if 37 - 37: o0oOOo0O0Ooo + OoOoOO00 - i1IIi . Oo0Ooo
 if 3 - 3: ooOoO0o % OoooooooOO / I1Ii111 + oO0o - O0
 if 72 - 72: oO0o * OoO0O00
 if 89 - 89: OoooooooOO . OOooOOo
 if 96 - 96: o0oOOo0O0Ooo + OoOoOO00 / i11iIiiIii - o0oOOo0O0Ooo * i11iIiiIii + OOooOOo
 I1i11 = packet . packet [ 0 : oo00 ]
 iIIiiIi = struct . pack ( "HH" , socket . htons ( Ooo000O00 ) , 0 )
 I1i11 = I1i11 [ 0 : oo00 - 4 ] + iIIiiIi
 if ( packet . inner_version == 6 and oo0O00OOOOO [ "n" ] == "ETR" and
 len ( OooOo00o0 . packet_json ) == 2 ) :
  O0I1II1 = I1i11 [ oo00 - 8 : : ] + OoOOoOo0o
  O0I1II1 = lisp_udp_checksum ( O0oO , oo0Oo00oo0OoO0O0 , O0I1II1 )
  I1i11 = I1i11 [ 0 : oo00 - 8 ] + O0I1II1 [ 0 : 8 ]
  if 26 - 26: Oo0Ooo / I1ii11iIi11i / Oo0Ooo % Oo0Ooo . IiII
  if 52 - 52: I1Ii111 - IiII / Ii1I
  if 64 - 64: I1Ii111 / Ii1I
  if 78 - 78: I11i % ooOoO0o - iIii1I11I1II1 / iIii1I11I1II1
  if 65 - 65: Ii1I . i1IIi + i11iIiiIii % I1Ii111 . OoO0O00 + Oo0Ooo
  if 82 - 82: O0 % I1IiiI / II111iiii * iII111i - OoO0O00 - II111iiii
  if 51 - 51: I1Ii111 % IiII / iIii1I11I1II1 % I1IiiI * i11iIiiIii
  if 26 - 26: II111iiii
  if 19 - 19: IiII - II111iiii / o0oOOo0O0Ooo . oO0o % OoooooooOO % I1IiiI
 if ( I11IIiIi1 ) :
  if ( packet . inner_version == 4 ) :
   I1i11 = I1i11 [ 0 : 12 ] + I1i11 [ 16 : 20 ] + I1i11 [ 12 : 16 ] + I1i11 [ 22 : 24 ] + I1i11 [ 20 : 22 ] + I1i11 [ 24 : : ]
   if 76 - 76: oO0o * I1ii11iIi11i
  else :
   I1i11 = I1i11 [ 0 : 8 ] + I1i11 [ 24 : 40 ] + I1i11 [ 8 : 24 ] + I1i11 [ 42 : 44 ] + I1i11 [ 40 : 42 ] + I1i11 [ 44 : : ]
   if 42 - 42: II111iiii . O0
   if 32 - 32: i1IIi % O0 / II111iiii - OoO0O00 + IiII * i11iIiiIii
  IiI11I111 = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = IiI11I111
  if 55 - 55: II111iiii
  if 93 - 93: i11iIiiIii / OoooooooOO % I1ii11iIi11i % I1ii11iIi11i
  if 37 - 37: OoO0O00 . I11i / I1ii11iIi11i . OoO0O00 - I1Ii111 + Oo0Ooo
  if 42 - 42: I1ii11iIi11i . I11i
  if 95 - 95: I1IiiI - I11i * I1Ii111 - I11i
  if 92 - 92: oO0o % iIii1I11I1II1 * o0oOOo0O0Ooo * OoooooooOO - iIii1I11I1II1
  if 51 - 51: Ii1I - OoO0O00 + i1IIi
 oo00 = 2 if packet . inner_version == 4 else 4
 IiI11III = 20 + Ooo000O00 if packet . inner_version == 4 else Ooo000O00
 Iiii111III = struct . pack ( "H" , socket . htons ( IiI11III ) )
 I1i11 = I1i11 [ 0 : oo00 ] + Iiii111III + I1i11 [ oo00 + 2 : : ]
 if 9 - 9: i11iIiiIii % Oo0Ooo + IiII + Ii1I . ooOoO0o / i1IIi
 if 40 - 40: I1Ii111 + I1IiiI - Ii1I
 if 27 - 27: i1IIi
 if 66 - 66: iII111i - ooOoO0o / i11iIiiIii + I1ii11iIi11i - Ii1I
 if ( packet . inner_version == 4 ) :
  IIIiIi11 = struct . pack ( "H" , 0 )
  I1i11 = I1i11 [ 0 : 10 ] + IIIiIi11 + I1i11 [ 12 : : ]
  Iiii111III = lisp_ip_checksum ( I1i11 [ 0 : 20 ] )
  I1i11 = Iiii111III + I1i11 [ 20 : : ]
  if 9 - 9: O0
  if 96 - 96: Oo0Ooo . II111iiii
  if 41 - 41: I1ii11iIi11i % o0oOOo0O0Ooo
  if 86 - 86: O0 * OoOoOO00 * O0 / O0
  if 50 - 50: OoooooooOO
 packet . packet = I1i11 + OoOOoOo0o
 return ( True )
 if 42 - 42: ooOoO0o / OoooooooOO
 if 31 - 31: II111iiii + Ii1I . iIii1I11I1II1 * OoO0O00 - O0 - OoO0O00
 if 12 - 12: oO0o + Ii1I
 if 7 - 7: iII111i / Oo0Ooo - OoO0O00 + I1Ii111 * II111iiii * ooOoO0o
 if 80 - 80: oO0o - i1IIi / I11i . II111iiii % O0 % I11i
 if 70 - 70: iIii1I11I1II1 * i1IIi * OOooOOo - Oo0Ooo % i1IIi
 if 60 - 60: o0oOOo0O0Ooo . OOooOOo % II111iiii - I1ii11iIi11i
 if 4 - 4: OOooOOo % ooOoO0o
 if 39 - 39: Ii1I
 if 67 - 67: iIii1I11I1II1 - OOooOOo
def lisp_allow_gleaning ( eid , group , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False , False )
 if 47 - 47: OOooOOo - OOooOOo * I1Ii111
 for oo0O00OOOOO in lisp_glean_mappings :
  if ( "instance-id" in oo0O00OOOOO ) :
   oooo = eid . instance_id
   Ii1iiiIi1ii1 , II1iiiIiiI = oo0O00OOOOO [ "instance-id" ]
   if ( oooo < Ii1iiiIi1ii1 or oooo > II1iiiIiiI ) : continue
   if 24 - 24: I1ii11iIi11i
  if ( "eid-prefix" in oo0O00OOOOO ) :
   oO0ooOOO = copy . deepcopy ( oo0O00OOOOO [ "eid-prefix" ] )
   oO0ooOOO . instance_id = eid . instance_id
   if ( eid . is_more_specific ( oO0ooOOO ) == False ) : continue
   if 37 - 37: II111iiii - iIii1I11I1II1 / o0oOOo0O0Ooo . O0 + II111iiii
  if ( "group-prefix" in oo0O00OOOOO ) :
   if ( group == None ) : continue
   Oo = copy . deepcopy ( oo0O00OOOOO [ "group-prefix" ] )
   Oo . instance_id = group . instance_id
   if ( group . is_more_specific ( Oo ) == False ) : continue
   if 9 - 9: o0oOOo0O0Ooo
  if ( "rloc-prefix" in oo0O00OOOOO ) :
   if ( rloc != None and rloc . is_more_specific ( oo0O00OOOOO [ "rloc-prefix" ] )
 == False ) : continue
   if 47 - 47: Ii1I * I1Ii111 / II111iiii
  return ( True , oo0O00OOOOO [ "rloc-probe" ] , oo0O00OOOOO [ "igmp-query" ] )
  if 73 - 73: ooOoO0o
 return ( False , False , False )
 if 53 - 53: IiII . Oo0Ooo
 if 54 - 54: i11iIiiIii % ooOoO0o % I1Ii111 + o0oOOo0O0Ooo
 if 2 - 2: IiII
 if 25 - 25: OoOoOO00 . OoO0O00 * o0oOOo0O0Ooo . OoooooooOO - Oo0Ooo + I1IiiI
 if 82 - 82: OoO0O00 - Ii1I * I11i * o0oOOo0O0Ooo
 if 17 - 17: OoooooooOO + I1Ii111
 if 91 - 91: iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo
def lisp_build_gleaned_multicast ( seid , geid , rloc , port , igmp ) :
 IIiI11I1I1i1i = geid . print_address ( )
 OO0oO00oOo0 = seid . print_address_no_iid ( )
 I111 = green ( "{}" . format ( OO0oO00oOo0 ) , False )
 oO0ooOOO = green ( "(*, {})" . format ( IIiI11I1I1i1i ) , False )
 O00o00o00OO0 = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 if 56 - 56: I1ii11iIi11i
 if 29 - 29: Oo0Ooo
 if 71 - 71: oO0o + II111iiii - OOooOOo - OoOoOO00
 if 68 - 68: I1ii11iIi11i % Oo0Ooo / iII111i . OOooOOo
 o0ooo0oOO0o = lisp_map_cache_lookup ( seid , geid )
 if ( o0ooo0oOO0o == None ) :
  o0ooo0oOO0o = lisp_mapping ( "" , "" , [ ] )
  o0ooo0oOO0o . group . copy_address ( geid )
  o0ooo0oOO0o . eid . copy_address ( geid )
  o0ooo0oOO0o . eid . address = 0
  o0ooo0oOO0o . eid . mask_len = 0
  o0ooo0oOO0o . mapping_source . copy_address ( rloc )
  o0ooo0oOO0o . map_cache_ttl = LISP_IGMP_TTL
  o0ooo0oOO0o . gleaned = True
  o0ooo0oOO0o . add_cache ( )
  lprint ( "Add gleaned EID {} to map-cache" . format ( oO0ooOOO ) )
  if 87 - 87: i1IIi
  if 5 - 5: OOooOOo
  if 22 - 22: Ii1I . I1ii11iIi11i * I1ii11iIi11i * OoOoOO00
  if 23 - 23: I1ii11iIi11i - OoOoOO00 + i11iIiiIii . I11i
  if 52 - 52: iII111i . OoOoOO00 * iIii1I11I1II1 . iII111i * IiII
  if 52 - 52: iII111i + iII111i
 OO0oooo = I1IIi1IIIi1I = iI11i1ii11i11 = None
 if ( o0ooo0oOO0o . rloc_set != [ ] ) :
  OO0oooo = o0ooo0oOO0o . rloc_set [ 0 ]
  if ( OO0oooo . rle ) :
   I1IIi1IIIi1I = OO0oooo . rle
   for IiI1iIIIiiiI in I1IIi1IIIi1I . rle_nodes :
    if ( IiI1iIIIiiiI . rloc_name != OO0oO00oOo0 ) : continue
    iI11i1ii11i11 = IiI1iIIIiiiI
    break
    if 85 - 85: Ii1I % OoOoOO00 / I1ii11iIi11i . OoOoOO00
    if 4 - 4: I1Ii111 - Oo0Ooo
    if 94 - 94: iIii1I11I1II1
    if 55 - 55: Ii1I . o0oOOo0O0Ooo * i11iIiiIii
    if 89 - 89: O0 % iIii1I11I1II1 . I1ii11iIi11i + OOooOOo / IiII
    if 84 - 84: i11iIiiIii . Oo0Ooo + OoOoOO00
    if 75 - 75: o0oOOo0O0Ooo
 if ( OO0oooo == None ) :
  OO0oooo = lisp_rloc ( )
  o0ooo0oOO0o . rloc_set = [ OO0oooo ]
  OO0oooo . priority = 253
  OO0oooo . mpriority = 255
  o0ooo0oOO0o . build_best_rloc_set ( )
  if 54 - 54: o0oOOo0O0Ooo
 if ( I1IIi1IIIi1I == None ) :
  I1IIi1IIIi1I = lisp_rle ( geid . print_address ( ) )
  OO0oooo . rle = I1IIi1IIIi1I
  if 95 - 95: Ii1I % I11i - OoooooooOO
 if ( iI11i1ii11i11 == None ) :
  iI11i1ii11i11 = lisp_rle_node ( )
  iI11i1ii11i11 . rloc_name = OO0oO00oOo0
  I1IIi1IIIi1I . rle_nodes . append ( iI11i1ii11i11 )
  I1IIi1IIIi1I . build_forwarding_list ( )
  lprint ( "Add RLE {} from {} for gleaned EID {}" . format ( O00o00o00OO0 , I111 , oO0ooOOO ) )
 elif ( rloc . is_exact_match ( iI11i1ii11i11 . address ) == False or
 port != iI11i1ii11i11 . translated_port ) :
  lprint ( "Changed RLE {} from {} for gleaned EID {}" . format ( O00o00o00OO0 , I111 , oO0ooOOO ) )
  if 11 - 11: OoO0O00 - oO0o
  if 50 - 50: II111iiii * IiII
  if 26 - 26: OoO0O00 . II111iiii
  if 19 - 19: iII111i / i11iIiiIii
  if 31 - 31: I1Ii111 / I1Ii111 % IiII
 iI11i1ii11i11 . store_translated_rloc ( rloc , port )
 if 68 - 68: O0 / OOooOOo % OoOoOO00
 if 68 - 68: OoooooooOO - IiII + I1IiiI * IiII / I11i - OoO0O00
 if 69 - 69: oO0o / II111iiii
 if 56 - 56: i1IIi + II111iiii + Ii1I . OoooooooOO
 if 26 - 26: OoooooooOO % Ii1I % I11i * oO0o - i1IIi - i1IIi
 if ( igmp ) :
  oOIII = seid . print_address ( )
  if ( oOIII not in lisp_gleaned_groups ) :
   lisp_gleaned_groups [ oOIII ] = { }
   if 76 - 76: i11iIiiIii + OoO0O00 - iII111i . OoOoOO00 * Oo0Ooo
  lisp_gleaned_groups [ oOIII ] [ IIiI11I1I1i1i ] = lisp_get_timestamp ( )
  if 15 - 15: II111iiii + iIii1I11I1II1
  if 100 - 100: OOooOOo
  if 43 - 43: OoO0O00 + I1Ii111 + OoOoOO00
  if 78 - 78: I11i
  if 30 - 30: iIii1I11I1II1
  if 74 - 74: I1IiiI - Oo0Ooo - i1IIi . iIii1I11I1II1 - I11i
  if 57 - 57: I1IiiI - i11iIiiIii - I1ii11iIi11i
  if 49 - 49: i1IIi . O0 % Ii1I * i1IIi
def lisp_remove_gleaned_multicast ( seid , geid ) :
 if 39 - 39: I1ii11iIi11i
 if 74 - 74: II111iiii % oO0o * Oo0Ooo / iIii1I11I1II1
 if 81 - 81: II111iiii + OoOoOO00 * O0
 if 64 - 64: iIii1I11I1II1 * Ii1I
 o0ooo0oOO0o = lisp_map_cache_lookup ( seid , geid )
 if ( o0ooo0oOO0o == None ) : return
 if 5 - 5: I11i . I11i / i1IIi - o0oOOo0O0Ooo % Oo0Ooo
 ooo0o0O = o0ooo0oOO0o . rloc_set [ 0 ] . rle
 if ( ooo0o0O == None ) : return
 if 85 - 85: OOooOOo
 OO000o = seid . print_address_no_iid ( )
 ooo0o00o0Oooo = False
 for iI11i1ii11i11 in ooo0o0O . rle_nodes :
  if ( iI11i1ii11i11 . rloc_name == OO000o ) :
   ooo0o00o0Oooo = True
   break
   if 32 - 32: iII111i
   if 27 - 27: iIii1I11I1II1 - iII111i
 if ( ooo0o00o0Oooo == False ) : return
 if 68 - 68: oO0o + OoooooooOO - i1IIi * OoOoOO00 % Oo0Ooo
 if 19 - 19: IiII * Oo0Ooo + I1IiiI * I1Ii111 % iIii1I11I1II1
 if 15 - 15: II111iiii % OoO0O00 % Oo0Ooo + I1Ii111
 if 54 - 54: I1Ii111 + OOooOOo
 ooo0o0O . rle_nodes . remove ( iI11i1ii11i11 )
 ooo0o0O . build_forwarding_list ( )
 if 6 - 6: Ii1I
 IIiI11I1I1i1i = geid . print_address ( )
 oOIII = seid . print_address ( )
 I111 = green ( "{}" . format ( oOIII ) , False )
 oO0ooOOO = green ( "(*, {})" . format ( IIiI11I1I1i1i ) , False )
 lprint ( "Gleaned EID {} RLE removed for {}" . format ( oO0ooOOO , I111 ) )
 if 8 - 8: OoO0O00
 if 91 - 91: Ii1I
 if 12 - 12: OoooooooOO + i11iIiiIii
 if 63 - 63: OOooOOo . i11iIiiIii
 if ( oOIII in lisp_gleaned_groups ) :
  if ( IIiI11I1I1i1i in lisp_gleaned_groups [ oOIII ] ) :
   lisp_gleaned_groups [ oOIII ] . pop ( IIiI11I1I1i1i )
   if 50 - 50: IiII % i11iIiiIii - iII111i . OoOoOO00 / Oo0Ooo
   if 30 - 30: Oo0Ooo . II111iiii + OoooooooOO % OoO0O00 * ooOoO0o * iIii1I11I1II1
   if 91 - 91: OoooooooOO
   if 86 - 86: iII111i / OoooooooOO - I1ii11iIi11i
   if 63 - 63: ooOoO0o % Ii1I * I1IiiI
   if 48 - 48: iII111i - iII111i - o0oOOo0O0Ooo + ooOoO0o - o0oOOo0O0Ooo / Ii1I
 if ( ooo0o0O . rle_nodes == [ ] ) :
  o0ooo0oOO0o . delete_cache ( )
  lprint ( "Gleaned EID {} remove, no more RLEs" . format ( oO0ooOOO ) )
  if 43 - 43: I1IiiI + Ii1I
  if 37 - 37: OoOoOO00 - OoooooooOO . ooOoO0o - IiII % iIii1I11I1II1 . iIii1I11I1II1
  if 64 - 64: OoOoOO00 + iII111i % I1Ii111 - OOooOOo + O0
  if 83 - 83: I1Ii111 + I1Ii111
  if 43 - 43: oO0o * i1IIi * Ii1I . iIii1I11I1II1 % o0oOOo0O0Ooo
  if 97 - 97: I1IiiI . i1IIi * OoOoOO00 / OOooOOo
  if 50 - 50: II111iiii . OoO0O00
  if 60 - 60: I11i . iIii1I11I1II1
def lisp_change_gleaned_multicast ( seid , rloc , port ) :
 oOIII = seid . print_address ( )
 if ( oOIII not in lisp_gleaned_groups ) : return
 if 41 - 41: II111iiii / I1IiiI
 for o0o0Oo0o0oOo in lisp_gleaned_groups [ oOIII ] :
  lisp_geid . store_address ( o0o0Oo0o0oOo )
  lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , port , False )
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
  if 44 - 44: I1ii11iIi11i + IiII + IiII * I1ii11iIi11i - OoooooooOO / I1Ii111
  if 3 - 3: I1ii11iIi11i + o0oOOo0O0Ooo * I11i / Oo0Ooo
  if 31 - 31: i11iIiiIii % OoO0O00 - oO0o / o0oOOo0O0Ooo % O0
  if 53 - 53: iIii1I11I1II1 * I1ii11iIi11i
  if 46 - 46: OOooOOo % OoOoOO00 * iII111i
  if 55 - 55: I1IiiI * iIii1I11I1II1 . OoOoOO00
  if 82 - 82: iIii1I11I1II1 - iII111i % I1IiiI + I1IiiI * i1IIi % O0
  if 63 - 63: I1IiiI + OoOoOO00
  if 55 - 55: o0oOOo0O0Ooo
  if 95 - 95: OoO0O00 * ooOoO0o * oO0o % Oo0Ooo
  if 36 - 36: I1IiiI - Ii1I + oO0o . iIii1I11I1II1
  if 47 - 47: Ii1I
  if 12 - 12: I1IiiI / IiII + OoOoOO00 . I1Ii111 / I1Ii111
  if 97 - 97: OOooOOo - iII111i . I1IiiI * oO0o . OoOoOO00 * IiII
  if 29 - 29: iIii1I11I1II1
  if 94 - 94: Ii1I - i11iIiiIii % O0 + Ii1I / O0 % I11i
  if 42 - 42: I1ii11iIi11i . iIii1I11I1II1 % I11i
  if 54 - 54: OoOoOO00 / Ii1I
  if 84 - 84: Oo0Ooo / OoO0O00 . o0oOOo0O0Ooo - iII111i . iII111i - II111iiii
  if 99 - 99: I1Ii111 % Oo0Ooo
  if 61 - 61: OoooooooOO % i11iIiiIii + OOooOOo
  if 53 - 53: iII111i . iIii1I11I1II1
  if 59 - 59: II111iiii . II111iiii - iII111i
  if 46 - 46: oO0o / iIii1I11I1II1 + OoO0O00
  if 33 - 33: Ii1I . iIii1I11I1II1 . O0 * I1ii11iIi11i . OoOoOO00 / i11iIiiIii
  if 85 - 85: iII111i
  if 23 - 23: O0
  if 83 - 83: i11iIiiIii % OoooooooOO
  if 45 - 45: OoO0O00 + Ii1I
  if 90 - 90: O0 * i1IIi . i1IIi * I1ii11iIi11i + I1ii11iIi11i / i1IIi
  if 52 - 52: O0 / iIii1I11I1II1 * IiII
  if 50 - 50: oO0o . Ii1I . OoooooooOO * o0oOOo0O0Ooo
  if 25 - 25: o0oOOo0O0Ooo % ooOoO0o
  if 91 - 91: I1Ii111 * i11iIiiIii / o0oOOo0O0Ooo * oO0o - o0oOOo0O0Ooo * OOooOOo
  if 2 - 2: i1IIi - OoOoOO00 / iII111i
  if 70 - 70: IiII / O0 - i1IIi
  if 23 - 23: OoOoOO00
  if 2 - 2: II111iiii * OoOoOO00 . iIii1I11I1II1 . ooOoO0o . ooOoO0o + iII111i
  if 60 - 60: I1ii11iIi11i / I1ii11iIi11i
  if 44 - 44: i11iIiiIii / ooOoO0o - iIii1I11I1II1 + OoO0O00
  if 62 - 62: i1IIi / I1Ii111 + ooOoO0o
igmp_types = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 80 - 80: iII111i + OoO0O00 % OoO0O00
lisp_igmp_record_types = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 4 - 4: OoOoOO00 * I11i * O0 . OoooooooOO + Ii1I % i1IIi
def lisp_process_igmp_packet ( packet ) :
 I1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 I1 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 I1 = bold ( "from {}" . format ( I1 . print_address_no_iid ( ) ) , False )
 if 11 - 11: OoOoOO00 % i11iIiiIii . OoOoOO00 % Oo0Ooo * Ii1I
 O00o00o00OO0 = bold ( "Receive" , False )
 lprint ( "{} {}-byte {}, IGMP packet: {}" . format ( O00o00o00OO0 , len ( packet ) , I1 ,
 lisp_format_packet ( packet ) ) )
 if 67 - 67: IiII - OoOoOO00 / I1Ii111 % oO0o % OOooOOo
 if 19 - 19: OoO0O00 - iII111i
 if 76 - 76: OoOoOO00 * ooOoO0o - iII111i * I1IiiI + I11i
 if 4 - 4: Oo0Ooo
 oOOoo0OooOOo = ( struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ] & 0x0f ) * 4
 if 52 - 52: iIii1I11I1II1 % OOooOOo / i1IIi - I11i / i11iIiiIii
 if 70 - 70: OoooooooOO
 if 81 - 81: i1IIi + O0 . IiII . I1IiiI / ooOoO0o
 if 75 - 75: I1ii11iIi11i / OoOoOO00
 oO0IiII1i = packet [ oOOoo0OooOOo : : ]
 o00iiI1i1 = struct . unpack ( "B" , oO0IiII1i [ 0 : 1 ] ) [ 0 ]
 if 21 - 21: II111iiii - o0oOOo0O0Ooo * OoO0O00 . OOooOOo
 if 65 - 65: o0oOOo0O0Ooo + I1IiiI
 if 21 - 21: I1Ii111
 if 74 - 74: iII111i
 if 51 - 51: O0 . II111iiii - OoooooooOO + ooOoO0o - o0oOOo0O0Ooo
 o0o0Oo0o0oOo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 o0o0Oo0o0oOo . address = socket . ntohl ( struct . unpack ( "II" , oO0IiII1i [ : 8 ] ) [ 1 ] )
 IIiI11I1I1i1i = o0o0Oo0o0oOo . print_address_no_iid ( )
 if 86 - 86: OOooOOo % i11iIiiIii / OoOoOO00
 if ( o00iiI1i1 == 17 ) :
  lprint ( "IGMP Query for group {}" . format ( IIiI11I1I1i1i ) )
  return ( True )
  if 72 - 72: I1IiiI . oO0o
  if 76 - 76: Ii1I - Oo0Ooo * II111iiii
 i1iiIiiiI1i1 = ( o00iiI1i1 in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( i1iiIiiiI1i1 == False ) :
  I1iii111 = "{} ({})" . format ( o00iiI1i1 , igmp_types [ o00iiI1i1 ] ) if ( o00iiI1i1 in igmp_types ) else o00iiI1i1
  if 73 - 73: iIii1I11I1II1 * Oo0Ooo - I1Ii111 % O0
  lprint ( "IGMP type {} not supported" . format ( I1iii111 ) )
  return ( [ ] )
  if 63 - 63: i11iIiiIii / I11i . I1ii11iIi11i . I1ii11iIi11i
  if 36 - 36: IiII % OoOoOO00 . ooOoO0o + i1IIi * OOooOOo
 if ( len ( oO0IiII1i ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 88 - 88: OoOoOO00 . O0
  if 47 - 47: I1Ii111 * iIii1I11I1II1 % OoO0O00
  if 48 - 48: i11iIiiIii
  if 15 - 15: oO0o - OoO0O00 . I1ii11iIi11i * oO0o / OoOoOO00
  if 89 - 89: OoO0O00 / oO0o % I11i - I1ii11iIi11i . o0oOOo0O0Ooo
 if ( o00iiI1i1 == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( IIiI11I1I1i1i , False ) ) )
  return ( [ [ None , IIiI11I1I1i1i , False ] ] )
  if 46 - 46: i11iIiiIii
 if ( o00iiI1i1 in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( o00iiI1i1 == 0x12 ) else 2 , bold ( IIiI11I1I1i1i , False ) ) )
  if 99 - 99: i11iIiiIii / oO0o / OoOoOO00 / O0 * I1ii11iIi11i
  if 72 - 72: ooOoO0o - I1Ii111 - iIii1I11I1II1 . I1IiiI
  if 77 - 77: Oo0Ooo * OoO0O00
  if 67 - 67: OoOoOO00 . I1Ii111 / I1IiiI * II111iiii
  if 45 - 45: I1ii11iIi11i * o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo
  if ( IIiI11I1I1i1i . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
  else :
   return ( [ [ None , IIiI11I1I1i1i , True ] ] )
   if 58 - 58: OOooOOo + O0
   if 19 - 19: o0oOOo0O0Ooo
   if 8 - 8: OOooOOo * OOooOOo - Ii1I * OoOoOO00 % OoO0O00 * O0
   if 70 - 70: I1IiiI
   if 17 - 17: I11i % OOooOOo - i11iIiiIii . OoooooooOO % OoO0O00 + OoO0O00
  return ( [ ] )
  if 24 - 24: Ii1I . OOooOOo . IiII / Oo0Ooo . Oo0Ooo . II111iiii
  if 63 - 63: ooOoO0o . I11i
  if 39 - 39: II111iiii % oO0o % I1IiiI - iIii1I11I1II1 / I1IiiI
  if 94 - 94: iII111i + oO0o
  if 43 - 43: iIii1I11I1II1 + iIii1I11I1II1
 O0O00oo = o0o0Oo0o0oOo . address
 oO0IiII1i = oO0IiII1i [ 8 : : ]
 if 8 - 8: iIii1I11I1II1
 I11IIiIii = "BBHI"
 O0O0oO0Oo0O = struct . calcsize ( I11IIiIii )
 iIi1i1 = "I"
 III11IiiII = struct . calcsize ( iIi1i1 )
 I1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 76 - 76: iIii1I11I1II1 + I1ii11iIi11i
 if 8 - 8: iIii1I11I1II1 / IiII / i1IIi % I1IiiI
 if 92 - 92: i11iIiiIii - oO0o
 if 62 - 62: O0 + O0 . Oo0Ooo + iIii1I11I1II1 + iII111i
 oOoOOooO = [ ]
 for iIi1iIIIiIiI in range ( O0O00oo ) :
  if ( len ( oO0IiII1i ) < O0O0oO0Oo0O ) : return
  OooO , iIiiiI1 , OOOO0OOO , I1IIIi = struct . unpack ( I11IIiIii ,
 oO0IiII1i [ : O0O0oO0Oo0O ] )
  if 75 - 75: o0oOOo0O0Ooo + i11iIiiIii % I1ii11iIi11i
  oO0IiII1i = oO0IiII1i [ O0O0oO0Oo0O : : ]
  if 45 - 45: I1Ii111 % Ii1I . ooOoO0o
  if ( OooO not in lisp_igmp_record_types ) :
   lprint ( "Invalid record type {}" . format ( OooO ) )
   continue
   if 99 - 99: I11i - OoOoOO00 % I11i / i1IIi
   if 55 - 55: o0oOOo0O0Ooo / ooOoO0o % I1IiiI / I1Ii111
  i11Iii1I1i = lisp_igmp_record_types [ OooO ]
  OOOO0OOO = socket . ntohs ( OOOO0OOO )
  o0o0Oo0o0oOo . address = socket . ntohl ( I1IIIi )
  IIiI11I1I1i1i = o0o0Oo0o0oOo . print_address_no_iid ( )
  if 39 - 39: I1IiiI + OoOoOO00 - Ii1I
  lprint ( "Record type: {}, group: {}, source-count: {}" . format ( i11Iii1I1i , IIiI11I1I1i1i , OOOO0OOO ) )
  if 87 - 87: Oo0Ooo + iII111i + Oo0Ooo - II111iiii % o0oOOo0O0Ooo + Ii1I
  if 62 - 62: OOooOOo
  if 91 - 91: iII111i . Ii1I - OoooooooOO / Ii1I / II111iiii - O0
  if 67 - 67: oO0o * i11iIiiIii / I1ii11iIi11i . I11i % OOooOOo
  if 75 - 75: ooOoO0o - OOooOOo
  if 97 - 97: i11iIiiIii / I11i % II111iiii
  if 20 - 20: I1Ii111 + OoooooooOO . o0oOOo0O0Ooo - ooOoO0o
  ooooO0 = False
  if ( OooO in ( 1 , 5 ) ) : ooooO0 = True
  if ( OooO in ( 2 , 4 ) and OOOO0OOO == 0 ) : ooooO0 = True
  IIIiI1i = "join" if ( ooooO0 ) else "leave"
  if 90 - 90: OoO0O00 + Oo0Ooo + IiII % o0oOOo0O0Ooo
  if 73 - 73: O0
  if 92 - 92: I1ii11iIi11i * o0oOOo0O0Ooo - OoooooooOO * OOooOOo . IiII - o0oOOo0O0Ooo
  if 7 - 7: i1IIi . i11iIiiIii . i1IIi % IiII * iII111i * OoooooooOO
  if ( IIiI11I1I1i1i . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   continue
   if 48 - 48: i1IIi . IiII / i1IIi / iII111i
   if 13 - 13: ooOoO0o - OoOoOO00 + I1ii11iIi11i % ooOoO0o % iIii1I11I1II1
   if 94 - 94: OOooOOo / OoO0O00 / OoO0O00 / Ii1I . IiII
   if 35 - 35: i1IIi
   if 58 - 58: Ii1I - IiII / ooOoO0o % o0oOOo0O0Ooo + I1ii11iIi11i
   if 89 - 89: IiII / OoooooooOO
   if 13 - 13: II111iiii . OOooOOo - O0 * oO0o
   if 71 - 71: ooOoO0o % ooOoO0o + o0oOOo0O0Ooo + iII111i / OoOoOO00
  if ( OOOO0OOO == 0 ) :
   oOoOOooO . append ( [ None , IIiI11I1I1i1i , ooooO0 ] )
   lprint ( "IGMPv3 {} (*, {})" . format ( bold ( IIIiI1i , False ) ,
 bold ( IIiI11I1I1i1i , False ) ) )
   if 27 - 27: I1ii11iIi11i * OoO0O00 - OoO0O00
   if 87 - 87: I1IiiI * I11i + iIii1I11I1II1 % i1IIi
   if 6 - 6: o0oOOo0O0Ooo
   if 94 - 94: I1ii11iIi11i * i11iIiiIii
   if 95 - 95: OoooooooOO - II111iiii . I1Ii111
  for iI1iII1II1 in range ( OOOO0OOO ) :
   if ( len ( oO0IiII1i ) < III11IiiII ) : return
   I1IIIi = struct . unpack ( iIi1i1 , oO0IiII1i [ : III11IiiII ] ) [ 0 ]
   I1 . address = socket . ntohl ( I1IIIi )
   oooOOOoOO00o = I1 . print_address_no_iid ( )
   oOoOOooO . append ( [ oooOOOoOO00o , IIiI11I1I1i1i , ooooO0 ] )
   lprint ( "{} ({}, {})" . format ( IIIiI1i ,
 green ( oooOOOoOO00o , False ) , bold ( IIiI11I1I1i1i , False ) ) )
   oO0IiII1i = oO0IiII1i [ III11IiiII : : ]
   if 31 - 31: i11iIiiIii - I11i
   if 91 - 91: I11i - iII111i
   if 35 - 35: I1IiiI * I11i + I11i
   if 67 - 67: I1ii11iIi11i - I1IiiI + Ii1I * Ii1I + Oo0Ooo
   if 41 - 41: i11iIiiIii
   if 97 - 97: i1IIi / Ii1I / ooOoO0o . Ii1I - ooOoO0o + oO0o
   if 27 - 27: OOooOOo % O0
   if 96 - 96: OoooooooOO / OOooOOo
 return ( oOoOOooO )
 if 87 - 87: IiII - OoooooooOO
 if 53 - 53: OoOoOO00 + Oo0Ooo
 if 33 - 33: I11i - OOooOOo + Oo0Ooo - iII111i * iII111i
 if 44 - 44: Oo0Ooo % OoOoOO00 / oO0o
 if 34 - 34: II111iiii + Ii1I + OoOoOO00
 if 9 - 9: I11i / oO0o * OoO0O00
 if 26 - 26: I1IiiI % OOooOOo * OoOoOO00
 if 14 - 14: I11i * Oo0Ooo . I1Ii111 * Ii1I . i11iIiiIii * I1ii11iIi11i
lisp_geid = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
if 11 - 11: oO0o + oO0o + o0oOOo0O0Ooo / iIii1I11I1II1 / I11i
def lisp_glean_map_cache ( seid , rloc , encap_port , igmp ) :
 if 68 - 68: OoooooooOO + i1IIi % I1ii11iIi11i . iII111i
 if 69 - 69: ooOoO0o * II111iiii + i11iIiiIii / oO0o + I1Ii111 - OOooOOo
 if 84 - 84: O0
 if 29 - 29: I11i + o0oOOo0O0Ooo . ooOoO0o * I1Ii111 - o0oOOo0O0Ooo * O0
 if 58 - 58: iII111i . oO0o + i11iIiiIii
 if 2 - 2: OOooOOo * Ii1I
 IIiiIIi1i1I11 = True
 o0ooo0oOO0o = lisp_map_cache . lookup_cache ( seid , True )
 if ( o0ooo0oOO0o and len ( o0ooo0oOO0o . rloc_set ) != 0 ) :
  o0ooo0oOO0o . last_refresh_time = lisp_get_timestamp ( )
  if 98 - 98: o0oOOo0O0Ooo / i1IIi - I1ii11iIi11i + I1Ii111 * IiII % o0oOOo0O0Ooo
  I1IIIiI = o0ooo0oOO0o . rloc_set [ 0 ]
  ooo0 = I1IIIiI . rloc
  ii1iIiiiIiI1 = I1IIIiI . translated_port
  IIiiIIi1i1I11 = ( ooo0 . is_exact_match ( rloc ) == False or
 ii1iIiiiIiI1 != encap_port )
  if 30 - 30: Oo0Ooo
  if ( IIiiIIi1i1I11 ) :
   oO0ooOOO = green ( seid . print_address ( ) , False )
   O00o00o00OO0 = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
   lprint ( "Change gleaned EID {} to RLOC {}" . format ( oO0ooOOO , O00o00o00OO0 ) )
   I1IIIiI . delete_from_rloc_probe_list ( o0ooo0oOO0o . eid , o0ooo0oOO0o . group )
   lisp_change_gleaned_multicast ( seid , rloc , encap_port )
   if 93 - 93: II111iiii - I1IiiI
 else :
  o0ooo0oOO0o = lisp_mapping ( "" , "" , [ ] )
  o0ooo0oOO0o . eid . copy_address ( seid )
  o0ooo0oOO0o . mapping_source . copy_address ( rloc )
  o0ooo0oOO0o . map_cache_ttl = LISP_GLEAN_TTL
  o0ooo0oOO0o . gleaned = True
  oO0ooOOO = green ( seid . print_address ( ) , False )
  O00o00o00OO0 = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( oO0ooOOO , O00o00o00OO0 ) )
  o0ooo0oOO0o . add_cache ( )
  if 80 - 80: I11i . o0oOOo0O0Ooo % IiII - OoOoOO00 % OOooOOo / OoooooooOO
  if 57 - 57: OoooooooOO % o0oOOo0O0Ooo - iIii1I11I1II1 . OoooooooOO
  if 42 - 42: o0oOOo0O0Ooo % OoooooooOO * OoO0O00 - o0oOOo0O0Ooo
  if 83 - 83: i1IIi . i1IIi * ooOoO0o
  if 26 - 26: I1IiiI - IiII
 if ( IIiiIIi1i1I11 ) :
  OO0oooo = lisp_rloc ( )
  OO0oooo . store_translated_rloc ( rloc , encap_port )
  OO0oooo . add_to_rloc_probe_list ( o0ooo0oOO0o . eid , o0ooo0oOO0o . group )
  OO0oooo . priority = 253
  OO0oooo . mpriority = 255
  OOOo0O00OO00O = [ OO0oooo ]
  o0ooo0oOO0o . rloc_set = OOOo0O00OO00O
  o0ooo0oOO0o . build_best_rloc_set ( )
  if 99 - 99: IiII * iII111i + i1IIi * I1Ii111
  if 88 - 88: o0oOOo0O0Ooo . IiII - Oo0Ooo
  if 24 - 24: Oo0Ooo - OOooOOo / Ii1I / II111iiii . Oo0Ooo - Ii1I
  if 5 - 5: IiII
  if 66 - 66: OoO0O00 . I1ii11iIi11i . OoooooooOO
 if ( igmp == None ) : return
 if 21 - 21: I11i / IiII + i1IIi . Oo0Ooo % II111iiii
 if 8 - 8: oO0o / iIii1I11I1II1 + OoooooooOO
 if 11 - 11: OOooOOo . O0 + IiII . i1IIi
 if 81 - 81: OoO0O00 - I11i - OoO0O00 + oO0o
 if 20 - 20: OoooooooOO - Oo0Ooo + I1Ii111 + OoooooooOO
 lisp_geid . instance_id = seid . instance_id
 if 66 - 66: I1ii11iIi11i / oO0o % IiII + II111iiii % iII111i
 if 54 - 54: iII111i * O0 / I1IiiI % Ii1I
 if 12 - 12: IiII % I1IiiI - o0oOOo0O0Ooo - I1ii11iIi11i - i11iIiiIii * i1IIi
 if 96 - 96: II111iiii % o0oOOo0O0Ooo % oO0o * ooOoO0o
 if 79 - 79: iII111i
 I111I = lisp_process_igmp_packet ( igmp )
 if ( type ( I111I ) == bool ) : return
 if 74 - 74: Oo0Ooo - IiII - iII111i - IiII / IiII
 for I1 , o0o0Oo0o0oOo , ooooO0 in I111I :
  if ( I1 != None ) : continue
  if 75 - 75: I11i - i11iIiiIii % O0 - O0 % O0
  if 93 - 93: ooOoO0o + iIii1I11I1II1
  if 27 - 27: i1IIi * i11iIiiIii - OoOoOO00 * Ii1I . IiII + iII111i
  if 25 - 25: I1ii11iIi11i % o0oOOo0O0Ooo - OoO0O00
  lisp_geid . store_address ( o0o0Oo0o0oOo )
  i1i1Ii , iIiiiI1 , II11iiiII1Ii = lisp_allow_gleaning ( seid , lisp_geid , rloc )
  if ( i1i1Ii == False ) : continue
  if 28 - 28: oO0o
  if ( ooooO0 ) :
   lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port ,
 True )
  else :
   lisp_remove_gleaned_multicast ( seid , lisp_geid )
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
def lisp_is_json_telemetry ( json_string ) :
 try :
  ii11i11iiiIi1 = json . loads ( json_string )
  if ( type ( ii11i11iiiIi1 ) != dict ) : return ( None )
 except :
  lprint ( "Could not decode telemetry json: {}" . format ( json_string ) )
  return ( None )
  if 82 - 82: OOooOOo
  if 64 - 64: II111iiii
 if ( "type" not in ii11i11iiiIi1 ) : return ( None )
 if ( "sub-type" not in ii11i11iiiIi1 ) : return ( None )
 if ( ii11i11iiiIi1 [ "type" ] != "telemetry" ) : return ( None )
 if ( ii11i11iiiIi1 [ "sub-type" ] != "timestamps" ) : return ( None )
 return ( ii11i11iiiIi1 )
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
def lisp_encode_telemetry ( json_string , ii = "?" , io = "?" , ei = "?" , eo = "?" ) :
 ii11i11iiiIi1 = lisp_is_json_telemetry ( json_string )
 if ( ii11i11iiiIi1 == None ) : return ( json_string )
 if 4 - 4: iII111i + I1IiiI
 if ( ii11i11iiiIi1 [ "itr-in" ] == "?" ) : ii11i11iiiIi1 [ "itr-in" ] = ii
 if ( ii11i11iiiIi1 [ "itr-out" ] == "?" ) : ii11i11iiiIi1 [ "itr-out" ] = io
 if ( ii11i11iiiIi1 [ "etr-in" ] == "?" ) : ii11i11iiiIi1 [ "etr-in" ] = ei
 if ( ii11i11iiiIi1 [ "etr-out" ] == "?" ) : ii11i11iiiIi1 [ "etr-out" ] = eo
 json_string = json . dumps ( ii11i11iiiIi1 )
 return ( json_string )
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
def lisp_decode_telemetry ( json_string ) :
 ii11i11iiiIi1 = lisp_is_json_telemetry ( json_string )
 if ( ii11i11iiiIi1 == None ) : return ( { } )
 return ( ii11i11iiiIi1 )
 if 36 - 36: OoooooooOO % OoooooooOO / OoO0O00 * I1IiiI
 if 55 - 55: O0 - O0
 if 32 - 32: I1IiiI + o0oOOo0O0Ooo + Oo0Ooo / OoO0O00 . I11i . Oo0Ooo
 if 32 - 32: I1Ii111 / i1IIi
 if 30 - 30: i11iIiiIii . II111iiii * Oo0Ooo + II111iiii - I1IiiI
 if 80 - 80: o0oOOo0O0Ooo - iII111i % i11iIiiIii % i11iIiiIii % OoooooooOO - IiII
 if 39 - 39: II111iiii / I1Ii111 + OoooooooOO + IiII + iIii1I11I1II1
 if 59 - 59: OoOoOO00 / II111iiii . Ii1I
 if 90 - 90: II111iiii
def lisp_telemetry_configured ( ) :
 if ( "telemetry" not in lisp_json_list ) : return ( None )
 if 77 - 77: i11iIiiIii . i11iIiiIii - iIii1I11I1II1 + OOooOOo
 iio0O0OOo = lisp_json_list [ "telemetry" ] . json_string
 if ( lisp_is_json_telemetry ( iio0O0OOo ) == None ) : return ( None )
 if 55 - 55: OoO0O00 + Oo0Ooo
 return ( iio0O0OOo )
 if 74 - 74: i1IIi - I11i - oO0o % I1IiiI
 if 57 - 57: Oo0Ooo / II111iiii + OoOoOO00
 if 67 - 67: IiII * IiII % oO0o - IiII * i11iIiiIii - i11iIiiIii
 if 27 - 27: i1IIi
 if 29 - 29: OOooOOo % I11i * Oo0Ooo
 if 92 - 92: OoOoOO00 / OoooooooOO % OoooooooOO + o0oOOo0O0Ooo
 if 91 - 91: OoOoOO00 - iII111i / iII111i - OoO0O00
def lisp_mr_or_pubsub ( action ) :
 return ( action in [ LISP_SEND_MAP_REQUEST_ACTION , LISP_SEND_PUBSUB_ACTION ] )
 if 97 - 97: Oo0Ooo / IiII % OOooOOo % Ii1I
 if 59 - 59: I1IiiI / Oo0Ooo / OoOoOO00
 if 79 - 79: O0 / ooOoO0o + OoOoOO00
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
